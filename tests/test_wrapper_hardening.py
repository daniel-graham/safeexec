#!/usr/bin/env python3
"""Compact stdlib regressions for two reported safeexec wrapper issues.

Wrappers are produced the way the installer produces them: the embedded
installer definitions are sourced with the final `main "$@"` call removed and
SAFEEXEC_DIR pointed at a temp dir, then write_wrapper_rm / _git / _pkgmgr emit
the wrapper text. Nothing destructive runs and no confirmation gate is reached:
backends are inert stubs and zero-argument invocations gate nothing.

Trigger tests (fail on the vulnerable baseline, run with SAFEEXEC_SH_PATH):
1. `is_disabled` must not evaluate SUDO_USER through a shell: a malicious
   SUDO_USER (command substitution, semicolon) must execute nothing, while
   explicit disable states (env var, user file, global file) stay recognized.
2. Zero-argument wrappers must reach dispatch and exit with the backend status
   under bash 3.x instead of aborting on an unbound `"${args[@]}"` expansion.

Only the generated text is read/replaced, so a later safe SUDO_USER helper, a
removed `eval`, or an array-safe dispatch is tolerated.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAFEEXEC_SH = Path(os.environ.get("SAFEEXEC_SH_PATH", str(REPO_ROOT / "safeexec.sh")))
BASH3 = os.environ.get("SAFEEXEC_BASH3", "/bin/bash")
WRAPPER_NAMES = ("rm", "git", "npm", "yarn", "pnpm", "bun")

CALL_IS_DISABLED = (
    'set -uo pipefail\nsource "$1"\nif is_disabled; then echo rc=0; else echo rc=1; fi\n'
)
STUB = (
    '#!/usr/bin/env bash\n: >"$SAFEEXEC_TEST_ARGV"\n'
    'for a in "$@"; do printf \'%s\\n\' "$a" >>"$SAFEEXEC_TEST_ARGV"; done\nexit 42\n'
)
# The revision's own guard/dispatch lines stay intact; only the backend lookup
# between `REAL_X=""` and the guard that consults is_disabled is replaced.
GUARD = re.compile(r'(?m)^[^\n]*is_disabled[^\n]*$')


def generate_wrappers(dest: Path) -> dict:
    """Run the installer's write_wrapper_* functions into dest; return text."""
    library, separator, tail = SAFEEXEC_SH.read_text(encoding="utf-8").rpartition('\nmain "$@"')
    if not separator or tail.strip():
        raise RuntimeError("could not isolate installer definitions before the final main call")
    body = ['SAFEEXEC_DIR="$1"', "write_wrapper_rm", "write_wrapper_git"]
    body += [f'write_wrapper_pkgmgr {pm}' for pm in WRAPPER_NAMES[2:]]
    subprocess.run(
        [BASH3, "-c", library + "\n" + "\n".join(body) + "\n", "safeexec-test", str(dest)],
        check=True, capture_output=True, text=True,
    )
    return {name: (dest / name).read_text(encoding="utf-8") for name in WRAPPER_NAMES}


def disabled_prefix(wrapper_text: str, tmp: Path) -> str:
    """Generated prefix up to the end of `is_disabled`, with isolated state paths."""
    start = wrapper_text.index("is_disabled() {")
    prefix = wrapper_text[: wrapper_text.index("\n}\n", start) + 3]
    prefix = re.sub(r'(?m)^STATE_FILE_USER=.*$', f'STATE_FILE_USER="{tmp}/user-state/disabled"', prefix)
    prefix = re.sub(r'(?m)^STATE_FILE_GLOBAL=.*$', f'STATE_FILE_GLOBAL="{tmp}/global-state/disabled"', prefix)
    return prefix


def replace_discovery(wrapper_text: str, var: str, stub: Path) -> str:
    """Keep the wrapper's own guard and dispatch, swap the real binary for a stub."""
    start = wrapper_text.index(f'\n{var}=""\n') + 1
    guard = GUARD.search(wrapper_text, start)
    if guard is None:
        raise RuntimeError(f"could not locate the is_disabled guard after {var}")
    return wrapper_text[:start] + f'{var}="{stub}"\n' + wrapper_text[guard.start():]


class WrapperHardeningTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        gen = self.tmp / "gen"
        gen.mkdir()
        self.wrappers = generate_wrappers(gen)

    def tearDown(self):
        self._tmpdir.cleanup()

    def call_is_disabled(self, prefix: str, env: dict) -> int:
        prefix_file = self.tmp / f"prefix-{abs(hash(prefix))}.sh"
        prefix_file.write_text(prefix, encoding="utf-8")
        base = {"PATH": os.environ["PATH"], "HOME": str(self.tmp / "home"), "TMPDIR": str(self.tmp)}
        base.update(env)
        result = subprocess.run([BASH3, "-c", CALL_IS_DISABLED, "safeexec-test", str(prefix_file)],
                                capture_output=True, text=True, env=base, cwd=str(self.tmp), timeout=10)
        lines = result.stdout.strip().splitlines()
        if not lines or not lines[-1].startswith("rc="):
            raise AssertionError(f"is_disabled harness gave no rc: {result.stdout!r} {result.stderr!r}")
        return int(lines[-1][3:])

    def test_is_disabled_ignores_malicious_sudo_user(self):
        marker = self.tmp / "pwned"
        payloads = {
            "command substitution": f"$(touch {marker})",
            "semicolon": f"x; touch {marker}",
        }
        for name, text in self.wrappers.items():
            prefix = disabled_prefix(text, self.tmp)
            with self.subTest(wrapper=name):
                # An unrecognized account must not disable the wrapper.
                self.assertEqual(self.call_is_disabled(prefix, {"SUDO_USER": "safeexec-no-such-user"}), 1)
            for label, payload in payloads.items():
                with self.subTest(wrapper=name, payload=label):
                    if marker.exists():
                        marker.unlink()
                    self.assertEqual(self.call_is_disabled(prefix, {"SUDO_USER": payload}), 1)
                    self.assertFalse(marker.exists(), f"SUDO_USER payload executed: {label}")

    def test_sudo_lookup_requires_root_and_a_safe_account_name(self):
        home = self.tmp / "sudo home with spaces"
        state = home / ".config/safeexec/disabled"
        state.parent.mkdir(parents=True)
        state.touch()
        for name, text in self.wrappers.items():
            # Bash's EUID is readonly. Substitute only that value in this
            # isolated fixture; preserve the actual username validation.
            prefix = disabled_prefix(text, self.tmp).replace(
                '${EUID:-$(id -u)}', '${SAFEEXEC_TEST_EUID:-501}')
            prefix += '\neval() { printf "%s\\n" "$SAFEEXEC_TEST_SUDO_HOME"; }\n'
            for uid, account, expected in ((0, "normal-user", 0), (501, "normal-user", 1),
                                           (0, "-", 1), (0, "x;false", 1), (0, "$(false)", 1)):
                with self.subTest(wrapper=name, uid=uid, account=account):
                    self.assertEqual(self.call_is_disabled(prefix, {
                        "SAFEEXEC_TEST_EUID": str(uid), "SUDO_USER": account,
                        "SAFEEXEC_TEST_SUDO_HOME": str(home),
                    }), expected)

    def assert_disabled(self, prefix: str, env: dict) -> None:
        self.assertEqual(self.call_is_disabled(prefix, dict(env, SUDO_USER="safeexec-no-such-user")), 0)

    def test_explicit_disable_states_still_recognized(self):
        for name, text in self.wrappers.items():
            prefix = disabled_prefix(text, self.tmp)
            with self.subTest(wrapper=name, state="env"):
                self.assert_disabled(prefix, {"SAFEEXEC_DISABLED": "1"})
            for state in ("user", "global"):
                with self.subTest(wrapper=name, state=state):
                    state_file = self.tmp / f"{state}-state" / "disabled"
                    state_file.parent.mkdir(parents=True, exist_ok=True)
                    state_file.write_text("", encoding="utf-8")
                    try:
                        self.assert_disabled(prefix, {})
                    finally:
                        state_file.unlink()

    def run_zero_argv(self, name: str, var: str) -> None:
        stub = self.tmp / f"stub-{name}"
        stub.write_text(STUB, encoding="utf-8")
        stub.chmod(0o755)
        argv_file = self.tmp / f"argv-{name}"
        wrapper_file = self.tmp / f"run-{name}"
        isolated = replace_discovery(self.wrappers[name], var, stub)
        isolated = re.sub(r'(?m)^STATE_FILE_GLOBAL=.*$',
                          f'STATE_FILE_GLOBAL="{self.tmp}/absent-global"', isolated)
        wrapper_file.write_text(isolated, encoding="utf-8")
        wrapper_file.chmod(0o755)
        (self.tmp / "home").mkdir(exist_ok=True)
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.tmp / "home"),
            "XDG_CONFIG_HOME": str(self.tmp / "xdg"),
            "SAFEEXEC_TEST_ARGV": str(argv_file),
        }
        result = subprocess.run([BASH3, str(wrapper_file)], capture_output=True, text=True, env=env,
                                cwd=str(self.tmp), timeout=10)
        self.assertNotIn("unbound variable", result.stderr, f"{name}: {result.stderr}")
        self.assertTrue(argv_file.exists(), f"{name}: backend stub was never invoked")
        self.assertEqual(argv_file.read_text(encoding="utf-8"), "", f"{name}: arguments leaked")
        self.assertEqual(result.returncode, 42, f"{name}: rc={result.returncode} {result.stderr}")

    def test_zero_argv_dispatch_git(self):
        self.run_zero_argv("git", "REAL_GIT")

    def test_zero_argv_dispatch_package_managers(self):
        for pm in WRAPPER_NAMES[2:]:
            with self.subTest(pm=pm):
                self.run_zero_argv(pm, "REAL_PM")


if __name__ == "__main__":
    unittest.main()
