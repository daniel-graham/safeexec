#!/usr/bin/env python3
"""
Harness tests for the safeexec Git repository bypass feature.

The wrapper is generated the same way the installer generates it: the embedded
installer definitions are loaded with the final `main "$@"` call removed, and
`write_wrapper_git` writes the wrapper into a temp dir. The REAL_GIT finder is
then replaced with a shim that delegates ONLY the internal `rev-parse` probes to
a real git binary and otherwise records the final argv and exits 0. Every
destructive git command is therefore inert: nothing but `rev-parse` ever reaches
git, and `confirm_or_die` is replaced by a marker that exits 126.

Contract under test:
- reset / revert / stash drop|clear|pop bypass confirmation only when the repo's
  worktree, git dir and common dir are strictly inside `tree:` entries of
  SAFEEXEC_GIT_ALLOWLIST (fallback SAFEEXEC_RM_ALLOWLIST, fallback XDG default).
- Exact absolute file lines never authorize git (tree-only matching).
- Global options (-C repeated, -c, --git-dir/--work-tree) and explicit
  GIT_DIR/GIT_WORK_TREE env are honored; linked worktree common dirs included.
- Missing allowlist / no repository / symlinked sibling escapes fail closed.
- The final argv is preserved verbatim and harmless commands are unaffected.

Baseline comparison: run with SAFEEXEC_SH_PATH pointing at a checkout without the
feature (for example `git show HEAD:safeexec.sh > /tmp/baseline.sh`); the bypass
tests are expected to fail there.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from io import BytesIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAFEEXEC_SH = Path(os.environ.get("SAFEEXEC_SH_PATH", str(REPO_ROOT / "safeexec.sh")))

FINDER_MARKER = "\n# Prefer diverted / backed-up real binary"
TAIL_MARKER = "\nif is_disabled;"


def extract_git_wrapper(target_file: Path = None):
    """Return (head, tail) of the generated git wrapper.

    head = function definitions (through the allowlist helpers), tail = top level
    option parsing, gate decision and final exec. The REAL_GIT finder between the
    two is intentionally dropped so tests can install a recording shim.
    """
    safeexec_path = target_file if target_file is not None else SAFEEXEC_SH
    content = safeexec_path.read_text(encoding="utf-8")
    library, separator, trailing = content.rpartition('\nmain "$@"')
    if not separator or trailing.strip():
        raise RuntimeError("Could not isolate installer definitions")
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(
            ["bash", "-c", library + '\nSAFEEXEC_DIR="$1"\nwrite_wrapper_git\n',
             "safeexec-test", directory],
            check=True, capture_output=True, text=True,
        )
        wrapper_text = (Path(directory) / "git").read_text(encoding="utf-8")

    if FINDER_MARKER not in wrapper_text:
        raise RuntimeError("Could not locate REAL_GIT finder in git wrapper")
    if TAIL_MARKER not in wrapper_text:
        raise RuntimeError("Could not locate wrapper entry point in git wrapper")
    head = wrapper_text[:wrapper_text.index(FINDER_MARKER)]
    tail = wrapper_text[wrapper_text.index(TAIL_MARKER) + 1:]
    return head, tail


try:
    GIT_HEAD, GIT_TAIL = extract_git_wrapper()
    EXTRACTION_ERROR = None
except Exception as exc:  # reported as a test failure rather than an import error
    GIT_HEAD = GIT_TAIL = ""
    EXTRACTION_ERROR = f"{type(exc).__name__}: {exc}"


def find_real_git() -> str:
    """Locate a real git binary, never a safeexec shim wrapping git."""
    override = os.environ.get("SAFEEXEC_TEST_REAL_GIT")
    candidates = [override] if override else []
    candidates += ["/usr/bin/git.safeexec.real", "/bin/git.safeexec.real",
                   "/opt/homebrew/bin/git.safeexec.real", "/usr/local/bin/git.safeexec.real",
                   "/usr/bin/git", "/bin/git", shutil.which("git")]
    for candidate in candidates:
        if not candidate or not os.access(candidate, os.X_OK):
            continue
        try:
            with open(candidate, "rb") as handle:
                blob = handle.read(4096)
        except OSError:
            continue
        if b"safeexec" in blob.lower():
            continue
        return candidate
    raise RuntimeError("No real git binary found (safeexec shims rejected)")


REAL_GIT_BIN = find_real_git()

SHIM_TEMPLATE = """#!/usr/bin/env bash
set -euo pipefail
for a in "$@"; do
  if [[ "$a" == "--path-format=absolute" ]]; then
    exec "{real_git}" "$@"
  fi
done
: >"$GIT_SHIM_RECORD"
printf '%s\\0' "$@" >>"$GIT_SHIM_RECORD"
exit 0
"""


class GitAllowlistTestCase(unittest.TestCase):
    """Behavioural tests for the safeexec git repository bypass."""

    def setUp(self):
        if EXTRACTION_ERROR:
            self.fail(f"could not build git wrapper from {SAFEEXEC_SH}: {EXTRACTION_ERROR}")
        self._tmpdir = tempfile.TemporaryDirectory()
        # macOS: /var -> /private/var symlink would break allowlist prefix checks.
        self.root = Path(os.path.realpath(self._tmpdir.name))
        self.allowlist = self.root / "git-allowlist"
        self.record = self.root / "final-argv.bin"
        self.shim = self.root / "git-shim"
        self.shim.write_text(SHIM_TEMPLATE.format(real_git=REAL_GIT_BIN), encoding="utf-8")
        self.shim.chmod(0o755)
        self.xdg = self.root / "xdg"
        self.xdg.mkdir()

    def tearDown(self):
        self._tmpdir.cleanup()

    # ------------------------------------------------------------------ helpers

    def set_allowlist(self, lines, path=None):
        target = Path(path) if path else self.allowlist
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
        return target

    def make_repo(self, name, base=None) -> Path:
        repo = (base or self.root) / name
        repo.mkdir(parents=True, exist_ok=True)
        self.real_git(repo, "init", "-q")
        self.real_git(
            repo,
            "-c", "user.email=test@example.invalid",
            "-c", "user.name=Safeexec Test",
            "commit", "--allow-empty", "-q", "-m", "init",
        )
        return repo

    def real_git(self, cwd, *args):
        return subprocess.run(
            [REAL_GIT_BIN, *args],
            cwd=str(cwd),
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                 "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
            check=True, capture_output=True, text=True, timeout=10,
        )

    def run_wrapper(self, args, cwd=None, allowlist=None, env_extra=None, set_allowlist_env=True):
        """Run the generated wrapper; return (returncode, argv or None, stderr)."""
        script = (
            GIT_HEAD
            + f'\nREAL_GIT="{self.shim}"\n'
            + 'confirm_or_die() { echo "SAFEEXEC_TEST_CONFIRM:$1" >&2; exit 126; }\n'
            + GIT_TAIL
        )
        env = os.environ.copy()
        for key in list(env):
            if key.startswith("GIT_"):
                env.pop(key)
        env.pop("SAFEEXEC_GIT_ALLOWLIST", None)
        env.pop("SAFEEXEC_RM_ALLOWLIST", None)
        env.pop("GIT_DIR", None)
        env.pop("GIT_WORK_TREE", None)
        env.pop("GIT_COMMON_DIR", None)
        env["SAFEEXEC_DISABLED"] = "0"
        env["XDG_CONFIG_HOME"] = str(self.xdg)
        env["GIT_SHIM_RECORD"] = str(self.record)
        if set_allowlist_env:
            env["SAFEEXEC_GIT_ALLOWLIST"] = str(allowlist if allowlist is not None else self.allowlist)
        if env_extra:
            env.update({k: str(v) for k, v in env_extra.items()})

        if self.record.exists():
            self.record.unlink()
        proc = subprocess.run(
            ["bash", "-c", script, "git-test", *args],
            cwd=str(cwd if cwd is not None else self.root),
            env=env, capture_output=True, text=True, timeout=10,
        )
        argv = None
        if self.record.exists():
            fields = self.record.read_bytes().split(b"\0")
            if fields and fields[-1] == b"":
                fields = fields[:-1]
            argv = [f.decode("utf-8", "surrogateescape") for f in fields]
        return proc.returncode, argv, proc.stderr

    def assert_bypassed(self, args, argv, rc, stderr):
        self.assertEqual(rc, 0, f"expected bypass for {args}, got rc={rc}, stderr={stderr!r}")
        self.assertNotIn("SAFEEXEC_TEST_CONFIRM", stderr)
        self.assertEqual(argv, list(args), "final argv must be preserved verbatim")

    def assert_blocked(self, rc, argv, stderr, args):
        self.assertEqual(rc, 126, f"expected confirmation block for {args}, got rc={rc}, stderr={stderr!r}")
        self.assertIn("SAFEEXEC_TEST_CONFIRM", stderr)
        self.assertIsNone(argv, "real git must not be reached when not allowlisted")

    # ------------------------------------------------------- trusted repo bypass

    def test_real_git_finder_supports_diverted_and_homebrew_backups(self):
        for backup in ("/usr/bin/git.safeexec.real", "/bin/git.safeexec.real",
                       "/opt/homebrew/bin/git.safeexec.real", "/usr/local/bin/git.safeexec.real"):
            with self.subTest(backup=backup), mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch("os.access", side_effect=lambda p, mode: p == backup), \
                    mock.patch("builtins.open", side_effect=lambda *args: BytesIO(b"real executable")):
                self.assertEqual(find_real_git(), backup)

    def test_real_git_finder_rejects_uppercase_safeexec_markers(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("os.access", side_effect=lambda p, mode: p == "/usr/bin/git"), \
                mock.patch("builtins.open", side_effect=lambda *args: BytesIO(b"#!/bin/sh\n# SAFEEXEC HARD WRAPPER\n")):
            with self.assertRaises(RuntimeError):
                find_real_git()

    def test_gated_subcommands_bypass_when_repo_in_trusted_tree(self):
        repo = self.make_repo("projects/trusted/repo")
        self.set_allowlist([f"tree:{self.root / 'projects/trusted'}"])
        gated = [
            ["reset", "--hard"],
            ["reset", "-q", "HEAD"],
            ["revert", "--no-edit", "HEAD"],
            ["stash", "drop"],
            ["stash", "drop", "stash@{0}"],
            ["stash", "clear"],
            ["stash", "pop"],
        ]
        for args in gated:
            with self.subTest(args=args):
                rc, argv, err = self.run_wrapper(args, cwd=repo)
                self.assert_bypassed(args, argv, rc, err)

    def test_tree_root_itself_is_not_a_descendant(self):
        repo = self.make_repo("projects/trusted/repo")
        self.set_allowlist([f"tree:{repo}"])
        self.assert_blocked(*self.run_wrapper(["stash", "drop"], cwd=repo), args=["stash", "drop"])
        self.set_allowlist([f"tree:{self.root / 'projects/trusted'}"])
        rc, argv, err = self.run_wrapper(["stash", "drop"], cwd=repo)
        self.assert_bypassed(["stash", "drop"], argv, rc, err)

    def test_allowlist_fallback_envs_and_xdg_default(self):
        repo = self.make_repo("trusted/repo")
        self.set_allowlist([f"tree:{self.root / 'trusted'}"])
        rc, argv, err = self.run_wrapper(
            ["stash", "pop"], cwd=repo, set_allowlist_env=False,
            env_extra={"SAFEEXEC_RM_ALLOWLIST": self.allowlist})
        self.assert_bypassed(["stash", "pop"], argv, rc, err)
        xdg_list = self.xdg / "safeexec" / "rm-allowlist"
        self.set_allowlist([f"tree:{self.root / 'trusted'}"], path=xdg_list)
        rc, argv, err = self.run_wrapper(["stash", "pop"], cwd=repo, set_allowlist_env=False)
        self.assert_bypassed(["stash", "pop"], argv, rc, err)

    # --------------------------------------------- global options and env overrides

    def test_two_argument_global_options_do_not_hide_gated_commands(self):
        trusted = self.make_repo("trusted/repo")
        outside = self.make_repo("outside/repo")
        self.set_allowlist([f"tree:{trusted.parent}"])
        for option in (["--config-env", "core.pager=PATH"],
                       ["--attr-source", "HEAD"]):
            probe = subprocess.run([REAL_GIT_BIN, *option, "rev-parse", "--is-inside-work-tree"],
                                   cwd=trusted, env={"PATH": "/usr/bin:/bin"},
                                   capture_output=True, text=True, timeout=10)
            for command in (["reset", "--hard"], ["revert", "HEAD"],
                            ["stash", "drop"], ["stash", "clear"], ["stash", "pop"]):
                args = [*option, *command]
                with self.subTest(args=args):
                    rc, argv, err = self.run_wrapper(args, cwd=outside)
                    self.assert_blocked(rc, argv, err, args)
                    rc, argv, err = self.run_wrapper(args, cwd=trusted)
                    if probe.returncode == 0:
                        self.assert_bypassed(args, argv, rc, err)
                    else:
                        # Older Git may lack --attr-source. Failed repository
                        # queries must stay gated even in a trusted directory.
                        self.assert_blocked(rc, argv, err, args)

    def test_global_options_c_and_c_flags(self):
        repo = self.make_repo("projects/trusted/repo")
        self.set_allowlist([f"tree:{self.root / 'projects/trusted'}"])
        cases = [
            ["-C", str(repo), "stash", "pop"],
            ["-C", "/", "-C", str(repo), "reset", "--hard"],
            ["-c", "core.pager=cat", "-C", str(repo), "revert", "--no-edit", "HEAD"],
            ["-c", "advice.detachedHead=false", "-C", str(repo), "stash", "clear"],
        ]
        for args in cases:
            with self.subTest(args=args):
                rc, argv, err = self.run_wrapper(args, cwd=self.root)
                self.assert_bypassed(args, argv, rc, err)

    def test_global_c_pointing_outside_trusted_tree_is_blocked(self):
        trusted = self.make_repo("projects/trusted/repo")
        untrusted = self.make_repo("projects/untrusted/repo")
        self.set_allowlist([f"tree:{self.root / 'projects/trusted'}"])
        args = ["-C", str(untrusted), "stash", "pop"]
        rc, argv, err = self.run_wrapper(args, cwd=trusted)
        self.assert_blocked(rc, argv, err, args)

    def test_git_dir_and_work_tree_options_outside_metadata_are_blocked(self):
        trusted = self.make_repo("projects/trusted/repo")
        untrusted = self.make_repo("projects/untrusted/repo")
        self.set_allowlist([f"tree:{self.root / 'projects/trusted'}"])
        cases = [
            ["--git-dir", str(untrusted / ".git"), "--work-tree", str(untrusted), "reset", "--hard"],
            ["--work-tree", str(untrusted), "--git-dir", str(untrusted / ".git"), "stash", "pop"],
        ]
        for args in cases:
            with self.subTest(args=args):
                rc, argv, err = self.run_wrapper(args, cwd=trusted)
                self.assert_blocked(rc, argv, err, args)

    def test_git_dir_environment_outside_metadata_is_blocked(self):
        trusted = self.make_repo("projects/trusted/repo")
        untrusted = self.make_repo("projects/untrusted/repo")
        self.set_allowlist([f"tree:{self.root / 'projects/trusted'}"])
        for extra in ({"GIT_DIR": untrusted / ".git"},
                      {"GIT_WORK_TREE": untrusted},
                      {"GIT_DIR": untrusted / ".git", "GIT_WORK_TREE": untrusted}):
            args = ["stash", "pop"]
            with self.subTest(env=extra):
                rc, argv, err = self.run_wrapper(args, cwd=trusted, env_extra=extra)
                self.assert_blocked(rc, argv, err, args)
        rc, argv, err = self.run_wrapper(
            ["stash", "pop"], cwd=trusted,
            env_extra={"GIT_DIR": trusted / ".git", "GIT_WORK_TREE": trusted})
        self.assert_bypassed(["stash", "pop"], argv, rc, err)

    # ------------------------------------------------------ linked worktree case

    def test_linked_worktree_uses_common_dir(self):
        main = self.make_repo("main-area/main-repo")
        linked = self.root / "linked-area/linked-worktree"
        linked.parent.mkdir()
        self.real_git(main, "worktree", "add", "-q", str(linked))
        self.set_allowlist([f"tree:{main.parent}", f"tree:{linked.parent}"])
        rc, argv, err = self.run_wrapper(["stash", "pop"], cwd=linked)
        self.assert_bypassed(["stash", "pop"], argv, rc, err)

        # Worktree allowed, shared common dir (main repo) NOT allowlisted.
        self.set_allowlist([f"tree:{linked.parent}"])
        rc, argv, err = self.run_wrapper(["reset", "--hard"], cwd=linked)
        self.assert_blocked(rc, argv, err, ["reset", "--hard"])

        # Common dir allowed, worktree dir NOT allowlisted.
        self.set_allowlist([f"tree:{main.parent}"])
        rc, argv, err = self.run_wrapper(["stash", "clear"], cwd=linked)
        self.assert_blocked(rc, argv, err, ["stash", "clear"])

        # Main worktree still bypasses when only the main tree is trusted.
        rc, argv, err = self.run_wrapper(["stash", "clear"], cwd=main)
        self.assert_bypassed(["stash", "clear"], argv, rc, err)

    def test_relocated_index_and_object_store_stay_in_trusted_trees(self):
        repo = self.make_repo("trusted/repo")
        self.set_allowlist([f"tree:{repo.parent}"])
        outside_objects = self.root / "outside-objects"
        outside_objects.mkdir()
        for override in ({"GIT_INDEX_FILE": self.root / "outside-index"},
                         {"GIT_OBJECT_DIRECTORY": outside_objects}):
            with self.subTest(override=override):
                rc, argv, err = self.run_wrapper(["reset", "--hard"], cwd=repo,
                                                 env_extra=override)
                self.assert_blocked(rc, argv, err, ["reset", "--hard"])
        rc, argv, err = self.run_wrapper(["reset", "--hard"], cwd=repo,
                                         env_extra={"GIT_INDEX_FILE": repo / "custom-index"})
        self.assert_bypassed(["reset", "--hard"], argv, rc, err)

    def test_bare_repository_remains_gated(self):
        bare = self.root / "trusted" / "bare.git"
        bare.parent.mkdir()
        self.real_git(self.root, "init", "--bare", "-q", str(bare))
        self.set_allowlist([f"tree:{bare.parent}"])
        rc, argv, err = self.run_wrapper(["stash", "clear"], cwd=bare)
        self.assert_blocked(rc, argv, err, ["stash", "clear"])

    # ------------------------------------------------------------ fail-closed cases

    def test_missing_allowlist_and_non_repository_fail_closed(self):
        repo = self.make_repo("projects/trusted/repo")
        args = ["stash", "drop"]
        rc, argv, err = self.run_wrapper(args, cwd=repo, allowlist=self.root / "does-not-exist")
        self.assert_blocked(rc, argv, err, args)

        self.set_allowlist([f"tree:{self.root}"])
        not_a_repo = self.root / "plain-dir"
        not_a_repo.mkdir()
        rc, argv, err = self.run_wrapper(args, cwd=not_a_repo)
        self.assert_blocked(rc, argv, err, args)

    def test_exact_file_lines_never_authorize_git(self):
        repo = self.make_repo("projects/trusted/repo")
        for line in [str(repo), str(repo / ".git"), f"{repo}/", str(repo / "README")]:
            args = ["stash", "drop"]
            with self.subTest(line=line):
                self.set_allowlist([line])
                rc, argv, err = self.run_wrapper(args, cwd=repo)
                self.assert_blocked(rc, argv, err, args)
        self.set_allowlist([f"tree:{repo.parent}"])
        rc, argv, err = self.run_wrapper(["stash", "drop"], cwd=repo)
        self.assert_bypassed(["stash", "drop"], argv, rc, err)

    def test_symlink_sibling_and_prefix_boundaries(self):
        trusted_parent = self.root / "projects/trusted"
        repo = self.make_repo("repo", base=trusted_parent)
        sibling = self.make_repo("repo-sibling", base=self.root / "projects/trusted-other")
        self.set_allowlist([f"tree:{trusted_parent}"])

        # Sibling tree sharing a text prefix must not be authorized.
        args = ["-C", str(sibling), "stash", "drop"]
        rc, argv, err = self.run_wrapper(args, cwd=self.root)
        self.assert_blocked(rc, argv, err, args)

        # Symlink outside the tree resolving inside it is authorized.
        outside_link = self.root / "link-to-trusted"
        outside_link.symlink_to(repo, target_is_directory=True)
        args = ["-C", str(outside_link), "stash", "pop"]
        rc, argv, err = self.run_wrapper(args, cwd=self.root)
        self.assert_bypassed(args, argv, rc, err)

        # Symlink inside the tree escaping outside it is refused.
        escape = trusted_parent / "escape"
        escape.symlink_to(sibling, target_is_directory=True)
        args = ["-C", str(escape), "reset", "--hard"]
        rc, argv, err = self.run_wrapper(args, cwd=self.root)
        self.assert_blocked(rc, argv, err, args)

        # Direct cwd in the sibling tree is refused as well.
        rc, argv, err = self.run_wrapper(["reset", "--hard"], cwd=sibling)
        self.assert_blocked(rc, argv, err, ["reset", "--hard"])

    def test_information_only_global_options_pass_through(self):
        repo = self.make_repo("untrusted/repo")
        for flag in ("--exec-path", "--html-path", "--man-path", "--info-path"):
            args = [flag, "reset", "--hard"]
            with self.subTest(flag=flag):
                rc, argv, err = self.run_wrapper(args, cwd=repo)
                self.assert_bypassed(args, argv, rc, err)

    # ----------------------------------------------------------- argv / harmlessness

    def test_final_argv_preserved_verbatim(self):
        repo = self.make_repo("trusted/repo")
        self.set_allowlist([f"tree:{self.root / 'trusted'}"])
        args = ["stash", "pop", "--", "file with space", "*.txt", "", "$HOME", "a'b"]
        rc, argv, err = self.run_wrapper(args, cwd=repo)
        self.assert_bypassed(args, argv, rc, err)

        args = ["-C", str(repo), "reset", "--hard", "HEAD~1", "--", "dir with space/"]
        rc, argv, err = self.run_wrapper(args, cwd=self.root)
        self.assert_bypassed(args, argv, rc, err)

    def test_harmless_commands_are_unaffected(self):
        repo = self.make_repo("trusted/repo")
        # No allowlist at all: non-gated subcommands still reach git.
        for args in (["status"], ["stash", "list"], ["stash"], ["stash", "push", "-m", "x"],
                     ["--version"], ["log", "--oneline", "-1"], ["stash", "show"]):
            with self.subTest(args=args):
                rc, argv, err = self.run_wrapper(args, cwd=repo)
                self.assertEqual(rc, 0, f"harmless {args} blocked: {err!r}")
                self.assertNotIn("SAFEEXEC_TEST_CONFIRM", err)
                self.assertEqual(argv, list(args))
        # Gated subcommands still fail closed without an allowlist file.
        for args in (["reset", "--hard"], ["revert", "HEAD"], ["stash", "drop"],
                     ["stash", "clear"], ["stash", "pop"]):
            with self.subTest(args=args):
                rc, argv, err = self.run_wrapper(args, cwd=repo)
                self.assert_blocked(rc, argv, err, args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
