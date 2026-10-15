#!/usr/bin/env python3
"""Isolated regressions for Homebrew/localbin shim lifecycle and selection."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE = Path(os.environ.get("SAFEEXEC_SH_PATH", REPO / "safeexec.sh"))
BASH = os.environ.get("BASH", "/bin/bash")


class ShimLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        source = SOURCE.read_text(encoding="utf-8")
        definitions, sep, tail = source.rpartition('\nmain "$@"')
        self.assertTrue(sep and not tail.strip(), "cannot isolate definitions before final main call")
        self.loader = self.tmp / "definitions.sh"
        self.loader.write_text(
            definitions + '''
SAFEEXEC_ROOT="$1/safeexec"
SAFEEXEC_DIR="$SAFEEXEC_ROOT/bin"
LOCALBIN="$1/localbin"
HOMEBREW_BIN="$1/homebrew/bin"
HOMEBREW_GIT="$HOMEBREW_BIN/git"
HOMEBREW_GIT_REAL="${HOMEBREW_GIT}.safeexec.real"
SUDOERS_FILE="$1/sudoers"
is_darwin() { return 0; }
''', encoding="utf-8")
        self.pm = "safeexec_probe_" + self.tmp.name

    def tearDown(self):
        self.tmpdir.cleanup()

    def shell(self, body, env=None):
        script = 'source "$1" "$2"\n' + body
        merged = dict(os.environ, SAFEEXEC_DISABLED="1")
        if env:
            merged.update(env)
        return subprocess.run([BASH, "-c", script, "safeexec-test", str(self.loader), str(self.tmp)],
                              cwd=self.tmp, env=merged, capture_output=True, text=True, timeout=8)

    def make_file(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    def test_reinstall_preserves_dangling_homebrew_backups(self):
        brew = self.tmp / "homebrew/bin"
        gitshim = "#!/bin/bash\n# SAFEEXEC HOMEBREW GIT SHIM\n"
        pmshim = "#!/bin/bash\n# SAFEEXEC HOMEBREW PM SHIM (npm)\n"
        self.make_file(brew / "git", gitshim)
        self.make_file(brew / "npm", pmshim)
        (brew / "git.safeexec.real").symlink_to("missing-git-target")
        (brew / "npm.safeexec.real").symlink_to("missing-npm-target")
        result = self.shell("install_homebrew_git_shim; install_homebrew_pm_shims")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((brew / "git").read_text(), gitshim)
        self.assertEqual((brew / "npm").read_text(), pmshim)
        self.assertEqual(os.readlink(brew / "git.safeexec.real"), "missing-git-target")
        self.assertEqual(os.readlink(brew / "npm.safeexec.real"), "missing-npm-target")

    def test_owned_shims_without_backups_are_never_backed_up_as_themselves(self):
        brew = self.tmp / "homebrew/bin"
        self.make_file(brew / "git", "#!/bin/bash\n# SAFEEXEC HOMEBREW GIT SHIM\n")
        self.make_file(brew / "npm", "#!/bin/bash\n# SAFEEXEC HOMEBREW PM SHIM (npm)\n")
        result = self.shell("install_homebrew_git_shim; install_homebrew_pm_shims")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SAFEEXEC HOMEBREW GIT SHIM", (brew / "git").read_text())
        self.assertIn("SAFEEXEC HOMEBREW PM SHIM (npm)", (brew / "npm").read_text())
        self.assertFalse((brew / "git.safeexec.real").is_symlink() or (brew / "git.safeexec.real").exists())
        self.assertFalse((brew / "npm.safeexec.real").is_symlink() or (brew / "npm.safeexec.real").exists())

    def test_uninstall_removes_owned_shims_and_restores_dangling_backups(self):
        brew = self.tmp / "homebrew/bin"
        self.make_file(brew / "git", "#!/bin/bash\n# SAFEEXEC HOMEBREW GIT SHIM\n")
        self.make_file(brew / "npm", "#!/bin/bash\n# SAFEEXEC HOMEBREW PM SHIM (npm)\n")
        (brew / "git.safeexec.real").symlink_to("lost-git")
        result = self.shell("remove_homebrew_git_shim; remove_homebrew_pm_shims")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((brew / "git").exists())
        self.assertTrue((brew / "git").is_symlink())
        self.assertEqual(os.readlink(brew / "git"), "lost-git")
        self.assertFalse((brew / "npm").exists() or (brew / "npm").is_symlink())

    def test_localbin_uninstall_keeps_unmanaged_dangling_intel_target(self):
        local = self.tmp / "localbin"
        target = local / "git"
        original = "../Cellar/git/2/bin/git"
        target.parent.mkdir(parents=True)
        target.symlink_to(original)
        result = self.shell("install_localbin_shims")
        self.assertEqual(result.returncode, 0, result.stderr)
        backup = local / "git.safeexec.real"
        self.assertTrue(backup.is_symlink())
        self.assertEqual(os.readlink(backup), original)
        target.unlink()
        unmanaged = "../Cellar/other-git/missing/git"
        target.symlink_to(unmanaged)
        result = self.shell("remove_localbin_shims")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(target.is_symlink())
        self.assertEqual(os.readlink(target), unmanaged)
        self.assertTrue(backup.is_symlink())
        self.assertEqual(os.readlink(backup), original)

    def candidates(self):
        fake = self.tmp / "fake"
        return [fake / "usr/bin" / f"{self.pm}.safeexec.real",
                fake / "bin" / f"{self.pm}.safeexec.real",
                fake / "opt/homebrew/bin" / f"{self.pm}.safeexec.real",
                fake / "usr/local/bin" / f"{self.pm}.safeexec.real",
                fake / "opt/homebrew/bin" / self.pm,
                fake / "usr/local/bin" / self.pm,
                fake / "usr/bin" / self.pm, fake / "bin" / self.pm]

    def generated_runtime_wrapper(self):
        result = self.shell(f"write_wrapper_pkgmgr {self.pm}")
        self.assertEqual(result.returncode, 0, result.stderr)
        wrapper = self.tmp / "safeexec/bin" / self.pm
        content = wrapper.read_text(encoding="utf-8")
        for prefix in ("/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"):
            content = content.replace(f'"{prefix}/', f'"{self.tmp}/fake{prefix}/')
        wrapper.write_text(content, encoding="utf-8")
        return wrapper

    def invoke_wrapper(self, wrapper):
        return subprocess.run([BASH, str(wrapper)], cwd=self.tmp,
                              env=dict(os.environ, SAFEEXEC_DISABLED="1", HOME=str(self.tmp)),
                              capture_output=True, text=True, timeout=5)

    def test_runtime_command_classifier_boundaries(self):
        wrapper = self.generated_runtime_wrapper()
        shim, backend = self.candidates()[4:6]
        backup = Path(str(shim) + ".safeexec.real")
        self.make_file(shim, f"#!/bin/sh\n# SAFEEXEC HOMEBREW PM SHIM ({self.pm})\n")
        backup.symlink_to("missing-backend")
        self.make_file(backend, "#!/bin/sh\nexit 0\n")
        helpers = self.shell("write_binary_helpers").stdout
        probe = self.tmp / "classify.sh"
        self.make_file(probe, "#!/bin/bash\nset -euo pipefail\n" + helpers +
                       '\nif is_real_command "$1"; then exit 0; else exit 1; fi\n')

        def accepted(path):
            return subprocess.run([BASH, str(probe), str(path)], capture_output=True,
                                  text=True, timeout=5).returncode == 0

        self.assertFalse(accepted(wrapper), "generated wrapper classified as a real backend")
        self.assertFalse(accepted(shim), "distinct safeexec shim classified as a real backend")
        self.assertFalse(accepted(backup), "dangling backup classified as a real backend")
        self.assertTrue(accepted(backend), "inert executable backend was rejected")

    def test_runtime_selection_skips_safeexec_shim_and_dispatches_real_backend(self):
        wrapper = self.generated_runtime_wrapper()
        shim = self.candidates()[4]
        self.make_file(shim, f"#!/bin/sh\n# SAFEEXEC HOMEBREW PM SHIM ({self.pm})\necho SHIM_DISPATCHED\nexit 41\n")
        (Path(str(shim) + ".safeexec.real")).symlink_to("missing-backend")
        backend = self.candidates()[5]
        self.make_file(backend, "#!/bin/sh\necho REAL_BACKEND_DISPATCHED\nexit 37\n")
        result = self.invoke_wrapper(wrapper)
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn("REAL_BACKEND_DISPATCHED", result.stdout)
        self.assertNotIn("SHIM_DISPATCHED", result.stdout)

    def test_runtime_selection_rejects_all_wrappers_with_prompt_127(self):
        wrapper = self.generated_runtime_wrapper()
        generated = wrapper.read_text(encoding="utf-8")
        for candidate in self.candidates():
            self.make_file(candidate, generated)
        result = self.invoke_wrapper(wrapper)
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertTrue(result.stderr.strip(), "missing-backend failure should be reported")


if __name__ == "__main__":
    unittest.main()
