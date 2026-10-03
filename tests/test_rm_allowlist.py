#!/usr/bin/env python3
"""
Unit test harness for safeexec rm allowlist contract.

Extracts the embedded rm wrapper from safeexec.sh and invokes is_allowlisted_rm
in Bash without executing rm or prompting.

Contract under test:
- Plain absolute lines retain exact matching.
- tree:/absolute/root permits strictly descendants, not root.
- Targets normalize relative paths and dotdot against physical cwd and existing parent symlinks;
  symlink escapes fail closed.
- Mixed targets: all targets must match.
- Operand semantics: '--' ends option parsing and paths following '--' are operands.
- No targets -> returns false (1).
- tree:/ is invalid (fails closed).
- Nonexistent descendants allowed when resolvable parents exist (missing leaves).
- No Python runtime required for wrapper.
- Temporary fixtures only.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAFEEXEC_SH = Path(os.environ.get("SAFEEXEC_SH_PATH", str(REPO_ROOT / "safeexec.sh")))


def extract_wrapper_functions(target_file: Path = None) -> str:
    """Extract functions and environment setup from the embedded rm wrapper in safeexec.sh."""
    safeexec_path = target_file if target_file is not None else SAFEEXEC_SH
    content = safeexec_path.read_text(encoding="utf-8")
    func_idx = content.find("write_wrapper_rm()")
    if func_idx == -1:
        raise RuntimeError("write_wrapper_rm() not found in safeexec.sh")

    cat_idx = content.find("cat ", func_idx)
    eof_match = re.search(r"<<\s*['\"]?([A-Za-z0-9_-]+)['\"]?", content[cat_idx : cat_idx + 100])
    if not eof_match:
        raise RuntimeError("Could not find heredoc EOF tag in write_wrapper_rm")
    eof_tag = eof_match.group(1)

    # Find starting EOF marker
    start_pos = -1
    for quote in ["'", '"', ""]:
        marker = f"<<{quote}{eof_tag}{quote}\n"
        pos = content.find(marker, cat_idx)
        if pos != -1:
            start_pos = pos + len(marker)
            break
    if start_pos == -1:
        raise RuntimeError(f"Could not find opening heredoc marker for {eof_tag}")

    end_pos = content.find(f"\n{eof_tag}", start_pos)
    if end_pos == -1:
        raise RuntimeError(f"Could not find closing heredoc marker for {eof_tag}")

    wrapper_text = content[start_pos:end_pos]

    # Stop before top-level command execution entry point
    markers = [
        "\n# Prefer diverted real binary",
        "\nREAL_RM=",
        "\nREAL_RM ",
        "\nif is_disabled",
        "\nforce=0",
    ]
    cut_pos = len(wrapper_text)
    for m in markers:
        pos = wrapper_text.find(m)
        if pos != -1 and pos < cut_pos:
            cut_pos = pos

    return wrapper_text[:cut_pos]


WRAPPER_FUNCTIONS = extract_wrapper_functions()


class RmAllowlistTestCase(unittest.TestCase):
    """Test suite covering safeexec rm allowlist specifications."""

    def setUp(self):
        # Resolve physical path to avoid macOS /var -> /private/var symlink discrepancies
        self._tmpdir = tempfile.TemporaryDirectory()
        self.test_root = os.path.realpath(self._tmpdir.name)
        self.allowlist_file = os.path.join(self.test_root, "rm-allowlist")

    def tearDown(self):
        self._tmpdir.cleanup()

    def set_allowlist(self, lines):
        with open(self.allowlist_file, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(f"{line}\n")

    def run_is_allowlisted(self, rm_args, cwd=None):
        """Invoke is_allowlisted_rm in Bash with given args and allowlist.

        Returns exit code of is_allowlisted_rm (0 = allowlisted, 1 = blocked).
        """
        bash_script = f"""{WRAPPER_FUNCTIONS}

# Safety guards ensuring no destructive execution or confirmation prompt
confirm_or_die() {{ echo "BLOCKED_CONFIRMATION" >&2; exit 126; }}
REAL_RM="/usr/bin/false"
enable -n exec 2>/dev/null || true
exec() {{ return 0; }}

is_allowlisted_rm "$@"
exit $?
"""
        env = os.environ.copy()
        env["SAFEEXEC_RM_ALLOWLIST"] = self.allowlist_file
        effective_cwd = cwd if cwd is not None else self.test_root

        proc = subprocess.run(
            ["bash", "-c", bash_script, "bash", *rm_args],
            cwd=effective_cwd,
            env=env,
            capture_output=True,
            text=True,
        )
        return proc.returncode

    # =========================================================================
    # Legacy: Plain Absolute Lines Exact Matching
    # =========================================================================

    def test_outside_symlink_into_tree_is_not_allowlisted(self):
        tree = Path(self.test_root) / "trusted"
        tree.mkdir()
        (tree / "file").touch()
        outside = Path(self.test_root) / "outside-link"
        outside.symlink_to(tree / "file")
        self.set_allowlist(["tree:" + str(tree)])
        self.assertEqual(self.run_is_allowlisted(["-rf", str(outside)]), 1)

    def test_dash_operand_after_first_operand_is_checked(self):
        tree = Path(self.test_root) / "trusted"
        tree.mkdir()
        self.set_allowlist(["tree:" + str(tree)])
        code = self.run_is_allowlisted(["-rf", str(tree / "file"), "--victim"])
        self.assertEqual(code, 1, "BSD rm treats trailing dash names as operands")

    def test_double_dash_after_first_operand_is_checked(self):
        tree = Path(self.test_root) / "trusted"
        tree.mkdir()
        self.set_allowlist(["tree:" + str(tree)])
        code = self.run_is_allowlisted(["-rf", str(tree / "file"), "--"])
        self.assertEqual(code, 1, "After the first operand, -- can be a BSD rm operand")

    def test_legacy_plain_absolute_exact_match(self):
        target = os.path.join(self.test_root, "single_file.txt")
        self.set_allowlist([target])
        code = self.run_is_allowlisted(["-rf", target])
        self.assertEqual(code, 0, "Exact match of plain absolute target must succeed")

    def test_legacy_plain_absolute_mismatch(self):
        target = os.path.join(self.test_root, "single_file.txt")
        other = os.path.join(self.test_root, "other_file.txt")
        self.set_allowlist([target])
        code = self.run_is_allowlisted(["-rf", other])
        self.assertEqual(code, 1, "Mismatching plain absolute target must fail")

    def test_legacy_plain_absolute_does_not_permit_descendants(self):
        parent_dir = os.path.join(self.test_root, "legacy_dir")
        child_file = os.path.join(parent_dir, "child.txt")
        self.set_allowlist([parent_dir])
        code = self.run_is_allowlisted(["-rf", child_file])
        self.assertEqual(code, 1, "Plain absolute line must retain exact matching, not permit descendants")

    # =========================================================================
    # Tree Root & Descendants Semantics
    # =========================================================================

    def test_tree_descendant_allowed(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        child = os.path.join(tree_dir, "child_dir")
        os.makedirs(child, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", child])
        self.assertEqual(code, 0, "Strict descendant of tree root must be allowed")

    def test_tree_deep_descendant_allowed(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        deep_child = os.path.join(tree_dir, "a", "b", "c", "leaf.txt")
        os.makedirs(os.path.dirname(deep_child), exist_ok=True)
        with open(deep_child, "w") as f:
            f.write("content")

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", deep_child])
        self.assertEqual(code, 0, "Deep descendant of tree root must be allowed")

    def test_tree_root_itself_fails(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        os.makedirs(tree_dir, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", tree_dir])
        self.assertEqual(code, 1, "tree:/root permits strictly descendants, not root itself")

    def test_tree_root_with_trailing_slash_fails(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        os.makedirs(tree_dir, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", f"{tree_dir}/"])
        self.assertEqual(code, 1, "tree:/root with trailing slash must not permit root itself")

    def test_tree_slash_invalid(self):
        target = os.path.join(self.test_root, "something")
        self.set_allowlist(["tree:/"])
        code = self.run_is_allowlisted(["-rf", target])
        self.assertEqual(code, 1, "tree:/ root allowlist is invalid and must fail closed")

    def test_tree_empty_path_invalid(self):
        target = os.path.join(self.test_root, "something")
        self.set_allowlist(["tree:"])
        code = self.run_is_allowlisted(["-rf", target])
        self.assertEqual(code, 1, "tree: without path is invalid and must fail closed")

    # =========================================================================
    # Sibling & Ancestor Escapes
    # =========================================================================

    def test_sibling_directory_fails(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        sibling_dir = os.path.join(self.test_root, "tree_dir_sibling")
        os.makedirs(tree_dir, exist_ok=True)
        os.makedirs(sibling_dir, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", sibling_dir])
        self.assertEqual(code, 1, "Sibling directory with matching prefix must be rejected")

    def test_ancestor_directory_fails(self):
        tree_dir = os.path.join(self.test_root, "a", "b", "c")
        ancestor = os.path.join(self.test_root, "a", "b")
        os.makedirs(tree_dir, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", ancestor])
        self.assertEqual(code, 1, "Ancestor directory of tree root must be rejected")

    # =========================================================================
    # Multi Target Handling
    # =========================================================================

    def test_multi_target_all_matching_succeeds(self):
        exact_file = os.path.join(self.test_root, "exact.txt")
        tree_dir = os.path.join(self.test_root, "tree_dir")
        child1 = os.path.join(tree_dir, "child1")
        child2 = os.path.join(tree_dir, "child2")
        os.makedirs(child1, exist_ok=True)
        os.makedirs(child2, exist_ok=True)

        self.set_allowlist([exact_file, f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", exact_file, child1, child2])
        self.assertEqual(code, 0, "Mixed targets where all match must succeed")

    def test_multi_target_one_failing_rejects_all(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        child = os.path.join(tree_dir, "child")
        outside = os.path.join(self.test_root, "outside.txt")
        os.makedirs(child, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", child, outside])
        self.assertEqual(code, 1, "Multiple targets with one non-matching must fail closed")

    # =========================================================================
    # Relative Paths & Dotdot Normalization
    # =========================================================================

    def test_relative_path_from_tree_root(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        child = os.path.join(tree_dir, "child")
        os.makedirs(child, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", "child"], cwd=tree_dir)
        self.assertEqual(code, 0, "Relative target from tree root cwd must be normalized and allowed")

    def test_relative_path_with_curdir(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        child = os.path.join(tree_dir, "child")
        os.makedirs(child, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", "./child"], cwd=tree_dir)
        self.assertEqual(code, 0, "./child relative target must normalize and be allowed")

    def test_dotdot_resolving_inside_tree(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        sub1 = os.path.join(tree_dir, "sub1")
        sub2 = os.path.join(tree_dir, "sub2")
        os.makedirs(sub1, exist_ok=True)
        os.makedirs(sub2, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", "../sub2"], cwd=sub1)
        self.assertEqual(code, 0, "Relative path using .. that stays inside tree must be allowed")

    def test_dotdot_escaping_tree_fails(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        os.makedirs(tree_dir, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", "../sibling"], cwd=tree_dir)
        self.assertEqual(code, 1, "Relative path using .. escaping tree root must fail closed")

    def test_dotdot_in_absolute_path_inside_tree(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        sub1 = os.path.join(tree_dir, "sub1")
        sub2 = os.path.join(tree_dir, "sub2")
        os.makedirs(sub1, exist_ok=True)
        os.makedirs(sub2, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        target = f"{tree_dir}/sub1/../sub2"
        code = self.run_is_allowlisted(["-rf", target])
        self.assertEqual(code, 0, "Absolute path containing .. that stays inside tree must normalize")

    # =========================================================================
    # Spaces in Paths
    # =========================================================================

    def test_paths_with_spaces_in_tree(self):
        tree_dir = os.path.join(self.test_root, "tree with spaces")
        child_file = os.path.join(tree_dir, "nested folder", "target file.txt")
        os.makedirs(os.path.dirname(child_file), exist_ok=True)
        with open(child_file, "w") as f:
            f.write("content")

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", child_file])
        self.assertEqual(code, 0, "Target with spaces inside tree root must be allowed")

    def test_relative_path_with_spaces(self):
        tree_dir = os.path.join(self.test_root, "tree with spaces")
        child_file = os.path.join(tree_dir, "my child.txt")
        os.makedirs(tree_dir, exist_ok=True)
        with open(child_file, "w") as f:
            f.write("content")

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", "my child.txt"], cwd=tree_dir)
        self.assertEqual(code, 0, "Relative target with spaces must be allowed")

    # =========================================================================
    # Symlinks: Escapes Fail Closed, Internal Symlinks Allowed
    # =========================================================================

    def test_internal_symlink_allowed(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        real_target_dir = os.path.join(tree_dir, "real_dir")
        os.makedirs(real_target_dir, exist_ok=True)

        symlink_dir = os.path.join(tree_dir, "symlink_dir")
        os.symlink(real_target_dir, symlink_dir)

        target = os.path.join(symlink_dir, "file.txt")
        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", target])
        self.assertEqual(code, 0, "Internal symlink resolving within tree root must be allowed")

    def test_symlink_escape_fails_closed(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        outside_dir = os.path.join(self.test_root, "outside_dir")
        os.makedirs(tree_dir, exist_ok=True)
        os.makedirs(outside_dir, exist_ok=True)

        escape_symlink = os.path.join(tree_dir, "escape_link")
        os.symlink(outside_dir, escape_symlink)

        target = os.path.join(escape_symlink, "leak.txt")
        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", target])
        self.assertEqual(code, 1, "Symlink pointing outside tree root must fail closed")

    def test_physical_cwd_symlink_escape_fails_closed(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        outside_dir = os.path.join(self.test_root, "outside_dir")
        os.makedirs(tree_dir, exist_ok=True)
        os.makedirs(outside_dir, exist_ok=True)

        escape_symlink = os.path.join(tree_dir, "escape_link")
        os.symlink(outside_dir, escape_symlink)

        self.set_allowlist([f"tree:{tree_dir}"])
        # Running from cwd that points outside tree root via symlink
        code = self.run_is_allowlisted(["-rf", "child.txt"], cwd=escape_symlink)
        self.assertEqual(code, 1, "Relative target from escaped symlink cwd must fail closed")

    def test_physical_cwd_internal_symlink_allowed(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        sub_dir = os.path.join(tree_dir, "sub_dir")
        os.makedirs(sub_dir, exist_ok=True)

        symlink_to_sub = os.path.join(tree_dir, "symlink_sub")
        os.symlink(sub_dir, symlink_to_sub)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", "leaf.txt"], cwd=symlink_to_sub)
        self.assertEqual(code, 0, "Relative target from internal symlink cwd must normalize and succeed")

    # =========================================================================
    # Missing Leaves (Nonexistent Descendants with Resolvable Parents)
    # =========================================================================

    def test_missing_leaf_with_existing_parent_allowed(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        parent_dir = os.path.join(tree_dir, "existing_parent")
        os.makedirs(parent_dir, exist_ok=True)

        missing_leaf = os.path.join(parent_dir, "does_not_exist.txt")
        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", missing_leaf])
        self.assertEqual(code, 0, "Nonexistent descendant with resolvable parent must be allowed")

    def test_nested_missing_leaves_with_existing_ancestor_allowed(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        parent_dir = os.path.join(tree_dir, "existing_parent")
        os.makedirs(parent_dir, exist_ok=True)

        deep_missing = os.path.join(parent_dir, "nonexistent_dir", "missing_file.txt")
        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", deep_missing])
        self.assertEqual(code, 0, "Deep nonexistent descendants with resolvable ancestor must be allowed")

    # =========================================================================
    # '--' Operand Semantics & Flag Handling
    # =========================================================================

    def test_double_dash_operand_semantics(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        child = os.path.join(tree_dir, "child")
        os.makedirs(child, exist_ok=True)

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", "--", child])
        self.assertEqual(code, 0, "Target following '--' delimiter must be parsed as operand")

    def test_double_dash_with_dash_prefixed_filename(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        os.makedirs(tree_dir, exist_ok=True)
        dash_file = os.path.join(tree_dir, "-f")
        with open(dash_file, "w") as f:
            f.write("content")

        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", "--", "-f"], cwd=tree_dir)
        self.assertEqual(code, 0, "Filename starting with dash after '--' must be treated as operand")

    def test_double_dash_with_no_targets_fails(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf", "--"])
        self.assertEqual(code, 1, "rm -rf -- with no targets must return false")

    def test_no_targets_fails(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        self.set_allowlist([f"tree:{tree_dir}"])
        code = self.run_is_allowlisted(["-rf"])
        self.assertEqual(code, 1, "rm -rf with no targets must return false")

    # =========================================================================
    # Allowlist Comments and Whitespace
    # =========================================================================

    def test_allowlist_comments_and_blank_lines_ignored(self):
        tree_dir = os.path.join(self.test_root, "tree_dir")
        child = os.path.join(tree_dir, "child")
        os.makedirs(child, exist_ok=True)

        self.set_allowlist([
            "# Comment line at start",
            "",
            "   ",
            f"tree:{tree_dir}",
            "# Comment at end",
        ])
        code = self.run_is_allowlisted(["-rf", child])
        self.assertEqual(code, 0, "Allowlist comments and empty lines must be ignored")


if __name__ == "__main__":
    unittest.main()
