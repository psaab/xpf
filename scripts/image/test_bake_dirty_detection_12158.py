#!/usr/bin/env python3
"""Regression tests for #12158: dirty detection must cover staged + untracked.

`git diff --quiet` (worktree vs index) misses staged edits and untracked
files, so both bake.py's deb_version_for_head and Makefile's DEB_GIT_DIRTY
yielded clean versions for non-HEAD source. bind_deb_identity then stripped
`-dirty` from the observed xpfd version before comparing, signing non-HEAD
bytes as HEAD in the release manifest.

Each cell runs against a THROWAWAY git repo (bake.ROOT is monkeypatched and
make is invoked with cwd=fixture), so the live checkout's state is
irrelevant. Pre-fix, the staged/untracked/bind cells FAIL; post-fix all pass.
debian/changelog is the one exclusion: `make deb` rewrites its version line
mid-build (restored after), so it must not count as dirt anywhere.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
_MAKEFILE = _ROOT / "Makefile"
_SPEC = importlib.util.spec_from_file_location("xpf_bake_12158", _HERE / "bake.py")
bake = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bake)


def _git(repo, *args):
    return subprocess.run(
        ["git", *args], cwd=repo, check=True,
        capture_output=True, text=True)


class DirtyDetection12158Tests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp(prefix="xpf-dirty-12158-"))
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "test@example.invalid")
        _git(self.repo, "config", "user.name", "xpf test")
        _git(self.repo, "config", "commit.gpgsign", "false")
        (self.repo / "debian").mkdir()
        (self.repo / "debian" / "changelog").write_text(
            "xpf (0.0.0) unstable; urgency=medium\n\n -- x\n")
        (self.repo / "src.txt").write_text("v1\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "base")
        self._old_root = bake.ROOT
        bake.ROOT = str(self.repo)
        self.addCleanup(setattr, bake, "ROOT", self._old_root)
        self.head = _git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.describe = _git(
            self.repo, "describe", "--tags", "--always",
            self.head).stdout.strip()
        self.package_version = "0.0.1+g" + self.head[:12]

    def _make_versions(self):
        """Eval the REAL Makefile's DEB_VERSION/VERSION in the fixture repo."""
        probe = subprocess.run(
            ["make", "-f", str(_MAKEFILE), "--eval",
             'show-12158:;@echo "DEB=[$(DEB_VERSION)] VER=[$(VERSION)]"',
             "show-12158"],
            cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        line = probe.stdout.strip()
        deb = line.split("DEB=[", 1)[1].split("]", 1)[0]
        ver = line.split("VER=[", 1)[1].split("]", 1)[0]
        return deb, ver

    def _staged_src_edit(self):
        (self.repo / "src.txt").write_text("v1\nstaged\n")
        _git(self.repo, "add", "src.txt")

    # bake.py deb_version_for_head --------------------------------------

    def test_bake_clean_tree_yields_clean_version(self):
        self.assertNotIn(".dirty", bake.deb_version_for_head())

    def test_bake_staged_edit_yields_dirty_version(self):
        self._staged_src_edit()
        self.assertIn(".dirty", bake.deb_version_for_head())

    def test_bake_untracked_file_yields_dirty_version(self):
        (self.repo / "new_input.txt").write_text("consumed\n")
        self.assertIn(".dirty", bake.deb_version_for_head())

    def test_bake_unstaged_edit_yields_dirty_version(self):
        (self.repo / "src.txt").write_text("v1\nunstaged\n")
        self.assertIn(".dirty", bake.deb_version_for_head())

    def test_bake_changelog_only_delta_yields_clean_version(self):
        # The `make deb` version-line rewrite must not dirty the version.
        (self.repo / "debian" / "changelog").write_text(
            "xpf (0.0.1) unstable; urgency=medium\n\n -- x\n")
        self.assertNotIn(".dirty", bake.deb_version_for_head())

    def test_bake_ignored_untracked_does_not_dirty(self):
        (self.repo / ".gitignore").write_text("*.pyc\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "ignore")
        (self.repo / "scratch.pyc").write_text("output\n")
        self.assertNotIn(".dirty", bake.deb_version_for_head())

    # Makefile DEB_VERSION / VERSION -------------------------------------

    def test_make_clean_tree_yields_clean_versions(self):
        deb, ver = self._make_versions()
        self.assertNotIn(".dirty", deb)
        self.assertNotIn("-dirty", ver)

    def test_make_staged_edit_dirties_both_versions(self):
        self._staged_src_edit()
        deb, ver = self._make_versions()
        self.assertIn(".dirty", deb)
        self.assertIn("-dirty", ver)

    def test_make_untracked_file_dirties_both_versions(self):
        (self.repo / "new_input.txt").write_text("consumed\n")
        deb, ver = self._make_versions()
        self.assertIn(".dirty", deb)
        self.assertIn("-dirty", ver)

    def test_make_changelog_only_delta_yields_clean_versions(self):
        (self.repo / "debian" / "changelog").write_text(
            "xpf (0.0.1) unstable; urgency=medium\n\n -- x\n")
        deb, ver = self._make_versions()
        self.assertNotIn(".dirty", deb)
        self.assertNotIn("-dirty", ver)

    # bind_deb_identity exact-byte comparison ------------------------------

    def _xpfd_output(self, version):
        return f"xpfd {version} (commit {self.head[:9]}, built test)\n"

    def test_bind_accepts_exact_clean_match(self):
        got_version, got_commit = bake.bind_deb_identity(
            self.package_version, self._xpfd_output(self.describe),
            skip_build=False, head_commit=self.head)
        self.assertEqual(got_version, self.describe)
        self.assertEqual(got_commit, self.head)

    def test_bind_rejects_dirty_binary_for_clean_commit(self):
        with self.assertRaises(SystemExit) as ctx:
            bake.bind_deb_identity(
                self.package_version,
                self._xpfd_output(self.describe + "-dirty"),
                skip_build=False, head_commit=self.head)
        self.assertIn("does not match package commit", str(ctx.exception.code))

    def test_bind_rejects_dirty_binary_under_skip_build(self):
        with self.assertRaises(SystemExit) as ctx:
            bake.bind_deb_identity(
                self.package_version,
                self._xpfd_output(self.describe + "-dirty"),
                skip_build=True, head_commit=self.head)
        self.assertIn("does not match package commit", str(ctx.exception.code))

    def test_bind_rejects_dirty_package_marker(self):
        with self.assertRaises(SystemExit) as ctx:
            bake.bind_deb_identity(
                self.package_version + ".dirty",
                self._xpfd_output(self.describe),
                skip_build=False, head_commit=self.head)
        self.assertIn("dirty source tree", str(ctx.exception.code))

    def test_bind_rejects_dirty_binary_without_local_source_object(self):
        unavailable_commit = "deadbeefcafe"
        package_version = "0.0.1+g" + unavailable_commit
        output = (
            f"xpfd release-dirty (commit {unavailable_commit}, built test)\n")
        with self.assertRaises(SystemExit) as ctx:
            bake.bind_deb_identity(
                package_version, output, skip_build=True, head_commit="")
        self.assertIn("dirty build bytes", str(ctx.exception.code))


    def test_every_xpf_file_staged_by_debian_rules_is_git_ignored(self):
        rules = (_ROOT / "debian" / "rules").read_text().replace("\\\n", " ")
        staged = set(re.findall(
            r"(?:\bcp\s+\S+\s+|>\s*)(debian/xpf\.[\w.-]+)(?=\s|$)",
            rules,
        ))
        self.assertTrue(staged, "no generated debian/xpf.* files found in debian/rules")
        for path in sorted(staged):
            result = subprocess.run(
                ["git", "check-ignore", "-q", path],
                cwd=_ROOT, capture_output=True, text=True,
            )
            self.assertEqual(
                result.returncode, 0,
                f"{path} staged by debian/rules is not git-ignored",
            )


if __name__ == "__main__":
    unittest.main()
