#!/usr/bin/env python3
"""Regression tests for #10850's version-bound image package selection."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
_SPEC = importlib.util.spec_from_file_location("xpf_bake_10850", _HERE / "bake.py")
bake = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bake)

_HAVE_DPKG_DEB = shutil.which("dpkg-deb") is not None


@unittest.skipUnless(_HAVE_DPKG_DEB, "dpkg-deb not installed")
class BakePackageIdentityTests(unittest.TestCase):
    def setUp(self):
        self.deb_dir = tempfile.mkdtemp(prefix="xpf-bake-identity-")
        self.addCleanup(shutil.rmtree, self.deb_dir, ignore_errors=True)

    def _build_deb(self, filename_version, control_version=None):
        pkg = Path(self.deb_dir) / f"build-{filename_version}"
        control = pkg / "DEBIAN" / "control"
        control.parent.mkdir(parents=True)
        control.write_text(
            "Package: xpf\n"
            f"Version: {control_version or filename_version}\n"
            "Architecture: amd64\n"
            "Maintainer: xpf test <test@example.invalid>\n"
            "Description: package identity fixture\n")
        path = Path(self.deb_dir) / f"xpf_{filename_version}_amd64.deb"
        subprocess.run(["dpkg-deb", "--build", str(pkg), str(path)],
                       check=True, capture_output=True, text=True)
        return path

    def test_new_requested_version_beats_newer_mtime(self):
        old = self._build_deb("0.0.10+g0123456789ab")
        requested = "0.0.11+g123456789abc"
        new = self._build_deb(requested)
        os.utime(old, (2_000_000_000, 2_000_000_000))
        os.utime(new, (1_000_000_000, 1_000_000_000))

        self.assertEqual(bake.select_xpf_deb(self.deb_dir, requested), str(new))

    def test_stale_only_deb_is_refused_even_with_fresh_mtime(self):
        stale = self._build_deb("0.0.10+g0123456789ab")
        os.utime(stale, (2_000_000_000, 2_000_000_000))

        with self.assertRaises(SystemExit) as ctx:
            bake.select_xpf_deb(self.deb_dir, "0.0.11+g123456789abc")
        self.assertIn("no xpf .deb", str(ctx.exception.code))
        self.assertIn("0.0.11+g123456789abc", str(ctx.exception.code))

    def test_filename_version_must_match_control_metadata(self):
        filename_version = "0.0.11+g123456789abc"
        self._build_deb(filename_version, "0.0.10+g0123456789ab")

        with self.assertRaises(SystemExit) as ctx:
            bake.select_xpf_deb(self.deb_dir, filename_version)
        self.assertIn("dpkg-deb Version", str(ctx.exception.code))

    def test_staged_xpfd_identity_matches_package_and_current_head(self):
        head = subprocess.check_output(
            ["git", "-C", str(_ROOT), "rev-parse", "HEAD"], text=True).strip()
        package_version = "0.0.10850+g" + head[:12]
        xpfd_version = subprocess.check_output(
            ["git", "-C", str(_ROOT), "describe", "--tags", "--always", head],
            text=True).strip()
        output = f"xpfd {xpfd_version} (commit {head[:9]}, built test)\n"

        got_version, got_commit = bake.bind_deb_identity(
            package_version, output, skip_build=False, head_commit=head)
        self.assertEqual(got_version, xpfd_version)
        self.assertEqual(got_commit, head)

    def test_skip_build_records_the_package_commit_not_current_head(self):
        current = subprocess.check_output(
            ["git", "-C", str(_ROOT), "rev-parse", "HEAD"], text=True).strip()
        package_commit = subprocess.check_output(
            ["git", "-C", str(_ROOT), "rev-parse", "HEAD^"], text=True).strip()
        package_version = "0.0.10849+g" + package_commit[:12]
        xpfd_version = subprocess.check_output(
            ["git", "-C", str(_ROOT), "describe", "--tags", "--always",
             package_commit], text=True).strip()
        output = f"xpfd {xpfd_version} (commit {package_commit[:9]}, built test)\n"

        got_version, got_commit = bake.bind_deb_identity(
            package_version, output, skip_build=True, head_commit=current)
        self.assertEqual(got_version, xpfd_version)
        self.assertEqual(got_commit, package_commit)
        self.assertNotEqual(got_commit, current)

    def test_package_and_staged_binary_commit_mismatch_is_refused(self):
        package_version = "0.0.11+g123456789abc"
        output = "xpfd release (commit fedcba987654, built test)\n"

        with self.assertRaises(SystemExit) as ctx:
            bake.bind_deb_identity(
                package_version, output, skip_build=True, head_commit="")
        self.assertIn("staged xpfd reports", str(ctx.exception.code))


if __name__ == "__main__":
    unittest.main()
