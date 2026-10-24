#!/usr/bin/env python3
"""Unit tests for bake.py's --version path-safety (#5992).

bake.py substitutes `--version` straight into artifact WRITE paths under
`--out`: `os.path.join(a.out, f"xpf-{ver}.qcow2")` (+ the .incus-metadata and
.SHA256SUMS siblings). Before the fix a value bearing a path separator, a `..`
component, an absolute path, or a leading dash was accepted verbatim, so
`--version '../../../etc/cron.d/x'` would write outside `--out`.

These tests assert validate_version() REJECTS path-escaping / crafted versions
and ACCEPTS the git-describe / semver versions the build legitimately produces,
in parity with scripts/deploy/xpf-deploy.py:validate_version.

RED on revert: drop validate_version (or stop calling it after parse_args) and
the traversal versions stop raising SystemExit — the asserts flip.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

bake = load_subject("xpf_bake", Path(__file__).with_name("bake.py"))


_BAD = [
    "../../../../etc/cron.d/x", "1.0/../x", "..", ".", "a/b", "a\\b",
    "/abs/1.2.3", "-rf", ".hidden", "1.0%n", "1.0 2.0", "a;rm -rf /",
    "a$(whoami)", "1:2.3.4", "",
]
_GOOD = [
    "1.2.3", "1.2.3-5-gabcdef", "1.2.3-dirty", "1.0.0+build.7",
    "1.0.0~rc1", "v1.2.3", "dev", "0.9.0+deb1",
]


class BakeValidateVersionTests(unittest.TestCase):
    def test_rejects_path_escaping_versions(self):
        for v in _BAD:
            with self.assertRaises(SystemExit, msg=f"{v!r} should be rejected"):
                bake.validate_version(v, "--version")

    def test_accepts_build_versions(self):
        for v in _GOOD:
            self.assertEqual(bake.validate_version(v, "--version"), v)

    def test_charset_parity_with_deploy(self):
        # The bake and xpf-deploy validators must accept/reject the SAME
        # versions (both name xpf-<ver> artifacts) — a drift is a real bug.
        deploy = load_subject(
            "xpf_deploy_p", Path(__file__).resolve().parents[1]
            / "deploy" / "xpf-deploy.py")
        for v in _GOOD + _BAD:
            bake_ok = deploy_ok = True
            try:
                bake.validate_version(v, "x")
            except SystemExit:
                bake_ok = False
            try:
                deploy.validate_version(v, "x")
            except SystemExit:
                deploy_ok = False
            self.assertEqual(bake_ok, deploy_ok,
                             f"bake vs deploy disagree on {v!r}")


if __name__ == "__main__":
    unittest.main()
