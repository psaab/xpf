#!/usr/bin/env python3
"""Unit tests for appliance name/image path-containment safety (#4905-B).

The appliance `name` and `image` are interpolated straight into filesystem
paths that xpf-deploy WRITES and REMOVES (often via sudo): the day-0 ISO in
CWD (`<name>-day0.iso`), and the per-VM overlay + shared golden qcow2 under
/var/lib/libvirt/images (`<name>.qcow2` / `<image>.qcow2`). Before the fix a
value bearing a path separator, a `..` component, an absolute path, or a
leading dash was accepted verbatim, so `../../../../tmp/owned` resolved to
`/tmp/owned.qcow2` and destroy/cleanup would `rm -f` (or `sudo rm -f`) it.

These tests assert:
  - validate_identifier() REJECTS separators, `..`, absolute paths, leading
    dashes, and shell metacharacters, and ACCEPTS ordinary names.
  - the sink helpers (day0_iso_path / libvirt_overlay_path / libvirt_golden_path)
    reject a traversal-bearing identifier and keep a valid one inside its
    managed dir.
  - validate_appliance() fails closed on a crafted name/image.

RED on revert: drop validate_identifier/contained_join (or stop calling them at
the sinks) and the traversal cases stop raising SystemExit — the asserts flip.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

xpf_deploy = load_subject("xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))


_BAD = [
    "../../../../tmp/owned",     # classic traversal
    "..",                        # bare parent
    ".",                         # bare current
    "foo/bar",                   # embedded separator
    "foo\\bar",                  # windows-ish separator
    "/etc/passwd",               # absolute
    "-rf",                       # leading dash (reads as a CLI flag)
    "a b",                       # space
    "a;rm -rf /",                # shell metacharacters
    "a$(whoami)",                # command substitution
    ".hidden",                   # leading dot
    "",                          # empty
]

_GOOD = ["fw", "xpf-appliance", "fw0", "node_1", "img.v2", "FW-Prod.01"]


class ValidateIdentifierTests(unittest.TestCase):
    def test_rejects_dangerous_identifiers(self):
        for v in _BAD:
            with self.assertRaises(SystemExit, msg=f"{v!r} should be rejected"):
                xpf_deploy.validate_identifier(v, "name")

    def test_accepts_ordinary_identifiers(self):
        for v in _GOOD:
            self.assertEqual(xpf_deploy.validate_identifier(v, "name"), v)


class SinkContainmentTests(unittest.TestCase):
    def test_day0_iso_path_rejects_traversal(self):
        with self.assertRaises(SystemExit):
            xpf_deploy.day0_iso_path("../../../../tmp/owned")

    def test_day0_iso_path_stays_in_cwd(self):
        p = xpf_deploy.day0_iso_path("fw")
        self.assertEqual(os.path.dirname(os.path.abspath(p)), os.getcwd())
        self.assertTrue(p.endswith("fw-day0.iso"))

    def test_overlay_path_rejects_traversal(self):
        with self.assertRaises(SystemExit):
            xpf_deploy.libvirt_overlay_path("../../etc/cron.d/x")

    def test_overlay_path_stays_in_images_dir(self):
        p = xpf_deploy.libvirt_overlay_path("fw")
        self.assertEqual(os.path.dirname(p), xpf_deploy.LIBVIRT_IMAGES)
        self.assertTrue(p.endswith("fw.qcow2"))

    def test_golden_path_rejects_traversal(self):
        with self.assertRaises(SystemExit):
            xpf_deploy.libvirt_golden_path("../../../tmp/owned")

    def test_golden_path_stays_in_images_dir(self):
        p = xpf_deploy.libvirt_golden_path("xpf-appliance")
        self.assertEqual(os.path.dirname(p), xpf_deploy.LIBVIRT_IMAGES)

    def test_contained_join_refuses_escape(self):
        # Even with the identifier gate bypassed, a basename that resolves out
        # of the managed dir is refused (defense-in-depth).
        with self.assertRaises(SystemExit):
            xpf_deploy.contained_join(xpf_deploy.LIBVIRT_IMAGES,
                                      "../../tmp/escape.qcow2", "overlay")


def _appliance(name="fw", image="xpf-appliance"):
    return {
        "name": name, "mode": "standalone", "node_id": None,
        "image": image, "cpu": 2, "memory": "4G", "config": None,
        "interfaces": [{"backing": "bridge", "source": "br0"}],
        "base_dir": "/tmp",
    }


class ValidateApplianceContainmentTests(unittest.TestCase):
    def test_crafted_name_rejected_at_load(self):
        with self.assertRaises(SystemExit):
            xpf_deploy.validate_appliance(
                _appliance(name="../../../../tmp/owned"), "test.yaml")

    def test_crafted_image_rejected_at_load(self):
        with self.assertRaises(SystemExit):
            xpf_deploy.validate_appliance(
                _appliance(image="../../../../tmp/golden"), "test.yaml")

    def test_valid_appliance_passes(self):
        # Should not raise: a well-formed appliance validates cleanly.
        xpf_deploy.validate_appliance(_appliance(), "test.yaml")


# --- #5992: --version path-safety at the artifact-name sink -----------------

# Versions that MUST be rejected before they name an artifact file.
_BAD_VERSIONS = [
    "../../../../etc/cron.d/x",   # traversal -> escapes --out
    "1.0/../x",                   # embedded traversal
    "..",                         # bare parent
    ".",                          # bare current
    "a/b",                        # embedded separator
    "a\\b",                       # windows-ish separator
    "/abs/1.2.3",                 # absolute
    "-rf",                        # leading dash (CLI-flag injection)
    ".hidden",                    # leading dot
    "1.0%n",                      # '%' (also the #5713 systemd class)
    "1.0 2.0",                    # space
    "a;rm -rf /",                 # shell metacharacters
    "a$(whoami)",                 # command substitution
    "1:2.3.4",                    # epoch ':' — excluded at the FILENAME sink
    "",                           # empty
]

# Versions the artifact naming legitimately produces (git-describe / semver);
# tightening the grammar must NOT reject these.
_GOOD_VERSIONS = [
    "1.2.3", "1.2.3-5-gabcdef", "1.2.3-dirty", "1.0.0+build.7",
    "1.0.0~rc1", "v1.2.3", "dev", "0.9.0+deb1", "2.4.1-rc3",
]


class ValidateVersionTests(unittest.TestCase):
    def test_rejects_path_escaping_versions(self):
        for v in _BAD_VERSIONS:
            with self.assertRaises(SystemExit, msg=f"{v!r} should be rejected"):
                xpf_deploy.validate_version(v, "--version")

    def test_accepts_build_versions(self):
        for v in _GOOD_VERSIONS:
            self.assertEqual(xpf_deploy.validate_version(v, "--version"), v)


class FetchVersionSinkTests(unittest.TestCase):
    """cmd_fetch must reject a crafted --version BEFORE it names/writes any
    artifact, so a traversal version cannot redirect the download out of --out.

    RED on revert: drop the validate_version(args.version) call in cmd_fetch (or
    the contained_join at the write) and the traversal version is accepted — the
    dst `os.path.join(out, "xpf-../../…​.qcow2")` escapes --out.
    """

    def _args(self, version, out, dry_run=False):
        import argparse as _ap
        return _ap.Namespace(
            version=version, image_url="https://example.invalid",
            out=out, alias=None, channel="stable", allow_rollback=True,
            qcow2_only=False, dry_run=dry_run, install_libvirt=False,
            no_import=False)

    def test_fetch_rejects_traversal_version(self):
        # dry-run so the ONLY thing that can raise is the path-safety gate
        # (validate_version, with contained_join as the belt) — not a network
        # failure. Reverting BOTH gates makes dry-run print the escaping dst and
        # return 0, so this assertRaises flips (clean RED-on-revert).
        import tempfile
        with tempfile.TemporaryDirectory() as out:
            with self.assertRaises(SystemExit):
                xpf_deploy.cmd_fetch(
                    self._args("../../../../tmp/owned", out, dry_run=True))
            # Nothing written outside out.
            self.assertFalse(
                os.path.exists(os.path.join(os.path.dirname(out), "owned.qcow2")))

    def test_fetch_accepts_legit_version_dryrun(self):
        # A legit version passes validation; dry-run performs no network/write
        # and the resolved artifact paths stay inside --out.
        import tempfile
        with tempfile.TemporaryDirectory() as out:
            rc = xpf_deploy.cmd_fetch(self._args("1.2.3-5-gabcdef", out, dry_run=True))
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
