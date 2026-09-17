#!/usr/bin/env python3
"""Unit test for the day-0 ISO file mode (#4586, ps-037-A10 A10-02).

build_config_drive() writes a day-0 config ISO whose sole payload is
xpf.conf — the most secret-bearing artifact on the box: the system
root-authentication hash, the security IKE pre-shared-key, the SNMP
community, and the DDNS tsig/api-token/password. xorriso/genisoimage
create that ISO under the process umask (a typical ~0022 yields a
world-readable 0644 file) and it lingers in CWD until an explicit
destroy. Any co-located UID could then `isoinfo -R -x /xpf.conf` the
secrets straight out of it.

The fix chmods the finished ISO to 0o600 immediately after it is built,
and stages the intermediate xpf.conf 0o600 too. These tests assert both:

  - after build_config_drive() the ISO has no group/other permission bits
    (mode & 0o077 == 0), regardless of the umask xorriso ran under;
  - the staged xpf.conf handed to the ISO builder is likewise owner-only.

On revert (drop the os.chmod(iso, 0o600), restore the 0o644 staging
chmod) both assertions go RED: the ISO comes back 0644 world-readable
and the staged copy 0644.
"""

from __future__ import annotations

import importlib.util
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy", Path(__file__).with_name("xpf-deploy.py")
)
xpf_deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xpf_deploy)


class _RealBuildRunner:
    """Runner that takes the real (non-dry) ISO build path."""

    def __init__(self):
        self.dry = False


class _DryBuildRunner:
    """Runner that plans the ISO build without executing it."""

    def __init__(self):
        self.dry = True


def _appliance(base_dir, name="fw-secret"):
    return {
        "name": name, "mode": "standalone", "node_id": None,
        "image": "xpf-appliance", "cpu": 2, "memory": "4G",
        "config": "day0.conf", "base_dir": base_dir, "interfaces": [],
    }


def _capture_config_drive_output(runner):
    """Build a temporary day-0 drive and return its operator output."""
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "day0.conf"), "w") as f:
            f.write("system {}\n")
        ap = _appliance(td, name="fw-validation")
        old_cwd = os.getcwd()
        os.chdir(td)
        try:
            output = io.StringIO()

            def fake_run_capture(argv, dry=False):
                out = argv[argv.index("-o") + 1]
                with open(out, "wb") as f:
                    f.write(b"\x00" * 2048)
                return ""

            with redirect_stdout(output), \
                    mock.patch.object(xpf_deploy.shutil, "which",
                                      return_value="/usr/bin/xorriso"), \
                    mock.patch.object(xpf_deploy, "run_capture",
                                      side_effect=fake_run_capture):
                xpf_deploy.build_config_drive(ap, runner)
            return output.getvalue()
        finally:
            os.chdir(old_cwd)



class Day0IsoModeTests(unittest.TestCase):
    def _build(self, staged_mode_holder):
        """Drive build_config_drive() with the ISO builder mocked out.

        The fake run_capture emulates xorriso: it materialises the target
        ISO world-readable (0o644) under a lax umask, exactly the defect
        the fix must correct. It also records the mode of the staged
        xpf.conf that is about to be packed, so we can assert the staging
        chmod too (the stage dir is rmtree'd right after this returns)."""

        def fake_run_capture(argv, dry=False):
            out = argv[argv.index("-o") + 1]
            stage = argv[-1]  # final positional arg = staging dir
            staged = os.path.join(stage, "xpf.conf")
            if os.path.isfile(staged):
                staged_mode_holder.append(os.stat(staged).st_mode & 0o777)
            with open(out, "wb") as f:
                f.write(b"\x00" * 2048)
            os.chmod(out, 0o644)  # world-readable, as the real tools leave it
            return ""

        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "day0.conf"), "w") as f:
                f.write('system { root-authentication { '
                        'encrypted-password "$6$topsecret"; } }\n')
            ap = _appliance(td)
            old_umask = os.umask(0o022)  # force the world-readable default
            old_cwd = os.getcwd()
            os.chdir(td)  # ISO lands in CWD — keep it inside the temp dir
            try:
                with mock.patch.object(xpf_deploy, "find_xpfd",
                                       return_value=None), \
                     mock.patch.object(xpf_deploy.shutil, "which",
                                       return_value="/usr/bin/xorriso"), \
                     mock.patch.object(xpf_deploy, "run_capture",
                                       side_effect=fake_run_capture):
                    iso = xpf_deploy.build_config_drive(ap, _RealBuildRunner())
                mode = os.stat(iso).st_mode & 0o777
            finally:
                os.chdir(old_cwd)
                os.umask(old_umask)
            return mode

    def test_iso_is_owner_only(self):
        staged = []
        mode = self._build(staged)
        # The secret-bearing ISO must not be readable by group/other.
        self.assertEqual(
            mode & 0o077, 0,
            f"day-0 ISO must be owner-only, got {oct(mode)} (#4586)")
        self.assertEqual(mode, 0o600, f"expected 0o600, got {oct(mode)}")

    def test_staged_conf_is_owner_only(self):
        staged = []
        self._build(staged)
        self.assertEqual(len(staged), 1,
                         "expected exactly one staged xpf.conf")
        self.assertEqual(
            staged[0] & 0o077, 0,
            f"staged xpf.conf must be owner-only, got {oct(staged[0])} (#4586)")


class Day0ValidationMessageTests(unittest.TestCase):
    def test_dry_run_does_not_claim_check_config_validation(self):
        # RED on revert: the old message says "check-config validated" even
        # though the dry-run returns before probing or invoking xpfd.
        with mock.patch.object(
                xpf_deploy, "find_xpfd",
                side_effect=AssertionError("dry-run must not probe xpfd")):
            output = _capture_config_drive_output(_DryBuildRunner())
        self.assertIn("not validated (dry-run)", output)
        self.assertNotIn("check-config validated", output)

    def test_missing_xpfd_warns_that_config_was_not_validated(self):
        # RED on revert: "skipping build-host validation" does not state the
        # config's validation status alongside the generated drive.
        with mock.patch.object(xpf_deploy, "find_xpfd", return_value=None):
            output = _capture_config_drive_output(_RealBuildRunner())
        self.assertIn("day-0 config not validated on build host", output)
        self.assertNotIn("check-config validated", output)


if __name__ == "__main__":
    unittest.main()
