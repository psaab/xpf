"""#13206 (D10-14): libvirt teardown must not leak the day-0 ISO, lie about
sudo removal, or hide the ISO from --dry-run plans.

Cells:
  1. A failed libvirt deploy's _cleanup_libvirt removes the day-0 ISO as well
     as the overlay (failed deploys must not leak day-0 secrets) -- but only
     after the domain is confirmed gone, and never when it survives.
  2. destroy_libvirt: a `sudo rm -f` fallback that fails (nonzero rc, or the
     file still present) is a hard SystemExit, never "==> removed (sudo)".
  3. _cleanup_libvirt: same honesty -- a failed sudo fallback warns loudly and
     prints no removed message (best-effort path: warn, not SystemExit).
  4. --dry-run plans include the day-0 ISO: destroy_libvirt plans
     `rm -f <overlay> <iso>` and destroy_incus plans `rm -f <iso>`.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("xpf_deploy_13206", _HERE / "xpf-deploy.py")
xd = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xd)

PRESENT, ABSENT = xd.DOMAIN_PRESENT, xd.DOMAIN_ABSENT


def _cp(argv, rc, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, out, err)


def _touch(path):
    open(path, "w").close()


class CleanupRemovesDay0Iso13206(unittest.TestCase):
    def _run_cleanup(self, states, td):
        overlay = os.path.join(td, "fw1.qcow2")
        iso = os.path.join(td, "fw1-day0.iso")
        for f in (overlay, iso):
            _touch(f)
        first, rest = states[0], iter(states[1:])
        located = (first, [xd.LIBVIRT_SYSTEM_URI] if first == PRESENT else [])

        def virsh(argv, *a, **kw):
            if argv[:2] == ["virsh", "-c"]:
                return _cp(argv, 0)
            raise AssertionError(f"unexpected command {argv}")

        with mock.patch.object(xd, "day0_iso_path", return_value=iso), \
             mock.patch.object(xd, "_virsh_domain_locate", side_effect=lambda n: located), \
             mock.patch.object(xd, "_virsh_domain_state", side_effect=lambda n: next(rest)), \
             mock.patch.object(xd.subprocess, "run", side_effect=virsh), \
             contextlib.redirect_stdout(io.StringIO()):
            xd._cleanup_libvirt("fw1", overlay, iso)
        return overlay, iso

    def test_cleanup_removes_iso_and_overlay_once_domain_gone(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, iso = self._run_cleanup([PRESENT, ABSENT], td)
            self.assertFalse(os.path.exists(overlay))
            self.assertFalse(os.path.exists(iso),
                             "failed deploy leaked the day-0 ISO (day-0 secrets)")

    def test_cleanup_keeps_iso_when_domain_survives(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, iso = self._run_cleanup([PRESENT, PRESENT], td)
            self.assertTrue(os.path.exists(overlay))
            self.assertTrue(os.path.exists(iso),
                            "cleanup removed the day-0 ISO of a domain not confirmed gone")


class SudoRemovalHonesty13206(unittest.TestCase):
    def _patch_os_remove_denied(self):
        real_remove = os.remove

        def denied(path):
            raise PermissionError(f"denied: {path}")

        return mock.patch.object(xd.os, "remove", side_effect=denied), real_remove

    def _destroy(self, td, sudo_run):
        overlay = os.path.join(td, "fw1.qcow2")
        iso = os.path.join(td, "fw1-day0.iso")
        for f in (overlay, iso):
            _touch(f)
        patcher, _ = self._patch_os_remove_denied()
        out = io.StringIO()
        with mock.patch.object(xd, "libvirt_overlay_path", return_value=overlay), \
             mock.patch.object(xd, "day0_iso_path", return_value=iso), \
             mock.patch.object(xd, "_virsh_domain_locate", return_value=(ABSENT, [])), \
             mock.patch.object(xd.subprocess, "run", side_effect=sudo_run), \
             patcher, contextlib.redirect_stdout(out):
            xd.destroy_libvirt({"name": "fw1"}, xd.Runner(dry=False))
        return overlay, iso, out.getvalue()

    def test_destroy_dies_loudly_when_sudo_rm_fails(self):
        def sudo_run(argv, **kw):
            return _cp(argv, 1, err="sudo: a password is required")
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as cm:
                self._destroy(td, sudo_run)
            self.assertIn("could not remove", str(cm.exception.code))

    def test_destroy_dies_when_sudo_reports_success_but_file_remains(self):
        def sudo_run(argv, **kw):
            return _cp(argv, 0)
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as cm:
                self._destroy(td, sudo_run)
            self.assertIn("still exists", str(cm.exception.code))

    def test_destroy_succeeds_when_sudo_rm_actually_removes(self):
        real_remove = os.remove

        def sudo_run(argv, **kw):
            for f in argv[3:]:
                if os.path.exists(f):
                    real_remove(f)
            return _cp(argv, 0)

        with tempfile.TemporaryDirectory() as td:
            overlay, iso, out = self._destroy(td, sudo_run)
            self.assertFalse(os.path.exists(overlay))
            self.assertFalse(os.path.exists(iso))
            self.assertIn("(sudo)", out)

    def test_cleanup_warns_and_never_claims_removal_when_sudo_fails(self):
        overlay_dir = tempfile.TemporaryDirectory()
        self.addCleanup(overlay_dir.cleanup)
        overlay = os.path.join(overlay_dir.name, "fw1.qcow2")
        iso = os.path.join(overlay_dir.name, "fw1-day0.iso")
        for f in (overlay, iso):
            _touch(f)

        def sudo_run(argv, **kw):
            return _cp(argv, 1, err="sudo: a password is required")

        patcher, _ = self._patch_os_remove_denied()
        out = io.StringIO()
        with mock.patch.object(xd, "_virsh_domain_locate", return_value=(ABSENT, [])), \
             mock.patch.object(xd.subprocess, "run", side_effect=sudo_run), \
             patcher, contextlib.redirect_stdout(out):
            xd._cleanup_libvirt("fw1", overlay, iso)  # must NOT raise
        text = out.getvalue()
        self.assertIn("WARNING", text)
        self.assertIn("could not remove", text)
        self.assertNotIn("==> removed overlay", text)
        self.assertNotIn("(sudo)", text)
        self.assertTrue(os.path.exists(overlay))
        self.assertTrue(os.path.exists(iso))


class DryRunIncludesDay0Iso13206(unittest.TestCase):
    def _planned(self, fn):
        runner = xd.Runner(dry=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            fn({"name": "fw1"}, runner)
        return out.getvalue()

    def test_destroy_libvirt_dry_run_plans_iso_removal(self):
        text = self._planned(xd.destroy_libvirt)
        lines = [ln for ln in text.splitlines() if ln.startswith("rm -f")]
        self.assertTrue(lines, "dry-run planned no rm -f at all")
        self.assertTrue(any("fw1.qcow2" in ln and "fw1-day0.iso" in ln for ln in lines),
                        f"dry-run omitted the day-0 ISO: {lines!r}")

    def test_destroy_incus_dry_run_plans_iso_removal(self):
        text = self._planned(xd.destroy_incus)
        self.assertIn("incus delete --force fw1", text)
        lines = [ln for ln in text.splitlines() if ln.startswith("rm -f")]
        self.assertTrue(any("fw1-day0.iso" in ln for ln in lines),
                        f"dry-run omitted the day-0 ISO: {lines!r}")


if __name__ == "__main__":
    unittest.main()
