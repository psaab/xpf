#!/usr/bin/env python3
"""Unit tests for three xpf-deploy robustness/UX fixes (fable-review-165).

H-21  a failing hypervisor command dies with the tool's REAL stderr
      ("command failed (rc=N): <cmd>\\n<stderr>"), not a bare
      CalledProcessError traceback. On revert (Runner.run does
      check=True with the output swallowed) the failing command raises
      CalledProcessError instead of SystemExit and the assertions go RED.

H-26  `--no-start` on libvirt DEFINES but does not START the domain — the
      deployer runs `virt-install --print-xml` and `virsh define`s the XML
      instead of `virt-install --import` (which boots). The docs say the
      tool RUNS virt-install, not "emits a command you run". On revert
      (unconditional --import boot; docs say "emits") both go RED.

H-27  a preflight fails BEFORE mutating on a missing image/golden/bridge or
      an already-taken name; a mid-deploy failure cleans up the half-created
      instance; and a `destroy` verb tears a VM down. On revert (no
      preflight/cleanup/destroy) the assertions go RED.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy", Path(__file__).with_name("xpf-deploy.py")
)
xpf_deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xpf_deploy)

_REPO = Path(__file__).resolve().parents[2]


class RecordingRunner:
    """Runner that records every argv instead of executing it (dry=True)."""

    def __init__(self):
        self.dry = True
        self.calls = []

    def run(self, argv):
        self.calls.append(list(argv))
        return ""


def _find_call(calls, prog):
    for c in calls:
        if c and c[0] == prog:
            return c
    return None


def _bridge_ap(name="fw"):
    return {
        "name": name, "mode": "standalone", "node_id": None,
        "image": "xpf-appliance", "cpu": 2, "memory": "4G",
        "interfaces": [
            {"_name": "fxp0", "backing": "bridge", "source": "br-mgmt"}],
    }


# ── H-21: failing hypervisor command reports its stderr, not a traceback ──
class StderrOnFailureTests(unittest.TestCase):
    def test_run_capture_dies_with_command_and_stderr(self):
        with self.assertRaises(SystemExit) as cm:
            xpf_deploy.run_capture(
                ["sh", "-c", "echo real-error-detail >&2; exit 3"])
        msg = str(cm.exception.code)
        # RED on revert: run_capture does not exist / does not surface stderr.
        self.assertIn("real-error-detail", msg)
        self.assertIn("rc=3", msg)
        self.assertIn("sh", msg)

    def test_runner_run_surfaces_stderr_not_bare_traceback(self):
        # The finding's cited symbol: Runner.run. On revert it does
        # subprocess.run(check=True) and raises CalledProcessError (NOT
        # SystemExit) with the stderr swallowed -> assertRaises(SystemExit) RED.
        runner = xpf_deploy.Runner(dry=False)
        with self.assertRaises(SystemExit) as cm:
            runner.run(["sh", "-c", "echo boom-from-tool >&2; exit 1"])
        self.assertIn("boom-from-tool", str(cm.exception.code))

    def test_run_capture_dry_run_prints_and_does_not_execute(self):
        # dry-run must never raise and never run the command.
        self.assertEqual(
            xpf_deploy.run_capture(["false"], dry=True), "")


# ── H-26: --no-start on libvirt defines-but-does-not-start; docs say "runs" ─
class LibvirtNoStartTests(unittest.TestCase):
    def test_no_start_defines_via_print_xml_and_virsh_define(self):
        r = RecordingRunner()
        xpf_deploy.deploy_libvirt(_bridge_ap("fw-ns"), r, start=False)
        virt = _find_call(r.calls, "virt-install")
        self.assertIsNotNone(virt, "virt-install was not invoked")
        # RED on revert: no --print-xml (it just runs --import, which boots).
        self.assertIn("--print-xml", virt)
        vdef = _find_call(r.calls, "virsh")
        self.assertIsNotNone(vdef, "virsh define was not invoked for --no-start")
        # #9669: virsh names the system URI, where the disks live.
        self.assertEqual(vdef[:4], ["virsh", "-c", xpf_deploy.LIBVIRT_SYSTEM_URI, "define"])

    def test_start_path_boots_without_print_xml_or_virsh_define(self):
        r = RecordingRunner()
        xpf_deploy.deploy_libvirt(_bridge_ap("fw-go"), r, start=True)
        virt = _find_call(r.calls, "virt-install")
        self.assertIsNotNone(virt)
        self.assertNotIn("--print-xml", virt)
        self.assertIsNone(_find_call(r.calls, "virsh"),
                          "start=True must not virsh define")

    def test_docs_say_runs_not_emits(self):
        readme = (_REPO / "examples/deploy/README.md").read_text()
        quick = (_REPO / "docs/deploy-quickstart.md").read_text()
        # RED on revert: the docs claim the tool "emits a command you run".
        self.assertNotIn("emits a `virt-install` command", readme)
        self.assertNotIn("the tool emits a", quick)
        self.assertIn("runs `virt-install", readme)
        self.assertIn("runs\n`virt-install`", quick)


# ── H-27: preflight, cleanup-on-failure, destroy verb ─────────────────────
class DestroyVerbTests(unittest.TestCase):
    def test_destroy_incus_deletes_instance(self):
        r = RecordingRunner()
        xpf_deploy.destroy_incus(_bridge_ap("fw-del"), r)
        # RED on revert: destroy_incus does not exist.
        self.assertEqual(_find_call(r.calls, "incus"),
                         ["incus", "delete", "--force", "fw-del"])

    def test_destroy_libvirt_undefines_and_removes_overlay(self):
        r = RecordingRunner()
        xpf_deploy.destroy_libvirt(_bridge_ap("fw-dl"), r)
        progs = [c[0] for c in r.calls]
        self.assertIn("virsh", progs)
        # destroy + undefine + overlay rm are all planned.
        joined = [" ".join(c) for c in r.calls]
        # #9669: every virsh argv names its URI, and teardown plans both.
        for uri in xpf_deploy.LIBVIRT_PROBE_URIS:
            self.assertTrue(any(j.startswith(f"virsh -c {uri} undefine") for j in joined), joined)
        self.assertTrue(any(j.startswith("rm -f") and ".qcow2" in j
                            for j in joined))

    def test_destroy_subcommand_is_wired(self):
        # End-to-end: the CLI actually dispatches `destroy` (RED on revert:
        # "destroy" is not a recognized subcommand -> treated as a YAML file).
        script = _REPO / "scripts/deploy/xpf-deploy.py"
        out = subprocess.run(
            ["python3", str(script), "--dry-run", "destroy",
             str(_REPO / "examples/deploy/standalone.yaml")],
            capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("incus delete --force", out.stdout)


class PreflightTests(unittest.TestCase):
    def test_incus_preflight_dies_on_missing_prereqs(self):
        # No incus objects exist -> preflight fails BEFORE any mutation.
        with mock.patch.object(xpf_deploy, "_incus_exists",
                               side_effect=lambda kind, name: False):
            runner = xpf_deploy.Runner(dry=False)
            with self.assertRaises(SystemExit) as cm:
                xpf_deploy.preflight_incus(_bridge_ap("fw-pf"), runner)
        msg = str(cm.exception.code)
        self.assertIn("preflight failed", msg)
        self.assertIn("image alias", msg)

    def test_incus_preflight_points_existing_name_at_destroy(self):
        # A re-run against an already-deployed name must NOT dead-end on a bare
        # "already exists" — it points at `destroy` (idempotency UX, H-27).
        with mock.patch.object(xpf_deploy, "_incus_exists",
                               side_effect=lambda kind, name: True):
            runner = xpf_deploy.Runner(dry=False)
            with self.assertRaises(SystemExit) as cm:
                xpf_deploy.preflight_incus(_bridge_ap("fw-dup"), runner)
        msg = str(cm.exception.code)
        self.assertIn("already exists", msg)
        self.assertIn("destroy", msg)

    def test_libvirt_preflight_dies_on_missing_golden(self):
        orig = xpf_deploy.LIBVIRT_IMAGES
        try:
            with tempfile.TemporaryDirectory() as tmp:
                xpf_deploy.LIBVIRT_IMAGES = os.path.join(tmp, "images")
                ap = _bridge_ap("fw-lv")
                ap["interfaces"] = [
                    {"_name": "fxp0", "backing": "bridge", "source": "lo"}]
                runner = xpf_deploy.Runner(dry=False)
                with self.assertRaises(SystemExit) as cm:
                    xpf_deploy.preflight_libvirt(ap, runner)
            msg = str(cm.exception.code)
            self.assertIn("golden image not found", msg)
        finally:
            xpf_deploy.LIBVIRT_IMAGES = orig

    def test_preflight_skipped_in_dry_run(self):
        # Dry-run plans against resources that may not exist yet -> no die.
        runner = xpf_deploy.Runner(dry=True)
        xpf_deploy.preflight_incus(_bridge_ap("fw-dry"), runner)   # must not raise
        xpf_deploy.preflight_libvirt(_bridge_ap("fw-dry"), runner)


class CleanupOnFailureTests(unittest.TestCase):
    def test_incus_cleanup_deletes_half_created_instance(self):
        class FailAtRunner:
            """Succeeds through `incus init`, then dies on the device add —
            mirrors a real Runner hitting a missing bridge mid-deploy."""

            def __init__(self):
                self.dry = False
                self.calls = []

            def run(self, argv):
                self.calls.append(list(argv))
                if "device" in argv and "add" in argv:
                    xpf_deploy.die("simulated: incus network br-lan not found")
                return ""

        ap = _bridge_ap("fw-clean")
        runner = FailAtRunner()
        recorder = mock.MagicMock(
            return_value=subprocess.CompletedProcess([], 0, "", ""))
        with mock.patch.object(xpf_deploy, "preflight_incus",
                               lambda a, r: None), \
             mock.patch.object(xpf_deploy, "build_config_drive",
                               lambda a, r: None), \
             mock.patch.object(xpf_deploy.subprocess, "run", recorder):
            with self.assertRaises(SystemExit):
                xpf_deploy.deploy_incus(ap, runner, start=False)
        # RED on revert: no cleanup -> the failed instance is never deleted.
        deletes = [c.args[0] for c in recorder.call_args_list
                   if c.args and c.args[0][:3] == ["incus", "delete", "--force"]]
        self.assertTrue(deletes, "half-created instance was not cleaned up")
        self.assertEqual(deletes[0], ["incus", "delete", "--force", "fw-clean"])




class VirshProbeThreeStateTests(unittest.TestCase):
    """#8977: a failed virsh probe must not read as 'domain absent'.

    `virsh dominfo` exits non-zero for a missing domain AND for an unreachable
    libvirtd, a permissions failure, or a timeout. Collapsing those to False
    made "we could not tell" read as "there is nothing there" -- and both
    teardown paths guarded only the DESTROY on it while leaving the disk
    UNLINK unguarded, so a live VM's overlay was removed anyway.

    ONE FUNCTION, TWO OPERATIONS, ONE GUARDED -- and the guard was on the
    survivable half. Skipping a shutdown is harmless; deleting a running VM's
    backing store is not, and one path escalates to `sudo rm -f` when the
    unlink is refused.
    """

    @staticmethod
    def _completed(rc, stderr=""):
        return subprocess.CompletedProcess(args=["virsh"], returncode=rc,
                                           stdout="", stderr=stderr)

    def test_probe_separates_absent_from_unknown_8977(self):
        cases = [
            (0, "", xpf_deploy.DOMAIN_PRESENT),
            (1, "error: failed to get domain 'fw1'", xpf_deploy.DOMAIN_ABSENT),
            (1, "error: failed to connect to the hypervisor", xpf_deploy.DOMAIN_UNKNOWN),
            (1, "error: authentication failed: permission denied", xpf_deploy.DOMAIN_UNKNOWN),
            (1, "", xpf_deploy.DOMAIN_UNKNOWN),
        ]
        for rc, err, want in cases:
            with mock.patch.object(subprocess, "run",
                                   return_value=self._completed(rc, err)):
                got = xpf_deploy._virsh_domain_state("fw1")
            self.assertEqual(got, want, f"rc={rc} stderr={err!r}")

    def test_missing_virsh_is_unknown_9325(self):
        # #9325 reversed this cell. #8977 kept a missing binary as ABSENT on the
        # claim "virsh is not installed, so no libvirt domain can exist". virsh
        # is a CLIENT: a restricted unit PATH, sudo's secure_path or a half-done
        # package upgrade raise FileNotFoundError while libvirtd runs the
        # domain, and ABSENT is the state that lets teardown unlink its disk.
        with mock.patch.object(subprocess, "run", side_effect=FileNotFoundError()):
            self.assertEqual(xpf_deploy._virsh_domain_state("fw1"),
                             xpf_deploy.DOMAIN_UNKNOWN)

    def test_destroy_refuses_to_unlink_when_state_unknown_8977(self):
        removed = []
        with tempfile.TemporaryDirectory() as td:
            overlay = os.path.join(td, "fw1.qcow2")
            open(overlay, "w").close()
            # #9669: destroy / cleanup ask _virsh_domain_locate (both URIs) first.
            with mock.patch.object(xpf_deploy, "_virsh_domain_locate",
                                   return_value=(xpf_deploy.DOMAIN_UNKNOWN, [])), \
                 mock.patch.object(xpf_deploy, "libvirt_overlay_path",
                                   return_value=overlay), \
                 mock.patch.object(xpf_deploy, "day0_iso_path",
                                   return_value=os.path.join(td, "fw1.iso")), \
                 mock.patch.object(os, "remove", side_effect=removed.append):
                with self.assertRaises(SystemExit) as cm:
                    xpf_deploy.destroy_libvirt(_bridge_ap("fw1"), xpf_deploy.Runner(dry=False))
        self.assertIn("cannot determine", str(cm.exception.code))
        self.assertEqual(removed, [],
                         "#8977: teardown removed a file while the domain's "
                         "existence was UNKNOWN -- if the domain is running "
                         "that deletes a live VM's disk")
        self.assertTrue(os.path.basename(overlay) in str(cm.exception.code)
                        or overlay in str(cm.exception.code),
                        "the refusal must name the file it declined to remove")

    def test_destroy_still_unlinks_when_absent_8977(self):
        # CONTROL. The whole point of the probe is to allow teardown when the
        # domain is genuinely gone. A fix that refuses on ABSENT as well would
        # pass the assertion above and break every ordinary teardown.
        removed = []
        with tempfile.TemporaryDirectory() as td:
            overlay = os.path.join(td, "fw1.qcow2")
            iso = os.path.join(td, "fw1.iso")
            open(overlay, "w").close()
            # #9669: destroy asks _virsh_domain_locate (both URIs) first.
            with mock.patch.object(xpf_deploy, "_virsh_domain_locate",
                                   return_value=(xpf_deploy.DOMAIN_ABSENT, [])), \
                 mock.patch.object(xpf_deploy, "libvirt_overlay_path",
                                   return_value=overlay), \
                 mock.patch.object(xpf_deploy, "day0_iso_path", return_value=iso), \
                 mock.patch.object(os, "remove", side_effect=removed.append):
                try:
                    xpf_deploy.destroy_libvirt(_bridge_ap("fw1"),
                                               xpf_deploy.Runner(dry=False))
                except SystemExit as exc:
                    # Caught explicitly so the CONTROL explains itself. A fix
                    # that refuses on ABSENT as well as UNKNOWN kills this cell
                    # either way, but without this it dies as an unexplained
                    # SystemExit -- caught by the wrong branch, which reads as
                    # a crash rather than as the control it is.
                    self.fail("CONTROL FAILED: an ABSENT domain must still have "
                              "its overlay removed, but teardown refused: "
                              f"{exc.code}")
        self.assertEqual(removed, [overlay],
                         "CONTROL FAILED: an ABSENT domain must still have its "
                         "overlay removed, or teardown never cleans up")

    def test_cleanup_leaves_overlay_when_state_unknown_8977(self):
        # The failed-deploy cleanup path. It must not raise -- the caller is
        # already handling a failure and re-raising would replace its diagnosis
        # -- but it must not delete either.
        removed = []
        with tempfile.TemporaryDirectory() as td:
            overlay = os.path.join(td, "fw1.qcow2")
            open(overlay, "w").close()
            # #9669: destroy / cleanup ask _virsh_domain_locate (both URIs) first.
            with mock.patch.object(xpf_deploy, "_virsh_domain_locate",
                                   return_value=(xpf_deploy.DOMAIN_UNKNOWN, [])), \
                 mock.patch.object(os, "remove", side_effect=removed.append):
                xpf_deploy._cleanup_libvirt("fw1", overlay)
        self.assertEqual(removed, [],
                         "#8977: the cleanup path removed the overlay while the "
                         "domain's existence was UNKNOWN. This path escalates to "
                         "`sudo rm -f` when the unlink is refused, so it is the "
                         "one that gets past a permissions barrier")


# #9669: the guard runs LAST. It used to sit above the #8977 class, and
# `python3 <file>` (how scripts/run-selftests.sh runs it) exits inside
# unittest.main() before that class is defined, so its five cells never ran
# in `make selftest`.
if __name__ == "__main__":
    unittest.main()
