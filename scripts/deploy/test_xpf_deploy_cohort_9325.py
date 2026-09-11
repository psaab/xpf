"""#9325: five xpf-deploy defects, one cell per state.

1 and 3: a teardown unlinked a disk without a probe affirmatively reporting the
  domain gone -- `virsh destroy`'s status was ignored, `undefine` of a RUNNING
  domain succeeds (it becomes transient), and a missing `virsh` read as ABSENT.
  `_incus_exists` had the same missing-binary shape in front of the day-0 drive.
2: a missing `qemu-img` read as "no backing file", so the golden-overwrite guard
  passed with a sibling overlay present.
4: a `--skip-validate` image signs `validated: false` and nothing deploy-side
  read it.
5: the golden temp name was predictable, so a planted symlink redirected the
  copy and was renamed over the golden; the sudo arm leaked its temp on failure.

The controls (named *_control) are the states that must keep working. Every
other cell reds against the pre-#9325 source.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
sys.path.insert(0, str(_ROOT / "scripts" / "dist"))

_SPEC = importlib.util.spec_from_file_location("xpf_deploy_9325", _HERE / "xpf-deploy.py")
xd = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xd)

import sign  # noqa: E402

PRESENT, ABSENT, UNKNOWN = xd.DOMAIN_PRESENT, xd.DOMAIN_ABSENT, xd.DOMAIN_UNKNOWN


def _completed(rc, stderr="", stdout=""):
    return subprocess.CompletedProcess(["x"], rc, stdout, stderr)


def _quiet():
    return contextlib.redirect_stdout(io.StringIO())


class _Reached(BaseException):
    """Raised by a stub the code must NOT reach; BaseException so no
    `except Exception` in the path under test can swallow it."""


# ── items 1 and 3: teardown needs an affirmative ABSENT ─────────────────────
class MissingBinaryIsNotAbsence9325(unittest.TestCase):
    def test_missing_virsh_is_unknown(self):
        with mock.patch.object(xd.subprocess, "run", side_effect=FileNotFoundError("virsh")):
            self.assertEqual(xd._virsh_domain_state("fw1"), UNKNOWN)

    def test_destroy_libvirt_with_virsh_missing_removes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, iso = os.path.join(td, "fw1.qcow2"), os.path.join(td, "fw1.iso")
            for f in (overlay, iso):
                open(f, "w").close()
            with mock.patch.object(xd, "libvirt_overlay_path", return_value=overlay), \
                 mock.patch.object(xd, "day0_iso_path", return_value=iso), \
                 mock.patch.object(xd.subprocess, "run", side_effect=FileNotFoundError("virsh")), \
                 _quiet():
                with self.assertRaises(SystemExit):
                    xd.destroy_libvirt({"name": "fw1"}, xd.Runner(dry=False))
            self.assertTrue(os.path.exists(overlay) and os.path.exists(iso),
                            "a virsh this process cannot run removed a domain's disks")


class IncusThreeStates9325(unittest.TestCase):
    def test_incus_state_per_answer(self):
        cases = [
            (FileNotFoundError("incus"), UNKNOWN),
            (PermissionError("incus"), UNKNOWN),
            (_completed(0), PRESENT),
            # measured wording of a missing instance
            (_completed(1, 'Error: Failed to fetch instance "fw1" in project "default": Instance not found'), ABSENT),
            (_completed(1, 'Error: Get "http://unix.socket/1.0": dial unix /var/lib/incus/unix.socket: connect: permission denied'), UNKNOWN),
            (_completed(1, ""), UNKNOWN),
        ]
        for answer, want in cases:
            kw = {"side_effect": answer} if isinstance(answer, BaseException) else {"return_value": answer}
            with mock.patch.object(xd.subprocess, "run", **kw):
                self.assertEqual(xd._incus_state("instance", "fw1"), want, repr(answer))

    def _destroy(self, states, iso):
        seq = iter(states)
        with mock.patch.object(xd, "day0_iso_path", return_value=iso), \
             mock.patch.object(xd, "_incus_state", side_effect=lambda k, n: next(seq)), \
             mock.patch.object(xd, "run_capture", return_value=""), _quiet():
            xd.destroy_incus({"name": "fw1"}, xd.Runner(dry=False))

    def test_destroy_incus_with_incus_missing_keeps_the_day0_drive(self):
        with tempfile.TemporaryDirectory() as td:
            iso = os.path.join(td, "fw1.iso")
            open(iso, "w").close()
            with mock.patch.object(xd, "day0_iso_path", return_value=iso), \
                 mock.patch.object(xd.subprocess, "run", side_effect=FileNotFoundError("incus")), \
                 _quiet():
                with self.assertRaises(SystemExit):
                    xd.destroy_incus({"name": "fw1"}, xd.Runner(dry=False))
            self.assertTrue(os.path.exists(iso), "an unrunnable incus removed the day-0 drive")

    def test_destroy_incus_refuses_when_the_instance_survives_delete(self):
        with tempfile.TemporaryDirectory() as td:
            iso = os.path.join(td, "fw1.iso")
            open(iso, "w").close()
            with self.assertRaises(SystemExit):
                self._destroy([PRESENT, PRESENT], iso)
            self.assertTrue(os.path.exists(iso))

    def test_destroy_incus_absent_removes_the_day0_drive_control(self):
        with tempfile.TemporaryDirectory() as td:
            iso = os.path.join(td, "fw1.iso")
            open(iso, "w").close()
            self._destroy([ABSENT], iso)
            self.assertFalse(os.path.exists(iso))

    def test_destroy_incus_removes_the_drive_after_a_confirmed_delete_control(self):
        with tempfile.TemporaryDirectory() as td:
            iso = os.path.join(td, "fw1.iso")
            open(iso, "w").close()
            self._destroy([PRESENT, ABSENT], iso)
            self.assertFalse(os.path.exists(iso))


class TeardownNeedsAffirmativeAbsence9325(unittest.TestCase):
    """destroy FAILS (a running domain it could not stop, or a stopped one),
    undefine SUCCEEDS -- which for a running domain leaves it running as a
    transient domain. Only the re-probe can tell the two apart."""

    def _virsh(self):
        # #9669: every virsh argv names its URI (`virsh -c <uri> <verb> ...`).
        def run(argv, *a, **kw):
            verb = argv[3] if argv[:2] == ["virsh", "-c"] and len(argv) > 3 else None
            if verb == "destroy":
                return _completed(1, "error: Failed to destroy domain 'fw1'")
            if verb == "undefine":
                return _completed(0)
            raise AssertionError(f"unexpected command {argv}")
        return run

    def _run(self, fn, states, td):
        overlay, iso = os.path.join(td, "fw1.qcow2"), os.path.join(td, "fw1.iso")
        for f in (overlay, iso):
            open(f, "w").close()
        # #9669: the first probe is the both-URI locate (state + the URIs holding
        # the domain); the re-probe after teardown is the aggregated state. The
        # cells' state sequences keep their #9325 meaning: states[0] is the
        # first answer, the rest are the re-probes.
        first, rest = states[0], iter(states[1:])
        located = (first, [xd.LIBVIRT_SYSTEM_URI] if first == PRESENT else [])
        with mock.patch.object(xd, "libvirt_overlay_path", return_value=overlay), \
             mock.patch.object(xd, "day0_iso_path", return_value=iso), \
             mock.patch.object(xd, "_virsh_domain_locate", side_effect=lambda n: located), \
             mock.patch.object(xd, "_virsh_domain_state", side_effect=lambda n: next(rest)), \
             mock.patch.object(xd.subprocess, "run", side_effect=self._virsh()), _quiet():
            if fn == "destroy":
                xd.destroy_libvirt({"name": "fw1"}, xd.Runner(dry=False))
            else:
                xd._cleanup_libvirt("fw1", overlay)
        return overlay, iso

    def test_destroy_refuses_when_the_domain_survives_undefine(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as cm:
                self._run("destroy", [PRESENT, PRESENT], td)
            self.assertIn("not confirmed gone", str(cm.exception.code))
            self.assertTrue(os.path.exists(os.path.join(td, "fw1.qcow2")))
            self.assertTrue(os.path.exists(os.path.join(td, "fw1.iso")))

    def test_destroy_refuses_when_the_reprobe_is_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit):
                self._run("destroy", [PRESENT, UNKNOWN], td)
            self.assertTrue(os.path.exists(os.path.join(td, "fw1.qcow2")))

    def test_destroy_removes_the_disks_once_the_domain_is_confirmed_gone_control(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, iso = self._run("destroy", [PRESENT, ABSENT], td)
            self.assertFalse(os.path.exists(overlay) or os.path.exists(iso))

    def test_cleanup_leaves_the_overlay_when_the_domain_survives_undefine(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, _ = self._run("cleanup", [PRESENT, PRESENT], td)
            self.assertTrue(os.path.exists(overlay))

    def test_cleanup_removes_the_overlay_once_the_domain_is_confirmed_gone_control(self):
        with tempfile.TemporaryDirectory() as td:
            overlay, _ = self._run("cleanup", [PRESENT, ABSENT], td)
            self.assertFalse(os.path.exists(overlay))


# ── item 2: a qemu-img that cannot run is "could not ask" ───────────────────
class QemuImgMissingIsIndeterminate9325(unittest.TestCase):
    """The measured table from #9325: only the third state changes.

        state                                  before     after
        fresh host, no golden yet              PROCEED    PROCEED
        golden present, no sibling .qcow2      PROCEED    PROCEED
        golden present + a sibling overlay     PROCEED    REFUSED
    """

    def setUp(self):
        self.imgdir = tempfile.mkdtemp(prefix="xpf-9325-images-")
        self.addCleanup(shutil.rmtree, self.imgdir, ignore_errors=True)
        self._orig = xd.LIBVIRT_IMAGES
        xd.LIBVIRT_IMAGES = self.imgdir
        self.addCleanup(setattr, xd, "LIBVIRT_IMAGES", self._orig)
        real = subprocess.run

        def no_qemu_img(argv, *a, **kw):
            if argv and argv[0] == "qemu-img":
                raise FileNotFoundError("qemu-img")
            return real(argv, *a, **kw)

        p = mock.patch.object(xd.subprocess, "run", side_effect=no_qemu_img)
        p.start()
        self.addCleanup(p.stop)
        self.src = os.path.join(tempfile.mkdtemp(prefix="xpf-9325-src-"), "new.qcow2")
        self.addCleanup(shutil.rmtree, os.path.dirname(self.src), ignore_errors=True)
        with open(self.src, "wb") as f:
            f.write(b"GOLDEN-V2")
        self.golden = os.path.join(self.imgdir, "xpf-appliance.qcow2")

    def _read(self, p):
        with open(p, "rb") as f:
            return f.read()

    def test_probe_raises_indeterminate(self):
        with self.assertRaises(xd._ProbeIndeterminate):
            xd._qcow2_backing_file(os.path.join(self.imgdir, "fw0.qcow2"))

    def test_fresh_host_proceeds_control(self):
        with _quiet():
            xd._install_libvirt_golden(self.src, "xpf-appliance")
        self.assertEqual(self._read(self.golden), b"GOLDEN-V2")

    def test_golden_without_a_sibling_proceeds_control(self):
        with open(self.golden, "wb") as f:
            f.write(b"GOLDEN-V1")
        with _quiet():
            xd._install_libvirt_golden(self.src, "xpf-appliance")
        self.assertEqual(self._read(self.golden), b"GOLDEN-V2")

    def test_golden_with_a_sibling_overlay_refuses(self):
        with open(self.golden, "wb") as f:
            f.write(b"GOLDEN-V1")
        with open(os.path.join(self.imgdir, "fw0.qcow2"), "wb") as f:
            f.write(b"OVERLAY")
        with _quiet(), self.assertRaises(SystemExit):
            xd._install_libvirt_golden(self.src, "xpf-appliance")
        self.assertEqual(self._read(self.golden), b"GOLDEN-V1",
                         "the golden was replaced under an overlay nothing could probe")


# ── item 5: the golden temp file ────────────────────────────────────────────
class GoldenTempFile9325(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp(prefix="xpf-9325-golden-")
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.golden = os.path.join(self.td, "xpf-appliance.qcow2")
        self.src = os.path.join(self.td, "src.bin")
        with open(self.golden, "wb") as f:
            f.write(b"OLD")
        with open(self.src, "wb") as f:
            f.write(b"NEW")

    def test_a_symlink_planted_at_the_old_temp_name_is_not_followed(self):
        victim = os.path.join(self.td, "victim")
        with open(victim, "wb") as f:
            f.write(b"VICTIM")
        os.symlink(victim, f"{self.golden}.xpf-tmp.{os.getpid()}")
        xd._atomic_install_golden(self.src, self.golden)
        self.assertFalse(os.path.islink(self.golden), "a planted symlink was renamed over the golden")
        with open(self.golden, "rb") as f:
            self.assertEqual(f.read(), b"NEW")
        with open(victim, "rb") as f:
            self.assertEqual(f.read(), b"VICTIM", "the copy was written through a planted symlink")

    def test_a_temp_swapped_during_the_write_is_refused(self):
        link = os.path.join(self.td, "swapped")
        os.symlink(os.path.join(self.td, "elsewhere"), link)
        real_lstat = os.lstat
        with mock.patch.object(xd.os, "lstat",
                               side_effect=lambda p, *a, **k: real_lstat(link) if ".xpf-tmp." in str(p) else real_lstat(p, *a, **k)):
            with self.assertRaises(SystemExit):
                xd._atomic_install_golden(self.src, self.golden)
        with open(self.golden, "rb") as f:
            self.assertEqual(f.read(), b"OLD")

    def test_the_sudo_arm_removes_its_temp_when_the_rename_fails(self):
        calls = []

        def run(argv, *a, **kw):
            calls.append(list(argv))
            if argv[:2] == ["sudo", "mv"]:
                return _completed(1, "mv: cannot move")
            return _completed(0)

        with mock.patch.object(xd.tempfile, "mkstemp", side_effect=PermissionError("images dir")), \
             mock.patch.object(xd.shutil, "copyfile", side_effect=PermissionError("images dir")), \
             mock.patch.object(xd.subprocess, "run", side_effect=run):
            with self.assertRaises(SystemExit):
                xd._atomic_install_golden(self.src, self.golden)
        installs = [c for c in calls if c[:2] == ["sudo", "install"]]
        self.assertEqual(len(installs), 1, calls)
        tmp = installs[0][-1]
        self.assertNotEqual(tmp, f"{self.golden}.xpf-tmp.{os.getpid()}", "the sudo temp name is still predictable")
        self.assertIn(["sudo", "rm", "-f", tmp], calls, "a failed sudo rename left its root-owned temp behind")


# ── item 4: the signed `validated` field is read ────────────────────────────
class ValidationVerdict9325(unittest.TestCase):
    def test_verdicts(self):
        self.assertEqual(xd._validation_verdict({"validated": "true"})[0], "true")
        self.assertEqual(xd._validation_verdict({"validated": " TRUE "})[0], "true")
        self.assertEqual(xd._validation_verdict({"validated": "false"})[0], "false")
        self.assertEqual(xd._validation_verdict({"validated": "yes"})[0], "false")
        self.assertEqual(xd._validation_verdict({"xpf-version": "1"})[0], "absent")


@unittest.skipUnless(shutil.which("minisign") and shutil.which("curl"), "minisign and curl are required")
class FetchReadsValidated9325(unittest.TestCase):
    VER = "1.2.3-4-gbbbbbbb"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-9325-fetch."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pub, self.sec = self.tmp / "img.pub", self.tmp / "img.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.pub), "-s", str(self.sec)],
                       check=True, capture_output=True)
        self.host, self.out = self.tmp / "host", self.tmp / "out"
        self.host.mkdir()
        env = {"XPF_IMAGE_PUBKEY": str(self.pub), "XDG_STATE_HOME": str(self.tmp / "state")}
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        self.addCleanup(lambda: [os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
                                 for k, v in saved.items()])
        self.qcow2 = f"xpf-{self.VER}.qcow2"
        self.sidecar = f"xpf-{self.VER}.manifest"

    def _publish(self, sidecar_text=None, withhold=False):
        (self.host / self.qcow2).write_bytes(b"QCOW2" * 64)
        listed = [self.qcow2]
        if sidecar_text is not None:
            (self.host / self.sidecar).write_text(sidecar_text)
            listed.append(self.sidecar)
        man = self.host / f"xpf-{self.VER}.SHA256SUMS"
        man.write_text("".join(f"{sign.sha256_file(str(self.host / n))}  {n}\n" for n in listed))
        sign.sign_manifest(str(man), str(self.sec), comment="9325 test")
        if withhold:
            (self.host / self.sidecar).unlink()

    def _fetch(self, **over):
        ns = argparse.Namespace(version=self.VER, image_url=self.host.as_uri(), out=str(self.out),
                                alias=None, channel="stable", allow_rollback=False, qcow2_only=True,
                                install_libvirt=False, no_import=True, dry_run=False,
                                allow_unvalidated=False)
        for k, v in over.items():
            setattr(ns, k, v)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            xd.cmd_fetch(ns)
        return buf.getvalue()

    def _downloaded(self):
        return (self.out / self.qcow2).exists()

    def test_an_unvalidated_image_is_refused_before_it_is_downloaded(self):
        self._publish("validated: false\n")
        with self.assertRaises(SystemExit) as cm:
            self._fetch()
        self.assertIn("refusing to fetch", str(cm.exception.code))
        self.assertFalse(self._downloaded(), "the unvalidated image was downloaded before the refusal")

    def test_allow_unvalidated_fetches_it_with_a_warning_control(self):
        self._publish("validated: false\n")
        out = self._fetch(allow_unvalidated=True)
        self.assertTrue(self._downloaded())
        self.assertIn("--allow-unvalidated", out)

    def test_a_withheld_listed_sidecar_is_refused_even_with_the_override(self):
        self._publish("validated: true\n", withhold=True)
        with self.assertRaises(SystemExit):
            self._fetch(allow_unvalidated=True)
        self.assertFalse(self._downloaded())

    def test_a_validated_image_fetches_control(self):
        self._publish("validated: true\n")
        out = self._fetch()
        self.assertTrue(self._downloaded())
        self.assertIn("provenance OK", out)

    def test_a_release_without_a_sidecar_warns_and_fetches_control(self):
        self._publish(None)
        out = self._fetch()
        self.assertTrue(self._downloaded())
        self.assertIn("lists no provenance sidecar", out)


class ImageRollReadsValidated9325(unittest.TestCase):
    FIELDS = {"xpf-version": "2.0.0", "ha-protocol-version": "3", "ha-protocol-min-compat": "2",
              "session-sync-protocol-version": "1"}

    def _roll(self, validated, **over):
        fields = dict(self.FIELDS)
        if validated is not None:
            fields["validated"] = validated
        args = types.SimpleNamespace(
            dry_run=False, backend="ssh", nodes=["fw0", "fw1"], node0_id=0, node1_id=1,
            recreate_hook="/bin/true", manifest="xpf-2.0.0.manifest", sha256sums=None, sig=None,
            pubkey=None, lease_ttl=1800, drain_deadline=120, boot_deadline=40,
            allow_session_drop=False, require_daemon_hold=False, allow_unvalidated=False)
        for k, v in over.items():
            setattr(args, k, v)

        def reached(*a, **k):
            raise _Reached()

        with mock.patch.object(xd, "_verified_image_manifest_versions", lambda *a, **k: dict(fields)), \
             mock.patch.object(xd.os.path, "isfile", lambda p: True), \
             mock.patch.object(xd, "_node_exec", side_effect=reached), \
             mock.patch.object(xd, "_node_exec_result", side_effect=reached), \
             mock.patch.object(xd, "_recreate_node_from_image", side_effect=reached), _quiet():
            xd.cmd_image_roll(args)

    def test_an_unvalidated_manifest_refuses_before_touching_a_node(self):
        with self.assertRaises(SystemExit) as cm:
            self._roll("false")
        self.assertIn("refusing to roll", str(cm.exception.code))

    def test_allow_unvalidated_proceeds_to_the_nodes_control(self):
        with self.assertRaises(_Reached):
            self._roll("false", allow_unvalidated=True)

    def test_a_validated_manifest_proceeds_control(self):
        with self.assertRaises(_Reached):
            self._roll("true")

    def test_a_manifest_without_the_field_proceeds_control(self):
        with self.assertRaises(_Reached):
            self._roll(None)


if __name__ == "__main__":
    unittest.main()
