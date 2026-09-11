#!/usr/bin/env python3
"""Unit tests for the libvirt per-VM disk overlay (fable-165 H-20).

The libvirt deploy path must NOT attach the shared golden qcow2 to a VM
as a writable disk. qcow2 is not a cluster filesystem, so an HA pair
booting two live domains off one file corrupts it, and even a single
`virt-install --import` would mutate the golden master in place (day-0
stamp, host keys, configstore DB baked in). Each domain must instead get
its OWN copy-on-write overlay
(`qemu-img create -f qcow2 -b <golden> -F qcow2 <overlay>`), leaving the
golden an immutable read-only backing store.

These tests drive deploy_libvirt() with a recording runner and assert:
  - an HA pair (fw0, fw1) gets TWO DISTINCT per-VM disk paths;
  - neither VM's writable --disk is the golden image;
  - each VM's overlay is created with the golden as the read-only -b
    backing store;
  - the overlay handed to virt-install is exactly the one qemu-img just
    created;
  - the standalone case also gets its own overlay, never the golden.

On revert (attach `path=.../{image}.qcow2` directly to both domains) the
distinctness and non-golden assertions go RED: both VMs get the same
path and it IS the golden.
"""

from __future__ import annotations

import contextlib
import fcntl
import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy", Path(__file__).with_name("xpf-deploy.py")
)
xpf_deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xpf_deploy)


# Sentinel for "the probe ran and could not determine the answer" (#6760).
_INDETERMINATE = object()


class RecordingRunner:
    """Runner that records every argv instead of executing it.

    dry=True so libvirt_disk() skips the host-state golden-exists check
    (there is no real image in a unit test); the recording still captures
    the qemu-img/virt-install argv the code would run.
    """

    def __init__(self):
        self.dry = True
        self.calls = []

    def run(self, argv):
        self.calls.append(list(argv))
        return ""


def _appliance(name, node_id=None):
    ap = {
        "name": name,
        "mode": "cluster" if node_id is not None else "standalone",
        "node_id": node_id,
        "image": "xpf-appliance",
        "cpu": 2,
        "memory": "4G",
        # no "config" -> build_config_drive returns None (no ISO build).
        "interfaces": [
            {"_name": "fxp0", "backing": "bridge", "source": "br-mgmt"},
        ],
    }
    return ap


def _find_call(calls, prog):
    for c in calls:
        if c and c[0] == prog:
            return c
    return None


def _boot_disk_path(virt_install_argv):
    """Return the writable boot --disk path (the one that is not a cdrom)."""
    disks = [virt_install_argv[i + 1]
             for i, a in enumerate(virt_install_argv) if a == "--disk"]
    boot = [d for d in disks if "device=cdrom" not in d]
    assert len(boot) == 1, f"expected exactly one boot disk, got {boot}"
    val = boot[0]
    assert val.startswith("path="), f"unexpected --disk form: {val}"
    return val[len("path="):]


def _qemu_backing_and_overlay(qemu_argv):
    """Return (backing, overlay) from a `qemu-img create ... -b B ... OVERLAY`."""
    backing = qemu_argv[qemu_argv.index("-b") + 1]
    overlay = qemu_argv[-1]  # target is the final positional arg
    return backing, overlay


GOLDEN = f"{xpf_deploy.LIBVIRT_IMAGES}/xpf-appliance.qcow2"


class LibvirtPerVmDiskTests(unittest.TestCase):
    def _deploy(self, ap):
        r = RecordingRunner()
        xpf_deploy.deploy_libvirt(ap, r, start=False)
        virt = _find_call(r.calls, "virt-install")
        qemu = _find_call(r.calls, "qemu-img")
        self.assertIsNotNone(virt, "virt-install was not invoked")
        self.assertIsNotNone(qemu, "qemu-img create was not invoked")
        return virt, qemu

    def test_ha_pair_gets_two_distinct_non_golden_disks(self):
        virt0, qemu0 = self._deploy(_appliance("ha-fw0", node_id=0))
        virt1, qemu1 = self._deploy(_appliance("ha-fw1", node_id=1))

        disk0 = _boot_disk_path(virt0)
        disk1 = _boot_disk_path(virt1)

        # (a) each VM gets a DISTINCT writable disk — the corruption fix.
        self.assertNotEqual(
            disk0, disk1,
            "HA pair must not share one writable qcow2 (image corruption)")

        # (b) neither writable disk is the golden image.
        self.assertNotEqual(disk0, GOLDEN)
        self.assertNotEqual(disk1, GOLDEN)

        # (c) each overlay is backed READ-ONLY by the golden image.
        back0, ov0 = _qemu_backing_and_overlay(qemu0)
        back1, ov1 = _qemu_backing_and_overlay(qemu1)
        self.assertEqual(back0, GOLDEN)
        self.assertEqual(back1, GOLDEN)

        # (d) virt-install attaches exactly the overlay qemu-img created.
        self.assertEqual(disk0, ov0)
        self.assertEqual(disk1, ov1)
        self.assertNotEqual(ov0, ov1)

        # (e) qemu-img creates qcow2 overlays with the qcow2 backing fmt.
        for q in (qemu0, qemu1):
            self.assertEqual(q[:3], ["qemu-img", "create", "-f"])
            self.assertIn("-F", q)
            self.assertEqual(q[q.index("-F") + 1], "qcow2")

    def test_golden_is_never_attached_writable(self):
        # Across BOTH nodes, no virt-install writable --disk is the golden.
        for name, nid in (("ha-fw0", 0), ("ha-fw1", 1)):
            virt, _ = self._deploy(_appliance(name, node_id=nid))
            self.assertNotEqual(_boot_disk_path(virt), GOLDEN)

    def test_standalone_gets_own_overlay(self):
        virt, qemu = self._deploy(_appliance("fw-solo"))
        disk = _boot_disk_path(virt)
        back, overlay = _qemu_backing_and_overlay(qemu)
        self.assertNotEqual(disk, GOLDEN)
        self.assertEqual(back, GOLDEN)
        self.assertEqual(disk, overlay)

    def test_name_equal_image_is_rejected(self):
        # If the VM name equals the golden basename the overlay path would
        # collide with the golden and overwrite it — must hard-fail.
        ap = _appliance("xpf-appliance")  # name == image
        r = RecordingRunner()
        with self.assertRaises(SystemExit):
            xpf_deploy.deploy_libvirt(ap, r, start=False)


class LibvirtGoldenOverwriteGuardTests(unittest.TestCase):
    """#5043: `fetch --install-libvirt` must NOT overwrite a golden qcow2 in
    place while per-VM overlays back onto it — that shifts the immutable
    backing bytes under every overlay and corrupts them (both HA nodes commonly
    share one golden). First install (no golden yet) and a re-fetch with no
    dependent overlays stay allowed; the dangerous in-place overwrite of an
    in-use golden fails closed.

    On revert (drop the guard so `_install_libvirt_golden` copies over any
    existing golden unconditionally) the refuse/no-clobber assertions in
    test_overwrite_with_dependent_overlay_is_refused go RED.
    """

    def setUp(self):
        # A private temp dir stands in for /var/lib/libvirt/images so the copy
        # path is writable (no sudo) and the scan sees only our fixtures.
        self._imgdir = tempfile.mkdtemp(prefix="xpf-golden-images-")
        self._srcdir = tempfile.mkdtemp(prefix="xpf-golden-src-")
        self._orig_images = xpf_deploy.LIBVIRT_IMAGES
        self._orig_backing = xpf_deploy._qcow2_backing_file
        xpf_deploy.LIBVIRT_IMAGES = self._imgdir
        # Fake the qemu-img backing probe so the test is hermetic (no qemu-img
        # required): a {realpath: backing-or-None} map drives the classifier.
        self._backing = {}

        # #6760: the map value may be the sentinel _INDETERMINATE, so a test can
        # express "the probe RAN and failed" — distinct from "no backing file".
        # Before #6760 the production probe collapsed both to None and the guard
        # read that as "not a dependent overlay".
        def fake_backing(path):
            v = self._backing.get(os.path.realpath(path))
            if v is _INDETERMINATE:
                raise xpf_deploy._ProbeIndeterminate(f"fake probe failed for {path}")
            return v

        xpf_deploy._qcow2_backing_file = fake_backing

    def tearDown(self):
        xpf_deploy.LIBVIRT_IMAGES = self._orig_images
        xpf_deploy._qcow2_backing_file = self._orig_backing
        shutil.rmtree(self._imgdir, ignore_errors=True)
        shutil.rmtree(self._srcdir, ignore_errors=True)

    def _write(self, path, content):
        with open(path, "wb") as f:
            f.write(content)
        return path

    def _src(self, content=b"VERIFIED-NEW-GOLDEN"):
        # Source lives OUTSIDE the images dir so it is never scanned as an
        # overlay (mirrors the real fetch out-dir).
        return self._write(os.path.join(self._srcdir, "verified.qcow2"), content)

    def _golden_path(self, image="xpf-appliance"):
        return os.path.join(self._imgdir, f"{image}.qcow2")

    def test_first_install_copies_the_golden(self):
        # No golden present yet -> the copy proceeds (first-install path).
        src = self._src(b"GOLDEN-V1")
        dst = xpf_deploy._install_libvirt_golden(src, "xpf-appliance")
        self.assertEqual(os.path.realpath(dst),
                         os.path.realpath(self._golden_path()))
        with open(dst, "rb") as f:
            self.assertEqual(f.read(), b"GOLDEN-V1")

    def test_refetch_without_dependent_overlays_replaces(self):
        # Golden exists, but nothing backs onto it -> legitimate re-fetch is
        # allowed and the golden is replaced with the new verified bytes.
        golden = self._write(self._golden_path(), b"GOLDEN-V1")
        # An unrelated image in the same dir (its own full image, no backing).
        other = self._write(os.path.join(self._imgdir, "some-other.qcow2"), b"x")
        self._backing[os.path.realpath(other)] = None
        xpf_deploy._install_libvirt_golden(self._src(b"GOLDEN-V2"), "xpf-appliance")
        with open(golden, "rb") as f:
            self.assertEqual(f.read(), b"GOLDEN-V2")

    def test_overwrite_with_dependent_overlay_is_refused(self):
        # Golden exists AND a per-VM overlay backs onto it -> refuse, and the
        # golden bytes must be UNCHANGED (no partial clobber before the die).
        golden = self._write(self._golden_path(), b"GOLDEN-V1")
        overlay = self._write(os.path.join(self._imgdir, "ha-fw0.qcow2"), b"ovl")
        self._backing[os.path.realpath(overlay)] = os.path.realpath(golden)
        with self.assertRaises(SystemExit):
            xpf_deploy._install_libvirt_golden(self._src(b"GOLDEN-V2"),
                                               "xpf-appliance")
        with open(golden, "rb") as f:
            self.assertEqual(f.read(), b"GOLDEN-V1",
                             "golden must not be touched when overwrite refused")

    def test_dependent_overlays_lists_only_true_backers(self):
        golden = self._write(self._golden_path(), b"G")
        dep0 = self._write(os.path.join(self._imgdir, "ha-fw0.qcow2"), b"a")
        dep1 = self._write(os.path.join(self._imgdir, "ha-fw1.qcow2"), b"b")
        indep = self._write(os.path.join(self._imgdir, "unrelated.qcow2"), b"c")
        self._backing[os.path.realpath(dep0)] = os.path.realpath(golden)
        self._backing[os.path.realpath(dep1)] = os.path.realpath(golden)
        # Backs onto a DIFFERENT golden -> not a dependent of this one.
        self._backing[os.path.realpath(indep)] = "/var/lib/libvirt/images/other.qcow2"
        found, unknown = xpf_deploy._dependent_overlays(golden)
        deps = {os.path.realpath(d) for d in found}
        self.assertEqual(deps,
                         {os.path.realpath(dep0), os.path.realpath(dep1)})
        self.assertEqual(unknown, [], "every fixture probes cleanly here, so "
                                      "nothing may land in the unknown bucket")

    def test_golden_is_not_its_own_overlay(self):
        # A golden whose own backing (spuriously) resolves to itself must never
        # be reported as a dependent overlay of itself.
        golden = self._write(self._golden_path(), b"G")
        self._backing[os.path.realpath(golden)] = os.path.realpath(golden)
        self.assertEqual(xpf_deploy._dependent_overlays(golden), ([], []))


class GoldenProbeIndeterminateTests(unittest.TestCase):
    """#6760: an overlay whose backing could not be PROBED must not be
    classified as "does not back onto the golden".

    The old probe returned None for four different outcomes — qemu-img absent,
    qemu-img failed, unparseable JSON, and genuinely no backing file — and the
    guard read None as "not a dependent overlay". So an unprobeable overlay was
    assumed safe and the golden was overwritten under exactly the file the tool
    had failed to read. A running domain's overlay is the realistic instance:
    qemu-img can fail on an image a live VM holds open.
    """

    def setUp(self):
        self._imgdir = tempfile.mkdtemp(prefix="xpf-golden-images-")
        self._srcdir = tempfile.mkdtemp(prefix="xpf-golden-src-")
        self._orig_images = xpf_deploy.LIBVIRT_IMAGES
        self._orig_backing = xpf_deploy._qcow2_backing_file
        xpf_deploy.LIBVIRT_IMAGES = self._imgdir
        self._backing = {}

        def fake_backing(path):
            v = self._backing.get(os.path.realpath(path))
            if v is _INDETERMINATE:
                raise xpf_deploy._ProbeIndeterminate(f"fake probe failed for {path}")
            return v

        xpf_deploy._qcow2_backing_file = fake_backing

    def tearDown(self):
        xpf_deploy.LIBVIRT_IMAGES = self._orig_images
        xpf_deploy._qcow2_backing_file = self._orig_backing
        shutil.rmtree(self._imgdir, ignore_errors=True)
        shutil.rmtree(self._srcdir, ignore_errors=True)

    def _write(self, path, content=b"x"):
        with open(path, "wb") as f:
            f.write(content)
        return path

    def _golden(self):
        return self._write(os.path.join(self._imgdir, "appliance.qcow2"), b"GOLDEN")

    def _src(self):
        return self._write(os.path.join(self._srcdir, "verified.qcow2"), b"NEW")

    def test_unprobeable_sibling_is_reported_unknown_not_independent(self):
        golden = self._golden()
        opaque = self._write(os.path.join(self._imgdir, "running-vm.qcow2"))
        self._backing[os.path.realpath(opaque)] = _INDETERMINATE

        deps, unknown = xpf_deploy._dependent_overlays(golden)
        self.assertEqual(deps, [], "an unprobeable file is not PROVABLY a dependant")
        self.assertEqual([p for p, _ in unknown], [os.path.abspath(opaque)],
                         "...but it must be reported as unknown, not dropped: "
                         "before #6760 it vanished and the golden was overwritten "
                         "under it")

    def test_overwrite_refused_when_a_sibling_is_unprobeable(self):
        golden = self._golden()
        before = open(golden, "rb").read()
        opaque = self._write(os.path.join(self._imgdir, "running-vm.qcow2"))
        self._backing[os.path.realpath(opaque)] = _INDETERMINATE

        with self.assertRaises(SystemExit):
            xpf_deploy._install_libvirt_golden(self._src(), "appliance")
        self.assertEqual(open(golden, "rb").read(), before,
                         "the golden was overwritten despite an unprobeable sibling "
                         "— this is the #6760 corruption path")

    def test_qemu_img_absent_is_indeterminate_9325(self):
        # #9325 reversed this cell. It insisted a missing qemu-img stay "no
        # backing", on the claim that anything else "would block every install
        # on a host without qemu-img". Measured, that is false: the probe only
        # runs on a SIBLING overlay, so the change moves exactly one state, and
        # it is the state this guard exists for.
        #
        #   state                                  before     after
        #   fresh host, no golden yet              PROCEED    PROCEED
        #   golden present, no sibling .qcow2      PROCEED    PROCEED
        #   golden present + a sibling overlay     PROCEED    REFUSED
        #
        # A qemu-img that cannot be run is "could not ask": an overlay created
        # before it left PATH, or by another tool, still backs onto the golden.
        xpf_deploy._qcow2_backing_file = self._orig_backing
        orig_run = xpf_deploy.subprocess.run

        def no_qemu_img(argv, *a, **kw):
            if argv and argv[0] == "qemu-img":
                raise FileNotFoundError("qemu-img")
            return orig_run(argv, *a, **kw)

        xpf_deploy.subprocess.run = no_qemu_img
        try:
            with self.assertRaises(xpf_deploy._ProbeIndeterminate):
                xpf_deploy._qcow2_backing_file("/nonexistent.qcow2")
        finally:
            xpf_deploy.subprocess.run = orig_run

    def test_clean_probe_still_permits_install(self):
        # The over-blocking control: with every sibling probing cleanly and none
        # backing onto the golden, the install must still proceed. An
        # implementation that treated any probe as suspicious would pass every
        # test above and break ordinary re-fetches.
        golden = self._golden()
        indep = self._write(os.path.join(self._imgdir, "other-vm.qcow2"))
        self._backing[os.path.realpath(indep)] = "/var/lib/libvirt/images/other.qcow2"
        self._backing[os.path.realpath(golden)] = None

        out = xpf_deploy._install_libvirt_golden(self._src(), "appliance")
        self.assertEqual(open(out, "rb").read(), b"NEW",
                         "a clean re-fetch with no dependants must still install")


class GoldenAtomicReplaceTests(unittest.TestCase):
    """#6761: golden replacement was an unlocked check-then-in-place-copy.

    Two distinct failures, and the second needs no concurrency at all: an
    INTERRUPTED `shutil.copyfile` onto the live golden leaves it TRUNCATED, and
    a truncated golden shifts the backing bytes under every existing overlay —
    the exact corruption the dependency guard exists to prevent.
    """

    def setUp(self):
        self._imgdir = tempfile.mkdtemp(prefix="xpf-golden-images-")
        self._srcdir = tempfile.mkdtemp(prefix="xpf-golden-src-")
        self._orig_images = xpf_deploy.LIBVIRT_IMAGES
        xpf_deploy.LIBVIRT_IMAGES = self._imgdir

    def tearDown(self):
        xpf_deploy.LIBVIRT_IMAGES = self._orig_images
        shutil.rmtree(self._imgdir, ignore_errors=True)
        shutil.rmtree(self._srcdir, ignore_errors=True)

    def _paths(self):
        golden = os.path.join(self._imgdir, "appliance.qcow2")
        with open(golden, "wb") as f:
            f.write(b"OLD-GOLDEN-CONTENT")
        src = os.path.join(self._srcdir, "verified.qcow2")
        with open(src, "wb") as f:
            f.write(b"NEW")
        return src, golden

    def test_interrupted_replace_leaves_the_old_golden_intact(self):
        src, golden = self._paths()
        before = open(golden, "rb").read()

        # #9325: the temp is written through the mkstemp descriptor with
        # copyfileobj now, so that is where the interruption is injected.
        real_copy = xpf_deploy.shutil.copyfileobj

        def boom(a, b, *args, **kw):
            real_copy(a, b, *args, **kw)   # write the temp fully...
            raise KeyboardInterrupt("interrupted after the temp write")

        xpf_deploy.shutil.copyfileobj = boom
        try:
            with self.assertRaises(KeyboardInterrupt):
                xpf_deploy._atomic_install_golden(src, golden)
        finally:
            xpf_deploy.shutil.copyfileobj = real_copy
        self.assertEqual([n for n in os.listdir(os.path.dirname(golden)) if "xpf-tmp" in n], [],
                         "an interruption must not leave the temp behind either")

        self.assertEqual(open(golden, "rb").read(), before,
                         "an interruption before the rename must leave the golden "
                         "WHOLLY the old image — an in-place copy would have left "
                         "it truncated and corrupted every overlay backing onto it")

    def test_successful_replace_is_whole(self):
        src, golden = self._paths()
        xpf_deploy._atomic_install_golden(src, golden)
        self.assertEqual(open(golden, "rb").read(), b"NEW")

    def test_no_temp_file_is_left_behind(self):
        # A stray sibling temp would itself be scanned by the dependency guard
        # on the next run, so cleanup is part of the contract rather than tidiness.
        src, golden = self._paths()
        xpf_deploy._atomic_install_golden(src, golden)
        strays = [n for n in os.listdir(self._imgdir) if "xpf-tmp" in n]
        self.assertEqual(strays, [], f"temp file(s) left behind: {strays}")

    def test_overlay_create_actually_takes_the_lock(self):
        # BIND THE WIRING, not the callee. The exclusivity test below proves the
        # lock works when held; it does NOT prove libvirt_disk takes it, and a
        # mutation that removed the lock from the overlay-create side passed
        # every other test in this file. Without both sides on the same lock the
        # TOCTOU is only half-closed, which is indistinguishable from closed.
        _, golden = self._paths()
        overlay_dir = tempfile.mkdtemp(prefix="xpf-overlay-")
        self.addCleanup(shutil.rmtree, overlay_dir, ignore_errors=True)

        taken = []
        real_lock = xpf_deploy._golden_lock

        @contextlib.contextmanager
        def recording_lock(path):
            taken.append(path)
            with real_lock(path) as held:
                yield held

        class LiveRunner:
            dry = False

            def __init__(self):
                self.calls = []

            def run(self, argv):
                self.calls.append(list(argv))
                return ""

        orig_overlay = xpf_deploy.libvirt_overlay_path
        xpf_deploy._golden_lock = recording_lock
        xpf_deploy.libvirt_overlay_path = lambda name: os.path.join(overlay_dir, f"{name}.qcow2")
        try:
            runner = LiveRunner()
            xpf_deploy.libvirt_disk({"name": "vm0", "image": "appliance"}, runner)
        finally:
            xpf_deploy._golden_lock = real_lock
            xpf_deploy.libvirt_overlay_path = orig_overlay

        self.assertEqual(len(taken), 1,
                         "libvirt_disk did not take the golden lock; the overlay "
                         "create races golden replacement (#6761)")
        self.assertEqual(os.path.realpath(taken[0]), os.path.realpath(golden),
                         "the overlay create must lock on the SAME golden the "
                         "replacement locks on, or the two never contend")

    def test_lock_is_exclusive_between_replace_and_overlay_create(self):
        # #6761 TOCTOU: the replacement and the overlay create must contend on
        # the SAME lock. Holding it in this process must block a second
        # acquisition, which is what serializes the two paths.
        _, golden = self._paths()
        with xpf_deploy._golden_lock(golden) as held:
            self.assertTrue(held, "the temp images dir is writable, so the lock "
                                  "must actually be taken here")
            lockpath = os.path.join(self._imgdir, ".xpf-golden.lock")
            fd = os.open(lockpath, os.O_CREAT | os.O_RDWR, 0o644)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
