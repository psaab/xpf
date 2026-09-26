#!/usr/bin/env python3
"""Hermetic unit tests for the validate.py scenario additions (fable-165 H-9).

validate.py's incus/QEMU scenarios cannot run without a hypervisor and a real
baked qcow2, but the pieces they hinge on ARE unit-testable without one:

  - `_qemu_img_verdict` — the pure config-level qcow2 bootability check the
    libvirt/plain-QEMU leg (scenario q) runs whenever qemu-img exists.
  - the OVMF firmware discovery ORDER (non-secboot preferred).
  - the scenario registry wiring (that e/q exist and dispatch).
  - the node-id day-0 drive the cluster scenario (e) depends on actually
    carrying a `node-id` file (make_config_drive round-trip).

RED on revert: dropping the qcow2 format/size verdict, removing scenario e/q,
or breaking the node-id drive all flip an assertion here.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
# validate.py's own top-level imports (make_config_drive, sign) resolve via the
# sys.path inserts it performs at import time.
_SPEC = importlib.util.spec_from_file_location("validate", _HERE / "validate.py")
validate = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(validate)

_SPEC_MCD = importlib.util.spec_from_file_location(
    "make_config_drive", _HERE / "make_config_drive.py")
make_config_drive = importlib.util.module_from_spec(_SPEC_MCD)
assert _SPEC_MCD.loader is not None
_SPEC_MCD.loader.exec_module(make_config_drive)


# ── _qemu_img_verdict: qcow2 libvirt-bootability (scenario q config leg) ───
class QemuImgVerdictTests(unittest.TestCase):
    FLOOR = validate.BAKE_MIN_BYTES

    def test_valid_qcow2_at_floor_passes(self):
        ok, _ = validate._qemu_img_verdict(
            {"format": "qcow2", "virtual-size": self.FLOOR}, self.FLOOR)
        self.assertTrue(ok)

    def test_larger_qcow2_passes(self):
        ok, reason = validate._qemu_img_verdict(
            {"format": "qcow2", "virtual-size": 20 * 1024 ** 3}, self.FLOOR)
        self.assertTrue(ok, reason)

    def test_wrong_format_fails(self):
        # A raw export is what libvirt/plain-QEMU would refuse as the qcow2.
        ok, reason = validate._qemu_img_verdict(
            {"format": "raw", "virtual-size": self.FLOOR}, self.FLOOR)
        self.assertFalse(ok)
        self.assertIn("qcow2", reason)

    def test_below_floor_fails(self):
        # A truncated / incomplete image.
        ok, reason = validate._qemu_img_verdict(
            {"format": "qcow2", "virtual-size": 1024}, self.FLOOR)
        self.assertFalse(ok)
        self.assertIn("floor", reason)

    def test_missing_or_nonint_size_fails(self):
        self.assertFalse(validate._qemu_img_verdict(
            {"format": "qcow2"}, self.FLOOR)[0])
        self.assertFalse(validate._qemu_img_verdict(
            {"format": "qcow2", "virtual-size": "8G"}, self.FLOOR)[0])


# ── OVMF discovery: first-existing wins ───────────────────────────────────
class OvmfDiscoveryTests(unittest.TestCase):
    def test_sb_off_fallback_list_contains_no_secboot_builds(self):
        """#6497 inverted the preference: an SB-ENFORCING pair is now tried
        first (_OVMF_SECBOOT_CODE_CANDIDATES + _OVMF_MS_VARS_CANDIDATES) and
        _OVMF_CODE_CANDIDATES is the SB-OFF fallback only.

        This case replaced `test_non_secboot_code_preferred_over_secboot`,
        which asserted the retired preference. Left in place it would have gone
        VACUOUS rather than red — the old list no longer holds a secboot entry
        at all, so its `first_plain < first_sb` comparison passes while testing
        nothing. The property that survives is what this list is FOR: a secboot
        build leaking into the fallback would make the "SB-off" leg silently
        SB-something, defeating the honest reporting #6497 added. The real
        preference order is asserted in test_validate_secureboot_6497.py.
        """
        for p in validate._OVMF_CODE_CANDIDATES:
            self.assertNotIn("secboot", p,
                             f"{p} is a secboot build in the SB-OFF fallback list")
            self.assertNotIn(".ms.", p,
                             f"{p} is an MS-keyed build in the SB-OFF fallback list")

    def test_find_first_returns_first_existing(self):
        orig = os.path.isfile
        present = {"/b", "/c"}
        validate.os.path.isfile = lambda p: p in present
        try:
            self.assertEqual(validate._find_first(["/a", "/b", "/c"]), "/b")
            self.assertIsNone(validate._find_first(["/x", "/y"]))
        finally:
            validate.os.path.isfile = orig


class ScenarioDPartitionCountTests(unittest.TestCase):
    def test_root_partition_count_counts_only_partition_rows_on_parent_disk(self):
        with patch.object(validate, "guest", side_effect=[
                SimpleNamespace(stdout="/dev/sdap2\n"),
                SimpleNamespace(stdout="sdap\n"),
                SimpleNamespace(stdout="disk\npart\npart\n"),
        ]) as run:
            count = validate.Harness._root_partition_count(object(), "instance")
        self.assertEqual(count, 2)
        self.assertEqual(run.call_args_list[1].args,
                         ("instance", "lsblk", "-no", "PKNAME", "/dev/sdap2"))
        self.assertEqual(run.call_args_list[2].args,
                         ("instance", "lsblk", "-ln", "-o", "TYPE", "/dev/sdap"))

    def test_scenario_d_checks_grown_restart_and_control_partition_counts(self):
        src = (_HERE / "validate.py").read_text()
        body = src.split("def scenario_d(self):", 1)[1].split(
            "def scenario_e(self):", 1)[0]
        self.assertIn("partition_count = self._root_partition_count(d)", body)
        self.assertIn("partition_count2 = self._root_partition_count(d)", body)
        self.assertIn("control_partition_count = self._root_partition_count(d2)", body)
        self.assertIn("part2 = self._root_part_gib(d)", body)
        self.assertIn("abs(part2 - part) > 0.1", body)
        self.assertIn("control_partition_count != partition_count", body)


# ── scenario registry wiring (single source of truth for CLI + dispatch) ──
class ScenarioRegistryTests(unittest.TestCase):
    def test_order_includes_h9_additions(self):
        self.assertEqual(validate.SCENARIO_ORDER, ["a", "b", "c", "d", "e", "q"])

    def test_every_key_maps_to_a_real_harness_method(self):
        for k in validate.SCENARIO_ORDER:
            self.assertIn(k, validate.SCENARIO_METHODS)
            meth = validate.SCENARIO_METHODS[k]
            self.assertTrue(hasattr(validate.Harness, meth),
                            f"scenario {k!r} -> missing Harness.{meth}")

    def test_h9_scenarios_present(self):
        self.assertEqual(validate.SCENARIO_METHODS["e"], "scenario_e")
        self.assertEqual(validate.SCENARIO_METHODS["q"], "scenario_qemu")


# ── node-id day-0 drive (scenario e depends on this) ──────────────────────
class NodeIdDriveTests(unittest.TestCase):
    def test_node_id_out_of_range_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = os.path.join(tmp, "x.conf")
            with open(conf, "w") as f:
                f.write("system { host-name x; }\n")
            with self.assertRaises(SystemExit):
                make_config_drive.build_config_drive(
                    conf, os.path.join(tmp, "x.iso"), node_id=2, validate=False)

    def test_node_id_1_drive_carries_node_id_file(self):
        if not shutil.which("xorriso"):
            self.skipTest("xorriso not installed — cannot build/extract the ISO")
        with tempfile.TemporaryDirectory() as tmp:
            conf = os.path.join(tmp, "n.conf")
            with open(conf, "w") as f:
                f.write("system { host-name xpf-node1; }\n")
            iso = make_config_drive.build_config_drive(
                conf, os.path.join(tmp, "n.iso"), node_id=1, validate=False)
            out = os.path.join(tmp, "extract")
            subprocess.run(
                ["xorriso", "-osirrox", "on", "-indev", iso,
                 "-extract", "/", out],
                check=True, capture_output=True)
            nid = os.path.join(out, "node-id")
            self.assertTrue(os.path.isfile(nid), "day-0 drive has no node-id file")
            with open(nid) as f:
                self.assertEqual(f.read().strip(), "1")
            self.assertTrue(os.path.isfile(os.path.join(out, "xpf.conf")))


if __name__ == "__main__":
    unittest.main()
