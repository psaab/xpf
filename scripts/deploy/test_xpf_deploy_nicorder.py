#!/usr/bin/env python3
"""Unit tests for the guest virtio-first NIC-order guard (fable-165 H-22).

The guest does NOT name interfaces by the order the deploy tool attaches
them. `enumeratePCINICs()` (pkg/daemon/linksetup.go) sorts NICs with a
virtio-first tiebreaker — sk=0 for driver `virtio_net`, sk=1 for
hardware — BEFORE `assignName()` hands out positional vSRX names. A
virtio-backed NIC (net/bridge/macvlan) therefore always enumerates ahead
of a passthrough NIC (sriov/physical/pci), no matter where the operator
lists it.

`validate_appliance()` used to check each declared role against its raw
list index only, so a YAML that put a virtio-class NIC AFTER a
hardware-class one passed validation but booted with the firewall zones
on swapped ports (trust/untrust inverted) — a silent security miswiring.

These tests drive validate_appliance() and assert:
  - a virtio-class NIC listed after a hardware-class NIC is REJECTED
    (die -> SystemExit), naming both offending positions;
  - the same interface set reordered virtio-first is ACCEPTED and gets
    the expected positional vSRX names;
  - pure-virtio and pure-hardware layouts (and the shipped examples) are
    unaffected;
  - backing_sort_key mirrors the guest's sk=0/sk=1 classes.

On revert (drop the virtio-first guard in validate_appliance) the
rejection test goes RED: the mixed-order appliance validates without
raising, exactly the latent zone-swap the guard exists to prevent.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

xpf_deploy = load_subject("xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "deploy"


def _iface(backing, source, role=None):
    ic = {"backing": backing, "source": source}
    if role is not None:
        ic["role"] = role
    return ic


def _appliance(interfaces, mode="standalone", node_id=None):
    return {
        "name": "fw",
        "mode": mode,
        "node_id": node_id,
        "interfaces": interfaces,
    }


class BackingSortKeyTests(unittest.TestCase):
    def test_virtio_class_is_zero(self):
        for b in ("net", "bridge", "macvlan"):
            self.assertEqual(xpf_deploy.backing_sort_key(b), 0, b)

    def test_hardware_class_is_one(self):
        for b in ("sriov", "physical", "pci"):
            self.assertEqual(xpf_deploy.backing_sort_key(b), 1, b)

    def test_classes_partition_valid_backings(self):
        # Every valid backing is classified exactly once, so the guard can
        # never see an unclassified backing slip through.
        self.assertEqual(
            xpf_deploy.VIRTIO_BACKINGS | xpf_deploy.HARDWARE_BACKINGS,
            xpf_deploy.VALID_BACKINGS,
        )
        self.assertEqual(
            xpf_deploy.VIRTIO_BACKINGS & xpf_deploy.HARDWARE_BACKINGS, set()
        )


class VirtioFirstGuardTests(unittest.TestCase):
    def test_virtio_after_hardware_is_rejected(self):
        # The H-22 hazard: pos1 fxp0 (virtio bridge), pos2 ge-0/0/0 (pci
        # VF, hardware), pos3 ge-0/0/1 (virtio bridge). Index-only
        # validation passes, but the guest sorts both virtio NICs first, so
        # the pos-3 bridge becomes ge-0/0/0 and the pos-2 VF becomes
        # ge-0/0/1 — zones swap. Must be rejected.
        ap = _appliance([
            _iface("bridge", "br-mgmt"),
            _iface("pci", "0000:09:00.0", role="ge-0/0/0"),
            _iface("bridge", "br-lan", role="ge-0/0/1"),
        ])
        with self.assertRaises(SystemExit) as cm:
            xpf_deploy.validate_appliance(ap, "test.yaml")
        msg = str(cm.exception)
        # Error names both offending positions and the virtio/hardware
        # classes so the operator can act on it.
        self.assertIn("interface 3", msg)
        self.assertIn("interface 2", msg)
        self.assertIn("virtio", msg)
        self.assertIn("hardware", msg)

    def test_virtio_after_hardware_rejected_without_roles(self):
        # The guard is class-based, so it fires even for position-only
        # configs that declare no roles at all.
        ap = _appliance([
            _iface("bridge", "br-mgmt"),
            _iface("sriov", "enp8s0"),
            _iface("net", "lan-net"),
        ])
        with self.assertRaises(SystemExit):
            xpf_deploy.validate_appliance(ap, "test.yaml")

    def test_virtio_after_hardware_rejected_in_cluster(self):
        ap = _appliance(
            [
                _iface("bridge", "br-mgmt"),          # fxp0
                _iface("bridge", "br-ha"),            # em0
                _iface("pci", "0000:09:00.0"),        # ge-0/0/0 (hardware)
                _iface("macvlan", "eno1"),            # virtio after hardware
            ],
            mode="cluster",
            node_id=0,
        )
        with self.assertRaises(SystemExit):
            xpf_deploy.validate_appliance(ap, "node0.yaml")

    def test_all_virtio_first_is_accepted(self):
        # Same physical set, reordered so the two virtio NICs precede the
        # hardware VF: valid, and names map positionally.
        ifaces = [
            _iface("bridge", "br-mgmt", role="fxp0"),
            _iface("bridge", "br-lan", role="ge-0/0/0"),
            _iface("pci", "0000:09:00.0", role="ge-0/0/1"),
        ]
        ap = _appliance(ifaces)
        xpf_deploy.validate_appliance(ap, "test.yaml")  # no raise
        self.assertEqual([ic["_name"] for ic in ifaces],
                         ["fxp0", "ge-0/0/0", "ge-0/0/1"])

    def test_pure_virtio_is_accepted(self):
        ap = _appliance([
            _iface("bridge", "br-mgmt"),
            _iface("bridge", "br-lan"),
            _iface("net", "wan-net"),
        ])
        xpf_deploy.validate_appliance(ap, "test.yaml")  # no raise

    def test_pure_hardware_is_accepted(self):
        # No virtio at all -> no cross-class inversion possible.
        ap = _appliance([
            _iface("pci", "0000:08:00.0"),
            _iface("sriov", "enp9s0"),
            _iface("physical", "enp10s0"),
        ])
        xpf_deploy.validate_appliance(ap, "test.yaml")  # no raise

    def test_hardware_then_virtio_boundary_only(self):
        # A single hardware NIC followed by a single virtio NIC is the
        # minimal inversion and must still be caught.
        ap = _appliance([
            _iface("bridge", "br-mgmt"),
            _iface("sriov", "enp8s0"),
            _iface("bridge", "br-lan"),
        ])
        with self.assertRaises(SystemExit):
            xpf_deploy.validate_appliance(ap, "test.yaml")


@unittest.skipUnless(xpf_deploy.yaml is not None, "PyYAML not installed")
class ShippedExamplesTests(unittest.TestCase):
    """Every shipped example YAML must satisfy the virtio-first guard."""

    def test_shipped_examples_validate(self):
        yamls = sorted(EXAMPLES.glob("*.yaml"))
        self.assertTrue(yamls, f"no example YAMLs under {EXAMPLES}")
        for path in yamls:
            with self.subTest(example=path.name):
                # load_yaml_appliance() calls validate_appliance() and
                # would die() on a virtio-after-hardware layout.
                xpf_deploy.load_yaml_appliance(str(path))


if __name__ == "__main__":
    unittest.main()
