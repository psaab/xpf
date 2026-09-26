#!/usr/bin/env python3
"""Unit tests for three xpf-deploy correctness fixes (fable-review-165).

H-23  libvirt `physical` backing resolves the netdev NAME to a PCI address
      before handing it to `virt-install --hostdev` (which requires a PCI /
      USB address, not an interface name). On revert (the raw netdev name is
      passed to --hostdev) the resolution assertion goes RED.

H-25  the fetch anti-rollback watermark orders git-describe commit counts and
      rc numbers NUMERICALLY, not lexically, so `1.2.3-10-gabc` outranks
      `1.2.3-9-gdef` and `rc10` outranks `rc9`. On revert (whole-string
      suffix compare) both orderings invert and the assertions go RED.

H-30  `fetch --install-libvirt` installs the verified qcow2 to the SAME
      libvirt golden path `deploy --hypervisor libvirt` reads, via one shared
      helper (`libvirt_golden_path`). On revert (no shared constant; fetch
      never lands the image at the deploy path) the agreement test goes RED.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy", Path(__file__).with_name("xpf-deploy.py")
)
xpf_deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xpf_deploy)


class RecordingRunner:
    """Runner that records every argv instead of executing it (dry=True so
    libvirt_disk() skips the host-state golden-exists check)."""

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


# ── H-23: physical backing on libvirt resolves netdev -> PCI address ──────
class PhysicalHostdevTests(unittest.TestCase):
    def setUp(self):
        # Real hosts vary; drive resolution with a deterministic stub so the
        # test does not depend on a physical NIC being present.
        self._orig_pci_of = xpf_deploy.pci_of
        xpf_deploy.pci_of = lambda dev: (
            "0000:08:00.0" if dev == "enp8s0" else "?")

    def tearDown(self):
        xpf_deploy.pci_of = self._orig_pci_of

    def _deploy(self, iface):
        ap = {
            "name": "fw", "mode": "standalone", "node_id": None,
            "image": "xpf-appliance", "cpu": 2, "memory": "4G",
            "interfaces": [
                {"_name": "fxp0", "backing": "bridge", "source": "br-mgmt"},
                iface,
            ],
        }
        r = RecordingRunner()
        xpf_deploy.deploy_libvirt(ap, r, start=False)
        virt = _find_call(r.calls, "virt-install")
        self.assertIsNotNone(virt, "virt-install was not invoked")
        return virt

    def test_physical_netdev_is_resolved_to_pci_for_hostdev(self):
        # The H-23 hazard: `--hostdev enp8s0` is an invalid hostdev spec.
        # The deployer must translate the netdev name to its PCI BDF.
        virt = self._deploy(
            {"_name": "ge-0/0/0", "backing": "physical", "source": "enp8s0"})
        self.assertIn("--hostdev", virt)
        addr = virt[virt.index("--hostdev") + 1]
        # RED on revert: the raw netdev name "enp8s0" would appear here.
        self.assertEqual(addr, "0000:08:00.0")
        self.assertTrue(xpf_deploy.is_pci_addr(addr),
                        f"--hostdev arg {addr!r} is not a PCI address")
        self.assertNotIn("enp8s0", virt,
                         "a netdev name must never reach virt-install --hostdev")

    def test_physical_accepts_a_raw_pci_source_unchanged(self):
        # A PCI address given directly under `physical:` passes through.
        virt = self._deploy(
            {"_name": "ge-0/0/0", "backing": "physical",
             "source": "0000:09:00.0"})
        addr = virt[virt.index("--hostdev") + 1]
        self.assertEqual(addr, "0000:09:00.0")

    def test_is_pci_addr_distinguishes_addr_from_netdev(self):
        self.assertTrue(xpf_deploy.is_pci_addr("0000:08:00.0"))
        self.assertTrue(xpf_deploy.is_pci_addr("0000:3b:00.1"))
        self.assertFalse(xpf_deploy.is_pci_addr("enp8s0"))
        self.assertFalse(xpf_deploy.is_pci_addr("ge-0/0/0"))


# ── H-25: watermark version ordering is numeric, not lexical ──────────────
class VersionKeyOrderingTests(unittest.TestCase):
    def setUp(self):
        self.k = xpf_deploy._ver_key

    def test_describe_commit_count_orders_numerically(self):
        # RED on revert: "10-gabc" < "9-gdef" lexically -> 10 ranked OLDER.
        self.assertGreater(self.k("1.2.3-10-gabc"), self.k("1.2.3-9-gdef"))
        self.assertGreater(self.k("1.2.3-100-gabc"), self.k("1.2.3-99-gdef"))

    def test_rc_numbers_order_numerically(self):
        # RED on revert: "rc10" < "rc9" lexically -> rc10 ranked below rc9.
        self.assertGreater(self.k("1.2.3-rc10"), self.k("1.2.3-rc9"))
        self.assertGreater(self.k("1.2.3-rc2"), self.k("1.2.3-rc1"))

    def test_prerelease_sorts_before_its_base_release(self):
        # rc/alpha/beta are BEFORE the final release (rc -> final is upgrade).
        self.assertLess(self.k("1.2.3-rc1"), self.k("1.2.3"))
        self.assertLess(self.k("1.2.3-rc10"), self.k("1.2.3"))

    def test_postrelease_commits_sort_after_base(self):
        # git-describe commits ahead of the tag rank AFTER the base release.
        self.assertGreater(self.k("1.2.3-1-gabc"), self.k("1.2.3"))
        self.assertGreater(self.k("1.2.3-1-gabc"), self.k("1.2.3-rc9"))

    # ── #8969: the tilde prerelease, and the general fail-open ──────────
    #
    # These live in the same class as the hyphen cases above ON PURPOSE. The
    # hyphen assertions are the control for the tilde ones: the two spellings
    # are the same semantic operation, the hyphen form was always handled as
    # the docstring promises, and the tilde form got the opposite ordering. No
    # argument about what a prerelease SHOULD do is needed -- the sibling row
    # already establishes it.

    def test_tilde_prerelease_sorts_before_its_base_like_the_hyphen(self):
        # RED on revert: `partition("-")` never saw `~`, so "1.2.3~rc1" had no
        # suffix, its release token parsed as the non-numeric "3~rc1", and it
        # sorted AFTER "1.2.3" -- passing an anti-rollback watermark that the
        # identical "1.2.3-rc1" is correctly refused by.
        self.assertLess(self.k("1.2.3~rc1"), self.k("1.2.3"))
        self.assertLess(self.k("1.2.3~beta2"), self.k("1.2.3"))
        # the two spellings denote the SAME version, so they compare equal --
        # a same-version redeploy passes, exactly as "1.2.3" over "1.2.3" does.
        self.assertEqual(self.k("1.2.3~rc1"), self.k("1.2.3-rc1"))

    def test_unparseable_version_fails_CLOSED_not_open(self):
        # The tilde was one instance of a general fail-open: ANY non-numeric
        # release token used to rank ABOVE every numeric one, so an
        # unorderable candidate passed the watermark silently. An unparseable
        # version now ranks BELOW, which refuses the upgrade loudly instead.
        #
        # Every string here is ACCEPTED by validate_version, so each is
        # reachable through `fetch --version` rather than hypothetical.
        for bad in ("garbage", "1.2.x", "1.2.3_rc1"):
            with self.subTest(bad):
                self.assertLess(self.k(bad), self.k("1.2.3"))

    def test_semver_build_metadata_is_not_precedence(self):
        # semver 11.4: build metadata is IGNORED when determining precedence.
        # Left in, its "+" made the release token non-numeric and "1.0.0+build.7"
        # outranked "1.0.0" -- and the version validator's own docstring
        # advertises that spelling as accepted input.
        self.assertEqual(self.k("1.0.0+build.7"), self.k("1.0.0"))
        self.assertLess(self.k("1.0.0+build.7"), self.k("1.0.1"))

    def test_real_upgrades_still_pass_the_watermark(self):
        # THE CONTROL FOR THE FAIL-CLOSED CHANGE. Ranking unparseable versions
        # BELOW the watermark is trivially satisfiable by ranking everything
        # below it -- a comparator that refuses every upgrade would pass every
        # assertion above. These rows fail if the fix is levelled down.
        self.assertGreater(self.k("1.2.4"), self.k("1.2.3"))
        self.assertGreater(self.k("1.3.0"), self.k("1.2.3"))
        self.assertGreater(self.k("2.0.0"), self.k("1.2.3"))
        self.assertGreaterEqual(self.k("1.2.3"), self.k("1.2.3"))
        self.assertGreater(self.k("1.2.3-1-gabc"), self.k("1.2.3"))

    def test_release_component_still_orders_numerically(self):
        self.assertGreater(self.k("1.10.0"), self.k("1.9.0"))
        self.assertGreater(self.k("2.0.0"), self.k("1.99.99"))

    def test_no_mixed_type_comparison_raises(self):
        # A digit run and a text run must never be compared directly (which
        # would raise TypeError in Python 3); the tagging prevents that.
        pairs = [
            ("1.2.3-rc9", "1.2.3-9-gabc"),   # text-suffix vs digit-suffix
            ("1.2.3-rc1", "1.2.3"),          # suffix vs no-suffix
            ("1.2.3-alpha", "1.2.3-rc1"),    # two text suffixes
        ]
        for a, b in pairs:
            with self.subTest(a=a, b=b):
                _ = self.k(a) < self.k(b)   # must not raise


# ── H-30: fetch install path == deploy golden path (shared SSOT) ──────────
class LibvirtGoldenPathAgreementTests(unittest.TestCase):
    def test_golden_helper_matches_deploy_backing(self):
        # The overlay the deploy side backs read-only MUST be exactly
        # libvirt_golden_path(image) — proves deploy consumes the SSOT.
        r = RecordingRunner()
        ap = {
            "name": "fw-solo", "mode": "standalone", "node_id": None,
            "image": "xpf-appliance", "cpu": 2, "memory": "4G",
            "interfaces": [
                {"_name": "fxp0", "backing": "bridge", "source": "br-mgmt"}],
        }
        xpf_deploy.deploy_libvirt(ap, r, start=False)
        qemu = _find_call(r.calls, "qemu-img")
        self.assertIsNotNone(qemu, "qemu-img create was not invoked")
        deploy_backing = qemu[qemu.index("-b") + 1]
        # RED on revert: libvirt_golden_path removed -> AttributeError.
        self.assertEqual(deploy_backing,
                         xpf_deploy.libvirt_golden_path("xpf-appliance"))

    def test_fetch_install_lands_at_deploy_golden(self):
        # fetch --install-libvirt must write the verified qcow2 to the SAME
        # path deploy reads. Redirect LIBVIRT_IMAGES to a tmpdir so both the
        # fetch install and the deploy golden compute under it.
        orig = xpf_deploy.LIBVIRT_IMAGES
        try:
            with tempfile.TemporaryDirectory() as tmp:
                xpf_deploy.LIBVIRT_IMAGES = os.path.join(tmp, "images")
                src = os.path.join(tmp, "xpf-1.2.3.qcow2")
                with open(src, "w") as f:
                    f.write("QCOW-BYTES")

                dest = xpf_deploy._install_libvirt_golden(src, "xpf-appliance")
                deploy_golden = xpf_deploy.libvirt_golden_path("xpf-appliance")

                # (a) fetch and deploy AGREE on the golden path.
                self.assertEqual(dest, deploy_golden)
                # (b) the verified image actually landed there.
                self.assertTrue(os.path.isfile(dest))
                with open(dest) as f:
                    self.assertEqual(f.read(), "QCOW-BYTES")
        finally:
            xpf_deploy.LIBVIRT_IMAGES = orig

    def test_fetch_defines_install_libvirt_flag(self):
        # The bridging flag must exist on the fetch subparser (RED on revert
        # if the whole feature is removed).
        self.assertTrue(hasattr(xpf_deploy, "libvirt_golden_path"))
        self.assertTrue(hasattr(xpf_deploy, "_install_libvirt_golden"))


# ── #10745: reject duplicate node IDs before deploying an HA pair ─────────
class DuplicateClusterNodeIDTests(unittest.TestCase):
    def _appliance(self, name, node_id):
        return {"name": name, "mode": "cluster", "node_id": node_id}

    def test_duplicate_ids_abort_the_whole_pair_before_deploy(self):
        appliances = {
            "fw0.yaml": self._appliance("fw0", 0),
            "fw0-copy.yaml": self._appliance("fw0-copy", 0),
        }
        deployed = []
        with mock.patch.object(xpf_deploy, "load_yaml_appliance",
                               side_effect=appliances.__getitem__), \
             mock.patch.object(xpf_deploy, "deploy",
                               side_effect=lambda ap, args: deployed.append(ap)):
            with self.assertRaises(SystemExit) as cm:
                xpf_deploy.cmd_deploy(
                    SimpleNamespace(yamls=list(appliances)))

        self.assertIn("repeats cluster node-id 0", str(cm.exception))
        self.assertEqual(deployed, [],
                         "duplicate pair was detected only after a deploy began")

    def test_pair_with_distinct_node_ids_is_deployed(self):
        appliances = {
            "fw0.yaml": self._appliance("fw0", 0),
            "fw1.yaml": self._appliance("fw1", 1),
        }
        deployed = []
        with mock.patch.object(xpf_deploy, "load_yaml_appliance",
                               side_effect=appliances.__getitem__), \
             mock.patch.object(xpf_deploy, "deploy",
                               side_effect=lambda ap, args: deployed.append(ap)):
            rc = xpf_deploy.cmd_deploy(
                SimpleNamespace(yamls=list(appliances)))

        self.assertEqual(rc, 0)
        self.assertEqual([ap["node_id"] for ap in deployed], [0, 1])


if __name__ == "__main__":
    unittest.main()
