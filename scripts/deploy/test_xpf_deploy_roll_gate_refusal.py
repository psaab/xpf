#!/usr/bin/env python3
"""Unit tests for the image-roll mixed-base gate REFUSAL path (#12207).

`test_xpf_deploy_gate.py` pins only the `_gate_mixed_base` PREDICATE, and every
roll-level suite stages manifests that always PASS (e.g.
`test_xpf_deploy_image_roll_identity.py:54-69`). The enforcement inside
`cmd_image_roll`'s `roll_one` — refuse before the first mutation, release the
leases on a pre-mutation failure, waive + relax only under explicit
`--allow-session-drop`, and pass `--allow-mixed-ha` to the second drain only
when the (still-OLD) node's binary probes as supporting it — was unpinned.
Production is alleged correct (and the Go drain gate in
pkg/upgrade/kernel_drain.go is a second layer); this suite pins the wiring.

The orchestrator fixture drives `cmd_image_roll` through the manifest
sidecar/SHA256SUMS chain. The minisign verification hook is neutralized exactly
as `MixedBaseSignedManifestTests` does; checksum binding is genuine: the
signed-but-INCOMPATIBLE new image (session-sync 6) against an OLD peer (ha 3 /
sync 5) must die with the gate reason BEFORE any drain or recreate, with BOTH
leases released (the `finally`'s `completed or not state_changed` leg — a
pre-mutation failure, not a held half-roll).

Mutant map (enforcement branches):

  M1 (no-drain build): weaken/remove the pre-drain refusal so the old peer is
      drained despite the incompatible manifest. The refusal oracle fails on
      its no-drain assertion.
  M3 (#10261-shape replay): recreate the node before refusing the incompatible
      session-sync shape. The refusal oracle fails on its no-recreate assertion;
      no drain or successful incompatible daemon is simulated.
  M4 (lease release): remove the pre-mutation `not state_changed` release leg.
      The lease-release assertion fails because both leases stay TTL-held.

The first/second-drain argv tests are REQUIRED controls for the feature probe,
not additional mutants. M2 (`assert_live`) is cohort-level at most, kept
separate per triage; this fixture does not add or label an `assert_live` check.

"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))
xpf_deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xpf_deploy)

R = xpf_deploy.NodeExecResult

NEWVER = "2.0.0-newimage"
OLDVER = "1.0.0-oldimage"

# The SIGNED new-image sidecar: session-sync 6, which the OLD peer (sync 5,
# below) does NOT speak -> the mixed-base gate FAILS. ha window [2,3] keeps
# the peer's ha 3 in-window so the failure is purely the session-sync leg.
NEW_MANIFEST_TEXT = """xpf_version: 2.0.0-newimage
ha_protocol_version: 3
ha_protocol_min_compat: 2
session_sync_protocol_version: 6
validated: true
"""

# A SIGNED new-image sidecar the OLD peer accepts (sync 5 == peer sync 5):
# the passing-gate control for the drain-argv cases.
COMPAT_MANIFEST_TEXT = """xpf_version: 2.0.0-newimage
ha_protocol_version: 3
ha_protocol_min_compat: 2
session_sync_protocol_version: 5
validated: true
"""


def _old_peer_proto():
    """`xpfd protocol-versions` as the still-OLD peer reports it: ha 3 in the
    new image's window, but session-sync 5 != new image sync 6."""
    return ("xpf-version=%s\n"
            "ha-protocol-version=3\n"
            "session-sync-protocol-version=5\n") % OLDVER


class _GateFake:
    """Scripted `_node_exec` for cmd_image_roll. Records drains, rejoins,
    recreates (via the patched hook wrapper), drain argv, and lease
    acquire/clear calls (distinguished by script content: the acquire script
    echoes ACQUIRED; the clear script removes the lease file). The mixed-ha
    probe answer is scripted per node via `probe`."""

    def __init__(self, reported, node_ids, probe=True, new_sync="6",
                 stop_after_first_drain=False):
        # reported: {node: proto-text or None} (None => xpfd not answering)
        self.reported = dict(reported)
        self.node_ids = dict(node_ids)
        self.new_sync = new_sync
        self.stop_after_first_drain = stop_after_first_drain
        if isinstance(probe, bool):
            probe = {n: probe for n in reported}
        self.probe = probe
        self.drained = []
        self.drain_argvs = []
        self.rejoined = []
        self.recreated = []
        self.acquired = []
        self.cleared = []

    def mark_recreated(self, node):
        self.recreated.append(node)
        self.reported[node] = (
            "xpf-version=%s\nha-protocol-version=3\n"
            "session-sync-protocol-version=%s\n" % (NEWVER, self.new_sync))

    def __call__(self, runner, backend, node, argv, check=True):
        if argv[:2] == ["sh", "-c"]:
            script = argv[2] if len(argv) > 2 else ""
            if "drain --help" in script:
                # The --allow-mixed-ha feature probe: answer per node.
                return ("-allow-mixed-ha\n" if self.probe.get(node, False)
                        else "usage: drain\n")
            if "rm -f" in script and "kernel-roll.lease" in script:
                self.cleared.append(node)
                return ""
            # Lease acquire (echoes ACQUIRED) and anything else sh-wrapped.
            if "ACQUIRED" in script:
                self.acquired.append(node)
                return "ACQUIRED\n"
            return ""
        if argv == ["xpfd", "protocol-versions"]:
            return self.reported.get(node) or ""
        if argv == ["cat", "/etc/xpf/node-id"]:
            nid = self.node_ids.get(node)
            return "" if nid is None else "%d\n" % nid
        if argv[:4] == ["xpfd", "upgrade", "kernel", "drain"]:
            self.drained.append(node)
            self.drain_argvs.append(list(argv))
            if self.stop_after_first_drain and len(self.drained) == 1:
                # Stop at the orchestrator/daemon boundary. Do not simulate a
                # successful drain for the incompatible-shape mutants.
                raise SystemExit("fixture stopped at drain command boundary")
            return ""
        if argv[:4] == ["xpfd", "upgrade", "kernel", "rejoin"]:
            self.rejoined.append(node)
            return ""
        return ""


def _roll_args(**over):
    kw = dict(
        dry_run=False, backend="ssh", nodes=["fw0", "fw1"],
        node0_id=0, node1_id=1,
        recreate_hook="/bin/true",
        manifest="xpf-2.0.0-newimage.manifest",
        sha256sums=None, sig=None, pubkey=None,
        lease_ttl=1800, drain_deadline=120, boot_deadline=40,
        allow_session_drop=False,
        allow_unvalidated=False,
        require_daemon_hold=False)
    kw.update(over)
    return types.SimpleNamespace(**kw)


class SignedFixtureBase(unittest.TestCase):
    """Stage the manifest/checksum chain and drive cmd_image_roll.

    Minisign verification is stubbed per the existing test convention;
    manifest/checksum binding and qcow2 digest resolution use real helpers.
    """

    manifest_text = NEW_MANIFEST_TEXT

    def setUp(self):
        here = Path(__file__).resolve().parent
        sys.path.insert(0, str(here.parent / "dist"))
        import sign
        self.sign = sign
        self.tmp = tempfile.mkdtemp(prefix="xpf-12207-test-")
        self.pub = os.path.join(self.tmp, "test.pub")
        with open(self.pub, "w") as f:
            f.write("untrusted-test-key\n")
        # As in MixedBaseSignedManifestTests: the SHA256SUMS + .minisig are
        # the SIGNED bytes, modelled as validly signed; the CHECKSUM binding
        # (pure Python) is exercised for real.
        self._orig_verify_sig = sign.verify_signature
        sign.verify_signature = lambda m, s, p: None
        # Stage the sidecar + the signed set covering sidecar + qcow2 (the
        # #10852 qcow2 binding resolves the signed digest for real).
        self.manifest = os.path.join(self.tmp, "xpf-2.0.0-newimage.manifest")
        with open(self.manifest, "w") as f:
            f.write(self.manifest_text)
        self.qcow2 = os.path.join(self.tmp, "xpf-2.0.0-newimage.qcow2")
        with open(self.qcow2, "w") as f:
            f.write("fake-image-bytes")
        self.sums = os.path.join(self.tmp, "xpf-2.0.0-newimage.SHA256SUMS")
        self.sign.write_manifest(self.sums, [self.manifest, self.qcow2])
        self.sig = self.sums + ".minisig"
        with open(self.sig, "w") as f:
            f.write("stub-signature (verify_signature patched)\n")

    def tearDown(self):
        self.sign.verify_signature = self._orig_verify_sig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, fake, **arg_over):
        """Drive cmd_image_roll against `fake` with the staged signed chain.
        Only the node surface, the recreate hook, and time are faked."""
        args = _roll_args(manifest=self.manifest,
                          sha256sums=self.sums, sig=self.sig,
                          pubkey=self.pub, **arg_over)
        stack = [
            mock.patch.object(xpf_deploy, "_node_exec", fake),
            # The #5816 renew/fence path answers every renew still-owned.
            mock.patch.object(xpf_deploy, "_node_exec_result",
                              lambda runner, backend, node, argv:
                                  R(0, "RENEWED\n", "", True)),
            mock.patch.object(
                xpf_deploy, "_recreate_node_from_image",
                lambda *a, **k: fake.mark_recreated(a[2])),
            mock.patch("time.sleep", lambda *a, **k: None),
        ]
        for p in stack:
            p.start()
        try:
            return xpf_deploy.cmd_image_roll(args)
        finally:
            for p in reversed(stack):
                p.stop()


class MixedBaseGateRefusalTests(SignedFixtureBase):
    """A signed-but-incompatible manifest + old peer must refuse BEFORE any
    mutation, name the reason, and release both leases."""

    def test_failed_gate_refuses_before_any_mutation(self):
        # M1 bypassing the refusal must reach the drain-command boundary;
        # M3 recreating before refusal is caught by the no-recreate assertion.
        fake = _GateFake(
            reported={"fw0": _old_peer_proto(), "fw1": _old_peer_proto()},
            node_ids={"fw0": 0, "fw1": 1}, stop_after_first_drain=True)
        try:
            self._run(fake)
        except SystemExit as exc:
            msg = str(exc)
        else:
            msg = ""
        self.assertEqual(fake.drained, [],
                         "a refused gate must NOT drain any node")
        self.assertEqual(fake.recreated, [],
                         "a refused gate must NOT recreate any node")
        self.assertEqual(fake.rejoined, [])
        self.assertIn("mixed-base gate FAILED", msg)
        self.assertIn("session-sync protocol differs", msg,
                      "the failure reason must name the mismatched leg")
        self.assertIn("peer 5", msg)
        self.assertIn("new image 6", msg)
        self.assertIn("--allow-session-drop", msg,
                      "the refusal must state the explicit override")

    def test_failed_gate_releases_both_leases(self):
        # M4: this failed gate has not changed cluster state, so finally must
        # release both acquired leases rather than TTL-holding them.
        fake = _GateFake(
            reported={"fw0": _old_peer_proto(), "fw1": _old_peer_proto()},
            node_ids={"fw0": 0, "fw1": 1})
        with self.assertRaises(SystemExit):
            self._run(fake)
        self.assertEqual(sorted(fake.acquired), ["fw0", "fw1"],
                         "both leases must have been acquired first")
        self.assertEqual(sorted(fake.cleared), ["fw0", "fw1"],
                         "a pre-mutation failure must release both leases")


class AllowSessionDropTests(SignedFixtureBase):
    """The explicit override reaches the first drain but does not fake a
    successful incompatible daemon or a completed mixed-wire roll."""

    def test_explicit_allow_drop_reaches_first_drain(self):
        # Same incompatible old peer, but the operator accepted the drop.
        # Stop at the drain command boundary: this pins the waiver's argv
        # without pretending the incompatible daemon successfully drained.
        fake = _GateFake(
            reported={"fw0": _old_peer_proto(), "fw1": _old_peer_proto()},
            node_ids={"fw0": 0, "fw1": 1}, probe=True,
            stop_after_first_drain=True)
        with self.assertRaises(SystemExit) as cm:
            self._run(fake, allow_session_drop=True)
        self.assertEqual(str(cm.exception),
                         "fixture stopped at drain command boundary")
        self.assertEqual(fake.drained, ["fw0"])
        self.assertIn("--allow-mixed-ha", fake.drain_argvs[0],
                      "explicit waiver relaxes the drain HA precheck")
        self.assertEqual(fake.recreated, [],
                         "the fixture must not simulate an incompatible "
                         "daemon completing a recreate")
        self.assertEqual(fake.rejoined, [])


class DrainArgvProbeTests(SignedFixtureBase):
    """First/second-drain argv cases under a passing gate and signed manifest."""

    manifest_text = COMPAT_MANIFEST_TEXT

    def _full_roll(self, probe):
        fake = _GateFake(
            reported={"fw0": _old_peer_proto(), "fw1": _old_peer_proto()},
            node_ids={"fw0": 0, "fw1": 1}, probe=probe, new_sync="5")
        rc = self._run(fake)
        self.assertEqual(rc, 0)
        self.assertEqual(fake.drained, ["fw0", "fw1"])
        return fake

    def test_first_drain_never_relaxed_second_drain_relaxed(self):
        # Control: the first drain has not waived the HA precheck; only the
        # second drain, against the rolled peer, may carry the flag.
        fake = self._full_roll(probe=True)
        self.assertNotIn("--allow-mixed-ha", fake.drain_argvs[0],
                         "the first drain must NOT relax the HA precheck")
        self.assertIn("--allow-mixed-ha", fake.drain_argvs[1],
                      "the second drain relaxes against the rolled peer")

    def test_second_drain_omits_flag_when_probe_false(self):
        # Control: a pre-INC-3 binary on the second-drain node must not receive
        # the unsupported flag; fall back to the exact-equality precheck.
        fake = self._full_roll(probe={"fw0": True, "fw1": False})
        self.assertNotIn("--allow-mixed-ha", fake.drain_argvs[0])
        self.assertNotIn("--allow-mixed-ha", fake.drain_argvs[1],
                         "a binary that predates --allow-mixed-ha must not "
                         "be passed the flag")



if __name__ == "__main__":
    unittest.main()
