#!/usr/bin/env python3
"""Unit tests for the image-roll post-recreate IDENTITY + VERSION gate (#5075).

In the LANE-2 HA image roll, each node is DRAINED to its peer, then RECREATED
from the new golden image by an operator-supplied `--recreate-hook`
(destroy + launch + day-0). The driver then polls until the node "comes back"
before rejoining it and moving on to the peer.

Before the fix, the readiness poll accepted ANY responding xpfd:

    pv = _node_protocol_versions(runner, backend, node)
    if pv.get("xpf-version"):      # <-- non-empty is enough
        back = True

so a `--recreate-hook` that relaunched the OLD image, a stale alias, or the
WRONG node-id satisfied the poll. The driver rejoined the wrong/old node and
proceeded to the peer with the pair on unintended/mixed software — a silent
deploy-integrity failure (the operator believes the image rolled when it did
not, or rolled the wrong node).

The fix requires the responding xpfd to be BOTH:
  - the EXPECTED build: its live `xpf-version` EXACTLY equals the AUTHENTICATED
    image manifest's xpf-version (`new_img`, already verified against the signed
    SHA256SUMS for the mixed-base gate), AND
  - the EXPECTED node: its /etc/xpf/node-id (the marker xpfd itself keys HA
    identity on) equals the cluster node-id the deploy assigned.
Any mismatch FAILS CLOSED with the never-both-down leases HELD; the peer stays
primary and the roll ERRORS instead of silently accepting.

RED on revert: restore `if pv.get("xpf-version"): back = True; break` (drop the
`_recreated_node_matches` gate) and both `test_wrong_build_recreate_rejected`
and `test_wrong_node_id_recreate_rejected` flip GREEN->RED — the old/wrong node
is accepted, the roll COMPLETES (rc=0) instead of raising SystemExit, and the
peer is rolled onto unintended software.
"""

from __future__ import annotations

import importlib.util
import types
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))
xpf_deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xpf_deploy)

NEWVER = "2.0.0-newimage"
OLDVER = "1.0.0-oldimage"

# The AUTHENTICATED image manifest the mixed-base gate + the #5075 identity gate
# read. Only xpf-version drives the identity gate; the ha/session-sync fields
# keep the (separately-tested) mixed-base gate passing so the roll reaches the
# post-recreate poll under test.
NEW_MANIFEST = {
    "xpf-version": NEWVER,
    "ha-protocol-version": "3",
    "ha-protocol-min-compat": "2",
    "session-sync-protocol-version": "5",
}


def _reported(xpf_version):
    """The `xpfd protocol-versions` a node REPORTS. ha/session-sync are held
    identical to NEW_MANIFEST so the mixed-base gate always passes — this suite
    targets the #5075 identity+version gate, not the mixed-base gate."""
    return {
        "xpf-version": xpf_version,
        "ha-protocol-version": "3",
        "session-sync-protocol-version": "5",
    }


class _Clock:
    """Monotonic fake clock so the boot-deadline poll loop terminates fast under
    mocked time.sleep. Each call advances `step`; with boot_deadline=40 and
    step=15 the reject path runs ~2 iterations then the deadline elapses."""

    def __init__(self, start=1000.0, step=15.0):
        self.t = start
        self.step = step

    def __call__(self):
        v = self.t
        self.t += self.step
        return v


class _RollFake:
    """Scripted `_node_exec` for cmd_image_roll. Each node reports its OWN
    xpf-version and its OWN /etc/xpf/node-id, so a recreation can be driven to
    the correct or the wrong build / node-id. Records drains and rejoins so a
    test can assert the peer was never touched on a rejected roll."""

    def __init__(self, reported, node_ids):
        # reported: {node_name: xpf_version_or_None}  (None => xpfd not answering)
        # node_ids: {node_name: int_or_None}          (None => /etc/xpf/node-id absent)
        self.reported = reported
        self.node_ids = node_ids
        self.drained = []
        self.rejoined = []

    def __call__(self, runner, backend, node, argv, check=True):
        # Lease acquire/clear + the drain --help feature probe all arrive as
        # ["sh", "-c", <script>]; ACQUIRED satisfies _acquire_lease and the
        # probe simply won't find "allow-mixed-ha" (drains without the flag).
        if argv[:2] == ["sh", "-c"]:
            return "ACQUIRED\n"
        if argv == ["xpfd", "protocol-versions"]:
            xv = self.reported.get(node)
            d = _reported(xv) if xv is not None else {}
            return "".join(f"{k}={v}\n" for k, v in d.items())
        if argv == ["cat", "/etc/xpf/node-id"]:
            nid = self.node_ids.get(node)
            return "" if nid is None else f"{nid}\n"
        if argv[:4] == ["xpfd", "upgrade", "kernel", "drain"]:
            self.drained.append(node)
            return ""
        if argv[:4] == ["xpfd", "upgrade", "kernel", "rejoin"]:
            self.rejoined.append(node)
            return ""
        return ""


def _img_args():
    return types.SimpleNamespace(
        dry_run=False, backend="ssh", nodes=["fw0", "fw1"],
        node0_id=0, node1_id=1,
        recreate_hook="/bin/true",
        manifest="xpf-2.0.0-newimage.manifest",
        sha256sums=None, sig=None, pubkey=None,
        lease_ttl=1800, drain_deadline=120, boot_deadline=40,
        allow_session_drop=False,
        # #7559: this suite drives the identity gate, not the daemon hold. The
        # scripted `_node_exec_result` answers every probe with the lease
        # renewal text, so `systemctl show xpfd` classifies as "unknown" and the
        # roll behaves exactly as it did before the hold existed.
        require_daemon_hold=False)


def _patches(fake):
    """Neutralize the signature/IO/recreate machinery so the test drives ONLY
    the post-recreate identity+version gate: the manifest verify returns the
    authenticated NEW_MANIFEST, the manifest/sums/sig files "exist", the recreate
    hook is a no-op, and time is faked so the poll loop terminates fast."""
    return [
        mock.patch.object(xpf_deploy, "_node_exec", fake),
        # The #5816 renew/fence path goes through _node_exec_result (structured
        # result) so a mid-reboot transport failure is not misread as a lost
        # lease. These identity tests do not exercise lease loss, so answer every
        # renew with a still-owned verdict (RENEWED) — the roll proceeds.
        mock.patch.object(xpf_deploy, "_node_exec_result",
                          lambda runner, backend, node, argv:
                              xpf_deploy.NodeExecResult(0, "RENEWED\n", "", True)),
        mock.patch.object(xpf_deploy, "_recreate_node_from_image",
                          lambda *a, **k: None),
        mock.patch.object(xpf_deploy, "_verified_image_manifest_versions",
                          lambda *a, **k: dict(NEW_MANIFEST)),
        mock.patch.object(xpf_deploy, "_verified_expected_qcow2_digest",
                          lambda *a, **k: ("xpf-2.0.0-newimage.qcow2", "a" * 64)),
        mock.patch.object(xpf_deploy.os.path, "isfile", lambda p: True),
        mock.patch("time.sleep", lambda *a, **k: None),
        mock.patch("time.time", _Clock()),
    ]


class RecreatedNodeMatchesTests(unittest.TestCase):
    """The pure #5075 identity+version predicate."""

    def test_matching_build_and_node_id_accepted(self):
        ok, reason = xpf_deploy._recreated_node_matches(
            _reported(NEWVER), NEWVER, 0, 0)
        self.assertTrue(ok, reason)

    def test_empty_live_version_is_not_back(self):
        # xpfd not answering yet -> keep polling (never a false "back").
        ok, _ = xpf_deploy._recreated_node_matches({}, NEWVER, None, 0)
        self.assertFalse(ok)

    def test_missing_manifest_version_fails_closed(self):
        ok, reason = xpf_deploy._recreated_node_matches(
            _reported(NEWVER), "", 0, 0)
        self.assertFalse(ok)
        self.assertIn("manifest", reason)

    def test_wrong_build_rejected(self):
        ok, reason = xpf_deploy._recreated_node_matches(
            _reported(OLDVER), NEWVER, 0, 0)
        self.assertFalse(ok)
        self.assertIn(OLDVER, reason)
        self.assertIn(NEWVER, reason)

    def test_unreadable_node_id_fails_closed(self):
        ok, reason = xpf_deploy._recreated_node_matches(
            _reported(NEWVER), NEWVER, None, 0)
        self.assertFalse(ok)
        self.assertIn("node-id", reason)

    def test_wrong_node_id_rejected(self):
        ok, reason = xpf_deploy._recreated_node_matches(
            _reported(NEWVER), NEWVER, 1, 0)
        self.assertFalse(ok)
        self.assertIn("WRONG node", reason)


class NodeClusterNodeIDTests(unittest.TestCase):
    """/etc/xpf/node-id parsing fails closed on absent/garbage content."""

    def _read(self, out):
        with mock.patch.object(xpf_deploy, "_node_exec",
                               lambda *a, **k: out):
            return xpf_deploy._node_cluster_node_id(
                xpf_deploy.Runner(False), "ssh", "fw0")

    def test_valid(self):
        self.assertEqual(self._read("0\n"), 0)
        self.assertEqual(self._read("1\n"), 1)

    def test_absent_or_garbage_is_none(self):
        self.assertIsNone(self._read(""))
        self.assertIsNone(self._read("not-an-int\n"))


class ImageRollIdentityGateTests(unittest.TestCase):
    """End-to-end cmd_image_roll: the post-recreate poll must reject a
    responding-but-wrong xpfd and accept only the expected node+build."""

    def _run(self, fake):
        stack = _patches(fake)
        for p in stack:
            p.start()
        try:
            return xpf_deploy.cmd_image_roll(_img_args())
        finally:
            for p in reversed(stack):
                p.stop()

    def test_wrong_build_recreate_rejected(self):
        # fw0 is recreated but comes back on the OLD build (stale alias / old
        # image). It must be REJECTED, the peer never touched, leases held.
        fake = _RollFake(reported={"fw0": OLDVER, "fw1": OLDVER},
                         node_ids={"fw0": 0, "fw1": 1})
        with self.assertRaises(SystemExit) as cm:
            self._run(fake)
        msg = str(cm.exception)
        self.assertIn(OLDVER, msg, "the wrong build must be named in the error")
        self.assertNotIn("fw0", fake.rejoined,
                         "a wrong-build node must NOT be rejoined")
        self.assertEqual(fake.drained, ["fw0"],
                         "the peer fw1 must NOT be drained after fw0 is rejected")

    def test_wrong_node_id_recreate_rejected(self):
        # fw0 comes back on the RIGHT build but with the WRONG node-id (the hook
        # launched node-id 1 where 0 was expected). Must be REJECTED.
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": OLDVER},
                         node_ids={"fw0": 1, "fw1": 1})
        with self.assertRaises(SystemExit) as cm:
            self._run(fake)
        msg = str(cm.exception)
        self.assertIn("WRONG node", msg)
        self.assertNotIn("fw0", fake.rejoined)
        self.assertEqual(fake.drained, ["fw0"])

    def test_never_responding_node_times_out(self):
        # xpfd never answers protocol-versions -> fail closed on the deadline
        # (this path was already safe pre-fix; guard it stays safe).
        fake = _RollFake(reported={"fw0": None, "fw1": OLDVER},
                         node_ids={"fw0": 0, "fw1": 1})
        with self.assertRaises(SystemExit) as cm:
            self._run(fake)
        self.assertIn("did NOT come back", str(cm.exception))
        self.assertNotIn("fw0", fake.rejoined)

    def test_correct_node_and_build_accepted(self):
        # Both nodes recreate onto the NEW build with the expected node-ids ->
        # the roll COMPLETES: both drained, both rejoined, rc=0.
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1})
        rc = self._run(fake)
        self.assertEqual(rc, 0)
        self.assertEqual(fake.drained, ["fw0", "fw1"])
        self.assertEqual(fake.rejoined, ["fw0", "fw1"])


if __name__ == "__main__":
    unittest.main()
