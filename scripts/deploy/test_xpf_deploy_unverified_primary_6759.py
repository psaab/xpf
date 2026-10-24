#!/usr/bin/env python3
"""#6759: detect a recreated node that is PRIMARY before its identity is proven.

The image-roll drains the node, then RECREATES it — a fresh disk. That wipes
the drain, because the drain lived on the disk that was replaced. The identity
gate (live xpf-version == the AUTHENTICATED manifest's, and /etc/xpf/node-id ==
the assigned cluster node-id, #5075) runs AFTERWARDS in the boot poll. Between
bringup and gate-pass the node is un-drained with unvalidated identity.

WHAT THIS DOES NOT DO. It does not close the window. The election happens during
the recreated node's own bringup — `daemon_run_bringup.go` runs `UpdateConfig`,
which elects on the single-node path — before any driver command reaches the
node. This DETECTS the exposure and stops the roll; it cannot prevent it.

Why the kernel-roll's fix cannot be reused: `holdSecondaryIfKernelCandidateArmed`
keys the election hold on the on-node kernel journal, and
`kernel_selfrecover.go` folds a clean ENOENT to "never armed" with no hold. A
reboot preserves that journal so ENOENT genuinely means "never armed"; a
recreate DESTROYS it, so ENOENT means "the evidence was wiped" — and nothing on
the node can tell those apart. The distinction is correct for the path it was
written for and has no way to be right for this one.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

xpf_deploy = load_subject("xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))


_STATUS_TEMPLATE = """Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring

Cluster ID: 1
Node name: node{me}

Redundancy group: 0 , Failover count: 2
    node0   200       {n0_rg0}        no       no       None
    node1   100       {n1_rg0}      no       no       None

Redundancy group: 1 , Failover count: 0
    node0   200       {n0_rg1}        no       no       None
    node1   100       {n1_rg1}      no       no       None
"""


def _status(me=0, n0_rg0="primary", n1_rg0="secondary",
            n0_rg1="primary", n1_rg1="secondary"):
    return _STATUS_TEMPLATE.format(me=me, n0_rg0=n0_rg0, n1_rg0=n1_rg0,
                                   n0_rg1=n0_rg1, n1_rg1=n1_rg1)


class _Exec:
    """Stands in for _node_exec, returning a canned status."""

    def __init__(self, out):
        self.out = out
        self.calls = []

    def __call__(self, runner, backend, node, argv, check=True):
        self.calls.append(list(argv))
        return self.out


class UnverifiedPrimaryDetectionTests(unittest.TestCase):
    def _with_status(self, out):
        stub = _Exec(out)
        real = xpf_deploy._node_exec
        xpf_deploy._node_exec = stub
        self.addCleanup(lambda: setattr(xpf_deploy, "_node_exec", real))
        return stub

    def test_detects_this_node_primary(self):
        self._with_status(_status(n0_rg0="primary"))
        self.assertIs(
            xpf_deploy._node_is_primary_for_any_rg(None, "incus", "fw0", 0), True,
            "node0 holds primary for RG0 and must be detected — an unverified node "
            "carrying traffic is the whole point of the check")

    def test_secondary_everywhere_is_not_primary(self):
        self._with_status(_status(n0_rg0="secondary", n0_rg1="secondary"))
        self.assertIs(
            xpf_deploy._node_is_primary_for_any_rg(None, "incus", "fw0", 0), False)

    def test_the_PEER_being_primary_is_not_this_node(self):
        # The OVER-DETECTION control, and the realistic healthy case: during a
        # correct roll the still-up PEER is primary for everything. Reading the
        # peer's row as ours would abort every good roll.
        self._with_status(_status(n0_rg0="secondary", n1_rg0="primary",
                                  n0_rg1="secondary", n1_rg1="primary"))
        self.assertIs(
            xpf_deploy._node_is_primary_for_any_rg(None, "incus", "fw0", 0), False,
            "the PEER (node1) is primary here; reading its row as node0's would "
            "abort every healthy image roll")

    def test_primary_in_any_rg_counts(self):
        # Secondary for RG0 but primary for RG1 — still carrying traffic.
        self._with_status(_status(n0_rg0="secondary", n0_rg1="primary"))
        self.assertIs(
            xpf_deploy._node_is_primary_for_any_rg(None, "incus", "fw0", 0), True)

    def test_unreadable_status_is_None_not_False(self):
        # An unreadable state must NOT be reported as "not primary": the caller
        # would turn an absent observation into a pass. None means "no
        # observation this tick", and the poll simply tries again.
        for out in ("", "Cluster not configured", None):
            self._with_status(out)
            self.assertIsNone(
                xpf_deploy._node_is_primary_for_any_rg(None, "incus", "fw0", 0),
                f"unreadable status {out!r} must be None, never False")

    def test_absent_node_id_is_None(self):
        # The identity gate may not have read a node-id yet. With no id there is
        # no row to match, so there is no observation — not a pass.
        self._with_status(_status())
        self.assertIsNone(
            xpf_deploy._node_is_primary_for_any_rg(None, "incus", "fw0", None))

    def test_a_non_node_row_is_never_read_as_a_node_row(self):
        # #4009: a line inside an RG block that is not a node row must not be
        # matched. Fields are compared exactly for this reason — a substring
        # match on "primary" would fire on the header text below.
        out = _status(n0_rg0="secondary", n0_rg1="secondary").replace(
            "Redundancy group: 0 , Failover count: 2\n",
            "Redundancy group: 0 , Failover count: 2\n"
            "    Note: node0 was primary before the last failover\n", 1)
        self._with_status(out)
        self.assertIs(
            xpf_deploy._node_is_primary_for_any_rg(None, "incus", "fw0", 0), False,
            "a prose line mentioning node0 and primary was read as a node row — "
            "that is the #4009 misparse, which steered a deploy into restarting "
            "the PRIMARY first")

    def test_it_reads_the_cluster_status_command(self):
        # BIND THE WIRING: the helper must actually ask the node for its cluster
        # status, not infer it from something already in hand.
        stub = self._with_status(_status())
        xpf_deploy._node_is_primary_for_any_rg(None, "incus", "fw0", 0)
        self.assertTrue(
            any("show chassis cluster status" in " ".join(c) for c in stub.calls),
            f"did not run the cluster-status read; calls were {stub.calls}")


if __name__ == "__main__":
    unittest.main()
