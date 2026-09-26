#!/usr/bin/env python3
"""Unit tests for the cross-orchestrator lease RENEW + FENCE (#5816).

The LANE-1/LANE-2 HA roll drivers (`kernel-roll` / `image-roll`) reserve BOTH
HA nodes with a lease whose deadline is `expires_at = now + --lease-ttl`. Before
this fix the lease was ONE-SHOT: `_acquire_lease` wrote the deadline once and
NEITHER roll path renewed it NOR re-verified ownership before its later mutation
points. A positive TTL shorter than the real roll duration (boot/drain deadlines,
an image-recreate hook, ordinary reboot/rejoin latency) let BOTH node leases
EXPIRE while the driver kept running — with no renewal and no ownership check. A
successor orchestrator could then atomically RECLAIM both expired leases and
start its own roll while the predecessor was still mutating the same pair:
split-brain deploy (corrupt the pair / brick both nodes).

The fix adds two mechanisms, both keyed on the SAME owner identity the existing
acquire/reclaim use (`nodename:pid<pid>` holder token):

  1. RENEWAL (`_renew_lease`): re-write `expires_at = now + ttl` iff WE still own
     the lease (holder matches), atomically (temp+rename) under the acquire
     flock. A lease another orchestrator reclaimed (holder differs / file gone)
     is reported "lost" and left untouched — renewal never resurrects a lost
     lease. Fired every poll tick (keep-alive) so a legitimately-slow roll never
     loses the lease.
  2. FENCE (`_fence_before_mutate`): immediately before EACH pair-mutating action
     (drain, arm+reboot, image-recreate, rejoin), renew-and-verify ownership of
     every lease or die() fail-closed. The load-bearing invariant: an
     orchestrator that has lost (or cannot confirm) its lease must NOT mutate the
     pair.

RED-on-revert (proven by hand, see the docstrings on the end-to-end tests):
  * Remove the fence-before-mutate call → a driver whose lease was reclaimed
    proceeds to drain/recreate a pair it no longer owns (the fence-abort tests
    flip: the mutation IS executed).
  * Remove the poll-loop keep-alive renewal → a roll that outruns its TTL loses
    the lease mid-flight and the pre-rejoin fence aborts a roll that should have
    succeeded (the renewal test flips: SystemExit instead of completion).
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

R = xpf_deploy.NodeExecResult
KNOWN_GOOD = "6.17.0-good"
CANDIDATE = "6.99.0-cand"
HOLDER = "orchA:pid1234"


# ── pure helpers: _renew_lease verdict mapping ─────────────────────────────
class RenewLeaseVerdictTests(unittest.TestCase):
    """`_renew_lease` maps the structured node result to owned/lost/unreachable.

    The tri-state is the crux: a mid-reboot TRANSPORT failure must be
    "unreachable" (retry, NEVER a loss — the #4905-A discipline), a reachable
    RENEWED is "owned", a reachable LOST (reclaimed by a peer) is "lost"."""

    def _renew_with(self, result):
        runner = xpf_deploy.Runner(False)
        with mock.patch.object(xpf_deploy, "_node_exec_result",
                               return_value=result):
            return xpf_deploy._renew_lease(runner, "ssh", "fw0", 0, HOLDER, 1800)

    def test_renewed_is_owned(self):
        self.assertEqual(self._renew_with(R(0, "RENEWED\n", "", True)), "owned")

    def test_lost_is_lost(self):
        self.assertEqual(self._renew_with(R(0, "LOST\n", "", True)), "lost")

    def test_transport_failure_is_unreachable_not_lost(self):
        # An un-ok read (SSH/incus drop, mid-reboot) must NEVER be a loss.
        self.assertEqual(
            self._renew_with(R(255, "", "ssh: connect timeout", False)),
            "unreachable")

    def test_unexpected_output_is_unreachable_not_lost(self):
        # A truncated / unknown token fails SAFE (unknown), never a false loss.
        self.assertEqual(self._renew_with(R(0, "weird\n", "", True)),
                         "unreachable")

    def test_dry_run_is_owned(self):
        runner = xpf_deploy.Runner(True)   # dry-run: no remote action
        self.assertEqual(
            xpf_deploy._renew_lease(runner, "ssh", "fw0", 0, HOLDER, 1800),
            "owned")

    def test_renew_script_is_atomic_and_holder_guarded(self):
        # The renew must mirror acquire's discipline: under the flock, guard on
        # the holder, write temp+rename, and echo RENEWED/LOST.
        captured = {}

        def _capture(runner, backend, node, argv):
            captured["argv"] = argv
            return R(0, "RENEWED\n", "", True)

        runner = xpf_deploy.Runner(False)
        with mock.patch.object(xpf_deploy, "_node_exec_result", _capture):
            xpf_deploy._renew_lease(runner, "ssh", "fw0", 0, HOLDER, 1800)
        script = captured["argv"][-1]
        self.assertIn("flock", script)                 # serialized vs reclaim
        self.assertIn('"holder"', script)              # holder-guarded rewrite
        self.assertIn(HOLDER, script)                  # OUR identity, not any
        self.assertIn(".tmp", script)                  # temp file
        self.assertIn("mv -f", script)                 # atomic rename
        self.assertIn("RENEWED", script)
        self.assertIn("LOST", script)


# ── pure helpers: _fence_before_mutate gate ────────────────────────────────
class FenceTests(unittest.TestCase):
    """The fence gate: owned → proceed; lost → abort; unreachable → abort."""

    def _fence(self, verdicts):
        # verdicts: dict node -> "owned"/"lost"/"unreachable"
        runner = xpf_deploy.Runner(False)
        with mock.patch.object(
                xpf_deploy, "_renew_lease",
                side_effect=lambda r, b, n, nid, h, t: verdicts[n]), \
                mock.patch("time.sleep", return_value=None):
            xpf_deploy._fence_before_mutate(
                runner, "ssh", [("fw0", 0), ("fw1", 0)], HOLDER, 1800, "drain fw0")

    def test_all_owned_proceeds(self):
        # No exception -> the caller is cleared to mutate.
        self._fence({"fw0": "owned", "fw1": "owned"})

    def test_lost_aborts_fail_closed(self):
        with self.assertRaises(SystemExit) as cm:
            self._fence({"fw0": "lost", "fw1": "owned"})
        self.assertIn("LOST", str(cm.exception))
        self.assertIn("Refusing", str(cm.exception))

    def test_peer_lost_aborts(self):
        # Losing the PEER lease (the load-bearing reservation) also aborts.
        with self.assertRaises(SystemExit) as cm:
            self._fence({"fw0": "owned", "fw1": "lost"})
        self.assertIn("fw1", str(cm.exception))

    def test_persistently_unreachable_aborts_fail_closed(self):
        # Cannot prove ownership after retries -> refuse to mutate (fail-closed).
        with self.assertRaises(SystemExit) as cm:
            self._fence({"fw0": "unreachable", "fw1": "owned"})
        self.assertIn("could NOT confirm", str(cm.exception))

    def test_dry_run_never_fences(self):
        runner = xpf_deploy.Runner(True)
        # _renew_lease must not even be consulted in dry-run.
        with mock.patch.object(xpf_deploy, "_renew_lease",
                               side_effect=AssertionError("must not renew")):
            xpf_deploy._fence_before_mutate(
                runner, "ssh", [("fw0", 0)], HOLDER, 1800, "drain fw0")


class KeepaliveTests(unittest.TestCase):
    """`_keepalive_leases`: renew the reachable, surface a provable loss, and
    NEVER treat an unreachable (mid-reboot) node as a loss."""

    def _keepalive(self, verdicts):
        runner = xpf_deploy.Runner(False)
        with mock.patch.object(
                xpf_deploy, "_renew_lease",
                side_effect=lambda r, b, n, nid, h, t: verdicts[n]):
            return xpf_deploy._keepalive_leases(
                runner, "ssh", [("fw0", 0), ("fw1", 0)], HOLDER, 1800)

    def test_all_owned_returns_none(self):
        self.assertIsNone(self._keepalive({"fw0": "owned", "fw1": "owned"}))

    def test_unreachable_node_is_not_a_loss(self):
        # fw0 mid-reboot (unreachable) while the peer lease stays owned -> the
        # keep-alive tolerates it (returns None), never a spurious loss.
        self.assertIsNone(
            self._keepalive({"fw0": "unreachable", "fw1": "owned"}))

    def test_provable_loss_is_surfaced(self):
        self.assertEqual(
            self._keepalive({"fw0": "owned", "fw1": "lost"}), "fw1")


# ── end-to-end: kernel-roll fence aborts BEFORE mutating a lost pair ────────
class _KernelLostLeaseBackend:
    """Scripted `_node_exec_result` for cmd_kernel_roll where a successor has
    already reclaimed the lease: every renew answers LOST. Records the xpfd
    verbs (drain/arm/rejoin) so a test can prove NONE ran — the fence aborted
    before the first mutation."""

    def __init__(self):
        self.verbs = []

    def __call__(self, runner, backend, node, argv):
        if argv[:2] == ["sh", "-c"]:
            s = argv[-1]
            if "RENEWED" in s:          # renew/fence -> reclaimed by successor
                return R(0, "LOST\n", "", True)
            return R(0, "ACQUIRED\n", "", True)   # acquire / clear
        if argv[:3] == ["xpfd", "upgrade", "kernel"]:
            verb = argv[3]
            if verb == "status":
                return R(0, f"promoted={KNOWN_GOOD} armed=none\n", "", True)
            self.verbs.append(verb)     # drain / arm / rejoin (should NOT run)
            return R(0, "", "", True)
        if argv[:1] == ["cat"] and "boot_id" in argv[-1]:
            return R(0, "BOOT\n", "", True)
        if argv == ["uname", "-r"]:
            return R(0, KNOWN_GOOD + "\n", "", True)
        return R(0, "", "", True)


def _kernel_args():
    return types.SimpleNamespace(
        dry_run=False, backend="ssh", nodes=["fw0", "fw1"],
        version=CANDIDATE, node0_id=0, node1_id=1,
        lease_ttl=1800, boot_deadline=600)


class KernelRollFenceAbortTests(unittest.TestCase):
    def test_fence_aborts_before_first_mutation_on_lost_lease(self):
        """A predecessor whose lease was reclaimed must NOT drain/arm the pair.

        RED on revert: delete the `_fence_before_mutate(... "drain fw0")` call in
        cmd_kernel_roll's roll_one and this flips — the driver proceeds to
        `xpfd upgrade kernel drain` on a pair it no longer owns, so `verbs`
        contains "drain" and the SystemExit is gone."""
        fake = _KernelLostLeaseBackend()
        with mock.patch.object(xpf_deploy, "_node_exec_result", fake), \
                mock.patch("time.sleep", return_value=None):
            with self.assertRaises(SystemExit) as cm:
                xpf_deploy.cmd_kernel_roll(_kernel_args())
        msg = str(cm.exception)
        self.assertIn("LOST", msg)
        self.assertIn("drain fw0", msg)
        # The load-bearing assertion: NO mutation ran — the fence stopped the
        # roll before the drain.
        self.assertEqual(fake.verbs, [],
                         "a lost-lease driver mutated the pair (split-brain)")


# ── end-to-end: a lease LOST after the drain must NOT trigger the finally rejoin ─
class _KernelLostAfterDrainBackend:
    """Scripted `_node_exec_result` for cmd_kernel_roll where the lease is still
    owned at the pre-DRAIN fence (drain runs) but a successor reclaims it before
    the pre-ARM fence (every renew from the 3rd on answers LOST). The pre-arm
    fence then die()s — and because die() is a SystemExit, roll_one's `finally`
    still runs with drained=True / completed=False / rebooted=False, the exact
    state that fires the best-effort restore-forwarding rejoin. Records
    (node, verb) so a test can prove the drain ran but NO post-loss rejoin did:
    an orchestrator that lost the lease must not un-drain a pair a successor owns.

    Renew ordering in roll_one(fw0, fw1): pre-drain fence renews fw0 then fw1
    (calls 1,2 -> RENEWED), the drain runs, then the pre-arm fence renews fw0
    (call 3 -> LOST) and die()s before it renews fw1."""

    def __init__(self):
        self.verbs = []
        self.renews = 0

    def __call__(self, runner, backend, node, argv):
        if argv[:2] == ["sh", "-c"]:
            s = argv[-1]
            if "RENEWED" in s:              # a renew/fence tick
                self.renews += 1
                # First two renews (pre-drain fence, fw0+fw1) grant ownership so
                # the drain runs; from the third on a successor has reclaimed the
                # lease, so the pre-arm fence reads LOST and aborts.
                verdict = "RENEWED" if self.renews <= 2 else "LOST"
                return R(0, verdict + "\n", "", True)
            return R(0, "ACQUIRED\n", "", True)   # acquire / clear
        if argv[:3] == ["xpfd", "upgrade", "kernel"]:
            verb = argv[3]
            if verb == "status":
                return R(0, f"promoted={KNOWN_GOOD} armed=none\n", "", True)
            self.verbs.append((node, verb))   # drain (ok) / rejoin (must NOT run)
            return R(0, "", "", True)
        if argv[:1] == ["cat"] and "boot_id" in argv[-1]:
            return R(0, "BOOT\n", "", True)
        if argv == ["uname", "-r"]:
            return R(0, KNOWN_GOOD + "\n", "", True)
        return R(0, "", "", True)


class KernelRollLostAfterDrainNoRejoinTests(unittest.TestCase):
    def test_fence_before_arm_loss_suppresses_finally_rejoin(self):
        """A lease reclaimed AFTER the drain (fence-before-arm reports LOST) must
        NOT let the finally best-effort rejoin fire — that would un-drain a pair a
        successor now owns, breaking the fence's own invariant (a lost
        orchestrator must not mutate the pair, #5816).

        This exercises the fence-before-ARM-LOST -> finally path, which the
        existing fence-abort test (fence-before-DRAIN, drained never set) does
        NOT reach: there the finally's `drained` guard is False, so the rejoin
        could never fire regardless of the lease state.

        RED on revert: drop the `and not lost_lease` guard from roll_one's
        finally-rejoin condition (let it rejoin unconditionally on
        drained/not-completed/not-rebooted). The finally then issues
        `xpfd upgrade kernel rejoin` on fw0 after the loss, so `verbs` becomes
        [('fw0','drain'),('fw0','rejoin')] instead of [('fw0','drain')]."""
        fake = _KernelLostAfterDrainBackend()
        with mock.patch.object(xpf_deploy, "_node_exec_result", fake), \
                mock.patch("time.sleep", return_value=None):
            with self.assertRaises(SystemExit) as cm:
                xpf_deploy.cmd_kernel_roll(_kernel_args())
        msg = str(cm.exception)
        self.assertIn("LOST", msg)
        self.assertIn("arm+reboot fw0", msg)
        # The drain ran (pre-drain fence granted ownership); the post-loss rejoin
        # must NOT have run (the lost_lease gate suppressed the finally rejoin).
        self.assertEqual(fake.verbs, [("fw0", "drain")],
                         "a lost-lease driver un-drained the pair in the finally "
                         "(split-brain rejoin)")


# ── end-to-end: renewal keeps a legit-slow roll's lease valid throughout ────
class _ExpiringLeaseKernelBackend:
    """Scripted `_node_exec_result` for cmd_kernel_roll that models a real
    WALL-CLOCK lease. A virtual clock advances on each patched time.sleep; the
    lease on each node has a deadline. A renew RESETS the deadline to now+ttl iff
    we still own it; if a renew/check finds the lease EXPIRED (now >= deadline),
    a successor 'B' reclaims it and every later renew answers LOST.

    With the poll-loop keep-alive present, the deadline is pushed forward every
    tick, so a roll that outruns its TTL never loses the lease and COMPLETES.
    Neutralize the keep-alive and the lease expires mid-roll; the pre-rejoin
    fence then aborts a roll that SHOULD have succeeded.

    TTL(15) > sleep-step(10) so renewal always stays ahead; promote takes 3
    ticks (30s virtual) > TTL(15) so WITHOUT renewal the lease expires."""

    TTL_TICKS_TO_PROMOTE = 3

    def __init__(self, ttl):
        self.now = 0.0
        self.ttl = ttl
        self.ticks = 0
        self.deadline = {}       # node -> virtual expiry
        self.reclaimed = set()   # nodes a successor grabbed after expiry
        self.armed_tick = {}     # node -> tick it was armed (reboot origin)
        self.verbs = []          # (node, verb) for drain/arm/rejoin

    # patched time hooks -------------------------------------------------
    def time(self):
        return self.now

    def sleep(self, secs):
        self.now += secs
        self.ticks += 1

    # lease model --------------------------------------------------------
    def _verdict(self, node):
        if node in self.reclaimed:
            return "LOST"
        if self.now >= self.deadline.get(node, 0.0):
            self.reclaimed.add(node)      # successor grabs the expired lease
            return "LOST"
        self.deadline[node] = self.now + self.ttl   # still owned -> extend
        return "RENEWED"

    def _rebooted(self, node):
        at = self.armed_tick.get(node)
        return at is not None and (self.ticks - at) >= self.TTL_TICKS_TO_PROMOTE

    def __call__(self, runner, backend, node, argv):
        if argv[:2] == ["sh", "-c"]:
            s = argv[-1]
            if "RENEWED" in s:
                return R(0, self._verdict(node) + "\n", "", True)
            self.deadline[node] = self.now + self.ttl   # acquire seeds deadline
            return R(0, "ACQUIRED\n", "", True)
        if argv[:3] == ["xpfd", "upgrade", "kernel"]:
            verb = argv[3]
            if verb == "status":
                # Before reboot the candidate is ARMED (armed=<ver>, waiting to
                # boot); after reboot it is PROMOTED (running the candidate,
                # nothing armed). armed=none pre-reboot would (correctly) read as
                # an arm that failed its preflight — not what this fake models.
                if self._rebooted(node):
                    return R(0, f"promoted={CANDIDATE} armed=none\n", "", True)
                return R(0, f"promoted={KNOWN_GOOD} armed={CANDIDATE}\n",
                         "", True)
            if verb == "arm":
                self.armed_tick[node] = self.ticks
            self.verbs.append((node, verb))
            return R(0, "", "", True)
        if argv[:1] == ["cat"] and "boot_id" in argv[-1]:
            tag = "B" if self._rebooted(node) else "A"
            return R(0, f"BOOT-{tag}-{node}\n", "", True)
        if argv == ["uname", "-r"]:
            return R(0, (CANDIDATE if self._rebooted(node) else KNOWN_GOOD)
                     + "\n", "", True)
        return R(0, "", "", True)


class KernelRollRenewalTests(unittest.TestCase):
    def test_slow_roll_keeps_lease_and_completes(self):
        """A roll longer than the TTL stays VALID+OWNED (renewal fires) and
        completes — no spurious fence-abort on the legitimately-slow path.

        RED on revert: delete the poll-loop keep-alive block
        (`lost = _keepalive_leases(...)`) in cmd_kernel_roll. The lease then
        expires ~2 ticks into the reboot poll (TTL 15 < 30s to promote); the
        pre-rejoin fence renew answers LOST and the roll dies with SystemExit
        instead of returning 0 — a roll that SHOULD have succeeded is aborted."""
        fake = _ExpiringLeaseKernelBackend(ttl=15)
        args = _kernel_args()
        args.lease_ttl = 15
        args.boot_deadline = 300
        with mock.patch.object(xpf_deploy, "_node_exec_result", fake), \
                mock.patch("time.time", fake.time), \
                mock.patch("time.sleep", fake.sleep):
            rc = xpf_deploy.cmd_kernel_roll(args)
        self.assertEqual(rc, 0, "the slow-but-owned roll must complete")
        rejoins = [n for (n, v) in fake.verbs if v == "rejoin"]
        self.assertEqual(rejoins, ["fw0", "fw1"],
                         "both nodes must rejoin — renewal held the lease")
        # And the lease was never actually lost on the happy path.
        self.assertEqual(fake.reclaimed, set(),
                         "renewal must keep the lease from expiring mid-roll")


# ── end-to-end: image-roll fence aborts before the destructive recreate ────
NEWVER = "2.0.0-newimage"
NEW_MANIFEST = {
    "xpf-version": NEWVER,
    "ha-protocol-version": "3",
    "ha-protocol-min-compat": "2",
    "session-sync-protocol-version": "5",
}


class _ImageLostAfterDrainBackend:
    """`_node_exec` (stdout) fake for cmd_image_roll: drain/rejoin/proto/cat.
    Paired with a `_node_exec_result` renew fake that grants ownership at the
    pre-drain fence but reports LOST at the pre-recreate fence — a successor
    reclaimed the lease after the drain. Records drains so a test proves the
    drain ran but the recreate did NOT."""

    def __init__(self):
        self.drained = []
        self.rejoined = []

    def __call__(self, runner, backend, node, argv, check=True):
        if argv[:2] == ["sh", "-c"]:
            return "ACQUIRED\n"          # acquire / clear / mixed-ha probe
        if argv == ["xpfd", "protocol-versions"]:
            # peer reports NEW_MANIFEST-compatible versions so the mixed-base
            # gate passes and the roll reaches the drain.
            return ("ha-protocol-version=3\n"
                    "session-sync-protocol-version=5\n")
        if argv[:4] == ["xpfd", "upgrade", "kernel", "drain"]:
            self.drained.append(node)
            return ""
        if argv[:4] == ["xpfd", "upgrade", "kernel", "rejoin"]:
            self.rejoined.append(node)
            return ""
        return ""


def _image_args():
    return types.SimpleNamespace(
        dry_run=False, backend="ssh", nodes=["fw0", "fw1"],
        node0_id=0, node1_id=1, recreate_hook="/bin/true",
        manifest="xpf-2.0.0-newimage.manifest",
        sha256sums=None, sig=None, pubkey=None,
        lease_ttl=1800, drain_deadline=120, boot_deadline=40,
        allow_session_drop=False,
        # #7559: this suite drives the lease fence, and the ssh backend does
        # not request the daemon hold, so the roll behaves exactly as it did
        # before the hold existed.
        require_daemon_hold=False)


class ImageRollFenceAbortTests(unittest.TestCase):
    def test_fence_aborts_before_recreate_on_lost_lease(self):
        """A lease reclaimed AFTER the drain must NOT proceed to the destructive
        recreate. The pre-drain fence grants ownership (drain runs); the
        pre-recreate fence answers LOST and aborts — recreate never fires.

        RED on revert: delete the `_fence_before_mutate(... "image-recreate")`
        call in cmd_image_roll's roll_one and this flips — the driver recreates
        (destroy+launch) a node whose pair a successor now owns; the recreate
        hook is invoked and no SystemExit is raised."""
        exec_fake = _ImageLostAfterDrainBackend()
        recreate_calls = []

        renew_calls = {"n": 0}

        def _renew_result(runner, backend, node, argv):
            # First fence (before drain) = 2 renews -> owned; second fence
            # (before recreate) = renews 3+ -> lost (successor reclaimed).
            renew_calls["n"] += 1
            verdict = "RENEWED" if renew_calls["n"] <= 2 else "LOST"
            return R(0, verdict + "\n", "", True)

        stack = [
            mock.patch.object(xpf_deploy, "_node_exec", exec_fake),
            mock.patch.object(xpf_deploy, "_node_exec_result", _renew_result),
            mock.patch.object(
                xpf_deploy, "_recreate_node_from_image",
                lambda *a, **k: recreate_calls.append(a[2])),
            mock.patch.object(xpf_deploy, "_verified_image_manifest_versions",
                              lambda *a, **k: dict(NEW_MANIFEST)),
            mock.patch.object(xpf_deploy, "_verified_expected_qcow2_digest",
                              lambda *a, **k: ("xpf-2.0.0-newimage.qcow2", "a" * 64)),
            mock.patch.object(xpf_deploy.os.path, "isfile", lambda p: True),
            mock.patch("time.sleep", lambda *a, **k: None),
        ]
        for p in stack:
            p.start()
        try:
            with self.assertRaises(SystemExit) as cm:
                xpf_deploy.cmd_image_roll(_image_args())
        finally:
            for p in reversed(stack):
                p.stop()
        msg = str(cm.exception)
        self.assertIn("LOST", msg)
        self.assertIn("image-recreate fw0", msg)
        self.assertEqual(exec_fake.drained, ["fw0"],
                         "the drain ran (pre-drain fence granted ownership)")
        # The load-bearing assertion: the destructive recreate did NOT run.
        self.assertEqual(recreate_calls, [],
                         "a lost-lease driver recreated the node (split-brain)")
        self.assertNotIn("fw0", exec_fake.rejoined)


if __name__ == "__main__":
    unittest.main()
