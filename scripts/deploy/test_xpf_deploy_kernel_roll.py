#!/usr/bin/env python3
"""Unit tests for kernel-roll reboot detection (#4905-A).

In the LANE-1 HA kernel roll, a node is DRAINED (ForceSecondary, both leases
released to the peer), then armed to reboot into a candidate kernel. The driver
polls until the node promotes the candidate; if the arm FAILED its preflight
(no reboot), the node stays drained-but-running and the `finally` must REJOIN
it so it resumes forwarding.

Before the fix, `_running_kernel` returned "" on ANY transport failure (an
SSH/incus drop, control-socket contention — the wrapper discarded the exit
status) and the loop set `rebooted = True` on that empty read. One transient
status blip then made the still-drained-and-running node look like a completed
revert (`rebooted and armed=none`), so `completed=True` suppressed the
finally-rejoin and the node was left DRAINED + ForceSecondary with its leases
gone — a silent loss of redundancy.

The fix returns STRUCTURED command results (exit code + stderr), records the
pre-arm boot_id, and confirms a reboot ONLY from an affirmative signal (a
CHANGED boot_id, or the candidate kernel actually running) — never from an
empty/failed read. These tests cover both the pure predicate and the
end-to-end loop.

RED on revert: restore `if not running: rebooted = True` in the poll loop and
`test_transient_blip_still_rejoins_drained_node` flips — the transient read
forges a reboot, the roll dies "REVERTED", and no rejoin fires.
"""

from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

xpf_deploy = load_subject("xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))

R = xpf_deploy.NodeExecResult
KNOWN_GOOD = "6.17.0-good"
CANDIDATE = "6.99.0-cand"


class RebootConfirmedTests(unittest.TestCase):
    """The affirmative-only reboot predicate (#4905-A crux)."""

    def test_transient_read_is_not_a_reboot(self):
        # boot_id unchanged, running still known-good -> NOT a reboot.
        self.assertFalse(
            xpf_deploy._reboot_confirmed("AAAA", "AAAA", KNOWN_GOOD, CANDIDATE))

    def test_unknown_boot_id_is_not_a_reboot(self):
        # A failed boot_id read ("") must never be treated as a reboot.
        self.assertFalse(
            xpf_deploy._reboot_confirmed("AAAA", "", KNOWN_GOOD, CANDIDATE))
        self.assertFalse(
            xpf_deploy._reboot_confirmed("", "", "", CANDIDATE))

    def test_changed_boot_id_is_a_reboot(self):
        self.assertTrue(
            xpf_deploy._reboot_confirmed("AAAA", "BBBB", KNOWN_GOOD, CANDIDATE))

    def test_candidate_running_is_a_reboot(self):
        self.assertTrue(
            xpf_deploy._reboot_confirmed("AAAA", "AAAA", CANDIDATE, CANDIDATE))


class NodeExecResultTests(unittest.TestCase):
    """The structured wrapper preserves rc/stderr (#4905-A)."""

    def test_failure_is_not_ok_and_keeps_stderr(self):
        fake = types.SimpleNamespace(returncode=255, stdout="",
                                     stderr="ssh: connect timeout")
        runner = xpf_deploy.Runner(False)
        with mock.patch.object(xpf_deploy.subprocess, "run", return_value=fake):
            res = xpf_deploy._node_exec_result(runner, "ssh", "fw0",
                                               ["uname", "-r"])
        self.assertFalse(res.ok)
        self.assertEqual(res.rc, 255)
        self.assertIn("connect timeout", res.err)

    def test_success_is_ok(self):
        fake = types.SimpleNamespace(returncode=0, stdout=KNOWN_GOOD + "\n",
                                     stderr="")
        runner = xpf_deploy.Runner(False)
        with mock.patch.object(xpf_deploy.subprocess, "run", return_value=fake):
            res = xpf_deploy._node_exec_result(runner, "incus", "fw0",
                                               ["uname", "-r"])
        self.assertTrue(res.ok)
        self.assertEqual(res.out.strip(), KNOWN_GOOD)


class _ArmFailedFake:
    """Scripted node backend for the arm-FAILED-plus-transient-blip scenario.

    The arm preflight fails without rebooting: the node stays on the known-good
    kernel with an unchanged boot_id and status armed=none. The FIRST `uname`
    poll fails transiently (transport drop); the second succeeds. A correct
    driver must NOT classify this as a reboot/revert and MUST rejoin the still-
    drained node in the finally."""

    def __init__(self):
        self.uname_calls = 0
        self.rejoin_calls = 0

    def __call__(self, runner, backend, node, argv):
        if argv[:3] == ["xpfd", "upgrade", "kernel"]:
            verb = argv[3]
            if verb == "status":
                return R(0, f"promoted={KNOWN_GOOD} armed=none\n", "", True)
            if verb == "rejoin":
                self.rejoin_calls += 1
                return R(0, "", "", True)
            # drain (check=True) and arm (check=False) both "succeed" at the
            # transport layer; arm not rebooting is the whole point.
            return R(0, "", "", True)
        if argv[:1] == ["cat"] and "boot_id" in argv[-1]:
            return R(0, "AAAA\n", "", True)   # boot_id never changes (no reboot)
        if argv == ["uname", "-r"]:
            self.uname_calls += 1
            if self.uname_calls == 1:
                return R(255, "", "ssh: connect timeout", False)  # transient blip
            return R(0, KNOWN_GOOD + "\n", "", True)   # back, still known-good
        if argv[:2] == ["sh", "-c"]:
            # The lease renew/fence scripts (#5816) echo RENEWED on success; the
            # acquire/clear scripts echo ACQUIRED (clear ignores output). Answer
            # a renew with a still-owned verdict so the fence never spuriously
            # aborts on the happy path.
            if "RENEWED" in argv[-1]:
                return R(0, "RENEWED\n", "", True)
            return R(0, "ACQUIRED\n", "", True)   # lease acquire / clear
        return R(0, "", "", True)


def _roll_args():
    return types.SimpleNamespace(
        dry_run=False, backend="ssh", nodes=["fw0", "fw1"],
        version=CANDIDATE, node0_id=0, node1_id=1,
        lease_ttl=1800, boot_deadline=600)


class KernelRollTransientBlipTests(unittest.TestCase):
    def test_transient_blip_still_rejoins_drained_node(self):
        fake = _ArmFailedFake()
        with mock.patch.object(xpf_deploy, "_node_exec_result", fake), \
             mock.patch("time.sleep", return_value=None):
            with self.assertRaises(SystemExit) as cm:
                xpf_deploy.cmd_kernel_roll(_roll_args())
        msg = str(cm.exception)
        # The node never actually rebooted, so it must NOT be called a revert...
        self.assertNotIn("REVERTED", msg,
                         "a transient status blip was misread as a reboot/revert")
        # ...and the drained node MUST be rejoined so it resumes forwarding.
        self.assertGreaterEqual(
            fake.rejoin_calls, 1,
            "the still-drained node was left ForceSecondary (no rejoin) — #4905-A")
        # And the second node must NOT be touched (roll stopped at node 0).
        self.assertEqual(fake.uname_calls, 2)


if __name__ == "__main__":
    unittest.main()
