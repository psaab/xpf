#!/usr/bin/env python3
"""#6762: lease renewal must continue DURING the recreate hook.

`_fence_before_mutate` extends both leases to one fresh TTL and returns. The
recreate hook that follows is an ARBITRARY operator script doing
destroy+launch+day-0 — an image pull, a cloud API wait, a bare-metal re-flash —
with no bound on its duration, and while it ran NOTHING renewed.

A hook outliving the TTL let the still-up peer's lease expire, and that peer
lease is the SOLE remaining reservation once the recreate wipes the node's own
/var/lib. A successor could then acquire BOTH node leases and begin a concurrent
roll on a pair this driver was mid-recreate on — the split-brain deploy the
whole lease mechanism exists to prevent.

The fence's own comment names the risk (#5545 flagged the recreate as
"potentially outlasting a short TTL"); a single extension answers "the phase
boundary", not "the phase".
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

xpf_deploy = load_subject("xpf_deploy", Path(__file__).with_name("xpf-deploy.py"))


def _script(body: str) -> str:
    """Write an executable shell script to a temp file and return its path."""
    fd, path = tempfile.mkstemp(prefix="xpf-hook-", suffix=".sh")
    with os.fdopen(fd, "w") as f:
        f.write("#!/bin/sh\n" + body + "\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return path


class RecreateKeepaliveTests(unittest.TestCase):
    def setUp(self):
        self._scripts = []

    def tearDown(self):
        for p in self._scripts:
            try:
                os.unlink(p)
            except OSError:
                pass

    def _hook(self, body):
        p = _script(body)
        self._scripts.append(p)
        return p

    def test_renewal_ticks_while_the_hook_runs(self):
        # A hook that outlives several renewal intervals must be renewed
        # THROUGHOUT, not once before it starts. Before #6762 this count was
        # exactly zero however long the hook ran.
        ticks = []
        rc, lost = xpf_deploy._run_with_lease_keepalive(
            [self._hook("sleep 0.55")], dict(os.environ),
            lambda: (ticks.append(1), None)[1], 0.1)
        self.assertEqual(rc, 0)
        self.assertIsNone(lost)
        self.assertGreaterEqual(len(ticks), 3,
                                f"renewal ticked {len(ticks)} times across a hook that "
                                f"outlived ~5 intervals; the peer lease is the sole "
                                f"reservation while the hook runs and it must keep "
                                f"being renewed (#6762)")

    def test_a_lost_lease_is_reported_and_the_hook_still_finishes(self):
        # Interrupting a half-finished destroy+launch is worse than letting it
        # complete, so a mid-hook loss is RECORDED and surfaced to the caller
        # (which fails closed before rejoin) rather than killing the hook.
        marker = tempfile.mktemp(prefix="xpf-hook-done-")
        self.addCleanup(lambda: os.path.exists(marker) and os.unlink(marker))
        rc, lost = xpf_deploy._run_with_lease_keepalive(
            [self._hook(f"sleep 0.35; touch {marker}")], dict(os.environ),
            lambda: "peer-node", 0.1)
        self.assertEqual(rc, 0, "the hook must be allowed to finish")
        self.assertEqual(lost, "peer-node", "the loss must reach the caller")
        self.assertTrue(os.path.exists(marker),
                        "the hook was killed mid-recreate; a half-done destroy+launch "
                        "is worse than a completed one plus a fail-closed stop")

    def test_hook_failure_is_still_reported(self):
        # The keepalive wrapper must not swallow the hook's exit status: a
        # failed recreate still has to stop the roll.
        rc, lost = xpf_deploy._run_with_lease_keepalive(
            [self._hook("exit 7")], dict(os.environ), lambda: None, 0.1)
        self.assertEqual(rc, 7)
        self.assertIsNone(lost)

    def test_fast_hook_does_not_require_a_tick(self):
        # The OVER-RENEWAL control. A hook that finishes inside one interval
        # needs no renewal — the fence before it already granted a fresh full
        # TTL. An implementation that renewed unconditionally would add a
        # remote round trip to every recreate, and renewal is not free: it
        # shells out to the node over the transport.
        ticks = []
        rc, lost = xpf_deploy._run_with_lease_keepalive(
            [self._hook("true")], dict(os.environ),
            lambda: (ticks.append(1), None)[1], 30)
        self.assertEqual(rc, 0)
        self.assertIsNone(lost)
        self.assertEqual(ticks, [],
                         "a hook that returned immediately triggered a renewal; the "
                         "fence before it already granted a fresh full TTL")

    def test_recreate_passes_a_keepalive_through(self):
        # BIND THE WIRING. _run_with_lease_keepalive being correct says nothing
        # about _recreate_node_from_image USING it — and the un-keepalived path
        # is exactly the pre-#6762 behaviour, so a missing hand-off is invisible
        # without this.
        seen = {}

        class Args:
            recreate_hook = self._hook("sleep 0.25")

        real = xpf_deploy._run_with_lease_keepalive

        def recording(argv, env, keepalive, interval):
            seen["keepalive"] = keepalive
            seen["interval"] = interval
            return real(argv, env, keepalive, interval)

        xpf_deploy._run_with_lease_keepalive = recording
        try:
            xpf_deploy._recreate_node_from_image(
                None, "incus", "fw0", Args(),
                keepalive=lambda: None, keepalive_interval=0.1)
        finally:
            xpf_deploy._run_with_lease_keepalive = real

        self.assertIn("keepalive", seen,
                      "_recreate_node_from_image ran the hook WITHOUT the keepalive "
                      "wrapper — renewal stops for the hook's whole duration, which "
                      "is the #6762 defect")
        self.assertEqual(seen["interval"], 0.1)


if __name__ == "__main__":
    unittest.main()
