#!/usr/bin/env python3
"""#7559: an image-recreated node must not be able to win an election before
the driver has proven it is the expected node running the expected image.

THE DEFECT. In the LANE-2 HA image roll each node is drained to its peer and
then RECREATED from the golden image by the operator's `--recreate-hook`
(destroy + launch + day-0), which WIPES its disk. The recreated node then runs
its own bringup — `pkg/daemon/daemon_run_bringup.go` calls
`cluster.UpdateConfig`, which itself runs an election — LONG before any driver
command reaches it. So it can claim a redundancy group while its identity and
image are still unproven. #6759's check DETECTS that and stops the roll; by the
time it can observe anything the election has already happened.

THE FIX IS NOT A HOLD THAT SURVIVES THE WIPE. Nothing on the node can survive a
recreate, which is why the kernel-roll's journal-keyed hold cannot be reused
(it folds a clean ENOENT to "never armed", and a wiped disk produces exactly
that). Instead the ELECTOR IS NOT STARTED: the recreate hook keeps xpfd from
auto-starting on the node's first boot, the driver evaluates the #5075 identity
gate WITH THE DAEMON DOWN — `xpfd protocol-versions` is a pure binary
invocation and `/etc/xpf/node-id` is a `cat`, neither needs a running daemon —
and only once the gate PASSES does the driver start xpfd. A node that fails the
gate is never started at all.

WHAT THESE TESTS BIND. Not "a field is checked": the load-bearing assertions are
that a node which FAILED the identity gate is never started (`systemctl enable
--now xpfd` is absent from the recorded call log), and — the accept-side control
— that a node which PASSED it IS started, before the rejoin, and the roll
completes. A gate that refused everything would satisfy the first half alone.

RED ON REVERT:
  - move the `_release_daemon_hold` call from after the gate to before the poll
    loop -> `test_wrong_build_never_starts_the_held_daemon` and
    `test_wrong_node_id_never_starts_the_held_daemon` flip GREEN->RED (the
    unverified node is started).
  - delete the release call entirely -> the positive control
    `test_correct_build_releases_the_hold_then_rejoins` flips GREEN->RED (a
    correctly-recreated node is left inert and never rejoined).
  - make `_daemon_hold_state` return "held" for an enabled-but-inactive unit ->
    `test_pending_boot_is_not_a_hold` flips (a node that is merely still booting
    would be reported as protected).
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

NEW_MANIFEST = {
    "xpf-version": NEWVER,
    "ha-protocol-version": "3",
    "ha-protocol-min-compat": "2",
    "session-sync-protocol-version": "5",
}


def _reported(xpf_version):
    return {
        "xpf-version": xpf_version,
        "ha-protocol-version": "3",
        "session-sync-protocol-version": "5",
    }


def _show(load="loaded", unit_file="enabled", active="active"):
    """The `systemctl show xpfd -p LoadState -p UnitFileState -p ActiveState`
    output for a unit in the named state."""
    return (f"LoadState={load}\n"
            f"UnitFileState={unit_file}\n"
            f"ActiveState={active}\n")


# The two states that matter end-to-end.
HELD = _show(load="masked", unit_file="masked", active="inactive")
RUNNING = _show()


class _Clock:
    """Monotonic fake clock so every bounded loop terminates under a mocked
    time.sleep. boot_deadline=40 with step=15 gives the poll ~2 iterations."""

    def __init__(self, start=1000.0, step=15.0):
        self.t = start
        self.step = step

    def __call__(self):
        v = self.t
        self.t += self.step
        return v


class _RollFake:
    """Scripted node surface for cmd_image_roll.

    `daemon` maps node -> the systemctl-show text the node reports BEFORE the
    driver releases the hold; a node whose hold is released reports RUNNING from
    then on (a real `enable --now` starts it). `calls` records every command in
    order so ORDERING (release before rejoin) is assertable, not just presence.
    """

    def __init__(self, reported, node_ids, daemon, stays_down=()):
        self.reported = reported
        self.node_ids = node_ids
        self.daemon = dict(daemon)
        # Nodes whose daemon does NOT come up after the release (a broken unit).
        self.stays_down = set(stays_down)
        self.released = set()
        self.drained = []
        self.rejoined = []
        self.calls = []

    # ── _node_exec: string-returning surface ──
    def exec(self, runner, backend, node, argv, check=True):
        self.calls.append((node, tuple(argv)))
        if argv[:2] == ["sh", "-c"]:
            return "ACQUIRED\n"
        if argv == ["xpfd", "protocol-versions"]:
            xv = self.reported.get(node)
            d = _reported(xv) if xv is not None else {}
            return "".join(f"{k}={v}\n" for k, v in d.items())
        if argv == ["cat", "/etc/xpf/node-id"]:
            nid = self.node_ids.get(node)
            return "" if nid is None else f"{nid}\n"
        if argv[:2] == ["systemctl", "enable"]:
            self.released.add(node)
            return ""
        if argv[:2] == ["cli", "-c"]:
            # The gRPC-backed readiness probe (and, before the gate passes, the
            # #6759 unverified-primary read). A daemon that has not been
            # started answers nothing; a released one reports a normal
            # SECONDARY block.
            if node in self.released and node not in self.stays_down:
                return ("Redundancy group: 1 , Failover count: 0\n"
                        f"    node{self.node_ids.get(node)}  1  secondary  "
                        "no  no\n")
            return ""
        if argv[:2] == ["systemctl", "unmask"]:
            return ""
        if argv[:4] == ["xpfd", "upgrade", "kernel", "drain"]:
            self.drained.append(node)
            return ""
        if argv[:4] == ["xpfd", "upgrade", "kernel", "rejoin"]:
            self.rejoined.append(node)
            return ""
        return ""

    # ── _node_exec_result: structured surface (lease renew + the hold probe) ──
    def exec_result(self, runner, backend, node, argv):
        if argv[:3] == ["systemctl", "show", "xpfd"]:
            self.calls.append((node, tuple(argv)))
            if node in self.released and node not in self.stays_down:
                return xpf_deploy.NodeExecResult(0, RUNNING, "", True)
            return xpf_deploy.NodeExecResult(
                0, self.daemon.get(node, ""), "", True)
        # Everything else on this surface is the #5816 lease renew: still ours.
        return xpf_deploy.NodeExecResult(0, "RENEWED\n", "", True)

    def started(self, node):
        return (node, ("systemctl", "enable", "--now", "xpfd")) in self.calls

    def index_of(self, node, prefix):
        for i, (n, argv) in enumerate(self.calls):
            if n == node and argv[:len(prefix)] == tuple(prefix):
                return i
        return -1


def _img_args(**over):
    ns = types.SimpleNamespace(
        # incus by default: its exec transport is the guest agent, so the
        # driver still reaches a node whose xpfd (and therefore whose
        # management address) is held. See _daemon_hold_supported.
        dry_run=False, backend="incus", nodes=["fw0", "fw1"],
        node0_id=0, node1_id=1,
        recreate_hook="/bin/true",
        manifest="xpf-2.0.0-newimage.manifest",
        sha256sums=None, sig=None, pubkey=None,
        lease_ttl=1800, drain_deadline=120, boot_deadline=40,
        allow_session_drop=False, require_daemon_hold=False)
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


def _run_roll(fake, args):
    """Drive cmd_image_roll against `fake`, neutralising only the signature /
    IO / recreate machinery — the daemon-hold logic under test is untouched."""
    patches = [
        mock.patch.object(xpf_deploy, "_node_exec", fake.exec),
        mock.patch.object(xpf_deploy, "_node_exec_result", fake.exec_result),
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
    for p in patches:
        p.start()
    try:
        return xpf_deploy.cmd_image_roll(args)
    finally:
        for p in reversed(patches):
            p.stop()


class DaemonHoldStateTests(unittest.TestCase):
    """The pure three-way classifier. `systemctl is-active` alone cannot do this
    job: it exits non-zero for EVERY inactive state, so it cannot tell a unit
    the hook masked from a node that is merely still booting — and those two
    must not be the same answer."""

    def test_masked_and_inactive_is_held(self):
        self.assertEqual(xpf_deploy._daemon_hold_state(
            _show(load="masked", unit_file="masked", active="inactive")),
            "held")

    def test_disabled_and_inactive_is_held(self):
        # A hook that disables rather than masks the unit is also a hold.
        self.assertEqual(xpf_deploy._daemon_hold_state(
            _show(unit_file="disabled", active="inactive")), "held")

    def test_enabled_and_active_is_running(self):
        self.assertEqual(xpf_deploy._daemon_hold_state(_show()), "running")

    def test_masked_but_actually_running_is_running(self):
        # ORDERING: running is decided BEFORE held. A unit that is masked in the
        # unit file but is nevertheless up can elect, and reporting it as
        # "held" would claim protection that does not exist.
        self.assertEqual(xpf_deploy._daemon_hold_state(
            _show(load="masked", unit_file="masked", active="active")),
            "running")

    def test_pending_boot_is_not_a_hold(self):
        # The middle row: enabled but not yet up. That is a node still booting,
        # NOT a hold — treating it as one would report an unprotected roll as
        # protected, and would then "release" a daemon nobody held.
        self.assertEqual(xpf_deploy._daemon_hold_state(
            _show(active="inactive")), "pending")
        self.assertEqual(xpf_deploy._daemon_hold_state(
            _show(active="failed")), "pending")

    def test_transitional_states_count_as_running(self):
        for st in ("activating", "reloading", "deactivating"):
            self.assertEqual(xpf_deploy._daemon_hold_state(_show(active=st)),
                             "running", st)

    def test_unreadable_is_unknown_not_held(self):
        # A transport blip / a guest with no systemd / dry-run. An unreadable
        # state must never be read as protection.
        for out in ("", None, "Failed to connect to bus\n", "garbage"):
            self.assertEqual(xpf_deploy._daemon_hold_state(out), "unknown",
                             repr(out))


class ReleaseGatedOnIdentityTests(unittest.TestCase):
    """END-TO-END: the harm. A node that has NOT passed the #5075 identity gate
    is never started."""

    def test_wrong_build_never_starts_the_held_daemon(self):
        # fw0 is recreated but comes back on the OLD build. The daemon is held,
        # so it never elected — and it must never be released either.
        fake = _RollFake(reported={"fw0": OLDVER, "fw1": OLDVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": HELD, "fw1": RUNNING})
        with self.assertRaises(SystemExit) as cm:
            _run_roll(fake, _img_args())
        self.assertIn(OLDVER, str(cm.exception))
        self.assertFalse(fake.started("fw0"),
                         "an UNVERIFIED node was started — it can now elect")
        self.assertNotIn("fw0", fake.rejoined)
        self.assertEqual(fake.drained, ["fw0"],
                         "the peer must not be touched after fw0 is rejected")

    def test_wrong_node_id_never_starts_the_held_daemon(self):
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": OLDVER},
                         node_ids={"fw0": 1, "fw1": 1},
                         daemon={"fw0": HELD, "fw1": RUNNING})
        with self.assertRaises(SystemExit) as cm:
            _run_roll(fake, _img_args())
        self.assertIn("WRONG node", str(cm.exception))
        self.assertFalse(fake.started("fw0"),
                         "a WRONG-node-id recreate was started")
        self.assertNotIn("fw0", fake.rejoined)

    def test_correct_build_releases_the_hold_then_rejoins(self):
        # POSITIVE CONTROL on the accept side: a gate that refused everything
        # would pass both rejection tests above. A legitimate roll must still
        # complete — and the release must come BEFORE the rejoin, because
        # `xpfd upgrade kernel rejoin` needs the daemon it just started.
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": HELD, "fw1": HELD})
        rc = _run_roll(fake, _img_args())
        self.assertEqual(rc, 0)
        self.assertEqual(fake.drained, ["fw0", "fw1"])
        self.assertEqual(fake.rejoined, ["fw0", "fw1"])
        for node in ("fw0", "fw1"):
            self.assertTrue(fake.started(node),
                            f"{node} passed the gate but was left inert")
            rel = fake.index_of(node, ["systemctl", "enable"])
            rej = fake.index_of(node, ["xpfd", "upgrade", "kernel", "rejoin"])
            self.assertGreater(rej, rel,
                               f"{node} was rejoined before xpfd was started")

    def test_release_happens_after_the_gate_not_before(self):
        # The ordering the whole mechanism rests on, asserted directly on the
        # recorded call sequence: nothing starts the daemon before the driver
        # has read BOTH halves of the identity gate.
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": HELD, "fw1": HELD})
        _run_roll(fake, _img_args())
        rel = fake.index_of("fw0", ["systemctl", "enable"])
        ver = fake.index_of("fw0", ["xpfd", "protocol-versions"])
        nid = fake.index_of("fw0", ["cat", "/etc/xpf/node-id"])
        self.assertGreater(rel, ver)
        self.assertGreater(rel, nid)

    def test_daemon_that_never_starts_is_not_rejoined(self):
        # Released, gate passed, but the unit does not come up. Never rejoin an
        # inert node: fail closed with the leases held and NAME the state.
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": HELD, "fw1": HELD},
                         stays_down=("fw0",))
        with self.assertRaises(SystemExit) as cm:
            _run_roll(fake, _img_args())
        msg = str(cm.exception)
        self.assertIn("not READY", msg)
        self.assertIn("held", msg, "the last observed state must be named")
        self.assertNotIn("fw0", fake.rejoined)


class UnprotectedRollTests(unittest.TestCase):
    """A hook that does not honour the hold. The default must stay exactly as
    it was — this change adds a guarantee, it does not break existing rolls."""

    def test_unheld_daemon_completes_the_roll_by_default(self):
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": RUNNING, "fw1": RUNNING})
        rc = _run_roll(fake, _img_args())
        self.assertEqual(rc, 0)
        self.assertEqual(fake.rejoined, ["fw0", "fw1"])
        # And the driver does not touch a daemon it never held.
        self.assertFalse(fake.started("fw0"))
        self.assertFalse(fake.started("fw1"))

    def test_unreadable_daemon_state_completes_the_roll_by_default(self):
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": "", "fw1": ""})
        rc = _run_roll(fake, _img_args())
        self.assertEqual(rc, 0)
        self.assertEqual(fake.rejoined, ["fw0", "fw1"])
        self.assertFalse(fake.started("fw0"))

    def test_require_daemon_hold_refuses_a_running_daemon(self):
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": RUNNING, "fw1": RUNNING})
        with self.assertRaises(SystemExit) as cm:
            _run_roll(fake, _img_args(require_daemon_hold=True))
        msg = str(cm.exception)
        self.assertIn("--require-daemon-hold", msg)
        self.assertIn("RUNNING", msg)
        self.assertEqual(fake.rejoined, [])

    def test_require_daemon_hold_refuses_an_unreadable_daemon_state(self):
        # A DISTINCT reason from "came back running" — #6495's lesson: two
        # causes rendered as one indistinguishable "refused" reintroduce the
        # blindness the reason string exists to remove.
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": "", "fw1": ""})
        with self.assertRaises(SystemExit) as cm:
            _run_roll(fake, _img_args(require_daemon_hold=True))
        msg = str(cm.exception)
        self.assertIn("never readable", msg)
        self.assertNotIn("came back with xpfd RUNNING", msg)
        self.assertEqual(fake.rejoined, [])

    def test_require_daemon_hold_accepts_a_held_daemon(self):
        # Accept-side control for the flag: it must not refuse everything.
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": HELD, "fw1": HELD})
        rc = _run_roll(fake, _img_args(require_daemon_hold=True))
        self.assertEqual(rc, 0)
        self.assertEqual(fake.rejoined, ["fw0", "fw1"])


class BackendSupportTests(unittest.TestCase):
    """The hold makes the node inert, and on the sealed appliance image that
    includes its management ADDRESS — `bake.py` purges cloud-init and deletes
    every netplan / interfaces.d file, so xpfd's own bootstrap lifeline is the
    only thing that ever addresses fxp0. Which transport the driver uses
    therefore decides whether the hold is safe or fatal."""

    def test_incus_supports_the_hold(self):
        # incus exec reaches the guest through the incus-agent, not by IP.
        self.assertTrue(xpf_deploy._daemon_hold_supported("incus", False))

    def test_ssh_does_not_support_the_hold_by_default(self):
        # The driver reaches the node by IP; a held xpfd means no IP, so the
        # poll would never see the node, time out, and leave it masked and
        # console-only — a persistent outage in place of a transient exposure.
        self.assertFalse(xpf_deploy._daemon_hold_supported("ssh", False))

    def test_require_flag_overrides_the_transport_judgement(self):
        # Only the operator knows whether their platform addresses the node
        # independently of xpfd.
        self.assertTrue(xpf_deploy._daemon_hold_supported("ssh", True))

    def test_ssh_roll_is_bit_identical_to_today(self):
        # END-TO-END: on ssh with no override, the driver must not probe, must
        # not release, and must not otherwise change — even when the node
        # happens to report a held daemon.
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": HELD, "fw1": HELD})
        rc = _run_roll(fake, _img_args(backend="ssh"))
        self.assertEqual(rc, 0)
        self.assertEqual(fake.rejoined, ["fw0", "fw1"])
        self.assertFalse([c for c in fake.calls if c[1][0] == "systemctl"],
                         "the ssh backend must issue no systemctl commands")

    def test_require_flag_makes_the_ssh_roll_use_the_hold(self):
        fake = _RollFake(reported={"fw0": NEWVER, "fw1": NEWVER},
                         node_ids={"fw0": 0, "fw1": 1},
                         daemon={"fw0": HELD, "fw1": HELD})
        rc = _run_roll(fake, _img_args(backend="ssh",
                                       require_daemon_hold=True))
        self.assertEqual(rc, 0)
        self.assertTrue(fake.started("fw0"))


class DaemonReadinessTests(unittest.TestCase):
    """`systemctl enable --now` returns the instant a Type=simple unit forks,
    and the very next step (`xpfd upgrade kernel rejoin`) dials gRPC ONCE,
    un-retried, with a 5s timeout — `RejoinAndConfirm` calls `ResetFailover()`
    outside its retry loop. So systemd activeness is a FALSE ready."""

    def test_cli_ready_needs_a_redundancy_group_block(self):
        self.assertTrue(xpf_deploy._daemon_cli_ready(
            "Redundancy group: 1 , Failover count: 0\n"
            "    node0  1  primary  no  no\n"))

    def test_cli_not_ready_on_an_empty_or_erroring_answer(self):
        for out in ("", None, "error: connection refused\n", "\n"):
            self.assertFalse(xpf_deploy._daemon_cli_ready(out), repr(out))

    def test_forked_but_unanswering_daemon_is_not_ready(self):
        # The unit is ACTIVE but the gRPC surface is not answering. Waiting on
        # ActiveState alone would rejoin here and fail on the un-retried dial.
        class _Forked(_RollFake):
            def exec(self, runner, backend, node, argv, check=True):
                if argv[:2] == ["cli", "-c"]:
                    self.calls.append((node, tuple(argv)))
                    return "error: could not connect\n"
                return super().exec(runner, backend, node, argv, check)

        fake = _Forked(reported={"fw0": NEWVER, "fw1": NEWVER},
                       node_ids={"fw0": 0, "fw1": 1},
                       daemon={"fw0": HELD, "fw1": HELD})
        with self.assertRaises(SystemExit) as cm:
            _run_roll(fake, _img_args())
        self.assertIn("not READY", str(cm.exception))
        self.assertEqual(fake.rejoined, [])


class HookContractTests(unittest.TestCase):
    """The recreate hook receives identity, daemon-hold, and image-integrity inputs."""

    def test_hook_env_carries_the_hold_contract(self):
        seen = {}

        class _Proc:
            returncode = 0

        def _fake_run(argv, env=None, **kw):
            seen.update(env or {})
            Path(env["XPF_ROLL_ATTESTATION_FILE"]).write_text(
                env["XPF_ROLL_EXPECT_SHA256"] + "\n")
            return _Proc()

        args = types.SimpleNamespace(recreate_hook="/bin/true")
        with mock.patch.object(xpf_deploy.subprocess, "run", _fake_run):
            xpf_deploy._recreate_node_from_image(
                xpf_deploy.Runner(False), "ssh", "fw0", args,
                expect_version=NEWVER, expect_node_id=0,
                expect_sha256="a" * 64, daemon_hold=True)
        self.assertEqual(seen.get("XPF_ROLL_NODE"), "fw0")
        self.assertEqual(seen.get("XPF_ROLL_DAEMON_HOLD"), "1")
        self.assertEqual(seen.get("XPF_ROLL_EXPECT_VERSION"), NEWVER)
        self.assertEqual(seen.get("XPF_ROLL_EXPECT_NODE_ID"), "0")
        self.assertEqual(seen.get("XPF_ROLL_EXPECT_SHA256"), "a" * 64)
        self.assertIn("XPF_ROLL_ATTESTATION_FILE", seen)

    def test_node_id_zero_is_still_exported(self):
        # node-id 0 is falsy; an `if expect_node_id:` guard would silently drop
        # the contract for exactly the node the roll starts with.
        seen = {}

        class _Proc:
            returncode = 0

        args = types.SimpleNamespace(recreate_hook="/bin/true")
        with mock.patch.object(xpf_deploy.subprocess, "run",
                               lambda argv, env=None, **kw: (
                                   seen.update(env or {}) or _Proc())):
            xpf_deploy._recreate_node_from_image(
                xpf_deploy.Runner(False), "ssh", "fw0", args,
                expect_version=NEWVER, expect_node_id=0, daemon_hold=True)
        self.assertEqual(seen.get("XPF_ROLL_EXPECT_NODE_ID"), "0")


if __name__ == "__main__":
    unittest.main()
