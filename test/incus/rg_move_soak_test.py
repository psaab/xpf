"""Hermetic cells for rg_move_soak.py (#18583, matrix row H11).

Each verdict rule has a cell that fails when the rule is reverted, and the
orchestration is driven end to end by a fake cluster — including the exact
shape the operator hit on 2026-10-31: every move to the peer fails fabric auth
on clock skew, every move back prints "already primary".
"""

import json
import os
import re
import tempfile
import unittest

import rg_move_soak as soak


def status_text(owner: dict, me: int, fwd_extra: str = "", dup: bool = False) -> str:
    """Render node `me`'s own `show chassis cluster status` for {rg: owner}."""
    out = ["Cluster ID: 22", f"Node name: node{me}", "",
           "Node   Priority Status         Preempt  Manual   Monitor-failures", ""]
    for rg in sorted(owner):
        out.append(f"Redundancy group: {rg} , Failover count: 3")
        for node in (0, 1):
            role = "primary" if owner[rg] == node else "secondary"
            out.append(f"node{node}  {200 - 100 * node}      {role:<14} no       no       None")
            if node == me:
                act = "active" if owner[rg] == node else "inactive"
                out.append(f"  Forwarding: rg-active={act} vrrp-master=none{fwd_extra}")
                if dup:
                    out.append(f"  Forwarding: rg-active={act} vrrp-master=none")
        out.append("")
    return "\n".join(out)


def views(owner, extra0="", extra1=""):
    return soak.parse_status(status_text(owner, 0, extra0)), soak.parse_status(status_text(owner, 1, extra1))


class StatusOwnership(unittest.TestCase):
    def test_clean_owner_each_way(self):
        for owner in (0, 1):
            v0, v1 = views({2: owner})
            own = soak.rg_ownership(2, v0, v1)
            self.assertEqual(own.owner, owner, own.detail)
            self.assertFalse(own.dual_active)

    def test_secondary_hold_is_a_non_owner(self):
        v0, v1 = views({2: 1})
        v0[2].roles[0] = "secondary-hold"
        self.assertEqual(soak.rg_ownership(2, v0, v1).owner, 1)

    def test_dual_primary_in_own_views_is_dual_active(self):
        # Each node claims the RG in its OWN view: node0's view alone would
        # score this healthy (the #18503 rule).
        v0, _ = views({2: 0})
        _, v1 = views({2: 1})
        own = soak.rg_ownership(2, v0, v1)
        self.assertTrue(own.dual_active)
        self.assertIsNone(own.owner)

    def test_dual_primary_by_role_alone_is_dual_active(self):
        # node1 claims primary in its OWN view but has not applied it yet;
        # node0's view still lists node1 as secondary. Only node1's own row
        # shows the second claimant.
        v0, _ = views({2: 0})
        _, v1 = views({2: 1})
        v1[2].forwarding = "inactive"
        own = soak.rg_ownership(2, v0, v1)
        self.assertTrue(own.dual_active, own.detail)

    def test_both_forwarding_active_is_dual_active(self):
        v0, v1 = views({2: 0})
        v1[2].forwarding = "active"
        self.assertTrue(soak.rg_ownership(2, v0, v1).dual_active)

    def test_divergence_suffix_is_not_owned(self):
        v0, v1 = views({2: 0}, extra0=" -- DIVERGENCE: VRRP master on only some member interfaces")
        own = soak.rg_ownership(2, v0, v1)
        self.assertIsNone(own.owner)
        self.assertIn("DIVERGENCE", own.detail)

    def test_forwarding_must_follow_role(self):
        v0, v1 = views({2: 0})
        v0[2].forwarding = "inactive"  # node0 primary but not applied
        self.assertIsNone(soak.rg_ownership(2, v0, v1).owner)

    def test_rg10_header_is_not_rg1(self):
        v = soak.parse_status(status_text({10: 1}, 0))
        self.assertNotIn(1, v)
        self.assertIn(10, v)

    def test_duplicate_rows_are_unreadable(self):
        v0 = soak.parse_status(status_text({2: 0}, 0, dup=True))
        v1 = soak.parse_status(status_text({2: 0}, 1))
        self.assertIsNone(soak.rg_ownership(2, v0, v1).owner)

    def test_missing_view_is_unowned(self):
        v0, _ = views({2: 0})
        self.assertIsNone(soak.rg_ownership(2, v0, {}).owner)

    def test_real_loss_status_parses(self):
        text = """Redundancy group: 2 , Failover count: 0
node0  200      primary        no       no       None
  Takeover ready: yes
  Transfer ready: yes
  Forwarding: rg-active=active vrrp-master=none
node1  100      secondary      no       no       None
"""
        v = soak.parse_status(text)
        self.assertEqual(v[2].roles, {0: "primary", 1: "secondary"})
        self.assertEqual(v[2].forwarding, "active")


USER_ERROR = ("error: rpc error: code = Unavailable desc = cannot connect to peer on any fabric address: "
              "rpc error: code = Unauthenticated desc = fabric RPC authentication failed: invalid auth token "
              "(the token authenticates under an accepted key at a window 60s ahead of ours, so the PSK is "
              "correct; ... Synchronise NTP on both nodes)")


class CLIClassify(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(soak.classify_cli(0, "Manual failover completed for redundancy group 2 (transfer committed)\n", 2)[0],
                         soak.CLI_OK)

    def test_ok_for_another_rg_is_not_ok(self):
        self.assertEqual(soak.classify_cli(0, "Manual failover completed for redundancy group 1 (transfer committed)", 2)[0],
                         soak.CLI_OTHER)

    def test_error_text_with_rc_zero_is_error(self):
        # The CLI can print `error:` and exit 0; the text decides.
        cls, first = soak.classify_cli(0, USER_ERROR, 2)
        self.assertEqual(cls, soak.CLI_ERROR)
        self.assertIn("fabric RPC authentication failed", first)

    def test_nonzero_rc_is_error_whatever_the_text(self):
        self.assertEqual(soak.classify_cli(1, "Manual failover completed for redundancy group 2 (transfer committed)", 2)[0],
                         soak.CLI_ERROR)

    def test_already_primary(self):
        self.assertEqual(soak.classify_cli(0, "Redundancy group 2 is already primary on node 0", 2)[0], soak.CLI_ALREADY)

    def test_unknown_text_is_other(self):
        self.assertEqual(soak.classify_cli(0, "Manual failover triggered for redundancy group 2", 2)[0], soak.CLI_OTHER)

    def test_skew_hint(self):
        self.assertIn("clock skew", soak.cli_error_hint(USER_ERROR))
        self.assertEqual(soak.cli_error_hint("error: something else"), "")


def rgres(rg=2, target=1, pre=0, cli=soak.CLI_OK, landed=0.8, dual=False, helper=None):
    if helper is None and landed is not None:
        helper = {target: True, 1 - target: False}
    return soak.RGMoveResult(rg, target, pre, "pre", cli, "first line", 0, 0.7, landed, "last", dual, helper)


GOOD_TRAFFIC = {"ping_lost": 3, "ping_max_gap_ms": 40.0, "ping_tail_replies": 95, "worst_stall_ms": 200.0,
                "worst_stall_stream": 5, "agg_zero_ms": 0.0, "tail_gbps": 20.0, "ping_covered": True,
                "iperf_covered": True}


def rec(rgs, traffic=None):
    r = soak.MoveRecord(1, rgs[0].target, 0, 100.0, 105.0, rgs)
    r.traffic = dict(GOOD_TRAFFIC) if traffic is None else traffic
    return r


class MoveVerdict(unittest.TestCase):
    B = soak.Budget()

    def verdict(self, r, traffic=True):
        return soak.move_verdict(r, self.B, traffic)

    def test_healthy_move_passes(self):
        self.assertEqual(self.verdict(rec([rgres()])), (soak.PASS, []))

    def test_precondition_failure_is_void_not_fail(self):
        # The cascade after a failed move: the RG is still on the target, the
        # CLI says "already primary". That is ONE VOID, not a second FAIL.
        v, why = self.verdict(rec([rgres(target=0, pre=0, cli=soak.CLI_ALREADY, landed=0.1)]))
        self.assertEqual(v, soak.VOID)
        self.assertIn("precondition", why[0])

    def test_unreadable_precondition_is_void(self):
        self.assertEqual(self.verdict(rec([rgres(pre=None)]))[0], soak.VOID)

    def test_already_primary_when_precondition_held_fails(self):
        v, why = self.verdict(rec([rgres(cli=soak.CLI_ALREADY)]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("already", why[0])

    def test_cli_error_fails(self):
        r = rgres(cli=soak.CLI_ERROR, landed=None)
        r.cli_first = USER_ERROR
        v, why = self.verdict(rec([r]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("clock skew", why[0])

    def test_unexpected_cli_text_fails(self):
        self.assertEqual(self.verdict(rec([rgres(cli=soak.CLI_OTHER)]))[0], soak.FAIL)

    def test_move_that_did_not_land_fails(self):
        # CLI said committed, but the views never agreed: the move did not happen.
        v, why = self.verdict(rec([rgres(landed=None)]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("did not land", why[0])

    def test_dual_active_sample_fails(self):
        v, why = self.verdict(rec([rgres(dual=True)]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("dual-active", why[0])

    def test_helper_disagreeing_fails(self):
        v, why = self.verdict(rec([rgres(helper={1: False, 0: True})]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("helper", why[0])

    def test_helper_unreadable_fails(self):
        v, why = self.verdict(rec([rgres(helper={1: None, 0: False})]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("unreadable", why[0])

    def test_ping_gap_over_budget_fails(self):
        t = dict(GOOD_TRAFFIC, ping_max_gap_ms=1500.0, ping_lost=149)
        self.assertEqual(self.verdict(rec([rgres()], t))[0], soak.FAIL)

    def test_stream_stall_over_budget_fails(self):
        t = dict(GOOD_TRAFFIC, worst_stall_ms=2500.0)
        v, why = self.verdict(rec([rgres()], t))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("stalled", why[0])

    def test_traffic_not_following_fails(self):
        # The RG moved in both views but nothing answers afterwards.
        t = dict(GOOD_TRAFFIC, ping_tail_replies=0)
        v, why = self.verdict(rec([rgres()], t))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("did not follow", " ".join(why))
        t = dict(GOOD_TRAFFIC, tail_gbps=0.0)
        self.assertEqual(self.verdict(rec([rgres()], t))[0], soak.FAIL)

    def test_traffic_generator_death_fails(self):
        self.assertEqual(self.verdict(rec([rgres()], dict(GOOD_TRAFFIC, iperf_covered=False)))[0], soak.FAIL)
        self.assertEqual(self.verdict(rec([rgres()], dict(GOOD_TRAFFIC, ping_covered=False)))[0], soak.FAIL)

    def test_traffic_ignored_when_disabled(self):
        self.assertEqual(self.verdict(rec([rgres()], {}), traffic=False)[0], soak.PASS)

    def test_multi_rg_any_failure_fails(self):
        v, _ = self.verdict(rec([rgres(rg=1), rgres(rg=2, landed=None)]))
        self.assertEqual(v, soak.FAIL)


class Traffic(unittest.TestCase):
    def test_ping_parse_unwraps_seq(self):
        text = "\n".join([
            "[1000.000000] 64 bytes from 1.2.3.4: icmp_seq=65534 ttl=63 time=0.2 ms",
            "[1000.010000] 64 bytes from 1.2.3.4: icmp_seq=65535 ttl=63 time=0.2 ms",
            "[1000.030000] 64 bytes from 1.2.3.4: icmp_seq=1 ttl=63 time=0.2 ms",
            "PING noise",
        ])
        r = soak.parse_ping(text)
        self.assertEqual([s for _, s in r], [65534, 65535, 65537])
        gaps = soak.ping_gaps(r)
        self.assertEqual(gaps[1].lost, 1)

    def _ping(self, t0, n, missing=()):
        lines = []
        for i in range(n):
            if i in missing:
                continue
            lines.append(f"[{t0 + i * 0.01:.6f}] 64 bytes from x: icmp_seq={i + 1} ttl=63 time=0.1 ms")
        return "\n".join(lines)

    def _iperf(self, anchor, n, dead=None, streams=(5, 7)):
        lines = []
        for i in range(n):
            st = []
            for sid in streams:
                bps = 0.0 if dead and sid == dead[0] and dead[1] <= i < dead[2] else 2e9
                st.append({"socket": sid, "start": i * 0.1, "end": (i + 1) * 0.1, "bits_per_second": bps})
            ev = {"event": "interval", "data": {"streams": st, "sum": {
                "start": i * 0.1, "end": (i + 1) * 0.1, "bits_per_second": sum(s["bits_per_second"] for s in st),
                "omitted": False}}}
            lines.append(f"{anchor + (i + 1) * 0.1 + 0.002:.6f} {json.dumps(ev)}")
        return "\n".join(lines)

    def test_window_attribution(self):
        # 10 s of ping at 100 pps, a 300 ms hole at 4.0 s; a stream dead for
        # 0.5 s at 6.0 s. Window A = [0,5), B = [5,10).
        replies = soak.parse_ping(self._ping(0.0, 1000, missing=range(400, 430)))
        gaps = soak.ping_gaps(replies)
        intervals, _, _ = soak.parse_iperf_stream(self._iperf(0.0, 100, dead=(7, 60, 65)))
        self.assertAlmostEqual(intervals[0][0], 0.0, places=2)
        stalls, agg = soak.stream_stalls(intervals, 1e6)
        b = soak.Budget()
        a = soak.traffic_for_window(0.0, 5.0, gaps, replies, stalls, agg, intervals, b)
        bb = soak.traffic_for_window(5.0, 9.99, gaps, replies, stalls, agg, intervals, b)
        self.assertEqual(a["ping_lost"], 30)
        self.assertAlmostEqual(a["ping_max_gap_ms"], 310.0, delta=1)
        self.assertEqual(a["worst_stall_ms"], 0.0)
        self.assertEqual(bb["ping_lost"], 0)
        self.assertAlmostEqual(bb["worst_stall_ms"], 500.0, delta=1)
        self.assertEqual(bb["worst_stall_stream"], 7)
        self.assertTrue(a["iperf_covered"] and a["ping_covered"])

    def test_vanished_stream_counts_as_stalled(self):
        intervals = [(0.0, 0.1, {5: 2e9, 7: 2e9}, 4e9), (0.1, 0.2, {5: 2e9}, 2e9), (0.2, 0.3, {5: 2e9}, 2e9)]
        stalls, _ = soak.stream_stalls(intervals, 1e6)
        self.assertEqual([(s.stream, round(s.seconds, 2)) for s in stalls], [(7, 0.2)])

    def test_uncovered_window_is_flagged(self):
        replies = soak.parse_ping(self._ping(0.0, 300))  # ping died at 3 s
        intervals, _, _ = soak.parse_iperf_stream(self._iperf(0.0, 30))
        stalls, agg = soak.stream_stalls(intervals, 1e6)
        t = soak.traffic_for_window(5.0, 10.0, soak.ping_gaps(replies), replies, stalls, agg, intervals, soak.Budget())
        self.assertFalse(t["ping_covered"])
        self.assertFalse(t["iperf_covered"])


class FakeClock:
    def __init__(self):
        self.t = 1_000_000.0

    def now(self):
        self.t += 0.001
        return self.t

    def sleep(self, s):
        self.t += max(0.0, s)


class FakeCluster:
    """A two-node cluster model. `skew_s` breaks the cross-node (fabric) path
    the way a skewed wall clock does; the local path (sync channel) works."""

    def __init__(self, clock, owner, skew_s=0.0, cli_rc_on_error=0, lag_polls=0):
        self.clock_ = clock
        self.owner = dict(owner)
        self.skew_s = skew_s
        self.cli_rc_on_error = cli_rc_on_error
        self.lag_polls = lag_polls
        self.pending = {}
        self.fw = {0: "fake:fw0", 1: "fake:fw1"}
        self.lan = "fake:lan"
        self.commands = []

    def cli(self, node, cmd):
        self.commands.append((node, cmd))
        m = re.match(r"request chassis cluster failover redundancy-group (\d+) node (\d)", cmd)
        rg, target = int(m.group(1)), int(m.group(2))
        self.clock_.sleep(0.6)
        if target != node and abs(self.skew_s) > 60:
            return self.cli_rc_on_error, USER_ERROR + "\n"
        if self.owner[rg] == target:
            return 0, f"Redundancy group {rg} is already primary on node {target}\n"
        if self.lag_polls:
            self.pending[rg] = (target, self.lag_polls)
        else:
            self.owner[rg] = target
        return 0, f"Manual failover completed for redundancy group {rg} (transfer committed)\n"

    def status(self, node):
        for rg, (target, n) in list(self.pending.items()):
            if n <= 1:
                self.owner[rg] = target
                del self.pending[rg]
            else:
                self.pending[rg] = (target, n - 1)
        self.clock_.sleep(0.15)
        return status_text(self.owner, node)

    def helper(self, node):
        return {rg: o == node for rg, o in self.owner.items()}

    def clock(self, ref):
        return self.clock_.t + (self.skew_s if ref == self.fw[1] else 0.0)

    def chrony(self, node):
        return "Leap status : Normal"


def run_fake(cluster, clock, moves=6, rgs="2", issuer=0, sleep_s=5.0):
    with tempfile.TemporaryDirectory() as d:
        cfg = soak.Config(moves=moves, sleep_s=sleep_s, rgs=rgs, issuer=issuer, traffic=False,
                          budget=soak.Budget(converge_s=sleep_s), outdir=d, run_id="t")
        logs = []
        rc = soak.Soak(cfg, cluster, now_fn=clock.now, sleep_fn=clock.sleep, log=logs.append).run()
        with open(os.path.join(d, "result.json")) as f:
            res = json.load(f)
    return rc, res, logs


class Orchestration(unittest.TestCase):
    def test_healthy_cluster_alternates_and_passes(self):
        clock = FakeClock()
        c = FakeCluster(clock, {0: 0, 1: 0, 2: 0})
        rc, res, _ = run_fake(c, clock, moves=6)
        self.assertEqual(rc, 0, res["summary"])
        self.assertEqual(res["summary"]["counts"], {"PASS": 6, "FAIL": 0, "VOID": 0})
        # Every move issued from node0, alternating node1/node0.
        self.assertEqual([n for n, _ in c.commands], [0] * 6)
        self.assertEqual([cmd[-1] for _, cmd in c.commands], list("101010"))

    def test_operator_skew_failure_is_reproduced(self):
        # fw1 71 s behind: every move to node1 errors (fabric auth), every move
        # back says "already primary". Expected: 3 FAIL + 3 VOID, exit 1, and
        # the FAIL reason names the clock.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, skew_s=-71.0)
        rc, res, logs = run_fake(c, clock, moves=6)
        self.assertEqual(rc, 1)
        self.assertEqual(res["summary"]["counts"], {"PASS": 0, "FAIL": 3, "VOID": 3})
        fails = [m for m in res["moves"] if m["verdict"] == "FAIL"]
        self.assertTrue(all(m["target"] == 1 for m in fails))
        self.assertIn("clock skew", fails[0]["reasons"][0])
        voids = [m for m in res["moves"] if m["verdict"] == "VOID"]
        self.assertTrue(all(m["rgs"][0]["cli_class"] == "already" for m in voids))
        self.assertAlmostEqual(res["preflight"]["node1_minus_node0_s"], -71.0, delta=0.5)
        self.assertEqual(res["preflight"]["peer_clock_line"], {})  # fake status has none
        self.assertTrue(any("WARNING" in line for line in logs))

    def test_moving_from_the_target_node_avoids_the_fabric(self):
        # Same skew, but the operator issues every move on node1: half the
        # moves are local and half cross the fabric, so it still fails half.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, skew_s=-71.0)
        rc, res, _ = run_fake(c, clock, moves=4, issuer=1)
        self.assertEqual(rc, 1)
        self.assertEqual(res["moves"][0]["verdict"], "PASS")  # node1 pulls RG2 locally
        self.assertEqual(res["moves"][1]["verdict"], "FAIL")  # node1 asks node0 over fabric

    def test_slow_landing_within_bound_passes_and_beyond_fails(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, lag_polls=3)
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 0, res["moves"])
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, lag_polls=10_000)
        rc, res, _ = run_fake(c, clock, moves=1, sleep_s=2.0)
        self.assertEqual(rc, 1)
        self.assertIn("did not land", res["moves"][0]["reasons"][0])

    def test_preflight_records_peer_clock_line(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        plain = c.status
        c.status = lambda node: "Peer clock offset: -72.0s (peer behind this node; measured 0.2s ago)\n" + plain(node)
        rc, res, _ = run_fake(c, clock, moves=1)
        self.assertEqual(res["preflight"]["peer_clock_line"]["0"][:24], "Peer clock offset: -72.0")

    def test_all_rgs(self):
        clock = FakeClock()
        c = FakeCluster(clock, {0: 0, 1: 0, 2: 0})
        rc, res, _ = run_fake(c, clock, moves=2, rgs="all")
        self.assertEqual(rc, 0)
        self.assertEqual(len(c.commands), 6)

    def test_no_clean_owner_voids_the_run(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        c.status = lambda node: status_text({2: node}, node)  # each claims it
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("no single clean owner", res["void"])


if __name__ == "__main__":
    unittest.main()
