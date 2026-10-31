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
                "worst_stall_stream": 5, "died_streams": [], "agg_zero_ms": 0.0, "tail_gbps": 20.0,
                "ping_covered": True, "iperf_covered": True}


def rec(rgs, traffic=None, v6=None):
    r = soak.MoveRecord(1, rgs[0].target, 0, 100.0, 105.0, rgs)
    r.traffic = {"v4": dict(GOOD_TRAFFIC) if traffic is None else traffic}
    if v6 is not None:
        r.traffic["v6"] = v6
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

    def test_fail_fast_refusal_is_a_cli_error_naming_the_clock(self):
        r = rgres(cli=soak.CLI_ERROR, landed=None)
        r.cli_first = ("error: rpc error: code = FailedPrecondition desc = cross-node request not sent: node1's wall "
                       "clock is 1m14.9s behind this node (measured 100ms ago over authenticated heartbeats), and "
                       "fabric RPC authentication fails past 1m0s of skew; fix time sync")
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

    def test_revert_after_landing_fails(self):
        r = rgres()
        r.reverted = "node0=primary/active node1=secondary/inactive"
        v, why = self.verdict(rec([r]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("after landing", why[0])

    def test_helper_disagreeing_fails(self):
        v, why = self.verdict(rec([rgres(helper={1: False, 0: True})]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("helper", why[0])

    def test_helper_unreadable_fails(self):
        v, why = self.verdict(rec([rgres(helper={1: None, 0: False})]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("unreadable", why[0])

    def test_member_counters_on_the_old_node_fail(self):
        # Status and helper flipped; the RETH members that carried the packets
        # are still the old node's: the traffic did not move (review B1).
        r = rgres()
        r.follow_expected = True
        r.member_delta = {0: 90000, 1: 12}
        v, why = self.verdict(rec([r]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("did not follow to node1", why[0])
        r.member_delta = {0: 30, 1: 90000}
        self.assertEqual(self.verdict(rec([r]))[0], soak.PASS)
        r.member_delta = {0: None, 1: 90000}
        self.assertIn("unmeasured", self.verdict(rec([r]))[1][0])

    def test_member_counter_bounds_are_pinned(self):
        # The other node may carry at most 10 % of the target's packets (on
        # the WAN RG this is the only guard against a split path), and the
        # target at least follow_min_pkts (500).
        r = rgres()
        r.follow_expected = True
        for delta, want in (({0: 1500, 1: 10000}, soak.FAIL),   # 15 % on the old node
                            ({0: 900, 1: 10000}, soak.PASS),    # 9 %
                            ({0: 0, 1: 499}, soak.FAIL),        # under the minimum
                            ({0: 0, 1: 500}, soak.PASS)):
            r.member_delta = delta
            self.assertEqual(self.verdict(rec([r]))[0], want, delta)

    def test_lan_neighbour_on_the_old_node_fails(self):
        r = rgres()
        r.neigh_node = {"v4": 0}
        v, why = self.verdict(rec([r]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("neighbour entry", why[0])
        r.neigh_node = {"v4": 1, "v6": None}  # v6 unresolved is not evidence either way
        self.assertEqual(self.verdict(rec([r]))[0], soak.PASS)
        r.neigh_node = {"v4": 1, "v6": 0}
        v, why = self.verdict(rec([r]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("v6 neighbour entry", why[0])

    def test_ping_gap_over_budget_fails(self):
        # Seat AF: COST must not absorb "the traffic stopped". A ping gap over
        # budget is a FAIL however the move landed.
        t = dict(GOOD_TRAFFIC, ping_max_gap_ms=1500.0, ping_lost=149)
        v, why = self.verdict(rec([rgres()], t))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("ping gap", why[0])

    def test_aggregate_outage_over_budget_fails(self):
        t = dict(GOOD_TRAFFIC, agg_worst_ms=1200.0)
        v, why = self.verdict(rec([rgres()], t))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("aggregate outage", why[0])

    def test_recovered_single_stream_stall_is_a_cost(self):
        t = dict(GOOD_TRAFFIC, worst_stall_ms=2500.0)
        v, why = self.verdict(rec([rgres()], t))
        self.assertEqual(v, soak.COST)
        self.assertIn("recovered", why[0])

    def test_stall_past_the_cost_cap_fails(self):
        v, why = self.verdict(rec([rgres()], dict(GOOD_TRAFFIC, worst_stall_ms=10500.0)))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("COST cap", why[0])
        self.assertEqual(self.verdict(rec([rgres()], dict(GOOD_TRAFFIC, worst_stall_ms=9900.0)))[0], soak.COST)

    def test_stream_that_never_recovers_fails(self):
        t = dict(GOOD_TRAFFIC, worst_stall_ms=9000.0, died_streams=[7])
        v, why = self.verdict(rec([rgres()], t))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("never recovered", why[0])

    def test_cost_does_not_hide_a_fail(self):
        t = dict(GOOD_TRAFFIC, worst_stall_ms=2500.0)
        v, why = self.verdict(rec([rgres(dual=True)], t))
        self.assertEqual(v, soak.FAIL)
        self.assertTrue(any("stalled" in w for w in why))

    def test_traffic_not_following_fails(self):
        # The RG moved in both views but nothing answers afterwards.
        t = dict(GOOD_TRAFFIC, ping_tail_replies=0)
        v, why = self.verdict(rec([rgres()], t))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("did not follow", " ".join(why))
        t = dict(GOOD_TRAFFIC, tail_gbps=0.0)
        self.assertEqual(self.verdict(rec([rgres()], t))[0], soak.FAIL)

    def test_ipv6_is_scored_too(self):
        v, why = self.verdict(rec([rgres()], v6=dict(GOOD_TRAFFIC, ping_tail_replies=0)))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("v6", why[0])

    def test_traffic_generator_death_fails(self):
        self.assertEqual(self.verdict(rec([rgres()], dict(GOOD_TRAFFIC, iperf_covered=False)))[0], soak.FAIL)
        self.assertEqual(self.verdict(rec([rgres()], dict(GOOD_TRAFFIC, ping_covered=False)))[0], soak.FAIL)

    def test_traffic_ignored_when_disabled(self):
        self.assertEqual(self.verdict(rec([rgres()], {}), traffic=False)[0], soak.PASS)

    def test_multi_rg_any_failure_fails(self):
        v, _ = self.verdict(rec([rgres(rg=1), rgres(rg=2, landed=None)]))
        self.assertEqual(v, soak.FAIL)


REAL_HELPER_STATUS = '{"status": {"ha_groups": [{"rg_id": 0, "active": false, "watchdog_timestamp": 45382, "forwarding_active": false, "lease_state": "inactive"}, {"rg_id": 1, "active": false, "watchdog_timestamp": 45382, "forwarding_active": false, "lease_state": "inactive"}, {"rg_id": 2, "active": false, "watchdog_timestamp": 45381, "forwarding_active": false, "lease_state": "inactive"}], "bindings": [{"interface": "ge-7-0-2", "queue_id": 0, "ifindex": 6, "rx_packets": 265995, "tx_packets": 70289003, "bound": true}, {"interface": "ge-7-0-1", "queue_id": 0, "ifindex": 5, "rx_packets": 78561686, "tx_packets": 562721, "bound": true}, {"interface": "ge-7-0-0", "queue_id": 0, "ifindex": 4, "rx_packets": 299380, "tx_packets": 8272509, "bound": true}, {"interface": "ge-7-0-2", "queue_id": 1, "ifindex": 6, "rx_packets": 2983317, "tx_packets": 12, "bound": true}, {"interface": "ge-7-0-1", "queue_id": 1, "ifindex": 5, "rx_packets": 14482103, "tx_packets": 3431739, "bound": true}, {"interface": "ge-7-0-0", "queue_id": 1, "ifindex": 4, "rx_packets": 451028, "tx_packets": 14482066, "bound": true}]}}'


class HelperSummary(unittest.TestCase):
    """HELPER_SNIPPET's parsing, against a real helper `status` reply
    (tcp fw1, 2026-10-31, trimmed). The `interface`/`ifname` key bug was
    found live only; this is the hermetic cell it lacked."""

    def test_real_status_reply(self):
        got = soak.helper_summary(json.loads(REAL_HELPER_STATUS))
        self.assertEqual(got["ha"], {"0": False, "1": False, "2": False})
        self.assertEqual(got["if"]["ge-7-0-1"], 78561686 + 562721 + 14482103 + 3431739)
        self.assertEqual(set(got["if"]), {"ge-7-0-0", "ge-7-0-1", "ge-7-0-2"})

    def test_forwarding_active_wins_over_active(self):
        r = {"status": {"ha_groups": [{"rg_id": 2, "active": True, "forwarding_active": False}],
                        "bindings": []}}
        self.assertEqual(soak.helper_summary(r)["ha"], {"2": False})
        r = {"status": {"ha_groups": [{"rg_id": 2, "active": True}], "bindings": []}}
        self.assertEqual(soak.helper_summary(r)["ha"], {"2": True})  # older helper

    def test_snippet_ships_the_same_parser(self):
        self.assertIn("def helper_summary(r):", soak.HELPER_SNIPPET)
        compile(soak.HELPER_SNIPPET, "<helper-snippet>", "exec")


class Summary(unittest.TestCase):
    def _moves(self, verdicts):
        out = []
        for i, v in enumerate(verdicts):
            m = rec([rgres()])
            m.index, m.verdict = i, v
            out.append(m)
        return out

    def test_exit_codes(self):
        s = soak.summarize
        self.assertEqual(s(self._moves([soak.PASS, soak.COST]), True, [], False)["exit"], 0)
        self.assertEqual(s(self._moves([soak.PASS, soak.COST]), True, [], True)["exit"], 1)
        self.assertEqual(s(self._moves([soak.PASS, soak.FAIL]), True, [], False)["exit"], 1)
        self.assertEqual(s(self._moves([soak.PASS, soak.VOID]), True, [], False)["exit"], 2)
        # A disabled check is never scored as a full PASS.
        self.assertEqual(s(self._moves([soak.PASS]), False, ["traffic"], False)["exit"], 2)


class Membership(unittest.TestCase):
    CONFIG = "\n".join([
        "set groups node0 interfaces ge-0/0/1 gigether-options redundant-parent reth1",
        "set groups node0 interfaces ge-0/0/2 gigether-options redundant-parent reth0",
        "set groups node1 interfaces ge-7/0/1 gigether-options redundant-parent reth1",
        "set groups node1 interfaces ge-7/0/2 gigether-options redundant-parent reth0",
        "set interfaces reth0 redundant-ether-options redundancy-group 1",
        "set interfaces reth1 redundant-ether-options redundancy-group 2",
    ])

    def test_rg_members(self):
        self.assertEqual(soak.rg_members(self.CONFIG), {1: ["ge-0-0-2", "ge-7-0-2"], 2: ["ge-0-0-1", "ge-7-0-1"]})

    def test_link_macs_and_neigh(self):
        links = ("2: fxp0: <BROADCAST> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether 10:66:6a:cc:b8:04 brd ff:ff:ff:ff:ff:ff\n"
                 "5: ge-7-0-1: <BROADCAST> mtu 9000 qdisc mq state UP\\    link/ether 02:bf:72:17:02:03 brd ff:ff:ff:ff:ff:ff\n"
                 "9: ge-7-0-2.50@ge-7-0-2: <BROADCAST> mtu 1500\\    link/ether 02:bf:72:17:01:01 brd ff:ff:ff:ff:ff:ff\n")
        macs = soak.link_macs(links)
        self.assertEqual(macs["02:bf:72:17:02:03"], "ge-7-0-1")
        self.assertEqual(macs["02:bf:72:17:01:01"], "ge-7-0-2.50")
        self.assertEqual(soak.neigh_mac("10.0.62.1 dev eth0 lladdr 02:bf:72:17:02:02 REACHABLE"), "02:bf:72:17:02:02")
        self.assertIsNone(soak.neigh_mac("10.0.62.1 dev eth0 FAILED"))


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
    """Fake time. Listeners see every advance, so the fake LAN host can emit
    ping replies and iperf3 intervals as time passes, exactly as the real
    generators stream them while the soak sleeps."""

    def __init__(self):
        self.t = 1_000_000.0
        self.listeners = []

    def _to(self, t):
        while self.t < t:
            step = min(0.05, t - self.t)
            self.t += step
            for fn in self.listeners:
                fn(self.t)

    def now(self):
        self._to(self.t + 0.001)
        return self.t

    def sleep(self, s):
        self._to(self.t + max(0.0, s))


class Proc:
    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


MEMBERS = {1: {0: "ge-0-0-2", 1: "ge-7-0-2"}, 2: {0: "ge-0-0-1", 1: "ge-7-0-1"}}
MACS = {(0, 1): "02:bf:72:16:01:00", (1, 1): "02:bf:72:16:01:01",
        (0, 2): "02:bf:72:16:02:02", (1, 2): "02:bf:72:16:02:03"}


class FakeCluster:
    """A two-node cluster plus a LAN host, in fake time.

    `skew_s` breaks the cross-node (fabric) path the way a skewed wall clock
    does; the local path (sync channel) works. `stuck_traffic` keeps every
    packet on the initial owner whatever the status says (review B1's
    fixture). `revert_after_s` hands an RG back that many seconds after a
    move lands. `dual_after_land` makes the views show both nodes primary once,
    after landing. `faults` maps a move number to a traffic fault injected
    0.3 s after that move's CLI: "gap" (a 1.5 s outage of ping and every
    stream), "stall" (stream 7 stalls 2.5 s), "die" (stream 7 stops for good).
    """

    def __init__(self, clock, owner, skew_s=0.0, cli_rc_on_error=0, lag_polls=0, lan_off=3.0,
                 stuck_traffic=False, revert_after_s=None, dual_after_land=False, helper_lie=False,
                 busy_iperf=False, faults=None, dual_after_s=None):
        self.clock_ = clock
        self.owner = dict(owner)
        self.initial = dict(owner)
        self.skew_s = skew_s
        self.cli_rc_on_error = cli_rc_on_error
        self.lag_polls = lag_polls
        self.lan_off = lan_off
        self.stuck_traffic = stuck_traffic
        self.revert_after_s = revert_after_s
        self.dual_after_land = dual_after_land
        self.dual_after_s = dual_after_s  # one dual-active sample this long after landing
        self.helper_lie = helper_lie
        self.busy_iperf = busy_iperf
        self.faults = faults or {}
        self.pending = {}
        self.landed_at = {}
        self.dual_pending = 0
        self.fw = {0: "fake:fw0", 1: "fake:fw1"}
        self.lan = "fake:lan"
        self.commands = []
        self.moves_seen = 0
        self.counters = {0: {}, 1: {}}
        self.files = {}
        self.gen_start = None
        self.last_emit = None
        self.ping_seq = {}
        self.iv_index = {}
        self.events = []  # (lan_t0, lan_t1, kind)
        clock.listeners.append(self._tick)

    # -- cluster -------------------------------------------------------

    def forwarder(self, rg):
        return self.initial.get(rg, 0) if self.stuck_traffic else self.owner.get(rg, 0)

    def _apply_time(self, t):
        for rg, (target, at) in list(self.pending.items()):
            if t >= at:
                self.owner[rg] = target
                self.landed_at[rg] = t
                del self.pending[rg]
                if self.dual_after_land:
                    self.dual_pending = 2
        if self.dual_after_s is not None:
            for rg, at in list(self.landed_at.items()):
                if t - at >= self.dual_after_s and (rg, at) not in getattr(self, "_dual_done", set()):
                    self._dual_done = getattr(self, "_dual_done", set()) | {(rg, at)}
                    self.dual_pending = 2
        if self.revert_after_s is not None:
            for rg, at in list(self.landed_at.items()):
                if t - at >= self.revert_after_s and self.owner[rg] == 1:
                    self.owner[rg] = 0
                    del self.landed_at[rg]

    def cli(self, node, cmd):
        self.commands.append((node, cmd))
        m = re.match(r"request chassis cluster failover redundancy-group (\d+) node (\d)", cmd)
        rg, target = int(m.group(1)), int(m.group(2))
        self.moves_seen += 1
        lan_now = self.clock_.t + self.lan_off
        fault = self.faults.get(self.moves_seen)
        if fault == "gap":
            self.events.append((lan_now + 0.3, lan_now + 1.8, "gap"))
        elif fault == "stall":
            self.events.append((lan_now + 0.3, lan_now + 2.8, "stall"))
        elif fault == "outage":
            self.events.append((lan_now + 0.3, lan_now + 3.8, "gap"))
        elif fault == "die":
            self.events.append((lan_now + 0.3, float("inf"), "stall"))
        self.clock_.sleep(0.6)
        if target != node and abs(self.skew_s) > 60:
            return self.cli_rc_on_error, USER_ERROR + "\n"
        if self.owner[rg] == target:
            return 0, f"Redundancy group {rg} is already primary on node {target}\n"
        if self.lag_polls:
            self.pending[rg] = (target, self.clock_.t + self.lag_polls * 0.5)
        else:
            self.owner[rg] = target
            self.landed_at[rg] = self.clock_.t
            if self.dual_after_land:
                self.dual_pending = 2
        return 0, f"Manual failover completed for redundancy group {rg} (transfer committed)\n"

    def status(self, node):
        self._apply_time(self.clock_.t)
        self.clock_.sleep(0.15)
        if self.dual_pending:
            # Both views of one sample (the soak reads them in parallel).
            self.dual_pending -= 1
            return status_text({rg: node for rg in self.owner}, node)
        return status_text(self.owner, node)

    def helper(self, node):
        ha = {rg: (o == node) != self.helper_lie for rg, o in self.owner.items()}
        return {"ha": ha, "if": dict(self.counters[node])}

    def config_set(self, node):
        return Membership.CONFIG

    def links(self, node):
        out = []
        for (n, rg), mac in MACS.items():
            if n == node:
                out.append(f"{rg + 3}: {MEMBERS[rg][n]}: <BROADCAST> mtu 9000\\    link/ether {mac} brd ff:ff:ff:ff:ff:ff")
        return "\n".join(out)

    def neigh(self, addr, dev=""):
        return f"{addr} dev eth0 lladdr {MACS[(self.forwarder(2), 2)]} REACHABLE"

    def lan_v6_router(self):
        return ("fe80::bf72:16:2", "eth0")

    def clock(self, ref):
        if ref == self.lan:
            return self.clock_.t + self.lan_off
        return self.clock_.t + (self.skew_s if ref == self.fw[1] else 0.0)

    def chrony(self, node):
        return "Leap status : Normal"

    # -- LAN host traffic generators -----------------------------------

    def popen_lan(self, script, outfile):
        kind = "iperf" if "iperf3" in script else "ping"
        fam = "v6" if " -6 " in script else "v4"
        self.files[(kind, fam)] = outfile
        if self.gen_start is None:
            self.gen_start = self.last_emit = self.clock_.t
        if kind == "iperf" and self.busy_iperf:
            with open(outfile, "a") as f:
                f.write(f"{self.clock_.t + self.lan_off:.6f} " + json.dumps(
                    {"event": "error", "data": "error - the server is busy running a test. try again later"}) + "\n")
        return Proc(), open(os.devnull, "w")

    def lan_sh(self, script):
        self.gen_start = None  # generators stopped
        return 0, ""

    def _in(self, lan_t, kind):
        return any(a <= lan_t < b and (k == kind or k == "gap") for a, b, k in self.events)

    def _tick(self, t):
        # RETH-member counters: whoever forwards each RG carries its packets.
        for rg, by_node in MEMBERS.items():
            if rg in self.owner:
                n = self.forwarder(rg)
                name = by_node[n]
                self.counters[n][name] = self.counters[n].get(name, 0) + 500
        if self.gen_start is None:
            return
        for (kind, fam), path in list(self.files.items()):
            if kind == "iperf" and self.busy_iperf:
                continue
            with open(path, "a") as f:
                if kind == "ping":
                    seq = self.ping_seq.get(fam, 0)
                    while self.gen_start + (seq + 1) * 0.01 <= t:
                        seq += 1
                        ts = self.gen_start + seq * 0.01 + self.lan_off
                        if not self._in(ts, "gap"):
                            f.write(f"[{ts:.6f}] 64 bytes from x: icmp_seq={seq % 65536} ttl=63 time=0.1 ms\n")
                    self.ping_seq[fam] = seq
                else:
                    i = self.iv_index.get(fam, 0)
                    while self.gen_start + (i + 1) * 0.1 <= t:
                        mid = self.gen_start + i * 0.1 + 0.05 + self.lan_off
                        gap = self._in(mid, "gap")
                        st = []
                        for sid in (5, 7, 9):
                            dead = gap or (sid == 7 and self._in(mid, "stall"))
                            st.append({"socket": sid, "start": i * 0.1, "end": (i + 1) * 0.1,
                                       "bits_per_second": 0.0 if dead else 2e9})
                        ev = {"event": "interval", "data": {"streams": st, "sum": {
                            "start": i * 0.1, "end": (i + 1) * 0.1,
                            "bits_per_second": sum(s["bits_per_second"] for s in st), "omitted": False}}}
                        f.write(f"{self.gen_start + (i + 1) * 0.1 + self.lan_off + 0.002:.6f} {json.dumps(ev)}\n")
                        i += 1
                    self.iv_index[fam] = i


def run_fake(cluster, clock, moves=6, rgs="2", issuer=0, sleep_s=5.0, traffic=True, helper_check=True,
             v6=False, restore=True, files=None, strict_cost=False):
    with tempfile.TemporaryDirectory() as d:
        cfg = soak.Config(moves=moves, sleep_s=sleep_s, rgs=rgs, issuer=issuer, traffic=traffic,
                          helper_check=helper_check, restore=restore, strict_cost=strict_cost,
                          budget=soak.Budget(converge_s=sleep_s), outdir=d, run_id="t",
                          target4="172.16.80.200", target6="2001:db8::200" if v6 else "",
                          lan_vip4="10.0.61.1")
        logs = []
        rc = soak.Soak(cfg, cluster, now_fn=clock.now, sleep_fn=clock.sleep, log=logs.append).run()
        with open(os.path.join(d, "result.json")) as f:
            res = json.load(f)
        if files is not None:
            files.extend(sorted(os.listdir(d)))
    return rc, res, logs


def verdicts(res):
    return [m["verdict"] for m in res["moves"]]


class Orchestration(unittest.TestCase):
    def test_healthy_cluster_alternates_and_passes(self):
        clock = FakeClock()
        c = FakeCluster(clock, {0: 0, 1: 0, 2: 0})
        rc, res, logs = run_fake(c, clock, moves=6)
        self.assertEqual(rc, 0, res["summary"])
        self.assertEqual(res["summary"]["counts"], {"PASS": 6, "COST": 0, "FAIL": 0, "VOID": 0})
        moves = [cmd for _, cmd in c.commands][:6]
        self.assertEqual([n for n, _ in c.commands][:6], [0] * 6)  # every move issued on node0
        self.assertEqual([cmd[-1] for cmd in moves], list("101010"))
        self.assertIn("rg-move-soak: 6 passed, 0 failed", "\n".join(logs))
        # The traffic-follow evidence was taken, on the right node, each move.
        for m in res["moves"]:
            r = m["rgs"][0]
            self.assertGreater(r["member_delta"][str(r["target"])], 500)
            self.assertEqual(r["neigh_node"]["v4"], r["target"])
        self.assertIn("end_node1_minus_node0_s", res["preflight"])
        self.assertEqual(res["preflight"]["lan_rg"], 2)

    def test_traffic_that_never_moved_fails(self):
        # Review B1's fixture: status and helper flip on every move, the
        # packets stay on node0. The old harness scored this 6/6 PASS.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, stuck_traffic=True)
        rc, res, _ = run_fake(c, clock, moves=4)
        self.assertEqual(rc, 1)
        to1 = [m for m in res["moves"] if m["target"] == 1]
        self.assertTrue(all(m["verdict"] == "FAIL" for m in to1))
        self.assertTrue(any("did not follow to node1" in r for r in to1[0]["reasons"]))

    def test_gap_is_attributed_to_its_own_move(self):
        # The LAN clock is 3 s ahead of the orchestrator: a sign flip or an
        # ignored offset moves the gap into the neighbouring window.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={3: "gap"})
        rc, res, _ = run_fake(c, clock, moves=5)
        self.assertEqual(verdicts(res), ["PASS", "PASS", "FAIL", "PASS", "PASS"], res["moves"][2]["reasons"])
        self.assertIn("ping gap", " ".join(res["moves"][2]["reasons"]))
        self.assertEqual(rc, 1)

    def test_recovered_stall_is_cost_and_dead_stream_fails(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={2: "stall"})
        rc, res, _ = run_fake(c, clock, moves=3)
        self.assertEqual(verdicts(res), ["PASS", "COST", "PASS"])
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={2: "die"})
        rc, res, _ = run_fake(c, clock, moves=3)
        self.assertEqual(res["moves"][1]["verdict"], "FAIL")
        self.assertIn("never recovered", " ".join(res["moves"][1]["reasons"]))
        self.assertEqual(rc, 1)

    def test_ipv6_is_measured(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        names = []
        rc, res, _ = run_fake(c, clock, moves=2, v6=True, files=names)
        # The artefact names the doc tells operators to read.
        self.assertEqual(names, ["iperf.jsonl", "iperf6.jsonl", "ping.log", "ping6.log", "result.json"])
        # And each holds what its name says.
        self.assertEqual(dict(c.files)[("ping", "v4")].rsplit("/", 1)[1], "ping.log")
        self.assertEqual(rc, 0, res["summary"])
        self.assertIn("v6", res["moves"][0]["traffic"])
        self.assertTrue(res["moves"][0]["traffic"]["v6"]["ping_covered"])

    def test_dual_active_after_landing_fails(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, dual_after_land=True)
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 1)
        self.assertIn("dual-active", res["moves"][0]["reasons"][0])

    def test_dual_active_late_in_the_window_fails(self):
        # One dual-active sample 2 s AFTER landing: only the rest-of-window
        # sampling can see it (review: "at any point").
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, dual_after_s=2.0)
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 1)
        self.assertIn("dual-active", " ".join(res["moves"][0]["reasons"]))

    def test_revert_after_landing_fails(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, revert_after_s=2.0)
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 1)
        self.assertIn("left node1 after landing", " ".join(res["moves"][0]["reasons"]))

    def test_helper_disagreement_is_read_and_fails(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, helper_lie=True)
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 1)
        self.assertIn("helper", res["moves"][0]["reasons"][0])

    def test_operator_skew_failure_is_reproduced(self):
        # fw1 71 s behind: every move to node1 errors (fabric auth), every move
        # back says "already primary". Expected: 3 FAIL + 3 VOID, exit 1, and
        # the FAIL reason names the clock.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, skew_s=-71.0)
        rc, res, logs = run_fake(c, clock, moves=6)
        self.assertEqual(rc, 1)
        self.assertEqual(res["summary"]["counts"], {"PASS": 0, "COST": 0, "FAIL": 3, "VOID": 3})
        fails = [m for m in res["moves"] if m["verdict"] == "FAIL"]
        self.assertTrue(all(m["target"] == 1 for m in fails))
        self.assertIn("clock skew", fails[0]["reasons"][0])
        voids = [m for m in res["moves"] if m["verdict"] == "VOID"]
        self.assertTrue(all(m["rgs"][0]["cli_class"] == "already" for m in voids))
        self.assertAlmostEqual(res["preflight"]["node1_minus_node0_s"], -71.0, delta=0.5)
        self.assertTrue(any("WARNING" in line for line in logs))
        self.assertEqual(res["preflight"]["peer_clock_line"], {})  # fake status has none

    def test_moving_from_the_target_node_avoids_the_fabric(self):
        # Same skew, but every move is issued on node1: half the moves are
        # local and half cross the fabric, so it still fails half.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, skew_s=-71.0)
        rc, res, _ = run_fake(c, clock, moves=4, issuer=1)
        self.assertEqual(rc, 1)
        self.assertEqual(res["moves"][0]["verdict"], "PASS")  # node1 pulls RG2 locally
        self.assertEqual(res["moves"][1]["verdict"], "FAIL")  # node1 asks node0 over fabric

    def test_landing_bound_is_from_the_cli_return(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, lag_polls=3)  # lands 1.5 s after the CLI
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 0, res["moves"])
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, lag_polls=10)  # lands 5 s after: past a 2 s bound
        rc, res, _ = run_fake(c, clock, moves=1, sleep_s=2.0)
        self.assertEqual(rc, 1)
        self.assertIn("did not land", res["moves"][0]["reasons"][0])

    def test_restore_leaves_node0_primary(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        rc, res, _ = run_fake(c, clock, moves=3)  # ends with RG2 on node1
        self.assertEqual(c.owner[2], 0)
        self.assertIn("restored", res["preflight"]["restore"])

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
        self.assertEqual(rc, 0, res["moves"])
        self.assertEqual(len([cmd for cmd in c.commands if "node 0" in cmd[1] or "node 1" in cmd[1]]), 6)

    def test_busy_iperf_server_voids_the_run(self):
        # Review B4: a busy or dead traffic target is not a move's fault.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, busy_iperf=True)
        rc, res, logs = run_fake(c, clock, moves=3)
        self.assertEqual(rc, 2)
        self.assertIn("server is busy", res["void"])
        self.assertEqual(res["moves"], [])
        self.assertTrue(any(line.startswith("FATAL:") for line in logs))

    def test_disabled_checks_never_exit_zero(self):
        for kw in ({"traffic": False}, {"helper_check": False}):
            clock = FakeClock()
            c = FakeCluster(clock, {2: 0})
            rc, res, _ = run_fake(c, clock, moves=2, **kw)
            self.assertEqual(rc, 2, kw)
            self.assertEqual(res["summary"]["counts"]["FAIL"], 0)

    def test_unmappable_reth_members_void_the_run(self):
        # A silent "nothing to measure" would turn the traffic-follow check
        # off; a RETH with no members found is "could not measure".
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        c.config_set = lambda node: "set interfaces reth1 redundant-ether-options redundancy-group 2"
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("a RETH with no members", res["void"])

    def test_unmappable_lan_neighbour_voids_the_run(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        c.neigh = lambda vip: f"{vip} dev eth0 lladdr 0a:00:00:00:00:01 REACHABLE"
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("neighbour entry", res["void"])

    def test_long_total_outage_is_never_a_pass(self):
        # Seat AF probe4: every move blackholes ALL traffic for 3.5 s, then
        # recovers. That is "the iperfs stop"; it must FAIL, and the ledger
        # line must say so.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={i: "outage" for i in range(1, 5)})
        rc, res, logs = run_fake(c, clock, moves=4)
        self.assertEqual(rc, 1)
        self.assertEqual(verdicts(res), ["FAIL"] * 4)
        self.assertIn("rg-move-soak: 0 passed, 4 failed, 0 cost", "\n".join(logs))

    def test_summary_line_carries_cost_and_strict_mode_fails_it(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={2: "stall"})
        rc, res, logs = run_fake(c, clock, moves=3)
        self.assertEqual(rc, 0)
        self.assertIn("rg-move-soak: 3 passed, 0 failed, 1 cost", "\n".join(logs))
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={2: "stall"})
        rc, res, logs = run_fake(c, clock, moves=3, strict_cost=True)
        self.assertEqual(rc, 1)
        self.assertIn("rg-move-soak: 2 passed, 1 failed, 1 cost", "\n".join(logs))

    def test_split_path_on_the_wan_rg_fails(self):
        # Seat AF probe3: after the move the target carries the RG's packets,
        # but the old owner's members keep carrying them too.
        class SplitPath(FakeCluster):
            def _tick(self, t):
                super()._tick(t)
                for rg, by_node in MEMBERS.items():
                    if rg in self.owner and self.owner[rg] != self.initial[rg]:
                        old = self.initial[rg]
                        self.counters[old][by_node[old]] = self.counters[old].get(by_node[old], 0) + 500
        clock = FakeClock()
        c = SplitPath(clock, {1: 0, 2: 0})
        rc, res, _ = run_fake(c, clock, moves=4, rgs="1")
        self.assertEqual(rc, 1)
        self.assertIn("did not follow to node1", " ".join(res["moves"][0]["reasons"]))

    def test_unparsed_rg_voids_instead_of_switching_the_check_off(self):
        # Seat AF probe3: RG1's RETH->RG line missing => no members => the
        # counter check would silently turn off while traffic is stuck.
        clock = FakeClock()
        c = FakeCluster(clock, {1: 0, 2: 0}, stuck_traffic=True)
        c.config_set = lambda node: "\n".join(line for line in Membership.CONFIG.splitlines()
                                              if "redundancy-group 1" not in line)
        rc, res, _ = run_fake(c, clock, moves=4, rgs="1")
        self.assertEqual(rc, 2)
        self.assertIn("RG1 maps to no RETH member", res["void"])

    def test_ipv6_follows_the_ra_router_not_the_global_vip(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        rc, res, _ = run_fake(c, clock, moves=2, v6=True)
        self.assertEqual(rc, 0, res["summary"])
        self.assertEqual(res["preflight"]["lan_v6_router"], ["fe80::bf72:16:2", "eth0"])
        self.assertEqual(res["moves"][0]["rgs"][0]["neigh_node"]["v6"], 1)
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        c.lan_v6_router = lambda: None
        rc, res, _ = run_fake(c, clock, moves=2, v6=True)
        self.assertEqual(rc, 2)
        self.assertIn("no IPv6 default route", res["void"])
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        plain = c.neigh
        c.neigh = lambda addr, dev="": "" if addr.startswith("fe80") else plain(addr, dev)
        rc, res, _ = run_fake(c, clock, moves=2, v6=True)
        self.assertEqual(rc, 2)
        self.assertIn("IPv6 default router", res["void"])

    def test_sigterm_skips_the_restore(self):
        # Seat AF probe5: no RG move may run after a SIGTERM (the lock
        # wrapper may have died from the same signal).
        class TermAfterMove1(FakeCluster):
            def cli(self, node, cmd):
                out = super().cli(node, cmd)
                if len(self.commands) == 2:
                    self.term_at = len(self.commands)
                    raise SystemExit(143)
                return out
        clock = FakeClock()
        c = TermAfterMove1(clock, {2: 0})
        with self.assertRaises(SystemExit):
            run_fake(c, clock, moves=6)
        self.assertEqual(c.commands[c.term_at:], [])
        self.assertIsNone(c.gen_start, "the LAN-host generators must be stopped")

    def test_no_clean_owner_voids_the_run(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        c.status = lambda node: status_text({2: node}, node)  # each claims it
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("no single clean owner", res["void"])

    def test_harness_error_is_void(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        c.config_set = lambda node: (_ for _ in ()).throw(RuntimeError("incus went away"))
        with tempfile.TemporaryDirectory() as d:
            argv = ["--fw0", "a", "--fw1", "b", "--lan", "c", "--target4", "x", "--outdir", d]
            orig = soak.IncusCluster
            soak.IncusCluster = lambda fw, lan: c
            try:
                old = soak.Soak.__init__

                def init(self, cfg, cluster, **kw):
                    old(self, cfg, cluster, now_fn=clock.now, sleep_fn=clock.sleep, log=lambda *_: None)
                soak.Soak.__init__ = init
                rc = soak.main(argv)
            finally:
                soak.IncusCluster = orig
                soak.Soak.__init__ = old
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
