"""Hermetic cells for rg_move_soak.py (#18583, matrix row H11).

Each verdict rule has a cell that fails when the rule is reverted, and the
orchestration is driven end to end by a fake cluster — including the exact
shape the operator hit on 2026-10-31: every move to the peer fails fabric auth
on clock skew, every move back prints "already primary".
"""

import ipaddress
import json
import os
import re
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

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

    def test_fallback_reply_is_its_own_class_18559(self):
        text = "Manual failover triggered for redundancy group 2 (peer unreachable; resigned locally, break-before-make)"
        self.assertEqual(soak.classify_cli(0, text, 2, untargeted=True)[0], soak.CLI_FALLBACK)
        self.assertEqual(soak.classify_cli(0, text, 2)[0], soak.CLI_OTHER)

    def test_no_longer_primary_reply_is_a_fallback_18559(self):
        # clusterfailover.UntargetedNoLongerPrimaryMessage, verbatim for both
        # owner shapes. An OK reply, but the group left by election, not by
        # the transfer: VOID like the other fallbacks, never "unexpected CLI
        # output" (docs/ha-rg-move-correctness.md troubleshooting row).
        for text in ("Redundancy group 2 is no longer primary on this node (now secondary); node 1 reports it "
                     "primary. Nothing to resign: the group already left this node during the request",
                     "Redundancy group 2 is no longer primary on this node (now secondary); no node reports it "
                     "primary yet (an election is in progress). Nothing to resign: the group already left this "
                     "node during the request"):
            self.assertEqual(soak.classify_cli(0, text, 2, untargeted=True)[0], soak.CLI_FALLBACK)
            self.assertEqual(soak.classify_cli(0, text, 1, untargeted=True)[0], soak.CLI_OTHER)
            self.assertEqual(soak.classify_cli(0, text, 2)[0], soak.CLI_OTHER)

    def test_dual_active_reply_is_a_fallback_18559(self):
        # clusterfailover.ResignNoteDualActive; the Go cell
        # TestSoakReplyNotesMatchGo18559 keeps the two texts in sync.
        text = "Manual failover triggered for redundancy group 2 (the peer is also primary; resigned locally)"
        self.assertEqual(soak.classify_cli(0, text, 2, untargeted=True)[0], soak.CLI_FALLBACK)
        self.assertEqual(soak.classify_cli(0, text, 2)[0], soak.CLI_OTHER)

    def test_triggered_is_accepted_only_for_an_untargeted_move_18559(self):
        text = "Manual failover triggered for redundancy group 2"
        self.assertEqual(soak.classify_cli(0, text, 2, untargeted=True)[0], soak.CLI_TRIGGERED)
        self.assertEqual(soak.classify_cli(0, text, 1, untargeted=True)[0], soak.CLI_OTHER)
        self.assertEqual(soak.classify_cli(0, text + " (superseded)", 2, untargeted=True)[0], soak.CLI_OTHER)
        self.assertEqual(soak.classify_cli(0, "Manual failover completed for redundancy group 2 (transfer committed)",
                                           2, untargeted=True)[0], soak.CLI_OK)


class MoveCommand(unittest.TestCase):
    def test_targeted_form_names_every_target(self):
        for target in (0, 1):
            self.assertEqual(soak.move_command(2, target, 0, soak.FORM_TARGETED),
                             (f"request chassis cluster failover redundancy-group 2 node {target}", False))

    def test_untargeted_away_names_no_node_only_away_from_the_issuer_18559(self):
        self.assertEqual(soak.move_command(1, 1, 0, soak.FORM_UNTARGETED_AWAY),
                         ("request chassis cluster failover redundancy-group 1", True))
        self.assertEqual(soak.move_command(1, 0, 0, soak.FORM_UNTARGETED_AWAY),
                         ("request chassis cluster failover redundancy-group 1 node 0", False))
        self.assertEqual(soak.move_command(2, 0, 1, soak.FORM_UNTARGETED_AWAY),
                         ("request chassis cluster failover redundancy-group 2", True))

    def test_skew_hint(self):
        self.assertIn("clock skew", soak.cli_error_hint(USER_ERROR))
        self.assertEqual(soak.cli_error_hint("error: something else"), "")


def rgres(rg=2, target=1, pre=0, cli=soak.CLI_OK, landed=0.8, dual=False, helper=None):
    if helper is None and landed is not None:
        helper = {target: True, 1 - target: False}
    return soak.RGMoveResult(rg, target, pre, "pre", cli, "first line", 0, 0.7, landed, "last", dual, helper)


GOOD_TRAFFIC = {"ping_lost": 3, "ping_max_gap_ms": 40.0, "ping_tail_replies": 95, "worst_stall_ms": 200.0,
                "worst_stall_stream": 5, "died_streams": [], "stalled_streams": [], "agg_zero_ms": 0.0, "tail_gbps": 20.0,
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


    def test_udp_void_is_per_move_void_when_other_evidence_is_clean(self):
        r = rec([rgres()])
        r.udp_probe = {"status": soak.VOID, "detail": "missing synced UDP session"}
        self.assertEqual(self.verdict(r), (soak.VOID, ["missing synced UDP session"]))

    def test_udp_void_does_not_mask_an_independent_move_failure(self):
        r = rec([rgres(cli=soak.CLI_ERROR)])
        r.udp_probe = {"status": soak.VOID, "detail": "UDP post-move session unavailable"}
        verdict, reasons = self.verdict(r)
        self.assertEqual(verdict, soak.FAIL)
        self.assertTrue(any("CLI error" in reason for reason in reasons))
        self.assertTrue(any("UDP probe evidence VOID" in reason for reason in reasons))
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
        r.neigh_node = {"v4": 1, "v6": None}  # unresolved mid-run: unmeasured, not a pass
        v, why = self.verdict(rec([r]))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("unmeasured", why[0])
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

    def test_several_streams_stalling_is_not_a_cost(self):
        # Seat AF probe6: 7 of 8 streams stall 3 s with ping clean and one
        # stream alive. That is not one stream backing off.
        def window(dead):
            ivs = []
            for i in range(60):
                st = {sid: (0.0 if sid in dead and 1.0 <= i * 0.1 < 4.0 else 1.4e9)
                      for sid in (5, 7, 9, 11, 13, 15, 17, 19)}
                ivs.append((i * 0.1, (i + 1) * 0.1, st, sum(st.values())))
            replies = [(i * 0.01, i + 1) for i in range(600)]
            stalls, agg = soak.stream_stalls(ivs, 1e6)
            return soak.traffic_for_window(0.0, 6.0, soak.ping_gaps(replies), replies, stalls, agg, ivs, soak.Budget())
        self.assertEqual(self.verdict(rec([rgres()], window({5})))[0], soak.COST)
        for dead in ({5, 7}, {5, 7, 9, 11, 13, 15, 17}):
            v, why = self.verdict(rec([rgres()], window(dead)))
            self.assertEqual(v, soak.FAIL, dead)
            self.assertIn(f"{len(dead)} streams", why[0])

    def test_recovered_single_stream_stall_is_a_cost(self):
        t = dict(GOOD_TRAFFIC, worst_stall_ms=2500.0, stalled_streams=[5])
        v, why = self.verdict(rec([rgres()], t))
        self.assertEqual(v, soak.COST)
        self.assertIn("recovered", why[0])

    def test_stall_past_the_cost_cap_fails(self):
        v, why = self.verdict(rec([rgres()], dict(GOOD_TRAFFIC, worst_stall_ms=10500.0, stalled_streams=[5])))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("COST cap", why[0])
        self.assertEqual(self.verdict(rec([rgres()], dict(GOOD_TRAFFIC, worst_stall_ms=9900.0, stalled_streams=[5])))[0], soak.COST)

    def test_stream_that_never_recovers_fails(self):
        t = dict(GOOD_TRAFFIC, worst_stall_ms=9000.0, died_streams=[7])
        v, why = self.verdict(rec([rgres()], t))
        self.assertEqual(v, soak.FAIL)
        self.assertIn("never recovered", why[0])

    def test_cost_does_not_hide_a_fail(self):
        t = dict(GOOD_TRAFFIC, worst_stall_ms=2500.0, stalled_streams=[5])
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

    def test_traffic_generator_death_is_void_never_pass(self):
        # #19054 changed this cell's expectation from FAIL to VOID: a window
        # the generators did not cover cannot be scored either way. It is
        # never PASS, and the reason names it.
        for gone in ("iperf_covered", "ping_covered"):
            v, why = self.verdict(rec([rgres()], dict(GOOD_TRAFFIC, **{gone: False})))
            self.assertEqual(v, soak.VOID, why)
            self.assertTrue(any("did not cover the move window" in w for w in why), why)

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
    generators stream them while the soak sleeps.

    Soak.views() and Soak.helpers() call into the fake from two worker
    threads. Every advance therefore holds `lock` (#19041): an unlocked
    read-modify-write of `t` raced between those threads.
    """

    def __init__(self):
        self.t = 1_000_000.0
        self.listeners = []
        self.lock = threading.RLock()

    def _to(self, t):
        with self.lock:
            while self.t < t:
                step = min(0.05, t - self.t)
                self.t += step
                for fn in self.listeners:
                    fn(self.t)

    def now(self):
        with self.lock:
            self._to(self.t + 0.001)
            return self.t

    def sleep(self, s):
        with self.lock:
            self._to(self.t + max(0.0, s))


class Proc:
    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


MEMBERS = {1: {0: "ge-0-0-2", 1: "ge-7-0-2"}, 2: {0: "ge-0-0-1", 1: "ge-7-0-1"}}
MACS = {(0, 1): "02:bf:72:16:01:00", (1, 1): "02:bf:72:16:01:01",
        (0, 2): "02:bf:72:16:02:02", (1, 2): "02:bf:72:16:02:03"}

class FakeMouseTarget:
    """Mouse-target socket state for the soak's pre-traffic reset."""

    def __init__(self, stale_ports=None, reset_fail=False, reset_timeout=False):
        self.established = dict(stale_ports or {})
        self.listening = {5210, 5211}
        self.reset_fail = reset_fail
        self.reset_timeout = reset_timeout
        self.checked_ports = []
        self.restarted = []

    def prepare_iperf(self, ports):
        self.checked_ports = list(ports)
        for port in sorted(set(ports)):
            count = self.established.get(port, 0)
            if not count:
                continue
            self.restarted.append(port)
            if self.reset_fail:
                return (f"could not restart mouse-iperf3@{port}.service after finding "
                        f"{count} ESTABLISHED sockets: injected restart failure")
            if self.reset_timeout:
                return ("mouse iperf reset timed out waiting for LISTEN with zero ESTABLISHED "
                        f"sockets on port(s) {port}")
            self.established.pop(port, None)
            self.listening.add(port)
        return None



class FakeCluster:
    """A two-node cluster plus a LAN host, in fake time.

    `skew_s` breaks the cross-node (fabric) path the way a skewed wall clock
    does; the local path (sync channel) works. `stuck_traffic` keeps every
    packet on the initial owner whatever the status says (review B1's
    fixture). `revert_after_s` hands an RG back that many seconds after a
    move lands. `dual_after_land` makes both nodes claim the RG for
    DUAL_HOLD_S after landing: a real dual-active STATE, which the soak's
    immediate re-sample sees again (#19041). `faults` maps a move number to a traffic fault injected
    0.3 s after that move's CLI: "gap" (a 1.5 s outage of ping and every
    stream), "stall" (stream 7 stalls 2.5 s), "die" (stream 7 stops for good).
    """

    def __init__(self, clock, owner, skew_s=0.0, cli_rc_on_error=0, lag_polls=0, lan_off=3.0,
                 stuck_traffic=False, revert_after_s=None, dual_after_land=False, helper_lie=False,
                 busy_iperf=False, faults=None, dual_after_s=None, stale_iperf_ports=None,
                 iperf_reset_fail=False, iperf_reset_timeout=False, untargeted_reply="transfer"):
        self.clock_ = clock
        # #18559: how the fake answers the UNTARGETED form issued on the owner.
        # "transfer": the fix (a make-before-break transfer, "transfer
        # committed"). "triggered": the pre-#18559 local resign, landing 0.5 s
        # later when the peer's heartbeat claims the RG. "fallback": a
        # post-#18559 build whose transfer never reached the peer.
        self.untargeted_reply = untargeted_reply
        self.owner = dict(owner)
        self.initial = dict(owner)
        self.skew_s = skew_s
        self.cli_rc_on_error = cli_rc_on_error
        self.lag_polls = lag_polls
        self.lan_off = lan_off
        self.stuck_traffic = stuck_traffic
        self.revert_after_s = revert_after_s
        self.dual_after_land = dual_after_land
        self.dual_after_s = dual_after_s  # a dual-active period starting this long after landing
        # ONE sample's two reads claim the RG this long after landing: each
        # node's next read renders it primary once (the pre-#19041 shape).
        self.dual_reads_after_s = None  # set by a cell (not a constructor argument: #18559 extends it)
        self.dual_reads = set()
        self.helper_lie = helper_lie
        self.busy_iperf = busy_iperf
        self.faults = faults or {}
        self.mouse_target = FakeMouseTarget(stale_iperf_ports, iperf_reset_fail, iperf_reset_timeout)
        self.target_prepared = False
        self.target_prepared_when_generators_started = None
        self.pending = {}
        self.landed_at = {}
        self.dual_until = float("-inf")  # both nodes claim every RG while clock < dual_until
        self.fw = {0: "fake:fw0", 1: "fake:fw1"}
        self.lan = "fake:lan"
        self.commands = []
        self.moves_seen = 0
        self.counters = {0: {}, 1: {}}
        self.files = {}
        self.gen_start = None
        self.last_emit = None
        self.udp_probe_started_at = None
        self.udp_probe_run_id = None
        self.udp_probe_identity_port = 41000
        self.udp_probe_lost_after_seq = None
        self.udp_probe_next_seq = 0
        self.udp_probe_sent = set()
        self.udp_probe_replied = set()
        self.udp_probe_boot_id = "0123456789abcdef0123456789abcdef"
        self.udp_probe_session_value = 71
        self.udp_probe_recreate_at = None
        self.udp_probe_session_queries = []
        self.udp_probe_snapshot_count = 0
        self.ping_seq = {}
        self.iv_index = {}
        self.events = []  # (lan_t0, lan_t1, kind)
        self._status_lock = threading.Lock()
        clock.listeners.append(self._tick)

    # -- cluster -------------------------------------------------------

    def prepare_iperf(self, ports):
        result = self.mouse_target.prepare_iperf(ports)
        self.target_prepared = result is None
        return result

    def udp_probe_start(self, run_id, target, port):
        if "udp-start-fail" in self.faults.values():
            return "fake UDP probe setup failed"
        self.udp_probe_started_at = self.clock_.t
        self.udp_probe_run_id = run_id
        self.udp_probe_identity_port = 41000
        self.udp_probe_lost_after_seq = None
        self.udp_probe_next_seq = 0
        self.udp_probe_sent = set()
        self.udp_probe_replied = set()
        self.udp_probe_session_value = 71
        self.udp_probe_recreate_at = None
        return None

    def _advance_udp_probe(self, t):
        if self.udp_probe_started_at is None:
            return
        count = max(1, int((t - self.udp_probe_started_at) /
                           soak.udp_session_probe.INTERVAL_S) + 1)
        while self.udp_probe_next_seq < count:
            seq = self.udp_probe_next_seq
            self.udp_probe_sent.add(seq)
            if self.udp_probe_lost_after_seq is None or seq < self.udp_probe_lost_after_seq:
                self.udp_probe_replied.add(seq)
            self.udp_probe_next_seq += 1

    def udp_probe_snapshot(self, run_id):
        if run_id != self.udp_probe_run_id or self.udp_probe_started_at is None:
            return None
        self.udp_probe_snapshot_count += 1
        self._advance_udp_probe(self.clock_.t)
        lines = ["BOOT " + self.udp_probe_boot_id + "\n",
                 "SOCKET 10.0.61.2 39000 203.0.113.9 6201\n"]
        for seq in sorted(self.udp_probe_sent):
            lines.append(f"SENT {seq}\n")
            if seq in self.udp_probe_replied:
                lines.append(f"REPLY {seq} 203.0.113.9 {self.udp_probe_identity_port}\n")
        return "".join(lines)

    def udp_probe_session_id(self, node, probe_snapshot):
        self.udp_probe_session_queries.append(node)
        if self.faults.get(self.moves_seen + 1) == "udp-restart-in-session-query":
            self.udp_probe_boot_id = "fedcba9876543210fedcba9876543210"
        if self.faults.get(self.moves_seen + 1) == "udp-pre-session-missing":
            return None, None
        try:
            parsed = soak.udp_session_probe.parse_log(probe_snapshot)
        except ValueError as exc:
            return None, str(exc)
        if parsed.socket_tuple is None:
            return None, "missing fake UDP socket tuple"
        return str(self.udp_probe_session_value), None

    def udp_probe_stop(self, run_id):
        self.udp_probe_started_at = None
        self.udp_probe_run_id = None

    def forwarder(self, rg):
        return self.initial.get(rg, 0) if self.stuck_traffic else self.owner.get(rg, 0)

    def _apply_time(self, t):
        for rg, (target, at) in list(self.pending.items()):
            if t >= at:
                self.owner[rg] = target
                self.landed_at[rg] = t
                del self.pending[rg]
                if self.faults.get(self.moves_seen) == "udp-lost-at-landing":
                    # The probe answers right up to the landing and never
                    # after it: only a checkpoint taken AT the landing sees
                    # the loss (one taken at the CLI return counts the
                    # replies in between).
                    self._advance_udp_probe(t)
                    self.udp_probe_lost_after_seq = self.udp_probe_next_seq
                if self.dual_after_land:
                    self.dual_until = t + self.DUAL_HOLD_S
        if self.udp_probe_recreate_at is not None and t >= self.udp_probe_recreate_at:
            self.udp_probe_session_value = 84
            self.udp_probe_recreate_at = None
        if self.dual_after_s is not None:
            for rg, at in list(self.landed_at.items()):
                if t - at >= self.dual_after_s and (rg, at) not in getattr(self, "_dual_done", set()):
                    self._dual_done = getattr(self, "_dual_done", set()) | {(rg, at)}
                    self.dual_until = t + self.DUAL_HOLD_S
        if self.dual_reads_after_s is not None:
            for rg, at in list(self.landed_at.items()):
                if t - at >= self.dual_reads_after_s and (rg, at) not in getattr(self, "_dual_reads_done", set()):
                    self._dual_reads_done = getattr(self, "_dual_reads_done", set()) | {(rg, at)}
                    self.dual_reads = {0, 1}
        if self.revert_after_s is not None:
            for rg, at in list(self.landed_at.items()):
                if t - at >= self.revert_after_s and self.owner[rg] == 1:
                    self.owner[rg] = 0
                    del self.landed_at[rg]

    def cli(self, node, cmd):
        self.commands.append((node, cmd))
        m = re.match(r"request chassis cluster failover redundancy-group (\d+)(?: node (\d))?$", cmd)
        rg = int(m.group(1))
        untargeted = m.group(2) is None
        # The untargeted form moves the RG away from the node it runs on.
        target = 1 - node if untargeted else int(m.group(2))
        self.moves_seen += 1
        lan_now = self.clock_.t + self.lan_off
        fault = self.faults.get(self.moves_seen)
        if self.udp_probe_lost_after_seq is not None and fault != "udp-lost":
            self.udp_probe_lost_after_seq = None
        if fault == "gap":
            self.events.append((lan_now + 0.3, lan_now + 1.8, "gap"))
        elif fault == "stall":
            self.events.append((lan_now + 0.3, lan_now + 2.8, "stall"))
        elif fault == "outage":
            self.events.append((lan_now + 0.3, lan_now + 3.8, "gap"))
        elif fault == "die":
            self.events.append((lan_now + 0.3, float("inf"), "stall"))
        elif fault == "udp-recreated-after-landing":
            self.udp_probe_recreate_at = self.clock_.t + 0.9
        elif fault == "udp-lost":
            self._advance_udp_probe(self.clock_.t)
            self.udp_probe_lost_after_seq = self.udp_probe_next_seq
        elif fault == "udp-recover":
            self.udp_probe_lost_after_seq = None
        self.clock_.sleep(0.6)
        if target != node and abs(self.skew_s) > 60:
            return self.cli_rc_on_error, USER_ERROR + "\n"
        if self.owner[rg] == target:
            return 0, f"Redundancy group {rg} is already primary on node {target}\n"
        if untargeted and self.untargeted_reply == "no-longer-primary":
            # The peer claimed the group while the request ran: an OK reply,
            # and the group is the peer's by election, not by the transfer.
            self.owner[rg] = target
            self.landed_at[rg] = self.clock_.t
            return 0, (f"Redundancy group {rg} is no longer primary on this node (now secondary); node {target} "
                       f"reports it primary. Nothing to resign: the group already left this node during the "
                       f"request\n")
        if untargeted and self.untargeted_reply in ("triggered", "fallback"):
            self.pending[rg] = (target, self.clock_.t + 0.5)
            note = (" (peer unreachable; resigned locally, break-before-make)"
                    if self.untargeted_reply == "fallback" else "")
            return 0, f"Manual failover triggered for redundancy group {rg}{note}\n"
        if self.lag_polls:
            self.pending[rg] = (target, self.clock_.t + self.lag_polls * 0.5)
        else:
            self.owner[rg] = target
            self.landed_at[rg] = self.clock_.t
            if self.dual_after_land:
                self.dual_until = self.clock_.t + self.DUAL_HOLD_S
        return 0, f"Manual failover completed for redundancy group {rg} (transfer committed)\n"

    STATUS_READ_S = 0.15  # one `show chassis cluster status` read, in fake time
    DUAL_HOLD_S = 1.0     # how long a fixture's dual-active state lasts

    def status(self, node):
        """One node's own view, read at ONE instant: when this call starts.

        Each call is independent, like production's two `incus exec ... cli`
        reads. Nothing ties node0's read to node1's, so a landing between
        them shows one node's view from before it and the other's from after
        it (#19041). `_status_lock` keeps the two worker threads' updates of
        the shared fake state apart. The read's fake time is spent outside
        that lock, on the clock, which has its own lock."""
        with self._status_lock:
            self._apply_time(self.clock_.t)
            if self.clock_.t < self.dual_until or node in self.dual_reads:
                self.dual_reads.discard(node)
                view = status_text({rg: node for rg in self.owner}, node)
            else:
                view = status_text(self.owner, node)
        self.clock_.sleep(self.STATUS_READ_S)
        return view

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
            self.target_prepared_when_generators_started = self.target_prepared
            self.gen_start = self.last_emit = self.clock_.t
        # #19054: the generator stops by itself after its own -t/-w seconds.
        m = re.search(r" -t (\d+) " if kind == "iperf" else r" -w (\d+) ", script)
        if m:
            if not hasattr(self, "gen_end"):
                self.gen_end = {}
            self.gen_end[(kind, fam)] = self.gen_start + int(m.group(1))
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
        self._advance_udp_probe(t)
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
            t_gen = min(t, getattr(self, "gen_end", {}).get((kind, fam), t))
            with open(path, "a") as f:
                if kind == "ping":
                    seq = self.ping_seq.get(fam, 0)
                    while self.gen_start + (seq + 1) * 0.01 <= t_gen:
                        seq += 1
                        ts = self.gen_start + seq * 0.01 + self.lan_off
                        if not self._in(ts, "gap"):
                            f.write(f"[{ts:.6f}] 64 bytes from x: icmp_seq={seq % 65536} ttl=63 time=0.1 ms\n")
                    self.ping_seq[fam] = seq
                else:
                    i = self.iv_index.get(fam, 0)
                    while self.gen_start + (i + 1) * 0.1 <= t_gen:
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
             v6=False, restore=True, files=None, strict_cost=False, managed_v6=None, form=soak.FORM_TARGETED,
             expect_transfer=False, traffic_s=None, now_fn=None):
    with tempfile.TemporaryDirectory() as d:
        cfg = soak.Config(moves=moves, sleep_s=sleep_s, rgs=rgs, issuer=issuer, traffic=traffic, form=form,
                          helper_check=helper_check, restore=restore, strict_cost=strict_cost,
                          iperf4_on_mouse_target=True,
                          iperf6_on_mouse_target=v6 if managed_v6 is None else managed_v6,
                          budget=soak.Budget(converge_s=sleep_s, expect_transfer=expect_transfer), outdir=d, run_id="t",
                          target4="172.16.80.200", target6="2001:db8::200" if v6 else "",
                          lan_vip4="10.0.61.1", **({"traffic_s": traffic_s} if traffic_s is not None else {}))
        logs = []
        kw = {"mono_fn": clock.now} if now_fn is not None else {}
        rc = soak.Soak(cfg, cluster, now_fn=now_fn or clock.now, sleep_fn=clock.sleep, log=logs.append, **kw).run()
        with open(os.path.join(d, "result.json")) as f:
            res = json.load(f)
        if files is not None:
            files.extend(sorted(os.listdir(d)))
    return rc, res, logs


def verdicts(res):
    return [m["verdict"] for m in res["moves"]]




class CappedFlowSessionCLI:
    """The remote `cli`'s `show security flow session` (#19038).

    cmd/cli/show_flow.go parseFlowSessionArgs defaults Limit to 100, and
    pkg/grpcapi getSessionsLegacy returns the first `limit` matching forward
    sessions in BPF hash order while counting every match into Total. The
    hash order depends on each node's map seed, so `probe_row[node]` is
    where the probe falls in that node's walk. Each new probe socket gets a
    new tuple, and with it a new row.
    """

    FILLERS = 150
    PROBE = ("10.0.61.2", 39000, "203.0.113.9", 6201, "udp")  # FakeCluster's SOCKET line

    def __init__(self, probe_row, probe_id):
        self.probe_row = dict(probe_row)
        self.probe_id = probe_id
        self.queries = []

    def table(self, node):
        rows = []
        for k in range(self.FILLERS):
            if k % 10 == 0:
                # Earlier probe sockets' lingering flows: same client, target
                # and port, different source port.
                rows.append((1000 + k, "10.0.61.2", 30000 + k, "203.0.113.9", 6201, "udp"))
            else:
                rows.append((1000 + k, f"10.0.61.{10 + k % 200}", 40000 + k, "172.16.80.202", 5211, "tcp"))
        rows.insert(self.probe_row[node], (self.probe_id(),) + self.PROBE)
        return rows

    def run(self, node, cmd):
        self.queries.append((node, cmd))
        words = cmd.split()
        if words[:4] != ["show", "security", "flow", "session"]:
            return 1, f"error: unexpected command {cmd!r}\n"
        limit, preds, args = 100, [], words[4:]
        if len(args) % 2:
            return 1, f'error: missing value for "{args[-1]}"\n'
        for key, val in zip(args[::2], args[1::2]):
            if key == "limit":
                limit = int(val)
            elif key in ("source-prefix", "destination-prefix"):
                net, col = ipaddress.ip_network(val if "/" in val else val + "/32"), 1 if key[0] == "s" else 3
                preds.append(lambda r, net=net, col=col: ipaddress.ip_address(r[col]) in net)
            elif key in ("source-port", "destination-port"):
                port, col = int(val), 2 if key[0] == "s" else 4
                preds.append(lambda r, port=port, col=col: r[col] == port)
            elif key == "protocol":
                preds.append(lambda r, proto=val.lower(): r[5] == proto)
            else:
                return 1, f'error: unknown session filter "{key}"\n'
        out = []
        for n in (node, 1 - node):  # the queried node's own section first
            matched = [r for r in self.table(n) if all(pred(r) for pred in preds)]
            out += [f"node{n}:", "-" * 74]
            for sid, src, sport, dst, dport, proto in matched[:limit]:
                out += [f"Session ID: {sid}, Policy name: allow/1, HA State: Active, Timeout: 60, "
                        "Session State: Unknown (validity not tracked)",
                        f"  In: {src}/{sport} --> {dst}/{dport};{proto}, Conn Tag: 0x0, If: reth1.0, "
                        "Zone: trust, Pkts: 9, Bytes: 900,",
                        f"  Out: {dst}/{dport} --> 172.16.80.8/{sport};{proto}, Conn Tag: 0x0, If: reth0.80, "
                        "Zone: untrust, Pkts: 9, Bytes: 900,", ""]
            out.append(f"Total sessions: {len(matched)}")
            if n == node:
                out.append("")
        return 0, "\n".join(out) + "\n"


class CappedCLICluster(FakeCluster):
    """FakeCluster whose Session ID query is the REAL IncusCluster method,
    with `incus exec <fw> -- cli -c <cmd>` answered by CappedFlowSessionCLI."""

    def __init__(self, clock, owner, probe_row, **kw):
        super().__init__(clock, owner, **kw)
        self.cli_model = CappedFlowSessionCLI(probe_row, lambda: self.udp_probe_session_value)

    def _exec(self, ref, argv, timeout=None):
        node = {name: n for n, name in self.fw.items()}[ref]
        if argv[:2] != ["cli", "-c"] or len(argv) != 3:
            return 1, f"unexpected argv {argv!r}"
        return self.cli_model.run(node, argv[2])

    def udp_probe_session_id(self, node, probe_snapshot):
        self.udp_probe_session_queries.append(node)
        return soak.IncusCluster.udp_probe_session_id(self, node, probe_snapshot)


# The four H11 runs on loss at #18559 head 3380701f5f
# (gate-18559-logs/loss-pr-1794194752/h11-untargeted-away-*): run -> (issuer,
# sleep, probe row in node0's and node1's walk). A row >= 100 is the node
# whose 20 moves VOIDed "UDP sequence probe flow was absent on synced
# standby"; a row < 100 is the node whose 20 moves SURVIVED. Each run is
# constant, and all four combinations appear, so the issuer is not the cause.
H11_ARTEFACT_SHAPES_19038 = {
    "s5-from0": (0, 5.0, {0: 120, 1: 130}),  # to node0 VOID, to node1 VOID
    "s5-from1": (1, 5.0, {0: 10, 1: 20}),    # to node0 SURVIVED, to node1 SURVIVED
    "s2-from0": (0, 2.0, {0: 120, 1: 20}),   # to node0 VOID, to node1 SURVIVED
    "s2-from1": (1, 2.0, {0: 10, 1: 130}),   # to node0 SURVIVED, to node1 VOID
}


class SessionListingCap19038(unittest.TestCase):
    """#19038: the probe's Session ID query must not depend on hash position."""

    PROBE = ("BOOT 0123456789abcdef0123456789abcdef\n"
             "SOCKET 10.0.61.2 39000 203.0.113.9 6201\nSENT 0\nREPLY 0 203.0.113.9 41000\n")
    QUERY = ("show security flow session source-prefix 10.0.61.2/32 source-port 39000 "
             "destination-prefix 203.0.113.9/32 destination-port 6201 protocol udp limit 10000")

    def test_artefact_shapes_survive_for_both_issuers_and_directions(self):
        for run, (issuer, sleep_s, probe_row) in H11_ARTEFACT_SHAPES_19038.items():
            with self.subTest(run=run):
                clock = FakeClock()
                c = CappedCLICluster(clock, {2: 0}, probe_row)
                rc, res, _ = run_fake(c, clock, moves=4, issuer=issuer, sleep_s=sleep_s)
                by_direction = {}
                for m in res["moves"]:
                    by_direction.setdefault(f"to node{m['target']}", set()).add(
                        (m["udp_probe"]["status"], m["udp_probe"]["detail"].split(";")[0]))
                self.assertEqual({d: {s for s, _ in v} for d, v in by_direction.items()},
                                 {"to node0": {"SURVIVED"}, "to node1": {"SURVIVED"}}, by_direction)
                self.assertEqual(rc, 0, res["summary"])
                self.assertEqual(verdicts(res), ["PASS"] * 4)
                # Pre-move query on the target (standby) and the final query
                # on the target (now primary), each with the tuple filter.
                self.assertEqual(len(c.cli_model.queries), 8)
                self.assertEqual({cmd for _, cmd in c.cli_model.queries}, {self.QUERY})

    def test_query_names_the_probe_tuple_and_an_explicit_limit(self):
        self.assertEqual(soak.udp_session_probe.session_query_for_probe(self.PROBE), self.QUERY)
        with self.assertRaisesRegex(ValueError, "no client SOCKET tuple"):
            soak.udp_session_probe.session_query_for_probe("BOOT 0123456789abcdef0123456789abcdef\n")

    def test_bare_listing_beyond_row_100_is_unreadable_not_absent(self):
        # The model reproduces the artefacts under the pre-fix bare query:
        # found when the probe's row is < 100, missing otherwise. A missing
        # probe in a listing whose Total exceeds its rows is not absence.
        for row in (0, 99, 100, 120):
            with self.subTest(row=row):
                model = CappedFlowSessionCLI({0: row, 1: 0}, lambda: 71)
                rc, out = model.run(0, "show security flow session")
                self.assertEqual(rc, 0)
                self.assertIn("Total sessions: 151", out)
                if row < 100:
                    self.assertEqual(soak.udp_session_probe.session_id_for_probe(self.PROBE, out), "71")
                else:
                    with self.assertRaisesRegex(ValueError, r"shows 100 rows but reports 'Total sessions: 151'"):
                        soak.udp_session_probe.session_id_for_probe(self.PROBE, out)

    def test_absence_needs_a_complete_local_section(self):
        model = CappedFlowSessionCLI({0: 0, 1: 0}, lambda: 71)
        other_port = self.QUERY.replace("source-port 39000", "source-port 39001")
        rc, complete = model.run(0, other_port)
        self.assertEqual(rc, 0)
        self.assertIn("Total sessions: 0\n", complete)
        # A complete, empty local section proves absence.
        self.assertIsNone(soak.udp_session_probe.session_id_for_probe(self.PROBE, complete))
        # The same section without its terminator (a CLI error, a cut-off
        # capture) proves nothing.
        cut = complete.replace("Total sessions: 0\n", "", 1)
        with self.assertRaisesRegex(ValueError, "no 'Total sessions:' terminator"):
            soak.udp_session_probe.session_id_for_probe(self.PROBE, cut)
        # The PEER section's terminator does not complete the local one.
        self.assertIn("node1:", cut)
        # Via the real IncusCluster method, an unreadable listing is an error
        # (the soak's "Session ID query failed" VOID), never "absent".
        cluster = soak.IncusCluster({0: "fw0", 1: "fw1"}, "lan", "target")
        cluster._exec = lambda ref, argv, timeout=None: (0, cut)
        session_id, error = cluster.udp_probe_session_id(1, self.PROBE)
        self.assertIsNone(session_id)
        self.assertRegex(error, r"could not parse flow-session capture on node1: .*no 'Total sessions:' terminator")


class IperfTargetManagedness(unittest.TestCase):
    @staticmethod
    def _fresh_cluster_env(filename):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        root = os.path.abspath(os.path.join(script_dir, "../.."))
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "PROJECT_ROOT": root,
            "BPFRX_CLUSTER_ENV": os.path.join(script_dir, filename),
            "CLUSTER_ENV_SCRIPT": os.path.join(script_dir, "cluster-env.sh"),
        }
        proc = subprocess.run(
            ["bash", "-c", 'source "$CLUSTER_ENV_SCRIPT" && env -0'],
            cwd=root, env=env, capture_output=True, check=True)
        return {entry.split(b"=", 1)[0].decode(): entry.split(b"=", 1)[1].decode()
                for entry in proc.stdout.split(b"\0") if entry}

    def _production_reset(self, env, target6):
        target4 = env["IPERF_TARGET4"]
        mouse4, mouse6 = env["MOUSE_TARGET_V4"], env["MOUSE_TARGET_V6"]
        managed4, managed6 = soak.iperf_target_managedness(
            target4, target6, mouse4, mouse6, env.get("TARGET_ALIAS_V4", ""),
            env.get("IPERF_TARGET_V4_V6_SAME_HOST", ""))
        ports = ([5211] if managed4 else []) + ([5210] if managed6 else [])
        cluster = soak.IncusCluster({0: "fw0", 1: "fw1"}, "lan", env["MOUSE_TARGET_REF"])
        calls, restarted = [], set()

        def fake_exec(ref, argv, timeout=None):
            calls.append((ref, argv))
            if argv[:2] == ["systemctl", "restart"]:
                restarted.add(int(re.search(r"@(\d+)\.service$", argv[2]).group(1)))
                return 0, ""
            match = re.search(r"state (established|listening).*:([0-9]+)", argv[2])
            self.assertIsNotNone(match, argv)
            state, port = match.group(1), int(match.group(2))
            if state == "established":
                return (0, "ESTAB stale-client") if port == 5210 and port not in restarted else (0, "")
            return 0, f"LISTEN 0 4096 0.0.0.0:{port} 0.0.0.0:*"

        cluster._exec = fake_exec
        error = cluster.prepare_iperf(ports)
        return error, calls, restarted, (managed4, managed6)

    def test_loss_split_target_and_same_host_target_mapping_18631(self):
        self.assertEqual(
            soak.iperf_target_managedness(
                "172.16.80.202", "2001:559:8585:80::201",
                "172.16.80.201", "2001:559:8585:80::201",
                "172.16.80.202", "no"),
            (True, False))
        self.assertEqual(
            soak.iperf_target_managedness(
                "172.16.80.210", "2001:559:8585:80::210",
                "172.16.80.210", "2001:559:8585:80::210", "",
                ""),
            (True, True))
        self.assertEqual(
            soak.iperf_target_managedness(
                "172.16.80.202", "2001:559:8585:80::201",
                "172.16.80.201", "2001:559:8585:80::201",
                "172.16.80.202", "unknown"),
            (True, False))
        self.assertEqual(
            soak.iperf_target_managedness(
                "172.16.80.202", "2001:559:8585:80::201",
                "172.16.80.201", "2001:559:8585:80::201",
                "172.16.80.202", ""),
            (True, False))

    def test_fresh_loss_env_exports_split_veto_even_for_equal_stale_v6_18631(self):
        env = self._fresh_cluster_env("loss-userspace-cluster.env")
        self.assertEqual(env["IPERF_TARGET_V4_V6_SAME_HOST"], "no")
        self.assertIn("IPERF_TARGET6_SPLIT_HOLDER", env)
        error, calls, restarted, managed = self._production_reset(
            env, target6=env["MOUSE_TARGET_V6"])
        self.assertIsNone(error)
        self.assertEqual(managed, (True, False))
        self.assertNotIn(5210, restarted)
        self.assertFalse(any("5210" in " ".join(argv) for _, argv in calls))

    def test_fresh_tcp_udp_equal_targets_restart_managed_5210_18631(self):
        for filename in ("tcp-userspace-cluster.env", "udp-userspace-cluster.env"):
            with self.subTest(filename=filename):
                env = self._fresh_cluster_env(filename)
                self.assertEqual(env["IPERF_TARGET4"], env["MOUSE_TARGET_V4"])
                self.assertEqual(env["IPERF_TARGET6"], env["MOUSE_TARGET_V6"])
                error, calls, restarted, managed = self._production_reset(
                    env, target6=env["IPERF_TARGET6"])
                self.assertIsNone(error)
                self.assertEqual(managed, (True, True))
                self.assertIn(5210, restarted)
                self.assertIn(
                    ["systemctl", "restart", "mouse-iperf3@5210.service"],
                    [argv for _, argv in calls])
                self.assertTrue(all(ref == env["MOUSE_TARGET_REF"] for ref, _ in calls))


class IncusTargetPreflight(unittest.TestCase):
    def test_prepare_iperf_restarts_only_stale_port_and_waits_for_ready_18631(self):
        cluster = soak.IncusCluster({0: "fw0", 1: "fw1"}, "lan", "loss:mouse-target")
        calls = []
        established_reads = {5210: 0, 5211: 0}
        listening_reads = {}

        def fake_exec(ref, argv, timeout=None):
            calls.append((ref, argv))
            if argv[:2] == ["systemctl", "restart"]:
                return 0, ""
            match = re.search(r"state (established|listening).*:([0-9]+)", argv[2])
            self.assertIsNotNone(match, argv)
            state, port = match.group(1), int(match.group(2))
            if state == "established":
                established_reads[port] += 1
                if port == 5211:
                    if established_reads[port] == 1:
                        return 0, "ESTAB stale-client-1\nESTAB stale-client-2\n"
                    if established_reads[port] < 4:
                        return 0, "ESTAB restart-drain\n"
                return 0, ""
            listening_reads[port] = listening_reads.get(port, 0) + 1
            if listening_reads[port] == 1:
                return 0, ""
            return 0, f"LISTEN 0 4096 0.0.0.0:{port} 0.0.0.0:*"

        cluster._exec = fake_exec
        with mock.patch.object(soak.time, "sleep") as sleep:
            self.assertIsNone(cluster.prepare_iperf([5211, 5210]))

        self.assertEqual([argv for ref, argv in calls if argv[:2] == ["systemctl", "restart"]],
                         [["systemctl", "restart", "mouse-iperf3@5211.service"]])
        self.assertEqual(established_reads, {5210: 1, 5211: 4})
        self.assertEqual(listening_reads, {5211: 3})
        self.assertEqual(sleep.call_count, 2)
        self.assertTrue(all(ref == "loss:mouse-target" for ref, _ in calls))


    def test_prepare_iperf_rechecks_ready_port_until_all_are_clean_18631(self):
        cluster = soak.IncusCluster({0: "fw0", 1: "fw1"}, "lan", "loss:mouse-target")
        established_reads = {5210: 0, 5211: 0}
        listening_reads = {5210: 0, 5211: 0}

        def fake_exec(ref, argv, timeout=None):
            if argv[:2] == ["systemctl", "restart"]:
                return 0, ""
            match = re.search(r"state (established|listening).*:([0-9]+)", argv[2])
            self.assertIsNotNone(match, argv)
            state, port = match.group(1), int(match.group(2))
            if state == "established":
                established_reads[port] += 1
                if established_reads[port] == 1:
                    return 0, "ESTAB stale-before-restart"
                if port == 5210 and established_reads[port] == 3:
                    return 0, "ESTAB reconnected-after-listen"
                if port == 5211 and established_reads[port] == 2:
                    return 0, "ESTAB still-draining"
                return 0, ""
            listening_reads[port] += 1
            if port == 5211 and listening_reads[port] == 1:
                return 0, ""
            return 0, f"LISTEN 0 4096 0.0.0.0:{port} 0.0.0.0:*"

        cluster._exec = fake_exec
        self.assertIsNone(cluster.prepare_iperf([5210, 5211]))
        self.assertEqual(established_reads, {5210: 4, 5211: 4})
        self.assertEqual(listening_reads, {5210: 3, 5211: 3})

    def test_prepare_iperf_readiness_timeout_18631(self):
        cluster = soak.IncusCluster({0: "fw0", 1: "fw1"}, "lan", "loss:mouse-target")
        established_reads = 0
        listening_reads = 0

        def fake_exec(ref, argv, timeout=None):
            nonlocal established_reads, listening_reads
            if argv[:2] == ["systemctl", "restart"]:
                return 0, ""
            match = re.search(r"state (established|listening).*:([0-9]+)", argv[2])
            self.assertIsNotNone(match, argv)
            state = match.group(1)
            if state == "established":
                established_reads += 1
                return (0, "ESTAB stale-client") if established_reads == 1 else (0, "")
            listening_reads += 1
            return 0, ""

        cluster._exec = fake_exec
        with mock.patch.object(soak.time, "monotonic", side_effect=[0.0, 11.0]), \
                mock.patch.object(soak.time, "sleep") as sleep:
            error = cluster.prepare_iperf([5211], timeout=10.0)

        self.assertIn("timed out", error)
        self.assertIn("5211", error)
        self.assertEqual(established_reads, 2)
        self.assertEqual(listening_reads, 1)
        sleep.assert_not_called()

    def test_prepare_iperf_reports_restart_failure_without_polling_18631(self):
        cluster = soak.IncusCluster({0: "fw0", 1: "fw1"}, "lan", "loss:mouse-target")
        commands = []

        def fake_exec(ref, argv, timeout=None):
            commands.append(argv)
            if argv[:2] == ["systemctl", "restart"]:
                return 1, "unit restart failed"
            if "5211" in argv[2]:
                return 0, "ESTAB stale-client"
            return 0, ""

        cluster._exec = fake_exec
        error = cluster.prepare_iperf([5210, 5211])
        self.assertIn("mouse-iperf3@5211.service", error)
        self.assertIn("1 ESTABLISHED sockets", error)
        self.assertIn("unit restart failed", error)
        self.assertFalse(any("state listening" in " ".join(argv) for argv in commands))


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
        for m in res["moves"]:
            self.assertEqual(m["udp_probe"]["status"], "SURVIVED")
        self.assertEqual(len(c.udp_probe_session_queries), 12)
        for index, m in enumerate(res["moves"]):
            self.assertEqual(c.udp_probe_session_queries[index * 2:index * 2 + 2],
                             [m["target"], m["target"]])

    def test_untargeted_away_alternates_forms_and_passes_on_the_transfer_18559(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        rc, res, _ = run_fake(c, clock, moves=4, form=soak.FORM_UNTARGETED_AWAY)
        self.assertEqual(rc, 0, res["summary"])
        self.assertEqual([cmd for _, cmd in c.commands][:4], [
            "request chassis cluster failover redundancy-group 2",
            "request chassis cluster failover redundancy-group 2 node 0",
            "request chassis cluster failover redundancy-group 2",
            "request chassis cluster failover redundancy-group 2 node 0",
        ])
        self.assertTrue(all(m["udp_probe"]["status"] == "SURVIVED" for m in res["moves"]))

    def test_untargeted_local_resign_is_judged_and_udp_checkpoints_at_landing_18559(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, untargeted_reply="triggered")
        rc, res, _ = run_fake(c, clock, moves=4, form=soak.FORM_UNTARGETED_AWAY)
        self.assertEqual(rc, 0, res["summary"])
        away = [m for m in res["moves"] if m["target"] == 1]
        self.assertEqual([m["rgs"][0]["cli_class"] for m in away], [soak.CLI_TRIGGERED] * 2)
        self.assertTrue(all(m["udp_probe"]["status"] == "SURVIVED" for m in res["moves"]))
        self.assertEqual(res["summary"]["cli_classes"], {soak.CLI_TRIGGERED: 2, soak.CLI_OK: 2})

    def test_udp_checkpoint_is_taken_at_the_landing_not_the_cli_return_18559(self):
        # The probe is answered until the landing and never after. A
        # checkpoint at the landing sees the loss; one at the CLI return
        # would count the replies between return and landing as survival.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, untargeted_reply="triggered", faults={1: "udp-lost-at-landing"})
        rc, res, _ = run_fake(c, clock, moves=1, form=soak.FORM_UNTARGETED_AWAY)
        first = res["moves"][0]
        self.assertEqual(first["udp_probe"]["status"], "LOST", first["udp_probe"])
        self.assertEqual(first["verdict"], "FAIL")
        self.assertEqual(rc, 1)

    def test_fallback_away_move_is_void_not_pass_18559(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, untargeted_reply="fallback")
        rc, res, _ = run_fake(c, clock, moves=2, form=soak.FORM_UNTARGETED_AWAY)
        away, back = res["moves"][0], res["moves"][1]
        self.assertEqual(away["rgs"][0]["cli_class"], soak.CLI_FALLBACK)
        self.assertEqual(away["verdict"], "VOID")
        self.assertTrue(any("did not run the transfer" in r for r in away["reasons"]), away["reasons"])
        self.assertEqual(back["verdict"], "PASS")
        self.assertEqual(res["summary"]["cli_classes"], {soak.CLI_FALLBACK: 1, soak.CLI_OK: 1})
        self.assertEqual(rc, 2)

    def test_no_longer_primary_away_move_is_void_not_fail_18559(self):
        # The OK "no longer primary" reply (the group left by election while
        # the request ran) scores like the fallback: VOID "did not run the
        # transfer", never FAIL "unexpected CLI output", even when the build
        # is expected to run the transfer.
        for expect in (False, True):
            clock = FakeClock()
            c = FakeCluster(clock, {2: 0}, untargeted_reply="no-longer-primary")
            rc, res, _ = run_fake(c, clock, moves=2, form=soak.FORM_UNTARGETED_AWAY, expect_transfer=expect)
            away, back = res["moves"][0], res["moves"][1]
            self.assertEqual(away["rgs"][0]["cli_class"], soak.CLI_FALLBACK)
            self.assertEqual(away["verdict"], "VOID", away["reasons"])
            self.assertTrue(any("did not run the transfer" in r for r in away["reasons"]), away["reasons"])
            self.assertFalse(any("unexpected CLI output" in r for r in away["reasons"]), away["reasons"])
            self.assertEqual(back["verdict"], "PASS")
            self.assertEqual(rc, 2)

    def test_expect_transfer_fails_a_plain_local_resign_18559(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, untargeted_reply="triggered")
        rc, res, _ = run_fake(c, clock, moves=2, form=soak.FORM_UNTARGETED_AWAY, expect_transfer=True)
        self.assertEqual(res["moves"][0]["verdict"], "FAIL")
        self.assertTrue(any("SOAK_EXPECT_TRANSFER" in r for r in res["moves"][0]["reasons"]))
        self.assertEqual(rc, 1)

    def test_udp_session_identity_recreation_fails_even_with_stable_nat_tuple(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={1: "udp-recreated-after-landing"})
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 1)
        first = res["moves"][0]
        self.assertEqual(first["udp_probe"]["status"], "RECREATED")
        self.assertEqual(first["verdict"], "FAIL")
        self.assertIn("Session ID changed 71->84", first["udp_probe"]["detail"])
        self.assertEqual(res["moves"][1]["udp_probe"]["status"], "SURVIVED")
        self.assertEqual(c.udp_probe_identity_port, 41000)

    def test_udp_post_move_silence_fails_move(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={1: "udp-lost"})
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 1)
        first = res["moves"][0]
        self.assertEqual(first["udp_probe"]["status"], "LOST")
        self.assertEqual(first["verdict"], "FAIL")
        self.assertIn("received no replies", first["udp_probe"]["detail"])
        self.assertEqual(res["moves"][1]["udp_probe"]["status"], "SURVIVED")

    def test_udp_loss_before_second_rg_cannot_be_masked_by_later_recovery(self):
        clock = FakeClock()
        c = FakeCluster(clock, {1: 0, 2: 0}, faults={1: "udp-lost", 2: "udp-recover"})
        rc, res, _ = run_fake(c, clock, moves=1, rgs="1,2", sleep_s=1.0)
        self.assertEqual(rc, 1)
        probe = res["moves"][0]["udp_probe"]
        self.assertEqual([check["status"] for check in probe["windows"]], ["LOST", "SURVIVED"])
        self.assertEqual(probe["status"], "LOST")
        self.assertEqual(res["moves"][0]["verdict"], "FAIL")

    def test_udp_probe_start_failure_is_per_move_void_not_whole_run_preflight_void(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={1: "udp-start-fail"})
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertEqual(len(res["moves"]), 2)
        self.assertNotIn("void", res)
        self.assertTrue(all(m["udp_probe"]["status"] == "VOID" for m in res["moves"]))
        self.assertTrue(all(m["traffic"] and m["traffic"]["v4"] for m in res["moves"]))

    def test_missing_synced_standby_session_is_per_move_void(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={1: "udp-pre-session-missing"})
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertEqual(res["moves"][0]["udp_probe"]["status"], "VOID")
        self.assertIn("absent on synced standby node", res["moves"][0]["udp_probe"]["detail"])
        self.assertEqual(res["moves"][1]["udp_probe"]["status"], "SURVIVED")
        self.assertTrue(res["moves"][0]["traffic"]["v4"])

    def test_sender_restart_during_session_query_is_per_move_void(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, faults={1: "udp-restart-in-session-query"})
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        first = res["moves"][0]["udp_probe"]
        self.assertEqual(first["status"], "VOID")
        self.assertIn("sender identity changed during Session ID query", first["detail"])
        self.assertEqual(res["moves"][1]["udp_probe"]["status"], "SURVIVED")

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
        # A dual-active STATE starting 2 s after landing and lasting
        # DUAL_HOLD_S: only the rest-of-window sampling can see it (review:
        # "at any point").
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, dual_after_s=2.0)
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 1)
        self.assertIn("dual-active", " ".join(res["moves"][0]["reasons"]))

    def test_one_dual_sample_late_in_the_window_fails(self):
        # The pre-#19041 shape, kept as its own cell (#19041 review F1/F3):
        # ONE sample's two reads show both nodes primary 2 s after landing.
        # After landing nothing clears it.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        c.dual_reads_after_s = 2.0
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
        self.assertEqual(c.udp_probe_snapshot_count, 13,
                         "a failed/already CLI result must not start a post-transition probe window")
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

    def test_fault_after_one_rg_before_record_restores_and_records_result_18631(self):
        class VoidOnSecondHelperRead(FakeCluster):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.helper_reads = {0: 0, 1: 0}

            def helper(self, node):
                self.helper_reads[node] += 1
                if self.helper_reads[node] > 1:
                    raise soak.VoidRun("injected fault on second helpers read")
                return super().helper(node)

        clock = FakeClock()
        c = VoidOnSecondHelperRead(clock, {2: 0})
        rc, result, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("second helpers read", result["void"])
        self.assertEqual(result["moves"], [])
        self.assertEqual(c.owner[2], 0)
        self.assertIn("restored", result["preflight"]["restore"])
        self.assertEqual([cmd.rsplit(" ", 1)[-1] for _, cmd in c.commands], ["1", "0"])

    def test_restore_refreshes_owner_when_one_rg_cli_throws_after_change_18631(self):
        class ApplyThenVoid(FakeCluster):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.injected = False

            def cli(self, node, cmd):
                if not self.injected and cmd.endswith("node 1"):
                    self.injected = True
                    super().cli(node, cmd)
                    raise soak.VoidRun("injected fault after CLI changed owner")
                return super().cli(node, cmd)

        clock = FakeClock()
        c = ApplyThenVoid(clock, {2: 0})
        rc, result, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("CLI changed owner", result["void"])
        self.assertEqual(result["moves"], [])
        self.assertEqual(c.owner[2], 0)
        self.assertIn("restored", result["preflight"]["restore"])
        self.assertEqual([cmd.rsplit(" ", 1)[-1] for _, cmd in c.commands], ["1", "0"])


    def test_owner_change_without_one_rg_cli_still_restores_18631(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})

        def fail_after_owner_change(soak_run):
            soak_run.c.owner[2] = 1
            return "injected traffic-preflight failure after owner change"

        with mock.patch.object(soak.Soak, "traffic_preflight", fail_after_owner_change):
            rc, result, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("owner change", result["void"])
        self.assertEqual(result["moves"], [])
        self.assertEqual(c.owner[2], 0)
        self.assertIn("restored", result["preflight"]["restore"])
        self.assertEqual([cmd.rsplit(" ", 1)[-1] for _, cmd in c.commands], ["0"])

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

    def test_preflight_resets_stale_iperf_sockets_18631(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, stale_iperf_ports={5211: 88})
        rc, res, _ = run_fake(c, clock, moves=2, v6=True)
        self.assertEqual(rc, 0, res.get("void", res.get("summary")))
        self.assertEqual(set(c.mouse_target.checked_ports), {5210, 5211})
        self.assertEqual(c.mouse_target.restarted, [5211])
        self.assertNotIn(5211, c.mouse_target.established)
        self.assertIn(5211, c.mouse_target.listening)
        self.assertTrue(c.target_prepared_when_generators_started)
        self.assertEqual(res["summary"]["counts"]["PASS"], 2)

    def test_preflight_skips_v6_port_when_ipv6_is_disabled_18631(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, stale_iperf_ports={5210: 88})
        rc, res, _ = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 0, res.get("void", res.get("summary")))
        self.assertEqual(c.mouse_target.checked_ports, [5211])
        self.assertEqual(c.mouse_target.restarted, [])
        self.assertEqual(c.mouse_target.established, {5210: 88})

    def test_preflight_skips_external_split_v6_port_18631(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, stale_iperf_ports={5210: 88})
        rc, res, _ = run_fake(c, clock, moves=2, v6=True, managed_v6=False)
        self.assertEqual(rc, 0, res.get("void", res.get("summary")))
        self.assertEqual(c.mouse_target.checked_ports, [5211])
        self.assertEqual(c.mouse_target.restarted, [])
        self.assertEqual(c.mouse_target.established, {5210: 88})
        self.assertEqual(res["summary"]["counts"]["PASS"], 2)

    def test_preflight_voids_when_iperf_reset_fails_18631(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 1}, stale_iperf_ports={5211: 88}, iperf_reset_fail=True)
        rc, res, logs = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("iperf socket preflight", res["void"])
        self.assertIn("mouse-iperf3@5211.service", res["void"])
        self.assertIn("restart failure", res["void"])
        self.assertEqual(res["moves"], [])
        self.assertEqual(c.moves_seen, 0)
        self.assertIsNone(c.target_prepared_when_generators_started)
        self.assertEqual(c.files, {})
        self.assertTrue(any(line.startswith("FATAL:") for line in logs))
        self.assertEqual(c.owner[2], 1)
        self.assertEqual(c.commands, [])

    def test_unreadable_final_owner_does_not_trigger_restore_18631(self):
        class UnreadableOnce(FakeCluster):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.status_reads = {0: 0, 1: 0}

            def status(self, node):
                self.status_reads[node] += 1
                if node == 1 and self.status_reads[node] == 3:
                    return ""
                return super().status(node)

        clock = FakeClock()
        c = UnreadableOnce(clock, {2: 1}, stale_iperf_ports={5211: 88}, iperf_reset_fail=True)
        rc, result, logs = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("iperf socket preflight", result["void"])
        self.assertEqual(c.owner[2], 1)
        self.assertEqual(c.commands, [])
        self.assertNotIn("restore", result["preflight"])
        self.assertIn("owner unreadable", "\n".join(logs))
        self.assertEqual(c.status_reads, {0: 4, 1: 4})
        v0, v1 = soak.parse_status(c.status(0)), soak.parse_status(c.status(1))
        self.assertEqual(soak.rg_ownership(2, v0, v1).owner, 1)


    def test_unreadable_then_changed_owner_retries_and_restores_18631(self):
        class UnreadableThenChanged(FakeCluster):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.status_reads = {0: 0, 1: 0}

            def status(self, node):
                self.status_reads[node] += 1
                if node == 1 and self.status_reads[node] == 3:
                    self.owner[2] = 1
                    return ""
                return super().status(node)

        clock = FakeClock()
        c = UnreadableThenChanged(
            clock, {2: 0}, stale_iperf_ports={5211: 88}, iperf_reset_fail=True)
        rc, result, logs = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("iperf socket preflight", result["void"])
        self.assertEqual(result["moves"], [])
        self.assertEqual(c.owner[2], 0)
        self.assertIn("retrying before restore decision", "\n".join(logs))
        self.assertIn("restored", result["preflight"]["restore"])
        self.assertEqual([cmd.rsplit(" ", 1)[-1] for _, cmd in c.commands], ["0"])


    def test_known_change_survives_unknown_retry_for_another_rg_18631(self):
        class MultiRGReadSequence(FakeCluster):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.status_reads = {0: 0, 1: 0}

            def status(self, node):
                self.status_reads[node] += 1
                read = self.status_reads[node]
                if read == 3:
                    self.owner[2] = 1
                    return status_text({2: 1}, node)
                if read == 4:
                    return status_text({1: 0}, node)
                return super().status(node)

        clock = FakeClock()
        c = MultiRGReadSequence(
            clock, {1: 0, 2: 0}, stale_iperf_ports={5211: 88}, iperf_reset_fail=True)
        rc, result, logs = run_fake(c, clock, moves=2, rgs="1,2")
        self.assertEqual(rc, 2)
        self.assertIn("iperf socket preflight", result["void"])
        self.assertEqual(result["moves"], [])
        self.assertEqual(c.owner, {1: 0, 2: 0})
        self.assertIn("retrying before restore decision", "\n".join(logs))
        self.assertIn("restored", result["preflight"]["restore"])
        self.assertEqual(len(c.commands), 1)
        self.assertIn("failover redundancy-group 2 node 0", c.commands[0][1])


    def test_preflight_timeout_voids_without_moving_rg_18631(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 1}, stale_iperf_ports={5211: 88}, iperf_reset_timeout=True)
        rc, res, logs = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 2)
        self.assertIn("iperf socket preflight", res["void"])
        self.assertIn("timed out", res["void"])
        self.assertEqual(res["moves"], [])
        self.assertEqual(c.owner[2], 1)
        self.assertEqual(c.commands, [])
        self.assertEqual(c.moves_seen, 0)
        self.assertIsNone(c.target_prepared_when_generators_started)
        self.assertEqual(c.files, {})
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
            argv = ["--fw0", "a", "--fw1", "b", "--lan", "c", "--target4", "x", "--mouse-target", "fake:target",
                    "--outdir", d]
            orig = soak.IncusCluster
            soak.IncusCluster = lambda fw, lan, mouse_target: c
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


class _InlineFuture:
    def __init__(self, executor):
        self._executor = executor
        self._value = None
        self._exc = None

    def result(self, timeout=None):
        self._executor.run_pending()
        if self._exc is not None:
            raise self._exc
        return self._value


class InterleavingExecutor:
    """Stands in for `concurrent.futures.ThreadPoolExecutor` in Soak.views()
    and Soak.helpers(), and replays ONE thread interleaving of the pair of
    reads, deterministically and in the calling thread (#19041).

    The `first` read runs. With `steps` 1-3, after that many of its 0.05 s
    fake-clock steps the other read runs to completion, and then the first
    read finishes: a worker thread descheduled mid-read while its peer runs.
    With `steps` 0 the other read starts only after the first has returned:
    one worker running to completion before the other is scheduled. Each
    read sees its own instant, so in every shape a landing can fall between
    the two reads: the handoff straddle that production's parallel status
    commands can also read. Load produced these shapes at random. A read
    that never advances the clock, such as helper(), simply runs the other
    read afterwards."""

    def __init__(self, first, steps):
        self.first = first
        self.steps = steps
        self.pending = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.run_pending()
        return False

    def submit(self, fn, *args, **kwargs):
        future = _InlineFuture(self)
        self.pending.append((future, fn, args, kwargs))
        return future

    @staticmethod
    def _call(future, fn, args, kwargs):
        try:
            future._value = fn(*args, **kwargs)
        except BaseException as exc:  # re-raised by result()
            future._exc = exc

    def run_pending(self):
        batch, self.pending = self.pending, []
        if len(batch) != 2:
            for item in batch:
                self._call(*item)
            return
        a, b = batch if self.first == 0 else batch[::-1]
        clock = getattr(getattr(a[1], "__self__", None), "clock_", None)
        ran_b = []
        if clock is not None and self.steps:
            count = [0]

            def interleave(_t):
                count[0] += 1
                if count[0] == self.steps and not ran_b:
                    clock.listeners.remove(interleave)
                    ran_b.append(True)
                    self._call(*b)
            clock.listeners.append(interleave)
        try:
            self._call(*a)
        finally:
            if clock is not None and self.steps and not ran_b and interleave in clock.listeners:
                clock.listeners.remove(interleave)
        if not ran_b:
            self._call(*b)


def interleaving_schedule(schedule):
    """The executor factory for one schedule. Call j uses choice
    (schedule // 8**(j % 3)) % 8: which read starts first (choice % 2), and
    when the other read runs (choice // 2: after 1, 2 or 3 of the first
    read's clock steps, or 0 = after the first read returns). The overlapped
    shapes shift each later poll's fake-time phase; the sequential shape is
    the one that can straddle a landing."""
    uses = [0]

    def factory(max_workers=None):
        j = uses[0]
        uses[0] += 1
        choice = (schedule // 8 ** (j % 3)) % 8
        return InterleavingExecutor(first=choice % 2, steps=choice // 2)
    return factory


class DualActiveSampling19041(unittest.TestCase):
    """#19041: the soak used to read node0 and node1 in parallel during a
    move. A clean handoff could then be read as the old owner primary (just
    before) and the target primary (just after), with no real overlap, and
    the old scorer recorded that pair as a dual-active FAIL. Under load,
    that failed Orchestration cells at random. During a move the soak now
    reads the target first and the old owner second, an order that cannot
    straddle a clean handoff.

    The cited cells run unmodified under SCHEDULES deterministic
    interleavings of every remaining parallel read, against a fake whose
    reads are independent like production's."""

    CELLS = ("test_landing_bound_is_from_the_cli_return",
             # The three below exist on #18559's branch; included when present.
             "test_fallback_away_move_is_void_not_pass_18559",
             "test_untargeted_local_resign_is_judged_and_udp_checkpoints_at_landing_18559")
    SCHEDULES = 200

    def test_cited_cells_hold_under_every_interleaving(self):
        present = [name for name in self.CELLS if hasattr(Orchestration, name)]
        self.assertIn("test_landing_bound_is_from_the_cli_return", present)
        failures = []
        for schedule in range(self.SCHEDULES):
            with mock.patch.object(soak.concurrent.futures, "ThreadPoolExecutor",
                                   interleaving_schedule(schedule)):
                for name in present:
                    result = unittest.TestResult()
                    Orchestration(name).run(result)
                    for _, trace in result.failures + result.errors:
                        failures.append(f"schedule {schedule} {name}: {trace.strip().splitlines()[-1][:160]}")
        per_cell = {name: sum(f" {name}: " in f for f in failures) for name in present}
        print(f"\n#19041 stress: {self.SCHEDULES} schedules x {len(present)} cells: {len(failures)} failed "
              f"({', '.join(f'{name} {n}' for name, n in per_cell.items())})")
        self.assertEqual(failures, [], f"{len(failures)} of {self.SCHEDULES * len(present)} runs failed; "
                                       f"first: {failures[:3]}")

    def test_schedules_cover_both_orders_and_every_step(self):
        # A scorer that is right for only one read order, or for only one
        # overlap, cannot pass the stress cell.
        seen = set()
        for schedule in range(self.SCHEDULES):
            factory = interleaving_schedule(schedule)
            seen.update((ex.first, ex.steps) for ex in (factory() for _ in range(3)))
        self.assertEqual(seen, {(first, steps) for first in (0, 1) for steps in (0, 1, 2, 3)})

    def test_the_fake_reproduces_the_handoff_straddle(self):
        # Positive control: the fake must NOT hide the production hazard. A
        # landing inside the first read, with the other read after it,
        # yields a dual-active PAIR from a clean handoff.
        for first, primary_after in ((0, 1), (1, 0)):
            with self.subTest(first=first):
                clock = FakeClock()
                c = FakeCluster(clock, {2: 1 - primary_after})
                c.pending[2] = (primary_after, clock.t + 0.01)
                ex = InterleavingExecutor(first, steps=0)
                f0, f1 = ex.submit(c.status, 0), ex.submit(c.status, 1)
                v0, v1 = soak.parse_status(f0.result()), soak.parse_status(f1.result())
                self.assertTrue(soak.rg_ownership(2, v0, v1).dual_active)


class ScriptedIncus(soak.IncusCluster):
    """The REAL IncusCluster (its cli() and status() build the `incus exec
    <fw> -- cli -c ...` argv) with `_exec` answered from a script: per node,
    the owner map that node's successive status reads see, the last one
    repeating. A move CLI reports `transfer committed`."""

    def __init__(self, reads, clock=None, read_s=0.0):
        super().__init__({0: "fw0", 1: "fw1"}, "lan", "target")
        self.reads = {n: list(r) for n, r in reads.items()}
        self.status_reads = {0: 0, 1: 0}
        self.clock_, self.read_s = clock, read_s  # each status read spends read_s of fake time

    def _exec(self, ref, argv, timeout=None):
        node = {"fw0": 0, "fw1": 1}[ref]
        cmd = argv[-1]
        if cmd.startswith("request chassis cluster failover"):
            rg = int(re.search(r"redundancy-group (\d+)", cmd).group(1))
            return 0, f"Manual failover completed for redundancy group {rg} (transfer committed)\n"
        if cmd == "show chassis cluster status":
            seq = self.reads[node]
            owner = seq.pop(0) if len(seq) > 1 else seq[0]
            self.status_reads[node] += 1
            if self.clock_ is not None and self.read_s:
                self.clock_.sleep(self.read_s)
            if owner is None:
                return 0, ""  # an unreadable view
            if owner == "header":
                return 0, "Redundancy group: 2 , Failover count: 3\n"  # no node row, no Forwarding line
            if owner == "noforward":
                return 0, "\n".join(line for line in status_text({2: 1}, node).splitlines()
                                    if "Forwarding:" not in line) + "\n"
            if owner == "dup":
                return 0, status_text({2: 1}, node, dup=True)  # duplicate rows: unreadable
            if owner == "dual":
                return 0, status_text({2: node}, node)
            return 0, status_text({2: owner}, node)
        return 1, f"unexpected {argv!r}"


class HandoffCluster:
    """A clean break-before-make handoff between two status reads. After the
    move CLI, ownership moves from the old owner to the target in one step,
    once `flip_after` more status reads have been taken. Each read renders
    the state at that read (#19041)."""

    def __init__(self, owner, flip_after):
        self.owner = owner
        self.flip_after = flip_after
        self.pending = None
        self.reads_since_cli = 0
        self.order = []

    def cli(self, node, cmd):
        self.pending = int(cmd.rsplit(" ", 1)[1])
        self.reads_since_cli = 0
        if self.flip_after == 0:
            self.owner, self.pending = self.pending, None
        return 0, "Manual failover completed for redundancy group 2 (transfer committed)\n"

    def status(self, node):
        view = status_text({2: self.owner}, node)
        self.order.append(node)
        if self.pending is not None:
            self.reads_since_cli += 1
            if self.reads_since_cli >= self.flip_after:
                self.owner, self.pending = self.pending, None
        return view


def peer_forwarding_view(me, owner):
    """`me`'s view with NO Forwarding line under its own row, and one under
    the PEER's row (Codex P1's shape, #19041)."""
    lines = ["Cluster ID: 22", f"Node name: node{me}", "",
             "Node   Priority Status         Preempt  Manual   Monitor-failures", "",
             "Redundancy group: 2 , Failover count: 3"]
    for node in (0, 1):
        role = "primary" if owner == node else "secondary"
        lines.append(f"node{node}  {200 - 100 * node}      {role:<14} no       no       None")
        if node != me:
            lines.append("  Forwarding: rg-active=inactive vrrp-master=none")
    return "\n".join(lines) + "\n"


class ProbeIncus(ScriptedIncus):
    """ScriptedIncus plus the shapes the #19041 review seats used."""

    def _exec(self, ref, argv, timeout=None):
        node = {"fw0": 0, "fw1": 1}[ref]
        if argv[-1] == "show chassis cluster status":
            seq = self.reads[node]
            shape = seq[0]
            if shape == "div":  # R16 F2: secondary/inactive with a DIVERGENCE note
                seq.pop(0) if len(seq) > 1 else None
                self.status_reads[node] += 1
                return 0, status_text({2: 1 - node}, node,
                                      " -- DIVERGENCE: VRRP master on only some member interfaces")
            if shape == "peerfwd":  # Codex P1: own Forwarding line missing, the peer row's present
                seq.pop(0) if len(seq) > 1 else None
                self.status_reads[node] += 1
                return 0, peer_forwarding_view(node, 1 - node)
            if shape == "unknownfwd":  # Codex P2: an unknown Forwarding value
                seq.pop(0) if len(seq) > 1 else None
                self.status_reads[node] += 1
                return 0, status_text({2: node}, node).replace("rg-active=active", "rg-active=unknown")
        return super()._exec(ref, argv, timeout)


class DualActiveScoring19041(unittest.TestCase):
    """The soak's dual-active scoring through the real Soak.views(),
    IncusCluster.status(), one_rg() and watch_window() (#19041). During a
    move, the target is read first and the old owner second, and every
    dual-active sample FAILs."""

    def soak_for(self, cluster, clock, converge_s=5.0, **kw):
        cfg = soak.Config(traffic=False, helper_check=False, budget=soak.Budget(converge_s=converge_s))
        return soak.Soak(cfg, cluster, now_fn=clock.now, sleep_fn=clock.sleep, log=lambda *_: None, **kw)

    def one_rg(self, reads, target=1, converge_s=5.0, read_s=0.0, cluster_cls=ScriptedIncus):
        clock = FakeClock()
        c = cluster_cls(reads, clock, read_s)
        s = self.soak_for(c, clock, converge_s)
        pre = soak.Ownership(1 - target, False, "pre")
        res, _, _ = s.one_rg(2, target, pre)
        return res, c, s

    def verdict(self, res, converge_s=5.0):
        rec = soak.MoveRecord(1, res.target, 0, 0.0, 0.0, [res])
        return soak.move_verdict(rec, soak.Budget(converge_s=converge_s), traffic_enabled=False)

    # -- the read order ---------------------------------------------------

    def test_target_first_never_reads_a_clean_handoff_as_dual_and_old_first_does(self):
        # The ownership flips between the two reads of one sample. Read the
        # target first, and the sample shows the handoff in progress (nobody
        # owns it yet) or done. Read the old owner first (the order parallel
        # reads can take), and the same clean handoff shows both primary.
        for target in (1, 0):
            old = 1 - target
            for first, want_dual in ((target, False), (old, True)):
                with self.subTest(target=target, first=first):
                    clock = FakeClock()
                    c = HandoffCluster(owner=old, flip_after=1)
                    c.cli(old, f"request chassis cluster failover redundancy-group 2 node {target}")
                    s = self.soak_for(c, clock)
                    v0, v1 = s.views(first=first)
                    self.assertEqual(c.order, [first, 1 - first])
                    self.assertEqual(soak.rg_ownership(2, v0, v1).dual_active, want_dual)

    def test_a_move_reads_the_target_first_wherever_the_handoff_falls(self):
        # one_rg over a clean handoff landing after 0..7 reads, both
        # directions: never dual-active, always landed. The old parallel
        # reads, made old-first by the executor patch, show a dual sample
        # for some of these positions.
        for target in (1, 0):
            old = 1 - target
            for flip_after in range(8):
                with self.subTest(target=target, flip_after=flip_after):
                    clock = FakeClock()
                    c = HandoffCluster(owner=old, flip_after=flip_after)
                    s = self.soak_for(c, clock)
                    with mock.patch.object(soak.concurrent.futures, "ThreadPoolExecutor",
                                           lambda max_workers=None: InterleavingExecutor(first=old, steps=0)):
                        res, _, _ = s.one_rg(2, target, soak.Ownership(old, False, "pre"))
                    self.assertEqual((res.dual_active, res.dual_samples), (False, 0), res.dual_detail)
                    self.assertIsNotNone(res.landed_s)
                    self.assertEqual(c.order[0], target)  # every sample starts with the target
                    self.assertEqual(c.order[:2], [target, old])

    def test_the_window_reads_the_move_target_first(self):
        clock = FakeClock()
        c = HandoffCluster(owner=1, flip_after=0)
        s = self.soak_for(c, clock)
        s._owners = {}
        res = soak.RGMoveResult(2, 1, 0, "pre", soak.CLI_OK, "", 0, 0.5, 0.6, "", False)
        s.watch_window([res], s.now() + 0.5, first=1)
        self.assertEqual(c.order[:4], [1, 0, 1, 0])
        self.assertFalse(res.dual_active)

    # -- real overlaps still FAIL ------------------------------------------

    def test_overlapping_reads_of_a_real_dual_active_fail(self):
        res, _, _ = self.one_rg({0: ["dual", "dual", 1], 1: ["dual", "dual", 1]})
        self.assertTrue(res.dual_active)
        self.assertEqual(res.dual_samples, 2)
        verdict, why = self.verdict(res)
        self.assertEqual(verdict, soak.FAIL)
        self.assertTrue(any("both nodes claimed it in one sample" in w and "node1 read first" in w for w in why), why)

    def test_sustained_dual_active_fails_and_never_lands(self):
        res, _, _ = self.one_rg({0: ["dual"], 1: ["dual"]})
        self.assertTrue(res.dual_active)
        self.assertIsNone(res.landed_s)

    def test_old_owner_still_primary_after_the_target_claimed_fails(self):
        # The target (read first) claims the RG and the old owner (read
        # second) still claims it: a real overlap, such as a make-before-break
        # transfer whose old owner has not let go. It FAILs even when the
        # next sample is clean.
        res, _, _ = self.one_rg({0: [0, 1], 1: [1]})
        self.assertTrue(res.dual_active)
        self.assertEqual(self.verdict(res)[0], soak.FAIL)

    def test_review_probes_all_fail(self):
        # Every shape the #19041 review seats used against the re-sample
        # mechanism at 27c29482b4 starts with one dual-active sample. With
        # the mechanism removed, each is a FAIL, whatever the next reads say.
        probes = {
            "R16 F1: target no longer holds it next": {0: [0, 9, 1], 1: [1, 9, 1]},
            "R16 F2: old owner's DIVERGENCE note": {0: [0, "div", 1], 1: [1, 1, 1]},
            "Codex P1: peer row's Forwarding line": {0: [0, "peerfwd", 1], 1: [1, 1, 1]},
            "Codex P2: unknown Forwarding value": {0: [0, 1, 1], 1: [1, "unknownfwd", 1]},
            "Codex P2: overlap through the target's next read": {0: [0, 1, 1], 1: [1, 1, 1]},
            "R18 shape B: old owner still holding next": {0: [0, 0, 1], 1: [1, 0, 1]},
            "header-only next read": {0: [0, 1], 1: [1, "header", 1]},
            "duplicate-row next read": {0: [0, "dup", 1], 1: [1]},
        }
        for name, reads in probes.items():
            with self.subTest(probe=name):
                res, _, _ = self.one_rg(reads, cluster_cls=ProbeIncus)
                self.assertTrue(res.dual_active, res.last_detail)
                self.assertEqual(self.verdict(res)[0], soak.FAIL)

    def test_post_landing_dual_sample_is_dual_active_and_a_revert(self):
        # R16/R18 F1 and Codex P1 (#19041 review at f51ca9d0b2). After landing
        # no handoff is pending, so a window sample in which node0 claims the
        # RG while node1 holds it is dual-active, and also a revert.
        res, c, s = self.one_rg({0: [1, 1, 0, 1], 1: [1, 1, 1, 1]})
        self.assertIsNotNone(res.landed_s)
        s._owners = {}
        s.watch_window([res], s.now() + 0.5, first=1)
        self.assertTrue(res.dual_active)
        self.assertNotEqual(res.reverted, "")
        self.assertEqual(res.dual_samples, 1)
        verdict, why = self.verdict(res)
        self.assertEqual(verdict, soak.FAIL)
        self.assertTrue(any("dual-active" in w for w in why), why)
        self.assertTrue(any("left node1 after landing" in w for w in why), why)

    def test_post_landing_one_sample_overlap_fails(self):
        # R18 shape A: landed on node1, then ONE sample in which both nodes'
        # own views claim RG2, then clean.
        res, c, s = self.one_rg({0: [1, "dual", 1], 1: [1, "dual", 1]})
        s._owners = {}
        s.watch_window([res], s.now() + 0.5, first=1)
        self.assertTrue(res.dual_active)
        self.assertEqual(self.verdict(res)[0], soak.FAIL)

    # -- whose Forwarding line ---------------------------------------------

    def test_a_peer_rows_forwarding_line_does_not_speak_for_the_node(self):
        # Codex P1, parser part: node0's view has no Forwarding line under
        # its own row, only one under node1's. That is not node0's Forwarding
        # state, so node0 is not shown released and the move cannot land.
        v0 = soak.parse_status(peer_forwarding_view(0, 1))
        v1 = soak.parse_status(status_text({2: 1}, 1))
        self.assertEqual(v0[2].forwarding_node, 1)
        self.assertIsNone(soak.own_forwarding(v0[2], 0))
        self.assertFalse(soak.views_readable(2, v0, v1))
        own = soak.rg_ownership(2, v0, v1)
        self.assertIsNone(own.owner)
        self.assertIn("unreadable", own.detail)
        res, _, _ = self.one_rg({0: ["peerfwd"], 1: [1]}, cluster_cls=ProbeIncus)
        self.assertIsNone(res.landed_s)

    def test_an_unknown_forwarding_value_is_not_a_reading(self):
        # Codex P2: a value that is neither active nor inactive.
        v0 = soak.parse_status(status_text({2: 1}, 0))
        v1 = soak.parse_status(status_text({2: 1}, 1).replace("rg-active=active", "rg-active=unknown"))
        self.assertFalse(soak.views_readable(2, v0, v1))
        own = soak.rg_ownership(2, v0, v1)
        self.assertIsNone(own.owner)
        self.assertIn("unreadable", own.detail)
        self.assertTrue(soak.views_readable(2, v0, soak.parse_status(status_text({2: 1}, 1))))

    # -- the landing bound, on the monotonic clock --------------------------

    def test_landing_read_past_the_bound_fails(self):
        # A 1 s bound, reads that take time. The first sample to see the RG
        # landed finishes past the bound, so the move FAILs.
        res, _, _ = self.one_rg({0: [0, 0, 1], 1: [0, 0, 1]}, converge_s=1.0, read_s=0.15)
        self.assertIsNotNone(res.landed_s)
        self.assertGreater(res.landed_s - res.cli_seconds, 1.0)
        verdict, why = self.verdict(res, converge_s=1.0)
        self.assertEqual(verdict, soak.FAIL)
        self.assertTrue(any("past the 1s bound" in w for w in why), why)

    def test_landing_within_the_bound_passes(self):
        res, _, _ = self.one_rg({0: [0, 0, 1], 1: [0, 0, 1]}, converge_s=5.0, read_s=0.15)
        self.assertEqual(self.verdict(res, converge_s=5.0)[0], soak.PASS)

    def test_a_wall_clock_step_cannot_shrink_the_landing_time(self):
        # Codex P2: the wall clock steps back 1.5 s mid-move. Durations and
        # deadlines run on the monotonic clock, so the landing still reads
        # past the 1 s bound and the move FAILs.
        clock = FakeClock()
        start = clock.t

        def wall():
            return clock.now() - (1.5 if clock.t - start > 0.5 else 0.0)
        c = ScriptedIncus({0: [0, 0, 1], 1: [0, 0, 1]}, clock, 0.15)
        cfg = soak.Config(traffic=False, helper_check=False, budget=soak.Budget(converge_s=1.0))
        s = soak.Soak(cfg, c, now_fn=wall, sleep_fn=clock.sleep, log=lambda *_: None, mono_fn=clock.now)
        res, _, _ = s.one_rg(2, 1, soak.Ownership(0, False, "pre"))
        self.assertGreater(res.landed_s - res.cli_seconds, 1.0)
        self.assertEqual(self.verdict(res, converge_s=1.0)[0], soak.FAIL)


class DualSampleReporting19041(unittest.TestCase):
    """The dual-active sample count reaches the summary and the per-move
    console line (#19041)."""

    def test_dual_samples_are_counted_and_printed(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0}, dual_after_land=True)
        rc, res, logs = run_fake(c, clock, moves=2)
        self.assertEqual(rc, 1)
        n = sum(r["dual_samples"] for m in res["moves"] for r in m["rgs"])
        self.assertGreater(n, 0)
        self.assertEqual(res["summary"]["dual_samples"], n)
        self.assertIn("dual_samples=", "\n".join(logs))
        self.assertNotIn("dual_suspects_cleared", res["summary"])

    def test_a_clean_run_has_none(self):
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        rc, res, logs = run_fake(c, clock, moves=2)
        self.assertEqual(res["summary"]["dual_samples"], 0)
        self.assertNotIn("dual_samples=", "\n".join(logs))


class SlowCliCluster(FakeCluster):
    """Every move CLI takes `cli_extra_s` more fake seconds: moves slower
    than the pre-#19054 traffic estimate (sleep + converge + 4 s per move)."""

    cli_extra_s = 20.0

    def cli(self, node, cmd):
        self.clock_.sleep(self.cli_extra_s)
        return super().cli(node, cmd)


class TrafficCoverage19054(unittest.TestCase):
    """#19054: a move window the traffic generators did not cover is VOID,
    never PASS, COST or FAIL, and the default run length covers moves slower
    than the old estimate."""

    def uncovered(self, res):
        return [m for m in res["moves"]
                if any(not (t.get("ping_covered") and t.get("iperf_covered"))
                       for t in (m.get("traffic") or {}).values())]

    def test_no_uncovered_move_is_scored(self):
        # The traffic is told to run 12 s; the run needs about 3 x 6 s.
        clock = FakeClock()
        c = FakeCluster(clock, {2: 0})
        rc, res, _ = run_fake(c, clock, moves=3, traffic_s=12)
        gone = self.uncovered(res)
        self.assertTrue(gone, "the fixture must leave at least one window uncovered")
        for m in gone:
            self.assertEqual(m["verdict"], "VOID", m["reasons"])
            self.assertTrue(any("did not cover the move window" in r and "unscored" in r for r in m["reasons"]),
                            m["reasons"])
            self.assertTrue(any("planned end came before this window closed" in r for r in m["reasons"]),
                            m["reasons"])
        self.assertEqual(rc, 2)
        self.assertEqual(res["summary"]["counts"]["FAIL"], 0, res["summary"])

    def test_moves_slower_than_the_old_estimate_stay_covered(self):
        # 6 moves of ~26 s each: the pre-#19054 run length (6 x 14 + 60 =
        # 144 s) expires before the last window; the new default does not.
        clock = FakeClock()
        c = SlowCliCluster(clock, {2: 0})
        rc, res, _ = run_fake(c, clock, moves=6)
        self.assertEqual(self.uncovered(res), [])
        self.assertEqual(rc, 0, res["summary"])
        self.assertGreaterEqual(res["preflight"]["traffic_s"], 6 * soak.TRAFFIC_S_PER_MOVE_CAP)


class Rg1DualDuringRg2Landing(FakeCluster):
    """Codex's #19055 reproduction: after RG2's move CLI, each node's next
    status read claims RG1 too, so the first sample of RG2's landing poll
    reads RG1 primary on both nodes. RG1 already landed on node1."""

    def cli(self, node, cmd):
        out = super().cli(node, cmd)
        if "redundancy-group 2" in cmd:
            self.rg1_dual_next = {0, 1}
        return out

    def status(self, node):
        if node in getattr(self, "rg1_dual_next", set()):
            self.rg1_dual_next.discard(node)
            with self._status_lock:
                self._apply_time(self.clock_.t)
                view = status_text({**self.owner, 1: node}, node)
            self.clock_.sleep(self.STATUS_READ_S)
            return view
        return super().status(node)


class OtherRgsDuringLandingPoll19055(unittest.TestCase):
    """#19055: with several RGs moved per move, every landing-poll sample
    scores dual-active for every RG the run moves."""

    def test_an_earlier_rgs_dual_active_during_a_later_landing_poll_fails(self):
        clock = FakeClock()
        c = Rg1DualDuringRg2Landing(clock, {1: 0, 2: 0})
        rc, res, _ = run_fake(c, clock, moves=1, rgs="1,2")
        move = res["moves"][0]
        rg1 = [r for r in move["rgs"] if r["rg"] == 1][0]
        self.assertTrue(rg1["dual_active"], rg1)
        self.assertEqual(rg1["dual_samples"], 1)
        self.assertIn("during RG2's landing poll", rg1["dual_detail"])
        self.assertEqual(move["verdict"], "FAIL", move["reasons"])
        self.assertTrue(any(r.startswith("RG1 dual-active") for r in move["reasons"]), move["reasons"])
        self.assertEqual(rc, 1)

    def test_a_clean_two_rg_move_has_no_dual_sample(self):
        clock = FakeClock()
        c = FakeCluster(clock, {1: 0, 2: 0})
        rc, res, _ = run_fake(c, clock, moves=2, rgs="1,2")
        self.assertEqual(rc, 0, res["summary"])
        self.assertEqual(res["summary"]["dual_samples"], 0)

    def test_a_later_rgs_dual_active_seen_early_is_kept(self):
        # RG2 (moved second) claims both primaries during RG1's landing poll:
        # the reading waits for RG2's result.
        class Rg2DualDuringRg1(FakeCluster):
            def cli(self, node, cmd):
                out = super().cli(node, cmd)
                if "redundancy-group 1" in cmd:
                    self.rg2_dual_next = {0, 1}
                return out

            def status(self, node):
                if node in getattr(self, "rg2_dual_next", set()):
                    self.rg2_dual_next.discard(node)
                    with self._status_lock:
                        self._apply_time(self.clock_.t)
                        view = status_text({**self.owner, 2: node}, node)
                    self.clock_.sleep(self.STATUS_READ_S)
                    return view
                return super().status(node)
        clock = FakeClock()
        c = Rg2DualDuringRg1(clock, {1: 0, 2: 0})
        rc, res, _ = run_fake(c, clock, moves=1, rgs="1,2")
        rg2 = [r for r in res["moves"][0]["rgs"] if r["rg"] == 2][0]
        self.assertTrue(rg2["dual_active"], rg2)
        self.assertIn("during RG1's landing poll", rg2["dual_detail"])
        self.assertEqual(rc, 1)


class LateGapCluster(FakeCluster):
    """Codex's #19056 reproduction. The move's traffic has a 1.51 s outage
    (ping and every stream) late in the window, and the controller's wall
    clock steps back 3 s one second after the move CLI returns. The LAN
    host's clock does not step."""

    def cli(self, node, cmd):
        out = super().cli(node, cmd)
        lan_now = self.clock_.t + self.lan_off
        self.events.append((lan_now + 3.4, lan_now + 4.91, "gap"))
        self.step_at = self.clock_.t + 1.0
        return out


class WallClockStep19056(unittest.TestCase):
    """#19056: traffic windows are anchored on the monotonic clock."""

    def run_step(self, step_s):
        clock = FakeClock()
        c = LateGapCluster(clock, {2: 0})

        def wall():
            stepped = getattr(c, "step_at", None) is not None and clock.t >= c.step_at
            return clock.now() - (step_s if stepped else 0.0)
        return run_fake(c, clock, moves=1, now_fn=wall)

    def test_a_backward_wall_step_cannot_hide_a_late_outage(self):
        rc, res, _ = self.run_step(3.0)
        move = res["moves"][0]
        self.assertEqual(move["verdict"], "FAIL", move["reasons"])
        self.assertTrue(any("ping gap" in r for r in move["reasons"]), move["reasons"])
        self.assertTrue(any("aggregate outage" in r for r in move["reasons"]), move["reasons"])
        self.assertEqual(rc, 1)

    def test_control_without_a_step_also_fails(self):
        rc, res, _ = self.run_step(0.0)
        self.assertEqual(res["moves"][0]["verdict"], "FAIL")

    def test_lan_time_maps_the_monotonic_clock_through_the_anchor(self):
        # In production the monotonic clock is nowhere near the wall clock.
        # A monotonic moment must still land at wall time + LAN offset.
        clock = FakeClock()
        s = soak.Soak(soak.Config(), None, now_fn=clock.now, sleep_fn=clock.sleep,
                      log=lambda *_: None, mono_fn=lambda: clock.t + 1000.0)
        s._anchor = (s.now(), s.wall())
        s.lan_offset = 3.0
        clock.sleep(2.0)
        self.assertAlmostEqual(s.lan_time(s.now()), clock.t + 3.0, places=2)


if __name__ == "__main__":
    unittest.main()
