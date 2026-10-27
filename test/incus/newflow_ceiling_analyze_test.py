"""Tests for the #4800 new-flow-ceiling attribution layer.

Two properties carry the value and are asserted hardest:

1. **The classifier must be able to name MORE THAN ONE culprit.** The
   interesting real-world answer to #4800 is "publish and replicate saturate
   before NAT does". A classifier that reports a single winner would let a
   reader conclude "publish is the bottleneck, shard publish" and miss that
   sharding the NAT allocator alone (#2852 Phase 2) was never going to help.

2. **A quiet run must name NOTHING.** The negative control: a snapshot pair
   where every ratio is below threshold must come back VALID with an empty
   culprit list, not with the least-cold site nominated by default.

The validity gates get their own tests because a harness that cannot fail is
worse than none: a run with no pool allocations, a restarted helper, a
backwards counter, an exhausted pool, an under-driving generator or traffic
landing on one RX queue must each be refused rather than reported as a
number.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from newflow_ceiling_analyze import (  # noqa: E402
    INCONCLUSIVE,
    INVALID,
    VALID,
    SnapshotError,
    analyze,
    parse_prometheus_text,
)


def snap(
    t,
    *,
    allocations=0,
    exhaustion=0,
    nat_acq=0,
    nat_blocked=0,
    shard_acq=None,
    shard_blocked=None,
    write_acq=None,
    write_blocked=None,
    pub_calls=0,
    pub_acq=0,
    pub_blocked=0,
    rep_upserts=0,
    rep_enqueued=0,
    rep_blocked=0,
    rep_depth_sum=0,
    rep_depth=0,
    es_acq=0,
    es_blocked=0,
    workers=None,
    helper_pid=4242,
):
    return {
        "t": t,
        "helper_pid": helper_pid,
        "pool": {
            "allocations_total": allocations,
            "exhaustion_total": exhaustion,
            "flow_shard_lock_acquisitions_total": nat_acq // 2 if shard_acq is None else shard_acq,
            "flow_shard_lock_contended_total": nat_blocked // 2 if shard_blocked is None else shard_blocked,
            "live_write_lock_acquisitions_total": nat_acq - nat_acq // 2 if write_acq is None else write_acq,
            "live_write_lock_contended_total": nat_blocked - nat_blocked // 2 if write_blocked is None else write_blocked,
            "live_lock_acquisitions_total": nat_acq,
            "live_lock_contended_total": nat_blocked,
        },
        "publish": {
            "publishes_total": pub_calls,
            "lock_acquisitions_total": pub_acq,
            "lock_contended_total": pub_blocked,
        },
        "replicate": {
            "upserts_total": rep_upserts,
            "enqueued_total": rep_enqueued,
            "lock_contended_total": rep_blocked,
            "queue_depth_sum": rep_depth_sum,
            "queue_depth_max": rep_depth,
        },
        # #9169 site 4: the event-stream producer-seq lock pair.
        "event_stream": {
            "lock_acquisitions_total": es_acq,
            "lock_contended_total": es_blocked,
        },
        "workers": workers if workers is not None else {},
    }


def six_even_workers(total):
    """Six workers sharing `total` installs evenly — the loss cluster's 6 RX
    queues, distributed as a healthy multi-worker run would be.

    The remainder is spread over the first `total % 6` workers so the six
    counters sum to EXACTLY `total`. Truncating it (`total // 6` for all six)
    lost up to 5 installs, which was invisible while the reported rate came
    from `pool.allocations_total` and became a real 0.199998-vs-0.2 discrepancy
    once the rate started deriving from these counters. A per-worker fixture
    that does not add up to its own stated total cannot express an exact
    accept-ratio, and real per-worker counters do add up."""
    per, extra = divmod(total, 6)
    return {str(i): per + (1 if i < extra else 0) for i in range(6)}


class AttributionNamesEverySaturatedSite(unittest.TestCase):
    def test_publish_and_replicate_both_named_when_both_saturate(self):
        """The load-bearing case for #4800.

        NAT stays cold (1% blocked), publish runs hot (40%), replication runs
        hotter (60%). A single-winner classifier would report only
        replication and a reader would shard the wrong thing; both must be
        named, replication first.
        """
        before = snap(
            0.0,
            allocations=0,
            nat_acq=0,
            nat_blocked=0,
            pub_acq=0,
            pub_blocked=0,
            rep_enqueued=0,
            rep_blocked=0,
            rep_upserts=0,
            workers=six_even_workers(0),
        )
        after = snap(
            10.0,
            allocations=600_000,
            nat_acq=1_200_000,
            nat_blocked=12_000,  # 1.0%
            pub_acq=1_800_000,
            pub_blocked=720_000,  # 40%
            rep_upserts=600_000,
            rep_enqueued=3_600_000,
            rep_blocked=2_160_000,  # 60%
            rep_depth=8,
            workers=six_even_workers(600_000),
        )
        a = analyze(before, after)

        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertEqual(a.new_flows_per_sec, 60_000.0)
        self.assertTrue(a.saturated)
        # BOTH, not one.
        self.assertIn("publish_shared_session", a.culprits)
        self.assertIn("replicate_session_upsert", a.culprits)
        # And NAT must not be swept in with them — that is the whole #2852
        # Phase-2 question.
        self.assertNotIn("nat_allocator_flow_shard", a.culprits)
        # Ratio-descending, so the reader sees the worse one first.
        self.assertEqual(
            a.culprits[:2], ["replicate_session_upsert", "publish_shared_session"]
        )

    def test_cold_sites_are_still_reported_with_their_ratios(self):
        """A site that did not saturate must still appear in the table.

        Omitting cold sites would make "NAT never blocked" indistinguishable
        from "NAT was not measured", which is exactly the distinction the
        Phase-2 decision needs.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=600_000,
                nat_acq=1_200_000,
                nat_blocked=12_000,
                pub_acq=1_800_000,
                pub_blocked=720_000,
                rep_upserts=600_000,
                rep_enqueued=3_600_000,
                rep_blocked=2_160_000,
                es_acq=1_200_000,
                es_blocked=6_000,
                workers=six_even_workers(600_000),
            ),
        )
        names = [s.name for s in a.sites]
        self.assertEqual(
            names,
            [
                "nat_allocator_flow_shard",
                "nat_allocator_live_write",
                "publish_shared_session",
                "replicate_session_upsert",
                # #9169: the fourth site. The claim this cell makes — a cold
                # site stays in the table with its ratio, so "never blocked" is
                # evidenced rather than inferred from an omission — is
                # unchanged; the table it holds the analyzer to is not.
                "event_stream_producer_seq",
            ],
        )
        es = next(s for s in a.sites if s.name == "event_stream_producer_seq")
        self.assertAlmostEqual(es.ratio, 0.005)
        self.assertFalse(es.saturated)
        nat = next(s for s in a.sites if s.name == "nat_allocator_flow_shard")
        self.assertAlmostEqual(nat.ratio, 0.01)
        self.assertFalse(nat.saturated)

    def test_event_stream_producer_seq_is_named_when_it_alone_saturates(self):
        """#9169 — THE cell this issue exists for.

        Before #9169 the model had three sites and the event-stream producer
        lock was not one of them. A run bound by that mutex would therefore
        produce the worst possible output: a new-flows/sec plateau with every
        named site COLD, which reads as "the firewall is not lock-bound" and
        sends the next person to look somewhere else. That is a counterfactual
        about the instrument, not a measurement -- which is exactly why this
        cell drives the shape synthetically.

        So this cell drives exactly that shape — the three original sites quiet
        (<= 0.1% blocked), site 4 hot (30%) — and asserts the analyzer names
        it, and names ONLY it. The three quiet sites are the control: a fourth
        row that fired on any loaded run would carry no information.

        FAIL-ON-REVERT: drop the `event_stream_producer_seq` row from
        `LOCK_SITES` and `culprits` comes back empty, which is the pre-#9169
        answer.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=300_000,
                nat_acq=600_000,
                nat_blocked=600,  # 0.1%
                pub_acq=900_000,
                pub_blocked=450,  # 0.05%
                rep_upserts=300_000,
                rep_enqueued=1_800_000,
                rep_blocked=1_800,  # 0.1%
                es_acq=600_000,
                es_blocked=180_000,  # 30%
                workers=six_even_workers(300_000),
            ),
        )
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertTrue(a.saturated)
        self.assertEqual(a.culprits, ["event_stream_producer_seq"])
        es = next(s for s in a.sites if s.name == "event_stream_producer_seq")
        self.assertAlmostEqual(es.ratio, 0.3)
        self.assertTrue(es.saturated)

    def test_a_helper_without_the_site_4_counters_raises_not_scores_clean(self):
        """A build that predates #9169 must REFUSE, not report a quiet site 4.

        `_scalar` raises on an absent series, and that is the whole defence
        here: scoring a missing counter as zero would give the fourth site a
        `contended = 0` over an `acquisitions = 0` denominator — reported as
        `ratio: None`, "never taken" — for a run in which it was taken on every
        single delta. The instrument would look present and say nothing.
        """
        before = snap(0.0, workers=six_even_workers(0))
        after = snap(
            10.0,
            allocations=1_000,
            nat_acq=2_000,
            es_acq=2_000,
            es_blocked=1_000,
            workers=six_even_workers(1_000),
        )
        del after["event_stream"]["lock_contended_total"]
        with self.assertRaises(SnapshotError):
            analyze(before, after)

    def test_all_three_can_be_named_together(self):
        """Nothing structurally caps the culprit list at two."""
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=100_000,
                nat_acq=200_000,
                nat_blocked=100_000,
                pub_acq=300_000,
                pub_blocked=150_000,
                rep_upserts=100_000,
                rep_enqueued=600_000,
                rep_blocked=300_000,
                workers=six_even_workers(100_000),
            ),
        )
        self.assertEqual(
            sorted(a.culprits),
            sorted(
                [
                    "nat_allocator_flow_shard",
                    "nat_allocator_live_write",
                    "publish_shared_session",
                    "replicate_session_upsert",
                ]
            ),
        )

    def test_shard_saturation_is_not_masked_by_cold_live_write_17036(self):
        """#17036: the split domains must vote separately.

        Shard domain saturates (50%) while live-write stays cold; the
        summed legacy pair would dilute the shard ratio. Only the
        shard site may be named. RED on revert to the summed site:
        the legacy ratio is 25% over the combined denominator only if
        both domains are summed — with a colder write domain it drops
        below naming the true culprit, and the site name is wrong.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=100_000,
                shard_acq=200_000,
                shard_blocked=100_000,
                write_acq=800_000,
                write_blocked=0,
                nat_acq=1_000_000,
                nat_blocked=100_000,
                workers=six_even_workers(100_000),
            ),
        )
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertIn("nat_allocator_flow_shard", a.culprits)
        self.assertNotIn("nat_allocator_live_write", a.culprits)
        self.assertNotIn("nat_allocator_live_mutex", a.culprits)


class NegativeControl(unittest.TestCase):
    def test_nothing_saturated_names_no_culprit(self):
        """A healthy, unsaturated run must nominate nobody.

        Every site is exercised heavily but blocks on well under 1% of
        acquisitions. If this named a culprit, every run would produce one and
        the attribution would carry no information.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                30.0,
                allocations=300_000,
                nat_acq=600_000,
                nat_blocked=600,  # 0.1%
                pub_acq=900_000,
                pub_blocked=450,  # 0.05%
                rep_upserts=300_000,
                rep_enqueued=1_800_000,
                rep_blocked=1_800,  # 0.1%
                rep_depth=3,
                es_acq=600_000,
                es_blocked=300,  # 0.05% — #9169 site 4, exercised and quiet
                workers=six_even_workers(300_000),
            ),
        )
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertEqual(a.culprits, [])
        self.assertFalse(a.saturated)
        self.assertEqual(a.new_flows_per_sec, 10_000.0)
        # ...and it still reports the real ratios, so "quiet" is evidenced
        # rather than merely asserted.
        for s in a.sites:
            self.assertIsNotNone(s.ratio)
            self.assertLess(s.ratio, 0.01)

    def test_untouched_site_reports_none_not_zero(self):
        """A site with zero acquisitions has NO ratio.

        Scoring it 0.0 would read as "measured, never blocked" — a positive
        finding about a site that was never on the path at all.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=1_000,
                nat_acq=2_000,
                nat_blocked=0,
                pub_acq=0,
                pub_blocked=0,
                rep_upserts=0,
                rep_enqueued=0,
                rep_blocked=0,
                workers=six_even_workers(1_000),
            ),
        )
        pub = next(s for s in a.sites if s.name == "publish_shared_session")
        self.assertIsNone(pub.ratio)
        self.assertFalse(pub.saturated)


class QueueDepthIsItsOwnFinding(unittest.TestCase):
    def test_backlogged_queue_is_named_even_when_the_mutex_is_cold(self):
        """Depth and contention are different failures.

        Producers never collide (0 blocked enqueues) but the consuming worker
        is ~4000 commands behind on average. Reporting only the mutex ratio
        would call this run clean.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=200_000,
                nat_acq=400_000,
                nat_blocked=40,
                pub_acq=600_000,
                pub_blocked=60,
                rep_upserts=200_000,
                rep_enqueued=1_200_000,
                rep_blocked=0,
                # 200k replications averaging depth 4000.
                rep_depth_sum=800_000_000,
                rep_depth=4_000,
                workers=six_even_workers(200_000),
            ),
        )
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertIn("replicate_session_upsert_queue_backlog", a.culprits)
        self.assertNotIn("replicate_session_upsert", a.culprits)
        self.assertAlmostEqual(a.replication_queue_depth_mean, 4_000.0)

    def test_shallow_queue_is_not_a_backlog(self):
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=200_000,
                nat_acq=400_000,
                nat_blocked=40,
                pub_acq=600_000,
                pub_blocked=60,
                rep_upserts=200_000,
                rep_enqueued=1_200_000,
                rep_blocked=0,
                rep_depth_sum=1_200_000,  # mean depth 6
                rep_depth=6,
                workers=six_even_workers(200_000),
            ),
        )
        self.assertEqual(a.culprits, [])

    def test_stale_lifetime_high_water_cannot_manufacture_a_backlog(self):
        """THE regression this class exists for.

        `..._queue_depth_max` is a process-lifetime `fetch_max`: it never
        falls. An earlier cell (or an earlier test run in the same helper
        process) that spiked to 50k leaves it pinned at 50k forever. Reading
        that absolute value as a window reading made EVERY subsequent cell
        report a replication backlog — and it poisoned them by naming the
        replication queue, which is precisely the site the #2852 Phase-2
        decision turns on. A systematic bias toward the wrong answer, wearing
        a VALID verdict.

        Here the lifetime max is already 50_000 at window START and does not
        move; depth SUM is flat, so the true mean depth this window is ~0.

        RED on revert: keying the backlog off `replication_queue_depth_max`
        again fails the assertNotIn on its message.
        """
        already_high = 50_000
        a = analyze(
            snap(
                0.0,
                rep_depth_sum=0,
                rep_depth=already_high,
                workers=six_even_workers(0),
            ),
            snap(
                10.0,
                allocations=200_000,
                nat_acq=400_000,
                nat_blocked=40,
                pub_acq=600_000,
                pub_blocked=60,
                rep_upserts=200_000,
                rep_enqueued=1_200_000,
                rep_blocked=0,
                # Depth summed to 200_000 over 200_000 replications: a mean
                # of 1.0, i.e. the consumer kept up perfectly.
                rep_depth_sum=200_000,
                rep_depth=already_high,  # unchanged — no new record
                workers=six_even_workers(200_000),
            ),
        )
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertNotIn(
            "replicate_session_upsert_queue_backlog",
            a.culprits,
            "a stale process-lifetime high-water must not name a culprit for a "
            "window in which the queue never backed up",
        )
        self.assertEqual(a.culprits, [])
        self.assertAlmostEqual(a.replication_queue_depth_mean, 1.0)
        # The lifetime value is still REPORTED — operators want it — it just
        # cannot vote. And this window set no new record.
        self.assertEqual(a.replication_queue_depth_max_lifetime, already_high)
        self.assertFalse(a.replication_queue_depth_new_record)

    def test_new_record_is_reported_as_context_but_still_does_not_vote(self):
        """A new all-time high with a healthy MEAN is not a backlog.

        One transient spike in an otherwise-drained window is exactly the
        thing a peak would over-report and a mean correctly does not.
        """
        a = analyze(
            snap(0.0, rep_depth=100, rep_depth_sum=0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=200_000,
                nat_acq=400_000,
                pub_acq=600_000,
                rep_upserts=200_000,
                rep_enqueued=1_200_000,
                rep_depth_sum=400_000,  # mean 2.0 — drained fine
                rep_depth=9_999,  # one spike set a new all-time high
                workers=six_even_workers(200_000),
            ),
        )
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertTrue(a.replication_queue_depth_new_record)
        self.assertEqual(a.replication_queue_depth_max_lifetime, 9_999)
        self.assertEqual(a.culprits, [])

    def test_fanout_multiplier_is_recovered_from_the_counter_pair(self):
        """On an all-live run, enqueued/upserts reproduces sibling count.

        In general the ratio is the live-sibling count because dead-worker
        legs are excluded. Six live workers must read back as 6.0.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=100_000,
                nat_acq=200_000,
                pub_acq=300_000,
                rep_upserts=100_000,
                rep_enqueued=600_000,
                workers=six_even_workers(100_000),
            ),
        )
        self.assertAlmostEqual(a.replication_fanout, 6.0)


class ValidityGates(unittest.TestCase):
    def test_no_pool_allocations_is_invalid_not_a_rate_of_zero(self):
        """The SNAT-rule-not-in-effect gate.

        Without this, a run where the pool-mode rule failed to commit reports
        "0 new flows/sec, nothing saturated" — a clean-looking result for a
        run that measured nothing at all.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(30.0, allocations=0, workers=six_even_workers(0)),
        )
        self.assertEqual(a.verdict, INVALID)
        self.assertEqual(a.new_flows_per_sec, 0.0)
        self.assertTrue(any("zero pool-mode SNAT allocations" in r for r in a.reasons))

    def test_helper_restart_is_invalid(self):
        a = analyze(
            snap(0.0, helper_pid=100, workers=six_even_workers(0)),
            snap(
                10.0,
                helper_pid=200,
                allocations=500_000,
                nat_acq=1_000_000,
                workers=six_even_workers(500_000),
            ),
        )
        self.assertEqual(a.verdict, INVALID)
        self.assertTrue(any("helper restarted" in r for r in a.reasons))

    def test_counter_regression_is_invalid(self):
        """A backwards counter is caught even when the pid did NOT change.

        Same pid on both sides, so the restart comparison passes cleanly and
        the monotonicity check is unambiguously what fires — the belt behind
        the pid check, for a restart that reused a pid or a scrape that
        crossed processes some other way.
        """
        before = snap(
            0.0, helper_pid=777, allocations=900_000, nat_acq=2_000_000,
            workers=six_even_workers(0),
        )
        after = snap(
            10.0, helper_pid=777, allocations=1_000, nat_acq=2_000,
            workers=six_even_workers(1_000),
        )
        a = analyze(before, after)
        self.assertEqual(a.verdict, INVALID)
        self.assertTrue(any("went backwards" in r for r in a.reasons), a.reasons)

    def test_non_positive_window_is_invalid(self):
        a = analyze(
            snap(10.0, allocations=0, workers=six_even_workers(0)),
            snap(10.0, allocations=500_000, workers=six_even_workers(500_000)),
        )
        self.assertEqual(a.verdict, INVALID)

    def test_short_window_is_invalid(self):
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                1.0,
                allocations=50_000,
                nat_acq=100_000,
                pub_acq=150_000,
                rep_upserts=50_000,
                rep_enqueued=300_000,
                workers=six_even_workers(50_000),
            ),
        )
        self.assertEqual(a.verdict, INVALID)
        self.assertTrue(any("below the" in r for r in a.reasons))

    def test_pool_exhaustion_is_inconclusive_not_a_lock_ceiling(self):
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=600_000,
                exhaustion=12_345,
                nat_acq=1_200_000,
                nat_blocked=600_000,
                pub_acq=1_800_000,
                rep_upserts=600_000,
                rep_enqueued=3_600_000,
                workers=six_even_workers(600_000),
            ),
        )
        self.assertEqual(a.verdict, INCONCLUSIVE)
        self.assertTrue(any("exhaustion" in r for r in a.reasons))

    def test_generator_underdrive_is_inconclusive(self):
        """Accepting 20k/s of an offered 100k/s means something upstream of
        the firewall bound first."""
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=200_000,
                nat_acq=400_000,
                pub_acq=600_000,
                rep_upserts=200_000,
                rep_enqueued=1_200_000,
                workers=six_even_workers(200_000),
            ),
            offered_flows_per_sec=100_000.0,
        )
        self.assertEqual(a.verdict, INCONCLUSIVE)
        self.assertAlmostEqual(a.accept_ratio, 0.2)
        self.assertTrue(any("bound first" in r for r in a.reasons))

    def test_rate_is_installed_flows_not_pool_allocations(self):
        """The reported rate must be INSTALLED flows, not pool allocations.

        A pool allocation is taken before pair admission and a refusal rolls it
        back without decrementing the cumulative counter, so under overload the
        allocation delta counts attempts. This fixture is that overload: 100k
        allocations over 10s but only 10k installs, i.e. 90% refused.

        The two numbers must not be confusable, so they are an order of
        magnitude apart. Reading allocations would report 10000/s — ten times
        the flows the firewall actually installed, and a "ceiling" ten times
        too high in exactly the regime this harness is pointed at.

        RED on revert: restore `result.new_flows_per_sec = allocations /
        elapsed` and this fails at 10000.0 != 1000.0.
        """
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=100_000,
                nat_acq=200_000,
                pub_acq=30_000,
                rep_upserts=10_000,
                rep_enqueued=60_000,
                workers=six_even_workers(10_000),
            ),
            offered_flows_per_sec=10_000.0,
        )
        self.assertAlmostEqual(
            a.new_flows_per_sec,
            1_000.0,
            msg="the rate must come from the summed per-worker new_flow_installs "
            "(10k installs / 10s), not from pool.allocations_total (100k/10s)",
        )
        # ...and the accept ratio inherits the corrected numerator, so a run
        # that refuses 90% of what it was offered is not scored as accepting it.
        self.assertAlmostEqual(a.accept_ratio, 0.1)

    def test_generator_at_rate_is_valid(self):
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            snap(
                10.0,
                allocations=1_000_000,
                nat_acq=2_000_000,
                pub_acq=3_000_000,
                rep_upserts=1_000_000,
                rep_enqueued=6_000_000,
                workers=six_even_workers(1_000_000),
            ),
            offered_flows_per_sec=100_000.0,
        )
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertAlmostEqual(a.accept_ratio, 1.0)

    def test_single_rx_queue_is_inconclusive(self):
        """One worker carrying everything is a core ceiling, not a lock one.

        Without this gate a run steered onto a single RX queue would report a
        high replication contention ratio and read as a cross-worker lock
        bound — the exact mis-attribution #4800 must avoid.
        """
        a = analyze(
            snap(0.0, workers={str(i): 0 for i in range(6)}),
            snap(
                10.0,
                allocations=100_000,
                nat_acq=200_000,
                nat_blocked=100_000,
                pub_acq=300_000,
                pub_blocked=150_000,
                rep_upserts=100_000,
                rep_enqueued=600_000,
                rep_blocked=300_000,
                workers={"0": 100_000, "1": 0, "2": 0, "3": 0, "4": 0, "5": 0},
            ),
        )
        self.assertEqual(a.verdict, INCONCLUSIVE)
        self.assertEqual(a.active_workers, 1)
        self.assertTrue(any("RSS-distribution-limited" in r for r in a.reasons))

    def test_worker_skew_is_inconclusive_even_when_all_workers_are_active(self):
        """Three active workers passes the count gate; 80% on one does not
        pass the share gate."""
        a = analyze(
            snap(0.0, workers={str(i): 0 for i in range(6)}),
            snap(
                10.0,
                allocations=100_000,
                nat_acq=200_000,
                pub_acq=300_000,
                rep_upserts=100_000,
                rep_enqueued=600_000,
                workers={"0": 80_000, "1": 10_000, "2": 10_000, "3": 0, "4": 0, "5": 0},
            ),
        )
        self.assertEqual(a.verdict, INCONCLUSIVE)
        self.assertAlmostEqual(a.max_worker_share, 0.8)
        self.assertTrue(any("single-worker-bound" in r for r in a.reasons))

    def test_zero_offered_rate_is_invalid_not_an_unratioed_pass(self):
        """A broken generator must not yield a firewall number.

        The shell derived the offered rate from `generator.json`; an
        unparseable report arrived here as `--offered-rate 0`. Zero is falsy,
        so `accept_ratio` stayed None, and the generator-bound INCONCLUSIVE
        check tests `accept_ratio is not None` — so the check that exists to
        catch a broken generator was DISABLED BY THE BROKEN GENERATOR, and
        the cell came back VALID.

        RED on revert: restoring the falsy `if offered_flows_per_sec:` guard
        without the explicit <= 0 refusal makes this VALID.
        """
        healthy_after = snap(
            10.0,
            allocations=1_000_000,
            nat_acq=2_000_000,
            pub_acq=3_000_000,
            rep_upserts=1_000_000,
            rep_enqueued=6_000_000,
            rep_depth_sum=1_000_000,
            workers=six_even_workers(1_000_000),
        )
        a = analyze(
            snap(0.0, workers=six_even_workers(0)),
            healthy_after,
            offered_flows_per_sec=0.0,
        )
        self.assertEqual(a.verdict, INVALID)
        self.assertTrue(any("not a measurement" in r for r in a.reasons))

        # Negative offered rates are refused the same way.
        b = analyze(
            snap(0.0, workers=six_even_workers(0)),
            healthy_after,
            offered_flows_per_sec=-1.0,
        )
        self.assertEqual(b.verdict, INVALID)

        # ...while OMITTING the offered rate entirely stays a legitimate mode
        # (a manual run with no generator report). It just cannot be
        # generator-gated, and says so by leaving accept_ratio None.
        c = analyze(
            snap(0.0, workers=six_even_workers(0)),
            healthy_after,
            offered_flows_per_sec=None,
        )
        self.assertEqual(c.verdict, VALID, c.reasons)
        self.assertIsNone(c.accept_ratio)

    def test_missing_timestamp_is_invalid_not_an_inflated_window(self):
        """A missing `t` used to default to 0.0.

        With `before.t` absent and `after.t` a real unix timestamp, the window
        became ~1.7e9 seconds: past the minimum-window gate, with a rate of
        essentially zero that still read VALID.
        """
        before = snap(0.0, workers=six_even_workers(0))
        del before["t"]
        after = snap(
            1.75e9,
            allocations=1_000_000,
            nat_acq=2_000_000,
            pub_acq=3_000_000,
            rep_upserts=1_000_000,
            rep_enqueued=6_000_000,
            workers=six_even_workers(1_000_000),
        )
        a = analyze(before, after)
        self.assertEqual(a.verdict, INVALID)
        self.assertTrue(any("before.t" in r for r in a.reasons))

    def test_missing_helper_pid_is_invalid_not_a_skipped_restart_check(self):
        """`helper_pid` is the only direct restart detector.

        Absent on either side, the comparison used to be skipped outright —
        and the shell manufactured that absence whenever `pidof` failed.
        """
        before = snap(0.0, workers=six_even_workers(0))
        before["helper_pid"] = None
        after = snap(
            10.0,
            allocations=1_000_000,
            nat_acq=2_000_000,
            pub_acq=3_000_000,
            rep_upserts=1_000_000,
            rep_enqueued=6_000_000,
            workers=six_even_workers(1_000_000),
        )
        a = analyze(before, after)
        self.assertEqual(a.verdict, INVALID)
        self.assertTrue(any("before.helper_pid" in r for r in a.reasons))

    def test_absent_worker_series_is_invalid_not_two_skipped_gates(self):
        """The worst of the three: an empty `workers` map disabled BOTH
        cross-worker gates.

        `if installs and ...` guarded the RSS-distribution check and
        `max_worker_share is not None` guarded the skew check. With no
        per-worker series, neither ran — so a run steered entirely onto one
        RX queue would sail through as a cross-worker lock bound, the exact
        mis-attribution the gates exist to prevent.
        """
        empty = {}
        a = analyze(
            snap(0.0, workers=empty),
            snap(
                10.0,
                allocations=1_000_000,
                nat_acq=2_000_000,
                nat_blocked=1_000_000,
                pub_acq=3_000_000,
                pub_blocked=1_500_000,
                rep_upserts=1_000_000,
                rep_enqueued=6_000_000,
                rep_blocked=3_000_000,
                workers=empty,
            ),
        )
        self.assertEqual(a.verdict, INVALID)
        self.assertTrue(
            any("RSS-distribution and worker-skew gates" in r for r in a.reasons)
        )
        self.assertEqual(a.culprits, [])

    def test_missing_counter_series_raises_rather_than_scoring_zero(self):
        """A missing COUNTER is an error, not a zero.

        Every REQUIRED_SNAPSHOT_KEY is present here, so this reaches the
        counter reads and proves `_get` still refuses to invent a value —
        scoring an absent contention series as 0 would report a clean site
        that was never measured.
        """
        before = snap(0.0, workers=six_even_workers(0))
        after = snap(10.0, allocations=1_000, workers=six_even_workers(1_000))
        del after["publish"]["lock_contended_total"]
        with self.assertRaises(SnapshotError):
            analyze(before, after)


SCRAPE = """\
# HELP xpf_userspace_source_nat_pool_allocations_total allocations
# TYPE xpf_userspace_source_nat_pool_allocations_total counter
xpf_userspace_source_nat_pool_allocations_total{pool="lab-pool",rule="snat"} 987654
xpf_userspace_source_nat_pool_allocations_total{pool="idle-pool",rule="other"} 3
xpf_userspace_source_nat_pool_exhaustions_total{pool="lab-pool",rule="snat"} 0
xpf_userspace_source_nat_pool_exhaustions_total{pool="idle-pool",rule="other"} 0
xpf_userspace_source_nat_pool_flow_shard_lock_acquisitions_total{pool="lab-pool",rule="snat"} 1000000
xpf_userspace_source_nat_pool_flow_shard_lock_acquisitions_total{pool="idle-pool",rule="other"} 4
xpf_userspace_source_nat_pool_flow_shard_lock_contended_total{pool="lab-pool",rule="snat"} 20000
xpf_userspace_source_nat_pool_flow_shard_lock_contended_total{pool="idle-pool",rule="other"} 0
xpf_userspace_source_nat_pool_live_write_lock_acquisitions_total{pool="lab-pool",rule="snat"} 1000000
xpf_userspace_source_nat_pool_live_write_lock_acquisitions_total{pool="idle-pool",rule="other"} 5
xpf_userspace_source_nat_pool_live_write_lock_contended_total{pool="lab-pool",rule="snat"} 20000
xpf_userspace_source_nat_pool_live_write_lock_contended_total{pool="idle-pool",rule="other"} 0
xpf_userspace_source_nat_pool_live_lock_acquisitions_total{pool="lab-pool",rule="snat"} 2000000
xpf_userspace_source_nat_pool_live_lock_acquisitions_total{pool="idle-pool",rule="other"} 9
xpf_userspace_source_nat_pool_live_lock_contended_total{pool="lab-pool",rule="snat"} 40000
xpf_userspace_source_nat_pool_live_lock_contended_total{pool="idle-pool",rule="other"} 0
xpf_userspace_shared_session_publishes_total 1000000
xpf_userspace_shared_session_publish_lock_acquisitions_total 3000000
xpf_userspace_shared_session_publish_lock_contended_total 900000
xpf_userspace_session_replication_upserts_total 1000000
xpf_userspace_session_replication_enqueued_total 6000000
xpf_userspace_session_replication_lock_contended_total 1200000
xpf_userspace_session_replication_queue_depth_sum 2500000
xpf_userspace_session_replication_queue_depth_max 17
xpf_userspace_event_stream_producer_seq_lock_acquisitions_total 2000000
xpf_userspace_event_stream_producer_seq_lock_contended_total 500000
xpf_userspace_worker_new_flow_installs_total{worker_id="0"} 170000
xpf_userspace_worker_new_flow_installs_total{worker_id="1"} 166000
xpf_userspace_worker_new_flow_installs_total{worker_id="2"} 164000
"""


class ScrapeParsing(unittest.TestCase):
    def test_selects_the_pool_under_test(self):
        """A second idle pool must not dilute the ratio.

        Summing both pools' acquisitions would add the idle pool's cold
        denominator to the loaded pool's numerator and understate contention.
        """
        s = parse_prometheus_text(
            SCRAPE, timestamp=100.0, pool_name="lab-pool", rule_name="snat", helper_pid=7
        )
        self.assertEqual(s["pool"]["allocations_total"], 987654)
        self.assertEqual(s["pool"]["flow_shard_lock_acquisitions_total"], 1_000_000)
        self.assertEqual(s["pool"]["flow_shard_lock_contended_total"], 20_000)
        self.assertEqual(s["pool"]["live_write_lock_acquisitions_total"], 1_000_000)
        self.assertEqual(s["pool"]["live_write_lock_contended_total"], 20_000)
        self.assertEqual(s["pool"]["live_lock_acquisitions_total"], 2_000_000)
        self.assertEqual(s["pool"]["live_lock_contended_total"], 40_000)
        self.assertEqual(s["publish"]["lock_contended_total"], 900_000)
        self.assertEqual(s["replicate"]["queue_depth_sum"], 2_500_000)
        self.assertEqual(s["replicate"]["queue_depth_max"], 17)
        # #9169 site 4 is scraped from the same text as the other three.
        self.assertEqual(s["event_stream"]["lock_acquisitions_total"], 2_000_000)
        self.assertEqual(s["event_stream"]["lock_contended_total"], 500_000)
        self.assertEqual(s["workers"], {"0": 170000, "1": 166000, "2": 164000})
        self.assertEqual(s["helper_pid"], 7)

    def test_unknown_pool_raises(self):
        with self.assertRaises(SnapshotError):
            parse_prometheus_text(
                SCRAPE, timestamp=1.0, pool_name="does-not-exist", rule_name="snat"
            )

    def test_ambiguous_pool_selection_raises(self):
        """Refusing to guess is the point: silently picking the first pool
        would attribute another rule's contention to this one."""
        with self.assertRaises(SnapshotError):
            parse_prometheus_text(SCRAPE, timestamp=1.0)

    def test_missing_global_series_raises(self):
        trimmed = "\n".join(
            l
            for l in SCRAPE.splitlines()
            if not l.startswith("xpf_userspace_session_replication_queue_depth_max")
        )
        with self.assertRaises(SnapshotError):
            parse_prometheus_text(
                trimmed, timestamp=1.0, pool_name="lab-pool", rule_name="snat"
            )

    def test_end_to_end_two_scrapes(self):
        """Parse -> analyze, the path the harness actually takes."""
        before = parse_prometheus_text(
            SCRAPE, timestamp=0.0, pool_name="lab-pool", rule_name="snat", helper_pid=7
        )
        # Advance the pool allocations AND the per-worker installs: a scrape
        # pair where the workers did not move is a run in which no worker
        # installed anything, and the RSS gate is right to refuse it.
        later = SCRAPE.replace(
            'xpf_userspace_source_nat_pool_allocations_total{pool="lab-pool",rule="snat"} 987654',
            'xpf_userspace_source_nat_pool_allocations_total{pool="lab-pool",rule="snat"} 1587654',
        )
        for worker, before_n, after_n in (
            ("0", 170000, 370000),
            ("1", 166000, 366000),
            ("2", 164000, 364000),
        ):
            later = later.replace(
                f'xpf_userspace_worker_new_flow_installs_total{{worker_id="{worker}"}} {before_n}',
                f'xpf_userspace_worker_new_flow_installs_total{{worker_id="{worker}"}} {after_n}',
            )
        after = parse_prometheus_text(
            later, timestamp=10.0, pool_name="lab-pool", rule_name="snat", helper_pid=7
        )
        a = analyze(before, after)
        self.assertEqual(a.verdict, VALID, a.reasons)
        self.assertEqual(a.new_flows_per_sec, 60_000.0)
        # No counter moved besides allocations, so no site can be saturated.
        self.assertEqual(a.culprits, [])


if __name__ == "__main__":
    unittest.main()
