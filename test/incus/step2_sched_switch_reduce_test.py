#!/usr/bin/env python3
"""Unit tests for step2-sched-switch-reduce.py (#821 V1-V3 gates).

Covers:
 - bucket_index_for_ns boundary pins (V1)
 - load_boundaries_ns derivation from cold + samples, including _error skip
 - reducer synthetic three-switches-two-durations (V2, §3.4 case 3)
 - out-of-order perf timestamp skip
 - empty events still emit 12 blocks
 - invariant sum(buckets[3:7]) == off_cpu_time_3to6 (V3)
 - drift warning when PERF_START_NS = STEP1_START_NS + 2 s

Run from the repo root:
    python3 -m unittest test.incus.step2-sched-switch-reduce_test
Or directly:
    python3 test/incus/step2-sched-switch-reduce_test.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from load_subject import load_subject  # noqa: E402


# --- load the reducer as a module ("-" in filename blocks normal import) -----

_HERE = Path(__file__).resolve().parent
_REDUCER_PATH = _HERE / "step2-sched-switch-reduce.py"



R = load_subject("step2_sched_switch_reduce", str(_REDUCER_PATH))


# --- V1: bucket_index_for_ns pins --------------------------------------------


class TestBucketIndex(unittest.TestCase):
    def test_bucket_index_for_ns_boundary_pins(self):
        """Port of umem.rs::bucket_index_for_ns must match these pins."""
        cases = [
            (0, 0),
            (1, 0),
            (1023, 0),
            (1024, 1),
            (2047, 1),
            (2048, 2),
            (4095, 2),
            (4096, 3),
            (8192, 4),
            (16384, 5),
            (32768, 6),
            (65536, 7),
            (2**24 - 1, 14),
            (2**24, 15),
            (2**64 - 1, 15),
        ]
        for ns, want in cases:
            with self.subTest(ns=ns):
                got = R.bucket_index_for_ns(ns)
                self.assertEqual(
                    got, want, f"ns={ns}: got b{got}, want b{want}"
                )


# --- STEP1_START_NS derivation -----------------------------------------------


def _write_inline(content: str, suffix: str) -> Path:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content.encode())
    os.close(fd)
    return Path(path)


class TestBoundariesDerivation(unittest.TestCase):
    def test_step1_start_ns_from_samples(self):
        """cold _sample_ts=1713571200 -> boundaries[0] = 1713571200_000_000_000.

        _error first-line in samples must be skipped; reducer uses the next
        12 valid warm samples.
        """
        cold = {"_sample_ts": "1713571200", "status": {"per_binding": []}}
        cold_path = _write_inline(json.dumps(cold), ".json")
        # 13 warm lines: first has _error, so we need 12 valid after it.
        warm_lines = []
        warm_lines.append(
            json.dumps({"_sample_ts": "1713571205", "_error": "timeout"})
        )
        for i in range(12):
            warm_lines.append(
                json.dumps(
                    {"_sample_ts": str(1713571205 + (i + 1) * 5), "status": {}}
                )
            )
        samples_path = _write_inline("\n".join(warm_lines) + "\n", ".jsonl")

        try:
            boundaries, warnings = R.load_boundaries_ns(cold_path, samples_path)
            self.assertEqual(len(boundaries), 13)
            self.assertEqual(boundaries[0], 1713571200 * 1_000_000_000)
            # The first warm line was skipped (error), so warm[0] should
            # be the second warm line = 1713571210.
            self.assertEqual(boundaries[1], 1713571210 * 1_000_000_000)
            # At least one warning about the _error skip.
            self.assertTrue(any("_error" in w for w in warnings))
        finally:
            cold_path.unlink()
            samples_path.unlink()

    def test_missing_cold_sample_ts_raises(self):
        cold = {"status": {"per_binding": []}}  # no _sample_ts
        cold_path = _write_inline(json.dumps(cold), ".json")
        samples_path = _write_inline("", ".jsonl")
        try:
            with self.assertRaises(ValueError):
                R.load_boundaries_ns(cold_path, samples_path)
        finally:
            cold_path.unlink()
            samples_path.unlink()

    def test_interval_halt_on_giant_gap(self):
        cold = {"_sample_ts": "1000000000"}
        # Next warm is 60 s later -> HALT (>30 s).
        warm_lines = [json.dumps({"_sample_ts": "1000000060"})]
        # Pad to 12 valid warm, 5 s each thereafter.
        for i in range(11):
            warm_lines.append(
                json.dumps({"_sample_ts": str(1000000060 + (i + 1) * 5)})
            )
        cold_path = _write_inline(json.dumps(cold), ".json")
        samples_path = _write_inline("\n".join(warm_lines) + "\n", ".jsonl")
        try:
            with self.assertRaises(ValueError):
                R.load_boundaries_ns(cold_path, samples_path)
        finally:
            cold_path.unlink()
            samples_path.unlink()


# --- V2: synthetic reducer test ----------------------------------------------


def _make_boundaries(start_s: int = 1_000_000_000) -> list[int]:
    """Evenly-spaced 5-s boundaries: 13 entries, start..start+60 s."""
    return [(start_s + i * 5) * 1_000_000_000 for i in range(13)]


class TestReducerSynthetic(unittest.TestCase):
    def test_reducer_synthetic_three_switches_two_durations(self):
        """§3.4 test case 3 (C175-HC-026: closed at schedule-in).

        Two off-CPU intervals in block 0, each opened by a sched_switch
        that moves the worker OFF-CPU and closed by a later sched_switch
        that moves it back ON-CPU (next_pid=worker):

          * voluntary: switch-out prev_state=S at +1.000000 s, scheduled
            back in at +1.000008 s -> 8 us off-CPU (bucket 3).  A
            sched_wakeup fires in between; it is informational and does
            NOT close the interval.
          * involuntary: switch-out prev_state=R at +2.500000 s (the
            worker stays runnable — the kernel emits NO wakeup for a
            preempted-runnable task), scheduled back in at +2.500032 s
            -> 32 us off-CPU (bucket 5).

        HIGH-3: perf timestamps are absolute unix wall-clock ns
        (perf-record uses `-k CLOCK_REALTIME`); the reducer applies them
        directly to `block_for_timestamp()` with no PERF_START_NS
        offsetting.  So the perf_ts values here are `step1_start_ns +
        <offset>`, not bare offsets.

        Expected per block 0:
          buckets[3] = 8000       (8 us = bucket 3: [4096, 8192))
          buckets[5] = 32000      (32 us = bucket 5: [16384, 32768))
          off_cpu_time_3to6 = 40000
          voluntary_3to6 = 8000
          involuntary_3to6 = 32000
        """
        boundaries = _make_boundaries()
        step1_start_ns = boundaries[0]
        tid = 9999
        worker_tids = {tid}
        perf_start_ns = step1_start_ns  # zero drift

        events = [
            # Voluntary sleep: worker switched OUT (S) at +1.000000 s.
            (
                "sched:sched_switch",
                tid,
                step1_start_ns + 1_000_000_000,
                {"prev_pid": tid, "prev_state": "S", "next_pid": 0},
            ),
            # Wakeup 4 us later — informational; does NOT close the interval.
            (
                "sched:sched_wakeup",
                tid,
                step1_start_ns + 1_000_004_000,
                {"pid": tid},
            ),
            # Worker scheduled back IN 8 us after switch-out -> 8 us off-CPU.
            (
                "sched:sched_switch",
                0,
                step1_start_ns + 1_000_008_000,
                {"prev_pid": 0, "prev_state": "R", "next_pid": tid},
            ),
            # Involuntary preemption: switched OUT (R) at +2.500000 s.  No
            # wakeup follows — a runnable-preempted task never sleeps.
            (
                "sched:sched_switch",
                tid,
                step1_start_ns + 2_500_000_000,
                {"prev_pid": tid, "prev_state": "R", "next_pid": 0},
            ),
            # Worker scheduled back IN 32 us later -> 32 us off-CPU (invol).
            (
                "sched:sched_switch",
                0,
                step1_start_ns + 2_500_032_000,
                {"prev_pid": 0, "prev_state": "R", "next_pid": tid},
            ),
            # A stat_runtime event in block 0 — enough runtime to pass the
            # ±1% accounting check.  Expected on-CPU for this block:
            #   block_duration = 5 s
            #   n_workers = 1
            #   total_off_cpu = 40000 ns (the two intervals above)
            #   expected_on_cpu = 5e9 - 40000 ≈ 5e9
            # We feed 5e9 exactly so rel_err = 40000/5e9 ≈ 8e-6 << 1%.
            (
                "sched:sched_stat_runtime",
                tid,
                step1_start_ns + 3_000_000_000,
                {"runtime_ns": 5_000_000_000},
            ),
        ]

        buf = io.StringIO()
        warn = io.StringIO()
        warnings = R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=perf_start_ns,
            out_stream=buf,
            warn_stream=warn,
        )
        self.assertEqual(warnings, [], f"unexpected warnings: {warnings}")
        lines = buf.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 12)
        blocks = [json.loads(l) for l in lines]
        # Block 0 assertions.
        b0 = blocks[0]
        self.assertEqual(b0["b"], 0)
        self.assertEqual(b0["buckets"][3], 8000)
        self.assertEqual(b0["buckets"][5], 32000)
        # All other buckets zero.
        for i, v in enumerate(b0["buckets"]):
            if i not in (3, 5):
                self.assertEqual(v, 0, f"block 0 bucket {i} = {v}, want 0")
        self.assertEqual(b0["off_cpu_time_3to6"], 40000)
        self.assertEqual(b0["voluntary_3to6"], 8000)
        self.assertEqual(b0["involuntary_3to6"], 32000)
        self.assertEqual(b0["stat_runtime_check"], "PASS")
        # Blocks 1..11: all zero, stat_runtime_check=WARN (zero runtime
        # but expected ≈ 5e9 → rel_err = 1.0 >> 0.01).
        for i in range(1, 12):
            bi = blocks[i]
            self.assertEqual(sum(bi["buckets"]), 0)
            self.assertEqual(bi["off_cpu_time_3to6"], 0)
            self.assertEqual(bi["stat_runtime_check"], "WARN")


class TestReducerScheduleInClose(unittest.TestCase):
    """C175-HC-026: off-CPU intervals close at schedule-in, not wakeup."""

    def test_involuntary_preemption_without_wakeup_is_measured(self):
        """A runnable-preempted worker (prev_state=R, NO wakeup) that is
        later rescheduled must have its off-CPU interval measured.

        Fail-on-revert: the pre-fix reducer closed intervals on
        sched_wakeup.  A preempted-runnable task emits no wakeup, so its
        interval was never closed and involuntary_3to6 stayed 0 — the
        exact signal this harness exists to detect went silently
        unmeasured.
        """
        boundaries = _make_boundaries()
        step1_start_ns = boundaries[0]
        tid = 4242
        worker_tids = {tid}
        events = [
            # Preempted while runnable at +1.000000 s (block 0). No wakeup.
            ("sched:sched_switch", tid, step1_start_ns + 1_000_000_000,
             {"prev_pid": tid, "prev_state": "R", "next_pid": 0}),
            # Rescheduled 16 us later -> 16 us off-CPU (bucket 4, in D1).
            ("sched:sched_switch", 0, step1_start_ns + 1_000_016_000,
             {"prev_pid": 0, "prev_state": "R", "next_pid": tid}),
        ]
        buf = io.StringIO()
        warn = io.StringIO()
        warnings = R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=step1_start_ns,
            out_stream=buf,
            warn_stream=warn,
        )
        self.assertEqual(warnings, [], f"unexpected warnings: {warnings}")
        b0 = json.loads(buf.getvalue().strip().split("\n")[0])
        self.assertEqual(b0["buckets"][4], 16000)
        self.assertEqual(b0["off_cpu_time_3to6"], 16000)
        self.assertEqual(b0["involuntary_3to6"], 16000)
        self.assertEqual(b0["voluntary_3to6"], 0)

    def test_wakeup_alone_does_not_close_interval(self):
        """A wakeup with NO following schedule-in must not accumulate.

        Fail-on-revert: the pre-fix reducer treated sched_wakeup as the
        interval end, so a switch-out + wakeup (no schedule-in) closed
        and accumulated off-CPU time. Under schedule-in semantics the
        interval stays open (unclosed) and nothing is accumulated.
        """
        boundaries = _make_boundaries()
        step1_start_ns = boundaries[0]
        tid = 55
        worker_tids = {tid}
        events = [
            ("sched:sched_switch", tid, step1_start_ns + 1_000_000_000,
             {"prev_pid": tid, "prev_state": "S", "next_pid": 0}),
            # Wakeup 8 us later, but the worker is never scheduled back in.
            ("sched:sched_wakeup", tid, step1_start_ns + 1_000_008_000,
             {"pid": tid}),
        ]
        buf = io.StringIO()
        warn = io.StringIO()
        warnings = R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=step1_start_ns,
            out_stream=buf,
            warn_stream=warn,
        )
        self.assertEqual(warnings, [])
        blocks = [json.loads(l) for l in buf.getvalue().strip().split("\n")]
        self.assertEqual(sum(sum(b["buckets"]) for b in blocks), 0)
        self.assertEqual(sum(b["off_cpu_time_3to6"] for b in blocks), 0)

    def test_parser_extracts_next_pid(self):
        """The perf-script parser must surface next_pid for sched_switch."""
        txt = (
            "xpf-userspace-w 12345 [003] 1234.567890123: "
            "sched:sched_switch: prev_comm=xpf-userspace-w prev_pid=12345 "
            "prev_prio=120 prev_state=R ==> next_comm=other next_pid=678 "
            "next_prio=120\n"
        )
        path = _write_inline(txt, ".txt")
        try:
            events = list(R.parse_perf_script(path))
        finally:
            path.unlink()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][3]["prev_pid"], 12345)
        self.assertEqual(events[0][3]["next_pid"], 678)


class TestReducerOutOfOrder(unittest.TestCase):
    def test_reducer_out_of_order_skip(self):
        """Out-of-order perf timestamp -> WARN + skip (monotonicity).

        Hits the `ts_ns < prev_perf_ts_ns` guard early in the event loop
        (rewound perf timestamp).  Distinct from `test_reducer_negative_
        wake_delta_skip` which exercises the wake-path `delta_ns < 0`
        branch after monotonicity has passed.
        """
        boundaries = _make_boundaries()
        step1_start_ns = boundaries[0]
        tid = 42
        worker_tids = {tid}
        events = [
            # First event at wall = step1_start + 1.0 s
            ("sched:sched_switch", tid, step1_start_ns + 1_000_000_000,
             {"prev_pid": tid, "prev_state": "S"}),
            # Second event at wall = step1_start + 0.5 s (rewinds) -> skipped
            ("sched:sched_wakeup", tid, step1_start_ns + 500_000_000,
             {"pid": tid}),
        ]
        buf = io.StringIO()
        warn = io.StringIO()
        warnings = R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=boundaries[0],
            out_stream=buf,
            warn_stream=warn,
        )
        self.assertTrue(any("out-of-order" in w for w in warnings))
        # 12 blocks still emitted, all zero (since wake was skipped).
        blocks = [json.loads(l) for l in buf.getvalue().strip().split("\n")]
        self.assertEqual(len(blocks), 12)
        self.assertEqual(sum(sum(b["buckets"]) for b in blocks), 0)


class TestReducerNegativeWakeDelta(unittest.TestCase):
    """LOW-7: exercise the wake-path `delta_ns < 0` branch at
    step2-sched-switch-reduce.py:401-410.

    The outer monotonicity guard on `ts_ns < prev_perf_ts_ns` is a
    STRICT less-than check (`<`, not `<=`), so an event with the same
    ts as the previous passes.  We exploit this: two back-to-back
    events with identical perf ts both satisfy monotonicity, and we
    abuse the two-tid layout to post-date one tid's off_start AFTER a
    wake for that same tid has been staged.

    Concretely: tid=A switches at ts=T (off_start_A=T, prev=T).  We
    then replay the stream by directly monkey-patching the wake event's
    ts to be T-1.  The monotonicity guard trips — this is the
    out-of-order path, NOT the wake path.

    Since the monotonicity guard is strictly stronger than the
    wake-path guard, the wake-path `delta_ns < 0` branch is provably
    unreachable under ordered perf input (by pigeonhole: if ts_wake >=
    prev_perf_ts >= ts_switch, then ts_wake >= off_start_A = ts_switch,
    so delta >= 0).  The branch remains in the code as defence-in-depth
    against a future refactor that might weaken the outer guard.

    We therefore pass an UNORDERED event stream directly (bypassing the
    outer guard's protection — which would have rejected the wake with
    an "out-of-order" WARN first).  The prev_perf_ts_ns guard is
    advanced by an unrelated event AFTER the switch but BEFORE the
    wake, demonstrating both WARN paths on the same stream.

    Actually, with ts_wake < ts_switch, the wake event fires
    out-of-order FIRST (prev_perf_ts was advanced by the switch).  So
    this test asserts that out-of-order fires, and documents that the
    wake-path negative-delta branch is an unreachable defensive guard.
    """

    def test_reducer_equal_ts_wake_delta_zero_accumulates(self):
        """LOW-7 R3: boundary equal-ts sub-case.

        When a `sched_wakeup` arrives with the EXACT same perf ts as the
        preceding `sched_switch`, the outer monotonicity guard (strict <)
        lets both through, and `delta_ns = 0`. The wake-path `delta_ns <
        0` branch is NOT triggered (0 is not < 0). Expected: the zero
        duration maps to bucket 0 and accumulates cleanly (no WARN, no
        skip). This test pins the equal-ts boundary case explicitly.
        """
        boundaries = _make_boundaries()
        step1_start_ns = boundaries[0]
        tid = 7
        worker_tids = {tid}
        t_common = step1_start_ns + 2_000_000_000
        events = [
            ("sched:sched_switch", tid, t_common,
             {"prev_pid": tid, "prev_state": "S"}),
            ("sched:sched_wakeup", tid, t_common,
             {"pid": tid}),
        ]
        buf = io.StringIO()
        warn = io.StringIO()
        warnings = R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=step1_start_ns,
            out_stream=buf,
            warn_stream=warn,
        )
        # No monotonicity WARN fired (equal ts passes strict < guard).
        # `reduce_events` returns a list of warning tuples; empty list = no
        # warnings fired.
        self.assertEqual(len(warnings), 0, f"unexpected warnings: {warnings}")
        self.assertNotIn("out-of-order", warn.getvalue())
        self.assertNotIn("negative delta", warn.getvalue())
        # Block 0 accumulates a zero-duration event into bucket 0.
        lines = [json.loads(l) for l in buf.getvalue().strip().split("\n")]
        self.assertEqual(len(lines), 12)
        # LOW-7 R4: explicitly pin the routing path.
        # bucket_index_for_ns(0) == 0, so delta_ns=0 routes to bucket[0].
        self.assertEqual(R.bucket_index_for_ns(0), 0)
        # bucket[0] accumulation of 0 ns leaves the count at 0 ns total.
        self.assertEqual(lines[0]["buckets"][0], 0)
        # All other buckets are also zero (no other events).
        self.assertEqual(lines[0]["buckets"], [0] * 16)
        self.assertEqual(lines[0]["off_cpu_time_3to6"], 0)

    def test_reducer_wake_before_switch_triggers_out_of_order(self):
        """Wake arrives with ts earlier than the preceding switch.

        Expected: out-of-order WARN fires, wake is skipped, no
        accumulation.  The wake-path `delta_ns < 0` branch at line 401
        is NOT reached (monotonicity guard catches it first); see
        class docstring.
        """
        boundaries = _make_boundaries()
        step1_start_ns = boundaries[0]
        tid = 7
        worker_tids = {tid}
        events = [
            ("sched:sched_switch", tid, step1_start_ns + 2_000_000_000,
             {"prev_pid": tid, "prev_state": "S"}),
            # Wake at an EARLIER ts than the switch — rewinds.
            ("sched:sched_wakeup", tid, step1_start_ns + 1_000_000_000,
             {"pid": tid}),
        ]
        buf = io.StringIO()
        warn = io.StringIO()
        warnings = R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=boundaries[0],
            out_stream=buf,
            warn_stream=warn,
        )
        self.assertTrue(
            any("out-of-order" in w for w in warnings),
            f"expected out-of-order WARN; got: {warnings}",
        )
        # Wake was skipped; buckets should remain zero.  Critically,
        # off_start_ns[tid] is STILL populated (never cleared), but no
        # wake ever lands — accumulation is zero for this tid.
        blocks = [json.loads(l) for l in buf.getvalue().strip().split("\n")]
        self.assertEqual(sum(sum(b["buckets"]) for b in blocks), 0)

    def test_reducer_wake_path_negative_delta_branch_directly(self):
        """Directly drive the wake-path `delta_ns < 0` branch.

        We bypass the monotonicity guard by emitting events with
        equal-or-ascending ts (guard is strict `<`), and abuse a quirk:
        if we issue the wake event's ts EQUAL to the previous switch
        ts, but the switch for the SAME tid was issued earlier with a
        LATER fields-encoded time, the stored off_start would still be
        the earlier ts — delta = 0, not negative.

        To hit negative delta, we construct a malformed stream that is
        monotonically non-decreasing on the wire (guard passes) but
        where off_start for the woken tid was set at a LATER ts by a
        prior switch — impossible in a single linear stream.

        So instead: we call `reduce_events` on a 2-event stream
        [switch@T, wake@T-1] where T-1 < T trips the OUTER guard first,
        and we document that the inner branch IS defensive dead code
        under ordered perf input.  Test passes iff an out-of-order
        WARN is emitted.

        This mirrors the sister test above but is kept as a named
        regression so future monotonicity-guard relaxations get flagged
        in test output.
        """
        boundaries = _make_boundaries()
        step1_start_ns = boundaries[0]
        tid = 9
        worker_tids = {tid}
        events = [
            ("sched:sched_switch", tid, step1_start_ns + 500_000_000,
             {"prev_pid": tid, "prev_state": "R"}),
            # Wake 100 ms earlier.
            ("sched:sched_wakeup", tid, step1_start_ns + 400_000_000,
             {"pid": tid}),
        ]
        buf = io.StringIO()
        warn = io.StringIO()
        warnings = R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=boundaries[0],
            out_stream=buf,
            warn_stream=warn,
        )
        # Outer monotonicity guard catches this; the inner negative-
        # delta branch does NOT fire (no "negative off-CPU delta" WARN).
        self.assertTrue(any("out-of-order" in w for w in warnings))
        self.assertFalse(
            any("negative off-CPU delta" in w for w in warnings),
            "inner negative-delta branch is unreachable under ordered "
            "perf input (defensive dead-code); if this test begins to "
            "trigger it, the outer monotonicity guard has been weakened",
        )


class TestReducerEmpty(unittest.TestCase):
    def test_reducer_emits_12_blocks(self):
        """Empty events still emit 12 zero-histogram lines."""
        boundaries = _make_boundaries()
        buf = io.StringIO()
        warn = io.StringIO()
        R.reduce_events(
            events=iter([]),
            boundaries_ns=boundaries,
            worker_tids={1, 2, 3, 4},
            perf_start_ns=boundaries[0],
            out_stream=buf,
            warn_stream=warn,
        )
        lines = buf.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 12)
        for i, l in enumerate(lines):
            obj = json.loads(l)
            self.assertEqual(obj["b"], i)
            self.assertEqual(len(obj["buckets"]), 16)
            self.assertEqual(sum(obj["buckets"]), 0)
            self.assertEqual(obj["off_cpu_time_3to6"], 0)
            self.assertEqual(obj["voluntary_3to6"], 0)
            self.assertEqual(obj["involuntary_3to6"], 0)
            self.assertEqual(obj["stat_runtime_check"], "WARN")


class TestReducerEmptyPerfHalts(unittest.TestCase):
    """C175-HC-070: an empty/truncated perf capture must fail loud."""

    def test_reducer_halts_on_empty_perf(self):
        """main() returns non-zero when the perf script has zero events.

        Fail-on-revert: the pre-fix main() always returned 0 (or 5 on
        drift), so an empty capture emitted 12 all-zero blocks and exited
        0 — the classifier then ruled the scheduler definitively OUT from
        a measurement that never happened.
        """
        cold = {"_sample_ts": "1000000000"}
        cold_path = _write_inline(json.dumps(cold), ".json")
        warm_lines = [
            json.dumps({"_sample_ts": str(1000000000 + (i + 1) * 5)})
            for i in range(12)
        ]
        samples_path = _write_inline("\n".join(warm_lines) + "\n", ".jsonl")
        perf_path = _write_inline("", ".txt")  # empty capture
        step1_start_ns = 1_000_000_000 * 1_000_000_000
        perf_start_ns = step1_start_ns  # zero drift -> not a drift halt

        real_stderr = sys.stderr
        real_stdout = sys.stdout
        cap_err = io.StringIO()
        cap_out = io.StringIO()
        try:
            sys.stderr = cap_err
            sys.stdout = cap_out
            rc = R.main(
                [
                    "--perf-script", str(perf_path),
                    "--step1-cold", str(cold_path),
                    "--step1-samples", str(samples_path),
                    "--worker-tids", "1",
                    "--perf-start-ns", str(perf_start_ns),
                ]
            )
        finally:
            sys.stderr = real_stderr
            sys.stdout = real_stdout
            cold_path.unlink()
            samples_path.unlink()
            perf_path.unlink()
        self.assertEqual(rc, 2, f"expected exit 2 on empty perf, got {rc}")
        self.assertIn("zero sched events", cap_err.getvalue())


class TestReducerInvariant(unittest.TestCase):
    def test_reducer_invariant_sum_buckets_3to6(self):
        """V3: sum(buckets[3:7]) == off_cpu_time_3to6 on every block.

        Exercise with several off-CPU events landing in and out of the
        D1 window.  HIGH-3: perf ts is absolute unix wall-clock ns,
        so events are placed at `boundaries[b] + 1 s`.
        """
        boundaries = _make_boundaries()
        step1_start_ns = boundaries[0]
        tid = 7
        worker_tids = {tid}
        events = []
        # Events at t = boundaries[b] + 1 s (inside block b).  Alternate
        # durations land in and out of the D1 window:
        # 512 ns -> bucket 0 (out-of-D1)
        # 4096 ns -> bucket 3 (in D1)
        # 16384 ns -> bucket 5 (in D1)
        # 262144 ns -> bucket 9 (out-of-D1)
        durations = [512, 4096, 16384, 262144]
        for b in range(12):
            off_ts = boundaries[b] + 1_000_000_000
            d = durations[b % len(durations)]
            # Switch OUT (opens interval) then switch IN (next_pid=tid,
            # closes interval d ns later) — C175-HC-026 schedule-in close.
            events.append(
                ("sched:sched_switch", tid, off_ts,
                 {"prev_pid": tid, "prev_state": "S", "next_pid": 0})
            )
            events.append(
                ("sched:sched_switch", 0, off_ts + d,
                 {"prev_pid": 0, "prev_state": "R", "next_pid": tid})
            )

        buf = io.StringIO()
        warn = io.StringIO()
        R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=step1_start_ns,
            out_stream=buf,
            warn_stream=warn,
        )
        blocks = [json.loads(l) for l in buf.getvalue().strip().split("\n")]
        for blk in blocks:
            self.assertEqual(
                sum(blk["buckets"][3:7]),
                blk["off_cpu_time_3to6"],
                f"block {blk['b']}: invariant violated",
            )


class TestReducerDrift(unittest.TestCase):
    def test_reducer_drift_warning(self):
        """PERF_START_NS = STEP1_START_NS + 2 s -> WARN (no hard fail)."""
        cold = {"_sample_ts": "1000000000"}
        cold_path = _write_inline(json.dumps(cold), ".json")
        warm_lines = []
        for i in range(12):
            warm_lines.append(
                json.dumps({"_sample_ts": str(1000000000 + (i + 1) * 5)})
            )
        samples_path = _write_inline("\n".join(warm_lines) + "\n", ".jsonl")
        # One valid sched event so the capture is non-empty (the empty
        # capture path is exercised by test_reducer_halts_on_empty_perf).
        perf_line = (
            "xpf 1 [000] 1000000001.000000000: sched:sched_switch: "
            "prev_comm=xpf prev_pid=1 prev_prio=120 prev_state=S ==> "
            "next_comm=y next_pid=0 next_prio=120\n"
        )
        perf_path = _write_inline(perf_line, ".txt")
        step1_start_ns = 1_000_000_000 * 1_000_000_000
        perf_start_ns = step1_start_ns + 2_000_000_000  # +2 s

        real_stderr = sys.stderr
        real_stdout = sys.stdout
        cap_err = io.StringIO()
        cap_out = io.StringIO()
        try:
            sys.stderr = cap_err
            sys.stdout = cap_out
            rc = R.main(
                [
                    "--perf-script", str(perf_path),
                    "--step1-cold", str(cold_path),
                    "--step1-samples", str(samples_path),
                    "--worker-tids", "1",
                    "--perf-start-ns", str(perf_start_ns),
                ]
            )
        finally:
            sys.stderr = real_stderr
            sys.stdout = real_stdout
            cold_path.unlink()
            samples_path.unlink()
            perf_path.unlink()
        # 2s drift is WARN, not HALT; rc=0 and no suspect_reason in JSONL.
        self.assertEqual(rc, 0)
        self.assertIn("WARN:", cap_err.getvalue())
        self.assertIn("drift_ns", cap_err.getvalue())
        for raw in cap_out.getvalue().strip().split("\n"):
            if raw:
                obj = json.loads(raw)
                self.assertNotIn("suspect_reason", obj)

    def test_reducer_drift_halt_emits_suspect(self):
        """HIGH-2: drift >= 5 s -> SUSPECT.

        Reducer exits 5 (H-STOP-5 convention) AND stamps every emitted
        JSONL line with `suspect_reason: "drift_ge_5s"`.
        """
        cold = {"_sample_ts": "1000000000"}
        cold_path = _write_inline(json.dumps(cold), ".json")
        warm_lines = []
        for i in range(12):
            warm_lines.append(
                json.dumps({"_sample_ts": str(1000000000 + (i + 1) * 5)})
            )
        samples_path = _write_inline("\n".join(warm_lines) + "\n", ".jsonl")
        perf_path = _write_inline("", ".txt")
        step1_start_ns = 1_000_000_000 * 1_000_000_000
        perf_start_ns = step1_start_ns + 6_000_000_000  # +6 s -> HALT

        real_stderr = sys.stderr
        real_stdout = sys.stdout
        cap_err = io.StringIO()
        cap_out = io.StringIO()
        try:
            sys.stderr = cap_err
            sys.stdout = cap_out
            rc = R.main(
                [
                    "--perf-script", str(perf_path),
                    "--step1-cold", str(cold_path),
                    "--step1-samples", str(samples_path),
                    "--worker-tids", "1",
                    "--perf-start-ns", str(perf_start_ns),
                ]
            )
        finally:
            sys.stderr = real_stderr
            sys.stdout = real_stdout
            cold_path.unlink()
            samples_path.unlink()
            perf_path.unlink()
        # Drift halt: exit 5, HALT stderr, suspect_reason on every line.
        self.assertEqual(rc, 5, f"expected exit 5, got {rc}")
        self.assertEqual(rc, R.EXIT_DRIFT_HALT)
        self.assertIn("HALT:", cap_err.getvalue())
        self.assertIn("suspect_reason", cap_err.getvalue())
        # JSONL forensics still emitted (12 blocks) with sentinel.
        lines = [l for l in cap_out.getvalue().strip().split("\n") if l]
        self.assertEqual(len(lines), 12)
        for raw in lines:
            obj = json.loads(raw)
            self.assertEqual(obj.get("suspect_reason"), "drift_ge_5s")


# --- Parser sanity: perf-script line format ---------------------------------


class TestPerfScriptParse(unittest.TestCase):
    def test_parse_perf_script_basic(self):
        """Parser handles typical perf-script line shapes."""
        # Textbook sched_switch line (perf 6.x, no call-graph):
        txt = (
            "xpf-userspace-w 12345 [003] 1234.567890123: "
            "sched:sched_switch: prev_comm=xpf-userspace-w prev_pid=12345 "
            "prev_prio=120 prev_state=R+ ==> next_comm=swapper/0 next_pid=0 "
            "next_prio=120\n"
            "xpf-userspace-w 12345 [003] 1234.567900000: "
            "sched:sched_wakeup: comm=xpf-userspace-w pid=12345 "
            "prio=120 target_cpu=003\n"
            "xpf-userspace-w 12345 [003] 1234.567999999: "
            "sched:sched_stat_runtime: comm=xpf-userspace-w pid=12345 "
            "runtime=9876 [ns] vruntime=12345 [ns]\n"
        )
        path = _write_inline(txt, ".txt")
        try:
            events = list(R.parse_perf_script(path))
        finally:
            path.unlink()
        self.assertEqual(len(events), 3)
        ev0 = events[0]
        self.assertEqual(ev0[0], "sched:sched_switch")
        self.assertEqual(ev0[1], 12345)
        self.assertEqual(ev0[2], 1234_567_890_123)
        self.assertEqual(ev0[3]["prev_pid"], 12345)
        self.assertEqual(ev0[3]["prev_state"], "R+")

        ev1 = events[1]
        self.assertEqual(ev1[0], "sched:sched_wakeup")
        self.assertEqual(ev1[3]["pid"], 12345)

        ev2 = events[2]
        self.assertEqual(ev2[0], "sched:sched_stat_runtime")
        self.assertEqual(ev2[3]["runtime_ns"], 9876)


if __name__ == "__main__":
    unittest.main()
