import asyncio
import time
import unittest
from types import SimpleNamespace

import mouse_latency_probe as probe
from mouse_latency_probe import (
    HISTOGRAM_BUCKETS_US,
    _run,
    _compute_histogram,
    _compute_percentiles,
    compute_validity,
)


class HistogramTests(unittest.TestCase):
    def test_boundary_lower_bucket(self):
        # Value exactly at boundary lands in that bucket (≤ upper).
        counts = _compute_histogram([10])
        self.assertEqual(counts[0], 1)
        self.assertEqual(sum(counts), 1)

    def test_boundary_upper_bucket(self):
        counts = _compute_histogram([100000])
        self.assertEqual(counts[-1], 1)

    def test_overflow_goes_to_top_bucket(self):
        counts = _compute_histogram([200000])
        self.assertEqual(counts[-1], 1)

    def test_distribution_across_buckets(self):
        rtts = [5, 15, 30, 75, 200, 400, 800, 2000, 4000, 8000, 20000, 50000]
        counts = _compute_histogram(rtts)
        self.assertEqual(sum(counts), len(rtts))
        # Each value falls in distinct bucket due to construction:
        # 5≤10, 15≤20, 30≤50, 75≤100, 200≤250, 400≤500, 800≤1000,
        # 2000≤2500, 4000≤5000, 8000≤10000, 20000≤25000, 50000≤100000
        self.assertEqual(counts, [1] * len(HISTOGRAM_BUCKETS_US))

    def test_empty(self):
        counts = _compute_histogram([])
        self.assertEqual(counts, [0] * len(HISTOGRAM_BUCKETS_US))


class PercentileTests(unittest.TestCase):
    def test_percentile_matches_statistics_quantiles(self):
        # The implementation uses statistics.quantiles(n=100,
        # method="inclusive"). Anchor the test to the same estimator
        # so they cannot drift.
        import statistics
        rtts = list(range(1, 1001))  # 1..1000
        p = _compute_percentiles(rtts)
        cuts100 = statistics.quantiles(rtts, n=100, method="inclusive")
        cuts1000 = statistics.quantiles(rtts, n=1000, method="inclusive")
        cuts4 = statistics.quantiles(rtts, n=4, method="inclusive")
        self.assertEqual(p["p50"], int(round(cuts100[49])))
        self.assertEqual(p["p95"], int(round(cuts100[94])))
        self.assertEqual(p["p99"], int(round(cuts100[98])))
        self.assertEqual(p["p999"], int(round(cuts1000[998])))
        self.assertEqual(p["min"], 1)
        self.assertEqual(p["max"], 1000)
        self.assertEqual(p["iqr"], int(round(cuts4[2] - cuts4[0])))

    def test_empty(self):
        p = _compute_percentiles([])
        self.assertIsNone(p["p99"])
        self.assertIsNone(p["p999"])
        self.assertIsNone(p["p50"])
        self.assertIsNone(p["min"])

    def test_single_sample(self):
        p = _compute_percentiles([42])
        self.assertEqual(p["p50"], 42)
        self.assertEqual(p["p99"], 42)
        self.assertEqual(p["p999"], 42)
        self.assertEqual(p["iqr"], 0)


class ValidityTests(unittest.TestCase):
    def test_clean_high_concurrency(self):
        attempts = [600] * 10  # 6000 total, M=10 floor=5000
        v = compute_validity(10, attempts, completed=5970, errors=30, coroutine_diagnostics=None)
        self.assertTrue(v["ok"], v["reasons"])

    def test_error_rate_too_high(self):
        attempts = [600] * 10
        # 200/6000 = 3.3% > 1%
        v = compute_validity(10, attempts, completed=5800, errors=200, coroutine_diagnostics=None)
        self.assertFalse(v["ok"])
        self.assertTrue(any("error_rate" in r for r in v["reasons"]))

    def test_degenerate_coroutine_min_attempts(self):
        # 9 coroutines did 600, one did 200; median=600, min=200 < 300
        attempts = [600] * 9 + [200]
        v = compute_validity(10, attempts, completed=5790, errors=10, coroutine_diagnostics=None)
        self.assertFalse(v["ok"])
        self.assertTrue(any("degenerate-coroutine" in r for r in v["reasons"]))

    def test_below_min_attempts_floor_m10(self):
        attempts = [400] * 10  # 4000 total, M=10 floor=5000
        v = compute_validity(10, attempts, completed=4000, errors=0, coroutine_diagnostics=None)
        self.assertFalse(v["ok"])
        self.assertTrue(any("min-attempts" in r for r in v["reasons"]))

    def test_min_attempts_floor_m1(self):
        # M=1: floor=500
        v_pass = compute_validity(1, [500], completed=500, errors=0, coroutine_diagnostics=None)
        self.assertTrue(v_pass["ok"], v_pass["reasons"])
        v_fail = compute_validity(1, [499], completed=499, errors=0, coroutine_diagnostics=None)
        self.assertFalse(v_fail["ok"])
        self.assertTrue(any("min-attempts" in r for r in v_fail["reasons"]))

    def test_m1_skips_degenerate_check(self):
        # Single coroutine cannot be "degenerate vs median" — gate
        # is concurrency >= 2.
        v = compute_validity(1, [600], completed=600, errors=0, coroutine_diagnostics=None)
        self.assertTrue(v["ok"])

    def test_boundary_m10_exactly_5000(self):
        attempts = [500] * 10  # exactly 5000
        v = compute_validity(10, attempts, completed=5000, errors=0, coroutine_diagnostics=None)
        self.assertTrue(v["ok"], v["reasons"])

    def test_boundary_m10_exactly_4999(self):
        attempts = [500] * 9 + [499]
        # min=499 vs median=500 → 499 >= 0.5*500=250 → not degenerate.
        # Total=4999 < 5000 → fails min-attempts.
        v = compute_validity(10, attempts, completed=4999, errors=0, coroutine_diagnostics=None)
        self.assertFalse(v["ok"])

    def test_boundary_m1_exactly_500(self):
        v = compute_validity(1, [500], completed=500, errors=0, coroutine_diagnostics=None)
        self.assertTrue(v["ok"])

    def test_inconsistent_counts_completed_more_than_attempted(self):
        # Copilot R1 #4: surface the bookkeeping invariant rather
        # than letting completed go unused.
        v = compute_validity(10, [600] * 10, completed=7000, errors=0, coroutine_diagnostics=None)
        self.assertFalse(v["ok"])
        self.assertTrue(any("inconsistent-counts" in r for r in v["reasons"]))

    def test_inconsistent_counts_completed_plus_errors_neq_attempted(self):
        # 6000 attempts, 5500 completed, 100 errors → 5600 ≠ 6000
        v = compute_validity(10, [600] * 10, completed=5500, errors=100, coroutine_diagnostics=None)
        self.assertFalse(v["ok"])
        self.assertTrue(any("inconsistent-counts" in r for r in v["reasons"]))


class CloseWriterTests(unittest.IsolatedAsyncioTestCase):
    class _Transport:
        def __init__(self):
            self.aborted = False

        def abort(self):
            self.aborted = True

    class _HangingWriter:
        def __init__(self):
            self.closed = False
            self.transport = CloseWriterTests._Transport()
            self.wait_started = asyncio.Event()

        def close(self):
            self.closed = True

        async def wait_closed(self):
            self.wait_started.set()
            await asyncio.Event().wait()

        def write(self, _data):
            pass

    async def test_close_writer_aborts_when_wait_closed_exceeds_deadline(self):
        writer = self._HangingWriter()
        deadline = time.monotonic() + 0.01

        await asyncio.wait_for(probe._close_writer(writer, deadline), timeout=0.2)

        self.assertTrue(writer.closed)
        self.assertTrue(writer.wait_started.is_set())
        self.assertTrue(writer.transport.aborted)

    async def test_close_writer_abort_mode_skips_graceful_wait(self):
        writer = self._HangingWriter()
        deadline = time.monotonic() + 10.0

        await asyncio.wait_for(
            probe._close_writer(writer, deadline, abort=True),
            timeout=0.2,
        )

        self.assertFalse(writer.closed)
        self.assertFalse(writer.wait_started.is_set())
        self.assertTrue(writer.transport.aborted)

    async def test_per_attempt_drain_timeout_closes_with_abort(self):
        abort_flags = []

        class FakeReader:
            async def readexactly(self, _n):
                return b""

        async def open_fake_connection(_target, _port):
            return FakeReader(), self._HangingWriter()

        async def forced_timeout(_writer, _deadline):
            raise asyncio.TimeoutError("forced drain timeout")

        async def record_close(_writer, _deadline, *, abort=False):
            abort_flags.append(abort)

        original_open_connection = probe.asyncio.open_connection
        original_drain = probe._drain_with_deadline
        original_close = probe._close_writer
        probe.asyncio.open_connection = open_fake_connection
        probe._drain_with_deadline = forced_timeout
        probe._close_writer = record_close
        try:
            rtts = []
            attempts = [0]
            errors = [0]
            await probe._run_per_attempt_probe_coro(
                "127.0.0.1",
                1,
                16,
                0.0,
                time.monotonic() + 0.01,
                rtts,
                attempts,
                errors,
            )
        finally:
            probe.asyncio.open_connection = original_open_connection
            probe._drain_with_deadline = original_drain
            probe._close_writer = original_close

        self.assertGreaterEqual(errors[0], 1)
        self.assertIn(True, abort_flags)


class PersistentConnectionModeTests(unittest.IsolatedAsyncioTestCase):
    async def _run_local_echo_probe(
        self,
        *,
        concurrency,
        duration,
        min_interval_ms,
        connection_mode="persistent",
        close_after_echo=False,
        delayed_coroutines=(),
        coroutine_delay=0.0,
    ):
        connection_count = 0
        connections_per_coroutine = [0] * concurrency
        coroutine_indices = {}
        task_indices = {}
        original_open_connection = probe.asyncio.open_connection
        probe_coro_name = (
            "_run_persistent_probe_coro"
            if connection_mode == "persistent"
            else "_run_per_attempt_probe_coro"
        )
        original_probe_coro = getattr(probe, probe_coro_name)

        async def handle_echo(reader, writer):
            nonlocal connection_count
            connection_count += 1
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
                    if close_after_echo:
                        await asyncio.sleep(0.001)
                        break
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                writer.close()

        async def counted_open_connection(*args, **kwargs):
            task_index = task_indices.get(asyncio.current_task())
            reader, writer = await original_open_connection(*args, **kwargs)
            if task_index is not None:
                connections_per_coroutine[task_index] += 1
            return reader, writer

        async def delayed_probe_coro(*args, **kwargs):
            attempt_counter = args[6]
            index = coroutine_indices.setdefault(
                id(attempt_counter), len(coroutine_indices)
            )
            task_indices[asyncio.current_task()] = index
            if index in delayed_coroutines:
                await asyncio.sleep(coroutine_delay)
            return await original_probe_coro(*args, **kwargs)

        server = await asyncio.start_server(handle_echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        setattr(probe, probe_coro_name, delayed_probe_coro)
        probe.asyncio.open_connection = counted_open_connection
        try:
            args = SimpleNamespace(
                target="127.0.0.1",
                port=port,
                concurrency=concurrency,
                duration=duration,
                payload_bytes=16,
                connection_mode=connection_mode,
                min_interval_ms=min_interval_ms,
            )
            result = await _run(args)
        finally:
            probe.asyncio.open_connection = original_open_connection
            setattr(probe, probe_coro_name, original_probe_coro)
            server.close()
            await server.wait_closed()
        return result, connection_count, connections_per_coroutine

    def _assert_same_coroutine_reused_connection(
        self, result, connections_per_coroutine
    ):
        attempts_per_coroutine = result["totals"]["attempts_per_coroutine"]
        self.assertTrue(
            any(
                attempts >= 2 and connections == 1
                for attempts, connections in zip(
                    attempts_per_coroutine, connections_per_coroutine
                )
            ),
            "no coroutine made at least two attempts on its single connection",
        )

    async def test_persistent_mode_reuses_one_connection_per_coroutine(self):
        # G10 (#18737 triage): judge REUSE directly, not a completion count. At
        # loadavg ~30, 0.2 s gave fewer than 4 completions and the cell failed
        # with reuse intact. The property is that one coroutine made at least
        # two attempts over its single connection.
        # 0.5 s keeps that observable under load.
        result, connection_count, connections_per_coroutine = (
            await self._run_local_echo_probe(
                concurrency=3,
                duration=0.5,
                min_interval_ms=0.0,
            )
        )
        self.assertEqual(result["config"]["connection_mode"], "persistent")
        self.assertEqual(result["config"]["min_interval_ms"], 0.0)
        self._assert_same_coroutine_reused_connection(
            result, connections_per_coroutine
        )
        self.assertEqual(
            result["totals"]["attempted"],
            result["totals"]["completed"] + result["totals"]["errors"],
        )
        self.assertLessEqual(result["totals"]["error_rate"], 0.05)
        self.assertLessEqual(connection_count, 3)
        self.assertEqual(len(result["coroutines"]), 3)
        self.assertGreater(result["phase_us"]["read_us"]["count"], 0)
        self.assertGreater(result["phase_us"]["drain_us"]["count"], 0)
        self.assertIn("max_start_gap_us", result["coroutines"][0])

    async def test_reuse_assertion_rejects_skewed_progress_without_reuse(self):
        # Two coroutines start after the probe deadline. The active one makes
        # successful per-attempt connections to a server that closes after each
        # echo: the old aggregate predicate (attempts >= 2, connections <= 3)
        # says reuse happened, although each attempt uses a distinct connection.
        result, connection_count, connections_per_coroutine = (
            await self._run_local_echo_probe(
                concurrency=3,
                duration=0.6,
                min_interval_ms=250.0,
                connection_mode="per-attempt",
                close_after_echo=True,
                delayed_coroutines=(0, 1),
                coroutine_delay=0.7,
            )
        )
        attempts_per_coroutine = result["totals"]["attempts_per_coroutine"]
        self.assertEqual(attempts_per_coroutine[:2], [0, 0])
        active_attempts = attempts_per_coroutine[2]
        self.assertGreaterEqual(active_attempts, 2)
        self.assertEqual(connections_per_coroutine[:2], [0, 0])
        self.assertEqual(connections_per_coroutine[2], active_attempts)
        self.assertEqual(result["coroutines"][2]["completed"], active_attempts)
        self.assertEqual(connection_count, active_attempts)
        self.assertLessEqual(connection_count, 3)
        self.assertLessEqual(result["totals"]["error_rate"], 0.05)
        with self.assertRaisesRegex(AssertionError, "single connection"):
            self._assert_same_coroutine_reused_connection(
                result, connections_per_coroutine
            )

    async def test_min_interval_bounds_persistent_attempt_rate(self):
        # G10 (#18737 triage): judge the INTERVAL bound, not a completion count.
        # Load can only stretch the gaps and cut attempts. It cannot shorten a
        # gap or add an attempt, so the upper bound on attempts and the lower
        # bound on the start gap stay sound under load. The old ">= 3 completed
        # in 0.12 s" failed at loadavg ~30 with the bound intact. 0.3 s keeps
        # at least one gap observable.
        duration, interval_ms = 0.3, 20.0
        result, connection_count, _ = await self._run_local_echo_probe(
            concurrency=1,
            duration=duration,
            min_interval_ms=interval_ms,
        )
        self.assertEqual(result["config"]["min_interval_ms"], interval_ms)
        self.assertGreaterEqual(
            result["totals"]["completed"], 2, "no start gap was observable"
        )
        self.assertLessEqual(
            result["totals"]["attempted"],
            int(duration * 1000 / interval_ms) + 2,
        )
        self.assertLessEqual(connection_count, 1)
        self.assertGreater(result["phase_us"]["sleep_overshoot_us"]["count"], 0)
        self.assertGreaterEqual(result["phase_us"]["start_gap_us"]["max"], 15_000)
        self.assertGreaterEqual(
            result["phase_us"]["start_gap_us"]["p50"],
            15_000,
            "the median start gap is under the 20 ms min interval",
        )

    async def test_min_interval_bounds_per_attempt_rate(self):
        duration, interval_ms = 0.3, 20.0
        result, connection_count, _ = await self._run_local_echo_probe(
            concurrency=1,
            duration=duration,
            min_interval_ms=interval_ms,
            connection_mode="per-attempt",
        )
        self.assertEqual(result["config"]["connection_mode"], "per-attempt")
        self.assertEqual(result["config"]["min_interval_ms"], interval_ms)
        self.assertLessEqual(
            result["totals"]["attempted"],
            int(duration * 1000 / interval_ms) + 2,
        )
        self.assertEqual(
            result["totals"]["attempted"],
            result["totals"]["completed"] + result["totals"]["errors"],
        )
        self.assertGreaterEqual(connection_count, result["totals"]["completed"])
        self.assertGreater(result["phase_us"]["sleep_overshoot_us"]["count"], 0)
        self.assertGreater(
            result["phase_us"]["start_gap_us"]["count"],
            0,
            "no inter-attempt gap was observable",
        )
        self.assertGreaterEqual(result["phase_us"]["start_gap_us"]["max"], 15_000)
        self.assertGreaterEqual(
            result["phase_us"]["start_gap_us"]["p50"],
            15_000,
            "the median per-attempt start gap is under the 20 ms min interval",
        )

    async def _run_with_forced_drain_timeout(self, *, connection_mode):
        async def handle_echo(reader, writer):
            try:
                while await reader.read(4096):
                    writer.write(b"x")
                    await writer.drain()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                writer.close()

        async def forced_timeout(_writer, _deadline):
            raise asyncio.TimeoutError("forced drain timeout")

        server = await asyncio.start_server(handle_echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        original_drain = probe._drain_with_deadline
        probe._drain_with_deadline = forced_timeout
        try:
            args = SimpleNamespace(
                target="127.0.0.1",
                port=port,
                concurrency=1,
                duration=0.08,
                payload_bytes=16,
                connection_mode=connection_mode,
                min_interval_ms=20.0,
            )
            result = await asyncio.wait_for(_run(args), timeout=1.0)
        finally:
            probe._drain_with_deadline = original_drain
            server.close()
            await server.wait_closed()
        return result

    async def test_per_attempt_drain_timeout_counts_error_and_terminates(self):
        result = await self._run_with_forced_drain_timeout(
            connection_mode="per-attempt"
        )
        self.assertEqual(result["totals"]["completed"], 0)
        self.assertGreater(result["totals"]["attempted"], 0)
        self.assertEqual(
            result["totals"]["attempted"],
            result["totals"]["errors"],
        )
        self.assertGreater(result["phase_us"]["drain_us"]["count"], 0)

    async def test_persistent_drain_timeout_counts_error_and_terminates(self):
        result = await self._run_with_forced_drain_timeout(
            connection_mode="persistent"
        )
        self.assertEqual(result["totals"]["completed"], 0)
        self.assertGreater(result["totals"]["attempted"], 0)
        self.assertEqual(
            result["totals"]["attempted"],
            result["totals"]["errors"],
        )
        self.assertGreater(result["phase_us"]["drain_us"]["count"], 0)


if __name__ == "__main__":
    unittest.main()


class ConcentratedTailAttributionTests(unittest.TestCase):
    """#8277: the gate must be able to return FAIL on a concentrated tail.

    The degenerate-coroutine rule is a FAIRNESS predicate that was applied as a
    VALIDITY predicate. A mouse-latency gate under elephant load exists to
    detect a tail; when the tail is concentrated in a minority of flows, those
    flows necessarily complete far fewer transactions, so the rule fired on
    exactly the reps that demonstrated the phenomenon and the cell reported
    INSUFFICIENT-DATA. On master `d8a876042` a cell whose loaded p99.9 was
    740-1349 ms against a 6.66 ms idle baseline -- 111x to 202x against a 2.0
    gate -- reported INSUFFICIENT-DATA with 0 of 15 reps valid.

    EVERY FIXTURE HERE SHARES ONE `attempts_per_coroutine`. That is the point
    and it is what the issue's acceptance criterion asks for: the versions can
    only be told apart by a rep where the two ATTRIBUTIONS differ, so the
    starvation shape is held identical and only the phase maxima move. A
    fixture built from a uniform rep, or one where the shapes also differ,
    passes against both the old rule and the new one and proves nothing.
    """

    # The real shape, from #8277's recorded run: 100 coroutines, 13 starved at
    # ~150 attempts, 21 at ~2500, 66 at ~2900. median is 2900, so the threshold
    # is 1450 -- the 13 are starved and the 21 are not.
    STARVED_IDS = list(range(13))

    @classmethod
    def attempts(cls):
        return [150] * 13 + [2500] * 21 + [2900] * 66

    @classmethod
    def diagnostics(cls, starved_phase, starved_max=300_000):
        """One `coroutines[]` block, built the way production builds it.

        Goes through `coroutine_diagnostic_record` rather than hand-writing the
        dict so the `max_<phase>` key spelling is the production spelling. A
        hand-written fixture would keep passing if the producer renamed a key,
        while the real consumer silently lost its attribution.
        """
        out = []
        for i, attempted in enumerate(cls.attempts()):
            starved = i in cls.STARVED_IDS
            # A healthy coroutine: sub-millisecond echo, small client phases.
            phases = {
                "read_us": [800],
                "sleep_overshoot_us": [3_600],
                "drain_us": [69],
                "connect_us": [120],
                "start_gap_us": [40],
            }
            if starved:
                phases[starved_phase] = [starved_max]
            out.append(
                probe.coroutine_diagnostic_record(
                    i, attempted, attempted, 0, [starved_max if starved else 800], phases
                )
            )
        return out

    def test_echo_path_starvation_is_a_result_not_an_invalidation(self):
        """The phenomenon. Starved on `read_us` -> the rep is VALID."""
        v = compute_validity(
            100, self.attempts(), completed=sum(self.attempts()), errors=0,
            coroutine_diagnostics=self.diagnostics("read_us"),
        )
        self.assertTrue(
            v["ok"],
            f"a concentrated tail attributable to the echo path must be admitted "
            f"so the gate can FAIL on it; reasons={v['reasons']}",
        )
        self.assertNotIn("degenerate-coroutine", " ".join(v["reasons"]))
        # The admission is recorded, so a rep admitted DESPITE starvation is
        # distinguishable in probe.json from one with no starvation at all.
        self.assertEqual(v["starvation"]["verdict"], "concentrated-tail-is-a-result")
        self.assertEqual(v["starvation"]["starved_coroutines"], self.STARVED_IDS)
        self.assertEqual(v["starvation"]["attribution"], {"read_us": self.STARVED_IDS})

    def test_timer_wake_starvation_still_invalidates(self):
        """The artifact the rule was written for. Same shape, other cause."""
        v = compute_validity(
            100, self.attempts(), completed=sum(self.attempts()), errors=0,
            coroutine_diagnostics=self.diagnostics("sleep_overshoot_us"),
        )
        self.assertFalse(v["ok"], "client-side timer starvation must still invalidate")
        joined = " ".join(v["reasons"])
        self.assertIn("degenerate-coroutine", joined)
        self.assertIn("client-side=", joined)

    def test_socket_backpressure_starvation_still_invalidates(self):
        """The other client-side cause: local socket drain."""
        v = compute_validity(
            100, self.attempts(), completed=sum(self.attempts()), errors=0,
            coroutine_diagnostics=self.diagnostics("drain_us"),
        )
        self.assertFalse(v["ok"], "client-side socket backpressure must still invalidate")
        self.assertIn("client-side=", " ".join(v["reasons"]))

    def test_one_client_side_coroutine_invalidates_the_whole_rep(self):
        """The conservative direction, asserted rather than assumed.

        A rep is admitted only when EVERY starved coroutine is demonstrably on
        the echo path. Without this the change would weaken the original rule
        instead of narrowing it: a rep with one genuine client-side artifact
        among many real ones would be admitted, and the artifact is exactly what
        the rule exists to reject.
        """
        diags = self.diagnostics("read_us")
        # Flip a SINGLE starved coroutine to the client-side cause.
        contaminated = self.STARVED_IDS[0]
        diags[contaminated] = probe.coroutine_diagnostic_record(
            contaminated, 150, 150, 0, [300_000],
            {"read_us": [800], "sleep_overshoot_us": [300_000], "drain_us": [69],
             "connect_us": [120], "start_gap_us": [40]},
        )
        v = compute_validity(
            100, self.attempts(), completed=sum(self.attempts()), errors=0,
            coroutine_diagnostics=diags,
        )
        self.assertFalse(v["ok"])
        self.assertIn(f"client-side=[{contaminated}]", " ".join(v["reasons"]))

    def test_missing_diagnostics_keeps_the_pre_8277_behaviour(self):
        """No attribution data means no attribution -- invalidate, as before.

        This is the fail-safe direction, and it is why `coroutine_diagnostics`
        has no default value: a caller that cannot supply it must choose this
        behaviour explicitly rather than inherit it.
        """
        v = compute_validity(
            100, self.attempts(), completed=sum(self.attempts()), errors=0,
            coroutine_diagnostics=None,
        )
        self.assertFalse(v["ok"])
        self.assertIn("unattributable=", " ".join(v["reasons"]))

    def test_a_coroutine_that_recorded_no_phases_is_unattributable(self):
        """A starved coroutine that completed nothing records no phase maxima.

        It cannot be attributed, so it cannot be admitted. Without this the
        `max()` over an empty set would decide the rep.
        """
        diags = self.diagnostics("read_us")
        blank = self.STARVED_IDS[0]
        diags[blank] = probe.coroutine_diagnostic_record(
            blank, 150, 0, 150, [], {},
        )
        v = compute_validity(
            100, self.attempts(), completed=sum(self.attempts()), errors=0,
            coroutine_diagnostics=diags,
        )
        self.assertFalse(v["ok"])
        self.assertIn(f"unattributable=[{blank}]", " ".join(v["reasons"]))

    def test_uniform_rep_is_unaffected_in_both_directions(self):
        """CONTROL. No starvation at all -> valid, and no starvation block.

        Without this the change could be "delete the rule" and every assertion
        above would still pass. The uniform case is also the one the issue notes
        still FAILs correctly on its own -- the median moves with the min -- so
        it must keep reaching the verdict untouched.
        """
        attempts = [2900] * 100
        v = compute_validity(
            100, attempts, completed=sum(attempts), errors=0,
            coroutine_diagnostics=self.diagnostics("read_us"),
        )
        self.assertTrue(v["ok"], v["reasons"])
        self.assertNotIn("starvation", v)

    def test_the_admitted_rep_still_fails_every_other_gate_it_should(self):
        """Admission is narrow: it removes ONE reason, not the whole §4.2 set.

        The same echo-path-starved rep with a high error rate stays invalid. A
        change that admitted the concentrated tail by short-circuiting the
        remaining gates would pass every test above.
        """
        attempts = self.attempts()
        total = sum(attempts)
        v = compute_validity(
            100, attempts, completed=total - 5000, errors=5000,
            coroutine_diagnostics=self.diagnostics("read_us"),
        )
        self.assertFalse(v["ok"])
        self.assertTrue(any("error_rate" in r for r in v["reasons"]))
        self.assertFalse(any("degenerate-coroutine" in r for r in v["reasons"]))

    def test_the_probe_json_key_names_are_pinned_to_their_literals(self):
        """The `coroutines[]` key names are a published schema, not an internal detail.

        Found by mutation: renaming the format in `phase_max_key` moved the
        PRODUCER and the CONSUMER together, so every other cell in this class
        stayed green while `probe.json` silently emitted different key names.
        That is single-sourcing working as designed internally and losing a
        guarantee externally -- the derived name has no test, so the pinned
        literal the old hand-written dict provided was decommissioned by the
        refactor that replaced it.

        These three names are cited by number in #8277's acceptance criteria and
        appear in the recorded analyses under docs/log/, so a rename would
        invalidate the vocabulary of every historical run without failing
        anything. Pinned here as an alias check: single-sourced in the code,
        literal in the test.
        """
        rec = probe.coroutine_diagnostic_record(
            0, 10, 10, 0, [800],
            {"read_us": [800], "sleep_overshoot_us": [10], "drain_us": [5],
             "connect_us": [120], "start_gap_us": [40]},
        )
        for literal in ("max_read_us", "max_sleep_overshoot_us", "max_drain_us"):
            self.assertIn(
                literal, rec,
                f"probe.json's per-coroutine block must carry {literal!r} verbatim",
            )
        # And the consumer must read the SAME literals, or the attribution
        # silently degrades to "unattributable" and #8277's defect returns.
        self.assertEqual(probe.attribute_starvation(rec), "read_us")
