import asyncio
import unittest
from types import SimpleNamespace

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
        v = compute_validity(10, attempts, completed=5970, errors=30)
        self.assertTrue(v["ok"], v["reasons"])

    def test_error_rate_too_high(self):
        attempts = [600] * 10
        # 200/6000 = 3.3% > 1%
        v = compute_validity(10, attempts, completed=5800, errors=200)
        self.assertFalse(v["ok"])
        self.assertTrue(any("error_rate" in r for r in v["reasons"]))

    def test_degenerate_coroutine_min_attempts(self):
        # 9 coroutines did 600, one did 200; median=600, min=200 < 300
        attempts = [600] * 9 + [200]
        v = compute_validity(10, attempts, completed=5790, errors=10)
        self.assertFalse(v["ok"])
        self.assertTrue(any("degenerate-coroutine" in r for r in v["reasons"]))

    def test_below_min_attempts_floor_m10(self):
        attempts = [400] * 10  # 4000 total, M=10 floor=5000
        v = compute_validity(10, attempts, completed=4000, errors=0)
        self.assertFalse(v["ok"])
        self.assertTrue(any("min-attempts" in r for r in v["reasons"]))

    def test_min_attempts_floor_m1(self):
        # M=1: floor=500
        v_pass = compute_validity(1, [500], completed=500, errors=0)
        self.assertTrue(v_pass["ok"], v_pass["reasons"])
        v_fail = compute_validity(1, [499], completed=499, errors=0)
        self.assertFalse(v_fail["ok"])
        self.assertTrue(any("min-attempts" in r for r in v_fail["reasons"]))

    def test_m1_skips_degenerate_check(self):
        # Single coroutine cannot be "degenerate vs median" — gate
        # is concurrency >= 2.
        v = compute_validity(1, [600], completed=600, errors=0)
        self.assertTrue(v["ok"])

    def test_boundary_m10_exactly_5000(self):
        attempts = [500] * 10  # exactly 5000
        v = compute_validity(10, attempts, completed=5000, errors=0)
        self.assertTrue(v["ok"], v["reasons"])

    def test_boundary_m10_exactly_4999(self):
        attempts = [500] * 9 + [499]
        # min=499 vs median=500 → 499 >= 0.5*500=250 → not degenerate.
        # Total=4999 < 5000 → fails min-attempts.
        v = compute_validity(10, attempts, completed=4999, errors=0)
        self.assertFalse(v["ok"])

    def test_boundary_m1_exactly_500(self):
        v = compute_validity(1, [500], completed=500, errors=0)
        self.assertTrue(v["ok"])

    def test_inconsistent_counts_completed_more_than_attempted(self):
        # Copilot R1 #4: surface the bookkeeping invariant rather
        # than letting completed go unused.
        v = compute_validity(10, [600] * 10, completed=7000, errors=0)
        self.assertFalse(v["ok"])
        self.assertTrue(any("inconsistent-counts" in r for r in v["reasons"]))

    def test_inconsistent_counts_completed_plus_errors_neq_attempted(self):
        # 6000 attempts, 5500 completed, 100 errors → 5600 ≠ 6000
        v = compute_validity(10, [600] * 10, completed=5500, errors=100)
        self.assertFalse(v["ok"])
        self.assertTrue(any("inconsistent-counts" in r for r in v["reasons"]))


class PersistentConnectionModeTests(unittest.IsolatedAsyncioTestCase):
    async def _run_local_echo_probe(
        self,
        *,
        concurrency,
        duration,
        min_interval_ms,
        connection_mode="persistent",
    ):
        connection_count = 0

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
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                writer.close()

        server = await asyncio.start_server(handle_echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
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
            server.close()
            await server.wait_closed()
        return result, connection_count

    async def test_persistent_mode_reuses_one_connection_per_coroutine(self):
        result, connection_count = await self._run_local_echo_probe(
            concurrency=3,
            duration=0.2,
            min_interval_ms=0.0,
        )
        self.assertEqual(result["config"]["connection_mode"], "persistent")
        self.assertEqual(result["config"]["min_interval_ms"], 0.0)
        self.assertGreater(result["totals"]["completed"], 3)
        self.assertEqual(
            result["totals"]["attempted"],
            result["totals"]["completed"] + result["totals"]["errors"],
        )
        self.assertLessEqual(result["totals"]["error_rate"], 0.05)
        self.assertLessEqual(connection_count, 3)

    async def test_min_interval_bounds_persistent_attempt_rate(self):
        result, connection_count = await self._run_local_echo_probe(
            concurrency=1,
            duration=0.12,
            min_interval_ms=20.0,
        )
        self.assertEqual(result["config"]["min_interval_ms"], 20.0)
        self.assertGreaterEqual(result["totals"]["completed"], 3)
        self.assertLessEqual(result["totals"]["attempted"], 8)
        self.assertLessEqual(connection_count, 1)

    async def test_min_interval_bounds_per_attempt_rate(self):
        result, connection_count = await self._run_local_echo_probe(
            concurrency=1,
            duration=0.12,
            min_interval_ms=20.0,
            connection_mode="per-attempt",
        )
        self.assertEqual(result["config"]["connection_mode"], "per-attempt")
        self.assertEqual(result["config"]["min_interval_ms"], 20.0)
        self.assertGreaterEqual(result["totals"]["completed"], 3)
        self.assertLessEqual(result["totals"]["attempted"], 8)
        self.assertEqual(
            result["totals"]["attempted"],
            result["totals"]["completed"] + result["totals"]["errors"],
        )
        self.assertGreaterEqual(connection_count, result["totals"]["completed"])


if __name__ == "__main__":
    unittest.main()
