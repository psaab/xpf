import json
import os
import tempfile
import unittest

from mouse_latency_aggregate import (
    decide,
    has_invalid_marker,
    load_cell_reps,
    median_rep_by_p99,
    select_valid_reps,
    summarize_cell,
)


def _make_rep(p99: int, ok: bool = True, p50: int = 100, p95: int = 500, rps: float = 200.0) -> dict:
    return {
        "rtt_us": {"p50": p50, "p95": p95, "p99": p99, "p999": p99 + 10},
        "totals": {"achieved_rps_total": rps, "attempts_per_coroutine": [600] * 10},
        "validity": {"ok": ok, "reasons": []},
    }


class SelectValidRepsTests(unittest.TestCase):
    def test_filters_invalid(self):
        reps = [_make_rep(100), _make_rep(200, ok=False), _make_rep(300)]
        self.assertEqual(len(select_valid_reps(reps)), 2)


class MedianByP99Tests(unittest.TestCase):
    def test_median_of_10(self):
        reps = [_make_rep(p99) for p99 in range(100, 200, 10)]
        # p99 values 100..190; sorted center is at index 5 → value 150.
        m = median_rep_by_p99(reps)
        self.assertEqual(m["rtt_us"]["p99"], 150)

    def test_median_of_3(self):
        reps = [_make_rep(100), _make_rep(300), _make_rep(200)]
        m = median_rep_by_p99(reps)
        self.assertEqual(m["rtt_us"]["p99"], 200)

    def test_empty(self):
        self.assertIsNone(median_rep_by_p99([]))


class SummarizeCellTests(unittest.TestCase):
    def test_insufficient_valid_reps(self):
        # Only 5 valid → INSUFFICIENT-DATA
        reps = [_make_rep(100) for _ in range(5)]
        s = summarize_cell(reps)
        self.assertEqual(s["status"], "INSUFFICIENT-DATA")

    def test_ok_with_10_valid(self):
        reps = [_make_rep(p99=100 + 10 * i) for i in range(10)]
        s = summarize_cell(reps)
        self.assertEqual(s["status"], "OK")
        self.assertIsNotNone(s["median_rep"])
        self.assertIsNotNone(s["iqr_p99_across_reps"])

    def test_excludes_invalid_from_median(self):
        # 7 valid + 3 invalid; the invalid ones with extreme p99 must
        # not contribute to the median.
        valid = [_make_rep(p99=100 + 10 * i) for i in range(7)]
        invalid = [_make_rep(p99=99999, ok=False) for _ in range(3)]
        s = summarize_cell(valid + invalid)
        self.assertEqual(s["status"], "OK")
        # Median p99 of 100..160 is at index 3 → 130.
        self.assertEqual(s["median_rep"]["p99_us"], 130)


class DecideTests(unittest.TestCase):
    def _gate_summaries(self, p99_idle: int, p99_loaded: int):
        idle = summarize_cell([_make_rep(p99=p99_idle) for _ in range(10)])
        loaded = summarize_cell([_make_rep(p99=p99_loaded) for _ in range(10)])
        return {(0, 10): idle, (128, 10): loaded}

    def test_pass_at_2x(self):
        # p99 idle 100, loaded 200 → ratio 2.0 → PASS (≤ 2)
        summaries = self._gate_summaries(100, 200)
        v = decide(summaries)
        self.assertEqual(v["verdict"], "PASS")
        self.assertAlmostEqual(v["ratio"], 2.0)

    def test_fail_above_2x(self):
        summaries = self._gate_summaries(100, 250)
        v = decide(summaries)
        self.assertEqual(v["verdict"], "FAIL")
        self.assertAlmostEqual(v["ratio"], 2.5)

    def test_pass_well_under_2x(self):
        summaries = self._gate_summaries(100, 150)
        v = decide(summaries)
        self.assertEqual(v["verdict"], "PASS")

    def test_custom_100e100m_gate_uses_requested_cell(self):
        idle = summarize_cell([_make_rep(p99=100) for _ in range(10)])
        loaded = summarize_cell([_make_rep(p99=190) for _ in range(10)])
        summaries = {(0, 100): idle, (100, 100): loaded}
        v = decide(summaries, gate_elephants=100, gate_mice=100)
        self.assertEqual(v["verdict"], "PASS")
        self.assertIn("N=100, M=100", v["gate"])

    def test_custom_gate_percentile(self):
        idle = summarize_cell([_make_rep(p99=100) for _ in range(10)])
        loaded = summarize_cell([_make_rep(p99=100) for _ in range(10)])
        # p999 is p99+10 from _make_rep, so the ratio is 210/110.
        loaded["median_rep"]["p999_us"] = 210
        summaries = {(0, 100): idle, (100, 100): loaded}
        v = decide(
            summaries,
            gate_elephants=100,
            gate_mice=100,
            gate_percentile="p999_us",
            threshold_ratio=1.5,
        )
        self.assertEqual(v["verdict"], "FAIL")

    def test_missing_gate_cell(self):
        v = decide({(0, 10): summarize_cell([_make_rep(100)] * 10)})
        self.assertEqual(v["verdict"], "INSUFFICIENT-DATA")

    def test_insufficient_data_in_gate(self):
        # Loaded gate cell has only 5 valid reps → INSUFFICIENT-DATA
        idle = summarize_cell([_make_rep(p99=100) for _ in range(10)])
        loaded = summarize_cell([_make_rep(p99=100) for _ in range(5)])
        v = decide({(0, 10): idle, (128, 10): loaded})
        self.assertEqual(v["verdict"], "INSUFFICIENT-DATA")


class LoadCellRepsInvalidMarkerTests(unittest.TestCase):
    def _setup_cell(self, tmpdir: str):
        cell_dir = os.path.join(tmpdir, "cell_N0_M10")
        os.makedirs(cell_dir)
        return cell_dir

    def _write_rep(self, cell_dir: str, idx: int, ok: bool = True, marker: str = ""):
        rep_dir = os.path.join(cell_dir, f"rep_{idx:02d}")
        os.makedirs(rep_dir)
        with open(os.path.join(rep_dir, "probe.json"), "w") as f:
            json.dump({
                "rtt_us": {"p50": 100, "p95": 500, "p99": 1000},
                "totals": {"achieved_rps_total": 200.0, "attempts_per_coroutine": [600] * 10},
                "validity": {"ok": ok, "reasons": []},
            }, f)
        if marker:
            open(os.path.join(rep_dir, f"INVALID-{marker}"), "w").close()
        return rep_dir

    def test_marker_overrides_probe_ok(self):
        with tempfile.TemporaryDirectory() as t:
            cell_dir = self._setup_cell(t)
            self._write_rep(cell_dir, 0, ok=True, marker="ha-transition")
            reps = load_cell_reps(cell_dir)
            self.assertEqual(len(reps), 1)
            self.assertFalse(reps[0]["validity"]["ok"])
            self.assertTrue(any("ha-transition" in r for r in reps[0]["validity"]["reasons"]))

    def test_no_marker_keeps_probe_ok(self):
        with tempfile.TemporaryDirectory() as t:
            cell_dir = self._setup_cell(t)
            self._write_rep(cell_dir, 0, ok=True)
            reps = load_cell_reps(cell_dir)
            self.assertTrue(reps[0]["validity"]["ok"])

    def test_missing_probe_json(self):
        # Orchestrator died before probe ran or pull failed: synthesize invalid.
        with tempfile.TemporaryDirectory() as t:
            cell_dir = self._setup_cell(t)
            os.makedirs(os.path.join(cell_dir, "rep_00"))
            reps = load_cell_reps(cell_dir)
            self.assertEqual(len(reps), 1)
            self.assertFalse(reps[0]["validity"]["ok"])

    def test_missing_probe_with_invalid_marker_keeps_marker(self):
        # R2 HIGH 1 partial: when probe.json is missing AND there's an
        # orchestrator INVALID-* marker (e.g. cwnd-not-settled), the
        # marker reason must survive — otherwise we lose attribution.
        with tempfile.TemporaryDirectory() as t:
            cell_dir = self._setup_cell(t)
            rep_dir = os.path.join(cell_dir, "rep_00")
            os.makedirs(rep_dir)
            open(os.path.join(rep_dir, "INVALID-cwnd-not-settled"), "w").close()
            reps = load_cell_reps(cell_dir)
            self.assertEqual(len(reps), 1)
            reasons = reps[0]["validity"]["reasons"]
            self.assertIn("no-probe-json", reasons)
            self.assertTrue(any("cwnd-not-settled" in r for r in reasons))

    def test_has_invalid_marker(self):
        with tempfile.TemporaryDirectory() as t:
            d = os.path.join(t, "rep")
            os.makedirs(d)
            self.assertFalse(has_invalid_marker(d))
            open(os.path.join(d, "INVALID-rg-state-flap"), "w").close()
            self.assertTrue(has_invalid_marker(d))


if __name__ == "__main__":
    unittest.main()
