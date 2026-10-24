#!/usr/bin/env python3
"""Unit tests for step2-sched-switch-classify.py (#821 V7 gate).

Covers:
 - IN verdict on synthetic correlated input with duty >= 1%
 - OUT verdict on anti-correlated input OR low duty
 - INCONCLUSIVE verdict on borderline input
 - meta.json schema (required keys, types)
 - WARN aggregation from off-cpu JSONL

Run:
    python3 test/incus/step2-sched-switch-classify_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from load_subject import load_subject  # noqa: E402


_HERE = Path(__file__).resolve().parent
_CLASSIFY_PATH = _HERE / "step2-sched-switch-classify.py"



C = load_subject("step2_sched_switch_classify", str(_CLASSIFY_PATH))


def _write_jsonl(objs: list[dict]) -> Path:
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    buf = ("\n".join(json.dumps(o) for o in objs) + "\n").encode()
    os.write(fd, buf)
    os.close(fd)
    return Path(path)


def _hist_blocks_with_shape3to6(values: list[float]) -> list[dict]:
    """Synthesize 12 hist-block dicts with shape[3..6] summing to `values[b]`.

    We place the full per-block value in shape[3] and zero elsewhere for
    simplicity.  T_D1,b will equal values[b] exactly.
    """
    assert len(values) == 12
    out = []
    for b, v in enumerate(values):
        shape = [0.0] * 16
        shape[3] = v
        out.append(
            {
                "b": b,
                "count_delta": 10000,
                "buckets": [0] * 16,
                "shape": shape,
                "tx_packets_delta": 1000,
            }
        )
    return out


def _off_cpu_blocks(
    off_times: list[int],
    stat: list[str] | None = None,
    vol_of: float = 0.5,
    block_span_ns: int | None = None,
) -> list[dict]:
    """Synthesize 12 off-cpu reducer dicts.

    `stat[b]` is "PASS" or "WARN"; defaults to all PASS.  The off time
    is placed entirely in bucket 3 (so the reducer invariant holds).
    When `block_span_ns` is given each block carries it (C175-HC-092
    real-window duty); otherwise the field is omitted (legacy JSONL).
    """
    assert len(off_times) == 12
    if stat is None:
        stat = ["PASS"] * 12
    out = []
    for b, t in enumerate(off_times):
        buckets = [0] * 16
        buckets[3] = t
        vol = int(t * vol_of)
        invol = t - vol
        blk = {
            "b": b,
            "buckets": buckets,
            "off_cpu_time_3to6": t,
            "voluntary_3to6": vol,
            "involuntary_3to6": invol,
            "stat_runtime_check": stat[b],
        }
        if block_span_ns is not None:
            blk["block_span_ns"] = block_span_ns
        out.append(blk)
    return out


def _run_classifier(
    hist_blocks: list[dict], off_blocks: list[dict], cell: str = "test/cell"
) -> tuple[int, dict]:
    rc, meta, _diag = _run_classifier_with_diag(hist_blocks, off_blocks, cell)
    return rc, meta


def _run_classifier_with_diag(
    hist_blocks: list[dict], off_blocks: list[dict], cell: str = "test/cell"
) -> tuple[int, dict, dict]:
    h_path = _write_jsonl(hist_blocks)
    o_path = _write_jsonl(off_blocks)
    out_dir = Path(tempfile.mkdtemp())
    out_md = out_dir / "correlation-report.md"
    try:
        rc = C.main(
            [
                "--hist-blocks", str(h_path),
                "--off-cpu", str(o_path),
                "--cell", cell,
                "--out", str(out_md),
            ]
        )
        meta_path = out_dir / "correlation-report.meta.json"
        diag_path = out_dir / "correlation-report.diag.json"
        meta = json.loads(meta_path.read_text())
        diag = json.loads(diag_path.read_text()) if diag_path.exists() else {}
    finally:
        h_path.unlink()
        o_path.unlink()
    return rc, meta, diag


class TestClassifyVerdicts(unittest.TestCase):
    def test_verdict_IN_correlated_and_high_duty(self):
        """High rho + high duty-cycle -> IN."""
        # Correlated ramps: shape[3] grows as off-cpu time grows.
        # off times chosen so sum = 3 s = 5 % duty on 60 s nominal.
        off_times = [int((b + 1) * 250_000_000) for b in range(12)]
        # sum = 250M * (1+2+..+12) = 250M * 78 = 19.5 G = 32.5 % duty
        shape_vals = [float(b + 1) * 0.01 for b in range(12)]  # strictly increasing
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertEqual(meta["verdict"], "IN", f"meta={meta}")
        self.assertGreaterEqual(meta["rho"], 0.8)
        self.assertGreaterEqual(meta["duty_cycle_pct"], 1.0)

    def test_verdict_OUT_low_duty_regardless_of_rho(self):
        """duty < 1% -> OUT even with perfect rho."""
        off_times = [1_000_000 for _ in range(12)]  # 12 ms total = 0.02 %
        shape_vals = [float(b + 1) for b in range(12)]  # correlated
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertEqual(meta["verdict"], "OUT", f"meta={meta}")
        self.assertLess(meta["duty_cycle_pct"], 1.0)

    def test_verdict_OUT_low_rho(self):
        """rho <= 0.3 -> OUT (even with high duty)."""
        # Anti-correlated: hist increasing, off decreasing.
        off_times = [int((12 - b) * 500_000_000) for b in range(12)]
        shape_vals = [float(b + 1) for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertEqual(meta["verdict"], "OUT", f"meta={meta}")
        self.assertLessEqual(meta["rho"], 0.3)

    def test_verdict_INCONCLUSIVE_midrange_rho(self):
        """0.3 < rho < 0.8 and duty >= 1% -> INCONCLUSIVE.

        We construct an input whose Spearman rho lands in the middle.
        Easiest approach: partial correlation via a permutation pattern.
        """
        # Shapes: 1..12 (rank: 1..12).
        # Off-cpu ranks: (6,1,2,3,4,5,7,8,9,10,11,12) - one swap from
        # perfect -> Spearman rho ~ 1 - 6d^2/(n(n^2-1)).
        # d_i = rank(x_i) - rank(y_i).  With pattern [6,1,2,3,4,5,7,...]:
        # ranks of y: [6,1,2,3,4,5,7,8,9,10,11,12] (already ranks).
        # d = (1-6,2-1,3-2,4-3,5-4,6-5,7-7,...) = (-5,1,1,1,1,1,0,0,0,0,0,0)
        # sum d^2 = 25+1+1+1+1+1 = 30.  n=12, n(n^2-1)=1716.
        # rho = 1 - 6*30/1716 = 1 - 0.1049 = 0.8951 -> still IN.
        #
        # Heavier swap: [12,11,1,2,3,4,5,6,7,8,9,10] (two swaps at head)
        # -> still high rho; not what we want.  Use random-ish pattern.
        # d pattern to hit rho ~ 0.5:
        # Want 1 - 6*sum(d^2)/1716 = 0.5 -> sum(d^2) = 143.
        # Use pattern: [4,2,6,1,3,5,7,12,9,11,8,10].  Compute sum(d^2).
        off_pattern = [4, 2, 6, 1, 3, 5, 7, 12, 9, 11, 8, 10]
        # Verify by calculation:
        d = [off_pattern[i] - (i + 1) for i in range(12)]
        sum_d2 = sum(x * x for x in d)
        expected_rho = 1.0 - 6 * sum_d2 / (12 * (12 * 12 - 1))
        # If it's not mid-range, the test harness is stale; tweak pattern.
        # We'll assert the computed verdict matches our expectation.
        off_times = [p * 500_000_000 for p in off_pattern]
        shape_vals = [float(b + 1) for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        # duty check: sum = 500M * 78 = 39 G = 65 % -> plenty
        self.assertGreaterEqual(meta["duty_cycle_pct"], 1.0)
        # Classify rho bucket.
        rho = meta["rho"]
        if rho >= 0.8:
            self.assertEqual(meta["verdict"], "IN")
        elif rho <= 0.3:
            self.assertEqual(meta["verdict"], "OUT")
        else:
            self.assertEqual(meta["verdict"], "INCONCLUSIVE")
        # For this hand-tuned pattern, confirm we got INCONCLUSIVE.
        self.assertGreater(rho, 0.3)
        self.assertLess(rho, 0.8)
        self.assertEqual(meta["verdict"], "INCONCLUSIVE")


class TestClassifyDutyWindow(unittest.TestCase):
    """C175-HC-092: duty-cycle uses the actual capture window."""

    def test_duty_uses_summed_block_span_not_fixed_60s(self):
        # Total off-CPU = 0.6 s. Blocks are 7 s each -> 84 s window ->
        # duty = 0.6 / 84 = 0.714 %.  Against the old fixed 60 s
        # denominator it would read 0.6 / 60 = 1.0 %.  The two land on
        # opposite sides of the 1.0 % IN/OUT threshold, so the real
        # window MUST be used.
        off_times = [50_000_000 for _ in range(12)]  # 12 * 50 ms = 0.6 s
        shape_vals = [float(b + 1) for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times, block_span_ns=7_000_000_000)
        rc, meta, diag = _run_classifier_with_diag(hist, off)
        self.assertEqual(rc, 0)
        # 84 s window -> ~0.714 %, NOT the 1.0 % a fixed 60 s would give.
        self.assertAlmostEqual(meta["duty_cycle_pct"], 100.0 * 0.6 / 84.0, places=4)
        self.assertLess(meta["duty_cycle_pct"], 1.0)
        self.assertEqual(diag["window_ns"], 84_000_000_000)

    def test_missing_block_span_falls_back_to_nominal_60s(self):
        # Legacy JSONL without block_span_ns keeps the 60 s nominal window.
        off_times = [50_000_000 for _ in range(12)]  # 0.6 s
        shape_vals = [float(b + 1) for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)  # no block_span_ns
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertAlmostEqual(meta["duty_cycle_pct"], 100.0 * 0.6 / 60.0, places=4)


class TestClassifyInsufficientEvidence(unittest.TestCase):
    """C175-HC-070: no-evidence input is INSUFFICIENT, not a definitive OUT."""

    def test_all_zero_blocks_are_insufficient_not_out(self):
        # Mirror empty-reducer output: every bucket 0, every
        # stat_runtime_check WARN. Fail-on-revert: the pre-fix classifier
        # computed duty 0 < 1% -> OUT, exit 0.
        off_times = [0] * 12
        shape_vals = [0.0] * 12
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times, stat=["WARN"] * 12)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 2)
        self.assertEqual(meta["verdict"], "INSUFFICIENT")

    def test_legit_low_duty_with_runtime_passes_still_out(self):
        # A real capture with some passing stat_runtime blocks and small
        # off-CPU is a genuine OUT (not insufficient) and stays exit 0.
        off_times = [1_000_000 for _ in range(12)]  # tiny but non-zero
        shape_vals = [float(b + 1) for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times, stat=["PASS"] * 12)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertEqual(meta["verdict"], "OUT")


class TestClassifyMetaSchema(unittest.TestCase):
    def test_meta_json_schema(self):
        """LOW-5 R4: top-level keys are EXACTLY the plan §3.1 step 11
        contract ({verdict, rho, pvalue, duty_cycle_pct, warn_blocks}).
        No extras at top level. Diagnostic data lives in a sibling
        `correlation-report.diag.json` file.
        """
        off_times = [int((b + 1) * 250_000_000) for b in range(12)]
        shape_vals = [float(b + 1) * 0.01 for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        rc, meta, diag = _run_classifier_with_diag(hist, off, cell="slug/under/test")
        self.assertEqual(rc, 0)
        # Plan-contracted top-level keys — EXACT set (no diagnostic).
        self.assertEqual(
            set(meta.keys()),
            {"verdict", "rho", "pvalue", "duty_cycle_pct", "warn_blocks"},
            f"meta.json has extra keys: {set(meta.keys())}",
        )
        self.assertIn(meta["verdict"], ("IN", "OUT", "INCONCLUSIVE", "SUSPECT"))
        # Diagnostic extras now live in sibling .diag.json.
        diag_required = [
            "cell",
            "reason",
            "T_D1",
            "off_cpu_time_3to6",
            "voluntary_total_ns",
            "involuntary_total_ns",
            "n_blocks",
            "rho_in",
            "rho_out",
            "duty_in_pct",
            "duty_out_pct",
            "nominal_window_ns",
        ]
        for k in diag_required:
            self.assertIn(k, diag, f"missing diag key: {k}")
        self.assertEqual(diag["cell"], "slug/under/test")
        self.assertEqual(diag["n_blocks"], 12)
        self.assertEqual(len(diag["T_D1"]), 12)
        self.assertEqual(len(diag["off_cpu_time_3to6"]), 12)
        # `suspect_reason` lives in diag (not meta), null when no drift.
        self.assertIsNone(diag.get("suspect_reason"))


class TestClassifyWarnAggregation(unittest.TestCase):
    def test_warn_block_aggregation(self):
        off_times = [int((b + 1) * 250_000_000) for b in range(12)]
        shape_vals = [float(b + 1) * 0.01 for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        stat = ["PASS"] * 12
        stat[0] = "WARN"
        stat[5] = "WARN"
        stat[11] = "WARN"
        off = _off_cpu_blocks(off_times, stat=stat)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(meta["warn_blocks"]), [0, 5, 11])


class TestVerdictHelper(unittest.TestCase):
    def test_verdict_from_degenerate_rho(self):
        v, _ = C.verdict_from(None, 50.0)
        self.assertEqual(v, "INCONCLUSIVE")

    def test_verdict_from_rules_boundary(self):
        # rho=0.8, duty=1.0 -> IN (>= in both)
        v, _ = C.verdict_from(0.8, 1.0)
        self.assertEqual(v, "IN")
        # rho=0.3, duty=50 -> OUT
        v, _ = C.verdict_from(0.3, 50.0)
        self.assertEqual(v, "OUT")
        # rho=0.5, duty=5.0 -> INCONCLUSIVE
        v, _ = C.verdict_from(0.5, 5.0)
        self.assertEqual(v, "INCONCLUSIVE")
        # rho=0.9, duty=0.5 -> OUT (low duty)
        v, _ = C.verdict_from(0.9, 0.5)
        self.assertEqual(v, "OUT")

    def test_verdict_from_suspect_short_circuits(self):
        """HIGH-2: suspect_reason short-circuits to SUSPECT regardless
        of otherwise-valid rho/duty values.
        """
        v, reason = C.verdict_from(0.9, 5.0, suspect_reason="drift_ge_5s")
        self.assertEqual(v, "SUSPECT")
        self.assertIn("drift_ge_5s", reason)
        # Even a low-duty capture flips to SUSPECT (drift dominates).
        v, _ = C.verdict_from(0.9, 0.1, suspect_reason="drift_ge_5s")
        self.assertEqual(v, "SUSPECT")
        # And with rho=None.
        v, _ = C.verdict_from(None, 50.0, suspect_reason="drift_ge_5s")
        self.assertEqual(v, "SUSPECT")


class TestClassifySuspectFromReducer(unittest.TestCase):
    """HIGH-2: integration — reducer stamps `suspect_reason` on its
    JSONL; classifier emits verdict=SUSPECT end-to-end.
    """

    def test_verdict_SUSPECT_when_reducer_marks_drift(self):
        off_times = [int((b + 1) * 250_000_000) for b in range(12)]
        shape_vals = [float(b + 1) * 0.01 for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        # Stamp suspect_reason on EVERY block (mirroring reducer output).
        for blk in off:
            blk["suspect_reason"] = "drift_ge_5s"
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertEqual(meta["verdict"], "SUSPECT")
        self.assertNotIn("suspect_reason", meta)  # LOW-5 R4: moved to sibling .diag.json
        self.assertNotIn("diagnostic", meta)

    def test_verdict_SUSPECT_from_drift_halt_marker(self):
        """Optional `--drift-halt-marker` path: operator can force
        SUSPECT out-of-band (e.g. capture harness detected the drift
        halt before even running the classifier).
        """
        off_times = [int((b + 1) * 250_000_000) for b in range(12)]
        shape_vals = [float(b + 1) * 0.01 for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        # Write a marker file.
        marker_fd, marker_path = tempfile.mkstemp(suffix=".txt")
        os.write(marker_fd, b"drift_ge_5s\n")
        os.close(marker_fd)
        h_path = _write_jsonl(hist)
        o_path = _write_jsonl(off)
        out_dir = Path(tempfile.mkdtemp())
        out_md = out_dir / "correlation-report.md"
        try:
            rc = C.main(
                [
                    "--hist-blocks", str(h_path),
                    "--off-cpu", str(o_path),
                    "--cell", "test/cell",
                    "--out", str(out_md),
                    "--drift-halt-marker", marker_path,
                ]
            )
            meta = json.loads(
                (out_dir / "correlation-report.meta.json").read_text()
            )
        finally:
            Path(marker_path).unlink()
            h_path.unlink()
            o_path.unlink()
        self.assertEqual(rc, 0)
        self.assertEqual(meta["verdict"], "SUSPECT")
        self.assertNotIn("suspect_reason", meta)  # LOW-5 R4: moved to sibling .diag.json
        self.assertNotIn("diagnostic", meta)


if __name__ == "__main__":
    unittest.main()
