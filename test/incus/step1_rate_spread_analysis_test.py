#!/usr/bin/env python3
"""Tests for step1-rate-spread-analysis.py (#4907 / C175-HC-128).

Guards the evidence-completeness checks: Threshold Y must not be derived
from a cell with the wrong stream count, from a cell with malformed
sender rates, or from a run where some requested cells are missing.

Run:
    python3 test/incus/step1-rate-spread-analysis_test.py
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from load_subject import load_subject  # noqa: E402


_HERE = Path(__file__).resolve().parent
_MOD_PATH = _HERE / "step1-rate-spread-analysis.py"



RS = load_subject("step1_rate_spread_analysis", str(_MOD_PATH))


def _iperf3_json(rates: list) -> dict:
    return {"end": {"streams": [{"sender": {"bits_per_second": r}} for r in rates]}}


def _write_cell(d: Path, name: str, rates: list) -> Path:
    p = d / f"{name}.json"
    p.write_text(json.dumps(_iperf3_json(rates)))
    return p


class LoadPerFlowRatesTests(unittest.TestCase):
    def test_exact_16_loads(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            p = _write_cell(d, "p5201-fwd", [1e9] * 16)
            rates = RS.load_per_flow_rates(p)
            self.assertEqual(len(rates), 16)

    def test_partial_stream_count_raises(self):
        # C175-HC-128 fail-on-revert: a truncated cell (2 of 16 streams)
        # previously computed a ratio; now it must raise.
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            p = _write_cell(d, "p5201-fwd", [1e9, 2e9])
            with self.assertRaises(RS.RateSpreadError):
                RS.load_per_flow_rates(p)

    def test_malformed_sender_bps_raises(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            # 16 streams but one has a zero/None sender rate (partly failed).
            rates = [1e9] * 15 + [0]
            p = _write_cell(d, "p5201-fwd", rates)
            with self.assertRaises(RS.RateSpreadError):
                RS.load_per_flow_rates(p)

    def test_expected_streams_none_disables_count_check(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            p = _write_cell(d, "p5201-fwd", [1e9, 2e9, 3e9])
            rates = RS.load_per_flow_rates(p, expected_streams=None)
            self.assertEqual(len(rates), 3)


class MainTests(unittest.TestCase):
    def _run(self, cells: list, evidence_dir: Path) -> int:
        argv = [
            "--evidence-dir",
            str(evidence_dir),
            "--cells",
            *cells,
            "--bootstrap-trials",
            "0",
        ]
        return RS.main(argv)

    def test_missing_cell_fails(self):
        # C175-HC-128 fail-on-revert: a missing requested cell previously
        # WARN'd and Y was derived from whichever cells existed. Now the
        # run must exit non-zero.
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            _write_cell(d, "p5201-fwd", [1e9] * 16)
            _write_cell(d, "p5202-fwd", [1e9] * 16)
            # p5203-fwd and p5204-fwd are absent.
            err = io.StringIO()
            with redirect_stderr(err):
                rc = self._run(
                    ["p5201-fwd", "p5202-fwd", "p5203-fwd", "p5204-fwd"], d
                )
            self.assertEqual(rc, 2)
            self.assertIn("missing cell file", err.getvalue())

    def test_partial_cell_fails(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            _write_cell(d, "p5201-fwd", [1e9] * 16)
            _write_cell(d, "p5202-fwd", [1e9] * 2)  # truncated
            err = io.StringIO()
            with redirect_stderr(err):
                rc = self._run(["p5201-fwd", "p5202-fwd"], d)
            self.assertEqual(rc, 2)

    def test_all_present_and_complete_succeeds(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            _write_cell(d, "p5201-fwd", [1e9 + i * 1e8 for i in range(16)])
            _write_cell(d, "p5202-fwd", [1e9 + i * 1e8 for i in range(16)])
            buf = io.StringIO()
            with redirect_stderr(buf):
                # Suppress stdout chatter by redirecting it too.
                real = sys.stdout
                sys.stdout = io.StringIO()
                try:
                    rc = self._run(["p5201-fwd", "p5202-fwd"], d)
                finally:
                    sys.stdout = real
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
