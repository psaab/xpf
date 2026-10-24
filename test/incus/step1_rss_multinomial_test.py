#!/usr/bin/env python3
"""Tests for step1-rss-multinomial.py (#4907 / C175-HC-130).

Guards that the Monte Carlo streams trials instead of retaining every
one, while preserving the deterministic-seed statistics.

Run:
    python3 test/incus/step1-rss-multinomial_test.py
"""
from __future__ import annotations

import subprocess
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from load_subject import load_subject  # noqa: E402


_HERE = Path(__file__).resolve().parent
_MOD_PATH = _HERE / "step1-rss-multinomial.py"



M = load_subject("step1_rss_multinomial", str(_MOD_PATH))


class SimulateStreamingTests(unittest.TestCase):
    def test_simulate_is_a_generator_not_a_list(self):
        # C175-HC-130 fail-on-revert: the old simulate() built and
        # returned a list holding one tuple per trial (GB-scale for 10M
        # trials). Streaming yields a generator instead.
        gen = M.simulate(trials=10, n_flows=16, n_workers=4, seed=42)
        self.assertIsInstance(gen, types.GeneratorType)
        self.assertNotIsInstance(gen, list)

    def test_seed_is_deterministic(self):
        a = M.tail_probabilities(
            M.simulate(trials=2000, n_flows=16, n_workers=4, seed=7), 16
        )
        b = M.tail_probabilities(
            M.simulate(trials=2000, n_flows=16, n_workers=4, seed=7), 16
        )
        self.assertEqual(a, b)

    def test_probabilities_are_well_formed(self):
        probs = M.tail_probabilities(
            M.simulate(trials=5000, n_flows=16, n_workers=4, seed=42), 16
        )
        for key, val in probs.items():
            self.assertGreaterEqual(val, 0.0, key)
            self.assertLessEqual(val, 1.0, key)
        # A perfectly fair split of 16 over 4 has max 4; P(max>=8) is a
        # small tail but must be strictly less than P(max>=7).
        self.assertGreaterEqual(probs["P(max>=7)"], probs["P(max>=8)"])
        self.assertGreaterEqual(probs["P(max>=8)"], probs["P(max>=9)"])

    def test_tail_probabilities_rejects_empty(self):
        with self.assertRaises(ValueError):
            M.tail_probabilities(iter([]), 16)

    def test_skewed_worker0_power_is_high(self):
        # Sanity: with worker0 taking 56% of flows, the max is large, so
        # the Verdict-A union fires almost always.
        probs = M.simulate(
            trials=3000,
            n_flows=16,
            n_workers=4,
            seed=1,
            probs=[0.56, 0.44 / 3, 0.44 / 3, 0.44 / 3],
        )
        tp = M.tail_probabilities(probs, 16)
        self.assertGreater(tp["FP_union_max9_or_min0"], 0.5)


class MainSmokeTests(unittest.TestCase):
    def test_cli_runs_small(self):
        result = subprocess.run(
            [sys.executable, str(_MOD_PATH), "--trials", "1000", "--seed", "42"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Monte Carlo", result.stdout)


if __name__ == "__main__":
    unittest.main()
