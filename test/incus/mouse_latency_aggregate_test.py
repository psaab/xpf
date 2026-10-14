import json
import os
import tempfile
import unittest

from mouse_latency_aggregate import (
    decide,
    exit_status_for_verdict,
    has_invalid_marker,
    load_cell_reps,
    median_rep_by_percentile,
    median_rep_by_p99,
    select_valid_reps,
    summarize_cell,
)


def _make_rep(
    p99: int,
    ok: bool = True,
    p50: int = 100,
    p95: int = 500,
    rps: float = 200.0,
    connection_mode: str = "per-attempt",
    min_interval_ms: float = 0.0,
) -> dict:
    return {
        "rtt_us": {"p50": p50, "p95": p95, "p99": p99, "p999": p99 + 10},
        "totals": {"achieved_rps_total": rps, "attempts_per_coroutine": [600] * 10},
        "validity": {"ok": ok, "reasons": []},
        "config": {
            "connection_mode": connection_mode,
            "min_interval_ms": min_interval_ms,
        },
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

    def test_selects_by_requested_percentile(self):
        reps = [
            _make_rep(100),
            _make_rep(200),
            _make_rep(300),
        ]
        reps[0]["rtt_us"]["p999"] = 10000
        reps[1]["rtt_us"]["p999"] = 200
        reps[2]["rtt_us"]["p999"] = 300

        by_p99 = median_rep_by_percentile(reps, "p99")
        by_p999 = median_rep_by_percentile(reps, "p999")

        self.assertEqual(by_p99["rtt_us"]["p99"], 200)
        self.assertEqual(by_p999["rtt_us"]["p999"], 300)


class SummarizeCellTests(unittest.TestCase):
    def test_insufficient_valid_reps(self):
        # Only 5 valid -> insufficient for a gate-grade cell.
        reps = [_make_rep(100) for _ in range(5)]
        s = summarize_cell(reps)
        self.assertEqual(s["status"], "INSUFFICIENT-VALID-REPS")

    def test_nine_valid_reps_is_insufficient(self):
        # A cell that exhausts the 15-rep ceiling at 9 valid reps must
        # not render as OK; gate-grade artifacts require the full 10.
        valid = [_make_rep(p99=100 + 10 * i) for i in range(9)]
        invalid = [_make_rep(p99=99999, ok=False) for _ in range(6)]
        s = summarize_cell(valid + invalid)
        self.assertEqual(s["n_reps_valid"], 9)
        self.assertEqual(s["n_reps_total"], 15)
        self.assertEqual(s["status"], "INSUFFICIENT-VALID-REPS")
        self.assertIsNone(s["median_rep"])

    def test_ok_with_10_valid(self):
        reps = [_make_rep(p99=100 + 10 * i) for i in range(10)]
        s = summarize_cell(reps)
        self.assertEqual(s["status"], "OK")
        self.assertIsNotNone(s["median_rep"])
        self.assertIsNotNone(s["iqr_p99_across_reps"])

    def test_median_rep_carries_probe_diagnostics(self):
        reps = [_make_rep(p99=100 + 10 * i) for i in range(10)]
        reps[5]["phase_us"] = {"read_us": {"p99": 1234}}
        reps[5]["coroutines"] = [{"id": 0, "max_start_gap_us": 20000}]
        s = summarize_cell(reps)
        self.assertEqual(s["median_rep"]["phase_us"], {"read_us": {"p99": 1234}})
        self.assertEqual(
            s["median_rep"]["coroutines"],
            [{"id": 0, "max_start_gap_us": 20000}],
        )

    def test_excludes_invalid_from_median(self):
        # 10 valid + 3 invalid; the invalid ones with extreme p99 must
        # not contribute to the median.
        valid = [_make_rep(p99=100 + 10 * i) for i in range(10)]
        invalid = [_make_rep(p99=99999, ok=False) for _ in range(3)]
        s = summarize_cell(valid + invalid)
        self.assertEqual(s["status"], "OK")
        # Median p99 of 100..190 is at index 5 → 150.
        self.assertEqual(s["median_rep"]["p99_us"], 150)

    def test_mixed_probe_config_within_cell_is_insufficient(self):
        reps = [_make_rep(p99=100) for _ in range(7)]
        reps += [
            _make_rep(
                p99=100,
                connection_mode="persistent",
                min_interval_ms=20.0,
            )
            for _ in range(3)
        ]
        s = summarize_cell(reps)
        self.assertEqual(s["status"], "INCONSISTENT-PROBE-CONFIG")
        self.assertEqual(len(s["probe_configs"]), 2)


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
        idle = summarize_cell(
            [_make_rep(p99=100) for _ in range(10)],
            representative_percentile="p999",
        )
        loaded = summarize_cell(
            [_make_rep(p99=100) for _ in range(10)],
            representative_percentile="p999",
        )
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
        self.assertEqual(v["percentile"], "p999_us")
        self.assertNotIn("p99_idle_us", v)

    def test_p99_gate_preserves_legacy_summary_aliases(self):
        summaries = self._gate_summaries(100, 190)
        v = decide(summaries)
        self.assertEqual(v["idle_us"], 100)
        self.assertEqual(v["loaded_us"], 190)
        self.assertEqual(v["p99_idle_us"], 100)
        self.assertEqual(v["p99_loaded_us"], 190)

    def test_missing_gate_cell(self):
        v = decide({(0, 10): summarize_cell([_make_rep(100)] * 10)})
        self.assertEqual(v["verdict"], "INSUFFICIENT-DATA")

    def test_insufficient_data_in_gate(self):
        # Loaded gate cell has only 5 valid reps → INSUFFICIENT-DATA
        idle = summarize_cell([_make_rep(p99=100) for _ in range(10)])
        loaded = summarize_cell([_make_rep(p99=100) for _ in range(5)])
        v = decide({(0, 10): idle, (128, 10): loaded})
        self.assertEqual(v["verdict"], "INSUFFICIENT-DATA")

    def test_nine_valid_gate_cell_is_insufficient(self):
        idle = summarize_cell([_make_rep(p99=100) for _ in range(10)])
        loaded = summarize_cell([_make_rep(p99=100) for _ in range(9)])
        v = decide({(0, 10): idle, (128, 10): loaded})
        self.assertEqual(v["verdict"], "INSUFFICIENT-DATA")
        self.assertIn("INSUFFICIENT-VALID-REPS", v["reason"])

    def test_gate_rejects_mixed_probe_configs(self):
        idle = summarize_cell(
            [
                _make_rep(
                    p99=100,
                    connection_mode="per-attempt",
                    min_interval_ms=0.0,
                )
                for _ in range(10)
            ]
        )
        loaded = summarize_cell(
            [
                _make_rep(
                    p99=100,
                    connection_mode="persistent",
                    min_interval_ms=20.0,
                )
                for _ in range(10)
            ]
        )
        v = decide({(0, 10): idle, (128, 10): loaded})
        self.assertEqual(v["verdict"], "INSUFFICIENT-DATA")
        self.assertIn("probe config mismatch", v["reason"])


class ExitStatusForVerdictTests(unittest.TestCase):
    """C175-HC-029: a measured FAIL must exit non-zero, not 0.

    Fail-on-revert guard: the pre-fix ``return 0 if verdict in
    ("PASS", "FAIL") else 2`` returned 0 for FAIL, so this asserts 1.
    """

    def test_pass_is_zero(self):
        self.assertEqual(exit_status_for_verdict("PASS"), 0)

    def test_fail_is_nonzero(self):
        self.assertEqual(exit_status_for_verdict("FAIL"), 1)
        self.assertNotEqual(exit_status_for_verdict("FAIL"), 0)

    def test_insufficient_is_two(self):
        self.assertEqual(exit_status_for_verdict("INSUFFICIENT-DATA"), 2)

    def test_unknown_verdict_is_not_a_pass(self):
        self.assertNotEqual(exit_status_for_verdict("SOMETHING-ELSE"), 0)


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

    def test_manifest_probe_config_overrides_probe_json_config(self):
        with tempfile.TemporaryDirectory() as t:
            cell_dir = self._setup_cell(t)
            rep_dir = self._write_rep(cell_dir, 0, ok=True)
            with open(os.path.join(rep_dir, "manifest.json"), "w") as f:
                json.dump({
                    "mouse_probe_connection_mode": "persistent",
                    "mouse_probe_min_interval_ms": 20,
                }, f)
            reps = load_cell_reps(cell_dir)
            s = summarize_cell(reps * 10)
            self.assertEqual(s["probe_config"], {
                "connection_mode": "persistent",
                "min_interval_ms": 20.0,
            })

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


class VoidNotAttributableTests(unittest.TestCase):
    """#8259 — the gate must refuse a verdict it cannot attribute.

    When the mice and the elephants terminate on the SAME host, the loaded
    cell adds the elephants' offered load to the very machine whose service
    time is inside every mouse sample, and the idle cell does not. The ratio
    then attributes that whole difference to firewall queueing.

    PASS is the dangerous half. A FAIL invites investigation; a PASS gets
    cited as a control, and one already was — #7159's cross-class PASS was
    used as the comparison point for #8259's FAIL and carries the same defect.
    """

    @staticmethod
    def _cell(mouse_target, elephant_target, p999):
        cell = {"status": "OK", "median_rep": {"p999_us": p999}}
        if mouse_target is not None:
            cell["mouse_target"] = mouse_target
        if elephant_target is not None:
            cell["elephant_target"] = elephant_target
        return cell

    def _decide(self, loaded, idle):
        return decide(
            {(100, 100): loaded, (0, 100): idle},
            gate_elephants=100,
            gate_mice=100,
            gate_percentile="p999_us",
        )

    def test_shared_target_voids_instead_of_failing(self):
        """The real #8259 numbers: a 7.69 ratio that must NOT be reported."""
        v = self._decide(
            self._cell("172.16.80.200", "172.16.80.200", 52039),
            self._cell("172.16.80.200", "172.16.80.200", 6765),
        )
        self.assertEqual(v["verdict"], "VOID-NOT-ATTRIBUTABLE")
        self.assertNotIn("ratio", v)
        self.assertEqual(v["mouse_target"], "172.16.80.200")
        self.assertIn("172.16.80.200", v["reason"])
        self.assertIn("VLAN 80", v["unblocked_by"])

    def test_shared_target_voids_a_PASS_too(self):
        """The half that matters most.

        A ratio comfortably under threshold is the case a reader trusts, and
        it is exactly as unattributable. Without this the gate would keep
        emitting citable PASSes on a shared target.
        """
        v = self._decide(
            self._cell("172.16.80.200", "172.16.80.200", 7000),
            self._cell("172.16.80.200", "172.16.80.200", 6765),
        )
        self.assertEqual(v["verdict"], "VOID-NOT-ATTRIBUTABLE")

    def test_separate_targets_still_produce_a_verdict(self):
        """The accept side, and the reason the check is not permanently true.

        Stand up a second host on VLAN 80, point ELEPHANT_TARGET_V4 at it, and
        the gate produces attributable numbers with no further change. A gate
        that voided unconditionally would pass every other cell here.
        """
        v = self._decide(
            self._cell("172.16.80.201", "172.16.80.200", 52039),
            self._cell("172.16.80.201", "172.16.80.200", 6765),
        )
        self.assertEqual(v["verdict"], "FAIL")
        self.assertAlmostEqual(v["ratio"], 52039 / 6765, places=3)

    def test_separate_targets_pass_is_still_a_pass(self):
        v = self._decide(
            self._cell("172.16.80.201", "172.16.80.200", 7000),
            self._cell("172.16.80.201", "172.16.80.200", 6765),
        )
        self.assertEqual(v["verdict"], "PASS")

    def test_legacy_artifacts_without_targets_are_not_voided(self):
        """Artifacts predating the split declare no targets.

        They must not be voided on a guess — that would retroactively void
        every historical run on a field they never carried. The void fires on
        POSITIVE evidence that the two are equal, never on its absence.
        """
        v = self._decide(
            self._cell(None, None, 52039),
            self._cell(None, None, 6765),
        )
        self.assertEqual(v["verdict"], "FAIL")

    def test_void_does_not_exit_zero(self):
        """A void painted green in CI would be the whole defect restored."""
        self.assertEqual(exit_status_for_verdict("VOID-NOT-ATTRIBUTABLE"), 2)
        self.assertEqual(exit_status_for_verdict("PASS"), 0)
        self.assertEqual(exit_status_for_verdict("FAIL"), 1)

    def test_idle_cell_shared_target_also_voids(self):
        """Either cell being unattributable voids the pair.

        The gate is a ratio; a contaminated denominator is as fatal as a
        contaminated numerator.
        """
        v = self._decide(
            self._cell("172.16.80.201", "172.16.80.200", 52039),
            self._cell("172.16.80.200", "172.16.80.200", 6765),
        )
        self.assertEqual(v["verdict"], "VOID-NOT-ATTRIBUTABLE")
        self.assertIn("idle cell", v["reason"])

    def test_void_takes_precedence_over_insufficient_data(self):
        """Attribution is the prior question.

        INSUFFICIENT-DATA says "collect more reps"; more reps cannot make an
        unattributable comparison attributable. Reporting it here would send
        someone to spend a cluster lock gathering data that still could not
        mean anything.
        """
        short = {
            "status": "INSUFFICIENT-VALID-REPS",
            "mouse_target": "172.16.80.200",
            "elephant_target": "172.16.80.200",
            "median_rep": None,
        }
        v = self._decide(short, self._cell("172.16.80.200", "172.16.80.200", 6765))
        self.assertEqual(v["verdict"], "VOID-NOT-ATTRIBUTABLE")

    def test_a_cell_with_no_valid_reps_still_reports_insufficient_data(self):
        """The other side of that ordering: nothing to attribute yet.

        A cell with zero valid reps records no targets at all, so the void
        cannot fire and INSUFFICIENT-DATA is the correct, more specific answer.
        """
        empty = {"status": "INSUFFICIENT-VALID-REPS", "median_rep": None}
        v = self._decide(empty, {"status": "OK", "median_rep": {"p999_us": 6765}})
        self.assertEqual(v["verdict"], "INSUFFICIENT-DATA")


def _with_targets(rep: dict, mouse_target: str, elephant_target: str) -> dict:
    """Stamp the rep manifest declaring where its two flows terminated."""
    rep["manifest"] = {
        "mouse_target": mouse_target,
        "elephant_target": elephant_target,
    }
    return rep


class MixedTargetPairTests(unittest.TestCase):
    """#13066 (D10-02) — mixed target pairs across reps must reject the cell.

    `shared_target_pair` returned `None` both when no rep declared a pair
    and when the valid reps split across pairs, and `summarize_cell` only
    acted on the not-`None` case. A partially re-run cell therefore
    summarised as a clean OK carrying no targets at all; `decide()` then
    read `(None, None)` for the pair, skipped the #8259
    VOID-NOT-ATTRIBUTABLE guard, and a cell whose reps terminated on a
    shared host could still emit a citable PASS.
    """

    def test_consistent_shared_pair_voids_end_to_end(self):
        """Positive control: the agreed-on pair must reach `decide()`.

        When every valid rep declares the same (shared) pair, the summary
        carries it and the #8259 guard fires. This is the behaviour the
        silent mixed-pair drop was bypassing.
        """
        idle = summarize_cell(
            [_with_targets(_make_rep(p99=100), "10.0.2.2", "10.0.2.2")
             for _ in range(10)]
        )
        loaded = summarize_cell(
            [_with_targets(_make_rep(p99=150), "10.0.2.2", "10.0.2.2")
             for _ in range(10)]
        )
        self.assertEqual(loaded["status"], "OK")
        self.assertEqual(loaded["mouse_target"], "10.0.2.2")
        self.assertEqual(loaded["elephant_target"], "10.0.2.2")
        v = decide({(0, 10): idle, (128, 10): loaded})
        self.assertEqual(v["verdict"], "VOID-NOT-ATTRIBUTABLE")

    def test_mixed_target_pairs_reject_the_cell(self):
        # 9 of 10 reps captured against the shared host, one rep re-run
        # after a target split: the cell cannot be summarised at all.
        reps = [
            _with_targets(_make_rep(p99=100 + 10 * i), "10.0.2.2", "10.0.2.2")
            for i in range(9)
        ]
        reps.append(_with_targets(_make_rep(p99=145), "10.0.2.3", "10.0.2.2"))
        s = summarize_cell(reps)
        self.assertEqual(s["status"], "INCONSISTENT-TARGETS")
        self.assertEqual(
            s["target_pairs"],
            [("10.0.2.2", "10.0.2.2"), ("10.0.2.3", "10.0.2.2")],
        )
        self.assertIsNone(s["median_rep"])
        self.assertNotIn("mouse_target", s)
        self.assertNotIn("elephant_target", s)

    def test_mixed_target_pairs_cannot_return_pass(self):
        """The exact false-PASS shape from the finding.

        The idle cell is attributable (split targets) and the ratio is a
        comfortable 1.5 <= 2.0, but 9 of 10 loaded reps — including the
        median rep — terminated on the shared host. The gate must refuse
        the verdict, not emit a citable PASS with the targets dropped.
        """
        idle = summarize_cell(
            [_with_targets(_make_rep(p99=300), "10.0.2.3", "10.0.2.2")
             for _ in range(10)]
        )
        loaded_reps = [
            _with_targets(_make_rep(p99=450), "10.0.2.2", "10.0.2.2")
            for _ in range(9)
        ]
        loaded_reps.append(
            _with_targets(_make_rep(p99=450), "10.0.2.3", "10.0.2.2")
        )
        loaded = summarize_cell(loaded_reps)
        v = decide({(0, 10): idle, (128, 10): loaded})
        self.assertNotEqual(v["verdict"], "PASS")
        self.assertEqual(v["verdict"], "INSUFFICIENT-DATA")
        self.assertIn("INCONSISTENT-TARGETS", v["reason"])

    def test_mixed_pairs_take_precedence_over_insufficient_reps(self):
        """Attribution is the prior question (#8259 ordering).

        INSUFFICIENT-VALID-REPS says "collect more reps", and more reps
        cannot make a cell that straddles two termination topologies
        summarisable — mirroring how decide() orders the void check.
        """
        reps = [
            _with_targets(_make_rep(p99=100), "10.0.2.2", "10.0.2.2")
            for _ in range(5)
        ]
        reps += [
            _with_targets(_make_rep(p99=100), "10.0.2.3", "10.0.2.2")
            for _ in range(4)
        ]
        s = summarize_cell(reps)
        self.assertEqual(s["status"], "INCONSISTENT-TARGETS")

    def test_iqr_follows_the_representative_percentile(self):
        """D10-02 tail: 100E100M gates on p999, so the across-rep spread
        must be computed for the gated percentile, not stay hardcoded to
        p99 while the representative is selected by p999.
        """
        reps = [_make_rep(p99=100 + 10 * i) for i in range(10)]
        s = summarize_cell(reps, representative_percentile="p999")
        self.assertIn("iqr_p999_across_reps", s)
        # _make_rep sets p999 = p99 + 10 for every rep, so the p999 sample
        # is the p99 sample shifted by +10 us: same spread.
        self.assertEqual(s["iqr_p999_across_reps"], s["iqr_p99_across_reps"])
