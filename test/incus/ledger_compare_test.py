"""Cells for ledger_compare.py — including the four the loop cannot live without.

A comparator with a broken band is INDISTINGUISHABLE from a healthy one on
every green run, and a loop is green almost all the time by construction. So
the cells that matter here are not the ones that check a happy path; they are
the ones that go RED when a specific piece of the guard is removed. Each of
those carries a `MUTATION:` line naming the edit it must survive, and
`test/incus/harness-ledger-mutation-selftest.sh` applies exactly those edits to
a copy of the module and asserts this file reds for each one. A cell without a
mutation behind it is a cell nobody has proved has power.

Falsifiability of this file: if ledger_compare.py's band, VOID exclusion, K
floor or NO-BASELINE distinction is broken, at least one cell here fails by
NAME. If a fixture stops reaching the code under test, the arrange-side
assertions (baseline_n, outcome on the healthy path) fail rather than the cell
passing vacuously. On an empty input the cells assert NO-BASELINE explicitly —
the empty set is never allowed to reach an assertion-free path.
"""

import contextlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import uuid

from ledger_compare import (
    BAND_REL_FLOOR,
    BAND_Z,
    COVERAGE_POSITIVE_CONTROL,
    COVERAGE_WINDOW,
    IMPROVED,
    LEDGER_CORRUPT,
    LEDGER_DIR_NAME,
    LEGACY_LEDGER_NAME,
    LedgerError,
    MIN_BASELINE_RUNS,
    NO_BASELINE,
    REGRESSION,
    VOID,
    WITHIN_BAND,
    _sorted_rows,
    all_exit_status,
    band,
    classify,
    compare,
    compare_all,
    coverage,
    exit_status,
    lint_ledger,
    lint_merge_completeness,
    lint_merge_completeness_ids,
    lint_row,
    lint_shard_names,
    load_ledger_text,
    main,
    parse_coverage_declared,
    parse_expected_red,
    parse_ledger,
    render,
    render_all,
    render_coverage,
    run_ids,
    run_ids_at_rev,
    shard_paths,
)

GATE = "test-failover"
ENV = "loss-userspace-cluster"


def row(
    ts,
    verdict="PASS",
    value=100.0,
    gate=GATE,
    env=ENV,
    headline="throughput_gbps",
    direction="higher-better",
    metrics=None,
    void_reason="",
    exe_check="MATCH",
    extra=None,
    run_id=None,
):
    """One ledger row. Complete enough to survive lint_row(), so the same
    fixtures can be round-tripped through parse_ledger()."""
    if metrics is None:
        metrics = {} if (verdict == "VOID" and value is None) else {headline: value}
    if extra:
        metrics = dict(metrics, **extra)
    return {
        "schema": 1,
        "run_id": run_id or uuid.uuid4().hex[:16],
        "ts": ts,
        "gate": gate,
        "env": env,
        "verdict": verdict,
        "void_reason": void_reason or ("did not measure" if verdict == "VOID" else ""),
        "headline_metric": "" if verdict == "VOID" else headline,
        "headline_direction": "" if verdict == "VOID" else direction,
        "metrics": metrics,
        "build_git_sha": "abc123",
        "build_exe_sha256": "d" * 64,
        "running_exe_sha256": "d" * 64,
        "exe_check": exe_check,
        "duration_s": 300,
        "artifacts": None,
        "adapter": "ha-smoke",
        "node": "loss:xpf-userspace-fw0",
    }


def greens(values, start=1):
    return [row(f"2026-09-01T00:{i:02d}:00Z", value=v) for i, v in enumerate(values, start=start)]


class BandArithmetic(unittest.TestCase):
    def test_band_is_median_mad_not_mean_stddev(self):
        # One wild point must NOT widen the band: that is the whole reason the
        # estimator is median/MAD. mean/stddev over [100,100,100,10] gives a
        # band wide enough to swallow a 40% regression.
        med, lo, hi = band([100.0, 100.0, 100.0, 10.0])
        self.assertEqual(med, 100.0)
        self.assertLess(hi - lo, 40.0)

    def test_identical_baseline_gets_relative_floor_not_zero_width(self):
        # Without the floor a perfectly repeatable gate gets a zero-width band
        # and every later run reports REGRESSION on ordinary jitter.
        med, lo, hi = band([100.0, 100.0, 100.0])
        self.assertAlmostEqual(lo, 95.0)
        self.assertAlmostEqual(hi, 105.0)

    def test_band_over_empty_baseline_raises(self):
        # The empty set must not produce a band. A band over nothing is a
        # number with the shape of evidence.
        with self.assertRaises(ValueError):
            band([])

    def test_classify_directions(self):
        self.assertEqual(classify(100, 95, 105, "higher-better"), WITHIN_BAND)
        self.assertEqual(classify(90, 95, 105, "higher-better"), REGRESSION)
        self.assertEqual(classify(110, 95, 105, "higher-better"), IMPROVED)
        self.assertEqual(classify(110, 95, 105, "lower-better"), REGRESSION)
        self.assertEqual(classify(90, 95, 105, "lower-better"), IMPROVED)
        # "neither": a move is reported, never celebrated.
        self.assertEqual(classify(110, 95, 105, "neither"), REGRESSION)
        self.assertEqual(classify(90, 95, 105, "neither"), REGRESSION)


class RequiredMutationCells(unittest.TestCase):
    """The four the brief names, plus the two the design adds."""

    def test_void_rows_do_not_satisfy_the_k_floor(self):
        # MUTATION: delete the `verdict == "PASS"` filter from the baseline.
        #
        # Two greens and one VOID. A VOID row is not a data point, so the
        # baseline is 2 and the answer is NO-BASELINE. A comparator that lets
        # the void count reaches 3 and reports a band instead — which is the
        # loop quietly starting to answer questions it has no grounds to
        # answer.
        rows = greens([100.0, 100.0]) + [
            row("2026-09-01T00:03:00Z", verdict="VOID", value=100.0),
            row("2026-09-01T00:04:00Z", value=60.0),
        ]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], NO_BASELINE)
        self.assertEqual(res["baseline_n"], 2)

    def test_void_rows_do_not_enter_the_band(self):
        # MUTATION: delete the `verdict == "PASS"` filter from the baseline.
        #
        # Four greens at 100 then two VOIDs at 50. The greens' band is
        # [95, 105] and the newest run at 50 is plainly outside it. A
        # comparator that lets voids in bands [100, 50, 50] instead — median
        # 50, half-width 2.5 — and reports the same 50 as WITHIN-BAND.
        rows = greens([100.0, 100.0, 100.0, 100.0]) + [
            row("2026-09-01T00:05:00Z", verdict="VOID", value=50.0),
            row("2026-09-01T00:06:00Z", verdict="VOID", value=50.0),
            row("2026-09-01T00:07:00Z", value=50.0),
        ]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], REGRESSION)
        self.assertEqual(res["baseline_values"], [100.0, 100.0, 100.0])

    def test_no_baseline_is_not_a_pass(self):
        # MUTATION: return WITHIN-BAND (or PASS) where NO-BASELINE is returned;
        # MUTATION: make exit_status treat NO-BASELINE as 0.
        #
        # "We have no grounds to judge this" and "this is fine" are different
        # answers, and the exit status must not collapse them either.
        rows = greens([100.0]) + [row("2026-09-01T00:02:00Z", value=60.0)]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], NO_BASELINE)
        self.assertNotEqual(res["outcome"], WITHIN_BAND)
        self.assertEqual(exit_status(res), 2, "NO-BASELINE must not exit 0")

    def test_k_floor_is_at_least_three(self):
        # MUTATION: MIN_BASELINE_RUNS = 3 -> 1 (or 2).
        #
        # Both halves matter: the constant itself, and the behaviour of a
        # two-green ledger. Pinning only the constant would leave a comparator
        # free to ignore it; asserting only the behaviour would pass under
        # K=2 for a three-green fixture.
        self.assertGreaterEqual(MIN_BASELINE_RUNS, 3)
        rows = greens([100.0, 100.0]) + [row("2026-09-01T00:03:00Z", value=60.0)]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], NO_BASELINE)
        self.assertEqual(res["baseline_n"], 2)

    def test_a_real_regression_does_not_fit_inside_the_band(self):
        # MUTATION: BAND_REL_FLOOR 0.05 -> 1.0, or BAND_Z 3.0 -> 50.0.
        #
        # A widened band is the decay mode with no symptom: every run reports
        # WITHIN-BAND and the history looks perfect. 23.1 Gbps baseline, 12.0
        # Gbps newest — a halving on the cluster's own documented figure.
        rows = greens([23.1, 23.0, 23.2]) + [row("2026-09-01T00:04:00Z", value=12.0)]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], REGRESSION)
        self.assertLess(res["band_lo"], 23.0)
        self.assertGreater(res["band_lo"], 12.0)
        self.assertEqual(exit_status(res), 1)

    def test_band_comparison_is_not_inverted(self):
        # MUTATION: invert the `lo <= value <= hi` test in classify().
        #
        # An inverted comparator reports REGRESSION on every healthy run and
        # WITHIN-BAND on the one run that matters, so BOTH directions are
        # asserted here — pinning only the regression side is satisfied by an
        # implementation that never returns WITHIN-BAND at all.
        rows = greens([23.1, 23.0, 23.2]) + [row("2026-09-01T00:04:00Z", value=12.0)]
        self.assertEqual(compare(rows, GATE, ENV)["outcome"], REGRESSION)
        rows = greens([23.1, 23.0, 23.2]) + [row("2026-09-01T00:04:00Z", value=23.05)]
        self.assertEqual(compare(rows, GATE, ENV)["outcome"], WITHIN_BAND)


class EmptyAndMismatchedSets(unittest.TestCase):
    def test_zero_matching_rows_is_no_baseline(self):
        # The empty-set pass, at the comparator layer.
        res = compare([], GATE, ENV)
        self.assertEqual(res["outcome"], NO_BASELINE)
        self.assertEqual(res["baseline_n"], 0)
        self.assertEqual(exit_status(res), 2)

    def test_rows_for_another_gate_do_not_leak_in(self):
        rows = [row(f"2026-09-01T00:0{i}:00Z", gate="test-ha-crash") for i in range(1, 5)]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], NO_BASELINE)

    def test_rows_from_another_env_do_not_enter_the_band(self):
        # MUTATION: drop the env filter.
        #
        # Five greens, all at the wrong env. Mixing envs into one band is how a
        # comparator reports a clean history for a gate whose runs never
        # actually compared to each other.
        rows = [
            row(f"2026-09-01T00:0{i}:00Z", env="standalone-vm", value=100.0)
            for i in range(1, 6)
        ]
        rows.append(row("2026-09-01T00:06:00Z", env=ENV, value=60.0))
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], NO_BASELINE)
        self.assertEqual(res["baseline_n"], 0)

    def test_env_is_resolved_from_the_newest_row_when_unspecified(self):
        # MUTATION: drop the same-env filter on `prior`.
        #
        # The wrong-env row sits IMMEDIATELY BEFORE the newest, inside the
        # last-K window. An earlier version of this fixture put it first,
        # where the window never reached it — so the cell passed with the
        # filter deleted and the mutation ESCAPED. A fixture that does not
        # enter the state under test is mutation-blind however carefully it
        # is read.
        rows = [
            row("2026-09-01T00:01:00Z", env=ENV, value=100.0),
            row("2026-09-01T00:02:00Z", env=ENV, value=100.0),
            row("2026-09-01T00:03:00Z", env=ENV, value=100.0),
            row("2026-09-01T00:04:00Z", env="standalone-vm", value=1.0),
            row("2026-09-01T00:05:00Z", env=ENV, value=60.0),
        ]
        res = compare(rows, GATE, env=None)
        self.assertEqual(res["env"], ENV)
        self.assertEqual(res["baseline_values"], [100.0, 100.0, 100.0])
        self.assertEqual(res["baseline_n"], 3)
        self.assertEqual(res["outcome"], REGRESSION)

    def test_a_prior_row_measuring_a_different_headline_does_not_count(self):
        # A row that measured something else is not a prior measurement of
        # this. Counting it toward K is a baseline made of unrelated numbers.
        rows = [
            row("2026-09-01T00:01:00Z", headline="cells_passed", value=21),
            row("2026-09-01T00:02:00Z", headline="cells_passed", value=21),
            row("2026-09-01T00:03:00Z", headline="cells_passed", value=21),
            row("2026-09-01T00:04:00Z", value=60.0),
        ]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], NO_BASELINE)
        self.assertEqual(res["baseline_n"], 0)

    def test_fail_rows_do_not_enter_the_band(self):
        rows = greens([100.0, 100.0]) + [
            row("2026-09-01T00:03:00Z", verdict="FAIL", value=100.0),
            row("2026-09-01T00:04:00Z", value=60.0),
        ]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], NO_BASELINE)
        self.assertEqual(res["baseline_n"], 2)


class VoidNewestRow(unittest.TestCase):
    def test_void_newest_row_reports_void_not_a_band_outcome(self):
        rows = greens([100.0, 100.0, 100.0]) + [
            row("2026-09-01T00:04:00Z", verdict="VOID", value=None, void_reason="helper restarted")
        ]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], VOID)
        self.assertEqual(res["void_reason"], "helper restarted")
        self.assertEqual(exit_status(res), 2)
        self.assertNotIn("band_lo", res)


class FlakeVersusRegressionSignal(unittest.TestCase):
    def _rows(self, newest_headline, newest_invariant, baseline_invariant=21):
        rows = []
        for i, v in enumerate([23.1, 23.0, 23.2], start=1):
            rows.append(
                row(
                    f"2026-09-01T00:0{i}:00Z",
                    value=v,
                    extra={"cells_passed": baseline_invariant, "cells_failed": 0},
                )
            )
        rows.append(
            row(
                "2026-09-01T00:04:00Z",
                value=newest_headline,
                extra={"cells_passed": newest_invariant, "cells_failed": 0},
            )
        )
        return rows

    def test_headline_moved_invariants_held_is_a_flake_candidate(self):
        res = compare(self._rows(12.0, 21), GATE, ENV)
        self.assertEqual(res["outcome"], REGRESSION)
        self.assertEqual(res["signal"], "flake-candidate")
        self.assertTrue(all(i["held"] for i in res["invariants"].values()))

    def test_headline_moved_with_an_invariant_is_a_regression_candidate(self):
        res = compare(self._rows(12.0, 14), GATE, ENV)
        self.assertEqual(res["outcome"], REGRESSION)
        self.assertEqual(res["signal"], "regression-candidate")
        self.assertIn("cells_passed", res["signal_note"])

    def test_no_invariant_with_a_baseline_is_undetermined_not_a_flake(self):
        # The empty set again, one level in: "every invariant held" and "there
        # were no invariants to check" are the same sentence only if you do
        # not look. Reporting flake-candidate here would tell an operator to
        # re-run when nothing supports that.
        rows = greens([23.1, 23.0, 23.2]) + [row("2026-09-01T00:04:00Z", value=12.0)]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], REGRESSION)
        self.assertEqual(res["invariants"], {})
        self.assertEqual(res["signal"], "undetermined")

    def test_within_band_carries_no_signal(self):
        res = compare(self._rows(23.05, 21), GATE, ENV)
        self.assertEqual(res["outcome"], WITHIN_BAND)
        self.assertIsNone(res.get("signal"))


class PinnedBaseline(unittest.TestCase):
    """#9922 F-088: the rolling band absorbs slow decay; the pin must not."""

    def test_slow_decay_sets_drift_with_cumulative_displacement(self):
        # MUTATION: pin the LAST K greens instead of the FIRST K.
        #
        # A 4%-per-run geometric decay reads WITHIN-BAND at every step (the
        # rolling window re-trusts each step) while the total displacement
        # grows to -36%. The pinned baseline over genesis must surface it.
        vals = [100.0 * (0.96**i) for i in range(12)]
        rows = [
            row(f"2026-09-01T00:{i:02d}:00Z", value=v)
            for i, v in enumerate(vals)
        ]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], WITHIN_BAND)
        self.assertEqual(res["pinned_values"], vals[:3])
        self.assertTrue(res["drift"])
        self.assertLess(res["displacement"], -0.30)
        self.assertIn("DRIFT", render(res))
        self.assertIn("cumulative displacement", render(res))

    def test_stable_history_has_no_drift(self):
        rows = greens([100.0, 100.0, 100.0, 100.0]) + [
            row("2026-09-01T00:05:00Z", value=100.0)
        ]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], WITHIN_BAND)
        self.assertFalse(res["drift"])
        self.assertAlmostEqual(res["displacement"], 0.0)

    def test_young_history_carries_no_pinned_section(self):
        # Below the K floor there is no rolling band, so there is nothing to
        # anchor beside it either: no pinned keys at all, not placeholders.
        rows = greens([100.0]) + [row("2026-09-01T00:02:00Z", value=60.0)]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], NO_BASELINE)
        self.assertNotIn("pinned_median", res)
        self.assertNotIn("displacement", res)
        self.assertNotIn("drift", res)

    def test_zero_pinned_median_yields_no_ratio_and_no_crash(self):
        # cells_failed pinned at 0 (the host-inbound shape): a ratio over a
        # zero median is undefined, so displacement is None and drift stays
        # False rather than crashing — while the rolling band still judges
        zeros = [0, 0, 0, 0]
        rows = [
            row(
                f"2026-09-01T00:{i:02d}:00Z",
                value=float(v),
                headline="cells_failed",
                direction="lower-better",
            )
            for i, v in enumerate(zeros)
        ]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], WITHIN_BAND)
        self.assertIsNone(res["displacement"])
        self.assertFalse(res["drift"])
        rows1 = rows + [
            row(
                "2026-09-01T00:05:00Z",
                value=1.0,
                headline="cells_failed",
                direction="lower-better",
            )
        ]
        res1 = compare(rows1, GATE, ENV)
        self.assertEqual(res1["outcome"], REGRESSION)
        self.assertIsNone(res1["displacement"])
        self.assertFalse(res1["drift"])

    def test_drift_is_informational_not_failed(self):
        # Drift attribution needs a human; the exit status must not move.
        vals = [100.0 * (0.96**i) for i in range(12)]
        rows = [
            row(f"2026-09-01T00:{i:02d}:00Z", value=v)
            for i, v in enumerate(vals)
        ]
        res = compare(rows, GATE, ENV)
        self.assertTrue(res["drift"])
        self.assertEqual(exit_status(res), 0)


class AggregateComparison(unittest.TestCase):
    """#9922 F-086: the aggregate over every (gate, env)."""

    def test_newest_fail_below_the_k_floor_exits_one(self):
        # MUTATION: drop the FAIL-first branch from exit_status.
        #
        # The outcome stays NO-BASELINE (there is no band to judge by) but
        # the exit is 1: a measured FAIL beats an undetermined band.
        rows = greens([100.0]) + [
            row("2026-09-01T00:02:00Z", verdict="FAIL", value=10.0)
        ]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], NO_BASELINE)
        self.assertEqual(res["verdict"], "FAIL")
        self.assertEqual(exit_status(res), 1)

    def test_window_fails_are_surfaced_not_banded(self):
        # MUTATION: drop the window_fails computation.
        #
        # A FAIL inside the window must neither enter the band nor vanish: it
        # is counted, timestamped, and rendered.
        rows = (
            greens([100.0, 100.0, 100.0])
            + [row("2026-09-01T00:03:00Z", verdict="FAIL", value=10.0)]
            + [row("2026-09-01T00:04:00Z", value=100.0)]
        )
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], WITHIN_BAND)
        self.assertEqual(res["baseline_values"], [100.0, 100.0, 100.0])
        self.assertEqual(res["window_fails"], 1)
        self.assertEqual(res["window_fail_ts"], ["2026-09-01T00:03:00Z"])
        self.assertIn("FAIL rows inside the baseline window: 1", render(res))

    def _mixed_rows(self):
        green = [
            row(f"2026-09-01T0{i}:00:00Z", value=100.0, gate="gate-green")
            for i in range(5)
        ]
        regressed = [
            row(f"2026-09-01T00:0{i}:00Z", value=100.0, gate="gate-reg")
            for i in range(3)
        ] + [row("2026-09-01T00:04:00Z", value=10.0, gate="gate-reg")]
        # FAIL newest on a thin baseline: NO-BASELINE outcome, FAIL verdict.
        failed = [row("2026-09-01T00:00:00Z", value=100.0, gate="gate-fail")] + [
            row("2026-09-01T00:01:00Z", verdict="FAIL", value=10.0, gate="gate-fail")
        ]
        return green + regressed + failed

    def test_compare_all_reds_on_regression_and_newest_fail(self):
        # MUTATION: aggregate-ignores-fail-verdict (red on REGRESSION only).
        # MUTATION: aggregate-never-red (red on nothing).
        agg = compare_all(self._mixed_rows())
        self.assertEqual(
            sorted(agg["red"]), [("gate-fail", ENV), ("gate-reg", ENV)]
        )
        self.assertEqual(sorted(agg["green"]), [("gate-green", ENV)])
        self.assertEqual(all_exit_status(agg), 1)

    def test_compare_all_tolerates_undetermined(self):
        # A thin-baseline pair is surfaced, not failed: the aggregate watches
        # for red, it is not a baseline-completeness gate.
        rows = greens([100.0]) + [row("2026-09-01T00:02:00Z", value=60.0)]
        agg = compare_all(rows)
        self.assertEqual(sorted(agg["undetermined"]), [(GATE, ENV)])
        self.assertEqual(agg["red"], {})
        self.assertEqual(all_exit_status(agg), 0)
        self.assertIn("UNDETERMINED", render_all(agg))

    def test_parse_expected_red(self):
        declared, problems = parse_expected_red(
            "# comment\n"
            "\n"
            "gate-fail loss-userspace-cluster newest-FAIL, tracked in #10122\n"
        )
        self.assertEqual(problems, [])
        self.assertEqual(
            declared,
            {("gate-fail", "loss-userspace-cluster"): "newest-FAIL, tracked in #10122"},
        )
        _d2, problems2 = parse_expected_red("gate-only\n")
        self.assertEqual(len(problems2), 1)
        self.assertIn("line 1", problems2[0])

    def test_all_exit_status_honors_declarations(self):
        # MUTATION: expected-red-stale-check-dropped.
        agg = compare_all(self._mixed_rows())
        declared = {("gate-fail", ENV): "x", ("gate-reg", ENV): "y"}
        self.assertEqual(all_exit_status(agg, declared), 0)
        self.assertIn("expected-red: still red", render_all(agg, declared))
        # A stale declaration (green now) fails so the file can only shrink.
        # ALL live reds stay declared here: with an undeclared red present the
        # first branch returns 1 regardless, and the cell could not kill a
        # VALID stale-check removal (it would pass for the wrong reason).
        stale = {("gate-fail", ENV): "x", ("gate-reg", ENV): "y",
                 ("gate-green", ENV): "was red once"}
        self.assertEqual(all_exit_status(agg, stale), 1)
        self.assertIn("STALE", render_all(agg, stale))
    def test_summary_carries_window_and_drift_warning_counts(self):
        # The automation boundary (run-selftests.sh) prints tail -1 on success;
        # without these counts a newest-PASS-after-FAILs and a DRIFT-flagged
        # WITHIN-BAND render identically to a clean history — the defect
        # recreated one layer up.
        windowed = (
            [row(f"2026-09-01T00:0{i}:00Z", value=100.0, gate="gate-win") for i in range(3)]
            + [row("2026-09-01T00:03:00Z", verdict="FAIL", value=10.0, gate="gate-win")]
            + [row("2026-09-01T00:04:00Z", value=100.0, gate="gate-win")]
        )
        drifted = [
            row(f"2026-09-01T00:{i:02d}:00Z", value=100.0 * (0.96 ** i), gate="gate-drift")
            for i in range(12)
        ]
        agg = compare_all(windowed + drifted)
        text = render_all(agg)
        self.assertIn("1 with window FAILs, 1 DRIFT-flagged", text.splitlines()[-1])

    def test_main_all_over_a_fixture_ledger(self):
        # End to end through main(): shards on disk, strict and declared runs,
        # and the corrupt-ledger mapping. Hermetic (tmp dir, no git, no net).
        work = tempfile.mkdtemp(prefix="xpf-compare-all.")
        self.addCleanup(shutil.rmtree, work, True)
        for r in self._mixed_rows():
            with open(os.path.join(work, f"{r['run_id']}.json"), "w") as fh:
                json.dump(r, fh)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--all", "--ledger", work])
        self.assertEqual(rc, 1)
        self.assertIn("gate-reg @ ", buf.getvalue())
        decl = os.path.join(work, "expected.txt")
        with open(decl, "w") as fh:
            fh.write(f"gate-fail {ENV} tracked\n")
            fh.write(f"gate-reg {ENV} tracked\n")
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc2 = main(["--all", "--ledger", work, "--expected-red", decl])
        self.assertEqual(rc2, 0)
        with open(os.path.join(work, "broken.json"), "w") as fh:
            fh.write("{not json\n")
        buf3 = io.StringIO()
        with contextlib.redirect_stdout(buf3):
            rc3 = main(["--all", "--ledger", work])
        self.assertEqual(rc3, 2)
        self.assertIn("LEDGER-CORRUPT", buf3.getvalue())


class ExitStatusMapping(unittest.TestCase):
    def test_mapping_matches_mouse_latency_aggregate_not_newflow_analyze(self):
        self.assertEqual(exit_status({"outcome": WITHIN_BAND, "verdict": "PASS"}), 0)
        self.assertEqual(exit_status({"outcome": IMPROVED, "verdict": "PASS"}), 0)
        self.assertEqual(exit_status({"outcome": REGRESSION, "verdict": "PASS"}), 1)
        self.assertEqual(exit_status({"outcome": VOID, "verdict": "VOID"}), 2)
        self.assertEqual(exit_status({"outcome": NO_BASELINE, "verdict": "PASS"}), 2)
        self.assertEqual(exit_status({"outcome": LEDGER_CORRUPT}), 2)

    def test_a_fail_row_inside_the_band_still_exits_one(self):
        # The band says the metric did not move; the row says the gate was
        # violated. The second one wins — a FAIL that reads as success is
        # C175-HC-029 repeating one layer up.
        rows = greens([23.1, 23.0, 23.2]) + [
            row("2026-09-01T00:04:00Z", verdict="FAIL", value=23.05)
        ]
        res = compare(rows, GATE, ENV)
        self.assertEqual(res["outcome"], WITHIN_BAND)
        self.assertEqual(res["verdict"], "FAIL")
        self.assertEqual(exit_status(res), 1)


class LedgerParsingAndLint(unittest.TestCase):
    def test_a_damaged_line_refuses_rather_than_being_skipped(self):
        # A skipped row does not count toward K, so a corrupt ledger silently
        # produces a thinner baseline that still reports WITHIN-BAND.
        text = "\n".join(json.dumps(r) for r in greens([100.0, 100.0])) + "\n{not json\n"
        with self.assertRaises(LedgerError):
            parse_ledger(text)

    def test_a_committed_conflict_marker_is_a_red_gate(self):
        text = (
            json.dumps(greens([100.0])[0])
            + "\n<<<<<<< HEAD\n"
            + json.dumps(greens([101.0])[0])
            + "\n"
        )
        problems = lint_ledger(text)
        self.assertTrue(problems)
        self.assertTrue(any("not parseable" in p for p in problems))

    def test_an_empty_ledger_is_not_a_clean_lint(self):
        self.assertTrue(lint_ledger(""))
        self.assertIn("zero rows", " ".join(lint_ledger("")))
        self.assertIn("zero rows", " ".join(lint_ledger("\n \n")))

    def test_lint_rejects_the_same_shapes_the_emitter_refuses(self):
        bad = dict(greens([100.0])[0], verdict="MAYBE")
        self.assertTrue(lint_row(bad, 1))
        bad = dict(greens([100.0])[0], verdict="VOID", void_reason="")
        self.assertTrue(lint_row(bad, 1))
        bad = dict(greens([100.0])[0], void_reason="something")
        self.assertTrue(lint_row(bad, 1))
        bad = dict(greens([100.0])[0], exe_check="MISMATCH")
        self.assertTrue(lint_row(bad, 1))
        bad = dict(greens([100.0])[0], metrics={"throughput_gbps": "fast"})
        self.assertTrue(lint_row(bad, 1))
        bad = dict(greens([100.0])[0], headline_metric="absent_metric")
        self.assertTrue(lint_row(bad, 1))
        bad = dict(greens([100.0])[0])
        del bad["exe_check"]
        self.assertTrue(lint_row(bad, 1))

    def test_lint_accepts_a_row_the_emitter_would_write(self):
        # The positive control. A linter that rejects everything would satisfy
        # every cell above while being useless, and a control that passes on
        # the CORRECT input is what proves the rejections are aimed.
        self.assertEqual(lint_row(greens([100.0])[0], 1), [])
        void = row("2026-09-01T00:01:00Z", verdict="VOID", value=None)
        self.assertEqual(lint_row(void, 1), [])
        self.assertEqual(lint_ledger(json.dumps(greens([100.0])[0])), [])

    def test_a_byte_identical_repeat_is_deduped_not_counted_twice(self):
        # MUTATION: drop the dedup `continue` in parse_ledger.
        #
        # `merge=union` on the ledger resolves a conflicting hunk by keeping
        # BOTH sides' lines, so a row both branches carried appears twice. A
        # baseline is a count of RUNS; counting one run twice inflates it and
        # can satisfy the K floor with two rows.
        dup = row("2026-09-01T00:01:00Z", value=100.0)
        text = "\n".join(json.dumps(r) for r in [dup, dup]) + "\n"
        rows = parse_ledger(text)
        self.assertEqual(len(rows), 1)

    def test_a_repeated_run_id_with_different_content_is_refused(self):
        # MUTATION: accept a conflicting repeat.
        #
        # Identical repeats are a benign merge artifact. Two DIFFERENT runs
        # claiming one identity is corruption, and deduping it would silently
        # drop a real measurement or admit a foreign one.
        a = row("2026-09-01T00:01:00Z", value=100.0, run_id="collide")
        b = row("2026-09-01T00:02:00Z", value=42.0, run_id="collide")
        text = "\n".join(json.dumps(r) for r in [a, b]) + "\n"
        with self.assertRaises(LedgerError):
            parse_ledger(text)
        problems = lint_ledger(text)
        self.assertTrue(any("repeats with DIFFERENT content" in p for p in problems))

    def test_lint_does_not_flag_a_benign_identical_repeat(self):
        # The positive control for the cell above. A linter that flagged every
        # repeat would red on an ordinary union merge and be turned off.
        dup = row("2026-09-01T00:01:00Z", value=100.0)
        text = "\n".join(json.dumps(r) for r in [dup, dup]) + "\n"
        self.assertEqual(lint_ledger(text), [])

    def test_lint_requires_a_run_id(self):
        bad = row("2026-09-01T00:01:00Z")
        del bad["run_id"]
        self.assertTrue(lint_row(bad, 1))

    def test_rows_out_of_timestamp_order_on_disk_are_sorted(self):
        # Parallel worktrees append to one ledger; the file is not guaranteed
        # to be in ts order.
        rows = greens([100.0, 100.0, 100.0])
        newest = row("2026-09-01T00:09:00Z", value=60.0)
        res = compare([newest] + rows, GATE, ENV)
        self.assertEqual(res["ts"], "2026-09-01T00:09:00Z")
        self.assertEqual(res["outcome"], REGRESSION)


class OneFilePerRunStorage(unittest.TestCase):
    """#8346: the ledger is a directory of <run_id>.json, not one appended file."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-ledger-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _shard(self, r, into=None):
        d = pathlib.Path(into or self.dir)
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{r['run_id']}.json").write_text(
            json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8"
        )

    def test_the_band_is_identical_to_the_band_over_one_file(self):
        # MUTATION: make load_ledger_text read only a single path.
        #
        # The acceptance criterion of #8346, and the regression that would
        # actually matter: a STORAGE change must not move a VERDICT. Asserted
        # as an equivalence over the same rows in both layouts rather than by
        # pinning a number, because a pinned number is satisfied by both sides
        # being wrong the same way.
        rows = greens([23.1, 23.0, 23.2]) + [row("2026-09-01T00:04:00Z", value=12.0)]
        as_file = "\n".join(json.dumps(r) for r in rows) + "\n"
        for r in rows:
            self._shard(r)
        from_file = compare(parse_ledger(as_file), GATE, ENV)
        from_dir = compare(parse_ledger(load_ledger_text(self.dir)), GATE, ENV)
        self.assertEqual(from_file, from_dir)
        # ...and the fixture must actually reach the interesting branch: an
        # equivalence between two NO-BASELINEs would hold for a broken loader.
        self.assertEqual(from_dir["outcome"], REGRESSION)
        self.assertEqual(len(shard_paths(self.dir)), 4)

    def test_a_directory_and_a_file_of_the_same_rows_load_identically(self):
        rows = greens([1.0, 2.0, 3.0])
        for r in rows:
            self._shard(r)
        self.assertEqual(
            {r["run_id"] for r in parse_ledger(load_ledger_text(self.dir))},
            {r["run_id"] for r in rows},
        )

    def test_an_empty_shard_directory_reds_exactly_as_an_empty_ledger_did(self):
        # MUTATION: drop the zero-rows problem from lint_ledger.
        #
        # The assertion #8346 flagged as most likely to be lost in the move.
        # An empty DIRECTORY is the new empty ledger, and linting it clean
        # would be the swept-nothing pass one layout down.
        os.makedirs(self.dir, exist_ok=True)
        self.assertEqual(load_ledger_text(self.dir), "")
        self.assertIn("zero rows", " ".join(lint_ledger(load_ledger_text(self.dir))))

    def test_a_missing_path_is_not_the_same_as_an_empty_one(self):
        # "We could not look" and "we looked and there is nothing" are
        # different answers; collapsing them makes a fresh checkout with no
        # ledger indistinguishable from one whose shards were all deleted.
        missing = os.path.join(self.dir, "nope")
        self.assertEqual(load_ledger_text(missing), "")
        self.assertFalse(os.path.exists(missing))

    def test_a_pretty_printed_shard_is_re_compacted_to_one_line(self):
        # A hand-edited shard must not become a stream of unparseable
        # fragments, which would report N problems for one file.
        r = row("2026-09-01T00:01:00Z")
        pathlib.Path(self.dir, f"{r['run_id']}.json").write_text(
            json.dumps(r, indent=2), encoding="utf-8"
        )
        text = load_ledger_text(self.dir)
        self.assertEqual(len(text.splitlines()), 1)
        self.assertEqual(lint_ledger(text), [])

    def test_shard_filename_must_equal_the_run_id(self):
        r = row("2026-09-01T00:01:00Z")
        self._shard(r)
        self.assertEqual(lint_shard_names(self.dir), [])          # positive control
        pathlib.Path(self.dir, f"{r['run_id']}.json").rename(
            pathlib.Path(self.dir, "someone-renamed-me.json")
        )
        probs = lint_shard_names(self.dir)
        self.assertTrue(probs)
        self.assertIn("filename IS the identity", probs[0])

    def test_lint_shard_names_is_empty_for_a_legacy_single_file(self):
        # There are no filenames to check in the legacy layout; reporting a
        # problem there would make it permanently red.
        f = os.path.join(self.dir, "ledger.jsonl")
        pathlib.Path(f).write_text(json.dumps(row("2026-09-01T00:01:00Z")), encoding="utf-8")
        self.assertEqual(lint_shard_names(f), [])

    def test_ordering_does_not_depend_on_the_storage_order(self):
        # MUTATION: tie-break _sorted_rows on load order instead of run_id.
        #
        # Under one appended file, load order WAS write order. Under one file
        # per run it is sorted-random-hex order, so a load-order tie-break
        # makes "which row is newest" a function of the filenames rather than
        # of the data. Two rows at the SAME ts is the state that exposes it.
        a = row("2026-09-01T00:01:00Z", value=1.0, run_id="aaaa")
        b = row("2026-09-01T00:01:00Z", value=2.0, run_id="bbbb")
        self.assertEqual([r["run_id"] for r in _sorted_rows([a, b])],
                         [r["run_id"] for r in _sorted_rows([b, a])])
        self.assertEqual(_sorted_rows([b, a])[-1]["run_id"], "bbbb")


class MergeGuardSeesAcrossTheMigration(unittest.TestCase):
    """run_ids_at_rev must read BOTH layouts at every revision."""

    def _fake_git(self, legacy_text=None, tree_names=()):
        class R:
            def __init__(self, rc, out):
                self.returncode, self.stdout = rc, out

        def run(cmd):
            # The fake HONOURS THE REQUESTED PATH. An earlier version returned
            # the legacy text for any `git show`, which made it blind to WHICH
            # path was asked for -- so the mutation that points the legacy
            # source at the wrong path ESCAPED. A fixture that cannot
            # distinguish the mutant from the original is not testing the
            # thing it names.
            if cmd[1] == "show":
                if cmd[2].endswith(f":test/results/{LEGACY_LEDGER_NAME}") and legacy_text is not None:
                    return R(0, legacy_text)
                return R(128, "")
            if cmd[1] == "ls-tree":
                wanted = f"test/results/{LEDGER_DIR_NAME}/"
                if cmd[-1] != wanted:
                    return R(0, "")
                return R(0, "\n".join(tree_names)) if tree_names else R(0, "")
            raise AssertionError(f"unexpected git call {cmd}")

        return run

    def test_a_parent_from_before_the_migration_is_not_the_empty_set(self):
        # MUTATION: drop the legacy `git show` source from run_ids_at_rev.
        #
        # THE cell of this change. After #8346 a parent commit that predates it
        # has no ledger.d/ at all. A source reading only the new layout returns
        # the EMPTY SET for that parent, `missing` is empty, and the merge
        # guard passes VACUOUSLY -- loudest on the one merge most likely to
        # drop rows: the migration's own, whose other parent is legacy-only.
        legacy = "\n".join(json.dumps(r) for r in greens([1.0, 2.0])) + "\n"
        ids = run_ids_at_rev("PARENT", run=self._fake_git(legacy_text=legacy))
        self.assertEqual(len(ids), 2)
        self.assertEqual(ids, run_ids(legacy))

    def test_a_rev_with_only_shards_reads_ids_off_the_filenames(self):
        ids = run_ids_at_rev("HEAD", run=self._fake_git(
            tree_names=[f"test/results/{LEDGER_DIR_NAME}/aaaa.json",
                        f"test/results/{LEDGER_DIR_NAME}/bbbb.json"]))
        self.assertEqual(ids, {"aaaa", "bbbb"})

    def test_a_rev_carrying_both_layouts_unions_them(self):
        legacy = json.dumps(row("2026-09-01T00:01:00Z", run_id="legacy1")) + "\n"
        ids = run_ids_at_rev("MID", run=self._fake_git(
            legacy_text=legacy,
            tree_names=[f"test/results/{LEDGER_DIR_NAME}/shard1.json"]))
        self.assertEqual(ids, {"legacy1", "shard1"})

    def test_the_migration_merge_shape_catches_a_dropped_id(self):
        """A jsonl-only parent merged with a shard-only parent — the real shape.

        This is the cell that proves the union is LIVE rather than a claim in
        inert code. Every other test here passes with the leg simplified back
        to a single path, because every other fixture has the id reachable
        from the layout that leg reads. Only a merge whose two parents use
        DIFFERENT layouts can tell a two-source reader from a one-source one,
        and that is exactly the shape of the migration's own merge commit:
        master carrying `ledger.jsonl`, this branch carrying `ledger.d/`.

        Asserted in both directions. The faithful merge is clean, and a merge
        that drops one id NAMES it — a cell that only checked the clean case
        would pass against a guard that can never fail.
        """
        legacy_rows = greens([1.0, 2.0, 3.0])
        legacy = "\n".join(json.dumps(r) for r in legacy_rows) + "\n"
        all_ids = sorted(r["run_id"] for r in legacy_rows)

        # parent 0: pre-migration master — the legacy file only, no ledger.d/
        p_legacy = run_ids_at_rev("MASTER", run=self._fake_git(legacy_text=legacy))
        # parent 1: the migration branch — shards only, no ledger.jsonl
        p_shards = run_ids_at_rev("BRANCH", run=self._fake_git(
            tree_names=[f"test/results/{LEDGER_DIR_NAME}/{i}.json" for i in all_ids]))
        self.assertEqual(p_legacy, p_shards, "the fixture's two parents must hold the SAME ids")
        self.assertEqual(len(p_legacy), 3)

        faithful = run_ids_at_rev("MERGE", run=self._fake_git(
            tree_names=[f"test/results/{LEDGER_DIR_NAME}/{i}.json" for i in all_ids]))
        self.assertEqual(
            lint_merge_completeness_ids(faithful, [p_legacy, p_shards]), [],
            "a faithful migration merge must be clean",
        )

        lossy = run_ids_at_rev("MERGE-BAD", run=self._fake_git(
            tree_names=[f"test/results/{LEDGER_DIR_NAME}/{i}.json" for i in all_ids[1:]]))
        probs = lint_merge_completeness_ids(lossy, [p_legacy, p_shards])
        self.assertTrue(probs, "a merge that dropped a row must be caught")
        self.assertIn(all_ids[0], " ".join(probs))
        # The LEGACY parent is the one that can only be seen through the
        # `git show` source. If that source were dropped it would read as the
        # empty set and contribute no complaint at all.
        self.assertIn("parent 0", probs[0])

    def test_a_migration_that_dropped_a_row_is_caught(self):
        # The guard validating this very change: 3 rows in the legacy parent,
        # 2 shards in the merge result.
        legacy = "\n".join(json.dumps(r) for r in greens([1.0, 2.0, 3.0])) + "\n"
        parent = run_ids_at_rev("P", run=self._fake_git(legacy_text=legacy))
        kept = sorted(parent)[:2]
        merged = run_ids_at_rev("M", run=self._fake_git(
            tree_names=[f"test/results/{LEDGER_DIR_NAME}/{i}.json" for i in kept]))
        probs = lint_merge_completeness_ids(merged, [parent])
        self.assertTrue(probs)
        self.assertIn("dropped 1 run_id", probs[0])
        # ...and the control: a faithful migration is clean.
        faithful = run_ids_at_rev("M2", run=self._fake_git(
            tree_names=[f"test/results/{LEDGER_DIR_NAME}/{i}.json" for i in sorted(parent)]))
        self.assertEqual(lint_merge_completeness_ids(faithful, [parent]), [])


@unittest.skipIf(shutil.which("git") is None, "git not installed")
class ConcurrentWritersDoNotConflict(unittest.TestCase):
    """#8346 acceptance: assert it by WRITING both, not by reasoning about it."""

    def test_two_branches_each_adding_a_shard_merge_without_conflict(self):
        d = tempfile.mkdtemp(prefix="xpf-ledger-git-")
        self.addCleanup(shutil.rmtree, d, True)

        def git(*args, check=True):
            r = subprocess.run(["git", "-C", d, *args], capture_output=True, text=True)
            if check and r.returncode != 0:
                raise AssertionError(f"git {args} failed: {r.stderr}")
            return r

        def shard(run_id, value):
            led = pathlib.Path(d, "test", "results", LEDGER_DIR_NAME)
            led.mkdir(parents=True, exist_ok=True)
            r = row("2026-09-01T00:01:00Z", value=value, run_id=run_id)
            (led / f"{run_id}.json").write_text(json.dumps(r), encoding="utf-8")

        git("init", "-q", ".")
        git("config", "user.email", "t@t")
        git("config", "user.name", "t")
        shard("base0000", 1.0)
        git("add", "-A")
        git("commit", "-qm", "base")
        base = git("rev-parse", "HEAD").stdout.strip()

        git("checkout", "-q", "-b", "laneA")
        shard("laneaaaa", 2.0)
        git("add", "-A")
        git("commit", "-qm", "lane A run")

        git("checkout", "-q", base)
        git("checkout", "-q", "-b", "laneB")
        shard("lanebbbb", 3.0)
        git("add", "-A")
        git("commit", "-qm", "lane B run")

        merge = git("merge", "--no-edit", "laneA", check=False)
        self.assertEqual(
            merge.returncode, 0,
            f"two concurrent gate runs CONFLICTED, which is the whole thing #8346 "
            f"removes:\n{merge.stdout}{merge.stderr}",
        )
        # A clean exit is not enough on its own -- the #8348 no-op driver also
        # exited 0. Assert the SET.
        names = {p.name for p in pathlib.Path(d, "test", "results", LEDGER_DIR_NAME).glob("*.json")}
        self.assertEqual(names, {"base0000.json", "laneaaaa.json", "lanebbbb.json"})


class ConstantsAreWhatTheCommentsClaim(unittest.TestCase):
    def test_constants(self):
        # These are asserted because the mutation runner edits them, and a
        # mutation that changed a constant nothing reads would score as an
        # escape and read as "the guard has no power".
        self.assertEqual(MIN_BASELINE_RUNS, 3)
        self.assertEqual(BAND_Z, 3.0)
        self.assertEqual(BAND_REL_FLOOR, 0.05)


class MergeCompletenessSeesADroppedRow8346(unittest.TestCase):
    """#8346: the check `lint_ledger` structurally cannot make.

    A dropped row leaves a well-formed, internally consistent, lint-clean
    file — nothing in the surviving rows says anything is missing. These
    cells pin that the completeness check sees what lint cannot, and that it
    does not fire on a legitimate merge.
    """

    @staticmethod
    def _led(*ids):
        # Built through the module's own `row()` helper so every fixture row
        # SURVIVES lint_row(). An earlier hand-rolled fixture omitted required
        # keys, which made the "lint is blind to a drop" control below fail for
        # a schema reason and look like it had detected the drop — a control
        # that passes for the wrong reason is worse than no control.
        return "\n".join(
            json.dumps(row(f"2026-09-01T00:0{n}:00Z", run_id=i))
            for n, i in enumerate(ids)
        ) + "\n"

    def test_a_dropped_row_is_reported(self):
        merged = self._led("a", "b")          # 'c' lost
        problems = lint_merge_completeness(merged, [self._led("a", "b"),
                                                    self._led("a", "c")])
        self.assertTrue(problems)
        self.assertIn("c", problems[0])

    def test_a_correct_union_is_clean(self):
        merged = self._led("a", "b", "c")
        self.assertEqual(
            lint_merge_completeness(merged, [self._led("a", "b"),
                                             self._led("a", "c")]),
            [],
        )

    def test_a_count_preserving_swap_is_still_caught(self):
        # The reason this is a SET check and not a row count: one row dropped
        # and one added leaves the count identical, so a count-based guard
        # passes on exactly the corruption it exists to catch.
        merged = self._led("a", "z")          # 'b' lost, 'z' gained
        problems = lint_merge_completeness(merged, [self._led("a", "b"), self._led("a")])
        self.assertTrue(problems)
        self.assertIn("b", problems[0])

    def test_lint_ledger_is_blind_to_the_same_drop(self):
        # The discriminating control, and the argument for this check
        # existing at all: run the ROW linter over the damaged merge result
        # and watch it report clean.
        self.assertEqual(lint_ledger(self._led("a", "b")), [])


class CoverageCensus(unittest.TestCase):
    """#9922 F-087: every wrapped gate measured, or declared unreached."""
    MAKE = "\trun --gate test-failover\n\trun --gate test-foo\n"

    def test_void_only_does_not_count_as_reached(self):
        # MUTATION: coverage-void-counts-as-measured (VOID in ever-measured).
        # MUTATION: coverage-window-void-counts-as-measured (VOID in the window).
        # A gate whose rows are all VOID never measured anything; counting
        # them would let it read green here AND as undetermined (surfaced,
        # non-failing) in the red-watch aggregate — green in both, measured
        # in neither.
        rows = [row("2026-09-01T00:00:00Z", value=100.0)] + [
            row("2026-09-01T00:01:00Z", verdict="VOID", value=None,
                gate="test-foo", void_reason="no summary")
        ]
        cov = coverage(self.MAKE, rows, "test-foo needs a recorded run\n")
        self.assertIn("test-foo", cov["void_only"])
        self.assertNotIn("test-foo", cov["reached"])
        self.assertTrue(cov["ok"])
        self.assertIn("VOID-ONLY", render_coverage(cov))
        # And without the declaration the same void-only gate fails.
        cov2 = coverage(self.MAKE, rows, "")
        self.assertEqual(cov2["missing"], ["test-foo"])
        self.assertFalse(cov2["ok"])

    def test_unreached_undeclared_is_missing(self):
        # MUTATION: coverage-missing-check-dropped (missing = []).
        rows = [row("2026-09-01T00:00:00Z", value=100.0)]
        cov = coverage(self.MAKE, rows, "")
        self.assertEqual(cov["zero_row"], ["test-foo"])
        self.assertEqual(cov["missing"], ["test-foo"])
        self.assertFalse(cov["ok"])
        self.assertIn("MISSING", render_coverage(cov))

    def test_declared_but_reached_is_stale_shrink_only(self):
        # MUTATION: coverage-stale-check-dropped (stale = []).
        rows = [row("2026-09-01T00:00:00Z", value=100.0),
                row("2026-09-01T00:01:00Z", value=100.0, gate="test-foo")]
        cov = coverage(self.MAKE, rows, "test-foo was red once\n")
        self.assertEqual(cov["stale"], ["test-foo"])
        self.assertFalse(cov["ok"])
        self.assertIn("STALE", render_coverage(cov))

    def test_declared_unreached_is_ok_and_makefile_placeholders_excluded(self):
        # $(GATE) is the harness-compare recipe's expansion, not a gate.
        make = self.MAKE + "\trun --gate $(GATE)\n"
        rows = [row("2026-09-01T00:00:00Z", value=100.0)]
        cov = coverage(make, rows, "test-foo needs a recorded run\n")
        self.assertNotIn("$(GATE)", cov["wrapped"])
        self.assertTrue(cov["ok"])

    def test_comment_prose_is_not_a_wrapped_gate(self):
        # MUTATION: coverage-recipe-filter-dropped (every line scanned).
        # The harness-coverage target's own comment says "--gate recipe";
        # without the tab-indented-recipe restriction the census adopts
        # "recipe" as a wrapped gate and the target reds itself.
        make = self.MAKE + "# Census every Makefile --gate recipe\n"
        rows = [row("2026-09-01T00:00:00Z", value=100.0)]
        cov = coverage(make, rows, "test-foo needs a recorded run\n")
        self.assertNotIn("recipe", cov["wrapped"])
        self.assertTrue(cov["ok"])

    def test_measurement_in_a_retired_env_does_not_satisfy_the_newest_env(self):
        # MUTATION: coverage-env-check-dropped (newest-env conjunct removed).
        # A gate measured long ago in env-retired whose newest rows (VOID) run
        # in the current env is NOT covered: the old other-env measurement
        # must not satisfy coverage forever.
        rows = [row("2026-09-01T00:00:00Z", value=100.0)] + [
            row("2026-08-01T00:00:00Z", value=100.0, gate="test-foo", env="env-retired"),
            row("2026-09-01T00:01:00Z", verdict="VOID", value=None,
                gate="test-foo", void_reason="cluster down"),
        ]
        cov = coverage(self.MAKE, rows, "")
        self.assertNotIn("test-foo", cov["reached"])
        self.assertIn("test-foo", cov["window_stale"])
        self.assertEqual(cov["missing"], ["test-foo"])
        self.assertFalse(cov["ok"])
        self.assertIn("STALE", render_coverage(cov))

    def test_measurement_outside_the_trailing_window_is_stale(self):
        # MUTATION: coverage-window-check-dropped (window = all rows).
        # One PASS followed by COVERAGE_WINDOW consecutive VOIDs: the gate is
        # not being measured anymore, and recency is ledger-relative (last K
        # rows), never wall-clock, so no frozen time is needed.
        olds = [row("2026-08-01T00:00:00Z", value=100.0, gate="test-foo")]
        voids = [
            row(f"2026-09-01T00:0{i}:00Z", verdict="VOID", value=None,
                gate="test-foo", void_reason="cluster down")
            for i in range(1, COVERAGE_WINDOW + 1)
        ]
        rows = [row("2026-09-01T00:00:00Z", value=100.0)] + olds + voids
        cov = coverage(self.MAKE, rows, "")
        self.assertNotIn("test-foo", cov["reached"])
        self.assertIn("test-foo", cov["window_stale"])
        self.assertFalse(cov["ok"])
        # Twin: the same history with the PASS inside the window stays reached.
        rows2 = [row("2026-09-01T00:00:00Z", value=100.0)] + voids + [
            row("2026-09-02T00:00:00Z", value=100.0, gate="test-foo")
        ]
        cov2 = coverage(self.MAKE, rows2, "")
        self.assertIn("test-foo", cov2["reached"])

    def test_positive_control_wrapped_but_unreached(self):
        # The :1054 branch: the control gate is wrapped but has no measured
        # row in its newest-env window — the matcher trips by name instead of
        # reporting a clean board.
        rows = [row("2026-09-01T00:01:00Z", value=100.0, gate="test-foo")]
        cov = coverage(self.MAKE, rows, "")
        self.assertTrue(any("test-failover" in p and "unreached" in p for p in cov["problems"]))
        self.assertFalse(cov["ok"])

    def test_positive_control_and_empty_wrapped_fail_closed(self):
        # A matcher that never reports REACHED must trip by name, not report
        # a clean board over an inverted world.
        cov = coverage("\trun --gate test-foo\n",
                       [row("2026-09-01T00:00:00Z", value=100.0, gate="test-foo")],
                       "")
        self.assertTrue(any("positive control" in p for p in cov["problems"]))
        self.assertFalse(cov["ok"])
        cov2 = coverage("no gates here\n", [], "")
        self.assertTrue(any("no --gate recipes" in p for p in cov2["problems"]))
        self.assertFalse(cov2["ok"])
        _d, problems = parse_coverage_declared("gate-only\n")
        self.assertEqual(len(problems), 1)
        self.assertIn("line 1", problems[0])

    def test_main_coverage_over_a_fixture_ledger(self):
        # End to end through main(): shards on disk, strict rc 1 on the
        # undeclared gate, rc 0 once declared, corrupt mapping to rc 2.
        work = tempfile.mkdtemp(prefix="xpf-coverage.")
        self.addCleanup(shutil.rmtree, work, True)
        for r in [row("2026-09-01T00:00:00Z", value=100.0)]:
            with open(os.path.join(work, f"{r['run_id']}.json"), "w") as fh:
                json.dump(r, fh)
        mk = os.path.join(work, "Makefile")
        with open(mk, "w") as fh:
            fh.write(self.MAKE)
        decl = os.path.join(work, "declared.txt")
        with open(decl, "w") as fh:
            fh.write("test-foo needs a recorded run\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--coverage", "--ledger", work, "--makefile", mk,
                       "--coverage-declared", decl])
        self.assertEqual(rc, 0)
        self.assertIn("coverage: OK", buf.getvalue())
        empty = os.path.join(work, "empty.txt")
        with open(empty, "w") as fh:
            fh.write("")
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc2 = main(["--coverage", "--ledger", work, "--makefile", mk,
                        "--coverage-declared", empty])
        self.assertEqual(rc2, 1)
        self.assertIn("coverage: FAIL", buf2.getvalue())
        with open(os.path.join(work, "broken.json"), "w") as fh:
            fh.write("{not json\n")
        buf3 = io.StringIO()
        with contextlib.redirect_stdout(buf3):
            rc3 = main(["--coverage", "--ledger", work, "--makefile", mk,
                        "--coverage-declared", decl])
        self.assertEqual(rc3, 2)


if __name__ == "__main__":
    unittest.main()
