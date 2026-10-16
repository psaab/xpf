use crate::fairness::{compute_cstruct, is_saturated};

use super::per_worker::{
    direction_multiplier, guard_sum_tolerances, max_worker_flow_share, trim_distribution_to_sum,
};
use super::rss::{evaluate_rss_expectation, RssExpectation};

pub(crate) const EPSILON: f64 = 0.05;
// Tolerance for the harness fail-fast guard per Codex round-4
// finding #3: sum(per_binding_active_flow_count) should stay near
// expected_sum, where
// expected_sum = non-starved_streams × direction_multiplier
// (direction_multiplier=1 when iface_filter_active=true, 2 for
// legacy/bidirectional input).
//
// #1281: active-flow gauges can report recently-active/stale flow-cache
// entries persistently enough to survive the steady-state median. Preserve
// the stricter undercount guard because missing telemetry masks real flow
// loss, but allow a bounded one-sided overcount window and normalize that
// accepted overcount before computing Cstruct.
pub(crate) const GUARD_RELATIVE: f64 = 0.10;
pub(crate) const GUARD_OVERCOUNT_DIVISOR: u32 = 4;
pub(crate) const GUARD_ABSOLUTE: u32 = 2;

pub(crate) struct VerdictInput<'a> {
    pub(crate) observed_cov: f64,
    pub(crate) aggregate_buckets_bps: &'a [u64],
    pub(crate) shaper_rate_bps: u64,
    pub(crate) distribution_a_i: &'a [u32],
    pub(crate) binding_distribution_a_i: &'a [u32],
    pub(crate) cstruct_source: &'static str,
    pub(crate) starved: u32,
    pub(crate) n_iperf_streams: u32,
    pub(crate) n_total_workers: u32,
    pub(crate) iface_filter_active: bool,
    pub(crate) rss_expectation: &'a RssExpectation,
    /// Operator declaration that the offered load is >= the structural
    /// cap, so the observed aggregate is REQUIRED to reach it (Gate 3).
    /// This is the independent input that breaks the V-3 circularity:
    /// the `saturated` label is descriptive, but enforcement is driven
    /// by this declaration, not by re-reading the same is_saturated
    /// predicate.
    pub(crate) expect_saturation: bool,
}

pub(crate) struct VerdictDecision {
    pub(crate) cstruct_distribution_a_i: Vec<u32>,
    pub(crate) cstruct_adjusted_for_a_i_overcount: bool,
    pub(crate) rss_expectation_pass: bool,
    pub(crate) rss_expectation_reason: String,
    pub(crate) max_worker_flow_share: f64,
    pub(crate) n_active: u32,
    pub(crate) cstruct: f64,
    pub(crate) gap: f64,
    pub(crate) saturated: bool,
    pub(crate) structural_cap_bps: u64,
    pub(crate) saturated_bucket_fraction: f64,
    pub(crate) aggregate_throughput_gate_enforced: bool,
    pub(crate) a_i_sum_check_ok: bool,
    pub(crate) a_i_sum: u32,
    pub(crate) iperf_non_starved_streams: u32,
    pub(crate) a_i_sum_under_tolerance: u32,
    pub(crate) a_i_sum_over_tolerance: u32,
    pub(crate) a_i_sum_tolerance: u32,
    pub(crate) verdict: &'static str,
    pub(crate) failure_reasons: Vec<String>,
}

pub(crate) fn evaluate(input: VerdictInput<'_>) -> VerdictDecision {
    // Harness fail-fast guard: sum(a_i) vs non-starved iperf stream count.
    //
    // Codex round-4 finding: with --iface filtering (the per-worker
    // contract introduced in round-3) we are looking at a single
    // direction's flow_cache only. The sum is therefore ~n_streams,
    // NOT 2×n_streams (which was correct only for the legacy
    // unfiltered/cross-iface aggregation that round-3 killed).
    //
    // Backward-compat: if the harness is run without --iface (legacy
    // 3-column TSV), rows are accepted across all interfaces and the
    // bidirectional 2× assumption still holds. We pick the multiplier
    // based on whether iface filtering is in effect.
    let a_i_sum: u32 = input.distribution_a_i.iter().sum();
    let binding_a_i_sum: u32 = input.binding_distribution_a_i.iter().sum();
    let n_non_starved = input.n_iperf_streams.saturating_sub(input.starved);
    // iface filter active => single-direction flow_cache, ~1×; otherwise
    // ~2× for bidirectional (both ingress and egress) entries. Use
    // iface_filter_active (not raw args.iface) so the legacy-input
    // fallback path uses the bidirectional multiplier as well.
    let dir_mult = direction_multiplier(input.iface_filter_active);
    let expected_sum = n_non_starved.saturating_mul(dir_mult);
    let (under_tolerance, over_tolerance) = guard_sum_tolerances(expected_sum);
    let a_i_delta = a_i_sum as i64 - expected_sum as i64;
    let a_i_abs_delta = a_i_delta.unsigned_abs() as u32;
    let tolerance = if a_i_delta > 0 {
        over_tolerance
    } else {
        under_tolerance
    };
    let a_i_sum_check_ok = a_i_abs_delta <= tolerance;

    // Candidate normalized distribution: trim an accepted overcount down
    // to the expected sum. `trim_distribution_to_sum` removes from the
    // LARGEST bucket, which for an evenly-loaded overcount MANUFACTURES
    // skew and RAISES Cstruct — loosening the Gate-2 tolerance
    // (observed_CoV ≤ Cstruct + 0.05). That is fail-open in exactly the
    // wrong direction (V-4). Gate on the TIGHTER of raw vs trimmed
    // Cstruct (fail-closed): the overcount normalization may only tighten
    // the ceiling, never loosen it. The legitimate #1281 stale-overcount
    // cases (e.g. {4,4,4,3,0,0} → {3,3,3,3,0,0}) trim to a LOWER Cstruct,
    // so they still normalize; only a trim that would raise Cstruct falls
    // back to the raw ceiling.
    let trimmed_distribution_a_i = if a_i_delta > 0 && a_i_sum_check_ok {
        trim_distribution_to_sum(input.distribution_a_i, expected_sum)
    } else {
        input.distribution_a_i.to_vec()
    };
    let cstruct_raw = compute_cstruct(input.distribution_a_i);
    let cstruct_trimmed = compute_cstruct(&trimmed_distribution_a_i);
    let (cstruct_distribution_a_i, cstruct) = if cstruct_trimmed < cstruct_raw {
        (trimmed_distribution_a_i, cstruct_trimmed)
    } else {
        (input.distribution_a_i.to_vec(), cstruct_raw)
    };
    let cstruct_adjusted_for_a_i_overcount = cstruct_distribution_a_i != input.distribution_a_i;

    let n_active: u32 = input.distribution_a_i.iter().filter(|&&a| a > 0).count() as u32;
    let max_worker_flow_share = max_worker_flow_share(input.distribution_a_i);
    // Distribution-based RSS expectations describe actual RSS placement and
    // therefore use observed `a_i`; `cstruct-max` is specifically a ceiling
    // on Gate 2's selected, fail-closed Cstruct, not on a second raw-only
    // Cstruct value hidden from the report (#13658).
    let (rss_expectation_pass, rss_expectation_reason) = evaluate_rss_expectation(
        input.rss_expectation,
        input.distribution_a_i,
        cstruct,
        input.n_total_workers,
    );
    let gap = input.observed_cov - cstruct;

    // Saturation: structural cap = (n_active / n_total_workers) × shaper_rate.
    // shaper_rate provided via --shaper-rate-bps; if zero, the cap is
    // unknown (0) and saturation cannot be determined.
    let structural_cap_bps = if input.shaper_rate_bps > 0 && input.n_total_workers > 0 {
        (input.shaper_rate_bps as u128 * n_active as u128 / input.n_total_workers as u128) as u64
    } else {
        0
    };
    // `saturated` stays a report-only descriptive LABEL (is_saturated
    // over the observed aggregate). It does NOT drive Gate 3 — enforcing
    // the aggregate gate off this same label is vacuous (V-3).
    let saturated = is_saturated(input.aggregate_buckets_bps, structural_cap_bps);
    let saturated_bucket_fraction =
        if structural_cap_bps > 0 && !input.aggregate_buckets_bps.is_empty() {
            let threshold = (structural_cap_bps as f64 * 0.95) as u64;
            let above = input
                .aggregate_buckets_bps
                .iter()
                .filter(|&&b| b >= threshold)
                .count();
            above as f64 / input.aggregate_buckets_bps.len() as f64
        } else {
            0.0
        };

    let mut failure_reasons: Vec<String> = Vec::new();
    if input.starved > 0 {
        failure_reasons.push(format!(
            "Gate 1 (starved flows): {} flow(s) below 1% of mean per-flow throughput for the entire steady-state window",
            input.starved
        ));
    }
    if gap > EPSILON {
        failure_reasons.push(format!(
            "Gate 2 (per-flow CoV): observed_cov - cstruct = {gap:.4} > epsilon {EPSILON}"
        ));
    }
    if !a_i_sum_check_ok {
        let direction = if a_i_delta > 0 { "above" } else { "below" };
        failure_reasons.push(format!(
            "Harness guard: sum(a_i)={a_i_sum} vs expected={expected_sum} \
             (non-starved={n_non_starved} × dir_mult={dir_mult}) \
             is {a_i_abs_delta} {direction} expected, exceeding tolerance={tolerance} \
             (under_tolerance={under_tolerance}, over_tolerance={over_tolerance})"
        ));
    }
    if !rss_expectation_pass {
        failure_reasons.push(format!("RSS expectation: {rss_expectation_reason}"));
    }
    if input.cstruct_source == "cos_queue" && binding_a_i_sum + tolerance < a_i_sum {
        failure_reasons.push(format!(
            "Harness guard: selected CoS sum(a_i)={a_i_sum} exceeds binding sum(a_i)={binding_a_i_sum} by more than tolerance={tolerance}; check --iface/--cos-ifindex/--cos-queue-id"
        ));
    }

    // Gate 3 (aggregate throughput). Enforced only when the operator
    // declares the offered load is expected to saturate the structural
    // cap (--expect-saturation). This breaks the V-3 circularity: the
    // `saturated` LABEL above is is_saturated over observed data, so
    // gating off it can never FAIL (a run that misses the cap is simply
    // labeled non-saturated and exempted). The operator declaration is an
    // INDEPENDENT input observed data cannot launder — the run OUGHT to
    // reach the cap, so the observed aggregate is required to actually
    // hit >=95% of the Nₐ/Nᵥ-scaled cap for >=80% of buckets.
    if input.expect_saturation {
        if structural_cap_bps == 0 {
            failure_reasons.push(
                "Gate 3 (aggregate throughput): --expect-saturation requires --shaper-rate-bps and --n-workers>0 to compute the Nₐ/Nᵥ-scaled structural cap".to_string(),
            );
        } else if !saturated {
            failure_reasons.push(format!(
                "Gate 3 (aggregate throughput): offered load declared saturating (--expect-saturation) but observed aggregate stayed below 95% of the Nₐ/Nᵥ-scaled cap ({:.1} Mb/s, Nₐ={}/Nᵥ={}) for >20% of steady-state buckets (saturated_bucket_fraction={:.2})",
                structural_cap_bps as f64 / 1_000_000.0,
                n_active,
                input.n_total_workers,
                saturated_bucket_fraction,
            ));
        }
    }

    let verdict = if failure_reasons.is_empty() {
        "PASS"
    } else {
        "FAIL"
    };

    VerdictDecision {
        cstruct_distribution_a_i,
        cstruct_adjusted_for_a_i_overcount,
        rss_expectation_pass,
        rss_expectation_reason,
        max_worker_flow_share,
        n_active,
        cstruct,
        gap,
        saturated,
        structural_cap_bps,
        saturated_bucket_fraction,
        aggregate_throughput_gate_enforced: input.expect_saturation,
        a_i_sum_check_ok,
        a_i_sum,
        iperf_non_starved_streams: n_non_starved,
        a_i_sum_under_tolerance: under_tolerance,
        a_i_sum_over_tolerance: over_tolerance,
        a_i_sum_tolerance: tolerance,
        verdict,
        failure_reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input<'a>(
        distribution_a_i: &'a [u32],
        rss: &'a RssExpectation,
        observed_cov: f64,
        n_iperf_streams: u32,
        n_total_workers: u32,
    ) -> VerdictInput<'a> {
        VerdictInput {
            observed_cov,
            aggregate_buckets_bps: &[],
            shaper_rate_bps: 0,
            distribution_a_i,
            binding_distribution_a_i: distribution_a_i,
            cstruct_source: "binding",
            starved: 0,
            n_iperf_streams,
            n_total_workers,
            iface_filter_active: true,
            rss_expectation: rss,
            expect_saturation: false,
        }
    }

    #[test]
    fn overcount_trim_never_loosens_gate2() {
        // V-4: {3,3} observed with an accepted overcount whose expected
        // sum is 5 trims to {2,3}: raw Cstruct 0.00, trimmed Cstruct
        // ~0.204. The gate must use the TIGHTER raw ceiling (fail-closed)
        // so observed_cov=0.10 exceeds Cstruct+epsilon and Gate 2 FAILS.
        // The buggy trim would raise Cstruct to ~0.204, making the gap
        // negative and PASSing an unfair run.
        let dist = [3u32, 3];
        let rss = RssExpectation::Any;
        // n_iperf_streams=5, iface filter active → dir_mult=1 →
        // expected_sum=5; a_i_sum=6 → +1 overcount inside tolerance → the
        // trim path is exercised.
        let d = evaluate(base_input(&dist, &rss, 0.10, 5, 2));
        assert!(
            d.cstruct <= 1e-9,
            "Cstruct must use the tighter raw ceiling (0.0), got {}",
            d.cstruct
        );
        assert_eq!(d.cstruct_distribution_a_i, vec![3, 3]);
        assert!(!d.cstruct_adjusted_for_a_i_overcount);
        assert_eq!(d.verdict, "FAIL");
        assert!(
            d.failure_reasons.iter().any(|r| r.contains("Gate 2")),
            "must fail Gate 2: {:?}",
            d.failure_reasons
        );
    }

    #[test]
    fn overcount_trim_still_normalizes_when_it_tightens() {
        // The legitimate #1281 case: {4,4,4,3,0,0} with expected_sum=12
        // trims to {3,3,3,3,0,0}. Raw Cstruct ~0.125, trimmed 0.0 → the
        // trim LOWERS the ceiling, so it is applied (fail-closed keeps
        // the min).
        let dist = [4u32, 4, 4, 3, 0, 0];
        let rss = RssExpectation::Any;
        let d = evaluate(base_input(&dist, &rss, 0.0, 12, 6));
        assert_eq!(d.cstruct_distribution_a_i, vec![3, 3, 3, 3, 0, 0]);
        assert!(d.cstruct_adjusted_for_a_i_overcount);
        assert!(d.cstruct <= 1e-9, "trimmed Cstruct is 0.0, got {}", d.cstruct);
    }

    #[test]
    fn expect_saturation_below_cap_fails_gate3() {
        // V-3: aggregate ~6 Gbps against a 20 Gbps scaled cap is NOT
        // saturated. Without --expect-saturation the aggregate leg is
        // diagnostic and the run PASSes; with it, Gate 3 FAILS.
        let dist = [1u32, 1, 1, 1, 1, 1];
        let rss = RssExpectation::Any;
        let buckets = vec![6_000_000_000u64; 60];
        let mut input = base_input(&dist, &rss, 0.0, 6, 6);
        input.aggregate_buckets_bps = &buckets;
        input.shaper_rate_bps = 20_000_000_000;
        // Diagnostic-only default: no gate.
        let diag = evaluate(input);
        assert_eq!(diag.verdict, "PASS");
        assert!(!diag.saturated);
        assert!(!diag.aggregate_throughput_gate_enforced);

        let mut input = base_input(&dist, &rss, 0.0, 6, 6);
        input.aggregate_buckets_bps = &buckets;
        input.shaper_rate_bps = 20_000_000_000;
        input.expect_saturation = true;
        let enforced = evaluate(input);
        assert_eq!(enforced.verdict, "FAIL");
        assert!(enforced.aggregate_throughput_gate_enforced);
        assert!(
            enforced
                .failure_reasons
                .iter()
                .any(|r| r.contains("Gate 3")),
            "must fail Gate 3: {:?}",
            enforced.failure_reasons
        );
    }

    #[test]
    fn expect_saturation_at_cap_passes_gate3() {
        // Aggregate at the scaled cap (>=95%) with --expect-saturation
        // must PASS — the gate is enforceable, not always-firing.
        let dist = [1u32, 1, 1, 1, 1, 1];
        let rss = RssExpectation::Any;
        let buckets = vec![6_000_000_000u64; 60];
        let mut input = base_input(&dist, &rss, 0.0, 6, 6);
        input.aggregate_buckets_bps = &buckets;
        input.shaper_rate_bps = 6_000_000_000;
        input.expect_saturation = true;
        let d = evaluate(input);
        assert!(d.saturated);
        assert_eq!(d.verdict, "PASS");
        assert!(d.aggregate_throughput_gate_enforced);
    }
}
