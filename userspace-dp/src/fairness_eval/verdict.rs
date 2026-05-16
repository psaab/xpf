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

    let cstruct_distribution_a_i = if a_i_delta > 0 && a_i_sum_check_ok {
        trim_distribution_to_sum(input.distribution_a_i, expected_sum)
    } else {
        input.distribution_a_i.to_vec()
    };
    let cstruct_adjusted_for_a_i_overcount = cstruct_distribution_a_i != input.distribution_a_i;

    let cstruct = compute_cstruct(&cstruct_distribution_a_i);
    let n_active: u32 = input.distribution_a_i.iter().filter(|&&a| a > 0).count() as u32;
    let max_worker_flow_share = max_worker_flow_share(input.distribution_a_i);
    let (rss_expectation_pass, rss_expectation_reason) = evaluate_rss_expectation(
        input.rss_expectation,
        input.distribution_a_i,
        compute_cstruct(input.distribution_a_i),
        input.n_total_workers,
    );
    let gap = input.observed_cov - cstruct;

    // Saturation: structural cap = (n_active / n_total_workers) × shaper_rate.
    // shaper_rate provided via --shaper-rate-bps; if zero, skip the saturated check.
    let saturated = if input.shaper_rate_bps > 0 && input.n_total_workers > 0 {
        let structural_cap_bps = (input.shaper_rate_bps as u128 * n_active as u128
            / input.n_total_workers as u128) as u64;
        is_saturated(input.aggregate_buckets_bps, structural_cap_bps)
    } else {
        false
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
