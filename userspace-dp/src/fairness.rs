//! Fairness regime computations per `docs/fairness-regimes.md`.
//!
//! These are pure functions (no I/O, no global state) used by:
//! - the production harness `fairness-eval` binary that consumes
//!   iperf3 JSON + scraped Prometheus metrics and emits the
//!   contract gates' verdict
//! - tests that pin the contract's worked-example table to its
//!   numeric values (single source of truth for the math)
//!
//! See `docs/pr/1219-fairness-harness/plan.md` for design.

/// Compute the structural CoV ceiling `Cstruct` for an observed
/// per-worker active-flow distribution.
///
/// `distribution[i]` = active flow count on worker i. Idle workers
/// (`a_i == 0`) are excluded from the per-flow set per the contract:
/// "the idle worker is excluded from the per-flow set (it has zero
/// flows), not 'compensating' for anything".
///
/// Returns the population CoV: `stddev / mean` across the per-flow
/// share multiset `{1/a_i : repeated a_i times for each active worker
/// i}`. The `S/N_v` cluster-aggregate scaling factor cancels because
/// CoV is dimensionless.
pub fn compute_cstruct(distribution: &[u32]) -> f64 {
    let mut shares: Vec<f64> = Vec::new();
    for &a_i in distribution {
        if a_i == 0 {
            continue;
        }
        let share = 1.0_f64 / (a_i as f64);
        for _ in 0..a_i {
            shares.push(share);
        }
    }
    if shares.is_empty() {
        return 0.0;
    }
    let mean = shares.iter().sum::<f64>() / (shares.len() as f64);
    if mean == 0.0 {
        return 0.0;
    }
    let var = shares
        .iter()
        .map(|s| (*s - mean).powi(2))
        .sum::<f64>()
        / (shares.len() as f64);
    var.sqrt() / mean
}

/// Compute observed CoV across the per-flow throughput vector
/// from the steady-state window. Returns the sample/population CoV
/// (`stddev / mean` over the input vector).
pub fn compute_observed_cov(per_flow_throughputs: &[u64]) -> f64 {
    if per_flow_throughputs.is_empty() {
        return 0.0;
    }
    let mean = per_flow_throughputs
        .iter()
        .map(|&x| x as f64)
        .sum::<f64>()
        / (per_flow_throughputs.len() as f64);
    if mean == 0.0 {
        return 0.0;
    }
    let var = per_flow_throughputs
        .iter()
        .map(|&x| (x as f64 - mean).powi(2))
        .sum::<f64>()
        / (per_flow_throughputs.len() as f64);
    var.sqrt() / mean
}

/// Count flows whose throughput stayed `< 1%` of mean per-flow
/// throughput for the **entire** steady-state window. Per the
/// contract: "A flow that drops below 1% transiently but recovers
/// does not count."
///
/// Zero-throughput window (#16540): when `total_bytes == 0` every
/// flow delivered nothing for the whole window. That is the
/// canonical starved case — the contract names the metric
/// "starved" rather than "zero-throughput" only to avoid implying
/// strict 0 Mb/s, which makes 0 the extreme of the `< 1% of mean`
/// rule, not an exception to it. The arithmetic threshold cannot
/// express it (mean is 0, and `0 < 0` is false), so it is handled
/// explicitly: every flow counts as starved. Without this, a run
/// that blackholes the class scores CoV 0 / 0 starved and PASSes
/// the merge gate — a false green automation keyed on `verdict`
/// would accept. Streams seeded with an empty bucket vec (never
/// present in any steady-state interval) delivered zero bytes too
/// and likewise count. An empty flow set (`&[]`) still returns 0:
/// there is no flow to starve.
///
/// `per_flow_buckets[i]` is flow i's per-second-bucket throughput
/// vector across the steady-state window.
pub fn starved_flow_count(per_flow_buckets: &[Vec<u64>]) -> u32 {
    if per_flow_buckets.is_empty() {
        return 0;
    }
    let total_cells: u64 = per_flow_buckets.iter().map(|v| v.len() as u64).sum();
    let total_bytes: u64 = per_flow_buckets
        .iter()
        .flat_map(|v| v.iter().copied())
        .sum();
    if total_bytes == 0 {
        return per_flow_buckets.len() as u32;
    }
    if total_cells == 0 {
        return 0;
    }
    let mean_per_cell = total_bytes as f64 / total_cells as f64;
    let starved_threshold = 0.01_f64 * mean_per_cell;
    let mut starved = 0u32;
    for flow_buckets in per_flow_buckets {
        let always_below = flow_buckets
            .iter()
            .all(|&b| (b as f64) < starved_threshold);
        if always_below {
            starved += 1;
        }
    }
    starved
}

/// Determine saturation per the contract: aggregate `≥ 95%` of
/// `(N_a / N_v) × shaper_rate` for `≥ 80%` of 1-second buckets.
///
/// `aggregate_buckets_bps[t]` = aggregate throughput at bucket t.
/// `structural_cap_bps` = `(N_a / N_v) × shaper_rate` precomputed
/// by the caller (the harness reads `N_a` from the binding metric
/// and `N_v` + `shaper_rate` from the queue config).
pub fn is_saturated(aggregate_buckets_bps: &[u64], structural_cap_bps: u64) -> bool {
    if aggregate_buckets_bps.is_empty() || structural_cap_bps == 0 {
        return false;
    }
    let threshold = (structural_cap_bps as f64 * 0.95) as u64;
    let above_count = aggregate_buckets_bps
        .iter()
        .filter(|&&b| b >= threshold)
        .count();
    let ratio = above_count as f64 / aggregate_buckets_bps.len() as f64;
    ratio >= 0.80
}

#[cfg(test)]
#[path = "fairness_tests.rs"]
mod tests;
