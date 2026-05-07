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
    if total_cells == 0 || total_bytes == 0 {
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
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 0.005
    }

    // Worked-example table from docs/fairness-regimes.md:

    #[test]
    fn cstruct_perfectly_balanced() {
        // {2,2,2,2,2,2}: 12 flows on 6 workers, each gets 1/2 share.
        // All shares equal -> CoV = 0.
        assert!(close(compute_cstruct(&[2, 2, 2, 2, 2, 2]), 0.00));
    }

    #[test]
    fn cstruct_mild_skew() {
        // {1,1,2,2,3,3}: 12 flows on 6 workers.
        // Share multiset = {1, 1, 1/2 × 4, 1/3 × 6}.
        // Mean = 6/12 = 0.5; verified CoV = 0.4714 (~ 0.47).
        assert!(close(compute_cstruct(&[1, 1, 2, 2, 3, 3]), 0.47));
    }

    #[test]
    fn cstruct_one_idle() {
        // {0,2,2,2,3,3}: 12 flows on 5 active workers.
        // Share multiset = {1/2 × 6, 1/3 × 6}; CoV = 0.20.
        assert!(close(compute_cstruct(&[0, 2, 2, 2, 3, 3]), 0.20));
    }

    #[test]
    fn cstruct_severe_skew() {
        // {1,3,0,0,0,0}: 4 flows on 2 active workers.
        // Share multiset = {1, 1/3 × 3}; mean = 2/4 = 0.5;
        // CoV = 0.5774 (~ 0.58).
        assert!(close(compute_cstruct(&[1, 3, 0, 0, 0, 0]), 0.58));
    }

    #[test]
    fn cstruct_degenerate_balanced() {
        // {6,0,0,0,0,6}: 12 flows on 2 workers, each fully loaded
        // with 6 flows. All shares = 1/6; CoV = 0.
        assert!(close(compute_cstruct(&[6, 0, 0, 0, 0, 6]), 0.00));
    }

    #[test]
    fn cstruct_empty_distribution() {
        assert_eq!(compute_cstruct(&[]), 0.0);
    }

    #[test]
    fn cstruct_all_idle() {
        assert_eq!(compute_cstruct(&[0, 0, 0]), 0.0);
    }

    #[test]
    fn cstruct_single_active_one_flow() {
        // 1 flow on 1 worker = trivially "fair" (1 share).
        assert_eq!(compute_cstruct(&[1, 0, 0, 0]), 0.0);
    }

    #[test]
    fn observed_cov_balanced() {
        assert!(close(
            compute_observed_cov(&[1_000, 1_000, 1_000, 1_000]),
            0.0
        ));
    }

    #[test]
    fn observed_cov_skewed() {
        // {500, 500, 1500, 1500}: mean = 1000; var = 250000;
        // stddev = 500; CoV = 0.5.
        assert!(close(compute_observed_cov(&[500, 500, 1500, 1500]), 0.5));
    }

    #[test]
    fn observed_cov_empty() {
        assert_eq!(compute_observed_cov(&[]), 0.0);
    }

    #[test]
    fn observed_cov_zero_mean() {
        assert_eq!(compute_observed_cov(&[0, 0, 0]), 0.0);
    }

    #[test]
    fn starved_none() {
        let buckets = vec![
            vec![100u64; 60],
            vec![100u64; 60],
            vec![100u64; 60],
        ];
        assert_eq!(starved_flow_count(&buckets), 0);
    }

    #[test]
    fn starved_one_persistent() {
        // Flow 0 is starved (always below 1% of mean); flows 1-3
        // are healthy.
        let mut buckets = vec![vec![0u64; 60]; 4];
        buckets[0] = vec![0u64; 60];
        for i in 1..4 {
            buckets[i] = vec![1_000u64; 60];
        }
        // Mean per cell: (0 + 60_000 × 3) / (60 × 4) = 750.
        // Threshold: 7.5. Flow 0 cells (all 0) all below.
        assert_eq!(starved_flow_count(&buckets), 1);
    }

    #[test]
    fn starved_transient_does_not_count() {
        // Flow 0 dips below 1% in some buckets but recovers.
        // Should NOT count as starved.
        let mut buckets = vec![vec![1_000u64; 60]; 4];
        buckets[0] = vec![0u64; 5]
            .into_iter()
            .chain(vec![1_000u64; 55])
            .collect();
        assert_eq!(starved_flow_count(&buckets), 0);
    }

    #[test]
    fn starved_empty() {
        assert_eq!(starved_flow_count(&[]), 0);
    }

    #[test]
    fn saturated_at_cap() {
        let buckets = vec![1_000u64; 60];
        assert!(is_saturated(&buckets, 1_000));
    }

    #[test]
    fn saturated_below_cap() {
        let buckets = vec![500u64; 60];
        assert!(!is_saturated(&buckets, 1_000));
    }

    #[test]
    fn saturated_partial() {
        // 70% of buckets at cap, 30% at half-cap. < 80% threshold.
        let mut buckets = vec![1_000u64; 42];
        buckets.extend(vec![500u64; 18]);
        assert!(!is_saturated(&buckets, 1_000));
    }

    #[test]
    fn saturated_exactly_threshold() {
        // 80% of buckets at cap, 20% below. == 80% threshold.
        let mut buckets = vec![1_000u64; 48];
        buckets.extend(vec![500u64; 12]);
        assert!(is_saturated(&buckets, 1_000));
    }

    #[test]
    fn saturated_zero_cap() {
        // Zero structural cap = no saturation possible.
        assert!(!is_saturated(&[1_000u64; 60], 0));
    }

    #[test]
    fn saturated_empty() {
        assert!(!is_saturated(&[], 1_000));
    }
}
