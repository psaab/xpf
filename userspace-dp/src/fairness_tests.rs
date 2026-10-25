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
    let buckets = vec![vec![100u64; 60], vec![100u64; 60], vec![100u64; 60]];
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
fn starved_all_zero_counts_every_flow() {
    // #16540: total_bytes == 0 is the canonical starved case (mean is
    // 0, so 0 is not `< 1% of mean` arithmetically). Every flow in the
    // window delivered nothing, so every flow counts as starved.
    let buckets = vec![vec![0u64; 60]; 6];
    assert_eq!(starved_flow_count(&buckets), 6);
}

#[test]
fn starved_all_empty_buckets_counts_every_flow() {
    // Seeded streams that never appear in any steady-state interval
    // carry an empty bucket vec and also delivered zero bytes.
    let buckets: Vec<Vec<u64>> = vec![Vec::new(), Vec::new(), Vec::new()];
    assert_eq!(starved_flow_count(&buckets), 3);
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
