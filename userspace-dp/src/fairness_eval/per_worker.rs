use std::collections::BTreeMap;

use super::inputs::{BindingFlowsRow, CosFlowsRow};
use super::verdict::{GUARD_ABSOLUTE, GUARD_OVERCOUNT_DIVISOR, GUARD_RELATIVE};

#[cfg_attr(test, derive(Debug))]
pub(crate) struct AggregateResult {
    pub(crate) distribution_a_i: Vec<u32>,
    pub(crate) iface_filter_active: bool,
}

/// Per-worker {a_i} aggregation over the steady-state window.
///
/// - filter rows by `iface_arg` when iface labels are present;
/// - sum counts per `(timestamp, worker_id)`;
/// - take the median of those sums per worker over the window;
/// - return one entry per `0..n_total_workers` (workers with no
///   matching samples report 0).
///
/// Returns `Err(msg)` immediately if any in-window, in-iface row
/// carries `worker_id >= n_total_workers`. Silently dropping such
/// rows would skew `{a_i}` and produce a false PASS if `--n-workers`
/// is misconfigured; failing fast forces the operator to correct it.
///
/// Returns `iface_filter_active=true` only when the user supplied an
/// iface AND at least one TSV row carried a non-empty iface label.
/// Legacy 3-column input (all `iface == ""`) collapses the filter to
/// inactive even when `iface_arg` is non-empty, matching the
/// bidirectional-2× guard fall-through in `main()`.
pub(crate) fn aggregate_per_worker(
    binding_flows: &[BindingFlowsRow],
    iface_arg: &str,
    n_total_workers: u32,
    warmup_secs: u64,
    final_burst_secs: u64,
) -> Result<AggregateResult, String> {
    let any_iface_label_present = binding_flows.iter().any(|r| !r.iface.is_empty());
    if !iface_arg.is_empty() && !any_iface_label_present && !binding_flows.is_empty() {
        eprintln!(
            "fairness-eval: WARNING — --iface={iface_arg} supplied but TSV rows have no iface label \
             (legacy 3-column input). Filter will drop ALL rows; treating --iface as unset.",
        );
    }
    let iface_filter_active = !iface_arg.is_empty() && any_iface_label_present;

    let ss_start_ts = binding_flows
        .iter()
        .map(|r| r.timestamp)
        .min()
        .unwrap_or(0)
        .saturating_add(warmup_secs);
    let ss_end_ts = binding_flows
        .iter()
        .map(|r| r.timestamp)
        .max()
        .unwrap_or(0)
        .saturating_sub(final_burst_secs);

    let mut per_ts_worker: BTreeMap<(u64, u32), u32> = BTreeMap::new();
    for row in binding_flows {
        if row.timestamp < ss_start_ts || row.timestamp > ss_end_ts {
            continue;
        }
        if iface_filter_active && row.iface != iface_arg {
            continue;
        }
        if row.worker_id >= n_total_workers {
            // Silently dropping out-of-range worker IDs would skew {a_i}
            // and produce a false PASS if --n-workers is misconfigured.
            return Err(format!(
                "worker_id={} in TSV exceeds --n-workers={n_total_workers}; \
                 re-run with the correct --n-workers value",
                row.worker_id
            ));
        }
        *per_ts_worker
            .entry((row.timestamp, row.worker_id))
            .or_insert(0) += row.count;
    }

    let mut per_worker_samples: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for ((_ts, w), c) in per_ts_worker {
        per_worker_samples.entry(w).or_default().push(c);
    }
    let distribution_a_i: Vec<u32> = (0..n_total_workers)
        .map(|w| {
            per_worker_samples
                .get(&w)
                .map(|samples| {
                    let mut s = samples.clone();
                    s.sort_unstable();
                    s[s.len() / 2]
                })
                .unwrap_or(0)
        })
        .collect();

    Ok(AggregateResult {
        distribution_a_i,
        iface_filter_active,
    })
}

pub(crate) fn aggregate_cos_per_worker(
    cos_flows: &[CosFlowsRow],
    cos_ifindex: i32,
    cos_queue_id: u32,
    n_total_workers: u32,
    warmup_secs: u64,
    final_burst_secs: u64,
) -> Result<Vec<u32>, String> {
    let ss_start_ts = cos_flows
        .iter()
        .map(|r| r.timestamp)
        .min()
        .unwrap_or(0)
        .saturating_add(warmup_secs);
    let ss_end_ts = cos_flows
        .iter()
        .map(|r| r.timestamp)
        .max()
        .unwrap_or(0)
        .saturating_sub(final_burst_secs);

    let mut per_ts_worker: BTreeMap<(u64, u32), u32> = BTreeMap::new();
    for row in cos_flows {
        if row.timestamp < ss_start_ts || row.timestamp > ss_end_ts {
            continue;
        }
        if row.ifindex != cos_ifindex || row.queue_id != cos_queue_id {
            continue;
        }
        if row.worker_id >= n_total_workers {
            return Err(format!(
                "worker_id={} in CoS TSV exceeds --n-workers={n_total_workers}; \
                 re-run with the correct --n-workers value",
                row.worker_id
            ));
        }
        *per_ts_worker
            .entry((row.timestamp, row.worker_id))
            .or_insert(0) += row.count;
    }

    let mut per_worker_samples: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for ((_ts, w), c) in per_ts_worker {
        per_worker_samples.entry(w).or_default().push(c);
    }
    Ok((0..n_total_workers)
        .map(|w| {
            per_worker_samples
                .get(&w)
                .map(|samples| {
                    let mut s = samples.clone();
                    s.sort_unstable();
                    s[s.len() / 2]
                })
                .unwrap_or(0)
        })
        .collect())
}

pub(crate) fn max_worker_flow_share(distribution_a_i: &[u32]) -> f64 {
    let total: u32 = distribution_a_i.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let max = distribution_a_i.iter().copied().max().unwrap_or(0);
    max as f64 / total as f64
}

pub(crate) fn direction_multiplier(iface_filter_active: bool) -> u32 {
    if iface_filter_active {
        1
    } else {
        2
    }
}

pub(crate) fn guard_sum_tolerances(expected_sum: u32) -> (u32, u32) {
    let under = ((GUARD_RELATIVE * expected_sum as f64) as u32).max(GUARD_ABSOLUTE);
    let over = expected_sum.saturating_add(GUARD_OVERCOUNT_DIVISOR - 1) / GUARD_OVERCOUNT_DIVISOR;
    (under, over.max(GUARD_ABSOLUTE))
}

pub(crate) fn trim_distribution_to_sum(distribution: &[u32], target_sum: u32) -> Vec<u32> {
    let mut trimmed = distribution.to_vec();
    let mut excess = trimmed.iter().sum::<u32>().saturating_sub(target_sum);
    while excess > 0 {
        let Some((idx, _)) = trimmed
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
            .max_by_key(|(_, count)| **count)
        else {
            break;
        };
        trimmed[idx] -= 1;
        excess -= 1;
    }
    trimmed
}

#[cfg(test)]
mod tests {
    //! Codex round-5 finding #1: these tests exercise the
    //! production aggregation helper and the direction multiplier
    //! gate end-to-end, not just the parser shape. They will
    //! catch:
    //!   - per-worker grouping replaced by per-binding grouping;
    //!   - direction_multiplier reverted from 1 → 2 when iface
    //!     filter is active;
    //!   - iface_filter_active misclassifying legacy 3-col input;
    //!   - sum-then-median replaced by raw count.
    use super::*;

    fn row(ts: u64, slot: u32, qid: u32, wid: u32, iface: &str, count: u32) -> BindingFlowsRow {
        BindingFlowsRow {
            timestamp: ts,
            binding_slot: slot,
            queue_id: qid,
            worker_id: wid,
            iface: iface.to_string(),
            count,
        }
    }

    fn cos_row(ts: u64, ifindex: i32, qid: u32, wid: u32, count: u32) -> CosFlowsRow {
        CosFlowsRow {
            timestamp: ts,
            ifindex,
            queue_id: qid,
            worker_id: wid,
            count,
        }
    }

    #[test]
    fn aggregate_per_worker_filters_iface_and_groups_by_worker() {
        // 3 timestamps × 6 workers, one row per worker per ts on
        // ge-0-0-2 with count = worker_id+1, plus noise on ge-0-0-3
        // with very large counts that MUST NOT contaminate the
        // filtered distribution.
        let mut rows = Vec::new();
        for ts in 1000u64..1003 {
            for w in 0u32..6 {
                rows.push(row(ts, w, 0, w, "ge-0-0-2", w + 1));
                rows.push(row(ts, 100 + w, 0, w, "ge-0-0-3", 999));
            }
        }
        let r = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0).unwrap();
        assert!(r.iface_filter_active);
        assert_eq!(r.distribution_a_i, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn aggregate_per_worker_sums_multiple_queues_per_worker() {
        // Same worker has 2 queue bindings on the same iface — the
        // per-(ts,worker) accumulator must SUM those, not replace.
        let mut rows = Vec::new();
        for ts in 1000u64..1003 {
            // worker 0: q0 contributes 2, q1 contributes 3 → expect 5
            rows.push(row(ts, 0, 0, 0, "ge-0-0-2", 2));
            rows.push(row(ts, 1, 1, 0, "ge-0-0-2", 3));
            // workers 1..5: single queue, count=1
            for w in 1u32..6 {
                rows.push(row(ts, w + 1, 0, w, "ge-0-0-2", 1));
            }
        }
        let r = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0).unwrap();
        assert_eq!(r.distribution_a_i, vec![5, 1, 1, 1, 1, 1]);
    }

    #[test]
    fn aggregate_per_worker_legacy_3col_disables_filter() {
        // Legacy parser produces iface="" and worker_id == binding_slot.
        // Even with --iface set, iface_filter_active should be false
        // because no row carries a non-empty iface label.
        let rows: Vec<_> = (0u32..6)
            .flat_map(|w| (1000u64..1003).map(move |ts| row(ts, w, 0, w, "", 7)))
            .collect();
        let r = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0).unwrap();
        assert!(!r.iface_filter_active, "legacy 3-col must collapse filter");
        // Each worker still appears at its slot/wid index with count 7.
        assert_eq!(r.distribution_a_i, vec![7, 7, 7, 7, 7, 7]);
    }

    #[test]
    fn aggregate_per_worker_missing_workers_default_to_zero() {
        // Only workers 0, 2, 4 produce samples; workers 1, 3, 5 are
        // expected to report 0 in the output Vec at indices 1, 3, 5.
        let rows: Vec<_> = (1000u64..1003)
            .flat_map(|ts| {
                [0u32, 2, 4]
                    .iter()
                    .map(move |&w| row(ts, w, 0, w, "ge-0-0-2", 4))
            })
            .collect();
        let r = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0).unwrap();
        assert_eq!(r.distribution_a_i, vec![4, 0, 4, 0, 4, 0]);
    }

    #[test]
    fn aggregate_per_worker_median_smooths_jitter() {
        // worker 0 sees counts 1, 5, 5 over 3 ts → median 5.
        // worker 1 sees 5, 1, 1 → median 1. (Filters out single
        // outliers on either side.)
        let rows = vec![
            row(1000, 0, 0, 0, "ge-0-0-2", 1),
            row(1001, 0, 0, 0, "ge-0-0-2", 5),
            row(1002, 0, 0, 0, "ge-0-0-2", 5),
            row(1000, 1, 0, 1, "ge-0-0-2", 5),
            row(1001, 1, 0, 1, "ge-0-0-2", 1),
            row(1002, 1, 0, 1, "ge-0-0-2", 1),
        ];
        let r = aggregate_per_worker(&rows, "ge-0-0-2", 2, 0, 0).unwrap();
        assert_eq!(r.distribution_a_i, vec![5, 1]);
    }

    #[test]
    fn aggregate_per_worker_rejects_out_of_range_worker_id() {
        // A row with worker_id >= n_total_workers must produce Err, not
        // silently produce a zero entry. Silently ignoring would allow a
        // misconfigured --n-workers to yield a false PASS verdict.
        let rows = vec![
            row(1000, 0, 0, 0, "ge-0-0-2", 3),
            row(1000, 1, 0, 6, "ge-0-0-2", 5), // worker_id=6 out of range for n=6
        ];
        let result = aggregate_per_worker(&rows, "ge-0-0-2", 6, 0, 0);
        assert!(result.is_err(), "out-of-range worker_id should return Err");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("worker_id=6"),
            "error should mention the bad worker_id: {msg}"
        );
    }

    #[test]
    fn aggregate_cos_per_worker_filters_ifindex_and_queue() {
        let mut rows = Vec::new();
        for ts in 1000u64..1003 {
            rows.push(cos_row(ts, 80, 4, 0, 3));
            rows.push(cos_row(ts, 80, 4, 1, 5));
            rows.push(cos_row(ts, 80, 5, 0, 99));
            rows.push(cos_row(ts, 81, 4, 1, 99));
        }
        let r = aggregate_cos_per_worker(&rows, 80, 4, 3, 0, 0).unwrap();
        assert_eq!(r, vec![3, 5, 0]);
    }

    #[test]
    fn direction_multiplier_iface_filter_active_is_one() {
        assert_eq!(direction_multiplier(true), 1);
    }

    #[test]
    fn direction_multiplier_no_iface_filter_is_two() {
        assert_eq!(direction_multiplier(false), 2);
    }

    #[test]
    fn guard_sum_tolerances_are_asymmetric_for_stale_overcount() {
        assert_eq!(guard_sum_tolerances(12), (2, 3));
        assert_eq!(guard_sum_tolerances(2), (2, 2));
        assert_eq!(guard_sum_tolerances(40), (4, 10));
    }

    #[test]
    fn trim_distribution_to_sum_removes_accepted_overcount_from_largest_buckets() {
        assert_eq!(
            trim_distribution_to_sum(&[4, 4, 4, 3, 0, 0], 12),
            vec![3, 3, 3, 3, 0, 0]
        );
        assert_eq!(trim_distribution_to_sum(&[1, 2, 3], 3), vec![1, 1, 1]);
        assert_eq!(trim_distribution_to_sum(&[1, 2, 3], 10), vec![1, 2, 3]);
        assert_eq!(trim_distribution_to_sum(&[0, 0, 0], 0), vec![0, 0, 0]);
    }
}
