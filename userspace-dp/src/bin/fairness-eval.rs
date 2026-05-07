//! `fairness-eval` — consume iperf3 JSON + per-binding active flow count
//! samples, compute the contract gates from `docs/fairness-regimes.md`,
//! emit a verdict JSON. Used by `test/incus/fairness-harness.sh`.
//!
//! See `docs/pr/1219-fairness-harness/plan.md` for design.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

#[path = "../fairness.rs"]
mod fairness;

use fairness::{
    compute_cstruct, compute_observed_cov, is_saturated, starved_flow_count,
};

const EPSILON: f64 = 0.05;
// Tolerance for the harness fail-fast guard per Codex round-4
// finding #3: sum(per_binding_active_flow_count) ≈ non-starved
// iperf stream count within `max(2, 10% × N)`.
const GUARD_RELATIVE: f64 = 0.10;
const GUARD_ABSOLUTE: u32 = 2;

#[derive(Debug, Deserialize)]
struct Iperf3Output {
    start: Iperf3Start,
    intervals: Vec<Iperf3Interval>,
}

#[derive(Debug, Deserialize)]
struct Iperf3Start {
    #[serde(default)]
    connected: Vec<Iperf3Connected>,
    test_start: Iperf3TestStart,
}

#[derive(Debug, Deserialize)]
struct Iperf3Connected {
    socket: u64,
    #[allow(dead_code)] // diagnostic only; useful for future per-stream debugging
    #[serde(default)]
    local_port: u32,
}

#[derive(Debug, Deserialize)]
struct Iperf3TestStart {
    #[serde(default)]
    duration: u64,
    #[serde(default, rename = "num_streams")]
    num_streams: u32,
}

#[derive(Debug, Deserialize)]
struct Iperf3Interval {
    streams: Vec<Iperf3StreamInterval>,
}

#[derive(Debug, Deserialize)]
struct Iperf3StreamInterval {
    socket: u64,
    start: f64,
    end: f64,
    bits_per_second: f64,
}

#[derive(Debug, Default, Deserialize)]
struct BindingFlowsRow {
    /// Wall-clock-aligned 1s timestamp (seconds since epoch, integer).
    timestamp: u64,
    #[allow(dead_code)] // diagnostic only; kept for traceability
    binding_slot: u32,
    #[allow(dead_code)] // not used in aggregation; iface filter is the discriminator
    queue_id: u32,
    /// Owner worker id; the contract's `{a_i}` is keyed on this, not
    /// binding_slot (multiple bindings per worker, one per interface).
    worker_id: u32,
    /// Interface name; used to filter to a single direction.
    iface: String,
    count: u32,
}

#[derive(Debug, Serialize)]
struct Verdict {
    distribution_a_i: Vec<u32>,
    n_active: u32,
    n_total_workers: u32,
    cstruct: f64,
    observed_cov: f64,
    gap: f64,
    epsilon: f64,
    saturated: bool,
    aggregate_mbps: f64,
    starved_flow_count: u32,
    /// Harness fail-fast guard result: sum(a_i) vs non-starved iperf streams.
    a_i_sum_check_ok: bool,
    a_i_sum: u32,
    iperf_non_starved_streams: u32,
    a_i_sum_tolerance: u32,
    /// PASS unless any gate fails.
    verdict: &'static str,
    failure_reasons: Vec<String>,
}

/// Output of `aggregate_per_worker`. Codex round-5 finding #1: the
/// helper is factored out of `main()` so the per-worker aggregation
/// logic (filter, group-by, sum, median, defaulting) and the
/// iface_filter_active gate are unit-testable in isolation rather
/// than only via end-to-end integration.
#[cfg_attr(test, derive(Debug))]
struct AggregateResult {
    distribution_a_i: Vec<u32>,
    iface_filter_active: bool,
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
fn aggregate_per_worker(
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

/// Codex round-4 finding (#1): direction multiplier resolves to 1
/// when the iface filter is in effect (single-direction flow_cache)
/// and 2 otherwise (legacy bidirectional input). Factored out so
/// the same helper is tested directly by `aggregation_tests` below.
fn direction_multiplier(iface_filter_active: bool) -> u32 {
    if iface_filter_active { 1 } else { 2 }
}

fn main() -> ExitCode {
    let args: Args = parse_args();

    let iperf_json: String = read_to_string(&args.iperf_json);
    let iperf: Iperf3Output = match serde_json::from_str(&iperf_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("fairness-eval: parsing iperf3 JSON: {e}");
            return ExitCode::from(2);
        }
    };

    let binding_flows: Vec<BindingFlowsRow> = parse_binding_flows_tsv(&args.binding_flows);

    // Determine the steady-state window: skip first warmup_secs and
    // last final_burst_secs of iperf3 intervals.
    let total_dur = iperf.start.test_start.duration;
    if total_dur <= args.warmup_secs + args.final_burst_secs {
        eprintln!(
            "fairness-eval: test duration {total_dur}s ≤ warmup {} + final-burst {}",
            args.warmup_secs, args.final_burst_secs
        );
        return ExitCode::from(2);
    }
    let ss_dur = total_dur - args.warmup_secs - args.final_burst_secs;
    // The fairness contract requires a ≥60s steady-state window to
    // produce a statistically meaningful CoV measurement. Shorter
    // runs would give a verdict on too few per-second buckets.
    const MIN_STEADY_STATE_SECS: u64 = 60;
    if ss_dur < MIN_STEADY_STATE_SECS {
        eprintln!(
            "fairness-eval: steady-state window {ss_dur}s < {MIN_STEADY_STATE_SECS}s minimum; use a longer -t or reduce --warmup-secs/--final-burst-secs"
        );
        return ExitCode::from(2);
    }
    let ss_start = args.warmup_secs as f64;
    let ss_end = (total_dur - args.final_burst_secs) as f64;

    // Per-stream per-bucket throughput in bytes/sec. Seed the map from
    // `start.connected[]` so streams that contributed zero throughput
    // for the entire steady-state window are still represented (with
    // an empty bucket vec) and correctly counted as starved by
    // starved_flow_count. Without this seeding, streams that sent no
    // data after warmup are silently invisible — Codex round-1+round-2
    // finding #1.
    let mut per_stream_buckets: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for c in &iperf.start.connected {
        per_stream_buckets.entry(c.socket).or_default();
    }
    let mut aggregate_buckets_bps: Vec<u64> = Vec::new();

    for interval in &iperf.intervals {
        let mut iv_start = f64::INFINITY;
        let mut iv_end = f64::NEG_INFINITY;
        let mut iv_total_bps = 0.0_f64;
        for s in &interval.streams {
            iv_start = iv_start.min(s.start);
            iv_end = iv_end.max(s.end);
            iv_total_bps += s.bits_per_second;
        }
        let mid = (iv_start + iv_end) * 0.5;
        if mid < ss_start || mid >= ss_end {
            continue;
        }
        for s in &interval.streams {
            let bytes = (s.bits_per_second / 8.0) as u64;
            per_stream_buckets.entry(s.socket).or_default().push(bytes);
        }
        aggregate_buckets_bps.push(iv_total_bps as u64);
    }

    let n_total_workers = args.n_workers;

    // Per-stream window-mean throughput for the per-flow CoV input.
    let per_flow_throughputs: Vec<u64> = per_stream_buckets
        .values()
        .filter(|v| !v.is_empty())
        .map(|v| {
            let sum: u64 = v.iter().sum();
            sum / v.len() as u64
        })
        .collect();

    let observed_cov = compute_observed_cov(&per_flow_throughputs);

    let starved = starved_flow_count(
        &per_stream_buckets.values().cloned().collect::<Vec<_>>(),
    );

    // {a_i}: per-WORKER active flow count for the test's data-
    // direction interface. The TSV has 6 columns (timestamp,
    // binding_slot, queue_id, worker_id, iface, count); we filter to
    // --iface and aggregate by worker_id at each timestamp before
    // taking the median over the steady-state window.
    //
    // This addresses Codex round-3 + Gemini round-1 fatal: per-binding
    // counts spread across multiple interfaces (each TCP flow generates
    // entries on BOTH ingress AND egress bindings, plus one per queue)
    // produced a meaningless 18-element distribution. The contract's
    // {a_i} is per-worker on the bottleneck-direction interface; this
    // is what fairness-eval now computes.
    let agg = match aggregate_per_worker(
        &binding_flows,
        &args.iface,
        n_total_workers,
        args.warmup_secs,
        args.final_burst_secs,
    ) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("fairness-eval: {e}");
            return ExitCode::from(2);
        }
    };
    let iface_filter_active = agg.iface_filter_active;
    let distribution_a_i = agg.distribution_a_i;

    let cstruct = compute_cstruct(&distribution_a_i);
    let n_active: u32 = distribution_a_i.iter().filter(|&&a| a > 0).count() as u32;

    let gap = observed_cov - cstruct;

    let aggregate_mbps =
        if aggregate_buckets_bps.is_empty() {
            0.0
        } else {
            (aggregate_buckets_bps.iter().sum::<u64>() as f64
                / aggregate_buckets_bps.len() as f64)
                / 1_000_000.0
        };

    // Saturation: structural cap = (n_active / n_total_workers) × shaper_rate.
    // shaper_rate provided via --shaper-rate-bps; if zero, skip the saturated check.
    let saturated = if args.shaper_rate_bps > 0 && n_total_workers > 0 {
        let structural_cap_bps = (args.shaper_rate_bps as u128
            * n_active as u128
            / n_total_workers as u128) as u64;
        is_saturated(&aggregate_buckets_bps, structural_cap_bps)
    } else {
        false
    };

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
    let a_i_sum: u32 = distribution_a_i.iter().sum();
    // Stream count: prefer start.connected[].len() (concrete stream
    // sockets observed at iperf3 setup time) over test_start.num_streams
    // (a self-reported integer). The seeded map sees every connected
    // socket; any not present in steady-state intervals are starved
    // candidates. Codex round-2 finding: don't trust interval presence
    // alone — derive expected count from connected[].
    let n_iperf_streams = if iperf.start.connected.is_empty() {
        iperf.start.test_start.num_streams
    } else {
        iperf.start.connected.len() as u32
    };
    let n_non_starved = n_iperf_streams.saturating_sub(starved);
    // iface filter active => single-direction flow_cache, ~1×; otherwise
    // ~2× for bidirectional (both ingress and egress) entries. Use
    // iface_filter_active (not raw args.iface) so the legacy-input
    // fallback path uses the bidirectional multiplier as well.
    let dir_mult = direction_multiplier(iface_filter_active);
    let expected_sum = n_non_starved.saturating_mul(dir_mult);
    let tolerance = ((GUARD_RELATIVE * expected_sum as f64) as u32).max(GUARD_ABSOLUTE);
    let a_i_sum_check_ok =
        (a_i_sum as i64 - expected_sum as i64).unsigned_abs() as u32 <= tolerance;

    let mut failure_reasons: Vec<String> = Vec::new();
    if starved > 0 {
        failure_reasons.push(format!(
            "Gate 1 (starved flows): {starved} flow(s) below 1% of mean per-flow throughput for the entire steady-state window"
        ));
    }
    if gap > EPSILON {
        failure_reasons.push(format!(
            "Gate 2 (per-flow CoV): observed_cov - cstruct = {gap:.4} > epsilon {EPSILON}"
        ));
    }
    if !a_i_sum_check_ok {
        failure_reasons.push(format!(
            "Harness guard: sum(a_i)={a_i_sum} vs iperf non-starved streams={n_non_starved} differ by more than tolerance={tolerance}"
        ));
    }

    let verdict = if failure_reasons.is_empty() {
        "PASS"
    } else {
        "FAIL"
    };

    let v = Verdict {
        distribution_a_i,
        n_active,
        n_total_workers,
        cstruct,
        observed_cov,
        gap,
        epsilon: EPSILON,
        saturated,
        aggregate_mbps,
        starved_flow_count: starved,
        a_i_sum_check_ok,
        a_i_sum,
        iperf_non_starved_streams: n_non_starved,
        a_i_sum_tolerance: tolerance,
        verdict,
        failure_reasons,
    };

    println!("{}", serde_json::to_string_pretty(&v).unwrap());

    if v.verdict == "PASS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

struct Args {
    iperf_json: PathBuf,
    binding_flows: PathBuf,
    /// Filter binding-flows rows to this interface name. Empty string =
    /// no filter (sum across all interfaces — only correct if your
    /// topology has just one). Defaults blank; harness script sets it.
    iface: String,
    warmup_secs: u64,
    final_burst_secs: u64,
    n_workers: u32,
    shaper_rate_bps: u64,
}

fn parse_args() -> Args {
    let mut iperf_json: Option<PathBuf> = None;
    let mut binding_flows: Option<PathBuf> = None;
    let mut iface: String = String::new();
    let mut warmup_secs: u64 = 5;
    let mut final_burst_secs: u64 = 1;
    let mut n_workers: u32 = 6;
    let mut shaper_rate_bps: u64 = 0;
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iperf-json" => {
                iperf_json = args.next().map(PathBuf::from);
            }
            "--binding-flows" => {
                binding_flows = args.next().map(PathBuf::from);
            }
            "--iface" => {
                iface = args.next().unwrap_or_default();
            }
            "--warmup-secs" => {
                warmup_secs = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);
            }
            "--final-burst-secs" => {
                final_burst_secs = args.next().and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            "--n-workers" => {
                n_workers = args.next().and_then(|s| s.parse().ok()).unwrap_or(6);
            }
            "--shaper-rate-bps" => {
                shaper_rate_bps = args.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: fairness-eval --iperf-json PATH --binding-flows PATH \\\n  [--iface NAME] [--warmup-secs N] [--final-burst-secs N] \\\n  [--n-workers N] [--shaper-rate-bps N]\n\n--iface NAME: filter binding-flows rows to this interface (recommended; without it, sums across all interfaces)."
                );
                std::process::exit(0);
            }
            _ => {
                eprintln!("fairness-eval: unknown arg {arg}; try --help");
                std::process::exit(2);
            }
        }
    }
    let iperf_json = match iperf_json {
        Some(p) => p,
        None => {
            eprintln!("fairness-eval: --iperf-json is required");
            std::process::exit(2);
        }
    };
    let binding_flows = match binding_flows {
        Some(p) => p,
        None => {
            eprintln!("fairness-eval: --binding-flows is required");
            std::process::exit(2);
        }
    };
    Args {
        iperf_json,
        binding_flows,
        iface,
        warmup_secs,
        final_burst_secs,
        n_workers,
        shaper_rate_bps,
    }
}

fn read_to_string(path: &PathBuf) -> String {
    let mut f = fs::File::open(path).unwrap_or_else(|e| {
        eprintln!("fairness-eval: open {}: {e}", path.display());
        std::process::exit(2);
    });
    let mut buf = String::new();
    f.read_to_string(&mut buf).unwrap_or_else(|e| {
        eprintln!("fairness-eval: read {}: {e}", path.display());
        std::process::exit(2);
    });
    buf
}

fn parse_binding_flows_tsv(path: &PathBuf) -> Vec<BindingFlowsRow> {
    // Format: timestamp\tbinding_slot\tqueue_id\tworker_id\tiface\tcount.
    // Skip header / comment lines starting with '#'. For backward
    // compatibility with the legacy 3-column format (older harness
    // versions), if only 3 columns are present, the iface filter is
    // treated as no-filter and worker_id defaults to binding_slot.
    let s = read_to_string(path);
    let mut rows: Vec<BindingFlowsRow> = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 6 {
            let ts: u64 = match parts[0].parse() { Ok(v) => v, Err(_) => continue };
            let slot: u32 = match parts[1].parse() { Ok(v) => v, Err(_) => continue };
            let qid: u32 = match parts[2].parse() { Ok(v) => v, Err(_) => continue };
            let wid: u32 = match parts[3].parse() { Ok(v) => v, Err(_) => continue };
            let iface = parts[4].to_string();
            let count: u32 = match parts[5].parse() { Ok(v) => v, Err(_) => continue };
            rows.push(BindingFlowsRow {
                timestamp: ts, binding_slot: slot, queue_id: qid,
                worker_id: wid, iface, count,
            });
        } else if parts.len() == 3 {
            // Legacy 3-column format: timestamp, binding_slot, count.
            // Pretend slot==worker_id and iface=="" so it still works
            // (caller responsible for ensuring single-iface workload).
            let ts: u64 = match parts[0].parse() { Ok(v) => v, Err(_) => continue };
            let slot: u32 = match parts[1].parse() { Ok(v) => v, Err(_) => continue };
            let count: u32 = match parts[2].parse() { Ok(v) => v, Err(_) => continue };
            rows.push(BindingFlowsRow {
                timestamp: ts, binding_slot: slot, queue_id: 0,
                worker_id: slot, iface: String::new(), count,
            });
        }
        // Other formats: silently skipped.
    }
    rows
}

#[cfg(test)]
mod aggregation_tests {
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
            .flat_map(|w| {
                (1000u64..1003).map(move |ts| row(ts, w, 0, w, "", 7))
            })
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
        assert!(
            result.is_err(),
            "out-of-range worker_id should return Err"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("worker_id=6"),
            "error should mention the bad worker_id: {msg}"
        );
    }

    #[test]
    fn direction_multiplier_iface_filter_active_is_one() {
        assert_eq!(direction_multiplier(true), 1);
    }

    #[test]
    fn direction_multiplier_no_iface_filter_is_two() {
        assert_eq!(direction_multiplier(false), 2);
    }
}

#[cfg(test)]
mod tsv_tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(content: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "fairness-eval-test-{}-{}.tsv",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    #[test]
    fn six_col_multi_iface_per_worker_aggregation() {
        // 2 timestamps × 3 ifaces × 6 workers, with worker counts
        // {2,2,2,2,2,2} on iface ge-0-0-2 and noise on the other
        // ifaces. Filtered to ge-0-0-2 we expect distribution_a_i =
        // [2,2,2,2,2,2] regardless of the noise.
        let mut content = String::new();
        content.push_str("# timestamp\tbinding_slot\tqueue_id\tworker_id\tiface\tcount\n");
        for ts in [1000u64, 1001u64] {
            for w in 0u32..6 {
                content.push_str(&format!(
                    "{ts}\t{w}\t{w}\t{w}\tge-0-0-2\t2\n"
                ));
                // Noise on a different iface — must NOT contribute
                // when --iface=ge-0-0-2 is set.
                content.push_str(&format!(
                    "{ts}\t{slot}\t{w}\t{w}\tge-0-0-3\t99\n",
                    slot = 6 + w
                ));
            }
        }
        let p = write_tmp(&content);
        let rows = parse_binding_flows_tsv(&p);
        let _ = fs::remove_file(&p);
        assert_eq!(rows.len(), 24, "expected 2 ts × 6 workers × 2 ifaces rows");
        // Apply the same filter the binary does and verify the
        // per-worker aggregation collapses to [2,2,2,2,2,2].
        let iface = "ge-0-0-2";
        let mut sum_per_worker = [0u32; 6];
        for r in &rows {
            if r.iface == iface {
                sum_per_worker[r.worker_id as usize] += r.count;
            }
        }
        // 2 timestamps × 2 (entries per worker per ts) → 4
        // entries summed; with count=2 each, per-worker sum = 4.
        // Median across the 2 timestamps would still be 2 (the
        // sample value at each ts). The integration of the
        // sum-then-median path lives in the verdict code; here we
        // just confirm the parser + filter shape.
        for v in &sum_per_worker {
            assert!(*v > 0, "per-worker sum should be non-zero on filtered iface");
        }
    }

    #[test]
    fn three_col_legacy_parses_with_empty_iface() {
        let content = "# timestamp\tbinding_slot\tcount\n1000\t0\t5\n1000\t1\t5\n";
        let p = write_tmp(content);
        let rows = parse_binding_flows_tsv(&p);
        let _ = fs::remove_file(&p);
        assert_eq!(rows.len(), 2);
        for r in &rows {
            assert_eq!(r.iface, "", "legacy 3-col should produce empty iface label");
            assert_eq!(r.worker_id, r.binding_slot, "legacy 3-col: worker_id == slot");
        }
    }
}
