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
// finding #3: sum(per_binding_active_flow_count) should stay near
// expected_sum, where
// expected_sum = non-starved_streams × direction_multiplier
// (direction_multiplier=1 when iface_filter_active=true, 2 for
// legacy/bidirectional input).
//
// #1281: active-flow gauges are low-frequency snapshots and can retain
// recently-active/stale flows for a short window. Preserve the stricter
// undercount guard because missing telemetry masks real flow loss, but
// allow a bounded one-sided overcount window for stale entries.
const GUARD_RELATIVE: f64 = 0.10;
const GUARD_OVERCOUNT_DIVISOR: u32 = 4;
const GUARD_ABSOLUTE: u32 = 2;

#[derive(Debug, Deserialize)]
struct Iperf3Output {
    start: Iperf3Start,
    intervals: Vec<Iperf3Interval>,
    #[serde(default)]
    end: Option<Iperf3End>,
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
    #[serde(default)]
    reverse: u8,
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
struct Iperf3End {
    #[serde(default)]
    sum_sent: Iperf3EndSum,
    #[serde(default)]
    cpu_utilization_percent: Option<Iperf3CpuUtilization>,
}

#[derive(Debug, Default, Deserialize)]
struct Iperf3EndSum {
    #[serde(default)]
    retransmits: u64,
}

#[derive(Debug, Default, Deserialize)]
struct Iperf3CpuUtilization {
    #[serde(default)]
    host_total: f64,
    #[serde(default)]
    host_user: f64,
    #[serde(default)]
    host_system: f64,
    #[serde(default)]
    remote_total: f64,
    #[serde(default)]
    remote_user: f64,
    #[serde(default)]
    remote_system: f64,
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

#[derive(Debug, Default, Deserialize)]
struct CosFlowsRow {
    timestamp: u64,
    ifindex: i32,
    queue_id: u32,
    worker_id: u32,
    count: u32,
}

#[derive(Clone, Debug, PartialEq)]
enum RssExpectation {
    Any,
    Balanced,
    AtLeastActiveWorkers(u32),
    MaxWorkerFlowShare(f64),
    CstructMax(f64),
}

#[derive(Debug, Serialize)]
struct Verdict {
    cstruct_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cos_ifindex: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cos_queue_id: Option<u32>,
    distribution_a_i: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_distribution_a_i: Option<Vec<u32>>,
    rss_expectation: String,
    rss_expectation_pass: bool,
    rss_expectation_reason: String,
    max_worker_flow_share: f64,
    n_active: u32,
    n_total_workers: u32,
    cstruct: f64,
    observed_cov: f64,
    gap: f64,
    epsilon: f64,
    saturated: bool,
    aggregate_mbps: f64,
    iperf_retransmits: u64,
    iperf_reverse: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf_cpu_host_total_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf_cpu_host_user_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf_cpu_host_system_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf_cpu_remote_total_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf_cpu_remote_user_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf_cpu_remote_system_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf_sender_cpu_total_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf_sender_cpu_user_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iperf_sender_cpu_system_percent: Option<f64>,
    starved_flow_count: u32,
    /// Harness fail-fast guard result: sum(a_i) vs non-starved iperf streams.
    a_i_sum_check_ok: bool,
    a_i_sum: u32,
    iperf_non_starved_streams: u32,
    a_i_sum_under_tolerance: u32,
    a_i_sum_over_tolerance: u32,
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

fn aggregate_cos_per_worker(
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

fn parse_rss_expectation(raw: &str) -> Result<RssExpectation, String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("any") {
        return Ok(RssExpectation::Any);
    }
    if raw.eq_ignore_ascii_case("balanced") {
        return Ok(RssExpectation::Balanced);
    }

    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let normalized = compact
        .replace("<=", ":")
        .replace(">=", ":")
        .replace('=', ":");
    let mut parts = normalized.splitn(2, ':');
    let key = parts.next().unwrap_or_default();
    let value = parts.next().unwrap_or_default();
    match key {
        "at-least-active-workers" | "active-workers" => {
            let n = value.parse::<u32>().map_err(|_| {
                format!("invalid --rss-expectation active worker count: {raw}")
            })?;
            Ok(RssExpectation::AtLeastActiveWorkers(n))
        }
        "max-worker-flow-share" => {
            let share = parse_fraction_or_percent(value).map_err(|e| {
                format!("invalid --rss-expectation max-worker-flow-share: {e}")
            })?;
            Ok(RssExpectation::MaxWorkerFlowShare(share))
        }
        "cstruct-max" | "cstruct" => {
            let max = parse_nonnegative_number_or_percent(value).map_err(|e| {
                format!("invalid --rss-expectation cstruct threshold: {e}")
            })?;
            Ok(RssExpectation::CstructMax(max))
        }
        _ => Err(format!(
            "unknown --rss-expectation {raw}; expected any, balanced, \
             at-least-active-workers:N, max-worker-flow-share:X, or cstruct-max:X"
        )),
    }
}

fn parse_number_or_percent(raw: &str) -> Result<f64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("missing value".to_string());
    }
    let value = if let Some(percent) = raw.strip_suffix('%') {
        percent
            .parse::<f64>()
            .map_err(|_| format!("{raw} is not a number"))?
            / 100.0
    } else {
        raw.parse::<f64>()
            .map_err(|_| format!("{raw} is not a number"))?
    };
    if !value.is_finite() {
        return Err(format!("{raw} is not a finite number"));
    }
    Ok(value)
}

fn parse_fraction_or_percent(raw: &str) -> Result<f64, String> {
    let value = parse_number_or_percent(raw)?;
    if !(0.0..=1.0).contains(&value) {
        return Err(format!("{raw} must be between 0 and 1 or 0% and 100%"));
    }
    Ok(value)
}

fn parse_nonnegative_number_or_percent(raw: &str) -> Result<f64, String> {
    let value = parse_number_or_percent(raw)?;
    if value < 0.0 {
        return Err(format!("{raw} must be non-negative"));
    }
    Ok(value)
}

fn max_worker_flow_share(distribution_a_i: &[u32]) -> f64 {
    let total: u32 = distribution_a_i.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let max = distribution_a_i.iter().copied().max().unwrap_or(0);
    max as f64 / total as f64
}

fn evaluate_rss_expectation(
    expectation: &RssExpectation,
    distribution_a_i: &[u32],
    cstruct: f64,
    n_total_workers: u32,
) -> (bool, String) {
    let total: u32 = distribution_a_i.iter().sum();
    let active_workers = distribution_a_i.iter().filter(|&&a| a > 0).count() as u32;
    let max_share = max_worker_flow_share(distribution_a_i);
    match expectation {
        RssExpectation::Any => (true, "any: no RSS/workload expectation configured".to_string()),
        RssExpectation::AtLeastActiveWorkers(min) => {
            if active_workers >= *min {
                (
                    true,
                    format!("active_workers={active_workers} >= expected {min}"),
                )
            } else {
                (
                    false,
                    format!("active_workers={active_workers} < expected {min}"),
                )
            }
        }
        RssExpectation::MaxWorkerFlowShare(max_allowed) => {
            if max_share <= *max_allowed {
                (
                    true,
                    format!("max_worker_flow_share={max_share:.4} <= expected {max_allowed:.4}"),
                )
            } else {
                (
                    false,
                    format!("max_worker_flow_share={max_share:.4} > expected {max_allowed:.4}"),
                )
            }
        }
        RssExpectation::CstructMax(max_allowed) => {
            if cstruct <= *max_allowed {
                (
                    true,
                    format!("cstruct={cstruct:.4} <= expected {max_allowed:.4}"),
                )
            } else {
                (
                    false,
                    format!("cstruct={cstruct:.4} > expected {max_allowed:.4}"),
                )
            }
        }
        RssExpectation::Balanced => {
            if total == 0 {
                return (false, "balanced: no active flows observed".to_string());
            }
            let expected_active = n_total_workers.min(total);
            let active_counts: Vec<u32> = distribution_a_i
                .iter()
                .copied()
                .filter(|&a| a > 0)
                .collect();
            let min = active_counts.iter().copied().min().unwrap_or(0);
            let max = active_counts.iter().copied().max().unwrap_or(0);
            let pass = active_workers == expected_active && max.saturating_sub(min) <= 1;
            if pass {
                (
                    true,
                    format!(
                        "balanced: active_workers={active_workers}, min={min}, max={max}"
                    ),
                )
            } else {
                (
                    false,
                    format!(
                        "balanced: active_workers={active_workers} expected {expected_active}, min={min}, max={max}"
                    ),
                )
            }
        }
    }
}

/// Codex round-4 finding (#1): direction multiplier resolves to 1
/// when the iface filter is in effect (single-direction flow_cache)
/// and 2 otherwise (legacy bidirectional input). Factored out so
/// the same helper is tested directly by `aggregation_tests` below.
fn direction_multiplier(iface_filter_active: bool) -> u32 {
    if iface_filter_active { 1 } else { 2 }
}

fn guard_sum_tolerances(expected_sum: u32) -> (u32, u32) {
    let under = ((GUARD_RELATIVE * expected_sum as f64) as u32).max(GUARD_ABSOLUTE);
    let over = expected_sum
        .saturating_add(GUARD_OVERCOUNT_DIVISOR - 1)
        / GUARD_OVERCOUNT_DIVISOR;
    (under, over.max(GUARD_ABSOLUTE))
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
    let cos_flows = args.cos_flows.as_ref().map(parse_cos_flows_tsv);

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
    let binding_distribution_a_i = agg.distribution_a_i;
    let mut iface_filter_active = agg.iface_filter_active;
    let mut distribution_a_i = binding_distribution_a_i.clone();
    let mut cstruct_source = "binding";
    let mut selected_cos_ifindex = None;
    let mut selected_cos_queue_id = None;

    if let Some(cos_flows) = &cos_flows {
        let cos_ifindex = match args.cos_ifindex {
            Some(v) => v,
            None => {
                eprintln!("fairness-eval: --cos-flows requires --cos-ifindex");
                return ExitCode::from(2);
            }
        };
        let cos_queue_id = match args.cos_queue_id {
            Some(v) => v,
            None => {
                eprintln!("fairness-eval: --cos-flows requires --cos-queue-id");
                return ExitCode::from(2);
            }
        };
        distribution_a_i = match aggregate_cos_per_worker(
            cos_flows,
            cos_ifindex,
            cos_queue_id,
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
        iface_filter_active = true;
        cstruct_source = "cos_queue";
        selected_cos_ifindex = Some(cos_ifindex);
        selected_cos_queue_id = Some(cos_queue_id);
    }

    let cstruct = compute_cstruct(&distribution_a_i);
    let n_active: u32 = distribution_a_i.iter().filter(|&&a| a > 0).count() as u32;
    let rss_expectation = match parse_rss_expectation(&args.rss_expectation) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("fairness-eval: {e}");
            return ExitCode::from(2);
        }
    };
    let max_worker_flow_share = max_worker_flow_share(&distribution_a_i);
    let (rss_expectation_pass, rss_expectation_reason) = evaluate_rss_expectation(
        &rss_expectation,
        &distribution_a_i,
        cstruct,
        n_total_workers,
    );

    let gap = observed_cov - cstruct;

    let aggregate_mbps =
        if aggregate_buckets_bps.is_empty() {
            0.0
        } else {
            (aggregate_buckets_bps.iter().sum::<u64>() as f64
                / aggregate_buckets_bps.len() as f64)
                / 1_000_000.0
        };
    let iperf_retransmits = iperf
        .end
        .as_ref()
        .map(|end| end.sum_sent.retransmits)
        .unwrap_or(0);
    let iperf_reverse = iperf.start.test_start.reverse != 0;
    let iperf_cpu = iperf
        .end
        .as_ref()
        .and_then(|end| end.cpu_utilization_percent.as_ref());
    let (
        iperf_cpu_host_total_percent,
        iperf_cpu_host_user_percent,
        iperf_cpu_host_system_percent,
        iperf_cpu_remote_total_percent,
        iperf_cpu_remote_user_percent,
        iperf_cpu_remote_system_percent,
        iperf_sender_cpu_total_percent,
        iperf_sender_cpu_user_percent,
        iperf_sender_cpu_system_percent,
    ) = if let Some(cpu) = iperf_cpu {
        let sender_total = if iperf_reverse {
            cpu.remote_total
        } else {
            cpu.host_total
        };
        let sender_user = if iperf_reverse {
            cpu.remote_user
        } else {
            cpu.host_user
        };
        let sender_system = if iperf_reverse {
            cpu.remote_system
        } else {
            cpu.host_system
        };
        (
            Some(cpu.host_total),
            Some(cpu.host_user),
            Some(cpu.host_system),
            Some(cpu.remote_total),
            Some(cpu.remote_user),
            Some(cpu.remote_system),
            Some(sender_total),
            Some(sender_user),
            Some(sender_system),
        )
    } else {
        (None, None, None, None, None, None, None, None, None)
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
    let binding_a_i_sum: u32 = binding_distribution_a_i.iter().sum();
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
    let (under_tolerance, over_tolerance) = guard_sum_tolerances(expected_sum);
    let a_i_delta = a_i_sum as i64 - expected_sum as i64;
    let a_i_abs_delta = a_i_delta.unsigned_abs() as u32;
    let tolerance = if a_i_delta > 0 {
        over_tolerance
    } else {
        under_tolerance
    };
    let a_i_sum_check_ok = a_i_abs_delta <= tolerance;

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
        let direction = if a_i_delta > 0 { "above" } else { "below" };
        failure_reasons.push(format!(
            "Harness guard: sum(a_i)={a_i_sum} vs expected={expected_sum} \
             (non-starved={n_non_starved} × dir_mult={dir_mult}) \
             is {a_i_abs_delta} {direction} expected, exceeding tolerance={tolerance} \
             (under_tolerance={under_tolerance}, over_tolerance={over_tolerance})"
        ));
    }
    if !rss_expectation_pass {
        failure_reasons.push(format!(
            "RSS expectation: {rss_expectation_reason}"
        ));
    }
    if cstruct_source == "cos_queue" && binding_a_i_sum + tolerance < a_i_sum {
        failure_reasons.push(format!(
            "Harness guard: selected CoS sum(a_i)={a_i_sum} exceeds binding sum(a_i)={binding_a_i_sum} by more than tolerance={tolerance}; check --iface/--cos-ifindex/--cos-queue-id"
        ));
    }

    let verdict = if failure_reasons.is_empty() {
        "PASS"
    } else {
        "FAIL"
    };

    let v = Verdict {
        cstruct_source,
        cos_ifindex: selected_cos_ifindex,
        cos_queue_id: selected_cos_queue_id,
        distribution_a_i,
        binding_distribution_a_i: (cstruct_source == "cos_queue")
            .then_some(binding_distribution_a_i),
        rss_expectation: args.rss_expectation,
        rss_expectation_pass,
        rss_expectation_reason,
        max_worker_flow_share,
        n_active,
        n_total_workers,
        cstruct,
        observed_cov,
        gap,
        epsilon: EPSILON,
        saturated,
        aggregate_mbps,
        iperf_retransmits,
        iperf_reverse,
        iperf_cpu_host_total_percent,
        iperf_cpu_host_user_percent,
        iperf_cpu_host_system_percent,
        iperf_cpu_remote_total_percent,
        iperf_cpu_remote_user_percent,
        iperf_cpu_remote_system_percent,
        iperf_sender_cpu_total_percent,
        iperf_sender_cpu_user_percent,
        iperf_sender_cpu_system_percent,
        starved_flow_count: starved,
        a_i_sum_check_ok,
        a_i_sum,
        iperf_non_starved_streams: n_non_starved,
        a_i_sum_under_tolerance: under_tolerance,
        a_i_sum_over_tolerance: over_tolerance,
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
    cos_flows: Option<PathBuf>,
    cos_ifindex: Option<i32>,
    cos_queue_id: Option<u32>,
    /// Filter binding-flows rows to this interface name. Empty string =
    /// no filter (sum across all interfaces — only correct if your
    /// topology has just one). Defaults blank; harness script sets it.
    iface: String,
    warmup_secs: u64,
    final_burst_secs: u64,
    n_workers: u32,
    shaper_rate_bps: u64,
    rss_expectation: String,
}

fn parse_args() -> Args {
    let mut iperf_json: Option<PathBuf> = None;
    let mut binding_flows: Option<PathBuf> = None;
    let mut cos_flows: Option<PathBuf> = None;
    let mut cos_ifindex: Option<i32> = None;
    let mut cos_queue_id: Option<u32> = None;
    let mut iface: String = String::new();
    let mut warmup_secs: u64 = 5;
    let mut final_burst_secs: u64 = 1;
    let mut n_workers: u32 = 6;
    let mut shaper_rate_bps: u64 = 0;
    let mut rss_expectation: String = "any".to_string();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iperf-json" => {
                iperf_json = args.next().map(PathBuf::from);
            }
            "--binding-flows" => {
                binding_flows = args.next().map(PathBuf::from);
            }
            "--cos-flows" => {
                cos_flows = Some(PathBuf::from(parse_required_string_arg(
                    "--cos-flows",
                    args.next(),
                )));
            }
            "--cos-ifindex" => {
                cos_ifindex = Some(parse_required_numeric_arg("--cos-ifindex", args.next()));
            }
            "--cos-queue-id" => {
                cos_queue_id = Some(parse_required_numeric_arg("--cos-queue-id", args.next()));
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
            "--rss-expectation" => {
                rss_expectation = parse_required_string_arg("--rss-expectation", args.next());
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: fairness-eval --iperf-json PATH --binding-flows PATH \\\n  [--cos-flows PATH --cos-ifindex N --cos-queue-id N] \\\n  [--iface NAME] [--warmup-secs N] [--final-burst-secs N] \\\n  [--n-workers N] [--shaper-rate-bps N] [--rss-expectation EXPR]\n\n--iface NAME: filter binding-flows rows to this interface (recommended for legacy per-binding mode).\n--cos-flows: class-specific CoS active-flow TSV; when present, Cstruct uses the selected CoS queue.\n--rss-expectation: any, balanced, at-least-active-workers:N, max-worker-flow-share:X, or cstruct-max:X."
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
        cos_flows,
        cos_ifindex,
        cos_queue_id,
        iface,
        warmup_secs,
        final_burst_secs,
        n_workers,
        shaper_rate_bps,
        rss_expectation,
    }
}

fn parse_required_numeric_arg<T>(flag: &str, raw: Option<String>) -> T
where
    T: std::str::FromStr,
{
    match parse_required_numeric_value(flag, raw) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("fairness-eval: {err}");
            std::process::exit(2);
        }
    }
}

fn parse_required_string_arg(flag: &str, raw: Option<String>) -> String {
    match parse_required_string_value(flag, raw) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("fairness-eval: {err}");
            std::process::exit(2);
        }
    }
}

fn parse_required_string_value(flag: &str, raw: Option<String>) -> Result<String, String> {
    let value = raw.ok_or_else(|| format!("{flag} requires a value"))?;
    if value.starts_with("--") {
        return Err(format!("{flag} requires a value, got {value:?}"));
    }
    Ok(value)
}

fn parse_required_numeric_value<T>(flag: &str, raw: Option<String>) -> Result<T, String>
where
    T: std::str::FromStr,
{
    let value = raw.ok_or_else(|| format!("{flag} requires a value"))?;
    value
        .parse::<T>()
        .map_err(|_| format!("{flag} must be numeric, got {value:?}"))
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

fn parse_cos_flows_tsv(path: &PathBuf) -> Vec<CosFlowsRow> {
    // Format: timestamp\tifindex\tqueue_id\tworker_id\tcount.
    // Source metric: xpf_userspace_cos_active_flow_count.
    let s = read_to_string(path);
    let mut rows: Vec<CosFlowsRow> = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 5 {
            continue;
        }
        let ts: u64 = match parts[0].parse() { Ok(v) => v, Err(_) => continue };
        let ifindex: i32 = match parts[1].parse() { Ok(v) => v, Err(_) => continue };
        let qid: u32 = match parts[2].parse() { Ok(v) => v, Err(_) => continue };
        let wid: u32 = match parts[3].parse() { Ok(v) => v, Err(_) => continue };
        let count: u32 = match parts[4].parse() { Ok(v) => v, Err(_) => continue };
        rows.push(CosFlowsRow {
            timestamp: ts,
            ifindex,
            queue_id: qid,
            worker_id: wid,
            count,
        });
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
    fn rss_expectation_balanced_accepts_even_integer_distribution() {
        let expectation = parse_rss_expectation("balanced").unwrap();
        let (pass, reason) =
            evaluate_rss_expectation(&expectation, &[2, 2, 2, 2, 2, 2], 0.0, 6);
        assert!(pass, "expected balanced pass: {reason}");
    }

    #[test]
    fn rss_expectation_balanced_rejects_skewed_distribution() {
        let expectation = parse_rss_expectation("balanced").unwrap();
        let (pass, reason) =
            evaluate_rss_expectation(&expectation, &[9, 1, 1, 1, 0, 0], 0.0, 6);
        assert!(!pass, "expected balanced failure");
        assert!(reason.contains("active_workers=4"), "reason: {reason}");
    }

    #[test]
    fn rss_expectation_max_share_accepts_percent_syntax() {
        let expectation = parse_rss_expectation("max-worker-flow-share:50%").unwrap();
        assert_eq!(expectation, RssExpectation::MaxWorkerFlowShare(0.5));
        let (pass, _reason) = evaluate_rss_expectation(&expectation, &[2, 2, 1, 1], 0.0, 4);
        assert!(pass);
    }

    #[test]
    fn rss_expectation_cstruct_max_rejects_high_structural_ceiling() {
        let expectation = parse_rss_expectation("cstruct<=25%").unwrap();
        let cstruct = compute_cstruct(&[9, 1, 1, 1]);
        assert!(cstruct > 1.0, "fixture must exercise CoV > 1.0");
        let (pass, reason) = evaluate_rss_expectation(&expectation, &[9, 1, 1, 1], cstruct, 4);
        assert!(!pass);
        assert!(reason.contains("cstruct=1."), "reason: {reason}");
    }

    #[test]
    fn rss_expectation_cstruct_max_accepts_whitespace_around_operator() {
        let expectation = parse_rss_expectation("cstruct <= 25%").unwrap();
        assert_eq!(expectation, RssExpectation::CstructMax(0.25));
    }

    #[test]
    fn rss_expectation_cstruct_max_accepts_values_above_one() {
        let expectation = parse_rss_expectation("cstruct-max:150%").unwrap();
        assert_eq!(expectation, RssExpectation::CstructMax(1.5));

        let expectation = parse_rss_expectation("cstruct<=1.2").unwrap();
        assert_eq!(expectation, RssExpectation::CstructMax(1.2));
    }

    #[test]
    fn rss_expectation_cstruct_max_rejects_negative_values() {
        let err = parse_rss_expectation("cstruct-max:-0.1").unwrap_err();
        assert!(err.contains("non-negative"), "err: {err}");
    }

    #[test]
    fn parse_cos_numeric_flags_reports_bad_values() {
        let parsed: i32 = parse_required_numeric_value("--cos-ifindex", Some("12".to_string()))
            .expect("valid ifindex");
        assert_eq!(parsed, 12);

        let err =
            parse_required_numeric_value::<u32>("--cos-queue-id", Some("bad".to_string()))
                .unwrap_err();
        assert!(
            err.contains("--cos-queue-id") && err.contains("bad"),
            "err: {err}"
        );

        let err = parse_required_numeric_value::<i32>("--cos-ifindex", None).unwrap_err();
        assert!(err.contains("requires a value"), "err: {err}");
    }

    #[test]
    fn parse_required_string_flags_report_missing_values() {
        let err = parse_required_string_value("--rss-expectation", None).unwrap_err();
        assert!(err.contains("requires a value"), "err: {err}");

        let err =
            parse_required_string_value("--cos-flows", Some("--cos-ifindex".to_string()))
                .unwrap_err();
        assert!(err.contains("--cos-flows"), "err: {err}");
    }

    #[test]
    fn rss_expectation_at_least_active_workers_rejects_too_few_workers() {
        let expectation = parse_rss_expectation("at-least-active-workers:5").unwrap();
        let (pass, reason) = evaluate_rss_expectation(&expectation, &[4, 4, 0, 0, 0, 0], 0.0, 6);
        assert!(!pass);
        assert!(reason.contains("active_workers=2"), "reason: {reason}");
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

    #[test]
    fn five_col_cos_flow_tsv_parses() {
        let content = "# timestamp\tifindex\tqueue_id\tworker_id\tcount\n1000\t80\t4\t1\t7\n";
        let p = write_tmp(content);
        let rows = parse_cos_flows_tsv(&p);
        let _ = fs::remove_file(&p);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timestamp, 1000);
        assert_eq!(rows[0].ifindex, 80);
        assert_eq!(rows[0].queue_id, 4);
        assert_eq!(rows[0].worker_id, 1);
        assert_eq!(rows[0].count, 7);
    }
}
