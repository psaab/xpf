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
    let ss_start_ts = binding_flows
        .iter()
        .map(|r| r.timestamp)
        .min()
        .unwrap_or(0)
        .saturating_add(args.warmup_secs);
    let ss_end_ts = binding_flows
        .iter()
        .map(|r| r.timestamp)
        .max()
        .unwrap_or(0)
        .saturating_sub(args.final_burst_secs);
    // Per-(timestamp, worker_id) accumulator: sum of counts across
    // bindings on the filtered iface for the same worker. (In a
    // typical loss-cluster topology each worker has one binding per
    // queue per iface; the sum collapses to that single binding's
    // count, but written as a sum to handle multi-queue-per-worker
    // configs cleanly.)
    let mut per_ts_worker: BTreeMap<(u64, u32), u32> = BTreeMap::new();
    for row in &binding_flows {
        if row.timestamp < ss_start_ts || row.timestamp > ss_end_ts {
            continue;
        }
        if !args.iface.is_empty() && row.iface != args.iface {
            continue;
        }
        *per_ts_worker
            .entry((row.timestamp, row.worker_id))
            .or_insert(0) += row.count;
    }
    // For each worker, collect its time-series of summed counts then
    // take the median. Workers with no samples report 0.
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
    // Each TCP flow creates flow_cache entries on BOTH ingress and egress
    // bindings (a forward flow + a reverse flow), so the data-plane sum is
    // expected to be ~2 × n_streams. Tolerance is per-stream-direction
    // (i.e. ± max(2, 0.10 × 2N)).
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
    let expected_sum = n_non_starved.saturating_mul(2);
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
    f.read_to_string(&mut buf).unwrap();
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
