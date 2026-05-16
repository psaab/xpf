use std::collections::BTreeMap;

use super::inputs::Iperf3Output;

pub(crate) struct Window {
    pub(crate) per_stream_buckets: BTreeMap<u64, Vec<u64>>,
    pub(crate) aggregate_buckets_bps: Vec<u64>,
    pub(crate) per_flow_throughputs: Vec<u64>,
}

pub(crate) fn extract_window(
    iperf: &Iperf3Output,
    warmup_secs: u64,
    final_burst_secs: u64,
) -> Result<Window, String> {
    // Determine the steady-state window: skip first warmup_secs and
    // last final_burst_secs of iperf3 intervals.
    let total_dur = iperf.start.test_start.duration;
    if total_dur <= warmup_secs + final_burst_secs {
        return Err(format!(
            "test duration {total_dur}s ≤ warmup {warmup_secs} + final-burst {final_burst_secs}"
        ));
    }
    let ss_dur = total_dur - warmup_secs - final_burst_secs;
    // The fairness contract requires a ≥60s steady-state window to
    // produce a statistically meaningful CoV measurement. Shorter
    // runs would give a verdict on too few per-second buckets.
    const MIN_STEADY_STATE_SECS: u64 = 60;
    if ss_dur < MIN_STEADY_STATE_SECS {
        return Err(format!(
            "steady-state window {ss_dur}s < {MIN_STEADY_STATE_SECS}s minimum; use a longer -t or reduce --warmup-secs/--final-burst-secs"
        ));
    }
    let ss_start = warmup_secs as f64;
    let ss_end = (total_dur - final_burst_secs) as f64;

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

    // Per-stream window-mean throughput for the per-flow CoV input.
    let per_flow_throughputs: Vec<u64> = per_stream_buckets
        .values()
        .filter(|v| !v.is_empty())
        .map(|v| {
            let sum: u64 = v.iter().sum();
            sum / v.len() as u64
        })
        .collect();

    Ok(Window {
        per_stream_buckets,
        aggregate_buckets_bps,
        per_flow_throughputs,
    })
}
