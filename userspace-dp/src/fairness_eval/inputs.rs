use serde::Deserialize;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use super::args::Args;

#[derive(Debug, Deserialize)]
pub(crate) struct Iperf3Output {
    pub(crate) start: Iperf3Start,
    pub(crate) intervals: Vec<Iperf3Interval>,
    #[serde(default)]
    pub(crate) end: Option<Iperf3End>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Iperf3Start {
    #[serde(default)]
    pub(crate) connected: Vec<Iperf3Connected>,
    /// Wall-clock start of the iperf run. `timesecs` is UNIX epoch
    /// seconds; the binding/CoS scrape TSV timestamps share the same
    /// clock, so this anchors the steady-state window to the actual run
    /// interval rather than the scrape-file extent (V-6). Absent in
    /// synthetic/legacy JSON, in which case the aggregation falls back
    /// to the min/max scrape heuristic.
    #[serde(default)]
    pub(crate) timestamp: Iperf3Timestamp,
    pub(crate) test_start: Iperf3TestStart,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Iperf3Timestamp {
    #[serde(default)]
    pub(crate) timesecs: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Iperf3Connected {
    pub(crate) socket: u64,
    #[expect(dead_code, reason = "#17195: dead in every build checked (release and --tests stripped probes in docs/log/17195.md); retained deliberately, so expect fires if a caller appears and the item should then lose this attribute instead of regaining allow(dead_code)")] // diagnostic only; useful for future per-stream debugging
    #[serde(default)]
    pub(crate) local_port: u32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Iperf3TestStart {
    #[serde(default)]
    pub(crate) duration: u64,
    #[serde(default, rename = "num_streams")]
    pub(crate) num_streams: u32,
    #[serde(default)]
    pub(crate) reverse: u8,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Iperf3Interval {
    pub(crate) streams: Vec<Iperf3StreamInterval>,
    /// Interval-summary flags. iperf3 marks warmup/omitted intervals
    /// (`-O`) with `sum.omitted=true`; those must not count as
    /// steady-state data (V-7). Absent in synthetic JSON → defaults
    /// to a non-omitted summary.
    #[serde(default)]
    pub(crate) sum: Iperf3IntervalSum,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Iperf3IntervalSum {
    #[serde(default)]
    pub(crate) omitted: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Iperf3StreamInterval {
    pub(crate) socket: u64,
    pub(crate) start: f64,
    pub(crate) end: f64,
    pub(crate) bits_per_second: f64,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Iperf3End {
    #[serde(default)]
    pub(crate) sum_sent: Iperf3EndSum,
    #[serde(default)]
    pub(crate) cpu_utilization_percent: Option<Iperf3CpuUtilization>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Iperf3EndSum {
    #[serde(default)]
    pub(crate) retransmits: u64,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Iperf3CpuUtilization {
    #[serde(default)]
    pub(crate) host_total: f64,
    #[serde(default)]
    pub(crate) host_user: f64,
    #[serde(default)]
    pub(crate) host_system: f64,
    #[serde(default)]
    pub(crate) remote_total: f64,
    #[serde(default)]
    pub(crate) remote_user: f64,
    #[serde(default)]
    pub(crate) remote_system: f64,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct BindingFlowsRow {
    /// Wall-clock-aligned 1s timestamp (seconds since epoch, integer).
    pub(crate) timestamp: u64,
    #[cfg_attr(not(test), expect(dead_code, reason = "#17195: dead in the release fairness-eval build but read under --tests; retained deliberately, so expect fires if a release caller appears"))]
    pub(crate) binding_slot: u32,
    #[expect(dead_code, reason = "#17195: dead in every build checked (release and --tests stripped probes in docs/log/17195.md); retained deliberately, so expect fires if a caller appears and the item should then lose this attribute instead of regaining allow(dead_code)")] // not used in aggregation; iface filter is the discriminator
    pub(crate) queue_id: u32,
    /// Owner worker id; the contract's `{a_i}` is keyed on this, not
    /// binding_slot (multiple bindings per worker, one per interface).
    pub(crate) worker_id: u32,
    /// Interface name; used to filter to a single direction.
    pub(crate) iface: String,
    pub(crate) count: u32,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct CosFlowsRow {
    pub(crate) timestamp: u64,
    pub(crate) ifindex: i32,
    pub(crate) queue_id: u32,
    pub(crate) worker_id: u32,
    pub(crate) count: u32,
}

pub(crate) struct Inputs {
    pub(crate) iperf: Iperf3Output,
    pub(crate) binding_flows: Vec<BindingFlowsRow>,
    pub(crate) cos_flows: Option<Vec<CosFlowsRow>>,
}

pub(crate) fn load(args: &Args) -> Result<Inputs, String> {
    let iperf_json = read_to_string(&args.iperf_json)?;
    let iperf: Iperf3Output =
        serde_json::from_str(&iperf_json).map_err(|e| format!("parsing iperf3 JSON: {e}"))?;
    let binding_flows = parse_binding_flows_tsv(&args.binding_flows)?;
    let cos_flows = args
        .cos_flows
        .as_ref()
        .map(parse_cos_flows_tsv)
        .transpose()?;
    Ok(Inputs {
        iperf,
        binding_flows,
        cos_flows,
    })
}

fn read_to_string(path: &PathBuf) -> Result<String, String> {
    let mut f = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(buf)
}

pub(crate) fn parse_binding_flows_tsv(path: &PathBuf) -> Result<Vec<BindingFlowsRow>, String> {
    // Format: timestamp\tbinding_slot\tqueue_id\tworker_id\tiface\tcount.
    // Skip header / comment lines starting with '#'. For backward
    // compatibility with the legacy 3-column format (older harness
    // versions), if only 3 columns are present, the iface filter is
    // treated as no-filter and worker_id defaults to binding_slot.
    let s = read_to_string(path)?;
    let (rows, skipped) = parse_binding_flows_rows(&s);
    warn_skipped("parse_binding_flows_tsv", path, skipped);
    Ok(rows)
}

fn parse_binding_flows_rows(s: &str) -> (Vec<BindingFlowsRow>, usize) {
    let mut rows: Vec<BindingFlowsRow> = Vec::new();
    let mut skipped = 0usize;
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_binding_flows_line(line) {
            Some(row) => rows.push(row),
            None => skipped += 1,
        }
    }
    (rows, skipped)
}

fn parse_binding_flows_line(line: &str) -> Option<BindingFlowsRow> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() == 6 {
        Some(BindingFlowsRow {
            timestamp: parts[0].parse().ok()?,
            binding_slot: parts[1].parse().ok()?,
            queue_id: parts[2].parse().ok()?,
            worker_id: parts[3].parse().ok()?,
            iface: parts[4].to_string(),
            count: parts[5].parse().ok()?,
        })
    } else if parts.len() == 3 {
        // Legacy 3-column format: timestamp, binding_slot, count.
        // Pretend slot==worker_id and iface=="" so it still works
        // (caller responsible for ensuring single-iface workload).
        let slot: u32 = parts[1].parse().ok()?;
        Some(BindingFlowsRow {
            timestamp: parts[0].parse().ok()?,
            binding_slot: slot,
            queue_id: 0,
            worker_id: slot,
            iface: String::new(),
            count: parts[2].parse().ok()?,
        })
    } else {
        None
    }
}

pub(crate) fn parse_cos_flows_tsv(path: &PathBuf) -> Result<Vec<CosFlowsRow>, String> {
    // Format: timestamp\tifindex\tqueue_id\tworker_id\tcount.
    // Source metric: xpf_userspace_cos_active_flow_count.
    let s = read_to_string(path)?;
    let (rows, skipped) = parse_cos_flows_rows(&s);
    warn_skipped("parse_cos_flows_tsv", path, skipped);
    Ok(rows)
}

fn parse_cos_flows_rows(s: &str) -> (Vec<CosFlowsRow>, usize) {
    let mut rows: Vec<CosFlowsRow> = Vec::new();
    let mut skipped = 0usize;
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_cos_flows_line(line) {
            Some(row) => rows.push(row),
            None => skipped += 1,
        }
    }
    (rows, skipped)
}

fn parse_cos_flows_line(line: &str) -> Option<CosFlowsRow> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 5 {
        return None;
    }
    Some(CosFlowsRow {
        timestamp: parts[0].parse().ok()?,
        ifindex: parts[1].parse().ok()?,
        queue_id: parts[2].parse().ok()?,
        worker_id: parts[3].parse().ok()?,
        count: parts[4].parse().ok()?,
    })
}

/// Emit a stderr warning when a TSV parse skipped one or more malformed rows.
/// A silent skip (ps-038-A1 F2) can undercount one worker's samples and flip
/// the CoV/fairness gate silently; surfacing the count lets the harness
/// operator notice a corrupted/truncated Prometheus scrape.
fn warn_skipped(parser: &str, path: &PathBuf, skipped: usize) {
    if skipped > 0 {
        eprintln!(
            "fairness-eval: {parser}: skipped {skipped} malformed row(s) in {}",
            path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

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
                content.push_str(&format!("{ts}\t{w}\t{w}\t{w}\tge-0-0-2\t2\n"));
                // Noise on a different iface — must NOT contribute
                // when --iface=ge-0-0-2 is set.
                content.push_str(&format!(
                    "{ts}\t{slot}\t{w}\t{w}\tge-0-0-3\t99\n",
                    slot = 6 + w
                ));
            }
        }
        let p = write_tmp(&content);
        let rows = parse_binding_flows_tsv(&p).unwrap();
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
        // 2 timestamps × 1 iface-filtered entry per worker per ts
        // → 2 entries summed; with count=2 each, per-worker sum = 4.
        // Median across the 2 timestamps would still be 2 (the
        // sample value at each ts). The integration of the
        // sum-then-median path lives in the verdict code; here we
        // just confirm the parser + filter shape.
        for v in &sum_per_worker {
            assert!(
                *v > 0,
                "per-worker sum should be non-zero on filtered iface"
            );
        }
    }

    #[test]
    fn three_col_legacy_parses_with_empty_iface() {
        let content = "# timestamp\tbinding_slot\tcount\n1000\t0\t5\n1000\t1\t5\n";
        let p = write_tmp(content);
        let rows = parse_binding_flows_tsv(&p).unwrap();
        let _ = fs::remove_file(&p);
        assert_eq!(rows.len(), 2);
        for r in &rows {
            assert_eq!(r.iface, "", "legacy 3-col should produce empty iface label");
            assert_eq!(
                r.worker_id, r.binding_slot,
                "legacy 3-col: worker_id == slot"
            );
        }
    }

    #[test]
    fn five_col_cos_flow_tsv_parses() {
        let content = "# timestamp\tifindex\tqueue_id\tworker_id\tcount\n1000\t80\t4\t1\t7\n";
        let p = write_tmp(content);
        let rows = parse_cos_flows_tsv(&p).unwrap();
        let _ = fs::remove_file(&p);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timestamp, 1000);
        assert_eq!(rows[0].ifindex, 80);
        assert_eq!(rows[0].queue_id, 4);
        assert_eq!(rows[0].worker_id, 1);
        assert_eq!(rows[0].count, 7);
    }

    #[test]
    fn binding_flows_counts_skipped_malformed_rows() {
        // ps-038-A1 F2: malformed rows must be COUNTED (and surfaced via a
        // warning), not silently dropped. Comment + blank lines are NOT
        // skips; a non-numeric field and a wrong-column-count row are.
        let content = "\
# header comment\n\
\n\
1000\t0\t0\t0\tge-0-0-2\t2\n\
1000\tXXX\t0\t0\tge-0-0-2\t2\n\
1000\t0\t0\n\
1000 0 0 0 ge-0-0-2\n\
2000\t1\t1\t1\tge-0-0-2\t3\n";
        let (rows, skipped) = parse_binding_flows_rows(content);
        // 2 valid 6-col rows + 1 valid 3-col row.
        assert_eq!(rows.len(), 3, "valid rows: {rows:?}");
        // 1 non-numeric 6-col + 1 unsupported 4-col => 2 skips.
        assert_eq!(skipped, 2, "skipped count");
    }

    #[test]
    fn cos_flows_counts_skipped_malformed_rows() {
        // ps-038-A1 F2 for the CoS TSV parser.
        let content = "\
# timestamp\tifindex\tqueue_id\tworker_id\tcount\n\
1000\t80\t4\t1\t7\n\
1000\t80\tbad\t1\t7\n\
1000\t80\t4\t1\n";
        let (rows, skipped) = parse_cos_flows_rows(content);
        assert_eq!(rows.len(), 1, "valid rows: {rows:?}");
        // 1 non-numeric queue_id + 1 wrong-column-count => 2 skips.
        assert_eq!(skipped, 2, "skipped count");
    }
}
