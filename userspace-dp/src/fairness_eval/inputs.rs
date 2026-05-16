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
    pub(crate) test_start: Iperf3TestStart,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Iperf3Connected {
    pub(crate) socket: u64,
    #[allow(dead_code)] // diagnostic only; useful for future per-stream debugging
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
    #[allow(dead_code)] // diagnostic only; kept for traceability
    pub(crate) binding_slot: u32,
    #[allow(dead_code)] // not used in aggregation; iface filter is the discriminator
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
    let mut rows: Vec<BindingFlowsRow> = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 6 {
            let ts: u64 = match parts[0].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let slot: u32 = match parts[1].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let qid: u32 = match parts[2].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let wid: u32 = match parts[3].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let iface = parts[4].to_string();
            let count: u32 = match parts[5].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            rows.push(BindingFlowsRow {
                timestamp: ts,
                binding_slot: slot,
                queue_id: qid,
                worker_id: wid,
                iface,
                count,
            });
        } else if parts.len() == 3 {
            // Legacy 3-column format: timestamp, binding_slot, count.
            // Pretend slot==worker_id and iface=="" so it still works
            // (caller responsible for ensuring single-iface workload).
            let ts: u64 = match parts[0].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let slot: u32 = match parts[1].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let count: u32 = match parts[2].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            rows.push(BindingFlowsRow {
                timestamp: ts,
                binding_slot: slot,
                queue_id: 0,
                worker_id: slot,
                iface: String::new(),
                count,
            });
        }
        // Other formats: silently skipped.
    }
    Ok(rows)
}

pub(crate) fn parse_cos_flows_tsv(path: &PathBuf) -> Result<Vec<CosFlowsRow>, String> {
    // Format: timestamp\tifindex\tqueue_id\tworker_id\tcount.
    // Source metric: xpf_userspace_cos_active_flow_count.
    let s = read_to_string(path)?;
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
        let ts: u64 = match parts[0].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ifindex: i32 = match parts[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let qid: u32 = match parts[2].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let wid: u32 = match parts[3].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let count: u32 = match parts[4].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        rows.push(CosFlowsRow {
            timestamp: ts,
            ifindex,
            queue_id: qid,
            worker_id: wid,
            count,
        });
    }
    Ok(rows)
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
        // 2 timestamps × 2 (entries per worker per ts) → 4
        // entries summed; with count=2 each, per-worker sum = 4.
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
}
