//! `fairness-eval` black-box integration tests (#547).
//!
//! Drives the merged `fairness-eval` binary as a subprocess with
//! synthetic `iperf3.json` + 6-column `binding-flows.tsv` files,
//! and asserts subprocess-visible contract only — exit code,
//! verdict string, failure_reasons class membership, required JSON
//! keys, distribution_a_i values, and broad numeric relationships.
//!
//! Per the v6 plan (`docs/pr/547-rss-skew-fixture/plan.md` §3.5),
//! these tests do NOT import `userspace_dp::fairness::*` or any
//! other internal helper. Cargo's tests/*.rs target physically
//! cannot reach the binary's internal modules; that boundary is
//! enforced by the compiler.
//!
//! Run with:
//!   cargo test --manifest-path userspace-dp/Cargo.toml --release \
//!     --test fairness_eval_blackbox

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// ---------------------------------------------------------------------------
// TempGuard: collision-resistant tempdir with Drop cleanup.
//
// Reuses the SystemTime+nanos+pid pattern from fairness-eval.rs::tsv_tests
// (line 729+ at HEAD, commit 9d3faf02) to avoid a tempfile crate dev-dep.
// Per Codex round-4 finding A:
// - process::id() does NOT disambiguate threads inside one cargo test
//   binary, but as_nanos() granularity + the test-name prefix supplied
//   by each call site provides intra-process uniqueness.
// - Drop runs during stack unwinding on panic; cargo test's catch_unwind
//   semantics ensure cleanup on test failure (modulo hard abort).
// ---------------------------------------------------------------------------

struct TempGuard {
    path: PathBuf,
}

impl TempGuard {
    fn new(prefix: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "fairness-eval-blackbox-{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("post-epoch system time")
                .as_nanos()
        ));
        fs::create_dir_all(&p).expect("create tempdir");
        Self { path: p }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Synthetic input synthesis.
// ---------------------------------------------------------------------------

/// A single iperf3 stream interval record.
#[derive(Debug, Clone, Copy)]
struct StreamSample {
    socket: u64,
    start: f64,
    end: f64,
    bits_per_second: f64,
}

/// Synthesise the minimum iperf3 JSON shape that fairness-eval consumes.
///
/// `connected_sockets` lists the sockets that appear in `start.connected[]`
/// (these define the iperf-stream universe). `intervals` is a Vec of
/// per-interval records, each containing a Vec<StreamSample>. Sockets in
/// `connected_sockets` that don't appear in any interval are starved
/// candidates per the harness's contract.
fn synth_iperf3_json(
    duration_s: u64,
    connected_sockets: &[u64],
    intervals: Vec<Vec<StreamSample>>,
) -> String {
    let connected: Vec<Value> = connected_sockets
        .iter()
        .enumerate()
        .map(|(i, &s)| {
            serde_json::json!({
                "socket": s,
                "local_port": 50000 + i as u32,
            })
        })
        .collect();
    let intervals_json: Vec<Value> = intervals
        .into_iter()
        .map(|streams| {
            let s_json: Vec<Value> = streams
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "socket": s.socket,
                        "start": s.start,
                        "end": s.end,
                        "bits_per_second": s.bits_per_second,
                    })
                })
                .collect();
            serde_json::json!({ "streams": s_json })
        })
        .collect();
    serde_json::to_string(&serde_json::json!({
        "start": {
            "connected": connected,
            "test_start": {
                "duration": duration_s,
                "num_streams": connected_sockets.len() as u32,
            },
        },
        "intervals": intervals_json,
    }))
    .expect("serialize iperf3 json")
}

/// A single 6-column TSV row.
#[derive(Debug, Clone)]
struct TsvRow {
    timestamp: u64,
    binding_slot: u32,
    queue_id: u32,
    worker_id: u32,
    iface: &'static str,
    count: u32,
}

/// A single 5-column class-specific CoS active-flow TSV row.
#[derive(Debug, Clone)]
struct CosTsvRow {
    timestamp: u64,
    ifindex: i32,
    queue_id: u32,
    worker_id: u32,
    count: u32,
}

/// Build the 6-column TSV (timestamp, binding_slot, queue_id, worker_id,
/// iface, count) with a leading comment-header line that matches what
/// `test/incus/fairness-harness.sh` emits on the cluster.
fn synth_tsv_6col(rows: &[TsvRow]) -> String {
    let mut s = String::from("# timestamp\tbinding_slot\tqueue_id\tworker_id\tiface\tcount\n");
    for r in rows {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            r.timestamp, r.binding_slot, r.queue_id, r.worker_id, r.iface, r.count
        ));
    }
    s
}

fn synth_cos_tsv_5col(rows: &[CosTsvRow]) -> String {
    let mut s = String::from("# timestamp\tifindex\tqueue_id\tworker_id\tcount\n");
    for r in rows {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            r.timestamp, r.ifindex, r.queue_id, r.worker_id, r.count
        ));
    }
    s
}

// ---------------------------------------------------------------------------
// Subprocess invocation.
//
// Cargo auto-builds same-package bin targets and exposes their path via
// the CARGO_BIN_EXE_<name> compile-time env var. Per Codex round-3 + Gemini
// round-1-retry verifications, this is reliable and needs no explicit
// dev-dep on the bin.
// ---------------------------------------------------------------------------

fn run_eval(
    iperf_json: &Path,
    tsv: &Path,
    extra_args: &[&str],
) -> Output {
    let bin = env!("CARGO_BIN_EXE_fairness-eval");
    let mut cmd = Command::new(bin);
    cmd.args([
        "--iperf-json", iperf_json.to_str().unwrap(),
        "--binding-flows", tsv.to_str().unwrap(),
    ]);
    cmd.args(extra_args);
    cmd.output().expect("fairness-eval invocation")
}

/// Convenience: write inputs to `tmp`, invoke the binary, parse stdout
/// JSON if exit code suggests it's emitted.
fn run_with_inputs(
    tmp: &TempGuard,
    iperf_json_str: &str,
    tsv_str: &str,
    extra_args: &[&str],
) -> (Output, Option<Value>) {
    let iperf_path = tmp.path().join("iperf3.json");
    let tsv_path = tmp.path().join("binding-flows.tsv");
    fs::write(&iperf_path, iperf_json_str).expect("write iperf3.json");
    fs::write(&tsv_path, tsv_str).expect("write tsv");
    let output = run_eval(&iperf_path, &tsv_path, extra_args);
    let json = if output.status.code() == Some(0) || output.status.code() == Some(1) {
        // PASS / FAIL emit verdict JSON to stdout.
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Find the first '{' so any leading log lines don't break parsing.
        if let Some(brace) = stdout.find('{') {
            serde_json::from_str(&stdout[brace..]).ok()
        } else {
            None
        }
    } else {
        None
    };
    (output, json)
}

fn run_with_inputs_and_cos(
    tmp: &TempGuard,
    iperf_json_str: &str,
    tsv_str: &str,
    cos_tsv_str: &str,
    extra_args: &[&str],
) -> (Output, Option<Value>) {
    let iperf_path = tmp.path().join("iperf3.json");
    let tsv_path = tmp.path().join("binding-flows.tsv");
    let cos_tsv_path = tmp.path().join("cos-flows.tsv");
    fs::write(&iperf_path, iperf_json_str).expect("write iperf3.json");
    fs::write(&tsv_path, tsv_str).expect("write tsv");
    fs::write(&cos_tsv_path, cos_tsv_str).expect("write cos tsv");
    let mut args = vec!["--cos-flows", cos_tsv_path.to_str().unwrap()];
    args.extend_from_slice(extra_args);
    let output = run_eval(&iperf_path, &tsv_path, &args);
    let json = if output.status.code() == Some(0) || output.status.code() == Some(1) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(brace) = stdout.find('{') {
            serde_json::from_str(&stdout[brace..]).ok()
        } else {
            None
        }
    } else {
        None
    };
    (output, json)
}

// ---------------------------------------------------------------------------
// Required-keys schema test.
// ---------------------------------------------------------------------------

/// Per v6 plan §3.4 plus the iperf diagnostics extension, the
/// always-present required-keys set is 12 fields. A rename of any would
/// be a contract break and must fail loudly. Verify on a PASS run.
#[test]
fn verdict_emits_required_keys() {
    let tmp = TempGuard::new("schema");
    let (sockets, json_str) = make_balanced_pass_inputs(6, 60);
    let tsv_str = make_balanced_tsv(6, &timestamps_for(60), "ge-0-0-2");
    let _ = sockets; // discard; not needed here
    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert!(
        output.status.success(),
        "schema fixture must PASS — stderr={}\nstdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let v = verdict.expect("verdict JSON");
    let obj = v.as_object().expect("verdict JSON is an object");

    // The 12 always-present required keys per v6 plan §3.4 plus iperf
    // diagnostics. CPU fields are optional because older iperf3 JSON may
    // omit end.cpu_utilization_percent.
    for key in [
        "distribution_a_i",
        "n_active",
        "cstruct",
        "observed_cov",
        "gap",
        "saturated",
        "a_i_sum_check_ok",
        "starved_flow_count",
        "verdict",
        "failure_reasons",
        "iperf_retransmits",
        "iperf_reverse",
    ] {
        assert!(
            obj.contains_key(key),
            "required key `{key}` missing from verdict JSON: {v}"
        );
    }

    // Type assertions on each required key — a contract break that
    // changes a field's JSON type (e.g. `saturated` from bool to
    // string) would not be caught by `contains_key` alone. Per Codex
    // code review LOW finding #3.
    assert!(v["distribution_a_i"].is_array(), "distribution_a_i must be array");
    assert!(v["n_active"].is_u64(), "n_active must be unsigned integer");
    assert!(v["cstruct"].is_f64(), "cstruct must be float");
    assert!(v["observed_cov"].is_f64(), "observed_cov must be float");
    assert!(v["gap"].is_f64(), "gap must be float");
    assert!(v["saturated"].is_boolean(), "saturated must be boolean");
    assert!(v["a_i_sum_check_ok"].is_boolean(), "a_i_sum_check_ok must be boolean");
    assert!(v["starved_flow_count"].is_u64(), "starved_flow_count must be unsigned integer");
    assert!(v["verdict"].is_string(), "verdict must be string");
    assert!(v["failure_reasons"].is_array(), "failure_reasons must be array");
    assert!(v["iperf_retransmits"].is_u64(), "iperf_retransmits must be unsigned integer");
    assert!(v["iperf_reverse"].is_boolean(), "iperf_reverse must be boolean");
}

#[test]
fn verdict_emits_iperf_end_diagnostics() {
    let tmp = TempGuard::new("iperf_diag");
    let (_sockets, json_str) = make_balanced_pass_inputs(6, 60);
    let mut iperf: Value = serde_json::from_str(&json_str).expect("fixture JSON");
    iperf["start"]["test_start"]["reverse"] = serde_json::json!(1);
    iperf["end"] = serde_json::json!({
        "sum_sent": {
            "retransmits": 17,
        },
        "cpu_utilization_percent": {
            "host_total": 10.0,
            "host_user": 1.5,
            "host_system": 8.5,
            "remote_total": 74.5,
            "remote_user": 2.0,
            "remote_system": 72.5,
        },
    });
    let json_str = serde_json::to_string(&iperf).expect("serialize fixture JSON");
    let tsv_str = make_balanced_tsv(6, &timestamps_for(60), "ge-0-0-2");

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert!(
        output.status.success(),
        "iperf diagnostics fixture must PASS — stderr={}\nstdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let v = verdict.expect("verdict JSON");
    assert_eq!(v["iperf_retransmits"], 17);
    assert_eq!(v["iperf_reverse"], true);
    assert_eq!(v["iperf_cpu_host_total_percent"].as_f64(), Some(10.0));
    assert_eq!(v["iperf_cpu_host_user_percent"].as_f64(), Some(1.5));
    assert_eq!(v["iperf_cpu_host_system_percent"].as_f64(), Some(8.5));
    assert_eq!(v["iperf_cpu_remote_total_percent"].as_f64(), Some(74.5));
    assert_eq!(v["iperf_cpu_remote_user_percent"].as_f64(), Some(2.0));
    assert_eq!(v["iperf_cpu_remote_system_percent"].as_f64(), Some(72.5));
    // reverse mode: sender is the remote endpoint
    assert_eq!(v["iperf_sender_cpu_total_percent"].as_f64(), Some(74.5));
    assert_eq!(v["iperf_sender_cpu_user_percent"].as_f64(), Some(2.0));
    assert_eq!(v["iperf_sender_cpu_system_percent"].as_f64(), Some(72.5));
}

#[test]
fn verdict_maps_forward_sender_cpu_to_host() {
    let tmp = TempGuard::new("iperf_forward_diag");
    let (_sockets, json_str) = make_balanced_pass_inputs(6, 60);
    let mut iperf: Value = serde_json::from_str(&json_str).expect("fixture JSON");
    iperf["start"]["test_start"]["reverse"] = serde_json::json!(0);
    iperf["end"] = serde_json::json!({
        "sum_sent": {
            "retransmits": 3,
        },
        "cpu_utilization_percent": {
            "host_total": 81.25,
            "host_user": 4.25,
            "host_system": 77.0,
            "remote_total": 12.5,
            "remote_user": 1.0,
            "remote_system": 11.5,
        },
    });
    let json_str = serde_json::to_string(&iperf).expect("serialize fixture JSON");
    let tsv_str = make_balanced_tsv(6, &timestamps_for(60), "ge-0-0-2");

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert!(
        output.status.success(),
        "forward iperf diagnostics fixture must PASS — stderr={}\nstdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let v = verdict.expect("verdict JSON");
    assert_eq!(v["iperf_retransmits"], 3);
    assert_eq!(v["iperf_reverse"], false);
    assert_eq!(v["iperf_cpu_host_total_percent"].as_f64(), Some(81.25));
    assert_eq!(v["iperf_cpu_host_user_percent"].as_f64(), Some(4.25));
    assert_eq!(v["iperf_cpu_host_system_percent"].as_f64(), Some(77.0));
    assert_eq!(v["iperf_cpu_remote_total_percent"].as_f64(), Some(12.5));
    assert_eq!(v["iperf_cpu_remote_user_percent"].as_f64(), Some(1.0));
    assert_eq!(v["iperf_cpu_remote_system_percent"].as_f64(), Some(11.5));
    // forward mode: sender is the host endpoint
    assert_eq!(v["iperf_sender_cpu_total_percent"].as_f64(), Some(81.25));
    assert_eq!(v["iperf_sender_cpu_user_percent"].as_f64(), Some(4.25));
    assert_eq!(v["iperf_sender_cpu_system_percent"].as_f64(), Some(77.0));
}

// ---------------------------------------------------------------------------
// Black-box cases.
// ---------------------------------------------------------------------------

#[test]
fn pass_case_skew_with_iface_noise() {
    let tmp = TempGuard::new("pass");
    // 6 sockets, each producing ~equal throughput across 60 1-second
    // intervals (warmup 0 / final-burst 0 means all 60 intervals count
    // as steady-state — needed to clear MIN_STEADY_STATE_SECS=60).
    let (sockets, json_str) = make_balanced_pass_inputs(6, 60);
    // Per-worker {a_i} = [1,1,1,1,1,1] on ge-0-0-2 — single direction,
    // matching the 6 iperf3 streams. Plus noise on ge-0-0-3 with huge
    // counts that the iface filter MUST drop. (sum(a_i)=6 matches
    // n_streams×direction_multiplier=6×1 within tolerance.)
    let mut rows: Vec<TsvRow> = Vec::new();
    for ts in timestamps_for(60) {
        for w in 0u32..6 {
            rows.push(TsvRow {
                timestamp: ts,
                binding_slot: w,
                queue_id: w,
                worker_id: w,
                iface: "ge-0-0-2",
                count: 1,
            });
            // Noise: on a different iface; worker_id MUST NOT confuse the
            // filtered aggregation. Counts huge to make a regression
            // (filter dropped, e.g.) explode the assertion.
            rows.push(TsvRow {
                timestamp: ts,
                binding_slot: 6 + w,
                queue_id: w,
                worker_id: w,
                iface: "ge-0-0-3",
                count: 999,
            });
        }
    }
    let tsv_str = synth_tsv_6col(&rows);

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit 0 (PASS); stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on PASS");
    assert_eq!(v["verdict"], "PASS");
    assert_eq!(
        v["distribution_a_i"],
        serde_json::json!([1, 1, 1, 1, 1, 1]),
        "iface filter should drop ge-0-0-3 noise; expected [1,1,1,1,1,1] per worker"
    );
    assert_eq!(v["n_active"], 6);
    assert_eq!(v["a_i_sum_check_ok"], true);
    assert_eq!(v["starved_flow_count"], 0);
    let _ = sockets;

    // Broad numeric: cstruct ≥ 0 and gap = observed_cov - cstruct.
    let cstruct = v["cstruct"].as_f64().expect("cstruct f64");
    let observed = v["observed_cov"].as_f64().expect("observed_cov f64");
    let gap = v["gap"].as_f64().expect("gap f64");
    assert!(cstruct >= 0.0, "cstruct must be >= 0");
    assert!((gap - (observed - cstruct)).abs() < 1e-9, "gap = observed_cov - cstruct");
}

#[test]
fn gate1_starved_flow_fails() {
    let tmp = TempGuard::new("gate1");
    // 6 streams; stream-with-socket=10 produces 0 bps in EVERY steady-
    // state interval. starved_flow_count = 1 → Gate 1 FAIL.
    let sockets = [5u64, 6, 7, 8, 9, 10];
    let mut intervals: Vec<Vec<StreamSample>> = Vec::new();
    for i in 0..60u64 {
        let mut iv = Vec::new();
        for &sock in &sockets {
            // socket=10 contributes 0 bps; others equal share.
            let bps = if sock == 10 { 0.0 } else { 1.0e9 };
            iv.push(StreamSample {
                socket: sock,
                start: i as f64,
                end: i as f64 + 1.0,
                bits_per_second: bps,
            });
        }
        intervals.push(iv);
    }
    let json_str = synth_iperf3_json(60, &sockets, intervals);
    let tsv_str = make_balanced_tsv(6, &timestamps_for(60), "ge-0-0-2");

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "Gate 1 FAIL must exit 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on FAIL");
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["starved_flow_count"], 1);
    let reasons = v["failure_reasons"].as_array().expect("failure_reasons array");
    assert!(
        reasons.iter().any(|r| r.as_str().unwrap_or("").contains("Gate 1")),
        "failure_reasons must contain a Gate 1 entry; got: {:?}",
        reasons
    );
}

#[test]
fn gate2_cov_gap_exceeds_epsilon_fails() {
    let tmp = TempGuard::new("gate2");
    // 6 streams; per-stream throughputs heavily skewed (one stream
    // dominates) but no flow is starved. With balanced {a_i}=[1;6]
    // (count=1 per worker, sum=6 matches the 6 streams), cstruct=0
    // and observed_cov should comfortably exceed EPSILON=0.05 → Gate
    // 2 FAIL without Gate 1.
    let sockets = [5u64, 6, 7, 8, 9, 10];
    let mut intervals: Vec<Vec<StreamSample>> = Vec::new();
    for i in 0..60u64 {
        let mut iv = Vec::new();
        for (idx, &sock) in sockets.iter().enumerate() {
            // First flow gets 10 Gbps, rest get 1 Gbps. The per-flow
            // arithmetic mean is (10 + 5×1)/6 ≈ 2.5 Gbps; stddev is
            // sqrt(((10-2.5)² + 5×(1-2.5)²)/6) ≈ 3.23 Gbps; CoV ≈
            // 3.23 / 2.5 ≈ 1.29. Far above EPSILON=0.05.
            let bps = if idx == 0 { 1.0e10 } else { 1.0e9 };
            iv.push(StreamSample {
                socket: sock,
                start: i as f64,
                end: i as f64 + 1.0,
                bits_per_second: bps,
            });
        }
        intervals.push(iv);
    }
    let json_str = synth_iperf3_json(60, &sockets, intervals);
    let tsv_str = make_balanced_tsv(6, &timestamps_for(60), "ge-0-0-2");

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "Gate 2 FAIL must exit 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on Gate 2 FAIL");
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["starved_flow_count"], 0, "no flow is starved in this case");
    let gap = v["gap"].as_f64().expect("gap f64");
    assert!(gap > 0.05, "gap must exceed EPSILON=0.05 to trigger Gate 2; got {gap}");
    let reasons = v["failure_reasons"].as_array().expect("failure_reasons array");
    assert!(
        reasons.iter().any(|r| r.as_str().unwrap_or("").contains("Gate 2")),
        "failure_reasons must contain a Gate 2 entry; got: {:?}",
        reasons
    );
}

#[test]
fn guard_sum_mismatch_fails() {
    let tmp = TempGuard::new("guard_sum");
    // 6 streams, all healthy → no Gate 1 / Gate 2 FAIL. But the TSV
    // reports a wildly inconsistent {a_i}: 100 active flows on worker 0,
    // 0 on the rest. sum=100 vs expected ~6 → harness sum guard fires.
    let (sockets, json_str) = make_balanced_pass_inputs(6, 60);
    let mut rows: Vec<TsvRow> = Vec::new();
    for ts in [1000u64, 1001, 1002, 1003, 1004] {
        rows.push(TsvRow {
            timestamp: ts,
            binding_slot: 0,
            queue_id: 0,
            worker_id: 0,
            iface: "ge-0-0-2",
            count: 100,
        });
    }
    let tsv_str = synth_tsv_6col(&rows);
    let _ = sockets;

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "Guard FAIL must exit 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on Guard FAIL");
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["a_i_sum_check_ok"], false);
    let reasons = v["failure_reasons"].as_array().expect("failure_reasons array");
    let guard_reason = reasons
        .iter()
        .filter_map(|r| r.as_str())
        .find(|r| r.contains("Harness guard"))
        .unwrap_or_else(|| panic!("failure_reasons must contain a Harness guard entry; got: {reasons:?}"));
    assert!(guard_reason.contains("expected=6"), "guard reason missing expected_sum: {guard_reason}");
    assert!(guard_reason.contains("non-starved=6"), "guard reason missing non-starved: {guard_reason}");
    assert!(guard_reason.contains("dir_mult=1"), "guard reason missing dir_mult: {guard_reason}");
}

#[test]
fn guard_p12_allows_bounded_stale_overcount() {
    let tmp = TempGuard::new("guard_p12_overcount_pass");
    let (_sockets, json_str) = make_balanced_pass_inputs(12, 60);
    // Canonical CoS sweep shape from #1281: 12 healthy streams, but
    // active-flow snapshots can retain three stale/recently-active
    // entries. sum(a_i)=15 vs expected=12 is a bounded overcount and
    // should not false-fail the run.
    let tsv_str = make_distribution_tsv(&[4, 4, 4, 3, 0, 0], &timestamps_for(60), "ge-0-0-2");

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "P=12 sum(a_i)=15 stale-overcount window should PASS; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on P=12 overcount PASS");
    assert_eq!(v["verdict"], "PASS");
    assert_eq!(v["a_i_sum_check_ok"], true);
    assert_eq!(v["a_i_sum"], 15);
    assert_eq!(v["iperf_non_starved_streams"], 12);
    assert_eq!(v["a_i_sum_under_tolerance"], 2);
    assert_eq!(v["a_i_sum_over_tolerance"], 3);
    assert_eq!(v["a_i_sum_tolerance"], 3);
    assert_eq!(
        v["distribution_a_i"],
        serde_json::json!([4, 4, 4, 3, 0, 0])
    );
    assert_eq!(
        v["cstruct_distribution_a_i"],
        serde_json::json!([3, 3, 3, 3, 0, 0])
    );
    assert_eq!(v["cstruct_adjusted_for_a_i_overcount"], true);
    assert_eq!(v["cstruct"].as_f64(), Some(0.0));
}

#[test]
fn rss_expectation_uses_observed_distribution_not_cstruct_normalized_copy() {
    // Deliberate observed-vs-trimmed contract, first pinned by 66bd82e28
    // ("Preserve observed RSS expectation input"): stale-count normalization
    // is used only for Gate 2's structural Cstruct. RSS expectations answer
    // what the observed RSS assignment did, and must not let the trimmed
    // copy conceal a worker that actually owned more than 25% of flows.
    let tmp = TempGuard::new("rss_observed_not_normalized");
    let (_sockets, json_str) = make_balanced_pass_inputs(12, 60);
    let tsv_str = make_distribution_tsv(&[4, 4, 4, 3, 0, 0], &timestamps_for(60), "ge-0-0-2");

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
        "--rss-expectation", "max-worker-flow-share:25%",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "RSS expectation must fail against observed [4,4,4,3,0,0], not pass against normalized [3,3,3,3,0,0]; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on RSS expectation FAIL");
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["a_i_sum_check_ok"], true);
    assert_eq!(
        v["distribution_a_i"],
        serde_json::json!([4, 4, 4, 3, 0, 0])
    );
    assert_eq!(
        v["cstruct_distribution_a_i"],
        serde_json::json!([3, 3, 3, 3, 0, 0])
    );
    assert_eq!(v["cstruct_adjusted_for_a_i_overcount"], true);
    assert_eq!(
        v["max_worker_flow_share"].as_f64(),
        Some(4.0 / 15.0),
        "max_worker_flow_share must reflect observed [4,4,4,3,0,0], not normalized [3,3,3,3,0,0]: {v}"
    );
    let reasons = v["failure_reasons"].as_array().expect("failure_reasons array");
    assert!(
        reasons.iter().any(|r| r
            .as_str()
            .unwrap_or("")
            .contains("max_worker_flow_share")),
        "failure_reasons must contain the observed RSS max-share failure; got: {:?}",
        reasons
    );
}

#[test]
fn cstruct_max_expectation_uses_selected_gate2_cstruct() {
    let tmp = TempGuard::new("rss_cstruct_max_uses_selected_cstruct");
    let (_sockets, json_str) = make_balanced_pass_inputs(12, 60);
    let tsv_str = make_distribution_tsv(&[4, 4, 4, 3, 0, 0], &timestamps_for(60), "ge-0-0-2");

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
        "--rss-expectation", "cstruct-max:1%",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "cstruct-max must use the selected Gate-2 Cstruct (0), not the raw observed Cstruct (~0.125); stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on selected-Cstruct PASS");
    assert_eq!(v["verdict"], "PASS");
    assert_eq!(v["cstruct"], 0.0);
    assert_eq!(
        v["cstruct_distribution_a_i"],
        serde_json::json!([3, 3, 3, 3, 0, 0])
    );
    assert_eq!(v["cstruct_adjusted_for_a_i_overcount"], true);
    assert_eq!(v["rss_expectation_pass"], true);
}

#[test]
fn guard_p12_rejects_overcount_beyond_stale_window() {
    let tmp = TempGuard::new("guard_p12_overcount_fail");
    let (_sockets, json_str) = make_balanced_pass_inputs(12, 60);
    let tsv_str = make_distribution_tsv(&[4, 4, 4, 4, 0, 0], &timestamps_for(60), "ge-0-0-2");

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "P=12 sum(a_i)=16 should exceed the overcount window; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on P=12 overcount FAIL");
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["a_i_sum_check_ok"], false);
    assert_eq!(v["a_i_sum"], 16);
    assert_eq!(v["a_i_sum_over_tolerance"], 3);
    assert_eq!(
        v["cstruct_distribution_a_i"],
        serde_json::json!([4, 4, 4, 4, 0, 0])
    );
    assert_eq!(v["cstruct_adjusted_for_a_i_overcount"], false);
    let reasons = v["failure_reasons"].as_array().expect("failure_reasons array");
    let guard_reason = reasons
        .iter()
        .filter_map(|r| r.as_str())
        .find(|r| r.contains("Harness guard"))
        .unwrap_or_else(|| panic!("failure_reasons must contain a Harness guard entry; got: {reasons:?}"));
    assert!(guard_reason.contains("expected=12"), "guard reason missing expected_sum: {guard_reason}");
    assert!(guard_reason.contains("over_tolerance=3"), "guard reason missing over_tolerance: {guard_reason}");
}

#[test]
fn cos_path_uses_normalized_distribution_for_bounded_stale_overcount() {
    let tmp = TempGuard::new("cos_p12_overcount_pass");
    let (_sockets, json_str) = make_balanced_pass_inputs(12, 60);
    let binding_tsv = make_distribution_tsv(&[3, 3, 3, 3, 0, 0], &timestamps_for(60), "ge-0-0-2");
    let cos_tsv = make_cos_distribution_tsv(&[4, 4, 4, 3, 0, 0], &timestamps_for(60), 80, 4);

    let (output, verdict) = run_with_inputs_and_cos(&tmp, &json_str, &binding_tsv, &cos_tsv, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
        "--cos-ifindex", "80",
        "--cos-queue-id", "4",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "CoS P=12 bounded stale-overcount window should PASS; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on CoS overcount PASS");
    assert_eq!(v["verdict"], "PASS");
    assert_eq!(v["cstruct_source"], "cos_queue");
    assert_eq!(v["distribution_a_i"], serde_json::json!([4, 4, 4, 3, 0, 0]));
    assert_eq!(
        v["binding_distribution_a_i"],
        serde_json::json!([3, 3, 3, 3, 0, 0])
    );
    assert_eq!(
        v["cstruct_distribution_a_i"],
        serde_json::json!([3, 3, 3, 3, 0, 0])
    );
    assert_eq!(v["cstruct_adjusted_for_a_i_overcount"], true);
    assert_eq!(v["a_i_sum_check_ok"], true);
    assert_eq!(v["a_i_sum"], 15);
    assert_eq!(v["a_i_sum_over_tolerance"], 3);
    assert_eq!(v["cstruct"].as_f64(), Some(0.0));
}

#[test]
fn cos_path_rejects_selected_queue_sum_that_exceeds_binding_sum() {
    let tmp = TempGuard::new("cos_binding_guard");
    let (_sockets, json_str) = make_balanced_pass_inputs(12, 60);
    let binding_tsv = make_distribution_tsv(&[1, 1, 1, 1, 1, 1], &timestamps_for(60), "ge-0-0-2");
    let cos_tsv = make_cos_distribution_tsv(&[3, 3, 3, 3, 0, 0], &timestamps_for(60), 80, 4);

    let (output, verdict) = run_with_inputs_and_cos(&tmp, &json_str, &binding_tsv, &cos_tsv, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
        "--cos-ifindex", "80",
        "--cos-queue-id", "4",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "selected CoS sum far above binding sum should FAIL; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on CoS binding guard FAIL");
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["cstruct_source"], "cos_queue");
    assert_eq!(v["a_i_sum"], 12);
    assert_eq!(
        v["binding_distribution_a_i"],
        serde_json::json!([1, 1, 1, 1, 1, 1])
    );
    let reasons = v["failure_reasons"].as_array().expect("failure_reasons array");
    assert!(
        reasons.iter().any(|r| r
            .as_str()
            .unwrap_or("")
            .contains("selected CoS sum(a_i)=12 exceeds binding sum(a_i)=6")),
        "failure_reasons must contain the selected-CoS-vs-binding guard; got: {:?}",
        reasons
    );
}

#[test]
fn guard_low_n_legacy_input_rejects_p2_undercount() {
    let tmp = TempGuard::new("guard_low_n_legacy");
    let sockets = [5u64, 6];
    let mut intervals: Vec<Vec<StreamSample>> = Vec::new();
    for i in 0..60u64 {
        intervals.push(vec![
            StreamSample {
                socket: sockets[0],
                start: i as f64,
                end: i as f64 + 1.0,
                bits_per_second: 1.0e9,
            },
            StreamSample {
                socket: sockets[1],
                start: i as f64,
                end: i as f64 + 1.0,
                bits_per_second: 1.0e9,
            },
        ]);
    }
    let json_str = synth_iperf3_json(60, &sockets, intervals);
    let mut tsv_str = String::from("# timestamp\tbinding_slot\tcount\n");
    for ts in timestamps_for(60) {
        tsv_str.push_str(&format!("{ts}\t0\t1\n"));
    }

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "legacy P=2 undercount should fail the bidirectional harness guard; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on low-N legacy FAIL");
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["a_i_sum_check_ok"], false);
    assert_eq!(v["a_i_sum"], 1);
    assert_eq!(v["iperf_non_starved_streams"], 2);
    assert_eq!(v["a_i_sum_tolerance"], 2);
    let reasons = v["failure_reasons"].as_array().expect("failure_reasons array");
    let guard_reason = reasons
        .iter()
        .filter_map(|r| r.as_str())
        .find(|r| r.contains("Harness guard"))
        .unwrap_or_else(|| panic!("failure_reasons must contain a Harness guard entry; got: {reasons:?}"));
    assert!(guard_reason.contains("expected=4"), "guard reason missing expected_sum: {guard_reason}");
    assert!(guard_reason.contains("non-starved=2"), "guard reason missing non-starved: {guard_reason}");
    assert!(guard_reason.contains("dir_mult=2"), "guard reason missing dir_mult: {guard_reason}");
}

#[test]
fn guard_low_n_iface_input_accepts_absolute_floor_p2_gap1() {
    let tmp = TempGuard::new("guard_low_n_iface");
    let sockets = [5u64, 6];
    let mut intervals: Vec<Vec<StreamSample>> = Vec::new();
    for i in 0..60u64 {
        intervals.push(vec![
            StreamSample {
                socket: sockets[0],
                start: i as f64,
                end: i as f64 + 1.0,
                bits_per_second: 1.0e9,
            },
            StreamSample {
                socket: sockets[1],
                start: i as f64,
                end: i as f64 + 1.0,
                bits_per_second: 1.0e9,
            },
        ]);
    }
    let json_str = synth_iperf3_json(60, &sockets, intervals);
    let mut rows: Vec<TsvRow> = Vec::new();
    for ts in timestamps_for(60) {
        rows.push(TsvRow {
            timestamp: ts,
            binding_slot: 0,
            queue_id: 0,
            worker_id: 0,
            iface: "ge-0-0-2",
            count: 1,
        });
    }
    let tsv_str = synth_tsv_6col(&rows);

    // P=2 streams, --iface active → dir_mult=1 → expected_sum=2.
    // Only one binding slot reports count=1 (the other is absent →
    // median=0). a_i_sum=1, gap=|1-2|=1, tolerance=max(0,2)=2.
    // 1 ≤ 2 → sum guard PASS (absolute floor is the operative gate).
    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "iface-filtered P=2 gap=1 should stay inside the absolute floor (tolerance=2); stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on low-N iface PASS");
    assert_eq!(v["verdict"], "PASS");
    assert_eq!(v["a_i_sum_check_ok"], true);
    assert_eq!(v["a_i_sum"], 1);
    assert_eq!(v["iperf_non_starved_streams"], 2);
    assert_eq!(v["a_i_sum_tolerance"], 2);
}

#[test]
fn guard_empty_tsv_fails_via_sum_guard() {
    let tmp = TempGuard::new("guard_empty");
    // 6 healthy streams; TSV has header only (no data rows). With
    // no rows present, `any_iface_label_present == false` so
    // `iface_filter_active == false` (even though --iface is
    // supplied), `direction_multiplier == 2`, and the harness
    // computes expected_sum = 6 × 2 = 12. Actual sum(a_i) == 0;
    // |0 - 12| = 12 ≫ tolerance → sum guard FAIL. observed_cov ==
    // 0 and cstruct == 0 (per Codex round-3 + code review trace),
    // so Gate 2 does NOT fire — only the sum guard.
    let (_sockets, json_str) = make_balanced_pass_inputs(6, 60);
    let tsv_str = "# timestamp\tbinding_slot\tqueue_id\tworker_id\tiface\tcount\n".to_string();

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "empty TSV → Guard FAIL must exit 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on empty-TSV FAIL");
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["a_i_sum_check_ok"], false);
    assert_eq!(
        v["distribution_a_i"],
        serde_json::json!([0, 0, 0, 0, 0, 0]),
        "empty TSV → all-zero distribution_a_i"
    );
    let reasons = v["failure_reasons"].as_array().expect("failure_reasons array");
    assert!(
        reasons.iter().any(|r| r.as_str().unwrap_or("").contains("Harness guard")),
        "failure_reasons must contain a Harness guard entry; got: {:?}",
        reasons
    );
    // Gate 2 must NOT fire on empty TSV — observed_cov - cstruct == 0
    // when both are 0, so gap == 0 < epsilon.
    assert!(
        !reasons.iter().any(|r| r.as_str().unwrap_or("").contains("Gate 2")),
        "empty TSV must NOT trigger Gate 2; got: {:?}",
        reasons
    );
}

#[test]
fn exit2_out_of_range_worker_id() {
    let tmp = TempGuard::new("exit2");
    // 6 healthy streams; TSV has worker_id=99 which exceeds n_workers=6.
    // aggregate_per_worker returns Err → main exits 2 with no verdict JSON.
    let (_sockets, json_str) = make_balanced_pass_inputs(6, 60);
    let mut rows: Vec<TsvRow> = Vec::new();
    for ts in [1000u64, 1001, 1002, 1003, 1004] {
        rows.push(TsvRow {
            timestamp: ts,
            binding_slot: 0,
            queue_id: 0,
            worker_id: 99, // out of range
            iface: "ge-0-0-2",
            count: 1,
        });
    }
    let tsv_str = synth_tsv_6col(&rows);

    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2",
        "--n-workers", "6",
        "--warmup-secs", "0",
        "--final-burst-secs", "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "out-of-range worker_id must exit 2; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Codex code review (MEDIUM): the parser-side `verdict` Option is
    // `None` for any exit code other than 0/1; that does not actually
    // PROVE no JSON was emitted. Inspect stdout directly: it must be
    // empty (or at minimum contain no `{`) on the exit-2 error path.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains('{'),
        "exit 2 must not emit verdict JSON; got stdout: {stdout}"
    );
    assert!(verdict.is_none(), "exit 2 must not emit verdict JSON");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("worker_id") && stderr.contains("n-workers"),
        "stderr must explain the out-of-range error; got: {stderr}"
    );
}

#[test]
fn gate3_expect_saturation_below_cap_fails() {
    let tmp = TempGuard::new("gate3_below");
    // 6 balanced ~1 Gbps streams → aggregate ~6 Gbps. Structural cap =
    // shaper_rate(20g) × Nₐ(6)/Nᵥ(6) = 20 Gbps → NOT saturated. Without
    // --expect-saturation the aggregate leg is diagnostic and the run
    // PASSes (V-3: previously unenforceable); with it, Gate 3 FAILs.
    let (_sockets, json_str) = make_balanced_pass_inputs(6, 60);
    let tsv_str = make_balanced_tsv(6, &timestamps_for(60), "ge-0-0-2");

    // Diagnostic-only (no flag): PASS even below the cap.
    let (diag_out, diag_v) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2", "--n-workers", "6",
        "--warmup-secs", "0", "--final-burst-secs", "0",
        "--shaper-rate-bps", "20000000000",
    ]);
    assert_eq!(diag_out.status.code(), Some(0), "no flag → aggregate is diagnostic, run PASSes; stderr={}", String::from_utf8_lossy(&diag_out.stderr));
    let diag = diag_v.expect("verdict JSON");
    assert_eq!(diag["saturated"], false);
    assert_eq!(diag["aggregate_throughput_gate_enforced"], false);

    // Enforced: FAIL below the cap.
    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2", "--n-workers", "6",
        "--warmup-secs", "0", "--final-burst-secs", "0",
        "--shaper-rate-bps", "20000000000",
        "--expect-saturation",
    ]);
    assert_eq!(output.status.code(), Some(1),
        "expect-saturation below cap must FAIL Gate 3; stderr={}",
        String::from_utf8_lossy(&output.stderr));
    let v = verdict.expect("verdict JSON");
    assert_eq!(v["verdict"], "FAIL");
    assert_eq!(v["saturated"], false);
    assert_eq!(v["aggregate_throughput_gate_enforced"], true);
    let reasons = v["failure_reasons"].as_array().expect("failure_reasons array");
    assert!(
        reasons.iter().any(|r| r.as_str().unwrap_or("").contains("Gate 3")),
        "must contain a Gate 3 aggregate-throughput reason; got: {reasons:?}"
    );
}

#[test]
fn gate3_expect_saturation_at_cap_passes() {
    let tmp = TempGuard::new("gate3_at");
    // Aggregate ~6 Gbps against a 6 Gbps scaled cap (>=95%) → saturated
    // → Gate 3 PASSes even with --expect-saturation (not always-firing).
    let (_sockets, json_str) = make_balanced_pass_inputs(6, 60);
    let tsv_str = make_balanced_tsv(6, &timestamps_for(60), "ge-0-0-2");
    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2", "--n-workers", "6",
        "--warmup-secs", "0", "--final-burst-secs", "0",
        "--shaper-rate-bps", "6000000000",
        "--expect-saturation",
    ]);
    assert_eq!(output.status.code(), Some(0),
        "expect-saturation at cap must PASS; stderr={}",
        String::from_utf8_lossy(&output.stderr));
    let v = verdict.expect("verdict JSON");
    assert_eq!(v["verdict"], "PASS");
    assert_eq!(v["saturated"], true);
    assert_eq!(v["aggregate_throughput_gate_enforced"], true);
}

#[test]
fn truncated_intervals_below_min_window_rejected() {
    let tmp = TempGuard::new("truncated_window");
    // V-7: declared duration 120s clears the ss_dur>=60 declared gate,
    // but only 10 one-second intervals are present. The reducer must
    // reject on OBSERVED sample count (exit 2, explicit error), not
    // produce a verdict from a handful of buckets.
    let sockets: Vec<u64> = (5..11).collect();
    let mut intervals = Vec::new();
    for i in 0..10u64 {
        let mut iv = Vec::new();
        for &sock in &sockets {
            iv.push(StreamSample { socket: sock, start: i as f64, end: i as f64 + 1.0, bits_per_second: 1.0e9 });
        }
        intervals.push(iv);
    }
    let json_str = synth_iperf3_json(120, &sockets, intervals);
    let tsv_str = make_balanced_tsv(6, &timestamps_for(10), "ge-0-0-2");
    let (output, _verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2", "--n-workers", "6",
        "--warmup-secs", "0", "--final-burst-secs", "0",
    ]);
    assert_eq!(output.status.code(), Some(2),
        "truncated interval set must be rejected with exit 2; stderr={}",
        String::from_utf8_lossy(&output.stderr));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("buckets"),
        "error must cite the observed bucket count: {stderr}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains('{'), "rejected run must not emit a verdict: {stdout}");
}

#[test]
fn verdict_emits_doc_mandated_required_metrics() {
    let tmp = TempGuard::new("required_metrics");
    // V-9: per-flow quantiles (item 1), steady-state window timestamps
    // (item 12), and the saturation time-series (item 6) must be in the
    // routine verdict JSON.
    let (_sockets, json_str) = make_balanced_pass_inputs(6, 60);
    let tsv_str = make_balanced_tsv(6, &timestamps_for(60), "ge-0-0-2");
    let (output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2", "--n-workers", "6",
        "--warmup-secs", "0", "--final-burst-secs", "0",
        "--shaper-rate-bps", "6000000000",
    ]);
    assert!(output.status.success(),
        "required-metrics fixture must PASS; stderr={}",
        String::from_utf8_lossy(&output.stderr));
    let v = verdict.expect("verdict JSON");

    // item 1: per-flow throughput quantiles + stream count.
    let q = &v["per_flow_throughput_mbps"];
    for k in ["stream_count", "min_mbps", "p25_mbps", "median_mbps", "p75_mbps", "max_mbps"] {
        assert!(q.get(k).is_some(), "per_flow_throughput_mbps.{k} missing: {v}");
    }
    assert_eq!(q["stream_count"], 6);
    assert!(q["median_mbps"].as_f64().unwrap() > 0.0, "median must be >0: {v}");
    assert!(q["max_mbps"].as_f64().unwrap() >= q["min_mbps"].as_f64().unwrap());

    // item 12: steady-state window timestamps.
    let w = &v["steady_state_window"];
    for k in ["iperf_epoch_start", "iperf_epoch_end", "relative_start_sec", "relative_end_sec"] {
        assert!(w.get(k).is_some(), "steady_state_window.{k} missing: {v}");
    }
    assert_eq!(w["relative_start_sec"].as_f64(), Some(0.0));
    assert_eq!(w["relative_end_sec"].as_f64(), Some(60.0));

    // item 6: saturation determination time-series.
    let ss = &v["saturation_series"];
    assert!(ss["aggregate_buckets_bps"].is_array(), "aggregate_buckets_bps must be array: {v}");
    assert_eq!(ss["aggregate_buckets_bps"].as_array().unwrap().len(), 60,
        "one bucket per steady-state second");
    assert!(ss.get("structural_cap_bps").is_some());
    assert!(ss.get("saturated_bucket_fraction").is_some());
    assert_eq!(v["aggregate_throughput_gate_enforced"], false);
}

#[test]
fn per_flow_metric_includes_starved_zero_streams() {
    let tmp = TempGuard::new("starved_metric");
    // Copilot #1 (V-9 accuracy): 6 connected streams, but socket 10
    // never appears in any interval → it produced no steady-state
    // throughput (starved). The per_flow_throughput_mbps metric must
    // count all 6 streams with the starved one at 0 Mb/s, NOT drop it.
    let sockets = [5u64, 6, 7, 8, 9, 10];
    let mut intervals: Vec<Vec<StreamSample>> = Vec::new();
    for i in 0..60u64 {
        let mut iv = Vec::new();
        // Only the first 5 sockets send; socket 10 is absent from every
        // interval → empty bucket vec → starved.
        for &sock in &sockets[..5] {
            iv.push(StreamSample {
                socket: sock,
                start: i as f64,
                end: i as f64 + 1.0,
                bits_per_second: 1.0e9,
            });
        }
        intervals.push(iv);
    }
    let json_str = synth_iperf3_json(60, &sockets, intervals);
    let tsv_str = make_balanced_tsv(6, &timestamps_for(60), "ge-0-0-2");
    let (_output, verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2", "--n-workers", "6",
        "--warmup-secs", "0", "--final-burst-secs", "0",
    ]);
    // Gate 1 fails on the starved stream, but the verdict JSON is still
    // emitted on exit 1.
    let v = verdict.expect("verdict JSON");
    assert_eq!(v["starved_flow_count"], 1, "socket 10 must be starved: {v}");
    let q = &v["per_flow_throughput_mbps"];
    assert_eq!(
        q["stream_count"], 6,
        "starved stream must be counted, not dropped: {v}"
    );
    assert_eq!(
        q["min_mbps"].as_f64(),
        Some(0.0),
        "starved stream contributes 0 Mb/s to the quantiles: {v}"
    );
    assert!(
        q["max_mbps"].as_f64().unwrap() > 0.0,
        "live streams still contribute >0: {v}"
    );
}

#[test]
fn expect_saturation_without_shaper_rate_is_arg_error() {
    let tmp = TempGuard::new("expect_sat_no_shaper");
    // Copilot #2: --expect-saturation without --shaper-rate-bps is an
    // operator CLI mistake → arg-validation error (exit 2), NOT a Gate-3
    // FAIL (exit 1) that automation would misread as a fairness
    // regression.
    let (_sockets, json_str) = make_balanced_pass_inputs(6, 60);
    let tsv_str = make_balanced_tsv(6, &timestamps_for(60), "ge-0-0-2");
    let (output, _verdict) = run_with_inputs(&tmp, &json_str, &tsv_str, &[
        "--iface", "ge-0-0-2", "--n-workers", "6",
        "--warmup-secs", "0", "--final-burst-secs", "0",
        "--expect-saturation",
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "expect-saturation without --shaper-rate-bps must be an arg error (exit 2); stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("shaper-rate"),
        "stderr must explain the missing --shaper-rate-bps: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains('{'),
        "arg error must not emit a verdict: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Shared input builders.
// ---------------------------------------------------------------------------

/// Build a 6-stream iperf3 JSON with `n_intervals` 1-second steady-state
/// intervals where every stream gets equal throughput. Returns the
/// connected sockets plus the JSON string.
fn make_balanced_pass_inputs(n_streams: u32, n_intervals: u64) -> (Vec<u64>, String) {
    let sockets: Vec<u64> = (5..(5 + n_streams as u64)).collect();
    let mut intervals: Vec<Vec<StreamSample>> = Vec::new();
    for i in 0..n_intervals {
        let mut iv = Vec::new();
        for &sock in &sockets {
            iv.push(StreamSample {
                socket: sock,
                start: i as f64,
                end: i as f64 + 1.0,
                bits_per_second: 1.0e9,
            });
        }
        intervals.push(iv);
    }
    let s = synth_iperf3_json(n_intervals, &sockets, intervals);
    (sockets, s)
}

/// `n` consecutive timestamps starting at 1000 (matches the steady-state
/// window width that the fixture's iperf3 JSON is built for).
fn timestamps_for(n: u64) -> Vec<u64> {
    (1000..(1000 + n)).collect()
}

/// Build an `n_workers`-worker balanced TSV with `count: 1` per
/// (timestamp, worker_id) on the given iface (median per worker = 1,
/// so `distribution_a_i = [1; n_workers]`). With 6 workers and the
/// PASS fixture's 6 iperf streams, sum(a_i)=6 matches
/// `n_streams × direction_multiplier=1` (iface filter active) within
/// tolerance.
fn make_balanced_tsv(n_workers: u32, timestamps: &[u64], iface: &'static str) -> String {
    let counts = vec![1; n_workers as usize];
    make_distribution_tsv(&counts, timestamps, iface)
}

fn make_distribution_tsv(counts: &[u32], timestamps: &[u64], iface: &'static str) -> String {
    let mut rows: Vec<TsvRow> = Vec::new();
    for &ts in timestamps {
        for (w, &count) in counts.iter().enumerate() {
            rows.push(TsvRow {
                timestamp: ts,
                binding_slot: w as u32,
                queue_id: 0,
                worker_id: w as u32,
                iface,
                count,
            });
        }
    }
    synth_tsv_6col(&rows)
}

fn make_cos_distribution_tsv(
    counts: &[u32],
    timestamps: &[u64],
    ifindex: i32,
    queue_id: u32,
) -> String {
    let mut rows: Vec<CosTsvRow> = Vec::new();
    for &ts in timestamps {
        for (w, &count) in counts.iter().enumerate() {
            rows.push(CosTsvRow {
                timestamp: ts,
                ifindex,
                queue_id,
                worker_id: w as u32,
                count,
            });
        }
    }
    synth_cos_tsv_5col(&rows)
}
