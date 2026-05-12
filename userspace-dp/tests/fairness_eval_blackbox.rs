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

// ---------------------------------------------------------------------------
// Required-keys schema test.
// ---------------------------------------------------------------------------

/// Per v6 plan §3.4 the required-keys set is 10 fields. A rename of any
/// would be a contract break and must fail loudly. Verify on a PASS run.
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

    // The 10 required keys per v6 plan §3.4.
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
}

// ---------------------------------------------------------------------------
// 6 black-box cases.
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
    assert!(
        reasons.iter().any(|r| r.as_str().unwrap_or("").contains("Harness guard")),
        "failure_reasons must contain a Harness guard entry; got: {:?}",
        reasons
    );
}

#[test]
fn guard_low_n_legacy_input_accepts_p2_recency_undercount() {
    let tmp = TempGuard::new("guard_low_n");
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
        Some(0),
        "P=2 low-N recency undercount should stay inside the harness guard; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v = verdict.expect("verdict JSON on low-N PASS");
    assert_eq!(v["verdict"], "PASS");
    assert_eq!(v["a_i_sum_check_ok"], true);
    assert_eq!(v["a_i_sum"], 1);
    assert_eq!(v["iperf_non_starved_streams"], 2);
    assert_eq!(v["a_i_sum_tolerance"], 3);
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
    let mut rows: Vec<TsvRow> = Vec::new();
    for &ts in timestamps {
        for w in 0..n_workers {
            rows.push(TsvRow {
                timestamp: ts,
                binding_slot: w,
                queue_id: 0,
                worker_id: w,
                iface,
                count: 1, // sum across 6 workers = 6, matches 6 streams (1× single-direction)
            });
        }
    }
    synth_tsv_6col(&rows)
}
