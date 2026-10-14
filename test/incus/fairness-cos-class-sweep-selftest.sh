#!/usr/bin/env bash
#
# #11769 — hermetic self-test for test/incus/fairness-cos-class-sweep.sh.
#
# The harness is a live-cluster GATE: every class sample drives real
# traffic through the shared loss cluster and scrapes the live daemon's
# Prometheus endpoint. Those measurement legs are LAB-ONLY and are
# deliberately NOT faked here — nothing in this file claims a fairness
# number about real hardware. What CAN be exercised without a cluster is
# the whole per-class pipeline, driven end-to-end through the real sweep:
#
#   fairness_multi_sample.py (real) → fairness-harness.sh (real, with a
#   fixture IPERF_BIN and a stub metrics endpoint on loopback) → the REAL
#   fairness-eval Rust binary → fairness_equal_flow_capture.py (real,
#   over the stub endpoint's scrapes) → the jq summary aggregation.
#
#   1. A fair fixture (equal per-stream rates, honest per-worker flow
#      counts) must sweep its class to verdict PASS and exit 0.
#   2. A skewed fixture (per-stream rates spanning ~8x) must FAIL the
#      multi-sample gap contract and exit 1 — proving the gate can fail,
#      so a pass means something.
#   3. The lab-only skip pattern: on a host with no incus, the sweep
#      SKIPs (exit 77) with the reason instead of running a sweep whose
#      dataplane legs all error out.
#
# The real fairness-eval binary is required (it is the SSOT contract); if
# it is not built the self-test SKIPs with the exact build command —
# `make test-cos-fairness-gates-lib` builds it first.
#
# Hermetic apart from a loopback listen for the stub metrics endpoint: no
# cluster, no external network, no traffic.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SUBJECT="${SCRIPT_DIR}/fairness-cos-class-sweep.sh"
TMP="$(mktemp -d)"
METRICS_PID=""
cleanup() {
  [ -n "$METRICS_PID" ] && kill "$METRICS_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT
fails=0

fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

# --- the real fairness-eval, or an honest skip ---------------------------
FAIRNESS_EVAL="${FAIRNESS_EVAL:-${ROOT}/userspace-dp/target/release/fairness-eval}"
if [[ ! -x "$FAIRNESS_EVAL" ]]; then
  for c in /dev/shm/cargo/release/fairness-eval "${ROOT}/target/release/fairness-eval"; do
    if [ -x "$c" ]; then FAIRNESS_EVAL="$c"; break; fi
  done
fi
if [[ ! -x "$FAIRNESS_EVAL" ]]; then
  echo "SKIP: fairness-eval is not built — run 'cargo build --manifest-path userspace-dp/Cargo.toml --release --bin fairness-eval' (or make test-cos-fairness-gates-lib) before the sweep self-test (#11769)"
  exit 77
fi

# --- stub metrics endpoint (loopback) -------------------------------------
# Serves the binding/CoS active-flow rows the harness scrapes (12 flows
# over 2 workers for the default N=12) plus the equal-flow estimator rows
# the sweep's capture leg reduces. IFINDEX 9 / queue 2 / iface ge-0-0-2
# match the class the self-test selects.
python3 - "$TMP/metrics.port" <<'SERVE' &
import http.server, sys, socketserver

port_file = sys.argv[1]
IFACE, IFINDEX, QUEUE = "ge-0-0-2", "9", "2"
BODY = (
    "# HELP xpf_userspace_binding_active_flow_count flows\n"
    "# TYPE xpf_userspace_binding_active_flow_count gauge\n"
    f'xpf_userspace_binding_active_flow_count{{binding_slot="0",iface="{IFACE}",queue_id="{QUEUE}",worker_id="0"}} 6\n'
    f'xpf_userspace_binding_active_flow_count{{binding_slot="1",iface="{IFACE}",queue_id="{QUEUE}",worker_id="1"}} 6\n'
    "# HELP xpf_userspace_cos_active_flow_count cos flows\n"
    "# TYPE xpf_userspace_cos_active_flow_count gauge\n"
    f'xpf_userspace_cos_active_flow_count{{ifindex="{IFINDEX}",queue_id="{QUEUE}",worker_id="0"}} 6\n'
    f'xpf_userspace_cos_active_flow_count{{ifindex="{IFINDEX}",queue_id="{QUEUE}",worker_id="1"}} 6\n'
    "# HELP xpf_fairness_equal_flow_estimate_valid valid\n"
    f'xpf_fairness_equal_flow_estimate_valid{{ifindex="{IFINDEX}",queue_id="{QUEUE}"}} 1\n'
    f'xpf_fairness_equal_flow_sampled_active_workers{{ifindex="{IFINDEX}",queue_id="{QUEUE}"}} 2\n'
    f'xpf_fairness_equal_flow_unsampled_active_workers{{ifindex="{IFINDEX}",queue_id="{QUEUE}"}} 0\n'
    f'xpf_fairness_equal_flow_target_per_flow_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}"}} 83000000\n'
    f'xpf_fairness_equal_flow_observed_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}"}} 1000000000\n'
    f'xpf_fairness_equal_flow_capped_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}"}} 1000000000\n'
    f'xpf_fairness_equal_flow_suppressed_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}"}} 0\n'
    f'xpf_fairness_equal_flow_throughput_loss_ratio{{ifindex="{IFINDEX}",queue_id="{QUEUE}"}} 0\n'
    "# HELP xpf_fairness_equal_flow_worker_observed_bps w\n"
    f'xpf_fairness_equal_flow_worker_observed_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}",worker_id="0"}} 500000000\n'
    f'xpf_fairness_equal_flow_worker_observed_per_flow_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}",worker_id="0"}} 83000000\n'
    f'xpf_fairness_equal_flow_worker_cap_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}",worker_id="0"}} 500000000\n'
    f'xpf_fairness_equal_flow_worker_suppressed_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}",worker_id="0"}} 0\n'
    f'xpf_fairness_equal_flow_worker_observed_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}",worker_id="1"}} 500000000\n'
    f'xpf_fairness_equal_flow_worker_observed_per_flow_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}",worker_id="1"}} 83000000\n'
    f'xpf_fairness_equal_flow_worker_cap_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}",worker_id="1"}} 500000000\n'
    f'xpf_fairness_equal_flow_worker_suppressed_bps{{ifindex="{IFINDEX}",queue_id="{QUEUE}",worker_id="1"}} 0\n'
).encode()


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a):
        pass


class S(socketserver.TCPServer):
    allow_reuse_address = True


srv = S(("127.0.0.1", 0), H)
with open(port_file, "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
SERVE
METRICS_PID=$!
for _ in $(seq 1 50); do
  [ -s "${TMP}/metrics.port" ] && break
  sleep 0.1
done
METRICS_URL="http://127.0.0.1:$(cat "${TMP}/metrics.port")/metrics"

# --- fixture generator (IPERF_BIN) ----------------------------------------
# Occupies 4s of wall time (so the scrape loops and the equal-flow
# estimator window see real samples), timestamps its start like a real
# iperf3, and emits FAKE_SWEEP_INTERVALS one-second intervals. With
# FAKE_SKEW=1 the per-stream rates span ~8x, which must break the gap
# contract.
cat > "${TMP}/iperf3" <<'FIXTURE_IPERF'
#!/usr/bin/env bash
args=("$@")
port=5202; streams=12; dur=65
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    -p) port="${args[$((i + 1))]}" ;;
    -P) streams="${args[$((i + 1))]}" ;;
    -t) dur="${args[$((i + 1))]}" ;;
  esac
done
gbps="${FAKE_SWEEP_GBPS:-1}"
start_ts=$(date +%s)
sleep "${FAKE_SWEEP_WALL_SECS:-4}"
python3 - "$port" "$streams" "$dur" "$gbps" "$start_ts" <<'PY'
import json, os, sys
port, streams, dur, gbps, start_ts = (int(sys.argv[1]), int(sys.argv[2]),
                                      int(sys.argv[3]), float(sys.argv[4]),
                                      int(sys.argv[5]))
total = gbps * 1e9
weights = [(2.0 ** i) for i in range(streams)] if os.environ.get("FAKE_SKEW") == "1" \
    else [1.0] * streams
norm = sum(weights)
rates = [total * w / norm for w in weights]
intervals = [{"streams": [{"socket": s, "start": float(i), "end": float(i + 1),
                           "bits_per_second": rates[s]} for s in range(streams)],
              "sum": {"omitted": False}} for i in range(max(dur, 1))]
print(json.dumps({
    "start": {"connected": [{"socket": s, "remote_port": port} for s in range(streams)],
              "timestamp": {"timesecs": start_ts},
              "test_start": {"protocol": "TCP", "num_streams": streams,
                             "duration": dur, "reverse": 1}},
    "intervals": intervals,
    "end": {"streams": [{"socket": s, "sender": {"bits_per_second": rates[s],
                                                 "retransmits": 0}} for s in range(streams)],
            "sum_sent": {"bits_per_second": total, "retransmits": 0},
            "sum_received": {"bits_per_second": total, "retransmits": 0},
            "sum": {"bits_per_second": total, "retransmits": 0},
            "cpu_utilization_percent": {"host_total": 5.0}},
}))
PY
exit 0
FIXTURE_IPERF
chmod +x "${TMP}/iperf3"

# --- stub incus (dataplane capture legs only) -------------------------------
mkdir -p "${TMP}/bin"
cat > "${TMP}/bin/incus" <<'STUB_INCUS'
#!/usr/bin/env bash
[ "$1" = "exec" ] || exit 0
shift
HOST="$1"; shift
[ "$1" = "--" ] && shift
case "$1" in
  sh|bash)
    script="$3"
    case "$script" in
      *journalctl*)
        printf 'Oct 14 10:00:00 fw0 xpfd[1]: startup\n'
        exit 0 ;;
      *"show chassis cluster data-plane statistics"*)
        printf 'Data plane statistics:\n    Enabled:            true\n    Forwarding supported: true\n    HA groups:          rg0 active=true rg1 active=true\n'
        exit 0 ;;
      *userspace-dp.json*)
        cat "${BE_MOCK_DP_STATUS:?}"
        exit 0 ;;
      *) exit 0 ;;
    esac ;;
  *) exit 0 ;;
esac
STUB_INCUS
chmod +x "${TMP}/bin/incus"

# Static dataplane status: counters identical in every snapshot, so the
# sweep's before/after deltas are all zero and no error is marked.
DP_STATUS="${TMP}/dp-status.json"
cat > "$DP_STATUS" <<'STATUS'
{
  "status": {
    "bindings": [
      {"iface": "ge-0-0-2", "tx_errors": 0}
    ],
    "cos_interfaces": [
      {
        "interface_name": "reth0.80",
        "ifindex": 9,
        "queues": [
          {"queue_id": 2, "forwarding_class": "iperf-1g",
           "drain_sent_bytes": 2000, "drain_park_root_tokens": 30,
           "drain_park_queue_tokens": 30, "tx_errors": 0}
        ]
      }
    ]
  }
}
STATUS

run_subject() { # run_subject <out-prefix> — echoes rc
  local out="$1"
  BE_MOCK_DP_STATUS="$DP_STATUS" \
  COS_IFINDEX=9 \
  CLASS_FILTER=q2-iperf-1g \
  SAMPLES=2 \
  SAMPLE_COOLDOWN_SEC=0 \
  WARMUP=0 \
  FINAL_BURST=0 \
  EQUAL_FLOW_ESTIMATOR_WINDOW_SECS=3 \
  DURATION=65 \
  METRICS_URL="$METRICS_URL" \
  FAIRNESS_EVAL="$FAIRNESS_EVAL" \
  ARTIFACT_ROOT="${TMP}/art-$out" \
  IPERF_BIN="${TMP}/iperf3" \
  N_WORKERS=2 \
  PATH="${TMP}/bin:$PATH" \
  bash "$SUBJECT" > "${TMP}/out-$out.txt" 2>&1
  echo $?
}

# --- 1. fair fixture: class sweeps to PASS ---------------------------------
unset FAKE_SKEW
rc="$(run_subject fair)"
row="$(tail -n +2 "${TMP}/art-fair/summary.tsv" 2>/dev/null | head -1)"
if [[ "$rc" = "0" ]] && grep -q "q2-iperf-1g" <<<"$row" \
  && awk -F'\t' '{exit !($6 == "PASS")}' <<<"$row"; then
  pass "fair fixture sweeps q2-iperf-1g to verdict PASS (exit 0)"
else
  fail "fair fixture must exit 0 with a PASS row; got rc=$rc row='$row'
$(sed -n '1,25p' "${TMP}/out-fair.txt")"
fi

# --- 2. skewed fixture: the gap contract must FAIL --------------------------
export FAKE_SKEW=1
rc="$(run_subject skewed)"
row="$(tail -n +2 "${TMP}/art-skewed/summary.tsv" 2>/dev/null | head -1)"
if [[ "$rc" = "1" ]] && awk -F'\t' '{exit !($6 == "FAIL")}' <<<"$row"; then
  pass "8x-skewed streams fail the multi-sample gap contract (exit 1)"
else
  fail "a skewed fixture must exit 1 with a FAIL row; got rc=$rc row='$row'
$(sed -n '1,25p' "${TMP}/out-skewed.txt")"
fi
unset FAKE_SKEW

# --- 3. lab-only legs: no incus → SKIP 77 with the reason -------------------
mkdir -p "${TMP}/nocluster"
for b in bash sh dirname mkdir date cat grep sed awk jq python3 curl timeout; do
  ln -sf "$(command -v "$b")" "${TMP}/nocluster/$b" 2>/dev/null || true
done
BE_MOCK_DP_STATUS="$DP_STATUS" \
  COS_IFINDEX=9 \
  CLASS_FILTER=q2-iperf-1g \
  ARTIFACT_ROOT="${TMP}/art-skip" \
  PATH="${TMP}/nocluster" \
  bash "$SUBJECT" > "${TMP}/out-skip.txt" 2>&1
rc=$?
if [[ "$rc" = "77" ]] && grep -q "SKIP: incus not found" "${TMP}/out-skip.txt" \
  && grep -q "lab-only (#11769)" "${TMP}/out-skip.txt"; then
  pass "no-incus host SKIPs (exit 77) with the lab-only reason"
else
  fail "no-incus host must SKIP 77 with the lab-only reason; got rc=$rc
$(cat "${TMP}/out-skip.txt")"
fi

# --- summary ----------------------------------------------------------------
if [[ $fails -eq 0 ]]; then
  echo "fairness-cos-class-sweep-selftest: all checks passed"
  exit 0
fi
echo "fairness-cos-class-sweep-selftest: ${fails} check(s) FAILED" >&2
exit 1
