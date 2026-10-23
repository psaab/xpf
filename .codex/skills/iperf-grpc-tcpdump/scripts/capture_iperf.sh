#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: capture_iperf.sh --family 4|6 [options]

Options:
  --family 4|6              Address family to test. Required.
  --parallel N              iperf3 parallel streams. Default: 1
  --duration SEC            iperf3 duration / server capture duration. Default: 5
  --cport PORT              Optional fixed client port for iperf3.
  --target IP               Override target. Default: 172.16.80.200 or 2001:559:8585:80::200
  --bpf-filter EXPR         Capture filter. Default: port 5201
  --artifact-dir DIR        Output directory. Default: /tmp/iperf-grpc-tcpdump-<timestamp>
  --capture-server HOST:PORT
                            gRPC capture endpoint. Default: 172.16.80.200:50051
  --capture-interface IFACE Server-side capture interface. Default: eth0
  --client INSTANCE         Client instance. Default: cluster-userspace-host
  --fw0 INSTANCE            Firewall node0 instance. Default: xpf-userspace-fw0
  --fw1 INSTANCE            Firewall node1 instance. Default: xpf-userspace-fw1
  --project NAME            Incus project/prefix. Default: loss
  --help                    Show this help.
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

vm_is_primary() {
  local project="$1"
  local vm="$2"
  local output node
  output=$(incus exec "${project}:${vm}" -- cli -c "show chassis cluster status" 2>/dev/null || true)
  node=$(awk '/^Node name:/ {print $3; exit}' <<<"$output")
  [[ -n "$node" ]] || return 1
  awk -v node="$node" '$1 == node && $3 == "primary" { found=1 } END { exit(found ? 0 : 1) }' <<<"$output"
}

detect_active_fw() {
  local project="$1" fw0="$2" fw1="$3"
  if vm_is_primary "$project" "$fw0"; then
    printf '%s\n' "$fw0"
    return 0
  fi
  if vm_is_primary "$project" "$fw1"; then
    printf '%s\n' "$fw1"
    return 0
  fi
  return 1
}

fw_ifaces() {
  local fw="$1"
  case "$fw" in
    *fw0) printf 'ge-0-0-1 ge-0-0-2\n' ;;
    *fw1) printf 'ge-7-0-1 ge-7-0-2\n' ;;
    *)
      echo "unknown firewall naming for $fw" >&2
      return 1
      ;;
  esac
}

json_summary() {
  local json="$1"
  python3 - "$json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    data = json.load(f)
err = data.get("error")
if err:
    print(f"error={err}")
    sys.exit(0)
end = data.get("end", {})
sent = (((end.get("sum_sent") or {}).get("bits_per_second")) or 0.0) / 1e9
retr = (end.get("sum_sent") or {}).get("retransmits")
intervals = []
for interval in data.get("intervals", []):
    summary = interval.get("sum", {})
    bps = (summary.get("bits_per_second") or 0.0) / 1e9
    intervals.append(bps)
print(f"throughput_gbps={sent:.3f}")
print(f"retransmits={retr}")
if intervals:
    print("interval_gbps=" + ",".join(f"{v:.3f}" for v in intervals))
    print(f"peak_interval_gbps={max(intervals):.3f}")
    print(f"tail_interval_gbps={intervals[-1]:.3f}")
PY
}

FAMILY=""
PARALLEL=1
DURATION=5
CPORT=""
TARGET=""
BPF_FILTER="port 5201"
ARTIFACT_DIR=""
CAPTURE_SERVER="172.16.80.200:50051"
CAPTURE_INTERFACE="eth0"
CLIENT_VM="cluster-userspace-host"
FW0_VM="xpf-userspace-fw0"
FW1_VM="xpf-userspace-fw1"
PROJECT="loss"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --family) FAMILY="${2:-}"; shift 2 ;;
    --parallel) PARALLEL="${2:-}"; shift 2 ;;
    --duration) DURATION="${2:-}"; shift 2 ;;
    --cport) CPORT="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --bpf-filter) BPF_FILTER="${2:-}"; shift 2 ;;
    --artifact-dir) ARTIFACT_DIR="${2:-}"; shift 2 ;;
    --capture-server) CAPTURE_SERVER="${2:-}"; shift 2 ;;
    --capture-interface) CAPTURE_INTERFACE="${2:-}"; shift 2 ;;
    --client) CLIENT_VM="${2:-}"; shift 2 ;;
    --fw0) FW0_VM="${2:-}"; shift 2 ;;
    --fw1) FW1_VM="${2:-}"; shift 2 ;;
    --project) PROJECT="${2:-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$FAMILY" == "4" || "$FAMILY" == "6" ]] || {
  echo "--family 4|6 is required" >&2
  usage >&2
  exit 2
}

require_cmd grpcurl
require_cmd incus
require_cmd iperf3
require_cmd python3

if [[ -z "$TARGET" ]]; then
  if [[ "$FAMILY" == "4" ]]; then
    TARGET="172.16.80.200"
  else
    TARGET="2001:559:8585:80::200"
  fi
fi

if [[ -z "$ARTIFACT_DIR" ]]; then
  ARTIFACT_DIR="/tmp/iperf-grpc-tcpdump-$(date +%Y%m%d-%H%M%S)-v${FAMILY}"
fi
mkdir -p "$ARTIFACT_DIR"

ACTIVE_FW=$(detect_active_fw "$PROJECT" "$FW0_VM" "$FW1_VM") || {
  echo "failed to detect active firewall" >&2
  exit 1
}
read -r FW_LAN_IF FW_WAN_IF < <(fw_ifaces "$ACTIVE_FW")

FW_STATS_BEFORE="$ARTIFACT_DIR/fw-stats-before.txt"
FW_STATS_AFTER="$ARTIFACT_DIR/fw-stats-after.txt"
FW_LAN_OUT="$ARTIFACT_DIR/fw-lan.txt"
FW_WAN_OUT="$ARTIFACT_DIR/fw-wan.txt"
SERVER_OUT="$ARTIFACT_DIR/server-grpc.txt"
IPERF_JSON="$ARTIFACT_DIR/iperf.json"
SUMMARY="$ARTIFACT_DIR/summary.txt"

cleanup() {
  local pids=("${CAP_PID:-}" "${LAN_PID:-}" "${WAN_PID:-}")
  for pid in "${pids[@]}"; do
    [[ -n "$pid" ]] || continue
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

incus exec "${PROJECT}:${ACTIVE_FW}" -- cli -c 'show chassis cluster data-plane statistics' >"$FW_STATS_BEFORE"

(
  timeout "$((DURATION + 5))" grpcurl -insecure -d "{
    \"bpf_filter\": \"${BPF_FILTER//\"/\\\"}\",
    \"interface\": \"${CAPTURE_INTERFACE}\",
    \"duration_seconds\": ${DURATION},
    \"text_output\": true,
    \"no_resolve\": true,
    \"verbosity\": 1
  }" "${CAPTURE_SERVER}" capture.CaptureService/StartCapture
) >"$SERVER_OUT" 2>&1 &
CAP_PID=$!

(
  incus exec "${PROJECT}:${ACTIVE_FW}" -- sh -lc "timeout $((DURATION + 2)) tcpdump -ni ${FW_LAN_IF} '${BPF_FILTER}' -nn -tttt"
) >"$FW_LAN_OUT" 2>&1 &
LAN_PID=$!

(
  incus exec "${PROJECT}:${ACTIVE_FW}" -- sh -lc "timeout $((DURATION + 2)) tcpdump -ni ${FW_WAN_IF} '${BPF_FILTER}' -nn -tttt"
) >"$FW_WAN_OUT" 2>&1 &
WAN_PID=$!

sleep 1

IPERF_CMD=(iperf3 "-c" "$TARGET" "-P" "$PARALLEL" "-t" "$DURATION" "-J")
if [[ "$FAMILY" == "6" ]]; then
  IPERF_CMD=("${IPERF_CMD[@]:0:1}" "-6" "${IPERF_CMD[@]:1}")
fi
if [[ -n "$CPORT" ]]; then
  IPERF_CMD+=("--cport" "$CPORT")
fi

if ! incus exec "${PROJECT}:${CLIENT_VM}" -- "${IPERF_CMD[@]}" >"$IPERF_JSON" 2>&1; then
  true
fi

wait "$CAP_PID" || true
wait "$LAN_PID" || true
wait "$WAN_PID" || true

incus exec "${PROJECT}:${ACTIVE_FW}" -- cli -c 'show chassis cluster data-plane statistics' >"$FW_STATS_AFTER"

{
  echo "artifacts=$ARTIFACT_DIR"
  echo "active_firewall=$ACTIVE_FW"
  echo "firewall_lan_if=$FW_LAN_IF"
  echo "firewall_wan_if=$FW_WAN_IF"
  echo "firewall_tcpdump_note=fw-lan.txt/fw-wan.txt are in-VM tcpdump and blind to AF_XDP fast-path flows (#16111); empty files do not prove the flow was absent - use server-grpc.txt plus fw-stats deltas"
  echo "client=${PROJECT}:${CLIENT_VM}"
  echo "target=$TARGET"
  echo "family=$FAMILY"
  echo "parallel=$PARALLEL"
  echo "duration=$DURATION"
  [[ -n "$CPORT" ]] && echo "cport=$CPORT"
  json_summary "$IPERF_JSON"
} | tee "$SUMMARY"
