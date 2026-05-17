# #1373 Phase 1/2 Smoke Gates

This runbook is the operator checklist for the #1373 Phase 1/2 smoke gates.
It uses the isolated userspace HA cluster on `loss` for userspace dataplane,
CoS, and HA traffic.

Prerequisite: #1401 or equivalent Makefile/env plumbing must be present before
running this runbook. Without that dependency, the HA Makefile gates and helper
scripts can still hard-code legacy instance names instead of honoring
`BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env`.

Do not run the final HA Makefile section until the operator has handed off the
cluster for destructive failover, crash, and restart testing.

## Common Setup

Run from the repo root:

```bash
cd /path/to/xpf
export BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
export ARTIFACT_ROOT="${ARTIFACT_ROOT:-/tmp/pr1373-smoke-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$ARTIFACT_ROOT"

run_loss_host() {
  local cmd=$1
  sg incus-admin -c "incus exec loss:cluster-userspace-host -- bash -lc $(printf '%q' "$cmd")"
}
```

Fresh deploys start CoS-off because `docs/ha-cluster-userspace.conf` has no
CoS fixture. If this is not a fresh deploy, redeploy before the CoS-off gate
or intentionally clear/reload the userspace cluster config first.

```bash
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" ./test/incus/cluster-setup.sh deploy all
./scripts/userspace-ha-validation.sh --env "$BPFRX_CLUSTER_ENV"
```

## Gate 1: CoS-Off IPv4/IPv6 Push And Reverse

This gate runs normal client push plus `iperf3 -R` for IPv4 and IPv6 from
`loss:cluster-userspace-host`. It stores raw iperf JSON and parsed collapse
metrics under `$ARTIFACT_ROOT/cos-off`.

```bash
set -euo pipefail
mkdir -p "$ARTIFACT_ROOT/cos-off"

PARALLEL="${PARALLEL:-6}"
DURATION="${DURATION:-10}"
IPERF_TIMEOUT="${IPERF_TIMEOUT:-$((DURATION + 15))}"
MIN_GBPS="${MIN_GBPS:-18.0}"
MAX_RETRANS="${MAX_RETRANS:-0}"
V4_TARGET="${V4_TARGET:-172.16.80.200}"
V6_TARGET="${V6_TARGET:-2001:559:8585:80::200}"

run_iperf_gate() {
  local label=$1
  local cmd=$2
  local json="$ARTIFACT_ROOT/cos-off/${label}.json"
  if ! run_loss_host "timeout -k 2 ${IPERF_TIMEOUT} ${cmd}" >"$json" 2>"${json%.json}.stderr"; then
    echo "FAIL ${label}: iperf command failed, see ${json%.json}.stderr" >&2
    return 1
  fi
  ./scripts/iperf-json-metrics.py "$json" | tee "${json%.json}.metrics.json"
}

run_iperf_gate v4-push "iperf3 -J --forceflush -c ${V4_TARGET} -P ${PARALLEL} -t ${DURATION}"
run_iperf_gate v4-reverse "iperf3 -J --forceflush -c ${V4_TARGET} -P ${PARALLEL} -t ${DURATION} -R"
run_iperf_gate v6-push "iperf3 -6 -J --forceflush -c ${V6_TARGET} -P ${PARALLEL} -t ${DURATION}"
run_iperf_gate v6-reverse "iperf3 -6 -J --forceflush -c ${V6_TARGET} -P ${PARALLEL} -t ${DURATION} -R"

python3 - "$ARTIFACT_ROOT/cos-off" "$MIN_GBPS" <<'PY'
import json
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
min_gbps = float(sys.argv[2])
max_retrans = int(os.environ.get("MAX_RETRANS", "0"))
failures = []
for path in sorted(root.glob("*.metrics.json")):
    metrics = json.loads(path.read_text(encoding="utf-8"))
    label = path.name.removesuffix(".metrics.json")
    avg = float(metrics.get("avg_gbps") or 0.0)
    if not metrics.get("ok"):
        failures.append(f"{label}: metrics parser error: {metrics.get('error')}")
    if not metrics.get("completed"):
        failures.append(f"{label}: iperf did not complete")
    if metrics.get("collapse_detected"):
        failures.append(f"{label}: collapse detected: {metrics.get('collapse_reason')}")
    if avg < min_gbps:
        failures.append(f"{label}: avg_gbps {avg:.3f} < {min_gbps:.3f}")
    retransmits = int(metrics.get("retransmits") or 0)
    if retransmits > max_retrans:
        failures.append(f"{label}: retransmits {retransmits} > {max_retrans}")
if failures:
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    raise SystemExit(1)
print(f"PASS cos-off v4/v6 push+reverse, min_gbps={min_gbps}, max_retrans={max_retrans}")
PY
```

## Gate 2: Screen/Flood Baseline

This gate proves the userspace cluster still exercises screen paths before BPF
retirement work proceeds. The userspace status path currently publishes an
aggregate `screen_drops` counter, so this gate isolates each configured check
instead of summing unrelated statistics: LAND-only, then SYN-flood-only, then
ICMP-flood-only. Each subcheck requires the aggregate counter to advance after
its matching probe. It always redeploys the baseline config on exit so the low
thresholds do not contaminate reruns or later CoS measurements.

This is not the #1374 SYN-cookie proof. SYN-cookie runtime integration remains
tracked by #1374; BPF retirement remains blocked until the SYN-cookie issue
adds its own runtime gate. This section covers the LAND, SYN-flood, and
ICMP-flood screen plumbing that already exists in userspace.

```bash
set -euo pipefail
mkdir -p "$ARTIFACT_ROOT/screen-flood"

PRIMARY_FW="${PRIMARY_FW:-xpf-userspace-fw0}"
SCREEN_RESTORE_NEEDED=0
cleanup_screen_gate() {
  if [[ "$SCREEN_RESTORE_NEEDED" -eq 1 ]]; then
    BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" ./test/incus/cluster-setup.sh deploy all \
      >"$ARTIFACT_ROOT/screen-flood/restore.stdout" \
      2>"$ARTIFACT_ROOT/screen-flood/restore.stderr" || true
  fi
}
trap cleanup_screen_gate EXIT

apply_screen_profile() {
  local label=$1
  local profile=$2
  local commands=$3
  sg incus-admin -c "incus exec loss:${PRIMARY_FW} -- cli" \
    >"$ARTIFACT_ROOT/screen-flood/${label}-configure.stdout" \
    2>"$ARTIFACT_ROOT/screen-flood/${label}-configure.stderr" <<EOF
configure
set security zones security-zone lan screen ${profile}
${commands}
commit
exit
EOF
  SCREEN_RESTORE_NEEDED=1
}

capture_screen_total() {
  local label=$1
  local out="$ARTIFACT_ROOT/screen-flood/${label}.txt"
  sg incus-admin -c "incus exec loss:${PRIMARY_FW} -- cli -c 'show security screen'" >"$out"
  python3 - "$out" <<'PY'
import pathlib
import re
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
match = re.search(r"Total screen drops:\s*(\d+)", text)
if not match:
    print("FAIL missing Total screen drops in show security screen output", file=sys.stderr)
    raise SystemExit(1)
print(match.group(1))
PY
}

assert_advanced() {
  local label=$1
  local before=$2
  local after=$3
  if (( after <= before )); then
    echo "FAIL ${label}: screen_drops did not advance: before=${before} after=${after}" >&2
    return 1
  fi
  echo "PASS ${label}: screen_drops advanced: before=${before} after=${after}"
}

send_land_probe() {
  run_loss_host 'set -euo pipefail
python3 - <<'"'"'PY'"'"'
import socket
import struct

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total) & 0xffff

src = dst = "172.16.50.1"
sport = dport = 65000
payload = b""
src_b = socket.inet_aton(src)
dst_b = socket.inet_aton(dst)
tcp = struct.pack("!HHLLBBHHH", sport, dport, 1, 0, 5 << 4, 0x02, 64240, 0, 0)
pseudo = src_b + dst_b + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp) + len(payload))
tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0x1373, 0, 64, socket.IPPROTO_TCP, 0, src_b, dst_b)
ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
packet = ip + tcp + payload
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for _ in range(5):
    sock.sendto(packet, (dst, 0))
PY'
}

apply_screen_profile land pr1373-land 'set security screen ids-option pr1373-land tcp land'
land_before=$(capture_screen_total land-before)
send_land_probe
land_after=$(capture_screen_total land-after)
assert_advanced LAND "$land_before" "$land_after"

apply_screen_profile syn pr1373-syn 'set security screen ids-option pr1373-syn tcp syn-flood attack-threshold 1
set security screen ids-option pr1373-syn tcp syn-flood source-threshold 1
set security screen ids-option pr1373-syn tcp syn-flood destination-threshold 1'
syn_before=$(capture_screen_total syn-before)
run_loss_host 'set -euo pipefail
for i in $(seq 1 80); do timeout 1 bash -lc "exec 3<>/dev/tcp/172.16.50.1/65000" >/dev/null 2>&1 || true; done'
syn_after=$(capture_screen_total syn-after)
assert_advanced SYN-flood "$syn_before" "$syn_after"

apply_screen_profile icmp pr1373-icmp 'set security screen ids-option pr1373-icmp icmp flood threshold 1'
icmp_before=$(capture_screen_total icmp-before)
run_loss_host 'set -euo pipefail
for i in $(seq 1 80); do ping -c 1 -W 1 172.16.50.1 >/dev/null 2>&1 || true; done'
icmp_after=$(capture_screen_total icmp-after)
assert_advanced ICMP-flood "$icmp_before" "$icmp_after"

BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" ./test/incus/cluster-setup.sh deploy all
SCREEN_RESTORE_NEEDED=0
trap - EXIT
```

The raw-socket packet uses source IP == destination IP and source port ==
destination port, matching the userspace LAND predicate. If the host cannot
open a raw socket, the LAND subcheck fails instead of silently treating LAND as
covered.

## Gate 3: CoS-On Per-Class 5200-5211

Apply the symmetric CoS fixture so reverse iperf traffic is classified by
source port on the LAN egress. The class sweep uses the existing fairness
harness and preserves per-class artifacts.

```bash
sg incus-admin -c "./test/incus/apply-cos-config.sh --symmetric loss:xpf-userspace-fw0" \
  >"$ARTIFACT_ROOT/apply-cos-symmetric.stdout" \
  2>"$ARTIFACT_ROOT/apply-cos-symmetric.stderr"

COS_IFINDEX_FORWARD="$(
  sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cat /run/xpf/userspace-dp.json" \
    | jq -r '(.cos_interfaces // [])[] | select(.interface_name == "reth0.80") | .ifindex' \
    | head -n1
)"
: "${COS_IFINDEX_FORWARD:?failed to detect reth0.80 CoS ifindex}"

COS_IFINDEX_REVERSE="$(
  sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- cat /run/xpf/userspace-dp.json" \
    | jq -r '(.cos_interfaces // [])[] | select(.interface_name == "ge-0-0-1" or .interface_name == "ge-0-0-1.0") | .ifindex' \
    | head -n1
)"
: "${COS_IFINDEX_REVERSE:?failed to detect ge-0-0-1 reverse CoS ifindex}"

export IPERF_LAUNCH_ARG_0=/usr/bin/incus
export IPERF_LAUNCH_ARG_1=exec
export IPERF_LAUNCH_ARG_2=loss:cluster-userspace-host
export IPERF_LAUNCH_ARG_3=--
export METRICS_URL="${METRICS_URL:-http://127.0.0.1:8080/metrics}"

ARTIFACT_ROOT="$ARTIFACT_ROOT/cos-on-5200-5211-push" \
COS_IFINDEX="$COS_IFINDEX_FORWARD" \
IFACE=ge-0-0-2 \
REVERSE= \
./test/incus/fairness-cos-class-sweep.sh

ARTIFACT_ROOT="$ARTIFACT_ROOT/cos-on-5200-5211-reverse" \
COS_IFINDEX="$COS_IFINDEX_REVERSE" \
IFACE=ge-0-0-1 \
REVERSE=-R \
./test/incus/fairness-cos-class-sweep.sh
```

For a rehearsal that is not the gate, set `SAMPLES=1 DURATION=45` before the
two sweep commands. Do not use that shortened run as the Phase 1/2 gate.

## Gate 4: CoS-On TCP Echo 6200-6211

This checks that the TCP echo service for each CoS class accepts a connection
through the userspace dataplane and returns the payload.

```bash
set -euo pipefail
mkdir -p "$ARTIFACT_ROOT/echo-6200-6211"
SUMMARY_TSV="$ARTIFACT_ROOT/echo-6200-6211/summary.tsv"
: >"$SUMMARY_TSV"
failed=0
for port in $(seq 6200 6211); do
  payload="pr1373-${port}"
  if run_loss_host "timeout 4 bash -lc 'payload=${payload}; exec 3<>/dev/tcp/172.16.80.200/${port}; printf %s \"\$payload\" >&3; IFS= read -r -N \${#payload} reply <&3; [[ \"\$reply\" == \"\$payload\" ]]'" \
    >"$ARTIFACT_ROOT/echo-6200-6211/${port}.stdout" \
    2>"$ARTIFACT_ROOT/echo-6200-6211/${port}.stderr"; then
    printf '%s\tPASS\n' "$port" | tee -a "$SUMMARY_TSV"
  else
    printf '%s\tFAIL\n' "$port" | tee -a "$SUMMARY_TSV"
    failed=1
  fi
done
test "$failed" -eq 0
```

## Gate 5: Deploy And Steady-State Userspace Readiness

This gate exercises the canonical deploy/readiness, router-advertisement,
ping, iperf, and collapse-detection validation suite. The validator may pin RG
ownership before the steady-state checks, but it is not the low-latency
failover/failback flow-survival proof. Treat any validator failure, collapse
detection, or unexplained retransmit warning as a stop-the-line artifact to
triage before BPF retirement proceeds.

```bash
set -euo pipefail
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" ./scripts/userspace-phase-cycle.sh \
  2>&1 | tee "$ARTIFACT_ROOT/userspace-phase-cycle.log"
```

When performance evidence is needed, run the stricter profiling variant as a
separate artifact set:

```bash
set -euo pipefail
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" ./scripts/userspace-phase-cycle.sh --perf \
  2>&1 | tee "$ARTIFACT_ROOT/userspace-phase-cycle-perf.log"
```

## Gate 6: RG-Movement HA Failover Acceptance

This is the stricter HA failover gate. It runs traffic through explicit RG
movement and validates flow survival across failover/failback windows. The
script's defaults are intentionally broader than a literal 60 ms / 0-loss SLA;
for BPF retirement evidence, pin the strict loss/retransmit knobs in the
artifact command line and archive the full artifact directory.

```bash
set -euo pipefail
ARTIFACT_DIR="$ARTIFACT_ROOT/userspace-ha-failover" \
TOTAL_CYCLES=2 \
MAX_ZERO_INTERVALS=0 \
MAX_STREAM_ZERO_INTERVALS=0 \
MAX_RETRANSMITS=0 \
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" ./scripts/userspace-ha-failover-validation.sh \
  2>&1 | tee "$ARTIFACT_ROOT/userspace-ha-failover.log"
```

## Gate 7: Existing HA Makefile Gates

These gates are destructive. They reboot, force-stop, fail over, or restart
cluster services. Run only after explicit operator handoff.

These are regression add-ons, not the strict HA acceptance gate. The validation
report must preserve each script log and call out any packet-loss or
takeover-time warnings separately. Cite Gate 6, not this section, as the
userspace HA acceptance proof.

```bash
set -euo pipefail
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" make test-failover \
  2>&1 | tee "$ARTIFACT_ROOT/ha-test-failover.log"
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" make test-ha-crash \
  2>&1 | tee "$ARTIFACT_ROOT/ha-test-ha-crash.log"
BPFRX_CLUSTER_ENV="$BPFRX_CLUSTER_ENV" make test-restart-connectivity \
  2>&1 | tee "$ARTIFACT_ROOT/ha-test-restart-connectivity.log"
```

Record the final `git rev-parse HEAD`, `$ARTIFACT_ROOT`, and the exit status
of every command in the validation report.
