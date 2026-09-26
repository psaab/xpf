#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IPERF_METRICS="${PROJECT_ROOT}/scripts/iperf-json-metrics.py"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"
RG="${RG:-1}"
SOURCE_NODE="${SOURCE_NODE:-0}"
TARGET_NODE="${TARGET_NODE:-1}"
IPERF_TARGET="${IPERF_TARGET:-172.16.80.200}"
EXTERNAL_V4_TARGET="${EXTERNAL_V4_TARGET:-1.1.1.1}"
EXTERNAL_V6_TARGET="${EXTERNAL_V6_TARGET:-2606:4700:4700::1111}"
EXTERNAL_PING_COUNT="${EXTERNAL_PING_COUNT:-4}"
CHECK_EXTERNAL_REACHABILITY="${CHECK_EXTERNAL_REACHABILITY:-1}"
TOTAL_CYCLES="${TOTAL_CYCLES:-1}"
CYCLE_INTERVAL="${CYCLE_INTERVAL:-10}"
SYNC_WAIT="${SYNC_WAIT:-5}"
FAILOVER_WAIT="${FAILOVER_WAIT:-30}"
PRE_FAILOVER_OBSERVE="${PRE_FAILOVER_OBSERVE:-10}"
if [[ -z "${IPERF_DURATION:-}" ]]; then
	if (( TOTAL_CYCLES > 1 )); then
		IPERF_DURATION="$(( PRE_FAILOVER_OBSERVE + SYNC_WAIT + TOTAL_CYCLES * (CYCLE_INTERVAL * 2 + FAILOVER_WAIT) + 20 ))"
	else
		IPERF_DURATION=60
	fi
fi
IPERF_STREAMS="${IPERF_STREAMS:-4}"
MIN_SESSIONS="${MIN_SESSIONS:-4}"
CHECK_KERNEL_SESSION_TABLE="${CHECK_KERNEL_SESSION_TABLE:-0}"
SESSION_SYNC_IDLE_TIMEOUT="${SESSION_SYNC_IDLE_TIMEOUT:-30}"
SESSION_SYNC_IDLE_STABLE_SAMPLES="${SESSION_SYNC_IDLE_STABLE_SAMPLES:-3}"
MIN_THROUGHPUT="${MIN_THROUGHPUT:-1.0}"
MAX_ZERO_INTERVALS="${MAX_ZERO_INTERVALS:-2}"
MAX_STREAM_ZERO_INTERVALS="${MAX_STREAM_ZERO_INTERVALS:-0}"
MAX_PREFLIGHT_ZERO_INTERVALS="${MAX_PREFLIGHT_ZERO_INTERVALS:-0}"
MAX_PREFLIGHT_STREAM_ZERO_INTERVALS="${MAX_PREFLIGHT_STREAM_ZERO_INTERVALS:-0}"
REQUIRE_FABRIC_ACTIVITY="${REQUIRE_FABRIC_ACTIVITY:-1}"
REQUIRE_STANDBY_READY="${REQUIRE_STANDBY_READY:-1}"
MIN_FABRIC_TX_DELTA="${MIN_FABRIC_TX_DELTA:-1}"
FABRIC_ACTIVITY_TRIGGER_DELTA="${FABRIC_ACTIVITY_TRIGGER_DELTA:-8}"
MAX_FAILOVER_SESSION_MISS_DELTA="${MAX_FAILOVER_SESSION_MISS_DELTA:-64}"
MAX_FAILOVER_NEIGHBOR_MISS_DELTA="${MAX_FAILOVER_NEIGHBOR_MISS_DELTA:-60}"
MAX_FAILOVER_ROUTE_MISS_DELTA="${MAX_FAILOVER_ROUTE_MISS_DELTA:-32}"
MAX_FAILOVER_POLICY_DENIED_DELTA="${MAX_FAILOVER_POLICY_DENIED_DELTA:-0}"
MAX_RETRANSMITS="${MAX_RETRANSMITS:-}"
MAX_RETRANSMITS_PER_GBPS="${MAX_RETRANSMITS_PER_GBPS:-}"
POST_FAILOVER_OBSERVE="${POST_FAILOVER_OBSERVE:-10}"
TRANSITION_SAMPLE_SECONDS="${TRANSITION_SAMPLE_SECONDS:-10}"
MAX_TRANSITION_KERNEL_RX_DROPPED_DELTA="${MAX_TRANSITION_KERNEL_RX_DROPPED_DELTA:-512}"
MAX_TRANSITION_DIRECT_TX_NOFRAME_DELTA="${MAX_TRANSITION_DIRECT_TX_NOFRAME_DELTA:-512}"
TRANSITION_PATH_TRIGGER_PKTS="${TRANSITION_PATH_TRIGGER_PKTS:-1000}"
MIN_TRANSITION_FABRIC_RX_DELTA="${MIN_TRANSITION_FABRIC_RX_DELTA:-32}"
MIN_TRANSITION_WAN_TX_DELTA="${MIN_TRANSITION_WAN_TX_DELTA:-32}"
MAX_STANDBY_WAN_TX_DELTA="${MAX_STANDBY_WAN_TX_DELTA:-0}"
STANDBY_WAN_IFACE_REGEX="${STANDBY_WAN_IFACE_REGEX:-ge-[0-9]+-0-2}"
RESTORE_SOURCE_NODE="${RESTORE_SOURCE_NODE:-1}"
ALLOW_STALE_SESSIONS="${ALLOW_STALE_SESSIONS:-0}"
IPERF_COMPLETION_GRACE_SEC="${IPERF_COMPLETION_GRACE_SEC:-2}"
STEADY_ONLY=0
DEPLOY=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--deploy) DEPLOY=1 ;;
	--env) ENV_FILE="$2"; shift ;;
	--rg) RG="$2"; shift ;;
	--source-node) SOURCE_NODE="$2"; shift ;;
	--target-node) TARGET_NODE="$2"; shift ;;
	--target) IPERF_TARGET="$2"; shift ;;
	--duration) IPERF_DURATION="$2"; shift ;;
	--parallel) IPERF_STREAMS="$2"; shift ;;
	--cycles) TOTAL_CYCLES="$2"; shift ;;
	--interval) CYCLE_INTERVAL="$2"; shift ;;
	--sync-wait) SYNC_WAIT="$2"; shift ;;
	--failover-wait) FAILOVER_WAIT="$2"; shift ;;
	--steady-only) STEADY_ONLY=1 ;;
	*)
		echo "unknown arg: $1" >&2
		exit 2
		;;
	esac
	shift
done

# shellcheck disable=SC1090
source "$ENV_FILE"

REMOTE_PREFIX="${INCUS_REMOTE:+${INCUS_REMOTE}:}"
FW0="${REMOTE_PREFIX}${VM0}"
FW1="${REMOTE_PREFIX}${VM1}"
HOST="${REMOTE_PREFIX}${LAN_HOST}"
ARTIFACT_DIR="${ARTIFACT_DIR:-/tmp/userspace-ha-failover-rg${RG}-$(date +%Y%m%d-%H%M%S)}"
REMOTE_IPERF_LOG="/tmp/userspace-iperf-rg${RG}-failover.log"
REMOTE_IPERF_UNIT="userspace-ha-rg${RG}-iperf3.service"
LOCAL_IPERF_LOG="${ARTIFACT_DIR}/iperf3.log"
LOCAL_IPERF_METRICS="${ARTIFACT_DIR}/iperf3.metrics.json"
FAILED=0
IPERF_WAIT_TIMEOUT_HIT=0

info() { printf '==> %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; FAILED=1; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

required_iperf_duration() {
	local cycles="$1"
	local interval="$2"
	if (( STEADY_ONLY == 1 )); then
		printf '%s\n' "$(( PRE_FAILOVER_OBSERVE + SYNC_WAIT + 10 ))"
		return 0
	fi
	if (( cycles > 1 )); then
		printf '%s\n' "$(( PRE_FAILOVER_OBSERVE + SYNC_WAIT + cycles * (interval * 2 + FAILOVER_WAIT) + 20 ))"
	else
		printf '%s\n' "$(( POST_FAILOVER_OBSERVE + SYNC_WAIT + 10 ))"
	fi
}

run_host() {
	sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "$1")"
}

run_vm() {
	local vm="$1"
	shift
	sg incus-admin -c "incus exec ${vm} -- bash -lc $(printf %q "$1")"
}

node_name() {
	case "$1" in
	0) printf 'node0\n' ;;
	1) printf 'node1\n' ;;
	*) die "unsupported node id: $1" ;;
	esac
}

vm_for_node() {
	case "$1" in
	0 | node0) printf '%s\n' "$FW0" ;;
	1 | node1) printf '%s\n' "$FW1" ;;
	*) die "unsupported node selector: $1" ;;
	esac
}

wait_for_vm_cli() {
	local vm="$1"
	local tries=45
	while (( tries > 0 )); do
		if run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics" >/tmp/userspace-cli-ready.out 2>/dev/null'; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

rg_primary_node_name() {
	local rg="$1"
	local status
	status="$(run_vm "$FW0" 'cli -c "show chassis cluster status"' 2>/dev/null || true)"
	if ! grep -Eq "Redundancy group: ${rg} " <<<"$status"; then
		return 1
	fi
	awk -v rg="$rg" '
		$0 ~ ("Redundancy group: " rg " ") { in_rg=1; next }
		in_rg && /^Redundancy group:/ { in_rg=0 }
		in_rg && /primary/ { print $1; exit }
	' <<<"$status"
}

wait_for_rg_owner() {
	local rg="$1"
	local expected
	expected="$(node_name "$2")"
	local tries="${3:-$FAILOVER_WAIT}"
	while (( tries > 0 )); do
		local current=""
		current="$(rg_primary_node_name "$rg" || true)"
		if [[ "$current" == "$expected" ]]; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

ensure_rg_owner() {
	local rg="$1"
	local target_node="$2"
	local current=""
	current="$(rg_primary_node_name "$rg" || true)"
	if [[ "$current" == "$(node_name "$target_node")" ]]; then
		return 0
	fi
	info "pinning RG${rg} to $(node_name "$target_node")"
	run_vm "$FW0" "cli -c \"request chassis cluster failover redundancy-group ${rg} node ${target_node}\" >/tmp/userspace-rg${rg}-pin.out"
	wait_for_rg_owner "$rg" "$target_node" 45 || die "RG${rg} did not move to $(node_name "$target_node")"
}

enabled_userspace_rg_vm() {
	local vm="$1"
	local rg="$2"
	local stats
	stats="$(run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"' 2>/dev/null || true)"
	grep -Eq 'Enabled:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$stats" &&
		grep -Eq "rg${rg} active=true" <<<"$stats" &&
		grep -Eq 'Ready bindings:[[:space:]]+[1-9][0-9]*/[0-9]+' <<<"$stats"
}

wait_for_userspace_rg_owner() {
	local rg="$1"
	local expected_vm="${2:-}"
	local tries=45
	while (( tries > 0 )); do
		local active=()
		local owner_vm stats query_failed=0
		for owner_vm in "$FW0" "$FW1"; do
			if ! stats="$(run_vm "$owner_vm" 'cli -c "show chassis cluster data-plane statistics"' 2>/dev/null)"; then
				query_failed=1
				continue
			fi
			if grep -Eq 'Enabled:[[:space:]]+true' <<<"$stats" &&
				grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$stats" &&
				grep -Eq "rg${rg} active=true" <<<"$stats" &&
				grep -Eq 'Ready bindings:[[:space:]]+[1-9][0-9]*/[0-9]+' <<<"$stats"; then
				active+=("$owner_vm")
			fi
		done
		if (( ${#active[@]} > 1 )); then
			printf 'split-brain userspace RG%s owners: %s\n' "$rg" "${active[*]}" >&2
			return 2
		fi
		if (( query_failed == 0 && ${#active[@]} == 1 )); then
			if [[ -z "$expected_vm" || "${active[0]}" == "$expected_vm" ]]; then
				printf '%s\n' "${active[0]}"
				return 0
			fi
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

arm_userspace_runtime() {
	local owner_vm
	local settle_status
	owner_vm="$(vm_for_node "$SOURCE_NODE")"
	info "waiting for userspace forwarding on RG${RG}"
	if ACTIVE_FW="$(wait_for_userspace_rg_owner "$RG")"; then
		info "active RG${RG} userspace firewall: ${ACTIVE_FW}"
		return 0
	else
		settle_status=$?
		if (( settle_status == 2 )); then
			die "userspace forwarding for RG${RG} is split-brain; refusing to arm"
		fi
	fi
	info "forcing userspace arm on ${owner_vm}"
	run_vm "$owner_vm" 'cli -c "request chassis cluster data-plane userspace forwarding arm" >/tmp/userspace-arm.out'
	if ACTIVE_FW="$(wait_for_userspace_rg_owner "$RG")"; then
		info "active RG${RG} userspace firewall: ${ACTIVE_FW}"
		return 0
	else
		settle_status=$?
		if (( settle_status == 2 )); then
			die "userspace forwarding for RG${RG} is split-brain after arm request"
		fi
	fi
	die "userspace forwarding did not become active for RG${RG}"
}

capture_vm_state() {
	local vm="$1"
	local label="$2"
	run_vm "$vm" 'cli -c "show chassis cluster status"' >"${ARTIFACT_DIR}/${label}-status.txt" 2>&1 || true
	run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"' >"${ARTIFACT_DIR}/${label}-dp-stats.txt" 2>&1 || true
	run_vm "$vm" 'cli -c "show chassis cluster data-plane interfaces"' >"${ARTIFACT_DIR}/${label}-dp-interfaces.txt" 2>&1 || true
	run_vm "$vm" "cli -c \"show security flow session destination-prefix ${IPERF_TARGET}\"" >"${ARTIFACT_DIR}/${label}-sessions.txt" 2>&1 || true
}

capture_cycle_state() {
	local cycle="$1"
	local phase="$2"
	capture_vm_state "$FW0" "cycle${cycle}-${phase}-fw0"
	capture_vm_state "$FW1" "cycle${cycle}-${phase}-fw1"
}

vm_artifact_suffix() {
	case "$1" in
	"$FW0") printf 'fw0\n' ;;
	"$FW1") printf 'fw1\n' ;;
	*) die "unsupported vm for artifact path: $1" ;;
	esac
}

cycle_stats_path() {
	local cycle="$1"
	local phase="$2"
	local vm="$3"
	printf '%s/cycle%s-%s-%s-dp-stats.txt\n' "${ARTIFACT_DIR}" "${cycle}" "${phase}" "$(vm_artifact_suffix "$vm")"
}

cycle_interfaces_path() {
	local cycle="$1"
	local phase="$2"
	local vm="$3"
	printf '%s/cycle%s-%s-%s-dp-interfaces.txt\n' "${ARTIFACT_DIR}" "${cycle}" "${phase}" "$(vm_artifact_suffix "$vm")"
}

sync_snapshot_path() {
	local label="$1"
	local vm="$2"
	printf '%s/%s-%s-sync.txt\n' "${ARTIFACT_DIR}" "${label}" "$(vm_artifact_suffix "$vm")"
}

transition_stats_path() {
	local cycle="$1"
	local phase="$2"
	local sample="$3"
	local vm="$4"
	printf '%s/cycle%s-%s-watch%02d-%s-dp-stats.txt\n' "${ARTIFACT_DIR}" "${cycle}" "${phase}" "${sample}" "$(vm_artifact_suffix "$vm")"
}

transition_interfaces_path() {
	local cycle="$1"
	local phase="$2"
	local sample="$3"
	local vm="$4"
	printf '%s/cycle%s-%s-watch%02d-%s-dp-interfaces.txt\n' "${ARTIFACT_DIR}" "${cycle}" "${phase}" "${sample}" "$(vm_artifact_suffix "$vm")"
}

status_summary_value() {
	local path="$1"
	local label="$2"
	python3 - "$path" "$label" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
label = sys.argv[2]
if not path.exists():
    print(f"status summary snapshot missing: {path}", file=sys.stderr)
    raise SystemExit(2)

pattern = f"  {label}:"
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if not line.startswith(pattern):
        continue
    match = re.search(r"(-?\d+)", line.split(":", 1)[1])
    if match:
        print(match.group(1))
    else:
        print(f"unparseable status summary value for {label!r} in {path}", file=sys.stderr)
        raise SystemExit(2)
    break
else:
    print(f"status summary label {label!r} not found in {path}", file=sys.stderr)
    raise SystemExit(2)
PY
}

status_summary_delta() {
	local post_path="$1"
	local pre_path="$2"
	local label="$3"
	local context="$4"
	local pre post delta

	if ! pre="$(status_summary_value "$pre_path" "$label")"; then
		fail "${context}: unable to read pre ${label}"
		return 1
	fi
	if ! post="$(status_summary_value "$post_path" "$label")"; then
		fail "${context}: unable to read post ${label}"
		return 1
	fi
	if ! delta="$(nondecreasing_counter_delta "$pre" "$post")"; then
		fail "${context}: ${label} counter decreased from ${pre} to ${post}"
		return 1
	fi
	printf '%s\n' "$delta"
}

sync_stats_value() {
	local path="$1"
	local service="$2"
	local column="$3"
	python3 - "$path" "$service" "$column" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
service = sys.argv[2]
column = sys.argv[3]
if not path.exists():
    print("__ERR__")
    raise SystemExit(0)

lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
capture = False
found_section = False
for line in lines:
    if line.strip() == "Services Synchronized:":
        capture = True
        found_section = True
        continue
    if capture and not line.strip():
        break
    if not capture:
        continue
    if service not in line:
        continue
    nums = re.findall(r"\d+", line)
    if column == "sent":
        print(nums[0] if len(nums) >= 1 else "__ERR__")
    elif column == "received":
        print(nums[1] if len(nums) >= 2 else "__ERR__")
    else:
        raise SystemExit(f"unsupported sync stats column: {column}")
    break
else:
    if not found_section:
        print("__ERR__")
    else:
        print("__ERR__")
PY
}

capture_sync_snapshot() {
	local vm="$1"
	local label="$2"
	run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"' >"$(sync_snapshot_path "$label" "$vm")" 2>&1 || true
}

wait_for_session_sync_idle() {
	local label="$1"
	local stable_needed="$SESSION_SYNC_IDLE_STABLE_SAMPLES"
	local stable=0
	local tries="$SESSION_SYNC_IDLE_TIMEOUT"
	local prev_source_sent="" prev_target_recv="" prev_target_pending="" prev_target_drained=""
	while (( tries > 0 )); do
		capture_sync_snapshot "$SOURCE_VM" "${label}-source"
		capture_sync_snapshot "$TARGET_VM" "${label}-target"
		local source_path target_path
		source_path="$(sync_snapshot_path "${label}-source" "$SOURCE_VM")"
		target_path="$(sync_snapshot_path "${label}-target" "$TARGET_VM")"
		local source_sent target_recv target_pending target_drained
		source_sent="$(sync_stats_value "$source_path" "Session create" sent)"
		target_recv="$(sync_stats_value "$target_path" "Session create" received)"
		if ! target_pending="$(status_summary_value "$target_path" "Session delta pending")"; then
			target_pending="__ERR__"
		fi
		if ! target_drained="$(status_summary_value "$target_path" "Session delta drained")"; then
			target_drained="__ERR__"
		fi
		if [[ "$source_sent" != "__ERR__" && "$target_recv" != "__ERR__" && "$target_pending" != "__ERR__" && "$target_drained" != "__ERR__" && "$source_sent" == "$target_recv" && "$target_pending" == "0" ]]; then
			stable=$((stable + 1))
			if (( stable >= stable_needed )); then
				pass "${label}: session sync idle (source_sent=${source_sent} target_recv=${target_recv} target_delta_pending=${target_pending} target_delta_drained=${target_drained})"
				return 0
			fi
		else
			stable=0
		fi
		prev_source_sent="$source_sent"
		prev_target_recv="$target_recv"
		prev_target_pending="$target_pending"
		prev_target_drained="$target_drained"
		sleep 1
		tries=$((tries - 1))
	done
	fail "${label}: session sync did not become idle before timeout (source_sent=${prev_source_sent:-0} target_recv=${prev_target_recv:-0} target_delta_pending=${prev_target_pending:-0} target_delta_drained=${prev_target_drained:-0})"
	return 1
}

status_fabric_tx_packets() {
	local path="$1"
	python3 - "$path" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists():
    print("0")
    raise SystemExit(0)

parents = set()
total = 0
section = None
skip_header = False

for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    line = raw_line.rstrip("\n")
    stripped = line.strip()
    if line.strip() == "Userspace fabric links:":
        section = "fabric"
        skip_header = True
        continue
    if line.strip() == "Userspace bindings:":
        section = "bindings"
        skip_header = True
        continue
    if section and not stripped:
        section = None
        skip_header = False
        continue
    if skip_header:
        skip_header = False
        continue
    if section == "fabric":
        parts = stripped.split()
        if len(parts) >= 2:
            parents.add(parts[1])
        continue
    if section == "bindings":
        # Column layout from 'show chassis cluster data-plane interfaces':
        #   [0]=slot [1]=queue ... [11]=TX_pkts ... [19]=interface
        # If the CLI format changes, these indices must be updated.
        parts = stripped.split()
        if len(parts) < 20:
            continue
        interface = parts[19]
        if interface in parents:
            try:
                total += int(parts[11])
            except ValueError:
                pass

print(total)
PY
}

interface_packets_value() {
	local path="$1"
	local iface_regex="$2"
	local direction="$3"
	python3 - "$path" "$iface_regex" "$direction" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
iface_regex = re.compile(sys.argv[2])
direction = sys.argv[3]
idx = 10 if direction == "rx" else 11
if not path.exists():
    print(f"missing interface snapshot: {path}", file=sys.stderr)
    raise SystemExit(2)

in_bindings = False
skip_header = False
total = 0
matched = False
bindings_rows = 0
malformed_rows = 0
for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    stripped = raw_line.strip()
    if stripped == "Userspace bindings:":
        in_bindings = True
        skip_header = True
        continue
    if in_bindings and not stripped:
        break
    if not in_bindings:
        continue
    if skip_header:
        skip_header = False
        continue
    parts = stripped.split()
    if len(parts) < 20:
        malformed_rows += 1
        continue
    bindings_rows += 1
    iface = parts[19]
    if not iface_regex.fullmatch(iface):
        continue
    matched = True
    try:
        total += int(parts[idx])
    except ValueError:
        print(f"invalid {direction} counter for {iface} in {path}", file=sys.stderr)
        raise SystemExit(2)

if not in_bindings:
    print(f"userspace bindings section not found in {path}", file=sys.stderr)
    raise SystemExit(2)
elif not matched:
    if bindings_rows == 0:
        if malformed_rows > 0:
            print(
                f"userspace bindings rows malformed in {path} "
                f"({malformed_rows} short rows)",
                file=sys.stderr,
            )
        else:
            print(f"userspace bindings section empty in {path}", file=sys.stderr)
    else:
        detail = ""
        if malformed_rows > 0:
            detail = f" ({malformed_rows} malformed rows ignored)"
        print(
            f"no interfaces matching /{iface_regex.pattern}/ in {path}{detail}",
            file=sys.stderr,
        )
    raise SystemExit(2)

print(total)
PY
}

nondecreasing_counter_delta() {
	local baseline="$1"
	local post="$2"
	python3 - "$baseline" "$post" <<'PY'
import sys

try:
    baseline = int(sys.argv[1])
    post = int(sys.argv[2])
except ValueError:
    print(f"invalid counter values: {sys.argv[1]!r} {sys.argv[2]!r}", file=sys.stderr)
    raise SystemExit(2)
if post < baseline:
    print(f"{baseline} {post}", file=sys.stderr)
    raise SystemExit(2)
print(post - baseline)
PY
}

standby_userspace_ready_vm() {
	local vm="$1"
	local rg="$2"
	local stats
	stats="$(run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"' 2>/dev/null || true)"
	grep -Eq 'Enabled:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Forwarding armed:[[:space:]]+true' <<<"$stats" &&
		grep -Eq "rg${rg} active=false" <<<"$stats" &&
		grep -Eq 'Ready bindings:[[:space:]]+[1-9][0-9]*/[0-9]+' <<<"$stats"
}

validate_target_connectivity() {
	local label="$1"
	if validate_target_reachability; then
		pass "${label}: target ${IPERF_TARGET} reachable"
	else
		fail "${label}: target ${IPERF_TARGET} unreachable"
	fi
}

validate_phase_fabric_path() {
	local cycle="$1"
	local phase="$2"
	local from_vm="$3"
	local from_name="$4"
	local to_vm="$5"
	local to_name="$6"
	local from_pre from_post to_pre to_post
	local from_if_baseline from_if_post
	local from_fabric_pre from_fabric_post from_fabric_delta
	local from_wan_tx_base from_wan_tx_post from_wan_tx_delta
	local from_session_delta to_session_delta session_delta
	local from_neighbor_delta to_neighbor_delta neighbor_delta
	local from_route_delta to_route_delta route_delta
	local from_policy_delta to_policy_delta policy_delta
	local from_churn

	from_pre="$(cycle_stats_path "$cycle" "${phase}-pre" "$from_vm")"
	from_post="$(cycle_stats_path "$cycle" "${phase}-post" "$from_vm")"
	to_pre="$(cycle_stats_path "$cycle" "${phase}-pre" "$to_vm")"
	to_post="$(cycle_stats_path "$cycle" "${phase}-post" "$to_vm")"
	from_if_baseline="$(cycle_interfaces_path "$cycle" "$phase" "$from_vm")"
	from_if_post="$(cycle_interfaces_path "$cycle" "${phase}-post" "$from_vm")"

	from_fabric_pre="$(status_fabric_tx_packets "$from_if_baseline")"
	from_fabric_post="$(status_fabric_tx_packets "$from_if_post")"
	from_fabric_delta=$(( from_fabric_post - from_fabric_pre ))
	if ! from_wan_tx_base="$(interface_packets_value "$from_if_baseline" "$STANDBY_WAN_IFACE_REGEX" tx)"; then
		fail "cycle ${cycle} ${phase}: unable to read standby ${from_name} WAN TX post-failover baseline counters"
		return
	fi
	if ! from_wan_tx_post="$(interface_packets_value "$from_if_post" "$STANDBY_WAN_IFACE_REGEX" tx)"; then
		fail "cycle ${cycle} ${phase}: unable to read standby ${from_name} WAN TX post-validation counters"
		return
	fi
	if ! from_wan_tx_delta="$(nondecreasing_counter_delta "$from_wan_tx_base" "$from_wan_tx_post")"; then
		fail "cycle ${cycle} ${phase}: standby ${from_name} WAN TX counter decreased" \
			"from ${from_wan_tx_base} to ${from_wan_tx_post}; failing closed"
		return
	fi
	from_session_delta="$(
		status_summary_delta "$from_post" "$from_pre" "Session misses" \
			"cycle ${cycle} ${phase}: ${from_name}"
	)" || {
		return
	}
	to_session_delta="$(
		status_summary_delta "$to_post" "$to_pre" "Session misses" \
			"cycle ${cycle} ${phase}: ${to_name}"
	)" || {
		return
	}
	session_delta=$(( from_session_delta + to_session_delta ))
	if (( session_delta <= MAX_FAILOVER_SESSION_MISS_DELTA )); then
		pass "cycle ${cycle} ${phase}: session miss delta ${session_delta} (source=${from_session_delta} target=${to_session_delta})"
	else
		fail "cycle ${cycle} ${phase}: session miss delta ${session_delta} (source=${from_session_delta} target=${to_session_delta}) exceeds ${MAX_FAILOVER_SESSION_MISS_DELTA}"
	fi

	from_neighbor_delta="$(
		status_summary_delta "$from_post" "$from_pre" "Neighbor misses" \
			"cycle ${cycle} ${phase}: ${from_name}"
	)" || {
		return
	}
	to_neighbor_delta="$(
		status_summary_delta "$to_post" "$to_pre" "Neighbor misses" \
			"cycle ${cycle} ${phase}: ${to_name}"
	)" || {
		return
	}
	neighbor_delta=$(( from_neighbor_delta + to_neighbor_delta ))
	if (( neighbor_delta <= MAX_FAILOVER_NEIGHBOR_MISS_DELTA )); then
		pass "cycle ${cycle} ${phase}: neighbor miss delta ${neighbor_delta} (source=${from_neighbor_delta} target=${to_neighbor_delta})"
	else
		fail "cycle ${cycle} ${phase}: neighbor miss delta ${neighbor_delta} (source=${from_neighbor_delta} target=${to_neighbor_delta}) exceeds ${MAX_FAILOVER_NEIGHBOR_MISS_DELTA}"
	fi

	from_route_delta="$(
		status_summary_delta "$from_post" "$from_pre" "Route misses" \
			"cycle ${cycle} ${phase}: ${from_name}"
	)" || {
		return
	}
	to_route_delta="$(
		status_summary_delta "$to_post" "$to_pre" "Route misses" \
			"cycle ${cycle} ${phase}: ${to_name}"
	)" || {
		return
	}
	route_delta=$(( from_route_delta + to_route_delta ))
	if (( route_delta <= MAX_FAILOVER_ROUTE_MISS_DELTA )); then
		pass "cycle ${cycle} ${phase}: route miss delta ${route_delta} (source=${from_route_delta} target=${to_route_delta})"
	else
		fail "cycle ${cycle} ${phase}: route miss delta ${route_delta} (source=${from_route_delta} target=${to_route_delta}) exceeds ${MAX_FAILOVER_ROUTE_MISS_DELTA}"
	fi

	from_policy_delta="$(
		status_summary_delta "$from_post" "$from_pre" "Policy denied packets" \
			"cycle ${cycle} ${phase}: ${from_name}"
	)" || {
		return
	}
	to_policy_delta="$(
		status_summary_delta "$to_post" "$to_pre" "Policy denied packets" \
			"cycle ${cycle} ${phase}: ${to_name}"
	)" || {
		return
	}
	policy_delta=$(( from_policy_delta + to_policy_delta ))
	if (( policy_delta <= MAX_FAILOVER_POLICY_DENIED_DELTA )); then
		pass "cycle ${cycle} ${phase}: policy denied delta ${policy_delta} (source=${from_policy_delta} target=${to_policy_delta})"
	else
		fail "cycle ${cycle} ${phase}: policy denied delta ${policy_delta} (source=${from_policy_delta} target=${to_policy_delta}) exceeds ${MAX_FAILOVER_POLICY_DENIED_DELTA}"
	fi

	from_churn=$(( from_session_delta + from_neighbor_delta + from_route_delta + from_policy_delta ))
	if [[ "${REQUIRE_FABRIC_ACTIVITY}" == "1" ]]; then
		if (( from_fabric_delta >= MIN_FABRIC_TX_DELTA )); then
			pass "cycle ${cycle} ${phase}: ${from_name} fabric TX delta ${from_fabric_delta}"
		elif (( from_churn >= FABRIC_ACTIVITY_TRIGGER_DELTA )); then
			fail "cycle ${cycle} ${phase}: ${from_name} fabric TX delta ${from_fabric_delta} with old-owner churn ${from_churn} (>= ${FABRIC_ACTIVITY_TRIGGER_DELTA})"
		else
			pass "cycle ${cycle} ${phase}: ${from_name} fabric TX delta ${from_fabric_delta}; old-owner churn ${from_churn} below trigger ${FABRIC_ACTIVITY_TRIGGER_DELTA}"
		fi
	else
		pass "cycle ${cycle} ${phase}: ${from_name} fabric TX delta ${from_fabric_delta}"
	fi

	if [[ "${REQUIRE_STANDBY_READY}" == "1" ]]; then
		if standby_userspace_ready_vm "$from_vm" "$RG"; then
			pass "cycle ${cycle} ${phase}: standby ${from_name} remained armed with ready bindings"
		else
			fail "cycle ${cycle} ${phase}: standby ${from_name} lost userspace readiness"
		fi
	fi

	if (( from_wan_tx_delta <= MAX_STANDBY_WAN_TX_DELTA )); then
		pass "cycle ${cycle} ${phase}: standby ${from_name} WAN TX delta ${from_wan_tx_delta}"
	else
		fail "cycle ${cycle} ${phase}: standby ${from_name} WAN TX delta" \
			"${from_wan_tx_delta} exceeds ${MAX_STANDBY_WAN_TX_DELTA}"
	fi
}

capture_transition_window() {
	local cycle="$1"
	local phase="$2"
	local seconds="$3"
	local sample stats_path interfaces_path
	for (( sample = 1; sample <= seconds; sample++ )); do
		if ! cycle_sleep 1 0; then
			fail "cycle ${cycle} ${phase}: iperf3 exited during transition sample ${sample}/${seconds}"
			break
		fi
		stats_path="$(transition_stats_path "$cycle" "$phase" "$sample" "$FW0")"
		if ! run_vm "$FW0" 'cli -c "show chassis cluster data-plane statistics"' >"$stats_path" 2>&1; then
			fail "cycle ${cycle} ${phase}: failed to capture ${FW0} transition statistics sample ${sample}"
		fi
		stats_path="$(transition_stats_path "$cycle" "$phase" "$sample" "$FW1")"
		if ! run_vm "$FW1" 'cli -c "show chassis cluster data-plane statistics"' >"$stats_path" 2>&1; then
			fail "cycle ${cycle} ${phase}: failed to capture ${FW1} transition statistics sample ${sample}"
		fi
		interfaces_path="$(transition_interfaces_path "$cycle" "$phase" "$sample" "$FW0")"
		if ! run_vm "$FW0" 'cli -c "show chassis cluster data-plane interfaces"' >"$interfaces_path" 2>&1; then
			fail "cycle ${cycle} ${phase}: failed to capture ${FW0} transition interface sample ${sample}"
		fi
		interfaces_path="$(transition_interfaces_path "$cycle" "$phase" "$sample" "$FW1")"
		if ! run_vm "$FW1" 'cli -c "show chassis cluster data-plane interfaces"' >"$interfaces_path" 2>&1; then
			fail "cycle ${cycle} ${phase}: failed to capture ${FW1} transition interface sample ${sample}"
		fi
	done
}

sample_window_interface_packets() {
	local cycle="$1"
	local phase="$2"
	local seconds="$3"
	local vm="$4"
	local iface_regex="$5"
	local direction="$6"
	local agg="${7:-last}"
	python3 - "$ARTIFACT_DIR" "$cycle" "$phase" "$seconds" "$(vm_artifact_suffix "$vm")" "$iface_regex" "$direction" "$agg" <<'PY'
import pathlib
import re
import sys

artifact_dir = pathlib.Path(sys.argv[1])
cycle = sys.argv[2]
phase = sys.argv[3]
seconds = int(sys.argv[4])
suffix = sys.argv[5]
iface_regex = re.compile(sys.argv[6])
direction = sys.argv[7]
agg = sys.argv[8]
if direction not in {"rx", "tx"}:
    print(f"invalid packet direction: {direction}", file=sys.stderr)
    raise SystemExit(2)
idx = 10 if direction == "rx" else 11
values = []

for sample in range(1, seconds + 1):
    path = artifact_dir / f"cycle{cycle}-{phase}-watch{sample:02d}-{suffix}-dp-interfaces.txt"
    if not path.exists():
        print(f"missing transition interface snapshot: {path}", file=sys.stderr)
        raise SystemExit(2)
    total = 0
    in_bindings = False
    skip_header = False
    matched = False
    bindings_rows = 0
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw_line.strip()
        if stripped == "Userspace bindings:":
            in_bindings = True
            skip_header = True
            continue
        if in_bindings and not stripped:
            break
        if not in_bindings:
            continue
        if skip_header:
            skip_header = False
            continue
        bindings_rows += 1
        parts = stripped.split()
        if len(parts) < 20:
            continue
        iface = parts[19]
        if not iface_regex.fullmatch(iface):
            continue
        matched = True
        try:
            total += int(parts[idx])
        except (IndexError, ValueError):
            print(f"invalid {direction} counter for {iface} in {path}", file=sys.stderr)
            raise SystemExit(2)
    if not in_bindings:
        print(f"userspace bindings section not found in {path}", file=sys.stderr)
        raise SystemExit(2)
    if not matched:
        if bindings_rows == 0:
            print(f"userspace bindings section empty in {path}", file=sys.stderr)
        else:
            print(f"no interfaces matching /{iface_regex.pattern}/ in {path}", file=sys.stderr)
        raise SystemExit(2)
    values.append(total)

if not values:
    print("no transition interface samples collected", file=sys.stderr)
    raise SystemExit(2)
elif agg == "max":
    print(max(values))
else:
    print(values[-1])
PY
}

sample_window_value() {
	local cycle="$1"
	local phase="$2"
	local seconds="$3"
	local vm="$4"
	local label="$5"
	local agg="${6:-last}"
	python3 - "$ARTIFACT_DIR" "$cycle" "$phase" "$seconds" "$(vm_artifact_suffix "$vm")" "$label" "$agg" <<'PY'
import pathlib
import re
import sys

artifact_dir = pathlib.Path(sys.argv[1])
cycle = sys.argv[2]
phase = sys.argv[3]
seconds = int(sys.argv[4])
suffix = sys.argv[5]
label = sys.argv[6]
agg = sys.argv[7]
pattern = f"  {label}:"
values = []
for sample in range(1, seconds + 1):
    path = artifact_dir / f"cycle{cycle}-{phase}-watch{sample:02d}-{suffix}-dp-stats.txt"
    if not path.exists():
        print(f"missing transition statistics snapshot: {path}", file=sys.stderr)
        raise SystemExit(2)
    found = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith(pattern):
            continue
        match = re.search(r"(-?\d+)", line.split(":", 1)[1])
        if match:
            values.append(int(match.group(1)))
            found = True
        break
    if not found:
        print(f"label {label!r} not found in {path}", file=sys.stderr)
        raise SystemExit(2)

if not values:
    print("no transition statistics samples collected", file=sys.stderr)
    raise SystemExit(2)
elif agg == "max":
    print(max(values))
else:
    print(values[-1])
PY
}

validate_transition_window() {
	local cycle="$1"
	local phase="$2"
	local from_vm="$3"
	local from_name="$4"
	local to_vm="$5"
	local to_name="$6"
	local seconds="$7"
	local from_pre to_pre
	local from_if_pre to_if_pre
	local to_kernel_rx_dropped_max from_no_frame_max
	local to_kernel_rx_dropped_pre from_no_frame_pre
	local to_kernel_rx_dropped_delta from_no_frame_delta
	local from_pending_local_max to_pending_local_max
	local from_outstanding_max to_outstanding_max
	local from_lan_rx_max from_fabric_tx_max to_fabric_rx_max to_wan_tx_max
	local from_lan_rx_pre from_fabric_tx_pre to_fabric_rx_pre to_wan_tx_pre
	local from_lan_rx_delta from_fabric_tx_delta to_fabric_rx_delta to_wan_tx_delta

	from_pre="$(cycle_stats_path "$cycle" "${phase}-pre" "$from_vm")"
	to_pre="$(cycle_stats_path "$cycle" "${phase}-pre" "$to_vm")"
	from_if_pre="$(cycle_interfaces_path "$cycle" "${phase}-pre" "$from_vm")"
	to_if_pre="$(cycle_interfaces_path "$cycle" "${phase}-pre" "$to_vm")"

	to_kernel_rx_dropped_max="$(sample_window_value "$cycle" "$phase" "$seconds" "$to_vm" "Kernel RX dropped" max)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${to_name} transition kernel RX drop samples"
		return
	}
	from_no_frame_max="$(sample_window_value "$cycle" "$phase" "$seconds" "$from_vm" "Direct TX no-frame fb" max)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${from_name} transition direct no-frame samples"
		return
	}
	from_pending_local_max="$(sample_window_value "$cycle" "$phase" "$seconds" "$from_vm" "Pending TX local" max)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${from_name} pending-local transition samples"
		return
	}
	to_pending_local_max="$(sample_window_value "$cycle" "$phase" "$seconds" "$to_vm" "Pending TX local" max)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${to_name} pending-local transition samples"
		return
	}
	from_outstanding_max="$(sample_window_value "$cycle" "$phase" "$seconds" "$from_vm" "Outstanding TX" max)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${from_name} outstanding-TX transition samples"
		return
	}
	to_outstanding_max="$(sample_window_value "$cycle" "$phase" "$seconds" "$to_vm" "Outstanding TX" max)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${to_name} outstanding-TX transition samples"
		return
	}
	from_lan_rx_max="$(
		sample_window_interface_packets "$cycle" "$phase" "$seconds" "$from_vm" \
			'ge-[0-9]+-0-1' rx max
	)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${from_name} LAN RX transition samples"
		return
	}
	from_fabric_tx_max="$(
		sample_window_interface_packets "$cycle" "$phase" "$seconds" "$from_vm" \
			'ge-[0-9]+-0-0' tx max
	)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${from_name} fabric TX transition samples"
		return
	}
	to_fabric_rx_max="$(sample_window_interface_packets "$cycle" "$phase" "$seconds" "$to_vm" 'ge-[0-9]+-0-0' rx max)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${to_name} fabric RX transition samples"
		return
	}
	to_wan_tx_max="$(sample_window_interface_packets "$cycle" "$phase" "$seconds" "$to_vm" 'ge-[0-9]+-0-2' tx max)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${to_name} WAN TX transition samples"
		return
	}

	to_kernel_rx_dropped_pre="$(status_summary_value "$to_pre" "Kernel RX dropped")" || {
		fail "cycle ${cycle} ${phase}: unable to read ${to_name} pre-transition kernel RX drop baseline"
		return
	}
	from_no_frame_pre="$(status_summary_value "$from_pre" "Direct TX no-frame fb")" || {
		fail "cycle ${cycle} ${phase}: unable to read ${from_name} pre-transition direct no-frame baseline"
		return
	}
	from_lan_rx_pre="$(interface_packets_value "$from_if_pre" 'ge-[0-9]+-0-1' rx)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${from_name} pre-transition LAN RX baseline"
		return
	}
	from_fabric_tx_pre="$(interface_packets_value "$from_if_pre" 'ge-[0-9]+-0-0' tx)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${from_name} pre-transition fabric TX baseline"
		return
	}
	to_fabric_rx_pre="$(interface_packets_value "$to_if_pre" 'ge-[0-9]+-0-0' rx)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${to_name} pre-transition fabric RX baseline"
		return
	}
	to_wan_tx_pre="$(interface_packets_value "$to_if_pre" 'ge-[0-9]+-0-2' tx)" || {
		fail "cycle ${cycle} ${phase}: unable to read ${to_name} pre-transition WAN TX baseline"
		return
	}

	to_kernel_rx_dropped_delta="$(
		nondecreasing_counter_delta "$to_kernel_rx_dropped_pre" \
			"$to_kernel_rx_dropped_max"
	)" || {
		fail "cycle ${cycle} ${phase}: ${to_name} transition kernel RX dropped counter decreased" \
			"from ${to_kernel_rx_dropped_pre} to ${to_kernel_rx_dropped_max}; failing closed"
		return
	}
	from_no_frame_delta="$(nondecreasing_counter_delta "$from_no_frame_pre" "$from_no_frame_max")" || {
		fail "cycle ${cycle} ${phase}: ${from_name} transition direct no-frame counter decreased" \
			"from ${from_no_frame_pre} to ${from_no_frame_max}; failing closed"
		return
	}
	from_lan_rx_delta="$(nondecreasing_counter_delta "$from_lan_rx_pre" "$from_lan_rx_max")" || {
		fail "cycle ${cycle} ${phase}: ${from_name} transition LAN RX counter decreased" \
			"from ${from_lan_rx_pre} to ${from_lan_rx_max}; failing closed"
		return
	}
	from_fabric_tx_delta="$(nondecreasing_counter_delta "$from_fabric_tx_pre" "$from_fabric_tx_max")" || {
		fail "cycle ${cycle} ${phase}: ${from_name} transition fabric TX counter decreased" \
			"from ${from_fabric_tx_pre} to ${from_fabric_tx_max}; failing closed"
		return
	}
	to_fabric_rx_delta="$(nondecreasing_counter_delta "$to_fabric_rx_pre" "$to_fabric_rx_max")" || {
		fail "cycle ${cycle} ${phase}: ${to_name} transition fabric RX counter decreased" \
			"from ${to_fabric_rx_pre} to ${to_fabric_rx_max}; failing closed"
		return
	}
	to_wan_tx_delta="$(nondecreasing_counter_delta "$to_wan_tx_pre" "$to_wan_tx_max")" || {
		fail "cycle ${cycle} ${phase}: ${to_name} transition WAN TX counter decreased" \
			"from ${to_wan_tx_pre} to ${to_wan_tx_max}; failing closed"
		return
	}

	if (( to_kernel_rx_dropped_delta <= MAX_TRANSITION_KERNEL_RX_DROPPED_DELTA )); then
		pass "cycle ${cycle} ${phase}: ${to_name} transition kernel RX dropped delta ${to_kernel_rx_dropped_delta}"
	else
		fail "cycle ${cycle} ${phase}: ${to_name} transition kernel RX dropped delta ${to_kernel_rx_dropped_delta} exceeds ${MAX_TRANSITION_KERNEL_RX_DROPPED_DELTA}"
	fi

	if (( from_no_frame_delta <= MAX_TRANSITION_DIRECT_TX_NOFRAME_DELTA )); then
		pass "cycle ${cycle} ${phase}: ${from_name} transition direct no-frame delta ${from_no_frame_delta}"
	else
		fail "cycle ${cycle} ${phase}: ${from_name} transition direct no-frame delta ${from_no_frame_delta} exceeds ${MAX_TRANSITION_DIRECT_TX_NOFRAME_DELTA}"
	fi

	pass "cycle ${cycle} ${phase}: path old-owner lan-rx=${from_lan_rx_delta} fabric-tx=${from_fabric_tx_delta}; new-owner fabric-rx=${to_fabric_rx_delta} wan-tx=${to_wan_tx_delta}"
	if (( from_lan_rx_delta >= TRANSITION_PATH_TRIGGER_PKTS )); then
		if (( from_fabric_tx_delta < MIN_FABRIC_TX_DELTA )); then
			fail "cycle ${cycle} ${phase}: stale-owner LAN RX delta ${from_lan_rx_delta} but old-owner fabric TX delta ${from_fabric_tx_delta} < ${MIN_FABRIC_TX_DELTA}"
		fi
		if (( to_fabric_rx_delta < MIN_TRANSITION_FABRIC_RX_DELTA )); then
			fail "cycle ${cycle} ${phase}: stale-owner LAN RX delta ${from_lan_rx_delta} but new-owner fabric RX delta ${to_fabric_rx_delta} < ${MIN_TRANSITION_FABRIC_RX_DELTA}"
		fi
		if (( to_wan_tx_delta < MIN_TRANSITION_WAN_TX_DELTA )); then
			fail "cycle ${cycle} ${phase}: stale-owner LAN RX delta ${from_lan_rx_delta} but new-owner WAN TX delta ${to_wan_tx_delta} < ${MIN_TRANSITION_WAN_TX_DELTA}"
		fi
	else
		pass "cycle ${cycle} ${phase}: old-owner LAN RX delta ${from_lan_rx_delta} below stale-owner trigger ${TRANSITION_PATH_TRIGGER_PKTS}"
	fi

	pass "cycle ${cycle} ${phase}: ${from_name} max pending-local=${from_pending_local_max} outstanding-tx=${from_outstanding_max}; ${to_name} max pending-local=${to_pending_local_max} outstanding-tx=${to_outstanding_max}"
}

zero_port_tcp_sessions() {
	local vm="$1"
	run_vm "$vm" "cli -c \"show security flow session destination-prefix ${IPERF_TARGET}\" 2>/dev/null | grep -Ec '^[[:space:]]+(In|Out): .*\\/0;tcp' || true"
}

validate_clean_session_baseline() {
	if [[ "${CHECK_KERNEL_SESSION_TABLE}" != "1" ]]; then
		pass "preflight: kernel session-table checks disabled for userspace failover validation"
		return 0
	fi
	local source_zero target_zero
	source_zero="$(zero_port_tcp_sessions "$SOURCE_VM")"
	target_zero="$(zero_port_tcp_sessions "$TARGET_VM")"
	if [[ "$source_zero" -gt 0 || "$target_zero" -gt 0 ]]; then
		capture_vm_state "$SOURCE_VM" "preflight-source"
		capture_vm_state "$TARGET_VM" "preflight-target"
		if [[ "$ALLOW_STALE_SESSIONS" == "1" ]]; then
			fail "preflight: stale zero-port TCP sessions present (source=${source_zero} target=${target_zero})"
		else
			die "preflight: stale zero-port TCP sessions present (source=${source_zero} target=${target_zero}); redeploy or clear flow state before stress testing"
		fi
	else
		pass "preflight: no stale zero-port TCP sessions on source or target owner"
	fi
}

session_count() {
	local vm="$1"
	run_vm "$vm" "cli -c \"show security flow session destination-prefix ${IPERF_TARGET}\" 2>/dev/null | grep -c '^Session ID:' || true"
}

validate_target_reachability() {
	local ping_log="/tmp/userspace-rg${RG}-ping.out"
	local tcp_log="/tmp/userspace-rg${RG}-tcp.out"
	run_host "ping -c 3 -W 1 ${IPERF_TARGET} >${ping_log} 2>&1 || true"
	if run_host "grep -q 'bytes from' ${ping_log}"; then
		return 0
	fi
	# Some targets drop the first probe while ARP/NDP settles. Fall back to a
	# TCP handshake against the iperf3 server so failover validation does not
	# fail before the actual RG transition is exercised.
	if run_host "timeout 3 bash -lc 'echo > /dev/tcp/${IPERF_TARGET}/5201' >${tcp_log} 2>&1"; then
		return 0
	fi
	return 1
}

external_ping_path() {
	local label="$1"
	printf '%s\n' "${ARTIFACT_DIR}/external-${label}.txt"
}

check_external_ping() {
	local label="$1"
	local family="$2"
	local target="$3"
	local path remote_path
	path="$(external_ping_path "${label}")"
	remote_path="/tmp/userspace-rg${RG}-${label}.txt"
	local escaped_target escaped_count escaped_remote_path
	escaped_target=$(printf '%q' "${target}")
	escaped_count=$(printf '%q' "${EXTERNAL_PING_COUNT}")
	escaped_remote_path=$(printf '%q' "${remote_path}")
	if [[ "$family" == "6" ]]; then
		run_host "ping -6 -c ${escaped_count} -W 1 ${escaped_target} >${escaped_remote_path} 2>&1 || true"
	else
		run_host "ping -c ${escaped_count} -W 1 ${escaped_target} >${escaped_remote_path} 2>&1 || true"
	fi
	run_host "cat ${escaped_remote_path} 2>/dev/null || true" >"${path}"
	run_host "grep -q 'bytes from' ${escaped_remote_path}"
}

validate_external_connectivity() {
	local label="$1"
	if [[ "${CHECK_EXTERNAL_REACHABILITY}" != "1" ]]; then
		info "${label}: external reachability checks skipped (CHECK_EXTERNAL_REACHABILITY=${CHECK_EXTERNAL_REACHABILITY})"
		return 0
	fi
	local ok=0
	if check_external_ping "${label}-ipv4" 4 "${EXTERNAL_V4_TARGET}"; then
		pass "${label}: external IPv4 reachable (${EXTERNAL_V4_TARGET})"
	else
		fail "${label}: external IPv4 unreachable (${EXTERNAL_V4_TARGET})"
		ok=1
	fi
	if check_external_ping "${label}-ipv6" 6 "${EXTERNAL_V6_TARGET}"; then
		pass "${label}: external IPv6 reachable (${EXTERNAL_V6_TARGET})"
	else
		fail "${label}: external IPv6 unreachable (${EXTERNAL_V6_TARGET})"
		ok=1
	fi
	return "$ok"
}

start_iperf() {
	local attempt
	for attempt in 1 2 3; do
		run_host "systemctl stop ${REMOTE_IPERF_UNIT} >/dev/null 2>&1 || true; systemctl reset-failed ${REMOTE_IPERF_UNIT} >/dev/null 2>&1 || true; pkill -9 iperf3 2>/dev/null || true; rm -f ${REMOTE_IPERF_LOG}"
		run_host "systemd-run --quiet --unit ${REMOTE_IPERF_UNIT%.service} /bin/sh -c $(printf %q "exec iperf3 --json-stream --forceflush --connect-timeout 5000 -t ${IPERF_DURATION} -c ${IPERF_TARGET} -P ${IPERF_STREAMS} > ${REMOTE_IPERF_LOG} 2>/dev/null")"
		sleep 8
		if ! run_host "pgrep -x iperf3 >/dev/null"; then
			info "iperf3 exited on attempt ${attempt}, retrying"
			sleep $((attempt * 5))
			continue
		fi
		return 0
	done
	return 1
}

recent_interval_metric() {
	local intervals="$1"
	local metric="$2"
	local tail_lines=$(( intervals + 8 ))
	local recent_lines
	recent_lines="$(run_host "tail -n ${tail_lines} ${REMOTE_IPERF_LOG} 2>/dev/null || true")"
	python3 - "$metric" "$recent_lines" <<'PY'
import json
import sys

metric = sys.argv[1]
raw_lines = sys.argv[2]
intervals = []
for raw in raw_lines.splitlines():
    raw = raw.strip()
    if not raw:
        continue
    try:
        event = json.loads(raw)
    except Exception:
        continue
    if event.get("event") == "interval":
        intervals.append(event.get("data") or {})

if not intervals:
    print("0")
    raise SystemExit(0)

last = intervals[-1]
stream_zero_total = 0
zero_streams = set()
aggregate_zero_total = 0
for interval in intervals:
    if float((interval.get("sum") or {}).get("bits_per_second") or 0.0) <= 0.0:
        aggregate_zero_total += 1
    for stream in interval.get("streams", []):
        if float(stream.get("bits_per_second") or 0.0) <= 0.0:
            stream_zero_total += 1
            zero_streams.add(str(stream.get("socket") or stream.get("id") or "?"))

if metric == "dead_streams":
    print(
        sum(
            1
            for stream in last.get("streams", [])
            if float(stream.get("bits_per_second") or 0.0) <= 0.0
        )
    )
elif metric == "zero_intervals":
    print(aggregate_zero_total + stream_zero_total)
elif metric == "stream_zero_intervals":
    print(stream_zero_total)
elif metric == "zero_streams":
    print(len(zero_streams))
else:
    raise SystemExit(f"unsupported recent interval metric: {metric}")
PY
}

recent_dead_streams() {
	recent_interval_metric 1 dead_streams
}

count_recent_zero_intervals() {
	local intervals="$1"
	recent_interval_metric "$intervals" zero_intervals
}

count_recent_stream_zero_intervals() {
	local intervals="$1"
	recent_interval_metric "$intervals" stream_zero_intervals
}

count_recent_zero_streams() {
	local intervals="$1"
	recent_interval_metric "$intervals" zero_streams
}

iperf_alive() {
	run_host "pgrep -x iperf3 >/dev/null"
}

iperf_completed() {
	run_host "grep -q '\"event\":\"end\"' ${REMOTE_IPERF_LOG}"
}

iperf_observed_end_remote() {
	local recent_lines
	recent_lines="$(run_host "tail -n 32 ${REMOTE_IPERF_LOG} 2>/dev/null || true")"
	python3 - "$recent_lines" <<'PY'
import json
import sys

observed = 0.0
for raw in sys.argv[1].splitlines():
    raw = raw.strip()
    if not raw:
        continue
    try:
        event = json.loads(raw)
    except Exception:
        continue
    if event.get("event") == "interval":
        observed = max(observed, float((event.get("data") or {}).get("sum", {}).get("end") or 0.0))
    elif event.get("event") == "end":
        observed = max(observed, float((event.get("data") or {}).get("sum_sent", {}).get("end") or 0.0))
print(f"{observed:.3f}" if observed > 0 else "")
PY
}

iperf_reached_expected_duration_remote() {
	local observed_end
	observed_end="$(iperf_observed_end_remote)"
	if [[ -z "${observed_end}" ]]; then
		return 1
	fi
	awk "BEGIN{exit !(${observed_end} >= (${IPERF_DURATION} - ${IPERF_COMPLETION_GRACE_SEC}))}"
}

iperf_effectively_completed_remote() {
	iperf_completed || iperf_reached_expected_duration_remote
}

wait_for_iperf_finish() {
	local tries=$((IPERF_DURATION + 20))
	while (( tries > 0 )); do
		if ! iperf_alive; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	IPERF_WAIT_TIMEOUT_HIT=1
	run_host "pkill -TERM -x iperf3 2>/dev/null || true"
	sleep 1
	run_host "pkill -KILL -x iperf3 2>/dev/null || true"
	return 1
}

copy_artifacts() {
	mkdir -p "${ARTIFACT_DIR}"
	run_host "cat ${REMOTE_IPERF_LOG} 2>/dev/null || true" >"${LOCAL_IPERF_LOG}"
	if ! python3 "${IPERF_METRICS}" "${LOCAL_IPERF_LOG}" >"${LOCAL_IPERF_METRICS}" 2>"${ARTIFACT_DIR}/iperf3.metrics.err"; then
		printf '{"ok":false,"error":"metrics_parse_failed"}\n' >"${LOCAL_IPERF_METRICS}"
	fi
}

iperf_metrics_field() {
	python3 - "${LOCAL_IPERF_METRICS}" "$1" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
field = sys.argv[2]
if not path.exists():
    print("")
    raise SystemExit(0)

data = json.loads(path.read_text(encoding="utf-8"))
value = data.get(field, "")
if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (int, float)):
    print(value)
else:
    print(value)
PY
}

count_zero_intervals() {
	iperf_metrics_field zero_intervals_total
}

count_stream_zero_intervals() {
	iperf_metrics_field stream_zero_intervals_total
}

count_zero_streams() {
	iperf_metrics_field zero_streams_total
}

extract_sender_throughput() {
	local value
	value="$(iperf_metrics_field avg_gbps)"
	printf '%.3f\n' "${value:-0}"
}

extract_retransmits() {
	local value
	value="$(iperf_metrics_field retransmits)"
	printf '%s\n' "${value:-0}"
}

iperf_collapse_detected() {
	[[ "$(iperf_metrics_field collapse_detected)" == "true" ]]
}

iperf_collapse_reason() {
	iperf_metrics_field collapse_reason
}

iperf_completed_local() {
	[[ "$(iperf_metrics_field completed)" == "true" ]]
}

iperf_effectively_completed_local() {
	local completed observed_end
	completed="$(iperf_metrics_field completed)"
	if [[ "$completed" == "true" ]]; then
		return 0
	fi
	observed_end="$(iperf_metrics_field observed_end_sec)"
	awk "BEGIN{exit !(${observed_end:-0} >= (${IPERF_DURATION} - ${IPERF_COMPLETION_GRACE_SEC}))}"
}

cycle_sleep() {
	local seconds="$1"
	local allow_expected_completion="${2:-0}"
	local remaining="$seconds"
	while (( remaining > 0 )); do
		if ! iperf_alive; then
			if iperf_completed; then
				return 0
			fi
			if [[ "$allow_expected_completion" == "1" ]] && iperf_reached_expected_duration_remote; then
				return 0
			fi
			return 1
		fi
		sleep 1
		remaining=$((remaining - 1))
	done
	return 0
}

validate_cycle_health() {
	local cycle="$1"
	local label="$2"
	local owner_vm="$3"
	local owner_name="$4"
	local final_phase="$5"
	local dead_streams
	if iperf_alive; then
		pass "cycle ${cycle} ${label}: iperf3 alive on ${owner_name}"
	elif iperf_effectively_completed_remote; then
		if [[ "$final_phase" == "1" ]]; then
			pass "cycle ${cycle} ${label}: iperf3 completed during final phase"
		else
			fail "cycle ${cycle} ${label}: iperf3 completed before all failover phases finished"
		fi
	else
		fail "cycle ${cycle} ${label}: iperf3 died"
	fi
	dead_streams="$(recent_dead_streams)"
	if [[ "$dead_streams" -gt 0 ]]; then
		fail "cycle ${cycle} ${label}: ${dead_streams}/${IPERF_STREAMS} streams at 0.00 bits/sec"
	else
		pass "cycle ${cycle} ${label}: all ${IPERF_STREAMS} streams carrying traffic"
	fi
	if [[ "${CHECK_KERNEL_SESSION_TABLE}" == "1" ]]; then
		local count zero_source zero_target
		count="$(session_count "$owner_vm")"
		if [[ "$count" -lt "$MIN_SESSIONS" ]]; then
			fail "cycle ${cycle} ${label}: ${owner_name} has only ${count} sessions (expected >= ${MIN_SESSIONS})"
		else
			pass "cycle ${cycle} ${label}: ${owner_name} has ${count} sessions"
		fi
		zero_source="$(zero_port_tcp_sessions "$FW0")"
		zero_target="$(zero_port_tcp_sessions "$FW1")"
		if [[ "$zero_source" -gt 0 || "$zero_target" -gt 0 ]]; then
			fail "cycle ${cycle} ${label}: zero-port TCP sessions present (fw0=${zero_source} fw1=${zero_target})"
		else
			pass "cycle ${cycle} ${label}: no zero-port TCP sessions present"
		fi
	fi
}

validate_pre_failover_health() {
	local owner_vm="$1"
	local owner_name="$2"
	local zero_intervals stream_zero_intervals zero_streams

	info "observing steady-state traffic for ${PRE_FAILOVER_OBSERVE}s before failover"
	if ! cycle_sleep "$PRE_FAILOVER_OBSERVE"; then
		fail "steady-state preflight: iperf3 exited before ${PRE_FAILOVER_OBSERVE}s observe window elapsed"
	fi
	capture_vm_state "$SOURCE_VM" "pre-failover-source"
	capture_vm_state "$TARGET_VM" "pre-failover-target"
	validate_cycle_health 0 "steady-state" "$owner_vm" "$owner_name" 0
	validate_external_connectivity "steady-state"

	zero_intervals="$(count_recent_zero_intervals "$PRE_FAILOVER_OBSERVE")"
	if [[ "$zero_intervals" -le "$MAX_PREFLIGHT_ZERO_INTERVALS" ]]; then
		pass "steady-state preflight: ${zero_intervals} zero-throughput intervals (<= ${MAX_PREFLIGHT_ZERO_INTERVALS})"
	else
		fail "steady-state preflight: ${zero_intervals} zero-throughput intervals (> ${MAX_PREFLIGHT_ZERO_INTERVALS})"
	fi

	stream_zero_intervals="$(count_recent_stream_zero_intervals "$PRE_FAILOVER_OBSERVE")"
	zero_streams="$(count_recent_zero_streams "$PRE_FAILOVER_OBSERVE")"
	if [[ "$stream_zero_intervals" -le "$MAX_PREFLIGHT_STREAM_ZERO_INTERVALS" ]]; then
		pass "steady-state preflight: ${stream_zero_intervals} per-stream zero-throughput intervals (<= ${MAX_PREFLIGHT_STREAM_ZERO_INTERVALS})"
	else
		fail "steady-state preflight: ${stream_zero_intervals} per-stream zero-throughput intervals across ${zero_streams} stream(s) (> ${MAX_PREFLIGHT_STREAM_ZERO_INTERVALS})"
	fi
}

run_failover_phase() {
	local cycle="$1"
	local from_node="$2"
	local to_node="$3"
	local phase="$4"
	local final_phase="$5"
	local from_vm to_vm to_name
	from_vm="$(vm_for_node "$from_node")"
	to_vm="$(vm_for_node "$to_node")"
	to_name="$(node_name "$to_node")"
	local from_name
	from_name="$(node_name "$from_node")"

	info "cycle ${cycle}: ${phase} RG${RG} to ${to_name}"
	capture_cycle_state "$cycle" "${phase}-pre"
	run_vm "$from_vm" "cli -c \"request chassis cluster failover redundancy-group ${RG} node ${to_node}\" >/tmp/userspace-rg${RG}-${phase}-cycle${cycle}.out"
	wait_for_rg_owner "$RG" "$to_node" "$FAILOVER_WAIT" || die "RG${RG} did not move to ${to_name} during cycle ${cycle} ${phase}"
	pass "cycle ${cycle} ${phase}: RG${RG} moved to ${to_name}"
	ACTIVE_FW="$(wait_for_userspace_rg_owner "$RG" "$to_vm")" ||
		die "userspace forwarding did not settle on ${to_name}" \
			"during cycle ${cycle} ${phase}"
	pass "cycle ${cycle} ${phase}: userspace forwarding active on ${ACTIVE_FW}"
	capture_cycle_state "$cycle" "$phase"
	validate_target_connectivity "cycle ${cycle} ${phase}"
	validate_external_connectivity "cycle${cycle}-${phase}"
	local transition_seconds remaining_interval
	transition_seconds="$TRANSITION_SAMPLE_SECONDS"
	if (( transition_seconds > CYCLE_INTERVAL )); then
		transition_seconds="$CYCLE_INTERVAL"
	fi
	if (( transition_seconds > 0 )); then
		capture_transition_window "$cycle" "$phase" "$transition_seconds"
		validate_transition_window "$cycle" "$phase" "$from_vm" "$from_name" "$to_vm" "$to_name" "$transition_seconds"
	fi
	remaining_interval=$(( CYCLE_INTERVAL - transition_seconds ))
	if (( remaining_interval > 0 )); then
		if ! cycle_sleep "$remaining_interval" "$final_phase"; then
			fail "cycle ${cycle} ${phase}: iperf3 exited before ${CYCLE_INTERVAL}s interval elapsed"
		fi
	fi
	capture_cycle_state "$cycle" "${phase}-post"
	validate_cycle_health "$cycle" "$phase" "$to_vm" "$to_name" "$final_phase"
	validate_phase_fabric_path "$cycle" "$phase" "$from_vm" "$from_name" "$to_vm" "$to_name"
	validate_target_connectivity "cycle ${cycle} ${phase} post"
	validate_external_connectivity "cycle${cycle}-${phase}-post"
}

restore_cluster() {
	if [[ "${RESTORE_SOURCE_NODE}" != "1" ]]; then
		return 0
	fi
	info "restoring RG${RG} to $(node_name "$SOURCE_NODE")"
	for vm in "$FW0" "$FW1"; do
		run_vm "$vm" "cli -c \"request chassis cluster failover reset redundancy-group ${RG}\" >/tmp/userspace-rg${RG}-reset.out" >/dev/null 2>&1 || true
	done
	sleep 1
	run_vm "$FW0" "cli -c \"request chassis cluster failover redundancy-group ${RG} node ${SOURCE_NODE}\" >/tmp/userspace-rg${RG}-restore.out" >/dev/null 2>&1 || true
	wait_for_rg_owner "$RG" "$SOURCE_NODE" 45 || true
}

cleanup() {
	copy_artifacts
	run_host "systemctl stop ${REMOTE_IPERF_UNIT} >/dev/null 2>&1 || true; systemctl reset-failed ${REMOTE_IPERF_UNIT} >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
	restore_cluster
	printf 'Artifacts: %s\n' "${ARTIFACT_DIR}"
}
trap cleanup EXIT

mkdir -p "${ARTIFACT_DIR}"

min_duration="$(required_iperf_duration "$TOTAL_CYCLES" "$CYCLE_INTERVAL")"
if (( IPERF_DURATION < min_duration )); then
	die "iperf duration ${IPERF_DURATION}s too short for ${TOTAL_CYCLES} cycle(s); need at least ${min_duration}s"
fi

if [[ $DEPLOY -eq 1 ]]; then
	info "deploying isolated userspace cluster from ${ENV_FILE}"
	BPFRX_CLUSTER_ENV="$ENV_FILE" "${PROJECT_ROOT}/test/incus/cluster-setup.sh" deploy all
fi

info "waiting for xpfd CLI readiness"
wait_for_vm_cli "$FW0" || die "fw0 CLI did not become reachable in time"
wait_for_vm_cli "$FW1" || die "fw1 CLI did not become reachable in time"

ensure_rg_owner "$RG" "$SOURCE_NODE"
arm_userspace_runtime

info "validating basic reachability to ${IPERF_TARGET}"
validate_target_reachability || die "cluster host cannot reach ${IPERF_TARGET}"

SOURCE_VM="$(vm_for_node "$SOURCE_NODE")"
TARGET_VM="$(vm_for_node "$TARGET_NODE")"
validate_clean_session_baseline
capture_vm_state "$SOURCE_VM" "before-source"
capture_vm_state "$TARGET_VM" "before-target"
wait_for_session_sync_idle "pre-traffic"

info "starting iperf3 ${IPERF_TARGET} -P${IPERF_STREAMS} -t${IPERF_DURATION}"
start_iperf || die "iperf3 failed to start"
pass "iperf3 started"

source_count="$(session_count "$SOURCE_VM")"
if [[ "$source_count" -lt "$MIN_SESSIONS" ]]; then
	info "source owner has only ${source_count} sessions before sync wait; continuing to steady-state validation"
else
	pass "source owner has ${source_count} sessions"
fi

info "waiting ${SYNC_WAIT}s for session sync to peer"
sleep "${SYNC_WAIT}"
wait_for_session_sync_idle "pre-failover"
if [[ "${CHECK_KERNEL_SESSION_TABLE}" == "1" ]]; then
	target_count="$(session_count "$TARGET_VM")"
	if [[ "$target_count" -lt "$MIN_SESSIONS" ]]; then
		fail "target owner has only ${target_count} synced sessions (expected >= ${MIN_SESSIONS})"
	else
		pass "target owner has ${target_count} synced sessions"
	fi
fi

validate_pre_failover_health "$SOURCE_VM" "$(node_name "$SOURCE_NODE")"

if (( STEADY_ONLY == 1 )); then
	info "steady-only mode: skipping RG${RG} failover"
elif (( TOTAL_CYCLES == 1 )); then
	run_failover_phase 1 "$SOURCE_NODE" "$TARGET_NODE" "failover" 1
else
	run_failover_phase 1 "$SOURCE_NODE" "$TARGET_NODE" "failover" 0
fi

if (( STEADY_ONLY == 1 )); then
	capture_vm_state "$SOURCE_VM" "steady-only-source"
	capture_vm_state "$TARGET_VM" "steady-only-target"
	wait_for_iperf_finish || true
	copy_artifacts
elif (( TOTAL_CYCLES == 1 )); then
	capture_vm_state "$SOURCE_VM" "after-source"
	capture_vm_state "$TARGET_VM" "after-target"

	if iperf_alive; then
		pass "iperf3 survived immediate failover"
	elif iperf_effectively_completed_remote; then
		pass "iperf3 completed during immediate post-failover window"
	else
		fail "iperf3 died immediately after failover"
	fi

	info "observing post-failover traffic for ${POST_FAILOVER_OBSERVE}s"
	cycle_sleep "${POST_FAILOVER_OBSERVE}" 1 || true
	if iperf_alive; then
		pass "iperf3 still alive after post-failover observe window"
	elif iperf_effectively_completed_remote; then
		pass "iperf3 completed during post-failover observe window"
	else
		fail "iperf3 died during post-failover observe window"
	fi
else
	for (( cycle = 1; cycle <= TOTAL_CYCLES; cycle++ )); do
		failover_final_phase=0
		if (( cycle == TOTAL_CYCLES )); then
			failover_final_phase=1
		fi
		if (( cycle > 1 )); then
			run_failover_phase "$cycle" "$SOURCE_NODE" "$TARGET_NODE" "failover" "$failover_final_phase"
		fi
		failback_final_phase=0
		if (( cycle == TOTAL_CYCLES )); then
			failback_final_phase=1
		fi
		run_failover_phase "$cycle" "$TARGET_NODE" "$SOURCE_NODE" "failback" "$failback_final_phase"
	done
fi

wait_for_iperf_finish || true
copy_artifacts

if (( IPERF_WAIT_TIMEOUT_HIT == 1 )); then
	fail "iperf3 did not exit within ${IPERF_DURATION}s + 20s grace; terminated remote client"
fi

zero_intervals="$(count_zero_intervals)"
if [[ "$zero_intervals" -le "$MAX_ZERO_INTERVALS" ]]; then
	pass "${zero_intervals} zero-throughput intervals (<= ${MAX_ZERO_INTERVALS})"
else
	fail "${zero_intervals} zero-throughput intervals (> ${MAX_ZERO_INTERVALS})"
fi

stream_zero_intervals="$(count_stream_zero_intervals)"
zero_streams="$(count_zero_streams)"
if [[ "$stream_zero_intervals" -le "$MAX_STREAM_ZERO_INTERVALS" ]]; then
	pass "${stream_zero_intervals} per-stream zero-throughput intervals (<= ${MAX_STREAM_ZERO_INTERVALS})"
else
	fail "${stream_zero_intervals} per-stream zero-throughput intervals across ${zero_streams} stream(s) (> ${MAX_STREAM_ZERO_INTERVALS})"
fi

throughput="$(extract_sender_throughput)"
if awk "BEGIN{exit !(${throughput} >= ${MIN_THROUGHPUT})}"; then
	pass "sender throughput ${throughput} Gbps"
else
	fail "sender throughput too low: ${throughput} Gbps"
fi

retransmits="$(extract_retransmits)"
pass "sender retransmits ${retransmits}"
if [[ -n "${MAX_RETRANSMITS}" ]]; then
	if [[ "${retransmits}" -le "${MAX_RETRANSMITS}" ]]; then
		pass "retransmits ${retransmits} within limit ${MAX_RETRANSMITS}"
	else
		fail "retransmits ${retransmits} exceed limit ${MAX_RETRANSMITS}"
	fi
fi

if [[ -n "${MAX_RETRANSMITS_PER_GBPS}" ]]; then
	retrans_per_gb="$(awk "BEGIN{if (${throughput} <= 0) {print 0} else {printf \"%.3f\", ${retransmits} / ${throughput}}}")"
	if awk "BEGIN{exit !(${retrans_per_gb} <= ${MAX_RETRANSMITS_PER_GBPS})}"; then
		pass "retransmits per Gbps ${retrans_per_gb} within limit ${MAX_RETRANSMITS_PER_GBPS}"
	else
		fail "retransmits per Gbps ${retrans_per_gb} exceed limit ${MAX_RETRANSMITS_PER_GBPS}"
	fi
fi

if iperf_collapse_detected; then
	fail "iperf3 interval collapse detected: $(iperf_collapse_reason)"
else
	pass "iperf3 interval collapse not detected"
fi

if iperf_completed_local; then
	pass "iperf3 completed successfully"
elif iperf_effectively_completed_local && awk "BEGIN{exit !(${throughput} >= ${MIN_THROUGHPUT})}"; then
	pass "iperf3 data transfer completed with adequate throughput despite control socket disruption"
elif awk "BEGIN{exit !(${throughput} >= ${MIN_THROUGHPUT})}"; then
	pass "iperf3 data transfer completed with adequate throughput despite control socket disruption"
else
	fail "iperf3 did not complete successfully"
fi

if (( FAILED != 0 )); then
	exit 1
fi
