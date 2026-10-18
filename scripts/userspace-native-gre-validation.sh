#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"
DEPLOY=0
FAILOVER=0
IPERF=0
UDP=0
TRACEROUTE=0
GRE_TARGET="${GRE_TARGET:-10.255.192.41}"
GRE_TCP_TARGET="${GRE_TCP_TARGET:-${GRE_TARGET}}"
GRE_TCP_PORT="${GRE_TCP_PORT:-22}"
GRE_TCP_RETRIES="${GRE_TCP_RETRIES:-3}"
GRE_TCP_RETRY_SLEEP="${GRE_TCP_RETRY_SLEEP:-0.2}"
GRE_IPERF_TARGET="${GRE_IPERF_TARGET:-${GRE_TARGET}}"
GRE_IPERF_PORT="${GRE_IPERF_PORT:-5201}"
GRE_IPERF_DURATION="${GRE_IPERF_DURATION:-20}"
GRE_IPERF_PARALLEL="${GRE_IPERF_PARALLEL:-1}"
GRE_IPERF_MIN_GBPS="${GRE_IPERF_MIN_GBPS:-1.0}"
GRE_HOST_IPERF_DURATION="${GRE_HOST_IPERF_DURATION:-${GRE_IPERF_DURATION}}"
GRE_HOST_IPERF_PARALLEL="${GRE_HOST_IPERF_PARALLEL:-1}"
GRE_HOST_IPERF_MIN_GBPS="${GRE_HOST_IPERF_MIN_GBPS:-0.5}"
GRE_UDP_TARGET="${GRE_UDP_TARGET:-${GRE_TARGET}}"
GRE_UDP_PORT="${GRE_UDP_PORT:-33434}"
GRE_UDP_BURST_COUNT="${GRE_UDP_BURST_COUNT:-100}"
GRE_UDP_INTERVAL_MS="${GRE_UDP_INTERVAL_MS:-10}"
GRE_UDP_PAYLOAD_SIZE="${GRE_UDP_PAYLOAD_SIZE:-256}"
GRE_TRACEROUTE_TARGET="${GRE_TRACEROUTE_TARGET:-${GRE_TARGET}}"
GRE_TRACEROUTE_MAX_HOPS="${GRE_TRACEROUTE_MAX_HOPS:-4}"
GRE_TRACEROUTE_CYCLES="${GRE_TRACEROUTE_CYCLES:-3}"
GRE_VALIDATE_HOST_PROBES="${GRE_VALIDATE_HOST_PROBES:-0}"
GRE_OUTER_REMOTE="${GRE_OUTER_REMOTE:-2602:ffd3:0:2::7}"
GRE_LOGICAL_DEV="${GRE_LOGICAL_DEV:-gr-0-0-0}"
PING_COUNT="${PING_COUNT:-5}"
GRE_PING_RETRIES="${GRE_PING_RETRIES:-3}"
GRE_PING_RETRY_SLEEP="${GRE_PING_RETRY_SLEEP:-0.2}"
FAILOVER_PING_COUNT="${FAILOVER_PING_COUNT:-40}"
FAILOVER_PREP_SECS="${FAILOVER_PREP_SECS:-3}"
PREFERRED_ACTIVE_NODE="${PREFERRED_ACTIVE_NODE:-1}"
PREFERRED_ACTIVE_RGS="${PREFERRED_ACTIVE_RGS:-1 2}"
TRANSIT_PING_ID="${TRANSIT_PING_ID:-$(( ( ( $$ + RANDOM ) % 60000 ) + 1024 ))}"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--deploy) DEPLOY=1 ;;
	--failover) FAILOVER=1 ;;
	--iperf) IPERF=1 ;;
	--udp) UDP=1 ;;
	--traceroute) TRACEROUTE=1 ;;
	--env) ENV_FILE="$2"; shift ;;
	--target) GRE_TARGET="$2"; shift ;;
	--outer-remote) GRE_OUTER_REMOTE="$2"; shift ;;
	--logical-dev) GRE_LOGICAL_DEV="$2"; shift ;;
	--count) PING_COUNT="$2"; shift ;;
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
ACTIVE_FW="${FW0}"
OUTER_DEV=""

info() { printf '==> %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

tcp_probe_cmd() {
	local target="$1"
	local port="$2"
	printf 'timeout 2 bash -lc %q' "exec 3<>/dev/tcp/${target}/${port}"
}

run_host_tcp_probe_with_retry() {
	local target="$1"
	local port="$2"
	local tries="${3:-$GRE_TCP_RETRIES}"
	local sleep_secs="${4:-$GRE_TCP_RETRY_SLEEP}"
	local attempt=1
	while (( attempt <= tries )); do
		if run_host "$(tcp_probe_cmd "${target}" "${port}") >/dev/null 2>&1"; then
			return 0
		fi
		if (( attempt < tries )); then
			sleep "${sleep_secs}"
		fi
		attempt=$((attempt + 1))
	done
	return 1
}

run_host_ping_with_retry() {
	local target="$1"
	local ping_id="$2"
	local tries="${3:-$GRE_PING_RETRIES}"
	local sleep_secs="${4:-$GRE_PING_RETRY_SLEEP}"
	local attempt=1
	while (( attempt <= tries )); do
		run_host "ping -c ${PING_COUNT} -W 1 -e ${ping_id} ${target} >/tmp/userspace-native-gre-ping.out 2>&1 || true"
		local output
		output="$(run_host 'cat /tmp/userspace-native-gre-ping.out')"
		printf '%s\n' "$output"
		if grep -q 'bytes from' <<<"$output"; then
			return 0
		fi
		if (( attempt < tries )); then
			sleep "${sleep_secs}"
		fi
		attempt=$((attempt + 1))
	done
	return 1
}

run_iperf_stream_to_log() {
	local log_path="$1"
	local target="$2"
	local port="$3"
	local duration="$4"
	local parallel="$5"
	local extra="${6:-}"
	local cmd="iperf3 -c ${target} -p ${port} -P ${parallel} -t ${duration}"
	if [[ -n "$extra" ]]; then
		cmd+=" ${extra}"
	fi
	cmd+=" --json-stream"
	sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "${cmd}")" >"${log_path}" 2>&1 || true
}

run_vm_iperf_stream_to_log() {
	local log_path="$1"
	local vm="$2"
	local target="$3"
	local port="$4"
	local duration="$5"
	local parallel="$6"
	local extra="${7:-}"
	local cmd="iperf3 -c ${target} -p ${port} -P ${parallel} -t ${duration}"
	if [[ -n "$extra" ]]; then
		cmd+=" ${extra}"
	fi
	cmd+=" --json-stream"
	sg incus-admin -c "incus exec ${vm} -- bash -lc $(printf %q "${cmd}")" >"${log_path}" 2>&1 || true
}

summarize_iperf_log() {
	local log_path="$1"
	python3 "${PROJECT_ROOT}/scripts/iperf-json-metrics.py" \
		"${log_path}" \
		--min-peak-gbps "${GRE_IPERF_MIN_GBPS}"
}

summarize_iperf_log_with_threshold() {
	local log_path="$1"
	local min_peak="$2"
	python3 "${PROJECT_ROOT}/scripts/iperf-json-metrics.py" \
		"${log_path}" \
		--min-peak-gbps "${min_peak}"
}

assert_iperf_log_healthy() {
	local log_path="$1"
	local label="$2"
	local summary
	summary="$(summarize_iperf_log "${log_path}")"
	assert_iperf_summary_healthy "$summary" "$GRE_IPERF_MIN_GBPS" "$label"
}

assert_iperf_log_healthy_with_threshold() {
	local log_path="$1"
	local label="$2"
	local min_gbps="$3"
	local summary
	summary="$(summarize_iperf_log_with_threshold "${log_path}" "${min_gbps}")"
	assert_iperf_summary_healthy "$summary" "$min_gbps" "$label"
}

assert_iperf_summary_healthy() {
	local summary="$1"
	local min_gbps="$2"
	local label="$3"
	printf '%s\n' "$summary"
	python3 - "$summary" "$min_gbps" "$label" <<'PY'
import json
import sys

summary = json.loads(sys.argv[1])
min_gbps = float(sys.argv[2])
label = sys.argv[3]

if not summary.get("ok"):
    raise SystemExit(f"{label}: failed to parse iperf log: {summary.get('error')}")
if not summary.get("completed"):
    raise SystemExit(f"{label}: iperf did not complete")
if summary.get("collapse_detected"):
    raise SystemExit(f"{label}: iperf collapsed: {summary.get('collapse_reason')}")
if float(summary.get("avg_gbps") or 0.0) < min_gbps:
    raise SystemExit(
        f"{label}: avg_gbps {float(summary.get('avg_gbps') or 0.0):.3f} below {min_gbps:.3f}"
    )
if int(summary.get("zero_intervals_total") or 0) > 0:
    raise SystemExit(
        f"{label}: observed {int(summary.get('zero_intervals_total') or 0)} zero interval(s)"
    )
PY
}

run_host() {
	sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "$1")"
}

run_vm() {
	local vm="$1"
	shift
	sg incus-admin -c "incus exec ${vm} -- bash -lc $(printf %q "$1")"
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

rg_primary_node() {
	local vm="$1"
	local rg="$2"
	local status
	status="$(run_vm "$vm" 'cli -c "show chassis cluster status"' 2>/dev/null || true)"
	if grep -Eq "Redundancy group: ${rg} " <<<"$status"; then
		awk -v rg="$rg" '
			$0 ~ ("Redundancy group: " rg " ") { in_rg=1; next }
			in_rg && /^Redundancy group:/ { in_rg=0 }
			in_rg && /primary/ { print $1; exit }
		' <<<"$status"
	fi
}

assert_logical_anchor_is_tun() {
	local vm="$1"
	local link
	link="$(run_vm "$vm" "ip -d link show ${GRE_LOGICAL_DEV}" 2>/dev/null || true)"
	printf '%s\n' "$link"
	grep -q 'tun type tun' <<<"$link" || die "${GRE_LOGICAL_DEV} is not a persistent TUN anchor on ${vm}"
}

cluster_rg_primary_node() {
	local rg="$1"
	local primary=""
	primary="$(rg_primary_node "$FW0" "$rg" || true)"
	if [[ -n "$primary" ]]; then
		printf '%s\n' "$primary"
		return 0
	fi
	primary="$(rg_primary_node "$FW1" "$rg" || true)"
	if [[ -n "$primary" ]]; then
		printf '%s\n' "$primary"
		return 0
	fi
	return 1
}

primary_vm_for_rg() {
	local rg="$1"
	local primary=""
	primary="$(cluster_rg_primary_node "$rg" || true)"
	case "$primary" in
	node0) printf '%s\n' "$FW0" ;;
	node1) printf '%s\n' "$FW1" ;;
	esac
}

derive_outer_dev() {
	local vm="$1"
	run_vm "$vm" "set -- \$(ip -6 route get ${GRE_OUTER_REMOTE} 2>/dev/null); while (( \$# > 0 )); do if [[ \$1 == dev ]]; then printf '%s\n' \"\$2\"; break; fi; shift; done | head -n 1"
}

pin_active_node() {
	local target_node="$1"
	local preferred_name="node0"
	if [[ "$target_node" == "1" ]]; then
		preferred_name="node1"
	fi
	info "pinning native GRE validation to ${preferred_name} for RGs:${PREFERRED_ACTIVE_RGS}"
	for rg in $PREFERRED_ACTIVE_RGS; do
		local current=""
		current="$(cluster_rg_primary_node "$rg" || true)"
		if [[ "$current" == "$preferred_name" ]]; then
			continue
		fi
		run_vm "$FW0" "cli -c \"request chassis cluster failover redundancy-group ${rg} node ${target_node}\" >/tmp/userspace-native-gre-rg${rg}.out"
	done
	local tries=45
	while (( tries > 0 )); do
		local all_good=1
		for rg in $PREFERRED_ACTIVE_RGS; do
			local current=""
			current="$(cluster_rg_primary_node "$rg" || true)"
			if [[ "$current" != "$preferred_name" ]]; then
				all_good=0
				break
			fi
		done
		if (( all_good == 1 )); then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	die "preferred active node ${preferred_name} did not take over RGs:${PREFERRED_ACTIVE_RGS}"
}

enabled_userspace_vm() {
	local vm="$1"
	local stats
	stats="$(run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"' 2>/dev/null || true)"
	grep -Eq 'Enabled:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Ready bindings:[[:space:]]+[1-9][0-9]*/[0-9]+' <<<"$stats"
}

wait_for_userspace_vm() {
	local vm="$1"
	local tries=45
	while (( tries > 0 )); do
		if enabled_userspace_vm "$vm" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

arm_supported_runtime() {
	local primary_rg primary_vm
	primary_rg="${PREFERRED_ACTIVE_RGS%% *}"
	[[ -n "$primary_rg" ]] || die "no preferred active RG configured"
	primary_vm="$(primary_vm_for_rg "$primary_rg")"
	[[ -n "$primary_vm" ]] || die "failed to determine RG${primary_rg} primary VM"
	info "waiting for userspace forwarding to arm"
	if wait_for_userspace_vm "$primary_vm"; then
		ACTIVE_FW="$primary_vm"
		OUTER_DEV="$(derive_outer_dev "$ACTIVE_FW")"
		[[ -n "$OUTER_DEV" ]] || die "failed to derive outer device for ${GRE_OUTER_REMOTE} on ${ACTIVE_FW}"
		info "active userspace firewall: ${ACTIVE_FW}"
		return 0
	fi
	run_vm "$FW0" 'cli -c "request chassis cluster data-plane userspace forwarding arm" >/tmp/userspace-native-gre-arm.out'
	wait_for_userspace_vm "$primary_vm" || die "userspace runtime did not arm on ${primary_vm}"
	ACTIVE_FW="$primary_vm"
	OUTER_DEV="$(derive_outer_dev "$ACTIVE_FW")"
	[[ -n "$OUTER_DEV" ]] || die "failed to derive outer device for ${GRE_OUTER_REMOTE} on ${ACTIVE_FW}"
	info "active userspace firewall: ${ACTIVE_FW}"
}

read_link_packets() {
	local vm="$1"
	local dev="$2"
	run_vm "$vm" "printf '%s %s\n' \$(cat /sys/class/net/${dev}/statistics/rx_packets) \$(cat /sys/class/net/${dev}/statistics/tx_packets)"
}

assert_outer_only_link_activity() {
	local label="$1"
	local before_outer="$2"
	local after_outer="$3"
	local before_logical="$4"
	local after_logical="$5"

	local outer_rx_before outer_tx_before outer_rx_after outer_tx_after
	local logical_rx_before logical_tx_before logical_rx_after logical_tx_after
	read -r outer_rx_before outer_tx_before <<<"$before_outer"
	read -r outer_rx_after outer_tx_after <<<"$after_outer"
	read -r logical_rx_before logical_tx_before <<<"$before_logical"
	read -r logical_rx_after logical_tx_after <<<"$after_logical"

	local outer_rx_delta=$((outer_rx_after - outer_rx_before))
	local outer_tx_delta=$((outer_tx_after - outer_tx_before))
	local logical_rx_delta=$((logical_rx_after - logical_rx_before))
	local logical_tx_delta=$((logical_tx_after - logical_tx_before))

	printf '%s outer_dev=%s outer_rx_delta=%d outer_tx_delta=%d logical_dev=%s logical_rx_delta=%d logical_tx_delta=%d\n' \
		"$label" "$OUTER_DEV" "$outer_rx_delta" "$outer_tx_delta" "$GRE_LOGICAL_DEV" "$logical_rx_delta" "$logical_tx_delta"

	(( outer_rx_delta > 0 || outer_tx_delta > 0 )) || die "${label}: outer device ${OUTER_DEV} saw no GRE traffic"
}

assert_mtr_healthy() {
	local output="$1"
	local target="$2"
	printf '%s\n' "$output"
	grep -q "  1.|-- " <<<"$output" || die "native GRE traceroute: missing first hop"
	# Check that the destination appears on ANY hop (not just hop 2),
	# since intermediate routers may add extra hops.
	grep -q "|-- ${target}" <<<"$output" || die "native GRE traceroute: destination ${target} did not resolve on any hop"
}

run_udp_burst_probe() {
	local target="$1"
	local port="$2"
	local count="$3"
	local interval_ms="$4"
	local payload_size="$5"
	run_host "python3 - <<'PY'
import socket
import time

target = ${target@Q}
port = int(${port@Q})
count = int(${count@Q})
interval_ms = int(${interval_ms@Q})
payload_size = int(${payload_size@Q})
payload = (b'BPFRX-GRE-UDP-' + b'X' * max(0, payload_size - 14))[:payload_size]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(count):
    sock.sendto(payload, (target, port))
    if interval_ms > 0:
        time.sleep(interval_ms / 1000.0)
sock.close()
PY"
}

start_logical_transit_capture() {
	local vm="$1"
	local outfile="$2"
	local filter="$3"
	run_vm "$vm" "rm -f ${outfile}; nohup sh -c \"timeout 6 tcpdump -n -i ${GRE_LOGICAL_DEV} -vv '${filter}' >${outfile} 2>&1\" >/dev/null 2>&1 &"
}

logical_transit_matches() {
	local vm="$1"
	local outfile="$2"
	local capture
	capture="$(run_vm "$vm" "cat ${outfile} 2>/dev/null || true")"
	printf '%s\n' "$capture" >&2
	grep -cE '^[0-9:.]+ (IP|IP6) ' <<<"$capture" || true
}

if (( DEPLOY == 1 )); then
	info "deploying isolated userspace cluster from ${ENV_FILE}"
	BPFRX_CLUSTER_ENV="$ENV_FILE" "${PROJECT_ROOT}/test/incus/cluster-setup.sh" deploy all
fi

wait_for_vm_cli "$FW0" || die "fw0 xpfd did not become reachable in time"
wait_for_vm_cli "$FW1" || die "fw1 xpfd did not become reachable in time"
wait_for_cluster_primary() {
	local rg="$1"
	local tries=60
	while (( tries > 0 )); do
		if cluster_rg_primary_node "$rg" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

wait_for_cluster_settle() {
	info "waiting for cluster primaries to settle"
	for rg in $PREFERRED_ACTIVE_RGS; do
		wait_for_cluster_primary "$rg" || die "RG${rg} did not elect a primary after deploy"
	done
}

if (( DEPLOY == 1 )); then
	wait_for_cluster_settle
fi
pin_active_node "$PREFERRED_ACTIVE_NODE"
arm_supported_runtime

[[ -n "$OUTER_DEV" ]] || die "failed to derive outer device for ${GRE_OUTER_REMOTE}"
run_vm "$ACTIVE_FW" "[ -d /sys/class/net/${GRE_LOGICAL_DEV} ]" >/dev/null 2>&1 || die "missing logical GRE device ${GRE_LOGICAL_DEV}"
if (( GRE_VALIDATE_HOST_PROBES == 1 )); then
	assert_logical_anchor_is_tun "$ACTIVE_FW"
fi

before_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
before_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
logical_capture_file="/tmp/userspace-native-gre-logical-capture.out"
start_logical_transit_capture "$ACTIVE_FW" "$logical_capture_file" "icmp and host ${GRE_TARGET} and icmp[4:2] == ${TRANSIT_PING_ID}"

info "running GRE transit probe to ${GRE_TARGET} from ${HOST}"
run_host_ping_with_retry "${GRE_TARGET}" "${TRANSIT_PING_ID}" || die "GRE ping failed"
sleep 4

after_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
after_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
logical_matches="$(logical_transit_matches "$ACTIVE_FW" "$logical_capture_file")"

read -r outer_rx_before outer_tx_before <<<"$before_outer"
read -r outer_rx_after outer_tx_after <<<"$after_outer"
read -r logical_rx_before logical_tx_before <<<"$before_logical"
read -r logical_rx_after logical_tx_after <<<"$after_logical"

outer_rx_delta=$((outer_rx_after - outer_rx_before))
outer_tx_delta=$((outer_tx_after - outer_tx_before))
logical_rx_delta=$((logical_rx_after - logical_rx_before))
logical_tx_delta=$((logical_tx_after - logical_tx_before))

printf 'outer_dev=%s outer_rx_delta=%d outer_tx_delta=%d logical_dev=%s logical_rx_delta=%d logical_tx_delta=%d logical_probe_matches=%d ping_id=%d\n' \
	"$OUTER_DEV" "$outer_rx_delta" "$outer_tx_delta" "$GRE_LOGICAL_DEV" "$logical_rx_delta" "$logical_tx_delta" "$logical_matches" "$TRANSIT_PING_ID"

(( outer_rx_delta > 0 )) || die "outer device ${OUTER_DEV} saw no GRE receive traffic"
(( outer_tx_delta > 0 )) || die "outer device ${OUTER_DEV} saw no GRE transmit traffic"
(( logical_matches == 0 )) || die "logical GRE device ${GRE_LOGICAL_DEV} still received tagged transit packets"

pass "native GRE transit stayed on ${OUTER_DEV} and off ${GRE_LOGICAL_DEV}"

info "running GRE TCP probe to ${GRE_TCP_TARGET}:${GRE_TCP_PORT} from ${HOST}"
run_host "$(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/tmp/userspace-native-gre-host-tcp.out 2>&1 || true"
host_tcp_output="$(run_host 'cat /tmp/userspace-native-gre-host-tcp.out 2>/dev/null || true')"
printf '%s\n' "$host_tcp_output"
run_host_tcp_probe_with_retry "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}" || die "GRE TCP connect from ${HOST} failed"

pass "native GRE transit TCP connect works from ${HOST}"

if (( GRE_VALIDATE_HOST_PROBES == 1 )); then
	info "running firewall-originated GRE probe from ${ACTIVE_FW}"
	run_vm "$ACTIVE_FW" "ping -c ${PING_COUNT} -W 1 ${GRE_TARGET} >/tmp/userspace-native-gre-host-ping.out 2>&1 || true"
	host_ping_output="$(run_vm "$ACTIVE_FW" 'cat /tmp/userspace-native-gre-host-ping.out')"
	printf '%s\n' "$host_ping_output"
	grep -q 'bytes from' <<<"$host_ping_output" || die "firewall-originated GRE ping failed"

	pass "native GRE host/control-plane traffic still works on ${ACTIVE_FW}"

	info "running firewall-originated GRE TCP probe from ${ACTIVE_FW}"
	run_vm "$ACTIVE_FW" "$(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/tmp/userspace-native-gre-fw-tcp.out 2>&1 || true"
	host_tcp_output="$(run_vm "$ACTIVE_FW" 'cat /tmp/userspace-native-gre-fw-tcp.out 2>/dev/null || true')"
	printf '%s\n' "$host_tcp_output"
	run_vm "$ACTIVE_FW" "$(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/dev/null 2>&1" || die "firewall-originated GRE TCP connect failed"

	pass "native GRE host/control-plane TCP connect works on ${ACTIVE_FW}"
	if (( IPERF == 1 )); then
		info "running firewall-originated GRE iperf3 probe to ${GRE_IPERF_TARGET}:${GRE_IPERF_PORT} from ${ACTIVE_FW}"
		host_iperf_log="$(mkdir -p /var/worktrees/.cache/tmpdir && TMPDIR=/var/worktrees/.cache/tmpdir mktemp)"
		run_vm_iperf_stream_to_log "${host_iperf_log}" "${ACTIVE_FW}" "${GRE_IPERF_TARGET}" "${GRE_IPERF_PORT}" "${GRE_HOST_IPERF_DURATION}" "${GRE_HOST_IPERF_PARALLEL}"
		assert_iperf_log_healthy_with_threshold "${host_iperf_log}" "host native GRE iperf" "${GRE_HOST_IPERF_MIN_GBPS}"
		rm -f "${host_iperf_log}"
		pass "native GRE host/control-plane iperf stayed up from ${ACTIVE_FW}"
	fi
fi

if (( IPERF == 1 )); then
	info "running GRE iperf3 probe to ${GRE_IPERF_TARGET}:${GRE_IPERF_PORT} from ${HOST}"
	iperf_log="$(mkdir -p /var/worktrees/.cache/tmpdir && TMPDIR=/var/worktrees/.cache/tmpdir mktemp)"
	run_iperf_stream_to_log "${iperf_log}" "${GRE_IPERF_TARGET}" "${GRE_IPERF_PORT}" "${GRE_IPERF_DURATION}" "${GRE_IPERF_PARALLEL}"
	assert_iperf_log_healthy "${iperf_log}" "steady native GRE iperf"
	rm -f "${iperf_log}"
	pass "native GRE iperf stayed up from ${HOST}"
fi

if (( UDP == 1 )); then
	info "running GRE UDP probe to ${GRE_UDP_TARGET}:${GRE_UDP_PORT} from ${HOST}"
	udp_before_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
	udp_before_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
	udp_capture_file="/tmp/userspace-native-gre-udp-capture.out"
	start_logical_transit_capture "$ACTIVE_FW" "$udp_capture_file" "udp and host ${GRE_UDP_TARGET} and port ${GRE_UDP_PORT}"
	run_udp_burst_probe "${GRE_UDP_TARGET}" "${GRE_UDP_PORT}" "${GRE_UDP_BURST_COUNT}" "${GRE_UDP_INTERVAL_MS}" "${GRE_UDP_PAYLOAD_SIZE}"
	sleep 2
	udp_after_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
	udp_after_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
	udp_matches="$(logical_transit_matches "$ACTIVE_FW" "$udp_capture_file")"
	assert_outer_only_link_activity \
		"steady_native_gre_udp" \
		"${udp_before_outer}" \
		"${udp_after_outer}" \
		"${udp_before_logical}" \
		"${udp_after_logical}"
	(( udp_matches == 0 )) || die "native GRE UDP probe still hit ${GRE_LOGICAL_DEV}"
	pass "native GRE UDP transit stayed on ${OUTER_DEV} and off ${GRE_LOGICAL_DEV}"
fi

if (( TRACEROUTE == 1 )); then
	info "running GRE traceroute probe to ${GRE_TRACEROUTE_TARGET} from ${HOST}"
	mtr_before_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
	mtr_before_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
	mtr_capture_file="/tmp/userspace-native-gre-mtr-capture.out"
	start_logical_transit_capture "$ACTIVE_FW" "$mtr_capture_file" "icmp and host ${GRE_TRACEROUTE_TARGET}"
	mtr_output="$(run_host "mtr -n ${GRE_TRACEROUTE_TARGET} --report --report-cycles=${GRE_TRACEROUTE_CYCLES} --max-ttl ${GRE_TRACEROUTE_MAX_HOPS}" || true)"
	assert_mtr_healthy "$mtr_output" "${GRE_TRACEROUTE_TARGET}"
	mtr_after_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
	mtr_after_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
	mtr_matches="$(logical_transit_matches "$ACTIVE_FW" "$mtr_capture_file")"
	assert_outer_only_link_activity \
		"steady_native_gre_mtr" \
		"${mtr_before_outer}" \
		"${mtr_after_outer}" \
		"${mtr_before_logical}" \
		"${mtr_after_logical}"
	if (( GRE_VALIDATE_HOST_PROBES == 0 )); then
		(( mtr_matches == 0 )) || die "native GRE traceroute still hit ${GRE_LOGICAL_DEV}"
	fi
	pass "native GRE traceroute works from ${HOST}"
fi

if (( FAILOVER == 1 )); then
	current_node="$PREFERRED_ACTIVE_NODE"
	failover_node=0
	if [[ "$current_node" == "0" ]]; then
		failover_node=1
	fi
	info "running active GRE failover probe from ${HOST} while moving RGs to node${failover_node}"
	failover_ping_log=""
	failover_ping_pid=""
	failover_tcp_log=""
	failover_tcp_pid=""
	if (( IPERF == 0 )); then
		failover_ping_log="$(mkdir -p /var/worktrees/.cache/tmpdir && TMPDIR=/var/worktrees/.cache/tmpdir mktemp)"
		sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "ping -i 0.2 -c ${FAILOVER_PING_COUNT} -W 1 ${GRE_TARGET}")" >"${failover_ping_log}" 2>&1 &
		failover_ping_pid=$!
		failover_tcp_log="$(mkdir -p /var/worktrees/.cache/tmpdir && TMPDIR=/var/worktrees/.cache/tmpdir mktemp)"
		sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "for seq in \$(seq 1 ${FAILOVER_PING_COUNT}); do if $(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/dev/null 2>&1; then echo ok seq=\${seq}; else echo fail seq=\${seq}; fi; sleep 0.2; done")" >"${failover_tcp_log}" 2>&1 &
		failover_tcp_pid=$!
	fi
	failover_iperf_log=""
	failover_iperf_pid=""
	if (( IPERF == 1 )); then
		failover_iperf_log="$(mkdir -p /var/worktrees/.cache/tmpdir && TMPDIR=/var/worktrees/.cache/tmpdir mktemp)"
		run_iperf_stream_to_log "${failover_iperf_log}" "${GRE_IPERF_TARGET}" "${GRE_IPERF_PORT}" "${GRE_IPERF_DURATION}" "${GRE_IPERF_PARALLEL}" &
		failover_iperf_pid=$!
	fi
	sleep "$FAILOVER_PREP_SECS"
	pin_active_node "$failover_node"
	arm_supported_runtime
	if [[ -n "$failover_ping_pid" ]]; then
		wait "$failover_ping_pid" || true
	fi
	if [[ -n "$failover_tcp_pid" ]]; then
		wait "$failover_tcp_pid" || true
	fi
	if [[ -n "$failover_iperf_pid" ]]; then
		wait "$failover_iperf_pid" || true
	fi
	if [[ -n "$failover_ping_log" ]]; then
		failover_ping_output="$(cat "${failover_ping_log}")"
		rm -f "${failover_ping_log}"
		printf '%s\n' "$failover_ping_output"
		max_seq="$(awk -F'icmp_seq=' '/bytes from/ { split($2, a, /[[:space:]]+/); if (a[1] > max) max=a[1] } END { print max+0 }' <<<"$failover_ping_output")"
		[[ "$max_seq" -ge $((FAILOVER_PING_COUNT - 5)) ]] || die "active GRE failover ping did not recover near the tail (max_seq=${max_seq})"
		grep -q 'bytes from' <<<"$failover_ping_output" || die "active GRE failover ping produced no replies"
	fi
	if [[ -n "$failover_tcp_log" ]]; then
		failover_tcp_output="$(cat "${failover_tcp_log}")"
		rm -f "${failover_tcp_log}"
		printf '%s\n' "$failover_tcp_output"
		max_tcp_seq="$(awk -F'seq=' '/^ok seq=/ { if ($2 > max) max = $2 } END { print max+0 }' <<<"$failover_tcp_output")"
		[[ "$max_tcp_seq" -ge $((FAILOVER_PING_COUNT - 5)) ]] || die "active GRE failover TCP did not recover near the tail (max_seq=${max_tcp_seq})"
		grep -q '^ok seq=' <<<"$failover_tcp_output" || die "active GRE failover TCP produced no successful connects"
	fi
	if [[ -n "$failover_iperf_log" ]]; then
		assert_iperf_log_healthy "${failover_iperf_log}" "failover native GRE iperf"
		rm -f "${failover_iperf_log}"
	fi
	if (( UDP == 1 )); then
		info "running post-failover GRE UDP probe to ${GRE_UDP_TARGET}:${GRE_UDP_PORT} from ${HOST}"
		udp_before_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
		udp_before_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
		udp_capture_file="/tmp/userspace-native-gre-post-failover-udp-capture.out"
		start_logical_transit_capture "$ACTIVE_FW" "$udp_capture_file" "udp and host ${GRE_UDP_TARGET} and port ${GRE_UDP_PORT}"
		run_udp_burst_probe "${GRE_UDP_TARGET}" "${GRE_UDP_PORT}" "${GRE_UDP_BURST_COUNT}" "${GRE_UDP_INTERVAL_MS}" "${GRE_UDP_PAYLOAD_SIZE}"
		sleep 2
		udp_after_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
		udp_after_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
		udp_matches="$(logical_transit_matches "$ACTIVE_FW" "$udp_capture_file")"
		assert_outer_only_link_activity \
			"post_failover_native_gre_udp" \
			"${udp_before_outer}" \
			"${udp_after_outer}" \
			"${udp_before_logical}" \
			"${udp_after_logical}"
		(( udp_matches == 0 )) || die "post-failover native GRE UDP probe still hit ${GRE_LOGICAL_DEV}"
	fi
	if (( TRACEROUTE == 1 )); then
		info "running post-failover GRE traceroute probe to ${GRE_TRACEROUTE_TARGET} from ${HOST}"
		mtr_before_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
		mtr_before_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
		mtr_capture_file="/tmp/userspace-native-gre-post-failover-mtr-capture.out"
		start_logical_transit_capture "$ACTIVE_FW" "$mtr_capture_file" "icmp and host ${GRE_TRACEROUTE_TARGET}"
		mtr_output="$(run_host "mtr -n ${GRE_TRACEROUTE_TARGET} --report --report-cycles=${GRE_TRACEROUTE_CYCLES} --max-ttl ${GRE_TRACEROUTE_MAX_HOPS}" || true)"
		assert_mtr_healthy "$mtr_output" "${GRE_TRACEROUTE_TARGET}"
		mtr_after_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
		mtr_after_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
		mtr_matches="$(logical_transit_matches "$ACTIVE_FW" "$mtr_capture_file")"
		assert_outer_only_link_activity \
			"post_failover_native_gre_mtr" \
			"${mtr_before_outer}" \
			"${mtr_after_outer}" \
			"${mtr_before_logical}" \
			"${mtr_after_logical}"
		if (( GRE_VALIDATE_HOST_PROBES == 0 )); then
			(( mtr_matches == 0 )) || die "post-failover native GRE traceroute still hit ${GRE_LOGICAL_DEV}"
		fi
	fi
	if (( GRE_VALIDATE_HOST_PROBES == 1 )); then
		assert_logical_anchor_is_tun "$ACTIVE_FW"
		run_vm "$ACTIVE_FW" "ping -c ${PING_COUNT} -W 1 ${GRE_TARGET} >/tmp/userspace-native-gre-post-failover-host-ping.out 2>&1 || true"
		post_failover_host_ping_output="$(run_vm "$ACTIVE_FW" 'cat /tmp/userspace-native-gre-post-failover-host-ping.out')"
		printf '%s\n' "$post_failover_host_ping_output"
		grep -q 'bytes from' <<<"$post_failover_host_ping_output" || die "post-failover firewall-originated GRE ping failed"
		run_vm "$ACTIVE_FW" "$(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/dev/null 2>&1" || die "post-failover firewall-originated GRE TCP connect failed"
		if (( IPERF == 1 )); then
			post_failover_host_iperf_log="$(mkdir -p /var/worktrees/.cache/tmpdir && TMPDIR=/var/worktrees/.cache/tmpdir mktemp)"
			run_vm_iperf_stream_to_log "${post_failover_host_iperf_log}" "${ACTIVE_FW}" "${GRE_IPERF_TARGET}" "${GRE_IPERF_PORT}" "${GRE_HOST_IPERF_DURATION}" "${GRE_HOST_IPERF_PARALLEL}"
			assert_iperf_log_healthy_with_threshold "${post_failover_host_iperf_log}" "post-failover host native GRE iperf" "${GRE_HOST_IPERF_MIN_GBPS}"
			rm -f "${post_failover_host_iperf_log}"
		fi
	fi
	pass "native GRE active tunnel traffic survived failover to ${ACTIVE_FW}"
fi
