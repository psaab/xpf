#!/usr/bin/env bash
# xpf cluster failover test
#
# Validates that active TCP connections survive fw0 reboot and manual failback.
# Requires: cluster nodes from BPFRX_CLUSTER_ENV running (default: loss userspace cluster).
# Requires: iperf3 server reachable at IPERF_TARGET (default from IPERF_TARGET4).
#
# Tests:
#   1. Start iperf3 --json-stream -P8 through the firewall (LAN host → WAN target)
#   2. Verify sessions sync from primary (fw0) to secondary (fw1)
#   3. Reboot fw0 (unclean — no priority-0 burst)
#   4. Verify every established stream resumes within 3s and no more than two
#      consecutive one-second aggregate intervals fall below MIN_THROUGHPUT
#   5. Verify fw0 comes back as secondary (no auto-preempt)
#   6. Manual failover: fw0 becomes primary again, iperf3 survives
#
# Usage:
#   ./test/incus/test-failover.sh
#   IPERF_TARGET=10.1.2.3 ./test/incus/test-failover.sh

set -euo pipefail

# #1875/#4020: this DESTRUCTIVE smoke reboots / force-stops / fails
# over a node on the SHARED loss cluster. Re-exec under the
# incus-admin group if needed, then serialize as a #1875 lock cell
# so a concurrent deploy/smoke can't collide with our reboot (it
# queues behind a held /tmp/xpf-cluster.lock instead of colliding).
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "test-failover $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# #7368: deploy_reassert_node0_primary_ok (the per-RG primacy predicate #6591
# added) and failover_ownership_verdict, both covered by
# `make test-deploy-lib` against a mocked incus.
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/iperf-throughput-lib.sh
source "${SCRIPT_DIR}/iperf-throughput-lib.sh"
# shellcheck source=test/incus/ha-assurance-lib.sh
source "${SCRIPT_DIR}/ha-assurance-lib.sh"
# shellcheck source=test/incus/failover-client-lib.sh
source "${SCRIPT_DIR}/failover-client-lib.sh"
# shellcheck source=test/incus/failover-clock-lib.sh
source "${SCRIPT_DIR}/failover-clock-lib.sh"
# shellcheck source=test/incus/failover-journal-lib.sh
source "${SCRIPT_DIR}/failover-journal-lib.sh"

IPERF_TARGET="${IPERF_TARGET:-$IPERF_TARGET4}"
# #6934: the IPv6 transit target. cluster-env.sh has exported IPERF_TARGET6 all
# along and this gate never read it — every assertion here was IPv4-only, which
# is why an IPv6-specific failover regression reached a human as an ad-hoc
# observation instead of reddening this gate.
IPERF_TARGET6="${IPERF_TARGET6:-2001:559:8585:80::200}"
V6_PROBE_COUNT=5        # #6934: see check_v6_transit for why this is not 1
V6_PROBE_MIN=3          # received replies required to call the path up
V6_RECHECK_DELAY=30     # #6934: seconds between the two post-failover samples
# COUPLED TO #7770 — tighten this when that is fixed.
#
# 3-of-5 is not a general-purpose tolerance; it is calibrated to absorb one
# specific KNOWN defect. #7770: a LAN/WAN redundancy-group split drops the first
# packet of every new flow, symmetrically in v4 and v6, and does not self-heal
# (measured 12.5% on 8 packets, still 12.5% on a fresh probe 45s later, against
# 0% for a full failover). A 0%-loss assertion here would red on that rather
# than on anything this gate is scoped to.
#
# So once #7770 lands, this threshold is LOOSER than it needs to be and would
# hide a one-packet regression. Raise V6_PROBE_MIN to V6_PROBE_COUNT then.
#
# Written down because a tolerance whose reason is undocumented is
# indistinguishable from a tolerance nobody thought about — the next reader
# cannot tell "3 of 5 because a known defect costs exactly one packet" from
# "3 of 5 because the author was not sure", and only the first has an expiry.
IPERF_DURATION_INPUT="${IPERF_DURATION:-}"
IPERF_STREAMS=8
MIN_SESSIONS=4          # minimum observed session entries (control + some data streams)
SYNC_WAIT=5             # seconds to wait for session sync sweep
SESSION_SYNC_IDLE_TIMEOUT="${SESSION_SYNC_IDLE_TIMEOUT:-30}"
SESSION_SYNC_IDLE_STABLE_SAMPLES="${SESSION_SYNC_IDLE_STABLE_SAMPLES:-3}"
PRE_FAILOVER_OBSERVE="${PRE_FAILOVER_OBSERVE:-10}"
REBOOT_WAIT=60          # max WALL-CLOCK seconds to wait for fw0 to come back (#1880)
MANUAL_FAILOVER_DEADLINE="${MANUAL_FAILOVER_DEADLINE:-10}"
EXTERNAL_PING_COUNT="${EXTERNAL_PING_COUNT:-4}"
EXTERNAL_V4_TARGET="${EXTERNAL_V4_TARGET:-1.1.1.1}"
EXTERNAL_V6_TARGET="${EXTERNAL_V6_TARGET:-2606:4700:4700::1111}"
STANDBY_WAN_IFACE_REGEX="${STANDBY_WAN_IFACE_REGEX:-ge-[0-9]+-0-2}"
MAX_STANDBY_WAN_TX_DELTA="${MAX_STANDBY_WAN_TX_DELTA:-0}"
REQUIRE_FABRIC_ACTIVITY="${REQUIRE_FABRIC_ACTIVITY:-1}"
MIN_FABRIC_TX_DELTA="${MIN_FABRIC_TX_DELTA:-1}"
FABRIC_ACTIVITY_TRIGGER_DELTA="${FABRIC_ACTIVITY_TRIGGER_DELTA:-8}"
MAX_FAILOVER_SESSION_MISS_DELTA="${MAX_FAILOVER_SESSION_MISS_DELTA:-64}"
MAX_FAILOVER_NEIGHBOR_MISS_DELTA="${MAX_FAILOVER_NEIGHBOR_MISS_DELTA:-60}"
MAX_FAILOVER_ROUTE_MISS_DELTA="${MAX_FAILOVER_ROUTE_MISS_DELTA:-32}"
MAX_FAILOVER_POLICY_DENIED_DELTA="${MAX_FAILOVER_POLICY_DENIED_DELTA:-0}"
MAX_ZERO_INTERVALS="${MAX_ZERO_INTERVALS:-2}"
MAX_STREAM_ZERO_INTERVALS="${MAX_STREAM_ZERO_INTERVALS:-0}"
MAX_PREFLIGHT_ZERO_INTERVALS="${MAX_PREFLIGHT_ZERO_INTERVALS:-0}"
MAX_PREFLIGHT_STREAM_ZERO_INTERVALS="${MAX_PREFLIGHT_STREAM_ZERO_INTERVALS:-0}"
MAX_RETRANSMITS="${MAX_RETRANSMITS:-}"
MAX_RETRANSMITS_PER_GBPS="${MAX_RETRANSMITS_PER_GBPS:-}"
MAX_TRANSITION_KERNEL_RX_DROPPED_DELTA="${MAX_TRANSITION_KERNEL_RX_DROPPED_DELTA:-512}"
MAX_TRANSITION_DIRECT_TX_NOFRAME_DELTA="${MAX_TRANSITION_DIRECT_TX_NOFRAME_DELTA:-512}"
TRANSITION_PATH_TRIGGER_PKTS="${TRANSITION_PATH_TRIGGER_PKTS:-1000}"
MIN_TRANSITION_FABRIC_RX_DELTA="${MIN_TRANSITION_FABRIC_RX_DELTA:-32}"
MIN_TRANSITION_WAN_TX_DELTA="${MIN_TRANSITION_WAN_TX_DELTA:-32}"
MIN_THROUGHPUT=1.0      # Gbps — iperf3 must report at least this
IPERF_DURATION_MIN=$(( 8 + SYNC_WAIT + SESSION_SYNC_IDLE_TIMEOUT + PRE_FAILOVER_OBSERVE + 3 + REBOOT_WAIT + 20 + SESSION_SYNC_IDLE_TIMEOUT + 3 * MANUAL_FAILOVER_DEADLINE + 10 + V6_RECHECK_DELAY + 2 * V6_PROBE_COUNT + 5 * 2 * EXTERNAL_PING_COUNT + 4 * (3 * 1 + 3) + 15 ))
# #7673: the CoS output filter classifies by DESTINATION PORT, and iperf3
# defaults to 5201 -- which cos-iperf-config.set maps to `iperf-100m`, a
# `transmit-rate 100m exact` class. Measuring a deliberately-100Mbit-shaped
# class against a 1.0 Gbps floor fails by construction, and it fails looking
# exactly like a forwarding regression (~92-94 Mbits/s, every failover
# assertion passing). 5211 is the `iperf-uncapped` term, whose scheduler
# carries no transmit-rate.
#
# This only bites once apply-cos-config.sh has been run, and the CoS config
# survives until the next deploy wipes it -- so the gate passed or failed
# depending on what the PREVIOUS agent left on the cluster. That is why it
# reproduced on master and read as a real regression.
#
# iperf-throughput-selftest.sh asserts this port still maps to an unshaped
# class, so the two files cannot drift apart silently.
IPERF_PORT="${IPERF_PORT:-5211}"

PASS=0
FAIL=0
VOID=0
ERRORS=()

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }

die() { echo "FATAL: $*" >&2; exit 2; }
failover_duration_value() {
	local requested="$1" minimum="$2"
	if [[ ! "$minimum" =~ ^[0-9]+$ ]]; then
		printf 'required duration is malformed: %s\n' "$minimum" >&2
		return 1
	fi
	if [[ -z "$requested" ]]; then
		printf '%s\n' "$minimum"
		return 0
	fi
	if [[ ! "$requested" =~ ^[0-9]+$ ]]; then
		printf 'IPERF_DURATION must be a positive integer number of seconds\n' >&2
		return 1
	fi
	if (( requested < minimum )); then
		printf 'IPERF_DURATION=%ss is shorter than the required %ss for the bounded HA windows\n' "$requested" "$minimum" >&2
		return 1
	fi
	printf '%s\n' "$requested"
}

if ! IPERF_DURATION="$(failover_duration_value "$IPERF_DURATION_INPUT" "$IPERF_DURATION_MIN")"; then
	die "refusing an IPERF_DURATION shorter than the required bounded HA window"
fi
unset IPERF_DURATION_INPUT

void() { echo "  VOID  $*"; VOID=$((VOID + 1)); }

# Match only the main client process, not the separate pool-mode iperf3 client.
main_iperf_running() {
	failover_main_iperf_running /tmp/iperf3-failover.pid "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS"
}

HA_CAPTURE_DIR="${TMPDIR:-/tmp}/test-failover-ha-$$"
declare -A RG1_STATS=()
declare -A RG1_INTERFACES=()
declare -A RG1_STATUS=()
declare -A RG1_SAMPLE_STATS=()
declare -A RG1_SAMPLE_INTERFACES=()
RG1_FAILBACK_SETTLED=false
RG1_FAILBACK_ELAPSED=0

ha_ensure_capture_dir() {
	mkdir -p "$HA_CAPTURE_DIR"
}

# Capture the actual CLI output with an identity line the shared pure
# predicate verifies before any summary/interface parser consumes it.
ha_capture_cli() {
	local node="$1" command="$2" slice="$3" phase="$4" node_id="$5" rg="$6" path="$7"
	ha_ensure_capture_dir || return 2
	printf 'HA capture identity: slice=%s phase=%s node=%s rg=%s\n' \
		"$slice" "$phase" "$node_id" "$rg" >"$path" || return 2
	if ! incus exec "$node" -- cli -c "$command" >>"$path" 2>&1; then
		printf 'CLI capture failed: %s phase=%s node=%s rg=%s\n' "$command" "$phase" "$node_id" "$rg" >&2
		return 2
	fi
	if ! ha_snapshot_identity_verdict "$path" "$slice" "$phase" "$node_id" "$rg"; then
		return 2
	fi
}

ha_capture_rg1_node() {
	local phase="$1" node_id="$2" node="$3" base
	base="${HA_CAPTURE_DIR}/manual-rg1-failback-${phase}-${node_id}-rg1"
	RG1_STATS["${phase}:${node_id}"]="${base}.stats"
	RG1_INTERFACES["${phase}:${node_id}"]="${base}.interfaces"
	RG1_STATUS["${phase}:${node_id}"]="${base}.status"
	local result=0
	if ! ha_capture_cli "$node" 'show chassis cluster data-plane statistics' \
		manual-rg1-failback "$phase" "$node_id" 1 "${RG1_STATS["${phase}:${node_id}"]}"; then
		result=2
	fi
	if ! ha_capture_cli "$node" 'show chassis cluster data-plane interfaces' \
		manual-rg1-failback "$phase" "$node_id" 1 "${RG1_INTERFACES["${phase}:${node_id}"]}"; then
		result=2
	fi
	if ! ha_capture_cli "$node" 'show chassis cluster status' \
		manual-rg1-failback "$phase" "$node_id" 1 "${RG1_STATUS["${phase}:${node_id}"]}"; then
		result=2
	fi
	return "$result"
}

ha_capture_rg1_pair() {
	local phase="$1" result=0
	if ! ha_capture_rg1_node "$phase" node0 "$FW0"; then result=2; fi
	if ! ha_capture_rg1_node "$phase" node1 "$FW1"; then result=2; fi
	return "$result"
}

ha_capture_rg1_status_pair() {
	local phase="$1" result=0
	RG1_STATUS["${phase}:node0"]="${HA_CAPTURE_DIR}/manual-rg1-failback-${phase}-node0-rg1.status"
	RG1_STATUS["${phase}:node1"]="${HA_CAPTURE_DIR}/manual-rg1-failback-${phase}-node1-rg1.status"
	if ! ha_capture_cli "$FW0" 'show chassis cluster status' \
		manual-rg1-failback "$phase" node0 1 "${RG1_STATUS["${phase}:node0"]}"; then
		result=2
	fi
	if ! ha_capture_cli "$FW1" 'show chassis cluster status' \
		manual-rg1-failback "$phase" node1 1 "${RG1_STATUS["${phase}:node1"]}"; then
		result=2
	fi
	return "$result"
}

ha_capture_rg1_sample_node() {
	local phase="$1" node_id="$2" node="$3" base
	base="${HA_CAPTURE_DIR}/manual-rg1-failback-${phase}-${node_id}-rg1"
	RG1_SAMPLE_STATS["${phase}:${node_id}"]="${base}.stats"
	RG1_SAMPLE_INTERFACES["${phase}:${node_id}"]="${base}.interfaces"
	local result=0
	if ! ha_capture_cli "$node" 'show chassis cluster data-plane statistics' \
		manual-rg1-failback "$phase" "$node_id" 1 "${RG1_SAMPLE_STATS["${phase}:${node_id}"]}"; then
		result=2
	fi
	if ! ha_capture_cli "$node" 'show chassis cluster data-plane interfaces' \
		manual-rg1-failback "$phase" "$node_id" 1 "${RG1_SAMPLE_INTERFACES["${phase}:${node_id}"]}"; then
		result=2
	fi
	return "$result"
}

ha_capture_rg1_sample_pair() {
	local phase="$1" result=0
	if ! ha_capture_rg1_sample_node "$phase" node0 "$FW0"; then result=2; fi
	if ! ha_capture_rg1_sample_node "$phase" node1 "$FW1"; then result=2; fi
	return "$result"
}

ha_rg1_owner_verdict() {
	local expected_node="$1" phase="$2"
	ha_rg_owner_verdict "$expected_node" 1 "$phase" \
		"${RG1_STATUS["${phase}:node0"]}" "${RG1_STATUS["${phase}:node1"]}"
}

ha_capture_sync_stats() {
	local label="$1" node_id="$2" node="$3" path
	path="${HA_CAPTURE_DIR}/sync-${label}-${node_id}.stats"
	if ! ha_capture_cli "$node" 'show chassis cluster data-plane statistics' \
		session-sync-idle "$label" "$node_id" all "$path"; then
		return 2
	fi
	printf '%s\n' "$path"
}

ha_sync_idle_streak_step() {
	local stable="$1" sample_status="$2" required="$3" next
	if [[ ! "$stable" =~ ^[0-9]+$ || ! "$required" =~ ^[1-9][0-9]*$ ]]; then
		printf 'invalid session-sync stable-streak arguments\n' >&2
		return 2
	fi
	case "$sample_status" in
	0) next=$((stable + 1)) ;;
	1) next=0 ;;
	2) printf '%s\n' "$stable"; return 2 ;;
	*) printf 'invalid session-sync sample verdict: %s\n' "$sample_status" >&2; return 2 ;;
	esac
	printf '%s\n' "$next"
	(( next >= required ))
}

ha_sync_idle_timeout_verdict() {
	local stable="$1" required="$2"
	if [[ ! "$stable" =~ ^[0-9]+$ || ! "$required" =~ ^[1-9][0-9]*$ ]]; then
		printf 'invalid session-sync timeout arguments\n' >&2
		return 2
	fi
	if (( stable >= required )); then
		return 0
	fi
	printf 'session sync failed to reach %s consecutive idle samples (observed %s)\n' "$required" "$stable" >&2
	return 1
}

ha_wait_for_session_sync_idle() {
	local label="$1" source_id="$2" source_node="$3" target_id="$4" target_node="$5"
	local attempt stable=0 source_path target_path rc
	for ((attempt = 1; attempt <= SESSION_SYNC_IDLE_TIMEOUT; attempt++)); do
		if ! source_path="$(ha_capture_sync_stats "${label}-${attempt}" "$source_id" "$source_node")"; then
			void "${label}: session sync CLI capture unavailable (${source_id}->${target_id})"
			return 2
		fi
		if ! target_path="$(ha_capture_sync_stats "${label}-${attempt}" "$target_id" "$target_node")"; then
			void "${label}: session sync CLI capture unavailable (${source_id}->${target_id})"
			return 2
		fi
		if ha_session_sync_idle_sample "$source_id" "$target_id" "$source_path" "$target_path"; then
			stable=$((stable + 1))
			if (( stable >= SESSION_SYNC_IDLE_STABLE_SAMPLES )); then
				pass "${label}: session sync idle (${source_id}->${target_id}, ${stable} consecutive samples)"
				return 0
			fi
		else
			rc=$?
			case "$rc" in
			1) stable=0 ;;
			2)
				void "${label}: session sync statistics malformed (${source_id}->${target_id})"
				return 2
				;;
			esac
		fi
		sleep 1
	done
	fail "${label}: session sync did not become idle within ${SESSION_SYNC_IDLE_TIMEOUT}s (${source_id}->${target_id})"
	return 1
}

ha_emit_verdict() {
	local label="$1" result reason
	shift
	if result=$("$@" 2>&1); then
		pass "$label"
	else
		local status=$?
		case "$status" in
		1) fail "$label${result:+: ${result}}" ;;
		2) void "$label${result:+: ${result}}" ;;
		*) void "$label: helper returned unexpected status ${status}${result:+: ${result}}" ;;
		esac
	fi
}

ha_target_reachability_cell() {
	local label="$1" ping_output ping_rc tcp_output="" tcp_rc=125 rc
	if ping_output=$(incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 1 "$IPERF_TARGET" 2>&1); then
		ping_rc=0
	else
		ping_rc=$?
	fi
	if ha_ping_reply_verdict "$ping_rc" "$ping_output"; then
		pass "${label}: iperf target reachable by ping (${IPERF_TARGET})"
		return 0
	else
		rc=$?
	fi
	if (( rc == 2 )); then
		void "${label}: iperf target ping capture unavailable (${IPERF_TARGET})"
		return 2
	fi
	if tcp_output=$(incus exec "$CLUSTER_LAN_HOST" -- \
		timeout 3 bash -lc "echo > /dev/tcp/${IPERF_TARGET}/5201" 2>&1); then
		tcp_rc=0
	else
		tcp_rc=$?
	fi
	if ha_target_reachability_verdict "$ping_rc" "$ping_output" "$tcp_rc" "$tcp_output"; then
		pass "${label}: iperf target reachable by TCP fallback at ${IPERF_TARGET}:5201"
	else
		rc=$?
		if (( rc == 1 )); then
			fail "${label}: iperf target ping and TCP fallback failed (${IPERF_TARGET}:5201)"
		else
			void "${label}: iperf target ping/TCP capture unavailable (${IPERF_TARGET}:5201)"
		fi
		return "$rc"
	fi
}

ha_external_ping_capture() {
	local family="$1" target="$2"
	if [[ "$family" == 6 ]]; then
		if HA_EXTERNAL_OUTPUT=$(incus exec "$CLUSTER_LAN_HOST" -- \
			ping -6 -c "$EXTERNAL_PING_COUNT" -W 1 "$target" 2>&1); then
			HA_EXTERNAL_RC=0
		else
			HA_EXTERNAL_RC=$?
		fi
	else
		if HA_EXTERNAL_OUTPUT=$(incus exec "$CLUSTER_LAN_HOST" -- \
			ping -c "$EXTERNAL_PING_COUNT" -W 1 "$target" 2>&1); then
			HA_EXTERNAL_RC=0
		else
			HA_EXTERNAL_RC=$?
		fi
	fi
}

ha_external_sweep() {
	local label="$1" v4_rc v4_output v6_rc v6_output
	if ! main_iperf_running; then
		void "${label}: external reachability window lacked the main iperf load (IPv4)"
		void "${label}: external reachability window lacked the main iperf load (IPv6)"
		return
	fi
	ha_external_ping_capture 4 "$EXTERNAL_V4_TARGET"
	v4_rc="$HA_EXTERNAL_RC"
	v4_output="$HA_EXTERNAL_OUTPUT"
	if ! main_iperf_running; then
		void "${label}: external reachability window lost the main iperf load (IPv4)"
		void "${label}: external reachability window lost the main iperf load (IPv6)"
		return
	fi
	ha_external_ping_capture 6 "$EXTERNAL_V6_TARGET"
	v6_rc="$HA_EXTERNAL_RC"
	v6_output="$HA_EXTERNAL_OUTPUT"
	if ! main_iperf_running; then
		void "${label}: external reachability window lost the main iperf load (IPv4)"
		void "${label}: external reachability window lost the main iperf load (IPv6)"
		return
	fi
	ha_emit_verdict "${label}: external IPv4 ${EXTERNAL_V4_TARGET}" \
		ha_external_ping_verdict "$v4_rc" "$v4_output"
	ha_emit_verdict "${label}: external IPv6 ${EXTERNAL_V6_TARGET}" \
		ha_external_ping_verdict "$v6_rc" "$v6_output"
}

ha_preflight_json_metrics() {
	local log="${HA_CAPTURE_DIR}/pre-failover.jsonl"
	local metrics="${HA_CAPTURE_DIR}/pre-failover.metrics.json"
	local gate_error="${HA_CAPTURE_DIR}/pre-failover.gate.err"
	local producer_error="${HA_CAPTURE_DIR}/pre-failover.producer.err"
	local recent_error="${HA_CAPTURE_DIR}/pre-failover.recent.err"
	local gate_output reason recent_value result=0
	local avg_gbps zero_intervals_total stream_zero_intervals_total zero_streams_total
	local retransmits collapse_detected collapse_reason completed observed_end_sec full_interval_count
	if ! incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log >"$log" 2>/dev/null; then
		void "pre-failover observation: aggregate zero-interval evidence unavailable"
		void "pre-failover observation: per-stream zero-interval evidence unavailable"
		void "pre-failover observation: recent dead-stream evidence unavailable"
		return 2
	fi
	if ! python3 "${SCRIPT_DIR}/../../scripts/iperf-json-metrics.py" \
		"$log" >"$metrics" 2>"$producer_error"; then
		printf '{"ok":false,"error":"metrics_parse_failed"}\n' >"$metrics"
	fi
	if gate_output=$(ha_metrics_gate "$metrics" 2>"$gate_error"); then
		eval "$gate_output"
	else
		reason=$(<"$gate_error")
		void "pre-failover observation: aggregate zero-interval evidence unavailable: ${reason:-ha_metrics_gate rejected metrics}"
		void "pre-failover observation: per-stream zero-interval evidence unavailable: ${reason:-ha_metrics_gate rejected metrics}"
		void "pre-failover observation: recent dead-stream evidence unavailable: ${reason:-ha_metrics_gate rejected metrics}"
		return 2
	fi
	if recent_value=$(ha_recent_interval_metric "$log" "$PRE_FAILOVER_OBSERVE" zero_intervals "$IPERF_STREAMS" 2>"$recent_error"); then
		ha_emit_verdict "pre-failover aggregate zero intervals (${recent_value}, limit ${MAX_PREFLIGHT_ZERO_INTERVALS})" \
			ha_counter_at_most_verdict "$recent_value" "$MAX_PREFLIGHT_ZERO_INTERVALS" "aggregate zero intervals"
	else
		reason=$(<"$recent_error")
		void "pre-failover observation: aggregate zero-interval evidence unavailable: ${reason:-recent JSON window rejected}"
		result=2
	fi
	if recent_value=$(ha_recent_interval_metric "$log" "$PRE_FAILOVER_OBSERVE" stream_zero_intervals "$IPERF_STREAMS" 2>"$recent_error"); then
		ha_emit_verdict "pre-failover per-stream zero intervals (${recent_value}, limit ${MAX_PREFLIGHT_STREAM_ZERO_INTERVALS})" \
			ha_counter_at_most_verdict "$recent_value" "$MAX_PREFLIGHT_STREAM_ZERO_INTERVALS" "per-stream zero intervals"
	else
		reason=$(<"$recent_error")
		void "pre-failover observation: per-stream zero-interval evidence unavailable: ${reason:-recent JSON window rejected}"
		result=2
	fi
	if recent_value=$(ha_recent_interval_metric "$log" 1 dead_streams "$IPERF_STREAMS" 2>"$recent_error"); then
		ha_emit_verdict "pre-failover recent dead streams (${recent_value}, limit 0)" \
			ha_counter_at_most_verdict "$recent_value" 0 "recent dead streams"
	else
		reason=$(<"$recent_error")
		void "pre-failover observation: recent dead-stream evidence unavailable: ${reason:-recent JSON window rejected}"
		result=2
	fi
	return "$result"
}

ha_pre_failover_observation() {
	local second alive=true preflight_rc
	info "observing same-load traffic for ${PRE_FAILOVER_OBSERVE}s before crash"
	for ((second = 1; second <= PRE_FAILOVER_OBSERVE; second++)); do
		sleep 1
		if ! main_iperf_running; then
			alive=false
		fi
	done
	if $alive; then
		if ha_preflight_json_metrics; then
			:
		else
			preflight_rc=$?
			if (( preflight_rc != 2 )); then
				void "pre-failover observation: metrics helper returned unexpected status ${preflight_rc}"
			fi
		fi
		ha_external_sweep "pre-failure steady"
	else
		void "pre-failover observation: main iperf client did not remain alive for ${PRE_FAILOVER_OBSERVE}s"
		void "pre-failover observation: aggregate zero-interval evidence unavailable"
		void "pre-failover observation: per-stream zero-interval evidence unavailable"
		void "pre-failover observation: recent dead-stream evidence unavailable"
		ha_external_sweep "pre-failure steady"
	fi
}

ha_recent_dead_streams_cell() {
	local label="$1"
	local log="${HA_CAPTURE_DIR}/recent-${label//[^[:alnum:]]/-}.jsonl"
	local metrics="${HA_CAPTURE_DIR}/recent-${label//[^[:alnum:]]/-}.metrics.json"
	local gate_error="${HA_CAPTURE_DIR}/recent-${label//[^[:alnum:]]/-}.gate.err"
	local parser_error="${HA_CAPTURE_DIR}/recent-${label//[^[:alnum:]]/-}.parser.err"
	local gate_output reason dead_streams
	local avg_gbps zero_intervals_total stream_zero_intervals_total zero_streams_total
	local retransmits collapse_detected collapse_reason completed observed_end_sec full_interval_count
	if ! main_iperf_running; then
		void "${label}: recent dead-stream window lacked the main iperf load"
		return
	fi
	if ! incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log >"$log" 2>/dev/null; then
		void "${label}: recent dead-stream evidence unavailable (JSON log capture failed)"
		return
	fi
	if ! python3 "${SCRIPT_DIR}/../../scripts/iperf-json-metrics.py" \
		"$log" >"$metrics" 2>"$parser_error"; then
		printf '{"ok":false,"error":"metrics_parse_failed"}\n' >"$metrics"
	fi
	if gate_output=$(ha_metrics_gate "$metrics" 2>"$gate_error"); then
		eval "$gate_output"
	else
		reason=$(<"$gate_error")
		void "${label}: recent dead-stream evidence unavailable: ${reason:-ha_metrics_gate rejected metrics}"
		return
	fi
	if ! main_iperf_running; then
		void "${label}: recent dead-stream window did not remain under the main iperf load"
		return
	fi
	if dead_streams=$(ha_recent_interval_metric "$log" 1 dead_streams "$IPERF_STREAMS" 2>"$parser_error"); then
		if main_iperf_running; then
			ha_emit_verdict "${label}: recent dead streams (${dead_streams}, limit 0)" \
				ha_counter_at_most_verdict "$dead_streams" 0 "recent dead streams"
		else
			void "${label}: recent dead-stream window did not remain under the main iperf load"
		fi
	else
		reason=$(<"$parser_error")
		void "${label}: recent dead-stream evidence unavailable: ${reason:-recent JSON window rejected}"
	fi
}

ha_rg1_owner_status_cell() {
	local expected_node="$1" phase="$2" label="$3" result status
	if result=$(ha_rg1_owner_verdict "$expected_node" "$phase" 2>&1); then
		pass "$label"
		return 0
	else
		status=$?
	fi
	case "$status" in
	1) fail "$label${result:+: ${result}}" ;;
	2) void "$label${result:+: ${result}}" ;;
	*) void "$label: owner helper returned unexpected status ${status}${result:+: ${result}}" ;;
	esac
	return "$status"
}

ha_wait_rg1_owner() {
	local expected_node="$1" deadline="$2" start attempt=1 phase reason status
	local saw_valid=false
	start=$(date +%s)
	while :; do
		phase=$(printf 'owner-poll-%02d' "$attempt")
		if ha_capture_rg1_status_pair "$phase"; then
			if reason=$(ha_rg1_owner_verdict "$expected_node" "$phase" 2>&1); then
				pass "manual RG1 failback settled on ${expected_node} (both node status queries, ${phase})"
				RG1_FAILBACK_SETTLED=true
				RG1_FAILBACK_ELAPSED=$(($(date +%s) - start))
				return 0
			else
				status=$?
				if (( status == 1 )); then
					saw_valid=true
					info "RG1 owner not settled at ${phase}: ${reason}"
				else
					info "RG1 owner poll is blind at ${phase}: ${reason}"
				fi
			fi
		else
			info "RG1 owner poll status capture unavailable at ${phase}"
		fi
		if (( $(date +%s) - start >= deadline )); then
			break
		fi
		sleep 1
		attempt=$((attempt + 1))
	done
	if $saw_valid; then
		fail "manual RG1 failback did not settle on ${expected_node} within ${deadline}s"
		return 1
	fi
	void "manual RG1 failback owner evidence unavailable for the full ${deadline}s deadline"
	return 2
}

ha_emit_diagnostic_verdict() {
	local label="$1" result status
	shift
	if result=$("$@" 2>&1); then
		pass "$label${result:+: ${result}}"
	else
		status=$?
		case "$status" in
		1) fail "$label${result:+: ${result}}" ;;
		2) void "$label${result:+: ${result}}" ;;
		*) void "$label: helper returned unexpected status ${status}${result:+: ${result}}" ;;
		esac
	fi
}

ha_rg1_mark_groups_void() {
	local reason="$1"
	void "RG1 Group 1 session-miss budget: ${reason}"
	void "RG1 Group 2 neighbor-miss budget: ${reason}"
	void "RG1 Group 3 route-miss budget: ${reason}"
	void "RG1 Group 4 policy-denied budget: ${reason}"
	void "RG1 Group 5 former-owner WAN TX: ${reason}"
	void "RG1 Group 6 fabric TX vs old-owner churn: ${reason}"
	void "RG1 Group 7 former-owner readiness: ${reason}"
	void "RG1 Group 8a new-owner Kernel RX dropped: ${reason}"
	void "RG1 Group 8b former-owner Direct TX no-frame fb: ${reason}"
	void "RG1 Group 8c transition path: ${reason}"
	void "RG1 Group 8 report-only sampled maxima: ${reason}"
}

ha_rg1_validate_samples() {
	local index phase node
	for ((index = 1; index <= 10; index++)); do
		phase=$(printf 'sample-%02d' "$index")
		for node in node0 node1; do
			if ! ha_snapshot_identity_verdict "${RG1_SAMPLE_STATS["${phase}:${node}"]:-}" \
				manual-rg1-failback "$phase" "$node" 1; then
				return 2
			fi
			if ! ha_snapshot_identity_verdict "${RG1_SAMPLE_INTERFACES["${phase}:${node}"]:-}" \
				manual-rg1-failback "$phase" "$node" 1; then
				return 2
			fi
		done
	done
}

ha_rg1_sampled_counter_delta() {
	if [[ $# -ne 13 ]]; then
		printf 'RG1 sampled counter delta: expected <node> <label> <phase-pre-file> and ten sample files\n' >&2
		return 2
	fi
	local node="$1" label="$2" pre_file="$3" baseline maximum
	local -a args=("$@") samples=("${args[@]:3}")
	if ! ha_snapshot_identity_verdict "$pre_file" manual-rg1-failback phase-pre "$node" 1; then
		return 2
	fi
	if ! baseline=$(ha_status_summary_value "$pre_file" "$label"); then return 2; fi
	if ! maximum=$(ha_sample_window_max manual-rg1-failback 1 "$node" "$label" \
		"${samples[@]}" "$baseline"); then
		return 2
	fi
	ha_nondecreasing_delta "$baseline" "$maximum"
}

ha_rg1_sampled_interface_delta() {
	if [[ $# -ne 14 ]]; then
		printf 'RG1 sampled interface delta: expected <node> <regex> <direction> <phase-pre-file> and ten sample files\n' >&2
		return 2
	fi
	local node="$1" regex="$2" direction="$3" pre_file="$4" baseline maximum
	local -a args=("$@") samples=("${args[@]:4}")
	if ! ha_snapshot_identity_verdict "$pre_file" manual-rg1-failback phase-pre "$node" 1; then
		return 2
	fi
	if ! baseline=$(ha_interface_packets_value "$pre_file" "$regex" "$direction"); then return 2; fi
	if ! maximum=$(ha_sample_window_interface_max manual-rg1-failback 1 "$node" \
		"$regex" "$direction" "${samples[@]}" "$baseline"); then
		return 2
	fi
	ha_nondecreasing_delta "$baseline" "$maximum"
}

ha_rg1_report_sample_max() {
	local label="$1" node="$2" metric="$3" pre_file="$4" result reason baseline
	shift 4
	if [[ $# -ne 10 ]]; then
		void "RG1 Group 8 report-only ${label} max unavailable (${node}): expected ten sample files"
		return
	fi
	if ! reason=$(ha_snapshot_identity_verdict "$pre_file" manual-rg1-failback phase-pre "$node" 1 2>&1); then
		void "RG1 Group 8 report-only ${label} max unavailable (${node}): ${reason:-phase-pre snapshot invalid}"
		return
	fi
	if ! baseline=$(ha_status_summary_value "$pre_file" "$metric" 2>&1); then
		void "RG1 Group 8 report-only ${label} max unavailable (${node}): ${baseline:-phase-pre baseline unavailable}"
		return
	fi
	if result=$(ha_sample_window_max manual-rg1-failback 1 "$node" "$metric" "$@" "$baseline" 2>&1); then
		info "RG1 Group 8 report-only ${label} max (${node}): ${result}"
	else
		reason="$result"
		void "RG1 Group 8 report-only ${label} max unavailable (${node}): ${reason}"
	fi
}

ha_rg1_evaluate() {
	local can_measure="$1" reason="$2"
	if [[ "$can_measure" != true ]]; then
		ha_rg1_mark_groups_void "$reason"
		return
	fi

	ha_emit_verdict "RG1 Group 1 session misses (phase-pre→phase-post, both nodes, limit ${MAX_FAILOVER_SESSION_MISS_DELTA})" \
		ha_pair_counter_budget_verdict "$MAX_FAILOVER_SESSION_MISS_DELTA" "Session misses" \
		manual-rg1-failback 1 phase-pre phase-post \
		"${RG1_STATS[phase-pre:node0]}" "${RG1_STATS[phase-pre:node1]}" \
		"${RG1_STATS[phase-post:node0]}" "${RG1_STATS[phase-post:node1]}"
	ha_emit_verdict "RG1 Group 2 neighbor misses (phase-pre→phase-post, both nodes, limit ${MAX_FAILOVER_NEIGHBOR_MISS_DELTA})" \
		ha_pair_counter_budget_verdict "$MAX_FAILOVER_NEIGHBOR_MISS_DELTA" "Neighbor misses" \
		manual-rg1-failback 1 phase-pre phase-post \
		"${RG1_STATS[phase-pre:node0]}" "${RG1_STATS[phase-pre:node1]}" \
		"${RG1_STATS[phase-post:node0]}" "${RG1_STATS[phase-post:node1]}"
	ha_emit_verdict "RG1 Group 3 route misses (phase-pre→phase-post, both nodes, limit ${MAX_FAILOVER_ROUTE_MISS_DELTA})" \
		ha_pair_counter_budget_verdict "$MAX_FAILOVER_ROUTE_MISS_DELTA" "Route misses" \
		manual-rg1-failback 1 phase-pre phase-post \
		"${RG1_STATS[phase-pre:node0]}" "${RG1_STATS[phase-pre:node1]}" \
		"${RG1_STATS[phase-post:node0]}" "${RG1_STATS[phase-post:node1]}"
	ha_emit_verdict "RG1 Group 4 policy denied packets (phase-pre→phase-post, both nodes, limit ${MAX_FAILOVER_POLICY_DENIED_DELTA})" \
		ha_pair_counter_budget_verdict "$MAX_FAILOVER_POLICY_DENIED_DELTA" "Policy denied packets" \
		manual-rg1-failback 1 phase-pre phase-post \
		"${RG1_STATS[phase-pre:node0]}" "${RG1_STATS[phase-pre:node1]}" \
		"${RG1_STATS[phase-post:node0]}" "${RG1_STATS[phase-post:node1]}"
	ha_emit_verdict "RG1 Group 5 former-owner WAN TX (mid→post, limit ${MAX_STANDBY_WAN_TX_DELTA})" \
		ha_snapshot_interface_budget_verdict "$MAX_STANDBY_WAN_TX_DELTA" \
		"$STANDBY_WAN_IFACE_REGEX" tx "former-owner WAN TX" \
		manual-rg1-failback 1 node1 mid "${RG1_INTERFACES[mid:node1]}" \
		phase-post "${RG1_INTERFACES[phase-post:node1]}"

	local session_delta neighbor_delta route_delta policy_delta old_churn fabric_delta
	local churn_error="${HA_CAPTURE_DIR}/rg1-churn.err" group6_ok=true
	if session_delta=$(ha_snapshot_counter_delta manual-rg1-failback 1 node1 "Session misses" \
		phase-pre "${RG1_STATS[phase-pre:node1]}" phase-post "${RG1_STATS[phase-post:node1]}" 2>"$churn_error") \
		&& neighbor_delta=$(ha_snapshot_counter_delta manual-rg1-failback 1 node1 "Neighbor misses" \
		phase-pre "${RG1_STATS[phase-pre:node1]}" phase-post "${RG1_STATS[phase-post:node1]}" 2>"$churn_error") \
		&& route_delta=$(ha_snapshot_counter_delta manual-rg1-failback 1 node1 "Route misses" \
		phase-pre "${RG1_STATS[phase-pre:node1]}" phase-post "${RG1_STATS[phase-post:node1]}" 2>"$churn_error") \
		&& policy_delta=$(ha_snapshot_counter_delta manual-rg1-failback 1 node1 "Policy denied packets" \
		phase-pre "${RG1_STATS[phase-pre:node1]}" phase-post "${RG1_STATS[phase-post:node1]}" 2>"$churn_error"); then
		old_churn=$((session_delta + neighbor_delta + route_delta + policy_delta))
	else
		reason=$(<"$churn_error")
		void "RG1 Group 6 fabric activity unavailable: old-owner churn evidence is blind: ${reason:-counter delta unavailable}"
		group6_ok=false
	fi
	if [[ "$group6_ok" == true ]]; then
		if fabric_delta=$(ha_snapshot_fabric_tx_delta manual-rg1-failback 1 node1 \
			mid "${RG1_INTERFACES[mid:node1]}" phase-post "${RG1_INTERFACES[phase-post:node1]}" 2>"$churn_error"); then
			ha_emit_diagnostic_verdict "RG1 Group 6 dynamic fabric TX vs old-owner churn (${fabric_delta} packets, churn ${old_churn})" \
				ha_fabric_activity_verdict "$fabric_delta" "$old_churn" "$MIN_FABRIC_TX_DELTA" \
				"$FABRIC_ACTIVITY_TRIGGER_DELTA" "$REQUIRE_FABRIC_ACTIVITY"
		else
			reason=$(<"$churn_error")
			void "RG1 Group 6 dynamic fabric TX unavailable: ${reason:-counter delta unavailable}"
		fi
	fi
	ha_emit_verdict "RG1 Group 7 former-owner readiness on RG1" \
		ha_rg_standby_status_verdict "${RG1_STATUS[mid:node1]}" \
		manual-rg1-failback mid node1 1

	local sample_error="${HA_CAPTURE_DIR}/rg1-samples.err"
	local -a node0_stats=() node1_stats=() node0_interfaces=() node1_interfaces=()
	local index phase delta lan_rx old_fabric_tx new_fabric_rx new_wan_tx
	for ((index = 1; index <= 10; index++)); do
		phase=$(printf 'sample-%02d' "$index")
		node0_stats+=("${RG1_SAMPLE_STATS["${phase}:node0"]:-}")
		node1_stats+=("${RG1_SAMPLE_STATS["${phase}:node1"]:-}")
		node0_interfaces+=("${RG1_SAMPLE_INTERFACES["${phase}:node0"]:-}")
		node1_interfaces+=("${RG1_SAMPLE_INTERFACES["${phase}:node1"]:-}")
	done
	if ! ha_rg1_validate_samples 2>"$sample_error"; then
		reason=$(<"$sample_error")
		void "RG1 Group 8a new-owner Kernel RX dropped: required ten-sample evidence unavailable: ${reason}"
		void "RG1 Group 8b former-owner Direct TX no-frame fb: required ten-sample evidence unavailable: ${reason}"
		void "RG1 Group 8c transition path: required ten-sample evidence unavailable: ${reason}"
		void "RG1 Group 8 report-only sampled maxima unavailable: ${reason}"
		return
	fi
	if delta=$(ha_rg1_sampled_counter_delta node0 "Kernel RX dropped" \
		"${RG1_STATS[phase-pre:node0]}" "${node0_stats[@]}" 2>"$sample_error"); then
		ha_emit_verdict "RG1 Group 8a new-owner Kernel RX dropped delta ${delta} (limit ${MAX_TRANSITION_KERNEL_RX_DROPPED_DELTA})" \
			ha_counter_at_most_verdict "$delta" "$MAX_TRANSITION_KERNEL_RX_DROPPED_DELTA" "Kernel RX dropped"
	else
		reason=$(<"$sample_error")
		void "RG1 Group 8a new-owner Kernel RX dropped: ${reason:-counter delta unavailable}"
	fi
	if delta=$(ha_rg1_sampled_counter_delta node1 "Direct TX no-frame fb" \
		"${RG1_STATS[phase-pre:node1]}" "${node1_stats[@]}" 2>"$sample_error"); then
		ha_emit_verdict "RG1 Group 8b former-owner Direct TX no-frame fb delta ${delta} (limit ${MAX_TRANSITION_DIRECT_TX_NOFRAME_DELTA})" \
			ha_counter_at_most_verdict "$delta" "$MAX_TRANSITION_DIRECT_TX_NOFRAME_DELTA" "Direct TX no-frame fb"
	else
		reason=$(<"$sample_error")
		void "RG1 Group 8b former-owner Direct TX no-frame fb: ${reason:-counter delta unavailable}"
	fi
	if lan_rx=$(ha_rg1_sampled_interface_delta node1 'ge-[0-9]+-0-1' rx \
		"${RG1_INTERFACES[phase-pre:node1]}" "${node1_interfaces[@]}" 2>"$sample_error"); then
		if (( lan_rx < TRANSITION_PATH_TRIGGER_PKTS )); then
			ha_emit_diagnostic_verdict "RG1 Group 8c transition path below-trigger observation (old-owner LAN RX ${lan_rx}, trigger ${TRANSITION_PATH_TRIGGER_PKTS})" \
				ha_transition_path_verdict "$lan_rx" 0 0 0 "$TRANSITION_PATH_TRIGGER_PKTS" \
				"$MIN_FABRIC_TX_DELTA" "$MIN_TRANSITION_FABRIC_RX_DELTA" "$MIN_TRANSITION_WAN_TX_DELTA"
		elif old_fabric_tx=$(ha_rg1_sampled_interface_delta node1 'ge-[0-9]+-0-0' tx \
			"${RG1_INTERFACES[phase-pre:node1]}" "${node1_interfaces[@]}" 2>"$sample_error") \
			&& new_fabric_rx=$(ha_rg1_sampled_interface_delta node0 'ge-[0-9]+-0-0' rx \
			"${RG1_INTERFACES[phase-pre:node0]}" "${node0_interfaces[@]}" 2>"$sample_error") \
			&& new_wan_tx=$(ha_rg1_sampled_interface_delta node0 "$STANDBY_WAN_IFACE_REGEX" tx \
			"${RG1_INTERFACES[phase-pre:node0]}" "${node0_interfaces[@]}" 2>"$sample_error"); then
			ha_emit_diagnostic_verdict "RG1 Group 8c transition path at/above trigger (old LAN RX ${lan_rx}, fabric TX ${old_fabric_tx}, new fabric RX ${new_fabric_rx}, new WAN TX ${new_wan_tx})" \
				ha_transition_path_verdict "$lan_rx" "$old_fabric_tx" "$new_fabric_rx" "$new_wan_tx" \
				"$TRANSITION_PATH_TRIGGER_PKTS" "$MIN_FABRIC_TX_DELTA" \
				"$MIN_TRANSITION_FABRIC_RX_DELTA" "$MIN_TRANSITION_WAN_TX_DELTA"
		else
			reason=$(<"$sample_error")
			void "RG1 Group 8c transition path: ${reason:-sampled path counters unavailable}"
		fi
	else
		reason=$(<"$sample_error")
		void "RG1 Group 8c transition path: ${reason:-old-owner LAN RX evidence unavailable}"
	fi
	ha_rg1_report_sample_max "Pending TX local" node0 "Pending TX local" \
		"${RG1_STATS[phase-pre:node0]}" "${node0_stats[@]}"
	ha_rg1_report_sample_max "Pending TX local" node1 "Pending TX local" \
		"${RG1_STATS[phase-pre:node1]}" "${node1_stats[@]}"
	ha_rg1_report_sample_max "Outstanding TX" node0 "Outstanding TX" \
		"${RG1_STATS[phase-pre:node0]}" "${node0_stats[@]}"
	ha_rg1_report_sample_max "Outstanding TX" node1 "Outstanding TX" \
		"${RG1_STATS[phase-pre:node1]}" "${node1_stats[@]}"
}

ha_run_rg1_failback_slice() {
	RG1_FAILBACK_SETTLED=false
	local sync_ok=true pre_ok=true pre_capture_ok=true owner_moved=false mid_capture_ok=true
	local mid_owner_ok=true post_capture_ok=true post_owner_ok=true load_ok=true can_measure=true
	local failure_reason="" request_output request_rc index phase sample_error
	info "Manual RG1 failback: isolating fw1/node1→fw0/node0 before RG0/RG2"
	if ! main_iperf_running; then
		load_ok=false
		failure_reason="main iperf process was not alive before phase-pre"
	fi
	if ! ha_wait_for_session_sync_idle "before RG1 failback" node1 "$FW1" node0 "$FW0"; then
		sync_ok=false
		failure_reason="${failure_reason:+${failure_reason}; }RG1 precondition session sync did not pass"
	fi
	if ! main_iperf_running; then
		load_ok=false
		failure_reason="${failure_reason:+${failure_reason}; }main iperf process was not alive at phase-pre"
	fi
	if ! ha_capture_rg1_pair phase-pre; then
		pre_capture_ok=false
		failure_reason="${failure_reason:+${failure_reason}; }phase-pre capture was blind"
	else
		if ha_rg1_owner_status_cell node1 phase-pre "RG1 phase-pre owner is fw1/node1"; then
			:
		else
			pre_ok=false
			failure_reason="${failure_reason:+${failure_reason}; }phase-pre RG1 owner was not proven as fw1/node1"
		fi
	fi
	if request_output=$(incus exec "$FW1" -- cli -c \
		'request chassis cluster failover redundancy-group 1' 2>&1); then
		request_rc=0
	else
		request_rc=$?
	fi
	info "RG1 failover request returned status ${request_rc}; request text is not ownership proof${request_output:+: ${request_output}}"
	if ha_wait_rg1_owner node0 "$MANUAL_FAILOVER_DEADLINE"; then
		owner_moved=true
	else
		local owner_rc=$?
		if (( owner_rc == 1 )); then
			failure_reason="${failure_reason:+${failure_reason}; }RG1 did not move to fw0/node0"
		else
			failure_reason="${failure_reason:+${failure_reason}; }RG1 owner polling was blind"
		fi
	fi
	if [[ "$owner_moved" == true ]]; then
		if ! main_iperf_running; then
			load_ok=false
			failure_reason="${failure_reason:+${failure_reason}; }main iperf process was not alive at phase-mid"
		fi
		if ! ha_capture_rg1_pair mid; then
			mid_capture_ok=false
			RG1_FAILBACK_SETTLED=false
			failure_reason="${failure_reason:+${failure_reason}; }phase-mid capture was blind"
		else
			if ha_rg1_owner_status_cell node0 mid "RG1 phase-mid owner is fw0/node0"; then
				:
			else
				mid_owner_ok=false
				RG1_FAILBACK_SETTLED=false
				failure_reason="${failure_reason:+${failure_reason}; }phase-mid RG1 owner was not proven as fw0/node0"
			fi
		fi
		if ha_target_reachability_cell "after RG1 failback"; then :; else :; fi
		ha_external_sweep "RG1 failback immediate"
		for ((index = 1; index <= 10; index++)); do
			phase=$(printf 'sample-%02d' "$index")
			sleep 1
			if ! main_iperf_running; then
				load_ok=false
				failure_reason="${failure_reason:+${failure_reason}; }main iperf process not alive before ${phase}"
			fi
			if ! ha_capture_rg1_sample_pair "$phase"; then
				failure_reason="${failure_reason:+${failure_reason}; }${phase} statistics/interfaces capture was blind"
			fi
			if ! main_iperf_running; then
				load_ok=false
				failure_reason="${failure_reason:+${failure_reason}; }main iperf process not alive after ${phase}"
			fi
		done
		if ! main_iperf_running; then
			load_ok=false
			failure_reason="${failure_reason:+${failure_reason}; }main iperf process was not alive at phase-post"
		fi
		if ! ha_capture_rg1_pair phase-post; then
			post_capture_ok=false
			post_owner_ok=false
			RG1_FAILBACK_SETTLED=false
			failure_reason="${failure_reason:+${failure_reason}; }phase-post capture was blind"
		else
			if ha_rg1_owner_status_cell node0 phase-post "RG1 phase-post owner remains fw0/node0"; then
				:
			else
				post_owner_ok=false
				RG1_FAILBACK_SETTLED=false
				failure_reason="${failure_reason:+${failure_reason}; }phase-post RG1 owner was not proven as fw0/node0"
			fi
		fi
		if ! main_iperf_running; then
			load_ok=false
			failure_reason="${failure_reason:+${failure_reason}; }main iperf process did not remain alive through phase-post"
		fi
		if ha_target_reachability_cell "after RG1 failback post-sampler"; then :; else :; fi
		ha_external_sweep "RG1 failback post-sampler"
		ha_recent_dead_streams_cell "RG1 failback post-sampler"
	else
		if ha_target_reachability_cell "after RG1 failback attempt"; then :; else :; fi
		ha_external_sweep "RG1 failback immediate"
		ha_recent_dead_streams_cell "RG1 failback immediate"
		void "RG1 failback post-sampler: target and external sweeps unavailable because RG1 did not settle on fw0"
		void "RG1 failback post-sampler: external IPv4 reachability not measured"
		void "RG1 failback post-sampler: external IPv6 reachability not measured"
	fi
	if [[ "$sync_ok" != true || "$pre_ok" != true || "$pre_capture_ok" != true \
		|| "$owner_moved" != true || "$mid_capture_ok" != true || "$mid_owner_ok" != true \
		|| "$post_capture_ok" != true || "$post_owner_ok" != true || "$load_ok" != true ]]; then
		can_measure=false
	fi
	ha_rg1_evaluate "$can_measure" "${failure_reason:-RG1 slice prerequisites were not satisfied}"
}

# check_v6_transit asserts IPv6 traffic still crosses the firewall (#6934).
#
# It probes the WAN-side target rather than the LAN VIP deliberately. Pinging
# the VIP exercises L2 and local delivery on the same segment and never crosses
# the fabric, so it stays green through exactly the failures this is here to
# catch — measured: during a LAN/WAN redundancy-group split the VIP answers with
# 0% loss while transit is degraded.
#
# The failure message deliberately does NOT blame the neighbour cache. That was
# this issue's first instinct for three rounds and it is measurably wrong here:
# on this LAN host the IPv4 and IPv6 neigh parameters are byte-identical, and
# poisoning the default gateway's entry with a bogus MAC costs 8.51s in IPv6
# against 8.71s in IPv4 — symmetric, and 8.5s rather than the ~30/~60s the old
# message asserted. A stale neighbour entry can produce a blackhole; it cannot
# produce a v4/v6 ASYMMETRY on this host, and it cannot produce a ~60s one.
# Measurements in docs/log/6934.md.
#
# It tolerates losing packets but not all of them, and that threshold is
# measured rather than picked. A cross-node split costs the FIRST packet of a
# new flow, reproducibly and without self-healing, so a `-c 1` probe would be
# flaky on a healthy-enough cluster while a "0% loss" assertion would red on a
# condition this gate is not scoped to. Requiring 3 of 5 separates a blackhole
# (0 received — the #6934 report) from that first-packet loss (4 of 5).
check_v6_transit() {
	local label="$1" out recv
	out=$(incus exec "$CLUSTER_LAN_HOST" -- ping6 -c "$V6_PROBE_COUNT" -W 1 "$IPERF_TARGET6" 2>&1 || true)
	recv=$(printf '%s\n' "$out" | sed -n 's/.* \([0-9][0-9]*\) received.*/\1/p' | head -1)
	[ -z "$recv" ] && recv=0
	if [ "$recv" -ge "$V6_PROBE_MIN" ]; then
		pass "IPv6 transit OK ${label} (${recv}/${V6_PROBE_COUNT} to ${IPERF_TARGET6})"
	else
		fail "IPv6 transit BLACKHOLED ${label}: only ${recv}/${V6_PROBE_COUNT} replies from ${IPERF_TARGET6}. Do NOT reach for a neighbour-cache explanation first: on this LAN host every neigh parameter is byte-identical between the families (base_reachable_time_ms 30000/30000, gc_stale_time 60/60, delay_first_probe_time 5/5, retrans_time_ms 1000/1000, ucast_solicit 3/3), and a deliberately poisoned gateway entry repairs in 8.51s for v6 against 8.71s for v4 — symmetric, and 8.5s rather than 30 or 60. A v6-ONLY failure therefore has to be somewhere the families genuinely differ, and the one place they do here is the default route: v4 is proto static, v6 is proto ra with a 180s lifetime refreshed every 10-30s. Capture ip -6 route / ip -6 neigh AND their v4 twins DURING the window (#6934, docs/log/6934.md)"
	fi
}
# #7368: a PRECONDITION failure is not a failover regression, and neither is an
# ownership/forwarding divergence. All three used to exit 2, so `FO_RC=2` was
# read as "failover broke" when it meant "the cluster was not in a state to
# test" — twice, on the shared gate, against changes that were not at fault.
die_precondition() { echo "FATAL[PRECONDITION]: $*" >&2; exit 2; }
die_divergence()   { echo "FATAL[DIVERGENCE]: $*" >&2; exit 3; }

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

wait_for_instance() {
	local inst="$1" max="$2"
	for i in $(seq 1 "$max"); do
		if incus exec "$inst" -- systemctl is-active --quiet xpfd 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	return 1
}

# #9087: the #8297 proxy-ARP ownership check, EXTRACTED so it can run after
# every ownership change instead of only in the preflight.
#
# It used to run exactly once, before any failover happened. The run then
# crash-failed fw0 -> fw1, rejoined, and manually failed back fw1 -> fw0, and
# never re-read the entries. So a demotion that LEAKS the entry was invisible
# to a clean run BY CONSTRUCTION — the only observation point preceded every
# transition — and surfaced only as the NEXT run's preflight failing against
# the same binaries. A cell that can only observe the state that precedes every
# transition cannot see a transition defect.
#
# $1 is the phase label, so a failure names WHICH transition leaked rather than
# leaving the reader to guess which of three observation points fired.
check_proxy_arp_ownership() {
	local phase="$1"
	fw0_proxy=$(incus exec "$FW0" -- ip neigh show proxy 2>/dev/null | grep -c "$POOL_NAT_ADDR" || true)
	fw1_proxy=$(incus exec "$FW1" -- ip neigh show proxy 2>/dev/null | grep -c "$POOL_NAT_ADDR" || true)
	if [[ "$fw0_proxy" -ge 1 && "$fw1_proxy" -ge 1 ]]; then
		# The #8297 defect. Was a tracked known_gap until #8646 closed it; now a
		# plain failure, because a regression here is a regression and not a gap.
		fail "both nodes answer proxy-ARP for $POOL_NAT_ADDR after ${phase} (fw0=$fw0_proxy fw1=$fw1_proxy); the upstream sees one IP at two RETH virtual MACs, which is the #8297 defect returning"
	elif [[ "$fw0_proxy" -ge 1 && "$fw1_proxy" -eq 0 ]]; then
		# PROMOTED from known_gap by #8646, which moved proxy-ARP ownership off
		# VRRP events and onto the cluster. Measured before promoting: ten probes
		# 6s apart on a settled cluster, fw0=1 fw1=0 on all ten. One sample was
		# not enough — it cannot distinguish "the gate selected the owner" from
		# "both answered and the owner's reply landed last", which is the error
		# #8640 made on this same address.
		pass "only the RG owner answers proxy-ARP for $POOL_NAT_ADDR (${phase})"
	else
		# THIS BRANCH IS NOT LEFTOVER SCAFFOLDING, and it is the reason this
		# cell has three states rather than two. Do not collapse it.
		#
		# Reading the two branches above as "known_gap became pass/fail" invites
		# simplifying the whole block to `if fw1 == 0: pass` — which would delete
		# this arm, and this arm is the only thing that distinguishes "the owner
		# answers and the standby does not" from "NOBODY answers". Those look
		# identical to any assertion phrased about the standby alone.
		#
		# It is a state that actually happened: #8314 gated proxy-ARP on RG
		# ownership, was merged, and was REVERTED by #8342 because
		# `ip neigh show proxy` came back EMPTY ON BOTH NODES — the failure moved
		# from two answerers to zero, which breaks pool-mode NAT outright rather
		# than merely duplicating an answer. The cause was borrowing
		# `isRethMasterState`, whose own doc says it returns false when no
		# instances exist for the RG: safe for the DHCP relay it came from, an
		# outage here.
		#
		# So the assertion above is deliberately two-sided — the owner MUST
		# answer (fw0 >= 1), not merely "the standby must not" — and this arm
		# catches the half that a one-sided phrasing would pass.
		fail "the RG OWNER does not answer proxy-ARP for $POOL_NAT_ADDR after ${phase} (fw0=$fw0_proxy fw1=$fw1_proxy). Gating the owner is the OPPOSITE failure and breaks pool-mode NAT outright — this is the #8314 over-correction, not the #8297 defect"
	fi
}

# rg_ownership_diagnosis renders WHY a redundancy group did not move, not merely
# that it did not (#9452).
#
# THREE channels, because no one of them is sufficient and the issue's own
# acceptance named only the first:
#
#   - the per-RG readiness lines from BOTH nodes. `Transfer ready: no (<reason>)`
#     names a refusal on the node GIVING the RG up — a pending outbound bulk
#     (#3912) or the #2082 peer-priority gate. `Takeover ready: no (<reason>)`
#     names the readiness gate on the node TAKING it. Which one is false matters:
#     measured on #9452, `Transfer ready` was `yes` on both nodes for all three
#     RGs and `Takeover ready` was the false one, so a message carrying only the
#     transfer-readiness reason would still have said nothing.
#
#   - the PEER's view of the same RG. A transfer-out the peer never observed and
#     one it observed and declined are the same picture from one side.
#
#   - the election's own journal lines. The status lines are a SNAPSHOT, and the
#     #7162 startup promotion hold that blocked #9452 expires on its own after
#     30s — so by the time a failing cell reads status the gate can already read
#     `yes` and the only surviving record of the refusal is the log. This is the
#     channel that actually named the #9452 cause:
#       cluster: election blocked by readiness gate rg=0 ready=false
#         reasons="[session sync startup hold: bulk sync not yet complete]"
rg_ownership_diagnosis() {
	local rg="$1" node
	printf '    ---- RG%s ownership diagnosis ----\n' "$rg"
	for node in "$FW0" "$FW1"; do
		printf '    [%s] show chassis cluster status, redundancy group %s:\n' "$node" "$rg"
		incus exec "$node" -- cli -c 'show chassis cluster status' 2>&1 |
			awk -v rg="$rg" '
				$0 ~ ("^Redundancy group: " rg "[ ,]") { p = 1; print "      " $0; next }
				p && /^Redundancy group: / { p = 0 }
				p { print "      " $0 }' || true
	done
	printf '    [%s] election / transfer / promotion-hold journal since test start:\n' "$FW0"
	if [[ -n "$FAILOVER_JOURNAL_CURSOR" ]]; then
		failover_journal_after_cursor "$FW0" "$FAILOVER_JOURNAL_CURSOR" 2>/dev/null |
			grep -E "readiness gate|transfer out|transfer-out|manual failover|promotion hold|primary transition|degraded" |
			tail -10 | sed 's/^/      /' || true
	else
		printf '      unavailable: no test-start journal cursor; unscoped history omitted\n'
	fi
}

# #11873: pin the current fw0 journal position before preflight/test activity.
# Read from this cursor only if failback diagnosis is needed, so deploy-time
# sync-hold/timeout transients cannot be blamed on this run. Cursors, unlike
# --since timestamps, remain sound across the crash reboot's clock skew.
FAILOVER_JOURNAL_CURSOR=""
if FAILOVER_JOURNAL_CURSOR=$(failover_capture_journal_cursor "$FW0"); then
	info "Captured fw0 journal cursor for the failover test window"
else
	info "Could not capture fw0 journal cursor; out-of-window journal will be omitted"
fi

# ── Preflight ────────────────────────────────────────────────────────

info "Preflight checks"

for inst in "$FW0" "$FW1" "$CLUSTER_LAN_HOST"; do
	instance_running "$inst" || die "$inst is not running"
done

# Reset any stale manual failover flags from previous test runs.
# Without this, fw1 can't take over during the reboot test because
# ManualFailover blocks election even when the peer is lost.
for rg in 0 1 2; do
	incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
done
sleep 2

# Verify fw0 is primary for EVERY redundancy group.
#
# #7368: this was `grep -q "node0.*primary"` over the whole status output.
# `secondary` does not contain `primary`, so that part was sound — but the grep
# is not scoped to a redundancy group, so a cluster with node0 SECONDARY for
# RG0 and primary for RG1 satisfied it. The reassert makes node0 primary for
# all RGs, and the post-failover phase below already asserts all three, so the
# precondition should be the same shape. deploy_reassert_node0_primary_ok is
# the predicate #6591 added and `make test-deploy-lib` covers; reusing it keeps
# one definition of "node0 is primary" rather than a second grep that can drift.
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if printf '%s\n' "$fw0_status" | deploy_reassert_node0_primary_ok; then
	pass "fw0 is primary for every redundancy group"
else
	die_precondition "fw0 is not primary for every redundancy group — cannot run the failover test. This is a PRECONDITION failure, NOT a failover regression: the cluster was not in a testable state before the change under test ran. Check the post-deploy reassert (#6591) and re-read the state directly:
$fw0_status"
fi
if ha_wait_for_session_sync_idle "before traffic" node0 "$FW0" node1 "$FW1"; then :; else :; fi

# Keep the existing two-packet check; this three-packet + TCP fallback cell
# exercises the legacy target-reachability path before the load starts.
if ha_target_reachability_cell "before traffic"; then :; else :; fi

# Verify iperf target reachable
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 2 -W 2 "$IPERF_TARGET" &>/dev/null; then
	pass "iperf3 target reachable ($IPERF_TARGET)"
else
	fail "Cannot reach iperf3 target $IPERF_TARGET from ${CLUSTER_LAN_HOST} with the existing two-packet ping check"
fi

# #6934: the IPv6 baseline. Asserted BEFORE any failover so a later v6 failure
# is attributable to the transition rather than to a cluster that never had v6
# transit — without this the post-failover cells could red on a broken fixture.
check_v6_transit "at baseline (before any failover)"

# ── #8280: pool-mode source-NAT traffic, alongside the main stream ──
#
# WHY THIS EXISTS. Every source-nat rule on this cluster used to be
# `interface;` mode, which is ADDRESS-ONLY: it rewrites the source to the
# egress interface's own address and returns before any port allocation, so it
# never reaches PortAllocator / AddressOccupancy::claim. Measured on #7174 M13:
# a change to the NAT port allocator passed this smoke 17/17 while the smoke
# never executed a line of it — the run looked identical whether the change was
# correct, reverted or broken.
#
# THE STATE THIS ENTERS, stated because an assertion that never reaches it buys
# nothing:
#   fw0 (primary)  allocate_translation -> AddressOccupancy::claim  — the pool
#                  port is claimed from the fresh cursor, then from the recycle
#                  FIFO as ports free and are re-claimed.
#   fw1 (standby)  handle_upsert_synced -> reserve_flow ->
#                  occupancy.reserve() -> claim_offset  — the HA import side.
#   across the crash + failback the roles SWAP, so ports fw1 imported as
#   reservations become locally owned and released: the reserve/recycle
#   lifecycle across a role change, which is the interaction no unit test
#   reaches.
#
# The source address is the lever. 10.0.61.240/28 is matched by the config's
# `rule pool-snat` and is assigned to nothing (LAN host is .102, VIP .1, DHCP
# .100-.199), so adding it here is the ONLY way traffic takes the pool path and
# every other assertion in this script keeps measuring exactly what it did.
# POOL_NAT_SMOKE=0 disables this phase entirely, so the CONFIG change can be
# shown not to shift any existing path: the run must return exactly the same
# assertion count it did before the pool rule existed.
POOL_NAT_SMOKE="${POOL_NAT_SMOKE:-1}"
POOL_SRC="${POOL_SRC:-10.0.61.240}"
POOL_NAT_ADDR="${POOL_NAT_ADDR:-172.16.80.7}"
POOL_PORT="${POOL_PORT:-5210}"
POOL_LAN_IF="${POOL_LAN_IF:-$(incus exec "$CLUSTER_LAN_HOST" -- \
	bash -c "ip -4 -o route get ${LAN_GW:-10.0.61.1} 2>/dev/null | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p'" 2>/dev/null | tr -d '\r')}"

# pool_session_count echoes the number of sessions on $1 whose translated tuple
# carries the pool address, or the literal string "VOID" when the query did not
# produce a session listing at all.
#
# The three states matter. `show security flow session` is an admission-gated
# session-scan surface sharing one 4-slot budget across REST and gRPC, so a
# refusal returns no listing — and a bare `grep -c` renders that as 0, which is
# indistinguishable from "the allocator handed out nothing". The assertions
# below would then report a confident NAT-allocator defect for an admission
# event. "Total sessions:" is the listing's own terminator, so its presence is
# what separates "ran and found none" from "did not run".
# POOL_QUERY_ERR carries the last query's stderr, so a VOID can say WHY.
POOL_QUERY_ERR=""
pool_session_count() {
	local node="$1" out
	# stderr is CAPTURED, not discarded. Verified on the path this actually
	# runs: cmd/cli/show_flow.go calls GetSessions and on error does
	# `return fmt.Errorf(...)` BEFORE printing "Total sessions:", and
	# cmd/cli/main.go writes `error: %v` to stderr. So the absence of the
	# terminator is a sound refusal signal — and the reason is on stderr, which
	# an earlier version threw away, leaving a VOID that could not be acted on.
	POOL_QUERY_ERR=$(incus exec "$node" -- cli -c \
		"show security flow session source-prefix ${POOL_SRC}" 2>&1 >/dev/null || true)
	out=$(incus exec "$node" -- cli -c \
		"show security flow session source-prefix ${POOL_SRC}" 2>/dev/null || true)
	if ! grep -q "Total sessions:" <<<"$out"; then
		echo VOID
		return
	fi
	grep -c "$POOL_NAT_ADDR" <<<"$out" || true
}

pool_src_teardown() {
	[[ -n "$POOL_LAN_IF" ]] || return 0
	incus exec "$CLUSTER_LAN_HOST" -- pkill -9 -f "iperf3.*-B ${POOL_SRC}" 2>/dev/null || true
	incus exec "$CLUSTER_LAN_HOST" -- \
		ip addr del "${POOL_SRC}/24" dev "$POOL_LAN_IF" 2>/dev/null || true
}
failover_teardown() {
	failover_stop_main_iperf /tmp/iperf3-failover.pid "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
	pool_src_teardown
}
# The cluster is SHARED: the secondary address must not outlive this run
# whatever happens, including a die() in the middle of a phase.
trap failover_teardown EXIT

if [[ "$POOL_NAT_SMOKE" != 1 ]]; then
	POOL_LAN_IF=""
	info "#8280: pool-mode NAT phase DISABLED (POOL_NAT_SMOKE=0)"
elif [[ -z "$POOL_LAN_IF" ]]; then
	info "#8280: could not resolve the LAN interface on ${CLUSTER_LAN_HOST}; pool-mode NAT coverage will be reported as NOT MEASURED"
else
	incus exec "$CLUSTER_LAN_HOST" -- \
		ip addr add "${POOL_SRC}/24" dev "$POOL_LAN_IF" 2>/dev/null || true
fi

# Stop a previously tracked main client from an interrupted prior run.
failover_stop_main_iperf /tmp/iperf3-failover.pid "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
sleep 1

# ── Phase 1: Start iperf3 ───────────────────────────────────────────

info "Starting iperf3 --json-stream -P${IPERF_STREAMS} -t${IPERF_DURATION} -p${IPERF_PORT} → ${IPERF_TARGET}"

# iperf3 server handles one client at a time. After a previous test
# disrupts connections (session clear / failover), the server may hold
# a stale session until TCP keepalive fires (~minutes). Retry startup
# with increasing back-off to wait for the server to become available.
iperf_started=false
for attempt in 1 2 3; do
	failover_stop_main_iperf /tmp/iperf3-failover.pid "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
	sleep 1
	iperf_start_seconds=$SECONDS
	failover_start_main_iperf "$IPERF_DURATION" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" \
		/tmp/iperf3-failover.log /tmp/iperf3-failover.pid

	sleep 8  # all parallel streams must be fully established

	if ! main_iperf_running; then
		info "iperf3 exited on attempt $attempt — server may be busy, retrying"
		sleep $((attempt * 5))
		continue
	fi

	fw0_sessions=$(incus exec "$FW0" -- cli -c \
		"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
	if [[ "$fw0_sessions" -ge "$IPERF_STREAMS" ]]; then
		iperf_started=true
		break
	fi

	# The iperf3 3.20 refused-connect capture is an `event:error` JSON line on
	# stdout (fixture: failover-client-connect-error.jsonl); stderr was empty.
	# Retry only on the captured JSON connection-failure event.
	if failover_main_iperf_connect_failed /tmp/iperf3-failover.log; then
		info "iperf3 stream connect failed on attempt $attempt — server busy, retrying"
		failover_stop_main_iperf /tmp/iperf3-failover.pid "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
		sleep $((attempt * 10))
		continue
	fi

	iperf_started=true
	break
done

if ! $iperf_started; then
	if ! main_iperf_running; then
		incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log 2>/dev/null || true
		die "iperf3 failed to start after 3 attempts"
	fi
fi

# Verify iperf3 is running
if main_iperf_running; then
	pass "iperf3 running on ${CLUSTER_LAN_HOST}"
else
	incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log 2>/dev/null || true
	die "iperf3 failed to start"
fi

# Verify sessions exist on fw0.
# iperf3 server is single-client — if a stale session from the previous
# test lingers, some data streams may not connect. Accept MIN_SESSIONS
# (control + some data) rather than requiring all IPERF_STREAMS.
#
# #4052: the 8 TCP streams take a sub-second to finish their 3-way
# handshakes, so a single immediate assert here can catch the
# establishment window with only 0-3 session entries and FALSE-FAIL a
# healthy cluster (a settled cluster shows ~25 session entries at
# 23.4 Gbps / 0 retr). Poll up to 10s (20 × 0.5s), breaking as soon as
# the count reaches MIN_SESSIONS; only fail if enough session entries never
# appear within the timeout.
fw0_sessions=0
for _ in $(seq 1 20); do
	fw0_sessions=$(incus exec "$FW0" -- cli -c \
		"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
	[[ "$fw0_sessions" -ge "$MIN_SESSIONS" ]] && break
	sleep 0.5
done
# #7368: cross-reference the two independent checks this script already
# performs before deciding WHICH failure this is.
#
# Primacy is read from `show chassis cluster status` — a field the node reports
# about itself, with no oracle. The session count is a real measurement. They
# were never compared, so #6656's divergence (node0 primary with 1 session,
# node1 carrying 33) surfaced as a session-count shortfall
# attributed to whatever change was under test, when the actual failure was
# that ownership and forwarding disagreed.
#
# The peer count is read ONLY on the shortfall path, so the healthy run pays
# nothing. failover_ownership_verdict is pure and selftested.
if [[ "$fw0_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw0 has $fw0_sessions session entries"
else
	fw1_probe=$(incus exec "$FW1" -- cli -c \
		"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
	case "$(failover_ownership_verdict "$fw0_sessions" "$fw1_probe" "$MIN_SESSIONS")" in
	diverged)
		die_divergence "OWNERSHIP AND FORWARDING DISAGREE. fw0 reports PRIMARY for every redundancy group but carries only $fw0_sessions session(s), while fw1 — reported secondary — carries $fw1_probe. The cluster-state field and the session counts disagree, so neither 'failover is broken' nor 'too few session entries' is the right reading; see #6656. Read both nodes directly before re-running:
  incus exec $FW0 -- cli -c 'show chassis cluster status'
  incus exec $FW1 -- cli -c 'show chassis cluster status'"
		;;
	*)
		fail "fw0 has only $fw0_sessions session entries (expected >= $MIN_SESSIONS); fw1 carries $fw1_probe, so this is a session-count shortfall rather than an ownership/forwarding divergence"
		;;
	esac
fi

# ── Phase 1b: pool-mode NAT traffic (#8280) ─────────────────────────
#
# A SECOND iperf3, bound to the pool-matched source and aimed at a different
# CoS class port, so it cannot contend with the main stream on 5211 (the
# server handles one client per port).
if [[ -n "$POOL_LAN_IF" ]]; then
	incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"iperf3 --forceflush --connect-timeout 5000 -B ${POOL_SRC} -t ${IPERF_DURATION} -c ${IPERF_TARGET} -p ${POOL_PORT} -P 2 > /tmp/iperf3-pool-8280.log 2>&1 &"
	sleep 6
fi

# ── Phase 2: Wait for session sync ──────────────────────────────────

info "Waiting ${SYNC_WAIT}s for session sync to fw1"
sleep "$SYNC_WAIT"

fw1_sessions=$(incus exec "$FW1" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
if [[ "$fw1_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw1 has $fw1_sessions synced sessions"
else
	fail "fw1 has only $fw1_sessions synced sessions (expected >= $MIN_SESSIONS)"
fi

# ── #8280: the pool allocator actually ran, and the peer imported it ──
#
# The discriminator is the TRANSLATED address. An interface-mode session shows
# reth0.80's own 172.16.80.8 in its `Out:` line; a POOL-mode session shows the
# pool's 172.16.80.7, which only AddressOccupancy::claim can hand out. Asserting
# "a session exists" would pass on interface mode and measure nothing.
if [[ "$POOL_NAT_SMOKE" != 1 ]]; then
	: # phase deliberately disabled; no assertion is owed
elif [[ -z "$POOL_LAN_IF" ]]; then
	fail "#8280 pool-mode NAT was NOT MEASURED: the LAN interface on ${CLUSTER_LAN_HOST} could not be resolved, so no traffic took the pool path. This is a VOID for the allocator, not a pass — the rest of this run says nothing about PortAllocator"
else
	pool_fw0=$(pool_session_count "$FW0")
	if [[ "$pool_fw0" == VOID ]]; then
		fail "#8280: fw0's session query returned no listing, so pool-mode NAT was NOT MEASURED. This is most likely session-scan ADMISSION (the surface is gated on a 4-slot budget shared across REST and gRPC), not a NAT defect — re-run when nothing else is scanning rather than reading it as an allocator failure. Query stderr: ${POOL_QUERY_ERR:-<none>}"
	elif [[ "$pool_fw0" -ge 1 ]]; then
		pass "fw0 translated $pool_fw0 pool-mode session(s) to $POOL_NAT_ADDR (PortAllocator::claim ran)"
	else
		fail "fw0 has no session translated to the pool address $POOL_NAT_ADDR. Either the pool-mode rule did not match ${POOL_SRC}, or the allocator refused — either way this run does NOT exercise the NAT port allocator (#8280)"
	fi

	# ── #8297 acceptance: the STANDBY must not answer proxy-ARP ──────────
	#
	# The defect was TWO answerers, so this asserts the NEGATIVE. Asserting that
	# the primary has the entry passes on the broken code — both nodes had it —
	# and would be a green about nothing.
	#
	# Read from the kernel (`ip neigh show proxy`), not from config: the config
	# said the same thing on both nodes throughout, and it was the installed
	# NTF_PROXY entry that differed from what ownership required.
	check_proxy_arp_ownership "preflight, before any failover"

	pool_fw1=$(pool_session_count "$FW1")
	if [[ "$pool_fw1" == VOID ]]; then
		fail "#8280: fw1's session query returned no listing, so the standby import was NOT MEASURED — see the admission note on the fw0 assertion above. Query stderr: ${POOL_QUERY_ERR:-<none>}"
	elif [[ "$pool_fw1" -ge 1 ]]; then
		pass "fw1 imported $pool_fw1 pool-mode session(s) (reserve_flow -> occupancy.reserve)"
	else
		fail "fw1 imported no pool-mode session for ${POOL_SRC}. The standby's reserve_flow -> occupancy.reserve() path is what a NAT-allocator change most affects across a role change, and it did not run (#8280)"
	fi
fi

if ha_wait_for_session_sync_idle "before fw0 crash" node0 "$FW0" node1 "$FW1"; then :; else :; fi
ha_pre_failover_observation

# ── Phase 3: Crash fw0 (sysrq reboot) ───────────────────────────────
#
# sysrq-b is the repo's proven unclean primitive (same as
# test-double-failover.sh): the guest resets instantly, with no unit
# stops, no priority-0 VRRP burst, and no shutdown-job queueing. The
# previous `reboot` here was a GRACEFUL systemd reboot despite the
# "unclean" claim — xpfd got a clean stop (emitting the planned-shutdown
# priority-0 burst, i.e. the ~1ms takeover path instead of the ~60ms
# worst-case detection this test exists to exercise) AND the whole
# shutdown queued behind any wedged stop job. The #1880 budget misses
# were exactly that: post-deploy `systemctl reload frr` poisons
# frr.service into a 2-minute stop-sigterm on FRR 10.6, and a graceful
# reboot inside that window waited out the timer.

info "Crashing fw0 (sysrq reboot — unclean shutdown, tests worst-case failover)"

# timeout is load-bearing AND needs -k: sysrq-b resets the guest
# INSTANTLY, killing the incus-agent serving this exec, so the exec
# never observes an exit status (measured: a 47-minute hang on the
# first live run). Worse, `incus exec` FORWARDS SIGTERM to the (dead)
# remote session instead of exiting (measured: `timeout 10` alone left
# the client alive for 38+ minutes), so only the -k SIGKILL follow-up
# reliably reaps the local client. `|| true` alone cannot save a
# command that never returns.
# Braces, not just 2>/dev/null on the command: bash prints its own
# "Killed" job notice for the SIGKILLed child, which would land in the
# test transcript as alarming noise.
failover_at_seconds=$((SECONDS - iperf_start_seconds))
{ timeout -k 5 10 incus exec "$FW0" -- bash -c 'echo b > /proc/sysrq-trigger' || true; } 2>/dev/null

# Wait for fw1 to detect failure and become primary
sleep 3
if ha_target_reachability_cell "after crash takeover"; then :; else :; fi
ha_external_sweep "crash takeover immediate"
ha_recent_dead_streams_cell "crash takeover immediate"

# Verify iperf3 survived the failover
if main_iperf_running; then
	pass "iperf3 survived fw0 reboot (failover to fw1)"
else
	fail "iperf3 DIED during fw0 reboot — failover broke TCP connections"
fi

# ── Phase 4: Wait for fw0 to come back as secondary (no auto-preempt) ─

info "Waiting for fw0 to reboot and rejoin as secondary (max ${REBOOT_WAIT}s)"

# Wall-clock budget (#1880): the old `seq 1 $REBOOT_WAIT` loop counted
# ITERATIONS as seconds, but each iteration costs ~1.2s (1s sleep +
# ~240ms incus exec), so "60s" silently meant ~74s and the PASS message
# under-reported by ~23%. Measured comebacks on the loss userspace
# cluster: ~22s clean (sysrq), so 60s wall keeps ~2.7x headroom.
fw0_back=false
wait_start=$SECONDS
crash_post_external_done=false
while (( SECONDS - wait_start < REBOOT_WAIT )); do
	if [[ "$crash_post_external_done" != true ]] && (( SECONDS - wait_start >= 10 )); then
		ha_external_sweep "crash post-10s"
		ha_recent_dead_streams_cell "crash post-10s"
		crash_post_external_done=true
	fi
	if wait_for_instance "$FW0" 1; then
		fw0_back=true
		info "fw0 xpfd active after $((SECONDS - wait_start))s"
		break
	fi
done
if [[ "$crash_post_external_done" != true ]]; then
	crash_elapsed=$((SECONDS - wait_start))
	if (( crash_elapsed < 10 )); then
		sleep $((10 - crash_elapsed))
	fi
	ha_external_sweep "crash post-10s"
	ha_recent_dead_streams_cell "crash post-10s"
fi

if $fw0_back; then
	pass "fw0 xpfd restarted after reboot"
else
	fail "fw0 xpfd did not come back within ${REBOOT_WAIT}s"
fi

# #11872: no NTP runs in the loss lab. A crash reboot can leave fw0 minutes
# behind, making fabric-auth and heartbeat freshness fail and blocking the
# pending-bulk peer barrier. Set BOTH clocks from one host UTC reading before
# the rejoin/failback checks.
if failover_resync_node_clocks "$FW0" "$FW1"; then
	pass "both firewall clocks resynced from host UTC after crash reboot"
else
	fail "could not resync both firewall clocks from host UTC after crash reboot"
fi


# Wait for cluster to stabilize (gRPC takes ~15s after systemctl active)
sleep 20

# Verify fw0 is secondary for EVERY redundancy group (NOT primary — no auto-preempt)
#
# These two assertions were `grep -q "node0.*secondary"` / `grep -q "node1.*primary"`
# over the whole status output — the #7368 shape, which the precondition above
# already fixed but which survived here. Unscoped, it does not just admit a
# partial state: because the secondary branch is tried FIRST, a cluster that
# auto-preempted for RG1 while staying secondary for RG0 matched it and reported
# PASS, leaving the elif that names the auto-preempt regression unreachable in
# precisely the mixed case it exists to catch. The failback loop below is already
# per-RG (`grep -A1 "Redundancy group: $rg"`); this phase was the gap between it
# and the per-RG precondition.
fw0_status_after=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if printf '%s\n' "$fw0_status_after" | deploy_node_role_every_rg_ok node0 secondary; then
	pass "fw0 rejoined as secondary for every redundancy group (no auto-preempt)"
elif printf '%s\n' "$fw0_status_after" | deploy_node_role_every_rg_ok node0 primary; then
	fail "fw0 auto-preempted to primary for every redundancy group (should stay secondary)"
else
	fail "fw0 is neither secondary nor primary for EVERY redundancy group after rejoin — a MIXED or unreadable state. A mixed state is itself the auto-preempt regression, on a subset of RGs:
$fw0_status_after"
fi

# Verify fw1 is still primary for EVERY redundancy group
fw1_status_after=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null)
if printf '%s\n' "$fw1_status_after" | deploy_node_role_every_rg_ok node1 primary; then
	pass "fw1 remains primary for every redundancy group after fw0 rejoin"
else
	fail "fw1 is not primary for every redundancy group after fw0 rejoin:
$fw1_status_after"
fi

# Verify iperf3 still running
if main_iperf_running; then
	pass "iperf3 survived fw0 rejoin"
elif failover_main_iperf_result_complete /tmp/iperf3-failover.log; then
	void "iperf3 completed before manual failback; no client remained to witness the failback event"
else
	fail "iperf3 DIED during fw0 rejoin"
fi

# ── Phase 4b: Manual failover — fw0 becomes primary again ───────────

info "Manual failback: measuring isolated RG1 from fw1/node1 to fw0/node0"
ha_run_rg1_failback_slice
failback_at_seconds=0

# After the measured RG1 slice, preserve the existing unmeasured RG0/RG2 moves.
# Each RG must be explicitly failed over — per-RG election is independent.
info "Manual failover: requesting fw1 to failover RG0 and RG2 to fw0"
for rg in 0 2; do
	# stderr is CAPTURED, not discarded. `2>/dev/null` here hid every refusal
	# this command can return, so a run that printed "Manual failover triggered"
	# and a run that printed nothing at all were the same transcript (#9452).
	incus exec "$FW1" -- cli -c "request chassis cluster failover redundancy-group $rg" 2>&1 |
		sed 's/^/    /' || true
done

# Verify fw0 is now primary for RG0 and RG2. RG1 was checked from both node
# status queries at phase-mid and phase-post above.
#
# A BOUNDED POLL, not a fixed `sleep 5`. The fixed sleep could not tell "the
# transfer was refused" from "the transfer is still in flight", and #9452 was
# the second: an RG moved 19-30s later, when the rejoining node's bounded
# #7162 startup promotion hold expired. So the cell was reading a real outage —
# fw1 had already demoted, leaving the RG owned by NEITHER node — and reporting
# it as a refusal, while simply lengthening the sleep would report a 30s
# blackhole as a pass.
#
# Polling gives the cell the ELAPSED time, which separates the two; the bound
# stays tight enough that the blackhole #9452 fixed still reds. Each RG is
# polled in turn, so later RGs are not charged the earlier ones' wait.
all_primary=true
if [[ "$RG1_FAILBACK_SETTLED" != true ]]; then
	all_primary=false
fi
slowest="$RG1_FAILBACK_ELAPSED"
for rg in 0 2; do
	fo_start=$(date +%s)
	moved=0
	while :; do
		if incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null |
			grep -A1 "Redundancy group: $rg" | grep -q "node0.*primary"; then
			moved=1
			break
		fi
		if (($(date +%s) - fo_start >= MANUAL_FAILOVER_DEADLINE)); then
			break
		fi
		sleep 1
	done
	fo_elapsed=$(($(date +%s) - fo_start))
	if ((moved)); then
		failback_at_seconds=$((SECONDS - iperf_start_seconds))
		if ((fo_elapsed > slowest)); then
			slowest=$fo_elapsed
		fi
		info "RG$rg moved to fw0 in ${fo_elapsed}s"
	else
		all_primary=false
		fail "fw0 is not primary for RG$rg ${MANUAL_FAILOVER_DEADLINE}s after manual failover. fw1 has ALREADY demoted, so for this whole window RG$rg is owned by NEITHER node: transit is blackholed and nothing answers proxy-ARP for the pool-NAT address. That is an outage, not a declined request — read the elapsed time and the readiness reasons below rather than assuming a refusal (#9452)
$(rg_ownership_diagnosis "$rg")"
	fi
done
if $all_primary; then
	pass "fw0 became primary for all RGs after manual failback (slowest ${slowest}s of ${MANUAL_FAILOVER_DEADLINE}s budget)"
fi
info "Recorded per-stream failback event at ${failback_at_seconds}s after iperf start (last RG moved)"

# Verify iperf3 survived manual failover
if main_iperf_running; then
	pass "iperf3 survived manual failover"
elif failover_main_iperf_result_complete /tmp/iperf3-failover.log; then
	pass "iperf3 completed successfully (finished before manual failover check)"
else
	fail "iperf3 DIED during manual failover"
fi

# #9087: re-read ownership AFTER the full crash-failover + manual-failback
# cycle. This is the state the NEXT run's preflight observes, and it is the one
# that was leaking: fw1 installs the entry while primary during the crash
# phase, steps back down at the failback, and used to keep it.
check_proxy_arp_ownership "after the crash failover AND the manual failback"

# ── #8280: the allocator still works AFTER a full role-change cycle ──
#
# THE STATE THIS ENTERS, which is the whole point of the phase. By this line
# fw0 has been primary -> secondary (crash) -> primary (manual failback). The
# pool ports it originally claimed were imported by fw1 as RESERVATIONS
# (reserve_flow -> occupancy.reserve -> claim_offset), then fw1 became primary
# and owned them, then primacy came back. A fresh claim now walks the recycle
# FIFO in exactly the post-churn state #7174 M13 is about: reserved-then-
# released tokens, and an `occupied` counter that must still agree with the
# bitmap. A leak leaves ports unclaimable; a drifted counter reports the address
# full when it is not. Either way this probe gets no translation.
#
# The sessions are CLEARED first. A surviving session from before the failover
# would satisfy "a pool-translated session exists" without a single new claim,
# which is a cell that passes without entering the state it names.
#
# The allocator and data path are both asserted below. #8297 fixed the
# proxy-ARP ownership needed for a pool-mode handshake; #10146 promotes the
# formerly known-gap #8341 data-path check to a real assertion.
if [[ "$POOL_NAT_SMOKE" == 1 && -n "$POOL_LAN_IF" ]]; then
	incus exec "$FW0" -- cli -c "clear security flow session source-prefix ${POOL_SRC}" &>/dev/null || true
	incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"timeout 6 iperf3 --connect-timeout 3000 -B ${POOL_SRC} -t 2 -c ${IPERF_TARGET} -p ${POOL_PORT} > /tmp/iperf3-pool-8280-post.log 2>&1 &" || true
	sleep 5
	post_pool=$(pool_session_count "$FW0")
	if [[ "$post_pool" == VOID ]]; then
		fail "#8280: the post-failback session query returned no listing, so the allocator's state after the role change was NOT MEASURED — see the admission note above. A VOID here is NOT evidence the allocator is healthy. Query stderr: ${POOL_QUERY_ERR:-<none>}"
	elif [[ "$post_pool" -ge 1 ]]; then
		pass "the pool allocator still hands out a translation after a full primary->secondary->primary cycle"
		# #8297 fixed the proxy-ARP ownership needed for a pool-mode handshake,
		# so the data-path half of this phase is now assertable. #8341 is a
		# separate regression: the allocator can hand out a translation while
		# TCP still fails before egress. The assertion below keeps those two
		# observations distinct.
		# #10146 promotes the formerly known-gap #8341 check to a real
		# assertion. A successful iperf3 run emits `iperf Done.`; matching
		# that positive result avoids treating an arbitrary error message as
		# proof that the pool-mode TCP flow connected.
		if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-pool-8280-post.log 2>/dev/null; then
			pass "a pool-mode TCP flow connects after the role change (data path, not just allocation)"
		else
			pool_log=$(incus exec "$CLUSTER_LAN_HOST" -- tail -5 /tmp/iperf3-pool-8280-post.log 2>&1 || echo "(pool probe log unreadable)")
			fail "a pool-mode TCP flow did not complete after the role change; the #8341 TCP-specific data-path defect may have returned. Pool probe log tail: ${pool_log}"
		fi
	else
		fail "after the crash failover AND the manual failback, a FRESH flow from ${POOL_SRC} got NO pool translation. The ports fw1 imported as reservations while it was standby are the ones a reserve/recycle lifecycle bug strands, and this is the only assertion in this suite that enters that state (#8280 / #7174 M13)"
	fi
fi

# #6934: the reported scenario. A manual RG failover moves the RETH virtual MAC,
# so every peer holding a neighbour entry for a VIP or for the stable RETH
# link-local must be corrected by the unsolicited-NA burst. The iperf3 check
# above cannot see a failure here: it is one long-lived IPv4 flow, so it
# survives on established state while a NEW IPv6 flow blackholes.
check_v6_transit "after manual failover"

# #6934: sample the window TWICE, not once. The reported symptom self-heals
# after ~60s with no intervention, and a single probe fired immediately after
# the failover reports a clean pass whether it landed before such a window
# opened or after it closed — a check that cannot distinguish "healthy" from
# "I sampled the wrong instant".
#
# Cost, counted rather than asserted: the 120s iperf3 starts at line ~207 and by
# the time control reaches here the script has already spent 8 + SYNC_WAIT + 3 +
# (reboot wait) + 20 + 5 seconds plus a 5-packet probe. That typically leaves
# ~35-55s of iperf3 still to run. Phase 5 waits for its terminal log marker for
# at most IPERF_DURATION seconds; normally this overlaps the remaining run and
# its final control exchange.
sleep "$V6_RECHECK_DELAY"
check_v6_transit "${V6_RECHECK_DELAY}s after manual failover"

# ── Phase 5: Wait for an iperf3 result and validate it ───────────────

info "Waiting for iperf3 final result (up to ${IPERF_DURATION}s)"

failover_wait_main_iperf_result /tmp/iperf3-failover.log "$IPERF_DURATION" || true

# Derive the throughput headline only from gate-validated JSON-stream metrics.
# Missing, malformed, or incomplete metrics are VOID evidence, never a
# zero-valued throughput FAIL; valid averages go through the anchored cell.
# M1 JSON capture/gate fixture begin
LOCAL_IPERF_LOG="${TMPDIR:-/tmp}/iperf3-failover.$$.json-stream.log"
LOCAL_IPERF_METRICS="${TMPDIR:-/tmp}/iperf3-failover.$$.metrics.json"
LOCAL_IPERF_GATE_ERR="${LOCAL_IPERF_METRICS}.gate.err"
LOCAL_IPERF_PRODUCER_ERR="${LOCAL_IPERF_METRICS}.producer.err"
iperf_gate_ok=false
iperf_gate_reason=""

if ! incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log \
	>"$LOCAL_IPERF_LOG" 2>/dev/null; then
	printf '{"ok":false,"error":"metrics_capture_failed"}\n' >"$LOCAL_IPERF_METRICS"
elif ! python3 "${SCRIPT_DIR}/../../scripts/iperf-json-metrics.py" \
	"$LOCAL_IPERF_LOG" >"$LOCAL_IPERF_METRICS" 2>"$LOCAL_IPERF_PRODUCER_ERR"; then
	printf '{"ok":false,"error":"metrics_parse_failed"}\n' >"$LOCAL_IPERF_METRICS"
fi

if gate_output=$(ha_metrics_gate "$LOCAL_IPERF_METRICS" 2>"$LOCAL_IPERF_GATE_ERR"); then
	eval "$gate_output"
	iperf_gate_ok=true
else
	iperf_gate_reason=$(<"$LOCAL_IPERF_GATE_ERR")
	[[ -n "$iperf_gate_reason" ]] || iperf_gate_reason="ha_metrics_gate rejected metrics"
fi
# M1 JSON capture/gate fixture end

if [[ "$iperf_gate_ok" == true ]]; then
	ha_emit_verdict "iperf3 whole-run zero-throughput intervals (${zero_intervals_total}, limit ${MAX_ZERO_INTERVALS})" \
		ha_counter_at_most_verdict "$zero_intervals_total" "$MAX_ZERO_INTERVALS" "whole-run zero intervals"
	ha_emit_verdict "iperf3 whole-run per-stream zero intervals (${stream_zero_intervals_total}, limit ${MAX_STREAM_ZERO_INTERVALS}; ${zero_streams_total} affected stream(s))" \
		ha_counter_at_most_verdict "$stream_zero_intervals_total" "$MAX_STREAM_ZERO_INTERVALS" "whole-run per-stream zero intervals"
	info "iperf3 whole-run zero-throughput streams: ${zero_streams_total}"
	pass "iperf3 sender retransmits ${retransmits}"
	if [[ -n "$MAX_RETRANSMITS" ]]; then
		ha_emit_verdict "iperf3 retransmits ${retransmits} (limit ${MAX_RETRANSMITS})" \
			ha_counter_at_most_verdict "$retransmits" "$MAX_RETRANSMITS" "retransmits"
	fi
	if [[ -n "$MAX_RETRANSMITS_PER_GBPS" ]]; then
		if [[ ! "$MAX_RETRANSMITS_PER_GBPS" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
			void "iperf3 retransmits-per-Gbps limit is malformed: ${MAX_RETRANSMITS_PER_GBPS}"
		else
			retrans_per_gb="$(awk -v retransmits="$retransmits" -v throughput="$avg_gbps" \
				'BEGIN { if (throughput <= 0) print 0; else printf "%.3f", retransmits / throughput }')"
			if awk "BEGIN{exit !(${retrans_per_gb} <= ${MAX_RETRANSMITS_PER_GBPS})}"; then
				pass "iperf3 retransmits per Gbps ${retrans_per_gb} within limit ${MAX_RETRANSMITS_PER_GBPS}"
			else
				fail "iperf3 retransmits per Gbps ${retrans_per_gb} exceed limit ${MAX_RETRANSMITS_PER_GBPS}"
			fi
		fi
	fi
	if [[ "$collapse_detected" == true ]]; then
		fail "iperf3 interval collapse detected: ${collapse_reason}"
	else
		pass "iperf3 interval collapse not detected"
	fi
	completion_grace="${IPERF_COMPLETION_GRACE_SEC:-2}"
	if [[ "$completed" == true ]]; then
		pass "iperf3 completed successfully"
	elif awk "BEGIN{exit !(${observed_end_sec} >= (${IPERF_DURATION} - ${completion_grace}))}"; then
		if awk "BEGIN{exit !(${avg_gbps} >= ${MIN_THROUGHPUT})}"; then
			pass "iperf3 data transfer completed (${avg_gbps} Gbps) — observed JSON duration with adequate throughput"
		else
			fail "iperf3 reached the expected JSON duration but throughput was below ${MIN_THROUGHPUT} Gbps"
		fi
	else
		VOID=$((VOID + 1))
		echo "  VOID iperf3 completion: JSON stream has no end event and observed ${observed_end_sec}s is short of the effective duration"
	fi
else
	void "iperf3 whole-run JSON metrics unavailable: ${iperf_gate_reason}"
fi

# M1 JSON verdict fixture begin
# Only gate-validated JSON metrics may produce the anchored throughput cell.
# A rejected document is ordinary VOID evidence, not a zero-throughput FAIL.
if [[ "$iperf_gate_ok" == true ]]; then
	evidence_note="json-stream avg_gbps from ${LOCAL_IPERF_METRICS}; ${full_interval_count} full intervals"
	throughput_verdict=$(iperf_throughput_json_verdict "$MIN_THROUGHPUT" "$avg_gbps" "$evidence_note")
	case "$throughput_verdict" in
	PASS\ *) pass "${throughput_verdict#PASS }" ;;
	FAIL\ *) fail "${throughput_verdict#FAIL }" ;;
	*)       fail "iperf3 throughput: unrecognised verdict from iperf_throughput_json_verdict: ${throughput_verdict}" ;;
	esac
else
	VOID=$((VOID + 1))
	echo "  VOID iperf3 throughput: ${iperf_gate_reason}"
fi
# M1 JSON verdict fixture end

if [[ "$iperf_gate_ok" == true ]]; then
	oracle_error="${LOCAL_IPERF_METRICS}.oracle.err"
	if failover_oracles=$(python3 "${SCRIPT_DIR}/iperf3_sum_parse.py" \
		--failover-check --json-stream --streams "$IPERF_STREAMS" \
		--min-throughput-gbps "$MIN_THROUGHPUT" --crash-at "$failover_at_seconds" \
		--failback-at "$failback_at_seconds" \
		<"$LOCAL_IPERF_LOG" 2>"$oracle_error"); then
		while IFS= read -r oracle; do
			case "$oracle" in
			PASS\ *) pass "${oracle#PASS }" ;;
			FAIL\ *) fail "${oracle#FAIL }" ;;
			VOID\ *) void "${oracle#VOID }" ;;
			*)       fail "iperf3 failover oracle returned an unrecognised verdict: ${oracle}" ;;
			esac
		done <<< "$failover_oracles"
	else
		oracle_reason=$(<"$oracle_error")
		void "iperf3 failover/failback oracle evidence unavailable: ${oracle_reason:-JSON interval parser failed}"
	fi
else
	info "Skipping JSON crash/failback oracle because the whole-run metrics gate rejected its input"
fi

# M1 JSON summary precedence fixture begin
if (( FAIL == 0 && VOID > 0 )); then
	exit 77
fi

# The summary is the one line the harness ledger parses. Keep its grammar
# unchanged; measured FAIL outranks ordinary capture VOID.
echo "  Failover test: $PASS passed, $FAIL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
	echo
	echo "Failures:"
	for err in "${ERRORS[@]}"; do
		echo "  - $err"
	done
	exit 1
fi
# M1 JSON summary precedence fixture end
