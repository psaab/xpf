#!/usr/bin/env bash
# xpf chained hard-reset failover test
#
# Validates that the cluster survives TWO consecutive hard-reset failovers
# across BOTH nodes with iperf3 traffic continuity:
#   fw0 crash → fw1 takes over → fw0 rejoins → fw1 crash → fw0 takes over → fw1 rejoins
#
# Unlike test-double-failover.sh (sysrq reboot), this uses `incus stop --force`
# to simulate abrupt power loss (no graceful shutdown, no priority-0 burst).
# The stopped VM must be explicitly restarted with `incus start`.
#
# Requires: cluster nodes from BPFRX_CLUSTER_ENV running (default: loss userspace cluster).
# Requires: iperf3 server reachable at IPERF_TARGET (default from IPERF_TARGET4).
#
# Phases:
#   Phase 1: fw0 hard-reset → fw1 becomes primary for all RGs
#   Phase 2: fw0 restart → fw0 rejoins as secondary, session sync established
#   Phase 3: fw1 hard-reset → fw0 becomes primary for all RGs
#   Phase 4: fw1 restart → cluster stable, both nodes healthy
#   Throughout: iperf3 TCP flow from cluster-lan-host survives (or new connections work)
#
# Usage:
#   ./test/incus/test-chained-crash.sh
#   IPERF_TARGET=10.1.2.3 ./test/incus/test-chained-crash.sh

set -euo pipefail

# #1875/#4020: this DESTRUCTIVE smoke reboots / force-stops / fails
# over a node on the SHARED loss cluster. Re-exec under the
# incus-admin group if needed, then serialize as a #1875 lock cell
# so a concurrent deploy/smoke can't collide with our reboot (it
# queues behind a held /tmp/xpf-cluster.lock instead of colliding).
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_DIR="$_CELL_DIR"
if [[ "${1:-}" == "--selftest" ]]; then
	if [[ $# -ne 1 ]]; then
		echo "usage: $0 --selftest" >&2
		exit 2
	fi
	exec bash "${SCRIPT_DIR}/iperf-throughput-selftest.sh" "$(basename "${BASH_SOURCE[0]}")"
fi

# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "test-chained-crash $*" "$0" "$@"

# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/iperf-throughput-lib.sh
source "${SCRIPT_DIR}/iperf-throughput-lib.sh"
# shellcheck source=test/incus/ha-smoke-iperf-lib.sh
source "${SCRIPT_DIR}/ha-smoke-iperf-lib.sh"
IPERF_TARGET="${IPERF_TARGET:-$IPERF_TARGET4}"
# #9691: measure the UNSHAPED class. iperf3 defaults to port 5201, which
# cos-iperf-config.set classifies as iperf-100m (transmit-rate 100m exact) on
# the reth0.80 path to IPERF_TARGET4, so this gate's throughput verdict depended
# on whether CoS was left applied on the shared cluster. #7673 fixed the same
# in test-failover.sh; iperf-throughput-selftest.sh asserts, for every HA smoke,
# that this port still maps to an unshaped class.
IPERF_PORT="${IPERF_PORT:-5211}"
IPERF_DURATION=300      # seconds — long enough to span both failover cycles
IPERF_STREAMS=4
MIN_SESSIONS=4          # minimum observed session entries (control + some data streams)
SYNC_WAIT=5             # seconds to wait for session sync sweep
TAKEOVER_TIMEOUT=5      # max seconds for new primary to take over
TAKEOVER_WAIT=60        # max seconds to wait for "Takeover ready: yes"
CONN_TIMEOUT=10         # max seconds for new TCP to succeed
VM_RESTART_WAIT=90      # max seconds for VM to come back after start
MIN_THROUGHPUT=1.0      # Gbps — iperf3 must report at least this

PASS=0
FAIL=0
ERRORS=()
LOG="/tmp/iperf3-chained-crash.log"
PIDFILE="/tmp/iperf3-chained-crash.pid"
IPERF_START_SECONDS=0
FAILOVER_EVENTS=()

main_iperf_running() {
	failover_main_iperf_running "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS"
}

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
die()   { echo "FATAL: $*" >&2; exit 2; }

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

wait_for_xpfd() {
	local inst="$1" max="$2"
	for i in $(seq 1 "$max"); do
		if incus exec "$inst" -- systemctl is-active --quiet xpfd 2>/dev/null; then
			echo "$i"
			return 0
		fi
		sleep 1
	done
	return 1
}

# Check that a specific node is primary for every RG.
node_is_primary() {
	local inst="$1" node="$2"
	local status
	status=$(incus exec "$inst" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	printf '%s\n' "$status" | deploy_node_role_every_rg_ok "$node" primary
}

fw0_is_primary() { node_is_primary "$FW0" "node0"; }
fw1_is_primary() { node_is_primary "$FW1" "node1"; }

# Wait for a node to become primary, return elapsed seconds
wait_for_node_primary() {
	local check_fn="$1" max="$2"
	for i in $(seq 1 "$max"); do
		if $check_fn; then
			echo "$i"
			return 0
		fi
		sleep 1
	done
	return 1
}

# Test new TCP connection through cluster
test_new_tcp() {
	local label="$1" max="$2"
	for i in $(seq 1 "$max"); do
		if incus exec "$CLUSTER_LAN_HOST" -- bash -c \
			"timeout 3 bash -c 'echo > /dev/tcp/${IPERF_TARGET}/5201'" 2>/dev/null; then
			pass "$label: new TCP connection succeeded (${i}s)"
			return 0
		fi
		sleep 1
	done
	fail "$label: new TCP connection failed within ${max}s"
	return 1
}

# Verify no dual-active: exactly one node should be primary per RG
check_no_dual_active() {
	local label="$1"
	local fw0_status fw1_status
	fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	fw1_status=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)

	local dual_active=false
	for rg in 0 1 2; do
		local fw0_pri fw1_pri
		fw0_pri=$(echo "$fw0_status" | grep -A2 "Redundancy group: $rg" | grep "node0" | grep -c "primary" || true)
		fw1_pri=$(echo "$fw1_status" | grep -A2 "Redundancy group: $rg" | grep "node1" | grep -c "primary" || true)
		if [[ "$fw0_pri" -eq 1 && "$fw1_pri" -eq 1 ]]; then
			fail "$label: dual-active detected on RG$rg"
			dual_active=true
		fi
	done
	if ! $dual_active; then
		pass "$label: no dual-active"
	fi
}

# Check session sync status on a node
check_session_sync() {
	local label="$1" inst="$2"
	local sync_status
	sync_status=$(incus exec "$inst" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	if echo "$sync_status" | grep -qi "Takeover ready.*yes"; then
		pass "$label: takeover ready (sync established)"
		return 0
	else
		fail "$label: not takeover-ready"
		return 1
	fi
}

cleanup() {
	info "Cleanup: stopping the tracked iperf3 client, ensuring both VMs are running"
	failover_stop_main_iperf "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
	# Ensure both VMs are running
	for inst in "$FW0" "$FW1"; do
		if ! instance_running "$inst"; then
			incus start "$inst" 2>/dev/null || true
			wait_for_xpfd "$inst" "$VM_RESTART_WAIT" >/dev/null 2>&1 || true
		fi
	done

	# Ensure xpfd is running on both
	incus exec "$FW0" -- systemctl start xpfd 2>/dev/null || true
	incus exec "$FW1" -- systemctl start xpfd 2>/dev/null || true
	sleep 5

	# Clear stale sessions
	incus exec "$FW0" -- cli -c "clear security flow session all" 2>/dev/null || true
	incus exec "$FW1" -- cli -c "clear security flow session all" 2>/dev/null || true

	# Reset failover flags
	for rg in 0 1 2; do
		incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
		incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	done
}

trap cleanup EXIT

# ── Preflight ────────────────────────────────────────────────────────

info "Preflight checks"

for inst in "$FW0" "$FW1" "$CLUSTER_LAN_HOST"; do
	instance_running "$inst" || die "$inst is not running"
done

# Reset any stale manual failover flags
for rg in 0 1 2; do
	incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
done
sleep 2

# Verify fw0 is primary
if fw0_is_primary; then
	pass "fw0 is primary for all RGs"
else
	die "fw0 is not primary for all RGs — cannot run chained crash test"
fi

# Stop only the client recorded by this harness; do not kill unrelated iperf3.
failover_stop_main_iperf "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
incus exec "$FW0" -- cli -c "clear security flow session all" 2>/dev/null || true
incus exec "$FW1" -- cli -c "clear security flow session all" 2>/dev/null || true
sleep 3

# Pre-warm ARP on both firewalls
incus exec "$FW0" -- ping -c 1 -W 3 "$IPERF_TARGET" &>/dev/null || true
incus exec "$FW1" -- ping -c 1 -W 3 "$IPERF_TARGET" &>/dev/null || true
sleep 1

# Verify iperf target reachable
target_ok=false
for i in $(seq 1 15); do
	if incus exec "$CLUSTER_LAN_HOST" -- ping -c 1 -W 3 "$IPERF_TARGET" &>/dev/null; then
		target_ok=true
		break
	fi
	sleep 1
done
if $target_ok; then
	pass "iperf3 target reachable ($IPERF_TARGET)"
else
	die "Cannot reach iperf3 target $IPERF_TARGET from ${CLUSTER_LAN_HOST}"
fi

# ── Start iperf3 ─────────────────────────────────────────────────────

info "Starting iperf3 -P${IPERF_STREAMS} -t${IPERF_DURATION} → ${IPERF_TARGET}"

iperf_started=false
for attempt in 1 2 3; do
	failover_stop_main_iperf "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
	sleep 1
	failover_start_main_iperf "$IPERF_DURATION" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" \
		"$LOG" "$PIDFILE" 1
	IPERF_START_SECONDS=$SECONDS

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

	if failover_main_iperf_connect_failed "$LOG"; then
		info "iperf3 stream connect failed on attempt $attempt — server busy, retrying"
		failover_stop_main_iperf "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
		sleep $((attempt * 10))
		continue
	fi

	iperf_started=true
	break
done

if ! $iperf_started; then
	if ! main_iperf_running; then
		incus exec "$CLUSTER_LAN_HOST" -- cat "${LOG}" 2>/dev/null || true
		die "iperf3 failed to start after 3 attempts"
	fi
fi

if main_iperf_running; then
	pass "tracked iperf3 client running on ${CLUSTER_LAN_HOST}"
else
	incus exec "$CLUSTER_LAN_HOST" -- cat "${LOG}" 2>/dev/null || true
	die "iperf3 failed to start"
fi

# Verify sessions on fw0
fw0_sessions=$(incus exec "$FW0" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
if [[ "$fw0_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw0 has $fw0_sessions session entries"
else
	fail "fw0 has only $fw0_sessions session entries (expected >= $MIN_SESSIONS)"
fi

# Wait for session sync fw0 → fw1
info "Waiting ${SYNC_WAIT}s for session sync to fw1"
sleep "$SYNC_WAIT"

fw1_sessions=$(incus exec "$FW1" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
if [[ "$fw1_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw1 has $fw1_sessions synced sessions"
else
	fail "fw1 has only $fw1_sessions synced sessions (expected >= $MIN_SESSIONS)"
fi

# ═══════════════════════════════════════════════════════════════════════
# Phase 1: Hard-reset fw0 → fw1 becomes primary
# ═══════════════════════════════════════════════════════════════════════

info "Phase 1: Hard-reset fw0 (incus stop --force) — fw1 must take over"

FAILOVER_EVENTS+=("$((SECONDS - IPERF_START_SECONDS))")
incus stop --force "$FW0" 2>/dev/null || true

# Wait for fw1 to take over
takeover_time=$(wait_for_node_primary fw1_is_primary "$TAKEOVER_TIMEOUT" || true)
if [[ -n "$takeover_time" ]]; then
	pass "phase1: fw1 became primary for all RGs (${takeover_time}s)"
else
	fail "phase1: fw1 did not become primary within ${TAKEOVER_TIMEOUT}s"
fi

# Verify iperf3 survived first failover
if main_iperf_running; then
	pass "phase1: tracked iperf3 client survived fw0 hard-reset (failover to fw1)"
else
	fail "phase1: tracked iperf3 client died during fw0 hard-reset"
fi
# Verify new TCP connections work through fw1
test_new_tcp "phase1" "$CONN_TIMEOUT"

# Verify connectivity via ping
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 3 "$IPERF_TARGET" &>/dev/null; then
	pass "phase1: ping through fw1 works"
else
	fail "phase1: ping through fw1 failed"
fi

# ═══════════════════════════════════════════════════════════════════════
# Phase 2: Restart fw0 → rejoins as secondary, session sync established
# ═══════════════════════════════════════════════════════════════════════

info "Phase 2: Restarting fw0 — must rejoin as secondary with session sync"

incus start "$FW0" 2>/dev/null || true

restart_time=$(wait_for_xpfd "$FW0" "$VM_RESTART_WAIT" || true)
if [[ -n "$restart_time" ]]; then
	pass "phase2: fw0 xpfd restarted (${restart_time}s)"
else
	fail "phase2: fw0 xpfd did not restart within ${VM_RESTART_WAIT}s"
fi

# Wait for cluster to stabilize
sleep 20

fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
# Verify fw0 is secondary (no auto-preempt)
if printf '%s\n' "$fw0_status" | deploy_node_role_every_rg_ok node0 secondary; then
	pass "phase2: fw0 rejoined as secondary for every RG (no auto-preempt)"
elif printf '%s\n' "$fw0_status" | deploy_node_role_every_rg_ok node0 primary; then
	fail "phase2: fw0 auto-preempted to primary (should stay secondary)"
else
	fail "phase2: fw0 role is unclear for one or more RGs"
fi
if fw1_is_primary; then
	pass "phase2: fw1 remains primary after fw0 rejoin"
else
	fail "phase2: fw1 is not primary after fw0 rejoin"
fi

# Check no dual-active
check_no_dual_active "phase2"

# Wait for "Takeover ready: yes" on fw0 (sync hold released)
info "Phase 2: Waiting for fw0 'Takeover ready: yes' (max ${TAKEOVER_WAIT}s)"

takeover_ready=false
for i in $(seq 1 "$TAKEOVER_WAIT"); do
	status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	if echo "$status" | grep -qi "Takeover ready.*yes"; then
		takeover_ready=true
		info "Phase 2: fw0 takeover ready after ${i}s"
		break
	fi
	sleep 1
done

if $takeover_ready; then
	pass "phase2: fw0 is takeover-ready (sync hold released)"
else
	fail "phase2: fw0 did not reach 'Takeover ready: yes' within ${TAKEOVER_WAIT}s"
fi

# Verify session sync from fw1 → fw0
sleep "$SYNC_WAIT"

fw0_synced=$(incus exec "$FW0" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
if [[ "$fw0_synced" -ge "$MIN_SESSIONS" ]]; then
	pass "phase2: fw0 has $fw0_synced synced sessions from fw1"
else
	fail "phase2: fw0 has only $fw0_synced synced sessions (expected >= $MIN_SESSIONS)"
fi

# Verify iperf3 still running after fw0 rejoin
if main_iperf_running; then
	pass "phase2: tracked iperf3 client survived fw0 rejoin"
else
	fail "phase2: tracked iperf3 client died during fw0 rejoin"
fi
# ═══════════════════════════════════════════════════════════════════════
# Phase 3: Hard-reset fw1 → fw0 becomes primary
# ═══════════════════════════════════════════════════════════════════════

info "Phase 3: Hard-reset fw1 (incus stop --force) — fw0 must take over"

FAILOVER_EVENTS+=("$((SECONDS - IPERF_START_SECONDS))")
incus stop --force "$FW1" 2>/dev/null || true

# Wait for fw0 to take over
takeover_time=$(wait_for_node_primary fw0_is_primary "$TAKEOVER_TIMEOUT" || true)
if [[ -n "$takeover_time" ]]; then
	pass "phase3: fw0 became primary for all RGs (${takeover_time}s)"
else
	fail "phase3: fw0 did not become primary within ${TAKEOVER_TIMEOUT}s"
fi

# Verify iperf3 survived second failover
if main_iperf_running; then
	pass "phase3: tracked iperf3 client survived fw1 hard-reset (failover to fw0)"
else
	fail "phase3: tracked iperf3 client died during fw1 hard-reset — session sync round-trip FAILED"
fi
# Verify new TCP connections work through fw0
test_new_tcp "phase3" "$CONN_TIMEOUT"

# Verify connectivity via ping
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 3 "$IPERF_TARGET" &>/dev/null; then
	pass "phase3: ping through fw0 works"
else
	fail "phase3: ping through fw0 failed"
fi

# ═══════════════════════════════════════════════════════════════════════
# Phase 4: Restart fw1 → cluster stabilizes, both nodes healthy
# ═══════════════════════════════════════════════════════════════════════

info "Phase 4: Restarting fw1 — cluster must stabilize with both nodes healthy"

incus start "$FW1" 2>/dev/null || true

# Wait for cluster to stabilize
sleep 20

fw1_status=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
# Verify fw1 is secondary (no auto-preempt)
if printf '%s\n' "$fw1_status" | deploy_node_role_every_rg_ok node1 secondary; then
	pass "phase4: fw1 rejoined as secondary for every RG (no auto-preempt)"
elif printf '%s\n' "$fw1_status" | deploy_node_role_every_rg_ok node1 primary; then
	fail "phase4: fw1 auto-preempted to primary (should stay secondary)"
else
	fail "phase4: fw1 role is unclear for one or more RGs"
fi

# Verify fw0 is still primary
if fw0_is_primary; then
	pass "phase4: fw0 remains primary after fw1 rejoin"
else
	fail "phase4: fw0 is not primary after fw1 rejoin"
fi

# Check no dual-active
check_no_dual_active "phase4"

# Verify both nodes are healthy
for inst in "$FW0" "$FW1"; do
	if instance_running "$inst"; then
		pass "phase4: $inst running"
	else
		fail "phase4: $inst not running"
	fi
done

for inst in "$FW0" "$FW1"; do
	if incus exec "$inst" -- systemctl is-active --quiet xpfd 2>/dev/null; then
		pass "phase4: xpfd active on $inst"
	else
		fail "phase4: xpfd not active on $inst"
	fi
done

# Verify connectivity
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 3 "$IPERF_TARGET" &>/dev/null; then
	pass "phase4: connectivity OK"
else
	fail "phase4: connectivity lost"
fi

# ── Wait for iperf3 to complete and validate results ─────────────────

info "Waiting for iperf3 to complete"

for i in $(seq 1 "$IPERF_DURATION"); do
	if ! main_iperf_running; then
		break
	fi
	sleep 1
done

if [[ "${#FAILOVER_EVENTS[@]}" -ne 2 ]]; then
	fail "iperf3 failover oracle expected two transition events, observed ${#FAILOVER_EVENTS[@]}"
else
	oracle_output=$(ha_smoke_iperf_verdicts "$LOG" "$IPERF_DURATION" "$IPERF_STREAMS" \
		"$MIN_THROUGHPUT" "${FAILOVER_EVENTS[@]}")
	while IFS= read -r verdict; do
		case "$verdict" in
		PASS\ *) pass "${verdict#PASS }" ;;
		FAIL\ *) fail "${verdict#FAIL }" ;;
		*)       fail "iperf3 oracle: unexpected verdict '${verdict}'" ;;
		esac
	done <<<"$oracle_output"
fi

failover_stop_main_iperf "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true

# ── Results ──────────────────────────────────────────────────────────

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Chained crash test: $PASS passed, $FAIL failed"
echo "  (fw0 crash → fw1 takeover → fw0 rejoin → fw1 crash → fw0 takeover → fw1 rejoin)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
	echo
	echo "Failures:"
	for err in "${ERRORS[@]}"; do
		echo "  - $err"
	done
	exit 1
fi
