#!/usr/bin/env bash
# xpf hard-crash / hung-node HA failover test
#
# Validates that the cluster recovers from hard VM crashes and daemon
# failures — scenarios not covered by the clean-reboot failover test.
#
# Requires: cluster nodes from BPFRX_CLUSTER_ENV running (default: loss userspace cluster).
# Requires: iperf3 server reachable at IPERF_TARGET (default from IPERF_TARGET4).
#
# Tests:
#   Phase 1: Hard VM stop (incus stop --force) — simulates kernel panic / power loss
#     - Start iperf3 through fw0 (primary)
#     - Force-stop fw0
#     - Verify fw1 takes over (VRRP master) within 2s
#     - Verify new TCP connections work through fw1
#     - Restart fw0, verify it rejoins as secondary
#     - Manual failover back to fw0
#
#   Phase 2: Daemon stop — tests #68 fail-closed behavior
#     - Start iperf3 through fw0 (primary)
#     - Stop xpfd on fw0 (should clear rg_active + teardown BPF)
#     - Verify fw1 takes over within 2s
#     - Verify new TCP connections work through fw1
#     - Restart xpfd, verify recovery
#
#   Phase 3: Multi-cycle crash (3 cycles force-stop/restart)
#     - Verify cluster recovers each time
#     - Track takeover latency per cycle
#
# Usage:
#   ./test/incus/test-ha-crash.sh
#   IPERF_TARGET=10.1.2.3 CRASH_CYCLES=5 ./test/incus/test-ha-crash.sh

set -euo pipefail

# Re-exec under incus-admin group if needed
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		exec sg incus-admin -c "$(printf '%q ' "$0" "$@")"
	fi
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"

IPERF_TARGET="${IPERF_TARGET:-$IPERF_TARGET4}"
IPERF_STREAMS=4
CRASH_CYCLES="${CRASH_CYCLES:-3}"          # multi-cycle crash iterations
TAKEOVER_TIMEOUT=5                          # max seconds for fw1 to take over
CONN_TIMEOUT=10                             # max seconds for new TCP to succeed
VM_RESTART_WAIT=90                          # max seconds for fw0 VM to come back
DAEMON_RESTART_WAIT=30                      # max seconds for xpfd to restart

PASS=0
FAIL=0
ERRORS=()
LOG="/tmp/iperf3-ha-crash.log"

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

# Check that fw1 is primary for all RGs (takeover detection)
fw1_is_primary() {
	local status
	status=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	for rg in 0 1 2; do
		if ! echo "$status" | grep -A2 "Redundancy group: $rg" | grep -q "node1.*primary"; then
			return 1
		fi
	done
	return 0
}

# Check that fw0 is primary for all RGs
fw0_is_primary() {
	local status
	status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	for rg in 0 1 2; do
		if ! echo "$status" | grep -A2 "Redundancy group: $rg" | grep -q "node0.*primary"; then
			return 1
		fi
	done
	return 0
}

# Wait for fw1 to become primary, return elapsed seconds
wait_for_takeover() {
	local max="$1"
	for i in $(seq 1 "$max"); do
		if fw1_is_primary; then
			echo "$i"
			return 0
		fi
		sleep 1
	done
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

# Restore fw0 as primary for all RGs
restore_fw0_primary() {
	local label="$1"
	# If fw0 is already primary, nothing to do
	if fw0_is_primary; then
		pass "$label: fw0 already primary"
		return 0
	fi
	# Reset manual failover flags
	for rg in 0 1 2; do
		incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
		incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	done
	sleep 1
	# Manual failover all RGs to fw0 (from fw1 which is current primary)
	for rg in 0 1 2; do
		incus exec "$FW1" -- cli -c "request chassis cluster failover redundancy-group $rg" 2>/dev/null || true
	done
	sleep 5
	if fw0_is_primary; then
		pass "$label: fw0 restored as primary"
		return 0
	else
		fail "$label: could not restore fw0 as primary"
		return 1
	fi
}

cleanup() {
	info "Cleanup: killing iperf3, resetting cluster state"
	incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
	# Ensure fw0 is running
	if ! instance_running "$FW0"; then
		incus start "$FW0" 2>/dev/null || true
		wait_for_xpfd "$FW0" "$VM_RESTART_WAIT" >/dev/null 2>&1 || true
	fi
	# Ensure xpfd is running on fw0
	incus exec "$FW0" -- systemctl start xpfd 2>/dev/null || true
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

# Ensure fw0 is primary for all RGs (restore if needed from previous test state)
if fw0_is_primary; then
	pass "fw0 is primary for all RGs"
else
	info "fw0 is not primary — attempting to restore"
	restore_fw0_primary "preflight" || true
	sleep 5
	if fw0_is_primary; then
		pass "fw0 restored as primary for all RGs"
	else
		die "fw0 is not primary for all RGs and could not restore"
	fi
fi

# Kill any stale iperf3 and clear stale sessions from previous test runs
incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
incus exec "$FW0" -- cli -c "clear security flow session all" 2>/dev/null || true
incus exec "$FW1" -- cli -c "clear security flow session all" 2>/dev/null || true
sleep 3

# Pre-warm ARP on the primary firewall — bpf_fib_lookup returns NO_NEIGH
# if no ARP entry exists, causing the first through-traffic packet to be slow
incus exec "$FW0" -- ping -c 1 -W 3 "$IPERF_TARGET" &>/dev/null || true
incus exec "$FW1" -- ping -c 1 -W 3 "$IPERF_TARGET" &>/dev/null || true
sleep 1

# Verify iperf target reachable (retry — ARP/NDP may need a few seconds after session clear)
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
	die "Cannot reach iperf3 target $IPERF_TARGET from cluster-lan-host"
fi

# ═══════════════════════════════════════════════════════════════════════
# Phase 1: Hard VM stop (kernel panic / power loss simulation)
# ═══════════════════════════════════════════════════════════════════════

info "Phase 1: Hard VM stop — simulating kernel panic / power loss"

# Start iperf3
info "Phase 1: Starting iperf3 -P${IPERF_STREAMS} → ${IPERF_TARGET}"
incus exec "$CLUSTER_LAN_HOST" -- bash -c \
	"iperf3 --forceflush --connect-timeout 5000 -t 120 -c ${IPERF_TARGET} -P ${IPERF_STREAMS} > ${LOG} 2>&1 &"
sleep 8

if incus exec "$CLUSTER_LAN_HOST" -- pgrep -x iperf3 &>/dev/null; then
	pass "phase1: iperf3 running"
else
	die "phase1: iperf3 failed to start"
fi

# Verify sessions on fw0
fw0_sessions=$(incus exec "$FW0" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
if [[ "$fw0_sessions" -ge "$IPERF_STREAMS" ]]; then
	pass "phase1: fw0 has $fw0_sessions established sessions"
else
	fail "phase1: fw0 has only $fw0_sessions sessions (expected >= $IPERF_STREAMS)"
fi

# Wait for session sync
sleep 5

# Force-stop fw0 — this is a hard kill, no graceful shutdown
info "Phase 1: Force-stopping fw0 (incus stop --force)"
incus stop --force "$FW0" 2>/dev/null || true

# Wait for fw1 to take over
takeover_time=$(wait_for_takeover "$TAKEOVER_TIMEOUT" || true)
if [[ -n "$takeover_time" ]]; then
	pass "phase1: fw1 took over as primary (${takeover_time}s)"
else
	fail "phase1: fw1 did not take over within ${TAKEOVER_TIMEOUT}s"
fi

# Verify new TCP connections work through fw1
test_new_tcp "phase1" "$CONN_TIMEOUT"

# Verify connectivity via ping
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 3 "$IPERF_TARGET" &>/dev/null; then
	pass "phase1: ping through fw1 works"
else
	fail "phase1: ping through fw1 failed"
fi

# Kill iperf3 from phase 1 (sessions are dead — fw0 hard-crashed)
incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
sleep 1

# Restart fw0
info "Phase 1: Restarting fw0"
incus start "$FW0" 2>/dev/null || true

restart_time=$(wait_for_xpfd "$FW0" "$VM_RESTART_WAIT" || true)
if [[ -n "$restart_time" ]]; then
	pass "phase1: fw0 xpfd restarted (${restart_time}s)"
else
	fail "phase1: fw0 xpfd did not restart within ${VM_RESTART_WAIT}s"
fi

# Wait for cluster to stabilize
sleep 10

# Verify fw0 is secondary (no auto-preempt)
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
if echo "$fw0_status" | grep -q "node0.*secondary"; then
	pass "phase1: fw0 rejoined as secondary"
else
	fail "phase1: fw0 did not rejoin as secondary"
fi

# Check no dual-active
check_no_dual_active "phase1-rejoin"

# Restore fw0 as primary for next phase
restore_fw0_primary "phase1" || true
sleep 5

# Wait for connectivity to stabilize after phase 1
# iperf3 server is single-client: after abrupt client death (force-stop),
# server may hold the stale connection for up to 120s (TCP keepalive).
# We must wait for it to become available.
info "Phase 1→2 transition: clearing sessions, waiting for iperf3 server to be ready"
incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
incus exec "$FW0" -- cli -c "clear security flow session all" 2>/dev/null || true
incus exec "$FW1" -- cli -c "clear security flow session all" 2>/dev/null || true
sleep 3
# Wait for ping connectivity first
for i in $(seq 1 30); do
	if incus exec "$CLUSTER_LAN_HOST" -- ping -c 1 -W 2 "$IPERF_TARGET" &>/dev/null; then
		break
	fi
	sleep 1
done
# Then wait for iperf3 server to accept connections (TCP 5201)
info "Phase 1→2: waiting for iperf3 server at ${IPERF_TARGET}:5201"
for i in $(seq 1 120); do
	if incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"timeout 3 bash -c 'echo > /dev/tcp/${IPERF_TARGET}/5201'" 2>/dev/null; then
		info "Phase 1→2: iperf3 server ready (${i}s)"
		break
	fi
	sleep 1
done
sleep 2

# ═══════════════════════════════════════════════════════════════════════
# Phase 2: Daemon stop — tests fail-closed behavior (#68)
# ═══════════════════════════════════════════════════════════════════════

info "Phase 2: Daemon stop — testing fail-closed shutdown behavior"

# Ensure fw0 is primary
if ! fw0_is_primary; then
	die "phase2: fw0 is not primary — cannot proceed"
fi

# Start iperf3
info "Phase 2: Starting iperf3 -P${IPERF_STREAMS} → ${IPERF_TARGET}"
incus exec "$CLUSTER_LAN_HOST" -- bash -c \
	"iperf3 --forceflush --connect-timeout 5000 -t 120 -c ${IPERF_TARGET} -P ${IPERF_STREAMS} > ${LOG} 2>&1 &"
sleep 8

if incus exec "$CLUSTER_LAN_HOST" -- pgrep -x iperf3 &>/dev/null; then
	pass "phase2: iperf3 running"
else
	# Show the log to diagnose
	incus exec "$CLUSTER_LAN_HOST" -- cat ${LOG} 2>/dev/null || true
	die "phase2: iperf3 failed to start"
fi

# Stop xpfd on fw0 (fail-closed: clears rg_active, tears down BPF)
info "Phase 2: Stopping xpfd on fw0 (systemctl stop)"
incus exec "$FW0" -- systemctl stop xpfd 2>/dev/null || true

# Wait for fw1 to take over
takeover_time=$(wait_for_takeover "$TAKEOVER_TIMEOUT" || true)
if [[ -n "$takeover_time" ]]; then
	pass "phase2: fw1 took over after daemon stop (${takeover_time}s)"
else
	fail "phase2: fw1 did not take over within ${TAKEOVER_TIMEOUT}s"
fi

# Verify new TCP connections work through fw1
test_new_tcp "phase2" "$CONN_TIMEOUT"

# Verify connectivity via ping
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 3 "$IPERF_TARGET" &>/dev/null; then
	pass "phase2: ping through fw1 works"
else
	fail "phase2: ping through fw1 failed"
fi

# Kill iperf3 from phase 2
incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
sleep 1

# Restart xpfd on fw0
info "Phase 2: Restarting xpfd on fw0"
incus exec "$FW0" -- systemctl start xpfd 2>/dev/null || true

restart_time=$(wait_for_xpfd "$FW0" "$DAEMON_RESTART_WAIT" || true)
if [[ -n "$restart_time" ]]; then
	pass "phase2: xpfd restarted (${restart_time}s)"
else
	fail "phase2: xpfd did not restart within ${DAEMON_RESTART_WAIT}s"
fi

# Wait for cluster to stabilize
sleep 10

# Verify fw0 is secondary
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
if echo "$fw0_status" | grep -q "node0.*secondary"; then
	pass "phase2: fw0 rejoined as secondary after daemon restart"
else
	fail "phase2: fw0 did not rejoin as secondary"
fi

# Check no dual-active
check_no_dual_active "phase2-rejoin"

# Restore fw0 as primary for next phase
restore_fw0_primary "phase2" || true
sleep 5

# Wait for connectivity to stabilize after phase 2
info "Phase 2→3 transition: clearing sessions and waiting for connectivity"
incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
incus exec "$FW0" -- cli -c "clear security flow session all" 2>/dev/null || true
incus exec "$FW1" -- cli -c "clear security flow session all" 2>/dev/null || true
sleep 3
for i in $(seq 1 30); do
	if incus exec "$CLUSTER_LAN_HOST" -- ping -c 1 -W 2 "$IPERF_TARGET" &>/dev/null; then
		break
	fi
	sleep 1
done
# Wait for iperf3 server to release stale client
info "Phase 2→3: waiting for iperf3 server at ${IPERF_TARGET}:5201"
for i in $(seq 1 120); do
	if incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"timeout 3 bash -c 'echo > /dev/tcp/${IPERF_TARGET}/5201'" 2>/dev/null; then
		info "Phase 2→3: iperf3 server ready (${i}s)"
		break
	fi
	sleep 1
done
sleep 2

# ═══════════════════════════════════════════════════════════════════════
# Phase 3: Multi-cycle crash (repeated force-stop/restart)
# ═══════════════════════════════════════════════════════════════════════

info "Phase 3: Multi-cycle crash test (${CRASH_CYCLES} cycles)"

# Ensure fw0 is primary
if ! fw0_is_primary; then
	die "phase3: fw0 is not primary — cannot proceed"
fi

cycle_failures=0

for cycle in $(seq 1 "$CRASH_CYCLES"); do
	info "Phase 3: Cycle ${cycle}/${CRASH_CYCLES} — force-stop fw0"

	# Verify connectivity before crash (retry a few times)
	pre_crash_ok=false
	for i in $(seq 1 10); do
		if incus exec "$CLUSTER_LAN_HOST" -- ping -c 1 -W 2 "$IPERF_TARGET" &>/dev/null; then
			pre_crash_ok=true
			break
		fi
		sleep 1
	done
	if ! $pre_crash_ok; then
		fail "phase3-cycle${cycle}: no connectivity before crash"
		cycle_failures=$((cycle_failures + 1))
		continue
	fi

	# Force-stop fw0
	incus stop --force "$FW0" 2>/dev/null || true

	# Measure takeover time
	takeover_time=$(wait_for_takeover "$TAKEOVER_TIMEOUT" || true)
	if [[ -n "$takeover_time" ]]; then
		pass "phase3-cycle${cycle}: fw1 took over (${takeover_time}s)"
	else
		fail "phase3-cycle${cycle}: fw1 did not take over within ${TAKEOVER_TIMEOUT}s"
		cycle_failures=$((cycle_failures + 1))
	fi

	# Verify new connections work
	test_new_tcp "phase3-cycle${cycle}" "$CONN_TIMEOUT" || cycle_failures=$((cycle_failures + 1))

	# Restart fw0
	incus start "$FW0" 2>/dev/null || true
	restart_time=$(wait_for_xpfd "$FW0" "$VM_RESTART_WAIT" || true)
	if [[ -n "$restart_time" ]]; then
		pass "phase3-cycle${cycle}: fw0 restarted (${restart_time}s)"
	else
		fail "phase3-cycle${cycle}: fw0 did not restart within ${VM_RESTART_WAIT}s"
		cycle_failures=$((cycle_failures + 1))
		continue
	fi

	# Wait for cluster stabilization
	sleep 10

	# Check no dual-active
	check_no_dual_active "phase3-cycle${cycle}"

	# Verify fw0 is in cluster (primary or secondary — after rapid
	# force-stop cycles, election may resolve either way)
	fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	if echo "$fw0_status" | grep -q "node0.*secondary"; then
		pass "phase3-cycle${cycle}: fw0 rejoined as secondary"
	elif echo "$fw0_status" | grep -q "node0.*primary"; then
		pass "phase3-cycle${cycle}: fw0 rejoined as primary (preempted)"
	else
		fail "phase3-cycle${cycle}: fw0 cluster status unclear"
		cycle_failures=$((cycle_failures + 1))
	fi

	# Restore fw0 as primary for next cycle (except last)
	if [[ "$cycle" -lt "$CRASH_CYCLES" ]]; then
		restore_fw0_primary "phase3-cycle${cycle}" || true
		# Clear stale sessions and wait for connectivity
		incus exec "$FW0" -- cli -c "clear security flow session all" 2>/dev/null || true
		incus exec "$FW1" -- cli -c "clear security flow session all" 2>/dev/null || true
		sleep 3
		for i in $(seq 1 15); do
			if incus exec "$CLUSTER_LAN_HOST" -- ping -c 1 -W 2 "$IPERF_TARGET" &>/dev/null; then
				break
			fi
			sleep 1
		done
	fi
done

if [[ "$cycle_failures" -eq 0 ]]; then
	pass "phase3: all ${CRASH_CYCLES} crash cycles completed successfully"
else
	fail "phase3: ${cycle_failures} failures across ${CRASH_CYCLES} crash cycles"
fi

# ── Final health check ────────────────────────────────────────────────

info "Final health checks"

# Clear stale sessions before final connectivity check
incus exec "$FW0" -- cli -c "clear security flow session all" 2>/dev/null || true
incus exec "$FW1" -- cli -c "clear security flow session all" 2>/dev/null || true
sleep 3

# Ensure both nodes are running
for inst in "$FW0" "$FW1"; do
	if ! instance_running "$inst"; then
		# Try to start it
		incus start "$inst" 2>/dev/null || true
		wait_for_xpfd "$inst" "$VM_RESTART_WAIT" >/dev/null 2>&1 || true
	fi
	if instance_running "$inst"; then
		pass "final: $inst running"
	else
		fail "final: $inst not running"
	fi
done

# Ensure xpfd active on both (wait briefly for late starters)
for inst in "$FW0" "$FW1"; do
	xpfd_ok=false
	for i in $(seq 1 15); do
		if incus exec "$inst" -- systemctl is-active --quiet xpfd 2>/dev/null; then
			xpfd_ok=true
			break
		fi
		sleep 1
	done
	if $xpfd_ok; then
		pass "final: xpfd active on $inst"
	else
		fail "final: xpfd not active on $inst"
	fi
done

# Verify connectivity
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 3 "$IPERF_TARGET" &>/dev/null; then
	pass "final: connectivity OK"
else
	fail "final: connectivity lost"
fi

# ── Results ──────────────────────────────────────────────────────────

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  HA crash test: $PASS passed, $FAIL failed"
echo "  (hard-stop + daemon-stop + ${CRASH_CYCLES} crash cycles)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
	echo
	echo "Failures:"
	for err in "${ERRORS[@]}"; do
		echo "  - $err"
	done
	exit 1
fi
