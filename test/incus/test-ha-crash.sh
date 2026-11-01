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
#     - Verify the ESTABLISHED iperf3 streams survive the takeover and keep
#       forwarding (#9692)
#     - Restart fw0, verify it rejoins as secondary
#     - Manual failover back to fw0
#
#   Phase 2: Daemon stop — tests #68 fail-closed behavior
#     - Start iperf3 through fw0 (primary)
#     - Stop xpfd on fw0 (should clear rg_active + teardown BPF)
#     - Verify fw1 takes over within 2s
#     - Verify new TCP connections work through fw1
#     - Verify the ESTABLISHED iperf3 streams survive the takeover and keep
#       forwarding (#9692)
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

# #1875/#4020: this DESTRUCTIVE smoke reboots / force-stops / fails
# over a node on the SHARED loss cluster. Re-exec under the
# incus-admin group if needed, then serialize as a #1875 lock cell
# so a concurrent deploy/smoke can't collide with our reboot (it
# queues behind the canonical cluster lock instead of colliding).
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "test-ha-crash $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/failover-clock-lib.sh
source "${SCRIPT_DIR}/failover-clock-lib.sh"
# #12203: shared scoped per-(node, RG) role reader for dual-active checks.
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/iperf-throughput-lib.sh
source "${SCRIPT_DIR}/iperf-throughput-lib.sh"

IPERF_TARGET="${IPERF_TARGET:-$IPERF_TARGET4}"
# #9692: the recovery cell below measures throughput, so measure the UNSHAPED
# class. Port 5201 is iperf-100m in cos-iperf-config.set (#7673/#9691).
IPERF_PORT="${IPERF_PORT:-5211}"
IPERF_STREAMS=4
CRASH_CYCLES="${CRASH_CYCLES:-3}"          # multi-cycle crash iterations
TAKEOVER_TIMEOUT=5                          # max seconds for fw1 to take over
CONN_TIMEOUT=10                             # max seconds for new TCP to succeed
VM_RESTART_WAIT=90                          # max seconds for fw0 VM to come back
DAEMON_RESTART_WAIT=30                      # max seconds for xpfd to restart

PASS=0
FAIL=0
# #18614: a cell that could not be judged (the clock precondition's VOID). It
# is neither a pass nor a fail, and a run with one exits 2, so a direct run is
# as honest as the harness-result.sh row.
VOID=0
ERRORS=()
LOG="/tmp/iperf3-ha-crash.log"
# #9692: how long to let the established streams settle after a takeover, and
# the rate their most recent [SUM] interval must reach to count as recovered.
RECOVERY_WAIT="${RECOVERY_WAIT:-10}"
RECOVERY_MIN_GBPS="${RECOVERY_MIN_GBPS:-0.5}"

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
void()  { echo "  VOID  $*"; VOID=$((VOID + 1)); }
die()   { echo "FATAL: $*" >&2; exit 2; }

# established_streams_recovered <phase> — #9692. The iperf3 client started
# before the failure must still be running and forwarding after the takeover.
# Without this the phase asserted only the takeover, a NEW connection and a ping,
# then killed the client, so a survivor that lost or refused the synced sessions,
# or a stopping node whose teardown broke established flows, still passed the
# mandated HA crash gate.
established_streams_recovered() {
	local phase="$1" last gbps
	sleep "$RECOVERY_WAIT"
	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep -x iperf3 &>/dev/null; then
		fail "${phase}: the established iperf3 streams DIED across the takeover"
		return
	fi
	last=$(incus exec "$CLUSTER_LAN_HOST" -- grep '\[SUM\]' "$LOG" 2>/dev/null | grep -v 'sender\|receiver' | tail -1 || true)
	gbps=$(iperf_sum_rate_gbps "$last")
	if [[ -n "$gbps" ]] && awk "BEGIN{exit !($gbps >= $RECOVERY_MIN_GBPS)}"; then
		pass "${phase}: established streams kept forwarding after the takeover (last interval ${gbps} Gbps)"
	else
		fail "${phase}: established streams did not recover after the takeover (last interval '${gbps:-unparseable}' Gbps, want >= ${RECOVERY_MIN_GBPS}) -- [SUM] line: ${last:-none}"
	fi
}

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

# start_instance <inst> <label> — #18523. `incus start` used to run with its
# error discarded, so a VM that could not start at all (on tcp: "All virtual
# functions on parent device mlx1 are already in use") surfaced only as
# "xpfd did not restart within 90s". Name the start failure itself. A caller
# skips the xpfd wait when this fails: a VM that did not start cannot run
# xpfd, so the 90s wait would only add a second FAIL for the same cause.
start_instance() {
	local inst="$1" label="$2" err
	if err=$(incus start "$inst" 2>&1); then
		return 0
	fi
	instance_running "$inst" && return 0
	fail "${label}: incus start ${inst} failed: $(printf '%s' "$err" | head -1)"
	return 1
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
		if [[ "$(deploy_node_rg_role node1 "$rg" <<<"$status" || true)" != primary ]]; then
			return 1
		fi
	done
	return 0
}

# Check that fw0 is primary for all RGs
# #18523: fw0 owns every RG only when both nodes' own views agree. The
# shared deploy-lib.sh helper is the one deploy-lib-selftest.sh drives.
fw0_is_primary() {
	deploy_restore_fw0_owns_all
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
	local label="$1" fw0_status="" fw1_status=""
	local fw0_bad=false fw1_bad=false fw0_problem fw1_problem
	if ! fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null); then
		fw0_bad=true
		fw0_problem=unreadable
	elif [[ -z "$fw0_status" ]]; then
		fw0_bad=true
		fw0_problem=empty
	fi
	if ! fw1_status=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null); then
		fw1_bad=true
		fw1_problem=unreadable
	elif [[ -z "$fw1_status" ]]; then
		fw1_bad=true
		fw1_problem=empty
	fi
	if [[ "$fw0_bad" == true ]]; then
		fail "$label: fw0 cluster status $fw0_problem"
	fi
	if [[ "$fw1_bad" == true ]]; then
		fail "$label: fw1 cluster status $fw1_problem"
	fi
	if [[ "$fw0_bad" == true || "$fw1_bad" == true ]]; then
		return 0
	fi
	local invalid_state=false rg
	for rg in 0 1 2; do
		local r0="" r1="" r0_bad=false r1_bad=false
		if ! r0=$(printf '%s\n' "$fw0_status" | deploy_node_rg_role node0 "$rg"); then
			r0_bad=true
		fi
		if ! r1=$(printf '%s\n' "$fw1_status" | deploy_node_rg_role node1 "$rg"); then
			r1_bad=true
		fi
		if [[ "$r0_bad" == true || "$r1_bad" == true ]]; then
			fail "$label: RG$rg role unreadable (fw0='${r0:-unreadable}' fw1='${r1:-unreadable}')"
			invalid_state=true
			continue
		fi
		case "$r0/$r1" in
		primary/primary)
			fail "$label: dual-active detected on RG$rg"
			invalid_state=true
			;;
		primary/* | */primary) ;;
		*)
			fail "$label: no primary detected on RG$rg (fw0=$r0 fw1=$r1)"
			invalid_state=true
			;;
		esac
	done
	if ! $invalid_state; then
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

# Restore fw0 as primary for all RGs.
# #18523: the polled restore and its verdict (a refused or over-budget
# restore FAILs; see deploy_restore_fw0_primary and RESTORE_FW0_WAIT /
# RESTORE_FW0_BUDGET in docs/testing-procedures.md) live in deploy-lib.sh,
# shared with the other HA smoke so the selftest drives the code run here.
restore_fw0_primary() {
	deploy_restore_fw0_primary "$1"
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
	die "Cannot reach iperf3 target $IPERF_TARGET from ${CLUSTER_LAN_HOST}"
fi

# #18614: one clock reading BEFORE the first crash. If chrony is not
# synchronised here, there is no time source for a crash-rebooted node to
# converge to, and the clock cell after the crash is VOID (lab/NTP), not FAIL.
failover_clock_baseline "$FW0" "$FW1"

# ═══════════════════════════════════════════════════════════════════════
# Phase 1: Hard VM stop (kernel panic / power loss simulation)
# ═══════════════════════════════════════════════════════════════════════

info "Phase 1: Hard VM stop — simulating kernel panic / power loss"

# Start iperf3
info "Phase 1: Starting iperf3 -P${IPERF_STREAMS} → ${IPERF_TARGET}"
incus exec "$CLUSTER_LAN_HOST" -- bash -c \
	"iperf3 --forceflush --connect-timeout 5000 -t 120 -c ${IPERF_TARGET} -p ${IPERF_PORT} -P ${IPERF_STREAMS} > ${LOG} 2>&1 &"
sleep 8

if incus exec "$CLUSTER_LAN_HOST" -- pgrep -x iperf3 &>/dev/null; then
	pass "phase1: iperf3 running"
else
	die "phase1: iperf3 failed to start"
fi

# Verify sessions on fw0
fw0_sessions=$(incus exec "$FW0" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
if [[ "$fw0_sessions" -ge "$IPERF_STREAMS" ]]; then
	pass "phase1: fw0 has $fw0_sessions session entries"
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

established_streams_recovered "phase1"

# Stop phase 1's client now that its survival across the takeover was measured
# (#9692; the synced sessions are expected to survive a hard stop of fw0).
incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
sleep 1

# Restart fw0
info "Phase 1: Restarting fw0"
if start_instance "$FW0" "phase1"; then
	restart_time=$(wait_for_xpfd "$FW0" "$VM_RESTART_WAIT" || true)
	if [[ -n "$restart_time" ]]; then
		pass "phase1: fw0 xpfd restarted (${restart_time}s)"
		# #18614: the post-crash clock state, logged before the settle, so a
		# rejoin FAIL below carries it even if chrony converges first.
		failover_clock_reading "phase1 post-restart" "$FW0" "$FW1"
	else
		fail "phase1: fw0 xpfd did not restart within ${VM_RESTART_WAIT}s"
	fi
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

# #18614 (was the #18523/#11872 resync, which ran right after the restart):
# the force-stopped VM comes back on its RTC, and a skew past the fabric-auth
# window breaks the failback below. Before it, wait for NTP to converge on both
# nodes and log the skew and the time it took; never set a clock. It runs HERE,
# after the rejoin checks, so those keep their 10 s settle and see the cluster
# in its real post-crash clock state; only the failback waits. fail-only:
# a converged run's cell count is unchanged (a resync still gets a PASS line
# naming it, and a VOID gets a VOID line that harness-result.sh scores).
if [[ -n "${restart_time:-}" ]]; then
	failover_clock_cell fail-only "phase1" "$FW0" "$FW1" "$FW0" || true
fi

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
	"iperf3 --forceflush --connect-timeout 5000 -t 120 -c ${IPERF_TARGET} -p ${IPERF_PORT} -P ${IPERF_STREAMS} > ${LOG} 2>&1 &"
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

established_streams_recovered "phase2"

# Stop phase 2's client now that its survival across the takeover was measured (#9692).
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
	if ! start_instance "$FW0" "phase3-cycle${cycle}"; then
		cycle_failures=$((cycle_failures + 1))
		continue
	fi
	restart_time=$(wait_for_xpfd "$FW0" "$VM_RESTART_WAIT" || true)
	if [[ -n "$restart_time" ]]; then
		pass "phase3-cycle${cycle}: fw0 restarted (${restart_time}s)"
		failover_clock_reading "phase3-cycle${cycle} post-restart" "$FW0" "$FW1"
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

	# #18614: as in phase 1, after the rejoin checks and before the restore.
	# Every cycle, the last included, so no unmeasured skew is left behind.
	failover_clock_cell fail-only "phase3-cycle${cycle}" "$FW0" "$FW1" "$FW0" || true

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
		# Try to start it.
		# #18614: a node started here also comes back on its RTC; check that
		# NTP converges rather than leaving an unmeasured skew for the next
		# harness (and never set the clock).
		if start_instance "$inst" "final" &&
			wait_for_xpfd "$inst" "$VM_RESTART_WAIT" >/dev/null 2>&1; then
			failover_clock_cell fail-only "final" "$FW0" "$FW1" "$inst" || true
		fi
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
if [[ $VOID -gt 0 ]]; then
	echo
	echo "  ${VOID} cell(s) VOID: the run is not a pass (see the VOID lines above)"
	exit 2
fi
