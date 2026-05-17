#!/usr/bin/env bash
# xpf restart connectivity regression test
#
# Validates that daemon restart in HA mode does not cause transient
# connectivity loss. This tests the fix for #75 — neighbor prewarm
# must run after VRRP MASTER (not before VIPs are installed).
#
# Requires: cluster nodes from BPFRX_CLUSTER_ENV running (default: loss userspace cluster).
# Requires: iperf3 server reachable at IPERF_TARGET (default from IPERF_TARGET4).
#
# Tests:
#   1. Verify baseline connectivity from cluster-lan-host → IPERF_TARGET
#   2. Restart xpfd on fw0 while continuously pinging
#   3. Assert ≤ MAX_LOST_PINGS lost during restart (default: 2)
#   4. Repeat RESTART_CYCLES times (default: 3) to catch intermittent issues
#
# Usage:
#   ./test/incus/test-restart-connectivity.sh
#   RESTART_CYCLES=5 MAX_LOST_PINGS=1 ./test/incus/test-restart-connectivity.sh

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
RESTART_CYCLES="${RESTART_CYCLES:-3}"
MAX_LOST_PINGS="${MAX_LOST_PINGS:-2}"       # allow 1-2 for VRRP transition
PING_COUNT=40                                # pings per cycle (0.5s interval = 20s)
PING_INTERVAL="0.5"
PRE_RESTART_PINGS=6                          # pings before restart (3s)
SETTLE_TIME="${SETTLE_TIME:-20}"             # seconds between cycles for cluster stabilization

PASS=0
FAIL=0
ERRORS=()
PING_LOG="/tmp/xpf-restart-ping.log"

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
die()   { echo "FATAL: $*" >&2; exit 2; }

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

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

restore_fw0_primary() {
	local label="$1"
	if fw0_is_primary; then
		return 0
	fi
	for rg in 0 1 2; do
		incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
		incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	done
	sleep 1
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
	incus exec "$CLUSTER_LAN_HOST" -- pkill -9 ping 2>/dev/null || true
	# Ensure fw0 xpfd is running
	incus exec "$FW0" -- systemctl start xpfd 2>/dev/null || true
	sleep 5
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

for inst in "$FW0" "$FW1"; do
	if ! incus exec "$inst" -- systemctl is-active --quiet xpfd 2>/dev/null; then
		die "xpfd not active on $inst"
	fi
done

# Ensure fw0 is primary
if fw0_is_primary; then
	pass "fw0 is primary for all RGs"
else
	info "fw0 is not primary — restoring"
	restore_fw0_primary "preflight" || die "cannot restore fw0 as primary"
fi

# Pre-warm ARP
incus exec "$FW0" -- ping -c 1 -W 3 "$IPERF_TARGET" &>/dev/null || true
sleep 1

# Verify baseline connectivity
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 2 "$IPERF_TARGET" &>/dev/null; then
	pass "baseline connectivity OK ($IPERF_TARGET)"
else
	die "no baseline connectivity to $IPERF_TARGET from cluster-lan-host"
fi

# ── Restart cycles ───────────────────────────────────────────────────

total_lost=0

for cycle in $(seq 1 "$RESTART_CYCLES"); do
	info "Cycle ${cycle}/${RESTART_CYCLES}: restart xpfd on fw0 while pinging"

	# Clear stale sessions
	incus exec "$FW0" -- cli -c "clear security flow session all" 2>/dev/null || true
	sleep 1

	# Start continuous ping in background on lan-host
	incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"ping -c ${PING_COUNT} -i ${PING_INTERVAL} ${IPERF_TARGET} > ${PING_LOG} 2>&1 &"

	# Wait for a few pings to succeed before restart (3s)
	sleep 3

	# Restart xpfd on fw0
	incus exec "$FW0" -- systemctl restart xpfd 2>/dev/null || true

	# Wait for ping to finish (~22s total ping time minus 3s pre-restart + 5s buffer)
	sleep 22

	# Parse ping results
	ping_output=$(incus exec "$CLUSTER_LAN_HOST" -- cat "$PING_LOG" 2>/dev/null || true)
	transmitted=$(echo "$ping_output" | grep -oP '\d+ packets transmitted' | grep -oP '^\d+' || echo "0")
	received=$(echo "$ping_output" | grep -oP '\d+ received' | grep -oP '^\d+' || echo "0")
	lost=$((transmitted - received))
	loss_pct=$(echo "$ping_output" | grep -oP '\d+(\.\d+)?% packet loss' | grep -oP '^[0-9.]+' || echo "100")

	if [[ "$lost" -le "$MAX_LOST_PINGS" ]]; then
		pass "cycle${cycle}: ${received}/${transmitted} received, ${lost} lost (${loss_pct}% loss, max allowed: ${MAX_LOST_PINGS})"
	else
		fail "cycle${cycle}: ${received}/${transmitted} received, ${lost} lost (${loss_pct}% loss, max allowed: ${MAX_LOST_PINGS})"
	fi
	total_lost=$((total_lost + lost))

	# Wait for cluster to stabilize before next cycle
	sleep "$SETTLE_TIME"

	# Ensure fw0 is primary for next cycle
	if ! fw0_is_primary; then
		restore_fw0_primary "cycle${cycle}" || true
		sleep 5
	fi

	# Pre-warm ARP for next cycle
	incus exec "$FW0" -- ping -c 1 -W 3 "$IPERF_TARGET" &>/dev/null || true
	sleep 1
done

# ── Final health check ───────────────────────────────────────────────

info "Final health checks"

for inst in "$FW0" "$FW1"; do
	if incus exec "$inst" -- systemctl is-active --quiet xpfd 2>/dev/null; then
		pass "final: xpfd active on $inst"
	else
		fail "final: xpfd not active on $inst"
	fi
done

if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 2 "$IPERF_TARGET" &>/dev/null; then
	pass "final: connectivity OK"
else
	fail "final: connectivity lost"
fi

# ── Results ──────────────────────────────────────────────────────────

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Restart connectivity: $PASS passed, $FAIL failed"
echo "  (${RESTART_CYCLES} cycles, ${total_lost} total pings lost)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
	echo
	echo "Failures:"
	for err in "${ERRORS[@]}"; do
		echo "  - $err"
	done
	exit 1
fi
