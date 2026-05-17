#!/usr/bin/env bash
# xpf cluster rapid failover stress test
#
# Validates that active TCP connections survive repeated rapid failover
# cycles (fw0→fw1→fw0→fw1...) without any stream death.
#
# Historically, rapid active/active failover cycles have killed TCP streams
# through dual-inactive windows, RST→CLOSED bugs, and txqueuelen drops.
# This test codifies the stress scenario as a permanent regression gate.
#
# Requires: cluster nodes from BPFRX_CLUSTER_ENV running (default: loss userspace cluster).
# Requires: iperf3 server reachable at IPERF_TARGET (default from IPERF_TARGET4).
#
# Tests:
#   1. Start iperf3 through the firewall (LAN host → WAN target)
#   2. Verify sessions sync from primary (fw0) to secondary (fw1)
#   3. Run TOTAL_CYCLES failover/failback cycles on RG1
#   4. At each half-cycle, verify 0 dead streams and iperf3 alive
#   5. Final validation: iperf3 alive, throughput above threshold
#
# Usage:
#   ./test/incus/test-stress-failover.sh
#   TOTAL_CYCLES=2 FAILOVER_INTERVAL=30 ./test/incus/test-stress-failover.sh  # quick smoke
#   TOTAL_CYCLES=60 FAILOVER_INTERVAL=180 ./test/incus/test-stress-failover.sh  # 3hr soak

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
IPERF_STREAMS="${IPERF_STREAMS:-8}"
FAILOVER_INTERVAL="${FAILOVER_INTERVAL:-60}"   # seconds between failovers
TOTAL_CYCLES="${TOTAL_CYCLES:-10}"
MIN_THROUGHPUT="${MIN_THROUGHPUT:-1.0}"         # Gbps

# iperf3 duration: enough time for all cycles + buffer
IPERF_DURATION="${IPERF_DURATION:-$(( TOTAL_CYCLES * FAILOVER_INTERVAL + 60 ))}"
SYNC_WAIT=5
LOG="/tmp/iperf3-stress-failover.log"

PASS=0
FAIL=0
ERRORS=()

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }

die() { echo "FATAL: $*" >&2; exit 2; }

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

check_streams() {
	local label="$1"
	local tail_lines=$(( IPERF_STREAMS * 2 + 5 ))
	local per_stream
	per_stream=$(incus exec "$CLUSTER_LAN_HOST" -- \
		tail -${tail_lines} "$LOG" 2>/dev/null \
		| grep -E '^\[  [0-9]|^\[ [0-9][0-9]' | tail -"$IPERF_STREAMS")
	local dead
	dead=$(echo "$per_stream" | grep -c "0.00 bits/sec" || true)
	local sum
	sum=$(incus exec "$CLUSTER_LAN_HOST" -- \
		tail -${tail_lines} "$LOG" 2>/dev/null \
		| grep 'SUM' | tail -1 || true)
	local bps
	bps=$(echo "$sum" | grep -oiE "[0-9.]+ [MG]bits/sec" | head -1)
	if [[ "$dead" -gt 0 ]]; then
		fail "$label: $dead/$IPERF_STREAMS streams dead ($bps)"
		return 1
	else
		pass "$label: all streams alive ($bps)"
		return 0
	fi
}

cleanup() {
	info "Cleanup: killing iperf3, resetting failover flags"
	incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
	for rg in 0 1 2; do
		incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
		incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	done
	# With preempt=false, resetting the flag alone doesn't move VRRP.
	# Explicitly request RG1 back to fw0 so the next test starts clean.
	incus exec "$FW0" -- cli -c 'request chassis cluster failover redundancy-group 1 node 0' 2>/dev/null || true
	sleep 2
}

trap cleanup EXIT

# ── Preflight ────────────────────────────────────────────────────────

info "Preflight checks"
info "Config: ${TOTAL_CYCLES} cycles, ${FAILOVER_INTERVAL}s interval, ${IPERF_STREAMS} streams, ${IPERF_DURATION}s iperf3 duration"

for inst in "$FW0" "$FW1" "$CLUSTER_LAN_HOST"; do
	instance_running "$inst" || die "$inst is not running"
done

# Reset any stale manual failover flags from previous test runs.
for rg in 0 1 2; do
	incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
done
sleep 2

# Ensure all RGs are on fw0
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
for rg in 0 1 2; do
	rg_primary=$(echo "$fw0_status" | grep -A2 "Redundancy group: $rg" | grep "node0" | grep -c "primary" || true)
	if [[ "$rg_primary" -ne 1 ]]; then
		incus exec "$FW0" -- cli -c "request chassis cluster failover redundancy-group $rg node 0" 2>/dev/null || true
	fi
done
sleep 3

# Verify fw0 is primary for all RGs
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
all_primary=true
for rg in 0 1 2; do
	rg_primary=$(echo "$fw0_status" | grep -A2 "Redundancy group: $rg" | grep "node0" | grep -c "primary" || true)
	if [[ "$rg_primary" -ne 1 ]]; then
		all_primary=false
	fi
done

if $all_primary; then
	pass "fw0 is primary for all RGs"
else
	die "fw0 is not primary for all RGs — reset cluster state first"
fi

# Verify iperf target reachable
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 2 -W 2 "$IPERF_TARGET" &>/dev/null; then
	pass "iperf3 target reachable ($IPERF_TARGET)"
else
	die "Cannot reach iperf3 target $IPERF_TARGET from cluster-lan-host"
fi

# Kill any stale iperf3
incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
sleep 1

# ── Phase 1: Start iperf3 ───────────────────────────────────────────

info "Phase 1: Starting iperf3 -P${IPERF_STREAMS} -t${IPERF_DURATION} → ${IPERF_TARGET}"

incus exec "$CLUSTER_LAN_HOST" -- bash -c \
	"iperf3 --forceflush --connect-timeout 5000 -t ${IPERF_DURATION} -c ${IPERF_TARGET} -P ${IPERF_STREAMS} > ${LOG} 2>&1 &"

sleep 8  # all parallel streams must be fully established

# Verify iperf3 is running
if incus exec "$CLUSTER_LAN_HOST" -- pgrep -x iperf3 &>/dev/null; then
	pass "iperf3 running on cluster-lan-host"
else
	incus exec "$CLUSTER_LAN_HOST" -- cat "$LOG" 2>/dev/null || true
	die "iperf3 failed to start"
fi

# Verify sessions exist on fw0
fw0_sessions=$(incus exec "$FW0" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
if [[ "$fw0_sessions" -ge "$IPERF_STREAMS" ]]; then
	pass "fw0 has $fw0_sessions established sessions"
else
	fail "fw0 has only $fw0_sessions established sessions (expected >= $IPERF_STREAMS)"
fi

# ── Phase 2: Wait for session sync ──────────────────────────────────

info "Phase 2: Waiting ${SYNC_WAIT}s for session sync to fw1"
sleep "$SYNC_WAIT"

fw1_sessions=$(incus exec "$FW1" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
if [[ "$fw1_sessions" -ge "$IPERF_STREAMS" ]]; then
	pass "fw1 has $fw1_sessions synced sessions"
else
	fail "fw1 has only $fw1_sessions synced sessions (expected >= $IPERF_STREAMS)"
fi

# ── Phase 3: Rapid failover cycles ──────────────────────────────────

info "Phase 3: Starting ${TOTAL_CYCLES} rapid failover cycles (${FAILOVER_INTERVAL}s interval)"

half_interval=$(( FAILOVER_INTERVAL / 2 ))
cycle_failed=false

for cycle in $(seq 1 "$TOTAL_CYCLES"); do
	info "Cycle ${cycle}/${TOTAL_CYCLES}: failover RG1 fw0→fw1"

	# Failover RG1 to fw1
	incus exec "$FW0" -- cli -c 'request chassis cluster failover redundancy-group 1' 2>/dev/null || true

	sleep "$half_interval"

	# Check streams after failover
	if ! check_streams "cycle ${cycle} failover"; then
		cycle_failed=true
	fi

	# Check iperf3 still alive
	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep -x iperf3 &>/dev/null; then
		fail "cycle ${cycle}: iperf3 died after failover"
		cycle_failed=true
		break
	fi

	info "Cycle ${cycle}/${TOTAL_CYCLES}: failback RG1 fw1→fw0"

	# Failback RG1 to fw0
	incus exec "$FW0" -- cli -c 'request chassis cluster failover reset redundancy-group 1' 2>/dev/null || true
	incus exec "$FW1" -- cli -c 'request chassis cluster failover reset redundancy-group 1' 2>/dev/null || true
	incus exec "$FW0" -- cli -c 'request chassis cluster failover redundancy-group 1 node 0' 2>/dev/null || true

	sleep "$half_interval"

	# Check streams after failback
	if ! check_streams "cycle ${cycle} failback"; then
		cycle_failed=true
	fi

	# Check iperf3 still alive
	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep -x iperf3 &>/dev/null; then
		fail "cycle ${cycle}: iperf3 died after failback"
		cycle_failed=true
		break
	fi
done

if ! $cycle_failed; then
	pass "all ${TOTAL_CYCLES} failover cycles completed with 0 dead streams"
fi

# ── Phase 4: Final validation ────────────────────────────────────────

info "Phase 4: Final validation"

# Verify iperf3 still running
if incus exec "$CLUSTER_LAN_HOST" -- pgrep -x iperf3 &>/dev/null; then
	pass "iperf3 still running after all cycles"
else
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" "$LOG" 2>/dev/null; then
		pass "iperf3 completed successfully (finished during cycles)"
	else
		fail "iperf3 died during stress test"
	fi
fi

# Count total zero-throughput intervals across the full log.
# Allow up to 1 per cycle — brief pauses during VRRP transitions are expected
# (iperf3 reports in 1s intervals; a 60ms failover can cause a 0-byte interval).
total_zero=$(incus exec "$CLUSTER_LAN_HOST" -- \
	grep -E '^\[  [0-9]|^\[ [0-9][0-9]' "$LOG" 2>/dev/null \
	| grep -c "0.00 bits/sec" || true)
max_zero="$TOTAL_CYCLES"
if [[ "$total_zero" -eq 0 ]]; then
	pass "0 zero-throughput intervals across entire run"
elif [[ "$total_zero" -le "$max_zero" ]]; then
	pass "$total_zero zero-throughput intervals across entire run (≤${max_zero} allowed)"
else
	fail "$total_zero zero-throughput intervals detected in log (>${max_zero})"
fi

# Kill iperf3 — we have all the data we need
incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
sleep 1

# Extract throughput from the last SUM line (iperf3 may still be running)
last_sum=$(incus exec "$CLUSTER_LAN_HOST" -- grep 'SUM' "$LOG" 2>/dev/null | tail -1 || true)
throughput=""
if echo "$last_sum" | grep -qiE "[0-9.]+ Gbits"; then
	throughput=$(echo "$last_sum" | grep -oiE "[0-9.]+ Gbits" | grep -oP '[\d.]+')
elif echo "$last_sum" | grep -qiE "[0-9.]+ Mbits"; then
	mbits=$(echo "$last_sum" | grep -oiE "[0-9.]+ Mbits" | grep -oP '[\d.]+')
	throughput=$(awk "BEGIN{printf \"%.3f\", $mbits / 1000}")
fi

if [[ -n "$throughput" ]] && awk "BEGIN{exit !($throughput >= $MIN_THROUGHPUT)}"; then
	pass "throughput: ${throughput} Gbps (>= ${MIN_THROUGHPUT} Gbps)"
else
	fail "throughput too low: ${throughput:-0} Gbps (expected >= ${MIN_THROUGHPUT} Gbps)"
fi

# ── Results ──────────────────────────────────────────────────────────

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Stress failover: $PASS passed, $FAIL failed"
echo "  ($TOTAL_CYCLES cycles × ${FAILOVER_INTERVAL}s interval)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
	echo
	echo "Failures:"
	for err in "${ERRORS[@]}"; do
		echo "  - $err"
	done
	exit 1
fi
