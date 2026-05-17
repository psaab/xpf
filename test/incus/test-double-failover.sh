#!/usr/bin/env bash
# xpf double failover test
#
# Validates that active TCP connections survive TWO consecutive crash failovers:
#   fw0 crash → fw1 takes over → fw0 rejoins → fw1 crash → fw0 takes over
# This tests session sync in both directions and ensures sessions survive
# a full round-trip failover cycle.
#
# Requires: cluster nodes from BPFRX_CLUSTER_ENV running (default: loss userspace cluster).
# Requires: iperf3 server reachable at IPERF_TARGET (default from IPERF_TARGET4).
#
# Tests:
#   1. Start iperf3 -P4 through the firewall (LAN host → WAN target)
#   2. Verify sessions exist on fw0 (primary)
#   3. Crash fw0 (sysrq reboot — unclean, no priority-0 burst)
#   4. Verify fw1 becomes primary, iperf3 survives
#   5. Wait for fw0 to reboot and rejoin as secondary with "Takeover ready: yes"
#   6. Wait for session sync from fw1 → fw0
#   7. Crash fw1 (sysrq reboot — unclean)
#   8. Verify fw0 becomes primary, iperf3 survives second failover
#   9. Validate throughput
#
# Usage:
#   ./test/incus/test-double-failover.sh
#   IPERF_TARGET=10.1.2.3 ./test/incus/test-double-failover.sh

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
IPERF_DURATION=300      # seconds — long enough to span two full failover cycles
IPERF_STREAMS=4
MIN_SESSIONS=4          # minimum established sessions (control + some data streams)
SYNC_WAIT=5             # seconds to wait for session sync sweep
REBOOT_WAIT=90          # max seconds to wait for a node to come back
TAKEOVER_WAIT=60        # max seconds to wait for "Takeover ready: yes"
MIN_THROUGHPUT=1.0      # Gbps — iperf3 must report at least this

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

# ── Preflight ────────────────────────────────────────────────────────

info "Preflight checks"

for inst in "$FW0" "$FW1" "$CLUSTER_LAN_HOST"; do
	instance_running "$inst" || die "$inst is not running"
done

# Reset any stale manual failover flags from previous test runs.
for rg in 0 1 2; do
	incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
done
sleep 2

# Verify fw0 is primary
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if echo "$fw0_status" | grep -q "node0.*primary"; then
	pass "fw0 is primary"
else
	die "fw0 is not primary — cannot run double failover test"
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

info "Starting iperf3 -P${IPERF_STREAMS} -t${IPERF_DURATION} → ${IPERF_TARGET}"

iperf_started=false
for attempt in 1 2 3; do
	incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
	sleep 1
	incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"iperf3 --forceflush --connect-timeout 5000 -t ${IPERF_DURATION} -c ${IPERF_TARGET} -P ${IPERF_STREAMS} > /tmp/iperf3-double-failover.log 2>&1 &"

	sleep 8  # all parallel streams must be fully established

	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
		info "iperf3 exited on attempt $attempt — server may be busy, retrying"
		sleep $((attempt * 5))
		continue
	fi

	fw0_sessions=$(incus exec "$FW0" -- cli -c \
		"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
	if [[ "$fw0_sessions" -ge "$IPERF_STREAMS" ]]; then
		iperf_started=true
		break
	fi

	# iperf3 is running but not enough sessions — streams may have timed out
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "unable to connect" /tmp/iperf3-double-failover.log 2>/dev/null; then
		info "iperf3 stream connect failed on attempt $attempt — server busy, retrying"
		incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
		sleep $((attempt * 10))
		continue
	fi

	iperf_started=true
	break
done

if ! $iperf_started; then
	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
		incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-double-failover.log 2>/dev/null || true
		die "iperf3 failed to start after 3 attempts"
	fi
fi

# Verify iperf3 is running
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 running on cluster-lan-host"
else
	incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-double-failover.log 2>/dev/null || true
	die "iperf3 failed to start"
fi

# Verify sessions exist on fw0
fw0_sessions=$(incus exec "$FW0" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
if [[ "$fw0_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw0 has $fw0_sessions established sessions"
else
	fail "fw0 has only $fw0_sessions established sessions (expected >= $MIN_SESSIONS)"
fi

# ── Phase 2: Wait for session sync fw0 → fw1 ────────────────────────

info "Waiting ${SYNC_WAIT}s for session sync to fw1"
sleep "$SYNC_WAIT"

fw1_sessions=$(incus exec "$FW1" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
if [[ "$fw1_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw1 has $fw1_sessions synced sessions"
else
	fail "fw1 has only $fw1_sessions synced sessions (expected >= $MIN_SESSIONS)"
fi

# ── Phase 3: Crash fw0 (first failover) ─────────────────────────────

info "Crashing fw0 (sysrq reboot — unclean shutdown, tests worst-case failover)"

incus exec "$FW0" -- bash -c 'echo b > /proc/sysrq-trigger' 2>/dev/null || true

# Wait for fw1 to detect failure and become primary
sleep 5

# Verify fw1 became primary
fw1_status=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
if echo "$fw1_status" | grep -q "node1.*primary"; then
	pass "fw1 became primary after fw0 crash"
else
	fail "fw1 did not become primary after fw0 crash"
fi

# Verify iperf3 survived the first failover
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived first failover (fw0 crash → fw1)"
else
	fail "iperf3 DIED during first failover — fw0 crash broke TCP connections"
fi

# ── Phase 4: Wait for fw0 to reboot and rejoin ──────────────────────

info "Waiting for fw0 to reboot and rejoin as secondary (max ${REBOOT_WAIT}s)"

fw0_back=false
for i in $(seq 1 "$REBOOT_WAIT"); do
	if wait_for_instance "$FW0" 1; then
		fw0_back=true
		info "fw0 xpfd active after ${i}s"
		break
	fi
done

if $fw0_back; then
	pass "fw0 xpfd restarted after reboot"
else
	fail "fw0 xpfd did not come back within ${REBOOT_WAIT}s"
fi

# Wait for cluster to stabilize (gRPC takes ~15s after systemctl active)
sleep 20

# Verify fw0 is secondary (no auto-preempt)
fw0_status_after=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if echo "$fw0_status_after" | grep -q "node0.*secondary"; then
	pass "fw0 rejoined as secondary (no auto-preempt)"
elif echo "$fw0_status_after" | grep -q "node0.*primary"; then
	fail "fw0 auto-preempted to primary (should stay secondary)"
else
	fail "fw0 cluster status unclear: $fw0_status_after"
fi

# Verify iperf3 still running after fw0 rejoin
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived fw0 rejoin"
else
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-double-failover.log 2>/dev/null; then
		pass "iperf3 completed successfully (finished before rejoin check)"
	else
		fail "iperf3 DIED during fw0 rejoin"
	fi
fi

# ── Phase 5: Wait for "Takeover ready: yes" on fw0 ──────────────────

info "Waiting for fw0 to reach 'Takeover ready: yes' (max ${TAKEOVER_WAIT}s)"

takeover_ready=false
for i in $(seq 1 "$TAKEOVER_WAIT"); do
	status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	if echo "$status" | grep -qi "Takeover ready.*yes"; then
		takeover_ready=true
		info "fw0 takeover ready after ${i}s"
		break
	fi
	sleep 1
done

if $takeover_ready; then
	pass "fw0 is takeover-ready (sync hold released)"
else
	fail "fw0 did not reach 'Takeover ready: yes' within ${TAKEOVER_WAIT}s"
fi

# ── Phase 6: Verify session sync fw1 → fw0 ──────────────────────────

info "Verifying session sync from fw1 → fw0"

# Additional wait for session sync to complete after takeover-ready
sleep "$SYNC_WAIT"

fw0_synced=$(incus exec "$FW0" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
if [[ "$fw0_synced" -ge "$MIN_SESSIONS" ]]; then
	pass "fw0 has $fw0_synced synced sessions from fw1"
else
	fail "fw0 has only $fw0_synced synced sessions (expected >= $MIN_SESSIONS)"
fi

# ── Phase 7: Crash fw1 (second failover) ─────────────────────────────

info "Crashing fw1 (sysrq reboot — second failover, fw0 must take over)"

incus exec "$FW1" -- bash -c 'echo b > /proc/sysrq-trigger' 2>/dev/null || true

# Wait for fw0 to detect failure and become primary
sleep 5

# Verify fw0 became primary
fw0_status_second=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
if echo "$fw0_status_second" | grep -q "node0.*primary"; then
	pass "fw0 became primary after fw1 crash (second failover)"
else
	fail "fw0 did not become primary after fw1 crash"
fi

# Verify iperf3 survived the second failover
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived second failover (fw1 crash → fw0)"
else
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-double-failover.log 2>/dev/null; then
		pass "iperf3 completed successfully (finished before second failover check)"
	else
		fail "iperf3 DIED during second failover — session sync round-trip FAILED"
	fi
fi

# ── Phase 8: Wait for iperf3 to complete and validate results ────────

info "Waiting for iperf3 to complete"

for i in $(seq 1 "$IPERF_DURATION"); do
	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
		break
	fi
	sleep 1
done

# Check iperf3 completed successfully.
# iperf3's control socket may close during failover even though all data
# streams survived — this produces "control socket has closed unexpectedly"
# instead of "iperf Done". Accept either outcome as long as the sender
# [SUM] line shows adequate throughput.
throughput=$(incus exec "$CLUSTER_LAN_HOST" -- grep '\[SUM\].*sender' /tmp/iperf3-double-failover.log 2>/dev/null \
	| grep -oP '[\d.]+\s+Gbits' | grep -oP '[\d.]+' || echo "0")

if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-double-failover.log 2>/dev/null; then
	pass "iperf3 completed successfully"
elif [[ -n "$throughput" ]] && awk "BEGIN{exit !($throughput >= $MIN_THROUGHPUT)}"; then
	pass "iperf3 data transfer completed (${throughput} Gbps) — control socket disrupted during failover"
else
	iperf_log=$(incus exec "$CLUSTER_LAN_HOST" -- tail -5 /tmp/iperf3-double-failover.log 2>/dev/null || echo "(no log)")
	fail "iperf3 did not complete: $iperf_log"
fi

if [[ -n "$throughput" ]] && awk "BEGIN{exit !($throughput >= $MIN_THROUGHPUT)}"; then
	pass "iperf3 throughput: ${throughput} Gbps (>= ${MIN_THROUGHPUT} Gbps)"
elif [[ -n "$throughput" ]] && [[ "$throughput" != "0" ]]; then
	fail "iperf3 throughput too low: ${throughput} Gbps (expected >= ${MIN_THROUGHPUT} Gbps)"
fi

# ── Results ──────────────────────────────────────────────────────────

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Double failover test: $PASS passed, $FAIL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
	echo
	echo "Failures:"
	for err in "${ERRORS[@]}"; do
		echo "  - $err"
	done
	exit 1
fi
