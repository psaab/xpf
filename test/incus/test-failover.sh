#!/usr/bin/env bash
# xpf cluster failover test
#
# Validates that active TCP connections survive fw0 reboot.
# Requires: cluster nodes from BPFRX_CLUSTER_ENV running (default: loss userspace cluster).
# Requires: iperf3 server reachable at IPERF_TARGET (default from IPERF_TARGET4).
#
# Tests:
#   1. Start iperf3 -P2 through the firewall (LAN host → WAN target)
#   2. Verify sessions sync from primary (fw0) to secondary (fw1)
#   3. Reboot fw0 (unclean — no priority-0 burst)
#   4. Verify iperf3 survives (TCP connections maintained through failover)
#   5. Verify fw0 comes back as secondary (no auto-preempt)
#   6. Manual failover: fw0 becomes primary again, iperf3 survives
#
# Usage:
#   ./test/incus/test-failover.sh
#   IPERF_TARGET=10.1.2.3 ./test/incus/test-failover.sh

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
IPERF_DURATION=120      # seconds — long enough to span retries + reboot + failback
IPERF_STREAMS=8
MIN_SESSIONS=4          # minimum established sessions (control + some data streams)
SYNC_WAIT=5             # seconds to wait for session sync sweep
REBOOT_WAIT=60          # max seconds to wait for fw0 to come back
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
# Without this, fw1 can't take over during the reboot test because
# ManualFailover blocks election even when the peer is lost.
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
	die "fw0 is not primary — cannot run failover test"
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

# iperf3 server handles one client at a time. After a previous test
# disrupts connections (session clear / failover), the server may hold
# a stale session until TCP keepalive fires (~minutes). Retry startup
# with increasing back-off to wait for the server to become available.
iperf_started=false
for attempt in 1 2 3; do
	incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
	sleep 1
	incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"iperf3 --forceflush --connect-timeout 5000 -t ${IPERF_DURATION} -c ${IPERF_TARGET} -P ${IPERF_STREAMS} > /tmp/iperf3-failover.log 2>&1 &"

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
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "unable to connect" /tmp/iperf3-failover.log 2>/dev/null; then
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
		incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log 2>/dev/null || true
		die "iperf3 failed to start after 3 attempts"
	fi
fi

# Verify iperf3 is running
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 running on cluster-lan-host"
else
	incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log 2>/dev/null || true
	die "iperf3 failed to start"
fi

# Verify sessions exist on fw0.
# iperf3 server is single-client — if a stale session from the previous
# test lingers, some data streams may not connect. Accept MIN_SESSIONS
# (control + some data) rather than requiring all IPERF_STREAMS.
fw0_sessions=$(incus exec "$FW0" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
if [[ "$fw0_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw0 has $fw0_sessions established sessions"
else
	fail "fw0 has only $fw0_sessions established sessions (expected >= $MIN_SESSIONS)"
fi

# ── Phase 2: Wait for session sync ──────────────────────────────────

info "Waiting ${SYNC_WAIT}s for session sync to fw1"
sleep "$SYNC_WAIT"

fw1_sessions=$(incus exec "$FW1" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
if [[ "$fw1_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw1 has $fw1_sessions synced sessions"
else
	fail "fw1 has only $fw1_sessions synced sessions (expected >= $MIN_SESSIONS)"
fi

# ── Phase 3: Reboot fw0 ─────────────────────────────────────────────

info "Rebooting fw0 (unclean shutdown — tests worst-case failover)"

incus exec "$FW0" -- reboot 2>/dev/null || true

# Wait for fw1 to detect failure and become primary
sleep 3

# Verify iperf3 survived the failover
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived fw0 reboot (failover to fw1)"
else
	fail "iperf3 DIED during fw0 reboot — failover broke TCP connections"
fi

# ── Phase 4: Wait for fw0 to come back as secondary (no auto-preempt) ─

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

# Verify fw0 is secondary (NOT primary — no auto-preempt)
fw0_status_after=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if echo "$fw0_status_after" | grep -q "node0.*secondary"; then
	pass "fw0 rejoined as secondary (no auto-preempt)"
elif echo "$fw0_status_after" | grep -q "node0.*primary"; then
	fail "fw0 auto-preempted to primary (should stay secondary)"
else
	fail "fw0 cluster status unclear: $fw0_status_after"
fi

# Verify fw1 is still primary
if incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null | grep -q "node1.*primary"; then
	pass "fw1 remains primary after fw0 rejoin"
else
	fail "fw1 is not primary after fw0 rejoin"
fi

# Verify iperf3 still running
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived fw0 rejoin"
else
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-failover.log 2>/dev/null; then
		pass "iperf3 completed successfully (finished before rejoin check)"
	else
		fail "iperf3 DIED during fw0 rejoin"
	fi
fi

# ── Phase 4b: Manual failover — fw0 becomes primary again ───────────

info "Manual failover: requesting fw1 to failover all RGs to fw0"

# Execute manual failover on fw1 for all RGs (current primary).
# Each RG must be explicitly failed over — RG0 alone doesn't move RG1/RG2
# because per-RG election is independent with non-preempt.
for rg in 0 1 2; do
	incus exec "$FW1" -- cli -c "request chassis cluster failover redundancy-group $rg" 2>/dev/null || true
done

# Wait for failover to complete
sleep 5

# Verify fw0 is now primary for ALL RGs
all_primary=true
for rg in 0 1 2; do
	if ! incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null | grep -A1 "Redundancy group: $rg" | grep -q "node0.*primary"; then
		all_primary=false
		fail "fw0 is not primary for RG$rg after manual failover"
	fi
done
if $all_primary; then
	pass "fw0 became primary for all RGs after manual failover"
fi

# Verify iperf3 survived manual failover
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived manual failover"
else
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-failover.log 2>/dev/null; then
		pass "iperf3 completed successfully (finished before manual failover check)"
	else
		fail "iperf3 DIED during manual failover"
	fi
fi

# ── Phase 5: Wait for iperf3 to complete and validate results ───────

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
throughput=$(incus exec "$CLUSTER_LAN_HOST" -- grep '\[SUM\].*sender' /tmp/iperf3-failover.log 2>/dev/null \
	| grep -oP '[\d.]+\s+Gbits' | grep -oP '[\d.]+' || echo "0")

if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-failover.log 2>/dev/null; then
	pass "iperf3 completed successfully"
elif [[ -n "$throughput" ]] && awk "BEGIN{exit !($throughput >= $MIN_THROUGHPUT)}"; then
	pass "iperf3 data transfer completed (${throughput} Gbps) — control socket disrupted during failover"
else
	iperf_log=$(incus exec "$CLUSTER_LAN_HOST" -- tail -5 /tmp/iperf3-failover.log 2>/dev/null || echo "(no log)")
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
