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
xpf_enter_destructive_cluster_cell "test-double-failover $*" "$0" "$@"

# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/iperf-throughput-lib.sh
source "${SCRIPT_DIR}/iperf-throughput-lib.sh"
# shellcheck source=test/incus/failover-clock-lib.sh
source "${SCRIPT_DIR}/failover-clock-lib.sh"
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
IPERF_DURATION=300      # seconds — long enough to span two full failover cycles
IPERF_STREAMS=4
MIN_SESSIONS=4          # minimum observed session entries (control + some data streams)
SYNC_WAIT=5             # seconds to wait for session sync sweep
REBOOT_WAIT=90          # max seconds to wait for a node to come back
TAKEOVER_WAIT=60        # max seconds to wait for "Takeover ready: yes"
MIN_THROUGHPUT=1.0      # Gbps — iperf3 must report at least this
LOG="/tmp/iperf3-double-failover.log"
PIDFILE="/tmp/iperf3-double-failover.pid"
IPERF_START_SECONDS=0
FAILOVER_EVENTS=()

main_iperf_running() {
	failover_main_iperf_running "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS"
}

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

fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if printf '%s\n' "$fw0_status" | deploy_node_role_every_rg_ok node0 primary; then
	pass "fw0 is primary for every redundancy group"
else
	die "fw0 is not primary for every redundancy group — cannot run double failover test"
fi

# Verify iperf target reachable
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 2 -W 2 "$IPERF_TARGET" &>/dev/null; then
	pass "iperf3 target reachable ($IPERF_TARGET)"
else
	die "Cannot reach iperf3 target $IPERF_TARGET from ${CLUSTER_LAN_HOST}"
fi

# Stop only the previous tracked client; unrelated iperf3 processes are not this
# smoke's evidence and must not be killed or allowed to satisfy its liveness.
failover_stop_main_iperf "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
sleep 1

# ── Phase 1: Start iperf3 ───────────────────────────────────────────

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

	# Retry only on iperf3's captured JSON connection-failure event.
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
		incus exec "$CLUSTER_LAN_HOST" -- cat "$LOG" 2>/dev/null || true
		die "iperf3 failed to start after 3 attempts"
	fi
fi

# Verify the tracked iperf3 supervisor, not an unrelated process.
if main_iperf_running; then
	pass "tracked iperf3 client running on ${CLUSTER_LAN_HOST}"
else
	incus exec "$CLUSTER_LAN_HOST" -- cat "$LOG" 2>/dev/null || true
	die "iperf3 failed to start"
fi

# Verify sessions exist on fw0
fw0_sessions=$(incus exec "$FW0" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
if [[ "$fw0_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw0 has $fw0_sessions session entries"
else
	fail "fw0 has only $fw0_sessions session entries (expected >= $MIN_SESSIONS)"
fi

# ── Phase 2: Wait for session sync fw0 → fw1 ────────────────────────

info "Waiting ${SYNC_WAIT}s for session sync to fw1"
sleep "$SYNC_WAIT"

fw1_sessions=$(incus exec "$FW1" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
if [[ "$fw1_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw1 has $fw1_sessions synced sessions"
else
	fail "fw1 has only $fw1_sessions synced sessions (expected >= $MIN_SESSIONS)"
fi

# ── Phase 3: Crash fw0 (first failover) ─────────────────────────────

info "Crashing fw0 (sysrq reboot — unclean shutdown, tests worst-case failover)"

# timeout -k is load-bearing (#1880): the sysrq reset kills the
# incus-agent serving this exec, so it may never return, and incus exec
# forwards SIGTERM to the (dead) remote session — only the SIGKILL
# follow-up reliably reaps the local client (measured 47min/38min hangs
# on test-failover.sh before the bound was added).
# Record the transition against the iperf3 JSON stream's monotonic seconds.
FAILOVER_EVENTS+=("$((SECONDS - IPERF_START_SECONDS))")
{ timeout -k 5 10 incus exec "$FW0" -- bash -c 'echo b > /proc/sysrq-trigger' || true; } 2>/dev/null

# Wait for fw1 to detect failure and become primary
sleep 5

# Verify fw1 became primary
fw1_status=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
if printf '%s\n' "$fw1_status" | deploy_node_role_every_rg_ok node1 primary; then
	pass "fw1 became primary for every redundancy group after fw0 crash"
else
	fail "fw1 did not become primary for every redundancy group after fw0 crash"
fi

# Verify the original tracked client survived the first failover.
if main_iperf_running; then
	pass "tracked iperf3 client survived first failover (fw0 crash → fw1)"
else
	fail "tracked iperf3 client died during first failover — fw0 crash broke the stream"
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

# #11872: fw0's crash reboot can leave its clock minutes behind in the no-NTP
# loss lab. Resync BOTH nodes from one host UTC reading before verifying
# rejoin/takeover readiness and crashing fw1 for the return failover.
if failover_resync_node_clocks "$FW0" "$FW1"; then
	pass "both firewall clocks resynced from host UTC after crash reboot"
else
	fail "could not resync both firewall clocks from host UTC after crash reboot"
fi


# Wait for cluster to stabilize (gRPC takes ~15s after systemctl active)
sleep 20

# Verify fw0 is secondary (no auto-preempt)
fw0_status_after=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if printf '%s\n' "$fw0_status_after" | deploy_node_role_every_rg_ok node0 secondary; then
	pass "fw0 rejoined as secondary for every redundancy group (no auto-preempt)"
elif printf '%s\n' "$fw0_status_after" | deploy_node_role_every_rg_ok node0 primary; then
	fail "fw0 auto-preempted to primary (should stay secondary)"
else
	fail "fw0 role is unclear for one or more redundancy groups: $fw0_status_after"
fi

# Verify the original tracked client remains alive after fw0 rejoins.
if main_iperf_running; then
	pass "tracked iperf3 client survived fw0 rejoin"
else
	fail "tracked iperf3 client died during fw0 rejoin"
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
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "^Session ID:" || true)
if [[ "$fw0_synced" -ge "$MIN_SESSIONS" ]]; then
	pass "fw0 has $fw0_synced synced sessions from fw1"
else
	fail "fw0 has only $fw0_synced synced sessions (expected >= $MIN_SESSIONS)"
fi

# ── Phase 7: Crash fw1 (second failover) ─────────────────────────────

info "Crashing fw1 (sysrq reboot — second failover, fw0 must take over)"

# Same timeout -k rationale as the fw0 crash above (#1880).
FAILOVER_EVENTS+=("$((SECONDS - IPERF_START_SECONDS))")
{ timeout -k 5 10 incus exec "$FW1" -- bash -c 'echo b > /proc/sysrq-trigger' || true; } 2>/dev/null

# Wait for fw0 to detect failure and become primary
sleep 5

# Verify fw0 became primary
fw0_status_second=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
if printf '%s\n' "$fw0_status_second" | deploy_node_role_every_rg_ok node0 primary; then
	pass "fw0 became primary for every redundancy group after fw1 crash (second failover)"
else
	fail "fw0 did not become primary for every redundancy group after fw1 crash"
fi

# Verify the original tracked client survived the second failover.
if main_iperf_running; then
	pass "tracked iperf3 client survived second failover (fw1 crash → fw0)"
else
	fail "tracked iperf3 client died during second failover — session sync round-trip FAILED"
fi

# ── Phase 8: validate throughput and both failover transitions ────────

info "Waiting for iperf3 to complete and validating both transition intervals"

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
