#!/usr/bin/env bash
# xpf cluster active/active RG failover test
#
# Validates that active TCP connections survive when a single redundancy
# group is moved to the peer node (active/active per-RG split).
#
# This tests fabric cross-chassis forwarding: traffic entering on the
# LAN (RG2, fw0) must cross the fabric link to exit on the WAN (RG1, fw1)
# when the RGs are split across nodes.
#
# Requires: cluster nodes from BPFRX_CLUSTER_ENV running (default: loss userspace cluster).
# Requires: iperf3 server reachable at IPERF_TARGET (default from IPERF_TARGET4).
#
# Tests:
#   1. Start iperf3 from LAN host through the firewall to WAN target
#   2. Failover RG1 (WAN) to fw1 — LAN stays on fw0 (active/active split)
#   3. Verify iperf3 survives the split (fabric cross-forwarding)
#   4. Failover RG1 back to fw0 — all RGs on fw0 again
#   5. Verify iperf3 survives the reunification
#
# Usage:
#   ./test/incus/test-active-active.sh
#   IPERF_TARGET=10.1.2.3 ./test/incus/test-active-active.sh

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
xpf_enter_destructive_cluster_cell "test-active-active $*" "$0" "$@"

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
IPERF_DURATION=90       # seconds — enough to span two failovers + settling
IPERF_STREAMS=8
SETTLE_WAIT=3           # seconds to let VRRP + election settle
MIN_THROUGHPUT=1.0      # Gbps — iperf3 must report at least this
LOG="/tmp/iperf3-active-active.log"
PIDFILE="/tmp/iperf3-active-active.pid"
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

cleanup() {
	# Stop only this harness's tracked iperf3 client.
	failover_stop_main_iperf "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
	incus exec "$FW0" -- cli -c 'request chassis cluster failover reset redundancy-group 1' 2>/dev/null || true
	incus exec "$FW1" -- cli -c 'request chassis cluster failover reset redundancy-group 1' 2>/dev/null || true
	# With preempt=false, resetting the flag alone doesn't move VRRP.
	# Explicitly request RG1 back to fw0 so the next test starts clean.
	incus exec "$FW0" -- cli -c 'request chassis cluster failover redundancy-group 1 node 0' 2>/dev/null || true
	sleep 2
}

trap cleanup EXIT

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

# Ensure all RGs are on fw0 (request peer failover if needed)
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
for rg in 0 1 2; do
	rg_primary=$(echo "$fw0_status" | grep -A2 "Redundancy group: $rg" | grep "node0" | grep -c "primary" || true)
	if [[ "$rg_primary" -ne 1 ]]; then
		incus exec "$FW0" -- cli -c "request chassis cluster failover redundancy-group $rg node 0" 2>/dev/null || true
	fi
done
sleep 3

if printf '%s\n' "$fw0_status" | deploy_node_role_every_rg_ok node0 primary; then
	pass "fw0 is primary for all RGs"
else
	die "fw0 is not primary for all RGs — reset cluster state first"
fi

# Verify iperf target reachable
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 2 -W 2 "$IPERF_TARGET" &>/dev/null; then
	pass "iperf3 target reachable ($IPERF_TARGET)"
else
	die "Cannot reach iperf3 target $IPERF_TARGET from ${CLUSTER_LAN_HOST}"
fi

# Stop only a previous client recorded by this harness.
failover_stop_main_iperf "$PIDFILE" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" || true
sleep 1

# ── Phase 1: Start iperf3 ───────────────────────────────────────────

info "Phase 1: Starting iperf3 -P${IPERF_STREAMS} -t${IPERF_DURATION} → ${IPERF_TARGET}"

failover_start_main_iperf "$IPERF_DURATION" "$IPERF_TARGET" "$IPERF_PORT" "$IPERF_STREAMS" \
	"$LOG" "$PIDFILE" 1
IPERF_START_SECONDS=$SECONDS

sleep 8  # all parallel streams must be fully established before failover

# Verify the tracked supervisor, not an unrelated iperf3 process.
if main_iperf_running; then
	pass "tracked iperf3 client running"
else
	die "iperf3 failed to start — check ${LOG} on ${CLUSTER_LAN_HOST}"
fi

# ── Phase 2: Failover RG1 (WAN) to fw1 ──────────────────────────────

info "Phase 2: Failover RG1 (WAN) to node1 — creating active/active split"

FAILOVER_EVENTS+=("$((SECONDS - IPERF_START_SECONDS))")
incus exec "$FW0" -- cli -c 'request chassis cluster failover redundancy-group 1' 2>/dev/null || true
sleep "$SETTLE_WAIT"

# Verify RG split: RG1 on fw1, RG2 on fw0
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)

rg1_node0=$(echo "$fw0_status" | grep -A2 "Redundancy group: 1" | grep "node0" | awk '{print $3}')
rg2_node0=$(echo "$fw0_status" | grep -A2 "Redundancy group: 2" | grep "node0" | awk '{print $3}')

if [[ "$rg1_node0" == "secondary" ]]; then
	pass "RG1 (WAN) moved to fw1"
else
	fail "RG1 did not move to fw1 (node0 state: $rg1_node0)"
fi

if [[ "$rg2_node0" == "primary" ]]; then
	pass "RG2 (LAN) stayed on fw0"
else
	fail "RG2 unexpectedly moved (node0 state: $rg2_node0)"
fi

# Verify VRRP states match cluster state
fw0_vrrp=$(incus exec "$FW0" -- cli -c 'show security vrrp' 2>/dev/null)

vrrp_101=$(echo "$fw0_vrrp" | grep "101" | head -1)
vrrp_102=$(echo "$fw0_vrrp" | grep "102" | head -1)

if echo "$vrrp_101" | grep -qi "BACKUP"; then
	pass "VRRP 101 (WAN) is BACKUP on fw0"
else
	fail "VRRP 101 (WAN) not BACKUP on fw0: $vrrp_101"
fi

if echo "$vrrp_102" | grep -qi "MASTER"; then
	pass "VRRP 102 (LAN) is MASTER on fw0"
else
	fail "VRRP 102 (LAN) not MASTER on fw0: $vrrp_102"
fi

# ── Phase 3: Verify iperf3 survives the split ────────────────────────

info "Phase 3: Verify traffic survives active/active split (fabric forwarding)"

sleep 5  # let traffic settle after failover

if main_iperf_running; then
	pass "tracked iperf3 client survived RG split (active/active fabric forwarding)"
else
	fail "tracked iperf3 client died after RG split (active/active fabric forwarding broken)"
fi

# ── Phase 3b: Verify NEW TCP connections work during split ────────────

info "Phase 3b: Verify new TCP connections work through split cluster"

# Test that a brand-new TCP 3-way handshake succeeds through the split
# cluster.  The Phase 1 iperf3 occupies port 5201 (iperf3 server is
# single-client), so we test TCP connectivity with /dev/tcp which
# proves the full SYN → SYN-ACK → ACK path works across fabric.
# The iperf3 server accepts the TCP connection (then sends "busy"),
# but the 3-way handshake completing is what matters.
if incus exec "$CLUSTER_LAN_HOST" -- bash -c \
	"timeout 5 bash -c 'echo > /dev/tcp/${IPERF_TARGET}/5201'" 2>/dev/null; then
	pass "new TCP connection through split cluster"
else
	fail "new TCP connection failed during split (TCP handshake to ${IPERF_TARGET}:5201)"
fi

# ── Phase 3c: Verify ICMP (ping) works during split ─────────────────

info "Phase 3c: Verify ping works through split cluster"

if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 3 "$IPERF_TARGET" &>/dev/null; then
	pass "ping through split cluster works"
else
	fail "ping through split cluster failed (new connections broken)"
fi

# ── Phase 4: Failover RG1 back to fw0 ───────────────────────────────

info "Phase 4: Failover RG1 (WAN) back to node0 — reunifying all RGs"

FAILOVER_EVENTS+=("$((SECONDS - IPERF_START_SECONDS))")
incus exec "$FW0" -- cli -c 'request chassis cluster failover redundancy-group 1 node 0' 2>/dev/null || true
sleep "$SETTLE_WAIT"

# Verify all RGs back on fw0
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)

if printf '%s\n' "$fw0_status" | deploy_node_role_every_rg_ok node0 primary; then
	pass "all RGs returned to fw0 after reunification"
else
	fail "not all RGs returned to fw0 after reunification"
fi

# ── Phase 5: Verify iperf3 survives reunification ────────────────────

info "Phase 5: Verify traffic survives RG reunification"

sleep 5

if main_iperf_running; then
	pass "tracked iperf3 client survived RG reunification"
else
	fail "tracked iperf3 client died after RG reunification"
fi

# ── Phase 6: validate throughput and both failover transitions ────────

info "Waiting for iperf3 to complete and validating both transition intervals"

for _ in $(seq 1 "$IPERF_DURATION"); do
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

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ ${FAIL} -gt 0 ]]; then
	echo ""
	echo "Failures:"
	for e in "${ERRORS[@]}"; do
		echo "  - $e"
	done
	exit 1
fi
