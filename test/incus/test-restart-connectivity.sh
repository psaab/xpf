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

# #1875/#4020: this DESTRUCTIVE smoke reboots / force-stops / fails
# over a node on the SHARED loss cluster. Re-exec under the
# incus-admin group if needed, then serialize as a #1875 lock cell
# so a concurrent deploy/smoke can't collide with our reboot (it
# queues behind the canonical cluster lock instead of colliding).
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "test-restart-connectivity $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"

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

# #18523: fw0 owns every RG only when both nodes' own views agree; see
# rg_on_fw0 below (defined before the first call).
fw0_is_primary() {
	local rg
	for rg in 0 1 2; do
		rg_on_fw0 "$rg" || return 1
	done
	return 0
}


# Restored means BOTH nodes agree: fw0's own view has node0 primary and
# fw1's own view has node1 non-owning. fw0's view alone would score a
# dual-primary split as restored (the ha_rg_owner_verdict rule, #18503).
rg_on_fw0() {
	local s0 s1
	s0=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	[[ "$(deploy_node_rg_role node0 "$1" <<<"$s0" || true)" == primary ]] || return 1
	s1=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	[[ "$(deploy_node_rg_role node1 "$1" <<<"$s1" || true)" =~ ^secondary(-hold)?$ ]]
}

# fw1 still claims the RG in its own view (re-requesting a yield from a node
# that already yielded only re-arms its hold and bumps its failover count).
rg_on_fw1() {
	local s1
	s1=$(incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)
	[[ "$(deploy_node_rg_role node1 "$1" <<<"$s1" || true)" == primary ]]
}

restore_fw0_primary() {
	local label="$1" deadline rg out last_err="" started=$SECONDS requests=0 refusals=0
	if fw0_is_primary; then
		return 0
	fi
	for rg in 0 1 2; do
		incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
		incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	done
	sleep 1
	# #18523: one RG at a time, polled, re-requested until the budget runs
	# out. A single fixed sleep after three blind requests was shorter than
	# one admission window plus a post-restart bulk (~50 sessions/s), and
	# swallowed the refusal that said why.
	local wait="${RESTORE_FW0_WAIT:-60}"
	if [[ ! "$wait" =~ ^[0-9]+$ ]]; then
		info "RESTORE_FW0_WAIT=$wait is not a whole number of seconds; using 60"
		wait=60
	fi
	deadline=$((SECONDS + wait))
	for rg in 0 1 2; do
		while ! rg_on_fw0 "$rg"; do
			if ((SECONDS >= deadline)); then
				break 2
			fi
			if rg_on_fw1 "$rg"; then
				out=$(incus exec "$FW1" -- cli -c "request chassis cluster failover redundancy-group $rg" 2>&1 || true)
				requests=$((requests + 1))
				if grep -qiE "error|refus|not connected|failed" <<<"$out"; then
					refusals=$((refusals + 1))
					last_err="RG$rg: $(head -1 <<<"$out")"
				fi
			fi
			for _ in 1 2 3 4 5; do
				rg_on_fw0 "$rg" && break
				sleep 1
			done
		done
	done
	if fw0_is_primary; then
		# #18523: the elapsed time and refusal count are part of the verdict;
		# a bare PASS after a long polled retry would hide exactly the
		# deferral (a half-open sync, a fence) this restore is waiting out.
		local took=$((SECONDS - started)) budget="${RESTORE_FW0_BUDGET:-30}"
		[[ "$budget" =~ ^[0-9]+$ ]] || budget=30
		if ((refusals > 0 || took > budget)); then
			# Restored, so the run continues, but a refused or slow restore is
			# the #18521 class (half-open sync, an undischarged fence) and
			# must not read as healthy. Healthy restores take 9-16s with one
			# request per RG and no refusal (integ5, 2026-10-29).
			fail "$label: fw0 restored only after ${took}s (budget ${budget}s; ${requests} request(s), ${refusals} refused${last_err:+; last refusal: $last_err})"
			return 0
		fi
		pass "$label: fw0 restored as primary in ${took}s (${requests} request(s), ${refusals} refused)"
		return 0
	else
		fail "$label: could not restore fw0 as primary within ${wait}s${last_err:+ (last refusal: $last_err)}"
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
	die "no baseline connectivity to $IPERF_TARGET from ${CLUSTER_LAN_HOST}"
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
