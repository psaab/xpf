#!/usr/bin/env bash
# test-private-rg.sh — Validate private RG election mode
#
# Tests the private-rg-election feature which eliminates VRRP on data-plane
# interfaces, using only the heartbeat control link for RG election.
#
# Prerequisites:
#   - Cluster VMs from BPFRX_CLUSTER_ENV running (make cluster-create)
#   - iperf3 server at IPERF_TARGET4
#
# Usage:
#   ./test/incus/test-private-rg.sh              # Full cycle; restore initial mode
#   ./test/incus/test-private-rg.sh enable       # Enable private-RG and test; leave enabled
#   ./test/incus/test-private-rg.sh disable      # Enable legacy VRRP and test; leave disabled
#   ./test/incus/test-private-rg.sh check        # Check current state only
#
# Full-cycle mode snapshots the selected cluster config and restores it on
# every exit. `enable` and `disable` deliberately leave their explicitly
# requested mode selected.
#
# Mode changes use the raw deploy path: the default deb deploy preserves the
# node's active config and does not push CONF, so it cannot establish the
# mode this test is meant to exercise.
#
# The full cycle tests its two temporary modes and restores the initial
# configuration and running mode on both nodes before returning.

set -euo pipefail

# #1875/#4020: this DESTRUCTIVE smoke reboots / force-stops / fails
# over a node on the SHARED loss cluster. Re-exec under the
# incus-admin group if needed, then serialize as a #1875 lock cell
# so a concurrent deploy/smoke can't collide with our reboot (it
# queues behind a held /tmp/xpf-cluster.lock instead of colliding).
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "test-private-rg $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"

CONF="${CLUSTER_CONF:-${PROJECT_ROOT}/docs/ha-cluster.conf}"
# shellcheck source=test/incus/private-rg-lib.sh
source "${SCRIPT_DIR}/private-rg-lib.sh"

WAN_CAPTURE_IFACE=$(privrg_reth_member "$CONF" reth0) || {
	echo "ERROR: cannot find the node0 WAN RETH (reth0) member in $CONF" >&2
	exit 1
}
LAN_CAPTURE_IFACE=$(privrg_reth_member "$CONF" reth1) || {
	echo "ERROR: cannot find the node0 LAN RETH (reth1) member in $CONF" >&2
	exit 1
}

PRIVRG_SNAPSHOT=""
PRIVRG_SNAPSHOT_DIR=""
PRIVRG_DEPLOY_ATTEMPTED=0
PRIVRG_BASE_MODE=""

privrg_deploy_config() {
	PRIVRG_DEPLOY_ATTEMPTED=1
	# cluster-deploy's default deb path preserves active node config. Force the
	# raw path so the edited CONF is pushed and the tested mode actually runs.
	(cd "$PROJECT_ROOT" && XPF_DEPLOY_FAST=1 make cluster-deploy) 2>&1 | tail -5
}

privrg_finish_full_cycle() {
	local run_status="$1" cleanup_status=0 expected_mode
	trap - EXIT INT TERM
	set +e

	if [[ -n "$PRIVRG_SNAPSHOT" && -f "$PRIVRG_SNAPSHOT" ]]; then
		if ! privrg_restore_conf "$CONF" "$PRIVRG_SNAPSHOT"; then
			echo "ERROR: failed to restore $CONF from the full-cycle snapshot" >&2
			cleanup_status=1
		fi
		if ! privrg_conf_byte_identical "$CONF" "$PRIVRG_SNAPSHOT"; then
			echo "ERROR: restored $CONF is not byte-identical to the full-cycle snapshot" >&2
			cleanup_status=1
		fi
		if git -C "$PROJECT_ROOT" ls-files --error-unmatch "$CONF" >/dev/null 2>&1 &&
		   ! git -C "$PROJECT_ROOT" diff --quiet -- "$CONF"; then
			echo "ERROR: tracked config remains dirty after full-cycle restore: $CONF" >&2
			cleanup_status=1
		fi

		if [[ "$PRIVRG_DEPLOY_ATTEMPTED" == 1 ]]; then
			if ! privrg_deploy_config; then
				echo "ERROR: failed to redeploy restored config on the cluster" >&2
				cleanup_status=1
			elif ! wait_cluster_ready; then
				echo "ERROR: cluster did not become ready after restoring $CONF" >&2
				cleanup_status=1
			fi
		fi

		expected_mode="$PRIVRG_BASE_MODE"
		if ! privrg_assert_both_running_modes "$FW0" "$FW1" "$expected_mode"; then
			echo "ERROR: running config on both nodes does not match the restored $CONF mode" >&2
			cleanup_status=1
		fi
		rm -rf -- "$PRIVRG_SNAPSHOT_DIR"
		PRIVRG_SNAPSHOT=""
		PRIVRG_SNAPSHOT_DIR=""
	fi

	if [[ "$run_status" -ne 0 ]]; then
		exit "$run_status"
	elif [[ "$cleanup_status" -ne 0 ]]; then
		exit 1
	fi
}

privrg_begin_full_cycle() {
	# Keep the mode-preserving snapshot private even when CONF is world-readable.
	PRIVRG_SNAPSHOT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/test-private-rg-conf.XXXXXX") || return 1
	PRIVRG_SNAPSHOT="${PRIVRG_SNAPSHOT_DIR}/conf"
	if ! privrg_snapshot_conf "$CONF" "$PRIVRG_SNAPSHOT"; then
		rm -rf -- "$PRIVRG_SNAPSHOT_DIR"
		PRIVRG_SNAPSHOT=""
		PRIVRG_SNAPSHOT_DIR=""
		return 1
	fi
	if grep -Eq '^[[:space:]]*no-private-rg-election[[:space:];]' "$PRIVRG_SNAPSHOT"; then
		PRIVRG_BASE_MODE=legacy
	else
		PRIVRG_BASE_MODE=private
	fi
	trap 'privrg_finish_full_cycle "$?"' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
}

PASS=0
FAIL=0
ERRORS=()

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
warn()  { echo "  WARN  $*"; }

wait_cluster_ready() {
	local max_wait=30
	local i=0
	while [[ $i -lt $max_wait ]]; do
		if incus exec "$FW0" -- systemctl is-active --quiet xpfd 2>/dev/null &&
		   incus exec "$FW1" -- systemctl is-active --quiet xpfd 2>/dev/null; then
			sleep 5  # Allow election to settle
			return 0
		fi
		sleep 1
		i=$((i + 1))
	done
	return 1
}

# ── Check functions ──────────────────────────────────────────────────

check_no_vrrp_multicast() {
	info "Checking for VRRP multicast on LAN and WAN RETH members..."
	local capture
	# A no-packet timeout has a tcpdump summary but a non-zero timeout status.
	# Preserve the summary so a timeout is not mistaken for a capture error.
	capture=$(incus exec "$FW0" -- timeout 3 tcpdump -c 1 -i "$WAN_CAPTURE_IFACE" vrrp 2>&1 || true)
	if [[ "$capture" == *"0 packets captured"* ]]; then
		pass "No VRRP multicast on $WAN_CAPTURE_IFACE (WAN RETH member)"
	else
		fail "VRRP multicast detected or capture failed on $WAN_CAPTURE_IFACE (WAN RETH member)"
	fi

	capture=$(incus exec "$FW0" -- timeout 3 tcpdump -c 1 -i "$LAN_CAPTURE_IFACE" vrrp 2>&1 || true)
	if [[ "$capture" == *"0 packets captured"* ]]; then
		pass "No VRRP multicast on $LAN_CAPTURE_IFACE (LAN RETH member)"
	else
		fail "VRRP multicast detected or capture failed on $LAN_CAPTURE_IFACE (LAN RETH member)"
	fi
}

check_vrrp_active() {
	info "Checking VRRP instances are running in the current xpfd invocation..."
	local log
	if ! log=$(privrg_xpfd_journal "$FW0"); then
		fail "Could not read fw0's current xpfd journal"
		return
	fi

	if privrg_log_has_vrrp_start "$log"; then
		pass "VRRP instances started on fw0 in this xpfd invocation"
	else
		fail "No VRRP instances on fw0 in the current xpfd invocation"
	fi

	if privrg_log_has_vrrp_master "$log"; then
		pass "VRRP MASTER state reached on fw0 in this xpfd invocation"
	else
		fail "VRRP did not reach MASTER on fw0 in the current xpfd invocation"
	fi
}

check_no_vrrp_instances() {
	info "Checking VRRP instances are NOT running in the current xpfd invocation..."
	local log
	if ! log=$(privrg_xpfd_journal "$FW0"); then
		fail "Could not read fw0's current xpfd journal"
		return
	fi

	if privrg_log_has_vrrp_start "$log"; then
		fail "VRRP instances running in private-rg mode"
	else
		pass "No VRRP instances in the current xpfd invocation (private-rg mode)"
	fi
}

check_vips_present() {
	info "Checking VIPs are present..."
	local addrs
	addrs=$(incus exec "$FW0" -- ip addr show 2>/dev/null)

	if echo "$addrs" | grep -q "$WAN_VIP4"; then
		pass "WAN VIP ${WAN_VIP4} present"
	else
		fail "WAN VIP ${WAN_VIP4} missing"
	fi

	if echo "$addrs" | grep -q "$LAN_VIP4"; then
		pass "LAN VIP ${LAN_VIP4} present"
	else
		fail "LAN VIP ${LAN_VIP4} missing"
	fi

	if echo "$addrs" | grep -q "$LAN_VIP6"; then
		pass "LAN VIP IPv6 present"
	else
		fail "LAN VIP IPv6 missing"
	fi
}

check_connectivity() {
	info "Checking connectivity from LAN host..."
	if ! incus info "$CLUSTER_LAN_HOST" &>/dev/null 2>&1; then
		warn "${CLUSTER_LAN_HOST} not running, skipping connectivity"
		return
	fi

	# IPv4 ping to VIP
	if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 2 "$LAN_VIP4" &>/dev/null; then
		pass "LAN host → RETH VIP ${LAN_VIP4} ping"
	else
		fail "LAN host → RETH VIP ${LAN_VIP4} ping"
	fi

	# IPv6 ping to VIP
	if incus exec "$CLUSTER_LAN_HOST" -- ping6 -c 3 -W 2 "$LAN_VIP6" &>/dev/null; then
		pass "LAN host → RETH VIP IPv6 ping"
	else
		fail "LAN host → RETH VIP IPv6 ping"
	fi

	# IPv4 cross-zone
	if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 2 "$WAN_GW4" &>/dev/null; then
		pass "LAN host → WAN gateway cross-zone"
	else
		fail "LAN host → WAN gateway cross-zone"
	fi

	# Internet
	if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 3 1.1.1.1 &>/dev/null; then
		pass "LAN host → internet (1.1.1.1)"
	else
		fail "LAN host → internet (1.1.1.1)"
	fi
}

check_manual_failover() {
	info "Testing manual failover..."
	# Failover RG1 to node1
	incus exec "$FW0" -- bash -c "echo 'request chassis cluster failover redundancy-group 1 node 1' | xpfd cli" &>/dev/null 2>&1 || true
	sleep 3

	# Check VIPs moved to fw1
	local fw1_addrs
	fw1_addrs=$(incus exec "$FW1" -- ip addr show 2>/dev/null)
	if echo "$fw1_addrs" | grep -q "$WAN_VIP4"; then
		pass "Manual failover: VIP moved to fw1"
	else
		fail "Manual failover: VIP not on fw1"
	fi

	# Check connectivity still works
	if incus exec "$CLUSTER_LAN_HOST" -- ping -c 3 -W 2 "$WAN_GW4" &>/dev/null 2>&1; then
		pass "Manual failover: connectivity preserved"
	else
		fail "Manual failover: connectivity lost"
	fi

	# #7770: the FIRST packet of each NEW flow, with the RG split HELD.
	#
	# The leg above cannot see this defect and never could. RG1 has moved to
	# node1 while RG2 (the LAN) stays on node0, which is the LAN/WAN split
	# #7770 is about, and the split is genuinely held here — the reset below is
	# the next statement. But `ping -c 3` is read as a BOOLEAN and `ping` exits
	# 0 if ANY reply arrives, so a probe that loses its first packet and
	# receives the other two is a PASS. The gate entered the state under test
	# and reported the healthy value from inside it.
	#
	# Three SEPARATE single-packet probes are the instrument. Each `ping`
	# invocation picks its own ICMP identifier, so each is a distinct flow and
	# each exercises the first-packet case that #7770 costs; `-c 1` leaves no
	# later packet to mask it, so the exit status is the measurement and there
	# is no output to parse (a parse that matches neither branch is how a gate
	# ends up emitting nothing while summarising "0 failed").
	#
	# Pre-fix this is 3 of 3 lost — measured on the loss userspace cluster as
	# 100% for `ping -c 1` during a held split. It is deliberately NOT tolerant
	# of one loss: one lost first packet IS the defect, and the same probe in
	# every other placement in this script is lossless.
	local newflow_lost=0 i
	for i in 1 2 3; do
		if ! incus exec "$CLUSTER_LAN_HOST" -- ping -c 1 -W 2 "$WAN_GW4" &>/dev/null 2>&1; then
			newflow_lost=$((newflow_lost + 1))
		fi
	done
	if [[ $newflow_lost -eq 0 ]]; then
		pass "Manual failover: first packet of each new flow survives the RG split (#7770)"
	else
		fail "Manual failover: $newflow_lost of 3 new flows lost their FIRST packet across the held RG split (#7770 — the LAN-owning node has no session for a flow the peer adjudicated, so the peer's return hits the wan->lan default deny)"
	fi

	# Reset failover
	incus exec "$FW0" -- bash -c "echo 'request chassis cluster failover reset redundancy-group 1' | xpfd cli" &>/dev/null 2>&1 || true
	sleep 5
}

# ── Mode functions ───────────────────────────────────────────────────

enable_private_rg() {
	info "Enabling private-rg-election (default — removing no-private-rg-election if present)..."
	sed -i '/no-private-rg-election/d' "$CONF"
	privrg_deploy_config
	wait_cluster_ready
	privrg_assert_both_running_modes "$FW0" "$FW1" private
}

disable_private_rg() {
	info "Disabling private-rg-election (adding no-private-rg-election)..."
	if ! grep -q "no-private-rg-election" "$CONF"; then
		sed -i '/heartbeat-threshold/a\        no-private-rg-election;' "$CONF"
	fi
	privrg_deploy_config
	wait_cluster_ready
	privrg_assert_both_running_modes "$FW0" "$FW1" legacy
}

# ── Test sequences ───────────────────────────────────────────────────

test_private_rg_enabled() {
	echo
	info "━━━ Testing with private-rg-election ENABLED ━━━"
	check_no_vrrp_instances
	check_no_vrrp_multicast
	check_vips_present
	check_connectivity
	check_manual_failover
}

test_private_rg_disabled() {
	echo
	info "━━━ Testing with private-rg-election DISABLED (VRRP mode) ━━━"
	check_vrrp_active
	check_vips_present
	check_connectivity
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
	local mode="${1:-full}"

	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  private-rg-election test suite"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

	case "$mode" in
		enable)
			enable_private_rg
			test_private_rg_enabled
			;;
		disable)
			disable_private_rg
			test_private_rg_disabled
			;;
		check)
			local log
			if log=$(privrg_xpfd_journal "$FW0"); then
				if privrg_log_has_vrrp_start "$log"; then
					info "Mode: VRRP (standard)"
				else
					info "Mode: private-rg-election (no VRRP)"
				fi
			else
				fail "Could not read fw0's current xpfd journal"
			fi
			check_vips_present
			check_connectivity
			;;
		full)
			# Full cycle always restores the initial file and running mode.
			privrg_begin_full_cycle
			enable_private_rg
			test_private_rg_enabled
			disable_private_rg
			test_private_rg_disabled
			;;
		*)
			echo "Usage: $0 [full|enable|disable|check]"
			exit 1
			;;
	esac

	echo
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  Results: $PASS passed, $FAIL failed"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

	if [[ $FAIL -gt 0 ]]; then
		echo
		echo "Failures:"
		for err in "${ERRORS[@]}"; do
			echo "  - $err"
		done
		exit 1
	fi
}

main "$@"
