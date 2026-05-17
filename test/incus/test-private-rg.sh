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
#   ./test/incus/test-private-rg.sh              # Full test (enable, test, disable, test)
#   ./test/incus/test-private-rg.sh enable        # Enable private-rg-election and test
#   ./test/incus/test-private-rg.sh disable       # Disable private-rg-election and test
#   ./test/incus/test-private-rg.sh check         # Check current state only

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

CONF="${CLUSTER_CONF:-${PROJECT_ROOT}/docs/ha-cluster.conf}"

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
	info "Checking for VRRP multicast on data interfaces..."
	local count
	count=$(incus exec "$FW0" -- timeout 3 tcpdump -c 1 -i ge-0-0-1 vrrp 2>&1 | grep -c "packet" || echo "0")
	# tcpdump reports "0 packets captured" if no VRRP seen
	if incus exec "$FW0" -- timeout 3 tcpdump -c 1 -i ge-0-0-1 vrrp 2>&1 | grep -q "0 packets captured"; then
		pass "No VRRP multicast on ge-0-0-1 (WAN)"
	else
		fail "VRRP multicast detected on ge-0-0-1 (WAN)"
	fi

	if incus exec "$FW0" -- timeout 3 tcpdump -c 1 -i ge-0-0-0 vrrp 2>&1 | grep -q "0 packets captured"; then
		pass "No VRRP multicast on ge-0-0-0 (LAN)"
	else
		fail "VRRP multicast detected on ge-0-0-0 (LAN)"
	fi
}

check_vrrp_active() {
	info "Checking VRRP instances are running..."
	local log
	log=$(incus exec "$FW0" -- journalctl -u xpfd --no-pager -n 100 2>/dev/null)

	if echo "$log" | grep -q "vrrp: instance starting"; then
		pass "VRRP instances started on fw0"
	else
		fail "No VRRP instances on fw0"
	fi

	if echo "$log" | grep -q "vrrp: state change.*MASTER"; then
		pass "VRRP MASTER state reached on fw0"
	else
		fail "VRRP did not reach MASTER on fw0"
	fi
}

check_no_vrrp_instances() {
	info "Checking VRRP instances are NOT running (private-rg mode)..."
	local log
	log=$(incus exec "$FW0" -- journalctl -u xpfd --no-pager -n 100 2>/dev/null)

	if echo "$log" | grep -q "vrrp: instance starting"; then
		fail "VRRP instances running in private-rg mode"
	else
		pass "No VRRP instances (private-rg mode)"
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

	# Reset failover
	incus exec "$FW0" -- bash -c "echo 'request chassis cluster failover reset redundancy-group 1' | xpfd cli" &>/dev/null 2>&1 || true
	sleep 5
}

# ── Mode functions ───────────────────────────────────────────────────

enable_private_rg() {
	info "Enabling private-rg-election (default — removing no-private-rg-election if present)..."
	sed -i '/no-private-rg-election/d' "$CONF"
	(cd "$PROJECT_ROOT" && make cluster-deploy) 2>&1 | tail -5
	wait_cluster_ready
}

disable_private_rg() {
	info "Disabling private-rg-election (adding no-private-rg-election)..."
	if ! grep -q "no-private-rg-election" "$CONF"; then
		sed -i '/heartbeat-threshold/a\        no-private-rg-election;' "$CONF"
	fi
	(cd "$PROJECT_ROOT" && make cluster-deploy) 2>&1 | tail -5
	wait_cluster_ready
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
			log=$(incus exec "$FW0" -- journalctl -u xpfd --no-pager -n 100 2>/dev/null)
			if echo "$log" | grep -q "vrrp: instance starting"; then
				info "Mode: VRRP (standard)"
			else
				info "Mode: private-rg-election (no VRRP)"
			fi
			check_vips_present
			check_connectivity
			;;
		full)
			# Full cycle: enable → test → disable → test
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
