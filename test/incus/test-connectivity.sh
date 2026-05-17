#!/usr/bin/env bash
# xpf connectivity test suite
#
# Validates end-to-end connectivity for standalone and cluster deployments.
# Handles VRF-aware pinging automatically — interfaces in a VRF use
# "ip vrf exec <vrf> ping" so tests work without manual intervention.
#
# Tests include:
#   - Service health (xpfd active)
#   - Same-subnet ping (fw → hosts)
#   - Cross-zone ping (trust → untrust, IPv4 + IPv6)
#   - mtr path validation (verify traffic traverses firewall)
#   - Internet reachability (cluster only — needs real WAN gateway)
#   - Cluster-specific: heartbeat, fabric, RETH VIP, session sync
#
# Usage:
#   ./test/incus/test-connectivity.sh              # Run all tests
#   ./test/incus/test-connectivity.sh standalone    # Standalone only
#   ./test/incus/test-connectivity.sh cluster       # Cluster only

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

PASS=0
FAIL=0
SKIP=0
ERRORS=()

# ── Helpers ──────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
skip()  { echo "  SKIP  $*"; SKIP=$((SKIP + 1)); }

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

# ping_vrf_aware <instance> <ping_args...>
# Tries ping in default table first, then each VRF until one succeeds.
# Returns 0 on success, 1 on failure.
ping_vrf_aware() {
	local inst="$1"; shift
	# Try default table
	if incus exec "$inst" -- ping "$@" </dev/null &>/dev/null; then
		return 0
	fi
	# Collect VRFs into array (avoid stdin issues with incus exec in loops)
	local vrfs
	vrfs=$(incus exec "$inst" -- ip vrf show 2>/dev/null | awk '/^[a-zA-Z]/ && NR>1{print $1}' || true)
	local vrf
	for vrf in $vrfs; do
		if incus exec "$inst" -- ip vrf exec "$vrf" ping "$@" </dev/null &>/dev/null; then
			return 0
		fi
	done
	return 1
}

# ping_test <instance> <target_ip> <description>
# VRF-aware ping — automatically tries all VRFs if default table fails.
ping_test() {
	local inst="$1" ip="$2" desc="$3"
	if ping_vrf_aware "$inst" -c 2 -W 2 "$ip"; then
		pass "$desc"
	else
		fail "$desc"
	fi
}

# ping6_test <instance> <target_ip> <description>
ping6_test() {
	local inst="$1" ip="$2" desc="$3"
	if ping_vrf_aware "$inst" -6 -c 2 -W 2 "$ip"; then
		pass "$desc"
	else
		fail "$desc"
	fi
}

# service_check <instance> <description>
# Verifies xpfd is running and not in a crash loop.
service_check() {
	local inst="$1" desc="$2"
	if incus exec "$inst" -- systemctl is-active --quiet xpfd 2>/dev/null; then
		pass "$desc"
	else
		fail "$desc"
	fi
}

# mtr_test <instance> <target_ip> <expected_hop_ip> <description>
# Runs mtr and validates: (1) 0% loss at target, (2) expected intermediate hop exists.
# expected_hop_ip can be "" to skip hop validation.
mtr_test() {
	local inst="$1" target="$2" hop="$3" desc="$4"
	local output
	output=$(incus exec "$inst" -- mtr --report --report-cycles 3 -n "$target" 2>&1) || true

	# Check for 0% loss at the final hop (last non-empty line with a host)
	local last_loss
	last_loss=$(echo "$output" | grep -v '???' | grep '|--' | tail -1 | awk '{print $3}' || echo "100.0")
	if [[ "$last_loss" != "0.0%" ]]; then
		fail "$desc (${last_loss} loss at target)"
		return
	fi

	# Validate expected intermediate hop if specified
	if [[ -n "$hop" ]]; then
		if echo "$output" | grep -q "$hop"; then
			pass "$desc (via $hop)"
		else
			fail "$desc (expected hop $hop not in path)"
		fi
	else
		pass "$desc"
	fi
}

# internet_test <instance> <description>
# Pings 1.1.1.1 — tests outbound internet through the firewall.
internet_test() {
	local inst="$1" desc="$2"
	if ping_vrf_aware "$inst" -c 3 -W 3 "1.1.1.1"; then
		pass "$desc"
	else
		fail "$desc"
	fi
}

# ── Standalone Tests ─────────────────────────────────────────────────

test_standalone() {
	info "Standalone firewall (xpf-fw)"

	if ! instance_running "xpf-fw"; then
		skip "xpf-fw not running — skipping standalone tests"
		return
	fi

	# Service health
	service_check "xpf-fw" "standalone: xpfd service active"

	# Direct host reachability (from firewall, auto VRF detection)
	ping_test "xpf-fw" "10.0.1.102"  "standalone: fw → trust-host (10.0.1.102)"
	ping_test "xpf-fw" "10.0.2.102"  "standalone: fw → untrust-host (10.0.2.102)"
	ping_test "xpf-fw" "10.0.30.101" "standalone: fw → dmz-host (10.0.30.101)"

	# Cross-zone: trust → untrust (requires policy permit + SNAT)
	if instance_running "trust-host" && instance_running "untrust-host"; then
		ping_test "trust-host" "10.0.2.102" "standalone: trust-host → untrust-host IPv4"
		ping6_test "trust-host" "2001:559:8585:bf02::102" "standalone: trust-host → untrust-host IPv6"
	else
		skip "standalone: cross-zone tests (trust-host or untrust-host not running)"
	fi

	# Cross-zone: trust → WAN interface IP (proves trust→wan zone policy works)
	if instance_running "trust-host"; then
		ping_test "trust-host" "172.16.50.5" "standalone: trust-host → fw WAN IP (172.16.50.5)"
	fi

	# mtr path validation: verify traffic traverses the firewall
	if instance_running "trust-host" && instance_running "untrust-host"; then
		mtr_test "trust-host" "10.0.2.102" "10.0.1.10" \
			"standalone: mtr trust→untrust (path through fw)"
	fi

	# Internet: standalone test env has no real WAN gateway — skip
	# (cluster tests validate internet connectivity below)
}

# ── Cluster Tests ────────────────────────────────────────────────────

test_cluster() {
	info "Cluster HA (${FW0} + ${FW1})"

	if ! instance_running "$FW0" || ! instance_running "$FW1"; then
		skip "${FW0} or ${FW1} not running — skipping cluster tests"
		return
	fi

	# Service health
	service_check "$FW0" "cluster: xpfd service active on fw0"
	service_check "$FW1" "cluster: xpfd service active on fw1"

	# Heartbeat connectivity (auto VRF — em0/fab0 may be in vrf-mgmt)
	ping_test "$FW0" "10.99.0.2" "cluster: fw0 → fw1 heartbeat (10.99.0.2)"
	ping_test "$FW1" "10.99.0.1" "cluster: fw1 → fw0 heartbeat (10.99.0.1)"

	# Fabric connectivity
	ping_test "$FW0" "10.99.1.2" "cluster: fw0 → fw1 fabric (10.99.1.2)"
	ping_test "$FW1" "10.99.1.1" "cluster: fw1 → fw0 fabric (10.99.1.1)"

	# WAN gateway
	ping_test "$FW0" "$WAN_GW4" "cluster: fw0 → WAN gateway (${WAN_GW4})"

	# LAN host connectivity
	if instance_running "$CLUSTER_LAN_HOST"; then
		# From firewall to LAN host
		ping_test "$FW0" "$LAN_HOST_IP" "cluster: fw0 → LAN host (${LAN_HOST_IP})"

		# From LAN host to RETH VIP (proves VRRP is working)
		ping_test "$CLUSTER_LAN_HOST" "$LAN_VIP4" "cluster: LAN host → RETH VIP (${LAN_VIP4})"

		# Cross-zone: LAN host through firewall to WAN gateway
		ping_test "$CLUSTER_LAN_HOST" "$WAN_GW4" "cluster: LAN host → WAN gateway cross-zone (${WAN_GW4})"

		# IPv6 LAN connectivity
		ping6_test "$CLUSTER_LAN_HOST" "$LAN_VIP6" "cluster: LAN host → RETH VIP IPv6"

		# Internet: LAN host → 1.1.1.1 (proves SNAT + routing through fw to internet)
		internet_test "$CLUSTER_LAN_HOST" "cluster: LAN host → internet (1.1.1.1)"

		# Internet IPv6: LAN host → Google DNS IPv6 (proves IPv6 routing through fw)
		ping6_test "$CLUSTER_LAN_HOST" "2607:f8b0:4005:80e::200e" \
			"cluster: LAN host → internet IPv6 (2607:f8b0:4005:80e::200e)"

		# IPv6 TCP: iperf3 from LAN host to WAN (proves SNAT v6 + return path)
		if incus exec "$CLUSTER_LAN_HOST" -- which iperf3 &>/dev/null 2>&1; then
			if incus exec "$CLUSTER_LAN_HOST" -- timeout 8 iperf3 -6 -c "$IPERF_TARGET6" -t 3 &>/dev/null 2>&1; then
				pass "cluster: LAN host → WAN iperf3 IPv6 TCP"
			else
				fail "cluster: LAN host → WAN iperf3 IPv6 TCP (SNAT v6 may be missing)"
			fi
		else
			skip "cluster: IPv6 TCP test (iperf3 not installed on cluster-lan-host)"
		fi

		# IPv4 TCP: iperf3 from LAN host to WAN
		if incus exec "$CLUSTER_LAN_HOST" -- which iperf3 &>/dev/null 2>&1; then
			if incus exec "$CLUSTER_LAN_HOST" -- timeout 8 iperf3 -c "$IPERF_TARGET4" -t 3 &>/dev/null 2>&1; then
				pass "cluster: LAN host → WAN iperf3 IPv4 TCP"
			else
				fail "cluster: LAN host → WAN iperf3 IPv4 TCP"
			fi
		else
			skip "cluster: IPv4 TCP test (iperf3 not installed on cluster-lan-host)"
		fi

		# mtr path validation: verify traffic traverses RETH VIP to WAN gateway
		mtr_test "$CLUSTER_LAN_HOST" "$WAN_GW4" "$LAN_VIP4" \
			"cluster: mtr LAN→WAN gateway (path through RETH VIP)"

		# mtr to internet: verify full path (RETH VIP → WAN gateway → internet)
		mtr_test "$CLUSTER_LAN_HOST" "1.1.1.1" "$LAN_VIP4" \
			"cluster: mtr LAN→internet (path through RETH VIP)"

		# mtr to internet IPv6: verify full IPv6 path through RETH VIP
		mtr_test "$CLUSTER_LAN_HOST" "2607:f8b0:4005:80e::200e" "$LAN_VIP6" \
			"cluster: mtr LAN→internet IPv6 (path through RETH VIP)"
	else
		skip "cluster: LAN host tests (${CLUSTER_LAN_HOST} not running)"
	fi

	# Internet from firewall directly
	internet_test "$FW0" "cluster: fw0 → internet (1.1.1.1)"
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
	local mode="${1:-all}"

	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  xpf connectivity test suite"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo

	case "$mode" in
		standalone) test_standalone ;;
		cluster)    test_cluster ;;
		all)        test_standalone; echo; test_cluster ;;
		*)          echo "Usage: $0 [standalone|cluster|all]"; exit 1 ;;
	esac

	echo
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
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
