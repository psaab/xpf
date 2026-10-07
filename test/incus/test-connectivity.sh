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
# shellcheck source=test/incus/cluster-lock.sh
source "${SCRIPT_DIR}/cluster-lock.sh"
# shellcheck source=test/incus/ha-assurance-lib.sh
source "${SCRIPT_DIR}/ha-assurance-lib.sh"

PASS=0
FAIL=0
SKIP=0
VOID=0
ERRORS=()

# ── Helpers ──────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
skip()  { echo "  SKIP  $*"; SKIP=$((SKIP + 1)); }
void()  { echo "  VOID  $*"; VOID=$((VOID + 1)); }
assurance_verdict() {
	local status="$1" description="$2"
	case "$status" in
	0) pass "$description" ;;
	1) fail "$description" ;;
	2) void "$description" ;;
	*) void "$description (unrecognized helper status=${status})" ;;
	esac
}
# #11581 M3.1/M3.2 precedence contract (documentation only; no probe behavior change).
#
# Ordinary capture VOID means a specific cell's evidence is blind: missing,
# failed, malformed, incomplete, or wrong-identity evidence, including a
# metrics-gate rejection. It does not contaminate other measurements.
# Global invalidation means the F-158 END probe attests that a destructive
# lane held the shared-cluster lock at an endpoint or changed the owner/epoch
# witness during the sampling window: the window's uncontended precondition
# failed, so every cluster sample is suspect.
# These causes are disjoint: ordinary VOID blinds this evidence; global
# invalidation makes all evidence from the cluster window suspect.
#
# Precedence rule 1: measured FAIL is sticky over ordinary VOID in either
# order. Later blind evidence must not erase a measured failure.
# Precedence rule 2: F-158 END invalidation aborts without a summary, making the
# whole invocation VOID even after measured cluster FAILs. F-158 START refusal
# occurs before cluster samples; in MODE=all its exit 77 suppresses the common
# summary, so prior standalone FAIL detail is also recorded as invocation VOID.
# These are the two specified F-158 no-summary run-abort exceptions; ordinary
# VOID after FAIL still retains the summary and FAIL verdict.
# Precedence rule 3: neither global invalidation nor ordinary blind evidence
# may produce PASS.
# Precedence rule 4: retain earlier cell details in the transcript; exit 77,
# no summary, and the probe's VOID cause line provide the existing evidence.
#
# #11581 N4: the §11 registry summary must cite invalidation cases (b)/(c)/(d).
# Keep this contract next to the real probe so prose and behavior stay aligned.

# xpf_assert_cluster_lock_idle <phase> — #9922 F-158 lock-IDLENESS probe.
#
# Tree policy forbids read-only gates from HOLDING the shared-cluster lock
# (selftest-enforced: this script must never route through the destructive
# lock cell), so instead of taking the lock we assert it is IDLE at the
# START and END of the shared-cluster sampling window. Contention means a
# destructive lane is mutating the nodes under us and every sample is
# suspect → reason + exit 77 (no summary → the harness wrapper records
# VOID and the results are discarded).
#
# #10126 closes the F-158 whole-window hole for the canonical
# with-cluster.sh holders. START records both the visible owner identity
# and the persistent owner-epoch sidecar BEFORE its non-blocking flock
# check. END performs the flock check first, then reads owner identity
# followed by the epoch (the final observation) and compares both.
# A with-cluster cell that acquired and released entirely between the
# probes therefore leaves the lock idle at END but changes the epoch and
# is voided. The epoch is primary; raw per-command flock holders do not
# publish an epoch and remain covered only when they overlap an endpoint.
# Blocking flock is deliberately not used: read-only gates must not hold
# the shared-cluster lock.
#
# The probe fires only when FW0 is remote-qualified (contains ':'):
# 'loss:xpf-userspace-fw0' samples the SHARED cluster, while a bare
# 'xpf-fw0' (BPFRX_CLUSTER_ENV= local defaults) is a dedicated local
# instance no other lane touches. Inside a held cell (valid
# XPF_CLUSTER_LOCK_HELD marker from a live ancestor holder) the probe is
# skipped — the cell already owns the cluster, and probing our own
# ancestor's lock would self-report contention (wg-interop.sh inc()
# precedent: skip the flock when xpf_cluster_lock_held).
XPF_CLUSTER_LOCK_IDLE_START_EPOCH=""
XPF_CLUSTER_LOCK_IDLE_START_OWNER=""
XPF_CLUSTER_LOCK_IDLE_START_SET=0
xpf_assert_cluster_lock_idle() {
	local phase="$1"
	local epoch owner
	[[ "$FW0" == *:* ]] || return 0
	if xpf_cluster_lock_held; then
		return 0
	fi
	case "$phase" in
	start)
		# Read before flock: an acquire+release after this snapshot but
		# before the endpoint is caught by the changed epoch even if the
		# lock is idle again by the time flock runs. A present but
		# unreadable witness is fail-closed, never an empty snapshot.
		if ! epoch="$(xpf_cluster_epoch_read)"; then
			echo "VOID: shared-cluster epoch ${XPF_CLUSTER_EPOCH} is unreadable at connectivity START — samples are discarded (no summary)" >&2
			exit 77
		fi
		owner="$(xpf_cluster_owner_identity)"
		if [[ -e "$XPF_CLUSTER_LOCK" ]] \
			&& ! ( flock -n 9 || exit 1 ) 9<"$XPF_CLUSTER_LOCK"; then
			echo "VOID: shared-cluster lock ${XPF_CLUSTER_LOCK} is held by another lane at connectivity ${phase} probe — samples taken under contention are discarded (no summary)" >&2
			exit 77
		fi
		XPF_CLUSTER_LOCK_IDLE_START_EPOCH="$epoch"
		XPF_CLUSTER_LOCK_IDLE_START_OWNER="$owner"
		XPF_CLUSTER_LOCK_IDLE_START_SET=1
		;;
	end)
		# Check the endpoint first: an active holder is the original
		# F-158 edge case, and must be voided before reading metadata.
		if [[ -e "$XPF_CLUSTER_LOCK" ]] \
			&& ! ( flock -n 9 || exit 1 ) 9<"$XPF_CLUSTER_LOCK"; then
			echo "VOID: shared-cluster lock ${XPF_CLUSTER_LOCK} is held by another lane at connectivity ${phase} probe — samples taken under contention are discarded (no summary)" >&2
			exit 77
		fi
		[[ "$XPF_CLUSTER_LOCK_IDLE_START_SET" -eq 1 ]] || {
			echo "VOID: connectivity END lock-idleness probe has no START owner-epoch snapshot — samples are discarded (no summary)" >&2
			exit 77
		}
		owner="$(xpf_cluster_owner_identity)"
		if ! epoch="$(xpf_cluster_epoch_read)"; then
			echo "VOID: shared-cluster epoch ${XPF_CLUSTER_EPOCH} is unreadable at connectivity END — samples are discarded (no summary)" >&2
			exit 77
		fi
		if [[ "$epoch" != "$XPF_CLUSTER_LOCK_IDLE_START_EPOCH" \
			|| "$owner" != "$XPF_CLUSTER_LOCK_IDLE_START_OWNER" ]]; then
			echo "VOID: shared-cluster lock owner epoch/identity changed during connectivity sampling window — samples taken across lock contention are discarded (no summary)" >&2
			exit 77
		fi
		;;
	*)
		echo "invalid lock-idleness probe phase: ${phase}" >&2
		return 2
		;;
	esac
}

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
	# F-158 START probe (guarded 77): the running-check above passed, so the
	# cluster is up and an exit 77 here means contention, not absence.
	xpf_assert_cluster_lock_idle "start"
	# #11581 N9: all new Group 10/11/12 cells go between the START probe above and the END probe below — never after END.

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
			skip "cluster: IPv6 TCP test (iperf3 not installed on ${CLUSTER_LAN_HOST})"
		fi

		# IPv4 TCP: iperf3 from LAN host to WAN
		if incus exec "$CLUSTER_LAN_HOST" -- which iperf3 &>/dev/null 2>&1; then
			if incus exec "$CLUSTER_LAN_HOST" -- timeout 8 iperf3 -c "$IPERF_TARGET4" -t 3 &>/dev/null 2>&1; then
				pass "cluster: LAN host → WAN iperf3 IPv4 TCP"
			else
				fail "cluster: LAN host → WAN iperf3 IPv4 TCP"
			fi
		else
			skip "cluster: IPv4 TCP test (iperf3 not installed on ${CLUSTER_LAN_HOST})"
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

		# #11581 Group 10: legacy TTL=1 probes require router-generated
		# time-exceeded evidence, not merely a successful ping exit status.
		local ttl4_output ttl4_rc ttl4_status ttl4_evidence
		if ttl4_output=$(incus exec "$CLUSTER_LAN_HOST" -- sh -c \
			'LC_ALL=C ping -c 1 -W 2 -t 1 1.1.1.1' 2>&1); then
			ttl4_rc=0
		else
			ttl4_rc=$?
		fi
		ttl4_evidence=${ttl4_output//$'\n'/'; '}
		if ha_ttl_output_verdict "$ttl4_rc" "$ttl4_output"; then
			ttl4_status=0
		else
			ttl4_status=$?
		fi
		assurance_verdict "$ttl4_status" \
			"cluster: Group10 IPv4 TTL=1 (LC_ALL=C ping -c 1 -W 2 -t 1 1.1.1.1; rc=${ttl4_rc}; output=${ttl4_evidence:-<empty>})"

		local ttl6_output ttl6_rc ttl6_status ttl6_evidence
		if ttl6_output=$(incus exec "$CLUSTER_LAN_HOST" -- sh -c \
			'LC_ALL=C ping -6 -c 1 -W 2 -t 1 2607:f8b0:4005:814::200e' 2>&1); then
			ttl6_rc=0
		else
			ttl6_rc=$?
		fi
		ttl6_evidence=${ttl6_output//$'\n'/'; '}
		if ha_ttl_output_verdict "$ttl6_rc" "$ttl6_output"; then
			ttl6_status=0
		else
			ttl6_status=$?
		fi
		assurance_verdict "$ttl6_status" \
			"cluster: Group10 IPv6 TTL=1 (LC_ALL=C ping -6 -c 1 -W 2 -t 1 2607:f8b0:4005:814::200e; rc=${ttl6_rc}; output=${ttl6_evidence:-<empty>})"

		# #11581 Group 11: reuse the shared MTR classifier. IPv6 unresolved
		# destination/no-hop results are warnings, not reachability proof.
		local mtr4_report mtr4_result mtr4_rc
		mtr4_report=$(incus exec "$CLUSTER_LAN_HOST" -- sh -c \
			'LC_ALL=C mtr 1.1.1.1 --report --report-cycles=1' 2>&1) || true
		if mtr4_result=$(python3 "${SCRIPT_DIR}/../../scripts/mtr_report_check.py" \
			"cluster IPv4 public path" "$mtr4_report" 0 2>&1); then
			pass "cluster: Group11 IPv4 MTR (LC_ALL=C mtr 1.1.1.1 --report --report-cycles=1): ${mtr4_result}"
		else
			mtr4_rc=$?
			if (( mtr4_rc == 1 )); then
				fail "cluster: Group11 IPv4 MTR (LC_ALL=C mtr 1.1.1.1 --report --report-cycles=1): ${mtr4_result}"
			else
				void "cluster: Group11 IPv4 MTR classifier unavailable (status=${mtr4_rc}): ${mtr4_result}"
			fi
		fi

		local mtr6_report mtr6_result mtr6_rc
		mtr6_report=$(incus exec "$CLUSTER_LAN_HOST" -- sh -c \
			'LC_ALL=C mtr -6 2607:f8b0:4005:814::200e --report --report-cycles=1' 2>&1) || true
		if mtr6_result=$(python3 "${SCRIPT_DIR}/../../scripts/mtr_report_check.py" \
			"cluster IPv6 public path" "$mtr6_report" 1 2>&1); then
			pass "cluster: Group11 IPv6 MTR (LC_ALL=C mtr -6 2607:f8b0:4005:814::200e --report --report-cycles=1): ${mtr6_result}"
		else
			mtr6_rc=$?
			if (( mtr6_rc == 1 )); then
				fail "cluster: Group11 IPv6 MTR (LC_ALL=C mtr -6 2607:f8b0:4005:814::200e --report --report-cycles=1): ${mtr6_result}"
			else
				void "cluster: Group11 IPv6 MTR classifier unavailable (status=${mtr6_rc}): ${mtr6_result}"
			fi
		fi

		# #11581 Group 12: route evidence precedes the controlled reachability
		# pings; the same route devices scope the read-only neighbor queries.
		local route4_output route4_rc route4_status route4_device route4_evidence
		if route4_output=$(incus exec "$CLUSTER_LAN_HOST" -- \
			ip route get 172.16.80.200 2>&1); then
			route4_rc=0
		else
			route4_rc=$?
		fi
		route4_evidence=${route4_output//$'\n'/'; '}
		if ha_route_lookup_verdict "$route4_rc" "$route4_output"; then
			route4_status=0
		else
			route4_status=$?
		fi
		assurance_verdict "$route4_status" \
			"cluster: Group12 IPv4 route (ip route get 172.16.80.200; rc=${route4_rc}; output=${route4_evidence:-<empty>})"
		route4_device=""
		if (( route4_status == 0 )); then
			route4_device=$(ha_route_device "$route4_output") || route4_device=""
		fi

		local route6_output route6_rc route6_status route6_device route6_evidence
		if route6_output=$(incus exec "$CLUSTER_LAN_HOST" -- \
			ip -6 route get 2001:559:8585:80::200 2>&1); then
			route6_rc=0
		else
			route6_rc=$?
		fi
		route6_evidence=${route6_output//$'\n'/'; '}
		if ha_route_lookup_verdict "$route6_rc" "$route6_output"; then
			route6_status=0
		else
			route6_status=$?
		fi
		assurance_verdict "$route6_status" \
			"cluster: Group12 IPv6 route (ip -6 route get 2001:559:8585:80::200; rc=${route6_rc}; output=${route6_evidence:-<empty>})"
		route6_device=""
		if (( route6_status == 0 )); then
			route6_device=$(ha_route_device "$route6_output") || route6_device=""
		fi

		local reach4_output reach4_rc reach4_status reach4_evidence
		if reach4_output=$(incus exec "$CLUSTER_LAN_HOST" -- sh -c \
			'LC_ALL=C ping -c 2 -W 1 172.16.80.200' 2>&1); then
			reach4_rc=0
		else
			reach4_rc=$?
		fi
		reach4_evidence=${reach4_output//$'\n'/'; '}
		if ha_ping_reply_verdict "$reach4_rc" "$reach4_output"; then
			reach4_status=0
		else
			reach4_status=$?
		fi
		assurance_verdict "$reach4_status" \
			"cluster: Group12 IPv4 controlled reachability (LC_ALL=C ping -c 2 -W 1 172.16.80.200; rc=${reach4_rc}; output=${reach4_evidence:-<empty>})"

		local reach6_output reach6_rc reach6_status reach6_evidence
		if reach6_output=$(incus exec "$CLUSTER_LAN_HOST" -- sh -c \
			'LC_ALL=C ping -6 -c 2 -W 1 2001:559:8585:80::200' 2>&1); then
			reach6_rc=0
		else
			reach6_rc=$?
		fi
		reach6_evidence=${reach6_output//$'\n'/'; '}
		if ha_ping_reply_verdict "$reach6_rc" "$reach6_output"; then
			reach6_status=0
		else
			reach6_status=$?
		fi
		assurance_verdict "$reach6_status" \
			"cluster: Group12 IPv6 controlled reachability (LC_ALL=C ping -6 -c 2 -W 1 2001:559:8585:80::200; rc=${reach6_rc}; output=${reach6_evidence:-<empty>})"

		local neigh4_output="" neigh4_rc=not_run neigh4_input=""
		if [[ -n "$route4_device" ]]; then
			if neigh4_output=$(incus exec "$CLUSTER_LAN_HOST" -- \
				ip neigh show 172.16.80.200 dev "$route4_device" 2>&1); then
				neigh4_rc=0
				neigh4_input="$neigh4_output"
			else
				neigh4_rc=$?
			fi
		fi
		local neigh6_output="" neigh6_rc=not_run neigh6_input=""
		if [[ -n "$route6_device" ]]; then
			if neigh6_output=$(incus exec "$CLUSTER_LAN_HOST" -- \
				ip -6 neigh show 2001:559:8585:80::200 dev "$route6_device" 2>&1); then
				neigh6_rc=0
				neigh6_input="$neigh6_output"
			else
				neigh6_rc=$?
			fi
		fi
		local neighbor_status neigh4_status neigh6_status neigh4_evidence neigh6_evidence
		neigh4_evidence=${neigh4_output//$'\n'/'; '}
		neigh6_evidence=${neigh6_output//$'\n'/'; '}
		if [[ "$neigh4_rc" != 0 || "$neigh6_rc" != 0 ]] \
			|| [[ -z "${neigh4_input//[[:space:]]/}" || -z "${neigh6_input//[[:space:]]/}" ]]; then
			neighbor_status=2
		else
			if ha_neighbor_identity_verdict "$route4_device" "$neigh4_input" \
				"$route4_device" "$neigh4_input"; then
				neigh4_status=0
			else
				neigh4_status=$?
			fi
			if ha_neighbor_identity_verdict "$route6_device" "$neigh6_input" \
				"$route6_device" "$neigh6_input"; then
				neigh6_status=0
			else
				neigh6_status=$?
			fi
			if (( neigh4_status == 1 || neigh6_status == 1 )); then
				neighbor_status=1
			elif (( neigh4_status == 2 || neigh6_status == 2 )); then
				neighbor_status=2
			elif ha_neighbor_identity_verdict "$route4_device" "$neigh4_input" \
				"$route6_device" "$neigh6_input"; then
				neighbor_status=0
			else
				neighbor_status=$?
			fi
		fi
		assurance_verdict "$neighbor_status" \
			"cluster: Group12 read-only neighbor identity (v4 ip neigh show 172.16.80.200 dev ${route4_device:-<no-route-device>} rc=${neigh4_rc} output=${neigh4_evidence:-<empty>}; v6 ip -6 neigh show 2001:559:8585:80::200 dev ${route6_device:-<no-route-device>} rc=${neigh6_rc} output=${neigh6_evidence:-<empty>})"
	else
		skip "cluster: LAN host tests (${CLUSTER_LAN_HOST} not running)"
		void "cluster: Group10 IPv4 TTL=1 (LAN host ${CLUSTER_LAN_HOST} unavailable)"
		void "cluster: Group10 IPv6 TTL=1 (LAN host ${CLUSTER_LAN_HOST} unavailable)"
		void "cluster: Group11 IPv4 MTR (LAN host ${CLUSTER_LAN_HOST} unavailable)"
		void "cluster: Group11 IPv6 MTR (LAN host ${CLUSTER_LAN_HOST} unavailable)"
		void "cluster: Group12 IPv4 route/ping/neighbor evidence (LAN host ${CLUSTER_LAN_HOST} unavailable)"
		void "cluster: Group12 IPv6 route/ping/neighbor evidence (LAN host ${CLUSTER_LAN_HOST} unavailable)"
	fi

	# Internet from firewall directly
	internet_test "$FW0" "cluster: fw0 → internet (1.1.1.1)"

	# F-158 END probe: a lane that grabbed the lock mid-window leaves the
	# samples above suspect (see the TOCTOU note on the probe helper).
	xpf_assert_cluster_lock_idle "end"
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

	# Keep the summary; the smoke-cells adapter maps zero failures plus nonzero rc to VOID.
	if (( VOID > 0 )); then
		return 2
	fi
}

main "$@"
