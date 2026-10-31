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
# iperf_target_claim_cell: #18576 measurement-target uniqueness preflight.
# Probes from the OFF-FIREWALL target container (MOUSE_TARGET_REF), so the
# holders' replies never reach a firewall node, and reads (only) both nodes'
# neighbor entries before and after; WAN_GW80_4 (the cluster's own address on
# the VLAN) answering is the positive control. The documented dual holder set
# (IPERF_TARGET4_KNOWN_HOLDERS, loss env) is SKIPped as excused only while the
# RG owner resolves the target to the container before and after; otherwise
# it is VOID (the run's v4 numbers are not certifiable). Any other set FAILs,
# an xpf RETH holder included.
iperf_target_claim_cell() {
	ha_target_claim_check "$MOUSE_TARGET_REF" "$IPERF_TARGET4" "$WAN_GW80_4" \
		"${IPERF_TARGET4_KNOWN_HOLDERS:-}" "$FW0" "$FW1"
	# 3 = an xpf RETH MAC answers for the target: a product defect, FAIL.
	# 4 = the known environment duplicate, excused only while the RG owner
	# resolves the target to the intended holder: SKIP, which leaves the exit
	# status alone and is counted in the ledger's cells_skipped.
	local status="$HA_TARGET_CLAIM_STATUS"
	local desc="cluster: iperf target ${IPERF_TARGET4} answered for by exactly one host (RFC 5227 ARP probe from ${MOUSE_TARGET_REF})"
	if [[ "$status" == 4 ]]; then
		skip "${desc}: ${HA_TARGET_CLAIM_REASON}"
		return 0
	fi
	[[ "$status" == 3 ]] && status=1
	assurance_verdict "$status" "${desc}: ${HA_TARGET_CLAIM_REASON}"
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

# wan_claim_cell: #18558 duplicate-WAN-address preflight (ha_wan_claim_check).
wan_claim_cell() {
	local desc="cluster: WAN IPv4 ${WAN_VIP4} answered for only by this cluster (RFC 5227 ARP probe)"
	ha_wan_claim_check "${CLUSTER_CONF:-}" "$WAN_VIP4" "$WAN_GW4" "$FW0" "$FW1"
	# 1 = non-xpf duplicate (lab), 3 = another xpf cluster claims it (an xpf
	# defect, e.g. a stale VIP, #18573): both FAIL, the reason says which.
	case "$HA_WAN_CLAIM_STATUS" in
	0) pass "$desc" ;;
	1 | 3) fail "$desc: ${HA_WAN_CLAIM_REASON}" ;;
	*) void "$desc: ${HA_WAN_CLAIM_REASON}" ;;
	esac
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

# check_mtr_reth_vip <mtr-output> <target_ip> <reth_vip>
# Validate a cluster MTR path through the RETH (#18174):
#   1. hop 1 is the RETH's LAN VIP — the firewall's own TTL/hop-limit-expired
#      error is sourced from the LAN address the host routes through. Before
#      #18174 the IPv4 error left from the RETH's per-node 169.254.<rg>.<n>
#      address (a shared-ifindex merge defect in the helper) and #18343/#18360
#      bent this check to accept 169.254/16 and fe80::/10; it no longer does.
#   2. when the target is more than one hop beyond the firewall, hop 2 — the
#      first router past it — must be RESOLVED. Its Time Exceeded comes back
#      addressed to the SNAT address quoting the translated probe; a `???`
#      there means the firewall dropped the RELATED error instead of
#      un-NATing it to the host (the #18174 blackhole, where every hop past
#      the firewall read `???` while the target still answered).
#   3. the destination itself is the final row, beyond hop 1, at 0% loss — a
#      responding first hop with an unresolved target must not pass.
check_mtr_reth_vip() {
	local output="$1" target="$2" vip="$3" line hop_field hop host loss first_hop=""
	local second_hop="" last_hop=0 target_hop=0 target_loss=""
	while IFS= read -r line; do
		[[ "$line" == *'|--'* ]] || continue
		read -r hop_field host loss _ <<<"$line"
		hop="${hop_field%%.*}"
		[[ "$hop" =~ ^[0-9]+$ ]] || continue
		(( hop > last_hop )) && last_hop=$hop
		if (( hop == 1 )); then
			first_hop="$host"
		elif (( hop == 2 )); then
			second_hop="$host"
		fi
		if [[ "$host" == "$target" ]]; then
			target_hop=$hop
			target_loss=$loss
		fi
	done <<<"$output"

	if [[ -z "$vip" || "$first_hop" != "$vip" ]]; then
		echo "first hop '${first_hop:-<missing>}' is not the RETH VIP ${vip:-<unset>}"
		return 1
	fi
	if (( target_hop == 0 || target_hop != last_hop || target_hop <= 1 )); then
		echo "destination ${target} is not the final hop beyond the RETH (final hop ${last_hop})"
		return 1
	fi
	if [[ "$target_loss" != "0.0%" ]]; then
		echo "${target_loss:-unknown} loss at target ${target}"
		return 1
	fi
	if (( target_hop > 2 )) && [[ -z "$second_hop" || "$second_hop" == '???' ]]; then
		echo "hop 2 '${second_hop:-<missing>}' beyond the RETH is unresolved (Time Exceeded not returned through the firewall)"
		return 1
	fi
	echo "via RETH VIP ${first_hop}, hop 2 ${second_hop:-<target>}, destination ${target} 0.0% loss"
}

# mtr_test <instance> <target_ip> <expected_hop_ip|reth:VIP> <description>
# Runs mtr and validates 0% loss at the target. Cluster paths pass
# `reth:<LAN VIP>` and are judged by check_mtr_reth_vip; the standalone path
# retains its literal firewall-hop check.
mtr_test() {
	local inst="$1" target="$2" hop="$3" desc="$4"
	local output last_loss verdict
	output=$(incus exec "$inst" -- mtr --report --report-cycles 3 -n "$target" 2>&1) || true

	if [[ "$hop" == reth:* ]]; then
		if verdict=$(check_mtr_reth_vip "$output" "$target" "${hop#reth:}"); then
			pass "$desc (${verdict})"
		else
			fail "$desc (${verdict})"
		fi
		return
	fi

	# Preserve the existing checker for the standalone path.
	last_loss=$(echo "$output" | grep -v '???' | grep '|--' | tail -1 | awk '{print $3}' || echo "100.0")
	if [[ "$last_loss" != "0.0%" ]]; then
		fail "$desc (${last_loss} loss at target)"
		return
	fi
	if echo "$output" | grep -q "$hop"; then
		pass "$desc (via $hop)"
	else
		fail "$desc (expected hop $hop not in path)"
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
	# #18174: the public IPv6 destination for the cluster internet cells. The
	# previous targets, 2607:f8b0:4005:80e::200e (ping6 cell) and
	# 2607:f8b0:4005:814::200e (Group10 TTL=1, Group11 MTR), no longer answer
	# echo at all: measured 0/3 from both the loss and the tcp LAN host on
	# 2026-10-30 while 2001:4860:4860::8888 answered 3/3. A dead destination made
	# the ping6 cell red on every smoke-watch line and could never be the final
	# row of an MTR. Google Public DNS is anycast and stable.
	local internet_target6="2001:4860:4860::8888"

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

	# Heartbeat/fabric peer addresses come from the cluster conf:
	# each `groups { nodeN { ... } }` block's peer-address is the
	# OTHER node's heartbeat IP. Selecting by group name (not by
	# occurrence order) keeps this right if blocks are reordered.
	# Hardcoding them breaks whenever a cluster renumbers (loss
	# userspace uses 10.99.12/13, legacy used 10.99.0/1).
	CLUSTER_CONF="${CLUSTER_CONF:-${PROJECT_ROOT}/docs/ha-cluster.conf}"
	peer_of() { # $1=group $2=key
		awk -v g="$1" -v k="$2" '
			$1=="groups" {ing=1; next}
			ing && $1==g {$2=="{" && (ins=1); next}
			ing && ins && $1==k {print $2; exit}' "$CLUSTER_CONF" | tr -d ';'
	}
	HB_FW1=$(peer_of node0 peer-address)
	HB_FW0=$(peer_of node1 peer-address)
	FAB_FW1=$(peer_of node0 fabric-peer-address)
	FAB_FW0=$(peer_of node1 fabric-peer-address)
	# Heartbeat connectivity (auto VRF — em0/fab0 may be in vrf-mgmt)
	ping_test "$FW0" "$HB_FW1" "cluster: fw0 → fw1 heartbeat (${HB_FW1})"
	ping_test "$FW1" "$HB_FW0" "cluster: fw1 → fw0 heartbeat (${HB_FW0})"

	# Fabric connectivity
	ping_test "$FW0" "$FAB_FW1" "cluster: fw0 → fw1 fabric (${FAB_FW1})"
	ping_test "$FW1" "$FAB_FW0" "cluster: fw1 → fw0 fabric (${FAB_FW0})"

	# WAN gateway
	ping_test "$FW0" "$WAN_GW4" "cluster: fw0 → WAN gateway (${WAN_GW4})"

	# #18558: the WAN IPv4 address must be answered for by this cluster alone.
	# VLAN 50 is a shared lab segment; tcp's .10 and udp's .11 were also held by
	# non-xpf devices, the gateway's ARP entry flipped between the two holders,
	# and every IPv4 cell below lost 20-80% while IPv6 stayed clean. FAIL names
	# the foreign MAC; VOID means the probe heard nothing, not even the gateway.
	wan_claim_cell

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
		ping6_test "$CLUSTER_LAN_HOST" "$internet_target6" \
			"cluster: LAN host → internet IPv6 (${internet_target6})"

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

		# MTR path validation (#18174): hop 1 is the RETH LAN VIP, the first
		# router beyond the firewall answers (its Time Exceeded is un-NATed
		# back to the host), and the target is the final 0%-loss hop.
		mtr_test "$CLUSTER_LAN_HOST" "$WAN_GW4" "reth:${LAN_VIP4}" \
			"cluster: mtr LAN→WAN gateway (via RETH VIP ${LAN_VIP4})"

		mtr_test "$CLUSTER_LAN_HOST" "1.1.1.1" "reth:${LAN_VIP4}" \
			"cluster: mtr LAN→internet IPv4 (via RETH VIP ${LAN_VIP4})"

		# #18174: a live destination (internet_target6, at the top of
		# test_cluster) so the destination can be the MTR's final row.
		mtr_test "$CLUSTER_LAN_HOST" "$internet_target6" "reth:${LAN_VIP6}" \
			"cluster: mtr LAN→internet IPv6 (via RETH VIP ${LAN_VIP6})"

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
			"LC_ALL=C ping -6 -c 1 -W 2 -t 1 ${internet_target6}" 2>&1); then
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
			"cluster: Group10 IPv6 TTL=1 (LC_ALL=C ping -6 -c 1 -W 2 -t 1 ${internet_target6}; rc=${ttl6_rc}; output=${ttl6_evidence:-<empty>})"

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
			"LC_ALL=C mtr -6 ${internet_target6} --report --report-cycles=1" 2>&1) || true
		if mtr6_result=$(python3 "${SCRIPT_DIR}/../../scripts/mtr_report_check.py" \
			"cluster IPv6 public path" "$mtr6_report" 1 2>&1); then
			pass "cluster: Group11 IPv6 MTR (LC_ALL=C mtr -6 ${internet_target6} --report --report-cycles=1): ${mtr6_result}"
		else
			mtr6_rc=$?
			if (( mtr6_rc == 1 )); then
				fail "cluster: Group11 IPv6 MTR (LC_ALL=C mtr -6 ${internet_target6} --report --report-cycles=1): ${mtr6_result}"
			else
				void "cluster: Group11 IPv6 MTR classifier unavailable (status=${mtr6_rc}): ${mtr6_result}"
			fi
		fi

		# #11581 Group 12: route evidence precedes the controlled reachability
		# pings; the same route devices scope the read-only neighbor queries.
		local route4_output route4_rc route4_status route4_device route4_evidence
		if route4_output=$(incus exec "$CLUSTER_LAN_HOST" -- \
			ip route get "$IPERF_TARGET4" 2>&1); then
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
			"cluster: Group12 IPv4 route (ip route get ${IPERF_TARGET4}; rc=${route4_rc}; output=${route4_evidence:-<empty>})"
		route4_device=""
		if (( route4_status == 0 )); then
			route4_device=$(ha_route_device "$route4_output") || route4_device=""
		fi

		local route6_output route6_rc route6_status route6_device route6_evidence
		if route6_output=$(incus exec "$CLUSTER_LAN_HOST" -- \
			ip -6 route get "$IPERF_TARGET6" 2>&1); then
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
			"cluster: Group12 IPv6 route (ip -6 route get ${IPERF_TARGET6}; rc=${route6_rc}; output=${route6_evidence:-<empty>})"
		route6_device=""
		if (( route6_status == 0 )); then
			route6_device=$(ha_route_device "$route6_output") || route6_device=""
		fi

		local reach4_output reach4_rc reach4_status reach4_evidence
		if reach4_output=$(incus exec "$CLUSTER_LAN_HOST" -- sh -c \
			"LC_ALL=C ping -c 2 -W 1 $IPERF_TARGET4" 2>&1); then
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
			"cluster: Group12 IPv4 controlled reachability (LC_ALL=C ping -c 2 -W 1 ${IPERF_TARGET4}; rc=${reach4_rc}; output=${reach4_evidence:-<empty>})"

		local reach6_output reach6_rc reach6_status reach6_evidence
		if reach6_output=$(incus exec "$CLUSTER_LAN_HOST" -- sh -c \
			"LC_ALL=C ping -6 -c 2 -W 1 $IPERF_TARGET6" 2>&1); then
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
			"cluster: Group12 IPv6 controlled reachability (LC_ALL=C ping -6 -c 2 -W 1 ${IPERF_TARGET6}; rc=${reach6_rc}; output=${reach6_evidence:-<empty>})"

		local neigh4_output="" neigh4_rc=not_run neigh4_input=""
		if [[ -n "$route4_device" ]]; then
			if neigh4_output=$(incus exec "$CLUSTER_LAN_HOST" -- \
				ip neigh show "$IPERF_TARGET4" dev "$route4_device" 2>&1); then
				neigh4_rc=0
				neigh4_input="$neigh4_output"
			else
				neigh4_rc=$?
			fi
		fi
		local neigh6_output="" neigh6_rc=not_run neigh6_input=""
		if [[ -n "$route6_device" ]]; then
			if neigh6_output=$(incus exec "$CLUSTER_LAN_HOST" -- \
				ip -6 neigh show "$IPERF_TARGET6" dev "$route6_device" 2>&1); then
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
			"cluster: Group12 read-only neighbor identity (v4 ip neigh show ${IPERF_TARGET4} dev ${route4_device:-<no-route-device>} rc=${neigh4_rc} output=${neigh4_evidence:-<empty>}; v6 ip -6 neigh show ${IPERF_TARGET6} dev ${route6_device:-<no-route-device>} rc=${neigh6_rc} output=${neigh6_evidence:-<empty>})"
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

	# #18576: the iperf3 target must be ONE host. loss's 172.16.80.200 is
	# answered by both xpf-mouse-target and the external v6 target box, so the
	# firewall's neighbor entry, and with it every iperf3 measurement, can move
	# between two different servers. See iperf_target_claim_cell.
	iperf_target_claim_cell

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
