#!/usr/bin/env bash
#
# #1827 / #11378 / #11379 — two-upstream FBF steering and IPv4 failover smoke.
#
# Applies the FBF fixture under the shared-cluster lock, validates the existing
# IPv4/IPv6 healthy steering contract, then poisons only the IPv4 ISP-B kernel
# neighbor and proves that ip-monitoring repoints both the reported action and
# the PBR kernel table before correlated marked traffic reaches the VLAN-80
# peer with ISP-A's interface-SNAT source. The exact neighbor predecessor and
# pre-test config/route overlays are restored on every exit.
#
# This does not measure IPv6 uplink failover, provider-independent failover,
# dual-public-IP NAT or throughput under dual-path load. The loss lab has one
# provider; the IPv4 witness is an isolated, reversible neighbor-cache test.
#
# Usage:
#   ./test/incus/test-fbf-steering.sh [loss:xpf-userspace-fw0]
#   FBF_EGRESS_HOST=loss:xpf-mouse-target  # managed VLAN-80 capture peer
#     provision it with ./test/incus/mouse-target-setup.sh up (installs tcpdump)
#   FBF_PING_DST=172.16.80.201 FBF_PING_DST6=2001:559:8585:80::201 ...
#   FBF_LAN_HOST=loss:cluster-userspace-host  # LAN traffic source
#   FBF_FAILOVER_DEADLINE=120                 # IPv4 convergence deadline, seconds
#
set -euo pipefail

TARGET="${1:-loss:xpf-userspace-fw0}"
[[ $# -le 1 ]] || { shift; echo "unexpected extra arguments: $*" >&2; exit 2; }
LAN_HOST="${FBF_LAN_HOST:-loss:cluster-userspace-host}"
ISP_A_GW4="${FBF_ISP_A_GW4:-172.16.50.1}"
ISP_B_GW4="${FBF_ISP_B_GW4:-172.16.80.1}"
ISP_B_GW6="${FBF_ISP_B_GW6:-2001:559:8585:80::1}"
EGRESS_HOST="${FBF_EGRESS_HOST:-${INCUS_REMOTE:-loss}:${MOUSE_TARGET_NAME:-xpf-mouse-target}}"
EGRESS_IFACE="${FBF_EGRESS_IFACE:-eth0}"
PING_DST4="${FBF_PING_DST:-${MOUSE_TARGET_V4:-172.16.80.201}}"
PING_DST6="${FBF_PING_DST6:-${MOUSE_TARGET_V6:-2001:559:8585:80::201}}"
PING_COUNT=5
MIN_ECHO_REPLIES=3
FAILOVER_DEADLINE="${FBF_FAILOVER_DEADLINE:-120}"
[[ "$FAILOVER_DEADLINE" =~ ^[0-9]{1,4}$ ]] \
	&& (( 10#$FAILOVER_DEADLINE > 0 && 10#$FAILOVER_DEADLINE <= 3600 )) \
	|| { echo "VOID: FBF_FAILOVER_DEADLINE must be an integer from 1 through 3600" >&2; exit 2; }
FAILOVER_DEADLINE=$((10#$FAILOVER_DEADLINE))
CAPTURE_SECONDS=$((FAILOVER_DEADLINE + 30))

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/fbf-two-upstream-config.set"
REMOTE_SETS="/tmp/fbf-two-upstream-$$.set"
REMOTE_CAPTURE_LOG="/tmp/fbf-steering-$$.log"
REMOTE_CAPTURE_PID="/tmp/fbf-steering-$$.pid"
CLI=/usr/local/sbin/cli

# The existing destructive-cell preamble is re-entrant under the Makefile's
# outer cell and makes standalone invocations serialize before any cluster IO.
# shellcheck source=./cluster-cell.sh
. "${SCRIPT_DIR}/cluster-cell.sh"
# shellcheck source=./cos-apply-lib.sh
. "${SCRIPT_DIR}/cos-apply-lib.sh"
# shellcheck source=./fbf-steering-lib.sh
. "${SCRIPT_DIR}/fbf-steering-lib.sh"
xpf_enter_destructive_cluster_cell "test-fbf-steering $TARGET" "$0" "$@"

info() { echo "==> $*"; }
pass() {
	PASS_COUNT=$((PASS_COUNT + 1))
	info "PASS: $*"
}
fail() {
	echo "FAIL: $*" >&2
	FAIL_COUNT=$((FAIL_COUNT + 1))
	SUMMARY_ALLOWED=1
	exit 1
}
void() {
	echo "VOID: $*" >&2
	exit 2
}

PASS_COUNT=0
FAIL_COUNT=0
SUMMARY_ALLOWED=0
PEER_CAPTURE_ACTIVE=0
PEER_CAPTURE_REQUIRED=0
REMOTE_SETS_PRESENT=0
CONFIG_ATTEMPTED=0
NEIGHBOR_MUTATION_STARTED=0
NEIGHBOR_SNAPSHOT=""
NEIGHBOR_KIND=""
NEIGHBOR_LLADDR=""
NEIGHBOR_NUD=""
NEIGHBOR_FLAGS=""
cleanup_files=()
COMMIT_MARKER=""
declare -A USED_IDS=()
NEXT_PING_ID=""
ID_CURSOR=$(( ((BASHPID + RANDOM + $(date +%s)) % 65534) + 1 ))

next_ping_id() {
	local candidate="$ID_CURSOR"
	while [[ -n "${USED_IDS[$candidate]+x}" ]]; do
		candidate=$((candidate % 65535 + 1))
	done
	USED_IDS[$candidate]=1
	ID_CURSOR=$((candidate % 65535 + 1))
	NEXT_PING_ID="$candidate"
}

cli_read() {
	incus exec "$TARGET" -- "$CLI" -c "$1"
}

metric_value() {
	local family="$1" filter="$2"
	incus exec "$TARGET" -- sh -c \
		"curl -fsS 127.0.0.1:8080/metrics | grep 'xpf_filter_hits_total{' | grep 'family=\"${family}\"' | grep 'filter=\"${filter}\"' | grep 'term=\"to-isp-b\"' | awk '{print \$NF}' | head -1"
}

cleanup_peer_capture() {
	local failed=0
	if (( PEER_CAPTURE_ACTIVE )); then
		if ! incus exec "$EGRESS_HOST" -- sh -c \
			"pid=\$(cat '$REMOTE_CAPTURE_PID' 2>/dev/null || true); if [ -n \"\$pid\" ] && kill -0 \"\$pid\" 2>/dev/null; then kill -INT \"\$pid\" 2>/dev/null || exit 1; fi; sleep 1" \
			>/dev/null 2>&1; then
			echo "FAIL: could not stop VLAN-80 peer capture" >&2
			failed=1
		fi
		PEER_CAPTURE_ACTIVE=0
	fi
	if (( PEER_CAPTURE_REQUIRED )); then
		if ! incus exec "$EGRESS_HOST" -- rm -f "$REMOTE_CAPTURE_LOG" "$REMOTE_CAPTURE_PID" >/dev/null 2>&1; then
			echo "FAIL: could not remove VLAN-80 peer capture files" >&2
			failed=1
		fi
		PEER_CAPTURE_REQUIRED=0
	fi
	return "$failed"
}

start_peer_capture() {
	local capture_filter
	capture_filter="(icmp and dst host ${PING_DST4}) or (icmp6 and dst host ${PING_DST6})"
	PEER_CAPTURE_REQUIRED=1
	if ! incus exec "$EGRESS_HOST" -- rm -f "$REMOTE_CAPTURE_LOG" "$REMOTE_CAPTURE_PID" >/dev/null 2>&1; then
		return 1
	fi
	PEER_CAPTURE_ACTIVE=1
	if ! incus exec "$EGRESS_HOST" -- sh -c \
		"timeout ${CAPTURE_SECONDS} tcpdump -i '$EGRESS_IFACE' -e -nn -vv -l '$capture_filter' > '$REMOTE_CAPTURE_LOG' 2>&1 & echo \$! > '$REMOTE_CAPTURE_PID'; sleep 1; pid=\$(cat '$REMOTE_CAPTURE_PID' 2>/dev/null || true); [ -n \"\$pid\" ] && kill -0 \"\$pid\"" \
		>/dev/null 2>&1; then
		return 1
	fi
	sleep 2
}

stop_peer_capture() {
	if (( PEER_CAPTURE_ACTIVE )); then
		if ! incus exec "$EGRESS_HOST" -- sh -c \
			"pid=\$(cat '$REMOTE_CAPTURE_PID' 2>/dev/null || true); if [ -n \"\$pid\" ] && kill -0 \"\$pid\" 2>/dev/null; then kill -INT \"\$pid\" 2>/dev/null || exit 1; fi; sleep 1" \
			>/dev/null 2>&1; then
			return 1
		fi
		PEER_CAPTURE_ACTIVE=0
	fi
}

read_neighbor_snapshot() {
	local json
	json="$(incus exec "$TARGET" -- ip -4 -j -details neigh show to "$ISP_B_GW4" dev "$WAN80_IFACE")" || return 1
	fbf_neighbor_snapshot "$ISP_B_GW4" "$WAN80_IFACE" "$json"
}

restore_neighbor() {
	local current
	local -a restore_args flags
	(( NEIGHBOR_MUTATION_STARTED )) || return 0
	if [[ "$NEIGHBOR_KIND" == ABSENT ]]; then
		incus exec "$TARGET" -- ip -4 neigh del "$ISP_B_GW4" dev "$WAN80_IFACE" >/dev/null 2>&1 || true
	else
		restore_args=(ip -4 neigh replace "$ISP_B_GW4" dev "$WAN80_IFACE")
		[[ -z "$NEIGHBOR_LLADDR" ]] || restore_args+=(lladdr "$NEIGHBOR_LLADDR")
		restore_args+=(nud "$NEIGHBOR_NUD")
		if [[ -n "$NEIGHBOR_FLAGS" ]]; then
			IFS=, read -r -a flags <<<"$NEIGHBOR_FLAGS"
			restore_args+=("${flags[@]}")
		fi
		incus exec "$TARGET" -- "${restore_args[@]}" >/dev/null 2>&1 || true
	fi
	for _ in 1 2 3; do
		current="$(read_neighbor_snapshot)" || return 1
		if [[ "$current" == "$NEIGHBOR_SNAPSHOT" ]]; then
			NEIGHBOR_MUTATION_STARTED=0
			info "Restored exact ISP-B neighbor predecessor: $NEIGHBOR_SNAPSHOT"
			return 0
		fi
		sleep 1
	done
	echo "FAIL: ISP-B neighbor did not return to exact predecessor ($NEIGHBOR_SNAPSHOT; got ${current:-unreadable})" >&2
	return 1
}

verify_restored_overlay() {
	local current_config status rules4 rules6 routes4 routes6
	current_config="$(cli_read 'show configuration | display set')" || return 1
	[[ "$current_config" == "$BASELINE_CONFIG" ]] || {
		echo "FAIL: configuration differs from the exact pre-test snapshot" >&2
		return 1
	}
	status="$(cli_read 'show services ip-monitoring status')" || return 1
	[[ -n "${status//[[:space:]]/}" ]] || return 1
	if grep -Eq '^Policy[[:space:]]+-[[:space:]]+fbf-fallback([[:space:]]|$)' <<<"$status"; then
		echo "FAIL: fbf-fallback policy remains after rollback" >&2
		return 1
	fi
	rules4="$(incus exec "$TARGET" -- ip -4 rule show)" || return 1
	rules6="$(incus exec "$TARGET" -- ip -6 rule show)" || return 1
	routes4="$(incus exec "$TARGET" -- ip -4 route show table all)" || return 1
	routes6="$(incus exec "$TARGET" -- ip -6 route show table all)" || return 1
	[[ "$rules4" == "$PRE_RULES4" && "$rules6" == "$PRE_RULES6" ]] || {
		echo "FAIL: PBR rule overlay differs from the pre-test snapshot" >&2
		return 1
	}
	[[ "$routes4" == "$PRE_ROUTE_ALL4" && "$routes6" == "$PRE_ROUTE_ALL6" ]] || {
		echo "FAIL: kernel route overlay differs from the pre-test snapshot" >&2
		return 1
	}
	return 0
}

restore_config() {
	local current_config history latest
	(( CONFIG_ATTEMPTED )) || return 0
	current_config="$(cli_read 'show configuration | display set')" || {
		echo "FAIL: cannot inspect configuration during cleanup" >&2
		return 1
	}
	if [[ "$current_config" != "$BASELINE_CONFIG" ]]; then
		history="$(cli_read 'show system commit history')" || {
			echo "FAIL: cannot inspect commit ownership before rollback" >&2
			return 1
		}
		latest="$(awk 'NF { line = $0 } END { print line }' <<<"$history")"
		if [[ -z "$COMMIT_MARKER" || "$latest" != *"  commit  ${COMMIT_MARKER}" ]]; then
			echo "FAIL: latest commit is not owned by marker ${COMMIT_MARKER:-missing}; refusing rollback 1" >&2
			return 1
		fi
		info "Restoring pre-test config (owned rollback 1 + commit)..."
		cos_rollback_one "$TARGET" || {
			echo "FAIL: owned rollback did not land" >&2
			return 1
		}
		sleep 3
	fi
	verify_restored_overlay || return 1
	CONFIG_ATTEMPTED=0
	info "Verified exact pre-test configuration and routing overlays restored"
	return 0
}

exit_handler() {
	local rc="${1:-1}" cleanup_failed=0
	trap - EXIT INT TERM HUP
	cleanup_peer_capture || cleanup_failed=1
	restore_neighbor || cleanup_failed=1
	restore_config || cleanup_failed=1
	if (( REMOTE_SETS_PRESENT )); then
		if ! incus exec "$TARGET" -- rm -f "$REMOTE_SETS" >/dev/null 2>&1; then
			echo "FAIL: could not remove staged FBF config file" >&2
			cleanup_failed=1
		fi
		REMOTE_SETS_PRESENT=0
	fi
	if (( ${#cleanup_files[@]} )) && ! rm -f "${cleanup_files[@]}"; then
		echo "FAIL: could not remove local FBF temporary files" >&2
		cleanup_failed=1
	fi
	if (( cleanup_failed )); then
		echo "FAIL: cleanup/restoration did not complete safely" >&2
		FAIL_COUNT=$((FAIL_COUNT + 1))
		SUMMARY_ALLOWED=1
		if (( rc == 0 || rc == 2 )); then rc=1; fi
	fi
	if (( FAIL_COUNT > 0 )); then
		SUMMARY_ALLOWED=1
		rc=1
	fi
	if (( SUMMARY_ALLOWED )); then
		printf '%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
	fi
	exit "$rc"
}
trap 'exit_handler $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

[[ -f "$CONFIG_FILE" ]] || void "cannot find $CONFIG_FILE"
command -v python3 >/dev/null 2>&1 || void "local python3 is required to preserve the neighbor JSON state"
IPV4_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
[[ "$ISP_A_GW4" =~ $IPV4_RE && "$ISP_B_GW4" =~ $IPV4_RE && "$PING_DST4" =~ $IPV4_RE ]] \
	|| void "IPv4 gateway/destination input is malformed"
[[ "$ISP_B_GW6" =~ ^[0-9a-fA-F:]+$ && "$PING_DST6" =~ ^[0-9a-fA-F:]+$ ]] \
	|| void "IPv6 gateway/destination input is malformed"
[[ "$EGRESS_IFACE" =~ ^[[:alnum:]_.:-]+$ ]] || void "invalid VLAN-80 capture interface"
incus exec "$TARGET" -- sh -c 'command -v ip >/dev/null 2>&1' \
	|| void "firewall target $TARGET or its ip utility is unavailable"
incus exec "$LAN_HOST" -- sh -c 'command -v ping >/dev/null 2>&1' \
	|| void "LAN probe host $LAN_HOST or its ping utility is unavailable"
incus exec "$EGRESS_HOST" -- sh -c 'command -v tcpdump >/dev/null 2>&1' \
	|| void "VLAN-80 peer capture unavailable at $EGRESS_HOST; run test/incus/mouse-target-setup.sh up first"
CAPTURE_FILTER="(icmp and dst host ${PING_DST4}) or (icmp6 and dst host ${PING_DST6})"
incus exec "$EGRESS_HOST" -- tcpdump -i "$EGRESS_IFACE" -d "$CAPTURE_FILTER" >/dev/null 2>&1 \
	|| void "cannot compile VLAN-80 peer capture filter on $EGRESS_HOST:$EGRESS_IFACE"

peer_gateway_mac() {
	local family="$1" gateway="$2" neighbors
	incus exec "$EGRESS_HOST" -- ping "-${family}" -n -c 1 -W 1 "$gateway" >/dev/null 2>&1 || true
	neighbors="$(incus exec "$EGRESS_HOST" -- ip "-${family}" neigh show to "$gateway" dev "$EGRESS_IFACE")" || return 1
	awk '{
		for (i = 1; i < NF; i++) if ($i == "lladdr") { print tolower($(i+1)); exit }
	}' <<<"$neighbors"
}
GATEWAY_MAC4="$(peer_gateway_mac 4 "$ISP_B_GW4")" || void "cannot read ISP-B IPv4 neighbor on peer"
GATEWAY_MAC6="$(peer_gateway_mac 6 "$ISP_B_GW6")" || void "cannot read ISP-B IPv6 neighbor on peer"
MAC_RE='^[[:xdigit:]][[:xdigit:]](:[[:xdigit:]][[:xdigit:]]){5}$'
[[ "$GATEWAY_MAC4" =~ $MAC_RE ]] || void "cannot resolve IPv4 ISP-B gateway MAC on peer $EGRESS_HOST"
[[ "$GATEWAY_MAC6" =~ $MAC_RE ]] || void "cannot resolve IPv6 ISP-B gateway MAC on peer $EGRESS_HOST"
info "VLAN-80 peer ISP-B gateway MACs: IPv4=$GATEWAY_MAC4 IPv6=$GATEWAY_MAC6"

BASELINE_CONFIG="$(cli_read 'show configuration | display set')" || void "cannot read target configuration"
[[ "$BASELINE_CONFIG" == *"set "* ]] || void "target returned no readable configuration"
if grep -Eq '^set (routing-instances ISP-B|firewall family inet filter fbf-steer|firewall family inet6 filter fbf-steer6|services ip-monitoring policy fbf-fallback)([[:space:]]|$)' <<<"$BASELINE_CONFIG"; then
	void "FBF fixture names already exist in the baseline; refusing to overwrite pre-existing config"
fi
grep -Eq '^set security nat source rule-set [^ ]+ rule [^ ]+ then source-nat interface$' \
	<<<"$BASELINE_CONFIG" || void "baseline interface-mode source NAT is unavailable for the on-wire discriminator"

interface_ipv4() {
	local unit="$1"
	awk -v unit="$unit" '
		$1 == "set" && $2 == "interfaces" && $3 == "reth0" &&
		$4 == "unit" && $5 == unit && $6 == "family" && $7 == "inet" &&
		$8 == "address" {
			address = $9
			sub(/\/.*/, "", address)
			if (address != "") print address
		}
	' <<<"$BASELINE_CONFIG"
}
mapfile -t ISP_A_ADDRS < <(interface_ipv4 50)
mapfile -t ISP_B_ADDRS < <(interface_ipv4 80)
(( ${#ISP_A_ADDRS[@]} == 1 && ${#ISP_B_ADDRS[@]} == 1 )) \
	|| void "reth0.50/reth0.80 need one unambiguous IPv4 interface-SNAT address each"
ISP_A_SNAT4="${ISP_A_ADDRS[0]}"
ISP_B_SNAT4="${ISP_B_ADDRS[0]}"
[[ "$ISP_A_SNAT4" =~ $IPV4_RE && "$ISP_B_SNAT4" =~ $IPV4_RE && "$ISP_A_SNAT4" != "$ISP_B_SNAT4" ]] \
	|| void "baseline WAN interface addresses cannot distinguish ISP-A from ISP-B"
info "Interface-SNAT witness: ISP-A=$ISP_A_SNAT4 ISP-B=$ISP_B_SNAT4"

PRE_POLICY_STATUS="$(cli_read 'show services ip-monitoring status')" || void "cannot read baseline ip-monitoring status"
[[ -n "${PRE_POLICY_STATUS//[[:space:]]/}" ]] || void "baseline ip-monitoring status is unreadable"
if grep -Eq '^Policy[[:space:]]+-[[:space:]]+fbf-fallback([[:space:]]|$)' <<<"$PRE_POLICY_STATUS"; then
	void "fbf-fallback policy already exists in the baseline"
fi
PRE_RULES4="$(incus exec "$TARGET" -- ip -4 rule show)" || void "cannot snapshot IPv4 policy rules"
PRE_RULES6="$(incus exec "$TARGET" -- ip -6 rule show)" || void "cannot snapshot IPv6 policy rules"
PRE_ROUTE_ALL4="$(incus exec "$TARGET" -- ip -4 route show table all)" || void "cannot snapshot IPv4 route tables"
PRE_ROUTE_ALL6="$(incus exec "$TARGET" -- ip -6 route show table all)" || void "cannot snapshot IPv6 route tables"
PRE_MAIN4="$(incus exec "$TARGET" -- ip -4 route show default)" || void "cannot read baseline IPv4 main-table routes"
PRE_NEXTHOPS="$(incus exec "$TARGET" -- ip nexthop show)" || void "cannot read baseline nexthop graph"
PRE_MAIN4_DEFAULTS="$(_fbf_default_routes "$PRE_MAIN4")"
_fbf_default_route_text_valid "$PRE_MAIN4_DEFAULTS" || void "baseline IPv4 main table has no readable default"
_fbf_default_route_gateway_status "$ISP_A_GW4" "$PRE_MAIN4_DEFAULTS" "$PRE_NEXTHOPS" \
	|| void "baseline ISP-A gateway $ISP_A_GW4 is not a main-table default"

SETS_TMP="$(mktemp)"
cleanup_files+=("$SETS_TMP")
grep -E '^set ' "$CONFIG_FILE" >"$SETS_TMP" || void "FBF fixture contains no set commands"
if [[ "$ISP_B_GW4" != "172.16.80.1" ]]; then
	sed -i "s/172\.16\.80\.1/${ISP_B_GW4}/g" "$SETS_TMP"
fi
if [[ "$ISP_A_GW4" != "172.16.50.1" ]]; then
	sed -i "s/172\.16\.50\.1/${ISP_A_GW4}/g" "$SETS_TMP"
fi
if [[ "$ISP_B_GW6" != "2001:559:8585:80::1" ]]; then
	sed -i "s|2001:559:8585:80::1|${ISP_B_GW6}|g" "$SETS_TMP"
fi
incus exec "$TARGET" -- rm -f "$REMOTE_SETS" >/dev/null 2>&1 || void "cannot stage FBF config on $TARGET"
incus file push --mode 0644 "$SETS_TMP" "${TARGET}/${REMOTE_SETS}" >/dev/null \
	|| void "cannot push FBF config to $TARGET"
REMOTE_SETS_PRESENT=1

CHECK_OUT="$(mktemp)"
cleanup_files+=("$CHECK_OUT")
info "commit check on $TARGET..."
incus exec "$TARGET" -- "$CLI" >"$CHECK_OUT" 2>&1 <<EOF || true
configure
load merge ${REMOTE_SETS}
commit check
exit
quit
EOF
cos_require_markers "commit check on $TARGET" "$CHECK_OUT" \
	"$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT_CHECK" \
	|| fail "commit check failed (candidate invalid; live state unchanged)"

APPLY_OUT="$(mktemp)"
cleanup_files+=("$APPLY_OUT")
COMMIT_MARKER="fbf-steering-test-$$_${RANDOM}-$(date +%s)"
CONFIG_ATTEMPTED=1
info "committing FBF two-upstream fixture with ownership marker $COMMIT_MARKER..."
incus exec "$TARGET" -- "$CLI" >"$APPLY_OUT" 2>&1 <<EOF || true
configure
load merge ${REMOTE_SETS}
commit comment ${COMMIT_MARKER}
exit
quit
EOF
cos_require_markers "commit on $TARGET" "$APPLY_OUT" \
	"$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT" \
	|| fail "fixture commit failed after commit-check passed"
sleep 3

# ---- Phase 2: healthy IPv4/IPv6 routing and status preconditions ----
NEXTHOPS="$(incus exec "$TARGET" -- ip nexthop show)" || void "cannot read target nexthop graph"
PBR_TABLE4=""
PBR_TABLE6=""
discover_isp_b_table() {
	local family="$1" gateway="$2" label="$3"
	local candidates candidate routes
	candidates="$(incus exec "$TARGET" -- sh -c \
		"ip -${family} rule show | awk -F'lookup ' '\$1 ~ /^29[0-9][0-9][0-9]:/ {print \$2}'")" \
		|| void "cannot read IPv${family} policy rules"
	candidates="$(tr -d '\r' <<<"$candidates")"
	[[ -n "${candidates//[[:space:]]/}" ]] \
		|| fail "no IPv${family} PBR ip rule in the 29000-29999 band (FBF kernel rule missing)"
	for candidate in $candidates; do
		routes="$(incus exec "$TARGET" -- ip "-${family}" route show table "$candidate")" \
			|| void "cannot read IPv${family} PBR table $candidate"
		if fbf_table_holds_default "$gateway" "$routes" "$NEXTHOPS"; then
			if [[ "$family" == 4 ]]; then PBR_TABLE4="$candidate"; else PBR_TABLE6="$candidate"; fi
			break
		fi
	done
	if [[ "$family" == 4 ]]; then
		[[ -n "$PBR_TABLE4" ]] || fail "no IPv4 PBR table in the 29000-29999 band holds the ISP-B default"
		info "IPv4 FBF table $PBR_TABLE4 holds ISP-B default via $gateway"
	else
		[[ -n "$PBR_TABLE6" ]] || fail "no IPv6 PBR table in the 29000-29999 band holds the ISP-B default"
		info "IPv6 FBF table $PBR_TABLE6 holds ISP-B default via $gateway"
	fi
}

check_main_table_leak() {
	local family="$1" gateway="$2" label="$3" routes defaults verdict
	routes="$(incus exec "$TARGET" -- ip "-${family}" route show default)" \
		|| void "cannot read IPv${family} main-table routes"
	defaults="$(_fbf_default_routes "$routes")"
	_fbf_default_route_text_valid "$defaults" || void "IPv${family} main table has no readable default route"
	verdict="$(fbf_main_default_leak_verdict "$gateway" "$routes" "$NEXTHOPS")"
	case "$verdict" in
		PASS\ *) pass "$label main table: ${verdict#PASS }" ;;
		FAIL*"could not be resolved"*) void "$label main-table nexthop graph is unreadable" ;;
		*) fail "$label main table: ${verdict#FAIL }" ;;
	esac
}

discover_isp_b_table 4 "$ISP_B_GW4" IPv4
discover_isp_b_table 6 "$ISP_B_GW6" IPv6
check_main_table_leak 4 "$ISP_B_GW4" IPv4
check_main_table_leak 6 "$ISP_B_GW6" IPv6

STATUS="$(cli_read 'show services ip-monitoring status')" || void "cannot read ip-monitoring status"
INITIAL_POLICY_STATE="$(fbf_ipmon_policy_state fbf-fallback "$STATUS" 2>/dev/null)" \
	|| void "ip-monitoring status omits or ambiguously reports fbf-fallback"
[[ "$INITIAL_POLICY_STATE" == PASS ]] || void "ISP-B was not healthy before injection (fbf-fallback status: $INITIAL_POLICY_STATE)"
fbf_ipmon_route_action_present ISP-B.inet.0 0.0.0.0/0 "$ISP_B_GW4" APPLIED "$STATUS" \
	|| void "ip-monitoring did not report the healthy ISP-B default as APPLIED"
pass "initial ip-monitoring health is PASS with ISP-B route action APPLIED"

# ---- Phase 3: retain the original healthy IPv4/IPv6 steering matrix ----
BEFORE4="$(metric_value inet fbf-steer)" || void "cannot read IPv4 steering counter"
BEFORE6="$(metric_value inet6 fbf-steer6)" || void "cannot read IPv6 steering counter"
[[ "$BEFORE4" =~ ^[0-9]+$ && "$BEFORE6" =~ ^[0-9]+$ ]] \
	|| void "steering counter readback is missing or malformed"
info "Steering-term hits before: IPv4=$BEFORE4 IPv6=$BEFORE6"

run_marked_ping() {
	local family="$1" destination="$2" label="$3" identifier="$4" output verdict
	info "Sending $PING_COUNT DSCP-af31 $label pings (tos 0x68, id $identifier) from $LAN_HOST to $destination..."
	output="$(incus exec "$LAN_HOST" -- ping "-${family}" -n -c "$PING_COUNT" -W 2 \
		-e "$identifier" -Q 0x68 "$destination" 2>&1 || true)"
	verdict="$(fbf_ping_reply_verdict "$MIN_ECHO_REPLIES" "$output")"
	case "$verdict" in
		PASS\ *) pass "$label target replies: ${verdict#PASS }" ;;
		*)       fail "$label marked probe to $destination failed: ${verdict#FAIL }" ;;
	esac
}

run_unmarked_control() {
	local family="$1" destination="$2" label="$3" identifier="$4"
	info "Sending $PING_COUNT unmarked $label control pings (id $identifier) to $destination..."
	incus exec "$LAN_HOST" -- ping "-${family}" -n -c "$PING_COUNT" -W 2 \
		-e "$identifier" -Q 0 "$destination" >/dev/null 2>&1 || true
}

check_peer_egress() {
	local family="$1" destination="$2" gateway_mac="$3" label="$4" verdict
	verdict="$(fbf_peer_egress_verdict "$family" "$destination" "$gateway_mac" \
		"$MIN_ECHO_REPLIES" "$PEER_CAPTURE_OUTPUT")"
	case "$verdict" in
		PASS\ *) pass "$label ISP-B next-hop evidence: ${verdict#PASS }" ;;
		*)       fail "$label egress check failed: ${verdict#FAIL }" ;;
	esac
}

next_ping_id
BASE_MARKED_ID4="$NEXT_PING_ID"
next_ping_id
BASE_MARKED_ID6="$NEXT_PING_ID"
next_ping_id
BASE_CONTROL_ID4="$NEXT_PING_ID"
next_ping_id
BASE_CONTROL_ID6="$NEXT_PING_ID"
start_peer_capture || void "could not start VLAN-80 peer capture"
run_marked_ping 4 "$PING_DST4" IPv4 "$BASE_MARKED_ID4"
run_marked_ping 6 "$PING_DST6" IPv6 "$BASE_MARKED_ID6"
run_unmarked_control 4 "$PING_DST4" IPv4 "$BASE_CONTROL_ID4"
run_unmarked_control 6 "$PING_DST6" IPv6 "$BASE_CONTROL_ID6"
sleep 2
stop_peer_capture || void "could not stop VLAN-80 peer capture"
PEER_CAPTURE_OUTPUT="$(incus exec "$EGRESS_HOST" -- cat "$REMOTE_CAPTURE_LOG")" \
	|| void "could not read VLAN-80 peer capture"
check_peer_egress 4 "$PING_DST4" "$GATEWAY_MAC4" IPv4
check_peer_egress 6 "$PING_DST6" "$GATEWAY_MAC6" IPv6
cleanup_peer_capture || void "could not clean up the healthy-leg peer capture"

AFTER4="$(metric_value inet fbf-steer)" || void "cannot read IPv4 steering counter after traffic"
AFTER6="$(metric_value inet6 fbf-steer6)" || void "cannot read IPv6 steering counter after traffic"
[[ "$AFTER4" =~ ^[0-9]+$ && "$AFTER6" =~ ^[0-9]+$ ]] \
	|| void "post-traffic steering counter readback is missing or malformed"
check_steering_delta() {
	local label="$1" before="$2" after="$3" delta max_delta
	delta=$((after - before))
	max_delta=$((PING_COUNT * 2 - 1))
	(( delta >= PING_COUNT )) \
		|| fail "$label steering counter delta $delta < $PING_COUNT — af31 traffic not hitting the FBF term"
	(( delta <= max_delta )) \
		|| fail "$label steering counter delta $delta > $max_delta — unmarked control traffic also steered"
	pass "$label steering counter delta $delta (marked traffic only)"
}
check_steering_delta IPv4 "$BEFORE4" "$AFTER4"
check_steering_delta IPv6 "$BEFORE6" "$AFTER6"
info "Steering-term hits after: IPv4=$AFTER4 IPv6=$AFTER6"

# ---- Phase 4: reversible IPv4 failure injection and route convergence ----
ROUTE_GET="$(incus exec "$TARGET" -- ip -4 route get "$ISP_B_GW4")" \
	|| void "cannot resolve the ISP-B kernel egress interface"
mapfile -t WAN80_DEVS < <(awk -v gateway="$ISP_B_GW4" '
	$1 == gateway {
		for (i = 1; i < NF; i++) if ($i == "dev") print $(i+1)
	}
' <<<"$ROUTE_GET")
(( ${#WAN80_DEVS[@]} == 1 )) || void "ISP-B route lookup did not identify one kernel device"
WAN80_IFACE="${WAN80_DEVS[0]}"
[[ "$WAN80_IFACE" =~ ^[[:alnum:]_.:-]+$ ]] || void "ISP-B route lookup returned an invalid kernel device"

NEIGH_JSON="$(incus exec "$TARGET" -- ip -4 -j -details neigh show to "$ISP_B_GW4" dev "$WAN80_IFACE")" \
	|| void "cannot snapshot the exact ISP-B neighbor predecessor"
NEIGH_SNAPSHOT="$(fbf_neighbor_snapshot "$ISP_B_GW4" "$WAN80_IFACE" "$NEIGH_JSON" 2>/dev/null)" \
	|| void "ISP-B neighbor snapshot is malformed or cannot be restored safely"
NEIGHBOR_SNAPSHOT="$NEIGH_SNAPSHOT"
if [[ "$NEIGH_SNAPSHOT" == ABSENT ]]; then
	NEIGHBOR_KIND=ABSENT
else
	IFS=$'\t' read -r NEIGHBOR_KIND NEIGHBOR_LLADDR NEIGHBOR_NUD NEIGHBOR_FLAGS <<<"$NEIGH_SNAPSHOT"
	[[ "$NEIGHBOR_KIND" == PRESENT ]] || void "ISP-B neighbor snapshot has an unsupported form"
fi

new_dead_mac() {
	printf '02:ff:%02x:%02x:%02x:%02x\n' \
		"$((RANDOM % 256))" "$((RANDOM % 256))" "$((RANDOM % 256))" "$((RANDOM % 256))"
}
DEAD_MAC="$(new_dead_mac)"
while [[ "${DEAD_MAC,,}" == "$GATEWAY_MAC4" ||
	( -n "$NEIGHBOR_LLADDR" && "${DEAD_MAC,,}" == "$NEIGHBOR_LLADDR" ) ]]; do
	DEAD_MAC="$(new_dead_mac)"
done
info "Poisoning only $ISP_B_GW4 on $WAN80_IFACE with reversible unicast $DEAD_MAC (predecessor: $NEIGH_SNAPSHOT)"

next_ping_id
FAILOVER_MARKED_ID4="$NEXT_PING_ID"
next_ping_id
FAILOVER_CONTROL_ID4="$NEXT_PING_ID"
start_peer_capture || void "could not start the IPv4 failover peer capture"
NEIGHBOR_MUTATION_STARTED=1
incus exec "$TARGET" -- ip -4 neigh replace "$ISP_B_GW4" dev "$WAN80_IFACE" \
	lladdr "$DEAD_MAC" nud permanent >/dev/null \
	|| void "could not install the reversible ISP-B neighbor poison"

route_dump_shape_valid() {
	awk '
		NF == 0 { next }
		$1 == "default" || $1 == "nexthop" || $1 == "local" ||
		$1 == "broadcast" || $1 == "blackhole" || $1 == "unreachable" ||
		$1 == "prohibit" || $1 == "throw" || $1 ~ /^[0-9A-Fa-f:.]+(\/[0-9]+)?$/ {
			valid++
			next
		}
		{ invalid = 1 }
		END { exit !(valid && !invalid) }
	' <<<"${1:-}"
}

wait_for_fallback() {
	local start="$SECONDS" saw_pass=0 saw_fail=0 status policy_state routes route_verdict
	while (( SECONDS - start < FAILOVER_DEADLINE )); do
		status="$(cli_read 'show services ip-monitoring status')" || void "ip-monitoring status became unreadable during failover"
		policy_state="$(fbf_ipmon_policy_state fbf-fallback "$status" 2>/dev/null)" \
			|| void "ip-monitoring status omitted or ambiguously reported fbf-fallback"
		case "$policy_state" in
			PASS) saw_pass=1 ;;
			FAIL)
				saw_fail=1
				if fbf_ipmon_route_action_present ISP-B.inet.0 0.0.0.0/0 "$ISP_A_GW4" APPLIED "$status"; then
					routes="$(incus exec "$TARGET" -- ip -4 route show table "$PBR_TABLE4")" \
						|| void "cannot read IPv4 PBR table during failover"
					if [[ -n "$routes" ]] && ! route_dump_shape_valid "$routes"; then
						void "IPv4 PBR route dump is unreadable during failover"
					fi
					route_verdict="$(fbf_table_transition_verdict "$ISP_B_GW4" "$ISP_A_GW4" "$routes" "$NEXTHOPS")"
					if [[ "${route_verdict%% *}" == PASS ]]; then
						info "ip-monitoring reports FAIL and ISP-B.inet.0 has the exclusive ISP-A default"
						pass "IPv4 fallback status/action/kernel route converged"
						return 0
					fi
				fi
				;;
			UNKNOWN) ;;
			*) void "ip-monitoring returned unsupported fbf-fallback state $policy_state" ;;
		esac
		sleep 2
	done
	if (( saw_fail )); then
		fail "ip-monitoring failed but ISP-B.inet.0 did not converge exclusively to ISP-A within ${FAILOVER_DEADLINE}s"
	elif (( saw_pass )); then
		fail "fbf-fallback stayed PASS despite the deliberate ISP-B neighbor blackhole"
	else
		void "ip-monitoring returned no usable PASS/FAIL state during the ${FAILOVER_DEADLINE}s failover window"
	fi
}

wait_for_fallback
info "Sending fresh IPv4 failover probes: marked id=$FAILOVER_MARKED_ID4, unmarked id=$FAILOVER_CONTROL_ID4"
FAILOVER_MARKED_OUTPUT="$(incus exec "$LAN_HOST" -- ping -4 -n -c "$PING_COUNT" -W 2 \
	-e "$FAILOVER_MARKED_ID4" -Q 0x68 "$PING_DST4" 2>&1 || true)"
incus exec "$LAN_HOST" -- ping -4 -n -c "$PING_COUNT" -W 2 \
	-e "$FAILOVER_CONTROL_ID4" -Q 0 "$PING_DST4" >/dev/null 2>&1 || true
stop_peer_capture || void "could not stop the IPv4 failover peer capture"
PEER_CAPTURE_OUTPUT="$(incus exec "$EGRESS_HOST" -- cat "$REMOTE_CAPTURE_LOG")" \
	|| void "could not read the IPv4 failover peer capture"

FAILOVER_PING_VERDICT="$(fbf_ping_reply_verdict "$MIN_ECHO_REPLIES" "$FAILOVER_MARKED_OUTPUT")"
case "$FAILOVER_PING_VERDICT" in
	PASS\ *) info "IPv4 fallback marked replies: ${FAILOVER_PING_VERDICT#PASS }" ;;
	*)       fail "IPv4 marked fallback probe failed: ${FAILOVER_PING_VERDICT#FAIL }" ;;
esac
FAILOVER_CAPTURE_VERDICT="$(fbf_peer_fallback_verdict "$PING_DST4" "$MIN_ECHO_REPLIES" \
	"$FAILOVER_MARKED_ID4" "$FAILOVER_CONTROL_ID4" "$ISP_A_SNAT4" "$PEER_CAPTURE_OUTPUT")"
case "$FAILOVER_CAPTURE_VERDICT" in
	PASS\ *) pass "${FAILOVER_CAPTURE_VERDICT#PASS }" ;;
	*)       fail "IPv4 fallback egress witness failed: ${FAILOVER_CAPTURE_VERDICT#FAIL }" ;;
esac
cleanup_peer_capture || fail "could not clean up the IPv4 failover peer capture"
info "PASS: FBF healthy steering plus IPv4 ip-monitoring fallback verified"
SUMMARY_ALLOWED=1
exit 0
