#!/usr/bin/env bash
# Hermetic self-test for test/incus/fbf-steering-lib.sh (#6936/#11378).
#
# No cluster, no incus, no network. Runs in `make test-fbf-steering-lib`.
#
# The row that matters is PROBE_BLIND. Under the counting form this smoke
# shipped with, that input produced the same verdict as a healthy table, which
# is why the defect was invisible to review: only a table that includes the
# middle row can distinguish "there is no leak" from "I could not look".
# Transition cells pin unique ip-monitoring actions, exclusive route migration,
# neighbor snapshots, and correlated fallback packets with the expected source
# address and DSCP. No cluster, Incus, or network is used by these cells.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./fbf-steering-lib.sh
. "${SCRIPT_DIR}/fbf-steering-lib.sh"

pass=0
fail=0
GW="172.16.80.1"
GW6="2001:559:8585:80::1"

check() {
	local name="$1" want="$2" gw="$3" routes="$4" got verdict
	got="$(fbf_main_default_leak_verdict "$gw" "$routes" "${5:-}")"
	verdict="${got%% *}"
	if [[ "$verdict" == "$want" ]]; then
		pass=$((pass + 1))
		printf 'ok   %-26s -> %s\n' "$name" "$verdict"
	else
		fail=$((fail + 1))
		printf 'FAIL %-26s -> want %s got %s (%s)\n' "$name" "$want" "$verdict" "$got"
	fi
	# TOTALITY: exactly one verdict line, and it is one of the two known words.
	if [[ "$(grep -c . <<<"$got")" -ne 1 ]]; then
		fail=$((fail + 1))
		printf 'FAIL %-26s -> verdict was not exactly one line: %q\n' "$name" "$got"
	fi
	if [[ "$verdict" != "PASS" && "$verdict" != "FAIL" ]]; then
		fail=$((fail + 1))
		printf 'FAIL %-26s -> verdict word %q is neither PASS nor FAIL\n' "$name" "$verdict"
	fi
}

# --- the healthy case: a main table with an unrelated (ISP-A) default -------
check CLEAN_ONE_DEFAULT   PASS "$GW" "default via 172.16.50.1 dev ge-0-0-2 proto static"
check CLEAN_TWO_DEFAULTS  PASS "$GW" "default via 172.16.50.1 dev ge-0-0-2
default via 10.0.61.254 dev ge-0-0-1 metric 100"
check MAIN_PROBE_ERROR_STRING FAIL "$GW" "incus: exec failed: target unavailable"
check MAIN_ECMP_INLINE_LEAK FAIL "$GW" "default proto static
    nexthop via 172.16.80.1 dev ge-0-0-2.80 weight 1
    nexthop via 172.16.50.1 dev ge-0-0-2.50 weight 1"
NH4=$'id 103 group 101/102\nid 101 via 172.16.80.1 dev ge-0-0-2.80 scope link\nid 102 via 172.16.50.1 dev ge-0-0-2.50 scope link'
check MAIN_ECMP_NHID_LEAK FAIL "$GW" "default nhid 103 proto static" "$NH4"
NH4_WEIGHTED=$'id 103 group 101,5/102,11\nid 101 via 172.16.50.1 dev ge-0-0-2.80 scope link\nid 102 via 172.16.60.1 dev ge-0-0-2.50 scope link'
check MAIN_ECMP_NHID_WEIGHTED_CLEAN PASS "$GW" "default nhid 103 proto static" "$NH4_WEIGHTED"
check MAIN_PROBE_ERROR_STRING_V6 FAIL "$GW6" "ip -6 route show failed"
NH6=$'id 203 group 201/202\nid 201 via 2001:559:8585:80::1 dev ge-0-0-2.80 scope link\nid 202 via 2001:559:8585:50::1 dev ge-0-0-2.50 scope link'
check MAIN_ECMP_NHID_LEAK_V6 FAIL "$GW6" "default nhid 203 proto static" "$NH6"
check MAIN_ECMP_NHID_UNRESOLVED FAIL "$GW" "default nhid 404 proto static"

# --- the defect the cell exists to catch -----------------------------------
check LEAK_EXACT          FAIL "$GW" "default via 172.16.80.1 dev ge-0-0-2 proto static"
check LEAK_AMONG_OTHERS   FAIL "$GW" "default via 172.16.50.1 dev ge-0-0-2
default via 172.16.80.1 dev ge-0-0-2 metric 200"

# --- THE MIDDLE ROW: the counting form scored every one of these as healthy -
check PROBE_BLIND_EMPTY   FAIL "$GW" ""
check PROBE_BLIND_WS      FAIL "$GW" "   "
check PROBE_BLIND_NEWLINE FAIL "$GW" "
"
# A cell with no needle cannot certify absence either.
check NO_GATEWAY_GIVEN    FAIL ""    "default via 172.16.50.1 dev ge-0-0-2"

# --- the positive control must not be satisfiable by a near-miss -----------
# A different gateway on the same /24 must NOT read as a leak.
check NEAR_MISS_GW        PASS "$GW" "default via 172.16.80.11 dev ge-0-0-2"

# --- fbf_table_holds_default: pick the PBR table by CONTENT, not position ---
checkt() {
	local name="$1" want="$2" gw="$3" routes="$4" got
	if fbf_table_holds_default "$gw" "$routes" "${5:-}"; then got=YES; else got=NO; fi
	if [[ "$got" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-26s -> %s\n' "$name" "$got"
	else
		fail=$((fail + 1)); printf 'FAIL %-26s -> want %s got %s\n' "$name" "$want" "$got"
	fi
}

checkp() {
	local name="$1" want="$2" minimum="$3" output="$4" got verdict
	got="$(fbf_ping_reply_verdict "$minimum" "$output")"
	verdict="${got%% *}"
	if [[ "$verdict" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-26s -> %s\n' "$name" "$verdict"
	else
		fail=$((fail + 1)); printf 'FAIL %-26s -> want %s got %s (%s)\n' "$name" "$want" "$verdict" "$got"
	fi
}

checke() {
	local name="$1" want="$2" family="$3" destination="$4" gateway_mac="$5" minimum="$6" output="$7" got verdict
	got="$(fbf_peer_egress_verdict "$family" "$destination" "$gateway_mac" "$minimum" "$output")"
	verdict="${got%% *}"
	if [[ "$verdict" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-26s -> %s\n' "$name" "$verdict"
	else
		fail=$((fail + 1)); printf 'FAIL %-26s -> want %s got %s (%s)\n' "$name" "$want" "$verdict" "$got"
	fi
}

checkp ISP_B_ECHO_ALL       PASS 3 "5 packets transmitted, 5 received, 0% packet loss"
checkp ISP_B_ECHO_PARTIAL   PASS 3 "5 packets transmitted, 3 received, 40% packet loss"
checkp ISP_B_ECHO_DROPPED   FAIL 3 "5 packets transmitted, 0 received, 100% packet loss"
checkp ISP_B_ECHO_ERROR     FAIL 3 "ping: connect: Network is unreachable"
checkp ISP_B_ECHO_MALFORMED FAIL 3 "incus exec failed while collecting ping output"

# The real ISP-B table.
checkt TBL_HAS_ISP_B_DEFAULT  YES "$GW" "default via 172.16.80.1 dev ge-0-0-2 proto static metric 20
172.16.80.0/24 dev ge-0-0-2 proto kernel scope link"
# The PRE-EXISTING GRE table that sits at priority 31000 on the loss cluster and
# that the old first-match discovery bound instead. Verbatim shape.
checkt TBL_GRE_NOT_ISP_B      NO  "$GW" "default nhid 101 via 10.255.192.41 dev gr-0-0-0 proto static metric 20
10.255.192.40/30 dev gr-0-0-0 proto kernel scope link src 10.255.192.42
local 10.255.192.42 dev gr-0-0-0 proto kernel scope host src 10.255.192.42"
# A table with routes but no default at all.
checkt TBL_NO_DEFAULT         NO  "$GW" "172.16.80.0/24 dev ge-0-0-2 proto kernel scope link"
# Empty / unreadable table must not select.
checkt TBL_EMPTY              NO  "$GW" ""
# The gateway must match as a whole token here too.
checkt TBL_NEAR_MISS_GW       NO  "$GW" "default via 172.16.80.11 dev ge-0-0-2"
# The gateway may appear on a NON-default route without selecting the table.
checkt TBL_GW_ONLY_NONDEFAULT NO  "$GW" "172.16.80.0/24 via 172.16.80.1 dev ge-0-0-2"

checkt TBL_ECMP_INLINE_V4 YES "$GW" "default proto static
    nexthop via 172.16.80.1 dev ge-0-0-2.80 weight 1
    nexthop via 172.16.80.2 dev ge-0-0-2.80 weight 1"
checkt TBL_ECMP_WRONG_V4  NO  "$GW" "default proto static
    nexthop via 172.16.80.2 dev ge-0-0-2.80 weight 1"
checkt TBL_ECMP_NHID_V4   YES "$GW" "default nhid 103 proto static" "$NH4"
checkt TBL_IPV6_DEFAULT   YES "$GW6" "default via 2001:559:8585:80::1 dev ge-0-0-2.80 proto static"
checkt TBL_ECMP_INLINE_V6 YES "$GW6" "default proto static
    nexthop via 2001:559:8585:80::1 dev ge-0-0-2.80 weight 1
    nexthop via 2001:559:8585:80::2 dev ge-0-0-2.80 weight 1"
checkt TBL_ECMP_NHID_V6   YES "$GW6" "default nhid 203 proto static" "$NH6"

V4_CAPTURE_OK=$'12:00:00.000001 02:00:00:00:80:01 > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos 0x68, ttl 64, id 1, offset 0, flags [DF], proto ICMP (1), length 84) 10.0.61.102 > 172.16.80.201: ICMP echo request, id 1, seq 1, length 64\n12:00:00.000002 02:00:00:00:80:01 > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos 0x68, ttl 64, id 2, offset 0, flags [DF], proto ICMP (1), length 84) 10.0.61.102 > 172.16.80.201: ICMP echo request, id 1, seq 2, length 64\n12:00:00.000003 02:00:00:00:80:01 > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos 0x68, ttl 64, id 3, offset 0, flags [DF], proto ICMP (1), length 84) 10.0.61.102 > 172.16.80.201: ICMP echo request, id 1, seq 3, length 64\n12:00:00.000004 02:00:00:00:80:08 > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos 0x0, ttl 64, id 4, offset 0, flags [DF], proto ICMP (1), length 84) 10.0.61.102 > 172.16.80.201: ICMP echo request, id 2, seq 1, length 64\n12:00:00.000005 02:00:00:00:80:08 > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos 0x0, ttl 64, id 5, offset 0, flags [DF], proto ICMP (1), length 84) 10.0.61.102 > 172.16.80.201: ICMP echo request, id 2, seq 2, length 64\n12:00:00.000006 02:00:00:00:80:08 > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos 0x0, ttl 64, id 6, offset 0, flags [DF], proto ICMP (1), length 84) 10.0.61.102 > 172.16.80.201: ICMP echo request, id 2, seq 3, length 64'
V6_CAPTURE_OK=$'12:00:00.000001 02:00:00:00:80:01 > 02:00:00:00:80:ee, ethertype IPv6 (0x86dd), length 98: IP6 (class 0x68, flowlabel 0, hlim 64, next-header ICMPv6 (58), payload length: 64) 2001:559:8585:61::102 > 2001:559:8585:80::201: ICMP6, echo request, id 1, seq 1, length 64\n12:00:00.000002 02:00:00:00:80:01 > 02:00:00:00:80:ee, ethertype IPv6 (0x86dd), length 98: IP6 (class 0x68, flowlabel 0, hlim 64, next-header ICMPv6 (58), payload length: 64) 2001:559:8585:61::102 > 2001:559:8585:80::201: ICMP6, echo request, id 1, seq 2, length 64\n12:00:00.000003 02:00:00:00:80:01 > 02:00:00:00:80:ee, ethertype IPv6 (0x86dd), length 98: IP6 (class 0x68, flowlabel 0, hlim 64, next-header ICMPv6 (58), payload length: 64) 2001:559:8585:61::102 > 2001:559:8585:80::201: ICMP6, echo request, id 1, seq 3, length 64\n12:00:00.000004 02:00:00:00:80:08 > 02:00:00:00:80:ee, ethertype IPv6 (0x86dd), length 98: IP6 (class 0x0, flowlabel 0, hlim 64, next-header ICMPv6 (58), payload length: 64) 2001:559:8585:61::102 > 2001:559:8585:80::201: ICMP6, echo request, id 2, seq 1, length 64\n12:00:00.000005 02:00:00:00:80:08 > 02:00:00:00:80:ee, ethertype IPv6 (0x86dd), length 98: IP6 (class 0x0, flowlabel 0, hlim 64, next-header ICMPv6 (58), payload length: 64) 2001:559:8585:61::102 > 2001:559:8585:80::201: ICMP6, echo request, id 2, seq 2, length 64\n12:00:00.000006 02:00:00:00:80:08 > 02:00:00:00:80:ee, ethertype IPv6 (0x86dd), length 98: IP6 (class 0x0, flowlabel 0, hlim 64, next-header ICMPv6 (58), payload length: 64) 2001:559:8585:61::102 > 2001:559:8585:80::201: ICMP6, echo request, id 2, seq 3, length 64'
V4_CAPTURE_SAME_MAC="${V4_CAPTURE_OK//02:00:00:00:80:08/02:00:00:00:80:01}"
V6_CAPTURE_SAME_MAC="${V6_CAPTURE_OK//02:00:00:00:80:08/02:00:00:00:80:01}"
GW_MAC4="02:00:00:00:80:01"
GW_MAC6="02:00:00:00:80:01"
V4_CAPTURE_WRONG_GATEWAY="${V4_CAPTURE_OK//02:00:00:00:80:01/02:00:00:00:80:02}"
V6_CAPTURE_WRONG_GATEWAY="${V6_CAPTURE_OK//02:00:00:00:80:01/02:00:00:00:80:02}"
checke PEER_V4_EXPECTED_GW   PASS 4 172.16.80.201 "$GW_MAC4" 3 "$V4_CAPTURE_OK"
checke PEER_V4_SAME_MAC      FAIL 4 172.16.80.201 "$GW_MAC4" 3 "$V4_CAPTURE_SAME_MAC"
checke PEER_V4_WRONG_GW      FAIL 4 172.16.80.201 "$GW_MAC4" 3 "$V4_CAPTURE_WRONG_GATEWAY"
checke PEER_V4_WRONG_TARGET  FAIL 4 172.16.80.202 "$GW_MAC4" 3 "$V4_CAPTURE_OK"
checke PEER_V4_NO_CAPTURE    FAIL 4 172.16.80.201 "$GW_MAC4" 3 ""
checke PEER_V6_EXPECTED_GW   PASS 6 2001:559:8585:80::201 "$GW_MAC6" 3 "$V6_CAPTURE_OK"
checke PEER_V6_SAME_MAC      FAIL 6 2001:559:8585:80::201 "$GW_MAC6" 3 "$V6_CAPTURE_SAME_MAC"
checke PEER_V6_WRONG_GW      FAIL 6 2001:559:8585:80::201 "$GW_MAC6" 3 "$V6_CAPTURE_WRONG_GATEWAY"

checki() {
	local name="$1" want="$2" got="${3:-}"
	if [[ "$got" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-26s -> %s\n' "$name" "$got"
	else
		fail=$((fail + 1)); printf 'FAIL %-26s -> want %s got %s\n' "$name" "$want" "$got"
	fi
}

IPMON_STATUS=$'Policy - fbf-fallback (Status: FAIL)\nPolicy - other-policy (Status: PASS)'
ipmon_state="$(fbf_ipmon_policy_state fbf-fallback "$IPMON_STATUS" 2>/dev/null || printf INVALID)"
checki IPMON_FAIL_STATE FAIL "$ipmon_state"
ipmon_state="$(fbf_ipmon_policy_state fbf-fallback 'Policy - fbf-fallback (Status: PASS)' 2>/dev/null || printf INVALID)"
checki IPMON_PASS_STATE PASS "$ipmon_state"
ipmon_state="$(fbf_ipmon_policy_state fbf-fallback 'Policy - other (Status: FAIL)' 2>/dev/null || printf INVALID)"
checki IPMON_MISSING_POLICY INVALID "$ipmon_state"
ipmon_state="$(fbf_ipmon_policy_state fbf-fallback $'Policy - fbf-fallback (Status: FAIL)\nPolicy - fbf-fallback (Status: PASS)' 2>/dev/null || printf INVALID)"
checki IPMON_DUPLICATE_POLICY INVALID "$ipmon_state"

ROUTE_ACTION=$'Instance Prefix Next-Hop State\nISP-B.inet.0 0.0.0.0/0 172.16.50.1 APPLIED'
if fbf_ipmon_route_action_present ISP-B.inet.0 0.0.0.0/0 172.16.50.1 APPLIED "$ROUTE_ACTION"; then got=YES; else got=NO; fi
checki IPMON_FALLBACK_ACTION YES "$got"
if fbf_ipmon_route_action_present ISP-B.inet.0 0.0.0.0/0 172.16.50.1 PENDING "$ROUTE_ACTION"; then got=YES; else got=NO; fi
checki IPMON_PENDING_ACTION NO "$got"
if fbf_ipmon_route_action_present ISP-B.inet.0 0.0.0.0/0 172.16.80.1 APPLIED "$ROUTE_ACTION"; then got=YES; else got=NO; fi
checki IPMON_WRONG_NEXT_HOP NO "$got"

checkv() {
	local name="$1" want="$2" old="$3" new="$4" routes="$5" got
	got="$(fbf_table_transition_verdict "$old" "$new" "$routes" "${6:-}")"
	checki "$name" "$want" "${got%% *}"
}
checkv TABLE_FALLBACK_PASS PASS 172.16.80.1 172.16.50.1 \
	"default via 172.16.50.1 dev wan50 proto static"
checkv TABLE_OLD_GATEWAY_FAIL FAIL 172.16.80.1 172.16.50.1 \
	"default via 172.16.80.1 dev wan80 proto static"
checkv TABLE_BOTH_GATEWAYS_FAIL FAIL 172.16.80.1 172.16.50.1 \
	"default proto static
    nexthop via 172.16.80.1 dev wan80 weight 1
    nexthop via 172.16.50.1 dev wan50 weight 1"
checkv TABLE_NO_FALLBACK_FAIL FAIL 172.16.80.1 172.16.50.1 \
	"default via 172.16.60.1 dev wan60 proto static"
checkv TABLE_EMPTY_UNKNOWN UNKNOWN 172.16.80.1 172.16.50.1 ""
checkv TABLE_UNREADABLE_UNKNOWN UNKNOWN 172.16.80.1 172.16.50.1 \
	"route probe failed"

neighbor="$(fbf_neighbor_snapshot 172.16.80.1 wan80 '[]' 2>/dev/null || printf INVALID)"
checki NEIGHBOR_ABSENT ABSENT "$neighbor"
neighbor="$(fbf_neighbor_snapshot 172.16.80.1 wan80 \
	'[{ "dst":"172.16.80.1", "dev":"wan80", "lladdr":"02:00:00:00:80:01", "state":"PERMANENT", "flags":["router"] }]' \
	2>/dev/null || printf INVALID)"
checki NEIGHBOR_PERMANENT_ROUTER $'PRESENT\t02:00:00:00:80:01\tPERMANENT\trouter' "$neighbor"
neighbor="$(fbf_neighbor_snapshot 172.16.80.1 wan80 \
	'[{ "dst":"172.16.80.1", "dev":"wan80", "lladdr":"02:00:00:00:80:01", "state":"REACHABLE", "flags":["unknown"] }]' \
	2>/dev/null || printf INVALID)"
checki NEIGHBOR_UNKNOWN_FLAG_INVALID INVALID "$neighbor"
neighbor="$(fbf_neighbor_snapshot 172.16.80.1 wan80 \
	'[{ "dst":"172.16.80.1", "dev":"wan80", "state":"FAILED" }, { "dst":"172.16.80.1", "dev":"wan80", "state":"FAILED" }]' \
	2>/dev/null || printf INVALID)"
checki NEIGHBOR_DUPLICATE_INVALID INVALID "$neighbor"

fallback_capture() {
	local marked_source="${1:-172.16.50.8}" marked_tos="${2:-0x68}"
	local marked_id="${3:-44001}" control_id="${4:-44002}"
	local control_source="${5:-172.16.50.8}" marked_ip_id="${6:-}" control_ip_id="${7:-}"
	local seq marked_packet_id control_packet_id
	for seq in 1 2 3; do
		marked_packet_id="$seq"
		control_packet_id="$seq"
		[[ -z "$marked_ip_id" ]] || marked_packet_id="$marked_ip_id"
		[[ -z "$control_ip_id" ]] || control_packet_id="$control_ip_id"
		printf '12:00:00.00000%s 02:00:00:00:80:01 > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos %s, ttl 64, id %s, offset 0, flags [DF], proto ICMP (1), length 84) %s > 172.16.80.201: ICMP echo request, id %s, seq %s, length 64\n' \
			"$seq" "$marked_tos" "$marked_packet_id" "$marked_source" "$marked_id" "$seq"
		printf '12:00:01.00000%s 02:00:00:00:80:08 > 02:00:00:00:80:ee, ethertype IPv4 (0x0800), length 98: IP (tos 0x0, ttl 64, id %s, offset 0, flags [DF], proto ICMP (1), length 84) %s > 172.16.80.201: ICMP echo request, id %s, seq %s, length 64\n' \
			"$seq" "$control_packet_id" "$control_source" "$control_id" "$seq"
	done
}
checkf() {
	local name="$1" want="$2" source="${3:-172.16.50.8}" tos="${4:-0x68}"
	local control_source="${5:-172.16.50.8}" got
	got="$(fbf_peer_fallback_verdict 172.16.80.201 3 44001 44002 172.16.50.8 \
		"$(fallback_capture "$source" "$tos" 44001 44002 "$control_source")")"
	checki "$name" "$want" "${got%% *}"
}

checkf FALLBACK_SOURCE_NAT_PASS PASS
checkf FALLBACK_OLD_SOURCE_FAIL FAIL 172.16.80.8
checkf FALLBACK_WRONG_DSCP_FAIL FAIL 172.16.50.8 0x0
checkf FALLBACK_CONTROL_SOURCE_FAIL FAIL 172.16.50.8 0x68 172.16.80.8
stale_ids="$(fallback_capture 172.16.50.8 0x68 44003 44004 172.16.50.8 44001 44002)"
verdict="$(fbf_peer_fallback_verdict 172.16.80.201 3 44001 44002 172.16.50.8 "$stale_ids")"
checki FALLBACK_STALE_IDS_FAIL FAIL "${verdict%% *}"
verdict="$(fbf_peer_fallback_verdict 172.16.80.201 3 44001 44002 172.16.50.8 '')"
checki FALLBACK_NO_CAPTURE_FAIL FAIL "${verdict%% *}"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]

