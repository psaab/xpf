#!/usr/bin/env bash
# Hermetic self-test for test/incus/fbf-steering-lib.sh (#6936).
#
# No cluster, no incus, no network. Runs in `make test-fbf-steering-lib`.
#
# The row that matters is PROBE_BLIND. Under the counting form this smoke
# shipped with, that input produced the same verdict as a healthy table, which
# is why the defect was invisible to review: only a table that includes the
# middle row can distinguish "there is no leak" from "I could not look".
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

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]

