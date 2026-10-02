#!/usr/bin/env bash
# Verdict helpers for the #1827 two-upstream FBF steering smoke (#6936).
#
# WHY THIS EXISTS
#
# `test-fbf-steering.sh` asserts, among other things, that the ISP-B default
# route does NOT leak into the main routing table — the pre-PR-2 pollution
# this smoke exists to catch. That cell was written as:
#
#     MAIN_DEFAULTS="$(incus exec "$TARGET" -- sh -c \
#         "ip route show default | grep -c 'via ${ISP_B_GW4}'" || true)"
#     [[ "${MAIN_DEFAULTS:-0}" -eq 0 ]] || fail "ISP-B default leaked ..."
#
# and it FAILS TO A VALUE INDISTINGUISHABLE FROM HEALTHY. Measured, three
# inputs collapse onto the same verdict:
#
#     main table has an unrelated default   -> "0" -> PASS   (correct)
#     probe produced NO OUTPUT AT ALL       -> ""  -> PASS   (WRONG)
#     main table holds the ISP-B default    -> "1" -> FAIL   (correct)
#
# The middle row is the defect. `grep -c` prints "0" and exits 1 when it
# matches nothing, so `|| true` is load-bearing and correct; but if the probe
# never ran, or ran and emitted nothing, the substitution is EMPTY and
# `${MAIN_DEFAULTS:-0}` silently supplies the healthy value. The cell then
# certifies "no leak" on the strength of having looked at nothing.
#
# (One neighbouring input does NOT collapse: non-numeric output, e.g. an
# incus error string, makes bash's `[[ -eq ]]` fail the comparison, so garbage
# reports FAIL rather than PASS. The hole is specifically the empty case.)
#
# THE FIX: A TOTAL VERDICT WITH AN INTRINSIC POSITIVE CONTROL
#
# Take the route text rather than a count, and make every input class yield
# exactly one verdict — including "the probe saw nothing", which becomes a
# FAIL because an absence cannot be certified by an instrument that returned
# no reading. The positive control is intrinsic rather than bolted on: the
# main table in this venue always carries the ISP-A default (the smoke's own
# PING_DST defaults to the ISP-A gateway and expects it to answer), so
# non-empty output is itself the evidence that the probe could read the table
# it is being asked to clear. A negative cell whose instrument cannot be shown
# to work is not a negative result.
#
# Depends on nothing but bash, so fbf-steering-selftest.sh
# (`make test-fbf-steering-lib`) is hermetic — no cluster.

# _fbf_default_routes <ip-route-show-output>
#
# Keep only default records and their inline ECMP `nexthop` rows. Other route
# entries may follow the default in a table dump and are not steering evidence.
_fbf_default_routes() {
	awk '
		NF == 0 { next }
		$1 == "default" { in_default = 1; print; next }
		$1 == "nexthop" && in_default { print; next }
		{ in_default = 0 }
	' <<<"${1:-}"
}

# _fbf_default_route_text_valid <default-route-output>
#
# A nonempty error string is not a route-table positive control. Accept only
# `ip route show default` records and their inline ECMP members.
_fbf_default_route_text_valid() {
	local routes="${1:-}"
	[[ -n "${routes//[[:space:]]/}" ]] || return 1
	awk '
		NF == 0 { next }
		$1 == "default" {
			saw_default = 1
			in_default = 1
			for (i = 2; i <= NF; i++) {
				if ($i == "via" || $i == "dev" || $i == "nhid" ||
				    $i == "proto" || $i == "scope" || $i == "metric" ||
				    $i == "table" || $i == "src" || $i == "blackhole" ||
				    $i == "unreachable" || $i == "prohibit" || $i == "throw" ||
				    $i == "encap" || $i == "onlink") {
					has_route_attribute = 1
				}
			}
			next
		}
		$1 == "nexthop" && in_default {
			saw_inline_nexthop = 1
			next
		}
		{ invalid = 1; in_default = 0 }
		END {
			exit !(saw_default && !invalid && (has_route_attribute || saw_inline_nexthop))
		}
	' <<<"$routes"
}

# _fbf_default_route_has_gateway <gateway> <default-route-output>
_fbf_default_route_has_gateway() {
	local gw="${1:-}" routes="${2:-}"
	[[ -n "${gw//[[:space:]]/}" && -n "${routes//[[:space:]]/}" ]] || return 1
	awk -v gw="$gw" '
		function has_gateway(    i) {
			for (i = 1; i < NF; i++) if ($i == "via" && $(i+1) == gw) return 1
			return 0
		}
		NF == 0 { next }
		$1 == "default" {
			in_default = 1
			if (has_gateway()) found = 1
			next
		}
		$1 == "nexthop" && in_default {
			if (has_gateway()) found = 1
			next
		}
		{ in_default = 0 }
		END { exit !found }
	' <<<"$routes"
}

# _fbf_default_route_nhids <default-route-output>
_fbf_default_route_nhids() {
	awk '$1 == "default" {
		for (i = 1; i < NF; i++) if ($i == "nhid" && $(i+1) ~ /^[0-9]+$/) print $(i+1)
	}' <<<"${1:-}"
}

# _fbf_nexthop_graph_contains <root-id> <gateway> <ip-nexthop-show-output>
#
# Resolve kernel nexthop-group IDs so ECMP defaults do not hide a member from
# the route text. Exit 2 means the referenced graph could not be inspected.
_fbf_nexthop_graph_contains() {
	local root="${1:-}" gw="${2:-}" nexthops="${3:-}"
	[[ "$root" =~ ^[0-9]+$ && -n "${gw//[[:space:]]/}" && -n "${nexthops//[[:space:]]/}" ]] || return 2
	awk -v root="$root" -v gw="$gw" '
		function reaches(id,    n, members, i) {
			if (visiting[id]) { unknown = 1; return 0 }
			if (!(id in known)) { unknown = 1; return 0 }
			visiting[id] = 1
			if (id in gateways) {
				i = gateways[id] == gw
				delete visiting[id]
				return i
			}
			if (id in groups) {
				n = split(groups[id], members, "/")
				for (i = 1; i <= n; i++) {
					sub(/,.*$/, "", members[i])
					if (reaches(members[i])) { delete visiting[id]; return 1 }
				}
			}
			delete visiting[id]
			return 0
		}
		$1 == "id" && NF >= 2 {
			id = $2
			known[id] = 1
			for (i = 3; i < NF; i++) {
				if ($i == "via") gateways[id] = $(i+1)
				if ($i == "group") groups[id] = $(i+1)
			}
		}
		END {
			if (reaches(root)) exit 0
			if (unknown) exit 2
			exit 1
		}
	' <<<"$nexthops"
}

# _fbf_default_route_gateway_status <gateway> <default-route-output> <nexthops>
#   0 = gateway found; 1 = complete route evidence, gateway absent;
#   2 = an nhid reference could not be resolved.
_fbf_default_route_gateway_status() {
	local gw="${1:-}" routes="${2:-}" nexthops="${3:-}"
	local ids id rc unresolved=0
	if _fbf_default_route_has_gateway "$gw" "$routes"; then
		return 0
	fi
	ids="$(_fbf_default_route_nhids "$routes")"
	for id in $ids; do
		if _fbf_nexthop_graph_contains "$id" "$gw" "$nexthops"; then
			return 0
		else
			rc=$?
		fi
		if (( rc == 2 )); then unresolved=1; fi
	done
	if (( unresolved )); then return 2; fi
	return 1
}

# fbf_main_default_leak_verdict <isp_b_gateway> <ip-route-show-default-output> [ip-nexthop-show-output]
#
# Print exactly one line: "PASS <message>" or "FAIL <message>". A successful
# observation requires parseable default-route data and resolved nhid groups;
# errors, blind probes and ambiguous route output fail closed.
fbf_main_default_leak_verdict() {
	local gw="${1:-}" routes="${2:-}" nexthops="${3:-}" defaults status count
	if [[ -z "${gw//[[:space:]]/}" ]]; then
		printf 'FAIL %s\n' "main-table leak check: no ISP-B gateway supplied — the cell has nothing to look for and cannot certify absence"
		return 0
	fi
	if [[ -z "${routes//[[:space:]]/}" ]]; then
		printf 'FAIL %s\n' "main-table leak check: 'ip route show default' returned NOTHING — the probe is blind, so the absence of the ISP-B default is unproven"
		return 0
	fi
	defaults="$(_fbf_default_routes "$routes")"
	if ! _fbf_default_route_text_valid "$defaults"; then
		printf 'FAIL %s\n' "main-table leak check: ip route returned no valid default-route records — output cannot certify absence of ISP-B: $(tr '\n' ';' <<<"$routes")"
		return 0
	fi
	if _fbf_default_route_gateway_status "$gw" "$defaults" "$nexthops"; then
		printf 'FAIL %s\n' "ISP-B default leaked into the MAIN table — defaults seen: $(tr '\n' ';' <<<"$defaults")"
		return 0
	else
		status=$?
	fi
	if (( status == 2 )); then
		printf 'FAIL %s\n' "main-table leak check: an nhid default could not be resolved; ISP-B leakage cannot be ruled out"
		return 0
	fi
	count="$(awk '$1 == "default" { n++ } END { print n+0 }' <<<"$defaults")"
	printf 'PASS %s\n' "main table returned $count valid default route(s), none via ${gw}"
}

# fbf_table_holds_default <gateway> <ip-route-show-table-output> [ip-nexthop-show-output]
#
# Exit 0 iff a default route or one of its ECMP/nexthop-group members uses the
# exact gateway. Other routes in the table do not participate in the verdict.
fbf_table_holds_default() {
	local gw="${1:-}" routes="${2:-}" nexthops="${3:-}" defaults
	[[ -n "${gw//[[:space:]]/}" && -n "${routes//[[:space:]]/}" ]] || return 1
	defaults="$(_fbf_default_routes "$routes")"
	_fbf_default_route_text_valid "$defaults" || return 1
	_fbf_default_route_gateway_status "$gw" "$defaults" "$nexthops"
}

# fbf_ping_reply_verdict <minimum-replies> <ping-output>
#
# A term hit proves only that a packet matched the rule. A reply from the
# ISP-B-only test target proves the marked packet was forwarded and returned.
# Errors and output without a packet summary are never treated as success.
fbf_ping_reply_verdict() {
	local minimum="${1:-}" output="${2:-}" transmitted received minimum_num
	if [[ ! "$minimum" =~ ^[0-9]+$ ]] || (( 10#$minimum == 0 )); then
		printf 'FAIL %s\n' "ISP-B echo check: invalid minimum reply count"
		return 0
	fi
	minimum_num=$((10#$minimum))
	if [[ "$output" =~ ([0-9]+)[[:space:]]+packets[[:space:]]+transmitted,[[:space:]]+([0-9]+)[[:space:]]+(packets[[:space:]]+)?received ]]; then
		transmitted="${BASH_REMATCH[1]}"
		received="${BASH_REMATCH[2]}"
	else
		printf 'FAIL %s\n' "ISP-B echo check: ping output has no parseable packet summary"
		return 0
	fi
	if (( 10#$received > 10#$transmitted )); then
		printf 'FAIL %s\n' "ISP-B echo check: malformed summary reports more replies than transmissions"
		return 0
	fi
	if (( 10#$received < minimum_num )); then
		printf 'FAIL %s\n' "ISP-B echo check received only ${received}/${transmitted} replies; term hits alone do not prove forwarding"
		return 0
	fi
	printf 'PASS %s\n' "ISP-B echo check received ${received}/${transmitted} replies"
}

# fbf_peer_egress_verdict <family:4|6> <destination> <gateway-mac> <minimum> <tcpdump-output>
#
# Score the managed peer's VLAN-80 capture, not a firewall parent-interface
# capture that may be blind to AF_XDP traffic. Marked FBF requests must arrive
# from the resolved ISP-B gateway MAC; unmarked controls use the main table's
# connected route and must arrive from a different Ethernet source.
fbf_peer_egress_verdict() {
	local family="${1:-}" destination="${2:-}" gateway_mac="${3:-}" minimum="${4:-}" output="${5:-}"
	local minimum_num stats marked unmarked wrong_gateway controls_via_gateway bad_mac
	gateway_mac="${gateway_mac,,}"
	if [[ "$family" != 4 && "$family" != 6 ]] ||
	    [[ -z "${destination//[[:space:]]/}" ]] ||
	    [[ ! "$gateway_mac" =~ ^[[:xdigit:]][[:xdigit:]](:[[:xdigit:]][[:xdigit:]]){5}$ ]] ||
	    [[ ! "$minimum" =~ ^[0-9]+$ ]] || (( 10#$minimum == 0 )); then
		printf 'FAIL %s\n' "VLAN-80 peer capture: invalid family, destination, gateway MAC or minimum count"
		return 0
	fi
	minimum_num=$((10#$minimum))
	stats="$(awk -v family="$family" -v destination="$destination" -v gateway_mac="$gateway_mac" '
		function valid_mac(mac) {
			return mac ~ /^[[:xdigit:]][[:xdigit:]]:[[:xdigit:]][[:xdigit:]]:[[:xdigit:]][[:xdigit:]]:[[:xdigit:]][[:xdigit:]]:[[:xdigit:]][[:xdigit:]]:[[:xdigit:]][[:xdigit:]]$/
		}
		function record_packet(kind,    mac) {
			mac = $2
			sub(/,$/, "", mac)
			if (!valid_mac(mac)) { bad_mac = 1; return }
			mac = tolower(mac)
			if (kind == "marked") {
				marked++
				if (mac != gateway_mac) wrong_gateway = 1
			} else {
				unmarked++
				if (mac == gateway_mac) controls_via_gateway = 1
			}
		}
		family == "4" && /IP \(tos 0x6[89ab][,)]/ && /ICMP echo request/ &&
		    index($0, " > " destination ":") { record_packet("marked") }
		family == "4" && (/IP \(tos 0x0[,)]/ || /IP \(tos 0x00[,)]/) &&
		    /ICMP echo request/ && index($0, " > " destination ":") { record_packet("unmarked") }
		family == "6" && /IP6 \(class 0x6[89ab][,)]/ && /ICMP6, echo request/ &&
		    index($0, " > " destination ":") { record_packet("marked") }
		family == "6" && (/IP6 \(class 0x0[,)]/ || /IP6 \(class 0x00[,)]/) &&
		    /ICMP6, echo request/ && index($0, " > " destination ":") { record_packet("unmarked") }
		END {
			print marked+0, unmarked+0, wrong_gateway+0, controls_via_gateway+0, bad_mac+0
		}
	' <<<"$output")"
	read -r marked unmarked wrong_gateway controls_via_gateway bad_mac <<<"$stats"
	if (( bad_mac != 0 )); then
		printf 'FAIL %s\n' "VLAN-80 peer capture has an echo request without an Ethernet source address"
		return 0
	fi
	if (( marked < minimum_num || unmarked < minimum_num )); then
		printf 'FAIL %s\n' "VLAN-80 peer capture saw ${marked} marked and ${unmarked} unmarked IPv${family} echo requests for ${destination}; egress comparison is under-sampled"
		return 0
	fi
	if (( wrong_gateway != 0 )); then
		printf 'FAIL %s\n' "marked IPv${family} requests did not arrive from ISP-B gateway MAC ${gateway_mac}"
		return 0
	fi
	if (( controls_via_gateway != 0 )); then
		printf 'FAIL %s\n' "unmarked IPv${family} controls also arrived from ISP-B gateway MAC ${gateway_mac}; next-hop comparison is unproven"
		return 0
	fi
	printf 'PASS %s\n' "VLAN-80 peer capture saw marked IPv${family} requests from ISP-B gateway ${gateway_mac} and direct-source unmarked controls"
}
