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

# fbf_main_default_leak_verdict <isp_b_gw> <ip-route-show-default-output>
#
#   Print exactly one line: "PASS <message>" or "FAIL <message>".
#
#   TOTAL BY CONSTRUCTION — every path prints, so this cell can never be the
#   silent hole that the counting form was. Callers map the verdict onto their
#   own pass/fail handling with a catch-all default.
fbf_main_default_leak_verdict() {
	local gw="$1" routes="$2"
	if [[ -z "${gw//[[:space:]]/}" ]]; then
		printf 'FAIL %s\n' "main-table leak check: no ISP-B gateway supplied — the cell has nothing to look for and cannot certify absence"
		return 0
	fi
	if [[ -z "${routes//[[:space:]]/}" ]]; then
		printf 'FAIL %s\n' "main-table leak check: 'ip route show default' returned NOTHING — the probe is blind, so the absence of the ISP-B default is unproven (this venue always carries the ISP-A default; empty means the probe failed, not that the table is clean)"
		return 0
	fi
	# Exact-token match on the field FOLLOWING "via". A substring match
	# (what the original `grep -c "via ${ISP_B_GW4}"` did) reports a leak for
	# any longer address sharing the prefix — `via 172.16.80.11` reads as
	# `via 172.16.80.1`. That direction is fail-CLOSED, so it costs a false
	# alarm rather than a silent pass, but it is still wrong and the selftest
	# pins it (NEAR_MISS_GW). awk avoids having to regex-escape the dots.
	if awk -v gw="$gw" '{for (i = 1; i < NF; i++) if ($i == "via" && $(i+1) == gw) found = 1} END {exit !found}' <<<"$routes"; then
		printf 'FAIL %s\n' "ISP-B default leaked into the MAIN table (pre-PR-2 pollution) — defaults seen: $(tr '\n' ';' <<<"$routes")"
		return 0
	fi
	printf 'PASS %s\n' "main table holds $(grep -c . <<<"$routes") default route(s), none via ${gw}"
}

# fbf_table_holds_default <gw> <ip-route-show-table-output>
#
#   Exit 0 iff the table's routes contain a default via exactly <gw>.
#
#   Used to pick the RIGHT PBR table out of the priority band. The smoke used
#   to take the FIRST rule in the former 31000+ band and stop:
#
#       ip rule show | awk -F'lookup ' '$1 ~ /^31[0-9][0-9][0-9]:/ {print $2; exit}'
#
#   A GRE rule already sat at priority 31000 on
#   loss:xpf-userspace-fw0:
#
#       31000: from all to 10.255.192.40/30 iif ge-0-0-1 lookup 488570
#
#   That exposed the old band overlap: PBR now uses 29000-29999 (#11319), so
#   this GRE rule is not a PBR candidate. The harness still selects by CONTENT
#   instead of position because multiple current PBR rules can target
#   different tables. Exact-token match, so `via 172.16.80.11` is not `via
#   172.16.80.1` (the same near-miss the leak verdict fixes).
fbf_table_holds_default() {
	local gw="$1" routes="$2"
	[[ -n "${gw//[[:space:]]/}" ]] || return 1
	[[ -n "${routes//[[:space:]]/}" ]] || return 1
	awk -v gw="$gw" '
		/^default/ { for (i = 1; i < NF; i++) if ($i == "via" && $(i+1) == gw) found = 1 }
		END { exit !found }' <<<"$routes"
}
