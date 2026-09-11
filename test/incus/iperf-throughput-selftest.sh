#!/usr/bin/env bash
#
# #6897 — self-test for test/incus/iperf-throughput-lib.sh.
#
# The defect this guards is a MISSING CELL, not a wrong number, so the
# load-bearing assertion is TOTALITY: every input class must yield exactly
# one verdict. A test that only checked the arithmetic would have passed
# against the buggy version, because the buggy version's arithmetic was fine
# for the one unit it recognised.
#
# Hermetic — sources the lib and feeds it literal [SUM] lines. No incus, no
# cluster, no network, no iperf3.
#
# Usage: ./test/incus/iperf-throughput-selftest.sh   (rc 0 = all pass)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${SCRIPT_DIR}/iperf-throughput-lib.sh"
[[ -f "$LIB" ]] || { echo "FAIL: lib not found at $LIB" >&2; exit 1; }
# shellcheck source=/dev/null
source "$LIB"

PASS=0
ok()   { PASS=$((PASS + 1)); echo "PASS ($PASS): $*"; }
bad()  { echo "FAIL: $*" >&2; exit 1; }

# --- unit normalisation -------------------------------------------------
# Real [SUM] sender lines. The Mbits row is the #6897 case: the old parser
# matched only "Gbits" and silently produced no cell for it.
check_rate() { # <desc> <expected> <line>
	local got; got="$(iperf_sum_rate_gbps "$3")"
	[[ "$got" == "$2" ]] || bad "$1: want $2 Gbps, got '${got:-<empty>}' from: $3"
	ok "$1 -> $got Gbps"
}
check_rate "Gbits normalises"  "22.9000"  '[SUM]   0.00-120.00  sec   320 GBytes  22.9 Gbits/sec   12  sender'
check_rate "Mbits normalises"  "0.0860"   '[SUM]   0.00-120.00  sec  1.20 GBytes   86.0 Mbits/sec   0   sender'
check_rate "Kbits normalises"  "0.000500" '[SUM]   0.00-10.00   sec  0.00 GBytes  500 Kbits/sec    0   sender'
check_rate "integer rate"      "10.0000"  '[SUM]   0.00-10.00   sec   12 GBytes    10 Gbits/sec    0   sender'

got="$(iperf_sum_rate_gbps '[SUM]   0.00-120.00  sec  no rate here  sender')"
[[ -z "$got" ]] || bad "a line with no rate/unit pair must yield nothing, got '$got'"
ok "unrecognised line yields no rate"

got="$(iperf_sum_rate_gbps '')"
[[ -z "$got" ]] || bad "an empty line must yield nothing, got '$got'"
ok "empty line yields no rate"

# --- TOTALITY: every input class emits exactly one verdict ---------------
# This is the #6897 regression guard. Under the pre-fix logic the Mbits row
# and the unparseable row emitted NOTHING.
check_verdict() { # <desc> <want-status> <min> <line>
	local out status n
	out="$(iperf_throughput_verdict "$3" "$4")"
	n="$(printf '%s\n' "$out" | grep -c .)"
	[[ "$n" == "1" ]] || bad "$1: want exactly ONE verdict line, got $n:
$out"
	status="${out%% *}"
	[[ "$status" == "$2" ]] || bad "$1: want $2, got $status ($out)"
	ok "$1 -> $status"
}
check_verdict "healthy Gbits run passes"      PASS 5 '[SUM] 0.00-120.00 sec 320 GBytes 22.9 Gbits/sec 12 sender'
check_verdict "sub-Gbit run FAILS not silent" FAIL 5 '[SUM] 0.00-120.00 sec 1.20 GBytes 86.0 Mbits/sec 0 sender'
check_verdict "Gbits below the floor fails"   FAIL 5 '[SUM] 0.00-120.00 sec 40 GBytes 2.5 Gbits/sec 0 sender'
check_verdict "exactly at the floor passes"   PASS 5 '[SUM] 0.00-120.00 sec 70 GBytes 5.0 Gbits/sec 0 sender'
check_verdict "unparseable line FAILS"        FAIL 5 '[SUM] 0.00-120.00 sec garbage sender'
check_verdict "absent [SUM] line FAILS"       FAIL 5 ''

# A sub-Gbit result must be reported with its REAL value, not as "0" and not
# as an absence — the number is what tells an operator how far it fell.
out="$(iperf_throughput_verdict 5 '[SUM] 0.00-120.00 sec 1.20 GBytes 86.0 Mbits/sec 0 sender')"
[[ "$out" == *"0.0860 Gbps"* ]] || bad "a sub-Gbit verdict must carry the normalised value, got: $out"
ok "sub-Gbit verdict carries its measured value"

# The absent-line and unparseable verdicts must be DISTINGUISHABLE, so a
# reader can tell "iperf3 produced nothing" from "iperf3 produced something
# this parser did not understand" — different causes, different next step.
a="$(iperf_throughput_verdict 5 '')"
b="$(iperf_throughput_verdict 5 '[SUM] garbage')"
[[ "$a" != "$b" ]] || bad "absent and unparseable must not render identically"
[[ "$a" == *"no measurement at all"* ]] || bad "absent verdict must say so, got: $a"
[[ "$b" == *"unparseable"* ]] || bad "unparseable verdict must say so, got: $b"
ok "absent and unparseable verdicts are distinguishable"

# --- WIRING + the #7673 PORT AGREEMENT, for EVERY HA smoke with a throughput cell ---
# Binding the lib alone would leave a green if someone deleted the CALL from a
# production path -- the shape that has repeatedly produced false confidence. A
# behavioural probe of these harnesses needs a cluster, so these are structural
# guards on each caller: the wiring exists, not that the surrounding logic is
# correct.
#
# #9690/#9691: these cells used to read test-failover.sh ONLY, and its four
# siblings kept both defects it had fixed: a Gbits-only parse with no else
# (#6897), and the 5201 default port that cos-iperf-config.set shapes to 100m
# (#7673). The list is every harness that starts an iperf3 client against
# IPERF_TARGET and judges its throughput.
#
# The port cells assert the AGREEMENT between each harness and the CoS set rather
# than pinning either to a literal. Pinning the port alone would encode which
# side is trusted, and the side that was wrong in #7673 is the one nobody
# suspected. Port to class is read in two steps (port to term, term to class)
# rather than assuming term 11.
COS_SET="$(dirname "$0")/cos-iperf-config.set"
SMOKES=(test-failover.sh test-double-failover.sh test-chained-crash.sh test-active-active.sh test-stress-failover.sh)
for smoke in "${SMOKES[@]}"; do
	f="${SCRIPT_DIR}/${smoke}"
	[[ -f "$f" ]] || bad "$smoke not found at $f"

	grep -q 'source "${SCRIPT_DIR}/iperf-throughput-lib.sh"' "$f" \
		|| bad "$smoke does not source iperf-throughput-lib.sh"
	grep -q 'iperf_throughput_verdict "$MIN_THROUGHPUT" "$sum_line"' "$f" \
		|| bad "$smoke does not call iperf_throughput_verdict -- its throughput cell can go silent again (#6897/#9690)"
	# The catch-all is what makes the caller total. Without it an unknown status
	# falls through the case and emits nothing -- #6897 one level up.
	awk '/^throughput_verdict=/,/^esac$/' "$f" | grep -qE '^\*\)[[:space:]]+fail ' \
		|| bad "$smoke: the throughput verdict case has no catch-all '*) fail' -- an unhandled status would emit no cell"
	# No inline Gbits-only parse may come back, in either the grep -oP or the
	# grep -oiE spelling; it silently reintroduces the value that matched no branch.
	if grep -vE '^[[:space:]]*#' "$f" | grep -qE "grep -o[a-zA-Z]* ['\"][^'\"]*Gbits"; then
		bad "$smoke: an inline Gbits-only throughput parse is back"
	fi
	ok "$smoke: sources the lib, calls the total verdict with a catch-all, no inline Gbits parse"

	grep -q -- '-p ${IPERF_PORT}' "$f" \
		|| bad "$smoke does not pass -p \${IPERF_PORT} to iperf3 -- it measures the 5201 default, the 100m-shaped class (#7673/#9691)"
	port=$(sed -n 's/^IPERF_PORT="\${IPERF_PORT:-\([0-9]*\)}"/\1/p' "$f")
	[ -n "$port" ] || bad "could not read the IPERF_PORT default out of $smoke -- this cell would otherwise pass having checked nothing"
	term=$(sed -n "s/^set firewall family inet filter bandwidth-output term \([0-9]*\) from destination-port ${port}$/\1/p" "$COS_SET" | head -1)
	[ -n "$term" ] || bad "$smoke: port $port matches no 'from destination-port' term in cos-iperf-config.set -- the smoke would be measuring an unclassified path"
	fc=$(sed -n "s/^set firewall family inet filter bandwidth-output term ${term} then forwarding-class \(.*\)$/\1/p" "$COS_SET" | head -1)
	[ -n "$fc" ] || bad "$smoke: filter term $term has no 'then forwarding-class' line -- cannot tell which class port $port lands in"
	sched=$(sed -n "s/^set class-of-service scheduler-maps [^ ]* forwarding-class $fc scheduler \(.*\)$/\1/p" "$COS_SET" | head -1)
	[ -n "$sched" ] || bad "$smoke: forwarding-class $fc has no scheduler in the scheduler-map -- cannot tell whether it is shaped"
	if grep -q "^set class-of-service schedulers $sched transmit-rate" "$COS_SET"; then
		bad "$smoke: iperf port $port lands in $fc/$sched, which HAS a transmit-rate -- the throughput gate is measuring a deliberately shaped class (#7673/#9691)"
	fi
	ok "$smoke: -p \${IPERF_PORT} default $port -> term $term -> $fc/$sched, unshaped"
done

echo
echo "iperf-throughput-lib self-test: $PASS passed"
