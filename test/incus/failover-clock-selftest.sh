#!/usr/bin/env bash
# Hermetic tests for the crash-failover clock precondition (#18614; the
# #11872 resync survives only as the XPF_FAILOVER_CLOCK_RESYNC=1 escape).
# No incus, cluster, network, real sleeping or system clock changes: `incus`,
# `date` and `sleep` are shell functions over a virtual clock in a file.
#
# The load-bearing property is that the measured path NEVER SETS A CLOCK. It is
# asserted three ways, because each one alone misses a mutation the others see:
#   1. dynamically: the mock `incus` admits exactly two node commands on the
#      measured path (`date +%s.%N`, `timeout 10 chronyc -n tracking`, and
#      `cat /proc/uptime` for the log line) and
#      records everything else, so a re-added `date -s` anywhere under
#      failover_clock_precondition reds every measured cell;
#   2. by mutation: a copy of the library with a silent resync spliced into
#      the measured path must be caught by (1) -- the detector is shown to fire;
#   3. statically: no harness under test/incus/ runs a clock-setting command
#      outside the escape, and none calls failover_resync_node_clocks directly
#      (which would bypass the banner and the ledger flag).
# SC2329: each scenario redefines the fc_node_state mock, which the mock incus
# calls. SC2016: the mutation splice is a literal line of shell.
# shellcheck disable=SC2329,SC2016
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Overridable so a mutation run can point this at a mutated copy.
FAILOVER_CLOCK_LIB="${FAILOVER_CLOCK_LIB:-${SCRIPT_DIR}/failover-clock-lib.sh}"
# shellcheck source=test/incus/failover-clock-lib.sh
source "$FAILOVER_CLOCK_LIB"

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1" >&2; FAIL=$((FAIL + 1)); }

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
FC_CALLS="${TMP_DIR}/incus-calls"   # every node command, "<node> <cmd>"
FC_WRITES="${TMP_DIR}/writes"       # every command outside the read whitelist
FC_VT="${TMP_DIR}/vclock"           # virtual host clock, epoch seconds
FC_HOSTREADS="${TMP_DIR}/hostreads" # one line per formatted host UTC reading
FC_BASE=1793440000

# ── the virtual world ────────────────────────────────────────────────────
fc_vt() { cat "$FC_VT"; }
fc_advance() {
	awk -v t="$(fc_vt)" -v d="$1" 'BEGIN { printf "%.6f\n", t + d }' >"${FC_VT}.n" &&
		mv "${FC_VT}.n" "$FC_VT"
}
# fc_node_state <node> <elapsed_s> -> "<offset_s|down> <leap status...>"
# Each scenario redefines it. The leap status may contain spaces, so it is
# the remainder of the line.
fc_node_state() { echo "0 Normal"; }

fc_reset() {
	: >"$FC_CALLS"
	: >"$FC_WRITES"
	: >"$FC_HOSTREADS"
	echo "${FC_BASE}.000000" >"$FC_VT"
	unset XPF_FAILOVER_CLOCK_RESYNC XPF_FAILOVER_CLOCK_SKEW_BOUND_S \
		XPF_FAILOVER_CLOCK_BUDGET_S XPF_FAILOVER_CLOCK_POLL_S XPF_FAILOVER_CLOCK_SAMPLES
	FC_SET_FAIL_NODE=""
}

# Host clock. `+%s.%N` is the precondition's reading; the formatted UTC string
# is the escape's resync reading, and each call returns a LATER second, so an
# escape that took one reading per node would set the nodes apart and red.
date() {
	case "$*" in
	"+%s.%N") fc_vt ;;
	"-u +%Y-%m-%d %H:%M:%S")
		local n
		n=$(wc -l <"$FC_HOSTREADS")
		echo read >>"$FC_HOSTREADS"
		printf '2026-10-02 12:34:%02d\n' $((56 + n))
		;;
	*)
		printf 'host date %s\n' "$*" >>"$FC_WRITES"
		return 97
		;;
	esac
}
# A wait that never ends must FAIL here, not hang the self-test: past
# FC_RUNAWAY_S virtual seconds the mock sleep ends the scenario's subshell
# (fc_run), and the cell reads the 124 as a failure.
FC_RUNAWAY_S=200 # above the largest budget any cell uses (the 120 s default)
sleep() {
	if awk -v t="$(fc_vt)" -v b="$FC_BASE" -v cap="$FC_RUNAWAY_S" 'BEGIN { exit !(t - b > cap) }'; then
		echo "RUNAWAY: the wait slept past ${FC_RUNAWAY_S} virtual seconds"
		exit 124
	fi
	fc_advance "$1"
}

FC_SET_FAIL_NODE=""
incus() {
	if [[ "${1:-}" != exec ]]; then
		printf 'incus %s\n' "$*" >>"$FC_WRITES"
		return 90
	fi
	local node="$2"
	shift 2
	[[ "${1:-}" == "--" ]] && shift
	local cmd="$*" elapsed off leap
	printf '%s %s\n' "$node" "$cmd" >>"$FC_CALLS"
	fc_advance 0.05 # half an exec round trip before the command runs
	elapsed=$(awk -v t="$(fc_vt)" -v b="$FC_BASE" 'BEGIN { printf "%.3f", t - b }')
	read -r off leap <<<"$(fc_node_state "$node" "$elapsed")"
	case "$cmd" in
	"date +%s.%N")
		[[ "$off" == down ]] && return 1
		awk -v t="$(fc_vt)" -v o="$off" 'BEGIN { printf "%.6f\n", t + o }'
		;;
	"cat /proc/uptime")
		[[ "$off" == down ]] && return 1
		awk -v e="$elapsed" 'BEGIN { printf "%.2f 0.00\n", e + 40 }'
		;;
	"timeout 10 chronyc -n tracking")
		[[ "$off" == down ]] && return 1
		if [[ "$leap" == Normal ]]; then
			printf 'Reference ID    : A29FC801 (162.159.200.1)\n'
		else
			printf 'Reference ID    : 00000000 ()\n'
		fi
		printf 'System time     : 0.000021953 seconds fast of NTP time\n'
		printf 'Leap status     : %s\n' "$leap"
		;;
	*)
		printf '%s %s\n' "$node" "$cmd" >>"$FC_WRITES"
		[[ "$node" == "$FC_SET_FAIL_NODE" ]] && return 1
		;;
	esac
	fc_advance 0.05
	return 0
}

# fc_run <outfile> <label> <n0> <n1> -- run the precondition in a subshell
# (so the runaway guard can end it), keep its output, and bring its verdict
# line back as FAILOVER_CLOCK_DETAIL.
fc_run() {
	local out="$1" rc
	shift
	: >"$TMP_DIR/detail"
	(
		failover_clock_precondition "$@"
		rc=$?
		printf '%s' "$FAILOVER_CLOCK_DETAIL" >"$TMP_DIR/detail"
		exit "$rc"
	) >"$out" 2>&1
	rc=$?
	FAILOVER_CLOCK_DETAIL=$(cat "$TMP_DIR/detail")
	return "$rc"
}

# fc_clock_writes -- every non-whitelisted command the run issued.
fc_clock_writes() { cat "$FC_WRITES"; }

# fc_marker_field <file> <key> -- value of key= on the LAST marker line.
fc_marker_field() {
	grep -E '^CLOCK_PRECONDITION: ' "$1" | tail -1 | tr ' ' '\n' | sed -n "s/^$2=//p"
}

# ── 1. converged at the first reading ───────────────────────────────────
fc_reset
fc_node_state() {
	case "$1" in
	fw0) echo "0.000 Normal" ;;
	*) echo "0.150 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c1.out" "phase1" fw0 fw1
rc=$?
if ((rc == 0)) &&
	[[ "$(fc_marker_field "$TMP_DIR/c1.out" resync)" == 0 &&
		"$(fc_marker_field "$TMP_DIR/c1.out" converged)" == 1 &&
		"$(fc_marker_field "$TMP_DIR/c1.out" skew_s)" == "+0.150" &&
		"$FAILOVER_CLOCK_DETAIL" == "phase1: clock precondition: NTP converged in "*"skew +0.150 s, bound 5 s"* &&
		-z "$(fc_clock_writes)" ]] &&
	grep -q '^clock precondition \[phase1\]: converged ' "$TMP_DIR/c1.out"; then
	ok "converged: PASS at the first reading, skew logged, no clock touched"
else
	bad "converged: rc=$rc detail='$FAILOVER_CLOCK_DETAIL' writes='$(fc_clock_writes)' out=$(cat "$TMP_DIR/c1.out")"
fi

# ── 2. converges within the budget ──────────────────────────────────────
# fw0 is the crash-rebooted node: 72 s behind and unsynchronised until chrony
# steps it 30 s into the check.
fc_reset
fc_node_state() {
	if [[ "$1" == fw0 ]] && awk -v e="$2" 'BEGIN { exit !(e < 30) }'; then
		echo "-72.000 Not synchronised"
	else
		echo "0.000 Normal"
	fi
}
fc_run "$TMP_DIR/c2.out" "fw0 crash reboot" fw0 fw1
rc=$?
conv=$(fc_marker_field "$TMP_DIR/c2.out" converge_s)
if ((rc == 0)) &&
	awk -v c="$conv" 'BEGIN { exit !(c >= 30 && c < 36) }' &&
	[[ "$FAILOVER_CLOCK_DETAIL" == *"NTP converged in ${conv} s"* &&
		-z "$(fc_clock_writes)" ]] &&
	grep -qE '^clock precondition \[fw0 crash reboot\]: 0\.[0-9] s: waiting: node1-node0 skew \+72\.000 s .*fw0: Not synchronised' "$TMP_DIR/c2.out" &&
	grep -qE "^clock precondition \[fw0 crash reboot\]: converged ${conv} s after the check began \(up fw0 7[0-9] s, fw1 7[0-9] s\): node1-node0 skew \+0\.000 s" "$TMP_DIR/c2.out"; then
	ok "converges within budget: PASS after ${conv} s, post-crash skew +72 s logged, no clock touched"
else
	bad "converges within budget: rc=$rc conv='$conv' detail='$FAILOVER_CLOCK_DETAIL' writes='$(fc_clock_writes)' out=$(cat "$TMP_DIR/c2.out")"
fi
# The wait logs the first reading and each change, not every poll.
waits=$(grep -c ': waiting: ' "$TMP_DIR/c2.out")
if ((waits == 1)); then
	ok "a long unchanged wait logs one line, not one per poll"
else
	bad "a long unchanged wait logged $waits waiting lines, want 1"
fi

# ── 3. never converges ──────────────────────────────────────────────────
fc_reset
export XPF_FAILOVER_CLOCK_BUDGET_S=20
fc_node_state() {
	case "$1" in
	fw0) echo "-72.000 Not synchronised" ;;
	*) echo "0.000 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c3.out" "phase3-cycle2" fw0 fw1
rc=$?
end=$(awk -v t="$(fc_vt)" -v b="$FC_BASE" 'BEGIN { printf "%.1f", t - b }')
if ((rc == 1)) &&
	awk -v e="$end" 'BEGIN { exit !(e >= 20 && e < 26) }' &&
	[[ "$(fc_marker_field "$TMP_DIR/c3.out" converged)" == 0 &&
		"$(fc_marker_field "$TMP_DIR/c3.out" resync)" == 0 &&
		"$FAILOVER_CLOCK_DETAIL" == "phase3-cycle2: clock precondition: NTP did not converge after a crash reboot within 20 s: node1-node0 skew +72.000 s"* &&
		"$FAILOVER_CLOCK_DETAIL" == *"chrony fw0: Not synchronised [00000000 ()], fw1: Normal [A29FC801 (162.159.200.1)]"* &&
		"$FAILOVER_CLOCK_DETAIL" == *"needs |skew| <= 5 s"* &&
		-z "$(fc_clock_writes)" ]]; then
	ok "never converges: FAIL after the ${end} s budget, reason names the skew and both chrony states, no clock touched"
else
	bad "never converges: rc=$rc end=$end detail='$FAILOVER_CLOCK_DETAIL' writes='$(fc_clock_writes)'"
fi

# ── 4. both conditions are required ─────────────────────────────────────
# Leap Normal on both while still 8 s apart (a slew in progress) is not
# converged; nor is a zero skew while one node is unsynchronised.
fc_reset
export XPF_FAILOVER_CLOCK_BUDGET_S=6
fc_node_state() {
	case "$1" in
	fw0) echo "8.000 Normal" ;;
	*) echo "0.000 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c4a.out" "slew" fw0 fw1
rc_a=$?
fc_reset
export XPF_FAILOVER_CLOCK_BUDGET_S=6
fc_node_state() {
	case "$1" in
	fw1) echo "0.000 Not synchronised" ;;
	*) echo "0.000 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c4b.out" "unsync" fw0 fw1
rc_b=$?
detail_b="$FAILOVER_CLOCK_DETAIL"
if ((rc_a == 1 && rc_b == 1)) && grep -q 'skew -8.000 s' "$TMP_DIR/c4a.out" &&
	[[ "$detail_b" == *"fw1: Not synchronised"* ]]; then
	ok "Normal-but-8s-apart and in-bound-but-unsynchronised both FAIL (both conditions, both nodes)"
else
	bad "both conditions: slew rc=$rc_a unsync rc=$rc_b detail='$detail_b'"
fi

# ── 5. a node whose clock cannot be read ────────────────────────────────
fc_reset
export XPF_FAILOVER_CLOCK_BUDGET_S=4
fc_node_state() {
	case "$1" in
	fw0) echo "down" ;;
	*) echo "0.000 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c5.out" "final" fw0 fw1
rc=$?
if ((rc == 1)) && [[ "$FAILOVER_CLOCK_DETAIL" == *"skew unknown (clock unreadable on fw0)"* &&
	"$FAILOVER_CLOCK_DETAIL" == *"fw0: unreadable [-]"* ]]; then
	ok "an unreadable node FAILs with the reason, never as converged"
else
	bad "unreadable node: rc=$rc detail='$FAILOVER_CLOCK_DETAIL'"
fi

# ── 6. the escape: resync + banner + recorded flag ──────────────────────
fc_reset
export XPF_FAILOVER_CLOCK_RESYNC=1
fc_node_state() {
	case "$1" in
	fw0) echo "-72.000 Not synchronised" ;;
	*) echo "0.000 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c6.out" "fw0 crash reboot" fw0 fw1
rc=$?
if ((rc == 0)) &&
	[[ "$(fc_clock_writes)" == $'fw0 date -u -s 2026-10-02 12:34:56\nfw1 date -u -s 2026-10-02 12:34:56' &&
		"$(wc -l <"$FC_HOSTREADS")" -eq 1 &&
		"$(fc_marker_field "$TMP_DIR/c6.out" resync)" == 1 &&
		"$FAILOVER_CLOCK_DETAIL" == *"RESYNCED from host UTC by XPF_FAILOVER_CLOCK_RESYNC=1 (NOT operator-faithful; skew before resync +72.000 s)"* ]] &&
	grep -q 'THIS RUN IS NOT OPERATOR-FAITHFUL' "$TMP_DIR/c6.out" &&
	grep -q 'before resync: node1-node0 skew +72.000 s' "$TMP_DIR/c6.out"; then
	ok "escape: both nodes set from ONE host reading, banner printed, resync=1 recorded, pre-resync skew logged"
else
	bad "escape: rc=$rc writes='$(fc_clock_writes)' detail='$FAILOVER_CLOCK_DETAIL' out=$(cat "$TMP_DIR/c6.out")"
fi

# The escape's resync attempts both nodes when one fails, and the cell fails.
fc_reset
export XPF_FAILOVER_CLOCK_RESYNC=1
FC_SET_FAIL_NODE=fw0
fc_run "$TMP_DIR/c6b.out" "fw0 crash reboot" fw0 fw1
rc=$?
if ((rc == 1)) && [[ "$(fc_clock_writes | cut -d' ' -f1 | tr '\n' ' ')" == 'fw0 fw1 ' ]] &&
	grep -q 'FAILED to set fw0' "$TMP_DIR/c6b.out" &&
	grep -q 'fw1 set to 2026-10-02 12:34:56 UTC' "$TMP_DIR/c6b.out" &&
	[[ "$FAILOVER_CLOCK_DETAIL" == *"could not resync both firewall clocks"* ]]; then
	ok "escape: a failed set names the node, does not skip the peer, and fails the cell"
else
	bad "escape failure: rc=$rc writes='$(fc_clock_writes)' detail='$FAILOVER_CLOCK_DETAIL'"
fi

# Anything but 0/1 is refused without touching a clock: a typo must not read
# as either mode.
fc_reset
export XPF_FAILOVER_CLOCK_RESYNC=yes
fc_run "$TMP_DIR/c6c.out" "phase1" fw0 fw1
rc=$?
if ((rc == 1)) && [[ -z "$(fc_clock_writes)" && ! -s "$FC_CALLS" &&
	"$FAILOVER_CLOCK_DETAIL" == *"XPF_FAILOVER_CLOCK_RESYNC must be 0 or 1 (got 'yes')"* ]]; then
	ok "an invalid escape value is refused, no clock read or set"
else
	bad "invalid escape value: rc=$rc detail='$FAILOVER_CLOCK_DETAIL' calls=$(cat "$FC_CALLS")"
fi

fc_reset
if failover_clock_precondition fw0 fw1 >/dev/null 2>&1 || failover_resync_node_clocks >/dev/null 2>&1; then
	bad "a wrong argument count is refused"
else
	ok "a wrong argument count is refused"
fi

# ── 7. the ledger records the flag (producer/consumer contract) ─────────
# The REAL adapter reads the REAL marker lines, so a renamed key or a changed
# line shape on either side reds here instead of silently dropping the flag.
HR="${SCRIPT_DIR}/harness-result.sh"
adapt_metrics() { bash "$HR" adapt "$1" 0 "$2" | cut -f5; }
{
	cat "$TMP_DIR/c1.out" "$TMP_DIR/c2.out"
	echo "  PASS  iperf3 throughput 9.1 Gbps"
	echo "  HA crash test: 7 passed, 0 failed"
} >"$TMP_DIR/ledger-measured.log"
{
	cat "$TMP_DIR/c1.out" "$TMP_DIR/c6.out" "$TMP_DIR/c2.out"
	echo "  PASS  iperf3 throughput 9.1 Gbps"
	echo "  HA crash test: 7 passed, 0 failed"
} >"$TMP_DIR/ledger-resync.log"
printf '  PASS  iperf3 throughput 9.1 Gbps\n  HA crash test: 7 passed, 0 failed\n' >"$TMP_DIR/ledger-none.log"
contract_ok=1
for adapter in smoke-cells ha-smoke; do
	m=$(adapt_metrics "$adapter" "$TMP_DIR/ledger-measured.log")
	[[ " $m " == *" clock_resync=0 "* ]] || { contract_ok=0; echo "  $adapter measured: '$m'" >&2; }
	m=$(adapt_metrics "$adapter" "$TMP_DIR/ledger-resync.log")
	[[ " $m " == *" clock_resync=1 "* ]] || { contract_ok=0; echo "  $adapter resync: '$m'" >&2; }
	m=$(adapt_metrics "$adapter" "$TMP_DIR/ledger-none.log")
	[[ " $m " != *"clock_resync"* ]] || { contract_ok=0; echo "  $adapter none: '$m'" >&2; }
done
if ((contract_ok)); then
	ok "ledger: clock_resync=1 if ANY call resynced (even between measured ones), 0 if all measured, absent if never run"
else
	bad "ledger: the adapters did not record clock_resync from the library's marker lines"
fi

# ── 8. mutation: a silent resync re-added on the measured path ──────────
# Proves the dynamic detector in cells 1-5 can fire. The splice is checked to
# have landed: a sed that misses its anchor exits 0 and would "pass" here.
MUT="${TMP_DIR}/mutated-lib.sh"
awk '{ print } /^_failover_clock_wait\(\) \{$/ { print "\tfailover_resync_node_clocks \"$2\" \"$3\" >/dev/null 2>&1" }' \
	"$FAILOVER_CLOCK_LIB" >"$MUT"
splice='failover_resync_node_clocks "\$2" "\$3" >/dev/null 2>&1'
if (($(grep -c "$splice" "$MUT") != $(grep -c "$splice" "$FAILOVER_CLOCK_LIB") + 1)); then
	bad "mutation: the silent-resync splice did not land (anchor _failover_clock_wait() { missing?)"
else
	mut_writes=$(
		# shellcheck disable=SC1090
		source "$MUT"
		fc_reset
		fc_node_state() { echo "0.000 Normal"; }
		failover_clock_precondition "phase1" fw0 fw1 >/dev/null 2>&1
		fc_clock_writes
	)
	if [[ "$mut_writes" == *"fw0 date -u -s"* && "$mut_writes" == *"fw1 date -u -s"* ]]; then
		ok "mutation: a silent date -s spliced into the measured path is detected (killed)"
	else
		bad "mutation: a silent date -s on the measured path went UNDETECTED (writes='$mut_writes')"
	fi
fi

# ── 9. static census: no harness sets a clock outside the escape ────────
# A shell line that runs a clock-SETTING command. One pattern, used both by
# the controls (one line at a time) and by the census (whole files at once).
FC_SETTER_RE='(^|[^[:alnum:]_-])date([[:space:]]+-[[:alnum:]]+)*[[:space:]]+(-s|-us|-su|--set)([[:space:]=]|$)|timedatectl[[:space:]]+set-time|hwclock[[:space:]].*(--hctosys|--systohc|(^|[[:space:]])-[sw]([[:space:]]|$))|chronyc[[:space:]].*(makestep|settime)|(^|[^[:alnum:]_-])ntpdate[[:space:]]'
fc_sets_clock() { grep -qE "$FC_SETTER_RE" <<<"$1"; }
# Positive and negative controls: the matcher is shown to see each setter
# shape, and not to see the reads this library and the soak make.
matcher_ok=1
for l in 'incus exec "$n" -- date -u -s "$now"' 'incus exec fw1 -- date -s "2026-10-31 10:00:00"' \
	'incus exec fw0 -- date --set="@1793440000"' 'incus exec fw0 -- timedatectl set-time "2026-10-31"' \
	'incus exec fw0 -- hwclock --hctosys' 'incus exec fw0 -- chronyc makestep' 'ntpdate pool.ntp.org'; do
	fc_sets_clock "$l" || { matcher_ok=0; echo "  matcher MISSED: $l" >&2; }
done
for l in 'incus exec "$node" -- date +%s.%N' 'date -u +%T.%N' 'date -u "+%Y-%m-%d %H:%M:%S"' \
	'incus exec "$1" -- timeout 10 chronyc -n tracking' 'date -d @1793440000 +%s' 'date -Iseconds'; do
	fc_sets_clock "$l" && { matcher_ok=0; echo "  matcher FALSE POSITIVE: $l" >&2; }
done
if ((matcher_ok)); then
	ok "census matcher: sees every clock-setter shape and none of the reads (controls)"
else
	bad "census matcher: missed a setter or flagged a read"
fi

# Scan every harness shell file. Comment lines are skipped (they describe the
# old resync); in the library, the escape function's body is the one
# sanctioned setter. Self-tests are fixtures, not harnesses.
census_hits=""
scanned=0
sourcing=0
for f in "$SCRIPT_DIR"/*.sh; do
	case "$(basename "$f")" in
	*-selftest.sh) continue ;;
	esac
	scanned=$((scanned + 1))
	hits=$(awk -v lib="$([[ "$(basename "$f")" == failover-clock-lib.sh ]] && echo 1 || echo 0)" '
		lib == 1 && /^failover_resync_node_clocks\(\) \{$/ { skip = 1 }
		skip { if (/^\}$/) skip = 0; next }
		/^[[:space:]]*#/ { next }
		{ print }' "$f" | grep -E "$FC_SETTER_RE" || true)
	[[ -n "$hits" ]] && census_hits+="$(basename "$f"): ${hits}"$'\n'
	if grep -qE '^[[:space:]]*source[[:space:]].*failover-clock-lib\.sh' "$f"; then
		sourcing=$((sourcing + 1))
		# Into a variable, never `grep | grep -q`: under pipefail an early
		# `-q` exit SIGPIPEs the producer on a large file, and the pipeline's
		# failure reads as "no match" -- a found call reported as absent.
		code=$(grep -vE '^[[:space:]]*#' "$f")
		if grep -qE '(^|[^[:alnum:]_])failover_resync_node_clocks([^[:alnum:]_]|$)' <<<"$code"; then
			census_hits+="$(basename "$f"): calls failover_resync_node_clocks directly (bypasses the escape banner and flag)"$'\n'
		fi
		if ! grep -qE '(^|[^[:alnum:]_])failover_clock_precondition[[:space:]]' <<<"$code"; then
			census_hits+="$(basename "$f"): sources failover-clock-lib.sh but never runs failover_clock_precondition"$'\n'
		fi
	fi
done
# Denominator: the census must have read the three crash smokes, or a green
# here means it scanned nothing.
if ((sourcing < 3 || scanned < 20)); then
	bad "census: scanned $scanned harness files, $sourcing sourcing the clock library (want >= 20 and >= 3)"
elif [[ -n "$census_hits" ]]; then
	bad "census: a harness sets a node clock outside the escape:"$'\n'"$census_hits"
else
	ok "census: $scanned harness files, $sourcing run the precondition, none sets a clock outside the escape"
fi

echo "----------------------------------------"
echo "failover clock selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
