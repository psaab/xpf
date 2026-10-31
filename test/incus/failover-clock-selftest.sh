#!/usr/bin/env bash
# Hermetic tests for the crash-failover clock precondition (#18614; the
# #11872 resync survives only as the XPF_FAILOVER_CLOCK_RESYNC=1 escape).
# No incus, cluster, network, real sleeping or system clock changes: `incus`,
# `timeout`, `date` and `sleep` are shell functions over a virtual clock kept
# in a file.
#
# The load-bearing property is that the measured path NEVER SETS A CLOCK. It is
# asserted three ways, because each one alone misses a mutation the others see:
#   1. dynamically: the mock `incus` admits exactly the read commands
#      (`date +%s.%N`, `timeout 10 chronyc -n tracking`, `cat /proc/uptime`)
#      and records everything else, so a re-added `date -s` anywhere under
#      the precondition, the baseline or the reading reds every measured cell;
#   2. by mutation: a copy of the library with a silent resync spliced into
#      the measured path must be caught by (1) -- the detector is shown to fire;
#   3. statically: no harness under test/incus/ or scripts/ (shell or Python)
#      runs a clock-setting command outside the escape, and no file but the
#      library calls failover_resync_node_clocks (which would bypass the banner
#      and the ledger mark). Each setter shape has a positive control, and the
#      file-level scan is run on planted fixture files first.
#
# The exec mock gives every node its own ASYMMETRIC, VARYING per-sample
# latency, so the measurement method itself is under test: only the
# minimum-RTT sample with the midpoint recovers the planted skew exactly, and
# the max-RTT, one-sample and no-midpoint variants all read it wrong.
#
# SC2329: each scenario redefines the fc_node_state mock, which the mock incus
# calls. SC2016: mutation splices and census fixtures are literal shell.
# SC2034: FC_LAT_<node> is read by indirection. SC2053: expect() globs.
# shellcheck disable=SC2329,SC2016,SC2034,SC2053
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
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
FC_UNTIMED="${TMP_DIR}/untimed"     # read commands NOT under a host timeout
FC_VT="${TMP_DIR}/vclock"           # virtual host clock, epoch seconds
FC_HOSTREADS="${TMP_DIR}/hostreads" # one line per formatted host UTC reading
FC_SEQ="${TMP_DIR}/seq"             # per-node date-sample counters
FC_BASE=1793440000
mkdir -p "$FC_SEQ"

# ── the virtual world ────────────────────────────────────────────────────
fc_vt() { cat "$FC_VT"; }
fc_advance() {
	awk -v t="$(fc_vt)" -v d="$1" 'BEGIN { printf "%.6f\n", t + d }' >"${FC_VT}.n" &&
		mv "${FC_VT}.n" "$FC_VT"
}
# fc_node_state <node> <elapsed_s> -> "<offset_s|down> <leap status...>"
# Each scenario redefines it. The leap status may contain spaces, so it is
# the remainder of the line; CHRONY_DOWN makes chronyc fail while the clock
# stays readable.
fc_node_state() { echo "0 Normal"; }

# Per-sample exec latency "<before> <after>" (seconds) for the Nth date sample
# a node has answered. Asymmetric and varying, and different per node, so the
# method's choices are visible in the node1-node0 difference:
#   fw0: rtt 0.62 (err +0.29), 0.50 (err 0, the minimum), 0.67 (err -0.315)
#   fw1: rtt 0.31 (err -0.145), 0.06 (err 0, the minimum), 0.40 (err +0.18)
# Min-RTT with the midpoint reads the planted skew exactly, error bound
# (0.50 + 0.06) / 2 = 0.280. Max-RTT is off by +0.495, the first sample alone
# by -0.435, and dropping the midpoint by -0.220.
FC_LAT_fw0="0.60:0.02 0.25:0.25 0.02:0.65"
FC_LAT_fw1="0.01:0.30 0.03:0.03 0.38:0.02"
fc_latency() {
	local node="$1" var n pats
	var="FC_LAT_${node//[^a-zA-Z0-9_]/_}"
	pats="${!var:-0.05:0.05 0.05:0.05 0.05:0.05}"
	n=$(cat "$FC_SEQ/$var" 2>/dev/null || echo 0)
	echo $((n + 1)) >"$FC_SEQ/$var"
	read -r -a arr <<<"$pats"
	echo "${arr[$((n % ${#arr[@]}))]/:/ }"
}

fc_reset() {
	: >"$FC_CALLS"
	: >"$FC_WRITES"
	: >"$FC_UNTIMED"
	: >"$FC_HOSTREADS"
	rm -f "$FC_SEQ"/*
	echo "${FC_BASE}.000000" >"$FC_VT"
	unset XPF_FAILOVER_CLOCK_RESYNC XPF_FAILOVER_CLOCK_SKEW_BOUND_S \
		XPF_FAILOVER_CLOCK_BUDGET_S XPF_FAILOVER_CLOCK_POLL_S XPF_FAILOVER_CLOCK_SAMPLES \
		XPF_FAILOVER_CLOCK_MAX_UNC_S
	FC_SET_FAIL_NODE=""
	FC_LAT_fw0="0.60:0.02 0.25:0.25 0.02:0.65"
	FC_LAT_fw1="0.01:0.30 0.03:0.03 0.38:0.02"
	_FC_BASE_TEXT=""
	FC_NTP_STANZA=present         # present | absent | error (`show configuration system ntp`)
	FC_PROBE_ANSWER=162.159.200.1 # servers answering the host's SNTP probe; FAIL = no python3
}
FC_NTP_STANZA=present
FC_PROBE_ANSWER=162.159.200.1
# The off-path probe: python3 on the HOST. A function shadows the binary, and
# answers as the scenario says.
python3() {
	[[ "${FC_UNDER_TIMEOUT:-0}" == 1 ]] || printf 'host python3\n' >>"$FC_UNTIMED"
	echo probe >>"$TMP_DIR/probes"
	[[ "$FC_PROBE_ANSWER" == FAIL ]] && return 127
	printf '%s\n' "$FC_PROBE_ANSWER"
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
# Host-side timeout: run the command, and tell the mock incus it is bounded.
timeout() {
	shift
	FC_UNDER_TIMEOUT=1 "$@"
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
	local cmd="$*" elapsed off leap pre=0.05 post=0.05
	printf '%s %s\n' "$node" "$cmd" >>"$FC_CALLS"
	case "$cmd" in
	"date +%s.%N" | "timeout 10 chronyc -n tracking" | "cat /proc/uptime" | "cli -c show configuration system ntp")
		[[ "${FC_UNDER_TIMEOUT:-0}" == 1 ]] || printf '%s %s\n' "$node" "$cmd" >>"$FC_UNTIMED"
		;;
	esac
	[[ "$cmd" == "date +%s.%N" ]] && read -r pre post <<<"$(fc_latency "$node")"
	fc_advance "$pre"
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
	"cli -c show configuration system ntp")
		[[ "$off" == down ]] && return 1
		case "$FC_NTP_STANZA" in
		present) printf 'ntp {\n    server 162.159.200.1 {\n        routing-instance mgmt;\n    }\n    server 91.189.91.112 {\n        routing-instance mgmt;\n    }\n}\n' ;;
		absent) printf 'configuration path not found: system ntp\n' ;;
		*) printf 'error: rpc error: code = Unavailable\n' ;;
		esac
		;;
	"timeout 10 chronyc -n tracking")
		[[ "$off" == down || "$leap" == CHRONY_DOWN ]] && return 1
		if [[ "$leap" == "Not synchronised" ]]; then
			printf 'Reference ID    : 00000000 ()\n'
		else
			printf 'Reference ID    : A29FC801 (162.159.200.1)\n'
		fi
		printf 'System time     : 0.000021953 seconds fast of NTP time\n'
		printf 'Leap status     : %s\n' "$leap"
		;;
	*)
		printf '%s %s\n' "$node" "$cmd" >>"$FC_WRITES"
		[[ "$node" == "$FC_SET_FAIL_NODE" ]] && return 1
		;;
	esac
	fc_advance "$post"
	return 0
}

# fc_run <outfile> <label> <n0> <n1> <rebooted> -- run the precondition in a
# subshell (so the runaway guard can end it), keep its output, and bring its
# verdict line and resync flag back.
fc_run() {
	local out="$1" rc
	shift
	: >"$TMP_DIR/detail"
	(
		failover_clock_precondition "$@"
		rc=$?
		printf '%s\n%s' "${FAILOVER_CLOCK_RESYNCED:-}" "$FAILOVER_CLOCK_DETAIL" >"$TMP_DIR/detail"
		exit "$rc"
	) >"$out" 2>&1
	rc=$?
	FAILOVER_CLOCK_RESYNCED=$(head -1 "$TMP_DIR/detail")
	FAILOVER_CLOCK_DETAIL=$(tail -n +2 "$TMP_DIR/detail")
	return "$rc"
}
fc_clock_writes() { cat "$FC_WRITES"; }
# fc_marker_field <file> <key> -- value of key= on the LAST marker line.
fc_marker_field() {
	grep -E '^CLOCK_PRECONDITION: ' "$1" | tail -1 | tr ' ' '\n' | sed -n "s/^$2=//p"
}
fc_elapsed() { awk -v t="$(fc_vt)" -v b="$FC_BASE" 'BEGIN { printf "%.1f", t - b }'; }
# fc_baseline_synced -- record a synchronised pre-crash baseline (context).
fc_baseline_synced() {
	fc_node_state() { echo "0.000 Normal"; }
	failover_clock_baseline fw0 fw1 >/dev/null
	echo "${FC_BASE}.000000" >"$FC_VT"
}
# fc_baseline_one_unsynced -- the #18584 state before the crash: fw0 drifting
# unsynchronised, fw1 (the RG owner) synchronised.
fc_baseline_one_unsynced() {
	fc_node_state() {
		case "$1" in
		fw0) echo "-0.400 Not synchronised" ;;
		*) echo "0.000 Normal" ;;
		esac
	}
	failover_clock_baseline fw0 fw1 >"$TMP_DIR/base.out"
	echo "${FC_BASE}.000000" >"$FC_VT"
}

# ── 1. converged at the first reading; the method recovers the skew ──────
fc_reset
fc_node_state() {
	case "$1" in
	fw0) echo "0.000 Normal" ;;
	*) echo "0.150 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c1.out" "phase1" fw0 fw1 fw0
rc=$?
if ((rc == 0)) &&
	[[ "$(fc_marker_field "$TMP_DIR/c1.out" resync)" == 0 &&
		"$(fc_marker_field "$TMP_DIR/c1.out" converged)" == 1 &&
		"$(fc_marker_field "$TMP_DIR/c1.out" verdict)" == PASS &&
		"$FAILOVER_CLOCK_DETAIL" == "phase1: clock precondition: NTP converged in "*"skew +0.150 s +/-0.280 s, bound 5 s; chrony synchronised on both: Normal / Normal)"* &&
		-z "$(fc_clock_writes)" ]] &&
	grep -q '^clock precondition \[phase1\]: converged ' "$TMP_DIR/c1.out"; then
	ok "converged: PASS at the first reading, skew and error logged, no clock touched"
else
	bad "converged: rc=$rc detail='$FAILOVER_CLOCK_DETAIL' writes='$(fc_clock_writes)' out=$(cat "$TMP_DIR/c1.out")"
fi
# The planted +0.150 s comes back EXACTLY only from the minimum-RTT sample's
# midpoint (max-RTT reads +0.645, one sample -0.285, no midpoint -0.070).
if [[ "$(fc_marker_field "$TMP_DIR/c1.out" skew_s)" == "+0.150" ]] &&
	grep -q 'skew +0.150 s (+/-0.280 s)' "$TMP_DIR/c1.out" &&
	(($(grep -c ' date +%s.%N$' "$FC_CALLS") == 6)); then
	ok "method: asymmetric varying latency, min-RTT midpoint of 3 samples per node reads +0.150 s +/-0.280 s exactly"
else
	bad "method: skew_s=$(fc_marker_field "$TMP_DIR/c1.out" skew_s) date-calls=$(grep -c ' date +%s.%N$' "$FC_CALLS") out=$(cat "$TMP_DIR/c1.out")"
fi
if [[ ! -s "$FC_UNTIMED" ]] && grep -q 'cli -c show configuration system ntp' "$FC_CALLS"; then
	ok "every node read (date, chronyc, uptime, the ntp config) runs under a host-side timeout"
else
	bad "node reads without a host-side timeout: $(cat "$FC_UNTIMED")"
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
fc_run "$TMP_DIR/c2.out" "fw0 crash reboot" fw0 fw1 fw0
rc=$?
conv=$(fc_marker_field "$TMP_DIR/c2.out" converge_s)
if ((rc == 0)) &&
	awk -v c="$conv" 'BEGIN { exit !(c >= 30 && c < 40) }' &&
	[[ "$FAILOVER_CLOCK_DETAIL" == *"NTP converged in ${conv} s"* &&
		-z "$(fc_clock_writes)" ]] &&
	grep -qE '^clock precondition \[fw0 crash reboot\]: [0-9.]+ s: waiting: node1-node0 skew \+72\.000 s .*fw0: Not synchronised' "$TMP_DIR/c2.out" &&
	grep -qE "^clock precondition \[fw0 crash reboot\]: converged ${conv} s after the check began \(up fw0 [0-9]+ s, fw1 [0-9]+ s\): node1-node0 skew \+0\.000 s" "$TMP_DIR/c2.out"; then
	ok "converges within budget: PASS after ${conv} s, post-crash skew +72 s and both uptimes logged"
else
	bad "converges within budget: rc=$rc conv='$conv' detail='$FAILOVER_CLOCK_DETAIL' out=$(cat "$TMP_DIR/c2.out")"
fi
# The wait sees two states (fw0 unsynchronised and 72 s off; then chrony
# Normal while the skew is still out) over eight readings: one line for the
# first reading and one per change, not one per poll.
waits=$(grep -c ': waiting: ' "$TMP_DIR/c2.out")
readings=$(($(grep -c ' date +%s.%N$' "$FC_CALLS") / 6))
if ((waits == 2 && readings >= 7)); then
	ok "a long wait logs the first reading and each change (${waits} lines over ${readings} readings), not one per poll"
else
	bad "a long wait logged $waits waiting lines over $readings readings, want 2: $(grep ': waiting: ' "$TMP_DIR/c2.out")"
fi

# ── 3. FAIL: the peer is synchronised, the rebooted node never converges ──
# Budget 17.5 s puts the last pre-budget reading at 17.0 s, so the cut final
# sleep (0.5 s) lands the verdict near 20.3 s; an uncut 2 s sleep lands 21.8 s.
fc_reset
fc_baseline_synced
export XPF_FAILOVER_CLOCK_BUDGET_S=17.5
fc_node_state() {
	case "$1" in
	fw0) echo "-72.000 Not synchronised" ;;
	*) echo "0.000 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c3.out" "phase3-cycle2" fw0 fw1 fw0
rc=$?
end=$(fc_elapsed)
if ((rc == 1)) &&
	awk -v e="$end" 'BEGIN { exit !(e >= 17.5 && e < 21) }' &&
	[[ "$(fc_marker_field "$TMP_DIR/c3.out" verdict)" == FAIL &&
		"$(fc_marker_field "$TMP_DIR/c3.out" converged)" == 0 &&
		"$FAILOVER_CLOCK_DETAIL" == "phase3-cycle2: clock precondition: NTP did not converge after a crash reboot within 17.5 s: #18584 class: the rebooted fw0 is not synchronised (Not synchronised) while the peer fw1 is"*"(lab, NTP or product"* &&
		"$FAILOVER_CLOCK_DETAIL" == *"node1-node0 skew +72.000 s"* &&
		"$FAILOVER_CLOCK_DETAIL" == *"chrony fw0: Not synchronised [00000000 ()], fw1: Normal [A29FC801 (162.159.200.1)]"* &&
		-z "$(fc_clock_writes)" ]] && ! grep -q '^CLOCK_VOID: ' "$TMP_DIR/c3.out"; then
	ok "FAIL-rebooted-only: peer synchronised, rebooted node not; FAIL at ${end} s (budget 17.5, at most one reading over), reason names skew and both states"
else
	bad "FAIL-rebooted-only: rc=$rc end=$end detail='$FAILOVER_CLOCK_DETAIL' out=$(cat "$TMP_DIR/c3.out")"
fi

# ── 4. neither node synchronised: VOID only where the build is not in the path
# C: no `system ntp` configured (the tcp lab today) -> VOID after one reading,
# no budget spent. With it configured, the same state is judged against the
# off-path probe: servers answering this host -> FAIL; none answering -> VOID
# (a lab NTP outage); probe unavailable -> FAIL; config unreadable -> VOID.
both_unsync() { echo "0.000 Not synchronised"; }
fc_reset
fc_node_state() { both_unsync; }
FC_NTP_STANZA=absent
failover_clock_baseline fw0 fw1 >"$TMP_DIR/c4-base.out"
echo "${FC_BASE}.000000" >"$FC_VT"
fc_run "$TMP_DIR/c4.out" "phase1" fw0 fw1 fw0
rc=$?
end=$(fc_elapsed)
if ((rc == 2)) && awk -v e="$end" 'BEGIN { exit !(e < 5) }' &&
	[[ "$(fc_marker_field "$TMP_DIR/c4.out" verdict)" == VOID &&
		"$FAILOVER_CLOCK_DETAIL" == "phase1: clock precondition VOID: no time source (lab): no \`system ntp\` is configured and neither node is synchronised"* &&
		"$FAILOVER_CLOCK_DETAIL" == *"before the first crash: node1-node0 skew"* ]] &&
	grep -q '^CLOCK_VOID: phase1: clock precondition VOID: no time source' "$TMP_DIR/c4.out" &&
	grep -q '^clock baseline (before the first crash; up fw0 [0-9]* s, fw1 [0-9]* s): node1-node0 skew.*; system ntp: not configured$' "$TMP_DIR/c4-base.out"; then
	ok "C (no stanza): neither node synchronised and no \`system ntp\` configured -> VOID after one reading (${end} s), baseline as context"
else
	bad "C (no stanza): rc=$rc end=$end detail='$FAILOVER_CLOCK_DETAIL' out=$(cat "$TMP_DIR/c4.out")"
fi
c4_case() { # <stanza> <probe answer> -> sets rc4 and d4
	fc_reset
	export XPF_FAILOVER_CLOCK_BUDGET_S=6
	fc_node_state() { both_unsync; }
	FC_NTP_STANZA="$1"
	FC_PROBE_ANSWER="$2"
	: >"$TMP_DIR/probes"
	fc_run "$TMP_DIR/c4x.out" "phase1" fw0 fw1 fw0
	rc4=$?
	d4="$FAILOVER_CLOCK_DETAIL"
	p4=$(wc -l <"$TMP_DIR/probes")
}
c4_ok=1
c4_case present 162.159.200.1
[[ $rc4 == 1 && "$d4" == *"neither node is synchronised although \`system ntp\` is configured (162.159.200.1 91.189.91.112) and its servers answer this host (162.159.200.1)"* && $p4 == 1 && ! -s "$FC_UNTIMED" ]] ||
	{ c4_ok=0; echo "  stanza+probe answers: rc=$rc4 probes=$p4 untimed='$(cat "$FC_UNTIMED")' '$d4'" >&2; }
c4_case present ""
[[ $rc4 == 2 && "$d4" == *"VOID: lab NTP outage: neither node is synchronised and no configured server (162.159.200.1 91.189.91.112) answers this host either"* ]] ||
	{ c4_ok=0; echo "  stanza+probe silent: rc=$rc4 '$d4'" >&2; }
c4_case present FAIL
[[ $rc4 == 1 && "$d4" == *"the off-path SNTP probe from this host was unavailable"* ]] ||
	{ c4_ok=0; echo "  stanza+no probe: rc=$rc4 '$d4'" >&2; }
c4_case error 162.159.200.1
[[ $rc4 == 2 && "$d4" == *"VOID: no measurement (harness): \`show configuration system ntp\` could not be read"* ]] ||
	{ c4_ok=0; echo "  stanza unreadable: rc=$rc4 '$d4'" >&2; }
if ((c4_ok)); then
	ok "C (stanza): neither synchronised with \`system ntp\` configured -> FAIL when its servers answer the host or the probe is unavailable, VOID (lab NTP outage) when none answers; an unreadable config is VOID"
else
	bad "C (stanza): neither-synchronised scoring is wrong"
fi

# ── 5. one node synchronised, the other not: the #18584 class, FAIL ───────
# A: the pre-crash baseline already had fw0 unsynchronised (the #18584 state:
# only the RG owner reaches NTP). B: its twin with a synchronised baseline.
# Both FAIL alike -- the baseline is context, never a VOID.
ab_after() {
	fc_node_state() {
		case "$1" in
		fw0) echo "-9.000 Not synchronised" ;;
		*) echo "0.000 Normal" ;;
		esac
	}
	export XPF_FAILOVER_CLOCK_BUDGET_S=6
}
fc_reset
fc_baseline_one_unsynced
ab_after
fc_run "$TMP_DIR/c5a.out" "phase1" fw0 fw1 fw0
rc_a=$?
d_a="$FAILOVER_CLOCK_DETAIL"
fc_reset
fc_baseline_synced
ab_after
fc_run "$TMP_DIR/c5b.out" "phase1" fw0 fw1 fw0
rc_b=$?
d_b="$FAILOVER_CLOCK_DETAIL"
if ((rc_a == 1 && rc_b == 1)) &&
	[[ "$d_a" == *"#18584 class: the rebooted fw0 is not synchronised (Not synchronised) while the peer fw1 is"* &&
		"$d_a" == *"before the first crash: node1-node0 skew +0.400 s"*"fw0: Not synchronised"* &&
		"$d_b" == *"#18584 class: the rebooted fw0 is not synchronised"* ]]; then
	ok "A/B: one node synchronised is FAIL (#18584 class) whether or not the baseline already showed it; the baseline rides as context"
else
	bad "A/B: rc=$rc_a/$rc_b A='$d_a' B='$d_b'"
fi
# The un-rebooted peer unsynchronised (or its chronyc silent) is the same class,
# and so is a one-node state with no stanza at all.
peer_ok=1
for case_ in "Not synchronised present" "CHRONY_DOWN present" "Not synchronised absent"; do
	read -r pl1 pl2 st <<<"$case_"
	[[ "$pl1" == Not ]] && pleap="Not synchronised" || pleap="$pl1"
	[[ "$pl1" == Not ]] || st="$pl2"
	fc_reset
	fc_baseline_synced
	export XPF_FAILOVER_CLOCK_BUDGET_S=6
	FC_NTP_STANZA="$st"
	FC_PEER_LEAP="$pleap"
	fc_node_state() {
		case "$1" in
		fw1) echo "0.000 ${FC_PEER_LEAP}" ;;
		*) echo "0.000 Normal" ;;
		esac
	}
	fc_run "$TMP_DIR/c5c.out" "phase1" fw0 fw1 fw0
	got=$?
	want_leap="$pleap"
	[[ "$pleap" == CHRONY_DOWN ]] && want_leap=unreadable
	if ((got != 1)) || [[ "$FAILOVER_CLOCK_DETAIL" != *"#18584 class: the un-rebooted peer fw1 is not synchronised (${want_leap}) while the rebooted fw0 is"* ]]; then
		peer_ok=0
		echo "  peer ${pleap}, stanza ${st}: rc=$got '$FAILOVER_CLOCK_DETAIL'" >&2
	fi
done
if ((peer_ok)); then
	ok "peer unsynchronised or its chronyc silent, with or without a stanza: FAIL (#18584 class), never a lab VOID"
else
	bad "peer-unsynchronised scoring is wrong"
fi

# ── 5b. AC's probe: a blip at the baseline instant must not decide anything ─
# fw1 was unsynchronised only at the baseline; at the check it is synchronised
# and fw0 converges 8 s in. The CURRENT reading drives the verdict: PASS.
fc_reset
fc_node_state() {
	case "$1" in
	fw1) echo "0.000 Not synchronised" ;;
	*) echo "0.000 Normal" ;;
	esac
}
failover_clock_baseline fw0 fw1 >/dev/null
echo "${FC_BASE}.000000" >"$FC_VT"
fc_node_state() {
	if [[ "$1" == fw0 ]] && awk -v e="$2" 'BEGIN { exit !(e < 8) }'; then
		echo "-3.000 Not synchronised"
	else
		echo "0.000 Normal"
	fi
}
fc_run "$TMP_DIR/c5d.out" "phase1" fw0 fw1 fw0
rc=$?
conv=$(fc_marker_field "$TMP_DIR/c5d.out" converge_s)
if ((rc == 0)) && awk -v c="$conv" 'BEGIN { exit !(c >= 8 && c < 16) }'; then
	ok "baseline blip: unsynchronised at the baseline only, converging 8 s in -> PASS after ${conv} s (no early VOID)"
else
	bad "baseline blip: rc=$rc conv='$conv' detail='$FAILOVER_CLOCK_DETAIL'"
fi

# ── 5c. D: chrony lost on both nodes mid-run, stanza configured ──────────
fc_reset
fc_baseline_synced
export XPF_FAILOVER_CLOCK_BUDGET_S=6
fc_node_state() { both_unsync; }
fc_run "$TMP_DIR/c5e.out" "phase3-cycle1" fw0 fw1 fw0
rc_d1=$?
d_d1="$FAILOVER_CLOCK_DETAIL"
fc_reset
fc_baseline_synced
export XPF_FAILOVER_CLOCK_BUDGET_S=6
FC_PROBE_ANSWER=""
fc_node_state() { both_unsync; }
fc_run "$TMP_DIR/c5f.out" "phase3-cycle1" fw0 fw1 fw0
rc_d2=$?
d_d2="$FAILOVER_CLOCK_DETAIL"
# And with the stanza configured, both nodes unsynchronised is WAITED out, not
# decided at the first reading: chrony back on both 8 s in -> PASS.
fc_reset
fc_baseline_synced
fc_node_state() {
	if awk -v e="$2" 'BEGIN { exit !(e < 8) }'; then
		echo "0.000 Not synchronised"
	else
		echo "0.000 Normal"
	fi
}
fc_run "$TMP_DIR/c5g.out" "phase3-cycle1" fw0 fw1 fw0
rc_d3=$?
if ((rc_d1 == 1 && rc_d2 == 2 && rc_d3 == 0)) && [[ "$d_d1" == *"its servers answer this host"* &&
	"$d_d1" == *"before the first crash: node1-node0 skew"*"fw0: Normal"* &&
	"$d_d2" == *"lab NTP outage"* ]]; then
	ok "D: chrony lost on both nodes after a synchronised baseline -> FAIL while the servers answer the host, VOID only when the host cannot reach them either; back on both 8 s in -> PASS (waited, not decided early)"
else
	bad "D: rc=$rc_d1/$rc_d2/$rc_d3 '$d_d1' / '$d_d2' / '$FAILOVER_CLOCK_DETAIL'"
fi

# ── 6. each condition alone is not enough ───────────────────────────────
fc_reset
fc_baseline_synced
export XPF_FAILOVER_CLOCK_BUDGET_S=6
fc_node_state() {
	case "$1" in
	fw0) echo "8.000 Normal" ;;
	*) echo "0.000 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c6a.out" "slew" fw0 fw1 fw0
rc_a=$?
fc_reset
fc_baseline_synced
export XPF_FAILOVER_CLOCK_BUDGET_S=6
fc_node_state() {
	case "$1" in
	fw1) echo "0.000 Not synchronised" ;;
	*) echo "0.000 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c6b.out" "unsync" fw0 fw1 fw1
rc_b=$?
detail_b="$FAILOVER_CLOCK_DETAIL"
if ((rc_a == 1 && rc_b == 1)) && grep -q 'skew -8.000 s' "$TMP_DIR/c6a.out" &&
	[[ "$detail_b" == *"#18584 class: the rebooted fw1 is not synchronised (Not synchronised) while the peer fw0 is"* ]]; then
	ok "synchronised-but-8s-apart FAILs (both synchronised, out of bound), and in-bound-but-rebooted-node-unsynchronised FAILs (either node as the rebooted one)"
else
	bad "each condition: slew rc=$rc_a unsync rc=$rc_b detail='$detail_b'"
fi

# ── 7. the bound, error included, at its edges ──────────────────────────
# With the method's +/-0.280 s: 4.5 s passes (4.78 <= 5), 4.9 s fails (5.18:
# the error counts), 5.5 s fails. A bound loosened by any margin, or an error
# bound dropped, flips one of them.
edge_ok=1
for case_ in "4.5 0" "4.9 1" "5.5 1"; do
	read -r sk want <<<"$case_"
	fc_reset
	fc_baseline_synced
	export XPF_FAILOVER_CLOCK_BUDGET_S=4
	FC_EDGE="$sk"
	fc_node_state() {
		case "$1" in
		fw0) echo "-${FC_EDGE} Normal" ;;
		*) echo "0.000 Normal" ;;
		esac
	}
	fc_run "$TMP_DIR/c7.out" "edge" fw0 fw1 fw0
	got=$?
	if ((got != want)); then
		edge_ok=0
		echo "  skew ${sk} s: rc=$got want=$want: $(grep -m1 'skew' "$TMP_DIR/c7.out")" >&2
	fi
done
if ((edge_ok)); then
	ok "bound edges: 4.5 s PASS, 4.9 s FAIL (|skew| + 0.280 s error > 5 s), 5.5 s FAIL"
else
	bad "bound edges: the bound or its error term is wrong"
fi

# ── 8. a reading too noisy to judge ─────────────────────────────────────
fc_reset
fc_baseline_synced
export XPF_FAILOVER_CLOCK_BUDGET_S=10
FC_LAT_fw0="1.2:1.2 1.2:1.2 1.2:1.2"
FC_LAT_fw1="1.2:1.2 1.2:1.2 1.2:1.2"
fc_node_state() { echo "0.000 Normal"; }
fc_run "$TMP_DIR/c8.out" "noisy" fw0 fw1 fw0
rc=$?
if ((rc == 2)) && [[ "$FAILOVER_CLOCK_DETAIL" == *"no measurement (harness/lab): the reading's error +/-2.400 s is over the 1 s cap"* &&
	"$FAILOVER_CLOCK_DETAIL" == *"measurement too noisy"* ]]; then
	ok "too noisy: a 2.4 s error bound (over the 1 s cap) never converges, VOID"
else
	bad "too noisy: rc=$rc detail='$FAILOVER_CLOCK_DETAIL'"
fi

# ── 9. a synchronised chrony around a leap second ───────────────────────
fc_reset
fc_node_state() {
	case "$1" in
	fw0) echo "0.000 Insert second" ;;
	*) echo "0.150 Delete second" ;;
	esac
}
fc_run "$TMP_DIR/c9.out" "leap" fw0 fw1 fw0
rc=$?
if ((rc == 0)) && [[ "$FAILOVER_CLOCK_DETAIL" == *"synchronised on both: Insert second / Delete second"* ]]; then
	ok "leap second: Insert second / Delete second count as synchronised"
else
	bad "leap second: rc=$rc detail='$FAILOVER_CLOCK_DETAIL'"
fi

# ── 10. a node whose clock cannot be read ───────────────────────────────
fc_reset
fc_baseline_synced
export XPF_FAILOVER_CLOCK_BUDGET_S=4
fc_node_state() {
	case "$1" in
	fw0) echo "down" ;;
	*) echo "0.000 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c10.out" "final" fw0 fw1 fw0
rc=$?
if ((rc == 2)) && [[ "$FAILOVER_CLOCK_DETAIL" == *"no measurement (harness/lab): clock unreadable on fw0"* &&
	"$FAILOVER_CLOCK_DETAIL" == *"fw0: unreadable [-]"* ]]; then
	ok "an unreadable clock is VOID (no measurement), never converged"
else
	bad "unreadable clock: rc=$rc detail='$FAILOVER_CLOCK_DETAIL'"
fi

# ── 11. the escape: resync + banner + recorded mark ─────────────────────
fc_reset
export XPF_FAILOVER_CLOCK_RESYNC=1
fc_node_state() {
	case "$1" in
	fw0) echo "-72.000 Not synchronised" ;;
	*) echo "0.000 Normal" ;;
	esac
}
fc_run "$TMP_DIR/c11.out" "fw0 crash reboot" fw0 fw1 fw0
rc=$?
if ((rc == 0)) &&
	[[ "$(fc_clock_writes)" == $'fw0 date -u -s 2026-10-02 12:34:56\nfw1 date -u -s 2026-10-02 12:34:56' &&
		"$(wc -l <"$FC_HOSTREADS")" -eq 1 &&
		"$FAILOVER_CLOCK_RESYNCED" == 1 &&
		"$(fc_marker_field "$TMP_DIR/c11.out" resync)" == 1 &&
		"$FAILOVER_CLOCK_DETAIL" == *"RESYNCED from host UTC by XPF_FAILOVER_CLOCK_RESYNC=1 (NOT operator-faithful, not H1-H3 evidence; skew before resync +72.000 s)"* ]] &&
	grep -q 'THIS RUN IS NOT OPERATOR-FAITHFUL' "$TMP_DIR/c11.out" &&
	grep -q 'before resync: node1-node0 skew +72.000 s' "$TMP_DIR/c11.out"; then
	ok "escape: both nodes set from ONE host reading, banner, resync=1 marker, RESYNCED flag, pre-resync skew logged"
else
	bad "escape: rc=$rc writes='$(fc_clock_writes)' detail='$FAILOVER_CLOCK_DETAIL' out=$(cat "$TMP_DIR/c11.out")"
fi
fc_reset
export XPF_FAILOVER_CLOCK_RESYNC=1
FC_SET_FAIL_NODE=fw0
fc_run "$TMP_DIR/c11b.out" "fw0 crash reboot" fw0 fw1 fw0
rc=$?
if ((rc == 1)) && [[ "$(fc_clock_writes | cut -d' ' -f1 | tr '\n' ' ')" == 'fw0 fw1 ' ]] &&
	grep -q 'FAILED to set fw0' "$TMP_DIR/c11b.out" &&
	grep -q 'fw1 set to 2026-10-02 12:34:56 UTC' "$TMP_DIR/c11b.out" &&
	[[ "$FAILOVER_CLOCK_DETAIL" == *"could not resync both firewall clocks"* ]]; then
	ok "escape: a failed set names the node, does not skip the peer, and fails the cell"
else
	bad "escape failure: rc=$rc writes='$(fc_clock_writes)' detail='$FAILOVER_CLOCK_DETAIL'"
fi
fc_reset
export XPF_FAILOVER_CLOCK_RESYNC=yes
fc_run "$TMP_DIR/c11c.out" "phase1" fw0 fw1 fw0
rc=$?
if ((rc == 2)) && [[ -z "$(fc_clock_writes)" && ! -s "$FC_CALLS" &&
	"$FAILOVER_CLOCK_DETAIL" == *"XPF_FAILOVER_CLOCK_RESYNC must be 0 or 1 (got 'yes')"* ]] &&
	grep -q '^CLOCK_VOID: ' "$TMP_DIR/c11c.out"; then
	ok "an invalid escape value is refused (VOID), no clock read or set"
else
	bad "invalid escape value: rc=$rc detail='$FAILOVER_CLOCK_DETAIL' calls=$(cat "$FC_CALLS")"
fi
fc_reset
fc_run "$TMP_DIR/c11d.out" "phase1" fw0 fw1 fw9
rc_d=$?
failover_clock_precondition phase1 fw0 fw1 >/dev/null 2>&1
rc_e=$?
failover_resync_node_clocks >/dev/null 2>&1
rc_f=$?
if ((rc_d == 2 && rc_e == 2 && rc_f != 0)) && [[ ! -s "$FC_CALLS" ]]; then
	ok "a rebooted node that is neither node, a missing argument, and an empty resync list are refused"
else
	bad "refusals: rebooted=$rc_d argc=$rc_e resync=$rc_f calls=$(cat "$FC_CALLS")"
fi

# ── 12. the measure-only reading ────────────────────────────────────────
fc_reset
fc_node_state() {
	case "$1" in
	fw0) echo "-1.600 Not synchronised" ;;
	*) echo "0.000 Normal" ;;
	esac
}
failover_clock_reading "phase1 post-restart" fw0 fw1 >"$TMP_DIR/c12.out" 2>&1
rc=$?
fc_node_state() { echo "down"; }
failover_clock_reading "down" fw0 fw1 >>"$TMP_DIR/c12.out" 2>&1
rc2=$?
if ((rc == 0 && rc2 == 0)) && [[ -z "$(fc_clock_writes)" ]] &&
	grep -q '^clock reading \[phase1 post-restart\] (up fw0 [0-9]* s, fw1 [0-9]* s): node1-node0 skew +1.600 s (+/-0.280 s); chrony fw0: Not synchronised' "$TMP_DIR/c12.out" &&
	! grep -q '^CLOCK_PRECONDITION' "$TMP_DIR/c12.out"; then
	ok "reading: logs the post-crash state, judges nothing, emits no marker, touches no clock"
else
	bad "reading: rc=$rc/$rc2 out=$(cat "$TMP_DIR/c12.out")"
fi

# ── 13. the cell helper maps the verdict onto the caller's cells ─────────
cells=""
pass() { cells+="P:$1|"; }
fail() { cells+="F:$1|"; }
cell_case() { # <mode> <node-state> [stanza]
	cells=""
	fc_reset
	fc_baseline_synced
	FC_NTP_STANZA="${3:-present}"
	export XPF_FAILOVER_CLOCK_BUDGET_S=4
	eval "fc_node_state() { $2; }"
	failover_clock_cell "$1" "c" fw0 fw1 fw0 >"$TMP_DIR/c13.out" 2>&1
}
cell_case pass-fail 'echo "0.000 Normal"'
c_pf="$cells"
cell_case fail-only 'echo "0.000 Normal"'
c_fo="$cells"
export XPF_FAILOVER_CLOCK_RESYNC=1
cells=""
failover_clock_cell fail-only "c" fw0 fw1 fw0 >"$TMP_DIR/c13.out" 2>&1
c_rs="$cells"
unset XPF_FAILOVER_CLOCK_RESYNC
cell_case fail-only '[[ $1 == fw0 ]] && echo "-9.000 Normal" || echo "0.000 Normal"'
c_fl="$cells"
cell_case fail-only 'echo "0.000 Not synchronised"' absent
c_vd="$cells"
vline=$(grep -c '^  VOID  c: clock precondition VOID' "$TMP_DIR/c13.out")
void() { cells+="V:$1|"; }
cell_case fail-only 'echo "0.000 Not synchronised"' absent
c_vf="$cells"
unset -f void
if [[ "$c_pf" == "P:c: clock precondition: NTP converged"* && -z "$c_fo" &&
	"$c_rs" == "P:c: clocks RESYNCED"* && "$c_fl" == "F:c: clock precondition: NTP did not converge"* &&
	-z "$c_vd" && "$vline" == 1 && "$c_vf" == "V:c: clock precondition VOID"* ]]; then
	ok "cell: pass-fail PASSes, fail-only is silent, a resync always gets a PASS line, FAIL -> fail, VOID -> void() or a VOID line"
else
	bad "cell: pf='$c_pf' fo='$c_fo' rs='$c_rs' fl='$c_fl' vd='$c_vd' vline=$vline vf='$c_vf'"
fi
unset -f pass fail

# ── 14. the ledger records the clock (producer/consumer contract) ────────
# The REAL adapter reads the REAL marker lines: a renamed key or a changed line
# shape on either side reds here instead of silently dropping the record.
HR="${SCRIPT_DIR}/harness-result.sh"
adapt() { bash "$HR" adapt "$1" "$2" "$3"; }
mklog() { # <out> <summary> <files...>
	local out="$1" summary="$2"
	shift 2
	{
		cat "$@"
		echo "  PASS  iperf3 throughput 9.1 Gbps"
		[[ -n "$summary" ]] && echo "  HA crash test: $summary"
	} >"$out"
}
L="$TMP_DIR/ledger"
mklog "$L-ok.log" "7 passed, 0 failed" "$TMP_DIR/c1.out" "$TMP_DIR/c2.out"
mklog "$L-resync.log" "7 passed, 0 failed" "$TMP_DIR/c1.out" "$TMP_DIR/c11.out" "$TMP_DIR/c2.out"
mklog "$L-fail.log" "6 passed, 1 failed" "$TMP_DIR/c1.out" "$TMP_DIR/c3.out"
mklog "$L-void.log" "7 passed, 0 failed" "$TMP_DIR/c4.out"
mklog "$L-void77.log" "" "$TMP_DIR/c4.out"
mklog "$L-none.log" "7 passed, 0 failed" /dev/null
contract_ok=1
expect() { # <what> <row> <verdict> <reason-glob> <metric-globs...>
	local what="$1" row="$2" v="$3" r="$4" g
	shift 4
	[[ "$(cut -f1 <<<"$row")" == "$v" && "$(cut -f2 <<<"$row")" == $r ]] || {
		contract_ok=0
		echo "  $what: row '$row'" >&2
	}
	for g in "$@"; do
		[[ " $(cut -f5 <<<"$row") " == $g ]] || {
			contract_ok=0
			echo "  $what: metrics '$(cut -f5 <<<"$row")' miss $g" >&2
		}
	done
}
for a in smoke-cells ha-smoke; do
	expect "$a ok" "$(adapt "$a" 0 "$L-ok.log")" PASS "" '* clock_resync=0 *' '* clock_converged=1 *' '* clock_void=0 *'
	expect "$a resync" "$(adapt "$a" 0 "$L-resync.log")" VOID '#18614 clock_resync=1: *cannot satisfy H1-H3' '* clock_resync=1 *'
	expect "$a fail" "$(adapt "$a" 1 "$L-fail.log")" FAIL "" '* clock_converged=0 *' '* clock_void=0 *'
	expect "$a void" "$(adapt "$a" 0 "$L-void.log")" VOID '#18614 clock precondition VOID: phase1: clock precondition VOID: no time source*' '* clock_void=1 *'
	expect "$a void77" "$(adapt "$a" 77 "$L-void77.log")" VOID '*CLOCK_VOID: phase1: clock precondition VOID: no time source*'
	row=$(adapt "$a" 0 "$L-none.log")
	expect "$a none" "$row" PASS ""
	[[ "$(cut -f5 <<<"$row")" != *clock_* ]] || {
		contract_ok=0
		echo "  $a none: clock keys on a row with no precondition: $row" >&2
	}
done
if ((contract_ok)); then
	ok "ledger: clock_resync/clock_converged/clock_void ride the row; a resynced or clock-VOID PASS is recorded VOID with the reason; a clock FAIL stays FAIL"
else
	bad "ledger: the adapters do not record the clock as the library reports it"
fi

# ── 15. mutation: a silent resync re-added on the measured path ──────────
# Proves the dynamic detector can fire. The splice is checked to have landed:
# a sed that misses its anchor exits 0 and would "pass" here.
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
		failover_clock_precondition "phase1" fw0 fw1 fw0 >/dev/null 2>&1
		fc_clock_writes
	)
	if [[ "$mut_writes" == *"fw0 date -u -s"* && "$mut_writes" == *"fw1 date -u -s"* ]]; then
		ok "mutation: a silent date -s spliced into the measured path is detected (killed)"
	else
		bad "mutation: a silent date -s on the measured path went UNDETECTED (writes='$mut_writes')"
	fi
fi

# ── 16. static census: nothing sets a clock outside the escape ───────────
# A line is normalised first (quotes, commas, brackets, parentheses -> space),
# so one pattern sees the shell spellings (`date "-s"`, `date -s"..."`) and the
# Python list form (`["date", "-s", now]`).
# date: a set flag anywhere in its arguments (`-u -d X -s T`), its value
# attached or not (`-s@N`, `-s2026-...`), or the positional MMDDhhmm form.
FC_SETTER_RE='(^|[^[:alnum:]_-])date[[:space:]]([^|;&]*[[:space:]])?(-s|-us|-su|--set)([[:space:]=@0-9]|$)'
FC_SETTER_RE+='|(^|[^[:alnum:]_-])date([[:space:]]+-[[:alnum:]]+)*[[:space:]]+[0-9]{8}([0-9]{2}){0,2}([.][0-9]{2})?([[:space:]]|$)'
FC_SETTER_RE+='|(^|[^[:alnum:]_-])timedatectl[[:space:]]+set-time'
FC_SETTER_RE+='|(^|[^[:alnum:]_-])hwclock[[:space:]].*(--hctosys|--systohc|(^|[[:space:]])-[sw]([[:space:]]|$))'
FC_SETTER_RE+='|(^|[^[:alnum:]_-])chronyc[[:space:]].*(makestep|settime)'
FC_SETTER_RE+='|(^|[^[:alnum:]_-])chronyd[[:space:]]([^|;&]*[[:space:]])?-q([[:space:]]|$)'
FC_SETTER_RE+='|(^|[^[:alnum:]_-])ntpd[[:space:]]([^|;&]*[[:space:]])?-[[:alnum:]]*q'
FC_SETTER_RE+='|(^|[^[:alnum:]_-])(ntpdate|adjtimex|phc_ctl)([[:space:]]|$)'
FC_SETTER_RE+='|(^|[^[:alnum:]_-])sntp[[:space:]]([^|;&]*[[:space:]])?-[[:alnum:]]*[sS]([[:space:]]|$)'
FC_SETTER_RE+='|(^|[^[:alnum:]_-])rdate[[:space:]]([^|;&]*[[:space:]])?-[[:alnum:]]*s([[:space:]]|$)'
FC_SETTER_RE+='|clock_settime|settimeofday|clock_adjtime'
FC_DIRECT_RE='(^|[^[:alnum:]_])failover_resync_node_clocks([^[:alnum:]_]|$)'
fc_normalise() { tr "\"',()[]" '       '; }
fc_sets_clock() { grep -qE "$FC_SETTER_RE" <<<"$(fc_normalise <<<"$1")"; }
matcher_ok=1
for l in 'incus exec "$n" -- date -u -s "$now"' 'incus exec fw1 -- date -s "2026-10-31 10:00:00"' \
	'incus exec fw0 -- date --set="@1793440000"' 'incus exec fw0 -- date -s@1793440000' \
	'incus exec fw0 -- date -s"2026-10-31 10:00"' 'incus exec fw0 -- date "-s" "2026-10-31"' \
	'incus exec fw0 -- timedatectl set-time "2026-10-31"' 'incus exec fw0 -- hwclock --hctosys' \
	'incus exec fw0 -- chronyc makestep' "incus exec fw0 -- chronyd -q 'server 162.159.200.1 iburst'" \
	'incus exec fw0 -- ntpd -gq' 'ntpdate pool.ntp.org' 'incus exec fw0 -- adjtimex -o 100' \
	'time.clock_settime(time.CLOCK_REALTIME, t)' 'subprocess.run(["incus", "exec", n, "--", "date", "-s", now])' \
	'subprocess.run(["incus", "exec", n, "--", "chronyc", "makestep"])' \
	'incus exec fw0 -- date -s2026-10-31T10:00:00' 'incus exec fw0 -- date -u -d "2026-10-31" -s "10:00"' \
	'incus exec fw0 -- date 103110002026' 'incus exec fw0 -- date -u 10311000' 'incus exec fw0 -- sntp -S 162.159.200.1' \
	'incus exec fw0 -- rdate -s time.example' 'incus exec fw0 -- phc_ctl /dev/ptp0 set'; do
	fc_sets_clock "$l" || {
		matcher_ok=0
		echo "  matcher MISSED: $l" >&2
	}
done
for l in 'incus exec "$node" -- date +%s.%N' 'date -u +%T.%N' 'date -u "+%Y-%m-%d %H:%M:%S"' \
	'timeout 10 incus exec "$1" -- timeout 10 chronyc -n tracking' 'date -d @1793440000 +%s' 'date -Iseconds' \
	"incus exec fw0 -- chronyd -Q 'server 162.159.200.1 iburst'" 'time.clock_gettime(time.CLOCK_REALTIME)' \
	'self._exec(ref, ["date", "+%s.%N"], timeout=10)' 'incus exec fw0 -- timedatectl show' 'chronyc -n sources' \
	'date +%s -d "2026-10-31"' 'sntp 162.159.200.1' 'rdate -p time.example' \
	"timeout 20 incus exec \"\$n\" -- cli -c 'show configuration system ntp'"; do
	if fc_sets_clock "$l"; then
		matcher_ok=0
		echo "  matcher FALSE POSITIVE: $l" >&2
	fi
done
if ((matcher_ok)); then
	ok "census matcher: sees all 23 setter shapes (date -s/-s@/-s2026/-s\"\"/\"-s\"/--set/-d X -s T/MMDDhhmm, timedatectl, hwclock, chronyc makestep, chronyd -q, ntpd -gq, ntpdate, adjtimex, sntp -S, rdate -s, phc_ctl, clock_settime, Python list form) and none of 15 reads"
else
	bad "census matcher: missed a setter or flagged a read"
fi

# fc_census_scan <file>... -- one line per finding. Comment lines are skipped.
# In the library the escape's own bodies are the one sanctioned setter and the
# one sanctioned resync call; in every other file a resync call is a finding,
# however the file got the function (source, `.`, or a sourced file that
# sources it). A file that sources the library must also run its check.
fc_census_scan() {
	local f lib hits code
	for f in "$@"; do
		lib=0
		[[ "$(basename "$f")" == failover-clock-lib.sh ]] && lib=1
		code=$(awk -v lib="$lib" '
			lib == 1 && /^(failover_resync_node_clocks|_failover_clock_escape)\(\) \{$/ { skip = 1 }
			skip { if (/^\}$/) skip = 0; next }
			/^[[:space:]]*#/ { next }
			{ print }' "$f")
		hits=$(fc_normalise <<<"$code" | grep -E "$FC_SETTER_RE" || true)
		[[ -n "$hits" ]] && printf '%s: sets a clock: %s\n' "$f" "$(head -1 <<<"$hits")"
		hits=$(grep -E "$FC_DIRECT_RE" <<<"$code" || true)
		[[ -n "$hits" ]] && printf '%s: calls failover_resync_node_clocks directly: %s\n' "$f" "$(head -1 <<<"$hits")"
		if ((lib == 0)) && grep -qE '^[[:space:]]*(source|\.)[[:space:]]+.*failover-clock-lib\.sh' <<<"$code"; then
			grep -qE '(^|[^[:alnum:]_])failover_clock_(cell|precondition)[[:space:]]' <<<"$code" ||
				printf '%s: sources failover-clock-lib.sh but never runs the clock check\n' "$f"
			# A clock VOID must reach the exit code of a direct run too.
			grep -qE '^void\(\)' <<<"$code" ||
				printf '%s: runs the clock check but defines no void(), so a clock VOID exits 0 when run directly\n' "$f"
		fi
	done
}

# File-level positive controls: the scan, not just the matcher, must see each
# evasion in a planted file, and must not flag a sanctioned escape body.
FX="$TMP_DIR/fixtures"
mkdir -p "$FX/lib"
printf '#!/bin/bash\n. ./failover-clock-lib.sh\nvoid() { :; }\nfailover_clock_cell fail-only x "$A" "$B" "$A"\nfailover_resync_node_clocks "$A" "$B"\n' >"$FX/dot-source.sh"
printf '#!/bin/bash\nsource ./failover-clock-lib.sh\nfailover_clock_cell fail-only x "$A" "$B" "$A"\n' >"$FX/no-void.sh"
printf '#!/bin/bash\nsource ./other-lib.sh\nfailover_resync_node_clocks "$A" "$B"\n' >"$FX/indirect.sh"
printf '#!/bin/bash\nsource ./failover-clock-lib.sh\n# failover_clock_cell is mentioned only in a comment\n' >"$FX/no-check.sh"
printf '#!/bin/bash\n. "$DIR/failover-clock-lib.sh"\necho no check here\n' >"$FX/dot-no-check.sh"
printf 'import time\n# date -s is fine in a comment\ntime.clock_settime(time.CLOCK_REALTIME, 0)\n' >"$FX/py-settime.py"
printf 'import subprocess\nsubprocess.run(["incus", "exec", n, "--", "date", "-s@1793440000"])\n' >"$FX/py-list.py"
printf '#!/bin/bash\nincus exec "$n" -- date "-s" "$now"\n' >"$FX/quoted.sh"
printf '#!/bin/bash\n# date -u -s "$now" in a comment is not a call\necho "date +%%s.%%N"\n' >"$FX/clean.sh"
printf 'failover_resync_node_clocks() {\n\tincus exec "$n" -- date -u -s "$now"\n}\n_failover_clock_escape() {\n\tfailover_resync_node_clocks "$2" "$3"\n}\nfoo() {\n\tincus exec "$n" -- hwclock --hctosys\n}\n' >"$FX/lib/failover-clock-lib.sh"
fx_out=$(fc_census_scan "$FX"/*.sh "$FX"/*.py "$FX/lib/failover-clock-lib.sh")
fx_ok=1
for want in "dot-source.sh: calls failover_resync_node_clocks directly" "indirect.sh: calls failover_resync_node_clocks directly" \
	"no-check.sh: sources failover-clock-lib.sh but never runs the clock check" \
	"dot-no-check.sh: sources failover-clock-lib.sh but never runs the clock check" "no-void.sh: runs the clock check but defines no void()" \
	"py-settime.py: sets a clock" \
	"py-list.py: sets a clock" "quoted.sh: sets a clock" "lib/failover-clock-lib.sh: sets a clock:" "hwclock --hctosys"; do
	[[ "$fx_out" == *"$want"* ]] || {
		fx_ok=0
		echo "  census fixture MISSED: $want" >&2
	}
done
if [[ "$fx_out" == *"clean.sh"* ]] || (($(grep -c 'lib/failover-clock-lib.sh' <<<"$fx_out") != 1)); then
	fx_ok=0
	echo "  census fixture false positive: $fx_out" >&2
fi
if ((fx_ok)); then
	ok "census fixtures: dot-sourced and indirect direct calls, a sourcing and a dot-sourcing file with no check, Python settime and list form, a quoted flag are all found; a comment and the sanctioned escape bodies are not"
else
	bad "census fixtures: the file-level scan missed an evasion or flagged a sanctioned line"
fi

# The real tree: every shell and Python harness under test/incus/ and scripts/.
mapfile -t census_files < <(
	{
		find "$SCRIPT_DIR" -maxdepth 1 -type f \( -name '*.sh' -o -name '*.py' \)
		find "$REPO_ROOT/scripts" -type f \( -name '*.sh' -o -name '*.py' \)
	} | grep -vE '(-selftest\.sh|_selftest\.sh|_test\.py|/test_[^/]*\.py)$' | sort
)
census_out=$(fc_census_scan "${census_files[@]}")
n_py=$(printf '%s\n' "${census_files[@]}" | grep -c '\.py$')
n_scripts=$(printf '%s\n' "${census_files[@]}" | grep -c '/scripts/')
sourcing=0
for f in "${census_files[@]}"; do
	grep -qE '^[[:space:]]*(source|\.)[[:space:]]+.*failover-clock-lib\.sh' "$f" && sourcing=$((sourcing + 1))
done
# Denominator, by NAME as well as by count: the census must have read the three
# crash smokes, the Python H11 soak beside them, and shell and Python under
# scripts/, or a green here means it scanned less than it claims.
missing=""
# Into a variable, never `printf | grep -q`: under pipefail an early -q exit
# can SIGPIPE the producer and read a present file as missing.
census_list=$(printf '%s\n' "${census_files[@]}")
for want in test/incus/test-failover.sh test/incus/test-ha-crash.sh test/incus/test-double-failover.sh \
	test/incus/rg_move_soak.py scripts/harness-census.sh scripts/iperf-json-metrics.py; do
	grep -qF "/$want" <<<"$census_list" || missing+=" $want"
done
if [[ -n "$missing" ]] || ((sourcing < 3 || ${#census_files[@]} < 100 || n_py < 10 || n_scripts < 30)); then
	bad "census: scanned ${#census_files[@]} files (${n_py} Python, ${n_scripts} under scripts/), ${sourcing} sourcing the clock library; missing by name:${missing:- none}"
elif [[ -n "$census_out" ]]; then
	bad "census: a harness sets a node clock or bypasses the escape:"$'\n'"$census_out"
else
	ok "census: ${#census_files[@]} harness files (${n_py} Python, ${n_scripts} under scripts/), ${sourcing} run the clock check, none sets a clock or calls the resync outside the escape"
fi

# ── 17. test-failover's iperf window pays for the clock floor's overshoot ──
# The clock wait shares REBOOT_WAIT's unused time plus the 20 s settle, floored
# at N s; past a slow comeback the floor runs up to N - 20 s beyond that, and
# IPERF_DURATION_MIN must carry it, or the stream ends before the failback.
TF="${SCRIPT_DIR}/test-failover.sh"
floor=$(sed -nE 's/^\(\( clock_budget >= ([0-9]+) \)\) \|\| clock_budget=[0-9]+$/\1/p' "$TF")
over=$(sed -nE 's/^CLOCK_FLOOR_OVERSHOOT=([0-9]+)$/\1/p' "$TF")
if [[ -n "$floor" && -n "$over" ]] && ((floor - 20 <= over)) &&
	grep -qE '^IPERF_DURATION_MIN=\$\(\(.*\+ CLOCK_FLOOR_OVERSHOOT \+' "$TF"; then
	ok "test-failover: the ${floor} s clock floor's overshoot (${floor} - 20 s) is paid by CLOCK_FLOOR_OVERSHOOT=${over} in IPERF_DURATION_MIN"
else
	bad "test-failover: clock floor '${floor}' s, CLOCK_FLOOR_OVERSHOOT '${over}', or its IPERF_DURATION_MIN term is missing or too small"
fi

echo "----------------------------------------"
echo "failover clock selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
