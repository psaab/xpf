#!/usr/bin/env bash
#
# Clock precondition for the crash-failover smokes (#18614).
#
# A crash-rebooted node comes back on its RTC and keeps whatever offset that
# left it with until chrony steps or slews it. An operator's cluster lives in
# that state, so the smokes must too: after a crash reboot they WAIT, with a
# bounded budget, for NTP to converge on both nodes, log the skew and how long
# it took, and FAIL the cell when it does not converge. They never set a clock.
#
# History. #11872 added `failover_resync_node_clocks` (`date -u -s` on both
# nodes from one host reading) because the loss lab had no NTP: a crash reboot
# came back 2m18s behind and broke fabric auth and every failback. Since #18589
# chrony reaches NTP through vrf-mgmt, and the resync only hid the skew that
# broke the operator's RG-move loop (docs/ha-rg-move-correctness.md, matrix row
# H11). It survives solely as the explicit XPF_FAILOVER_CLOCK_RESYNC=1 escape
# for a lab with no NTP. The escape prints a banner and records
# `resync=1` on its CLOCK_PRECONDITION line, which harness-result.sh turns into
# `clock_resync=1` on the ledger row, so a resynced run never reads as an
# operator-faithful one.
#
# Knobs (read at call time):
#   XPF_FAILOVER_CLOCK_SKEW_BOUND_S  5    |node1 - node0| must be at most this
#   XPF_FAILOVER_CLOCK_BUDGET_S      120  seconds to wait for convergence
#   XPF_FAILOVER_CLOCK_POLL_S        2    seconds between samples
#   XPF_FAILOVER_CLOCK_SAMPLES       3    incus-exec date samples per node per
#                                         reading; the minimum-RTT one is used
#   XPF_FAILOVER_CLOCK_RESYNC        0    1 = the no-NTP escape (sets clocks)
#
# Why 5 s and 120 s (#18614 evidence, docs/ha-rg-move-correctness.md):
#   - What it protects: every skew under 30 s authenticates in any fabric
#     token window alignment, and #18585 alarms at 10 s. 5 s is half that
#     alarm, so a converged cluster never sits next to it.
#   - What it must not trip on. On loss with both nodes Normal, this method
#     read up to 0.23 s with the heartbeat at 0.0 s (RTT 0.18-0.21 s). On the
#     #18614 live runs, six crash reboots converged at -1.07, +0.07, +0.49,
#     +0.04, -1.11 and -1.49 s. The three near -1 s were read within seconds
#     of fw0 turning Normal. A 2 s bound would have left 0.5 s of margin.
#   - `Leap status: Normal` on both nodes is what shows that chrony
#     synchronised. The bound catches a node that reports synchronised while
#     still seconds off: slewing outside the `makestep 1 3` window, or its
#     servers disagreeing.
#   - The budget. On that live run (4 force-stop reboots of fw0, 0.0.26315),
#     chrony reached Normal 17.2-18.1 s after xpfd reported active; xpfd
#     itself was active 19-20 s after `incus start`. 120 s is over 6x that,
#     and still covers one full 64 s default poll interval if the first iburst
#     round runs before vrf-mgmt can route.

# failover_clock_precondition <label> <node0> <node1>
#   The measured precondition. Samples both nodes until the node1-node0 skew is
#   within the bound AND chrony reports `Leap status: Normal` on both, or the
#   budget runs out. Prints one line per state change and a CLOCK_PRECONDITION
#   marker line, and sets FAILOVER_CLOCK_DETAIL to a one-line verdict for the
#   caller's pass/fail cell. Returns 0 when converged (or, under the escape,
#   when the resync succeeded) and 1 otherwise.
failover_clock_precondition() {
	FAILOVER_CLOCK_DETAIL=""
	# No reading may leak from an earlier call into this one's lines.
	_FC_SKEW="" _FC_UNC="" _FC_DOWN="" _FC_LEAP0="" _FC_LEAP1="" _FC_REF0="" _FC_REF1=""
	if (($# != 3)); then
		FAILOVER_CLOCK_DETAIL="clock precondition: usage: failover_clock_precondition <label> <node0> <node1>"
		echo "$FAILOVER_CLOCK_DETAIL" >&2
		return 1
	fi
	local label="$1" n0="$2" n1="$3"
	local bound="${XPF_FAILOVER_CLOCK_SKEW_BOUND_S:-5}"
	local budget="${XPF_FAILOVER_CLOCK_BUDGET_S:-120}"
	local poll="${XPF_FAILOVER_CLOCK_POLL_S:-2}"
	local samples="${XPF_FAILOVER_CLOCK_SAMPLES:-3}"
	local knob
	for knob in "$bound" "$budget" "$poll"; do
		if ! [[ "$knob" =~ ^[0-9]+([.][0-9]+)?$ ]] || ! awk -v v="$knob" 'BEGIN { exit !(v > 0) }'; then
			_failover_clock_refuse "$label" "the skew bound, budget and poll interval must be positive numbers (got bound='${bound}' budget='${budget}' poll='${poll}')"
			return 1
		fi
	done
	if ! [[ "$samples" =~ ^[1-9][0-9]*$ ]]; then
		_failover_clock_refuse "$label" "XPF_FAILOVER_CLOCK_SAMPLES must be a positive integer (got '${samples}')"
		return 1
	fi
	case "${XPF_FAILOVER_CLOCK_RESYNC:-0}" in
	0) ;;
	1)
		_failover_clock_escape "$label" "$n0" "$n1" "$samples" "$bound" "$budget"
		return
		;;
	*)
		_failover_clock_refuse "$label" "XPF_FAILOVER_CLOCK_RESYNC must be 0 or 1 (got '${XPF_FAILOVER_CLOCK_RESYNC}')"
		return 1
		;;
	esac
	_failover_clock_wait "$label" "$n0" "$n1" "$samples" "$bound" "$budget" "$poll"
}

# _failover_clock_wait <label> <n0> <n1> <samples> <bound> <budget> <poll>
#   The measured path. It reads clocks and chrony state, and nothing else.
_failover_clock_wait() {
	local label="$1" n0="$2" n1="$3" samples="$4" bound="$5" budget="$6" poll="$7"
	local start now elapsed state="" prev="" first=1
	start=$(date +%s.%N)
	while :; do
		_failover_clock_measure "$n0" "$n1" "$samples"
		now=$(date +%s.%N)
		elapsed=$(awk -v a="$start" -v b="$now" 'BEGIN { printf "%.1f", b - a }')
		if _failover_clock_converged "$bound"; then
			echo "clock precondition [${label}]: converged ${elapsed} s after the check began ($(_failover_clock_uptimes "$n0" "$n1")): $(_failover_clock_state_text "$n0" "$n1") (bound ${bound} s)"
			_failover_clock_marker "$label" 0 1 "$elapsed" "$bound" "$budget"
			FAILOVER_CLOCK_DETAIL="${label}: clock precondition: NTP converged in ${elapsed} s (node1-node0 skew ${_FC_SKEW} s, bound ${bound} s; chrony Leap status Normal on both)"
			return 0
		fi
		if awk -v e="$elapsed" -v b="$budget" 'BEGIN { exit !(e >= b) }'; then
			echo "clock precondition [${label}]: NOT converged after ${elapsed} s (budget ${budget} s; $(_failover_clock_uptimes "$n0" "$n1")): $(_failover_clock_state_text "$n0" "$n1")"
			_failover_clock_marker "$label" 0 0 "-" "$bound" "$budget"
			FAILOVER_CLOCK_DETAIL="${label}: clock precondition: NTP did not converge after a crash reboot within ${budget} s: $(_failover_clock_state_text "$n0" "$n1"); needs |skew| <= ${bound} s and Leap status Normal on both nodes. No clock was set (XPF_FAILOVER_CLOCK_RESYNC=1 is the no-NTP escape)"
			return 1
		fi
		# One line for the first reading (the post-crash state) and one per
		# change, so a long wait does not flood the log.
		state="${_FC_LEAP0}|${_FC_LEAP1}|$(_failover_clock_within "$bound" && echo in || echo out)"
		if ((first)) || [[ "$state" != "$prev" ]]; then
			echo "clock precondition [${label}]: ${elapsed} s: waiting: $(_failover_clock_state_text "$n0" "$n1") (bound ${bound} s, budget ${budget} s)"
		fi
		first=0
		prev="$state"
		sleep "$poll"
	done
}

# _failover_clock_escape <label> <n0> <n1> <samples> <bound> <budget>
#   XPF_FAILOVER_CLOCK_RESYNC=1. Measures and logs the state first, so the run
#   still shows what the operator would have seen, then sets both clocks.
_failover_clock_escape() {
	local label="$1" n0="$2" n1="$3" samples="$4" bound="$5" budget="$6" rc
	_failover_clock_measure "$n0" "$n1" "$samples"
	echo "clock precondition [${label}]: before resync: $(_failover_clock_state_text "$n0" "$n1")"
	cat <<'BANNER'
##############################################################################
##  XPF_FAILOVER_CLOCK_RESYNC=1: SETTING BOTH NODE CLOCKS FROM THE HOST     ##
##  (date -u -s). THIS RUN IS NOT OPERATOR-FAITHFUL: it repairs the clock   ##
##  state a crash-rebooted cluster really lives in, so a skew that breaks   ##
##  fabric auth or failback cannot show up here (#18614). The ledger row    ##
##  records clock_resync=1. Use only on a lab with no NTP.                  ##
##############################################################################
BANNER
	failover_resync_node_clocks "$n0" "$n1"
	rc=$?
	_failover_clock_marker "$label" 1 - "-" "$bound" "$budget"
	if ((rc == 0)); then
		FAILOVER_CLOCK_DETAIL="${label}: clocks RESYNCED from host UTC by XPF_FAILOVER_CLOCK_RESYNC=1 (NOT operator-faithful; skew before resync ${_FC_SKEW:-unreadable} s)"
	else
		FAILOVER_CLOCK_DETAIL="${label}: XPF_FAILOVER_CLOCK_RESYNC=1 could not resync both firewall clocks from host UTC (skew before resync ${_FC_SKEW:-unreadable} s)"
	fi
	return "$rc"
}

# _failover_clock_refuse <label> <reason> — a misconfigured call. No clock is
# read or set; the cell fails with the reason.
_failover_clock_refuse() {
	FAILOVER_CLOCK_DETAIL="${1}: clock precondition refused: ${2}; no clock was touched"
	echo "clock precondition [${1}]: REFUSED: ${2}"
	_failover_clock_marker "$1" 0 0 "-" "-" "-"
}

# _failover_clock_marker <label> <resync> <converged> <converge_s> <bound> <budget>
#   The machine-readable line harness-result.sh reads (`clock_resync`). The
#   label goes last because it may contain spaces.
_failover_clock_marker() {
	printf 'CLOCK_PRECONDITION: resync=%s converged=%s skew_s=%s converge_s=%s bound_s=%s budget_s=%s label=%s\n' \
		"$2" "$3" "${_FC_SKEW:--}" "$4" "$5" "$6" "$1"
}

# _failover_clock_measure <n0> <n1> <samples>
#   One reading of both nodes into the _FC_* globals: _FC_SKEW (node1-node0,
#   seconds, empty when either clock was unreadable), _FC_UNC (the half-RTT
#   sum, the measurement's own error bound), _FC_LEAP0/1, _FC_REF0/1 and
#   _FC_DOWN (the nodes whose clock could not be read).
_failover_clock_measure() {
	local n0="$1" n1="$2" samples="$3" o0 o1 c0 c1
	_FC_SKEW="" _FC_UNC="" _FC_DOWN=""
	o0=$(_failover_clock_offset "$n0" "$samples") || {
		o0=""
		_FC_DOWN="$n0"
	}
	o1=$(_failover_clock_offset "$n1" "$samples") || {
		o1=""
		_FC_DOWN="${_FC_DOWN:+$_FC_DOWN }$n1"
	}
	c0=$(_failover_clock_chrony "$n0")
	c1=$(_failover_clock_chrony "$n1")
	_FC_LEAP0="${c0%%|*}" _FC_REF0="${c0#*|}"
	_FC_LEAP1="${c1%%|*}" _FC_REF1="${c1#*|}"
	if [[ -n "$o0" && -n "$o1" ]]; then
		read -r _FC_SKEW _FC_UNC < <(awk -v a="$o0" -v b="$o1" 'BEGIN {
			split(a, x, " "); split(b, y, " ")
			printf "%+.3f %.3f\n", y[1] - x[1], (x[2] + y[2]) / 2 }')
	fi
}

# _failover_clock_offset <node> <samples>
#   NTP-style offset of <node>'s wall clock against this host, from the
#   minimum-RTT of <samples> `incus exec date` readings (the same method as
#   rg_move_soak.py measure_offset). The host clock cancels out of the
#   node1-node0 difference. Prints "<offset_s> <rtt_s>" (positive = node
#   ahead); returns 1 when no reading succeeded.
_failover_clock_offset() {
	local node="$1" samples="$2" i a r b best=""
	for ((i = 0; i < samples; i++)); do
		a=$(date +%s.%N)
		r=$(incus exec "$node" -- date +%s.%N 2>/dev/null) || continue
		b=$(date +%s.%N)
		[[ "$r" =~ ^[0-9]+([.][0-9]+)?$ ]] || continue
		best=$(awk -v a="$a" -v r="$r" -v b="$b" -v best="$best" 'BEGIN {
			off = r - (a + b) / 2; rtt = b - a
			if (best != "") { split(best, p, " "); if (p[2] + 0 <= rtt) { print best; exit } }
			printf "%.3f %.3f\n", off, rtt }')
	done
	[[ -n "$best" ]] || return 1
	printf '%s\n' "$best"
}

# _failover_clock_chrony <node> — "<leap status>|<reference id>" from
# `chronyc -n tracking`; "unreadable|-" when chronyc did not answer.
_failover_clock_chrony() {
	local out leap ref
	if ! out=$(incus exec "$1" -- timeout 10 chronyc -n tracking 2>/dev/null); then
		printf 'unreadable|-\n'
		return 0
	fi
	leap=$(sed -n '/^Leap status/{s/^Leap status[[:space:]]*:[[:space:]]*//p;q;}' <<<"$out")
	ref=$(sed -n '/^Reference ID/{s/^Reference ID[[:space:]]*:[[:space:]]*//p;q;}' <<<"$out")
	printf '%s|%s\n' "${leap:-unreadable}" "${ref:--}"
}

# _failover_clock_uptimes <n0> <n1> -- "up <n0> <s> s, <n1> <s> s", so a
# convergence time read at any point after a crash reboot can be put on the
# rebooted node's own boot timeline.
_failover_clock_uptimes() {
	local n up out=""
	for n in "$@"; do
		up=$(incus exec "$n" -- cat /proc/uptime 2>/dev/null) || up=""
		up="${up%% *}"
		[[ "$up" =~ ^[0-9]+([.][0-9]+)?$ ]] && up="${up%%.*} s" || up="unreadable"
		out="${out:+$out, }${n} ${up}"
	done
	printf 'up %s' "$out"
}

_failover_clock_within() {
	[[ -n "$_FC_SKEW" ]] && awk -v s="$_FC_SKEW" -v b="$1" 'BEGIN { if (s < 0) s = -s; exit !(s <= b) }'
}

_failover_clock_converged() {
	_failover_clock_within "$1" && [[ "$_FC_LEAP0" == Normal && "$_FC_LEAP1" == Normal ]]
}

_failover_clock_state_text() {
	local skew
	if [[ -n "$_FC_SKEW" ]]; then
		skew="node1-node0 skew ${_FC_SKEW} s (+/-${_FC_UNC} s)"
	else
		skew="node1-node0 skew unknown (clock unreadable on ${_FC_DOWN})"
	fi
	printf '%s; chrony %s: %s [%s], %s: %s [%s]' "$skew" \
		"$1" "$_FC_LEAP0" "$_FC_REF0" "$2" "$_FC_LEAP1" "$_FC_REF1"
}

# failover_resync_node_clocks <node>...
#   THE ESCAPE ONLY (#11872): set every named node's wall clock from a SINGLE
#   host reading, so the nodes agree by construction. A harness must not call
#   this directly; failover_clock_precondition calls it under
#   XPF_FAILOVER_CLOCK_RESYNC=1, which is what makes the banner and the
#   ledger flag unavoidable (failover-clock-selftest.sh enforces this).
#   Prints one line per node ("set ..." / "FAILED ..."); returns 0 only if
#   every node was set. Every node is ATTEMPTED even when an earlier one
#   failed, so one down node does not hide the other's outcome.
#   FAILOVER_CLOCK_NOW overrides the host reading (hermetic self-test seam).
failover_resync_node_clocks() {
	if (($# == 0)); then
		echo "failover_resync_node_clocks: no nodes given" >&2
		return 1
	fi
	local now="${FAILOVER_CLOCK_NOW:-$(date -u '+%Y-%m-%d %H:%M:%S')}"
	local node rc=0
	for node in "$@"; do
		if incus exec "$node" -- date -u -s "$now" >/dev/null 2>&1; then
			echo "clock resync: $node set to ${now} UTC"
		else
			echo "clock resync: FAILED to set $node to ${now} UTC" >&2
			rc=1
		fi
	done
	return "$rc"
}
