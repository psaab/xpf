#!/usr/bin/env bash
#
# Clock precondition for the crash-failover smokes (#18614).
#
# A crash-rebooted node comes back on its RTC and keeps whatever offset that
# left it with until chrony steps or slews it. An operator's cluster lives in
# that state, so the smokes must too: after a crash reboot they WAIT, with a
# bounded budget, for NTP to converge on both nodes, log the skew and how long
# it took, and score the cell from WHO did not converge. They never set a
# clock.
#
# Scoring (failover_clock_precondition's return code), always from the
# CURRENT reading; the pre-crash baseline is context in the reason only:
#   0 PASS  both nodes synchronised and the skew, error included, in bound.
#   2 VOID  only where the build cannot be in the path:
#           - neither node synchronised AND no `system ntp` is configured (a
#             config fact the build cannot influence: a lab that never had
#             the #18584 stanza committed);
#           - neither node synchronised, `system ntp` configured, and none of
#             its servers answers an SNTP query from THIS host either (the
#             off-path control: a lab NTP outage);
#           - no measurement: a clock unreadable, a reading too noisy, the
#             ntp config unreadable, or a misconfigured call (harness/lab).
#   1 FAIL  everything else -- lab, NTP or product, because xpfd owns chrony's
#           vrf-mgmt binding and its restart (#18584/#18589,
#           pkg/daemon/daemon_system.go):
#           - ONE node synchronised and the other not (the #18584 class: only
#             the RG owner reaching NTP is how fw1 drifted 60-90 s behind in
#             the operator's loop), whichever node it is;
#           - neither synchronised although `system ntp` is configured and its
#             servers answer this host;
#           - both synchronised but further apart than the bound.
#
# History. #11872 added `failover_resync_node_clocks` (`date -u -s` on both
# nodes from one host reading) because the loss lab had no NTP: a crash reboot
# came back 2m18s behind and broke fabric auth and every failback. Since #18589
# chrony reaches NTP through vrf-mgmt, and the resync only hid the skew that
# broke the operator's RG-move loop (docs/ha-rg-move-correctness.md, matrix row
# H11). It survives solely as the explicit XPF_FAILOVER_CLOCK_RESYNC=1 escape
# for a lab with no NTP. The escape prints a banner and records `resync=1` on
# its CLOCK_PRECONDITION line; harness-result.sh then records the row VOID
# (not evidence) when it would have passed, so a resynced run can never stand
# as an operator-faithful one.
#
# Knobs (read at call time):
#   XPF_FAILOVER_CLOCK_SKEW_BOUND_S  5    |skew| + error must be at most this
#   XPF_FAILOVER_CLOCK_BUDGET_S      120  seconds to wait for convergence
#   XPF_FAILOVER_CLOCK_POLL_S        2    seconds between readings
#   XPF_FAILOVER_CLOCK_SAMPLES       3    incus-exec date samples per node per
#                                         reading; the minimum-RTT one is used
#   XPF_FAILOVER_CLOCK_MAX_UNC_S     1    a reading whose own error bound is
#                                         over this is "too noisy" and never
#                                         counts as converged
#   XPF_FAILOVER_CLOCK_RESYNC        0    1 = the no-NTP escape (sets clocks)
#
# Why these numbers (#18614 evidence, docs/ha-rg-move-correctness.md):
#   - Bound 5 s: the #18585 peer-skew alarm's CLEAR threshold
#     (PeerClockSkewClear, pkg/cluster/peer_clock_skew_18585.go), so a
#     converged gate never runs while that alarm is raised. Every wall-clock
#     comparison in pkg/cluster and pkg/grpcapi tolerates it; fabric tokens
#     authenticate under 30 s in any window alignment.
#   - It must not trip on a converged cluster. On loss with both nodes Normal,
#     this method read up to 0.23 s with the heartbeat at 0.0 s (RTT
#     0.18-0.21 s). On the #18614 live runs, six crash reboots converged at
#     -1.07, +0.07, +0.49, +0.04, -1.11 and -1.49 s; the three near -1 s were
#     read within seconds of fw0 turning Normal.
#   - The bound is applied to |skew| PLUS the reading's own error bound (half
#     the two nodes' sample RTTs, about 0.2 s on loss), so a skew the method
#     cannot resolve from the bound never passes; a reading whose error bound
#     alone is over XPF_FAILOVER_CLOCK_MAX_UNC_S is "too noisy" (VOID).
#   - A synchronised Leap status on both nodes (`Normal`, or `Insert second`
#     / `Delete second` around a leap second) is what shows that chrony
#     synchronised. The bound catches a node that reports synchronised while
#     still seconds off: slewing outside the `makestep 1 3` window, or its
#     servers disagreeing.
#   - Budget 120 s: on four force-stop reboots of fw0 (0.0.26315) chrony
#     reached Normal 17.2-18.1 s after xpfd reported active, which was 19-20 s
#     after `incus start`. 120 s is over 6x that, and still covers one full
#     64 s default poll interval if the first iburst round runs before
#     vrf-mgmt can route.
#   - Overrun: the budget is checked after each reading and the last sleep is
#     cut to the time left, so a verdict lands at most one reading past the
#     budget (about 1.5-2 s on loss: 3 samples per node plus two chronyc).
#   - Every node command runs under a host-side `timeout`, so a wedged incus
#     exec costs at most 10-15 s per command instead of hanging the smoke.

# failover_clock_baseline <node0> <node1>
#   One reading BEFORE the first crash, logged and recorded as CONTEXT for any
#   later verdict's reason, never as a decision: a single instant can catch a
#   chrony blip, and a one-node-synchronised baseline is the #18584 state the
#   gate exists to catch, not a lab excuse. Also logs the `system ntp` config.
failover_clock_baseline() {
	if (($# != 2)); then
		echo "failover_clock_baseline: usage: failover_clock_baseline <node0> <node1>" >&2
		return 1
	fi
	_failover_clock_knobs_lenient
	_failover_clock_measure "$1" "$2" "$_FC_SAMPLES"
	_FC_BASE_TEXT="$(_failover_clock_state_text "$1" "$2")"
	_failover_clock_ntp_config "$1" "$2"
	echo "clock baseline (before the first crash; $(_failover_clock_uptimes "$1" "$2")): ${_FC_BASE_TEXT}; $(_failover_clock_ntp_text)"
	return 0
}

# failover_clock_reading <label> <node0> <node1>
#   One measure-only reading, logged and never judged: no wait, no cell, no
#   clock touched. A harness takes it right after a crash-rebooted node is
#   back, so a later FAIL (a rejoin, say) has the post-crash clock state in
#   its log even if chrony converges before the precondition runs.
failover_clock_reading() {
	if (($# != 3)); then
		echo "failover_clock_reading: usage: failover_clock_reading <label> <node0> <node1>" >&2
		return 1
	fi
	_failover_clock_knobs_lenient
	_failover_clock_measure "$2" "$3" "$_FC_SAMPLES"
	echo "clock reading [${1}] ($(_failover_clock_uptimes "$2" "$3")): $(_failover_clock_state_text "$2" "$3")"
	return 0
}

# failover_clock_precondition <label> <node0> <node1> <rebooted-node>
#   The measured precondition. Samples both nodes until the skew is within the
#   bound and chrony is synchronised on both, or the budget runs out, then
#   scores PASS (0), FAIL (1) or VOID (2) as described at the top. Prints one
#   line per state change, a CLOCK_PRECONDITION marker (and a CLOCK_VOID line
#   on VOID) for harness-result.sh, and sets FAILOVER_CLOCK_DETAIL to the
#   one-line verdict. FAILOVER_CLOCK_RESYNCED=1 when the escape ran.
failover_clock_precondition() {
	FAILOVER_CLOCK_DETAIL=""
	FAILOVER_CLOCK_RESYNCED=0
	# No reading may leak from an earlier call into this one's lines.
	_FC_SKEW="" _FC_UNC="" _FC_DOWN="" _FC_LEAP0="" _FC_LEAP1="" _FC_REF0="" _FC_REF1=""
	_FC_NTP_STATE=unknown _FC_NTP_SERVERS="" _FC_OFFPATH=""
	if (($# != 4)); then
		FAILOVER_CLOCK_DETAIL="clock precondition: usage: failover_clock_precondition <label> <node0> <node1> <rebooted-node>"
		echo "$FAILOVER_CLOCK_DETAIL" >&2
		return 2
	fi
	local label="$1" n0="$2" n1="$3" rebooted="$4"
	local bound="${XPF_FAILOVER_CLOCK_SKEW_BOUND_S:-5}"
	local budget="${XPF_FAILOVER_CLOCK_BUDGET_S:-120}"
	local poll="${XPF_FAILOVER_CLOCK_POLL_S:-2}"
	local samples="${XPF_FAILOVER_CLOCK_SAMPLES:-3}"
	_FC_MAXUNC="${XPF_FAILOVER_CLOCK_MAX_UNC_S:-1}"
	local knob
	for knob in "$bound" "$budget" "$poll" "$_FC_MAXUNC"; do
		if ! [[ "$knob" =~ ^[0-9]+([.][0-9]+)?$ ]] || ! awk -v v="$knob" 'BEGIN { exit !(v > 0) }'; then
			_failover_clock_refuse "$label" "the skew bound, budget, poll interval and error cap must be positive numbers (got bound='${bound}' budget='${budget}' poll='${poll}' max_unc='${_FC_MAXUNC}')"
			return 2
		fi
	done
	if ! [[ "$samples" =~ ^[1-9][0-9]*$ ]]; then
		_failover_clock_refuse "$label" "XPF_FAILOVER_CLOCK_SAMPLES must be a positive integer (got '${samples}')"
		return 2
	fi
	if [[ "$rebooted" != "$n0" && "$rebooted" != "$n1" ]]; then
		_failover_clock_refuse "$label" "the rebooted node '${rebooted}' is neither ${n0} nor ${n1}"
		return 2
	fi
	case "${XPF_FAILOVER_CLOCK_RESYNC:-0}" in
	0) ;;
	1)
		_failover_clock_escape "$label" "$n0" "$n1" "$samples" "$bound" "$budget"
		return
		;;
	*)
		_failover_clock_refuse "$label" "XPF_FAILOVER_CLOCK_RESYNC must be 0 or 1 (got '${XPF_FAILOVER_CLOCK_RESYNC}')"
		return 2
		;;
	esac
	_failover_clock_wait "$label" "$n0" "$n1" "$rebooted" "$samples" "$bound" "$budget" "$poll"
}

# failover_clock_cell <pass-fail|fail-only> <label> <node0> <node1> <rebooted>
#   Runs the precondition and records its verdict as the CALLER's cell, with
#   the caller's pass/fail (and void, when it defines one; otherwise an
#   "  VOID  ..." line, which harness-result.sh reads from the marker).
#   fail-only keeps a converged run's cell count unchanged, but a resynced run
#   still gets an explicit PASS line naming the resync. Returns the verdict.
failover_clock_cell() {
	local mode="$1" rc
	shift
	failover_clock_precondition "$@"
	rc=$?
	case "$rc" in
	0)
		if [[ "$mode" == pass-fail || "$FAILOVER_CLOCK_RESYNCED" == 1 ]]; then
			pass "$FAILOVER_CLOCK_DETAIL"
		fi
		;;
	1) fail "$FAILOVER_CLOCK_DETAIL" ;;
	*)
		if declare -F void >/dev/null; then
			void "$FAILOVER_CLOCK_DETAIL"
		else
			echo "  VOID  $FAILOVER_CLOCK_DETAIL"
		fi
		;;
	esac
	return "$rc"
}

# _failover_clock_wait <label> <n0> <n1> <rebooted> <samples> <bound> <budget> <poll>
#   The measured path. It reads clocks and chrony state, and nothing else.
_failover_clock_wait() {
	local label="$1" n0="$2" n1="$3" rebooted="$4" samples="$5" bound="$6" budget="$7" poll="$8"
	local start now elapsed state="" prev="" first=1 peer="$n1"
	[[ "$rebooted" == "$n1" ]] && peer="$n0"
	# The config is read from the un-rebooted peer first; it is a fact the
	# build under test cannot change.
	_failover_clock_ntp_config "$peer" "$rebooted"
	start=$(date +%s.%N)
	while :; do
		_failover_clock_measure "$n0" "$n1" "$samples"
		now=$(date +%s.%N)
		elapsed=$(awk -v a="$start" -v b="$now" 'BEGIN { printf "%.1f", b - a }')
		if _failover_clock_converged "$bound"; then
			echo "clock precondition [${label}]: converged ${elapsed} s after the check began ($(_failover_clock_uptimes "$n0" "$n1")): $(_failover_clock_state_text "$n0" "$n1") (bound ${bound} s)"
			_failover_clock_marker "$label" 0 1 PASS "$elapsed" "$bound" "$budget"
			FAILOVER_CLOCK_DETAIL="${label}: clock precondition: NTP converged in ${elapsed} s (node1-node0 skew ${_FC_SKEW} s +/-${_FC_UNC} s, bound ${bound} s; chrony synchronised on both: ${_FC_LEAP0} / ${_FC_LEAP1})"
			return 0
		fi
		# Neither node synchronised and nothing configured to synchronise
		# them: waiting cannot help, so do not spend the budget.
		if { [[ "$_FC_NTP_STATE" == absent ]] &&
			! _failover_clock_synced "$_FC_LEAP0" && ! _failover_clock_synced "$_FC_LEAP1"; } ||
			awk -v e="$elapsed" -v b="$budget" 'BEGIN { exit !(e >= b) }'; then
			_failover_clock_verdict "$label" "$n0" "$n1" "$rebooted" "$bound" "$budget" "$elapsed"
			return
		fi
		# One line for the first reading (the post-crash state) and one per
		# change, so a long wait does not flood the log.
		state="${_FC_LEAP0}|${_FC_LEAP1}|$(_failover_clock_within "$bound" && echo in || echo out)"
		if ((first)) || [[ "$state" != "$prev" ]]; then
			echo "clock precondition [${label}]: ${elapsed} s: waiting: $(_failover_clock_state_text "$n0" "$n1") (bound ${bound} s, budget ${budget} s)"
		fi
		first=0
		prev="$state"
		# Never sleep past the budget: the last reading lands on it, not up
		# to a whole poll interval beyond it.
		sleep "$(awk -v p="$poll" -v b="$budget" -v e="$elapsed" 'BEGIN { r = b - e; printf "%.1f", (r < p ? r : p) }')"
	done
}

# _failover_clock_verdict <label> <n0> <n1> <rebooted> <bound> <budget> <elapsed>
#   Not converged: scored from the CURRENT reading (see the top of the file).
_failover_clock_verdict() {
	local label="$1" n0="$2" n1="$3" rebooted="$4" bound="$5" budget="$6" elapsed="$7"
	local peer peer_leap reb_leap why="" state ctx what
	if [[ "$rebooted" == "$n0" ]]; then
		peer="$n1" peer_leap="$_FC_LEAP1" reb_leap="$_FC_LEAP0"
	else
		peer="$n0" peer_leap="$_FC_LEAP0" reb_leap="$_FC_LEAP1"
	fi
	state="$(_failover_clock_state_text "$n0" "$n1"); $(_failover_clock_ntp_text)"
	ctx="${_FC_BASE_TEXT:+ (before the first crash: ${_FC_BASE_TEXT})}"
	echo "clock precondition [${label}]: NOT converged after ${elapsed} s (budget ${budget} s; $(_failover_clock_uptimes "$n0" "$n1")): ${state}"
	if [[ -z "$_FC_SKEW" ]]; then
		why="no measurement (harness/lab): clock unreadable on ${_FC_DOWN}"
	elif _failover_clock_noisy; then
		why="no measurement (harness/lab): the reading's error +/-${_FC_UNC} s is over the ${_FC_MAXUNC} s cap"
	elif ! _failover_clock_synced "$peer_leap" && ! _failover_clock_synced "$reb_leap"; then
		case "$_FC_NTP_STATE" in
		absent) why="no time source (lab): no \`system ntp\` is configured and neither node is synchronised" ;;
		present)
			local -a srvs
			read -r -a srvs <<<"$_FC_NTP_SERVERS"
			_failover_clock_offpath "${srvs[@]}"
			[[ "$_FC_OFFPATH" == none ]] &&
				why="lab NTP outage: neither node is synchronised and no configured server (${_FC_NTP_SERVERS}) answers this host either"
			;;
		*) why="no measurement (harness): \`show configuration system ntp\` could not be read and neither node is synchronised" ;;
		esac
	fi
	if [[ -n "$why" ]]; then
		_failover_clock_marker "$label" 0 0 VOID "-" "$bound" "$budget"
		FAILOVER_CLOCK_DETAIL="${label}: clock precondition VOID: ${why}; after ${elapsed} s: ${state}${ctx}. No clock was set"
		echo "CLOCK_VOID: ${FAILOVER_CLOCK_DETAIL}"
		return 2
	fi
	if ! _failover_clock_synced "$peer_leap" && ! _failover_clock_synced "$reb_leap"; then
		case "$_FC_OFFPATH" in
		unavailable) what="the off-path SNTP probe from this host was unavailable" ;;
		*) what="its servers answer this host (${_FC_OFFPATH#answered: })" ;;
		esac
		what="neither node is synchronised although \`system ntp\` is configured (${_FC_NTP_SERVERS}) and ${what}"
	elif ! _failover_clock_synced "$reb_leap"; then
		what="#18584 class: the rebooted ${rebooted} is not synchronised (${reb_leap}) while the peer ${peer} is -- one node reaching NTP and not the other"
	elif ! _failover_clock_synced "$peer_leap"; then
		what="#18584 class: the un-rebooted peer ${peer} is not synchronised (${peer_leap}) while the rebooted ${rebooted} is -- one node reaching NTP and not the other"
	else
		what="both nodes are synchronised but further apart than |skew| + error <= ${bound} s"
	fi
	_failover_clock_marker "$label" 0 0 FAIL "-" "$bound" "$budget"
	FAILOVER_CLOCK_DETAIL="${label}: clock precondition: NTP did not converge after a crash reboot within ${budget} s: ${what} (lab, NTP or product: xpfd owns chrony's vrf-mgmt binding and restart): ${state}${ctx}; needs |skew| + error <= ${bound} s and a synchronised Leap status (Normal, Insert second or Delete second) on both nodes. No clock was set (XPF_FAILOVER_CLOCK_RESYNC=1 is the no-NTP escape)"
	return 1
}

# _failover_clock_ntp_config <node>... -- `show configuration system ntp` from
# the first node whose CLI answers: _FC_NTP_STATE present (with
# _FC_NTP_SERVERS), absent, or unknown when no node's CLI answered.
_failover_clock_ntp_config() {
	local n out
	_FC_NTP_STATE=unknown _FC_NTP_SERVERS=""
	for n in "$@"; do
		out=$(timeout 20 incus exec "$n" -- cli -c 'show configuration system ntp' 2>&1) || continue
		_FC_NTP_SERVERS=$(sed -nE 's/^[[:space:]]*server[[:space:]]+([^[:space:]{;]+).*/\1/p' <<<"$out" | tr '\n' ' ')
		_FC_NTP_SERVERS="${_FC_NTP_SERVERS% }"
		if [[ -n "$_FC_NTP_SERVERS" ]]; then
			_FC_NTP_STATE=present
			return 0
		fi
		if grep -qE 'configuration path not found|^[[:space:]]*ntp[[:space:]]*\{' <<<"$out"; then
			_FC_NTP_STATE=absent
			return 0
		fi
	done
	return 0
}

_failover_clock_ntp_text() {
	case "${_FC_NTP_STATE:-unknown}" in
	present) printf 'system ntp: %s' "$_FC_NTP_SERVERS" ;;
	absent) printf 'system ntp: not configured' ;;
	*) printf 'system ntp: unreadable' ;;
	esac
}

# The off-path control: an SNTP query from THIS host to each server, with the
# product out of the path. Prints the servers that answered in sync.
_FC_SNTP_PY='import socket, sys
ok = []
for srv in sys.argv[1:]:
    try:
        s = socket.socket(socket.AF_INET6 if ":" in srv else socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(b"\x1b" + 47 * b"\0", (srv, 123))
        d, _ = s.recvfrom(512)
        if len(d) >= 48 and (d[0] & 7) == 4 and d[1] != 0:
            ok.append(srv)
    except Exception:
        pass
print(" ".join(ok))'

# _failover_clock_offpath <server>... -- _FC_OFFPATH = "answered: <servers>",
# "none", or "unavailable" (no python3, or the probe did not finish).
_failover_clock_offpath() {
	local out
	if (($# == 0)) || ! out=$(timeout 20 python3 -I -c "$_FC_SNTP_PY" "$@" 2>/dev/null); then
		_FC_OFFPATH=unavailable
		return 0
	fi
	if [[ -n "${out// /}" ]]; then
		_FC_OFFPATH="answered: ${out}"
	else
		_FC_OFFPATH=none
	fi
}

# _failover_clock_escape <label> <n0> <n1> <samples> <bound> <budget>
#   XPF_FAILOVER_CLOCK_RESYNC=1. Measures and logs the state first, so the run
#   still shows what the operator would have seen, then sets both clocks.
_failover_clock_escape() {
	local label="$1" n0="$2" n1="$3" samples="$4" bound="$5" budget="$6" rc
	FAILOVER_CLOCK_RESYNCED=1
	_failover_clock_measure "$n0" "$n1" "$samples"
	echo "clock precondition [${label}]: before resync: $(_failover_clock_state_text "$n0" "$n1")"
	cat <<'BANNER'
##############################################################################
##  XPF_FAILOVER_CLOCK_RESYNC=1: SETTING BOTH NODE CLOCKS FROM THE HOST     ##
##  (date -u -s). THIS RUN IS NOT OPERATOR-FAITHFUL: it repairs the clock   ##
##  state a crash-rebooted cluster really lives in, so a skew that breaks   ##
##  fabric auth or failback cannot show up here (#18614). The ledger row    ##
##  records clock_resync=1 and a would-be PASS is recorded VOID: it is not  ##
##  H1-H3 evidence. Use only on a lab with no NTP.                          ##
##############################################################################
BANNER
	failover_resync_node_clocks "$n0" "$n1"
	rc=$?
	if ((rc == 0)); then
		_failover_clock_marker "$label" 1 - PASS "-" "$bound" "$budget"
		FAILOVER_CLOCK_DETAIL="${label}: clocks RESYNCED from host UTC by XPF_FAILOVER_CLOCK_RESYNC=1 (NOT operator-faithful, not H1-H3 evidence; skew before resync ${_FC_SKEW:-unreadable} s)"
	else
		_failover_clock_marker "$label" 1 - FAIL "-" "$bound" "$budget"
		FAILOVER_CLOCK_DETAIL="${label}: XPF_FAILOVER_CLOCK_RESYNC=1 could not resync both firewall clocks from host UTC (skew before resync ${_FC_SKEW:-unreadable} s)"
	fi
	return "$rc"
}

# _failover_clock_refuse <label> <reason> — a misconfigured call (VOID). No
# clock is read or set.
_failover_clock_refuse() {
	FAILOVER_CLOCK_DETAIL="${1}: clock precondition VOID: refused (harness): ${2}; no clock was touched"
	echo "clock precondition [${1}]: REFUSED: ${2}"
	_failover_clock_marker "$1" 0 0 VOID "-" "-" "-"
	echo "CLOCK_VOID: ${FAILOVER_CLOCK_DETAIL}"
}

# _failover_clock_marker <label> <resync> <converged> <verdict> <converge_s> <bound> <budget>
#   The machine-readable line harness-result.sh reads (clock_resync,
#   clock_converged, clock_void). The label goes last because it may contain
#   spaces.
_failover_clock_marker() {
	printf 'CLOCK_PRECONDITION: resync=%s converged=%s verdict=%s skew_s=%s converge_s=%s bound_s=%s budget_s=%s label=%s\n' \
		"$2" "$3" "$4" "${_FC_SKEW:--}" "$5" "$6" "$7" "$1"
}

# _failover_clock_knobs_lenient -- the sample count and error cap for the
# measure-only calls, falling back to the defaults on a bad value (they judge
# nothing, so there is nothing to refuse).
_failover_clock_knobs_lenient() {
	_FC_SAMPLES="${XPF_FAILOVER_CLOCK_SAMPLES:-3}"
	[[ "$_FC_SAMPLES" =~ ^[1-9][0-9]*$ ]] || _FC_SAMPLES=3
	_FC_MAXUNC="${XPF_FAILOVER_CLOCK_MAX_UNC_S:-1}"
	[[ "$_FC_MAXUNC" =~ ^[0-9]+([.][0-9]+)?$ ]] || _FC_MAXUNC=1
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
#   rg_move_soak.py measure_offset). The midpoint cancels a symmetric exec
#   latency; the minimum-RTT sample is the one whose asymmetry can be largest
#   only by the least. The host clock cancels out of the node1-node0
#   difference. Prints "<offset_s> <rtt_s>" (positive = node ahead); returns 1
#   when no reading succeeded.
_failover_clock_offset() {
	local node="$1" samples="$2" i a r b best=""
	for ((i = 0; i < samples; i++)); do
		a=$(date +%s.%N)
		r=$(timeout 10 incus exec "$node" -- date +%s.%N 2>/dev/null) || continue
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
	if ! out=$(timeout 15 incus exec "$1" -- timeout 10 chronyc -n tracking 2>/dev/null); then
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
		up=$(timeout 10 incus exec "$n" -- cat /proc/uptime 2>/dev/null) || up=""
		up="${up%% *}"
		[[ "$up" =~ ^[0-9]+([.][0-9]+)?$ ]] && up="${up%%.*} s" || up="unreadable"
		out="${out:+$out, }${n} ${up}"
	done
	printf 'up %s' "$out"
}

# _failover_clock_within <bound> -- the reading is readable, not too noisy,
# and its skew is inside the bound even at the far edge of its own error.
_failover_clock_within() {
	[[ -n "$_FC_SKEW" ]] && ! _failover_clock_noisy &&
		awk -v s="$_FC_SKEW" -v u="$_FC_UNC" -v b="$1" 'BEGIN { if (s < 0) s = -s; exit !(s + u <= b) }'
}

# _failover_clock_noisy -- the reading's own error bound is over the cap.
_failover_clock_noisy() {
	[[ -n "$_FC_UNC" ]] && awk -v u="$_FC_UNC" -v c="${_FC_MAXUNC:-1}" 'BEGIN { exit !(u > c) }'
}

# _failover_clock_synced <leap status> -- chrony is synchronised. Around a
# leap second a synchronised chrony reports Insert/Delete second, not Normal.
_failover_clock_synced() {
	case "$1" in
	Normal | "Insert second" | "Delete second") return 0 ;;
	*) return 1 ;;
	esac
}

_failover_clock_converged() {
	_failover_clock_within "$1" && _failover_clock_synced "$_FC_LEAP0" && _failover_clock_synced "$_FC_LEAP1"
}

_failover_clock_state_text() {
	local skew
	if [[ -n "$_FC_SKEW" ]]; then
		skew="node1-node0 skew ${_FC_SKEW} s (+/-${_FC_UNC} s)"
		_failover_clock_noisy &&
			skew="${skew}, measurement too noisy (error over the ${_FC_MAXUNC:-1} s cap)"
	else
		skew="node1-node0 skew unknown (clock unreadable on ${_FC_DOWN})"
	fi
	printf '%s; chrony %s: %s [%s], %s: %s [%s]' "$skew" \
		"$1" "$_FC_LEAP0" "$_FC_REF0" "$2" "$_FC_LEAP1" "$_FC_REF1"
}

# failover_resync_node_clocks <node>...
#   THE ESCAPE ONLY (#11872): set every named node's wall clock from a SINGLE
#   host reading, so the nodes agree by construction. Nothing but
#   _failover_clock_escape may call this: the escape is what makes the banner
#   and the ledger mark unavoidable (failover-clock-selftest.sh's census
#   enforces it in every scanned file).
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
