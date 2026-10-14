#!/usr/bin/env bash
#
# v6-na-recovery-lib-12495.sh — #12495's ANALYSIS layer.
#
# WHY THIS EXISTS. The issue's acceptance is an ATTRIBUTION, not a plain
# pass/fail: "recorded lab run showing IPv6 neighbor recovery attributable to
# the becomeMaster NA burst (vs RA SLLA)". On the loss cluster two different
# v6 mechanisms repair a neighbor entry after an RG failover:
#
#   - the becomeMaster unsolicited-NA burst (pkg/vrrp instance_garp.go), one
#     NA per v6 VIP (Router+Override, target link-layer = new vMAC), and
#   - the daemon RA stream (pkg/daemon daemon_ra.go) whose SLLA option
#     refreshes the host's entry for the RA's source — the stable RETH
#     link-local that is ALSO the v6 default gateway (#6934 measured the RA
#     arriving 0.58 s after the failover command, then 10-30 s refreshes).
#
# A transit probe alone therefore cannot attribute anything: it goes green
# when either mechanism worked. The discriminator is WHICH ENTRY MOVED:
# an RA's SLLA can only rewrite the neighbor entry for the RA's own source
# address (the router link-local, RFC 4861 §6.3.4/§7.2.3); a GLOBAL VIP's
# neighbor entry is writable only by an override NA (or the host's own
# re-resolution, which the wire timeline rules in or out). So:
#
#   PRIMARY ORACLE   global VIP entry flips to a lladdr != baseline, with an
#                    override NA for that VIP observed at-or-before the flip
#                    => recovery attributable to the burst.
#   WITNESS          the v4 GARP burst launched by the SAME becomeMaster.
#                    #6934 measured 96/96 GARP+NA on the wire together; a
#                    capture that shows GARP but no NA proves the instrument
#                    was live and the transition happened while the NA is
#                    genuinely absent — the #12201 mutant-A shape. A capture
#                    with NEITHER is a blind instrument: VOID, never pass,
#                    never fail (the screen-probe #8336 witness discipline).
#
# THE VERDICT IS THREE-VALUED (PASS / FAIL / VOID) and TOTAL: every input
# class renders exactly one verdict line, including missing files, unprimed
# baselines, and unparsed frames. Unparsed frames arrive as PARSEERR lines
# from v6-na-parse-12495.py and are treated as a broken instrument (VOID),
# because "frame I could not read" and "frame that was not sent" must never
# render as the same zero.
#
# INPUT FORMATS (one event per line, whitespace-separated):
#   <ms> NA <src-ip6> <target-ip6> <tlla-mac|-> <flags>     flags e.g. RO
#   <ms> RA <src-ip6> <slla-mac|-> <lifetime-sec>
#   <ms> ARP <sender-ipv4> <sender-mac> <opcode>
#   <ms> PARSEERR <reason...>
#   <ms> NEIGH <addr> <lladdr|none> <state>                 (neigh timeline)
#
# All functions are pure: no I/O beyond reading the files they are handed,
# no cluster, no network. Hermetically tested by
# v6-na-recovery-12495-selftest.sh (make test-v6-na-recovery-lib).

# v6na_mac_norm <mac> — lowercase canonical form; empty for '-'/'none'.
v6na_mac_norm() {
	local m="${1:-}"
	case "$m" in
	- | none | "" | FAILED) printf '' ;;
	*) printf '%s\n' "$m" | tr 'A-F' 'a-f' ;;
	esac
}

# v6na_first_matching <events-file> <t0-ms> <window-ms> <awk-pattern>
#   Print the FIRST event line whose timestamp is within [t0, t0+window] and
#   whose fields (from the event verb on) match the awk pattern, or nothing.
v6na_first_matching() {
	local file="${1:-}" t0="${2:-0}" window="${3:-0}" pat="${4:-}"
	[[ -n "$file" && -f "$file" ]] || return 0
	awk -v t0="$t0" -v win="$window" -v pat="$pat" '
		$1 ~ /^[0-9]+$/ && $1 >= t0 && $1 <= t0 + win {
			line = $2
			for (i = 3; i <= NF; i++) line = line " " $i
			if (line ~ pat) { print; exit }
		}
	' "$file"
}

# v6na_count_matching <events-file> <t0-ms> <window-ms> <awk-pattern>
v6na_count_matching() {
	local file="${1:-}" t0="${2:-0}" window="${3:-0}" pat="${4:-}"
	[[ -n "$file" && -f "$file" ]] || { printf '0\n'; return 0; }
	awk -v t0="$t0" -v win="$window" -v pat="$pat" '
		$1 ~ /^[0-9]+$/ && $1 >= t0 && $1 <= t0 + win {
			line = $2
			for (i = 3; i <= NF; i++) line = line " " $i
			if (line ~ pat) n++
		}
		END { print n + 0 }
	' "$file"
}

# v6na_first_flip <neigh-file> <addr> <baseline-mac> <t0-ms>
#   Print "<ms> <newmac>" for the first post-t0 sample of <addr> whose
#   lladdr differs from the baseline (and is a real MAC), or nothing. An
#   entry that goes FAILED/none and comes back with the SAME MAC is not a
#   flip — re-learning the identical binding is not recovery evidence.
v6na_first_flip() {
	local file="${1:-}" addr="${2:-}" base t0="${4:-0}"
	base="$(v6na_mac_norm "${3:-}")"
	[[ -n "$file" && -f "$file" && -n "$addr" ]] || return 0
	awk -v addr="$addr" -v base="$base" -v t0="$t0" '
		$1 ~ /^[0-9]+$/ && $1 >= t0 && $2 == "NEIGH" && $3 == addr {
			ll = tolower($4)
			if (ll == "-" || ll == "none" || ll == "failed") next
			if (ll != base) { print $1, ll; exit }
		}
	' "$file"
}

# v6na_first_good_na_ms <events-file> <t0-ms> <window-ms> <target-ip6> <base-mac>
#   Print the timestamp of the first attribution-grade NA for <target-ip6>:
#   Override flag set ($6), and a TLLA ($5) that differs from the baseline
#   binding. Fields: $1 ms, $2 verb, $3 src, $4 target, $5 tlla, $6 flags.
v6na_first_good_na_ms() {
	local file="${1:-}" t0="${2:-0}" window="${3:-0}" target="${4:-}" base
	base="$(v6na_mac_norm "${5:-}")"
	[[ -n "$file" && -f "$file" && -n "$target" ]] || return 0
	awk -v t0="$t0" -v win="$window" -v vip="$target" -v base="$base" '
		$1 ~ /^[0-9]+$/ && $1 >= t0 && $1 <= t0 + win && $2 == "NA" && $4 == vip {
			if ($6 !~ /O/) next          # no Override: cannot rewrite a cache entry (#6934)
			ll = tolower($5)
			if (ll == "-" || ll == "none" || ll == base) next
			print $1; exit
		}
	' "$file"
}

# v6na_verdict <t0-ms> <window-ms> <vip> <gw-lla> <base-vip-mac> <base-gw-mac>
#              <events-file> <neigh-file> <transit-recv> <transit-count>
#              <transit-min>
#   Print the four cells and the final V6NA-VERDICT line. Arguments are
#   defaulted, not required: a short argument list renders VOID, never a
#   shell abort that emits a guess (screen-probe-lib discipline).
v6na_verdict() {
	local t0="${1:-}" window="${2:-}" vip="${3:-}" gw="${4:-}"
	local base_vip base_gw
	base_vip="$(v6na_mac_norm "${5:-}")"
	base_gw="$(v6na_mac_norm "${6:-}")"
	local events="${7:-}" neigh="${8:-}"
	local recv="${9:-}" count="${10:-}" min="${11:-3}"

	# TOTALITY, first gate: a missing or non-numeric timeline origin makes
	# every window comparison meaningless. Refuse to compare against
	# garbage rather than letting awk's string coercions render a verdict
	# from an undefined window (empty t0 compares ">= """ lexically true in
	# awk, which would admit pre-failover frames as evidence).
	if [[ ! "$t0" =~ ^[0-9]+$ || ! "$window" =~ ^[0-9]+$ ]]; then
		echo "INSTRUMENT: MALFORMED-WINDOW"
		echo "GW-ENTRY: NO-BASELINE (${gw:-none})"
		echo "TRANSIT: NOT-MEASURED (${recv:-?}/${count:-?}, min ${min})"
		echo "VIP-ENTRY: VOID (${vip:-none})"
		echo "V6NA-VERDICT: VOID malformed t0/window (${t0:-<empty>}/${window:-<empty>}) — the decision layer refuses to compare against a missing timeline origin"
		return 0
	fi

	local instrument="VOID" vip_cell="VOID" gw_cell="NO-BASELINE" transit_cell="NOT-MEASURED"
	local verdict="VOID" why=""

	# ── Cell 1: the instrument. Decided in evidence order: a broken parser
	# outranks everything; then the subject NA (good frames > wrong frames >
	# absent frames); the GARP witness only distinguishes "absent" from
	# "instrument never saw anything".
	local parseerr arp_witness na_vip_any na_vip_good
	parseerr="$(v6na_count_matching "$events" 0 999999999999 'PARSEERR')"
	arp_witness="$(v6na_count_matching "$events" "$t0" "$window" '^ARP ')"
	na_vip_any="$(v6na_count_matching "$events" "$t0" "$window" "^NA [^ ]+ ${vip} ")"
	na_vip_good="$(awk -v t0="$t0" -v win="$window" -v vip="$vip" -v base="$base_vip" '
		$1 ~ /^[0-9]+$/ && $1 >= t0 && $1 <= t0 + win && $2 == "NA" && $4 == vip {
			if ($6 !~ /O/) next
			ll = tolower($5)
			if (ll == "-" || ll == "none" || ll == base) next
			n++
		}
		END { print n + 0 }
	' "$events" 2>/dev/null)"
	if (( parseerr > 0 )); then
		instrument="PARSEERR"
		why="broken instrument: the wire capture contains ${parseerr} unparseable frame(s); a frame that cannot be read is not a frame that was not sent"
	elif (( na_vip_good > 0 )); then
		instrument="LIVE-NA"
	elif (( na_vip_any > 0 )); then
		instrument="NA-NOT-ATTRIBUTABLE"
		why="NA frames for ${vip} were captured but none carried Override with a new target link-layer address"
	elif (( arp_witness > 0 )); then
		instrument="MISSING-NA"
	else
		instrument="BLIND"
	fi
	echo "INSTRUMENT: ${instrument}"

	# ── Cell 2: the global VIP neighbor entry (the discriminator) ───────
	local flip_line flip_ms na_ms
	flip_line="$(v6na_first_flip "$neigh" "$vip" "$base_vip" "$t0")"
	na_ms="$(v6na_first_good_na_ms "$events" "$t0" "$window" "$vip" "$base_vip")"
	if [[ -z "$base_vip" ]]; then
		vip_cell="UNPRIMED"
		why="${why:+$why; }no baseline neighbor entry for ${vip}: nothing to attribute recovery of"
	elif [[ -n "$flip_line" ]]; then
		flip_ms="${flip_line%% *}"
		if [[ -n "$na_ms" && "$na_ms" -le "$flip_ms" ]]; then
			vip_cell="ATTRIBUTED-NA"
		else
			vip_cell="RECOVERED-UNATTRIBUTED"
			why="${why:+$why; }${vip} entry flipped with no override NA for it beforehand (host re-resolution?)"
		fi
	else
		vip_cell="STALE"
	fi

	# ── Cell 3: the gateway link-local entry (informational) ────────────
	# This entry is writable by BOTH mechanisms, so it can corroborate but
	# never decide; RA-ATTRIBUTED here does not veto a VIP PASS.
	local gw_flip gw_flip_ms gw_na_ms ra_ms
	gw_flip="$(v6na_first_flip "$neigh" "$gw" "$base_gw" "$t0")"
	if [[ -n "$gw" && -n "$base_gw" ]]; then
		if [[ -n "$gw_flip" ]]; then
			gw_flip_ms="${gw_flip%% *}"
			gw_na_ms="$(v6na_first_good_na_ms "$events" "$t0" "$window" "$gw" "$base_gw")"
			ra_ms="$(v6na_first_matching "$events" "$t0" "$window" '^RA ')"
			ra_ms="${ra_ms%% *}"
			if [[ -n "$gw_na_ms" && "$gw_na_ms" -le "$gw_flip_ms" ]]; then
				gw_cell="NA-ATTRIBUTED"
			elif [[ -n "$ra_ms" && "$ra_ms" -le "$gw_flip_ms" ]]; then
				gw_cell="RA-ATTRIBUTED"
			else
				gw_cell="FLIPPED-UNATTRIBUTED"
			fi
		else
			gw_cell="STALE"
		fi
	fi
	echo "GW-ENTRY: ${gw_cell} (${gw:-none})"

	# ── Cell 4: end-to-end v6 transit (the recovery oracle) ─────────────
	if [[ "$recv" == "" || "$count" == "" ]]; then
		transit_cell="NOT-MEASURED"
	elif [[ "$recv" =~ ^[0-9]+$ ]] && (( recv >= min )); then
		transit_cell="OK"
	else
		transit_cell="BLACKHOLED"
	fi
	echo "TRANSIT: ${transit_cell} (${recv:-?}/${count:-?} to the WAN-side v6 target, min ${min})"
	echo "VIP-ENTRY: ${vip_cell} (${vip:-none})"

	# ── The verdict, in dependency order ────────────────────────────────
	# FAIL outranks VOID (a measured defect is worse than a missing
	# measurement), and the instrument is decided before the subject.
	case "$instrument" in
	PARSEERR | NA-NOT-ATTRIBUTABLE | BLIND)
		verdict="VOID"
		[[ -n "$why" ]] || why="instrument state ${instrument}: the measurement did not decide"
		;;
	MISSING-NA)
		verdict="FAIL"
		why="the v4 GARP witness fired but no override NA for ${vip} reached the wire — the #12201 mutant-A shape (becomeMaster NA launch missing) survived the unit pins"
		;;
	LIVE-NA)
		case "$vip_cell" in
		ATTRIBUTED-NA)
			case "$transit_cell" in
			OK) verdict="PASS" ;;
			BLACKHOLED)
				verdict="FAIL"
				why="neighbor recovery is NA-attributed but v6 transit is blackholed — a separate (route/fabric-class) defect; capture ip -6 route/neigh per the #6934 table"
				;;
			NOT-MEASURED)
				verdict="VOID"
				why="entry attribution proven but transit was not measured"
				;;
			esac
			;;
		RECOVERED-UNATTRIBUTED | UNPRIMED)
			verdict="VOID"
			[[ -n "$why" ]] || why="VIP entry state ${vip_cell}: recovery not attributable to the NA burst"
			;;
		STALE)
			if [[ "$transit_cell" == "BLACKHOLED" ]]; then
				verdict="FAIL"
				why="override NA on the wire but the ${vip} neighbor entry never moved and transit is blackholed — receiver-side defect"
			else
				verdict="VOID"
				why="override NA on the wire but the ${vip} entry never flipped within the window"
			fi
			;;
		esac
		;;
	*)
		verdict="VOID"
		why="unrecognized instrument state ${instrument}"
		;;
	esac
	echo "V6NA-VERDICT: ${verdict} ${why}"
}

# v6na_exit_status <verdict-line>
#   0 PASS — neighbor recovery recorded AND attributable to the NA burst.
#   1 FAIL — a defect shape: missing burst, stale entry with blackhole, or
#            attributed recovery with transit still blackholed.
#   2 VOID — the measurement did not decide.
#   4 anything else: the decision layer itself is broken; fail closed.
v6na_exit_status() {
	local line="${1:-}"
	case "$line" in
	"V6NA-VERDICT: PASS"*) return 0 ;;
	"V6NA-VERDICT: FAIL"*) return 1 ;;
	"V6NA-VERDICT: VOID"*) return 2 ;;
	*) return 4 ;;
	esac
}
