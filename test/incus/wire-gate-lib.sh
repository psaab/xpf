#!/usr/bin/env bash
# shellcheck shell=bash
#
# Shared verdict core for the wire-deny gates: wire-policy-deny.sh and
# wire-appmatch-twins.sh (#9531), wire-zone-matrix.sh (#10028),
# wire-hostinbound-deny.sh (#10029), wire-conntrack-lifecycle.sh (#10030).
# Pure bash, no cluster, no incus, no network — every
#
# WHY THIS EXISTS
#
# The wire gates share one falsifiability shape: a counted probe burst
# that must NOT emerge peer-side, a counted near-miss control burst that MUST
# emerge in the same capture window, and floors below which no verdict may be
# PASS. If each script grew its own copy, a floor fix in one and not the other
# would be a silent divergence in what "conformant" means — the exact class of
# drift the §2 oracle exists to prevent. One total verdict function per gate,
# five callers, hermetic matrices on all.
#
# lekko vocabulary (mirrors the WIRE_GATE adapter contract in
# harness-result.sh `harness_adapt_wire_gate`):
#
#   offered   frames the sender reports transmitting for a leg
#   observed  frames the peer-side capture attributes to a leg
#   leaked    observed frames on a leg that must not emerge
#
# Closed VOID slugs only (design §8): env-void, row-timeout, no-prober,
# harness-void, capture-blind, under-sampled, uncalibrated, dut-void.

# The §2 floors. Drop legs (deny assertions): >= 1,000 offered frames.
# Loss legs (permit assertions): >= 10,000 offered frames across two sizes.
# Liveness legs (permit assertions at twins-grade): 1,500 offered so routine
# path loss cannot manufacture a miss, 1,000 observed to prove the window.
# Loss-grade (10k, 0%-loss) belongs to the wire_policy_permit row, out of
# lane — the demotion the #9531 reviewers sanctioned for the twins permit
# legs (plan §16: lab UDP loss makes 0%-loss claims unpassable).
WIRE_DROP_FLOOR=1000
WIRE_LOSS_FLOOR=10000
WIRE_LIVENESS_OFFERED=1500

# Closed VOID slug set (design §8). Membership is checked, never assumed.
wire_closed_slug() {
	case " env-void row-timeout no-prober harness-void capture-blind under-sampled uncalibrated dut-void " in
	*" $1 "*) return 0 ;;
	*) return 1 ;;
	esac
}

# wire_num <value> — exit 0 iff value is a non-negative integer literal.
wire_num() {
	case "${1:-}" in
	"" | *[!0-9]*) return 1 ;;
	*) return 0 ;;
	esac
}

# wire_deny_verdict <probe_offered> <probe_leaked> <control_offered> <control_observed> <cksum_bad>
#
# The single-leg deny verdict (wire_policy_deny). Prints exactly one
# `WIRE_GATE wire_policy_deny <verdict> reason=<slug> <metrics>` line and
# returns 0/1/2 for PASS/FAIL/VOID. TOTAL: every input combination prints.
#
# Order is load-bearing, not aesthetic:
#   1. under-sampled floors on OFFERED counts — a verdict about fewer
#      frames than §2 allows is VOID before any other question is asked;
#   2. leak — emerged probe frames are a positive observation of breakage
#      and survive a missing control (the capture evidently saw *something*);
#   3. capture-blind — no leak but no control either proves only that the
#      capture saw nothing, never that the policy held;
#   4. checksum — a rewrite with a broken checksum is FAIL (§2.4), not a pass
#      with loss;
#   5. PASS.
wire_deny_verdict() {
	local po="${1:-}" pl="${2:-}" co="${3:-}" cb="${4:-}" ck="${5:-}"
	local metrics="probe_offered=$po probe_leaked=$pl control_offered=$co control_observed=$cb cksum_bad=$ck"
	if ! wire_num "$po" || ! wire_num "$pl" || ! wire_num "$co" || ! wire_num "$cb" || ! wire_num "$ck"; then
		printf 'WIRE_GATE wire_policy_deny VOID reason=harness-void %s\n' "$metrics"
		return 2
	fi
	if ((10#$po < WIRE_DROP_FLOOR)) || ((10#$co < WIRE_DROP_FLOOR)); then
		printf 'WIRE_GATE wire_policy_deny VOID reason=under-sampled %s\n' "$metrics"
		return 2
	fi
	if ((10#$pl > 0)); then
		printf 'WIRE_GATE wire_policy_deny FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	if ((10#$cb < WIRE_DROP_FLOOR)); then
		printf 'WIRE_GATE wire_policy_deny VOID reason=capture-blind %s\n' "$metrics"
		return 2
	fi
	if ((10#$ck > 0)); then
		printf 'WIRE_GATE wire_policy_deny FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	printf 'WIRE_GATE wire_policy_deny PASS reason=-- %s\n' "$metrics"
	return 0
}
#
# The appmatch-twins verdict. LIVE-FINDING DEMOTION (see plan §16): the lab
# lan->wan path drops 0-13% of UDP bursts variably (measured same-day,
# DUT idle), so 0%-loss assertions over 10k frames cannot pass here. The
# permit twins are therefore LIVENESS-grade, not loss-grade: each must emerge
# at its observed floor so the deny absences read against a proven capture
# path, but no 0%-loss claim is made (that belongs to the wire_policy_permit
# row, out of lane — the demotion GLM r1 explicitly sanctioned). Deny legs
# keep full §2 drop-floor rigor: loss cannot hide a leak, and any emerged
# deny frame is FAIL.
#
# Order: numeric validity; offered floors per leg (deny 1000, permit 1500 —
# the 500-frame margin absorbs routine path loss so the OBSERVED floor, not
# luck, decides); deny leaks (positive observations, survive everything);
# checksums; permit-leg cross-check (an emerged twin proves the shared
# window, so a missing twin is a drop); both-missing (capture unproven).
wire_twins_verdict() {
	local t80o="${1:-}" t80b="${2:-}" t88o="${3:-}" t88b="${4:-}"
	local u53o="${5:-}" u53b="${6:-}" u35o="${7:-}" u35b="${8:-}" ck="${9:-}"
	local a
	for a in "$t80o" "$t80b" "$t88o" "$t88b" "$u53o" "$u53b" "$u35o" "$u35b" "$ck"; do
		if ! wire_num "$a"; then
			printf 'WIRE_GATE wire_appmatch_twins VOID reason=harness-void tcp80_offered=%s tcp80_observed=%s tcp8080_offered=%s tcp8080_observed=%s udp53_offered=%s udp53_observed=%s udp5353_offered=%s udp5353_observed=%s deny_leaked=0 permit_missing=0 cksum_bad=0\n' \
				"$t80o" "$t80b" "$t88o" "$t88b" "$u53o" "$u53b" "$u35o" "$u35b"
			return 2
		fi
	done
	local metrics="tcp80_offered=$t80o tcp80_observed=$t80b tcp8080_offered=$t88o tcp8080_observed=$t88b udp53_offered=$u53o udp53_observed=$u53b udp5353_offered=$u35o udp5353_observed=$u35b deny_leaked=$((10#$t88b + 10#$u35b)) permit_missing=$((10#$t80o > 10#$t80b ? 10#$t80o - 10#$t80b : 0)) cksum_bad=$ck"
	# NOTE: permit_missing floors each leg shortfall at zero (handshake/data
	# inflation on permit legs must not drive it negative); the UDP leg is
	# folded into the cross-check, not the aggregate.
	if ((10#$t88o < WIRE_DROP_FLOOR)) || ((10#$u35o < WIRE_DROP_FLOOR)) ||
		((10#$t80o < 1500)) || ((10#$u53o < 1500)); then
		printf 'WIRE_GATE wire_appmatch_twins VOID reason=under-sampled %s\n' "$metrics"
		return 2
	fi
	if ((10#$t88b > 0)) || ((10#$u35b > 0)); then
		printf 'WIRE_GATE wire_appmatch_twins FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	if ((10#$ck > 0)); then
		printf 'WIRE_GATE wire_appmatch_twins FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	# Permit-leg cross-check at the drop floor on OBSERVED counts. One twin
	# emerged while its sibling did not: the shared window/filter demonstrably
	# delivers, so the missing twin was dropped by policy (FAIL appmatch_drop
	# via the gate's FAIL line). Neither emerged: capture unproven (VOID).
	local t80ok=0 u53ok=0
	((10#$t80b >= WIRE_DROP_FLOOR)) && t80ok=1
	((10#$u53b >= WIRE_DROP_FLOOR)) && u53ok=1
	if ((t80ok == 0)) && ((u53ok == 0)); then
		printf 'WIRE_GATE wire_appmatch_twins VOID reason=capture-blind %s\n' "$metrics"
		return 2
	fi
	if ((t80ok == 0)) || ((u53ok == 0)); then
		printf 'WIRE_GATE wire_appmatch_twins FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	printf 'WIRE_GATE wire_appmatch_twins PASS reason=-- %s\n' "$metrics"
	return 0
}
# wire_parse_transcript <file>
#
# Hermetic input path shared by both gates' --fixture modes. The transcript is
# one line of space-separated k=v pairs (a pcap-summary reduction); prints
# `OK <assignments>` on success for eval, or a final-form VOID line on
# malformed input — malformed is VOID harness-void, never zero-frames-PASS.
wire_parse_transcript() {
	local file="${1:-}" raw tok k v
	if [[ ! -f "$file" ]]; then
		return 2
	fi
	raw=$(grep -vE '^[[:space:]]*(#|$)' "$file" | head -1)
	if [[ -z "$raw" ]]; then
		return 2
	fi
	for tok in $raw; do
		case "$tok" in
		[A-Za-z0-9_]*=*)
			k=${tok%%=*}
			v=${tok#*=}
			if ! wire_num "$v"; then
				return 2
			fi
			printf '%s=%s\n' "$k" "$v"
			;;
		*)
			return 2
			;;
		esac
	done
	return 0
}
# wire_matrix_verdict <cksum_bad> <cell_count> [<cell-key> <probe64-offered> <probe64-observed> <probe1400-offered> <probe1400-observed> <control64-offered> <control64-observed> <control1400-offered> <control1400-observed>]...
#
# The zone-matrix verdict (#10028) is deliberately not a generic N-cell
# reducer.  §3 names exactly six ordered pairs under BOTH default policies:
# trust↔untrust, trust↔dmz, and untrust↔dmz, in each direction.  The complete
# row is therefore exactly these twelve keys, once each:
#
#   deny:trust->untrust deny:untrust->trust deny:trust->dmz
#   deny:dmz->trust deny:untrust->dmz deny:dmz->untrust
#   permit:trust->untrust permit:untrust->trust permit:trust->dmz
#   permit:dmz->trust permit:untrust->dmz permit:dmz->untrust
#
# Every cell has one probe and one SAME-pair near-miss control under its
# capture window.  Deny probes and controls have the §2 drop floor (1,000);
# permit probes and controls are §2 loss-grade (10,000 frames at EACH of
# 64 B and 1400 B).  A loss-grade permit cell passes only with every offered
# frame observed at the peer-side capture; this is not the #9531 appmatch
# liveness demotion.  A missing near-miss control is capture-blind, never a
# deny PASS.  Metrics retain per-size counts and aggregate required metrics.
# Prints exactly one `WIRE_GATE wire_zone_matrix ...` line; rc 0/1/2.
wire_matrix_verdict() {
	local ck="${1:-}" n="${2:-}"
	local expected_keys=(
		deny:trust-\>untrust deny:untrust-\>trust deny:trust-\>dmz
		deny:dmz-\>trust deny:untrust-\>dmz deny:dmz-\>untrust
		permit:trust-\>untrust permit:untrust-\>trust permit:trust-\>dmz
		permit:dmz-\>trust permit:untrust-\>dmz permit:dmz-\>untrust
	)
	local zero="cells_measured=0 cells_failed=0 deny_cells=0 permit_cells=0 deny_leaked=0 permit_missing=0 control_missing=0 permit64_offered=0 permit64_observed=0 permit1400_offered=0 permit1400_observed=0 cksum_bad=0"
	if ! wire_num "$ck" || ! wire_num "$n"; then
		printf 'WIRE_GATE wire_zone_matrix VOID reason=harness-void %s\n' "$zero"
		return 2
	fi
	# The identity/completeness contract is part of this row, not a caller
	# convention.  A one-cell or duplicate-key fixture cannot certify §3.
	if ((10#$n != 12)) || (($# != 2 + 9 * 12)); then
		printf 'WIRE_GATE wire_zone_matrix VOID reason=harness-void %s\n' "$zero"
		return 2
	fi
	shift 2
	local -a all_records=("$@")
	local key p64o p64b p1400o p1400b c64o c64b c1400o c1400b
	local i j found
	declare -A seen
	for ((i = 0; i < 12; i++)); do
		key=$1; p64o=$2; p64b=$3; p1400o=$4; p1400b=$5
		c64o=$6; c64b=$7; c1400o=$8; c1400b=$9
		shift 9
		found=0
		for j in "${expected_keys[@]}"; do
			if [[ "$key" == "$j" ]]; then found=1; break; fi
		done
		if ((found == 0)) || [[ -n "${seen[$key]:-}" ]]; then
			printf 'WIRE_GATE wire_zone_matrix VOID reason=harness-void %s\n' "$zero"
			return 2
		fi
		seen["$key"]=1
		for j in "$p64o" "$p64b" "$p1400o" "$p1400b" "$c64o" "$c64b" "$c1400o" "$c1400b"; do
			if ! wire_num "$j"; then
				printf 'WIRE_GATE wire_zone_matrix VOID reason=harness-void %s\n' "$zero"
				return 2
			fi
		done
	done
	for key in "${expected_keys[@]}"; do
		if [[ -z "${seen[$key]:-}" ]]; then
			printf 'WIRE_GATE wire_zone_matrix VOID reason=harness-void %s\n' "$zero"
			return 2
		fi
	done
	local -a records=("${all_records[@]}")
	local failed=0 blind=0 short=0 leaked=0 missing=0 control_missing=0 duplicate=0
	local deny_cells=0 permit_cells=0 permit64o=0 permit64b=0 permit1400o=0 permit1400b=0
	local reason="--" is_permit
	# Re-read the records from the positional array so identity validation
	# above happens before any metric is scored.
	for ((i = 0; i < 12; i++)); do
		key=${records[$((i * 9))]}
		p64o=${records[$((i * 9 + 1))]}; p64b=${records[$((i * 9 + 2))]}
		p1400o=${records[$((i * 9 + 3))]}; p1400b=${records[$((i * 9 + 4))]}
		c64o=${records[$((i * 9 + 5))]}; c64b=${records[$((i * 9 + 6))]}
		c1400o=${records[$((i * 9 + 7))]}; c1400b=${records[$((i * 9 + 8))]}
		is_permit=0
		[[ "$key" == permit:* ]] && is_permit=1
		local floor=$WIRE_DROP_FLOOR
		((is_permit == 1)) && floor=$WIRE_LOSS_FLOOR
		if ((is_permit == 1)); then
			permit_cells=$((permit_cells + 1))
			permit64o=$((permit64o + 10#$p64o)); permit64b=$((permit64b + 10#$p64b))
			permit1400o=$((permit1400o + 10#$p1400o)); permit1400b=$((permit1400b + 10#$p1400b))
			if ((10#$p64o < floor || 10#$p1400o < floor ||
					10#$c64o < floor || 10#$c1400o < floor)); then
				short=$((short + 1)); [[ "$reason" == "--" ]] && reason=under-sampled
				continue
			fi
			# The capture must prove the control path before interpreting
			# a completely silent permit probe as a policy drop.  If every
			# leg is silent, this cell is capture-blind, not FAIL.
			if ((10#$p64b == 0 && 10#$p1400b == 0 &&
					10#$c64b == 0 && 10#$c1400b == 0)); then
				blind=$((blind + 1)); [[ "$reason" == "--" ]] && reason=capture-blind
				continue
			fi
			local over=0
			((10#$p64b > 10#$p64o)) && over=$((over + 10#$p64b - 10#$p64o))
			((10#$p1400b > 10#$p1400o)) && over=$((over + 10#$p1400b - 10#$p1400o))
			((10#$c64b > 10#$c64o)) && over=$((over + 10#$c64b - 10#$c64o))
			((10#$c1400b > 10#$c1400o)) && over=$((over + 10#$c1400b - 10#$c1400o))
			duplicate=$((duplicate + over))
			local d1=$((10#$p64o - 10#$p64b)); local d2=$((10#$p1400o - 10#$p1400b))
			local d3=$((10#$c64o - 10#$c64b)); local d4=$((10#$c1400o - 10#$c1400b))
			((d1 < 0)) && d1=0; ((d2 < 0)) && d2=0
			((d3 < 0)) && d3=0; ((d4 < 0)) && d4=0
			local cell_missing=$((d1 + d2))
			missing=$((missing + cell_missing))
			if ((over > 0)); then
				failed=$((failed + 1))
			# The same-pair near-miss control is mandatory.  A control
			# shortfall is a capture-blind VOID; a probe shortfall with a
			# proven control is a measured policy_drop FAIL.
			elif ((d3 > 0 || d4 > 0)); then
				control_missing=$((control_missing + d3 + d4))
				blind=$((blind + 1)); [[ "$reason" == "--" ]] && reason=capture-blind
			elif ((d1 > 0 || d2 > 0)); then
				failed=$((failed + 1))
			fi
		else
			deny_cells=$((deny_cells + 1))
			if ((10#$p64o < floor || 10#$c64o < floor ||
					10#$p1400o < floor || 10#$c1400o < floor)); then
				short=$((short + 1)); [[ "$reason" == "--" ]] && reason=under-sampled
				continue
			fi
			local cell_leaked=$((10#$p64b + 10#$p1400b))
			local cell_control_missing=0
			((10#$c64b < WIRE_DROP_FLOOR)) && cell_control_missing=$((cell_control_missing + WIRE_DROP_FLOOR - 10#$c64b))
			((10#$c1400b < WIRE_DROP_FLOOR)) && cell_control_missing=$((cell_control_missing + WIRE_DROP_FLOOR - 10#$c1400b))
			leaked=$((leaked + cell_leaked))
			control_missing=$((control_missing + cell_control_missing))
			if ((cell_leaked > 0)); then
				failed=$((failed + 1))
			elif ((cell_control_missing > 0)); then
				blind=$((blind + 1)); [[ "$reason" == "--" ]] && reason=capture-blind
			fi
		fi
	done
	local metrics="cells_measured=12 cells_failed=$failed deny_cells=$deny_cells permit_cells=$permit_cells deny_leaked=$leaked permit_missing=$missing control_missing=$control_missing duplicate_frames=$duplicate permit64_offered=$permit64o permit64_observed=$permit64b permit1400_offered=$permit1400o permit1400_observed=$permit1400b cksum_bad=$ck"
	if ((failed > 0)); then
		printf 'WIRE_GATE wire_zone_matrix FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	if ((short > 0 || blind > 0)); then
		printf 'WIRE_GATE wire_zone_matrix VOID reason=%s %s\n' "$reason" "$metrics"
		return 2
	fi
	if ((10#$ck > 0)); then
		printf 'WIRE_GATE wire_zone_matrix FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	printf 'WIRE_GATE wire_zone_matrix PASS reason=-- %s\n' "$metrics"
	return 0
}
#
# wire_hostinbound_verdict <reply_frames> <ctrl_offered> <ctrl_observed> <cksum_bad> <ncells> [<offered> <completed> <refused>]...
#
# The host-inbound deny verdict (#10029): N port-cells (one management port
# at one DUT address each) measured under ONE shared capture window on the
# prober, with a same-address permitted TCP netconf control proving the window.
# Per-cell inputs stay per-cell — no aggregate may conceal a thin cell (the
# twins §5a rule). EXPOSED = completed + refused: a completed handshake is
# proof of admission, and so is a RST — with listeners bound on every probed
# addr:port an admitted SYN completes, so a refusal means the SYN reached the
# host stack past host-inbound (or the apparatus lost its listener, which the
# gate's ownership check fails closed on independently).
# Prints exactly one `WIRE_GATE wire_hostinbound_deny ...` line; rc 0/1/2.
# Order: validity; per-cell offered floors (1000); exposed and reply-frame
# positives (FAIL, surviving everything); capture-blind; checksums; PASS.
wire_hostinbound_verdict() {
	local rf="${1:-}" coff="${2:-}" cobs="${3:-}" ck="${4:-}" n="${5:-}"
	local zero="cells_measured=0 syn_offered=0 handshake_completed=0 refused_total=0 exposed_total=0 reply_frames=0 ctrl_offered=0 ctrl_observed=0 cksum_bad=0"
	if ! wire_num "$rf" || ! wire_num "$coff" || ! wire_num "$cobs" || ! wire_num "$ck" || ! wire_num "$n"; then
		printf 'WIRE_GATE wire_hostinbound_deny VOID reason=harness-void %s\n' "$zero"
		return 2
	fi
	if ((10#$n < 1)) || (($# != 5 + 3 * 10#$n)); then
		printf 'WIRE_GATE wire_hostinbound_deny VOID reason=harness-void %s\n' "$zero"
		return 2
	fi
	shift 5
	local a
	for a in "$@"; do
		if ! wire_num "$a"; then
			printf 'WIRE_GATE wire_hostinbound_deny VOID reason=harness-void %s\n' "$zero"
			return 2
		fi
	done
	local i off comp ref short=0 offsum=0 compsum=0 refsum=0
	for ((i = 0; i < 10#$n; i++)); do
		off=$1; comp=$2; ref=$3
		shift 3
		offsum=$((offsum + 10#$off)); compsum=$((compsum + 10#$comp)); refsum=$((refsum + 10#$ref))
		if ((10#$off < WIRE_DROP_FLOOR)); then short=1; fi
	done
	local exposed=$((compsum + refsum))
	local metrics="cells_measured=$n syn_offered=$offsum handshake_completed=$compsum refused_total=$refsum exposed_total=$exposed reply_frames=$rf ctrl_offered=$coff ctrl_observed=$cobs cksum_bad=$ck"
	if ((short == 1)) || ((10#$coff < WIRE_DROP_FLOOR)); then
		printf 'WIRE_GATE wire_hostinbound_deny VOID reason=under-sampled %s\n' "$metrics"
		return 2
	fi
	if ((exposed > 0)) || ((10#$rf > 0)); then
		printf 'WIRE_GATE wire_hostinbound_deny FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	if ((10#$cobs > 10#$coff)); then
		printf 'WIRE_GATE wire_hostinbound_deny FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	if ((10#$cobs < WIRE_DROP_FLOOR)); then
		printf 'WIRE_GATE wire_hostinbound_deny VOID reason=capture-blind %s\n' "$metrics"
		return 2
	fi
	if ((10#$ck > 0)); then
		printf 'WIRE_GATE wire_hostinbound_deny FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	printf 'WIRE_GATE wire_hostinbound_deny PASS reason=-- %s\n' "$metrics"
	return 0
}
#
# wire_conntrack_verdict <created> <witnessed> <stale_present> <exp_offered> <exp_leaked> <fresh_offered> <fresh_leaked> <syn_offered> <syn_observed> <ctrl_sess> <cksum_bad>
#
# The conntrack-lifecycle verdict (#10030): one TCP session is created and
# witnessed present via the Arm B session_list contract, idles past its
# per-application inactivity-timeout, and must read evicted; post-expiry
# non-SYN bursts for the expired tuple AND a never-existed tuple must both
# drop on the wire (the mid-stream pickup shape is the same dataplane path:
# no session + no SYN), while a same-window permitted SYN burst (the
# near-miss: SYN-ness is the keyed field) plus one full control connection
# prove the window and the witness. evicted is DERIVED (stale==0), never an
# input — a blind witness must not be able to report eviction by seeing
# nothing. ctrl_sess is the session-table proof for the control connection:
# it separates "the create-session specifically never installed" (FAIL —
# the witness is proven alive) from "the witness sees nothing at all"
# (VOID harness-void).
# Prints exactly one `WIRE_GATE wire_conntrack_lifecycle ...` line; rc 0/1/2.
# Order: validity; offered floors; uncreated subject (VOID); mid-stream
# leaks (FAIL, surviving everything); unwitnessed (FAIL iff the witness is
# proven alive, else VOID); stale survivor (FAIL); capture-blind; checksums;
# PASS.
wire_conntrack_verdict() {
	local cr="${1:-}" w="${2:-}" st="${3:-}" eo="${4:-}" el="${5:-}" fo="${6:-}" fl="${7:-}" so="${8:-}" sob="${9:-}" cs="${10:-}" ck="${11:-}"
	local zero="created=0 witnessed=0 evicted=0 stale_present=0 exp_offered=0 exp_leaked=0 fresh_offered=0 fresh_leaked=0 syn_offered=0 syn_observed=0 ctrl_sess=0 lifecycle_bad=0 cksum_bad=0"
	if (($# != 11)); then
		printf 'WIRE_GATE wire_conntrack_lifecycle VOID reason=harness-void %s\n' "$zero"
		return 2
	fi
	local a
	for a in "$@"; do
		if ! wire_num "$a"; then
			printf 'WIRE_GATE wire_conntrack_lifecycle VOID reason=harness-void %s\n' "$zero"
			return 2
		fi
	done
	if ((10#$cr > 1)) || ((10#$w > 1)); then
		printf 'WIRE_GATE wire_conntrack_lifecycle VOID reason=harness-void %s\n' "$zero"
		return 2
	fi
	local evicted=0
	if ((10#$st == 0)); then evicted=1; fi
	local bad=$((10#$el + 10#$fl + 10#$st))
	((10#$cr == 0)) && bad=$((bad + 1))
	((10#$w == 0)) && bad=$((bad + 1))
	((10#$cs == 0)) && bad=$((bad + 1))
	local metrics="created=$cr witnessed=$w evicted=$evicted stale_present=$st exp_offered=$eo exp_leaked=$el fresh_offered=$fo fresh_leaked=$fl syn_offered=$so syn_observed=$sob ctrl_sess=$cs lifecycle_bad=$bad cksum_bad=$ck"
	if ((10#$eo < WIRE_DROP_FLOOR)) || ((10#$fo < WIRE_DROP_FLOOR)) || ((10#$so < WIRE_LIVENESS_OFFERED)); then
		printf 'WIRE_GATE wire_conntrack_lifecycle VOID reason=under-sampled %s\n' "$metrics"
		return 2
	fi
	if ((10#$cr == 0)); then
		if ((10#$cs > 0)); then
			printf 'WIRE_GATE wire_conntrack_lifecycle FAIL reason=-- %s\n' "$metrics"
			return 1
		fi
		printf 'WIRE_GATE wire_conntrack_lifecycle VOID reason=harness-void %s\n' "$metrics"
		return 2
	fi
	if ((10#$el + 10#$fl > 0)); then
		printf 'WIRE_GATE wire_conntrack_lifecycle FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	if ((10#$w == 0)); then
		if ((10#$cs > 0)); then
			printf 'WIRE_GATE wire_conntrack_lifecycle FAIL reason=-- %s\n' "$metrics"
			return 1
		fi
		printf 'WIRE_GATE wire_conntrack_lifecycle VOID reason=harness-void %s\n' "$metrics"
		return 2
	fi
	# The same-window permitted control must also have a session-table
	# witness; a missing control census is not evidence of eviction.
	if ((10#$cs == 0)); then
		printf 'WIRE_GATE wire_conntrack_lifecycle VOID reason=harness-void %s\n' "$metrics"
		return 2
	fi
	if ((10#$st > 0)); then
		printf 'WIRE_GATE wire_conntrack_lifecycle FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	if ((10#$sob < WIRE_DROP_FLOOR)); then
		printf 'WIRE_GATE wire_conntrack_lifecycle VOID reason=capture-blind %s\n' "$metrics"
		return 2
	fi
	if ((10#$ck > 0)); then
		printf 'WIRE_GATE wire_conntrack_lifecycle FAIL reason=-- %s\n' "$metrics"
		return 1
	fi
	printf 'WIRE_GATE wire_conntrack_lifecycle PASS reason=-- %s\n' "$metrics"
	return 0
}

# Finalization is deliberately shared by the live gates.  The cleanup callback
# remains installed as EXIT while INT/TERM are ignored, so a cancellation
# cannot interrupt a multi-commit restore or print a verdict before restoration
# has been verified.
wire_gate_finalize() {
	local rc=$? restore_ok=0
	trap '' EXIT INT TERM
	if [[ -n "${WIRE_GATE_CLEANUP_FN:-}" ]]; then
		"${WIRE_GATE_CLEANUP_FN}" || true
	fi
	if [[ -n "${WIRE_GATE_RESTORE_OK_REF:-}" ]]; then
		local -n restore_ref="$WIRE_GATE_RESTORE_OK_REF"
		restore_ok="$restore_ref"
	fi
	trap - INT TERM
	if ((restore_ok == 0)); then
		printf '%s\n' "${WIRE_GATE_RESTORE_VOID:-WIRE_GATE harness VOID reason=harness-void}"
		exit 2
	fi
	if [[ -n "${WIRE_GATE_FINAL_OUT:-}" ]]; then
		printf '%s\n' "$WIRE_GATE_FINAL_OUT"
		exit "${WIRE_GATE_FINAL_RC:-$rc}"
	fi
	exit "$rc"
}

# Hermetic proof for the finalizer contract: cleanup runs with TERM ignored,
# a successful restore prints the pending verdict/rc, and a failed restore
# demotes it to the gate-specific harness VOID/rc=2.
wire_gate_finalizer_selftest() {
	local tmp mode out rc expected_rc expected_out
	tmp="$(mktemp "${TMPDIR:-/var/tmp}/xpf-wire-finalizer.XXXXXX")" || return 1
	export WIRE_GATE_FINALIZER_TEST_FILE="$tmp"
	export -f wire_gate_finalize
	for mode in green restore-fail; do
		out="$(
			WIRE_GATE_FINALIZER_TEST_MODE="$mode" bash -c '
				cleanup() {
					kill -TERM "$$"
					printf cleanup >>"$WIRE_GATE_FINALIZER_TEST_FILE"
				}
				RESTORE_OK=1
				[[ "$WIRE_GATE_FINALIZER_TEST_MODE" == restore-fail ]] && RESTORE_OK=0
				WIRE_GATE_CLEANUP_FN=cleanup
				WIRE_GATE_RESTORE_OK_REF=RESTORE_OK
				WIRE_GATE_RESTORE_VOID="finalizer-restore-void"
				WIRE_GATE_FINAL_OUT="finalizer-pass"
				WIRE_GATE_FINAL_RC=1
				false
				wire_gate_finalize
			' 2>/dev/null
		)"
		rc=$?
		if [[ "$mode" == green ]]; then
			expected_rc=1; expected_out=finalizer-pass
		else
			expected_rc=2; expected_out=finalizer-restore-void
		fi
		if [[ "$rc" != "$expected_rc" || "$out" != "$expected_out" ]]; then
			rm -f "$tmp"
			unset WIRE_GATE_FINALIZER_TEST_FILE
			return 1
		fi
	done
	if [[ "$(<"$tmp")" != cleanupcleanup ]]; then
		rm -f "$tmp"
		unset WIRE_GATE_FINALIZER_TEST_FILE
		return 1
	fi
	rm -f "$tmp"
	unset WIRE_GATE_FINALIZER_TEST_FILE
	return 0
}
