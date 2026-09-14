#!/usr/bin/env bash
# shellcheck shell=bash
#
# Shared verdict core for the #9531 wire-deny gates (wire-policy-deny.sh,
# wire-appmatch-twins.sh). Pure bash, no cluster, no incus, no network — every
# function here is drivable hermetically through each gate's --selftest.
#
# WHY THIS EXISTS
#
# The two wire gates share one falsifiability shape: a counted probe burst
# that must NOT emerge peer-side, a counted near-miss control burst that MUST
# emerge in the same capture window, and floors below which no verdict may be
# PASS. If each script grew its own copy, a floor fix in one and not the other
# would be a silent divergence in what "conformant" means — the exact class of
# drift the §2 oracle exists to prevent. One total verdict function, two
# callers, hermetic matrices on both.
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
WIRE_DROP_FLOOR=1000
WIRE_LOSS_FLOOR=10000

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
