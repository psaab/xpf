#!/usr/bin/env bash
# #19140 smoke: a primary whose RETH data member loses its XDP shim yields the
# RG to a healthy peer.
#
# The pass criteria are PRE-REGISTERED in docs/log/19140.md (P1-P7, the
# --both/--lone/--standby variants, the VOID conditions). This script scores
# them; it does not decide them.
#
# The injection is operator-style: one node, `bpftool link detach` of the
# member's XDP link (the link stays UP, exactly the #19140 shape), no clock
# changes. On the loss cluster RG1 is reth0 (WAN, ge-0-0-2 / ge-7-0-2) and RG2
# is reth1 (LAN, ge-0-0-1 / ge-7-0-1), so:
#   - the RG1 path is a ping train LAN host -> IPERF_TARGET4 (it crosses both
#     RGs; after RG1 moves it splits through the fabric);
#   - the RG2-only path (P6) is a ping train LAN host -> the LAN VIP.
#
# Usage:
#   ./test/incus/member-shim-loss-failover.sh            # the main arm
#   ./test/incus/member-shim-loss-failover.sh --both     # detach on both nodes
#   ./test/incus/member-shim-loss-failover.sh --lone     # node1's xpfd stopped
#   ./test/incus/member-shim-loss-failover.sh --standby  # detach on node1
#
# Exit: 0 all cells passed; 1 a cell failed; 2 VOID (ABORT_CAUSE= names why).

set -euo pipefail

# #1875/#4020: destructive (detaches XDP, stops xpfd for --lone, fails RGs
# over) on the SHARED cluster: serialize as a lock cell.
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "member-shim-loss $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"

VARIANT=main
case "${1:-}" in
"") ;;
--both | --lone | --standby) VARIANT="${1#--}" ;;
*)
	echo "usage: $0 [--both|--lone|--standby]" >&2
	exit 2
	;;
esac

RG="${RG:-1}"
OTHER_RG="${OTHER_RG:-2}"
WAN_TARGET="${WAN_TARGET:-$IPERF_TARGET4}"
RG2_TARGET="${RG2_TARGET:-$LAN_VIP4}"
GRACE=10                # memberShimDebtGrace
CLEAR_HOLD=10           # memberShimClearHold
TOL=2                   # +/- on the grace and clear-hold (P2, P7)
MOVE_AFTER_DEBT=3       # P3: the move within 3 s of the debt
MOVE_DEADLINE=15        # P3: and by 15 s after injection at most
LOSS_BOUND=16           # P4: total RG1-path loss from injection
NO_FLAP=60              # P5 and the variants' hold
P1_BOUND=3              # P1: the ERROR within 3 s
RG2_GAP_BOUND=1         # P6: RG2-only path, no gap over 1 s
LOAD_VOID=8             # VOID: a firewall node's 1-minute loadavg above this
SKEW_VOID=1             # VOID: node clock skew above 1 s

PASS=0
FAIL=0
info() { echo "==> $*"; }
pass() {
	echo "  PASS  $*"
	PASS=$((PASS + 1))
}
fail() {
	echo "  FAIL  $*"
	FAIL=$((FAIL + 1))
}
summary() { echo "Member-shim loss (${VARIANT-}): $PASS passed, $FAIL failed"; }
void_exit() {
	echo "ABORT_CAUSE=VOID: $*"
	summary
	exit 2
}

PIDS=()
WORK="$(mktemp -d "${TMPDIR:-/tmp}/member-shim-19140.XXXXXX")"
cleanup() {
	local p
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
	rm -rf "$WORK"
}
trap cleanup EXIT

node_ref() { if [[ "$1" == 0 ]]; then echo "$FW0"; else echo "$FW1"; fi; }
now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", b - a }'; }

# The local RETH member (Linux name) of RG on node n, from the node's config.
member_of() {
	local n="$1" fpc set reth
	fpc=$([[ "$n" == 0 ]] && echo 0 || echo 7)
	set=$(timeout 20 incus exec "$(node_ref "$n")" -- cli -c "show configuration interfaces | display set" 2>/dev/null || true)
	reth=$(awk -v rg="$RG" '$2 == "interfaces" && $4 == "redundant-ether-options" && $5 == "redundancy-group" && $6 == rg { print $3; exit }' <<<"$set")
	[[ -n "$reth" ]] || return 1
	awk -v reth="$reth" -v fpc="ge-$fpc/" '$2 == "interfaces" && index($3, fpc) == 1 && $5 == "redundant-parent" && $6 == reth { gsub("/", "-", $3); print $3; exit }' <<<"$set"
}

# Role of node<n> for RG, from `show chassis cluster status` on fw0 (or fw1).
cluster_status() { timeout 10 incus exec "$1" -- cli -c "show chassis cluster status" 2>/dev/null || true; }
role_of() {
	awk -v node="node$1" -v rg="$2" '/^Redundancy group:/ { cur = $3; next } cur == rg && $1 == node { print tolower($3); exit }'
}
owner_of_rg() { # prints 0, 1, none or both
	local s r0 r1
	s=$(cluster_status "$FW0")
	[[ -n "$s" ]] || s=$(cluster_status "$FW1")
	r0=$(role_of 0 "$1" <<<"$s")
	r1=$(role_of 1 "$1" <<<"$s")
	if [[ "$r0" == primary && "$r1" == primary ]]; then
		echo both
	elif [[ "$r0" == primary ]]; then
		echo 0
	elif [[ "$r1" == primary ]]; then
		echo 1
	else
		echo none
	fi
}

# The XDP bpf_link id on <member> of node<n>, or empty.
xdp_link_id() {
	local ref ifindex
	ref=$(node_ref "$1")
	ifindex=$(incus exec "$ref" -- cat "/sys/class/net/$2/ifindex" 2>/dev/null) || return 0
	incus exec "$ref" -- bpftool -j link show 2>/dev/null |
		jq -r --argjson ifx "$ifindex" '.[] | select(.type == "xdp" and .ifindex == $ifx) | .id' | head -1
}
detach() { # node member
	local id
	id=$(xdp_link_id "$1" "$2")
	[[ -n "$id" ]] || void_exit "no XDP bpf_link on node$1 $2 before the injection"
	incus exec "$(node_ref "$1")" -- bpftool link detach id "$id" ||
		void_exit "bpftool link detach id $id on node$1 failed"
	sleep 0.2
	[[ -z "$(xdp_link_id "$1" "$2")" ]] || void_exit "the detach did not take on node$1 $2 (an XDP link is still attached)"
}

# Clock offsets (host clock - orchestrator clock), measured once: node
# journals and LAN-host ping stamps are converted to the orchestrator's clock,
# never paired raw.
offset_of() { # incus-ref
	local a c b
	a=$(now)
	c=$(incus exec "$1" -- date +%s.%N)
	b=$(now)
	awk -v a="$a" -v b="$b" -v c="$c" 'BEGIN { printf "%.3f", c - (a + b) / 2 }'
}
# Journal lines since orchestrator-<epoch> on node<n> matching <regex>, with
# their stamps converted to the orchestrator's clock.
journal_since() {
	local off since
	off=$([[ "$1" == 0 ]] && echo "$OFF0" || echo "$OFF1")
	since=$(awk -v t="$2" -v o="$off" 'BEGIN { printf "%d", t + o - 2 }')
	incus exec "$(node_ref "$1")" -- journalctl -u xpfd --since "@$since" -o short-unix --no-pager 2>/dev/null |
		grep -E "$3" | awk -v o="$off" '{ $1 = sprintf("%.3f", $1 - o); print }' || true
}
first_stamp() { awk 'NR == 1 { print $1 }'; }

# A ping train from the LAN host; replies are stamped (-D) on the LAN host's
# clock for gap analysis. The -w deadline ends it even if this script dies.
start_ping() { # target outfile seconds
	incus exec "$CLUSTER_LAN_HOST" -- ping -D -n -i 0.01 -w "$3" "$1" >"$2" 2>&1 &
	PIDS+=("$!")
}
# The largest gap between consecutive replies at or after orchestrator-<epoch>.
max_gap_after() {
	awk -v t0="$2" -v o="$OFFL" -F'[][]' '/bytes from/ { t = $2 - o; if (t < t0) { last = t; next } if (last == "") last = t0; g = t - last; if (g > max) max = g; last = t } END { printf "%.2f", max + 0 }' "$1"
}

# Re-attach by an operator commit (a description toggle forces a compile,
# which re-attaches; #19110 has no automatic retry).
commit_reattach() { # node member
	local ref out
	ref=$(node_ref "$1")
	out="$WORK/commit-$1.txt"
	incus exec "$ref" -- /usr/local/sbin/cli >"$out" 2>&1 <<EOF || true
configure
set interfaces ${2//-//} description member-shim-19140
commit
delete interfaces ${2//-//} description
commit
exit
quit
EOF
	grep -q "commit complete" "$out"
}

restore_rg_to_node0() {
	if [[ "$(owner_of_rg "$RG")" != 0 ]]; then
		timeout 20 incus exec "$FW0" -- cli -c "request chassis cluster failover redundancy-group $RG node 0" >/dev/null 2>&1 || true
		sleep 3
		timeout 20 incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $RG" >/dev/null 2>&1 || true
	fi
}

# ── Preconditions and VOID checks ─────────────────────────────────────
info "precondition: settled roles, node0 primary for RG$RG ($VARIANT)"
[[ "$(owner_of_rg "$RG")" == 0 ]] || void_exit "node0 is not the sole primary of RG$RG before the run"
for n in 0 1; do
	incus exec "$(node_ref "$n")" -- sh -c 'command -v bpftool' >/dev/null 2>&1 || void_exit "bpftool missing on node$n"
done
M0=$(member_of 0) || true
M1=$(member_of 1) || true
[[ -n "${M0:-}" && -n "${M1:-}" ]] || void_exit "could not derive RG$RG's RETH members from the config (node0='${M0:-}' node1='${M1:-}')"
info "RG$RG members: node0 $M0, node1 $M1"

OFF0=$(offset_of "$FW0")
OFF1=$(offset_of "$FW1")
OFFL=$(offset_of "$CLUSTER_LAN_HOST")
skew=$(awk -v a="$OFF0" -v b="$OFF1" 'BEGIN { d = a - b; if (d < 0) d = -d; printf "%.3f", d }')
info "node clock skew ${skew}s (offsets vs this host: node0 ${OFF0}s, node1 ${OFF1}s, LAN host ${OFFL}s)"
if awk -v s="$skew" -v m="$SKEW_VOID" 'BEGIN { exit !(s > m) }'; then
	void_exit "node clock skew ${skew}s exceeds ${SKEW_VOID}s"
fi

# ── Inject ────────────────────────────────────────────────────────────
PING_SECONDS=$((MOVE_DEADLINE + NO_FLAP + 20))
start_ping "$WAN_TARGET" "$WORK/rg1.txt" "$PING_SECONDS"
start_ping "$RG2_TARGET" "$WORK/rg2.txt" "$PING_SECONDS"
sleep 3

if [[ "$VARIANT" == lone ]]; then
	info "--lone: stopping node1's xpfd"
	incus exec "$FW1" -- systemctl stop xpfd
	sleep 5
fi

for n in 0 1; do
	la=$(incus exec "$(node_ref "$n")" -- cut -d' ' -f1 /proc/loadavg)
	echo "loadavg node$n=$la (firewall node)"
	if awk -v l="$la" -v m="$LOAD_VOID" 'BEGIN { exit !(l > m) }'; then
		void_exit "firewall node$n 1-minute loadavg $la exceeds $LOAD_VOID at injection"
	fi
done
echo "loadavg orchestrator=$(cut -d' ' -f1 /proc/loadavg) (context only, never VOIDs)"

T0=$(now)
case "$VARIANT" in
main | lone) detach 0 "$M0" ;;
standby) detach 1 "$M1" ;;
both)
	detach 0 "$M0"
	detach 1 "$M1"
	;;
esac
info "injected at $T0"

# ── Observe ───────────────────────────────────────────────────────────
MOVED_AT=""
FLAPS=0
NONE_SEEN=0
last=0
end=$(awk -v t="$T0" -v w="$((MOVE_DEADLINE + NO_FLAP))" 'BEGIN { printf "%.0f", t + w }')
while (($(date +%s) < end)); do
	o=$(owner_of_rg "$RG")
	[[ "$o" == none ]] && NONE_SEEN=$((NONE_SEEN + 1))
	if [[ "$o" != "$last" && "$o" != none ]]; then
		if [[ "$o" == 1 && -z "$MOVED_AT" ]]; then
			MOVED_AT=$(now)
		elif [[ -n "$MOVED_AT" ]]; then
			FLAPS=$((FLAPS + 1))
		fi
		last="$o"
	fi
	sleep 0.5
done
FINAL_OWNER=$(owner_of_rg "$RG")

ERR_RE='has no XDP shim attached'
DEBT_RE='charging the RG member-shim election debt'
err0=$(journal_since 0 "$T0" "$ERR_RE" | first_stamp)
debt0=$(journal_since 0 "$T0" "$DEBT_RE")
debt1=$(journal_since 1 "$T0" "$DEBT_RE")
debt0_rg=$(grep -E "rg=$RG( |$)" <<<"$debt0" | first_stamp)
debt0_other=$(grep -E "rg=(0|$OTHER_RG)( |$)" <<<"$debt0" | first_stamp)
debt1_rg=$(grep -E "rg=$RG( |$)" <<<"$debt1" | first_stamp)

in_band() { awk -v x="$1" -v lo="$2" -v hi="$3" 'BEGIN { exit !(x >= lo && x <= hi) }'; }

case "$VARIANT" in
main)
	# P1
	if [[ -n "$err0" ]] && in_band "$(elapsed "$T0" "$err0")" -5 "$P1_BOUND"; then
		pass "P1 node0 ERROR '$ERR_RE' $(elapsed "$T0" "$err0")s after injection"
	else
		fail "P1 node0 ERROR '$ERR_RE' not within ${P1_BOUND}s (first=${err0:-none})"
	fi
	# P2
	if [[ -n "$debt0_rg" && -z "$debt0_other" ]] &&
		in_band "$(elapsed "$T0" "$debt0_rg")" $((GRACE - TOL)) $((GRACE + TOL)); then
		pass "P2 member-shim debt on RG$RG only, $(elapsed "$T0" "$debt0_rg")s after injection"
	else
		fail "P2 debt on RG$RG at ${debt0_rg:+$(elapsed "$T0" "$debt0_rg")s}${debt0_rg:-never}; other RGs: ${debt0_other:-none}"
	fi
	# P3
	if [[ -n "$MOVED_AT" && -n "$debt0_rg" ]] &&
		in_band "$(elapsed "$debt0_rg" "$MOVED_AT")" -1 "$MOVE_AFTER_DEBT" &&
		in_band "$(elapsed "$T0" "$MOVED_AT")" 0 "$MOVE_DEADLINE"; then
		pass "P3 RG$RG moved to node1 $(elapsed "$debt0_rg" "$MOVED_AT")s after the debt ($(elapsed "$T0" "$MOVED_AT")s after injection)"
	else
		fail "P3 RG$RG move: ${MOVED_AT:+$(elapsed "$T0" "$MOVED_AT")s after injection}${MOVED_AT:-no move}"
	fi
	# P4
	gap=$(max_gap_after "$WORK/rg1.txt" "$T0")
	if [[ -n "$MOVED_AT" ]] && in_band "$gap" 0 "$LOSS_BOUND"; then
		pass "P4 RG$RG path loss ${gap}s (bound ${LOSS_BOUND}s)"
	else
		fail "P4 RG$RG path loss ${gap}s (bound ${LOSS_BOUND}s, moved=${MOVED_AT:-no})"
	fi
	# P5
	if [[ "$FLAPS" == 0 && "$FINAL_OWNER" == 1 ]]; then
		pass "P5 no flap for ${NO_FLAP}s after the move"
	else
		fail "P5 flaps=$FLAPS final owner=$FINAL_OWNER"
	fi
	;;
both)
	if [[ -z "$MOVED_AT" && "$FINAL_OWNER" == 0 && -n "$debt0_rg" && -n "$debt1_rg" ]]; then
		pass "both: no move and no flap for ${NO_FLAP}s; debt on both nodes"
	else
		fail "both: moved=${MOVED_AT:-no} final=$FINAL_OWNER debt node0=${debt0_rg:-none} node1=${debt1_rg:-none}"
	fi
	;;
lone)
	if [[ -z "$MOVED_AT" && "$FINAL_OWNER" == 0 && "$NONE_SEEN" == 0 && -n "$debt0_rg" ]]; then
		pass "lone: node0 kept RG$RG with the debt, never ownerless"
	else
		fail "lone: moved=${MOVED_AT:-no} final=$FINAL_OWNER ownerless_samples=$NONE_SEEN debt=${debt0_rg:-none}"
	fi
	;;
standby)
	if [[ -z "$MOVED_AT" && "$FINAL_OWNER" == 0 && -n "$debt1_rg" && -z "$debt0_rg" ]]; then
		pass "standby: no move; node1 charged, node0 not"
	else
		fail "standby: moved=${MOVED_AT:-no} final=$FINAL_OWNER debt node1=${debt1_rg:-none} node0=${debt0_rg:-none}"
	fi
	;;
esac

# P6 (every variant): the RG2-only path.
gap2=$(max_gap_after "$WORK/rg2.txt" "$T0")
if in_band "$gap2" 0 "$RG2_GAP_BOUND"; then
	pass "P6 RG$OTHER_RG-only path largest gap ${gap2}s"
else
	fail "P6 RG$OTHER_RG-only path largest gap ${gap2}s (bound ${RG2_GAP_BOUND}s)"
fi

# ── Recover (P7 on the main arm) and restore ──────────────────────────
for n in 0 1; do
	m=$([[ "$n" == 0 ]] && echo "$M0" || echo "$M1")
	if [[ -z "$(xdp_link_id "$n" "$m")" ]]; then
		A0=$(now)
		if commit_reattach "$n" "$m" && [[ -n "$(xdp_link_id "$n" "$m")" ]]; then
			info "node$n $m re-attached by a commit"
		else
			fail "recovery: a commit on node$n did not re-attach $m"
			continue
		fi
		if [[ "$VARIANT" == main && "$n" == 0 ]]; then
			sleep $((CLEAR_HOLD + TOL + 2))
			cleared=$(journal_since 0 "$A0" 'member-shim election debt cleared' | grep -E "rg=$RG( |$)" | first_stamp)
			if [[ -n "$cleared" ]] && in_band "$(elapsed "$A0" "$cleared")" $((CLEAR_HOLD - TOL)) $((CLEAR_HOLD + TOL)); then
				pass "P7 debt cleared $(elapsed "$A0" "$cleared")s after the re-attach"
			else
				fail "P7 debt clear after the re-attach: ${cleared:+$(elapsed "$A0" "$cleared")s}${cleared:-never}"
			fi
		fi
	fi
done
if [[ "$VARIANT" == lone ]]; then
	incus exec "$FW1" -- systemctl start xpfd || fail "restore: starting node1's xpfd failed"
	sleep 10
fi
restore_rg_to_node0

summary
((FAIL == 0))
