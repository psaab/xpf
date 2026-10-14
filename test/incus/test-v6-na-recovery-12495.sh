#!/usr/bin/env bash
#
# test-v6-na-recovery-12495.sh — #12495's LAB leg: fail over an RG carrying
# IPv6 neighbors and decide whether neighbor recovery is attributable to the
# becomeMaster unsolicited-NA burst (vs the daemon RA's SLLA).
#
# THIS IS THE CLUSTER STEP the issue's acceptance asks for, run through the
# #1875 destructive-cluster lease cell (cluster-cell.sh), exactly like every
# other failover smoke: a standalone run re-execs through with-cluster.sh and
# QUEUES behind a held lock; a run already inside a cell proceeds lock-free.
#
# THE PROCEDURE (the attribution design lives in v6-na-recovery-lib-12495.sh
# and is hermetically tested by make test-v6-na-recovery-lib):
#
#   1. PRIME   ping6 the LAN v6 VIP once from the LAN host so it holds a
#              neighbor entry for it. Without this the discriminating entry
#              does not exist and the run can only VOID (UNPRIMED).
#   2. BASELINE  record `ip -6 neigh` for the VIP and the RA-provisioned
#              default gateway, and start a tcpdump for ARP + ND on the LAN
#              host's Ethernet device — an ordinary kernel netdev, so the
#              capture is NOT subject to the firewalls' AF_XDP blindness
#              (#6934's instrument table).
#   3. FAILOVER `request chassis cluster failover redundancy-group $RG` on
#              the current primary. t0 = command completion.
#   4. SAMPLE   `ip -6 neigh` for both addresses every $V6_NA_POLL_MS for
#              $V6_NA_WINDOW_MS, then 5 pings to the WAN-side v6 target
#              (IPERF_TARGET6, the same 3-of-5 oracle check_v6_transit uses).
#   5. PARSE    the pcap locally (v6-na-parse-12495.py) into normalized
#              NA/RA/ARP/PARSEERR events.
#   6. FAIL BACK to the original primary and verify ownership returned.
#   7. VERDICT  v6na_verdict over the timeline; print the four cells.
#
# EXIT STATUS
#   0 PASS   neighbor recovery recorded AND attributable to the NA burst —
#            the evidence #12495's acceptance asks for.
#   1 FAIL   a defect shape: GARP witness with no NA (the #12201 mutant-A
#            survivor), NA on the wire but the entry never moved while
#            transit blackholed, or attributed recovery with transit dead.
#   2 VOID   the measurement did not decide (blind capture, unprimed
#            baseline, RA-attributed-only recovery, cluster unreachable —
#            the skip pattern for hermetic environments).
#   3 FAILBACK FAILURE — the shared cluster was left failed over. This
#            outranks any measurement outcome: it changes what every other
#            lane measures.
#   4 the decision layer itself is broken.
#
# ENVIRONMENT
#   V6_NA_RG        RG whose RETH carries the LAN v6 VIP (default 2 —
#                   reth1→RG2 on the loss userspace cluster).
#   V6_NA_WINDOW_MS / V6_NA_POLL_MS  observation window / sampling period
#                   (defaults 20000 / 500). LAN_IF: capture interface
#                   (default eth0). cluster-env.sh supplies FW0/FW1/
#                   CLUSTER_LAN_HOST/LAN_VIP6/IPERF_TARGET6.

set -euo pipefail

_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# #4020/#1875: failover moves nodes on the SHARED loss cluster — serialize.
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "test-v6-na-recovery-12495 $*" "$0" "$@"
# shellcheck source=cluster-env.sh
source "${_CELL_DIR}/cluster-env.sh"
# shellcheck source=v6-na-recovery-lib-12495.sh
source "${_CELL_DIR}/v6-na-recovery-lib-12495.sh"

V6_NA_RG="${V6_NA_RG:-2}"
V6_NA_WINDOW_MS="${V6_NA_WINDOW_MS:-20000}"
V6_NA_POLL_MS="${V6_NA_POLL_MS:-500}"
LAN_IF="${LAN_IF:-eth0}"
V6_NA_TRANSIT_MIN="${V6_NA_TRANSIT_MIN:-3}"
V6_NA_TRANSIT_COUNT="${V6_NA_TRANSIT_COUNT:-5}"
FAILOVER_DEADLINE="${FAILOVER_DEADLINE:-120}"
REMOTE_PCAP=/tmp/v6na-12495.pcap

info() { echo "==> $*"; }
cell() { echo "  $*"; }

die_void() { echo "VOID: $*" >&2; exit 2; }

# ── Preflight, including the SKIP pattern for cluster-less environments ──
command -v python3 >/dev/null 2>&1 || die_void "python3 is required locally to parse the capture"
if ! incus info "$FW0" >/dev/null 2>&1; then
	die_void "cluster instance ${FW0} is not reachable — this is the #12495 LAB leg and needs the loss cluster; the hermetic halves are the pkg/vrrp unit pins and make test-v6-na-recovery-lib"
fi
incus exec "$CLUSTER_LAN_HOST" -- command -v tcpdump >/dev/null 2>&1 ||
	die_void "tcpdump is not installed on ${CLUSTER_LAN_HOST}; install it before the run (the capture is the instrument)"

# rg_primary <from-node> — prints "node0" or "node1" for V6_NA_RG's primary,
# or nothing when the status output cannot be parsed (fail-closed: callers
# VOID rather than guess; the request text is never ownership proof, #6440).
rg_primary() {
	local out
	out="$(incus exec "$1" -- cli -c 'show chassis cluster status' 2>/dev/null || true)"
	printf '%s\n' "$out" | grep -A1 "Redundancy group: ${V6_NA_RG}" | head -1 |
		sed -n 's/.*\(node[01]\).*primary.*/\1/p'
}

wait_primary() { # <want-node0-or-node1> <deadline-s>
	local want="$1" deadline="$2" label="$3" start now
	start="$(date +%s)"
	while :; do
		[[ "$(rg_primary "$FW0")" == "$want" ]] && return 0
		now="$(date +%s)"
		(( now - start < deadline )) || return 1
		sleep 2
	done

}

PRIMARY_BEFORE="$(rg_primary "$FW0")"
[[ "$PRIMARY_BEFORE" == node0 || "$PRIMARY_BEFORE" == node1 ]] ||
	die_void "cannot determine the current primary for RG${V6_NA_RG} from show chassis cluster status — refusing to fail over blind"
info "RG${V6_NA_RG} primary before: ${PRIMARY_BEFORE} (FW0=node0, FW1=node1)"

GW_LL="$(incus exec "$CLUSTER_LAN_HOST" -- ip -6 route show default 2>/dev/null |
	sed -n 's/^default via \([^ ]*\).*/\1/p' | head -1)"
[[ -n "$GW_LL" ]] || die_void "the LAN host has no IPv6 default route to watch — is v6 up on this cluster?"

T="$(mktemp -d /tmp/xpf-v6na-12495.XXXXXX)"
trap 'rm -rf "$T"' EXIT

# ── 1. Prime the discriminating entry ────────────────────────────────────
incus exec "$CLUSTER_LAN_HOST" -- ping6 -c 1 -W 2 "$LAN_VIP6" >/dev/null 2>&1 ||
	die_void "baseline ping6 to the LAN VIP ${LAN_VIP6} failed — the v6 service is not healthy pre-failover, so a post-failover observation would not be attributable to the transition"

# ── 2. Baseline + capture ───────────────────────────────────────────────
neigh_sample() { # one line pair, appended to the timeline by the caller
	incus exec "$CLUSTER_LAN_HOST" -- sh -c "ip -6 neigh show $LAN_VIP6; ip -6 neigh show $GW_LL" 2>/dev/null
}
norm_neigh() { # <addr> <raw-line> — emit "<ms> NEIGH <addr> <lladdr|none> <state>"
	local addr="$1" raw="$2" ll state
	ll="$(printf '%s\n' "$raw" | sed -n 's/.* lladdr \([^ ]*\).*/\1/p' | head -1)"
	state="$(printf '%s\n' "$raw" | awk '{print $NF}')"
	[[ -n "$ll" ]] || ll=none
	[[ -n "$state" ]] || state=unknown
	printf '%s NEIGH %s %s %s\n' "$(date +%s%3N)" "$addr" "$ll" "$state"
}
BASE_RAW="$(neigh_sample)"
BASE_VIP_LINE="$(printf '%s\n' "$BASE_RAW" | head -1)"
BASE_GW_LINE="$(printf '%s\n' "$BASE_RAW" | tail -1)"
norm_neigh "$LAN_VIP6" "$BASE_VIP_LINE" >>"$T/neigh.txt"
norm_neigh "$GW_LL" "$BASE_GW_LINE" >>"$T/neigh.txt"
BASE_VIP_MAC="$(printf '%s\n' "$BASE_VIP_LINE" | sed -n 's/.* lladdr \([^ ]*\).*/\1/p')"
BASE_GW_MAC="$(printf '%s\n' "$BASE_GW_LINE" | sed -n 's/.* lladdr \([^ ]*\).*/\1/p')"
cell "baseline: ${LAN_VIP6} -> ${BASE_VIP_MAC:-<no entry>}; ${GW_LL} -> ${BASE_GW_MAC:-<no entry>}"

incus exec "$CLUSTER_LAN_HOST" -- sh -c \
	"nohup tcpdump -i ${LAN_IF} -U -n -w ${REMOTE_PCAP} 'arp or (icmp6 and ip6[40] >= 133 and ip6[40] <= 136)' >/tmp/v6na-12495.tcpdump.log 2>&1 &" ||
	die_void "could not start tcpdump on ${CLUSTER_LAN_HOST}"
sleep 2 # let the capture arm before the transition (#6934 armed 10s early)

# ── 3. Fail over ────────────────────────────────────────────────────────
REQUEST_NODE="$FW0"
[[ "$PRIMARY_BEFORE" == node1 ]] && REQUEST_NODE="$FW1"
info "requesting RG${V6_NA_RG} failover on ${REQUEST_NODE} (${PRIMARY_BEFORE} is primary)"
incus exec "$REQUEST_NODE" -- cli -c "request chassis cluster failover redundancy-group ${V6_NA_RG}" >/dev/null 2>&1 || true
T0="$(date +%s%3N)"

# ── 4. Sample the neighbor timeline through the window ──────────────────
POLL_N=$(( V6_NA_WINDOW_MS / V6_NA_POLL_MS ))
for ((i = 0; i < POLL_N; i++)); do
	raw="$(neigh_sample)"
	norm_neigh "$LAN_VIP6" "$(printf '%s\n' "$raw" | head -1)" >>"$T/neigh.txt"
	norm_neigh "$GW_LL" "$(printf '%s\n' "$raw" | tail -1)" >>"$T/neigh.txt"
	sleep "$(awk -v ms="$V6_NA_POLL_MS" 'BEGIN { printf "%.3f", ms / 1000 }')"
done

# End-to-end recovery oracle: same shape as test-failover's check_v6_transit.
TRANSIT_OUT="$(incus exec "$CLUSTER_LAN_HOST" -- ping6 -c "$V6_NA_TRANSIT_COUNT" -W 1 "$IPERF_TARGET6" 2>&1 || true)"
TRANSIT_RECV="$(printf '%s\n' "$TRANSIT_OUT" | sed -n 's/.* \([0-9][0-9]*\) received.*/\1/p' | head -1)"
[[ -n "$TRANSIT_RECV" ]] || TRANSIT_RECV=0
cell "transit: ${TRANSIT_RECV}/${V6_NA_TRANSIT_COUNT} replies from ${IPERF_TARGET6}"

# ── 5. Stop capture, fetch, parse ───────────────────────────────────────
incus exec "$CLUSTER_LAN_HOST" -- pkill -x tcpdump >/dev/null 2>&1 || true
sleep 1
incus exec "$CLUSTER_LAN_HOST" -- cat "$REMOTE_PCAP" >"$T/cap.pcap" 2>/dev/null ||
	die_void "could not fetch the capture from ${CLUSTER_LAN_HOST}"
[[ -s "$T/cap.pcap" ]] || die_void "the capture file is empty — the instrument never armed"
python3 "${_CELL_DIR}/v6-na-parse-12495.py" "$T/cap.pcap" >"$T/events.txt" ||
	die_void "the capture could not be read (bad magic/linktype) — not evidence of anything"

# ── 6. Fail back — restore the shared cluster's placement ────────────────
# The failover moved the RG to the OTHER node; a failback request issued on
# the CURRENT primary moves it back to its peer. Ask, then wait out the
# deadline.
WANT_AFTER="$PRIMARY_BEFORE"
FAILBACK_RC=0
CURRENT="$(rg_primary "$FW0")"
REQUEST_BACK="$FW0"
[[ "$CURRENT" == node1 ]] && REQUEST_BACK="$FW1"
if [[ -n "$CURRENT" && "$CURRENT" != "$WANT_AFTER" ]]; then
	incus exec "$REQUEST_BACK" -- cli -c "request chassis cluster failover redundancy-group ${V6_NA_RG}" >/dev/null 2>&1 || true
fi
wait_primary "$WANT_AFTER" "$FAILOVER_DEADLINE" || FAILBACK_RC=1
incus exec "$CLUSTER_LAN_HOST" -- rm -f "$REMOTE_PCAP" /tmp/v6na-12495.tcpdump.log >/dev/null 2>&1 || true

# ── 7. Verdict ───────────────────────────────────────────────────────────
VERDICT_OUT="$(v6na_verdict "$T0" "$V6_NA_WINDOW_MS" "$LAN_VIP6" "$GW_LL" \
	"$BASE_VIP_MAC" "$BASE_GW_MAC" "$T/events.txt" "$T/neigh.txt" \
	"$TRANSIT_RECV" "$V6_NA_TRANSIT_COUNT" "$V6_NA_TRANSIT_MIN")"
printf '%s\n' "$VERDICT_OUT"
VERDICT_LINE="$(printf '%s\n' "$VERDICT_OUT" | sed -n 's/^V6NA-VERDICT: //p' | tail -1)"
RC=0
v6na_exit_status "V6NA-VERDICT: $VERDICT_LINE" || RC=$?

if [[ "$FAILBACK_RC" -ne 0 ]]; then
	echo "FAILBACK: RG${V6_NA_RG} did not return to ${WANT_AFTER} within ${FAILOVER_DEADLINE}s — the shared cluster is left failed over; fix placement before any other lane runs" >&2
	exit 3
fi
info "raw evidence (neigh timeline, events, pcap) is under $T and removed by the EXIT trap"
exit "$RC"
