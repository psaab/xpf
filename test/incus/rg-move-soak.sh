#!/usr/bin/env bash
# xpf continuous one-node RG-move soak (#18583, regression matrix row H11).
#
# The operator's loop, made rigorous: from ONE node, alternate
#   request chassis cluster failover redundancy-group <rg> node 0|1
# every SOAK_SLEEP seconds (after the CLI returns) for SOAK_MOVES moves, with
# iperf3 (-P8 IPv4, -P2 IPv6) and ping -D -i 0.01 (IPv4 + IPv6) running from
# the LAN host, and score every move: the CLI text, ownership in BOTH nodes'
# own status within the bound and for the rest of the window, each node's
# `Forwarding: rg-active=` line, each helper's own ha_groups[].forwarding_active, no
# dual-active, that the traffic itself moved (the target node's RETH members
# carry the packets, the LAN host's neighbour entry for the LAN VIP resolves
# to the target node), and the loss/stall in that move's window on the LAN
# host's clock. node0 is left primary at the end (matrix row D3).
#
# It NEVER fixes clocks. Every gate before it resynced both node clocks first;
# the operator does not, and a skewed pair is exactly what the operator hit
# (docs/ha-rg-move-correctness.md). The preflight measures and reports the
# inter-node skew instead.
#
# Knobs (environment):
#   SOAK_MOVES       number of moves                       (default 20)
#   SOAK_SLEEP       seconds after each CLI return         (default 5)
#   SOAK_RG          2 | 1 | "1,2" | all                   (default 2)
#   SOAK_FROM        node that issues every move (0|1)     (default 0)
#   SOAK_CONVERGE_S  seconds after the CLI returns for the RG to land in both
#                    views                                  (default SOAK_SLEEP)
#   SOAK_MAX_GAP_MS  longest ping gap allowed per move     (default 1000)
#   SOAK_MAX_STALL_MS worst iperf3 stream stall per move   (default 2000)
#                    Over-budget gaps/stalls that recover are COST (#18559),
#                    not FAIL; SOAK_STRICT_COST=1 scores them as FAIL.
#   SOAK_FOLLOW_MIN_PKTS RETH-member packets the target must carry between
#                    landing and the window's end (default 500)
#   SOAK_TRAFFIC=0   skip traffic (control-plane only; the run exits 2)
#   SOAK_HELPER_CHECK=0 skip the helper reads (the run exits 2)
#   SOAK_IPV6=0      IPv4 only
#   SOAK_RESTORE=0   do not put node0 back as primary at the end
#   SOAK_IPERF_PORT  IPv4 iperf3 server port (default 5211, the unshaped class)
#   SOAK_IPERF6_PORT IPv6 iperf3 server port (default 5210)
#   SOAK_OUT         output directory (default /var/tmp/rg-move-soak-<utc>)
#
# Exit: 0 every move PASS or COST; 1 any FAIL; 2 no FAIL but VOID (a void
# move, a void run — preflight, busy traffic target, harness error, SIGTERM —
# or a disabled check). The last line, "rg-move-soak: N passed, M failed",
# is what the smoke-cells ledger adapter scores (make test-rg-move-soak).
#
# Usage:
#   ./test/incus/rg-move-soak.sh                     # loss, 20 moves, RG2
#   SOAK_MOVES=200 SOAK_SLEEP=5 make test-rg-move-soak
#   SOAK_RG=all SOAK_FROM=1 ./test/incus/rg-move-soak.sh

set -euo pipefail

_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_DIR="$_CELL_DIR"

# #1875/#4020: RG moves are destructive on the SHARED cluster. Serialize as a
# lock cell (re-execs through with-cluster.sh unless a live ancestor holds it).
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "rg-move-soak ${SOAK_MOVES:-20}x RG${SOAK_RG:-2} every ${SOAK_SLEEP:-5}s $*" "$0" "$@"

# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"

OUT="${SOAK_OUT:-/var/tmp/rg-move-soak-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
echo "rg-move-soak: env=${BPFRX_CLUSTER_ENV:-} fw0=$FW0 fw1=$FW1 lan=$CLUSTER_LAN_HOST target=$IPERF_TARGET4"
# The pipeline's status is tee's under `|| true`; take python's from
# PIPESTATUS with errexit off instead.
set +e
python3 -u "${SCRIPT_DIR}/rg_move_soak.py" \
	--fw0 "$FW0" --fw1 "$FW1" --lan "$CLUSTER_LAN_HOST" \
	--target4 "$IPERF_TARGET4" --target6 "${IPERF_TARGET6:-}" \
	--lan-vip4 "${LAN_VIP4:-}" --lan-vip6 "${LAN_VIP6:-}" \
	--outdir "$OUT" 2>&1 | tee "$OUT/soak.log"
rc=${PIPESTATUS[0]}
set -e
echo "rg-move-soak: exit $rc (exit codes: 0 = every move PASS/COST, 1 = a FAIL, 2 = VOID); artefacts in $OUT"
exit "$rc"
