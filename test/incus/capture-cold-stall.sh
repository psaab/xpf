#!/usr/bin/env bash
#
# capture-cold-stall.sh — #1782 residual cold-start stall capture harness.
#
# Run this at the next overnight idle window on the loss userspace
# cluster. It records the evidence the #1782 research plan
# (docs/research/1782-cold-start-stall-residual/plan.md §6/§7) needs to
# disambiguate the residual cold-start stall after #1780 Path A:
#
#   H2 — next-hop ABSENT from the userspace dynamic_neighbors mirror
#        after overnight idle (kernel still DELAY/STALE-usable).
#   H3 — first-miss resolution waits for the kernel REACHABLE round-trip
#        (measured by neighbor_pending_dwell, NOT resolver get_rtt).
#   H5 — sibling cold SYNs to the same next-hop dropped because only one
#        pending_neigh slot per (worker, next_hop) is buffered.
#   H1 — per-worker 3s neg-cache lockout (amplifier).
#   H4 — TCP SYN-RTO (amplifier).
#
# This is a doc-style diagnostic capture, NOT a pass/fail gate. It does
# not change firewall behaviour; it only observes. Run it, then attach
# the artifact directory to the #1782 issue.
#
# Sequencing (plan §6):
#   1. start `ip monitor neigh` on the fw BEFORE the idle window
#      (so the DELNEIGH/GC that removes the entry is captured), then
#      WAIT for the idle window (operator-controlled). Realistically:
#      run --monitor-only the night before, then --connect in the
#      morning pointing at the same ART dir.
#   2. t0' pre-connect sample (still idle): keyed dynamic_neighbors
#      membership for the next-hop + `ip neigh` NUD/lladdr + metrics;
#   3. cold connect (iperf3 -c <target> -t 3) with per-flow wall-time;
#   4. t1 recovery sample (same as t0');
#   5. counter deltas t0'->t1 from the Prometheus endpoint;
#   6. tcpdump of the SYN exchange (connecting flow + siblings);
#   7. pending_neigh timeout / retrans-sysctl state.
#
# Usage:
#   ./test/incus/capture-cold-stall.sh                 # full capture, 0s idle
#   IDLE_SECONDS=28800 ./test/incus/capture-cold-stall.sh
#   ./test/incus/capture-cold-stall.sh --monitor-only  # arm ip monitor, exit
#   ART=/tmp/cold-stall-X ./test/incus/capture-cold-stall.sh --connect
#
# Env knobs (defaults come from the selected cluster env; normally loss):
#   FW          firewall node            (default INCUS_REMOTE:VM0)
#   HOST        client/generator node    (default INCUS_REMOTE:LAN_HOST)
#   TARGET_V4   cold-connect v4 target   (default from cluster env IPERF_TARGET4)
#   TARGET_V6   cold-connect v6 target   (default from cluster env IPERF_TARGET6)
#   PORT        iperf3 port              (default 5201)
#   SIBLINGS    parallel sibling streams (default 4 — exercises H5)
#   NEXTHOP_V4  next-hop to grep for     (default = TARGET_V4, directly connected)
#   NEXTHOP_V6  next-hop to grep for     (default = TARGET_V6, directly connected)
#   DP_IFACE    data-path egress iface   (default per-node: ge-0-0-2 on fw0,
#               ge-7-0-2 on fw1 — reth0.80 WAN side, FPC 0 vs 7)
#   METRICS_URL daemon Prometheus URL    (default http://127.0.0.1:8080/metrics)
#   IDLE_SECONDS pre-connect idle wait   (default 0)
#   ART         artifact dir             (default /tmp/cold-stall-<ts>)
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${PROJECT_ROOT}/test/incus/cluster-env.sh"

FW="${FW:-${INCUS_REMOTE}:${VM0}}"
HOST="${HOST:-${INCUS_REMOTE}:${LAN_HOST}}"
TARGET_V4="${TARGET_V4:-$IPERF_TARGET4}"
TARGET_V6="${TARGET_V6:-$IPERF_TARGET6}"
PORT="${PORT:-5201}"
SIBLINGS="${SIBLINGS:-4}"
NEXTHOP_V4="${NEXTHOP_V4:-$TARGET_V4}"
NEXTHOP_V6="${NEXTHOP_V6:-$TARGET_V6}"
# The WAN-side VF name is per-node (ge-{FPC}-0-2, FPC 0 vs 7 — see
# pkg/daemon/linksetup.go + docs/ha-cluster-userspace.conf), so derive the
# default from the target node instead of hardcoding node 0's name (#1786).
# An explicit DP_IFACE env override still wins.
case "$FW" in
  *fw1) DP_IFACE="${DP_IFACE:-ge-7-0-2}" ;;
  *)    DP_IFACE="${DP_IFACE:-ge-0-0-2}" ;;
esac
METRICS_URL="${METRICS_URL:-http://127.0.0.1:8080/metrics}"
IDLE_SECONDS="${IDLE_SECONDS:-0}"
ART="${ART:-/tmp/cold-stall-$(date +%s)}"

MODE="full"
case "${1:-}" in
  --monitor-only) MODE="monitor-only" ;;
  --connect)      MODE="connect" ;;
  "")             MODE="full" ;;
  *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

mkdir -p "$ART"
echo "#1782 cold-stall capture: fw=$FW host=$HOST mode=$MODE art=$ART"
echo "  target v4=$TARGET_V4 v6=$TARGET_V6 port=$PORT siblings=$SIBLINGS"
echo "  next-hop v4=$NEXTHOP_V4 v6=$NEXTHOP_V6 dp_iface=$DP_IFACE"
echo "  NOTE: the dynamic_neighbors membership dump (H2 fingerprint) is gated"
echo "  behind XPF_DEBUG_NEIGHBOR_KEYS — the daemon under capture MUST be"
echo "  launched with that env set, or the membership check reads empty."

# fw-side command wrapper (per CLAUDE.md / existing scripts).
fw() { sg incus-admin -c "incus exec $FW -- $*"; }
# client-side command wrapper.
cl() { sg incus-admin -c "incus exec $HOST -- $*"; }

ts() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }

# A reusable point-in-time sample of the cold-path state on the firewall.
#   $1 = label (t0prime, t0, t1). Records keyed dynamic_neighbors
# membership (item 3 / H2), `ip neigh` NUD/lladdr (item 2), and a full
# Prometheus metrics snapshot (item 3).
sample() {
  local label="$1"
  local dir="$ART/$label"
  mkdir -p "$dir"
  echo "[$(ts)] sample $label" | tee -a "$ART/timeline.log"

  fw "curl -s $METRICS_URL" > "$dir/metrics.prom" 2>"$dir/metrics.err" || true

  # Keyed dynamic_neighbors membership (the H2 fingerprint). PR-1 dumps
  # every present key as xpf_userspace_dynamic_neighbor_present{ifindex,ip}.
  # Match BOTH labels: the key is (ifindex, ip), so grepping ip alone could
  # false-PRESENT if the same IP exists on another interface (Codex r1).
  # DPIDX is the kernel ifindex of the data-path egress; cache it once.
  if [ -z "${DPIDX:-}" ]; then
    DPIDX=$(fw "cat /sys/class/net/$DP_IFACE/ifindex" 2>/dev/null | tr -d '[:space:]')
  fi
  grep 'xpf_userspace_dynamic_neighbor_present' "$dir/metrics.prom" \
    > "$dir/dynamic_neighbor_keys.txt" 2>/dev/null || true
  {
    echo "# dynamic_neighbors membership for next-hops at $label (ifindex=$DPIDX iface=$DP_IFACE)"
    for nh in "$NEXTHOP_V4" "$NEXTHOP_V6"; do
      if [ -n "$DPIDX" ] && grep -F "ip=\"$nh\"" "$dir/dynamic_neighbor_keys.txt" 2>/dev/null \
           | grep -Fq "ifindex=\"$DPIDX\""; then
        echo "PRESENT  $nh   (ifindex $DPIDX)"
      else
        echo "ABSENT   $nh   (ifindex $DPIDX)  <-- H2 candidate (cross-check ip neigh NUD)"
      fi
    done
  } | tee "$dir/membership.txt" | sed 's/^/    /'

  # Kernel neighbor NUD state / lladdr for the next-hops (item 2).
  fw "ip -s neigh show" > "$dir/ip_neigh_v4.txt" 2>/dev/null || true
  fw "ip -6 -s neigh show" > "$dir/ip_neigh_v6.txt" 2>/dev/null || true
  {
    grep -F "$NEXTHOP_V4" "$dir/ip_neigh_v4.txt" 2>/dev/null || echo "no kernel v4 entry for $NEXTHOP_V4"
    grep -iF "$NEXTHOP_V6" "$dir/ip_neigh_v6.txt" 2>/dev/null || echo "no kernel v6 entry for $NEXTHOP_V6"
  } > "$dir/nexthop_nud.txt" 2>/dev/null || true
}

# Item 6: pending_neigh timeout / kernel retrans-time sysctl state. Tells
# us the H1-arming threshold (2s default fallback vs 800ms validated fast
# path — forwarding_build/mod.rs compute_pending_neigh_timeout_ns).
capture_sysctls() {
  echo "[$(ts)] capturing retrans-time sysctls" | tee -a "$ART/timeline.log"
  {
    echo "## per-interface retrans / base_reachable for $DP_IFACE"
    fw "sysctl net.ipv4.neigh.$DP_IFACE.retrans_time_ms" 2>/dev/null || true
    fw "sysctl net.ipv4.neigh.$DP_IFACE.base_reachable_time_ms" 2>/dev/null || true
    fw "sysctl net.ipv6.neigh.$DP_IFACE.retrans_time_ms" 2>/dev/null || true
    fw "sysctl net.ipv6.neigh.$DP_IFACE.base_reachable_time_ms" 2>/dev/null || true
    echo "## default neigh retrans"
    fw "sysctl net.ipv4.neigh.default.retrans_time_ms" 2>/dev/null || true
    fw "sysctl net.ipv6.neigh.default.retrans_time_ms" 2>/dev/null || true
    echo "## all interfaces"
    fw "sysctl -a 2>/dev/null | grep -E 'neigh.*(retrans_time_ms|base_reachable_time_ms)'" 2>/dev/null || true
  } > "$ART/retrans_sysctls.txt" 2>&1 || true
}

# Item 4: start timestamped `ip monitor neigh` in the background BEFORE
# the idle window. Catches the DELNEIGH/GC that removes the next-hop
# during idle — the H2 root cause.
start_neigh_monitor() {
  echo "[$(ts)] starting ip monitor neigh on $FW -> $ART/ip_monitor_neigh.log" \
    | tee -a "$ART/timeline.log"
  sg incus-admin -c "incus exec $FW -- stdbuf -oL ip -ts monitor neigh" \
    > "$ART/ip_monitor_neigh.log" 2>"$ART/ip_monitor_neigh.err" &
  echo $! > "$ART/.ip_monitor.pid"
}

stop_neigh_monitor() {
  if [ -f "$ART/.ip_monitor.pid" ]; then
    local pid; pid="$(cat "$ART/.ip_monitor.pid")"
    echo "[$(ts)] stopping ip monitor neigh (local pid $pid)" | tee -a "$ART/timeline.log"
    kill "$pid" 2>/dev/null || true
    fw "pkill -f 'ip -ts monitor neigh'" 2>/dev/null || true
    rm -f "$ART/.ip_monitor.pid"
  fi
}

# Item 5: tcpdump the SYN exchange (connecting flow + siblings) on the
# data-path egress iface so outbound SYNs and retransmits (H4/H5) show up.
start_syn_tcpdump() {
  echo "[$(ts)] starting tcpdump (SYN exchange) on $FW:$DP_IFACE" | tee -a "$ART/timeline.log"
  sg incus-admin -c "incus exec $FW -- timeout 20 tcpdump -i $DP_IFACE -n -w - 'tcp and (tcp[tcpflags] & tcp-syn != 0) and (host $TARGET_V4 or host $TARGET_V6)'" \
    > "$ART/syn_exchange.pcap" 2>"$ART/syn_exchange.tcpdump.err" &
  echo $! > "$ART/.tcpdump.pid"
  sleep 1
}

stop_syn_tcpdump() {
  if [ -f "$ART/.tcpdump.pid" ]; then
    local pid; pid="$(cat "$ART/.tcpdump.pid")"
    echo "[$(ts)] stopping tcpdump (local pid $pid)" | tee -a "$ART/timeline.log"
    wait "$pid" 2>/dev/null || true
    rm -f "$ART/.tcpdump.pid"
  fi
}

# Item 1/3: the cold connect. One primary flow whose connect wall-time we
# measure, plus SIBLINGS parallel flows to the same target so the H5
# sibling-drop path is exercised.
cold_connect() {
  local fam="$1" target="$2" tag="$3"
  echo "[$(ts)] COLD CONNECT $tag -> $target (1 primary + $SIBLINGS siblings)" \
    | tee -a "$ART/timeline.log"
  local cdir="$ART/connect_$tag"
  mkdir -p "$cdir"

  # Siblings exercise the H5 one-representative-pending drop: parallel cold
  # flows to the SAME next-hop. They must NOT all hit one iperf3 server (it is
  # single-connection -> "server busy" rejections that mask the resolver/RTO
  # timing, Codex+AGY r1). Each sibling targets a DISTINCT per-class port
  # (PORT+i, i.e. 5202..), all reaching the same target IP -> same
  # (egress_ifindex, next_hop) neighbor key, so the sibling-drop path is
  # exercised without server-busy collisions.
  local sib_pids=()
  for i in $(seq 1 "$SIBLINGS"); do
    (
      local start end rc sport
      sport=$((PORT + i))
      start=$(date +%s.%N)
      rc=0
      cl "iperf3 -c $target $fam -t 3 -p $sport --connect-timeout 5000 --json" \
        > "$cdir/sibling_$i.json" 2>"$cdir/sibling_$i.err" || rc=$?
      end=$(date +%s.%N)
      echo "sibling $i port=$sport rc=$rc wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')s" \
        >> "$cdir/wall_times.txt"
    ) &
    sib_pids+=($!)
  done

  {
    local start end rc
    start=$(date +%s.%N)
    rc=0
    cl "iperf3 -c $target $fam -t 3 -p $PORT --connect-timeout 5000 --json" \
      > "$cdir/primary.json" 2>"$cdir/primary.err" || rc=$?
    end=$(date +%s.%N)
    echo "primary port=$PORT rc=$rc wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')s" \
      | tee -a "$cdir/wall_times.txt"
  }

  for pid in "${sib_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  echo "  per-flow wall times:" | tee -a "$ART/timeline.log"
  sed 's/^/    /' "$cdir/wall_times.txt" | tee -a "$ART/timeline.log"
}

# Reduce the counter deltas t0'->t1 from the two metrics snapshots. The
# columns are the per-mechanism signals the plan calls out (§6.3).
reduce_deltas() {
  local before="$ART/t0prime/metrics.prom"
  local after="$ART/t1/metrics.prom"
  echo "[$(ts)] reducing counter deltas t0'->t1" | tee -a "$ART/timeline.log"
  local pats='xpf_userspace_neighbor_pending_dwell_|xpf_userspace_neighbor_pending_timeout_drops_total|xpf_userspace_neg_neigh_fast_fail_total|xpf_userspace_pending_neigh_duplicate_drops_total|xpf_userspace_neighbor_resolver_|xpf_userspace_neighbor_warm_|xpf_daemon_neighbor_periodic_last_success_age_seconds'
  {
    printf "%-78s %14s %14s %14s\n" "metric" "t0prime" "t1" "delta"
    {
      grep -hE "$pats" "$before" 2>/dev/null | grep -v '^#'
      grep -hE "$pats" "$after"  2>/dev/null | grep -v '^#'
    } | awk '{print $1}' | sort -u | while read -r m; do
      local b a d
      b=$(awk -v k="$m" '$1==k{print $2; exit}' "$before" 2>/dev/null)
      a=$(awk -v k="$m" '$1==k{print $2; exit}' "$after"  2>/dev/null)
      b=${b:-0}; a=${a:-0}
      d=$(awk -v a="${a:-0}" -v b="${b:-0}" 'BEGIN{printf "%.3f", a-b}')
      printf "%-78s %14s %14s %14s\n" "$m" "$b" "$a" "$d"
    done
  } | tee "$ART/counter_deltas.txt"
}

trap 'stop_syn_tcpdump; stop_neigh_monitor' EXIT

# Fail fast if DP_IFACE does not exist on the target node. Every
# per-interface evidence channel below (neigh sysctls, the SYN-exchange
# tcpdump, the ifindex-keyed membership check) tolerates errors with
# `|| true`, so a wrong interface name would otherwise produce a quietly
# hollow artifact — unacceptable for a one-shot overnight capture (#1786).
# Placed AFTER the EXIT trap so a wrong-iface --connect resume cleanly
# stops the overnight monitor (finalizing its log) instead of orphaning
# it, and BEFORE the monitor/sysctl/tcpdump arming below.
fw "ip link show $DP_IFACE" >/dev/null 2>&1 \
  || { echo "ERROR: DP_IFACE $DP_IFACE not present on $FW" >&2; exit 2; }

# Arm the monitor + capture sysctls first (item 4 / item 6). In --connect mode
# resuming an overnight --monitor-only run, REUSE the existing monitor log —
# never re-run start_neigh_monitor, which would truncate ('>') the overnight
# ip_monitor_neigh.log and destroy the DELNEIGH/GC evidence (the H2 root cause).
# The EXIT trap still stops the overnight monitor PID to finalize the log.
if [ "$MODE" = "connect" ] && [ -f "$ART/ip_monitor_neigh.log" ]; then
  echo "[$(ts)] --connect: reusing existing overnight ip_monitor_neigh.log (not truncating)" \
    | tee -a "$ART/timeline.log"
else
  start_neigh_monitor
fi
capture_sysctls

if [ "$MODE" = "monitor-only" ]; then
  echo "[$(ts)] --monitor-only: ip monitor neigh armed, leaving it running."
  echo "Re-run with --connect (ART=$ART) in the morning to do the cold connect."
  trap - EXIT
  exit 0
fi

if [ "$MODE" = "full" ] && [ "$IDLE_SECONDS" -gt 0 ]; then
  echo "[$(ts)] idle wait ${IDLE_SECONDS}s (use a real overnight window for the bug)" \
    | tee -a "$ART/timeline.log"
  sleep "$IDLE_SECONDS"
fi

# t0' — pre-connect sample (still idle). The H2-vs-H3 separator.
sample t0prime

# Arm tcpdump just before the connect (item 5).
start_syn_tcpdump

# t0 — at stall start = the cold connect itself.
sample t0
cold_connect "-4" "$TARGET_V4" v4
cold_connect "-6" "$TARGET_V6" v6

stop_syn_tcpdump

# t1 — recovery sample.
sample t1

# Counter deltas + the #1780 regression guard.
reduce_deltas
echo "[$(ts)] #1780 phase-age regression guard (must be small/healthy):" \
  | tee -a "$ART/timeline.log"
grep 'xpf_daemon_neighbor_periodic_last_success_age_seconds' "$ART/t1/metrics.prom" \
  2>/dev/null | grep -v '^#' | sed 's/^/    /' | tee -a "$ART/timeline.log" || true

echo
echo "[$(ts)] capture complete. Artifacts in: $ART"
echo "  timeline.log            — ordered event log"
echo "  ip_monitor_neigh.log    — DELNEIGH/GC during idle (H2)"
echo "  t0prime/membership.txt  — pre-connect dynamic_neighbors miss (H2)"
echo "  t0prime/nexthop_nud.txt — kernel NUD state at t0' (H2/H3)"
echo "  counter_deltas.txt      — H1/H3/H5 + #1780 guard signals"
echo "  syn_exchange.pcap       — SYN-RTO pattern (H4/H5)"
echo "  retrans_sysctls.txt     — H1-arming threshold (item 6)"
echo "  connect_v4/, connect_v6/ — per-flow connect wall-time + rc"
