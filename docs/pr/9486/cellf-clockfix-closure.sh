#!/usr/bin/env bash
# #9486 cell F — fix fw0 clock skew (fabric auth root cause), then complete
# the adjacent-rollback closure: PREV boots (proven cell E) -> failover to
# node 1 (expect SUCCESS now) -> pinned iperf through PREV-primary ->
# re-cut forward -> failback -> teardown.
set -euo pipefail
info() { echo "info: $*"; }
warn() { echo "warn: $*" >&2; }
die() { echo "die: $*" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
EVID="$ROOT/docs/pr/9486/evidence"
exec > >(tee -a "$EVID/cellf.log") 2>&1

# shellcheck source=test/incus/deploy-lib.sh
source "$ROOT/test/incus/deploy-lib.sh"

R0="loss:xpf-userspace-fw0"
R1="loss:xpf-userspace-fw1"
LAN="loss:cluster-userspace-host"
TARGET="172.16.80.200"
VD="/var/lib/xpf/versions"

wait_active() { # <rinst> <tries>
  local r="$1" n="$2" s
  for ((i=0; i<n; i++)); do
    s="$(incus exec "$r" -- systemctl is-active xpfd 2>&1 || true)"
    [[ "$s" == "active" ]] && { echo "active after ~$((i*5))s"; return 0; }
    sleep 5
  done
  echo "NOT-ACTIVE after ${n}x5s (last=$s)"
  return 1
}

echo "=== CELL-F START $(date -u +%FT%TZ) ==="
NEW2="$(incus exec "$R1" -- readlink /var/lib/xpf/versions/current)"
PREV="working-15061-g7ef226474-dirty"
echo "NEW2=$NEW2 PREV=$PREV"
incus exec "$R1" -- test -d "$VD/$PREV" || die "PREV slot missing — STOP per parent ruling"

echo "=== 1. clock evidence + fix (fw0 ~125 s slow, no NTP source) ==="
echo "before: host=$(date -u +%FT%TZ) fw0=$(incus exec "$R0" -- date -u +%FT%TZ) fw1=$(incus exec "$R1" -- date -u +%FT%TZ)" | tee "$EVID/cellf-clock.log"
FW1TIME="$(incus exec "$R1" -- date -u '+%Y-%m-%d %H:%M:%S')"
echo "setting fw0 clock to fw1 time: $FW1TIME"
incus exec "$R0" -- date -u -s "$FW1TIME" 2>&1 | tee -a "$EVID/cellf-clock.log"
sleep 2
echo "after: host=$(date -u +%FT%TZ) fw0=$(incus exec "$R0" -- date -u +%FT%TZ) fw1=$(incus exec "$R1" -- date -u +%FT%TZ)" | tee -a "$EVID/cellf-clock.log"

echo "=== 2. sanity: failover RG0 to node1 and back on healthy NEW2 pair ==="
incus exec "$R1" -- cli -c "request chassis cluster failover redundancy-group 0 node 1" 2>&1 | tail -2 | tee "$EVID/cellf-sanity.log"
sleep 8
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | grep -E "node1.*primary|Redundancy group: 0" | tee -a "$EVID/cellf-sanity.log" || true
deploy_reassert_primary_node0 "$R0" "$R1" 2>&1 | tail -1 | tee -a "$EVID/cellf-sanity.log"

echo "--- recorders ---"
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus exec "$LAN" -- bash -c "nohup ping -i 0.2 -D $TARGET > /tmp/9486f-ping.log 2>&1 & echo ping-started"
incus exec "$LAN" -- bash -c "nohup iperf3 -c $TARGET -t 1500 -P4 -i1 > /tmp/9486f-iperf.log 2>&1 & echo iperf-started"

echo "=== 3. failover all RGs to fw1 (both NEW2) ==="
for rg in 0 1 2; do
  incus exec "$R0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
  incus exec "$R1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
  incus exec "$R1" -- cli -c "request chassis cluster failover redundancy-group $rg node 1" 2>&1 | tail -1 || true
done
sleep 10
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/cellf-fw1primary.log" | grep -Ei "node[01]  |Redundancy" || die "fw1 primary not confirmed"

echo "=== 4. adjacent rollback fw1 (primary) NEW2 -> PREV ==="
SNAP="$VD/.$NEW2.dbsnap"
incus exec "$R1" -- ls "$SNAP/active.json" 2>&1 | tee "$EVID/cellf-snap.log"
incus exec "$R1" -- systemctl stop xpfd 2>&1 || true
incus exec "$R1" -- bash -c "rm -rf /etc/xpf/.configdb.restore.partial && cp -a $SNAP /etc/xpf/.configdb.restore.partial && rm -rf /etc/xpf/.configdb.old && mv /etc/xpf/.configdb /etc/xpf/.configdb.old && mv /etc/xpf/.configdb.restore.partial /etc/xpf/.configdb && ls /etc/xpf/.configdb" 2>&1 | tee "$EVID/cellf-dbrestore.log"
incus exec "$R1" -- bash -c "ln -sfn $PREV $VD/current && readlink $VD/current"
for b in xpfd cli xpf-userspace-dp; do
  incus exec "$R1" -- bash -c "ln -sfn $VD/current/$b /usr/local/sbin/$b"
done
incus exec "$R1" -- bash -c "cat > /etc/systemd/system/xpfd.service.d/10-xpf-version.conf <<EOF
# Managed by xpf-upgrade (#1917 increment B). Pins ExecStart to the
# concrete versioned binary so a helper respawn resolves the matching
# version's xpf-userspace-dp (systemd does not symlink-resolve argv[0]).
[Service]
ExecStartPre=
ExecStartPre=$VD/$PREV/xpfd verify-dataplane
ExecStart=
ExecStart=$VD/$PREV/xpfd
EOF"
incus exec "$R1" -- systemctl daemon-reload
incus exec "$R1" -- systemctl start xpfd
wait_active "$R1" 24 2>&1 | tee "$EVID/cellf-rb-boot.log" || die "rollback boot failed"
echo "ROLLBACK-BOOT-OK(2)"
sleep 8
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/cellf-rb-roles.log" | grep -Ei "node[01]  |Redundancy" || true

echo "=== 5. failover to node 1 with PREV running ==="
for rg in 0 1 2; do
  incus exec "$R0" -- cli -c "request chassis cluster failover redundancy-group $rg node 1" 2>&1 | tail -1 | tee "$EVID/cellf-failover.log" || true
done
sleep 12
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/cellf-prev-roles.log" | grep -Ei "node[01]  |Redundancy|Software version|Peer software" || echo "PREV-CLI-UNREACHABLE"
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | grep -Ei "sync|Sync|Transfer ready" | tee "$EVID/cellf-prev-sync.log" || true

if incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | grep -qE "node1 +100 +primary"; then
  echo "PREV-IS-PRIMARY — pinned iperf through rolled-back fw1"
  incus exec "$LAN" -- iperf3 -c "$TARGET" -t 30 -P4 2>&1 | tail -4 | tee "$EVID/cellf-prev-iperf.log"
  incus exec "$LAN" -- ping -c 5 -W 2 "$TARGET" 2>&1 | tail -3 | tee "$EVID/cellf-prev-ping.log"
  incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | grep -E "node1.*primary" | tee "$EVID/cellf-prev-during.log" || echo "ROLE-CHANGED-DURING-IPERF"
else
  echo "PREV-NOT-PRIMARY — recording as observed"
fi

echo "=== 6. re-cut fw1 forward to NEW2, failback, final ==="
incus exec "$R1" -- /usr/local/share/xpf/staged/xpfd upgrade --rolling 2>&1 | tee "$EVID/cellf-recut.log" | tail -8
incus exec "$R1" -- readlink /var/lib/xpf/versions/current | tee "$EVID/cellf-recut-current.log"
incus exec "$R1" -- systemctl is-active xpfd
deploy_reassert_primary_node0 "$R0" "$R1"
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/cellf-final-status.log" | grep -Ei "node[01]  |Redundancy|Failover count|Software version"
for n in 0 1; do
  r="loss:xpf-userspace-fw$n"
  echo "fw$n final: current=$(incus exec "$r" -- readlink /var/lib/xpf/versions/current) active=$(incus exec "$r" -- systemctl is-active xpfd) clock=$(incus exec "$r" -- date -u +%T)"
done | tee "$EVID/cellf-final-nodes.log"

echo "--- stopping recorders, pulling logs ---"
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus file pull "$LAN/tmp/9486f-ping.log" "$EVID/ping-cellf.log" 2>&1 || echo "no ping log"
incus file pull "$LAN/tmp/9486f-iperf.log" "$EVID/iperf-cellf.log" 2>&1 || echo "no iperf log"
wc -l "$EVID/ping-cellf.log" "$EVID/iperf-cellf.log" 2>&1 || true
echo "=== CELL-F COMPLETE ==="
