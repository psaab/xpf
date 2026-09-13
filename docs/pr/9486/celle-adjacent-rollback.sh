#!/usr/bin/env bash
# #9486 cell E — adjacent rollback NEW2→NEW15061 on fw1 (the REAL post-flip
# scenario): fw1 primary first, pinned iperf path through fw1, sync observed.
# Operator mirror of flip.go rollback(): stop -> restore PREFLIGHT snapshot
# (.<NEW2>.dbsnap) -> re-flip current/sbin/unit to NEW15061 -> start.
# Afterwards: failover to node 1 (expect success — envelope-consistent),
# pinned iperf, then re-cut forward to NEW2, failback, teardown.
set -euo pipefail
info() { echo "info: $*"; }
warn() { echo "warn: $*" >&2; }
die() { echo "die: $*" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
EVID="$ROOT/docs/pr/9486/evidence"
exec > >(tee -a "$EVID/celle.log") 2>&1

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

echo "=== CELL-E START $(date -u +%FT%TZ) ==="
NEW2="$(incus exec "$R1" -- readlink /var/lib/xpf/versions/current)"
PREV="$(incus exec "$R1" -- bash -c 'cur=$(readlink /var/lib/xpf/versions/current); ls -t /var/lib/xpf/versions/ | grep -v "^\." | grep -v "^current$" | grep -v "^$cur$" | head -1')"
echo "NEW2=$NEW2 PREV=$PREV"
[[ "$PREV" == *"15061"* ]] || die "PREV ($PREV) is not the expected NEW15061 slot — refusing to roll anywhere else"
SNAP="$VD/.$NEW2.dbsnap"
incus exec "$R1" -- ls -la "$SNAP" 2>&1 | tee "$EVID/celle-snap-list.log"
echo "--- slot listing fw1 ---"
incus exec "$R1" -- bash -c 'ls -la /var/lib/xpf/versions/' | tee "$EVID/celle-slots.log"

echo "--- recorders ---"
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus exec "$LAN" -- bash -c "nohup ping -i 0.2 -D $TARGET > /tmp/9486e-ping.log 2>&1 & echo ping-started"
incus exec "$LAN" -- bash -c "nohup iperf3 -c $TARGET -t 1500 -P4 -i1 > /tmp/9486e-iperf.log 2>&1 & echo iperf-started"

echo "=== failover all RGs to fw1 (both NEW2 healthy) ==="
for rg in 0 1 2; do
  incus exec "$R0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
  incus exec "$R1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
  incus exec "$R1" -- cli -c "request chassis cluster failover redundancy-group $rg node 1" 2>&1 | tail -1 || true
done
sleep 10
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/celle-fw1primary.log" | grep -Ei "node[01]  |Redundancy" || die "fw1 primary not confirmed"
echo "--- baseline pinned iperf on NEW2 fw1-primary ---"
incus exec "$LAN" -- iperf3 -c "$TARGET" -t 20 -P4 2>&1 | tail -3 | tee "$EVID/celle-newprimary-iperf.log"

echo "=== ADJACENT ROLLBACK fw1: $NEW2 -> $PREV (fw1 primary) ==="
echo "-- 1. stop"
incus exec "$R1" -- systemctl stop xpfd 2>&1 || true
echo "-- 2. restore PREFLIGHT snapshot"
incus exec "$R1" -- bash -c "rm -rf /etc/xpf/.configdb.restore.partial && cp -a $SNAP /etc/xpf/.configdb.restore.partial && rm -rf /etc/xpf/.configdb.old && mv /etc/xpf/.configdb /etc/xpf/.configdb.old && mv /etc/xpf/.configdb.restore.partial /etc/xpf/.configdb && ls -la /etc/xpf/.configdb" 2>&1 | tee "$EVID/celle-dbrestore.log"
echo "-- 3. re-flip current/sbin/unit to PREV"
incus exec "$R1" -- bash -c "ln -sfn $PREV $VD/current && readlink $VD/current"
for b in xpfd cli xpf-userspace-dp; do
  incus exec "$R1" -- bash -c "ln -sfn $VD/current/$b /usr/local/sbin/$b && readlink /usr/local/sbin/$b"
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
EOF
cat /etc/systemd/system/xpfd.service.d/10-xpf-version.conf"
incus exec "$R1" -- systemctl daemon-reload
echo "-- 4. start rolled-back daemon"
incus exec "$R1" -- systemctl start xpfd
if ! wait_active "$R1" 24 2>&1 | tee "$EVID/celle-rb-boot.log"; then
  echo "ROLLBACK-BOOT-FAILED"
  incus exec "$R1" -- journalctl -u xpfd --since "8 minutes ago" --no-pager 2>&1 | tail -6 | tee "$EVID/celle-rb-journal.log"
  die "adjacent rollback failed to boot — investigate before recovering"
fi
echo "ROLLBACK-BOOT-OK"
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/celle-rb-status.log" | grep -Ei "Software version|Peer software|HA protocol|node[01]  " || echo "RB-CLI-UNREACHABLE (timing?)"
sleep 8
echo "--- roles after rollback boot (fw0 should have taken over) ---"
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/celle-rb-roles.log" | grep -Ei "node[01]  |Redundancy" || true

echo "=== failover to node 1 with PREV running (expect success) ==="
for rg in 0 1 2; do
  incus exec "$R0" -- cli -c "request chassis cluster failover redundancy-group $rg node 1" 2>&1 | tail -1 || true
done
sleep 12
echo "--- roles from PREV view ---"
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/celle-prev-roles.log" | grep -Ei "node[01]  |Redundancy|Software version|Peer software" || echo "PREV-CLI-UNREACHABLE"
echo "--- sync state (observed) ---"
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | grep -Ei "sync|Sync|Transfer ready" | tee "$EVID/celle-prev-sync.log" || true
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | grep -Ei "sync|Sync|Transfer ready" | tee "$EVID/celle-prev-sync-fw0.log" || true

if incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | grep -qE "node1 +100 +primary"; then
  echo "PREV-IS-PRIMARY — pinned-path iperf through rolled-back fw1"
  incus exec "$LAN" -- iperf3 -c "$TARGET" -t 30 -P4 2>&1 | tail -4 | tee "$EVID/celle-prev-iperf.log"
  incus exec "$LAN" -- ping -c 5 -W 2 "$TARGET" 2>&1 | tail -3 | tee "$EVID/celle-prev-ping.log"
  incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | grep -E "node1.*primary" | tee "$EVID/celle-prev-roles-during.log" || echo "ROLE-CHANGED-DURING-IPERF"
else
  echo "PREV-NOT-PRIMARY — recording as observed (mixed-version refusal validated)"
fi

echo "=== re-cut fw1 forward to NEW2 ==="
incus exec "$R1" -- /usr/local/share/xpf/staged/xpfd upgrade --rolling 2>&1 | tee "$EVID/celle-recut.log" | tail -12
incus exec "$R1" -- readlink /var/lib/xpf/versions/current | tee "$EVID/celle-recut-current.log"
incus exec "$R1" -- systemctl is-active xpfd
echo "=== failback to node0, final state ==="
deploy_reassert_primary_node0 "$R0" "$R1"
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/celle-final-status.log" | grep -Ei "node[01]  |Redundancy|Failover count|Software version"
for n in 0 1; do
  r="loss:xpf-userspace-fw$n"
  echo "fw$n final: current=$(incus exec "$r" -- readlink /var/lib/xpf/versions/current) active=$(incus exec "$r" -- systemctl is-active xpfd)"
done | tee "$EVID/celle-final-nodes.log"

echo "--- stopping recorders, pulling logs ---"
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus file pull "$LAN/tmp/9486e-ping.log" "$EVID/ping-celle.log" 2>&1 || echo "no ping log"
incus file pull "$LAN/tmp/9486e-iperf.log" "$EVID/iperf-celle.log" 2>&1 || echo "no iperf log"
wc -l "$EVID/ping-celle.log" "$EVID/iperf-celle.log" 2>&1 || true
echo "=== CELL-E COMPLETE ==="
