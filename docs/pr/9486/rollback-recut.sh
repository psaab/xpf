#!/usr/bin/env bash
# #9486 validation driver part 2 — operator rollback of fw1 + re-cut forward.
# Run in its own with-cluster.sh cell AFTER part 1 verified BOTH cuts.
# Mirrors pkg/upgrade flip.go rollback() steps 1-4 manually (HA rollback is
# operator-driven; no `xpfd upgrade --rollback` verb exists — see #9486):
#   1. stop new daemon  2. restore config DB from PREFLIGHT snapshot
#   3. re-flip current/sbin/unit to previous  4. start old daemon.
set -euo pipefail
info() { echo "info: $*"; }
warn() { echo "warn: $*" >&2; }
die() { echo "die: $*" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EVID="$ROOT/docs/pr/9486/evidence"
exec > >(tee -a "$EVID/run.log") 2>&1

# shellcheck source=test/incus/deploy-lib.sh
source "$ROOT/test/incus/deploy-lib.sh"

OLD1="$(grep '^OLD1=' "$EVID/oldver.env" | cut -d= -f2)"
NEWVER="$(grep '^NEWVER=' "$EVID/newver.env" | cut -d= -f2)"

R1="loss:xpf-userspace-fw1"
LAN="loss:cluster-userspace-host"
TARGET="172.16.80.200"
echo "=== confirm node0 primary before rolling back fw1 (secondary) ==="
deploy_reassert_primary_node0 "loss:xpf-userspace-fw0" "$R1"
echo "=== ROLLBACK fw1: NEW=$NEWVER -> OLD=$OLD1 ==="

SNAP="/var/lib/xpf/versions/.$NEWVER.dbsnap"
echo "-- snapshot present? --"
incus exec "$R1" -- ls -la "$SNAP" 2>&1 | tee "$EVID/rollback-snap-list.log"
echo "-- live DB before --"
incus exec "$R1" -- ls -la /etc/xpf/.configdb 2>&1 | tee "$EVID/rollback-livedb-before.log"

echo "-- 1. stop new daemon"
incus exec "$R1" -- systemctl stop xpfd
incus exec "$R1" -- systemctl is-active xpfd 2>&1 || echo "(stopped as intended)"

echo "-- 2. restore config DB from PREFLIGHT snapshot (swap dance mirrors restoreDBSnapshot)"
incus exec "$R1" -- bash -c "rm -rf /etc/xpf/.configdb.restore.partial && cp -a $SNAP /etc/xpf/.configdb.restore.partial && rm -rf /etc/xpf/.configdb.old && mv /etc/xpf/.configdb /etc/xpf/.configdb.old && mv /etc/xpf/.configdb.restore.partial /etc/xpf/.configdb && ls -la /etc/xpf/.configdb" 2>&1 | tee "$EVID/rollback-dbrestore.log"

echo "-- 3. re-flip current/sbin/unit to $OLD1"
VD="/var/lib/xpf/versions"
incus exec "$R1" -- bash -c "ln -sfn $OLD1 $VD/current && readlink $VD/current"
for b in xpfd cli xpf-userspace-dp; do
  incus exec "$R1" -- bash -c "ln -sfn $VD/current/$b /usr/local/sbin/$b && readlink /usr/local/sbin/$b"
done
incus exec "$R1" -- bash -c "cat > /etc/systemd/system/xpfd.service.d/10-xpf-version.conf <<EOF
# Managed by xpf-upgrade (#1917 increment B). Pins ExecStart to the
# concrete versioned binary so a helper respawn resolves the matching
# version's xpf-userspace-dp (systemd does not symlink-resolve argv[0]).
[Service]
ExecStartPre=
ExecStartPre=$VD/$OLD1/xpfd verify-dataplane
ExecStart=
ExecStart=$VD/$OLD1/xpfd
EOF
cat /etc/systemd/system/xpfd.service.d/10-xpf-version.conf"
incus exec "$R1" -- systemctl daemon-reload

echo "-- 4. start old daemon"
incus exec "$R1" -- systemctl start xpfd
sleep 8
incus exec "$R1" -- systemctl is-active xpfd 2>&1 | tee "$EVID/rollback-boot.log"
echo "-- rolled-back version --"
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/rollback-status.log" | grep -Ei "Software version|node[01] "
echo "-- forwards after rollback? --"
incus exec "$LAN" -- ping -c 5 -W 2 "$TARGET" 2>&1 | tail -3 | tee "$EVID/rollback-ping.log"
incus exec "$LAN" -- iperf3 -c "$TARGET" -t 15 -P4 2>&1 | tail -4 | tee "$EVID/rollback-iperf.log"

echo "=== RE-CUT fw1 forward to $NEWVER ==="
incus exec "$R1" -- /usr/local/share/xpf/staged/xpfd upgrade --rolling 2>&1 | tee "$EVID/recut-fw1.log" | tail -12
echo "-- verify --"
incus exec "$R1" -- readlink /var/lib/xpf/versions/current | tee "$EVID/recut-current.log"
incus exec "$R1" -- systemctl is-active xpfd
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/recut-status.log" | grep -Ei "Software version|node[01] "

echo "=== reassert node0 primary ==="
deploy_reassert_primary_node0 "loss:xpf-userspace-fw0" "$R1"
incus exec "loss:xpf-userspace-fw0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/final-status.log" | grep -Ei "node[01]|Redundancy|Failover count|Software version"

echo "=== stopping recorders, pulling logs ==="
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus file pull "$LAN/tmp/9486-ping.log" "$EVID/ping.log" 2>&1 || echo "no ping.log"
incus file pull "$LAN/tmp/9486-iperf.log" "$EVID/iperf.log" 2>&1 || echo "no iperf.log"
wc -l "$EVID/ping.log" "$EVID/iperf.log" 2>&1 || true
echo "=== PART 2 COMPLETE ==="
