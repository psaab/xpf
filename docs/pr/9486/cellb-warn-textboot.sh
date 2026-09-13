#!/usr/bin/env bash
# #9486 cell B — (i) XPF_DEPLOY_DEB=0 warn + same-tree guard evidence,
# (ii) item-6 text-boot variant with fw1 PRIMARY and pinned iperf path.
set -euo pipefail
info() { echo "info: $*"; }
warn() { echo "warn: $*" >&2; }
die() { echo "die: $*" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
EVID="$ROOT/docs/pr/9486/evidence"
exec > >(tee -a "$EVID/cellb.log") 2>&1

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
rg_roles() { # <label>
  incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/$1.log" | grep -Ei "node[01]  |Redundancy|Software version|Peer software|sync" || true
}

echo "=== CELL-B START $(date -u +%FT%TZ) ==="
OLD1="$(grep '^OLD1=' "$EVID/oldver.env" | cut -d= -f2)"
NEW2="$(incus exec "$R1" -- readlink /var/lib/xpf/versions/current)"
echo "OLD1=$OLD1 NEW2=$NEW2"

echo "--- recorders ---"
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus exec "$LAN" -- bash -c "nohup ping -i 0.2 -D $TARGET > /tmp/9486c-ping.log 2>&1 & echo ping-started"
incus exec "$LAN" -- bash -c "nohup iperf3 -c $TARGET -t 1500 -P4 -i1 > /tmp/9486c-iperf.log 2>&1 & echo iperf-started"

echo "=== (i) XPF_DEPLOY_DEB=0 full entry (expect WARN + guard behaviour) ==="
export GOCACHE=/dev/shm/gocache-9486 GOTMPDIR=/dev/shm
XPF_DEPLOY_DEB=0 make cluster-deploy > "$EVID/deploy-deb0.log" 2>&1; RC=$?
echo "DEB0-RC=$RC"
grep -c "XPF_DEPLOY_DEB=0 is deprecated" "$EVID/deploy-deb0.log" || echo "WARN-LINE-ABSENT"
grep -Ei "refuse|Refuse|already committed|nothing to do" "$EVID/deploy-deb0.log" | head -6 || echo "NO-REFUSE-LINE"
echo "--- versions after DEB=0 run (expect unchanged $NEW2) ---"
for n in 0 1; do
  r="loss:xpf-userspace-fw$n"
  echo "fw$n: current=$(incus exec "$r" -- readlink /var/lib/xpf/versions/current) active=$(incus exec "$r" -- systemctl is-active xpfd)"
done | tee "$EVID/deb0-postver.log"

echo "=== (ii) ITEM-6: failover all RGs to fw1 ==="
for rg in 0 1 2; do
  incus exec "$R0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
  incus exec "$R1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
  incus exec "$R1" -- cli -c "request chassis cluster failover redundancy-group $rg node 1" 2>&1 | tail -2 || true
done
sleep 10
rg_roles "cellb-fw1primary"
echo "--- pinned-path iperf on NEW fw1-primary (baseline for June window) ---"
incus exec "$LAN" -- iperf3 -c "$TARGET" -t 20 -P4 2>&1 | tail -3 | tee "$EVID/cellb-newprimary-iperf.log"

echo "=== (ii) text-boot June on fw1-PRIMARY ==="
incus exec "$R1" -- systemctl stop xpfd 2>&1 || true
incus exec "$R1" -- bash -c "rm -rf /etc/xpf/.configdb.new2-saved && mv /etc/xpf/.configdb /etc/xpf/.configdb.new2-saved && ls /etc/xpf/xpf.conf"
incus exec "$R1" -- bash -c "ln -sfn $OLD1 $VD/current && readlink $VD/current"
for b in xpfd cli xpf-userspace-dp; do
  incus exec "$R1" -- bash -c "ln -sfn $VD/current/$b /usr/local/sbin/$b"
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
EOF"
incus exec "$R1" -- systemctl daemon-reload
incus exec "$R1" -- systemctl start xpfd
if wait_active "$R1" 24 2>&1 | tee "$EVID/cellb-june-boot.log"; then
  echo "JUNE-PRIMARY-BOOT-OK"
  sleep 10
  echo "--- RG roles + versions + sync during June window (observed, not required) ---"
  incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/cellb-june-status.log" | head -40 || echo "JUNE-CLI-UNREACHABLE"
  echo "--- pinned-path proof: iperf traverses fw1 (primary all RGs) ---"
  incus exec "$LAN" -- iperf3 -c "$TARGET" -t 30 -P4 2>&1 | tail -4 | tee "$EVID/cellb-june-iperf.log"
  incus exec "$LAN" -- ping -c 5 -W 2 "$TARGET" 2>&1 | tail -3 | tee "$EVID/cellb-june-ping.log"
  echo "--- fw0 view during June window ---"
  incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/cellb-june-fw0view.log" | grep -Ei "node[01]  |Software version|Peer software|sync|Sync" || true
else
  echo "JUNE-PRIMARY-BOOT-FAILED"
  incus exec "$R1" -- journalctl -u xpfd --since "8 minutes ago" --no-pager 2>&1 | tail -6 | tee "$EVID/cellb-june-journal.log"
fi

echo "=== recover fw1 to NEW2, restore DB, failback ==="
incus exec "$R1" -- systemctl stop xpfd 2>&1 || true
incus exec "$R1" -- bash -c "rm -rf /etc/xpf/.configdb && mv /etc/xpf/.configdb.new2-saved /etc/xpf/.configdb && ls /etc/xpf/.configdb"
incus exec "$R1" -- bash -c "ln -sfn $NEW2 $VD/current && readlink $VD/current"
incus exec "$R1" -- bash -c "cat > /etc/systemd/system/xpfd.service.d/10-xpf-version.conf <<EOF
# Managed by xpf-upgrade (#1917 increment B). Pins ExecStart to the
# concrete versioned binary so a helper respawn resolves the matching
# version's xpf-userspace-dp (systemd does not symlink-resolve argv[0]).
[Service]
ExecStartPre=
ExecStartPre=$VD/$NEW2/xpfd verify-dataplane
ExecStart=
ExecStart=$VD/$NEW2/xpfd
EOF"
incus exec "$R1" -- systemctl daemon-reload
incus exec "$R1" -- systemctl start xpfd
wait_active "$R1" 24 2>&1 | tee "$EVID/cellb-recover-boot.log"
deploy_reassert_primary_node0 "$R0" "$R1"
rg_roles "cellb-final"
for n in 0 1; do
  r="loss:xpf-userspace-fw$n"
  echo "fw$n final: current=$(incus exec "$r" -- readlink /var/lib/xpf/versions/current) active=$(incus exec "$r" -- systemctl is-active xpfd) dpkg=$(incus exec "$r" -- dpkg-query -W -f='${Version}' xpf)"
done | tee "$EVID/cellb-final-nodes.log"

echo "--- stopping recorders, pulling logs ---"
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus file pull "$LAN/tmp/9486c-ping.log" "$EVID/ping-cellb.log" 2>&1 || echo "no ping log"
incus file pull "$LAN/tmp/9486c-iperf.log" "$EVID/iperf-cellb.log" 2>&1 || echo "no iperf log"
wc -l "$EVID/ping-cellb.log" "$EVID/iperf-cellb.log" 2>&1 || true
echo "=== CELL-B COMPLETE ==="
