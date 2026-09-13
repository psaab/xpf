#!/usr/bin/env bash
# #9486 cell D — item 6 retry: pin AFTER June boots (the DB removal in cell C
# cleared the manual-primary pin, so June booted secondary). Failover to
# node 1 with June already running, verify June primary, then pinned iperf.
set -euo pipefail
info() { echo "info: $*"; }
warn() { echo "warn: $*" >&2; }
die() { echo "die: $*" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
EVID="$ROOT/docs/pr/9486/evidence"
exec > >(tee -a "$EVID/celld.log") 2>&1

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

echo "=== CELL-D START $(date -u +%FT%TZ) ==="
OLD1="$(grep '^OLD1=' "$EVID/oldver.env" | cut -d= -f2)"
NEW2="$(incus exec "$R1" -- readlink /var/lib/xpf/versions/current)"
echo "OLD1=$OLD1 NEW2=$NEW2"

echo "=== June text-boot on fw1 (currently secondary) ==="
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
wait_active "$R1" 24 2>&1 | tee "$EVID/celld-june-boot.log" || die "June boot failed"
sleep 10
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | grep -Ei "Software version|HA protocol" | tee "$EVID/celld-june-ver.log" || true

echo "=== failover to node 1 AFTER June is running (pin in June's DB) ==="
for rg in 0 1 2; do
  incus exec "$R0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
  incus exec "$R1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" >/dev/null 2>&1 || true
  incus exec "$R0" -- cli -c "request chassis cluster failover redundancy-group $rg node 1" 2>&1 | tail -1 || true
done
sleep 12
echo "--- roles from June's view ---"
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/celld-june-roles.log" | grep -Ei "node[01]  |Redundancy" || echo "JUNE-CLI-UNREACHABLE"
echo "--- roles from fw0's view ---"
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/celld-fw0-roles.log" | grep -Ei "node[01]  |Redundancy" || echo "FW0-CLI-UNREACHABLE"

if incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | grep -qE "node1 +100 +primary"; then
  echo "JUNE-IS-PRIMARY — pinned-path iperf through June now"
  incus exec "$LAN" -- iperf3 -c "$TARGET" -t 30 -P4 2>&1 | tail -4 | tee "$EVID/celld-june-iperf.log"
  incus exec "$LAN" -- ping -c 5 -W 2 "$TARGET" 2>&1 | tail -3 | tee "$EVID/celld-june-ping.log"
  incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | grep -E "node1.*primary" | tee "$EVID/celld-june-roles-during.log" || echo "ROLE-CHANGED-DURING-IPERF"
else
  echo "JUNE-NOT-PRIMARY (failover refused or unconfirmed — see roles logs); recording as observed"
  incus exec "$R1" -- journalctl -u xpfd --since "6 minutes ago" --no-pager 2>&1 | grep -Ei "failover|demot|promot|primary" | tail -8 | tee "$EVID/celld-june-failover.log" || true
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
wait_active "$R1" 24 2>&1 | tee "$EVID/celld-recover-boot.log"
deploy_reassert_primary_node0 "$R0" "$R1"
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/celld-final-status.log" | grep -Ei "node[01]  |Redundancy|Failover count|Software version"
for n in 0 1; do
  r="loss:xpf-userspace-fw$n"
  echo "fw$n final: current=$(incus exec "$r" -- readlink /var/lib/xpf/versions/current) active=$(incus exec "$r" -- systemctl is-active xpfd)"
done | tee "$EVID/celld-final-nodes.log"
echo "=== CELL-D COMPLETE ==="
