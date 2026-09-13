#!/usr/bin/env bash
# #9486 validation part 3 — recover fw1 to NEW, then text-bootstrap rollback
# variant. Own with-cluster.sh cell. See evidence/ROLLBACK-ANALYSIS.md.
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

echo "=== PART3-A: recover fw1 to NEW ($NEWVER) ==="
incus exec "$R1" -- systemctl stop xpfd 2>&1 || true
incus exec "$R1" -- bash -c "ln -sfn $NEWVER $VD/current && readlink $VD/current"
for b in xpfd cli xpf-userspace-dp; do
  incus exec "$R1" -- bash -c "ln -sfn $VD/current/$b /usr/local/sbin/$b"
done
incus exec "$R1" -- bash -c "cat > /etc/systemd/system/xpfd.service.d/10-xpf-version.conf <<EOF
# Managed by xpf-upgrade (#1917 increment B). Pins ExecStart to the
# concrete versioned binary so a helper respawn resolves the matching
# version's xpf-userspace-dp (systemd does not symlink-resolve argv[0]).
[Service]
ExecStartPre=
ExecStartPre=$VD/$NEWVER/xpfd verify-dataplane
ExecStart=
ExecStart=$VD/$NEWVER/xpfd
EOF"
incus exec "$R1" -- systemctl daemon-reload
incus exec "$R1" -- systemctl start xpfd
wait_active "$R1" 24 2>&1 | tee "$EVID/recover-boot.log"
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/recover-status.log" | grep -Ei "Software version|node[01]  " || echo "CLI-UNREACHABLE (see log)"
incus exec "$R1" -- journalctl -u xpfd --since "6 minutes ago" --no-pager 2>&1 | grep -Ei "refusing|FAIL|error" | head -5 || echo "no errors in journal"

echo "=== PART3-B: text-bootstrap rollback variant (DB removed, boot from xpf.conf) ==="
incus exec "$R1" -- systemctl stop xpfd 2>&1 || true
incus exec "$R1" -- bash -c "mv /etc/xpf/.configdb /etc/xpf/.configdb.new-saved && ls /etc/xpf/xpf.conf"
incus exec "$R1" -- bash -c "ln -sfn $OLD1 $VD/current && readlink $VD/current"
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
if wait_active "$R1" 24 2>&1 | tee "$EVID/textboot-boot.log"; then
  echo "TEXT-BOOT-OK"
  incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/textboot-status.log" | grep -Ei "Software version|node[01]  " || echo "CLI-UNREACHABLE (see log)"
  echo "-- forwards on OLD binary? --"
  incus exec "$LAN" -- ping -c 5 -W 2 "$TARGET" 2>&1 | tail -3 | tee "$EVID/textboot-ping.log"
  incus exec "$LAN" -- iperf3 -c "$TARGET" -t 15 -P4 2>&1 | tail -4 | tee "$EVID/textboot-iperf.log"
else
  echo "TEXT-BOOT-FAILED (see journal)"
  incus exec "$R1" -- journalctl -u xpfd --since "6 minutes ago" --no-pager 2>&1 | tail -8 | tee "$EVID/textboot-journal.log"
fi

echo "=== PART3-C: re-flip fw1 to NEW, restore saved DB ==="
incus exec "$R1" -- systemctl stop xpfd 2>&1 || true
incus exec "$R1" -- bash -c "rm -rf /etc/xpf/.configdb && mv /etc/xpf/.configdb.new-saved /etc/xpf/.configdb && ls -la /etc/xpf/.configdb"
incus exec "$R1" -- bash -c "ln -sfn $NEWVER $VD/current && readlink $VD/current"
incus exec "$R1" -- bash -c "cat > /etc/systemd/system/xpfd.service.d/10-xpf-version.conf <<EOF
# Managed by xpf-upgrade (#1917 increment B). Pins ExecStart to the
# concrete versioned binary so a helper respawn resolves the matching
# version's xpf-userspace-dp (systemd does not symlink-resolve argv[0]).
[Service]
ExecStartPre=
ExecStartPre=$VD/$NEWVER/xpfd verify-dataplane
ExecStart=
ExecStart=$VD/$NEWVER/xpfd
EOF"
incus exec "$R1" -- systemctl daemon-reload
incus exec "$R1" -- systemctl start xpfd
wait_active "$R1" 24 2>&1 | tee "$EVID/finalrecut-boot.log"
incus exec "$R1" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/final-status-fw1.log" | grep -Ei "Software version|node[01]  " || echo "CLI-UNREACHABLE (see log)"

echo "=== reassert node0 primary, final state ==="
deploy_reassert_primary_node0 "$R0" "$R1"
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/final-status.log" | grep -Ei "node[01]  |Redundancy|Failover count|Software version"
for n in 0 1; do
  r="loss:xpf-userspace-fw$n"
  echo "--- fw$n final: current=$(incus exec "$r" -- readlink /var/lib/xpf/versions/current) active=$(incus exec "$r" -- systemctl is-active xpfd) dpkg=$(incus exec "$r" -- dpkg-query -W -f='${Version}' xpf)"
done | tee "$EVID/final-nodes.log"

echo "=== stopping recorders, pulling logs ==="
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus file pull "$LAN/tmp/9486-ping.log" "$EVID/ping.log" 2>&1 || echo "no ping.log"
incus file pull "$LAN/tmp/9486-iperf.log" "$EVID/iperf.log" 2>&1 || echo "no iperf.log"
wc -l "$EVID/ping.log" "$EVID/iperf.log" 2>&1 || true
echo "=== PART 3 COMPLETE ==="
