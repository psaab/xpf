#!/usr/bin/env bash
# #9486 item 4b — run the REAL default entry point once under the cell lock:
# literal `make cluster-deploy` (no XPF_* overrides), proving the flipped
# recipe itself works end to end. Records everything to evidence/.
set -euo pipefail
info() { echo "info: $*"; }
warn() { echo "warn: $*" >&2; }
die() { echo "die: $*" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
EVID="$ROOT/docs/pr/9486/evidence"
exec > >(tee -a "$EVID/deploy-default.log") 2>&1

R0="loss:xpf-userspace-fw0"
R1="loss:xpf-userspace-fw1"
LAN="loss:cluster-userspace-host"
TARGET="172.16.80.200"

echo "=== ITEM-4b REAL DEFAULT ENTRY POINT $(date -u +%FT%TZ) ==="
echo "env: XPF_DEPLOY_FAST=[${XPF_DEPLOY_FAST:-unset}] XPF_DEPLOY_DEB=[${XPF_DEPLOY_DEB:-unset}]"
[[ -z "${XPF_DEPLOY_FAST:-}" && -z "${XPF_DEPLOY_DEB:-}" ]] || die "must run with default env"
for n in 0 1; do
  r="loss:xpf-userspace-fw$n"
  echo "--- fw$n pre: dpkg=$(incus exec "$r" -- dpkg-query -W -f='${Version}' xpf) current=$(incus exec "$r" -- readlink /var/lib/xpf/versions/current) active=$(incus exec "$r" -- systemctl is-active xpfd)"
done
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | grep -Ei "Software version|node[01]  |Failover count" | tee "$EVID/deploy-default-prestatus.log"

echo "--- starting recorders ---"
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus exec "$LAN" -- bash -c "nohup ping -i 0.2 -D $TARGET > /tmp/9486b-ping.log 2>&1 & echo ping-started"
incus exec "$LAN" -- bash -c "nohup iperf3 -c $TARGET -t 1200 -P4 -i1 > /tmp/9486b-iperf.log 2>&1 & echo iperf-started"

echo "--- make cluster-deploy (REAL default recipe) ---"
export GOCACHE=/dev/shm/gocache-9486 GOTMPDIR=/dev/shm
make cluster-deploy 2>&1 | tail -40
RC="${PIPESTATUS[0]}"
echo "MAKE-RC=$RC"
[[ "$RC" == "0" ]] || die "make cluster-deploy failed (rc=$RC)"
echo "--- post state ---"
for n in 0 1; do
  r="loss:xpf-userspace-fw$n"
  echo "--- fw$n post: dpkg=$(incus exec "$r" -- dpkg-query -W -f='${Version}' xpf) current=$(incus exec "$r" -- readlink /var/lib/xpf/versions/current) active=$(incus exec "$r" -- systemctl is-active xpfd)"
  incus exec "$r" -- bash -c 'ls /var/lib/xpf/versions/ | tr "\n" " "; echo; cat /var/lib/xpf/versions/$(readlink /var/lib/xpf/versions/current)/.srcgen'
done
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/deploy-default-poststatus.log" | grep -Ei "Software version|node[01]  |Failover count"

echo "--- stopping recorders, pulling logs ---"
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus file pull "$LAN/tmp/9486b-ping.log" "$EVID/ping-default.log" 2>&1 || echo "no ping log"
incus file pull "$LAN/tmp/9486b-iperf.log" "$EVID/iperf-default.log" 2>&1 || echo "no iperf log"
echo "zero-transfer SUM seconds:"
grep -cE "\[SUM\].* 0\.00 bits/sec" "$EVID/iperf-default.log" || true
grep -Ei "reset|error|failed" "$EVID/iperf-default.log" | head -5 || echo "CLEAN-NO-RESETS"
echo "=== ITEM-4b COMPLETE ==="
