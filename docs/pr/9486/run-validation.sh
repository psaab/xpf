#!/usr/bin/env bash
# #9486 validation driver — deb deploy on loss userspace cluster.
# Runs INSIDE one with-cluster.sh cell (caller holds the #1875 lock).
# Mirrors deploy_vm_deb command-for-command (push -> apt install ->
# staged `xpfd upgrade --rolling`), split so the postinst stage-only
# assert (criterion 3) can observe the window between install and cut.
set -euo pipefail
# deploy-lib.sh expects the cluster-setup.sh logging helpers; define minimal
# stand-ins when sourced standalone (fixes `info: command not found` in
# deploy_reassert_primary_node0).
info() { echo "info: $*"; }
warn() { echo "warn: $*" >&2; }
die() { echo "die: $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EVID="$ROOT/docs/pr/9486/evidence"
mkdir -p "$EVID"
LOG="$EVID/run.log"
exec > >(tee -a "$LOG") 2>&1

# shellcheck source=test/incus/deploy-lib.sh
source "$ROOT/test/incus/deploy-lib.sh"

DEB="$(ls -t "$ROOT"/dist-deb/xpf_*.deb 2>/dev/null | grep -v appliance | head -1)"
[[ -n "$DEB" ]] || { echo "FATAL: no xpf_*.deb in dist-deb/"; exit 1; }
DEB_BASE="$(basename "$DEB")"
R0="loss:xpf-userspace-fw0"
R1="loss:xpf-userspace-fw1"
LAN="loss:cluster-userspace-host"
TARGET="172.16.80.200"

echo "=== #9486 validation run $(date -u +%FT%TZ) deb=$DEB_BASE ==="

node_state() { # <rinst> <label>
  local r="$1" label="$2"
  local f="$EVID/${label}.log"
  {
    echo "--- $label $(date -u +%FT%TZ) ---"
    echo "dpkg: $(incus exec "$r" -- dpkg-query -W -f='${Version}' xpf 2>&1)"
    echo "current: $(incus exec "$r" -- readlink /var/lib/xpf/versions/current 2>&1)"
    echo "versions: $(incus exec "$r" -- ls /var/lib/xpf/versions/ 2>&1 | tr '\n' ' ')"
    echo "srcgen-NEW: [see post-cut]"
    echo "xpfd-pid: $(incus exec "$r" -- systemctl show xpfd -p MainPID 2>&1)"
    echo "sbin-xpfd: $(incus exec "$r" -- bash -c 'if [ -L /usr/local/sbin/xpfd ]; then echo LINK-$(readlink /usr/local/sbin/xpfd); else echo REAL-$(sha256sum /usr/local/sbin/xpfd | cut -c1-16); fi' 2>&1)"
    echo "dropin: $(incus exec "$r" -- bash -c 'cat /etc/systemd/system/xpfd.service.d/10-xpf-version.conf 2>/dev/null | grep ExecStart= | head -2 || echo ABSENT' 2>&1)"
    echo "staged-gen: $(incus exec "$r" -- bash -c 'readlink /var/lib/xpf/staged-gen/current-gen 2>&1; ls /var/lib/xpf/staged-gen/ 2>&1 | tr "\n" " "' 2>&1)"
  } | tee "$f"
}

# ---- A. pre-state ----
node_state "$R0" "pre-fw0"
node_state "$R1" "pre-fw1"
echo "--- cluster pre ---"
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/pre-status.log" | grep -Ei "node[01]|Redundancy|Failover count|Software version"

# ---- B. one-time torn-layout repair: recreate missing `current` ----
# Raw pushes replaced sbin links with real files and `current` is absent
# (nothing in upgrade code removes it; raw reconcile only drops DANGLING
# sbin links). Without a restorable previous the cut refuse-before-STOPs.
# Repair = point `current` at the newest surviving version dir; the cut
# still validates its restorability (lockstep+ELF) before any STOP.
for n in 0 1; do
  r="loss:xpf-userspace-fw$n"
  oldest_newest="$(incus exec "$r" -- bash -c 'ls -t /var/lib/xpf/versions/ | grep -v "^\." | head -1')"
  echo "fw$n: repair current -> $oldest_newest"
  incus exec "$r" -- bash -c "ls -la /var/lib/xpf/versions/$oldest_newest/xpfd /var/lib/xpf/versions/$oldest_newest/xpf-userspace-dp"
  incus exec "$r" -- ln -sfn "$oldest_newest" /var/lib/xpf/versions/current
  incus exec "$r" -- readlink /var/lib/xpf/versions/current
  if [ "$n" = "0" ]; then OLD0="$oldest_newest"; else OLD1="$oldest_newest"; fi
done
{ echo "OLD0=$OLD0"; echo "OLD1=$OLD1"; } | tee "$EVID/oldver.env"

# ---- C. recorders (background; killed in step J) ----
incus exec "$LAN" -- pkill -9 -f "ping.*$TARGET" 2>/dev/null || true
incus exec "$LAN" -- pkill -9 -f "iperf3.*$TARGET" 2>/dev/null || true
sleep 1
incus exec "$LAN" -- bash -c "nohup ping -i 0.2 -D $TARGET > /tmp/9486-ping.log 2>&1 & echo started"
incus exec "$LAN" -- bash -c "nohup iperf3 -c $TARGET -t 1500 -P4 -i1 > /tmp/9486-iperf.log 2>&1 & echo started"

deploy_one() { # <idx> <rinst> <oldver>
  local idx="$1" r="$2" old="$3"
  echo "===== deploying node$idx ($r) ====="
  local pid_before
  pid_before="$(incus exec "$r" -- systemctl show xpfd -p MainPID | cut -d= -f2)"
  echo "-- push deb"
  incus file push "$DEB" "$r/tmp/$DEB_BASE"
  echo "-- apt install (STAGE-ONLY expected)"
  incus exec "$r" -- apt-get install -y --reinstall "/tmp/$DEB_BASE" 2>&1 | tee "$EVID/apt-fw$idx.log" | tail -8
  echo "-- stage-only asserts"
  local pid_after cur_after sbin_after
  pid_after="$(incus exec "$r" -- systemctl show xpfd -p MainPID | cut -d= -f2)"
  cur_after="$(incus exec "$r" -- readlink /var/lib/xpf/versions/current)"
  sbin_after="$(incus exec "$r" -- bash -c 'if [ -L /usr/local/sbin/xpfd ]; then echo LINK; else echo REAL; fi')"
  echo "pid-after=$pid_after current-after=$cur_after sbin=$sbin_after"
  [[ "$pid_before" == "$pid_after" ]] || { echo "FAIL: xpfd pid changed across apt install ($pid_before -> $pid_after)"; return 1; }
  [[ "$cur_after" == "$old" ]] || { echo "FAIL: current moved across apt install ($cur_after != $old)"; return 1; }
  grep -q "staged only" "$EVID/apt-fw$idx.log" || { echo "FAIL: postinst did not report stage-only"; return 1; }
  echo "STAGE-ONLY-OK node$idx (pid $pid_after unchanged, current still $old)"
  # forwarding alive pre-cut?
  incus exec "$LAN" -- ping -c 3 -W 2 "$TARGET" 2>&1 | tail -2
  echo "-- cut via staged rolling driver"
  incus exec "$r" -- /usr/local/share/xpf/staged/xpfd upgrade --rolling 2>&1 | tee "$EVID/cut-fw$idx.log" | tail -15
  echo "-- post-cut verify"
  local cur_new ver_new
  cur_new="$(incus exec "$r" -- readlink /var/lib/xpf/versions/current)"
  echo "current-now=$cur_new (old was $old)"
  [[ "$cur_new" != "$old" ]] || { echo "FAIL: current did not advance"; return 1; }
  NEWVER="$cur_new"
  echo "NEWVER=$NEWVER" | tee "$EVID/newver.env"
  incus exec "$r" -- bash -c 'ls /var/lib/xpf/versions/$0/.srcgen && cat /var/lib/xpf/versions/$0/.srcgen' "$cur_new"
  incus exec "$r" -- systemctl is-active xpfd
  incus exec "$r" -- cli -c "show chassis cluster status" 2>&1 | grep -Ei "Software version|node[01] "
}

# ---- D/E. secondary first (node1 is secondary-hold), then primary ----
deploy_one 1 "$R1" "$OLD1"
sleep 5
deploy_one 0 "$R0" "$OLD0"

# ---- F. reassert node0 primary ----
deploy_reassert_primary_node0 "$R0" "$R1"
node_state "$R0" "postcut-fw0"
node_state "$R1" "postcut-fw1"
incus exec "$R0" -- cli -c "show chassis cluster status" 2>&1 | tee "$EVID/postcut-status.log" | grep -Ei "node[01]|Redundancy|Failover count|Software version"

echo "=== FORWARD CUT COMPLETE; proceeding to rollback fw1 ==="
