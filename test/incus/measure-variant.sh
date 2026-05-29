#!/usr/bin/env bash
# #1630 §3.6 throwaway measurement driver. Build xpf-userspace-dp with a
# given K (XPF_COS_K) and P2 (XPF_COS_P2) baked at compile time, push the
# helper to both loss userspace cluster nodes, restart xpfd, settle, and
# run the Gate 1 small-four-alone harness (push v4).
#
# Usage: measure-variant.sh <K> <P2:0|1> [label]
set -euo pipefail
K="${1:?K required}"
P2="${2:?P2 required}"
LABEL="${3:-K${K}_P2${P2}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "=== [$LABEL] build XPF_COS_K=$K XPF_COS_P2=$P2 ==="
# option_env! is not tracked by cargo without a build script, so touch the
# two probe source files to force recompilation of the affected crate
# units when only the env changed.
touch userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs \
      userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs \
      userspace-dp/src/afxdp/cos/queue_service/mod.rs
( cd userspace-dp && XPF_COS_K="$K" XPF_COS_P2="$P2" \
    cargo build --release 2>&1 | tail -2 )
install -m 0755 userspace-dp/target/release/xpf-userspace-dp ./xpf-userspace-dp
ls -la ./xpf-userspace-dp

for vm in xpf-userspace-fw0 xpf-userspace-fw1; do
  echo "=== [$LABEL] stop xpfd + kill helper + push to $vm ==="
  sg incus-admin -c "incus exec loss:$vm -- systemctl stop xpfd" 2>/dev/null || true
  sg incus-admin -c "incus exec loss:$vm -- pkill -9 xpf-userspace-dp" 2>/dev/null || true
  sleep 1
  sg incus-admin -c "incus file push ./xpf-userspace-dp loss:$vm/usr/local/sbin/xpf-userspace-dp --mode 0755 --quiet" 2>/dev/null || \
    sg incus-admin -c "incus file push ./xpf-userspace-dp loss:$vm/usr/local/sbin/xpf-userspace-dp --mode 0755" >/dev/null 2>&1
done
# Start secondary first then primary to keep RG0 mastership stable on fw0.
for vm in xpf-userspace-fw1 xpf-userspace-fw0; do
  sg incus-admin -c "incus exec loss:$vm -- systemctl start xpfd"
done

echo "=== [$LABEL] settle 25s ==="
for i in $(seq 1 25); do sleep 1; done

echo "=== [$LABEL] verify CoS still applied + oversubscription-policy ==="
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- bash -lc 'cli -c \"show configuration class-of-service\" 2>/dev/null | grep -i oversub'" 2>&1 | head -2

echo "=== [$LABEL] Gate 1 ==="
DURATION="${DURATION:-20}" ./test/incus/cos-gate1-small-four-alone.sh push v4 2>&1 | tail -10
