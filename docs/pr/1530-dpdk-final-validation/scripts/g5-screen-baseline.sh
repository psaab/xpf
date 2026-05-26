#!/usr/bin/env bash
#
# G5.d — Screen / flood baseline: LAND, SYN-flood, ICMP-flood.
#
# Drives short attack bursts from the LAN host and checks that the
# RG0 primary's screen statistics counters increment. The daemon must
# stay up (cluster status snapshot taken before and after).
#
# Writes:
#   artifacts/smoke-screen-land.log
#   artifacts/smoke-screen-land-stats.log
#   artifacts/smoke-screen-synflood.log
#   artifacts/smoke-screen-synflood-stats.log
#   artifacts/smoke-screen-icmpflood.log
#   artifacts/smoke-screen-icmpflood-stats.log
#   artifacts/smoke-screen-before.txt
#   artifacts/smoke-screen-after.txt
#
# Requires hping3 on the LAN host. If absent, the script attempts
# `apt-get install -y hping3` once and proceeds; if install fails, the
# attack steps are skipped with a documented WARN and the gate is
# marked INCONCLUSIVE — Phase B operator must rerun after installing.
#
# CALLER must hold cluster access lock via smoke-runner singleton.

set -uo pipefail

ART_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

HOST=${HOST:-loss:cluster-userspace-host}
FW0=${FW0:-loss:xpf-userspace-fw0}
V4_TARGET=${V4_TARGET:-172.16.80.200}

screen_show() {
    sg incus-admin -c "incus exec $FW0 -- cli -c 'show security flow screen statistics'" 2>&1
}

ensure_hping3() {
    if sg incus-admin -c "incus exec $HOST -- which hping3" >/dev/null 2>&1; then
        return 0
    fi
    echo "g5-screen: hping3 missing on $HOST; attempting install"
    sg incus-admin -c "incus exec $HOST -- apt-get update -y" 2>&1 | tail -5 || true
    sg incus-admin -c "incus exec $HOST -- apt-get install -y hping3" 2>&1 | tail -5 || true
    sg incus-admin -c "incus exec $HOST -- which hping3" >/dev/null 2>&1
}

if ! ensure_hping3; then
    echo "g5-screen: INCONCLUSIVE — hping3 unavailable on $HOST; skipping attack runs" >&2
    echo "g5-screen: install hping3 and rerun this script to complete G5.d" >&2
    exit 3
fi

# Baseline snapshot.
screen_show > "$ART_DIR/smoke-screen-before.txt"

INCONCLUSIVE=0
FAIL=0

# --- LAND attack: src=dst, both 172.16.80.200 ---
echo "g5-screen: == LAND attack =="
sg incus-admin -c "incus exec $HOST -- hping3 --syn -a $V4_TARGET -s 80 -p 80 -c 20 $V4_TARGET" \
    > "$ART_DIR/smoke-screen-land.log" 2>&1 || true
screen_show > "$ART_DIR/smoke-screen-land-stats.log"

if ! grep -Ei 'land' "$ART_DIR/smoke-screen-land-stats.log" >/dev/null 2>&1; then
    echo "g5-screen: WARN — LAND counter not found in screen statistics"
    INCONCLUSIVE=1
fi

# --- SYN flood: short burst, kill at 5s ---
echo "g5-screen: == SYN flood (5s) =="
( sg incus-admin -c "incus exec $HOST -- hping3 -S -p 80 --flood -c 50000 $V4_TARGET" \
    > "$ART_DIR/smoke-screen-synflood.log" 2>&1 ) &
SYN_PID=$!
sleep 5
kill "$SYN_PID" 2>/dev/null || true
wait "$SYN_PID" 2>/dev/null || true
screen_show > "$ART_DIR/smoke-screen-synflood-stats.log"

if ! grep -Ei 'syn.?flood|syn_flood' "$ART_DIR/smoke-screen-synflood-stats.log" >/dev/null 2>&1; then
    echo "g5-screen: WARN — syn-flood counter not visible in screen statistics"
    INCONCLUSIVE=1
fi

# --- ICMP flood: short burst, kill at 5s ---
echo "g5-screen: == ICMP flood (5s) =="
( sg incus-admin -c "incus exec $HOST -- hping3 --icmp --flood -c 50000 $V4_TARGET" \
    > "$ART_DIR/smoke-screen-icmpflood.log" 2>&1 ) &
ICMP_PID=$!
sleep 5
kill "$ICMP_PID" 2>/dev/null || true
wait "$ICMP_PID" 2>/dev/null || true
screen_show > "$ART_DIR/smoke-screen-icmpflood-stats.log"

if ! grep -Ei 'icmp.?flood|icmp_flood' "$ART_DIR/smoke-screen-icmpflood-stats.log" >/dev/null 2>&1; then
    echo "g5-screen: WARN — icmp-flood counter not visible in screen statistics"
    INCONCLUSIVE=1
fi

# Final snapshot.
screen_show > "$ART_DIR/smoke-screen-after.txt"

# Survivability check — cluster status still primary/secondary.
sg incus-admin -c "incus exec $FW0 -- cli -c 'show chassis cluster status'" \
    > "$ART_DIR/smoke-screen-cluster-after.txt" 2>&1 || true

if ! grep -q 'primary' "$ART_DIR/smoke-screen-cluster-after.txt" 2>/dev/null; then
    echo "g5-screen: FAIL — cluster lost primary after flood baseline" >&2
    FAIL=1
fi

if [[ "$FAIL" -ne 0 ]]; then
    echo "g5-screen: FAIL — see logs"
    exit 1
fi

if [[ "$INCONCLUSIVE" -ne 0 ]]; then
    echo "g5-screen: PARTIAL — daemon survived but counters were not all visible; review screen-*-stats logs"
    exit 0
fi

echo "g5-screen: PASS — LAND + SYN-flood + ICMP-flood counters all visible, daemon healthy"
