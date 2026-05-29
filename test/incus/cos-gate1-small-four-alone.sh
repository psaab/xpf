#!/usr/bin/env bash
# #1630 Gate 1 — small-four-alone CoS A/B. Runs ONLY the 100m/1g/3g/6g
# exact classes (ports 5201-5204) in parallel, 12 streams each, with NO
# large-class competition and the whole cluster available. Each must
# reach >= 95% of its configured shape.
#
# Usage:
#   ./test/incus/cos-gate1-small-four-alone.sh [push|reverse] [v4|v6]
#
# Expects the loss userspace cluster deployed + cos-iperf-config.set
# applied (includes oversubscription-policy guarantee-rate 0.7).
set -euo pipefail

DIRECTION="${1:-push}"
AF="${2:-v4}"
DURATION="${DURATION:-20}"
STREAMS="${STREAMS:-12}"
TARGET_V4="${TARGET_V4:-172.16.80.200}"
TARGET_V6="${TARGET_V6:-2001:559:8585:80::200}"
HOST="${HOST:-loss:cluster-userspace-host}"
ART="${ART:-/tmp/cos-gate1-$(date +%s)}"

TARGET="$TARGET_V4"
[ "$AF" = "v6" ] && TARGET="$TARGET_V6"

declare -a PORTS=(5201 5202 5203 5204)
REV_FLAG=""
[ "$DIRECTION" = "reverse" ] && REV_FLAG="-R"

mkdir -p "$ART"
echo "#1630 Gate1 small-four-alone: dir=$DIRECTION af=$AF target=$TARGET dur=${DURATION}s streams=$STREAMS art=$ART"

declare -a PIDS=()
for port in "${PORTS[@]}"; do
  (
    sg incus-admin -c "incus exec $HOST -- iperf3 -c $TARGET -P $STREAMS -t $DURATION -p $port $REV_FLAG --json" \
      > "$ART/g1_${port}.json" 2>"$ART/g1_${port}.err" || true
  ) &
  PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait "$pid"; done

python3 - "$ART" "$DIRECTION" "$AF" <<'PYEOF'
import json, os, sys
art, direction, af = sys.argv[1], sys.argv[2], sys.argv[3]
ports = [5201, 5202, 5203, 5204]
names = {5201: "iperf-100m", 5202: "iperf-1g", 5203: "iperf-3g", 5204: "iperf-6g"}
shape = {5201: 0.1, 5202: 1.0, 5203: 3.0, 5204: 6.0}
rows = []
all_pass = True
for p in ports:
    f = os.path.join(art, f"g1_{p}.json")
    try:
        d = json.load(open(f))
    except Exception as e:
        rows.append((p, names[p], shape[p], None, None, f"ERR {e}"))
        all_pass = False
        continue
    sr = d.get("end", {}).get("sum_received") or {}
    ss = d.get("end", {}).get("sum_sent") or {}
    recv = (sr.get("bits_per_second") or ss.get("bits_per_second") or 0) / 1e9
    pct = recv / shape[p] * 100
    ok = pct >= 95.0
    all_pass = all_pass and ok
    rows.append((p, names[p], shape[p], round(recv, 3), round(pct, 1), "PASS" if ok else "FAIL"))
print(f"\n#1630 Gate1 ({direction}/{af})")
print(f"{'port':<6}{'class':<14}{'shape':>7}{'recv_G':>8}{'%shape':>8}  verdict")
for p, n, sh, recv, pct, v in rows:
    if recv is None:
        print(f"{p:<6}{n:<14}{sh:>6.2f}G {v}")
    else:
        print(f"{p:<6}{n:<14}{sh:>6.2f}G {recv:>7.2f}G {pct:>7.1f}%  {v}")
print(f"\nGATE1 {'PASS' if all_pass else 'FAIL'} (all four >= 95% of shape)")
PYEOF
