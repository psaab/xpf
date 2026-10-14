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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# #13070 (D10-15): ports/classes/shapes come from the shared CoS schedule
# library instead of script-local copies of cos-iperf-config.set.
# shellcheck source=cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"

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

# The small four exact classes: 100m/1g/3g/6g (#13070 / D10-15 — derived
# from the canonical grid, was a hand-listed copy).
declare -a PORTS=("${COS_SCHEDULE_PORTS[@]:1:4}")
REV_FLAG=""
[ "$DIRECTION" = "reverse" ] && REV_FLAG="-R"

mkdir -p "$ART"
echo "#1630 Gate1 small-four-alone: dir=$DIRECTION af=$AF target=$TARGET dur=${DURATION}s streams=$STREAMS art=$ART"

declare -a PIDS=()
for port in "${PORTS[@]}"; do
  (
    rc=0
    incus_exec "$HOST" iperf3 -c "$TARGET" -P "$STREAMS" -t "$DURATION" -p "$port" $REV_FLAG --json \
      > "$ART/g1_${port}.json" 2>"$ART/g1_${port}.err" || rc=$?
    echo "$rc" > "$ART/g1_${port}.rc"
  ) &
  PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait "$pid"; done

python3 - "$ART" "$DIRECTION" "$AF" "$SCRIPT_DIR" <<'PYEOF'
import json, os, sys
art, direction, af = sys.argv[1], sys.argv[2], sys.argv[3]
# #13070 (D10-15): ports/classes/shapes are DERIVED from the fixture via
# cos_fixture_spec (this heredoc used to carry its own copy of the grid).
sys.path.insert(0, sys.argv[4])
from cos_fixture_spec import canonical_cos_schedule
schedule = canonical_cos_schedule()
ports = sorted(p for p in schedule if 5201 <= p <= 5204)
names = {p: schedule[p]["forwarding_class"] for p in ports}
shape = {p: schedule[p]["cap_bps"] / 1e9 for p in ports}
rows = []
all_pass = True
for p in ports:
    # Generator health: a crashed or unlaunched iperf3 sender leaves a
    # nonzero (or missing) .rc sidecar. Treat it as a hard failure — do
    # not read a stale/partial JSON as a pass (#4240 V-2).
    rcf = os.path.join(art, f"g1_{p}.rc")
    try:
        rc = int(open(rcf).read().strip())
    except Exception:
        rc = 1  # missing/unreadable .rc == generator never completed
    if rc != 0:
        rows.append((p, names[p], shape[p], None, None, f"ERR generator rc={rc}"))
        all_pass = False
        continue
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
# Propagate the verdict as the process exit status. Under `set -euo
# pipefail` this heredoc is the last command, so a nonzero exit here
# becomes the script's exit status. A JSON parse error or a nonzero
# generator rc already flips all_pass, so malformed/missing output
# correctly yields exit 1 (#4240 V-2).
sys.exit(0 if all_pass else 1)
PYEOF
