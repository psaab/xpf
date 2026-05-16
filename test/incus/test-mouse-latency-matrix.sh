#!/usr/bin/env bash
# Run the full 12-cell #905 mouse-latency matrix.
#
# Usage: test-mouse-latency-matrix.sh <out_root>
#
# Set MOUSE_COS_SURPLUS_SHARING=1 to run every preflight/rep under
# the diagnostic surplus-sharing fixture instead of the strict exact
# fixture. The per-rep manifest records the selected fixture bit.
#
# 12 cells: N ∈ {0, 8, 32, 128} × M ∈ {1, 10, 50}.
# Per cell: run up to 15 total reps as needed to reach 10 valid reps.
# Cell stops at 10 valid reps OR 15 total, whichever is first.
# (Replacements + extensions both draw from the 15-rep ceiling per
# plan §4.7; the >30% conditional was simplified out — we always
# allow up to 15 since the 30% trigger doesn't help if a cell lands
# 1-3 invalid reps and the conditional path was a footgun.)
#
# Cells run in PASS-gate-relevant order so a wall-budget truncation
# degrades gracefully:
#   1. (0, 10)   ← idle baseline of the gate
#   2. (128, 10) ← loaded measurement of the gate
#   then (8, 10), (32, 10), and the rest of the matrix.
#
# Run echo-server preflight first (plan §4.6); abort if it fails.
#
# Total wall budget cap: 6 hours (plan §4.7).

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <out_root>" >&2
    exit 1
fi

# #929: enforce mutual exclusion against concurrent matrix runs
# (cross-class default vs same-class wrapper). Both call into this
# script and both apply CoS, which is global mutable cluster state.
# Concurrent runs would alternately overwrite each other's CoS
# fixture and silently corrupt both datasets. flock -n fails fast
# instead of waiting.
#
# Copilot D.1: hard-code /tmp rather than ${TMPDIR:-/tmp} — two
# invocations with different TMPDIR env values would lock
# different files and bypass the mutex. The CoS state being
# protected is per-host, so the lock must be per-host.
LOCK_FILE="/tmp/test-mouse-latency-matrix.lock"
exec 9>"$LOCK_FILE"
flock -n 9 || {
    echo "ABORT: another mouse-latency matrix is already running" >&2
    echo "       (lock held on $LOCK_FILE)" >&2
    echo "       wait for it to finish or kill it before retrying" >&2
    exit 1
}

OUT_ROOT="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DURATION=${MOUSE_LATENCY_DURATION:-60} # per-rep probe seconds
WALL_CAP=$((6*3600)) # seconds, plan §4.7

mkdir -p "$OUT_ROOT"

# Prioritized cell order: gate cells first, then remaining M=10 cells,
# then everything else.
DEFAULT_CELLS=$'0 10\n128 10\n8 10\n32 10\n0 1\n8 1\n32 1\n128 1\n0 50\n8 50\n32 50\n128 50'
CELLS_RAW=${MOUSE_LATENCY_CELLS:-$DEFAULT_CELLS}
mapfile -t CELLS < <(printf '%s\n' "$CELLS_RAW" | sed '/^[[:space:]]*$/d')

start_t=$(date +%s)

# ---- echo-server preflight (plan §4.6)
PREFLIGHT_DIR="${OUT_ROOT}/preflight"
mkdir -p "$PREFLIGHT_DIR"
echo "Running echo-server preflight..."
# Use a 60s probe to satisfy the M=1 min-attempts floor of 500
# (plan §4.2). The plan §4.6 originally specified 5s, but with the
# probe driver's M=1 floor that would always INVALIDATE on
# min-attempts. 60s costs us 60s once, vs. losing the validity
# verdict entirely.
"${SCRIPT_DIR}/test-mouse-latency.sh" 0 1 60 "$PREFLIGHT_DIR" || true

# R2 fresh MED 2: orchestrator INVALIDates by writing a marker file
# and exiting 0; preflight must check the marker file too, not just
# the orchestrator exit code.
if compgen -G "${PREFLIGHT_DIR}/INVALID-*" > /dev/null 2>&1; then
    echo "preflight invalidated; aborting matrix" >&2
    ls "$PREFLIGHT_DIR" >&2
    exit 1
fi
if [[ ! -f "$PREFLIGHT_DIR/probe.json" ]]; then
    echo "preflight produced no probe.json; aborting" >&2
    exit 1
fi
preflight=$(python3 -c '
import json, sys
# Copilot R2 #4: defensive JSON parsing — partial writes or schema
# drift should produce an actionable preflight FAIL line, not a
# stack trace that aborts the matrix.
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
except Exception as e:
    print(f"FAIL invalid-json={e}")
    sys.exit(0)
rtt = d.get("rtt_us")
totals = d.get("totals")
validity = d.get("validity")
if not isinstance(rtt, dict):
    print("FAIL missing-field=rtt_us"); sys.exit(0)
if not isinstance(totals, dict):
    print("FAIL missing-field=totals"); sys.exit(0)
# Codex R9: validity may be missing or wrong-type from schema drift;
# coerce to dict so the .get() calls below cannot stack-trace.
if not isinstance(validity, dict):
    validity = {}
p = rtt.get("p99")
err = totals.get("error_rate")
v = validity.get("ok", False)
reasons = validity.get("reasons", [])
# R3 MED: gate on the probes own validity verdict (min-attempts
# floor, degenerate-coroutine, etc.), not just p99/error_rate.
if not v:
    print(f"FAIL validity={reasons}")
elif p is None:
    print("FAIL missing-field=rtt_us.p99")
elif err is None:
    print("FAIL missing-field=totals.error_rate")
elif p >= 5000:
    print(f"FAIL p99={p}")
elif err >= 0.001:
    print(f"FAIL err={err}")
else:
    print("OK")
' "$PREFLIGHT_DIR/probe.json")
if [[ "$preflight" != "OK" ]]; then
    echo "preflight failed: $preflight" >&2
    exit 1
fi
echo "preflight OK"

rep_is_valid() {
    # Combine: probe.json validity AND no INVALID-* marker file (the
    # orchestrator writes those for HA transitions, RG flaps, elephant
    # collapse, client saturation, etc.).
    local rep_dir="$1"
    if compgen -G "${rep_dir}/INVALID-*" > /dev/null 2>&1; then
        return 1
    fi
    if [[ ! -f "${rep_dir}/probe.json" ]]; then
        return 1
    fi
    # Copilot R3 #4: defensive parse — malformed JSON / schema drift
    # treated as invalid instead of stack-tracing into the matrix log.
    python3 -c 'import json,sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    sys.exit(0 if d["validity"]["ok"] else 1)
except Exception:
    sys.exit(1)' "${rep_dir}/probe.json"
}

WALL_CAP_HIT=0

run_cell() {
    local N="$1" M="$2"
    local cell_dir="${OUT_ROOT}/cell_N${N}_M${M}"
    mkdir -p "$cell_dir"
    local valid=0
    local total=0
    local hard_cap=15  # plan §4.7: 15-rep ceiling
    # Per plan §4.7: keep going until 10 valid OR 15 total. Both
    # ordinary replacements (any INVALID rep) AND auto-extension
    # (the >30% rule) draw from the same ceiling. R1 HIGH 2.
    while [[ $total -lt $hard_cap && $valid -lt 10 ]]; do
        # Wall budget guard. Copilot R3 #3: signal the outer cell
        # loop via WALL_CAP_HIT so it stops scheduling additional
        # cells; previously `return 0` only exited run_cell and the
        # outer loop kept iterating, hitting the cap on each cell.
        local now=$(date +%s)
        if [[ $((now - start_t)) -gt $WALL_CAP ]]; then
            echo "wall-budget cap reached, stopping matrix" >&2
            WALL_CAP_HIT=1
            return 0
        fi
        local rep_dir="${cell_dir}/rep_$(printf '%02d' $total)"
        mkdir -p "$rep_dir"
        echo "  cell N=$N M=$M rep=$total ..."
        "${SCRIPT_DIR}/test-mouse-latency.sh" "$N" "$M" "$DURATION" "$rep_dir" || true
        if rep_is_valid "$rep_dir"; then
            valid=$((valid + 1))
        fi
        total=$((total + 1))
    done

    echo "  cell N=$N M=$M done: $valid valid / $total total"
}

for cell in "${CELLS[@]}"; do
    read -r N M <<< "$cell"
    run_cell "$N" "$M"
    if [[ $WALL_CAP_HIT -eq 1 ]]; then
        echo "wall-budget cap hit; remaining cells skipped" >&2
        break
    fi
done

echo "Matrix complete; running aggregator..."
python3 "${SCRIPT_DIR}/mouse_latency_aggregate.py" \
    --root "$OUT_ROOT" \
    --out "${OUT_ROOT}/summary.json" \
    --gate-elephants "${MOUSE_LATENCY_GATE_ELEPHANTS:-128}" \
    --gate-mice "${MOUSE_LATENCY_GATE_MICE:-10}" \
    --threshold-ratio "${MOUSE_LATENCY_GATE_THRESHOLD_RATIO:-2.0}" \
    --gate-percentile "${MOUSE_LATENCY_GATE_PERCENTILE:-p99_us}"
