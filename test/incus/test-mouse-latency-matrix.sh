#!/usr/bin/env bash
# Run the full 12-cell #905 mouse-latency matrix.
#
# Usage: test-mouse-latency-matrix.sh <out_root>
#
# Set MOUSE_COS_SURPLUS_SHARING=1 to run every preflight/rep under
# the diagnostic surplus-sharing fixture instead of the strict exact
# fixture. The per-rep manifest records the selected fixture bit.
#
# Set MOUSE_PROBE_CONNECTION_MODE=persistent for high-concurrency
# 100E100M runs where the validation target is tail latency of
# established mouse transactions rather than echo-server accept rate.
# Set MOUSE_PROBE_MIN_INTERVAL_MS=20 with that mode on the isolated
# validation cluster; it still produces hundreds of thousands of
# samples per 60-second rep without overdriving the selected 620x TCP
# echo daemon.
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
# #8244: OUT_ROOT and SCRIPT_DIR are resolved BEFORE the mutex so that a
# lock-contention abort can write its artifact too. A run that never started
# because another holds the lock is precisely the "never ran" case that used
# to be indistinguishable from a gate FAIL.
OUT_ROOT="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

LOCK_FILE="/var/worktrees/.cache/tmpdir/test-mouse-latency-matrix.lock"
exec 9>"$LOCK_FILE"
flock -n 9 || {
    abort_matrix ABORTED-LOCK-CONTENTION \
        "another mouse-latency matrix holds $LOCK_FILE; wait for it or stop it"
}

# shellcheck source=test/incus/mouse-elephant-lib.sh
# #8244: for MOUSE_DEFAULT_ECHO_PORT / MOUSE_DEFAULT_IPERF_PORT. This script
# did not source the library, so the port defaults had to be re-declared here
# and drifted from the rep script's copy by construction.
. "${SCRIPT_DIR}/mouse-elephant-lib.sh"

# #8244: an abort must be DISTINGUISHABLE from a gate failure, in the
# artifact, by field name.
#
# Every abort path here used to `exit 1` and write no summary.json at all, so
# the only signal was an ABSENCE — and rc=1 is also what a measured gate FAIL
# returns. "Never ran" and "ran and failed" were the same observation. On
# #7100 the same rc=1 meant one with 0 JSON files and the other with 62, and
# the run was read as the lab being unprovisioned when eleven of twelve echo
# listeners were up.
#
# This is the same defect as #8259's void verdict, one layer out: a state the
# harness could not measure, reported as though it had measured it. Same
# remedy — a named outcome a consumer reads by field name, and an exit code
# that is neither PASS(0) nor FAIL(1).
#
# The shape matches what mouse_latency_aggregate.py writes, so a reader that
# already parses summary.json["verdict"]["verdict"] needs no change.
abort_matrix() {
    local code="$1"; shift
    local reason="$*"
    echo "ABORT [$code]: $reason" >&2
    if [[ -n "${OUT_ROOT:-}" ]]; then
        mkdir -p "$OUT_ROOT" 2>/dev/null || true
        # The whole-grid scan is what turns "the lab is down" into "one port is
        # down". target-services.sh already knows how to produce it; the abort
        # simply stops throwing it away.
        local scan
        scan="$("${SCRIPT_DIR}/target-services.sh" status 2>&1 || true)"
        # `|| true` so a broken writer can never stop the abort from
        # aborting — but NOT `2>/dev/null`: swallowing stderr here hid a
        # missing ABORT_OUT (KeyError) during development, and an artifact
        # that silently fails to be written is the very defect being fixed.
        ABORT_CODE="$code" ABORT_REASON="$reason" ABORT_SCAN="$scan" \
        ABORT_OUT="${OUT_ROOT}/summary.json" \
        python3 -c '
import json, os
json.dump({
    "verdict": {
        "verdict": os.environ["ABORT_CODE"],
        "reason": os.environ["ABORT_REASON"],
        "target_services_scan": os.environ["ABORT_SCAN"],
    },
    "summaries": {},
}, open(os.environ["ABORT_OUT"], "w"), indent=2)
' || true
    fi
    exit 2
}
DURATION=${MOUSE_LATENCY_DURATION:-60} # per-rep probe seconds
WALL_CAP=$((6*3600)) # seconds, plan §4.7

mkdir -p "$OUT_ROOT"

# Prioritized cell order: gate cells first, then remaining M=10 cells,
# then everything else.
DEFAULT_CELLS=$'0 10\n128 10\n8 10\n32 10\n0 1\n8 1\n32 1\n128 1\n0 50\n8 50\n32 50\n128 50'
CELLS_RAW=${MOUSE_LATENCY_CELLS:-$DEFAULT_CELLS}
mapfile -t CELLS < <(printf '%s\n' "$CELLS_RAW" | sed '/^[[:space:]]*$/d')

start_t=$(date +%s)

# ---- target-service preflight (#8040)
#
# BEFORE the 60s probe rep below, and before any CoS mutation: check that the
# per-class listeners this matrix will actually use are up, and report the
# WHOLE grid if they are not.
#
# The old preflight reached the target only through test-mouse-latency.sh's
# single-port /dev/tcp check, so a matrix aborted on the first class it
# happened to reach and said nothing about the other twenty-three. A sweep
# that fixed that one port then failed on the next. Worse, the abort arrived
# after a build, a deploy and the shared /tmp/xpf-cluster.lock had all been
# spent — this check is cheap and answers first.
#
# Scoped to the ports this run needs, not all 24: an unrelated class being
# down must not block a matrix that never sends to it.
MOUSE_PORT="${MOUSE_PORT:-$MOUSE_DEFAULT_ECHO_PORT}"
ELEPHANT_PORT="${ELEPHANT_PORT:-$MOUSE_DEFAULT_IPERF_PORT}"
if ! "${SCRIPT_DIR}/target-services.sh" check "$MOUSE_PORT" "$ELEPHANT_PORT"; then
    abort_matrix ABORTED-TARGET-SERVICES-DOWN \
        "the target services this run needs are not up: echo $MOUSE_PORT / iperf3 $ELEPHANT_PORT (#8040)"
fi

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
    ls "$PREFLIGHT_DIR" >&2
    abort_matrix ABORTED-PREFLIGHT-INVALID "preflight rep was invalidated"
fi
if [[ ! -f "$PREFLIGHT_DIR/probe.json" ]]; then
    abort_matrix ABORTED-PREFLIGHT-NO-PROBE "preflight produced no probe.json"
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
    abort_matrix ABORTED-PREFLIGHT-FAILED "preflight failed: $preflight"
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
