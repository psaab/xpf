#!/usr/bin/env bash
# Validate exact CoS queues under best-effort/uncapped contention.
#
# Runs four IPv4 forward cells on the loss userspace cluster:
#   exact 5202 vs contender 5200
#   exact 5210 vs contender 5200
#   exact 5202 vs contender 5211
#   exact 5210 vs contender 5211
#
# The harness records exact-alone and exact+contender iperf3 JSON plus
# before/during/after DrainShape snapshots from /run/xpf/userspace-dp.json,
# then delegates fail-closed validation to cos_be_contention_validate.py.

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ENV_FILE="${ENV_FILE:-$ROOT_DIR/test/incus/loss-userspace-cluster.env}"
# #13070 (D10-15): the incus CLI wrapper comes from the shared CoS
# schedule + wrapper library instead of a harness-local copy.
# shellcheck source=cos-apply-lib.sh
source "$ROOT_DIR/test/incus/cos-apply-lib.sh"
APPLY_COS_CONFIG="${APPLY_COS_CONFIG:-$ROOT_DIR/test/incus/apply-cos-config.sh}"
VALIDATOR="${VALIDATOR:-$ROOT_DIR/test/incus/cos_be_contention_validate.py}"

TARGET_IP="${TARGET_IP:-172.16.80.200}"
# #8040: fail on the target-service contract BEFORE the CoS fixture is applied
# and the lock is spent. Scoped to the four ports this smoke actually uses, so
# an unrelated class being down does not block it — but the report on failure
# is the whole 24-port grid, because a runner wants every hole at once.
SKIP_TARGET_PRECHECK="${SKIP_TARGET_PRECHECK:-0}"
if [[ "$SKIP_TARGET_PRECHECK" != "1" ]]; then
    TARGET_V4="$TARGET_IP" "$ROOT_DIR/test/incus/target-services.sh" \
        check 5200 5202 5210 5211 || exit 1
fi
DURATION="${DURATION:-8}"
EXACT_PARALLEL="${EXACT_PARALLEL:-4}"
CONTENDER_PARALLEL="${CONTENDER_PARALLEL:-4}"
IPERF_TIMEOUT="${IPERF_TIMEOUT:-$((DURATION + 15))}"
DURING_CAPTURE_AFTER_SEC="${DURING_CAPTURE_AFTER_SEC:-2}"
BETWEEN_PHASE_SLEEP_SEC="${BETWEEN_PHASE_SLEEP_SEC:-1}"
APPLY_CONFIG="${APPLY_CONFIG:-1}"
USE_SG_INCUS_ADMIN="${USE_SG_INCUS_ADMIN:-1}"
DATAPLANE_STATUS_PATH="${DATAPLANE_STATUS_PATH:-/run/xpf/userspace-dp.json}"
COS_INTERFACE_NAME="${COS_INTERFACE_NAME:-reth0.80}"
COS_IFINDEX="${COS_IFINDEX:-}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-}"
CELL_FILTER="${CELL_FILTER:-}"
MAX_EXACT_DROP_RATIO="${MAX_EXACT_DROP_RATIO:-0.15}"
WRONG_QUEUE_SENT_BYTES_TOLERANCE="${WRONG_QUEUE_SENT_BYTES_TOLERANCE:-0}"
MIN_EXPECTED_SENT_BYTES="${MIN_EXPECTED_SENT_BYTES:-1}"
MIN_CONTENDER_BPS="${MIN_CONTENDER_BPS:-100000000}"
MIN_EXACT_BASELINE_CAP_RATIO="${MIN_EXACT_BASELINE_CAP_RATIO:-0.70}"
MIN_CONTENDED_ROOT_PRESSURE_RATIO="${MIN_CONTENDED_ROOT_PRESSURE_RATIO:-0.90}"
ROOT_SHAPE_BPS="${ROOT_SHAPE_BPS:-25000000000}"
IPERF_EXTRA_ARGS="${IPERF_EXTRA_ARGS:-}"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "cos-be-contention-harness: env file not found: $ENV_FILE" >&2
    exit 2
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

REMOTE_PREFIX="${INCUS_REMOTE:+${INCUS_REMOTE}:}"
FW0="${REMOTE_PREFIX}${VM0}"
FW1="${REMOTE_PREFIX}${VM1}"
HOST="${REMOTE_PREFIX}${LAN_HOST}"
APPLY_TARGET_VM="${APPLY_TARGET_VM:-$FW0}"
ACTIVE_FW="${ACTIVE_FW:-}"

enabled() {
    case "${1,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "cos-be-contention-harness: required command not found: $1" >&2
        exit 2
    fi
}

require_cmd incus
require_cmd python3
if enabled "$USE_SG_INCUS_ADMIN"; then
    require_cmd sg
fi
if [[ ! -x "$VALIDATOR" ]]; then
    echo "cos-be-contention-harness: validator is not executable: $VALIDATOR" >&2
    exit 2
fi
if enabled "$APPLY_CONFIG" && [[ ! -x "$APPLY_COS_CONFIG" ]]; then
    echo "cos-be-contention-harness: apply script is not executable: $APPLY_COS_CONFIG" >&2
    exit 2
fi

if [[ -z "$ARTIFACT_ROOT" ]]; then
    ARTIFACT_ROOT=$(mktemp -d -t cos-be-contention.XXXXXX)
else
    mkdir -p "$ARTIFACT_ROOT"
fi

log() {
    printf '==> %s\n' "$*"
}

# #13070 (D10-15): source the shared CoS schedule + incus wrapper library.
# shellcheck source=cos-apply-lib.sh
source "$ROOT_DIR/test/incus/cos-apply-lib.sh"

# run_incus used to be a harness-local `sg incus-admin` wrapper; it now
# delegates to the shared cos-apply-lib.sh wrappers. The
# USE_SG_INCUS_ADMIN knob keeps its exact meaning through INCUS_FORCE_SG:
# enabled (the default) routes every call through `sg incus-admin` exactly
# as before, disabled lets the shared wrapper auto-detect group membership.
run_incus() {
    local vm=$1
    local cmd=$2

    if enabled "$USE_SG_INCUS_ADMIN"; then
        INCUS_FORCE_SG=1 incus_exec_shell "$vm" "$cmd"
    else
        incus_exec_shell "$vm" "$cmd"
    fi
}

run_apply_config() {
    enabled "$APPLY_CONFIG" || return 0

    log "applying symmetric CoS fixture to $APPLY_TARGET_VM"
    if enabled "$USE_SG_INCUS_ADMIN"; then
        local apply_cmd
        printf -v apply_cmd '%q --symmetric %q' "$APPLY_COS_CONFIG" "$APPLY_TARGET_VM"
        sg incus-admin -c "$apply_cmd" \
            > "$ARTIFACT_ROOT/apply-cos.stdout" \
            2> "$ARTIFACT_ROOT/apply-cos.stderr"
    else
        "$APPLY_COS_CONFIG" --symmetric "$APPLY_TARGET_VM" \
            > "$ARTIFACT_ROOT/apply-cos.stdout" \
            2> "$ARTIFACT_ROOT/apply-cos.stderr"
    fi
}

# Deliberately NOT the lib's detect_active_primary (#13070 / D10-15): that
# one answers "who holds RG0" from `show chassis cluster status` with a
# tolerant fallback. THIS detector answers "whose data plane is actually
# forwarding" from data-plane statistics and FAILS (rc 1) when neither
# node forwards — the contention smoke must not silently pick a node.
detect_active_fw() {
    local vm
    local stats
    for vm in "$FW0" "$FW1"; do
        stats="$(run_incus "$vm" 'cli -c "show chassis cluster data-plane statistics"' 2>/dev/null || true)"
        if grep -Eq 'Enabled:[[:space:]]+true' <<<"$stats" &&
            grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$stats" &&
            grep -Eq 'HA groups:[[:space:]].*rg[1-9][0-9]* active=true' <<<"$stats"; then
            printf '%s\n' "$vm"
            return 0
        fi
    done
    return 1
}

capture_status() {
    local phase_dir=$1
    local phase=$2
    local rc=0

    mkdir -p "$phase_dir"
    run_incus "$ACTIVE_FW" "cat \"$DATAPLANE_STATUS_PATH\"" \
        > "$phase_dir/status-${phase}.json" \
        2> "$phase_dir/status-${phase}.stderr"
    rc=$?
    printf '%s\n' "$rc" > "$phase_dir/status-${phase}.rc"
    return 0
}

start_iperf() {
    local phase_dir=$1
    local role=$2
    local port=$3
    local parallel=$4
    local remote_cmd

    remote_cmd="timeout -k 2 ${IPERF_TIMEOUT} iperf3 -J --forceflush -c ${TARGET_IP} -p ${port} -P ${parallel} -t ${DURATION}"
    if [[ -n "$IPERF_EXTRA_ARGS" ]]; then
        remote_cmd+=" ${IPERF_EXTRA_ARGS}"
    fi
    {
        rc=1
        printf '%s\n' "$remote_cmd" > "$phase_dir/${role}-iperf.cmd"
        run_incus "$HOST" "$remote_cmd" \
            > "$phase_dir/${role}-iperf.json" \
            2> "$phase_dir/${role}-iperf.stderr"
        rc=$?
        printf '%s\n' "$rc" > "$phase_dir/${role}-iperf.rc"
        exit "$rc"
    } &
    STARTED_IPERF_PID=$!
}

wait_for_pids() {
    local status=0
    local pid

    for pid in "$@"; do
        if ! wait "$pid"; then
            status=1
        fi
    done
    return "$status"
}

run_phase() {
    local phase_dir=$1
    local exact_port=$2
    local contender_port=${3:-}
    local exact_pid
    local contender_pid
    local wait_status=0

    mkdir -p "$phase_dir"
    capture_status "$phase_dir" before
    start_iperf "$phase_dir" exact "$exact_port" "$EXACT_PARALLEL"
    exact_pid=$STARTED_IPERF_PID
    if [[ -n "$contender_port" ]]; then
        start_iperf "$phase_dir" contender "$contender_port" "$CONTENDER_PARALLEL"
        contender_pid=$STARTED_IPERF_PID
    else
        contender_pid=
    fi
    sleep "$DURING_CAPTURE_AFTER_SEC"
    capture_status "$phase_dir" during
    if [[ -n "$contender_pid" ]]; then
        wait_for_pids "$exact_pid" "$contender_pid" || wait_status=1
    else
        wait_for_pids "$exact_pid" || wait_status=1
    fi
    capture_status "$phase_dir" after
    sleep "$BETWEEN_PHASE_SLEEP_SEC"
    return "$wait_status"
}

class_selected() {
    local label=$1
    local raw
    local filter
    local -a filters

    [[ -n "$CELL_FILTER" ]] || return 0
    IFS=',' read -r -a filters <<< "$CELL_FILTER"
    for raw in "${filters[@]}"; do
        filter=${raw//[[:space:]]/}
        [[ -n "$filter" ]] || continue
        if [[ "$filter" == "$label" ]]; then
            return 0
        fi
    done
    return 1
}

# Format:
#   label exact_port exact_queue exact_class contender_port contender_queue
#   contender_class
#
# Exact caps and per-cell contender floors are derived by the validator from
# the canonical CoS port grid so the live harness and offline reducer do not
# drift apart.
cells=(
    "exact5202-vs-5200 5202 2 iperf-1g 5200 0 best-effort"
    "exact5210-vs-5200 5210 10 iperf-24g 5200 0 best-effort"
    "exact5202-vs-5211 5202 2 iperf-1g 5211 11 iperf-uncapped"
    "exact5210-vs-5211 5210 10 iperf-24g 5211 11 iperf-uncapped"
)

selected_cells=()
for spec in "${cells[@]}"; do
    read -r label _exact_port _exact_queue _exact_class _contender_port _contender_queue _contender_class <<< "$spec"
    if class_selected "$label"; then
        selected_cells+=("$spec")
    fi
done
if [[ "${#selected_cells[@]}" -eq 0 ]]; then
    echo "cos-be-contention-harness: CELL_FILTER selected no cells: $CELL_FILTER" >&2
    exit 2
fi

log "artifact root: $ARTIFACT_ROOT"
run_apply_config || {
    echo "cos-be-contention-harness: failed to apply symmetric CoS; see $ARTIFACT_ROOT/apply-cos.stderr" >&2
    exit 2
}

if [[ -z "$ACTIVE_FW" ]]; then
    ACTIVE_FW="$(detect_active_fw || true)"
fi
if [[ -z "$ACTIVE_FW" ]]; then
    echo "cos-be-contention-harness: unable to detect active userspace firewall" >&2
    exit 2
fi
log "capturing dataplane status from $ACTIVE_FW"

python3 - "$ARTIFACT_ROOT" "$COS_INTERFACE_NAME" "$COS_IFINDEX" "$ROOT_SHAPE_BPS" "${selected_cells[@]}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
cos_interface_name = sys.argv[2]
cos_ifindex_raw = sys.argv[3]
root_shape_bps = int(sys.argv[4])
cells = []
for raw in sys.argv[5:]:
    (
        label,
        exact_port,
        exact_queue,
        exact_forwarding_class,
        contender_port,
        contender_queue,
        contender_forwarding_class,
    ) = raw.split()
    cells.append(
        {
            "label": label,
            "exact_port": int(exact_port),
            "exact_queue": int(exact_queue),
            "exact_forwarding_class": exact_forwarding_class,
            "contender_port": int(contender_port),
            "contender_queue": int(contender_queue),
            "contender_forwarding_class": contender_forwarding_class,
            "baseline_dir": f"{label}/baseline",
            "contended_dir": f"{label}/contended",
        }
    )
manifest = {
    "cos_interface_name": cos_interface_name,
    "cos_ifindex": int(cos_ifindex_raw) if cos_ifindex_raw else None,
    "root_shape_bps": root_shape_bps,
    "cells": cells,
}
(root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY

overall_run_status=0
for spec in "${selected_cells[@]}"; do
    read -r label exact_port exact_queue _exact_class contender_port contender_queue _contender_class <<< "$spec"
    cell_dir="$ARTIFACT_ROOT/$label"
    log "cell=$label exact_port=$exact_port exact_queue=$exact_queue contender_port=$contender_port contender_queue=$contender_queue"
    if ! run_phase "$cell_dir/baseline" "$exact_port"; then
        overall_run_status=1
    fi
    if ! run_phase "$cell_dir/contended" "$exact_port" "$contender_port"; then
        overall_run_status=1
    fi
done

if [[ "$overall_run_status" -ne 0 ]]; then
    log "one or more iperf launcher processes returned non-zero; validator will fail closed"
fi

python3 "$VALIDATOR" "$ARTIFACT_ROOT" \
    --max-exact-drop-ratio "$MAX_EXACT_DROP_RATIO" \
    --wrong-queue-sent-bytes-tolerance "$WRONG_QUEUE_SENT_BYTES_TOLERANCE" \
    --min-expected-sent-bytes "$MIN_EXPECTED_SENT_BYTES" \
    --min-contender-bps "$MIN_CONTENDER_BPS" \
    --min-exact-baseline-cap-ratio "$MIN_EXACT_BASELINE_CAP_RATIO" \
    --min-contended-root-pressure-ratio "$MIN_CONTENDED_ROOT_PRESSURE_RATIO"
validator_status=$?

log "summary: $ARTIFACT_ROOT/summary.tsv"
log "drain shape: $ARTIFACT_ROOT/drain-shape.tsv"
exit "$validator_status"
