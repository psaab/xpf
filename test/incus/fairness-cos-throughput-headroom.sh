#!/usr/bin/env bash
# Compare high-rate CoS fairness/throughput fixtures under strict exact
# scheduling and an optional surplus-sharing diagnostic config.

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

TARGET_VM=${TARGET_VM:-loss:xpf-userspace-fw0}
APPLY_CONFIG=${APPLY_CONFIG:-1}
COMPARE_SURPLUS_SHARING=${COMPARE_SURPLUS_SHARING:-1}
CLASS_FILTER=${CLASS_FILTER:-q8,q9,q10}
ARTIFACT_ROOT=${ARTIFACT_ROOT:-}
SWEEP=${SWEEP:-$ROOT_DIR/test/incus/fairness-cos-class-sweep.sh}
APPLY_COS_CONFIG=${APPLY_COS_CONFIG:-$ROOT_DIR/test/incus/apply-cos-config.sh}
RESTORE_STRICT_NEEDED=0
# Mirror fairness-cos-class-sweep.sh's reverse default. If the sweep
# is going to run iperf3 -R, CoS must be applied with reverse
# source-port filters; otherwise the headroom numbers are unclassified
# reverse traffic. An explicit REVERSE= selects forward-only fixtures.
SWEEP_REVERSE=${REVERSE--R}
COS_DIRECTION_FLAGS=()
if [[ -n "$SWEEP_REVERSE" ]]; then
    COS_DIRECTION_FLAGS+=(--symmetric)
fi

enabled() {
    case "${1,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

if [[ ! -x "$SWEEP" ]]; then
    echo "fairness-cos-throughput-headroom: sweep is not executable: $SWEEP" >&2
    exit 2
fi
if enabled "$APPLY_CONFIG" && [[ ! -x "$APPLY_COS_CONFIG" ]]; then
    echo "fairness-cos-throughput-headroom: apply script is not executable: $APPLY_COS_CONFIG" >&2
    exit 2
fi

if [[ -z "$ARTIFACT_ROOT" ]]; then
    ARTIFACT_ROOT=$(mktemp -d -t cos-throughput-headroom.XXXXXX)
else
    mkdir -p "$ARTIFACT_ROOT"
fi

SUMMARY_TSV="$ARTIFACT_ROOT/summary.tsv"
SUMMARY_MD="$ARTIFACT_ROOT/summary.md"
cat > "$SUMMARY_TSV" <<'HEADER'
scenario	class	port	queue_id	rate_bps	exit_status	verdict	mean_observed_cov	max_observed_cov	stdev_observed_cov	avg_mbps	avg_rate_utilization	avg_cstruct	mean_gap	max_gap	starved_flows	per_run_verdicts
HEADER

restore_strict_if_needed() {
    [[ "$RESTORE_STRICT_NEEDED" -eq 1 ]] || return 0
    enabled "$APPLY_CONFIG" || return 0

    if "$APPLY_COS_CONFIG" "${COS_DIRECTION_FLAGS[@]}" "$TARGET_VM" \
        > "$ARTIFACT_ROOT/restore-strict.stdout" \
        2> "$ARTIFACT_ROOT/restore-strict.stderr"; then
        RESTORE_STRICT_NEEDED=0
        return 0
    fi
    return 1
}

on_exit() {
    local status=$?
    trap - EXIT HUP INT QUIT TERM
    if ! restore_strict_if_needed; then
        echo "fairness-cos-throughput-headroom: failed to restore strict config; see $ARTIFACT_ROOT/restore-strict.stderr" >&2
        status=2
    fi
    exit "$status"
}

on_int() {
    local status=130
    trap - EXIT HUP INT QUIT TERM
    if ! restore_strict_if_needed; then
        echo "fairness-cos-throughput-headroom: failed to restore strict config after interrupt; see $ARTIFACT_ROOT/restore-strict.stderr" >&2
        status=2
    fi
    exit "$status"
}

on_term() {
    local status=143
    trap - EXIT HUP INT QUIT TERM
    if ! restore_strict_if_needed; then
        echo "fairness-cos-throughput-headroom: failed to restore strict config after termination; see $ARTIFACT_ROOT/restore-strict.stderr" >&2
        status=2
    fi
    exit "$status"
}

on_hup() {
    local status=129
    trap - EXIT HUP INT QUIT TERM
    if ! restore_strict_if_needed; then
        echo "fairness-cos-throughput-headroom: failed to restore strict config after hangup; see $ARTIFACT_ROOT/restore-strict.stderr" >&2
        status=2
    fi
    exit "$status"
}

on_quit() {
    local status=131
    trap - EXIT HUP INT QUIT TERM
    if ! restore_strict_if_needed; then
        echo "fairness-cos-throughput-headroom: failed to restore strict config after quit; see $ARTIFACT_ROOT/restore-strict.stderr" >&2
        status=2
    fi
    exit "$status"
}

trap on_exit EXIT
trap on_hup HUP
trap on_int INT
trap on_quit QUIT
trap on_term TERM

apply_config_for_scenario() {
    local scenario=$1
    local out=$2

    enabled "$APPLY_CONFIG" || return 0
    mkdir -p "$out"
    if [[ "$scenario" == surplus-sharing ]]; then
        RESTORE_STRICT_NEEDED=1
        "$APPLY_COS_CONFIG" "${COS_DIRECTION_FLAGS[@]}" --surplus-sharing "$TARGET_VM" > "$out/apply.stdout" 2> "$out/apply.stderr"
    else
        "$APPLY_COS_CONFIG" "${COS_DIRECTION_FLAGS[@]}" "$TARGET_VM" > "$out/apply.stdout" 2> "$out/apply.stderr"
    fi
}

run_scenario() {
    local scenario=$1
    local out="$ARTIFACT_ROOT/$scenario"
    local status
    local apply_status

    mkdir -p "$out"
    echo "=== $(date -Is) scenario=$scenario class_filter=$CLASS_FILTER ==="
    apply_config_for_scenario "$scenario" "$out"
    apply_status=$?
    if [[ "$apply_status" -ne 0 ]]; then
        echo "fairness-cos-throughput-headroom: failed to apply $scenario config; see $out/apply.stderr" >&2
        printf '%s\t-\t-\t-\t-\t%s\tERROR\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\n' "$scenario" "$apply_status" >> "$SUMMARY_TSV"
        return "$apply_status"
    fi

    env CLASS_FILTER="$CLASS_FILTER" ARTIFACT_ROOT="$out/sweep" "$SWEEP" \
        > "$out/sweep.stdout" 2> "$out/sweep.stderr"
    status=$?
    if [[ -f "$out/sweep/summary.tsv" ]]; then
        tail -n +2 "$out/sweep/summary.tsv" \
            | awk -v scenario="$scenario" 'BEGIN { FS = OFS = "\t" } { print scenario, $0 }' \
            >> "$SUMMARY_TSV"
    else
        printf '%s\t-\t-\t-\t-\t%s\tERROR\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\n' "$scenario" "$status" >> "$SUMMARY_TSV"
    fi
    return "$status"
}

overall_status=0
run_scenario strict || overall_status=$?

if enabled "$COMPARE_SURPLUS_SHARING"; then
    run_scenario surplus-sharing || {
        status=$?
        if [[ "$overall_status" -eq 0 || "$status" -eq 2 ]]; then
            overall_status=$status
        fi
    }
    # Leave the fixture in the strict default state after the diagnostic
    # comparison unless the operator explicitly disabled config applies.
    if ! restore_strict_if_needed; then
        echo "fairness-cos-throughput-headroom: failed to restore strict config; see $ARTIFACT_ROOT/restore-strict.stderr" >&2
        overall_status=2
    fi
fi

if ! {
    printf '# CoS Throughput Headroom Comparison\n\n'
    printf 'Artifacts: `%s`\n\n' "$ARTIFACT_ROOT"
    printf 'Class filter: `%s`\n\n' "$CLASS_FILTER"
    printf '| Scenario | Class | Queue | Verdict | Avg Mbps | Avg rate utilization | Mean CoV | Max CoV | Mean Gap | Max Gap | Starved |\n'
    printf '|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|\n'
    tail -n +2 "$SUMMARY_TSV" | while IFS=$'\t' read -r scenario class _port queue _rate _status verdict mean max _stdev mbps util _cstruct mean_gap max_gap starved _per_run; do
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$scenario" "$class" "$queue" "$verdict" "$mbps" "$util" "$mean" "$max" "$mean_gap" "$max_gap" "$starved"
    done
} > "$SUMMARY_MD"; then
    echo "fairness-cos-throughput-headroom: failed to write $SUMMARY_MD" >&2
    overall_status=2
fi

echo "fairness-cos-throughput-headroom: wrote $SUMMARY_TSV"
echo "fairness-cos-throughput-headroom: wrote $SUMMARY_MD"
exit "$overall_status"
