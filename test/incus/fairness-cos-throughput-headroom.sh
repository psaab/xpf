#!/usr/bin/env bash
# Compare high-rate CoS fairness/throughput fixtures under strict exact
# scheduling and an optional surplus-sharing diagnostic config.

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=active-fw.sh
source "$ROOT_DIR/test/incus/active-fw.sh"
# shellcheck source=cluster-env.sh
source "$ROOT_DIR/test/incus/cluster-env.sh"

APPLY_CONFIG=${APPLY_CONFIG:-1}
# D10-14 (#13069): do not hardcode a cluster node. Only the RG primary
# forwards traffic and apply-cos-config.sh must run against it (config
# sync replicates the commit to the secondary), so an unset TARGET_VM is
# resolved by probing the candidates below; if no active primary answers
# the script fails closed instead of configuring the standby.
TARGET_VM=${TARGET_VM:-}
read -r -a TARGET_VM_CANDIDATES <<< "${TARGET_VM_CANDIDATES:-loss:xpf-userspace-fw0 loss:xpf-userspace-fw1}"
METRICS_URL=${METRICS_URL:-}
COS_IFINDEX=${COS_IFINDEX:-}

COMPARE_SURPLUS_SHARING=${COMPARE_SURPLUS_SHARING:-1}
CLASS_FILTER=${CLASS_FILTER:-q8,q9,q10}
ARTIFACT_ROOT=${ARTIFACT_ROOT:-}
SWEEP=${SWEEP:-$ROOT_DIR/test/incus/fairness-cos-class-sweep.sh}
APPLY_COS_CONFIG=${APPLY_COS_CONFIG:-$ROOT_DIR/test/incus/apply-cos-config.sh}
COS_GATE_EMITTED=0
cos_gate_fallback() {
    [[ "$COS_GATE_EMITTED" == "1" ]] && return 0
    printf 'COS_GATE fairness-cos-throughput-headroom VOID reason=%s\n' "$1"
    COS_GATE_EMITTED=1
}
if [[ "${COS_GATE_SELFTEST:-0}" == "1" ]]; then
    echo "COS_GATE fairness-cos-throughput-headroom PASS reason=-- classes_failed_total=0 strict_sum_class_avg_mbps=3000 surplus_sum_class_avg_mbps=3100 paired_sum_class_avg_delta_mbps=100 paired_sum_class_avg_delta_pct=3.333 classes_failed_strict=0 classes_failed_surplus=0 max_gap_strict=0.01 max_gap_surplus=0.02"
    COS_GATE_EMITTED=1
    exit 0
fi
if [[ -z "$METRICS_URL" || -z "$COS_IFINDEX" ]]; then
    cos_gate_fallback metrics-config-missing
    exit 2
fi

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
    cos_gate_fallback harness-unavailable
    exit 2
fi
if enabled "$APPLY_CONFIG" && [[ ! -x "$APPLY_COS_CONFIG" ]]; then
    cos_gate_fallback apply-config-unavailable
    exit 2
fi

if [[ -z "$TARGET_VM" ]]; then
    if ! TARGET_VM="$(active_fw_detect "${TARGET_VM_CANDIDATES[@]}")"; then
        echo "fairness-cos-throughput-headroom: unable to detect the active primary firewall (tried: ${TARGET_VM_CANDIDATES[*]}); set TARGET_VM explicitly" >&2
        cos_gate_fallback active-primary-unavailable
        exit 2
    fi
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

    # D10-14 (#13069): restore the CANONICAL forward-only fixture. The
    # sweep scenarios deliberately apply --symmetric (reverse traffic is
    # classified on source ports), but carrying those direction flags
    # into the restore leaves the reverse source-port terms installed
    # for every later test suite; a flag-less apply deletes the
    # bandwidth-output-reverse filter and its ge-0-0-1 attachment before
    # re-applying the strict forward-only sets.
    if "$APPLY_COS_CONFIG" "$TARGET_VM" \
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
    if [[ "$COS_GATE_EMITTED" != "1" ]]; then
        local reason=harness-aborted
        [[ "$status" == "0" ]] && reason=harness-incomplete
        cos_gate_fallback "$reason"
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
    cos_gate_fallback signal-interrupted
    exit "$status"
}

on_term() {
    local status=143
    trap - EXIT HUP INT QUIT TERM
    if ! restore_strict_if_needed; then
        echo "fairness-cos-throughput-headroom: failed to restore strict config after termination; see $ARTIFACT_ROOT/restore-strict.stderr" >&2
        status=2
    fi
    cos_gate_fallback signal-interrupted
    exit "$status"
}

on_hup() {
    local status=129
    trap - EXIT HUP INT QUIT TERM
    if ! restore_strict_if_needed; then
        echo "fairness-cos-throughput-headroom: failed to restore strict config after hangup; see $ARTIFACT_ROOT/restore-strict.stderr" >&2
        status=2
    fi
    cos_gate_fallback signal-interrupted
    exit "$status"
}

on_quit() {
    local status=131
    trap - EXIT HUP INT QUIT TERM
    if ! restore_strict_if_needed; then
        echo "fairness-cos-throughput-headroom: failed to restore strict config after quit; see $ARTIFACT_ROOT/restore-strict.stderr" >&2
        status=2
    fi
    cos_gate_fallback signal-interrupted
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

    env CLASS_FILTER="$CLASS_FILTER" ARTIFACT_ROOT="$out/sweep" \
        METRICS_URL="$METRICS_URL" COS_IFINDEX="$COS_IFINDEX" FAIRNESS_EVAL="${FAIRNESS_EVAL:-$ROOT_DIR/userspace-dp/target/release/fairness-eval}" \
        "$SWEEP" > "$out/sweep.stdout" 2> "$out/sweep.stderr"
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

gate_line=$(python3 - "$SUMMARY_TSV" "$ARTIFACT_ROOT/paired-summary.tsv" "$overall_status" <<'PY'
import csv
import math
import sys

summary_path, paired_path, status = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    with open(summary_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))
except OSError:
    print("COS_GATE fairness-cos-throughput-headroom VOID reason=summary-unavailable")
    raise SystemExit(2)
if status == 2 or not rows:
    print("COS_GATE fairness-cos-throughput-headroom VOID reason=scenarios-incomplete")
    raise SystemExit(2)
by_scenario = {"strict": {}, "surplus-sharing": {}}
for row in rows:
    scenario = row.get("scenario")
    if scenario not in by_scenario or row.get("verdict") == "ERROR":
        print("COS_GATE fairness-cos-throughput-headroom VOID reason=error-row")
        raise SystemExit(2)
    if row.get("verdict") not in ("PASS", "FAIL"):
        print("COS_GATE fairness-cos-throughput-headroom VOID reason=summary-verdict-invalid")
        raise SystemExit(2)
    key = (row.get("class"), row.get("port"), row.get("queue_id"))
    if not all(key) or key in by_scenario[scenario]:
        print("COS_GATE fairness-cos-throughput-headroom VOID reason=unpaired-row")
        raise SystemExit(2)
    try:
        avg = float(row["avg_mbps"])
        mean_gap = float(row["mean_gap"])
        max_gap = float(row["max_gap"])
        row_status = int(row["exit_status"])
    except (KeyError, TypeError, ValueError):
        print("COS_GATE fairness-cos-throughput-headroom VOID reason=summary-metric-invalid")
        raise SystemExit(2)
    if not all(math.isfinite(value) for value in (avg, mean_gap, max_gap)) or avg < 0 or row_status not in (0, 1):
        print("COS_GATE fairness-cos-throughput-headroom VOID reason=summary-metric-invalid")
        raise SystemExit(2)
    if (row["verdict"] == "PASS" and row_status != 0) or (row["verdict"] == "FAIL" and row_status != 1):
        print("COS_GATE fairness-cos-throughput-headroom VOID reason=summary-exit-disagree")
        raise SystemExit(2)
    by_scenario[scenario][key] = {
        "avg": avg, "gap": max_gap, "verdict": row["verdict"]
    }
strict = by_scenario["strict"]
surplus = by_scenario["surplus-sharing"]
if not strict or strict.keys() != surplus.keys():
    print("COS_GATE fairness-cos-throughput-headroom VOID reason=unpaired-rows")
    raise SystemExit(2)
strict_sum = sum(row["avg"] for row in strict.values())
surplus_sum = sum(row["avg"] for row in surplus.values())
delta = surplus_sum - strict_sum
if strict_sum == 0 and delta != 0:
    print("COS_GATE fairness-cos-throughput-headroom VOID reason=delta-percent-undefined")
    raise SystemExit(2)
delta_pct = (delta / strict_sum * 100) if strict_sum else 0.0
strict_failed = sum(row["verdict"] == "FAIL" for row in strict.values())
surplus_failed = sum(row["verdict"] == "FAIL" for row in surplus.values())
failed_total = sum(
    strict[key]["verdict"] == "FAIL" or surplus[key]["verdict"] == "FAIL"
    for key in strict
)
max_strict = max(row["gap"] for row in strict.values())
max_surplus = max(row["gap"] for row in surplus.values())
with open(paired_path, "w", newline="", encoding="utf-8") as fh:
    writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
    writer.writerow((
        "class", "port", "queue_id", "strict_avg_mbps", "surplus_avg_mbps",
        "delta_mbps", "delta_pct", "strict_verdict", "surplus_verdict"
    ))
    for key in sorted(strict):
        a, b = strict[key], surplus[key]
        diff = b["avg"] - a["avg"]
        if a["avg"] == 0 and diff != 0:
            print("COS_GATE fairness-cos-throughput-headroom VOID reason=delta-percent-undefined")
            raise SystemExit(2)
        diff_pct = diff / a["avg"] * 100 if a["avg"] else 0.0
        writer.writerow((
            key[0], key[1], key[2], f'{a["avg"]:.6f}', f'{b["avg"]:.6f}',
            f"{diff:.6f}", f"{diff_pct:.6f}", a["verdict"], b["verdict"]
        ))
verdict = "FAIL" if failed_total else "PASS"
if (status == 0 and verdict != "PASS") or (status == 1 and verdict != "FAIL"):
    print("COS_GATE fairness-cos-throughput-headroom VOID reason=summary-exit-disagree")
    raise SystemExit(2)
print(
    "COS_GATE fairness-cos-throughput-headroom "
    f"{verdict} reason=-- classes_failed_total={failed_total} "
    f"strict_sum_class_avg_mbps={strict_sum:.6f} "
    f"surplus_sum_class_avg_mbps={surplus_sum:.6f} "
    f"paired_sum_class_avg_delta_mbps={delta:.6f} "
    f"paired_sum_class_avg_delta_pct={delta_pct:.6f} "
    f"classes_failed_strict={strict_failed} classes_failed_surplus={surplus_failed} "
    f"max_gap_strict={max_strict:.6f} max_gap_surplus={max_surplus:.6f}"
)
raise SystemExit(status)
PY
)
gate_status=$?
if ! {
    printf '# CoS Throughput Headroom Comparison\n\n'
    printf 'Artifacts: `%s`\n\n' "$ARTIFACT_ROOT"
    printf 'Class filter: `%s`\n\n' "$CLASS_FILTER"
    printf 'Metrics URL: `%s`; CoS ifindex: `%s`; target: `%s`\n\n' "$METRICS_URL" "$COS_IFINDEX" "$IPERF_TARGET4"
    printf 'Strict/surplus sums are diagnostic sums of per-class `avg_mbps` from separate sequential trials; they are not simultaneous aggregate bandwidth and are not pass thresholds.\n\n'
    printf '| Scenario | Class | Queue | Verdict | Avg Mbps | Avg rate utilization | Mean CoV | Max CoV | Mean Gap | Max Gap | Starved |\n'
    printf '|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|\n'
    tail -n +2 "$SUMMARY_TSV" | while IFS=$'\t' read -r scenario class _port queue _rate _status verdict mean max _stdev mbps util _cstruct mean_gap max_gap starved _per_run; do
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$scenario" "$class" "$queue" "$verdict" "$mbps" "$util" "$mean" "$max" "$mean_gap" "$max_gap" "$starved"
    done
    if [[ -f "$ARTIFACT_ROOT/paired-summary.tsv" ]]; then
        printf '\n## Paired Per-Class Diagnostic\n\n'
        printf '| Class | Port | Queue | Strict avg Mbps | Surplus avg Mbps | Delta Mbps | Delta %% | Strict verdict | Surplus verdict |\n'
        printf '|---|---:|---:|---:|---:|---:|---:|---|---|\n'
        tail -n +2 "$ARTIFACT_ROOT/paired-summary.tsv" | while IFS=$'\t' read -r class port queue strict_avg surplus_avg delta delta_pct strict_verdict surplus_verdict; do
            printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
                "$class" "$port" "$queue" "$strict_avg" "$surplus_avg" "$delta" "$delta_pct" "$strict_verdict" "$surplus_verdict"
        done
    fi
} > "$SUMMARY_MD"; then
    echo "fairness-cos-throughput-headroom: failed to write $SUMMARY_MD" >&2
    overall_status=2
fi

echo "fairness-cos-throughput-headroom: wrote $SUMMARY_TSV"
echo "fairness-cos-throughput-headroom: wrote $SUMMARY_MD"
if [[ "$overall_status" -eq 2 && "$gate_status" -ne 2 ]]; then
    gate_line="COS_GATE fairness-cos-throughput-headroom VOID reason=artifact-write-failed"
    gate_status=2
fi
if [[ -z "$gate_line" ]]; then
    gate_line="COS_GATE fairness-cos-throughput-headroom VOID reason=aggregation-failed"
    gate_status=2
fi
COS_GATE_EMITTED=1
printf '%s\n' "$gate_line"
exit "$gate_status"
