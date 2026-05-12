#!/usr/bin/env bash
# Run fairness_multi_sample.py across every canonical CoS fixture class.
#
# This is intentionally a sequential qualification harness: each class gets its
# own sample directory and verdict, then the script emits an aggregate summary
# and returns non-zero if any class fails its multi-sample thresholds.

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

TARGET=${TARGET:-172.16.80.200}
N=${N:-12}
DURATION=${DURATION:-75}
REVERSE=${REVERSE:--R}
METRICS_URL=${METRICS_URL:-http://127.0.0.1:8080/metrics}
IFACE=${IFACE:-ge-0-0-2}
COS_IFINDEX=${COS_IFINDEX:-}
SAMPLES=${SAMPLES:-3}
PER_RUN_TIMEOUT_SEC=${PER_RUN_TIMEOUT_SEC:-180}
ARTIFACT_ROOT=${ARTIFACT_ROOT:-/tmp/cos-fairness-all-$(date +%Y%m%d-%H%M%S)}
HARNESS=${HARNESS:-$ROOT_DIR/test/incus/fairness-harness.sh}
WRAPPER=${WRAPPER:-$ROOT_DIR/test/incus/fairness_multi_sample.py}
FAIRNESS_EVAL=${FAIRNESS_EVAL:-$ROOT_DIR/userspace-dp/target/release/fairness-eval}

if [[ -z "$COS_IFINDEX" ]]; then
    echo "fairness-cos-class-sweep: COS_IFINDEX is required for the shaped egress interface" >&2
    exit 2
fi
if [[ ! -x "$HARNESS" ]]; then
    echo "fairness-cos-class-sweep: harness is not executable: $HARNESS" >&2
    exit 2
fi
if [[ ! -x "$WRAPPER" ]]; then
    echo "fairness-cos-class-sweep: wrapper is not executable: $WRAPPER" >&2
    exit 2
fi
if [[ ! -x "$FAIRNESS_EVAL" ]]; then
    echo "fairness-cos-class-sweep: fairness-eval is not executable: $FAIRNESS_EVAL" >&2
    echo "  build with: cargo build --manifest-path userspace-dp/Cargo.toml --release --bin fairness-eval" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "fairness-cos-class-sweep: jq is required to build the aggregate summary" >&2
    exit 2
fi

mkdir -p "$ARTIFACT_ROOT"
SUMMARY_TSV="$ARTIFACT_ROOT/summary.tsv"
SUMMARY_MD="$ARTIFACT_ROOT/summary.md"

cat > "$SUMMARY_TSV" <<'HEADER'
class	port	queue_id	rate_bps	exit_status	verdict	mean_observed_cov	max_observed_cov	stdev_observed_cov	avg_mbps	avg_cstruct	avg_gap	starved_flows	per_run_verdicts
HEADER

classes=(
    "q0-best-effort-100m 5207 0 100000000"
    "q4-iperf-a-1g 5201 4 1000000000"
    "q5-iperf-b-10g 5202 5 10000000000"
    "q1-iperf-d-13g 5204 1 13000000000"
    "q2-iperf-e-16g 5205 2 16000000000"
    "q3-iperf-f-19g 5206 3 19000000000"
    "q6-iperf-c-25g 5203 6 25000000000"
)

overall_status=0
for spec in "${classes[@]}"; do
    read -r label port queue rate <<< "$spec"
    out="$ARTIFACT_ROOT/$label"
    mkdir -p "$out"

    echo "=== $(date -Is) class=$label port=$port queue=$queue rate=$rate ==="
    env \
        FAIRNESS_EVAL="$FAIRNESS_EVAL" \
        COS_IFINDEX="$COS_IFINDEX" \
        COS_QUEUE_ID="$queue" \
        SHAPER_RATE_BPS="$rate" \
        IFACE="$IFACE" \
        "$WRAPPER" \
            --samples "$SAMPLES" \
            --out-dir "$out/samples" \
            --per-run-timeout-sec "$PER_RUN_TIMEOUT_SEC" \
            --harness "$HARNESS" \
            -- "$TARGET" "$port" "$N" "$DURATION" "$REVERSE" "$METRICS_URL" \
        > "$out/wrapper.stdout" 2> "$out/wrapper.stderr"
    status=$?
    if (( status == 2 )); then
        overall_status=2
    elif (( status != 0 && overall_status == 0 )); then
        overall_status=1
    fi

    summary_json="$out/samples/summary.json"
    if [[ -f "$summary_json" ]]; then
        jq -r \
            --arg class "$label" \
            --arg port "$port" \
            --arg queue "$queue" \
            --arg rate "$rate" \
            --arg status "$status" \
            '[
                $class,
                $port,
                $queue,
                $rate,
                $status,
                .verdict,
                (.observed_cov.mean | tostring),
                (.observed_cov.max | tostring),
                (.observed_cov.sample_stdev | tostring),
                (([.samples[].aggregate_mbps] | add / length) | tostring),
                (([.samples[].cstruct] | add / length) | tostring),
                (([.samples[].gap] | add / length) | tostring),
                (([.samples[].starved_flow_count] | add) | tostring),
                ([.samples[].verdict] | join(","))
            ] | @tsv' "$summary_json" >> "$SUMMARY_TSV"
        jq '{verdict, observed_cov, samples: [.samples[] | {sample, verdict, aggregate_mbps, observed_cov, cstruct, gap, starved_flow_count}]}' "$summary_json"
    else
        printf '%s\t%s\t%s\t%s\t%s\tERROR\t-\t-\t-\t-\t-\t-\t-\t-\n' \
            "$label" "$port" "$queue" "$rate" "$status" >> "$SUMMARY_TSV"
        sed -n '1,80p' "$out/wrapper.stderr" >&2
    fi
done

{
    printf '# CoS Fairness Class Sweep\n\n'
    printf 'Artifacts: `%s`\n\n' "$ARTIFACT_ROOT"
    printf 'Target: `%s`, streams: `%s`, duration: `%s`, reverse: `%s`, metrics: `%s`, cos_ifindex: `%s`\n\n' \
        "$TARGET" "$N" "$DURATION" "$REVERSE" "$METRICS_URL" "$COS_IFINDEX"
    printf '| Class | Port | Queue | Verdict | Mean CoV | Max CoV | Stdev CoV | Avg Mbps | Avg Cstruct | Avg Gap | Starved | Per-run |\n'
    printf '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n'
    tail -n +2 "$SUMMARY_TSV" | while IFS=$'\t' read -r class port queue _rate _status verdict mean max stdev mbps cstruct gap starved per_run; do
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$class" "$port" "$queue" "$verdict" "$mean" "$max" "$stdev" "$mbps" "$cstruct" "$gap" "$starved" "$per_run"
    done
} > "$SUMMARY_MD"

echo "fairness-cos-class-sweep: wrote $SUMMARY_TSV"
echo "fairness-cos-class-sweep: wrote $SUMMARY_MD"
exit "$overall_status"
