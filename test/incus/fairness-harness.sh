#!/usr/bin/env bash
# fairness-harness.sh — run iperf3, scrape /metrics, compute fairness gates.
#
# Per docs/fairness-regimes.md and docs/pr/1219-fairness-harness/plan.md:
# - runs iperf3 -P N -J --forceflush against $TARGET on $PORT for $T seconds
#   (or, with --mixed-cos / MIXED_COS=1, concurrently runs the primary
#   port and MIXED_PORT under one metrics scrape)
# - in parallel, scrapes the daemon's /metrics endpoint every 1 s and
#   extracts xpf_userspace_binding_active_flow_count{binding_slot=N}
#   and, when COS_IFINDEX/COS_QUEUE_ID are set, the class-specific
#   xpf_userspace_cos_active_flow_count metric
# - feeds both inputs into the fairness-eval Rust binary, which emits a
#   verdict JSON
# - exits 0 on PASS, 1 on FAIL, 2 on parse/IO error
#
# Usage:
#   fairness-harness.sh [TARGET] [PORT] [N] [DURATION] [REVERSE] [METRICS_URL]
#   fairness-harness.sh --mixed-cos [TARGET] [PORT] [N] [DURATION] [REVERSE] [METRICS_URL]
#
# Mixed CoS mode defaults to canonical fixture ports 5201 (queue 4)
# and 5202 (queue 5) and evaluates each class separately from the
# same live xpf_userspace_cos_active_flow_count scrape. Set COS_IFINDEX
# to the shaped egress ifindex. Override COS_QUEUE_ID /
# MIXED_COS_QUEUE_ID only for non-canonical fixtures.
#
# Defaults match the existing iperf-c P=12 -R workload that produced the
# 47% per-flow CoV measurement that motivates the harness.

set -euo pipefail

MIXED_COS=${MIXED_COS:-0}
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --mixed-cos) MIXED_COS=1; shift ;;
        --) shift; break ;;
        *) echo "fairness-harness: unknown flag $1" >&2; exit 2 ;;
    esac
done

TARGET=${1:-172.16.80.200}
if [[ "$MIXED_COS" -eq 1 ]]; then
    DEFAULT_PORT=5201
else
    DEFAULT_PORT=5203
fi
PORT=${2:-$DEFAULT_PORT}
N=${3:-12}
T=${4:-120}
REVERSE=${5:--R}
METRICS_URL=${6:-http://127.0.0.1:8080/metrics}
# IFACE filters per-binding samples to one interface so {a_i} reflects
# per-worker counts for the test's data direction, not bidirectional
# entries summed across all interfaces (Codex round-3 + Gemini round-1
# fatal: aggregating across WAN+LAN+FABRIC produces fictitious Cstruct).
IFACE=${IFACE:-ge-0-0-2}
COS_IFINDEX=${COS_IFINDEX:-}
COS_QUEUE_ID=${COS_QUEUE_ID:-}
MIXED_PORT=${MIXED_PORT:-5202}
MIXED_N=${MIXED_N:-$N}
MIXED_REVERSE=${MIXED_REVERSE:-$REVERSE}
MIXED_COS_QUEUE_ID=${MIXED_COS_QUEUE_ID:-}
N_WORKERS=${N_WORKERS:-6}
SHAPER_RATE_BPS=${SHAPER_RATE_BPS:-25000000000}
RSS_EXPECTATION=${RSS_EXPECTATION:-any}
MIXED_RSS_EXPECTATION=${MIXED_RSS_EXPECTATION:-$RSS_EXPECTATION}
WARMUP=${WARMUP:-5}
FINAL_BURST=${FINAL_BURST:-1}

WORK_DIR=$(mktemp -d -t fairness-harness.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT

IPERF_OUT="$WORK_DIR/iperf-out.json"
MIXED_IPERF_OUT="$WORK_DIR/iperf-out-mixed.json"
BINDING_TSV="$WORK_DIR/binding-flows.tsv"
COS_TSV="$WORK_DIR/cos-flows.tsv"

FAIRNESS_EVAL=${FAIRNESS_EVAL:-/usr/local/bin/fairness-eval}
if [ ! -x "$FAIRNESS_EVAL" ]; then
    # Try cargo target dir as fallback for local development.
    for c in /dev/shm/cargo/release/fairness-eval ./target/release/fairness-eval ./userspace-dp/target/release/fairness-eval; do
        if [ -x "$c" ]; then FAIRNESS_EVAL=$c; break; fi
    done
fi
if [ ! -x "$FAIRNESS_EVAL" ]; then
    echo "fairness-harness: fairness-eval binary not found (tried $FAIRNESS_EVAL)" >&2
    echo "  build with: cargo build --release --bin fairness-eval" >&2
    exit 2
fi

canonical_cos_queue_for_port() {
    case "$1" in
        5201) printf '4\n' ;;
        5202) printf '5\n' ;;
        5203) printf '6\n' ;;
        5204) printf '1\n' ;;
        5205) printf '2\n' ;;
        5206) printf '3\n' ;;
        5207) printf '0\n' ;;
        *) return 1 ;;
    esac
}

if [[ "$MIXED_COS" -eq 1 ]]; then
    if [[ -z "$COS_IFINDEX" ]]; then
        echo "fairness-harness: --mixed-cos requires COS_IFINDEX for the shaped egress interface" >&2
        exit 2
    fi
    if [[ -z "$COS_QUEUE_ID" ]]; then
        if ! COS_QUEUE_ID=$(canonical_cos_queue_for_port "$PORT"); then
            echo "fairness-harness: cannot infer COS_QUEUE_ID for PORT=$PORT; set COS_QUEUE_ID explicitly" >&2
            exit 2
        fi
    fi
    if [[ -z "$MIXED_COS_QUEUE_ID" ]]; then
        if ! MIXED_COS_QUEUE_ID=$(canonical_cos_queue_for_port "$MIXED_PORT"); then
            echo "fairness-harness: cannot infer MIXED_COS_QUEUE_ID for MIXED_PORT=$MIXED_PORT; set MIXED_COS_QUEUE_ID explicitly" >&2
            exit 2
        fi
    fi
fi

scrape_metrics() {
    local binding_out=$1
    local cos_out=$2
    # Columns: timestamp, binding_slot, queue_id, worker_id, iface, count.
    # The harness needs all labels so fairness-eval can filter by iface
    # and aggregate by worker_id (NOT by binding_slot — that confuses
    # the contract's per-worker {a_i} with per-binding counts spread
    # across multiple interfaces).
    printf '# timestamp\tbinding_slot\tqueue_id\tworker_id\tiface\tcount\n' > "$binding_out"
    # Columns: timestamp, ifindex, queue_id, worker_id, count.
    printf '# timestamp\tifindex\tqueue_id\tworker_id\tcount\n' > "$cos_out"
    while true; do
        local ts
        local metrics
        ts=$(date +%s)
        metrics=$(curl -sS --max-time 1 "$METRICS_URL" 2>/dev/null || true)
        # Portable parse: grep the metric lines, then sed extracts all
        # 4 labels + the value. Avoids gawk-only match() which fails
        # on mawk.
        # Label order is alphabetical (binding_slot < iface < queue_id <
        # worker_id): the Prometheus Go client always emits labels sorted
        # lexicographically regardless of the descriptor order, so this
        # regex is deterministic across prometheus-client versions.
        if ! printf '%s\n' "$metrics" \
            | grep '^xpf_userspace_binding_active_flow_count{' \
            | sed -nE 's/^[^\{]*\{binding_slot="([0-9]+)",iface="([^"]+)",queue_id="([0-9]+)",worker_id="([0-9]+)"\} ([0-9]+).*$/\1\t\3\t\4\t\2\t\5/p' \
            | awk -v ts="$ts" -F'\t' '{ printf "%s\t%s\t%s\t%s\t%s\t%s\n", ts, $1, $2, $3, $4, $5 }' >> "$binding_out"; then
            : # parse glitch; keep going
        fi
        if ! printf '%s\n' "$metrics" \
            | grep '^xpf_userspace_cos_active_flow_count{' \
            | sed -nE 's/^[^\{]*\{ifindex="(-?[0-9]+)",queue_id="([0-9]+)",worker_id="([0-9]+)"\} ([0-9]+).*$/\1\t\2\t\3\t\4/p' \
            | awk -v ts="$ts" -F'\t' '{ printf "%s\t%s\t%s\t%s\t%s\n", ts, $1, $2, $3, $4 }' >> "$cos_out"; then
            : # network glitch; keep going
        fi
        sleep 1
    done
}

run_iperf() {
    local label=$1
    local out=$2
    local port=$3
    local streams=$4
    local reverse_flag=$5

    echo "fairness-harness: running ${label}: iperf3 -c $TARGET -P $streams -t $T -p $port $reverse_flag for ${T}s"
    iperf3 -c "$TARGET" -P "$streams" -t "$T" -p "$port" $reverse_flag -J --forceflush > "$out"
}

run_eval() {
    local label=$1
    local iperf_out=$2
    local cos_queue_id=${3:-}
    local rss_expectation=${4:-$RSS_EXPECTATION}

    echo "fairness-harness: evaluating ${label}..."
    local eval_args=(
        --iperf-json "$iperf_out"
        --binding-flows "$BINDING_TSV"
        --iface "$IFACE"
        --warmup-secs "$WARMUP"
        --final-burst-secs "$FINAL_BURST"
        --n-workers "$N_WORKERS"
        --shaper-rate-bps "$SHAPER_RATE_BPS"
        --rss-expectation "$rss_expectation"
    )
    if [[ -n "$COS_IFINDEX" && -n "$cos_queue_id" ]]; then
        eval_args+=(
            --cos-flows "$COS_TSV"
            --cos-ifindex "$COS_IFINDEX"
            --cos-queue-id "$cos_queue_id"
        )
    fi
    "$FAIRNESS_EVAL" "${eval_args[@]}"
}

scrape_metrics "$BINDING_TSV" "$COS_TSV" &
SCRAPE_PID=$!

cleanup() {
    kill "$SCRAPE_PID" 2>/dev/null || true
    wait "$SCRAPE_PID" 2>/dev/null || true
}
trap 'cleanup; rm -rf "$WORK_DIR"' EXIT

if [[ "$MIXED_COS" -eq 1 ]]; then
    run_iperf "primary port $PORT queue $COS_QUEUE_ID" "$IPERF_OUT" "$PORT" "$N" "$REVERSE" &
    PRIMARY_PID=$!
    run_iperf "mixed port $MIXED_PORT queue $MIXED_COS_QUEUE_ID" "$MIXED_IPERF_OUT" "$MIXED_PORT" "$MIXED_N" "$MIXED_REVERSE" &
    MIXED_PID=$!

    IPERF_STATUS=0
    if wait "$PRIMARY_PID"; then :; else IPERF_STATUS=$?; fi
    if wait "$MIXED_PID"; then
        :
    else
        MIXED_WAIT_STATUS=$?
        if [[ "$IPERF_STATUS" -eq 0 ]]; then
            IPERF_STATUS=$MIXED_WAIT_STATUS
        fi
    fi
    if [[ "$IPERF_STATUS" -ne 0 ]]; then
        cleanup
        exit "$IPERF_STATUS"
    fi
else
    run_iperf "single" "$IPERF_OUT" "$PORT" "$N" "$REVERSE"
fi

cleanup

if [[ "$MIXED_COS" -eq 1 ]]; then
    set +e
    run_eval "primary port $PORT queue $COS_QUEUE_ID" "$IPERF_OUT" "$COS_QUEUE_ID" "$RSS_EXPECTATION"
    PRIMARY_EVAL_STATUS=$?
    run_eval "mixed port $MIXED_PORT queue $MIXED_COS_QUEUE_ID" "$MIXED_IPERF_OUT" "$MIXED_COS_QUEUE_ID" "$MIXED_RSS_EXPECTATION"
    MIXED_EVAL_STATUS=$?
    set -e
    if [[ "$PRIMARY_EVAL_STATUS" -ne 0 ]]; then
        exit "$PRIMARY_EVAL_STATUS"
    fi
    exit "$MIXED_EVAL_STATUS"
fi

run_eval "single" "$IPERF_OUT" "$COS_QUEUE_ID" "$RSS_EXPECTATION"
