#!/usr/bin/env bash
# fairness-harness.sh — run iperf3, scrape /metrics, compute fairness gates.
#
# Per docs/fairness-regimes.md and docs/pr/1219-fairness-harness/plan.md:
# - runs iperf3 -P N -J --forceflush against $TARGET on $PORT for $T seconds
# - in parallel, scrapes the daemon's /metrics endpoint every 1 s and
#   extracts xpf_userspace_binding_active_flow_count{binding_slot=N}
# - feeds both inputs into the fairness-eval Rust binary, which emits a
#   verdict JSON
# - exits 0 on PASS, 1 on FAIL, 2 on parse/IO error
#
# Usage:
#   fairness-harness.sh [TARGET] [PORT] [N] [DURATION] [REVERSE] [METRICS_URL]
#
# Defaults match the existing iperf-c P=12 -R workload that produced the
# 47% per-flow CoV measurement that motivates the harness.

set -euo pipefail

TARGET=${1:-172.16.80.200}
PORT=${2:-5203}
N=${3:-12}
T=${4:-120}
REVERSE=${5:--R}
METRICS_URL=${6:-http://127.0.0.1:8080/metrics}
N_WORKERS=${N_WORKERS:-6}
SHAPER_RATE_BPS=${SHAPER_RATE_BPS:-25000000000}
WARMUP=${WARMUP:-5}
FINAL_BURST=${FINAL_BURST:-1}

WORK_DIR=$(mktemp -d -t fairness-harness.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT

IPERF_OUT="$WORK_DIR/iperf-out.json"
BINDING_TSV="$WORK_DIR/binding-flows.tsv"

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

scrape_metrics() {
    local out=$1
    printf '# timestamp\tbinding_slot\tcount\n' > "$out"
    while true; do
        local ts
        ts=$(date +%s)
        # Portable parse: grep the metric lines, then sed extracts
        # binding_slot=N and the trailing value. Avoids gawk-only
        # match($0, /re/, arr) which fails on mawk.
        if ! curl -sS --max-time 1 "$METRICS_URL" 2>/dev/null \
            | grep '^xpf_userspace_binding_active_flow_count{' \
            | sed -nE 's/^[^\{]*\{[^}]*binding_slot="([0-9]+)"[^}]*\} ([0-9]+).*$/\1\t\2/p' \
            | awk -v ts="$ts" -F'\t' '{ printf "%s\t%s\t%s\n", ts, $1, $2 }' >> "$out"; then
            : # network glitch; keep going
        fi
        sleep 1
    done
}

scrape_metrics "$BINDING_TSV" &
SCRAPE_PID=$!

cleanup() {
    kill "$SCRAPE_PID" 2>/dev/null || true
    wait "$SCRAPE_PID" 2>/dev/null || true
}
trap 'cleanup; rm -rf "$WORK_DIR"' EXIT

echo "fairness-harness: running iperf3 -c $TARGET -P $N -t $T -p $PORT $REVERSE for ${T}s"
iperf3 -c "$TARGET" -P "$N" -t "$T" -p "$PORT" $REVERSE -J --forceflush > "$IPERF_OUT"

cleanup

echo "fairness-harness: evaluating..."
"$FAIRNESS_EVAL" \
    --iperf-json "$IPERF_OUT" \
    --binding-flows "$BINDING_TSV" \
    --warmup-secs "$WARMUP" \
    --final-burst-secs "$FINAL_BURST" \
    --n-workers "$N_WORKERS" \
    --shaper-rate-bps "$SHAPER_RATE_BPS"
