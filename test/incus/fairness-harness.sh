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
#   fairness-harness.sh --mixed-cos-isolated [TARGET] [PORT] [N] [DURATION] [REVERSE] [METRICS_URL]
#
# Mixed CoS mode defaults to canonical fixture ports 5201 (queue 4)
# and 5202 (queue 5) and evaluates each class separately from the
# same live xpf_userspace_cos_active_flow_count scrape. Set COS_IFINDEX
# to the shaped egress ifindex. Override COS_QUEUE_ID /
# MIXED_COS_QUEUE_ID only for non-canonical fixtures. In mixed mode the
# harness infers SHAPER_RATE_BPS / MIXED_SHAPER_RATE_BPS from canonical
# fixture ports; set them explicitly for non-canonical fixtures.
# MIXED_RSS_EXPECTATION inherits RSS_EXPECTATION by default; set
# MIXED_RSS_EXPECTATION=any when only the primary class should enforce
# an RSS/workload expectation.
#
# --mixed-cos-isolated keeps the mixed-CoS evaluator but requires explicit
# generator placement knobs so the two classes can be separated for hostile
# reviews. Supported knobs:
#   IPERF_NETNS / MIXED_IPERF_NETNS         optional `ip netns exec` namespaces
#   IPERF_CPUSET / MIXED_IPERF_CPUSET       optional `taskset -c` CPU lists
#   IPERF_CMD_PREFIX / MIXED_IPERF_CMD_PREFIX
#                                           optional command prefix words
#   IPERF_BIN / MIXED_IPERF_BIN             generator binary, default iperf3
#   PRIMARY_RSS_STEERING / MIXED_RSS_STEERING
#                                           free-form NIC/RSS assumption notes
#   ARTIFACT_DIR                            placement artifact directory
#
# Defaults match the existing iperf-c P=12 -R workload that produced the
# 47% per-flow CoV measurement that motivates the harness.

set -euo pipefail

MIXED_COS=${MIXED_COS:-0}
ISOLATED_GENERATORS=${ISOLATED_GENERATORS:-0}
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --mixed-cos) MIXED_COS=1; shift ;;
        --mixed-cos-isolated) MIXED_COS=1; ISOLATED_GENERATORS=1; shift ;;
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
SHAPER_RATE_BPS=${SHAPER_RATE_BPS:-}
MIXED_SHAPER_RATE_BPS=${MIXED_SHAPER_RATE_BPS:-}
RSS_EXPECTATION=${RSS_EXPECTATION:-any}
MIXED_RSS_EXPECTATION=${MIXED_RSS_EXPECTATION:-$RSS_EXPECTATION}
WARMUP=${WARMUP:-5}
FINAL_BURST=${FINAL_BURST:-1}
ARTIFACT_DIR=${ARTIFACT_DIR:-}
IPERF_BIN=${IPERF_BIN:-iperf3}
MIXED_IPERF_BIN=${MIXED_IPERF_BIN:-$IPERF_BIN}
IPERF_NETNS=${IPERF_NETNS:-}
MIXED_IPERF_NETNS=${MIXED_IPERF_NETNS:-}
IPERF_CPUSET=${IPERF_CPUSET:-}
MIXED_IPERF_CPUSET=${MIXED_IPERF_CPUSET:-}
IPERF_CMD_PREFIX=${IPERF_CMD_PREFIX:-}
MIXED_IPERF_CMD_PREFIX=${MIXED_IPERF_CMD_PREFIX:-}
PRIMARY_RSS_STEERING=${PRIMARY_RSS_STEERING:-unspecified}
MIXED_RSS_STEERING=${MIXED_RSS_STEERING:-unspecified}
PRIMARY_GENERATOR_LABEL=${PRIMARY_GENERATOR_LABEL:-primary}
MIXED_GENERATOR_LABEL=${MIXED_GENERATOR_LABEL:-mixed}

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

canonical_shaper_rate_for_port() {
    case "$1" in
        5201) printf '1000000000\n' ;;
        5202) printf '10000000000\n' ;;
        5203) printf '25000000000\n' ;;
        5204) printf '13000000000\n' ;;
        5205) printf '16000000000\n' ;;
        5206) printf '19000000000\n' ;;
        5207) printf '100000000\n' ;;
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
    if [[ -z "$SHAPER_RATE_BPS" ]]; then
        if ! SHAPER_RATE_BPS=$(canonical_shaper_rate_for_port "$PORT"); then
            echo "fairness-harness: cannot infer SHAPER_RATE_BPS for PORT=$PORT; set SHAPER_RATE_BPS explicitly" >&2
            exit 2
        fi
    fi
    if [[ -z "$MIXED_SHAPER_RATE_BPS" ]]; then
        if ! MIXED_SHAPER_RATE_BPS=$(canonical_shaper_rate_for_port "$MIXED_PORT"); then
            echo "fairness-harness: cannot infer MIXED_SHAPER_RATE_BPS for MIXED_PORT=$MIXED_PORT; set MIXED_SHAPER_RATE_BPS explicitly" >&2
            exit 2
        fi
    fi
else
    SHAPER_RATE_BPS=${SHAPER_RATE_BPS:-25000000000}
fi

format_command() {
    local arg
    for arg in "$@"; do
        printf '%q ' "$arg"
    done
}

append_prefix_words() {
    local -n cmd_ref=$1
    local prefix=$2

    if [[ -n "$prefix" ]]; then
        local words=()
        # Intentionally word-split test-harness prefixes such as:
        #   incus exec loss:cluster-userspace-host --
        #   ip vrf exec blue
        # Prefixes that need shell quoting should be wrapped by a small
        # script and passed as IPERF_BIN instead.
        # shellcheck disable=SC2206
        words=( $prefix )
        cmd_ref+=("${words[@]}")
    fi
}

build_iperf_cmd() {
    local cmd_name=$1
    local -n cmd_ref=$cmd_name
    local port=$2
    local streams=$3
    local reverse_flag=$4
    local netns=$5
    local cpuset=$6
    local cmd_prefix=$7
    local iperf_bin=$8

    cmd_ref=()
    if [[ -n "$netns" ]]; then
        cmd_ref+=(ip netns exec "$netns")
    fi
    if [[ -n "$cpuset" ]]; then
        cmd_ref+=(taskset -c "$cpuset")
    fi
    append_prefix_words "$cmd_name" "$cmd_prefix"
    cmd_ref+=("$iperf_bin" -c "$TARGET" -P "$streams" -t "$T" -p "$port")
    append_prefix_words "$cmd_name" "$reverse_flag"
    cmd_ref+=(-J --forceflush)
}

generator_signature() {
    printf 'netns=%s|cpuset=%s|prefix=%s|bin=%s|rss=%s' \
        "$1" "$2" "$3" "$4" "$5"
}

validate_isolated_generators() {
    [[ "$ISOLATED_GENERATORS" -eq 1 ]] || return 0
    if [[ "$MIXED_COS" -ne 1 ]]; then
        echo "fairness-harness: isolated generator mode requires mixed CoS mode" >&2
        exit 2
    fi

    local has_isolation=0
    for value in \
        "$IPERF_NETNS" "$MIXED_IPERF_NETNS" \
        "$IPERF_CPUSET" "$MIXED_IPERF_CPUSET" \
        "$IPERF_CMD_PREFIX" "$MIXED_IPERF_CMD_PREFIX" \
        "$PRIMARY_RSS_STEERING" "$MIXED_RSS_STEERING"
    do
        if [[ -n "$value" && "$value" != "unspecified" ]]; then
            has_isolation=1
            break
        fi
    done
    if [[ "$has_isolation" -ne 1 ]]; then
        echo "fairness-harness: --mixed-cos-isolated requires CPU, netns, prefix, or RSS steering placement metadata" >&2
        exit 2
    fi

    if [[ -n "$IPERF_CPUSET" && -n "$MIXED_IPERF_CPUSET" && "$IPERF_CPUSET" == "$MIXED_IPERF_CPUSET" ]]; then
        echo "fairness-harness: isolated mode requires distinct IPERF_CPUSET and MIXED_IPERF_CPUSET when both are set" >&2
        exit 2
    fi

    local primary_sig
    local mixed_sig
    primary_sig=$(generator_signature "$IPERF_NETNS" "$IPERF_CPUSET" "$IPERF_CMD_PREFIX" "$IPERF_BIN" "$PRIMARY_RSS_STEERING")
    mixed_sig=$(generator_signature "$MIXED_IPERF_NETNS" "$MIXED_IPERF_CPUSET" "$MIXED_IPERF_CMD_PREFIX" "$MIXED_IPERF_BIN" "$MIXED_RSS_STEERING")
    if [[ "$primary_sig" == "$mixed_sig" ]]; then
        echo "fairness-harness: isolated mode primary and mixed generator placement are identical" >&2
        exit 2
    fi
}

setup_artifact_dir() {
    if [[ "$ISOLATED_GENERATORS" -eq 1 && -z "$ARTIFACT_DIR" ]]; then
        ARTIFACT_DIR=$(mktemp -d -t fairness-harness-artifacts.XXXXXX)
    fi
    if [[ -n "$ARTIFACT_DIR" ]]; then
        mkdir -p "$ARTIFACT_DIR"
    fi
}

write_placement_artifact() {
    [[ -n "$ARTIFACT_DIR" ]] || return 0

    local primary_cmd=()
    local mixed_cmd=()
    build_iperf_cmd primary_cmd "$PORT" "$N" "$REVERSE" "$IPERF_NETNS" "$IPERF_CPUSET" "$IPERF_CMD_PREFIX" "$IPERF_BIN"
    if [[ "$MIXED_COS" -eq 1 ]]; then
        build_iperf_cmd mixed_cmd "$MIXED_PORT" "$MIXED_N" "$MIXED_REVERSE" "$MIXED_IPERF_NETNS" "$MIXED_IPERF_CPUSET" "$MIXED_IPERF_CMD_PREFIX" "$MIXED_IPERF_BIN"
    fi

    local artifact="$ARTIFACT_DIR/generator-placement.txt"
    local mode=single
    if [[ "$ISOLATED_GENERATORS" -eq 1 ]]; then
        mode=mixed-cos-isolated
    elif [[ "$MIXED_COS" -eq 1 ]]; then
        mode=mixed-cos
    fi

    {
        printf 'mode=%s\n' "$mode"
        printf 'target=%s\n' "$TARGET"
        printf 'metrics_url=%s\n' "$METRICS_URL"
        printf 'duration_secs=%s\n' "$T"
        printf 'primary.label=%s\n' "$PRIMARY_GENERATOR_LABEL"
        printf 'primary.port=%s\n' "$PORT"
        printf 'primary.streams=%s\n' "$N"
        printf 'primary.reverse=%s\n' "$REVERSE"
        printf 'primary.cos_ifindex=%s\n' "${COS_IFINDEX:-}"
        printf 'primary.cos_queue_id=%s\n' "${COS_QUEUE_ID:-}"
        printf 'primary.shaper_rate_bps=%s\n' "${SHAPER_RATE_BPS:-}"
        printf 'primary.netns=%s\n' "$IPERF_NETNS"
        printf 'primary.cpuset=%s\n' "$IPERF_CPUSET"
        printf 'primary.cmd_prefix=%s\n' "$IPERF_CMD_PREFIX"
        printf 'primary.bin=%s\n' "$IPERF_BIN"
        printf 'primary.rss_steering=%s\n' "$PRIMARY_RSS_STEERING"
        printf 'primary.command=%s\n' "$(format_command "${primary_cmd[@]}")"
        if [[ "$MIXED_COS" -eq 1 ]]; then
            printf 'mixed.label=%s\n' "$MIXED_GENERATOR_LABEL"
            printf 'mixed.port=%s\n' "$MIXED_PORT"
            printf 'mixed.streams=%s\n' "$MIXED_N"
            printf 'mixed.reverse=%s\n' "$MIXED_REVERSE"
            printf 'mixed.cos_ifindex=%s\n' "${COS_IFINDEX:-}"
            printf 'mixed.cos_queue_id=%s\n' "${MIXED_COS_QUEUE_ID:-}"
            printf 'mixed.shaper_rate_bps=%s\n' "${MIXED_SHAPER_RATE_BPS:-}"
            printf 'mixed.netns=%s\n' "$MIXED_IPERF_NETNS"
            printf 'mixed.cpuset=%s\n' "$MIXED_IPERF_CPUSET"
            printf 'mixed.cmd_prefix=%s\n' "$MIXED_IPERF_CMD_PREFIX"
            printf 'mixed.bin=%s\n' "$MIXED_IPERF_BIN"
            printf 'mixed.rss_steering=%s\n' "$MIXED_RSS_STEERING"
            printf 'mixed.command=%s\n' "$(format_command "${mixed_cmd[@]}")"
        fi
    } > "$artifact"
    echo "fairness-harness: wrote generator placement artifact: $artifact"
}

validate_isolated_generators
setup_artifact_dir
write_placement_artifact

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
    local netns=${6:-}
    local cpuset=${7:-}
    local cmd_prefix=${8:-}
    local iperf_bin=${9:-iperf3}
    local cmd=()

    build_iperf_cmd cmd "$port" "$streams" "$reverse_flag" "$netns" "$cpuset" "$cmd_prefix" "$iperf_bin"
    echo "fairness-harness: running ${label}: $(format_command "${cmd[@]}")for ${T}s"
    "${cmd[@]}" > "$out"
}

run_eval() {
    local label=$1
    local iperf_out=$2
    local cos_queue_id=${3:-}
    local rss_expectation=${4:-$RSS_EXPECTATION}
    local shaper_rate_bps=${5:-$SHAPER_RATE_BPS}

    echo "fairness-harness: evaluating ${label}..."
    local eval_args=(
        --iperf-json "$iperf_out"
        --binding-flows "$BINDING_TSV"
        --iface "$IFACE"
        --warmup-secs "$WARMUP"
        --final-burst-secs "$FINAL_BURST"
        --n-workers "$N_WORKERS"
        --shaper-rate-bps "$shaper_rate_bps"
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
    run_iperf "primary port $PORT queue $COS_QUEUE_ID" "$IPERF_OUT" "$PORT" "$N" "$REVERSE" "$IPERF_NETNS" "$IPERF_CPUSET" "$IPERF_CMD_PREFIX" "$IPERF_BIN" &
    PRIMARY_PID=$!
    run_iperf "mixed port $MIXED_PORT queue $MIXED_COS_QUEUE_ID" "$MIXED_IPERF_OUT" "$MIXED_PORT" "$MIXED_N" "$MIXED_REVERSE" "$MIXED_IPERF_NETNS" "$MIXED_IPERF_CPUSET" "$MIXED_IPERF_CMD_PREFIX" "$MIXED_IPERF_BIN" &
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
    run_iperf "single" "$IPERF_OUT" "$PORT" "$N" "$REVERSE" "$IPERF_NETNS" "$IPERF_CPUSET" "$IPERF_CMD_PREFIX" "$IPERF_BIN"
fi

cleanup

if [[ "$MIXED_COS" -eq 1 ]]; then
    set +e
    run_eval "primary port $PORT queue $COS_QUEUE_ID" "$IPERF_OUT" "$COS_QUEUE_ID" "$RSS_EXPECTATION" "$SHAPER_RATE_BPS"
    PRIMARY_EVAL_STATUS=$?
    run_eval "mixed port $MIXED_PORT queue $MIXED_COS_QUEUE_ID" "$MIXED_IPERF_OUT" "$MIXED_COS_QUEUE_ID" "$MIXED_RSS_EXPECTATION" "$MIXED_SHAPER_RATE_BPS"
    MIXED_EVAL_STATUS=$?
    set -e
    if [[ "$PRIMARY_EVAL_STATUS" -eq 2 || "$MIXED_EVAL_STATUS" -eq 2 ]]; then
        exit 2
    fi
    if [[ "$PRIMARY_EVAL_STATUS" -ne 0 ]]; then
        exit "$PRIMARY_EVAL_STATUS"
    fi
    exit "$MIXED_EVAL_STATUS"
fi

run_eval "single" "$IPERF_OUT" "$COS_QUEUE_ID" "$RSS_EXPECTATION"
