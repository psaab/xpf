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
# Mixed CoS mode defaults to canonical fixture ports 5202 (queue 2,
# 1 Gbps exact) and 5205 (queue 5, 9 Gbps exact) and evaluates each
# class separately from the
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
# compute AND network isolation so the two classes can be separated for
# hostile reviews. Supported knobs:
#   IPERF_CPUSET / MIXED_IPERF_CPUSET       generator `taskset -c` CPU lists;
#                                           required and must not overlap
#   CPUSET_MAX_CPU_ID                       optional max generator CPU id;
#                                           defaults to local CPU topology
#   IPERF_NETNS / MIXED_IPERF_NETNS         generator-context netns names;
#                                           distinct names count as network
#                                           isolation
#   IPERF_NETWORK_ID / MIXED_IPERF_NETWORK_ID
#                                           explicit network/RSS/NIC domains;
#                                           distinct values count as network
#                                           isolation
#   IPERF_LAUNCH_ARG_0..N / MIXED_IPERF_LAUNCH_ARG_0..N
#                                           local launcher argv, e.g.
#                                           incus exec host --
#   IPERF_GENERATOR_ARG_0..N / MIXED_IPERF_GENERATOR_ARG_0..N
#                                           generator-context argv before
#                                           iperf3, e.g. numactl args
#   IPERF_LAUNCH_NETNS / MIXED_IPERF_LAUNCH_NETNS
#                                           optional local launcher netns
#   IPERF_LAUNCH_CPUSET / MIXED_IPERF_LAUNCH_CPUSET
#                                           optional local launcher cpuset
#   IPERF_BIN / MIXED_IPERF_BIN             generator binary, default iperf3
#   PRIMARY_RSS_STEERING / MIXED_RSS_STEERING
#                                           free-form NIC/RSS audit notes
#   ARTIFACT_DIR                            placement artifact directory
#
# Defaults track the high-rate canonical CoS grid: single-class mode
# uses port 5210 (24 Gbps exact), while mixed mode compares the 1 Gbps
# and 9 Gbps exact classes.

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
    DEFAULT_PORT=5202
else
    DEFAULT_PORT=5210
fi
PORT=${2:-$DEFAULT_PORT}
N=${3:-12}
T=${4:-120}
# Default to the historical reverse fixture only when the argument is
# absent. An explicit empty fifth argument selects forward mode.
REVERSE=${5--R}
METRICS_URL=${6:-http://127.0.0.1:8080/metrics}
# IFACE filters per-binding samples to one interface so {a_i} reflects
# per-worker counts for the test's data direction, not bidirectional
# entries summed across all interfaces (Codex round-3 + Gemini round-1
# fatal: aggregating across WAN+LAN+FABRIC produces fictitious Cstruct).
IFACE=${IFACE:-ge-0-0-2}
COS_IFINDEX=${COS_IFINDEX:-}
COS_QUEUE_ID=${COS_QUEUE_ID:-}
MIXED_PORT=${MIXED_PORT:-5205}
MIXED_N=${MIXED_N:-$N}
# Preserve an explicit empty MIXED_REVERSE so mixed forward fixtures do
# not silently inherit reverse mode.
MIXED_REVERSE=${MIXED_REVERSE-$REVERSE}
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
IPERF_LAUNCH_NETNS=${IPERF_LAUNCH_NETNS:-}
MIXED_IPERF_LAUNCH_NETNS=${MIXED_IPERF_LAUNCH_NETNS:-}
IPERF_LAUNCH_CPUSET=${IPERF_LAUNCH_CPUSET:-}
MIXED_IPERF_LAUNCH_CPUSET=${MIXED_IPERF_LAUNCH_CPUSET:-}
IPERF_NETNS=${IPERF_NETNS:-}
MIXED_IPERF_NETNS=${MIXED_IPERF_NETNS:-}
IPERF_CPUSET=${IPERF_CPUSET:-}
MIXED_IPERF_CPUSET=${MIXED_IPERF_CPUSET:-}
CPUSET_MAX_CPU_ID=${CPUSET_MAX_CPU_ID:-}
CPUSET_HARD_MAX_CPU_ID=${CPUSET_HARD_MAX_CPU_ID:-8191}
IPERF_CMD_PREFIX=${IPERF_CMD_PREFIX:-}
MIXED_IPERF_CMD_PREFIX=${MIXED_IPERF_CMD_PREFIX:-}
IPERF_NETWORK_ID=${IPERF_NETWORK_ID:-}
MIXED_IPERF_NETWORK_ID=${MIXED_IPERF_NETWORK_ID:-}
PRIMARY_RSS_STEERING=${PRIMARY_RSS_STEERING:-unspecified}
MIXED_RSS_STEERING=${MIXED_RSS_STEERING:-unspecified}
PRIMARY_GENERATOR_LABEL=${PRIMARY_GENERATOR_LABEL:-primary}
MIXED_GENERATOR_LABEL=${MIXED_GENERATOR_LABEL:-mixed}

if [[ -n "$IPERF_CMD_PREFIX" || -n "$MIXED_IPERF_CMD_PREFIX" ]]; then
    echo "fairness-harness: IPERF_CMD_PREFIX is deprecated; use IPERF_LAUNCH_ARG_N and IPERF_GENERATOR_ARG_N" >&2
    exit 2
fi

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
        5200|6200) printf '0\n' ;;
        5201|6201) printf '1\n' ;;
        5202|6202) printf '2\n' ;;
        5203|6203) printf '3\n' ;;
        5204|6204) printf '4\n' ;;
        5205|6205) printf '5\n' ;;
        5206|6206) printf '6\n' ;;
        5207|6207) printf '7\n' ;;
        5208|6208) printf '8\n' ;;
        5209|6209) printf '9\n' ;;
        5210|6210) printf '10\n' ;;
        5211|6211) printf '11\n' ;;
        *) return 1 ;;
    esac
}

canonical_shaper_rate_for_port() {
    case "$1" in
        5200|6200) printf '25000000000\n' ;;
        5201|6201) printf '100000000\n' ;;
        5202|6202) printf '1000000000\n' ;;
        5203|6203) printf '3000000000\n' ;;
        5204|6204) printf '6000000000\n' ;;
        5205|6205) printf '9000000000\n' ;;
        5206|6206) printf '12000000000\n' ;;
        5207|6207) printf '15000000000\n' ;;
        5208|6208) printf '18000000000\n' ;;
        5209|6209) printf '21000000000\n' ;;
        5210|6210) printf '24000000000\n' ;;
        5211|6211) printf '25000000000\n' ;;
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
    if [[ -z "$SHAPER_RATE_BPS" ]]; then
        if ! SHAPER_RATE_BPS=$(canonical_shaper_rate_for_port "$PORT"); then
            SHAPER_RATE_BPS=25000000000
        fi
    fi
fi

format_command() {
    local arg
    for arg in "$@"; do
        printf '%q ' "$arg"
    done
}

collect_numbered_args() {
    local prefix=$1
    local -n out_ref=$2
    local i=0
    local name
    local suffix
    local max_i=-1
    local -A seen=()
    out_ref=()

    while IFS= read -r name; do
        suffix=${name#"${prefix}_"}
        if [[ ! "$suffix" =~ ^(0|[1-9][0-9]*)$ ]]; then
            echo "fairness-harness: invalid numbered argv variable $name; expected canonical ${prefix}_N" >&2
            exit 2
        fi
        i=$((10#$suffix))
        if [[ "$i" != "$suffix" ]]; then
            echo "fairness-harness: invalid numbered argv variable $name; index exceeds shell arithmetic range" >&2
            exit 2
        fi
        seen["$i"]=$name
        (( i > max_i )) && max_i=$i
    done < <(compgen -v "${prefix}_" || true)

    (( max_i >= 0 )) || return 0
    for ((i = 0; i <= max_i; i++)); do
        if [[ ! ${seen[$i]+x} ]]; then
            echo "fairness-harness: missing ${prefix}_${i}; numbered argv variables must be contiguous from ${prefix}_0" >&2
            exit 2
        fi
        name=${seen[$i]}
        out_ref+=("${!name}")
    done
}

append_optional_netns_and_cpuset() {
    local -n cmd_ref=$1
    local netns=$2
    local cpuset=$3

    if [[ -n "$netns" ]]; then
        cmd_ref+=(ip netns exec "$netns")
    fi
    if [[ -n "$cpuset" ]]; then
        cmd_ref+=(taskset -c "$cpuset")
    fi
}

build_iperf_cmd() {
    local cmd_name=$1
    local -n cmd_ref=$cmd_name
    local port=$2
    local streams=$3
    local reverse_flag=$4
    local launch_netns=$5
    local launch_cpuset=$6
    local launch_arg_prefix=$7
    local generator_netns=$8
    local generator_cpuset=$9
    local generator_arg_prefix=${10}
    local iperf_bin=${11}
    local launch_args=()
    local generator_args=()

    cmd_ref=()
    collect_numbered_args "$launch_arg_prefix" launch_args
    collect_numbered_args "$generator_arg_prefix" generator_args

    append_optional_netns_and_cpuset "$cmd_name" "$launch_netns" "$launch_cpuset"
    cmd_ref+=("${launch_args[@]}")
    append_optional_netns_and_cpuset "$cmd_name" "$generator_netns" "$generator_cpuset"
    cmd_ref+=("${generator_args[@]}")
    cmd_ref+=("$iperf_bin" -c "$TARGET" -P "$streams" -t "$T" -p "$port")
    if [[ -n "$reverse_flag" ]]; then
        cmd_ref+=("$reverse_flag")
    fi
    cmd_ref+=(-J --forceflush)
}

max_cpu_from_possible_spec() {
    local spec=$1
    local clean
    local part
    local -a parts
    local start
    local end
    local max=-1

    clean=${spec//[[:space:]]/}
    [[ -z "$clean" ]] && return 1
    IFS=',' read -r -a parts <<< "$clean"
    for part in "${parts[@]}"; do
        if [[ "$part" =~ ^([0-9]+)$ ]]; then
            start=$((10#${BASH_REMATCH[1]}))
            (( start > max )) && max=$start
        elif [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start=$((10#${BASH_REMATCH[1]}))
            end=$((10#${BASH_REMATCH[2]}))
            (( start > end )) && return 1
            (( end > max )) && max=$end
        else
            return 1
        fi
    done
    (( max >= 0 )) || return 1
    printf '%s\n' "$max"
}

discover_cpuset_max_cpu_id() {
    local max
    local hard_max
    local nproc_count

    if [[ ! "$CPUSET_HARD_MAX_CPU_ID" =~ ^[0-9]+$ ]]; then
        echo "fairness-harness: CPUSET_HARD_MAX_CPU_ID must be a non-negative integer" >&2
        return 1
    fi
    hard_max=$((10#$CPUSET_HARD_MAX_CPU_ID))

    if [[ -n "$CPUSET_MAX_CPU_ID" ]]; then
        if [[ ! "$CPUSET_MAX_CPU_ID" =~ ^[0-9]+$ ]]; then
            echo "fairness-harness: CPUSET_MAX_CPU_ID must be a non-negative integer" >&2
            return 1
        fi
        max=$((10#$CPUSET_MAX_CPU_ID))
    elif [[ -r /sys/devices/system/cpu/possible ]] && max=$(max_cpu_from_possible_spec "$(cat /sys/devices/system/cpu/possible)"); then
        :
    elif nproc_count=$(nproc --all 2>/dev/null) && [[ "$nproc_count" =~ ^[0-9]+$ ]] && (( nproc_count > 0 )); then
        max=$((10#$nproc_count - 1))
    else
        echo "fairness-harness: cannot discover CPU topology; set CPUSET_MAX_CPU_ID explicitly" >&2
        return 1
    fi

    if (( max > hard_max )); then
        echo "fairness-harness: CPUSET_MAX_CPU_ID=$max exceeds CPUSET_HARD_MAX_CPU_ID=$hard_max" >&2
        return 1
    fi
    printf '%s\n' "$max"
}

cpuset_to_bitmap() {
    local spec=$1
    local label=$2
    local -n out_ref=$3
    local max_cpu_id=$4
    local clean
    local part
    local -a parts
    local start
    local end
    local cpu
    local value

    out_ref=()
    clean=${spec//[[:space:]]/}
    if [[ -z "$clean" ]]; then
        echo "fairness-harness: empty CPU set for $label" >&2
        return 1
    fi
    IFS=',' read -r -a parts <<< "$clean"
    for part in "${parts[@]}"; do
        if [[ "$part" =~ ^([0-9]+)$ ]]; then
            value=${BASH_REMATCH[1]}
            cpu=$((10#$value))
            if (( cpu > max_cpu_id )); then
                echo "fairness-harness: CPU $cpu in $label exceeds max CPU id $max_cpu_id" >&2
                return 1
            fi
            out_ref["$cpu"]=1
        elif [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start=$((10#${BASH_REMATCH[1]}))
            end=$((10#${BASH_REMATCH[2]}))
            if (( start > end )); then
                echo "fairness-harness: invalid CPU range $part for $label" >&2
                return 1
            fi
            if (( end > max_cpu_id )); then
                echo "fairness-harness: CPU range $part in $label exceeds max CPU id $max_cpu_id" >&2
                return 1
            fi
            for ((cpu = start; cpu <= end; cpu++)); do
                out_ref["$cpu"]=1
            done
        else
            echo "fairness-harness: invalid CPU set token $part for $label" >&2
            return 1
        fi
    done
}

cpuset_overlap() {
    local -n left_ref=$1
    local -n right_ref=$2
    local cpu
    local overlap=()

    for cpu in "${!left_ref[@]}"; do
        if [[ ${right_ref[$cpu]+x} ]]; then
            overlap+=("$cpu")
        fi
    done
    if ((${#overlap[@]} > 0)); then
        local joined
        joined=$(IFS=','; printf '%s' "${overlap[*]}")
        printf '%s\n' "$joined"
        return 0
    fi
    return 1
}

network_domain() {
    local explicit_id=$1

    if [[ -n "$explicit_id" ]]; then
        printf '%s\n' "$explicit_id"
    fi
    return 0
}

append_runtime_artifact() {
    [[ -n "$ARTIFACT_DIR" ]] || return 0
    local label=$1
    local pid=$2
    local artifact="$ARTIFACT_DIR/generator-placement.txt"
    local taskset_out
    {
        printf '%s.launcher_pid=%s\n' "$label" "$pid"
        if taskset_out=$(taskset -pc "$pid" 2>/dev/null); then
            printf '%s.launcher_pid_cpuset=%s\n' "$label" "$taskset_out"
        else
            printf '%s.launcher_pid_cpuset=unavailable\n' "$label"
        fi
    } >> "$artifact"
}

validate_isolated_generators() {
    [[ "$ISOLATED_GENERATORS" -eq 1 ]] || return 0
    if [[ "$MIXED_COS" -ne 1 ]]; then
        echo "fairness-harness: isolated generator mode requires mixed CoS mode" >&2
        exit 2
    fi
    if [[ -z "$IPERF_CPUSET" || -z "$MIXED_IPERF_CPUSET" ]]; then
        echo "fairness-harness: --mixed-cos-isolated requires IPERF_CPUSET and MIXED_IPERF_CPUSET" >&2
        exit 2
    fi

    local -A primary_cpus=()
    local -A mixed_cpus=()
    local max_cpu_id
    local overlap
    if ! max_cpu_id=$(discover_cpuset_max_cpu_id); then
        exit 2
    fi
    if ! cpuset_to_bitmap "$IPERF_CPUSET" "IPERF_CPUSET" primary_cpus "$max_cpu_id"; then
        exit 2
    fi
    if ! cpuset_to_bitmap "$MIXED_IPERF_CPUSET" "MIXED_IPERF_CPUSET" mixed_cpus "$max_cpu_id"; then
        exit 2
    fi
    if overlap=$(cpuset_overlap primary_cpus mixed_cpus); then
        echo "fairness-harness: isolated mode CPU sets overlap: $overlap" >&2
        exit 2
    fi

    local primary_network
    local mixed_network
    primary_network=$(network_domain "$IPERF_NETWORK_ID")
    mixed_network=$(network_domain "$MIXED_IPERF_NETWORK_ID")
    if [[ -n "$IPERF_NETNS" || -n "$MIXED_IPERF_NETNS" ]]; then
        if [[ -z "$IPERF_NETNS" || -z "$MIXED_IPERF_NETNS" || "$IPERF_NETNS" == "$MIXED_IPERF_NETNS" ]]; then
            echo "fairness-harness: isolated mode generator netns values must both be set and distinct" >&2
            exit 2
        fi
    elif [[ -z "$primary_network" || -z "$mixed_network" || "$primary_network" == "$mixed_network" ]]; then
        echo "fairness-harness: --mixed-cos-isolated requires distinct generator netns or distinct IPERF_NETWORK_ID domains" >&2
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

copy_artifact_file() {
    local src=$1
    local dst=$2

    [[ -n "$ARTIFACT_DIR" ]] || return 0
    [[ -e "$src" ]] || return 0
    if ! cp "$src" "$ARTIFACT_DIR/$dst"; then
        echo "fairness-harness: failed to preserve artifact $src -> $ARTIFACT_DIR/$dst" >&2
        exit 2
    fi
}

persist_harness_artifacts() {
    [[ -n "$ARTIFACT_DIR" ]] || return 0

    copy_artifact_file "$BINDING_TSV" binding-flows.tsv
    copy_artifact_file "$COS_TSV" cos-flows.tsv
    if [[ "$MIXED_COS" -eq 1 ]]; then
        copy_artifact_file "$IPERF_OUT" iperf-primary.json
        copy_artifact_file "$MIXED_IPERF_OUT" iperf-mixed.json
    else
        copy_artifact_file "$IPERF_OUT" iperf-single.json
    fi
}

write_placement_artifact() {
    [[ -n "$ARTIFACT_DIR" ]] || return 0

    local primary_cmd=()
    local mixed_cmd=()
    local primary_launch_args=()
    local mixed_launch_args=()
    local primary_generator_args=()
    local mixed_generator_args=()
    local primary_network
    local mixed_network

    collect_numbered_args IPERF_LAUNCH_ARG primary_launch_args
    collect_numbered_args IPERF_GENERATOR_ARG primary_generator_args
    primary_network=$(network_domain "$IPERF_NETWORK_ID")

    build_iperf_cmd primary_cmd "$PORT" "$N" "$REVERSE" \
        "$IPERF_LAUNCH_NETNS" "$IPERF_LAUNCH_CPUSET" IPERF_LAUNCH_ARG \
        "$IPERF_NETNS" "$IPERF_CPUSET" IPERF_GENERATOR_ARG "$IPERF_BIN"
    if [[ "$MIXED_COS" -eq 1 ]]; then
        collect_numbered_args MIXED_IPERF_LAUNCH_ARG mixed_launch_args
        collect_numbered_args MIXED_IPERF_GENERATOR_ARG mixed_generator_args
        mixed_network=$(network_domain "$MIXED_IPERF_NETWORK_ID")
        build_iperf_cmd mixed_cmd "$MIXED_PORT" "$MIXED_N" "$MIXED_REVERSE" \
            "$MIXED_IPERF_LAUNCH_NETNS" "$MIXED_IPERF_LAUNCH_CPUSET" MIXED_IPERF_LAUNCH_ARG \
            "$MIXED_IPERF_NETNS" "$MIXED_IPERF_CPUSET" MIXED_IPERF_GENERATOR_ARG "$MIXED_IPERF_BIN"
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
        printf 'primary.launch_netns=%s\n' "$IPERF_LAUNCH_NETNS"
        printf 'primary.launch_cpuset=%s\n' "$IPERF_LAUNCH_CPUSET"
        printf 'primary.launch_args=%s\n' "$(format_command "${primary_launch_args[@]}")"
        printf 'primary.generator_netns=%s\n' "$IPERF_NETNS"
        printf 'primary.generator_cpuset=%s\n' "$IPERF_CPUSET"
        printf 'primary.generator_args=%s\n' "$(format_command "${primary_generator_args[@]}")"
        printf 'primary.network_id=%s\n' "$primary_network"
        printf 'primary.bin=%s\n' "$IPERF_BIN"
        printf 'primary.rss_steering=%s\n' "$PRIMARY_RSS_STEERING"
        printf 'primary.command_intent=%s\n' "$(format_command "${primary_cmd[@]}")"
        if [[ "$MIXED_COS" -eq 1 ]]; then
            printf 'mixed.label=%s\n' "$MIXED_GENERATOR_LABEL"
            printf 'mixed.port=%s\n' "$MIXED_PORT"
            printf 'mixed.streams=%s\n' "$MIXED_N"
            printf 'mixed.reverse=%s\n' "$MIXED_REVERSE"
            printf 'mixed.cos_ifindex=%s\n' "${COS_IFINDEX:-}"
            printf 'mixed.cos_queue_id=%s\n' "${MIXED_COS_QUEUE_ID:-}"
            printf 'mixed.shaper_rate_bps=%s\n' "${MIXED_SHAPER_RATE_BPS:-}"
            printf 'mixed.launch_netns=%s\n' "$MIXED_IPERF_LAUNCH_NETNS"
            printf 'mixed.launch_cpuset=%s\n' "$MIXED_IPERF_LAUNCH_CPUSET"
            printf 'mixed.launch_args=%s\n' "$(format_command "${mixed_launch_args[@]}")"
            printf 'mixed.generator_netns=%s\n' "$MIXED_IPERF_NETNS"
            printf 'mixed.generator_cpuset=%s\n' "$MIXED_IPERF_CPUSET"
            printf 'mixed.generator_args=%s\n' "$(format_command "${mixed_generator_args[@]}")"
            printf 'mixed.network_id=%s\n' "$mixed_network"
            printf 'mixed.bin=%s\n' "$MIXED_IPERF_BIN"
            printf 'mixed.rss_steering=%s\n' "$MIXED_RSS_STEERING"
            printf 'mixed.command_intent=%s\n' "$(format_command "${mixed_cmd[@]}")"
        fi
        printf 'runtime_probe=launcher_pid_and_cpuset_only; generator-context proof must come from the launch target or wrapper\n'
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

require_binding_scrape_rows() {
    if awk -F'\t' -v iface="$IFACE" '
        $0 !~ /^#/ && NF >= 6 && $5 == iface { seen = 1 }
        END { exit seen ? 0 : 1 }
    ' "$BINDING_TSV"; then
        return 0
    fi
    echo "fairness-harness: no binding active-flow metric rows for iface $IFACE from $METRICS_URL" >&2
    echo "fairness-harness: check METRICS_URL reachability from the harness host" >&2
    return 2
}

require_cos_scrape_rows() {
    local cos_queue_id=$1

    if awk -F'\t' -v ifindex="$COS_IFINDEX" -v queue_id="$cos_queue_id" '
        $0 !~ /^#/ && NF >= 5 && $2 == ifindex && $3 == queue_id { seen = 1 }
        END { exit seen ? 0 : 1 }
    ' "$COS_TSV"; then
        return 0
    fi
    echo "fairness-harness: no CoS active-flow metric rows for ifindex $COS_IFINDEX queue $cos_queue_id from $METRICS_URL" >&2
    echo "fairness-harness: check METRICS_URL reachability and COS_IFINDEX/COS_QUEUE_ID" >&2
    return 2
}

run_iperf() {
    local label=$1
    local out=$2
    local port=$3
    local streams=$4
    local reverse_flag=$5
    local launch_netns=${6:-}
    local launch_cpuset=${7:-}
    local launch_arg_prefix=${8:-}
    local generator_netns=${9:-}
    local generator_cpuset=${10:-}
    local generator_arg_prefix=${11:-}
    local iperf_bin=${12:-iperf3}
    local cmd=()

    build_iperf_cmd cmd "$port" "$streams" "$reverse_flag" \
        "$launch_netns" "$launch_cpuset" "$launch_arg_prefix" \
        "$generator_netns" "$generator_cpuset" "$generator_arg_prefix" "$iperf_bin"
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
    require_binding_scrape_rows || return 2
    if [[ -n "$COS_IFINDEX" && -n "$cos_queue_id" ]]; then
        require_cos_scrape_rows "$cos_queue_id" || return 2
    fi

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

IPERF_STATUS=0
if [[ "$MIXED_COS" -eq 1 ]]; then
    run_iperf "primary port $PORT queue $COS_QUEUE_ID" "$IPERF_OUT" "$PORT" "$N" "$REVERSE" \
        "$IPERF_LAUNCH_NETNS" "$IPERF_LAUNCH_CPUSET" IPERF_LAUNCH_ARG \
        "$IPERF_NETNS" "$IPERF_CPUSET" IPERF_GENERATOR_ARG "$IPERF_BIN" &
    PRIMARY_PID=$!
    append_runtime_artifact primary "$PRIMARY_PID"
    run_iperf "mixed port $MIXED_PORT queue $MIXED_COS_QUEUE_ID" "$MIXED_IPERF_OUT" "$MIXED_PORT" "$MIXED_N" "$MIXED_REVERSE" \
        "$MIXED_IPERF_LAUNCH_NETNS" "$MIXED_IPERF_LAUNCH_CPUSET" MIXED_IPERF_LAUNCH_ARG \
        "$MIXED_IPERF_NETNS" "$MIXED_IPERF_CPUSET" MIXED_IPERF_GENERATOR_ARG "$MIXED_IPERF_BIN" &
    MIXED_PID=$!
    append_runtime_artifact mixed "$MIXED_PID"

    if wait "$PRIMARY_PID"; then :; else IPERF_STATUS=$?; fi
    if wait "$MIXED_PID"; then
        :
    else
        MIXED_WAIT_STATUS=$?
        if [[ "$IPERF_STATUS" -eq 0 ]]; then
            IPERF_STATUS=$MIXED_WAIT_STATUS
        fi
    fi
else
    set +e
    run_iperf "single" "$IPERF_OUT" "$PORT" "$N" "$REVERSE" \
        "$IPERF_LAUNCH_NETNS" "$IPERF_LAUNCH_CPUSET" IPERF_LAUNCH_ARG \
        "$IPERF_NETNS" "$IPERF_CPUSET" IPERF_GENERATOR_ARG "$IPERF_BIN"
    IPERF_STATUS=$?
    set -e
fi

cleanup
persist_harness_artifacts

if [[ "$IPERF_STATUS" -ne 0 ]]; then
    exit "$IPERF_STATUS"
fi

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
