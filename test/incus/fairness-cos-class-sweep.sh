#!/usr/bin/env bash
# Run fairness_multi_sample.py across every canonical CoS fixture class.
#
# This is intentionally a sequential qualification harness: each class gets its
# own sample directory and verdict, then the script emits an aggregate summary
# and returns non-zero if any class fails its multi-sample gap contract.

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
ARTIFACT_ROOT=${ARTIFACT_ROOT:-}
HARNESS=${HARNESS:-$ROOT_DIR/test/incus/fairness-harness.sh}
WRAPPER=${WRAPPER:-$ROOT_DIR/test/incus/fairness_multi_sample.py}
FAIRNESS_EVAL=${FAIRNESS_EVAL:-$ROOT_DIR/userspace-dp/target/release/fairness-eval}
CAPTURE_DATAPLANE=${CAPTURE_DATAPLANE:-1}
DATAPLANE_VM=${DATAPLANE_VM:-loss:xpf-userspace-fw0}
DATAPLANE_STATUS_PATH=${DATAPLANE_STATUS_PATH:-/run/xpf/userspace-dp.json}
DATAPLANE_STATS_CMD=${DATAPLANE_STATS_CMD:-"cli -c 'show chassis cluster data-plane statistics'"}
DATAPLANE_CAPTURE_TIMEOUT_SEC=${DATAPLANE_CAPTURE_TIMEOUT_SEC:-20}

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

if [[ -z "$ARTIFACT_ROOT" ]]; then
    ARTIFACT_ROOT=$(mktemp -d -t cos-fairness-all.XXXXXX)
else
    mkdir -p "$ARTIFACT_ROOT"
fi
SUMMARY_TSV="$ARTIFACT_ROOT/summary.tsv"
SUMMARY_MD="$ARTIFACT_ROOT/summary.md"
DATAPLANE_SUMMARY_TSV="$ARTIFACT_ROOT/dataplane-summary.tsv"
if ! rm -f "$DATAPLANE_SUMMARY_TSV"; then
    echo "fairness-cos-class-sweep: failed to remove stale dataplane summary: $DATAPLANE_SUMMARY_TSV" >&2
    exit 2
fi

cat > "$SUMMARY_TSV" <<'HEADER'
class	port	queue_id	rate_bps	exit_status	verdict	mean_observed_cov	max_observed_cov	stdev_observed_cov	avg_mbps	avg_cstruct	mean_gap	max_gap	starved_flows	per_run_verdicts
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

mark_parse_error() {
    overall_status=2
}

append_error_row() {
    local label=$1
    local port=$2
    local queue=$3
    local rate=$4
    local status=$5

    printf '%s\t%s\t%s\t%s\t%s\tERROR\t-\t-\t-\t-\t-\t-\t-\t-\t-\n' \
        "$label" "$port" "$queue" "$rate" "$status" >> "$SUMMARY_TSV"
    printf "summary class=%s wrapper_status=%s verdict=ERROR mean_cov=- max_cov=-\n" \
        "$label" "$status"
}

mark_dataplane_error() {
    dataplane_status=2
}

capture_dataplane_enabled() {
    case "${CAPTURE_DATAPLANE,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

run_dataplane_cmd() {
    local stderr=$1
    shift

    if ! command -v timeout >/dev/null 2>&1; then
        echo "timeout command not found; dataplane capture cannot be bounded" > "$stderr"
        return 127
    fi

    timeout --kill-after=5s "$DATAPLANE_CAPTURE_TIMEOUT_SEC" "$@" 2> "$stderr"
    local rc=$?
    if (( rc == 124 || rc == 137 )); then
        echo "dataplane capture command timed out after ${DATAPLANE_CAPTURE_TIMEOUT_SEC}s (exit $rc): $*" >> "$stderr"
    elif (( rc != 0 )); then
        echo "dataplane capture command failed (exit $rc): $*" >> "$stderr"
    fi
    return "$rc"
}

capture_dataplane_snapshot() {
    local phase=$1
    local root=$2
    local dir="$root/dataplane"

    capture_dataplane_enabled || return 0
    mkdir -p "$dir"
    date -Is > "$dir/captured-$phase.txt"

    if ! command -v incus >/dev/null 2>&1; then
        echo "incus command not found; dataplane snapshot skipped" > "$dir/skipped-$phase.txt"
        mark_dataplane_error
        return 0
    fi

    if ! run_dataplane_cmd "$dir/status-$phase.stderr" \
        incus exec "$DATAPLANE_VM" -- sh -lc "cat \"$DATAPLANE_STATUS_PATH\"" \
        > "$dir/status-$phase.json"; then
        echo "failed to capture $DATAPLANE_STATUS_PATH from $DATAPLANE_VM" >> "$dir/status-$phase.stderr"
        mark_dataplane_error
    fi

    if ! run_dataplane_cmd "$dir/cli-$phase.stderr" \
        incus exec "$DATAPLANE_VM" -- sh -lc "$DATAPLANE_STATS_CMD" \
        > "$dir/cli-$phase.txt"; then
        echo "failed to run dataplane stats command on $DATAPLANE_VM" >> "$dir/cli-$phase.stderr"
        mark_dataplane_error
    fi
}

capture_dataplane_journal() {
    local root=$1
    local since=$2
    local dir="$root/dataplane"

    capture_dataplane_enabled || return 0
    mkdir -p "$dir"

    if ! command -v incus >/dev/null 2>&1; then
        echo "incus command not found; dataplane journal skipped" > "$dir/journal-skipped.txt"
        mark_dataplane_error
        return 0
    fi

    if ! run_dataplane_cmd "$dir/journal-since.stderr" \
        incus exec "$DATAPLANE_VM" -- sh -lc "journalctl -u xpfd --since \"$since\" --no-pager -o short-iso" \
        > "$dir/journal-since.txt"; then
        echo "failed to capture xpfd journal from $DATAPLANE_VM" >> "$dir/journal-since.stderr"
        mark_dataplane_error
    fi

    if [[ -f "$dir/journal-since.txt" ]]; then
        grep -c 'DBG SEG_MISS' "$dir/journal-since.txt" > "$dir/seg-miss-count.txt" || echo 0 > "$dir/seg-miss-count.txt"
    fi
}

write_dataplane_delta() {
    local before_json=$1
    local after_json=$2
    local dir=$3

    capture_dataplane_enabled || return 0
    mkdir -p "$dir"

    if [[ ! -s "$before_json" || ! -s "$after_json" ]]; then
        printf 'missing status snapshots: before=%s after=%s\n' "$before_json" "$after_json" > "$dir/counter-delta.skipped"
        mark_dataplane_error
        return 0
    fi

    if ! jq -s '
        def st: .status // .;
        def sum_bind($s; $f): [($s.bindings // [])[]? | .[$f] // 0] | add // 0;
        def sum_per($s; $f): [($s.per_binding // [])[]? | .[$f] // empty] | add;
        def sum_counter($s; $f):
            (sum_per($s; $f)) as $p
            | if $p == null then sum_bind($s; $f) else $p end;
        def sum_cos($s; $f): [($s.cos_interfaces // [])[]? | (.queues // [])[]? | .[$f] // 0] | add // 0;
        def counters($s): {
            tx_errors: sum_counter($s; "tx_errors"),
            tx_submit_error_drops: sum_counter($s; "tx_submit_error_drops"),
            pending_tx_local_overflow_drops: sum_counter($s; "pending_tx_local_overflow_drops"),
            dbg_tx_ring_full: sum_counter($s; "dbg_tx_ring_full"),
            dbg_sendto_enobufs: sum_counter($s; "dbg_sendto_enobufs"),
            dbg_bound_pending_overflow: sum_counter($s; "dbg_bound_pending_overflow"),
            dbg_cos_queue_overflow: sum_counter($s; "dbg_cos_queue_overflow"),
            redirect_inbox_overflow_drops: sum_counter($s; "redirect_inbox_overflow_drops"),
            cos_no_owner_binding_drops_total: ($s.cos_no_owner_binding_drops_total // 0),
            binding_post_drain_backup_bytes: sum_counter($s; "post_drain_backup_bytes"),
            binding_drain_sent_bytes_shaped_unconditional: sum_counter($s; "drain_sent_bytes_shaped_unconditional"),
            binding_post_drain_backup_cos_drops: sum_counter($s; "post_drain_backup_cos_drops"),
            binding_post_drain_backup_cos_drop_bytes: sum_counter($s; "post_drain_backup_cos_drop_bytes"),
            admission_flow_share_drops: sum_cos($s; "admission_flow_share_drops"),
            admission_buffer_drops: sum_cos($s; "admission_buffer_drops"),
            admission_ecn_marked: sum_cos($s; "admission_ecn_marked"),
            tx_ring_full_submit_stalls: sum_cos($s; "tx_ring_full_submit_stalls"),
            cos_post_drain_backup_bytes: sum_cos($s; "post_drain_backup_bytes"),
            cos_drain_sent_bytes_shaped_unconditional: sum_cos($s; "drain_sent_bytes_shaped_unconditional"),
            cos_post_drain_backup_cos_drops: sum_cos($s; "post_drain_backup_cos_drops"),
            cos_post_drain_backup_cos_drop_bytes: sum_cos($s; "post_drain_backup_cos_drop_bytes")
        };
        (.[0] | st) as $before_s
        | (.[1] | st) as $after_s
        | (counters($before_s)) as $before
        | (counters($after_s)) as $after
        | {
            before: $before,
            after: $after,
            delta: ($after | with_entries(.value = (.value - ($before[.key] // 0))))
        }
    ' "$before_json" "$after_json" > "$dir/counter-delta.json" 2> "$dir/counter-delta.stderr"; then
        mark_dataplane_error
        return 0
    fi

    if ! jq -r '
        (["metric", "before", "after", "delta"] | @tsv),
        (.delta as $delta
         | .before as $before
         | .after as $after
         | $delta
         | to_entries[]
         | [.key, ($before[.key] // 0), ($after[.key] // 0), .value]
         | @tsv)
    ' "$dir/counter-delta.json" > "$dir/counter-delta.tsv" 2> "$dir/counter-delta-tsv.stderr"; then
        mark_dataplane_error
    fi

    if ! jq -sr '
        def st: .status // .;
        def cos_rows($s):
            [($s.cos_interfaces // [])[]? as $iface
             | ($iface.queues // [])[]?
             | {
                key: (($iface.ifindex // 0 | tostring) + "\t" + (.queue_id // 0 | tostring)),
                ifindex: ($iface.ifindex // 0),
                interface: ($iface.interface_name // "-"),
                queue_id: (.queue_id // 0),
                class: (.forwarding_class // "-"),
                admission_flow_share_drops: (.admission_flow_share_drops // 0),
                admission_buffer_drops: (.admission_buffer_drops // 0),
                admission_ecn_marked: (.admission_ecn_marked // 0),
                tx_ring_full_submit_stalls: (.tx_ring_full_submit_stalls // 0),
                post_drain_backup_bytes: (.post_drain_backup_bytes // 0),
                drain_sent_bytes_shaped_unconditional: (.drain_sent_bytes_shaped_unconditional // 0),
                post_drain_backup_cos_drops: (.post_drain_backup_cos_drops // 0),
                post_drain_backup_cos_drop_bytes: (.post_drain_backup_cos_drop_bytes // 0)
             }];
        def cos_map($s): reduce cos_rows($s)[] as $r ({}; .[$r.key] = $r);
        (.[0] | st) as $before
        | (.[1] | st) as $after
        | (cos_map($before)) as $bm
        | (["ifindex", "interface", "queue_id", "class", "admission_flow_share_drops_delta", "admission_buffer_drops_delta", "admission_ecn_marked_delta", "tx_ring_full_submit_stalls_delta", "post_drain_backup_bytes_delta", "drain_sent_bytes_shaped_unconditional_delta", "post_drain_backup_cos_drops_delta", "post_drain_backup_cos_drop_bytes_delta"] | @tsv),
        (cos_rows($after)[] as $r
         | ($bm[$r.key] // {}) as $b
         | [
            $r.ifindex,
            $r.interface,
            $r.queue_id,
            $r.class,
            ($r.admission_flow_share_drops - ($b.admission_flow_share_drops // 0)),
            ($r.admission_buffer_drops - ($b.admission_buffer_drops // 0)),
            ($r.admission_ecn_marked - ($b.admission_ecn_marked // 0)),
            ($r.tx_ring_full_submit_stalls - ($b.tx_ring_full_submit_stalls // 0)),
            ($r.post_drain_backup_bytes - ($b.post_drain_backup_bytes // 0)),
            ($r.drain_sent_bytes_shaped_unconditional - ($b.drain_sent_bytes_shaped_unconditional // 0)),
            ($r.post_drain_backup_cos_drops - ($b.post_drain_backup_cos_drops // 0)),
            ($r.post_drain_backup_cos_drop_bytes - ($b.post_drain_backup_cos_drop_bytes // 0))
           ]
         | select((.[4:] | map(select(. != 0)) | length) > 0)
         | @tsv)
    ' "$before_json" "$after_json" > "$dir/cos-queue-delta.tsv" 2> "$dir/cos-queue-delta.stderr"; then
        mark_dataplane_error
    fi
}

append_dataplane_class_summary() {
    local label=$1
    local delta_json=$2

    capture_dataplane_enabled || return 0
    [[ -s "$delta_json" ]] || return 0

    if [[ ! -f "$DATAPLANE_SUMMARY_TSV" ]]; then
        cat > "$DATAPLANE_SUMMARY_TSV" <<'HEADER'
class	tx_errors_delta	tx_submit_error_drops_delta	pending_tx_local_overflow_drops_delta	dbg_tx_ring_full_delta	dbg_sendto_enobufs_delta	dbg_bound_pending_overflow_delta	dbg_cos_queue_overflow_delta	redirect_inbox_overflow_drops_delta	admission_flow_share_drops_delta	admission_buffer_drops_delta	admission_ecn_marked_delta	tx_ring_full_submit_stalls_delta	binding_post_drain_backup_cos_drops_delta
HEADER
    fi

    if ! jq -r --arg class "$label" '
        .delta as $d
        | [
            $class,
            ($d.tx_errors // 0),
            ($d.tx_submit_error_drops // 0),
            ($d.pending_tx_local_overflow_drops // 0),
            ($d.dbg_tx_ring_full // 0),
            ($d.dbg_sendto_enobufs // 0),
            ($d.dbg_bound_pending_overflow // 0),
            ($d.dbg_cos_queue_overflow // 0),
            ($d.redirect_inbox_overflow_drops // 0),
            ($d.admission_flow_share_drops // 0),
            ($d.admission_buffer_drops // 0),
            ($d.admission_ecn_marked // 0),
            ($d.tx_ring_full_submit_stalls // 0),
            ($d.binding_post_drain_backup_cos_drops // 0)
          ]
        | @tsv
    ' "$delta_json" >> "$DATAPLANE_SUMMARY_TSV" 2> "${delta_json%.json}-summary.stderr"; then
        mark_dataplane_error
    fi
}

overall_status=0
dataplane_status=0
SWEEP_START_ISO=$(date -Is)
capture_dataplane_snapshot before "$ARTIFACT_ROOT"
for spec in "${classes[@]}"; do
    read -r label port queue rate <<< "$spec"
    out="$ARTIFACT_ROOT/$label"
    mkdir -p "$out"

    echo "=== $(date -Is) class=$label port=$port queue=$queue rate=$rate ==="
    capture_dataplane_snapshot before "$out"
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
    capture_dataplane_snapshot after "$out"
    write_dataplane_delta "$out/dataplane/status-before.json" "$out/dataplane/status-after.json" "$out/dataplane"
    append_dataplane_class_summary "$label" "$out/dataplane/counter-delta.json"
    if (( status == 2 )); then
        overall_status=2
        append_error_row "$label" "$port" "$queue" "$rate" "$status"
        sed -n '1,80p' "$out/wrapper.stderr" >&2
        continue
    elif (( status != 0 && status != 1 )); then
        overall_status=2
        append_error_row "$label" "$port" "$queue" "$rate" "$status"
        sed -n '1,80p' "$out/wrapper.stderr" >&2
        continue
    elif (( status != 0 && overall_status == 0 )); then
        overall_status=1
    fi

    summary_json="$out/samples/summary.json"
    if [[ -f "$summary_json" ]]; then
        row_file="$out/summary-row.tsv"
        jq_err="$out/summary-jq.stderr"
        if jq -er \
            --arg class "$label" \
            --arg port "$port" \
            --arg queue "$queue" \
            --arg rate "$rate" \
            --arg status "$status" \
            '
            def require_samples:
                if (.samples | type) != "array" or (.samples | length) == 0 then
                    error("summary.json has no samples")
                else
                    .
                end;
            def required_number(path; field_name):
                getpath(path) as $value
                | if ($value | type) == "number" then
                    $value
                else
                    error("summary.json missing numeric " + field_name)
                end;
            def required_string(path; field_name):
                getpath(path) as $value
                | if ($value | type) == "string" and ($value | length) > 0 then
                    $value
                else
                    error("summary.json missing string " + field_name)
                end;
            def sample_numbers(key):
                ([.samples[] | .[key]]) as $values
                | if any($values[]; (type != "number")) then
                    error("summary.json sample missing numeric " + key)
                else
                    $values
                end;
            def sample_verdicts:
                ([.samples[] | .verdict]) as $values
                | if any($values[]; (type != "string" or length == 0)) then
                    error("summary.json sample missing string verdict")
                else
                    $values
                end;
            require_samples
            | sample_numbers("aggregate_mbps") as $aggregate_mbps
            | sample_numbers("starved_flow_count") as $starved
            | sample_verdicts as $sample_verdicts
            | [
                $class,
                $port,
                $queue,
                $rate,
                $status,
                required_string(["verdict"]; "verdict"),
                (required_number(["observed_cov", "mean"]; "observed_cov.mean") | tostring),
                (required_number(["observed_cov", "max"]; "observed_cov.max") | tostring),
                (required_number(["observed_cov", "sample_stdev"]; "observed_cov.sample_stdev") | tostring),
                (($aggregate_mbps | add / length) | tostring),
                (required_number(["cstruct", "mean"]; "cstruct.mean") | tostring),
                (required_number(["gap", "mean"]; "gap.mean") | tostring),
                (required_number(["gap", "max"]; "gap.max") | tostring),
                ($starved | add | tostring),
                ($sample_verdicts | join(","))
            ] | @tsv' "$summary_json" > "$row_file" 2> "$jq_err"; then
            cat "$row_file" >> "$SUMMARY_TSV"
            awk -F'\t' '{printf "summary class=%s wrapper_status=%s verdict=%s mean_cov=%s max_cov=%s\n", $1, $5, $6, $7, $8}' "$row_file"
        else
            mark_parse_error
            append_error_row "$label" "$port" "$queue" "$rate" "$status"
            echo "fairness-cos-class-sweep: invalid summary for $label: $summary_json" >&2
            sed -n '1,80p' "$jq_err" >&2
        fi
    else
        mark_parse_error
        append_error_row "$label" "$port" "$queue" "$rate" "$status"
        sed -n '1,80p' "$out/wrapper.stderr" >&2
    fi
done

capture_dataplane_snapshot after "$ARTIFACT_ROOT"
capture_dataplane_journal "$ARTIFACT_ROOT" "$SWEEP_START_ISO"
write_dataplane_delta "$ARTIFACT_ROOT/dataplane/status-before.json" "$ARTIFACT_ROOT/dataplane/status-after.json" "$ARTIFACT_ROOT/dataplane"
if (( dataplane_status != 0 )); then
    overall_status=2
fi

{
    printf '# CoS Fairness Class Sweep\n\n'
    printf 'Artifacts: `%s`\n\n' "$ARTIFACT_ROOT"
    printf 'Target: `%s`, streams: `%s`, duration: `%s`, reverse: `%s`, metrics: `%s`, cos_ifindex: `%s`\n\n' \
        "$TARGET" "$N" "$DURATION" "$REVERSE" "$METRICS_URL" "$COS_IFINDEX"
    printf '| Class | Port | Queue | Verdict | Mean CoV | Max CoV | Stdev CoV | Avg Mbps | Avg Cstruct | Mean Gap | Max Gap | Starved | Per-run |\n'
    printf '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n'
    tail -n +2 "$SUMMARY_TSV" | while IFS=$'\t' read -r class port queue _rate _status verdict mean max stdev mbps cstruct mean_gap max_gap starved per_run; do
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$class" "$port" "$queue" "$verdict" "$mean" "$max" "$stdev" "$mbps" "$cstruct" "$mean_gap" "$max_gap" "$starved" "$per_run"
    done
    if capture_dataplane_enabled; then
        printf '\n## Dataplane Counter Deltas\n\n'
        printf 'VM: `%s`, status: `%s`\n\n' "$DATAPLANE_VM" "$DATAPLANE_STATUS_PATH"
        if [[ -f "$ARTIFACT_ROOT/dataplane/seg-miss-count.txt" ]]; then
            printf 'DBG SEG_MISS log lines since sweep start: `%s`\n\n' "$(tr -d '\n' < "$ARTIFACT_ROOT/dataplane/seg-miss-count.txt")"
        fi
        if [[ -f "$ARTIFACT_ROOT/dataplane/counter-delta.tsv" ]]; then
            printf '### Sweep Total\n\n'
            printf '| Metric | Before | After | Delta |\n'
            printf '|---|---:|---:|---:|\n'
            tail -n +2 "$ARTIFACT_ROOT/dataplane/counter-delta.tsv" | while IFS=$'\t' read -r metric before after delta; do
                printf '| %s | %s | %s | %s |\n' "$metric" "$before" "$after" "$delta"
            done
            printf '\n'
        fi
        if [[ -f "$DATAPLANE_SUMMARY_TSV" ]]; then
            printf '### Per-Class TX Attribution\n\n'
            printf '| Class | TX errors | Submit drops | Pending overflow | TX ring full | ENOBUFS | Bound overflow | CoS overflow | Redirect overflow | Flow-share drops | Buffer drops | ECN marked | TX-ring stalls | Post-drain CoS drops |\n'
            printf '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n'
            tail -n +2 "$DATAPLANE_SUMMARY_TSV" | while IFS=$'\t' read -r class tx submit pending ring enobufs bound cos redirect flow buffer ecn stalls post_drain; do
                printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
                    "$class" "$tx" "$submit" "$pending" "$ring" "$enobufs" "$bound" "$cos" "$redirect" "$flow" "$buffer" "$ecn" "$stalls" "$post_drain"
            done
            printf '\n'
        fi
        if [[ -f "$ARTIFACT_ROOT/dataplane/cos-queue-delta.tsv" ]]; then
            printf '### Nonzero CoS Queue Deltas\n\n'
            printf '| Ifindex | Interface | Queue | Class | Flow-share drops | Buffer drops | ECN marked | TX-ring stalls | Post-drain bytes | Shaped unconditional bytes | Post-drain CoS drops | Post-drain CoS drop bytes |\n'
            printf '|---:|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|\n'
            tail -n +2 "$ARTIFACT_ROOT/dataplane/cos-queue-delta.tsv" | while IFS=$'\t' read -r ifindex iface queue class flow buffer ecn stalls backup shaped drops drop_bytes; do
                printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
                    "$ifindex" "$iface" "$queue" "$class" "$flow" "$buffer" "$ecn" "$stalls" "$backup" "$shaped" "$drops" "$drop_bytes"
            done
            printf '\n'
        fi
    fi
} > "$SUMMARY_MD"

echo "fairness-cos-class-sweep: wrote $SUMMARY_TSV"
echo "fairness-cos-class-sweep: wrote $SUMMARY_MD"
exit "$overall_status"
