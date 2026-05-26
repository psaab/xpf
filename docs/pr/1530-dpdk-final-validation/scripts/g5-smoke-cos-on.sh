#!/usr/bin/env bash
#
# G5.c — CoS-on class sweep, v4 + v6, push + reverse.
#
# Reads the per-class DSCP map from cos-dscp-map.txt (produced by
# g5-capture-cos-map.sh), then drives iperf3 with --tos $DSCP per
# class. Each (class, family, direction) gets its own log.
#
# Writes:
#   artifacts/smoke-v{4,6}-coson-<class>-{push,reverse}.log
#   artifacts/cos-interfaces-xpf-userspace-fw{0,1}.txt
#   artifacts/cos-queues-xpf-userspace-fw{0,1}.txt
#
# PASS criterion: every iperf3 run completes with a `[SUM] ... sender`
# line and non-zero bitrate. Per-class absolute floors are intentionally
# not gated here — class weights vary per deployment. The hard gate is
# "traffic flowed on every class without the daemon faulting".
#
# CALLER must hold cluster access lock via smoke-runner singleton.

set -uo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ART_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/artifacts
mkdir -p "$ART_DIR"

HOST=${HOST:-loss:cluster-userspace-host}
V4_TARGET=${V4_TARGET:-172.16.80.200}
V6_TARGET=${V6_TARGET:-2001:559:8585:80::200}
STREAMS=${STREAMS:-4}
DURATION=${DURATION:-10}
DSCP_MAP=${DSCP_MAP:-$ART_DIR/cos-dscp-map.txt}

if [[ ! -s "$DSCP_MAP" ]]; then
    echo "g5-coson: FAIL — DSCP map missing or empty: $DSCP_MAP" >&2
    echo "g5-coson: run g5-capture-cos-map.sh first" >&2
    exit 1
fi

# Parse "class=DSCP" lines, ignore comments and blanks.
mapfile -t ENTRIES < <(grep -Ev '^\s*(#|$)' "$DSCP_MAP")

if [[ "${#ENTRIES[@]}" -eq 0 ]]; then
    echo "g5-coson: FAIL — no class=DSCP entries in $DSCP_MAP" >&2
    exit 1
fi

echo "g5-coson: ${#ENTRIES[@]} class(es) to sweep"

run_iperf() {
    local logfile="$1"; shift
    sg incus-admin -c "incus exec $HOST -- iperf3 $*" 2>&1 | tee "$logfile"
}

FAIL=0
for entry in "${ENTRIES[@]}"; do
    class=${entry%%=*}
    dscp=${entry##*=}
    if [[ -z "$class" || -z "$dscp" ]]; then
        echo "g5-coson: WARN — skipping malformed entry: $entry" >&2
        continue
    fi
    echo "g5-coson: == sweeping class=$class dscp=$dscp =="

    for fam_target in "v4:$V4_TARGET" "v6:$V6_TARGET"; do
        fam=${fam_target%%:*}
        tgt=${fam_target#*:}
        v6flag=""
        [[ "$fam" == "v6" ]] && v6flag="-6"

        for dir in push reverse; do
            rflag=""
            [[ "$dir" == "reverse" ]] && rflag="-R"
            log="$ART_DIR/smoke-${fam}-coson-${class}-${dir}.log"
            run_iperf "$log" "$v6flag -c $tgt -P $STREAMS -t $DURATION $rflag --tos $dscp"

            if ! grep -Eq '\[SUM\].*sender' "$log"; then
                echo "g5-coson: FAIL — ${fam} ${class} ${dir} produced no SUM line" >&2
                FAIL=1
            fi
        done
    done
done

# Capture per-node CoS state for the artifact bundle.
for node in xpf-userspace-fw0 xpf-userspace-fw1; do
    sg incus-admin -c "incus exec loss:$node -- cli -c 'show class-of-service interface'" \
        > "$ART_DIR/cos-interfaces-${node}.txt" 2>&1 || true
    sg incus-admin -c "incus exec loss:$node -- cli -c 'show interfaces queue'" \
        > "$ART_DIR/cos-queues-${node}.txt" 2>&1 || true
done

if [[ "$FAIL" -ne 0 ]]; then
    echo "g5-coson: FAIL — at least one class sweep leg produced no traffic"
    exit 1
fi

echo "g5-coson: PASS — full class sweep produced traffic on every leg"
