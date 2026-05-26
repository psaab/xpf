#!/usr/bin/env bash
#
# G5.a/G5.b — CoS-off IPv4 and IPv6 push + reverse smoke.
#
# Drives iperf3 from the LAN host (loss:cluster-userspace-host)
# through the cluster to the WAN targets:
#   v4: 172.16.80.200
#   v6: 2001:559:8585:80::200
#
# Streams: -P 4    Duration: -t 10    Reverse: -R for the reverse run.
#
# Writes:
#   artifacts/smoke-v4-cosoff-push.log
#   artifacts/smoke-v4-cosoff-reverse.log
#   artifacts/smoke-v6-cosoff-push.log
#   artifacts/smoke-v6-cosoff-reverse.log
#
# PASS criterion: each log contains a `[SUM] ... sender` line with
# bitrate above MIN_GBPS (default 5). Set MIN_GBPS to override.
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
MIN_GBPS=${MIN_GBPS:-5}

run_iperf() {
    local label="$1"; shift
    local logfile="$ART_DIR/smoke-$label.log"
    echo "g5-smoke: == $label =="
    sg incus-admin -c "incus exec $HOST -- iperf3 $*" 2>&1 | tee "$logfile"
}

# Extract sender throughput in Gbps from an iperf3 log.
# Returns "0" if no SUM line found.
sender_gbps() {
    local logfile="$1"
    local line bw unit
    line=$(grep -E '\[SUM\].*sender' "$logfile" | tail -n1 || true)
    if [[ -z "$line" ]]; then
        echo "0"
        return
    fi
    # Field layout: [SUM]  0.00-10.00  sec  XXX GBytes  YY.Y Gbits/sec  ...  sender
    bw=$(echo "$line" | awk '{for(i=1;i<=NF;i++){ if($i ~ /(K|M|G)bits\/sec/){ print $(i-1), $i; exit } }}')
    if [[ -z "$bw" ]]; then
        echo "0"
        return
    fi
    local val=$(echo "$bw" | awk '{print $1}')
    unit=$(echo "$bw" | awk '{print $2}')
    case "$unit" in
        Gbits/sec) echo "$val" ;;
        Mbits/sec) echo "$val" | awk '{printf "%.3f", $1/1000}' ;;
        Kbits/sec) echo "$val" | awk '{printf "%.6f", $1/1000000}' ;;
        *)         echo "0" ;;
    esac
}

FAIL=0
check_run() {
    local label="$1"
    local logfile="$ART_DIR/smoke-$label.log"
    local gbps
    gbps=$(sender_gbps "$logfile")
    echo "g5-smoke:   $label = $gbps Gbits/sec"
    awk -v v="$gbps" -v m="$MIN_GBPS" 'BEGIN{ exit !(v+0 >= m+0) }' || {
        echo "g5-smoke: FAIL — $label below floor ${MIN_GBPS} Gbps (got $gbps)" >&2
        FAIL=1
    }
}

# IPv4
run_iperf v4-cosoff-push    "-c $V4_TARGET -P $STREAMS -t $DURATION"
run_iperf v4-cosoff-reverse "-c $V4_TARGET -P $STREAMS -t $DURATION -R"

# IPv6
run_iperf v6-cosoff-push    "-6 -c $V6_TARGET -P $STREAMS -t $DURATION"
run_iperf v6-cosoff-reverse "-6 -c $V6_TARGET -P $STREAMS -t $DURATION -R"

check_run v4-cosoff-push
check_run v4-cosoff-reverse
check_run v6-cosoff-push
check_run v6-cosoff-reverse

if [[ "$FAIL" -ne 0 ]]; then
    echo "g5-smoke: FAIL — one or more CoS-off legs below floor"
    exit 1
fi

echo "g5-smoke: PASS — CoS-off v4 + v6 push + reverse all above floor"
