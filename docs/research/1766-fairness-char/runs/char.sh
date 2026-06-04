#!/usr/bin/env bash
# Q1 characterization driver for #1766. NOT production code.
# Runs iperf3 -P12 -p5208 (forward) from loss:cluster-userspace-host ->
# 172.16.80.200, scrapes q8 cos_active_flow_count + v8 grant + equal_flow
# metrics at warmup-skip + steady-state, captures per-stream rates, and
# computes Cstruct vs observed per-flow CoV.
set -euo pipefail
REMOTE=loss
FW=xpf-userspace-fw0
HOST=cluster-userspace-host
TARGET=${TARGET:-172.16.80.200}
PORT=${PORT:-5208}
P=${P:-12}
DUR=${DUR:-75}
QID=8
IFINDEX=14
LABEL=${1:-run}
OUT=$(dirname "$0")/$LABEL
mkdir -p "$OUT"

scrape() { sg incus-admin -c "incus exec ${REMOTE}:${FW} -- bash -c 'curl -s http://127.0.0.1:8080/metrics'" 2>/dev/null; }

echo "[$LABEL] launching iperf3 -P$P -p$PORT -t$DUR forward"
sg incus-admin -c "incus exec ${REMOTE}:${HOST} -- bash -c 'iperf3 -c ${TARGET} -p ${PORT} -P ${P} -t ${DUR} -J --forceflush'" > "$OUT/iperf.json" 2>"$OUT/iperf.err" &
IPERF_PID=$!

# scrape v8 grant + cos flow at t=12s (post-warmup baseline) and t=DUR-8 (steady)
sleep 12
scrape > "$OUT/metrics_t12.prom"
sleep $((DUR-12-8))
scrape > "$OUT/metrics_steady.prom"

wait $IPERF_PID || true
echo "[$LABEL] done -> $OUT"
