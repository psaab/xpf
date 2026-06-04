#!/usr/bin/env bash
# Operator repro: iperf3 -P12 5211 (uncapped) for 5s, kill, then
# immediately -P12 5208 for the measurement window. NOT production code.
set -euo pipefail
REMOTE=loss; HOST=cluster-userspace-host; FW=xpf-userspace-fw0
TARGET=172.16.80.200; DUR=${DUR:-70}
LABEL=${1:-kill}; OUT=$(dirname "$0")/$LABEL; mkdir -p "$OUT"
scrape(){ sg incus-admin -c "incus exec ${REMOTE}:${FW} -- bash -c 'curl -s http://127.0.0.1:8080/metrics'" 2>/dev/null; }
echo "[$LABEL] 5211 uncapped P12 5s -> kill -> 5208 P12 ${DUR}s"
# launch 5211 detached on the host
sg incus-admin -c "incus exec ${REMOTE}:${HOST} -- bash -c 'nohup iperf3 -c ${TARGET} -p 5211 -P12 -t 60 >/dev/null 2>&1 & echo started'" >/dev/null 2>&1
sleep 5
sg incus-admin -c "incus exec ${REMOTE}:${HOST} -- bash -c 'pkill -f \"iperf3 -c ${TARGET} -p 5211\"'" >/dev/null 2>&1 || true
# now the measurement run on 5208
sg incus-admin -c "incus exec ${REMOTE}:${HOST} -- bash -c 'iperf3 -c ${TARGET} -p 5208 -P12 -t ${DUR} -J --forceflush'" > "$OUT/iperf.json" 2>"$OUT/iperf.err" &
P=$!
sleep 12; scrape > "$OUT/metrics_t12.prom"
sleep $((DUR-12-8)); scrape > "$OUT/metrics_steady.prom"
wait $P || true
echo "[$LABEL] done"
