#!/usr/bin/env bash
# #1614 residual-v2 measurement cell runner. Run under: flock /tmp/xpf-cluster.lock sg incus-admin -c "/tmp/xpf1614/run-cell.sh <cellname> <port> [port...]"
# Env: DURATION (default 30), STREAMS (default 12), UDP_BW (if set, run iperf3 -u -b $UDP_BW per stream)
set -euo pipefail
CELL="$1"; shift
PORTS=("$@")
DURATION="${DURATION:-30}"
STREAMS="${STREAMS:-12}"
TARGET="${TARGET:-172.16.80.200}"
HOST="loss:cluster-userspace-host"
FW="${FW:-loss:xpf-userspace-fw1}"
ART="/tmp/xpf1863/cells/${CELL}-$(date +%H%M%S)"
mkdir -p "$ART"

snap() {
  incus exec "$FW" -- curl -s 127.0.0.1:8080/metrics \
    | grep -E '^xpf_(userspace_cos_|userspace_worker_cos_)' > "$ART/$1" || true
}

snap metrics-before.txt

# UDP_MODE=1: open-loop UDP, per-stream -b = shape*factor/streams (inelastic demand ≥ shape)
declare -A SHAPE_M=( [5201]=100 [5202]=1000 [5203]=3000 [5204]=6000 [5205]=9000 [5206]=12000 [5207]=15000 [5208]=18000 [5209]=21000 [5210]=24000 [5211]=24000 )
UDP_FACTOR="${UDP_FACTOR:-110}"  # percent of shape to offer

pids=()
for port in "${PORTS[@]}"; do
  UDP_FLAG=""
  if [ "${UDP_MODE:-0}" = "1" ] || [[ " ${UDP_PORTS:-} " == *" $port "* ]]; then
    per_stream_m=$(( SHAPE_M[$port] * UDP_FACTOR / 100 / STREAMS ))
    [ "$per_stream_m" -lt 1 ] && per_stream_m=1
    UDP_FLAG="-u -b ${per_stream_m}M -l 1400"
  fi
  ( incus exec "$HOST" -- iperf3 -c "$TARGET" -P "$STREAMS" -t "$DURATION" -p "$port" $UDP_FLAG --json \
      > "$ART/sim_${port}.json" 2> "$ART/sim_${port}.err" || true ) &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done

snap metrics-after.txt

python3 - "$ART" "${PORTS[@]}" <<'PYEOF'
import json, os, statistics, sys
art = sys.argv[1]
ports = [int(p) for p in sys.argv[2:]]
shape = {5201:0.1,5202:1.0,5203:3.0,5204:6.0,5205:9.0,5206:12.0,5207:15.0,5208:18.0,5209:21.0,5210:24.0,5211:0.0}
name = {5201:"100m",5202:"1g",5203:"3g",5204:"6g",5205:"9g",5206:"12g",5207:"15g",5208:"18g",5209:"21g",5210:"24g",5211:"uncap"}
total=0.0
print(f"{'port':<6}{'class':<8}{'shape':>7}{'recv_G':>8}{'%shape':>8}{'CoV%':>7}{'retr':>7}{'lossp':>7}")
for port in ports:
    try:
        d=json.load(open(os.path.join(art,f"sim_{port}.json")))
    except Exception as e:
        print(f"{port:<6}ERROR {e}"); continue
    streams=d.get("end",{}).get("streams",[])
    rates=[]
    udp=False
    for s in streams:
        if "udp" in s:
            udp=True
            bps=s["udp"].get("bits_per_second",0)
        else:
            bps=s.get("sender",{}).get("bits_per_second",0)
        if bps>0: rates.append(bps/1e9)
    if udp:
        # receiver-side: sum lost/total over streams; throughput = sent*(1-loss)
        tot_pk=sum(s["udp"].get("packets",0) for s in streams)
        lost=sum(s["udp"].get("lost_packets",0) for s in streams)
        sent_g=sum(rates)
        lossp=100.0*lost/tot_pk if tot_pk else 0
        recv=sent_g*(1-lossp/100.0)
        retr=0
    else:
        sr=d.get("end",{}).get("sum_received") or {}
        ss=d.get("end",{}).get("sum_sent") or {}
        recv=(sr.get("bits_per_second") or ss.get("bits_per_second") or 0)/1e9
        retr=ss.get("retransmits",0) or 0
        lossp=0
    cov=(statistics.stdev(rates)/statistics.mean(rates)*100) if len(rates)>1 and statistics.mean(rates)>0 else 0
    sh=shape[port]
    pct=recv/sh*100 if sh>0 else 0
    total+=recv
    print(f"{port:<6}{name[port]:<8}{sh:>6.1f}G{recv:>7.2f}G{pct:>7.1f}%{cov:>6.1f}%{retr:>7}{lossp:>6.2f}%")
print(f"{'SUM':<6}{'':<8}{'':>7}{total:>7.2f}G")
PYEOF
echo "ART=$ART"
