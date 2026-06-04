#!/usr/bin/env python3
# Analyze a #1766 char run: per-stream CoV, q8 {a_i}, Cstruct, v8 grant
# share, equal_flow state. NOT production code.
import json, sys, re, statistics, glob, os

def cov(xs):
    xs = [x for x in xs if x is not None]
    if len(xs) < 2: return 0.0
    m = statistics.mean(xs)
    if m == 0: return 0.0
    return statistics.pstdev(xs)/m

def cstruct(ai, nv=6):
    # per-flow share multiset: for each active worker with a flows, a copies of 1/a
    shares=[]
    for a in ai:
        if a>0:
            shares += [1.0/a]*a
    return cov(shares)

def parse_metric(text, name, qid=None):
    out={}
    for line in text.splitlines():
        if not line.startswith(name): continue
        m=re.match(rf'{re.escape(name)}\{{([^}}]*)\}}\s+([0-9.eE+-]+)', line)
        if not m: continue
        labels=dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        if qid is not None and labels.get('queue_id')!=str(qid): continue
        wid=labels.get('worker_id')
        out[wid]=float(m.group(2))
    return out

def main():
    d=sys.argv[1]
    ij=json.load(open(f'{d}/iperf.json'))
    streams=ij['end']['streams']
    rates=[s['sender']['bits_per_second']/1e9 for s in streams]
    retr=sum(s['sender'].get('retransmits',0) for s in streams)
    sumg=sum(rates)
    t12=open(f'{d}/metrics_t12.prom').read()
    st=open(f'{d}/metrics_steady.prom').read()
    # q8 active flow distribution at steady
    af=parse_metric(st,'xpf_userspace_cos_active_flow_count',8)
    ai=[int(af.get(str(w),0)) for w in range(6)]
    # v8 granted bytes delta t12->steady
    g12=parse_metric(t12,'xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total')
    gst=parse_metric(st,'xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total')
    c12=parse_metric(t12,'xpf_userspace_worker_cos_queue_lease_acquire_v8_calls_total')
    cst=parse_metric(st,'xpf_userspace_worker_cos_queue_lease_acquire_v8_calls_total')
    gd=[gst.get(str(w),0)-g12.get(str(w),0) for w in range(6)]
    cd=[cst.get(str(w),0)-c12.get(str(w),0) for w in range(6)]
    # production fairness gauges (daemon-computed)
    def gauge(text,name):
        for line in text.splitlines():
            if line.startswith(name) and 'queue_id="8"' in line:
                return float(line.rsplit(' ',1)[1])
        return None
    daemon_cs=gauge(st,'xpf_fairness_cstruct')
    daemon_mws=gauge(st,'xpf_fairness_max_worker_flow_share')
    surplus=gauge(st,'xpf_userspace_cos_drain_surplus_sent_bytes_total')
    guarantee=gauge(st,'xpf_userspace_cos_drain_guarantee_sent_bytes_total')
    # equal_flow state
    ef=[l for l in st.splitlines() if 'cos_equal_flow' in l and 'queue_id="8"' in l]
    obs_cov=cov(rates)
    cs=cstruct(ai)
    print(f"== {os.path.basename(d)} ==")
    print(f"streams N={len(rates)} SUM={sumg:.2f} Gb/s retrans={retr}")
    print(f"per-stream Gb/s sorted: {sorted(round(r,2) for r in rates)}")
    print(f"q8 {{a_i}} steady (w0..w5): {ai}  Nactive={sum(1 for a in ai if a>0)}")
    print(f"observed per-flow CoV = {obs_cov*100:.1f}%")
    print(f"Cstruct(draw)         = {cs*100:.1f}%")
    print(f"gap (obs - Cstruct)   = {(obs_cov-cs)*100:+.1f} pp   ε=5pp  -> {'PHYSICS (<=Cstruct+5pp)' if obs_cov<=cs+0.05 else 'GAP (>Cstruct+5pp)'}")
    print(f"daemon xpf_fairness_cstruct={None if daemon_cs is None else round(daemon_cs*100,1)}%  max_worker_flow_share={None if daemon_mws is None else round(daemon_mws,3)}")
    print(f"drain surplus_sent={None if surplus is None else round(surplus/1e9,1)}GB  guarantee_sent={None if guarantee is None else round(guarantee/1e9,1)}GB")
    print(f"v8 granted GB delta (w0..w5): {[round(x/1e9,2) for x in gd]}")
    print(f"v8 grant-share CoV across workers = {cov([x for x in gd])*100:.1f}%")
    print(f"v8 acquire-calls delta (w0..w5): {[int(x) for x in cd]}")
    if ef:
        print("equal_flow q8 metrics:")
        for l in ef: print("  "+l)
    else:
        print("equal_flow q8 metrics: ABSENT (enforcement OFF)")
    # grant-per-flow sanity: granted bytes per active flow should be ~flat if v8 fair-share working
    gpf=[ (gd[w]/ai[w]) if ai[w]>0 else None for w in range(6)]
    print(f"v8 grant-per-flow GB (w0..w5): {[round(x/1e9,3) if x else None for x in gpf]}")
    print(f"grant-per-flow CoV (active only) = {cov([x for x in gpf if x is not None])*100:.1f}%")

main()
