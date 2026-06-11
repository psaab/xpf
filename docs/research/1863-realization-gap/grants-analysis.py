import sys, re, os
def load(f):
    d={}
    for line in open(f):
        m=re.match(r'(\w+)\{([^}]*)\}\s+([0-9.e+-]+)',line)
        if m: d[(m.group(1),m.group(2))]=float(m.group(3))
    return d
for d in sorted(sys.argv[1:]):
    b=load(d+'/metrics-before.txt'); a=load(d+'/metrics-after.txt')
    dd={k:a[k]-b.get(k,0) for k in a}
    g=[(l,v) for (n,l),v in dd.items() if n=='xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total']
    calls=sum(v for (n,l),v in dd.items() if n=='xpf_userspace_worker_cos_queue_lease_acquire_v8_calls_total')
    sent=sum(v for (n,l),v in dd.items() if n=='xpf_userspace_cos_drain_guarantee_sent_bytes_total')
    tot=sum(v for l,v in g)
    per=' '.join(f"{v/1e9:.1f}" for l,v in sorted(g))
    print(f"{os.path.basename(d):<24} grants={tot/1e9:6.1f}GB sent={sent/1e9:6.1f}GB calls={calls:>10,.0f} per-worker(GB): {per}")
