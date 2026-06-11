import sys, re, glob, os
def load(f):
    d={}
    for line in open(f):
        m=re.match(r'(\w+)\{([^}]*)\}\s+([0-9.e+-]+)',line)
        if m: d[(m.group(1),m.group(2))]=float(m.group(3))
    return d
qname={'1':'100m','2':'1g','3':'3g','4':'6g','5':'9g','6':'12g','10':'24g'}
for d in sorted(sys.argv[1:]):
    b=load(d+'/metrics-before.txt'); a=load(d+'/metrics-after.txt')
    dd={k:a[k]-b.get(k,0) for k in a}
    ep=sum(v for (n,l),v in dd.items() if n=='xpf_userspace_cos_waterfill_epochs_total')
    brk=sum(v for (n,l),v in dd.items() if n=='xpf_userspace_cos_waterfill_phase1_budget_breaks_total')
    print(f"=== {os.path.basename(d)}  epochs={ep:,.0f} (mean {180e6/ep if ep else 0:,.0f}ns/worker-epoch)  breaks={brk:,.0f}")
    print(f"{'q':<5}{'class':<6}{'p1adm':>10}{'p2adm':>10}{'sent_GB':>9}{'B/honor':>9}{'elig':>10}")
    for q in ['1','2','3','4','5','6','10']:
        def g(n):
            return sum(v for (nm,l),v in dd.items() if nm==n and f'queue_id="{q}"' in l)
        p1=g('xpf_userspace_cos_waterfill_phase1_admissions_total')
        p2=g('xpf_userspace_cos_waterfill_phase2_admissions_total')
        s=g('xpf_userspace_cos_drain_guarantee_sent_bytes_total')
        el=g('xpf_userspace_cos_waterfill_eligible_visits_total')
        tot=p1+p2
        if tot or s:
            print(f"{q:<5}{qname.get(q,'?'):<6}{p1:>10,.0f}{p2:>10,.0f}{s/1e9:>9.2f}{(s/tot if tot else 0):>9,.0f}{el:>10,.0f}")
    # undergrant causes
    for cause in ['share_exhausted','class_cap','epoch_rotated','seqlock_give_up','cap_zero','outstanding_cap']:
        v=sum(val for (n,l),val in dd.items() if 'undergrant' in n and cause in l)
        if v: print(f"  undergrant {cause}: {v:,.0f}")
