import random, statistics
random.seed(42)

def pop_cov_per_flow(counts):
    # counts: list of flows-per-active-worker (exclude zeros)
    shares=[]
    for c in counts:
        if c==0: continue
        shares += [1.0/c]*c   # per-flow rate = (1/Nv)*share, constant factors cancel
    m=sum(shares)/len(shares)
    var=sum((s-m)**2 for s in shares)/len(shares)
    return (var**0.5)/m

def sim(N,K,trials=200000):
    tot=0.0
    for _ in range(trials):
        bins=[0]*K
        for _ in range(N):
            bins[random.randrange(K)]+=1
        tot+=pop_cov_per_flow(bins)
    return tot/trials

for N in (6,12,24,48):
    base=sim(N,6)
    # naive "fanout doubles K" assuming each of 6 hw queues splits to 2 sw slots,
    # AND the per-slot capacity is HALVED (shared hw-queue bandwidth) -> capacity cancels in CoV,
    # so per-flow CoV floor is just multinomial(N,12) IF flows spread evenly across 12 slots.
    fan=sim(N,12)
    print(f"N={N:3d}: floor K=6 = {base:.4f} | floor K=12(fanout) = {fan:.4f} | delta = {fan-base:+.4f}")

print("\n--- Lazy fanout: split ONLY the single hottest queue into 2 slots ---")
def sim_lazy(N,K=6,trials=200000):
    base_t=0.0; lazy_t=0.0
    for _ in range(trials):
        bins=[0]*K
        for _ in range(N):
            bins[random.randrange(K)]+=1
        base_t+=pop_cov_per_flow(bins)
        # split hottest queue's flows into two ~equal slots
        bins2=bins[:]
        hi=bins2.index(max(bins2))
        c=bins2[hi]
        bins2[hi]=c//2
        bins2.append(c-c//2)
        lazy_t+=pop_cov_per_flow(bins2)
    return base_t/trials, lazy_t/trials
for N in (12,24,48):
    b,l=sim_lazy(N)
    print(f"N={N:3d}: floor base = {b:.4f} | lazy-split-hottest = {l:.4f} | delta = {l-b:+.4f}")

print("\n--- Capacity-aware: each WORKER has capacity 1.0; a fanned queue's 2 slots SHARE one hw-queue bw ---")
print("    per-flow rate = (worker_capacity / flows_on_worker); fanned slots split ONE queue's bw, not add a core")
def sim_capacity(N,K=6,trials=100000):
    base_t=0.0; fan_t=0.0
    for _ in range(trials):
        bins=[0]*K
        for _ in range(N):
            bins[random.randrange(K)]+=1
        # base: each active queue has capacity 1.0 (its own core), per-flow = 1/c
        def cov_caps(items):  # items: list of (capacity, nflows)
            shares=[]
            for cap,c in items:
                if c==0: continue
                shares += [cap/c]*c
            m=sum(shares)/len(shares); var=sum((s-m)**2 for s in shares)/len(shares)
            return (var**0.5)/m
        base_items=[(1.0,c) for c in bins]
        base_t+=cov_caps(base_items)
        # fanout hottest into 2 slots that SHARE the queue's 1.0 hw capacity (0.5 each), no new core
        hi=bins.index(max(bins)); c=bins[hi]
        fan_items=[(1.0,bins[i]) for i in range(K) if i!=hi]
        fan_items.append((0.5,c//2)); fan_items.append((0.5,c-c//2))
        fan_t+=cov_caps(fan_items)
    return base_t/trials, fan_t/trials
for N in (12,24,48):
    b,f=sim_capacity(N)
    print(f"N={N:3d}: floor base = {b:.4f} | fanout(shared-bw, no new core) = {f:.4f} | delta = {f-b:+.4f}")
