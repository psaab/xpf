#!/usr/bin/env python3
# #1742 same-queue XSK fanout — per-flow CoV floor simulation.
# Population CoV, matching userspace-dp/src/fairness.rs compute_observed_cov.
import random
random.seed(42)

def cov_caps(items):
    # items: list of (capacity, nflows). per-flow rate = capacity/nflows.
    shares = []
    for cap, c in items:
        if c == 0:
            continue
        shares += [cap / c] * c
    if not shares:
        return 0.0
    m = sum(shares) / len(shares)
    var = sum((s - m) ** 2 for s in shares) / len(shares)
    return (var ** 0.5) / m

def draw(N, K):
    bins = [0] * K
    for _ in range(N):
        bins[random.randrange(K)] += 1
    return bins

def sim(N, K=6, beta=1.0, split="binomial", trials=200000):
    """Split the hottest queue into 2 slots.
    beta = effective capacity of the fanned hot queue / baseline (1.0 each
    other queue). beta=1.0 => bandwidth-bound (slots SHARE one hw queue's bw,
    NO new core). beta>1.0 => processing-bound with added/stolen CPU."""
    base_t = 0.0; fan_t = 0.0
    for _ in range(trials):
        bins = draw(N, K)
        base_t += cov_caps([(1.0, c) for c in bins])
        hi = bins.index(max(bins)); c = bins[hi]
        if split == "perfect":
            a, b = c // 2, c - c // 2
        else:  # stateless 5-tuple hash => Binomial(c, 0.5)
            a = sum(1 for _ in range(c) if random.random() < 0.5); b = c - a
        items = [(1.0, bins[i]) for i in range(K) if i != hi]
        items.append((beta / 2.0, a)); items.append((beta / 2.0, b))
        fan_t += cov_caps(items)
    return base_t / trials, fan_t / trials

if __name__ == "__main__":
    print("Baseline reproduces documented floor (N=12,K=6 closed-form 0.5106):")
    for N in (6, 12, 24, 48):
        b, _ = sim(N, beta=1.0)
        print(f"  N={N:3d}: floor K=6 = {b:.4f}")

    print("\nbeta=1.0 (bandwidth-bound, no new core) — split-hottest:")
    for N in (12, 24, 48):
        b, perf = sim(N, beta=1.0, split="perfect")
        _, binom = sim(N, beta=1.0, split="binomial")
        print(f"  N={N:3d}: base={b:.4f} perfect={perf:+.4f} (d={perf-b:+.4f}) "
              f"binomial={binom:.4f} (d={binom-b:+.4f})")

    print("\nbeta sweep (binomial split) — processing-bound regime:")
    for N in (12, 24, 48):
        b, _ = sim(N, beta=1.0)
        row = [f"N={N:3d} base={b:.4f}"]
        for beta in (1.0, 1.25, 1.4, 2.0):
            _, f = sim(N, beta=beta, split="binomial")
            row.append(f"b={beta}:{f-b:+.4f}")
        print("  " + "  ".join(row))
