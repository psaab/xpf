# Claude SMR plan-review r1 — #1608

**Reviewer hat:** HPC networking + DDoS mechanism + AF_XDP cache
design + CPU-arch (L1/L2/branch) reviewer. Hostile by mandate.

**Verdict:** PLAN-KILL (provisional — convertible to PLAN-NEEDS-MAJOR
on response to F1+F2)

## Convergent thesis

Two of the three structural concerns below are recoverable, but the
first one is plan-level fatal: the 4c.1 per-source rate-limit is
**per-AF_XDP-queue, not per-source-IP**, and the entire "small botnet
floods don't take out the cold path" justification depends on the
latter semantic. The plan correctly admits this in R2 — but R2's
admission is the entire problem, not a footnote.

## F1 (FATAL) — Per-source-IP rate-limit is not per-source-IP

§9 R2 admits "the per-worker bucket is effectively N× the configured
rate" under the realistic attack (random src_port). This means the
CLI knob's semantic is "per-source per-AF_XDP-queue" — and AF_XDP
queue assignment is RSS-hash-driven, not operator-controlled.

The attacker who knows or guesses N (typically 8-16 on production
hardware) sets their packet rate to `(operator_pps − ε) × N` and
**every worker's bucket stays below threshold** — full bypass. The
operator-facing semantic "set 1000 cold-path packets/sec per source IP"
in the issue body is unimplementable on the AF_XDP zero-copy fast
path without cross-worker shared state.

This isn't a documentation problem. The issue's acceptance criterion
explicitly says "≥50% CPU% drop under 1 Mpps cold-path flood from
10 source IPs." With 10 sources × N=12 workers, the attacker gets
12× headroom under a per-worker bucket. Acceptance fails by
construction.

**Recovery options (must pick one before PLAN-READY):**

(a) Cross-worker shared per-source state — atomic 8-byte token counter
    in a shared open-addressed table, like the shared session map.
    Costs MESI ping-pong on every cold-path miss (~50-100 cycles vs the
    5-cycle per-worker version). Still a win vs full policy scan
    (~500-1000 cycles).

(b) Truthful CLI semantic — rename the knob to
    `cold-path-rate-limit per-source-per-worker` and document the N
    multiplier. Operators set the per-worker rate; total budget is
    N × that rate. Reasonable for many deployments, but DOES NOT
    meet the issue's stated acceptance criterion.

(c) Pre-RSS aggregation — count source-IP packets at the userspace-xdp
    shim BEFORE the AF_XDP queue dispatch. This is the correct layer
    architecturally but adds eBPF map writes per packet, a fundamental
    perf regression for the legitimate-traffic case. Likely a
    non-starter.

(d) Per-worker bucket with cross-worker advisory sync — each worker
    maintains its own bucket, but every K-th drop emits a token to
    a shared rate-limit counter that all workers consult before
    deciding to drop. Probabilistic; still leaks N× headroom in the
    common case.

My recommendation: (b) with the truthful name. This issue ships
defensive depth; honest semantics > meeting an aspirational
acceptance number. The 4c block stays valuable because under a
SINGLE-source attack (true botnet-style with no src_port spray), RSS
delivers all packets to one queue and the per-worker bucket IS the
per-source bucket. The whole-attack class that 4c.1 stops is
"single-source loud," not "many-source spray."

## F2 (FATAL) — Verdict cache returns wrong verdicts under per-packet match

§3.1 fixes the src_port concern by widening the key, but DSCP,
forwarding-class, fragment-flags, TCP-flag, and routing-instance
matches are also per-packet dimensions a policy can use. The plan's
R3 hand-waves "reuse the has_dscp_match gate" — but that gate is
DSCP-specific. Each per-packet match dimension needs its own gate.

The flow-cache solved this with the cache-key-invariant doc in
`protocol/security.rs:62-90` and the explicit (a)-extend-key /
(b)-cache-sensitive classification. The verdict cache plan does
not. Reviewers MUST require the verdict cache to ride the same
infrastructure (`Filter.has_<X>_match_terms` aggregate flag, plus a
table extension here for any future per-packet match field).

Recovery: cite `protocol/security.rs:62-90` invariant explicitly,
add a "match dimension X coverage" table in §3.3 listing every
current per-packet match in policy rule shape, and gate cache
insertion off when any out-of-key match is present. If the gate is
on more than ~5% of typical configs, the cache is useless — measure
in the bench.

## F3 (MAJOR) — Cache-bench substitute for 1 Mpps wire-line is gimcrack

§0 + §9 R1 admits the synthetic flood harness belongs to #1607.
Substituting a cargo-bench that drives the rate-limit + verdict cache
from a synthetic descriptor stream doesn't measure:

- AF_XDP RX driver cost (you skip the part that matters for "CPU% per worker")
- Cache pollution from the existing flow-cache scan
- RSS spray (you can't fake N-way queue spread in a single-thread bench)

A cargo bench tells you the rate-limit + cache cells are fast in
isolation. It does NOT tell you whether they meet the acceptance
criterion "CPU% per worker drops ≥ 50% under 1 Mpps cold-path flood."
Reviewers will catch this; the honest path is to gate this PR on
#1607's microbench harness landing, or downgrade the acceptance
criterion to "unit-level: gate is O(1) hash + branch, cache is O(1)
hash + branch."

Recovery: downgrade the acceptance criterion. The defensive-depth
value of 4c is real and provable WITHOUT a 1 Mpps lab number;
that's the right honest framing.

## F4 (MAJOR) — `now_ns` cadence is multi-millisecond under flood

The plan's §2.2 claims "the cached now_ns is sub-ms under load."
That's true for the legitimate-traffic case where the worker
processes a full burst quickly. Under a 1 Mpps cold-path flood, the
worker is policy-scan-bound and spends MUCH longer per batch. now_ns
might be 50-100 ms stale across a single poll burst (the worker is
in the policy linear scan loop the entire time).

If the cache is on the cold path BEHIND the policy linear scan, the
poll batch doesn't refresh now_ns until the batch is drained. The
rate-limit sees a stale now_ns and refills the same bucket multiple
times per real-second — exact opposite of what we want.

Recovery: confirm poll_descriptor batch structure refreshes now_ns
at least every N descriptors (likely yes — `now_ns` is captured at
batch start). If batch can hold many seconds of work, plan needs
a periodic now_ns refresh inside the batch loop. Cite the call site.

## F5 (MINOR) — IPv6 `Option<IpAddr>` is 17B but plan says 17 + 8 = 24B

Storage math in §2.1: `IpAddr` is actually 17 bytes (1 discriminant +
16 payload). `Option<IpAddr>` is 17 + 1 padding (None tag) = 24 with
alignment. `TokenBucket` is `u32 + u64` = 16 (8-aligned). Total per
entry is 24 + 16 = 40 B, not 24 + 8 = 32 B. 4 K entries × 40 B = 160 KB
just for 4c.1; plus 4c.2 with `(IpAddr, IpAddr, u16, u16, u8)` ≈ 40 B
key + 16 B value = 56 B per entry × 4 K = 224 KB. **Total 384 KB —
EXCEEDS the 256 KB acceptance criterion.**

Recovery options:
- Compact key (32-bit src_ip for v4, 64-bit truncated hash for v6 keyed
  by full IpAddr verification on hit). Costs a hash + memcmp; OK
  since cold path was already O(rules) anyway.
- Reduce to 2 K entries × 4 ways = 8 K total.
- Separate v4 and v6 tables; v4 entries are 4 + 8 = 12 B → 192 KB
  for 16 K entries. V6 gets the smaller table.

Pick one before PLAN-READY.

## F6 (MINOR) — Verdict cache cold-start on HA failover masks a real attack

§4 says "the verdict cache is similarly cold on failover. Acceptable."
This is true for legitimate traffic. For the attack-in-progress case,
the verdict cache on the OLD master had absorbed 10 K port-scan probes
to "deny" verdicts. After failover, the NEW master sees those same
probes as cold-path-novel and runs the full policy scan on each. The
acceptance criterion is "≥30% policy-eval cycles drop on second pass" —
"second pass" might mean "second pass on the same node" (passes
trivially) or "second pass over the wire" (fails after failover).

Recovery: state the criterion as same-node second pass; document the
failover wipe. Optionally: explore HA-sync of the verdict cache as a
follow-up issue.

## F7 (NIT) — `Some(0)` defensive handling is silent UB

§1.2 says `Some(0)` is treated as `None`. This is silently lossy. If
operator sets `cold-path-rate-limit per-source 0` they almost
certainly meant "drop everything" not "no limit." Reject at config
compile time with a `commit check` warning, or treat as drop-all.
Picking either is fine; silent reinterpretation is not.

## What is right about this plan

- §1.4 ordering (after flow-cache miss, before policy resolution) is correct.
- §3.4 distinguishes verdict-cache vs flow-cache cleanly — answers the
  obvious "isn't this the flow cache" reviewer reflex.
- §5 counter list is well-chosen for ops.
- The §10 out-of-scope list is realistic.
- The §11 v1 framing and "iterate before code lands" stance is right.

## Verdict and exit path

**PLAN-KILL (provisional)** — Cannot land as-is.

Convertible to PLAN-NEEDS-MAJOR by addressing F1 + F2 with explicit
recovery choices. F3-F5 are MAJOR but recoverable by rewording. F6-F7
are nit-tier.

Round-2 plan must include:

1. Truthful F1 semantic — either ship a cross-worker shared bucket
   (and pay the MESI cost honestly) or rename the knob to
   per-source-per-worker and document the N multiplier.
2. F2 cache-key-invariant table + has_<X>_match gate-off behavior
   per existing #1431 infrastructure.
3. F3 downgrade acceptance to in-isolation microbench OR explicit
   sequencing gate on #1607.
4. F5 storage math corrected; choose compaction path.
5. F4 now_ns cadence cited from poll_descriptor mod.rs.

— Claude SMR
