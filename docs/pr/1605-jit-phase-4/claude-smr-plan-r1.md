# Claude SMR plan-review — Phase 4 Cranelift JIT (round 1)

**VERDICT: PLAN-KILL.**

Round 1 of hostile review against plan v1 (commit
`c469829ffa6f4a8579912616c8b65c12a5ade6e3`). I'm reviewing through
three hats: dataplane SMR (AF_XDP/UMEM physics, TCP/UDP semantics,
HA sync portability), CPU architecture (cache, branch prediction,
iTLB, MESI), and software-design patterns (ownership, invariants
under concurrency, error propagation).

The verdict is PLAN-KILL because the plan's own honest-framing
section is correct: Phase 4 optimises a code path that the shipped
descriptor implementation has already collapsed into ~30 instructions
with `#[inline(always)]`. The doc's "+30-50%" estimate is a March
2026 number that predates Option C landing and is structurally
obsolete. The plan's leading hypothesis is the right verdict. Below
are the hostile checks I ran to confirm it, plus a few weaknesses
in the plan itself that should be tightened before the kill is
published.

## Findings

### F1 (CONFIRM-KILL): The 2-3 ns / 0.4-0.6% ceiling is real

Walked `userspace-dp/src/afxdp/frame/rewrite/ipv4.rs:14-123`. The
IPv4 arm is:

- One `packet.len() < ip + 20` check (one CMP+JCC).
- One IHL parse + range check (load+AND+SHL+CMP+JCC).
- One TTL check (`packet[ip + 8] <= 1`).
- Optional `expected_ports` two-port compare branch.
- Four optional NAT byte writes (each behind
  `if let Some(IpAddr::V4(...))` patterns that branch-predict
  perfectly on a steady flow — predictor sees the same outcome
  every packet).
- One TTL decrement (`packet[ip + 8] -= 1`).
- One IP-csum: load old, build sum from `ip_csum_delta` field
  and constant `0xFEFF`, fold once, store.
- One L4-csum: same shape with `l4_csum_delta`.

What Cranelift would do differently: embed `dst_mac`, `src_mac`,
`vlan_id`, `ether_type`, `rewrite_src_ip`, `rewrite_dst_ip`,
`rewrite_src_port`, `rewrite_dst_port`, `ip_csum_delta`,
`l4_csum_delta` as immediates instead of loads from `&rd`. The
struct (`flow_cache.rs:50-74`) is ~96 bytes; the hot-path loads
touch maybe two cache lines worth of `RewriteDescriptor`. Saving
those loads is real but bounded.

At 3 GHz the in-L1 load-to-use latency is ~4 cycles ≈ 1.3 ns;
worst case (L2 hit) ~12 cycles ≈ 4 ns. **The descriptor lives
inside `FlowCacheEntry` which the hot path already has in cache
(it just succeeded a key compare).** So L1 hits are the steady
state and the per-load savings are dominated by the few ns of
load-to-use port pressure, not by cache misses.

The plan's 2-3 ns/packet is honest. At 1.92 Mpps that is 0.4-0.6%
of one core (4-6 ms of CPU per wall-clock second), buried under
memcpy 8%, NAPI 12%, syscalls 3%, and the rest of `poll_binding`'s
22% which includes the cache lookup, validation, mirror sampling,
COS classification, and `pending_tx_prepared.push_back` (verified
`flow_cache_hit.rs:310-326`). **Nothing Cranelift emits at the
rewrite arm changes any of those.**

### F2 (CONFIRM-KILL): Compile-cost amortization rules out short flows

100 µs Cranelift compile / 2-3 ns saved per packet ⇒ 33-50 k
packets minimum to break even on the compile cost alone.

Production firewall traffic mix (typical operator deployment):

- DNS queries: 2 packets per flow. **Never amortizes.**
- HTTP/3 short request (8 KB): ~6 packets. **Never amortizes.**
- TLS-only flow (browser tab, idle keepalive): ~50 packets/session.
  **Never amortizes.**
- Bulk TCP transfer (>1 MB): ~700+ packets. **Maybe amortizes if
  flow lifetime > ~17 ms at line rate.**
- iperf3 30s stream: ~250k packets. **Easily amortizes — but this
  is a benchmark workload, not production.**

Under DDoS / port scans / SYN floods, every new flow burns 100 µs
of compile time. At 10 k flows/sec that's 1 second of compile CPU
per wall-clock second per core — JIT thrashes the dataplane to a
halt. The plan's mitigation ("gate on bytes_observed > 64 KB AND
lifetime_packets > 1000") works but it means **JIT activates on
~0% of real flows**.

This is sufficient for kill on its own.

### F3 (CONFIRM-KILL): HA sync is descriptor-rebuild, not
descriptor-replay

Verified: `pkg/cluster/` has zero `RewriteDescriptor` references
(grep returned nothing). The synced session-table wire format
does not include the descriptor. The new primary calls
`RewriteDescriptor::from_forward_decision` (`flow_cache.rs:228`)
on first cache miss after failover. This means:

- Plan's Question 3 (HA failover semantics) answer is correct:
  no JIT page replay needed, peer rebuilds on the data path.
- But it also means Phase 4 would have to either skip JIT
  generation entirely on the just-recovered primary until traffic
  settles, OR risk the same compile-storm problem at failover
  time (when the entire session table flushes through the flow
  cache cold).

This is a second-order problem on top of F2.

### F4 (CONFIRM-KILL): TX path is safe but the safety argument is
trivial because TX doesn't re-call rewrite

Walked `userspace-dp/src/afxdp/tx/transmit/stage.rs:15-60` and the
`PreparedTxRequest` definition usage. The TX stage consumes
`offset`, `len`, `recycle`, `expected_ports`, `expected_protocol`,
`egress_ifindex`, `cos_queue_id`, `dscp_rewrite`, `mirror_clone`.
It does NOT re-invoke any rewrite function — the rewrite has
already mutated the UMEM bytes before push_back.

So the PROT_EXEC eviction barrier the plan worries about
(Question 4) is in fact a non-issue: the JIT function is only
called during rewrite_in_place, and that completes synchronously
before the request hits the TX queue. The plan over-engineers
this with an RCU epoch barrier proposal. Simpler: the JIT
function lifetime is tied to a single rewrite call, which is
synchronous. No barrier needed for already-emitted bytes.

This is a finding against the plan's complexity, not against its
verdict. If Phase 4 ever revives, drop the RCU section.

### F5 (CONFIRM-KILL): Phase 3 trie integration is unwired

Verified: `userspace-dp/src/prefix_set.rs:180-225` defines
`PrefixTrieV4` and `PrefixTrieV6`. But `userspace-dp/src/policy.rs:2`
imports `PrefixSetV4` and `PrefixSetV6` (the linear/hashmap form),
NOT the trie. Spot-check at `policy.rs:65-88` and `policy.rs:341`
confirms the policy address-set fields are `PrefixSetV4`/`V6` —
the trie types are **dead code on master**.

The plan's Question 7 recommendation (split Phase 3 out as a
standalone ~200-LOC PR wiring the existing trie types into
`policy.rs`'s match path) is the right call. That work is
independent of Phase 4 and would land real benefit (O(log N) vs
O(N) per address-book match for policies with large CIDR sets).

### F6 (CONFIRM-KILL): Architectural-mismatch pattern matches #946
Phase 2 and #961

Project memory documents two prior PLAN-KILLs with the same shape:
"Refactor: <Pattern>" issue proposing a large architectural change
that ships partially as a smaller phase, then the original full
plan gets killed because the shipped phase absorbed most of the
benefit. #946 Phase 2 (batched pipeline) was killed because Phase 1
already extracted the per-packet stages. #961 (PacketContext) was
killed for similar reasons.

Phase 4 fits the pattern: Phase 1 (descriptors with `#[inline(always)]`)
absorbed the rewrite-path wins. The standalone trie work fits in a
separate small PR. The original "JIT the rewrite functions"
proposal no longer has a credible perf gap to close.

### F7 (PLAN-WEAKNESS): Option D is hand-wavy in the plan

The plan proposes "widen the descriptor into 4 variants
(apply_nat × {src_only, dst_only, both, none})". This is
unconvincing:

- The variant-selection branch must live somewhere. Either:
  (a) a `fn(&mut [u8], ...)` field on `FlowCacheEntry` (one
  indirect call per packet, branch-predictor friendly but still
  an indirect call), or (b) a 2-bit tag + match (still a branch).
  Either is ~1-2 ns/packet.
- The existing `if let Some(IpAddr::V4(...))` patterns in
  `apply_rewrite_descriptor_ipv4` branch-predict perfectly on a
  steady flow. The predictor sees `Some` every packet for the
  whole flow lifetime. The branch's cost is essentially zero in
  steady state.

So Option D's claimed "captures 90% of Cranelift's win for 5% of
the engineering cost" is probably "captures 0% of Cranelift's
win for 5% of the engineering cost". The branches Option D
removes are already free.

This further reinforces the kill: there isn't even an Option D
salvage that's worth doing.

### F8 (PLAN-WEAKNESS): Plan understates the binary-size / build
budget hit

Cranelift's actual dependency tree (regalloc2, cranelift-codegen,
cranelift-frontend, cranelift-module, cranelift-jit, target-lexicon,
isle, gimli, object) adds ~8-12 MB to the release binary, not
~5 MB as the plan says. Build time on a CI box goes from ~90 s to
~3-4 minutes (rustc_codegen_cranelift's own benchmark). For a
dataplane that runs on operator hardware with strict image-size
budgets, this is non-trivial. The plan should cite a real
`cargo bloat` number if Phase 4 ever revives.

## Domain-specific checks the plan should pass

### Hot-path allocation rule

Plan respects it: no per-packet allocation. JIT pages are one-shot
mmap'd; eviction returns to free list. **PASS.**

### Lock ordering / ArcSwap semantics

Plan doesn't touch ArcSwap. Flow cache is per-worker, no shared
state added. **PASS** (but moot given verdict).

### HA sync portability

Confirmed in F3: flow cache is not synced; new primary rebuilds.
Plan correctly preserves this. **PASS** (moot).

### Numerical / counter overflow

Plan adds no new counters. **N/A.**

### Verifier / kernel-API constraints

AF_XDP UMEM ownership constraint (cross-binding requires memcpy)
is acknowledged. **PASS** (moot).

### Adversarial-frame safety

Plan proposes 10 k random tuples for differential fuzz. This is
**insufficient** — adversarial inputs (VLAN-overlap, embedded ICMP,
malformed IHL, IPv6 extension headers, fragmented packets) are
structured, not random. The 10 k random tuples will miss most of
them. If Phase 4 ever revives, fuzz needs to use a structure-aware
generator (afl++ with a frame grammar, or `proptest` with
hand-written frame strategies). **WEAKNESS.**

## Self-correction note

Codex and AGY are reviewing the same plan in parallel. I have not
yet seen their verdicts. If either of them finds something I
missed — e.g., a Phase 4 sub-problem that the plan's framing
obscures, or an instruction-cache-pressure argument for per-flow
specialisation I haven't considered — I will reconsider and
revise this verdict. As of round 1, I expect convergent PLAN-KILL.

## What the plan should record on kill

If Phase 4 is killed in round 1 / 2:

1. Update `docs/userspace-jit-design.md` status table: Phase 4
   "Not started" → "KILLED (2026-05-26) — descriptor path already
   saturates AF_XDP UMEM physics on this hardware".
2. Add a "Decision" section entry to the doc citing this plan
   and the three reviewer verdicts.
3. Comment on #1605 with the kill verdict and reviewer task IDs.
4. Add `plan-kill` label to #1605 (the `jit` and `perf` labels are
   already on it).
5. Spin out Phase 3 (`PrefixTrieV4/V6` wiring) into a new child
   issue with a smaller scope and the existing types as the
   starting point. **Do not close #1605** because the umbrella
   doc-coherency tracking is still useful as the JIT-pipeline
   archival surface. Mark #1605 as not-planned-but-keep-open
   per the `plan-kill` provisional convention.

## Bottom line

PLAN-KILL is the right verdict. The descriptor path has already
absorbed the win. Cranelift on top adds complexity, binary size,
build time, and compile-storm fragility for a sub-1% CPU savings
on the median case and negative savings under churn. The right
follow-up is a small Phase 3 PR (wire the existing tries into
policy match), not Cranelift.
