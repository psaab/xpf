# Phase 4 Cranelift JIT — Plan (DRAFT v2)

**Status:** DRAFT v2 — pending second adversarial plan review
(Codex round-2 + AGY round-2 + SMR round-3).

**Tracking issue:** #1605
**Design doc:** `docs/userspace-jit-design.md` (co-canonical).

## Headline framing (revised v2)

Plan v1 framed Phase 4 narrowly as "Cranelift JIT for per-flow
rewrite functions". Under that framing, Codex/AGY/SMR converged to
PLAN-KILL — the descriptor path (`apply_rewrite_descriptor_ipv4`)
already saturates the rewrite arm at <1% of one core remaining, and
Cranelift's 2-3 ns/packet win is below noise.

Plan v2 incorporates the user's reframing: **how does Phase 4
behave at 1M security policies under line-rate traffic?** The design
doc's "+30-50%" Phase 4 estimate was always aggregate across five
sub-targets, not just the rewrite arm. The five are:

1. Per-flow compiled fast-path (rewrite) — **Phase 1 absorbed it.**
2. Policy decision trees — design doc claims Phase 2 done, but the
   production path is still a **linear scan within the zone-pair**
   (`policy.rs:429-457`). With 1M policies this is the actual cliff.
3. NAT rule compilation — linear scan at session-miss time.
4. Screen inlining — Phase 5 done.
5. Frame rewrite templates — Phase 1 absorbed it.

The 1M-policies framing brings (2) and (3) back into scope. Plan
v2 splits Phase 4 into:

- **Phase 4a — Cranelift JIT for per-flow rewrite.** Status: PLAN-KILL
  (carried from v1 plus reviewer convergence). Documented for the
  archival surface; not implemented.
- **Phase 4b — Policy + NAT decision-tree builder, NO Cranelift.** A
  static data-structure transformation that replaces the linear
  zone-pair rule scan with an O(log M) decision tree at config-apply
  time. This is the right surface for 1M-policies scaling. **Plan v2
  recommends Phase 4b as a new sibling issue, not a sub-issue of
  #1605**, because the Cranelift JIT umbrella (#1605) is being
  closed.

If reviewers concur, the outcome at end of plan-review is:

1. #1605 closes (not-planned-but-keep-open as the JIT-pipeline
   archival surface, with `plan-kill` label).
2. Phase 4b moves to a new issue with its own plan.
3. `docs/userspace-jit-design.md` gets Phase 4 marked KILLED with
   the verdict captured.

## Issue framing

Issue #1605 raises seven open architectural questions for Phase 4.
Plan v2 answers each one, but reorganises around the Phase 4a/4b
split. v1 answers are preserved verbatim where still accurate;
revisions are flagged.

### Q1 (code-generator choice): Cranelift vs dynasm-rs vs descriptor-only

**v2 answer:** None. Phase 4a is killed (no JIT). Phase 4b is a
data-structure transformation (no JIT). Cranelift, dynasm-rs, and
the descriptor-only option are all moot for Phase 4b. If future work
needs JIT, revisit then.

### Q2 (compile granularity / threshold under churn)

**v2 answer:** Phase 4b compiles ONCE per config-apply, not
per-flow. Compile cost is amortised across all flows for that
config generation. Under DDoS / port-scan / SYN-flood, the
decision-tree data structure is read-only and shared — no
compile-storm risk. This is precisely why the JIT route was a
liability under churn and the data-structure route is not.

### Q3 (PROT_EXEC ownership + HA failover)

**v2 answer:** Phase 4b has no PROT_EXEC pages. The decision-tree
data structure lives in the regular `ConfigSnapshot` and is
serialised across HA on config sync (same as today's policy state).
Failover semantics unchanged. SMR r1 also independently verified
that the existing `pkg/cluster/` session-sync wire format does NOT
carry rewrite descriptors — flow cache is per-worker, rebuilt on
the data path. Phase 4b doesn't change that.

### Q4 (config invalidation barrier)

**v2 answer:** Phase 4b uses the existing config-generation
counter. The decision-tree blob is part of `ConfigSnapshot`; bump
the generation; old `Arc<PolicyState>` references in flight are
held via the existing ArcSwap pattern; new packets see the new
tree. No new barrier needed.

### Q5 (cross-binding rewrite)

**v2 answer:** Unchanged from v1. AF_XDP UMEM-ownership is
structural; Phase 4 does not transcend it. Phase 4a was killed
partly because cross-binding still requires memcpy regardless of
how the rewrite is dispatched. Phase 4b does not touch the
cross-binding path.

### Q6 (verifier-like safety)

**v2 answer:** Phase 4a's Cranelift-IR-bounds claim is
moot (killed). For Phase 4b, the decision-tree data structure is
plain Rust with safe indexed access; bounds are checked at
construction time when the tree is built from the
`ConfigSnapshot`. Differential test: 10k random
`(packet_5tuple, ConfigSnapshot)` cases must produce
identical action between the linear-scan path on master and the
decision-tree path. Add structure-aware adversarial coverage
(VLAN-overlap, malformed headers, IPv6 extension headers).

### Q7 (Phase 3 ordering)

**v2 answer (CORRECTED from v1):** **Phase 3 is already
shipped**, not partial. `PrefixSetV4` and `PrefixSetV6` in
`userspace-dp/src/prefix_set.rs:33-47` are enum types with three
variants (`MatchAny | Linear | Trie`). `from_prefixes` dispatches
to the `Trie` variant when prefix count exceeds
`PREFIX_SET_LINEAR_MAX`, and `PrefixSetV*::contains`
(lines 78-83 / 124-131) routes runtime calls into the trie path
automatically. Plan v1 F5 was wrong; SMR r2 documents the
self-correction. The design doc's "Phase 3 NOT STARTED" row needs
updating to "DONE".

## Honest scope/value framing

### Phase 4a (per-flow rewrite JIT)

The doc claims "+30-50% over descriptors". Wall-clock conversion on
the loss userspace cluster:

- 23 Gbps × 1500 B MTU ⇒ ~1.92 Mpps aggregate / 6 workers ⇒
  320 kpps/worker.
- Per-packet budget per worker: ~3125 ns.
- `apply_rewrite_descriptor_ipv4` (`frame/rewrite/ipv4.rs:14-123`)
  is ~30 ops + 6-8 L1 loads from `&RewriteDescriptor`.
- Cranelift would embed those 6-8 loads as immediates, saving
  ~0.3 ns × 6 = ~2-3 ns/packet.
- 2-3 ns × 1.92 Mpps × 6 workers / total-cores-budget ⇒
  **0.4-0.6% of one core**.

That's buried under memcpy (8% CPU, cross-UMEM, unavoidable per
AF_XDP UMEM ownership), NAPI (12%), syscalls (3%), and the
remainder of `poll_binding`'s 22% which a per-flow rewrite JIT
doesn't touch.

**Compile-cost amortisation:** Cranelift 100 µs / 2-3 ns =
33-50 k packets per flow minimum to break even. Production traffic:

- DNS query (2 packets): **never amortises.**
- Short HTTP/3 (≤20 packets): **never amortises.**
- Idle TLS keepalive (~50 packets): **never amortises.**
- Bulk TCP transfer (>700 packets): amortises at line-rate
  lifetimes.
- iperf3 benchmark (~250k+ packets): easily amortises.

Under DDoS / port-scan (10k-1M conn/sec), every new flow burns
100 µs of compile time. JIT compiler saturates a core before doing
useful work. **Phase 4a is a DoS vulnerability waiting to happen.**

> Phase 4a verdict: **PLAN-KILL** (carried from v1, ratified by
> Codex/AGY/SMR convergence — Codex retry pending due to sandbox
> infra blocker on r1).

### Phase 4b (decision-tree builder for policy + NAT)

#### What the cliff looks like at 1M policies

Master code path on session miss
(`poll_descriptor/mod.rs:1375` & `:2393` both call
`evaluate_policy_result_with_len`):

```rust
// policy.rs:429-442
if let Some(indices) = state.zone_pair_index.get(&key) {
    for &idx in indices {
        if let Some(result) = try_match_rule(
            &state.rules[idx], src_ip, dst_ip, protocol,
            src_port, dst_port, packet_len,
        ) {
            return result;
        }
    }
}
```

`try_match_rule` does: inactive check + `compiled_apps.matches`
(HashMap O(1)) + 2× `PrefixSetV*::contains` (trie O(log N) when
N>linear-threshold) + hit-counter increment. Cost per rule ≈
~10-20 ns at L1.

At 1k rules per zone-pair × 10-20 ns/rule = **10-20 µs per session
miss** — well above the ~10 µs budget for new-session forwarding
latency.

At 1M total rules (typically split across hundreds of zone-pairs):
worst-case zone-pair holds the bulk; say ~10k rules in the worst
hot zone-pair. **100-200 µs per session miss in that zone-pair.**
At 100k conn/sec session-creation rate that's 10-20 seconds of CPU
per wall-clock second — dataplane melts on new-flow burst.

**At line rate of 1.92 Mpps for established traffic, no policy
eval happens** (flow-cache-hit short-circuits all policy +
NAT + FIB at `flow_cache_hit.rs:93`). So the cliff is at
session-creation rate, not at established line rate. Existing flows
DO continue at line rate even if new sessions stall.

#### Proposed Phase 4b structure

At config-apply, for each zone-pair index, build a static decision
tree exploiting rule structure:

1. **Layer 1: protocol dispatch.** Group rules by protocol byte
   (TCP=6, UDP=17, ICMP=1, etc.) → 1-byte O(1) dispatch.
2. **Layer 2: port-range bucketing.** Within a protocol, build a
   sorted interval tree over (src_port_range, dst_port_range).
   Binary search → O(log M_protocol) hits.
3. **Layer 3: address-set short-circuit.** Within a port-bucket,
   order rules by address-set selectivity (smallest set first).
   Rules with `MatchAny` address sets go last. Existing trie path
   from Phase 3 already accelerates the per-rule address match.
4. **Layer 4: hit-counter increment.** Unchanged.

Per-eval cost target: O(log M_per_zone_pair) instead of O(M).

#### What this DOES NOT include

- No Cranelift, no PROT_EXEC, no per-flow code-gen.
- No HA wire protocol change (decision tree is local to the
  daemon; rebuilt from `ConfigSnapshot` on each side).
- No flow-cache change (cache-hit short-circuits policy already).

#### Expected benefit

- At 10k rules per zone-pair: 100-200 µs → 1-2 µs per session miss
  (~100×). New-flow latency under control.
- At 1M total rules spread across zone-pairs: same shape, 100×
  speedup applied where the linear-scan cliff is.
- Established line rate (23 Gbps): unchanged — flow-cache short
  circuits.
- DDoS resilience: under 100k-1M conn/sec session-creation rate,
  policy eval cost drops from melt-the-dataplane to ~10% of one
  core. Phase 4b is a real anti-DDoS hardening.

#### Compile cost

Building the tree at config-apply for 1M rules: estimate ~50-200 ms
of CPU once, then ArcSwap-published. Config-apply is already
infrequent (operator pushes config); 50-200 ms is acceptable.

> Phase 4b verdict guidance: **PLAN-PROMOTE-TO-NEW-ISSUE.** Not
> implemented in plan v2's PR scope; a new fresh issue + plan
> covers it.

## What's already shipped

- `apply_rewrite_descriptor()` orchestrator, single caller,
  `#[inline]` — `frame/rewrite/mod.rs:44`.
- `apply_rewrite_descriptor_ipv4()` / `_ipv6()` with
  `#[inline(always)]` — `frame/rewrite/`.
- `RewriteDescriptor` struct with precomputed `ip_csum_delta`,
  `l4_csum_delta` — `flow_cache.rs:50-74`.
- 4-way set-associative 4096-entry flow cache —
  `flow_cache.rs:6-25`.
- `FlowCacheStamp` HA-aware invalidation —
  `flow_cache.rs:76-112`.
- **Phase 3 address-book tries (corrected from v1):**
  `PrefixSetV4`/`PrefixSetV6` enum with `Trie` variant dispatching
  via `from_prefixes` — `prefix_set.rs:33-83 / 105-131`.
- **Phase 2 policy zone-pair indexing** — `policy.rs:429-432`
  (`state.zone_pair_index.get(&key)`).

What's NOT shipped (the 1M-policies cliff):

- **Per-zone-pair decision-tree compile** — the linear scan at
  `policy.rs:430-442` still runs O(M) within a zone pair. This is
  Phase 4b's target.
- **NAT-rule decision-tree compile** — separate but identical
  shape; defer to Phase 4b extension or its own sub-issue.

## Concrete design (Phase 4a — killed; Phase 4b — sketched)

### Phase 4a sketch (for archival only)

Per-flow Cranelift function emitted at session-miss-→insert time,
storing a function pointer in `FlowCacheEntry`. Hot path branches
on `entry.jit_fn.is_some()` and calls the JIT instead of
`apply_rewrite_descriptor`. PROT_EXEC pages mmap'd per worker.

**Status:** documented and KILLED. Not implemented. Doc-coherency
update reflects the kill verdict.

### Phase 4b sketch (deferred to new issue)

Add a new type `PolicyDecisionTree` in `userspace-dp/src/policy.rs`:

```rust
pub(crate) struct PolicyDecisionTree {
    by_zone_pair: FxHashMap<u32, ZonePairTree>,
    global_tree: ZonePairTree,
    default_action: PolicyAction,
}

struct ZonePairTree {
    by_protocol: [Option<ProtocolTree>; 256],
    // 256-byte protocol dispatch; per-protocol port-range tree.
}

struct ProtocolTree {
    // Sorted intervals of (src_range, dst_range, rule_index)
    intervals: Vec<PortRangeBucket>,
}

struct PortRangeBucket {
    src_range: (u16, u16),
    dst_range: (u16, u16),
    // Rules ordered by address-set selectivity within this bucket
    rules: Vec<u32>,
}
```

Replace `evaluate_policy_result_with_len` body with a tree walk.
The existing `try_match_rule` per-rule check is reused for the
final address-set+app match at the leaf. Construction lives next
to `PolicyState::from_snapshot` in `policy.rs`.

**Public API preservation:** existing `evaluate_policy`,
`evaluate_policy_with_len`, `evaluate_policy_result_with_len`
signatures unchanged. Only the internal walk changes.

**Implementation phasing for 4b (if promoted to its own issue):**

- Step 1: tree builder + correctness differential test against
  master.
- Step 2: tree walk replacing linear scan; bench with 100k +
  1M-rule configs.
- Step 3: NAT decision tree (same shape, separate state).

## Hidden invariants the change must preserve

(Carries from v1; some are now moot under Phase 4a's kill.)

1. **Hot-path allocation rule:** zero per-packet allocation. Phase
   4b's tree is read-only at runtime; satisfied.
2. **Side-effect ordering:** unchanged (rewrite path not touched
   by 4b).
3. **HA sync portability:** policy state already crosses HA via
   `ConfigSnapshot`; 4b's tree is local-rebuild. Satisfied.
4. **Stale-handle hazard:** ArcSwap on `PolicyState` preserves
   in-flight refs through config bumps. Already the project's
   pattern.
5. **Lifetime / borrow-checker shape:** Phase 4b is plain safe
   Rust; no unsafe. Phase 4a was MED-HIGH on this axis (killed).
6. **Verifier safety:** Phase 4b uses safe-Rust indexed access at
   the tree leaves; differential testing covers parity with the
   linear-scan reference.

## Risk assessment

| Class | 4a (KILLED) | 4b (PROMOTED to new issue) |
|-------|-------------|---------------------------|
| Behavioural regression | HIGH | LOW (differential test + linear-scan reference) |
| Lifetime / borrow-checker | MED-HIGH | LOW (safe Rust, no PROT_EXEC) |
| Performance regression | MED (compile storm under churn) | LOW (config-apply only) |
| Architectural mismatch | HIGH (#946 P2 / #961 pattern) | LOW (well-scoped data-structure change) |

## Test plan

Plan v2 ships NO production code. The PR for this plan (when
merged) updates `docs/userspace-jit-design.md` and closes #1605
with `plan-kill` + `not-planned-but-keep-open`. A separate Phase
4b PR (under a new issue) will carry the implementation tests.

Plan-merge gates (for THIS plan PR):

- cargo build clean (already verified locally on c469829ff).
- cargo test --release: existing 952+ tests pass unchanged.
- Doc update lints clean.
- Three-reviewer convergence: Codex r2 + AGY r2 + SMR r3 all
  PLAN-READY or NEEDS-MINOR-fixed.

For Phase 4b (separate plan + issue):

- 1M synthetic rule generator + benchmark.
- Differential test vs master linear-scan path on 10k random
  configs × 100 random packets each.
- Smoke matrix on loss userspace cluster (v4+v6 × push+reverse ×
  CoS-off+CoS-on; per-class 5201-5206).
- HA failover regression (`make test-failover`).
- DDoS stress: synthetic 100k-1M conn/sec, dataplane must stay
  responsive.

## Out of scope

- Phase 4a Cranelift implementation (killed; not implemented).
- Phase 4b implementation in THIS plan-PR (moved to its own
  issue + plan).
- NAT rule decision-tree (folded into Phase 4b or its sibling).
- Filter / firewall-filter JIT (out per #1605 body).
- ARM64 support (deployed target is x86_64).
- Cross-NIC shared UMEM (separate research).

## Open questions for adversarial review (v2)

1. **Is the Phase 4a→4b split right?** Phase 4a (rewrite-arm JIT)
   is killed by the descriptor-already-saturates argument. Phase
   4b (policy decision tree) is promoted to a fresh issue. Is
   there a third sub-target the framing misses (NAT eval,
   filter eval, mirror sampling, COS classification)? If yes, the
   plan should explicitly defer or fold.

2. **Phase 4b implementation choice — interval tree vs hash-based
   bucketing?** The plan sketches interval trees on port ranges
   ordered by address-set selectivity. Is binary search over
   sorted port-range intervals faster than per-byte radix or
   Bloom-filter prefiltering? At 1M rules the answer depends on
   port-range distribution in production configs. Reviewer should
   propose a synthetic config that stresses each shape and
   indicate which structure wins.

3. **Phase 4b as a sub-issue of #1605 vs new sibling issue?** The
   plan proposes new sibling (#1605 closes). Alternative: keep
   #1605 open as the umbrella, file Phase 4b as a child issue,
   make 4a a closed sub-issue. Either preserves the doc-coherency
   contract. Pick the cleaner one.

4. **Should we revisit Phase 4a after Phase 4b ships?** The
   plan's answer is no (the 2-3 ns/packet ceiling is structural).
   But once 4b cuts session-miss latency from 100 µs to 1 µs,
   maybe the relative weight of the rewrite arm grows enough to
   matter? The math says no (rewrite arm runs at line rate; 4b
   helps session-miss rate). Reviewer to verify with quote-line
   evidence.

5. **Verifier-safety for adversarial-frame parity in 4b.** Plan
   v2 reuses `try_match_rule` at tree leaves. Are there malformed
   packets where the existing `try_match_rule` returns one
   verdict and a tree-walk path takes a different leaf and
   returns a different verdict? Adversarial test cases:
   - VLAN-tagged 802.1Q frames where protocol byte parsing
     diverges between paths.
   - IPv6 extension headers where L4 protocol read is from a
     different offset.
   - Fragmented IPv4 where ports are not present in the wire
     packet.
   The plan's claim "reuses try_match_rule, so parity is
   trivial" must be defended against these.

6. **Phase 3 verification.** SMR r2 corrected my r1 wrong claim
   that `PrefixTrieV4/V6` is dead code. AGY independently noted
   the same correction. Reviewer for v2 should verify the
   `PrefixSet*::from_prefixes` linear-vs-trie threshold
   (`prefix_set.rs:65`) is sane for 1M-policy deployments —
   e.g., is `PREFIX_SET_LINEAR_MAX` set high enough that large
   address-books always pick `Trie`?

7. **Should plan v2's PR (this plan + doc update + #1605 close)
   actually land, or is closing #1605 premature?** If Phase 4b
   has substantive risk of needing JIT later, keep #1605 open as
   the umbrella. If 4b is purely a data-structure transform that
   never needs JIT, close #1605 with `plan-kill`. Reviewer to
   decide.
