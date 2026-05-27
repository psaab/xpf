# Phase 4 JIT — PLAN-KILLED (convergent)

**Status:** **PLAN-KILLED 2026-05-27** on convergent verdicts:
AGY r3 (`adversarial-review-mpnnu0cr-h4vt3w`) and Claude SMR r4
(`docs/pr/1605-jit-phase-4/claude-smr-plan-r4.md`). Codex r1/r2/r3
all returned deterministic sandbox infra failures; per
`feedback_codex_infra_must_retry` the methodology proceeded on
3-of-4 (Claude SMR + AGY + Copilot, with Codex infra-blocked).
Copilot would review the closing PR if one is filed.

Plan v4 (commit `031fb7ba5`) is the kill artifact. The architectural
direction documented below is preserved for posterity; the
specific scope (Cranelift JIT and the 4b multi-stage DAG as
designed) is killed for the reasons summarised under "Kill
findings" below.

**Phase 4a (Cranelift per-flow rewrite JIT):** PLAN-KILL across
v1/v2/v3/v4. Cold-path packets ARE the flow-cache miss; JIT
doesn't help.

**Phase 4b (1M-policies multi-stage DAG):** PLAN-KILL on plan v4
because two prerequisites that the plan assumed are not actually
in place on master:

1. **Wire-protocol pre-expansion:** the Go control plane sends
   per-rule `source_addresses: Vec<String>`
   (`userspace-dp/src/protocol/security.rs:63-66`); there is no
   address-book reference ID. Plan v4's CoW Arc-shared
   LPM-per-address-book mitigation is structurally impossible
   without a wire-protocol redesign. With pre-expansion, 100k
   rules × 16 MB DIR-24-8 = ~1.6 TB RAM at production scale.
2. **Hardware ceiling at 49 Mpps unverified:** the 270 ns
   per-packet budget was derived from 25 Gbps + 64 B = 49 Mpps,
   but the deployed mlx5 VF has only demonstrated ~5.91
   Mpps/worker on the WARM path; the cold path has never been
   measured at >5 Mpps. The 49 Mpps target is hypothetical.

**Phase 4c (cold-path hardening):** can ship independently against
the existing linear-scan path; file as a separate child issue.

For the full rationale, kill findings, and recommended follow-up
(close #1605 narrow scope with `plan-kill`, file prerequisite
issues), see "Recommended next steps" at the bottom.

## Historical framing (preserved for archival)

Original v1 framing (narrow Phase 4 = rewrite JIT) was correctly
PLAN-KILLED by Codex/AGY/SMR convergence on round 1. The
coordinator then added 1M-policies at line rate as a load-bearing
constraint (issue #1605 comment 2026-05-27), extending the original
7 questions to Q1-Q13. v2-v4 evolved the plan under that constraint.
v4 trimmed scope to 4b.0 (microbench) + 4b.3 (LPM); AGY r3 then
KILLED v4 by identifying that 4b.3 alone is a regression (more
memory, no perf gain — the linear scan over `indices` at
`policy.rs:430-442` remains the dominant cost) AND that the
wire-protocol pre-expansion makes the memory budget structurally
unachievable without prerequisite work.

The architecture for what a viable Phase 4b WOULD look like
(multi-stage DAG: protocol byte → port-range tree → LPM →
bucket scan, with wire-protocol restructure for address-book
sharing + cold-path rate-limiting + verdict micro-cache) is
preserved below as reference for a future re-plan once the
prerequisites land.

**Tracking issue:** #1605 (now extended to Q1-Q13).
**Design doc:** `docs/userspace-jit-design.md` (co-canonical).
**Hardware reference:** loss userspace cluster, AF_XDP zero-copy,
mlx5 VF, native XDP.

## Headline framing (v4)

The coordinator added a load-bearing scale constraint on
2026-05-27 (issue #1605 comment): **line-rate packet evaluation
against 1,000,000 active security policies on the AF_XDP fast
path**, including the **cold path** that DDoS / port-scan /
SYN-flood traffic exercises. Per-packet budget at 25 Gbps + 64 B
frames is ~270 ns. Linear scan is dead by three orders of
magnitude. Even O(log N) binary search costs 30-70% of the budget
and leaves nothing for screen/NAT/rewrite.

Target shape: **O(1) average / O(log K_per_bucket) worst-case
with K_per_bucket ≤ ~32.**

Plan v4 separates three sub-questions and **commits to a trimmed
first cut** (SMR r3 F6):

- **Phase 4a — Cranelift per-flow rewrite JIT.** Killed in v1/v2/v3;
  remains killed in v4. It doesn't solve the cold-path 1M-policies
  problem because cold-path packets never reach the flow cache
  (they ARE the cache miss).
- **Phase 4b — Policy decision DAG with multi-stage decomposition
  for 1M-policies line-rate scale.** The full architecture is
  documented here. **v4 commits to shipping only 4b.0 + 4b.3 as
  the first cut.** All other sub-PRs (4b.1, 4b.2, 4b.4, 4b.5,
  4b.6) are deferred until 4b.0's measurements justify them.
- **Phase 4c — Adversarial cold-path hardening.** Documented for
  future reference; all sub-PRs deferred to post-4b.3 re-plan.

**Why first-cut = 4b.0 + 4b.3:**
- 4b.0 (synthetic 1M-policy gen + microbench) ships the
  measurement harness that every later decision depends on. It
  resolves SMR r3 F3 (does the cluster sustain 49 Mpps at 64 B?
  if not, the 270 ns budget relaxes and the DAG complexity drops).
- 4b.3 (DIR-24-8 or sparse-trie LPM replacement for
  `PrefixTrieV4::contains`) is the single highest-impact change
  identified by r3 F2 — the existing uncompressed binary trie
  walks up to 64 cache-line hops per packet for src+dst, which
  dominates any reasonable budget. Even if 4b.1/4b.2/4b.4 are
  never built, replacing the LPM moves the needle.

If reviewers conclude even the trimmed scope is too large or that
1M policies on this hardware is structurally unachievable,
PLAN-KILL of the whole umbrella remains acceptable.

> *If reviewers conclude the perf gain is too small to justify
> the churn, **PLAN-KILL is an acceptable verdict.***

## Issue framing — Q1-Q13

Q1 (code-gen choice): see §4a + §4b. v3 answer: Cranelift not
required for Phase 4b; descriptor path stays for Phase 4a-killed.
Q2 (compile granularity / threshold): see §4b. Q3 (PROT_EXEC + HA):
moot under 4a kill. Q4 (config invalidation): unchanged ArcSwap
pattern. Q5 (cross-binding): unchanged AF_XDP UMEM ownership.
Q6 (verifier-safety): plain-Rust DAG in §4b. Q7 (Phase 3
ordering): RESOLVED — Phase 3 is a HARD PREREQUISITE, not a
deferrable. Existing `PrefixSet*::Trie` uncompressed binary trie
is structurally insufficient for 1M-policy line-rate (next §).

Q8-Q13 (added by coordinator 2026-05-27):

- **Q8: Per-zone-pair decision shape at K=10k-100k.** See §4b
  multi-stage DAG.
- **Q9: Config-apply latency at 1M rules.** See §4b construction
  budget.
- **Q10: Memory footprint** at 6 in-flight ConfigSnapshots ×
  1M policies. See §4b interning.
- **Q11: Address-book scale**. See §4b LPM-tree upgrade.
- **Q12: HA session-sync + 1M policies failover timing.** See
  §4b + §HA.
- **Q13: Worst-case adversarial workload — cold path at line
  rate.** See §4c.

## Honest scope/value framing

### What 1M policies × 270 ns/packet actually permits

At 25 Gbps + 64 B, line rate is ~3.7 Mpps per worker (assuming 6
workers and 6 NIC RX queues; per-worker budget 270 ns ÷ ~3 = ~90
ns wall clock when overhead is amortised against the 22%
`poll_binding` figure from the architecture doc). Within 270 ns of
end-to-end per-packet budget, the policy decision step gets maybe
80-120 ns. That is **8-12 L1 loads worth of compute**, or about
**6 dependent cache-line hops**.

This is a hard physical ceiling that no software architecture can
escape. So the design rules are:

1. **Zero dependent loads per packet beyond ~6.** Multi-level
   pointer chases (the existing
   `PrefixTrieV4::contains` Box<TrieNode> walks up to 32 hops)
   are structurally dead. Need flat-array radix or DIR-24-8-style
   single-load lookups.
2. **Branch prediction must dominate.** No data-dependent
   branches the predictor can't learn. Decision DAGs encoded as
   `switch (tag) { ... }` over a 1-byte tag at L1 are OK.
3. **Hot working set ≤ L2.** At 1MB L2 per core (typical
   Sapphire/Granite Rapids), the policy DAG's hot subset must
   fit. 1M policies × ~16 B per entry = 16 MB — too big for L2.
   The hot subset (top of zone-pair DAG + per-zone-pair fast
   buckets) must be ≤ ~1 MB.

These three rules cut the design space severely.

### Phase 4a (per-flow rewrite JIT) — KILLED (carried)

The rewrite arm runs only on flow-cache HIT. Under 1M-policies
cold-path stress, **no rewrites happen** — packets are dropped or
denied by policy before reaching the rewrite path. So Phase 4a
doesn't address the coordinator's constraint at all. Carry the
v1/v2 PLAN-KILL verdict.

> Phase 4a verdict: **PLAN-KILL.**

### Phase 4b (1M-policy decision DAG, NO Cranelift)

#### Why Cranelift is still wrong here

Cranelift-emitted match cascades over 1M policies would generate
~16 MB of machine code per zone-pair. L1-i is 32-64 KB. Branch
predictor capacity is ~4k BTB entries. The JIT'd code falls out
of all CPU caches on every cold-path packet. **Cranelift
amplifies the cache problem, doesn't solve it.**

#### Architecture: multi-stage decomposition

Within each zone-pair, the policy set is broken into stages, each
of which is O(1) at runtime:

1. **Stage 0 — zone-pair lookup.** Already shipped in Phase 2:
   `zone_pair_index: FxHashMap<u32, Vec<usize>>` at
   `policy.rs:429`. O(1) hash, ~3-5 ns. Returns "rule-set handle"
   for this zone-pair.

2. **Stage 1 — protocol filter.** New: per-zone-pair
   256-byte array of `Option<NonZeroU32>` indexing into a
   protocol-specific sub-DAG. O(1) array load. ~2 ns.

3. **Stage 2 — port-range bucketing.** New: per-protocol
   sub-DAG, indexed by (src_port_range_id, dst_port_range_id).
   Ports are pre-compiled at config-apply into a flat sorted
   array of disjoint intervals; runtime does a single-load
   bisect of ≤ log2(N_intervals) hops. Typical
   N_intervals ≤ 256 ⇒ 8 hops at ~3 ns each = ~24 ns. Returns
   bucket-id. **K_per_bucket invariant: ≤ 32 rules**, enforced at
   build time by further splitting overflow buckets on the next
   selectivity axis.

4. **Stage 3 — address-LPM lookup.** New: DIR-24-8-style flat
   LPM for IPv4 (TBL24 = 16 MB max but mostly empty; sparse
   representation = ~2-4 MB). For IPv6, two-stage hash of
   /64 prefix + tail trie. **One single load to TBL24** (24-bit
   index), then conditional ≤ 1 extra load for /25-/32 (TBL8
   subtree). ~5-8 ns per address. Two addresses per packet
   (src + dst) = ~15 ns.

5. **Stage 4 — bucket linear scan.** Final K ≤ 32 rules in
   the bucket get a linear scan with the existing
   `try_match_rule`. At 5-10 ns per rule × ≤ 32 = ≤ 320 ns
   worst case. **Average bucket fill is much smaller** (most
   buckets have 1-3 rules) → typical 5-30 ns.

Total worst-case per-packet policy cost:
~5 + 2 + 24 + 15 + 320 = **~366 ns worst case**.
Average case:
~5 + 2 + 8 + 15 + 15 = **~45 ns average**.

The worst case exceeds the 80-120 ns budget by ~3×. Three
mitigations:

- **Bucket K-cap = 16, not 32** (sharper split at build time).
- **App-match early termination**: most rules carry application
  matchers (proto+port hash); the bucket scan can short-circuit
  on app-match miss before address-set check.
- **Acceptance**: at K_per_bucket=16 worst case = 5+2+24+15+160
  = 206 ns. Still over budget but within ~2×. We can either:
  (a) Accept ~12 Gbps line rate on cold path at K=16
  (instead of 25 Gbps).
  (b) Build deeper splits (Stage 2.5: per-app selectivity).
  Plan v3 picks (a) and documents the line-rate degradation as
  the cold-path cost. Warm path (flow cache hit) remains at 23+
  Gbps.

#### Phase 4b sub-PRs

The implementation cannot ship as one PR. Sequence:

- **4b.0**: synthetic 1M-policy ConfigSnapshot generator +
  microbench harness. ~500 LOC. **New child issue.**
- **4b.1**: protocol-stage array (Stage 1) — small, isolated.
  ~300 LOC.
- **4b.2**: port-range bucketing (Stage 2) + build-time bucket
  splitter. ~1.5k LOC.
- **4b.3**: DIR-24-8 LPM (Stage 3) replacing
  `PrefixTrieV4::contains`. Big change; ~3k LOC. **HARD
  PREREQUISITE for cold-path scale.**
- **4b.4**: bucket scan + try_match_rule integration. ~500
  LOC + integration testing.
- **4b.5**: NAT decision-DAG mirror of 4b.1-4b.4. Similar
  shape, separate state.
- **4b.6**: COS / filter / mirror decision-DAG (lower
  priority — these are at the same code surface but smaller
  rule counts in practice).

Each sub-PR ships with: cargo build clean, cargo test --release,
microbench at K=10k/100k/1M policies, smoke matrix on the loss
userspace cluster, HA failover regression.

> Phase 4b verdict guidance: **PLAN-PROMOTE-TO-NEW-ISSUE-SERIES.**
> 4b is too large to ship inside this plan's PR. The plan PR
> updates the design doc, closes the original #1605 scope as
> the umbrella tracking issue, and spawns 4b.0-4b.6 child
> issues.

### Phase 4c (cold-path hardening — adversarial workload)

The user's Q13 frames the cold path as the failure mode. Even
with Phase 4b's ~45 ns average / ~206 ns worst-case, a sustained
SYN-flood from random source IPs takes the SAME path as a real
new flow — both miss the flow cache and hit the DAG.

Mitigations:

- **Per-source-IP rate limit** before policy eval. SYN-floods are
  characterised by sourcing from few IPs with high rate; a small
  hash + counter pre-filter at ~5 ns/packet drops them BEFORE
  the DAG. This is closer to a screen function than a new JIT
  surface — extend the existing screen pipeline. (Phase 5
  was "DONE inherent" because per-zone screen short-circuits on
  empty config; Phase 5b is "active rate-limit on cold-path
  source IPs at line rate" — new sub-issue.)
- **Cold-path verdict micro-cache**: a 64k-entry LRU keyed on
  (src_zone, dst_zone, proto, dport, src/24, dst/24) that
  records "denied|permitted|further-eval" outcomes. **Reduces
  cold-path cost for the small-botnet class of attacks** (SMR
  r3 F5 correction — v3's "95% hit on SYN-floods" was hand-wavy;
  large-botnet randomized src-IP attacks sample 2^24 unique /24s
  and would see ~0.4% hit at 64k LRU, not 95%). Useful against
  realistic ~10k-source botnets, not against full-spoofed
  uniform attacks.
- **Sliding-window per-zone-pair limits**: if 4b DAG eval rate
  exceeds a configured threshold, fall back to deny-by-default
  with logging until rate drops. This is operator-visible
  policy, not silent degradation.

Phase 4c is also a child issue series, sequenced AFTER 4b.0-4b.3
land.

> Phase 4c verdict guidance: **PLAN-PROMOTE-TO-NEW-ISSUE-SERIES,
> after 4b core lands.**

## Honest delivery & scope

Plan v3 is an **architectural plan**, not a single
implementation PR. The deliverables in the **plan PR** are:

1. `docs/pr/1605-jit-phase-4/plan.md` (this file).
2. `docs/pr/1605-jit-phase-4/claude-smr-plan-r*.md` (SMR docs).
3. `docs/pr/1605-jit-phase-4/reviewer-ids.md` (task IDs).
4. `docs/userspace-jit-design.md` updated with:
   - "Scale target" section: 1M policies first-class.
   - Phase 4 row marked KILLED for Cranelift / split into 4b/4c.
   - Phase 3 row updated to DONE (with the K_per_bucket caveat
     that further LPM work in 4b.3 supersedes the existing
     uncompressed binary trie).
5. Issue #1605 close with `plan-kill` on the original narrow
   Phase 4 scope; OR keep open as umbrella with `plan-kill` on
   4a and child issues for 4b.0-4b.6 + 4c.x.

**No production code in this plan PR.** Each sub-PR is its own
plan-review cycle.

## What's already shipped

- Phase 1: descriptor + flow cache fast path. **Cold path
  bypasses it.**
- Phase 2: zone-pair hash + per-protocol app matcher. **Within
  zone-pair, still linear scan.**
- Phase 3: `PrefixSetV4::Trie` uncompressed binary trie. **Too
  slow for 1M-policy line rate.** 4b.3 replaces with
  DIR-24-8.
- Phase 5: per-zone screen short-circuit. **No active
  cold-path rate-limit yet.**

## Hidden invariants the change must preserve

(All carry from v1/v2 plus the v3 additions.)

1. **Hot-path allocation rule.** Zero per-packet alloc.
2. **Side-effect ordering.** rewrite path untouched.
3. **HA sync portability.** Policy DAG is per-snapshot, crosses
   HA via existing config-sync wire. New DAG construction must
   complete within the existing config-apply window (~250 ms
   today; budget grows but plan caps at ≤ 5 s for 1M rules).
   **During reconstruction, the old `PolicyState` continues
   serving traffic via the existing ArcSwap pattern** (SMR r3
   F9 clarification) — config-apply does not introduce a
   service interruption, only an extended commit-confirm
   window for the operator UX. **Open verification (4b.0
   deliverable):** confirm `pkg/cluster/config_sync*` ships the
   pre-built DAG over the wire so the secondary doesn't rebuild
   on activation — failover must remain ~60 ms.
4. **Stale-handle hazard.** ArcSwap on PolicyState; in-flight
   refs survive config bumps.
5. **Memory footprint at 6 in-flight snapshots × 1M policies.**
   (Revised v4 per SMR r3 F4 — v3's "~250 MB after interning"
   number was optimistic.) Realistic shape:
   - Per-rule struct (action, policy_id, hit_counter,
     address-book + port-range Arcs): ~32 B × 1M = 32 MB per
     snapshot. 6 snapshots = 192 MB.
   - Address-book LPM tables (4b.3 DIR-24-8): 16 MB worst-case
     per IPv4 table for 1M CIDRs; sparse-trie alternative is
     smaller. At 10k address-books in worst-case deployment ×
     1 MB average (most books are small) = 10 GB per snapshot.
     **Even with Arc-shared per-snapshot, this is a hard
     budget breaker.**
   - Mitigation: CoW per address-book — when config-apply changes
     book X, only book X's new LPM lives in the new snapshot;
     unchanged books are shared via `Arc<PrefixLpmV4>` across
     all snapshots. 6 snapshots × delta-only allocations ≈
     ~10-12 GB at steady-state (live address-books) + ~100 MB
     of in-flight per-rule deltas.
   - **Honest conclusion:** at 10k address-books × 1M CIDRs each
     (the absolute worst-case spread of 1M policies × 100 CIDRs
     per book), memory dominates at ~10 GB. This is acceptable
     on operator-class hardware (typical 64-256 GB RAM) but
     NOT on smaller deployments.
   - 4b.0's memory-footprint measurement is the deliverable that
     gates the LPM representation choice — if the realistic
     production policy mix uses fewer than 1k unique address-books
     with mean 100 CIDRs each, the footprint drops to ~150 MB
     and the design space relaxes.
6. **Worst-case adversarial.** 4c rate-limits + micro-cache
   keep the cold path within ~5× of average even under
   sustained adversarial src-IP randomisation.

## Risk assessment (v3)

| Class | 4a (KILLED) | 4b core (4b.0-4b.4) | 4c (cold-path hardening) |
|-------|-------------|---------------------|---------------------------|
| Behavioural | HIGH | MED — DAG must match linear-scan reference byte-for-byte across adversarial inputs | MED — silent rate-limit fallback risks production false-positives |
| Lifetime / borrow | MED-HIGH (PROT_EXEC) | LOW (safe Rust DAG) | LOW |
| Performance regression | MED (compile storm) | LOW under steady-state; MED under burst config-apply | LOW |
| Architectural mismatch | HIGH (#946 P2 / #961 pattern) | LOW — 1M-policy scaling is a real production need | LOW |
| Memory footprint | N/A | MED — interning must work or we blow 1.2 GB | LOW |
| Cold-path adversarial | DOES NOT ADDRESS | LOW (with 4b.3 LPM) | MITIGATES (4c is the mitigation) |

## Test plan

### Plan-merge gates (THIS plan-PR)

- Three-reviewer convergence on v3: Codex r1 (retry-after-infra) +
  AGY r1 + Claude SMR r3.
- Doc-coherency updates pass review.
- No production code lands.

### Sub-PR gates (each 4b.x or 4c.x sub-PR)

- cargo build clean.
- cargo test --release: existing 952+ tests pass, new tests
  added.
- 5/5 named-test flake check on new modules.
- Microbench at K=10k, 100k, 1M policies (`scripts/policy-eval-bench.sh`,
  new).
- Synthetic 1M-policy ConfigSnapshot generator
  (`test/incus/synthetic-policy-gen.sh`, new in 4b.0).
- Smoke matrix on loss userspace cluster: v4 + v6 × push +
  reverse × CoS-off + CoS-on; per-class CoS 5201-5206 = 30
  measurements.
- **Cold-path adversarial smoke**: hping3 SYN-flood from
  randomised src IPs at >1 Mpps, dataplane must remain
  responsive (existing flows hold throughput; new flows queue
  with bounded latency).
- HA failover regression: `make test-failover` with a 1M-policy
  config loaded; failover timing remains ≤ 100 ms (relaxed from
  60 ms to allow for new DAG warm-up).
- Config-apply latency: synthetic 1M-policy push completes in
  ≤ 5 s.
- Memory footprint: 6 in-flight ConfigSnapshots stay under
  500 MB RSS.

## Out of scope (v3)

- Phase 4a Cranelift implementation (killed).
- Filter / firewall-filter JIT (still out per #1605 body).
- ARM64 support (x86_64 only on this hardware).
- Cross-NIC shared UMEM.
- Phase 6+ extensions (NAT64 specialisation, IPsec SA fast
  path, BGP next-hop trie) — separate research.

## Open questions for adversarial review (v3)

1. **Is the 270 ns per-packet budget at 25 Gbps + 64 B real on
   the deployed mlx5 VF + 6-worker config?** The architecture
   doc shows 23 Gbps with 1500 B frames (1.92 Mpps total). 64 B
   at 25 Gbps is 49 Mpps — 25× higher pps. Has any prior
   measurement on this hardware demonstrated headroom for
   49 Mpps with any policy load, or is the 25 Gbps line-rate
   target itself overly aggressive for the small-frame case?
   Reviewer to validate against `docs/userspace-perf-compare.md`.

2. **Is DIR-24-8 actually faster than the existing uncompressed
   binary trie in practice on this CPU?** DIR-24-8's selling
   point is 1-2 memory accesses vs ≤ 32 for a binary trie. But
   DIR-24-8 sparse representations either bloat (16 MB TBL24)
   or fragment (sparse hash → 2 accesses). At 1M-rule
   address-books, what's the actual memory footprint and L1
   load count? Plan claims 5-8 ns/lookup; verify against actual
   `perf stat` numbers from a related project (Cilium's LPM,
   VPP's mtrie, BPF LPM).

3. **Bucket K=16 vs K=32.** Plan picks K=16 to fit budget. But
   bucket-splitting at K=16 may overgrow the build-time DAG
   construction past 5 s. What's the realistic trade-off?
   Reviewer to quantify build-time at K=8/16/32 on the
   synthetic 1M-rule config.

4. **Cold-path verdict micro-cache (4c.2) collisions.** Keyed on
   (src_zone, dst_zone, proto, dport, src/24, dst/24). At 64k
   entries with realistic adversarial src-IP distribution
   (randomised /24 with 256k unique /24s), hit rate is ~25%.
   Plan claims 95% on SYN-floods because attackers sample a
   small key space. Is that an empirical claim or wishful
   thinking? Reviewer to require a hping3-driven measurement
   before 4c lands.

5. **HA failover at 1M policies.** 60 ms today. With 1M-rule
   DAG construction at ~5 s at config apply, the per-failover
   cost depends on whether the secondary already has the DAG
   pre-built (yes — via session-sync) or rebuilds on takeover
   (no — too slow). Verify against `pkg/cluster/session_sync*`
   and `pkg/cluster/config_sync*` that pre-built DAGs ship
   over the wire and the secondary doesn't rebuild on
   activation.

6. **Memory footprint claim (≤ 500 MB at 6 in-flight × 1M
   policies).** Plan claims interning of address-book and
   port-range refs cuts 1.2 GB → ~250 MB. Verify the
   interning shape is structurally possible: address-book
   refs across rules ARE typically shared (same address-book
   referenced by N rules), but port-range refs may not be
   (each rule may carry a unique port-range tuple). Reviewer
   to compute the realistic dedup factor.

7. **Sub-PR sequencing for 4b.0-4b.6 + 4c.x.** Plan v3 sketches
   the order but doesn't pin priorities. Is the right
   sequence:
   - 4b.0 (gen + bench) — fastest signal
   - 4b.3 (LPM) — biggest blocker
   - 4b.1 + 4b.2 (stages 1+2)
   - 4b.4 (bucket scan)
   - 4b.5 (NAT mirror)
   - 4c.1 (rate-limit)
   - 4c.2 (micro-cache)
   - 4b.6 (COS / filter / mirror)
   Or does a different order ship measurable wins faster?

8. **Should #1605 stay open as umbrella or close as plan-kill?**
   Plan v3's recommendation is **close with `plan-kill` on
   the narrow Phase 4 scope, spin out 4b.0-4b.6 + 4c.x as
   new child issues. Keep doc-coherency contract**: every 4b/4c
   PR updates `docs/userspace-jit-design.md` Scale Target section
   in the same change set.

9. **Is plan v3 itself too ambitious?** A 7-sub-PR program plus
   3 4c sub-PRs is 10 PRs of work, each its own plan-review +
   smoke + Copilot cycle. Methodology overhead is substantial.
   Reviewer to weigh: ship the smallest concrete win first
   (probably 4b.3 DIR-24-8 LPM standalone) and re-plan after,
   vs commit to the full 10-PR architecture now.

10. **Is the 23 Gbps warm-path throughput preserved across
    Phase 4b changes?** New stages add a hash + array load
    + interval bisect to the COLD path, but the WARM path
    (flow cache hit) bypasses all of it. Plan v3 must confirm
    no regression on the warm path during 4b.0-4b.6
    integration. Reviewer to require a "regression line" in
    every 4b.x sub-PR smoke output.

---

## Kill findings (load-bearing)

AGY r3 (`adversarial-review-mpnnu0cr-h4vt3w`) PLAN-KILL of plan v4
identified two structural blockers that I missed in v1-v4
self-review:

### KF-1: Wire protocol pre-expands address-books

`userspace-dp/src/protocol/security.rs:63-66` (also `:150-153`):

```rust
#[serde(rename = "source_addresses", default)]
pub source_addresses: Vec<String>,
#[serde(rename = "destination_addresses", default)]
pub destination_addresses: Vec<String>,
```

And `userspace-dp/src/policy.rs:325-344` constructs the
`PrefixSet*` independently for every rule:

```rust
for prefix in &snap.source_addresses {
    parse_address(prefix, &mut src_v4, &mut src_v6);
}
...
source_v4: PrefixSetV4::from_prefixes(src_v4),
```

The Rust dataplane has no notion of "address-book reference" —
the Go side already expanded every rule's address-book to its
literal CIDR list. Plan v4's "Arc-share LPM tables across rules
that reference the same address-book" mitigation is structurally
impossible without a wire-protocol redesign on BOTH the Go side
(emit address-book IDs + a shared CIDR table) AND the Rust side
(reconstruct shared `Arc<PrefixLpm>` from those IDs).

With pre-expansion in place, plan v4's DIR-24-8 LPM hits 16 MB
per `PrefixSetV4::Trie` (any rule with >16 unique CIDRs in its
source or destination set). 100k rules × 16 MB = **1.6 TB RAM**.
That's not "a memory budget issue", that's "the daemon cannot
boot at production scale".

### KF-2: 4b.3 alone is a regression

The dominant cold-path cost at 1M policies in a hot zone-pair is
the linear scan of the `indices` vector at
`policy.rs:430-442`:

```rust
if let Some(indices) = state.zone_pair_index.get(&key) {
    for &idx in indices {
        if let Some(result) = try_match_rule(...) {
            return result;
        }
    }
}
```

Plan v4's first cut (4b.0 measurement + 4b.3 LPM replacement)
addresses the per-rule address match (`PrefixSetV*::contains`)
but **does NOT replace the linear scan**. At 1M indices × 3 ns
short-circuit cost = 3 ms per packet = **0.0003 Mpps** — five
orders of magnitude below the 49 Mpps target. Even a free LPM
inside each rule cannot rescue the linear scan over indices.

The viable Phase 4b therefore requires 4b.1 (protocol stage) +
4b.2 (port-range bucketing) + 4b.4 (bucket scan) to SHIP
TOGETHER with the LPM in 4b.3, not as separate first-cut PRs.
Plan v4's trim is not a viable first cut.

### KF-3: 49 Mpps target unverified

AGY r3 finding #8 (consistent with SMR r3 F3): the architecture
doc's 23 Gbps profile is at 1500 B (1.92 Mpps); per-worker max
~5.91 Mpps on the warm path. 64 B at 25 Gbps = 49 Mpps × 6 =
294 Mpps aggregate, well above any demonstrated hardware
ceiling. The 270 ns per-packet budget is hypothetical and the
plan cannot commit to it without measurement.

## Recommended next steps

1. **Close #1605 narrow scope with `plan-kill`** (or keep open
   as umbrella; either is defensible — plan author recommends
   "keep open as umbrella because the doc-coherency contract
   still requires a tracking surface").
2. **Phase 4a Cranelift per-flow rewrite JIT** — hard KILLED.
   Flip `docs/userspace-jit-design.md` Phase 4 row to "KILLED
   2026-05-27 — descriptor path already saturates the rewrite
   arm at ≤0.6% of one core remaining; Cranelift's per-flow
   compile-storm vulnerability under DDoS makes the cure worse
   than the disease".
3. **File prerequisite issues for any future Phase 4b
   resurrection**:
   - **Prereq A: wire-protocol restructure** — Go control plane
     emits address-book IDs + a shared CIDR table; Rust
     reconstructs `Arc<PrefixLpm>` per book. Without this, no
     1M-policy memory budget is achievable. File as a new
     issue.
   - **Prereq B: cold-path 64 B hardware ceiling measurement**
     — synthetic policy generator + microbench harness on the
     loss userspace cluster. Without this, no 270 ns/packet
     design target is defensible. File as a new issue (some
     overlap with v3's 4b.0 deliverable).
4. **Phase 4c (cold-path hardening)** can ship independently
   against the existing linear-scan path. File as a new issue
   scoped to: (a) per-source-IP rate-limit at ingress (before
   policy eval); (b) small verdict micro-cache between flow
   cache and full policy eval, sized for ~10k-source small
   botnet attacks (not large-botnet uniform-spoof). This
   limits blast radius if no Phase 4b plan ever ships.
5. **Update `docs/userspace-jit-design.md`** in the closing PR:
   - Add "Scale target" section: 1M policies is a first-class
     production constraint.
   - Flip Phase 4 row to "KILLED 2026-05-27".
   - Mark Phase 3 row as "DONE (binary trie shipped) — see
     prerequisite B for 1M-policy scale-up requirements
     unaddressed by the binary trie".
   - Add Decision-section entry citing this plan's verdict +
     AGY r3 + SMR r4 task IDs.
