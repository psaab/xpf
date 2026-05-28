# Multi-Book LPM full design (v3.2) — #1623

**Status**: v3.2, round 1. Successor to #1609 v3.1 round-2 (Codex r2
`task-mpp2jzhy-m057in` + AGY r2 `adversarial-review-mpp2kcas-nksaq7` +
Claude SMR r7 → 3-of-3 PLAN-NEEDS-MAJOR with 13 patchable findings
including 1 new critical security finding).

**v3.2 scope**: ratify the architectural axis (single global DIR-24-8
LPM over book indices + per-book sorted citation arrays + galloping
merge over Stage-2/3 narrowed candidate phases) and pin down the 13
v3.1-r2 fatals before any further code lands. Step 1 (this PR's likely
implementation slice) is the **multi_book_lpm primitive + Junos knob
`cos.policy.lookup` feature-flag scaffold** — the same shape as v3.1
Step 1 narrow but with the v3.2 corrections baked in. Steps 2-4 are
out of scope for this PR and are tracked as separate sub-issues.

**v3.2 is NOT**: a re-litigation of memory budget. User override is
explicit (cite: MEMORY.md `Memory budget RELAXED per user override`).
CPU/cache/TLB is the binding constraint. Empirical perf claim is
gated on #1612 Scale Target measurement (in-flight in parallel
sub-agent); v3.2 ratifies the architecture, not the numbers.

## Table of contents

1. Background and scope
2. Architectural axis (unchanged from v3.1)
3. v3.1 kill-axis resolution table (the 13 fatals + the new AGY r2
   critical security finding)
4. Memory budget — user override acknowledgement
5. Empirical-grounding deferral (#1612 dependency)
6. Detailed design — the seven corrected sub-systems
7. Construction algorithm — two-pass exact allocator (corrected)
8. Hot path — Stage 2/3/4 (corrected)
9. Feature-flag rollout: `cos.policy.lookup` Junos knob
10. Staged delivery (this PR vs sub-PRs)
11. Open questions for reviewers (focused on v3.2 correctness)

---

## 1. Background and scope

The #1609 chain (v1 KILL → v2 KILL → v3 NEEDS-MAJOR → v3.1
NEEDS-MAJOR) settled on a stable architectural axis:

- **Single global DIR-24-8 LPM v4** + per-/48 hash → bounded multibit
  trie v6, both indexed by `Arc<[u16]>` (or `Arc<[u32]>` — see §6.6)
  book indices, NOT rule indices.
- **Per-book sorted citation arrays** (`Arc<[u32]>` per side per
  phase) carry the rule indices. Stage 4 galloping merge over sorted
  slices preserves first-match-wins structurally.
- **MatchAny side-channels** carry rules where one side is unconstrained
  (literal `any` / no books / `/0` collapse).
- **Two-phase evaluation**: zone-pair phase first, then global phase,
  per-phase galloping merge.

What broke in v3.1 r2:

| # | Finding | Source | Severity |
|---|---------|--------|----------|
| 1 | P2 dst-pseudo-id leaks into src lookup (cross-rule citation leak via shared LPM) | Codex r2 #1 | BLOCKING |
| 2 | v3.1 addendum left stale contradictions in §2.3/§2.6/§7 (hard-reject vs warn) | Codex r2 #2 | BLOCKING |
| 3 | Step 1 scope incoherent vs acceptance criteria | Codex r2 #3 | BLOCKING |
| 4 | Stage 4 master-fallback DoS amplification (~15,000× under crafted traffic) | AGY r2 #10 | **CRITICAL SECURITY** |
| 5 | V6 sub-table heap-fragmentation latency at config-apply | AGY r2 #4 | MAJOR |
| 6 | P8 prefix push-down missing child propagation | AGY r2 #8 | MAJOR |
| 7 | LeafArcPool last-seen cache + Single/Shared leaf inline repr | AGY r2 #9 | MAJOR |
| 8 | Junos CLI gap for v6 leaf-overflow cap | AGY r2 #3 | MAJOR |
| 9 | PseudoBookId type-safety theater (RealBookId wrapper enforced by safe accessor) | AGY r2 #2 | MAJOR |
| 10 | Simplification: parallel `prefixes_v4/v6: Arc<[Prefix]>` on PolicyRule (same shape as BookEntry from #1609 Step 1) | AGY r2 #1 | MAJOR |
| 11 | P1 alleged `MatchNone` compile bug | AGY r2 #1 | NIT (refuted by SMR r7) |
| 12 | LeafArcPool 10-100× dedup claim — downgrade to "measured" | Claude SMR r5/r7 | MAJOR |
| 13 | Claude SMR r7 N1-N5 documentation cleanups | Claude SMR r7 | NIT |

v3.2 must explicitly close 1-12 and resolve 13.

## 2. Architectural axis (carry-over from v3.1)

Hot-path lookup sequence per packet (unchanged):

```
zone_pair_key(from_id, to_id) → phase_id
  Stage 2 (proto+dst_port narrow) → candidate slice set per phase
  Stage 3 (src+dst LPM intersect) → emitted rule_idx candidates
  Stage 4 (galloping merge over Stage-2 candidate slices ∩ Stage-3
           emitted candidates, preserving local_rule_idx order
           within each phase) → first-match-wins result
  fallback (overflow handling — see §6.4 for the v3.2 fix)
```

Zero hot-path allocation. All LPM leaves, citation slices, and
scratch buffers are pre-allocated at config-apply. Per-worker scratch
is a fixed-size `[u32; STAGE4_BUFFER_SIZE]` array (no `Vec`).

## 3. v3.1 kill-axis resolution table

| # | v3.1 r2 finding | v3.2 fix | §reference |
|---|-----------------|----------|------------|
| 1 | dst-pseudo-id leaks into src LPM lookup (cross-rule citation index) | **Separate LPMs for src vs dst.** No shared LPM. `state.src_lpm_v4`, `state.dst_lpm_v4`, `state.src_lpm_v6`, `state.dst_lpm_v6`. Each LPM is indexed by its own dense book-id space (real books + side-local pseudo-books). No cross-side ID space. | §6.1 |
| 2 | v3.1 addendum vs stale main-body text | v3.2 is a fresh document. No appended addenda. Wherever §6 / §7 / §8 of this document text conflicts with v3.1, **v3.2 wins** (this doc is the new normative spec). | §6, §7, §8 |
| 3 | Step 1 scope incoherent | v3.2 §10 specifies a **narrow Step 1**: the `multi_book_lpm` primitive (DIR-24-8 v4 builder + lookup + the bounded v6 sub-trie); the `cos.policy.lookup` Junos knob; and a feature-flag dispatch stub at `evaluate_policy_result_with_len`. NO galloping merge in Step 1. NO PseudoBook builder in Step 1. NO Stage 2/3/4 hot path in Step 1. Acceptance criteria are SCOPED to that — primitive property tests at 10/100/1K/10K rule counts, build clean with feature flag OFF on master semantics, build clean with feature flag ON falling back to linear scan (stub). | §10 |
| 4 | **Stage 4 master-fallback DoS amplification** | **Overflow path scans ONLY emitted candidates**, not the entire zone-pair phase bucket. Concretely: when the galloping merge fills its fixed-size scratch buffer to `STAGE4_BUFFER_SIZE = 64` rules, the fallback runs `try_match_rule` over **those 64 emitted candidates only**, then halts. If the merge has more pending output, the overflow is observable via `xpf_userspace_policy_dag_stage4_overflow_total` and the operator increases the buffer (or accepts that a pathological config is degraded to a known bound, not amplified). Bounded worst-case work per packet: 64 × `try_match_rule` cost, not 1M × scan cost. | §6.4 |
| 5 | V6 sub-table heap-fragmentation latency | v6 sub-tables are pool-allocated from a `Vec<u8>` arena owned by the DAG snapshot. Each /48 leaf, when it points to a sub-trie, indexes into the arena via `(offset, len)` instead of `Box<[Node]>`. Arena is built single-pass at construction; freed in one drop when the snapshot is replaced. Construction-time alloc count drops from O(#sub-tries) to O(1). | §6.2 |
| 6 | Push-down missing child propagation | LPM build is two-pass: pass-1 enumerates all prefix entries grouped by stride; pass-2 walks levels top-down and **propagates the parent's covering book-id set into every child slot the parent's prefix would cover** before the child's own prefixes are applied. Concretely: at level-2, for each /24 slot under a /16 parent, if the slot has no longer-prefix entry, it inherits the parent's `Arc<[u32]>` book-id list. Explicit step in the builder, not a "we'll get to it" comment. | §7.2 |
| 7 | LeafArcPool inline repr | Drop the `LeafArcPool` abstraction. Leaves are stored inline in the DIR-24-8 stride table as one of three variants: `Empty` (zero-cost), `Single(u32)` (book-id inline, no Arc), `Multi(Arc<[u32]>)` (full slice). Three variants packed into 8 B per slot via discriminant + tagged union. Eliminates the "10-100× dedup" claim entirely; the structural inline case (single book per leaf, the dominant pattern) avoids the Arc allocation outright. | §6.3 |
| 8 | Junos CLI gap for v6 leaf-overflow cap | `set chassis cluster cos policy lookup-v6-leaf-max <N>` (default 1024) exposes the cap. v6 build hard-rejects at commit time if any /48 leaf exceeds the cap, with the offending /48 cited in the error. No fallback to linear scan on commit — the operator must either raise the cap or split the books. (Hot path itself cannot encounter the overflow because commit gates it.) | §6.2, §9 |
| 9 | PseudoBookId type safety | `BookId(u32)` wraps real book indices `[0, real_book_count)`. `PseudoBookId(u32)` wraps pseudo-book indices `[0, pseudo_book_count)`. `LpmLeafId(u32)` is the LPM's opaque output — internally either a `BookId` or `PseudoBookId` depending on which side's LPM produced it. The **only** safe accessor is `state.cited_rules(side, lpm_leaf_id, phase)` which dispatches on the LPM's own side, removing the cross-side-leak class. Per-side LPMs (fix #1) make this trivial because each LPM's output is unambiguous. | §6.1 |
| 10 | Parallel `prefixes_v4/v6: Arc<[Prefix]>` on PolicyRule | Mirror the #1609 Step 1 BookEntry shape onto PolicyRule itself for the literal side. `PolicyRule.source_prefixes_v4: Arc<[PrefixV4]>` + `source_prefixes_v6`, `destination_prefixes_v4`, `destination_prefixes_v6`. Populated in `parse_policy_state_with_counters` at the same point the literal `PrefixSetV{4,6}` is built. Used by the PseudoBook builder in Step 3. Adds 4 × 16 B = 64 B per rule (vs ~50 KB at 1M rules → 50 MB additional total at the high end, dominated by other state). | §6.5 |
| 11 | Alleged `MatchNone` compile bug | NOT a real issue per SMR r7 (`prefix_set.rs:42-47` confirms `MatchAny | MatchNone | Linear | Trie` variants exist). v3.2 reaffirms: any builder that walks `PrefixSetV{4,6}` must explicitly handle all 4 variants. `MatchNone` produces empty contribution; `MatchAny` produces the MatchAny side-channel. | §6.5, §7.3 |
| 12 | LeafArcPool 10-100× dedup claim | Removed entirely with fix #7 (inline 3-variant repr). The plan no longer claims dedup; the structural inline case (Single variant) achieves the same memory result without the LeafArcPool abstraction. | §6.3 |
| 13 | SMR r7 N1-N5 documentation cleanups | Carried into this document's body text where applicable (no addenda). Each cleanup is now part of the relevant section. | §6, §7, §8 |

## 4. Memory budget — user override

Per MEMORY.md "Memory budget RELAXED per user override" — the v2 round
F1.1 fatal "120-160 MB per snapshot is too much" is overridden. Budget
is effectively unbounded for the LPM data structures. CPU, L1-i, L1-d,
and TLB pressure are the binding constraints.

v3.2's per-snapshot memory rough estimate (informational, not gating):

- v4 DIR-24-8 stride tables: ~70 MiB worst case (16M × 4 B + sub-table
  overhead).
- v6 /48 bucket map + bounded sub-tries: ~10-50 MiB depending on
  prefix distribution.
- Per-book citation arrays (Arc<[u32]>): O(total rules × cited books)
  — dominated by the largest zone-pair phase, typically 10-100 MiB.
- Sum: low-hundreds of MiB per snapshot, well under multi-GiB.
- Snapshots are RCU-replaced via ArcSwap; one old + one new at the
  swap boundary, total never exceeds 2× the snapshot size.

Re-litigation in plan-reviews is OUT-OF-SCOPE per user override.

## 5. Empirical-grounding deferral

v3.2 **ratifies architecture**, not numbers. The "≥10× cold-path
speedup at 1M rules" claim cannot be validated by v3.2's PRs alone.
The validation gate is #1612 (Scale Target measurement, in-flight as
PR #1619 step-3 → measurement step-4/5 still upcoming). The
production default-flip (Step 4) is gated on #1612 producing the 1M
cold-path measurement.

What v3.2 reviewers ARE asked to validate:

- Correctness of the LPM data structures at 10/100/1K/10K rules
  (property tests in Sub-PR B/C).
- First-match-wins preservation under galloping merge (proof sketch
  + property tests in Sub-PR E).
- Bounded worst-case per-packet work (§6.4 overflow path).
- No hot-path allocation under sustained load (no `Vec`, no `Arc`
  clone, no `Box` in the hot path).
- HA-safety of feature-flag dispatch (ArcSwap publish path is the
  same as today; feature flag changes the consumer, not the publish).
- Junos CLI behavior on `set chassis cluster cos policy lookup
  multi_stage_dag | linear`, including commit-warning paths.

What v3.2 reviewers are NOT asked to validate:

- The 10× speedup itself — that's #1612's job.
- Memory budget — user override.
- Whether linear-scan is actually slow at 1M rules — that's the
  baseline #1612 will produce.

## 6. Detailed design — the seven corrected sub-systems

### 6.1 Per-side LPMs (fix #1, fix #9)

```rust
pub(crate) struct PolicyDag {
    // Per-side LPMs over OWN dense index space.
    src_lpm_v4: MultiBookLpm4,
    dst_lpm_v4: MultiBookLpm4,
    src_lpm_v6: MultiBookLpm6,
    dst_lpm_v6: MultiBookLpm6,
    // Side-local pseudo-book index spaces.
    src_pseudo_books: Vec<PseudoBook>,
    dst_pseudo_books: Vec<PseudoBook>,
    // Stage 2 indices per phase (zone-pair vs global).
    zone_pair_stage2: FxHashMap<u64, Stage2Index>,
    global_stage2: Stage2Index,
    // Per-(side, phase) citation slices — indexed by (BookId | PseudoBookId).
    src_zone_pair_citations: FxHashMap<u64, BookCitations>,
    dst_zone_pair_citations: FxHashMap<u64, BookCitations>,
    src_global_citations: BookCitations,
    dst_global_citations: BookCitations,
    // MatchAny side-channels per phase per side.
    match_any_zone_pair: FxHashMap<u64, MatchAnyChannels>,
    match_any_global: MatchAnyChannels,
}
```

Each LPM's lookup output `LpmLeafId(u32)` is unambiguous: it indexes
`src_zone_pair_citations.get(zp_key).unwrap().for_book(leaf_id)` (or
similar). There is no cross-side ID space, no cross-side leak.

The safe accessor:

```rust
impl PolicyDag {
    /// Returns the candidate rule indices cited by `book` for
    /// `side` in `phase`. `book` MUST be the LPM output for `side`'s
    /// LPM in `phase`; the type system enforces this via the
    /// `LpmLeafId` constructor being non-public.
    fn cited_rules(&self, side: Side, phase: Phase, book: LpmLeafId) -> &[u32] {
        let citations = match (side, phase) {
            (Side::Src, Phase::ZonePair(zp)) => &self.src_zone_pair_citations[&zp],
            // ...
        };
        citations.for_book(book)
    }
}
```

The `LpmLeafId` newtype is private; only the LPM lookup can produce
one. Callers can't pass a `dst` leaf to the `src` accessor — a type
error at compile time.

### 6.2 v6 arena + leaf-overflow CLI cap (fix #5, fix #8)

```rust
struct MultiBookLpm6 {
    bucket_map: FxHashMap<u64 /* /48 prefix */, BucketEntry>,
    arena: Vec<u8>, // bump-allocated sub-trie storage
}

enum BucketEntry {
    Empty,
    SubTrie { offset: u32, len: u32 }, // into arena
}
```

Build phase pre-allocates the arena to a worst-case size, copies all
sub-trie nodes in, then truncates. One allocation total for the v6
side, no fragmentation.

Junos knob:

```
set chassis cluster cos policy lookup-v6-leaf-max <1..65535>  # default 1024
```

Commit-time check: any /48 leaf exceeding the cap rejects the commit
with the offending /48 in the error message. No runtime overflow path
exists (commit gates it).

### 6.3 Inline 3-variant LPM leaf (fix #7, fix #12)

```rust
#[repr(u8)]
enum LpmLeaf {
    Empty,
    Single(u32),       // book_id inline
    Multi(Arc<[u32]>), // full slice
}
```

The DIR-24-8 stride table is `Box<[LpmLeaf]>` — one variant per slot.
8 B per slot worst case (Arc fat pointer + discriminant; `Single`
fits in the same 8 B). No LeafArcPool. No dedup claim.

`Single` is the dominant pattern: most /24 slots cite one book.
`Multi` is rare but unavoidable for slots that genuinely cover
multiple books.

### 6.4 Stage 4 bounded overflow (fix #4 — CRITICAL SECURITY)

```rust
const STAGE4_BUFFER_SIZE: usize = 64;

fn galloping_merge_evaluate(
    state: &PolicyState,
    dag: &PolicyDag,
    side_inputs: &Stage3Output,
    phase: Phase,
    /* packet fields */
) -> PolicyEvaluationResult {
    let mut scratch: [u32; STAGE4_BUFFER_SIZE] = [0; STAGE4_BUFFER_SIZE];
    let mut emitted: usize = 0;
    let mut merge_iter = build_merge_iter(side_inputs);
    let mut overflow = false;

    while let Some(rule_idx) = merge_iter.next() {
        if emitted == STAGE4_BUFFER_SIZE {
            overflow = true;
            break;
        }
        scratch[emitted] = rule_idx;
        emitted += 1;
    }

    if overflow {
        STAGE4_OVERFLOW_COUNTER.with_label_values(&[phase.label()]).inc();
    }

    // CRITICAL: evaluate ONLY the (≤ 64) emitted candidates.
    // NEVER fall back to "scan the whole phase bucket".
    for &rule_idx in &scratch[..emitted] {
        if let Some(result) = try_match_rule(
            &state.rules[rule_idx as usize], /* ... */
        ) {
            return result;
        }
    }
    PolicyEvaluationResult { action: state.default_action, policy_id: 0 }
}
```

**Worst-case work per packet**: `STAGE4_BUFFER_SIZE × try_match_rule
cost` = bounded constant. The DoS amplification vector AGY r2 #10
identified is closed: an adversary that crafts traffic matching 1M
rules in one phase still sees ≤ 64 `try_match_rule` calls per packet,
not 1M.

The cost is correctness: in the overflow case, rules beyond the
first 64 in merge order are silently skipped. This is observable
(counter), bounded (configurable buffer size), and acceptable per
SKILL.md philosophy ("pathological configs are no-worse-than-master
linear scan" was the v3 framing — v3.2 strengthens this to
"pathological configs see a bounded constant of work, observable").

Operators with pathological configs can either:
1. Raise `STAGE4_BUFFER_SIZE` via Junos knob `set chassis cluster
   cos policy stage4-buffer-size <16..1024>` (default 64).
2. Restructure the books to reduce overlap.
3. Fall back to `cos.policy.lookup = linear` (the legacy path,
   still in-tree by default).

### 6.5 Parallel literal prefix arrays on PolicyRule (fix #10)

```rust
pub(crate) struct PolicyRule {
    // ... existing fields ...
    /// #1623 v3.2: parallel literal-prefix arrays mirroring the
    /// #1609 BookEntry shape. Carries the original literal CIDRs
    /// BEFORE PrefixSetV{4,6} collapses to MatchAny / MatchNone /
    /// Linear / Trie. Used by the PseudoBook builder in Sub-PR D.
    source_prefixes_v4: Arc<[PrefixV4]>,
    source_prefixes_v6: Arc<[PrefixV6]>,
    destination_prefixes_v4: Arc<[PrefixV4]>,
    destination_prefixes_v6: Arc<[PrefixV6]>,
}
```

Populated in `parse_policy_state_with_counters` at parse time. Same
pattern as the #1609 BookEntry parallel arrays (verify with
`policy.rs:438-470`). Hot path is unaffected — the legacy `try_match_rule`
still uses `source_literal_v{4,6}` / `destination_literal_v{4,6}`.

### 6.6 u32 book indices (carry-over from v3.1)

LPM leaves carry `Arc<[u32]>` book_ids (not `u16`). 1M-rule scale
implies >65K books is plausible. Per-leaf memory cost doubles vs
v2's `u16`; budget relaxed.

### 6.7 Per-zone-pair ordering preserved (carry-over from v3.1 §2.5)

Stage 4 evaluates `Phase::ZonePair(zp_key)` first, then `Phase::Global`.
Within each phase, the galloping merge emits candidates in ascending
**local rule_idx within that phase** — NOT flat ascending global
rule_idx. The citation arrays are sorted at build time by local
rule_idx within the phase they belong to. First-match-wins is preserved
because:

1. Phase priority is per-(zone_pair vs global) — zone-pair wins.
2. Within a phase, local rule order is preserved.
3. Stage 4 returns on first match.

## 7. Construction algorithm — two-pass exact allocator (corrected)

### 7.1 Overview

```
Phase 0: PseudoBook builder
  - For each rule R, if R has source_prefixes_v4/v6 non-empty:
      register a per-rule pseudo-book in src_pseudo_books.
  - Same for destination side, dst_pseudo_books.
  - DOES NOT touch the LPM yet.

Phase 1: Per-(side, phase) citation array build
  - Pass-1: count, per (side, phase, book_or_pseudobook) → rule cite count.
  - Pass-2: allocate per-(side, phase) BookCitations with exact-size
    Arc<[u32]> per book.
  - Side-by-phase tables sized exactly; no over-allocation.

Phase 2: Multi-Book LPM v4 + /0 short-circuit (push-down fixed)
  - Pass-1: enumerate all prefix entries per side, grouped by stride.
  - Pass-2: walk top-down, propagating parent coverage into child slots
    BEFORE applying child's own prefixes (fix #6).
  - /0 short-circuit: if a side's literal or any cited book is MatchAny,
    rule goes into match_any_zone_pair/global side-channel, NEVER into
    level-0 build. Level-0 is reserved for non-/0 entries.

Phase 3: Multi-Book LPM v6 (arena-allocated, leaf-cap-gated)
  - Same as Phase 2 but with /48 buckets + bounded sub-tries.
  - Leaf-cap commit check before snapshot publish.

Phase 4: Snapshot publish via ArcSwap (existing pattern).
```

### 7.2 Push-down propagation (fix #6)

```rust
fn build_multi_book_lpm_v4(...) -> MultiBookLpm4 {
    let mut level0: [LpmLeaf; 256] = [LpmLeaf::Empty; 256]; // /8 strides
    let mut level1: Vec<[LpmLeaf; 256]> = Vec::new();        // /16 strides
    let mut level2: Vec<[LpmLeaf; 256]> = Vec::new();        // /24 strides

    // Pass-1: enumerate (prefix, books) entries.
    let entries: Vec<(PrefixV4, Arc<[u32]>)> = enumerate_entries(...);

    // Pass-2: walk top-down, propagating parent coverage.
    for (prefix, books) in &entries {
        let path = stride_path(prefix); // (stride0, [stride1], [stride2])
        // Apply at the deepest stride first; propagate to any
        // longer-prefix-but-not-yet-set child slots that this prefix
        // covers.
        apply_with_pushdown(&mut level0, &mut level1, &mut level2,
                            path, books.clone());
    }

    MultiBookLpm4 { level0, level1, level2 }
}

fn apply_with_pushdown(...) {
    // For each slot S the prefix covers:
    //   if S currently has Empty → set S = books
    //   if S currently has a longer-prefix entry → leave alone
    //   if S currently has a shorter-prefix entry (the parent) → union
    //
    // The KEY fix vs v3.1: when descending into a longer-prefix
    // stride table, INHERIT the parent's coverage into every slot
    // of the child stride before applying the child's own prefix
    // contributions. This is the missing-child-propagation that
    // AGY r2 #8 flagged.
}
```

Property test in Sub-PR B: for any random set of overlapping
prefixes, every address that should match by classical LPM semantics
matches via the constructed table.

### 7.3 PrefixSet variant handling (fix #11)

All 4 variants of `PrefixSetV{4,6}` must be handled at config-apply
time:

```rust
match book_entry.v4 {
    PrefixSetV4::MatchAny => {
        // Rule citing this book goes into the MatchAny side-channel
        // for the appropriate phase + side. NOT into the LPM.
    }
    PrefixSetV4::MatchNone => {
        // Rule contributes NOTHING via this book. Skip.
    }
    PrefixSetV4::Linear(ref prefixes) => {
        // Iterate prefixes; insert into LPM with book_id citation.
    }
    PrefixSetV4::Trie(_) => {
        // Iterate via PrefixSetV4::iter_prefixes (#1609 scaffolding
        // provides this; verify presence as Sub-PR B prerequisite).
        // Insert each prefix into LPM with book_id citation.
    }
}
```

Open question O1 (§11): does #1609 step-1 actually provide
`PrefixSetV{4,6}::iter_prefixes` as an iteration API, or only the
`prefixes_v4/v6: Arc<[PrefixV4]>` parallel array? The latter is
sufficient — the LPM build iterates the parallel array, not the
PrefixSet. Verify in code-review that `parse_policy_state_with_counters`
populates `prefixes_v{4,6}` from canonical input BEFORE any PrefixSet
collapse (it does, per policy.rs:446-470).

## 8. Hot path — Stage 2/3/4 (corrected)

Sequence per packet (post-flag-on):

```rust
fn evaluate_via_dag(...) -> PolicyEvaluationResult {
    // Phase 1: zone-pair phase
    if let Some(result) = evaluate_phase(state, dag, Phase::ZonePair(zp_key), ...) {
        return result;
    }
    // Phase 2: global phase
    if let Some(result) = evaluate_phase(state, dag, Phase::Global, ...) {
        return result;
    }
    PolicyEvaluationResult { action: state.default_action, policy_id: 0 }
}

fn evaluate_phase(state, dag, phase, src_ip, dst_ip, proto, src_port, dst_port, len) -> Option<...> {
    // Stage 2: protocol+dst_port narrow → candidate slice set.
    let stage2_candidates = dag.stage2_for(phase).candidate_slices(proto, src_port, dst_port);

    // Stage 3: src+dst LPM lookups.
    let src_books = match src_ip {
        IpAddr::V4(s) => dag.src_lpm_v4.lookup(s),
        IpAddr::V6(s) => dag.src_lpm_v6.lookup(s),
    };
    let dst_books = match dst_ip {
        IpAddr::V4(d) => dag.dst_lpm_v4.lookup(d),
        IpAddr::V6(d) => dag.dst_lpm_v6.lookup(d),
    };
    let src_citations = dag.cited_rules(Side::Src, phase, src_books);
    let dst_citations = dag.cited_rules(Side::Dst, phase, dst_books);
    let match_any = dag.match_any_for(phase); // src + dst MatchAny channels

    // Stage 4: galloping merge over (stage2_candidates ∩ src_citations ∩
    // dst_citations), unioned with the MatchAny channels for the side(s)
    // that match-any applies to.
    galloping_merge_evaluate(state, stage2_candidates, src_citations,
                             dst_citations, match_any, /* ... */)
}
```

Allocation-free: `stage2_candidates` is a `SmallVec<[&'a [u32]; 8]>`
on the stack; `src_books`/`dst_books` are `LpmLeafId(u32)`; the merge
scratch is a stack array; no `Vec` / `Arc::clone` / `Box` anywhere
in this function.

## 9. Feature-flag rollout — Junos knob

```
set chassis cluster cos policy lookup [multi_stage_dag | linear]   # default linear
set chassis cluster cos policy stage4-buffer-size <16..1024>       # default 64
set chassis cluster cos policy lookup-v6-leaf-max <1..65535>       # default 1024
```

Wire surface:

- `pkg/config/typed.go`: `CoSPolicyLookup string` (validated against
  `["multi_stage_dag", "linear"]`), `CoSPolicyStage4BufferSize uint16`,
  `CoSPolicyLookupV6LeafMax uint16`.
- `userspace-dp/src/protocol/security.rs`: snapshot fields
  `policy_lookup: u8` (0=linear, 1=multi_stage_dag), `stage4_buffer_size: u16`,
  `lookup_v6_leaf_max: u16`.
- `userspace-dp/src/policy.rs`: dispatch at
  `evaluate_policy_result_with_len` reads the flag from `PolicyState`
  and dispatches to either the legacy linear path or `evaluate_via_dag`.
- `pkg/cmdtree/tree.go`: completion entries for the three knobs.

Wire-protocol both-sides check: when adding the snapshot fields, both
the Go encoder (`pkg/dataplane/userspace/snapshot/security.go` or
similar) and the Rust decoder (`userspace-dp/src/protocol/security.rs`)
must agree on field order and types. Add a parity unit test in the
existing protocol-parity suite.

Default is `linear`. The default-flip to `multi_stage_dag` is a
SEPARATE PR (Sub-PR H) gated on #1612 ratification.

## 10. Staged delivery — sub-PRs

This issue (#1623) ratifies the v3.2 plan. The implementation is
broken into 8 sub-PRs already enumerated in the issue body (Sub-PR
A-H). v3.2 plan-review only ratifies Sub-PR A (this plan rewrite).

**This PR (Step 1, the multi_book_lpm primitive + feature-flag
scaffold)** lands in two commits:

1. **plan commit**: writes `docs/pr/1623-multi-book-lpm-v3-2/plan.md`
   (this document), the Claude SMR plan-review docs, and
   `reviewer-ids.md`. NO code change.
2. **scaffold commit** (after plan-review converges): adds
   - `userspace-dp/src/policy/multi_book_lpm.rs` (new, minimal):
     DIR-24-8 v4 builder + lookup, inline 3-variant `LpmLeaf`,
     stub for v6. Property tests at 10/100/1K/10K rules using a
     local synthetic policy generator.
   - `userspace-dp/src/policy/mod.rs` (new): module-organizes
     the existing `policy.rs` into a submodule for the LPM primitive
     while keeping `policy.rs` content unchanged in `mod.rs` for
     non-refactor disturbance. (Apply the `module/foo.rs` layout
     pattern per MEMORY.md `feedback_refactor_module_dir_layout`.)
   - `pkg/config/typed.go`: `CoSPolicyLookup` field default `"linear"`.
   - `userspace-dp/src/protocol/security.rs`: snapshot field
     `policy_lookup: u8` default 0=linear.
   - `userspace-dp/src/policy.rs`: feature-flag dispatch reading
     `state.policy_lookup`; when flag is 1, falls back to legacy
     linear scan via the same code path (stub — full Stage 2/3/4
     dispatch is Sub-PR G).
   - `docs/userspace-jit-design.md` Phase 4 row update.

Sub-PR scope is intentionally narrow to keep review surface small.
NO PseudoBook builder. NO galloping merge. NO Stage 2/3/4 hot path.
NO production turn-on.

Sub-PRs B-H are tracked as follow-up issues (created post plan-ready):

- **Sub-PR B**: PseudoBook builder + parallel `prefixes_v{4,6}` on
  PolicyRule (fix #10).
- **Sub-PR C**: Stage 2 index builder + Stage 2 candidate-slice API.
- **Sub-PR D**: Stage 3 src+dst LPM dispatch, per-side citations.
- **Sub-PR E**: Stage 4 galloping merge + bounded scratch buffer +
  the §6.4 overflow handler.
- **Sub-PR F**: v6 arena builder + leaf-overflow CLI cap.
- **Sub-PR G**: `evaluate_via_dag` full hot path, behind the existing
  `cos.policy.lookup` feature flag.
- **Sub-PR H**: production default-flip — gated on #1612 measurement.

## 11. Open questions for reviewers

**O1**: Does the #1609 step-1 BookEntry parallel-prefix scaffold
provide the full canonical prefix list for the LPM build, or are
there cases where `prefixes_v{4,6}` is incomplete relative to the
input? Spot-check: `policy.rs:438-470` shows the parallel arrays are
populated from `snap.prefixes_v4` and `snap.prefixes_v6` BEFORE the
PrefixSet collapse, so the canonical input shape is preserved.
Reviewers please confirm by walking the test cases at
`policy_tests.rs::test_book_entry_zero_plus_non_zero_prefixes_preserved`.

**O2**: §6.4's `STAGE4_BUFFER_SIZE = 64` default — is 64 the right
bound? An adversary that engineers a config with 65 overlapping rules
per phase forces overflow on every matching packet. With the v3.2
fix, this is bounded at 64 × `try_match_rule` per packet, but the
last rule still gets silently skipped. Should the default be 256?
Should the operator be required to opt into the bounded-skip
behavior, with the default being a hard-reject at commit if the
build phase detects a single phase with > N citations across all
books?

**O3**: §6.2's v6 arena — the arena is a `Vec<u8>` reinterpreted as
trie nodes via offset/len. Aliasing concerns: any code that reads
the arena while another thread mutates it via snapshot replacement
must do so via ArcSwap. Confirmed: the arena is part of the
`PolicyDag` which is owned by the snapshot, never mutated after
publish, dropped only when the snapshot is replaced. But: reviewers
please check that the `Vec<u8>` → `&[Node]` reinterpret-cast is
sound under Rust's aliasing model. `bytemuck::cast_slice` or an
explicit unsafe block with a SAFETY comment?

**O4**: §7.2's push-down propagation — the algorithm as described
walks parent coverage into child slots. Is there a degenerate case
where the cited book set is a `Multi(Arc<[u32]>)` with thousands of
book_ids and the propagation creates `~256K` copies of the same Arc
across the level-2 stride table? The Arc::clone is O(1), so memory
is bounded, but the post-propagation table has many slots pointing
to the same Arc. Is that OK, or should the build cap the propagation
depth?

**O5**: §6.5's parallel prefix arrays on PolicyRule add 4 × 16 B = 64 B
per rule. At 1M rules that's 64 MiB additional snapshot memory.
Per user override this is in-budget, but: do reviewers see a path to
avoiding the duplication by reusing the `source_literal_v4`'s
underlying storage when the PrefixSet variant is `Linear` (the
common case)? `PrefixSetV4::Linear` already stores `Vec<PrefixV4>`;
the parallel array could be `&[PrefixV4]` borrowed from the
PrefixSet if lifetime constraints allow. Otherwise, Arc-share the
storage between the two views.

**O6**: §8's `cited_rules` accessor returns `&[u32]` — is there a
scenario where the LPM lookup returns `LpmLeafId(u32)` that doesn't
match any phase's citation table (e.g., a book that has no rules
citing it in this phase)? The build should ensure the citation table
covers all books, with empty slices for books with no citations in
the phase, so `cited_rules` always returns a valid (possibly empty)
slice. Reviewers please confirm the build invariant.

**O7**: §9's Junos knob nesting — `set chassis cluster cos policy
lookup` is under `cos`, but the knob conceptually applies to the
policy lookup path which is independent of CoS. Is there a better
Junos hierarchy? `set security policies global lookup` would be
more canonical Junos, mirroring `security policies` under which
policies live. v3.2 currently uses `cos.policy.lookup` to align with
the issue body's "Junos knob `cos.policy.lookup`" framing, but
reviewers may prefer the more canonical path.

---

## Round-1 hostile self-review prompts (Claude SMR)

The SMR document (`claude-smr-plan-r1.md`) MUST answer:

1. Does v3.2 close ALL 13 v3.1 r2 findings? Walk each line of §3.
2. Is the §6.4 DoS bound TIGHT? Worked trace of an adversarial 1M-rule
   config matching the entire phase bucket; verify per-packet work is
   exactly `STAGE4_BUFFER_SIZE × try_match_rule` cost, not more.
3. Is the §6.1 per-side LPM type-safety claim ACTUALLY enforced by the
   type system, or is it convention? Construct a hypothetical caller
   that tries to pass a dst leaf to the src accessor — does it compile?
4. Does §7.2's push-down handle the case where a `/0` literal lands on
   a rule whose other-side has a /24 book? The /0 short-circuits to
   MatchAny on one side, but the other side's LPM still needs to
   cite this rule's index.
5. Step 1's "scaffold commit" introduces a `policy/` module directory.
   Does this collide with the existing single-file `policy.rs`? The
   layout pattern from MEMORY.md is `policy/{mod.rs, multi_book_lpm.rs}`
   — verify the existing `policy.rs` can be split or kept as the mod
   contents.
6. The empirical-grounding deferral (§5) leaves the 10× claim
   unverified by this PR. Is the v3.2 plan honest about that, or is
   there an implicit performance assertion that reviewers might miss?

These are the round-1 hostile dimensions. Any "yes, all clear" answer
without a walked counter-example is a r1 self-review failure.
