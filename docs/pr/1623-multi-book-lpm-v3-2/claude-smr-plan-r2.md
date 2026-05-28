# Claude SMR plan-review r2 — #1623 v3.2 convergence

**Role**: domain SMR — same scope as r1.

**Verdict (round 2): PLAN-NEEDS-MAJOR — 3-of-3 convergence with
Codex r1 + AGY r1.**

## Round-1 convergence

| Reviewer | Verdict (label) | Verdict (substance) | New BLOCKING surfaced beyond SMR r1 |
|---|---|---|---|
| Codex r1 (`task-mppkw5cs-ca6c61`) | PLAN-NEEDS-MAJOR | NEEDS-MAJOR with 5 BLOCKING + 7 MAJOR | 5 |
| AGY r1 (`adversarial-review-mppkv5ca-5lruxf`) | PLAN-NEEDS-MINOR (label) | NEEDS-MAJOR (substance — 5 BLOCKING in findings) | 5 |
| SMR r1 (self, `claude-smr-plan-r1.md`) | PLAN-NEEDS-MINOR | NEEDS-MINOR (R1-R3) | 0 |

SMR r1 underestimated the surface — found 3 residual issues (R1
LpmLeafId, R2 merge dedup, R3 policy/ move) but missed 5 BLOCKING
defects that both Codex and AGY caught independently. SMR r2 walks
each below and ratifies.

## Newly-surfaced BLOCKING findings

### B1: §6.4 silent truncation breaks first-match-wins (Codex #1, AGY #2)

The §6.4 design says "evaluate ONLY the (≤ 64) emitted candidates"
and "rules beyond the first 64 in merge order are silently skipped".

Worked counter-example (Codex #1):
- 65 zone-pair candidates survive Stage 2 + LPM.
- First 64 are Stage-2 false positives that fail `try_match_rule`
  due to source-port / range / inactive flag / application detail.
- Candidate 65 is the real match (e.g., a deny rule for the
  attacker's specific port).
- v3.2 §6.4 truncates at 64, evaluates 64 false-positives, then
  returns the **default action** (or falls through to global, which
  may also default-permit).
- The attacker's traffic is **silently permitted** instead of
  matching the deny rule at position 65.

This is a Stage-4 SECURITY BYPASS, not just a DoS limit. The v3.1 r2
finding said "Stage 4 master-fallback is a DoS amplification" because
it scanned 1M rules; v3.2's fix replaces unbounded scan with bounded
silent-skip, which is a *worse* security posture (silent permit
instead of slow deny).

§6.4's framing as "bounded constant of work, observable" is wrong.
Observability via a counter is not equivalent to correctness; an
operator can't read counters fast enough to prevent attack traffic
from being permitted.

This is the dominant fatal in r1. The v3.2 fix DOES NOT close AGY r2
#10 — it merely changes the failure mode from DoS to silent bypass.

**Required fix path** (Codex + AGY convergent):
- Commit-time hard-reject: configurations whose worst-case Stage 4
  emission can exceed `STAGE4_BUFFER_SIZE` are rejected at commit.
  The build phase enumerates per-(zone_pair, side, stage2_key) the
  maximum possible candidate count and refuses to publish if any
  combo exceeds the buffer.
- Alternatively, "explicitly unsafe opt-in" mode where the operator
  acknowledges the silent-skip risk via a Junos knob.
- Production `multi_stage_dag` flag MUST NOT permit silent truncation.

### B2: §6.4 hidden merge work invalidates the bounded-work claim (Codex #2, AGY #1)

The §6.4 pseudocode calls `merge_iter.next()` 65 times. Each
`next()` call walks the input citation slices to find the next
candidate. SMR r1 asserted this is O(1) per next under galloping
merge. That's WRONG.

Galloping merge over sorted slices is O(log N) **per emitted output**
ONLY when the inputs have a non-trivial intersection. For
adversarial-empty intersection (Codex #2 / AGY #1 worked example):
- Stage 2 citation: 1M rules.
- Src citation: odd IDs.
- Dst citation: even IDs.
- Intersection is empty.
- Galloping merge walks ALL 1M elements of both slices to prove
  empty intersection.
- `next()` returns `None` after O(N) work.
- The 65-iteration loop bound doesn't help because the bound is on
  output, not on the merge's internal work.

**This is the same DoS amplification AGY r2 #10 originally flagged**,
just hidden one layer deeper in the merge implementation. v3.2 did
not close it.

**Required fix path**:
- Specify a per-`next()` work budget (max comparisons / max steps),
  with the merge giving up and reporting overflow when exceeded.
- Combined with B1's commit-reject, this becomes: commit-reject
  configs whose merge-work envelope can exceed N comparisons per
  packet.

### B3: §7.2 push-down propagation contradicts itself (Codex #3)

§7.2 pseudocode comments say:
- "if S currently has a longer-prefix entry → leave alone"
- "INHERIT the parent's coverage into every slot of the child stride"

These contradict. Worked counter-example (Codex #3):
- Book A covers `10.0.0.0/16`.
- Book B covers `10.0.1.0/24`.
- Address `10.0.1.5` must cite BOTH A and B.
- Under "leave alone": the /24 slot gets B's coverage; A's coverage
  is dropped from this slot.
- Result: `10.0.1.5` cites only B, missing A. Classical LPM
  semantics violated.

**Required fix**: shortest-to-longest build order; each child slot
is `parent_coverage ∪ child_contributions`, deduped and sorted.
"Leave alone" is wrong; "union" is required.

### B4: §6.2 Vec<u8> arena is unsound AND leaks memory (Codex #5, AGY #3)

Two independent defects:

1. **Alignment UB**: `Vec<u8>` is byte-aligned; reinterpreting an
   arbitrary byte offset as `&[Node]` (where `Node` has 4-byte or
   8-byte alignment) is immediate UB.
2. **Memory leak**: If `Node` contains `Arc<[u32]>` (the citation
   slices), `Vec<u8>` only frees the raw bytes on drop. The Arc
   refcounts in the buffer are NEVER decremented → every
   `Arc<[u32]>` leaks on snapshot replacement.

**Required fix**: `Vec<Node>` (typed, not bytes); offsets are in
`Node` units, not bytes; Rust's drop glue walks the arena and drops
the Arcs correctly.

### B5: §6.3 LpmLeaf size is 24B per slot, not 8B (Codex #7, AGY #4)

`Arc<[T]>` is a fat pointer (16 B: ptr + len). With the 1-byte
discriminant + 7-byte alignment padding, `LpmLeaf` is 24 B per slot.

At a DIR-24-8 level-2 stride table with 2^24 slots:
- Plan §4 estimate: 70 MiB per LPM.
- Actual: 16M × 24 B = **384 MiB per LPM**.
- With separate src + dst LPMs: 768 MiB per snapshot just for
  level-2 v4 tables.

This is a memory-budget hit. Per user override the budget is
relaxed, so it's not a kill on memory grounds — but the cache/TLB
pressure tripled vs the 8 B claim is real. Working-set per LPM
lookup spans 24 cache lines (24 B + 8 B sentinel + ...) instead of
8 cache lines.

**Required fix** (AGY #4 + Codex #7 converge): `Multi(u32)` indexes
a central `Vec<Arc<[u32]>>` pool. Tagged enum then fits in 8 B
(discriminant + u32 + padding). Pool indirection costs one extra
pointer chase per `Multi` slot but the slot itself stays cache-line
friendly.

### B6: §8 SmallVec allocates above inline cap (Codex #8)

`SmallVec<[&'a [u32]; 8]>` claimed allocation-free. But: if
`candidate_slices` returns > 8 slices for a phase, SmallVec spills
to heap → hot-path Vec allocation.

**Required fix**: enforce `≤ 8 candidate slices per phase` at build
time, or use a non-spilling `ArrayVec`/fixed array with hard-reject
on overflow.

### B7: §8 MatchAny union semantics under-specified (Codex #9)

§8 says merge is `Stage2 ∩ Src ∩ Dst`, then "unioned with MatchAny
channels". Ordering and dedupe semantics are not specified, so
implementer freedom can produce different correctness behaviors.
With B1 + B2 in mind, the MatchAny union compounds the candidate
count which can push past `STAGE4_BUFFER_SIZE`.

**Required fix**: define ONE sorted, unique local-rule stream per
phase. MatchAny-side rules must be intersected with the constrained
opposite side and Stage 2, then merged + deduped before consuming
scratch.

### B8: §10 vs §3 Step-1 v6 scope contradiction (Codex #10)

§3 row #5 says "bounded multibit trie" is in v3.2 scope. §10 says
Step 1 includes "stub for v6". These contradict.

**Required fix**: choose one. Either Step 1 ships bounded v6
(growing Step 1 scope), or §3 explicitly defers v6 arena to Sub-PR F
and Step 1 is v4-only-with-v6-stub.

### B9: §6.4 vs §8 fallback signature contradiction (Codex #12)

`galloping_merge_evaluate` returns `PolicyEvaluationResult` (default
on miss). §8's `evaluate_phase` is called as if returning
`Option<...>` to allow zone-pair → global fallback. With the
default-on-miss signature, global fallback NEVER fires.

**Required fix**: `evaluate_phase` returns `Option<...>`; only the
top-level returns the default action after both phases fail.

### B10: §7.2 push-down build-time blowup with Multi books (AGY #5)

If the parent set is `Multi(Arc<[u32]>)` with 10K book_ids and gets
propagated to 256K stride slots via push-down, that's 2.6B
operations + 256K Arc allocations per snapshot build. This is a
config-apply latency bomb (potentially minutes per commit on
pathological configs).

**Required fix** (AGY #5): use PseudoBook resolution to ensure every
trie slot contains at most one `u32` (real BookId or PseudoBookId).
This collapses `LpmLeaf::Multi` entirely — every slot is `u32`,
push-down is O(1) copy. AGY's proposal is materially better than
v3.2's current design.

## Convergence summary

| Finding | SMR r1 | Codex r1 | AGY r1 | Convergent severity |
|---------|--------|----------|--------|---------------------|
| §6.4 silent truncation security bypass | MISSED | BLOCKING #1 | BLOCKING #2 | BLOCKING |
| §6.4 hidden merge work | MISSED | BLOCKING #2 | BLOCKING #1 | BLOCKING |
| §6.2 Vec<u8> arena UB + leak | RAISED as O3 (open) | BLOCKING #5 | BLOCKING #3 | BLOCKING |
| §6.3 LpmLeaf 24B size | MISSED | MAJOR #7 | BLOCKING #4 | BLOCKING |
| §7.2 push-down contradiction | MISSED | BLOCKING #3 | (covered by #5) | BLOCKING |
| §7.2 push-down build blowup | MISSED | (overlaps) | BLOCKING #5 | BLOCKING |
| §8 SmallVec spill | MISSED | MAJOR #8 | (n/a) | MAJOR |
| §8 MatchAny union semantics | MISSED | MAJOR #9 | (n/a) | MAJOR |
| §10 vs §3 v6 scope | MISSED | MAJOR #10 | (n/a) | MAJOR |
| §6.4 vs §8 fallback signature | MISSED | MAJOR #12 | (n/a) | MAJOR |
| §9 Junos hierarchy | RAISED as O7 (open) | MAJOR #11 | MINOR #7 | MAJOR |
| §6.1 LpmLeafId per-side newtypes | RAISED as R1 | MAJOR #6 | MAJOR #6 | MAJOR |
| §6.4 dedup invariant | RAISED as R2 | (covered by B7) | (covered) | MAJOR |
| §10 policy/ module move | RAISED as R3 | (out of scope of Codex) | (n/a) | MINOR |

3-of-3 verdict: **PLAN-NEEDS-MAJOR**. Multiple BLOCKING items not
anticipated by SMR r1. Multiple defects that go beyond
documentation cleanup — they require structural changes to §6.2
(typed arena), §6.3 (Multi(u32) pool indirection or AGY's PseudoBook
collapse), §6.4 (commit-reject vs silent-skip semantics), §7.2
(union-on-build with sorted order, not "leave alone"), §8
(allocation-free contract enforcement).

## Reflection on the iteration

This is the 6th plan-review round on the architectural axis
(#1609 v1-v3.1 across 5 rounds + #1623 v3.2 r1 here). The user
contract explicitly says "do NOT spawn v4 without user authorization"
after the 3rd kill on #1609 — but #1623 was the user-authorized
follow-up after that escalation. So this v3.2 r1 NEEDS-MAJOR is
properly a 4th major-iteration kill within the post-escalation
authorization.

The architectural axis (Multi-Book LPM + MatchAny side-channels +
two-phase eval + per-side LPMs) remains sound across all 6 rounds.
The design surface depth is the problem — each round closes some
findings but surfaces new ones at one level deeper:

- v1: memory bomb
- v2: 6 fatals (cross-side ID, Stage 4 overflow, K_bucket cap, ...)
- v3: 5 majors
- v3.1: 13 issues + new critical security finding
- v3.2: 10 BLOCKING+MAJOR including: silent truncation is worse than
  unbounded scan, hidden merge work, Vec<u8> arena UB+leak, LpmLeaf
  size 3× claimed, push-down contradicts itself

The right answer per the v3.1 r7 SMR recommendation is now even
clearer: **Path B — STAGED Step 1 minimal**. Specifically, the
SMR r7 wording:

> drastically narrow Step 1 scope to JUST adding the parallel
> `prefixes_v4/v6: Arc<[Prefix]>` field on BookEntry + PolicyRule,
> plus the `PrefixSetV{4,6}::iter_prefixes` API. NO LPM yet. NO
> PseudoBooks. NO feature flag. Pure preparatory work that the
> full Step 1 will build on. File a follow-up issue for the actual
> Multi-Book LPM primitive. This is a v3.2 scope drop, not a v3.2
> patch.

#1609 step-1 already shipped the BookEntry parallel-prefix
scaffolding (PR #1624 d339b69f8). The next narrow step is the
parallel-prefix on PolicyRule (v3.2 §6.5 / AGY r2 #1) — without
any LPM, PseudoBook, or feature flag. That's a 5-LOC-per-rule
addition + tests, mechanically reviewable, no surface depth issues.

## Recommendation

**PLAN-NEEDS-MAJOR**. Three viable paths from here:

**Path A — v3.3 + r2** (4 hours): write v3.3 incorporating all 10
BLOCKING+MAJOR findings. Specifically:
- §6.2: typed `Vec<Node>` arena.
- §6.3: PseudoBook collapse (AGY #5) — every slot is `u32`. No
  Multi variant. No Arc in slots.
- §6.4: commit-time hard-reject on configs that could overflow the
  merge envelope; or explicit unsafe-opt-in mode.
- §7.2: shortest-to-longest build; union not leave-alone.
- §8: ArrayVec with build-time bound; Option<...> phase signature.
- §6.1: distinct `SrcLpmLeafId` / `DstLpmLeafId` newtypes.
- §9: `set security policies global lookup-type` instead of
  `set chassis cluster cos policy lookup`.
- §10 + §3: align Step 1 v6 scope.

Risk: another round may surface more issues (the iteration history
shows each round finds deeper defects). 6 rounds with no convergence
is the strongest signal yet that the planning approach is
under-resolving the design surface.

**Path B — STAGED Step 1 minimal**: ship the §6.5 parallel-prefix
on PolicyRule (the AGY r2 #1 simplification) RIGHT NOW. No LPM, no
feature flag, no Stage 2/3/4. Pure mechanical addition mirroring
the #1609 Step 1 BookEntry shape onto PolicyRule. Then file a fresh
issue for the LPM primitive that starts from the v3.2 r1 closure
list as its v1 plan. This is the narrowest possible step that
unblocks future LPM work without re-entering the v3.2 plan-review
churn.

**Path C — PLAN-KILLED with escalation per user contract**: this is
the 4th major-iteration kill since the original #1609 v3 escalation.
The architectural axis is sound but the planning bandwidth (6
rounds × ~3 hours each = ~18 hours) is structurally not closing the
design surface. Escalate to user for path selection.

## Recommended path

**Path B + Path A in parallel**:

1. **Path B (this PR)**: STAGED — ship the §6.5 PolicyRule
   parallel-prefix scaffolding now (~50 LOC + tests). Single-commit
   PR, narrow scope, no v3.2 design dependency. Closes the AGY r2 #1
   simplification.
2. **Path A (this issue, deferred)**: v3.3 plan rewrite addressing
   all 10 BLOCKING+MAJOR findings. NOT in this PR. Future plan-review
   round once the v3.3 spec lands.

This Path B+A combo gets the AGY r2 #1 simplification shipped
(useful for future LPM build) while parking the larger design
work for a fresh v3.3 plan that addresses the convergent findings.

Per user contract on third kill: this is now the 4th
major-iteration kill on the axis. **Escalating to user for
direction**: Path A (write v3.3 now), Path B (ship parallel-prefix
only), Path C (PLAN-KILL hard), or Path A+B in parallel.

My recommendation, if I had to pick: **Path A+B**. Ship Path B as
the v3.2-scope-drop STAGED PR; defer Path A v3.3 to a separate
plan-review iteration with the user's explicit direction.
