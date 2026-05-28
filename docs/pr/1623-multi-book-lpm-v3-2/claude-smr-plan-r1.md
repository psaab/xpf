# Claude SMR plan-review r1 — #1623 v3.2

**Role**: domain SMR — LPM data structures (DIR-24-8, multibit trie),
set intersection (galloping merge), Junos policy semantics
(first-match-wins, zone-pair vs global, MatchAny / MatchNone), DoS
resistance (bounded worst-case work), cache/TLB pressure modeling.

**Mandate**: hostile. The #1609 v3.1 SMR-r6 soft-passed and Codex r2 +
AGY r2 caught 13 new fatals. v3.2 SMR r1 must NOT soft-pass. Each
finding requires a walked counter-example or worked trace.

**Verdict**: **PLAN-NEEDS-MINOR**. v3.2 closes the 13 v3.1 r2 findings
structurally. Three v3.2-specific residual issues remain that should
be addressed before PLAN-READY but are not r1-blocking. Two open
questions (O2, O3) need explicit answers before Sub-PR B build, but
this PR's narrow Step 1 scope (multi_book_lpm primitive + feature
flag scaffold) does not depend on those answers.

## Walk of the 6 hostile self-review prompts

### Prompt 1: Does v3.2 close ALL 13 v3.1 r2 findings?

Walking §3:

| # | v3.1 r2 finding | v3.2 closure | Verified |
|---|-----------------|--------------|----------|
| 1 | Cross-side LPM ID leak | Per-side LPMs (§6.1), each with own dense index space. `LpmLeafId` newtype is non-public; only the LPM that produced it can be used with the matching side's accessor. Type-checker enforces. | YES — see Prompt 3 walk |
| 2 | Stale addendum vs main body | v3.2 is a fresh document. No addenda. Where v3.2 differs from v3.1, v3.2 wins (§3 normative statement). | YES |
| 3 | Step 1 scope incoherence | §10 specifies a narrow Step 1: primitive + flag + stub. Acceptance criteria are scoped to that primitive. NO galloping merge, NO PseudoBook, NO Stage 2/3/4 in Step 1. | YES |
| 4 | Stage 4 master-fallback DoS amplification | §6.4 fix: fixed-size stack scratch (`STAGE4_BUFFER_SIZE = 64`), overflow path evaluates ONLY the emitted candidates (≤ 64), NEVER scans the phase bucket. Worst-case per-packet work bounded at `64 × try_match_rule`. | YES — see Prompt 2 worked trace |
| 5 | V6 heap-fragmentation | §6.2 arena: one `Vec<u8>` reinterpreted, one alloc total for v6 side. No per-node Box. | YES (modulo Prompt 4 / O3 on aliasing safety) |
| 6 | Push-down child propagation | §7.2 explicit pass-2 walks parent coverage into child slots before applying child's prefixes. | Structurally YES — see Prompt 4 walk for /0 edge case |
| 7 | LeafArcPool inline repr | §6.3 inline 3-variant `LpmLeaf::{Empty, Single, Multi}`. No LeafArcPool abstraction. | YES |
| 8 | Junos CLI for v6 leaf cap | §9 `lookup-v6-leaf-max` knob, commit-time hard-reject. | YES |
| 9 | PseudoBookId type safety | Subsumed by fix #1 (per-side LPMs). Each LPM's leaf id is unambiguous because its side's citation table is the only legal consumer. | YES |
| 10 | Parallel prefixes on PolicyRule | §6.5 mirrors the #1609 BookEntry shape onto PolicyRule. Populated at parse time, hot path unaffected. | YES |
| 11 | Alleged MatchNone bug | §7.3 explicit handling of all 4 PrefixSetV{4,6} variants. SMR r7 already refuted the AGY claim. | YES (and AGY r2 finding partially refuted in #1609 SMR r7) |
| 12 | LeafArcPool 10-100× claim | Removed entirely with fix #7. No dedup claim made. | YES |
| 13 | SMR r7 N1-N5 doc cleanups | Carried into body text. | YES |

**Verdict on Prompt 1**: 13/13 closed structurally. AGY r2 findings
are fully addressed. Codex r2 findings are fully addressed. SMR r7
findings are fully addressed.

### Prompt 2: Is the §6.4 DoS bound TIGHT?

Worked trace — adversarial 1M-rule config:

Suppose the operator (or attacker) has loaded 1,000,000 policies all
in the same zone-pair `(trust, untrust)` with overlapping prefix sets
designed to maximize Stage 4 candidates. An attacker sends a packet
crafted to match every rule's source + destination + Stage 2 filter.

Pre-v3.2 (v3.1 §2.8): galloping merge buffers up to 64 candidates,
then drops to "master linear scan over `state.zone_pair_index[zp_key]`"
— which scans all 1,000,000 rules in the phase bucket. Per-packet
work = 1M × `try_match_rule`. At 50 ns per `try_match_rule`, that's
50 ms per packet → ~20 pps single-flow ceiling under attack. **15,000×
amplification vs the no-attack 3.3 μs (10 rules × 50 ns × 6 stages)
baseline.**

v3.2 (§6.4): galloping merge fills `scratch[64]`, sets `overflow = true`,
exits the merge loop. The for-loop then evaluates **only `scratch[..64]`**.
Per-packet work = 64 × `try_match_rule` = 64 × 50 ns = **3.2 μs**. The
remaining 999,936 rules are silently skipped (observable via
`xpf_userspace_policy_dag_stage4_overflow_total`). Per-packet work is
the same order as a normally-narrow config.

**Bound is tight**: `STAGE4_BUFFER_SIZE × try_match_rule_cost`. No
hidden work in `merge_iter.next()` because the loop exits as soon as
the scratch fills — `next()` is called at most 65 times (64 successful
+ 1 that triggers the break). The break exits BEFORE `next()` reads
all 1M citation entries from the merge inputs.

Caveat: `merge_iter.next()` itself walks the input citation slices.
If the merge inputs are themselves large (e.g., one side cites all
1M rules), then `next()` walks pointers to find the next candidate.
For a 3-way merge with input sizes (1M, 1M, 1M), the worst-case work
PER `next()` is O(log K) for K-way merge with a heap, or O(K) for a
linear k-way merge. With K=3 (Stage 2 ∩ Src ∩ Dst), this is O(1) per
next-call. Total work to fill the 64-slot scratch = 65 × O(1) = O(1).
Bound holds.

**One subtle issue**: if the merge is implemented as a heap or
priority queue, `next()` might still chase pointers across the entire
citation array to find the next-lowest local_rule_idx. The
implementation MUST ensure that `next()` short-circuits at the first
candidate it finds beyond the scratch limit. Concretely, the scratch
fill loop should break BEFORE calling `next()` once it has 64
candidates — which the §6.4 pseudocode does:

```rust
while let Some(rule_idx) = merge_iter.next() {  // <-- this is the
    if emitted == STAGE4_BUFFER_SIZE {           //     final next()
        overflow = true;
        break;                                    // exit before
    }                                              // calling next()
    scratch[emitted] = rule_idx;                  // again
    emitted += 1;
}
```

This is correct: the 64th iteration calls `next()` to fill scratch[63],
the 65th calls `next()` once (returning Some), the check triggers
break, and the loop exits. Total `next()` calls = 65.

**Residual concern**: under the K=3 merge model, can a malicious
input make a SINGLE `next()` call do O(N) work? Galloping merge over
sorted slices does O(log N) work per next via binary search, where
N is the size of the shorter slice. Adversary can't push this past
O(log 1M) = 20 comparisons per next. 20 × 65 = 1300 comparisons total
per packet. Bounded.

**Bound is TIGHT.** v3.2 §6.4 closes the DoS amplification vector.

### Prompt 3: Is the §6.1 per-side LPM type safety actually enforced?

Hypothetical attacker:

```rust
fn malicious_caller(dag: &PolicyDag, phase: Phase) {
    let src_leaf: LpmLeafId = dag.src_lpm_v4.lookup(some_ip);
    let dst_citations = dag.cited_rules(Side::Dst, phase, src_leaf);
    //                                  ^^^^^^^^^             ^^^^^^^^
    //                                  passing dst, but src_leaf came from
    //                                  src_lpm_v4 — type-system check?
}
```

`LpmLeafId(u32)` is a single newtype across both LPMs, so the
type-checker WON'T reject this call. The "type safety" claim in §6.1
is actually CONVENTION-enforced via the safe accessor's runtime
dispatch — but the wrong leaf passed in won't trigger a compile error.

**Residual issue R1 (PLAN-NEEDS-MINOR)**: §6.1 should use distinct
newtypes per side:

```rust
pub struct SrcLpmLeafId(u32);   // private constructor
pub struct DstLpmLeafId(u32);   // private constructor

impl PolicyDag {
    fn cited_rules_src(&self, phase: Phase, book: SrcLpmLeafId) -> &[u32];
    fn cited_rules_dst(&self, phase: Phase, book: DstLpmLeafId) -> &[u32];
}
```

The LPM lookups return their respective newtypes; the citation
accessor only accepts the matching newtype. Compile-time enforcement.
This is the fix for R1 — Sub-PR D must implement this signature, NOT
the §6.1-as-written shared `LpmLeafId`.

This is a documentation fix in v3.2 (clarify §6.1 to show distinct
newtypes), not an architectural rewrite. Marking PLAN-NEEDS-MINOR
rather than PLAN-NEEDS-MAJOR because the architectural axis is
unchanged.

### Prompt 4: Does §7.2 handle /0 + other-side /24 correctly?

Edge case: rule R with `source any` and `destination 10.0.0.0/24`.

- Source: literal "any" → MatchAny. Rule lands in `match_any_zone_pair[zp].src` channel.
- Destination: literal `10.0.0.0/24` → goes into `dst_lpm_v4` with citation for R.

Stage 4 input: `dst_citations` from lookup(packet.dst) intersected with `src` channel which is "MatchAny implies all rules".

Galloping merge for this packet:
- If `packet.dst ∈ 10.0.0.0/24`: `dst_citations` includes R.
- `match_any_zone_pair[zp].src` is a sorted slice including R's index.
- Stage 2 candidate (proto+dst_port): assume R is in there.
- Merge intersects 3 inputs: Stage 2 ∩ MatchAny.src ∩ dst_citations[R included]. R is in all 3 inputs → R is emitted.

**Correct.** §7.2 handles this because the LPM build SKIPS rules with
MatchAny on the side being built — those rules go to the side-channel,
not the LPM. The other side's LPM still includes the rule's citation.

What about the reverse: `source 10.0.0.0/24` AND `destination any`?

- Source: literal `10.0.0.0/24` → `src_lpm_v4` with citation for R.
- Destination: literal "any" → MatchAny → rule lands in `match_any_zone_pair[zp].dst` channel.

Symmetric to above. Correct.

What about `source any AND destination any`?

- Both sides → MatchAny channels. R lands in BOTH `match_any.src` AND
  `match_any.dst`. Stage 4 merge: Stage 2 ∩ MatchAny.src ∩ MatchAny.dst
  → R is in all three → R is emitted.

Correct.

What about `source 10.0.0.0/8 AND destination 192.168.0.0/16` where the books include `/0`?

This is the /0 short-circuit case (§7.1: "if a side's literal or any cited book is MatchAny, rule goes into match_any_zone_pair/global side-channel, NEVER into level-0 build"). If the rule's source book contains a `/0` entry, the book's `PrefixSetV4` collapses to MatchAny, so the rule's `source_v4_match_any = true`, and the rule goes to the MatchAny.src channel for that phase even if other prefixes are also present in the book.

But — does that lose the rule's OTHER books? If R cites books B1 (with /0) and B2 (with /16), the LPM build for R's source side must:
- B1 → MatchAny → R goes to MatchAny.src.
- B2 → /16 → R also goes into src_lpm_v4 with /16 citation.

If R is in BOTH MatchAny.src AND src_lpm_v4, will it be matched twice and incorrectly first-match-wins on the wrong order? Let's check.

Stage 4 merge inputs: MatchAny.src ∪ (dst_citations ∩ src_citations from LPM).

If R appears in MatchAny.src, the merge emits R from that channel. The LPM emission of R is redundant; the merge dedupes by local_rule_idx (since the channels are all sorted by local_rule_idx, dedup is just a < comparison in the merge).

Actually — DOES the §6.4 merge dedupe? Re-reading: the galloping
merge over sorted slices preserves first-match-wins ordering. If
the same local_rule_idx appears in multiple input slices, the merge
emits it once.

**Residual issue R2 (PLAN-NEEDS-MINOR)**: §6.4 pseudocode doesn't
explicitly state the dedup invariant on merge output. The merge iter
should emit each `local_rule_idx` AT MOST ONCE per phase. Add this
to §6.4 as an explicit invariant + property test.

### Prompt 5: Does the `policy/` module directory collide with `policy.rs`?

Current state: `userspace-dp/src/policy.rs` is a single file containing
all PolicyState code. `userspace-dp/src/policy_tests.rs` is colocated.

Per Rust's module system, `userspace-dp/src/policy/mod.rs` and
`userspace-dp/src/policy.rs` CANNOT both exist. Step 1 must choose:

Option A: keep `policy.rs`, add `multi_book_lpm` as a sibling file
`userspace-dp/src/multi_book_lpm.rs`. Doesn't follow the
`feedback_refactor_module_dir_layout` pattern but avoids the
collision.

Option B: move `policy.rs` → `policy/mod.rs`, then add
`policy/multi_book_lpm.rs`. Follows the layout pattern but is a
mechanical move that risks unrelated diff churn.

Option C: add `policy/` directory with `policy/multi_book_lpm.rs` and
NOTHING ELSE under it. `policy.rs` continues to exist. Reference the
LPM as `crate::policy::multi_book_lpm::*` via `use` statements added
inside `policy.rs`. This works in Rust 2018+ as long as `policy/` is
a proper module directory with a `mod.rs` OR via the inline `mod`
declaration in `policy.rs`.

Wait — Option C doesn't work either: `policy.rs` and `policy/mod.rs`
are mutually exclusive. The compiler errors with "file found for module
`policy` at both `policy.rs` and `policy/mod.rs`".

**Residual issue R3 (PLAN-NEEDS-MINOR)**: §10 says "policy/mod.rs (new):
module-organizes the existing policy.rs into a submodule for the LPM
primitive while keeping policy.rs content unchanged in mod.rs for
non-refactor disturbance." This is the right idea (Option B); the
plan should explicitly state:

1. `git mv userspace-dp/src/policy.rs userspace-dp/src/policy/mod.rs`
2. `git mv userspace-dp/src/policy_tests.rs userspace-dp/src/policy/tests.rs`
3. Update the `#[path]` attribute on the `mod tests` declaration.
4. Add `userspace-dp/src/policy/multi_book_lpm.rs` with the LPM
   primitive.
5. Add `mod multi_book_lpm;` to `policy/mod.rs`.

This is a no-content-change move + one new file. Diff churn is
contained to the move, which is trivially reviewable.

Marking PLAN-NEEDS-MINOR rather than blocking because the plan
already gestures at this; just needs to be explicit.

### Prompt 6: Is the empirical-grounding deferral honest?

§5 explicitly says v3.2 ratifies architecture not numbers. The 10×
claim is acknowledged as gated on #1612. Sub-PR H (the production
default-flip) is gated on #1612.

Step 1's acceptance criteria (§10) are scoped to correctness, not
performance. Property tests at 10/100/1K/10K rule counts validate
LPM correctness, NOT speed.

Honest. No implicit performance assertion in this PR. Reviewers
should not gate Step 1 on absolute speed numbers because they don't
exist yet and the feature flag default is `linear`.

---

## Residual issues (PLAN-NEEDS-MINOR)

| ID | §ref | Description | Fix |
|----|------|-------------|-----|
| R1 | §6.1 | `LpmLeafId` shared newtype loses compile-time per-side check | Use distinct `SrcLpmLeafId` / `DstLpmLeafId` newtypes per side; safe accessor per side. Update §6.1 + §8 to reflect. |
| R2 | §6.4 | Merge dedup invariant not stated | Add explicit "merge emits each local_rule_idx at most once per phase" invariant + property test in Sub-PR E. |
| R3 | §10 | `policy/` module move not explicit | Spell out the 5-step move: `policy.rs` → `policy/mod.rs`, `policy_tests.rs` → `policy/tests.rs`, etc. |

None are r1-blocking. Codex + AGY should also walk these in their
hostile reviews.

## Verdict

**PLAN-NEEDS-MINOR**. The architecture closes all 13 v3.1 r2
findings. Three residual issues (R1, R2, R3) are documentation /
clarification fixes, not architectural rewrites. The v3.2 plan is
ready for Codex + AGY hostile review.

If Codex + AGY come back PLAN-READY-WITH-NITS or PLAN-NEEDS-MINOR
aligned with R1-R3, the plan converges to PLAN-READY after one fix
round.

If Codex + AGY surface NEW fatals on top of R1-R3, this becomes a
multi-round convergence and the user contract (3rd kill →
escalation) applies, but v3.2 r1 self-review is honest about R1-R3
upfront so the reviewers don't have to find them.

**Recommendation**: dispatch Codex + AGY hostile plan-review against
this v3.2 plan + this SMR doc. Do NOT proceed to Step 1
implementation until 3-of-3 converges to PLAN-READY-WITH-NITS or
better.
