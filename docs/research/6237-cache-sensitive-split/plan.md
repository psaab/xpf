# #6237 — split `filter/engine/cache_sensitive.rs` by call-frequency domain

## 1. Status

**PLAN-DRAFT v1 — research + blast-radius only. No production code, no PR.**

Firsthand verdict: this is a **clean, behavior-preserving code-motion split**
with **no cross-domain function calls and no shared helper functions** — a
strong candidate to drive to merge. The one non-mechanical wrinkle is that
relative `use` prefixes shift by one `super::` (file→directory module), and
`filter/README.md` carries ~8 path references that must be repointed. The
`#5293` exhaustive-`FilterTerm`-destructure guard is the *only* `let FilterTerm {`
in the tree and moves intact into `rotation.rs`, preserving the anti-drift
invariant that makes physical separation safe.

The live design fork (surfaced by the issue's own embedded reviewer verdict):
**full 3-file split** vs **narrow to a rotation-only extraction**. Both are
defensible; see §10 open questions. Recommendation: land `rotation.rs` first
(largest, coldest, most-distinct region — the least-arguable win and the issue's
own acceptance ordering), then treat `cached_tx.rs` / `counter_capture.rs` as a
reviewable second step that is PLAN-KILL-able if it fragments the seed/replay
unit.

## 2. Issue framing

`userspace-dp/src/filter/engine/cache_sensitive.rs` (732 LOC; production ends at
line 570, tests 573-732) co-locates three regions with very different call
frequencies:

- **cached TX-result rebuild** (lines 17-138) — flow-cache-HIT / seed / mirror
  replay fast path.
- **input counter-descriptor capture** (lines 140-273) — seed-time `then count`
  handle capture, replayed on cache hits.
- **cold filter-rotation semantic comparison** (lines 276-570) — control-plane /
  worker-loop change detection deciding when cached per-session decisions are
  invalidated on a config rotation.

The file was born from #1546 (engine split) and deliberately co-located the
rebuild path with the comparison predicates so a contributor touching DSCP
semantics had to update both in one file. #5293 later replaced that soft
co-location guard with a **compile-time** one: `filter_term_semantics_match`
destructures `FilterTerm` exhaustively with no `..`, so a new field fails to
compile until classified. That stronger invariant is what now permits physical
separation without reviving the #1546 silent-drift failure mode.

## 3. Honest scope

This is a **modularity / readability split**, not a behavior change and not a
performance feature. The win:

- Separates three call-frequency domains that today share a file, so a reader /
  reviewer touching the cold rotation comparator is not wading through the
  hot-path cached rebuild, and vice-versa.
- Isolates the `#5293` compile-time guard and its comparator tests with the
  rotation logic they protect.

**PLAN-KILL is acceptable if** the split fragments a tight cohesive unit (the
cached-rebuild and counter-capture paths are both seed/replay-path descriptor
work — see §10 Q1) or if the shared-helper / import churn makes it net-negative.
This is not a duplicate of #1546 (the broad engine split) or #5293 (the
compile-time guard); it is a post-#1546 refinement *enabled by* #5293.

## 4. What is already shipped (do not re-litigate)

- **#5293** (`b43b16f44`) — `filter_term_semantics_match` derives from an
  exhaustive `FilterTerm` destructure (no `..`); all six `flex_*` fields are
  compared. Verified: this is the **only** `let FilterTerm {` in the entire
  `userspace-dp/src` tree.
- **#2544 / #2573** — cached TX rebuild accumulates modifiers across fall-through
  terms and pushes every matched `then count` term.
- **#3777** — input `then count` capture on cache hits with #2620 PBR
  count-ownership deferral.
- **#2400 / #2506 / #2622** — `*_constrained` / `*_except` flags compared in the
  rotation change detector (guarded by tests that move with `rotation.rs`).
- **#6350** (current `HEAD` `f6fd76043`) — removed 8 dead `FilterState` fields;
  touched `engine/mod.rs`, `tx_selection.rs`, `compiler.rs`, `filter/mod.rs`,
  `tests.rs`, README. **It did NOT touch `cache_sensitive.rs`.** The 8-symbol
  `pub(crate) use cache_sensitive::{...}` re-export block in `engine/mod.rs` is
  intact. This plan bases off `HEAD` and has no interaction with #6350's edits.

## 5. Concrete design

### 5.1 Target layout (file → directory module)

```
filter/engine/cache_sensitive.rs            (delete)
filter/engine/cache_sensitive/mod.rs        (new — facade: mod decls + doc + 8 re-exports)
filter/engine/cache_sensitive/cached_tx.rs        (domain 1)
filter/engine/cache_sensitive/counter_capture.rs  (domain 2)
filter/engine/cache_sensitive/rotation.rs         (domain 3 + comparator tests)
```

`engine/mod.rs` is **UNCHANGED**: `mod cache_sensitive;` now resolves to the
directory module, and its existing `pub(crate) use cache_sensitive::{...8...}`
re-export continues to resolve as long as `cache_sensitive/mod.rs` re-exports the
same 8 names (§6).

### 5.2 Function → file map (with visibility, attrs, LOC)

**`cached_tx.rs`** — domain 1, cached TX-result rebuild (~122 LOC, src 17-138):

| fn | vis | attr |
|----|-----|------|
| `evaluate_filter_ref_tx_selection_cached` | `pub(crate)` | — |
| `evaluate_filter_ref_tx_selection_cached_v4` | private | — |
| `merge_matched_cached_modifiers` | private | `#[inline]` |
| `evaluate_filter_ref_tx_selection_cached_v6` | private | — |

**`counter_capture.rs`** — domain 2, input counter-descriptor capture (~134 LOC,
src 140-273):

| fn | vis | attr |
|----|-----|------|
| `evaluate_interface_input_filter_counters_cached` | `pub(crate)` | — |
| `capture_input_filter_counters_v4` | private | `#[inline]` |
| `capture_input_filter_counters_v6` | private | `#[inline]` |

**`rotation.rs`** — domain 3, cold rotation semantic comparison + tests (~295 LOC
src 276-570, +160 LOC tests 573-732):

| fn | vis | attr |
|----|-----|------|
| `three_color_policer_semantics_match` | private | — |
| `filter_term_semantics_match` (**#5293 exhaustive destructure**) | private | — |
| `dscp_sensitive_filter_semantics_match` | private | — |
| `input_dscp_filter_family_changed` | private | — |
| `input_dscp_filter_families_changed` | `pub(crate)` | — |
| `interface_input_filter_has_dscp_match` | `pub(crate)` | — |
| `interface_output_filter_has_dscp_match` | `pub(crate)` | — |
| `input_per_packet_l4_filter_family_changed` | private | — |
| `input_per_packet_l4_filter_families_changed` | `pub(crate)` | — |
| `interface_input_filter_has_per_packet_l4_match` | `pub(crate)` | — |
| `interface_output_filter_has_per_packet_l4_match` | `pub(crate)` | — |
| `mod cache_sensitive_2400_tests` (comparator tests) | `#[cfg(test)]` | — |

### 5.3 Cross-domain calls — NONE

Verified by walking every call site:

- Domain 1 calls only `term_matches_v4/v6` (matching), `filter_log_match` (eval),
  and its own `merge_matched_cached_modifiers`.
- Domain 2 calls only `term_matches_v4/v6` (matching) and its own
  `capture_input_filter_counters_v4/v6`.
- Domain 3 calls only its own `filter_term_semantics_match` →
  `three_color_policer_semantics_match` / `dscp_sensitive_filter_semantics_match`.

No function in one domain calls a function defined in another. The three regions
are cleanly separable.

### 5.4 Shared helpers — NONE need to live in `mod.rs`

The only "shared" items are the two `pub(super)` **engine** helpers imported by
more than one domain:

- `super::matching::{term_matches_v4, term_matches_v6}` — used by domains 1 and 2.
- `super::eval::filter_log_match` — used by domain 1 only.

These are *imports*, not local helpers. Each submodule imports what it needs
independently (import duplication, not code duplication). **No helper function is
extracted into `mod.rs`.** Confirmed visibility: `term_matches_v4/v6`
(`matching.rs:178/322`) and `filter_log_match` (`eval.rs:544`) are all
`pub(super)` where `super = engine`, i.e. `pub(in engine)` — visible throughout
the entire `engine` subtree including `engine::cache_sensitive::{cached_tx,
counter_capture}`. **No visibility widening is required.**

### 5.5 The one non-mechanical change: `use`-prefix depth shift

Each new submodule sits one level deeper (`engine::cache_sensitive::<sub>` vs
today's `engine::cache_sensitive`), so every relative import gains one `super::`.
Function bodies are byte-identical; only the module-level `use` lines change:

| today (in `cache_sensitive.rs`, depth 3) | after (in each submodule, depth 4) | consumers |
|---|---|---|
| `use super::super::*;` | `use super::super::super::*;` | all three |
| `use super::eval::filter_log_match;` | `use super::super::eval::filter_log_match;` | `cached_tx.rs` |
| `use super::matching::{term_matches_v4, term_matches_v6};` | `use super::super::matching::{term_matches_v4, term_matches_v6};` | `cached_tx.rs`, `counter_capture.rs` |
| test module `use super::super::super::*;` | `use super::super::super::super::*;` | in `rotation.rs` |

The test module's `super::filter_term_semantics_match` reference is **unchanged**
(one `super::`): the tests move together with `filter_term_semantics_match` into
`rotation.rs`, so `super` from the test module still lands on `rotation`, and a
child test module retains access to its parent's private items. This is the
mechanism that keeps the comparator tests calling the private comparator without
widening its visibility.

### 5.6 `mod.rs` facade (new)

```rust
//! Cache-sensitive filter evaluation, split by call-frequency domain (#6237).
//! Facade over three submodules; re-exports the pub(crate) surface #1546/engine
//! consume. The #1546 co-location-for-anti-drift rationale is superseded by the
//! #5293 compile-time exhaustive FilterTerm destructure in rotation.rs.
mod cached_tx;
mod counter_capture;
mod rotation;

pub(crate) use cached_tx::evaluate_filter_ref_tx_selection_cached;
pub(crate) use counter_capture::evaluate_interface_input_filter_counters_cached;
pub(crate) use rotation::{
    input_dscp_filter_families_changed, input_per_packet_l4_filter_families_changed,
    interface_input_filter_has_dscp_match, interface_input_filter_has_per_packet_l4_match,
    interface_output_filter_has_dscp_match, interface_output_filter_has_per_packet_l4_match,
};
```

## 6. Public API preservation (facade re-exports)

Consumers reference these via the chain
`crate::filter::X` → `filter/mod.rs: pub(crate) use engine::*`
→ `engine/mod.rs: pub(crate) use cache_sensitive::{...}`. **No consumer names
`cache_sensitive::` directly** (verified by grep). The facade must therefore
re-export exactly these **8** `pub(crate)` symbols (unchanged names), and
`engine/mod.rs` needs no edit:

1. `evaluate_filter_ref_tx_selection_cached`  → `cached_tx`
2. `evaluate_interface_input_filter_counters_cached`  → `counter_capture`
3. `input_dscp_filter_families_changed`  → `rotation`
4. `input_per_packet_l4_filter_families_changed`  → `rotation`
5. `interface_input_filter_has_dscp_match`  → `rotation`
6. `interface_input_filter_has_per_packet_l4_match`  → `rotation`
7. `interface_output_filter_has_dscp_match`  → `rotation`
8. `interface_output_filter_has_per_packet_l4_match`  → `rotation`

Confirmed consumers (all resolve through the re-export, untouched by the split):

- `afxdp/tx/cos_classify.rs` (`evaluate_filter_ref_tx_selection_cached`,
  ×3 call sites)
- `afxdp/poll_descriptor/filter.rs`
  (`evaluate_interface_input_filter_counters_cached`,
  `interface_input_filter_has_dscp_match`,
  `interface_input_filter_has_per_packet_l4_match`)
- `afxdp/flow_cache.rs` (`interface_input_filter_has_dscp_match`,
  `interface_output_filter_has_dscp_match`,
  `interface_input_filter_has_per_packet_l4_match`,
  `interface_output_filter_has_per_packet_l4_match`)
- `afxdp/worker/loop_body/mod.rs` (`input_dscp_filter_families_changed`,
  `input_per_packet_l4_filter_families_changed`)
- `filter/tests.rs` (via `use super::*` = `filter::*`; ~many assertions)

## 7. Hidden invariants (the crux)

1. **#5293 exhaustive `FilterTerm` destructure MUST stay exhaustive in
   `rotation.rs`.** It is the sole `let FilterTerm {` in the tree; moving it must
   copy it verbatim (no `..` slips in). This is the anti-drift guard that
   *replaces* the #1546 physical co-location — so the drift protection the
   original co-location provided **survives the move as a compile-time property,
   not a "same-file" property**. Confirmed: after the split, adding a
   `FilterTerm` field still fails to compile in `rotation.rs` until classified,
   exactly as today.
2. **The cache-rebuild ↔ invalidation drift guard is now compile-time.** Pre-#5293
   it relied on co-location + reviewer diligence; the split does not weaken it
   because the exhaustive-match property is independent of file boundaries.
3. **`#[inline]` attributes preserved verbatim** on
   `merge_matched_cached_modifiers`, `capture_input_filter_counters_v4/v6`.
   Within a single crate, `#[inline]` MIR is exported for cross-CGU inlining, so a
   module move does **not** change inlinability — but the attribute must not be
   dropped in the copy.
4. **Concrete free functions, no new abstraction** (issue Class-B contract):
   no traits, dynamic dispatch, locks, atomics, or bounds checks introduced.
   `Arc` / counter-handle identity, allocation-free packet behavior, and the
   `SmallVec` no-spill expectation are preserved because the bodies are copied
   unchanged.
5. **`pub(crate)` visibility of the 8 exported fns is retained** so the facade can
   re-export them; private helpers stay private (no widening).

## 8. Risk table

| Risk | Likelihood | Severity | Mitigation |
|------|-----------|----------|-----------|
| Behavior change (logic) | Very low | High | Pure copy of bodies; `cargo test` full suite must be green with zero logic diff. |
| `#5293` guard weakened (`..` slips in, or field dropped) | Low | High | Diff-review the destructure verbatim; the #5293 tests move with it and a revert must still RED. |
| Import-prefix mistake (wrong `super::` depth) | Medium | Low | Compile-time failure; caught immediately by `cargo build`. |
| Consumer breakage | Very low | High | No consumer names `cache_sensitive::`; facade re-exports identical 8 names; `engine/mod.rs` untouched. |
| `#[inline]`/codegen regression on cached rebuild | Very low | Med | Same-crate move; MIR-inlining unaffected. Issue asks for asm/bench proof — see §10 Q2. |
| Stale doc path references | **High (certain)** | Low | `filter/README.md` repoint (§9); part of the same work item. |
| Split fragments a cohesive seed/replay unit | Medium | Med (design) | Phase rotation first; §10 Q1 invites PLAN-KILL of the cached_tx/counter_capture sub-split. |

The behavioral crux is **preserving the drift guard**, and it survives because
the guard is the compile-time exhaustive match, not the shared file.

## 9. Documentation obligations (part of the same work item)

`filter/README.md` references the target file / comparator by path in ~8 places
that MUST be repointed:

- `cache_sensitive.rs` cached TX-selection ref (line ~125) → `cached_tx.rs`.
- `filter_term_semantics_match (engine/cache_sensitive.rs)` (lines ~136, ~504,
  ~610, ~635, ~882-883, ~901) → `engine/cache_sensitive/rotation.rs`.
- Path `userspace-dp/src/filter/engine/cache_sensitive.rs` (line ~866) → the
  facade dir / `rotation.rs` as appropriate.

The new `mod.rs` facade doc-comment should carry the module-responsibility note
and record that the #1546 co-location rationale is superseded by the #5293
compile-time guard. The old file-header block (lines 1-11) is rewritten as the
facade doc rather than copied into a submodule.

## 10. Open questions (each PLAN-KILL-invitable)

1. **Full 3-file split vs narrow rotation-only extraction.** The issue's own
   embedded reviewer verdict is *"NARROW to a rotation extraction"* — arguing
   `cached_tx` and `counter_capture` are both seed/replay-path descriptor work
   and splitting them into two ~130-LOC files fragments a cohesive unit. Do we
   ship all three, or extract `rotation.rs` only and leave `cached_tx` +
   `counter_capture` co-located (a ~256-LOC file)? **PLAN-KILL the sub-split** if
   reviewers judge the seed-path unit is cohesive.
2. **Asm/benchmark evidence bar.** The issue's acceptance criteria demand
   optimized-assembly + a cached-rebuild benchmark showing "no indirect call,
   heap allocation, lock, atomic, or >1% regression." A same-crate module move
   cannot change codegen (namespace boundary ≠ CGU/section boundary; `#[inline]`
   MIR still exported). Is generating that asm/bench artifact in scope, or does
   "module boundary is a namespace boundary" suffice? **PLAN-KILL / de-scope** the
   asm bar if it is disproportionate for a pure namespace move.
3. **Is #5293 truly a sufficient replacement for co-location?** The embedded
   reviewer explicitly disputes this: #5293 proves *syntactic* exhaustiveness, not
   that a new field is *classified correctly* across decline / re-eval / rebuild /
   rotation. Does the split need to add the reviewer's proposed
   "cache-sensitivity contract matrix" test before separation is safe, or is that
   a separate hardening issue? **PLAN-KILL** if the matrix is a precondition.
4. **README churn worth it?** Repointing ~8 doc references is certain work for a
   pure modularity win. Does that argue for keeping one file (net-negative), or is
   it routine doc upkeep?
5. **Import strategy.** Each submodule re-imports `super::super::super::*` plus the
   two `pub(super)` engine helpers, vs. `mod.rs` re-exporting a curated prelude the
   submodules pull with `use super::*`. Which keeps the diff most byte-faithful and
   the least surprising to a reviewer? (Recommendation: direct ancestor imports —
   fewest moving parts, mirrors current behavior.)
6. **Landing order.** Issue mandates rotation first, then counter capture, then
   cached TX — as three PRs or one? A single behavior-preserving PR is simplest to
   review against the "no logic change" bar; three PRs match the issue text but
   triple the parent-RED / smoke overhead for a pure move.

## 11. Out of scope

- Any change to filter matching / rebuild / rotation **logic** (this is code
  motion only).
- Adding the reviewer-proposed cache-sensitivity contract matrix test (Q3) —
  track separately if wanted.
- Touching `engine/mod.rs`, `filter/mod.rs`, or any consumer file (the facade
  makes them untouched).
- Reopening the #1546 evaluator/compiler split or the #5293 guard itself.
- Performance work / new benchmarks beyond whatever asm/bench evidence Q2
  resolves to require.

## 12. Test plan

- **`make test` (full Go + Rust cargo suite)** — a pure split must be green with
  zero logic change. Specifically the filter cache, rotation, DSCP, flex-match,
  counter, and TX-selection tests in `filter/tests.rs` +
  `afxdp/tx/cos_classify_tests.rs` + `afxdp/flow_cache_tests.rs`.
- **#5293 destructure tests** (`cache_sensitive_2400_tests`, moved into
  `rotation.rs`) — `flex_field_change_is_not_cache_equal`,
  `unscoped_vs_all_malformed_*` must pass, and a revert of the `flex_*` / `_constrained`
  comparisons must still RED after the move (proves the guard binds in its new home).
- **Parent-RED merge gate** — neutralize one field comparison in the moved
  `filter_term_semantics_match` and assert a specific test flips RED (proves the
  moved comparator is the enforced path).
- **Loss-cluster deploy smoke** (`make cluster-deploy` + `test-failover`,
  v4+v6) — `cache_sensitive` feeds the hot forwarding path (cos_classify,
  flow_cache, poll_descriptor), so a deploy + sustained iperf3 confirms no
  functional regression even though the change is behavior-preserving. Serialize
  through one agent; deploy wipes CoS (re-apply).
- **Codegen check (conditional on Q2)** — if the asm bar stays, `cargo asm` /
  symbol inspection on `evaluate_filter_ref_tx_selection_cached` before/after to
  show identical inlining and no new indirect call.
