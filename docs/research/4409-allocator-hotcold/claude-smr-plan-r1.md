# Claude SMR — hostile plan review r1 — #4409(b)

Reviewer stance: adversarial. I tried to break the plan on the four invariants
and on whether it should exist at all. I independently re-read the 1797-LOC
`allocator.rs`, the callers, and verified the Rust visibility reasoning against
the source and against the language rules. Below is what survived and what did
not.

## Verdict

**PLAN-READY-WITH-NITS**, escalating one non-technical decision to the human.
The design is correct and the four invariants hold under scrutiny. The nits are
real but small (build-cleanliness + gate right-sizing). The ONE thing I could not
resolve as a reviewer is a value/taste call, not a correctness defect — I flag it
explicitly rather than soft-pass it (see "The honest kill argument").

## Claim-by-claim hostile verification

### Invariant #2 (visibility crux) — the reasoning is CORRECT. Verified.
This was the claim most likely to be wrong, so I attacked it hardest.

- **Descendant reads ancestor privates:** Rust's rule is "a private item may be
  accessed by the current module and its descendants." `nat::allocator::gc` is a
  descendant of `nat::allocator`, so it can call the private `free_translated_port`
  and read the private fields `PortAllocator.shared`, `PortAllocatorShared.live`,
  and the `#[cfg(test)] gc_lock_acquisitions` with NO annotation. Confirmed against
  the actual field/method privacy in the source (lines 597-622, 633-637, 841-850).
  The plan's "zero field widening" is real.
- **`pub(super)` width:** for an item in `crate::nat::allocator::gc`,
  `pub(super)` = `pub(in crate::nat::allocator)` → visible to `nat::allocator` and
  its descendants ONLY, NOT to `nat::source`/`nat::status`/`nat::tests_*`. And the
  3 methods are private-in-parent TODAY (visible to exactly `nat::allocator` + its
  descendants). So the bump adds visibility to precisely one module — `gc`, where
  the code now lives. **No external surface is gained.** The plan's strongest claim
  survives.
- **Inherent impl in a child module + call resolution:** multiple inherent
  `impl PortAllocator` blocks across modules of the same crate are legal; a
  `self.gc_expired_chunked(..)` call in the parent resolves because the method is
  `pub(super)` (visible at the parent call site). Confirmed the only callers of the
  3 moved entry methods are in `allocator.rs` (grep: lines 786, 911, 980, 1022,
  1035, 1231) — no external caller, so `pub(super)` is exactly sufficient.
- **Hybrid `allocator.rs` + `allocator/gc.rs` in edition 2024:** supported. The
  crate is edition 2024 (Cargo.toml:4). No crate config blocks it.

Nothing here is a kill. The visibility design is the plan's best feature.

### Invariant #1 (zero-alloc / byte-identical hot) — holds, with one caveat handled.
- No hot method moves; I re-confirmed the move set touches only the 6 GC methods.
- I traced each moved body's external references: they touch only pub(super) live
  fields, pub(super) `PersistentLease` fields, the parent-private `free_translated_port`
  (descendant-OK), `collect_*`/`reclaim_*` (co-moved), `GC_CHUNK` (co-moved), and —
  under `#[cfg(test)]` only — `gc_lock_acquisitions` + `Ordering`. No OTHER private
  item is pulled across; the byte-identical claim is not hiding a missing dependency.
- The lazy-Vec zero-alloc-when-nothing-expires property (`freed: Vec::new()`) moves
  verbatim; no new alloc.
- **Caveat (nit N1):** `Ordering` is used in gc.rs ONLY inside the `#[cfg(test)]`
  block of `gc_expired_chunked` (verified: allocator.rs:1567-1570). So the gc.rs
  `use std::sync::atomic::Ordering;` MUST be `#[cfg(test)]`-gated, else non-test
  builds get an unused-import warning. There is no crate-level `deny(warnings)`
  (binary crate, no lib.rs, no `-D warnings` in cargo config), so this only warns —
  but `make test-rust`/CI may run stricter, and a warning in a "pure code-motion"
  PR is sloppy. The plan's §4.1 header sketch shows an ungated `use ...Ordering;` —
  fix it to a cfg-gated import (or move the whole `use` into the cfg(test) test
  module). Minor, must-fix at implementation.

### Invariant #3 (lock discipline) — holds.
Verbatim move; `gc_expired_chunked` still self-acquires the short per-chunk `live`
CS and frees lock-free after drop; `gc_expired_locked`/`_for_addr_locked` still take
`&mut live` from the caller. Global-outer/recycle-inner ordering unchanged because
zero lock code is edited. No new reentrancy: `allocate_translation` calls
`gc_expired_chunked` BEFORE taking its own guard (line 911) — unchanged sequence.
The `#[cfg(test)]` acquisition-count seam still fires from the moved body. No kill.

### Invariant #4 (byte-identical) — holds; audit is clean.
Because `allocator.rs` stays in place (hybrid layout), the diff is a pure deletion
of the 6 methods + `GC_CHUNK` + one `mod gc;` insertion, with zero edits to retained
lines. The methods are already at 4-space impl-method indent in both files, so the
"dedented diff" gate is really a same-indent diff — even simpler than the plan
states. I confirmed `GC_CHUNK`'s only code reference is inside `gc_expired_chunked`
(the tests_pool.rs:4023 hit is a comment), so removing it from allocator.rs breaks
nothing.

## Classification audit — I checked for a MISSED cross-call. None found.
- `insert_lease_expiration_locked` / `remove_lease_expiration_locked` are correctly
  KEPT in allocator.rs: their callers are `reuse_existing_lease_locked` (1133,1149),
  `release_flow` (1208-1209), `rollback_flow` (1273) — all hot, NONE in the GC
  engine. The GC engine removes index entries INLINE (1655-1659, 1694-1695), so it
  does not depend on these helpers. Correct call to leave them put.
- `free_translated_port` is called from 7 hot sites + the 3 GC methods; keeping it
  in allocator.rs (parent) and letting gc.rs call it as a descendant is right.
- Test seams `debug_gc_expired_chunked` / `debug_gc_lock_acquisitions` stay in
  allocator.rs and still resolve (former calls the now-pub(super) child method,
  latter reads a parent-private field from the parent). No seam breaks.

## Nits (must-fix / should-fix at implementation)
- **N1 (must-fix):** cfg-gate the `Ordering` import in gc.rs (above).
- **N2 (should-fix):** the R1 perf gate (§8.5) is over-specified. For a pure
  code-motion where `gc_expired_chunked` is provably not an inline candidate today
  (non-`#[inline]`, ≥2 call sites, contains a mutex-lock + loop + lazy Vec), a
  symbol/`nm` compare confirming `allocate_translation` still emits a `call` to the
  same mangled symbol and gains no new `__rust_alloc`/vtable is SUFFICIENT. Requiring
  a full multi-thread `snat_allocator` bench delta for a code-motion PR is ceremony.
  Downgrade the bench from "REQUIRED (one of two)" to "optional confirmation".
- **N3 (should-note):** the plan leaves `snapshot` in allocator.rs, so part (b)
  separates "GC" but NOT "stats" — mildly ironic against the issue's "cold config/
  stats/GC" wording. Option C (move snapshot too, `pub(in crate::nat)`) is cleaner
  on that axis; pick it or explicitly note stats-stays-hot-adjacent-by-design.
- **N4 (nice-to-have):** state in §4.1 that `mod gc;` is a PRIVATE child module and
  nothing in gc is re-exported (no `pub mod`, no `use gc::*` in the parent).

## The honest kill argument (escalated, not soft-passed)
The plan itself concedes the issue's premise is dead: post-#4676 the GC is
amortized-HOT, so this is not a hot/cold split but a ~180-LOC same-temperature
cohesion move that drops allocator.rs by ~10% and adds a cross-module hot call.
Everything about the mechanics is clean and safe — but "clean and safe" is not
"worth doing." A reviewer who values keeping the amortized-GC engine co-located
with its hot callers (so the whole allocate→gc→free story reads in one file) would
PLAN-KILL this on taste alone, and that position is defensible. I cannot
adjudicate that as a code reviewer; it is a maintainer preference.

My recommendation: land it (Option B) IF the maintainer wants the `allocator/`
directory seam established for the follow-on deterministic-NAT / AddressOccupancy
extractions; otherwise PLAN-KILL as "obsoleted by #2852/#4676, file already
well-factored." Either is correct. This is the decision to put in front of the
human, and the plan already frames it that way (§3 criterion 3, §10 Q1).

## What would flip me to a hard PLAN-KILL
Only if the perf gate (N2/§8.5) actually shows a regression in `allocate_translation`
codegen — then the cross-module move is not free and the modest value would not
cover it. I judge that outcome unlikely but it is the one empirical gate that
matters; it must be run, not assumed.
