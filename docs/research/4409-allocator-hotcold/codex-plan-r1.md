# Codex hostile plan review r1 — #4409(b) — VERBATIM

- Task ID: task-mrdqkeiu-i44qsd
- Codex session: 019f47c3-6921-7c71-bb08-fa318f09d4fb

---

**Verdict: PLAN-KILL**

This plan should not proceed as written. It is not a hot/cold split anymore; it moves amortized-hot GC into another module for a modest LOC win, while the perf invariant is not actually proven.

**Killing Reasons**
1. `gc_expired_chunked` is on the hot path: every non-persistent allocation calls it at allocator.rs:911, and `release_flow` calls it periodically at allocator.rs:1231. Calling this "cold" is stale.
2. The "not an inline candidate today" claim is asserted, not proven. With `ALLOCATION_GC_BUDGET = 8`, inlining could constant-fold the chunk loop in allocator.rs:1556. Default release has no LTO/profile override, so moving the callee into `nat::allocator::gc` can affect CGU placement.
3. The proposed perf gate is defective. `benches/snat_allocator.rs` is a #2852 reimplementation bench, not a production `PortAllocator`/GC/module-boundary benchmark; its own header says it reimplements both shapes side-by-side. That bench cannot validate this refactor. The asm comparison must be mandatory, not "asm OR bench."
4. The value is too small: ~180 LOC moved, no binary/runtime win, no contention reduction, and the truly cold production method `snapshot` stays in place at allocator.rs:1507.

**Non-Kills**
Visibility reasoning is correct. A child module `nat::allocator::gc` can access ancestor-private fields/methods like `PortAllocator.shared` at allocator.rs:633, `PortAllocatorShared.live` at allocator.rs:610, `gc_lock_acquisitions` at allocator.rs:620, and private `free_translated_port` at allocator.rs:841. `pub(super)` in `allocator/gc.rs` is `pub(in crate::nat::allocator)`, not visible to `nat::source` or `nat::status`. The hybrid `allocator.rs` + `allocator/gc.rs` layout is legal in edition 2024.

Lock discipline also survives a verbatim move. `gc_expired_chunked` locks `live` inside the chunk at allocator.rs:1566, drops it before freeing ports at allocator.rs:1575, while the locked variants take caller-held `&mut live` at allocator.rs:1598 and allocator.rs:1614. No double-lock appears if bodies are copied exactly.

**Missed Issues**
The plan's "retained lines unedited" rule would preserve stale comments: `allocator.rs` currently says GC constants/private types stay "fully private to this file" at allocator.rs:75, which becomes false after introducing `allocator/gc.rs`.

Also, `gc.rs` should not unconditionally import `Ordering` only for a `#[cfg(test)]` use; make that import `#[cfg(test)]` or fully qualify it.

Cleaner outcome: close #4409(b) as obsolete after #2852/#4676, or cut a genuinely cleaner seam later, such as `AddressOccupancy` at allocator.rs:406 or deterministic NAT, with a real perf gate.
