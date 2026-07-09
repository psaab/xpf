# Plan of Action — #4409(b): `nat/allocator.rs` PortAllocator hot/cold split

- **Revision:** r1
- **Base:** origin/master `4eb28ae25eb8`
- **Branch:** `research/4409-allocator-hotcold` (docs only; no production source touched)
- **Scope:** issue #4409 **part (b) ONLY** — extract the cold/GC path out of
  `userspace-dp/src/nat/allocator.rs` WITHOUT perturbing the hot path.
- **Status:** PLAN-READY candidate (reframed) — awaiting Codex + Claude-SMR
  convergence. See §3 for the honest value caveat and §10 for the PLAN-KILL
  triggers.

---

## 1. Status & revision history

| Rev | What changed | Reviewer state |
|-----|--------------|----------------|
| r1  | First converged draft against the REAL 1797-LOC origin/master (not the 761-LOC file the issue was filed against). | Pending Codex + SMR round 1 |

---

## 2. Problem framing (and a load-bearing correction)

Issue #4409 (from ps-review-010/011) describes `nat/allocator.rs` as a **926-LOC
god-struct** that "mixes the HOT bitmap/allocation with COLD config/stats/GC/
persistent-leases", and asks part (b) to "separate the hot bitmap from the cold
config/stats/GC" while keeping the `reserve_flow`/#4388 and 1:N/#4399 hot paths
zero-alloc.

**Correction that reframes the whole task:** the file the issue was filed against
no longer exists. Since ps-review-010/011, two large refactors landed on
`allocator.rs`:

- **#2852 Phase 1** replaced the mutex-guarded `owner_by_translated` /
  `addr_index_by_translated` / `next_port_offset_by_addr` maps with a **lock-free
  per-address atomic occupancy bitmap** (`AddressOccupancy`: `Vec<AtomicU64>` +
  atomic cursor + a per-address recycle `Mutex<VecDeque<u16>>`). The port CLAIM
  is now lock-free; only `live_by_flow` + the persistent-lease maps stay under
  the global mutex.
- **#4676** made the expiry GC **chunked and opportunistic**: `gc_expired_chunked`
  runs INLINE on the hot allocation path (`allocate_translation`, line 911, every
  non-persistent allocation) and on the periodic release path (`release_flow`,
  line 1231), dropping the alloc mutex between chunks.

Current origin/master `allocator.rs` is **1797 LOC** (not 926/761). The single
most important consequence for part (b):

> **The "cold GC" the issue wants to separate is no longer cold.** Post-#4676 the
> GC engine is *amortized-hot* — it is invoked from inside the hot allocation and
> release methods. There is no clean hot/cold temperature line to cut along.

The genuinely-cold production surface is exactly **one method** (`snapshot`, a
1/s status-poll reader) plus the `#[cfg(test)]` debug accessors (~90 LOC that are
compiled OUT of the release binary). So a literal "hot/cold" file split would
move ~24 release LOC — not worth a PR.

This plan therefore **reframes** part (b) from a temperature split to a
**cohesion split**: extract the self-contained *lease-expiration GC engine*
(6 methods, ~180 LOC) into a child module `nat/allocator/gc.rs`. That is a real,
defensible module boundary independent of temperature — and, as §6 proves, it can
be done with **zero net visibility widening** and **byte-identical hot bodies**.

---

## 3. Honest scope & value — and when to PLAN-KILL

**What this buys:**
- Removes a cohesive ~180-LOC lease-expiration state machine
  (`gc_expired_chunked` / `gc_expired_locked` / `gc_expired_for_addr_locked` /
  `collect_expired_global_locked` / `collect_expired_for_addr_locked` /
  `reclaim_expired_lease_locked` + `GC_CHUNK`) from `allocator.rs`
  (1797 → ~1615 LOC), so the allocation/claim core and the reclamation engine are
  read and reasoned about separately.
- Establishes an `allocator/` directory that a **future** deterministic-CGNAT
  extraction (#4559 block, ~250 LOC) or `AddressOccupancy` extraction (~175 LOC)
  could reuse — but those are explicitly OUT of scope here (§9).

**What this does NOT buy:** it does not make the hot path faster, does not reduce
lock contention, and does not shrink the release binary meaningfully (the GC is
still called, just from another file in the same crate). It is a readability/
modularity change only.

**PLAN-KILL is an acceptable outcome and is warranted if any reviewer concludes:**
1. The split forces visibility widening that exposes allocator internals beyond
   the `nat::allocator` subtree (i.e. leaks to `nat::source` / `nat::status` /
   `nat::tests_*`). *[Plan claim: it does NOT — §6.2 proves zero net widening.]*
2. Moving `gc_expired_chunked` (an every-allocation call) across a module/codegen
   boundary measurably regresses the hot allocation path under the crate's
   default release profile. *[Plan claim: it does not, and §8 gates on proof.]*
3. The modularity win (~10% LOC, one cohesive engine) is judged too small to
   justify any cross-module coupling on an amortized-hot path — i.e. "leave the
   GC engine co-located with its hot callers; the cohesion is already documented
   by the section headers." This is a legitimate taste call and a valid PLAN-KILL.

The plan's position: proceed (PLAN-READY) because the widening is provably nil and
the hot bodies are provably byte-identical, but the value is modest and reviewers
should feel free to PLAN-KILL on criterion 3 (taste) alone.

---

## 4. Concrete design

### 4.1 Module layout (hybrid file module — hot file stays put)

```
userspace-dp/src/nat/
  allocator.rs            # UNCHANGED PATH. Add `mod gc;`. Loses the 6 GC methods
                          # + GC_CHUNK. Everything else byte-identical.
  allocator/
    gc.rs                 # NEW. `nat::allocator::gc` — a *child* of nat::allocator.
                          # Second `impl PortAllocator { ... }` block: the 6 moved
                          # GC methods + `const GC_CHUNK`.
```

Rust 2018+/2024 supports `foo.rs` alongside `foo/bar.rs` for submodule `bar` of
`foo`. `allocator.rs` stays exactly where it is — the hot code's file path is
unchanged, so `git blame`/history for every hot method is fully preserved and the
byte-identical audit (§6.4) is a clean "6 methods removed" diff.

`allocator.rs` gains one line near the top:
```rust
mod gc;   // child module: lease-expiration GC engine (#4409(b))
```

`gc.rs` header:
```rust
use super::{PersistentSourceKey, PortAllocator, PortAllocatorLiveState};
use std::sync::atomic::Ordering;   // only for the #[cfg(test)] gc_lock_acquisitions bump

const GC_CHUNK: usize = 8;         // moved verbatim from allocator.rs (only user is here)

impl PortAllocator {
    // gc_expired_chunked / gc_expired_locked / gc_expired_for_addr_locked /
    // collect_expired_global_locked / collect_expired_for_addr_locked /
    // reclaim_expired_lease_locked — bodies byte-identical.
}
```

**Why a CHILD module, not a sibling** (this is the crux of constraint #2): Rust's
privacy rule — *"a private item may be accessed by the current module and its
descendants"* — means a child module can read the parent's **private methods and
private struct fields** with NO visibility annotation. A *sibling* module
(`nat::allocator_gc`) could not, and would force widening `free_translated_port`,
`shared`, `live`, `gc_lock_acquisitions`, and every touched field to `pub(super)`
= `pub(in crate::nat)`, leaking them to `nat::source`/`nat::status`. The child
layout is what makes the widening nil. The issue's own suggested path
(`nat/allocator/gc.rs`) is already the child layout.

### 4.2 Move set and per-item visibility table

| Item | Kind | Today (in allocator.rs) | After (in gc.rs) | Why this visibility |
|------|------|-------------------------|------------------|---------------------|
| `gc_expired_chunked` | method | private `fn` | **`pub(super) fn`** | Called by `allocate_translation` + `release_flow` in the PARENT (`nat::allocator`). A child item must be `pub(super)` to be visible to its parent. |
| `gc_expired_locked` | method | private `fn` | **`pub(super) fn`** | Called by `allocate_translation_locked` in the parent. |
| `gc_expired_for_addr_locked` | method | private `fn` | **`pub(super) fn`** | Called by `allocate_translation_locked` in the parent. |
| `collect_expired_global_locked` | method | private `fn` | private `fn` | Callers (`gc_expired_chunked`, `gc_expired_locked`) are co-located in gc.rs. No widening. |
| `collect_expired_for_addr_locked` | method | private `fn` | private `fn` | Only caller (`gc_expired_for_addr_locked`) is in gc.rs. No widening. |
| `reclaim_expired_lease_locked` | method | private `fn` | private `fn` | Only callers (`collect_*`) are in gc.rs. No widening. |
| `GC_CHUNK` | const | private | private (moved) | Only reference is inside `gc_expired_chunked`. (A code-comment mention in `tests_pool.rs:4023` is prose, not a symbol reference.) |

**Items that STAY in allocator.rs and are called BY gc.rs — visibility UNCHANGED
(descendant-access rule):**

| Item accessed from gc.rs | Kind | Current visibility | Widening needed? |
|--------------------------|------|--------------------|------------------|
| `PortAllocator.shared` | field | private | **No** — child reads ancestor private |
| `PortAllocatorShared.live` | field | private | **No** |
| `PortAllocatorShared.gc_lock_acquisitions` | `#[cfg(test)]` field | private | **No** |
| `PortAllocator::free_translated_port` | method | private | **No** |
| `PortAllocatorLiveState.lease_expirations` | field | `pub(super)` | No (already) |
| `PortAllocatorLiveState.persistent_by_source` | field | `pub(super)` | No (already) |
| `PortAllocatorLiveState.lease_expirations_by_addr` | field | `pub(super)` | No (already) |
| `PersistentLease.{addr_index,translated,active_flows,expires_at_ns}` | fields | `pub(super)` | No (already) |

**Net widening: three methods change `fn` → `pub(super) fn`. Zero fields, zero
consts, zero types widened.** And critically (§6.2), those three `pub(super)`
bumps expose the methods to the *same module set they already reach today*.

### 4.3 Which impl block each method lands in

`PortAllocator` gets a **second inherent `impl` block** in `gc.rs` holding the 6
GC methods. Rust permits multiple inherent impl blocks for one type across modules
in the same crate. The hot methods (`allocate_translation`, `allocate_translation_locked`,
`release_flow`, `rollback_flow`, `reserve_flow`, `allocate_deterministic_v4/v6`,
`try_next_port`, `address_index`, `free_translated_port`, `reuse_existing_lease_locked`,
`insert_/remove_lease_expiration_locked`, `snapshot`, `new`, all `debug_*`) remain
in the original `impl PortAllocator` block in `allocator.rs`, untouched.

### 4.4 Full HOT vs MOVED classification (every method)

HOT / stays in allocator.rs, **byte-identical** (call sites to moved GC methods
are unchanged — inherent-method resolution finds the child-module impl):

- `address_index` (pub(super)) — hot, `allocate_translation` + `source.rs`
- `try_next_port` (pub(super)) — hot 1:N / `port no-translation` (#4399), `source.rs`
- `free_translated_port` (private) — hot free primitive (7 hot call sites) + GC callee
- `allocate_translation` (pub(super)) — **the crux hot method**; calls `gc_expired_chunked`
- `allocate_translation_locked` (private) — hot pressure/persistent; calls `gc_expired_locked`, `gc_expired_for_addr_locked`
- `reuse_existing_lease_locked` (private) — hot persistent-lease reuse
- `insert_lease_expiration_locked` / `remove_lease_expiration_locked` (private assoc fns) — hot-only index helpers (callers: `release_flow`, `rollback_flow`, `reuse_existing_lease_locked`) — **NOT** moved (they are not GC callees; the GC engine does its index removal inline)
- `release_flow` (pub(super)) — hot; calls `gc_expired_chunked`
- `rollback_flow` (pub(super)) — hot
- `allocate_deterministic_v4` / `allocate_deterministic_v6` (pub(super)) — hot #4559 CGNAT
- `reserve_flow` (pub(super)) — hot #4388 HA-sync reserve
- `snapshot` (pub(super)) — cold stats reader; **stays** (it is stats, not GC; moving it would force `pub(in crate::nat)` to keep `nat::status` visibility for a 24-line marginal gain — see §10 Q3)
- `new` (pub(crate)), all `debug_*` (`#[cfg(test)] pub(super)`) — construction/test, stay
- `AddressOccupancy` (private struct + impl), `Deterministic{V4,V6}` + free fns, `sticky_pool_index`, `allocator_capacity`, `PoolAddressFamily` — stay

MOVED to gc.rs: the 6 GC-engine methods + `GC_CHUNK` (table §4.2).

---

## 5. API / behavior preservation

- No public (`pub(crate)`) surface changes. `nat/mod.rs`'s re-exports
  (`PortAllocator`, `PortAllocatorSnapshot`, `Deterministic*`, the free fns) are
  untouched — nothing they name moves.
- No method signatures change. No struct/field layout changes. No control-flow
  changes. The move is pure code-motion of 6 method bodies + 1 const.
- Every caller (`source.rs`, `status.rs`, `nat64.rs`, all `tests_*`) is unaffected
  — they call `pub(super)` entry points that keep their exact paths and signatures.
- `cargo test` behavior identical: the white-box tests reach the GC engine via
  `debug_gc_expired_chunked` (which stays in allocator.rs and calls the now-child
  `gc_expired_chunked` — resolves fine) and via `debug_gc_lock_acquisitions`.

---

## 6. The four hard invariants — with proof

### 6.1 Invariant #1 — Zero-alloc hot path preserved

Enumerated hot methods and their disposition:

| Hot method | Moved? | Body byte-identical? | New alloc/box/Vec/dyn added? |
|------------|--------|----------------------|------------------------------|
| `allocate_translation` | No | Yes | No |
| `allocate_translation_locked` | No | Yes | No |
| `reuse_existing_lease_locked` | No | Yes | No |
| `release_flow` | No | Yes | No |
| `rollback_flow` | No | Yes | No |
| `reserve_flow` (#4388) | No | Yes | No |
| `allocate_deterministic_v4/v6` (#4559) | No | Yes | No |
| `try_next_port` (1:N #4399) | No | Yes | No |
| `address_index` | No | Yes | No |
| `free_translated_port` | No | Yes | No |
| `insert_/remove_lease_expiration_locked` | No | Yes | No |

None of the hot methods move. The only edit to `allocator.rs` in the hot region
is the *removal* of the 6 GC method definitions; every retained hot body is
untouched, so no clone/box/Vec/indirection is introduced. The GC engine itself
already allocates its `freed: Vec<(usize,u16)>` lazily (`Vec::new()` does not
allocate until first push; on the common "nothing expired" path
`collect_expired_*` returns 0 and the Vec stays empty) — moving the method
preserves that byte-for-byte. **No dynamic dispatch** is introduced: the calls
stay static inherent-method calls (`self.gc_expired_chunked(..)`), resolved at
compile time regardless of which module the impl lives in.

Residual concern (inlining/codegen, addressed as a risk in §7 R1 and gated in §8):
`gc_expired_chunked` is called on every non-persistent allocation. It is a
non-`#[inline]`, multi-call-site, ~35-line function (loop + mutex + lazy Vec), so
it is not a viable inline candidate into `allocate_translation` today and is
already emitted as a `call`. Moving it to a sibling module in the SAME crate does
not change that it is a `call`; it can only affect cross-CGU inlining of a function
that is not inlined today. §8 gates on an asm/bench equivalence check to make this
airtight rather than merely argued.

### 6.2 Invariant #2 — Cross-impl visibility is MINIMAL (the crux)

Two directions, two rules:

- **gc.rs → allocator.rs (child reads parent):** Rust grants descendants access to
  ancestor *private* items and fields. So `self.shared`, `self.shared.live`,
  `self.shared.gc_lock_acquisitions`, `free_translated_port`, and every `PersistentLease`/
  `PortAllocatorLiveState` field gc.rs touches need **no annotation**. Widening = 0.
- **allocator.rs → gc.rs (parent calls child):** a child item must be at least
  `pub(super)` to be visible to its parent. So `gc_expired_chunked`,
  `gc_expired_locked`, `gc_expired_for_addr_locked` get `pub(super)`. This is the
  minimal keyword that lets the parent call them; anything narrower
  (`pub(self)`/private) would not compile.

**No over-exposure — proven by comparing the reachable module set.** For an item
in `nat::allocator::gc`, `pub(super)` == `pub(in crate::nat::allocator)` — visible
to `nat::allocator` and its descendants (`nat::allocator::gc`) only. It is NOT
visible to `nat::source`, `nat::status`, or the `nat::tests_*` modules. Today those
same 3 methods are `private` in `nat::allocator`, i.e. visible to `nat::allocator`
+ its descendants — the *same set*. So the `pub(super)` bump grants visibility to
**exactly one new module: gc itself, where the method now lives**. Net externally-
reachable surface: unchanged. `collect_*`/`reclaim_*`/`GC_CHUNK` stay private and
are strictly narrower than a sibling design would allow.

Conclusion: the widening is both *necessary* (parent-call requirement) and *not
wider than necessary* (does not leak past `nat::allocator`). Constraint #2 met.

### 6.3 Invariant #3 — Lock discipline unchanged

The 6 methods move verbatim, so their locking is identical:

- `gc_expired_chunked` continues to acquire `self.shared.live` itself in a SHORT
  per-chunk critical section, drop it, then free ports on the lock-free bitmap
  (`free_translated_port` → `AddressOccupancy::free_recycle`, a `fetch_and` + the
  innermost per-address recycle mutex). Nothing here changes.
- `gc_expired_locked` / `gc_expired_for_addr_locked` continue to take
  `&mut PortAllocatorLiveState` (the caller in `allocate_translation_locked` holds
  the guard) and free inline under that guard.
- Lock ordering stays: global `live` mutex OUTER, per-address `recycle` mutex
  INNER, never inverted; no method acquires `live` while holding `recycle`.
- No double-lock is introduced: the parent's `allocate_translation` fast path
  still calls `gc_expired_chunked` BEFORE it takes its own `live` guard (line 911),
  and `gc_expired_chunked` takes/releases its own guard — the pre-existing
  (non-reentrant, safe) sequence. The `#[cfg(test)] gc_lock_acquisitions` seam that
  proves the between-chunks release still fires from within the moved body.

Because zero lock code is edited, the discipline is preserved by construction.

### 6.4 Invariant #4 — Byte-identical bodies

- The 6 moved method bodies are copied verbatim. The ONLY textual deltas are the
  visibility keyword on 3 of them (`fn` → `pub(super) fn`) and the module/`impl`
  wrapper + `use`/`const` scaffolding in gc.rs — exactly the deltas constraint #4
  permits.
- Verification gate (§8): a scripted `diff` of each moved body (stripped of the
  leading `pub(super) ` and compared at the same indentation — the methods are
  already at 4-space `impl`-method indent in both files, so no dedent is even
  required) must show ZERO body-line differences. The `allocator.rs` side of the
  diff must show ONLY deletions (the 6 methods + `GC_CHUNK` + `mod gc;` insertion),
  no edits to any retained line.

---

## 7. Risk table (4 classes)

| # | Class | Risk | Likelihood | Impact | Mitigation |
|---|-------|------|-----------|--------|------------|
| R1 | Performance | Cross-module placement stops a cross-CGU inline of `gc_expired_chunked` that happens today → per-allocation regression | Low (not an inline candidate today; default profile already splits CGUs) | Med if real | §8 asm/bench equivalence gate: dump release codegen for `allocate_translation`/`release_flow` before vs after and/or run `benches/snat_allocator.rs`; require within-noise. Fallback: `#[inline]` on the 3 GC entry methods (a documented deviation from "vis-keyword-only") ONLY if the gate flags a regression. |
| R2 | Correctness | A moved body is silently altered (whitespace/编辑 slip) changing GC semantics | Low | High | §6.4 byte-identical diff gate + full `cargo test --release` (the #3011/#3047/#4676 GC tests in `tests_pool.rs` pin FIFO order, collision retain, and the between-chunks lock-release seam). |
| R3 | Encapsulation | Widening leaks allocator internals to `nat::source`/`status`/tests | Nil (proven §6.2) | Med | Child-module layout; grep-assert no new `pub(super)`/`pub(in)` on any field or on `collect_*`/`reclaim_*`; assert the 3 method bumps are `pub(super)` not `pub(crate)`/`pub(in crate::nat)`. |
| R4 | Maintainability / value | Modest ~10% LOC win doesn't justify a second file + a cross-module hot call; "cold" framing is stale | Med (taste) | Low | §3 reframes honestly as cohesion (not temperature); reviewers may PLAN-KILL on this alone (§10 Q1/Q5). File name `gc.rs` (not `cold.rs`) reflects the amortized-hot reality. |

---

## 8. Test / validation plan

Pre-merge (at `/engineer` time; this is the plan the implementation must satisfy):

1. **Byte-identical body diff** — script asserts each of the 6 moved bodies is
   identical (modulo the leading `pub(super) `) to its origin, and that
   `allocator.rs`'s retained lines are unedited. (§6.4)
2. **Visibility grep-assertions** — no field/type in `allocator.rs` gained
   `pub(super)`/`pub(in ...)`; exactly 3 methods in `gc.rs` are `pub(super)`;
   `collect_*`/`reclaim_*`/`GC_CHUNK` are private.
3. **`cargo build --release`** — compiles clean (proves the child-module visibility
   design actually holds; a wrong sibling assumption would fail here).
4. **`cargo test --release`** (full userspace-dp suite via `make test-rust`) — must
   be green, with specific attention to the `tests_pool.rs` GC tests: #4676
   chunked-release seam (`debug_gc_lock_acquisitions` > 1), #3011 FIFO recycle,
   #3047 collision-retain, persistent-lease expiry/rollback.
5. **Codegen/perf equivalence gate (R1)** — either (a) `cargo asm` / objdump symbol
   compare of `allocate_translation` + `release_flow` before/after shows no new
   heap-alloc or dyn-dispatch and the `gc_expired_chunked` call is still a static
   call, OR (b) `benches/snat_allocator.rs` allocate throughput is within noise of
   the pre-change baseline. One of the two is REQUIRED before merge.
6. **NAT smoke on the standalone test VM** (NOT the per-class CoS cluster smoke —
   this is the NAT allocator, so a source-NAT datapath check suffices):
   - Configure a pool-mode SNAT rule (trust→untrust), start `xpfd`.
   - Drive `iperf3` from `trust-host` (10.0.1.102) out through the DUT so real
     flows allocate/release pool ports.
   - `show security nat source pool <name>` — confirm the **hit counters**
     (allocations/used-ports/reuses) advance and settle, i.e. the allocate and
     release+GC paths still work end-to-end after the move.
   - `show security flow session` sanity: sessions install and age out.
   This exercises `allocate_translation` (fast path) + `release_flow` +
   `gc_expired_chunked` on real traffic — the exact surface the move touches.

No cluster/HA smoke is required unless `reserve_flow` behavior is in doubt (it is
not moved); the standalone SNAT smoke is sufficient for part (b).

---

## 9. Out of scope (explicit)

- **Part (a) — `nat/tests.rs` split per module.** Already partly done (the crate
  has `tests_source/_static/_destination/_pool/_counter/_dnat_proto/_scope/_l4_match`).
  Not touched here. Separate issue-part.
- **Part (c) — `nat/source.rs` rule-parse vs allocation-driver split.** Not touched.
  Separate issue-part.
- **`AddressOccupancy` extraction** (the lock-free bitmap, ~175 LOC, lines 406-580)
  — a clean self-contained-type extraction, but it is the HOT core the issue wants
  to KEEP, not the cold part; and its hot inherent methods (`claim`/`reserve`/
  `free_recycle`) would need `pub(super)` and carry a sharper inlining question.
  Deferred; noted as a future option (§10 Q4).
- **Deterministic-CGNAT extraction** (#4559 block: `Deterministic{V4,V6}` +
  `deterministic_indices_*` + `reverse_deterministic_*` + `deterministic_v6_word_offset`
  + `allocate_deterministic_v4/v6`, ~250 LOC) — arguably a *larger, cleaner*
  cohesion seam than GC, but it is not "cold config/stats/GC" and `allocate_deterministic_*`
  are hot. Out of part (b)'s scope; flagged as an alternative worth its own issue.
- Any behavior change, lock-strategy change, or performance work on the allocator.

---

## 10. Open questions (each may be answered "PLAN-KILL")

1. **Is the cohesion win worth it given the stale premise?** The issue asked for a
   hot/cold split; post-#4676 there is no cold GC. Is a same-temperature cohesion
   extraction of the GC engine still worth a PR, or should part (b) be closed as
   "obsoleted by #2852/#4676; the file is already well-factored"? *(→ possible PLAN-KILL)*
2. **`pub(super)` on the 3 GC entry methods — acceptable, or over-exposed?** §6.2
   argues it grants no new external visibility (same module set as today's
   private). Do the reviewers accept that, or do they want the GC engine to stay
   private-in-allocator (which forces it to stay in allocator.rs → no split)? *(→ PLAN-KILL if the latter)*
3. **Should `snapshot` move too?** It is the one genuinely-cold production method.
   Moving it to gc.rs (or a separate `cold.rs`) honors the issue's "stats" wording
   but needs `pub(in crate::nat)` (to keep `nat::status` visibility) and mixes
   stats into a `gc` module. Keep it in allocator.rs (current plan) or move it?
4. **Is `AddressOccupancy` the better first cut?** Extracting the lock-free bitmap
   type is arguably cleaner (self-contained type, no shared-field access) than the
   GC engine. Should part (b) target that instead of / in addition to GC?
5. **Hybrid `allocator.rs`+`allocator/gc.rs` vs converting to `allocator/mod.rs`?**
   The crate uses `dir/mod.rs` everywhere and has no hybrid precedent. Hybrid keeps
   the hot file's path (zero churn, cleanest byte-identical audit); `mod.rs`
   matches convention but relocates the hot file (git-rename-tracked). Which does
   the project prefer? *(Style call, not a PLAN-KILL, but reviewers should pick.)*
6. **R1 gate sufficiency:** is an asm symbol-compare enough, or do the reviewers
   require the `snat_allocator` bench delta as the hard gate before merge?

---

## 11. Alternatives considered & recommendation

| Option | Moves | Widening | Value | Verdict |
|--------|-------|----------|-------|---------|
| A. Literal cold-only | `snapshot` + `#[cfg(test)]` debug accessors | `snapshot`→`pub(in crate::nat)`; accessors→`pub(in crate::nat)` | ~24 release LOC; tiny | Rejected — trivial |
| **B. GC-engine extraction (RECOMMENDED)** | 6 GC methods + `GC_CHUNK` → `allocator/gc.rs` | 3 methods → `pub(super)` (zero net); 0 fields | ~180 LOC cohesive engine | **Proceed / PLAN-READY** subject to §10 taste calls |
| C. B + `snapshot` | Option B + `snapshot` | B + `snapshot`→`pub(in crate::nat)` | +24 LOC, honors "stats" | Viable variant (Q3) |
| D. `AddressOccupancy` extraction | the bitmap type | bitmap methods → `pub(super)` | ~175 LOC, but it's the HOT core | Deferred (Q4) — not "cold", sharper perf question |
| E. PLAN-KILL | nothing | — | closes a stale-premise issue | Acceptable (§3, Q1/Q2) |

**Recommendation:** Option **B**. It is the only option that (i) matches part (b)'s
"separate the GC" intent, (ii) has provably-zero net visibility widening via the
child-module descendant rule, (iii) leaves every hot method byte-identical, and
(iv) carries only a low, gate-able codegen risk. The honest caveat (§3) stands: the
value is modularity-only and modest, and a reviewer PLAN-KILL on taste grounds
(Q1/Q2) is a legitimate, respected outcome rather than a defect in the plan.
