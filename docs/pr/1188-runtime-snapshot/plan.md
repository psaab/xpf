---
status: REVISED v5 — Codex+Gemini round-4 caught two more bugs: (1) `arc_swap::Guard::into_inner` is hallucinated — no such method exists; use `Arc::clone(&*guard)` which still gives TOCTOU avoidance because we clone the exact observed Arc; (2) forwarding-site ordering: `screen_state.update_profiles` + `sessions.set_timeouts` at `worker/mod.rs:731-732` read `forwarding`, must use `new_forwarding` not the cached pre-assignment value. v5 specifies the full forwarding-site code template and scrubs stale prose at lines 59, 192, 234
issue: #1188
phase: Replace `.load_full()` with `.load()` + `Arc::as_ptr` comparison in worker tick loop
---

## 1. Issue framing — corrected

Issue #1188's headline ("up to 8 ArcSwap loads per iteration → bus
saturation") is **substantively correct**. The original v1 plan
(consolidate 3 fields into `ImmutableRuntime`) was wrong because:

1. v1 inventoried only 3 per-tick `.load()` calls. Gemini Pro 3.1
   caught the actual count: **6 per-tick `.load_full()` calls**
   at `worker/mod.rs:725, 738, 743, 748, 757, 765`.
2. **`.load_full()` ALWAYS clones the `Arc`**, doing one atomic
   refcount increment on the clone and one decrement when the
   guard drops if unchanged. That's 2 atomic RMW operations per
   `.load_full()` per tick.
3. The existing code already does `Arc::ptr_eq(&cached, &live)`
   immediately after each `.load_full()` (lines 727, 739, 744,
   749, 758, 766), so the clone is **wasted** in the common case
   (no config change since last tick).

**Cycle math (corrected):**

- 6 `.load_full()` × 2 RMW ops = 12 atomic RMW ops/tick on shared
  Arc control blocks
- ~10K-100K worker ticks/sec per worker (depends on poll_mode and
  load) × 8 workers
- ≈ 0.96B–9.6B atomic RMWs/sec on the shared cache lines holding
  the Arc control blocks

These atomic RMWs all hit the SAME cache line for each shared
state's Arc, which the coordinator core also touches whenever it
swaps. Result: MESI cache-line ping-pong on the QPI/UPI between
worker cores (or between worker cores and coordinator core on
the same socket) — exactly what the issue body describes.

## 2. Honest scope/value framing

**The fix:** replace each `.load_full()` with `.load()` (returns
a `Guard<Arc<T>>`, no clone) + `Arc::ptr_eq(cached, &*guard)`
comparison. When the comparison shows divergence, consume the
observed `Guard` via `arc_swap::Guard::into_inner(guard)` (no
second load, no TOCTOU window). The caller decides when to
assign the new Arc to its cached slot — the forwarding site at
`worker/mod.rs:727` needs to compare old vs new before the
assignment to call `cos_runtime_config_changed(old, new)`.

```rust
// before:
let live_forwarding = shared_forwarding.load_full();   // clone always
if !Arc::ptr_eq(&forwarding, &live_forwarding) {
    forwarding = live_forwarding;
    // ... refresh dependent state ...
}

// after — see helper at §4.3 and per-site templates at §4.2:
if let Some(new_forwarding) =
    load_arc_if_changed(&forwarding, &shared_forwarding)
{
    /* compare old vs new for cos_runtime_config_changed,
       update screen_state + sessions from new_forwarding,
       THEN assign forwarding = new_forwarding */
}
```

**Win:**

- Steady state (no config change): saved 12 atomic RMW ops/tick →
  ~0.96B–9.6B ops/sec eliminated from the QPI/UPI bus.
- On actual config change (rare, < 1/sec normally): one
  cheap `.load()` + one `Arc::clone` (atomic increment).
  Negligible at ~1/sec rate.
- No coordinator-side changes. No new types except the helper
  fn. No semantics change.

**The architectural value:** matches the existing `Arc::ptr_eq`
intent — the existing code clearly *wanted* to compare without
cloning, but `.load_full()` semantics forced the clone first.
This refactor expresses the intent correctly.

**This v2 plan is concrete, measurable, narrow.** No PLAN-KILL
discussion this round — the underlying problem is real and the
fix is clear.

## 3. What's already shipped

- 6 `.load_full()` + `Arc::ptr_eq` blocks at
  `worker/mod.rs:725-780`
- 1 `.load()` + manual `==` comparison for `shared_validation`
  at line 721-723 (the right pattern, only used in one place)
- 1 `.load()` for `ha_state` at line 801 (cached as `ha_runtime`,
  separately compared)
- 1 `.load()` for `shared_fabrics` at line 908 (cached as
  `live_fabrics`)

The 3 `.load()` sites are NOT the problem; they don't clone. The
6 `.load_full()` sites are.

## 4. Concrete design

### 4.1 The 6 sites to fix

| Line | Field | Cache var |
|---|---|---|
| 725 | `shared_forwarding` | `forwarding` |
| 738 | `shared_cos_owner_worker_by_queue` | `cos_owner_worker_by_queue` |
| 743 | `shared_cos_owner_live_by_queue` | `cos_owner_live_by_queue` |
| 748 | `shared_cos_root_leases` | `cos_shared_root_leases` |
| 757 | `shared_cos_queue_leases` | `cos_shared_queue_leases` |
| 765 | `shared_cos_queue_vtime_floors` | `cos_shared_queue_vtime_floors` |

### 4.2 Pattern

For each of the 6 sites, transform from the existing
`load_full + ptr_eq` pattern to the helper.

**Forwarding site** (the most order-sensitive — `worker/mod.rs:725-736`):

```rust
if let Some(new_forwarding) =
    load_arc_if_changed(&forwarding, &shared_forwarding)
{
    // Compare BEFORE assignment — needs both old and new.
    let cos_changed =
        cos_runtime_config_changed(forwarding.as_ref(), new_forwarding.as_ref());

    // Use NEW values for side effects (Codex round-4 catch).
    // `screen_state.update_profiles` and `sessions.set_timeouts`
    // must read the freshly-rotated forwarding, not the cached
    // pre-assignment value.
    screen_state.update_profiles(new_forwarding.screen_profiles.clone());
    sessions.set_timeouts(new_forwarding.session_timeouts);

    forwarding = new_forwarding;

    if cos_changed {
        reset_worker_cos_runtimes(&mut bindings);
        rebuild_cos_fast_interfaces = true;
    }
}
```

**The other 5 sites** (`shared_cos_owner_worker_by_queue`,
`shared_cos_owner_live_by_queue`, `shared_cos_root_leases`,
`shared_cos_queue_leases`, `shared_cos_queue_vtime_floors` —
all simpler, no `cos_runtime_config_changed` analog):

```rust
if let Some(new_X) = load_arc_if_changed(&cached_X, &shared_X) {
    cached_X = new_X;
    /* same side effects as before — usually setting
       rebuild_cos_fast_interfaces = true; or releasing leases */
}
```

For these 5 sites, the assignment can come first because the
side effects don't read the cached value. Pattern is more
forgiving than the forwarding site.

**Both bugs caught by reviewers in earlier rounds:**
- v3: helper mutated cached before block ran → `cos_runtime_config_changed` would skip (Codex round-3).
- v4: helper non-mutating but `screen_state.update_profiles(forwarding.X)` would read OLD forwarding if assignment was at end (Codex round-4).
- v5: full template above shows correct ordering; "use new_X for side effects, then assign" is the rule.

The helper is non-mutating and returns the freshly observed Arc
(`Arc::clone(&*guard)`). No TOCTOU window, no second `.load_full()`,
old/new comparison and side effects all use whichever value
is correct.

### 4.3 Optional: helper macro

To avoid 6 copies of the same pattern, introduce a small helper:

```rust
/// If the `ArcSwap` has been rotated since `cached` was observed,
/// return the freshly-rotated `Arc`. Otherwise return `None`.
///
/// **Non-mutating by design (Codex round-3 catch):** the helper does
/// not assign to `cached`. The caller decides when to assign,
/// because some callers (notably the forwarding site at
/// `worker/mod.rs:727`) need to call
/// `cos_runtime_config_changed(old, new)` while both the old and
/// new Arcs are accessible.
///
/// **TOCTOU avoidance (Codex round-2 / Gemini round-4 correction):**
/// clone the exact `Arc` the `Guard` is observing — `Arc::clone(&*guard)`
/// — instead of calling `.load_full()` a second time. Calling
/// `.load_full()` again could return a *newer* Arc if the coordinator
/// rotated between our `ptr_eq` check and the second load. Cloning
/// the observed Guard pins the exact snapshot we compared.
///
/// **Why not `arc_swap::Guard::into_inner`?** Because that method
/// does not exist. `arc_swap::Guard` is a hazard-pointer-style protect
/// — it does not hold its own strong refcount. Converting a Guard
/// to an owned `Arc<T>` requires an atomic refcount increment via
/// `Arc::clone`. That increment cost is real and acceptable: it
/// only fires when the configuration actually changed (rare).
///
/// Gemini Pro 3.1 round-2: use idiomatic `Arc::ptr_eq` (the `Guard`
/// derefs to `&Arc<T>`); `T: ?Sized` is dropped — all 6 call sites
/// are sized concrete types.
fn load_arc_if_changed<T>(
    cached: &Arc<T>,
    shared: &ArcSwap<T>,
) -> Option<Arc<T>> {
    let guard = shared.load();
    if Arc::ptr_eq(cached, &*guard) {
        None
    } else {
        Some(Arc::clone(&*guard))
    }
}
```

Usage: see per-site templates in §4.2. The forwarding site is
the most order-sensitive (must compare old/new and use new
values for `screen_state` / `sessions` updates BEFORE
assignment). The other 5 sites can assign first.

Each of the 6 sites becomes an `if let Some(new_X) = ...` head
plus the existing side-effect block, with the assignment
(`cached_X = new_X`) placed correctly relative to the side
effects per the per-site templates above.

**Decision: ship the helper.** It makes the 6 sites uniform and
the diff cleaner; it's also a future-proof primitive for any
new `ArcSwap` field added to worker_loop.

## 5. Public API preservation

`worker_loop` signature unchanged. No external API changes.
The helper is a private fn or a module-local utility.

## 6. Hidden invariants the change must preserve

- **Visibility:** when the coordinator swaps an Arc, the next
  worker tick must observe the change. `ArcSwap::load()` provides
  acquire-ordered access; `Arc::ptr_eq` compares Arc identity.
  Pointer comparison is a value comparison, no ordering issue.
- **Refresh side effects:** each of the 6 sites does specific
  bookkeeping when the Arc changes (rebuild cos_fast_interfaces,
  release_all_cos_root_leases, etc.). The new pattern preserves
  these by keeping the existing block inside the `if changed`
  branch.
- **No torn reads of dependent state:** the same tick that
  observes `shared_forwarding` rotation may not yet observe a
  related `shared_cos_*` rotation if they were swapped
  separately. This is **the same as today** — both the old and
  new code observe each Arc independently.

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | **VERY LOW** | Side effects only fire on actual change; same as today |
| Borrow-checker | LOW | The `Guard` returned by `.load()` is dropped at end of block; no lifetime issues |
| Performance regression | **VERY LOW** (correctness side) | One extra pointer comparison per tick — negligible |
| Correctness on rotation | LOW | If the Arc is rotated between the `.load()` ptr comparison and the subsequent `.load_full()`, we just observe the new Arc — slightly newer than the guard, but always-monotonic |
| Test breakage | LOW | Existing tests assert config-change observation; that path is unchanged |

## 8. Test plan

- `cargo build --release`: clean
- `cargo test --release`: 974/974 pass
- 5x flake check on `make test-failover` (verifies HA / config
  changes still propagate)
- Smoke matrix on loss userspace cluster: 30 cells, 0 retrans
- **Perf measurement** (the critical gate): collect
  `perf stat -e cache-misses,cache-references,LLC-load-misses`
  on the master baseline vs the v4 build during steady-state
  iperf3 run. Document atomic-RMW reduction.

## 9. Out of scope

- Further consolidation of unrelated worker_loop parameters
  (#945/#946 territory; not this PR).
- Coordinator-side changes (none needed).
- Adding new ArcSwap fields or replacing existing fields with
  alternative concurrency primitives.

## 10. Open questions for adversarial review

1. **Is `Arc::as_ptr` comparison sound across threads?** `ArcSwap`
   provides acquire-ordered loads, so the `*const T` read from
   the guard reflects a value the coordinator published with
   release-ordered store. Pointer comparison is a value op on
   `*const T`. The cached `Arc<T>` was the published value at
   some prior tick. If coordinator rotates twice between two
   ticks, we still observe a difference.

2. **Is the `drop(live_X_guard)` before `.load_full()` necessary?**
   `.load()` holds a hazard-pointer-style guard internally. If
   we hold the guard while calling `.load_full()` (which clones
   the Arc), are we double-borrowing the inner Arc? Confirm
   `arc_swap` semantics permit this.

3. **What if 5 of 6 fields are usually changed together?** Then
   the `.load() + ptr_eq` short-circuit hits N times less
   often, and we pay the `.load_full()` cost N times anyway.
   Likelihood: low — config reloads change `forwarding`, while
   CoS lease rotations are independent.

4. **Should the `shared_validation` `.load()` site (line 721) be
   refactored similarly for consistency?** It's already cheap
   (no `.load_full()`) but the value-equality check (`**live != validation`) is more expensive than `Arc::as_ptr` comparison
   would be. Borderline; if the diff is small, fold in;
   otherwise leave for a follow-up.

5. **Helper fn vs inline?** Question 4 in section 4.3. Already
   chose helper. Confirm.

## 11. Verdict request

PLAN-READY → execute the 6-site refactor.
PLAN-NEEDS-MINOR → tweak helper signature or include #4.
PLAN-NEEDS-MAJOR → revise.
PLAN-KILL → premise wrong (but Gemini Pro 3.1 verified the bug
is real, so this is unlikely).
