---
status: v10 FINAL — Codex round-10 PLAN-READY. Implementation uses Option A (tests call `super::supervisor::*` directly; cleanest path, no re-export needed). Plan rounds 1-10 progression preserved in git history
issue: #1189
phase: First incremental migration of one manager surface
---

## 1. Issue framing

Issue #1189: `coordinator/mod.rs` is currently 1,959 lines
("3,000-line monolith" in the issue body — actual count is
1,959, with manager stubs already split out as separate files
totalling ~290 LOC). Codex's Tier D review confirmed direction
is right but premise is partially stale (decomposition started,
just not finished).

Current state:

```
coordinator/
  bpf_maps.rs            16 LOC
  cos_state.rs           26 LOC
  ha_state.rs            25 LOC
  inject.rs              154 LOC  (active — packet inject path)
  mod.rs                 1959 LOC (the monolith)
  neighbor_manager.rs    19 LOC   (stub)
  session_manager.rs     30 LOC   (stub)
  status.rs              191 LOC  (active — status surface)
  tests.rs               1016 LOC
  worker_manager.rs      31 LOC   (stub)
```

The named manager files exist as types but are mostly empty
shells; the real logic lives in `mod.rs`'s `Coordinator` impl.

## 2. Honest scope/value framing — v2 (narrowed per Codex round-1)

**Important correction:** `WorkerManager` already exists as a
struct (`coordinator/worker_manager.rs:13-19`) with the right
fields (`live`, `identities`, `handles`, `last_planned_*`).
`Coordinator` already owns it via `pub(in crate::afxdp) workers:
WorkerManager` field. This PR is NOT "create WorkerManager" —
it's **migrate selected worker-related METHODS from `impl
Coordinator` into `impl WorkerManager`**.

**Codex round-1 narrowed the scope.** The original plan said
"extract worker supervision" but Codex caught:

1. The named `Coordinator::spawn_worker` doesn't exist — worker
   spawn is embedded in `Coordinator::reconcile`
   (`mod.rs:322,630`) which passes 12+ deps to `worker_loop`
   (HA runtime, shared forwarding, fabrics, RG epochs, sessions,
   neighbors, slow path, local tunnel, CoS shared maps, event
   stream, panic slots, recent status queues).
2. `WorkerCommand` dispatch is owned by HA paths
   (`ha.rs:40,102,171,310,366`), not just worker supervision.
3. Tests reach private worker state directly via two paths —
   field access (`coordinator.workers.identities/live` at
   `coordinator/tests.rs:312,322,958`; line 1001 is a *comment*,
   not field access) and helper-function calls
   (`super::panic_payload_message` /
   `super::spawn_supervised_worker` /
   `super::spawn_supervised_aux` at
   `coordinator/tests.rs:840,869,889,903,918`). `ha_tests.rs:235`
   reaches `super::ha::*` worker-command sites which are NOT
   moved in Phase 1. See section 3 for the test-surface
   treatment.

So `reconcile` and HA command dispatch CANNOT migrate cleanly
in Phase 1. They span too many managers' state.

**Phase 1 v2 — concrete movable slices only:**

- `panic_payload_message` helper (free function or method;
  pure formatting)
- `spawn_supervised_worker` / `spawn_supervised_aux` (the panic-
  catch wrapper; depends only on `WorkerHandle` lifecycle, no
  cross-manager state)
- Worker stop/clear loops at `mod.rs:202-222` (iterate
  `self.workers.handles` to send shutdown / await joins / clear)
- `last_planned_workers` / `last_planned_bindings` accessor
  methods (currently inline; pure getter wrappers)

**Stays on `Coordinator` for Phase 1:**

- `reconcile` (multi-manager state)
- HA command dispatch in `ha.rs` (HA-owned)
- `refresh_bindings` (CoS / forwarding / worker state span)
- CoS refresh
- Neighbor monitor
- Local tunnel source spawning

**Follow-up phases (not this PR):** larger extractions of
`reconcile` or HA dispatch require a `WorkerSpawnDeps` /
context type design — out of scope here.

Win for Phase 1:
- `coordinator/mod.rs` shrinks by ~50-150 LOC (the panic /
  shutdown / accessor helpers)
- `worker_manager.rs` grows from 31 LOC stub with `new()` only
  to ~120-200 LOC with the migrated methods
- Validates the migration shape (small struct + sibling
  module + `pub(in crate::afxdp)` field for test access) before
  larger extractions like `reconcile` or HA dispatch
- This is a **behavior-preserving refactor**. The supervisor
  helpers (`panic_payload_message`, `spawn_supervised_worker`,
  `spawn_supervised_aux`) move into `coordinator/supervisor.rs`
  with their bodies essentially intact, but **module-relative
  paths must be rewritten** because `super::` resolves to a
  different parent after the move. Concretely, the
  `Arc<super::worker_runtime::WorkerRuntimeAtomics>` parameter at
  `mod.rs:1924` becomes `Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>`
  (or `super::super::worker_runtime::WorkerRuntimeAtomics`) in
  the new file. See section 4 step 8. The stop loop becomes
  `WorkerManager::stop_and_clear(...)` with explicit fd inputs;
  body is the same logic with `self.workers.` references
  rewritten to `self.`. Accessors are obviously not byte-
  identical. No observable behavior change in any case.

**Hard rule (Codex round-1 #4):** WorkerManager methods MUST
NOT take `&mut Coordinator`. If a method needs Coordinator-only
state, it stays on Coordinator.

## 3. Code paths affected

### `coordinator/mod.rs` — items leaving the file

Phase 1 v5 moves five concrete slices out of `mod.rs`:

1. **`panic_payload_message(payload: &Box<dyn Any + Send>) -> String`**
   — pure free function at `mod.rs:1849`. Becomes a `pub(super)`
   free function in a new `coordinator/supervisor.rs` (rationale
   below).
2. **`spawn_supervised_worker(...)`** — the panic-catch wrapper
   for the per-worker `worker_loop` thread. Pure code motion to
   `coordinator/supervisor.rs` as a `pub(super)` free function.
   It already takes its dependencies as parameters and does not
   touch `Coordinator` or `WorkerManager` state.
3. **`spawn_supervised_aux(...)`** — the panic-catch wrapper for
   *non-worker* aux threads (currently used by the neighbor
   monitor at `mod.rs:780` and the local-tunnel source at
   `mod.rs:830`). This is **not** worker-lifecycle and must not
   live on `WorkerManager`. Lands in `coordinator/supervisor.rs`
   alongside `spawn_supervised_worker` as a `pub(super)` free
   function.
4. **Worker stop/clear loop** at `mod.rs:202-222` (inside
   `Coordinator::stop_inner` at `mod.rs:187`, called by both
   `stop` and `stop_with_event_stream`). Iterates
   `self.workers.handles` to send shutdown / await joins / drop
   `xsk_map`/`heartbeat_map` entries / clear `handles`. Becomes
   a method `WorkerManager::stop_and_clear(&mut self,
   xsk_map_fd: Option<&OwnedFd>, heartbeat_map_fd: Option<&OwnedFd>)`
   — see section 4 step 3 for the full signature and body.
   `OwnedFd` here is the project's local
   `crate::afxdp::bpf_map::OwnedFd` (with `pub(super) fd: c_int`
   field), **not** `std::os::fd::OwnedFd`. The map fds live on
   `Coordinator` via `BpfMaps`, not on `WorkerManager`, hence
   the explicit parameters.
5. **Accessor wrappers** for `last_planned_workers` /
   `last_planned_bindings` — trivial `&self` getters added on
   `WorkerManager`. All read sites get updated:
   - `mod.rs:572-573` (stage label inside `reconcile`).
   - `mod.rs:1061` (`num_workers = self.workers.last_planned_workers.max(1)` —
     CoS vtime floor sizing).
   - `coordinator/status.rs:184` (`Coordinator::planned_counts`,
     which currently reads
     `self.workers.last_planned_workers` and
     `self.workers.last_planned_bindings` directly).
   The two write sites at `mod.rs:288-289` (reconcile clear path)
   and `mod.rs:568-569` (reconcile set path) keep direct field
   access — accessors are read-only by design.
   The fields keep `pub(in crate::afxdp)` visibility because
   `reconcile` writes them; the accessors just give callers a
   stable read path. Pure wrapper change; no behavior change.

### What **stays on `Coordinator`** in Phase 1

- `Coordinator::reconcile` (multi-manager state).
- HA `WorkerCommand` dispatch in `ha.rs:40,102,171,310,366` (HA-owned).
- `refresh_bindings` (CoS / forwarding / worker state span).
- `worker_panics.clear()` — the panic-tracking map is a
  `Coordinator` field, not a `WorkerManager` field. Phase 1 keeps
  the clear in `Coordinator` and only moves the handle-iteration
  / join / map-cleanup loop into `WorkerManager::stop_and_clear`.
- Neighbor monitor and local-tunnel source supervision (they
  call `spawn_supervised_aux` after this PR; `Coordinator` still
  owns the join handles).

### `coordinator/supervisor.rs` (new file, ~80-120 LOC)

New sibling of `worker_manager.rs` holding the three free
functions above. Visibility: `pub(super)` so `mod.rs` and
`worker_manager.rs` can call into it without exposing the
helpers crate-wide.

### `worker_manager.rs` grows

From 31 LOC stub (struct + `new()`) to ~60-90 LOC: add
`stop_and_clear(...)` plus `last_planned_workers()` /
`last_planned_bindings()` accessors.

### Test surface

Two distinct kinds of test reaches into private worker-related state.

**Direct field access (unaffected by this PR):**

- `tests.rs:312,322` insert into `coordinator.workers.identities`.
- `tests.rs:958` inserts into `coordinator.workers.live`.
- `tests.rs:1001` is a comment about deliberately *not*
  inserting into `coordinator.workers.live` for slot 7 — no
  field access, just documentation; flagging here only because a
  future grep would surface it.

These rely on the existing `pub(in crate::afxdp)` field
visibility on `WorkerManager`'s fields and continue to work
unchanged — the fields keep that visibility because `reconcile`
in `mod.rs` writes them.

**Helper-function calls (require path update):**

- `tests.rs:840` — `super::panic_payload_message(&payload)`
- `tests.rs:869` — `super::spawn_supervised_worker(...)`
- `tests.rs:889,903,918` — `super::spawn_supervised_aux(...)`

After the move, `super::panic_payload_message` etc. no longer
resolve directly inside `coordinator::tests` (because the
helpers have moved to `coordinator::supervisor`). Two equally
valid options — pick one in implementation:

- **Option A (preferred):** update the five call sites above
  from `super::panic_payload_message` →
  `super::supervisor::panic_payload_message` (similarly for
  the other two helpers). Cleaner; no re-export.
- **Option B:** add a private `use supervisor::{panic_payload_message,
  spawn_supervised_worker, spawn_supervised_aux};` in `mod.rs`
  so the existing five test paths stay unchanged. (Rust rejects
  `pub(super) use` of `pub(super)` items as a private-item
  re-export, so the `use` MUST be private — module-scope only.
  An alternative is to widen the helpers to `pub(in crate::afxdp)`
  and use `pub(super) use`, but the private `use` is the cleaner
  fix and keeps visibility minimal.)

**Production helper-call sites in `mod.rs` (require path
update under both Option A and Option B):**

- `mod.rs:679` — `spawn_supervised_worker(...)` from
  `Coordinator::reconcile` (the worker spawn path).
- `mod.rs:780` — `spawn_supervised_aux("neigh-monitor", ...)`
  from the neighbor-monitor setup.
- `mod.rs:830` — `spawn_supervised_aux(format!(...), ...)`
  from the local-tunnel source setup.

These are bare unqualified calls today (the helpers live in the
same module). After the move they need to resolve into
`supervisor::*`. The cleanest fix is a private
`use supervisor::{spawn_supervised_worker, spawn_supervised_aux};`
at the top of `mod.rs` so the three production sites stay
untouched. Note: the production import only needs the two spawn
helpers — `panic_payload_message` is exclusively used by tests
(`tests.rs:840`), so importing it in non-test scope would
trigger an `unused_imports` warning under `#[cfg(not(test))]`
builds. Under Option A the prod `use` covers production calls
and tests use the explicit `super::supervisor::*` path. Under
Option B the prod `use` covers production calls and a
`#[cfg(test)] use supervisor::panic_payload_message;` is added
in `coordinator/mod.rs` (the parent module of `tests`) so that
the existing `super::panic_payload_message` test path at
`tests.rs:840` continues to resolve. Note: a test-module-local
import would *not* satisfy `super::panic_payload_message`
because `super::` from inside the test module resolves to
`coordinator::` (where the symbol must live to be reachable via
that path); the `cfg(test) use` in the parent module gates
the import to test builds without leaking it into prod.

Implementation checklist must touch all five lines (840, 869,
889, 903, 918) under Option A or none under Option B; do not
mix the two.

`ha_tests.rs:235` reaches `super::ha::*` worker-command sites
which are NOT moved in Phase 1 — those tests are unaffected.

## 4. Concrete design

1. Create `coordinator/supervisor.rs`. Move
   `panic_payload_message`, `spawn_supervised_worker`, and
   `spawn_supervised_aux` into it as `pub(super)` free
   functions. Body verbatim (these already take their deps as
   parameters; no receiver change needed).
2. Add `mod supervisor;` to `coordinator/mod.rs`.
3. Add method on `WorkerManager`:

   ```rust
   pub(super) fn stop_and_clear(
       &mut self,
       xsk_map_fd: Option<&OwnedFd>,
       heartbeat_map_fd: Option<&OwnedFd>,
   )
   ```

   where `OwnedFd` is `crate::afxdp::bpf_map::OwnedFd` (the
   project's local newtype, **not** `std::os::fd::OwnedFd`; it
   has a `pub(super) fd: c_int` field). Body is the existing
   `mod.rs:202-222` block with `self.workers.` references
   rewritten to `self.`, preserving the `if let Some(map_fd) =
   ...` conditional cleanup exactly as today:

   ```rust
   for handle in self.handles.values_mut() {
       handle.stop.store(true, Ordering::Relaxed);
   }
   for (_, handle) in self.handles.iter_mut() {
       if let Some(join) = handle.join.take() {
           let _ = join.join();
       }
   }
   if let Some(map_fd) = xsk_map_fd {
       for slot in self.live.keys().copied().collect::<Vec<_>>() {
           let _ = delete_xsk_slot(map_fd.fd, slot);
       }
   }
   if let Some(map_fd) = heartbeat_map_fd {
       for slot in self.live.keys().copied().collect::<Vec<_>>() {
           let _ = delete_heartbeat_slot(map_fd.fd, slot);
       }
   }
   self.handles.clear();
   self.identities.clear();
   self.live.clear();
   ```

   `Coordinator::stop_inner` at `mod.rs:187` (called by both
   `stop` and `stop_with_event_stream`) replaces `mod.rs:202-222`
   with:

   ```rust
   self.workers.stop_and_clear(
       self.bpf_maps.map_fd.as_ref(),
       self.bpf_maps.heartbeat_map_fd.as_ref(),
   );
   self.worker_panics.clear();   // stays on Coordinator
   ```

   The conditional-cleanup behavior is preserved bit-for-bit:
   `Option<&OwnedFd>` is `None` exactly when `bpf_maps.*` is
   `None` today, so the same branches execute in both cases.
   `worker_panics.clear()` stays on `Coordinator` per Codex
   round-2 guidance — `worker_panics` is a Coordinator field,
   not WorkerManager state.

4. Add `last_planned_workers(&self) -> usize` and
   `last_planned_bindings(&self) -> usize` accessors on
   `WorkerManager`. Update mod.rs read sites to call the
   accessors. (Field visibility unchanged: still
   `pub(in crate::afxdp)` for write access in `reconcile`.)
5. Update test paths per Option A or Option B above.
6. Verify nothing else references the three free functions (at
   `mod.rs:1849`, `mod.rs:1894`, `mod.rs:1922`) outside the
   sites listed above. They are free `fn` items in the
   `coordinator` module, not methods on `Coordinator`. After
   the move they live in `coordinator::supervisor`; any leftover
   bare call would fail to resolve and be caught by the
   compiler.
7. **Comment / doc-path cleanup** — the supervisor helper bodies
   include doc comments that reference the helpers' *current*
   location. After the move, three known references go stale and
   must be updated by hand (no `pub(in crate::afxdp)`/
   compiler signal to flag them):
   - `coordinator/mod.rs:1890` (inside the moving
     `spawn_supervised_aux` doc) — "see `recent_exceptions`
     users in this file" still resolves correctly because
     `recent_exceptions` is on `Coordinator` (which stays in
     `mod.rs`); update the wording to "see `recent_exceptions`
     users in `coordinator/mod.rs`" so it remains accurate after
     the helper itself moves to `supervisor.rs`.
   - `docs/operations/worker-supervisor.md:11` — currently
     "`spawn_supervised_worker` in `userspace-dp/src/afxdp/
     coordinator/mod.rs`"; update path to `coordinator/supervisor.rs`.
   - `userspace-dp/src/afxdp/sharded_neighbor.rs:21` — currently
     "`spawn_supervised_worker` in `coordinator/mod.rs`"; update
     path to `coordinator/supervisor.rs`.
8. **Module-relative path rewrites inside the moved helpers** —
   `spawn_supervised_worker` at `mod.rs:1924` takes
   `Arc<super::worker_runtime::WorkerRuntimeAtomics>`. From
   `mod.rs`, `super::` resolves to `coordinator`'s parent
   (`afxdp`); after the move into `coordinator/supervisor.rs`,
   `super::` resolves to `coordinator`, which does **not** own
   `worker_runtime`. The fix in the new file: change to
   `Arc<crate::afxdp::worker_runtime::WorkerRuntimeAtomics>`
   (absolute, robust to further refactors) or
   `Arc<super::super::worker_runtime::WorkerRuntimeAtomics>`
   (relative, two hops up). Pick the absolute form for clarity.
   Re-grep the moved helper bodies for any other `super::*`
   path-bearing references and rewrite the same way; the
   compiler will catch any miss.

**Hard rule (Codex round-1 #4):** WorkerManager methods MUST NOT
take `&mut Coordinator`. `stop_and_clear` complies — it takes
borrowed fds, not the parent.

**Honesty about "pure code motion":** the supervisor functions
move with their bodies essentially intact, but module-relative
paths inside them must be rewritten (see step 8 above —
`super::worker_runtime` no longer resolves correctly after the
move). `stop_and_clear` is **not** byte-identical to the old
loop body — it loses the implicit `self.workers.` qualifier on
every reference and gains explicit fd parameters at the call
site. Behaviorally identical, but the body is rewritten, not
copy-pasted. Accessor wrappers are obviously not byte-identical
either. Phase 1 is "behavior-preserving refactor", not "byte-
verbatim move".

## 5. Public API preservation

No external (non-`afxdp`) signatures change. Within `afxdp`:

- `Coordinator::stop_inner` (`mod.rs:187`) keeps its signature
  (`pub(crate) fn stop_inner(&mut self, clear_synced_state: bool)`);
  its body now calls `self.workers.stop_and_clear(...)` and
  then `self.worker_panics.clear()` in place of the inline
  `mod.rs:202-222` block. Both public callers (`stop` and
  `stop_with_event_stream`) pick up the change transparently.
- `panic_payload_message`, `spawn_supervised_worker`,
  `spawn_supervised_aux` change resolution path from
  `coordinator::*` to `coordinator::supervisor::*`. With
  Option B re-exports their old paths still resolve.
- New: `WorkerManager::stop_and_clear`,
  `WorkerManager::last_planned_workers`,
  `WorkerManager::last_planned_bindings` — all `pub(super)` /
  `pub(in crate::afxdp)`.

## 6. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Supervisor helpers move verbatim; `stop_and_clear` is the same loop with explicit fd params; accessors are trivial getters |
| Borrow-checker / lifetime | LOW-MED | `stop_and_clear` takes `Option<&OwnedFd>` (read-only borrow on `BpfMaps` fields) and `&mut self` for the WorkerManager. The map fds live on `Coordinator` via `self.bpf_maps`, not under `self.workers`, so the split-borrow `self.workers.stop_and_clear(self.bpf_maps.map_fd.as_ref(), self.bpf_maps.heartbeat_map_fd.as_ref())` is clean — disjoint fields |
| Cross-manager coupling | LOW | Phase 1 explicitly excludes anything that spans multiple managers (reconcile, HA dispatch, refresh_bindings, neighbor/tunnel supervision lifecycle) |
| Test path breakage | LOW | Predictable: tests need either updated `super::supervisor::*` paths or a re-export in `mod.rs`. Documented above |
| Performance regression | LOW | `stop_and_clear` runs at shutdown only; accessor wrappers compile to direct field reads |

## 7. Test plan

**Cargo build**: clean.

**Cargo tests**: `cargo test --release` — all 952+ pass.

**5x flake check** on the most affected named test (probably
something in `coordinator/tests.rs`).

**Go tests**: unaffected (Rust-only).

**Smoke matrix on loss userspace cluster**:
- Pass A (CoS off): 6 cells, 0 retrans
- Pass B (CoS on): 24 cells, 0 retrans
- Total: 30 cells, 0 retrans (this is a behavior-preserving refactor — supervisor helper bodies move essentially intact with module-relative path rewrites; stop loop and accessors rewritten in shape but not in behavior)

**Failover smoke**: `make test-failover` if accessible — the
worker-supervision path is exercised heavily during failover.

## 8. Out of scope

- Migrating ConfigManager, NeighborManager, SessionManager —
  each is its own follow-up PR
- Adding tests for `WorkerManager` in isolation (the issue body
  cites "untestable"; making it testable is part of the value
  but adding new unit tests is follow-up work, not blocking
  this PR)
- Renaming any methods or changing signatures
- Splitting `tests.rs` into per-manager test files

## 9. Open questions for adversarial review

1. Is `WorkerManager` the right first target, or would
   `NeighborManager` / `SessionManager` be lower-coupling and
   thus a better Phase 1?
2. How tangled is worker supervision with HA state in the
   current `mod.rs`? If extraction requires touching HA state
   too, that's a Phase 1.5 (or a different first target).
3. Will the 1016-line `tests.rs` break in non-obvious ways?
   Specifically, do any tests construct `Coordinator` and then
   call worker-related private methods?
4. Does the existing `worker_manager.rs` (31 LOC stub) have any
   committed direction the migration must follow, or is it an
   empty starting point?

## 10. Verdict request

PLAN-READY → execute Phase 1 (WorkerManager only).
PLAN-NEEDS-MINOR → tweak choice or scope, then execute.
PLAN-NEEDS-MAJOR → revise (e.g., different first manager).
PLAN-KILL → premise wrong; e.g., extraction structurally
impossible due to coupling.
