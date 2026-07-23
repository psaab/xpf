# #6242 — Per-worker transactional `WorkerRuntimeRecord` — research plan (DRAFT v1)

## 1. Status

- **State:** DRAFT — research + design only. No production code. Awaiting
  hostile plan review (Claude SMR + Codex + AGY) run by the parent.
- **Issue:** #6242 `refactor(userspace-dp): give each worker one transactional
  runtime record` (report id CW-B1-03, Class B, Medium/High).
- **Chain position:** #6241 (typed launch bundles) is **MERGED**; it left an
  explicit `#6242 LIFECYCLE CONTRACT` note in `worker/launch.rs`. #6242
  (this plan) consolidates the per-worker runtime owners. #6240 (OPEN,
  `decompose bring_up_workers into an explicit post-teardown transaction`)
  **CONSUMES** the record this plan defines — #6240's cross-issue
  decomposition assigns #6242 to "own the worker-id runtime record and
  lifecycle registry only".
- **Base:** `origin/master` @ `f199b5240` (includes #6241).
- **Failover-critical:** YES — touches the post-teardown worker bring-up /
  rollback transaction (`bring_up_workers` + `stop_inner`). Any change here
  MUST pass `make test-failover` on the loss userspace cluster before merge.

## 2. Framing — the problem

One worker's runtime is **horizontally owned by four maps** split across two
structs:

| Owner | Type | Key | Struct | Site |
|-------|------|-----|--------|------|
| `handles` | `BTreeMap<u32, WorkerHandle>` | `worker_id` | `WorkerManager` | `worker_manager.rs:30` |
| `worker_panics` | `BTreeMap<u32, Arc<Mutex<Option<String>>>>` | `worker_id` | `Coordinator` | `mod.rs:345` |
| `worker_exception_rings` | `BTreeMap<u32, Arc<Mutex<ExceptionEventRing>>>` | `worker_id` | `Coordinator` | `mod.rs:353` |
| `worker_last_resolution` | `BTreeMap<u32, Arc<Mutex<Option<ResolutionEvent>>>>` | `worker_id` | `Coordinator` | `mod.rs:357` |

`WorkerHandle` (`types/runtime.rs:20-37`) itself already carries
`stop / heartbeat / commands / session_export_ack / cos_status /
runtime_atomics / cold_path_atomics / join`. So a single worker's lifetime
is scattered across `WorkerManager.handles` **plus** three sibling
`Coordinator` maps, all keyed by the same `worker_id`, none of which are
registered or rolled back as one unit.

Because registration is multi-map and hand-sequenced, every lifecycle edit
has to touch several disjoint sites and keep their order straight. #5289
(per-worker exception rings + last-resolution) is the most recent map added
at coordinator scope rather than folded into the worker record, and it left
a **concrete drift artifact**: a double-clear (see §4). Each new worker-scoped
status channel today means "another map + another hand-maintained
insert/remove/clear triplet."

## 3. Honest scope / value

**What this buys (correctness + maintainability, NOT perf):**

- Eliminates the multi-map registration/rollback hazard: worker runtime
  becomes **one `insert` and one `remove`/`clear`**, keyed by `worker_id`.
- **Removes the #5289 double-clear dead code** in `stop_inner` (§4) — a real,
  if currently benign, ownership-drift artifact.
- **Deletes the three hand-maintained `.remove(&worker_id)` calls** on the
  spawn-failure arm (`bringup.rs:572/576/577`) by moving registration to
  post-spawn-success, so a failed worker never had slots to unwind.
- Collapses the cross-map join in `worker_runtime_snapshots`
  (`handles.iter()` + `worker_panics.get(worker_id)`) into a single record
  read.
- Unblocks #6240 (the `bring_up_workers` transaction decomposition), which is
  explicitly waiting on this record type.

**This is NOT a performance change.** The packet path never reads any of the
four maps — workers hold direct `Arc` clones (§7). Grouping the coordinator
maps changes no layout, atomic, cache line, `ArcSwap` publication, packet
allocation, dispatch, endian, or XSK/UMEM ownership. The win is purely the
elimination of a drift-prone, multi-owner lifecycle.

**PLAN-KILL is acceptable** if consolidating forces the #4952 **differential
rollback** (spawn-fail keeps launched workers; bind-incomplete clears all —
§7) into a fragile flag-laden record that is genuinely worse to reason about
than the four separate maps. The differential is the crux; if the record
cannot preserve it cleanly, do not ship.

## 4. What's shipped (the substrate this must not break)

- **#5289** — per-worker POD exception rings + last-resolution slots
  (`worker_exception_rings` / `worker_last_resolution`), replacing the
  process-global mutex DoS. Introduced the two coordinator maps this record
  absorbs; also introduced the **double-clear** (see below).
- **#925** — per-worker `worker_panics` panic-payload slot.
- **#4952** — post-teardown worker-**spawn**-failure fails the reconcile
  closed **without** tearing down already-launched workers (the DIFFERENTIAL
  rollback). Test: `reconcile_post_teardown_worker_spawn_failure_fails_closed_4952`
  (`tests.rs:3789`) — but it uses ONE worker, so partial-success cleanup is
  UNCHARACTERIZED.
- **#5143** — post-spawn in-thread bind-incomplete fails closed and DOES
  `stop_inner(false)` (stop + join + clear ALL workers). Test:
  `post_spawn_inthread_bind_failure_fails_closed_5143` (`tests.rs:3866`).
- **#5165 / #6314** — retained monitor/warmer join handles in `stop_inner`.
- **#6244** — typed `ReconcileStage`; `stop_inner` no longer writes
  `last_reconcile_stage`.
- **#6245** — explicit per-slot `BindingSetupFailure` in the startup report.
- **#6241 (just merged)** — 5 typed worker-launch bundles
  (`worker/launch.rs`). Its `WorkerPublishedTelemetry` holds the SAME
  `recent_exceptions` / `last_resolution` `Arc`s registered in the
  coordinator maps, and it carries an explicit **#6242 LIFECYCLE CONTRACT**
  (`worker/launch.rs:230-253`): "the two `Arc`s #6242's future per-worker
  runtime record will own; integrate, don't re-allocate."

### The concrete drift: the #5289 double-clear

In `stop_inner` (`mod.rs`), linear control flow with no early return:

```
:635  self.worker_panics.clear();            // drops ALL panic Arcs
:638  self.worker_exception_rings.clear();    // drops ALL ring Arcs (map now empty)
:639  self.worker_last_resolution.clear();    // drops ALL slot Arcs (map now empty)
 ...
:711  for ring in self.worker_exception_rings.values() { ring.lock().clear() }  // DEAD: map already empty
:716  for slot in self.worker_last_resolution.values()  { *slot = None }        // DEAD: map already empty
```

The content-clear loops at `:711-720` iterate maps that were emptied at
`:638-639`, so they never execute a body. This is the "ownership has drifted"
evidence in CW-B1-03. Harmless today (dropping the `Arc`s frees the rings),
but it is dead code that #6242 removes.

## 5. Concrete design

### 5.1 The record type (in `worker_manager.rs`)

```rust
/// #6242: the complete per-worker runtime, keyed by worker_id. Consolidates
/// the four previously-scattered owners — WorkerManager.handles + the three
/// Coordinator BTreeMaps (worker_panics / worker_exception_rings /
/// worker_last_resolution) — into ONE record so registration and rollback are
/// single-op. Cold-path only: the packet path holds direct Arc clones and
/// never looks up this record (see §7).
pub(in crate::afxdp) struct WorkerRuntimeRecord {
    pub(in crate::afxdp) handle: WorkerHandle,
    pub(in crate::afxdp) panic: Arc<Mutex<Option<String>>>,
    pub(in crate::afxdp) exception_ring: Arc<Mutex<ExceptionEventRing>>,
    pub(in crate::afxdp) last_resolution: Arc<Mutex<Option<ResolutionEvent>>>,
}
```

`runtime_atomics` / `cold_path_atomics` stay INSIDE `WorkerHandle` (unchanged);
the record wraps the handle, it does not flatten it.

### 5.2 Storage

`WorkerManager.handles: BTreeMap<u32, WorkerHandle>` becomes
`WorkerManager.records: BTreeMap<u32, WorkerRuntimeRecord>`. The three
`Coordinator` fields (`worker_panics`, `worker_exception_rings`,
`worker_last_resolution`) and their `new()` inits are **deleted**.

`live` and `identities` stay on `WorkerManager` **unchanged** — they are
**binding-slot**-keyed records, not worker-id records (per CW-B1-03 and
`worker_manager.rs:3-9`). Do not fold them into the worker record.

### 5.3 Registration becomes one op (post-spawn)

Today `bring_up_workers` inserts the three observability slots **before**
spawn (`bringup.rs:373-379`, `:411`) and the handle **after** spawn
(`:545-557`). The record moves ALL of it to post-spawn-success:

1. Build the three `Arc`s as locals (as today).
2. Clone `exception_ring` / `last_resolution` into `WorkerPublishedTelemetry`
   and `panic` into `spawn_supervised_worker` — **exactly as today**
   (`Arc::clone`, share the Arc per #6241's contract; strong_count stays 2,
   bit-identical to master).
3. On `Ok(join)`: assemble the full `WorkerRuntimeRecord { handle: WorkerHandle
   { .. , join: Some(join) }, panic, exception_ring, last_resolution }` and
   `records.insert(worker_id, record)` — **one op**.
4. On `Err`: **nothing was inserted for this worker**, so there is nothing to
   unwind — drop the locals, `break`, propagate. The three
   `.remove(&worker_id)` at `:572/576/577` are **deleted**.

Two construction variants (open question OQ-1):

- **(A) locals-only:** keep the three `Arc`s as plain locals; assemble the
  record inline on `Ok`. Minimal diff, no new type.
- **(B) `PendingWorkerRuntime { panic, exception_ring, last_resolution }`
  with `commit(handle) -> WorkerRuntimeRecord`:** documents the two-phase
  construction and pairs the three `Arc`s so a future edit can't half-wire
  them. **Per the AMEND: NO self-removing borrow into `WorkerManager`, and
  NO `Drop` side effects** — "abort" is just dropping the value (no map
  mutation, no thread signalling). Recommended primary; A is the fallback.

### 5.4 Rollback preserves the #4952 differential (see §7)

- **spawn-fail** → return `Err(Spawn)`; launched workers' records untouched
  (nothing was inserted for the failed worker). `reconcile/mod.rs:402` still
  runs `refresh_bindings`; the caller fails closed; the launched workers are
  reclaimed by the NEXT reconcile's teardown. **Differential preserved.**
- **bind-incomplete** → `stop_inner(false)` → `stop_and_clear` iterates
  `records` (global two-pass, §7), then `records.clear()`. ALL workers torn
  down. Same as today.

### 5.5 `stop_and_clear` (worker_manager.rs) — keep the global two-pass

```rust
pub(super) fn stop_and_clear(&mut self, xsk_map_fd, heartbeat_map_fd) {
    for rec in self.records.values_mut() { rec.handle.stop.store(true, ..) } // pass 1: signal ALL
    for rec in self.records.values_mut() {                                    // pass 2: join ALL
        if let Some(join) = rec.handle.join.take() { let _ = join.join(); }
    }
    if let Some(fd) = xsk_map_fd       { for (&slot,_) in &self.live { delete_xsk_slot(fd, slot) } }
    if let Some(fd) = heartbeat_map_fd { for (&slot,_) in &self.live { delete_heartbeat_slot(fd, slot) } }
    self.records.clear();      // drops handle + panic + ring + last_resolution Arcs together
    self.identities.clear();
    self.live.clear();
}
```

The signal-ALL-then-join-ALL two-pass and the XSK/heartbeat slot deletion
(over `live`, while the coordinator FDs are still open) are **preserved
exactly** — do not collapse into a per-record join. `records.clear()`
subsumes the three `Coordinator.*.clear()` at `mod.rs:635/638/639` and makes
the dead content-clear loops at `:711-720` removable.

### 5.6 Read-site migration (all cold: status ~1 Hz / teardown)

| Site | Today | After |
|------|-------|-------|
| `status.rs:438` `recent_exceptions()` | `worker_exception_rings.values()` | `records.values().map(\|r\| &r.exception_ring)` |
| `status.rs:473` `last_resolution()` | `worker_last_resolution.values()` | `records.values().map(\|r\| &r.last_resolution)` |
| `status.rs:727-748` `worker_runtime_snapshots()` | `handles.iter()` + `worker_panics.get(id)` | `records.iter()`, read `r.handle.*` + `r.panic` (join collapses) |
| `status.rs:491` `cos_statuses()` | `handles.values()` | `records.values().map(\|r\| &r.handle)` |
| `status.rs:704/718` counts | `handles` | `records` |
| `tunnel_supervision.rs:95/232/433` | `handles` is_empty/values | `records` |
| `teardown.rs:55` | `handles.is_empty()` | `records.is_empty()` |
| `bringup.rs:644` `Spawned{handles}` | `handles.len()` | `records.len()` |
| `mod.rs:1132` (cfg(test) seam) | build `WorkerHandle`, insert `handles` | build `WorkerRuntimeRecord` (empty panic/ring/last_resolution), insert `records` |

**Estimated migration surface:** ~20 production sites across 6 files
(`mod.rs`, `worker_manager.rs`, `bringup.rs`, `status.rs`,
`tunnel_supervision.rs`, `teardown.rs`) + ~3 test files
(`status_tests.rs` — 8 map insert/remove sites, `tests.rs` #4952/#5143,
`worker_manager` self-tests).

### 5.7 Docs to update (module contract)

- `coordinator/README.md:26` (the status.rs row describing the per-worker
  rings) + `:99-101` (the #6242 lifecycle-contract pointer).
- `worker/launch.rs:230-253` — resolve the `#6242 LIFECYCLE CONTRACT` note
  from "do NOT integrate here / future" to "integrated: the record reads
  these Arcs".
- `types/runtime.rs` — doc on `WorkerHandle` noting it is now wrapped by
  `WorkerRuntimeRecord`.

## 6. Public API preservation

- **No proto / wire / gRPC change.** The four maps are internal
  (`pub(crate)` / `pub(in crate::afxdp)`); a grep of `proto/` and
  `protocol*` shows zero coupling.
- **Status-surface method signatures + outputs unchanged:**
  `recent_exceptions()`, `last_resolution()`, `worker_runtime_snapshots()`,
  `cos_statuses()` return the same types and the same merged/sorted content.
  Operator-visible `show` output is byte-identical.
- **`ReconcileStage` variants + `Display` strings unchanged**
  (`Spawned{handles,identities,live}` still reports the same counts, now from
  `records.len()`).
- The record type + `records` field are internal; renaming `handles` →
  `records` is a private-visibility change only.

## 7. Hidden invariants (MUST hold)

1. **The #4952 DIFFERENTIAL rollback.** Verified firsthand:
   - `bring_up_workers` spawn-fail arm (`bringup.rs:559-595`) removes ONLY the
     failed worker's pre-spawn slots and `break`s; it returns `Err(Spawn)`
     via `:604-609` **without** calling `stop_inner`.
   - `reconcile/mod.rs:391-417` runs `refresh_bindings` unconditionally, then
     maps `Err(Spawn) → ReconcileError::WorkerSpawn`. Launched workers stay
     live; the caller fails closed; the next reconcile tears them down.
   - Bind-incomplete (`bringup.rs:639`) calls `stop_inner(false)` → ALL
     workers stopped/joined/cleared.
   Under the record (post-spawn insert), spawn-fail has **nothing to remove**
   for the failed worker and **never touches** launched records → differential
   preserved **and** the manual 3× remove vanishes. A naive "one insert / one
   remove that also clears launched workers on spawn-fail" is a #4952
   regression — MUST NOT happen.
2. **Registration order.** Today: three observability slots inserted BEFORE
   spawn, handle AFTER spawn. #6242 moves ALL registration to
   post-spawn-success (the AMEND-endorsed reorder). This is behavior-preserving
   on the observable END STATE (after spawn-fail: launched workers have full
   records, failed worker has none — identical to today); the only difference
   is the elimination of the transient pre-spawn window where a not-yet-spawned
   worker's empty slots were briefly map-visible to a ~1 Hz status reader (no
   operator value). Confirm the reorder is acceptable (OQ-2).
3. **Packet-path read stays non-indirected.** The worker's hot path holds
   DIRECT `Arc` clones of its own `recent_exceptions` / `last_resolution`
   (threaded via `WorkerPublishedTelemetry` → `worker/lifecycle.rs:39-41` →
   `WorkerContext.recent_exceptions/last_resolution`, `types/runtime.rs:550-551`).
   It **never** looks up `WorkerRuntimeRecord`. The record is cold-only
   (status + teardown). The consolidation adds ZERO hot-path indirection —
   this is the load-bearing precondition for the whole refactor.
4. **`stop_and_clear` global two-pass + FD lifetime.** signal-ALL → join-ALL →
   delete XSK/heartbeat slots (over `live`, coordinator FDs still open) →
   clear. Do NOT join one worker while peers are unsignalled; do NOT drop
   coordinator FDs before slot deletion. No per-record `Drop` that
   signals/joins one worker at a time (AMEND).
5. **No double-clear.** After #6242, teardown drops record `Arc`s exactly
   once (`records.clear()`); the dead `:711-720` content-clear loops are
   deleted, not duplicated.
6. **Arc identity / strong_count.** The record must hold the SAME `Arc` the
   worker telemetry holds (share the Arc, not a fresh alloc) — #6241 contract.
   End state strong_count == 2 per Arc, bit-identical to master.
7. **`live` / `identities` stay slot-keyed and separate** — not folded into
   the worker-id record.

## 8. Risk table

| Risk | Severity | Notes / mitigation |
|------|----------|--------------------|
| Breaking the #4952 differential (clearing launched workers on spawn-fail) | **HIGH / failover** | The crux. Post-spawn insert preserves it structurally; add the N-worker forced-failure test (§9) that ASSERTS launched records survive. |
| Post-teardown transaction regression (silent forwarding outage / persisted broken snapshot) | **HIGH / failover** | Keep `bring_up_workers` return-Err-without-stop on spawn-fail; keep `reconcile/mod.rs` mapping. `make test-failover` gate. |
| Borrow-checker friction on the consolidated record | Medium | Two-phase build (Pending → commit) keeps `coord` borrows local to pre-spawn; record assembled from moved-out locals after `coord` is done being borrowed (mirrors #6241's bundle move). |
| Status-surface behavior drift (missing/duplicated exceptions, wrong newest resolution) | Medium | `exception_ring_merge_6101` + `last_resolution` newest-wins tests must stay green; migrate their map-insert seams to `records`. |
| `stop_and_clear` order change breaks FD lifetime or join safety | Medium | Preserve the two-pass verbatim; diff-review the exact sequence. |
| Hidden hot-path lookup introduced by mistake | Medium | Invariant #3; grep that no worker/packet code references `records`. |
| Test-seam churn (`mod.rs:1132`, `force_worker_*`) | Low | cfg(test) only; mechanical. |

## 9. Test plan

- `make test-rust` (full `cargo test --bin xpf-userspace-dp`) + release build.
- **Preserve** `reconcile_post_teardown_worker_spawn_failure_fails_closed_4952`,
  `post_spawn_inthread_bind_failure_fails_closed_5143`,
  `exception_ring_merge_6101`, and the `last_resolution` newest-wins test —
  migrate their coordinator-map seams to `records`.
- **NEW — N-worker differential test (the crux, closes the #4952 one-worker
  gap):** plan **N ≥ 3** workers, force the spawn of worker **N** to fail
  (`force_worker_spawn_fail` after N-1 successes — may need a "fail the Kth
  spawn" seam variant). ASSERT:
  - `reconcile` returns `Err(WorkerSpawn(SpawnWorkerFailed))`;
  - workers `0..N-1` **survive** — `records` contains exactly those N-1 ids,
    each with a live `handle` (join present) AND its `panic` / `exception_ring`
    / `last_resolution` `Arc`s present (only observability, all four owners
    together);
  - the failed worker id is **absent** from `records`;
  - NO `stop_inner` ran (launched workers still heartbeating).
- **NEW — bind-incomplete clears ALL:** with N workers and a forced
  bind-incomplete, assert `records` is **empty** after the fail-closed
  reconcile (contrast with the spawn-fail case above — this is the
  differential, pinned by two symmetric tests).
- **NEW — no double-clear / teardown atomicity:** after `stop_inner`, assert
  `records` empty and all four owners gone in one step.
- **Loss userspace cluster:** `make test-failover` (v4+v6), plus an AF_XDP
  apply/reapply cycle — this is failover-critical control-plane code.

## 10. Out of scope + the #6240 hand-off

**Out of scope for #6242:**

- Splitting `bring_up_workers` into phase modules — that is #6240.
- Touching `live` / `identities` (binding-slot records) — kept separate.
- The worker-launch argument bundles — that is #6241 (merged).
- `BindingSetupFailure` / startup-report detail — that is #6245.
- Any hot-path / worker-loop change.
- Fixing the warmer's ignored spawn result — behavior, not this refactor.

**Hand-off to #6240 — the record shape it consumes:** #6240's cross-issue
decomposition says #6242 owns "the worker-id runtime record and lifecycle
registry only," and #6240 "must not independently redesign runtime records."
So #6240's `bringup/worker_launch.rs` phase and `bringup/readiness.rs`
rollback phase will consume:

- `WorkerManager.records: BTreeMap<u32, WorkerRuntimeRecord>` as the single
  worker-id registry (no more three sibling `Coordinator` maps to thread
  through phase outputs);
- a **post-spawn-success** registration point that is one `records.insert`
  (variant B: `PendingWorkerRuntime::commit(handle)`), so #6240's
  `worker_launch` phase returns a record, not four fragments;
- `stop_and_clear` as the single rollback op for the readiness phase —
  #6240's central rollback calls it and clears one map, and the #4952
  differential is already encoded (spawn-fail returns without it;
  bind-incomplete calls it).

#6240's AMEND explicitly flags that the spawn-vs-bind-incomplete rollback
distinction "needs a separate correctness decision" and "a mechanical
refactor must preserve the distinction." #6242 is where that distinction is
made structural (post-spawn insert), so #6240 inherits it for free.

## 11. Open questions (each PLAN-KILL-invitable)

1. **OQ-1 — Pending type or locals?** Variant B
   (`PendingWorkerRuntime { panic, exception_ring, last_resolution }` +
   `commit(handle)`, drop-to-abort with NO side effects) vs Variant A
   (plain locals, inline assembly on `Ok`). B documents the two-phase
   construction and pairs the Arcs; A is the minimal diff. If B ends up
   needing lifetime/borrow gymnastics or a `Drop` impl to be ergonomic,
   that is a PLAN-KILL signal for B — fall back to A, and if A is just "the
   same four locals with an inline struct" the consolidation value is thinner
   (still removes the 3 coordinator maps + double-clear).
2. **OQ-2 — Is the pre-spawn→post-spawn registration reorder acceptable?**
   It eliminates the transient window where a not-yet-ready worker's empty
   observability slots are map-visible to the status reader. End state is
   identical; is there ANY status/HA path that depends on seeing a slot for a
   spawned-but-not-yet-registered worker? (Firsthand read: no — status is
   ~1 Hz and a phantom empty slot has no operator value. If review finds a
   dependency, the reorder is off and the value drops.)
3. **OQ-3 — Does the record earn its keep, or is it "four locals with extra
   steps"?** If the honest outcome is a rename of `handles`→`records` + a
   4-field struct + ~20 mechanical read-site edits, with the differential
   preserved only by the pre-existing post-spawn discipline, is the drift
   elimination + double-clear removal + #6240 unblock worth the churn — or is
   the cleaner win just "delete the dead `:711-720` loops + fold the two
   #5289 maps into `WorkerHandle`" without a new wrapper type? (i.e. a
   smaller PLAN-KILL-adjacent alternative.)
4. **OQ-4 — Fold into `WorkerHandle` vs wrap it?** Alternative: add `panic`,
   `exception_ring`, `last_resolution` as fields ON `WorkerHandle` (no new
   `WorkerRuntimeRecord` type), keeping `handles` as the single map. Fewer
   moving parts, but blurs "thread handle" vs "observability" and may read
   worse to #6240. Which does review prefer?
5. **OQ-5 — "Fail the Kth spawn" test seam.** The N-worker differential test
   needs to fail spawn N after N-1 successes. `force_worker_spawn_fail` today
   decrements per planned worker (fails the FIRST K). Do we need a
   `force_worker_spawn_fail_at_index` seam, or does re-ordering the planned
   set / setting the counter to fail the last of N suffice? (If a new seam is
   required, that is added test surface to weigh.)
6. **OQ-6 — `stop_and_clear` signature.** It still needs the XSK/heartbeat
   map FDs (they live on `Coordinator.bpf_maps`) and `live` (slot-keyed).
   Confirm the record consolidation does not tempt a signature change that
   would move FD ownership — it must not (FD lifetime invariant #4).
7. **OQ-7 — Do we migrate the `status_tests.rs` seams to `records` in-PR, or
   is there a shared test helper that should own record construction** so the
   8 insert/remove sites don't each hand-build a record?
