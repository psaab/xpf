# #1326 Phase 2+ — per-stage carve inside worker/loop_body/

**Status:** DRAFT v1 — pending adversarial plan review.

**KILL is an explicitly invited outcome.** Phase 1 (PR #1569) already
satisfied the original modularity-gate trigger of the issue (mod.rs
went from 2635 to 1359 LOC; the worker_loop body now lives in its
own file at `worker/loop_body/mod.rs`). Phase 2+ is **optional follow-up
decomposition** of the per-tick body itself. If reviewers conclude that
the per-tick body is a single cohesive piece whose split would fragment
ordering invariants or pessimize codegen with negligible offsetting
benefit, **PLAN-KILL is the right verdict** and the issue should be
closed wontfix-with-rationale.

This document is deliberately hostile to its own thesis. The benefit
must be concrete; an aesthetic "1290-LOC file is large" complaint is
NOT sufficient given the cohesion risks below.

## 1. Issue framing

Issue #1326 originally asked for `worker/loop_body/` carved into
named tick phases (`setup.rs`, `tick.rs`, `poll_drive.rs`,
`debug_report.rs`) — as documented in the issue body's "Decomposition
sketch". Phase 1 created the directory and moved the function
verbatim. Phase 2+ would split the function body into sibling files.

## 2. State at master HEAD (e07f733a6)

`userspace-dp/src/afxdp/worker/loop_body/mod.rs` is **1290 LOC**, one
`pub(crate) fn worker_loop` (52 parameters; 1276 LOC body):

| Region | LOC | Content |
|--------|-----|---------|
| L52–L246 | ~195 | One-shot per-worker setup: pin thread, load Arcs, partition private vs shared binding plans, build `cos_owner_live_by_tx_ifindex`, build `cos_fast_interfaces`, allocate poll fds, allocate `dbg_*` accumulators, allocate `wr_*` runtime-attribution counters. |
| L248–L1278 | ~1030 | The `while !stop` per-tick loop. |
| L1279–L1289 | ~11 | Shutdown wrap-up: flush filter counters, release CoS leases, publish final CoS status, store shutdown heartbeat. |

The per-tick body decomposes into the following sub-regions:

| Sub-region | LOC | Purpose |
|------------|-----|---------|
| L249–L281 | ~33 | Worker-runtime attribution (#869): accrue wall_ns/active/idle deltas; ~1s `runtime_atomics.publish()`. |
| L282–L405 | ~124 | **Per-tick Arc short-circuit refresh** (#1188): validation, forwarding, mirror_targets, 6 CoS Arcs. Sets `rebuild_cos_fast_interfaces`. The forwarding-arc branch ALSO mutates `screen_state`, `sessions.set_timeouts`, calls `purge_sessions_for_input_dscp_filter_revalidation`, calls `republish_local_delivery_sessions_for_lo0_filter`, and calls `reset_worker_cos_runtimes` + `apply_shared_recycles_to_bindings`. |
| L406–L436 | ~31 | `rebuild_cos_fast_interfaces` consumer: rebuild `cos_fast_interfaces` map per binding, republish `publish_cos_exact_backlog`. |
| L437–L512 | ~76 | **Command dispatch**: `apply_worker_commands`; #941 `VacateAllSharedExactSlots`; `apply_worker_shaped_tx_requests`; `cancelled_keys` cleanup with `delete_session_map_redirect_for_session`. |
| L513–L541 | ~29 | Heartbeat store; `sessions.expire_stale_entries`; `release_source_nat_allocation`; `delete_session_map_entry_for_removed_session_with_origin`. |
| L542–L564 | ~23 | **Periodic BPF conntrack last_seen** (#333) + fabric Arc rebuild (#121). |
| L565–L609 | ~45 | **Poll all bindings** (`poll_binding` per binding with round-robin `poll_start`). |
| L610–L670 | ~61 | **Debug accumulator updates** (debug-log feature). Aggregates `dbg_poll` into local accumulators. |
| L671–L680 | ~10 | `poll_start` advance + ~100ms `cos_status` publish. |
| L681–L740 | ~60 | **Session delta drain + HA flush** (`drain_deltas` → `purge_queued_flows_for_closed_deltas` → `flush_session_deltas`). Two branches differ only in `session_export_ack` store. |
| L741–L1233 | ~493 | **Periodic ~1s debug report** + per-binding telemetry publish + stall detection. Mostly under `#[cfg(feature = "debug-log")]`. Note: the per-binding atomic publish at L1131-L1231 happens INSIDE this `if elapsed >= DBG_REPORT_INTERVAL_NS` branch — meaning the published BindingLive atomics (`dbg_tx_ring_full`, `umem_inflight_frames`, etc.) only update every ~5s (`DBG_REPORT_INTERVAL_NS`), not every tick. |
| L1234–L1277 | ~44 | Idle/work classification + poll mode sleep (BusyPoll spin/sleep, Interrupt poll). |

## 3. Honest scope/value framing

### 3a. What's the concrete win?

A) **Aesthetic LOC**: `loop_body/mod.rs` goes from 1290 LOC to ~250
LOC orchestrator + 6-8 sibling files of ~50-500 LOC. The orchestrator
becomes a list of named tick phases.

B) **perf-top symbol granularity**: today every cycle attributable to
the per-tick loop body shows up as one symbol (`worker_loop`).
Splitting yields per-phase symbols visible in `perf top`/`perf record`.

C) **Future-add discoverability**: a new "publish epoch X" or "refresh
Arc Y" hook can be added in the obvious place without touching a 1278-LOC
function.

### 3b. What's the win NOT?

- **NOT a perf improvement.** This is pure code motion; the inliner
  must reconstruct what the monolithic body already gives the codegen.
  Realistic outcome: zero perf change if `#[inline]` is applied
  correctly; small perf regression if a sub-fn's borrow shape forces
  the compiler to spill a previously-register-resident variable.

- **NOT a maintainability win for hot-path edits.** Edits to the
  per-tick body in master HEAD are mostly small additions to existing
  sub-regions (publish a new counter, refresh a new Arc). The 1278-LOC
  function reads sequentially top-to-bottom — adding a new Arc refresh
  at line 405 is a 4-line insertion. The same insertion in the split
  layout requires opening `arc_refresh.rs`, adding the load, AND
  potentially threading a new `rebuild_*` flag back to the
  orchestrator. **Code motion does not improve this.**

- **NOT a borrow-shape win.** The function currently lives in one
  borrow scope, which lets `bindings`, `sessions`, `screen_state`,
  `forwarding`, `mirror_targets`, `shared_recycles`, `dbg_poll` all
  borrow mutably in adjacent regions. Splitting into sub-fns forces
  each sub-fn signature to enumerate every captured mutable borrow.
  Sub-fns with 8-15 `&mut` parameters are worse than the inlined form.

### 3c. Absolute scale of the win

- mod.rs LOC after Phase 1: 1359 (worker/mod.rs) + 1290 (loop_body/mod.rs).
  After Phase 2+: 1359 + ~250 (loop_body/mod.rs orchestrator) + ~1040
  spread across 6-8 sibling files. **Net LOC: unchanged.**
- Engineering-style modularity gate: 1290 LOC loop_body/mod.rs is
  **below** the >2000 LOC file gate that triggered #1326. The 1278 LOC
  fn IS above the engineering-style ">200 LOC fn" gate — but that gate
  exists for tight short routines like `poll_binding`, not for per-tick
  worker orchestrators which are inherently sequential.
- perf-top granularity gain: small. In practice the worker-loop CPU is
  spent inside `poll_binding` (already its own symbol), shared-recycle
  application, session-delta flush, and the debug-log build (when
  feature is enabled). The skeleton tick scheduling is <2% of cycles.

**If reviewers conclude the perf/maintainability gain is too small to
justify the churn, PLAN-KILL is an acceptable verdict.**

## 4. What's already shipped

- **#946 Phase 1**: per-stage code motion inside `poll_binding` body
  (`afxdp/poll_stages.rs`). 6 stages extracted; Phase 2 of #946
  (batched per-stage iteration) was PLAN-KILLED because
  flow_cache + session table + MissingNeighbor are order-coupled.
- **#1326 Phase 1 (PR #1569)**: file-level extraction of `worker_loop`
  body from `worker/mod.rs` into `worker/loop_body/mod.rs`. Pure code
  motion. Cleared the >2000 LOC modularity-gate concern.
- **#1188**: per-tick Arc short-circuit (`.load() + Arc::ptr_eq +
  Guard::into_inner`) — already encoded as `load_arc_if_changed` and
  used at every Arc refresh site in the current loop body.
- **#959**: BindingWorker sub-struct decomposition (10 sub-files:
  telemetry/scratch/cos_state/tx_counters/bpf_maps/timers/tx_pipeline/
  bind_meta/flow_cache_state/xsk_rings).

## 5. Concrete design

### 5a. Candidate split (only if reviewers ratify)

```
worker/loop_body/
  mod.rs                  pub(crate) fn worker_loop — ~250 LOC orchestrator
                          + the `WorkerLoopState` bundle struct
                          + the `WorkerCounterBundle` debug-log bundle struct
  setup.rs                One-shot pre-loop setup (L52–L246)
                          fn build_worker_loop_state(...) -> WorkerLoopState
                          fn build_initial_cos_fast_interfaces(...) -> CosFastInterfaces
                          (CosFastInterfaces is the existing per-binding map type)
  arc_refresh.rs          Per-tick Arc short-circuit + dependent state updates (L282–L405)
                          fn refresh_shared_arcs(state, shared_*) -> ArcRefreshOutcome
                          ArcRefreshOutcome { rebuild_cos_fast_interfaces: bool, purged_input_dscp: u32, republished_lo0: u32 }
                          The forwarding-arc branch's side effects (screen_state,
                          sessions.set_timeouts, purge_sessions_*, republish_*,
                          reset_worker_cos_runtimes, apply_shared_recycles_to_bindings)
                          stay INSIDE refresh_shared_arcs to preserve ordering.
  cos_rebuild.rs          fn rebuild_cos_fast_interfaces_if_dirty(state, dirty)
                          Consumer of the dirty flag from arc_refresh (L406–L436).
  commands.rs             apply_worker_commands dispatch + #941 vacate dispatch +
                          shaped_tx + cancelled_keys (L437–L512).
                          fn dispatch_pending_commands(state) -> WorkerCommandResults
  session_maintenance.rs  Heartbeat store + expire_stale_entries + release_source_nat +
                          delete_session_map_entry (L513–L541)
                          + periodic BPF conntrack last_seen refresh (#333) (L542–L553)
                          + fabric arc rebuild (#121) (L554–L564).
                          fn run_session_maintenance(state, loop_now_ns)
  poll_drive.rs           Poll all bindings (L565–L609) + dbg_poll aggregation
                          (L610–L670) + poll_start advance + cos_status publish
                          (L671–L680). fn poll_all_bindings(state, dbg) -> bool (did_work)
  session_delta_flush.rs  Session delta drain + HA flush (L681–L740).
                          fn flush_session_deltas_if_pending(state, exported_sequences)
  debug_report.rs         Periodic ~1s debug report + telemetry publish + stall
                          detection (L741–L1233). All gated by #[cfg(feature = "debug-log")]
                          where possible; the non-debug-log path is the per-binding
                          atomic publish at L1131-L1231, which RUNS REGARDLESS of the
                          debug-log feature but is gated by the same DBG_REPORT_INTERVAL_NS
                          throttle (see open question Q1).
                          fn debug_report_if_due(state, debug_counters, loop_now_ns)
  poll_sleep.rs           Idle/work classification + poll-mode sleep (L1234–L1277).
                          fn classify_and_maybe_sleep(state, did_work, &mut idle_iters, poll_mode, ...)
```

### 5b. The `WorkerLoopState` bundle

Per the issue body, the function takes 52 parameters at signature
position. Threading 52 args through 8 sub-fns is unworkable. Bundle into
a per-worker mutable state struct, owned by `worker_loop` and passed
`&mut` to each sub-fn:

```rust
pub(crate) struct WorkerLoopState<'a> {
    pub worker_id: u32,
    pub bindings: Vec<BindingWorker>,
    pub binding_lookup: WorkerBindingLookup,
    pub sessions: SessionTable,
    pub screen_state: ScreenState,
    pub forwarding: Arc<ForwardingState>,
    pub validation: ValidationState,
    pub mirror_targets: Arc<MirrorTargetMap>,
    pub cos_owner_worker_by_queue: Arc<BTreeMap<(i32, u8), u32>>,
    pub cos_owner_live_by_queue: Arc<BTreeMap<(i32, u8), Arc<BindingLiveState>>>,
    pub cos_shared_root_leases: Arc<BTreeMap<i32, Arc<SharedCoSRootLease>>>,
    pub cos_shared_exact_backlogs: Arc<BTreeMap<i32, Arc<SharedCoSExactBacklog>>>,
    pub cos_shared_queue_leases: Arc<BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>>,
    pub cos_shared_queue_vtime_floors: Arc<BTreeMap<(i32, u8), Arc<SharedCoSQueueVtimeFloor>>>,
    pub shared_recycles: Vec<RecycleFrame>,
    pub bpf_fds: BpfMapFds, // bundles session_map_fd + conntrack_v4_fd + conntrack_v6_fd
    pub shared_arcs: &'a SharedArcs, // refs to the 52-arg shared_* inputs
    // ...
}
```

This is the **shape that triggers PLAN-KILL risk**. The state bundle
collects 30+ fields that all need `&mut` at different points. Each sub-fn
takes `&mut WorkerLoopState`, which means **the entire state is locked
for the duration of the sub-fn**. That's a regression vs the inlined form,
where each `&mut` is taken only on the specific field needed and a
neighbouring `let` can read another field concurrently.

The alternative (passing each `&mut field` individually as a sub-fn arg)
gives the 8-15-arg ugly sub-fns described in §3b. **Neither is good.**

### 5c. Compiler/codegen impact

- All sub-fns mark `#[inline]`. None mark `#[inline(always)]` (per
  #1188 plan-review feedback: always-inline removes the codegen unit's
  ability to choose). Verify post-merge: `nm release/userspace-dp |
  grep worker_loop` to confirm the orchestrator survived as a single
  symbol with sub-fns inlined.
- Binary size delta budget: ±0.5%. Measure on release build.
- Hot-path register pressure: verify the per-tick `poll_binding` call
  site at L573-L606 still passes its arguments by register, not stack
  spill, after splitting. `cargo asm` on `poll_drive::poll_all_bindings`.

## 6. Public API preservation

- `pub(crate) fn worker_loop(<52 args>)` — signature unchanged. The
  `worker/mod.rs` re-export `pub(crate) use loop_body::worker_loop;`
  stays unchanged. No external caller touched.
- All helpers currently called from `worker_loop` (`apply_worker_commands`,
  `poll_binding`, `flush_session_deltas`, `refresh_bpf_conntrack_last_seen`,
  `build_worker_cos_fast_interfaces`, etc.) remain at their current
  paths. No symbol renames.

## 7. Hidden invariants the change must preserve

### 7a. Side-effect ordering

The current per-tick order is non-negotiable:

1. WorkerRuntime accrual (must happen FIRST so deltas are attributed
   to the previous tick's `wr_state`).
2. Arc refresh (validation/forwarding/CoS/mirror/fabric). Forwarding-
   arc refresh MUST set `rebuild_cos_fast_interfaces = true` BEFORE the
   consumer at L406 sees the dirty flag. CoS-arc refreshes ALSO set
   the same flag.
3. `rebuild_cos_fast_interfaces` consumer — rebuilds the per-binding
   map and republishes exact backlog before any TX work.
4. Command dispatch — `apply_worker_commands` returns
   `WorkerCommandResults` whose `shaped_tx_requests` and `cancelled_keys`
   feed shared_recycles in the same tick.
5. Heartbeat store + session expiry + BPF conntrack refresh + fabric
   refresh — must all complete before `poll_binding` so the poll sees
   current forwarding + session state.
6. `poll_binding` per binding (round-robin).
7. `dbg_poll` aggregation (post-poll, before delta flush).
8. CoS status publish (~100ms throttle).
9. Session delta flush (after poll so deltas from this tick's poll
   are flushed).
10. Periodic debug report + per-binding telemetry publish.
11. Idle/work classification + sleep.

**Any sub-fn split that breaks this order is wrong.** The plan keeps
the orchestrator calling sub-fns in exactly this sequence.

### 7b. Allocation rules

`shared_recycles` is pre-allocated `with_capacity(RX_BATCH_SIZE * 2)`
ONCE at L124 and reused in-place every tick. The sub-fn split MUST NOT
move that allocation inside a sub-fn (would re-allocate every tick) and
MUST NOT clone it across sub-fn boundaries. Pass as `&mut Vec<...>`.

Same for `dbg_poll` (`DebugPollCounters::default()` is currently created
fresh every tick at L566 — that's fine, stack-allocated zero-init).

### 7c. HA sync invariants

Session delta flush at L681-L740 emits HA sync deltas. The
`flush_session_deltas` call site uses `bindings.first()` for the worker's
identity — if the split puts this in `session_delta_flush.rs`, it MUST
still pass `&bindings` (not a clone) and pull `bindings.first()` itself.

### 7d. Stale-handle / borrow-shape

The `forwarding` Arc is refreshed at L291-L351 and AGAIN at L557-L564
(fabric Arc rebuild). The fabric branch builds a NEW `Arc::new(updated)`
from `(*forwarding).clone()`. After this rebuild the local `forwarding`
binding points at a different Arc than `shared_forwarding`. Subsequent
sub-fns that need `forwarding` MUST see the locally-updated copy, not
re-load from `shared_forwarding`. The state bundle (§5b) covers this
by holding the local `forwarding` field directly.

### 7e. The DBG_REPORT_INTERVAL_NS gate hides non-debug-log work

L1131-L1231 publishes `BindingLiveState` atomics
(`dbg_tx_ring_full`, `umem_inflight_frames`, etc.) — these are read by
the daemon's `show chassis forwarding`. They run INSIDE the
`if elapsed >= DBG_REPORT_INTERVAL_NS` branch, which means even in
non-debug-log release builds, these atomics only update every ~5s.

This is either:
- (a) **a known throttle** (5s update interval for diagnostic atomics
  is acceptable — `umem_inflight_frames` is sampled, not summed); or
- (b) **a pre-existing bug** that the original Phase 1 mechanical
  move preserved verbatim.

Phase 2 must preserve current behavior exactly — i.e. KEEP the
throttle. A separate issue can be filed to lift the publish out of
the throttle if (b) is the truth. **The split must not silently change
the publish cadence.**

## 8. Risk assessment

| Risk class | Level | Reasoning |
|------------|-------|-----------|
| Behavioral regression | MEDIUM | 11-step per-tick ordering must be preserved. Most likely break: misplacing a sub-fn call that the linear body had at a specific position. |
| Lifetime / borrow-checker | HIGH | 30+ field state bundle vs 8-15 individual `&mut` args. Either form is fragile. Real risk that some pair of sub-fns needs concurrent `&mut` on disjoint state, which the bundle prevents. |
| Performance regression | LOW-MEDIUM | Inliner usually recovers monolithic codegen IF `#[inline]` is applied correctly. Real risk: sub-fn arg spill at boundaries. Mitigate with `cargo asm` + objdump + iperf-12 reverse smoke. |
| Architectural mismatch (#961/#946-Phase-2) | **HIGH** | This is the central risk. The loop body is a sequential dispatch where each region writes state that downstream regions read. The "named tick phases" model assumes phases are loosely coupled. **In this body, phases are tightly coupled by `rebuild_cos_fast_interfaces`, the `forwarding` Arc, `shared_recycles`, and the `did_work` flag.** This is the exact pattern that PLAN-KILLED #946 Phase 2. |

## 9. Test plan

Standard for refactors:
- [x] `cargo build` clean, no new warnings.
- [x] `cargo test --release` full suite (1487+ tests).
- [x] 5/5 flake on worker-related tests (`shared_binding_plan_*`,
      `publish_tx_completion_ring_telemetry_*`,
      `cos_runtime_config_changed_*`).
- [x] Go suite: 30 packages pass.
- [ ] **NOT smoking per-PR**: this PR is part of the wave-1 refactor
      batch (per `MEMORY.md::feedback_retirement_batch_smoke_at_end`).
      Post `<!-- AWAITING-BATCH-MERGE -->` and let the batch smoke
      catch it.
- [ ] `cargo asm` on `worker_loop` to verify sub-fns inline. Capture
      release-build binary size delta (±0.5% budget).

## 10. Out of scope (explicitly)

- Behavioral changes to ANY of the 11 tick phases.
- Lifting the `DBG_REPORT_INTERVAL_NS` gate on `BindingLiveState`
  atomic publish (§7e — separate issue if needed).
- Changing `BindingWorker` sub-struct layout (#959 settled it).
- Touching `poll_binding` body — that's #946's territory.
- Adding new per-tick logic (publishers, refresh paths). The split is
  pure code motion ONLY.
- The 16-param `BindingWorker::create` ctor refactor (originally in
  issue #1326 body) — that's #961's territory.

## 11. Open questions for adversarial review

Each question is invitable to PLAN-KILL.

**Q1.** L1131-L1231 publishes BindingLive atomics inside the
`DBG_REPORT_INTERVAL_NS` branch. Is that an intentional 5s throttle
on `umem_inflight_frames` and ring-pressure counters, or a pre-existing
bug that Phase 1 mechanical move preserved? Either way Phase 2 must
preserve it — but if the reviewer concludes this is a bug that should
be fixed FIRST, the right answer is PLAN-KILL Phase 2 until that's
separately resolved.

**Q2.** The `WorkerLoopState` bundle (§5b) collects 30+ mutable fields.
This makes every sub-fn take `&mut WorkerLoopState`, which locks the
entire state for the sub-fn's duration. Is that strictly worse than the
current monolithic form where each field is independently borrowed?
If yes, what's the alternative — individual `&mut field` args (8-15
per sub-fn signature)?

**Q3.** The `forwarding` Arc-refresh branch at L291-L351 has 5
side-effects (screen state, sessions timeouts, input-DSCP purge,
lo0 republish, CoS reset). These are tightly tied to the Arc-refresh
ordering. Pulling them into a separate sub-fn means that sub-fn now
mutates `screen_state`, `sessions`, `bindings`, `shared_recycles`. That
is ~7-8 sub-struct touches in a single helper. Is the new helper more
readable than the linear branch, or LESS readable because the
forwarding-arc-update side-effects are now hidden behind a sub-fn name?

**Q4.** `rebuild_cos_fast_interfaces` is a boolean flag that 5 separate
Arc-refresh branches set, and one consumer at L406 reads. After the
split, `arc_refresh::refresh_shared_arcs` returns an `ArcRefreshOutcome`
struct, and the orchestrator passes it to `cos_rebuild::*`. Is that
explicit "dirty flag returned by sub-fn" form better than the in-scope
local variable? Or have we just moved the coupling from a local var to
a struct return?

**Q5.** Phase 1 of #1326 was justified by the >2000 LOC modularity
gate. Phase 2 has no such hard trigger — `loop_body/mod.rs` at 1290 LOC
is below the file-LOC gate, and the >200 LOC fn gate doesn't realistically
apply to per-tick worker orchestrators which are inherently sequential.
**What's the concrete next-edit scenario where Phase 2 measurably helps?**
If reviewers cannot name one, PLAN-KILL.

**Q6.** Compare to the PLAN-KILLED #946 Phase 2: that one died because
flow_cache, session table, and MissingNeighbor were order-coupled across
"stages" the plan wanted to separate. Phase 2 of #1326 carves a body
that is ALSO order-coupled (11 tick phases with explicit ordering
dependencies). What makes this one different from #946 Phase 2? Is it
genuinely different, or is the same architectural mismatch waiting to
bite us at implementation time?

**Q7.** perf-top granularity gain claim: the orchestrator currently shows
up as `worker_loop`. After the split, sub-fns show up if NOT inlined.
But §5c says we want sub-fns to inline. Resolve the contradiction: do
we want inlined sub-fns (no perf-top gain) or out-of-line sub-fns
(measurable boundary cost)? Can't have both.

## 12. Recommended verdict from the author

**PLAN-KILL.** The work is achievable mechanically but the value is
insufficient to justify the borrow-shape complexity and architectural
mismatch risk. Specifically:

1. The 11-phase per-tick ordering is the function's defining cohesion.
   Splitting along that boundary either (a) preserves cohesion via a
   `WorkerLoopState` bundle that locks all 30 fields for each sub-fn,
   or (b) leaks the cohesion through 8-15-arg sub-fn signatures.
   Neither is better than the inlined form.

2. The win is aesthetic LOC and (claimed) perf-top symbol granularity,
   the latter contradicted by the necessary `#[inline]` annotations.

3. Phase 1 already extracted the meaningful seam (file boundary, isolating
   the body from `worker/mod.rs`). The remaining 1290 LOC is one sequential
   per-tick orchestrator. Carving it further fragments a single cohesive
   piece without delivering a concrete edit-pattern win.

4. The pattern (per-stage carve of an order-coupled sequential body) is
   the same one that PLAN-KILLED #946 Phase 2. The right outcome is to
   close #1326 wontfix-with-rationale, with #1326 Phase 1 (PR #1569) as
   the achievable shipped scope.

Reviewers may disagree — that's the point of dispatching Codex + AGY
independently. If either reviewer can name a concrete next-edit scenario
that Phase 2 measurably helps with, or can demonstrate the borrow shape
is cleaner than the author claims, PLAN-READY is the right verdict.
But absent that, PLAN-KILL stands.
