# #6240 — decompose `bring_up_workers` into an explicit post-teardown transaction

## 1. Status

`DRAFT v1 — pending adversarial plan review`

Research + plan-draft only. No production source touched. Deliverable is this
plan + the blast-radius survey below, for the parent's hostile plan review.

## 2. Issue framing (in my words)

`bring_up_workers` (`userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs`)
is the tail phase of `Coordinator::reconcile`. It runs on the
**post-teardown destructive path**: `teardown::tear_down` has already stopped
and joined the previous workers, reset `coord.forwarding` /
`coord.shared_validation`, and dropped the old BPF-map FDs, so by the time
`bring_up_workers` runs the data plane has *already moved*. Every failure it
raises is a failure with **no prior state to restore** — only fail-closed
bookkeeping plus a retry / last-good reconcile. That is what makes this
function load-bearing far out of proportion to its line count.

The function has regrown to **626 LOC** (issue snapshot; on current master
after #6348 it is lines **96–764**, and the file is **870 LOC** with three
functions). It now owns ~15 distinct responsibilities: ring validation,
per-worker `BindingPlan` construction, shared-UMEM policy + status projection,
BPF-FD ownership transfer, mirror + six CoS runtime-map publications,
preserved-session replay, on-demand neighbor-resolver launch, the worker spawn
loop (40-argument `worker_loop`, three per-worker status-map registrations,
two `#[cfg(test)]` forced-failure seams), the #4952 spawn-failure early
return, the #5143 startup-readiness barrier + #6348 explicit-failure render +
stop/join rollback, the neighbor monitor + warmer launches, and the local
tunnel / WireGuard reconcile. The ask (CW-B1-01) is a **class-B refactor with
A-only cold extractions**: keep a short explicit transaction shell, extract the
one-shot setup blocks that don't touch rollback/ownership/ordering, and only
then (behind design sign-off) restructure the transactional core.

## 3. Honest scope / value framing

A 626-LOC function with a 40-argument closure inside a 283-LOC loop is a real
modularity hazard: every recent fix (#4952, #5143, #5165, #5289, #6244, #6245,
#6348, #6314) had to edit a distant slice of one body and preserve subtle
ordering by hand. The value of decomposition is **readability + testability**
of that transaction — nothing here is a perf problem. Every proposed boundary
runs once per reconcile, never per packet / per worker tick, so there is no hot
path to protect and no allocation budget to respect; the win is purely being
able to reason about (and unit-test) each phase in isolation.

This is also a **FAILOVER-CRITICAL** path. It runs on every full reconcile,
including on the recovering node after a failover — the #6348 batched smoke
just re-ran it cleanly under `test-failover` (libxdp bind OK, all 18 slots
bound, workers=6). The load-bearing asset is the **post-teardown rollback
contract**, not the code shape. A decomposition that changes *when* or *how*
rollback fires is a real regression on the appliance's failover bring-up.

Verbatim, per the parent's instruction:

> If reviewers conclude the decomposition risks the failover bring-up path more
> than the modularity win justifies, PLAN-KILL is acceptable.

## 4. What is already shipped here (the plan must compose with all of it)

- **#1328** — original per-phase split of `Coordinator::reconcile` into
  `reconcile/{teardown,reset,snapshot,bringup}.rs`. `bring_up_workers` *is* the
  bringup phase from that split; this issue sub-splits it further.
- **#4952** — post-teardown worker-**spawn** failure fails the reconcile closed
  (`WorkerBringUpError::Spawn` → `ReconcileError::WorkerSpawn`). On the first
  spawn failure it **aborts remaining launches, does NOT stop the
  already-launched workers**, preserves the `spawn_worker_failed:` stage, and
  skips the auxiliary bring-up.
- **#5143** — startup-readiness barrier: HEARTBEAT != READINESS. Every spawned
  worker reports the slot set its in-thread XSK/UMEM binds actually brought up;
  on any shortfall/timeout it `stop_inner(false)` (stop+join+clear ALL new
  workers) and returns `WorkerBringUpError::BindIncomplete`.
- **#5165 / #6314** — retain + join the neighbor **monitor** / **warmer** join
  handles (install stop+join together only on successful spawn).
- **#5289** — per-worker exception ring + last-resolution slot (inserted before
  spawn, removed on the spawn-Err arm and in teardown).
- **#6244** — typed `ReconcileStage` progress replaces the `last_reconcile_stage`
  string side-channel; `WorkerBringUpError` carries the typed stage; legacy
  operator strings preserved byte-for-byte via `Display`.
- **#6245** — `WorkerStartupReport` carries explicit typed `BindingSetupFailure`
  (worker+slot+phase+reason); the barrier surfaces the cause into the stage.
- **#6348** — `WorkerBindShortfall.failures` → `ReconcileStage::WorkerBindIncomplete`
  Display renders the explicit per-slot failures (`failures=[private:slot=1:…]`).

**Coupled-issue sequencing (critical, see §8/§11).** The issue's own
design-review amendment defines an ownership order in which #6240 is an
**umbrella that CONSUMES** the types from its siblings and performs only the
*remaining mechanical* phase extraction — it "must not independently redesign
launch bundles, runtime records, setup outcomes, or reconcile status." Current
state on master:

| Issue | Owns | State |
|-------|------|-------|
| #6244 | typed progress/stage | **CLOSED** |
| #6245 | explicit binding-setup failures | **CLOSED** |
| #6246 | unrepresentable prepared-reconcile states | **CLOSED** |
| #6241 | typed worker-launch bundle (the 40-arg protocol) | **OPEN** |
| #6242 | per-worker transactional runtime record | **OPEN** |
| #6243 | unified activated/deferred map-pin preflight | **OPEN** |

The two issues that most directly de-risk the hard block (#6241 launch bundle,
#6242 runtime record) are **still open**. This is the single most important
scoping fact in the plan: PR-2 (the worker-launch restructuring) *is* #6241 +
#6242 territory and should not be attempted ahead of them.

## 5. Concrete design — extraction boundaries

Strongly prefer an increment split. Keep `bring_up_workers`'s signature and its
sole caller (`reconcile/mod.rs:391`) byte-identical; move blocks into free
`fn`s within a `bringup/` submodule directory, preserving side-effect ordering
and every `last_reconcile_stage` write verbatim.

### PR-1 — A-only COLD extractions (behavior-preserving, low risk)

Pure / near-pure one-shot blocks that touch **no** rollback path, **no** FD
ownership transfer, and **no** launch ordering. Each is a free fn that borrows
only what it reads/writes; none borrow `&mut coord` across a launch:

1. **Ring clamp** (`bringup.rs:118–132`, ~15 LOC) →
   `fn clamp_ring_entries(ring_entries: usize) -> u32` (pure; keep the stale-binary
   warn eprintln). *Borrows nothing.*
2. **Shared-UMEM status projection** (`:170–192`, ~23 LOC) →
   `fn project_shared_umem_status(workers: &BTreeMap<u32, Vec<BindingPlan>>, bindings: &mut [BindingStatus])`.
   Reads the built plans, writes four `BindingStatus` fields. *No coord state.*
3. **Per-worker binding-ifindex set** (`:224–235`, ~12 LOC) →
   `fn worker_binding_ifindexes(workers: &…) -> BTreeMap<u32, BTreeSet<i32>>`. *Pure local.*
4. **Command-queue construction** (`:250–256`, ~7 LOC) →
   `fn build_worker_command_queues(worker_ids) -> Arc<BTreeMap<…>>`. *Pure local alloc.*
5. (optional) **plan sort** (`:166–168`) folded into #2's helper or left inline.

Net PR-1 extraction is small — roughly **55–70 LOC** across four pure helpers —
but each is independently unit-testable and removes distracting local machinery
from the transaction shell. **Own smoke is optional** for PR-1 (behavior-preserving,
covered by the existing coordinator/server suite + the #4952/#5143/#5245 tests);
a fail-on-revert is not applicable to pure code motion, so PR-1 relies on the
existing tests still passing plus a `cargo test` + release build.

### PR-1.5 (candidate) — auxiliary-service launch outlines

The three neighbor-service launches are self-contained one-shot blocks, but
each is **ordering-load-bearing**, so they are *not* class-A cold. They can be
outlined into free fns that take `&mut Coordinator` and preserve the guard +
install-together-on-success pattern verbatim:

- `fn ensure_resolver_before_worker_launch(coord: &mut Coordinator)` (`:268–331`, ~64 LOC)
  — **MUST run before** the worker loop (workers clone `coord.neighbors.resolver`
  at `:401`).
- `fn start_neighbor_monitor(coord: &mut Coordinator)` (`:670–712`, ~43 LOC)
  — **MUST run after** the readiness barrier.
- `fn start_neighbor_warmer(coord: &mut Coordinator)` (`:713–756`, ~44 LOC)
  — post-readiness.

These are mechanical `&mut coord` outlines (~150 LOC moved), LOW–MED risk. They
belong on `NeighborManager` per the amendment's suggestion, but a first cut can
keep them as `bringup/` free fns. The load-bearing invariant is the
**relative order vs. the worker launch** (resolver before, monitor/warmer
after) — the extraction must not let the shell reorder them.

### PR-2 — B structural (needs design sign-off + failover smoke; likely BLOCKED on #6241/#6242)

The transactional core that resists clean extraction:

- **BindingPlan build + `coord.workers.live`/`identities` insert** (`:133–165`).
- **BPF-FD ownership transfer** into `coord.bpf_maps` (`:216–223`).
- **CoS/mirror publication** + `refresh_cos_runtime_maps` (`:236–249`).
- **Preserved-session replay** (`:257–267`).
- **The worker spawn loop** (`:336–618`, ~283 LOC): the loop body makes
  **25 `coord.*` clones** and invokes the **40-argument** `worker_loop`, plus
  the two `#[cfg(test)]` forced-failure seams and the three per-worker registry
  inserts (`worker_panics`, `worker_exception_rings`, `worker_last_resolution`)
  that pair with the spawn-Err `.remove(&worker_id)` arm.
- **The two rollback paths** (`:619–632` spawn-fail; `:633–664` bind-incomplete).

A clean `launch_workers(coord, workers, cmd_queues, startup_tx) -> LaunchOutcome`
extraction is only *readable* once the 40-arg `worker_loop` is a typed bundle
(#6241) and the per-worker runtime state is one record (#6242). Attempting it
first means either threading ~25 refs by hand or moving the 25-clone body
wholesale into a helper that still takes `&mut coord` — a move that reduces the
*shell's* size but not the *complexity*, and re-opens every #4952/#5143/#5289
pairing for a re-review with no net structural win. **Recommendation: gate PR-2
behind #6241 + #6242, or fold it into them.**

### Proposed signatures (PR-1)

```rust
fn clamp_ring_entries(ring_entries: usize) -> u32;                    // pure
fn project_shared_umem_status(workers: &BTreeMap<u32, Vec<BindingPlan>>,
                              bindings: &mut [BindingStatus]);         // borrows bindings mut
fn worker_binding_ifindexes(workers: &BTreeMap<u32, Vec<BindingPlan>>)
    -> BTreeMap<u32, std::collections::BTreeSet<i32>>;                // pure
fn build_worker_command_queues(worker_ids: impl Iterator<Item = u32>)
    -> Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>>;       // pure
```

## 6. Public API preservation

- `pub(super) fn bring_up_workers(coord, snapshot, bindings, fds, ring_entries,
  preserved_synced_sessions) -> Result<(), WorkerBringUpError>` — signature
  unchanged.
- Sole caller `reconcile/mod.rs:391` unchanged; the unconditional
  `self.refresh_bindings(bindings)` at `:402` (runs on BOTH success and error)
  and the `bringup_result.map_err(...)` variant mapping stay outside the
  function and are untouched.
- `WorkerBringUpError` (Spawn / BindIncomplete) and its → `ReconcileError`
  mapping unchanged.
- `planned_worker_slots` and `collect_worker_startup_readiness` (already free
  fns in this module) unchanged.

## 7. Hidden invariants — each MUST be preserved

1. **The distinct post-teardown rollback contract (the #1 invariant).** The two
   failures roll back **differently** and this is deliberate:
   - *Spawn failure* (`:619–632`) returns `Err(Spawn)` **WITHOUT** calling
     `stop_inner` — already-launched workers stay live in
     `coord.workers.handles`; the next reconcile's teardown stops them.
     `reconcile/mod.rs:399–402` intentionally `refresh_bindings` the partial
     state ("some workers up, then a spawn aborted the rest").
   - *Bind-incomplete* (`:633–664`) calls `stop_inner(false)` — stops + joins +
     clears ALL new workers, keeping preserved synced sessions.
   A decomposition that unifies these into one "central rollback that always
   stops every launched worker" **changes documented #4952 behavior** and is a
   regression, not a cleanup. Any such change needs a separate correctness
   decision + user sign-off, out of scope for a mechanical refactor.
2. **FD ownership vs. raw descriptors.** `OwnedFd`s move into `coord.bpf_maps`
   (`:216–223`); `BindingPlan` / `DnatTableFds` carry the **raw integer** fds
   (`:155–160`, `:461`) into workers. No phase output or rollback guard may drop
   an `OwnedFd` while any worker can still touch its raw descriptor. `stop_inner`
   already encodes the safe order: stop+join workers → `workers.stop_and_clear`
   deletes XSK/heartbeat slots **while the FDs are still live** (`mod.rs:626`)
   → only then set `bpf_maps.*_fd = None` (`:657–663`). Preserve this ordering.
3. **Resolver-before-launch / monitor+warmer-after-readiness ordering.**
   `coord.neighbors.resolver` must exist before the worker loop clones it
   (`:401`); monitor + warmer start only after the readiness barrier passes
   (`:670–756`). The `... launch → prove readiness → launch auxiliaries` gloss
   is **false for the resolver** — it is a pre-launch auxiliary.
4. **#5143 readiness barrier semantics.** Bounded 10s deadline, `bound ==
   planned` per spawned worker, fail-closed on shortfall/timeout. Verbatim.
5. **#6348 explicit-failure render.** `WorkerBindShortfall.failures` →
   `WorkerBindIncomplete` Display (`failures=[…]` / `[no-explicit-failure]`).
6. **CoS publication before launch.** owner-by-queue + mirror + active-shards +
   `refresh_cos_runtime_maps` (`:236–249`) publish the immutable inputs workers
   read; must precede the spawn loop.
7. **Preserved-session replay timing** (`:257–267`) — seeds the session map +
   command queues before workers launch; count feeds the `ReplayedSynced` stage.
8. **Per-worker registry insert/remove pairing** (#925/#5289): `worker_panics`,
   `worker_exception_rings`, `worker_last_resolution` inserted before spawn,
   `.remove(&worker_id)` on the spawn-Err arm — split across a helper only with
   the payload contract re-validated.
9. **Sparse worker-id sizing** — `last_planned_worker_slots = max(id)+1`, not
   `len()` (v8 lease arrays index by id).
10. **Stage-write ordering** — `Planned` → (`ReplayedSynced`) →
    `SpawnWorkerFailed`|`Spawned`|`WorkerBindIncomplete`; `stop_inner` no longer
    writes the stage (#6244), so the typed identity is recorded once and survives.
11. **Warmer's ignored spawn result** (`:701–713` monitor / warmer) — do NOT
    incidentally "fix" the best-effort `Err` arm; that is behavior, not motion.

## 8. Risk table

| Risk | Level | Notes |
|------|-------|-------|
| Behavioral — rollback semantics changed (unify spawn-fail vs bind-incomplete) | **HIGH** | The #1 invariant. Only PR-2 can trip this; PR-1 cold blocks never touch a rollback path. |
| Failover-path regression (post-teardown bring-up on the recovering node) | **HIGH** for PR-2 / **LOW** for PR-1 | PR-2 mandates `make test-failover`; PR-1 is behavior-preserving pure motion. |
| Borrow-checker — extracting from a body with 25 shared-mutable `coord.*` clones + a 40-arg closure | **HIGH** for PR-2 / **LOW** for PR-1 | This is the crux. PR-1's four helpers borrow only locals / `bindings`; PR-2's launch extraction is genuinely hard until #6241/#6242 land. |
| Architectural mismatch — is "explicit pipeline" the right shape, or does the shared transaction state resist clean extraction? (#946-P2/#961 dead-end class) | **MED–HIGH** | The transaction's shared `&mut coord` state is exactly what makes phase outputs leaky. PR-1 sidesteps it; PR-2 depends on #6241/#6242 supplying the typed bundles that make phase boundaries real. |
| Coupled-issue ordering — #6240 racing/duplicating #6241/#6242 (both OPEN) | **MED** | Mitigation: PR-1 is orthogonal to all siblings; PR-2 is explicitly gated behind #6241 + #6242. |
| Test blind spot — existing #4952 test has ONE worker, cannot characterize partial-success cleanup | **MED** | Add the N-worker forced-failure-on-launch-N test (see §9) BEFORE any PR-2 rollback motion. |
| Docs drift — `docs/userspace-dataplane-architecture.md`, `coordinator/README.md`, `docs/afxdp-packet-processing.md` describe bringup | **LOW** | Update the module map in the same PR that moves code. |

## 9. Test plan

- **Full cargo suite** — `cargo test --manifest-path userspace-dp/Cargo.toml
  --bin xpf-userspace-dp` (short `TMPDIR=/tmp` per the socket-bind gotcha).
- **The bring-up regression tests must stay green and are the fail-on-revert
  anchors** for any behavioral touch: `reconcile_post_teardown_worker_spawn_failure_fails_closed_4952`,
  `post_spawn_inthread_bind_failure_fails_closed_5143`,
  `worker_bind_incomplete_report_carries_explicit_failure_6245`
  (`coordinator/tests.rs:3789/3877/3979`), plus the server no-persist tests
  `post_teardown_spawn_failure_fails_closed_no_persist_4952` /
  `full_apply_post_teardown_spawn_failure_fails_closed_no_persist_6140` /
  the bind-incomplete server test (`server/tests.rs`).
- **New test (required before PR-2 rollback motion):** an **N-worker** forced
  failure on launch N — pin exact `workers.handles`/`live` contents, auxiliary
  start state (no monitor/warmer before readiness), FD retention, stage text,
  and session preservation for BOTH the spawn-fail (partial workers RETAINED)
  and bind-incomplete (ALL cleared) paths. The current single-worker seams
  cannot express the partial-success distinction.
- **Loss-cluster `make test-failover` (MANDATORY for PR-2)** — this is the
  failover bring-up path; batched v4+v6, push + reverse, CoS on/off per the
  smoke rules. PR-1 (pure motion) may batch its smoke with the next dataplane PR.
- **fail-on-revert** for any behavioral change (there should be NONE — the goal
  is byte-identical behavior; a fail-on-revert that binds is only meaningful if
  a behavioral line moved, which for PR-1 it does not).

## 10. Out of scope / deferred

- Any change to *when* rollback fires or *which* workers it stops (that is a
  #4952 correctness decision, not this refactor).
- The 40-arg `worker_loop` → typed bundle (**#6241**, OPEN) and the per-worker
  runtime record (**#6242**, OPEN) — #6240 CONSUMES these; PR-2 is gated on them.
- Map-pin preflight unification (**#6243**, OPEN).
- Final typed progress representation beyond what #6244 shipped (**#6244** closed).
- The warmer's best-effort spawn-result handling (behavior, not motion).
- **The PR-1 / PR-2 split decision itself is deferred to the adversarial
  review**: ship PR-1 cold extractions now; hold PR-2 until #6241/#6242 land (or
  fold PR-2 into them) — or PLAN-KILL PR-2 entirely if the failover risk is
  judged to outweigh the modularity win.

## 11. Open questions for adversarial review (each PLAN-KILL-invitable)

1. **Is PR-1 net-positive at all?** The four cold blocks are only ~55–70 LOC.
   Does extracting them into free fns *meaningfully* shrink the transaction's
   cognitive load, or is it churn that adds four call sites for a body that is
   still 500+ LOC of entangled launch/rollback? If the answer is "churn,"
   PLAN-KILL PR-1 too.
2. **Do any "cold" blocks actually participate in rollback?** The BindingPlan
   loop (`:133–165`) inserts into `coord.workers.live`/`identities` — which
   `stop_inner` later clears. I classified it **B** for that reason. Is the
   shared-UMEM projection (`:170–192`) or command-queue build (`:250–256`)
   *also* observed by a rollback path I missed (e.g. does a later `stop_inner`
   read a command queue)? If any PR-1 block is rollback-visible, it drops out of PR-1.
3. **Can the worker-launch block be extracted without threading ~25 mutable
   refs — or does the shared transaction state make extraction net-negative
   until #6241/#6242 land?** My firsthand read: NO, not cleanly. The 25
   `coord.*` clones + 40-arg `worker_loop` mean any pre-#6241 extraction either
   threads the refs by hand or moves the body wholesale behind `&mut coord`,
   reducing shell size but not complexity. Is that a correct reading, and does
   it justify gating PR-2 on #6241/#6242?
4. **Is decomposing a post-teardown transaction worth ANY failover risk?** The
   whole win is readability/testability of a path that already has 6+ regression
   tests and a passing `test-failover`. Is the marginal readability worth even
   the LOW residual risk of a mechanical move on the appliance's recovering-node
   bring-up? (Explicit PLAN-KILL invitation.)
5. **Does #6240 have a coherent identity separate from #6241/#6242, or should it
   be closed as an umbrella and the work done entirely inside #6241/#6242?** The
   amendment frames #6240 as "consume the sibling types + do the remaining
   mechanical extraction." If PR-1's cold blocks are the *only* #6240-native
   work and everything else is #6241/#6242, is a standalone #6240 PR justified
   or should PR-1 fold into the #6241 series?
6. **Resolver ordering trap.** If PR-1.5 outlines `ensure_resolver_before_worker_launch`
   as a separate fn, what *statically* prevents a future edit from calling it
   after the launch (silently breaking the `:401` clone)? Is a free fn with a
   doc-comment enough, or does this need the resolver handle passed *into* the
   launch helper as a required argument so the ordering is type-enforced?
7. **The N-worker test is a prerequisite, not a follow-up.** Should the plan
   REQUIRE the N-worker partial-failure characterization test to land (and pass
   fail-on-revert against the CURRENT code) BEFORE any rollback-path motion, so
   the distinct #4952/#5143 contract is actually pinned before it is touched?
