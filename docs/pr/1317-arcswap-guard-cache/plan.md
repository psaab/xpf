# #1317 — ArcSwap Guard caching across spin iterations

**Status:** **PLAN-KILLED v1** 2026-05-26 — Codex PLAN-NEEDS-MAJOR + AGY
PLAN-KILL. Iteration-skip design has a fatal HA-state observation race
on `DemoteOwnerRGS` / `VacateAllSharedExactSlots` commands; the
flamegraph attribution is unverified (the perf.data in the repo root
is from February with no userspace symbols, no ArcSwap frames); the
12.3% claim is most plausibly an idle-spin sampling artifact that
amortizes to ~0% under saturation — making the ≥8% acceptance gate
mathematically unattainable on the iperf3 smoke matrix. Pivot to
`arc_swap::Cache` is the suggested forward path, but requires fresh
flamegraph evidence captured under saturation before any new plan
should be written. See "Review verdicts" section appended at bottom.

## 1. Issue framing

#1317 (follow-up to #1314 adaptive idle-spin) reports a flamegraph
collected on the loss userspace cluster in which
`arc_swap::HybridStrategy::load` aggregates to **12.3% of total CPU
samples** across the 12 `Arc<ArcSwap<…>>` field reads on the worker
hot-path. The issue proposes caching the `Guard` (or the resolved
`Arc<T>`) across spin iterations so the steady-state idle-spin burst
does not re-execute 12 HybridStrategy loads per outer iteration.

Goal: drive `arc_swap::HybridStrategy::load` aggregate self-time below
2% on the loss userspace cluster flamegraph and recover at least 8%
of total CPU (allow 4% headroom for non-ideal cache hit rate vs the
12.3% upper bound).

## 2. Honest scope/value framing

**Absolute scale (best case):** if 12.3% of CPU on the worker hot path
is genuinely spent in `HybridStrategy::load` per the flamegraph, and
we eliminate ~10% of that across idle spins by short-circuiting
redundant loads, the win is on the order of **6-10% CPU at idle
saturation** — measurable. Under saturated traffic (every poll has
`did_work=true`), the win is much smaller because we still need to
re-poll on the work boundary.

**Realistic floor:** even if the flamegraph hot-frame is inflated by
inlining/folding (HybridStrategy::load is called from many ArcSwap
sites and may sample-attribute generously), short-circuiting an
extra-redundant load path on the idle-spin tail still avoids cache-line
bouncing on the shared Arc control blocks across all 6 workers — the
real penalty is not just per-call ns but cross-core coherency traffic.
That secondary win is the structural argument.

*If reviewers conclude the perf gain is too small to justify the
churn, PLAN-KILL is an acceptable verdict.*

This issue is **not** a refactor — it is a hot-path micro-optimization
with measurable acceptance criteria. The plan deliberately scopes the
change to one surgical edit in `worker/loop_body/mod.rs`.

## 3. What's already shipped (composition context)

- **#1188** (commit `b2a31e0` etc): introduced `load_arc_if_changed()`
  which uses `.load()` + `Arc::ptr_eq` + `Guard::into_inner` instead
  of `.load_full()` — eliminates the unconditional `Arc` clone/drop
  pair on every tick. Saves the **clone+drop atomics** but the
  `.load()` HybridStrategy traversal is still per-tick.

- **#1314** (open): adaptive idle-spin budget tracker. The 12.3%
  flamegraph in #1317 was captured during #1314 analysis. #1314 is
  the umbrella for "recover CPU after copy-elimination"; #1317 is
  one specific lever inside that envelope.

- **Per-tick `.load()` site count** (verified by reading
  `userspace-dp/src/afxdp/worker/loop_body/mod.rs` at @ origin/master):
  - line 57: `shared_validation.load()` — initial state seed
  - line 58: `shared_forwarding.load_full()` — initial state seed
  - line 59-65: 6× `load_full()` on the CoS shared maps + mirror_targets — initial seed
  - line 283: `shared_validation.load()` — **per outer tick**
  - line 291: `load_arc_if_changed(&forwarding, &shared_forwarding)` — **per outer tick**
  - line 353: mirror_targets — per outer tick
  - line 356: cos_owner_worker_by_queue — per outer tick
  - line 363: cos_owner_live_by_queue — per outer tick
  - line 369: cos_shared_root_leases — per outer tick
  - line 377: cos_shared_exact_backlogs — per outer tick
  - line 383: cos_shared_queue_leases — per outer tick
  - line 391: cos_shared_queue_vtime_floors — per outer tick
  - line 437: `ha_state.load()` — **per outer tick** (RAW load, not via helper)
  - line 558: `shared_fabrics.load()` — **per outer tick** (raw load, used immediately)

  Total: **11 per-tick `.load()` calls** (10 via `load_arc_if_changed`
  helper + 1 raw `validation` + 1 raw `ha_state` + 1 raw
  `shared_fabrics` = **12 fields**, all hot per tick). Issue's count
  of "12 fields" matches reading exactly.

  *Note:* the issue's body cites `worker/mod.rs:769-798` for the
  field list. That line range in the current tree is
  `partition_binding_plans` and shared-UMEM helpers — **stale line
  reference**. The actual ArcSwap field declarations live in
  `worker/loop_body/mod.rs:14-48` (the `worker_loop` fn signature)
  after the #1326 extract. Treat the issue body line numbers as
  historical; the fields/semantics are unchanged.

## 4. Concrete design

### Observation about the outer loop shape

The worker hot path is:

```rust
loop {
    if stop.load(Ordering::Relaxed) { break; }
    let loop_now_ns = monotonic_nanos();
    // ... debug-state publish on cadence ...

    // === 12× ArcSwap loads (the cost we want to avoid) ===
    let live_validation = shared_validation.load();        // 1
    if let Some(new) = load_arc_if_changed(&forwarding, &shared_forwarding) {...}  // 2
    if let Some(new) = load_arc_if_changed(&mirror_targets, ...) {...}   // 3
    // ... 6 more load_arc_if_changed calls ...            // 4-9
    let ha_runtime = ha_state.load();                      // 10
    // ...
    {
        let live_fabrics = shared_fabrics.load();          // 11
        if !live_fabrics.is_empty() && ... { rebuild forwarding }
    }
    // 12th is the initial `validation` raw `.load()` site at L283.

    // === Per-binding poll work ===
    let mut did_work = false;
    for offset in 0..bindings.len() { /* RX/TX poll */ }

    if did_work {
        idle_iters = 0;
        continue;          // <-- re-runs all 12 .load()s
    }
    idle_iters = idle_iters.saturating_add(1);
    if idle_iters <= IDLE_SPIN_ITERS { std::hint::spin_loop(); }   // 256-iter window
    else { thread::sleep(IDLE_SLEEP_US); }
}
```

`IDLE_SPIN_ITERS = 256`; `std::hint::spin_loop()` is a CPU PAUSE hint
(~30-100ns on x86). So when the binding has no traffic to drain, the
worker tight-loops ~256 outer iterations × ~30-100ns of pause **plus
the 12 ArcSwap loads each time**. Each `HybridStrategy::load` is
~30-80ns; 12 of them is ~360-960ns per outer iteration. Across 256
idle iters, that is ~92-246µs of pure ArcSwap-load CPU per idle burst
**per worker**. Six workers × idle bursts that happen every time the
queue drains — that maps to ~12% under saturation flamegraph
attribution (some loads attribute to the helper, some to the field
site, all under HybridStrategy).

### Proposed fix: skip ArcSwap refresh on consecutive idle iterations

**Design:** Introduce a per-iteration `arc_refresh_pending: bool`. On
the **first** idle iteration after a busy iteration, refresh the 12
ArcSwap fields normally. On subsequent idle iterations (idle_iters >
0 in the spin window), skip the ArcSwap polling block and go straight
to the per-binding poll. Re-enable the refresh when either:

1. `did_work == true` on the previous iteration (we just drained
   packets — coordinator may have rotated state behind us), OR
2. `idle_iters` rolls over a safety tick (e.g., refresh every 1ms
   regardless), OR
3. We are about to exit the spin window (`idle_iters >
   IDLE_SPIN_ITERS`), so the post-sleep iteration always refreshes.

Concretely:

```rust
let mut arc_refresh_pending = true;
let mut last_refresh_ns: u64 = 0;
const ARC_REFRESH_SAFETY_NS: u64 = 1_000_000; // 1ms safety tick

loop {
    if stop.load(Ordering::Relaxed) { break; }
    let loop_now_ns = monotonic_nanos();

    if arc_refresh_pending
        || loop_now_ns.saturating_sub(last_refresh_ns) >= ARC_REFRESH_SAFETY_NS
    {
        // === existing 12 ArcSwap load block, unchanged ===
        let live_validation = shared_validation.load();
        if **live_validation != validation { validation = **live_validation; }
        if let Some(new_forwarding) = load_arc_if_changed(&forwarding, &shared_forwarding) {
            // ... existing handling ...
        }
        // ... etc ...
        last_refresh_ns = loop_now_ns;
        arc_refresh_pending = false;
    }
    // else: re-use already-cached `validation`, `forwarding`,
    // `cos_*`, `mirror_targets`, `ha_runtime`, `shared_fabrics`-derived state.

    // === Per-binding poll work (unchanged) ===
    let mut did_work = false;
    // ...
    for offset in 0..bindings.len() { ... }

    if did_work {
        idle_iters = 0;
        arc_refresh_pending = true; // refresh on next iteration
        continue;
    }
    idle_iters = idle_iters.saturating_add(1);
    if idle_iters <= IDLE_SPIN_ITERS {
        std::hint::spin_loop();
    } else {
        thread::sleep(IDLE_SLEEP_US);
        arc_refresh_pending = true; // post-sleep: full refresh
    }
}
```

**Key properties:**

- **First idle iter after busy:** full refresh (catches coordinator
  rotations that happened during burst).
- **Subsequent idle iters (2..=256):** skip the 12 ArcSwap loads
  entirely. Only `stop.load(Relaxed)`, `monotonic_nanos()`, the
  `arc_refresh_pending` branch, and the per-binding poll loop run.
- **Safety tick (1ms):** even in a long idle spin, refresh forces a
  re-poll once every 1ms so a config change that lands while the
  worker is spinning is observed within 1ms. **Far below** the
  500ms event-debounce on the Go control plane and the 200ms HA
  heartbeat threshold.
- **Post-sleep:** the `IDLE_SLEEP_US`=1µs sleep is taken on
  iteration 257+. The next iteration always refreshes, so any
  rotation that occurred during the sleep is observed immediately.
- **Post-`did_work`:** the `continue` path sets
  `arc_refresh_pending = true`, so the very next iteration refreshes
  before draining any further packets. Coordinator rotations that
  happen *during* packet drain are observed at the next outer-tick
  top.

### Why this is preferable to `arc_swap::Cache`

`arc_swap::Cache<Arc<ArcSwap<T>>, T>` is the canonical "many loads,
few rotations" pattern — but it requires either:

- One `Cache` per worker per field (12 caches per worker × 6 workers
  = 72 Cache instances), each with its own private last-observed
  pointer; OR
- A worker-local struct that owns all 12 caches and provides typed
  accessors.

Both introduce significantly more code churn than the iteration-skip
pattern. They also still pay a cheaper but non-zero per-call cost
(version-counter compare + branch).

The iteration-skip pattern is strictly cheaper: zero loads on the
skip path. The trade-off is the 1ms safety tick (vs Cache's
zero-staleness on rotation). Given that all 12 fields are slow-path
control state, 1ms is acceptable.

### Why this is preferable to "cache Guard across spin iterations"
(the issue's literal proposal)

Holding an `arc_swap::Guard<Arc<T>>` across spin iterations would
pin the ArcSwap debt-list slot, preventing the writer from reclaiming
the prior `Arc<T>` until the Guard is dropped. The arc_swap docs
explicitly warn against long-lived Guards: "Holding a Guard across
operations that may publish a new Arc will delay the old Arc's
reclamation by however long the Guard lives". In our case, a writer
that rotates the Arc during an idle-spin burst would have its prior
Arc held alive for ~7-26µs (one full IDLE_SPIN_ITERS window) — not
catastrophic, but unbounded if the spin window grows in the future.

The iteration-skip pattern doesn't hold any Guard. It just doesn't
ask the question. Cleaner: on the next refresh, we always do a
fresh `.load()` which sees the current Arc and frees the cached one
via the existing `Arc::ptr_eq` rotation.

### Pseudocode → real diff size estimate

The change is **one wrapping `if`** around the existing ArcSwap-load
block (L283-405 today) plus the `arc_refresh_pending` bookkeeping in
the `did_work` / sleep branches. Estimated diff: ~30 added lines, 0
deleted lines, all in `worker/loop_body/mod.rs`. No new files. No
public API changes.

## 5. Public API preservation

No `pub` or `pub(crate)` items change. `worker_loop` signature is
unchanged. The `load_arc_if_changed` helper is unchanged. No new
exports from `worker/loop_body/mod.rs` or `worker/mod.rs`.

## 6. Hidden invariants the change must preserve

1. **Coordinator → worker config rotation is observed within bounded
   latency.** New bound: max(1ms safety tick, post-`did_work` refresh,
   post-sleep refresh). All current consumers tolerate this.

2. **HA state rotations (RG transitions) drive `WorkerCommand`
   enqueues, not silent ArcSwap rotations.** The `commands` queue is
   read every iteration; `ha_state.load()` is only used to read the
   already-rotated state. So a `WorkerCommand` like `VacateAllSharedExactSlots`
   enqueued by the coordinator is processed immediately at L437-475 —
   we just may be reading a slightly stale `ha_runtime` snapshot for
   the next 1ms. **Verify:** `apply_worker_commands` consumes
   `ha_runtime.as_ref()` at L449. A stale `ha_runtime` here means a
   command is processed against state that is up to 1ms behind. If
   the command itself encodes the necessary state delta (which it
   should — commands are state-deltas, not state-snapshots), this is
   safe. **Open question for review.**

3. **`shared_fabrics.load()` (L558) updates `forwarding.fabrics`
   inline.** If we skip this `.load()`, fabric link rotations during
   an idle spin are delayed up to 1ms. Fabric link state changes are
   netlink-driven (link up/down), already debounced; 1ms is fine.

4. **`shared_validation` (L283) drives validation cache.** Validation
   state is the config-validation cache (generation counters, etc.).
   1ms stale validation cannot cause a packet to be processed against
   a wrong rule — packets process against `forwarding`, which is
   refreshed on the same boundary.

5. **`session_export_ack`** and ring-buffer publishers — out of scope.
   These are atomics, not ArcSwaps. Unchanged.

6. **`stop.load(Relaxed)`** — still polled every iteration. Shutdown
   responsiveness unchanged.

7. **Heartbeat publish at L513.** Still per-iteration. The
   coordinator-side watchdog liveness check is unaffected.

8. **`session.expire_stale_entries(loop_now_ns)` at L514.** Still
   per-iteration. Session GC unaffected.

9. **`refresh_bpf_conntrack_last_seen` cadence** — already gated by
   `CT_REFRESH_INTERVAL_NS` so per-iteration call is cheap; unchanged.

10. **`runtime_atomics.publish(...)`** — gated by `wr_last_publish_ns`
    cadence; unchanged.

11. **Debug-state cadence (`debug_state_publish_due`)** — per-tick
    check unchanged.

## 7. Risk assessment (4-class table)

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | **LOW** | All 12 fields are slow-path control state with multi-ms/multi-sec rotation cadence; 1ms staleness bound is far below any consumer's observation threshold. Verified above. |
| Lifetime / borrow-checker | **LOW** | No new lifetimes introduced. `arc_refresh_pending: bool` is a stack local. No Guards held across iterations. |
| Performance regression | **LOW** | Adds a single branch (`if arc_refresh_pending || elapsed_ns >= 1ms`) on the hot path. Branch is highly predictable (almost always false in idle spin, true on first iter after work). Branch cost ~1ns vs ~360-960ns of ArcSwap loads saved. Net positive at all traffic profiles. |
| Architectural mismatch (#961/#946-Phase-2) | **LOW** | This is a localized hot-path optimization, not a structural refactor. Not in the same risk class as the killed batched-pipeline / packet-context refactors. The change is reversible by removing the wrapping `if`. |

## 8. Test plan

### Pre-merge (unit/integration)

- `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build` — clean
- `TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release` — full suite passes
- 5× flake check on `worker_loop` related named test(s) — pick a
  named test that exercises the per-tick refresh path; candidates:
  - `worker::tests::*` (if any cover the loop)
  - failing that, the full cargo test as the flake gate.
- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./...` — Go suite
  passes (no Go-side changes expected; sanity check only).

### Smoke matrix (loss userspace cluster)

Standard skill matrix:

- **Pass A — CoS disabled:** v4 + v6 × push + reverse single-stream,
  plus the 12-stream `-P 12 -t 10 -R` reverse reproducer at line rate
  with 0 retrans.
- **Pass B — CoS enabled:** 24 per-class measurements (ports
  5201-5206, v4+v6, push+reverse) with 0 retrans on unshaped classes
  and configured rates on shaped classes.

### CPU measurement (acceptance criterion)

The whole point of this change. Before merge:

1. Deploy the **master** build to `loss:xpf-userspace-fw0` and run
   the perf-test skill matrix (steady-state iperf3 at saturation +
   `perf record` for 30s).
2. Capture flamegraph; extract `arc_swap::HybridStrategy::load`
   aggregate self-time (baseline).
3. Deploy the **PR HEAD** build and repeat.
4. Extract post-fix aggregate self-time.

**Acceptance:** post-fix `arc_swap::HybridStrategy::load` aggregate
self-time ≤ 2% (from baseline ~12%) AND total worker-loop CPU drops
by ≥ 8% absolute on the same workload.

If the measurement does not meet ≥ 8%, the PR does not merge — the
change is reverted and the issue is updated with the measurement
delta. This is the explicit objective gate.

### HA failover

- `make test-failover` is **NOT required** here — no
  cluster/VRRP/session-sync code touched. However, the smoke matrix
  on `loss:xpf-userspace-fw0/fw1` is HA-active by definition, so
  baseline failover behavior is exercised implicitly.

## 9. Out of scope (explicitly)

- **Swapping to `arc_swap::Cache`** — discussed in §4 and rejected
  in this iteration for code-size + complexity reasons. Can be a
  follow-up if iteration-skip turns out to be insufficient (which
  the measurement gate will surface).
- **Reducing the 12 ArcSwap fields to fewer by struct packing** —
  out of scope. The fields have independent rotation semantics
  (config vs CoS vs HA vs fabrics) and packing them into one Arc
  would force coupled rotation, hurting unrelated subsystems.
- **Eliminating ArcSwap entirely** — out of scope. ArcSwap is the
  right primitive for "many readers, infrequent writer with publish
  semantics".
- **#1314 adaptive idle-spin budget** — separate issue. #1317 ships
  the per-load short-circuit; #1314 may later compose by also
  shortening the spin window itself.

## 10. Open questions for adversarial review (at least 5, each
invitable to PLAN-KILL)

1. **Is the 12.3% flamegraph attribution real?** The issue cites a
   flamegraph but does not attach it inline. Could the 12.3% be
   inflated by sampling artifacts (frame-pointer chains hitting
   HybridStrategy as a common deeper frame), and the real ArcSwap
   self-time be 2-3%? If so, the 8% acceptance gate cannot be met
   regardless of how clean the fix is, and the PR doesn't merge.
   **Codex/AGY: examine the flamegraph linked in the issue and
   re-validate the 12.3% figure before approving the plan.**

2. **Does the 1ms safety tick conflict with the
   `event_debounce 500ms` mentioned in the user prompt?** The prompt
   says "verify the staleness window doesn't cause HA-state
   observation lag > advertised event-debounce 500ms". 1ms ≪ 500ms,
   so we are safe with two orders of magnitude headroom. Confirm
   that 500ms is the right comparison bar (it's the Go-side cluster
   state → VRRP priority update debounce; HA state observation in
   the worker is a different downstream consumer).

3. **`apply_worker_commands` with stale `ha_runtime`:** does any
   `WorkerCommand` variant assume `ha_runtime` is read-your-writes
   consistent with the command's enqueue moment? E.g., if the
   coordinator enqueues `VacateAllSharedExactSlots` *and* rotates
   `ha_state` to "this worker is no longer primary", the command is
   processed but the `ha_runtime` snapshot may still say "primary".
   Walk every `WorkerCommand` variant and check the read pattern.

4. **`Arc<ShardedNeighborMap>` and similar non-ArcSwap shared state**
   — are there *other* hot-path lock-free reads not counted in the
   12 ArcSwap fields that the plan should also short-circuit? If
   yes, the 8% target is over-pessimistic; if no, the 8% target is
   the right number.

5. **Is the iteration-skip + 1ms safety tick functionally equivalent
   to just polling at 1ms cadence directly (instead of every tick
   when busy)?** I.e., would a simpler "always poll on 1ms cadence"
   design with no `did_work` coupling be cheaper? **Counter:** on a
   busy worker, we *want* to poll right after each work burst because
   coordinator rotations during a burst should land at the very next
   tick. The 1ms-only design would delay observation by up to 1ms
   even on busy workers, which is worse than the current proposal.
   But is this counter actually true? If the coordinator never
   rotates faster than 1ms (which it doesn't — control-plane RPC
   latency is far slower), then the 1ms-only design is equivalent
   and simpler.

6. **Architectural mismatch with #961 / #946 Phase 2:** unlike those
   kills, this change does **not** restructure the loop or alter
   side-effect ordering — it gates an existing block on a freshness
   flag. Confirm this is the correct architectural premise.

7. **#1188 staleness mention:** the issue's project-memory entry
   `project_1188_done` says #1188 already eliminated "~12 atomic
   RMWs/tick" from `.load_full()`. Does #1317 double-count #1188's
   savings? **Counter:** #1188 saved the *clone+drop* on the
   short-circuit path; the underlying `.load()` HybridStrategy walk
   (debt-list bookkeeping + atomic load) still runs and is what the
   #1317 flamegraph attributes to. No double-count.

## Decision criteria for adversarial review

- **PLAN-READY** — plan is sound, scope is bounded, risk analysis
  matches code, gates are objective.
- **PLAN-NEEDS-MINOR** — typo/clarification level.
- **PLAN-NEEDS-MAJOR** — one of the open questions (especially #1 or
  #3) requires more investigation before code is written.
- **PLAN-KILL** — flamegraph attribution is bogus, OR the 8% gate is
  unattainable structurally, OR the staleness window invalidates a
  consumer invariant I missed. All acceptable verdicts.

---

## Review verdicts (round 1 — plan v1 @ 382f240e)

### Codex (`task-mpnhwnpo-4mt856`): PLAN-NEEDS-MAJOR

Blocking findings:

1. **HA command ordering is unsafe as written.** `update_ha_state()`
   stores the new HA runtime in the ArcSwap and *then* enqueues
   `DemoteOwnerRGS`, `RefreshOwnerRGS`, and `VacateAllSharedExactSlots`
   (`userspace-dp/src/afxdp/ha.rs:39`). The worker passes
   `ha_runtime.as_ref()` into `apply_worker_commands()`
   (`worker/loop_body/mod.rs:437`). `DemoteOwnerRGS` and
   `RefreshOwnerRGS` re-resolve sessions using that HA snapshot
   (`session_glue/commands/demote_owner_rgs.rs:46`,
   `refresh_owner_rgs.rs:45`). If the loop skips `ha_state.load()`
   while commands are pending, a demotion can be processed against
   stale "active" state, or activation against stale "inactive"
   state. That is **not 1ms observation lag — it is a one-shot
   command doing the wrong rewrite**. Required revision: trigger
   set must become `arc_refresh_pending || has_commands ||
   safety_tick || post_block`.

2. **Per-tick load count is 11, not 12.** Plan §3 enumerates
   "10 via helper + 3 raw = 12"; correct count is 8 helper + 3 raw
   = 11. `local_tunnel_deliveries` is loaded only on slow-path local
   delivery (`tx/dispatch/slow_path.rs:159`), not in the per-tick
   block.

3. **The pseudocode does not compile as "wrap unchanged."**
   `ha_runtime` is currently a per-iteration `Guard` from
   `ha_state.load()`. Skipping the refresh block leaves no live
   Guard to pass to `apply_worker_commands()` / `poll_binding()`.
   Implementation must introduce a persistent cached
   `Arc<BTreeMap<...>>` and refresh via `load_arc_if_changed()`.

4. **Flamegraph attribution unverified.** No flamegraph artifact in
   the repo. The `perf.data` in repo root is from Feb 2026 with no
   userspace symbols. Without folded-stack evidence distinguishing
   self time from inlined-caller aggregation, the 12.3% premise is
   not reviewable. If true self-time is 2-3%, the ≥8% CPU gate is
   structurally impossible and the plan should be killed or
   re-scoped before code.

Other notes: worst-case staleness is *not* "≤1ms" — if traffic
arrives during a skipped idle iteration, the entire poll iteration
can process packets with stale validation, forwarding, mirror,
CoS, fabrics-derived forwarding, and HA state before `did_work`
forces refresh. With `RX_BATCH_SIZE=64` and
`MAX_RX_BATCHES_PER_POLL=4` that is up to 256 descriptors per
binding per stale outer iteration.

### AGY (`adversarial-review-mpnhwyn8-3pg74m`): PLAN-KILL (or major
restructure to thread-local `arc_swap::Cache`)

Independent confirmation of the HA race plus three additional
hostile findings:

1. **Fatal HA consistency race** — same race Codex flagged. At
   23 Gbps peak baseline, a 1ms window leaks ~23 million bits
   (thousands of packets) of duplicated or incorrect traffic during
   failover.

2. **Saturated throughput mismatch.** Under iperf3 saturation the
   worker loop drains in batches; per-iteration ArcSwap-load
   checks amortize so baseline overhead is already ~0%. The
   12.3% is most plausibly an **idle-spin sampling artifact**,
   not saturated-workload overhead. ≥8% CPU drop under iperf3
   saturation is mathematically unattainable because there is no
   12% overhead to optimize away in a busy system.

3. **Physical fallacy of cache-line bouncing.** Because writes
   are extremely rare in steady state, the pointer cache lines
   reside in MESI Shared state across all 6 worker cores.
   Read-only access to Shared lines incurs **zero coherency
   traffic** and executes at L1 speeds. The plan's cross-core
   coherency-traffic argument is wrong.

4. **`arc_swap::Cache` rejected too casually.** Caches can be
   thread-local mutable locals inside `worker_loop` — no global
   struct encapsulation required. Provides zero-staleness on
   rotation (no HA race) and zero atomic ops on the common path.
   The right pivot.

5. Confirmed: line numbers in issue body are stale (769-798 is
   `partition_binding_plans` now); per-tick load count is 11 not
   12; #1188 ptr_eq short-circuit is independent (not
   double-counted).

### Disposition

Both reviewers converge on:

- Iteration-skip with 1ms safety tick is unsafe (HA race) and
  unverifiable (no flamegraph evidence) — **the v1 plan is dead**.
- Pivot to thread-local `arc_swap::Cache` is the suggested
  forward path, but the perf premise itself needs to be
  re-established under saturation before the pivot becomes a
  defensible plan.
- The ≥8% CPU acceptance gate is most likely structurally
  unattainable under saturation; the real win (if any) is in
  idle-spin reduction, which is a different metric and aligns
  with #1314 (adaptive idle-spin budget), not with the iperf3
  saturation smoke matrix.

Per the triple-review skill:

> **Both PLAN-KILL → stop. Update plan.md to record the KILLED
> status with both reviewer findings preserved verbatim. Comment
> on the issue with the analysis. Do NOT open a PR.**

This work item is closed at the plan stage. A future revival
requires:

1. A fresh flamegraph captured on the loss userspace cluster
   **under iperf3 saturation** showing the per-frame self-time
   attribution of `arc_swap::HybridStrategy::load` (use
   `perf record --call-graph fp` + folded-stack post-processing
   to distinguish self vs cumulative).
2. If the self-time is ≥4% under saturation: write plan v2
   targeting thread-local `arc_swap::Cache` (not iteration-skip),
   with the HA-state field handled via a tighter primitive
   (e.g., explicit refresh in `apply_worker_commands` regardless
   of cache freshness, OR a generation-counter ratchet on the
   command queue).
3. If self-time is <4% under saturation: this is an
   idle-spin-only optimization and should be folded into #1314,
   not pursued as a standalone perf claim.

