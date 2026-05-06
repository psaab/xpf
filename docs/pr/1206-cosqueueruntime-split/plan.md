---
status: REVISED v2 — addressing Codex (PLAN-NEEDS-MINOR, task-mou6u7ou-4h4a6u) and Gemini Pro 3 (NEEDS-MINOR/MAJOR convergent, task-mou6vue9-thj49g)
issue: #1206
phase: pure code-motion refactor; struct shape change with byte-for-byte behavior preservation
---

## Round-1 verdict resolution

Both reviewers converged on the same architectural corrections. v2 incorporates:

### Field placement corrections (Codex finding #1; Gemini #1.B)

| Field | v1 placement | v2 placement | Reason |
|---|---|---|---|
| `queue_vtime` | `CoSQueueHotState` (wrong) | `FlowFairState` | `types/cos.rs:524` documents "Meaningful only on flow_fair queues"; `account_cos_queue_flow_enqueue` early-returns on `!queue.flow_fair` |
| `worker_id` | `CoSQueueConfigState` (wrong) | `VMinQueueState` | tied directly to `vtime_floor.slots` indexing per `admission.rs:468` |
| `flow_hash_seed` | `CoSQueueConfigState` (acceptable but suboptimal) | `FlowFairState` | flow-fair-only by comment + use; non-flow-fair queues keep seed=0 today and don't read it |
| `drop_counters` + `owner_profile` | `...` ellipsis (Codex flagged) | explicit fields in `CoSQueueTelemetry` | real runtime fields at `types/cos.rs:621,636` |
| V_min scratch counters | widened to `u64` in v1 sketch | preserve `u32` per current code | `types/cos.rs:656` ships `u32`; no reason to widen |

### Critical: no double-boxing (Gemini finding #1.A)

v1 had:
```rust
pub(in crate::afxdp) flow_fair_state: Option<Box<FlowFairState>>,

struct FlowFairState {
    pub(in crate::afxdp) flow_bucket_items: Box<[VecDeque<CoSPendingTxItem>; COS_FLOW_FAIR_BUCKETS]>,
    // ...
}
```

`flow_fair_state` is already heap-allocated via the outer `Box`; nesting another
`Box` around `flow_bucket_items` adds a pointless second indirection on every
hot-path access with **zero memory benefit** (the array is already off the
`CoSQueueRuntime` footprint via the outer Box). v2 inlines the array:

```rust
struct FlowFairState {
    pub(in crate::afxdp) flow_bucket_items: [VecDeque<CoSPendingTxItem>; COS_FLOW_FAIR_BUCKETS],
    // ...
}
```

### Box-deref hoisting discipline (both reviewers)

Hot-path helpers (`pop_front_inner`, `push_front_inner`,
`account_cos_queue_flow_enqueue`, `account_cos_queue_flow_dequeue`) bind the
`&mut FlowFairState` once at entry to the flow-fair branch:

```rust
let Some(ff) = queue.flow_fair_state.as_mut() else {
    return /* non-flow-fair early-return as today */;
};
// Use ff.flow_bucket_items[bucket], ff.flow_bucket_head_finish_bytes[bucket], etc.
```

Avoids `queue.flow_fair_state.as_mut().unwrap().flow_bucket_items[bucket]`
repeated per field access (Codex).

### Helper-method strategy (Gemini #5)

Pass-through `#[inline]` methods on `CoSQueueRuntime` ONLY for immutable,
frequently-accessed config bits (avoid diff noise):
- `queue_id() -> u8`
- `flow_fair() -> bool`
- `shared_exact() -> bool`
- `transmit_rate_bytes() -> u64`

For mutable state and heavily-borrowed sub-structs (`hot`, `v_min`,
`flow_fair_state`), expose the sub-struct directly. Helper methods on
mutable state would create partial-borrow checker errors at hot-path call
sites that hold one sub-struct mutably while reading another immutably.

### `pop_snapshot_stack` placement (both reviewers)

Moves to `FlowFairState`. Non-flow-fair callers only `.clear()` it during
teardowns/batch aborts; those calls become:

```rust
if let Some(ff) = queue.flow_fair_state.as_mut() {
    ff.pop_snapshot_stack.clear();
}
```

### Single PR (both reviewers)

Not staged. Compiler-enforced correctness across the workspace makes this
safe; staging would require reviewers to look at 4-5 PRs touching the same
~50-100 call sites for no incremental gain.

### Order with #1207 / #1209 (both reviewers)

**#1206 lands first**, before #1207 (service-skeleton) and #1209 (telemetry
double-buffer). Both depend on the new struct shape; merging them first
creates avoidable conflicts. The plan sequencing on those issues already
documents this dependency.



## 1. Issue framing

`CoSQueueRuntime` (`userspace-dp/src/afxdp/types/cos.rs`, lines
~270-720) currently mixes 8 concerns in one struct: immutable config,
token bucket, runnable/parking, byte counters, flow-fair arrays
(~232 KB inline at 4096 buckets), FIFO storage, V_min state, scratch
counters + owner telemetry atomics.

Problems this causes:
- Cold 4096-bucket arrays sit inline next to hot fields → cache-line
  ownership bouncing on the worker hot path.
- Non-flow-fair queues pay the inline footprint they never use
  (~232 KB per queue × 8 queues × 8 workers × 2 ifaces ≈ 30 MB
  static overhead).
- Reasoning about which fields participate in which invariant is hard
  because they're all in one type.

Per Codex CoS findings retrospective: "The main benefit is not just
navigability. It keeps cold 4096-bucket arrays and telemetry out of
the hottest queue fields and makes cache-line ownership easier to
reason about."

## 2. Honest scope/value framing

**Pure code-motion refactor.** No behavior change, no new tests, no
algorithmic changes. The struct shape changes; everything that
operated on the old struct continues to operate via thin pass-through
on the new sub-structs.

**Value:**
- Memory: ~30 MB savings on typical deployments (non-flow-fair
  queues stop paying for flow_bucket arrays).
- Cache: hot fields pack tighter; flow-fair arrays move to a `Box`
  so the queue's primary cache lines aren't polluted by the cold
  bucket bookkeeping.
- Cognitive: each sub-struct has one job; tests can target a
  specific concern without building the whole queue runtime.

**Not promised**: measurable hot-path speedup. Codex flagged this as
medium value; the win is mostly correctness/maintainability for
future fairness work (#1207, #1209, #1211).

**If reviewers conclude the cache-locality benefit doesn't justify
touching every CoS hot-path call site, PLAN-NEEDS-MAJOR or PLAN-KILL
is reasonable.**

## 3. What's already shipped

`CoSQueueRuntime` itself ships at `types/cos.rs:270`-ish through
~720. Methods on it: `front`, `is_empty`, plus indirect access via
the per-queue helper functions in `cos/queue_ops/`, `cos/admission.rs`,
`cos/queue_service/`, `cos/tx_completion.rs`, `tx/cos_classify.rs`.

The hot paths that read CoSQueueRuntime fields:
- `cos_queue_pop_front_inner` (`pop.rs`)
- `cos_queue_push_front_inner` (`push.rs`)
- `cos_queue_v_min_continue` (`v_min.rs`)
- `account_cos_queue_flow_enqueue/dequeue` (`accounting.rs`)
- `service_exact_*` (`queue_service/service.rs`)

## 4. Concrete design

### 4.1 Target struct shape (v2 — corrected per round-1 review)

```rust
pub(in crate::afxdp) struct CoSQueueRuntime {
    pub(in crate::afxdp) config: CoSQueueConfigState,
    pub(in crate::afxdp) hot: CoSQueueHotState,
    pub(in crate::afxdp) flow_fair_state: Option<Box<FlowFairState>>,
    pub(in crate::afxdp) v_min: VMinQueueState,
    pub(in crate::afxdp) telemetry: CoSQueueTelemetry,
}

/// Immutable-after-build config bits. All fields written exactly once
/// in `promote_cos_queue_*` builders; never mutated on the hot path.
pub(in crate::afxdp) struct CoSQueueConfigState {
    pub(in crate::afxdp) queue_id: u8,
    pub(in crate::afxdp) priority: u8,
    pub(in crate::afxdp) transmit_rate_bytes: u64,
    pub(in crate::afxdp) exact: bool,
    pub(in crate::afxdp) surplus_sharing: bool,
    pub(in crate::afxdp) flow_fair: bool,
    pub(in crate::afxdp) shared_exact: bool,
    pub(in crate::afxdp) surplus_weight: u32,
    pub(in crate::afxdp) buffer_bytes: u64,
    pub(in crate::afxdp) dscp_rewrite: Option<u8>,
    // worker_id moved to VMinQueueState (tied to vtime_floor.slots indexing)
    // flow_hash_seed moved to FlowFairState (flow-fair-only)
}

/// Hot per-pop / per-push state. Token bucket + FIFO storage +
/// runnable bookkeeping. NOT flow-fair-specific (flow-fair fields
/// live in FlowFairState).
pub(in crate::afxdp) struct CoSQueueHotState {
    pub(in crate::afxdp) tokens: u64,
    pub(in crate::afxdp) last_refill_ns: u64,
    pub(in crate::afxdp) queued_bytes: u64,
    pub(in crate::afxdp) surplus_deficit: u64,
    pub(in crate::afxdp) items: VecDeque<CoSPendingTxItem>, // FIFO storage
    pub(in crate::afxdp) local_item_count: u32,
    // queue_vtime moved to FlowFairState (flow-fair-only;
    // types/cos.rs:524 documents "Meaningful only on flow_fair queues")
    // ... runnable/parking flags
}

/// Flow-fair MQFQ state. Only allocated when `queue.flow_fair == true`,
/// keeping FIFO queues' `CoSQueueRuntime` footprint small. The struct
/// itself is the only Box — internal arrays are inline (NO double-boxing).
pub(in crate::afxdp) struct FlowFairState {
    pub(in crate::afxdp) queue_vtime: u64,                  // moved from hot
    pub(in crate::afxdp) flow_hash_seed: u64,               // moved from config
    pub(in crate::afxdp) active_flow_buckets: u16,
    pub(in crate::afxdp) active_flow_buckets_peak: u16,
    pub(in crate::afxdp) flow_bucket_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    pub(in crate::afxdp) flow_bucket_head_finish_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    pub(in crate::afxdp) flow_bucket_tail_finish_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    // CRITICAL: NOT Box<[...]> — we're already inside Option<Box<FlowFairState>>;
    // a second Box would be pointless double-indirection on hot path.
    pub(in crate::afxdp) flow_bucket_items: [VecDeque<CoSPendingTxItem>; COS_FLOW_FAIR_BUCKETS],
    pub(in crate::afxdp) flow_rr_buckets: FlowRrRing,
    pub(in crate::afxdp) pop_snapshot_stack: Vec<CoSQueuePopSnapshot>,
}

pub(in crate::afxdp) struct VMinQueueState {
    pub(in crate::afxdp) worker_id: u32,                    // moved from config
    pub(in crate::afxdp) vtime_floor: Option<Arc<SharedCoSQueueVtimeFloor>>,
    pub(in crate::afxdp) v_min_suspended_remaining: u32,
    pub(in crate::afxdp) consecutive_v_min_skips: u32,
    pub(in crate::afxdp) v_min_throttles_scratch: u32,        // u32 per current code (NOT u64)
    pub(in crate::afxdp) v_min_hard_cap_overrides_scratch: u32, // u32 per current code
}

pub(in crate::afxdp) struct CoSQueueTelemetry {
    // Owner-write scratch counters drained on publish via existing
    // CoSStatusInterval cadence. Field list mirrors current
    // types/cos.rs:621-660 (CoSQueueDropCounters at :621,
    // CoSQueueOwnerProfile at :636) — no `...` ellipsis.
    pub(in crate::afxdp) drop_counters: CoSQueueDropCounters,
    pub(in crate::afxdp) owner_profile: CoSQueueOwnerProfile,
    // Other v2 telemetry fields enumerated against current types/cos.rs
    // at implementation time (this is pure code motion; no new fields).
}
```

`flow_fair_state: Option<Box<...>>` is the central memory win:
non-flow-fair queues store `None` (8 bytes) instead of the inline
~232 KB.

### 4.2 Migration strategy — single PR or staged?

**Single PR, all at once.** Rationale:
- Field-by-field staged migration is more total LOC than wholesale
  move.
- Test coverage at the cargo workspace level guarantees byte-for-
  byte behavior preservation IF the move is mechanical.
- Each call site rewrites `queue.field` → `queue.config.field` (or
  `queue.hot.field`, etc.). Compiler enforces correctness — no
  silent wrong-substruct accesses.

**However**: the diff is large (~50-100 call sites). Reviewer fatigue
on large diffs is real. Discuss in plan-review whether to stage by
sub-struct (config first, then hot, then flow_fair_state with the
boxing change, then v_min, then telemetry).

### 4.3 Compiler-enforced correctness

Rust's type system makes this kind of refactor very safe:
- Renaming `queue.queue_id` to `queue.config.queue_id` either
  compiles or doesn't — no silent miscompiles.
- The Box on `flow_fair_state` forces every access through `.as_ref()`
  / `.as_mut()` / `.as_deref_mut()`, surfacing every hot-path call
  site.

### 4.4 Hot-path inlining

Non-flow-fair codepath: `if let Some(ff) = queue.flow_fair_state.as_mut()
{ ... } else { ... }`. The branch predictor handles the (constant per
queue) flow_fair flag; the indirection through `Box` is one extra
load on a cold path.

Concern: do flow_fair queues see a regression from the extra `Box`
deref? Measurement-driven question.

### 4.5 Helper-method strategy

Where the migration would inflate call sites with `.config.` /
`.hot.` access chains, add thin `&self` helpers on `CoSQueueRuntime`:

```rust
impl CoSQueueRuntime {
    #[inline] pub fn queue_id(&self) -> u8 { self.config.queue_id }
    #[inline] pub fn flow_fair(&self) -> bool { self.config.flow_fair }
    // ...
}
```

This keeps the diff focused on structural change rather than
ergonomic noise.

## 5. Public API preservation

- `CoSQueueRuntime` itself (the type name + module path) preserved.
- Direct field access becomes sub-struct field access OR helper
  method. Both are byte-equivalent at the codegen level.
- All public methods on `CoSQueueRuntime` preserved (or migrated
  identically via pass-through to sub-struct methods).
- Nothing on the public crate surface changes.

## 6. Hidden invariants the change must preserve

- **MQFQ vtime semantics** (`pop.rs:112` served-finish, etc.) — every
  current line referencing `queue.queue_vtime` must end up
  referencing the hoisted `ff.queue_vtime` (where `let Some(ff) =
  queue.flow_fair_state.as_mut()` per §4.4) since v2 moves
  `queue_vtime` into `FlowFairState`. No behavior change.
- **Flow-fair bucket lifecycle** (active count, peak, head/tail
  finish times) — all bucket bookkeeping moves to FlowFairState
  intact.
- **V_min publish-on-commit invariant** (#940 + #941) — `vtime_floor
  .as_ref()` chain is wrapped via `queue.v_min.vtime_floor` but
  semantics unchanged.
- **Snapshot rollback** (`pop_snapshot_stack`) — moves into
  FlowFairState because it's only used on the flow-fair path.
  Verify: are any non-flow-fair callers reading the stack? If yes,
  it stays on the hot or top-level type.
- **Cargo test --release**: 977+ tests must pass byte-for-byte.

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Pure code motion; compiler enforces correctness |
| Hot-path perf regression on flow_fair queues | MED | One extra Box deref per hot-path access; needs measurement |
| Diff size / reviewer fatigue | HIGH | ~50-100 call sites change |
| Mid-refactor merge conflicts | MED | Other in-flight CoS work (#1207, #1209) touches same files; serialize |
| Migration mistakes | LOW | Compiler catches them; no silent miscompiles |

## 8. Test plan

- `cargo build --release` clean
- `cargo test --release` 977+ pass without modification
- Hand-test a known flow-fair test case 5×: identical output across
  runs vs pre-refactor (deterministic)
- Hand-measure on iperf-c P=12 t=120 -R: aggregate within ±1% of
  pre-refactor; CoV within ±2 percentage points (within run-to-run
  noise)
- Memory check: `pmap` on running daemon shows non-flow-fair queues
  no longer carry the inline ~232 KB
- 5×flake on the most-affected named test (`cos::queue_ops::tests::*`)

## 9. Out of scope

- Algorithmic changes (anything that affects per-flow/per-queue
  ordering, throttling, admission). All bytes-equivalent.
- Cache-line layout optimization within sub-structs (separate
  follow-up; first get the high-level shape right).
- Telemetry double-buffering (#1209 — separate effort).
- Service.rs consolidation (#1207 — separate effort).

## 10. Open questions for adversarial review

All round-1 questions resolved in v2:

- ~~Single PR vs staged~~: **single PR** (both reviewers agreed).
- ~~Box-deref cost on flow_fair hot path~~: **acceptable**; mitigated
  by Box-deref hoisting (§4.4).
- ~~Helper-method strategy~~: **pass-through `#[inline]` on immutable
  config bits only**; mutable sub-structs exposed directly to avoid
  partial-borrow checker errors (§4.5).
- ~~Order with #1207/#1209~~: **#1206 lands first** (both reviewers).
- ~~`pop_snapshot_stack` placement~~: **moves to `FlowFairState`**;
  non-flow-fair callers wrap in `if let Some(ff) = ...`.

Remaining open question for v3 review:

1. **VMinQueueState scope.** Some V_min state is per-runtime
   (`vtime_floor` Arc, `v_min_suspended_remaining`,
   `consecutive_v_min_skips`, scratch counters). Per-call lag
   thresholds computed each tick stay file-private to `v_min.rs`.
   Confirm against current `types/cos.rs:640-660` at impl time.

## 11. Verdict request

PLAN-READY → execute (pick single-PR or staged per Q1).
PLAN-NEEDS-MINOR → tweak struct shape / helper strategy.
PLAN-NEEDS-MAJOR → revise (different sub-struct boundaries, different
indirection scheme).
PLAN-KILL → cache-locality benefit doesn't justify the diff size.
