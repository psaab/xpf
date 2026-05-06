---
status: REVISED v2 — addressing Codex (PLAN-NEEDS-MAJOR, task-mou6u87v-3y6ih0) and Gemini Pro 3 (PLAN-NEEDS-MAJOR, task-mou6vz0k-2bk35b)
issue: #1207
phase: pure code-motion refactor; behavior preserved
---

## Round-1 verdict resolution

Both reviewers PLAN-NEEDS-MAJOR with the same headline finding: the v1
adapter trait is underspecified. The current 4 variants differ in more
than just drain helper and scratch shape:

- **Local FIFO**: needs `free_tx_frames` for release/settle.
- **Local flow-fair**: needs `free_tx_frames` AND restores TX frames on rollback.
- **Prepared FIFO**: needs `pending_fill_frames` + `slot` + `in_flight_prepared_recycles`.
- **Prepared flow-fair**: pops from queue + restores items to queue head in LIFO order; does NOT restore TX frames.

v1's `settle_submission(queue, scratch, inserted)` and
`restore_to_queue_head(queue, scratch, area)` cannot implement these
faithfully: missing parameters for FIFO drop semantics, missing
`free_tx_frames` for local flow-fair restore, and the skeleton can't
iterate `A::Scratch` (opaque to it) to map descriptors or extract
offsets for `stamp_submits`.

### v2 fix: richer adapter contract

The trait owns descriptor insertion + accepted-offset stamping + complete
rollback (per both reviewers). Skeleton owns the invariant ordering:
drain → submit → stamp-after-commit → settle → publish-V_min → apply-result.

```rust
trait ServiceAdapter {
    type Scratch;

    /// Drain stage: pop items from queue (or for FIFO, take items
    /// already in scratch) into adapter's scratch shape. Returns
    /// the build outcome including any rollback-relevant state.
    fn drain_to_scratch(
        &mut self,
        queue: &mut CoSQueueRuntime,
        free_tx_frames: &mut VecDeque<u64>,
        pending_fill_frames: &mut VecDeque<u64>,            // prepared variants only
        in_flight_prepared_recycles: &mut Vec<...>,         // prepared variants only
        scratch: &mut Self::Scratch,
        area: &MmapArea,
        root_budget: u64,
        secondary_budget: u64,
        dscp_rewrite: Option<u8>,
    ) -> ExactCoSScratchBuild;

    /// Insert descriptors into the TX ring writer. The adapter owns
    /// scratch iteration because the skeleton can't see `Self::Scratch`'s
    /// internal shape. Returns the inserted count.
    fn insert_descriptors(
        &self,
        scratch: &Self::Scratch,
        writer: &mut TxRingWriter,
    ) -> u32;

    /// Stamp accepted descriptors with the post-commit submit timestamp
    /// (#812 invariant: must be sampled AFTER writer.commit()).
    /// Adapter owns the offset extraction from its scratch shape.
    fn stamp_accepted(
        &self,
        scratch: &Self::Scratch,
        inserted: u32,
        ts_submit: u64,
        tx_submit_ns: &mut TxSubmitTimestamps,
    );

    /// Unified rollback: called on Drop or inserted == 0. Per Gemini —
    /// FIFO adapters drop/release frames; flow-fair adapters push items
    /// back to queue head in LIFO order. Optional &mut CoSQueueRuntime
    /// because FIFO doesn't need queue access for rollback.
    fn cancel_submission(
        &mut self,
        queue: Option<&mut CoSQueueRuntime>,
        free_tx_frames: &mut VecDeque<u64>,
        scratch: &mut Self::Scratch,
    );

    /// Settle stage: queue accounting + partial-rollback for the
    /// inserted prefix. Returns (sent_packets, sent_bytes).
    fn settle_submission(
        &mut self,
        queue: &mut CoSQueueRuntime,
        scratch: &mut Self::Scratch,
        inserted: u32,
    ) -> (u64, u64);
}
```

Four adapters, monomorphized at call sites:

- `LocalFifoAdapter` — items in scratch directly; drain re-claims items, settle accounts dropped/sent
- `LocalFlowFairAdapter` — pops from queue's flow-fair buckets; restore_to_queue_head handles LIFO push-back AND TX frame release
- `PreparedFifoAdapter` — handles pending_fill_frames + recycles
- `PreparedFlowFairAdapter` — flow-fair pop; rollback does NOT touch TX frames

### Other v2 changes from round-1 findings

- **Plan slop fixed** (Codex): `VecDeque<u64>` (current type), not
  `Vec<TxFrame>`. Pseudocode return is `sent_packets > 0` not
  `!sent_packets == 0`.
- **Generic monomorphization confirmed acceptable** (both reviewers):
  ~4 copies of skeleton body in binary, offset by ~600 LOC source
  reduction. No `dyn` dispatch unless the implementation introduces
  trait objects.
- **Hot-path inlining discipline** (Codex): use private generic fns,
  concrete zero-sized adapters, `#[inline]` / `#[inline(always)]` on
  tiny adapter methods. Verify generated symbols/asm with `size`/
  `cargo bloat` if needed.
- **Order: wait for #1206 first** (both reviewers, both plans agree).
  v2 explicitly serializes — implement #1207 only AFTER #1206 lands
  on master, then rebase #1207 against the new struct shape.



## 1. Issue framing

`userspace-dp/src/afxdp/cos/queue_service/service.rs` (631 LOC) has 4
near-duplicate variants of the same service skeleton:

- `service_exact_local_queue_direct` (FIFO + Local)
- `service_exact_local_queue_direct_flow_fair` (MQFQ + Local)
- `service_exact_prepared_queue_direct` (FIFO + Prepared)
- `service_exact_prepared_queue_direct_flow_fair` (MQFQ + Prepared)

All four follow the same skeleton: drain → submit → stamp → settle →
publish V_min → apply send result. Only the drain helper and scratch
shape differ.

## 2. Honest scope/value framing

Pure code-quality / maintainability win. Reduces ~200 LOC of duplication.

Doesn't move user-facing fairness numbers. Doesn't unblock #789 (which
is structurally bounded). It's a maintainability improvement that
makes future fairness work (#936, #937, #1211) cheaper to implement.

**If reviewers think the diff complexity isn't worth the LOC reduction
when the existing 4 variants are already well-tested and stable,
PLAN-NEEDS-MAJOR or PLAN-KILL is reasonable.**

## 3. Concrete design

### 3.1 Trait-driven adapter

```rust
trait ServiceAdapter {
    type Item;
    type Scratch;

    fn drain_to_scratch(
        &mut self,
        queue: &mut CoSQueueRuntime,
        free_tx_frames: &mut Vec<TxFrame>,
        scratch: &mut Self::Scratch,
        area: &MmapArea,
        root_budget: u64,
        secondary_budget: u64,
        dscp_rewrite: Option<u8>,
    ) -> ExactCoSScratchBuild;

    fn restore_to_queue_head(
        &mut self,
        queue: &mut CoSQueueRuntime,
        scratch: &mut Self::Scratch,
        area: &MmapArea,
    );

    fn settle_submission(
        &mut self,
        queue: &mut CoSQueueRuntime,
        scratch: &mut Self::Scratch,
        inserted: u32,
    ) -> (u64, u64);  // (sent_packets, sent_bytes)

    fn release_scratch_frames(
        scratch: &mut Self::Scratch,
        free_tx_frames: &mut Vec<TxFrame>,
    );
}
```

Four adapter implementations, monomorphized at call sites:

```rust
struct LocalFifoAdapter;
struct LocalFlowFairAdapter;
struct PreparedFifoAdapter;
struct PreparedFlowFairAdapter;
```

### 3.2 Shared service skeleton

```rust
fn service_exact_queue<A: ServiceAdapter>(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    mut adapter: A,
    scratch: &mut A::Scratch,
) -> bool {
    // 1. Reap if no free TX frames
    // 2. Look up queue + dscp_rewrite + root_budget
    // 3. adapter.drain_to_scratch(...)
    // 4. Match on ExactCoSScratchBuild::{Ready, Drop}
    // 5. xsk.tx.transmit + writer.insert + commit
    // 6. Stamp submit timestamp
    // 7. Handle inserted == 0 (rollback)
    // 8. adapter.settle_submission(...)
    // 9. publish_committed_queue_vtime
    // 10. apply send result
    !sent_packets == 0
}
```

The 4 entry points become thin dispatchers:

```rust
pub(in crate::afxdp) fn service_exact_local_queue_direct(...) -> bool {
    let flow_fair = ...;
    let mut scratch = std::mem::take(&mut binding.scratch.scratch_exact_local_tx);
    let result = if flow_fair {
        service_exact_queue(binding, ..., LocalFlowFairAdapter, &mut scratch)
    } else {
        service_exact_queue(binding, ..., LocalFifoAdapter, &mut scratch)
    };
    binding.scratch.scratch_exact_local_tx = scratch;
    result
}
// similar for prepared variant
```

### 3.3 Generic monomorphization, not dyn

`fn service_exact_queue<A: ServiceAdapter>` instantiates 4 copies at
compile time. Hot path stays inlined; no dyn dispatch overhead.

Code size cost: 4× the skeleton body in the binary. At ~150 LOC of
generic code, that's ~600 LOC of generated code total — about
break-even with the current 4× inline duplication.

## 4. Public API preservation

Public function signatures (`service_exact_local_queue_direct`,
`service_exact_prepared_queue_direct`) preserved. Internal helpers
(adapter trait, monomorphized skeleton) are file-private.

## 5. Hidden invariants

- **Submit timestamp captured AFTER `writer.commit()`** (#812 Codex
  HIGH-1 — measurement methodology). The skeleton must preserve this.
- **Rollback is per-pop snapshot** (#785 Phase 3 Codex HIGH —
  `pop_snapshot_stack` LIFO restore). Adapter `restore_to_queue_head`
  must invoke the right helper for FIFO vs flow-fair (different
  rollback shapes).
- **V_min publish is post-settle, not post-submit** (#940 + #941).
  The skeleton's step 9 must come AFTER step 8.
- **Drop-error handling differs per variant** (FIFO drops a single
  item; flow-fair Drop variant carries `dropped_bytes` for the
  account_dequeue update). Adapter signature handles via
  `ExactCoSScratchBuild::Drop` enum carrying the variant-specific
  payload.

## 6. Risk

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Pure code motion; trait monomorphization preserves codegen shape |
| Trait abstraction overhead | LOW | Generic monomorphization, no dyn |
| Diff size / reviewer fatigue | MED | ~600 LOC moved/restructured |
| Rollback path subtle | MED | The 4 variants have slightly different rollback shapes; adapter must capture this faithfully |
| Hot-path perf regression | LOW-MED | Need before/after iperf-c / iperf-d measurement |

## 7. Test plan

- `cargo build --release` clean
- `cargo test --release` 977+ pass without modification
- iperf-c P=12 t=120 -R: aggregate + CoV within ±2 percentage points
  of pre-refactor master
- iperf-d P=12 t=120: aggregate + CoV within ±2 pp
- 5×flake on `cos::queue_service::tests::*`
- Hand-test rollback path: confirm a `inserted == 0` case correctly
  pushes scratch items back to the queue head in LIFO order (existing
  test should cover but verify it's still hit)

## 8. Out of scope

- Algorithmic changes to the service path
- Token-bucket / admission changes (separate file, separate concern)
- Telemetry counter consolidation (#1209)
- Struct-shape changes to CoSQueueRuntime (#1206 — that's a prereq)

## 9. Open questions for adversarial review

1. **Order with #1206.** This refactor accesses `CoSQueueRuntime`
   fields heavily. If #1206 lands first, the access patterns change
   to `queue.config.field` etc. Should #1207 wait for #1206, or do
   them concurrently with rebase?
2. **Trait scope.** Could `Self::Scratch` be a single type
   parameterized by `Item`? Currently 4 distinct scratch types;
   consolidating would force more refactoring of the scratch shape
   itself.
3. **Generic monomorphization vs `match`.** Could the variant
   dispatch be a runtime `match` on a `ServiceVariant` enum, with
   `service_exact_queue` taking `variant: ServiceVariant`? Cuts
   binary size but adds a branch per call. Worth it?
4. **Settle-submission split.** Current code has different
   "stamp accepted descriptors" logic between FIFO and flow-fair.
   Should that move INTO the adapter, or stay in the skeleton with
   a callback?

## 10. Verdict request

PLAN-READY → execute (single PR, ~600 LOC diff).
PLAN-NEEDS-MINOR → tweak adapter shape.
PLAN-NEEDS-MAJOR → revise (different abstraction, e.g., enum-dispatch).
PLAN-KILL → existing duplication is fine; not worth the diff.
