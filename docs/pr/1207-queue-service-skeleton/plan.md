# #1207 — Consolidate queue_service/service.rs around one monomorphized service skeleton

**Status:** DRAFT v1 — pending adversarial plan review (Codex + Gemini Pro 3)

## 1. Issue framing

`userspace-dp/src/afxdp/cos/queue_service/service.rs` (718 LOC)
holds four near-duplicate service variants:

| Fn | Scratch | Path | Drain | Restore | Settle |
|---|---|---|---|---|---|
| `service_exact_local_queue_direct` | `scratch_exact_local_tx: Vec<ExactLocalScratchTxRequest>` | Local FIFO | `drain_exact_local_fifo_items_to_scratch` | `release_exact_local_scratch_frames` | `settle_exact_local_fifo_submission` |
| `service_exact_local_queue_direct_flow_fair` | `scratch_local_tx: Vec<(u64, TxRequest)>` | Local MQFQ | `drain_exact_local_items_to_scratch_flow_fair` | `restore_exact_local_scratch_to_queue_head_flow_fair` | `settle_exact_local_scratch_submission_flow_fair` |
| `service_exact_prepared_queue_direct` | `scratch_exact_prepared_tx: Vec<ExactPreparedScratchTxRequest>` | Prepared FIFO | `drain_exact_prepared_fifo_items_to_scratch` | `release_exact_prepared_scratch` | `settle_exact_prepared_fifo_submission` |
| `service_exact_prepared_queue_direct_flow_fair` | `scratch_prepared_tx: Vec<PreparedTxRequest>` | Prepared MQFQ | `drain_exact_prepared_items_to_scratch_flow_fair` | `restore_exact_prepared_scratch_to_queue_head_flow_fair` | `settle_exact_prepared_scratch_submission_flow_fair` |

All four follow the same skeleton:
1. (Local only) if free_tx_frames empty, reap completions
2. Query queue dscp rewrite
3. Clear scratch
4. Read root tokens budget
5. Drain queue → scratch (via per-variant drain fn)
6. Match ExactCoSScratchBuild result; handle Drop / MirrorTxFrameReserve
7. If scratch empty after Ready, set error / return
8. Transmit (writer = xsk.tx.transmit(); insert; commit; drop)
9. Stamp submits post-commit at `monotonic_nanos()` (#812 HIGH #1)
10. If inserted == 0: count stall, wake tx, release/restore, refresh activity, return false
11. Bump submitted telemetry + outstanding_tx
12. Settle accepted prefix
13. Publish V_min (post-settle, #940)
14. apply_direct_exact_send_result
15. maybe_wake_tx
16. return progress

The only meaningful differences across the four variants are:
- Scratch vector type & item shape (different XdpDesc iterator)
- Pre-stage (`reap_tx_completions` only for Local kind because
  free_tx_frames is the Local-mirror frame pool)
- Drain fn (FIFO vs MQFQ; Local vs Prepared)
- Drop/empty/rollback handler (release-on-clear vs
  push-front-restore)
- Settle fn signature (slightly different param packs)
- Local FIFO sets `set_error("no free TX frame available")`;
  the other three do not (they return false silently on
  empty scratch after Ready)

The two public entry points (`service_exact_local_queue_direct`
and `service_exact_prepared_queue_direct`) dispatch to the
flow-fair variant first if `queue.flow_fair()` is true.

## 2. Honest scope / value framing

Pure code-quality / maintainability win on the hot CoS service
path. The issue self-rates as **P4 (moderate effort, low-medium
value)**. The win quantified:

**Baseline measurements (release build, master @ 63dfe02a):**

The four `service_exact_*` fns are aggressively inlined. They do
not appear as standalone symbols in `nm`. They all collapse into
`service_exact_guarantee_queue_direct_with_info` (the dispatcher
caller in `mod.rs`), which compiles to **0x5323 = 21,283 bytes**
of x86_64 machine code — the **3rd largest function in the
entire userspace-dp binary** (`nm --size-sort` confirms).

For comparison:
- 53,487 bytes — `poll_binding_process_descriptor` (full poll loop)
- 42,801 bytes — `build_forwarding_state_with_policy_counters_and_previous`
- **21,283 bytes — `service_exact_guarantee_queue_direct_with_info` (target)**
- 39,002 bytes — `worker_loop`

Service.rs source = 718 LOC. Issue asks for ≥ 200 LOC reduction.

The win, at absolute scale: if the four service variants are
de-monomorphized via a single non-generic skeleton with a small
state-shape struct, the call site shrinks from 4× inlined-copy
machine code to 1× shared body + 4 thin wrappers. Realistic code
size reduction estimate: **~10-12 KB of .text** (about 50% of
the 21,283-byte combined function), since:
- Stamp/submit/commit prologue+epilogue (~1.5 KB each × 4 = 6 KB)
  becomes 1× shared (~1.5 KB) → -4.5 KB
- Drop/MirrorTxFrameReserve handler (~0.8 KB each × 4) becomes
  1× shared → -2.4 KB
- inserted==0 path (~0.6 KB each × 4) → -1.8 KB
- Publish V_min + apply send + wake (~0.3 KB each × 4) → -0.9 KB

Perf consequences are likely **neutral** — modern CPUs (Skylake+)
have 32-KB L1i and a 1.5K-entry µop cache. Compressing one 21 KB
hot function to ~11 KB will not noticeably improve L1i; this
function is already inside the hot poll path where it stays warm.
Worst case the consolidation slightly hurts because the shared
skeleton forces stack-frame indirection through adapter calls
instead of straight-line inlining. We will measure.

**If reviewers conclude the perf gain is too small to justify
the churn, PLAN-KILL is an acceptable verdict.** The maintenance
value (one skeleton vs four near-copies) and the explicit Codex
ask in the issue (point to the disposition-doc retrospective)
are the real drivers.

## 3. What's already shipped / partially batched

- **#812** (Codex HIGH #1, shipped): post-commit submit stamping
  via `monotonic_nanos()` after `writer.commit()` + drop. All
  four service variants now sample `ts_submit` post-commit;
  this is **load-bearing** and the consolidated skeleton MUST
  preserve it (no pre-commit stamping).
- **#710** (shipped): `tx_submit_error_drops` Prometheus
  counter is bumped under `ExactCoSScratchBuild::Drop` paths.
  Per-variant counter bumps; consolidated skeleton MUST keep
  the same counter increments.
- **#940** (shipped): `publish_committed_queue_vtime` runs
  post-settle in all four variants. Even though FIFO queues
  have `vtime_floor=None` today, the call site is preserved
  as a no-op shield. Consolidated skeleton keeps this.
- **#789 / #1217** disposition doc §C is the published
  reference for this refactor. The disposition doc is the
  source of the proposed skeleton signature in the issue.
- **#1166** (TSO extract, merged) is the precedent for a layered
  consolidation extracting a large helper from `dispatch.rs`
  into its own module. Same shape: extract, preserve hot-path
  inlining, smoke the matrix.
- **#959** BindingWorker decomposition is complete (all phases
  shipped); sub-struct accessors (`binding.cos`, `binding.scratch`,
  `binding.tx_pipeline`, `binding.live`, `binding.telemetry`,
  `binding.xsk`, `binding.umem`, `binding.slot`) are stable and
  used by all four service fns in the same way.

## 4. Concrete design

### 4.1 Strategy: non-generic shared body, per-variant adapter trait

Issue suggested:
```rust
fn service_exact_queue<A: ServiceAdapter>(...)
```

A generic skeleton parameterized by an adapter trait WILL
monomorphize back to 4 copies and **does not reduce code
size**. The issue's own proposal would fail acceptance criterion
"LOC reduction in `service.rs` ≥ 200 lines" only at source-LOC
level; **machine-code size would barely change** because
monomorphization expands `service_exact_queue<A>` once per
adapter type.

**Revised strategy:** A non-generic shared skeleton that
accepts a small `ServiceShape` struct with **function pointers**
for the variant-specific stages. Function-pointer indirection
through an `fn(...)` (not `dyn Fn`) is one indirect-branch
predictable through BTB after warmup; cost ~1-3 cycles per call.
The skeleton runs ~4 of these indirect calls per service
invocation; against ~200ns of actual TX submit work, this is
~1% overhead AT MOST and likely zero (BTB-predicted).

```rust
// Non-generic, shared by all four variants.
fn service_exact_queue_skeleton(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    secondary_budget: u64,
    now_ns: u64,
    shared_recycles: &mut Vec<(u32, u64)>,
    shape: &ServiceShape,
) -> bool {
    if shape.needs_reap_local && binding.tx_pipeline.free_tx_frames.is_empty() {
        let _ = reap_tx_completions(binding, shared_recycles);
    }
    let queue_dscp_rewrite = cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx);
    (shape.clear_scratch)(binding);
    let root_budget = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.tokens)
        .unwrap_or(0);
    let build = (shape.drain)(
        binding,
        root_ifindex,
        queue_idx,
        root_budget,
        secondary_budget,
        queue_dscp_rewrite,
        shared_recycles,
    );
    match build {
        ExactCoSScratchBuild::Ready => {}
        ExactCoSScratchBuild::Drop { error, dropped_bytes } => {
            (shape.rollback)(binding, root_ifindex, queue_idx);
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(binding, root_ifindex, queue_idx, dropped_bytes);
            } else {
                refresh_cos_interface_activity(binding, root_ifindex);
            }
            binding.live.tx_errors.fetch_add(1, Ordering::Relaxed);
            binding.live.tx_submit_error_drops.fetch_add(1, Ordering::Relaxed);
            binding.live.set_error(error);
            return false;
        }
        ExactCoSScratchBuild::MirrorTxFrameReserve { dropped_bytes } => {
            if !shape.allow_mirror_reserve {
                unreachable!("prepared CoS queues do not drain local mirror clones")
            }
            if dropped_bytes > 0 {
                subtract_direct_cos_queue_bytes(binding, root_ifindex, queue_idx, dropped_bytes);
            } else {
                refresh_cos_interface_activity(binding, root_ifindex);
            }
            binding.live.mirror_drops_tx_frame_reserve.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    }
    let scratch_len = (shape.scratch_len)(binding);
    if scratch_len == 0 {
        if shape.empty_sets_error {
            maybe_wake_tx(binding, true, now_ns);
            binding.live.set_error("no free TX frame available".to_string());
        }
        return false;
    }

    // debug-log TCP RST sniff (prepared variants only)
    if cfg!(feature = "debug-log") && shape.debug_log_tcp_rst {
        (shape.debug_log_rst_sniff)(binding);
    }

    let mut writer = binding.xsk.tx.transmit(scratch_len as u32);
    let inserted = (shape.insert_descriptors)(&mut writer, binding);
    writer.commit();
    drop(writer);

    // #812 HIGH #1: post-commit stamp.
    let ts_submit = monotonic_nanos();
    (shape.stamp_submits)(binding, inserted, ts_submit);

    if inserted == 0 {
        binding.telemetry.dbg_tx_ring_full += 1;
        count_tx_ring_full_submit_stall(binding, root_ifindex, queue_idx, scratch_len as u64);
        maybe_wake_tx(binding, true, now_ns);
        (shape.rollback)(binding, root_ifindex, queue_idx);
        refresh_cos_interface_activity(binding, root_ifindex);
        binding.live.set_error(shape.insert_failed_error.to_string());
        return false;
    }
    binding.telemetry.dbg_tx_ring_submitted += inserted as u64;
    binding.tx_pipeline.outstanding_tx = binding.tx_pipeline.outstanding_tx.saturating_add(inserted);

    let (sent_packets, sent_bytes) = (shape.settle)(binding, root_ifindex, queue_idx, inserted as usize, now_ns);

    // #940 V_min publish (no-op for FIFO).
    publish_committed_queue_vtime(
        binding
            .cos
            .cos_interfaces
            .get(&root_ifindex)
            .and_then(|root| root.queues.get(queue_idx)),
    );
    apply_direct_exact_send_result(binding, root_ifindex, queue_idx, sent_packets, sent_bytes);
    maybe_wake_tx(binding, true, now_ns);
    sent_packets > 0 || sent_bytes > 0
}
```

### 4.2 ServiceShape

```rust
struct ServiceShape {
    needs_reap_local: bool,
    allow_mirror_reserve: bool,
    debug_log_tcp_rst: bool,
    empty_sets_error: bool,
    insert_failed_error: &'static str,
    clear_scratch: fn(&mut BindingWorker),
    drain: fn(&mut BindingWorker, i32, usize, u64, u64, Option<u8>, &mut Vec<(u32, u64)>) -> ExactCoSScratchBuild,
    rollback: fn(&mut BindingWorker, i32, usize),
    scratch_len: fn(&BindingWorker) -> usize,
    debug_log_rst_sniff: fn(&mut BindingWorker),
    insert_descriptors: fn(&mut TxWriter, &BindingWorker) -> u32,
    stamp_submits: fn(&mut BindingWorker, u32, u64),
    settle: fn(&mut BindingWorker, i32, usize, usize, u64) -> (u64, u64),
}
```

The four shape constants live as `const` items at module
scope. Function-pointer constants resolve at link time; no
allocation, no `Box<dyn>`. The shape is passed by `&` so the
caller side reads 8 bytes (the pointer) plus four register
arguments.

### 4.3 Thin wrappers

```rust
#[inline]
pub(super) fn service_exact_local_queue_direct(...) -> bool {
    let flow_fair = binding.cos.cos_interfaces.get(&root_ifindex)
        .and_then(|root| root.queues.get(queue_idx))
        .map(|q| q.flow_fair()).unwrap_or(false);
    let shape = if flow_fair { &SHAPE_LOCAL_FLOW_FAIR } else { &SHAPE_LOCAL_FIFO };
    service_exact_queue_skeleton(binding, root_ifindex, queue_idx,
        secondary_budget, now_ns, shared_recycles, shape)
}

#[inline]
pub(super) fn service_exact_prepared_queue_direct(...) -> bool {
    let flow_fair = ...;
    let shape = if flow_fair { &SHAPE_PREPARED_FLOW_FAIR } else { &SHAPE_PREPARED_FIFO };
    service_exact_queue_skeleton(...)
}
```

### 4.4 Hot-path inlining decisions (explicit)

- `service_exact_queue_skeleton`: **`#[inline(never)]`**. The
  whole point is to NOT have 4 inlined copies. Skeleton lives
  out of line.
- Public entry points (`service_exact_local_queue_direct`,
  `service_exact_prepared_queue_direct`): keep `#[inline]`
  (their current attribute). They are trivial dispatchers.
- Shape constants: `static SHAPE_*: ServiceShape = ...`. fn
  pointers in shape resolve at link time.
- Per-shape adapters (drain wrappers, insert wrappers, etc.):
  declared as private `fn` items at module scope. Mark
  `#[inline(never)]` on the inner adapter bodies that the
  current fns inline today (drain/settle/restore are already
  separate fns; the only newly-introduced functions are the
  thin shape adapters that convert the per-variant call
  signature to the uniform fn-pointer signature). Each adapter
  is ~10 lines and adds one call frame; we explicitly forbid
  the compiler from inlining them back into the skeleton
  because that would defeat consolidation.

### 4.5 Borrow-checker shape

The four current variants are tight loops over `binding` with
interleaved &/&mut borrows. The skeleton must not introduce
borrow-checker regressions. Key concern: passing
`shared_recycles: &mut Vec<(u32, u64)>` into the drain
adapter while also passing `&mut binding`. Today this works
because `shared_recycles` is a separate local; the adapter
takes both as args. Same shape preserved.

The `scratch_len` adapter takes `&BindingWorker` (not &mut)
because it just reads the length. This matches the current
`binding.scratch.scratch_X.is_empty()` shape.

## 5. Public API preservation

The two `pub(super)` entry points keep identical signatures:

- `service_exact_local_queue_direct(binding, root_ifindex, queue_idx, secondary_budget, now_ns, shared_recycles) -> bool`
- `service_exact_prepared_queue_direct(binding, root_ifindex, queue_idx, secondary_budget, now_ns, shared_recycles) -> bool`

Both are called from `mod.rs:422` and `mod.rs:430` (only
callers in the tree). No external use.

The two `*_flow_fair` variants are private (`fn`, no `pub`)
in master and become unused after consolidation; they will
be deleted.

## 6. Hidden invariants the change MUST preserve

| Invariant | Where | How preserved |
|---|---|---|
| Post-commit submit stamping (#812 HIGH #1) | `ts_submit = monotonic_nanos()` AFTER `writer.commit() + drop(writer)` | Skeleton has a single stamp call site after `drop(writer)` |
| Only accepted prefix (`take(inserted as usize)`) stamped | All four variants today | `stamp_submits` adapter implements `take(inserted)` per variant |
| Retry tail returned to free_tx_frames | Local rollback paths only | `rollback` adapter for Local variants does `release_exact_local_scratch_frames` (FIFO) or `restore_exact_local_scratch_to_queue_head_flow_fair` (MQFQ) |
| Restore-vs-release semantics | FIFO release (drop frames), MQFQ restore (push_front) | Per-shape `rollback` adapter encodes the right policy |
| `outstanding_tx.saturating_add(inserted)` after commit | All four | Skeleton |
| `tx_submit_error_drops` bumped only on Drop, not on inserted==0 | Different counters | Skeleton |
| `mirror_drops_tx_frame_reserve` bumped on MirrorTxFrameReserve, NOT for prepared variants | `unreachable!()` in prepared | `allow_mirror_reserve: bool` shape flag → `unreachable!()` else accept |
| V_min publish post-settle (#940) | After settle, before apply_send | Skeleton |
| `set_error("no free TX frame available")` on empty-after-Ready | Only `service_exact_local_queue_direct` (FIFO) does this; the other three return false silently | `empty_sets_error: bool` shape flag |
| TCP RST debug-log sniff | Prepared variants only, behind `cfg!(feature = "debug-log")` | `debug_log_tcp_rst: bool` shape flag |
| HA sync portability | Not affected — service path doesn't touch HA | n/a |
| Side-effect ordering: reap → drain → insert/commit → stamp → settle → publish → apply | Strict order in all four | Skeleton enforces single ordering |
| `count_tx_ring_full_submit_stall` called with `scratch_len` (Local FIFO uses `.len()`, Local MQFQ also `.len()`, Prepared FIFO also `.len()`, Prepared MQFQ also `.len()`) | All four | `scratch_len` adapter reads each variant's `.len()` |
| `set_error("tx ring insert failed")` (local) vs `set_error("prepared tx ring insert failed")` (prepared) | Different strings | `insert_failed_error: &'static str` shape field |

## 7. Risk assessment

| Risk class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Pure code motion. Adapter dispatch is mechanical. Per-class CoS smoke (5201-5206 × v4+v6 × push+reverse, all 24 cells) covers every variant. |
| Lifetime / borrow-checker | LOW-MED | Function-pointer adapters take exact same arg lifetime shape as inline code. One known thing to watch: passing `&mut binding` through adapter while shape is `&ServiceShape` borrow — shape is `'static` so no conflict. |
| Performance regression | LOW | Four extra indirect calls per service invocation; ~3-12 cycles total against ~200 ns of actual TX submit work (= ~600 cycles). Worst case ~2% per-call overhead, masked by BTB prediction after warmup. Acceptance: iperf-c P=12 t=120 no measurable degradation, per-class CoS smoke unchanged. |
| Architectural mismatch (#961 / #946 Phase 2) | LOW | This is structural code motion, not a control-flow re-architecture. The issue's own ask is identical to disposition-doc §C, which is the published reference. No batched-pipeline / cross-packet state restructure. |

## 8. Test plan

- `cargo build --release` clean (`/dev/shm/cargo`)
- `cargo test --release` — full suite must pass; ~950+ tests
- 5/5 flake check on the most affected named tests (the
  cos::queue_service tests in `queue_service/tests.rs`, which
  is 2,164 LOC of unit + property tests over all four service
  variants).
- `go test ./...` — 30 packages pass
- **Pass A (CoS disabled)** smoke on loss userspace cluster:
  - v4 + v6 × push + reverse single-stream (4 cells)
  - v4 + v6 × `-P 12 -R -t 10` multi-stream reverse (2 cells) — line rate, 0 retrans
- **Pass B (CoS enabled)** smoke:
  - 5201-5206 × v4 + v6 × push + reverse (24 cells)
  - Shaped class (iperf-a) hits configured rate cleanly, ECN marks allowed, no buffer drops
- **Code-size verification**: `nm --size-sort` shows
  `service_exact_guarantee_queue_direct_with_info` shrunk from
  21,283 bytes to ≤ 12,000 bytes; new `service_exact_queue_skeleton`
  symbol present (≤ 6,000 bytes); `.text` section total
  smaller (~8-10 KB)
- **No new dyn dispatch on hot path**: confirmed by
  `objdump -d | grep -E "callq.*\*"` count not increasing
  in service path (the four shape-fn-pointer calls are NOT
  `callq *(...)` indirect — they're direct `callq` to const
  fn-pointer addresses resolved at link time; verify)

## 9. Out of scope (explicitly deferred)

- Consolidating the drain stage (`drain.rs` has 4 drain fns ~540 LOC). Different
  data shapes (mirror clones vs FIFO refs vs prepared
  capability handles). Could be Step 2.
- Consolidating the settle stage (`mod.rs:926–1078` has 4 settle
  fns). Different rollback policy. Step 3.
- Restore helpers (`restore_exact_local_scratch_to_queue_head_flow_fair`,
  `restore_exact_prepared_scratch_to_queue_head_flow_fair`) —
  retain as-is, called by rollback adapters.
- Pre-#1561 CoSBatch publish ordering is preserved bit-for-bit;
  ordering changes are explicitly out of scope.
- Performance measurement / hardware perf-counter analysis on
  bare metal — lab is virtualized; perf neutrality is gauged
  via iperf-c smoke matrix.

## 10. Open questions for adversarial review

1. **Is the fn-pointer-table strategy preferable to the generic
   `service_exact_queue<A: ServiceAdapter>` strategy that the
   issue body literally suggests?** The generic strategy
   monomorphizes back to 4 copies and DOES NOT reduce machine
   code. Reviewers: is there a third option (e.g., trait object
   with `dyn ServiceAdapter` — explicitly rejected by acceptance
   criterion "no dyn on hot path") that is better?

2. **Is the ~10-12 KB .text reduction estimate realistic, or
   is it optimistic?** Could the consolidation cause the
   skeleton fn to grow because it carries more arguments
   (extra `&shape` pointer, looser register allocation, more
   stack spills)?

3. **`empty_sets_error: bool` is a genuine behavioral
   difference between Local FIFO and the other three.** Is
   this an undocumented bug we should NOT preserve (i.e.,
   should all four variants set the same error string)? Or
   does the asymmetry have a real reason (Local FIFO is the
   only variant whose empty scratch means "out of TX
   frames" — the other three can be empty-after-Ready for
   other reasons like queue exhaustion that aren't worth
   surfacing as an error)?

4. **`insert_failed_error: &'static str`** — two strings
   today: `"tx ring insert failed"` and `"prepared tx ring
   insert failed"`. Reviewers: should we deduplicate to one
   string, or preserve both for operator visibility?

5. **Does function-pointer indirection through `static SHAPE_*:
   ServiceShape` actually compile to direct calls or to
   indirect-through-memory loads?** A `static SHAPE_FOO:
   ServiceShape = ServiceShape { drain: drain_fn_a, ... };`
   followed by `(shape.drain)(...)` — LLVM may or may not
   constant-propagate the function pointer. If it doesn't,
   we have 4 indirect branches per call. BTB should predict
   them, but worst-case mispredict (~15-20 cycles) × 4 = 60-80
   cycles. Against ~600 cycles of actual work that's ~10-13%.
   We may need to specialize on the static address.

6. **Drain fns currently take `&mut binding.cos.cos_interfaces`
   subfield directly (split borrow).** Funneling through a
   single `drain: fn(&mut BindingWorker, ...)` adapter forces
   the adapter to do the same split-borrow inside its body.
   This is fine but the adapter cannot itself be inlined back
   (or we lose consolidation). Are we sure the borrow shape
   composes?

7. **#812 post-commit stamping is load-bearing.** The skeleton
   collapses 4 stamp call sites to 1. If the consolidated
   stamp uses a fn-pointer adapter that does the `.take(inserted)`
   slicing, are we sure the compiler doesn't reorder
   `monotonic_nanos()` relative to the stamp loop in a way that
   re-introduces the bug #812 fixed?

8. **`unreachable!()` for prepared MirrorTxFrameReserve.** The
   skeleton replaces an inline `unreachable!()` with a
   `shape.allow_mirror_reserve == false → unreachable!()`
   branch. The `_unchecked` variant would be unsafe; the
   checked variant adds a branch on every call. Worth it for
   the safety, but it IS a new branch on the hot path.

9. **Is shipping this consolidation worth the churn at all?**
   The hot function being consolidated is the #3 largest in
   the binary; trimming ~10 KB doesn't change L1i pressure
   meaningfully. This is fundamentally a maintainability win.
   If reviewers conclude "the four current fns are fine and
   the consolidation cost > maintenance benefit", **PLAN-KILL
   is the correct outcome.** Do not push through.

10. **Field-by-field equivalence testing.** The issue's risk
    section says "Hot path. Plan-review is mandatory.
    Field-by-field equivalence testing." Does the test plan
    above actually meet that bar, or do we need a property
    test that drives both the old and new code paths with the
    same input and compares per-counter deltas?
