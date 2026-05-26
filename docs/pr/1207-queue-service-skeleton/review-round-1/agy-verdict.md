# AGY adversarial PLAN review (plan v1, round 1)

Task id: `adversarial-review-mpn2zlka-837uwh` (timed out)
Retry task id: `adversarial-review-mpn39vc7-1z493e` (succeeded)
Verdict: **PLAN-KILL on v1** — endorses salvage pivot

## Verbatim summary

> The `PLAN-KILL` verdict on plan v1 is **100% correct**. The plan is
> fundamentally unsalvageable in its current form due to multiple
> fatal compiler and architectural issues.

AGY independently validated the four fatal findings:

1. **Dynamic Dispatch Violation** — `(shape.drain)(...)` compiles to
   `callq *%rax` indirect because `#[inline(never)]` prevents
   constant-propagation of the static SHAPE_FOO reference.
2. **Borrow-Checker Failure E0502** — `writer = binding.xsk.tx.transmit(...)`
   holds `&mut binding.xsk.tx`; passing `binding` again to
   `insert_descriptors(&mut writer, binding)` is a hard compile error.
3. **x86_64 ABI Stack Spilling** — 7-arg skeleton exceeds the 6
   integer-arg register limit (`rdi rsi rdx rcx r8 r9`); `shape: &ServiceShape`
   spills to stack on the hot path.
4. **Semantic Calcification of `empty_sets_error`** — flag obscures the
   real distinction (Local pool exhaustion vs Prepared queue state).

## Recommended salvage pivot (verbatim)

```rust
enum ServiceVariant {
    LocalFifo, LocalFlowFair, PreparedFifo, PreparedFlowFair,
}

#[inline]
pub(super) fn service_exact_local_queue_direct(...) -> bool {
    let flow_fair = ...;
    if flow_fair {
        service_exact_inline_body::<{ServiceVariant::LocalFlowFair}>(...)
    } else {
        service_exact_inline_body::<{ServiceVariant::LocalFifo}>(...)
    }
}

#[inline(never)]
fn finish_submission_epilogue(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    inserted: u32,
    sent_packets: u64,
    sent_bytes: u64,
    now_ns: u64,
) -> bool {
    let ts_submit = monotonic_nanos();
    stamp_submits(&mut binding.tx_pipeline.tx_submit_ns, ..., ts_submit);
    binding.telemetry.dbg_tx_ring_submitted += inserted as u64;
    binding.tx_pipeline.outstanding_tx = binding.tx_pipeline.outstanding_tx.saturating_add(inserted);
    publish_committed_queue_vtime(...);
    apply_direct_exact_send_result(binding, root_ifindex, queue_idx, sent_packets, sent_bytes);
    maybe_wake_tx(binding, true, now_ns);
    sent_packets > 0 || sent_bytes > 0
}
```

Why the pivot works (per AGY):
- Zero dynamic dispatch (all calls statically resolved)
- Compile-safe split borrows (drain/insert stay inline in caller)
- Register-perfect epilogue (7 args but cold path after `commit()`)
- Maintains hot-path performance while deduplicating the 60-80 LOC
  shared epilogue

AGY also flagged property-based differential testing as mandatory for
any v2 attempt: a mock harness must run both old and new paths with
the same inputs and assert bit-for-bit equivalence in ring writes,
telemetry, and queue state.
