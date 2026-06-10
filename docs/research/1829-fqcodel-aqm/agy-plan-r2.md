I will now inspect the plan v2 file to understand the FQ-CoDel AQM proposal.
I will look for the exact implementation details in `userspace-dp/src/afxdp/cos/admission.rs` to check the admission ECN behavior and queue promotion.
I will now check `/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/admission.rs` to see what is there around lines 525-532.
I will now view `cos/queue_service/service.rs` around lines 21-27 in the worktree to verify the dispatch of flow_fair.
I will check `queue_service/mod.rs` around lines 1610 and 1653 to see how non-exact queues are served and if the fused peek+pop with the `MIN_FINISH_BUCKET_FIFO` sentinel covers single-flow non-exact queues.
I will search for the definition of `cos_queue_peek_min_bucket` to understand how it handles FIFO vs MQFQ queues.
I will view `cos/queue_ops/mod.rs` around line 222.
I will view the next lines of `queue_ops/mod.rs` to verify the pop behavior for FIFO queues.
I will find where `cos_queue_pop_known_bucket` is defined.
I will view `cos/queue_ops/pop.rs` around line 114.
I will view `cos_queue_pop_known_bucket_inner` in `queue_ops/pop.rs`.
I will search for the definition of the `flow_fair` method on `CoSQueueRuntime` to see if it relies on `flow_fair_state.is_some()`.
I will search for `flow_fair` definition inside the struct `CoSQueueRuntime` in the types directory.
I will view `/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/types/cos.rs` around line 612 to see how `flow_fair` is implemented.
I will search for functions starting with `service_exact_` in `queue_service/service.rs` to see if they all have this `flow_fair` early return dispatch pattern.
I will view `cos/queue_service/service.rs` around line 372.
I will search for definitions of exact queue drains in `queue_service/drain.rs` to see what is defined and who calls them.
I will search for references to `drain_exact_local_fifo_items_to_scratch` to confirm it is only called from the unreachable portion of `service_exact_local_queue_direct`.
I will view `/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_service/service.rs` around line 57.
I will search for occurrences of `build_cos_batch_from_queue` to verify how non-exact queues are handled.
I will view `queue_service/drain.rs` around lines 217 and 472 in the worktree to check the exact flow-fair peek-pop structures.
I will view `/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_service/drain.rs` around line 472.
I will view `cos/queue_ops/pop.rs` from line 1 to 100 to check if `local_item_count` is handled inside `cos_queue_pop_known_bucket` or the pop helper.
I will view the rest of `/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_ops/pop.rs` to see what is updated in `cos_queue_pop_known_bucket_inner`.
I will search for the definition of `account_cos_queue_flow_dequeue` to verify if it handles flow-bucket bytes, active flow count, etc.
I will view `cos/queue_ops/accounting.rs` around line 83.
I will view the next lines of `accounting.rs` to see what else `account_cos_queue_flow_dequeue` does.
I will search for `cos_queue_clear_orphan_snapshot_after_drop` to verify its implementation and effects.
I will view `cos/queue_ops/drain.rs` around line 32.
I will view the rest of `cos/queue_ops/drain.rs` to see the complete implementation of `cos_queue_clear_orphan_snapshot_after_drop`.
I will view `/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_service/drain.rs` lines 490 to 520.
I will search for occurrences of `recycle_cancelled_prepared_offset_with_shared` to understand how prepared frame recycling is handled on cancel/discard.
I will view `cos/queue_service/drain.rs` around line 527.
I will view `cos/queue_service/mod.rs` around line 558 to see how `build_cos_batch_from_queue` is called and what state is available in the caller.
I will search for references to `select_non_exact_cos_guarantee_batch` or similar batch selection functions in `worker/cos/` or the tx paths to see how they are processed.
I will view `cos/queue_service/mod.rs` lines 530-550 to see the context of line 558.
I will view lines 480 to 530 of `cos/queue_service/mod.rs` to see the name of the function containing the `build_cos_batch_from_queue` call.
I will view lines 460 to 480 of `cos/queue_service/mod.rs` to get the function name.
I will view `cos/queue_service/mod.rs` around line 1274 to see what function calls `build_cos_batch_from_queue` in production.
I will view `cos/queue_service/mod.rs` around line 1250.
I will search for occurrences of `select_cos_surplus_batch` to see how the resulting `CoSBatch` is handled.
I will search for `build_nonexact_cos_batch` to see who calls the non-exact queue selection functions.
I will view `/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_service/mod.rs` around line 190.
I will search for `into_prepared_request` or `to_local_request` to verify if they are conversion functions that will need to copy the `enqueue_ns` field.
I will view `types/tx.rs` around line 29 to inspect the definition of `into_prepared_request`.
I will check `cos/queue_ops/push.rs` in the worktree to see how promotion is triggered and if the CoDel state is initialized/allocated correctly during lazy promotion.
I will search for `promote_to_flow_fair` definition.
I will view `push.rs` around line 87.
I will search for `struct FlowFairState` to inspect the MQFQ scheduling structure and where the per-bucket CoDel state array can be integrated.
I will view `/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/types/cos.rs` around line 735.
I will view lines 776 to 820 of `types/cos.rs`.
I will view lines 821 to 860 of `types/cos.rs`.
I will search for functions that rebuild or update the Class of Service runtime, to verify that CoDel state is correctly initialized, preserved, or reset when the configuration changes.
I will view `/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/builders.rs` to see how config reloads rebuild the runtimes.
I will search for how the `cos_interfaces` map is cleared or reset during a configuration reload or swap.
I will view `worker/cos/mod.rs` around line 365 to check config reload reset logic.
I will view the rest of the function `reset_binding_cos_runtime` to see how configuration changes and epoch resets handle outstanding items in the queues.
I will view the ECN policy logic in `userspace-dp/src/afxdp/cos/admission.rs` to see how per-flow vs aggregate ECN marking is applied.滋 Under what conditions does it fire? Let's look around line 276. Obesity checks are there. Or let's search/grep for `apply_cos_admission_ecn_policy`. 滋 This will help us confirm if there's any gap in signaling. Want to check if there is any window (either configuration reload or lifecycle) where neither is active. Or does one suppress the other cleanly? Let's check.
I will search for occurrences of `apply_cos_admission_ecn_policy` to see how it is ordered relative to enqueue/promotion.
I will view `/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/tx/cos_classify.rs` around line 878 to see the sequencing of enqueue, promotion, and ECN.
I will view the next lines of `cos_classify.rs` to see when the item is pushed back.
# Adversarial Review: Issue #1829 — CoS FQ-CoDel dequeue-time AQM

**Verdict**: `PLAN-READY-WITH-FINDINGS`

---

## 1. Verification of Round-1 Resolutions

### AoS CodelBucketState
*   **Status**: **Resolved**. 
*   **Evidence**: The plan adopts the array-of-structs pattern in §6.2a (`docs/research/1829-fqcodel-aqm/plan.md:286-302`), introducing `Option<Box<[CodelBucketState; 4096]>>` on `FlowFairState`. This keeps the memory layout clean and restricts cache-line accesses to a single bucket per dequeue.

### Admission/CoDel ECN Double-Signaling
*   **Status**: **Resolved**.
*   **Evidence**: §6.2c-bis (`docs/research/1829-fqcodel-aqm/plan.md:409-423`) outlines the suppression logic: when `codel_target_ns > 0`, the per-flow admission ECN arm is bypassed. The aggregate admission arm is preserved strictly as a buffer-protection backstop.

### FIFO Drain Accounting & Reachability Claim
*   **Status**: **Conceded & Resolved**. 
*   *Verification*:
    *   Exact queues always eagerly promote to `FlowFairState` at creation time: `userspace-dp/src/afxdp/cos/admission.rs:525-532`.
    *   The direct exact service loop dispatches instantly to the `flow_fair` version if `flow_fair()` returns true: `userspace-dp/src/afxdp/cos/queue_service/service.rs:20-27` (Local) and `userspace-dp/src/afxdp/cos/queue_service/service.rs:380-387` (Prepared).
    *   This renders the direct exact FIFO service branches and their associated index-walk drains (`drain_exact_*_fifo_items_to_scratch`) production-unreachable.
    *   Non-exact queues in FIFO mode (`flow_fair_state == None`) are serviced by `build_cos_batch_from_queue` in `userspace-dp/src/afxdp/cos/queue_service/mod.rs:1274,1370`, which uses the fused peek+pop: `userspace-dp/src/afxdp/cos/queue_service/mod.rs:1610,1653`.
    *   In FIFO mode, `cos_queue_peek_min_bucket` returns the sentinel `MIN_FINISH_BUCKET_FIFO`: `userspace-dp/src/afxdp/cos/queue_ops/mod.rs:226-231`.
    *   The corresponding pop operation (`cos_queue_pop_known_bucket`) uses this sentinel to pop directly from the front of the hot deque: `userspace-dp/src/afxdp/cos/queue_ops/pop.rs:165-170`.
*   *Conclusion*: Since all active FIFO and MQFQ dequeue paths are covered by the 4 fused peek+pop pairs, the index-walk drains are out of scope. The FIFO accounting concern is safely resolved by scoping.

---

## 2. Hostile Verification of v2 Deltas

### [FINDING-1] Stale Inline `CodelState` in `CoSQueueHotState` Across Promote/Demote Cycles
*   **Risk**: **Behavioral regression/spurious signals.** 
*   **Verification**: Unpromoted (FIFO) queues utilize an inline `CodelState` within `CoSQueueHotState` (§6.2a, `docs/research/1829-fqcodel-aqm/plan.md:281-285`). When a second flow arrives, the queue is promoted via `promote_to_flow_fair` in `userspace-dp/src/afxdp/cos/queue_ops/push.rs:87-96`, which allocates the bucket array in `FlowFairState`. When the queue becomes empty, it is demoted via `maybe_demote_drained_best_effort` in `userspace-dp/src/afxdp/cos/queue_ops/mod.rs:310`, which drops the `FlowFairState` box. 
*   **Failure Mode**: The inline `CodelState` in `CoSQueueHotState` is *never* reset or cleared during promotion or demotion. If the queue previously accumulated control-law state in FIFO mode (e.g., `dropping == true` or a high `count`), this stale state persists. Upon demotion back to FIFO, the next packet immediately inherits this stale state, causing immediate drops or ECN marks.
*   **Remedy**: Explicitly reset the inline `CodelState` to `CodelState::default()` inside `maybe_demote_drained_best_effort` (or during promotion).

### [FINDING-2] Phase-1 Telemetry Lacks Minimum Sojourn Tracking for Phase-2 Gate Validation
*   **Risk**: **Invalid Gate Correlation (False Positive/Negative).**
*   **Verification**: The Phase-2 gate in §6.1d (`docs/research/1829-fqcodel-aqm/plan.md:265-278`) checks if shaped queues sustain sojourn above target for $\ge 100\text{ ms}$. However, Phase 1 telemetry (§6.1c, `docs/research/1829-fqcodel-aqm/plan.md:252-264`) only tracks `sojourn_ewma_ns` (alpha=1/8) and `sojourn_peak_ns`. 
*   **Failure Mode**: CoDel acts on the *minimum* sojourn time over a sliding window (RFC 8289) to filter out transient spikes and scheduler service gaps. An EWMA or peak metric is heavily biased by transient scheduling delays (e.g., a worker thread context switch yielding a 10 ms delay for one batch). If a queue is emptied immediately after a gap, the minimum sojourn drops to 0, meaning there is no standing queue. However, EWMA and Peak would suggest a standing queue exists.
*   **Remedy**: Phase 1 telemetry must track and export a windowed minimum sojourn (e.g., `sojourn_min_ns`) to correctly validate the Phase-2 gating criteria in §6.1d.

### [FINDING-3] Phase-1 Standalone ECN Suppression Sequencing Gap
*   **Risk**: **Transient loss of per-flow ECN signals.**
*   **Verification**: The per-flow ECN bypass in §6.2c-bis (`docs/research/1829-fqcodel-aqm/plan.md:409-423`) is gated on `codel_target_ns > 0`. 
*   **Failure Mode**: If the bypass logic is merged in Phase 1 (standalone telemetry), setting `codel_target_ns > 0` to collect telemetry will bypass per-flow admission ECN *before* the dequeue-time CoDel marking engine exists. This leaves the queue with zero per-flow ECN signals, causing behavior shifts that invalidate Phase 1 baseline measurements.
*   **Remedy**: Explicitly document that the bypass logic in `userspace-dp/src/afxdp/cos/admission.rs` must not be introduced in the Phase-1 codebase; it must be sequenced strictly as part of the Phase-2 PR.

### CoS Config Rebuilds
*   **Status**: **Safe**.
*   **Verification**: During a config reload, `reset_binding_cos_runtime` in `userspace-dp/src/afxdp/worker/cos/mod.rs:320-350` drains all queues and clears the `cos_interfaces` map. Dropping the old runtime safely drops both `FlowFairState` and `CoSQueueHotState`, fully reclaiming the heap-allocated CoDel state arrays and resetting all timers. A new runtime is built cleanly from config parameters.
