# Hostile Adversarial Plan Review (Round 1) — #1849: CoS per-packet overhead compensation

This review assesses the research plan documented at `docs/research/1849-overhead-comp/plan.md` on the branch `research/1849-overhead-comp` within the tree `/home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead`.

---

## Numbered Findings

### 1. Missing Rate-Domain Surplus Debits in `tx_completion.rs`
*   **Severity**: Critical
*   **Description**: The §3a inventory completely misses the surplus budget accounting under exact queue demand. In [tx_completion.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/tx_completion.rs#L726-L733) (and the matching prepared variant at L836-L840), the shaper debits the non-exact surplus budget using payload bytes (`sent_bytes`) without any overhead compensation:
    ```rust
    if debit_nonexact_surplus_budget {
        if let Some(backlog) = shared_exact_backlog.as_ref() {
            backlog.consume_residual_surplus_budget(sent_bytes);
        } else {
            root.nonexact_surplus_under_exact_tokens = root
                .nonexact_surplus_under_exact_tokens
                .saturating_sub(sent_bytes);
        }
    }
    ```
    Because `residual_rate` (which refills these buckets in [queue_service/mod.rs:366-373](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L366-L373)) is in the rate domain and would be wire-rate under Option B, debiting payload bytes (`sent_bytes`) breaks basis-pairing invariant **I1** and leaks tokens for non-exact surplus traffic on small-packet mixes.

### 2. Lack of `sent_packets` Parameter in `apply_cos_*_result`
*   **Severity**: High
*   **Description**: The entry points [apply_cos_send_result](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/tx_completion.rs#L655-L663) and [apply_cos_prepared_result](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/tx_completion.rs#L761-L768) in [tx_completion.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/tx_completion.rs) do not take a packet-count argument:
    ```rust
    pub(in crate::afxdp) fn apply_cos_send_result(
        binding: &mut BindingWorker,
        root_ifindex: i32,
        ...
        sent_bytes: u64,
        retry: VecDeque<TxRequest>,
    )
    ```
    Without receiving `sent_packets` alongside `sent_bytes`, these completion hooks cannot compute `wire_bytes = sent_bytes + sent_packets * overhead_bytes`. This violates the plan's §3c assumption that batch-level wire bytes can be computed with zero new work in the loops because the completion hooks are currently blind to packet count.

### 3. Length Extraction Bypass of `cos_item_len` in Egress Drain Loops
*   **Severity**: Critical
*   **Description**: The plan's claim in §3c that `cos_item_len` is the *only* per-item length read in the scheduler (with 14 call sites) is factually incorrect. In [drain.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/queue_service/drain.rs), the egress loops directly destructure [CoSPendingTxItem](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/types/cos.rs#L711) to extract length inline:
    *   [drain.rs:69](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/queue_service/drain.rs#L69): `let len = req.bytes.len() as u64;`
    *   [drain.rs:220](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/queue_service/drain.rs#L220): `let len = match front { CoSPendingTxItem::Local(req) => req.bytes.len() as u64, ... };`
    *   [drain.rs:334](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/queue_service/drain.rs#L334): `let len = req.len as u64;`
    *   [drain.rs:475](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/queue_service/drain.rs#L475): `let len = match front { CoSPendingTxItem::Prepared(req) => req.len as u64, ... };`
    
    If these loops bypass `cos_item_len`, the drain pass budgets (`remaining_root` / `remaining_secondary`) will be decremented by payload bytes instead of wire bytes. This lets more packets slide onto the wire than the rate shaper allowed, introducing temporary link overdrive and a budget desync.

### 4. Incorrect Push/Enqueue Site in Occupancy Domain (O1)
*   **Severity**: Medium
*   **Description**: The §3b inventory states that occupancy updates for `queue.hot.queued_bytes` occur in `queue_ops/push.rs:108,161`. In reality, [push.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/queue_ops/push.rs) does not access `queued_bytes` at all. The actual admission push site is located in [tx/cos_classify.rs:934](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/tx/cos_classify.rs#L934):
    ```rust
    queue.hot.queued_bytes = queue.hot.queued_bytes.saturating_add(item_len);
    ```
    This is a planning/documentation error that misidentifies the boundary of the occupancy domain.

### 5. Alignment and Footprint impact of `CoSQueueConfigState`
*   **Severity**: Low
*   **Description**: The immutable [CoSQueueConfigState](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/types/cos.rs#L630) is currently 56 bytes. Copying the 8-byte `overhead_bytes` constant into each queue's config state expands the struct to exactly 64 bytes (a full cache line). While this neatly aligns the start of [CoSQueueHotState](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/types/cos.rs#L701) to a 64-byte boundary (preventing false sharing), it increases the memory footprint of the queue runtime array and must be tested for cache pressure at high scale.

---

## Multiple Path Verification

### §4 Boundary Choice Analysis
The plan's assertion that mixing payload-based class guarantees (Option A) with a wire-based root shaper skews the waterfill allocator ([#1743](https://github.com/psaab/xpf/issues/1743)/[#1614](https://github.com/psaab/xpf/issues/1614)) is **correct**. 
If the root token bucket is wire-based, it drains faster under small-packet traffic than the payload-based class token buckets expect. Consequently, the scheduler will run out of root tokens before the class guarantees are fully satisfied (even when the configured class guarantees are mathematically within the root shaping rate). Coherent boundaries (Option B) are necessary if the feature is implemented.

### §5 Config Spelling & Range
Proposed nesting under `shaping-rate` matches the nested `burst-size` node in [schema.go:1086](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/pkg/config/schema.go#L1086). Limiting the knob to unsigned `0..124` is a sensible safety choice. Introducing negative overhead (Junos signed `-120..124`) requires signed saturating additions (e.g. `saturating_add_signed`), which introduces complexity, potential zero-byte packet pacing loops, or underflow errors.

---

## Final Verdict

**PLAN-KILL**

### Justification
1.  Our explicit position on **Q1 (demand gate)** is that this feature is dead weight and must be deferred or killed.
2.  The documented workaround of shaping at 85–95% headroom in [cos-wan-sqm.md:134-142](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/docs/cos-wan-sqm.md#L134-L142) is fully adequate for low-rate framed links (e.g., sub-100 Mbit PPPoE/DSL) where AF_XDP has massive CPU headroom.
3.  Implementing wire-based compensation introduces high correctness risks and extensive hot-path churn across multiple modules (such as [tx_completion.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/tx_completion.rs), [drain.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/cos/queue_service/drain.rs), and [cos_classify.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/userspace-dp/src/afxdp/tx/cos_classify.rs)) to address the plan's severe inventory omissions.
4.  Finally, because the loss cluster lacks actual PPPoE/ATM endpoints, the bufferbloat improvement is structurally unprovable in this lab ([cos-wan-sqm.md:273-274](file:///home/ps/git/bpfrx/.claude/worktrees/1849-research-overhead/docs/cos-wan-sqm.md#L273-L274)), making the feature's real-world value impossible to validate.
