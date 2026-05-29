**Fold Verification**
- r1 BLOCKING-1 is folded correctly on mechanism: the park estimator uses `head_len`, not quantum. Strictly, `head_len` is the 5th Rust argument, `need_bytes`, not the 4th: [queue_service/mod.rs:707](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_service/mod.rs:707) calls `estimate_cos_queue_wakeup_tick(... queue.transmit_rate_bytes(), head_len, now_ns, true)`, and [queue_service/mod.rs:1548](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1548) names that slot `need_bytes`.
- r1 BLOCKING-2 was not wrong. I do not acknowledge an r1 error; v2’s rejection is false in this worktree.
- r1 BLOCKING-3 is folded on the TX counter: [tx_completion.rs:482](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/tx_completion.rs:482) writes `drain_sent_bytes`, and [tx_completion.rs:486](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/tx_completion.rs:486) splits `drain_guarantee_sent_bytes`. But the four-layer table is still defective below.
- H-LEASE is first-class now, and the source supports the lease target: [mod.rs:690](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:690) has `COS_ROOT_LEASE_TARGET_US: u64 = 200`; [token_bucket.rs:184](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/token_bucket.rs:184) computes `lease_bytes`; [token_bucket.rs:188](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/token_bucket.rs:188) early-returns when `queue.hot.tokens >= lease_bytes`.

**Findings**
BLOCKING-1: v2’s “no waterfill drain path” premise is false, so §3’s single-branch model and §5’s park-counter interpretation are invalid.

Evidence:
- [forwarding_build/cos.rs:426](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/forwarding_build/cos.rs:426): `let oversubscription_policy = match iface.cos_oversubscription_policy.as_str()`
- [forwarding_build/cos.rs:427](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/forwarding_build/cos.rs:427): `"guarantee-rate" => CoSOversubscriptionPolicy::GuaranteeRate`
- [cos/builders.rs:103](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/builders.rs:103): `oversubscription_policy: config.oversubscription_policy`
- [queue_service/mod.rs:596](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_service/mod.rs:596): `in GuaranteeRate mode ... dispatch to`
- [queue_service/mod.rs:608](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_service/mod.rs:608): `return select_exact_cos_guarantee_queue_waterfill(`
- [queue_service/mod.rs:853](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_service/mod.rs:853): waterfill Phase 1 has `if queue.hot.tokens < head_len`
- [queue_service/mod.rs:862](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_service/mod.rs:862): then calls `estimate_cos_queue_wakeup_tick`
- [queue_service/mod.rs:973](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_service/mod.rs:973): Phase 2 does `if root.tokens < head_len || queue.hot.tokens < head_len`
- [queue_service/mod.rs:974](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_service/mod.rs:974): `Don't park in Phase 2`

BLOCKING-2: F-E’s `class_granted < cap` guard is insufficient; it can busy-poll a worker-share-exhausted lease before epoch rotation.

Evidence:
- [rotate_epoch_v8.rs:39](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:39): `if start != 0 && now_ns < start.saturating_add(EPOCH_DURATION_NS) { return; }`
- [shared_cos_lease/mod.rs:1081](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1081): `if (my_consumed as u64) >= my_effective_share`
- [shared_cos_lease/mod.rs:1082](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1082): `break; // primary share exhausted`
- [shared_cos_lease/mod.rs:1153](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1153): `my_curr_tag == my_tag`
- [shared_cos_lease/mod.rs:1155](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1155): `(my_consumed_now as u64) >= my_effective_share`
- [shared_cos_lease/mod.rs:1156](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1156): `(class_granted_now as u64) < cap`

That is exactly the counterexample: class room remains, but this worker cannot acquire more until rotation or bypass. F-E must test worker share availability, not just class cap.

BLOCKING-3: §5’s `total_granted / cap_granted < 1 => drain park` bisection is not sound.

Evidence:
- [rotate_epoch_v8.rs:230](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:230): per-worker loop over `worker_active_flow_buckets`
- [rotate_epoch_v8.rs:232](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:232): `my_share = new_cap * my_count / total_flows`
- [shared_cos_lease/mod.rs:1092](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1092): `let class_room = cap - class_granted`
- [shared_cos_lease/mod.rs:1093](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1093): `let my_room = my_effective_share - my_consumed`
- [shared_cos_lease/mod.rs:1094](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1094): `let take = still_needed.min(class_room).min(my_room)`

With 12 streams spread across workers, `total_granted < cap_granted` can be a worker-share/equal-flow distribution artifact, not “drain cannot pull the grant.” The table needs a separate per-worker-share exhaustion branch before H7/H-LEASE.

MAJOR-1: H-LEASE still underspecifies the lease-size perturbation; `max_total_leased = burst/4` is not the actual formula.

Evidence:
- [shared_cos_lease/mod.rs:713](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:713): `let max_total_leased = burst_bytes`
- [shared_cos_lease/mod.rs:714](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:714): `.saturating_div(4)`
- [shared_cos_lease/mod.rs:715](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:715): `.min(max_frame_lease_bytes.saturating_mul(active_shards as u64))`
- [shared_cos_lease/mod.rs:1114](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1114): acquire gates on `try_bump_outstanding(... self.config.max_total_leased)`

Raising `lease_bytes` can raise the outstanding cap until `burst/4`, changing the same acquire path the carry relies on. §9 gestures at this, but §6/R4 still state the wrong bound.

MAJOR-2: H-TCP’s kill ratio needs byte-domain normalization before it can kill the plan.

Evidence:
- [types/tx.rs:12](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/tx.rs:12): `struct TxRequest`
- [types/tx.rs:13](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/tx.rs:13): `bytes: Vec<u8>`
- [types/tx.rs:79](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/tx.rs:79): `struct PreparedTxRequest`
- [types/tx.rs:81](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/types/tx.rs:81): `len: u32`
- [queue_ops/mod.rs:185](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_ops/mod.rs:185): `fn cos_item_len`
- [queue_ops/mod.rs:187](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_ops/mod.rs:187): `req.bytes.len()`
- [queue_ops/mod.rs:188](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_ops/mod.rs:188): `req.len`

`drain_sent` is TX frame bytes. iperf3 is application goodput. A raw `goodput/drain_sent` can falsely look like TCP loss from headers/retransmits. Wheel-park can also depress goodput through burstiness even if shaper bytes are full; the ratio can separate that only after payload/L2 normalization.

MINOR-1: v2’s “4th positional arg is `head_len`” wording is wrong even though the mechanism is right. Source signature has `queue_rate_bytes` as arg 4 and `need_bytes` as arg 5 at [queue_service/mod.rs:1543](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1543)-[1549](/home/ps/git/bpfrx/.claude/worktrees/1630-research-midrate-residual/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1549).

VERDICT: PLAN-NEEDS-MAJOR
