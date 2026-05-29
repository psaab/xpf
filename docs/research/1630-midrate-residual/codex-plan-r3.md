**A. Verification**

1. Boundary arithmetic: refuted for the cited worktree/run shape.
The code does compute `floor(quantum_sum * fraction)`, and `candidate_budget > pass1_remaining` does break to Phase 2. But `quantum_sum` is not the runnable/nonempty eligible set v3 assumes. It is the static configured exact queue vector.

Evidence:
- `userspace-dp/src/afxdp/cos/builders.rs:80`: `let mut exact_queues_by_rate_ascending: Vec<usize> = (0..config.queues.len())`
- `userspace-dp/src/afxdp/cos/builders.rs:81`: `.filter(|&idx| config.queues[idx].exact && config.queues[idx].guarantee_enabled)`
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:789`: `for &qi in &root.exact_queues_by_rate_ascending {`
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:790-791`: `quantum_sum = quantum_sum.saturating_add(cos_guarantee_quantum_bytes(&root.queues[qi]));`
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:798`: `let pass1 = ((quantum_sum as f64) * frac).floor() as u64;`
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:811-815`: Phase 1 filters empty/runnable only after the budget was inflated.
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:889`: `if candidate_budget > root.waterfill_pass1_remaining_bytes {`

So: a stripped runtime containing only 3g would exclude 3g. The actual `cos-iperf-config.set` solo traffic shape with all exact classes configured does not support v3’s `0.7 * 75000 = 52500` solo conclusion.

2. H-LEASE kill: confirmed.
- `userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1062-1064`: `my_effective_share = ... unwrap_or(my_share)`
- `userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1081-1082`: `if ... >= my_effective_share { break; }`
- `userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1093-1097`: grant `take` is bounded by `my_room`.
- `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:218-222`: `elapsed_ns` is capped by `EPOCH_DURATION_NS`, then `new_cap` is derived from it.
- `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:232`: `my_share = new_cap * my_count / total_flows`.

3. Layering: confirmed.
- `userspace-dp/src/afxdp/types/cos.rs:369`: `pub(in crate::afxdp) struct CoSInterfaceRuntime`
- `userspace-dp/src/afxdp/types/cos.rs:382-385`: oversubscription policy/fraction live there.
- `userspace-dp/src/afxdp/types/cos.rs:406`: `exact_queues_by_rate_ascending: Vec<usize>`
- `userspace-dp/src/afxdp/types/cos.rs:414`: `waterfill_pass1_remaining_bytes: u64`
- `userspace-dp/src/afxdp/types/cos.rs:419`: `waterfill_phase2_cursor: usize`
These are plain per-runtime fields, not atomics and not the v8 seqlock payload.

**Findings**

BLOCKING-1: v3’s load-bearing solo/boundary arithmetic is wrong for the actual configured-runtime model.  
The plan assumes `quantum_sum` is over runnable/nonempty exact queues. Source shows it is over every configured exact guarantee queue in `exact_queues_by_rate_ascending`, built once at config apply. That means a “solo 3g” traffic run using the full fixture can have the full 10-class Phase-1 budget, so 3g is Phase-1-honored, not Phase-2-only. F-W1 would then be a no-op for the measured solo residual.

MAJOR-1: Phase 2 is not proven lossy for a stripped solo class either.  
The drain loop re-enters with fixed `now_ns`, but after a Phase-2 send drains the queue bucket, the next selector pass reaches the Phase-1 queue-token park before Phase 2’s non-parking skip.

Evidence:
- `userspace-dp/src/afxdp/tx/drain/phase_shaped.rs:44-47`: `while should_enter_shaped_drain(binding)` reuses `ctx.now_ns`.
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:853-873`: Phase 1 parks on `queue.hot.tokens < head_len`.
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:973-978`: Phase 2 skips without parking only after reaching Phase 2.
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:984-999`: Phase 2 returns a full `candidate_budget` when tokens exist.

MAJOR-2: F-W1’s oversubscription gate is underspecified against the actual helper surface.  
The proposed source of truth is currently private to `tx_completion.rs`, uses a nonempty demand mask, and differs from waterfill’s static configured-queue budget. The plan must say whether the selector gate is static configured-rate, local nonempty, local+peer demand, runnable/serviceable, and whether it is frozen at Phase-1 refill.

Evidence:
- `userspace-dp/src/afxdp/cos/tx_completion.rs:383-389`: demand mask includes exact+guarantee+nonempty.
- `userspace-dp/src/afxdp/cos/tx_completion.rs:400`: `fn exact_backlog_guarantee_rate_bytes_for_mask` is private.
- `userspace-dp/src/afxdp/cos/tx_completion.rs:652-654`: local mask is OR’d with peer demand before rate summing.
- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:789-798`: waterfill’s current budget does not use that demand mask.

MINOR-1: Priority-low is not a real hot-path interaction in this tree.  
F-W1 cannot currently preserve or break `priority_low_min_share_bytes` semantics because the runtime fields are explicitly unused.

Evidence:
- `userspace-dp/src/afxdp/types/cos.rs:386-392`: `priority_low_min_share_bytes` doc says no hot-path code consults it.
- `userspace-dp/src/afxdp/types/cos.rs:393-401`: reserved helper fields are “Currently UNUSED.”

VERDICT: PLAN-NEEDS-MAJOR
