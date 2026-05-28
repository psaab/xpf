# AGY plan-review r2 — #1625 per-queue epoch-cap

Job: adversarial-review-mpplbz0k-zo4swh.

**Verdict: PLAN-KILL**

## Executive Summary

After verifying the codebase and analyzing the findings from the Codex plan-review (task-mppkt4ad-g3gtz0), the AGY plan-review (adversarial-review-mppk1nwa-s66mo9), and the Claude SMR round-2 verdict revision, the verdict for Plan v1 is a definitive **PLAN-KILL**.

The proposed selector-level per-queue epoch cap in Plan v1 is **structurally redundant**, introduces **layering violations** that lead to **double-throttling** in production, and **completely fails** to address the actual root causes of the ~20%/class equalization observed in the PR #1618 smoke matrix.

## 1. Verification of the v8 Redundancy Claim

The claim that the v8 shared lease already implements the exact mechanism proposed in Plan v1 is **100% correct**.

### Evidence 1.1: Automatic v8 Lease Allocation for Exact Queues
`userspace-dp/src/afxdp/coordinator/mod.rs:1092-1095, 1120-1126` automatically allocates a `SharedCoSQueueLease` in v8 mode for every exact queue with non-zero configured transmit rate.

### Evidence 1.2: The Identical Cap Formula
`userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:215-225` computes `new_cap_raw = rate × elapsed_ns / 1e9` — the exact same formula Plan v1 proposes. `EPOCH_DURATION_NS = 200_000` matches the 200 µs epoch Plan v1 calls out.

### Evidence 1.3: Total Grant Capping at the Lease Layer
`shared_cos_lease/mod.rs:1089-1092` strictly blocks grants once `class_granted >= cap`.

### How this renders Plan v1 redundant
`token_bucket.rs:101/191` refills `queue.hot.tokens` from the v8 lease. If a class has hit its lease cap, the lease returns 0. `hot.tokens` drops below `head_len`, the selector's existing token check at `mod.rs:853` skips the queue naturally. Adding another cap inside the selector is redundant, violates abstraction boundaries, and risks double-throttling.

## 2. Root Cause of the PR #1618 Smoke Matrix Equalization

If the v8 lease already caps rates, why did the step-1 smoke show a uniform ~20% distribution? Four major unaddressed root causes:

### Cause 2.1: The `worker_fair_share` Math (Dispositive)
`rotate_epoch_v8.rs:230-235`:
```rust
let my_share = ((new_cap as u128) * (my_count as u128) / (total_flows as u128)) as u64;
```
The lease divides the per-class capacity to workers proportionally to **active flow counts**, not configured rates. Under uniform 12-flow-per-class fixture, each worker gets `cap × 12/132 = cap/11` regardless of class rate → uniform equalization.

### Cause 2.2: Permanent Phase-2 Lock-in (Scaffold Bug)
`queue_service/mod.rs:787-801` refills `waterfill_pass1_remaining_bytes` only when `== 0`. Loop breaks with positive remainder at line 889-893 under saturation. Phase 2 returns work continuously → reset path at lines 1002-1005 never reached. Selector permanently in Phase-2 best-effort RR.

### Cause 2.3: Bypass-Grace Surplus Fires Under Saturation
`rotate_epoch_v8.rs:182-205` arms bypass when `aggregate_underuse && any_peer_cpu_bound_under_util`. Under multi-class saturation with worker CPU skew, this can fire → caps bypassed → equalized.

### Cause 2.4: The Smoke Fixture Doesn't Enable `guarantee-rate`
`test/incus/cos-iperf-config.set:69-70` only sets `scheduler-map bandwidth-limit` + `shaping-rate 25g`. No `oversubscription-policy guarantee-rate`. The smoke runs in proportional default mode → bypasses the new waterfill code path entirely.

## 3. Final Verdict: PLAN-KILL

1. **Zero Efficacy**: The selector-level cap is structurally redundant with the existing v8 shared lease.
2. **Defect Preservation**: The plan fails to address the actual root causes.
3. **Double Throttling Risk**: Implementing as proposed would lead to double-throttling.

## Recommended Next Steps

1. **Option A (Investigation)**: Label issue `plan-kill`, file a new issue to instrument the selector and lease paths to diagnose `worker_fair_share` skew empirically.
2. **Option D (Surgical Fixes)**: Lightweight bug-fix PR for the Phase-2 lock-in and the jumboframe `break` bug in the existing scaffold.
