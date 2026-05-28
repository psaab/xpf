# Adversarial Review: #1625 per-queue epoch-cap (Step-2 of #1614 Axis A)

**Reviewer Profile:** CoS scheduling theory expert, Junos guarantee-rate semantics, token-bucket math, AF_XDP TX-path, race-free epoch rotation, bpfrx per-binding owner-only single-writer discipline.
**Target Branch Diff:** `origin/master...HEAD` (branch: `perf/1625-per-queue-epoch-cap`)
**Verdict:** **PLAN-NEEDS-MAJOR**

---

## Executive Summary

While the intent of introducing a per-queue per-epoch byte allowance is correct for solving the equal-distribution defect of the step-1 scaffold (PR #1618), a deep architectural audit of the current waterfill selector (`userspace-dp/src/afxdp/cos/queue_service/mod.rs`) and the proposed plan v1 (`plan.md`) reveals **two severe, fatal logical flaws in the existing codebase and the planned mechanism**, alongside multiple race conditions, mathematical redundancies, and hot-path design smells. 

We **cannot** recommend proceeding to implementation without a **PLAN-NEEDS-MAJOR** revision. This review details these findings with worked mathematical counter-examples, code-line evidence, and mitigation steps.

---

## 1. §2 Diagnosis Correctness & Worked Counter-Examples

The plan §2 diagnosis claims that Phase 2 visits have no per-queue per-time bounds, and that under saturated load, equal sharing occurs because the worker's round-robin cadence is too fast (~200 µs). This is mathematically true but overlooks a much more severe, **already existing structural defect in the step-1 scaffold** that permanently disables Phase 1.

### Finding 1.1: Saturated SMR Refill Defect — Permanent Phase 2 Lock-In (Fatal Scaffold Bug)
In the current implementation of `select_exact_cos_guarantee_queue_waterfill` ([mod.rs:787-801](file:///home/ps/git/bpfrx/.claude/worktrees/1625-per-queue-epoch-cap/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L787-L801)), `waterfill_pass1_remaining_bytes` is refilled lazily only when it is **exactly equal to zero**:
```rust
787:     if root.waterfill_pass1_remaining_bytes == 0 {
...
799:         root.waterfill_pass1_remaining_bytes = pass1;
800:         root.waterfill_phase2_cursor = 0;
801:     }
```
However, in Phase 1 selection, `waterfill_pass1_remaining_bytes` is decremented by `candidate_budget` ([mod.rs:896-898](file:///home/ps/git/bpfrx/.claude/worktrees/1625-per-queue-epoch-cap/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L896-L898)). When the budget falls below the `candidate_budget` of the next queue in the ascending walk, the loop breaks ([mod.rs:889-893](file:///home/ps/git/bpfrx/.claude/worktrees/1625-per-queue-epoch-cap/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L889-L893)):
```rust
889:         if candidate_budget > root.waterfill_pass1_remaining_bytes {
890:             // Budget exhausted... Fall through to Phase 2
891:             break;
892:         }
```
**The Worked Counter-Example:**
1. Let the system have two queues: $Q_0$ (100 Mbps, quantum 1500 B) and $Q_1$ (6 Gbps, quantum 512 KB). Let `guarantee_fraction = 0.5`.
2. At initialization, `waterfill_pass1_remaining_bytes = 0`. Refill sets it to `(1500 + 524288) * 0.5 = 262,894` B.
3. $Q_0$ is serviced. `candidate_budget = 1500` B. It is selected and `waterfill_pass1_remaining_bytes` is decremented to `261,394` B.
4. On subsequent calls, $Q_0$ (or other queues) keep draining the budget. Eventually, `waterfill_pass1_remaining_bytes` drops to `1,000` B.
5. In the next call, the refill block is skipped because `1000 != 0`. The Phase 1 loop starts.
6. For the very first queue $Q_0$, `candidate_budget` is at least `1500` B.
7. Since `1500 > 1000`, the loop breaks immediately at line 889.
8. The selector falls through to Phase 2. Phase 2 descending walk finds $Q_1$ or $Q_0$ runnable (since they are saturated), selects it, and returns `Some`.
9. On the next call, `waterfill_pass1_remaining_bytes` is **still 1,000 B**. The refill block is skipped again. Phase 1 breaks immediately again. Phase 2 returns `Some` again.
10. **Result:** The system is **permanently locked in Phase 2 best-effort round-robin**. The epoch never rotates because the only line that resets the budget to zero is at line 1004:
```rust
1002:     // Epoch exhausted: nothing serviced. Reset Phase 1 budget
1003:     // for next call (lazy refill above will recompute).
1004:     root.waterfill_pass1_remaining_bytes = 0;
```
Under saturated arrival, Phase 2 **never** returns `None` (there is always backlog). Thus, `waterfill_pass1_remaining_bytes` remains positive forever, Phase 1 is never executed again, and no rate guarantees are honored. The step-1 scaffold is completely broken.

> [!IMPORTANT]
> **Mitigation:** The timer-based epoch rotation proposed in §3 of Plan v1 is **mandatory** to force `waterfill_pass1_remaining_bytes = 0` at epoch boundaries. However, the plan must explicitly document that the step-1 scaffold was permanently locked in Phase 2 under saturated load, and explain how the timer-based reset is the specific architectural fix.

---

### Finding 1.2: Jumboframe Priority-Inversion Cascade (Major Starvation Vulnerability)
The Phase 1 loop breaks immediately if `candidate_budget > waterfill_pass1_remaining_bytes` ([mod.rs:889-893](file:///home/ps/git/bpfrx/.claude/worktrees/1625-per-queue-epoch-cap/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L889-L893)). 

`candidate_budget` is computed by taking the max of `head_len` ([mod.rs:879-883](file:///home/ps/git/bpfrx/.claude/worktrees/1625-per-queue-epoch-cap/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L879-L883)):
```rust
879:         let candidate_budget = queue
880:             .hot
881:             .tokens
882:             .min(cos_guarantee_quantum_bytes(queue))
883:             .max(head_len);
```

**The Worked Counter-Example:**
1. Suppose we have 3 queues in ascending order of rate: $Q_0$ (100 Mbps), $Q_1$ (1 Gbps), and $Q_2$ (3 Gbps).
2. `waterfill_pass1_remaining_bytes` currently has `5,000` B remaining in the epoch.
3. $Q_0$ (100 Mbps) receives a **jumboframe packet of 9,000 B** at its head.
4. $Q_1$ (1 Gbps) and $Q_2$ (3 Gbps) have standard **1500 B packets** at their heads.
5. The selector runs. $Q_0$ is checked first. `candidate_budget` for $Q_0$ is `max(1500, 9000) = 9000` B.
6. Since `9000 > 5000` (`candidate_budget > pass1_remaining`), the Phase 1 loop **breaks immediately**.
7. **Result:** $Q_1$ and $Q_2$ are **completely skipped** in Phase 1, even though their 1500 B packets would have fit perfectly in the remaining 5000 B budget!
8. The selector falls through to Phase 2 and selects the high-rate $Q_2$ queue first. $Q_1$ (1 Gbps) gets completely starved this epoch.
9. A single large packet at the head of a small-rate queue causes a **priority-inversion cascade**, starving subsequent small-rate queues and bypassing their guarantees.

> [!CAUTION]
> **Required Fix:** In the Phase 1 loop, if a queue's `candidate_budget` exceeds `waterfill_pass1_remaining_bytes`, the selector **must not `break`**. It should `continue` to examine subsequent ascending queues to see if they have smaller packets that can fit into the remaining epoch budget. Breaking early is a major logical bug.

---

## 2. §3 Mechanism Soundness & Allowance Floor Pitfalls

### Finding 2.1: The 1500 B Floor is Redundant and Dangerous
The plan §3 introduces `cos_per_queue_epoch_allowance_bytes` and floors the allowance at `COS_GUARANTEE_QUANTUM_MIN_BYTES = 1500` B:
```rust
    let allowance = ((queue.transmit_rate_bytes() as u128)
        * (COS_GUARANTEE_VISIT_NS as u128) / 1_000_000_000u128) as u64;
    allowance.max(COS_GUARANTEE_QUANTUM_MIN_BYTES)
```
The plan claims this floor is needed for "liveness" of low-rate queues (e.g. 5 Mbps). **This is mathematically and structurally incorrect.**

1. **Token Bucket enforces the true rate:** If a 5 Mbps queue is active under saturated load, it accumulates tokens at `5 Mbps × 200 µs = 125` bytes per epoch.
2. In order to transmit a 1500 B packet, the queue must have at least 1500 tokens (`queue.hot.tokens >= head_len`, line 853).
3. The queue must wait `1500 / 125 = 12` epochs (2.4 ms) to accumulate enough tokens to transmit a single packet.
4. When it finally has 1500 tokens, it transmits 1 packet. Its rate is exactly `1500 B / 2.4 ms = 5 Mbps`. The token bucket naturally enforces the correct rate!
5. **The danger of the floor:** If we floor the epoch allowance at 1500 B, then during a burst (when the queue has accumulated 1 MB of tokens while idle), the queue is allowed to transmit up to 1500 B **every single epoch**.
6. This lets the 5 Mbps queue drain its burst at `1500 B / 200 µs = 60 Mbps`! This is **11.7× its configured rate**.
7. If the queue has 64-byte small packets and the allowance is not floored (125 B), it can send 1 packet of 64 B, then another 64 B (total 128 B >= 125 B), capping it properly at ~5 Mbps. If we floor it at 1500 B, it can send 23 small packets (1472 B) per epoch, completely blowing past its rate!

> [!WARNING]
> **Required Fix:** Remove the `max(COS_GUARANTEE_QUANTUM_MIN_BYTES)` floor from `cos_per_queue_epoch_allowance_bytes`. Let the allowance compute to its true mathematical value. Standard token-bucket limits will naturally bound low-rate queues over multiple epochs, and removing the floor protects the system from burst-over-allocation and queue-skew under small packet sizes.

---

## 3. §4 Per-Binding-Only Caps & Multi-RSS Reality

### Finding 3.1: Configured Rates Starve Pinned Classes Under Skew
The plan §4 states that if a class is spread across $N$ bindings, the effective cap is $N \times$ rate. This is acceptable for the synthetic smoke harness where flows are pinned, but is a **major regression hazard in production**.

Suppose a 3 Gbps class (Class A) is spread across 4 bindings, and a 1 Gbps class (Class B) is pinned to Binding 0.
- Binding 0 sees Class A (offered 3 Gbps) and Class B (offered 1 Gbps).
- Class A's cap on Binding 0 is configured as 3 Gbps. Class B's cap is 1 Gbps.
- The total capacity of Binding 0 is e.g. 2 Gbps.
- Since Class A's cap is 3 Gbps (greater than the binding's total capacity), the cap for Class A **never binds** on Binding 0!
- Class A can consume almost all of Binding 0's capacity, potentially starving Class B, which gets capped at 1 Gbps.
- Across the whole firewall, Class A's effective cap is $4 \times 3\text{ Gbps} = 12\text{ Gbps}$.

> [!IMPORTANT]
> **Operator Documentation Requirement:** We must explicitly update `docs/fairness-regimes.md` to state that `guarantee-rate` enforces caps **per-queue per-binding**. If a class's flows are distributed across multiple RSS bindings, the effective cap multiplies by the active binding count. We should also recommend that operators use `shared_exact` if they need strict global enforcement.

---

## 4. Epoch Rotation Race Conditions

### Finding 4.1: NTP / Virtualization Clock Jump Freeze
The plan's epoch rotation logic is timer-based:
```rust
let elapsed = now_ns.saturating_sub(root.guarantee_epoch_start_ns);
if elapsed >= COS_GUARANTEE_VISIT_NS { ... }
```
If the system clock jumps backwards (e.g. due to NTP corrections, VM migrations, or hypervisor virtualization suspends), `now_ns` can be smaller than `guarantee_epoch_start_ns`. 
1. `now_ns.saturating_sub` will return `0`.
2. `elapsed` will remain `0` until `now_ns` catches up to the previously recorded start time.
3. **Result:** Epoch rotation is **completely frozen** for the duration of the drift. Any queue that has hit its epoch cap will be **permanently starved** during this freeze!

> [!WARNING]
> **Required Fix:** Guard against backwards clock jumps by checking if `now_ns < root.guarantee_epoch_start_ns`. If a backward jump is detected, force an immediate epoch rotation by setting `root.guarantee_epoch_start_ns = now_ns` and resetting the epoch bytes.
> ```rust
> if now_ns < root.guarantee_epoch_start_ns {
>     // Force immediate rotation on backward clock jump
>     root.guarantee_epoch_start_ns = now_ns;
>     for queue in &mut root.queues {
>         queue.hot.epoch_bytes_serviced = 0;
>     }
> }
> ```

---

### Finding 4.2: Jitter-Induced Phase Drift & Rate Degradation
If the worker thread experiences scheduling jitter (e.g. long syscall, page fault, or descheduling on a non-RT kernel), `elapsed` can exceed `COS_GUARANTEE_VISIT_NS` by a large margin (e.g. 210 µs instead of 200 µs).

If the rotation logic sets `root.guarantee_epoch_start_ns = now_ns`, it aligns the next epoch to the arbitrary time of the worker's resumption.
- If the average call interval is 210 µs due to CPU load, the queue is allowed to send its 200 µs allowance every 210 µs.
- This leads to a systematic **5% throughput degradation** (e.g. a 10 Gbps class is capped at 9.52 Gbps).
- Standard scheduler theory dictates that the epoch start must be advanced by the configured interval to maintain long-term alignment:
  `root.guarantee_epoch_start_ns += COS_GUARANTEE_VISIT_NS;`
  Or, if multiple epochs were skipped:
  `root.guarantee_epoch_start_ns += (elapsed / COS_GUARANTEE_VISIT_NS) * COS_GUARANTEE_VISIT_NS;`

> [!TIP]
> **Required Fix:** Advance `guarantee_epoch_start_ns` by multiples of `COS_GUARANTEE_VISIT_NS` rather than aligning to `now_ns`, to prevent systematic rate degradation under scheduling jitter.

---

## 5. Floating-Point Hot-Path Smell

### Finding 5.1: Floating-Point Saturating Cast Vulnerability
Line 798 of `mod.rs` uses floating-point multiplication and cast:
```rust
797:         let frac = root.oversubscription_guarantee_fraction;
798:         let pass1 = ((quantum_sum as f64) * frac).floor() as u64;
```
If `frac` is negative, `NaN`, or `Infinity` (due to a buggy config compiler or memory corruption):
- **NaN or Negative:** `pass1` evaluates to `0`. `waterfill_pass1_remaining_bytes` is set to `0`. On the next call, the refill condition `waterfill_pass1_remaining_bytes == 0` is true again, leading to an **infinite loop of float multiplication and sum loops** on the packet-processing hot path!
- **Infinity:** `pass1` evaluates to `u64::MAX`. The Phase 1 budget never runs out, permanently disabling Phase 2.

> [!CAUTION]
> **Required Fix:** Eliminate all floats from the per-packet hot path. Represent `oversubscription_guarantee_fraction` as a fixed-point integer (e.g., scaled by `65536` or `10000`). Replace the float math with a safe integer multiply-and-shift:
> `let pass1 = (quantum_sum * fraction_scaled) >> 16;`
> This avoids FPU pipeline stalls, provides deterministic results, and eliminates NaN/Infinity/negative saturating cast vulnerabilities entirely.

---

## 6. Checklist & Plan-Kill Conditions

### Finding 6.1: Double-Service Index Flaw for High Queue Indexes
In Phase 1 selection, `honored_mask` tracks honored queues using a bitmask of size 64 ([mod.rs:899-901](file:///home/ps/git/bpfrx/.claude/worktrees/1625-per-queue-epoch-cap/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L899-L901)):
```rust
899:         if queue_idx < 64 {
900:             honored_mask |= 1u64 << queue_idx;
901:         }
```
In Phase 2, the bitmask check is skipped if `queue_idx >= 64` ([mod.rs:938](file:///home/ps/git/bpfrx/.claude/worktrees/1625-per-queue-epoch-cap/userspace-dp/src/afxdp/cos/queue_service/mod.rs#L938)):
```rust
938:         if queue_idx < 64 && (honored_mask & (1u64 << queue_idx)) != 0 {
```
**Result:** Any queue with `queue_idx >= 64` that is successfully honored in Phase 1 is **not marked** in `honored_mask` and will be **visited and serviced again in Phase 2**. This is a structural scale defect that causes unfair double-service for high-index queues.

> [!IMPORTANT]
> **Required Fix:** Assert or statically enforce that the maximum number of exact queues is `< 64` at config-compile time, or expand `honored_mask` to a boolean array to ensure high-index queues are not double-serviced.

---

## Bottom Line & Verdict

### **Verdict:** **PLAN-NEEDS-MAJOR**

The current Plan v1 is **not ready** because it inherits severe structural defects from the step-1 scaffold (the permanent Phase 2 lock-in) and introduces new ones (jumboframe priority inversion, redundancy/danger of the MTU floor, clock-jump freeze, and float saturating cast hazards). 

We will transition the plan to **PLAN-READY** once the four critical fixes are adopted in the v2 plan:
1. **Fix the Phase 1 Loop Break:** Change the loop break on budget exhaustion to a `continue` to prevent jumboframe priority-inversion starvation.
2. **Remove the 1500 B Floor:** Delete the floor in `cos_per_queue_epoch_allowance_bytes` and let the token bucket handle low-rate limits.
3. **Secure Clock Rotation:** Force rotation on backwards clock jumps and advance the epoch start incrementally by `COS_GUARANTEE_VISIT_NS` to prevent jitter rate drift.
4. **Eliminate Hot-Path Floats:** Replace the float math in the Phase 1 budget refill with fixed-point integer scaling.
