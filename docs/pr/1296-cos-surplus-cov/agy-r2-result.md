# AGY Adversarial Review (Round 2)
**Target:** docs/pr/1296-cos-surplus-cov/plan-v2.md (commit `385934e6b`, branch `perf/1296-cos-surplus-cov`)  
**Verdict:** `PLAN-NEEDS-MAJOR`

While Plan v2 is highly elegant and makes a valiant attempt to reconcile equal-flow fairness with work-conserving surplus sharing, **a rigorous mathematical and behavioral trace reveals fatal structural flaws in the hybrid design.** The core value claims (achieving $\le 0.10$ CoV while retaining full throughput/work-conservation) are in direct conflict.

Below is the hostile pushback on your 8 review areas, backed by concrete evidence and worked traces.

---

### 1. Stability of `target_per_flow` Under Surplus Draw
**Objection:** The feedback loop between surplus draw and `target_per_flow` calculation diverges, destroying work-conservation.

Under hybrid, `prev_grants[i]` includes the surplus drawn by a worker. When Worker A (consumer) draws surplus, its per-flow sample `per_flow_A = prev_grants[A] / active_flows[A]` inflates. Meanwhile, Worker B (donor with low demand) consumes less than its share, so `per_flow_B = prev_grants[B] / active_flows[B]` remains low.

`publish_equal_flow_epoch_v8.rs:105` computes:
```rust
105:         candidate_target = candidate_target.min(per_flow);
```
In any epoch where surplus is drawn:
1. `candidate_target` is set by the **donor's** lower rate (e.g., 15), not the consumer's inflated rate (e.g., 22.5).
2. The published `smoothed_target_per_flow` converges to the **donor's low rate**.
3. In the next epoch, the consumer is capped at `target_per_flow * active_flows_consumer` (e.g., $15 \times 4 = 60$).
4. Because the consumer is capped at 60 (which is strictly less than its primary fair share of 80), its primary path is throttled, and it is **completely blocked** from drawing surplus in the surplus loop because:
   ```rust
   let my_room = my_effective_share.saturating_sub(my_consumed); // 60 - 60 = 0
   ```
5. Consequently, **the consumer cannot draw surplus, aggregate throughput drops, and the system fails to be work-conserving, degenerating to a strict-exact regime.** The unused primary share of the donor is wasted.

---

### 2. CAS Contention on `v8.epoch.packed_granted`
**Objection:** Legitimate primary path requests will be starved out or suffer tail-latency spikes due to surplus loop spinning.

In `acquire_v8` (`mod.rs:1192-1236`), a high-demand consumer that has exhausted primary share will spin aggressively in the surplus loop, performing high-frequency compare-and-swap (CAS) operations on the same atomic `v8.epoch.packed_granted`:
```rust
1210:                 if v8
1211:                     .epoch
1212:                     .packed_granted
1213:                     .0
1214:                     .compare_exchange_weak( ... )
```
When a donor thread receives a new burst of packets and attempts to make a primary grant request, it must write to the exact same cache line via:
```rust
1104:             if v8
1105:                 .epoch
1106:                 .packed_granted
1107:                 .0
1108:                 .compare_exchange_weak( ... )
```
Because the surplus consumer spins aggressively across multiple cores without backoff, it will keep invalidating the cache line of `packed_granted` for the donor's core. In a high-throughput multi-core environment, **legitimate primary requests are highly susceptible to CAS-level starvation**, causing massive tail-latency spikes on the donor's critical fast path.

---

### 3. Donor Starvation Risk Under Asymmetric Demand
**Objection:** The hybrid mode degenerates to strict-exact and fails to preserve the structural ceiling under asymmetric demand.

Let’s trace the asymmetric-demand case:
* Total Class Cap = `120`
* **Worker A (Consumer):** 4 active flows, unlimited demand. Primary share $T_A = 120 \times \frac{4}{6} = 80$.
* **Worker B (Donor):** 2 active flows, demand-bound at $15$ per flow (total demand $30$). Primary share $T_B = 120 \times \frac{2}{6} = 40$.
* **Epoch 1:**
  * Worker B consumes $30$ (leaving $10$ units unused).
  * Worker A consumes its primary share $80$ and draws $10$ units of surplus $\rightarrow$ total granted = $90$.
* **Epoch 2 Rotation:**
  * `per_flow_A = 90 / 4 = 22.5`
  * `per_flow_B = 30 / 2 = 15`
  * `target_per_flow = min(22.5, 15) = 15`.
* **Epoch 2 Grants:**
  * Worker A's cap is $15 \times 4 = 60$. Since $60 < T_A$ (80), Worker A is throttled *below* its primary fair share.
  * Worker B gets $30$.
  * Total aggregate throughput drops to $60 + 30 = 90$ (down from 120!).
  * The $30$ units of unused capacity are completely stranded. No surplus is drawn because Worker A is capped at 60.

Without donor slack (which is consumed/eliminated by the cap math), **the hybrid mode actively suppresses active workers below their primary shares, destroying work-conservation.**

---

### 4. `V8RateMode` Variant Approach
**Assessment:** The 3rd enum variant (`EqualFlowWorkConserving`) is architecturally cleaner than adding a boolean flag like `surplus_open_when_enforced`.
* **Why:** Type-level distinction enforces explicit compilation paths.
* **Warning:** If you add the 3rd variant, you **must** update every single match site, including `v8_equal_flow_active` (`mod.rs:1335`), `rotate_epoch_v8.rs:123`, and `equal_flow_cap_v8` (`mod.rs:1459`). Failing to update `rotate_epoch_v8.rs` would cause the rotation thread to completely skip cap publication for the hybrid mode, leaving the lease permanently in an uninitialized or failed-open state.

---

### 5. Compiler Relaxation Rollback
**Assessment:** 
* `pkg/config/parser_class_of_service_test.go:308` contains `TestCompileClassOfServiceEqualFlowEnforcementRejectsSurplusSharing`, which explicitly asserts the combination is rejected. If you relax `pkg/config/compiler.go:432`, **this test will break immediately** and must be rewritten.
* **Config Safety:** A walk of `test/incus/cos-iperf-config.set` and other `.set`/`.conf` files confirms that no pre-existing configs combine `equal-flow-enforcement` and `surplus-sharing`. Thus, relaxing the compiler check is safe from an operational regression standpoint on existing clusters.

---

### 6. Acceptance Gate $\le 0.10$ CoV
**Objection:** The $\le 0.10$ CoV acceptance gate is mathematically and physically impossible under hybrid mode with donor slack.

Suppose a donor's demand is naturally lower than the cap (e.g., rate of 5 per flow due to application limits), while the consumer's flows are saturated at the cap (rate of 20 per flow):
* 4 flows at rate 20
* 2 flows at rate 5
* **Mean per-flow rate:** $(4 \times 20 + 2 \times 5) / 6 = 15$
* **Variance:** $[4 \times (20-15)^2 + 2 \times (5-15)^2] / 6 = [100 + 200] / 6 = 50$
* **Standard Deviation:** $\sqrt{50} \approx 7.07$
* **CoV:** $7.07 / 15 = 0.471$ ($47.1\%$)

Because the donor's flows naturally run at a lower rate, **their very existence guarantees a high raw per-flow CoV.** The only way to get CoV $\le 0.10$ is to force the consumer's flows down to the donor's low rate (strict-exact mode), which destroys work-conservation. The claim that hybrid can deliver both high aggregate throughput and low CoV is structurally false.

---

### 7. #1304 Phase 1 Alignment
**Assessment:** Plan v2 is **not** implementing #1304 Phase 1. 
#1304 Phase 1 is explicitly specified as a non-work-conserving strict-exact mechanism. By attempting to bolt on surplus sharing, Plan v2 introduces highly speculative, unstable feedback loops. **We should file a new sibling issue for the hybrid mode** rather than overloading #1304, to prevent corrupting the clean strict-exact delivery path.

---

### 8. #1211 Cross-Worker Coordination Check
**Assessment:** The data flow is **highly distinguishable** from the killed #1211 AFD ECN drop.
* In #1211, real-time packet drops required synchronous cross-core atomic operations on every packet transmission, creating massive hardware cache-line bouncing.
* In hybrid mode, cross-worker reads of `active_flows_by_worker` are performed **only once per epoch** (e.g., 10ms boundary) by the single thread that wins the rotation EVEN $\rightarrow$ ODD CAS. Acquirers read this pre-published cap in a read-only local fashion during the epoch. 
* This is a slow, decoupled control-plane loop, not a fast-path coordination, and is safe from a cache-contention perspective.

---

### Summary of Major Objections & Path Forward
Plan v2 cannot proceed to implementation as written. The core design suffers from a mathematical deadlock:
1. If the cap math reacts to donor demand, the consumer's cap is throttled, destroying work-conservation (Question 1 & 3).
2. If the consumer draws surplus to preserve work-conservation, the difference between the donor's low-rate flows and the consumer's high-rate flows causes CoV to skyrocket (Question 6).

**Recommendation:** Reject Plan v2 (`PLAN-NEEDS-MAJOR`). Pivot the implementation away from the speculative work-conserving hybrid, and focus purely on delivering the robust, non-work-conserving **Phase 1 strict-exact equal-flow suppression** as originally framed in #1304.
