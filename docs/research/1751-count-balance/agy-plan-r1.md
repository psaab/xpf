# AGY adversarial plan review — #1751 count-balance, round 1

Job: adversarial-review-mpxeval5-4q2iwn (succeeded). Verbatim verdict + findings.

## Verdict: PLAN-READY

**1. #1203 Contradiction (§4) — VERIFIED TRUE.** Per-flow MQFQ runs on ALL shaped
queues incl shared_exact (#1735): `cos/README.md:50-54`; `flow_fair = queue.exact`
for both shared_exact and owner-local-exact (`cos/admission.rs:413-415, 458-460`);
exact queues promote eagerly at build so `flow_fair_state.is_some()` ⇒
`flow_fair()` true ⇒ pop path bypasses the cheap FIFO branch and dispatches MQFQ
(`cos/queue_ops/pop.rs:59-70`). Scheduler no longer single-FIFO. NOT a PLAN-KILL.

**2. Count-vs-Rows Skew & Truncation (§2.2, §2.3) — SOUND (WITH LIMITATIONS).**
Active count and rows filter on the same `active_entry_age` in one scan
(`flow_cache.rs:478-481`); dwell+cooldown absorb low-PPS jitter. Truncation defer
guard (§6.2) structurally sufficient. INSIDIOUS RISK: a worker with 100 ICMP
(non-steerable) + 0 TCP reports steerable-count 0 → seen as unloaded → steered to
→ overloaded (`coordinator/rebalance.rs:289-293` drops non-TCP/UDP). Mitigation:
documented limitation (§3.6); cannot steer ICMP anyway, so excluding it from the
candidate path is correct.

**3. Convergence / Anti-Thrash (§3.4) — MATHEMATICALLY SOUND.** Overshoot guard
`c_hi - c_lo ≥ 2` ⇒ post-move `c_hi-1 ≥ c_lo+1` ⇒ strictly decreases L1 distance
to balanced; L1 is a non-negative integer ⇒ terminates in ≤N moves. Cooldown +
DWELL_TICKS_REQUIRED=2 prevent closed ping-pong. [Reviewer note: AGY's proof uses
the L1 potential — the CORRECT one — while the plan TEXT states max-min, which
Codex+SMR show is the wrong potential. The algorithm terminates; the plan text
must be corrected to L1/sum-of-squares.]

**4. Homogeneous / Heterogeneous (§3.6) — DEFENSIBLE.** -P12 equal-rate ⇒ count
is a perfect load proxy. No reliable per-flow rate feed until #1750; gating on
heterogeneous balancing would stall indefinitely. Limitation documented;
rate-aware tiebreak correctly deferred to #1750.

**5. Validation Gate CoS-ON vs CoS-OFF — MATERIAL RISK IDENTIFIED.** shared_exact
workers sync queue_vtime via the `vtime_floor: Arc<...>` floor
(`admission.rs:490`); timing skew / contention there could diverge per-worker
service rates even with balanced counts. Real risk, but the plan handles it: live
A/B gate in BOTH CoS modes is the acceptance criterion (§10) + within-queue
follow-up (§11) if CoS-ON fails while CoS-OFF passes.

No blocker or structural defect remains. Proceed to the pre-code live trace (§10).
