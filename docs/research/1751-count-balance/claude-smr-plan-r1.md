# Claude-SMR hostile plan review — #1751 count-balance, round 1

Reviewing as domain SMR (AF_XDP dataplane + CoS scheduler), CPU-arch/design, and
SW-design-patterns. HOSTILE by mandate (`feedback_triple_review_includes_claude_smr`):
I am NOT a synthesizer. I independently verified each claim against master + the
engineer/1748 branch source rather than trusting the plan's self-report.

## Verdict: PLAN-NEEDS-MINOR

The architecture is sound and the central #1203 KILL-risk resolves NOT-A-KILL on
verified master source. But the plan ships ONE genuinely wrong artifact (the
convergence proof, §3.4) and TWO over-claims (count-vs-rows §2.2; the steerable-
count semantics) that must be corrected before PLAN-READY. None are structural;
all are tightenings. I converge with Codex's PLAN-NEEDS-MAJOR on substance (same
findings) but rate it MINOR because the move-machinery reuse means the surface is
small and every finding has a one-paragraph fix.

## Finding 1 — Convergence proof §3.4 is WRONG as written (MUST FIX). Severity: MAJOR-on-the-doc, trivial-fix.

The plan §3.4 uses `Φ = max_w counts[w] - min_w counts[w]` and claims
termination "in `≤ Φ₀` admitted moves." I constructed and hand-traced a
counterexample (independently, matching Codex's): `[3,3,3,3,1,1,1,1]`, `K=2`,
`Φ₀ = 2`. Trace of admitted moves (each picks hi=3→lo=1, delta=2 passes the
overshoot guard `delta≥2`):
- `[3,3,3,3,1,1,1,1]` → `[2,3,3,3,2,1,1,1]` (Φ=2)
- → `[2,2,3,3,2,2,1,1]` (Φ=2)
- → `[2,2,2,3,2,2,2,1]` (Φ=2)
- → `[2,2,2,2,2,2,2,2]` (Φ=0)

**4 admitted moves, Φ stayed at 2 the entire time until the last move.** So
`Φ = max - min` is NOT a strictly-decreasing potential and "`≤ Φ₀` moves" is
**false** (it took 4 ≫ Φ₀=2). The claim "global Φ strictly decreases whenever the
(hi,lo) pair was the unique extremal pair" is also wrong — above, the (hi,lo)
*values* (3,1) are the extremal values throughout, but moving one such pair does
not reduce max or min while other workers still sit at 3 and 1.

**The algorithm still terminates** — but the correct potential is the **L1
distance to the balanced target** `Ψ = Σ_w |counts[w] - mean|` (or sum-of-squares
`Σ (counts[w]-mean)²`). Each admitted move (delta≥2 ⇒ `c_hi-1 ≥ c_lo+1`) strictly
decreases Ψ by ≥ 2 (the source moves one step toward mean, the dest one step
toward mean, neither overshoots), Ψ is a non-negative integer bounded by ~`2N`,
so termination is in ≤ `Ψ₀/2 ≤ N` admitted moves at the even partition (±1).
**Fix:** replace the §3.4 potential with Ψ (L1-to-target) or sum-of-squares; drop
the false "≤Φ₀" bound; keep the integer-monotone-termination + cooldown-no-thrash
conclusion (which IS correct under the right potential). Note AGY's r1 "proof"
actually used the L1 argument — so AGY validated the *correct* potential while
calling the plan-text sound; the plan TEXT is what is wrong.

## Finding 2 — §2.2 over-claims the #1750 decoupling; count MUST be POST-FILTER steerable rows (MUST FIX). Severity: MINOR.

I verified `flow_worker_map()` (`coordinator/status.rs:168`) aggregates
per-binding ArcSwap loads, and the controller post-filters rows to TCP/UDP +
valid-ifindex before building `FlowSample` (`coordinator/rebalance.rs:286-293`,
`session_key_from_tuple` parse `:283`). Two corrections:

- **Count the POST-FILTER `flows`, not raw rows.** §3.1 already says "per-worker
  count = number of `flows` whose `worker_id == w`", which is correct — but §2.2
  option 1 and §6.2's truncation guard talk about "counting rows per worker_id",
  which reads ambiguously as raw rows. Make it unambiguous everywhere: the count
  is over the **steerable `FlowSample` set** the candidate is also drawn from.
  This is the ONLY count that guarantees "source worker has a movable flow"
  (avoids the `NoEligibleFlow` that blocked #1748). Counting raw rows would let a
  worker with N ICMP rows look loaded while having 0 steerable candidates.
- **The decoupling is real but the staleness guard is NOT.** §2.2 correctly
  notes count==rows atomicity is free from the same returned `Vec`. But the plan
  must STOP implying it gets #1750's freshness/staleness guard for free — it does
  not (no `published_ns` without #1750). State plainly: Path A gets count-vs-rows
  self-consistency (sufficient for the decision) but NOT a snapshot-age defer;
  if publish-cadence lag proves a live problem, adopt #1750 Path 1 (the bundle).
  This is honest and keeps the #1750 dependency "soft, recommended" rather than
  silently assuming a guard it lacks.

## Finding 3 — the unsteerable-count divergence is a forever-hottest-but-no-candidate hazard (CONFIRM HANDLED). Severity: MINOR.

Because the count is over steerable flows (Finding 2), a worker with only
non-steerable traffic (ICMP, unsteered ports) has steerable-count 0 → it is
never the `hi` source (good) and is a valid `lo` destination. But the inverse —
a worker that is genuinely the busiest by TOTAL load (ICMP + a little TCP) — can
be `hi` by steerable count yet have few movable flows; the move just picks one of
its TCP flows, which is correct. The real residual: a worker chosen as `lo`
(low steerable count) might actually be CPU-saturated by non-steerable traffic,
so steering a TCP flow there overloads it. The plan's §3.6 honesty covers the
homogeneous-iperf gate (no ICMP), but the operator doc MUST state: count-balance
balances STEERABLE-flow count, not total CPU load, so heavy non-steerable
background traffic can mislead destination choice. This matches the #1750-r2
livelock lesson (the defer there was for stale snapshots; here it is a documented
limitation, not a livelock, because steerable-count 0 can never be `hi`). No
livelock — confirm in the plan and in a unit test (`unsteerable_only_worker_is_never_source`).

## Finding 4 — the #1203 resolution is CORRECT on master; phrase #1735 precisely (NIT). Severity: NIT.

I independently verified the load-bearing claim. On master:
- `CoSQueueRuntime::flow_fair()` returns `flow_fair_state.is_some()`
  (`cos/types/cos.rs:612-613`) — runtime state gate, not the old config gate.
- The historical `!shared_exact` exclusion is GONE: policy is `flow_fair =
  queue.exact` for both shared_exact and owner-local exact
  (`cos/admission.rs:458-460`); exact queues promote EAGERLY and allocate
  `FlowFairState` at build (`cos/admission.rs:525-526` per Codex; README:52-54).
- The pop path dispatches MQFQ when `flow_fair()` (`cos/queue_ops/pop.rs:59-70`):
  the cheap FIFO branch is `!flow_fair()` only.
So `shared_exact` queues run per-flow MQFQ at runtime on master — the exact
single-FIFO floor #1203's close comment blamed is gone. The plan's §4.3 is
correct. NIT: phrase it precisely as Codex says — "exact/shared_exact promote
EAGERLY at build (always MQFQ); non-exact shaped queues are lazily eligible." The
plan currently lumps them; tighten the wording. NOT a kill — confirmed.

## Finding 5 — ENDORSE Codex's pre-code CoS-ON manual re-pin gate (ADD). Severity: design-improvement.

This is the best finding of the round and I fully endorse it. R1 proved the
count→CoV link CoS-OFF; the live gate is CoS-ON shared_exact (5210→iperf-24g,
`cos-iperf-config.set` term 10). The single biggest un-de-risked assumption is
"post-#1735 shared_exact MQFQ + count-balanced placement reaches R1-class CoV."
That can be measured BEFORE writing any selector code by repeating R1's manual
ethtool round-robin re-pin with CoS loaded (`apply-cos-config.sh`) at `-P12
-p5210`. Outcomes:
- manual CoS-ON re-pin → ~3-4% CoV ⇒ the whole plan is de-risked; implement.
- manual CoS-ON re-pin → ~50% ⇒ the #1203 within-queue floor recurs on the
  #1735 scheduler; do NOT write selector code expecting it to fix shared_exact;
  ship CoS-OFF scope only + file the within-queue follow-up (§11). This converts
  the plan's MED-risk row 2 into a cheap pre-code decision instead of a
  post-implementation surprise. **Add this as the FIRST item in §10.**

## Cross-check against the #1748 machinery reuse (independent)
I confirmed `tick()` (`controller.rs:257-424`) structure — dwell, dwell-ticks,
interval gate, budget gate, second-move unwind, forward barrier
(promote→demote→install), reverse-barrier rollback/teardown — is orthogonal to
`select_move`'s decision. Swapping `select_move` + `is_over_threshold` →
`is_count_imbalanced` leaves the barriered ownership transfer, ntuple ioctl,
RebalancedOut/Owner suppression, and teardown reverse-barrier UNTOUCHED, so
#1748's 9 correctness rounds carry forward. The plan's §7 claim is accurate. One
watch: `MoveCandidate.new_queue` must still come from `workers[lo].queue_id`
(the ntuple ring_cookie) — the plan §3.2 has this right.

## Summary of required changes for PLAN-READY
1. §3.4: replace `Φ=max-min` with L1-to-target (or sum-of-squares) potential;
   drop the false "≤Φ₀ moves" bound; keep termination + no-thrash. (Finding 1)
2. §2.2/§3.1/§6.2: make the count unambiguously over POST-FILTER steerable
   `FlowSample`s; stop implying a #1750 staleness guard Path A doesn't have.
   (Finding 2)
3. §3.6/operator-doc + a unit test: document count-balances-steerable-not-CPU;
   `unsteerable_only_worker_is_never_source` test. (Finding 3)
4. §4.3: phrase #1735 precisely (eager exact/shared_exact vs lazy non-exact).
   (Finding 4)
5. §10: add the pre-code CoS-ON manual re-pin gate as item 1. (Finding 5)

With these the plan is PLAN-READY. The design (count-balance reusing the #1748
move machinery, #1750-decoupled, #1203-floor-fixed-on-master) is correct.
