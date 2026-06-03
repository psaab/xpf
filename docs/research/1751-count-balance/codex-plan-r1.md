# Codex hostile plan review — #1751 count-balance, round 1

Session: CODEX_COMPANION_SESSION_ID=research-1751-r1-* (codex-cli 0.135.0,
sandbox read-only, -C worktree). Verbatim verdict + findings below.

## Verdict: PLAN-NEEDS-MAJOR

**1. #1203 Contradiction** — Not PLAN-KILL. The plan's central claim survives:
current master does not have the old `exact && !shared_exact` FIFO gate for
`shared_exact`. Evidence: #1203 sticky CoV 55.2% mean with "residual variance is
per-queue TCP fairness once the controller has flattened the per-queue count"
(`docs/issues/pr-history.md:19281-19283`); runtime gate is state-based
(`types/cos.rs:612-613` `flow_fair_state.is_some()`); old shared_exact exclusion
gone (`cos/admission.rs:458-460` `flow_fair = queue.exact` for both); exact
queues allocate MQFQ eagerly (`cos/admission.rs:525-526`); FIFO exact drain path
says shared_exact unreachable there (`cos/queue_service/drain.rs:46-51`); live
gate is shared_exact (`cos-iperf-config.set:51-52, 133-136`). No kill. But
phrase #1735 precisely: non-exact shaped queues eligible/lazy; exact/shared_exact
eagerly MQFQ.

**2. Count/Rows Atomicity** — Decoupling from #1750 conditionally sound but the
plan overclaims it. `FlowWorkerMapSnapshot` is rows+truncation only
(`umem/mod.rs:250-255`); count + rows still two independent publishes
(`debug_state.rs:217-224` vs `:226-247`); `flow_worker_map()` aggregates
per-binding ArcSwap loads (`coordinator/status.rs:168-187`). Counting rows from
the returned Vec makes count==candidate-rows for that tick (avoids the skew) but
gives NO timestamp/staleness guard and is not "true active count" (active rows
gated by `last_used_epoch` ~650 ms window `flow_cache.rs:453-459`; controller
drops non-TCP/UDP `coordinator/rebalance.rs:286-293`). MUST hard-require: count
only post-filter steerable FlowSamples; defer on truncated; stop claiming a real
staleness guard unless #1750 lands.

**3. Convergence / Anti-Thrash** — Algorithm salvageable, formal proof WRONG. The
plan claims termination in `≤Φ₀` moves using `Φ=max-min` (`plan.md:186-194`).
Counterexample `[3,3,3,3,1,1,1,1]`, K=2, Φ₀=2: takes FOUR admitted moves to reach
`[2,...,2]` while Φ stays 2 until the last move. Use L1 distance to balanced
target or sum-of-squares instead. No permanent oscillation if counts are
post-filter steerable + cooldown expires; if counts include raw unsteerable rows,
livelock is real.

**4. Homogeneous / Heterogeneous** — Honest enough. Count-balance defensible for
homogeneous iperf -P12; not a general rate-fairness controller; elephant/mice
gated on a reliable per-flow signal. Keep limitation prominent in docs + test
naming.

**5. Live Gate** — A/B gate in both CoS modes necessary but too late. Cheaper
decisive pre-code gate: repeat R1's manual exact-5tuple round-robin re-pin on
current master with CoS ON at -P12 -p5210 (R1 proved CoS-off:
`r1-spike-findings.md:3-13,30-35`). If manual CoS-on count-balanced placement
still lands ~50%, do not write selector code expecting it to fix shared_exact; if
near R1-class CoV, the plan is much stronger.

**Required revisions:** add the pre-code CoS-on manual re-pin gate; fix the
convergence proof; tighten the feed invariant to "post-filter steerable rows from
the same returned snapshot."
