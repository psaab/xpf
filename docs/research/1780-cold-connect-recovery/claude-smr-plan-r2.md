# Claude SMR plan-review — #1780 round 2 (v2 @ 850a954a6)

**Verdict: PLAN-READY** for the v2 scope (Path A committable + resolver-fix
diagnostic-gated).

v2 folds both round-1 findings (Codex + my r1) and the factual corrections:
- Path A retargeted to the **Go** `runPeriodicNeighborResolution` (the actual
  15s loop), not Rust `queue_warm_pass`. The stall analysis (a blocking
  synchronous handler freezes the `for-select` loop; a hung `warmNeighborCache`
  wedges the `neighborWarmupInFlight` guard) is grounded in the code I read.
- Path B (first-probe-bypass) **dropped** — Codex proved the first probe is
  already immediate and the 1s limiter doesn't gate it; bypassing it was a
  fix for a non-bottleneck and a per-binding storm risk.
- The resolver/probe fix is **deferred + capture-gated** with a real dominance
  capture (ARP tcpdump + full counters), so we won't churn the resolver path on
  an unverified premise (the discipline lesson from 3 refuted hypotheses).

Path A stands on its own merit: **a periodic neighbor-maintenance loop that can
be frozen 17.5h by one hung handler is a defect independent of the
cold-connect hang**, and the `neighbor_periodic_last_pass_age` gauge is both the
fix's observability and the diagnostic the capture needs. Low risk
(control-plane, slow path), HA-aware (must keep the standby-skip), `make
test-failover` gating.

Residual nits for /engineer-time (not plan blockers): (a) if isolating
`resolveNeighbors`/`forceProbeNeighbors` into goroutines, prevent overlapping
passes (a guard like `warmNeighborCache`'s, or keep them synchronous-but-
timeout-bounded which is simpler); (b) confirm the `daemon_neighbor_listener`
netlink goroutine isn't a separate stall vector (capture covers it).

PLAN-READY. Recommend: ship Path A on `/engineer 1780` once round-2 confirms;
keep the resolver/probe fix as a capture-gated follow-up (the running
`/tmp/idle-hang-longcapture.out` + the operator's overnight capture feed it).
