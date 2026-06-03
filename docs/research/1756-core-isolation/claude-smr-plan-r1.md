# Claude SMR hostile review — #1756 Path C plan r1

Reviewing as domain SMR (AF_XDP dataplane), CPU-arch/scheduler, and SW
design. Goal: try to overturn the PLAN-KILL; fall back to confirming.

## Attempt to overturn

**Lever 1 — could Go steal more than utime+stime shows?** Yes in
principle: a Go thread that runs 22%-of-one-core total can still inflict
cache/TLB pollution and MESI traffic on a busy-polling worker each time
it co-locates, and that cost is NOT in the worker's utime+stime — it
shows up as IPC degradation while the worker IS on-CPU. So "22% of one
core" is a benefit ceiling on *reclaimed CPU time* but not on *jitter*.
BUT: the jitter is independently bounded by the involuntary-preemption
measurement (15-134/s → ≤6.7% worst, <0.4% typical), and at baseline
there are **0 retransmits** — if cache/MESI pollution were materially
hurting throughput we would expect ring starvation / retrans. We don't.
Overturn fails: both the CPU-time ceiling AND the jitter+retrans
evidence independently bound the benefit below 16.7%.

**Lever 2 — does isolating Go let softirq run faster and free >22%?**
softirq on a worker core competes with the worker, not with Go (Go is
~3.7%/core). Removing Go frees ~3.7%/core for softirq+worker to share;
it does not change the ~25% softirq volume (that's a function of pps,
not scheduler pressure). Overturn fails.

**Lever 3 — the queue%5 funnel.** Confirmed against source:
`replan_bindings_from_candidates` sets `binding.worker_id = (queue_id %
workers.max(1))`. 6 queues, workers=5 → queue 5 % 5 = 0 → worker 0
owns queues 0 and 5. This is real and makes B strictly worse than a
uniform −16.7% (it's −16.7% raw PLUS load skew onto worker 0, the
#1183 funnel). Strengthens the kill.

**Lever 4 — does Path C differ from #712/#741?** #712 reserved cores
0-1 for IRQ; Path C reserves core 0 for Go. Both leave the ~25%/core
softirq on the worker cores (the documented reason #741 was a no-op).
Path C additionally pays a worker. No regime found where dedicating to
Go specifically wins where #712's IRQ-reserve lost. Overturn fails;
this is largely #712 re-litigated with a worse worker math.

## Methodology caveats (honest)

- No BTF → could not attribute preemptions to `next_comm == xpfd`. The
  plan correctly frames the /proc preemption count as an UPPER bound
  (includes softirq/RCU/timer), which only strengthens a kill.
- Throughput anchor (12.3 Gb/s, 5210) is a CoS-shaped class, not the
  raw 16 Gb/s ceiling; it is a stable A/B anchor, not a capacity claim.
  Plan states this. Fine for a kill (the kill is mechanism-based, not
  throughput-delta-based).
- The 22%-of-one-core figure is a single 8 s steady-state window. A
  control-plane BURST (HA bulk sync / FRR reload) could spike Go
  transiently — but the fix for that is throttling the burst or #739,
  not a permanent dedicated core (plan §9/§11.2 acknowledges this).

## Source/line spot-checks

- `pin_current_thread` @ neighbor.rs:713, called loop_body/mod.rs:59 —
  correct.
- `worker_id = queue_id % workers` in replan — correct.
- `--workers` lifecycle.rs:269, process.go:79, manager.go:1191 — correct.
- `workers 6;` ha-cluster-userspace.conf:286 — correct.
- #712/#741 revert + softirq-spread rationale in cos-validation-notes.md
  §"CPU pinning retry post-#740" — correct, faithfully summarized.
- #739 OPEN (isolcpus/nohz_full) — verified via gh.

## Verdict

**PLAN-KILL-CORRECT (PLAN-READY for the kill).** The benefit is bounded
below 16.7% by two independent measurements (Go CPU envelope = 22% of
one core; jitter ≤6.7% worst / <0.4% typical with 0 retrans), the cost
is a hard 16.7% worker cut worsened by the queue%5 funnel, and the
correct jitter lever (#739) needs no worker sacrifice. Recommend
PLAN-KILL with redirect to #739.

## Cross-review note (post round-1 convergence)

Codex + AGY independently reached the same kill and added two precedents
I had not cited: #1243 (the exact 5-worker dedicated-CPU mode was
already PLAN-KILLED at −17% with VRRP-starvation risk) and the
#1244-era keep-6-workers daemon pin (+30%, 17→22.7 Gbps) which shows
the *real* win is core-0 Go pinning WITHOUT dropping a worker. Both fold
into plan v2 and only harden the kill. Final SMR verdict unchanged:
**PLAN-KILL-CORRECT.**
