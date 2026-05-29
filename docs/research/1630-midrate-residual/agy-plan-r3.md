# AGY adversarial plan-review — #1630 cause-2 — r3

Job: `adversarial-review-mpqcyavq-io08la` — succeeded; full result
returned. Verdict: **PLAN-READY** — BUT on a FALSE config assumption;
the load-bearing §1 is wrong. See below.

## AGY r3 read the CORRECT tree this round (worktree 0e5bb3812)

Unlike r2, AGY r3 traced source from the worktree path and confirmed the
waterfill selector, the H-LEASE kill, the per-binding non-atomic
waterfill state, and the §10-R3 scope. Those confirmations are valid.

## Why AGY r3's PLAN-READY is REJECTED (the §1 error)

AGY §1 "confirmed" the boundary by asserting *"For a solo 3g class,
`quantum_sum = 75,000`"*. This is only true if the running CONFIG
contains ONLY 3g. **It does not.** `exact_queues_by_rate_ascending` is
built ONCE at config-apply over ALL configured exact queues
(`builders.rs:80-83`); the `quantum_sum` loop (`queue_service/mod.rs:789`)
sums over that static vector with NO eligibility guard. The solo/4-class
harness applies the FULL `cos-iperf-config.set` (`apply-cos-config.sh:73,
140 load merge`) — all 10 exact classes — and merely sends traffic to one
port. So `quantum_sum = 2.65 MB`, Phase-1 budget = 1.85 MB, and 3g/6g ARE
Phase-1-honored every epoch. **This is exactly Codex r3 BLOCKING-1, which
AGY missed.** AGY conflated traffic-solo with config-solo.

## Disposition

AGY r3 PLAN-READY does NOT stand. The decisive verdict is Codex r3
BLOCKING-1 (PLAN-NEEDS-MAJOR) + Claude SMR r3 (concur, PLAN-NEEDS-MAJOR):
H-WATERFILL is falsified for the measured config. AGY's non-§1 findings
(Phase-2 lossiness mechanism, counter separation, layering, scope) are
folded as supporting context. 2-of-3 decisive against the v3 mechanism;
v4 converges to a measurement-first plan with NO pre-committed fix.
