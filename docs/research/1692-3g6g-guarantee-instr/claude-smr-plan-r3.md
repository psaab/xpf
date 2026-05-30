# Claude-SMR plan-review r3 — #1692 (HOSTILE) — converging PLAN-KILL

Reviewer seat: Claude SMR. Round 3 against plan v2, folding Codex r2 +
AGY r2.

Verdict: **PLAN-KILL** (the instrument cannot disambiguate; structural,
not fixable by another column).

## Self-correction of my r2

My r2 PLAN-READY argued `backlog_i` is a sound demand proxy because the
park-without-pop path keeps a share-capped worker's queue full. **That was
wrong** — it is true only OPEN-LOOP (arrivals > service). Codex r2 and
AGY r2 independently caught the closed-loop case: under TCP, the sender's
congestion control paces DOWN to the L1-enforced bottleneck, so arrivals
converge to service and `queue.hot.queued_bytes → ~0` on a share-capped
worker too. I verified the enqueue/dequeue accounting
(`tx/cos_classify.rs:887,915` increment after admission;
`cos/tx_completion.rs:511` decrements on send): a paced TCP flow leaves
the accepted queue near-empty at scrape time. So `backlog_i ≈ 0` does NOT
separate (0) demand-bound from (L1) share-cap. My r2 "no L1↔0 aliasing"
claim is retracted.

## The decisive defect (Codex r2 CRITICAL-1) — verified

`p1_admit_i ≪ eligible_visits_i` was v2's claimed UNIQUE fingerprint for
L3. It is NOT unique. I verified the counter sites:
- `eligible_visits` bumped at `queue_service/mod.rs:851` — BEFORE the
  queue-token gate.
- queue-token gate at `:879`: `if queue.hot.tokens < head_len { … continue }`
  — skips WITHOUT bumping `phase1_admissions`.
- `phase1_admissions` bumped at `:947` — only AFTER passing the gate.

When L1 (the v8 lease) starves `queue.hot.tokens` (its `acquire_v8`
returned < `head_len` because `my_share` is exhausted), the selector
reaches `:879`, parks, and `continue`s. Result: `p1_admit ≪
eligible_visits` — **the exact L3 fingerprint, produced by L1.** The
token gate that L1 controls sits structurally BETWEEN the visit-count
(`:851`) and the admit-count (`:947`), so the selector-layer counter
cannot tell "selector Phase-1 budget exhausted" (true L3, `:926-935`)
from "v8 lease starved the bucket so the selector skips" (L1). The two
layers are aliased on the only column that was supposed to separate them.

## Why this is STRUCTURAL, not "add one more column"

The three candidate layers are SERIALLY COUPLED, not independent:

```
L1 (v8 acquire_v8 my_share)  →  queue.hot.tokens  →  L3 (selector token
gate :879 + Phase-1 budget :926)  →  drain_sent
```

L1's output (granted tokens) IS L3's input (`hot.tokens`). Any passive
counter downstream of L1 (admit, drain, backlog) reflects the COMPOSITION
of L1∘L3, not either alone. The only counter that isolates L1 is
`granted_i vs share_integral_i` — and:
- `share_integral_i` is unmeasurable soundly (Codex r2 F2 + AGY r2 F2):
  `acquire_v8`-driven rotation means the integral is acquire-cadence, not
  epoch-cadence; a banked-token worker skips acquires and undercounts;
  one delayed acquire grants a multi-epoch cap; and v2's own formula
  (`my_share × epoch_elapsed`) double-counts dimensionally
  (`my_share` is already bytes/epoch).
- even a rotation-side correct `share_integral` does not break the L1↔L3
  admit aliasing above, because that aliasing is in the SELECTOR counter,
  not the lease counter.

And the one independent signal that COULD break the coupling — per-worker
DEMAND — is collapsed by TCP closed-loop (the backlog defect above). To
recover a true demand signal you would need per-flow OFFERED-load
instrumentation at the sender or pre-admission RX, which is a different,
much larger instrument than "per-(class,worker) counters off worker-local
state," and would itself perturb the measurement.

## Verdict rationale (the consumer criterion, applied)

Per `feedback_review_scaffolding_against_consumer` and the plan's own §7:
**an instrument that cannot DECIDE between its target layers is a
structural failure, regardless of internal counter correctness.** Three
independent hostile reviewers across three rounds (Codex r1+r2, AGY r2,
Claude-SMR r1+r2+r3) have now shown:
- r1: the L1 sub-case discriminator was a mathematical constant (fixed);
- r2: L1↔(0) aliasing via TCP-paced backlog collapse; L1↔L3 aliasing via
  the token gate between visit and admit; `share_integral` unmeasurable.

These are not successive bugs in the table; they are three faces of ONE
fact: **L1, L3, and demand are not separable by passive counters because
the layers are serially coupled and the demand signal is closed-loop.**

This is the #1211 lesson in instrument form: do not build a measurement
that solves a non-existent (here, unmeasurable) separation. It is also
consistent with the #1630 finding that mid-rate 3g/6g sit on a transport-
physics floor that IMPROVES with parallelism — i.e. the most probable
real cause is the demand-bound (0) outcome, which is itself a documented
PLAN-KILL, and which this instrument cannot even confirm cleanly.

## What survives (for any future revisit)

NOT a new passive-counter design. A future attempt would need either:
1. an ACTIVE differential experiment, not passive counters — e.g. pin a
   single 3g flow to a single worker (one flow, one queue) so L1's
   `my_share = full cap` and the token gate cannot starve, then measure
   whether 3g reaches shape. If it does, the multi-worker under-delivery
   is the v8 share-split (L1 by-design); if it does NOT, it is L3 or
   demand. This is a controlled A/B, not an instrument — and it belongs
   in a fresh issue with its own plan, not this one; OR
2. a sender-side offered-load harness to break the closed-loop demand
   ambiguity — out of scope for a userspace-dp counter PR.

Both are larger than the chartered "instrument-first per-(class,worker)
counters" and neither is justified until the cheaper #1614 Path B
(re-scope gates + document the ceiling) lands. PLAN-KILL #1692 as a
passive-instrumentation effort; the controlled-A/B idea (option 1) may be
filed fresh if the by-design L1 answer is not accepted.
