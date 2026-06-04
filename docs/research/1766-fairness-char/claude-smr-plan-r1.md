# Claude SMR — hostile self-review of #1766 plan (r1)

Reviewing as domain SMR (AF_XDP zero-copy dataplane, MQFQ/V_min
scheduling, RSS multinomial statistics, TCP congestion control) +
CPU/cache + measurement-methodology. Goal: break the PHYSICS verdict.

## Attempted kills and why they fail

1. **"Cstruct from a 650ms {a_i} proxy vs 75s throughput CoV is a
   category error."** Partially valid as a *precision* complaint
   (logged §6.5), but not a verdict-breaker: the daemon's own
   steady-window-internal `xpf_fairness_cstruct` gauge matched my
   offline Cstruct on every run I cross-checked (r5 50.0/50.0, r6
   54.4/54.4, r8 71.5/71.5). If the proxy were unrepresentative the two
   would diverge. And the gap to Cstruct (45–65 pp) is an order of
   magnitude larger than any plausible window-misalignment noise (Codex
   independently recomputed warmup-excluded CoV: barely moved).
   → not a kill.

2. **"The grant↔observed correlation is circular — a shared
   active-count bug feeds both."** This is the strongest attack and I
   conceded it (§3 softened from "proof" to "strong evidence"). The
   load-bearing disconfirmation is the *direction* of the residual: a
   v8/V_min accounting *gap* that over-credited crowded workers would
   make crowded-worker flows run *faster* (lower or inverted spread) or
   throttle solo workers; the data shows the canonical designed split
   (solo highest grant-per-flow ~10.3 GB, crowded lowest ~7–8 GB). A
   *leak* has a signature opposite to what is observed. → not a kill,
   but the plan must not over-claim (fixed).

3. **"V_min could be throttling and you can't see it."** True that the
   counters aren't exported (§3.3, conceded). But V_min's *mechanism*
   (`v_min.rs:181` `cont = queue_vtime <= v_min + lag`) only ever
   *delays the worker that is ahead*. Its failure mode is
   over-compression (CoV too LOW) or stall (aggregate too low), never
   CoV-too-high. Observed CoV is far below ceiling AND aggregate is at
   the structural cap on the 5-active runs → neither V_min failure mode
   is present. → not a kill; observability follow-up logged.

4. **"Saturated runs invalidate the cwnd-bound framing."** Correct, and
   I rewrote §4. But note this *helps* the verdict: r7 hit 107% of its
   15G structural cap with CoV 4.2% vs Cstruct 44.7% — saturated-regime
   physics sitting 40 pp under the ceiling is the cleanest possible
   evidence that the per-worker scheduler divides each worker's
   (now-capped) share fairly. → strengthens, not breaks.

5. **"You never saw the 6-pile, so the worst case is unmeasured."** I
   captured 5 distinct 5-piles (Cstruct 67–81%) all 45–65 pp under
   ceiling, and dropped the bogus 0.91 monotonicity number (6-pile is
   0.707). The empirical basis is the 5-pile coverage, not a theorem.
   A 6-pile raises Cstruct (0.707) far faster than the v8-mitigated
   observed CoV (~25% per the issue), so its margin is *larger*. → not
   a kill.

## Residual concerns I could not fully close
- Forward-only path. Reverse (ge-0-0-1 egress) physics is argued
  identical but not measured. Cheap confirmatory add if a reviewer
  insists; does not change the verdict for the operator's
  forward-direction repro.
- V_min counters genuinely unobservable on this build — the indirect
  argument is sound but a direct read would be stronger. Logged as
  optional observability follow-up, not a blocker.

## SMR verdict
**PLAN-READY (accept-as-physics)** after the r2 corrections. The Q1
verdict (physics, no v8/V_min gap) survives every attack; the strongest
attack (grant-correlation circularity) is neutralized by the
residual-direction argument and was over-claimed in r1 (now fixed). Q2
(equal-flow default-OFF) and Q3 (Cstruct gate already correct) are
sound. No production code change warranted; the only follow-ups are
doc/observability/harness adds, all optional and out of scope for a
behavior PR.
