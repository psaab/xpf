# Claude SMR — hostile plan review r3 (#3607)

Reviewing `plan.md` v3. Round-2 Codex + AGY both confirmed round-1 RESOLVED and
raised refinement-level findings (not architecture rejections). v3 closes them.

## Verdict: PLAN-READY on Option B (consumer-split, v3), with DEFER-the-sketch / PLAN-DEFER-operator as fallbacks

## Round-2 findings → v3 resolution (all addressed)
- **cookie-OFF aggregate drops legit sustained SYNs** (AGY BLOCKER, Codex MAJOR):
  v3 §5a adds a per-zone OFF-attack `TokenBucket` consulted only when `syn-cookie`
  is OFF; `increment_and_classify` stays untouched (alarm + cookie-ON). No bypass
  (no cookie when off). ✓
- **sketch fail-closed with token-bucket cells** (Codex BLOCKER): v3 §5b
  re-derives fail-closed (collisions only drain faster ⇒ over-count; sustained
  victim always trips) and reframes "stay-tripped-until-idle" → "rate-enforced" as
  the intended fix; new tests in §9; DEFER-the-sketch in §10a. ✓
- **`admit()` polarity** (Codex MAJOR): §5/§6 pin `true = over = drop`, same as
  `increment`, drop-in. ✓
- **missing-profile warn dampener** (Codex MAJOR): §3/§5 keep it on `RateCounter`
  (suppress-until-idle); §9 keeps `tests.rs:4085` green with no edits. ✓
- **cookie-ON permanent cookie-lock** (AGY MAJOR): §10 documents it as
  Junos-consistent + #3315-D3, with operator guidance + a tracked hysteresis
  follow-up; fixing via count-only-admitted would re-open the bypass. ✓
- **standby-ACK validator signature churn** (AGY MINOR): §4/§8 acknowledge it. ✓

## Residual hostile checks on v3 (no blocker)
- **Does the OFF-attack bucket + count-all aggregate double-count SYNs?** No: the
  aggregate `RateCounter` measures arrival rate (alarm + cookie-ON); the OFF-attack
  `TokenBucket` makes the drop decision only when cookie is OFF. They read the same
  stream but serve disjoint decisions; no interference (§5a).
- **cookie-ON "benign" claim honest?** Yes for `syn-cookie` ON (a challenge is one
  extra RTT, recoverable). The only residual annoyance (cookie-lock at threshold +
  per-source suppression) is documented, not hidden (§10). This is the correct
  posture for a design-fork.
- **Is v3 growing unbounded across rounds?** No — the architecture (token-bucket
  shapers + untouched RateCounter latch/dampener) has been stable since v2; rounds
  2-3 only refined *which* consumers migrate and pinned polarity/fail-closed. This
  is convergence, not churn.

## Bottom line
v3 is internally consistent and resolves every round-2 finding without
reintroducing a round-1 one. PLAN-READY on Option B (consumer-split); issue stays
open, label `plan-deferred-research`, awaiting manual `/engineer`. DEFER-the-sketch
and PLAN-DEFER-operator remain explicit, honest fallbacks if the user weights
blast radius over the accuracy gain.
