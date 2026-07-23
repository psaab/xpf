# Claude SMR — hostile plan review r3 — #6177

Re-review of `plan.md` r3 (@ e41e68cdccdc) after folding Codex r2 (F1–F5). Posture:
hostile — did the folds land, and is the reframed recommendation actually sound?

## Codex-fold disposition (firsthand-checked, not taken on faith)

- **F1 (narrow ACK claim)** — FOLDED. §3 now distinguishes the dominant priority-0
  path (ack not the lever) from the compound-rare all-3-adverts-lost subset (ack CAN
  order, but #6367's VIP-gate was still the wrong tool). The all-3-lost analysis is
  correct: with no priority-0 the peer's `masterDownTimer` (armed at ~97 ms
  masterDownInterval from the last normal advert) fires and promotes via the ungated
  masterDown path, OR the post-ack `ForceRGMaster` fires if the ack round-trip beats it.
  Accurate.
- **F2 (benign split)** — FOLDED and materially more honest. §3/§4 separate the benign
  success-path VIP-timing window from the real failure-path forwarding hazard. I
  re-verified the crux firsthand: daemon_ha.go:367 warns-and-continues on a failed
  `SetRGActive(false)`; :389 signals regardless; `reconcileRGStateLoop` (:604-620) is a
  2 s ticker that re-drives rg_active. So "~2 s reconcile-bounded dual-forward" is a
  correct characterization. #5482 exhaustion (instance_vip.go:125) correctly cited.
- **F3 (Option D)** — FOLDED with the right call. §5-D lays out D1 (conflicts with #485)
  and D2 (#485-compatible: gate the signal on SetRGActive success) and — crucially —
  gives the firsthand reason D2 is not a clean win: withholding the ack cannot un-take
  the peer's priority-0 VIP move, so a D2 abort can produce a LONGER blackhole than
  today's bounded dual-forward. Filing it as a separate research issue (not dismiss, not
  bundle) is the correct disposition. I could not find a way to make D2 obviously safe
  without the #5079/#485 design pass, so "file it" is right.
- **F4 (drop Residual-2)** — FOLDED. §6 drops it with the coherent-generation-model
  argument. Correct: signal (:173-181) and arm (:149-156) stay key-only, so hardening
  only disarm/timeout is asymmetric. Dropping is the honest call given unreachability.
- **F5 (branch-level test)** — FOLDED. §6/§9 replace the primitive-only claim with a
  branch-level demotion-order test covering SetRGActive success + failure, and stop
  claiming primitive tests protect the ordering.

## New hostile probes on r3

- **Probe D — does filing Option D leave #6177's `security` label satisfied?** The plan
  files the security-relevant hazard (failed-SetRGActive dual-forward) as a NEW issue
  and lands only test+doc on #6177. A hostile reader could say "#6177 is labeled
  security and you shipped no security fix." Rebuttal is on the page (§3 threat model:
  not attacker-triggerable, ~2 s bounded, tracked in the new issue), and per
  `feedback_triage_new_issue_per_finding` filing-not-dismissing is correct. But the plan
  MUST ensure the new issue is actually filed and cross-linked before #6177's security
  label is dropped (§11 Q-c makes this explicit). Acceptable.
- **Probe E — is the branch-level test feasible without a live cluster?** The demotion
  branch is inside `watchClusterEvents`, which consumes real cluster events. The plan
  says "or an extracted testable seam." That is an implementation risk (the /engineer
  may need to extract the demotion body into a unit-testable function). Flag as an
  implementation note, not a plan defect — the seam is a normal refactor.
- **Probe F — Residual-3 fail-on-revert:** the branch-level test's fail-on-revert guard
  should be that removing the `SetRGActive` call (or its ordering) changes the asserted
  order — the plan should ensure the test actually BINDS the ordering, not just runs the
  branch. Minor: the /engineer must pick a neutralization that goes RED. Noted, not
  blocking.

No new blocking hole. r3 is materially more honest than r2 and the recommendation is
coherent: PLAN-KILL Residual-1's VIP-gate, DROP Residual-2, LAND a branch-level
Residual-3 + doc fix, FILE Option D. This is the correct research outcome — a partial
PLAN-KILL (Residual-1 + Residual-2) inside a PLAN-READY narrowed scope, with the real
security-relevant hazard tracked in its own issue rather than force-shipped.

## Verdict

**VERDICT: PLAN-READY** (narrowed): PLAN-KILL Residual-1 (VIP-gate) + DROP Residual-2;
LAND a branch-level demotion-order test (Residual-3) + the doc-accuracy fix on #6177;
FILE the failed-`SetRGActive` forwarding fence (Option D) as a separate `/research`
issue. Probes D–F are implementation notes, not blockers.
