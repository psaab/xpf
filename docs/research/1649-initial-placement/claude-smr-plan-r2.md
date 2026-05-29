# Claude SMR hostile plan-review — #1649 r2

Reviewing as an RSS / NIC-flow-steering / AF_XDP / Linux-kernel-networking
domain expert. Confirmation round after r2 revisions.

## Verdict: PLAN-READY (PLAN-KILL is correct, rationale now sound)

My r1 BLOCKING finding (§6 falsely claimed no non-re-steer mechanism exists) is
resolved: r2 §6 acknowledges and shows the masked src-port-residue mechanism
verified on the NIC, and the kill spine moved to the multinomial argument in
§7.0. The three reviewers now converge.

## Confirmation of the load-bearing kill (§7.0)

The kill rests on a theorem I consider airtight and that Codex (r2) and AGY (r2)
independently confirmed by re-derivation:

> Any *static* mapping `f(5-tuple) → queue` yields i.i.d. queue draws with a
> fixed per-queue probability vector. A balanced vector = the RSS floor; an
> imbalanced one is worse. No static scheme can create the **negative
> dependence** required to make N≤M flows avoid already-occupied queues — only a
> per-flow occupancy-aware decision (a reactive controller = §5 re-steer) does.

Empirical agreement across all three reviewers (N=6, M=6):
- RSS uniform: P(perfect spread) ≈ 1.54%, CoV ≈ 0.87.
- Residue, residues 6/7 → RSS: CoV ≈ 0.874 (identical to RSS — AGY).
- Residue, residues 6/7 → Q0 or explicit: CoV 0.93-1.00 (worse — AGY).
- Pure mod-8 bucket CoV 1.05 (my r1 Monte-Carlo).
- Sequential/coordinated ports: P(spread) ≈ 20%, CoV ≈ 0.54 (AGY) — the
  controlled-harness exception that matches the Phase-0 3.8% and ONLY that.

This is the decisive, falsification-resistant kill: the mechanism exists but is
on (or below) the same floor for the realistic ephemeral-port flow mix.

## Codex r2 precision note — adopted

Codex correctly observed that when residues 6/7 fall through to RSS, the actual
6-queue distribution is *identical* to RSS, not strictly worse; "worse" only
holds for the pure-8-bucket or biased-fallthrough layouts. r2 §7.0 now states
"same-as-RSS at best, or worse" and no longer leans on "worse." Correct.

## Residual nits (non-blocking, all satisfied)

- 1024 cap = `MLX5E_ETHTOOL_FLOW_SPEC_NUM` (AGY-verified); used only to bound
  the exact-5-tuple controller, not the 6-rule residue mechanism. Fine.
- ~1 ms/rule demoted to secondary nail. Fine.
- Queue-bound determinism worded as "the worker whose XSK is bound to queue N."
  Fine.
- mlx5-VF (not PF) noted explicitly; ethtool tests ran on the actual VF and the
  VF exposes the full ntuple path + 1024 cap. Fine.

## Salvage check — confirm dismissal

A controlled-harness even-flow knob is a lab demo achievable with raw `ethtool`;
not worth a daemon controller, and a #1203-style automatic controller is
re-steer (§5). No production-worthy opt-in. Confirm KILL.

## Convergence

All three reviewers PLAN-READY on the KILL:
- Codex r2: "VERDICT: PLAN-READY (kill correct)"
- AGY r2: "PLAN-READY (kill correct, rationale sound)"
- Claude SMR r2 (this doc): PLAN-READY (kill correct)

Proceed to the §9 deliverable: document the multinomial floor curve + the
"why HW ntuple steering does not help" subsection in `docs/fairness-regimes.md`
at /engineer time. No production code in this research.
