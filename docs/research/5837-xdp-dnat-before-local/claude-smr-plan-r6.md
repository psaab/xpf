# Claude SMR — plan review r6 (#5837)

**Verdict: self-corrected from PLAN-READY to concurring with PLAN-KILL of the drive-by
dataplane fix + ship the Track-1 commit-WARNING.** (Converged position in plan §0.)

## Honest self-correction
My r2–r6 PLAN-READYs were premature — the SMR-soft-pass → self-correction pattern the skill
explicitly warns about. Codex r6 disproved two of v6's "closures" I had signed off:
- The `intent_authoritative` bit does NOT achieve fail-closed for a missing/failed-insert key —
  it only gates READY, and the non-READY path still passes local (= #5837). I called this
  closed; it isn't.
- My ingress-interface "proof" was factually wrong: a packet can ingress an interface other than
  the one owning the destination address (DNAT is ingress-scoped independently), and the physical
  fabric parent IS in the ingress set (an intentional HA path), contradicting my "fabric skipped"
  claim.
- An entire HA-failover generation-safety dimension (stale-but-authoritative standby staying
  takeover-eligible) was never in the plan until Codex surfaced it — first-order for an HA firewall.

I was closing findings faster than they were truly closed. Correcting that now.

## Why PLAN-KILL-of-drive-by is the honest converged answer
Applying the team-lead's own PLAN-READY test — *architectural agreement AND verifier feasibility
settled* — neither holds:
- **Verifier: unsettled and worsening.** The probe must land in the miss arm + every degraded
  branch + behind an AH guard, under the 1M-insn cap with tail-call forbidden and no headroom
  metric. Each correctness round ADDED hot-path surface. The go/no-go is an unhedged gamble that
  only `shimverify` can settle, and REJECT is materially likely.
- **Not-just-nits open.** Fail-closed-incomplete-state and HA-failover generation-safety are
  architecture-level (they decide whether the *security* fix holds under failure/failover), not
  polish. They're solvable but each solution grows the verifier surface further.

Six rounds of Codex finding a real hole at each newly-exposed layer is a signal about the
*change*, not the plan: this is a large, deep, verifier-risky project, not a drive-by bug fix.

## What IS ready
The **Track-1 commit-time WARNING** (§0a) is genuinely PLAN-READY and worth shipping: it's a
pure config-compiler check (the compiler already has `cfg.Warnings` + both the pool addresses and
interface addresses), zero dataplane/verifier risk, and it fixes the bug's worst property — today
the bypass is **silent**; the warning makes it **loud**. That is a real, immediate security-posture
improvement.

## What the research produced (value, not a dead end)
- Killed Option A (reuse `dnat_table`) with a proven shared-key collision — prevented a
  corruptible fix.
- Established Option B (dedicated intent map) as the only viable dataplane design, fully specified
  through v6, with the four remaining hard problems (fail-closed generation-tagging, per-rule
  ingress + attach transition, HA-takeover generation gating, capability boot-timing) enumerated
  as the Track-2 scope (§0b) for a future funded effort.
- Surfaced the true cost: a shim-ABI + new-map-lifecycle + degraded-mode + restart + HA-failover +
  config-compile-propagation change gated on an unvalidated verifier verdict — decidedly not a
  quick fix.

**Concur: PLAN-KILL (drive-by) + Track-1 WARNING shippable + Track-2 full fix deferred.**
