# AGY adversarial plan-review — #1630 cause-2 — r2

Job: `adversarial-review-mpqcfeya-tvz2g7` — succeeded; result returned
in FULL this round (unlike r1). Verdict: **PLAN-NEEDS-MAJOR** (PLAN-KILL
on the H-LEASE fix branch).

## IMPORTANT: AGY's §2 "waterfill REJECTION VERIFIED" is a WRONG-TREE error

AGY §2 claims "There is no `select_exact_cos_guarantee_queue_waterfill`
in the active codebase … `oversubscription_policy` is never read in the
drain." **This is false on origin/master `0e5bb3812`.** AGY grepped
`/home/ps/git/bpfrx` — the session's MAIN CHECKOUT, which is at a STALE
detached HEAD `e01472f4a` that predates the #1614 A1 waterfill merge.
The research worktree and origin/master DO contain the waterfill selector
(verified: `git show origin/master:.../queue_service/mod.rs` has the
dispatch at :608 and the fn at :771; the stale cwd checkout has neither).
This is the SAME wrong-tree error Claude SMR made in r1 (see
claude-smr-plan-r2.md). **Codex r1+r2 BLOCKING (waterfill exists) is
correct; AGY §2 and the original agy-r1 rejection are retracted.**

## AGY findings that ARE correct and load-bearing (kept for v3)

- **§3 — bisection TX-contamination (CORRECT).** Stranded
  `queue.hot.tokens` after a TX-ring refusal reduces the next top-up's
  `total_granted`, so `total_granted/cap_granted < 1` can be a
  DRAWN-NOT-SENT artifact mis-bisected as GRANT-NOT-DRAWN. Fix: the §5
  ratio must net out residual hot tokens. Reinforces Codex r2 BLOCKING-3.
- **§4 — F-E busy-poll (CORRECT, == Codex r2 BLOCKING-2).** With a 200µs
  epoch = 4 ticks and per-worker `my_effective_share`, a share-exhausted
  worker with `class_granted < cap` would busy-poll up to ~150µs under
  F-E. The guard must be `my_consumed < my_effective_share`.
- **§6 — H-LEASE is TOOTHLESS (CORRECT, decisive for the fix choice).**
  Raising `lease_bytes` to `rate×600µs` has ZERO effect: `acquire_v8`
  hard-caps the grant at `my_effective_share ≤ my_share = new_cap × …`,
  and `new_cap ≤ rate × EPOCH_DURATION_NS` (200µs). The bucket can never
  bank > 200µs of credit under the v8 epoch ceiling unless
  `EPOCH_DURATION_NS` itself is raised (global seqlock perturbation).
  **This kills the H-LEASE fix branch** and pushes the fix to the
  waterfill allocator or a scheduler change.
- **§5 — H-TCP PLAN-KILL is a "pacing dodge" (PARTIALLY VALID).** AGY
  argues smooth delivery is the shaper's duty, so attributing the loss to
  TCP and re-framing Gate 1 is a cop-out; the right path is sub-tick
  pacing. v3 should treat H-TCP as "needs a smoothing fix" not "kill",
  unless the goodput/drain_sent measurement proves the bytes genuinely
  left the NIC at full rate.

## Disposition

All three reviewers: PLAN-NEEDS-MAJOR. The substance (Codex + Claude SMR,
verified against the correct tree) is: re-ground on the waterfill
selector. AGY's non-tree-dependent findings (#3/#4/#6) are folded into v3.
