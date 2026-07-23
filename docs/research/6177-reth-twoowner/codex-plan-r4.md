# Codex — hostile plan review r4 (CONVERGENCE) — #6177 (medium effort, ~43.4k tokens)

Raw: `codex-plan-r4-raw.txt`. **VERDICT: PLAN-READY.**

"No recommendation-changing blocker found. The r4 design recommendation is confirmed."
- F1 race precision correct (R's independent master-down timer can beat post-ack
  ForceRGMaster; O's separate safety timer is >=500 ms).
- The 2 s loop correctly characterized as retry cadence; persistent SetRGActive(false)
  failure leaves dual-forwarding unbounded.
- Failed fabric prep now an unquantified availability risk.
- Option D correctly includes the 15 s floor / 30 s default #5079 lease tradeoff — FILE
  for dedicated research; do not ship here.
- §8 removed Residual-2 and accurately states attempt-before-signal; agrees with §§6/7/9.

Two non-blocking stale sentences flagged (both fixed post-convergence in the final r4):
- §3 δ_remove note claimed benignity for any δ_remove incl. failed removal → corrected to
  success-path-only.
- §3 "ack barrier genuinely does" said rg_active "is cleared" → corrected to "attempted".

Confirmed: kill the VIP gate, drop Residual-2, land the branch-level success/failure
ordering test + doc correction, file Option D separately. **VERDICT: PLAN-READY**
