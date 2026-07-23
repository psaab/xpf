# Claude SMR — plan review r4 (CONVERGENCE) — #6177

r4 folds every Codex r3 precision correction (retry-cadence-not-2s-bound, F1
ForceRGMaster-race precision, purge of §8 stale Residual-2 text, false-invariant
correction to attempt-before-signal, #5079 lease detail). I re-verified each fold
against source and against Codex r4's independent confirmation — all correct.

Codex r4 (PLAN-READY) flagged two non-blocking leftover contradictions from my earlier
edits; both are now fixed in the final r4:
- §3 δ_remove note no longer claims benignity for the failed-removal case (success-path
  only).
- §3 "ack barrier genuinely does" now says the rg_active clear is **attempted** before
  signaling, not "cleared."

No open contradiction remains. The converged recommendation — PLAN-KILL Residual-1's
VIP-gate, DROP Residual-2, LAND a branch-level demotion-order test (SetRGActive
success+failure) + doc-accuracy fix on #6177, FILE Option D (rg_active forwarding fence)
as a separate `/research` issue — is firsthand-sound and survived four hostile rounds
(3 SMR + 4 Codex).

**VERDICT: PLAN-READY** (narrowed). Converged with Codex PLAN-READY (2-of-3; AGY
infra-blocked).
