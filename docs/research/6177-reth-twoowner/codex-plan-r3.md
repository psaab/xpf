# Codex — hostile plan review r3 — #6177 (medium effort, ~66.6k tokens)

Raw: `codex-plan-r3-raw.txt`. **VERDICT: PLAN-NEEDS-REVISION** — the high-level
recommendation HOLDS (kill Residual-1 VIP-gate; drop Residual-2; land branch-level
success/failure ordering test; correct docs; file Option D separately), but r3 had
precision/consistency errors. Required corrections (all folded into r4):

1. **F1 overstated.** The all-3-adverts-lost ack ordering applies ONLY to the sub-case
   where post-ack `ForceRGMaster` wins the race against R's independently-expiring
   masterDownTimer (R's timer is within its master-down horizon, up to ~97 ms; it is NOT
   O's ≥500 ms post-resign safety timer). The ack cannot suppress R's own timer.
2. **The "~2 s bound" is FALSE.** `reconcileRGStateLoop` is a retry CADENCE, not a
   recovery BOUND — each pass can re-fail `SetRGActive` (daemon_ha.go:842). Transient
   failure clears ~≤2 s; PERSISTENT control-socket failure ⇒ dual-forward UNBOUNDED.
3. **Failed fabric-prep treated too casually.** Best-effort prep can fail ⇒ masking
   absent; state as an unquantified transient risk, not "brief TCP-recoverable loss."
4. **Filing Option D still right**, but note the #5079 lease is ~15/30 s (abort→~30 s
   blackhole) and the follow-up must weigh transient-vs-persistent failure; do not use a
   false 2 s bound to prejudge.
5. **Dropping Residual-2 sound**, but §8 had STALE Residual-2 impl/`DisarmIdentityChecked`
   text contradicting §§6/7/9 — removed. The "#5640 ack ⇒ rg_active cleared" invariant is
   FALSE (current code only ATTEMPTS the clear before signaling) — §8 corrected.

r4 folds all five. Adjudication: all valid, all folded firsthand-verified against source.
