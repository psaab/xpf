# Claude SMR plan-review — #6371 r7 (confirmation)

Reviewing `docs/research/6371-rgactive-fence/plan.md` @ r7 (commit ce791df15).
SMR was already PLAN-READY at r6 (the substantive design converged there); r7
applies only the five narrow plan-text-consistency fixes Codex r6 listed. Confirmed:

1. §5.2 heading no longer claims it closes persistent modes — now "closes the
   peer-fence one-shot (persistent map-write is detected-not-fixed, §5.4)."
   Consistent with §5.4.
2. Residual acceptance is now explicitly **conditional** (header + §5.4): this
   /research pass opens no issues; acceptance is contingent on the filed follow-up
   issue + named security/HA signer at /engineer time. Honest.
3. §6 quarantine failure is fail-closed (retain replay/poll/watchdog suppression
   gate until all 16 keys are confirmed zeroed) — matches §5.1's contract; the
   "log + proceed" text is gone.
4. "up-to-30 s" is gone; §5.1/§10 frame it as a ≥30 s cold-boot never-seen-peer
   floor, not a strict upper bound.
5. Locator corrected to `manager_ha.go:638-640`.

No new contradiction introduced. The design (boot pin-quarantine +
generation-linearized convergent-retry clear + doc; PLAN-KILL Option D/A′/decouple;
conditionally-deferred map-as-authority cleanup) stands unchanged and complete.

VERDICT: PLAN-READY
