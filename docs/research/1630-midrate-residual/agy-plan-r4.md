# AGY adversarial plan-review — #1630 cause-2 — r4

Job: `adversarial-review-mpqdcfge-8levl3` — succeeded; full result.
Verdict: **PLAN-READY (with amendments).** AGY read the CORRECT tree
this round (worktree `0e5bb3812`) and verified the r3 falsification.

## AGY r4 verdict and amendments (all folded into v5)

AGY confirms the measurement-first convergence is "honest, scientifically
disciplined, and correct" and that all three shaper-internal mechanisms
are statically falsified under the test config. Two required amendments —
IDENTICAL to Codex r4's findings 1 and 3 — both folded into v5:

1. **Ingress offered-load blind spot.** §5 must track per-class ingress
   arrived bytes and verify `offered > rate×wall` before drawing shaper
   conclusions, or an RX/conntrack/traffic-gen cap below shape will be
   mis-attributed to a shaper bug. → **Folded: §5.0 counter 0
   (offered_bytes), gated FIRST in §5.2 and §6.1.**
2. **Operational scope gating.** A cause-1+#1643-only PR must NOT close
   #1630 and must scope-note "low-rate classes only"; #1630 stays open
   until cause-2 lands and all four solo clear ≥95%. → **Folded: §10-R5
   + §11-Q5.**
3. **H-TCP L2 normalization** (`goodput × 1514/1460` vs `drain_sent`) to
   settle H-TCP on iperf3. → **Folded: §5.1 counter 8 (L2-normalized).**

## Convergence note

AGY r4 PLAN-READY-with-amendments + Codex r4 PLAN-NEEDS-MAJOR (the SAME
three amendments as fixable gaps) + Claude SMR r4 = converged once the
amendments land (v5). The amendments are additive instrumentation +
scope-discipline, not a mechanism change — the measurement-first core is
agreed by all three.
