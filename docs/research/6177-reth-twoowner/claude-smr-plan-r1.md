# Claude SMR — hostile plan review r1 — #6177

Reviewing `docs/research/6177-reth-twoowner/plan.md` r1 (@ 9b3b8fa866c3).
Posture: hostile. Goal: break the PLAN-KILL recommendation or find an unsound claim.

## Findings

### SMR-1 (MAJOR) — the "benign" conclusion leans on an unmeasured `δ_remove`, but is presented as if the magnitude matters
The plan says `δ_remove ≈ tens-of-µs to sub-ms` with no measurement (violates
`runnable-repro-before-measurement-claim`). A hostile reviewer will seize on the
unmeasured number. BUT the actual PLAN-KILL does not depend on `δ_remove` being
small — it depends on the harm being masked (fabric-redirect + rg_active + GARP +
#5482) **regardless** of window width. The plan must decouple the two: state
explicitly that the benign conclusion holds for ANY `δ_remove` (even the ~1 s
failed-removal case), so the unmeasured magnitude is not load-bearing. As written,
§3 invites a "you didn't measure it" rejection of an argument that does not actually
need the measurement. **Fix:** add a sentence to §4/§7 making the
magnitude-independence explicit; downgrade the µs/ms figures to "illustrative, not
load-bearing."

### SMR-2 (MAJOR) — the `security` label is not addressed head-on
#6177 is labeled `bug, security`. The plan concludes "benign" but never states the
**security threat model** and why it is empty. A hostile reviewer reads "benign"
as hand-waving past a security label. Required: an explicit threat-model paragraph —
the window is (a) not attacker-triggerable (it occurs only on an operator/weight
-driven planned failover, not on demand), (b) bounded to a transient duplicate-ARP,
(c) the dual-active **forwarding** hazard that WOULD be a security issue is already
closed by #5640's rg_active-clear gate, which this plan retains. Without this, the
PLAN-KILL is exposed on the exact axis the label calls out.

### SMR-3 (MEDIUM) — fabric-redirect transit coverage is asserted as a guarantee; it is best-effort
§3 says transit "is fabric-redirected to R." Firsthand: `tryPrepareUserspaceRGDemotion`
is a **best-effort** bounded (5 s) prep that logs `Warn` and proceeds on failure
(daemon_ha_userspace_readiness.go:23-27). So on a prep failure the transit-coverage
leg is absent and the residual exposure is a brief packet loss (TCP-recoverable), not
a guaranteed zero-loss redirect. The plan overstates the guarantee. **Fix:** qualify
as "best-effort, ordered-before removal" and note the fallback harm (brief loss,
TCP-recoverable) so the benign claim survives even when prep fails.

### SMR-4 (MEDIUM) — Option A hybrid ("reorder on success, priority-0-first on failure") is not rebutted
A sharp reviewer will propose: attempt removeVIPs first; on success send priority-0
(closes the slow window); on failure send priority-0 anyway (no worse than today).
The plan rebuts A but not this hybrid. **Fix:** rebut it — you cannot know the
removal outcome without attempting it, and attempting-first IS the reorder, so the
hybrid adds `δ_remove` latency to EVERY normal failover for zero benefit on the
failed case. Net-negative, same as A.

### SMR-5 (MEDIUM) — Residual-2 is dead-code hardening; the YAGNI counter is not weighed
The plan lands Residual-2 (delete-by-key identity) but it is UNREACHABLE today
(initiator serializes per-RG). User memory favors simple/direct solutions and warns
against scope creep. A hostile reviewer will ask why we harden an unreachable path.
The plan should explicitly weigh YAGNI vs the case FOR landing it (flagged by the
#5640 review; cheap; symmetric with the residual-3 tests that would otherwise test a
half-hardened barrier) and take a defensible position rather than landing it by
default. Acceptable outcome either way, but the tradeoff must be on the page.

### SMR-6 (MINOR) — "no timing change ⇒ but still run make test-failover" needs the rationale nailed
§8/§9 correctly require `make test-failover` (the file set touches pkg/daemon HA),
but should state plainly that this is a **regression gate**, not a measurement of the
window (which is unchanged), so a reviewer does not expect the smoke to "prove the
window closed" — nothing closes it; the smoke proves nothing regressed.

### SMR-7 (MINOR) — the retained #5640 property should be stated as an invariant to protect
The plan keeps #5640's rg_active-clear-before-ack ordering (daemon_ha.go:367→389).
Since the whole point is "the ack barrier's genuine value is the forwarding gate, not
the VIP gate," the plan should name this as an invariant the /engineer PR must NOT
disturb while editing the barrier for Residual-2 (so a refactor doesn't accidentally
move signalFailoverActuated ahead of SetRGActive(false)).

## Verdict

**PLAN-NEEDS-REVISION.** The core analysis (ACK-is-not-the-lever, window-benign,
both-levers-net-negative, land #2/#3) is sound and firsthand-verified — I could not
break the PLAN-KILL recommendation. But the doc as written is exposed on the
`security` label (SMR-2), overstates fabric coverage (SMR-3), leaves the measurement
magnitude looking load-bearing when it is not (SMR-1), and does not rebut the obvious
Option-A hybrid (SMR-4). Revise r2 with SMR-1..SMR-5 addressed (SMR-6/7 are polish).
Direction is PLAN-READY-narrowed once those land.
