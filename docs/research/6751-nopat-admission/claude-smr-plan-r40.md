# Claude SMR hostile plan review — #6751 plan v15.28 (round 39 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.28 folds AGY r39's
nit and Codex r39's two blockers + major + minor + two nits. The
two blockers are the first in several rounds that are about HONESTY
rather than mechanism: the plan's legacy-proof claims exceeded what
the wire can prove. This pass checks the honesty folds are as
careful as the mechanism folds, and owns a factual error of my own.
Codex r40 and AGY r40 have not been dispatched yet.

## B1 fold (capability-gated windows), attacked

The v15.27 observed-prime claim conflated "a bulk window happened"
with "a both-empty-driven authoritative prime completed" — and
Codex's evidence is damning in the best way: the no-heartbeat-ACK
cohort PREDATES the #5085 lossless-bulk fix (heartbeat ACK
63ab422cf, lossless bulk 52fc4a513), so the exact peer that
motivated mode (ii) is the peer whose window is historically
lossy. The fold's rule — a non-capability-advertising peer's
window is FRAMING-ONLY (installs frames per today's interop;
NEVER clears lineage, NEVER drives the definitive alias pass,
NEVER releases the lineage hold) — is the only honest rule, and
it composes with the already-ratified mixed-version cell (suspects
keep their marks, session-lifetime bound).
Attack 1 — does framing-only regress the legacy standby's failover
correctness? No: the receiver's ACK and VRRP hold-release toward
legacy peers is today's behavior unchanged; the plan's new
machinery (lineage marks, definitive pass) simply declines to
trust what it cannot verify. The pre-#5085 exposure is inherited
and now explicitly documented, not worsened and not pretended
away.
Attack 2 — the capability advertisement's own mixed-version
bootstrap: a new receiver advertising to an old sender gets the
old sender's framing-only windows (quarantine + provisional
admission per the ratified cell); the definitive pass waits for a
capable peer or the session lifetime. Consistent.

## B2 fold (retained-C0 honesty + interval cap), attacked

Codex r39 blocker 2 caught a factual error in MY v15.27 fold: I
cited sync_protocol.go:59 as a read deadline — it is a two-second
WRITE deadline. Owned in the plan text. The corrected statement is
the honest one: for the retained-C0 trace (close notification
lost, no-ACK peer, no read-side detector BY DESIGN), NOTHING
plan-bounded kills C0 — the terminal is the readiness-timeout
degraded release with the debt RETAINED, discharged by any
subsequent genuine both-empty transition (OS/TCP failure, peer
restart, a later real disconnect). The quiet interval is capped
by the readiness timeout (the 7.5s > 5s ordering inconsistency
Codex also caught, daemon.go:1148).
Attack 3 — is "debt retained forever against a zombie C0" a
liveness regression? The debt is daemon-lifetime and discharges on
any genuine both-empty; the VRRP hold is RELEASED at the timeout
(availability preserved); the only cost is the standby keeps
owing a prime it may not get until the zombie dies — exactly the
degraded posture the timeout exists to provide. Bounded, honest,
and strictly better than a false proof that would reconcile
against a non-definitive snapshot.

## m4/n5/n6 folds, verified

The named admission mutex (engaged-check, stamp issuance, child
registration, release-side advance, disengage ordering —
advance-BEFORE-disengage, distinct from the sync.go:301/322
locks) is the linearization point the r38 accept-proof rule
needed; the exact accept-after-sweep-start → resume-after-release
trace is pinned; the "CURRENT store as definitive" literal is
gone (disposition-definitive only, never lineage-definitive).
The §6 two-field reconciliation (folded as AGY r39's nit during
the round) removes the last section-to-section contradiction Codex
named load-bearing.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.28 that
I can construct. The plan's legacy claims now say exactly what the
wire can prove and no more. Both forks remain settled; the
option-(a) core is untouched through four independent
confirmations. If Codex r40 and AGY r40 converge, this is
terminal.
