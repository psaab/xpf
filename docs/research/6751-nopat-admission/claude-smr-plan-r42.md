# Claude SMR hostile plan review — #6751 plan v15.30 (round 41 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.30 folds Codex r41's
four blockers and AGY r41's two nits. Three of the four are the
now-familiar contradiction class (new rule written here, old rule
still standing there); the fourth (private-RG gate not code-real)
is a scope honesty question. Codex r42 and AGY r42 have not been
dispatched yet.

## B1 fold (emission gate + capability scoping), attacked

Attack 1 — the emission gate's failure semantics: the capability
frame is a checked direct write (sync_protocol.go:49-82's class)
BEFORE the connection is published for general selection; a failed
write fails the connection AND its cold-prime. Is failing the
cold-prime on a capability-write failure too strong? The
alternative (publish the connection with unknown capability) puts
the new peer's first window into framing-only/disposition-only —
which is the SAFE degradation, not a failure mode. So failing the
connection is stricter than necessary, but it is fail-CLOSED in
the correct direction (no authority is ever assumed), and the
reconnect path retries immediately. The stricter choice is
defensible; the safe-degradation alternative is noted as the
implementation's acceptable variant only if the gate's failure
rate proves non-trivial — but the plan's default (fail closed) is
the right starting posture.
Attack 2 — the EPOCH-DEFINITIVE scoping: the retained rules now
say the epoch pass is lineage-definitive only for
capability-advertising windows and disposition-only otherwise,
with genuine rows importing before the ACK in both classes. The
never-ACK-unresolved rule survives in both classes (disposition
completes before ACK). Composition is coherent.

## B2 fold (derived interval everywhere), verified

The stale `2.5 × keepalive_timeout` parameterization is replaced
by `2 × syncReadDeadline + 5s` at every site (the r38-era text
and the r41 summary). No remaining site asserts a 7.5s bound.

## B3 fold (fence lifecycle event + precedence + distinct effect), attacked

Attack 3 — the seventh event type's composition with the v15.14
tag machinery: the fence-cycle expiry mints its
(abortGeneration, lifecycleSequence) tag at admission like every
other event, with cancellation on re-arm. The precedence rule
(fence engagement atomically gates the readiness release; the
readiness commit unit re-validates fence state) closes the async
disconnect-notification race (sync_conn.go:569-570) — the
connected-only callback that races fence engagement is suppressed
at its own commit gate. And the DISTINCT release effect (no
syncBulkPrimed, no bulk-sync-complete record, no debt discharge)
prevents the degraded release from masquerading as a completed
prime — the debt machinery's integrity is preserved because the
fence's release is explicitly not a prime completion.

## B4 fold (private-RG gate introduced), attacked

Attack 4 — is introducing a new production gate in a research plan
for an SNAT issue proportionate? The gate is the SAME class as the
classic RETH VRRP sync hold (sync-before-takeover), which the
cluster already accepts as the failover-correctness posture; a
private-RG cluster without it has the identical preempt-before-sync
exposure the classic gate exists to prevent. The alternative
(stop claiming it) would leave the fence's hold-class enumeration
dishonest. Introduction is the honest and proportionate choice,
with the behavior change (failover delay for private-RG clusters
until sync-ready or the degraded terminal) explicitly priced and
§9-pinned (vip_readiness_test.go's current permissive expectation
gets the new refusal test alongside it).

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.30 that
I can construct. The remaining implementation-level notes: the
emission gate's failure-rate posture (fail-closed default, with
the noted variant); the seventh event's cancellation primitive
naming at implementation. Both forks remain settled; the
option-(a) core is untouched. If Codex r42 and AGY r42 converge,
this is terminal.
