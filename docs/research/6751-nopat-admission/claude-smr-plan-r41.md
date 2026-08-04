# Claude SMR hostile plan review — #6751 plan v15.29 (round 40 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.29 folds Codex r40's
two blockers + major + minor (AGY r40 converged PLAN-READY with
zero findings). The two blockers are about the capability
machinery's own integrity: authority binding per window, and the
degraded terminal's code-reality. Codex r41 and AGY r41 have not
been dispatched yet.

## B1 fold (per-window authority + ordered send + disposition-only), attacked

The v15.28 framing-only rule was contradicted by the retained
r15-era resolution rules (resolve at every BulkEnd; P1 at every
completed BulkEnd), and the bootstrap made the contradiction
reachable on new↔new (ticker advertisement at 5-10s, cold-prime
immediate at sync_conn.go:130).
Attack 1 — the ordered send contract's robustness: handshake →
capability frame → any data frame. The contract is a sender-side
ordering on the same connection, so the receiver's capability
state transitions from UNKNOWN (non-capable, safe) to capable
BEFORE the first window's BulkStart — and per-window binding
records the class AT BulkStart, so a window begun pre-advertisement
is framing-only forever (correct) and a window begun
post-advertisement is authoritative (correct). No mid-window
ambiguity remains. The one residual: a capability frame LOST in
transit (the send is reliable on the sync connection — the same
lossless direct-write class as clock sync — so loss means the
connection itself is broken, which is the existing disconnect
path). Sound.
Attack 2 — disposition-only vs the never-ACK-unresolved rule: the
provisional admission keeps the never-ACK-unresolved behavior
(the quarantine disposition completes in the same serialized pass
before the ACK); the LINEAGE holds (suspect marks) are not part of
the ACK's gating — they persist across the ACK as marks awaiting
a definitive snapshot. The ACK semantics (today's interop) and
the lineage semantics (new) no longer share a terminal — which is
exactly what M3 formalizes.
Attack 3 — fresh-capable-prime on first-learn: forcing a prime
when capability is learned could storm under flap; the debt
coalesces (one prime for all held suspects) and the prime-REQUEST
machinery already bounds the cycle. Bounded.

## B2 fold (derived interval + fence-owned disconnected-eligible terminal), attacked

Codex's three code facts are all verified in the fold: the ≈20s
detector (sync.go:90, sync_conn_read.go:33), the connected-only 5s
readiness timer with its no-release-without-reconnect regression
(session_sync_readiness_test.go:33), and the classic RETH VRRP 30s
hold (manager.go:351). The derived interval (the peer's actual
bound, not 2.5×keepalive) and the fence-owned disconnected-eligible
terminal with each hold class named as outer bounds are the honest
design.
Attack 4 — does a fence-owned release at ≈20s+ delay failover
beyond acceptable bounds? The degraded release is the LAST resort;
the normal path (a successful both-empty prime) completes orders
of magnitude faster, and the classic 30s VRRP hold is the outer
bound the operator already accepts. The alternative (a false
proof) is strictly worse. Honest and priced.

## M3 fold (two debt terminals), verified

Delivery debt (BulkEnd-ACK) and alias-proof debt (capable
definitive snapshot or row close) are separate; a legacy
both-empty discharges only the former. The composition is
coherent and matches the framing-only rule.

## m4 fold (the §9 regression), verified

The retained-C0 degraded-terminal regression is pinned with all
four assertions (no plan-bounded kill; disconnected-eligible
terminal; hold-class outer bounds; separate debt terminals).

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.29 that
I can construct. The capability machinery now has the same
wire-honesty as the rest of the plan: authority is bound per
window, ordered before data, and degraded safely at every
bootstrap state. Both forks remain settled; the option-(a) core
is untouched. If Codex r41 and AGY r41 converge, this is
terminal.
