# Claude SMR hostile plan review — #6751 plan v15.6 (round 19 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.6 exists because of a
process failure on MY side: my v15.5 python fold of the fence transition
silently failed to match the drifted source text, so the fence landed
only in the header and commit message while the normative §5.6 text
kept the rejected v15.4 close-both behavior. Codex r19 caught it. That
failure mode (saying a fold landed when it did not) is exactly what the
converged plan must not carry into implementation, so this review first
verifies the normative text is really there, then attacks the contract
it describes. Codex r20 has not been dispatched yet.

## Normative presence, verified (not trusted from the commit message)

The six-clause contract is now in §5.6 in the plan's own normative
voice: (1) atomic abort-generation counter + fenced flag; (2)
`installConn` returns ADMITTED/REFUSED with refused connections closed
without pending-frame/loop/callback/cold-prime work; (3)
install-before-dispatch for the pending first frame; (4) COMMIT-TIME
generation validation at every stateful frame application; (5)
reset-once ownership with nested-abort re-arm; (6) receiver-local peer
convergence onto the cold-prime edge. I re-read each clause against
the code it cites: sync_conn_read.go:91 (handlers dispatch without
generation checks today), :109/:183 (frames install sessions and
replace bulk state), sync_conn.go:119/130 (pending first frame
processed BEFORE installConn; handleNewConnection unconditionally
starts the receive loop), sync_conn.go:139/551 + sync_bulk.go:65 (the
cold-prime edge and fresh epoch). All accurate.

## Contract attacks attempted

- **(4) commit-time guard vs cost**: the guard re-validates the
  abort-generation at every stateful commit — one atomic load on the
  serialized loop per frame application. The loop already serializes
  all session/bulk mutations (that is why sync_conn_gen.go:381's
  single-threaded safety contract holds), so the guard adds a load,
  not a lock. Cheap.
- **(3) install-before-dispatch reorder**: moving the pending first
  frame behind the admitted install changes ordering guarantees the
  current code may rely on (the pending frame today primes state the
  install then uses). The fold says the pending frame carries the same
  generation guard, so a legacy peer's pending frame during a fence is
  discarded at commit regardless of the reorder — the reorder is a
  defense-in-depth, not the load-bearing clause. Sound.
- **(2) refused-connection lifecycle**: closing a refused connection
  with no loop/callbacks/cold-prime means the peer sees a silent
  close and retries — converging onto the cold-prime edge after the
  fence clears. An old peer knows nothing of the fence and needs
  nothing: the receiver-local verdict enforces the transition
  regardless of peer version. Sound.
- **(5) timeout reset safety**: the wedged-handler case — a handler
  that never confirms detached — is safe only because (4) discards its
  frames at commit. Without (4), the timeout reset would be the r19
  race; with (4), the wedged handler is a dead letter writing to a
  generation that no longer exists. The two clauses are load-bearing
  together; the plan says so.

## Residual nits

1. The AbortFenceTimeout parameter now has a home in the §9 parameter
   summary (AGY r19's nit, folded in v15.5.2) — verified present.
2. The generation guard's frame-side carrier (where the frame's
   generation is read from at commit — the connection's slot
   generation, not a per-frame field) is an implementation detail the
   plan should name explicitly: frames inherit the abort generation of
   the connection slot that delivered them. One line for §5.6 — fold
   as nit.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.6, and the
fold itself is now verified present in the normative text rather than
asserted by the header. The alias discipline has a complete, fenced
abort lifecycle with commit-time validation, a receiver-local peer
convergence rule needing no peer cooperation, and pinned race tests
for each of the five failure modes Codex found. If Codex r20
converges, this is terminal.
