# Claude SMR hostile plan review — #6751 plan v15.8 (round 21 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.8 folds Codex r21's
bounded-admission blocker, and it also CORRECTS my own r21 fold-check,
which asserted the "entire tail as one commit unit inside the fence
check" design that Codex showed is unbounded and self-deadlocking.
This review owns that error explicitly, verifies the stamp-and-enqueue
shape against the actual tail contents, and attacks the intent
revalidation model. Codex r22 has not been dispatched yet.

## Owning the r21 error

My r21 review called clause (2b) "the honest fix (vs revalidating the
generation before every tail step, which would be four guards instead
of one commit unit)". Codex r21 showed the commit unit is the wrong
shape entirely: the tail contains synchronous clock I/O, up to 10,000
journal-entry replays, and `doBulkSync()` writing every owned session
frame synchronously with a fresh 2s deadline each
(sync_conn.go:132/137/141/194, sync_bulk.go:92/133,
sync_protocol.go:59) — unbounded in cardinality and backpressure;
`s.mu` self-deadlocks (`BulkSync → getActiveConn` re-enters it,
sync_conn.go:588); and there IS no global serialized receiver loop to
run it on (each connection launches its own receiveLoop,
sync_conn.go:132, sync_conn_gen.go:381 acknowledges two fabric
loops). "One commit unit inside the fence check" would either deadlock
or block every abort/deadline/quarantine/frame-commit event for the
duration of a bulk. The stamp-and-enqueue shape (bounded atomic unit +
generation-bound intents that revalidate at their own effect-commit)
is the correct one, and it is what v15.8 now says.

## Stamp-and-enqueue, verified against the tail contents

- The atomic unit (slot stamp + intent enqueue, microseconds, no I/O)
  cannot deadlock and cannot starve the arbiter — it does no network
  I/O, no journal replay, no BulkSync.
- Each intent (loop launch, clock sync, callbacks, cold-prime)
  executes OUTSIDE the arbiter on the normal async paths and
  revalidates its bound generation and slot at its own effect-commit
  point — the same commit-time guard as clause (4), so the machinery
  is one guard used everywhere, not four bespoke ones (answering my
  r21 objection: it is not "four guards", it is one guard applied at
  each effect site, which is where it always had to live given there
  is no global loop).
- A stale intent (generation advanced, slot detached, or fence set)
  is cancelled and its completion treated as stale — so an abort
  landing between verdict and tail can never let a stale tail take
  effect, which was the original TOCTOU.
- The two pinned tests (blocked-I/O, large-bulk with 10k journal
  entries) prove AbortFenceTimeout and the atomic unit stay bounded
  under both — the exact scenarios that would have wedged the r21
  design.

## Attacks attempted

- **Intent reordering**: two intents from different admissions racing
  — each carries its own generation/slot binding, so an older intent's
  effects are discarded at its effect-commit if a newer admission
  superseded the slot. No cross-intent contamination.
- **Cold-prime intent superseded by a new abort**: the cold-prime
  intent revalidates at its BulkSync effect-commit; a newer abort
  generation cancels it, and the newer abort's own recovery drives a
  fresh cold-prime. No duplicate or stale prime.
- **The arbiter itself**: the fence is in the connection registry
  (which exists and is already the arbitration point for installs) —
  not a new global loop, so the "no global serialized receiver loop"
  reality is consistent with the rest of the contract.
- **§11 stale fabric-gate text**: fixed (the design has had no
  disposition gate since v15; non-fabric identity-NPTv6 rows
  quarantine and timeout-admit by design, not by gate accident).

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.8. The
admission path is now bounded by construction (stamp + enqueue),
every effect site revalidates with the same commit-time generation
guard, and the tail's unbounded work stays on background goroutines
where it belongs. If Codex r22 converges, this is terminal.
