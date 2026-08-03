# Claude SMR hostile plan review — #6751 plan v15.2 (round 15.2, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.2 is my own sixth alias
iteration, and this round AGY and Codex each caught a real systems bug
in the quarantine's interaction with bulk sync (reconcile deletes
quarantined-key sessions as stale; deferred admission races bulk
epochs). This pass re-walks the bulk lifecycle end to end after the
epoch-pinning fold and attacks what the BulkEnd-resolution rule changes.
Codex r16 has not been dispatched yet; this review stands as the SMR
verdict for the round.

## Bulk lifecycle after the fold, re-walked

1. **Decode**: signature-matching upsert → key RECORDED in the current
   bulk's received set (bookkeeping not gated — AGY r15's reconcile
   fix) + entry placed in the quarantine (import gated).
2. **During the bulk**: a sibling canonical base arrives (the normal
   base-first order) → the confirmation checks the current store and
   drops the alias at insertion. No window.
3. **BulkEnd (serialized pass)**: every quarantine entry pinned to this
   epoch resolves BEFORE the ACK and sync-hold release: still-matching
   entries with a sibling in the (now complete) received set
   confirm-drop; everything else admits through the complete normal
   import path (generation checks, timestamp rebasing, bookkeeping,
   coordinator reserve, helper dispatch) in the same pass. The receiver
   therefore never ACKs with a genuine row unresolved — Codex r15's
   scenario-1 (ACK + sync-hold release while Q is missing) is dead,
   and the reconcile-delete race is dead two ways (the key is in the
   received set AND the row is resolved in the same pass).
4. **Cross-epoch**: nothing defers past its own BulkEnd, so Codex r15's
   scenario-2 (E1 frame counted into E2, falsely retaining a stale row
   whose delete was lost) is dead — a lost-base alias resolves at its
   own BulkEnd as timeout-admit (today's degraded behavior for a wire
   loss, bounded to one epoch).
5. **Incremental deltas** (no bulk open): the 5s fallback timer with
   the current store as definitive; all actions ride the serialized
   event loop (timer enqueues a wakeup), matching the
   single-threaded-safety contract at sync_conn_gen.go:381.

## What the epoch rule changes, attacked

- A burst of >4096 signature-matching frames in one bulk: the
  quarantine cap evicts oldest — evicted entries must follow the same
  resolve rule (treat as timeout-admit candidates at BulkEnd, or
  confirm-check at eviction). One-line implementation note for §9:
  eviction resolves as admit-after-confirm-check, never as blind
  admission. (Nit, folded into §9.)
- A bulk that never ends (peer stalls mid-bulk): entries sit in
  quarantine; the fallback timer does not apply to bulk-pinned entries
  — the bulk's own liveness timeout (the existing bulk machinery's
  timeout, which tears down/restarts the bulk) resolves them at
  teardown. Verify at implementation that the bulk-teardown path also
  runs the resolution pass. (Nit, folded into §9.)
- The derive-until-capable transition: a new sender transitions
  mid-stream after the capability frame lands; pre-transition aliases
  are in the wire and hit the receiver quarantine (confirmed-dropped);
  post-transition nothing flows. A permanently lost capability keeps
  legacy behavior — never drops sync. The transition is safe and the
  liveness story is honest (per-tick re-advertisement).

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives. The two nits
above (cap-eviction resolution rule, bulk-teardown resolution pass) are
folded into §9 as implementation notes. The alias discipline is now:
exact omission on the happy path, epoch-definitive quarantine with
safe admission on the legacy window, bookkeeping that never lies to
reconcile, and a delete lifecycle matched to the exporter's real queue
order. Round 16 (re-review of v15.2) is next.
