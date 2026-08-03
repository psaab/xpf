# Claude SMR hostile plan review — #6751 plan v15.7 (round 20 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.7 folds Codex r20's two
lifecycle blockers (the wedged-slot timeout that misses cold-prime, and
the admission TOCTOU between verdict and setup tail). Both are the
class of bug where a state machine's transition is 95% specified and
the missing 5% is where the wedge lives. This pass verifies the two
folds against the actual registry/callback machinery and attacks their
edges. Codex r21 has not been dispatched yet.

## Clause (5) deterministic detach, verified

Codex r20 blocker 1a's mechanism chain is accurate: slots clear only
from `handleDisconnect` (sync_conn.go:480), and the empty→connected
edge that arms `needColdPrime` requires BOTH slots nil
(sync_conn.go:248/278). The v15.7 clause (5) now
generation-invalidates AND logically detaches both slots before the
fence releases — including on AbortFenceTimeout — so the registry
reaches both-nil deterministically on every transition, and the next
admission always sees the empty→connected edge. Late callbacks from
the detached slots are treated as stale: their slot generation is
older than the reset's, so clause (4)'s commit-time guard discards
their frames at commit. The two failure modes (a wedged slot keeping
the registry nonempty; a late callback mutating post-reset state) both
die — one by the detach, one by the guard. The pinned test drives a
timeout with a still-registered slot and asserts the both-nil outcome
plus cold-prime arm.

## Clause (2b) atomic admission, verified

The admission TOCTOU Codex found is real: `installConn` returns and
the tail (receive-loop launch, clock sync, lifecycle callbacks,
cold-prime) runs as separate steps (sync_conn.go:130), so an abort
could land between verdict and tail and leave a connection whose
verdict is stale but whose setup executes anyway. The v15.7 clause
(2b) makes the ADMITTED verdict and its ENTIRE setup tail ONE
serialized step under the fence check: on the already-serialized
receiver loop, admission and tail are a single commit unit — either
the connection comes up fully with the current generation, or it
closes before any tail step runs. The pinned test drives an abort
between verdict and loop/callback/cold-prime and asserts the
all-or-nothing outcome. This is the honest fix (vs revalidating the
generation before every tail step, which would be four guards instead
of one commit unit).

## Attacks attempted

- **Slot detach vs in-flight handler**: a handler currently
  mid-dispatch when the detach lands — its frames are commit-discarded
  by clause (4) (stale slot generation), and its slot entry is
  logically removed regardless of what its socket does afterward. The
  handler becomes a dead letter; the socket close completes whenever
  it completes. No wedged-slot residue.
- **Back-to-back aborts during the tail**: the second abort inside an
  active fence is a no-op unless it carries a newer generation (clause
  (5) nested semantics), and the atomic tail is inside the fence check,
  so an abort cannot interleave with the tail by construction — there
  is no "second abort during the tail" state.
- **The cold-prime edge after a timeout detach**: the detach is
  generation-invalidated, so the edge that fires is the GENUINE
  empty→connected edge (not a re-used stale slot) — `BulkSync`
  allocates a fresh epoch (sync_bulk.go:65). Verified the epoch is
  fresh, not inherited.
- **m2 residue**: the piggyback alternative is now removed everywhere
  (the earlier fold's replace silently failed on drifted text — the
  second silent-fold failure this saga; the fix was re-applied with a
  verified edit and grep-confirmed). The transport is the dedicated
  periodic ticker alone in §5.6, §6, and §11.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.7. The
abort lifecycle is now fully closed: fenced admission with atomic
tails, commit-time generation validation at every mutation point,
deterministic detach on every transition including timeouts, reset-once
ownership with nested-abort semantics, and receiver-local peer
convergence onto a fresh-epoch cold-prime. If Codex r21 converges,
this is terminal.
