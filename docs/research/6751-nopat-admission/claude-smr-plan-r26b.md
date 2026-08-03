# Claude SMR hostile plan review — #6751 plan v15.13 (round 25 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.13 folds Codex r25's two
blockers, and they converge with AGY r25's earlier equal-generation
finding into one honest principle: a lifecycle ordering discipline is
only as strong as the point where its tags are minted. This pass
verifies the tuple-tag and epoch-envelope designs against the send
queue and lifecycle callback machinery, and attacks their edges.
Codex r26 has not been dispatched yet.

## Tuple tags (abortGeneration, lifecycleSequence), verified

Codex r25's assignment analysis is right and it is the same bug AGY
r25 found independently: the abort advances to G, the disconnect binds
G, the replacement's admission reads the same G — and if the connect
commits `true@G` first, the delayed disconnect still passes `G >= G`
and overwrites with `false@G`. My r12-era "fresh generation per event"
claim did not specify WHERE the freshness comes from, and both
reviewers found the gap. The v15.13 rule mints tags ONLY at the
transition's commit point (admission onto the lifecycle queue) as a
tuple of the lineage's abort generation plus a per-generation
lifecycle sequence — so (a) no callback can forge ahead (it never
mints, it carries), (b) the connect-vs-disconnect ordering is
determined by queue admission order, not callback scheduling, and (c)
a stale tag fails the strict-inequality CAS regardless of when the
callback runs. The strict-inequality rule for value-flipping mutations
stays as defense-in-depth. Non-monotonic VALUES (true→false→true)
remain free because the tags, not the values, advance — verified
against the legitimate flip sequences.

## Effects inside the commit unit, verified

Codex r25's second half (a stale bulk-received callback can race after
a newer lifecycle transition and still stop the readiness timer,
release the VRRP sync hold, and mark sync ready, daemon_ha_sync.go:90)
is the correct objection to per-field flag CAS: the flag write is
linearizable, but the EFFECTS are not protected by it. The v15.13
rule executes the safety-critical effects (timer stop, VRRP sync-hold
release, sync-ready marking) only INSIDE the committed lifecycle event
— the same commit unit that writes the flag performs the hold release
— so (i) a newer transition can never interleave between the flag
write and the release, and (ii) a failed/stale event admission
suppresses ALL associated effects atomically (nothing it would have
done happens). §9 pins the stale bulk-received callback vs
ReleaseSyncHold test explicitly.

## Epoch envelopes at enqueue, verified

Codex r25's queued-behind-A scenario is the correct objection to
dequeue-time binding: A dequeued under N waits through the abort and
is correctly discarded, but B (enqueued under N, dequeued under N+1)
binds N+1 at dequeue even though its content predates the abort — and
a generation-zero B unconditionally deletes newer state
(sync_conn_gen.go:263). The v15.13 envelope stamps at ENQUEUE, so B's
envelope says N and the sendLoop discards it whenever the send would
cross an epoch boundary — the binding is content-origin, not
dequeue-time. And the epoch-advance rule is now honest about the
backstop: cold-prime arms only on a both-slots-empty transition
(sync_conn.go:235/278) and routine single-fabric flips explicitly do
NOT re-bulk (sync_conn.go:178/208), so the compared epoch advances
ONLY on transitions that schedule an authoritative prime — a routine
no-prime flip keeps sending deltas (the delta stream itself is the
authority there), and whenever the epoch does advance and deltas are
discarded, the scheduled prime is the guaranteed re-conveyance. The
prime's own frames share the envelope discipline
(flushDeleteJournal sync_conn_write.go:135 and the bulk write path
sync_bulk.go:95), so a prime cannot overtake a newer queued delta.

## Attacks attempted

- Does the lifecycleSequence wrap or collide across abort generations?
  The sequence is per-generation (resets at each abort generation
  advance), and the CAS compares tuples lexicographically (generation
  first, then sequence) — no cross-generation collision.
- Does the envelope discipline slow the delta stream? One stamp at
  enqueue (a load, not a lock) and one compare at send — the stream's
  per-frame `writeMu` (sync_bulk.go:95) already dominates; no new
  contention point.
- Does the epoch-not-advancing-on-routine-flips rule re-open the
  generation-zero unconditional-delete window on those flips? The
  gen-0 delete on a no-prime flip is the documented UNORDERED class
  (bounded by the next authoritative bulk) — the flip does not create
  a false authority, it preserves the stream's continuity, and the
  unordered-class bounding applies unchanged. Honest.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.13. The
lifecycle ordering is minted at queue admission (strictly ordered,
unforgeable), the safety-critical effects live inside the commit unit
(stale events are effect-free by construction), and the send guard
binds content origin at enqueue with an honest authority rule for
epoch advancement. If Codex r26 converges, this is terminal.
