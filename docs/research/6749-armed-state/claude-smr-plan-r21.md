# Claude SMR plan review — round 21 — #6749 armed-state plan v8.16 (0ef942686)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.16 folds are MY text, written this session, so
this pass attacks my own fold text first, source in hand). Attack
surface: the closeout-follow set, the flow-level pair rule, the
fence-at-exposure + settlement ingress, the last-exposed state
machine + uniform base, the completion ledger, the node-local stamp,
the re-specified freshness ordering, the verb quiescence gate +
failed-UP ownership, the tombstone, the UNQUALIFIED GO-LOCAL rule,
the drain-failure policy, the marker census, the identity/telemetry
separation.

**Verdict: DEMAND-REVISION** — 1 BLOCKER + 2 MAJOR + 4 MINOR. The
BLOCKER is self-found in my own v8.16 fold while writing the round's
review prompts (the unqualified GO-LOCAL rule publishes staged
configs early — exactly the defect class the rule was meant to
repair, recreated by deleting the qualifier without a replacement
discriminator). The rest are containment pins.

---

## SMR21-1 (BLOCKER) — the unqualified GO-LOCAL rule publishes staged configs early

My v8.16 fold deleted the "no apply in flight" qualifier (AGY r20
f2's circular deadlock) and made the GO-LOCAL re-sync fire on
`ActivePair().revision > m.acceptedCommitRevision` PERIOD. Trace
the PENDING-XSK STAGED window (manager_compile.go:272-313): B is
compiled and STAGED (the config is promoted (active pair = B),
`m.pendingCommitRevision = B`, `m.acceptedCommitRevision = A`) with
`DeferWorkers=true` because the XSK cannot bind yet; the
deferred-publish leg (the `OnXSKBound` registration,
maps_sync.go:451-456's shape) owns B's publish, firing when the
bind becomes possible. The unqualified rule fires on the next poll
tick (active(B) > accepted(A)) and the drain drives a FULL apply of
B — publishing B EARLY, defeating the defer: either the bind still
fails (the whole point of the staging) and the drain's apply fails
and retries at backoff — a polling-driven retry loop with
side-effect churn (the Compile's early phases re-run on every
retry, against a bind that cannot succeed yet) — or the drain
races the deferred leg's own publish (duplicate applies). The
qualifier's deletion was correct (the circular deadlock was real),
but the replacement discriminator is missing: the staged window has
a LIVE owner — the `OnXSKBound` registration for the pending pair.
The correct firing rule: `active > accepted` AND **no live
deferred-publish registration exists for the active pair** — the
staged window is owned by its registration (no deadlock: a leaked
registration (the staged leg died) has NO live registration, so
the rule fires and the drain's StartCompile OVERLAP-finalizes the
orphan and drives the apply — the AGY r20 f2 closure survives
intact). §9 (d) gains the staged-window assertion (the rule does
NOT fire while the registration lives; it DOES fire once the
registration completes or is lost).

## SMR21-2 (MAJOR) — the verb quiescence gate's clear points must cover the post-program window

The v8.16 gate refuses operator binding/queue verbs while
`m.linkCycleActive`. Its purpose is narrow: prevent a
verb-driven worker re-spawn during the batch's DOWN→MAC→UP
program (the live-XSK-during-MAC-cycle class). It must therefore
HOLD from the quiescence through the batch's program phase (or the
batch's abandonment) and CLEAR at the restore — NOT persist
through the restore debt's retries: once the restore's rebind has
run (workers re-bound, whatever the ctrl state), the current
batch's transaction is over and the gate's coverage is done — a
later MAC attempt re-quiesces and re-sets the gate. The
restore-debt cases (ctrl error with workers bound; a rebind
failure with the restore debt retrying) are POST-window: the
operator's verb reconcile is then idempotent and
helper-serialized (and equivalent to the batch's own restore), so
holding the gate there only locks the operator out of legitimate
maintenance for an unbounded window. Pin: the gate sets on
`Valid`, clears at the transaction's restore completion (or
abandon), and the restore debt's retries do NOT hold it.

## SMR21-3 (MINOR) — the uniform base's edge cases are correct by the empty/no-op semantics

The boot case: last-exposed is EMPTY at boot — the first commit's
invalidation composes empty→new, a no-op (no sessions exist at
boot — correct). The replay case (the restore's first-exposure of
an already-exposed A): last-exposed == A, so the composition is a
no-op — and the helper's session table is empty (fresh helper), so
there is nothing to delete — correct (the completion ledger's
tails run anyway (the session clear is a harmless no-op; the
markers are idempotent)). And the no-gate invariant: `oldActive ==
last-exposed` whenever nothing was ever gated (every accepted
apply advances both), so the uniform base changes NOTHING on the
common path. Stated so the reviewers don't have to re-derive.

## SMR21-4 (MAJOR) — the PENDING-XSK deferred leg's stamp is coherent by construction (pin) and the #5134 clone's forced stamp is reconciled

The deferred-publish leg (a different goroutine) does NOT re-stamp:
the staged snapshot carries `DeferWorkers` baked in at STAGING
time from T1's own node (the node-local stamp happens once, at
staging), so the deferred publish's send carries T1's intent
regardless of the then-current head. Pin that (the stored token
covers it). The #5134 clone's forcible `DeferWorkers=false`
(manager_worker_arm_5134.go:50-64) is a DIFFERENT verb class — the
worker-arm debt's retry, whose whole purpose is arming the
ACCEPTED config's workers after its MAC settles (the epoch's
completion mechanism, authorized by the debt's settlement); it is
suppressed while `pending > accepted` (the staged-ahead rule), so
it can only fire for the ACCEPTED config's own arm retry, where
`false` is the correct stamp. The node-local rule governs
Compiles; the #5134 republish is not a Compile. Coherent — pinned
so the reviewers don't re-derive.

## SMR21-5 (MINOR) — the fence's out-of-loop raiser is gen-ordered by construction (pin)

Today the session-gen fence is raised by `configApplyLoop`
(sync_conn_gen.go:398-432); the v8.16 drain raises it at observed
acceptance (out-of-loop). Pin the discipline: the drain raises the
fence to the settlement item's gen via the SAME gen-ordered fence
API (monotonic — a raise to an older gen is a no-op), and the
ordered loop's later high-water advance happens at the settlement
— drain-first by construction, never a race (the high-water
advance requires the fence already at the same gen).

## SMR21-6 (MINOR) — the tombstone is runtime-scoped; the config re-adds at the next apply (pin)

A tombstone for a fabric the CONFIG still lists: the helper drops
the fabric state on the tombstone, and the next full apply re-adds
it (the config's fabric set is authoritative) — the runtime clear
is operational state, the config is intent; the oscillation
(clear-then-re-add) is the same posture as any runtime teardown
vs config intent, stated.

## SMR21-7 (MINOR) — the closeout-follow set's own failure is the commit's synchronous error (pin)

A management-auth mutation failing under the gate: the closeout is
inside the commit's synchronous flow — its failure is the commit's
error, surfaced to the operator (no debt needed — the closeout is
not deferred, so it needs no retry owner).

## Attack trace (what else I tried, and why it fails to break v8.16)

1. **The second leg's abort vs the first leg's published
   workerless snapshot.** The abort leaves A's deferred snapshot
   published (workerless) until B's queued flow — which is queued
   directly behind applySem (bounded), and B's own precheck stamps
   B's `DeferWorkers` from B's classification, replacing the latch
   wholesale. The window is bounded and the latch ownership is
   explicit. Coherent.
2. **The settlement landing twice.** The repost is stale-checked
   (a newer gen landed → discarded); the in-order advance skips a
   duplicate (the gen is monotonic — a second advance to the same
   gen is a no-op). Coherent.
3. **Q1, twentieth enumeration.** The closeout set, the fence,
   the ledger, the node stamp, the verb gate, the tombstone — none
   mutate binding slots on their refuse/degrade paths. No new
   `Registered && !Armed && state==none` producer.

## Required for convergence

v8.17: SMR21-1's live-registration discriminator (+ the §9 staged-
window assertion); SMR21-2's gate clear points; SMR21-3..7 folded.
Codex r21 and AGY r21 pending at this writing — their verdicts may
add to this list.

**Verdict: DEMAND-REVISION** (1 BLOCKER + 2 MAJOR + 4 MINOR —
contained; the v8.16 surface otherwise held under my attacks).
