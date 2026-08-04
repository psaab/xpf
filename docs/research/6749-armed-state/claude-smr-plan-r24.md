# Claude SMR plan review — round 24 — #6749 armed-state plan v8.19 (8d1911b5f)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.19 folds are MY text, written this session,
so this pass attacks my own fold text first, source in hand). Attack
surface: the restart-suppression marker, the deferred-arm timer, the
completion listener, the OVERLAP clear + publisher liveness, the
stage-timeout pin, the fence read discipline, the send wiring, §9's
new assertions, and Q1 (24th enumeration).

**Verdict: DEMAND-REVISION** — 1 BLOCKER + 1 MAJOR + 4 MINOR + 3
NIT. The BLOCKER is self-found in my own v8.19 listener fold (the
notice's tails have no pair-currency gate — and the obvious
abort-only fix LEAKS, traced below). AGY r24 (1 BLOCKER + 2 MAJOR
+ 1 MINOR + 1 NIT) independently found the same spine; Codex
remains infra-blocked (usage limit, reset Aug 10 — third
documented attempt this session).

---

## SMR24-1 (BLOCKER) — the completion notice's tails have no pair-currency gate, and the abort-only fix LEAKS

Trace (self-found in my own Delta-3 fold; = AGY r24 f1,
independently derived): B is accepted via the status-loop
catch-up (`beginFirstExposure(B)` advances `m.lastExposedPair`
to B atomically, manager-side) and posts the completion notice.
Before the daemon scheduler drains it, C promotes and applies
under `applySem` (`commitAndApply`) — C's `beginFirstExposure(C)`
returns prior = B (B is last-exposed), C's wrapper composes
B→C and completes. The stale notice for B then drains and runs
B's tails with NO currency check (my v8.19 text specifies
neither `applySem` nor a re-read): the invalidation composes
A→B and DELETES sessions C re-permits (A-permitted, B-revoked,
C-permitted — live, authorized traffic); the applied stamp
overwrites C's stamp with B's revision. CONFIRMED against the
fold text — the cursor's exactly-once authority governs
double-execution, not staleness.

The obvious fix — abort the notice if its pair is no longer
current — is INSUFFICIENT (traced): C's own tails compose B→C,
so a session A-permitted, B-revoked, C-revoked is covered by
NOBODY (not B-permitted, so absent from the B→C delta; and B's
tails were aborted) — an A-era session outlives its revocation.
The correct fix is the plan's OWN uniform-base rule applied to
the notice path: the drain acquires `applySem`, re-reads the
CURRENT pair at drain time, and composes prior → CURRENT
(A→C covers A\B\C-revoked exactly, keeps A\B∩C-permitted,
and C's B→C covers B\C — the union is complete with no
over-deletion); the applied stamp and the peer push are
currency-gated (skip when the notice's pair is no longer
current — C's own stamp/push already ran or runs on its own
tails); a superseded notice's cursor entry is marked
SUPERSEDED (terminal — the composition was covered by the
newer pair's chain), never left pending.

## SMR24-2 (MAJOR) — the cursor's check-and-advance has no pinned atomic

My fold says the Compile-leg wrapper and the listener "both
consult and advance the same cursor record" with
`completionState` as "the SINGLE exactly-once authority"
(= AGY r24 f2). The transports are per-acceptance unique (a
Compile-leg acceptance yields an `ApplyResult`; a catch-up
acceptance yields a notice — never both for one acceptance),
so the double-transport case cannot occur; the residual race
is PHASE-level (the wrapper advancing phase k of cursor X
while the listener drains a notice touching cursor X's phase
k+1). Pin: the cursor record lives manager-side; EVERY
read-modify-write of `{phaseCursor, completionState}` goes
through one manager method under `m.mu` (the daemon wrapper's
phase completions call it across the package boundary; the
listener likewise) — the check-and-advance is then atomic by
construction, and the §9 (a) assertion exercises the
interleaving.

## SMR24-3 (MINOR) — the post-clear value of `m.lastSnapshot` is unpinned (= AGY r24 f3, downgraded on the nil-guard census)

My fold says the OVERLAP finalization "drops `m.lastSnapshot`'s
staged reference" without naming the resulting value. Pin: the
post-clear value is NIL — the staged object is the only
reference (revert-to-published is impossible: staging
OVERWRITES `m.lastSnapshot` and the manager retains no second
reference; adding one is new state, rejected). AGY f3's panic
scenario does not survive the census: EVERY auxiliary producer
nil-guards under the same `m.mu` (syncSnapshotLocked
process_status.go:11; overlay manager_overlay.go:129/:134 (the
`:187` dereference is reachable only past those guards);
neighbor manager_neighbor.go:52/:84/:202/:259; HA
manager_ha.go:159/:209/:524/:630; status
manager_status.go:111; applied_nat_view.go:85 — VERIFIED).
The real cost is a TRANSIENT publish gap: with
`m.lastSnapshot == nil`, the route overlay / scheduler /
neighbor republish legs skip until the GO-LOCAL re-drive
rebuilds (≤ the 60s backoff floor) — stated, plus the census
as the canary (a NEW producer without a nil-guard fails the
build-time canary test).

## SMR24-4 (MINOR) — the notice channel's overflow drops tails (= AGY r24 f4)

The enqueue-after-unlock is non-blocking; a full buffer drops
the notice and the tails never run. Pin: the notice is an
OPTIMIZATION over a sweep — the daemon's apply scheduler runs
a periodic pending-cursor sweep (the cursor registry is
queryable daemon-side) at the standing debt cadence, so a
dropped notice delays the tails to the sweep interval rather
than losing them; the enqueue failure itself records a Warn
edge (never silent).

## SMR24-5 (MINOR) — the suppression marker's recording locus wastes one drain cycle per restart-only sync

My fold records the marker in "the drain's guard-refusal" —
but the FIRST refusal happens in `syncAndApply`'s guard
(daemon_apply_commit.go:381-402, VERIFIED), which records
nothing: the GO-LOCAL rule fires once, the drain compiles and
refuses, and only then does the marker land. Pin: the
recording lives in the SHARED guard-refusal path (one routine
called by both the sync-receive guard and the drain's guard),
so the marker lands on the FIRST refusal and the drain never
fires even once for R.

## SMR24-6 (MINOR) — my own r23 disposition row's "§9 (a)/(d)" citation is claimed-but-wrong

The SMR23-3 row cites §9 (a)/(d) for the listener — but the
v8.19 §9 edits added the listener NO assertion (only (d)'s
restart-suppression and (f)'s publisher leg landed). Add the
listener assertions to §9 (a): the stale-notice composition
(prior → CURRENT at drain time, never A→B over C), the
currency-gated stamp/push, the SUPERSEDED terminal marking,
and the sweep fallback (= AGY r24 f5's demand).

## SMR24-7 (NIT) — the stage-timeout/bind race serialization

The five-minute scheduler entry's fire and the `OnXSKBound`
registration's completion race at the boundary (bind succeeds
at 4m59s, timeout at 5m00s): both serialize under `m.mu` (the
scheduler fires into the same manager loop), and the fire
re-checks the registration's liveness under the same lock
(a completed registration cancels the entry atomically —
pinned, not racy).

## SMR24-8 (NIT) — the `isExposed` closure's lock-order rule

The closure reads `DurableRevision()` (`s.mu`) under
`QueueConfig`'s `writeMu` — pin the order writeMu → `s.mu` as
the ONLY direction (the reconciler reads `ActivePair()` under
`s.mu` and RELEASES before `QueueConfig`; no `s.mu` holder may
call into the sync layer's send path — the census is the
reconciler + the loop's begin/end, which take no `s.mu`).

## SMR24-9 (NIT) — the held-push-forever budget note

A drain that never completes (the persistent-storage-failure
class) leaves the gated push held forever — the peer never
receives the gated config. That is a CONSEQUENCE of an
already-budgeted class (the peer's state never leads the
primary's exposed state — correct by invariant), stated in §8.

## Attack trace (what else I tried, and why it fails to break v8.19)

1. **The restart-suppression GC.** A suppressed R followed by a
   guard-PASSING R′: R′ applies, `acceptedCommitRevision`
   advances past R, R's entry is GC'd as moot. A suppressed R
   followed by restart-only R′: a second entry — bounded by the
   active-revision window. A daemon restart over a restart-only
   ACTIVE config: the boot path applies it (the correct owner);
   an operator downgrade before the restart: the boot applies
   the (no-longer-restart-only) active config — no reliance on
   the rule at boot at all. Coherent.
2. **The deferred-arm timer's crash edge.** A daemon crash
   between `Load`'s record and the post-phase-4 arm: the on-disk
   confirm envelope is untouched by the deferred arm (the record
   is in-memory), so the NEXT boot's `Load` recovers the window
   again — idempotent by construction (the recovery path is the
   same read). The arm on a consumed window (a boot leg that
   resolves the confirm) is a no-op — pinned.
3. **The expired-deadline semantics.** An already-expired
   deadline fires immediately on the arm: the executor promotes
   the rollback target and re-applies — REPLACING the
   just-boot-applied config. Intended: the confirm window
   expired, the rollback is owed; the ordering (after the boot
   apply, under `applySem`) is the whole point. Coherent.
4. **The OVERLAP-clear vs the fence.** The cleared staged object
   was never published, so no fence/token state references it;
   the re-drive's rebuild mints a new build token (buildSeq
   monotonic) — the fence admits it. Coherent.
5. **Q1, twenty-fourth enumeration.** The v8.19 mechanics
   (restartSuppressed, the deferred arm, the completion notice,
   the staged-reference clear, the liveness branch, the fence
   read discipline, the send closures) mutate NO binding slots
   on any refuse/degrade path. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
6. **The r23 disposition table.** Every row re-derived against
   the file: all citations verified EXCEPT the SMR23-3 row's
   "§9 (a)/(d)" (SMR24-6).

## Required for convergence

v8.20: SMR24-1's currency-gated notice drain (applySem +
prior→CURRENT composition + SUPERSEDED terminal); SMR24-2's
m.mu check-and-advance pin; SMR24-3's NIL pin + canary census;
SMR24-4's sweep; SMR24-5's shared recording locus; SMR24-6's
§9 (a) listener assertions; SMR24-7..9 folded. AGY r24's
f1-f5 map onto SMR24-1/2/3/4/6 respectively.

**Verdict: DEMAND-REVISION** (1 BLOCKER + 1 MAJOR + 4 MINOR +
3 NIT — all pins on the v8.19 mechanics, nothing architectural;
the rest of the v8.19 surface held).
