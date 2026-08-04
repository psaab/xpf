# Claude SMR plan review — round 17 — #6749 armed-state plan v8.12 (08c78677f)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.12 folds are my own prior session's text, so
this pass attacks my own fold text first, source in hand). Attack
surface: the Option-B exposure gate, the paired transport, the
ping-at-top seed, the respawn-on-divergence, the freshness token, the
typed `error_code`, the predecessor-chained reservation, the
PrepareLinkCycleChecked tri-state + typed restore, the
repair-before-rebind, the no-timeout FIFO, the causal map-generation
readiness, and the §1 r16 disposition table.

**Verdict: DEMAND-REVISION** — 3 BLOCKER + 3 MAJOR + 5 MINOR. SMR17-1
and SMR17-2 are independently derived convergences with AGY r17 f1/f2
(both source-verified here); SMR17-3 converges with AGY f4; SMR17-4/5
sharpen AGY f3/f5; SMR17-6 (disposition accuracy on the missing chain
tests) and SMR17-9/11 are SMR-only.

---

## SMR17-1 (BLOCKER) — the exposure gate has no mechanical locus and no re-exposure trigger

The v8.12 fold (plan.md:2936-2961) asserts "a promotion whose pair
write has NOT durably landed is NOT EXPOSED to the dataplane at all …
the dataplane keeps the LAST DURABLE config until `writeTreeMarked`
(db.go:431-461) lands the new pair". I read the retry machinery it
leans on: `persistRetryLoop` (store_persist.go:389-465) is a plain
goroutine that re-writes under `s.mu` with doubling backoff and, on
success, logs and journals — **there is no observer, hook, channel, or
callback to the daemon or the manager anywhere in it**. The plan
names no store API exposing the degraded state to the apply path, no
re-exposure debt, and no owner. Trace the full window:

1. Commit C promotes B (revision R_b); the pair write fails →
   `persistDegraded=true`, background retry scheduled. The gate skips
   B's dataplane apply. The commit reports SUCCESS to the operator.
2. The manager stages nothing (or stages B and suppresses): either
   way `m.pendingCommitRevision > m.acceptedCommitRevision` once the
   pair is read, so the staged-ahead divergence suppression (§5-C
   (iv)) engages and suppresses ALL auxiliary full-publish producers
   — with NO exit, because the only allowed first-publish of B is
   "its own compile leg", which the gate already ran past.
3. The status poll observes the helper at A's revisions. The re-sync
   fires only on HELPER divergence (helper-ahead/behind) — not on a
   Go-side staged-but-gated config. Nothing fires.
4. The retry lands the write minutes later. `persistRetryLoop` logs
   "active config persisted after earlier write failure" and clears
   the flag. **Nobody re-drives the apply.** B reaches the dataplane
   only when an UNRELATED future apply event happens (next commit,
   DHCP/feed re-apply, HA sync, helper restart) — or never.
5. Meanwhile the (v) latch echo gate
   (`m.pendingCommitRevision == m.acceptedCommitRevision`) is frozen
   for the whole window, and on the HA SyncApply path the two nodes'
   dataplanes diverge indefinitely (primary applied B, secondary
   gated).

This is a NEW silent control-plane/dataplane divergence with no
convergence owner — the exact terminal class this issue exists to
kill, reintroduced by the fold that was supposed to close Codex r16
f2. The aliasing is dead, but the cure as written is worse than the
Option-B disease it replaced (Option-B at least APPLIED the config).
Required: (a) an explicit re-exposure owner — the store's
persist-retry success notifies the daemon (post-persist hook or a
polled `PersistDegraded()` getter the daemon's apply scheduler
drains), which drives the NORMAL apply path (applySem +
`ActivePair()` + three-bucket precheck + `StartCompile`) as a
re-exposure apply; (b) the commit result surfaces "dataplane exposure
pending-durable" (posture sentence + edge Warn on the debt); (c) the
§6 inventory gains the hook/getter; (d) a chain test: degraded write
→ commit succeeds → NO dataplane apply → retry lands → re-exposure
apply publishes B → helper observed at B's revisions → suppression
lifts.

## SMR17-2 (BLOCKER) — the freshness token's build-current validation compares only the (config, revision) pair; the same-commit stale-content window stays open

The fold (plan.md:3031-3053) claims Codex r16 f7 CLOSED via "(ii)
VALIDATES at send time under `m.mu` that the built snapshot's
`(config, revision)` still equals the manager's current pair". Codex
r16 f7's window is a SAME-COMMIT reshape: T1 builds older feed-derived
content outside `m.mu`; T2 builds newer same-commit content and
publishes; T1 locks, validates — **the pair is identical by
construction** (same commit revision, same config pointer lineage) —
mints a NEWER `snapshot_token`, and sends STALE content. Every layer
passes: pair-equality validation (trivially), the helper's
strictly-greater token refusal (T1's token is newer), the DUAL
refusal (same commit_revision, fresh publication_rev). The fold as
written does not close f7 for the only class f7 was about; the
disposition row ("CLOSED — … the build-current validation at send
time (T1's stale snapshot abandoned Go-side)") is claimed-but-wrong.
(AGY r17 f2 found the same hole from the lock-ordering side: even
ignoring content, token order is LOCK order, not build order.)
Required: the send-time validation must compare CONTENT — either a
build-sequence stamped at input capture under `m.mu` (cheap;
`latestBuildSeq == thisBuildSeq` at send) or the builder content hash
(snapshotContentHash exists, process_status.go:72-80) recorded per
latest staged/published snapshot and compared. And pin the token's
mint locus honestly: the plan's "stamped at BUILD time inside `m.mu`"
contradicts the build-outside-`m.mu` reality it itself cites
(manager_compile.go:177-228) — the mint belongs in the send
primitive's `m.mu` section (the helper-side refusal is then the
backstop; the Go-side content check is the closer).

## SMR17-3 (BLOCKER) — the mandatory live-MAC re-apply's `ActivePair()` re-read admits an interposed-commit wrong-MAC publish

Source: `reapplyAfterDeferredMAC(cfg *config.Config)` today re-applies
the CAPTURED cfg (daemon_apply_dataplane.go:472-489) — captured under
the same applySem hold the flow still holds, so the captured
`(C1, R1)` pair is coherent. The v8.12 fold (plan.md:2914-2916)
replaces it with "the mandatory live-MAC re-apply
(daemon_apply_dataplane.go:466-489, which calls `ActivePair()` itself
for its second apply)". An operator's C2 commit promotes in the store
(the configstore promotion does NOT need applySem) while C1's flow
sits in MAC programming; the re-apply's `ActivePair()` then returns
`(C2, R2)`, and the re-apply compiles and publishes C2 NON-DEFERRED
(the reservation for this flow was C1's; the re-apply is a
non-deferred second apply) WITHOUT C2's three-bucket RETH precheck —
workers armed on C2's plan with C1's MACs: the armed-before-MAC-safe
class this plan's own completion machinery exists to prevent, held
open until C2's own queued flow acquires applySem and runs its
precheck. (AGY r17 f4 independently.) The DHCP/feed re-read rule was
correct for paths that capture BEFORE acquiring the semaphore
(daemon_feeds.go:26-41, daemon_dhcp.go:85-90); over-generalizing it
to a path whose capture is already under the hold INVERTS the safety
argument. Required: the re-apply passes the pair captured at ITS
apply-flow entry (coherent under the held semaphore — the simplest
and safest), OR re-reads `ActivePair()` and ABANDONS the re-apply to
C2's queued flow when the revision moved (C2's own flow then runs its
precheck). A chain test: C1 deferred live-MAC → operator commits C2
mid-MAC-program → the re-apply publishes C1's pair (or abandons) —
never C2 un-prechecked.

## SMR17-4 (MAJOR) — `map_generation` has no seed rule and no pinned first-proof producer

`publication_rev` seeds from the helper's echo at the Compile-top
ping; `map_generation` (plan.md:1846-1866) does not. A manager
re-init over a SURVIVING helper resets the minted generation to 0
while the helper's `accepted_fabric_map_generation` keeps its old
value — `accepted != current` with no path back (the readiness rule
compares equality) → `FabricSyncStateOK()` false indefinitely → HA
takeover readiness (daemon_ha.go:774-783) permanently false in
exactly the window HA exists for. (This is the sharper form of AGY
r17 f3's fresh-boot attack; the plain fresh-boot case self-heals via
the boot apply's fabric leg — the map commit mints and the full
snapshot carries the generation — but the re-init desync does not.)
Required: seed `map_generation` from the same startup ping echo
(accepted value → minted high-water, mirroring the publication_rev
seed), and pin the first-proof producer in a chain test (boot apply →
map commit mints → snapshot carries → echo matches → proof exists →
readiness true).

## SMR17-5 (MAJOR) — the PENDING-XSK STAGED reservation can leak `compileInFlight=true` forever

The new outcome (plan.md:2804-2808) keeps the reservation OPEN
(inFlight=true) for the deferred-publish leg. If the leg never runs —
the XSK never binds (permanent bind failure under the #5134 retry),
or a daemon abort between staging and bind — the reservation never
Finishes, `m.compileInFlight` stays true, and the (v) latch echo
("skips while `m.compileInFlight`", plan.md:2052-2055) freezes
PERMANENTLY: lost-completion reconciliation dies with it. (AGY r17
f5.) The predecessor chain as written only no-ops a FINISHED
predecessor's Finish; it does not close an UNFINISHED one. Required:
a newer `StartCompile` FINALIZES any open predecessor as OVERLAP (the
chain head moves; the staged leg's later Finish is a no-op by token),
the (v) echo gate keys on the head's state, and a chain test pins it
(staged → abort → new apply → echo reconciles).

## SMR17-6 (MAJOR) — §9 does not contain half the chain tests the fold claims (disposition accuracy)

The fold narrative (plan.md:394-404) and disposition row f15
(plan.md:1133) claim "§9 gains the chain tests (migration
failure/retry + allocator ordering + capability-2 envelope refusal,
Option-B exposure gate, paired transport on every apply path,
ping-first Compile ordering, respawn-on-divergence, freshness-token
stale send, typed error_code classification, token ABA + outcomes +
CLI default, PrepareLinkCycleChecked tri-state + stop_workers
timeout, typed restore + restore debt, repair-before-rebind +
post-settle rule, no-timeout queue + Warn lifecycle, causal
readiness)". I grepped §9 (plan.md:3794-4754) for each: NO test item
mentions migration, allocator, capability-2, exposure gate, paired
transport, ping-first, error_code, ABA, PrepareLinkCycleChecked,
restore debt, or map_generation/causal-readiness. Present only:
respawn-on-divergence (item 13, :4092-4098), a single freshness-token
assertion inside the reservation matrix (:4046-4047),
repair-before-rebind + post-settle (:4649-4693), the no-timeout queue
+ Warn (:4610-4628), and the not-seeded-yet retry routing
(:4055-4057). This is the Codex r16 f1/f15 class — a
claimed-but-wrong disposition row — and these missing tests are the
only enforcement of SMR17-1..5's required fixes. Required: write the
missing items.

## SMR17-7 (MINOR) — the ≤ ~1s late-arrival exposure claim ignores FIFO queueing

The event-fired first-fire attempt BLOCKING-acquires applySem FIFO
(plan.md:2292-2299); behind a legal multi-minute owner hold the
wrong-MAC member forwards for minutes, not "≤ ~1s". The no-priority
decision (AGY r16 f8, accepted at plan.md:2557-2563) already owns
this latency class for the recovery itself — the exposure text must
match: "≤ ~1s + applySem queueing (unbounded worst case; a
partial-path blackhole for flows hashed to the member)". (AGY r17
f7.)

## SMR17-8 (MINOR) — the 60s queued-Warn edge must key on first-queue time, not the acquisition episode

A `RetryLater` release-and-requeue must continue the SAME queue
episode; otherwise sustained `m.mu` contention keeps resetting the
edge and the Warn never fires for a batch waiting hours. (AGY r17
f8.) Pin: the Warn keys on the work item's first-queue timestamp.

## SMR17-9 (MINOR) — PrepareLinkCycleChecked's hold span is unpinned

"the manager validates the token under the SAME `m.mu` acquisition
that begins the quiescence" (plan.md:2473-2478): the quiescence's
ctrl-disable + stop_workers RPCs then run under `m.mu` — a NEW
`m.mu`-across-RPC site while applySem is held (bounded by the 3s
`controlBaseDeadline` each, process_control.go:34-41 — not the 67s
class, but unpinned) — and if the hold extends into the MAC phase,
the per-mutation try-lock claimToken re-reads self-deadlock (Go
`sync.Mutex` is non-reentrant). Pin: try-acquire `m.mu` → validate →
issue the quiescence RPCs under the hold → RELEASE before the MAC
phase → the per-mutation try-lock re-reads resume after release; fold
the bounded hold into the manager-lock-delay budget note.

## SMR17-10 (MINOR) — the ping's deadline class (AGY r17 f6, corrected)

The Compile-top ping is a SMALL request at the 3s
`controlBaseDeadline` (process_control.go:34-41), not the 67-120s
class AGY feared; the spawn path is the pre-existing ensureProcess
behavior (already under `m.mu` today at manager_compile.go:324-325).
Pin the deadline class in the budget text; no design change.

## SMR17-11 (MINOR) — edit hygiene: duplication/splice artifacts contradict the "verified per-edit" claim

Disposition row f1 claims "every v8.12 fold verified per-edit against
the file". The file carries ~10 splice artifacts, one load-bearing:
plan.md:2827-2839 duplicates the OLD boolean-capture outcomes text
AFTER the v8.12 chain text — "PRE-PUBLISH FAILURE (restore the
captured prior latch)" directly contradicts the normative "a restore
applies the HEAD's OWN captured prior" two paragraphs up; an
implementer reading the second paragraph implements the wrong restore
semantics. Also: :2017-2021 (splice drops "CAS refusal with current >
expected" mid-sentence — broken grammar and a dangling rule),
:3555-3558 ("**Control verbs:**" header three times), :2505-2506
(orphan fragment "ever performed against a stale token)."),
:2126-2127 (duplicated section header), :2989-2991, :2336-2337,
:2356-2358, :3028-3029, :3996-3998 (duplicated lines). Fix all; the
:2827-2839 deletion is the mandatory one.

## Attack trace (what else I tried, and why it fails to break v8.12)

1. **The respawn-on-divergence vs AGY r16 f2's runtime shape.** A
   timeout-but-landed B leaves the helper at R_b while Go's accepted
   is R_a; the re-sync re-applies the ACTIVE config — whose revision
   IS R_b (the store promotion landed; only the publish timed out),
   so the DUAL identity leg passes (equal, not strictly-older). Under
   the exposure gate the helper can never hold a revision the store
   lacks (the gate forbids the exposure). The startup respawn covers
   the manager-restart shape. Coherent.
2. **The wire-race false-failure.** T1 validates, mints token N,
   releases `m.mu`, sends; T2 mints N+1 and lands first; T1 is
   refused (strictly-older token). T1's content was current at
   validation — the refusal is a false apply failure for T1's commit,
   owned by the re-sync (latest-wins converges on T2's pair, which
   subsumes). Reachable only via non-daemon overlapping Compiles
   (direct CLI racing a daemon apply — the daemon's own applies are
   applySem-serialized). Safe; worth a one-line posture note (folded
   into SMR17-2's required pin).
3. **The retry-loop ordering (note echo → accepted → divergence).**
   The common lineage-observation routine ordering is pinned at
   plan.md:2006-2010 and §6 item 6; the re-sync's firing check reads
   the post-note state. Sound.
4. **Q1, sixteenth enumeration.** The exposure gate, respawn,
   freshness token, typed errors, chained reservation, tri-state
   quiescence, typed restore, repair-before-rebind, causal readiness
   — none mutate binding slots on their refuse/degrade paths. No new
   `Registered && !Armed && state==none` producer.
5. **The (v) echo during the staged-ahead suppression.** Frozen by
   the pending>accepted gate — correct while a publish is genuinely
   pending; the SMR17-1/17-5 fixes own the two wedge shapes.

## Required for convergence

v8.13: SMR17-1's re-exposure owner + posture + §6 hook + chain test;
SMR17-2's content-current validation + mint-locus pin; SMR17-3's
captured-pair (or revision-gated abandon) re-apply rule; SMR17-4's
seed + first-proof pin; SMR17-5's supersession-closes-predecessor
rule; SMR17-6's missing chain tests; SMR17-7..11 folded. AGY r17
converges on 1/2/3/4/5/7/8 of these; Codex r17 pending at this
writing.

**Verdict: DEMAND-REVISION** (3 BLOCKER + 3 MAJOR + 5 MINOR — the
exposure gate's missing trigger is the round's defining defect: the
fold traded a config-identity alias for a silent divergence with no
owner).
