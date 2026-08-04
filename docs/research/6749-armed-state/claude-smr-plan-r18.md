# Claude SMR plan review — round 18 — #6749 armed-state plan v8.13 (92fb722e1)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.13 folds are MY text, written this session, so
this pass attacks my own fold text first, source in hand). Attack
surface: the exposure debt + accepted/exposed split, the build
sequence, the paired-transport sweep, the boot-apply debt, the
error_code census, the recorded-outcomes chain, the merged checked
quiescence, the executable restore debt, the honest late-arrival and
FIFO texts, the single-transaction map_generation, and the §1 r17
disposition table.

**Verdict: DEMAND-REVISION** — 2 BLOCKER + 3 MAJOR + 5 MINOR. SMR18-1
is SMR-only (the auxiliary-producer hybrid — my fold gated the
daemon's apply but not the manager's own publishers); SMR18-2/3/4/5
converge with AGY r18 f4/f5/f1/f3 (three of which I had independently
derived before reading AGY's output — the refs-capture, the replay
order, and the post-quiescence contradiction are all in MY OWN v8.13
text).

---

## SMR18-1 (BLOCKER) — the exposure gate does not gate the manager's OWN publishers; the gate window admits an A-config/B-FIB hybrid

My v8.13 fold gates the DAEMON's apply
(`applyConfigLocked` consults `PersistDegraded()` and skips). But the
commit's OTHER tails still run — including the FRR reload, which
moves the RIB to B's routes — and the manager's auxiliary full-publish
producers are NOT gated: the route overlay
(manager_overlay.go:188-250) clones `m.lastSnapshot` (A's snapshot,
stamped with A's revisions) and refreshes the FIB section from the
CURRENT RIB — B's routes. The clone carries A's `commit_revision`
(stamped at A's compile), so the helper's DUAL refusal passes it
(publication fresh, commit equal) — and the divergence suppression
does not fire because B was never staged manager-side (the gate
skipped the compile, so `m.pendingCommitRevision == m.acceptedCommitRevision`
stays at A). The helper therefore runs A's policy/NAT with B's FIB
for the whole gate window — the exact same-content-wrong-lineage
hybrid class the adoption gate and the request fence exist to kill,
re-introduced through the overlay back door by MY OWN fold. (The
scheduler republish (manager_compile.go:575-621) and the #5134 clone
(manager_worker_arm_5134.go:57-92) have the same shape.) Bounded by
the exposure drain, but unowned and unstated — and my §9 chain test
(a) asserts "the helper never sees B" during the gate, which is
FALSE for B's routes. Required: the daemon's gated commit sets a
manager-visible suppression flag (`m.exposureGateActive`) alongside
the staged-ahead rule; ALL auxiliary full-publish producers (route
overlay, scheduler republish, #5134 retry, SyncFabricState) check it
and hold; the exposure drain clears it after the re-exposure apply's
observed acceptance; FRR itself follows the commit (control plane —
visible, converges at the drain); §9 (a) asserts the suppression and
the drain's clearing.

## SMR18-2 (BLOCKER) — the input-capture "snapshots the refs" is unimplementable for lazily-read inputs; the validation must be content-based

My v8.13 fold mints `buildSeq` at an input-capture section that
"snapshots … the feed/overlay state refs". Storing a REFERENCE does
not freeze anything: the build runs outside `m.mu` and dereferences
the refs lazily, and a concurrent feed/overlay mutation between
capture and dereference silently changes the content the buildSeq
supposedly orders (and is a data race outright). (AGY r18 f4
independently.) The correct form drops input enumeration entirely:
(i) the input-capture section under `m.mu` mints `buildSeq` (==
`snapshot_token` — the wire ordering and the helper-side backstop)
and records NOTHING else; (ii) the send-time validation under `m.mu`
compares the built snapshot's SEMANTIC HASH (builder.go:156-178 —
computed at build end, deterministic content, covering feed/overlay/
scheduler/NAT state because they are all in the snapshot) against
`m.latestBuiltHash` (recorded at every build's end under `m.mu`): a
stale build's hash differs from the latest and is abandoned —
identical-content rebuilds pass (dedup semantics preserved). And the
abandon's REPORT is pinned: a build abandoned for staleness returns
SUPERSEDED-BY-NEWER-BUILD, which is SUCCESS-equivalent for the apply
flow (the newer build carries the same or a newer pair — the
commit's dataplane leg is fulfilled by it); if the NEWER build's own
send fails, the re-sync debt owns the outcome (never a silent loss).

## SMR18-3 (MAJOR) — the recorded-outcomes replay order is unspecified

My fold says the head's Finish "applies its own outcome AND REPLAYS
completed predecessors' recorded outcomes in chain order". Outcome
application is NON-COMMUTATIVE: replaying a predecessor's
PRE-PUBLISH FAILURE (restore the predecessor's captured prior) AFTER
the head's ACCEPTED would clobber the accepted intent with a
historical flag pair. (AGY r18 f5.) Pin the fold: replay recorded
predecessor outcomes FIRST in chain order (oldest → newest), then
apply the head's own outcome LAST — the head's outcome is always the
terminal word (T1-ACCEPTED-recorded + T2-head-PRE-PUBLISH-FAILURE →
replay T1's intent, then T2's restore of T2's OWN prior … and T2's
prior IS T1's `{true,true}` — so the terminal state restores T1's
inFlight?! No: T2's restore applies T2's captured prior as the
RESTORE, and then the fold must answer whether the replay or the
restore is terminal. The consistent rule: the head's RESTORE applies
the head's prior, then any recorded ACCEPTED/tail intents replay on
top — i.e. restores first (chronological), intents after
(chronological), inFlight=false whenever every node has a recorded
terminal outcome. The §6 entry gains the 7×7 fold matrix.)

## SMR18-4 (MAJOR) — the post-quiescence try-lock skip contradicts the standing try-lock-skip text

My v8.13 fold added "a try-lock skip AFTER the quiescence has begun
is NOT RetryLater — it routes through the restore finalizer", but the
standing debt-execution text (v8.11, AGY r15 f6 = SMR r15 SMR15-4,
plan.md:2833+) still says a contended per-mutation claimToken re-read
"skips the mutation to the next backoff tick with the work item
still claimed — no stall, no monopoly". Read literally together, an
implementer can skip-and-keep-stopped with workers already quiesced
— the whole dataplane down for a backoff tick. (AGY r18 f1.)
Resolution: the standing rule's scope is pinned PRE-QUIESCENCE
(before `PrepareLinkCycleChecked` returns `Valid`); after `Valid`,
a contended re-read CANNOT skip — it routes through the restore
finalizer (restore, release, re-Claim). The standing text gains the
scope sentence; §9 (g) asserts both arms.

## SMR18-5 (MAJOR) — peer-MAC resolution inside the `m.mu` transaction must read the neighbor CACHE, never a fresh netlink dump

The single-transaction map_generation builds the payload in the same
`m.mu` section that samples and mints; `FabricSnapshot`'s peer
address/MAC resolution (daemon_ha_fabric.go:484-490) is part of the
payload. A fresh netlink neighbor-table dump inside `m.mu` is
blocking OS I/O of unbounded latency under the manager's hottest
lock. (AGY r18 f3.) The manager already maintains the neighbor
cache (manager_neighbor.go:129-140's regen machinery): the
resolution reads the CACHED entries under `m.mu` (free); a cache
MISS resolves to the existing unresolved-posture (the payload
carries the unresolved marker the guard already handles) and the
cache's own regen drives the next attempt — never a netlink dump
under the lock. §5-C (i) and §6 gain the sentence.

## SMR18-6 (MINOR) — the exposure debt's wake is the debt's OWN schedule; the latency budget is pinned

"the daemon's apply scheduler POLLS `PersistDegraded()` on its wake
cadence" — the debt's recording must SCHEDULE a 1s wake (the debt
carries its own nextAt), not rely on ambient scheduler wakes (a
gated commit with no other debts would never wake). The total
commit→exposure latency is the store's retry backoff (1s initial,
doubling to a 60s ceiling — verified
`ensurePersistRetryLoopLocked`, store_commit.go:615-628) + the
debt's 1s wake + the apply — stated in the budget text; polling
cannot accelerate the store's own retry (AGY r18 f8) and does not
need to (the bound is the store's maxBackoff, honest).

## SMR18-7 (MINOR) — two consumer-contract pins (error_code Go signature; the exposure warning's delivery surface)

1. The typed-response survival needs the Go contract (AGY r18 f2/f9):
   `requestDetailedLocked` returns the DECODED response AND a typed
   error — callers branch on `resp.error_code` BEFORE the
   `err != nil` early-return; the zero-struct form
   (process_control.go:163-169) is amended so a typed refusal
   returns the parsed body, never the zero struct.
2. The "dataplane exposure pending-durable" warning rides the
   COMMIT's result surface (the apply RPC's existing warning list
   returned to the CLI — named explicitly, not a new
   `ControlResponse.warnings` field; the commit's CLI prints it).
   §6 names the surface; the show-command visibility is the
   exposure debt's presence in `show` (AGY r18 f6).

## SMR18-8 (MINOR) — the late-arrival blackhole bound is the member's OWN backoff clock

The fold says "the debt's next attempt (5s initial backoff)" — but a
member with prior failures sits at the 60s floor, and its factory-
MAC blackhole lasts until THAT attempt (plus FIFO queueing). (AGY
r18 f7.) The honest bound: `member's current backoff + FIFO queueing
+ the transaction`, with the no-priority note. Text corrected.

## SMR18-9 (MINOR) — the respawn replay and the fabric debt's retry composition

The restore debt's respawn FOLLOWED BY the paired full apply: the
replay runs the FULL revised `applyConfigLocked` (a fresh
`StartCompile(false)` reservation + the three-bucket precheck — NOT
the CLI's default-reservation path); the ctrl=0 window while the
restore debt retries is fail-closed and Warn-visible (stated). The
fabric sync debt's retry re-uses the recorded
`(map_generation, payload)` — a fresh sample mints a NEW generation
and SUPERSEDES the debt (never a re-mint moving the target).

## SMR18-10 (MINOR) — the gate locus is the getter alone; the skip always (re)records the debt; the peer's lag is visible

The gate's locus is `Store.PersistDegraded()` consulted inside
`applyConfigLocked` BEFORE compiling (the promotion-return-flag
variant is deleted — one mechanism); the flag is store-global but
self-consistent (a successful commit-path write clears it
synchronously — a later durable commit is never gated by an older
failure). EVERY skip (re)records the exposure debt — the re-sync and
restore paths through `applyConfigLocked` inherit it idempotently
(single-flight). The HA peer's reported applied state keys to the
exposed pair, and the primary-side lag is VISIBLE in `show chassis
cluster` output during the window (never silent).

## Attack trace (what else I tried, and why it fails to break v8.13)

1. **The (v) latch echo during the gate window.** The gate skips
   BEFORE compiling, so B is never staged manager-side:
   `m.pendingCommitRevision == m.acceptedCommitRevision` stays at A,
   the (v) echo keeps reconciling A's latch, and the adoption gate
   compares A == A. No freeze, no false adoption.
2. **The exposure debt vs the re-sync debt double coverage.** Both
   can cover the same eventual apply; both are latest-wins and
   single-flight; the drain is idempotent (observed-acceptance
   clears each). Redundant, not harmful.
3. **A durable B gated by an older A failure.** The commit-path
   successful write clears `persistDegraded` synchronously
   (store_persist.go:389-400's exit condition requires the commit
   paths to clear it) — B's own apply is never skipped by A's
   corpse.
4. **Q1, seventeenth enumeration.** The gate, the build sequence,
   the chain, the checked quiescence, the restore debt, the
   map_generation transaction — none mutate binding slots on their
   refuse/degrade paths. No new `Registered && !Armed && state==none`
   producer.
5. **The helper-side token backstop vs two managers.** A stale
   same-host manager process could mint conflicting buildSeqs —
   the helper's per-incarnation strictly-greater refusal orders
   them; the surviving manager's re-sync converges. Safe.

## Required for convergence

v8.14: SMR18-1's suppression flag + drain clearing + §9 assertion;
SMR18-2's content-hash validation + the superseded report; SMR18-3's
predecessors-first-head-last fold + the §6 matrix; SMR18-4's
pre/post-quiescence scope pin; SMR18-5's cache-read resolution;
SMR18-6..10 folded. AGY r18 converges on 2/3/4/5/7/8; Codex r18
pending at this writing.

**Verdict: DEMAND-REVISION** (2 BLOCKER + 3 MAJOR + 5 MINOR — the
defining defect is SMR18-1: my own gate gated the daemon and forgot
the manager's publishers; the overlay publishes B's FIB in A's clone
through the whole window).
