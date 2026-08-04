# Claude SMR plan review — round 23 — #6749 armed-state plan v8.18 (0e4604ac4)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.18 folds are a prior session's text carrying
MY lineage, so this pass attacks the fold text first, source in hand).
Attack surface: the invariant edges (timer arming, the drain's guard),
the closeout A-live model, beginFirstExposure's cross-layer transport,
the OVERLAP cancellation + OPEN check, the deferred-publish registry,
fence-on-accepted + the seed field, the owner-token fence registry,
the settlement lifecycle, the restore-authorized quiesce +
RecordLinkObservation, the tombstone persistence, the structured send
transaction, §9's re-specification, and Q1 (23rd enumeration).

**Verdict: DEMAND-REVISION** — 2 BLOCKER + 2 MAJOR + 3 MINOR + 1 NIT.
Both BLOCKERs are v8.18-introduced or v8.18-incomplete interactions
verified against source: the restart-only GO-LOCAL loop (Delta 1 ×
Delta 5) and the publisher that never checks the liveness the plan
pins on a different leg. AGY r23 (3 BLOCKER + 2 MAJOR + 1 MINOR)
independently found the same spine; Codex is infra-blocked this round
(usage limit, reset Aug 10 — two documented dispatch attempts).

---

## SMR23-1 (BLOCKER) — the restart-only guard × GO-LOCAL rule is an unbounded compile-and-refuse loop

Trace (verified against source): an HA peer syncs a topology- or
identity-changing config. `syncAndApply` holds `applySem`, promotes
the peer config via `configstore.SyncApply`, and then refuses the
live apply in the guard (daemon_apply_commit.go:381-402 —
`clusterTopologyCommitPreflight(d.cluster != nil, compiled)` /
`clusterIdentityCommitPreflight(d.cluster, compiled)` — VERIFIED at
:375-402). The active pair advances to R; nothing is applied; no
Compile runs; **nothing advances `m.acceptedCommitRevision`** (it
advances only on observed acceptance), and nothing records WHY.

v8.18's GO-LOCAL rule (plan.md:4119-4155) fires on
`ActivePair().revision > m.acceptedCommitRevision` AND no live
registration — both true on the very next poll tick. The drain
acquires `applySem`, re-reads the active config, and the v8.18
revised `applyConfigLocked` evaluates the SAME guard and refuses.
Now the two exit shapes both loop forever:

- If the guard-refusal returns an ERROR (the `syncAndApply` shape,
  `return nil, terr`): the re-sync debt persists and retries at
  backoff to the 60s floor — permanently.
- If it returns success-without-acceptance (a "deliberate skip"
  decision): the debt's clear condition ("only on the observed
  acceptance of the re-apply's `publication_rev` AND the active
  config's `commit_revision` in a successful status",
  plan.md:4156-4159) can NEVER fire — the config is never applied,
  so no acceptance is ever observed — the debt retries forever at
  the 60s floor.

Each retry COMPILES the config (the guard needs the compiled form),
takes `applySem`, and emits the error/Warn — an unbounded
compile-and-refuse loop for what is a NORMAL, expected state (a
restart-required config awaiting an operator restart). Delta 1's
"it defers to the operator restart exactly as the SyncApply path
does" is FALSE as written: the SyncApply path refuses ONCE per
sync-receive; the drain re-fires forever. Every #5840/#6192
topology/identity sync puts the standby into this loop BY DESIGN.
(AGY r23 f1, independently derived; cadence correction — the loop
runs at the debt's 60s backoff floor, not the 1s poll: the poll
re-records an already-recorded debt idempotently.)

**Fix (pin):** the guard-refusal in the drain records a
revision-keyed RESTART-SUPPRESSION marker (terminal
"restart-required" state, Warn-once with the reason): the GO-LOCAL
rule's firing condition gains `AND ActivePair().revision ∉
restartSuppressed`, the re-sync debt CLEARS into that terminal
marker (not into acceptance), and the marker dies only with the
process (the boot path owns the apply after the operator restart).
A newer promotion R′ > R re-arms the rule for R′ only.

## SMR23-2 (MAJOR) — the timer-arms-post-boot-apply edge names no mechanism, and §9 (b) does not test it

The invariant's startup edge (plan.md:4540-4558) states "the
rollback executor's timer is armed only AFTER the boot apply
completes" as fact. Verified against source it is a CHANGE, not a
fact: `d.store.SetRollbackExecutor(d.executeConfirmedRollback)`
runs at daemon init BEFORE the startup phases
(daemon_run.go:130-136 — VERIFIED), and `Load`'s confirm-window
recovery re-arms the timer UNCONDITIONALLY
(`s.confirmTimer = time.AfterFunc(remaining, ...)`,
store_persist.go:231-253 — VERIFIED). The executor acquires
`applySem`, which is FREE during the startup phases (the phases
run sequentially; nothing holds the semaphore across them), so a
recovered near-expiry timer can fire between naming
(daemon_run_naming.go:42-90) and manager construction/dataplane
apply (daemon_run_bringup.go:161-208/:418-520) — the B-derived
naming with A-derived dataplane the plan itself describes. The
plan must NAME the mechanism and its expiry semantics:

- (a) move the registration post-phase-4 — but then `Load`'s
  re-arm has no executor: what does `fireConfirmTimer` do with no
  registered executor (drop? defer? the confirm window may be the
  ONLY rollback authority — a dropped expiry is a silent
  confirmed-commit that never rolls back);
- (b) gate `executeConfirmedRollback`'s fire on a boot-complete
  flag — the window can expire DURING boot: the rollback must be
  QUEUED (run ordered after the boot apply), never dropped, and
  the queue's target is the store state the boot apply just
  applied — the executor's promote+apply under `applySem` is then
  an ordinary serialized DECISION (coherent, but state it);
- (c) defer `Load`'s re-arm itself: `Load` records the recovered
  window WITHOUT arming, and a post-boot-apply daemon call arms
  it (the store gains a `ArmRecoveredConfirmTimer()` the daemon
  invokes after phase 4 — the store-layer change is small and
  keeps the executor registration where it is).

Pick one; state the expiry-during-boot semantics either way.
AND: the disposition-table row for Codex f2 cites "§9 (b)" for
this edge — §9 (b) (plan.md:7267-7308) asserts only that no
interposition is reachable from any promotion path; it has NO
assertion for the timer-arming edge (AGY r23 f6's second half,
verified). The citation is claimed-but-wrong; the test must
assert the chosen mechanism (a recovered timer whose deadline
falls mid-startup does NOT fire before the boot apply completes;
a queued expiry fires after, in order).

## SMR23-3 (MAJOR) — the status-loop catch-up acceptance has no completion-tail owner

v8.18's own registry names `syncSnapshotLocked` "the ACTUAL
publisher" whose catch-up "publishes → completes" (plan.md:1015,
2140). That publish IS an acceptance leg (it advances
`m.publishedSnapshot` and `markAppliedSnapshotLocked` —
VERIFIED process_status.go:2221-2226, and the main publish path
below it) — and in the plan's model it must run
`beginFirstExposure` (it is a first exposure of B). But Delta 3's
transport is the `ApplyResult`, which exists ONLY on the Compile
leg: the catch-up runs inside the manager's background status
loop with no `ApplyConfig` frame, no `ApplyResult`, and no daemon
wrapper (AGY r23 f3, independently verified). The plan says
nothing about who runs the daemon completion tails for THIS leg
(session invalidation prior→B, the peer push, the applied stamp):
no completion listener, no cursor-polling drain, no manager→daemon
notification (the `OnXSKBound` channel shape, maps_sync.go:451-456,
exists as precedent). Codex r22 f5 REQUIRED this ("the status
loop's leg has no ApplyResult to ride — the cursor must be
queryable by the daemon wrapper afterward"); the v8.18 fold pins
the Compile leg and leaves this leg's tails ownerless.

**Fix (pin):** name the owner — a daemon-side completion listener
(the daemon polls the installed completion cursor after status
applications, or the manager posts a completion notice on the
existing bounded daemon channel) that runs the phased tails for
cursor entries whose `completionState` is incomplete; state which
tails are no-ops on the helper-restart shape (empty base ⇒
invalidation no-op; the peer push and applied stamp are NOT
no-ops for HA) and that the listener is idempotent against the
Compile-leg wrapper (the cursor's `completionState` is the single
authority — a tail runs exactly once regardless of which side
observes it first).

## SMR23-4 (BLOCKER) — the actual publisher never checks the liveness the plan pins on the OnXSKBound leg

Delta 4 puts the token-liveness check on "the deferred leg"
(`OnXSKBound`) and the OPEN check on "the send primitive"
(plan.md:4395-4413). But Delta 5 names `syncSnapshotLocked` the
ACTUAL publisher — and its publish conditions (VERIFIED
process_status.go:2206-2275: nil guards; `publishedSnapshot >=
generation` skip; the helper-ahead catch-up; the XSK-liveness
defer + same-plan exception; the plan-change helper restart; the
content-hash dedup) NEVER consult the registry token's state.
Trace: T1 stages (pending-XSK); same-pair T2 starts and
OVERLAP-finalizes T1 (the registration → cancelled); T2 FAILS
before staging its own object, so `m.lastSnapshot` STILL
references T1's staged object; the XSK becomes bindable; the next
status poll's `syncSnapshotLocked` sees `publishedSnapshot <
m.lastSnapshot.Generation`, passes the liveness/same-plan gates,
and PUBLISHES T1's cancelled staged object (AGY r23 f4's trace,
verified against the function body — the helper-ahead catch-up
does not save it: the helper never had T1's generation, so the
code falls through to the real send). The OVERLAP cancellation
the plan ships therefore does NOT cover the actual publisher —
the exact late-publish class SMR22-1/AGY-f2/Codex-f6 closed on
the OnXSKBound leg remains open on the syncSnapshotLocked leg.

**Fix (pin, one of):** (i) `syncSnapshotLocked`'s publish path
gains the token-liveness check (a cancelled registration ⇒ the
staged object is dead: skip the publish, drop `m.lastSnapshot`'s
staged reference, and let the GO-LOCAL re-drive own the re-apply);
or (ii) the OVERLAP finalization atomically CLEARS the staged
reference itself (`m.lastSnapshot` can never reference a
cancelled staged object — the registry and the snapshot reference
transition under the same `m.mu` section), making the publisher's
blindness safe by construction. State which; §9 (f) asserts the
OnXSKBound leg only today — it must assert the chosen publisher
guard (T1 staged → OVERLAP → T2 fails pre-staging → XSK bindable
→ NO publish of T1).

## SMR23-5 (MINOR) — the stage timeout's mechanics are unpinned

The registration's fourth lifetime bound is "an explicit STAGE
TIMEOUT" (plan.md:4410-4414) with no duration, no firing owner,
and no stated posture. Pin: the duration (the XSK-bind failure
mode — a channel-set change recovers in seconds-to-minutes; a
destroyed VF never recovers); the owner (a scheduler entry
recorded at staging, cancelled with the registration); and the
posture — during the stage AND the re-drive's retries the staged
config's `DeferWorkers=true` keeps the dataplane DOWN, and for a
never-recoverable XSK that is indefinite BY CONFIG INTENT (the
config committed a binding plan whose interfaces cannot bind; the
dataplane stays down until the operator fixes the XSK or the
config — Warn-visible, not silent). The hazard budget must carry
the class.

## SMR23-6 (MINOR) — the fence registry's admission read discipline and crash window are unpinned

The owner-token registry (plan.md:4995-5010) defines the writers
but not the reader: the session-admission check
(sync_conn_gen.go:398-432's `max(fence, high-water)`) reads the
EFFECTIVE fence (max over live slots) AND the high-water — pin
whether the pair is read atomically (one lock / one seqlock
generation) or the tear is admitted (a fence raise landing
between the two reads admits a session the raised fence should
have held — fail-open; the discipline must be one consistent
snapshot, cheap to implement and free to state). And the crash
window: a process exit loses all slots AND the in-memory
high-water; between crash and the boot's first re-raise, session
admission runs against the LOST high-water — pre-existing
posture, state it in the budget.

## SMR23-7 (MINOR) — the structured send transaction's wiring is unpinned

AGY r23 f5, verified: `QueueConfig` lives in `pkg/cluster`
(sync_conn_config.go:1-8 imports only context/slog/time — no
configstore), takes raw text, and allocates the generation BEFORE
taking `writeMu` (:236-243 — VERIFIED); the daemon claims its
marker BEFORE calling it (daemon_ha_sync.go:474-497). The
transaction needs three pins: (i) the exposure/pair revalidation
closure (a constructor-injected `activePair func() (*config.Config,
uint64)` + `isExposed func(rev uint64) bool` — the daemon wires
the configstore reads; no package cycle); (ii) the marker-claim
ordering (the claim moves AFTER the send, or the structured
result rewrites it — and the reconciler at :474-497 now reads
`sentPair` from the result); (iii) the held-push re-wake owner
(a gated pair HOLDS the push — the exposure drain's completion
must wake the sync layer's reconciler, else the peer waits for
the periodic tick — state which and the bound).

## SMR23-8 (NIT) — the cursor-crash phrasing is circular

"re-derives the cursor from the store-retained prior + the
cursor" (plan.md:5031-5035) — the crash LOSES the cursor;
recovery derives from the `appliedRevision` sidecar + the store's
rollback/archive trees (exposed revision vs active revision ⇒ the
incomplete tail set). Reword.

## Attack trace (what else I tried, and why it fails to break v8.18)

1. **The guard-equality claim (Codex's attack 2).** The guard's
   inputs are `d.cluster` (the actual HA runtime) + the compiled
   candidate; the drain is daemon-side and re-reads/compiles the
   ACTIVE config, so it CAN evaluate the identical predicate —
   the equality is implementable. The hole is SMR23-1's loop, not
   the evaluation.
2. **The tombstone's re-add trigger.** A still-configured-but-down
   fabric's population goroutines (daemon_ha_sync.go:1223-1242)
   retry on their cadence; the first successful nonzero map write
   lifts the tombstone and the same machinery's next
   `update_fabrics` re-derives the FabricLink — one trigger, no
   gap. A config-REMOVED fabric is absent by construction and the
   goroutines read the config's fabric set. Coherent.
3. **The settlement crash rule.** The channel/cursor/debt are all
   in-memory; a crash loses them together; the sidecar + store
   trees re-derive the incomplete set (SMR23-8's phrasing aside).
   Idempotent re-run is safe. Coherent.
4. **The fence registry's owner-scoped clear.** A loop END clears
   only its own slot; the drain's slot survives; the max covers
   the overlap. A loop begin at G while the drain holds G′ > G:
   max = G′, never lowered. Coherent (the reader discipline is
   SMR23-6, not a writer hole).
5. **Q1, twenty-third enumeration.** The v8.18 mechanics
   (restart-suppression marker, registration registry, fence
   registry, settlement lifecycle, cursor, closeout projection,
   tombstone persistence, structured send) mutate NO binding
   slots on any refuse/degrade path — the binding-plan arm state
   remains the tri-state machinery's alone. No new
   `Registered && !Armed && state==none` producer. Q1 holds.
6. **The disposition table.** Every row re-derived: all fold
   claims verified present in the normative text EXCEPT the Codex
   f2 row's "§9 (b)" citation for the timer edge (SMR23-2) and
   the f6/f7 rows' implied publisher coverage (SMR23-3/SMR23-4).

## Required for convergence

v8.19: SMR23-1's restart-suppression marker (rule + debt clear +
re-arm semantics); SMR23-2's named timer mechanism + expiry
semantics + the §9 (b) assertion; SMR23-3's named catch-up tail
owner + idempotency; SMR23-4's publisher-liveness pin (check or
atomic clear) + the §9 (f) assertion; SMR23-5..7 folded; SMR23-8
reworded. AGY r23's f5 wiring and f6 test gaps fold with
SMR23-7/SMR23-2. Codex infra-blocked (usage limit, reset Aug 10;
documented attempts: r23 dispatch 05:33 UTC + retry 12:0x UTC —
proceeding 2-of-3 per the infra-blocked exception, retries
continue each round).

**Verdict: DEMAND-REVISION** (2 BLOCKER + 2 MAJOR + 3 MINOR + 1
NIT — contained pins, not architectural; the v8.18 surface
otherwise held).
