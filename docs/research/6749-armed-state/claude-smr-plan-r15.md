# Claude SMR plan review — round 15 — #6749 armed-state plan v8.10 (12ced136fe30)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — I wrote the v8.10 folds, so this pass attacks my own
fold text first). Attack surface: the two-revision lineage
(commit_revision assignment atomicity, publication_rev seed/burn
rules), the note CAS, the asymmetric echo, the universal StartCompile
reservation, the divergence-fired re-sync, the work-pull fence, the
recovery transaction, the fairness bound, the env ack-set, the fabric
debt.

**Verdict: DEMAND-REVISION** — two BLOCKERs in my own fold
(SMR15-1: the StartCompile reservation can clobber itself in one
apply; SMR15-2: the publication_rev seed has no acquisition
ordering), plus three MAJORs and three MINORs. AGY r15 independently
found every one of them (f1 = SMR15-1, f4 = SMR15-2, f5 = SMR15-3,
f6 = SMR15-4) and adds three more I missed (f2 helper-behind-nonzero,
f3 post-quiescence restore, f7/f8 debt semantics) — all verified
against source below.

---

## SMR15-1 (BLOCKER, converges with AGY r15 f1) — the StartCompile reservation can clobber itself in one apply

My v8.10 text says EVERY Compile begins with `StartCompile(deferIntent
bool)` AND the daemon's precheck calls `StartCompile(true)` at
daemon_apply_dataplane.go:69-72. In one apply, the ordering is:
precheck (true) → ApplyConfig → Compile entry (false) — the second
call overwrites the first, stamping `snap.DeferWorkers = false` at
manager_compile.go:330-332 and arming workers on unprogrammed RETH
MACs. Compile receives no `deferIntent` (ApplyConfig(ctx, cfg) has no
options, apply.go:37-40), so Compile cannot distinguish a fresh
precheck reservation from a stale one.

**Required fix:** the reservation is set EXACTLY ONCE per apply, by
the DAEMON at the apply-flow entry: `StartCompile(rethMACPending)`
before invoking ApplyConfig (the precheck's decision is already
computed there, daemon_apply_dataplane.go:45-82). Compile NEVER calls
StartCompile — it READS the reservation (and asserts one exists, a
canary). `ClearCompileReservation()` still routes every exit and
abort. The non-deferred case is `StartCompile(false)` from the same
single call site, which also explicitly resets any stale flag — the
universal-reset property is preserved without the clobber.

## SMR15-2 (BLOCKER, converges with AGY r15 f4) — the publication_rev seed has no acquisition ordering

My v8.10 text seeds `m.lastPublicationRev` "at manager startup from
the helper's echoed stored publication_rev" without gating sends on
the seed. A startup re-apply (or any early publish) fired before the
first completed status poll mints from 0; a helper that outlived the
manager restart (stored = N) refuses `1 <= N` — the boot apply fails
closed and every retry mints `attempt+1 <= N` until the first poll
lands. **Fix:** no full-publish send happens before the seed is
initialized — a `publicationRevSeeded` boolean set on the FIRST
successful status poll of each manager lifetime, gating every
full-publish producer (sends before it return a retryable
not-seeded-yet error to their callers, which the existing retry
owners absorb). The manager restart case with a co-restarting helper
(stored = 0) is unaffected.

## SMR15-3 (MAJOR, converges with AGY r15 f5) — the 150s bound is not the honest fairness guarantee

A commit's whole-pipeline `applySem` hold includes MULTIPLE
sequential control requests (apply_snapshot, update_neighbors,
update_fabrics, FRR reload — daemon_apply.go:49-56 ×
process_control.go:33-56's per-request deadlines): the worst legal
single-owner hold is several minutes, not 120s. **Fix (wording, not
design):** the contract is EVENTUAL progress — attempts retry
indefinitely with a bounded per-attempt context (150s), and progress
is guaranteed by FIFO waiter wake plus bounded owner holds (every
owner releases in bounded time); no acquisition-time guarantee is
made. The v8.10 "bounded-wait" sentence is corrected.

## SMR15-4 (MAJOR, converges with AGY r15 f6) — the per-mutation claimToken re-read must be try-lock-or-skip too

My v8.10 text makes Claim/Report try-lock-or-skip on `m.mu` but
leaves the per-mutation re-read blocking: the status loop holding
`m.mu` through a 120s control request then monopolizes `applySem`
(via the blocked work loop) behind it. **Fix:** the per-mutation
re-read is also try-lock-or-skip — a contended read skips the
mutation to the next backoff tick; the work item stays claimed (no
stall, no monopoly).

## SMR15-5 (MAJOR, credit AGY r15 f2 — I missed this) — the re-sync must also fire on NONZERO helper-behind

My v8.10 helper-behind case routes only "echoes 0 → startup
re-apply". A helper behind with a NONZERO stored revision
(`0 < status.commit_revision < m.acceptedCommitRevision` — an
incomplete persist, or a helper that kept an older-but-real state)
matches NEITHER the startup re-apply (rev != 0) NOR the re-sync's
`status > accepted` firing rule: adoption blocked, no owner,
permanent divergence. **Fix:** the re-sync ALSO fires on
helper-behind-nonzero (`0 < status.commit_revision <
m.acceptedCommitRevision`, or `status.publication_rev` behind with
nonzero stored) — the same active-config re-apply owner (the
strictly-greater publication rule accepts the newer send; the
commit_revision carries the accepted config's identity).

## SMR15-6 (MAJOR, credit AGY r15 f3 — I missed this) — every quiesced attempt must END with a restore-rebind

My v8.10 recovery says a quiescence failure ABORTS the attempt and
the debt retries — but the abort leaves the dataplane STOPPED
(`stop_workers` + `ctrl.Enabled=0` already executed) for the whole
backoff (up to 60s, indefinitely on a persistent failure). **Fix:**
every attempt that entered the quiesce ENDS with a restore
(`NotifyLinkCycle`'s rebind + ctrl re-enable) on EVERY outcome —
success, phase failure, or abort — so the dataplane returns to the
pre-attempt (running) state before the backoff; the debt then
retries the failed phase from RUNNING, not STOPPED. The restore is
idempotent and cheap (the plan-binded sockets re-create).

## SMR15-7 (MINOR, credit AGY r15 f7) — the fabric debt keys on projection-IDENTITY, with a rev-ordered clear

Codex r14 f12 killed the planner-field key (telemetry aliases); my
v8.10 full-payload key has the dual hole: a telemetry update
(peer-MAC resolve) changes the payload, so the readiness query's
map-derived hash misses the debt keyed on the pre-telemetry payload.
**Fix:** the debt keys on `(commit_revision,
projection-identity(planner fields))` for LOOKUP (a telemetry change
is the same identity — the debt is found), and records the
last-sent payload hash per entry for the CLEAR rule: a clean sync
clears the entry ONLY when its sent payload is the debt's payload
or NEWER by send order (publication-rev-ordered) — a stale clean
retry never clears a newer unsynced payload, and a telemetry-updated
debt is never invisible.

## SMR15-8 (MINOR, credit AGY r15 f8) — the note debt clears on echo >= sent

My v8.10 "cleared ONLY on an exact echo" wedges against
supersession: a newer accepted commit advances stored past the
note's rev and the exact echo never comes. **Fix:** the note debt
clears on an echo of the captured sent rev OR ANY NEWER rev (the
lineage has moved past — the note's purpose is fulfilled), and a
younger echo leaves it retrying.

## SMR15-9 (NIT) — two specification pins of my own

1. **Recovery batch arrivals:** a member whose link returns DURING
   an in-flight batch's quiescence defers to the next attempt (the
   batch's rebind physically binds its slots — physically inert
   while its MAC obligation is outstanding — and the next attempt
   programs it). One sentence.
2. **commit_revision atomicity is implementable as asserted:** the
   store persists each active-config write via
   `fsatomic.WriteFileDurable` (temp + fsync + rename + dir-fsync,
   store_persist.go:952), so embedding the revision in the same
   write is genuinely atomic — but each of the five promotion paths
   must be enumerated in the implementation checklist to confirm it
   writes through that boundary (no in-memory-only promote).

## Attack trace (what else I tried, and why it fails to break v8.10)

1. **The note's stored rev vs the snapshot's.** The note sets the
   same stored `commit_revision` the next full apply would set — the
   echo after a successful note shows the staged rev while the
   content is the dedup-equal incumbent's. The gates compare
   revisions, and the dedup hash proved content equality, so this is
   coherent; the NAT alarm's authority (appliedSnapshot) is
   untouched.
2. **The abandoned note after a CAS refusal.** The racing publish
   advances accepted past the note; the staged config it referred to
   is superseded by the normal acceptance machinery
   (pending collapses to accepted at C's acceptance). No leak.
3. **FabricSyncDebtOutstanding hash coherence (pre-f7 fix).**
   controllers.go:112-132 commits the map from the same struct it
   sends, so the map's latest content IS the sent payload — the
   readiness query coheres for the steady case; the f7 telemetry
   case is the only hole and SMR15-7 covers it.
4. **Q1 fourteenth enumeration.** The CAS refusal, the
   strictly-greater refusal, the rebase, and the asymmetric echo all
   perform no slot mutation on their refuse/drift paths. No new
   `Registered && !Armed && state==none` producer.

## Required for convergence

v8.11: SMR15-1's single-call-site reservation (= AGY f1), SMR15-2's
seed gate (= AGY f4), SMR15-3's honesty correction (= AGY f5),
SMR15-4's try-lock extension (= AGY f6), SMR15-5's
helper-behind-nonzero firing (= AGY f2), SMR15-6's restore-rebind
(= AGY f3), SMR15-7's identity-keyed debt (= AGY f7), SMR15-8's
echo>=sent clear (= AGY f8), SMR15-9's two pins — plus whatever
Codex r15 adds.

**Verdict: DEMAND-REVISION.**
