# Claude SMR plan review — round 16 — #6749 armed-state plan v8.11 (c381b621a44f)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — I wrote the v8.11 folds, so this pass attacks my own
fold text first). Attack surface: the R1 rollout/transport, the R2
split high-waters + dual refusal + legacy-zero + rebase proof, the
note three-way, the both-direction re-sync via applyConfigLocked, the
tokened compile reservation, the work-pull validator + unwind, the
recovery batch/restore, the no-timeout fairness, the no-arg readiness
query.

**Verdict: DEMAND-REVISION** — one MAJOR design correction in my own
fold (SMR16-1: the batch-arrival "REVALIDATES before enabling" rule
is either a no-op or takes the whole dataplane down via the enabled
gate — the correct form is absorption/immediate event-fired
attempts), plus five MINOR/NIT specification pins. Everything else in
the v8.11 surface held under my attacks (trace below).

---

## SMR16-1 (MAJOR) — the batch-arrival rule gates the wrong thing

My v8.11 recovery text says the batch's global rebind "REVALIDATES
every `macAndLinkRecovery` member's MAC before enabling its slots".
Trace the semantics. The member's slots were ARMED at the epoch
completion (bound while down, armed — the all-or-nothing `enabled`
gate counts them). At the batch's rebind, the armed convergence
converges the CURRENT armed vector — it has no member-scoped
enablement condition. Two literal readings of my sentence, both bad:

1. **No-op reading:** the convergence arms per the coherent vector
   regardless of any "revalidation" — the sentence specifies nothing
   (the member is rebound-and-enabled with a factory MAC, exactly
   Codex r15 f10's hazard).
2. **Un-arm reading:** the revalidation un-arms the member's slots
   (marks them pending until the MAC validates) — then the
   all-or-nothing `enabled` gate (status.rs:274-281 counts EVERY
   registered slot) goes FALSE and the batch's rebind takes the
   WHOLE dataplane down for the recovery window — the exact outage
   class this PR exists to fix.

The correct rule, and the one the fold must carry: **absorption.**
The batch re-Claims at rebind time (post-sleep, pre-rebind) and
newly-due members (whose links returned during the quiescence) are
absorbed INTO the batch's own validation+program phase — the batch
programs their MACs as part of ITS work (it already owns the
quiescence), so no member is ever rebound with a wrong MAC. A member
the batch cannot absorb (its link returns AFTER the re-Claim but
before the rebind completes) is handled by an event-fired attempt
with NO backoff for first-fires (the backoff applies to RETRIES) —
the attempt fires at the event, joins the quiescence tail, and its
MAC program lands ≤ the sleep remainder after the event; its own
post-program rebind re-creates that member's sockets (the batch's
rebind having bound them is fine — the MAC program's DOWN→UP
re-inits the queues and the attempt's rebind is part of its own
transaction). The residual exposure is ≤ ~1s of one member
forwarding with a factory MAC (peer frames to the virtual MAC drop
at that member — a partial-path blackhole for flows hashed to it),
and it is stated honestly. The "revalidation" that remains is a
READ-ONLY MAC-match check used for ROUTING (which phase the member
needs), NEVER a programRethMAC inside the batch rebind (that would
double-cycle: the rebind just bound fresh sockets and the program's
DOWN→UP would kill them immediately).

## SMR16-2 (MINOR) — the revision high-water must be a dedicated counter, not archiveSeq

My R1 rollout text says the next promotion assigns "the next durable
value from the store's high-water". If that high-water is read as
`archiveSeq`, every Codex r14 f2 defect reopens (manual
`ArchiveConfig` bumps it without a promotion; CommitConfirmed /
SyncApply / PromoteRollback don't). Pin it: the revision high-water
is a NEW dedicated counter seeded from `max(active.json revision,
0)` and bumped ONLY inside the five promotion paths — never from
archive filenames.

## SMR16-3 (MINOR) — three specification pins from my own attack surfaces

1. **Migration-write-failure posture:** a failed legacy-migration
   rewrite at `Load` leaves the revision UNCONFIRMED (the same rule
   as Option-B) — the daemon starts (Option-B semantics) with the
   gates in the legacy-zero/fail-closed state until the write
   succeeds (retried), NOT a hard Load failure and NOT a silent
   revision-0-forever.
2. **The note-echo loop ordering:** the poll processes (1) the note
   debt's echo-clear, (2) accepted advancement, (3) divergence
   classification/re-sync firing — in that order, pinned.
3. **UNKNOWN vs PRE-PUBLISH FAILURE classification:** a received
   error RESPONSE (helper refusal, helper mid-apply error) is
   PRE-PUBLISH FAILURE (the helper's apply guards
   (snapshot.rs:33-105) roll back — nothing landed); a
   timeout/EOF/dial-unknown is UNKNOWN; a dial failure BEFORE the
   send is PRE-PUBLISH.

## SMR16-4 (MINOR) — the unwind's own failure routes to the #5134 machinery

The balanced unwind's restore-rebind can itself fail (UNKNOWN,
workers stopped). That state is exactly the #5134 debt's territory
(deferred worker arm): the unwind's failure records the worker-arm
debt and the generic pending-activation retry owns recovery — not a
new owner.

## SMR16-5 (MINOR) — two fairness pins

1. A `ValidateClaimToken` skip AFTER acquiring `applySem` releases
   the semaphore BEFORE sleeping (not just on batch abandonment) —
   the monopoly the try-lock rule exists to kill.
2. The 60s queued-state Warn resets its edge on state change
   (acquire success, retry scheduling) — one edge per queue episode,
   not one per lifetime.

## SMR16-6 (NIT) — `FabricSyncStateOK()` polarity on a fresh boot

The no-arg answer must be "NO outstanding unconfirmed sync work for
the current projection" (a fresh boot with nothing outstanding is
OK=true), not "a positive proof exists" (which would false-block a
fresh boot and correctly fail-closed only on an old helper's echoed
zero).

## Attack trace (what else I tried, and why it fails to break v8.11)

1. **The migration + legacy-zero + upgrade path.** A legacy
   active.json migrates to rev 1 at Load; the helper restarts
   (required) with stored 0 (legacy-zero mode active); the startup
   re-apply carries (rev 1, ping-seeded publication) → accepted →
   legacy mode exits. Coherent.
2. **The dual refusal + rollback promote.** The promote assigns a
   FRESH commit_revision (higher) → passes the identity leg;
   publication fresh → passes. The content is older and the helper
   accepts — a legitimate rollback, not a stale clone.
3. **The feed/DHCP pair re-read.** Re-reading the store's current
   active (config, revision) under the semaphore at apply time and
   compiling THAT selection closes the captured-A-labelled-B race;
   the feed/DHCP content re-derives inside the lock as today.
4. **The OVERLAP outcome + debt supersession.** T2's publish
   advances `acceptedCommitRevision` past T1's debt key — the
   commit-level supersession machinery cancels T1's MAC debt; T2's
   precheck owns the new epoch. The reservation token only governs
   the (deferWorkers, inFlight) pair, which is correct — the debt
   rides the existing rule.
5. **The minted/observed split + retries.** Every wire retry
   re-mints (newer) and the strict-greater helper accepts each;
   observed advances only on proof. The lost original's rev is
   dead-burned. Consistent.
6. **Q1 fifteenth enumeration.** The dual refusal, the note
   three-way refusal, the typed errors, the rebase, and the
   migration all perform no slot mutation on their refuse/degrade
   paths. No new `Registered && !Armed && state==none` producer.

## Required for convergence

v8.12 (or v8.11.1): SMR16-1's absorption/immediate-attempt rule
replacing the "REVALIDATES before enabling" sentence (and the
read-only routing check pinned), plus SMR16-2..6 folded. If Codex
and AGY r16 converge on the same correction and nothing new at
DEMAND level, v8.12 should be the convergence candidate.

**Verdict: DEMAND-REVISION** (1 MAJOR + 5 MINOR/NIT — contained,
not architectural).
