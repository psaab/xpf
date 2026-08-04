# Claude SMR plan review — round 14 — #6749 armed-state plan v8.9 (6e2da70b98e1)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — I wrote the v8.9 folds, so this pass attacks my own
fold text first). Attack surface: the commit-seq epoch semantics
(archiveSeq), the five-producer census + epoch-rollback refusal, the
`note_config_epoch` dedup transfer, the StartDeferredCompile
reservation, the re-sync debt, the work-pull interface, the env
ack-set, the fabric sync debt.

**Verdict: DEMAND-REVISION** — one BLOCKER of my own found
independently of (and identically to) AGY r14 f5 (SMR14-1: the
`note_config_epoch` verb as committed is an unguarded lineage
regression primitive), plus three MINORs. AGY r14's other findings
converge with my own attack-trace items and add one shape I rated
insufficiently (the asymmetric echo corruption, AGY f2 — verified
below and upgraded to a required fold). Every finding verified
against source.

---

## SMR14-1 (BLOCKER) — `note_config_epoch` needs compare-and-set semantics (converges with AGY r14 f5)

My v8.9 dedup-transfer text says: on a content-dedup skip, "the
manager then issues `note_config_epoch` (B's commit seq) — the
helper sets its stored `config_epoch` to B's seq WITHOUT any
snapshot mutation." There is no ordering guard. A racing full apply
C (seq newer than B) can land between the skip and the note; the
unguarded note then REWRITES the helper's stored epoch BACKWARD
from C's seq to B's — a lineage regression: subsequent
`expected_config_epoch` fences compare against the regressed value
(false-refusals), and the rollback-refusal's protection against
stale clones is weakened until the next full apply. The reverse
guard (note refused when its seq < stored) turns the same race
into an unnecessary fail-closed suppression (AGY f5's second horn).

**Required fix (fold into v8.10):** the note is a COMPARE-AND-SET:
`note_config_epoch { new_seq, expected_seq }` — the helper applies
it ONLY when `stored == expected_seq` (the seq Go read when it
decided the dedup transfer), else refuses with a
`stale_expected_epoch` error carrying the CURRENT stored seq. A
refusal is INFORMATIVE, not a failure: the racing publish already
advanced lineage past the note, so Go abandons the note (no
retry), and the gates re-evaluate against the newer stored seq.
Go marks `acceptedConfigEpoch = pendingConfigEpoch` only on the
observed CAS success.

## SMR14-2 (BLOCKER, credit AGY r14 f2 — I verified and upgraded it) — the latch echo must be ASYMMETRIC (clear-only)

AGY's shape, re-derived: reach (helper stored epoch == Go's
accepted epoch, helper `stored_defer_workers == true`, Go
`m.deferWorkers == false`) via a lost OPERATOR-ARM response where
the verb landed (consuming nothing — the latch was set by an
earlier deferred apply) and Go's flag was already cleared by the
verb's send path. A subsequent NON-deferred compile builds outside
`m.mu` (manager_compile.go:177-228); a 1 Hz poll passes the (v)
gate (epoch matches, `compileInFlight == false` for a
non-deferred compile) and reconciles `m.deferWorkers = true` from
the lingering latch; the compile then stamps
`snap.DeferWorkers = true` at :330-332 — a non-deferred config is
published DEFERRED (workers never start; the dataplane wedges
with the operator seeing a clean commit).

My v8.9 attack-trace rated the echo's (v) gate sufficient; it is
not — the gate checks lineage, but the lingering-latch case HAS
matching lineage. The echo's PURPOSE is one-directional: clear
Go's flag when the HELPER consumed the latch (the lost-completion
case: Go true, helper false). Go must NEVER adopt `true` from the
echo — defer intent only ever originates Go-side
(StartDeferredCompile). **Fix:** the echo reconciles clear-only
(helper false → Go false); a helper-true/Go-false mismatch is a
drift Warn (edge-triggered) whose owner is the next full apply
(which stamps `defer_workers` from Go's own flag, re-asserting
the truth) or the re-sync if the epochs also diverge.

## SMR14-3 (MINOR) — the re-sync debt must re-read the active config AT DRAIN TIME

Consecutive timeout-but-landed configs B then C: the single-flight
debt must re-apply the NEWEST active config (C), not the B that
was active when the debt was recorded. The v8.9 text says the
daemon "re-reads the ACTIVE config from the configstore" — pin
that the read happens at DRAIN time (and re-reads on every
backoff retry), so a chain of landeds converges on the newest
commit (whose seq passes the rollback refusal).

## SMR14-4 (MINOR) — pin the recovery debt clear predicate for operator-claimed slots (converges with AGY r14 f3, which rates BLOCKER)

A member whose slots are operator-disarmed (`state=operator`)
while its `macAndLinkRecovery` entry completes will never show
`bound+ready` on those slots — the observed-success clear never
fires (AGY's infinite-retry shape). The debt's obligation is the
MAC/link transaction, not the operator's arm state: the clear
predicate must count the member's NON-operator slots bound+ready
and IGNORE operator-claimed slots entirely (their arming stays
the operator's; the recovery completes the MAC/link work and
clears).

## SMR14-5 (MINOR) — the suppression cache needs a TTL (converges with AGY r14 f4, which rates BLOCKER)

Replace-oldest eviction of a rejected identity from the helper's
≤4 watch set strands Go's suppression (the env bump for the
evicted identity never comes). Give the Go cache entry a TTL
(50s ≈ 10× the dispatch debounce): on expiry Go re-sends once;
the helper re-rejects on a fresh sample and re-acks (re-inserting
the identity into the set), so an evicted identity's recovery is
re-observed within one TTL.

## SMR14-6 (NIT) — three specification pins

1. The takeover-readiness debt read needs an explicit interface
   method (AGY f6): `FabricSyncDebtOutstanding(projectionHash
   uint64) bool` on the HA controller path.
2. `MACDebtWorkItem.Deadline` (AGY f7): advisory only — an
   expired deadline re-Claims (never drops an obligation).
3. The `compileInFlight` clear sites: every Compile exit
   (success, build failure, publish failure, panic/recover) AND
   the apply flow's deferred clear
   (daemon_apply_dataplane.go:74-82) route through
   `clearDeferredCompile()` — the ONLY two methods that touch
   the (deferWorkers, compileInFlight) pair, so the pairing can
   never skew.

## Attack trace (what else I tried, and why it fails to break v8.9)

1. **The rollback-refusal vs legitimate flows.** A rollback to an
   OLDER config is a NEW commit with a NEWER archiveSeq
   (monotonic per store_commit.go:304) — passes. An HA secondary
   reverse-syncing an OLDER peer config commits it LOCALLY (newer
   local seq) — passes; epochs are node-local end-to-end.
2. **Factory reset (AGY f1, rated BLOCKER there).** The helper's
   `state.json` lives at `os.TempDir()/xpf-userspace-dp/
   state.json` (capabilities.go:21) — survives a /var/lib/xpf
   archive wipe, and the helper does NOT self-restore on a
   process restart (lifecycle.rs:182-203 initializes stored
   generations to 0). The brick needs the helper PROCESS to
   outlive the configstore wipe with no manager-fresh epoch
   state — a service-restart-only factory reset achieves it
   (manager fresh, helper stored=42, reseeded seq=1 → every
   apply rollback-refused, the re-sync debt retries forever).
   Fix (fold into v8.10): a bootstrap epoch rebase — the
   manager's FIRST apply after startup with
   `acceptedConfigEpoch == 0` carries `allow_epoch_rebase: true`
   (one-shot, only valid when the manager holds no accepted
   config); the helper accepts and re-bases its stored epoch to
   the reseeded counter's value. Belt-and-braces: move
   `state.json` under /var/lib/xpf so a factory reset wipes it
   too (the running process's RAM copy still needs the rebase).
3. **Concurrent member recoveries.** The debt scheduler is
   single-threaded per daemon (one attempt at a time), so two
   recovering members produce back-to-back — never concurrent —
   global quiesces, bounded by the attempt cadence. Acceptable;
   a sentence should say so.
4. **claimToken wholesale discard.** An operator cancellation
   between Claim and Report discards valid sibling results; the
   retry re-Claims and re-drives them (MAC equality no-ops,
   link rereads are µs-scale). Correct; per-member tokens are
   over-engineering.
5. **Q1 thirteenth enumeration.** The note CAS, the rollback
   refusal, and the asymmetric echo all perform no slot
   mutation on their refuse paths. No new
   `Registered && !Armed && state==none` producer.

## Required for convergence

v8.10: SMR14-1's CAS (= AGY f5), SMR14-2's asymmetric echo (=
AGY f2), SMR14-3's drain-time pin, SMR14-4's clear predicate (=
AGY f3), SMR14-5's TTL (= AGY f4), SMR14-6's three pins (= AGY
f6/f7 + the exit pairing), AGY f1's epoch rebase (attack trace
2), plus whatever Codex r14 adds.

**Verdict: DEMAND-REVISION.**
