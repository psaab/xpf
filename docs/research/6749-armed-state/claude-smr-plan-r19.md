# Claude SMR plan review — round 19 — #6749 armed-state plan v8.14 (ef735f529)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.14 folds are MY text, written this session, so
this pass attacks my own fold text first, source in hand). Attack
surface: the pair-specific gate, the typed ApplyOutcome + deferred
tails, the revision-keyed marker, the suppression flag, the delayed
invalidation + content-hash leg, the fold matrix, the mutation lease +
blocking reconciliation, the restore debt API, the canonical fabric
pair, the note verb.

**Verdict: DEMAND-REVISION** — 2 MAJOR + 5 MINOR. Both MAJORs are
self-found defects in MY OWN v8.14 folds (the hash leg's incoherence
with the canonical fabrics replacement, and the revision-keyed
marker's node-local vs inter-node conflation). The rest of the v8.14
surface held under my attacks (trace below).

---

## SMR19-1 (MAJOR) — the content-hash leg is incoherent with the canonical fabrics replacement AND unnecessary

My v8.14 fold has the full snapshot's fabrics section READ FROM THE
CANONICAL PAIR AT THE PUBLISH LEG (never the pre-m.mu build), while
the freshness validation compares the build-END semantic hash against
`m.latestBuiltHash`. A fabric mutation landing between build end and
the publish leg makes the WIRE content (replaced fabrics, generation
g′) differ from the HASHED content (built fabrics, g) — the
validation compared a hash of content that is never sent, and the
sent content was never validated. Worse, the note-CAS dedup compares
semantic hashes of candidate vs stored; a post-hash fabrics swap
makes the dedup decision about the wrong content. Attacking the
leg's purpose directly: it is also UNNECESSARY. The two remaining
legs cover every case: (a) PAIR-CURRENT — the build's `(config,
revision)` must equal `m.currentPair` (a newer commit's promotion
invalidates); (b) NO ACCEPTED NEWER BUILD — a strictly-newer build
OBSERVED-ACCEPTED invalidates (the same-commit reshape: T2's fresher
content accepted ⇒ T1 abandoned; T2 not yet accepted ⇒ T1 publishes
and T2 converges milliseconds later — the natural direction, never
stale-over-fresh); (c) the helper's strictly-greater `snapshot_token`
refusal is the wire backstop for the residual race (T1 validated
before T2's acceptance LANDED — the refusal catches it, and the
typed `stale_snapshot_token` classifies it as superseded,
success-equivalent). The `m.latestBuiltHash` machinery (and its
 fabrics incoherence) is DELETED; the validation runs at the publish
leg's ENTRY under `m.mu` as (a)+(b). Required: fold the deletion +
the three-leg rule; §9 (d) re-specified (the hash assertions become
the pair-current/accepted-successor/backstop assertions).

## SMR19-2 (MAJOR) — the revision-keyed marker conflates node-local and inter-node identity

My v8.14 fold keys `ActiveApplied()` to the (text, revision) PAIR to
stop a same-text gated promotion inheriting applied state. But the
epoch contract itself says revisions are NODE-LOCAL ("each node
promotes locally") — the same config text carries DIFFERENT
revisions on different nodes (the peer assigns its own high-water +
1 on `SyncApply`). An inter-node revision comparison is therefore
meaningless: the primary cannot key anything to the peer's revision.
The correct split: (i) NODE-LOCAL — the pair comparison stands
(`ActiveApplied()` / the receiver's own gate: (text, LOCAL
revision)); (ii) INTER-NODE — the sync layer's applied tracking
keys to the config DIGEST (as today, daemon_ha_sync.go:474/:549)
plus the typed outcome's DEFERRED gen settlement (the peer's
`lastAppliedConfigGen` and CF/readiness tails advance only on
EXPOSURE (v8.14's typed outcome — that part is right), so the
primary's view of the peer lags visibly until the peer's local
exposure debt converges). The equal-text shortcut case (a same-text
promotion, new revision): the shortcut compares digests — the peer
already HAS the text — but its LOCAL pair (text, R_b′) is unexposed;
the shortcut skipping the push is then IRRELEVANT to convergence
(the peer's own exposure debt converges it locally) — correct, but
only because the exposure debt is node-local. Required: the fold
states the split explicitly (revision-keyed node-locally,
digest+deferred-gen inter-node) and §6's marker text is scoped.

## SMR19-3 (MINOR) — the suppression flag's fail-stale cost and set-ordering

`m.exposureGateActive` holds auxiliary producers for the whole gate
window — during a long storage outage the helper's FIB goes STALE
(route updates held: a fail-stale, not fail-closed, posture for
routing). That is the correct conservative choice (the alternative
is the A-config/B-FIB hybrid), but it must be stated, and: (i)
suppressed overlays are LATEST-WINS on clear (only the newest
publishes — not every held one replays); (ii) the flag set is
ordered BEFORE the commit's FRR reload in the flow (so no overlay
can carry B's RIB before suppression — the RIB watcher's event is
async but the flag is already set); (iii) a newer NON-GATED
commit's successful apply also clears the flag (the store recovered
between commits — the flag is not solely the drain's to clear).

## SMR19-4 (MINOR) — the pair-current leg must exempt the explicit revision-0 CLI path

The direct CLI `Compile` (pkg/cli/apply.go:196-200,
legacy_dataplane.go:190-195) passes revision 0 explicitly — its pair
is NEVER `m.currentPair` (it promotes nothing), so the pair-current
leg abandons EVERY CLI Compile. Pin: the explicit revision-0
reservation bypasses the pair-current leg (the legacy-zero mode
governs it helper-side; the accepted-successor leg and the token
backstop still apply).

## SMR19-5 (MINOR) — the deferred-tail set for non-HA commits

The typed outcome's deferred set must be named: DEFER =
{dataplane-adjacent success markers (MarkActiveApplied, applied
stamp, `armedActive`, CF clear, `lastAppliedConfigGen`) + the
session clear + the peer push}; FOLLOW = {FRR reload, networkd,
services} (control plane — visible, converges at exposure). The
deferred session clear means sessions valid under A keep flowing
while B waits (correct — A is still enforced); B's session-relevant
changes take effect at exposure (stated).

## SMR19-6 (MINOR) — the lease's batch latency budget + the restore apply's semaphore

The mutation lease holds `m.mu` across each netlink syscall; a
12-member batch's MAC phase is N × (read + syscall) under the lock
(~1s worst) — bounded and stated (the status loop's own RPC holds
are larger); the batch's own latency budget gains the sentence. The
restore debt's missing-process full apply ACQUIRES `applySem`
(FIFO behind any in-flight MAC batch — no concurrent daemon-side
StartCompiles; the chain covers the non-daemon overlap shapes
regardless).

## SMR19-7 (MINOR) — `durableRevision`'s advance has no crash window

The revision travels INSIDE the atomically-written envelope, so
`durableRevision` is advanced in-memory only after
`writeTreeMarked`'s rename lands AND is re-derived from the on-disk
envelope at `Load` — a crash between the write and the in-memory
advance self-heals at restart (the file is the truth). Pin the
derivation in §6's store bullet.

## Attack trace (what else I tried, and why it fails to break v8.14)

1. **The gate at applyConfigLocked's ENTRY.** The pre-dataplane
   mutations (daemon_apply.go:127/:167/:200/:246) are
   SNMP/web-management/bootstrap/kernel/VRF state — none publish
   into the helper; the gate's skip defers only the dataplane leg
   and the deferred-tail set (SMR19-5). Coherent.
2. **The restore drain vs the MAC batch.** The drain acquires
   applySem FIFO; the batch's transaction is bounded and
   terminating; the restore's full apply then runs the full
   machinery. No interleaving.
3. **The typed outcome vs the commit's synchronous contract.** The
   commit returns success + the pending note SYNCHRONOUSLY; the
   exposure is async but owned (the debt + the always-live timer +
   the visible lag). The operator is never lied to (the note names
   the pending state) — Juniors-parity preserved.
4. **Q1, eighteenth enumeration.** The pair-specific gate, the
   typed outcome, the suppression flag, the lease, the canonical
   pair, the note verb — none mutate binding slots on their
   refuse/degrade paths. No new `Registered && !Armed &&
   state==none` producer.
5. **The unknown-verb note classification.** An old helper rejects
   the note as unknown-verb — but that helper echoes revision 0, so
   the note path never runs (fail-closed earlier); an untyped
   unknown-verb error is classified as the legacy/mixed-version
   case (no `error_code` → today's handling), never as a CAS
   refusal. Coherent.

## Required for convergence

v8.15: SMR19-1's three-leg rule (hash machinery deleted); SMR19-2's
node-local/inter-node split; SMR19-3's fail-stale statement +
ordering + non-gated clear; SMR19-4's CLI exemption; SMR19-5's
deferred-set enumeration; SMR19-6/7 folded. AGY r19 and Codex r19
pending at this writing — their verdicts may add to this list.

**Verdict: DEMAND-REVISION** (2 MAJOR + 5 MINOR — contained, not
architectural; both MAJORs are self-found in my own v8.14 text).
