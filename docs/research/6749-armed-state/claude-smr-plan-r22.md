# Claude SMR plan review — round 22 — #6749 armed-state plan v8.17 (aca354bba)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.17 folds are MY text, written this session, so
this pass attacks my own fold text first, source in hand). Attack
surface: the promotion-serialization invariant, the tightening-only
closeout, beginFirstExposure, the completion cursor, the token
argument, fence-on-accepted, the live-registration discriminator,
the settlement identity + fence ownership, the verb-gate clear
points + cancellation-insensitive link recording, the three-path
tombstone, the outbound ordering.

**Verdict: DEMAND-REVISION** — 2 MAJOR + 4 MINOR. Both MAJORs are
self-found in my own v8.17 folds (the OVERLAP-finalized staged leg
can publish late over the newer accepted config; beginFirstExposure's
locus/transport and the oldActive dual-source are unpinned). The
rest of the v8.17 surface held under my attacks (trace below).

---

## SMR22-1 (MAJOR) — the OVERLAP-finalized staged leg can publish late over the newer accepted config

Trace: T1 compiles and stages (pending-XSK, `DeferWorkers=true`
baked in from T1's node). T2 (a NEWER commit — under the
promotion-serialization invariant, T2's own flow publishes it)
starts, and its `StartCompile` finalizes T1's open staged
reservation as OVERLAP (the v8.13 rule that keeps `compileInFlight`
from wedging). The `OnXSKBound` registration for T1's staged object
STILL LIVES (nothing cancelled it), and when the XSK becomes
bindable, the deferred leg fires with T1's staged object — a LEGIT
send by every fence: T1's pair is... NOT current (T2 was promoted
and accepted — the manager-side pair-current leg at the send
primitive refuses it — GOOD) — but the leg's send path is the
STAGED object's own publish, and my v8.17 text never says the leg
re-checks liveness: if the leg publishes anyway (its registration
is its authorization), T1's OLDER content overwrites T2's accepted
config late (the DUAL refusal does not save it: T1's
`commit_revision` is strictly older → the helper REFUSES — OK, the
helper saves it THIS time — but T1's content carrying a FRESH
`publication_rev` and the SAME commit revision (a same-commit
staged reshape) passes both legs and lands). The OVERLAP
finalization must CANCEL the staged leg's registration (not just
mark the reservation), and the deferred leg must check its token's
liveness BEFORE publishing (an OVERLAP-finalized token is dead —
the leg discards the staged object and skips). The registration's
lifetime is then bounded by exactly: OnXSKBound firing (with the
liveness check), OVERLAP finalization (which cancels), helper
death (the registration dies with the process), and an explicit
stage timeout (a never-firing event — the GO-LOCAL re-drive owns
it: the staged config is the ACCEPTED control-plane config, so a
never-binding XSK converts to the re-sync's full-apply retry at
backoff — not an indefinite stage).

## SMR22-2 (MAJOR) — beginFirstExposure's locus/transport and the oldActive dual-source are unpinned

My v8.17 fold says the transition runs "AT acceptance" without
saying WHERE, and leaves the wrapper's `oldActive` parameter in
place alongside the returned prior. Pin: the transition runs
MANAGER-SIDE at acceptance (the same `m.mu` section that advances
`m.acceptedCommitRevision` — reads-and-advances `m.lastExposedPair`
atomically, so the prior is always the pre-advance value); the
returned `{priorPair, ledgerID}` rides the `ApplyResult` to the
daemon wrapper (the manager's ApplyResult gains them); and the
wrapper's `oldActive` parameter is REPLACED by the prior ON THE
INVALIDATION PATH (one source of truth — under the promotion-
serialization invariant they agree in the no-gate case
(`oldActive == last-exposed` — the wrapper's own capture is
redundant there), and they differ EXACTLY post-gate (B promoted
and gated, C committed direct-durable: `oldActive` is B
(store-active), the prior is A (last-exposed) — the prior is the
correct invalidation base, and the wrapper's `oldActive` would
reopen Codex r20 f5's direct-C case if it ever won). The
completion cursor's lifecycle: manager-INSTALLED at acceptance
(same section), daemon-CONSUMED via the `ApplyResult`'s ledgerID —
ONE cursor, transported (never two).

## SMR22-3 (MINOR) — the invariant's boot-recovery edge

The boot-recovery promote runs inside `Load`
(store_persist.go:171-228) — pin: `Load` completes before the
daemon's apply scheduler starts (startup serialization), so no
apply flow can run concurrently with it; the invariant holds at
the edge.

## SMR22-4 (MINOR) — the tightening closeout's own-access strand (pin)

B removes the community the operator is CURRENTLY connected
through: the closeout applies it at commit time, killing the
operator's session immediately — acceptable (the commit already
landed control-plane; Juniors-parity (removing your own access
ends the session on commit); reconnect with the new credentials) —
stated. The closeout debt's coherence: the commit's note names the
pending exposure and the closeout debt's Warn names the failed
removal — both visible, never silent.

## SMR22-5 (MINOR) — the tombstone re-add posture (pin)

A full apply re-adds the CONFIG's fabric set (authoritative); the
deliberate runtime clear (HA fabric down) is operational state
that re-converges on its own machinery (the fabric population
goroutines (`startClusterComms`) re-drive it) — the tombstone is
consumed once (it fixes the helper's retained state after the
runtime clear), and no oscillation exists (the apply re-establishes
the intended set; the operational resolution continues on its own
cadence). Stated.

## SMR22-6 (MINOR) — the settlement's crash cases (pin)

The loop's ack is on PROCESSING, not on post: a post that lands
and is then lost (a loop crash before processing — the in-memory
channel is gone) is covered by the tail debt's repost (the ack
never came); a crash losing BOTH the item and the daemon-local
debt is covered by the completion cursor's crash rule (re-run the
idempotent tails conservatively at startup). Coherent.

## Attack trace (what else I tried, and why it fails to break v8.17)

1. **The persistence retry vs the drain's read.** The retry
   re-reads `s.active` under `s.mu` and writes atomically
   (`writeTreeMarked`); the drain's `ActivePair()` read is
   `s.mu`-atomic too — old-or-new, never torn. Coherent.
2. **The fence-on-accepted vs a legitimate retry.** A retry of the
   same build after a transient refusal carries the same token;
   the fence never advanced (the refusal was a rejection) — the
   retry is admissible. A NEW build always has a HIGHER token
   (buildSeq is monotonic) — the "new build with a lower token
   than a rejected one" case cannot arise Go-side; the only
   cross-authority case is a stale manager process, which the
   per-incarnation reset covers. Coherent.
3. **The gate's clear-on-transfer collision.** Between the
   transfer and the restore debt's next attempt, the operator's
   verbs are free; a registration toggle re-spawns workers; the
   retry's next attempt re-quiesces (`stop_workers` — helper-
   serialized, wins) and its own restore rebinds the CURRENT plan
   (including the operator's change). The operator's workers are
   stopped and re-created by the retry's own machinery — coherent,
   bounded, and helper-serialized throughout.
4. **Q1, twenty-first enumeration.** The invariant, the closeout
   set, the cursor, the token argument, the discriminator, the
   tombstone — none mutate binding slots on their refuse/degrade
   paths (the tombstone is runtime fabric state, not the binding
   plan (the plan is config-derived)). No new
   `Registered && !Armed && state==none` producer.

## Required for convergence

v8.18: SMR22-1's registration cancellation + liveness check +
stage-timeout owner; SMR22-2's locus/transport/single-source pins;
SMR22-3..6 folded. Codex r22 and AGY r22 pending at this writing —
their verdicts may add to this list.

**Verdict: DEMAND-REVISION** (2 MAJOR + 4 MINOR — contained, not
architectural; the v8.17 surface otherwise held).
