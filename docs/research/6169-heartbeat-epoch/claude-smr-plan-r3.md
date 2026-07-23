# Claude SMR — hostile plan review, #6169 boot-epoch, round 3 (plan v3)

Stance: HOSTILE re-attack of v3. Verified against `origin/master` @ `11e23b49a`.

## Round-2 findings — resolution check

- **Wire discriminator (r2 §2).** §5.1's key-derived, tail-anchored,
  MAC-verified marker is correct. `HMAC(key,"xpf-ha-boot-epoch-v2")[:8]` is
  domain-separated from the frame HMAC (distinct message), constant-per-key
  (fine — it is a presence flag, not a nonce), unforgeable, and 2⁻⁶⁴ against an
  archived v1 body. Reading it only after MAC verify + keyless-parses-full-frame
  closes the unkeyed-`bodyEnd` regression. **Resolved.** (One bounds nit, N1.)
- **Separated nonce / total order (r2 §1).** §5.2 separating the Manager
  send-nonce (never reset on key change) from `peerAdmission` fixes the repeated
  `(E,1)`; counter-exhaustion→force-epoch is sound. **Resolved.**
- **Key-gen TOCTOU (r2 §4).** §5.3 snapshot-at-verify / check-at-commit with a
  monotonic *counter* (not key value) even defeats K1→K2→K1 ABA. **Resolved.**
- **Re-prime scope (r2 §4).** §5.5 clearing only `{highEpoch,highCounter,sawEpoch}`
  (keeping `peerAuthSeen` — the rolled-back v1 node still signs XPFA) + cluster-
  wide never-used-key rotation is correct. **Resolved.**
- **#5639 (r2 §5).** §3 makes it a hard prerequisite with a Manager-scoped
  cross-channel owner; v3 retracts the "`sync_auth.go` unchanged" claim.
  **Resolved as a sequencing decision** (N2).
- **Concurrency (r2 §6).** Dedicated admission lock + `handlePeerHeartbeat` after
  unlock + `buildHeartbeat` only reads the bring-up-resolved epoch. **Resolved.**

## Required revision — the election fence is over-broad (R1)

§5.4 fences *any* persist-failure ("hold-secondary while a peer is present").
That both **over-fences** and introduces a **new outage mode**:

1. **Persist-failure with a VALID intact file is self-healing, not a self-lock.**
   If the file holds a valid `prev`, the emitted candidate is `max(prev+1, now)`;
   the next reboot re-reads the *same* `prev` and the wall clock has advanced, so
   the next incarnation is ≥ the emitted value — the peer never records anything
   this node cannot reproduce. Fencing this case is pure availability loss for no
   security gain.
2. **Both-nodes-persist-fail → no primary (new outage).** An absolute
   "hold-secondary while a peer is present" makes a two-node cluster where *both*
   nodes fail to persist (shared image/disk fault) elect **no** primary — an
   outage the current design does not have.

**Fix:** scope the fence to the genuinely dangerous case — **state-loss** (no
valid `prev`: `CLEAN_FIRST_BOOT`/`DELETED`/`UNREADABLE`/`CORRUPT`) **and** unable
to persist. Only then can a future incarnation emit a *lower* epoch (backward
clock) than one already emitted. For a valid-intact-file persist-failure, a
DEGRADED signal + async retry suffices (self-healing). For the pathological
both-nodes-state-loss+persist-fail case, fall back to normal priority election
(a triple-fault; accept it rather than guarantee an outage). State this
explicitly — an unconditional fence trades a very narrow self-lock for a broader
availability regression.

## Nits

- **N1 — bounds-guard the marker read.** A minimal keyed frame can have
  `bodyEnd < 16`; the marker read `body[bodyEnd-16:bodyEnd-8]` must guard
  `bodyEnd >= 16` (else `hasEpoch=false`). Trivial but must be in the parse.
- **N2 — #6169 is BLOCKED-ON #5639, not merely "sequenced behind."** §3 should
  state plainly that `/engineer 6169` cannot proceed until the cross-channel auth
  owner exists (in #5639 or folded), because the epoch downgrade-gate rides on
  it. This is a scheduling fact the user needs when deciding `/engineer`.
- **N3 — election-apply after a post-commit key rotation.** §5.3 applies
  `handlePeerHeartbeat` after the admission unlock; if the key rotates in that
  gap the applied peer-RG-state is still genuine (validly K1-signed data), so
  this is acceptable — but say so, so a reader does not mistake it for a residual
  TOCTOU.
- **N4 — bounded bring-up resolve.** §5.4's synchronous bring-up persist needs a
  stated timeout (a hung disk must not block bring-up); on timeout → high-seeded
  value + DEGRADED + async retry + (state-loss-scoped) fence.

## Scope judgment

v3 is a **sound and complete design**, but the research has revealed the true
scope: a **#5639 prerequisite + an election-path change + a key-rotation recovery
runbook**, i.e. a sequenced multi-PR effort, not "add an epoch." That is a
legitimate outcome to put in front of the user: the value (closing a named,
now-more-credible residual with an O(1) total order) is real, but the cost is
higher than the issue implied. I do **not** recommend PLAN-KILL — the center is
correct and a half-fix is worse than the honest 64 bound — but the plan must
present the scope honestly so the user can choose to drive it staged, defer, or
kill on cost/benefit.

## Verdict

Every round-2 finding is resolved; the only correctness-affecting item is R1 (the
fence must be scoped to state-loss to avoid a new outage mode), plus four nits.
Once R1 is folded, this is implementable (subject to the #5639 prerequisite).

VERDICT: PLAN-NEEDS-MINOR

---

## Self-correction (post-Codex-r3, same round)

My NEEDS-MINOR missed the crux: Codex r3 proved the **volatile election fence
does not survive a crash after a failed write** — an unpersisted epoch `H` is
emitted, the peer records `(H, highCounter)`, the node crashes, and the next
incarnation re-derives the same `H` with a reset counter → rejected until it
catches the old high-water (or dual-primary). An in-memory fence cannot carry
"an unknown epoch may have escaped." The correct invariant is **persist-before-
emit**: never emit an epoch marker unless the epoch is durably persisted; on
persist-failure emit v1-no-marker (degrade this node to the ring) or fall silent
→ the peer takes over via existing timeout (fail-closed). That **eliminates the
ill-defined election fence entirely** (Codex r3 §1+§2). I also under-weighted:
the key-gen check must carry into `handlePeerHeartbeat` (peer-state/election
apply after unlock is still stale; key-publish+reset must be atomic — §3); live
empty→key activation has no epoch barrier (§4); the concrete admission algorithm
dropped the `!hasEpoch && sawEpoch → REJECT` epoch-strip gate (§5, or archived
markerless frames re-enter the churnable ring); and the `bodyEnd>=16` guard is
mandatory (short v1 frame panics).

**Corrected verdict: PLAN-NEEDS-MAJOR** — the marker + separated-nonce center
holds, but the persistence/emit invariant, key-rotation linearization, and
live-key barrier need a v4.

VERDICT: PLAN-NEEDS-MAJOR
