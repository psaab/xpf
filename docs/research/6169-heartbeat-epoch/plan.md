# #6169 — cluster/heartbeat across-reboot boot-epoch anti-replay (research plan)

**Status:** DRAFT v5 — revised after four rounds of adversarial plan review
(Codex r1–r4 + Claude SMR r1–r4, each round PLAN-NEEDS-MAJOR). Pending round-5
review. AGY infra-down.

Worktree `.claude/worktrees/6169-research`, branch `research/6169-heartbeat-epoch`,
base `origin/master` @ `11e23b49a`. **/research** — STOPS at PLAN-READY; no
production code; implementation only on `/engineer 6169`.

> **v5 changelog (what round 4 forced).** The **key-derived marker** and the
> **separated Manager send-nonce + `(epoch,counter)` total order** remain the
> confirmed correct center (all four rounds). Round 4 showed **persist-before-emit
> alone is not fail-closed**: a persist-failed was-primary node emitting markerless
> frames is rejected by a peer holding `sawEpoch` (one-way UDP partition) →
> **sustained dual-primary**. v5 introduces one **epoch-ownership hold** that
> subsumes the persist-fail response, the live-key barrier, *and* the ownership
> demote (reusing the existing kernel-upgrade hold + the never-seen/went-silent
> distinction), so the failure cases resolve cleanly: asymmetric → peer takes
> over; both-fail → safe outage (not dual-primary); sole-node → promotes. v5 also
> replaces the far-future heuristic with a **checksummed persisted epoch (trust a
> valid value, never regress)**, a **serialized read-max-write persistence
> worker** (async retry can no longer overwrite a newer durable epoch), moves
> `lastSeen` inside the gen-checked transaction, restores the **+16-byte tail
> reserve**, and requires **#5639 to drain pre-arm unauthenticated sync
> connections**.

---

## 1. Issue framing

#5477 (merged #6167) bounded the A→B→A heartbeat replay with a 64-slot
per-session ring. FIFO eviction is triggered by any never-seen session including
a replayed one, so ≥65 captured authenticated sessions sustain a forged
liveness/election drive. Round 1 sharpened it: the ring counts **sender
sessions**, freshly drawn on every heartbeat restart (routine VRF/config rebinds,
`daemon_apply_dataplane.go:435`), so the captures accumulate over ordinary
operation. #6169 wants a signed **monotonic-across-reboot boot epoch** giving a
total order so a retired incarnation can never be replayed once a newer one is
seen. Closed PR #6370 failed the gate with five findings; three plan-review
rounds then showed the complete fix is materially more coupled — a #5639
prerequisite, a persistence invariant, and a key-rotation recovery protocol.

## 2. Honest scope / value framing

Closes the named #6167 residual (a passive on-path sniffer with ≥65 captured
sessions replays a retired incarnation to refresh peer liveness / re-apply its
stale RG role). Threat model: on-path **replay** without forging (no PSK) and
without actively blocking the live peer. The cost is real — a #5639
prerequisite, a persist-before-emit path, and a coordinated key-rotation
runbook. **If reviewers judge the residual too narrow to justify this surface,
PLAN-KILL is acceptable** (§11); not recommended — the center is sound and a
half-fix is worse than the honest 64 bound.

## 3. Prerequisite and composition

- **PREREQUISITE — #5639 (OPEN, bug/security):** the auth-seen proof is split and
  transient — `HeartbeatPeerAuthSeen` dereferences the replaceable receiver
  (`peer_state.go:29`); sync auth arms `SessionSync.syncAuthedEver`
  (`sync_auth.go:415`) which `syncPeerAuthSeen` ORs in (`sync_auth.go:139`); comms
  recreation replaces `SessionSync` (`daemon_ha_sync.go:851`). #6169's epoch
  downgrade-gate rides on the same auth-seen state. **#6169 is BLOCKED-ON #5639**
  (`/engineer 6169` cannot proceed until it lands, or the two are done together).
  **#5639 acceptance criteria** (strengthened per Codex r3 + r4): one
  Manager/daemon-scoped cross-channel auth owner armed by *both* heartbeat and
  sync-auth, with a commit-time owner-generation recheck **AND active
  drain/rehandshake of any unauthenticated sync connection installed before the
  owner armed** — a recheck alone does not evict a pass-through connection whose
  auth was fixed at handshake (`sync_auth.go:329`), so it must be drained or
  re-validated per message.
- **Composes with:** #4107 (`XPFA` 52-byte trailer, unchanged), #5477/#6167 ring
  (kept for v1-migration), #5081/#5086. **Independent of held #5078.** v4 keeps
  the corrected note: #5639's owner *does* touch `sync_auth.go`'s auth-seen bit.
- **Reused:** `fullSetSeqGuard` `(incarnation,seq)` comparison (`sync_conn_gen.go:64`).
- **Persistence precedent — SNMPv3 `engineBoots`** (`agent.go:573`):
  **fail-closed on read/parse/arithmetic/write uncertainty.** v4 adopts this
  literally via persist-before-emit (§5.4), not a volatile fence.

## 4. The five findings — verified

Unchanged (all CONFIRMED): F1 rolling-upgrade split; F2 ring churn (worse — many
same-epoch sessions from routine restarts); F3 self-lock + undesigned
persistence; F4 lifecycle reset + wrong-node recovery; F5 parse ambiguity. §5
shows how v4 closes each; the resolutions were rebuilt across three rounds.

## 5. Concrete design — v4

### 5.1 Wire — key-derived, tail-anchored, MAC-verified epoch marker (F1 + F5)

`XPFA` 52-byte trailer unchanged (dissolves F1). Epoch rides immediately before
it, read from the tail after MAC verify:

```
… [ body ]  [ marker(8)=HMAC(key,"xpf-ha-boot-epoch-v2")[:8] ][ epoch(8,LE) ]  [ XPFA(4)|session(8)|counter(8)|HMAC(32) ]
```

Receiver: (1) find `XPFA` at `len-52` and **verify the HMAC first** — only a
verified frame authorizes `bodyEnd=len-52`; **the keyless path never trusts
`bodyEnd`** and parses the full legacy frame. (2) **Guard `bodyEnd ≥ 16`** (a
canonical zero-RG body is 13 bytes — a short v1 replay must not panic the slice);
then check `body[bodyEnd-16:bodyEnd-8] == HMAC(key,label)[:8]` → `hasEpoch`,
`epoch=body[bodyEnd-8:bodyEnd]`.

Robustness (round-3 confirmed): the marker is a key-derived PRF value —
domain-separated from the frame HMAC, unforgeable without the PSK, and an archived
v1 body collides only at ≈`q/2⁶⁴` (acceptable under the passive-replay model — an
attacker cannot retrofit it without breaking the outer MAC). No forward-parse
dependency, no field-cap dependency, no key-rotation rollout boundary, no
`HAProtocolVersion` change. **Never-unsigned-when-keyed preserved: a
marker-enabled frame reserves 68 tail bytes** (16 marker+epoch + 52 `XPFA`), not
52 — else a maximal frame reaches 1488 bytes while the receiver reads
`maxHeartbeatSize=1472` (Codex r4 defect). **Separate hygiene fix** (not
load-bearing): cap monitor count + name length — **decided policy: commit-time
reject (`validateChassisClusterStrict`, matching the 255-group cap) + defensive
rate-limited truncate** in the marshaler.

### 5.2 Anti-replay total order — separated state (F2)

Two distinct Manager/daemon-scoped pieces (never conflated):

- **Sender send-nonce `{session, counter}`** — created once per daemon; `counter`
  monotonic; **never reset on a key change**; reset only on a new Manager (daemon
  restart), where the epoch is strictly higher. **Counter exhaustion** is
  practically unreachable (`MaxUint64` at 10 Hz ≈ 10¹¹ years); v4 treats it as a
  hard defensive assertion (refuse to advance past `MaxUint64`) rather than a live
  epoch-rotation dance — documented as unreachable, not a runtime path.
- **Receiver `peerAdmission{ring, highEpoch, highCounter, sawEpoch, keyGen}`** —
  survives heartbeat restart; reset on daemon restart; a re-prime clears only
  `{highEpoch, highCounter, sawEpoch}`.

v2-frame guard (`fullSetSeqGuard` comparison), under the admission lock after MAC
verify: `epoch>highEpoch → advance,ACCEPT`; `epoch==highEpoch && counter>highCounter
→ advance,ACCEPT`; else REJECT. `(epoch,counter)` is a total order because
`epoch` (persisted, strictly increasing per daemon — guaranteed by §5.4's
**persist-before-emit**) distinguishes incarnations and `counter` (Manager-scoped,
survives heartbeat restart) distinguishes frames. The 64-ring is used **only** for
v1 (`hasEpoch==false`) frames from a not-yet-upgraded peer.

### 5.3 Receiver decision — one linearized, key-gen-checked transaction

```
info := parseAuthTrailer(frame); (keyGen,key) := m.authKeySnapshot()
macOK := info.present && len(key)>0 && verifyMAC(frame,key)
bodyEnd := (macOK ? len-52 : len);  read the marker only if macOK && bodyEnd>=16
pkt := UnmarshalHeartbeat(frame[:bodyEnd]); hasEpoch,epoch := parseMarker(...) if macOK
… clusterID / duplicate-node checks …
m.mu.Lock()                                                  // ONE lock for admission + apply (no nesting)
  if keyGen != m.keyGen { m.mu.Unlock(); DROP }              // key rotated since verify → discard
  if macOK && !hasEpoch && sawEpoch { m.mu.Unlock(); noteRejectedFromPeer(); REJECT "epoch strip" }
  accept := macOK ? (hasEpoch ? admitEpoch(epoch,counter) : ring.admit(session,counter))
                  : baseAuthDecision(...)
  if !accept { m.mu.Unlock(); noteRejectedFromPeer(); REJECT }
  markAuthSeen(); if hasEpoch { sawEpoch=true }
  lastSeen = now                                              // INSIDE the gen-checked txn (Codex r4)
  handlePeerHeartbeatLocked(pkt)                              // peer-alive/RG/election, m.mu already held
m.mu.Unlock()
```

- **Single `m.mu` transaction** (Codex r4): the whole admit → `lastSeen` →
  peer-state/election apply is one critical section under `m.mu`, checked against
  `keyGen` at the top. A `handlePeerHeartbeatLocked` variant avoids the reentrant
  `m.mu` the v4 sketch had. `lastSeen` is set *inside* the transaction, so a
  gen-mismatch drop never leaves `lastSeen≠0` with `peerAlive=false` (which would
  strand a fresh node — Codex r4).
- **Key-publish + admission-reset is one atomic step** (re-prime/§5.5) also under
  `m.mu` and bumping `keyGen`, so no frame is admitted between publish and reset.
  A monotonic `keyGen` counter is ABA-safe (K1→K2→K1).
- **Epoch-strip gate** (`!hasEpoch && sawEpoch → REJECT`) keeps a markerless frame
  out of the churnable ring after a marker has been seen.
- **`noteRejectedFromPeer()`** records a "frame arrived from the peer but was
  rejected" timestamp — distinct from `lastSeen` — consumed by the ownership hold
  (§5.4) to tell a *present-but-unverifiable* peer from a *genuinely-absent* one.

### 5.4 Epoch persistence + the epoch-ownership hold (F3 + F4; unifies the fence)

**Persistence rules.**
- **Persist-before-emit:** a frame carries a marker only if that epoch is durably
  persisted (`markerEnabled`), so no unpersisted epoch escapes (round-3 crash
  schedule impossible).
- **Checksummed, never-regress:** the epoch file stores `epoch || crc`. On read, a
  **crc-valid** value is TRUSTED and never regressed below — even if it is far in
  the future (a legitimate forward clock); only a **crc-invalid / absent** value
  is state-loss → seed from the clamped wall clock. This **drops the far-future
  heuristic**, which Codex r4 showed *regresses* a legitimate forward-clock value
  (boot far-forward → persist `Tfuture` → correct clock → the old heuristic
  rejected intact `Tfuture` and emitted a lower `Treal` → peer rejects →
  dual-primary). The residual is now only a genuine **crc-invalid corruption /
  deletion** *and* a backward clock — operator-recoverable (§5.5).
- **Serialized read-max-write worker** (Codex r4): all persistence goes through a
  single worker; each write **re-reads the durable value and writes
  `max(durable, candidate)`**, so a stale async retry (G1 chose C1, slept; G2 wrote
  C2>C1) can never overwrite C2 with C1. `markerEnabled` is set only for the
  current `keyGen` after a successful write. Async retry uses bounded backoff off
  the send path (never a per-100 ms fsync).

**The epoch-ownership hold** (subsumes the persist-fail response, the live-key
barrier, and the ownership demote):

> **Invariant:** a node may hold a redundancy group PRIMARY only if it can emit a
> durably-persisted marker for its current `keyGen`. While it cannot
> (`markerEnabled==false`: persist-failed, resolving, or a live key-enable in
> progress), it takes an **epoch-ownership hold** — reusing the existing
> kernel-upgrade hold mechanism (`SetKernelUpgradeHold`: demote-if-primary + guard
> every promotion path, `kernel_selfrecover.go:52`, `election.go:44/405`).

Release semantics — the piece that makes the failure cases correct:
- A held node **does NOT promote via the went-silent timeout** (`handlePeerTimeout`).
  It promotes **only** via the never-seen path (`handlePeerNeverSeen` — the peer
  *never existed*, i.e. a single-node deployment) OR when it clears the hold
  (persist succeeds).
- The hold clears when `markerEnabled` becomes true (persist recovers /epoch
  resolves) → the node re-enters normal election and emits its (higher, durable)
  marker; the peer re-anchors.

This yields exactly-one-primary in every case (verified against the code paths):
- **Asymmetric (A persist-fails, B healthy):** A holds (demoted); B is not held,
  gets no *accepted* A frames, times A out via the normal went-silent path and
  **promotes**. → B primary, A secondary. ✓
- **Both-fail (both hold, both hold a prior epoch):** each rejects the other's
  markerless frames, but `noteRejectedFromPeer()` shows the peer is *present*
  (frames arriving), so neither reaches the never-seen path and **neither
  promotes** → a **safe outage** (not dual-primary) until a disk recovers or the
  operator re-baselines via §5.5 key rotation. A correlated double-disk fault; an
  opt-in "stay-primary-degraded" override may be offered. ✓
- **Sole node (persist-fail, no peer ever):** the never-seen path fires after the
  grace and it **promotes** — no receiver to protect. ✓

This also **subsumes the live key-enable barrier** (Codex r4): a Manager may boot
unkeyed and enable auth live, and heartbeat/timeout/readiness/monitor all elect
independently — but while the epoch is unresolved for the new `keyGen` the node is
under the ownership hold, which guards *every* promotion path (that is exactly what
`SetKernelUpgradeHold` already does). So there is no separate barrier to slot
before `UpdateConfig`'s election; the hold is armed the instant `markerEnabled`
is false for the live key and cleared when the epoch resolves. The resolve itself
runs on the serialized worker off `m.mu` (no durable I/O under the config lock).

### 5.5 Re-prime + coordinated recovery (F4)

Re-prime clears only `{highEpoch, highCounter, sawEpoch}` (keep `peerAuthSeen`,
the ring, the sender nonce — a rolled-back v1 node still signs `XPFA`, so cleartext
enforcement must stay). **Race-free recovery = coordinated cluster-wide rotation
to a NEVER-USED key** (config-synced PSK): *isolate the affected node → (roll back
if applicable) → install the new key on **both** nodes → the atomic keyGen-bump
resets each node's floor (§5.3) → reconnect.* A never-used key makes archived
captures unverifiable; the atomic keyGen-bump+reset prevents an in-flight old-key
frame re-arming. A one-sided key change (MAC mismatch → split) is called out as
unsafe. This same rotation is the operator recovery for the both-fail outage and
the crc-invalid+backward-clock self-lock.

## 6. Honest residuals

- **Post-restart / post-re-prime single-admit window** (bounded): after a receiver
  daemon restart or a re-prime, `highEpoch=0`; a retired frame can be admitted
  **once** and cause a transient election effect before the live higher-epoch
  frame repairs the floor. The epoch closes the **sustained** replay; fully
  closing the single-admit needs disk-persisting the **receiver** floor (named
  follow-up, adds its own cross-restart self-lock).
- **crc-invalid corruption / deletion ∧ backward-clock self-lock** (§5.4): with
  the checksummed-trust rule a legitimate forward clock no longer regresses; the
  only remaining self-lock needs genuine state corruption/deletion *and* a
  backward clock — operator-recoverable via cluster key rotation (§5.5).
- **Correlated double persist-failure → safe outage** (§5.4): both nodes losing
  durable epoch state simultaneously holds both secondary (no dual-primary) until
  a disk recovers or the operator re-baselines. A triple-fault; optional opt-in
  "stay-primary-degraded" override.

## 7. Multiple Path Options (final)

- **Wire:** key-derived tail-anchored marker (A, chosen) vs forward-parsed TLV
  (B, desyncs on archived bodies) vs v2 trailer / version bump (C, F1/blast-radius).
- **Same-epoch guard:** separated nonce + `(epoch,counter)` (A) vs
  shared/reset-on-key nonce (B, breaks the order) vs bigger ring (C, moves the
  constant).
- **Persist-failure:** **persist-before-emit + the epoch-ownership hold
  (A, chosen — reuses the kernel-upgrade hold; held nodes promote only via the
  never-seen/single-node path, giving asymmetric→takeover, both-fail→safe outage,
  sole-node→promote)** vs markerless + peer-timeout alone (B, one-way UDP
  partition → dual-primary — round-4 killer) vs volatile election fence (C, does
  not survive a crash — round-3 killer).
- **Persist monotonicity:** **checksummed-trust + never-regress + serialized
  read-max-write (A, chosen)** vs far-future rejection (B, regresses a legit
  forward clock) vs unserialized async retry (C, overwrites a newer durable value).

## 8. Staging

- **Stage −1 (PREREQ = #5639):** one Manager/daemon-scoped cross-channel auth
  owner (heartbeat + sync-auth) with the commit-time owner-generation recheck.
- **Stage 0:** Manager-scope the sender send-nonce; decided cap policy. Composes
  with Stage −1; closes routine-restart churn (no wire change; an old peer still
  draws new sessions until it upgrades).
- **Stage 1 (wire change):** key-derived marker + `(epoch,counter)` guard +
  persist-before-emit init (bring-up + live key-enable barrier) + key-gen
  linearization + coordinated re-prime. Closes the daemon-reboot vector.
  −1 + 0 + 1 = the complete fix.

## 9. Public API preservation

Unchanged: `MarshalHeartbeat`, `MarshalHeartbeatAuth`, `heartbeatAuthTrailer`,
`verifyHeartbeatMAC`, `heartbeatAuthReplay.admit`, `CurrentHAProtocolVersion`,
`SessionSyncWireVersion`, #5078's handshake. `UnmarshalHeartbeat` called on
`frame[:bodyEnd]` (verified); epoch parsed by a separate tail-reader.
`HeartbeatPacket` gains `BootEpoch uint64` (display). New: marker derive/parse,
`admit*`, `peerAdmission` + sender nonce + `epochState` + `keyGen` on Manager,
`resolveEpoch` (persist-before-emit), live-key barrier. #5639's owner touches
`sync_auth.go`'s auth-seen bit.

## 10. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (bring-up / key-enable / failover) | **HIGH** | Persist-before-emit + live-key barrier + key-gen recheck touch the send/election path; `make test-failover` (v4+v6) + mixed-version + persist-fail-fail-closed + key-rotation-reprime harnesses mandatory. |
| HA availability (self-lock / ownership) | **MED** | Persist-before-emit removes the crash-escape; the ownership hold prevents the markerless dual-primary; residual = crc-invalid∧backward-clock self-lock + correlated double-fault safe-outage, both operator-recoverable. |
| Wire/interop | **LOW** | Unchanged 52-byte `XPFA`; key-derived marker; old receiver ignores it; `bodyEnd≥16` guard. |
| Security (replay/downgrade) | **LOW-MED** | Total order + key-gen linearization + epoch-strip gate + cross-channel owner; bounded single-admit residual documented. |
| Coupling / scope | **MED-HIGH** | Hard #5639 prereq + persist/election-integration — a sequenced multi-PR effort. |

## 11. Out of scope / PLAN-KILL

Disk-persisting the receiver floor (closes the single-admit window) — follow-up.
Retiring the v1 ring — kept for migration. **PLAN-KILL?** Legitimate only if the
residual is judged too narrow for the #5639 prereq + persist-before-emit +
key-rotation runbook. Not recommended: the residual is real and more credible
post-review, the center is sound, a half-fix is worse than the honest 64 bound.
Realistic path: sequence behind #5639; land Stage 0 (restart churn) before Stage 1.

## 12. Open questions for round-5 (each invitable to PLAN-KILL)

1. **Epoch-ownership hold correctness.** Does "a held node promotes only via the
   never-seen (single-node) path, never via the went-silent timeout" give
   exactly-one-primary in all three cases (asymmetric → takeover, both-fail →
   safe outage, sole-node → promote), and does `noteRejectedFromPeer()` correctly
   distinguish present-but-unverifiable from genuinely-absent at every election
   site (`handlePeerTimeout` / `handlePeerNeverSeen` / readiness / monitor)?
2. **Hold ↔ kernel-hold reuse.** Can the epoch-ownership hold reuse
   `SetKernelUpgradeHold`/`ClearKernelUpgradeHold` cleanly (they interact with a
   real kernel-upgrade hold — is a two-source hold well-defined), or does it need
   its own hold flag with the same demote+guard semantics?
3. **Checksummed persistence.** Is "trust a crc-valid value, never regress; only
   crc-invalid/absent is state-loss" the right rule, and does the serialized
   read-max-write worker fully prevent an async retry regressing the durable
   floor across a key generation?
4. **Single `m.mu` transaction.** Is folding admit + `lastSeen` +
   `handlePeerHeartbeatLocked` into one `m.mu` critical section (with a locked
   handler variant) free of the reentrancy and stale-`lastSeen` defects, and does
   holding `m.mu` across the (non-I/O) admission add unacceptable contention at
   ~10 Hz?
5. **#5639 drain.** Is "drain/rehandshake pre-arm unauthenticated sync
   connections" the right acceptance bar, and does it belong in #5639 or #6169
   Stage −1?
6. **Scope / readiness.** After five rounds the center is validated and the
   failure-mode state machine is now concretely specified — is v5 PLAN-READY to
   `/engineer` (sequenced behind #5639, Stage 0 before Stage 1), or does the
   remaining intricacy argue for re-scoping / PLAN-KILL on cost/benefit?

---

### Appendix — files in blast radius (for /engineer)

`pkg/cluster/heartbeat.go` (marker derive/write/parse, +68 tail reserve,
MAC-before-`bodyEnd`, `bodyEnd≥16`, `admit*` with the epoch-strip gate, `readLoop`
single `m.mu` transaction + `lastSeen`-inside + `noteRejectedFromPeer` +
`handlePeerHeartbeatLocked`); `pkg/cluster/heartbeat_epoch.go` new (checksummed
persist, serialized read-max-write worker, `markerEnabled`); `pkg/cluster/manager.go`
(`peerAdmission` + sender nonce + `epochState` + `keyGen`; epoch-ownership hold
reusing/paralleling the kernel hold; cross-channel owner via #5639);
`pkg/cluster/election.go` / `kernel_selfrecover.go` (held nodes promote only via
never-seen); `pkg/cluster/group_state.go` (atomic keyGen-bump+reset on key change);
`pkg/cluster/heartbeat_manager.go` (`buildHeartbeat` reads resolved epoch; marker
gated on `markerEnabled`); `pkg/config` (commit-time monitor/name caps);
`pkg/cluster/README.md` + this doc. Tests: F1 mixed-version both ways; **F2 65
same-epoch sessions must not churn the guard**; F3 persist-fail→ownership-hold
(asymmetric takeover, both-fail safe-outage, sole-node promote),
crash-after-would-be-emit (no escape), crc-invalid+backward-clock recovery,
forward-clock-correction NO regression, async-retry no durable regress; F4 key-gen
TOCTOU (K1-verify/K2-reset/stale drop + `lastSeen` not stranded), live key-enable
under the hold, epoch-strip reject, coordinated re-prime; F5 archived 256-byte-name
body → no false marker, short v1 body no panic, keyless full-frame parse.
