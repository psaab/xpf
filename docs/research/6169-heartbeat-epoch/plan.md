# #6169 — cluster/heartbeat across-reboot boot-epoch anti-replay (research plan)

**Status:** DRAFT v4 — revised after three rounds of adversarial plan review
(Codex r1–r3 + Claude SMR r1–r3, each round PLAN-NEEDS-MAJOR). Pending round-4
review. AGY infra-down.

Worktree `.claude/worktrees/6169-research`, branch `research/6169-heartbeat-epoch`,
base `origin/master` @ `11e23b49a`. **/research** — STOPS at PLAN-READY; no
production code; implementation only on `/engineer 6169`.

> **v4 changelog (what round 3 forced).** The **key-derived marker** and the
> **separated Manager send-nonce + `(epoch,counter)` total order** are the
> confirmed correct center (both reviewers). The round-3 killer: a **volatile
> election fence cannot survive a crash after a failed persist** — an unpersisted
> epoch escapes to the peer and the next incarnation re-derives it with a reset
> counter → self-lock/dual-primary. v4 therefore **drops the election fence** and
> adopts **persist-before-emit + fail-closed**: a node emits an epoch marker only
> if that epoch is durably persisted; on persist failure it emits no marker and
> the peer's existing timeout/takeover handles it. v4 also: linearizes the
> **key-generation** check *through* `handlePeerHeartbeat` and makes
> key-publish+admission-reset one atomic transaction; adds a **live empty→key
> enable barrier**; restores the explicit **`!hasEpoch && sawEpoch → REJECT`**
> epoch-strip gate; and adds the **`bodyEnd ≥ 16`** bounds guard.

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
  **#5639 acceptance criteria** (strengthened per Codex r3): one Manager/daemon-
  scoped cross-channel auth owner armed by *both* heartbeat and sync-auth, with a
  **commit-time owner-generation recheck** (or active draining of pre-arm
  cleartext connections) so a cleartext sync handshake that read "not yet armed"
  cannot install a long-lived unauthenticated connection after the owner arms.
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
`HAProtocolVersion` change. **Separate hygiene fix** (not load-bearing): cap
monitor count + name length — **decided policy: commit-time reject
(`validateChassisClusterStrict`, matching the 255-group cap) + defensive
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

### 5.3 Receiver decision — one linearized transaction, key-gen carried through

```
info := parseAuthTrailer(frame); (keyGen,key) := m.authKeySnapshot()
macOK := info.present && len(key)>0 && verifyMAC(frame,key)
bodyEnd := (macOK ? len-52 : len);  guard bodyEnd>=16 for the marker read
pkt := UnmarshalHeartbeat(frame[:bodyEnd]); hasEpoch,epoch := parseMarker(frame,bodyEnd,key) if macOK
… clusterID / duplicate-node checks …
admission.Lock()
  if keyGen != m.currentKeyGen() { admission.Unlock(); DROP }              // key rotated mid-verify → discard
  // base auth (via #5639 owner): reject bad MAC / cleartext-downgrade
  if macOK && !hasEpoch && sawEpoch { admission.Unlock(); REJECT "epoch strip" }   // <-- restored gate (F4)
  accept := macOK ? (hasEpoch ? admitEpoch(epoch,counter) : ring.admit(session,counter))
                  : baseAuthDecision(...)                                   // no key / dual-accept window
  if accept && macOK { markAuthSeen(); if hasEpoch { sawEpoch=true } }
  if accept { lastSeen=now }
admission.Unlock()
if accept { m.mu.Lock(); if m.currentKeyGen()==keyGen { handlePeerHeartbeat(pkt) }; m.mu.Unlock() }  // recheck gen (Codex r3 §3)
```

- **Key-gen carried through** (Codex r3 §3): `handlePeerHeartbeat` (peer-alive,
  peer-RG replacement, election) runs under `m.mu` and **rechecks `keyGen`** — a
  frame verified under K1 does not apply peer-state/election after a K2 reset.
- **Key-publish + admission-reset is one atomic transaction** (Codex r3 §3):
  the re-prime resets the floor **and** bumps `keyGen` under the admission lock in
  a single step, so no frame is admitted between publish and reset (which would
  otherwise leave that frame's watermark erased and replayable).
- **Epoch-strip gate restored** (Codex r3 §5): a MAC-valid markerless frame after
  `sawEpoch` is REJECTED — it never re-enters the churnable ring.
- Dedicated admission lock; `handlePeerHeartbeat` (which takes `m.mu`) is not
  nested under it.

### 5.4 Epoch persistence — persist-before-emit + fail-closed (F3; drops the fence)

**Invariant (the round-3 correction): a node includes an epoch marker in a frame
only if that epoch is DURABLY PERSISTED.** An unpersisted epoch is never emitted,
so a crash-after-failed-write can never leak an epoch the next incarnation cannot
reproduce (Codex r3 §1's schedule is impossible).

Resolution (at bring-up when keyed, and at live key-enable — §5.4b):

```
cls := classify(readFile(path))   // VALID(prev) | NONE(ENOENT) | UNREADABLE | CORRUPT
prev := (cls==VALID && inDomain(prev)) ? prev : 0     // fail-closed on any uncertainty (SNMP discipline)
now  := clampedWallClockNanos()                       // reject <=0 / overflow; reject prev>now+MARGIN as corrupt
cand := max(prev+1, now)                              // checked overflow → now
if writeDurable(path, cand) == ok:  epoch=cand; markerEnabled=true          // persisted → may emit marker
else:                               markerEnabled=false; asyncRetryPersist()  // NOT persisted → emit NO marker
```

Fail-closed behavior when `markerEnabled==false` (persist failed / uncertain):
- The sender emits **v1-style frames with no marker** (still `XPFA`-signed).
- Peer that never recorded an epoch from this node → accepts via the ring (this
  node degrades to the ring bound — honest, and now *true* because no epoch is
  emitted, unlike v3's false "degrades to ring" claim).
- Peer that HAS recorded an epoch (`sawEpoch`) → rejects the markerless frames as
  epoch-strip → times this node out → **takes over** (existing behavior). The
  node is fail-closed-absent until the async persist succeeds; then it emits the
  (higher, now-durable) epoch and the peer re-anchors. **No election fence is
  needed** — the peer's normal timeout/takeover is the fail-closed response, and
  a sole node (no peer to protect) simply stays primary emitting no marker.
- `classify` cannot distinguish first-boot from a deleted file (both `ENOENT`);
  v4 does not try — persist-before-emit makes the distinction moot: either the
  seed persists (and is emitted, monotone via the `+1` floor / high `now`) or it
  does not (and no epoch is emitted). The **irreducible residual** is genuine
  state-loss (a previously-persisted high value is deleted) **and** a backward
  clock — a lower epoch is then persisted and emitted → the peer rejects it →
  operator-recoverable via the §5.5 cluster key rotation. This is the same narrow
  self-lock all monotonic-epoch schemes carry; it is now the *only* residual.
- Async persist retry uses **bounded backoff off the send path** (never a
  per-100 ms fsync).

### 5.4b Live key-enable barrier (Codex r3 §4)

A Manager may boot unkeyed and enable auth live (`UpdateConfig` publishes the key
and immediately elects; the sender fetches the key each tick). v4 gates marker
emission on a per-key-generation "epoch resolved" barrier: **on an empty→set key
transition, resolve+persist the epoch (§5.4) for that `keyGen` BEFORE the sender
emits any marker and BEFORE the election `UpdateConfig` runs.** Until the barrier
completes, the sender emits markerless (v1) frames — which is safe because the
peer has not yet seen a marker from this node under the new key. (Equivalently:
resolve the epoch for every Manager at construction; v4 prefers the lazy
key-gated barrier so an unkeyed cluster does no epoch I/O.)

### 5.5 Re-prime + coordinated recovery (F4)

Re-prime clears only `{highEpoch, highCounter, sawEpoch}` (keep `peerAuthSeen`,
the ring, the sender nonce — a rolled-back v1 node still signs `XPFA`, so cleartext
enforcement must stay). **Race-free recovery = coordinated cluster-wide rotation
to a NEVER-USED key** (config-synced PSK) executed as: *isolate the affected node
→ (roll back if applicable) → install the new key on **both** nodes → the
`keyGen` bump atomically resets each node's floor (§5.3) → reconnect.* A never-used
key makes archived captures unverifiable; the atomic keyGen-bump+reset prevents an
in-flight old-key frame re-arming. A one-sided key change (MAC mismatch → split)
is called out as unsafe.

## 6. Honest residuals

- **Post-restart / post-re-prime single-admit window** (bounded): after a receiver
  daemon restart or a re-prime, `highEpoch=0`; a retired frame can be admitted
  **once** and cause a transient election effect before the live higher-epoch
  frame repairs the floor. The epoch closes the **sustained** replay; fully
  closing the single-admit needs disk-persisting the **receiver** floor (named
  follow-up, adds its own cross-restart self-lock).
- **State-loss ∧ backward-clock self-lock** (§5.4): the only remaining self-lock,
  operator-recoverable via cluster key rotation.

## 7. Multiple Path Options (final)

- **Wire:** key-derived tail-anchored marker (A, chosen) vs forward-parsed TLV
  (B, desyncs on archived bodies) vs v2 trailer / version bump (C, F1/blast-radius).
- **Same-epoch guard:** separated nonce + `(epoch,counter)` (A) vs
  shared/reset-on-key nonce (B, breaks the order) vs bigger ring (C, moves the
  constant).
- **Persist-failure:** **persist-before-emit + fail-closed (A, chosen — the peer's
  timeout is the fail-closed)** vs volatile election fence (B, does not survive a
  crash — round-3 killer) vs status-reason-only (C, does not gate election).

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
| HA availability (self-lock) | **MED** | Reduced to state-loss∧backward-clock; operator-recoverable. Persist-before-emit removes the crash-across-emit self-lock. |
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

## 12. Open questions for round-4 (each invitable to PLAN-KILL)

1. **Persist-before-emit completeness.** Does "emit a marker only if durably
   persisted; else markerless + peer-takeover" fully remove the crash-across-emit
   self-lock, and is "markerless → peer with `sawEpoch` takes over" the right
   fail-closed (vs falling fully silent)? Any schedule where an unpersisted epoch
   still escapes?
2. **Live key-enable barrier.** Is gating marker emission on a per-`keyGen`
   "epoch resolved" barrier sufficient given `UpdateConfig` elects immediately
   after publishing the key, and does the barrier compose with the async persist
   retry without blocking `UpdateConfig`?
3. **Key-gen linearization.** Does carrying `keyGen` into `handlePeerHeartbeat`
   (recheck under `m.mu`) + atomic keyGen-bump-with-reset fully close the
   admit-then-reset-then-apply and publish-before-reset windows?
4. **#5639 owner acceptance.** Is "one cross-channel owner + commit-time
   owner-generation recheck / cleartext drain" the right bar, and can #6169's
   epoch state cleanly ride it?
5. **Residual acceptance.** Is the state-loss∧backward-clock self-lock (operator-
   recoverable) + the bounded single-admit window an acceptable floor for
   PLAN-READY, or does the receiver-floor persistence need to be in Stage 1?
6. **Scope.** Given the accumulated coupling, is this PLAN-READY to `/engineer`
   (sequenced behind #5639), or should it be re-scoped / PLAN-KILLed on
   cost/benefit?

---

### Appendix — files in blast radius (for /engineer)

`pkg/cluster/heartbeat.go` (marker derive/write/parse, MAC-before-`bodyEnd`,
`bodyEnd≥16`, `admit*` with the epoch-strip gate, `readLoop` reorder + key-gen
carry); `pkg/cluster/heartbeat_epoch.go` new (`resolveEpoch` persist-before-emit +
classify + async retry); `pkg/cluster/manager.go` (`peerAdmission` + sender nonce
+ `epochState` + `keyGen`; cross-channel owner via #5639); `pkg/cluster/group_state.go`
(atomic keyGen-bump+reset on key change; live key-enable barrier);
`pkg/cluster/heartbeat_manager.go` (`buildHeartbeat` reads resolved epoch; marker
gated on `markerEnabled`); `pkg/config` (commit-time monitor/name caps);
`pkg/cluster/README.md` + this doc (persist-before-emit, key-rotation runbook,
residuals). Tests: F1 mixed-version both ways; **F2 65 same-epoch sessions must
not churn the guard**; F3 persist-fail→markerless→peer-takeover, crash-after-
would-be-emit (no escape), state-loss∧backward-clock operator-recovery; F4 key-gen
TOCTOU (K1-verify/K2-reset/stale drop), live key-enable barrier, epoch-strip
reject, coordinated re-prime; F5 archived 256-byte-name body → no false marker,
short v1 body no panic, keyless full-frame parse.
