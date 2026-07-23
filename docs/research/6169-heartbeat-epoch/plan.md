# #6169 — cluster/heartbeat across-reboot boot-epoch anti-replay (research plan)

**Status:** DRAFT v3 — revised after two rounds of adversarial plan review
(Codex r1+r2 and Claude SMR r1+r2, both PLAN-NEEDS-MAJOR each round). Pending
round-3 review. AGY infra-down.

Research worktree: `.claude/worktrees/6169-research`, branch
`research/6169-heartbeat-epoch`. Base: `origin/master` @ `11e23b49a`.
**/research** deliverable — STOPS at PLAN-READY; no production code touched;
implementation begins only on `/engineer 6169`.

> **v3 changelog (what rounds 1–2 forced).** The `(epoch,counter)` lexicographic
> guard is the confirmed **correct center** (both reviewers). Everything around
> it was rebuilt:
> - **Wire discriminator** is now a **key-derived, tail-anchored marker** read
>   *after* MAC verification (v2's forward-parsed TLV could be desynced by an
>   archived/uncapped v1 body that the unchanged PSK still authenticates forever).
> - **Sender send-nonce is separated from receiver admission state** and is
>   **never reset on a key change** (v2 conflated them → repeated `(E,1)` broke
>   the total order).
> - **Persist-failure is an election FENCE**, not a status reason (readiness does
>   not demote a primary; the peer-dead path bypasses it); the epoch resolves at
>   **bring-up before the first election**, not lazily at first send.
> - **Re-prime clears only the epoch floor**, carries a **key-generation stamp**
>   to close a verify-under-K1 / reset-under-K2 / commit-stale TOCTOU, and the
>   recovery is a **coordinated cluster-wide never-used-key rotation**.
> - **#6169 is sequenced behind #5639** (a real prerequisite): its
>   cross-channel auth owner must be Manager/daemon-scoped; the epoch admission
>   state joins it. This is a decision, not an open question.
> - **Honest framing:** the epoch closes the *sustained* replay; a bounded
>   post-restart/re-prime window can admit one retired frame (transient election
>   effect), fully closed only by disk-persisting the receiver floor (follow-up).

---

## 1. Issue framing

#5477 (merged #6167) bounded the A→B→A heartbeat replay with a 64-slot
per-session watermark ring. The bound is not absolute: FIFO eviction is
triggered by any never-seen session including a **replayed** one, so an attacker
holding **≥65** distinct authenticated captures can churn the ring by replay
alone and sustain a forged liveness/election drive. Round-1 review sharpened the
threat: the ring counts **sender sessions**, and a fresh session is drawn on
every heartbeat restart, which fires on **routine VRF/config rebinds**
(`daemon_apply_dataplane.go:435`) — so the ≥65 captures accumulate over ordinary
operation, not a lifetime of reboots. #6169 asks for the complete fix: a signed
**monotonic-across-reboot boot epoch** giving a total order so a retired
incarnation can never be replayed once a newer one is seen.

The first implementation (**closed PR #6370**) failed the merge gate with five
findings; two rounds of plan review then showed the fix is materially more
coupled than "add an epoch" — it is entangled with the auth-owner lifecycle
(#5639), the bring-up election sequence, and a key-rotation recovery protocol.
This v3 captures the full converged design.

## 2. Honest scope / value framing

- **What the win is.** Closes the named #6167 residual — a passive on-path
  sniffer that has captured ≥65 authenticated sessions (accumulated over routine
  restarts) can today replay a retired incarnation to refresh peer liveness and
  re-apply its stale RG role/priority. The `(epoch,counter)` total order rejects
  every retired frame with O(1) state.
- **Threat model.** On-path attacker that can **replay** captured authenticated
  frames but cannot forge/mint (no PSK) and does **not** actively block the live
  peer. (An attacker who can also block the live peer is strictly stronger than
  #4107/#5477 defend against — see the honest residual, §6.)
- **Cost/complexity honesty.** v3 is a **multi-part, #5639-dependent** effort
  with an election-fence and a coordinated recovery runbook — larger than the
  issue implied. **If reviewers judge the residual too narrow to justify this
  surface, PLAN-KILL is acceptable** (§11). We do not recommend it: the residual
  is real and *more* credible post-review, the center is sound, and shipping a
  half-fix (v1/v2's equal-epoch churn, unsafe recovery, undefined persist-failure)
  would be worse than the honest 64 bound.

## 3. Prerequisite and composition

- **PREREQUISITE — #5639 (OPEN, bug/security):** "replaceable sync-auth owner
  accepts unsigned heartbeat/first-sync frame." The auth-seen proof is split and
  transient: `HeartbeatPeerAuthSeen` dereferences the *replaceable* receiver
  (`peer_state.go:29`), sync auth arms `SessionSync.syncAuthedEver`
  (`sync_auth.go:415`) which `syncPeerAuthSeen` ORs in (`sync_auth.go:139`), and
  full comms recreation replaces `SessionSync` (`daemon_ha_sync.go:851`). #6169's
  epoch downgrade-gate has the **same lifecycle bug**. **Decision:** #6169
  **sequences behind #5639**, which must land a single **Manager/daemon-scoped
  cross-channel auth owner** armed by *both* heartbeat and sync-auth and
  surviving comms recreation. #6169's `{highEpoch, highCounter, sawEpoch}` and
  the Manager sender-nonce join that owner. (If the project prefers, the
  cross-channel owner can be built inside #6169 and #5639 marked resolved-by —
  but it is one change either way, not "leave it open.")
- **Composes with (not restructures):** #4107 auth (`XPFA` 52-byte trailer,
  unchanged), #5477/#6167 ring (kept for v1-migration frames), #5081/#5086.
- **Independent of held #5078** (session-sync PSK handshake) — verified; but note
  §3's cross-channel owner *touches* `sync_auth.go`'s auth-seen bit, so v3
  **retracts** v2's "`sync_auth.go` unchanged" claim (that was wrong — #5639's
  fix necessarily touches it). #6169 does not touch #5078's reflected-nonce
  handshake.
- **Reused primitive:** `fullSetSeqGuard` (`sync_conn_gen.go:64`) — the
  `(incarnation, seq)` lexicographic comparison (NOT its bulk-re-prime reset).
- **Persistence precedent:** SNMPv3 `engineBoots` (`pkg/snmp/agent.go`) —
  load/increment/persist once at init, **fail-closed to the ceiling + refuse
  authenticated traffic until re-discovery** on corruption. §5.4 adapts this: the
  heartbeat cannot refuse to send (it drives liveness), so the analog is a high
  seed + an **election fence** + operator re-prime.

## 4. The five findings — verified firsthand

Unchanged from v2 (all CONFIRMED): F1 rolling-upgrade split (PR#6370's
unconditional 60-byte `XPFE` trailer → v1 keyed receiver rejects → dual-primary);
F2 ring churn — worse than first realized, because the epoch is daemon-scoped
while `session`/`counter` are transient (reset on every heartbeat restart), so
many sessions share one epoch and churn the ring; F3 self-lock + undesigned
persist/recovery; F4 lifecycle reset + wrong-node rollback recovery; F5 parse
ambiguity (and v1's residual-byte replacement re-introduced it via uncapped
uint8 monitor count / name length). See §5 for how v3 closes each.

## 5. Concrete design — v3

### 5.1 Wire — key-derived, tail-anchored, MAC-verified epoch marker (F1 + F5)

The `XPFA` **52-byte** trailer stays byte-for-byte unchanged (dissolves F1: a v1
receiver still finds it at `len-52`, verifies `data[:len-32]`, `admit()`s, and
ignores the body it does not parse). The epoch rides **immediately before the
trailer**, read from the tail — never by forward-parsing the variable-length
legacy body:

```
… [ body: header|groups|monitors|version ]                       ← MAC-covered
  [ marker(8) = HMAC(key,"xpf-ha-boot-epoch-v2")[:8] ][ epoch(8, LE) ]   ← #6169, MAC-covered
  [ "XPFA"(4) ][ session(8) ][ counter(8) ][ HMAC-SHA256(32) ]   ← unchanged #4107 trailer
```

Receiver order (closes F5 + the keyless-`bodyEnd` regression Codex r2 found):

1. Locate `XPFA` at `len-52` **and verify the HMAC first**. Only a MAC-verified
   frame authorizes `bodyEnd = len-52`. **The keyless path (no local key) never
   trusts `bodyEnd`** — it parses the full legacy frame, because an unkeyed body
   can naturally place `"XPFA"` bytes at `len-52`.
2. After MAC verify, check `body[bodyEnd-16 : bodyEnd-8] == HMAC(key,
   "xpf-ha-boot-epoch-v2")[:8]`. If it matches, `epoch = body[bodyEnd-8:bodyEnd]`
   and `hasEpoch=true`; else `hasEpoch=false`.

Why this is robust where v2's TLV was not:

- **Key-derived.** An old/archived v1 frame (uncapped marshaler, valid under the
  unchanged PSK forever) cannot carry the correct 8-byte marker except with
  probability 2⁻⁶⁴; an attacker cannot forge it (needs the key, and the marker is
  MAC-covered). So detection does **not** depend on canonicalizing legacy bodies
  — it needs no field caps to be *sound*, and needs no key-rotation rollout
  boundary. (Codex r2 §2 fully resolved.)
- **Tail-anchored + MAC-gated.** No forward-parse desync is possible (Codex r2's
  256-byte-name counter-example cannot fabricate a key-derived marker), and
  `bodyEnd` is only trusted after verification.
- **No `HAProtocolVersion` change** → no session-sync/RG-transfer blast radius
  (verified: `SessionSyncWireVersion = CurrentHAProtocolVersion`).
- **Never-unsigned-when-keyed** preserved (+16 bytes into the tail reserve).

**Separate hygiene fix (not load-bearing for detection):** cap monitor count and
interface-name length. **Decided policy:** reject at commit
(`validateChassisClusterStrict`, matching the existing 255-group cap) *and*
defensively truncate in `marshalHeartbeatBody` with a rate-limited warn +
telemetry (mirrors the `oversizeHeartbeatGroupsWarn` pattern). This fixes the
latent uint8 overflow (`heartbeat.go:254,260`) independent of the epoch.

### 5.2 Anti-replay total order — separated sender/receiver state (F2)

Two **distinct** pieces of Manager/daemon-scoped state (Codex r2 §1 — do not
conflate them):

- **Sender send-nonce** `{session, counter}` — created once per daemon, monotonic
  `counter`, **never reset on a key change**, reset only when a new Manager is
  built (daemon restart), at which point the epoch is strictly higher. Define
  `counter` exhaustion: at `MaxUint64` (unreachable at 10 Hz for ~10¹¹ years)
  force a fresh epoch rather than wrap.
- **Receiver `peerAdmission`** `{ring, highEpoch, highCounter, sawEpoch, keyGen}`
  (auth-seen lives in #5639's cross-channel owner) — survives heartbeat restart,
  reset on daemon restart; **only `{highEpoch, highCounter, sawEpoch}` are
  cleared by a re-prime** (§5.5).

v2-frame guard (reusing `fullSetSeqGuard`'s comparison), evaluated under the
admission lock after MAC verify:

```
if epoch > highEpoch                            { highEpoch,highCounter = epoch,counter; ACCEPT }  // genuine reboot
if epoch == highEpoch && counter > highCounter  { highCounter = counter;                 ACCEPT }  // live frame
ACCEPT? no → REJECT                                                                                 // retired or same-incarnation replay
```

`(epoch,counter)` is a total order across every frame the peer ever sends:
`epoch` (persisted, strictly increasing per daemon) distinguishes incarnations;
`counter` (Manager-scoped, monotonic, survives heartbeat restart) distinguishes
frames within one. **Correctness reduces to epoch strict-monotonicity** (SMR r2
R1): the per-incarnation `counter` reset is safe *only because* the epoch
strictly increases — a repeated epoch (persist-fail + non-advancing clock) +
counter reset is a regression, which is exactly the F3 self-lock (an operator-
recoverable REJECT, never a replay admit). This is why F3's init is fenced
(§5.4). The 64-ring stays **only** for v1 (`hasEpoch==false`) migration frames;
with the Manager-scoped sender nonce it sees one session/monotonic-counter per
daemon, so routine restarts no longer churn it either.

### 5.3 Receiver decision — one linearized transaction with a key-generation stamp

```
info := parseAuthTrailer(frame)                 // locate XPFA; NOT trusted until verified
keyGen, key := m.authKeySnapshot()              // (generation, key) atomic snapshot
macOK := info.present && len(key)>0 && verifyMAC(frame, key)
bodyEnd := len(frame) - 52  if macOK else len(frame)   // bodyEnd only from a verified trailer
pkt := UnmarshalHeartbeat(frame[:bodyEnd])
hasEpoch, epoch := parseEpochMarker(frame, bodyEnd, key)  if macOK else false
… clusterID / duplicate-node checks …
admission.Lock()
  if keyGen != m.currentKeyGen() { admission.Unlock(); DROP }   // key rotated mid-verify (TOCTOU) → discard, re-read next frame
  accept, reason := admit(info, macOK, hasEpoch, epoch, counter) // base auth (#5639 owner) → epoch guard (v2) → ring (v1)
  if accept && macOK { markAuthSeen(); if hasEpoch { sawEpoch=true } }
  if accept { lastSeen=now; snapshotPeerApply := pkt }           // captured under lock
admission.Unlock()
if accept { handlePeerHeartbeat(snapshotPeerApply) }             // election apply AFTER unlock (m.mu, no nesting)
```

- **Key-generation stamp** (Codex r2 §4/§6): the MAC is verified under a snapshot
  `keyGen`; the commit is dropped if the key rotated before the lock was taken,
  so an archived K1 frame can never re-arm `sawEpoch`/`highEpoch` in freshly
  K2-reset state.
- **Dedicated admission lock**, not `m.mu` (SMR r2 R5): `handlePeerHeartbeat`
  (which takes `m.mu`) runs *after* the admission lock is released — no reentrant
  deadlock, and admission + `lastSeen` + the peer-state to apply are captured as
  one linearized unit relative to a key reset.
- **Base-auth first**: the #5639 cross-channel owner's `peerAuthSeen` gates the
  cleartext-downgrade decision and **survives heartbeat restart**, closing the
  reopen v2 left (a no-trailer frame is not dual-accepted after a routine
  restart).

### 5.4 Epoch init + election fence (F3)

Resolve the epoch **once, at Manager bring-up, before the first election**
(`daemon_run_bringup.go:161` runs an election before heartbeat starts — lazy
first-send is too late). Explicit state `epochState{initialized, epoch,
persisted bool, lastErr, keyGen}`:

```
resolveEpoch(path):                         // called synchronously at bring-up when keyed
  cls  := classify(readFile(path))          // {CLEAN_FIRST_BOOT(no file), DELETED, UNREADABLE, CORRUPT, VALID(prev)}
  prev := (cls==VALID) ? prev : 0           // only a VALID, in-domain prev seeds the +1 floor
  now  := wallClockNanos()                  // require 0 < now < MaxInt64; else fall to a fixed high floor
  cand := max(prev+1, now)                  // checked: prev+1 overflow → cand=now; cand<=prev impossible after the guard
  if writeDurable(path, cand) == ok: {epoch=cand; persisted=true; READY}
  else:                                      {epoch=cand; persisted=false; DEGRADED; startAsyncPersistRetry()}
```

Arithmetic/state classification (Codex r2 §3, complete set):
- `CLEAN_FIRST_BOOT`/`DELETED`/`UNREADABLE`/`CORRUPT` are **distinct** and logged
  distinctly; only `VALID` seeds `prev`.
- **Reject a corrupt far-future** `prev > now + MARGIN` (`MARGIN` = a documented
  bound, e.g. 10 years of ns) → treat as state-loss (Codex r2 + SMR r2 R3), so a
  corrupt high value cannot become an unreachable self-lock floor.
- Reject `prev == 0` / `prev >= MaxUint64 - guard` as invalid.
- **Never persist a value below a VALID prev** (a `+1` floor guarantees this;
  the state-loss seed uses `now`, which is far above any plausible counter).
- Guard negative/overflow `UnixNano`.

**Persist-failure = election fence** (Codex r2 §3; the crux correction over v2's
"status reason"):
- A node that has emitted, or may emit, an **unpersisted** epoch is placed under
  an **election hold**: it does **not** preempt to primary while a peer is
  present. It **still promotes on confirmed-peer-absent** (the existing
  never-seen/peer-dead path) so a *sole* node is never outaged for a local disk
  fault. It continues sending heartbeats, advertising fenced-secondary state.
- The async persist retry uses **bounded backoff off the send path** — never a
  synchronous fsync in `send()` (Codex r2 §3: a 100 ms ticker + slow fsync would
  suppress all heartbeats / storm the log). On success it clears DEGRADED and
  lifts the hold.
- Correct the v2 claim: permanent persist-failure does **not** "degrade to the
  ring bound" (an epoch-bearing lower frame never falls back to the ring); it
  degrades to a fenced, operator-recoverable self-lock risk — an **availability**
  posture, never a replay admit.

### 5.5 Re-prime + coordinated recovery (F4)

- **Re-prime clears only `{highEpoch, highCounter, sawEpoch}`** — NOT
  `peerAuthSeen`, NOT the ring, NOT the sender nonce (Codex r2 §4: clearing
  cleartext enforcement is unnecessary and unsafe — a rolled-back v1 node still
  signs `XPFA`, so the peer should keep enforcing auth; and resetting the counter
  breaks the total order).
- **Race-free recovery = a coordinated cluster-wide rotation to a NEVER-USED
  key.** The documented runbook (self-lock or one-sided v2→v1 rollback):
  *isolate the affected node → (roll it back if applicable) → install the new key
  on **both** nodes (config-synced PSK) → the key-generation change resets each
  node's `{highEpoch,highCounter,sawEpoch}` → reconnect.* A never-used key makes
  every archived K1 capture unverifiable (race-free), and the key-gen stamp
  (§5.3) prevents an in-flight K1 frame from re-arming after reset. Note the
  failure mode of a **one-sided** key change (MAC mismatch → split) so the doc
  never implies per-node rotation is safe.
- **Rejected:** auto-re-anchor on peer-down (reopens the attack); daemon-restart
  (resets the wrong node + a failover blip).

## 6. Honest residuals

- **Post-restart / post-re-prime anchor window (bounded).** After a receiver
  daemon restart or a re-prime, `highEpoch=0`; a retired frame can be admitted
  **once** and drive a transient election effect before the live higher-epoch
  frame repairs the floor. So "a retired incarnation can *never* be replayed" is
  overstated (Codex r2 §1) — the epoch closes the **sustained** replay; the
  single-admit window needs an attacker who can also inject at exactly that
  instant, and is fully closed only by disk-persisting the **receiver** floor
  (named follow-up, which adds its own cross-restart self-lock needing operator
  recovery — deliberately deferred).
- **Persist permanently failing** (RO `/var/lib`): the node runs
  fenced-secondary (or sole-node primary), DEGRADED surfaced; never a silent
  wedge or a replay admit.

## 7. Multiple Path Options (design-heavy decisions, updated)

### 7.1 Wire discriminator (F1+F5)
- **A — key-derived tail-anchored marker, MAC-gated (RECOMMENDED).** Robust
  against archived/uncapped v1 bodies; no forward-parse dependency; no
  key-rotation rollout boundary.
- **B — forward-parsed typed TLV + field caps (v2).** REJECTED: archived captures
  under the unchanged PSK can desync the parse into a valid-looking TLV.
- **C — v2 auth trailer / version bump.** REJECTED (F1 split / session-sync blast
  radius).

### 7.2 Same-epoch guard (F2)
- **A — separated Manager sender-nonce + `(epoch,counter)` receiver high-water;
  ring→v1-only (RECOMMENDED).**
- **B — shared/reset-on-key-change nonce (v2).** REJECTED: repeated `(E,1)` breaks
  the total order.
- **C — enlarge the ring.** REJECTED: moves the constant only.

### 7.3 Persist-failure posture (F3)
- **A — bring-up resolve + election fence (hold-secondary; promote if peer
  absent) + async retry (RECOMMENDED).**
- **B — status reason only (v2).** REJECTED: readiness does not demote a primary
  and is bypassed on the peer-dead path.
- **C — hard fence even when sole node.** REJECTED: outages a single node on a
  local disk fault.

### 7.4 Auth-owner lifecycle (F4 / #5639)
- **A — sequence behind #5639's Manager-scoped cross-channel owner
  (RECOMMENDED).**
- **B — move only heartbeat ownership (v2).** REJECTED: sync-auth owner stays
  transient (Codex r2 §5) — #5639 not subsumed.

## 8. Staging

- **Stage −1 (PREREQ = #5639):** one Manager/daemon-scoped cross-channel auth
  owner (heartbeat + sync-auth), surviving comms recreation.
- **Stage 0:** Manager-scope the sender send-nonce; decided cap policy
  (commit-reject + defensive truncate). Composes with Stage −1. Closes the
  routine-restart churn for the existing mechanism (no wire change) — but note an
  *old* peer still draws new sessions until it upgrades.
- **Stage 1 (the wire change):** key-derived epoch marker + `(epoch,counter)`
  guard + bring-up election-fenced init + coordinated re-prime. Closes the
  daemon-reboot vector. Stage −1 + 0 + 1 together = the complete #6169 fix.

## 9. Public API preservation

- Unchanged signatures: `MarshalHeartbeat`, `MarshalHeartbeatAuth`,
  `heartbeatAuthTrailer`, `verifyHeartbeatMAC`, `heartbeatAuthReplay.admit`.
- `UnmarshalHeartbeat` is called on `frame[:bodyEnd]` (verified) — signature
  unchanged; the epoch is parsed by a separate tail-reader, not by
  `UnmarshalHeartbeat`.
- `HeartbeatPacket` gains `BootEpoch uint64` (additive, read-only for display).
- New: epoch marker derive/parse, `Manager.admit*`, `peerAdmission` + sender
  send-nonce on Manager, `epochState` bring-up resolver, key-generation stamp,
  election-fence hook, `ha-boot-epoch` persistence.
- **Unchanged:** `CurrentHAProtocolVersion`, `SessionSyncWireVersion`, #5078's
  handshake. **#5639's cross-channel owner touches `sync_auth.go`'s auth-seen
  bit** (v3 corrects v2's "unchanged" claim).

## 10. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (election / bring-up / failover) | **HIGH** | Election-fence + bring-up epoch resolve touch the promotion path; `make test-failover` (v4+v6) + a mixed-version + a persist-failure-fence + a key-rotation-reprime harness are mandatory. |
| HA availability (self-lock) | **MED** | Reduced to state-loss∧backward-clock, fenced + operator-recoverable via cluster key rotation. |
| Wire/interop | **LOW** | Unchanged 52-byte `XPFA`; key-derived marker; old receiver ignores it. |
| Security (replay/downgrade) | **LOW-MED** | Total order + key-gen stamp + cross-channel owner; bounded post-restart single-admit residual documented. |
| Architectural mismatch / coupling | **MED-HIGH** | Hard #5639 prerequisite + election-path changes — larger, sequenced effort than the issue implied. |

## 11. Out of scope / PLAN-KILL

- Disk-persisting the **receiver** floor (closes the post-restart single-admit
  window) — follow-up.
- Retiring the ring for v1 — kept for migration.
- **PLAN-KILL?** Legitimate only if the project judges the residual too narrow to
  justify the #5639 prerequisite + election-fence + key-rotation runbook. Not
  recommended: the residual is real and more credible post-review, the
  `(epoch,counter)` center is sound, and a half-fix is worse than the honest 64
  bound. If not killed, the realistic path is **sequence behind #5639** and land
  Stage 0 (restart-churn) before Stage 1 (epoch).

## 12. Open questions for round-3 (each invitable to PLAN-KILL)

1. **#5639 sequencing.** Is "build the Manager-scoped cross-channel auth owner in
   #5639, then add epoch state in #6169" the right split, and does the owner
   correctly survive *both* comms recreation and heartbeat restart without
   regressing #5639's sync-auth-first case?
2. **Election-fence semantics.** Is "hold-secondary while a peer is present,
   promote on confirmed-peer-absent" the correct persist-failure posture, and
   where exactly does the hold hook into the bring-up election
   (`daemon_run_bringup.go:161`) and the peer-dead single-node path
   (`election.go:427`) without introducing a new split-brain?
3. **Key-derived marker.** Is an 8-byte `HMAC(key,label)[:8]` marker the right
   size/derivation (domain-separated from the frame HMAC), and does reading it
   only after MAC verify fully close the archived-capture and unkeyed-`bodyEnd`
   ambiguities?
4. **Key-generation stamp.** Does the `keyGen` snapshot-at-verify / check-at-commit
   fully linearize admission against a mid-flight key rotation, including
   `lastSeen`/peer-state/election application?
5. **Bring-up ordering.** Resolving + persisting the epoch synchronously at
   bring-up — does any current bring-up path start heartbeat or run an election
   before `resolveEpoch` can complete, and is the bounded synchronous attempt
   acceptable there (vs a small startup latency)?
6. **Scope.** Given the #5639 prerequisite + election-fence, is this still the
   right issue to drive, or should it be re-scoped/split — and is PLAN-KILL
   warranted on cost/benefit?

---

### Appendix — files in blast radius (for /engineer)

- `pkg/cluster/heartbeat.go` — key-derived epoch marker derive/write/parse;
  MAC-verify-before-`bodyEnd`; `admit*` (base→epoch→ring); `readLoop` reorder +
  key-gen stamp; **cap monitor count + name length** (with `validateChassisClusterStrict`).
- `pkg/cluster/heartbeat_epoch.go` (new) — `resolveEpoch` bring-up state machine
  (classify/checked-arithmetic/durable-persist/async-retry).
- `pkg/cluster/manager.go` — `peerAdmission` + sender send-nonce + `epochState` +
  key-generation counter; **cross-channel auth owner (via #5639)**.
- `pkg/cluster/election.go` / bring-up — persist-failure **election hold**
  (hold-secondary; promote on peer-absent).
- `pkg/cluster/heartbeat_manager.go` — `buildHeartbeat` **reads** the resolved
  epoch (no I/O under `m.mu`); sender reads Manager nonce for the key-gen snapshot.
- `pkg/daemon/*` — bring-up sequencing so `resolveEpoch` precedes the first
  election; DEGRADED/fence surfaced.
- `pkg/config` — commit-time monitor/name caps.
- `pkg/cluster/README.md` + this doc — lifecycle, election-fence, key-rotation
  recovery runbook, honest residuals.
- Tests: F1 mixed-version both directions; **F2 — 65 distinct same-epoch sessions
  via simulated heartbeat restarts must NOT churn past the `(epoch,counter)`
  guard**, + one-receiver-restart equal-epoch replay; F3 — state classification,
  checked-arithmetic edges, persist-failure **fence** (hold-secondary + sole-node
  promote), async retry; F4 — heartbeat-restart carry, key-gen TOCTOU (K1-verify /
  K2-reset / stale-commit dropped), coordinated re-prime, one-sided-rollback
  wedge-then-cluster-rotate; F5 — key-derived marker rejects an archived
  256-byte-name v1 body (Codex r2's counter-example) + unkeyed-`XPFA`-at-`bodyEnd`
  parses the full frame.
