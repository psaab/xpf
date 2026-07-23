# #6169 — cluster/heartbeat across-reboot boot-epoch anti-replay (research plan)

**Status:** DRAFT v2 — revised after round-1 plan review (Codex + Claude SMR both
PLAN-NEEDS-MAJOR). Pending round-2 adversarial review. AGY infra-down.

Research worktree: `.claude/worktrees/6169-research`, branch
`research/6169-heartbeat-epoch`. Base: `origin/master` @ `11e23b49a`.
**/research** deliverable — STOPS at PLAN-READY; no production code is touched;
implementation begins only on `/engineer 6169`.

> **v2 changelog (what round-1 forced):** v1's Path A (epoch in the MAC-covered
> body, `XPFA` trailer unchanged) is retained — both reviewers agree it dissolves
> **F1** (rolling-upgrade split) and **F5** (v1/v2 trailer ambiguity) and avoids
> the version-machinery blast radius. But Codex caught a **critical** flaw v1
> missed: the epoch is daemon-scoped while the anti-replay `session`/`counter`
> are **transient** (reset on every heartbeat restart, which fires on routine
> VRF/config rebinds), so **many distinct sessions share one epoch → same-epoch
> ring churn stays fully alive (F2 NOT closed)**. v2 fixes the **anti-replay
> nonce lifetime** as the core change: Manager-scope `session`/`counter`, replace
> the ring's same-epoch role with a Manager-scoped **`(epoch,counter)`
> lexicographic high-water**, keep the 64-ring for **v1-migration only**. v2 also
> replaces the ambiguous "residual-8-bytes" epoch detection with a **typed,
> length-delimited, MAC-covered extension + capped marshaler fields**, designs a
> real **F3 init/recovery state machine**, and makes the **F4 re-prime an
> explicit race-free action on the *rejecting* node** — composing with the OPEN
> **#5639** (peerAuthSeen/ring lifecycle).

---

## 1. Issue framing

#5477 (merged as #6167) bounded the A→B→A heartbeat replay with a 64-slot
per-session watermark ring (`heartbeatAuthReplay.admit`). The #6167 hostile
review proved the bound is not absolute: FIFO eviction is triggered by any
never-seen session including a **replayed** one, so an attacker holding **≥65**
distinct authenticated captures can churn the ring by replay alone and sustain a
forged liveness/election drive. #6169 asks for the complete fix: a signed
**monotonic-across-reboot boot epoch** so a retired incarnation always carries a
lower epoch than the live one and can never be replayed — with **O(1)** receiver
state, independent of the ring.

A first implementation (**closed PR #6370**) hit the full merge gate; both
reviewers returned MERGE-NEEDS-MAJOR with five structural findings. This plan
resolves all five coherently.

## 2. Honest scope / value framing

- **What the win is.** Closes a **named** #6167 residual. Round-1 review made it
  **more** credible, not less: the attacker does **not** need 65 daemon reboots —
  the ring counts **sender sessions**, and a fresh session is drawn on every
  heartbeat restart, which fires on **routine VRF/config rebinds**
  (`daemon_apply_dataplane.go:435`). So an on-path sniffer accumulates the ≥65
  captures over ordinary operation, not a lifetime of reboots.
- **Threat model.** A passive **on-path** sniffer/injector on the dedicated
  control link (`em0`) that can **replay** captured authenticated frames but
  **cannot** forge/mint (no PSK) and does **not** block the live peer. The
  PSK/HMAC (#4107) already blocks forging; this closes the replay residual.
- **Absolute-scale honesty.** Defense-in-depth on an already-authenticated
  channel. **If reviewers conclude the residual is too narrow to justify the
  wire change + lifecycle + recovery surface, PLAN-KILL is acceptable.** We do
  not recommend it (§10): the receiver-only alternative only moves the 65
  constant, and shipping a half-fix (equal-epoch churn still live, unsafe
  rollback, undefined persist-failure) would be **worse** than the honest 64
  bound — which is exactly why v1 was rejected and v2 is scoped as it is.

## 3. What's already shipped / partially batched (must compose with)

- **#4107 auth** (`heartbeat.go`): PSK/HMAC-SHA256 `"XPFA"` **52-byte** trailer
  `magic(4)+session(8)+counter(8)+HMAC(32)`, appended after the body.
  `heartbeatAuthDecision` = dual-accept (no key → all; key+trailer → enforce
  MAC+nonce; key+no-trailer+`peerAuthSeen` → reject as cleartext downgrade).
- **#5477/#6167 ring** (`heartbeatAuthReplay`, 64-slot FIFO): the ≥65 residual is
  what #6169 closes. v2 **keeps** the ring for v1-migration frames; it does not
  change the ring algorithm.
- **#5639 (OPEN, bug/security)** — "replaceable sync-auth owner accepts unsigned
  heartbeat/first-sync frame": the `peerAuthSeen` + ring **reset on heartbeat
  restart** (`RestartHeartbeat` recreates the receiver). This is the **same
  lifecycle bug** #6169's new epoch state would inherit. **#6169 must compose
  with #5639** (§5.5) — leaving the admission state transient reopens the
  cleartext downgrade that undermines the epoch downgrade gate.
- **#5081/#5086** — #5086's ring merged (#5477/#6167); #5081 is a `pkg/daemon`
  transport-key reconcile. #6169 is additive to both.
- **Independent of held #5078** (session-sync PSK handshake, `sync_auth.go`) —
  verified untouched.
- **HA-version machinery** (`peer_state.go`, `sync.go`): the frame's
  `HAProtocolVersion` feeds `HAProtocolVersionMismatch` →
  `daemon_ha_userspace_readiness.go` **blocks RG transfer**, and
  `SessionSyncWireVersion = CurrentHAProtocolVersion` gates session sync.
  **Load-bearing:** the epoch must NOT reuse/bump this field (§5.1).
- **Reusable primitive:** `fullSetSeqGuard` (`sync_conn_gen.go:64`) is exactly a
  lexicographic `(incarnation, seq)` high-water with a controlled reset — the
  pattern for §5.3's `(epoch,counter)` guard. **Reuse the comparison, NOT its
  bulk-re-prime reset trigger** (that resets on a session-sync event, wrong for
  heartbeat).
- **Persistence precedent:** SNMPv3 `engineBoots` (`pkg/snmp/agent.go`) —
  load/increment/persist, **fail-closed to the ceiling on corruption + refuse
  authenticated traffic until re-discovery**. §5.4 adapts this honestly (the
  heartbeat cannot "refuse to send," so the analog is a high seed + a DEGRADED
  signal + operator re-prime, not a silent wall-clock seed).

## 4. The five findings — verified firsthand (`origin/master` + PR #6370)

- **F1 — rolling-upgrade split (Critical). CONFIRMED.** PR #6370 emitted a NEW
  60-byte `"XPFE"` trailer unconditionally when keyed; a keyed v1 receiver looks
  for `"XPFA"` at `len-52` (lands on random session bytes → `present=false`) and,
  with `peerAuthSeen=true` in a running cluster, rejects as "missing auth trailer
  (enforced)" → dual-primary. No emit-gate, no version bump. A size-changing
  trailer has **no** free additive dual-accept.
- **F2 — bypass via ring churn (Critical). CONFIRMED + WORSE than v1 realized.**
  PR #6370 ran `admit()` before the epoch check. v1's fix (epoch-before-ring)
  **is still insufficient**: the epoch is daemon-scoped and survives a heartbeat
  restart, but `authSession`/`authCounter` are transient sender fields
  (`heartbeat.go:643,692`) reset on every `newHeartbeatSender`, and
  `RestartHeartbeat` fires on routine rebinds. So one daemon at epoch `E` emits
  **many** distinct sessions `S1…Sn`, **all at `E`**; every capture passes
  `epoch == highEpoch`, reaches the ring, and churns it exactly as today. A
  single receiver restart also yields a one-shot equal-epoch replay (Manager
  `highEpoch=E` survives, the ring is empty). **The nonce lifetime is the real
  bug.**
- **F3 — genuine-reboot self-lock (Major). CONFIRMED, and undesigned in v1.**
  `max(persisted+1, wallclock)`; state-loss + backward-clock → genuine node
  emits `< E` → peer's in-memory floor rejects forever. `sync.Once` caches an
  unpersisted value and cannot be un-finalized for retry. v1's "persist-before-
  send **or** wall-clock degrade" are mutually exclusive; "restart the rejecting
  peer" is **attacker-raceable** (the live genuine node is the *lower* one, so an
  archived higher replay wins the re-anchor). Uncovered arithmetic: `prev ==
  MaxUint64` wrap, negative `UnixNano()` cast, trusted far-future corrupt value.
- **F4 — state-lifecycle (Major). CONFIRMED, and v1 fixed the wrong half.**
  `RestartHeartbeat` recreates the receiver preserving only `lastSeen`;
  `sawEpoch`/`highEpoch`/ring/`peerAuthSeen` zero → routine restart reopens
  replay/downgrade. Moving only `highEpoch`/`sawEpoch` (v1) leaves the ring +
  `peerAuthSeen` transient → the cleartext downgrade reopens (a no-trailer frame
  after restart is dual-accepted because `peerAuthSeen=false`, and the §5.3 gate
  runs only when `macOK`). A legit **one-sided** v2→v1 rollback is wedged: the
  state rejecting the rolled-back node lives on the **upgraded peer**, so
  restarting the rolled-back node clears the **wrong** node; and `HAProtocolVersion`
  stays 1 so the mismatch gate cannot fence the asymmetric interval.
- **F5 — parse ambiguity (Moderate). CONFIRMED; v1's replacement re-introduced
  it.** PR #6370's v2-first parse + format-agnostic MAC (`data[:len-32]`)
  mis-parses a v1 frame with `"XPFE"` at `len-60`. v1's "residual 8 bytes ⇒
  epoch" is **also** ambiguous: monitor count and name length are **uncapped
  uint8** (`heartbeat.go:254,260`), so a MAC-valid body can desync the forward
  parse and leave a stray 8-byte tail (Codex's worked counter-example) or hide a
  real epoch.

## 5. Concrete design — v2

Path A (epoch in the MAC-covered body, `XPFA` trailer unchanged) is retained for
**F1/F5**; the core new work is the **anti-replay nonce lifetime + total-order
guard** (F2), the **init/recovery state machine** (F3), and the **admission-state
lifecycle + re-prime** (F4).

### 5.1 Wire — typed, length-delimited, MAC-covered epoch extension (F1 + F5)

The `"XPFA"` **52-byte** trailer is left **byte-for-byte unchanged** (this is
what dissolves F1 — an `origin/master` v1 receiver still finds `"XPFA"` at
`len-52`, still verifies `data[:len-32]`, still `admit()`s, and its
`UnmarshalHeartbeat` returns right after `HAProtocolVersion`, ignoring the extra
body bytes; verified: one non-test caller, `readLoop:796`). The epoch rides in
the body as a **TLV extension** after the version section:

```
… [VersionLen][SoftwareVersion][HAProtocolVersion(2)]                     ← existing version section
  [ExtType=1 (1B)][ExtLen=8 (1B)][BootEpoch(8, LE)]                        ← #6169 epoch TLV (MAC-covered)
  [ "XPFA"(4) ][ session(8) ][ counter(8) ][ HMAC-SHA256(32) ]            ← unchanged #4107 trailer
```

- **No `HAProtocolVersion` bump / no version reuse.** Verified blast radius:
  sending version 2 trips `HAProtocolVersionMismatch` → blocks session-sync + RG
  transfer during rolling upgrade. The TLV is a self-contained additive body
  field (the #2239 DHCP-lease-sync discipline).
- **Unambiguous detection (kills the F5 residual-byte problem).** The receiver
  locates the fixed 52-byte trailer first ⇒ `bodyEnd = len-52` (or `len` when no
  trailer). It forward-parses the body `[:bodyEnd]`; after the version section,
  if `off < bodyEnd` it reads `[ExtType][ExtLen]` and, for `ExtType==1,
  ExtLen==8`, the 8 epoch bytes. **Two belts:** (a) the TLV is typed +
  length-delimited (not "whatever bytes remain"); (b) the marshaler is made
  canonical so the forward parse to `off` cannot desync —
  **cap/reject monitor count > 255 and interface-name length > 255**
  (`marshalHeartbeatBody`; fixes the latent uint8 overflow at `heartbeat.go:254,260`,
  matching the existing `maxHeartbeatGroups=255` cap). A malformed/unknown ext
  (wrong type/len, or leftover ≠ a valid TLV) is treated as **no epoch** and
  logged — never guessed.
- **Written only when keyed.** `marshalHeartbeatBody` writes the TLV iff a
  non-zero `pkt.BootEpoch` is set, which the sender does **only** in the keyed
  branch. An unkeyed frame is byte-identical legacy; `BootEpoch==0` ≡ "no epoch".
- **Never-unsigned-when-keyed** preserved: the +10 TLV bytes go into the tail
  reserve, so a keyed frame still always carries its HMAC.

### 5.2 Anti-replay nonce lifetime — the F2 core fix

Move `authSession` + `authCounter` **off the transient `heartbeatSender` and
into Manager-scoped state** (§5.5), so they **survive a heartbeat restart** and
only reset on a full daemon restart / auth-key rotation. Consequences:

- **v1-migration frames**: the ring now sees **one** session per daemon with a
  **monotonic** counter → it cannot be churned by routine restarts. (This alone
  closes the routine-restart vector for the existing #4107/#5477 mechanism — no
  wire change; see the Stage-0 split in §5.7.)
- **v2 (epoch-bearing) frames**: replace the ring's same-epoch role with a
  Manager-scoped **`(epoch, counter)` lexicographic high-water**
  (`(highEpoch, highCounter)`), reusing the `fullSetSeqGuard` comparison (NOT its
  reset trigger):

```
// admitEpoch: MAC already verified. Single Manager-locked transaction.
if epoch > highEpoch                 { highEpoch, highCounter = epoch, counter; return ACCEPT }  // genuine reboot
if epoch == highEpoch && counter > highCounter { highCounter = counter;        return ACCEPT }  // live frame
return REJECT                                                                                     // retired OR same-incarnation replay
```

`(epoch, counter)` is a **total order over every frame the peer ever sends**:
`epoch` distinguishes daemon incarnations (persisted, strictly increasing),
`counter` distinguishes frames within an incarnation (Manager-scoped, monotonic,
survives heartbeat restart, resets per daemon under a strictly-higher epoch).
This closes **both** churn vectors (heartbeat-restart and daemon-reboot) with
O(1) state, and the advance is a **single commit** (no advance-then-ring-reject
partial-commit). The 64-ring stays **only** for v1 (`hasEpoch==false`) frames
during migration.

### 5.3 Receiver decision flow (F2 ordering + F4 downgrade gate)

`readLoop` is reordered so parsing and admission are one coherent transaction:

```
info := parseHeartbeatAuth(frame, key)        // locate 52B XPFA trailer → bodyEnd; macOK
pkt  := UnmarshalHeartbeat(frame[:bodyEnd])    // canonical body parse (capped fields) + epoch TLV → hasEpoch,epoch
… existing clusterID / duplicate-node checks …
m.mu.Lock()   // single admission critical section (heartbeat ~10/s → negligible contention)
  accept, reason := admitHeartbeat(info, hasEpoch, epoch, counter)
    // 1) base auth: heartbeatAuthDecision(keyCfg, present, macOK, peerAuthSeen)  → reject bad MAC / cleartext-downgrade
    // 2) if macOK && hasEpoch:  accept = admitEpoch(epoch, counter)              → (epoch,counter) total order (F2)
    //    else if macOK && !hasEpoch && sawEpoch: reject "epoch strip (downgrade)"
    //    else if macOK && !hasEpoch:            accept = ring.admit(session,counter)  → v1-migration ring
  if macOK { peerAuthSeen = true; if hasEpoch { sawEpoch = true } }
m.mu.Unlock()
```

Because `admitEpoch` runs **before** any ring mutation and lower-or-equal frames
never reach the ring, the churn is dead. `peerAuthSeen`/`sawEpoch` live in the
Manager (§5.5) so the cleartext- and epoch-downgrade gates **survive a heartbeat
restart** — closing the F4 reopen Codex flagged (the no-trailer-after-restart
dual-accept).

### 5.4 Sender epoch init/recovery state machine (F3)

Replace `sync.Once` with a **retryable init** guarded by a dedicated mutex (never
under `m.mu`, so no durable I/O under `buildHeartbeat`'s `RLock`):

```
epochInit():                         // lazy, first keyed send
  prev := loadPersisted(path)        // CHECKED: parse-fail / prev==0 / prev>=MaxUint64-margin / negative → prev = 0 (state-loss)
  now  := clampWallClock()           // guard UnixNano()<0 (pre-1970 clock) → floor; guard overflow
  cand := max(prev+1, now)           // both terms required (state-loss→now; backward-clock→prev+1)
  if !persisted:
     if writeDurable(path, cand) == ok:  persisted = true;  epoch = cand;  READY
     else:                               epoch = cand;  DEGRADED            // high seed (now ≫ any counter); keep retrying next send
  return epoch
```

- **Persist-before-send is the target; the DEGRADED path is the honest
  fallback, not an alternative.** On persist failure the value is still
  wall-clock-floored (≈1.7·10¹⁸ — the "seed high" analog of SNMP's ceiling), and
  the node raises a **DEGRADED readiness reason** (`ha-boot-epoch-not-persisted`,
  wired like the `HAProtocolVersionMismatch` reason) so the operator sees it. It
  is monotone in the common case; the only residual is state-loss on the *next*
  incarnation, which is exactly the operator-recoverable self-lock (§5.5).
- **SNMP analogy corrected.** SNMP pins to the ceiling and *refuses authenticated
  traffic* until re-discovery. The heartbeat **cannot refuse to send** (it drives
  liveness), so the adapted discipline is: high seed + DEGRADED signal + a
  bounded **operator re-prime** for the receiver floor — not a silent seed that
  pretends nothing happened.
- **Retry, not `sync.Once`.** The epoch *value* is computed once (stable within
  the daemon); the *persist* is retried on later sends until durable, so a
  transient disk error self-heals.

### 5.5 Admission-state lifecycle + re-prime (F4) — composes with #5639

Introduce a single **Manager-scoped `peerAdmission` struct** — `{ring,
peerAuthSeen, session, counter, highEpoch, highCounter, sawEpoch}` — created once
per daemon, referenced by the receiver:

- **Survives a heartbeat restart** (`RestartHeartbeat`/config recompile) → closes
  F4a for *all* admission state, not half of it. This is precisely the lifecycle
  the OPEN **#5639** tracks for `peerAuthSeen`+ring; **#6169 either lands after
  #5639** (and adds the epoch fields into the same struct) **or subsumes #5639's
  heartbeat portion** by moving the whole struct. **Decision for the user
  (§11 Q1):** sequence behind #5639, or fold. Recommended: fold the lifecycle
  move into #6169 (the epoch is meaningless without it) and mark #5639's
  heartbeat portion resolved-by-#6169.
- **Reset on daemon restart** (new Manager) — a genuinely fresh incarnation.
- **Re-prime (the controlled escape for F3 self-lock + F4b legit rollback):**
  - **Primary, race-free: auth-key rotation.** Changing the chassis-cluster
    `authentication-key` makes every archived capture fail the MAC, so re-priming
    the peer floor at that instant cannot be raced by a replay. Implement:
    `peerAdmission` resets `{highEpoch, highCounter, sawEpoch, peerAuthSeen,
    ring}` when the local auth-key **fingerprint changes**. This is a natural
    operator action when rolling back software or clearing a wedged node, and it
    fixes Codex's "resets the wrong node" — the reset happens on the **rejecting**
    node the moment its own key rotates.
  - **Secondary: explicit `request chassis cluster heartbeat-epoch reprime`** on
    the rejecting node (clears the peer floor in place). NOT race-free alone
    (pair with link isolation / key rotation) — documented as such.
  - **Rejected:** auto-re-anchor on peer-down (reopens the attack); daemon-restart
    (resets the wrong node + a failover blip).

### 5.6 Honest residuals

- **Post-daemon-restart / post-re-prime anchor window** (bounded): after a
  daemon restart or re-prime, `highEpoch=0`; an attacker who can *also actively
  block* the live peer could briefly walk the floor up through captured epochs.
  Under #6169's threat model (replay without blocking the live peer) the live
  peer's current frame wins within one interval. Blocking-the-peer is a strictly
  stronger attacker than #4107/#5477 defend; disk-persisting the **receiver**
  floor (Option 4-ii) would close even that but adds a cross-restart self-lock
  needing operator file surgery — named follow-up, not the default.
- **Persist permanently failing** (RO `/var/lib`): DEGRADED signal raised;
  defense degrades toward the (now restart-safe) ring bound, never a silent
  wedge of a live peer.

## 6. Multiple Path Options (design-heavy decisions)

### 6.1 Wire (F1+F5)
- **A — epoch TLV in MAC-covered body, `XPFA` unchanged (RECOMMENDED).**
  Dissolves F1+F5; unconditional keyed emit; no version-machinery entanglement.
- **B — capability-gated v2 trailer.** Needs a mutual-capability body flag to
  avoid a bootstrap deadlock and *still* carries F5 unless a MAC-covered type
  discriminator is added — more parts than A for no gain.
- **B′ — v2 gated on `HAProtocolVersion≥2`.** REJECTED: trips the mixed-base
  session-sync/RG-transfer gate.

### 6.2 Same-epoch replay guard (F2)
- **A — Manager-scope session/counter + `(epoch,counter)` lexicographic
  high-water; ring→v1-only (RECOMMENDED).** Closes both churn vectors, O(1),
  single-commit. Reuses `fullSetSeqGuard`'s comparison.
- **B — epoch-before-ring but keep transient session/counter (v1's approach).**
  REJECTED: routine restarts emit many same-epoch sessions → churn stays live.
- **C — enlarge the ring.** REJECTED: only moves the 65 constant.

### 6.3 Persistence/recovery (F3+F4)
- **A — checked `max(persisted+1,wallclock)` + retryable persist-before-send +
  DEGRADED signal + key-rotation re-prime (RECOMMENDED).**
- **B — auto re-anchor on peer-down.** REJECTED: reopens the attack.
- **C — disk-persist the receiver floor by default.** Stronger post-restart, but
  a cross-restart self-lock needing operator file surgery — follow-up, not
  default.

## 5.7 Staging (keep the PR reviewable)

- **Stage 0 (lifecycle + hardening, no wire change):** Manager-scope
  session/counter/ring/`peerAuthSeen` (survive heartbeat restart) + cap monitor
  count/name length. Independently valuable: closes the **routine-restart churn**
  for the existing #4107/#5477 mechanism and fixes the uint8 overflow. Overlaps
  **#5639** — see §5.5 Q1.
- **Stage 1 (the wire change):** epoch TLV (Path A) + `(epoch,counter)` guard +
  F3 init state machine + key-rotation re-prime. Closes the **daemon-reboot**
  vector. Stage 0 + Stage 1 together = the complete #6169 fix.

Stages may ship as two PRs (Stage 0 first) or one; both must land for closure.

## 7. Public API preservation

- Unchanged signatures: `MarshalHeartbeat`, `UnmarshalHeartbeat` (gains an
  internal TLV read + field caps; signature unchanged — but see §11 Q2 on whether
  to pass `bodyEnd`), `MarshalHeartbeatAuth`, `heartbeatAuthTrailer`,
  `verifyHeartbeatMAC`, `heartbeatAuthDecision`.
- `HeartbeatPacket` gains `BootEpoch uint64` (additive).
- `heartbeatAuthReplay.admit` unchanged (now fed a stable session/counter).
- New: `Manager.admitEpoch`/`admitHeartbeat`, `peerAdmission` struct,
  `nextBootEpoch`+retry init, `Manager.heartbeatBootEpoch`, marshaler field caps,
  key-fingerprint re-prime, `ha-boot-epoch-not-persisted` readiness reason.
- **Unchanged:** `CurrentHAProtocolVersion`, `SessionSyncWireVersion`,
  `sync_auth.go` (#5078).

## 8. Hidden invariants the change must preserve

- Never-unsigned-when-keyed (+10 TLV bytes into the tail reserve).
- Admission is **one transaction**: MAC verified → evaluate `(epoch,counter,mode)`
  → commit; no partial advance.
- `admitEpoch` before any ring mutation (F2); `sawEpoch`/`peerAuthSeen` read for
  the downgrade gates and Manager-scoped so they survive a heartbeat restart.
- Dual-accept stays additive (old receiver ignores the TLV + validates the
  unchanged trailer) — no F1 rejection.
- No `HAProtocolVersion` semantics change; no `syncMsg*`/`SessionSyncWireVersion`
  change.
- Durable epoch I/O never under `m.mu` (lazy first-keyed-send, dedicated init
  mutex).
- `(epoch,counter)` monotonic per peer across restart/reboot except the
  operator-recoverable state-loss∧backward-clock case.

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (rolling upgrade / failover) | **MED-HIGH** | Touches the election-critical receive path + nonce lifetime; `make test-failover` (v4+v6) mandatory, plus a mixed-version (v1↔v2) harness test. |
| HA availability (self-lock) | **MED** | F3 reduced to state-loss∧backward-clock, operator-recoverable via key-rotation re-prime; must be unit-proven + documented. |
| Wire/interop | **LOW** | Unchanged 52-byte `XPFA` trailer; old receiver ignores the TLV (single `UnmarshalHeartbeat` caller). |
| Security (replay/downgrade) | **LOW** | `(epoch,counter)` total order + single trailer format + Manager-scoped downgrade gates. |
| Architectural mismatch | **LOW-MED** | Overlaps #5639 lifecycle — sequencing decision (§11 Q1) needed to avoid double-work. |

## 10. Out of scope / PLAN-KILL

- Disk-persisting the **receiver** floor (Option 4-ii/6.3-C) — follow-up.
- Retiring the ring entirely (even for v1) — kept for migration.
- **PLAN-KILL?** Not recommended: the residual is a named #6167 follow-up and is
  *more* credible post-review; `(epoch,counter)` closes it with O(1) state.
  PLAN-KILL is legitimate **only** if the project rejects the lifecycle/recovery
  redesign — in which case keep the honest 64 bound rather than ship a half-fix.

## 11. Open questions for adversarial round-2 (each invitable to PLAN-KILL)

1. **#5639 sequencing.** Fold the admission-state lifecycle move into #6169
   (recommended — the epoch is meaningless without it) or sequence #6169 behind
   #5639? If folded, does #6169 correctly subsume #5639's heartbeat portion
   without regressing its sync-auth-owner case?
2. **TLV detection.** Is "locate the 52-byte trailer → `bodyEnd` → forward-parse
   a typed TLV, with capped monitor/name fields" now provably unambiguous for
   *every* MAC-valid body (empty version, max version, max monitors), and does
   capping monitor count/name length break any legitimate large-cluster config?
   Should `UnmarshalHeartbeat` take an explicit `bodyEnd` rather than infer it?
3. **`(epoch,counter)` sufficiency.** With session/counter Manager-scoped and the
   `(epoch,counter)` guard, is the 64-ring still needed at all beyond v1
   migration, and is there any lifetime where `counter` resets under an unchanged
   `epoch` (proving the guard's premise)?
4. **F3 arithmetic + DEGRADED posture.** Are the checked-arithmetic cases
   (`MaxUint64` wrap, negative `UnixNano`, far-future corrupt) complete? Is
   "raise a DEGRADED readiness reason but keep sending the high-seeded epoch" the
   right fail-open-toward-availability posture, or must a persist-failed node be
   fenced from election?
5. **Key-rotation re-prime race.** Does resetting the peer floor on local
   auth-key fingerprint change fully close the rollback/self-lock race (archived
   captures dead under the new key), and what happens if only one node rotates?
6. **Scope / staging.** Is the Stage-0/Stage-1 split right, and is Stage 0
   (Manager-scope + caps, no wire change) worth shipping first as the
   restart-churn fix even independent of the epoch?

---

### Appendix — files in blast radius (for /engineer)

- `pkg/cluster/heartbeat.go` — `HeartbeatPacket.BootEpoch`; `marshalHeartbeatBody`
  (+TLV reserve/write, **cap monitor count + name length**);
  `UnmarshalHeartbeat`/`parseBodyEpoch` (TLV read bounded by `bodyEnd`);
  `admitEpoch`; `admitHeartbeat`; `readLoop` reorder.
- `pkg/cluster/heartbeat_epoch.go` (new) — `nextBootEpoch` (checked arithmetic +
  retryable persist), `Manager.heartbeatBootEpoch`.
- `pkg/cluster/manager.go` — `peerAdmission` struct (ring, peerAuthSeen, session,
  counter, highEpoch, highCounter, sawEpoch) + bootEpoch init state.
- `pkg/cluster/heartbeat_manager.go` — `buildHeartbeat` sets `BootEpoch`; sender
  reads Manager-scoped session/counter; key-fingerprint re-prime hook.
- `pkg/daemon/daemon_ha_userspace_readiness.go` — `ha-boot-epoch-not-persisted`
  DEGRADED reason.
- `pkg/cluster/README.md` + this doc — lifecycle, recovery, honest residuals.
- Tests (`heartbeat_epoch_test.go`): F1 mixed-version dual-accept both
  directions; **F2 the real gate — 65 distinct same-epoch sessions via simulated
  heartbeat restarts must NOT churn past the `(epoch,counter)` guard**, plus a
  one-receiver-restart equal-epoch replay; F3 state-loss∧backward-clock +
  persist-failure DEGRADED + checked-arithmetic edges; F4 heartbeat-restart carry
  + key-rotation re-prime + one-sided-rollback wedge-then-reprime; F5 canonical
  body parse across every truncation/cap boundary + malformed-TLV → no-epoch.
