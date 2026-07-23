# #6169 — cluster/heartbeat across-reboot boot-epoch anti-replay (research plan)

**Status:** DRAFT v6 — revised after five rounds of adversarial plan review
(Codex r1–r5 + Claude SMR r1–r5, each round PLAN-NEEDS-MAJOR). Pending round-6
review. AGY infra-down.

Worktree `.claude/worktrees/6169-research`, branch `research/6169-heartbeat-epoch`,
base `origin/master` @ `11e23b49a`. **/research** — STOPS at PLAN-READY; no
production code; implementation only on `/engineer 6169`.

> **v6 changelog (what round 5 forced).** The **key-derived marker** and the
> **separated Manager send-nonce + `(epoch,counter)` total order** remain the
> validated center (five rounds). Round 5 exposed a **fundamental** flaw in v5's
> ownership hold: sole-node availability + two-node partition safety is
> **impossible from heartbeat absence alone** — a one-way receive partition is
> indistinguishable from a genuinely-absent peer, so v5's "held node promotes via
> never-seen" recreates dual-primary. v6 therefore **chooses CONSISTENCY**: in a
> *configured* cluster a node that cannot emit a durably-persisted marker is
> **peer-visibly epoch-ineligible** (advertises ineligibility, demotes, never
> promotes) → **safe outage + an explicit operator override** for availability; a
> genuinely standalone deployment is explicit config (no peer → no epoch → no
> hold). This removes the never-seen exception, the asymmetric-takeover gap, and
> the attacker-gameable `noteRejectedFromPeer`. v6 also makes epoch allocation a
> **strict successor** (`> max(durable, emitted)`, `MaxUint64`→fail-held), binds a
> **sender-side `{keyGen,key,markerEnabled,epoch,RG}` snapshot** (no stale K1 body
> signed under K2), corrects that **key rotation cannot repair a write fault**,
> uses a **separate hold flag** (not the kernel bool) with an aggregate gate, and
> requires **#5639 to gen-check before applying any pending/in-flight sync
> message** (not just drain installed connections).

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
runbook, and — surfaced by review — a real HA-availability constraint at the
persist boundary (§5.4/§11). **If reviewers judge the residual too narrow to
justify this surface, PLAN-KILL/defer is a legitimate user call** (§11 cost/benefit).

## 3. Prerequisite and composition

- **PREREQUISITE — #5639 (OPEN, bug/security):** the auth-seen proof is split and
  transient — `HeartbeatPeerAuthSeen` dereferences the replaceable receiver
  (`peer_state.go:29`); sync auth arms `SessionSync.syncAuthedEver`
  (`sync_auth.go:415`) which `syncPeerAuthSeen` ORs in (`sync_auth.go:139`); comms
  recreation replaces `SessionSync` (`daemon_ha_sync.go:851`). #6169's epoch
  downgrade-gate rides on the same auth-seen state. **#6169 is BLOCKED-ON #5639**
  (`/engineer 6169` cannot proceed until it lands, or the two are done together).
  **#5639 acceptance criteria** (strengthened per Codex r3–r5): one
  Manager/daemon-scoped cross-channel auth owner armed by *both* heartbeat and
  sync-auth, with a commit-time owner-generation recheck AND a **generation check
  before applying any pending / in-flight sync message** — draining *installed*
  connections is not enough (Codex r5 §6): the current setup removes a connection
  from pre-auth tracking, applies a legacy pending frame, then installs it
  (`sync_conn.go:100/119/130`), and a payload already read before `handleMessage`
  (`sync_conn_read.go:71`) cannot be retracted by closing the connection. The
  owner must therefore gen-check at message-application time (a fully linearized
  arm-and-drain), not only evict connections.
- **Composes with:** #4107 (`XPFA` 52-byte trailer, unchanged), #5477/#6167 ring
  (kept for v1-migration), #5081/#5086. **Independent of held #5078.** v6 keeps
  the corrected note: #5639's owner *does* touch `sync_auth.go`'s auth-seen bit.
- **Reused:** `fullSetSeqGuard` `(incarnation,seq)` comparison (`sync_conn_gen.go:64`).
- **Persistence precedent — SNMPv3 `engineBoots`** (`agent.go:573`):
  **fail-closed on read/parse/arithmetic/write uncertainty.** v6 adopts this
  via persist-before-emit + peer-visible epoch-ineligibility (§5.4).

## 4. The five findings — verified

Unchanged (all CONFIRMED): F1 rolling-upgrade split; F2 ring churn (worse — many
same-epoch sessions from routine restarts); F3 self-lock + undesigned
persistence; F4 lifecycle reset + wrong-node recovery; F5 parse ambiguity. §5
shows how v6 closes each; the resolutions were rebuilt across five rounds.

## 5. Concrete design — v6

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
  practically unreachable (`MaxUint64` at 10 Hz ≈ 10¹¹ years); v6 treats it as a
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
  if macOK && !hasEpoch && sawEpoch { m.mu.Unlock(); REJECT "epoch strip" }
  accept := macOK ? (hasEpoch ? admitEpoch(epoch,counter) : ring.admit(session,counter))
                  : baseAuthDecision(...)
  if !accept { m.mu.Unlock(); REJECT }
  markAuthSeen(); if hasEpoch { sawEpoch=true }
  lastSeen = now                                              // INSIDE the gen-checked txn (Codex r4)
  handlePeerHeartbeatLocked(pkt)                              // peer-alive/RG/election, m.mu already held
m.mu.Unlock()
```

- **Single `m.mu` transaction** (Codex r4): admit → `lastSeen` →
  peer-state/election apply is one critical section under `m.mu`, checked against
  `keyGen` at the top. A `handlePeerHeartbeatLocked` variant avoids the reentrant
  `m.mu` the v4 sketch had. `lastSeen` is set *inside* the transaction, so a
  gen-mismatch drop never leaves `lastSeen≠0` with `peerAlive=false` (which would
  strand a fresh node).
- **Key-publish + admission-reset is one atomic step** (re-prime/§5.5) also under
  `m.mu` and bumping `keyGen`, so no frame is admitted between publish and reset.
  A monotonic `keyGen` counter is ABA-safe (K1→K2→K1).
- **Epoch-strip gate** (`!hasEpoch && sawEpoch → REJECT`) keeps a markerless frame
  out of the churnable ring after a marker has been seen.
- **No `noteRejectedFromPeer`** (dropped in v6): v5 used it to tell a
  present-but-unverifiable peer from an absent one, but Codex r5 showed (a) a
  one-way receive partition defeats it and (b) an attacker's replayed frames make
  it a gameable liveness signal. v6's consistency choice (§5.4) does not need a
  frame-derived presence signal — a *configured* peer is known from config.

### 5.4 Epoch persistence + peer-visible epoch-eligibility (F3 + F4; chooses consistency)

**Persistence rules.**
- **Persist-before-emit:** a frame carries a marker only if that epoch is durably
  persisted (`markerEnabled`), so no unpersisted epoch escapes.
- **Checksummed, never-regress:** the epoch file stores `epoch || crc`. A
  **crc-valid** value is TRUSTED and never regressed below (even far-future — a
  legitimate forward clock advanced with a checked `+1` is safe and need not wait
  for wall time); only a **crc-invalid / absent** value is state-loss. This
  **drops the far-future heuristic**, which Codex r4 showed *regresses* a
  legitimate forward-clock value.
- **Serialized worker + STRICT SUCCESSOR** (Codex r5 §4): one worker; each
  allocation re-reads the durable value and publishes
  `next = max(durable, emitted_high_water) + 1` clamped to also be `≥ clampedNow`
  — **strictly above both the durable floor and any value ever emitted**, and the
  exact published value becomes the emitted epoch. A stale retry can therefore
  never re-publish `P` (which would reset the counter under an unchanged epoch and
  reopen dual-primary). `MaxUint64` reached → **fail held** (never wrap/regress).
  `markerEnabled` is set only for the current `keyGen` after the durable write.
  Bounded backoff off the send path (no per-100 ms fsync).

**Peer-visible epoch-eligibility** (v6's consistency choice — replaces v5's hold):

> **Invariant:** a node may own a redundancy group PRIMARY only if it can emit a
> durably-persisted marker for its current `keyGen` (`markerEnabled`). While it
> cannot (persist-failed / resolving / live key-enable in progress) it is
> **epoch-ineligible**: it (a) **advertises ineligibility on the wire** (a new RG
> flag in the heartbeat body — so a healthy peer takes ownership *even without
> `sawEpoch`*, closing Codex r5 §2), (b) **demotes** any group it holds, and (c)
> **never promotes** via any election path.

The hold is a **dedicated `epochIneligible` source**, distinct from
`kernelUpgradeHold` (Codex r5 §3 — literal reuse cross-clears); the promotion gate
is the aggregate `kernelUpgradeHold || epochIneligible || …`, each source
sets/clears its own flag, and the demote-if-primary re-fires whenever the aggregate
transitions armed.

**The consistency choice (Codex r5 §1 — the fundamental point).** Sole-node
availability and two-node partition safety are **impossible from heartbeat absence
alone** (a one-way receive partition is indistinguishable from an absent peer). So:
- **Configured cluster:** an epoch-ineligible node **never promotes**, even if it
  hears nothing (which could be a one-way partition). Outcomes:
  - *Asymmetric* (A ineligible, B healthy): A advertises ineligibility + demotes;
    B reads it and **owns** (regardless of `sawEpoch`). → B primary, A secondary. ✓
  - *Both-ineligible* (correlated persist fault) or *A-ineligible + B-genuinely-down*:
    **safe outage** (no primary) — the design deliberately chooses consistency over
    a possible dual-primary. Availability is restored by **storage recovery** or an
    explicit **operator override** (`request chassis cluster force-primary
    epoch-degraded`, audited) when the operator confirms the peer is truly dead.
- **Standalone:** a genuinely single-node deployment (no cluster / an explicit
  standalone marker) has no peer to replay-protect → the epoch mechanism and its
  eligibility gate do not engage at all.

This **subsumes the live key-enable window**: while the epoch is unresolved for a
new `keyGen` the node is epoch-ineligible, which guards *every* promotion path and
is advertised, so a live empty→key-enable cannot promote on stale state. The
resolve runs on the serialized worker off `m.mu`.

**Sender-side generation atomicity** (Codex r5 §5): the sender takes ONE snapshot
binding `{keyGen, key, markerEnabled, epoch, RG states, eligibility}` and signs
from it; if `keyGen` advanced since the snapshot it re-snapshots — so a paused
sender can never sign a stale K1 marker/PRIMARY body under K2.

### 5.5 Re-prime + coordinated recovery (F4)

Re-prime clears only `{highEpoch, highCounter, sawEpoch}` (keep `peerAuthSeen`,
the ring, the sender nonce — a rolled-back v1 node still signs `XPFA`). **Race-free
recovery = coordinated cluster-wide rotation to a NEVER-USED key** (config-synced
PSK): *isolate → (roll back if applicable) → install the new key on **both** nodes
→ the atomic keyGen-bump resets each node's floor (§5.3) → reconnect.* A never-used
key makes archived captures unverifiable; the atomic keyGen-bump+reset prevents an
in-flight old-key frame re-arming. A one-sided key change (MAC mismatch → split) is
unsafe. **Key rotation does NOT repair a persist/write fault** (Codex r5 §4): a
node that cannot write stays epoch-ineligible after rotation — that path is
recovered by **storage repair or the operator override**, not by rotation. Rotation
recovers the *receiver-floor* self-lock (a crc-invalid or rolled-back durable
value), not the *sender's* inability to persist.

## 6. Honest residuals

- **Post-restart / post-re-prime single-admit window** (bounded): after a receiver
  daemon restart or a re-prime, `highEpoch=0`; a retired frame can be admitted
  **once** and cause a transient election effect before the live higher-epoch
  frame repairs the floor. The epoch closes the **sustained** replay; fully
  closing the single-admit needs disk-persisting the **receiver** floor (named
  follow-up, adds its own cross-restart self-lock).
- **crc-invalid corruption / deletion ∧ backward-clock self-lock** (§5.4):
  operator-recoverable via cluster key rotation (§5.5, receiver-floor reset).
- **Rollback to an older complete `{epoch,crc}` pair** (Codex r5 §4): a filesystem
  snapshot restore reinstates a *valid* older value that CRC cannot detect as
  stale; it regresses the durable floor. Mitigation is out of band (don't restore
  `/var/lib/xpf/ha-boot-epoch` from a snapshot; or a monotonic-hardware counter) —
  documented, not solved in-band.
- **`MaxUint64` epoch exhaustion** (Codex r5 §4): unreachable at 10 Hz (~10¹¹
  years) but has no successor; the worker **fails held** rather than wrapping.
- **Persist/write fault → epoch-ineligible → safe outage** (§5.4): a node that
  cannot durably write its epoch is epoch-ineligible and will not own a group; if
  it is the only otherwise-healthy node the cluster has **no primary** until
  storage recovers or the operator issues the audited `force-primary
  epoch-degraded` override. This is the deliberate consistency-over-availability
  choice; it is a real availability cost of the mechanism (see §11 cost/benefit).

## 7. Multiple Path Options (final)

- **Wire:** key-derived tail-anchored marker (A, chosen) vs forward-parsed TLV
  (B, desyncs on archived bodies) vs v2 trailer / version bump (C, F1/blast-radius).
- **Same-epoch guard:** separated nonce + `(epoch,counter)` (A) vs
  shared/reset-on-key nonce (B, breaks the order) vs bigger ring (C, moves the
  constant).
- **Persist-failure / ownership:** **peer-visible epoch-ineligibility + choose
  CONSISTENCY (A, chosen — a configured-cluster ineligible node advertises, demotes,
  never promotes; availability via storage recovery / audited operator override)**
  vs a hold that promotes via never-seen (B, one-way partition → dual-primary —
  round-5 killer) vs markerless + peer-timeout alone (C, round-4 killer) vs a
  volatile election fence (D, round-3 killer). The consistency choice is forced:
  sole-node availability + partition safety is impossible from heartbeat absence
  alone.
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
| HA availability (self-lock / ownership) | **MED-HIGH** | Persist-before-emit removes the crash-escape and peer-visible epoch-ineligibility prevents the markerless dual-primary, but the consistency choice makes a persist fault an eligibility (potential safe-outage) condition recovered by storage repair or an audited operator override — a real availability cost (§11). |
| Wire/interop | **LOW** | Unchanged 52-byte `XPFA`; key-derived marker; old receiver ignores it; `bodyEnd≥16` guard. |
| Security (replay/downgrade) | **LOW-MED** | Total order + key-gen linearization + epoch-strip gate + cross-channel owner; bounded single-admit residual documented. |
| Coupling / scope | **MED-HIGH** | Hard #5639 prereq + persist/election-integration — a sequenced multi-PR effort. |

## 11. Out of scope / PLAN-KILL / cost-benefit

Disk-persisting the receiver floor (single-admit window) — follow-up. Retiring the
v1 ring — kept for migration.

**The cost/benefit the research surfaced (now the load-bearing decision).** Five
rounds validated the anti-replay *center* (key-derived marker + `(epoch,counter)`
total order) but proved the *persistence/ownership boundary* is genuinely hard:
because the epoch is a **durable** security counter, a node's ability to be PRIMARY
now depends on writing it, and a partition cannot be told from an absent peer — so
the only safe choice is **consistency** (a persist-failed node is epoch-ineligible
→ possible safe outage until storage recovery / an operator override). That is a
**real HA-availability constraint** traded for closing a **narrow** residual (an
on-path sniffer with ≥65 captured sessions). Two honest terminal outcomes:
- **Proceed (scoped):** the design is sound and complete; drive it sequenced
  behind #5639, Stage 0 (restart-churn, no wire change, independently valuable)
  before Stage 1 (the epoch + ownership), accepting the availability constraint.
- **PLAN-KILL / defer:** keep the honest 64-ring bound (already documented by
  #6167) and decline the epoch, judging the availability constraint too high for
  the residual. **Codex has held that PLAN-KILL is not *forced*** (the defects are
  repairable) — but the cost/benefit is a **user judgment**, which is exactly why
  `/research` stops here for approval rather than auto-proceeding.

## 12. Open questions for round-6 (each invitable to PLAN-KILL)

1. **Peer-visible ineligibility + consistency choice.** Is advertising an epoch-
   ineligible RG flag (peer takes ownership without `sawEpoch`) + "an ineligible
   node in a configured cluster never promotes" free of any remaining dual-primary
   or wrong-owner schedule, and is the audited `force-primary epoch-degraded`
   override the right availability escape?
2. **Strict successor.** Is `next = max(durable, emitted)+1` (≥ clampedNow,
   `MaxUint64`→fail-held) the correct allocation, and does it compose with the
   serialized worker so no reboot/retry ever re-publishes `P`?
3. **Separate hold flag + aggregate gate.** Does a dedicated `epochIneligible`
   source (with a demote-re-fire on aggregate arm) compose cleanly with
   `kernelUpgradeHold`/`ResetFailover` without cross-clearing?
4. **Sender-side snapshot.** Does one `{keyGen,key,markerEnabled,epoch,RG,eligibility}`
   snapshot (re-snapshot on `keyGen` change) fully close the stale-K1-body-under-K2
   send race, and where does it slot vs the current build-then-read-key sender?
5. **#5639 message-time gen check.** Is "gen-check before applying any
   pending/in-flight sync message" the right prerequisite bar, and does it belong
   in #5639 or #6169 Stage −1?
6. **Cost/benefit — the load-bearing decision.** The mechanism now makes a node's
   ability to be PRIMARY depend on durably writing a boot-epoch file: a persist
   fault → epoch-ineligible → potential safe-outage until storage recovery / an
   operator override. Is trading that HA-availability constraint for closing the
   on-path-sniffer replay residual the right call, or is the honest outcome to
   keep the documented 64-ring bound (#6167) and PLAN-KILL / defer the epoch? This
   is the decision the research now puts to the user.

## 13. Research conclusion & recommendation (converged after 6 rounds)

Six hostile plan-review rounds (Codex r1–r6 + Claude SMR r1–r6; AGY infra-down)
converged on the following, which is the actual `/research` deliverable:

**What is settled (both reviewers).**
- The **anti-replay center is validated**: the key-derived, tail-anchored,
  MAC-verified epoch marker (F1/F5) + the separated Manager send-nonce with an
  `(epoch,counter)` total order (F2) is correct and worth implementing. Codex
  confirmed it every round; PLAN-KILL of the *mechanism* is **not** justified.
- The **consistency choice is correct**: a durable security epoch cannot preserve
  both sole-node availability and two-node partition safety from heartbeat absence
  alone, so a persist-failed node in a configured cluster must be
  epoch-ineligible.
- **Stage 0 is independently valuable and cheap**: Manager-scoping the anti-replay
  nonce + the field caps closes the **routine-restart churn** (the *more common*
  vector Codex identified) with **no wire change and no availability cost**.

**What Stage 1 (the wire epoch) still requires** — the six rounds showed it
entangles the *entire* HA stack, and each round surfaced a new cross-layer
dual-primary hazard that is fixable but not yet fully specified:
- a **two-phase actuation barrier** (physically fence VRRP-resign + dataplane
  deactivate *before* advertising ineligibility / releasing peer takeover — the
  logical demote is async/droppable over a 64-event channel; Codex r6 §1);
- a **rolling-upgrade-safe wire contract** for ineligibility — project it onto the
  **existing legacy yield encoding** (`weight=0` / `StateSecondaryHold`, which old
  receivers already honor) or capability-gate it, not a new unrecognized flag
  (Codex r6 §2);
- an **operator override that is a break-glass consistency waiver** with durable
  peer fencing + auto-revoke-on-peer-return (Codex r6 §3);
- an explicit **engagement predicate** `epochRequired = configuredCluster &&
  keyConfigured` (keyless clusters do not engage the epoch at all; keyed→empty
  defined) (Codex r6);
- the **#5639 prerequisite** (cross-channel auth owner + message-application-time
  generation check, linearized through deferred config to `configApplyLoop`).

**Recommendation to the user.** Given a **narrow** residual (an on-path sniffer
with ≥65 captured sessions) against a **large, #5639-blocked, full-HA-stack
change with a real availability cost** (a durable-write fault → possible
safe-outage / break-glass override):

1. **Ship Stage 0** (Manager-scope the nonce + caps) — it closes the common
   routine-restart vector safely and cheaply, no wire change. This can proceed as
   its own PR (and largely *is* #5639's heartbeat lifecycle fix).
2. **Defer / PLAN-KILL Stage 1** (the wire epoch) as currently scoped — keep the
   honest 64-ring bound (#6167 already documents it) and revisit the full epoch
   only if the threat model justifies the cross-layer cost, ideally with a witness
   / quorum that removes the partition-vs-absence ambiguity at the root.

The reviewers did **not** reach a clean PLAN-READY for the full Stage 1 (Codex
held NEEDS-MAJOR each round with a real, new, fixable cross-layer finding; SMR
reached READY only *conditional* on the user accepting the availability cost).
That non-convergence is itself the signal: **Stage 1 is a genuine multi-PR HA
program, not a bounded fix**, and the decision to pay its cost is the user's.

---

### Appendix — files in blast radius (for /engineer)

`pkg/cluster/heartbeat.go` (marker derive/write/parse, +68 tail reserve,
MAC-before-`bodyEnd`, `bodyEnd≥16`, `admit*` with the epoch-strip gate, `readLoop`
single `m.mu` transaction + `lastSeen`-inside + `handlePeerHeartbeatLocked` +
sender-side `{keyGen,key,markerEnabled,epoch,RG,eligibility}` snapshot);
`pkg/cluster/heartbeat_epoch.go` new (checksummed persist, serialized worker with
STRICT-SUCCESSOR allocation, `markerEnabled`); `pkg/cluster/manager.go`
(`peerAdmission` + sender nonce + `epochState` + `keyGen`; dedicated
`epochIneligible` hold source + aggregate promotion gate; cross-channel owner via
#5639); `pkg/cluster/election.go` / `kernel_selfrecover.go` (aggregate gate;
epoch-ineligible advertised + demoted + never promotes in a configured cluster); `pkg/cluster/group_state.go` (atomic keyGen-bump+reset on key change);
`pkg/cluster/heartbeat_manager.go` (`buildHeartbeat` reads resolved epoch; marker
gated on `markerEnabled`); `pkg/config` (commit-time monitor/name caps);
`pkg/cluster/README.md` + this doc. Tests: F1 mixed-version both ways; **F2 65
same-epoch sessions must not churn the guard**; F3 persist-fail→epoch-ineligible
(asymmetric peer-takeover, configured-cluster both-fail/peer-down safe-outage,
true-standalone epoch-disengaged),
crash-after-would-be-emit (no escape), crc-invalid+backward-clock recovery,
forward-clock-correction NO regression, async-retry no durable regress; F4 key-gen
TOCTOU (K1-verify/K2-reset/stale drop + `lastSeen` not stranded), live key-enable
under the hold, epoch-strip reject, coordinated re-prime; F5 archived 256-byte-name
body → no false marker, short v1 body no panic, keyless full-frame parse.
