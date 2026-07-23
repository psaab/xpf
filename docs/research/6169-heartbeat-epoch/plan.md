# #6169 — cluster/heartbeat across-reboot boot-epoch anti-replay (research plan)

**Status:** DRAFT v1 — pending adversarial plan review (Claude SMR + Codex; AGY infra-down)

Research worktree: `.claude/worktrees/6169-research`, branch
`research/6169-heartbeat-epoch`. Base: `origin/master` @ `11e23b49a`.
This is a **/research** deliverable: it STOPS at PLAN-READY. No production
code is touched. Implementation begins only on `/engineer 6169`.

---

## 1. Issue framing

#5477 (merged as #6167) closed the pre-existing single-watermark A→B→A
heartbeat replay by remembering a **bounded set of 64 per-session high-water
counters** in `heartbeatAuthReplay.admit` (`pkg/cluster/heartbeat.go`). That
raised the on-link replay attacker's cost from 2 recorded incarnations to 65.

The #6167 hostile review proved the bound is **not absolute**: ring eviction is
FIFO and is triggered by any never-seen session, *including a replayed retired
frame*. An attacker who has passively captured **`heartbeatReplaySessions`+1
(= 65) or more** distinct authenticated daemon incarnations off the wire can
churn the ring by **replay alone** (no reboot, no minting) and sustain a forged
liveness/election drive indefinitely (empirically: 64 recordings → all
rejected; 65 → sustained admits).

#6169 asks for the **complete fix**: sign a **monotonic-across-reboot boot
epoch** into the heartbeat frame so a retired incarnation always carries a
lower epoch than the live one and can never be replayed once a newer
incarnation is seen — closing the ≥65-recording sustained replay with **O(1)
receiver state**, independent of the bounded ring.

A first implementation (**closed PR #6370**) reached the full merge gate and
**both** reviewers returned MERGE-NEEDS-MAJOR with five structural findings.
This plan resolves all five coherently before any code is written again.

## 2. Honest scope / value framing

- **What the win is.** Closes a **named, documented residual** (#6167's own
  follow-up). Concretely: an on-path attacker who has sniffed the control link
  across ≥65 distinct daemon incarnations over the cluster's lifetime can today
  replay a retired incarnation's authenticated heartbeat to refresh peer
  liveness and re-apply its stale RG role/priority. The boot epoch reduces that
  from "sustainable indefinitely" to "rejected the instant a newer incarnation
  has been observed," with **O(1)** state (`highEpoch`, `sawEpoch`) rather than
  the O(64) ring.
- **Threat model.** A passive **on-path** sniffer on the dedicated cluster
  control link (`em0`, `10.99.x.x`) with a valid capture history — the same
  attacker #4107/#5477 already assume. The PSK/HMAC (#4107) still blocks forging
  or minting; this closes only the *replay-of-captured-authenticated-frames*
  residual.
- **Cost.** A wire change (8 signed bytes/frame) + receiver state + a
  persistence file. The heartbeat is ~10/s per direction, so the byte cost is
  negligible.
- **Absolute-scale honesty.** This is a **defense-in-depth** hardening of an
  already-authenticated channel against a strong, patient, on-path attacker. It
  is not a fix for an unauthenticated exposure. **If reviewers conclude the
  residual is too narrow to justify the wire change + migration + self-lock
  surface, PLAN-KILL is an acceptable verdict** (see §10 for why we do *not*
  recommend it: the receiver-only alternatives only move the constant, and the
  project already committed to the complete fix as a named follow-up).

## 3. What's already shipped / partially batched (must compose with)

- **#4107 control-channel auth** (`heartbeat.go`): PSK/HMAC-SHA256 trailer
  `"XPFA"(4)+session(8)+counter(8)+HMAC(32)` = **52 bytes**, appended after the
  body. `heartbeatAuthDecision` is the dual-accept policy (no key → accept all;
  key + trailer → enforce MAC + nonce; key + no trailer + `peerAuthSeen` →
  reject as cleartext downgrade). **KEYED IS ENFORCING**: a keyed receiver that
  has seen the peer authenticate rejects a frame with no recognized trailer.
- **#5477/#6167 bounded nonce ring** (`heartbeatAuthReplay`, 64 slots, FIFO):
  rejects a return to a session at/below its remembered watermark; the ≥65
  residual is exactly what #6169 closes. **We must NOT restructure this ring** —
  the plan layers the epoch gate *in front of* it.
- **#5639 `peerAuthSeen` sticky-bit lifecycle** on comms-recreate — the receiver
  is recreated on `RestartHeartbeat`, resetting its sticky auth state. #6169's
  new receiver state has the *same* lifecycle question (finding 4) and must
  follow a coherent discipline, not restructure #5639.
- **#5081 / #5086** — #5086's A→B→A ring already merged (#5477/#6167); #5081 is a
  `pkg/daemon` transport-key reconcile, not the wire. #6169 is additive to both.
- **Independent of held #5078** (session-sync PSK handshake in `sync_auth.go`, a
  separate TCP mechanism). #6169 touches only the UDP heartbeat frame. Verified:
  no read/write of `sync_auth.go`.
- **HA-version machinery** (`peer_state.go`, `sync.go`): the frame's
  `HAProtocolVersion` field feeds `HAProtocolVersionMismatch` → the #1930
  mixed-base readiness gate (`daemon_ha_userspace_readiness.go`) which **blocks
  RG transfer** on mismatch, and `SessionSyncWireVersion = CurrentHAProtocolVersion`
  gates session sync. **This is load-bearing for the design** — see §5.
- **Precedents to mirror.** SNMPv3 `engineBoots` persistence
  (`pkg/snmp/agent.go`: load/increment/persist, **fail-closed to the ceiling on
  corruption**, `/var/lib/xpf`), and the #4126 VRRP-checksum dual-accept
  migration (`pkg/vrrp/packet_checksum_test.go`). The #2239 DHCP-lease-sync and
  the `sync_protocol.go` extensions are the project's established pattern for
  **additive, length-gated, self-detecting wire growth with NO version bump**.

## 4. The five findings — verified firsthand against `origin/master` + PR #6370

Each was re-derived against the actual code, not taken on report.

### F1 — Rolling-upgrade split (Critical). CONFIRMED.
PR #6370's sender emits the v2 `"XPFE"` **60-byte** trailer *unconditionally*
whenever keyed (`heartbeat.go` `send()`), with **no peer-capability gate** and
**no `CurrentHAProtocolVersion` bump** (still 1). A v1 keyed receiver on
`origin/master` locates its trailer by checking `"XPFA"` at `len-52`; in a v2
frame `len-52` lands on the random `session[4:8]` bytes, so `present=false`.
In a *running keyed cluster* both nodes have `peerAuthSeen=true`, so
`heartbeatAuthDecision(key, present=false, …, peerAuthSeen=true)` returns
`false, "missing auth trailer (enforced: peer previously authenticated)"` — the
v1 node **rejects every v2 frame**, declares the upgraded peer dead, and
promotes → **dual-primary during rolling upgrade**. Unlike the v1 trailer
(whose predecessor was keyless/accept-all), there is **no free additive
dual-accept** for a *size-changing* trailer.

### F2 — Bypassable via ring-churn (Critical). CONFIRMED.
In `readLoop`, `nonceFresh := auth.macOK && r.authReplay.admit(session, counter)`
runs **before** `epochAdmit`. `admit()` inserts/evicts the FIFO ring
*regardless of the epoch outcome*, so a MAC-valid **lower-epoch** frame that
`epochAdmit` will reject **still mutates the ring**. ~65 distinct MAC-valid
lower-epoch captures (each a different retired session) churn the live session
out of the ring; a captured **current-high-epoch** frame is then ring-"new"
again, and `epochAdmit` admits an **equal** epoch (`epoch < highEpoch` is
false) → the replay is re-admitted. The epoch check must run **before** (or
atomically with) any ring mutation.

### F3 — Genuine-reboot self-lock (Major). CONFIRMED.
`nextBootEpoch = max(persisted+1, wall_clock_nanos)`. A **lost/corrupt** state
file → `prev=0` → epoch = wall clock. A persistence **write failure** logs but
returns the unpersisted epoch, and `bootEpochOnce` (`sync.Once`) **caches it and
blocks any retry**. If the peer stored high-water `E`, and then this node's
epoch file is wiped/corrupt **and** its wall clock is now `< E` (a backward RTC
step / NTP correction across the loss), the genuine reboot emits `< E` and the
peer **rejects it forever** — the peer's high-water is in-memory and only
self-heals when the *peer* restarts. That is a **HA availability regression**
(a security fix that can wedge a genuine node out of the cluster). Note both
conditions are required: state-loss alone is covered by the wall-clock floor;
backward-clock alone is covered by `persisted+1`.

### F4 — State-lifecycle reset (Major). CONFIRMED.
`RestartHeartbeat` (`heartbeat_manager.go`) recreates the receiver via
`newHeartbeatReceiver`, preserving **only `lastSeen`** (explicitly seeded back);
`sawEpoch`, `highEpoch`, the `authReplay` ring, and `peerAuthSeen` are all
**zeroed**. A routine heartbeat restart (a VRF rebind / config-triggered
recompile — `RestartHeartbeat` is called on control-interface changes) thus
**silently reopens** replay/downgrade acceptance: the next frame re-anchors
`highEpoch` at whatever arrives (possibly a replayed low value) and `sawEpoch`
resets so a v1-downgrade is accepted again. Separately, a **legitimate v2→v1
software rollback** (`git revert` of #6169 on one node) is **indistinguishable**
from an epoch-strip downgrade attack: sticky `sawEpoch` makes the peer reject
the rolled-back node's v1 frames forever. There is no controlled re-prime.

### F5 — Parse ambiguity (Moderate). CONFIRMED — and the PR's own reasoning is wrong.
`verifyHeartbeatMAC` MACs exactly `data[:len-32]` for **both** formats.
`parseHeartbeatAuth` tries v2 first: if `"XPFE"` sits at `len-60`, it computes
`verifyHeartbeatMAC(data,key)` — **the same span a v1 frame already signs** — so
a genuine **v1** frame whose 4 body bytes at `len-60` happen to spell `"XPFE"`
(≈2⁻³²) **passes the v2 MAC** and is mis-parsed as v2 with a garbage epoch
(e.g. `SoftwareVersion="XPFEzz…"`). The PR comment claims it "falls through to
the correct v1 parse," but the fall-through only runs when the v2 MAC *fails* —
which it does **not**, because the MAC span is identical. Worse: the misparse
latches `hasEpoch`+`sawEpoch=true`, after which the receiver **rejects every
subsequent genuine v1 frame as a downgrade** → a single coincidence can wedge a
still-v1 peer.

## 5. Concrete design — RECOMMENDED path (Path A: epoch in the MAC-covered body)

The decisive insight: PR #6370's findings F1 and F5 are **inherent to changing
the auth trailer** (new magic, new size). If instead the epoch rides in the
**MAC-covered heartbeat body** and the **`"XPFA"` (52-byte) auth trailer is left
byte-for-byte unchanged**, both findings dissolve, because:

- an **old (v1) receiver** still finds `"XPFA"` at `len-52`, still verifies the
  HMAC over `data[:len-32]` (which now includes the epoch body bytes — the MAC
  still matches because it is computed over the actual bytes sent), still
  `admit()`s, and its `UnmarshalHeartbeat` **stops after `HAProtocolVersion` and
  ignores the trailing body bytes + trailer** (verified: exactly one non-test
  caller, `readLoop:796`; it returns right after reading `HAProtocolVersion`).
  → **No F1 rolling-upgrade split; emit can be unconditional when keyed.**
- there is **only one auth-trailer format** (`"XPFA"`), so there is no v1/v2
  trailer to confuse. → **F5 disappears entirely.**

### 5.1 Wire format (v-additive, no version bump)

Body layout today ends with the optional version trailer:
`[VersionLen][SoftwareVersion][HAProtocolVersion(2)]`. We append **one optional
MAC-covered field** after it:

```
… [VersionLen][SoftwareVersion][HAProtocolVersion(2)] [BootEpoch(8, LE)]   ← body (MAC-covered)
  [ "XPFA"(4) ][ session(8) ][ counter(8) ][ HMAC-SHA256(32) ]             ← unchanged #4107 trailer
```

**Presence detection is deterministic, not sentinel-guessed.** Because the auth
trailer is a **fixed 52 bytes** (unchanged), the receiver first locates it
(`heartbeatAuthTrailer` → `"XPFA"` at `len-52`) and thereby knows
`bodyEnd = len-52` exactly. It parses the body `[:bodyEnd]`; if, after the
version section ends at offset `off`, there are exactly 8 residual bytes
(`bodyEnd - off == 8`), those bytes **are** the boot epoch. A not-yet-upgraded
keyed sender emits no residual bytes (`off == bodyEnd`) → `hasEpoch=false`.
There is **no magic/sentinel** and therefore **no F5-class collision** — the
trailer boundary is authoritative and MAC-covered.

- **We do NOT bump `HAProtocolVersion` / `CurrentHAProtocolVersion`.** Verified
  blast radius: `SessionSyncWireVersion = CurrentHAProtocolVersion` and the
  frame's `HAProtocolVersion` feeds `HAProtocolVersionMismatch` →
  `daemon_ha_userspace_readiness.go` **blocks RG transfer + session sync on
  mismatch**. Sending version 2 to a v1 peer would set its
  `peerHAProtocolVersion=2`, trip the mismatch gate, and **break session sync /
  handoff during the rolling upgrade** — a *different* split. The epoch is
  therefore a **self-contained additive body field**, mirroring the #2239
  DHCP-lease-sync and `sync_protocol.go` "additive, length-gated, no version
  bump" discipline.
- **Never-unsigned-when-keyed invariant preserved.** `marshalHeartbeatBody`
  already reserves the trailer tail; we add 8 to the body reserve so a keyed
  frame is still guaranteed to fit and is never silently downgraded to
  unsigned.

### 5.2 Sender

`send()` keeps calling **`MarshalHeartbeatAuth`** (the v1 signer) but with the
epoch woven into the body — i.e. `buildHeartbeat` sets a new
`HeartbeatPacket.BootEpoch uint64` field, and `marshalHeartbeatBody` writes it
after the version section **only when non-zero and keyed**. The trailer code is
untouched. Emit is **unconditional when keyed** (safe per §5). Signature options
in §6.

### 5.3 Receiver — ordering that closes F2

`readLoop` is reordered so the epoch gate runs **before** the ring mutates:

```
auth := parseHeartbeatAuth(buf[:n], key)          // v1 trailer only; unchanged
epoch, hasEpoch := parseBodyEpoch(buf[:n], auth)  // body field, bounded by bodyEnd=len-52
accept, reason := heartbeatAuthDecision(len(key)>0, auth.present, auth.macOK, /*nonceFresh*/ true-placeholder…)
// NOTE: restructure so admit() is NOT called until the epoch gate passes:
if auth.macOK {
    // 1) epoch gate FIRST — no ring mutation yet
    epochFresh := hasEpoch && m.epochAdmit(auth.senderNode, epoch)   // Manager-scoped (F4)
    accept, reason = heartbeatEpochDecision(hasEpoch, epochFresh, m.sawEpoch())
    // 2) only if the epoch passed do we consult/mutate the #5477 ring
    if accept && !r.authReplay.admit(auth.session, auth.counter) {
        accept, reason = false, "stale nonce (replay)"
    }
}
```

- A **lower-epoch** (retired) frame is rejected at step 1 and **never touches
  the ring** → the churn bypass (F2) is dead: the live session can no longer be
  evicted by retired-frame replay.
- An **equal-epoch** frame (same live incarnation) passes step 1 and the
  **#5477 ring still governs intra-incarnation counter replay** (unchanged
  semantics — this is why we keep, not restructure, the ring). A same-epoch
  replay is caught by the ring exactly as today.
- `epochAdmit` only advances `highEpoch` for `epoch >= highEpoch` (monotone
  tighten), so advancing-then-ring-reject can never *open* a replay.

`heartbeatEpochDecision(hasEpoch, epochFresh, peerEpochSeen)` keeps PR #6370's
truth table (v2 fresh → accept; v2 stale → reject; v1 while peer not-yet-epoched
→ accept; v1 after peer epoched → reject as downgrade), composed with
`heartbeatAuthDecision` so each stays small and independently tested.

### 5.4 Sender epoch source — F3 discipline

`nextBootEpoch = max(persisted_prev + 1, wall_clock_nanos)`, persisted durably
via `fsatomic.WriteFileDurable` to `/var/lib/xpf/ha-boot-epoch`, **mirroring
SNMP `engineBoots`** (same root, same "load/increment/persist once, seed high on
loss" discipline). The two terms are both required (state-loss → wall clock;
backward-clock-with-state → `persisted+1`). Hardening beyond PR #6370:

1. **Persist-before-first-send.** The value is committed to disk **before** it
   is ever emitted; on a persist **failure** we do **not** finalize
   `bootEpochOnce` with an unpersisted value that blocks retry — instead we
   retry on the next keyed send until it sticks (or degrade to the wall-clock
   floor, which is already ~1.7·10¹⁸ — far above any counter — logging LOUD).
   This removes the "`sync.Once` caches an unpersisted epoch" trap in F3.
2. **Never regress.** `epoch` is monotone across every restart *except* the
   simultaneous state-loss **and** backward-clock case, which is
   operator-recoverable (§5.5), never a silent wedge.

### 5.5 Receiver state lifecycle — F4 discipline

Move `highEpoch` + `sawEpoch` **off the transient `heartbeatReceiver` and onto
the `Manager`** (alongside the existing `bootEpoch`/`bootEpochOnce`), accessed by
the receiver through `Manager` methods. Lifecycle boundary:

- **Survives a heartbeat restart** (`RestartHeartbeat` / config-triggered
  recompile) → **closes F4a** (routine restart no longer reopens the window).
- **Cleared on a full daemon restart** (new `Manager`) → gives a **natural,
  controlled re-prime**: a legitimate **v2→v1 software rollback** restarts the
  daemon, and the peer's `sawEpoch`/`highEpoch` re-prime on the peer's next
  daemon restart, so a coordinated rollback (the operator restarts the node they
  roll back) is accepted — **closes F4b** without a bespoke command. The **same
  boundary is the F3 recovery**: to clear a rare self-lock, restart the
  *rejecting* peer's daemon. This is documented as the operator recovery for
  both F3 and F4b.

This matches the existing #4107/#5477/#5639 discipline (their ring +
`peerAuthSeen` already reset on daemon restart), so we compose with, rather than
restructure, held work. See §5.6 for the residual and the disk-persist
alternative.

### 5.6 Honest residuals of the recommended path

- **Post-daemon-restart anchor window** (bounded, ~1 heartbeat interval): after a
  daemon restart `highEpoch=0`; an on-path attacker who can *also* DoS the live
  peer could anchor low and briefly walk the high-water through captured retired
  epochs. The live peer's higher-epoch frame immediately overrides it once
  heard. This is the **same** post-restart window #4107's `peerAuthSeen` and
  #5477's ring already accept. Closing it fully requires disk-persisting the
  **receiver** high-water (Option 4-ii, §6.3), which trades the window for a
  harder self-lock that needs operator file surgery. **Recommended default:
  in-memory Manager-scoped, document the window honestly** (the project values
  honest security docs — cf. #6167's own correction).

## 6. Multiple Path Options (the design-heavy decisions)

### 6.1 Wire encoding (findings F1 + F5)
- **Path A — epoch in MAC-covered body, `"XPFA"` trailer unchanged (RECOMMENDED).**
  Dissolves F1 and F5; unconditional keyed emit; no version bump; no
  session-sync blast radius. Cost: `marshalHeartbeatBody` + `UnmarshalHeartbeat`
  learn one optional trailing field; the receiver computes `bodyEnd=len-52`.
- **Path B — keep a v2 auth trailer, but capability-gate the emit.** Sender
  emits v1 until it has proof the peer speaks v2, then switches. Needs a
  bootstrap that avoids the "both wait for the other" deadlock — e.g. an
  **additive body capability flag** ("I speak epoch") that both advertise, and
  each switches to the v2 trailer only once *mutual* capability is observed.
  Still carries F5's parse-ambiguity risk (two trailer formats) unless a
  MAC-covered type discriminator is added. **More moving parts than Path A for
  no benefit.**
- **Path B′ — v2 trailer gated on `HAProtocolVersion≥2`.** REJECTED: bumping /
  sending version 2 trips `HAProtocolVersionMismatch` → blocks session-sync + RG
  transfer during rolling upgrade (verified blast radius). Would need a separate
  epoch-capability signal *anyway*, i.e. it collapses back into Path B.

### 6.2 Sender epoch monotonicity (finding F3)
- **Option 3-i — `max(persisted+1, wall_clock)` + persist-before-send +
  operator recovery (RECOMMENDED).** Monotone in every case but the rare
  state-loss∧backward-clock, which is operator-recoverable (restart the
  rejecting peer). Mirrors SNMP engineBoots.
- **Option 3-ii — auto re-anchor on confirmed peer-down + new session.**
  REJECTED: an attacker who can make the real peer appear down can then get a
  retired replay re-anchored — reopens the exact attack the epoch closes.
- **Option 3-iii — pure persisted counter (no wall clock).** REJECTED:
  state-loss resets to 0 and *always* self-locks against the peer's high-water;
  the wall-clock floor is what makes state-loss safe.

### 6.3 Receiver high-water lifecycle (finding F4)
- **Option 4-i — Manager-scoped in-memory (RECOMMENDED).** Survives heartbeat
  restart (closes F4a); cleared on daemon restart → natural re-prime (closes
  F4b) + F3 recovery. Matches #4107/#5477/#5639.
- **Option 4-ii — disk-persist the receiver high-water.** Closes the
  post-restart window (§5.6) but reintroduces a cross-daemon-restart self-lock
  that needs operator file surgery on a legit peer reboot with state loss.
  Offer as a documented follow-up, not the default.
- **Option 4-iii — explicit operator re-prime command**
  (`request chassis cluster heartbeat-epoch reset`). Cleaner UX than "restart
  the daemon," but more surface; can be added later. Not required if 4-i's
  daemon-restart boundary is accepted.

## 7. Public API preservation

- `MarshalHeartbeat`, `UnmarshalHeartbeat`, `MarshalHeartbeatAuth`,
  `heartbeatAuthTrailer`, `verifyHeartbeatMAC`, `heartbeatAuthDecision`,
  `heartbeatAuthReplay.admit` — **signatures unchanged**. (Path A adds an
  optional body field read *inside* `UnmarshalHeartbeat`/`marshalHeartbeatBody`;
  their signatures do not change.)
- `HeartbeatPacket` gains one field `BootEpoch uint64` (additive struct field).
- New: `Manager.epochAdmit`, `Manager.sawEpoch()`, `heartbeatEpochDecision`,
  `nextBootEpoch`, `Manager.heartbeatBootEpoch`, `parseBodyEpoch` (helper).
- `CurrentHAProtocolVersion`, `MinCompatHAProtocolVersion`,
  `SessionSyncWireVersion` — **unchanged** (deliberately, §5).
- No `sync_auth.go` (#5078), no ring restructure (#5477), no `peerAuthSeen`
  restructure (#5639).

## 8. Hidden invariants the change must preserve

- **Never-unsigned-when-keyed** (#4107): the +8 body bytes go into the tail
  reserve; a keyed frame still always carries its HMAC.
- **Side-effect ordering**: epoch gate strictly **before** `authReplay.admit`
  (F2); `sawEpoch` read for the downgrade gate **before** `epochAdmit` could set
  it (v2 branch does not consult `peerEpochSeen`).
- **Dual-accept during rolling upgrade** stays *additive* (old receiver ignores
  the body field + validates the unchanged trailer) — no enforcing rejection of
  a mixed-version peer (F1).
- **No `HAProtocolVersion` semantic change** → mixed-base session-sync + RG
  handoff gates unaffected.
- **HA sync portability**: heartbeat frame only; no `syncMsg*`/`syncHeader`
  change; `SessionSyncWireVersion` untouched.
- **Monotonicity**: sender epoch strictly increases across restart/reboot except
  the operator-recoverable state-loss∧backward-clock case.
- **Concurrency**: `highEpoch`/`sawEpoch` on `Manager` are touched from
  `readLoop` (one goroutine) but read cross-goroutine for status — guard with
  the existing `m.mu` or atomics, matching `peerAuthSeen`'s atomic discipline.

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (rolling upgrade / failover) | **MED** | Path A is additive, but the readLoop reorder + Manager-scoped state touch the election-critical path; `make test-failover` (v4+v6) is mandatory. |
| HA availability (self-lock) | **MED→LOW** | F3 residual reduced to state-loss∧backward-clock, operator-recoverable; must be unit-proven + documented. |
| Wire/interop | **LOW** | Unchanged 52-byte `"XPFA"` trailer; old receiver ignores the body field (proven: single `UnmarshalHeartbeat` caller). |
| Security (replay/downgrade) | **LOW** | Epoch-before-ring closes F2; single trailer format closes F5; strict floor + downgrade gate retained. |
| Architectural mismatch | **LOW** | Composes with #4107/#5477/#5639; no version-machinery entanglement. |

## 10. Out of scope (explicitly) / PLAN-KILL consideration

- **Disk-persisting the receiver high-water** (Option 4-ii) — follow-up.
- **Operator re-prime command** (Option 4-iii) — follow-up; the daemon-restart
  boundary is the initial recovery path.
- **Retiring the #5477 ring** in favor of a single `(highEpoch, counter)`
  watermark — tempting (the epoch makes the ring's cross-incarnation role
  redundant) but it **restructures held work**; explicitly deferred.
- **#5078 sync_auth PSK** — separate mechanism, untouched.
- **PLAN-KILL?** Considered and **not** recommended: the residual is a *named*
  #6167 follow-up; the only receiver-only alternative (enlarge the ring) merely
  moves the 65 constant and never closes the class, while the epoch closes it
  with O(1) state. We flag PLAN-KILL as legitimate **only** if reviewers judge
  the on-path-sniffer-across-65-incarnations threat too narrow to justify the
  self-lock surface — in which case the honest move is to keep the ring, keep
  the honest #6167 doc, and close #6169 as won't-fix.

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Path A residual-byte detection.** Is "exactly 8 residual body bytes before
   the fixed 52-byte trailer ⇒ epoch" robust against *every* legal body
   (empty `SoftwareVersion`, truncated monitors, 255-byte version)? Could any
   monitor/version truncation leave a stray 8-byte tail that a receiver
   misreads as an epoch? (If yes, prefer a 1-byte MAC-covered presence marker —
   still no F5 collision because it's inside `bodyEnd`.)
2. **F3 self-lock acceptability.** Is "restart the rejecting peer's daemon" an
   acceptable operator recovery for the state-loss∧backward-clock self-lock, or
   must Option 4-iii's explicit reset command ship in v1?
3. **F4 daemon-restart re-prime vs security.** Does clearing `highEpoch` on
   daemon restart (§5.5/§5.6) open an *unacceptable* post-restart replay window
   for an on-path attacker who can DoS the live peer — i.e. must Option 4-ii
   (disk-persist) be the default rather than a follow-up?
4. **Epoch-before-ring for equal epochs.** With the reorder, is the #5477 ring
   still the *sole* guard for same-epoch (intra-incarnation) replay, and is that
   sufficient, or does equal-epoch need its own `(epoch,counter)` high-water?
5. **Unconditional keyed emit.** Is there *any* keyed-receiver code path on
   `origin/master` (not just `heartbeatAuthDecision`) that inspects body length
   or trailing bytes and could reject a body that grew by 8 signed bytes? (We
   found only `readLoop`→`UnmarshalHeartbeat`; challenge this.)
6. **Wall-clock as a floor.** `uint64(time.Now().UnixNano())` — any real
   deployment where the wall clock is *below* a legitimately-persisted counter
   at first keyed send in a way `persisted+1` doesn't cover?

---

### Appendix — files in blast radius (implementation, for /engineer)

- `pkg/cluster/heartbeat.go` — `HeartbeatPacket.BootEpoch`,
  `marshalHeartbeatBody` (+8 reserve, write field), `UnmarshalHeartbeat` /
  `parseBodyEpoch` (read field bounded by `bodyEnd`), `epochAdmit`,
  `heartbeatEpochDecision`, `readLoop` reorder.
- `pkg/cluster/heartbeat_epoch.go` (new) — `nextBootEpoch`,
  `Manager.heartbeatBootEpoch` (persist-before-send hardening).
- `pkg/cluster/manager.go` — `bootEpoch`/`bootEpochOnce` (exists in PR) +
  `highEpoch`/`sawEpoch` moved here (F4).
- `pkg/cluster/heartbeat_manager.go` — `buildHeartbeat` sets `BootEpoch`.
- `pkg/cluster/README.md` + this doc — operator recovery + honest residuals.
- Tests: `heartbeat_epoch_test.go` — keep PR #6370's fail-on-revert
  (`TestHeartbeatEpochRejectsRetiredIncarnationAfterRingChurn`) + add F1
  (mixed-version dual-accept), F2 (ring-churn-then-equal-epoch replay), F3
  (state-loss∧backward-clock + persist-failure), F4 (heartbeat-restart carry +
  daemon-restart re-prime), F5 (v1 body with `"XPFE"`-like bytes no longer
  mis-parses — trivially true under Path A since there is no v2 magic).
