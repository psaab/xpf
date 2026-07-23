# Claude SMR — hostile plan review, #6169 boot-epoch, round 2 (plan v2)

Stance: HOSTILE re-attack of v2. Verified against `origin/master` @ `11e23b49a`.

## Round-1 findings — resolution check

- **F2 (session/counter lifetime).** §5.2 moves `session`/`counter` to Manager
  scope + a `(epoch,counter)` lexicographic high-water, ring→v1-only. Traced:
  `counter` as a Manager `atomic.Uint64` is monotonic across a heartbeat restart
  (the Manager persists; only a new Manager/daemon resets it), and on a daemon
  reset the epoch strictly increases so `(E',0) > (E,·)`. Same-epoch churn is
  dead because no second session ever reaches the ring at the live epoch.
  **Resolved — with one coupling caveat, R1 below.**
- **F5 (detection).** §5.1 typed length-delimited MAC-covered TLV + capped
  marshaler fields removes the residual-byte ambiguity. **Resolved — tighten R2.**
- **F3.** §5.4 retryable-init (value fixed once, persist retried), checked
  arithmetic, DEGRADED signal, corrected SNMP analogy. **Resolved — R3, R4.**
- **F4.** §5.5 Manager-scoped `peerAdmission` (full state), race-free
  key-rotation re-prime on the rejecting node, composes with #5639. **Resolved —
  R5, R6.**
- **F1 (Path A).** Unchanged; correct. Resolved.

The architecture now hangs together. Remaining items are **spec tightenings**,
not redesign — but several are load-bearing for correctness.

## Required revisions

**R1 — Make explicit that `(epoch,counter)` correctness *reduces to* epoch strict
monotonicity, and fold the failure into F3.** The old ring tolerated a counter
reset because a genuine reboot drew a *new session* (never-seen). The new guard
resets `counter` per incarnation and relies on the epoch strictly increasing to
keep `(E',0) > (E,highCounter)`. If the epoch ever **repeats** (persist-fail +
non-advancing clock), the counter reset is a **regression → self-lock**. This is
not a new class (it is the F3 self-lock), but §5.2 must state the dependency
outright: the guard is only as strong as the epoch's strict monotonicity, which
makes the F3 init state machine load-bearing, and the failure mode is the same
operator-recoverable self-lock (never a replay admit).

**R2 — The TLV must *exactly consume* `bodyEnd-off`, else no-epoch.** Capping
monitor count/name length makes the *new* sender canonical, but an *old*
(uncapped) keyed peer could in principle emit a body the new receiver's forward
parse desyncs on. Defuse it structurally: after the version section, accept an
epoch only if the leftover `bodyEnd-off` is **exactly** a well-formed
`[ExtType=1][ExtLen=8][8]` (i.e. `bodyEnd-off == 10` and the type/len match) —
any other leftover size, unknown type, or partial TLV ⇒ **no epoch, logged**.
That makes even a desync-y or crafted body fail *closed to no-epoch* (safe:
worst case a genuine epoch is missed for one frame, never a spurious latch of
`sawEpoch`). Also confirm the caps never bite real configs (IFNAMSIZ ≤ 15;
monitors ≪ 255 — the cap mirrors the existing `maxHeartbeatGroups=255` and is
pure defense).

**R3 — Sanity-cap the persisted epoch on load (the far-future-corrupt case).** A
parseable but corrupt **far-future** persisted value would become an unreachable
floor and self-lock the node's own future reboots. `loadPersisted` must reject
`prev > now + margin` (e.g. a few years of ns) as corrupt → treat as state-loss
(seed from wall clock). This mirrors SNMP's out-of-range boots rejection and
completes the checked-arithmetic set alongside `MaxUint64` wrap and negative
`UnixNano`.

**R4 — Do NOT fence a persist-failed node; justify it.** §5.4 raises a DEGRADED
readiness reason. Round-2 must state why that is the *ceiling* of the response:
persist failure degrades toward a rare **self-lock** (a REJECT), i.e. an
availability risk, **not** a replay admit — so fencing a persist-failed node from
election would trade a rare self-lock for a *guaranteed* availability loss (and,
if it is the sole live node, an outage). Keep it in election + DEGRADED signal +
operator re-prime. Say this explicitly so a reviewer does not read "just log it"
as hand-waving.

**R5 — Use a dedicated `admissionMu`, not `m.mu`, and spell out no lock nesting.**
§5.3 puts admission "in one `m.mu` critical section," but `readLoop` then calls
`handlePeerHeartbeat`, which itself takes `m.mu.Lock` — reusing `m.mu` for
admission risks a **re-entrant deadlock** (Go mutexes are not reentrant). Give
`peerAdmission` its own `sync.Mutex`/`RWMutex`; hold it only for the admission
transaction, release it, *then* call `handlePeerHeartbeat`. This also keeps
admission off the `m.mu`/`buildHeartbeat` path entirely. Reconfirm the durable
epoch I/O stays out of every lock (lazy first-keyed-send, separate init mutex).

**R6 — Nail the one-sided-rollback recovery: key rotation is CLUSTER-WIDE.** §5.5
says key rotation is the "natural operator action" for a rollback, but a software
rollback does not inherently change the key. Make the runbook explicit: to
recover a one-sided v2→v1 rollback the operator **rotates the cluster
`authentication-key`** (a shared, config-synced PSK), which resets *both* nodes'
`peerAdmission` (fingerprint change) and invalidates every archived capture
(race-free) so the upgraded peer re-anchors from the rolled-back node's v1
frames. Note the failure mode of a *one-sided* key change (MAC mismatch → split)
so the doc does not imply per-node rotation is safe. Confirm folding #5639's
heartbeat lifecycle does not regress its **sync-auth-owner** (non-heartbeat)
portion — that likely stays #5639's scope (§11 Q1).

## Non-blocking

- Stage-0/Stage-1 split is right; Stage 0 (Manager-scope + caps) is independently
  correct and closes the *restart* churn without a wire change — worth shipping
  first and likely == #5639's heartbeat fix.
- Retiring the ring even for v1 is tempting but correctly deferred.

## Verdict

v2's architecture resolves every round-1 finding; the remaining items are
specification tightenings (R1 coupling statement, R2 exact-TLV-consume, R3 load
sanity-cap, R4 no-fence justification, R5 dedicated lock, R6 cluster-wide
rotation). None require a redesign, but R2/R3/R5 are correctness-affecting and
must be in the plan before it is implementable, so this is not yet READY.

VERDICT: PLAN-NEEDS-MINOR

---

## Self-correction (post-Codex-r2, same round)

My NEEDS-MINOR under-weighted four items Codex r2 proved are architecture-level,
not spec-tightening. Verified firsthand; I agree and converge to NEEDS-MAJOR:

1. **DEGRADED is not an election fence.** A status reason does not gate election:
   ordinary RG readiness does not demote an existing primary
   (`election.go:322`) and is bypassed on the peer-dead single-node path
   (`election.go:427`); the `HAProtocolVersionMismatch` precedent is consulted
   only by userspace/manual-transfer readiness, not an unconditional fence. A
   node that may emit an unpersisted epoch must be **held secondary before the
   first election** (which runs at bring-up, before heartbeat starts —
   `daemon_run_bringup.go:161`), promoting only on confirmed-peer-absent. Lazy
   first-send init is too late.
2. **The TLV wire discriminator is not robust for archived/mixed v1 frames.**
   The MAC covers the whole (uncapped) legacy body, so detection that depends on
   forward-parsing it can be desynced. Capping the *new* sender cannot expire
   archived captures under the unchanged PSK. The fix is a **key-derived,
   tail-anchored marker** (read backward from `bodyEnd` *after* MAC verify) that
   an old sender cannot produce and an attacker cannot forge — and `bodyEnd`
   itself must never be trusted from an unverified `XPFA` (keyless path parses
   the full frame).
3. **The re-prime/key-rotation has a key-generation TOCTOU** (verify under K1 →
   reset under K2 → commit stale `macOK`), clearing `peerAuthSeen` reopens
   cleartext (the rolled-back v1 node still signs XPFA, so it is unnecessary),
   and recovery is a coordinated cluster-wide never-used-key sequence, not a
   one-liner. Admission needs a key-generation stamp checked at commit.
4. **#5639 is not subsumed** — the sync-auth owner (`syncAuthedEver`,
   `sync_auth.go:415`) is a separate transient bit ORed into `syncPeerAuthSeen`
   and replaced on comms recreation. #6169 must **sequence behind** a #5639
   cross-channel auth owner, not leave it as an open question.

Plus: separate sender send-nonce from receiver `peerAdmission` (never reset the
counter on key change — it breaks the `(epoch,counter)` total order); async
bounded persist retry (never per-send fsync); full arithmetic/state
classification; and soften "can never be replayed" to "closes *sustained*
replay" (a bounded post-restart window admits one retired frame).

**Corrected verdict: PLAN-NEEDS-MAJOR** — the `(epoch,counter)` guard is the
correct center; the persistence/election posture, wire discriminator, cross-
channel auth owner, and key-generation protocol need a v3.

VERDICT: PLAN-NEEDS-MAJOR
