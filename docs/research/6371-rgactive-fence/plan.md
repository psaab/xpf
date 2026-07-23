# Plan of Action — #6371 rg_active ownership reconciliation

- **Issue:** #6371 (bug, security). Named mechanism: a failed `SetRGActive(false)`
  still fires `signalFailoverActuated`. Real content (research): the pinned
  `rg_active` eBPF map is the daemon's Active authority, and stale-active values
  are re-armed to the helper without being reconciled against desired ownership →
  **indefinite reactivation** (restart; failed peer-fence; persistent map-write).
- **Research branch:** `research/6371-rgactive-fence`
- **Base:** origin/master @ `3ecdc80568a3`
- **Prior art:** #5640, #5079, #485, #3917 (`fenceAllRedundancyGroups`), #1928
  (cluster-only HA replay), `fce172532` (removed the demote preflight).
- **Revision:** r6 — after Codex r1-r5 (each BLOCKER/≥4 findings) + Claude
  SMR r1-r5, all firsthand-verified. Codex r5 confirmed r4-B1/B2/B3/B4/H7 CLOSED;
  r6 adds the remaining concurrency-linearization invariant + residual-honesty
  fixes. AGY infra-down (2-of-3).
- **Status:** DRAFT (r6). **Recommendation: PLAN-KILL Option D + Path A′ + the
  decouple. SHIP Path D = (1) boot pin-quarantine (fail-closed) + (2) a
  generation-linearized, convergent, retryable clear with a shared per-RG
  unresolved-clear debt across all clear sites + (3) doc correction. Path D closes
  the reachable restart + peer-fence reactivation modes and detects-and-alarms
  (does not auto-fix) the extremely-rare persistent-map-write residual; PLAN-DEFER
  the map-as-authority architectural cleanup as an accepted, detected-but-unfixed
  residual, with a follow-up issue filed now + a named security/HA signer.**

---

## 1. Problem statement

The named mechanism is real but not the hazard: the transfer-out ack is not a
promotion fence (the peer promotes on heartbeat-observed `SecondaryHold` +
priority-0 VRRP, §3.4), and the "persistent control-socket failure" precondition
is bounded ~11 s by the helper forwarding lease measured from the last **applied**
active IPC, for new ordinary admission (§3.2). The real, reachable, **unbounded**
security content: `rg_active` is the daemon's Active authority (poll re-derives
`haGroups.Active` from it, watchdog re-publishes it), and stale-active values are
never reconciled against desired ownership. Reachable unbounded modes:
- **Stale-active restart (§3.5):** a former owner reboots with `rg_active=1`
  pinned; cluster startup re-arms the helper `active=true`; the fresh state
  machine never issues a corrective clear; the watchdog renews the lease
  indefinitely.
- **Failed peer-fence (§3.6):** `fenceAllRedundancyGroups` logs a failed clear
  and returns without touching `rgStateMachine` or scheduling a retry → one
  **transient** map error leaves the RG active indefinitely.
- **Persistent map-write failure** (extremely rare): the pin never reaches 0.

## 2. Blast radius / affected code (read firsthand @ 3ecdc80568a3)

| Path | Role |
|------|------|
| `pkg/dataplane/loader_userspace_shim.go:602` | `rg_active`/`ha_watchdog` are **pinned** shared maps (survive restart) |
| `pkg/dataplane/userspace/manager_compile.go:360,372-378` | cluster startup: `refreshHAStateFromMapsLocked` → `syncHAStateLocked` **re-arms the helper from the pinned map** (runs EARLY, at config apply) |
| `pkg/dataplane/userspace/process_status.go:208` | 1 s poll re-derives `haGroups` from the pin |
| `pkg/dataplane/userspace/manager_ha.go:257-360` | `refreshHAStateFromMapsLocked`/`mergeHAStateFromMaps` (`Active=rgVal!=0`, republishes all 16 array keys) — **private**; `HAController` is write-only |
| `pkg/dataplane/userspace/manager_ha.go:751,781` | watchdog re-publishes the full group set; Rust lease renews per active update |
| `pkg/daemon/rg_state.go:75,204,250-261` | fresh state machine `applied=false`; `NeedsApply` returns **sticky** `applyPending` (set only inside `reconcileLocked` when `active!=applied`) |
| `pkg/daemon/daemon_ha.go:604-605,806-848` | reconcile loop (starts LATE, `daemon_run.go:380/561`); acts on `Changed\|\|NeedsApply`; "correct stale rg_active" comment is false |
| `pkg/daemon/daemon_ha_sync.go:1267` | peer-fence `fenceAllRedundancyGroups`: failed clear logs + returns, **no rgStateMachine change, no retry** |
| `pkg/daemon/daemon_run_shutdown.go:153` | shutdown clear (5th site) — best-effort teardown |
| `pkg/cluster/election.go:113-120,419`, `group_state.go:23`, `heartbeat.go:58` | non-preempt boot stays Secondary; never-seen-peer 30 s startup floor |
| `pkg/daemon/daemon.go:199` | NAT-pool alarm manager — **NAT-specific**; no generic alarm manager |

## 3. Reachability / precondition analysis

### 3.1 `rg_active` is dead to packet programs but is the daemon's Active authority
No forwarding path reads the eBPF maps (userspace-dp gates on `rg_runtime`;
`check_egress_rg_active` is uncalled retired-eBPF). The daemon control plane
treats the pinned map as authoritative (poll re-derivation + startup replay +
watchdog re-publish).

### 3.2 The named precondition is bounded ~11 s; other modes are not
The lease renews per watchdog IPC **applied by the helper** while a group is
`active`; `haGroups.Active` is map-derived. Persistent control-socket failure →
no IPC applied → lease expires ≤~11 s (measured from the last applied active IPC;
bounds new ordinary admission, not queued-packet egress) → fail closed. A
stale-active map with a live socket keeps renewing → unbounded (§3.5/3.6).

### 3.3 No fabric mitigation (`fce172532`); residual = stale-ARP/ND residue + pre-latch admission (no wall-clock queue-drain bound claimed).

### 3.4 The ack is not the fence (`election.go:160`, `failover.go:127`) → Option D invalid.

### 3.5 BLOCKER — stale-active restart (firsthand): pinned `rg_active=1` →
startup re-arm (`manager_compile.go:372-378`) → fresh `applied=false` → no
corrective clear (`daemon_ha.go:806`) → watchdog renews → indefinite.

### 3.6 BLOCKER — failed peer-fence one-shot (firsthand): `fenceAllRedundancyGroups`
(`daemon_ha_sync.go:1267`) does not update `rgStateMachine` or retry, so a single
transient map error is never reconciled away.

## 4. Options — code-fix variants for the *named* defect rejected
- **Option D (hold ack):** PLAN-KILL (not a fence, §3.4).
- **Path A′ (retry in demotion branch):** REJECT (2 s dial + 3 s roundtrip,
  uncancellable → self-trips the 3 s barrier).
- **r2 decouple:** REJECT (poll re-derives from the map → oscillation). The
  per-call `UpdateRGActive` map-first/return-on-map-error ordering is **correct**.

## 5. Recommended path — **Path D**

### 5.1 Boot pin-quarantine (fail-closed) — closes stale-active restart
Zero **all 16** `rg_active` (and `ha_watchdog`) pin entries at the **earliest**
boot point — immediately after `loadUserspaceShimSharedMaps`, **before**
`manager_compile` HA replay and before the status/watchdog loops start — so every
map-derived consumer (replay, poll, watchdog) reads 0 and the helper starts
fail-closed. The daemon re-activates legitimately-owned RGs via the normal
election → `SetRGActive(true)` path. This supersedes the r4 seed-`applied`
approach: there is **no re-arm-to-clear window** (the pin is zeroed before any
consumer reads it, addressing the ordering BLOCKER) and it needs **no** sticky-
`applyPending` recompute. Zeroing all 16 array keys also tombstones a stale-active
**removed/unconfigured** RG. Cluster nodes only (standalone already clears via
`clearHelperHAStateWithDebtEnsureRetryLocked`).

**Invariant choice (explicit):** this is **fail-closed on boot** — a restarted
node does NOT resume forwarding from the stale pin; it re-earns ownership by
election. **The availability cost is small in the common case:** VRRP is
daemon-managed, so a daemon restart already drops adverts and the peer takes over
within masterDownInterval (~97 ms) — the returning node is legitimately Secondary,
so quarantining its stale pin **prevents dual-active rather than adding an
outage**. It re-owns only by normal failback/election (~election-time, ~1 s with a
live already-known peer). The worst case is a **cold cluster boot** (both nodes
down), where the never-seen-peer election floor applies (**at least 30 s**, plus
scheduling/election work — not a strict upper bound) and fail-closed is
unambiguously correct anyway. This intentionally trades the current
hitless-daemon-restart behavior for safety (a node cannot prove it retained
ownership across a restart while its peer may have taken over). Optional
refinement to shrink even the cold-boot gap (follow-up, not required):
**peer-authoritative boot** — keep the pin quarantined, learn authoritative
ownership from the peer on reconnect, then re-activate if still owner.

**Quarantine failure is fail-closed (not "log + proceed"):** if any of the 16
pin-key writes (or the `ha_watchdog` zeroing) fails, a surviving nonzero key would
re-arm on replay/poll/watchdog — so a partial quarantine-write failure MUST abort
dataplane arming (or retain a gate that suppresses replay, poll, AND watchdog
publication) until the quarantine is confirmed complete. A failure-injection test
covers this.

### 5.2 Convergent, retryable clear + shared unresolved-clear debt — closes peer-fence + persistent modes
Make every clear site record a **daemon-level** per-RG *desired-inactive intent
with a clear generation* (NOT on `rgStateMachine`, since the peer-fence bypasses
it). The reconcile loop is the single **retry consumer**: it drives
`SetRGActive(false)` until **convergence**, defined as **pinned `rg_active`==0
AND the helper reports `Active=false`** for that generation (a nil error or lease
expiry alone is insufficient — the poll can reload a non-zero pin). This:
- fixes the failed **peer-fence one-shot** (§3.6): the fence records intent; the
  reconcile retries to convergence even though the fence bypasses `rgStateMachine`;
- makes a **persistent map-write failure** retry-and-detected (the intent never
  converges → debt → alarm), rather than silently active;
- supersedes/clears the intent on a legitimate ownership change (new generation).

**Linearization invariant (Codex r5 BLOCKER — the load-bearing contract).**
`UpdateRGActive` serializes on the manager mutex, but that orders *lock
acquisition*, not *ownership causality*: with three activation-capable paths and
five clear categories running from different goroutines, a stale clear-retry can
land after a newer legitimate activation (stranding the owner inactive), or an old
activation can land after a newer peer-fence (resurrecting the peer-fence
one-shot). `ApplyIfCurrent`/`rgStateMachine.epoch` do not fix this — the former
validates bookkeeping only *after* the physical write, and the epoch increments on
every unchanged periodic reconcile. The plan therefore requires **one
daemon-owned per-RG monotonic ownership generation** that gates **every** writer
(activate AND clear, all paths incl. quarantine=gen0):
- every intended write captures the generation it was issued for;
- a write (true or false) is applied to the map/helper only if its generation is
  still the current one — a **stale write is dropped** (and re-drives the current
  desired), enforced **before** the physical write, not after;
- a clear dominates until a **strictly newer, still-current** ownership transition
  supersedes it;
- convergence may clear debt only if the generation is **still current across a
  fresh pin + helper readback**;
- a resolved inactive intent / tombstone survives until ownership supersession.
The daemon-level intent + reconcile retry-consumer is the right structure; this
invariant is what linearizes it. (Stated as an invariant; the implementation is
/engineer's.)

**Debt/alarm:** raise a `show security alarms` entry + increment
`ha_rg_active_unresolved_clear{...}` when an intent is unconverged for ≥ T
(hysteresis; T defined, e.g. ~5 s ≈ min lease margin); clear only on confirmed
convergence for the SAME generation; preserve the first-failure timestamp across
retries; **the shutdown site is out of the runtime alarm** — the reconcile loop is
canceled/joined before shutdown clearing, so a failed shutdown clear is not
runtime-convergent; it is instead **recovered by the next boot's §5.1 quarantine**
(state it that way, not "runtime-convergent"). This needs a new `HAController`
**read/snapshot** API (currently write-only) exposing the pinned `rg_active` +
helper `Active` per RG, with defined locking/order and **fail-closed on a map-read
error**.

### 5.3 Doc + stale-comment correction
Issue body (unbounded → the reactivation modes + the bounded ~11 s named case);
the false `daemon_ha.go:605` "correct stale rg_active" comment; the stale #5640
"ack prevents peer promotion" claims — enumerated: `daemon_ha.go:168`,
`docs/session-sync-architecture.md:1358`, `cluster/sync.go`,
`cluster/sync_failover.go`, `daemon.go`, `daemon_ha_sync.go`, and the sync-test
rationale; the stale fabric/#485-preflight comments (`fce172532`); #5079 relabel
(demoted **owner's** election-eligibility lease); document the map-as-Active-
authority + the five clear sites + the boot-quarantine invariant.

### 5.4 Residual + deferral
Path D **closes the two reachable unbounded reactivation modes** (stale-active
restart → §5.1; failed peer-fence one-shot → §5.2, linearized). It **does NOT
close** the **extremely-rare persistent map-write failure**: `UpdateRGActive`
returns before mutating manager/helper state when the eBPF map write itself fails
(`manager_ha.go:635`), so an indefinitely-failing pin write stays indefinitely
active — Path D's retry + alarm make it **detected-and-alarmed, but not
terminated**. This is an **accepted, detected-but-unfixed residual**, disclosed
here. "Stuck VRRP ownership" is a separate election/VRRP domain (not dual-active
unless split-brain; produces no clear debt).

**PLAN-DEFER** the map-as-authority architectural cleanup (retire the eBPF map as
the daemon's Active store; unify daemon-desired vs persisted-manager state) —
which is what would actually *terminate* the persistent-map-write residual, not
merely a cosmetic simplification. Its deferral therefore **requires**: (a) this
explicit detected-but-unfixed disclosure, (b) a **concrete follow-up issue filed
now** (title: "retire rg_active eBPF map as the daemon HA Active authority"),
linked from #6371, and (c) a **named security/HA owner** recorded as the accepting
signer at /engineer time. It cannot be presented as a non-hazard cleanup.

**PLAN-KILL** Option D + Path A′ + the decouple; the per-call `UpdateRGActive`
ordering is affirmed correct.

## 6. Detailed design (Path D)
- **§5.1:** add a `QuarantineHAState()` on the userspace manager (zero all
  `rg_active`+`ha_watchdog` keys + empty `haGroups`) called from HA init before
  replay; guard cluster-only; fail-closed if the map write errors (log + proceed
  helper-unarmed).
- **§5.2:** a daemon-level per-RG `ownershipGen uint64` (monotonic, bumped on
  every ownership transition) + `clearIntent{gen; since}`; a single apply gate
  covers **every** true/false writer and drops a stale-generation write before the
  physical map/helper mutation (the linearization invariant); the reconcile drives
  `SetRGActive(false)` for the current-gen intent and reads back convergence
  (pin==0 AND helper `Active=false`, gen still current) via the new
  `HAController.HASnapshot()`; debt→alarm on non-convergence ≥ T.
- No change to the per-call `UpdateRGActive` map-first ordering,
  `signalFailoverActuated`, `waitFailoverActuated`, #5079, #485, or the #1928
  cluster-only guard. (The generation gate wraps the writers; it does not reorder
  the map-vs-helper writes inside `UpdateRGActive`.)
- Realistic scope: ~250-350 LOC (quarantine + generation gate + intent/convergence
  + snapshot API + alarm + metric) + docs + tests. No wire/ABI/Rust behavior
  change.

## 7. Test plan (parent-RED bindings)
- **Restart quarantine (core):** pinned `rg_active=1` for a not-owned RG →
  boot → assert the helper is NOT armed active (pin zeroed before replay) and the
  node re-activates only after election. Parent-RED: revert §5.1 → helper re-armed
  from the pin → assertion fails.
- **Legitimate-owner re-activation:** peer down → node re-elects primary → assert
  `active` after election (fail-closed gap bounded, no permanent fail-close).
- **Peer-fence convergence:** inject a transient failed peer-fence clear → assert
  the reconcile retries to convergence (pin=0 AND helper inactive) and the debt
  raises then clears. Parent-RED: revert §5.2 → RG stays active, no retry.
- **Generation linearization (Codex r5 BLOCKER):** interleave a stale clear-retry
  (gen G) with a newer legitimate activation (gen G+1) → assert the stale clear is
  dropped and the owner stays active; and the inverse (old activation vs newer
  peer-fence) → assert the fence wins and its debt is not retired. Parent-RED:
  remove the generation gate → the stale write lands → owner stranded inactive (or
  peer-fence resurrected).
- **Quarantine partial-write failure:** inject a failing pin-key write during
  §5.1 → assert the dataplane is NOT armed / replay+poll+watchdog are suppressed
  (no surviving nonzero key re-arms). Parent-RED: revert the fail-closed guard →
  the surviving key re-arms.
- **Ordering-correctness (guards the r2 decouple):** failed map write →
  `UpdateRGActive` returns error, does NOT send `update_ha_state(false)`; poll
  keeps `Active=true`.
- **Rust lease bound:** `is_forwarding_active` false once `now > until`.
- **Smoke:** `make test-failover` (loss userspace cluster, v4+v6) +
  `test-restart-connectivity`: a restarted former-owner does NOT resume forwarding
  an RG the peer owns.

## 8. Risk analysis / rollback
- **Availability:** §5.1 fail-closed-on-boot costs a legitimate owner up to the
  election window — the disclosed, accepted safety trade (§5.1). The
  peer-authoritative refinement (follow-up) shrinks it.
- **Convergence correctness:** debt clears only on confirmed (pin=0 AND helper
  inactive) for the generation — no false clear on a nil error.
- **Map-read errors:** the snapshot API fails closed (treat as still-active →
  keep the intent) so a read error cannot mask a stale-active RG.
- **Rollback:** `git revert`; no schema/wire/ABI/Rust change.

## 9. Documentation updates
Per §5.3.

## 10. Open questions (for reviewers)
1. Ship plain fail-closed-on-boot (§5.1) now with peer-authoritative boot as a
   tracked enhancement, or design peer-authoritative boot into #6371 directly (to
   avoid the up-to-30 s legitimate-owner gap)?
2. Convergence read-back: extend `HAController` with a snapshot API (chosen), or
   have the daemon read the pinned map directly (it already holds a shim handle)?
3. Alarm `T` value + surface (`show security alarms` + counter vs metric-only).

## 11. Convergence / verdict ledger

| Round | Codex | Claude SMR | AGY | Plan rev |
|-------|-------|------------|-----|----------|
| r1 | PLAN-NEEDS-REVISION (6) | PLAN-NEEDS-REVISION (5) | infra-down | r1 |
| r2 | PLAN-NEEDS-REVISION (BLOCKER decouple) | PLAN-NEEDS-REVISION (5) | infra-down | r2 |
| r3 | PLAN-NEEDS-REVISION (BLOCKER stale-restart) | PLAN-READY | infra-down | r3 |
| r4 | PLAN-NEEDS-REVISION (5 BLOCKER+2 HIGH, impl-completeness) | PLAN-NEEDS-REVISION (2) | infra-down | r4 |
| r5 | PLAN-NEEDS-REVISION (linearization BLOCKER + residual-honesty) | PLAN-READY | infra-down | r5 |
| r6 | pending | pending | infra-down | r6 |

Convergence target (2-of-3, AGY infra-blocked): Codex + Claude SMR agree on
PLAN-READY for Path D (boot pin-quarantine + generation-linearized convergent-retry
clear/debt + doc; PLAN-KILL Option D/A′/decouple; the persistent-map-write residual
is a disclosed detected-but-unfixed accepted risk; deferral of the map-as-authority
cleanup with a filed follow-up + named signer).
