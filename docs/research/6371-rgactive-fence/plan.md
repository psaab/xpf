# Plan of Action — #6371 rg_active ownership reconciliation

- **Issue:** #6371 (bug, security) — framed as "a failed `SetRGActive(false)`
  still fires `signalFailoverActuated` → dual cluster-active forwarding." Research
  found the real security content is broader: **`rg_active` (the daemon's Active
  authority) can diverge from desired ownership and never be reconciled, giving
  indefinite reactivation** — most clearly on a stale-active restart.
- **Research branch:** `research/6371-rgactive-fence`
- **Base:** origin/master @ `3ecdc80568a3`
- **Prior art:** #5640 (fence barrier), #5079 (owner-side transfer-out
  election-eligibility lease), #485 (activation/demotion ordering), #3917
  (`fenceAllRedundancyGroups`), #1928 (cluster-only HA replay), `fce172532`
  (removed the flow-cache demote preflight).
- **Revision:** r4 — after hostile Codex r1/r2/r3 (each a BLOCKER or ≥4 findings)
  + Claude SMR r1/r2/r3, all firsthand-verified. AGY infra-down (2-of-3).
- **Status:** DRAFT (r4). **Recommendation: PLAN-KILL Option D + Path A′ + the
  decouple (affirm the per-call `UpdateRGActive` ordering is correct); SHIP a
  startup ownership-reconciliation fix that closes the genuinely-unbounded
  stale-active-restart reactivation, plus a shared unresolved-clear-debt
  persistence alarm and doc correction; PLAN-DEFER only the full
  single-Active-authority redesign, with explicit unbounded-mode disclosure +
  a tracked follow-up filed now.**

---

## 1. Problem statement (re-scoped by the research)

The issue's stated mechanism — a failed `SetRGActive(ctx,rgID,false)`
(`daemon_ha.go:367`) still runs the unconditional `signalFailoverActuated`
(`:389`) → the peer promotes off the ack — is **real but not the hazard**: the
ack is not a promotion fence (the peer promotes on heartbeat-observed
`StateSecondaryHold` + priority-0 VRRP regardless, §3.4), and the specific
"persistent control-socket failure" precondition is **bounded ~11 s** by the
helper forwarding lease (§3.2).

Hostile review surfaced the actual security content: the eBPF `rg_active` map is
the daemon's **Active authority** (the status poll re-derives `haGroups.Active`
from it and the watchdog re-publishes it to the helper, §3.1), yet **nothing
reconciles the map against desired ownership when they diverge outside a state
transition.** The concrete, reachable, **unbounded** manifestation is a
**stale-active restart** (§3.5): a former owner reboots with `rg_active=1` pinned,
the fresh state machine starts `applied=false`, the reconcile never issues a
corrective clear, and the poll/watchdog re-arm the helper `active=true`
indefinitely — dual-active with the peer that legitimately took over.

## 2. Blast radius / affected code (read firsthand @ 3ecdc80568a3)

| Path | Role |
|------|------|
| `pkg/daemon/rg_state.go:75` (`newRGStateMachine`) | fresh state machine: `active=false`, `applied=false`, no pending apply |
| `pkg/daemon/daemon_ha.go:604-605` | `reconcileRGStateLoop` "correct stale rg_active from prior run" — **false** for a pinned-map/`applied=false` divergence |
| `pkg/daemon/daemon_ha.go:806-848` | reconcile acts only on `Changed \|\| NeedsApply` — a fresh `applied=false` never detects `map=1` |
| `pkg/dataplane/loader_userspace_shim.go:602` | `rg_active` is a **pinned** shared map (survives restart) |
| `pkg/dataplane/userspace/manager_compile.go:360,372-378` | cluster-node startup: `refreshHAStateFromMapsLocked` (reads pinned map) → `syncHAStateLocked` **re-arms the helper `active=true`** from the stale map |
| `pkg/dataplane/userspace/manager_ha.go:257-360` | `refreshHAStateFromMapsLocked`/`mergeHAStateFromMaps` — `haGroups.Active = rgVal!=0` (map is authority) |
| `pkg/dataplane/userspace/manager_ha.go:631-716,751,781` | `UpdateRGActive` (map-first, return-on-map-error — correct); watchdog re-publish renews the Rust lease per active update |
| `userspace-dp/src/afxdp/ha/state.rs:4`, `types/runtime.rs:343` | lease `active(now)=until!=0 && now<=until` (inclusive), renewed only for `active` groups; `HA_WATCHDOG_STALE_AFTER_SECS=10` |
| clear sites (all five) | cluster-event `daemon_ha.go:367`; VRRP-BACKUP `:583`; reconcile `:846`; peer-fence `fenceAllRedundancyGroups` `daemon_ha_sync.go:1267` (**bypasses `rgStateMachine`, no retry debt**); shutdown `daemon_run_shutdown.go:153` |
| `pkg/cluster/failover.go:127`, `election.go:160` | `ManualFailover`→`SecondaryHold`; peer promotes on observing it (ack-independent) |
| `pkg/daemon/daemon.go:199` | NAT-pool alarm manager — **NAT-specific** (CLI + gRPC callbacks); no generic alarm manager exists |

## 3. Reachability / precondition analysis

### 3.1 `rg_active` is dead to packet programs but is the daemon's Active authority
No forwarding path reads the eBPF `rg_active`/`ha_watchdog` maps (userspace-dp
gates on `rg_runtime`; `check_egress_rg_active` is uncalled retired-eBPF). But the
daemon control plane treats the pinned map as authoritative: the 1 s poll
re-derives `haGroups.Active` from it (`mergeHAStateFromMaps`), startup replays it
(`manager_compile.go:360`), and the watchdog re-publishes `update_ha_state`.

### 3.2 The issue's precondition is bounded ~11 s; other modes are not
The lease is renewed every watchdog IPC **applied** by the helper while the
group is `active`; `haGroups.Active` is map-derived. So:
- **Persistent control-socket failure (the issue's precondition):** no IPC is
  applied → lease expires ≤~11 s → fail closed. **Bounded.** (Phrase the bound on
  IPC *application*, not "error returned": a request may be applied by the helper
  before its response fails, so the daemon seeing an error does not prove
  non-application.) ~11 s bounds **new ordinary admission**, not final egress of
  already-queued packets.
- **Map stays active + socket up:** the watchdog keeps renewing → the helper
  forwards **indefinitely**. This is correct while the node legitimately owns the
  RG, but **unbounded** when the map is stale-active and never reconciled:
  the stale-active restart (§3.5) and a persistent map-write failure with live
  reads (reconcile keeps returning error, map never reaches 0, poll re-arms).

### 3.3 No fabric mitigation
`fce172532` removed the flow-cache demote preflight; userspace mode skips Linux
blackhole routes. Residual dual-forwarded traffic is stale-ARP/ND residue +
pre-latch admission (no wall-clock queue-drain bound is claimed).

### 3.4 The ack is not the fence
`ManualFailover` publishes `SecondaryHold`; the peer promotes on observing it
(`election.go:160`) + priority-0 VRRP, independent of the ack →
`signalFailoverActuated` is a coordination signal, not proof forwarding stopped →
Option D is an invalid fence (§4).

### 3.5 BLOCKER — stale-active restart is never reconciled (firsthand-verified)
1. `rg_active=1` survives (pinned map, `loader_userspace_shim.go:602`).
2. Cluster startup `refreshHAStateFromMapsLocked` reads it → `syncHAStateLocked`
   re-arms the fresh helper `active=true` (`manager_compile.go:372-378`).
3. The fresh `rgStateMachine` is `desired=false, applied=false` (`rg_state.go:75`).
4. Non-preempt boot starts Secondary; initial reconcile is `false→false`.
5. Reconcile acts only on `Changed || NeedsApply` (`daemon_ha.go:806`) — both
   false — so **no corrective clear**; the "startup repair" comment (`:605`) is
   false for this divergence.
6. The watchdog re-publishes map-derived `active=true`; the Rust lease renews on
   every active update → **indefinite reactivation with a live socket**. No clear
   is attempted, so a reconcile-only alarm sees nothing.

This is the reachable, unbounded, security-relevant defect. It is independent of
the failed-clear mechanism the issue names, and disproves any "current behavior is
correct / bounded" conclusion.

## 4. Options — code-fix variants for the *named* defect are rejected
- **Option D (hold the ack):** PLAN-KILL — not a valid fence (§3.4).
- **Path A′ (fast retry in the demotion branch):** REJECT — one attempt allows
  2 s dial + 3 s roundtrip, uncancellable; 3 attempts > the 3 s actuation barrier
  → self-inflicted `failoverAckFailed`.
- **r2 decouple (live update past a failed map write):** REJECT — harmful; the
  poll re-derives Active from the map, so it oscillates/reactivates. The current
  **map-first / return-on-map-error ordering is correct.**
None of these touch §3.5.

## 5. Recommended path — **Path D: reconcile `rg_active` against desired ownership**

1. **Close the stale-active-restart reactivation (the core security fix).** On
   cluster-node startup, the pinned `rg_active` map must not be trusted as
   ownership. Seed the `rgStateMachine`'s `applied` (per RG) from the **actual**
   pinned map value so the reconcile's `NeedsApply` (`applied != desired`) detects
   a stale-active non-owned RG and issues the corrective `SetRGActive(false)` —
   fail-closed until legitimate election, while a genuine still-owner
   (`desired=true`) stays applied (hitless). Equivalent seam to weigh in
   /engineer: have `manager_compile` start **fail-closed** (do not re-arm from the
   pinned map on a cluster node) and let the daemon drive activation on election.
   Either closes the unbounded window; both need explicit restart semantics
   (bounded re-arm-then-clear window ≤ the immediate reconcile pass).
2. **Shared unresolved-clear debt + persistence alarm/metric.** A per-RG
   *unresolved-clear* debt raised whenever any clear site fails or a demotion is
   requested but not confirmed applied — shared across **all five** sites,
   including the ones that bypass `rgStateMachine` (peer-fence
   `fenceAllRedundancyGroups`) and the restart/persistent-map-write cases (a
   reconcile-only signal misses those). Time-based hysteresis (raise after ≥T,
   clear on confirmed applied), explicit supersession/removal on ownership change
   and restart, and requested-value classification (a map-only failure after a
   confirmed live clear is not dual-active-risk). This needs its **own** plumbing
   — there is no generic alarm manager (the NAT-pool one is NAT-specific), so this
   is materially more than the r3 "40-70 LOC" estimate; scope it honestly at
   /engineer.
3. **Doc + stale-comment correction (expanded):**
   - Issue body: the socket-down mechanism is bounded ~11 s; the genuinely
     unbounded content is the stale-active-restart / map-not-reconciled defect.
   - Fix the stale #5640 "ack prevents peer promotion" claims — enumerated:
     `daemon_ha.go:168`, `docs/session-sync-architecture.md:1358`,
     `cluster/sync.go`, `cluster/sync_failover.go`, `daemon.go`,
     `daemon_ha_sync.go`, and the matching sync-test rationale.
   - Fix the false "correct stale rg_active from prior run" comment
     (`daemon_ha.go:605`) and the stale "fabric-mitigated"/#485-preflight comments
     (`fce172532`).
   - Relabel #5079 (demoted **owner's** election-eligibility lease, not a
     forwarding fence) and document the map-as-Active-authority + the five clear
     sites.
4. **PLAN-DEFER only the full single-Active-authority redesign** (retire the map
   as authority / unify daemon-desired vs persisted-manager state). Its deferral
   requires **accurate unbounded-mode disclosure** (persistent map-write failure
   with a live socket, and genuinely-stuck ownership, remain indefinite even after
   Path D — Path D closes only the restart path and adds detection), **accountable
   security/HA-owner signoff**, and a **tracked follow-up issue filed now** — not
   "if later required."

Rationale: the issue's named mechanism is bounded/benign; the real, reachable,
unbounded hazard is stale-active reactivation. Path D fixes the clearly-reachable
restart path, surfaces the residual unbounded modes operationally, and corrects
the record — a genuine, proportionate security fix — while honestly deferring the
larger authority redesign with disclosure + a tracked issue.

## 6. Detailed design (Path D)

- **Startup seed (item 1):** at daemon HA init, read the pinned `rg_active`
  (and `ha_watchdog`) map per RG and seed `rgStateMachine.applied` accordingly
  (a small `SeedApplied(active bool)` on the state machine, or reuse
  `mergeHAStateFromMaps`), BEFORE the first `reconcileRGStatePass`. Guard: cluster
  nodes only (standalone already clears via `clearHelperHAStateWithDebtEnsureRetryLocked`).
  Confirm the immediate reconcile then clears a non-owned stale-active RG.
- **Debt/alarm (item 2):** a per-RG `unresolvedClearSince time.Time` +
  `unresolvedClearCount`, set at every clear request (all five sites) and cleared
  on a confirmed applied-inactive (helper status reports the group inactive, not
  merely a nil error). Raise a `show security alarms` entry + increment
  `ha_rg_active_unresolved_clear{...}` after hysteresis. Requires its own alarm
  registration (no generic manager).
- **No** change to `UpdateRGActive` ordering, `signalFailoverActuated`,
  `waitFailoverActuated`, #5079, or #485.
- Docs/comments per §5.3. Scope: realistically ~120-200 LOC across daemon +
  userspace-manager + a metric + docs. No wire/ABI/Rust behavior change.

## 7. Test plan (parent-RED bindings)

- **Stale-active-restart regression (the core):** construct a daemon/manager with
  a pinned `rg_active=1` for an RG the node does NOT own (Secondary, no VRRP
  master); run startup seed + one reconcile pass; assert `SetRGActive(false)` was
  issued and the helper is not left armed. Parent-RED: revert the seed →
  `applied=false` → no clear → the RG stays armed → assertion fails (behavioral,
  per `feedback_red_on_revert_must_be_assertion_not_build_break`). `TMPDIR=/tmp`.
- **Ordering-correctness regression (guards against the r2 decouple):** failing
  map write → `UpdateRGActive` returns error and does NOT send
  `update_ha_state(false)`; a follow-on poll keeps `Active=true` (no divergence).
- **Debt/alarm:** drive a persistent failed clear (reconcile) AND a bypass
  peer-fence failed clear; assert the shared debt raises the alarm after
  hysteresis and clears on confirmed applied-inactive. Parent-RED: revert →
  no alarm.
- **Rust lease bound:** `is_forwarding_active` false once `now > until`.
- **Smoke:** `make test-failover` (loss userspace cluster, v4+v6) + a
  restart-connectivity check that a restarted former-owner does NOT resume
  forwarding an RG the peer owns.

## 8. Risk analysis / rollback

- **Risk:** the startup seed must not cause a forwarding blip for a legitimate
  still-owner — seed `applied` (not force-clear); the reconcile keeps a
  `desired=true` RG active. Verify the boot re-arm-then-clear window is bounded by
  the immediate reconcile pass.
- **Risk:** the alarm/debt must clear on a CONFIRMED applied-inactive (helper
  status), not a nil error, to avoid false clears; and must not fire on a
  legitimate demoted RG at steady state.
- **Rollback:** `git revert`; no schema/wire/ABI/Rust change.

## 9. Documentation updates
Per §5.3 — the enumerated stale #5640 comments (incl.
`docs/session-sync-architecture.md:1358`, `daemon_ha.go:168` "peer never
promotes", sync-test rationale), the false `daemon_ha.go:605` startup-repair
comment, the fabric/#485 stale comments, #5079 relabel, the map-as-authority +
five clear sites, and the ~11 s IPC-application bound. HA design notes /
`docs/fabric-cross-chassis-fwd.md` gain the lease bound + fabric-ingress exception.

## 10. Open questions (for reviewers)
1. Startup seam: seed `applied`-from-map (minimal, self-corrects via reconcile) vs
   `manager_compile` boot-fail-closed (no re-arm from the pinned map). Which is
   the cleaner, more hitless-restart-honest fix?
2. Is Path D's scope (restart fix + detection + doc) the right #6371 boundary, or
   should the persistent-map-write-failure + stuck-ownership unbounded modes be
   their own tracked issue rather than "accepted + alarmed" here?
3. Alarm surface: `show security alarms` + counter (own plumbing) vs metric-only.

## 11. Convergence / verdict ledger

| Round | Codex | Claude SMR | AGY | Plan rev |
|-------|-------|------------|-----|----------|
| r1 | PLAN-NEEDS-REVISION (6) | PLAN-NEEDS-REVISION (5) | infra-down | r1 |
| r2 | PLAN-NEEDS-REVISION (BLOCKER+4) | PLAN-NEEDS-REVISION (5) | infra-down | r2 |
| r3 | PLAN-NEEDS-REVISION (BLOCKER stale-restart+4) | PLAN-READY | infra-down | r3 |
| r4 | pending | pending | infra-down | r4 |

Convergence target (2-of-3, AGY infra-blocked): Codex + Claude SMR agree on
PLAN-READY for Path D (startup ownership reconciliation closing the stale-active
restart + shared-debt alarm + doc; PLAN-KILL Option D/A′/decouple; deferral of the
full authority redesign with disclosure + tracked follow-up).
