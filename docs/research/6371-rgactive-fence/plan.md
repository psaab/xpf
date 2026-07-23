# Plan of Action — #6371 rg_active forwarding fence on a failed clear

- **Issue:** #6371 (bug, security) — "a failed `SetRGActive(false)` still fires
  `signalFailoverActuated` → dual cluster-active forwarding under control-socket
  failure." Surfaced during #6177 /research.
- **Research branch:** `research/6371-rgactive-fence`
- **Base:** origin/master @ `3ecdc80568a3`
- **Prior art:** #5640 (fence-completion barrier), #5079 (owner-side transfer-out
  election-eligibility lease), #485 (activation/demotion ordering), #3917
  (`fenceAllRedundancyGroups` peer-fence), `fce172532` (collapsed userspace
  demotion prep to a barrier — removed the flow-cache demote preflight).
- **Revision:** r3 — rewritten after hostile Codex r2 (BLOCKER + 4 findings) +
  Claude SMR r2, all firsthand-verified below. AGY infra-down (2-of-3).
- **Status:** DRAFT (r3). **Recommendation: PLAN-KILL the issue's Option D AND
  every code-fix variant (r1 Path A′, r2 decouple) — the current
  `UpdateRGActive` ordering is CORRECT. Ship a minimal Option-(c): doc/comment
  correction + a persistence/hysteresis observability alarm. Accept the bounded
  residual risk explicitly and PLAN-DEFER the deep transfer-phase redesign.**

---

## 1. Problem statement

On a coordinated transfer-out the peer sends `SendFailover(rgID)` and waits up to
`failoverAckTimeout` (20 s) for an ack; this node handles it in
`handleRemoteFailover` → `OnRemoteFailover` arms the #5640 barrier +
`ManualFailover` + the #5079 lease; `WaitFailoverApplied = waitFailoverActuated`
(barrier 3 s) gates the ack. The demotion event runs
`ResignRG`→(if `tr.Changed`)`SetRGActive(false)`→ **unconditional**
`signalFailoverActuated`. The issue claims a failed clear + released ack →
**UNBOUNDED** dual-active under persistent control-socket failure, and proposes
**Option D** (hold the ack until the clear is confirmed).

**Research outcome:** the "unbounded" premise is refuted **for the issue's
stated precondition** (persistent control-socket failure → the helper's
forwarding lease self-expires at ~11 s because the socket-down watchdog cannot
renew it). Option D is an **invalid fence** (the peer promotes independently of
the ack). Both code-fix variants explored (Path A′ retry, r2 map/live-update
decouple) are **unsafe or harmful**; the current ordering is correct. Only a
minimal observability + documentation change is warranted.

## 2. Blast radius / affected code (read firsthand @ 3ecdc80568a3)

| Path | Role |
|------|------|
| `pkg/daemon/daemon_ha.go:353-389` | cluster-event demotion: `SetCluster(false)`→`ResignRG`→(if `tr.Changed`)`SetRGActive(false)` at 367→ unconditional `signalFailoverActuated` at 389 |
| `pkg/daemon/rg_state.go:250-265` | `reconcileLocked`: default `desired = clusterPri \|\| allVRRPMaster` |
| `pkg/daemon/daemon_ha.go:567-590` | VRRP-BACKUP handler: RETH-mode clear (`SetRGActive(false)` ~583) |
| `pkg/daemon/daemon_ha.go:820-848` | `reconcileRGState`: 2 s desired-vs-applied retry clear (`SetRGActive(false)` ~846) |
| `pkg/daemon/daemon_ha_sync.go:1268` | `fenceAllRedundancyGroups` (#3917) peer-fence: clears **all** RGs on a fence msg |
| `pkg/dataplane/userspace/manager_ha.go:631-716` | `Manager.UpdateRGActive`: BPF `rg_active` map write (638, returns on err) **then** live `update_ha_state` (699) |
| `pkg/dataplane/userspace/manager_ha.go:257-360` | `refreshHAStateFromMapsLocked`/`mergeHAStateFromMaps`: **re-derives `haGroups.Active` FROM the rg_active map** (`group.Active = rgVal != 0`) |
| `pkg/dataplane/userspace/process_status.go:150-258` | 1 s status poll: `refreshHAStateFromMapsLocked` + watchdog re-publish (`update_ha_state` when `Active` delta) |
| `pkg/dataplane/userspace/manager_compile.go:360` | startup: replays `Active` from the map (`refreshHAStateFromMapsLocked`) |
| `pkg/dataplane/maps_fabric.go:36-47` | writes the `rg_active` eBPF map |
| `pkg/cluster/failover.go:120-128` | `ManualFailover` → `StateSecondaryHold` (heartbeat-published) |
| `pkg/cluster/election.go:160-167` | peer promotes on observing `StateSecondaryHold` — independent of the ack |
| `pkg/daemon/daemon_ha_sync.go:1067` | owner-side transfer-out lease = `2·localFailoverCommitTimeout + 20 s` = 26 s (election-eligibility, not a forwarding fence) |
| `userspace-dp/src/afxdp/types/runtime.rs:335-370` | `HAForwardingLease` / `active(now)=until!=0 && now<=until` (inclusive) / `HA_WATCHDOG_STALE_AFTER_SECS=10` |
| `userspace-dp/src/afxdp/forwarding/ha.rs:66-113`, `shared_ops.rs:803-812` | lease gate + fabric-ingress exception |

## 3. Reachability / precondition analysis (the crux, corrected)

### 3.1 `rg_active` is dead to packet programs but LIVE control-plane authority
No **forwarding** path reads the eBPF `rg_active`/`ha_watchdog` maps
(`userspace-xdp` has none; `check_egress_rg_active` is uncalled retired-eBPF;
userspace-dp gates on `rg_runtime`). **But the daemon's own control plane treats
the map as the authoritative `Active` store:** the 1 s status poll
(`refreshHAStateFromMapsLocked` → `mergeHAStateFromMaps`, `group.Active = rgVal!=0`)
**re-derives `m.haGroups` from the map**, startup replays `Active` from it
(`manager_compile.go:360`), and the watchdog re-publishes `update_ha_state`
whenever `Active` deltas. So the map is not vestigial — it is the source of truth
that reconstructs the helper's HA state. This corrects r1/r2's "dead map"
framing and is why the r2 decouple is unsafe (§4).

### 3.2 The lease bound is CONDITIONAL on the demotion being latched (or socket-down)
`update_ha_state` sets `lease = ActiveUntil(max(watchdog_ts, now)+10)`; packet-time
`active(now)= now ≤ until` (inclusive whole-second → up to ~11 s). The lease is
**renewed** every watchdog IPC while `haGroups.Active=true` — and
`haGroups.Active` is derived from the map. Therefore:
- **Map latched inactive (rg_active=0):** poll sets `Active=false` → watchdog stops
  renewing `true` → lease expires ≤~11 s → helper fails closed. Bounded.
- **Persistent control-socket failure (the issue's precondition):** the watchdog
  IPC cannot reach the helper → no renewal → lease expires ≤~11 s → fail closed.
  **Bounded.** ✔ (This is the issue's stated scenario — it *is* bounded.)
- **Map STILL active + socket UP (NOT the issue's precondition):** the watchdog
  keeps renewing `true` → the helper forwards **indefinitely**. This is *correct*
  when the node legitimately still owns the RG (VRRP still MASTER); it becomes a
  hazard only if the map is never cleared despite a demotion — e.g. a stuck/missed
  VRRP-BACKUP with the reconcile loop unable to clear. The reconcile loop
  (`reconcileRGState`, reads live VRRP states every 2 s) is the recovery for a
  *dropped* BACKUP event; a genuinely stuck VRRP-MASTER is a different failure
  domain (VRRP, not this defect).

So the honest bound is: **≤~11 s once the demotion is latched into the map OR the
socket is persistently down** — which covers the issue's precondition. The
"unbounded is unreachable" claim must carry this qualification, not stand
unconditionally.

### 3.3 No fabric mitigation; residual exposure
`fce172532` removed the flow-cache demote preflight; userspace mode skips Linux
blackhole routes. On a failed helper update, existing local flows keep forwarding
locally until latch/expiry. VRRP priority-0 moves the VIP (1 ms peer takeover),
so most new traffic goes to the peer; the genuinely dual-forwarded traffic is
stale-ARP/ND residue to the pre-resign MAC + whatever was admitted before latch —
bounded by min{ARP/ND timeout, ~11 s}. (Do not claim a TX-queue wall-clock drain
bound — queued volume is bounded, drain time is not formally established.)

### 3.4 The ack is not the fence
`ManualFailover` publishes `StateSecondaryHold`; the peer promotes on observing it
(`election.go:160`) + priority-0 VRRP (1 ms takeover), independent of the ack.
`signalFailoverActuated` (389) fires at the cluster-event point — in RETH mode
before the clear (583) — so the ack is a coordination signal, not proof forwarding
stopped. This kills Option D (§4).

## 4. Options — all code-fix variants rejected; current ordering is correct

- **Option D (hold the ack):** PLAN-KILL. Not a valid fence (§3.4); where it bites
  it strands the requester without stopping local forwarding.
- **Path A′ (fast retry in the demotion branch, r1):** REJECT. One `SetRGActive`
  attempt allows 2 s dial + 3 s roundtrip with no in-flight cancel; 3 attempts
  ≈ 15 s > the 3 s actuation barrier → the retry itself trips `failoverAckFailed`.
- **r2 decouple (send live update even if the map write fails):** REJECT —
  **harmful.** Because the poll re-derives `haGroups.Active` from the map (§3.1),
  a failed map write + successful live clear → next poll rereads the stale
  `active=1` → watchdog re-publishes `active=true` → **helper reactivates and the
  lease renews**, oscillating indefinitely against the reconcile clear. Holding
  `m.mu` only prevents interleaving *during* the call. The **current
  map-first / return-on-map-error ordering is correct**: it keeps the daemon's
  single `Active` authority (the map) and the helper consistent.
- **Conclusion:** there is no safe local code change that improves on the current
  bounded, fail-closed behavior for the issue's precondition. The only lever that
  would help the (out-of-precondition) "socket up + stale-active map" case is a
  single-`Active`-authority redesign (retire the map as authority, or a per-RG
  dirty/desired-state repair) — high blast radius, PLAN-DEFER (§5).

## 5. Recommended path — **Path C: minimal Option-(c) (doc + observability), no HA-path code change**

1. **Persistence/hysteresis "rg_active clear failing" security alarm + counter.**
   Drive it from the **reconcile loop** (`reconcileRGState`, `daemon_ha.go:846`) —
   the natural persistent-failure detector (it already retries every 2 s and
   dedups). Raise a `show security alarms` entry after N consecutive failed
   clears / ≥T seconds, clear it on the next confirmed success (hysteresis, like
   the NAT-pool alarm manager, `daemon.go:201`). A monotonic counter
   (`ha_rg_active_clear_failed_total`) counts attempts independently across ALL
   clear sites (cluster-event 367, VRRP-BACKUP 583, reconcile 846, peer-fence
   `fenceAllRedundancyGroups`). This is a **helper-liveness / dual-active-risk**
   signal — the one genuine gap (today a persistent failure is an ordinary
   deduped `Warn`). No change to `UpdateRGActive`, `signalFailoverActuated`,
   `waitFailoverActuated`, or the map ordering.
2. **Doc + stale-comment correction:**
   - Issue body: replace "UNBOUNDED" with the §3.2 conditional ~11 s bound.
   - Remove the stale "fabric-mitigated"/#485-preflight comments in the demotion
     branch (`daemon_ha.go` 342-349, 385-388) — `fce172532` removed the preflight.
   - Enumerate and correct the stale #5640 comments that describe the ack as
     *preventing peer promotion* (`cluster/sync.go`, `cluster/sync_failover.go`,
     `daemon.go`, `daemon_ha_sync.go`): the ack is a coordination signal; the peer
     promotes via `SecondaryHold`/priority-0 regardless.
   - Fix the #5079 description: it is the **demoted owner's** election-eligibility
     lease (26 s prod), not the requester's, and not a forwarding fence.
   - Document that the `rg_active` eBPF map is the daemon-side `Active` authority
     (poll re-derivation) and the ~11 s-after-latch/socket-down lease bound.
3. **Explicit security-risk acceptance + PLAN-DEFER the redesign.** The residual —
   ≤~11 s (latched/socket-down) of fail-closed dual-forwarded stale-ARP residue,
   plus a pre-latch window bounded by VRRP-resign + 2 s reconcile — is **accepted**
   as the permanent posture (fail-closed lease + operator alarm). The
   single-`Active`-authority redesign (retire the map-as-authority, or per-RG
   dirty-map repair with explicit restart semantics) is DEFERRED as
   disproportionate; file a follow-up research issue if a zero-window guarantee is
   later required. This deferral is an explicit acceptance, NOT a claim that no
   residual exists.

Rationale: the issue's headline hazard does not exist as stated for its own
precondition; no safe code fix improves on the current behavior; the current
`UpdateRGActive` ordering is correct. The only warranted change is observability +
doc hygiene.

## 6. Detailed design (Path C)

- **Alarm/counter:** add a per-RG consecutive-failed-clear counter to
  `rgStateMachine` (or the reconcile pass), raise/clear a `show security alarms`
  entry via the existing alarm manager, increment
  `ha_rg_active_clear_failed_total{site=...}` in the Prometheus collector
  (`pkg/api/`). Gate the alarm on persistence (≥N ticks), not a one-shot, so
  benign transients do not raise it.
- **No** change to `UpdateRGActive`, the map-write ordering, the #5640 barrier,
  `signalFailoverActuated`, #5079, or #485 ordering.
- Docs/comments per §5.2. Scope: ~40-70 LOC (mostly the alarm + counter) + tests.
  No wire/ABI/Rust change.

## 7. Test plan (parent-RED bindings)

- **Regression proving the current ordering is correct (guards against the r2
  decouple):** a userspace-manager test that freezes `rg_active=1`, injects a
  failing map write, and asserts `UpdateRGActive` returns error and does **not**
  publish `update_ha_state(false)` — then a follow-on poll (`mergeHAStateFromMaps`)
  keeps `Active=true` (no divergence). Parent-RED: apply the decouple → the live
  clear is sent while the map stays 1 → the poll re-reads 1 and the test asserts
  the resulting oscillation/reactivation. (`TMPDIR=/tmp`, short sun_path.)
- **Alarm/counter:** drive persistent failed clears through the reconcile loop
  (failing `SetRGActive`); assert the counter increments each tick and the alarm
  raises after N and clears on the next success. Parent-RED: revert the alarm →
  counter stays 0 / no alarm entry.
- **Rust lease bound:** extend `ha_tests.rs` — `is_forwarding_active` false once
  `now > until` (pins `HA_WATCHDOG_STALE_AFTER_SECS`).
- **Smoke:** `make test-failover` (loss userspace cluster, v4+v6) — zero-drop
  failover unchanged (Path C touches no HA-path behavior).

## 8. Risk analysis / rollback

- **Risk:** the alarm must be persistence-gated (hysteresis) so it does not fire
  on benign transients or on legitimate steady-state (a demoted RG whose map is
  0 has no failed clears). Verify it clears after a confirmed success.
- **Risk:** none to the forwarding/HA path — Path C adds observability + docs only.
- **Rollback:** `git revert`; no schema/wire/ABI/Rust change.

## 9. Documentation updates
Per §5.2 (issue body, demotion-branch comments, #5640 ack comments across
sync.go/sync_failover.go/daemon.go/daemon_ha_sync.go, #5079 description, the
map-as-Active-authority + ~11 s bound). HA design notes /
`docs/fabric-cross-chassis-fwd.md` gain the lease fail-closed bound + fabric-ingress
gate exception.

## 10. Open questions (for reviewers)
1. Is the persistence alarm worth the `show security alarms` + counter surface, or
   is **doc-only** the right minimal outcome (i.e. pure PLAN-KILL of code)?
2. Is the explicit security-risk acceptance of the bounded window acceptable, or
   does the security label force the single-`Active`-authority redesign now
   despite its blast radius?
3. Confirm the four clear sites (367 / 583 / 846 / `fenceAllRedundancyGroups`) are
   the complete set the counter should cover.

## 11. Convergence / verdict ledger

| Round | Codex | Claude SMR | AGY | Plan rev |
|-------|-------|------------|-----|----------|
| r1 | PLAN-NEEDS-REVISION (6) | PLAN-NEEDS-REVISION (5) | infra-down | r1 |
| r2 | PLAN-NEEDS-REVISION (BLOCKER+4) | PLAN-NEEDS-REVISION (5) | infra-down | r2 |
| r3 | pending | pending | infra-down | r3 |

Convergence target (2-of-3, AGY infra-blocked): Codex + Claude SMR agree on
PLAN-READY for Path C (minimal doc + hysteresis alarm, no HA-path code change,
current ordering affirmed correct) — or PLAN-KILL-to-doc-only if the alarm is
judged not worth the surface.
