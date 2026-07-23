# Plan of Action — #6371 rg_active forwarding fence on a failed clear

- **Issue:** #6371 (bug, security) — "a failed `SetRGActive(false)` still fires
  `signalFailoverActuated` → dual cluster-active forwarding under control-socket
  failure." Surfaced during #6177 /research (Codex F2/F3).
- **Research branch:** `research/6371-rgactive-fence`
- **Base:** origin/master @ `3ecdc80568a3`
- **Prior art:** #5640 (merged #6174) the fence-completion barrier; #5079 the
  owner-side transfer-out auto-restore lease; #485 the activation/demotion
  ordering; `fce172532` collapsed userspace demotion prep to a barrier-only
  (removed the flow-cache demote preflight).
- **Revision:** r2 — rewritten after hostile Codex r1 (6 substantive findings,
  all firsthand-verified below) + Claude SMR r1. AGY infra-down (2-of-3).
- **Status:** DRAFT (r2). **Recommendation: PLAN-KILL the issue's proposed fix
  (Option D) and the r1 Path A′ retry.** The "UNBOUNDED dual-active" premise is
  refuted (bounded ~11 s by the helper lease + VIP move; the peer promotes via
  heartbeat regardless of the ACK). Ship instead a **NARROW correctness + hygiene
  PR** (Path B, §5). PLAN-DEFER the deep transfer-phase redesign as
  disproportionate to a bounded, fail-closed window.

---

## 1. Problem statement (corrected)

On a coordinated transfer-out the peer sends `SendFailover(rgID)` and waits up to
`failoverAckTimeout` (**20 s**, `pkg/cluster/sync.go`) for an ack; this node
(owner) handles it in `handleRemoteFailover` (`sync_failover.go:423`):
`OnRemoteFailover` arms the #5640 barrier + `ManualFailover(rgID)` + the #5079
lease, then `WaitFailoverApplied = waitFailoverActuated` (barrier timeout **3 s**,
`daemon.go:1083`) gates the ack; timeout → `failoverAckFailed`.

The issue asserts: a failed `SetRGActive(ctx,rgID,false)` (`daemon_ha.go:367`)
still runs the unconditional `signalFailoverActuated` (`daemon_ha.go:389`) → the
ack releases → the peer promotes while `rg_active` is set → **UNBOUNDED**
dual-active under persistent control-socket failure.

**r1→r2 corrections (all verified firsthand — see §2/§3):**
1. The `SetRGActive` at line 367 is only reached on the **direct / no-reth-vrrp**
   path. In **normal RETH mode** the cluster-event transition is *unchanged*
   while VRRP is still MASTER, so line 367 is **skipped**; `signalFailoverActuated`
   (389) still fires, and the real `rg_active` clear happens **later** in the
   VRRP-BACKUP handler (`daemon_ha.go:583`). The issue analyses the direct-mode
   clear point only.
2. The dual-active window is **bounded at ~11 s** by the helper forwarding lease
   (`HA_WATCHDOG_STALE_AFTER_SECS = 10`, inclusive whole-second expiry), not
   unbounded.
3. The ack is **not** a deterministic peer-promotion fence: the peer promotes on
   heartbeat-observed `StateSecondaryHold` (`election.go:160`) and on the
   priority-0 VRRP advert (1 ms takeover timer), independent of the ack.
4. There is **no** fabric mitigation during the window (`fce172532` removed it;
   the demotion-branch comments are stale).

## 2. Blast radius / affected code (read firsthand @ 3ecdc80568a3)

| Path | Role |
|------|------|
| `pkg/daemon/daemon_ha.go:353-389` | cluster-event demotion branch: `SetCluster(false)`→`ResignRG`→(direct-mode) `SetRGActive(false)` at 367→ **unconditional** `signalFailoverActuated` at 389 |
| `pkg/daemon/rg_state.go:250-265` | `reconcileLocked`: default `desired = clusterPri \|\| allVRRPMaster` — RETH cluster-event demotion is `tr.Changed=false` while VRRP MASTER |
| `pkg/daemon/daemon_ha.go:567-590` | **VRRP-BACKUP handler**: the RETH-mode `rg_active` clear (`SetRGActive(false)` at ~583); does **not** signal the fence |
| `pkg/daemon/daemon_ha.go:707-853` | `reconcileRGState` — 2 s desired-vs-applied retry of the clear (`ShouldLogApplyError` dedup) |
| `pkg/dataplane/userspace/manager_ha.go:631-716` | `Manager.UpdateRGActive` — **dead** `bpfShim.UpdateRGActive` (eBPF map, 638) returns on error **before** the live `requestLocked(update_ha_state)` (699) |
| `pkg/dataplane/maps_fabric.go:36-47` | `dataplane.Manager.UpdateRGActive` — writes the `rg_active` eBPF map (nothing live reads it) |
| `pkg/dataplane/userspace/process_control.go:81,106,129-142` | control socket: **fresh dial per request**, 2 s dial + up to 3 s roundtrip deadline |
| `pkg/cluster/failover.go:120-128` | `ManualFailover` sets `rg.State = StateSecondaryHold` in-memory → published via heartbeat |
| `pkg/cluster/election.go:160-167` | peer promotes on observing `StateSecondaryHold` — independent of the ack |
| `pkg/cluster/sync_failover.go:423-451` | `handleRemoteFailover` — `WaitFailoverApplied` gates the ack; timeout → `failoverAckFailed` |
| `pkg/daemon/daemon_ha_sync.go:1067` | production transfer-out lease = `2·localFailoverCommitTimeout + 20 s` = **26 s** (election-time recovery, not a forwarding fence) |
| `userspace-dp/src/afxdp/types/runtime.rs:335-370` | `HAForwardingLease` / `active(now)= until!=0 && now<=until` (inclusive) / `HA_WATCHDOG_STALE_AFTER_SECS=10` |
| `userspace-dp/src/afxdp/forwarding/ha.rs:66-113` | `enforce_ha_resolution_snapshot` — the lease gate for Forward/MissingNeighbor/LocalDelivery |
| `userspace-dp/src/afxdp/shared_ops.rs:803-812` | fabric-ingress path: deliberately redirects when owner not active (a lease-gate exception) |
| `pkg/daemon/daemon_ha_userspace_readiness.go:132-193` | `prepareUserspaceRGDemotionWithTimeout` — **session-sync barrier only**, no flow-cache demote |

## 3. Reachability / precondition analysis (the crux, corrected)

### 3.1 The live forwarding gate is the helper lease; the eBPF map is dead
`Manager.UpdateRGActive` writes (1) the `rg_active` **eBPF map** then (2) the
**control-socket** `update_ha_state`. **No live path reads the eBPF map:**
`userspace-xdp` has zero refs; `check_egress_rg_active` (`xpf_helpers.h:2371`) is
uncalled retired-eBPF code (`bpf/tc|xdp/*.c` deleted #1476); the legacy loader is
retired. Forwarding gates on the helper's `rg_runtime` via
`is_forwarding_active(now_secs)`, fed **only** by `update_ha_state`.

### 3.2 The window is bounded at ~11 s (fail-closed), not unbounded
`update_ha_state` sets `lease = ActiveUntil(max(watchdog_ts, now) + 10)`; at
packet time `active(now) = now ≤ until` (inclusive, whole-second → up to ~11 s
wall-clock). After a demotion `m.haGroups[rgID].Active` is latched `false`
(`manager_ha.go:641`, **before** the socket send), so no later successful
`update_ha_state` can refresh the lease to `true`; the only survival is "no
socket message ever succeeds," in which case the lease expires at ~11 s and the
helper fails closed for **every** RG on the node. **Unbounded is unreachable.**

**Gate universality — narrowed (Codex F5):** `enforce_ha_resolution_snapshot`
gates ordinary new-flow admission, session/cache hits (`cached_flow_decision_valid`
re-checks), and flowless transit. Exceptions that are **not** universally
lease-gated: trusted **fabric-ingress** delivery (`ha.rs`/`shared_ops.rs:803`)
and the peer-return fast path (both fabric-only, by design), and **frames already
admitted into a bounded TX queue** may drain slightly past expiry (natural expiry
issues no `DemoteOwnerRGS`). These do **not** sustain ordinary independent
old-owner transit; the correct claim is "the lease bounds **new ordinary
admission** at ~11 s," not "every packet on every path."

### 3.3 The residual dual-forwarded exposure (corrected — no fabric mitigation)
`fce172532` removed the flow-cache demote preflight; userspace mode also skips
Linux blackhole-route injection. So on a failed helper update, this node's
**existing** flows keep forwarding **locally** (not fabric-relayed) until the
lease expires. VRRP priority-0 moves the VIP to the peer (1 ms takeover), so most
*new* traffic goes to the peer; the genuinely dual-forwarded traffic is (a)
existing local flows whose packets still reach this node (stale ARP/ND to the
pre-resign MAC, asymmetric paths) and (b) whatever the helper admits before
expiry — bounded by min{ARP/ND cache timeout, ~11 s lease}. This is the precise
security surface; it is real but bounded and fail-closed.

### 3.4 Why the ack is not the fence (Codex F3)
`ManualFailover` publishes `StateSecondaryHold` immediately; the peer's election
promotes on observing it via heartbeat (`election.go:160`), and a priority-0
advert independently arms the peer's 1 ms takeover. So the peer can promote with
or without the ack. `signalFailoverActuated` fires at the **cluster-event** point
(389), which in RETH mode is *before* `rg_active` is cleared (that clear is the
VRRP-BACKUP handler at 583) and *before* VRRP has fully resigned — i.e. the ack is
a coordination signal, not proof that forwarding stopped. This both weakens the
issue's causal chain (the ack is not the sole promotion trigger) and kills
Option D (§4).

## 4. Multiple Path Options

### Option D — hold the ack until the clear is CONFIRMED (issue's proposal) → PLAN-KILL
- **Not a valid fence (Codex F3):** the peer promotes on heartbeat-observed
  `SecondaryHold` + priority-0 VRRP regardless of the ack, so withholding it does
  **not** reliably prevent dual forwarding.
- **Where it *does* bite it makes things worse:** in direct mode, withholding the
  ack strands the requester (→ its 26 s #5079 lease) without stopping this node
  forwarding (its clear still failed) — a lose-lose, not the r1 "peer has the VIP
  but doesn't forward" (that r1 blackhole proof was wrong; the peer does not
  already hold the VIP via the ack).
- **Verdict: PLAN-KILL** — invalid fence.

### Option (a) — locally fence forwarding on a failed clear, don't abort
The only mechanism that fences forwarding independent of `rg_active` is the
helper's own state — reachable only via the same control socket that failed. So
"fence locally without the socket" reduces to the ~11 s lease (already present)
+ VIP move (already present). No new lever exists. **Nothing to add.**

### Option (b) — bounded fast retry then hard fence → REJECT (Codex F6)
`SetRGActive` context is checked only *before* the I/O and does not cancel it;
one attempt allows 2 s dial + 3 s roundtrip, so 3 attempts ≈ 15 s > the 3 s
actuation barrier → the retry would itself trip `failoverAckFailed`. A hard fence
(kill helper) duplicates the ~11 s lease and blackholes healthy RGs. **Reject.**

### Option (c) — accept + alarm + doc → viable as part of Path B
Accept the bounded, fail-closed window; add observability + doc correction. This
is the defensible core, folded into Path B below.

## 5. Recommended path — **Path B: narrow correctness + hygiene PR**

PLAN-KILL Option D and the r1 Path A′ retry. Ship a small, low-risk PR:

1. **Decouple the dead eBPF-map write from the live helper update in
   `Manager.UpdateRGActive` (the one genuine latent bug).** Today a failed
   `bpfShim.UpdateRGActive` (dead map) returns *before* the live
   `update_ha_state`, so a rare map-syscall error would **block the real
   demotion delivery**. Fix: latch desired state, attempt the live helper
   `update_ha_state` **regardless** of the dead-map result, and return the two
   failures **separately** (or drop the dead-map write from the safety-critical
   path entirely — decide during /engineer whether any consumer remains). This
   directly shrinks the reachability of a stuck-active RG.
2. **Mode-agnostic dual-active-risk / helper-liveness alarm + metric** on a
   failed clear, at **both** clear sites (direct-mode `daemon_ha.go:367` and the
   RETH VRRP-BACKUP `daemon_ha.go:583`) — distinct from the benign transient
   `Warn`, so a persistent helper-unreachable condition is operator-visible
   (`show security alarms` / a Prometheus counter). Actionable value: it flags a
   wedged/dead helper (an otherwise-silent fault the reconcile `Warn` masks).
3. **Doc + stale-comment correction:** replace "UNBOUNDED" (issue body + any HA
   docs) with the ~11 s lease bound; fix the stale "fabric-mitigated"/#485
   comments in the demotion branch (`fce172532` removed the preflight); document
   the RETH-vs-direct clear points and that the ack is a coordination signal, not
   a forwarding fence (peer promotes via `SecondaryHold`).

**Explicitly out of scope / PLAN-DEFER:** Codex's deeper redesign ("define
distinct RETH/direct transfer phases; do not expose `SecondaryHold` or priority-0
VRRP before a confirmed local fence"). That reworks the coordinated-transfer
protocol and VRRP timing — high blast radius — to close a window that is already
bounded (~11 s), fail-closed, and where the peer promotes anyway. Disproportionate
per project pragmatism; file a follow-up research issue if a zero-window guarantee
is later required.

Rationale: the issue's headline hazard does not exist as stated; the only
genuinely shippable correctness item is #1, plus warranted observability (#2) and
doc hygiene (#3). This is a **light ship**, and it **PLAN-KILLs** the heavy fix
the issue proposed.

## 6. Detailed design of the recommended change

- **`pkg/dataplane/userspace/manager_ha.go` `UpdateRGActive`:** compute/latch the
  in-memory `haGroups` state first; run the live `update_ha_state` regardless of
  the dead-map write result; accumulate both errors (`errors.Join`) so a
  dead-map failure never short-circuits the live demotion. Preserve the existing
  poll-race lock discipline (the comment at 635-637 explains why the map write is
  under `m.mu`). Alternative to weigh in /engineer: delete the dead-map write.
- **`pkg/daemon/daemon_ha.go`:** extract the two clear sites to a shared helper
  that, on a non-nil error, emits the security alarm + increments the counter
  (gate strictly on the actuation/BACKUP clear, not the reconcile retries which
  already dedup). No control-flow change to `signalFailoverActuated` (the ack
  release is not the defect).
- **Metric:** `ha_rg_active_clear_failed_total{path="direct|vrrp-backup"}` in the
  Prometheus collector (`pkg/api/`).
- **No** change to `waitFailoverActuated` / `handleRemoteFailover` / #5079 / #485.
- Scope: ~50-80 LOC + tests. No wire/ABI change; no Rust behavior change.

## 7. Test plan (parent-RED bindings)

- **Userspace-manager unit test:** inject a failing `bpfShim.UpdateRGActive` and
  a recording control-socket; assert `update_ha_state` is **still** sent
  (demotion delivered) and both errors are reported. Parent-RED: revert the
  decouple → the live send is skipped → assertion fails (behavioral, not a build
  break, per `feedback_red_on_revert_must_be_assertion_not_build_break`). Run
  with `TMPDIR=/tmp` (short sun_path, `feedback_userspace_socket_tests_need_short_tmpdir`).
- **Daemon unit test (both modes):** drive a demotion so the clear runs and
  fails; assert the counter increments and the alarm fires — separately for the
  direct-mode line-367 path **and** the RETH VRRP-BACKUP line-583 path. Verify
  the event-injection harness reaches each branch (extend
  `daemon_ha_fence_3917_test.go`'s `fenceRecorderHA`).
- **Rust lease bound (guard the ~11 s claim):** extend `ha_tests.rs` to assert
  `is_forwarding_active` is false once `now > until` (pins
  `HA_WATCHDOG_STALE_AFTER_SECS`).
- **Smoke:** `make test-failover` on the loss userspace cluster (mandatory for
  cluster/failover code), v4+v6, zero-drop unchanged.

## 8. Risk analysis / rollback

- **Risk:** reordering `UpdateRGActive` must preserve the #????-poll-race lock
  discipline (map write under `m.mu`); keep both writes under the lock, only
  change the error short-circuit. Verify the activation path (`active=true`)
  still fails closed if the live update fails (a partial activate must not report
  success).
- **Risk:** the alarm must not fire on benign reconcile retries — gate strictly
  on the actuation/BACKUP clear.
- **Rollback:** `git revert`; no schema/wire/ABI/Rust change.

## 9. Documentation updates

- Correct "UNBOUNDED" in the #6371 issue body (comment) → ~11 s lease bound.
- Fix stale demotion-branch comments (`daemon_ha.go` 342-349, 385-388) — remove
  the "fabric-mitigated" claim (`fce172532`), document RETH-vs-direct clear
  points + the ack-is-coordination-not-fence semantics.
- Update HA design notes / `docs/fabric-cross-chassis-fwd.md` with the lease
  fail-closed bound + the fabric-ingress lease-gate exception.

## 10. Open questions (for reviewers)

1. Is decoupling the dead-map write worth it, or should the dead `rg_active`
   eBPF-map write be **removed** outright (confirm zero consumers incl. any
   out-of-tree tooling / parity tests)?
2. Is the alarm best as a `show security alarms` entry, a Prometheus counter, or
   both — given the window is already bounded/fail-closed?
3. Does closing even a bounded ~11 s dual-active window ever justify the deep
   transfer-phase redesign (PLAN-DEFER here), or is fail-closed + alarm the right
   permanent posture?

## 11. Convergence / verdict ledger

| Round | Codex | Claude SMR | AGY | Plan rev |
|-------|-------|------------|-----|----------|
| r1 | PLAN-NEEDS-REVISION (6 findings) | PLAN-NEEDS-REVISION (5 findings) | infra-down | r1 |
| r2 | pending | pending | infra-down | r2 |

Convergence target (2-of-3, AGY infra-blocked): Codex + Claude SMR agree on
PLAN-READY for Path B (or PLAN-KILL of all code if reviewers show the dead-map
decouple + alarm are not worth any change and doc-only suffices).
