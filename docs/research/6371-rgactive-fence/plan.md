# Plan of Action — #6371 rg_active forwarding fence on a failed clear

- **Issue:** #6371 (bug, security) — "a failed `SetRGActive(false)` still fires
  `signalFailoverActuated` → dual cluster-active forwarding under control-socket
  failure." Surfaced during #6177 /research (Codex F2/F3).
- **Research branch:** `research/6371-rgactive-fence`
- **Base:** origin/master @ `3ecdc80568a3`
- **Prior art:** #5640 (merged #6174) added the fence-completion barrier that
  gates the transfer-out applied-ack on the local demotion being actuated;
  #5079 the owner-side transfer-out auto-restore lease; #485 the
  activation/demotion ordering contract.
- **Revision:** r1 (pre-review draft) — awaiting Codex + Claude SMR hostile
  plan-review. AGY infra-down (2-of-3 per standing rules).
- **Status:** DRAFT. Leading recommendation: **PLAN-KILL Option D** (the heavy
  hold-the-ACK fix) as net-negative, and ship a **LIGHT hardening** (Path A′:
  observability alarm + fast bounded retry + doc correction). The headline
  "UNBOUNDED dual-active" premise is **firsthand-refuted**: the userspace
  helper's forwarding lease self-expires at ≤10 s (`HA_WATCHDOG_STALE_AFTER_SECS`),
  so the window is bounded and fail-closed.

---

## 1. Problem statement

On a **coordinated transfer-out** the peer (requester) sends `SendFailover(rgID)`
and promotes only after it receives `failoverAckApplied`. This node (the current
owner) receives the request in `handleRemoteFailover`
(`pkg/cluster/sync_failover.go:423`):

1. `OnRemoteFailover` (`pkg/daemon/daemon_ha_sync.go:987`) arms the
   fence-completion barrier (`armFailoverActuation`), calls
   `cluster.ManualFailover(rgID)` (enqueues the async demotion event), and arms
   the #5079 transfer-out lease.
2. `WaitFailoverApplied(rgID)` = `waitFailoverActuated(rgID)`
   (`sync_failover.go:443-449`) blocks until the barrier is closed, then acks
   `failoverAckApplied`. A barrier **timeout** (3 s) downgrades to
   `failoverAckFailed` so the peer holds.

The async demotion event is consumed by `watchClusterEvents`
(`pkg/daemon/daemon_ha.go:353-389`, the `else` / non-primary branch):

```
tryPrepareUserspaceRGDemotion  →  ResignRG (VRRP priority-0)  →
  injectBlackholeRoutes  →  SetRGActive(ctx, rgID, false)  →
  signalFailoverActuated(rgID)          // line 389 — UNCONDITIONAL
```

**Defect:** `SetRGActive(ctx, ev.GroupID, false)` at line 367 is followed by an
*unconditional* `signalFailoverActuated(ev.GroupID)` at line 389. If the clear
returns an error, the code logs `slog.Warn("failed to update rg_active from
cluster event")` and **still** closes the barrier. `waitFailoverActuated`
returns nil → the ack is `applied` → the peer promotes while this node's
`rg_active` was not confirmed cleared. #5640 gated the ack on the *success*
path; the *failed* clear is unfenced. The 2 s `reconcileRGStateLoop` retries the
clear, but that is a retry cadence, not a hard bound.

The issue frames this as **UNBOUNDED** dual cluster-active forwarding under a
persistent control-socket failure. Section 3 refutes the "unbounded" premise
firsthand; the residual is a **bounded ≤10 s, fabric-mitigated** window.

## 2. Blast radius / affected code (read firsthand @ 3ecdc80568a3)

| Path | Role |
|------|------|
| `pkg/daemon/daemon_ha.go:353-389` | demotion branch: `SetRGActive(false)` (367) then **unconditional** `signalFailoverActuated` (389) |
| `pkg/daemon/daemon_ha.go:142-217` | the #5640 barrier: arm/disarm/signal/wait/batch |
| `pkg/daemon/daemon_ha.go:604-704` | `reconcileRGStateLoop` (2 s ticker) + `reconcileRGStatePass` |
| `pkg/daemon/daemon_ha.go:707-853` | `reconcileRGState` — desired-vs-applied retry of `SetRGActive(false)` (`s.NeedsApply()`, `ShouldLogApplyError`) — **each pass can re-fail** |
| `pkg/daemon/daemon_ha_sync.go:987-1057` | `OnRemoteFailover` / `WaitFailoverApplied = waitFailoverActuated` wiring; #5079 lease arm |
| `pkg/cluster/sync_failover.go:423-451` | `handleRemoteFailover` — `WaitFailoverApplied` gates the ack; timeout → `failoverAckFailed` (peer holds) |
| `pkg/cluster/manager.go:336-349` | `DefaultRemoteTransferOutLease = 30 s`, floor `minRemoteTransferOutLease = 15 s` |
| `pkg/cluster/election.go:67-106` | #5079 lease expiry restores this node primary if a transfer never commits |
| `pkg/dataplane/userspace/manager_ha.go:631-716` | `Manager.UpdateRGActive` — **BPF map write FIRST, then control-socket `update_ha_state`**; either can error |
| `pkg/dataplane/maps_fabric.go:36-47` | `dataplane.Manager.UpdateRGActive` — writes the `rg_active` eBPF map (a syscall, helper-independent) |
| `pkg/dataplane/userspace/process_status.go:150-258` | 1 s `statusLoop` — on `requestLocked` error it **only logs**, never restarts the helper |
| `pkg/dataplane/userspace/process.go:18-30` | `ensureProcessLocked` restarts an unhealthy helper — **only on config apply / binding-plan change**, not periodically |
| `userspace-dp/src/afxdp/ha/state.rs:4-118` | `update_ha_state` — the sole writer of the helper's `rg_runtime` forwarding state (control-socket-fed) |
| `userspace-dp/src/afxdp/types/runtime.rs:335-370` | `HAForwardingLease` / `is_forwarding_active(now_secs)` — the packet-time forwarding gate |
| `userspace-dp/src/afxdp/mod.rs:402` | `HA_WATCHDOG_STALE_AFTER_SECS = 10` |
| `userspace-dp/src/afxdp/shared_ops.rs:807`, `session_glue/mod.rs:183,197` | forwarding resolution consults `is_forwarding_active(now_secs)` |

## 3. Reachability / precondition analysis (the crux)

The issue's severity hinges on **"unbounded" dual-active**. Firsthand tracing of
the forwarding gate refutes it.

### 3.1 What actually gates forwarding for the userspace dataplane

`Manager.UpdateRGActive` (`manager_ha.go:631`) does two writes, in order:

1. `m.bpfShim.UpdateRGActive(rgID, active)` — writes the `rg_active` **eBPF map**
   (`maps_fabric.go:38`, a `map.Update` syscall). Returns on error *before* the
   socket send.
2. `m.requestLocked(update_ha_state)` — the **control-socket** message that
   updates the helper's internal HA state. Returns on error.

**The live forwarding path reads neither BPF map.** Verified:
- `userspace-xdp/` (the retained AF_XDP steering shim) has **zero** references to
  `rg_active` / `ha_watchdog` (grep empty). The shim only steers packets to
  userspace queues.
- `check_egress_rg_active()` exists only in `bpf/headers/xpf_helpers.h:2371` —
  a **retired-eBPF parity header**; the `bpf/tc/*.c` / `bpf/xdp/*.c` programs
  that called it were deleted in #1476. Nothing in the live path compiles it.
- `userspace-dp` forwarding resolves ownership through the coordinator's
  `rg_runtime` (`is_forwarding_active(now_secs)` at `shared_ops.rs:807`,
  `session_glue/mod.rs:183,197`), **not** the eBPF map. `rg_runtime` is written
  **only** by `update_ha_state` (`ha/state.rs:4`), i.e. the control socket.

Therefore the `rg_active` eBPF-map write (step 1) is vestigial for the live
userspace dataplane; the **control-socket `update_ha_state` (step 2) is the real
demotion delivery**.

### 3.2 The 10 s forwarding lease bounds and fail-closes the window

`update_ha_state` sets, for an active group:
`lease = ActiveUntil( max(watchdog_ts, now) + HA_WATCHDOG_STALE_AFTER_SECS )`
(`runtime.rs:357-366`, constant = **10 s**). At **packet time**, forwarding
consults `is_forwarding_active(now_secs) = active && (until != 0 && now ≤ until)`
(`runtime.rs:368`). The lease is re-evaluated against the *current* monotonic
clock on every packet.

Consequences under a persistent control-socket failure (the issue's premise):
- The demotion `update_ha_state` (active=false) never reaches the helper — but
  neither does any *refresh*. The helper keeps the last `until = T_last + 10 s`.
- Once `now > T_last + 10 s`, `is_forwarding_active` returns false for **every**
  RG on this node → the helper fails closed (HAInactive → fabric-redirect/drop).
- The daemon's watchdog heartbeat cannot keep the lease alive: after the
  demotion, `m.haGroups[rgID].Active` is already `false` in Go memory, so the
  *next* successful `update_ha_state` (from the heartbeat or the reconcile
  retry) would carry `active=false` → immediate demote. The only way the lease
  survives is if **no** socket message succeeds — in which case it expires.

**The dual-active window is bounded at ≤10 s** (typically ≤2 s: the reconcile
loop re-attempts the clear every 2 s and succeeds the moment the socket
recovers). The "unbounded" premise is false.

### 3.3 The window is further mitigated, and the precondition is narrow

- **Fabric preflight:** the demotion branch runs `tryPrepareUserspaceRGDemotion`
  *before* the clear, shifting existing flow-cache entries to `FabricRedirect`
  so this node relays its residual flows to the peer rather than forwarding them
  independently (`daemon_ha.go:342-349`). During the window this node is largely
  a fabric relay, not an independent second forwarder.
- **VRRP resign is unconditional and precedes the clear:** `ResignRG`
  (priority-0) moves the VIP/vMAC to the peer regardless of the clear result, so
  new traffic is L2-delivered to the peer; only stale-ARP residue reaches this
  node during the window.
- **Precondition reachability:** a "helper alive + forwarding + control socket
  wedged for ≥10 s" state is narrow. If the helper is **dead**, it forwards
  nothing → no dual-active. If it is **alive**, its control server generally
  answers; a wedged accept loop with live workers is the only way to hold the
  window open, and even that fail-closes at 10 s. There is **no** continuous
  supervisor that restarts a wedged-but-alive helper (`statusLoop` only logs on a
  failed poll; `ensureProcessLocked` runs only on config apply), so the lease —
  not a restart — is the fail-closed backstop, but it *is* a fail-closed
  backstop.

**Net:** the genuine exposure is a **≤10 s, fabric-mitigated, fail-closed**
dual-active window during a coordinated transfer-out that races a
control-socket failure — not an unbounded split-brain.

## 4. Multiple Path Options

### Option D — hold the ACK until the clear is CONFIRMED (the issue's proposal)
Do not call `signalFailoverActuated` on a failed clear; let
`waitFailoverActuated` time out (3 s) → `failoverAckFailed` → the peer holds.

- **Fatal flaw (firsthand):** `ResignRG` already ran *before* the clear, so the
  VIP has **already** moved to the peer. Under Option D the peer's ack is
  `failed` → the peer stays cluster-secondary → `rg_active` false → **the peer
  holds the VIP but does not forward** → a **blackhole**, cleared only by this
  node's reconcile finally clearing + re-electing, or the #5079 lease (15-30 s).
  Option D **replaces a ≤10 s fabric-mitigated dual-active with a ≥15 s
  blackhole** — strictly worse for availability, and it does not even prevent
  this node from forwarding (its `rg_active` is still stuck).
- **#485 conflict:** #485 fixed the ordering so demotion is
  preflight→resign→blackhole→clear and activation is the reverse. Holding the
  ack after resign violates the invariant that "once we resign, the peer must be
  allowed to take forwarding" — the resign already surrendered the VIP.
- **Verdict:** **PLAN-KILL.** Net-negative.

### Option (a) — fence FORWARDING locally on a failed clear, do NOT abort
Keep releasing the ack (peer promotes — correct, the VIP already moved), but on
a failed clear proactively drive this node's helper toward fail-closed faster
than the 10 s lease.

- The fabric preflight already redirects existing flows; the residual is the
  lease. A cheap belt-and-suspenders: on a failed clear, `triggerReconcile()`
  so the 2 s cadence collapses to near-immediate, and rely on the lease as the
  hard bound. Feasible and low-risk. Does not introduce a blackhole.
- Can the dataplane fence forwarding independent of `rg_active` state? Yes —
  the fabric preflight (`DemoteOwnerRGS` / flow-cache→FabricRedirect) is exactly
  that mechanism and is already invoked. A *forced* local demote of the helper's
  `rg_runtime` for the RG (mark HAInactive) without the successful socket send
  is **not** possible — the helper's state is only reachable via the same
  control socket that just failed. So "fence forwarding independent of the
  socket" reduces to the fabric preflight (already done) + the lease.

### Option (b) — bounded escalation: fast retry, then hard fence
Retry the clear N times fast (e.g. 3× at 50-100 ms) inside the demotion branch
*before* signaling; if still failing, either signal anyway (never abort) or hard
fence (kill the helper / drop-all).

- Fast-retry-then-signal (no kill) tightens the *typical* window with no
  blackhole risk. Cheap, low-risk.
- Hard-fence (kill helper) is a fail-closed backstop but blackholes **all** RGs
  on the node (including legitimately-owned ones) and duplicates what the 10 s
  lease already does — reject the kill variant.

### Option (c) — accept + alarm (PLAN-KILL the code change)
Accept the ≤10 s bounded window as already fail-closed by the lease; add only a
security-severity alarm/metric + a doc correction.

- Defensible: the precondition is already bounded by a fail-closed path
  (§3.2). The only genuine gap is **observability** — today a failed clear on
  the actuation path is an ordinary `Warn`, indistinguishable from a benign
  transient and not surfaced as a dual-active-risk event.

## 5. Recommended path — **A′ = (a) + (b:fast-retry) + (c:alarm), PLAN-KILL D**

Ship a **light** hardening; do **not** hold/abort the ack:

1. **Never abort the failover** — keep releasing the ack after resign (the VIP
   already moved; aborting blackholes). PLAN-KILL Option D.
2. **Fast bounded retry** of `SetRGActive(false)` in the demotion branch before
   `signalFailoverActuated` (e.g. up to 3 attempts, ~50 ms apart) to shrink the
   typical window from ≤2 s (reconcile cadence) to sub-second on transient
   errors. On still-failing, proceed to signal (no blackhole).
3. **`triggerReconcile()` on a still-failing clear** so the retry cadence
   collapses to near-immediate rather than waiting up to 2 s.
4. **Security-severity alarm + metric** distinct from the benign transient
   `Warn`: emit a cluster event / structured log + a Prometheus counter
   (`ha_rg_active_clear_failed_on_actuation`) when the clear is still failing at
   `signalFailoverActuated` time, so a persistent failure is operator-visible and
   the ≤10 s lease is the documented hard backstop.
5. **Doc correction:** replace the "UNBOUNDED" framing in the issue and any
   affected docs (`docs/fabric-cross-chassis-fwd.md`, HA design notes) with the
   verified ≤10 s lease bound + fabric mitigation.

Rationale: the current behavior is already bounded and fail-closed; the only
real defects are (i) missing security observability of the risky path and (ii)
an over-long typical retry cadence. Option D would actively regress availability.
This is a **ship-code** outcome (light), not a pure PLAN-KILL — but it PLAN-KILLs
the heavy fix the issue proposed.

## 6. Detailed design of the recommended change

- **Location:** `pkg/daemon/daemon_ha.go` demotion branch (353-389). Extract the
  `SetRGActive(ctx, ev.GroupID, false)` call into a small helper
  `clearRGActiveWithRetry(ctx, rgID)` that attempts the clear up to N times with
  a short backoff, returns the final error.
- On a non-nil final error: `triggerReconcile()`, emit the security alarm
  (`d.cluster.RecordEvent` + counter), then **still** call
  `signalFailoverActuated` (unchanged control flow — no abort).
- **Metric:** add the counter to the existing Prometheus collector
  (`pkg/api/`); increment on the failed-clear-at-actuation path only.
- **No change** to `waitFailoverActuated` / `handleRemoteFailover` / the #5079
  lease / #485 ordering — the ack still releases; the peer still promotes.
- Scope: ~40-60 LOC + a unit test. No Rust change (the lease already exists and
  is correct).

## 7. Test plan (parent-RED bindings)

- **Daemon unit test** (extend `daemon_ha_fence_3917_test.go` or a new
  `daemon_ha_failed_clear_6371_test.go`): a `fenceRecorderHA` whose
  `SetRGActive(_, id, false)` returns an error. Assert that on a demotion event
  (a) the barrier is **still** signaled (peer not stranded → no blackhole),
  (b) `triggerReconcile` fires, (c) the security counter increments, (d) the
  clear was retried N times. Parent-RED: revert the retry/alarm → the counter
  stays 0 / retry count 1 → RED (an assertion failure, not a build break, per
  `feedback_red_on_revert_must_be_assertion_not_build_break`).
- **Reachability regression (doc-as-test):** a Rust unit test asserting
  `is_forwarding_active` returns false once `now > until` for a stale lease
  (may already exist in `ha_tests.rs` — extend/reference to pin the ≤10 s bound
  the plan relies on, so a future change to `HA_WATCHDOG_STALE_AFTER_SECS` that
  breaks the bound is caught).
- **Smoke:** `make test-failover` on the loss userspace cluster (mandatory for
  cluster/failover code) — assert zero-drop failover unchanged (v4+v6).

## 8. Risk analysis / rollback

- **Risk:** the fast-retry adds up to ~150 ms of latency on the demotion path on
  a genuinely failing clear — negligible vs. the 3 s barrier timeout and it only
  triggers on error. On the success path (the common case) it is a single
  attempt, unchanged.
- **Risk:** the alarm must not fire on benign transients — gate it strictly on
  the *actuation-path* failed clear (not the reconcile-loop retries, which
  already have `ShouldLogApplyError` dedup).
- **Rollback:** `git revert`; no schema/wire/ABI change, no Rust change.

## 9. Documentation updates

- Correct the "UNBOUNDED" claim in the #6371 issue body (comment) and in
  `docs/fabric-cross-chassis-fwd.md` / the HA design notes: document the ≤10 s
  `HA_WATCHDOG_STALE_AFTER_SECS` forwarding-lease bound as the fail-closed
  backstop and the fabric-preflight mitigation.
- Note in `pkg/daemon/daemon_ha.go` the rationale for **not** aborting the ack
  on a failed clear (VIP already resigned → abort blackholes).

## 10. Open questions (for reviewers)

1. **Load-bearing claim to hammer:** does *any* live forwarding path read the
   `rg_active` / `ha_watchdog` eBPF maps (making step-1 the true fence)? Plan
   says NO (§3.1). If a reviewer finds a live reader, the reachability analysis
   changes (step-1 success would fence forwarding regardless of the socket, and
   the whole issue is even more benign).
2. Is `is_forwarding_active(now_secs)` truly consulted on **every** transit
   forwarding decision for an owned RG, or are there paths that forward without
   it (which would let a demoted-but-unnotified RG forward past 10 s)? Plan
   assumes it is the universal gate (§3.2); reviewers should probe
   `enforce_ha_resolution_snapshot` and the local-delivery path.
3. Is the security alarm worth the Prometheus surface, or should it be a cluster
   event + structured log only? (Cost/benefit — the window is already bounded.)
4. Should the fast-retry live in the demotion branch or be folded into a shared
   `SetRGActive`-with-retry used by both the event path and the reconcile loop?

## 11. Convergence / verdict ledger

| Round | Codex | Claude SMR | AGY | Plan rev |
|-------|-------|------------|-----|----------|
| r1 | pending | pending | infra-down | r1 |

Convergence target: Codex + Claude SMR agree (2-of-3, AGY infra-blocked) on
PLAN-READY for Path A′ (or PLAN-KILL if reviewers show the window is fully
mooted by an existing fail-closed reader of the eBPF map, or that the alarm is
not worth any code).
