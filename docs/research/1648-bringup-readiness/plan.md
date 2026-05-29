# #1648 — Dataplane bringup-readiness: first cold connect drops a single SYN (~1s RTO) after `systemctl restart`/deploy

**Status:** v1 (DRAFT) — research-only (`/research`, not `/engineer`). Gate-B
(cluster measurement) is the decider and runs FIRST. No production code, no PR.
**Branch:** `research/1648-bringup-readiness` (off origin/master @ `da88f1ab1`, incl. #1660 B3 merge)
**Worktree:** `.claude/worktrees/1648-research-bringup`
**Reviewers:** Codex + AGY + Claude SMR (3-way at /research; Copilot joins at /engineer)
**Scope:** Re-scoped per the Gate-R refutation (2026-05-29). Pin the EXACT loss
point of the single dropped SYN during dataplane bringup after daemon
restart/deploy, then choose a fix (readiness-ordering vs lossless-gap vs
accept-the-artifact), or PLAN-KILL the readiness-gate framing if Gate-B refutes
it.

---

## 0. What changed (why this is v1 of a NEW research line, not a continuation)

The prior research line on this issue (branch `research/1648-startup-neigh-race`,
plan v6, 3-way PLAN-READY) targeted a **seq=0 neighbor-dump multicast-drop race**
(H-0). **Gate-R conclusively REFUTED H-0**:

- counter A (seq=0 NEW/DEL skipped during `initial_neighbor_dump`) = **0 across 7
  restarts**.
- `initial_neighbor_dump` duration = **95–139µs** (not ~1s).
- Failover is World 2: clean 0/20, crash 0/25, ENOBUFS=0 — unaffected.

The ~1s **does** reproduce on the first connect after `systemctl restart`/deploy,
with a clean single-SYN TCP-RTO signature:

```
689.548911  10.0.61.102.57282 > 172.16.80.200.5201: Flags [SEW]   <- first SYN, dropped
690.556201  10.0.61.102.57282 > 172.16.80.200.5201: Flags [S]     <- retransmit at +1.007s
690.556874  172.16.80.200.5201 > 10.0.61.102.57282: Flags [S.]    <- SYN-ACK at +0.0006s (instant)
```

Exactly **one** SYN is dropped; the +1.007s retransmit is answered immediately.
The seq=0 counter never incremented for that flow. So the mechanism is a
**single dropped SYN during dataplane bringup**, a DIFFERENT mechanism from the
dump-race. The dump-race plan is the archive of a refuted hypothesis; this plan
does not reuse it.

---

## 1. Problem statement

After `systemctl restart xpfd` / a deploy, the **first** transit TCP connect
through the firewall drops exactly one SYN and recovers via the client's
~1.007s TCP SYN-RTO. Steady-state cold connects are 0.6–3.7ms (#1651 Gate-M);
failover is unaffected (Gate-R World 2). Control: a fully-booted daemon shows
0/50 slow connects. The symptom is therefore exclusively a daemon-restart-boot
artifact.

**The research must:**
1. Pin the EXACT XDP/dataplane loss point of that one SYN (Gate-B measurement).
2. Determine which readiness sub-gate (ctrl.enabled, binding flags=READY,
   heartbeat-live, XSK-slot-registered) is open at the instant of the drop.
3. Decide a fix per the multi-path menu in §5, OR PLAN-KILL the readiness-gate
   framing if Gate-B shows the drop is not in a readiness gap (e.g. a kernel-side
   neighbor miss the dataplane never sees).

---

## 2. Architecture walk (verified against source, with file:line)

### 2.1 The XDP shim is the entry program from the first packet

`Manager.LoadUserspaceShim()` calls `SelectUserspaceXDPShimEntryProgram()`
(`pkg/dataplane/loader.go:129`) and `CompileUserspaceShim()` calls it again
(`:159`) before `attachUserspaceShimXDP(result)` (`:165`). So the
`xdp_userspace_prog` shim (`userspace-xdp/src/lib.rs:336`) is the attached entry
program on the dataplane interfaces from the moment the interface is brought up
on restart. **The first cold SYN after restart is seen by the shim, not by a
passthrough/kernel-only program.** (To be re-confirmed by Gate-B because there is
a `SwapToUserspaceXDPShimEntryProgram` dance in `maps_sync.go` — see §2.4.)

### 2.2 The shim's transit-SYN disposition is gated on four conditions

Walking `try_xdp_userspace` (`userspace-xdp/src/lib.rs:343`) for a transit TCP
SYN to a cold non-local target:

1. **ctrl gate** (`:345`): if `ctrl.enabled == 0` (or metadata mismatch) →
   `degraded_ctrl_disabled_action` (`:867`). For a transit SYN,
   `is_degraded_local_or_control` (`:910`) returns **false** (not early-filter,
   not NDP, not local-dest, not interface-NAT-ESP, not GRE-local), so →
   `drop_degraded_transit` (`:939`) → **`XDP_DROP`**.
2. **ingress-iface gate** (`:365`): if the ingress ifindex is not in
   `USERSPACE_INGRESS_IFACES`, → `cpumap_or_pass` (XDP_PASS / cpumap). (Populated
   by `syncIngressIfaceMapLocked`, `maps_sync.go:782`.)
3. **binding gate** (`:384–408`): index `ifindex*16 + queue`. If the
   `USERSPACE_BINDINGS` Array entry has `flags == 0` (unpopulated), transit →
   `drop_degraded_transit` → **`XDP_DROP`** (`:406`).
4. **binding-ready gate** (`:409`): if `(flags & USERSPACE_BINDING_READY) == 0`,
   transit → **`XDP_DROP`** (`:423`).
5. **heartbeat gate** (`:425–464`): if the `USERSPACE_HEARTBEAT[slot]` Array
   value is 0/missing or stale (older than `heartbeat_timeout_ms`), transit →
   **`XDP_DROP`** (`:440` / `:463`).
6. Only after all gates pass: `bpf_xdp_adjust_meta` + `USERSPACE_XSK_MAP.redirect(
   binding.slot, 0)` (`:635`). A redirect Err on a non-interface-NAT transit
   packet → `drop_degraded_transit` (`:652`) → **`XDP_DROP`**.

**KEY CORRECTION to the issue hypothesis:** the issue body says the first SYN is
`XDP_PASS`'d to the kernel which then drops it (no neighbor/route). The source
shows that for a **transit** SYN during any of the four not-ready windows the
shim returns **`XDP_DROP`**, not `XDP_PASS`. `XDP_PASS`/cpumap only happens for
local/control packets (`pass_local_control`, `:903`) or the ingress-iface-miss
fast path (`:366`). The drop is therefore most likely at the XDP shim, not the
kernel. Gate-B must confirm which.

### 2.3 What the worker thread does (the readiness producers)

`bring_up_workers` (`coordinator/reconcile/bringup.rs:21`):
- For each registered binding it inserts a `BindingLiveState` and spawns a worker
  thread (`:233 spawn_supervised_worker`). `binding.ready=false` is set ONLY for
  unregistered/`ifindex<=0` bindings (`:43`); registered ones get a worker.
- Inside the worker thread, `BindingWorker::create` (`worker/mod.rs:~265+`)
  performs, in order: socket bind → `live.set_bound(user_fd)` (`:328`) →
  `touch_heartbeat(heartbeat_map_fd, slot, &live, init_now)` (`:355`, writes the
  first `USERSPACE_HEARTBEAT[slot]`) → `register_binding_xsk` (`:472`) which calls
  `register_xsk_slot(xsk_map_fd, slot, user_fd)` (`:733`) populating
  `USERSPACE_XSK_MAP[slot]` and `live.set_xsk_registered(true)` (`:746`).
- The neighbor monitor thread is started after workers (`:330–343`); its
  `initial_neighbor_dump` sets `neighbor_generation = 1` on completion
  (`neighbor.rs:516/520`).
- Per-tick the worker refreshes the heartbeat (`loop_body/mod.rs:628`,
  `lifecycle.rs:57 maybe_touch_heartbeat`).

### 2.4 The Go control plane is what flips the XDP-visible gates

`applyHelperStatusLocked` (`maps_sync.go:260`), driven by the **1s status poll
loop** (`process.go:381 time.NewTicker(time.Second)`):

- Computes `ctrl.Enabled`. On a fresh boot, the **first** `status.Enabled` tick
  sets `neighborsPrewarmed=true` and arms a hard-timeout `ctrlEnableAt`
  (3s standalone / 15s HA) (`:311–331`), calls `bootstrapNAPIQueuesAsyncLocked`
  + `proactiveNeighborResolveLocked` (`:329–330`).
- ctrl is enabled (`:388 ctrl.Enabled = 1`) when
  `probeBindingsReady && neighborSyncReady` where
  `probeBindingsReady` = all bindings `Registered && Armed` (`:340–352`) and
  `neighborSyncReady = status.NeighborGeneration > 0` (`:361`). Then an XSK
  **liveness probe** must observe `xskReceiveLive` (RX progress) before
  `xskLivenessProven` (`:396–404`); until proven it stays in a probe state but
  ctrl is already 1 once the gates pass.
- Per-binding `USERSPACE_BINDINGS` flags are written at `:591–627`: `flags =
  userspaceBindingReady` iff `binding.Registered && binding.Armed` (`:596`).
  Note: this does NOT wait for `Bound` (deliberate, `:597–601`, to avoid the
  chicken-and-egg where the shim drops packets so the socket never RXes).
- `SwapToUserspaceXDPShimEntryProgram` (`:392/400/407`) is invoked while
  enabling — but per §2.1 the shim is already the selected entry program from
  load, so this is idempotent on a fresh boot (confirm in Gate-B; if the swap is
  a real transition there may be a brief non-shim window).
- The bindings watchdog `verifyBindingsMapLocked` (`:1053`) repairs zeroed
  binding entries, but only when `m.ctrlWasEnabled` (`:1059`) — i.e. it does not
  help the very first enable.

### 2.5 The candidate drop windows (ordered by likelihood)

Given §2.2–2.4, on the first connect after restart the SYN can be dropped at:

- **W-CTRL**: SYN arrives while `ctrl.enabled == 0` (before the poll loop flips
  it). The gap is bounded by the 1s poll cadence + the readiness gates. This is
  the **prime suspect** — a single 1s poll tick aligns exactly with the ~1.007s
  RTO recovery (the SYN is dropped in tick N; ctrl enables at tick N+1 ~1s later;
  the +1.007s retransmit lands just after and is redirected). → `XDP_DROP` via
  `degraded_ctrl_disabled_action`.
- **W-BIND**: ctrl already enabled but `USERSPACE_BINDINGS[idx].flags == 0` for
  the SYN's (ifindex,queue) — binding not yet written or written for a different
  queue. → `XDP_DROP` (`:406`).
- **W-READY**: binding present but `READY` bit clear. → `XDP_DROP` (`:423`).
- **W-HB**: binding ready but `USERSPACE_HEARTBEAT[slot]` still 0/stale (worker
  hasn't ticked yet, or programBootstrapMaps zeroed it and the worker hasn't
  re-touched). → `XDP_DROP` (`:440`).
- **W-XSK**: all Go-visible gates pass but `USERSPACE_XSK_MAP[slot]` not yet
  populated by `register_xsk_slot` → `redirect` Err → `XDP_DROP` (`:652`). This
  is the window the issue body's hypothesis named. Ordering note: the worker
  writes heartbeat (`:355`) BEFORE registering the XSK slot (`:472`), so W-HB can
  close before W-XSK — meaning a SYN could pass the HB gate and still hit a
  missing XSK slot. **This is a real ordering inversion worth measuring.**
- **W-PASS-KERNEL** (the issue's stated hypothesis): SYN is `XDP_PASS`'d (only
  possible via the ingress-iface-miss path `:366` or if it is misclassified as
  local/control) and the kernel drops it for lack of a cold neighbor/route. Per
  §2.2 this should NOT happen for a correctly-classified transit SYN, but Gate-B
  must rule it out (e.g. a transient ingress-iface map gap).

Gate-B pins which of W-CTRL / W-BIND / W-READY / W-HB / W-XSK / W-PASS-KERNEL the
single dropped SYN falls in. The fix target depends entirely on the answer.

---

## 3. Blast radius

- Symptom impact: one ~1.007s connect stall on the FIRST transit flow after a
  `systemctl restart`/deploy. Steady-state and failover unaffected. Deploy-only.
- Files implicated (read-only so far; any /engineer change is scoped here):
  - `userspace-xdp/src/lib.rs` (the shim gates) — changing gate behavior is
    BPF-verifier-sensitive and changes the fail-closed contract.
  - `pkg/dataplane/userspace/maps_sync.go` (`applyHelperStatusLocked`,
    ordering of ctrl-enable vs binding/heartbeat writes).
  - `userspace-dp/src/afxdp/worker/mod.rs` (worker create ordering:
    heartbeat-then-XSK).
  - `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs` (worker spawn
    ordering vs ctrl-enable signalling).
- HA budget constraint: any readiness change MUST NOT delay forwarding-active
  enough to regress the ~60ms VRRP/failover budget. Gate-R showed failover is
  already fast; a fix must keep it that way (re-verify with `make test-failover`
  at /engineer if the fix touches the enable path).

---

## 4. Success criteria

1. **Gate-B pins the loss point**: ≥7 restart trials with the dropped SYN's
   arrival timestamp correlated against the T-timeline (T_worker-spawn,
   T_XSK-slot-registered, T_binding-flags-READY, T_heartbeat-first-write,
   T_ctrl-enabled, T_first-cold-SYN). The drop is attributed to exactly one
   window with a programmatic counter (the XDP degraded-path stat for the
   matching reason, OR a kernel drop counter), not just inference.
2. A chosen fix (one of §5 paths) that removes the single-SYN drop in ≥7
   restart trials (target: 0/7 slow connects, matching the settled-daemon 0/50
   control), with NO failover regression and NO change to the fail-closed
   transit contract during a genuinely-not-ready window.
   OR
3. A justified PLAN-KILL / accept-the-artifact decision with Gate-B numbers.

---

## 5. Design — multiple paths (decide after Gate-B)

### Path 1 — Tighten the readiness ORDERING so the SYN is redirected, not dropped

**1.A — Make the XSK slot + heartbeat precede the binding-READY flag.**
If Gate-B pins W-XSK (or the W-HB→W-XSK inversion), the fix is to ensure the
worker has populated `USERSPACE_XSK_MAP[slot]` AND written a live heartbeat
BEFORE the Go side writes `flags = READY` for that binding. Today
`applyHelperStatusLocked` sets READY on `Registered && Armed` (`maps_sync.go:596`)
which can be true before the worker's `register_xsk_slot` lands (worker/mod.rs
order is bind→heartbeat→XSK). Option: gate the Go READY write on a helper-reported
`XSKRegistered` flag (add to `BindingStatus`) so READY implies a populated XSK
slot. Cost: one more status field + a one-tick (≤1s) delay to first-READY. Keeps
fail-closed correct (READY now strictly implies redirectable).

**1.B — Enable ctrl only after at least one binding is fully redirectable.**
If Gate-B pins W-CTRL with a binding/XSK gap at enable time, require that the
first ctrl-enable also see ≥1 binding with XSKRegistered+live-heartbeat. This
narrows the W-CTRL→W-XSK race at the cost of a possible extra poll tick.

**1.C — Drive the enable off an event, not the 1s poll.** The 1s poll cadence is
the dominant term in the ~1.007s gap (the RTO recovers right after the next
tick). Trigger an immediate `applyHelperStatusLocked` when the helper signals
"all bindings registered+armed+XSK-registered+heartbeat-live" (a control-socket
push or a short-interval catch-up poll during the bringup window only). This
shrinks the not-ready window from ~1s to ~ms. Must throttle (CLAUDE.md control-
socket contention rule) — only during bringup, not steady-state.

### Path 2 — Make the bringup-window not lossy for the FIRST SYN

**2.A — Buffer-or-pass instead of drop during the genuinely-not-ready window.**
If the drop is unavoidable for a brief window, change the transit disposition
during not-ready from `XDP_DROP` to a non-lossy outcome. Options:
  - `XDP_PASS` to the kernel during not-ready so the kernel forwards it (requires
    the kernel to have a route+neighbor; Gate-B step 4 must confirm the kernel
    CAN resolve the cold target — if not, this just moves the drop). This
    **weakens the fail-closed contract** (transit leaks to kernel during the
    window) and is the issue body's implicit assumption — only viable if Gate-B
    proves the kernel path resolves.
  - Redirect-on-first-success buffering inside the dataplane (`pending_neigh`)
    requires the packet to first reach the worker, which it cannot if the XSK
    slot isn't registered — so this does not help W-XSK / W-CTRL. Only relevant
    if Gate-B shows the SYN DOES reach `poll_descriptor` but is dropped later.
  Path 2 is structurally weaker than Path 1 (it accepts a lossy or
  contract-weakening window) and is the fallback if ordering cannot be fixed.

### Path 3 — Accept the artifact (deploy-only, document, close)

Single ~1.007s connect on the first flow after a `systemctl restart`/deploy,
self-recovering via standard TCP RTO, steady-state and failover unaffected. This
is a deploy-testing artifact, not a production-traffic or failover defect. Honest
option given the low impact; the bar to ship a readiness change to the
fail-closed bringup path (BPF-verifier risk, failover-budget risk) may exceed the
value of removing one deploy-time RTO. Decide against Gate-B numbers + the cost of
the chosen Path-1 variant.

### Rejected up front (with reasons)

- Re-introducing the seq=0 staged-replay (5.A.2 from the archived plan): Gate-R
  refuted H-0 (counter A=0). It would not fix this symptom.
- Generic "warm the neighbor at boot" (#1636 already ships the warmer; Gate-R
  shows the dump is 95–139µs and neighbor gen gates ctrl anyway): the drop is a
  readiness-gate gap, not a cold neighbor.
- Blanket "enable ctrl immediately at boot": would expose transit before
  bindings/SNAT/VIPs are ready (the very reason for the 3s/15s prewarm delay,
  `maps_sync.go:300–310`) — regresses correctness and HA.

---

## 6. Gate-B — the measurement (runs FIRST, on `loss:xpf-userspace-fw0/fw1`)

Throwaway instrumentation, reverted after; verify `strings <bin> | grep
<marker>` = 0 on BOTH nodes; restore cluster healthy. Marker: `BRINGUP-1648`.

**B-1. Instrument the bringup T-timeline (Rust + Go, eprintln/slog with the
marker + CLOCK_MONOTONIC ns):**
- T_worker-spawn (bringup.rs:281 "started worker thread").
- T_heartbeat-first-write (worker/mod.rs:355, after `touch_heartbeat`).
- T_XSK-slot-registered (worker/mod.rs:746, after `set_xsk_registered`).
- T_binding-flags-READY (maps_sync.go:620, when `flags == READY` is first written
  per (ifindex,queue) — log idx+slot+flags).
- T_ctrl-enabled (maps_sync.go:692, ctrl.Enabled=1 commit).
- T_first-cold-SYN-arrives: see B-2.

**B-2. Count first-SYN outcomes at the shim during the bringup window.**
The shim already has degraded-path counters (`USERSPACE_FALLBACK_STATS`,
reasons in `maps_sync.go:707`). Read the per-reason deltas across the restart
window (snapshot before connect, after the dropped SYN, after recovery):
- `ctrl_disabled` (0), `binding_missing` (2), `binding_not_ready` (3),
  `heartbeat_missing` (4), `heartbeat_stale` (5), `redirect_err` (10),
  `transit_drop` (15), `pass_to_kernel` (14).
- Additionally add a throwaway eprintln in the SYN-matching branch that logs
  ingress_ifindex + selected_queue + binding.flags + heartbeat-present +
  XDP-action for TCP-SYN-no-ACK to the iperf3 target IP/port, so the dropped SYN
  is attributable to a specific gate. (Restrict to the target 5-tuple to avoid
  flooding.)

**B-3. Confirm whether the SYN reaches the dataplane at all.**
Add a throwaway counter at the worker `poll_descriptor`/RX path
(`loop_body/mod.rs`) and at `pending_neigh` enqueue, keyed on the target
5-tuple. If the count is 0 for the dropped SYN, the drop is at XDP (W-CTRL/
W-BIND/W-READY/W-HB/W-XSK); if >0, the drop is inside the dataplane (re-targets
the fix away from the readiness gate).

**B-4. Kernel-side check (only if B-2 shows `pass_to_kernel` for the SYN).**
If the SYN was XDP_PASS'd, inspect `nstat`/`/proc/net/snmp` and a host tcpdump
on the egress path: did the kernel forward-then-fail (no neighbor) or drop at
input? This distinguishes W-PASS-KERNEL from the XDP-drop windows and decides
Path 2.A viability (kernel must be able to resolve the cold target).

**B-5. Correlate + pin.** ≥7 restarts, each with `ip neigh flush all` on fw0 +
the LAN client. Client tcpdump captures the SYN-RTO signature; record the SYN's
arrival ts and the T-timeline. **Pin the drop to exactly one window.** State the
per-reason counter that incremented for the dropped SYN.

**B-6. Honesty gate (Gate-R precedent).** If the measurement shows the drop is
NOT in a readiness gap that any §5 path can close (e.g. it is a kernel-side
neighbor miss the dataplane never sees, or it is W-PASS-KERNEL where the kernel
cannot resolve regardless), then **PLAN-KILL the readiness-gate framing** and
recommend Path 3 (accept) or a re-scope, exactly as Gate-R killed the dump-race
framing. A confidently-asserted mechanism that the counters refute must be
abandoned, not rationalized.

**Revert + verify clean:** rebuild both nodes from clean source, redeploy,
confirm `strings | grep BRINGUP-1648` = 0 on both, cluster healthy (a clean
v4+v6 push/-R smoke), before returning.

---

## 7. Test / validation plan (at /engineer, AFTER a path is approved)

- Unit: Go test for the chosen `applyHelperStatusLocked` ordering change
  (table-driven over binding states proving READY is only written when the new
  precondition holds). Rust unit if a worker-ordering change is made.
- Cluster: ≥7 `systemctl restart` trials, target 0/7 slow connects (vs the
  reproduced ~1008–1036ms). Settled-daemon control 0/50 unchanged.
- Failover non-regression: `make test-failover` (clean + crash) must stay
  0-drop; confirm the ~60ms budget unaffected (Gate-R baseline: clean 0/20,
  crash 0/25).
- Full smoke matrix (v4+v6 × push/-R × CoS-off/CoS-on) per the standing smoke
  rules.
- BPF-verifier: if `lib.rs` gate behavior changes, confirm the shim still loads
  (verifier-sensitive; the not-ready drop arms are fail-closed by design).

## 8. Rollout / fail-safe

- The fix must preserve fail-closed: a genuinely not-ready binding (no XSK slot,
  no live heartbeat) must still NOT redirect; the change only removes the
  spurious drop of a SYN that arrives just before readiness completes, by either
  tightening ordering (Path 1) or providing a non-lossy disposition that does not
  weaken the transit contract (Path 2, only if Gate-B blesses it).
- If Path 1.C (event-driven enable) is chosen, the bringup-only fast poll must be
  throttled and disabled once steady-state to respect the control-socket
  contention rule.

## 9. Open questions for the reviewers (Gate-B will answer most)

1. Is the shim genuinely the entry program at the instant of the first SYN, or is
   there a real `SwapToUserspaceXDPShimEntryProgram` transition window where a
   different program (or none) is attached? (§2.1 / §2.4)
2. Which window does the dropped SYN fall in (W-CTRL / W-BIND / W-READY / W-HB /
   W-XSK / W-PASS-KERNEL)? (§2.5)
3. Is the W-HB→W-XSK ordering inversion (heartbeat written before XSK slot) real
   and reachable for the dropped SYN? (§2.3)
4. For Path 1.C, can an event-driven enable shrink the window without violating
   the control-socket contention rule or the 3s/15s prewarm-delay rationale?
5. Cost/benefit: is removing a single deploy-time RTO worth any change to the
   fail-closed bringup path (BPF-verifier + failover-budget risk)? (Path 3)

## 10. Decision record (to be filled at convergence)

- Gate-B pinned window: (pending Gate-B)
- Chosen path: (pending)
- Reviewer verdicts at convergence: (pending)

## 11. Reviewer ledger

See `reviewer-ids.md` for Codex + AGY task-ids per round and Claude SMR doc
paths.
