# #1648 — Dataplane bringup-readiness: first cold connect drops a single SYN (~1s RTO) after `systemctl restart`/deploy

**Status:** v2 — research-only (`/research`, not `/engineer`). Gate-B
(cluster measurement) is the decider and runs FIRST. No production code, no PR.
v2 folds r1: Codex PLAN-NEEDS-REVISION + AGY PLAN-NEEDS-MINOR + Claude SMR
PLAN-NEEDS-MINOR. Three convergent corrections: (a) the XDP shim is `#![no_std]`/
`#![no_main]` — Gate-B CANNOT use eprintln in the shim; it must use the existing
`USERSPACE_TRACE` eBPF map for per-flow attribution; (b) the
`maps_sync.go:597` "chicken-and-egg" comment is REFUTED — `Bound`/`XSKRegistered`
are set inside the worker thread independent of RX, so gating Go's BPF READY on
the helper's already-existing `XSKRegistered`/`Ready` is safe (Path 1.A is "use
existing state," not "add a field"); (c) Path 1.B must require the SELECTED-QUEUE
binding redirectable, not "one binding globally."
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
(`:159`) before `attachUserspaceShimXDP(result)` (`:165`). `AttachXDP`
(`loader.go:462`) attaches `m.XDPEntryProgram()` directly, and the swap method
returns early when the program is already selected (`loader.go:581-582 if
m.XDPEntryProgram() == name { return nil }`). So the `xdp_userspace_prog` shim
(`userspace-xdp/src/lib.rs:336`) is the attached entry program on the dataplane
interfaces once the interface is brought up on restart, and the
`SwapToUserspaceXDPShimEntryProgram` calls in `maps_sync.go:392/400/407` are
**no-ops on a fresh boot** (verified by all three r1 reviewers). Caveat (do NOT
overclaim "from the first packet"): there may be a sub-window between
interface-up and `attachUserspaceShimXDP` where a different program (or none) is
attached and the kernel default applies. **Gate-B Q1 must confirm the attach
timeline; the plan does not assert first-packet coverage without that evidence.**

### 2.2 The shim's transit-SYN disposition is gated on several conditions

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
  The inline comment (`:597–601`) claims this must NOT wait for `Bound` to avoid a
  "chicken-and-egg where the shim drops packets so the socket never RXes."
  **This comment is REFUTED (Codex + AGY r1, verified):** `Bound` and
  `XSKRegistered` are set inside the worker thread during socket
  creation/registration, BEFORE any packet RX — `live.set_bound(user_fd)`
  (`worker/mod.rs:328`, `set_bound` stores `bound=true` immediately at
  `umem/mod.rs:761-764`) and `live.set_xsk_registered(true)`
  (`worker/mod.rs:746`). They are independent of the packet-receiving liveness
  probe (`xskReceiveLive`, `maps_sync.go:372`). The comment conflated `Bound`
  with `xskReceiveLive`. So gating the BPF READY write on the helper-reported
  `XSKRegistered`/`Ready` does NOT deadlock startup — it is the safe fix
  (Path 1.A). Crucially, the helper ALREADY computes and ships the stronger
  state: `refresh_bindings.rs:225-228 ready = registered && bound &&
  xsk_registered && heartbeat_fresh(...)`, and the wire `BindingStatus` carries
  `Ready`, `Bound`, `XSKRegistered` (`protocol.go:1012-1016`). Go simply ignores
  the stronger fields today.
- `SwapToUserspaceXDPShimEntryProgram` (`:392/400/407`) is invoked while
  enabling — per §2.1 the shim is already the selected entry program from load,
  so this is a no-op on a fresh boot (all three r1 reviewers verified via
  `loader.go:581-582`).
- The bindings watchdog `verifyBindingsMapLocked` (`:1053`) repairs zeroed
  binding entries, but only when `m.ctrlWasEnabled` (`:1059`) — i.e. it does not
  help the very first enable.

### 2.5 The candidate drop windows (ordered by likelihood)

Given §2.2–2.4, on the first connect after restart the SYN can be dropped at:

- **W-CTRL**: SYN arrives while `ctrl.enabled == 0` (before the poll loop flips
  it). The gap is bounded by the 1s poll cadence + the readiness gates. A prime
  suspect. **Caution (Claude SMR r1 MINOR-3):** do NOT infer the gap size from
  the ~1.007s RTO. ~1.007s is the *client's* RFC 6298 initial TCP RTO — it would
  be ~1s regardless of whether the actual not-ready gap is 50ms or 950ms, as long
  as the gap < 1s and the binding is ready by the retransmit. The RTO is the
  *recovery* clock, not the *gap* clock. Gate-B must MEASURE the actual gap
  (T_ctrl-enabled − T_first-cold-SYN, or T_XSK-registered − T_SYN), not assume it
  equals the poll cadence. This matters for path selection: Path 1.C
  (event-driven enable) only helps if the gap is poll-dominated; if the gap is
  the worker's XSK-bind latency, the poll cadence is irrelevant. → `XDP_DROP` via
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

**1.A — Gate the Go BPF READY write on the helper's existing `XSKRegistered`
(FAVORED, if Gate-B pins W-XSK / the W-HB→W-XSK inversion).**
The helper ALREADY ships `XSKRegistered` and a strong `Ready` (= registered &&
bound && xsk_registered && heartbeat_fresh) in the wire `BindingStatus`
(`protocol.go:1012-1016`, computed at `refresh_bindings.rs:225-228`). Go ignores
them and writes `flags = READY` on only `Registered && Armed`
(`maps_sync.go:596`). The fix is to change that condition to also require
`binding.XSKRegistered` (or use `binding.Ready` directly). Because §2.4 refutes
the chicken-and-egg comment, this does NOT deadlock startup — `XSKRegistered`
becomes true inside the worker before any RX. After the change, `flags & READY`
strictly implies a populated `USERSPACE_XSK_MAP[slot]`, so the shim's
binding-ready gate (`lib.rs:409`) can never pass while the XSK slot is empty →
the W-XSK redirect-Err drop is eliminated. **No new status field needed** (Codex
r1). Cost: at most a one-poll-tick (≤1s) delay to first-READY — addressed by
Path 1.C if Gate-B shows the gap is poll-dominated. Update the now-wrong inline
comment at `maps_sync.go:597`.
**Scope (Claude SMR r2):** the change must cover BOTH READY-write sites — the
primary binding (`maps_sync.go:596`, currently `Registered && Armed`) AND the
VLAN-alias-child binding (`maps_sync.go:634`, currently `Registered && Armed &&
Bound`). Note `Bound` is set at `worker/mod.rs:328` BEFORE `set_xsk_registered`
at `:746`, so the alias path carries the SAME W-XSK inversion and needs
`XSKRegistered` too. The repair-only bindings watchdog (`verifyBindingsMapLocked`,
`maps_sync.go:1101`, also `Registered && Armed`) runs only post-first-enable
(`m.ctrlWasEnabled` gate `:1059`) so it does not affect the first-SYN window, but
should get the same condition for consistency at /engineer time.

**1.B — Enable ctrl / write READY only after the SELECTED-QUEUE binding for the
ingress surface is redirectable (not "one binding globally").**
The shim indexes the EXACT binding for the packet's queue:
`binding_idx = ingress_ifindex * BINDING_QUEUES_PER_IFACE + selected_queue`
(`lib.rs:383`), `selected_queue = rx_queue_index % queue_count`
(`select_userspace_queue`, `lib.rs:1308-1330`). So "≥1 binding ready" is
insufficient — the SYN's specific queue binding must be redirectable. If Gate-B
pins W-CTRL with a per-queue gap, the ctrl-enable / per-binding-READY logic must
require every eligible ingress-surface binding (or at minimum the selected queue)
to be XSKRegistered+heartbeat-live, per Codex r1. (In practice 1.A already does
this per-binding, since READY is written per (ifindex,queue); 1.B is the
ctrl-enable analogue.)

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
    proves the kernel path resolves. **Additional caveat (Claude SMR r1):** even
    if the kernel CAN forward, doing so during the W-CTRL window forwards transit
    WITHOUT SNAT (the documented reason for the 3s/15s prewarm delay,
    `maps_sync.go:300-310`) → return traffic blackholes. So Path 2.A is strictly
    MORE dangerous for W-CTRL than a plain drop; reject it for that window. AGY r1
    independently flagged Path 2.A as compromising the firewall's core security
    boundary.
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

**CONSTRAINT (Codex r1):** the XDP shim is `#![no_std]`/`#![no_main]`
(`lib.rs:1-2`). **No `eprintln!`/`println!`/`slog` is possible inside the shim.**
All shim-side instrumentation MUST be eBPF-safe (BPF map writes via the existing
counter/trace maps, or `bpf_printk`/trace_pipe). Go-side timeline logging can use
`slog`. The original v1 "throwaway eprintln in the SYN-matching branch" is
withdrawn.

**B-1. Instrument the bringup T-timeline (Go via slog; Rust helper threads via
eprintln to journald; CLOCK_MONOTONIC ns, marker `BRINGUP-1648`):**
- T_worker-spawn (bringup.rs:281 "started worker thread" — Rust helper thread,
  eprintln OK; this is NOT the shim).
- T_heartbeat-first-write (worker/mod.rs:355, after `touch_heartbeat` — Rust
  helper thread, eprintln OK).
- T_XSK-slot-registered (worker/mod.rs:742-746, after `set_xsk_registered` —
  there is already an eprintln "registered slot=… in XSKMAP" at `:742`; add the
  ns timestamp).
- T_binding-flags-READY (maps_sync.go:620, when `flags == READY` is first written
  per (ifindex,queue) — slog idx+slot+flags).
- T_ctrl-enabled (maps_sync.go:692, ctrl.Enabled=1 commit — slog).
- T_first-cold-SYN-arrives: see B-2.

**B-2. Attribute the dropped SYN to one shim exit using the existing
`USERSPACE_TRACE` eBPF map (PRIMARY attribution; eBPF-safe).**
The shim already records a per-flow trace entry on every gate exit via
`record_trace(...)` into `USERSPACE_TRACE` (`lib.rs:329-330,959-1004`), keyed on
an avalanche hash of (ingress_ifindex, protocol, src_port, dst_port) and carrying
`stage`, `reason`, `selected_queue`, `slot`, `vlan_id`, and the full 5-tuple.
Enable it by setting `USERSPACE_CTRL_FLAG_TRACE` (bit 2) in `userspace_ctrl.flags`
during the experiment (Go can set this in `applyHelperStatusLocked`/bootstrap, or
a throwaway one-shot map write). Note: `binding_missing` and `early_filter` traces
are FORCED regardless of the trace flag (`record_trace` `:969-972`), and ICMP is
skipped (`:976`), so a TCP SYN is captured. After the restart + the dropped-SYN
connect, dump `USERSPACE_TRACE` from Go (a throwaway readback over the pinned map
`UserspaceTracePinPath`) and find the entry matching the iperf3 data-SYN 5-tuple
(src=client:ephemeral, dst=172.16.80.200:5201). Its `stage`/`reason` field is the
DEFINITIVE window pin: `BINDING_MISSING`(2)→W-BIND, `BINDING_NOT_READY`(3)→W-READY,
`HEARTBEAT_MISSING`(4)/`HEARTBEAT_STALE`(5)→W-HB, `REDIRECT_ERR`(11)→W-XSK,
`REDIRECT_ERR`(11)→W-XSK. **W-CTRL is NOT pinnable via the trace map** — when
`ctrl.enabled==0` the shim takes the early return at `lib.rs:345-347` into
`degraded_ctrl_disabled_action` (`:867`), which does NOT call `record_trace` (and
the trace flag lives in `ctrl.flags`, moot while disabled). So W-CTRL leaves NO
trace entry. W-CTRL is instead pinned by the **B-1 timeline**: the data-SYN
tcpdump arrival ts falls BEFORE T_ctrl-enabled (`maps_sync.go:692`), corroborated
by a non-zero `ctrl_disabled`(reason 0) cumulative-counter delta across the
window. Thus the attribution decision tree is: trace entry present → its stage
gives W-BIND/W-READY/W-HB/W-XSK; trace entry ABSENT + SYN arrived before
T_ctrl-enabled → W-CTRL; trace entry ABSENT + SYN arrived after T_ctrl-enabled +
ingress-iface-miss counter incremented → W-PASS-KERNEL (see B-4).
**Caveat (Claude SMR r1 MINOR-1/2):** the trace map is
keyed by a 4-field hash and is last-writer-wins per key, so confirm no other live
flow collides on the same hash during the window (the iperf3 control SYN on a
different port hashes differently; verify the dumped entry's stored 5-tuple
matches the data SYN exactly). The cumulative `USERSPACE_FALLBACK_STATS`
per-reason deltas (`maps_sync.go:707`) are CORROBORATING only — they are shared
across all packets (VRRP/ARP/control) and cannot by themselves attribute the data
SYN.

**B-3. Confirm whether the SYN reaches the dataplane at all (eBPF-safe / helper).**
The worker RX/`pending_neigh` path is in the Rust HELPER (not the shim), so an
eprintln keyed on the target 5-tuple IS viable there
(`worker/loop_body/mod.rs`). Add a throwaway helper-side log at the RX descriptor
ingest and at `pending_neigh` enqueue for the target 5-tuple. If neither fires for
the dropped SYN, the drop is at the shim (W-CTRL/W-BIND/W-READY/W-HB/W-XSK,
corroborated by B-2's trace stage); if the RX log fires but `pending_neigh`
doesn't (or it does and the packet is dropped later), the drop is INSIDE the
dataplane → re-target the fix away from the readiness gate.

**B-4. Kernel-side check (only if B-2's trace shows the SYN took a PASS path).**
If the trace stage is a local/control PASS or the SYN hit the ingress-iface-miss
fast path (`lib.rs:364-366`, which returns `cpumap_or_pass` with NO trace/counter
— so a SYN that vanishes with NO trace entry implicates this path), inspect
`nstat`/`/proc/net/snmp` + a host tcpdump on the egress path: did the kernel
forward-then-fail (no neighbor) or drop at input? This distinguishes
W-PASS-KERNEL from the XDP-drop windows and decides Path 2.A viability. NOTE
(Codex r1): the ingress-iface-miss pass path has no counter; a SYN that is
PASS'd there leaves NO trace entry — so "no trace entry for the data SYN AND the
shim was the entry program" is itself the signature of W-PASS-KERNEL via the
ingress-iface gate. A throwaway counter at `lib.rs:366` (eBPF map increment, NOT
eprintln) closes this gap if the no-trace case appears.

**B-5. Correlate + pin + MEASURE THE GAP.** ≥7 restarts, each with `ip neigh
flush all` on fw0 + the LAN client. Client tcpdump captures the SYN-RTO signature;
record the SYN's arrival ts and the full T-timeline. **Pin the drop to exactly one
window** via B-2's trace stage for the data-SYN 5-tuple. **Also record the actual
not-ready gap** (T of the matching readiness producer − T_first-cold-SYN, e.g.
T_XSK-registered − T_SYN for W-XSK, or T_ctrl-enabled − T_SYN for W-CTRL) — do NOT
infer it from the ~1.007s RTO (SMR MINOR-3). The gap magnitude decides whether
Path 1.C (event-driven enable) is needed (gap poll-dominated, ~hundreds of ms) or
whether Path 1.A alone suffices (gap is the worker XSK-bind latency, ~ms).

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
