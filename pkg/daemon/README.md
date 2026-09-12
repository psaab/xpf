# pkg/daemon

Daemon lifecycle and orchestration. Loads the configured dataplane backend,
applies compiled config to all subsystems (routing, NAT, DHCP, cluster, ...),
handles signals
(SIGHUP reload, SIGTERM shutdown), and wires the commit-atomicity
semaphore (#846) so `Store.Commit()` and `applyConfig()` always run
together.

This is the package `cmd/xpfd` instantiates. It depends on essentially
every other internal package.

The daemon stores dataplane backends behind `dataplane.RuntimeDataPlane` and
uses the split config, HA/fabric, sessions, telemetry, and link-cycle domains.
The runtime dataplane is published through ONE synchronized point (#2114):
`Daemon.dpCell` (`atomic.Pointer[dpSlot]`) with the `dataplane()` /
`setDataplane()` accessor pair — the `natPoolAlarm` (#2116) idiom. Every
in-package ACQUISITION of the handle goes through the accessors; a
`pkg/daemon` AST canary (`daemon_dp_canary_test.go`) fails the build on a
direct `.dpCell` reference outside them. Readers that nil-check AND use
the value load ONCE into a local (the plan's §5.3 snapshot boundaries: one
load per sampler/watchdog tick, per event/request callback, or per
straight-line block — never per-element). `setDataplane`'s kind-gated
guard keeps a non-nil interface wrapping a nil value (any nillable kind)
out of the cell.

**Publication is not lifetime.** The cell answers "what is published
now?"; it does not bound how long a handle someone already took stays
usable. Two consequences the code makes explicit:

- **Escaping consumers.** Six things outlive a single call. The three
  OPERATOR-FACING management servers — gRPC, REST, and the console CLI —
  do NOT receive the backend handle: they receive `liveDataPlane`
  (`daemon_dp_live.go`), a daemon-owned indirection that re-reads the cell
  on every method, so a later `setDataplane(nil)` is immediately visible
  to them. TWO of the three DATA-PATH consumers are deliberate
  capture-once wiring, and are documented as such rather than claimed
  converted: conntrack GC and cluster `SessionSync` take the DECOMPOSED
  `dataplane.SessionStore` / `dataplane.Telemetry` domains (a live
  indirection would put an atomic load + interface assertion +
  `SessionStoreOf` allocation on every per-session step). The THIRD — the
  userspace event-stream loop — is NOT capture-once: it re-resolves the
  provider, the stream instance AND the session-delta drainer from the
  cell on every poll tick (#6743 r6-F4 for the first two — it used to
  capture a provider at Phase 5 from the constructed-but-unarmed bootstrap
  backend and keep polling it after an arm failure cleared the cell; r7-F1
  for the drainer, which stayed captured at loop entry and kept draining a
  disowned backend at 10 Hz on the fast fallback branch) and re-installs
  its callbacks when a rollback + corrected re-arm replaces the stream
  instance. #7017: that last clause was true of the CLUSTERED loop only.
  `runUserspaceEventStream`'s standalone (no-cluster) arm called
  `wireUserspaceEventStreamCallbacks` and RETURNED with it, so it never ran
  the `es != wired` re-install and a replacement stream on a standalone
  daemon got no callbacks at all — its dataplane events accumulated in the
  callback-not-ready queue, and RT_FLOW records stopped reaching `show
  log`, syslog and the flow exporter until the daemon restarted. That arm
  now runs `watchUserspaceEventStreamCallbacks`: the same 500 ms cadence
  and the same first-wire behaviour, but it never returns and applies the
  same instance-identity re-install every tick. It is registered on the run
  WaitGroup, and `runShutdownSequence` calls `stop()` before `wg.Wait()`,
  so it joins within one tick of shutdown.
  `handleEventStreamFullResync` likewise resolves its session
  exporter from the cell on every call, so a full resync after a rollback
  + corrected re-arm exports from the CURRENT backend rather than the
  torn-down one (#6743 r2-B8, bound by
  `full_resync_per_call_6743_test.go`). Its export and queueing are one
  transaction (#9766, #9767): the frame is acknowledged only when every
  install reached the send queue, the fallback loop's drain is held off
  meanwhile, and a failed attempt backs off before it exports again (see
  `docs/session-sync-architecture.md`, "Bulk Owner-RG Export").
  Behavioural guards live in
  `daemon_dp_escape_test.go` (gRPC) and `daemon_dp_escape_rest_test.go`
  (REST); `daemon_ha_userspace_stream_live_test.go` drives the event-stream
  loop across a `setDataplane(nil)`, across a stream replacement, and —
  on the reconcile-cadence branch, which needs its own connected-stream
  fixture — across a backend republication (#6743 r2-B3);
  `daemon_standalone_stream_rewire_7017_test.go` is the standalone twin of
  the stream-replacement case plus the shutdown join.

  The console-CLI site has TWO halves, and neither covers it alone
  (corrected in #6743 r2 — an earlier revision of this paragraph said the
  canary "covers" the site, which was falsified by two compiled escapes
  that left the whole package green):
  - `daemon_dp_escape_canary_test.go` is the SYNTACTIC fence. It asserts
    that no production function sources a management-probe value from
    anywhere other than an in-place `liveDataplane()` call — keyed on the
    POSITION of a type assertion and on DATA FLOW, not on a declaration
    form or on the presence of the name, both of which were escapable.
    Its stated limit is in the file header and is real: the AST cannot
    establish temporal containment in general, so a wiring that crosses a
    function boundary is outside it.
  - `TestConsoleCLIProbeWiringFollowsTheCell` is the BEHAVIOURAL half: it
    drives the site's exact wiring through the `cliDataPlane` interface
    across a publication and a disown. The site itself is inside
    `if isInteractive()`, so no unit test can execute the real block —
    which is why the structural half exists at all.
- **The indirection must not ERASE capabilities.** Go computes a method
  set statically, so `liveDataPlane`'s is exactly its declared forwarders:
  the MANDATORY management surface and nothing else. Consumers reach
  OPTIONAL capabilities by asserting on `any` — `LastApplyResult`,
  `Sessions`, `Telemetry`, `Status`, `AppliedNATView`, the session cursor,
  the userspace controls — and every one of those assertions fails against
  the adapter, silently, on a HEALTHY deployment (#6743 r6-F1: NAT-pool
  and userspace Prometheus families stop being emitted, NAT statistics
  report healthy zeros, session paging falls back to the O(N^2) path).
  Every such probe therefore resolves through `dataplane.Unwrap` first —
  `dpProbe()` in `pkg/grpcapi`, `pkg/api` and `pkg/cli`, and the
  `dataplane.LastApplyResultOf` / `SessionStoreOf` / `TelemetryOf` helper
  family. `Unwrap` is NOT a way to keep a backend: it performs the same
  per-call cell load and returns nil once the daemon has disowned one, so
  a probe after `setDataplane(nil)` still fails closed.
  `daemon_dp_capability_2114_test.go` binds preservation and
  unreachability in separate bodies; `daemon_dp_probe_canary_test.go` is
  the fence against a new probe asserting on the raw `dp` field.
- **Resolve ONCE per operation.** `GetPersistentNAT()` returns a pointer,
  and each call is its own cell load; a `check == nil` followed by a
  second call to `.Len()`/`.Clear()`/`.All()` nil-dereferences if the
  daemon disowns the backend in between (#6743 r6-F2). Every caller binds
  the result to a local; `TestPersistentNATResolvedOncePerOperation`
  fences the shape across `pkg/grpcapi`, `pkg/api`, `pkg/cli` and
  `pkg/natshow`.
- **`dp != nil` no longer means "a dataplane exists".** The servers hold a
  permanently non-nil adapter, so a render keyed on the field describes a
  backend that may not be there — `show system buffers` answered "No BPF
  maps available" (a claim about a loaded backend's maps) for a daemon
  whose startup arm failed. Those sites bind `backend :=
  dataplane.Unwrap(dp)` to a local and make BOTH the publication decision
  (`backend == nil`) and every capability assertion against that ONE value
  (#6743 r6-F3, single-resolution form since r7 — an earlier revision of
  this line said they ask `dataplane.Published(dp)`, which was never true
  of the merged code; that predicate resolved the cell a second time and
  was deleted in r2-B6). For the same reason a clear that RACES the
  disown fails inside the forwarder with `dataplane.ErrNotPublished`;
  `pkg/grpcapi` maps it to `codes.Unavailable`, matching what its
  `dp == nil || !IsLoaded()` pre-check returns for the identical
  operator-visible condition, instead of reporting daemon lifecycle state
  as `codes.Internal`.
- **A torn-down backend can still be published.** The commit-confirmed
  rollback calls `Teardown()` and deliberately LEAVES the object in the
  cell so a corrected commit re-arms that same object
  (`TestDataplaneCell_RollbackRearmRecurrence` pins this). Between the
  teardown and the re-arm, a management call resolves to a detached
  backend and the `pkg/dataplane` retained-unarmed registry state proceeds
  exactly as it did pre-#2114. Closing that window needs a
  generation/lease on the backend itself and is tracked as **#6741**.
Legacy `dataplane.DataPlane` access is isolated behind `legacyDP()` for
callers that still need legacy eBPF compatibility while their domain adapters
are completed (DPDK retired #1525). Userspace currently reaches those old callers through
`userspace.LegacyDataPlaneAdapter`; the userspace `Manager` remains a
runtime-domain type, and the adapter is only the transition boundary for
status, CLI, and cluster-sync paths that still call `legacyDP()`.

Dataplane construction in `daemon_run.go` goes through
`buildRuntimeDataPlane()`: omitted `system dataplane-type` and explicit
`userspace` select `userspace.Boot()` directly, while explicit `ebpf` still
falls through `dataplane.NewRuntimeDataPlane()` so the legacy rollback path
and retired-DPDK sentinel handling stay unchanged.

Config apply uses the runtime `ConfigSink.ApplyConfig` path. This is required
for userspace AF_XDP, which is intentionally not exposed as a legacy
`DataPlane`; apply-time callers must not reintroduce `legacyDP().Compile` as
the primary compile/apply gate.

## Entry points

- `Daemon` — `daemon.go`.
- `Options` — `daemon.go`. `ConfigPath`, `NoDataplane`, `APIAddr`,
  `GRPCAddr`, `Version`.
- `New(opts Options) (*Daemon, error)` — `daemon.go`. Fails when the
  config store cannot be constructed (#1893 fail-closed: unusable
  `.configdb` means no boot, not a delayed nil-deref panic).
- `CompileHealth` — `daemon.go`. Snapshot of the most recent compile
  outcome; `pkg/api` consumes it for the `/health` endpoint.

### `commit confirmed` rollback-target pre-flight (#6707)

`commit confirmed` arms a timer that, on expiry, reverts the store to the
previously-active config and re-applies it. That re-apply is **unconditional
by design** (#1956 OQ-15.2, `daemon_apply_commit.go`): `PromoteRollback` has
already reverted the STORE, so aborting the dataplane apply at that point
would leave store and dataplane disagreeing — a split-brain strictly worse
than applying the target. The consequence is that every property the rollback
depends on has to be decided at ARM time, which is what the pre-flight closure
in `commitConfirmedAndApply` is for. It already validated the rollback target
for device-map safety (#1956 R-8/V-3), cluster topology (#5840) and cluster
identity (#6192).

`rollbackTargetAppliablePreflight` (`rollback_target_appliable_6707.go`) adds
the missing property: the target must be **appliable at all**. The predicate is
`dpuserspace.PolicyContentRejectionReasons`, the Go single source of truth for
"the helper refuses this WHOLE policy snapshot", which `show security
match-policies` also gates on. #6707 first keyed on
`config.LenientDroppedPolicyLocator` alone: the #5575 poison, where a tolerant
compile dropped a match / `then permit` constraint and the lowering stamped the
`__unsupported__` sentinel. That was one refusal class of several, so every
other class still armed a rollback that reverts the store but not forwarding:
- an undefined or unrepresentable address or application (#3261), including
  #9524's mixed address forms and #9525's changed application matches;
- an unresolvable zone (#9410);
- a zone-pair stanza naming `junos-global` (#9570);
- a duplicate rule identity (#9584).

Since #9588 the gate asks the mirror, so a class added there reaches `commit
confirmed` with no edit here, and the two lists cannot drift. It is still a
local prediction: no round trip, and no dependence on helper liveness at arm
time.

The call passes the daemon's LIVE feed overlay for the rollback target
(`d.feedSnapshotsForConfig(rollbackTarget)`), the same source the apply path
hands the manager (`SetFeedSnapshots`). Address representability is
feed-aware. With a nil overlay, a declared `dynamic-address` binding reads as
unrepresentable, so a nil there would refuse `commit confirmed` on every box
that uses feeds. One consequence is deliberate: while a referenced binding has
a feed with no installed snapshot yet, `SnapshotForBindings` omits it and the
mirror fails it closed (#5645). The helper would refuse that snapshot now, so
`commit confirmed` is refused until the feed is ready. A plain `commit` is
unaffected.

Without the gate the #6707 sequence is: boot from a persisted config A whose
policy hits the poison (a lenient boot load, or a peer-sync `SyncApply` — a
strict commit rejects it outright, so the target can only be poisoned by a
route that does not strict-compile), correct it in candidate B, `commit
confirmed` B, then lose contact. At timeout the store reverts to A, the
dataplane refuses A's snapshot — **logged only** — and forwarding stays on the
UNCONFIRMED B while the store and the tail subsystems say A, with the rollback
announced as successful. The recovery mechanism has failed to recover, which is
the #1960 no-brick concern in its concrete form.

The refusal is deliberately narrow, and only the CONFIRMED variant is gated. A
plain `commit` of B is untouched and remains the way forward — it makes B
permanent, which is what an operator correcting a broken active config wants.
Gating the plain path would remove the only route OFF a poisoned active config.
A nil rollback target (the first commit on a fresh store) is also unaffected:
that timeout path reverts to bootstrap mode (#1922 Item 1b) rather than to a
compiled config, so there is nothing to validate.

Regression coverage: `rollback_target_appliable_6707_test.go` (gate behaviour
plus an AST wiring guard that the call is reached from `commitConfirmedAndApply`
and absent from the plain-commit entry points),
`rollback_target_mirror_9588_test.go` (one tolerant-compiled row per refusal
class, each first confirmed to be a strict reject; a feed-backed target that
arms with the live overlay and is refused without it; the unready-feed refusal;
and an AST guard that the call passes `feedSnapshotsForConfig` for the same
target) and `pkg/config/lenient_dropped_locator_6707_test.go` (both policy
shapes, compiled by the real tolerant compiler rather than asserted into a
struct literal).

Not covered: a window that `Store.Load` re-arms at boot (#4577) is not
re-checked against the running binary's refusal classes. The commit was
accepted before the restart, and refusing to re-arm would make an unconfirmed
commit permanent, so that path needs a decision rather than this gate.

### A recovered commit-confirmed target is pre-flighted too (#9615)

The #6707/#9588 pre-flight above runs when `commit confirmed` ARMS a window in
this process. `Store.Load` also re-arms a window that was still live at restart
(#4577), and that path never ran the pre-flight. The timeout then applied the
target unconditionally, citing "validated at commit-confirmed time". For a
recovered window that premise is false in two ways:
- the box may have upgraded inside the window, and the new build's refusal
  classes can cover the old config;
- a target that binds a dynamic-address feed has no installed snapshot right
  after a restart.

Refusing to re-arm would make the unconfirmed commit permanent, so the window
always stays armed and the check runs twice:

- **At boot** (`checkRecoveredConfirmTarget`, startup phase
  `recovered-confirm-preflight`, after manager-init so the feed manager
  exists). If the recovered target fails the pre-flight, the daemon logs an
  error naming the reasons and the deadline. It records the same text as a
  journal entry (`confirm_rollback_target_refused`) and as the local CLI's
  pending-window `[ALARM: …]` line (`Store.ConfirmAlarm`), so the operator can
  confirm or re-commit before the timer fires. The remote CLI's pending flag
  does not carry the text.
- **When the timer fires** (`confirmRollbackTargetHandledAtFire`, called from
  `executeConfirmedRollback` BEFORE `PromoteRollback`, so nothing is promoted
  yet):
  - A target refused only because a feed has no snapshot (the refusal
    disappears once every binding resolves) is deferred: `Store.DeferConfirmTimer`
    re-arms the same generation for 5 s, at most 24 times.
  - Any other refusal, or a feed still unready at the cap, promotes the store to
    the target (persisted as committed, as #6538 does for a recovered target
    that no longer compiles). The daemon then enters the bootstrap/lifeline safe
    state instead of applying a target the dataplane refuses.
  - An appliable target rolls back and applies exactly as before.

### The recovered commit-confirmed rollback fires against a HALF-BUILT daemon (#6739)

`Store.Load` restores a still-live `commit confirmed` window by re-arming
`time.AfterFunc(time.Until(deadline))` (#4577). That happens in startup **phase
1** (`loadAndBootstrapConfig`), and `d.store.SetRollbackExecutor(
d.executeConfirmedRollback)` is registered before the phase list even starts —
while every manager `initManagers` builds (`d.routing`, `d.frr`, `d.networkd`,
`d.ipsec`, `d.ra`, `d.cluster`, `d.vrrpMgr`, the dataplane) is not constructed
until **phase 3**. Nothing holds `applySem` across the phases, so the timer
goroutine and the startup phases run concurrently.

The remaining duration is strictly positive — an already-expired window is
rolled back *synchronously* in an earlier branch of
`recoverPendingConfirmLocked` and never reaches the re-arm — but it is bounded
below only by how close the boot is to the deadline. A box that reboots shortly
before its deadline (`commit confirmed 1` plus a ~55 s boot) arms a timer with
seconds on it, against startup phases doing netlink and manager construction.
**So the whole rollback transaction can run with every manager nil.**

Both branches of `executeConfirmedRollback` are reachable in that window:

- `prevCfg != nil` — the full `applyConfigLocked` pipeline re-applies the
  rollback target. `applyTailReconciles` step 8 is the site that was NOT
  nil-guarded: it dereferenced `d.vrrpMgr` and **panicked the daemon at boot**.
  It now fails CLOSED, matching the gate one branch below it — reporting a
  successful apply while the manager does not hold the requested instance set
  claims HA coverage that is not running, and a nil manager holds no instance
  set at all.
- `prevCfg == nil` — the #1922 Item 1b first-commit branch runs
  `enterBootstrapMode` + `reconcileManagementAfterPromotion` instead of an
  apply. Its teardown steps are individually nil-guarded
  (`relinquishClusterForBootstrap` on `d.cluster`, the FRR and dataplane steps
  on theirs).

**Coverage is at the DISPATCH, not just at the guarded function.** The cell that
enters `applyTailReconciles` directly binds the guard but cannot see an
unguarded dereference in any of the ~10 reconcile helpers *ahead* of the tail —
that would panic the daemon at boot while the direct-entry cell stayed green.
`recovered_rollback_dispatch_6739_test.go` therefore drives the real dispatch
(the store's own timer-expiry logic → the registered executor → an **unstubbed**
apply body) against a daemon in the exact pre-manager shape, over both branches,
with a rollback target that declares a chassis cluster and RETH members so the
cluster/VRRP/fabric reconciles actually run. It asserts the apply REACHED the
guarded site rather than surviving by returning early, and a fixture assertion
fails if the config ever stops compiling to that cluster shape — an
empty-config apply survives for reasons that have nothing to do with the guard
and would report a clean census anyway.

The pre-existing rollback cells in `bootstrap_rollback_test.go` drive the same
dispatch but set `applyBodyForTest`, which returns from `applyConfigLocked`
before any reconcile helper runs. That seam is why this panic survived to be
found by reading rather than by the suite.

This is deliberately **not** work item G's startup-readiness gate. G releases
recovery at end-of-phase-5, and #7675 (which carries G + H + H2, and their
unresolved 2-of-3 reviewer split) records that landing G without H converts this
short pre-manager window into a post-manager bootstrap-with-live-cluster hybrid.
Guarding the dereference and binding the dispatch move **no dispatch point**.

### Config-apply file layout (#5661)

The config-apply path was carved out of the former ~3095-line
`daemon_apply.go` monolith into responsibility-scoped siblings (pure code
motion, no behavior/ordering/locking change — apply step and side-effect
sequence are load-bearing and unchanged). `daemon_apply.go` now retains
only the apply entrypoints and core orchestrator:

- `daemon_apply.go` — apply entrypoints (`applyConfig`,
  `applyConfigResult`, `applyCancelCtx`), the core `applyConfigLocked`
  orchestrator, the procfs knob helpers (`setRethIPv6Knobs`,
  `setVLANSubAddrGenMode`), and `compileErrorMustAbortApply`.
- `daemon_apply_commit.go` — commit/sync/rollback drivers
  (`commitAndApply`, `syncAndApply`, `commitConfirmedAndApply`,
  `executeConfirmedRollback`, peer config push) plus first-boot
  `bootstrapFromFile`.
- `daemon_apply_reset.go` — factory-reset (zeroize) generation guard and
  `factoryReset` (#5281).
- `daemon_apply_hostauth.go` — host-authorization closeout owners and
  their bounded runner (#5874).
- `daemon_apply_dataplane.go` — dataplane/HA core apply
  (`applyDataplaneAndHACore`) and deferred-worker-arm bookkeeping.
- `daemon_apply_routing.go` — services (ip-monitoring), routing-rule, and
  route-leak snapshot reconcile.
- `daemon_apply_interfaces.go` — fabric IPVLAN, VRF, management-VRF
  rebind, and interface reconcile.
- `daemon_apply_tail.go` — the `applyTailReconciles` orchestrator and its
  LLDP / DHCP-relay / event-engine / initial policy-scheduler reconcile
  helpers.
### `daemon_run.go` file layout (#5661)

`Run` and its startup/shutdown machinery were split out of a single
~2820-LOC `daemon_run.go` into cohesive sibling files in `package daemon`
— pure code motion, no rename/reorder/logic change, so the load-bearing
startup-phase and shutdown ordering is untouched:

- `daemon_run.go` — the core lifecycle: `buildRuntimeDataPlane`, `Run`,
  and the startup-phase orchestration (`startupSignalContext`,
  `startupPhase`, `runStartupPhases`, `runStartupOrAbort`,
  `startReconcileRGStateLoop`). `buildRuntimeDataPlane` **must stay here**:
  the retirement-boundary canary
  (`TestDaemonRuntimeEntryPointUsesRuntimeDataPlane`,
  `pkg/dataplane/retirement_boundary_canary_test.go`) parses this file and
  requires a `dataplane.NewRuntimeDataPlane` call in it.
- `daemon_run_bringup.go` — startup bring-up phases: `initManagers`,
  `loadAndBootstrapConfig`, `setupDataplaneAndInitialConfig`,
  `enableForwarding`.
- `daemon_run_naming.go` — startup interface naming/enumeration:
  `setupInterfaceNaming`, `namingParamsFromConfig`,
  `applyStartupNamingForConfig`, `maybeReapplyConfigArrivalNaming`,
  `runBootstrapExitStartup`.
- `daemon_run_servers.go` — API-surface bring-up and the #5054/#5961
  per-transport commit-wiring seams: the six `*CommitFn`/`*CommitConfirmedFn`
  methods, `startGRPCServer`, `startHTTPServer`, `resolveAPIBinds`.
- `daemon_run_shutdown.go` — ordered teardown: `applyCloseoutDrainTimeout`,
  `runShutdownSequence`, `runHAShutdownUpdate`.

  **The fail-closed actions run FIRST (#9035).** `TimeoutStopSec=20`, and
  systemd SIGKILLs there wherever the teardown has got to. Exactly THREE actions
  must have completed by then, because only they are fail-closed — everything
  else is best-effort cleanup whose loss costs telemetry, not correctness:

  1. **kernel transit closed** (#9686), on the non-hitless (fail-closed) stop
     only: `markDataplaneNotArmed` installs the #7191 barrier and writes
     `ip_forward` and `conf.all.forwarding` to 0, before `Teardown` detaches
     every XDP program. Without it the "fail-closed" stop ended with the kernel
     routing any transit that still reached the node (surviving interface
     addresses, static/BGP or link-local next hops) with no policy, session or
     NAT, for the whole downtime. It keys on `hitless` alone, not on a
     published runtime, and nothing on the way out re-opens it. A hitless stop
     keeps the dataplane attached with the shim dropping transit, so it leaves
     forwarding as it was;
  2. **`rg_active` cleared**, so this node stops forwarding; and
  3. **the Kea units stopped** (#6787), so it stops answering DHCP.

  Miss either and the peer promotes onto a segment this node is still serving:
  duplicate OFFERs from two lease databases with neither aware of the other.

  Both now run immediately after `stop(); wg.Wait()`, ahead of every teardown
  that can block. They used to sit ~90 lines lower, after the telemetry, feeds,
  RPM, SNMP, FRR and LLDP teardowns. The block's own comment already stated the
  intent — *"clear rg_active BEFORE stopping subsystems that may hang"* — but it
  was positioned relative to the two subsystems anyone had worried about (VRRP,
  sync), so **every teardown added above it silently moved ownership-release
  later in the budget**. #9035 measured the flow-export drain alone reaching
  22 s (serial, 2 s per collector, uncapped cardinality, untimed join) — over
  budget before either action ran.

  Bounding that drain is necessary and is done (`telemetryDrainBudget`,
  `joinWithBudget` in `daemon_flowexport.go`), but it is **not sufficient and
  never could be**: it fixes the one subsystem that was measured and leaves the
  next slow one to re-break the same invariant. The ORDER is what makes it
  structural — nothing added after that point can push the fail-closed actions
  past the budget, because they have already happened.

  It cannot move earlier than `wg.Wait()`. `desired = clusterPri ||
  allVrrpMaster` (`rg_state.go`), so a live reconcile goroutine would re-drive
  `rg_active` back to true after the clear — the #6530 retry doing its job
  against a clear it cannot distinguish from a spurious revert. Residual, stated
  rather than implied: `wg.Wait()` is itself unbounded.

  Bound by `TestFailClosedShutdownActionsPrecedeBlockingTeardowns9035` (source
  order) and `TestExporterTeardownsJoinThroughTheBudget9035` (the call sites —
  restoring a bare `flowWg.Wait()` leaves a cell that only exercises
  `joinWithBudget` directly GREEN, which is why the wiring is bound separately).

  **Background-apply fence (#6788).** The first thing `runShutdownSequence`
  does — before it cancels the in-flight apply and before the single apply
  drain — is latch `Daemon.applyFenced` and quiesce the DHCP client's
  address-change callback. The ordering is load-bearing: **fence, then cancel,
  then drain.**

  The drain is a drain-and-**release**, not a barrier. It acquires `applySem`
  to wait out an in-flight apply's #5643 closeout and hands the semaphore
  straight back, so without the fence any background applier that wakes
  afterwards acquires immediately and runs a FULL `applyConfigLocked` into a
  half-torn-down daemon — after FRR is stopped, the dataplane is torn down and
  the VIPs are withdrawn. Cancellation cannot cover it: `applyCancelContext`
  aborts an apply that is already RUNNING, and the background appliers bind
  `context.Background()` deliberately so they always run to completion
  (`applyConfigUnderSem`); there is nothing to cancel in an apply that has not
  started. Refusing before it begins is also strictly better than aborting one
  midway, since no half-finished apply is left behind.

  Every background full apply passes the fence through ONE helper,
  `beginBackgroundApply` — `applyConfig`, `applyActiveConfig` and
  `applyActiveConfigResult` are a family that must agree, and a shared
  predicate cannot drift the way three hand-written guards can. It tests the
  fence **twice**, and the second test is the load-bearing one: an applier can
  already be blocked on `applySem` behind an in-flight apply when shutdown
  fences, and checking only before the acquire lets it through the instant that
  apply releases — precisely the semaphore the drain just freed. The COMMIT
  paths are deliberately not fenced: they bind request-scoped contexts, are
  already covered by #2926 cancellation, and their servers are stopped during
  teardown.

  The DHCP quiesce is separate and **both are required**. `dhcp.Manager.Quiesce`
  stops the 2s lease-change debounce timer and latches so a lease event racing
  shutdown re-arms nothing; it is emphatically NOT `StopAll`, because cancelling
  a client runs `finishClient` → `removeAddress` and would strip the DHCP
  address from every DHCP interface — including a DHCP-managed management NIC —
  both during this shutdown and across a graceful restart, which is the exact
  contract `pkg/dhcp`'s client-context comment preserves. And the fence alone is
  not sufficient either: `onDHCPAddressChange` nudges the Surface-A DDNS
  reconcile and, on its management-only branch, runs `applyMgmtVRFRoutes`
  (netlink route writes) and `reconcileDNSFromDHCP` — none of which pass through
  `beginBackgroundApply`. Stopping the callback is what closes that half.
- `daemon_run_routehelpers.go` — route/tunnel inference helpers:
  `riMemberLinuxName`, `collectAppliedTunnels`, `linkLocalV6Net`,
  `inferIPv6StaticNextHopInterfaces`.

### Struct decomposition (#4407, in progress)

The `Daemon` struct historically fused 150+ flat fields spanning ~15
subsystems. It is being decomposed incrementally into per-subsystem
sub-structs — pure code motion, no behavior/locking/lifecycle change (the
Go compiler enforces completeness). Each increment groups one cohesive,
self-contained field cluster and lands as its own reviewable PR; the
tracker issue #4407 carries the remaining increments.

- **Increment 1 — DHCP-server lease sync (PATH C, #2239):** the flat
  `dhcpLeaseSync*` / `dhcpLeaseLast*` fields moved into
  `dhcpLeaseSyncState` (defined in `daemon_dhcp_lease_sync.go`, the file
  that owns the push/seed orchestration), reached as `d.dhcpLeaseSync.*`.
  A named sub-field (not an embed) was used because the access sites are
  bounded to that one file — the explicit `d.dhcpLeaseSync.` qualifier is
  clearer than field promotion. `ipsecSANudgeCh` stayed a flat `Daemon`
  field (it is IPsec-SA-sync state, not lease-sync).
- **Increment 2 — periodic neighbor-resolution guards (#1780 Path A):** the
  nine flat supervision fields for `runPeriodicNeighborResolution` (the
  per-phase in-flight overlap guards, the per-phase last-success UnixNano
  timestamps feeding the `neighbor_periodic_last_success_age_seconds{phase}`
  gauge, the loop-started gate, and the `warmNeighborCache` warmup guard)
  moved into `neighborPeriodicGuards` (defined in `daemon_neighbor.go`, the
  file that owns the supervision loop), reached as `d.neighborGuards.*`. The
  fields keep their exact `atomic.Bool` / `atomic.Int64` types (dropping the
  now-redundant `neighbor`/`Neighbor`/`Periodic` name prefixes), and
  `runGuardedNeighborPhase` still takes `&`-pointers to the addressable struct
  fields, so this is pure code motion — no behavior/locking change. A named
  sub-field (not an embed) matches increment 1: every non-test access site is
  bounded to `daemon_neighbor.go`. `lastStandbyNeighborRefresh` stayed a flat
  `Daemon` field (like increment 1's `ipsecSANudgeCh`) — it is the
  standby-side refresh rate limit read in `daemon_health.go`, a different
  mechanism from the periodic-resolution supervision grouped here.
- **Increment 3 — periodic configuration-archival timer (#4078):** the four
  flat supervision fields for the `system archival configuration
  transfer-interval` timer (`archiveTimerMu`, `archiveTimerKey`,
  `archiveTimerStop`, `archiveNewTicker`) moved into `archiveTimerState`
  (defined in `daemon_archive_timer.go`, the file that owns the
  reconcile/run/stop lifecycle), reached as `d.archiveTimer.*` (fields renamed
  `mu`/`key`/`stop`/`newTicker`). The fields keep their exact types, so this is
  pure code motion — no behavior/locking change. A named sub-field (not an
  embed) matches increments 1 and 2: every access site is bounded to
  `daemon_archive_timer.go` (plus its `archive_timer_4078_test.go`), and the
  `d.archiveTimer.key` qualifier additionally removes the prior confusing
  collision between the old `archiveTimerKey` field and the still-flat
  package-level `archiveTimerKey(interval, sites)` hash-gate helper.
  `archiveTransfer` stayed a flat `Daemon` field (like increment 1's
  `ipsecSANudgeCh` and increment 2's `lastStandbyNeighborRefresh`) — it is the
  one-shot transfer-on-commit upload seam used by `archiveConfig` in
  `daemon_flow.go`, a different mechanism from the periodic timer grouped here.
  - **Interval overflow bound (#5784).** `transfer-interval` is an
    operator-settable value in MINUTES, bounded to `[1, 2880]` at commit
    (`schema_system.go`), so a normal commit cannot overflow
    `time.Duration(min)*time.Minute` into a non-positive Duration and panic
    `time.NewTicker` in `runArchiveTimer` (an xpfd crash). The `interval <= 0`
    guard in `reconcileArchiveTimer` inspects the minutes integer, not the
    `× time.Minute` product, so a pathological value from the lenient
    `Store.Load` / peer-sync ingress (which bypasses the strict schema bound)
    would still reach `NewTicker`. `clampArchiveIntervalMinutes`
    (`daemon_archive_timer.go`) re-applies a `[1, config.MaxDurationMinutes]`
    clamp at runtime as defense-in-depth — the minutes-scoped sibling of the
    #5723 `clampRPMIntervalSeconds` / #5705 keepalive clamps, closing the
    config-interval × time.Unit overflow class for the minutes straggler.
- **Increment 4 — host-inbound fail-open / ambiguity previous-apply sets
  (#3698 / #3710 / #3718):** the three flat `map[string]bool` fields
  (`hostInboundAddresslessZones`, `hostInboundAddresslessIfaces`,
  `hostInboundAmbiguousAddrs`) moved into `hostInboundFailOpenState` (defined in
  `daemon_nft.go`, the file that owns the three `logHostInbound*Transitions`
  diff/log functions), reached as `d.hostInboundFailOpen.*` (fields renamed
  `addresslessZones`/`addresslessIfaces`/`ambiguousAddrs`, dropping the
  redundant `hostInbound` prefix). All three hold the set observed on the
  PREVIOUS apply and are diffed against the current set to emit
  state-transition logs only; they keep their exact `map[string]bool` types and
  the identical applySem-only access contract, so this is pure code motion — no
  behavior/locking change. A named sub-field (not an embed) matches increments
  1–3: every access site is bounded to `daemon_nft.go` (plus the
  `host_inbound_addressless_3698_test.go` / `host_inbound_ambiguous_3718_test.go`
  tests). The similarly-named `*prometheus.Desc` fields in `pkg/api` are a
  SEPARATE collector that scrapes the live window from the active config
  independently of these logs — they are unrelated to this grouping.
- **Increment 5 — Surface A (router/interface-address) DDNS state (#2691 P2):**
  the six flat `surfaceA*` fields (the `*ddns.SurfaceAManager`, the depth-1
  `surfaceAReconcileNowCh` nudge channel, the `surfaceAReconcileInFlight`
  no-freeze guard, and the three per-warning-dedup `sync.Map`s —
  `surfaceACheckIPAllowlistWarned` / `surfaceACheckIPSourceBindWarned` /
  `surfaceACheckIPNoURLWarned`) moved into `surfaceAState` (defined in
  `daemon_ddns_surface_a.go`, the file that owns the reconcile loop), reached as
  `d.surfaceA.<field>` with the redundant `surfaceA` prefix dropped (`mgr`,
  `reconcileNowCh`, `reconcileInFlight`, `checkIPAllowlistWarned`,
  `checkIPSourceBindWarned`, `checkIPNoURLWarned`). The fields keep their exact
  types (`atomic.Bool` / `sync.Map` inside a value sub-field of the never-copied
  `*Daemon`, so the non-copyable members are safe) and their exact access
  contract, so this is pure code motion — no behavior/locking change. A named
  sub-field (not an embed) matches increments 1–4: every production access site
  is bounded to `daemon_ddns_surface_a.go` plus the construct/gate sites in
  `daemon_run.go` (and the four `daemon_ddns_surface_a_test.go` literals). The
  **Surface B** DHCP-lease DDNS manager (`ddns` / `ddnsReconcileNowCh` /
  `ddnsReconcileInFlight`) stays a set of flat `Daemon` fields — it is a
  DIFFERENT DDNS mechanism, exactly the two-mechanism split increment 1's note
  anticipated when it kept the mirrored `ddnsReconcile*` fields flat.

This exhausts the CLEAN, single-cluster / single-file pure-code-motion
increments. The remaining `Daemon` field clusters are the broad /
review-gated remainder, deliberately NOT taken as further code-motion-only
increments: **flowexport** (18 `flow*`/`ipfix*` fields spanning three files —
too broad for one reviewable code-motion PR), **fabric cross-chassis
forwarding** (the `fabric*` refresh state — broad, spread across the HA
forwarding path), and the **SNMP + `applyConfigLocked` reconcile-ordering**
cluster (deferred to `/triple-review` per #4407, because regrouping it
touches apply-ordering rather than being inert field motion). These are the
natural stopping point for the mechanical decomposition.

### Management-listener lifecycle (`managementReconciler`, #5866)

`d.mgmt` (`management.go`) owns the HTTP/HTTPS management-listener lifecycle so a
day-2 web-management commit actually replaces the live listener and the
authentication snapshot instead of leaving the boot-time server enforcing the
old bind/port/TLS/auth until a restart (a revoked credential stayed usable). It
mirrors `reconcileSNMP`: `reconcileWebManagement` runs EARLY in
`applyConfigLocked` — before the dataplane apply that can abort — so a committed
credential revocation is enforced even on an apply that returns early
(`store.Commit` has already promoted the config). Reconcile discipline:

**The reconcile follows the PROMOTION, not the apply (#6718, #6720).**
`reconcileWebManagement` runs early in `applyConfigLocked` so a committed auth
revocation survives an apply that *aborts partway*. That contract had an
unstated precondition: `applyConfigLocked` is its only caller, so a path that
returns **before entering the apply** never reaches it. Two do, and both leave a
superseded credential authenticating against the live listener:

- `executeConfirmedRollback`'s `prevCfg == nil` branch — a first
  `commit confirmed` on a fresh store times out, the store reverts to the empty
  tree, `enterBootstrapMode` runs and the function returns. The abandoned
  commit's off-box bind and api-auth credential stayed live.
- `syncAndApply`'s topology (#5840) and identity (#6192) backstops — `SyncApply`
  has already promoted the peer config, then the backstop returns. The listener
  kept honouring a credential the now-active config revoked.

Both now call `reconcileManagementAfterPromotion`. The reconcile is the GENERIC
one in every case, including the bootstrap one: with the empty tree active there
is no web-management stanza, so the desired state IS the `--api-addr` flag
default with no credential — which is exactly "revert to the flag-default
endpoint and drop the abandoned credential". Keeping the management LIFELINE,
which is why that branch skips the apply, is not the same as keeping the
abandoned commit's off-box bind and secret.

The backstops keep returning their error and keep refusing to arm the dataplane.
Their constraint is the boot-only HA runtime; the authorization reconcile has no
such constraint. Hoisting those checks ABOVE the `SyncApply` promotion would also
close the divergence, but it changes the tolerant path from "converge with the
peer, refuse to arm" to "refuse the config" — a deliberate #1960 behaviour choice
that does not belong in a bug fix.

**A partition commit the peer never held is alarmed, not lost silently (#9530).**
The store marks a local commit made while the peer is unreachable (see
`pkg/configstore`, "A commit the cluster peer never held"). The daemon supplies
its three inputs (`config_divergence_9530.go`):
- `configPeerReachable` (heartbeat alive and session sync connected), wired with
  `SetPeerReachableFn` at cluster bring-up;
- `noteConfigSharedWithPeer` after every config push (the commit push, the
  reconcile push, and its test seam). It counts only when the peer reads RG0
  secondary: in the dual-active heal window the peer is still primary and
  rejects the push;
- `reportConfigSyncDivergence` after a successful `handleConfigSync`, which
  raises the divergence once as an `EventConfigSync` cluster event naming the
  rollback slot. `show system alarms` lists it as CRITICAL, on the local CLI and
  over gRPC.

**Startup ordering and publication (#6719).** `d.mgmt` is an
`atomic.Pointer[managementReconciler]`, not a plain field, and the type is doing
real work rather than being defensive. `startClusterComms` runs at
`daemon_run.go` ~:405 and `startHTTPServer` at ~:596, so for roughly 190 lines of
`Run` the peer-sync apply path is live while the reconciler does not exist yet —
`reconcileWebManagement` reads the pointer on exactly that path. A plain field
write racing those reads is a data race on the pointer that gates the management
auth reconcile; the atomic gives the happens-before edge and makes the plain read
impossible to reintroduce. (#6827 round 5 had narrowed this to the stale-cert
path under `staleCertMu` and said so explicitly — "Do not read this as `mgmt is
guarded`; it is not". It is now.)

`start` also derives its snapshot from `store.ActiveConfig()` **under `m.mu`**,
not before taking it. The pre-#6719 shape read the active config first and only
then contended for the lock, which lost a promotion outright: startup read config
A, a peer sync promoted B (revoking A's credential) and called `reconcile`, that
reconcile won the lock, found `m.srv == nil` and no-opped, and `start` then
installed the server built from the stale A. The credential stayed accepted until
some later reconcile or a restart, and the same window applied to the bind
address and TLS. Reading under the lock makes both interleavings correct rather
than one lossy: a promotion that lands before the read is simply seen, and one
that lands while the lock is held blocks and then converges against a server that
now exists. `committedDesired` (the reconcile path) reads the same
`store.ActiveConfig()`, so the two derivations agree on their authority by
construction. `startLocked` is the shared body; `startTo` remains the
explicit-config test seam.

- **Auth change on an unchanged endpoint** → live `api.Server.ReplaceAuth`
  (atomic snapshot swap, effective next request, no rebind, no window).
- **Endpoint change** → reconcile ONLY the listener leg that changed, PER LEG:
  an HTTP-bind change make-before-break rebinds only the HTTP leg
  (`api.Server.ReconcileHTTP`); a TLS enable/disable or HTTPS-bind change rebinds
  only the HTTPS leg (`api.Server.ReconcileHTTPS`) and never touches the live
  HTTP listener. The whole-server rebuild it replaces re-bound the retained HTTP
  socket on a TLS enable (`EADDRINUSE`, since `SO_REUSEADDR` ≠ `SO_REUSEPORT`),
  so a TLS change could never converge without a restart. Each leg is
  make-before-break inside `api.Server` (new socket serving before the old
  retires — no unreachable window, no double-bind of an unchanged socket).
- **Failed leg (re)bind** → **fail-safe**: retain THAT leg's previous listener
  (fail-closed — not mgmt-down), leave its fingerprint field unrecorded so the
  next commit retries (retry debt), and log the error. This does not brick an
  otherwise-successful commit (same posture as `reconcileSNMP` bind-failure
  retry).
- **Auth ordering — a REVOCATION publishes FIRST, a GRANT and a LOOSENING
  publish LAST.** The directions are not symmetric and are not sequenced
  together, and a non-nil credential set is itself SPLIT: it is a revocation and
  a grant at once, and only the revocation half is unconditionally a tightening.
  - The **revocation half** of a non-nil `next.Auth` publishes **before either
    leg is (re)bound**, and regardless of the outcome — even when the HTTP leg's
    OWN rebind then fails and the old listener is retained. Two things follow. A
    committed credential revocation is never blocked by a bind failure (#5866
    Finding A, #5561 round 7) — deferring it there left the RETAINED listener
    honouring the OLD secret indefinitely, a permanent fail-open rather than a
    race. And no listener ever SERVES under a superseded snapshot (#5561 round
    9): `ReconcileHTTP` binds and starts serving before it returns, so
    publishing afterwards left the new socket enforcing the old policy for the
    width of the intervening `ReconcileHTTPS` — worst case a loopback→off-box
    move that ADDS the credential the #4047/#5127 clamp requires, where the old
    snapshot is legitimately nil and the new routable listener answered
    everything through the nil-snapshot pass-through.
  - The **grant half** waits until every listener that is SERVING sits at an
    address the committed config names (#5561 round 12). Round 9 licensed an
    unconditional publish on the argument that a non-nil set "only ADDS a
    requirement"; that holds only against a NIL live snapshot. Credential sets
    are not monotonic — `{A} → {A,B}` and `{A} → {B}` both make a value
    acceptable that was not acceptable a moment ago, and the listener it becomes
    acceptable on may be one this config asked to stop serving. So while some
    live listener is at an address the config does not name, only
    `api.AuthForRetainedListener(live, next)` — the intersection with what that
    listener already accepted — goes out. A nil live snapshot is the UNIVERSAL
    set (it is the pass-through posture), which is what keeps the round-9 case
    publishing whole.
  - **The gate for that is the property, not a proxy** (#5561 round 13).
    `mgmtEndpoint.everyLiveLegNamedBy(next)` asks where the live legs actually
    are: the HTTP leg is always serving at `cur.addr`; the HTTPS leg is serving
    only when `cur.tls` is set, because `ReconcileHTTPS` creates the leg only
    after BOTH the keypair and the bind succeed. It is read TWICE — before the
    rebinds (is anything about to move off what `next` names?) and after (did
    everything land on it?), which works because each fingerprint field advances
    only on its own leg's success. The previous gate, `rebinding && len(errs) ==
    0`, was strictly wider: a failure to **ENABLE** a leg leaves NO listener at
    an unnamed address, yet it withheld anyway. That turned an ordinary commit —
    rotate the password and enable TLS, where port 443 is already held — into a
    deny-all: a single-account rotation intersects to the EMPTY set, which
    rejects every non-exempt request, on the HTTP address the same commit named
    and never moved. The empty set is absorbing (`∅ ∩ X = ∅`) and that
    fingerprint could never converge, so neither re-committing nor rotating
    again recovered; only backing the TLS enable out did.
  - **The empty intersection stays representable, and every state that can
    reach it has an EXIT.** Refusing to represent `∅` would mean keeping a
    credential the committed config no longer carries alive on a listener the
    operator asked to leave — the round-7 fail-open. What was wrong was entering
    it with nothing retained anywhere and no way out. It is now entered only
    while some listener really is serving an unnamed address, so a later commit
    always exits it: converge that bind, or commit the address that is actually
    serving (which moves nothing and publishes whole).

    Both exits rest on the unnamed address being one a committed config CAN
    name, and round 13's predicate quietly assumed the HTTP leg is always live
    at `cur.addr`. It is not: a boot HTTP bind failure leaves `curSet` false and
    `cur.addr` empty, and — since round 14 made `startTo` adopt the server so
    the bind can be retried — a later reconcile can bind the HTTPS leg while
    HTTP still fails. The absent HTTP leg then read as a mismatch, so a rotation
    on the live, correctly-named HTTPS listener intersected to `∅` with NEITHER
    exit available: the HTTP bind keeps failing, and no committed config can
    make `next.Addr` empty because `resolveAPIBinds` always yields a concrete
    address. `everyLiveLegNamedBy` now treats an empty `e.addr` as "that leg is
    not serving, so it imposes no requirement", symmetric with the cleared-`tls`
    arm. Pinned by
    `TestMgmtLiveHTTPSLegIsGrantedWhenTheHTTPLegNeverBound_5561` (#5561 round
    16).
  - **Removing ALL api-auth is a revocation too, and it lands immediately**
    (#5561 round 14). The committed policy authorizes no credential, and there
    are exactly two ways to say that to a listener:
    `mgmtEndpoint.allLoopback()` decides which (`publishNilDirectionLocked`,
    called before AND after the rebinds).
    - **nil** — `dynamicAuthMiddleware`'s pass-through — goes out only once
      every LIVE leg is at a loopback address. Its justification is the
      #4047/#5127 clamp, which `resolveAPIBinds` evaluates against the bind the
      COMMITTED config asked for and never re-evaluates against the listener
      that is serving; a leg retained by a failed rebind is not that bind, so
      "the rebind succeeded" is a proxy and the addresses are checked directly.
    - **Deny-all** — non-nil and EMPTY, rejecting every non-exempt request —
      goes out while any live leg is still off-loopback. Before round 14 there
      was no second arm: the live snapshot was left ALONE, so the credential the
      operator had just deleted went on authenticating on that routable address
      for as long as the loopback bind kept failing. That is indefinite, not a
      window, and it inverts the instruction. Deny-all honours the revocation
      without the fail-open, the same over-restrict-and-retry posture the
      intersection takes on the non-nil path — and the post-rebind call is what
      converges it to nil once the loopback bind lands, so it is an intermediate
      and not a lockout.
    - **Both call sites are load-bearing, and for DIFFERENT reasons** (#5561
      round 16). On a rebind that FAILS, the off-loopback leg is RETAINED and
      keeps following the server-wide snapshot, so the post-rebind call alone
      would still land the deny-all — there the pre-rebind call is redundant.
      What it is for is the rebind that SUCCEEDS: the old leg is then RETIRED,
      and `api.Server.trackRetiring` PINS it to whatever `s.auth` holds at that
      instant. The post-rebind call cannot repair that pin, because by then
      `m.cur` is loopback so the committed nil is what publishes, and
      `api.authSlot.tighten` drops a nil `next` by design. Without the
      pre-rebind publish the pin captures the credential the operator DELETED,
      and it keeps authenticating on the routable address for the whole
      drain plus every keep-alive connection already accepted. Pinned by
      `TestMgmtRemovedCredentialNeverSurvivesOnTheRetiredLeg_5561`, which is the
      only case in the package where this nil-direction rebind converges — every
      other one exercises the retained path, which is why deleting the
      pre-rebind call site was silent before round 16.
  - **Generation fence — the WHOLE desired state comes from one COMMITTED
    generation** (#5561 round 14, superseding the credential-only pin of rounds
    10 and 12). Serializing applies does not order their CONTENT: a caller that
    snapshots `store.ActiveConfig()` and THEN waits on the apply semaphore (the
    DHCP lease-change callback) can be overtaken by commits and then run, alone
    and in order, carrying a superseded generation. `reconcile` therefore routes
    through `committedDesired`, which re-derives endpoint AND credentials from
    `store.ActiveConfig()`. On the ordinary commit path that is the identity
    (`store.Commit` / `PromoteRollback` promote before the apply runs); on a
    stale replay it is the repair.

    Pinning only the credential half left the listener being driven toward the
    STALE endpoint under the COMMITTED policy — a hybrid belonging to no
    committed generation, and one nothing downstream can reason about. With the
    committed policy nil, that hybrid is an OFF-LOOPBACK listener with NO
    authentication, and the nil gate cannot repair it: it only declines to
    publish ANOTHER nil, and the nil is already live, so there is no credential
    left to restore. With the policy non-nil, the hybrid's `next` NAMES the
    stale address, so `everyLiveLegNamedBy` reads TRUE and the full credential
    set publishes at an endpoint the committed config never authorized it for.
    Round 13 did not close that: it sharpened which question is asked; the
    hybrid corrupts the `next` the question is asked about. Fencing the
    generation removes both. This fences the MANAGEMENT LISTENER only — the rest
    of the pipeline still reconciling toward a superseded generation is #6716.
  - **A RETIRED listener never gains a credential** (#5561 round 14). Retirement
    is asynchronous: `stopLegLocked` closes a channel, and the leg's goroutine
    closes the socket and drains later, so `ReconcileHTTP` returns while the old
    address is still accepting and still serving what it accepted. Publishing
    the committed set right after therefore handed a credential authorized for
    the NEW address to the one the same commit retired. Each leg now carries its
    own `authSlot`: LIVE legs follow the server-wide snapshot (the #5866 live
    swap is unchanged), and a leg is PINNED at retirement to what it was already
    serving, after which `ReplaceAuth` only ever intersects it — revocations
    still land there, grants and nils never do.
  - **Boot retry debt is real debt** (#5561 round 14). Every "over-restrict and
    let the next commit converge" argument above is only as good as the
    convergence, and two boot paths had none. An HTTP bind failure returned
    before `m.srv` was assigned, so `reconcileTo`'s `m.srv == nil`
    short-circuit made every later reconcile a silent no-op — management stayed
    down for the life of the process. An HTTPS bind failure is deliberately
    non-fatal, but `startTo` recorded the DESIRED HTTPS fingerprint as converged
    anyway, so the leg-changed test was false on every subsequent commit and
    `ReconcileHTTPS` was never called again. `startTo` now adopts the server
    whether or not the bind succeeded, and asks `api.Server.HTTPSServing()`
    rather than inferring convergence from a nil error.
  - **A converged fingerprint is not a live listener** (#6827 round 6). The
    same inference failed in the STEADY state, not just at boot: an HTTPS serve
    loop that terminates unexpectedly marks its leg `dead` and leaves it
    INSTALLED (it cannot be unlinked there without taking `lifeMu`, which
    deadlocks a shutdown racing the exit). The fingerprint still matched the
    committed endpoint, so `reconcileTo`'s leg-changed test was false on every
    later commit and `ReconcileHTTPS` was never called; and had it been called,
    its same-address arm returned `nil` on a non-nil pointer. HTTPS was
    therefore unrecoverable on an UNCHANGED configuration for the life of the
    process — and with it any stale-cert diagnosis, which can only be
    discharged against a served certificate. The HTTPS arm now also fires when
    `next.TLS && !m.srv.HTTPSServing()`, and the api-side no-op tests
    `listenerLeg.serving()` instead of the pointer. Pinned by
    `TestADeadHTTPSLegIsRebuiltByTheNextReconcile_6827` (daemon, end to end from
    `reconcileWebManagement`) and `TestReconcileHTTPSReplacesADeadLeg_6827`
    (`pkg/api`).
  - **The HTTP leg never got that fix** (#6803). Round 6 repaired the HTTPS arm
    and stopped. The HTTP arm still gated on the converged fingerprint alone
    (`next.Addr != m.cur.addr`), and `api.Server.ReconcileHTTP`'s same-address
    short circuit still tested a non-nil pointer rather than `serving()` — the
    two defects round 6 named, on the other leg. So an HTTP serve loop that
    terminated unexpectedly left the REST/management API down for the life of
    the process on an UNCHANGED configuration, exactly as HTTPS did before round
    6. The HTTP arm now also fires when `next.Addr != "" && !m.srv.HTTPServing()`
    — gated on a non-empty desired address so it stays strictly additive, since
    `ReconcileHTTP` refuses an empty bind and the #6827 over-reach guard
    `a_failed_boot_then_an_empty_bind_binds_nothing` pins that direction — and
    `ReconcileHTTP`'s no-op now asks `s.httpLeg.serving()`, mirroring
    `ReconcileHTTPS`. New accessor `api.Server.HTTPServing()` is the exact
    counterpart of `HTTPSServing()`.
  - **…and nothing CALLED the reconcile** (#6803). Both gate fixes are only
    reachable from `applyConfigLocked`, the sole caller of
    `reconcileWebManagement`, so recovery still waited on an operator committing
    — from a box whose management API had just died, which is the box they can no
    longer reach to commit from. `mgmtListenerReassertLoop`
    (`mgmt_listener_reassert.go`) is the owner: started unconditionally in `Run`
    beside `proxyARPReassertLoop` / `raDeadSenderReassertLoop` (#6793) /
    `fabricIPVLANReassertLoop` (#6791) / `hostInboundConntrackReassertLoop`
    (#6802), 30s, taking `applySem` before acting (#4001) and re-checking the
    gate INSIDE the semaphore because the commit it queued behind may already
    have rebound the listener. Its gate is
    `effectiveHTTPListener().State == StateFailed` — deliberately the SAME
    question `show system services` answers, so the box can never report a dead
    listener nothing is retrying, or retry one it reports healthy. Pinned by
    `mgmt_listener_reassert_6803_test.go` (dead-leg rebind on an UNCHANGED
    config, paired against a healthy leg that must NOT be bounced; the gate
    tracks the operator view; the owner re-binds with no commit; the
    inside-the-semaphore re-check; the loop ticks; and a loop-START cell) and
    `pkg/api/reconcile_http_dead_leg_6803_test.go`.

    Not covered by #6803: the PRIMARY (loopback) gRPC listener has the same hole
    — `Run` logs a serve error and the goroutine exits with nothing re-binding —
    while the FABRIC gRPC listener beside it has had a backoff supervisor since
    #5047. Filed separately.

  Pinned by `TestMgmtReconcileRevokeHonoredDespiteHTTPSBindFailure_5866`
  (revocation honored across a failing HTTPS rebind),
  `TestMgmtReconcileRemoveAuthDeniesAllWhenHTTPRebindFails_5866` (a retained
  non-loopback HTTP listener gets DENY-ALL — neither the nil, which is the
  fail-open, nor the deleted credential),
  `TestMgmtNilAuthNeverDropsARetainedOffLoopbackHTTPSLeg_5561` (the same for a
  retained non-loopback HTTPS leg while the HTTP leg converged onto loopback),
  `management_authsanction_5561_test.go` (the grant gate asks where the live
  legs are — both the never-moved and the converged-move shapes — and every
  empty intersection is exitable), `management_authpublish_5561_test.go`, which
  records the LIVE snapshot at the instant each listener is bound and requires
  it to be the published one, `management_authstale_5561_test.go` (the fence: a
  stale replay never binds the superseded generation's endpoint, in both the
  credentialed and the removed-api-auth directions),
  `management_bootretry_5561_test.go` (both boot paths retry, and the deny-all
  intermediate exits), and `pkg/api/listener_retiredauth_5561_test.go` (a
  retired leg gains no grant and is never dropped to no-auth, while a live leg
  still follows the snapshot).

#### Stale management-TLS-certificate diagnosis on rename (#6827)

The auto-generated management HTTPS certificate is DURABLE on disk and is NOT
re-minted by a later `set system host-name`, so its SANs go stale and clients
verifying by host name start failing. `pkg/api`'s own load-path diagnostic
cannot see a plain rename — the HTTPS leg is rebuilt only when the TLS flag or
the HTTPS bind address changes, so a rename on an unchanged endpoint reloads
nothing. `Daemon.renameHostNotingStaleMgmtCert` closes that gap from the apply
side. `applyHostname` calls it in place of a bare `Sethostname` — it performs
the rename AND records the debt under ONE hold of `staleCertMu` (#6827 round 7,
see the fence bullet below) — and then delivers the diagnosis as its last act.
The delivery is deliberately NOT part of `reconcile()`, which runs early in the
apply and can only ever see the old name.

Marking and delivering are ONE path (`deliverStaleMgmtCertDiagnosis`), because
at BOOT the hook runs before its own dependency exists — the first config apply
is startup phase 4 while `startHTTPServer` publishes `d.mgmt` later in `Run`.
Three properties carry the mechanism:

- **A debt, not a one-shot.** `staleCertPending` clears only when a delivery
  actually REACHED a served certificate (`WarnStaleMgmtCertForHostName` reports
  that). Clearing it whenever the delivery merely RAN loses the diagnosis
  permanently when HTTPS is off or its bind failed: the next boot's
  `applyHostname` sees the name already applied and returns early, and the load
  path's inferred heuristic declines a CROSS-SHAPE rename by design (a
  shape-preserving one it would still catch, but only at the next certificate
  load — a restart or an HTTPS rebind, not the commit). Delivery is attempted at
  the rename itself and RETRIED at the boot management start and on every
  web-management reconcile (so a later `web-management https` enable — or the
  rebuild of an HTTPS leg whose serve loop died — settles an old debt). The
  two DEFERRED retry points are bound at their own call site by
  `TestDeferredDeliveryIsWiredAtItsRetryPoints_6827`, on deliberately different
  observables: the `reconcileWebManagement` one on the debt FLAG, because the
  reconcile that brings HTTPS up makes `pkg/api`'s LOAD path emit the same
  warning text (a text assertion there passes with the retry deleted); the
  `startHTTPServer` one on the kernel-name read, which sits past the
  nil-reconciler guard, because that call site cannot be handed a serving HTTPS
  leg in-process — it constructs the `api.Server` itself and the cert-dir test
  seam exists only afterwards.
- **The name is read from the kernel at DELIVERY**, never stored at rename time,
  so a deferred diagnosis is never the replay of a name captured at some earlier
  commit. It IS the kernel's current name for every rename the daemon performs
  (#6827 round 7). Rounds 5 and 6 claimed otherwise — that `Sethostname` moves
  the name before the generation is recorded, so no fence could close the gap —
  but that was a property of where the lock was taken.
  `renameHostNotingStaleMgmtCert` holds `staleCertMu` ACROSS both the syscall
  and the bump, so the generation exists before the window can open: a delivery
  either warns while
  the rename is still blocked on the mutex (name still current) or finds the
  generation already moved and abandons. The residual is a privileged
  `sethostname(2)` from OUTSIDE the daemon, which no in-process fence can see.
  Bound by `TestRenameAndGenerationBumpAreOneCriticalSection_6827`, which
  observes from inside the syscall seam that the mutex is held.
- **The delivery is generation-fenced, before it speaks.** The kernel read runs
  unlocked; `staleCertGen` is sampled before it and RE-VALIDATED after it, under
  `staleCertMu` held across the certificate inspection and the clear. A delivery
  whose generation has been superseded abandons without warning and without
  clearing — it must not settle a newer rename's debt with older evidence, and
  must not emit a diagnosis naming a host name that a recorded rename has
  already replaced (round 5 checked only on the clear side, after the warning
  was already out). The re-validation tests `staleCertPending` as well as the
  generation (#6827 round 7): two deliveries for ONE rename — the boot delivery
  racing the rename's own attempt, say — sample the same generation, so a
  generation-only re-check lets the second one duplicate the line the first has
  already emitted. Nothing is lost by either arm: the newer rename's own
  `applyHostname` runs its own delivery. The race is reachable
  because the boot delivery runs on the `Run` goroutine outside `applySem` while
  cluster comms — started right after the mutating startup phases, before
  `startHTTPServer` — can drive a peer `SyncApply` into `applyHostname`. Pinned
  by `TestDebtClearIsGenerationSafe_6827`: one subtest supplies the competing
  rename itself, one drives it through the production note path (so the
  `staleCertGen++` is bound, not just the comparison), one is the negative
  control where an unraced delivery MUST settle, one overlaps two
  same-generation deliveries so the second must stay silent, and one pins the
  unreadable-kernel-name guard that would otherwise discharge the debt with no
  identity behind it.

#### Effective-listener snapshot for `show system services` (#6385/#6401)

`show system services` reports the EFFECTIVE STATE of each management listener,
not the requested/config-declared addresses. `Daemon.effectiveListeners`
(`daemon_run_servers.go`) builds one `sysservices.Listeners` snapshot. Each row
is a `sysservices.Listener{Addr, State}` where `State` ∈ {`Listening`, `Failed`,
`Disabled`} (#6401) — so a CONFIGURED-but-FAILED bind is reported as
`addr (bind failed)`, distinct from a genuinely-off listener's `disabled` and
from a serving listener's bare address:

- **gRPC** — `grpcSrv.EffectiveListener()`. The gRPC server records its own
  lifecycle (`grpcListenState`): `Listening` with the actual bound address
  (`lis.Addr()`, post-#5035 loopback clamp), `Failed` on a `net.Listen` error or
  once the serve loop exits (the bound address is CLEARED so a dead server never
  reports a stale bind), and — in the brief pre-bind startup window — `Listening`
  on the requested `--grpc-addr`. gRPC is always configured, so it is never
  `Disabled`. Before the server is even constructed, `effectiveListeners`
  synthesizes pre-bind `Listening` on `--grpc-addr`.
- **HTTP REST** — `d.mgmt.effectiveHTTPListener()`. `Disabled` when the
  reconciler is absent (empty `--api-addr`, listener never started); `Failed`
  (reporting the attempted `lastHTTPAttempt`) when it was configured but the boot
  bind never converged (`curSet` false); `Failed` ALSO when a converged leg's
  serve loop later exits UNEXPECTEDLY — `api.Server.EffectiveHTTPAddr()` returns
  `""` for a leg the serve goroutine marked `dead` (listener.go), symmetric with
  the gRPC serve-exit clear, so a dead HTTP listener is never reported
  `Listening`; else `Listening` on the ACTUAL bound address read from the live
  server (`EffectiveHTTPAddr()` → `httpLeg.ln.Addr()`, so an ephemeral `:0`
  resolves to its concrete port and a wildcard/hostname bind is normalized). A
  day-2 rebind failure RETAINS the old serving leg (its socket stays live →
  `EffectiveHTTPAddr` non-empty), so this reports the address still serving, not
  the failed new bind.

BOTH render surfaces read this ONE snapshot: the remote gRPC renderer via
`grpcapi.Config.ListenersFn` and the local console CLI via `cli.SetListenersFn`,
both formatting through `sysservices.Listeners.Lines`, so the two surfaces can
never disagree. Before #6385 both renderers hardcoded
`127.0.0.1:50051 / 127.0.0.1:8080 (always on)`, so a relocated, clamped, failed,
or disabled listener was reported wrong; the remote gRPC path (the common
operator path) was the one a local-only fix left unfixed (the dropped #6384
A10-b2-F5).

## Cluster mode

Detected by the presence of `/etc/xpf/node-id` (contents `0` or `1`).
Absent → standalone. Cluster mode triggers the bondless-RETH naming
convention (`fxp0`, `em0`, `ge-{0,7}-0-X`).

### Cluster-comms epoch lifecycle (`startClusterComms` / `stopClusterComms`, #4958)

`startClusterComms` (`daemon_ha_sync.go`) launches an **asynchronous
constructor goroutine** that resolves the sync interface address (a retry loop
of up to ~60s during the networkd race) before it can build the session-sync
object. A transport-field change (`clusterTransportKey`) restarts comms
mid-flight: the apply path calls `stopClusterComms` then `startClusterComms`
while the *prior* epoch's constructor may still be resolving. That created two
data-race failure modes:

- **Nil-deref panic** — `stopClusterComms` set `d.sessionSync = nil` between the
  constructor's write and its next dereference (`SetAuthProvider`).
- **Stale overwrite** — a superseded epoch's constructor finished late and wrote
  its `d.sessionSync` / `d.fabricRefreshCh{,1}` over the new epoch's state.

The lifecycle is now **epoch-guarded** by `clusterCommsMu` + a `clusterCommsGen`
generation counter (all comms-epoch fields — `sessionSync`,
`fabricRefreshCh{,1}`, `clusterCommsCtx`/`Cancel`, `activeClusterTransport` —
are read/written only under that lock; every reader goes through
`getSessionSync()` / `snapshotFabricRefreshChans()` / `getClusterCommsCtx()` /
`activeTransport()`, capturing the value once):

- `beginClusterCommsEpoch` bumps the generation and installs the fresh
  sub-context; `startClusterComms` hands the post-bump generation to the
  constructor.
- The constructor builds the session-sync object in a **local `ss`** and wires
  every callback / cluster reference against it (never re-reading the shared
  field), then calls **`publishSessionSyncIfCurrent(gen, ss)`** — a
  publish-if-current: it stores `d.sessionSync = ss` only while `gen` still
  matches `clusterCommsGen`, otherwise it **drops** the publish (`slog.Debug`)
  and the goroutine returns before touching cluster state. The fabric channels
  publish the same way (`publishFabricRefreshChansIfCurrent`); each
  `populateFabricFwd{,1}` loop receives its channel **by value** at launch, so a
  restart's field swap cannot race the receive.
- `stopClusterComms` bumps the generation (superseding any in-flight
  constructor), cancels the context, **joins the constructor** via
  `clusterCommsWG`, then nils the shared state and `Stop()`s the old session
  sync. The join runs outside the lock (the constructor's publish path also
  takes it), so there is no deadlock.

- `activeClusterTransport` joined the epoch in **#6290** and publishes the same
  way, via `setActiveTransportIfCurrent(gen, key)`. It had been written by
  `startClusterComms` holding neither `clusterCommsMu` nor `applySem`, and read
  by `applyTailReconciles` step 20 under `applySem` — and a semaphore only
  excludes participants that take it. The issue judged that benign because the
  boot `startClusterComms` precedes the gRPC/HTTP servers, but those are not the
  only appliers: the boot `applyConfig` starts the DHCP clients
  (`reconcileDHCPClients`) with `onDHCPAddressChange` already wired, and that
  callback re-enters `applyConfig` — hence step 20 — on a goroutine created
  BEFORE the write. Goroutine creation therefore orders them the wrong way and
  supplies no happens-before, so a lease landing in that window was a real data
  race, the mirror of #5113 on `mgmtVRFInterfaces`. Step 20 now takes ONE
  `activeTransport()` snapshot for both its comparison and every `old_*` pair it
  logs. (Not a count: the earlier "eight log fields" here was wrong when it was
  written — four of step 20's eight pairs came from the locally-computed
  `newTransport`, which was never shared state — and #7073 has since changed the
  number again, #7070.)
- The line reporting the restart is derived from `clusterTransportKey` by
  `transportChangeLogArgs`, one `old_`/`new_` pair per field, rather than
  written out by hand. The hand-written list had drifted from the whole-struct
  comparison that decides the restart: it printed four pairs where the
  comparison used six, so a commit changing only `fabric1-interface` /
  `fabric1-peer-address` restarted comms correctly and then logged four
  identical `old`/`new` pairs — a line asserting a change and showing none
  (#7073). Deriving the pairs from the struct makes that drift
  unrepresentable; `cluster_transport_log_totality_7073_test.go` binds both the
  totality and the call site.

`make test-failover` is the required smoke for this path. The guard is covered
by `daemon_ha_comms_race_test.go` (deterministic drop-of-stale-publish +
`-race` concurrency) and, for the transport key, by
`cluster_transport_race_6290_test.go` (production writer vs production reader
under `-race`, plus a deterministic stale-epoch drop).

### Periodic converger for the Kea applier (#6535)

RA and Kea are the two per-RG services `applyRethServicesForRG` /
`clearRethServicesForRG` own. RA has had a per-pass converger since #5861
(`reconcileClusterRAServices`); Kea had none. Every Kea driver was an EDGE —
those two functions run only under `if tr.Changed`, `applyDirectVIPOwnership`
only on an ownership change, and the commit path only when an operator
commits — and `dhcpserver`'s async worker logs an apply error and drops it
rather than retrying.

So a failover whose Kea apply failed left the wrong node serving: persistent
dual-DHCP (the demoting node's stop failed, both Kea instances up) or no-DHCP
(the promoting node's start failed, neither up), until the next RG transition
or commit. Neither of those happens on its own.

`reconcileClusterDHCPServices` is the missing converger, called from
`reconcileRGState` beside `reconcileClusterRAServices` and following the same
rule that section states: the applied marker advances only on a verified
success, so a transient error is retried on a later pass rather than latched
as converged. It re-drives ONLY when `dhcpserver.Manager.ClaimApplyRetry`
reports the last COMPLETED attempt failed, and the manager spaces retries
(30s) — a permanently broken Kea must not be held in a continuous
15s-bounded systemctl restart loop by a 2s tick.

**The filtered result is a COPY with the narrowed fields swapped, not a
rebuild (#9348).** `filterDHCPConfigForMasterRGs` used to construct its result
field by field — `var result config.DHCPServerConfig` plus
`&config.DHCPLocalServerConfig{Groups: filtered}` — which names exactly the
fields the author knew about and silently drops the rest. Six were being
dropped, measured:

```
v4 SocketType    src="udp" filtered=""
v4 ExpiredLeases src=true  filtered=false
v6 SocketType    src="udp" filtered=""
v6 ExpiredLeases src=true  filtered=false
DynamicDNS       src=true  filtered=false
DynamicDNSv6     src=true  filtered=false
```

The two that MATTER are the family-level Kea scalars. A CLUSTERED node rendered
Kea without the operator's `expired-leases-processing` (#1387 — Kea fell back to
its built-in reclamation defaults) and without `dhcp-socket-type` (#7318 — Kea
fell back to `raw`), while a STANDALONE node rendered both from the same
committed config. #7318 exists precisely because `raw` does not work on some
substrates, so on a cluster that leaf read as applied and was not.

The DDNS pair is harmless, and that was checked rather than assumed: this result
reaches only `dhcpserver.Manager`, and the DDNS policy is read straight off the
ACTIVE config by `ddns.Manager.ReconcileScoped(ctx, &cfg.System.DHCPServer,
opts)` — `pkg/dhcpserver` never reads `DynamicDNS` at all. They ride along
anyway, because the point of the shape is that nobody has to make that
judgement per field.

The copy IS the guard: a field added to either struct is carried by
construction rather than needing someone to remember this site — the same shape
#9141 used for `resolveDHCPRethInterfaces`.
`TestClusterFilterCarriesEveryFieldItDoesNotNarrow9348` walks the source
reflectively and fails on any non-narrowed field that does not survive, with a
positive control so a walk that examined nothing cannot report a clean result.

**`Daemon.dhcpServer` is an INTERFACE so the apply wiring is drivable (#9349).**
It was a concrete `*dhcpserver.Manager` whose test seams (`runSystemctl`,
`unitActive`, `confPath4`/`confPath6`, `warn`) are unexported, so a `pkg/daemon`
test could not construct a harmless one. The consequence was measured by mutation
during #9141: BOTH DHCP derivation calls in `applyServicesReconcile` could be
severed —

```go
desired := cfg.System.DHCPServer      // instead of desiredStandaloneDHCPConfig(cfg)
dhcpCfg := &cfg.System.DHCPServer     // instead of d.desiredClusterDHCPConfig(cfg)
```

— and the ENTIRE Go suite stayed green. Neither is subtle. **Standalone**, Kea is
handed RETH *logical* names (`reth1.0`), which are not kernel devices, so DHCP
fails on every RETH-backed segment. **Clustered**, Kea is handed the unfiltered
config, so both nodes serve every group regardless of RG mastership — dual-DHCP,
the exact failure #1835 F3 / #6520 exist to prevent.

The functions BELOW those call sites were already well covered (#6520/#4647 on
the filter, #9141 on the resolver, #6535 on the converger). What had no cell was
the WIRING between the apply and the applier — and a cell for a function is blind
to its caller not calling it. `dhcp_apply_wiring_9349_test.go` drives
`applyServicesReconcile` with a RECORDING applier and asserts on the config that
actually reaches `Apply` / `ApplyClusterCommit`; the recorder deliberately
re-implements nothing, because a fake that supplied the derivation could not
observe production failing to.

`pkg/grpcapi`'s `Config.DHCPServer` became a three-method `DHCPServerStatus`
interface in the same change: leaving it concrete would have forced a type
assertion at the hand-off and reintroduced the coupling this removes.

**Single-sourced desired state.** `desiredClusterDHCPConfig` is the one place
that derives the Kea desired state from (active config, current master-RG
set); the commit path, both transition edges, and the converger all call it.
`desiredStandaloneDHCPConfig` is its non-cluster sibling (#9141) — the
committed stanza with RETH names resolved, no RG filtering. Both RETURN a
desired config; neither edits one in place.
This is single-sourced rather than bound with an agreement test because a
divergence between the converger and an edge is ALWAYS a bug — the converger
runs every pass and would fight the edge indefinitely.

Guards: `TestFailedKeaApplyIsRetriedByReconcileConverger` (three real
reconcile passes: an edge pass whose apply fails, a no-transition pass that
must re-drive it, and a third that must NOT) and
`TestClaimApplyRetryOnlyAfterAFailedApply`, in
`dhcp_apply_converger_6535_test.go`.

### Cluster DHCP member scoping: node-local vs RG-scoped (#6520)

`filterDHCPConfigForMasterRGs` decides which members of each
`dhcp-local-server` / `dhcpv6-local-server` group this node serves. Two
properties, both wrong before #6520.

**It names the kernel device, not an approximation of it (#9407).**
`resolveDHCPRethInterfaces` used to translate with
`LinuxIfName(ResolveReth(ref))` — the slash rewrite and the RETH member map,
and nothing else. That is two arms short of `Config.ResolveKernelIfName`, and
both gaps produced a name Kea cannot bind: `reth1.0` → `ge-0-0-1.0` (a dangling
unit suffix) and `reth1.80` with `vlan-id 180` → `ge-0-0-1.80` (the unit
number, not the VLAN device). Only the CLUSTER path papered over the first,
with `stripUntaggedUnitSuffix` (#4647), so the STANDALONE builder named a
phantom device on identical config.

The vlan-id gap did more than misname a device. This filter compares the
group's resolved interface against `rethInterfacesMatchingRG`, which ALREADY
derives `<member>.<vlan-id>` — so a tagged group resolved to `<member>.<unit>`
matched neither `masterIfaces` nor `rgScoped`, and the #6520 "not RG-scoped
implies node-local, always keep" arm below kept a redundancy-group-owned
segment on a node that masters nothing. Measured with no RG mastered: the group
survived as `ge-0-0-1.80`. The derivation is now the canonical resolver, which
is the same rule `rethInterfacesMatchingRG`'s arms reproduce, so the two sides
of the compare derive names identically rather than being asserted to agree
(#8994's doctrine). `TestKeaAndRGSetsDeriveNamesIdentically9407` binds that
over a corpus rather than only on the outcomes today's cells enumerate.

**It does not mutate the active config (#9141).** RETH logical names are
translated to physical member Linux names by `resolveDHCPRethInterfaces`, which
RETURNS a copy. It used to take a `*config.DHCPServerConfig` and rewrite
`group.Interfaces[i]` in place, and every call site reached that slice from the
daemon's shared active config: `dhcpCfg := cfg.System.DHCPServer` LOOKS like a
copy but is a shallow struct copy over a pointer (`DHCPLocalServer`), a map of
pointers (`Groups`) and a slice (`Interfaces`), so the rewrite landed on the
live config. `desiredClusterDHCPConfig`'s comment even claimed the function
"copies the config", which is what kept the defect invisible.

The harm was not in DHCP — it was in DDNS, one subsystem over.
`rgForInterfaces` (`daemon_ddns.go`) looks a group member up in
`cfg.Interfaces.Interfaces`, keyed by JUNOS names, so after the rewrite
(`reth1.0` → `ge-0-0-1.0`) the lookup missed and the pool scored RG 0 = "not
HA-owned". `buildLeaseSubnetRGMap` then reported no RG-owned pool at all,
`ddnsReconcileOptions` saw `anyRGOwnedPool` false, and the unattributable-lease
branch flipped from FAIL-CLOSED to admit — disarming the #2664 per-lease
double-write / stale-memfile guard, ORDER-DEPENDENTLY (different behaviour
before and after the first apply in a process lifetime, repaired only by a
restart, which recompiles the config from text). The operator-visible
`show dhcp server` also rendered `ge-0-0-1.0` where `reth1.0` was configured.
The PEER was never affected: config sync ships TEXT (`ShowActive` → the
ConfigTree AST), not the compiled struct.

Guards: `dhcp_reth_resolve_nomutate_9141_test.go`.

**Mastership scopes only RG-scoped members.** The keep-set used to be built
exclusively from `rethInterfacesForRG` over the currently-MASTER RGs, and that
function only ever yields members of `reth*` interfaces. Every interface that
is *not* part of a redundancy group — the `fxp0` management lifeline, and any
plain node-local data interface — was therefore removed from every group on
BOTH nodes, and a group made only of such members vanished entirely. Clustering
a box silently killed the DHCP service its operator had configured on a
node-local segment. Redundancy-group mastership answers "which node answers for
this REDUNDANT interface"; it says nothing about an interface with no redundant
peer, and Junos clusters likewise run `fxp0` services per node. So:

- a member that belongs to NO redundancy group is **node-local** and is kept
  unconditionally, on both nodes;
- a member that IS redundancy-group-scoped is kept only while this node masters
  that RG (unchanged).

Both sets come from ONE walker, `rethInterfacesMatchingRG`, of which
`rethInterfacesForRG` is now a predicate wrapper. That is deliberate rather than
stylistic: a divergence between "RG-scoped" and "mastered" is always a bug,
because the keep rule is exactly *RG-scoped implies mastered*. If one set
resolved a RETH member to a different name than the other, a node-local
interface would read as an unmastered RG member (service dropped) or an RG
member as node-local (both nodes serving DHCP on one redundant segment).

**A narrowed group must not keep Kea's per-subnet interface selector.**
`config.DHCPServerGroup` carries independent `Interfaces` and `Pools` arrays
with no semantic edge — nothing records which pool belongs to which member. So
once this filter removes a member, "the group has exactly one interface" no
longer implies "every pool in the group is served on that interface", which is
the inference `dhcpserver.subnetInterface` makes when it emits Kea's per-subnet
`interface` selector (#1778). A mixed `[fxp0.0, reth0.80]` group narrowed to the
surviving RETH member would bind the fxp0 pool's subnet to the RETH member.

The filter therefore sets `DHCPServerGroup.MembersFiltered` whenever it actually
shrinks a group, and `subnetInterface` omits the selector for such a group —
falling back to Kea address-based subnet selection, the same mechanism every
multi-interface group already uses. This never changes WHICH subnets are served,
only how Kea selects among them. `MembersFiltered` is a runtime marker, excluded
from every marshal (`json:"-"`, `yaml:"-"`) so it cannot reach the
compiled-config dump, the golden compile baseline, or the peer over cluster
config-sync.

Dropping the whole group instead was considered and rejected: for a mixed-RG
group in active/active (say `reth0.80` in RG1 and `reth1.0` in RG2) BOTH nodes
would drop it and DHCP would stop everywhere.

Guards: `pkg/daemon/dhcp_rg_filter_6520_test.go` (node-local member kept beside
a mastered RETH member; node-local-only group survives on a node mastering
nothing; an RG-scoped member of a BACKUP RG is still removed; the flag is set
exactly when the group shrank) and
`pkg/dhcpserver/kea_filtered_group_selector_6520_test.go` (the renderer emits no
per-subnet selector for a narrowed group, and still emits one for an authored
singleton). The two files name their own side of the agreement so a failure says
which half broke.

### DHCP-learned routes and their routing instance: the key shape (#9135)

`collectDHCPRoutes` (`daemon_flow.go`) tags each DHCP-learned route with the
routing instance that owns the learning interface, so `renderDHCPDefaults`
can emit it in the instance's table instead of the default one (#8963). The
lookup crosses a spelling boundary, and the two sides are owned by different
subsystems:

- the **producer** is `RoutingInstance.Interfaces`, which the compiler appends
  VERBATIM from the config token, so the canonical Junos form carries slashes
  (`ge-0/0/1.0`);
- the **consumer** is `lease.Interface`, which is `config.DHCPLeaseIfName` —
  `LinuxIfName` unconditionally (slashes become dashes) plus a `.<vlan-id>`
  suffix for a tagged unit, so `ge-0-0-1` or `ge-0-0-3.50`.

Keying the map on the raw member made the #8963 remedy **inert for the
canonical spelling**: only a dash-authored config ever resolved, and every
other VRF-attached DHCP route fell back to the default context — the exact
behaviour #8963 was filed against. `dhcpLeaseKeysForMember` now inserts each
member under every spelling a lease can present. Three consequences of
`DHCPLeaseIfName` being the consumer's rule shape that set:

1. a lease key can never contain a slash, so the raw config token is not a
   candidate key at all and is no longer inserted;
2. a lease key never carries a unit NUMBER (`DHCPLeaseIfName` has no
   unit-number fallback), so `logicalUnitDeviceKey`'s `base.<unit>` arm —
   correct for the netdev-name family (#8321/#8597) — is wrong here;
3. a member naming the WHOLE DEVICE claims every unit on it (#9063's reading),
   and a tagged unit's lease key is `base.<vlan-id>`, which the device name
   alone cannot produce — so those units are enumerated.

reth is deliberately not resolved: `buildDHCPClientSpecs` keys the lease on the
config interface name with no `ResolveReth`, so a reth client's lease is keyed
`reth0`, which the base spelling already covers.

The renderer-side #8963 tests live in `pkg/frr` and hand-build `DHCPRoute`
literals, so they are upstream-blind by construction — the fixture's shape is
why the defect survived the fix. `dhcp_route_vrf_key_shape_9135_test.go` drives
`collectDHCPRoutes` and, separately, `assembleFRRConfig`: severing
`DHCPRoutes: d.collectDHCPRoutes()` there previously killed zero tests.

### Out-of-band `rg_active` writers must re-arm the reconcile retry (#6530)

`rgStateMachine` (`rg_state.go`) tracks a desired `active` value and an
`applied` marker, and `reconcileRGState`'s retry predicate is
`tr.Changed || s.NeedsApply()` — i.e. "the desired value moved, or the last
apply did not converge". `applied`/`applyPending` are advanced only by
`MarkApplied` and `ApplyIfCurrent`, and **neither has a path that SETS
`applyPending`**: both only CLEAR it, when `applied == active`.

That makes the retry structurally blind to any writer that changes `rg_active`
in the dataplane WITHOUT going through the state machine's transition path.
After such a write the machine still believes `desired == applied`, the
reconcile pass does nothing, and nothing else re-arms it — so forwarding stays
wherever the second writer left it, permanently. It is a blackhole with no
retry, not a glitch the next 2 s tick repairs.

`fenceAllRedundancyGroups` (`daemon_ha_sync.go`) is the instance that surfaced
this. A received peer fence writes `SetRGActive(rg, false)` directly; before
the fix a fenced primary never came back, because the reconcile pass that
exists precisely to restore it could not see that anything had changed. (The
fence itself is opt-in on the SENDING node — `set chassis cluster peer-fencing
disable-rg` or `disable-rg-confirmed`, `heartbeat_manager.go` — but the
RECEIVING side is wired unconditionally, so a node with no fencing configured
is still exposed to a peer that has it.)

#7147: `fenceAllRedundancyGroups` now RETURNS a `cluster.FenceResult` reporting
how many RGs it drove to `rg_active=false` out of how many the live config
holds, so a sequenced fence can be acknowledged truthfully. Two rules for
anyone editing it: count a group only on a CLEAN `SetRGActive`, matching the
"not known to have converged" reading the `InvalidateApplied` rule below
already takes; and leave `DataplaneAvailable` false on the config-only path
rather than returning a vacuous 0-of-0 success, which the peer would read as
"this node is safely dark" when nothing was attempted.

The fix is the class, not the call site: `rgStateMachine.InvalidateApplied()`
re-arms the retry, and the fence calls it after each write. Rules for any
future writer:

- Call `InvalidateApplied()` **after** the write, so the reconcile pass that
  observes the re-armed retry runs against settled dataplane state.
- Call it on **failure as well as success**. A write that returned an error may
  still have partially landed, so "not known to have converged" is the only
  honest reading, and forcing a re-drive is the fail-closed one. It costs at
  most one idempotent re-apply on the next tick.
- `InvalidateApplied` sets `applied = !active` rather than only flipping
  `applyPending`, preserving the invariant `reconcileLocked` relies on
  (`applyPending` is true exactly when `applied != active`).
- The one deliberate exception is `daemon_run_shutdown.go`'s
  `SetRGActive(..., false)`: the daemon is exiting and there is no later
  reconcile pass to arm.

Bound honestly: ordering between two unsynchronised `rg_active` writers is not
something the state machine can resolve. What `InvalidateApplied` guarantees is
that the machine never *silently* believes a convergence it did not observe.
Guards: `TestFenceRearmsReconcileRetry` (end-to-end through two real reconcile
passes) and `TestInvalidateAppliedRearmsAnySecondWriter` /
`TestInvalidateAppliedKeepsStructInvariant` (the generic second-writer
contract), all in `rg_state_fence_rearm_6530_test.go`.

### A completing apply must not erase a debt armed while it was in flight (#6799)

This section used to end by conceding that *"if a concurrent event-handler apply
stamps `applied` after the fence's write, the retry is disarmed again"*. That
concession was the defect, and #6799 closes it.

The reconcile loop captured a transition under `s.mu`, dropped the lock, ran
`SetRGActive` off-lock — an IPC round-trip to the Rust helper — and then recorded
the result with an **unguarded `MarkApplied(tr.Active)`**. A fence landing inside
that window armed the debt and the completing apply erased it: `applied` becomes
the value written, which now equals `active`, so `applyPending` is cleared.

**The erasure is permanent, not transient.** `reconcileLocked` only *sets*
`applyPending` when `applied != active`, and after the erasure they agree — so
nothing re-arms it, `tr.Changed || s.NeedsApply()` never fires again, and
forwarding stays wherever the out-of-band writer left it. That is #6530's
"fenced-then-recovered primary stays dark forever", reopened.

**The epoch cannot detect it, which is why the fix is keyed elsewhere.**
`InvalidateApplied` deliberately does not bump the epoch, and even if it did, the
desired-value fallback would accept the record anyway. So the state machine
carries an **invalidation counter**: `InvalidateApplied` bumps it, `rgTransition`
carries the value observed when the transition was produced, and a record is
refused when it moved.

Two further things #6799 changed, both of which were latent hazards rather than
the reported bug:

- **One decision, one lock hold.** `recordRGActiveAppliedIfCurrentOrStable` took
  *three* separate holds (`ApplyIfCurrent`, then `CurrentDesired`, then
  `MarkApplied`), so the state it decided on could move between the decision and
  the act. It is now a thin wrapper over `rgStateMachine.RecordApplied`, which
  decides and acts under a single hold — the same no-cached-boolean discipline
  `pkg/ra`'s `finishDrainDecision` settled on.
- **One recorder for all six sites.** Four cluster/VRRP event handlers already
  used the guarded helper; the two reconcile-loop arms called raw `MarkApplied`.
  All six now route through `RecordApplied`, and the shared body
  (`markAppliedLocked`) makes the #757 log-once gate reset structurally identical
  rather than pinned by a duplicate test. `ApplyIfCurrent` was removed once it
  had no production caller, and its two tests moved onto `RecordApplied` rather
  than being deleted.

The reconcile arms also treat a REFUSED record as "not converged": the activation
arm only raises `setLocalFailoverCommitReady` inside the accepted branch, because
that flag gates a **peer failover commit** (`waitLocalFailoverCommitReady` →
`cluster.requestPeerFailover`) and must never be raised off a convergence the
machine declined. Lowering it stays unconditional — lowering readiness is always
safe. Guards: `rg_apply_invalidate_race_6799_test.go`, whose wiring cell lands
the fence *inside* the in-flight `SetRGActive` (the #6530 test fences between
passes, which is sequential and cannot reach this window).

**Where the wiring lives (#6428).** `startClusterComms` was a 602-line
constructor; the sub-constructions were extracted verbatim into thirteen focused
builders in **`daemon_ha_comms_wiring.go`** (VRF-device resolution, HA watchdog
heartbeat, sync-transport selection, session-sync transport refs, fabric gRPC
listeners, the config / peer-lifecycle / remote-failover callback groups, the
cluster peer-failover hooks, fence wiring, event-stream wiring, the auxiliary
comms loops, and the fabric-forwarding loops). What stays in
`daemon_ha_sync.go` is the control-flow spine, because **the order is the
contract** and it is documented on `startClusterComms` itself:

- `beginClusterCommsEpoch` first — every goroutine below captures its
  sub-context and every publish presents its generation;
- `resolveClusterVRFDevice` before the heartbeat goroutine and the constructor
  goroutine (both take `vrfDevice` by value);
- `syncRGStrictVIPOwnershipMode` before the heartbeat goroutine, so `rg_active`
  already follows VIP ownership once VRRP starts driving it;
- `clusterCommsWG.Add(1)` on the caller's stack, never inside the goroutine, so
  `stopClusterComms` cannot `Wait()` past an unregistered constructor;
- inside the constructor: resolve → build `ss` → `publishSessionSyncIfCurrent`
  → **all** wiring → `ss.Start`. Every `ss.On*` callback, cluster-Manager hook
  and `SetVRFDevice` must be installed before `Start`, which spawns the
  accept/connect goroutines whose first connection runs the authoritative
  cold-prime bulk;
- `wireUserspaceEventStreamForSync` before the `ss.Start` retry loop — its
  result selects which drain loop that loop launches;
- fabric refresh channels published before `startFabricForwardingLoops` hands
  each loop its own channel by value.

The five blocks that carry a `return` out of the constructor goroutine (address
resolution, fab1 resolution, `ss` construction + publish, the `ss.Start` retry
loop, the fabric-channel publish) were deliberately NOT extracted: turning those
escapes into sentinel returns is exactly the rewrite that can change which
later phases still run — the `ss.Start` loop must fall through to the auxiliary
loops when all 30 attempts fail, but must NOT when the context was cancelled.

**Goroutine lifecycle: only ONE of eleven is joined.** `clusterCommsWG.Add(1)`
appears exactly once in the tree — it tracks the session-sync constructor
goroutine, and `stopClusterComms` joins only that one. The other ten goroutines
this path spawns (`startHeartbeatWithRetry`, the HA watchdog ticker, the gRPC
fabric-listener poller and its inner listener, `eventStreamFallbackLoop` /
`runUserspaceEventStream`, `syncIPsecSAPeriodic`, `configSyncReconcileLoop`,
`populateFabricFwd{,1}`, `monitorFabricState`) are context-cancelled only,
never joined. That asymmetry is the structural reason **#7257** is reachable:
`stopClusterComms` cancels the context, joins only the constructor, and then
calls `d.cluster.StopHeartbeat()` — which nils the heartbeat handles under
`m.mu` while an unjoined `startHeartbeatWithRetry` goroutine may still be
inside `StartHeartbeat` dereferencing them unlocked. #6428 did not move
`startHeartbeatWithRetry` and did not change the lifecycle; #7257 needs a
lifecycle fix, not a code move.

**The wiring was unbound when #6428 measured it.** `go tool cover -func` over
`./pkg/daemon/` reported **0.0% statement coverage** for all ten builders that
live inside the constructor goroutine, and nilling all 30 wiring assignments at
once left `./pkg/daemon/` and `./pkg/cluster/` fully green. The tests that do
call `startClusterComms` deliberately configure it to early-return before the
goroutine. `cluster_comms_wiring_bound_6428_test.go` now binds the 17
observable sites — the 15 `ss.*` handles plus `d.syncPeerAddr{,1}` — by calling
each builder directly and asserting the installation, each site mutation-proven
(unwire it, the test reds naming that field). The remaining 13 sites are the
`d.cluster.Set*()` hooks and `ss.SetAuthProvider`/`SetSyncTransport`;
`cluster.Manager` exposes no getter for any of them, so binding those needs an
observation seam in `pkg/cluster`.

### Per-RG Router-Advertisement reconcile (#5861)

In cluster mode RA senders run ONLY on the RG that is the current active
owner: the desired RA set is the union of `buildRAConfigs` filtered to the
RGs this node is MASTER for. Every RA-affecting cluster event —
a day-2 config commit, a VRRP MASTER/BACKUP transition, and a periodic
dropped-event safety pass (`reconcileRGState`) — funnels through the single
authoritative applier `reconcileClusterRAServices` (`daemon_ra_reconcile.go`).

Before #5861 the cluster commit path SKIPPED `ra.Apply` (RA was managed
only by ownership events) and `reconcileRGState` re-applied RA only on an
`rg_active` transition (`if tr.Changed`). So a day-2 RA edit (add/remove
prefix, change DNS/MTU/lifetimes/options) on an RG that stayed MASTER never
reached `ra.Apply` and the primary kept advertising the OLD set until
failover/restart. `reconcileClusterRAServices` now re-applies RA on the
active owner whenever the effective desired set changes even when ownership
is stable, and `ra.Apply` diffs safely (no RA gap for unchanged senders).

**Owner gating + demotion-race guard.** The desired set is built from
`snapshotRethMasterState()` — an RG's interfaces are included ONLY while
this node is its active owner. The ownership snapshot and the `ra.Apply`
run under `raReconcileMu`, and the VRRP demote path updates rg-state
(`SetVRRP`/`Reconcile`) BEFORE it drives the RA reconcile. So a config apply
that races a demotion either snapshots the RG as already-inactive (its
senders are withdrawn / never armed) or snapshots it active — in which case
the node genuinely was the owner at apply time and the demote's own reconcile
pass, serialized behind this one on `raReconcileMu`, withdraws immediately
after. An inactive owner never transmits; a removal emits the lifetime-0
goodbye only from the current owner (`ra.Apply`'s graceful-withdraw path).

**Idempotence.** A stable digest of the desired set (`lastRAReconcileHash`,
updated only on a successful apply) gates the actual `ra.Apply`, so the
periodic safety pass costs nothing when nothing moved and a transient apply
error is retried on the next pass rather than latched as converged. For the
digest to be stable, `desiredClusterRA` sorts the desired set both BY interface
(the ownership snapshot iterates maps) AND, within each interface, its
`Prefixes` slice (`sortRAPrefixes`). Without the within-interface sort, 2+
DHCPv6-PD-delegated prefixes targeting one RA interface would append in
`DelegatedPrefixesForRA`'s map-iteration order — nondeterministic — and, because
the digest marshals order-sensitively and `ra.configEqual` compares prefixes
index-by-index, the every-2s reconcile would FLAP the hash and spuriously
re-apply RA (a sub-second RA gap + a per-poll-tick apply log). The in-place sort
is safe because `buildRAConfigs` returns freshly-owned configs (#6036).
Relatedly, `buildRAConfigs` is a pure builder the periodic reconcile now re-runs
every tick, so its per-PD-prefix "advertising prefix via RA" line logs at
`slog.Debug`, not `Info` — an `Info` there would be per-poll-tick spam (#6036).

### Direct-mode VIP failover (private-rg-election / no-reth-vrrp)

When `no-reth-vrrp` or `private-rg-election` is configured, the daemon owns
VIP add/remove and the post-failover GARP directly (there are no VRRP
instances). `directSendGARPs` (`daemon_ha_vip.go`) sends a broadcast GARP
burst per VIP plus a supplementary **directed** ARP probe to the subnet
gateway so a router that ignores broadcast gratuitous ARP still re-binds the
VIP to the new master's MAC. The probe target is derived by the single source
of truth `vrrp.GatewayProbeTarget(ipNet)` — the subnet's first usable host
(network address + 1), respecting the actual prefix length, returning
`ok=false` (skip the directed probe) on /31 (RFC 3021) and /32 where no
in-subnet gateway host exists. Before #3922 this site forced the last octet
to `.1`, which lands OUTSIDE the subnet on /25+ or a non-.0 network (e.g. VIP
`10.0.61.18/28` → `10.0.61.1`, outside `.16-.31`) → the directed probe hit a
foreign address and the real gateway's ARP cache was never updated → post-
failover blackhole until the stale entry aged out. #2377 fixed the identical
forced-.1 in `vrrp.sendGARP` but missed this direct-mode site; #3922 routes
both through the shared `vrrp.GatewayProbeTarget` helper.

## Interface management

`enumerateAndRenameInterfaces()` runs at startup (in `linksetup.go`),
writes `.link` files for every PCI-enumerated NIC, and assigns vSRX names
based on PCI bus order plus the cluster node ID. RETH members match by
`OriginalName=` (PCI kernel name), not `MACAddress=` — the MAC alternates
between physical and virtual at boot, and `ensureRethLinkOriginalName()`
auto-fixes stale `.link` files.

It **returns an error when naming does not converge** (#5842). Every step
that can fail — the `.link` write, the rename, and the `networkctl reload`
— accumulates into one aggregate that `enumerateAndRenameInterfaces`
joins and returns, mirroring the device-map path's `renameErrs` (#4956).
The pass still COMPLETES on a failure rather than abandoning midway: a
half-renamed NIC set is worse than a finished-and-reported one.

`writeLinkFile` and `writeBootstrapFxp0Network` return `(changed, error)`
for the same reason. A single `bool` made `false` mean BOTH "already
correct, nothing to do" and "the write failed" — opposite facts under one
value, so no caller could have distinguished them even if it wanted to.

This matters beyond diagnostics: `maybeReapplyConfigArrivalNaming` consumes
the one-shot `emptyHANamingPending` marker only when
`applyStartupNamingForConfig` returns nil. Positional mode always returned
nil, so a #4179 config-less HA node whose renames all failed burned its
single retry and stayed on standalone names until a restart — the failure
#4956 had already fixed for the mapped path, still open on the default one.

`deriveKernelName()` synthesizes that predictable kernel name from a NIC's
sysfs PCI address via `pciAddrToEnp()`, which mirrors systemd's
`ID_NET_NAME_PATH` scheme (`systemd.net-naming-scheme(7)`):
`en[P<domain>]p<bus>s<slot>[f<func>]`. The `P<domain>` segment is present
ONLY when the PCI domain is non-zero, so single-domain systems (domain 0000
— the test VM and loss cluster) keep the bare `enp<bus>s<slot>[f<func>]`
form, while multi-PCI-domain hardware gets the domain prefix that stops two
NICs at the same bus/slot in different domains from resolving to the same
name (#6199). All fields are parsed hex / rendered decimal to match systemd.

Any interface not declared in the active config is brought down and given
`ActivationPolicy=always-down` in networkd — EXCEPT the #1922 protected set
(see below).

### NIC tuning ownership + released-interface teardown (#6801)

Two per-interface knobs are written to the mlx5 NICs the userspace
dataplane binds AF_XDP on:

- the **RSS indirection table** (`rss_indirection.go`, D3 / #785) — hash
  outputs are concentrated onto queues `0..workers-1`;
- **interrupt coalescence** (`coalescence.go`, #801 Step-0) — adaptive
  off, `rx-usecs`/`tx-usecs` pinned.

Both take their target set from ONE allowlist,
`dpuserspace.UserspaceBoundLinuxInterfaces(cfg)`, recomputed from the
**new** compiled config on every reconcile — so both were blind to an
allowlist that SHRANK. Binding `{ge-0-0-1, ge-0-0-2}` and then committing
a config that binds only `ge-0-0-1` left `ge-0-0-2` with xpf's
concentrated RSS table and adaptive-off/pinned-usecs coalescence: every
loop walked the new set, so nothing ever visited the released name. The
coalescence capture was reverted only at daemon shutdown; the RSS table
was never reverted at all. A NIC handed back to the host stack or to
another dataplane stayed limited to the old AF_XDP queue subset.

`released_nic_tunables.go` closes that with a level-triggered
`owned - current` teardown, run from `applyStep0TunablesWith` (which
executes at boot AND on every commit):

| Step | Function | What it does |
|------|----------|--------------|
| release | `releaseUnboundNICTunables` | For each owned interface absent from the current allowlist: `ethtool -X <if> default` + restore the captured pre-xpfd coalescence, then drop ownership |
| claim | `claimNICTunableOwnership` | Union the current allowlist's mlx5 members into the owned set |

Ownership is two records, unioned, because the knobs diverge on error
paths: `priorHostTunables.rssOwned` (a set — the restore is the
idempotent `ethtool -X default`, so no prior table has to be captured)
and `priorHostTunables.mlx5Adaptive` (the coalescence capture, which
exists only when the `ethtool -c` probe parsed).

Invariants worth keeping:

- **Ownership is released only after the restore write SUCCEEDS.** A
  failed `ethtool` keeps the interface owned, so the next reconcile
  recomputes the same released set and retries. No timer is needed —
  a released name stays outside the allowlist until it is re-bound.
  Same shape as the #5114 host-scope retry debt.
- **An empty allowlist is NOT, by itself, a withdrawal.**
  `UserspaceBoundLinuxInterfaces` degrades to nil when its snapshot build
  fails (#2514), and `applyTailReconciles` still runs the tunable step on
  a commit whose dataplane apply failed. Treating "no names" as "release
  everything" would let a transient derivation error rip the tuning off
  NICs the dataplane is still forwarding on, and `ethtool -X ... default`
  mid-traffic re-steers in-flight flows onto different RX queues. The
  withdrawal trigger is therefore the CONFIG signal — `userspaceDP ==
  false`, a pure config read with no error path — never an empty list.
  With userspace-dp still enabled and an empty list, ownership is
  retained untouched, mirroring the refusal `applyRSSIndirection` and
  `applyCoalescence` already make.
- **A released name that is no longer an mlx5 netdev drops ownership
  without an ethtool call.** Unplugged, renamed by a `.link` change, or
  rebound to another driver — the ring/coalescence configuration went
  with it. This honors the "never invoke ethtool on a non-mlx5 netdev"
  guard (#797 H1) and stops retry debt growing without bound on a NIC
  that can never accept the restore.
- **The claim is config-derived, deliberately a superset** of "actually
  reprogrammed this reconcile". Over-claiming costs at most one extra
  idempotent `ethtool -X <if> default` on release — the same call the
  rss-indirection kill switch already issues on exactly this set.
  Under-claiming is the defect: a NIC xpf tunes but never records can
  never be handed back.

#6801 scopes itself to interfaces that leave xpf's ownership **while the
daemon keeps running**. The stop case is #7619, below.

### Restoring the RSS table on daemon stop (#7619)

`restoreStep0TunablesOnShutdown` reverted coalescence, host-scope knobs
and neigh `retrans_time_ms` but NOT `rssOwned`, so a clean `systemctl
stop xpfd` left every bound mlx5 NIC with its hash outputs concentrated
onto queues `0..workers-1`. The kernel stack then ran on a table shaped
for a dataplane that was not there, until the next boot re-claimed the
NIC or an operator ran `ethtool -X <if> default` by hand. It is the same
end state #6801 fixed for a released interface, reached by the other
door.

`restoreOwnedRSSOnShutdown` closes it, and three decisions are worth
recording because the issue left them open:

- **It runs on EVERY stop, including a restart's.** systemd delivers an
  ordinary SIGTERM either way and exposes nothing at stop time that
  separates them, so "exempt a restart" is not implementable — the
  choice is restore-always or restore-never. Restore-always costs a
  restart two `ethtool` calls per owned NIC (default the table, then
  re-concentrate on the next start) across a window in which the daemon
  is not forwarding anyway. Restore-never is the defect.
- **Bounded by `rssShutdownRestoreBudget` (5s)**, mirroring
  `hostAuthCloseoutBudget` (#5874). One `ethtool` round-trip per owned
  NIC on a path the unit caps at `TimeoutStopSec=20`: a hung `ethtool`
  must cost a logged timeout, not a SIGKILLed daemon. The walk is
  name-sorted so a truncation is deterministic, and it truncates rather
  than aborting — a failure on one NIC does not abandon the rest.
- **The retry debt is logged and left**, unlike #6801's. That path drops
  ownership only after a successful restore so a later reconcile tick can
  retry; a stop has no later tick, and the in-memory ownership map exits
  with the process. Reconciliation is the next boot's claim, which
  re-captures and re-applies. A NIC left concentrated by a failed
  restore-on-stop is stranded only if xpfd never starts again — a case no
  shutdown path can fix.

**The empty-captures guard is part of the contract.**
`step0RestoreHasCaptures` decides whether the shutdown restore has any
work; a NIC with ONLY rss ownership (no host-scope opt-in, no coalescence
capture, no neigh retrans) must admit, or the restore call added below it
never runs and the defect survives its own fix. Adding a fifth capture
kind without adding it to that predicate is the same bug again. The
restore body lives in `restoreStep0Captures`, split from the snapshot
handoff (apply-lock, `priorTunablesMu`, one-shot clear) so the wiring
itself is reachable from a test with injected backends — #7619 was a
missing CALL, not a broken function, and a test that only exercises the
leaf cannot see it.

## Bootstrap mode + management lifeline (#1922)

`bootstrap.go` implements the SAFE-BOOTSTRAP daemon state so the daemon can
never lock an operator out of a remote box it manages.

- **Five-case boot predicate** (`computeBootClass`, computed once in `Run`
  after `Store.Load` + `bootstrapFromFile`): fresh / never-committed →
  **bootstrap**; valid `active.json` / clean day-0 import /
  operator-committed-empty → **normal**; corrupt/too-new → fail-safe (already
  fatal via #1917 D1). The **HA-node guard** keys on `/etc/xpf/node-id` FILE
  presence (NOT the config-derived `clusterMode`): a node-id node always
  resolves NOT-bootstrap.
- **Fail-closed on compile failure (#1960):** a PRESENT, previously-committed
  `active.json` that is valid JSON but no longer COMPILES (even through the
  tolerant `compileTreeLenient` path) is the dangerous tuple
  `ActiveConfig()==nil` + `EverCommitted()==true`. Without a guard, that
  tuple resolves to **normal** and runs the positional claim-all rename on a
  box whose intended config is unknown. `Store.Load` now tags this error with
  `configstore.ErrConfigCompile`; `Run` classifies it via `classifyLoadError`,
  logs it loudly (Error), SKIPS `bootstrapFromFile` (so the text `xpf.conf` is
  not blind-imported over the broken DB), and passes `configCompileFailed=true`
  to `computeBootClass`, which forces **bootstrap** — overriding even the
  HA-node guard. The control plane stays up so the operator can recover
  in-band. A daemon hard-exit is deliberately NOT used (it would also strand
  mgmt). Distinct from `ErrConfigDBUnreadable` (#1917 D1, which IS a fatal exit
  because the bytes themselves cannot be read).
  - **The boot commit-confirmed recovery reaches the same guard (#6538).** A
    `commit confirmed` window that expired while the daemon was down is
    resolved inside `Store.Load` by `recoverPendingConfirmLocked`, which
    reverts to the record's `PrevTree`. That tree is a previously-committed
    config, but `Load`'s tree repairs (`rewriteRetiredDataplaneType`,
    `SanitizeTreeControlChars`) run only on `active.json`, never on the
    `PrevTree` inside `confirm.json` — so a target committed on an older build
    (`system dataplane-type ebpf` is the concrete case) can fail even the
    lenient compile. That branch used to warn, assign the nil into
    `s.compiled`, set `everCommitted = true`, and let `Load` return SUCCESS —
    reconstructing the exact dangerous tuple above and bypassing this guard.
    It now returns an `ErrConfigCompile`-tagged error, so the recovery lands in
    `loadCompileFailed` like any other uncompilable committed config. The
    rollback itself still completes first: the unconfirmed config must not
    stand, and the reverted tree has to stay reachable for in-band recovery.
  - **Why mgmt stays reachable — freeze in last-known-good, not a wipe.** This
    path does NOT run the `enterBootstrapMode()` teardown (which removes the
    `10-xpf-*` `.network`/`.link` files, clears the FRR managed section, and
    tears down the dataplane); that teardown is reserved for confirmed-commit
    rollback. On a previously-committed box the last-good networkd + FRR state
    therefore persists untouched, so the box stays reachable at its EXISTING
    management address (rather than dropping to bootstrap fxp0-DHCP and
    possibly changing the IP out from under a connected operator) while the
    config is fixed. That is a deliberate choice: the only thing the box must
    NOT do on an uncompilable config is the *new* takeover (positional
    claim-all / fresh apply), which bootstrap suppresses. The lifeline/protected
    set govern the rename + apply sweeps and the fresh-install case; they are
    not what keeps a *previously* managed box reachable here.
    - **Transit is still fail-closed** — do not read "freeze" as "the firewall
      keeps forwarding." Bootstrap mode suppresses `enableForwarding` and the
      dataplane arm (`dp.Start`), and since #5275 it also explicitly WRITES
      `ip_forward` / `ipv6.conf.all.forwarding` to `0`
      (`applyBootTransitPolicy`), so the daemon itself forwards no transit in
      this state. The explicit close is load-bearing, not belt-and-braces:
      sysctls outlive the process, so a daemon *restart* into this state used
      to inherit `ip_forward=1` from the previous armed run and route transit
      with no policy attached. A cold reboot carries NO transit until the
      operator commits a compilable config; only a daemon restart that leaves
      an already-armed dataplane *process* running keeps enforcing the
      last-known-good policy in the interim. Either way no traffic is forwarded
      under an unknown/no policy — what persists is interface identity + mgmt
      reachability, not unpoliced forwarding.
  - **In-band recovery is real (not just "repair the DB").** On compile failure
    `Store.Load` keeps `compiled` nil (the fail-closed signal) but retains the
    parsed-but-broken tree as the active tree and loads the on-disk rollback
    history. So `configure` clones the broken config into the candidate (the
    operator can `show`/edit the offending stanza), `rollback N` /
    `show | compare rollback N` reach prior good configs, and a
    `commit confirmed` of either promotes a working config. Repairing/removing
    the on-disk DB remains the out-of-band fallback.
  - **FRR managed section is cleared on a compile-failed boot unless forwarding
    is genuinely live (#1993).** `frr` is an independent service that starts from
    its persisted `frr.conf` (the managed section from the last good
    `applyConfig`), which freeze-in-last-known-good leaves intact. On a
    compile-failed boot where the dataplane is unarmed (no transit), FRR would
    otherwise still form peerings and advertise the last-good prefixes — peers
    route transit to this node's physical IPs and it blackholes them rather than
    failing over to the HA partner. To close that cross-daemon gap, the
    compile-failure boot path calls
    `clearFRRForFailClosedBoot(configCompileFailed)` immediately after the FRR
    manager is constructed (`d.frr = frr.New()`).
    - **The preserve decision requires LIVE FORWARDING, not just pins.** Pins on
      `/sys/fs/bpf/xpf/links` prove only that an XDP link is *attached*, not that
      forwarding is *live*: a graceful hitless shutdown (`dp.Close()` →
      helper `Close()` → `stopLocked` disables `ctrl.enabled`; the BPF `Close()`
      deliberately leaves pinned maps/links for the next daemon to reuse) leaves
      the pins in place while forwarding is STOPPED. A pin-only guard would read
      "pins exist" and wrongly preserve FRR on a graceful restart, recreating the
      blackhole. The decision is therefore two stages: (1) **pins are a cheap
      pre-filter** — no `xdp_*` pins (e.g. a cold reboot cleared the bpffs tmpfs)
      ⇒ no surviving dataplane ⇒ CLEAR, skipping the socket probe (a pin-probe
      *error* does not preserve; it falls through to stage 2); (2) **the
      authoritative signal** is a lightweight one-shot status query against any
      PRE-EXISTING helper on its control socket
      (`dpuserspace.ProbeForwardingArmed` → `ProcessStatus.Enabled &&
      ForwardingArmed`, the same pair the runtime gates forwarding on). FRR is
      preserved **only** when that probe says forwarding is live. Every other
      outcome — socket missing / connect-refused / timeout / `Enabled=false` /
      `ForwardingArmed=false` / probe error — **clears** (fail toward fail-over:
      an unarmed/unknown helper is not forwarding). The control-socket path is
      resolved the same way the runtime Manager resolves it
      (`DefaultControlSocketPath` → `deriveUserspaceConfig`); a compile-failed
      boot has a nil active config, so it uses the default path (matching a
      surviving helper from a default-config deployment), and a custom-path
      deployment falls back to the default → probe finds nothing → clears
      (safe direction). Both the pin pre-filter
      (`failClosedBootHasPinnedXDPLinks`) and the armed probe
      (`failClosedBootForwardingArmed`) are package-var seams so the decision is
      unit-tested without a real helper; the pure decision is
      `failClosedBootShouldClearFRR`.
    - When the decision is CLEAR, `d.frr.Clear()` strips ONLY the managed
      section and reloads FRR. Dropping those peerings makes upstream/peers fail
      over to the HA partner instead of blackholing transit. This is the SAME
      primitive `enterBootstrapMode()` uses, but it deliberately runs *only* the
      FRR-clear step — NOT the `.network`/`.link` removal or link-cycle — so
      freeze-in-last-known-good MANAGEMENT reachability (the existing mgmt IP) is
      preserved. Normal/fresh-install boots remain byte-identical, and it is
      fully reversible: the first compilable `commit confirmed` (or a cluster
      `SyncApply`) re-renders FRR via `applyFRRConfig` and re-installs the
      managed section. A degraded reload (`ErrFRRReloadDegraded`) is logged, not
      fatal — `Clear()` has already written the empty managed section to disk, so
      a later FRR restart converges. The VIP/RETH data path already failed over
      before this fix because #1960 suppresses this node's VRRP/cluster.
    - **Residual (cross-daemon ordering):** FRR is an independent systemd
      service and may advertise last-good prefixes from its OWN start before
      xpfd reaches the clear. The clear collapses that window once the peerings
      drop (peer hold-down then carries transit on the partner). A unit-ordering
      change (`xpfd` clears FRR before FRR forms peerings) would shrink the
      window further but is a separable follow-up, not required for the Go fix.
- **Bootstrap mode** (`d.bootstrapMode` atomic): runs gRPC/REST/CLI normally
  but SUPPRESSES interface takeover ACTIONS — the full rename loop, host
  tunables, `enableForwarding`, dataplane arm (`dp.Start`), the boot-time
  `applyConfig`, and the #2079 NAT pool-alarm monitor start (#2114: the
  monitor samples the dataplane cell, which a bootstrap-exit arm failure
  clears, so it must not run during the bootstrap window). Managers are
  still constructed (so the exit reconcile wires every subsystem). A plain
  first `commit` is REFUSED — the operator must `commit confirmed`. Exit is
  one-way, on the first non-empty config apply (confirmed commit OR cluster
  `SyncApply`); `runBootstrapExitStartup` then runs the deferred startup
  takeover (including starting the NAT pool-alarm monitor on a successful
  arm) before the reconcile.
- **PCI-keyed lifeline** (`setupBootstrapLifeline`): in bootstrap mode the
  daemon detects the default-route mgmt NIC (v4 then v6, else refuse +
  console), records its PCI+MAC to `/etc/xpf/lifeline-interface` (keyed by
  PCI, survives rename/restart/rollback), and — only if that NIC is
  enumeration index 0 — renames just it to fxp0 and snapshots its addressing
  into the bootstrap `.network`.
  - **Appliance factory boot (#7114).** The default-route signal does not
    exist on the appliance image: `scripts/image/bake.py` purges cloud-init
    and deletes every netplan / `interfaces.d` file, so a factory boot (no
    day-0 drive) has no route, no address, and no `.network` anywhere — and
    the refusal above left every port DOWN and unrenamed, console-only, which
    contradicts the image's shipped vNIC#1 → fxp0 factory contract
    (`docs/install-images.md`, PR #1906). One discriminator resolves it: the
    bake writes `/etc/xpf/appliance`, and the daemon (`isApplianceFactoryBoot`)
    falls back to the FIRST ENUMERATED NIC only when that marker is present
    **and** `EverCommitted()` is false. Selection itself is the pure
    `chooseBootstrapLifeline` — a default route always wins; the fallback
    applies only when there is no route at all. Both halves of the gate are
    load-bearing: the marker keeps the #1922 refusal intact for foreign-host
    `.deb` installs (the postinst never writes it), and `!everCommitted` keeps
    it intact for the #1960 fail-closed boot, where a box that HAS been
    configured (possibly with a device-map that wants no auto-fxp0) is in
    bootstrap because its committed config stopped compiling. Steps 2-4 above
    are unchanged and run identically for either provenance.
  - **Incomplete addressing observation refuses (#6789).** `setupBootstrapLifeline`
    is a chain of fail-closed refusals — no default route, NIC enumeration
    failed, not enumeration index 0 — each of which logs and returns having
    mutated NOTHING. The addressing snapshot used to be the one observation
    that GUESSED instead. `interfaceAddrSnapshot` returned empty slices on a
    `LinkByName` failure and discarded the `AddrList` error, while its sibling
    `isDHCPManaged` was documented to return false on any uncertainty so the
    writer would snapshot static addresses — the SAFE direction. The writer
    asked `isDHCPManaged(x) || (len(v4) == 0 && len(v6) == 0)`, so the very
    failure that made `isDHCPManaged` fail safe also emptied the address list
    and drove the OR into the DHCP branch. **Two helpers reading the same
    netlink state failed in opposite directions, and the unsafe one won.** A
    statically-addressed management NIC then received a `DHCP=yes` `.network`
    and was renamed — and the rename cycles the link, so the static address
    went away on a box reachable only over that NIC, in bootstrap, with no
    committed config to roll back to.

    Both helpers are now one typed observation, `snapshotLifelineAddrs`, which
    returns an error instead of an empty result and folds the DHCP-lease
    heuristic into the SAME netlink walk (they were two walks over one state,
    which is what allowed them to disagree). An incomplete observation aborts
    `setupBootstrapLifeline` **before** the `.link` write, the rename and the
    reload, matching what every other refusal in that function already does and
    the "selects nothing" console-only posture `chooseBootstrapLifeline`
    documents.

    The refusal is **scoped to a lifeline chosen by DEFAULT ROUTE**, which is
    positive evidence the NIC carries live addressing the rename must reproduce
    under the fxp0 name. The appliance factory lifeline above is chosen
    precisely when there is no default route, so there is no addressing to
    reproduce and DHCP is the image's documented contract: a failed observation
    there cannot change a byte of the output, and refusing would break the
    factory boot to guard information that was never going to be used. For the
    same reason a route-dump failure is fatal only for a family the snapshot
    HAS addresses in — the family whose `Gateway=` line would otherwise be
    missing. The netlink calls sit behind injectable seams
    (`lifelineLinkByName` / `lifelineAddrList` / `lifelineRouteList`) so each
    observation failure is reachable from a test that asserts zero side
    effects.
  - **An unreadable route table claims NOTHING (#6789, the selection half).**
    The same "error reads as a confident answer" shape sits one step earlier, in
    the SELECTION, and there it is worse. `detectLifelineInterface` dumped
    routes with the error discarded (`if err != nil { continue }`), and a failed
    dump returns a nil slice — byte-for-byte what "this box has no default
    route" looks like. The caller BRANCHES on exactly that distinction:
    `applianceFactory := routeIface == "" && d.applianceFactoryBoot()`. So on a
    box carrying the appliance marker that has never committed, a netlink error
    silently flipped selection from "the NIC holding the default route" to
    "the FIRST ENUMERATED NIC" — which is then renamed, and `renameInterface`
    is an explicit `LinkSetDown` → `LinkSetName` → `LinkSetUp`. If the real
    management NIC is not enumeration index 0, the wrong NIC is claimed and the
    management NIC is cycled on a box reachable only over it. It is reachable on
    a real factory box, because the previous boot's lifeline writes an fxp0 DHCP
    `.network`, so the next boot genuinely HAS a default route while
    `EverCommitted()` is still false.

    Note the asymmetry: on a NON-appliance box the identical error is harmless —
    an empty `routeIface` makes `chooseBootstrapLifeline` refuse, which is the
    console-only contract. The appliance marker is what converts a swallowed
    netlink error into a claimed and cycled NIC.

    `detectLifelineInterface` now returns an error and the caller refuses when
    the route state is UNKNOWN (`routeIface == "" && routeErr != nil`). The
    guard keys on the observation having FAILED, never on `routeIface` being
    empty: keying on empty would disable the #7114 factory contract entirely and
    strand every appliance image console-only on first boot. A route that WAS
    found and resolved is positive identification and is used even if another
    family's dump errored — the error only matters when it could have hidden the
    answer. The second swallowed error there (`LinkByIndex` on a found route)
    is propagated for the same reason.
- **Protected set** (`resolveProtectedInterfaces` →
  `dataplane.SetProtectedInterfaceResolver`): fxp0 + the lifeline NIC + an
  explicit `system management-interface` leaf are NEVER marked Unmanaged /
  always-down / address-stripped, even on an empty/absent/rolled-back config.
  An explicit non-fxp0 leaf narrows fxp0 off the auto-protection.
- **First-commit rollback** (`enterBootstrapMode`): a timed-out first
  `commit confirmed` stops+discards the NAT pool-alarm monitor (#2114 — the
  reason is NOT a data race: `dpCell` is an `atomic.Pointer`, so a
  concurrent load against a later re-arm's clear is well-defined. The
  reason is that a surviving sampler would keep issuing control-socket
  calls into a backend the rollback has just torn down. The monitor is
  rebuilt fresh on a corrected re-arm because it is not restartable after
  `Stop`), removes the takeover `.network` files (keeping
  the lifeline + `.link` files), clears the FRR managed section, and
  detaches the dataplane — instead of applying an empty config — and the
  store persists the never-committed marker so a restart re-enters
  bootstrap. The detach also drops the #5275 armed flag and closes kernel
  transit forwarding: the node is un-armed by that step, so leaving
  `ip_forward=1` would let the next apply tail keep routing transit for a
  dataplane that is no longer attached.

## Notable gotchas

- **An 802.1Q sub-interface's netdev is named for its VLAN ID, not its unit
  number — and BOTH sides of a lookup must agree (#8597 K84/K85).**
  `set interfaces ge-0-0-1 unit 10 vlan-id 100` is created by networkd as
  `ge-0-0-1.100`. #8321 finding 07 fixed the PRODUCER of the connected-prefix
  map (`connectedByLogical`, `daemon_run_routehelpers.go`) to key on the VLAN
  ID. It did not touch the CONSUMERS, which kept deriving their key with
  `config.LinuxIfName()` — the unit number — so the producer wrote
  `ge-0-0-1.100`, the consumers looked up `ge-0-0-1.10`, and every VRF-scoped
  lookup missed. Three consumers shared the assumption:
  `riMemberLinuxName` (the VRF bind name — the bind failed against a
  nonexistent device while the commit reported success, leaving the member in
  the main table), `collectPrefixesForInterface` (a VRF-scoped static next-hop
  left without interface scope), and the `claimedByVRF` stamp (a VRF-owned
  interface stayed visible to the GLOBAL table, so a global next-hop could
  resolve onto a tenant's interface).
  The rule now lives in one place, `logicalUnitDeviceKey`, called by the
  producer and by `logicalUnitDeviceKeyForRef` on the consumer side, so the two
  cannot drift apart again.
  Three traps for the next reader:
  - **It is not a substitution of one field for the other.** A unit with no
    `vlan-id` is not tagged, and `base.<unit>` is correct there. Dropping that
    fallback passes every tagged-unit cell and breaks every untagged one.
  - **`config.DHCPLeaseIfName` looks like the same function and is not** — it
    has no unit-number fallback. Its own doc calls unit number and VLAN ID
    "distinct concepts, bridged only here", which is precisely the invariant
    these consumers were violating.
  - **`config.ResolveKernelIfName` is not a drop-in either**: it additionally
    resolves reth to the local physical member and maps tunnel devices, neither
    of which the producer does, so routing a consumer through it trades one
    miss for a different one (`reth0.50`).
  A fixture only sees this when **unit number != vlan-id**; the pre-existing
  cells used units 50/80 with no `vlan-id` and passed against both
  implementations, which is how the producer-side defect survived to #8321 and
  the consumer-side to #8597.

- **Every shutdown-path `applySem` acquire is BOUNDED (#8597).**
  `daemon_run_shutdown.go` states the rule at its own drain — *"bound it
  defensively anyway so a wedged apply cannot block the whole shutdown past the
  drain budget"*. A census of `applySem` acquires reachable from the shutdown
  sequence finds exactly two: that drain, and `stopPolicySchedulerLoop`, which
  used `context.Background()`.

  With an apply wedged, the unbounded one never returned. The scheduler was
  never cancelled, shutdown never reached the HA relinquish that follows, and
  systemd's `TimeoutStopSec` ended the process with SIGKILL — no `rg_active`
  clear, no priority-0 advert, no RA goodbye. A sub-second handover became a
  blackout, from a contained degradation (one wedged apply) that the bounded
  drain right above it was written to survive.

  Bounding an acquire has a second half: **do not release a permit you did not
  take.** The original released unconditionally, which was only safe because
  the acquire could not fail. On a weight-1 semaphore, releasing without
  acquiring raises the count above capacity and admits a second holder
  alongside the wedged apply — from the very path whose purpose is to serialise
  against it. `TestStopPolicySchedulerLoopDoesNotReleaseASemaphoreItNeverTook_8597`
  pins that.

  On timeout the call proceeds to the cancel anyway. Bounding the wait is only
  worth something if the call still does its job: #5308 orders this BEFORE the
  dataplane teardown so no late scheduler tick runs against a closed runtime.

  **Residual, stated rather than implied:** this does not make the join
  unconditionally bounded. A tick already parked in `publishPolicyScheduleState`
  acquires with `d.daemonCtx`, which is the raw parent and is
  production-uncancelled, so cancelling the scheduler ctx does not release it
  and `schedulerWg.Wait()` can still block behind the same wedged apply. What
  the bound removes is the case where the stall happens with no tick in flight
  at all. Closing the rest needs the scheduler's own ctx to reach its updateFn —
  a signature/ownership change rather than a bound. Filed as #8660.

- **An unarmed dataplane stops kernel transit forwarding (#5275).** Kernel
  transit forwarding is CONDITIONAL on the dataplane being armed. The daemon
  tracks that as `Daemon.dataplaneArmed` (accessor `DataplaneArmed()`), set
  true only after `rt.Start()` (→ `LoadUserspaceShim`) returns nil, and the
  gate in `daemon_transit_gate.go` drives `/proc/sys/net/ipv4/ip_forward` and
  `/proc/sys/net/ipv6/conf/all/forwarding` to match it.
  - **Why.** A successful config *compile* followed by an *arm* failure took a
    branch that logged "running in config-only mode", cleared the dataplane
    cell, and fell through to `applyConfig` — while bring-up had already
    raised both knobs and `applyKernelTuning` re-raised them at every apply
    tail. With no XDP shim attached and no nftables `hook forward` chain
    anywhere in the repo (the host-inbound tables are `hook input`), the
    kernel routed transit under zero policy. #1960/#1993 fail closed on a
    compile failure only; this closes the arm-failure sibling.
  - **When it closes.** Every path that lands in `setDataplane(nil)` — the
    boot `rt.Start` failure (`armBootDataplane`), the bootstrap-exit
    `rt.Start` failure (`armBootstrapExitDataplane`), and both retired-backend
    arms (`ErrDPDKBackendRetired` / `ErrEBPFBackendRetired`); the two states
    that never arm at all (bootstrap mode and `--no-dataplane`, via
    `applyBootTransitPolicy`); and the first-commit-confirmed rollback, whose
    `runBootstrapTeardownSteps` step 4 DETACHES an already-armed dataplane
    without passing through either arm writer.
  - **When it re-opens.** A successful arm. Recovery does NOT need a daemon
    restart on the bootstrap path: the bootstrap-exit arm on the first
    compilable `commit confirmed` (or cluster `SyncApply`) re-enables both
    knobs. There is, however, **no re-arm path after a NON-bootstrap boot arm
    failure** — `rt.Start` has exactly two call sites (boot and bootstrap
    exit), and the boot one runs once — so that node stays transit-closed
    until xpfd restarts. Fixing the config and re-committing is not enough;
    `systemctl restart xpfd` is.
  - **How to tell.** The failure logs at **Error**: `dataplane arm FAILED;
    kernel transit forwarding DISABLED (fail-closed, degraded)` with a
    `remediation` attribute. Confirm with `sysctl net.ipv4.ip_forward` (0) and
    `journalctl -u xpfd | grep 'arm FAILED'`.
  - **What still works.** `ip_forward` governs FORWARDED packets only, so
    management is unaffected by design (#1960 no-brick): SSH, gRPC/REST/CLI,
    the cluster heartbeat, and DHCP are locally terminated, and the `hook
    input` host-inbound chains are untouched. The daemon does NOT exit. The
    #7191 nftables barrier is likewise forward-hook only and carries no
    management exemption *because it needs none* — management is INPUT.
  - **How deep the barrier goes (#7191).** The gate is no longer the sysctl
    alone. While unarmed the daemon also installs `xpf_transit_barrier`, an
    unconditional forward-hook DROP, in **both** the `inet` and `bridge`
    families (`pkg/nftables/transit_barrier.go`). The bridge leg exists
    because `ip_forward` does not govern bridged frames at all, and this repo
    creates bridge domains. Before #7191 the repo had **zero** `hook forward`
    chains, so a single sysctl — raisable by a `sysctl.d` drop-in, a systemd
    unit, an operator, or any future code path — was the only thing between an
    unarmed box and kernel routing.

    The barrier is installed and removed from the same `mark*` helpers that
    drive the sysctls, and re-asserted on every apply tail, so a stale barrier
    self-heals rather than silently black-holing armed transit. It is scoped
    strictly to the unarmed window, which is the window `ip_forward=0` already
    covers — so it closes nothing that was open. That scoping is not a detail:
    several ARMED paths deliberately rely on an open kernel forward hook
    (route-based IPsec plaintext off an xfrm interface, SNAT'd frames passed up
    for kernel routing, the #7409 slow-path reinject), and a barrier live while
    armed would drop all three.

    Plan §6's third leg, a flowtable disable, is a deliberate no-op: xpf creates
    no flowtable, so there is nothing to flush.
    `TestNoFlowtableIsEverCreated7191` pins that assumption.
  - **The per-interface attach is now part of the arm state (#7191).**
    `dataplaneArmed` used to track only the `rt.Start()` boundary, so a box
    where Start succeeded but an individual interface failed to attach reported
    itself armed and kept `ip_forward=1` with nothing adjudicating that
    interface. The post-attach arm-coverage proof
    (`pkg/dataplane/armproof.go`), previously observe-only, is now consulted on
    the apply tail and disarms through the SAME `markDataplaneArmFailed` path a
    Start failure uses — one arm state, one set of side effects.

    The gate is one-way (it can only disarm) and three-state: a report that has
    never been published, or one that could not classify, does **not** disarm,
    because gating on a reading that never happened is a brick rather than a
    fence. Note the proof currently conflates "no tracked link" with "the
    link's identity could not be read", so a readback fault disarms like a real
    attach failure — the conservative direction, recorded in
    `daemon_arm_coverage_7191.go`.
  - **The gate is only as good as the verdict it reads, and an ABORTED apply
    used to leave it describing a different one (#7289 R1).**
    `ProveArmCoverage` is the sole publisher of the coverage cell and it runs at
    the TAIL of `CompileUserspaceShim`, so every abort between Phase 2's host
    mutation and that tail returned first. Two reachable states, neither of
    which disarmed: on a box's FIRST apply the cell had never been published, so
    the verdict was `armCoverageUnknown` and the switch above has no case for it;
    on any LATER apply the cell still held the PREVIOUS generation's report,
    which said `Ran=true, Uncovered=0`, so the gate classified **Complete** and
    logged "arm coverage complete" for an apply that had just failed to attach
    anything. `pkg/dataplane/armcoverage_publish.go` states the opposite as its
    own invariant — "a stale report answering for a previous generation is worse
    than no report" — and the abort path is where that was not honoured.

    `CompileUserspaceShim`'s post-`CompileConfig` aborts now route through
    `Manager.abortAfterHostMutation`
    (`pkg/dataplane/armcoverage_abort_7289.go`), which runs the REAL proof
    before returning the caller's error unchanged. Running it, rather than
    publishing a synthetic "everything uncovered" report, is the whole design: a
    re-attach can fail while the PREVIOUS shim is still attached and still
    adjudicating that interface, and disarming there is a brick, not a fence.
    The live proof answers both directions correctly. It does **not** restore
    the host state Phase 2 already moved — PR #7288 makes that divergence
    visible, and this makes the forwarding surface it leaves adjudicated.
    Fail-on-revert: `TestAbortAfterHostMutationRepublishesCoverage7289`, its
    control `TestAbortAfterHostMutationDoesNotDisarmAStillAttachedSurface7289`
    (which reds on the synthetic-report implementation), and the wiring guard
    `TestEveryPostCompileAbortPublishesCoverage7289`.
  - **What is NOT covered.** FRR adjacencies and VRRP/RG ownership are *not*
    relinquished by this gate — an unarmed node can still hold a VIP and
    advertise routes, so peers may keep steering transit at it (a blackhole
    rather than an open router: strictly the safer failure, but still a gap).
    That half of #5275 is HA-coupled and split to a successor issue. The
    `ip_forward=0` here is also only one leg of the full transit barrier in
    `docs/research/5275-arm-failclosed/plan.md` §6 (which adds an inet FORWARD
    drop, a bridge-family barrier, and a flowtable disable), and the arm
    boundary tracked is `Start`/`LoadUserspaceShim`, not the later
    per-interface AF_XDP attach inside the first `ApplyConfig` (see the
    observe-only proof in `pkg/dataplane/armproof.go`).
  - **Armed behaviour is unchanged.** The armed desired value is `1`,
    byte-identical to the pre-#5275 unconditional write. The AF_XDP fast path
    does not itself need `ip_forward` (measured in `docs/image-validation.md`:
    with both knobs at 0 an armed appliance still moved 4.29 Gbit/s v4 /
    3.02 Gbit/s v6 at 0% loss), but several ARMED paths `XDP_PASS` to the
    kernel and do rely on it — route-based-VPN plaintext off an xfrm
    interface, and SNAT'd frames passed up for kernel routing (the reason
    `enableForwarding` also sets `accept_local`). The gate never lowers the
    knob while armed.
  - Tests: `pkg/daemon/transit_forwarding_failclosed_5275_test.go`.

- ISSU (in-service software upgrade) preserves sessions across the upgrade
  by handing the BPF map FDs to the new daemon and timing the cutover
  against HA failover.
- CoS configuration is wiped on every cluster deploy. Re-apply with
  `test/incus/apply-cos-config.sh` after `cluster-setup.sh deploy`. (See
  CLAUDE.md.)
- `commitFn` and `commitConfirmedFn` are passed to `pkg/cli` and
  `pkg/grpcapi`; they hold the apply semaphore across the commit + apply
  pair so concurrent committers serialize.
- **Factory-reset gate (`factoryReset`, wired as `grpcapi.Config.ZeroizeFn`
  AND as the in-process CLI's `cli.SetFactoryResetFn`, #5281/#5871).** Neither
  a gRPC `zeroize` nor an interactive-console `request system zeroize` erases
  state out-of-band any more: BOTH route the wipe through this one
  `factoryReset` transaction (#5871 wired the console — `daemon_run.go`
  `shell.SetFactoryResetFn(d.factoryReset)` — through the same gate the gRPC
  server already used). `factoryReset`
  acquires the SAME `applySem` commit/apply/HA-sync serialize on (draining any
  in-flight apply), enters a **terminal reset generation** (`d.resetting`,
  `isResetting`/`enterResetGeneration`/`exitResetGeneration`) BEFORE running the
  wipe closure, and — on a successful wipe — leaves that generation set for the
  daemon's remaining lifetime (the gRPC handler stops xpfd moments later). Once
  set, every config writer that acquires `applySem` short-circuits on
  `errDaemonResetting`: `commitAndApply` / `commitConfirmedAndApply` /
  `syncAndApply` reject **before** persisting (so a racing commit/HA-sync cannot
  re-create the just-erased `.configdb` SSOT), `executeConfirmedRollback`
  skips, `applyConfigLocked` refuses (defense-in-depth),
  `ipsecApplyForLeaseChange` refuses (so a DHCP-lease rebind cannot re-render
  the erased swanctl PSK snippet), and `actuateRouteOverlayLocked` refuses (so an
  `ip-monitoring` probe-flap sweep cannot re-render `/etc/frr/frr.conf` and
  re-materialize the erased routing-auth keys). It fail-CLOSES: a wipe error exits the reset
  generation and releases the gate so the box stays recoverable, and the handler
  reports the reset incomplete and does NOT stop the daemon. The other `applySem`
  acquirers stay ungated: DNS writes `/etc/resolv.conf`, proxy-ARP writes nft,
  the policy scheduler and NAT-pool alarm touch dataplane/in-memory state, and
  the host-tunables restore must run on shutdown — none re-render a wiped secret.
- **Cancellable apply at coarse boundaries (#2926, follow-up to #2914/#2868).**
  `applyConfigLocked(ctx, cfg)` checks `ctx.Err()` at three phase boundaries and
  returns the ctx error at the next one rather than completing the netlink + FRR
  reload + Rust control-socket sync: **C1** before the netlink reconcile phase
  (step 0), **C2** before the dataplane apply / Rust sync push (step 2), and
  **C3** before the FRR reload (step 3). The checks sit only at boundaries where
  bailing leaves a consistent, restart-recoverable state — each major
  side-effecting phase (and the RETH MAC / VIP / worker-rebind sequence between
  C2 and C3) runs to completion once started, so the apply is never interrupted
  mid-phase; on the next boot the boot-time apply re-runs the whole pipeline
  against the active config, so a skipped tail converges. The cancellation
  signal is a **dedicated daemon-stop** context (`applyCancelCtx` →
  `d.applyCancelContext`), *not* the request/commit context: a daemon stop
  aborts an in-flight commit/remediation apply (the eventengine remediation path
  that #2914 made cancellable only at the pre-semaphore wait), but a mere request
  cancellation (HTTP/gRPC client disconnect) is deliberately ignored after
  `store.Commit` — aborting a promoted commit on a still-running daemon would
  leave the store ahead of the dataplane/FRR with no automatic re-apply to
  converge. The boot / DHCP / feed applies (`applyConfig`) and the
  confirmed-rollback re-apply (`executeConfirmedRollback`) pass a non-cancellable
  `context.Background()` so they always complete.
  - **Host-authorization closeout on a post-promotion cancel (#5643 / M35).**
    The "a skipped tail converges on next boot" reasoning holds for
    FRR/IPsec/DHCP/RA/VRRP/syslog/exporters, but **not** for the nft
    host-authorization owners (`applyLo0Filter` / `applyHostInboundFilter`, the
    kernel `xpf_lo0` / `xpf_hostinbound` PRIMARY enforcement) or the OS
    login/sudo/root-SSH credential reconciles: those persist on the box
    independent of xpfd and do **not** converge while the daemon stays
    intentionally stopped. Since `store.Commit` promotes the config UPSTREAM of
    `applyConfigLocked`, **every** ctx-cancellation early-return inside it — C1
    (in `applyVRFReconcile`), C2 (before the dataplane apply), and C3 (before
    the FRR reload) — is post-promotion, and a cancel that skipped the tail would
    leave the OLD, more-permissive host authorization live for the whole stop
    window (a monotonic-revocation violation). So each of those early-returns is
    funneled through `closeoutHostAuthOnCancel(err, cfg)`, which — only for a
    `context.Canceled` / `DeadlineExceeded` error — runs a bounded,
    non-cancellable `applyHostAuthorizationCloseout(cfg)` against the committed
    config before propagating the cancel. The closeout runs the security-critical
    owners in tail order (step 9.5–13): the two nft loads, then
    `applySystemLogin` / `reconcileSudoers` / `reconcileAbsentLoginUsers` /
    `applySSHConfig`, then **`applyRootAuth`** — the sole manager of root's
    `/etc/shadow` password and `/root/.ssh/authorized_keys`, without which a
    committed root-credential revocation would stay unenforced for the stop
    window. `runShutdownSequence` drains `applySem` (bounded by
    `applyCloseoutDrainTimeout`) after `applyCancel()` so that closeout completes
    before teardown/exit.
    - **Collect-and-budget the closeout (#5874).** The five credential
      reconcilers were best-effort **voids** whose failures the closeout
      discarded — it returned only the two nft errors, so a cancel could report
      clean while a login / sudoers / absent-user / SSH / root-auth reconcile
      silently failed and the committed host-auth state never actually
      converged. They now **return** their accumulated failures
      (`reconcileUserPassword` and `deprovisionLoginUser` too, so a
      password-write / revocation failure is not re-swallowed); the closeout
      runs each owner as a named `hostAuthOwner`, records a per-owner
      `hostAuthOwnerOutcome`, and `summarizeHostAuthCloseout` joins every
      **failing OR timed-out** owner into the returned error — naming which
      owner did not reconcile — so `closeoutHostAuthOnCancel` propagates a
      fail-visible cancel instead of a false-clean one. The "bounded" claim is
      now an **enforced** wall-clock budget (`hostAuthCloseoutBudget`, 30s):
      `runHostAuthCloseoutOwners` runs each owner under a shared deadline in its
      own goroutine (sequentially — the M35 order is load-bearing — but bounded),
      so a wedged reconciler is reported timed-out (convergence unknown) rather
      than hanging the daemon-stop path, and owners queued after the budget is
      exhausted are reported timed-out too, never silently skipped and never
      launched concurrently with the abandoned owner. On the **normal** apply
      path (`applyTailReconciles`) the same reconcilers' returns are
      intentionally discarded (`_ =`) — next-boot convergence still covers a
      transient failure there; only the daemon-stop cancel, where next-boot
      convergence does not happen, collects and fails on them.
    - **Unreadable ownership inventories now reach this closeout (#6798).**
      The reconcilers above could only report failures they could SEE, and an
      ownership read that failed was invisible to them: `hasProvenanceMarker`
      collapsed every `os.ReadFile` error to the same `false` a genuine `ENOENT`
      produces, `provisionedNames` skipped an unreadable root with a bare
      `continue`, and `reconcileSudoers` discarded its `ReadDir` error outright
      (`entries, _ :=`). Each gate then read "could not tell" as "not ours,
      skip" and returned **nil**, so the closeout — whose entire job is to catch
      an unconverged host-auth state — was handed a clean result over a removed
      administrator's still-live password, `authorized_keys`, and passwordless
      sudo grant. The reads now distinguish **absent** (a determination) from
      **unreadable** (proves nothing) and return the latter, so
      `summarizeHostAuthCloseout` attributes it to the owning reconciler
      (`system-login`, `sudoers`, `absent-login-users`, `root-auth`) and the
      cancel fails visibly. The gates report **without revoking** — acting on a
      marker xpf cannot read is #6797's overclaim from the other side, and for
      root's `authorized_keys` a total lockout — and markers are **retained**, so
      the debt survives for the next apply instead of being abandoned. See
      `docs/system-login.md` §"Unreadable ownership inventories are not empty
      ones (#6798)".
  - **Early signal capture — startup is abortable (#5807).** The shutdown
    signal context is captured at the **TOP of `Run`** (`startupSignalContext`),
    BEFORE the mutating startup phases (config load + bootstrap → interface
    naming → manager init + first `applyConfig` → dataplane load/`Start`). Before
    #5807 `signal.NotifyContext` was installed only AFTER those phases, so a
    `SIGTERM` (or daemon-mode `SIGINT`) arriving DURING startup took the process
    default action — immediate kill, no deferred cleanup — leaving partially
    applied links / routes / FRR / IPsec / DHCP / HA / dataplane state with none
    of the fencing steady-state shutdown performs. The phases now run through
    `runStartupOrAbort` → `runStartupPhases`, which checks the signal context at
    each phase boundary: a signal mid-startup skips the remaining phases and runs
    the **same ordered `runShutdownSequence` teardown** for whatever was
    initialized (every teardown step nil-guards its manager, so a partial init
    tears down cleanly), then `Run` returns the non-nil abort error instead of
    proceeding into steady state. A PLAIN phase error (no signal) keeps the
    pre-#5807 path — return the error, deferred `#5308` loop stops are the
    cleanup — distinguished from a signal abort by the signal context's state,
    never the error's identity. The signal set matches the old late install
    (interactive: `SIGTERM` only, so the CLI keeps `SIGINT` for Ctrl-C; daemon:
    both). The four long-lived startup runtimes (`cluster.Start`,
    `watchClusterEvents`, `startKernelSelfRecovery`, `dp.Start`) bind to
    `d.daemonCtx` (the raw, signal-uncancelled parent), NOT the phase signal
    context — the teardown needs them live — so `initManagers` /
    `setupDataplaneAndInitialConfig` no longer take a `ctx` parameter.
  - **Wiring (the part that makes this actually fire on `systemctl stop`).**
    `applyCancelCtx` deliberately does **not** return `d.daemonCtx`. In
    production `cmd/xpfd` passes `context.Background()` into `Run`, and that
    `context.Background()` is what `d.daemonCtx` holds — it is never cancelled
    (the signal-cancellable context is a *local* `ctx` captured at the TOP of
    `Run` by `startupSignalContext` → `signal.NotifyContext`, #5807). Returning
    `d.daemonCtx` would make C1/C2/C3 dead code on a real stop. Instead `Run`
    creates `d.applyCancelContext` as a **child of the SIGTERM/SIGINT signal
    context**, so a real `systemctl stop xpfd` cancels it, and the
    next coarse boundary observes `ctx.Err() != nil` and bails. `d.daemonCtx`
    stays the (uncancelled) parent of the long-lived background goroutines —
    flow-export/IPFIX relays, RPM probe-pin retry, the policy scheduler, cluster
    comms, and the `dp.Start` dataplane runtime. Those are torn down
    **explicitly** in the shutdown sequence, and the orderly teardown
    (`logFinalStats` through `dp.Telemetry`, the HA `rg_active` clear through
    `dp.HA()`, `dp.Teardown`) still needs the dataplane runtime live while it
    runs — which is why the apply-abort signal is isolated from `d.daemonCtx`
    rather than cancelling it. `Run` cancels `d.applyCancelContext` at the very
    start of the shutdown sequence (before the explicit subsystem teardown), and
    the teardown itself performs no `applyConfigLocked`, so the cancel aborts
    only a genuinely in-flight commit/remediation apply, never the shutdown's own
    cleanup.
  - **Cancel + join the two daemonCtx-bound loops BEFORE dependent teardown
    (#5308).** Because `d.daemonCtx` is never cancelled and neither the policy
    scheduler nor the RPM probe-pin retry loop binds to the run `WaitGroup`,
    `stop()` + `wg.Wait()` does not stop them. The shutdown sequence therefore
    calls `stopPolicySchedulerLoop()` + `stopPinRetryLoop()` immediately after
    `wg.Wait()` and BEFORE the subsystems they call into are torn down: the
    scheduler republishes schedule state through the dataplane runtime
    (`UpdatePolicyScheduleState`, closed by `dp.Close`/`dp.Teardown`), and the
    pin-retry loop runs routing-pin syscalls through the routing/FRR manager
    (stopped by `frr.Stop`/routing teardown). Each helper cancels its loop's
    context (the scheduler's `schedulerCancel`; a cancellable child of
    `d.daemonCtx` for pin-retry — it no longer binds `context.Background()`) and
    joins the goroutine on a `WaitGroup` (`schedulerWg`/`pinRetryWg`). The
    cancel is taken under the loop's own lock (`applySem` / `rpmMu`) but that
    lock is RELEASED before the join — an in-flight tick blocked on that same
    lock (`publishPolicyScheduleState` on `applySem`; `probePinRetryLoop` on
    `rpmMu`) must be able to finish so the goroutine can observe `ctx.Done()`.
    A `schedulerStopped`/`pinRetryStopped` latch prevents a late reconcile from
    starting a new generation after the join (which would race the `Wait`).
    Both helpers are idempotent / nil-safe and are ALSO registered as `defer`s
    in `Run`, so an early-error return (or an embedded library caller whose ctx
    cancels) that never reaches the shutdown sequence still cancels + joins both
    loops instead of leaking them.
  - **Two MORE background loops are cancelled + joined the same way (#5523
    C179-093):** the session-aggregation flush goroutine (`applyAggregator` →
    `agg.Run`, which binds to `context.Background()` and was previously cancelled
    only on a config replace/disable — never at shutdown, so its `#5313`
    `ctx.Done` final flush was skipped and up to a full ~5 min window of
    `SESSION_CLOSE` counters was dropped on every stop) and the IPsec
    DHCP-rebind retry loop (`ipsecRebindRetryLoop`, which bound directly to
    `d.daemonCtx` so a 30s rebind tick could run a `swanctl` reapply while
    teardown was in flight). `stopAggregator()` / `stopIPsecRebindLoop()` run
    immediately after `stopPinRetryLoop()` — the aggregator BEFORE the
    flow/feeds/event teardown so its final flush still has a live
    `SetLogFunc → er.ForwardLogMsg` path, the rebind loop BEFORE FRR/IPsec
    teardown. Each mirrors the #5308 shape: a cancellable child of
    `d.daemonCtx` (rebind loop) or the existing `aggCancel` (aggregator), a
    `WaitGroup` join (`aggWg` / `ipsecRebindWg`), the lock (`aggReconMu` /
    `ipsecRebindMu`) released before the join, an `aggStopped` /
    `ipsecRebindStopped` latch against a late restart, and a matching `defer` in
    `Run`. Other still-`daemonCtx`-bound goroutines (VRRP/cluster/fabric HA
    watchers) are intentionally left for a separate HA-scoped change.
  - **BOTH shutdown joins are BOUNDED because both can block on a
    context-insensitive downstream before the HA takeover fence (#6395 / #6397).**
    `stopAggregator()` and `stopIPsecRebindLoop()` both run in
    `runShutdownSequence` BEFORE the fence, so a plain `WaitGroup.Wait()` on
    either could push the whole stop past the systemd 20s `TimeoutStopSec` and get
    the process SIGKILLed before the peer takeover fence runs.
    - **The aggregator join is bounded by `aggregatorFlushJoinTimeout` (3s,
      #6395).** The `#5313` final flush forwards the pending report SYNCHRONOUSLY
      through the syslog client (`logFn → er.ForwardLogMsg`), and a stream-syslog
      sink allows up to `defaultWriteTimeout` (~4s) PER line — a stalled or
      unreachable collector could block `aggWg.Wait()` for many seconds.
    - **The IPsec DHCP-rebind join is bounded by `ipsecRebindJoinTimeout` (3s,
      #6397).** The loop's `cancel` IS observed at its `ctx.Done` / ticker select
      and at `applySem.Acquire(ctx, …)` — but NOT inside a `swanctl` apply already
      in flight. `tryIPsecRebindRetry`'s re-render+reload shells out under
      `context.WithTimeout(context.Background(), swanctlTimeout=15s)`
      (`pkg/ipsec/manager.go` `runSwanctl`) — a BACKGROUND context the loop's
      cancel does not interrupt — plus a 5s `WaitDelay`, so a rebind that is
      MID-APPLY when shutdown fires blocks a plain `ipsecRebindWg.Wait()` for up
      to ~20s. (The earlier "left unbounded on purpose / same safe shape as the
      #5308 pin/scheduler joins" note was WRONG: those loops do no
      background-context shell-out on cancel; this one does.)

    Each `stop*` therefore joins on a `done` channel with a `time.After(<budget>)`
    fallback: the happy path returns in microseconds (aggregator flush completes
    in ms; the rebind loop is normally parked on its ticker / `ctx.Done`, not
    mid-apply), and on a stalled downstream we log a warning and PROCEED to
    teardown — the aggregator drops the partial report, the rebind loop leaves its
    in-flight `swanctl` shell-out to finish in the background as the process exits.
    A missed fence is worse than either.
  - **The RG-state reconcile safety-net loop IS run-`WaitGroup`-registered so
    `wg.Wait()` joins it BEFORE HA ownership relinquish (#5681 / M23).**
    `reconcileRGStateLoop` (the periodic safety net that corrects `rg_active` /
    blackhole-route drift) binds the run/signal `ctx`, so it belongs on the run
    `WaitGroup` — not the daemonCtx cancel+join path above. `Run` launches it
    through `startReconcileRGStateLoop(ctx, &wg)`, which does the
    `wg.Add(1)`/`defer wg.Done()` wrap exactly like the sibling DDNS/proxy-ARP/
    Surface-A reconcile loops. This is load-bearing: `wg.Wait()` runs BEFORE the
    HA ownership-relinquish steps (the `rg_active` clear, RA withdraw, direct-
    mode VIP removal, VRRP `Stop`), so a reconcile pass that was in flight (or a
    tick that just passed the `ctx.Done()` select) COMPLETES and the loop EXITS
    before ownership cleanup begins. As a bare `go` goroutine it was unjoined:
    `stop()` cancelled its ctx but a late pass could re-enable forwarding /
    re-add VIPs AFTER `wg.Wait()` returned — during ownership cleanup — and
    re-assert mastership, opening a transient dual-master / blackhole window on
    planned shutdown or failover. Quiescing it early removes no needed shutdown
    behavior: the VRRP BACKUP transition during shutdown is driven by
    `watchVRRPEvents` (deliberately on `context.Background()`), not this loop.
- FRR reload runs with a 15 s context timeout to keep `systemctl reload
  frr` from hanging. The systemd unit has `TimeoutStopSec=20` as a safety
  net.
- HA fail-closed shutdown clears `rg_active` and watchdog state through the
  runtime HA controller under one daemon-owned deadline. Controller
  implementations may have their own RPC deadlines, but daemon shutdown does
  not wait past the outer deadline for those calls to return.
  **Netlink installer migration (#6387, COMPLETE).** PR-2 added an ADDITIVE
  `pkg/nftables` netlink `Installer` (no `nft` binary) that renders the
  host-inbound / lo0 / fence rulesets bit-for-bit equivalent to the
  `build*Payload` text, plus a non-skippable kernel ruleset-parity CI
  (`daemon_nft_netlink_parity_test.go`) that diffs the oracle `nft -f -` dump
  vs the netlink dump in a private netns. **PR-3 (the CUTOVER) is done:**
  production now installs and tears down every host-inbound / lo0 /
  cold-boot-fence / gap-fence table through the netlink `nftInstaller` seam
  (`daemon_nft_netlink.go`), so a node needs only the kernel `nf_tables`
  MODULE — never the `nft` BINARY (the #6387 fw1 config-sync trap). The
  daemon dpuserspace views / junos-host programs / lo0 terms are copied into
  the `pkg/nftables` input specs by the promoted converters (`toNft*` in
  `daemon_nft_netlink.go`). The 14+ fail-closed regression tests inject an
  install/teardown failure through the single `fakeNftInstaller` seam
  (replacing the pre-PR-3 `nftApplyPayload` / `nftDeleteTable` stubs); a
  netlink install failure still returns its error into the `errors.Join`
  fail-closed tail (invariant H7), a failed teardown still keeps
  `hostInboundEnforced` (#5790), and the cold-boot / coverage-gap fences still
  install fail-closed (#5644/#5789).

  **#7181 — the APPLIED state is now exported.** Until #7181 the observed-state
  machine never left this package: `hostInboundEnforced` had no exported
  accessor and no reader outside `daemon_nft.go`, so every operator-facing zone
  projection rendered DESIRED config with no way to say whether a kernel table
  was enforcing it. `codex-review-182:4394` put it as "on a cold-boot #5644
  failure, diagnostics can report default-deny while no table exists".

  `Daemon.HostInboundApplied()` (`host_inbound_applied_7181.go`) exports it, and
  it is deliberately NOT a bool. `hostInboundEnforced` is STICKY-TRUE — a failed
  render does not clear it, because the retained generation may still be
  protecting; only a successful teardown clears it — so it cannot separate the
  two states an operator most needs separated:

  | state | meaning |
  |---|---|
  | `not-established` | nothing has ever published a host-inbound DROP; a configured default-deny is NOT in force |
  | `current` | the most recent real render succeeded |
  | `stale` | a later render FAILED; the retained generation covers only what it covered when it loaded, and an address that appeared since may be covered only by the #5789 additive gap fence, or not at all |

  The `stale` row is not hypothetical — the day-2 branch above exists to handle
  exactly it. Rendering it as `current` is the confidently-wrong answer #5719
  refused to ship on the counter side.

  Carried by a generation counter (successful real installs only), a
  last-apply-failed flag with its timestamp, and a gap-fence-active marker, all
  written on the same `applySem`-serialized paths as the latch. Rendered by REST
  (`ZoneInfo.host_inbound_applied`, omitted entirely when the daemon was not
  asked) and by gRPC `ShowText`. **An unwired callback renders NOTHING rather
  than "not enforced"** — absence claims nothing, the same contract
  `PerZoneCountersAvailable` uses. When the netlink install fails because the
  kernel `nf_tables` subsystem is UNAVAILABLE, the returned error is tagged
  `xnft.ErrNFTablesUnavailable` (a one-time distinct operator log +
  Config-Sync `CF` monitor-failure reason, §12.5) without ever downgrading
  fail-closed. The `nftApplyPayload` / `nftDeleteTable` package vars and the
  `build*Payload` text builders are RETAINED as the parity-CI ORACLE (and the
  `TestNftDeleteTable*IdempotentAddDelete` payload-shape tests) — do NOT delete
  them while the parity CI depends on them; production no longer calls them.

- **A narrowing token that will not resolve must never be DROPPED from an
  lo0 term (#6806).** Both lo0 renderers — the netlink builder
  (`pkg/nftables/netlink_lo0.go`) and the `buildLo0FilterPayload` text
  oracle below — used to resolve `from protocol` and `from icmp-type` /
  `icmp-code` per token and skip the ones that failed. An ALL-unresolvable
  list emptied the slice, the `len(...) > 0` guard emitted no predicate, and
  the term matched every protocol / every ICMP type in its scope; a
  PARTIALLY-unresolvable list built the rule from a narrowed subset, so a
  `discard` term stopped denying what it could not resolve. Both now fail
  closed: the netlink builder errors the plan, and the oracle keeps the raw
  token so `nft -f -` rejects the ruleset — the posture ports/DSCP (#6405)
  and addresses (#6512) already had.

  Two things about this are easy to get wrong on the next pass:

  - **The two dimensions arrive by different channels.** Protocol reaches
    the builder as a RAW string, so the builder detects it. ICMP reaches it
    already RESOLVED to `[]int`, so an unresolvable token leaves NO trace
    and needs the `ICMPTypeUnrepresentable` / `ICMPCodeUnrepresentable`
    markers carried by `toNftLo0Term`. A fix that only hardened the
    resolver would have closed protocol and left ICMP wide open.
  - **Renderer AGREEMENT is not the property to test.** Before the fix both
    renderers dropped the token, so they agreed perfectly while both were
    fail-open — an equality/parity check between them could never have
    caught this, and the T1 parity CI did not. What must hold is that
    neither mirror loses the refusal evidence at its own boundary.

  Reachable only from the tolerant load / peer-sync / mixed-version paths
  (#1960) — strict commit rejects these tokens — which is exactly where the
  userspace mirror hands the raw token to the Rust filter compiler and it
  refuses the whole snapshot. A kernel term that widens while userspace
  refuses the same filter is a mode-dependent fail-open.

- lo0 input filters (`interfaces lo0 unit 0 family inet[6] filter input
  <name>`) lock down host-bound/control-plane traffic via an nftables table
  `inet xpf_lo0`. `daemon_nft.go:applyLo0Filter` installs the table via the
  netlink `nftInstaller` (`toNftLo0Spec` → `InstallLo0`) since #6387 PR-3; the
  `buildLo0FilterPayload` text below is now the parity-CI ORACLE (the netlink
  build is proven bit-equivalent to it), not the production path. nft parses an
  `-f -` payload **atomically** — a syntax error on any
  line rejects the ENTIRE payload (the kernel keeps the PREVIOUS table
  untouched, not a half-applied ruleset). The payload MUST therefore reset the
  prior table with the valid atomic idiom: `table inet xpf_lo0`
  (create-if-absent, no body — idempotent) + `flush table inet xpf_lo0` + the
  redefined table. Do NOT use `flush ruleset inet xpf_lo0`: `flush ruleset`
  takes at most an OPTIONAL family (`flush ruleset [<family>]`), never a table
  name — appending one is an nft parse error that silently dropped the whole
  filter (#2069). `TestLo0FilterPayloadNftParses` parse-checks the real payload
  with `nft -c -f -` when nft is on PATH.
  **Distinct hook-input priority (#3364):** `xpf_lo0` registers `type filter
  hook input priority 0` (`nftLo0FilterPriority`) and `xpf_hostinbound`
  registers the same hook at `priority 10` (`nftHostInboundPriority`). Two base
  chains on the SAME hook at an IDENTICAL priority have implementation-defined
  inter-chain evaluation order, so which chain's reject/log/counter fires for a
  packet both match would be order-dependent (a `drop` stays terminal regardless,
  so this was never a permit bypass — only an observability/determinism gap). The
  spread makes `xpf_lo0` evaluate STRICTLY BEFORE `xpf_hostinbound`: the lo0.0
  input filter is the operator's explicit, named, RE-wide control-plane firewall
  (authoritative accept/reject/discard verdicts), so it takes observable
  precedence over the coarser zone host-inbound default-deny backstop — the Junos
  lo0-filter-then-zone ordering. `nft_chain_priority_test.go`
  (`TestNftLocalDeliveryChainsDistinctPriority` /
  `TestNftLocalDeliveryPriorityConstantsOrdered`) pins
  `nftLo0FilterPriority < nftHostInboundPriority` and goes RED if the two are
  equalized.
  **Fail-closed (#3392, mirroring host-inbound #3333):** `applyLo0Filter`
  RETURNS the apply/teardown error instead of swallowing it at WARN, and
  `applyConfigLocked` joins it (`lo0Err`) into the commit result alongside
  `networkdErr`/`dhcpServerErr`/`hostInboundErr`, so a committed lo0 filter that
  did not reach the kernel reports commit FAILURE rather than silent success.
  The teardown (no filter bound) calls the netlink `nftInstaller.DeleteTable`
  (#6387 PR-3), which lists-then-deletes: the benign absent-table case is a
  no-op (nil), while a genuine teardown failure (stale filter left in the
  kernel) still surfaces fail-closed. Boot / DHCP
  re-applies go through `applyConfig`, which only LOGS the error, so a transient
  nft failure cannot brick startup; the next clean commit re-renders. Tests:
  `lo0_filter_test.go` (apply/teardown failure-surfaced fail-on-revert,
  success-no-error, idempotent add+delete teardown) and
  `daemon_apply_runtime_test.go:TestApplyConfigLockedSurfacesLo0Failure` (the
  commit-level `errors.Join` wiring proof).
  **Interface-reconcile fail-closed (#5310, mirroring #3333/#3392):**
  `applyInterfaceReconcile` (tunnels / xfrmi / fabric bonds / legacy-reth
  cleanup) was VOID and swallowed every sub-stage failure at WARN, and the tail
  commit-error join EXCLUDED the whole stage — so a commit that added a
  route-based IPsec VPN whose xfrmi `LinkAdd` failed (`xfrmManager.Apply`
  returned `nil` unconditionally) reported SUCCESS while the interface, and the
  route-based IPs bound to it, carried no traffic (cross-module false
  convergence). It now RETURNS an `errors.Join` of its sub-stage failures;
  `applyConfigLocked` captures it (`ifaceErr`) and threads it into the tail
  `errors.Join(networkdErr, applyErr, dhcpServerErr, hostInboundErr, lo0Err,
  ipsecErr, ifaceErr)` (`applyErr` = the #5679 ordinary dataplane-apply
  failure, below), so a genuine reconcile failure fails the commit closed. The
  underlying managers keep their idempotency (`xfrmManager.Apply` adopts an
  already-exists link and treats an already-gone delete as success #4901/#5261;
  `bondManager` #4823/#5119), so a benign re-apply still returns `nil` — this is
  purely surfacing GENUINE failures. All later reconcile steps still run (the
  error is deferred to the tail, fail-closed but complete). Tests:
  `apply_interface_reconcile_failclosed_5310_test.go` (direct
  applyInterfaceReconcile xfrmi/bond failure-surfaced + idempotent-no-error, and
  the `applyTailReconciles` commit-join wiring proof) plus
  `pkg/routing/xfrm_apply_failclosed_5310_test.go` (the routing-side
  `xfrmManager.Apply` returns-error / tolerates-already-exists half).
  **Ordinary dataplane-apply fail-closed (#5679, mirroring the above):** the
  main config-apply's full dataplane push (`applyDataplaneAndHACore` →
  the runtime dataplane's `ApplyConfig`) split its error into two classes but ACTED on only one.
  A required-protocol-gate error (`compileErrorMustAbortApply`) DISARMS the
  dataplane and returns early (terminal `err`, commit fails, peer sync skipped).
  But an ORDINARY (non-abort) apply failure — a control-socket / helper hiccup
  that leaves the OLD compiled policy live and forwarding — only called
  `recordCompileFailure` (for `/health`) and then FELL THROUGH: `applyConfigLocked`
  returned `nil` and the commit reported SUCCESS while `store.Commit` had already
  promoted the NEW config, so a tightening commit (e.g. a new deny) looked applied
  while the looser old policy was still on the wire — a fail-open-to-stale on the
  main config path (the config-commit analog of the feeds publication-debt bug
  #5646/#5667). The fix captures that ordinary failure as a DEFERRED commit error
  (`applyErr`, a fourth named return of `applyDataplaneAndHACore`) threaded into
  the tail `errors.Join`, so the commit reports FAILURE while the rest of the
  reconciles still run (fail-closed but complete, exactly like `networkdErr` /
  `ifaceErr`). It is NOT demoted to abort: the dataplane stays armed with the old
  config, so `applyErrSkipsPeerSync` still returns `false` and the standby
  converges (#4034); and because the applied identity never advanced, the feed
  onUpdate retry (`applyConfigResult`, #5646) and any identical re-commit
  re-apply and self-heal a transient error. Tests:
  `apply_failure_failclosed_5679_test.go` (ordinary-apply-fails-commit +
  wraps-injected + does-not-skip-peer-sync fail-on-revert, plus the abort-class
  still-early-returns + still-skips-peer-sync guard against over-reach).
  **Route-leak snapshot reconcile fail-closed (#5696, a #5642 residual):**
  `reconcileRouteLeakSnapshot` republishes the routes-only userspace snapshot after
  `applyRoutingRules` reconciles the kernel ip-rule table on a rib-group / next-table
  transition, so the userspace FIB does not keep a deleted-VRF inter-VRF leak that
  the earlier full apply published from the PRE-reconcile rules (#5642). But it was
  VOID and swallowed BOTH its failure legs at WARN — a transient
  `PublishRouteOverlaySnapshot` failure OR a `BumpFIBGeneration` failure only logged
  and returned, so the commit reported SUCCESS while the userspace FIB retained the
  exact stale leak #5642 removed. Unlike the ip-monitoring actuator (`daemon_ipmon.go`,
  #3757 dirty-retry), this commit-tail reconcile has NO retry engine to rediscover a
  swallowed failure — it is logged-and-forgotten. It now RETURNS an `error`;
  `applyConfigLocked` captures it (`routeLeakErr`) and threads it into the tail
  `errors.Join(networkdErr, applyErr, dhcpServerErr, hostInboundErr, lo0Err, ipsecErr,
  ifaceErr, routeLeakErr)`, so a genuine republish/FIB-bump failure fails the commit
  closed (the OLD pre-reconcile snapshot stays live; a re-commit re-runs the
  reconcile). Benign no-ops — helperless dataplane, or a duplicate-skip because the
  route set did not move — return `nil` and keep the commit successful (no FIB-bump
  churn). Tests: `route_leak_snapshot_failclosed_5696_test.go`
  (publish-fails-commit + bump-fails-commit fail-on-revert, duplicate-skip /
  helperless / clean-success stay-success, and the `applyTailReconciles` commit-join
  wiring proof).
  **Routing-rule reconcile fail-closed (#5844, mirroring #5310/#5696):**
  `applyRoutingRules` reconciles the kernel policy-routing (`ip rule`) table —
  next-table (`ApplyNextTableRules`), rib-group (`ApplyRibGroupRules`), and
  PBR/filter-based-forwarding (`ApplyPBRRules`). Each of those managers already
  RETURNS a fail-closed error (a partial clear/add leaves stale-or-missing
  cross-VRF policy in the kernel — `#3731`/`#5118`/`#2273`), but
  `applyRoutingRules` was VOID and LOGGED-and-DROPPED all three, so a commit was
  acknowledged after a partial reconcile — and the immediately-following
  `reconcileRouteLeakSnapshot` then canonized that partial live kernel state into
  the userspace FIB. It now collects the three errors via `errors.Join` (still
  running every rule type after one fails — fail-closed but COMPLETE) and RETURNS
  them; `applyConfigLocked` captures it (`routingRuleErr`) and threads it into the
  tail `errors.Join(networkdErr, applyErr, dhcpServerErr, hostInboundErr, lo0Err,
  ipsecErr, ifaceErr, routeLeakErr, routingRuleErr)`, so a partial ip-rule
  reconcile fails the commit closed. The snapshot republish still runs (ordering
  preserved: the deferred error does not abort it). `BuildPBRRules` *build
  degradation* is DELIBERATELY not joined — a filter term that cannot be expressed
  as an `ip rule` is a fail-SAFE under-steer (dropped to the main table, still
  enforced by the userspace filter path), a representability warning rather than a
  partial kernel mutation, so fail-closing it would reject configs that commit
  fine today. Tests: `routing_rule_reconcile_failclosed_5844_test.go` (direct
  applyRoutingRules fails-closed-and-complete via a `RuleList`-failing
  `NewManagerWithRuleOpsForTest` fake, clean-config stays-success, and the
  `applyTailReconciles` commit-join wiring proof).
  **Fabric IPVLAN fail-closed + retry owner (#6791, mirroring #5310/#5696/#5844/#5700
  on the propagation half and #6793 on the recovery half):** `applyFabricIPVLAN`
  returned NOTHING. It retried `ensureFabricIPVLAN` five times at 1s, then logged
  `CRITICAL: fabric IPVLAN creation failed after retries — cluster heartbeat will
  not work` and `continue`d — so the commit reported SUCCESS on a node with no
  `fab0`/`fab1`, i.e. no cluster heartbeat and no session-sync transport. The
  evidence was an ASYMMETRY, not a judgement call: in `applyConfigLocked` its
  neighbours are captured and joined (`mgmtRouteErr := …`, `ifaceErr := …`) while
  `d.applyFabricIPVLAN(cfg)` was a bare statement — the only reconciler in that
  sequence whose error could not propagate. It now returns
  `errors.Join(fabricErrs...)`, captured as `fabricErr` and threaded into the tail
  join. Safe to surface because `ensureFabricIPVLAN` returns an error ONLY when
  there is no usable overlay: address failures are warn-only inside it and it uses
  the idempotent `AddrReplace`, and an already-correct overlay returns nil — so
  there is no benign already-exists that could newly fail a healthy commit.
- **A caller-less config apply has a retry owner and a degraded signal
  (#9811).** A `commit confirmed` timeout promotes the STORE to the
  rollback target and then applies it, because the store has already moved
  and the dataplane must be brought into agreement unconditionally. When
  that apply failed it was only LOGGED. Under the #5679 contract a failed
  full apply keeps the old compiled policy live, so the node went on
  ENFORCING the abandoned configuration while the store, `show
  configuration`, the peer resync and `/health` all reported the promoted
  one — and unlike the commit path there is no caller to report to, so
  nothing retried it until some later unrelated apply happened to succeed.
  `configApplyDebt` latches the failure and `configApplyReassertLoop`
  (started unconditionally in `Run`, beside the loops below) re-applies
  until it converges; `ConfigApplyDebt()` feeds `/health`, which returns
  503 while it is owed.

  The retry re-reads the ACTIVE config rather than replaying the config
  whose apply failed, and that is load-bearing rather than incidental: a
  commit landing between the failure and the next tick makes the promoted
  target stale, so replaying it would UNDO the operator's newer commit and
  turn a convergence mechanism into a config regression. Re-applying
  whatever is active converges on the same invariant and is also what
  discharges the debt after an unrelated successful commit, which would
  otherwise leave a permanent false degraded on a converged node.

  SCOPE: this covers the auto-rollback path only. Every caller-less apply
  (boot load, DHCP lease callback, feed refresh, config poll) has the same
  shape and #9693 already owns the ROUTING tail for all of them — but on
  those paths the store has NOT advanced, so the reported configuration is
  still the enforced one and the consequence is different.

  Separately, `fabricIPVLANReassertLoop` is the persistent recovery owner the
  overlay never had: `applyFabricIPVLAN` runs only from a config apply on BOTH
  standalone and cluster nodes, so a netlink failure outlasting those five seconds
  (a parent NIC still being renamed after a power cycle) left the fabric absent
  until an operator happened to commit. It is also the only owner that can cover
  the DEFERRED (`OnXSKBound`) overlays, which are created after the apply has
  returned and so cannot report failure to the commit at all. Started
  unconditionally in `Run` alongside `proxyARPReassertLoop` /
  `raDeadSenderReassertLoop`, it takes `applySem` BEFORE reading `ActiveConfig`
  (#4001) and re-checks its gate inside the semaphore; the gate is one netlink name
  lookup per configured `fab*` device (present AND admin-up), so it is free on a
  healthy node and a complete no-op on a config with no fabric interfaces. Tests:
  `fabric_ipvlan_failclosed_6791_test.go` (producing half returns-and-names the
  failure with a healthy-path control; the `applyTailReconciles` commit-join WIRING
  proof; gate quiet-when-up / fires-when-down; the re-assert re-creates; and a
  loop-START cell asserting `Run` launches it unconditionally).

  **Fabric overlay management-VRF membership (#9813).** A fabric overlay carries
  the session-sync address, and session sync binds its sockets to `vrf-mgmt`, so
  the overlay must be a member of that VRF. Only the apply bound it: step 0b
  before networkd, and the authoritative step-2.7 re-bind after it. Two paths
  create an overlay outside an apply, and neither sets a master: the re-assert
  loop above and the deferred `OnXSKBound` callback. An overlay can also lose its
  master without being re-created, for example through an out-of-band
  `ip link set nomaster`. Session sync over that fabric then stayed down until the
  next apply of any kind.
  - After its ensure step, the re-assert pass binds every configured overlay that
    the last apply published in the management-VRF set but whose master is not
    `vrf-mgmt`. Its cheap gate counts such an overlay too.
  - `createDeferredFabricOverlays`, the `OnXSKBound` callback, binds each overlay
    it creates.
  - Nothing is bound when the last apply did not manage `vrf-mgmt`.
  - Tests: `fabric_overlay_vrf_9813_test.go`. It includes a kernel cell that runs
    in a private netns (`unshare -rn`) and skips without `CAP_NET_ADMIN`.
  - Routing-instance interface-LIST members have the same gap, and
    `riMemberVRFReassertLoop` closes it. Step 0a and the #6805 late pass bind
    them, both only from an apply, so a member netdev re-created outside one (a
    driver re-probe, a VF reset) or unbound out of band forwards in the DEFAULT
    table until the next apply. The loop binds only a member whose master is not
    its VRF: `BindInterfaceToVRF` logs at Info on every call, so re-running the
    apply's bind loop each tick would log on every tick of a healthy node. It
    leaves a tunnel carrying its own `routing-instance` stanza alone, because
    that is the tunnel manager's claim (`reconcileVRFClaimLocked` case 1, recorded
    in `appliedRI` only from its own bind), and it resolves names through
    `riMemberLinuxName` exactly as step 0a does, so the two reason about ONE name
    set. It takes `applySem` before the config read that drives the binding
    (#4001). Tests: `ri_member_vrf_reassert_9813_test.go`, including a kernel cell.

  **Host-inbound conntrack revocation retry (#6802, the same recovery shape):**
  `flushDeniedHostInboundConntrack` (the #5566 reconcile) deletes established
  kernel conntrack entries for host services the operator has just removed,
  because those entries would otherwise ride the host-inbound chain's leading
  `ct state established,related accept`. A delete failure therefore fails **OPEN**
  — the now-denied service keeps being served on its existing connections. It is
  deliberately still NOT a commit failure (the nft table is applied, so new
  connections are enforced, and rolling back over a transient conntrack error
  would discard correct enforcement); what #6802 added is everything else, since
  before it the flush returned nothing, set no flag, bumped no counter, published
  no metric, and no ticker re-ran it. The flush now returns a bool, and
  `noteHostInboundConntrackFlush` retains the **exact** failed request as debt —
  not a set re-derived at retry time, which would attempt a different revocation
  than the one that failed, and the two diverge precisely when a commit landed in
  between. `hostInboundConntrackReassertLoop` is the owner, started
  unconditionally in `Run` beside the three loops above, 30s, gated on a single
  atomic pointer load; it takes `applySem` before acting (#4001) and re-reads the
  debt INSIDE the semaphore, because the commit it queued behind may already have
  flushed successfully. A success clears the debt: the filter is built from the
  desired set, so a current revocation subsumes an older one.
  `HostInboundConntrackRevocationOwed` / `HostInboundConntrackFlushFailures` are
  wired into the REST/metrics server (`daemon_run_servers.go`) as
  `xpf_host_inbound_conntrack_revocation_pending` and
  `…_failures_total`; an accessor with no production caller would leave the
  operator exactly as blind as before (the #6852 shape). Tests:
  `host_inbound_conntrack_retry_6802_test.go` (paired outcome cell on the delete
  seam, which had no failing fixture at all before; debt retain/clear; the retry
  re-drives the OWED request; the inside-the-semaphore re-check; the loop ticks; a
  loop-START cell; and a WIRING cell for the two metric assignments) plus
  `pkg/api/metrics_hostinbound_conntrack_revoke_6802_test.go` (both series track
  their fn, and are OMITTED rather than published as `0` when unwired — the #6828
  absent-vs-zero distinction).

  **Routing reconcile retry owner (#9693).** Every apply reconciles the kernel
  policy-routing rules (`applyPolicyRoutingRules`: next-table, rib-group and
  firewall-filter PBR) and then republishes the userspace route snapshot from that
  kernel state (`reconcileRouteLeakSnapshot`). #5844 and #5696 made both
  failures deferred commit errors, but nothing re-ran them. A transient failure
  left stale or missing cross-VRF policy in the kernel and a FIB built from it
  until an unrelated apply, and on the applies nobody waits on (boot, DHCP lease,
  feed, config-poll) it was only logged. The apply now latches
  `routingReconcileDebt` (`noteRoutingReconcileResult`). The always-on
  `routingReconcileReassertLoop` re-runs both reconciles every 30 s while the
  debt is owed. Like its siblings, it takes `applySem` before reading the active
  config and re-checks the debt inside. It never re-runs the FRR apply, whose
  manager owns its own degraded retry. `RoutingReconcileDebt()` reports the
  latch, a monotonic failure count and the last error.

  **Managed service-file reload debt (#6800, the recovery half of #6791/#6793
  applied to the two managed-FILE appliers):** `applySyslogFiles` and
  `applySystemNTP` converge an on-disk service configuration and then gate a
  RUNTIME reload on "did the on-disk set change" — `reconcileSyslogDropins` ->
  `systemctl restart rsyslog`, and `reconcileManagedFile` -> `chronyc reload
  sources` / `systemctl reload chrony`. The gate is what stops a steady-state
  commit from bouncing rsyslog and chrony, but it also ERASED the debt of a
  FAILED reload: the write half had already converged the files, so the failing
  reload was logged and dropped, and every later apply compared desired against
  the converged set, saw `changed == false`, and skipped the reload. The daemon
  kept serving the PREVIOUS ruleset — records still flowing to a syslog
  destination the operator had removed, chrony still polling the old server set
  — until an unrelated syslog/NTP edit or a reboot, on a node that had reported
  a successful commit. The failure is transient and ordinary (`systemctl
  restart` on a unit that is failed/masked or has a queued job, or the 15s exec
  timeout on a loaded box), which is exactly why a retry owner recovers and a
  dropped error does not. `serviceReloadDebt` (`daemon_service_reload_debt.go`,
  a `Daemon` field, zero value = nothing owed) now retains the reload still
  owed, per SERVICE and — for chrony — per LEG, because the sources and
  threshold reloads are independent commands: a sources failure followed by a
  threshold-only edit must replay BOTH, and re-deriving the request from the
  later apply's own change flags would drop the sources debt. Both call sites
  fold the retained debt into the request they issue (before the no-change early
  return) and latch/discharge the outcome; `reloadChronyRuntime` now RETURNS a
  per-leg `chronyReloadOutcome` instead of returning nothing.
  `serviceReloadDebtReassertLoop` is the always-on owner for the case with no
  next apply at all (a boot-time failure): started unconditionally in `Run`
  alongside `proxyARPReassertLoop` / `raDeadSenderReassertLoop` /
  `fabricIPVLANReassertLoop`, it takes `applySem` BEFORE re-driving anything the
  apply path also writes (#4001 — a restart issued outside the semaphore can
  load a HALF-CONVERGED drop-in set mid-reconcile and latch a success for it)
  and re-reads the debt INSIDE the semaphore so a commit that discharged it
  while the tick queued does not get a gratuitous second bounce. The gate is
  three booleans under one mutex, so a healthy node pays nothing per tick.
  Seams: `rsyslogRestartFn` / `chronyReloadFn` (both owners go through one
  entry point, which is what makes the re-drive assertable), `chronyRunCmd`
  (per-leg outcomes without a real chronyc), and `rsyslogConfDir` /
  `chronySourcesPath` / `chronyThresholdPath` as vars so the reconcile runs
  against a temp dir. Tests: `service_reload_debt_6800_test.go` (latch +
  discharge pairs for both services; the steady-state retry with an explicit
  "the files really are converged" premise guard and its debt-free negative;
  per-leg outcome pairs; the two SYMMETRIC "owed leg survives an apply that
  changed the other file" cells; a same-config cell binding that the fold
  precedes the early return; the re-assert replaying the EXACT owed leg; the
  per-service gates via a paired one-owes/one-quiet cell; the
  inside-the-semaphore re-read; loop ticks + ctx cancel; a loop-START cell
  asserting `Run` launches it unconditionally; and the accessor + metric-wiring
  cells below).
  **One var relocates the whole sshd drop-in (#7609).** `sshdConfPath` is a
  package var so a test can point the drop-in at a throwaway tree, and
  `applySSHConfig` used to create its DIRECTORY from a hard-coded
  `/etc/ssh/sshd_config.d`. Relocating the var therefore produced a file path
  with no parent, the write failed with `ENOENT`, and — the part that matters —
  that failure surfaced as whatever the test was actually asserting. A cell
  checking only "an error was returned" passed while observing the fixture's own
  broken seam rather than the condition it injected. The directory is now
  `filepath.Dir(sshdConfPath)`: byte-identical in production (pinned by
  `TestProductionDropInDirIsUnchanged7609`, because every other cell relocates
  the path and so none of them would notice a wrong production value), and one
  seam relocates file and parent together — the property `provisionedUsersDir`
  already has for the three #5841 marker roots.

  **Retry-owner visibility completed (#7615).** Six always-on loops in `Run`
  re-drive a failure that had no other owner. #6800 and #6802 published;
  `RADeadSenderPending` (#6793), `FabricOverlayMissing` (#6791) and
  `ManagementListenerDown` (#6803) now do too, as
  `xpf_ra_dead_sender_pending` / `xpf_fabric_overlay_missing` /
  `xpf_management_listener_down`. Each accessor reads the SAME predicate its
  loop gates on — deliberately, because one derived from a parallel predicate
  could report 0 while the loop was still re-driving, and both halves would look
  correct alone. Emitted before the dataplane gate (these repairs all run in
  config-only mode) and OMITTED rather than published as `0` when unwired
  (#6828). Tests: `pkg/api/metrics_retry_owner_visibility_7615_test.go`
  (paired per gauge through a pedantic registry, plus the absent-vs-zero
  contract) and `pkg/daemon/retry_owner_visibility_7615_test.go` (the
  source-level wiring cell, and a cell binding each accessor to its loop's own
  gate in both directions).

  **The sixth owner joined in #7685, by a different predicate than expected.**
  `proxyARPReassertLoop` was left out of #7615 because it keeps no debt — it
  re-runs its reconcile unconditionally every tick — and the follow-up assumed
  the missing signal was drift detection: read the per-interface
  `proxy_arp`/`proxy_ndp` sysctl before writing and report when it disagreed.
  That is the wrong signal. **Drift is expected**: a link DOWN/UP outside a
  commit re-defaults the sysctl, and the loop corrects it on the next tick, so a
  gauge reads false except inside a 30 s window a scrape rarely catches, and a
  counter reports a routine event — the metric operators learn to ignore.

  The reconcile already held a real debt, and the code already called it that.
  A **configured** proxy-arp interface whose Linux netdev does not resolve is
  retained rather than torn down (#6536, `retainUnresolvedProxyResponders`),
  with a log line naming it debt. That condition does **not** self-heal on the
  next tick — it persists until the interface exists — and while it holds the
  responder is not answering on a node whose commit reported success. That is
  published as `ProxyARPUnresolved` / `xpf_proxy_arp_unresolved_pending`.

  It costs nothing on the path the loop's design depends on: `proxyARPIfaceMap`
  is not called at all when no proxy-arp is configured, so the added tracking
  performs zero interface lookups there — measured by a cell that counts
  resolver calls, with a positive control proving the counter can move. The
  value is the one the reconcile computed, stored rather than recomputed, so the
  gauge and the reconcile cannot disagree; and it is cleared when proxy-arp is
  unconfigured, since a signal that keeps firing after the fix gets muted. Tests:
  `pkg/daemon/proxyarp_unresolved_debt_7685_test.go`.

  **The loop also wakes on an RG ownership change (#9087), and the ticker alone
  was the whole latency budget.** Proxy-ARP ownership is decided per redundancy
  group (#8297), but nothing drove the reconcile when that ownership MOVED: the
  apply path runs on a commit and a failover is not a commit. So for up to
  `proxyARPReassertInterval` after a transition the new owner had not installed
  the entry and the old owner had not swept it. Measured on the loss cluster
  right after a crash-failover plus manual failback: `fw0=0 fw1=1` — the only
  answerer being the node that no longer owns the address, which mis-steers
  pool-mode NAT return traffic for the window. `nudgeProxyARPReassert` is now
  fired from BOTH edges, because they fix different ends of the same window:
  `applyRethServicesForRG` (MASTER) so the new owner installs, and
  `clearRethServicesForRG` (BACKUP) so the demoted node sweeps. The demote nudge
  deliberately precedes that function's store/config early returns — those are
  about RA/Kea state and say nothing about whether a sweep is owed, and a node
  whose config is unreadable still holds the stale kernel entry. The send is
  non-blocking depth-1: the callers are on the VRRP event loop and the reconcile
  takes `applySem`, so a blocking send would stall every later transition behind
  a commit. Tests: `pkg/daemon/proxyarp_ownership_nudge_9087_test.go`, which
  binds both call sites AND the nudge→reconcile link — deleting the loop's nudge
  arm survived the call-site cells, because they only proved the channel
  received a wakeup.

  **The sweep listed the wrong kernel table until #9087.**
  `dataplane.ReconcileProxyARP` read existing entries with `netlink.NeighList`,
  whose dump request carries `Flags: 0` and returns the ordinary ARP/ND table.
  Proxy entries live in the kernel's separate pneigh table, dumped only for a
  request carrying `NTF_PROXY` — `netlink.NeighProxyList`. `existing` was
  therefore always empty and both loops it feeds broke in opposite directions:
  the stale-removal loop removed nothing EVER (the #8297 gate fired correctly on
  the demoted standby every 30 s while the kernel entry survived indefinitely),
  and the add loop re-issued a `NeighSet` every tick forever. Every unit test
  replaces that seam with a fake returning what the case wants, so in every test
  it behaved like `NeighProxyList` — which is why a well-covered function
  carried a production-only defect, and why the guard asserts the wiring by
  function identity.

  **sshd is the third instance, and the one the "already covered" reading
  misses.** `applySSHConfig`'s UPDATE path does have a retry owner: #2062's
  `revertDropIn` restores the prior content on a failed reload, so the file no
  longer matches desired and the next apply rewrites and reloads. The REMOVAL
  path has nothing to revert TO — the drop-in is DELETED, the reload then fails,
  and every later apply reads `hadDropIn == false` and returns before reaching a
  reload. sshd keeps enforcing the xpf policy the operator REMOVED, which may be
  MORE permissive than the base-image default (`PermitRootLogin`, ciphers,
  MACs), until a manual restart or a reboot. The removal gate is now
  `!hadDropIn && !d.sshdReloadOwed()`, both reload sites record their outcome
  (an update-path SUCCESS discharges a removal debt — sshd has re-read its
  configuration either way), and the re-assert re-validates with `sshd -t`
  before the SIGHUP exactly as the apply path does (#4311), leaving the debt
  OUTSTANDING when validation fails because nothing was reloaded.
  R61 also flagged chrony's SHARED 15s context: one hung `chronyc reload
  sources` consumed the whole budget, so all four threshold fallbacks ran
  against an already-expired context — 15s of apply latency buying no
  convergence on either leg. The sources leg now has its own
  `chronySourcesReloadTimeout` inside the aggregate, so it cannot starve them.
  Operator visibility, mirroring #6802: `ManagedServiceReloadOwed` /
  `ManagedServiceReloadFailures` are wired into the REST/metrics server
  (`daemon_run_servers.go`) as `xpf_managed_service_reload_pending` and
  `xpf_managed_service_reload_failures_total`, both labelled by `service`
  (`rsyslog`, `chrony-sources`, `chrony-threshold`, `sshd`) because the legs fail
  independently and a collapsed gauge would not say WHICH reload never landed.
  The counter earns its place beside the gauge: a count that CLIMBS while the
  gauge stays 1 means the retry owner is running but not converging (a masked or
  failed unit), which the gauge alone cannot distinguish from one transient
  failure already paid. Both series are OMITTED rather than published as `0`
  when the fn is unwired (the #6828 absent-vs-zero distinction), and an accessor
  with no production caller would leave the operator exactly as blind as before
  (the #6852 shape) — hence the source-level wiring cell. Pinned by
  `pkg/api/metrics_managed_service_reload_6800_test.go` through a PEDANTIC
  registry, which is what makes a missing `Describe` entry a hard error rather
  than a silent production degradation.

  **VRF setup / management-bind fail-closed (#5700, mirroring #5310/#5696/#5844):**
  `applyVRFReconcile` LOGGED-and-DROPPED its `ReconcileVRFs` failure (WARN) and
  returned only the #2926-C1 ctx-cancellation, even though `reconcileVRFs`'s
  partial-failure contract still records the VRF in the managed set
  (`IsManagedVRF` true) — so a commit reported the VRF configured while its
  `vrf-*` device was absent on the kernel, with no retry owner (false
  convergence). It now returns `(ctxErr, vrfErr)`: `ctxErr` is the unchanged C1
  abort; `vrfErr` is the deferred VRF-device-setup failure, captured by
  `applyConfigLocked` and threaded into the tail `errors.Join(..., mgmtRouteErr,
  vrfErr)`. The AUTHORITATIVE post-networkd management-VRF re-bind (which
  `networkctl reconfigure` necessitates by stripping the master binding) is
  extracted into `rebindManagementVRFIfaces`, which aggregates and RETURNS its
  bind failures; `applyDataplaneAndHACore` joins them into `networkdErr` (like the
  #1956 device-map-teardown joins), so a genuine management-VRF bind failure also
  fails the commit closed. A failed commit is the retry owner (the next apply
  re-reconciles). The heartbeat restart that follows the rebind is surfaced the
  same way (#9751): `restartHeartbeatAfterRebind` joins a restart that exhausted
  its bind retries into `networkdErr`. That restart leaves the heartbeat stopped,
  owing a retry the next apply performs. The old call discarded
  `RestartHeartbeat`'s result. `HeartbeatRestartOwed` separates that case from a
  heartbeat that was never running, which is not an error. Deliberately LEFT best-effort (WARN, not surfaced): the
  routing-instance member binds (they run BEFORE `applyInterfaceReconcile` creates
  tunnel/xfrmi members, so a not-yet-created member is an EXPECTED transient
  absence, not a permanent failure) and the pre-networkd management bind (stripped
  and re-established by the authoritative rebind above) — surfacing either would
  reject configs that commit fine today. Tests:
  `vrf_setup_bind_commit_truth_5700_test.go` (direct `applyVRFReconcile`
  surfaces-setup / tolerates-success / ctx-cancel-is-not-a-VRF-error via a
  `vrf-mgmt`-`LinkAdd`-failing `NewManagerWithLinkOpsForTest` fake; direct
  `rebindManagementVRFIfaces` surfaces-bind / tolerates-success / empty-noop; and
  the `applyTailReconciles` commit-join wiring proof).
  **Per-term disposition mirrors userspace (#3427):** `nftRulesFromTerm` maps a
  term's `then` action to the kernel verdict the SAME way the userspace lo0
  evaluator does (`pkg/dataplane/userspace/filters.go` `NextTerm =
  (term.NextTerm || term.Action == "") && term.RoutingInstance == ""`). A term
  with NO terminating action is a Junos FALL-THROUGH (explicit `then next term`
  or a modifier-only term): it emits no TERMINATING verdict and the subsequent
  terms run. Pre-#3445 such a term emitted NOTHING; now it emits its honored
  modifiers (`then log`/`then count`, see the modifier bullet below) as a
  NON-TERMINATING rule (modifier statements, no verdict) so the per-term log /
  count fires while the chain still falls through to later terms (nft continues
  past any rule carrying no verdict). A fall-through term with no honored
  modifier still emits nothing. The pre-#3427 code mapped an empty action to a
  terminating `accept`, which SHADOWED every later discard/reject term — a
  control-plane fail-OPEN diverging from userspace (`from protocol tcp then next
  term` followed by `from destination-port 22 then discard` accepted SSH at term
  1, leaving the drop unreachable). A
  `routing-instance` (PBR) term is explicitly NOT a fall-through: userspace sets
  `continue_term=false` when `routing_instance` is non-empty and the evaluator
  TERMINATES the matched term, returning its action — the empty-action
  placeholder `Accept` — so the packet is ACCEPTED. The kernel lo0 input chain
  cannot perform route-selection, but the filter VERDICT is accept, so it emits
  a TERMINATING `accept` (mirroring userspace); it must NOT be skipped, because a
  skip lets a later deny term match and OVER-DROP legitimate host traffic on the
  kernel-primary lo0 chain. Userspace stays authoritative for the actual
  route-selection. Pinned by `TestNftRuleFromTermFallThroughNoBareAccept`,
  `TestNftRuleFromTermRoutingInstanceTerminatesAccept`, the end-to-end
  `TestLo0PayloadFallThroughDoesNotShadowDiscard`, and
  `TestLo0PayloadRoutingInstanceTerminatesAcceptNoOverDrop` (the over-drop
  counterexample).
  **`routing-instance` + `next term` is rejected at COMMIT, not un-terminated
  here (#9140):** because a routing-instance term terminates, co-locating it
  with `then next term` is the #5142 contradiction reached through
  `term.RoutingInstance` instead of `term.TerminalActions` — the operator wrote
  a fall-through and got a terminating accept that killed every later term.
  `validateFilterTerminalConflictStrict` (`pkg/config`) now hard-rejects that
  combination at commit. This renderer is UNCHANGED: the tolerant load /
  peer-sync path downgrades the gate to a warning (#1960), so the shape can
  still arrive, and it must keep mirroring the Rust evaluator, which terminates
  it. Making the nft side fall through alone would be a kernel-vs-userspace
  divergence — pinned by
  `TestNftRoutingInstanceWithNextTermStillTerminatesMirroringRust9140` and
  `TestLo0PayloadRoutingInstanceNextTermShadowsLaterDeny9140`
  (`lo0_ri_nextterm_mirror_9140_test.go`).
  **Unknown terminating action fails CLOSED (#3724 M08):** the terminating
  verdict switch mirrors the Rust filter compiler
  (`userspace-dp/src/filter/compiler.rs`) EXACTLY — `discard` → `drop`,
  `accept` (and the empty-action routing-instance PBR term) → `accept`, and any
  OTHER non-empty action → `drop`. An unknown / unhandled action cannot arrive
  through the CLI commit path (`validateFilterActionsStrict` plus the
  `UnknownActions` capture in `compileFilterThen` leave `term.Action == ""`), but
  a tolerant load / peer session-sync / mixed-version snapshot can carry a future
  action string directly in `term.Action`. The Rust compiler fails such a term
  CLOSED to `FilterAction::Discard`; the kernel mirror — the PRIMARY host-bound
  enforcement — MUST match, or it would ADMIT host-bound traffic userspace-dp
  drops (a mixed-version control-plane fail-OPEN). The pre-#3724 default arm
  rendered nft `accept` for any non-`discard` action; it now renders `drop` and
  logs the drift. Pinned by `TestNftRuleFromTermUnknownActionFailsClosed`
  (known accept/discard still map correctly; unknown actions render `drop`).

  **Non-terminating `then` modifier policy (#3445):** the kernel lo0 chain is
  the PRIMARY enforcement for host-bound traffic, so a term's non-terminating
  `then` modifiers must not silently diverge from userspace. The policy is
  explicit per modifier — implement what nft can honor on a `hook input` chain,
  and WARN at commit for what it cannot, never silently drop:
  - **honored in nft:** `then log` / `then syslog` (both compile to `term.Log`)
    → an nft `log prefix "xpf-lo0 <term>: "` statement (to journald), and
    `then count <name>` → a NAMED nft counter (`counter name "<n>"`, the object
    declared once in the table body by `buildLo0FilterPayload`; `nftables.
    Lo0CounterName` sanitizes + prefixes the Junos name to a bare-safe `xpflo0_*`
    identifier). nft executes a rule's statements left-to-right and the verdict
    terminates, so these prepend the verdict; on a fall-through term they form a
    NON-TERMINATING rule on their own (see the disposition bullet above).
  - **warned, not mirrored:** `then policer` (a Junos bandwidth+burst token
    bucket with a configurable then-action — nft `limit` cannot reproduce the
    rate mapping or the loss-priority action), `then dscp` (traffic-class
    rewrite) and `then forwarding-class` (egress CoS selection is meaningless for
    locally-delivered host-bound traffic). `config.validateLo0FilterKernelMirror
    Warnings` emits a commit WARNING naming the family/filter/term/modifier so the
    operator knows the kernel host-bound path will not enforce them; userspace
    stays authoritative for whatever lo0-filtered traffic actually reaches the
    XSK. `then loss-priority` is already reported globally inert by
    `validateFilterLossPriorityWarnings` (#2507), which subsumes the mirror gap.
    **`then routing-instance` (#3724 M04):** a PBR term terminates as `accept` on
    the kernel mirror (see the disposition bullet) — the verdict IS honored, but
    the kernel `hook input` chain cannot perform the route selection the term
    requests. `validateLo0FilterKernelMirrorWarnings` warns at commit that the PBR
    route selection is silently not performed on the primary host-bound path
    (userspace-dp stays authoritative for lo0-filtered traffic that reaches the
    XSK). Pinned by `TestLo0FilterKernelMirrorRoutingInstanceWarns`.
  - **`reject` (#3445 H10):** faithfully mirrors the userspace reject-reply
    synthesis (`userspace-dp` `poll_descriptor/reject_reply.rs`) — a TCP RST for
    TCP, an ICMP/ICMPv6 administratively-prohibited Destination Unreachable for
    everything else. nft cannot pick the reply protocol within ONE rule, so a
    reject term emits TWO: a TCP-only `reject with tcp reset`, then a
    family-agnostic `reject with icmpx type admin-prohibited` (icmpx selects
    ICMP vs ICMPv6 from the packet, so the same pair is correct in both rendering
    passes). The pre-fix bare `reject` sent ICMP port-unreachable for ALL
    protocols (including TCP) — a different wire response than userspace.
  Because a term can now lower to zero, one, or two rules, the lo0 table uses the
  atomic `add table; delete table; table { ... }` idiom (shared with the
  host-inbound table) instead of the prior `flush table`: `flush` does not delete
  named counter objects, so redeclaring a `then count` counter on the next commit
  would collide ("File exists"). A consequence is the lo0 counters reset to zero
  on every rebuild — nothing scrapes them, so there is no metric impact. Pinned by
  `TestNftRuleFromTermLogMirror`, `TestNftRuleFromTermCountMirror`,
  `TestLo0PayloadSharedCounterDeclaredOnce`, `TestNftRuleFromTermRejectVsDiscard`,
  `TestNftRuleFromTermPrefixListExcept`, `TestLo0FilterPayloadFlushIdiom`, and (config
  side) `compiler_lo0_mirror_modifiers_3445_test.go`.

  **Address / prefix-list lowering mirrors userspace (#3433):**
  `nftRulesFromTerm` lowers each direction's `source-address` /
  `destination-address` + `source-prefix-list` / `destination-prefix-list`
  scope through the SHARED userspace resolver
  (`dpuserspace.ResolveFilterPrefixListAddrs`) so the kernel mirror uses the
  EXACT empty-set / except / positive-wins / `any`-no-constraint semantics of
  the userspace matcher (`filters.go` + `userspace-dp` `filter/engine/matching.rs`
  `nets_match_v4/v6`). `nftAddrPredicate` then family-filters the resolved set
  for the chain's family and renders the predicate. The replaced raw string
  concatenation diverged on every one of these shapes (codex-094 H01-H05/H09):
  a positive literal `any` is no constraint (match ALL, NOT the unloadable
  `ip saddr any`); a constrained-but-empty POSITIVE scope (defined-empty or
  lenient-unresolved prefix-list, all-malformed literal, or a wrong-family
  literal such as a v4 CIDR in an inet6 filter) matches NOTHING — the rule is
  SKIPPED (a term that matches nothing has no enforcement), fail-CLOSED rather
  than the pre-fix "no predicate -> match ALL sources" fail-OPEN; an empty
  EXCEPT scope is match-all (no predicate); a non-empty except is the nft
  negated set `saddr != { ... }`; and a leniently-loaded MIXED positive+except
  in one direction is positive-wins (the except side is dropped, never folded —
  mirroring `resolvePrefixListAddrs`, hard-rejected at commit by #3359). An
  UNRESOLVED positive prefix-list ref combined with an `except` ref (both refs
  unresolved, no resolved positive scope — reachable only on the tolerant /
  peer-sync path, rejected twice at strict commit) is lowered ACTION-AWARE and
  fail-CLOSED (#5225): the empty positive is NOT the match-any universe (it is a
  specific scope that did not resolve), so the #4338 "any except X" compose is
  refused — an `accept`/PBR/modifier term matches NOTHING (never admit an
  unresolvable set; pre-#5225 it composed to match-ALL = admit every packet,
  fail-OPEN), while a `discard`/`reject` term keeps match-ALL so the deny still
  drops broadly (a deny that matched nothing would fall through to a later
  permit — the #5097 concern). Because the lo0 mirror threads `term.Action`
  through the shared resolver, its predicate matches the userspace verdict for
  this shape too. A malformed or wrong-family literal is also an operator-visible commit error
  (`validateFilterAddressLiteralsStrict`, lenient-downgraded on the peer-sync /
  load path — #1960 no-brick). Pinned by `TestNftRuleFromTermAddressSemantics3433`,
  `TestNftRuleFromTermWrongFamilyMatchesNothing`, and (config side)
  `firewall_address_literal_3433_test.go`.

  **A MALFORMED address token fails the install CLOSED (#6512).** #3433 dropped
  a malformed token silently, so an ALL-malformed positive list reached
  "constrained + empty -> match nothing". That resolution is wrong for the two
  shapes #6512 filed. A PARTIALLY malformed positive list installed a NARROWED
  rule — a `discard`/`reject` term enforcing a smaller address set than the
  operator wrote, with the dropped range falling through to the implicit accept
  (fail-OPEN). And an EXCEPT list narrowed to empty takes the "empty except ->
  match ALL" arm above, so the direction becomes UNCONSTRAINED (fail-OPEN in the
  other direction) — which is why "skip the bad entry" can never be the fix
  here. Both builders now refuse: `nftFamilyAddrs` (oracle) keeps the token
  VERBATIM so `nft -f -` rejects the whole ruleset, and `filterFamilyAddrs`
  (`pkg/nftables/netlink_lo0.go`, the production builder) returns an error that
  fails the plan and aborts the install — the same posture both already had for
  an unrepresentable port / DSCP token (#6405). Wrong-family and `any`/empty
  tokens are unaffected: those are legitimate drops that match the userspace
  matcher.

  Fail-closed here does not mean fail-to-boot (#1960): the install error makes
  `applyLo0Filter` install the #6476 cold-boot fail-closed fence (lifelines
  exempt, mandatory L3 / return traffic admitted) and the boot apply logs and
  discards the error, so an already-persisted config still loads — it just does
  not get a kernel filter that differs from what the operator wrote. On the
  strict COMMIT path the commit now fails with the malformed token named,
  instead of silently installing the narrowed filter.

  Detection is on the TOKEN, not on the #6463 `AddressUnrepresentable` marker,
  because that marker is derived from `term.UnknownAddresses` — malformed
  LITERAL `from source-address` / `destination-address` tokens only. A malformed
  entry inside a referenced `policy-options prefix-list` reaches this lowering
  through `ResolveFilterPrefixListAddrs` with the marker unset, and is not
  rejected at strict commit either (`validateFirewallPrefixListReferencesStrict`
  validates that the REFERENCE resolves, not that its entries parse). Pinned by
  `pkg/nftables/netlink_lo0_addrs_6512_test.go` (builder fails closed; wrong-family
  and placeholder tokens still lower) and
  `pkg/daemon/lo0_addr_failclosed_6512_test.go` (the token reaches the builder
  from a prefix-list on the ordinary commit path; a failed build fences and
  surfaces the error).

  **ICMP type/code lowering mirrors userspace (#3483):** `nftRulesFromTerm`
  renders `icmp-type` and `icmp-code` as INDEPENDENT predicates, each gated
  only on its own value list — `icmp[v6] type <set>` when `len(ICMPTypes) > 0`
  and `icmp[v6] code <set>` when `len(ICMPCodes) > 0` (family selects `icmp`
  vs `icmpv6`). This matches both userspace projections: `filters.go` emits
  `ICMPCodes` gated only on `len > 0`, and the Rust matcher tests
  `icmp_code_match_enabled` in a block separate from `icmp_type_match_enabled`.
  The pre-fix nft mirror nested the code predicate inside
  `if len(term.ICMPTypes) > 0`, so a code-only term (`from protocol icmp
  icmp-code 4 then discard`, no `icmp-type`) dropped the code match on the
  kernel lo0 path — the kernel mirror then matched BROADER than userspace (a
  `discard` dropped ALL ICMP fail-closed-over-broad, an `accept` admitted ALL
  ICMP fail-open). Pinned by `TestNftRuleFromTermICMPCodeOnly` (v4 + v6 +
  multi-value, code-only) and `TestNftRuleFromTermICMPTypeCode`.

  **Protocol / DSCP lowering normalizes through the shared resolvers (#3436):**
  `nftRulesFromTerm` resolves each `from protocol` token through the shared
  `appid.ProtocolNumber` SSOT (the same resolver the commit gate
  `filterProtocolResolvable` and the userspace matcher `ip_proto.rs` use) and
  emits the NUMERIC nft `l4proto` token (`meta l4proto 47`, set form
  `meta l4proto { 47, 6, 50 }`). It resolves each `dscp` / `traffic-class` token
  through the `dataplane.DSCPValues` SSOT (case-insensitive, numeric 0..63
  pass-through) and emits the numeric `ip[6] dscp` value. The pre-fix code
  emitted both tokens RAW (codex-094 H08/M01): nft does not share the Junos
  alias table — `meta l4proto junos-gre` / `junos-tcp-any` / `ipip` is a parse
  error that rejects the whole atomically-loaded lo0 table (legitimate commit
  broken) or, on the lenient/peer-sync path, leaves the kernel mirror absent
  while userspace stays armed. Likewise nft's DSCP names are lowercase only and
  do not cover every xpf code point — an upper-case `EF` (accepted
  case-insensitively at commit) and `be` (best-effort, which has NO nft name)
  both failed the atomic load. Emitting numeric values is unconditionally
  nft-safe and matches the SAME protocol / code point as userspace. An
  unresolvable token cannot reach a committed config (the commit gate rejects
  it); on the lenient path an unresolvable protocol is dropped with a warning
  and an unresolvable DSCP token falls back to its lower-cased form. Pinned by
  `TestNftRuleFromTermProtocolAliases`, `TestNftRuleFromTermProtocolMultiAliasSet`,
  `TestNftRuleFromTermDSCP`, and `TestNftRuleFromTermDSCPNamesAndCase`.

  **TCP-flags lowering fails CLOSED on an unrepresentable expression (#5512):**
  a representable `tcp-flags` value lowers through the commit-validated
  `config.ParseTCPFlagsExpression` to the canonical masked-equality form
  (`meta l4proto 6 tcp flags & (syn | ack) == syn`, #3231). An UNREPRESENTABLE
  expression — a `|` disjunction, a De-Morgan negated group, an unknown flag, a
  dangling `!`, a `&` with no operand — cannot reach a committed config
  (`compileFirewall` + the #5455 strict gate reject it), but the LENIENT load
  path (peer session-sync, a #1960 fail-closed load-downgrade, a mixed-version
  snapshot) admits the term with only a warning. The pre-#5512 mirror then
  DROPPED the tcp-flags predicate and emitted the term's configured verdict,
  WIDENING it: an `accept` term meant to admit only a specific flag combination
  (`syn & !ack`) admitted EVERY TCP segment it scoped — a control-plane
  fail-OPEN on the PRIMARY host-inbound path. `nftRulesFromTerm` now fails the
  term CLOSED instead: it emits a per-TERM terminating `drop` of the term's
  scoped traffic (`<match> meta l4proto 6 drop`) regardless of the term's
  configured action, so an `accept` term's traffic is DENIED, a `discard`/`reject`
  term still denies, and a fall-through / routing-instance term terminates as a
  drop rather than continuing permissively. This mirrors the userspace direction
  (`filters.go` sets `TCPFlagsUnparseable` and the Rust filter compiler raises
  `SnapshotIntegrityError::UnrepresentableFilterTCPFlags`), but per-TERM: the fix
  must NOT reject the whole atomically-loaded lo0 table (that leaves NO host
  filter = fail-OPEN, the trap the pre-#3231 comma-join hit). The `meta l4proto 6`
  guard scopes the drop to TCP (a tcp-flags constraint only ever matches TCP in
  the userspace matcher `per_packet_l4_matches`), so a tcp-flags-ONLY term does
  not lower to a bare `drop` that would deny ALL host-inbound traffic. Pinned by
  `TestNftRuleFromTermTCPFlagsUnrepresentableFailsClosed` (RED-on-revert: the
  reverted arm emits `meta l4proto 6 accept`, the widen) and
  `TestLo0FilterPayloadUnrepresentableTCPFlagsParses` (the emission parses under
  `nft -c -f -`, proving it never fails the whole ruleset).

  **flexible-match-range is MIRRORED, and an unrepresentable one matches
  NOTHING (#6804):** before this the lo0 mirror had no handling for
  `from flexible-match-range` at ALL — the netlink spec (`Lo0FilterTerm`) had no
  field for it, so the predicate was dropped at that boundary and the term
  rendered WITHOUT its narrowing. An `accept` term meant to admit only packets
  whose header bytes match a pattern admitted every packet it scoped: the same
  control-plane fail-OPEN #5512 fixed for tcp-flags, on the chain that is the
  PRIMARY enforcement for host traffic.

  A representable predicate now renders as nft's raw payload match,
  `@nh,<byteOffset*8>,<byteLen*8> & <mask> == <value>` — `layer-3` match-start
  (the only start point the compiler emits) is the network-header base. The load
  is whole BYTES because nft loads byte-aligned; a sub-byte bit length is carried
  by the MASK, exactly as the userspace matcher does it, and the expected value
  is pre-masked on both sides (nft compares the masked load, so a value with bits
  outside the mask would never match — a silent never-match is a different fail
  direction but just as quiet).

  An UNREPRESENTABLE predicate — more than one named range (#5823), an
  unparseable numeric token (`UnknownFlexMatch`), or a load width outside 1..4
  bytes — makes the term match NOTHING (no rule emitted), so later terms still
  run. That mirrors userspace, which poisons the term to
  `FlexMatchStart::Unsupported` so `flex_matches()` returns false. It is
  deliberately NOT the #5512 tcp-flags drop: a tcp-flags constraint only ever
  matches TCP so that drop can be scoped with `meta l4proto 6`, whereas a
  flexible-match-range has no natural narrowing — a term whose ONLY predicate was
  the flex-match would render a bare `drop` and deny ALL host-inbound traffic,
  turning a fail-open into a lockout.

  The width rules mirror the userspace snapshot builder exactly: a zero
  bit-length defaults to 4 (32-bit), and an oversized width is NOT capped to 4 —
  capping would compare only the truncated window and BROADEN the match (the
  #3406 fail-open), so it is reported unrepresentable instead.

  Pinned by `TestNftNetlinkParity/lo0_flexible_match_range` (three widths,
  including a sub-byte 12-bit case, diffed between the nft-parsed oracle and the
  real netlink install) and
  `TestNftNetlinkParity/lo0_unrepresentable_flex_match_matches_nothing`. The
  parity case is what makes the two renderers' agreement real rather than
  asserted — both go through the actual `nft` parser and the actual netlink
  install.
- host-inbound-traffic (`security zones <z> host-inbound-traffic`) is the
  PRIMARY kernel enforcement for host-bound traffic to a firewall interface IP
  / VRRP VIP (SSH, ping, OSPF/BGP to the box — #3070). Such traffic is shunted
  to the kernel by the XDP shim before reaching userspace-dp, so
  `daemon_nft.go:applyHostInboundFilter` builds an `inet xpf_hostinbound`
  table (same atomic flush idiom as lo0) via `buildHostInboundFilterPayload`,
  consuming `userspace.BuildZoneHostInboundViews(cfg)`. The chain registers
  `type filter hook input priority 10` (`nftHostInboundPriority`) — DISTINCT from
  the `xpf_lo0` chain's `priority 0` so this host-inbound backstop evaluates
  AFTER the operator's explicit lo0 input filter rather than at an
  implementation-defined order relative to it (#3364, see the lo0 bullet). Per
  host-inbound-CONFIGURED zone it accepts the listed system-services/protocols
  to that zone's addresses and DROPs the rest; the userspace-dp LocalDelivery
  check (`forwarding/host_inbound.rs`) is the secondary path for the XSK-reaching
  subset. **Address sources (#3172, #3224):** the per-zone destination address
  set is the de-duplicated union of (a) the live interface snapshot
  (`buildInterfaceSnapshots` -> `AddrList(FAMILY_ALL)`), which carries BOTH static
  `family inet[6] address` config leaves AND DHCP/DHCPv6-learned kernel addresses
  (the snapshot does no scope/flag/dynamic filtering, so a DHCP-addressed WAN's
  learned address IS scoped — the #3224 fail-open premise does not reproduce), and
  (b) RETH VRRP VIPs resolved from config (so the deny is scoped on the backup
  node too, where the VIP is not yet live). SLAAC is not a separate case: xpfd sets
  `IPv6AcceptRA=no` on every managed interface (`pkg/networkd`), so DHCPv6 is the
  only IPv6 dynamic path and the live snapshot captures it. **Refresh:** a
  DHCP/DHCPv6 lease callback classified for full recompile runs serialized
  `applyConfig`; the chain receives a second fence/re-render opportunity only if
  that apply reaches `applyTailReconciles`. A required protocol-gate error can
  return before that tail, leaving the address for a later applicable successful
  reconcile. **#5791:** `dhcpLeaseChangeRequiresRecompile` now classifies the
  management-only skip on the config-derived host-inbound LIFELINE set
  (`config.HostInboundLifelineSet` / `HostInboundLifelineInterface`, the SAME
  authority this fence uses), NOT the broad management-VRF name class
  (fxp*/fab*/em*). Only a TRUE lifeline (fxp0, em0, fab*, or a configured
  chassis-cluster control/fabric interface) takes the lightweight management-only
  branch; a zoned NON-lifeline DHCP interface (e.g. a standalone `fxp1`) now forces
  the full recompile that builds its address-scoped host-inbound fence, closing the
  addressless→addressed gap where the broad class exempted it from that reapply.
  **Lifeline exclusion — by INTERFACE and by address VALUE (#7284):**
  management/cluster-control interfaces (fxp0 / em0 / fab*) are excluded from
  the address sets, so an address reachable ONLY through a lifeline is never
  denied. A management address ALSO configured on a non-lifeline interface is
  additionally withheld by VALUE from any drop set that would deny it with no
  accept — every host-inbound drop is destination-address-only with no `iifname`
  (#3718), so arriving on the lifeline cannot exempt it and only a value
  subtraction can. Before #7284 a zone with no stanza (#3405) or an unzoned
  interface (#4420) dropped NEW management connections to that address, and the
  #5566 conntrack reconcile flushed its ESTABLISHED ones. A zone that DOES admit
  the service keeps the address, because its accept already precedes the drop and
  that drop still expresses policy for every other service on it. `ct state
  established,related` and IPv6 ND + v4/v6 PMTUD control messages are accepted
  before any deny, which is what preserves HA control traffic. See
  `docs/host-inbound-service-matrix.md`, "Lifeline exclusion is by address VALUE,
  in the fence and the real table". A configured zone that resolves to zero
  recognized matches fails OPEN (no deny) rather than locking the zone out.
  **Unzoned interfaces (#4420 HI-2):** an interface that carries an address but
  is assigned to NO security zone is not covered by any per-zone view above, so
  before #4420 its firewall-local addresses fell through the chain's
  `policy accept` to the host stack with NO host-inbound admission — a fail-open,
  and a deviation from Junos (an interface not in a zone passes no flow /
  host-inbound traffic at all). `applyHostInboundFilter` now also scopes a
  catch-all DROP to those addresses (`userspace.BuildUnzonedHostInboundAddrs`,
  counted under the reserved `junos-host` sentinel label so the #3361 scraper
  reports them as `zone="junos-host"`). Lifeline INTERFACES are excluded and
  zoned addresses subtracted, so it never conflicts with a zone rule — but an
  unzoned drop carries NO service accept, so a management address shared onto an
  unzoned interface is denied outright here (see the lifeline note above); it is
  emitted only when the zone model is in use (>= 1 zone), so a
  bootstrap / zoneless box is left untouched. Unzoned interfaces are not
  AF_XDP-bound, so the kernel nft deny is the sole and sufficient enforcement
  point (no userspace-dp change). **Known limitation (#4420 HI-1):** the chain
  matches destination address only, so host-bound MULTICAST / BROADCAST (OSPF /
  RIP / VRRP / PIM link-local groups, limited / directed broadcast) is not scoped
  by any `daddr` set and still falls through `policy accept` — it is NOT
  subjected to the per-zone host-inbound protocols admission (a Junos-parity
  gap). Closing it needs per-zone ingress-interface (`iifname`) multicast
  admission in lockstep with the Rust classifier and is a behavior / hardening
  change (a zone running a routing protocol in FRR without the matching
  `host-inbound-traffic protocols` knob relies on today's accept), so it is
  tracked separately rather than folded here.
  Token→nft mapping (`hostInboundServiceMatches`/`hostInboundProtocolMatches`)
  mirrors the Rust classifier and must stay in sync. **Structured SSOT (#3627
  B1a):** since #3627 these two functions no longer carry their own hard-coded
  nft strings — they RENDER (`renderHostInboundMatches`) the single structured
  token→tuple SSOT `config.HostInboundServiceMatch` / `HostInboundProtocolMatch`
  (`[]config.L4Match{Proto, Ports, ICMPType, Reject}`). The same table backs the
  `request security match-policies` host-inbound classifier
  (`dataplane/userspace.ClassifyHostInbound`), so the reported admitting token
  cannot drift from the port the kernel opens. The render is byte-identical to
  the pre-#3627 strings, proven by
  `TestHostInboundNftRenderGoldenByteIdentical`; a per-tuple Rust parity test is
  a deferred follow-up (the domain-parity guards still hold). The authoritative
  operator-facing token→port matrix across all three surfaces (Go SSOT allowlist,
  this nft mirror, the Rust AF_XDP classifier), including the deliberate
  narrowings and the ident-reset divergence, is
  `docs/host-inbound-service-matrix.md` (#3619). **ident-reset (#3310):**
  `system-services ident-reset` is NOT a plain admit — Junos actively RESETS
  inbound ident (auth/TCP-113) probes. Its nft verdict
  (`hostInboundServiceAction`) is `reject with tcp reset` (the first `reject`
  rule in `xpf_hostinbound`), emitted before the catch-all drop, so the kernel
  synthesizes an RFC-correct RST and 113 is NEVER opened to the host.
  `any-service` precedence wins (a fully-open zone admits 113 and emits no
  ident-reset reject). **#3226:** `all` does NOT shadow it — `all` expands to a
  named-service set that CONTAINS ident-reset, so the chain emits the reject
  rule. The verdict is taken from the EXPANDED token
  (`config.HostInboundServiceTokenExpansion` in `hostInboundMatchSet`); keying it
  on the authored token would render `tcp dport 113 accept` and admit the very
  probes the per-token form resets. The Rust AF_XDP secondary path does NOT
  reset — it simply drops 113 (the classifier ident-reset arm contributes nothing
  to the admit set), a documented divergence on the near-nonexistent
  DNAT/static-NAT-to-113 path. Tests: `host_inbound_nft_test.go` (accept-listed /
  deny-rest fail-on-revert, no-stanza-no-deny, lifeline-never-denied,
  `any-service`-opens-zone, ident-reset emits-reset /
  `any-service`-suppresses-reset / nft-parse-check),
  `host_inbound_all_scoping_3226_test.go` (`all` scoped-not-blanket, `all`
  renders the ident-reset RESET verdict, `any-service` still blanket),
  `host_inbound_parity_test.go` (ident-reset reject-verdict parity).

  **`system-services all` scoping (#3226):** `all` is no longer a full admit. It
  expands to the union of the named system-services (excluding the xpf-only
  `gre` and `r-exec`/`rexec` extensions, which Juniper's service list does not
  define) via `config.HostInboundAllExpansionServices`, exactly as
  #3199 scoped `protocols all` to the routing set, so an `all` zone now renders
  per-service accepts PLUS the catch-all drop instead of a bare
  `<fam> daddr <addrs> accept` with no deny. `hostInboundAllowsAll` therefore
  matches `any-service` alone. Junos scopes `all` to "traffic from the defined
  system services available on the Routing Engine" and its service list carries
  no raw IP protocol, so the pre-#3226 blanket admit of GRE/ESP/OSPF/PIM/VRRP was
  a fail-OPEN. No-op on every shipped config (each puts `all` on the
  lifeline-only `control` zone, which contributes no host-inbound addresses).
  The union must equal Juniper's DEFINED-service set in both directions, so the
  same change adds the services xpf did not recognize at all — `r2cp`,
  `reverse-ssh`, `reverse-telnet`, `rpm`, `lsselfping`, `tcp-encap`, `appqoe`,
  `high-availability`. Without them a scoped `all` denied a defined service AND
  the operator could not name it (strict validation rejects tokens outside the
  same allowlist), a fail-CLOSED regression rather than an over-admit closed.
  The union's membership is DERIVED at test time from Juniper's published YANG
  module, vendored whole and gzipped at
  `pkg/config/testdata/junos-es-conf-security@2024-01-01.yang.gz` and PARSED by
  `pkg/config/host_inbound_tokens_test.go` under a pinned SHA-256 — not from the
  prose reference pages, which are individually incomplete and had this set
  wrong three times.
  Of those, only `reverse-telnet` (tcp 2900), `reverse-ssh` (tcp 2901) and
  `lsselfping` (udp 8503) render a match: the first two carry explicit YANG
  platform defaults, the third is RFC 7746 / IANA. The rest are in
  `config.HostInboundUnportedSystemServices` — recognized, in the `all` union,
  but rendering NOTHING, because xpf has no authoritative listening port to
  admit for them (Junos documents rpm/r2cp as operator-configured; the rest are
  simply unsourced) and a guessed port would open an unused port while still
  denying the one actually in use. Naming one explicitly draws a WARN-only commit advisory.
  Full write-up: `docs/host-inbound-service-matrix.md`.
  **Counted drops + scrape (#3361):** each per-zone/family catch-all drop is
  `<fam> daddr <addrs> counter name "<n>" drop`, where `<n>` =
  `nftables.HostInboundDenyCounterName(zone, family)` (encoding
  `xpfhi_<family>_<len>_<zone>`, reversible even when the zone name contains
  `_`/`-`). The `<zone>` segment is passed through `sanitizeNftIdent` (maps any
  byte outside the bare-safe nft set `[A-Za-z0-9_.-]` to `_`, length-preserving),
  because the counter is emitted both as a REFERENCE (above, quoted — nft accepts
  it) AND as a DECLARATION. **The DECLARATION is emitted UNQUOTED
  (`counter <n> { }`, #3578):** nft v1.1.6 rejects a quoted name in declaration
  position (`counter "<n>" { }` → `syntax error, unexpected quoted string`),
  which previously aborted the whole atomic `nft -f` load so the host-inbound
  chain never installed. For an exotic zone name carrying nft-unsafe bytes
  (commit blocks only `/`) the sanitized form is what surfaces as the Prometheus
  zone label, and two such zones can collide onto one counter (metric
  aggregation only — DROP rules stay per `(zone, daddr)`). The named counter
  objects are declared at the top of the table body,
  so the table now uses an `add table` / `delete table` / recreate idiom instead
  of lo0's plain `flush table`: `flush` keeps named objects, so redeclaring the
  counters on the next commit would collide ("File exists"). delete+recreate also
  drops a stale counter for a zone that no longer enforces. A consequence is that
  these counters reset to zero on every table rebuild (every commit + every
  DHCP/DHCPv6 address change that re-renders the chain); Prometheus `rate()` reset
  detection handles this. `pkg/nftables.ReadHostInboundDenyCounters()` reads the
  counters back via netlink (no nft shell-out) and the API collector
  (`pkg/api/metrics_counters.go:collectHostInboundKernelDenies`) exports them as
  `xpf_host_inbound_kernel_denies_total{zone,family}` (REST aggregate
  `host_inbound_kernel_denies`). This is the PRIMARY host-inbound enforcement
  path and is DISTINCT from the userspace-dp `xpf_host_inbound_denies_total`
  (`GlobalCtrHostInboundDeny`, #3326) — they are not double counts. Before #3361
  these kernel drops were uncounted and `host_inbound_denies` stayed 0 even while
  the firewall was actively denying control-plane traffic. The #5644 cold-boot
  fail-closed FENCE re-creates that blind spot on purpose (it renders catch-all
  DROPs with NO named counters), so `ReadHostInboundDenyCounters` reports the
  present-but-counterless table as `HostInboundTableCounterless` and the API
  marks that zero non-authoritative rather than publishing it (#5719). Adding a
  named counter to the fence would silently re-certify the zero.

## RPM + ip-monitoring wiring (#1827)

- `daemon_rpm.go` — config-hash-gated RPM probe lifecycle
  (`reconcileRPM`, applyConfigLocked step 17b): probes + probe-pin
  rules re-apply only when the rendered RPM stanza (or RETH map, or
  the HA gating filter result) changed, so unrelated commits never
  wipe probe state. Also owns the §4.4 HA gating scope
  (`filterRPMForHAGating`).
- `daemon_ipmon.go` — `assembleFRRConfig` (the SOLE `frr.FullConfig`
  constructor, shared by the full apply path and the routes-only
  actuator) + `actuateRouteOverlay` (FRR re-render → snapshot publish
  via `PublishRouteOverlaySnapshot` → `BumpFIBGeneration` ONLY after
  publish success, under `applySem`). The ip-monitoring engine lives
  in `pkg/ipmon`; RG transitions re-evaluate gating via
  `reconcileIPMonGating` from `reconcileRGState`.
