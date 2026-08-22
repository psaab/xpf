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
  instance. `handleEventStreamFullResync` likewise resolves its session
  exporter from the cell on every call, so a full resync after a rollback
  + corrected re-arm exports from the CURRENT backend rather than the
  torn-down one (#6743 r2-B8, bound by
  `full_resync_per_call_6743_test.go`). Behavioural guards live in
  `daemon_dp_escape_test.go` (gRPC) and `daemon_dp_escape_rest_test.go`
  (REST); `daemon_ha_userspace_stream_live_test.go` drives the event-stream
  loop across a `setDataplane(nil)`, across a stream replacement, and —
  on the reconcile-cadence branch, which needs its own connected-stream
  fixture — across a backend republication (#6743 r2-B3).

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
  `activeTransport()` snapshot for both its comparison and its eight log
  fields.

`make test-failover` is the required smoke for this path. The guard is covered
by `daemon_ha_comms_race_test.go` (deterministic drop-of-stale-publish +
`-race` concurrency) and, for the transport key, by
`cluster_transport_race_6290_test.go` (production writer vs production reader
under `-race`, plus a deterministic stale-epoch drop).

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
    input` host-inbound chains are untouched. The daemon does NOT exit.
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
  install fail-closed (#5644/#5789). When the netlink install fails because the
  kernel `nf_tables` subsystem is UNAVAILABLE, the returned error is tagged
  `xnft.ErrNFTablesUnavailable` (a one-time distinct operator log +
  Config-Sync `CF` monitor-failure reason, §12.5) without ever downgrading
  fail-closed. The `nftApplyPayload` / `nftDeleteTable` package vars and the
  `build*Payload` text builders are RETAINED as the parity-CI ORACLE (and the
  `TestNftDeleteTable*IdempotentAddDelete` payload-shape tests) — do NOT delete
  them while the parity CI depends on them; production no longer calls them.

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
  re-reconciles). Deliberately LEFT best-effort (WARN, not surfaced): the
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
  **Lifeline safety:** a zone with NO stanza emits no deny (admit-all);
  management/cluster-control interfaces (fxp0 / em0 / fab*) are excluded from
  the address sets so a host-inbound deny can never strand management or break
  HA; `ct state established,related` and IPv6 ND + v4/v6 PMTUD control messages
  are accepted before any deny; a configured zone that resolves to zero
  recognized matches fails OPEN (no deny) rather than locking the zone out.
  **Unzoned interfaces (#4420 HI-2):** an interface that carries an address but
  is assigned to NO security zone is not covered by any per-zone view above, so
  before #4420 its firewall-local addresses fell through the chain's
  `policy accept` to the host stack with NO host-inbound admission — a fail-open,
  and a deviation from Junos (an interface not in a zone passes no flow /
  host-inbound traffic at all). `applyHostInboundFilter` now also scopes a
  catch-all DROP to those addresses (`userspace.BuildUnzonedHostInboundAddrs`,
  counted under the reserved `junos-host` sentinel label so the #3361 scraper
  reports them as `zone="junos-host"`). Lifelines are excluded and zoned
  addresses subtracted, so it can never strand management or conflict with a zone
  rule; it is emitted only when the zone model is in use (>= 1 zone), so a
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
  the firewall was actively denying control-plane traffic.

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
