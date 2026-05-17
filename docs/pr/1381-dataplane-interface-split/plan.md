# #1381 dataplane interface split plan

Status: design/scaffold PR for #1381, prerequisite to #1373 Phase 4.

This PR does not remove the eBPF dataplane. It makes the split actionable by
pinning the target interfaces, the daemon migration order, and the state
ownership decisions that must hold before the BPF-shaped `dataplane.DataPlane`
surface can disappear.

## Current coupling

`pkg/dataplane/dataplane.go` exposes one `DataPlane` interface with 130
methods. It mixes:

- eBPF loader and raw map access (`AttachXDP`, `AttachTC`, `Map`, stale-map
  cleanup);
- config lowering writers (`SetZone`, `SetSNATRule`, `SetPolicerConfig`,
  `UpdatePolicyScheduleState`);
- runtime session and counter APIs;
- HA, fabric, scheduler, link-cycle, and event APIs.

`pkg/dataplane/userspace/manager.go` currently embeds `dataplane.DataPlane`
and keeps `inner *dataplane.Manager`. That makes userspace compile by
inheriting all eBPF writers. It also makes userspace runtime state depend on
`m.inner.Map(...)` for XDP shim maps, BPF conntrack mirrors, DNAT bridge maps,
FIB generation, RG state, and helper control.

`pkg/daemon` stores one `dataplane.DataPlane` and calls both generic runtime
methods and BPF-shaped methods from the same field. The real daemon surface is
smaller than the current interface: lifecycle/config, HA/fabric, session
lookup/iteration, events, scheduler state, link-cycle hooks, and a few
userspace-only optional interfaces.

## Current caller inventory

The split must move real callers, not only reshape `pkg/dataplane` in
isolation. The current consumers are:

| Consumer | Current dependency | Target domain |
|---|---|---|
| `pkg/api/server.go` (`Config.DP`, `Server.dp`) | REST handlers and metrics read sessions, counters, events, NAT/policy/filter state, and userspace status through `dataplane.DataPlane`. | `Telemetry`, `SessionStore`, plus an explicit userspace status/control extension kept out of the root interface. |
| `pkg/grpcapi/server.go` (`Config.DP`, `Server.dp`) | gRPC show/monitor/control paths read generic counters and type-assert userspace status/control DTOs. | `Telemetry`, `SessionStore`, `LinkController`, and a backend-specific userspace control adapter. |
| `pkg/cli/cli.go` (`CLI.dp`) | Operational commands read sessions/counters/events and some userspace-only status surfaces. | CLI should consume gRPC for remote operation; in-process CLI should use `Telemetry`, `SessionStore`, and explicit optional userspace diagnostic interfaces. |
| `pkg/conntrack/gc.go` (`GC.dp`) | GC iterates/deletes BPF session maps and pushes per-IP session-limit state. | `SessionStore` for iteration/delete/count. Per-IP screen/session-limit publish remains backend-private config/state work. |
| `pkg/cluster/sync.go` (`SessionSync.dp`) | HA sync exports/imports sessions, installs cluster-synced entries, type-asserts userspace sweep-profile hooks, and stale-reconcile manually deletes reverse sessions plus DNAT companions. | `SessionStore` for install/delete/export/reconcile and a narrow `SessionDeltaSource` adapter hanging off the session domain. Companion reverse/NAT cleanup must be owned by the same session/NAT delete semantics as GC. |
| Daemon HA/fabric/apply code | Calls `UpdateRGActive`, `UpdateHAWatchdog`, `UpdateFabricFwd`, `UpdateFabricFwd1`, `SyncFabricState`, BPF writers, scheduler updates, and userspace link-cycle hooks. | `HAController`, `ConfigSink`, `LinkController`; BPF writers stay inside the eBPF backend. |
| Metrics/API/CLI session and counter readers | Mix map-backed eBPF counters, helper JSON status, and userspace formatting DTOs. | `Telemetry` owns generic counters/events; userspace-only formatting remains an extension with adapter-local DTO conversion. |

Each migration phase must name which rows it removes from the old root
`DataPlane`; otherwise the root interface can shrink on paper while callers
keep depending on the BPF-shaped surface through side assertions.

## Stub mode rejection

Stub mode is rejected for production and for the #1373 Phase 4 path.

Adding no-op userspace implementations for the 100+ BPF-shaped writers would
keep the build green while hiding missing feature ownership. It would also keep
daemon code structured around map writes that userspace must not receive after
the split. A temporary stub is only acceptable as compile-only scaffolding in a
single migration PR when all of these are true:

- the stub returns a typed `ErrUnsupportedDataplaneOperation` or panics in
  tests, never silently succeeds;
- the call site is deleted or rerouted in the same stacked series;
- a canary fails if the stub remains after the phase that introduced it.

The target design is split-by-domain, not stub-by-method.

## Target public interfaces

The daemon-owned abstract dataplane should shrink to this interface. It has 9
methods and no BPF map writers:

```go
type DataPlane interface {
	Start(context.Context) error
	ApplyConfig(context.Context, *config.Config) (*ApplyResult, error)
	LastApplyResult() *ApplyResult
	Close() error
	Teardown() error

	Link() LinkController
	HA() HAController
	Sessions() SessionStore
	Telemetry() Telemetry
}
```

`Start` replaces `Load` plus backend-specific background startup. For eBPF it
loads programs and seeds counters; for DPDK it starts route sync; for userspace
it starts the helper supervisor and the minimal XDP shim collection. `Close`
stops runtime resources. `Teardown` removes backend-owned persistent state.

`ApplyConfig` replaces daemon-driven BPF writer calls:

```go
type ApplyResult struct {
	ZoneIDs           map[string]uint16
	ManagedInterfaces []networkd.InterfaceConfig
	FilterIDs         map[string]uint32
	FilterSpans       map[string]FilterCounterSpan
	NATCounterIDs     map[string]uint32
	PoolIDs           map[string]uint8
	PolicyNames       map[uint32]string
	AppNames          map[uint16]string
	PolicyScheduleRuleSlots []PolicyScheduleRuleSlot
	Capabilities            Capabilities
	Generation              uint64
}

type FilterCounterSpan struct {
	FilterID  uint32
	RuleStart uint32
	RuleCount uint32
}

type ConfigSink interface {
	ApplyConfig(context.Context, *config.Config) (*ApplyResult, error)
	LastApplyResult() *ApplyResult
}
```

The eBPF backend may keep its existing compiler internally, but `Set*`,
`Clear*`, `DeleteStale*`, `UpdatePolicyScheduleState`, and `Map` become
methods on the eBPF manager only. Userspace builds a snapshot/helper update
from `*config.Config`; DPDK keeps its own lowering path.

`ApplyResult` is also the replacement for the display metadata currently read
through `LastCompileResult()`. It must carry at least:

- `FilterIDs` and `FilterSpans` for firewall counter display. Today
  `pkg/grpcapi/server_show_firewall.go` and `pkg/cli/cli_show_security.go`
  use `LastCompileResult().FilterIDs` and then read BPF filter config to find
  `RuleStart`. After the split, `RuleStart` must be carried in the apply
  result or a backend-neutral telemetry metadata object; display code must not
  call `ReadFilterConfig` on the root interface.
- `NATCounterIDs` for source NAT rule display. Today `pkg/cli/cli_show_nat.go`
  maps `rule-set/rule` to a counter ID via `LastCompileResult().NATCounterIDs`.
  That mapping is config/apply metadata, not a BPF map-writer method, so it
  belongs in `ApplyResult`.
- `PoolIDs`, `PolicyNames`, `AppNames`, and `PolicyScheduleRuleSlots` for NAT
  display, flow/session attribution, event labels, and policy-scheduler
  runtime updates. Scheduler callers must consume the compiled slots directly;
  eBPF/DPDK/userspace must not recompute slots from original config indexes.
- stable generation numbers for those IDs so mixed old/new metadata cannot be
  combined with counters from a different apply generation.

`LinkController` owns link-cycle behavior that currently leaks through optional
interfaces:

```go
type LinkController interface {
	SetDeferWorkers(bool)
	PrepareLinkCycle()
	NotifyLinkCycle()
}
```

Backends that do not need a hook return a no-op `LinkController`. The daemon
must stop type-asserting to `*userspace.Manager` for link behavior.

`HAController` owns redundancy-group and fabric state:

```go
type HAController interface {
	SetRGActive(context.Context, int, bool) error
	SetHAWatchdog(context.Context, int, uint64) error
	SetFabricForwarding(context.Context, FabricID, dataplane.FabricFwdInfo) error
	SyncFabricState(context.Context) error
}

type FabricID uint8
```

`UpdateFabricFwd` and `UpdateFabricFwd1` collapse into one method keyed by
`FabricID`. Userspace sends helper control messages. eBPF writes `fabric_fwd`
maps. DPDK writes its shared-memory state.

`SessionStore` owns read/write session state used by GC, CLI, HA sync, and
event reconciliation:

```go
type SessionStore interface {
	ForEachV4(func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	ForEachV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	GetV4(dataplane.SessionKey) (dataplane.SessionValue, error)
	GetV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error)
	PutClusterSyncedV4(dataplane.SessionKey, dataplane.SessionValue) error
	PutClusterSyncedV6(dataplane.SessionKeyV6, dataplane.SessionValueV6) error
	DeleteV4(dataplane.SessionKey) error
	DeleteV6(dataplane.SessionKeyV6) error
	Count() (v4, v6 int)
	Clear() (v4, v6 int, err error)
}
```

The eBPF implementation wraps `sessions` and `sessions_v6`. Userspace wraps
the helper session socket/event stream and its Rust-owned session store. GC
must depend on `SessionStore`, not raw BPF map iteration.

GC migration is not only `ForEach` plus `Delete`. The current GC also owns
side effects that must move to explicit domain methods:

- session-change gating reads `GlobalCtrSessionsNew` and
  `GlobalCtrSessionsClosed`; this becomes `Telemetry.GlobalCounter` or a
  `SessionStore.ChangeGeneration()` helper, not a raw dataplane call;
- per-IP session-limit counting publishes screen/session-limit maps after the
  sweep; this becomes backend-private config/state publish on the eBPF backend
  and a userspace snapshot/control update on the userspace backend;
- persistent-NAT preservation currently saves bindings before session delete;
  `SessionStore.Delete*` must either perform the preservation atomically or
  expose a `BeforeDelete` hook owned by the NAT/session domain;
- DNAT reverse-entry cleanup currently calls `DeleteDNATEntry*`; delete
  ownership must move into the backend session/NAT store so expiring a session
  removes companion DNAT/NAT64 reverse state in the same generation; and
- GC stats must still count v4/v6 entries and expired deletes without assuming
  BPF map iteration order.

Cluster sync has the same delete problem through a different path. The stale
bulk reconcile path in `pkg/cluster/sync.go` currently iterates local sessions,
finds peer-owned entries absent from the received bulk set, then manually
deletes:

- the forward session;
- the reverse session referenced by `SessionValue.ReverseKey`; and
- companion DNAT/NAT64 reverse entries via `DeleteDNATEntry*`.

That logic must not remain a separate BPF-shaped cleanup copy after the split.
Move it behind a session-domain operation such as:

```go
type SessionStore interface {
	// ...
	DeleteWithCompanionsV4(dataplane.SessionKey, DeleteReason) error
	DeleteWithCompanionsV6(dataplane.SessionKeyV6, DeleteReason) error
	ReconcileClusterBulk(ClusterBulkReconcileInput) (ClusterBulkReconcileResult, error)
}
```

The exact method shape can change during implementation, but the invariant is
fixed: GC expiry and cluster stale reconciliation must use the same backend
delete semantics so reverse-key cleanup, DNAT/NAT64 cleanup, persistent-NAT
preservation, and generation accounting cannot drift. Existing
`pkg/cluster/sync_test.go` mocks that record `DeleteDNATEntry*` as no-op
callbacks are not sufficient; they let the split compile while preserving the
duplicated cleanup path.

Userspace session deltas remain an optional extension until the generic event
stream can carry the same information:

```go
// Package pkg/dataplane/runtime, not pkg/dataplane/userspace.
type SessionDelta struct {
	Family      SessionFamily
	Key         SessionIdentity
	Value       SessionState
	OwnerRGID   int
	Reason      SessionDeltaReason
	Generation  uint64
}

type SessionDeltaSnapshot struct {
	Deltas        []SessionDelta
	Status        RuntimeStatus
	BackendEpoch  uint64
	Truncated     bool
}

type SessionDeltaSource interface {
	DrainSessionDeltas(max uint32) (SessionDeltaSnapshot, error)
	ExportOwnerRGSessions(rgIDs []int, max uint32) (SessionDeltaSnapshot, error)
	SessionSyncSweepProfile() (enabled bool, fast, slow time.Duration)
}
```

`SessionStore.SessionDeltas()` is the bridge for this optional source. Generic
map-backed session stores return nil; the userspace backend returns an adapter
that converts helper-private DTOs into `pkg/dataplane/runtime` DTOs at the
backend boundary.

These DTOs must live in the same package as the abstract runtime interfaces or
in a third leaf package imported by both `pkg/dataplane` and
`pkg/dataplane/userspace`. The public interface must not reference
`userspace.SessionDeltaInfo`, `userspace.ProcessStatus`, or any other
`pkg/dataplane/userspace` type. Otherwise `pkg/dataplane` gains a reverse import
on one backend while `pkg/dataplane/userspace` already imports `pkg/dataplane`,
creating a package cycle and making the abstraction unusable. The userspace
manager should adapt its helper protocol DTOs to these runtime DTOs at the
backend boundary.

`Telemetry` owns events and counters:

```go
type Telemetry interface {
	NewEventSource() (dataplane.EventSource, error)
	GlobalCounter(uint32) (uint64, error)
	ReadFloodCounters(uint16) (dataplane.FloodState, error)
	InterfaceCounters(int) (dataplane.InterfaceCounterValue, error)
	ZoneCounters(uint16, int) (dataplane.CounterValue, error)
	PolicyCounters(uint32) (dataplane.CounterValue, error)
	FilterCounters(uint32) (dataplane.CounterValue, error)
	NATRuleCounter(uint32) (dataplane.CounterValue, error)
	NATPortCounter(uint32) (uint64, error)
	MapStats() []dataplane.MapStats
}
```

Counter reset/seed methods are backend-private lifecycle/config work. Raw
`Map(name)` is not exposed by the abstract interface.

## Architectural mismatch with prior split work

This plan is intentionally narrower than the earlier map-ownership and
userspace-retirement plans:

- #961-style map ownership plans move individual BPF maps to clearer owners.
  This plan removes map writers from the daemon-facing abstraction entirely;
  backend-private eBPF maps may remain after the root interface split.
- #946 Phase 2 work focused on userspace state parity while eBPF remained a
  compatibility substrate. This plan defines the package/interface boundary
  that lets that state parity become the only daemon dependency.
- #964 Step 3-style cleanup deletes residual userspace/eBPF coupling once
  features are already owned by the userspace backend. This plan is the
  prerequisite contract that prevents new callers from reintroducing that
  coupling during #1373.

Do not treat any of those patterns as an implicit implementation of this plan:
the acceptance gate here is caller migration off the BPF-shaped root interface,
not only map cleanup or feature parity.

## Daemon migration

The daemon should migrate in this order:

1. Introduce the new interfaces beside the old `DataPlane`. Add adapters:
   `ebpfAdapter`, `userspaceAdapter`, and `dpdkAdapter` can delegate to current
   managers while callers move.
2. Change `Daemon.dp` to the new 9-method interface. Keep the old interface
   behind `internal/ebpfwriter` or an unexported adapter used only by the eBPF
   compiler.
3. Move `applyConfigLocked` compile work behind `dp.ApplyConfig`. The daemon
   keeps kernel-side setup before apply: VRFs, tunnels, XFRM, bonds, fabric
   IPVLAN, RETH MAC, networkd application using `ApplyResult`.
4. Move scheduler updates into `ApplyConfig` or an explicit `ConfigSink`
   delta. `UpdatePolicyScheduleState` must not remain a daemon call because it
   is read/write state tied to policy ownership, not generic telemetry.
5. Replace `d.dp.UpdateRGActive`, `UpdateHAWatchdog`, `UpdateFabricFwd`,
   `UpdateFabricFwd1`, and `SyncFabricState` with `d.dp.HA()`.
6. Replace GC, logging, HA sync, and CLI session reads with `d.dp.Sessions()`.
   Userspace `SessionDeltaSource` remains optional and is type-asserted from
   the sessions domain, not the root dataplane.
7. Replace `NewEventSource` and counter reads with `d.dp.Telemetry()`.
8. Replace userspace type assertions in fabric/IPVLAN/link-cycle handling with
   `d.dp.Link()` and a narrow userspace binding-ready callback interface.
9. Delete userspace embedding of `dataplane.DataPlane` and `inner
   *dataplane.Manager`. At this point the canary added by this PR must be
   inverted to fail if either dependency returns.

## BPF pin ownership

Pins in `UserspaceMapPins` and related userspace shim maps need explicit
owners before the eBPF dataplane source is removed.

| Pin | Current dependency | Target owner before #1373 Phase 4 |
|---|---|---|
| `/sys/fs/bpf/xpf/userspace_ctrl` | Go writes ctrl/armed state; Rust reads helper control. | Minimal userspace XDP shim. Keep while AF_XDP redirect uses a BPF shim. Replace with helper control socket only if the shim is removed later. |
| `/sys/fs/bpf/xpf/userspace_bindings` | Go publishes slot/queue/ifindex plan for XDP redirect. | Minimal userspace XDP shim. Source of truth is `ConfigSnapshot`; pin is derived runtime state. |
| `/sys/fs/bpf/xpf/userspace_ingress_ifaces` | Go publishes ingress allowlist/fallback metadata. | Minimal userspace XDP shim until fallback path is gone; derived from snapshot. |
| `/sys/fs/bpf/xpf/userspace_heartbeat` | Rust workers update liveness; Go reads status. | Minimal userspace XDP shim. Long-term telemetry should move to helper status socket, but not required before eBPF dataplane removal. |
| `/sys/fs/bpf/xpf/userspace_xsk_map` | Rust opens fd for AF_XDP redirect. | Minimal userspace XDP shim. Required as long as AF_XDP redirect is XDP-map based. |
| `/sys/fs/bpf/xpf/userspace_local_v4` | Go mirrors local IPv4 addresses for shim/fallback behavior. | Userspace helper snapshot/state. Remove pin before Phase 4. |
| `/sys/fs/bpf/xpf/userspace_local_v6` | Go mirrors local IPv6 addresses for shim/fallback behavior. | Userspace helper snapshot/state. Remove pin before Phase 4. |
| `/sys/fs/bpf/xpf/userspace_sessions` | Rust requires this BPF map for live helper session keys. | Rust-owned in-memory/session-store state exposed by session socket/event stream. Remove pin before Phase 4. |
| `/sys/fs/bpf/xpf/sessions` | Rust optionally mirrors v4 sessions for `show security flow session`; eBPF GC/CLI read it. | `SessionStore` implementation. Userspace CLI reads helper sessions; eBPF-only backend keeps private map. Remove userspace dependency before Phase 4. |
| `/sys/fs/bpf/xpf/sessions_v6` | Same as `sessions` for IPv6. | Same as `sessions`. Remove userspace dependency before Phase 4. |
| `/sys/fs/bpf/xpf/dnat_table` | Rust opens optional v4 DNAT mirror for embedded ICMP NAT reversal and fallback. | Rust NAT/session state. Remove pin before Phase 4. |
| `/sys/fs/bpf/xpf/dnat_table_v6` | Same as `dnat_table` for IPv6. | Rust NAT/session state. Remove pin before Phase 4. |
| `/sys/fs/bpf/xpf/userspace_trace` | Shim/helper trace diagnostics. | Minimal userspace XDP shim until replaced by userspace event/trace channel. |
| `/sys/fs/bpf/xpf/userspace_cpumap` | Go programs cpumap redirect for the shim. | Minimal userspace XDP shim only if cpumap redirect remains enabled. Derived from worker config. |
| `/sys/fs/bpf/xpf/userspace_fallback_progs` | Go wires fallback program tail calls for compat mode. | Remove before Phase 4; there is no eBPF fallback dataplane after #1373. |
| `/sys/fs/bpf/xpf/userspace_fallback_stats` | Go reads fallback stats from shim. | Remove before Phase 4 or replace with userspace telemetry counters. |
| `/sys/fs/bpf/xpf/userspace_interface_nat_v4` | Go publishes interface SNAT helper state. | Rust NAT config from snapshot. Remove pin before Phase 4. |
| `/sys/fs/bpf/xpf/userspace_interface_nat_v6` | Same as v4. | Rust NAT config from snapshot. Remove pin before Phase 4. |
| `/sys/fs/bpf/xpf/links/xdp_*`, `/sys/fs/bpf/xpf/links/tc_*` | eBPF manager pins attach links; userspace removes XDP link pins before recompile. | eBPF backend private. Userspace shim owns only its own XDP attachment lifecycle; no TC link ownership. |

The Phase 4 invariant is: userspace may keep the minimal AF_XDP/XDP shim pins,
but it must not depend on eBPF firewall/session/NAT maps or `*dataplane.Manager`
for state ownership.

## Migration phases

Phase 0: scaffold and canaries.

- Land this plan.
- Keep current behavior unchanged.
- Add AST canary documenting the current userspace embedding and `inner`
  dependency so future work cannot claim the split is done without updating
  the test.

Phase 1: interfaces and adapters.

- Add the target interfaces and adapters while `dataplane.DataPlane` remains.
- Move daemon call sites one domain at a time.
- Add compile-time assertions for the new root interface and domains.
- Add a negative compile/test canary ensuring userspace code cannot call raw
  eBPF `Set*`/`Clear*`/`Map` methods through the new root interface.

Phase 2: config ownership.

- Move daemon `Compile` calls to `ApplyConfig`.
- Keep eBPF writer methods on `*dataplane.Manager`.
- Userspace `ApplyConfig` owns snapshot publish, helper control, and derived
  shim map writes.
- Scheduler state is applied through config ownership, not a daemon map write.

Phase 3: session, NAT, and telemetry ownership.

- Replace userspace dependencies on `userspace_sessions`, `sessions`,
  `sessions_v6`, `dnat_table`, and `dnat_table_v6`.
- CLI/API/session sync read through `SessionStore`.
- Embedded ICMP NAT reversal reads Rust-owned NAT/session state.
- Event stream carries policy deny, screen drop, filter log, and session events
  needed by #1379.

Phase 4: remove eBPF inheritance.

- Delete `dataplane.DataPlane` embedding and `inner *dataplane.Manager` from
  userspace `Manager`.
- Invert the scaffold canary: userspace Manager must not embed
  `dataplane.DataPlane`, must not name `*dataplane.Manager`, and must not
  import `github.com/cilium/ebpf` outside the XDP shim owner package.
- Remove daemon access to old BPF-shaped interface.

Phase 5: eBPF source retirement gate for #1373.

- Delete or isolate eBPF firewall source once #1374, #1375, #1376, #1377,
  #1378, #1379, and the #1380 telemetry decision are satisfied.
- Keep only the minimal AF_XDP/XDP shim code if still required for redirect.

## Compatibility matrix

| Surface | Required compatibility during split |
|---|---|
| REST API | Existing `/api/v1` responses must stay wire-compatible. Handler internals may move from `DataPlane` to `Telemetry`/`SessionStore`, but JSON names and counter/session semantics must not change without a versioned API note. |
| gRPC API | Existing protobuf messages and service methods stay stable. Userspace-only operational controls may use adapter-local interfaces, but generated protobuf DTOs must not import backend packages. |
| CLI | Local and remote CLI output must stay equivalent. In-process CLI can depend on runtime domains; remote CLI should continue to prefer gRPC so command behavior does not depend on whether it runs inside `xpfd`. |
| Cluster session sync | Session install/delete/export semantics must be unchanged across mixed-version peers until the HA compatibility version is explicitly bumped. Any new `SessionDeltaSnapshot` fields must have zero-value behavior. |
| Metrics | Metric names, labels, and counter/gauge types stay stable. Backend-local counter resets must not leak through a domain-interface migration. |
| Config-only and compile-failed mode | `show`, `commit check`, and API health paths must not require a live userspace helper unless the old path already did. `ApplyConfig` errors must leave `LastApplyResult` at the last successful generation. |

## Risks and invariants

- Stale handles: callers may cache `d.dp.Sessions()` or `d.dp.Telemetry()`.
  Domain objects must either remain valid across config apply or fail with a
  typed stale-generation error that forces the caller to reacquire them.
- Lifetime ordering: `Close`, `Teardown`, helper restart, and HA demotion must
  not race with outstanding session/counter readers. Interfaces that return
  snapshots must copy data or document a generation-bound lifetime.
- Atomic apply visibility: `ApplyConfig` must publish config, capability,
  session, counter, and shim-map generations in an order where readers see
  either the old complete generation or the new complete generation, not a
  hybrid.
- Replay windows: HA `SessionDeltaSource` exports must carry a backend epoch or
  monotonically increasing generation so reconnect/retry paths do not replay a
  stale delete over a newer create.
- Backend escape hatches: optional userspace controls are allowed only as leaf
  adapter interfaces. They must not become methods on the root `DataPlane`,
  because that recreates a userspace-shaped root after removing the BPF-shaped
  one.
- Failure attribution: migration code must distinguish unsupported backend
  capability from transient helper failure. Silent no-op adapters are
  forbidden outside tests.

## Tests and canaries

Required during the split:

- `go test ./pkg/dataplane/... ./pkg/dataplane/userspace/... ./pkg/daemon/...`
- `go build ./...`
- AST canary: userspace `Manager` must not embed `dataplane.DataPlane` or hold
  `inner *dataplane.Manager` after Phase 4. This PR adds the temporary
  pre-split form that records the current debt.
- Interface method-count canary: the exported root `DataPlane` interface has
  at most 15 methods after Phase 1.
- Import canary: the abstract dataplane/runtime package must not import
  `pkg/dataplane/userspace`, and backend packages must adapt their private DTOs
  at the package boundary.
- Negative userspace compile canary: userspace code cannot call eBPF-only
  writer methods through the abstract dataplane.
- Session parity tests: eBPF and userspace `SessionStore` produce equivalent
  `show security flow session` data, including v4/v6, NAT flags, RG metadata,
  and reverse entries.
- Apply-result metadata tests: firewall filter display and source NAT rule
  display use `LastApplyResult().FilterIDs`, `FilterSpans.RuleStart`, and
  `NATCounterIDs`, with no calls to `ReadFilterConfig` or
  `LastCompileResult()` through the root dataplane.
- GC side-effect tests: session expiry preserves persistent-NAT bindings,
  removes companion DNAT/NAT64 reverse entries, updates per-IP session-limit
  state, and uses backend-neutral session-change telemetry.
- Cluster stale-reconcile tests: bulk reconciliation deletes the forward
  stale session through `SessionStore`, removes the reverse-key companion, and
  removes DNAT/NAT64 reverse state through the same session/NAT-owned delete
  path used by GC. Tests must fail if `pkg/cluster/sync.go` keeps a local
  `DeleteDNATEntry*` cleanup copy.
- NAT embedded ICMP tests: userspace no longer depends on BPF `dnat_table`
  pins for v4 or v6 reversal.
- HA canaries: RG activation, watchdog, fabric0/fabric1 updates, manual
  failover prep, and userspace event-stream export remain green.
- Scheduler canary for #1378: changing a time-based scheduler updates the
  active policy state in userspace without a daemon-side BPF map write.
- Event canary for #1379: userspace emits PolicyDeny, ScreenDrop, FilterLog,
  SessionOpen, and SessionClose through the generic event source.

Operational canaries:

- `loss:xpf-userspace-fw0/1` IPv4 and IPv6 iperf before/after failover.
- Native GRE userspace validation with transit staying on WAN and `gr-0-0-0`
  out of transit.
- Userspace HA validation with repeated RG failover and no stale VIP/session
  ownership.
- Cold restart with stale pins present: startup must either ignore removed
  pins or replace them from owned userspace state.

## Non-goals for this PR

- Removing eBPF programs or generated BPF Go files.
- Replacing AF_XDP/XDP shim attachment.
- Implementing #1374 through #1380 feature parity.
- Making userspace manager independent of `*dataplane.Manager` in this patch.

## Phase 1 acceptance gate

Phase 1 is not complete until all of these are true:

- the root interface compiles without importing any backend package;
- the caller inventory above has an owner row for every remaining old
  `dataplane.DataPlane` call site;
- adapters preserve REST, gRPC, CLI, metrics, cluster sync, and config-only
  behavior from the compatibility matrix;
- tests include import, method-count, negative-writer, and stale-generation
  canaries;
- firewall/NAT show commands have moved from compile-result/BPF-filter-config
  reads to `ApplyResult` metadata; and
- GC side effects are owned by `SessionStore`/NAT/Telemetry domains rather than
  raw BPF map methods; and
- cluster stale reconciliation uses the same `SessionStore`/NAT companion-delete
  semantics as GC and has reverse-key plus DNAT/NAT64 cleanup tests; and
- rollback is documented as switching the daemon back to the existing
  `dataplane.DataPlane` adapter without changing persistent config format.

## Implementation note: first Phase 1 slice

The first implementation slice keeps the legacy BPF-shaped `DataPlane`
interface in place and adds the new contract beside it:

- `pkg/dataplane.RuntimeDataPlane`, `ConfigSink`, `ApplyResult`,
  `SessionStore`, `Telemetry`, HA, and link-domain interfaces are now defined
  without importing backend packages.
- `ApplyResult` carries `FilterIDs`, `FilterSpans` (`FilterID`, `RuleStart`,
  `RuleCount`), `NATCounterIDs` widened to `uint32`, `PoolIDs`,
  `PolicyNames`, `AppNames`, compiled `PolicyScheduleRuleSlots`,
  capabilities, and a generation. eBPF, DPDK, and userspace compiles now
  publish `LastApplyResult()`.
- `pkg/dataplane/runtime` owns the neutral session-delta DTOs and
  `SessionDeltaSource`; `SessionStore.SessionDeltas()` exposes that optional
  source and userspace adapts its helper-private
  `SessionDeltaInfo`/`ProcessStatus` at the package boundary.
- eBPF, DPDK, and userspace managers now satisfy `RuntimeDataPlane` at
  compile time. Shared adapters cover eBPF/DPDK HA plus generic telemetry and
  session surfaces; userspace keeps backend-specific link and HA controllers so
  link-cycle prepare/defer/rebind semantics and fabric-state helper sync stay
  intact.
- Cluster stale-bulk reconciliation now routes through
  `dataplane.SessionStore.ReconcileClusterBulk`, whose companion-delete path
  owns forward, reverse, and DNAT/DNATv6 cleanup. A canary fails if
  `pkg/cluster/sync.go` reintroduces local `DeleteDNATEntry*` cleanup.

Remaining Phase 1 work is still explicit: daemon/API/gRPC/CLI callers must move
from `LastCompileResult()` and BPF map reads to `LastApplyResult()`/domain
interfaces, GC must move to `SessionStore`/`Telemetry`, and the legacy
`DataPlane` method-count canary can only flip after those callers no longer need
the BPF-shaped surface.
