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
	Capabilities      Capabilities
	Generation         uint64
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

Userspace session deltas remain an optional extension until the generic event
stream can carry the same information:

```go
type SessionDeltaSource interface {
	DrainSessionDeltas(max uint32) ([]userspace.SessionDeltaInfo, userspace.ProcessStatus, error)
	ExportOwnerRGSessions(rgIDs []int, max uint32) ([]userspace.SessionDeltaInfo, userspace.ProcessStatus, error)
	SessionSyncSweepProfile() (enabled bool, fast, slow time.Duration)
}
```

`Telemetry` owns events and counters:

```go
type Telemetry interface {
	NewEventSource() (dataplane.EventSource, error)
	GlobalCounter(uint32) (uint64, error)
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

## Tests and canaries

Required during the split:

- `go test ./pkg/dataplane/... ./pkg/dataplane/userspace/... ./pkg/daemon/...`
- `go build ./...`
- AST canary: userspace `Manager` must not embed `dataplane.DataPlane` or hold
  `inner *dataplane.Manager` after Phase 4. This PR adds the temporary
  pre-split form that records the current debt.
- Interface method-count canary: the exported root `DataPlane` interface has
  at most 15 methods after Phase 1.
- Negative userspace compile canary: userspace code cannot call eBPF-only
  writer methods through the abstract dataplane.
- Session parity tests: eBPF and userspace `SessionStore` produce equivalent
  `show security flow session` data, including v4/v6, NAT flags, RG metadata,
  and reverse entries.
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
