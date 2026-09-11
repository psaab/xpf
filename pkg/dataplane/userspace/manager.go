package userspace

import (
	"context"
	"net"
	"os/exec"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"net/netip"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

var _ dataplane.ConfigSink = (*Manager)(nil)
var _ dataplane.RuntimeDataPlane = (*Manager)(nil)

// DataplaneMode describes which packet-processing pipeline is active.
type DataplaneMode int

const (
	ModeEBPFOnly        DataplaneMode = iota // Fallback-only, no userspace forwarding
	ModeUserspaceCompat                      // Userspace preferred, degraded transit fails closed
	ModeUserspaceStrict                      // Strict userspace only, no transit fallback
)

const userspaceXDPEntryProg = "xdp_userspace_prog"

func (m DataplaneMode) String() string {
	switch m {
	case ModeEBPFOnly:
		return "ebpf_only"
	case ModeUserspaceCompat:
		return "userspace_compat"
	case ModeUserspaceStrict:
		return "userspace_strict"
	default:
		return "unknown"
	}
}

func init() {
	// RegisterRuntimeBackend retains the userspace runtime as a
	// compatibility / test seam for callers that go through the legacy
	// dataplane.NewRuntimeDataPlane(...) factory (and for the existing
	// canaries that exercise the registry round-trip). Daemon startup
	// prefers userspace.Boot() directly via the pkg/daemon helper, so
	// this registry entry is no longer the canonical boot path.
	// Removing it is out of scope for #1520; #1474 already permits its
	// presence as the test / compatibility seam.
	dataplane.RegisterRuntimeBackend(dataplane.TypeUserspace, func() dataplane.RuntimeDataPlane {
		return Boot()
	})
}

// Boot constructs the userspace AF_XDP runtime and returns it as a
// dataplane.RuntimeDataPlane wrapped in the legacy-compatible adapter.
//
// Daemon startup prefers Boot() over dataplane.NewRuntimeDataPlane(
// TypeUserspace) for the default and explicit userspace selections.
// The runtime backend registry entry for TypeUserspace (see init()
// above) is retained as a compatibility / test seam — it remains
// reachable via dataplane.NewRuntimeDataPlane(TypeUserspace) but is
// no longer the canonical daemon boot path.
//
// The explicit "dataplane-type ebpf" rollback does NOT use the
// userspace registry entry at all; it goes through the
// dataplane.NewRuntimeDataPlane → TypeEBPF switch which constructs
// a bare *dataplane.Manager (legacy) via the legacy program loader.
//
// The returned value still implements dataplane.DataPlane via the
// adapter, so daemon.legacyDP() can keep handing a compatibility handle
// to the remaining CLI, gRPC, and cluster session-sync call sites until
// #1451 finishes the surface shrink. When #1521 / #1473 need to thread
// additional construction configuration in, they should add a typed
// options argument here. No empty options struct is added pre-emptively
// (YAGNI).
func Boot() dataplane.RuntimeDataPlane {
	return NewLegacyDataPlaneAdapter(New())
}

type Manager struct {
	bpfShim *dataplane.Manager

	mu        sync.Mutex
	sessionMu sync.Mutex // separate lock for session sync requests (Phase 3)
	// ctrlIOMu guards ctrlIOConns and ctrlShutdown, the #8526 stop bound on
	// control-socket round trips. It is a LEAF: nothing holding it acquires
	// m.mu, and the only legal order is m.mu -> ctrlIOMu. That is what lets
	// BeginControlShutdown run — and cut an in-flight round trip short —
	// while another goroutine holds m.mu across that very round trip. See
	// control_shutdown_8526.go for the hazard and the ordering rule.
	ctrlIOMu sync.Mutex
	// ctrlIOConns is the set of control-socket connections whose round trip
	// is in flight right now. requestDetailedLocked serializes on m.mu, so in
	// production this holds at most one entry; it is a set rather than a
	// single field so the bound does not depend on that staying true.
	ctrlIOConns map[net.Conn]struct{}
	// lastArmedControlDeadline is the deadline armControlIO last applied to a
	// control-socket connection, guarded by ctrlIOMu (#9344).
	//
	// It exists so the WIRING is checkable. requestDetailedLocked's choice of
	// sizing function was severable without a single test failing — a
	// mutation swapped controlWorkDeadline back for controlRoundtripDeadline
	// and the suite stayed green, because the cell that checks the floor calls
	// the sizing function directly and nothing observed what the socket got.
	// A behavioural alternative (a helper that sleeps past the base deadline)
	// would work but makes the cell timing-dependent; this makes it exact.
	lastArmedControlDeadline time.Duration
	// ctrlShutdown latches once the PROCESS is stopping, and never clears.
	// Only BeginControlShutdown sets it, and its only caller is the daemon's
	// runShutdownSequence, which the process does not return from. Close and
	// Teardown deliberately do NOT set it: the bootstrap rollback tears the
	// dataplane down and reuses this object, and a latch there would cap every
	// later apply at controlShutdownCeiling for the life of the daemon.
	ctrlShutdown bool
	proc         *exec.Cmd
	// procSup is the supervisor record for the CURRENTLY spawned helper
	// generation: the single goroutine that owns cmd.Wait() for it, plus the
	// channel that goroutine closes when the child is reaped (#5838).
	//
	// INVARIANT: procSup is non-nil exactly while proc is non-nil, and each
	// spawn allocates a strictly greater procGen. Every asynchronous callback
	// that can outlive a generation (the waiter itself, and the restart timer)
	// re-checks its captured generation against procGen under m.mu before
	// mutating anything, so a stale notification from generation N can never
	// clear or restart generation N+1.
	procSup *helperGeneration
	// procGen counts helper PROCESS generations. Distinct from `generation`,
	// which counts CONFIG snapshots: one config can outlive many helper
	// processes across a crash-restart, and one helper can serve many configs.
	procGen uint64
	// helperCrashEpisodes is the #8397 bounded history of RECOVERED crash
	// episodes, oldest-first, and helperCrashEpisodesTotal the unbounded count
	// of them. Separate from helperCrash because that record is episode-scoped
	// by contract and wiped on every recovery; see helper_crash_history_8397.go
	// for why the wipe is worth preserving rather than extending.
	helperCrashEpisodes      []HelperCrashEpisode
	helperCrashEpisodesTotal int

	// helperCrash records the last UNEXPECTED helper exit for the operator and
	// drives the restart backoff. Zero value means "no crash on record".
	helperCrash HelperCrashRecord
	// restartTimerFn overrides how a crash restart is armed. Production leaves
	// it nil (time.AfterFunc); a test injects a synchronous or recording timer.
	// Per-Manager, not a package var — see scheduleRestartTimer.
	restartTimerFn func(time.Duration, func())
	cfg            config.UserspaceConfig
	clusterHA      bool
	// helperHAStatePublished records whether THIS helper process has been sent a
	// clustered HA inventory at least once (a successful update_ha_state with a
	// non-empty group set). It is NOT derivable from len(m.haGroups): that is the
	// MANAGER's view, which seedHAGroupInventoryLocked populates from config
	// before any publish, so it is non-empty long before the helper knows
	// anything.
	//
	// #7465: arming and inventory publication are independent.
	// desiredForwardingArmedLocked never reads the helper's HA state — on a
	// clustered node it returns true whenever any RG with ID>0 is configured — and
	// the 1 Hz status poll calls syncDesiredForwardingStateLocked
	// UNCONDITIONALLY while the HA publish above it is gated on an active
	// signature, a 2s post-activation hold and a 5s throttle. Arming is cheap and
	// eager; publication is expensive and reluctant. So a helper that holds a
	// snapshot but no inventory gets armed, and the Rust per-packet gate reads an
	// empty ha_state as "this box is not clustered" and delivers LocalDelivery
	// traffic it would otherwise mark HAInactive.
	//
	// Cleared in resetAfterHelperGoneLocked: a new helper starts with an empty
	// inventory, so the fact that the PREVIOUS one was told says nothing.
	helperHAStatePublished bool
	generation             uint64
	// neighborReplaceGen is a dedicated monotonic counter for the #6034
	// manager-neighbor replace-generation envelope. Every authoritative
	// update_neighbors replace (RegenerateNeighborSnapshot, BumpFIBGeneration)
	// allocates the next value and stamps it on the ControlRequest so the
	// helper can fence a stale/reordered replace and ACK the applied
	// generation. Distinct from `generation` (the config-snapshot counter):
	// this only advances on a neighbor push and is never reused, so a retry
	// always carries a strictly higher generation. Guarded by m.mu (both
	// senders hold it across the send).
	neighborReplaceGen uint64
	syncCancel         context.CancelFunc
	lastStatus         ProcessStatus
	// helperStatusObserved records that a helper status has been decoded at
	// least once in this Manager's life — i.e. that lastStatus describes a
	// helper we actually heard from rather than a zero value (#6691 round 10).
	//
	// It exists because a required-protocol gate must arm on an OBSERVED
	// too-old version and never on the ABSENCE of one, and
	// lastStatus.ConfigSnapshotProtocolVersion == 0 cannot tell those apart: it
	// is equally "no helper has ever answered" and "a helper answered without
	// the field". Both are < ProtocolVersion, and only the second is an
	// incompatibility. Guarded by m.mu, like lastStatus itself.
	helperStatusObserved bool
	lastSnapshot         *ConfigSnapshot
	lastApply            *dataplane.ApplyResult
	// lastSnapshotRejectReasons holds the #3261 diagnostic: the reasons the
	// most recently built snapshot carries unrepresentable policy content that
	// the helper integrity preflight rejects (previous-good retained, or
	// fresh-boot default-deny — never fail-open). Set under m.mu at every full
	// snapshot build, surfaced via ProcessStatus.LastSnapshotRejectReasons and
	// the xpf_userspace_policy_content_rejected gauge so the Go/Rust skew
	// (ForwardingSupported=true while the helper rejected the snapshot) is
	// observable. nil/empty means the last build was fully representable.
	lastSnapshotRejectReasons []string
	// lastZoneIDCollisions holds the #3719 diagnostic: the zones the most
	// recent snapshot build QUARANTINED because their StableZoneID collided
	// with an earlier-sorting zone. Set under m.mu at every full snapshot
	// build, surfaced via ProcessStatus.ZoneIDCollisions and the
	// xpf_userspace_zone_id_collision gauge. nil/empty means no active
	// collision.
	lastZoneIDCollisions  []string
	policySchedulerActive map[string]bool
	// routeOverlay is the ip-monitoring effective-route overlay
	// (#1827 PR-1b). Cached so the FULL apply path
	// (buildSnapshotWithSchedulerState in ApplyConfig) preserves the
	// overlay across operator commits while a policy is FAILED.
	// Updated by SetRouteOverlay / PublishRouteOverlaySnapshot.
	routeOverlay []config.RouteOverlayEntry
	// feedOverlay is the dynamic-address feed-prefix overlay (#2049):
	// address-name -> union of live feed-backed CIDR strings. Cached so
	// the FULL apply path (buildSnapshotWithSchedulerState in ApplyConfig)
	// merges the current feed prefixes into the address book the helper
	// enforces. Set by SetFeedSnapshots (daemon, from feeds.Manager) under
	// m.mu, mirroring routeOverlay. A feed onUpdate re-runs applyConfig
	// against the SAME *config.Config; the overlay is what makes the
	// rebuilt snapshot's AddressBooks (and thus the content hash) shift on
	// a feed change so the duplicate-publish gate lets the refresh through.
	feedOverlay map[string][]string
	haGroups    map[int]HAGroupStatus
	// haWatchdogMapWrite writes the kernel-visible watchdog timestamp into the
	// BPF shim's ha_watchdog map. It runs on EVERY heartbeat tick (the BPF ~2s
	// stale window relies on this fast map write, so it is never throttled).
	// Indirected through a field so tests can drive the IPC-throttle path in
	// UpdateHAWatchdog without a loaded BPF map. Defaults to
	// bpfShim.UpdateHAWatchdog (set in New()); nil-safe at the call site.
	haWatchdogMapWrite func(rgID int, timestamp uint64) error
	// haWatchdogIPCSynced tracks, per RG, the watchdog timestamp and Active
	// state last published to the helper via the update_ha_state socket IPC.
	// It throttles that IPC (see UpdateHAWatchdog): the shim map write above
	// happens every tick, but the JSON socket round-trip fires only on an
	// Active-state change (failover/failback — instant) or a periodic backstop
	// comfortably under the helper's ~10s stale-lease window. Guarded by m.mu.
	haWatchdogIPCSynced map[int]haWatchdogIPCSyncState
	// fabricSnapshotBuilder resolves the fabric snapshots (with live peer/local
	// MACs from kernel neighbor + link state) that SyncFabricState pushes to the
	// helper. Indirected through a field so tests can inject a deterministic
	// resolved MAC without real netlink neighbor state, mirroring
	// haWatchdogMapWrite. nil-safe at the call site: it defaults to
	// buildFabricSnapshots when unset (so bare &Manager{} literals still work).
	fabricSnapshotBuilder func(*config.Config) []FabricSnapshot

	// neighborSnapshotBuilder samples the kernel neighbor table for a config.
	// Nil means buildNeighborSnapshots; tests inject a sample (#9684), the same
	// seam fabricSnapshotBuilder gives the fabric rows.
	neighborSnapshotBuilder func(*config.Config) []NeighborSnapshot

	// ingressFoldResolver maps a peer's #7095 cluster-stable ingress fold to
	// this node's own {ifindex, vlan}. Injected by the daemon, which owns both
	// the config (reth -> local member) and the ifindex snapshot. Nil resolves
	// nothing, which is the pre-#7095 import behaviour.
	ingressFoldResolver func(uint32) (uint32, uint16, bool)
	lastIngressIfaces   []uint32
	// ingressInventoryAdopted records whether this Manager has reconciled
	// lastIngressIfaces against the rows actually present in the PINNED
	// userspace_ingress_ifaces map (#6784). It is false on a freshly
	// constructed Manager, which is exactly the daemon-restart case: the map
	// is PinByName-pinned at /sys/fs/bpf/xpf and its rows outlive the process,
	// but lastIngressIfaces does not — so without one adoption pass the reap
	// loop in syncIngressIfaceMapLocked scans an EMPTY inventory and deletes
	// nothing, leaving rows this process never wrote and cannot name. Set once
	// per Manager, after a successful enumeration; within a process the
	// inventory is then maintained exactly as #6537 established.
	ingressInventoryAdopted bool
	lastRSTv4               []netip.Addr
	lastRSTv6               []netip.Addr
	lastRSTAttempt          time.Time
	lastRSTInstallOK        bool
	lastSnapshotHash        [32]byte // content hash of last published snapshot (excludes volatile fields)
	// applySnapshotOutcomeUnknown (#9520) is set while the helper may hold content
	// this Manager never saw it accept, so lastSnapshot and lastSnapshotHash may
	// not describe it. See recordApplySnapshotOutcomeLocked.
	applySnapshotOutcomeUnknown bool
	// partialOutcomeUnknown (#9684) marks the sections the helper may hold from
	// an update_neighbors / update_fabrics round trip whose response was lost, so
	// lastSnapshot's copy may not describe them. See partial_update_outcome_9684.go.
	partialOutcomeUnknown partialSections
	// partialUpdateEpoch (#9684) advances on every update_neighbors /
	// update_fabrics request (requestLocked) and on every re-sample of a section
	// into a publish (resampleSectionsLocked). Compile reads it before building
	// its snapshot outside m.mu and compares it under the lock, so the kernel is
	// sampled under m.mu only when something may have sent the helper newer
	// section content in between.
	partialUpdateEpoch atomic.Uint64
	// #1866 D3: canonical summary of the WG endpoint set in the last
	// successfully published snapshot, for publish-boundary transition
	// logging (logWgEndpointSetTransitionLocked).
	lastPublishedWgEndpoints string
	// #1197: O(1) neighbor lookup index for the listener hot path.
	// Keyed by (ifindex, ip-string). Rebuilt whenever lastSnapshot.Neighbors
	// is replaced. Read under m.mu (existing snapshot lock).
	neighborIndex map[neighborIndexKey]*NeighborSnapshot
	// #1197: ifindex set for listener filter; rebuilt on config commit.
	monitoredIfindexes      map[int]struct{}
	lastBindingIndices      []uint32
	neighborsPrewarmed      bool
	ctrlEnableAt            time.Time
	ctrlWasEnabled          bool
	initialCtrlCleanupDone  bool
	ctrlDisabledAt          uint64    // monotonic ktime_ns when ctrl was last disabled
	lastDemotionTime        time.Time // wall clock when last RG demotion occurred
	xskLivenessFailed       bool
	xskLivenessProven       bool
	xskProbeStart           time.Time
	lastXSKRX               uint64
	lastNAPIBootstrap       time.Time
	lastStandbyNeighResolve time.Time
	bindingsBusySince       time.Time
	lastBindingsAutoRebind  time.Time
	// consecutiveFailedAutoRebinds counts auto-rebind attempts that did not
	// clear the wedge (#7497 blocker 5). Reset to 0 the moment no wedge is
	// detected. Guarded by the same mutex as the two fields above — every
	// reader and writer is on a ...Locked path reached from the status poll.
	consecutiveFailedAutoRebinds int
	publishedSnapshot            uint64
	publishedPlanKey             string
	// appliedSnapshot is the config + generation the helper has
	// ACTUALLY applied via a successful full apply_snapshot — the
	// generation the helper echoes back as
	// status.LastSnapshotGeneration (userspace-dp snapshot.rs sets
	// last_snapshot_generation only on a full apply). It is captured
	// ONLY at the apply_snapshot publish/catch-up sites via
	// markAppliedSnapshotLocked, NOT on FIB-bump / neighbor-regen /
	// content-dedup-skip paths (which advance publishedSnapshot or
	// lastSnapshot.Generation without the helper accepting a new
	// snapshot generation). It is the generation-coherent source for
	// the #2079 NAT pool-utilization-alarm monitor: AppliedNATView
	// pairs this Config with the same-generation pool counters.
	appliedSnapshot     appliedSnapshot
	sessionMirrorFailed bool
	sessionMirrorErr    string

	// syncedImportRefusals counts HA synced-session imports the helper REFUSED
	// on semantic grounds (#6785) — a stale install generation, the aggregate
	// import ceiling, or a translated-tuple reservation refusal. Each one rolls
	// back this node's BPF mirror row, so the counter is the health DEBT the
	// rollback leaves behind: the peer believes it synced a session this node
	// does not hold, and only the peer's next full sync closes that gap.
	//
	// It is deliberately NOT the sticky sessionMirrorFailed flag. That flag
	// gates HA takeover-readiness (#5247) and means the session socket is sick;
	// a refusal comes from a HEALTHY helper answering correctly. Counting it
	// separately keeps the refusal visible without making a standby that a peer
	// oversubscribed look unfit to take over. Atomic because it is read by the
	// status path without m.mu.
	syncedImportRefusals atomic.Uint64
	deferWorkers         bool // skip worker spawn until NotifyLinkCycle
	xskBoundNotified     bool // OnXSKBound fired at most once
	// pendingWorkerArm records "generation debt" from a deferred-MAC
	// re-apply that failed to publish (#5134). After a live RETH
	// virtual-MAC change with no link cycle, the first apply publishes a
	// workerless DeferWorkers=true snapshot and the daemon issues a
	// MANDATORY re-apply to arm the workers with the now-correct MAC. If
	// that re-apply's apply_snapshot fails, the manager keeps the
	// workerless snapshot as lastSnapshot/publishedSnapshot and the commit
	// still reports success — a silent forwarding outage. The daemon records
	// the debt here instead of swallowing the error; the status reconcile
	// loop (retryDeferredWorkerArmLocked) then retries the DeferWorkers=false
	// publish every tick until the workers bind, self-healing a transient
	// helper / control-socket error.
	pendingWorkerArm bool

	// pendingHAStateClear records "clear debt" from a standalone (non-cluster)
	// HA-state clear whose idempotent empty update_ha_state RPC failed (#5487).
	// A cluster->standalone reconfig clears the helper's HA groups; if that RPC
	// hits a transient control-socket error the apply returns an error but the
	// helper keeps the stale groups while the manager is clusterHA=false. The
	// status poll's HA sync is gated behind m.clusterHA, so the clear is never
	// retried and owner_rg_id<=0 forwarding candidates stay HAInactive (transit
	// drop). The poll tick retries clearHelperHAStateLocked while this is set,
	// OUTSIDE the clusterHA guard, until the helper reports no groups.
	pendingHAStateClear bool

	// clearHelperHAStateHook, when non-nil, replaces the update_ha_state RPC in
	// clearHelperHAStateLocked so tests can inject a transient clear failure
	// without a control socket (#5487). Production leaves it nil.
	clearHelperHAStateHook func() error

	lookupUserspaceCtrlForFailClosedHook userspaceCtrlLookupHook

	// disableCtrlMapHook, when non-nil, replaces the bpfShim userspace_ctrl
	// map in disableUserspaceCtrlLocked so tests can inject Lookup/Update/
	// readback faults without a privileged BPF map (#5486). Production leaves
	// it nil.
	disableCtrlMapHook ctrlMapUpdater
	// helperStatusCtrlMapHook / helperStatusBindingsMapHook, when non-nil,
	// replace the two bpfShim maps applyHelperStatusLocked operates on, so its
	// ctrl-gate decision is reachable without a privileged BPF map (#6994).
	// Production leaves both nil. This is the SAME map-free seam
	// disableCtrlMapHook establishes for the disable path (#5486); #6994 exists
	// because applyHelperStatusLocked lacked it, which made its whole body —
	// including the #6871 link-cycle gate — unreachable to every unprivileged
	// test and therefore bound by nothing CI runs.
	helperStatusCtrlMapHook     ctrlMapUpdater
	helperStatusBindingsMapHook ctrlMapUpdater
	// failClosedCtrlMapHook, when non-nil, replaces the bpfShim userspace_ctrl
	// map in failClosedUserspaceCtrlMapLocked (#9337), so "a rejected publish
	// drove ctrl to Enabled=0" — the #4959 security property — is observable
	// without CAP_BPF. Production leaves it nil; unprivileged the shim map is
	// nil and the fail-closed write silently no-ops, which is exactly the state
	// in which a guard cannot tell fail-closed from never-tried.
	failClosedCtrlMapHook ctrlMapUpdater
	// syncClassifierMapsHook, when non-nil, replaces the ingress/local/
	// interface-NAT classifier map writes in unit tests (#7468). Nil in
	// production.
	syncClassifierMapsHook func(*ConfigSnapshot) error

	// controlRequestHook replaces requestLocked in unit tests that exercise
	// manager state transitions without opening a Unix control socket.
	controlRequestHook func(ControlRequest, *ProcessStatus) error

	// addrListForLocalSyncHook, when non-nil, replaces netlink.AddrList in
	// buildDesiredLocalAddressSets so tests can inject a transient
	// enumeration failure (#3924). Production leaves it nil.
	addrListForLocalSyncHook addrListHook
	// localAddressCapacityAlarm latches the #9646 capacity refusal text while it
	// persists, so the 1/s status poll alarms once per transition. Guarded by mu.
	localAddressCapacityAlarm string

	mode               DataplaneMode // current active runtime mode
	configuredMode     DataplaneMode // user-configured desired mode (from config)
	lastHASyncTime     time.Time     // throttle HA watchdog sync to avoid control socket contention
	lastRGActivateTime time.Time     // wall clock of last update_ha_state; statusLoop skips HA sync for 2s

	rgTransitionInFlight atomic.Bool // set before syncHAStateLocked, cleared on completion

	// linkCycleLeaseUntil is the #6871 link-cycle lease: the deadline until
	// which an in-flight RETH MAC link DOWN/UP owns the dataplane, or 0 when no
	// cycle is in flight. The unit is MONOTONIC nanoseconds since
	// linkCycleLeaseEpoch, not UnixNano — a wall-clock deadline would let an NTP
	// step expire a live lease or strand a dead one (#6871 round 6). See the lease
	// block in process_linkcycle.go for what it suppresses, why a deadline
	// rather than a bare flag, and why the daemon renews it per RETH member.
	//
	// atomic, and for exactly the reason rgTransitionInFlight above is: the
	// guard has to survive m.mu being RELEASED. PrepareLinkCycle joins the
	// workers and returns, dropping m.mu while the daemon takes the NIC down —
	// and every other holder of m.mu is free to run in that window, including
	// the 1 Hz status tick, which has four independent ways to undo the join
	// before the link comes back up.
	linkCycleLeaseUntil atomic.Int64

	// linkCycleHB owns the #6871 round-8 lease heartbeat: the goroutine that
	// renews a live lease on a FIXED period, so the interval the TTL has to
	// cover is a constant instead of a function of operator-controlled
	// cardinality. See linkCycleLeaseHeartbeat in process_linkcycle.go.
	//
	// Its own mutex, not m.mu: acquire/release run under m.mu in production but
	// not in tests, and the heartbeat goroutine must never need m.mu (it calls
	// RenewLinkCycle, which is pure atomics) or stopping it from under m.mu
	// would deadlock.
	linkCycleHB linkCycleHeartbeat

	// neighborPrewarmInFlight is the #5104 singleflight guard for the async
	// neighbor-resolve prewarm scan spawned by the status loop. The loop kicks
	// a full scan every 1s for the first 60s (then every 10s on HA standby); a
	// scan does route-indexed NeighList dumps and a bounded probe sweep. Under
	// slow netlink or a large RIB a scan can outlast its tick, so this flag
	// coalesces overlapping ticks onto the running scan: CAS false->true before
	// spawning, cleared (via defer) when the scan goroutine returns. Lock-free
	// (like rgTransitionInFlight) because the clear happens off m.mu in the
	// background scan goroutine.
	neighborPrewarmInFlight atomic.Bool
	// neighborPrewarmScan runs one prewarm scan. Indirected through a field so
	// tests can inject a deterministic/blocking scan to exercise the #5104
	// singleflight coalescing without real netlink. nil-safe at the call site:
	// it defaults to proactiveNeighborResolveAsync when unset, so bare
	// &Manager{} literals still work.
	neighborPrewarmScan func(ctx context.Context, cfg *config.Config)

	// Counter delta tracking: previous binding counter totals for computing
	// deltas to write into BPF counter maps (#332).
	prevBindingCounters userspaceCounterSnapshot

	eventStream       *EventStream
	eventStreamCancel context.CancelFunc

	// OnXSKBound is called once when all XSK bindings are bound.
	// Used by the daemon to defer IPVLAN creation until after XSK
	// binds in zerocopy mode on fabric parents.
	OnXSKBound func()

	// #1620: cold-path latency histogram sample mask. Set by the
	// daemon via SetColdPathSampleMask once at startup. Stamped onto
	// every ConfigSnapshot built by buildSnapshotWithSchedulerState.
	// nil pointer ⇒ omit the field from the wire (userspace-dp
	// defaults to 0xff per #1620 plan §4.3).
	coldPathSampleMask *uint64
}

// #1620: set the cold-path sample mask. Called by the daemon at
// startup with the validated CLI flag value (powers-of-two-minus-one
// or 0 with --enable-cold-path-1-in-1-sampling). nil means "no
// operator setting; let userspace-dp use its default 0xff."
func (m *Manager) SetColdPathSampleMask(mask *uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.coldPathSampleMask = mask
}

const rstSuppressionRetryBackoff = 5 * time.Second

func shouldAttemptRSTSuppression(
	now time.Time,
	desiredV4 []netip.Addr,
	desiredV6 []netip.Addr,
	appliedV4 []netip.Addr,
	appliedV6 []netip.Addr,
	lastAttempt time.Time,
	lastInstallOK bool,
) bool {
	if lastAttempt.IsZero() {
		return true
	}
	if !slices.Equal(desiredV4, appliedV4) || !slices.Equal(desiredV6, appliedV6) {
		return true
	}
	if lastInstallOK {
		return false
	}
	return now.Sub(lastAttempt) >= rstSuppressionRetryBackoff
}

func New() *Manager {
	bpfShim := dataplane.New()
	bpfShim.SelectUserspaceXDPShimEntryProgram()
	return &Manager{
		bpfShim:             bpfShim,
		configuredMode:      ModeUserspaceCompat,
		haGroups:            make(map[int]HAGroupStatus),
		haWatchdogMapWrite:  bpfShim.UpdateHAWatchdog,
		haWatchdogIPCSynced: make(map[int]haWatchdogIPCSyncState),
	}
}

func (m *Manager) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if _, err := m.Compile(cfg); err != nil {
		return nil, err
	}
	return m.LastApplyResult(), nil
}

// ForwardingSupported reports whether a capability gate has disarmed transit
// forwarding, for #8447's xpf_dataplane_forwarding_supported metric.
//
// Reads the SAME field `desiredForwardingArmedLocked` gates on
// (`m.lastStatus.Capabilities.ForwardingSupported`), so the metric and the
// arm/disarm decision cannot disagree about why traffic stopped. A metric
// derived from a second copy of this state would be free to read healthy while
// the bindings were disarmed, which is the failure this exists to end.
//
// Note this is the CAPABILITY gate, not the HA arming decision below it: a
// standby node with capabilities intact reports true here while legitimately
// not forwarding. Distinguishing an intentional standby from a disarmed box is
// what the reasons list is for, and it is on `show chassis forwarding`.
func (m *Manager) ForwardingSupported() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastStatus.Capabilities.ForwardingSupported
}

func (m *Manager) LastApplyResult() *dataplane.ApplyResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastApply.Clone()
}

func (m *Manager) RuntimeSessionDeltaSource() dpruntime.SessionDeltaSource {
	return runtimeSessionDeltaSource{manager: m}
}

func (m *Manager) Start(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	// #7409: arm the kernel-learned route import for every subsequent
	// snapshot build. This is the ONE production bring-up path for the
	// userspace dataplane (LegacyDataPlaneAdapter.Start delegates here), and
	// the import defaults to DISABLED precisely so that reaching this line is
	// the only way it can switch on — see EnableLearnedRouteImport in
	// routes.go for why a build-host-dependent default would be worse than
	// no feature at all.
	EnableLearnedRouteImport()
	return m.Load()
}

func (m *Manager) Link() dataplane.LinkController {
	return userspaceLinkController{manager: m}
}

func (m *Manager) HA() dataplane.HAController {
	return userspaceHAController{manager: managerHAOps{manager: m}}
}

func (m *Manager) Sessions() dataplane.SessionStore {
	return userspaceSessionStore{
		SessionStore: dataplane.NewDataPlaneSessionStore(NewLegacyDataPlaneAdapter(m)),
		source:       m.RuntimeSessionDeltaSource(),
	}
}

func (m *Manager) SessionDeltas() dpruntime.SessionDeltaSource {
	return m.RuntimeSessionDeltaSource()
}

func (m *Manager) Telemetry() dataplane.Telemetry {
	return dataplane.NewDataPlaneTelemetry(NewLegacyDataPlaneAdapter(m))
}

func (m *Manager) recordApplyResultLocked(result *dataplane.ApplyResult, caps UserspaceCapabilities, generation uint64) {
	if result == nil {
		return
	}
	result.Capabilities = dataplane.Capabilities{
		ForwardingSupported: caps.ForwardingSupported,
		UnsupportedReasons:  append([]string(nil), caps.UnsupportedReasons...),
	}
	result.Generation = generation
	m.lastApply = result.Clone()
}

// EventStream returns the event stream instance, or nil if not available.
func (m *Manager) EventStream() *EventStream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventStream
}

// XSKBoundNotified reports whether the OnXSKBound callback has already fired.
// The daemon uses this to distinguish first applyConfig (defer IPVLAN) from
// subsequent calls (reconcile normally).
func (m *Manager) XSKBoundNotified() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.xskBoundNotified
}

func (m *Manager) SetOnXSKBound(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OnXSKBound = fn
}

// Mode returns the current active dataplane runtime mode.
func (m *Manager) Mode() DataplaneMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// SetConfiguredMode sets the user-configured desired dataplane mode.
// The active mode is computed in applyHelperStatusLocked based on runtime
// state and may differ from the configured mode.
func (m *Manager) SetConfiguredMode(mode DataplaneMode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configuredMode = mode
}

func (m *Manager) SessionSyncSweepProfile() (bool, time.Duration, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return false, 0, 0
	}
	if !m.lastStatus.Enabled || !m.lastStatus.ForwardingArmed || !m.lastStatus.Capabilities.ForwardingSupported {
		return false, 0, 0
	}
	// Userspace forwarding already streams authoritative open/close deltas, so
	// the walk is not the primary path; slow it from the 1s cadence that was
	// tuned for the eBPF session tables.
	//
	// #7842: this used to say "keep a periodic refresh for long-lived flows",
	// which the sweep does NOT do and structurally cannot. Its filter is
	// `val.Created >= s.lastSweepTime` (`cluster/sync_conn_sweep.go`), so it
	// only ever queues sessions created SINCE the last sweep; a long-lived flow
	// has `Created < threshold` and is never re-sent. That file says so itself:
	// "every session that existed before the sweep started is permanently
	// invisible to it". The sentence mattered because it was cited as the
	// justification for narrowing the walk to a refresh it was never doing.
	//
	// What the walk IS: the recovery path for a `queueMessage` send-queue
	// overflow. That branch arms `syncBackfillNeeded`, whose only consumers are
	// in the sweep, and an overflowing sweep declines to advance
	// `lastSweepTime` so the next one replays the same window. Both the delta
	// stream and the sweep queue through that one bounded channel, so this is
	// the repair for a DROPPED DELTA, not merely a second copy of one.
	//
	// The `enabled` bool below is NOT an on/off switch for the sweep --
	// `sweepIntervalsForDataPlane` consults it only to decide whether to adopt
	// these intervals, and false falls through to the 1s/10s defaults.
	return true, 15 * time.Second, 60 * time.Second
}

func (m *Manager) Load() error {
	return m.bpfShim.LoadUserspaceShim()
}

func (m *Manager) Close() error {
	// #8526: cut any in-flight control round trip BEFORE taking m.mu. Both
	// stop paths below block on a mutex that another goroutine may be holding
	// across a control round trip whose reachable deadline is 67s — 3.35x the
	// unit's TimeoutStopSec. Cutting first lets this acquisition complete
	// inside the stop budget instead of being resolved by systemd's SIGKILL.
	// Ordering is the whole mechanism: moving either call below the Lock makes
	// it unreachable exactly when it is needed.
	//
	// cutInFlightControlIO, not BeginControlShutdown: neither of these methods
	// is reliably terminal for the Manager (the bootstrap rollback tears down
	// and reuses the object), so they must not latch the shutdown ceiling. See
	// control_shutdown_8526.go.
	m.cutInFlightControlIO()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.bpfShim.Close()
}

func (m *Manager) Teardown() error {
	m.cutInFlightControlIO()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	return m.bpfShim.Teardown()
}

// SetDeferWorkers tells the manager to skip worker startup during the next
// Compile(). Workers will be started on the first NotifyLinkCycle() instead.
// Use this when RETH MAC programming will follow Compile() — avoids the
// double-bind that causes EBUSY on mlx5 zero-copy queues.
func (m *Manager) SetDeferWorkers(v bool) {
	m.mu.Lock()
	m.deferWorkers = v
	m.mu.Unlock()
}

// ArmCoverageSummary forwards the #7191 arm-coverage proof from the bpf shim so
// the daemon can gate on per-interface attach coverage. The userspace manager
// holds no coverage state of its own — one source, per #7191.
func (m *Manager) ArmCoverageSummary() (uncovered, total int, ran, seen bool) {
	if m == nil || m.bpfShim == nil {
		return 0, 0, false, false
	}
	return m.bpfShim.ArmCoverageSummary()
}
