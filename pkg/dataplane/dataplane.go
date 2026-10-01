package dataplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
)

// ErrDPDKBackendRetired is returned from NewDataPlane and
// NewRuntimeDataPlane when caller code still asks for the DPDK
// backend after Phase 2 of the DPDK retirement (#1527, umbrella
// #1525).  Operators must migrate to "set system dataplane-type
// userspace" (or omit the directive entirely for the default).
//
// Chain A (#1526) handles user-facing rejection at commit time;
// this sentinel covers the runtime factory path for callers that
// still pass TypeDPDK through. Defense-in-depth against silent
// registry resurrection lives in
// pkg/dataplane/runtime/import_canary_test.go (forbidden-import
// canary) after #1528 deleted pkg/dataplane/dpdk and its
// package-local test.
// ErrSyncedImportRefused classifies an HA synced-session mirror that REACHED a
// healthy userspace helper and was refused on SEMANTIC grounds (#6785): a stale
// install generation (#2170), the aggregate synced-import ceiling (#5674), or a
// translated-tuple reservation refusal (#6600).
//
// It lives here, not in pkg/dataplane/userspace, so the cluster session-sync
// layer can classify the error it already receives without importing the
// userspace manager (which would be an import cycle). The wire token that
// produces it stays with the transport that parses it
// (syncedImportRefusedPrefix, pkg/dataplane/userspace/process_control.go).
//
// The distinction it carries is load-bearing. A transport failure means the
// helper session socket is sick and must gate HA takeover-readiness (#5247); a
// refusal is the CORRECT answer from a healthy helper — the peer sent something
// stale, or this node is at its own import ceiling. Marking the mirror unhealthy
// for a refusal would latch a working standby "not takeover-ready" the first
// time a peer oversubscribed it, which is a worse failure than the split truth
// the refusal reporting exists to fix. What a refusal DOES owe is compensation
// (the helper did not take the session, so the local BPF row is split truth) and
// visibility, because the peer believes it synced a session this node does not
// hold and only its next full sync closes that gap.
var ErrSyncedImportRefused = errors.New("synced session import refused by helper")

// ErrSyncedImportRepairPending means the helper committed shared import
// authority but latched worker-local convergence after a bounded queue refused
// an upsert. Callers must not classify this as an Applied import or roll the
// committed helper row back; the helper repairs from its latest shared row.
var ErrSyncedImportRepairPending = errors.New("synced session worker repair pending")

// ErrSyncedImportRepairOverflow means the helper committed shared import
// authority but its bounded per-worker repair latch was full. It is distinct
// from a terminal import refusal: callers must surface it and must not claim
// that worker-local state converged.
var ErrSyncedImportRepairOverflow = errors.New("synced session worker repair latch overflow")

var ErrDPDKBackendRetired = errors.New(
	"the DPDK dataplane backend has been retired; use " +
		"'set system dataplane-type userspace' (see #1525)",
)

// ErrEBPFBackendRetired is returned from NewDataPlane,
// NewRuntimeDataPlane, and Manager.Load() when caller code still asks
// for the legacy eBPF backend after the #1476 source-removal phase of
// the #1373 eBPF retirement umbrella.  Operators must migrate to
// "set system dataplane-type userspace" (or omit the directive
// entirely for the default).
//
// Chain A (commit-time validator validateDataplaneTypeStrictEBPF in
// pkg/config) handles user-facing rejection at commit time; this
// sentinel covers the runtime factory path for callers that still
// pass TypeEBPF through, the Manager.Load() interface contract method
// that remains in tree for DataPlane assertion compatibility, and
// stored-config rolling-upgrade paths surfaced by AGY r4.
var ErrEBPFBackendRetired = errors.New(
	"the legacy eBPF dataplane backend has been retired; use " +
		"'set system dataplane-type userspace' (see #1373)",
)

// Compile-time assertion that Manager implements DataPlane.
var _ DataPlane = (*Manager)(nil)
var _ ConfigSink = (*Manager)(nil)
var _ RuntimeDataPlane = (*Manager)(nil)

// Dataplane type constants used in system { dataplane-type <type>; }.
//
// TypeDPDK is preserved as a typed token for the retirement-error
// code path in NewDataPlane / NewRuntimeDataPlane after Phase 2 of
// #1525.  No production code path may construct a DPDK backend
// through the registry — see ErrDPDKBackendRetired and the
// retirement-boundary canary in retirement_boundary_canary_test.go.
const (
	TypeEBPF      = "ebpf"
	TypeDPDK      = "dpdk"
	TypeUserspace = "userspace"
)

// EffectiveType resolves the operator-facing dataplane type. The empty config
// value means the userspace runtime path.
func EffectiveType(dpType string) string {
	if dpType == "" {
		return TypeUserspace
	}
	return dpType
}

func UserspaceCtrlPinPath() string {
	return filepath.Join(bpfPinPath, "userspace_ctrl")
}

func UserspaceBindingsPinPath() string {
	return filepath.Join(bpfPinPath, "userspace_bindings")
}

func UserspaceIngressIfacesPinPath() string {
	return filepath.Join(bpfPinPath, "userspace_ingress_ifaces")
}

func UserspaceHeartbeatPinPath() string {
	return filepath.Join(bpfPinPath, "userspace_heartbeat")
}

func UserspaceXSKMapPinPath() string {
	return filepath.Join(bpfPinPath, "userspace_xsk_map")
}

func UserspaceLocalV4PinPath() string {
	return filepath.Join(bpfPinPath, "userspace_local_v4")
}

func UserspaceLocalV6PinPath() string {
	return filepath.Join(bpfPinPath, "userspace_local_v6")
}

func UserspaceCPUMapPinPath() string {
	return filepath.Join(bpfPinPath, "userspace_cpumap")
}

func UserspaceSessionsPinPath() string {
	return filepath.Join(bpfPinPath, "userspace_sessions")
}

func ConntrackV4PinPath() string {
	return filepath.Join(bpfPinPath, "sessions")
}

func ConntrackV6PinPath() string {
	return filepath.Join(bpfPinPath, "sessions_v6")
}

func UserspaceDnatTablePinPath() string {
	return filepath.Join(bpfPinPath, "dnat_table")
}

func UserspaceDnatTableV6PinPath() string {
	return filepath.Join(bpfPinPath, "dnat_table_v6")
}

func UserspaceTracePinPath() string {
	return filepath.Join(bpfPinPath, "userspace_trace")
}

// backendRegistry holds constructors for non-eBPF, non-DPDK dataplane
// backends.  After the Phase 2 DPDK retirement (#1527, umbrella #1525)
// userspace is the sole remaining registrant and it uses
// RegisterRuntimeBackend, not RegisterBackend.  RegisterBackend remains
// for forward-compatibility with hypothetical future backends.
var backendRegistry = map[string]func() DataPlane{}
var runtimeBackendRegistry = map[string]func() RuntimeDataPlane{}

// RegisterBackend registers a dataplane constructor for the given type.
// Panics if dpType is TypeDPDK: the DPDK backend was retired in Phase 2
// of #1525 (#1527).  NewDataPlane intercepts TypeDPDK before consulting
// the registry, so any registered DPDK constructor would be silently
// unreachable; the panic makes the programming error immediately visible.
func RegisterBackend(dpType string, ctor func() DataPlane) {
	if dpType == TypeDPDK {
		panic("TypeDPDK backend registration rejected: DPDK retired in #1527 (umbrella #1525)")
	}
	backendRegistry[dpType] = ctor
}

// RegisterRuntimeBackend registers a runtime-domain dataplane constructor.
// Panics if dpType is TypeDPDK for the same reason as RegisterBackend.
func RegisterRuntimeBackend(dpType string, ctor func() RuntimeDataPlane) {
	if dpType == TypeDPDK {
		panic("TypeDPDK runtime backend registration rejected: DPDK retired in #1527 (umbrella #1525)")
	}
	runtimeBackendRegistry[dpType] = ctor
}

// NewDataPlane creates a legacy DataPlane backend based on the given type
// string.  It intentionally does not accept the empty default: daemon startup
// must use NewRuntimeDataPlane so omitted config resolves to userspace instead
// of silently falling back to legacy eBPF.
func NewDataPlane(dpType string) (DataPlane, error) {
	switch dpType {
	case "":
		return nil, fmt.Errorf(
			"empty dataplane type defaults to %q; use NewRuntimeDataPlane for default selection",
			TypeUserspace,
		)
	case TypeEBPF:
		// Phase 1 reject preservation (#1476): TypeEBPF is kept as a
		// typed token so old configs still parse, but no production
		// constructor for the legacy backend exists after source
		// removal. Mirrors the DPDK retirement pattern.
		return nil, ErrEBPFBackendRetired
	case TypeDPDK:
		return nil, ErrDPDKBackendRetired
	default:
		if ctor, ok := backendRegistry[dpType]; ok {
			return ctor(), nil
		}
		// Legacy NewDataPlane retains TypeEBPF and TypeDPDK only as
		// retirement-error tokens. TypeUserspace has no legacy
		// DataPlane shape and must go through NewRuntimeDataPlane.
		// Operators selecting userspace at the config layer never
		// reach this branch because daemon startup uses
		// NewRuntimeDataPlane.
		return nil, fmt.Errorf("unknown dataplane type %q (use NewRuntimeDataPlane for userspace; ebpf and dpdk are retired)", dpType)
	}
}

// NewRuntimeDataPlane creates a daemon-facing runtime dataplane backend.
// Userspace registers here directly so daemon startup does not require a
// legacy BPF-shaped DataPlane compatibility adapter.
func NewRuntimeDataPlane(dpType string) (RuntimeDataPlane, error) {
	dpType = EffectiveType(dpType)
	switch dpType {
	case TypeEBPF:
		// Phase 1 reject preservation (#1476): the legacy eBPF
		// backend is retired. The daemon_run.go soft-fallback
		// catches ErrEBPFBackendRetired (alongside the existing
		// ErrDPDKBackendRetired branch) and runs in config-only
		// mode while the operator updates the persisted config.
		return nil, ErrEBPFBackendRetired
	case TypeDPDK:
		// EffectiveType only rewrites empty -> userspace, never
		// -> dpdk, so this branch cannot intercept legitimate
		// empty-default callers.  Any TypeDPDK that reaches here
		// is an explicit "set system dataplane-type dpdk" that
		// must be rejected after Phase 2 of #1525.
		return nil, ErrDPDKBackendRetired
	default:
		if ctor, ok := runtimeBackendRegistry[dpType]; ok {
			return ctor(), nil
		}
		if dpType == TypeUserspace {
			return nil, fmt.Errorf("dataplane type %q runtime backend is not registered", dpType)
		}
		dp, err := NewDataPlane(dpType)
		if err != nil {
			return nil, err
		}
		runtimeDP, ok := dp.(RuntimeDataPlane)
		if !ok {
			return nil, fmt.Errorf("dataplane type %q does not implement RuntimeDataPlane", dpType)
		}
		return runtimeDP, nil
	}
}

// DataPlane defines the abstract interface for a packet-processing dataplane.
// The eBPF Manager is the legacy implementation; the userspace AF_XDP
// backend is the primary/default target after Phase 2 of the DPDK retirement.
type DataPlane interface {
	// Lifecycle
	Load() error
	IsLoaded() bool
	Close() error
	Teardown() error // full teardown: detach programs, unpin maps, remove all BPF state

	// Program attachment
	AttachXDP(ifindex int, forceGeneric bool) error
	DetachXDP(ifindex int) error
	AttachTC(ifindex int) error
	DetachTC(ifindex int) error
	AddTxPort(ifindex int) error

	// Compilation
	Compile(cfg *config.Config) (*CompileResult, error)
	LastCompileResult() *CompileResult

	// Zone / interface mapping
	SetZone(ifindex int, vlanID uint16, zoneID uint16, routingTable uint32, flags uint8, rgID uint8, screenFlags uint32) error
	SetVlanIfaceInfo(subIfindex int, parentIfindex int, vlanID uint16) error
	ClearIfaceZoneMap() error
	ClearVlanIfaceMap() error
	SetZoneConfig(zoneID uint16, cfg ZoneConfig) error

	// Policy
	SetZonePairPolicy(fromZone, toZone uint16, ps PolicySet) error
	SetPolicyRule(policySetID uint32, ruleIndex uint32, rule PolicyRule) error
	ClearZonePairPolicies() error
	SetDefaultPolicy(action uint8) error
	// UpdatePolicyScheduleState republishes enforcement for a scheduler
	// window transition. It returns a non-nil error when the transition
	// did NOT converge (the new inactive-bit view was not applied) so the
	// caller can retry and surface the failure — a swallowed failure
	// leaves stale enforcement live past the window (#3780).
	UpdatePolicyScheduleState(cfg *config.Config, activeState map[string]bool) error

	// Address book
	SetAddressBookEntry(cidr string, addressID uint32) error
	SetAddressMembership(resolvedID, setID uint32) error
	ClearAddressBookV4() error
	ClearAddressBookV6() error
	ClearAddressMembership() error

	// Application
	SetApplication(protocol uint8, dstPort uint16, appID uint32, timeout uint32, algType uint8, srcPortLow, srcPortHigh uint16) error
	SetAppRange(index uint32, entry AppRangeEntry) error
	ClearAppRanges() error
	ClearApplications() error

	// Sessions
	IterateSessions(fn func(SessionKey, SessionValue) bool) error
	BatchIterateSessions(fn func(SessionKey, SessionValue) bool) error
	DeleteSession(key SessionKey) error
	BatchDeleteSessions(keys []SessionKey) (int, error)
	SetSessionV4(key SessionKey, val SessionValue) error
	IterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error
	BatchIterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error
	DeleteSessionV6(key SessionKeyV6) error
	BatchDeleteSessionsV6(keys []SessionKeyV6) (int, error)
	SetSessionV6(key SessionKeyV6, val SessionValueV6) error
	GetSessionV4(key SessionKey) (SessionValue, error)
	GetSessionV6(key SessionKeyV6) (SessionValueV6, error)
	SessionCount() (v4, v6 int)
	ClearAllSessions() (int, int, error)

	// DNAT
	SetDNATEntry(key DNATKey, val DNATValue) error
	DeleteDNATEntry(key DNATKey) error
	SetDNATEntryV6(key DNATKeyV6, val DNATValueV6) error
	DeleteDNATEntryV6(key DNATKeyV6) error

	// SNAT

	// NAT pools

	// SNAT egress IPs (interface-mode SNAT)

	// Static NAT

	// NPTv6 (RFC 6296)

	// NAT64

	// Screen
	SetScreenConfig(profileID uint32, cfg ScreenConfig) error
	ClearScreenConfigs() error

	// Session count maps (populated by GC for session limiting)
	UpdateSessionCountSrc(key SessionCountKey, count uint32) error
	UpdateSessionCountDst(key SessionCountKey, count uint32) error
	ClearSessionCounts() error

	// Port mirroring
	SetMirrorConfig(ifindex int, mirrorIfindex int, rate uint32) error
	ClearMirrorConfigs() error

	// Flow
	SetFlowTimeout(idx, seconds uint32) error
	SetFlowConfig(cfg FlowConfigValue) error

	// Firewall filters
	SetIfaceFilter(key IfaceFilterKey, filterID uint32) error
	ClearIfaceFilterMap() error
	SetFilterConfig(filterID uint32, cfg FilterConfig) error
	ReadFilterConfig(filterID uint32) (FilterConfig, error)
	SetFilterRule(index uint32, rule FilterRule) error
	ClearFilterConfigs() error

	// Policers
	SetPolicerConfig(id uint32, cfg PolicerConfig) error
	ClearPolicerConfigs() error

	// Counters
	ReadGlobalCounter(index uint32) (uint64, error)
	IncrementGlobalCounter(index uint32, delta uint64) error
	ReadFloodCounters(zoneID uint16) (FloodState, error)
	ReadInterfaceCounters(ifindex int) (InterfaceCounterValue, error)
	ReadZoneCounters(zoneID uint16, direction int) (CounterValue, error)
	ReadPolicyCounters(policyID uint32) (CounterValue, error)
	ReadFilterCounters(ruleIdx uint32) (CounterValue, error)
	ReadNATRuleCounter(counterID uint32) (CounterValue, error)
	ReadNATPortCounter(poolID uint32) (uint64, error)
	SeedNATPortCounters()
	SeedSessionIDCounter(nodeID int)
	ClearGlobalCounters() error
	ClearInterfaceCounters() error
	ClearZoneCounters() error
	ClearPolicyCounters() error
	ClearFilterCounters() error
	ClearAllCounters() error
	ClearNATRuleCounters() error

	// FIB
	// BumpFIBGeneration invalidates cached per-session FIB entries.
	// #1844: returns the bump error so callers with retry semantics
	// (the ip-monitoring routes-only actuator's pendingFIBBump) can
	// see a failed bump.
	//
	// #7149: no production caller ignores it any more, and the phrase
	// that used to sit here -- "fire-and-forget callers may ignore it"
	// -- named exactly one caller, CompileConfig, which is the one it
	// was wrong for. Each of the three picks the treatment its own path
	// supports: the ip-monitoring actuator retries (pendingFIBBump), the
	// route-leak commit tail fails the commit closed for want of a retry
	// owner (#5696 M19), and the compiler REPORTS -- it runs after
	// compileZones has mutated the host, so returning the error there
	// would manufacture the half-applied apply #4960 exists to prevent.
	// A new caller must choose one of the three; silently dropping it
	// publishes a snapshot carrying the previous generation.
	BumpFIBGeneration() (uint32, error)
	// StartFIBSync is a no-op on every in-tree backend: eBPF resolves
	// FIB queries via bpf_fib_lookup in-kernel and the userspace
	// AF_XDP runtime wraps the eBPF no-op through the legacy
	// adapter.  The hook is retained on the interface for backends
	// that need a userspace route populator (DPDK had one; retired
	// in #1527 / #1525).
	StartFIBSync(ctx context.Context)

	// NotifyLinkCycle signals that data-plane interfaces were taken DOWN/UP
	// (e.g. during RETH MAC programming).  The userspace dataplane uses this
	// to rebind AF_XDP sockets whose kernel-side RQ was destroyed by the
	// link cycle.  No-op for the eBPF-only dataplane.
	NotifyLinkCycle()

	// SyncFabricState pushes updated fabric MACs to the userspace helper.
	// No-op for the eBPF-only dataplane.
	SyncFabricState()

	// Map statistics
	GetMapStats() []MapStats

	// Hitless restart: delete stale entries
	DeleteStaleIfaceZone(written map[IfaceZoneKey]bool)
	DeleteStaleVlanIface(written map[uint32]bool)
	DeleteStaleZonePairPolicies(written map[ZonePairKey]bool)
	DeleteStaleApplications(written map[AppKey]bool)
	DeleteStaleDNATStatic(written map[DNATKey]bool)
	DeleteStaleDNATStaticV6(written map[DNATKeyV6]bool)
	DeleteStaleStaticNAT(writtenV4 map[StaticNATKeyV4]bool, writtenV6 map[StaticNATKeyV6]bool)
	ZeroStaleScreenConfigs(maxID uint32)
	DeleteStaleIfaceFilter(written map[IfaceFilterKey]bool)
	ZeroStaleFilterConfigs(startID uint32)

	// Fabric cross-chassis forwarding
	UpdateFabricFwd(info FabricFwdInfo) error
	UpdateFabricFwd1(info FabricFwdInfo) error
	UpdateRGActive(rgID int, active bool) error
	UpdateHAWatchdog(rgID int, timestamp uint64) error

	// Persistent NAT table
	GetPersistentNAT() *PersistentNATTable

	// Event source for reading pipeline events (session open/close, deny, etc.)
	NewEventSource() (EventSource, error)

	// Raw map access (eBPF-specific; non-eBPF implementations return nil)
	Map(name string) *ebpf.Map
}

// EventSource reads raw event records from the dataplane.
// The eBPF implementation wraps a ring buffer reader; the userspace
// AF_XDP implementation uses the control-socket event stream.
type EventSource interface {
	// ReadEvent blocks until an event is available and returns raw bytes.
	// Returns an error on close or failure.
	ReadEvent() ([]byte, error)

	// Close shuts down the event source, unblocking any pending ReadEvent.
	Close() error
}
