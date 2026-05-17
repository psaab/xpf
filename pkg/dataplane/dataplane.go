package dataplane

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/config"
)

// Compile-time assertion that Manager implements DataPlane.
var _ DataPlane = (*Manager)(nil)
var _ ConfigSink = (*Manager)(nil)

// Dataplane type constants used in system { dataplane-type <type>; }.
const (
	TypeEBPF      = "ebpf" // default
	TypeDPDK      = "dpdk"
	TypeUserspace = "userspace"
)

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

// backendRegistry holds constructors for non-eBPF dataplane backends.
// Sub-packages register themselves via RegisterBackend in their init().
var backendRegistry = map[string]func() DataPlane{}

// RegisterBackend registers a dataplane constructor for the given type.
func RegisterBackend(dpType string, ctor func() DataPlane) {
	backendRegistry[dpType] = ctor
}

// NewDataPlane creates a DataPlane backend based on the given type string.
// An empty string defaults to eBPF.
func NewDataPlane(dpType string) (DataPlane, error) {
	switch dpType {
	case "", TypeEBPF:
		return New(), nil
	default:
		if ctor, ok := backendRegistry[dpType]; ok {
			return ctor(), nil
		}
		return nil, fmt.Errorf("unknown dataplane type %q (valid: ebpf, dpdk, userspace)", dpType)
	}
}

// DataPlane defines the abstract interface for a packet-processing dataplane.
// The eBPF Manager is the primary implementation; a DPDK implementation can
// be added as an alternative backend.
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
	UpdatePolicyScheduleState(cfg *config.Config, activeState map[string]bool)

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
	ClearDNATStatic() error
	SetDNATEntryV6(key DNATKeyV6, val DNATValueV6) error
	DeleteDNATEntryV6(key DNATKeyV6) error
	ClearDNATStaticV6() error

	// SNAT
	SetSNATRule(fromZone, toZone, ruleIdx uint16, val SNATValue) error
	ClearSNATRules() error
	SetSNATRuleV6(fromZone, toZone, ruleIdx uint16, val SNATValueV6) error
	ClearSNATRulesV6() error

	// NAT pools
	SetNATPoolConfig(poolID uint32, cfg NATPoolConfig) error
	SetNATPoolIPV4(poolID, index uint32, ip uint32) error
	SetNATPoolIPV6(poolID, index uint32, ip [16]byte) error
	ClearNATPoolConfigs() error
	ClearNATPoolIPs() error

	// SNAT egress IPs (interface-mode SNAT)
	SetSNATEgressIP(key SNATEgressKey, val SNATEgressValue) error
	ClearSNATEgressIPs() error

	// Static NAT
	SetStaticNATEntryV4(ip uint32, direction uint8, translated uint32) error
	SetStaticNATEntryV6(ip [16]byte, direction uint8, translated [16]byte) error
	ClearStaticNATEntries() error

	// NPTv6 (RFC 6296)
	SetNPTv6Rule(key NPTv6Key, val NPTv6Value) error
	DeleteStaleNPTv6(written map[NPTv6Key]bool)

	// NAT64
	SetNAT64Config(index uint32, cfg NAT64Config) error
	SetNAT64Count(count uint32) error
	ClearNAT64Configs() error

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
	BumpFIBGeneration() uint32
	StartFIBSync(ctx context.Context) // DPDK: background route sync; eBPF: no-op

	// NotifyLinkCycle signals that data-plane interfaces were taken DOWN/UP
	// (e.g. during RETH MAC programming).  The userspace dataplane uses this
	// to rebind AF_XDP sockets whose kernel-side RQ was destroyed by the
	// link cycle.  No-op for the eBPF-only and DPDK dataplanes.
	NotifyLinkCycle()

	// SyncFabricState pushes updated fabric MACs to the userspace helper.
	// No-op for eBPF-only and DPDK dataplanes.
	SyncFabricState()

	// Map statistics
	GetMapStats() []MapStats

	// Hitless restart: delete stale entries
	DeleteStaleIfaceZone(written map[IfaceZoneKey]bool)
	DeleteStaleVlanIface(written map[uint32]bool)
	DeleteStaleZonePairPolicies(written map[ZonePairKey]bool)
	DeleteStaleApplications(written map[AppKey]bool)
	DeleteStaleSNATRules(written map[SNATKey]bool)
	DeleteStaleSNATRulesV6(written map[SNATKey]bool)
	DeleteStaleDNATStatic(written map[DNATKey]bool)
	DeleteStaleDNATStaticV6(written map[DNATKeyV6]bool)
	DeleteStaleStaticNAT(writtenV4 map[StaticNATKeyV4]bool, writtenV6 map[StaticNATKeyV6]bool)
	DeleteStaleNAT64(count uint32, writtenPrefixes map[NAT64PrefixKey]bool)
	ZeroStaleScreenConfigs(maxID uint32)
	ZeroStaleNATPoolConfigs(startID uint32)
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

	// Raw map access (eBPF-specific; DPDK implementations may return nil)
	Map(name string) *ebpf.Map
}

// EventSource reads raw event records from the dataplane.
// The eBPF implementation wraps a ring buffer reader; DPDK uses rte_ring.
type EventSource interface {
	// ReadEvent blocks until an event is available and returns raw bytes.
	// Returns an error on close or failure.
	ReadEvent() ([]byte, error)

	// Close shuts down the event source, unblocking any pending ReadEvent.
	Close() error
}
