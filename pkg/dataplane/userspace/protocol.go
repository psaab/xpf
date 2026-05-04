package userspace

import (
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const (
	ProtocolVersion = 1
	TypeUserspace   = "userspace"
)

type ControlRequest struct {
	Type               string                    `json:"type"`
	SuppressStatus     bool                      `json:"suppress_status,omitempty"`
	Snapshot           *ConfigSnapshot           `json:"snapshot,omitempty"`
	Forwarding         *ForwardingControlRequest `json:"forwarding,omitempty"`
	HAState            *HAStateUpdateRequest     `json:"ha_state,omitempty"`
	Queue              *QueueControlRequest      `json:"queue,omitempty"`
	Binding            *BindingControlRequest    `json:"binding,omitempty"`
	Packet             *InjectPacketRequest      `json:"packet,omitempty"`
	SessionSync        *SessionSyncRequest       `json:"session_sync,omitempty"`
	SessionDeltas      *SessionDeltaDrainRequest `json:"session_deltas,omitempty"`
	SessionExport      *SessionExportRequest     `json:"session_export,omitempty"`
	Neighbors          []NeighborSnapshot        `json:"neighbors,omitempty"`
	NeighborGeneration uint64                    `json:"neighbor_generation,omitempty"`
	NeighborReplace    bool                      `json:"neighbor_replace,omitempty"`
	Fabrics            []FabricSnapshot          `json:"fabrics,omitempty"`
}

type ControlResponse struct {
	OK            bool               `json:"ok"`
	Error         string             `json:"error,omitempty"`
	Status        *ProcessStatus     `json:"status,omitempty"`
	SessionDeltas []SessionDeltaInfo `json:"session_deltas,omitempty"`
}

type ConfigSnapshot struct {
	Version         int                          `json:"version"`
	Generation      uint64                       `json:"generation"`
	FIBGeneration   uint32                       `json:"fib_generation,omitempty"`
	GeneratedAt     time.Time                    `json:"generated_at"`
	Summary         SnapshotSummary              `json:"summary"`
	Capabilities    UserspaceCapabilities        `json:"capabilities"`
	MapPins         UserspaceMapPins             `json:"map_pins"`
	Zones           []ZoneSnapshot               `json:"zones,omitempty"`
	Interfaces      []InterfaceSnapshot          `json:"interfaces,omitempty"`
	Fabrics         []FabricSnapshot             `json:"fabrics,omitempty"`
	TunnelEndpoints []TunnelEndpointSnapshot     `json:"tunnel_endpoints,omitempty"`
	Neighbors       []NeighborSnapshot           `json:"neighbors,omitempty"`
	Routes          []RouteSnapshot              `json:"routes,omitempty"`
	Flow            FlowSnapshot                 `json:"flow,omitempty"`
	DefaultPolicy   string                       `json:"default_policy,omitempty"`
	Policies        []PolicyRuleSnapshot         `json:"policies,omitempty"`
	SourceNAT       []SourceNATRuleSnapshot      `json:"source_nat_rules,omitempty"`
	StaticNAT       []StaticNATRuleSnapshot      `json:"static_nat_rules,omitempty"`
	DestinationNAT  []DestinationNATRuleSnapshot `json:"destination_nat_rules,omitempty"`
	NAT64           []NAT64RuleSnapshot          `json:"nat64_rules,omitempty"`
	Nptv6           []Nptv6RuleSnapshot          `json:"nptv6_rules,omitempty"`
	Screens         []ScreenProfileSnapshot      `json:"screens,omitempty"`
	Filters         []FirewallFilterSnapshot     `json:"filters,omitempty"`
	Policers        []PolicerSnapshot            `json:"policers,omitempty"`
	ClassOfService  *ClassOfServiceSnapshot      `json:"class_of_service,omitempty"`
	FlowExport      *FlowExportSnapshot          `json:"flow_export,omitempty"`
	Config          *config.Config               `json:"config,omitempty"`
	Userspace       config.UserspaceConfig       `json:"userspace"`
	DeferWorkers    bool                         `json:"defer_workers,omitempty"`
}

type FlowSnapshot struct {
	AllowDNSReply      bool   `json:"allow_dns_reply,omitempty"`
	AllowEmbeddedICMP  bool   `json:"allow_embedded_icmp,omitempty"`
	TCPMSSAllTCP       int    `json:"tcp_mss_all_tcp,omitempty"`
	TCPMSSIPsecVPN     int    `json:"tcp_mss_ipsec_vpn,omitempty"`
	TCPMSSGreIn        int    `json:"tcp_mss_gre_in,omitempty"`
	TCPMSSGreOut       int    `json:"tcp_mss_gre_out,omitempty"`
	TCPSessionTimeout  int    `json:"tcp_session_timeout,omitempty"`  // seconds, 0=default
	UDPSessionTimeout  int    `json:"udp_session_timeout,omitempty"`  // seconds, 0=default
	ICMPSessionTimeout int    `json:"icmp_session_timeout,omitempty"` // seconds, 0=default
	GREAcceleration    bool   `json:"gre_acceleration,omitempty"`     // extract GRE key into session ports
	Lo0FilterInputV4   string `json:"lo0_filter_input_v4,omitempty"`  // lo0 inet input filter name
	Lo0FilterInputV6   string `json:"lo0_filter_input_v6,omitempty"`  // lo0 inet6 input filter name
}

type SnapshotSummary struct {
	HostName       string `json:"host_name"`
	DataplaneType  string `json:"dataplane_type"`
	InterfaceCount int    `json:"interface_count"`
	ZoneCount      int    `json:"zone_count"`
	PolicyCount    int    `json:"policy_count"`
	SchedulerCount int    `json:"scheduler_count"`
	HAEnabled      bool   `json:"ha_enabled"`
}

type ZoneSnapshot struct {
	Name string `json:"name"`
	ID   uint16 `json:"id"`
}

type InterfaceSnapshot struct {
	Name                      string                     `json:"name"`
	Zone                      string                     `json:"zone,omitempty"`
	LinuxName                 string                     `json:"linux_name,omitempty"`
	ParentLinuxName           string                     `json:"parent_linux_name,omitempty"`
	Ifindex                   int                        `json:"ifindex,omitempty"`
	ParentIfindex             int                        `json:"parent_ifindex,omitempty"`
	RXQueues                  int                        `json:"rx_queues,omitempty"`
	VLANID                    int                        `json:"vlan_id,omitempty"`
	LocalFabric               string                     `json:"local_fabric_member,omitempty"`
	RedundancyGroup           int                        `json:"redundancy_group,omitempty"`
	UnitCount                 int                        `json:"unit_count"`
	Tunnel                    bool                       `json:"tunnel"`
	MTU                       int                        `json:"mtu,omitempty"`
	HardwareAddr              string                     `json:"hardware_addr,omitempty"`
	Addresses                 []InterfaceAddressSnapshot `json:"addresses,omitempty"`
	FilterInputV4             string                     `json:"filter_input_v4,omitempty"`
	FilterOutputV4            string                     `json:"filter_output_v4,omitempty"`
	FilterInputV6             string                     `json:"filter_input_v6,omitempty"`
	FilterOutputV6            string                     `json:"filter_output_v6,omitempty"`
	CoSShapingRateBytesPerSec uint64                     `json:"cos_shaping_rate_bytes_per_sec,omitempty"`
	CoSBurstSize              uint64                     `json:"cos_shaping_burst_bytes,omitempty"`
	CoSSchedulerMap           string                     `json:"cos_scheduler_map,omitempty"`
	CoSDSCPClassifier         string                     `json:"cos_dscp_classifier,omitempty"`
	CoSIEEE8021Classifier     string                     `json:"cos_ieee8021_classifier,omitempty"`
	CoSDSCPRewriteRule        string                     `json:"cos_dscp_rewrite_rule,omitempty"`
}

type ClassOfServiceSnapshot struct {
	ForwardingClasses   []CoSForwardingClassSnapshot    `json:"forwarding_classes,omitempty"`
	DSCPClassifiers     []CoSDSCPClassifierSnapshot     `json:"dscp_classifiers,omitempty"`
	IEEE8021Classifiers []CoSIEEE8021ClassifierSnapshot `json:"ieee8021_classifiers,omitempty"`
	DSCPRewriteRules    []CoSDSCPRewriteRuleSnapshot    `json:"dscp_rewrite_rules,omitempty"`
	Schedulers          []CoSSchedulerSnapshot          `json:"schedulers,omitempty"`
	SchedulerMaps       []CoSSchedulerMapSnapshot       `json:"scheduler_maps,omitempty"`
}

type CoSForwardingClassSnapshot struct {
	Name  string `json:"name"`
	Queue int    `json:"queue"`
}

type CoSDSCPClassifierSnapshot struct {
	Name    string                           `json:"name"`
	Entries []CoSDSCPClassifierEntrySnapshot `json:"entries,omitempty"`
}

type CoSDSCPClassifierEntrySnapshot struct {
	ForwardingClass string  `json:"forwarding_class,omitempty"`
	LossPriority    string  `json:"loss_priority,omitempty"`
	DSCPValues      []uint8 `json:"dscp_values,omitempty"`
}

type CoSIEEE8021ClassifierSnapshot struct {
	Name    string                               `json:"name"`
	Entries []CoSIEEE8021ClassifierEntrySnapshot `json:"entries,omitempty"`
}

type CoSIEEE8021ClassifierEntrySnapshot struct {
	ForwardingClass string  `json:"forwarding_class,omitempty"`
	LossPriority    string  `json:"loss_priority,omitempty"`
	CodePoints      []uint8 `json:"code_points,omitempty"`
}

type CoSDSCPRewriteRuleSnapshot struct {
	Name    string                            `json:"name"`
	Entries []CoSDSCPRewriteRuleEntrySnapshot `json:"entries,omitempty"`
}

type CoSDSCPRewriteRuleEntrySnapshot struct {
	ForwardingClass string `json:"forwarding_class,omitempty"`
	LossPriority    string `json:"loss_priority,omitempty"`
	DSCPValue       uint8  `json:"dscp_value,omitempty"`
}

type CoSSchedulerSnapshot struct {
	Name              string `json:"name"`
	TransmitRateBytes uint64 `json:"transmit_rate_bytes,omitempty"`
	TransmitRateExact bool   `json:"transmit_rate_exact,omitempty"`
	Priority          string `json:"priority,omitempty"`
	BufferSizeBytes   uint64 `json:"buffer_size_bytes,omitempty"`
}

type CoSSchedulerMapSnapshot struct {
	Name    string                         `json:"name"`
	Entries []CoSSchedulerMapEntrySnapshot `json:"entries,omitempty"`
}

type CoSSchedulerMapEntrySnapshot struct {
	ForwardingClass string `json:"forwarding_class"`
	Scheduler       string `json:"scheduler,omitempty"`
}

type FabricSnapshot struct {
	Name            string `json:"name"`
	ParentInterface string `json:"parent_interface,omitempty"`
	ParentLinuxName string `json:"parent_linux_name,omitempty"`
	ParentIfindex   int    `json:"parent_ifindex,omitempty"`
	OverlayLinux    string `json:"overlay_linux_name,omitempty"`
	OverlayIfindex  int    `json:"overlay_ifindex,omitempty"`
	RXQueues        int    `json:"rx_queues,omitempty"`
	PeerAddress     string `json:"peer_address,omitempty"`
	LocalMAC        string `json:"local_mac,omitempty"`
	PeerMAC         string `json:"peer_mac,omitempty"`
}

type TunnelEndpointSnapshot struct {
	ID              uint16 `json:"id,omitempty"`
	Interface       string `json:"interface,omitempty"`
	LinuxName       string `json:"linux_name,omitempty"`
	Ifindex         int    `json:"ifindex,omitempty"`
	Zone            string `json:"zone,omitempty"`
	RedundancyGroup int    `json:"redundancy_group,omitempty"`
	MTU             int    `json:"mtu,omitempty"`
	Mode            string `json:"mode,omitempty"`
	OuterFamily     string `json:"outer_family,omitempty"`
	Source          string `json:"source,omitempty"`
	Destination     string `json:"destination,omitempty"`
	Key             uint32 `json:"key,omitempty"`
	TTL             int    `json:"ttl,omitempty"`
	TransportTable  string `json:"transport_table,omitempty"`
}

type SourceNATRuleSnapshot struct {
	Name                 string   `json:"name"`
	FromZone             string   `json:"from_zone,omitempty"`
	ToZone               string   `json:"to_zone,omitempty"`
	SourceAddresses      []string `json:"source_addresses,omitempty"`
	DestinationAddresses []string `json:"destination_addresses,omitempty"`
	InterfaceMode        bool     `json:"interface_mode,omitempty"`
	Off                  bool     `json:"off,omitempty"`
	PoolName             string   `json:"pool_name,omitempty"`
}

type StaticNATRuleSnapshot struct {
	Name       string `json:"name"`
	FromZone   string `json:"from_zone,omitempty"`
	ExternalIP string `json:"external_ip"`
	InternalIP string `json:"internal_ip"`
}

// DestinationNATRuleSnapshot captures a pre-expanded DNAT table entry for the
// userspace dataplane. Each snapshot is one (protocol, destination IP, destination port)
// tuple. The Go builder handles multi-port and protocol expansion.
type DestinationNATRuleSnapshot struct {
	Name               string `json:"name"`
	FromZone           string `json:"from_zone,omitempty"`
	DestinationAddress string `json:"destination_address"`
	DestinationPort    uint16 `json:"destination_port,omitempty"`
	Protocol           string `json:"protocol,omitempty"` // "tcp", "udp", or ""
	PoolAddress        string `json:"pool_address"`
	PoolPort           uint16 `json:"pool_port,omitempty"`
}

// NAT64RuleSnapshot captures a NAT64 prefix and its IPv4 source pool for the
// userspace dataplane.
type NAT64RuleSnapshot struct {
	Name          string   `json:"name"`
	Prefix        string   `json:"prefix"`         // e.g. "64:ff9b::/96"
	PoolAddresses []string `json:"pool_addresses"` // resolved IPv4 pool addresses
}

// Nptv6RuleSnapshot captures an NPTv6 (RFC 6296) stateless prefix translation
// rule for the userspace dataplane.
type Nptv6RuleSnapshot struct {
	Name           string `json:"name"`
	FromZone       string `json:"from_zone,omitempty"`
	InternalPrefix string `json:"internal_prefix"` // e.g. "fd35:1940:0027::/48"
	ExternalPrefix string `json:"external_prefix"` // e.g. "2602:fd41:0070::/48"
}

// ScreenProfileSnapshot captures a per-zone screen profile for the userspace
// dataplane. Mirrors the BPF screen_config structure.
type ScreenProfileSnapshot struct {
	Zone               string `json:"zone"`
	Land               bool   `json:"land,omitempty"`
	SynFin             bool   `json:"syn_fin,omitempty"`
	NoFlag             bool   `json:"tcp_no_flag,omitempty"`
	FinNoAck           bool   `json:"fin_no_ack,omitempty"`
	WinNuke            bool   `json:"winnuke,omitempty"`
	PingDeath          bool   `json:"ping_death,omitempty"`
	Teardrop           bool   `json:"teardrop,omitempty"`
	ICMPFragment       bool   `json:"icmp_fragment,omitempty"`
	SynFrag            bool   `json:"syn_frag,omitempty"`
	SourceRoute        bool   `json:"source_route,omitempty"`
	ICMPFloodThreshold uint32 `json:"icmp_flood_threshold,omitempty"`
	UDPFloodThreshold  uint32 `json:"udp_flood_threshold,omitempty"`
	SYNFloodThreshold  uint32 `json:"syn_flood_threshold,omitempty"`
	// Advanced screen features for userspace dataplane
	SessionLimitSrc   uint32 `json:"session_limit_src,omitempty"`
	SessionLimitDst   uint32 `json:"session_limit_dst,omitempty"`
	PortScanThreshold uint32 `json:"port_scan_threshold,omitempty"`
	IPSweepThreshold  uint32 `json:"ip_sweep_threshold,omitempty"`
}

type FirewallFilterSnapshot struct {
	Name   string                 `json:"name"`
	Family string                 `json:"family"` // "inet" or "inet6"
	Terms  []FirewallTermSnapshot `json:"terms"`
}

type FirewallTermSnapshot struct {
	Name            string   `json:"name"`
	SourceAddresses []string `json:"source_addresses,omitempty"`
	DestAddresses   []string `json:"destination_addresses,omitempty"`
	Protocols       []string `json:"protocols,omitempty"`
	SourcePorts     []string `json:"source_ports,omitempty"` // "80" or "1024-65535"
	DestPorts       []string `json:"destination_ports,omitempty"`
	DSCPValues      []uint8  `json:"dscp_values,omitempty"`
	Action          string   `json:"action"` // "accept", "discard", "reject"
	Count           string   `json:"count,omitempty"`
	Log             bool     `json:"log,omitempty"`
	PolicerName     string   `json:"policer,omitempty"`
	RoutingInstance string   `json:"routing_instance,omitempty"`
	ForwardingClass string   `json:"forwarding_class,omitempty"`
	DSCPRewrite     *uint8   `json:"dscp_rewrite,omitempty"`
}

type PolicerSnapshot struct {
	Name          string `json:"name"`
	BandwidthBps  uint64 `json:"bandwidth_bps"`
	BurstBytes    uint64 `json:"burst_bytes"`
	DiscardExcess bool   `json:"discard_excess"`
}

// FlowExportSnapshot captures flow monitoring/export configuration for the
// userspace dataplane.
type FlowExportSnapshot struct {
	CollectorAddress string `json:"collector_address"`
	CollectorPort    int    `json:"collector_port"`
	SamplingRate     int    `json:"sampling_rate"`
	ActiveTimeout    int    `json:"active_timeout,omitempty"`   // seconds, 0=default 60
	InactiveTimeout  int    `json:"inactive_timeout,omitempty"` // seconds, 0=default 15
}

type PolicyApplicationSnapshot struct {
	Name            string `json:"name"`
	Protocol        string `json:"protocol,omitempty"`
	SourcePort      string `json:"source_port,omitempty"`
	DestinationPort string `json:"destination_port,omitempty"`
}

type PolicyRuleSnapshot struct {
	Name                 string                      `json:"name"`
	FromZone             string                      `json:"from_zone,omitempty"`
	ToZone               string                      `json:"to_zone,omitempty"`
	SourceAddresses      []string                    `json:"source_addresses,omitempty"`
	DestinationAddresses []string                    `json:"destination_addresses,omitempty"`
	Applications         []string                    `json:"applications,omitempty"`
	ApplicationTerms     []PolicyApplicationSnapshot `json:"application_terms,omitempty"`
	Action               string                      `json:"action,omitempty"`
}

type InterfaceAddressSnapshot struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	Scope   int    `json:"scope,omitempty"`
}

type RouteSnapshot struct {
	Table       string   `json:"table"`
	Family      string   `json:"family"`
	Destination string   `json:"destination"`
	NextHops    []string `json:"next_hops,omitempty"`
	Discard     bool     `json:"discard"`
	NextTable   string   `json:"next_table,omitempty"`
}

type NeighborSnapshot struct {
	Interface string `json:"interface,omitempty"`
	Ifindex   int    `json:"ifindex,omitempty"`
	Family    string `json:"family"`
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	State     string `json:"state,omitempty"`
	Router    bool   `json:"router,omitempty"`
	LinkLocal bool   `json:"link_local,omitempty"`
}

type UserspaceMapPins struct {
	Ctrl        string `json:"ctrl,omitempty"`
	Bindings    string `json:"bindings,omitempty"`
	Heartbeat   string `json:"heartbeat,omitempty"`
	XSK         string `json:"xsk,omitempty"`
	LocalV4     string `json:"local_v4,omitempty"`
	LocalV6     string `json:"local_v6,omitempty"`
	Sessions    string `json:"sessions,omitempty"`
	ConntrackV4 string `json:"conntrack_v4,omitempty"`
	ConntrackV6 string `json:"conntrack_v6,omitempty"`
	DnatTable   string `json:"dnat_table,omitempty"`
	DnatTableV6 string `json:"dnat_table_v6,omitempty"`
	Trace       string `json:"trace,omitempty"`
}

type UserspaceCapabilities struct {
	ForwardingSupported bool     `json:"forwarding_supported"`
	UnsupportedReasons  []string `json:"unsupported_reasons,omitempty"`
}

type ProcessStatus struct {
	PID                    int                               `json:"pid"`
	StartedAt              time.Time                         `json:"started_at"`
	ControlSocket          string                            `json:"control_socket"`
	StateFile              string                            `json:"state_file"`
	Workers                int                               `json:"workers"`
	RingEntries            int                               `json:"ring_entries"`
	HelperMode             string                            `json:"helper_mode"`
	IOUringPlanned         bool                              `json:"io_uring_planned"`
	IOUringActive          bool                              `json:"io_uring_active,omitempty"`
	IOUringMode            string                            `json:"io_uring_mode,omitempty"`
	IOUringLastError       string                            `json:"io_uring_last_error,omitempty"`
	Enabled                bool                              `json:"enabled"`
	ForwardingArmed        bool                              `json:"forwarding_armed,omitempty"`
	Capabilities           UserspaceCapabilities             `json:"capabilities"`
	LastSnapshotGeneration uint64                            `json:"last_snapshot_generation"`
	LastFIBGeneration      uint32                            `json:"last_fib_generation,omitempty"`
	LastSnapshotAt         time.Time                         `json:"last_snapshot_at,omitempty"`
	InterfaceAddresses     int                               `json:"interface_addresses,omitempty"`
	NeighborEntries        int                               `json:"neighbor_entries,omitempty"`
	NeighborGeneration     uint64                            `json:"neighbor_generation,omitempty"`
	RouteEntries           int                               `json:"route_entries,omitempty"`
	WorkerHeartbeats       []time.Time                       `json:"worker_heartbeats,omitempty"`
	// #869: per-worker busy/idle runtime telemetry.
	WorkerRuntime          []WorkerRuntimeStatus             `json:"worker_runtime,omitempty"`
	HAGroups               []HAGroupStatus                   `json:"ha_groups,omitempty"`
	Fabrics                []FabricSnapshot                  `json:"fabrics,omitempty"`
	Queues                 []QueueStatus                     `json:"queues,omitempty"`
	Bindings               []BindingStatus                   `json:"bindings,omitempty"`
	// #802: focused per-binding ring-pressure view. Projected from
	// Bindings by the Rust helper; parallel rather than replacement.
	PerBinding             []BindingCountersSnapshot         `json:"per_binding,omitempty"`
	RecentSessionDeltas    []SessionDeltaInfo                `json:"recent_session_deltas,omitempty"`
	RecentExceptions       []ExceptionStatus                 `json:"recent_exceptions,omitempty"`
	CoSInterfaces          []CoSInterfaceStatus              `json:"cos_interfaces,omitempty"`
	FilterTermCounters     []FirewallFilterTermCounterStatus `json:"filter_term_counters,omitempty"`
	LastResolution         *PacketResolution                 `json:"last_resolution,omitempty"`
	SlowPath               SlowPathStatus                    `json:"slow_path,omitempty"`
	LastCacheFlushAt       uint64                            `json:"last_cache_flush_at,omitempty"` // monotonic secs (#312)
	DataplaneMode          string                            `json:"dataplane_mode,omitempty"`      // Current active mode: "ebpf_only", "userspace_compat", "userspace_strict"
	ConfiguredMode         string                            `json:"configured_mode,omitempty"`     // Desired mode from config
	EntryPrograms          map[int]string                    `json:"entry_programs,omitempty"`      // ifindex -> attached XDP program name
	FallbackCounters       map[string]uint64                 `json:"fallback_counters,omitempty"`   // reason_name -> count
}

type CoSInterfaceStatus struct {
	Ifindex             int              `json:"ifindex,omitempty"`
	InterfaceName       string           `json:"interface_name,omitempty"`
	OwnerWorkerID       *uint32          `json:"owner_worker_id,omitempty"`
	ShapingRateBytes    uint64           `json:"shaping_rate_bytes,omitempty"`
	BurstBytes          uint64           `json:"burst_bytes,omitempty"`
	WorkerInstances     int              `json:"worker_instances,omitempty"`
	NonemptyQueues      int              `json:"nonempty_queues,omitempty"`
	RunnableQueues      int              `json:"runnable_queues,omitempty"`
	TimerLevel0Sleepers int              `json:"timer_level0_sleepers,omitempty"`
	TimerLevel1Sleepers int              `json:"timer_level1_sleepers,omitempty"`
	Queues              []CoSQueueStatus `json:"queues,omitempty"`
}

type CoSQueueStatus struct {
	QueueID             int     `json:"queue_id,omitempty"`
	OwnerWorkerID       *uint32 `json:"owner_worker_id,omitempty"`
	ForwardingClass     string  `json:"forwarding_class,omitempty"`
	Priority            int     `json:"priority,omitempty"`
	Exact               bool    `json:"exact,omitempty"`
	TransmitRateBytes   uint64  `json:"transmit_rate_bytes,omitempty"`
	BufferBytes         uint64  `json:"buffer_bytes,omitempty"`
	WorkerInstances     int     `json:"worker_instances,omitempty"`
	QueuedPackets       uint64  `json:"queued_packets,omitempty"`
	QueuedBytes         uint64  `json:"queued_bytes,omitempty"`
	RunnableInstances   int     `json:"runnable_instances,omitempty"`
	ParkedInstances     int     `json:"parked_instances,omitempty"`
	NextWakeupTick      uint64  `json:"next_wakeup_tick,omitempty"`
	SurplusDeficitBytes uint64  `json:"surplus_deficit_bytes,omitempty"`
	// #710/#718: per-queue admission-path counters aggregated across
	// worker instances by the Rust coordinator. JSON tags MUST match the
	// Rust serde rename(...) exactly — the wire format is the contract.
	AdmissionFlowShareDrops uint64 `json:"admission_flow_share_drops,omitempty"`
	AdmissionBufferDrops    uint64 `json:"admission_buffer_drops,omitempty"`
	AdmissionEcnMarked      uint64 `json:"admission_ecn_marked,omitempty"`
	// #709 / #751: owner-profile telemetry. Populated only when an
	// exact queue can inherit a binding-scoped owner profile
	// unambiguously; zero for shared_exact, non-exact, and ambiguous
	// multi-owner-local shapes. See docs/709-owner-hotspot-plan.md for
	// the decision tree these counters drive. JSON tags MUST match Rust
	// serde rename(...) byte-for-byte.
	//
	// DrainLatencyHist and RedirectAcquireHist are power-of-two ns
	// bucketed (see Rust `bucket_index_for_ns`): index 0 is < 1 µs,
	// index N >= 1 is [2^(N+9), 2^(N+10)) ns, index 15 saturates at
	// >= 2^24 ns (~16 ms).
	ActiveFlowBucketsPeak uint64   `json:"active_flow_buckets_peak,omitempty"`
	FlowFair              bool     `json:"flow_fair,omitempty"`
	DrainLatencyHist     []uint64 `json:"drain_latency_hist,omitempty"`
	DrainInvocations     uint64   `json:"drain_invocations,omitempty"`
	DrainNoopInvocations uint64   `json:"drain_noop_invocations,omitempty"`
	RedirectAcquireHist  []uint64 `json:"redirect_acquire_hist,omitempty"`
	OwnerPPS             uint64   `json:"owner_pps,omitempty"`
	PeerPPS              uint64   `json:"peer_pps,omitempty"`
	// #760 overshoot-hunt instrumentation. DrainSentBytes /
	// DrainParkRootTokens / DrainParkQueueTokens are queue-scoped.
	// PostDrainBackupBytes is binding-scoped (same row as
	// OwnerPPS/PeerPPS). See Rust `CoSQueueStatus` for field
	// semantics and write-site locations.
	DrainSentBytes        uint64 `json:"drain_sent_bytes,omitempty"`
	DrainParkRootTokens   uint64 `json:"drain_park_root_tokens,omitempty"`
	DrainParkQueueTokens  uint64 `json:"drain_park_queue_tokens,omitempty"`
	PostDrainBackupBytes                uint64 `json:"post_drain_backup_bytes,omitempty"`
	DrainSentBytesShapedUnconditional   uint64 `json:"drain_sent_bytes_shaped_unconditional,omitempty"`
	PostDrainBackupCosDrops             uint64 `json:"post_drain_backup_cos_drops,omitempty"`
	PostDrainBackupCosDropBytes         uint64 `json:"post_drain_backup_cos_drop_bytes,omitempty"`
}

type FirewallFilterTermCounterStatus struct {
	Family     string `json:"family,omitempty"`
	FilterName string `json:"filter_name,omitempty"`
	TermName   string `json:"term_name,omitempty"`
	Packets    uint64 `json:"packets,omitempty"`
	Bytes      uint64 `json:"bytes,omitempty"`
}

type HAStateUpdateRequest struct {
	Groups []HAGroupStatus `json:"groups,omitempty"`
}

// #869: WorkerRuntimeStatus mirrors the Rust WorkerRuntimeStatus;
// each entry is one AF_XDP worker thread's cumulative runtime counters,
// refreshed on the worker's ~1s publish cadence.  All fields omit when
// zero so older daemons parse correctly.
type WorkerRuntimeStatus struct {
	WorkerID    uint32 `json:"worker_id,omitempty"`
	TID         uint64 `json:"tid,omitempty"`
	WallNS      uint64 `json:"wall_ns,omitempty"`
	ActiveNS    uint64 `json:"active_ns,omitempty"`
	IdleSpinNS  uint64 `json:"idle_spin_ns,omitempty"`
	IdleBlockNS uint64 `json:"idle_block_ns,omitempty"`
	ThreadCPUNS uint64 `json:"thread_cpu_ns,omitempty"`
	WorkLoops   uint64 `json:"work_loops,omitempty"`
	IdleLoops   uint64 `json:"idle_loops,omitempty"`
	// #925 Phase 1+2 (catch+report+observe): Dead == true means the
	// worker_loop panicked and the supervisor caught it. Set-only
	// today — cleared only by daemon restart. Phase 2 surfaces this
	// on Prometheus as `xpf_userspace_worker_dead` (this PR). A
	// hypothetical Phase 3 (respawn, deferred indefinitely) would
	// clear this by replacing WorkerRuntimeAtomics on relaunch.
	// PanicMessage holds the rendered payload for operator diagnosis.
	Dead         bool   `json:"dead,omitempty"`
	PanicMessage string `json:"panic_message,omitempty"`
}

type HAGroupStatus struct {
	RGID              int    `json:"rg_id"`
	Active            bool   `json:"active"`
	WatchdogTimestamp uint64 `json:"watchdog_timestamp,omitempty"`
}

type SlowPathStatus struct {
	Active             bool   `json:"active"`
	DeviceName         string `json:"device_name,omitempty"`
	Mode               string `json:"mode,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	QueuedPackets      uint64 `json:"queued_packets,omitempty"`
	InjectedPackets    uint64 `json:"injected_packets,omitempty"`
	InjectedBytes      uint64 `json:"injected_bytes,omitempty"`
	DroppedPackets     uint64 `json:"dropped_packets,omitempty"`
	DroppedBytes       uint64 `json:"dropped_bytes,omitempty"`
	RateLimitedPackets uint64 `json:"rate_limited_packets,omitempty"`
	QueueFullPackets   uint64 `json:"queue_full_packets,omitempty"`
	WriteErrors        uint64 `json:"write_errors,omitempty"`
}

type PacketResolution struct {
	Disposition    string `json:"disposition"`
	LocalIfindex   int    `json:"local_ifindex,omitempty"`
	EgressIfindex  int    `json:"egress_ifindex,omitempty"`
	IngressIfindex int    `json:"ingress_ifindex,omitempty"`
	NextHop        string `json:"next_hop,omitempty"`
	NeighborMAC    string `json:"neighbor_mac,omitempty"`
	SrcIP          string `json:"src_ip,omitempty"`
	DstIP          string `json:"dst_ip,omitempty"`
	SrcPort        uint16 `json:"src_port,omitempty"`
	DstPort        uint16 `json:"dst_port,omitempty"`
	FromZone       string `json:"from_zone,omitempty"`
	ToZone         string `json:"to_zone,omitempty"`
}

type ForwardingControlRequest struct {
	Armed bool `json:"armed"`
}

type QueueControlRequest struct {
	QueueID    uint32 `json:"queue_id"`
	Registered bool   `json:"registered"`
	Armed      bool   `json:"armed"`
}

type BindingControlRequest struct {
	Slot       uint32 `json:"slot"`
	Registered bool   `json:"registered"`
	Armed      bool   `json:"armed"`
}

type QueueStatus struct {
	QueueID    uint32    `json:"queue_id"`
	WorkerID   uint32    `json:"worker_id"`
	Interfaces []string  `json:"interfaces,omitempty"`
	Registered bool      `json:"registered"`
	Armed      bool      `json:"armed"`
	Ready      bool      `json:"ready"`
	LastChange time.Time `json:"last_change,omitempty"`
}

type BindingStatus struct {
	Slot                              uint32    `json:"slot"`
	QueueID                           uint32    `json:"queue_id"`
	WorkerID                          uint32    `json:"worker_id"`
	Interface                         string    `json:"interface,omitempty"`
	Ifindex                           int       `json:"ifindex,omitempty"`
	Registered                        bool      `json:"registered"`
	Armed                             bool      `json:"armed"`
	Ready                             bool      `json:"ready"`
	Bound                             bool      `json:"bound"`
	XSKRegistered                     bool      `json:"xsk_registered"`
	XSKBindMode                       string    `json:"xsk_bind_mode,omitempty"`
	ZeroCopy                          bool      `json:"zero_copy,omitempty"`
	SocketFD                          int       `json:"socket_fd,omitempty"`
	RXPackets                         uint64    `json:"rx_packets,omitempty"`
	RXBytes                           uint64    `json:"rx_bytes,omitempty"`
	RXBatches                         uint64    `json:"rx_batches,omitempty"`
	RXWakeups                         uint64    `json:"rx_wakeups,omitempty"`
	MetadataPackets                   uint64    `json:"metadata_packets,omitempty"`
	MetadataErrors                    uint64    `json:"metadata_errors,omitempty"`
	ValidatedPackets                  uint64    `json:"validated_packets,omitempty"`
	ValidatedBytes                    uint64    `json:"validated_bytes,omitempty"`
	LocalDeliveryPackets              uint64    `json:"local_delivery_packets,omitempty"`
	ForwardCandidatePkts              uint64    `json:"forward_candidate_packets,omitempty"`
	RouteMissPackets                  uint64    `json:"route_miss_packets,omitempty"`
	NeighborMissPackets               uint64    `json:"neighbor_miss_packets,omitempty"`
	DiscardRoutePackets               uint64    `json:"discard_route_packets,omitempty"`
	NextTablePackets                  uint64    `json:"next_table_packets,omitempty"`
	ExceptionPackets                  uint64    `json:"exception_packets,omitempty"`
	ConfigGenMismatches               uint64    `json:"config_gen_mismatches,omitempty"`
	FIBGenMismatches                  uint64    `json:"fib_gen_mismatches,omitempty"`
	UnsupportedPackets                uint64    `json:"unsupported_packets,omitempty"`
	FlowCacheHits                     uint64    `json:"flow_cache_hits,omitempty"`
	FlowCacheMisses                   uint64    `json:"flow_cache_misses,omitempty"`
	FlowCacheEvictions                uint64    `json:"flow_cache_evictions,omitempty"`
	// #918: collision-driven subset of flow_cache_evictions (full-set
	// LRU displacement vs stale-on-lookup eviction). Acceptance gate
	// watches collision_evictions / hits under load.
	FlowCacheCollisionEvictions       uint64    `json:"flow_cache_collision_evictions,omitempty"`
	// #941 Work item D / #943: V_min throttle counters. Hard-cap is
	// the escape-hatch firing when fairness brake (regular throttle)
	// has thrown V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back times.
	// Together: VMinThrottles = "fairness brake fired",
	// VMinThrottleHardCapOverrides = "brake too tight, escape hatch
	// rescued throughput". Ratio is the LAG_THRESHOLD diagnostic.
	VMinThrottleHardCapOverrides      uint64    `json:"v_min_throttle_hard_cap_overrides,omitempty"`
	VMinThrottles                     uint64    `json:"v_min_throttles,omitempty"`
	SessionHits                       uint64    `json:"session_hits,omitempty"`
	SessionMisses                     uint64    `json:"session_misses,omitempty"`
	SessionCreates                    uint64    `json:"session_creates,omitempty"`
	SessionExpires                    uint64    `json:"session_expires,omitempty"`
	SessionDeltaPending               uint64    `json:"session_delta_pending,omitempty"`
	SessionDeltaGenerated             uint64    `json:"session_delta_generated,omitempty"`
	SessionDeltaDropped               uint64    `json:"session_delta_dropped,omitempty"`
	SessionDeltaDrained               uint64    `json:"session_delta_drained,omitempty"`
	PolicyDeniedPackets               uint64    `json:"policy_denied_packets,omitempty"`
	ScreenDrops                       uint64    `json:"screen_drops,omitempty"`
	SNATPackets                       uint64    `json:"snat_packets,omitempty"`
	DNATPackets                       uint64    `json:"dnat_packets,omitempty"`
	SlowPathPackets                   uint64    `json:"slow_path_packets,omitempty"`
	SlowPathBytes                     uint64    `json:"slow_path_bytes,omitempty"`
	SlowPathLocalDeliveryPackets      uint64    `json:"slow_path_local_delivery_packets,omitempty"`
	SlowPathMissingNeighborPackets    uint64    `json:"slow_path_missing_neighbor_packets,omitempty"`
	SlowPathNoRoutePackets            uint64    `json:"slow_path_no_route_packets,omitempty"`
	SlowPathNextTablePackets          uint64    `json:"slow_path_next_table_packets,omitempty"`
	SlowPathForwardBuildPackets       uint64    `json:"slow_path_forward_build_packets,omitempty"`
	SlowPathDrops                     uint64    `json:"slow_path_drops,omitempty"`
	SlowPathRateLimited               uint64    `json:"slow_path_rate_limited,omitempty"`
	KernelRXDropped                   uint64    `json:"kernel_rx_dropped,omitempty"`
	KernelRXInvalidDescs              uint64    `json:"kernel_rx_invalid_descs,omitempty"`
	TXPackets                         uint64    `json:"tx_packets,omitempty"`
	TXBytes                           uint64    `json:"tx_bytes,omitempty"`
	TXErrors                          uint64    `json:"tx_errors,omitempty"`
	TXCompletions                     uint64    `json:"tx_completions,omitempty"`
	DirectTXPackets                   uint64    `json:"direct_tx_packets,omitempty"`
	CopyTXPackets                     uint64    `json:"copy_tx_packets,omitempty"`
	InPlaceTXPackets                  uint64    `json:"in_place_tx_packets,omitempty"`
	DirectTXNoFrameFallbackPackets    uint64    `json:"direct_tx_no_frame_fallback_packets,omitempty"`
	DirectTXBuildFallbackPackets      uint64    `json:"direct_tx_build_fallback_packets,omitempty"`
	DirectTXDisallowedFallbackPackets uint64    `json:"direct_tx_disallowed_fallback_packets,omitempty"`
	DebugPendingFillFrames            uint32    `json:"debug_pending_fill_frames,omitempty"`
	DebugSpareFillFrames              uint32    `json:"debug_spare_fill_frames,omitempty"`
	DebugFreeTXFrames                 uint32    `json:"debug_free_tx_frames,omitempty"`
	DebugPendingTXPrepared            uint32    `json:"debug_pending_tx_prepared,omitempty"`
	DebugPendingTXLocal               uint32    `json:"debug_pending_tx_local,omitempty"`
	DebugOutstandingTX                uint32    `json:"debug_outstanding_tx,omitempty"`
	DebugInFlightRecycles             uint32    `json:"debug_in_flight_recycles,omitempty"`
	// #802/#804: ring-pressure instrumentation mirror fields. See the
	// Rust `BindingStatus` for semantics and write sites. The #804
	// split replaces the pre-#804 `dbg_pending_overflow` field with
	// two distinct wire keys — `dbg_bound_pending_overflow` for the
	// `bound_pending` FIFO evict sites in `tx.rs`, and
	// `dbg_cos_queue_overflow` for the class-of-service admission
	// overflow in `enqueue_cos_item`. A snapshot from a pre-#804
	// helper deserializes both as 0 (standard Go json zero-value),
	// which is the right backward-compat behavior.
	DbgTxRingFull                     uint64    `json:"dbg_tx_ring_full,omitempty"`
	DbgSendtoENOBUFS                  uint64    `json:"dbg_sendto_enobufs,omitempty"`
	DbgBoundPendingOverflow           uint64    `json:"dbg_bound_pending_overflow,omitempty"`
	DbgCoSQueueOverflow               uint64    `json:"dbg_cos_queue_overflow,omitempty"`
	RxFillRingEmptyDescs              uint64    `json:"rx_fill_ring_empty_descs,omitempty"`
	OutstandingTX                     uint32    `json:"outstanding_tx,omitempty"`
	// #878: per-binding UMEM total frames and TX-ring depth (set
	// once at worker construction) plus in-flight gauge (republished
	// each ~1s by the worker as a single atomic store from local
	// state — no torn reads). fwdstatus Buffer% =
	//   max(UmemInflightFrames/UmemTotalFrames,
	//       OutstandingTX/TxRingCapacity)
	// aggregated as max across bindings. Zero on UmemTotalFrames
	// means "not yet published" — fwdstatus falls back to the legacy
	// "unknown" display.
	UmemTotalFrames                   uint32    `json:"umem_total_frames,omitempty"`
	TxRingCapacity                    uint32    `json:"tx_ring_capacity,omitempty"`
	UmemInflightFrames                uint32    `json:"umem_inflight_frames,omitempty"`
	// #812: per-queue TX submit→completion latency telemetry. 16 log2-
	// spaced buckets (see Rust `DRAIN_HIST_BUCKETS` wire contract), plus
	// a total completion count and running sum-ns. Emitted on the rich
	// BindingStatus AND projected onto BindingCountersSnapshot so
	// step1-capture consumers can compute per-queue latency
	// distributions without a second join. omitempty keeps forward-
	// compat — a pre-#812 helper that lacks these fields decodes into
	// empty slice / zero u64.
	TxSubmitLatencyHist               []uint64  `json:"tx_submit_latency_hist,omitempty"`
	TxSubmitLatencyCount              uint64    `json:"tx_submit_latency_count,omitempty"`
	TxSubmitLatencySumNs              uint64    `json:"tx_submit_latency_sum_ns,omitempty"`
	// #825: per-kick `sendto` latency telemetry. 16 log2 buckets
	// (wire-compatible with `tx_submit_latency_hist` /
	// `drain_latency_hist`), plus count, sum-ns, and the
	// EAGAIN/EWOULDBLOCK retry tally (T1 ring-pushback signal per
	// #819 §4.1). omitempty keeps forward-compat — a pre-#825
	// helper that lacks these fields decodes into empty slice /
	// zero uint64.
	TxKickLatencyHist                 []uint64  `json:"tx_kick_latency_hist,omitempty"`
	TxKickLatencyCount                uint64    `json:"tx_kick_latency_count,omitempty"`
	TxKickLatencySumNs                uint64    `json:"tx_kick_latency_sum_ns,omitempty"`
	TxKickRetryCount                  uint64    `json:"tx_kick_retry_count,omitempty"`
	LastHeartbeat                     time.Time `json:"last_heartbeat,omitempty"`
	LastError                         string    `json:"last_error,omitempty"`
	LastChange                        time.Time `json:"last_change,omitempty"`
}

// BindingCountersSnapshot is the focused per-binding ring-pressure view
// surfaced on ProcessStatus.PerBinding. It is a strict subset of
// BindingStatus, emitted by the Rust helper so the daemon's poll path
// can deserialize only the triage counters when that's all it needs.
// See the Rust `BindingCountersSnapshot` definition for semantics.
//
// #802.
type BindingCountersSnapshot struct {
	WorkerID uint32 `json:"worker_id"`
	Ifindex  int    `json:"ifindex,omitempty"`
	QueueID  uint32 `json:"queue_id"`
	DbgTxRingFull    uint64 `json:"dbg_tx_ring_full,omitempty"`
	DbgSendtoENOBUFS uint64 `json:"dbg_sendto_enobufs,omitempty"`
	// #804: split from the pre-#804 `dbg_pending_overflow` field. Two
	// distinct increment sites (bound-pending FIFO evict in tx.rs vs
	// CoS queue admission in enqueue_cos_item) now publish two
	// distinct wire keys so operators can disambiguate. A snapshot
	// from a pre-#804 helper will leave both fields at the Go
	// zero-value — there is no silent re-attribution of the legacy
	// counter. Consumers that want a total across either path should
	// sum these two explicitly.
	DbgBoundPendingOverflow     uint64 `json:"dbg_bound_pending_overflow,omitempty"`
	DbgCoSQueueOverflow         uint64 `json:"dbg_cos_queue_overflow,omitempty"`
	RxFillRingEmptyDescs        uint64 `json:"rx_fill_ring_empty_descs,omitempty"`
	OutstandingTX               uint32 `json:"outstanding_tx,omitempty"`
	// #878: per-binding capacities pulled through to the leaner
	// snapshot so the daemon's fast poller can compute Buffer%
	// without joining the full BindingStatus. See BindingStatus
	// for full semantics.
	UmemTotalFrames             uint32 `json:"umem_total_frames,omitempty"`
	TxRingCapacity              uint32 `json:"tx_ring_capacity,omitempty"`
	UmemInflightFrames          uint32 `json:"umem_inflight_frames,omitempty"`
	TXErrors                    uint64 `json:"tx_errors,omitempty"`
	TxSubmitErrorDrops          uint64 `json:"tx_submit_error_drops,omitempty"`
	PendingTxLocalOverflowDrops uint64 `json:"pending_tx_local_overflow_drops,omitempty"`
	// #812: per-queue TX submit→completion latency histogram, pulled
	// through from BindingStatus so step1-capture consumers can
	// compute per-queue latency distributions without a second
	// query. Layout is 16 log2-spaced buckets (see the Rust
	// `DRAIN_HIST_BUCKETS` wire contract); omitempty on all three
	// preserves forward-compat — a pre-#812 helper that lacks these
	// fields decodes into empty slice / zero u64 without the daemon
	// erroring.
	TxSubmitLatencyHist    []uint64 `json:"tx_submit_latency_hist,omitempty"`
	TxSubmitLatencyCount   uint64   `json:"tx_submit_latency_count,omitempty"`
	TxSubmitLatencySumNs   uint64   `json:"tx_submit_latency_sum_ns,omitempty"`
	// #825: per-kick `sendto` latency telemetry, pulled through
	// from BindingStatus so step1-capture / P3 consumers can
	// compute per-queue kick-latency distributions without a
	// second query. omitempty on all four preserves forward-compat.
	TxKickLatencyHist    []uint64 `json:"tx_kick_latency_hist,omitempty"`
	TxKickLatencyCount   uint64   `json:"tx_kick_latency_count,omitempty"`
	TxKickLatencySumNs   uint64   `json:"tx_kick_latency_sum_ns,omitempty"`
	TxKickRetryCount     uint64   `json:"tx_kick_retry_count,omitempty"`
	// #918: per-set LRU collision-eviction counter, brought through
	// to the lean snapshot for fast-poll consumers that need the
	// flow-cache thrash signal. Default keeps pre-#918 helpers parseable.
	FlowCacheCollisionEvictions uint64 `json:"flow_cache_collision_evictions,omitempty"`
	// #941 Work item D / #943: V_min throttle counters. The lean
	// per_binding view is what fast-poll consumers (mouse-latency
	// orchestrator, MQFQ diagnostics) read; without these here, V_min
	// observability stops at the rich BindingStatus and ProcessStatus.per_binding
	// projects zeros even when the atomics flushed real values.
	VMinThrottleHardCapOverrides uint64 `json:"v_min_throttle_hard_cap_overrides,omitempty"`
	VMinThrottles                uint64 `json:"v_min_throttles,omitempty"`
}

type ExceptionStatus struct {
	Timestamp        time.Time `json:"timestamp"`
	Slot             uint32    `json:"slot"`
	QueueID          uint32    `json:"queue_id"`
	WorkerID         uint32    `json:"worker_id"`
	Interface        string    `json:"interface,omitempty"`
	Ifindex          int       `json:"ifindex,omitempty"`
	IngressIfindex   int       `json:"ingress_ifindex,omitempty"`
	Reason           string    `json:"reason"`
	PacketLength     uint32    `json:"packet_length,omitempty"`
	AddrFamily       uint8     `json:"addr_family,omitempty"`
	Protocol         uint8     `json:"protocol,omitempty"`
	ConfigGeneration uint64    `json:"config_generation,omitempty"`
	FIBGeneration    uint32    `json:"fib_generation,omitempty"`
	SrcIP            string    `json:"src_ip,omitempty"`
	DstIP            string    `json:"dst_ip,omitempty"`
	SrcPort          uint16    `json:"src_port,omitempty"`
	DstPort          uint16    `json:"dst_port,omitempty"`
	FromZone         string    `json:"from_zone,omitempty"`
	ToZone           string    `json:"to_zone,omitempty"`
}

type InjectPacketRequest struct {
	Slot             uint32 `json:"slot"`
	PacketLength     uint32 `json:"packet_length,omitempty"`
	AddrFamily       uint8  `json:"addr_family,omitempty"`
	Protocol         uint8  `json:"protocol,omitempty"`
	ConfigGeneration uint64 `json:"config_generation,omitempty"`
	FIBGeneration    uint32 `json:"fib_generation,omitempty"`
	MetadataValid    bool   `json:"metadata_valid"`
	DestinationIP    string `json:"destination_ip,omitempty"`
	EmitOnWire       bool   `json:"emit_on_wire,omitempty"`
}

type SessionDeltaDrainRequest struct {
	Max uint32 `json:"max,omitempty"`
}

type SessionExportRequest struct {
	OwnerRGs []int  `json:"owner_rgs,omitempty"`
	Max      uint32 `json:"max,omitempty"`
}

type SessionSyncRequest struct {
	Operation        string `json:"operation,omitempty"`
	AddrFamily       uint8  `json:"addr_family,omitempty"`
	Protocol         uint8  `json:"protocol,omitempty"`
	SrcIP            string `json:"src_ip,omitempty"`
	DstIP            string `json:"dst_ip,omitempty"`
	SrcPort          uint16 `json:"src_port,omitempty"`
	DstPort          uint16 `json:"dst_port,omitempty"`
	IngressZone      string `json:"ingress_zone,omitempty"`
	EgressZone       string `json:"egress_zone,omitempty"`
	// #919/#922: u16 zone-id mirrors. Additive — the Rust daemon
	// prefers the IDs when nonzero and falls back to the legacy
	// name strings otherwise. Old peers without these fields
	// continue to work (Rust serde sets the IDs to 0).
	IngressZoneID    uint16 `json:"ingress_zone_id,omitempty"`
	EgressZoneID     uint16 `json:"egress_zone_id,omitempty"`
	OwnerRGID        int    `json:"owner_rg_id,omitempty"`
	EgressIfindex    int    `json:"egress_ifindex,omitempty"`
	TXIfindex        int    `json:"tx_ifindex,omitempty"`
	TunnelEndpointID uint16 `json:"tunnel_endpoint_id,omitempty"`
	TXVLANID         uint16 `json:"tx_vlan_id,omitempty"`
	NextHop          string `json:"next_hop,omitempty"`
	NeighborMAC      string `json:"neighbor_mac,omitempty"`
	SrcMAC           string `json:"src_mac,omitempty"`
	NATSrcIP         string `json:"nat_src_ip,omitempty"`
	NATDstIP         string `json:"nat_dst_ip,omitempty"`
	NATSrcPort       uint16 `json:"nat_src_port,omitempty"`
	NATDstPort       uint16 `json:"nat_dst_port,omitempty"`
	FabricIngress    bool   `json:"fabric_ingress,omitempty"`
	IsReverse        bool   `json:"is_reverse,omitempty"`
}

type SessionDeltaInfo struct {
	Timestamp        time.Time `json:"timestamp"`
	Slot             uint32    `json:"slot"`
	QueueID          uint32    `json:"queue_id"`
	WorkerID         uint32    `json:"worker_id"`
	Interface        string    `json:"interface,omitempty"`
	Ifindex          int       `json:"ifindex,omitempty"`
	Event            string    `json:"event"`
	AddrFamily       uint8     `json:"addr_family,omitempty"`
	Protocol         uint8     `json:"protocol,omitempty"`
	SrcIP            string    `json:"src_ip,omitempty"`
	DstIP            string    `json:"dst_ip,omitempty"`
	SrcPort          uint16    `json:"src_port,omitempty"`
	DstPort          uint16    `json:"dst_port,omitempty"`
	IngressZone      string    `json:"ingress_zone,omitempty"`
	EgressZone       string    `json:"egress_zone,omitempty"`
	// #919/#922: u16 zone-id mirrors decoded directly from the binary
	// event-stream payload (bytes [21],[22] u8 → u16 here for symmetry
	// with SessionSyncRequest). The HA delta path prefers these IDs;
	// the legacy strings stay populated when JSON callers fill them.
	IngressZoneID    uint16    `json:"ingress_zone_id,omitempty"`
	EgressZoneID     uint16    `json:"egress_zone_id,omitempty"`
	OwnerRGID        int       `json:"owner_rg_id,omitempty"`
	Disposition      string    `json:"disposition,omitempty"`
	Origin           string    `json:"origin,omitempty"`
	EgressIfindex    int       `json:"egress_ifindex,omitempty"`
	TXIfindex        int       `json:"tx_ifindex,omitempty"`
	TunnelEndpointID uint16    `json:"tunnel_endpoint_id,omitempty"`
	TXVLANID         uint16    `json:"tx_vlan_id,omitempty"`
	NextHop          string    `json:"next_hop,omitempty"`
	NeighborMAC      string    `json:"neighbor_mac,omitempty"`
	SrcMAC           string    `json:"src_mac,omitempty"`
	NATSrcIP         string    `json:"nat_src_ip,omitempty"`
	NATDstIP         string    `json:"nat_dst_ip,omitempty"`
	NATSrcPort       uint16    `json:"nat_src_port,omitempty"`
	NATDstPort       uint16    `json:"nat_dst_port,omitempty"`
	FabricRedirect   bool      `json:"fabric_redirect,omitempty"`
	FabricIngress    bool      `json:"fabric_ingress,omitempty"`
}

// ---------------------------------------------------------------------------
// Event stream wire format (binary framed, helper → daemon push stream).
// ---------------------------------------------------------------------------

// EventFrameHeaderSize is the byte length of every event stream frame header.
const EventFrameHeaderSize = 16

// Event stream message types.
const (
	EventTypeSessionOpen   uint8 = 1
	EventTypeSessionClose  uint8 = 2
	EventTypeSessionUpdate uint8 = 3
	EventTypeAck           uint8 = 4  // daemon → helper
	EventTypePause         uint8 = 5  // daemon → helper
	EventTypeResume        uint8 = 6  // daemon → helper
	EventTypeDrainRequest  uint8 = 7  // daemon → helper (target seq in header)
	EventTypeDrainComplete uint8 = 8  // helper → daemon
	EventTypeFullResync    uint8 = 9  // helper → daemon
	EventTypeKeepalive     uint8 = 10 // helper → daemon (idle heartbeat)
)

// Session event flag bits in the Flags byte of SessionOpen/Update/Close payloads.
const (
	SessionEventFlagFabricRedirect uint8 = 1 << 0
	SessionEventFlagFabricIngress  uint8 = 1 << 1
	SessionEventFlagIsReverse      uint8 = 1 << 2
)
