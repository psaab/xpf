package config

import (
	"strconv"
	"strings"
)

// LinuxIfName translates a Junos-style interface name (e.g. "ge-0/0/0")
// to a valid Linux interface name (e.g. "ge-0-0-0"). Linux IFNAMSIZ
// forbids "/" so we replace with "-".
func LinuxIfName(name string) string {
	return strings.ReplaceAll(name, "/", "-")
}

// InterfaceSlot extracts the FPC slot number from a Junos interface name.
// "ge-0/0/7" → 0, "ge-7/0/7" → 7, "xe-3/1/2" → 3.
// Returns -1 if the name doesn't match the <type>-N/N/N pattern.
func InterfaceSlot(name string) int {
	// Find the first "-" separator, then parse the FPC number before the first "/".
	dashIdx := strings.Index(name, "-")
	if dashIdx < 0 || dashIdx+1 >= len(name) {
		return -1
	}
	rest := name[dashIdx+1:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return -1
	}
	slot, err := strconv.Atoi(rest[:slashIdx])
	if err != nil {
		return -1
	}
	return slot
}

// SlotToNodeID maps a vSRX FPC slot to a cluster node-id.
// Convention: slot 0 → node0, slot 7 → node1.
func SlotToNodeID(slot int) int {
	if slot == 7 {
		return 1
	}
	return 0
}

// RethToPhysical returns a map of reth name → local physical member name.
// Built from interfaces that have RedundantParent set.
func (c *Config) RethToPhysical() map[string]string {
	m := make(map[string]string)
	bestScore := make(map[string]int)
	localNodeID := -1
	if c.Chassis.Cluster != nil {
		localNodeID = c.Chassis.Cluster.NodeID
	}
	for _, ifc := range c.Interfaces.Interfaces {
		if ifc.RedundantParent != "" {
			score := 1
			if localNodeID >= 0 {
				slot := InterfaceSlot(ifc.Name)
				if slot >= 0 {
					if SlotToNodeID(slot) == localNodeID {
						score = 2
					} else {
						score = 0
					}
				}
			}
			prev, ok := m[ifc.RedundantParent]
			if !ok || score > bestScore[ifc.RedundantParent] ||
				(score == bestScore[ifc.RedundantParent] && ifc.Name < prev) {
				m[ifc.RedundantParent] = ifc.Name
				bestScore[ifc.RedundantParent] = score
			}
		}
	}
	return m
}

// ResolveReth resolves "reth0" or "reth0.50" to the physical member equivalent.
// Returns input unchanged if not a RETH name.
func (c *Config) ResolveReth(ref string) string {
	rethMap := c.RethToPhysical()
	parts := strings.SplitN(ref, ".", 2)
	if phys, ok := rethMap[parts[0]]; ok {
		if len(parts) == 2 {
			return phys + "." + parts[1]
		}
		return phys
	}
	return ref
}

// ResolveFab resolves "fab0" or "fab0.0" to the backing physical member
// interface using LocalFabricMember. Returns input unchanged if not a fab name
// or the interface has no LocalFabricMember set.
func (c *Config) ResolveFab(ref string) string {
	parts := strings.SplitN(ref, ".", 2)
	base := parts[0]
	if c.Interfaces.Interfaces == nil {
		return ref
	}
	ifc, ok := c.Interfaces.Interfaces[base]
	if !ok || ifc.LocalFabricMember == "" {
		return ref
	}
	resolved := ifc.LocalFabricMember
	if len(parts) == 2 {
		return resolved + "." + parts[1]
	}
	return resolved
}

// Config is the top-level typed configuration, compiled from the AST.
type Config struct {
	Security          SecurityConfig
	Interfaces        InterfacesConfig
	Applications      ApplicationsConfig
	RoutingOptions    RoutingOptionsConfig
	Protocols         ProtocolsConfig
	RoutingInstances  []*RoutingInstanceConfig
	Firewall          FirewallConfig
	ClassOfService    *ClassOfServiceConfig
	Services          ServicesConfig
	ForwardingOptions ForwardingOptionsConfig
	System            SystemConfig
	PolicyOptions     PolicyOptionsConfig
	Schedulers        map[string]*SchedulerConfig
	Chassis           ChassisConfig
	EventOptions      []*EventPolicy
	BridgeDomains     []*BridgeDomainConfig
	Warnings          []string // non-fatal validation warnings
}

// ChassisConfig holds chassis-level configuration (clustering, etc).
type ChassisConfig struct {
	Cluster *ClusterConfig
}

// ClusterConfig defines chassis cluster settings for HA.
type ClusterConfig struct {
	ClusterID             int
	NodeID                int
	RethCount             int
	HeartbeatInterval     int    // milliseconds, 0=default(1000)
	HeartbeatThreshold    int    // missed heartbeats before lost, 0=default(3)
	ControlInterface      string // interface for heartbeat traffic (e.g. "hb0")
	PeerAddress           string // peer node's control link IP (e.g. "10.99.0.2")
	FabricInterface       string // interface for session/config sync (e.g. "fab0")
	FabricPeerAddress     string // peer's fabric link IP (e.g. "10.99.1.2")
	Fabric1Interface      string // secondary fabric interface (e.g. "fab1")
	Fabric1PeerAddress    string // peer's secondary fabric IP
	ConfigSync            bool   // enable config synchronization to peer on commit
	ControlLinkRecovery   bool   // enable control-link-recovery
	NATStateSync          bool   // enable NAT state synchronization (session sync with NAT fields)
	IPsecSASync           bool   // enable IPsec SA synchronization (connection name sync for failover re-initiation)
	RethAdvertiseInterval int    // RETH VRRP advertisement interval in milliseconds, 0=default(30)
	HitlessRestart        bool   // preserve BPF state on shutdown (default false in HA — fail-closed)
	PeerFencing           string // peer fencing action on heartbeat timeout: "", "disable-rg"
	TakeoverHoldTime      int    // milliseconds, 0=immediate takeover once ready
	NoRethVRRP            bool   // cluster directly manages VIPs (no VRRP for RETH interfaces)
	PrivateRGElection     bool   // election over control link only, suppress RETH VRRP
	RedundancyGroups      []*RedundancyGroup
}

// RedundancyGroup defines a cluster redundancy group.
type RedundancyGroup struct {
	ID                 int
	NodePriorities     map[int]int // node-id -> priority
	GratuitousARPCount int
	Preempt            bool
	StrictVIPOwnership bool
	InterfaceMonitors  []*InterfaceMonitor
	IPMonitoring       *IPMonitoring
}

// InterfaceMonitor defines an interface health monitor within a redundancy group.
type InterfaceMonitor struct {
	Interface string
	Weight    int
}

// IPMonitoring defines IP reachability monitoring for a redundancy group.
type IPMonitoring struct {
	GlobalWeight    int
	GlobalThreshold int
	Targets         []*IPMonitorTarget
}

// IPMonitorTarget defines a single IP address to probe for reachability.
type IPMonitorTarget struct {
	Address string
	Weight  int
}

// EventPolicy defines an event-driven policy (event-options).
type EventPolicy struct {
	Name            string
	Events          []string
	WithinClauses   []*EventWithin
	AttributesMatch []string // raw "field matches pattern" strings
	ThenCommands    []string // change-configuration commands
}

// EventWithin defines a temporal trigger clause.
type EventWithin struct {
	Seconds      int
	TriggerOn    int // trigger on N
	TriggerUntil int // trigger until N
}

// BridgeDomainConfig defines a bridge domain with VLAN membership and optional IRB interface.
type BridgeDomainConfig struct {
	Name             string // bridge domain name (e.g. "bd0")
	VlanIDs          []int  // member VLAN IDs
	RoutingInterface string // IRB routing interface reference (e.g. "irb.0")
	DomainType       string // bridge domain type (optional)
}

// IRBToBridge returns a mapping of IRB interface reference (e.g. "irb.0") to
// bridge device name (e.g. "br-bd0") for all bridge domains with a routing-interface.
func IRBToBridge(bds []*BridgeDomainConfig) map[string]string {
	m := make(map[string]string)
	for _, bd := range bds {
		if bd.RoutingInterface != "" {
			m[bd.RoutingInterface] = "br-" + bd.Name
		}
	}
	return m
}

// PolicyOptionsConfig holds prefix-lists, communities, as-paths, and policy-statements for routing control.
type PolicyOptionsConfig struct {
	PrefixLists      map[string]*PrefixList
	Communities      map[string]*CommunityDef
	ASPaths          map[string]*ASPathDef
	PolicyStatements map[string]*PolicyStatement
}

// ASPathDef defines a named AS-path regular expression for route matching.
type ASPathDef struct {
	Name  string
	Regex string // AS-path regex pattern (e.g. "65000", "65[0-9]+")
}

// CommunityDef defines a named BGP community with member values.
type CommunityDef struct {
	Name    string
	Members []string // e.g. "65000:100", "no-export", "no-advertise"
}

// PrefixList defines a named list of IP prefixes.
type PrefixList struct {
	Name     string
	Prefixes []string // CIDR entries ("10.0.0.0/8", "2001:db8::/32")
}

// PolicyStatement defines a routing policy with terms.
type PolicyStatement struct {
	Name          string
	Terms         []*PolicyTerm
	DefaultAction string // "accept", "reject", or "" (implicit reject)
}

// PolicyTerm is a single match+action clause within a policy-statement.
type PolicyTerm struct {
	Name            string
	FromProtocol    string         // "direct", "static", "bgp", "ospf"
	PrefixList      string         // from prefix-list <name>
	FromCommunity   string         // from community <name> (match against community-list)
	FromASPath      string         // from as-path <name> (match against as-path access-list)
	RouteFilters    []*RouteFilter // prefix matching
	Action          string         // "accept", "reject"
	NextHop         string         // then next-hop (e.g. "peer-address", "self", IP)
	LoadBalance     string         // then load-balance (e.g. "consistent-hash", "per-packet")
	LocalPreference int            // BGP local-preference (0 = not set)
	Metric          int            // BGP MED/metric (0 = not set)
	MetricType      int            // OSPF metric type (1 or 2, 0 = not set)
	Community       string         // BGP community to set (e.g. "65000:100")
	Origin          string         // BGP origin: "igp", "egp", "incomplete"
}

// RouteFilter matches a prefix with a match type.
type RouteFilter struct {
	Prefix    string // CIDR ("192.168.50.0/24")
	MatchType string // "exact", "longer", "orlonger", "upto"
	UptoLen   int    // for "upto" match type
}

// SchedulerConfig defines a time-based policy scheduler.
type SchedulerConfig struct {
	Name      string
	StartTime string // "HH:MM:SS"
	StopTime  string // "HH:MM:SS"
	StartDate string // "YYYY-MM-DD" (optional)
	StopDate  string // "YYYY-MM-DD" (optional)
	Daily     bool   // recur daily
}

// ClassOfServiceConfig holds CoS forwarding classes, schedulers,
// scheduler-maps, and per-interface shaping configuration.
type ClassOfServiceConfig struct {
	ForwardingClasses   map[string]*CoSForwardingClass
	DSCPClassifiers     map[string]*CoSDSCPClassifier
	IEEE8021Classifiers map[string]*CoSIEEE8021Classifier
	DSCPRewriteRules    map[string]*CoSDSCPRewriteRule
	Schedulers          map[string]*CoSScheduler
	SchedulerMaps       map[string]*CoSSchedulerMap
	Interfaces          map[string]*CoSInterface
}

// CoSForwardingClass maps a forwarding-class name to a queue number.
type CoSForwardingClass struct {
	Name  string
	Queue int
}

// CoSDSCPClassifier maps DSCP code points into forwarding classes.
type CoSDSCPClassifier struct {
	Name    string
	Entries []*CoSDSCPClassifierEntry
}

// CoSDSCPClassifierEntry assigns one or more DSCP values to a forwarding class.
type CoSDSCPClassifierEntry struct {
	ForwardingClass string
	LossPriority    string
	DSCPValues      []uint8
}

// CoSIEEE8021Classifier maps 802.1p PCP values into forwarding classes.
type CoSIEEE8021Classifier struct {
	Name    string
	Entries []*CoSIEEE8021ClassifierEntry
}

// CoSIEEE8021ClassifierEntry assigns one or more PCP values to a forwarding class.
type CoSIEEE8021ClassifierEntry struct {
	ForwardingClass string
	LossPriority    string
	CodePoints      []uint8
}

// CoSDSCPRewriteRule maps forwarding classes to egress DSCP rewrite values.
type CoSDSCPRewriteRule struct {
	Name    string
	Entries []*CoSDSCPRewriteRuleEntry
}

// CoSDSCPRewriteRuleEntry assigns a DSCP rewrite code point to a forwarding class.
type CoSDSCPRewriteRuleEntry struct {
	ForwardingClass string
	LossPriority    string
	DSCPValue       uint8
}

// CoSScheduler defines the Phase 1 class scheduler knobs.
type CoSScheduler struct {
	Name              string
	TransmitRateBytes uint64
	TransmitRateExact bool
	Priority          string
	BufferSizeBytes   uint64
	// SurplusSharing (#915) lifts the surplus-phase skip on
	// transmit-rate exact queues so they can draw from the root
	// shaper's surplus tokens once their own bucket is empty.
	// Only meaningful when TransmitRateExact == true; cleared
	// by ValidateConfig otherwise (warn-and-strip).
	SurplusSharing bool
}

// CoSSchedulerMap binds forwarding classes to named schedulers.
type CoSSchedulerMap struct {
	Name    string
	Entries map[string]*CoSSchedulerMapEntry
}

// CoSSchedulerMapEntry is a single forwarding-class -> scheduler binding.
type CoSSchedulerMapEntry struct {
	ForwardingClass string
	Scheduler       string
}

// CoSInterface holds unit-level CoS configuration for an interface.
type CoSInterface struct {
	Name  string
	Units map[int]*CoSInterfaceUnit
}

// CoSInterfaceUnit defines the Phase 1 root shaper attached to a logical unit.
type CoSInterfaceUnit struct {
	Unit               int
	ShapingRateBytes   uint64
	BurstSizeBytes     uint64
	SchedulerMap       string
	DSCPClassifier     string
	IEEE8021Classifier string
	DSCPRewriteRule    string
}

// SystemConfig holds system-level configuration.
type SystemConfig struct {
	HostName                 string
	DomainName               string   // system domain-name (e.g. "example.com")
	DomainSearch             []string // system domain-search (search domains)
	TimeZone                 string
	NameServers              []string // DNS server addresses
	NTPServers               []string // NTP server addresses
	NTPThreshold             int      // NTP threshold in seconds (0 = default)
	NTPThresholdAction       string   // "accept" or "reject"
	NoRedirects              bool     // disable ICMP redirects
	BackupRouter             string   // backup default gateway IP
	BackupRouterDst          string   // backup router destination prefix
	Lo0FilterInputV4         string   // lo0 unit 0 family inet filter input (host-bound filtering)
	Lo0FilterInputV6         string   // lo0 unit 0 family inet6 filter input (host-bound filtering)
	DataplaneType            string   // "ebpf" (default), "dpdk", or "userspace"
	DPDKDataplane            *DPDKConfig
	UserspaceDataplane       *UserspaceConfig
	InternetOptions          *InternetOptionsConfig
	Services                 *SystemServicesConfig
	Syslog                   *SystemSyslogConfig
	DHCPServer               DHCPServerConfig
	SNMP                     *SNMPConfig
	Login                    *LoginConfig
	RootAuthentication       *RootAuthConfig
	Archival                 *ArchivalConfig
	MasterPassword           string   // pseudorandom-function value
	LicenseAutoUpdate        string   // license autoupdate URL
	DisabledProcesses        []string // processes marked "disable"
	PersistGroupsInheritance bool     // system commit persist-groups-inheritance (syntax accepted, runtime no-op)
}

// DPDKConfig holds DPDK dataplane-specific configuration.
type DPDKConfig struct {
	Cores          string // EAL core list (e.g. "2-5")
	Memory         int    // Hugepages in MB
	SocketMem      string // Per-NUMA socket memory (e.g. "1024,1024")
	RXMode         string // "polling", "interrupt", "adaptive"
	AdaptiveConfig *DPDKAdaptiveConfig
	Ports          []DPDKPort
}

// DPDKAdaptiveConfig holds adaptive RX mode tuning parameters.
type DPDKAdaptiveConfig struct {
	IdleThreshold   int // Empty polls before sleep (default 256)
	ResumeThreshold int // Burst size to resume polling (default 32)
	SleepTimeout    int // Max sleep ms (default 100)
}

// DPDKPort maps a PCI address to a logical interface.
type DPDKPort struct {
	PCIAddress string // e.g. "0000:03:00.0"
	Interface  string // logical interface name (e.g. "wan0")
	RXMode     string // per-port RX mode override
	Cores      string // per-port core list override
}

// UserspaceConfig holds separate-process userspace dataplane configuration.
type UserspaceConfig struct {
	Binary        string `json:"binary"`                 // helper process path
	ControlSocket string `json:"control_socket"`         // unix control socket path
	EventSocket   string `json:"event_socket,omitempty"` // event stream socket path (auto-derived if empty)
	StateFile     string `json:"state_file"`             // helper state file path
	Workers       int    `json:"workers"`                // worker thread count
	RingEntries   int    `json:"ring_entries"`           // planned AF_XDP ring entries
	PollMode      string `json:"poll_mode"`              // "busy-poll" (default) or "interrupt"

	// RSSIndirectionDisabled, when true, disables D3 RSS indirection
	// reshaping (#785 / #797). Default is enabled — operators opt out
	// explicitly via `set system dataplane rss-indirection disable`.
	// Serialized as an inverted bool so omission implies the safe
	// default (enabled) and only disabled deploys carry the field.
	RSSIndirectionDisabled bool `json:"rss_indirection_disabled,omitempty"`

	// ClaimHostTunables is the #801 opt-in gate for host-scope knobs
	// that are NOT interface-scoped (CPU governor + netdev_budget + the
	// mlx5 adaptive-coalescence flip). D3's rss-indirection stays bound
	// to a specific NIC so it is safe to apply by default; the Step-0
	// knobs reach outside xpfd's interface allowlist and the operator
	// must explicitly opt in via
	// `set system dataplane claim-host-tunables true`. When false (the
	// default), xpfd never writes to cpufreq scaling_governor,
	// /proc/sys/net/core/netdev_budget, or mlx5 adaptive-rx/tx, even if
	// the derived default values are non-zero. Per-iface rx-usecs/tx-usecs
	// are still applied when coalescence is otherwise configured —
	// those are bound to the same mlx5 interface as D3.
	ClaimHostTunables bool `json:"claim_host_tunables,omitempty"`

	// Phase B Step-0 tunables (#801). Each is a first-class knob with
	// a documented default so operators can override without editing
	// systemd units or sysctl.conf. Omission leaves the zero value and
	// daemon resolves the default at apply-time (empty string / 0).

	// CPUGovernor requests a cpufreq governor on every writable
	// /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor node on the
	// host. Accepted values:
	//   "performance"          — explicit (default)
	//   "schedutil"            — explicit override
	//   "default" / ""         — skip (leave whatever the host has set)
	// Running inside a VM without a writable cpufreq sysfs is a no-op
	// (detected at apply-time); the daemon logs a single informational
	// line noting the skip. On bare metal the setting is applied on
	// daemon start and re-applied on every commit.
	CPUGovernor string `json:"cpu_governor,omitempty"`

	// NetdevBudget is the value written to /proc/sys/net/core/netdev_budget.
	// 0 means "leave the kernel default" (no write); the daemon
	// resolves a non-zero default at apply-time (600, per #801).
	NetdevBudget int `json:"netdev_budget,omitempty"`

	// CoalescenceAdaptiveDisabled, when true, disables mlx5 adaptive
	// coalescing on every userspace-dp-bound mlx5 interface
	// (`ethtool -C <iface> adaptive-rx off adaptive-tx off`). Default
	// is true (disable) at apply-time; the config knob is
	// `set system dataplane coalescence adaptive disable|enable`.
	// Serialized as an inverted bool so the most-common "disable"
	// deploy case is the zero value.
	//
	// CoalescenceAdaptiveExplicit distinguishes "operator explicitly
	// set enable" from "omitted, use default". Default is
	// "disabled" so an omitted knob leaves the field at
	// CoalescenceAdaptiveDisabled=false but the daemon still applies
	// "adaptive off". An explicit "enable" sets Explicit=true and
	// Disabled=false so the daemon skips the ethtool write (operator
	// override).
	CoalescenceAdaptiveDisabled bool `json:"coalescence_adaptive_disabled,omitempty"`
	CoalescenceAdaptiveExplicit bool `json:"coalescence_adaptive_explicit,omitempty"`

	// CoalescenceRXUsecs / CoalescenceTXUsecs set the rx-usecs and
	// tx-usecs coalescing ceiling on mlx5 interfaces. 0 means "use
	// daemon default" (8 µs per #801). Only written when adaptive
	// coalescing is disabled — with adaptive on, the kernel controls
	// these values dynamically and writes are a waste.
	CoalescenceRXUsecs int `json:"coalescence_rx_usecs,omitempty"`
	CoalescenceTXUsecs int `json:"coalescence_tx_usecs,omitempty"`
}

// RootAuthConfig holds root-authentication settings.
type RootAuthConfig struct {
	EncryptedPassword string
	SSHKeys           []string
}

// ArchivalConfig holds configuration archival settings.
type ArchivalConfig struct {
	TransferOnCommit bool
	TransferInterval int // minutes between auto-archives (0 = on commit only)
	ArchiveSites     []string
	ArchiveDir       string // local directory for archives (default /var/lib/xpf/archive)
	MaxArchives      int    // max number of archives to keep (default 10)

	// #651: archive site URLs for which an inline `password "$9$..."`
	// credential was configured. bpfrx's archival shells out to `scp`
	// with `-o BatchMode=yes` and cannot use inline passwords, so a
	// password here is ignored silently unless we warn. We keep the
	// URLs (not the passwords) so the warning can name the site.
	ArchiveSitesWithPassword []string
}

// InternetOptionsConfig holds internet-options settings.
type InternetOptionsConfig struct {
	NoIPv6RejectZeroHopLimit bool
}

// SystemServicesConfig holds system services (SSH, web-management).
type SystemServicesConfig struct {
	SSH                *SSHServiceConfig
	WebManagement      *WebManagementConfig
	DNSEnabled         bool // system services dns
	DNSProxyConfigured bool // system services dns dns-proxy (syntax accepted, runtime no-op)
}

// SSHServiceConfig holds SSH service settings.
type SSHServiceConfig struct {
	RootLogin string // "allow", "deny", "deny-password"
}

// WebManagementConfig holds web management settings.
type WebManagementConfig struct {
	HTTP                bool
	HTTPS               bool
	HTTPInterface       string         // interface binding for HTTP
	HTTPSInterface      string         // interface binding for HTTPS
	SystemGeneratedCert bool           // auto-generated TLS certificate
	APIAuth             *APIAuthConfig // REST API authentication
}

// APIAuthConfig holds REST API authentication settings.
type APIAuthConfig struct {
	Users   []*APIAuthUser // basic auth users
	APIKeys []string       // bearer/X-API-Key tokens
}

// APIAuthUser defines a basic auth user for the REST API.
type APIAuthUser struct {
	Username string
	Password string
}

// SystemSyslogConfig holds traditional Junos system syslog config.
type SystemSyslogConfig struct {
	Hosts []*SyslogHostConfig
	Files []*SyslogFileConfig
	Users []*SyslogUserConfig // user destinations (e.g. "user * { any emergency; }")
}

// SyslogUserConfig defines a syslog user destination.
type SyslogUserConfig struct {
	User     string // "*" = all users
	Facility string
	Severity string
}

// SyslogHostConfig defines a syslog host destination.
type SyslogHostConfig struct {
	Address         string
	Facilities      []SyslogFacility // multiple facility/severity pairs
	AllowDuplicates bool
}

// SyslogFacility represents a facility/severity pair in syslog config.
type SyslogFacility struct {
	Facility string // "daemon", "change-log", "any", etc.
	Severity string // "info", "warning", "error", "emergency", "any"
}

// SyslogFileConfig defines a syslog file destination.
type SyslogFileConfig struct {
	Name     string
	Facility string
	Severity string
}

// SNMPConfig holds SNMP agent configuration.
type SNMPConfig struct {
	Location    string
	Contact     string
	Description string
	Communities map[string]*SNMPCommunity
	TrapGroups  map[string]*SNMPTrapGroup
	V3Users     map[string]*SNMPv3User
}

// SNMPCommunity defines an SNMP community string.
type SNMPCommunity struct {
	Name          string
	Authorization string // "read-only" or "read-write"
}

// SNMPTrapGroup defines an SNMP trap destination group.
type SNMPTrapGroup struct {
	Name    string
	Targets []string // IP addresses
}

// SNMPv3User defines an SNMPv3 USM user with authentication and privacy.
type SNMPv3User struct {
	Name         string
	AuthProtocol string // "md5", "sha", "sha256"
	AuthPassword string
	PrivProtocol string // "des", "aes128"
	PrivPassword string
}

// LoginClassPermission defines what a login class can do.
type LoginClassPermission int

const (
	PermView    LoginClassPermission = iota // show commands
	PermClear                               // clear commands
	PermControl                             // restart/request commands
	PermConfig                              // configure mode
	PermAll                                 // super-user: everything
)

// LoginClassPermissions maps class names to their allowed permissions.
var LoginClassPermissions = map[string][]LoginClassPermission{
	"super-user":   {PermAll},
	"operator":     {PermView, PermClear, PermControl},
	"read-only":    {PermView},
	"unauthorized": {},
}

// LoginConfig holds user account definitions.
type LoginConfig struct {
	Users []*LoginUser
}

// LoginUser defines a system user account.
type LoginUser struct {
	Name    string
	UID     int
	Class   string   // "super-user", "read-only", etc.
	SSHKeys []string // authorized SSH public keys
}

// ServicesConfig holds service configuration (flow-monitoring, RPM, etc.).
type ServicesConfig struct {
	FlowMonitoring            *FlowMonitoringConfig
	RPM                       *RPMConfig
	ApplicationIdentification bool // DPI-based application detection
}

// RPMConfig holds RPM (Real-time Performance Monitoring) configuration.
type RPMConfig struct {
	Probes map[string]*RPMProbe
}

// RPMProbe defines a single RPM probe for health monitoring.
type RPMProbe struct {
	Name  string
	Tests map[string]*RPMTest
}

const (
	DefaultRPMProbeType            = "icmp-ping"
	DefaultRPMProbeIntervalSeconds = 5
	DefaultRPMProbeCount           = 1
	DefaultRPMTestIntervalSeconds  = 60
	DefaultRPMSuccessiveLosses     = 3
	DefaultRPMTCPDestinationPort   = 80
)

// RPMTest defines a test within an RPM probe.
type RPMTest struct {
	Name                string
	ProbeType           string // "http-get", "icmp-ping", "tcp-ping"
	Target              string // target IP or hostname
	SourceAddress       string
	RoutingInstance     string
	ProbeInterval       int // seconds (0 = default 5)
	ProbeCount          int // number of probes per test (0 = default 1)
	TestInterval        int // seconds (0 = default 60)
	ThresholdSuccessive int // successive failures before probe-fail (0 = default 3)
	ProbeLimit          int // max consecutive failed probes before stopping the current test cycle (0 = unlimited)
	DestPort            int // for tcp-ping
}

func (t *RPMTest) EffectiveProbeType() string {
	if t == nil || t.ProbeType == "" {
		return DefaultRPMProbeType
	}
	return t.ProbeType
}

func (t *RPMTest) EffectiveProbeInterval() int {
	if t == nil || t.ProbeInterval <= 0 {
		return DefaultRPMProbeIntervalSeconds
	}
	return t.ProbeInterval
}

func (t *RPMTest) EffectiveProbeCount() int {
	if t == nil || t.ProbeCount <= 0 {
		return DefaultRPMProbeCount
	}
	return t.ProbeCount
}

func (t *RPMTest) EffectiveTestInterval() int {
	if t == nil || t.TestInterval <= 0 {
		return DefaultRPMTestIntervalSeconds
	}
	return t.TestInterval
}

func (t *RPMTest) EffectiveSuccessiveLossThreshold() int {
	if t == nil || t.ThresholdSuccessive <= 0 {
		return DefaultRPMSuccessiveLosses
	}
	return t.ThresholdSuccessive
}

func (t *RPMTest) EffectiveDestinationPort() int {
	if t == nil || t.DestPort <= 0 {
		return DefaultRPMTCPDestinationPort
	}
	return t.DestPort
}

// FlowMonitoringConfig holds flow monitoring configuration.
type FlowMonitoringConfig struct {
	Version9     *NetFlowV9Config
	VersionIPFIX *NetFlowIPFIXConfig
}

// NetFlowIPFIXConfig holds IPFIX (NetFlow v10) template definitions.
type NetFlowIPFIXConfig struct {
	Templates map[string]*NetFlowIPFIXTemplate
}

// NetFlowIPFIXTemplate defines an IPFIX export template.
type NetFlowIPFIXTemplate struct {
	Name                string
	FlowActiveTimeout   int      // seconds
	FlowInactiveTimeout int      // seconds
	TemplateRefreshRate int      // seconds
	ExportExtensions    []string // e.g. "app-id", "flow-dir"
}

// NetFlowV9Config holds NetFlow v9 template definitions.
type NetFlowV9Config struct {
	Templates map[string]*NetFlowV9Template
}

// NetFlowV9Template defines a NetFlow v9 export template.
type NetFlowV9Template struct {
	Name                string
	FlowActiveTimeout   int      // seconds (0 = default 60)
	FlowInactiveTimeout int      // seconds (0 = default 15)
	TemplateRefreshRate int      // seconds (0 = default 60)
	ExportExtensions    []string // e.g. "app-id", "flow-dir"
}

// ForwardingOptionsConfig holds forwarding/sampling configuration.
type ForwardingOptionsConfig struct {
	Sampling        *SamplingConfig
	DHCPRelay       *DHCPRelayConfig
	FamilyInet6Mode string // "flow-based" or "packet-based" (default "flow-based")
	PortMirroring   *PortMirroringConfig
}

// PortMirroringConfig holds port mirroring (SPAN) configuration.
type PortMirroringConfig struct {
	Instances map[string]*PortMirrorInstance
}

// PortMirrorInstance defines a named port mirroring instance.
type PortMirrorInstance struct {
	Name      string
	InputRate int      // 1-in-N sampling rate (0 = mirror all)
	Input     []string // ingress interfaces to mirror
	Output    string   // egress mirror destination interface
}

// DHCPRelayConfig holds DHCP relay agent configuration.
type DHCPRelayConfig struct {
	ServerGroups map[string]*DHCPRelayServerGroup
	Groups       map[string]*DHCPRelayGroup
}

// DHCPRelayServerGroup defines a group of DHCP servers.
type DHCPRelayServerGroup struct {
	Name    string
	Servers []string // server IPs
}

// DHCPRelayGroup defines a DHCP relay group bound to interfaces.
type DHCPRelayGroup struct {
	Name              string
	Interfaces        []string
	ActiveServerGroup string // reference to server group name
}

// SamplingConfig holds sampling instance definitions.
type SamplingConfig struct {
	Instances map[string]*SamplingInstance
}

// SamplingInstance defines a traffic sampling instance.
type SamplingInstance struct {
	Name        string
	InputRate   int // 1-in-N sampling rate (0 = sample all)
	FamilyInet  *SamplingFamily
	FamilyInet6 *SamplingFamily
}

// SamplingFamily holds per-AF sampling output configuration.
type SamplingFamily struct {
	FlowServers              []*FlowServer
	SourceAddress            string
	InlineJflow              bool
	InlineJflowSourceAddress string // inline-jflow { source-address; }
}

// FlowServer defines a flow export collector destination.
type FlowServer struct {
	Address          string
	Port             int
	Version9Template string
}

// FirewallConfig holds firewall filter definitions.
type FirewallConfig struct {
	FiltersInet        map[string]*FirewallFilter          // family inet filters
	FiltersInet6       map[string]*FirewallFilter          // family inet6 filters
	Policers           map[string]*PolicerConfig           // named policer definitions
	ThreeColorPolicers map[string]*ThreeColorPolicerConfig // named three-color policers
}

// PolicerConfig defines a single-rate two-color policer (token bucket).
type PolicerConfig struct {
	Name                    string
	BandwidthLimit          uint64 // bytes per second (converted from Junos bits/sec)
	BurstSizeLimit          uint64 // burst bucket size in bytes
	ThenAction              string // "discard" or "loss-priority high/medium-high/medium-low/low"
	LogicalInterfacePolicer bool   // shared across protocol families on the interface
}

// ThreeColorPolicerConfig defines a three-color policer (RFC 2697/2698).
type ThreeColorPolicerConfig struct {
	Name       string
	TwoRate    bool   // true=two-rate (RFC 2698), false=single-rate (RFC 2697)
	ColorBlind bool   // color-blind mode (default: color-aware)
	CIR        uint64 // committed information rate (bytes/sec)
	CBS        uint64 // committed burst size (bytes)
	PIR        uint64 // peak information rate (bytes/sec, two-rate only)
	PBS        uint64 // peak/excess burst size (bytes)
	ThenAction string // action on exceed/violate: "discard" or "loss-priority"
}

// FirewallFilter defines a named firewall filter with ordered terms.
type FirewallFilter struct {
	Name  string
	Terms []*FirewallFilterTerm
}

// FirewallFilterTerm is a single match/action term within a filter.
type FirewallFilterTerm struct {
	Name              string
	SourceAddresses   []string        // CIDRs
	DestAddresses     []string        // CIDRs
	SourcePrefixLists []PrefixListRef // source-prefix-list references
	DestPrefixLists   []PrefixListRef // destination-prefix-list references
	DSCP              string          // DSCP/traffic-class name (ef, af43, etc.) or number
	Protocol          string          // tcp, udp, icmp, icmpv6
	DestinationPorts  []string        // port numbers or names
	SourcePorts       []string        // source port numbers or ranges
	ICMPType          int             // -1 = not set
	ICMPCode          int             // -1 = not set
	TCPFlags          []string        // TCP flags: "syn", "ack", "fin", "rst", "psh", "urg"
	IsFragment        bool            // match IP fragments
	Action            string          // "accept", "reject", "discard", ""
	RoutingInstance   string          // routing-instance name (policy-based routing)
	Log               bool
	Count             string           // counter name
	ForwardingClass   string           // forwarding-class name
	LossPriority      string           // loss-priority (low, medium-low, medium-high, high)
	DSCPRewrite       string           // then dscp <value> — rewrite DSCP/traffic-class
	Policer           string           // then policer <name> — reference to policer definition
	FlexMatch         *FlexMatchConfig // flexible-match-range configuration
}

// FlexMatchConfig defines a flexible byte-offset match condition.
type FlexMatchConfig struct {
	MatchStart string // "layer-3" (only supported start point)
	ByteOffset uint8  // byte offset from match start
	BitLength  uint8  // match length in bits (8, 16, 32)
	Value      uint32 // expected value (after mask)
	Mask       uint32 // mask to apply before comparison
}

// PrefixListRef references a named prefix-list with optional "except" modifier.
type PrefixListRef struct {
	Name   string
	Except bool
}

// DHCPServerConfig holds DHCP server configuration.
type DHCPServerConfig struct {
	DHCPLocalServer   *DHCPLocalServerConfig
	DHCPv6LocalServer *DHCPLocalServerConfig
}

// DHCPLocalServerConfig holds per-group DHCP server settings.
type DHCPLocalServerConfig struct {
	Groups map[string]*DHCPServerGroup
}

// DHCPServerGroup defines a DHCP server group.
type DHCPServerGroup struct {
	Name       string
	Interfaces []string
	Pools      []*DHCPPool
}

// DHCPPool defines an address pool for DHCP leases.
type DHCPPool struct {
	Name       string
	RangeLow   string
	RangeHigh  string
	Subnet     string // pool network (e.g. "10.0.1.0/24")
	Router     string
	DNSServers []string
	LeaseTime  int // seconds (0 = default 86400)
	Domain     string
}

// DynamicAddressConfig defines dynamic address feed servers and address-name bindings.
type DynamicAddressConfig struct {
	FeedServers     map[string]*FeedServer
	AddressBindings map[string]*AddressBinding // keyed by address-name
}

// FeedServer defines a remote address feed source with optional per-feed paths.
type FeedServer struct {
	Name           string
	URL            string      // explicit url (takes precedence)
	Hostname       string      // hostname for building URLs with per-feed paths
	UpdateInterval int         // seconds (0 = default 3600)
	HoldInterval   int         // seconds (0 = default 7200)
	FeedName       string      // single feed-name (backward compat, no path)
	FeedEntries    []FeedEntry // named feeds with per-feed paths
}

// FeedEntry is a named feed within a feed-server, with an optional path.
type FeedEntry struct {
	Name string
	Path string
}

// AddressBinding binds an address-name to one or more feed-names via a profile.
type AddressBinding struct {
	Name      string
	FeedNames []string // feed-names referenced in the profile
}

// SecurityConfig holds all security-related configuration.
type SecurityConfig struct {
	Zones              map[string]*ZoneConfig // keyed by zone name
	Policies           []*ZonePairPolicies    // ordered list of zone-pair policy sets
	GlobalPolicies     []*Policy              // global policies (apply to all zone pairs)
	DefaultPolicy      PolicyAction           // global fallback policy (permit-all or deny-all)
	NAT                NATConfig
	Screen             map[string]*ScreenProfile // keyed by profile name
	AddressBook        *AddressBook
	Log                LogConfig
	Flow               FlowConfig
	ALG                ALGConfig
	IPsec              IPsecConfig
	DynamicAddress     DynamicAddressConfig
	SSHKnownHosts      map[string][]SSHKnownHostKey // host -> keys
	PolicyStatsEnabled bool                         // policy-stats system-wide enable
	PreIDDefaultPolicy *PreIDDefaultPolicy          // pre-id-default-policy
}

// FlowConfig holds flow/session timeout configuration.
type FlowConfig struct {
	TCPSession                 *TCPSessionConfig
	UDPSessionTimeout          int // seconds, 0 = default (60s)
	ICMPSessionTimeout         int // seconds, 0 = default (30s)
	TCPMSSIPsecVPN             int // TCP MSS clamp for IPsec VPN traffic (0 = disabled)
	TCPMSSGreIn                int // TCP MSS clamp for GRE ingress traffic (0 = disabled)
	TCPMSSGreOut               int // TCP MSS clamp for GRE egress traffic (0 = disabled)
	AllowDNSReply              bool
	AllowEmbeddedICMP          bool
	GREPerformanceAcceleration bool
	PowerModeDisable           bool
	SynFloodProtectionMode     string // "syn-cookie" or "" (default = drop)
	Traceoptions               *FlowTraceoptions
	AgingEarlyAgeout           int // seconds (0 = disabled)
	AgingHighWatermark         int // percent of max sessions (0 = disabled)
	AgingLowWatermark          int // percent of max sessions (0 = disabled)
}

// FlowTraceoptions holds flow trace debugging configuration.
type FlowTraceoptions struct {
	File          string   // log file name
	FileSize      int      // max file size in bytes
	FileCount     int      // number of rotated files
	Flags         []string // trace flags (e.g. "basic-datapath", "session")
	PacketFilters []*TracePacketFilter
}

// TracePacketFilter defines a packet filter for flow tracing.
type TracePacketFilter struct {
	Name              string
	SourcePrefix      string
	DestinationPrefix string
}

// ALGConfig holds ALG (Application Layer Gateway) disable flags.
type ALGConfig struct {
	DNSDisable  bool
	FTPDisable  bool
	SIPDisable  bool
	TFTPDisable bool
}

// TCPSessionConfig holds TCP session timeout configuration.
type TCPSessionConfig struct {
	EstablishedTimeout   int  // default 1800
	InitialTimeout       int  // default 30
	ClosingTimeout       int  // default 30
	TimeWaitTimeout      int  // default 120
	NoSynCheck           bool // allow mid-stream TCP session creation
	NoSynCheckInTunnel   bool // allow mid-stream TCP for tunnel traffic only
	RstInvalidateSession bool // immediately expire session on RST
}

// LogConfig holds logging/syslog configuration.
type LogConfig struct {
	Mode            string // "stream" or "event"
	Format          string // "sd-syslog", "syslog", "binary", "structured"
	SourceInterface string // interface for source address
	Streams         map[string]*SyslogStream
	Report          bool // enable session aggregation reporting (security log report)
}

// SyslogTransport defines the transport protocol for a syslog stream.
type SyslogTransport struct {
	Protocol   string // "udp" (default), "tcp", "tls"
	TLSProfile string // TLS profile name (for protocol=tls)
}

// SyslogStream defines a syslog forwarding destination.
type SyslogStream struct {
	Name          string
	Host          string
	Port          int    // default 514
	Severity      string // "error", "warning", "info", or "" (no filter)
	Facility      string // "local0".."local7", "user", "daemon", or "" (default: local0)
	Format        string // per-stream format override
	Category      string // "all", or specific category
	SourceAddress string // source IP for this stream
	Transport     SyslogTransport
}

// SSHKnownHostKey represents a known SSH host key.
type SSHKnownHostKey struct {
	Type string // "ecdsa-sha2-nistp256-key", "ssh-rsa-key", etc.
	Key  string
}

// PreIDDefaultPolicy defines a pre-identification default policy.
type PreIDDefaultPolicy struct {
	LogSessionInit  bool
	LogSessionClose bool
}

// ZoneConfig represents a security zone.
type ZoneConfig struct {
	Name               string
	Description        string
	Interfaces         []string
	ScreenProfile      string // reference to screen profile name
	HostInboundTraffic *HostInboundTraffic
	TCPRst             bool // send TCP RST for non-SYN packets to closed ports
}

// HostInboundTraffic defines what services are permitted to the firewall itself.
type HostInboundTraffic struct {
	SystemServices []string // ssh, ping, dns, etc.
	Protocols      []string // ospf, bgp, etc.
}

// ZonePairPolicies contains ordered policies for a from-zone/to-zone pair.
type ZonePairPolicies struct {
	FromZone string
	ToZone   string
	Policies []*Policy
}

// Policy is a single security policy rule.
type Policy struct {
	Name          string
	Description   string
	Match         PolicyMatch
	Action        PolicyAction
	Log           *PolicyLog
	Count         bool
	SchedulerName string // reference to SchedulerConfig name
}

// PolicyMatch defines what traffic a policy matches.
type PolicyMatch struct {
	SourceAddresses      []string // address-book names or "any"
	DestinationAddresses []string
	Applications         []string // application names or "any"
}

// PolicyAction is the action to take when a policy matches.
type PolicyAction int

const (
	PolicyPermit PolicyAction = iota
	PolicyDeny
	PolicyReject
)

// PolicyLog configures session logging for a policy.
type PolicyLog struct {
	SessionInit  bool
	SessionClose bool
}

// NATConfig holds NAT configuration.
type NATConfig struct {
	Source               []*NATRuleSet
	SourcePools          map[string]*NATPool // named source NAT pools
	AddressPersistent    bool                // source { address-persistent; }
	Destination          *DestinationNATConfig
	Static               []*StaticNATRuleSet
	NAT64                []*NAT64RuleSet
	NATv6v4              *NATv6v4Config // natv6v4 options
	PoolUtilizationAlarm *PoolUtilizationAlarmConfig
	ProxyARP             []*ProxyARPEntry
}

// ProxyARPEntry configures proxy ARP responses for NAT addresses.
type ProxyARPEntry struct {
	Interface string
	Addresses []string // /32 CIDRs (expanded from ranges)
}

// PoolUtilizationAlarmConfig configures NAT pool utilization alarms.
type PoolUtilizationAlarmConfig struct {
	RaiseThreshold int
	ClearThreshold int
}

// NATv6v4Config holds NAT64 v6-to-v4 translation options.
type NATv6v4Config struct {
	NoV6FragHeader bool // no-v6-frag-header: omit IPv6 fragment header in translated packets
}

// NAT64RuleSet defines NAT64 translation rules.
type NAT64RuleSet struct {
	Name       string
	Prefix     string // well-known prefix, e.g. "64:ff9b::/96"
	SourcePool string // IPv4 source pool name for translated packets
}

// StaticNATRuleSet is a set of static 1:1 NAT rules bound to a zone.
type StaticNATRuleSet struct {
	Name     string
	FromZone string
	Rules    []*StaticNATRule
}

// DestinationNATConfig holds destination NAT pools and rule sets.
type DestinationNATConfig struct {
	Pools    map[string]*NATPool
	RuleSets []*NATRuleSet
}

// NATRuleSet is a set of NAT rules bound to a zone pair.
type NATRuleSet struct {
	Name     string
	FromZone string
	ToZone   string
	Rules    []*NATRule
}

// NATRule is a single NAT rule.
type NATRule struct {
	Name  string
	Match NATMatch
	Then  NATThen
}

// NATMatch defines what traffic a NAT rule matches.
type NATMatch struct {
	SourceAddress        string   // CIDR (first address, for backward compat)
	SourceAddresses      []string // all matched source CIDRs (bracket list support)
	SourceAddressName    string   // address-book name (resolved during compilation)
	DestinationAddress   string   // CIDR (first address, for backward compat)
	DestinationAddresses []string // all matched destination CIDRs (bracket list support)
	DestinationPort      int      // primary port (first port for BPF rule)
	DestinationPorts     []int    // all matched ports (for multi-port DNAT rules)
	Protocol             string   // "tcp", "udp", "icmp6", "gre", or "" (auto)
	Application          string   // application name (e.g. "junos-http")
}

// NATThen defines the NAT translation action.
type NATThen struct {
	Type      NATType
	Interface bool   // source-nat interface mode
	PoolName  string // pool reference
	Off       bool   // source-nat off (no-NAT exemption)
}

// NATType is the type of NAT.
type NATType int

const (
	NATSource NATType = iota
	NATDestination
	NATStatic
)

// NATPool is a pool of addresses for NAT.
type NATPool struct {
	Name          string
	Address       string   // single address (DNAT compat)
	Addresses     []string // multiple addresses (source NAT pools)
	Port          int      // optional port mapping (DNAT)
	PortLow       int      // source pool port range low (default 1024)
	PortHigh      int      // source pool port range high (default 65535)
	PersistentNAT *PersistentNATConfig
	Deterministic *DeterministicNATConfig
}

// PersistentNATConfig configures persistent NAT bindings for a pool.
type PersistentNATConfig struct {
	PermitAnyRemoteHost bool
	InactivityTimeout   int // seconds (default 300)
}

// DeterministicNATConfig configures CGNAT deterministic port allocation.
type DeterministicNATConfig struct {
	BlockSize   int    // port block size per subscriber (e.g. 2016)
	HostAddress string // subscriber CIDR (e.g. "100.64.0.0/22")
}

// StaticNATRule is a 1:1 bidirectional NAT rule.
type StaticNATRule struct {
	Name          string
	Match         string // destination-address (external/public IP)
	SourceAddress string // source-address match (optional, e.g. "::/0" for NAT64)
	Then          string // static-nat prefix (internal/private IP), or "inet" for NAT64
	IsNPTv6       bool   // true if this is an nptv6-prefix rule (RFC 6296)
}

// LimitSessionScreen configures per-IP session limiting.
type LimitSessionScreen struct {
	SourceIPBased      int // max sessions per source IP, 0 = disabled
	DestinationIPBased int // max sessions per destination IP, 0 = disabled
}

// ScreenProfile defines IDS screening options.
type ScreenProfile struct {
	Name         string
	ICMP         ICMPScreen
	IP           IPScreen
	TCP          TCPScreen
	UDP          UDPScreen
	LimitSession LimitSessionScreen
}

// ICMPScreen configures ICMP screening.
type ICMPScreen struct {
	PingDeath      bool
	FloodThreshold int
}

// IPScreen configures IP screening.
type IPScreen struct {
	SourceRouteOption bool
	TearDrop          bool
	IPSweepThreshold  int // unique destination IPs per source (0 = disabled)
}

// TCPScreen configures TCP screening.
type TCPScreen struct {
	SynFlood          *SynFloodConfig
	Land              bool
	WinNuke           bool
	SynFrag           bool
	SynFin            bool
	NoFlag            bool
	FinNoAck          bool
	PortScanThreshold int // TCP SYN count per source IP (0 = disabled)
}

// UDPScreen configures UDP screening.
type UDPScreen struct {
	FloodThreshold int
}

// SynFloodConfig configures SYN flood protection thresholds.
type SynFloodConfig struct {
	AlarmThreshold       int
	AttackThreshold      int
	SourceThreshold      int
	DestinationThreshold int
	Timeout              int
}

// AddressBook holds named addresses and address sets.
type AddressBook struct {
	Addresses   map[string]*Address
	AddressSets map[string]*AddressSet
}

// Address is a named address entry (IP prefix).
type Address struct {
	Name  string
	Value string // CIDR notation
}

// AddressSet is a named group of addresses and/or nested address-sets.
type AddressSet struct {
	Name        string
	Addresses   []string // references to Address names
	AddressSets []string // references to other AddressSet names (nested)
}

// InterfacesConfig holds interface configuration.
type InterfacesConfig struct {
	Interfaces map[string]*InterfaceConfig
}

// InterfaceConfig represents a network interface.
type InterfaceConfig struct {
	Name                string
	Description         string                  // free-text interface description
	MTU                 int                     // interface-level MTU (overridden by unit MTU)
	Speed               string                  // interface speed (e.g. "1g", "10g", "auto")
	Duplex              string                  // "full", "half", "auto"
	VlanTagging         bool                    // 802.1Q trunk mode
	FlexibleVlanTagging bool                    // flexible 802.1Q VLAN tagging (QinQ)
	Encapsulation       string                  // physical link-layer encapsulation (e.g. "flexible-ethernet-services")
	Bandwidth           uint64                  // interface bandwidth in bits per second
	Disable             bool                    // administratively disabled
	RedundantParent     string                  // gigether-options redundant-parent (HA)
	LAGParent           string                  // gigether-options 802.3ad <ae-name> (LAG member binding)
	RedundancyGroup     int                     // redundant-ether-options redundancy-group (0 = none)
	FabricMembers       []string                // fabric-options member-interfaces
	LocalFabricMember   string                  // resolved local member for this node (vSRX fabric-options mode)
	BondMode            string                  // bond mode: "active-backup" for fabric, "802.3ad" for ae
	AggregatedEtherOpts *AggregatedEtherOptions // ae interface options (LACP, etc.)
	Units               map[int]*InterfaceUnit
	Tunnel              *TunnelConfig // non-nil for tunnel interfaces (gre0, etc.)
}

// AggregatedEtherOptions defines LAG/ae interface parameters.
type AggregatedEtherOptions struct {
	LACPActive   bool   // LACP active mode
	LACPPassive  bool   // LACP passive mode
	LACPPeriodic string // LACP periodic timer: "fast" or "slow"
	LinkSpeed    string // required member link speed (e.g. "1g", "10g")
	MinimumLinks int    // minimum active member links before bundle goes down
}

// InterfaceUnit represents a logical unit on an interface.
type InterfaceUnit struct {
	Number           int
	Description      string           // free-text unit description
	VlanID           int              // 0 = native/untagged, >0 = 802.1Q tagged
	InnerVlanID      int              // inner VLAN tag for QinQ (flexible-vlan-tagging)
	PointToPoint     bool             // point-to-point link (for tunnels)
	Addresses        []string         // CIDR notation
	PrimaryAddress   string           // address marked as primary
	PreferredAddress string           // address marked as preferred
	MTU              int              // family-level MTU (0 = default)
	DHCP             bool             // family inet { dhcp; }
	DHCPOptions      *DHCPInetOptions // dhcp sub-options (lease-time, etc.)
	DHCPv6           bool             // family inet6 { dhcpv6; }
	DHCPv6Client     *DHCPv6ClientConfig
	DADDisable       bool                  // family inet6 { dad-disable; }
	SamplingInput    bool                  // family inet/inet6 { sampling { input; } }
	SamplingOutput   bool                  // family inet/inet6 { sampling { output; } }
	FilterInputV4    string                // family inet { filter { input NAME; } }
	FilterOutputV4   string                // family inet { filter { output NAME; } }
	FilterInputV6    string                // family inet6 { filter { input NAME; } }
	FilterOutputV6   string                // family inet6 { filter { output NAME; } }
	VRRPGroups       map[string]*VRRPGroup // keyed by address (CIDR), each address can have VRRP groups
	Tunnel           *TunnelConfig         // per-unit tunnel config (for multi-unit GRE/IPIP)
}

// VRRPGroup defines a VRRP (Virtual Router Redundancy Protocol) group.
type VRRPGroup struct {
	ID                 int
	VirtualAddresses   []string // virtual IP addresses
	Priority           int      // 1-255, default 100
	Preempt            bool
	AcceptData         bool
	AdvertiseInterval  int    // seconds, default 1
	AuthType           string // "md5" or ""
	AuthKey            string
	TrackInterface     string // lower priority if interface is down
	TrackPriorityDelta int    // how much to lower priority
}

// DHCPv6ClientConfig holds DHCPv6 client options (dhcpv6-client stanza).
type DHCPv6ClientConfig struct {
	DUIDType                   string   // "duid-ll" or "duid-llt"
	ClientType                 string   // "stateful" or "stateless"
	ClientIATypes              []string // "ia-pd", "ia-na"
	PrefixDelegatingPrefixLen  int      // preferred-prefix-length (0 = not set)
	PrefixDelegatingSubPrefLen int      // sub-prefix-length (0 = not set)
	ReqOptions                 []string // dns-server, domain-name, etc.
	UpdateRAInterface          string   // update-router-advertisement interface
}

// DHCPInetOptions holds DHCPv4 client options for family inet dhcp stanza.
type DHCPInetOptions struct {
	LeaseTime              int  // seconds (0 = default)
	RetransmissionAttempt  int  // number of retransmission attempts
	RetransmissionInterval int  // seconds between retransmissions
	ForceDiscover          bool // always start with DISCOVER
}

// ApplicationsConfig holds application definitions.
type ApplicationsConfig struct {
	Applications    map[string]*Application
	ApplicationSets map[string]*ApplicationSet
}

// ApplicationSet groups multiple applications or nested application-sets.
type ApplicationSet struct {
	Name         string
	Applications []string // references to Application or ApplicationSet names
}

// Application defines a network application by protocol and port.
type Application struct {
	Name              string
	Protocol          string // tcp, udp, icmp, or numeric ("47")
	DestinationPort   string // "80", "8080-8090"
	SourcePort        string // "1024-65535" (optional)
	InactivityTimeout int    // seconds (0 = default)
	ALG               string // "ssh", "ftp", etc. (informational)
	Description       string
}

// RoutingOptionsConfig holds static routing configuration.
type RoutingOptionsConfig struct {
	StaticRoutes              []*StaticRoute
	Inet6StaticRoutes         []*StaticRoute // rib inet6.0 static routes
	GenerateRoutes            []*GenerateRoute
	ForwardingTableExport     string // forwarding-table { export <policy>; }
	AutonomousSystem          uint32 // autonomous-system <number>
	RibGroups                 map[string]*RibGroup
	InterfaceRoutesRibGroup   string // global interface-routes { rib-group inet <name>; }
	InterfaceRoutesRibGroupV6 string // global interface-routes { rib-group inet6 <name>; }
}

// GenerateRoute defines a Junos generate (aggregate) route.
// In FRR, these become blackhole/reject static routes or BGP aggregate-address.
type GenerateRoute struct {
	Prefix  string // route prefix (e.g. "192.168.0.0/16")
	Policy  string // contributing route policy (optional)
	Discard bool   // discard traffic to this route (blackhole)
}

// RibGroup defines a RIB group for route sharing between routing instances.
type RibGroup struct {
	Name       string
	ImportRibs []string // import-rib [ rib1 rib2 ... ]
}

// NextHopEntry defines a single next-hop for a static route.
type NextHopEntry struct {
	Address   string // IP address (e.g. "10.0.1.1" or "fe80::1")
	Interface string // outgoing interface (for IPv6 link-local)
}

// StaticRoute defines a single static route.
type StaticRoute struct {
	Destination string         // CIDR: "10.0.0.0/8" or "::/0"
	NextHops    []NextHopEntry // multiple next-hops = ECMP
	Discard     bool           // null route (blackhole)
	Preference  int            // route preference (admin distance), default 5
	NextTable   string         // routing instance name for inter-VRF route leaking (e.g. "Comcast.inet.0" → "Comcast")
}

// ProtocolsConfig holds dynamic routing protocol configuration.
type ProtocolsConfig struct {
	OSPF                *OSPFConfig
	OSPFv3              *OSPFv3Config
	BGP                 *BGPConfig
	RIP                 *RIPConfig
	ISIS                *ISISConfig
	RouterAdvertisement []*RAInterfaceConfig
	LLDP                *LLDPConfig
}

// LLDPConfig holds LLDP (Link Layer Discovery Protocol) configuration.
type LLDPConfig struct {
	Interfaces     []LLDPInterface // interfaces to enable LLDP on
	Interval       int             // transmit interval in seconds (0 = default 30)
	HoldMultiplier int             // hold multiplier (0 = default 4)
	Disable        bool            // globally disable LLDP
}

// LLDPInterface holds per-interface LLDP configuration.
type LLDPInterface struct {
	Name    string
	Disable bool // per-interface disable
}

// OSPFv3Config holds OSPFv3 (IPv6 OSPF) routing configuration.
type OSPFv3Config struct {
	RouterID string
	Areas    []*OSPFv3Area
	Export   []string
}

// OSPFv3Area defines an OSPFv3 area.
type OSPFv3Area struct {
	ID         string // "0.0.0.0" (backbone) or area number
	Interfaces []*OSPFv3Interface
}

// OSPFv3Interface defines an interface participating in OSPFv3.
type OSPFv3Interface struct {
	Name    string
	Passive bool
	Cost    int
}

// RIPConfig holds RIP routing configuration.
type RIPConfig struct {
	Interfaces   []string // interfaces participating in RIP
	Passive      []string // passive interfaces (receive only)
	Redistribute []string // "connected", "static", "ospf"
	AuthKey      string   // authentication key/password
	AuthType     string   // "md5" or "simple"
}

// ISISConfig holds IS-IS routing configuration.
type ISISConfig struct {
	NET             string // ISO NET address (e.g. "49.0001.0100.0000.0001.00")
	Level           string // "level-1", "level-2", "level-1-2" (default "level-2")
	Interfaces      []*ISISInterface
	Export          []string // "connected", "static", etc.
	AuthKey         string   // area-level authentication key
	AuthType        string   // "md5" or "simple" (plaintext)
	WideMetricsOnly bool     // use wide (32-bit) metrics
	Overload        bool     // set overload bit
}

// ISISInterface defines an interface participating in IS-IS.
type ISISInterface struct {
	Name          string
	Level         string // override per-interface
	Passive       bool
	Metric        int    // 0 = default
	AuthKey       string // per-interface authentication key
	AuthType      string // "md5" or "simple"
	BFD           bool   // enable BFD on this interface
	BFDInterval   int    // BFD minimum-interval in ms (0 = default)
	BFDMultiplier int    // BFD detect-multiplier (0 = default)
}

// RAInterfaceConfig configures Router Advertisement on an interface.
type RAInterfaceConfig struct {
	Interface       string
	ManagedConfig   bool   // managed-configuration (M flag)
	OtherStateful   bool   // other-stateful-configuration (O flag)
	Preference      string // "high", "medium", "low" (default: medium)
	DefaultLifetime int    // seconds, 0 = default (1800)
	MaxAdvInterval  int    // seconds, 0 = default (600)
	MinAdvInterval  int    // seconds, 0 = default (200)
	Prefixes        []*RAPrefix
	DNSServers      []string // recursive DNS server addresses
	NAT64Prefix     string   // PREF64 prefix (e.g. "64:ff9b::/96")
	NAT64PrefixLife int      // PREF64 lifetime in seconds (0 = default)
	LinkMTU         int      // advertised link MTU, 0 = omit
	SourceLinkLocal string   // explicit link-local to use as RA source (overrides auto-selected)
}

// RAPrefix defines a prefix advertised via RA.
type RAPrefix struct {
	Prefix        string // CIDR notation
	OnLink        bool   // on-link flag (default true)
	Autonomous    bool   // SLAAC autonomous flag (default true)
	ValidLifetime int    // seconds, 0 = default (2592000 = 30 days)
	PreferredLife int    // seconds, 0 = default (604800 = 7 days)
}

// OSPFConfig holds OSPF routing configuration.
type OSPFConfig struct {
	RouterID           string // e.g. "10.0.0.1"
	ReferenceBandwidth int    // Mbps for auto-cost calculation (0 = FRR default 100)
	PassiveDefault     bool   // all interfaces passive by default
	Areas              []*OSPFArea
	Export             []string // export policy names (future)
}

// OSPFArea defines an OSPF area.
type OSPFArea struct {
	ID           string // "0.0.0.0" (backbone) or area number
	AreaType     string // "stub", "nssa", "" (normal)
	NoSummary    bool   // stub/nssa no-summary (totally stubby)
	Interfaces   []*OSPFInterface
	VirtualLinks []*OSPFVirtualLink
}

// OSPFVirtualLink defines a virtual link to the backbone through a transit area.
type OSPFVirtualLink struct {
	NeighborID  string // router-id of ABR at the other end
	TransitArea string // the area this virtual-link traverses (the area ID where it's configured)
}

// OSPFInterface defines an interface participating in OSPF.
type OSPFInterface struct {
	Name          string
	Passive       bool   // passive interface (no hello)
	NoPassive     bool   // override passive-default (explicitly active)
	Cost          int    // OSPF cost, 0 = default
	NetworkType   string // "point-to-point", "broadcast", "" (default)
	AuthType      string // "md5", "simple", "" (none)
	AuthKey       string // authentication key/password
	AuthKeyID     int    // key-id for MD5 (1-255)
	BFD           bool   // enable BFD on this interface
	BFDInterval   int    // BFD minimum-interval in ms (0 = default)
	BFDMultiplier int    // BFD detect-multiplier (0 = default)
}

// BGPConfig holds BGP routing configuration.
type BGPConfig struct {
	LocalAS              uint32
	RouterID             string
	ClusterID            string // route reflector cluster ID
	GracefulRestart      bool   // enable graceful restart
	Multipath            int    // maximum equal-cost paths (0 = disabled)
	MultipathMultipleAS  bool   // allow multipath across different ASes
	LogNeighborChanges   bool   // log neighbor state transitions
	Dampening            bool   // enable route flap dampening
	DampeningHalfLife    int    // half-life in minutes (default 15)
	DampeningReuse       int    // reuse threshold (default 750)
	DampeningSuppress    int    // suppress threshold (default 2000)
	DampeningMaxSuppress int    // max suppress time in minutes (default 60)
	Neighbors            []*BGPNeighbor
	Export               []string // "connected", "static", "ospf", etc.
}

// BGPNeighbor defines a BGP peer.
type BGPNeighbor struct {
	Address              string // peer IP
	PeerAS               uint32
	Description          string
	MultihopTTL          int      // 0 = directly connected
	Export               []string // per-group export policies (route-map out)
	FamilyInet           bool     // activate under address-family ipv4 unicast
	FamilyInet6          bool     // activate under address-family ipv6 unicast
	GroupName            string   // BGP group name (for display)
	AuthPassword         string   // TCP MD5 password for BGP session
	BFD                  bool     // enable BFD for this neighbor
	BFDInterval          int      // BFD minimum interval in ms (0 = default 300)
	BFDMultiplier        int      // BFD detect-multiplier (0 = default 3)
	RouteReflectorClient bool     // mark as route-reflector client
	DefaultOriginate     bool     // advertise default route to this neighbor
	AllowASIn            int      // allow own AS in path N times (0 = disabled)
	RemovePrivateAS      bool     // strip private AS numbers from updates
	PrefixLimitInet      int      // max IPv4 prefixes (0 = unlimited)
	PrefixLimitInet6     int      // max IPv6 prefixes (0 = unlimited)
}

// TunnelConfig defines a GRE, IPIP, or other tunnel interface.
type TunnelConfig struct {
	Name            string   // Linux interface name (e.g. "gr-0-0-0", "ip-0-0-0")
	Mode            string   // "gre" or "ipip"
	Source          string   // local tunnel endpoint IP
	Destination     string   // remote tunnel endpoint IP
	Key             uint32   // GRE key, 0 = none
	TTL             int      // tunnel TTL, 0 = default 64
	Addresses       []string // IPs to assign to tunnel interface (CIDR)
	RoutingInstance string   // destination routing-instance (VRF)
	Keepalive       int      // keepalive interval in seconds (0 = disabled)
	KeepaliveRetry  int      // number of missed keepalives before declaring down (0 = default 3)
	AnchorOnly      bool     // create a dummy anchor instead of a kernel tunnel device
}

// TunnelNameMap returns a mapping from Junos interface reference (e.g. "gr-0/0/0.0")
// to the Linux tunnel interface name. For tunnel interfaces with per-unit tunnel config,
// unit 0 uses the base Linux name, unit N>0 appends "uN".
func (c *Config) TunnelNameMap() map[string]string {
	m := make(map[string]string)
	for ifName, ifc := range c.Interfaces.Interfaces {
		if ifc.Tunnel != nil && ifc.Tunnel.Source != "" {
			// Interface-level tunnel: all units share the same tunnel
			baseName := LinuxIfName(ifName)
			for unitNum := range ifc.Units {
				ref := ifName + "." + strconv.Itoa(unitNum)
				m[ref] = baseName
			}
			continue
		}
		// Per-unit tunnels: each unit with tunnel config gets its own Linux name
		for unitNum, unit := range ifc.Units {
			if unit.Tunnel != nil {
				ref := ifName + "." + strconv.Itoa(unitNum)
				m[ref] = unit.Tunnel.Name
			}
		}
	}
	return m
}

// IPsecConfig holds IPsec VPN configuration.
type IPsecConfig struct {
	// Phase 1 (IKE)
	IKEProposals map[string]*IKEProposal
	IKEPolicies  map[string]*IKEPolicy
	Gateways     map[string]*IPsecGateway

	// Phase 2 (IPsec)
	Proposals map[string]*IPsecProposal
	Policies  map[string]*IPsecPolicyDef
	VPNs      map[string]*IPsecVPN
}

// IKEProposal defines Phase 1 (IKE) negotiation parameters.
type IKEProposal struct {
	Name            string
	AuthMethod      string // "pre-shared-keys"
	EncryptionAlg   string // "aes-256-cbc"
	AuthAlg         string // "sha-256"
	DHGroup         int    // DH group number
	LifetimeSeconds int
}

// IKEPolicy defines Phase 1 policy (mode, proposal reference, PSK).
type IKEPolicy struct {
	Name      string
	Mode      string // "main" or "aggressive"
	Proposals string // IKE proposal reference
	PSK       string // pre-shared key
}

// IPsecProposal defines Phase 2 (ESP) encryption and authentication parameters.
type IPsecProposal struct {
	Name            string
	Protocol        string // "esp"
	EncryptionAlg   string // "aes-256-cbc", "aes-128-gcm"
	AuthAlg         string // "hmac-sha-256" (ignored for GCM)
	DHGroup         int    // DH group number
	LifetimeSeconds int
}

// IPsecPolicyDef defines Phase 2 policy (PFS + proposal reference).
type IPsecPolicyDef struct {
	Name      string
	PFSGroup  int    // PFS DH group number (0 = disabled)
	Proposals string // IPsec proposal reference
}

// IPsecGateway defines a remote IKE gateway.
type IPsecGateway struct {
	Name             string
	Address          string // remote gateway IP
	DynamicHostname  string // dynamic peer hostname (DNS-resolved)
	LocalAddress     string // local IP
	IKEPolicy        string // IKE policy reference
	ExternalIface    string // external-facing interface
	LocalCertificate string // local certificate name for pubkey auth
	Version          string // "v1-only", "v2-only" (empty = both)
	NoNATTraversal   bool   // disable NAT-T (legacy, use NATTraversal)
	NATTraversal     string // "enable" (default), "disable", "force"
	DeadPeerDetect   string // "always-send", "optimized", "probe-idle"
	DPDInterval      int    // seconds
	DPDThreshold     int    // retry count before peer is considered dead
	LocalIDType      string // "hostname", "inet", "fqdn"
	LocalIDValue     string // identity value
	RemoteIDType     string // "hostname", "inet", "fqdn"
	RemoteIDValue    string // identity value
}

type IPsecTrafficSelector struct {
	Name     string
	LocalIP  string
	RemoteIP string
}

// IPsecVPN defines an IPsec VPN tunnel.
type IPsecVPN struct {
	Name             string
	Gateway          string // gateway reference
	IPsecPolicy      string // IPsec policy reference
	LocalID          string // local traffic selector (CIDR)
	RemoteID         string // remote traffic selector (CIDR)
	PSK              string // pre-shared key (legacy, prefer IKE policy)
	LocalAddr        string // local address
	BindInterface    string // tunnel interface (e.g. "st0.0") — creates xfrmi with if_id
	DFBit            string // "copy", "set", "clear"
	EstablishTunnels string // "immediately", "on-traffic"
	TrafficSelectors map[string]*IPsecTrafficSelector
}

// RoutingInstanceConfig represents a VRF-based routing instance.
type RoutingInstanceConfig struct {
	Name                      string
	Description               string
	InstanceType              string         // "virtual-router" or "vrf"
	Interfaces                []string       // interfaces belonging to this instance
	StaticRoutes              []*StaticRoute // per-instance static routes
	Inet6StaticRoutes         []*StaticRoute // per-instance rib inet6.0 static routes
	OSPF                      *OSPFConfig    // per-instance OSPF (optional)
	OSPFv3                    *OSPFv3Config  // per-instance OSPFv3 (optional)
	BGP                       *BGPConfig     // per-instance BGP (optional)
	RIP                       *RIPConfig     // per-instance RIP (optional)
	ISIS                      *ISISConfig    // per-instance IS-IS (optional)
	TableID                   int            // Linux kernel routing table number (auto-assigned)
	InterfaceRoutesRibGroup   string         // interface-routes { rib-group inet <name>; }
	InterfaceRoutesRibGroupV6 string         // interface-routes { rib-group inet6 <name>; }
}
