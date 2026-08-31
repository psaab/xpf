package config

// Chassis cluster, redundancy groups, interface/IP monitoring, event
// policies, and bridge domains.

// ChassisConfig holds chassis-level configuration (clustering, etc).
type ChassisConfig struct {
	Cluster *ClusterConfig
	// DeviceMap is the #1956 bare-metal stable-identity managed allowlist.
	// nil OR an empty entry set means positional mode (today's behavior);
	// device-map mode is selected on len(DeviceMap.Entries) > 0, never on
	// DeviceMap != nil (an empty `chassis device-map {}` block must not
	// trip the silent-all-unconfigured trap — R-7/V-7).
	DeviceMap *DeviceMapConfig
}

// DeviceMapConfig is the #1956 bare-metal device-map: an opt-in stanza that
// binds host NICs (by stable identity — PCI bus address with permanent-MAC
// fallback) to xpf logical names, and governs everything NOT named here via
// UnmappedPolicy. See docs/bare-metal-device-map.md and the plan in
// docs/research/1956-bare-metal-device-map/.
type DeviceMapConfig struct {
	// Entries binds each logical name to a stable host identity.
	Entries []DeviceMapEntry
	// UnmappedPolicy governs NICs with no entry:
	//   "leave-alone" (default in device-map mode): never renamed, never
	//                 marked always-down, never address-stripped.
	//   "manage-down": today's claim-all behavior (bring unconfigured NICs
	//                 down). Provided for operators who DO want xpf to own
	//                 the whole box.
	UnmappedPolicy string
}

// DeviceMapPolicyLeaveAlone / DeviceMapPolicyManageDown are the two
// unmapped-interface-policy values. Leave-alone is the bare-metal default.
const (
	DeviceMapPolicyLeaveAlone = "leave-alone"
	DeviceMapPolicyManageDown = "manage-down"
)

// DeviceMapKey* are the per-entry identity key-order values (V-5). The
// default (empty) is treated as pci-then-mac.
const (
	DeviceMapKeyPCIThenMAC = "pci-then-mac"
	DeviceMapKeyMACThenPCI = "mac-then-pci"
	DeviceMapKeyPCI        = "pci"
	DeviceMapKeyMAC        = "mac"
)

// DeviceMapEntry binds one xpf logical name to one host NIC identity.
type DeviceMapEntry struct {
	// LogicalName is the xpf/vSRX name the bound NIC is renamed to
	// (e.g. "ge-0/0/3", "fxp0"). Stored Junos-style with slashes; the
	// daemon converts to the Linux kernel name (ge-0-0-3) via LinuxIfName.
	LogicalName string
	// PCIAddr is the primary identity key (DDDD:BB:DD.F), "" if unset.
	PCIAddr string
	// MAC is the permanent/factory-MAC fallback key, "" if unset. Compared
	// against PermHWAddr, never the running MAC (RETH virtual-MAC alternates
	// — R-3/R-6).
	MAC string
	// KeyOrder selects the resolution priority chain (DeviceMapKey*).
	// "" => pci-then-mac.
	KeyOrder string
}

// EffectiveKeyOrder returns the entry's key-order, defaulting empty to
// pci-then-mac.
func (e DeviceMapEntry) EffectiveKeyOrder() string {
	if e.KeyOrder == "" {
		return DeviceMapKeyPCIThenMAC
	}
	return e.KeyOrder
}

// EffectiveUnmappedPolicy returns the device-map's unmapped-interface-policy,
// defaulting empty to leave-alone (the bare-metal-safe default — an operator
// who wrote a map clearly wants selective management).
func (d *DeviceMapConfig) EffectiveUnmappedPolicy() string {
	if d == nil || d.UnmappedPolicy == "" {
		return DeviceMapPolicyLeaveAlone
	}
	return d.UnmappedPolicy
}

// Active reports whether device-map mode is engaged: a non-nil config with at
// least one entry. An empty `device-map {}` block is positional mode (R-7).
func (d *DeviceMapConfig) Active() bool {
	return d != nil && len(d.Entries) > 0
}

// ClusterConfig defines chassis cluster settings for HA.
type ClusterConfig struct {
	ClusterID int
	NodeID    int
	// NodeIDSet records whether the `chassis cluster node` leaf was
	// actually present (and parsed to an integer) in the compiled config,
	// as opposed to NodeID sitting at its zero default. It is load-bearing
	// for the node-identity cross-check (#4185): a config that carries a
	// cluster stanza but no explicit `node` leaf must NOT be treated as
	// "node 0" when reconciling against the /etc/xpf/node-id file, or an
	// absent leaf on a node-1 box would false-reject as a mismatch.
	NodeIDSet bool
	RethCount int
	// #6772: both defaults corrected. The runtime substitutes
	// cluster.DefaultHeartbeatInterval (100ms) and
	// cluster.DefaultHeartbeatThreshold (5); these comments said 1000 and 3.
	HeartbeatInterval   int    // milliseconds, 0 = runtime default (100)
	HeartbeatThreshold  int    // missed heartbeats before lost, 0 = runtime default (5)
	ControlInterface    string // interface for heartbeat traffic (e.g. "hb0")
	PeerAddress         string // peer node's control link IP (e.g. "10.99.0.2")
	FabricInterface     string // interface for session/config sync (e.g. "fab0")
	FabricPeerAddress   string // peer's fabric link IP (e.g. "10.99.1.2")
	Fabric1Interface    string // secondary fabric interface (e.g. "fab1")
	Fabric1PeerAddress  string // peer's secondary fabric IP
	ConfigSync          bool   // enable config synchronization to peer on commit
	ControlLinkRecovery bool   // enable control-link-recovery
	// StrictSessionAuth is the #7441 operator-declared posture: when set AND
	// this node holds a control-link PSK, an established session-sync
	// connection that has not authenticated within the in-place-upgrade grace
	// is closed.
	//
	// It closes the #6628 residual — a hostile stream admitted BEFORE the key
	// was committed keeps injecting frames, because the in-place upgrade only
	// ever PROMOTES a connection whose peer answers and a hostile peer declines
	// by staying silent. Nothing on the wire separates a decliner from a
	// legitimate peer that cannot answer yet, so the discriminator has to come
	// from the operator, who knows whether the cluster is homogeneous.
	//
	// NODE-LOCAL: never overwritten by config-sync (preserveNodeLocalChassis in
	// pkg/daemon). A flag carried in synced config would be clearable by the
	// admitted connection it is meant to evict — #5078's "re-arming through
	// config-sync" constraint, which is why it is not stored that way.
	StrictSessionAuth bool
	// ControlLinkAuthKey is the #4107 shared PSK that authenticates cluster
	// control-channel messages. When set, the heartbeat/election channel is
	// signed with HMAC-SHA256; a forged or unauthenticated heartbeat is
	// rejected once BOTH nodes carry the key (dual-accept during a rolling
	// upgrade so a mixed-version cluster does not split-brain). ${node}-
	// agnostic: the SAME key on both nodes, synced by config-sync. Secret-
	// typed so it is redacted on every show/log/JSON/YAML path and never
	// echoed into an error string.
	ControlLinkAuthKey Secret
	// ControlLinkAuthKeyAlt is a SECOND key this node ACCEPTS on the control
	// channel but never SIGNS with (#6630). It exists so a PSK rotation is a
	// rolling operation instead of a planned outage.
	//
	// Without it, rotating one node to a new key makes each end receive a
	// present-but-invalid HMAC from the other. Those frames are rejected
	// without refreshing lastSeen, so after heartbeat-interval x threshold
	// (~1s at shipped settings) BOTH nodes declare the peer dead and BOTH take
	// over their redundancy groups — dual-master with duplicate VIPs for the
	// whole window between the two commits.
	//
	// "Additional accepted", not "previous", because it holds the NEW key in
	// the first half of a rotation and the OLD key in the second. The
	// procedure in pkg/cluster/README.md walks both halves.
	//
	// Secret-typed and redacted exactly like ControlLinkAuthKey. It does NOT
	// satisfy the #6611 keyed-cluster requirement on its own: a cluster whose
	// only key is this one signs with nothing, so validateClusterAuthKeyStrict
	// still demands ControlLinkAuthKey.
	ControlLinkAuthKeyAlt Secret
	NATStateSync          bool   // enable NAT state synchronization (session sync with NAT fields)
	IPsecSASync           bool   // enable IPsec SA synchronization (connection name sync for failover re-initiation)
	DHCPLeaseSync         bool   // enable DHCP-server lease synchronization (#2239 PATH C: lease state held on standby, seeded into Kea on takeover)
	RethAdvertiseInterval int    // RETH VRRP advertisement interval in milliseconds, 0=default(30)
	HitlessRestart        bool   // preserve BPF state on shutdown (default false in HA — fail-closed)
	PeerFencing           string // peer fencing action on heartbeat timeout: "", "disable-rg", "disable-rg-confirmed" (#7147)
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
