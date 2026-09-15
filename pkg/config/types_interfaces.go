package config

// Physical and logical interface configuration: units, VRRP, DHCPv4/v6
// client options, and aggregated-ether (LAG) options.

// InterfacesConfig holds interface configuration.
type InterfacesConfig struct {
	Interfaces map[string]*InterfaceConfig

	// MalformedAddresses records a token inside a bracketed interface address
	// list that is neither a valid address for its family nor a declared
	// `address` sub-statement (#9424), so
	// validateInterfaceAddressListStrict can reject the commit and the
	// tolerant path can warn instead (#1960). Same record-at-compile /
	// reject-in-a-strict-gate shape as ScreenProfile.UnknownLeaves and
	// SecurityConfig.MalformedZonePairs: the typed-leaf gate validates only
	// the FIRST key slot of an `address` leaf, so by the time the config is
	// compiled the bad token is gone and the unit looks like one that simply
	// carries fewer addresses.
	//
	// json:"-" deliberately, for the reason MalformedZonePairs carries it:
	// this is a COMPILE-TIME DIAGNOSTIC, not config content, and serialising
	// it would perturb every fixture and ConfigFingerprint comparison that
	// compares compiled configs for a field that is nil in every valid config.
	MalformedAddresses []string `json:"-"`
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
	// AuthoredUnits reports that the candidate carried at least one `unit`
	// instance for this interface, even when every one was quarantined on the
	// lenient path and Units is empty (#9899 P2). The tunnel emitter's
	// unitless fallback (bare-name endpoint from the interface-level tunnel)
	// is only for interfaces authored WITHOUT units; without this bit an
	// interface whose final unit was quarantined would activate a fallback
	// endpoint the operator never configured.
	AuthoredUnits bool
	// #4308 (fable-review-167 I-3): parity knobs that are typed + compiled
	// so they stop silently vanishing, but are ACCEPTED-ONLY today (a
	// commit-time advisory warns they are not enforced). native-vlan-id
	// needs the QinQ tagging pipeline (#2354); the gratuitous-ARP knobs
	// map to per-interface sysctls not yet written by the interface apply
	// path. See validateInterfaceParityWarnings.
	NativeVlanID           int  // native-vlan-id <id> (0 = unset) — accepted-only (#4308)
	GratuitousARPReply     bool // gratuitous-arp-reply — accepted-only (#4308)
	NoGratuitousARPRequest bool // no-gratuitous-arp-request — accepted-only (#4308)
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
	DADDisable       bool // family inet6 { dad-disable; }
	// #4308 (fable-review-167 I-3): family inet parity knobs, typed +
	// compiled so they stop silently vanishing but ACCEPTED-ONLY today
	// (commit-time advisory; see validateInterfaceParityWarnings).
	// unnumbered-address needs a networkd borrow-address implementation;
	// targeted-broadcast needs dataplane directed-broadcast forwarding.
	UnnumberedInet    string                // family inet unnumbered-address <donor> — accepted-only (#4308)
	TargetedBroadcast bool                  // family inet targeted-broadcast — accepted-only (#4308)
	SamplingInput     bool                  // family inet/inet6 { sampling { input; } }
	SamplingOutput    bool                  // family inet/inet6 { sampling { output; } }
	FilterInputV4     string                // family inet { filter { input NAME; } }
	FilterOutputV4    string                // family inet { filter { output NAME; } }
	FilterInputV6     string                // family inet6 { filter { input NAME; } }
	FilterOutputV6    string                // family inet6 { filter { output NAME; } }
	VRRPGroups        map[string]*VRRPGroup // keyed by address (CIDR), each address can have VRRP groups
	Tunnel            *TunnelConfig         // per-unit tunnel config (for multi-unit GRE/IPIP)
	// DynamicDNSInet / DynamicDNSInet6 are the per-family Surface A
	// router/interface-address DDNS bindings (#2691 P2, plan §5.9): publish
	// THIS interface unit's learned v4 / v6 address as a configured FQDN through
	// a referenced `system services dynamic-dns provider`. nil == no Surface A
	// publish for that family. The two families are INDEPENDENT (a v4 record can
	// go to one provider, the v6 record to another), so they are distinct
	// fields, matching the per-family Surface B policy split (#2663).
	DynamicDNSInet  *InterfaceDynamicDNSConfig // family inet  { dynamic-dns ... }
	DynamicDNSInet6 *InterfaceDynamicDNSConfig // family inet6 { dynamic-dns ... }
}

// InterfaceDynamicDNSConfig is one per-interface, per-family Surface A DDNS
// binding (#2691 P2, plan §5.9). It says "publish this interface unit's learned
// address (for this family) as Hostname, via the named Provider, observing the
// address from AddressSource". The Provider references a
// `system services dynamic-dns provider <name>` catalog entry (credentials +
// backend + transport configured once there).
type InterfaceDynamicDNSConfig struct {
	// Provider is the name of the `system services dynamic-dns provider` catalog
	// entry this binding publishes through. Required (a binding with no provider
	// publishes nothing and warns at commit).
	Provider string
	// Hostname is the absolute FQDN to publish (e.g. wan.example.net). Required.
	Hostname string
	// AddressSource selects where the unit's current address is observed:
	// "interface" (netlink / static, default) or "dhcp" (the DHCP client lease).
	AddressSource string
	// TTLSeconds is the published record TTL (0 == engine default, 300).
	TTLSeconds int
	// SourceAddress optionally binds the UPDATE socket's source IP for THIS
	// binding (overrides the provider's source-address when set). Free-form IP
	// literal; fail-open at runtime.
	SourceAddress string
}

// VRRPGroup defines a VRRP (Virtual Router Redundancy Protocol) group.
type VRRPGroup struct {
	ID                 int
	VirtualAddresses   []string // virtual IP addresses
	Priority           int      // 1-255, default 100
	Preempt            bool
	PreemptHoldTime    int // seconds a higher-priority backup waits before preempting a live lower-priority master; 0 = immediate (Junos `preempt hold-time`)
	AcceptData         bool
	AdvertiseInterval  int    // seconds, default 1
	AuthType           string // "md5" or ""
	AuthKey            Secret // VRRP auth key; redacted on JSON/YAML marshal (#2053)
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
