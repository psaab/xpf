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
	// `json:"-"` keeps this compile-time diagnostic out of JSON/REST.
	// fingerprintIgnore separately excludes it from semantic comparisons:
	// the fault is reported through Warnings, not by differing config content.
	MalformedAddresses []string `json:"-"`
}

// InterfaceConfig represents a network interface.
type InterfaceConfig struct {
	Name                string
	Description         string                  // free-text interface description
	MTU                 int                     // L3 (IP) MTU to programme on the netdev; compileInterfaces translates the authored Junos media MTU (#16594). Family/unit MTU overrides it.
	Speed               string                  // interface speed (10m..100g notation or "auto")
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
	//
	// `json:"-"` is load-bearing: ConfigSnapshot serializes the typed Config into
	// the opaque Rust JSON payload, so this compiler-internal bit would otherwise
	// be visible on the Go→Rust wire and appear in the #9821 golden.
	// The bit is compiler-internal — the emitter's fallback decision is already
	// encoded in the emitted endpoint rows, and no Rust consumer reads the bit
	// itself. Nothing is lost by not persisting it: the config DB stores the
	// TREE, and compileInterfaces recomputes the bit on every load.
	AuthoredUnits bool `json:"-"`
	// #4308 (fable-review-167 I-3): parity knobs are typed + compiled so
	// they stop silently vanishing. #11434 enforces native-vlan-id: untagged
	// frames resolve to the unit with the matching vlan-id. The remaining
	// gratuitous-ARP, unnumbered-address, and targeted-broadcast settings stay
	// accepted-only; see validateInterfaceParityWarnings.
	NativeVlanID           int  // native-vlan-id <id> (0 = unset)
	GratuitousARPReply     bool // gratuitous-arp-reply — accepted-only (#4308)
	NoGratuitousARPRequest bool // no-gratuitous-arp-request — accepted-only (#4308)
}

// TaggingEnabled reports whether the interface enables VLAN tagging in
// either mode: plain `vlan-tagging` (VlanTagging) or
// `flexible-vlan-tagging` (FlexibleVlanTagging). Flexible tagging with a
// single outer tag (the only shape the #5879 QinQ gate admits — an inner
// tag is rejected at commit) creates the same 802.1Q `<parent>.<vid>`
// children as plain tagging, so every writer that keys on tagging must
// consult this helper rather than VlanTagging alone (#15215 A28-03: the
// #14574 gate accepts flexible-vlan-tagging, and a writer keyed only on
// VlanTagging silently folded the tagged unit's addresses onto the
// untagged parent, left the bridge-domain member unenslaved, and split
// VRRP/VIP placement). Nil-safe: a nil interface enables nothing.
func (ifc *InterfaceConfig) TaggingEnabled() bool {
	return ifc != nil && (ifc.VlanTagging || ifc.FlexibleVlanTagging)
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
	Number             int
	Disable            bool             // unit-level `disable` — administratively disabled (#14575)
	Description        string           // free-text unit description
	VlanID             int              // 0 = native/untagged, >0 = 802.1Q tagged
	InnerVlanID        int              // inner VLAN tag for QinQ (flexible-vlan-tagging)
	PointToPoint       bool             // point-to-point link (for tunnels)
	Addresses          []string         // CIDR notation
	PrimaryAddress     string           // IPv4 address marked as primary
	PrimaryAddressV6   string           // IPv6 address marked as primary (#15653)
	PreferredAddress   string           // IPv4 address marked as preferred
	PreferredAddressV6 string           // IPv6 address marked as preferred (#15653)
	MTU                int              // family-level MTU (0 = default)
	DHCP               bool             // family inet { dhcp; }
	DHCPOptions        *DHCPInetOptions // dhcp sub-options (lease-time, etc.)
	DHCPv6             bool             // family inet6 { dhcpv6; }
	DHCPv6Client       *DHCPv6ClientConfig
	DADDisable         bool // family inet6 { dad-disable; }
	// #4308 (fable-review-167 I-3): family inet parity knobs, typed +
	// compiled so they stop silently vanishing but ACCEPTED-ONLY today
	// (commit-time advisory; see validateInterfaceParityWarnings).
	// unnumbered-address needs a networkd borrow-address implementation;
	// targeted-broadcast needs dataplane directed-broadcast forwarding.
	UnnumberedInet    string                // family inet unnumbered-address <donor> — accepted-only (#4308)
	TargetedBroadcast bool                  // family inet targeted-broadcast — accepted-only (#4308)
	SamplingV4Input   bool                  // family inet  { sampling { input; } }  (#14608: per-family)
	SamplingV4Output  bool                  // family inet  { sampling { output; } }
	SamplingV6Input   bool                  // family inet6 { sampling { input; } }
	SamplingV6Output  bool                  // family inet6 { sampling { output; } }
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
	// FamilyInet records authored inet presence for compiler-only validation.
	FamilyInet bool `json:"-"`
	// FamilyInet6 records authored inet6 presence for the IPv6 MTU gate.
	// It is compiler evidence, not snapshot wire data.
	FamilyInet6 bool `json:"-"`
	// ISOAddresses records `family iso address <NET>` values (#16865).
	// Junos carries the IS-IS NET here (preferably lo0); the derivation
	// in compiler_derivations.go folds a lo0 NET into ISISConfig.NET
	// when no explicit `protocols isis net` was authored. Compiler-only
	// evidence, like FamilyInet above.
	ISOAddresses []string `json:"-"`
}

// PrimaryAddressForFamily returns the unit's primary address for the
// requested family (true = IPv6). IPv4 reads PrimaryAddress only when it
// holds an IPv4 CIDR; IPv6 reads PrimaryAddressV6, falling back to
// PrimaryAddress only when that slot holds an IPv6 CIDR (single-family
// inet6 units authored before #15653, and hand-built fixtures, stored
// their primary in the shared slot). The family check is load-bearing:
// an unchecked shared-slot return leaked a v6 value to IPv4 consumers
// for inet6-first dual-stack units (#15944 H4-01). (#15653)
func (u *InterfaceUnit) PrimaryAddressForFamily(ipv6 bool) string {
	if u == nil {
		return ""
	}
	if !ipv6 {
		if u.PrimaryAddress != "" && !cidrIsIPv6(u.PrimaryAddress) {
			return u.PrimaryAddress
		}
		return ""
	}
	if u.PrimaryAddressV6 != "" {
		return u.PrimaryAddressV6
	}
	if cidrIsIPv6(u.PrimaryAddress) {
		return u.PrimaryAddress
	}
	return ""
}

// PreferredAddressForFamily is PrimaryAddressForFamily for `preferred`.
func (u *InterfaceUnit) PreferredAddressForFamily(ipv6 bool) string {
	if u == nil {
		return ""
	}
	if !ipv6 {
		if u.PreferredAddress != "" && !cidrIsIPv6(u.PreferredAddress) {
			return u.PreferredAddress
		}
		return ""
	}
	if u.PreferredAddressV6 != "" {
		return u.PreferredAddressV6
	}
	if cidrIsIPv6(u.PreferredAddress) {
		return u.PreferredAddress
	}
	return ""
}

// cidrIsIPv6 reports whether a CIDR string's address is IPv6.
func cidrIsIPv6(cidr string) bool {
	for i := range cidr {
		if cidr[i] == ':' {
			return true
		}
		if cidr[i] == '/' {
			return false
		}
	}
	return false
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
	ID               int
	VirtualAddresses []string // virtual IP addresses
	Priority         int      // 1-255, default 100
	Preempt          bool     // default true (Junos/RFC 5798); cleared only by `no-preempt` (#15047)
	// PreemptSet records that preemption was explicitly authored
	// (`preempt` or Junos `no-preempt`, #15046) so the emitter can
	// round-trip `no-preempt` instead of dropping it as the default.
	PreemptSet        bool
	PreemptHoldTime   int // seconds a higher-priority backup waits before preempting a live lower-priority master; 0 = immediate (Junos `preempt hold-time`)
	AcceptData        bool
	AdvertiseInterval int // seconds, default 1
	// Inet6AdvertiseIntervalMS is the Junos `inet6-advertise-interval`
	// in milliseconds (100..40000, #16558), kept distinct from the
	// seconds AdvertiseInterval so sub-second IPv6 cadence survives to
	// pkg/vrrp (which works in ms). 0 = unset.
	Inet6AdvertiseIntervalMS int
	// VirtualLinkLocalAddress records a Junos
	// `virtual-link-local-address` value (#16558) so the strict gate can
	// name-refuse it and the tolerant path can warn; xpf auto-derives
	// the virtual-router link-local (#5089) and never actuates this.
	VirtualLinkLocalAddress string
	AuthType                string // "md5" or ""
	AuthKey                 Secret // VRRP auth key; redacted on JSON/YAML marshal (#2053)
	TrackInterface          string // lower priority if interface is down
	TrackPriorityDelta      int    // how much to lower priority
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
	// PinnedPrefixes are the operator-pinned IA_PD exception prefixes
	// (#12533): `prefix-delegating pinned-prefix <cidr>` leaves, masked
	// and sorted. A delegation contained by (or equal to) a pin is the
	// ONLY delegation exempt from the #10856 class/overlap refusals, and
	// only for the client whose stanza carries the pin.
	PinnedPrefixes []string
}

// DHCPv6ExpectsAddress reports whether this DHCPv6 client can install a
// routable address on its own unit (#16785). A PD-only client
// (client-ia-type ia-pd without ia-na) delegates prefixes for downstream
// RA; it never installs a WAN address, so "DHCP intent, no global v6"
// is its steady state, not a pending lease. A stateless client likewise
// requests options only. Every other shape — bare `dhcpv6;` (nil
// client), a client with no explicit IA types (the runtime defaults to
// IA_NA), ia-na, or ia-na+ia-pd — expects an address.
func (c *DHCPv6ClientConfig) DHCPv6ExpectsAddress() bool {
	if c == nil {
		return true
	}
	if c.ClientType == "stateless" {
		return false
	}
	if len(c.ClientIATypes) == 0 {
		return true
	}
	for _, t := range c.ClientIATypes {
		if t == "ia-na" {
			return true
		}
	}
	return false
}

// UnitDHCPv6ExpectsAddress is DHCPv6ExpectsAddress for a unit: true when
// the unit runs a DHCPv6 client that can install an address. Units with
// no DHCPv6 intent at all also return true (no v6 lease is pending for
// another reason); callers gate on DHCPv6/DHCPv6Client themselves.
func (u *InterfaceUnit) UnitDHCPv6ExpectsAddress() bool {
	if u == nil || u.DHCPv6Client == nil {
		return true
	}
	return u.DHCPv6Client.DHCPv6ExpectsAddress()
}

// DHCPInetOptions holds DHCPv4 client options for family inet dhcp stanza.
type DHCPInetOptions struct {
	LeaseTime              int  // seconds (0 = default)
	RetransmissionAttempt  int  // number of retransmission attempts
	RetransmissionInterval int  // seconds between retransmissions
	ForceDiscover          bool // always start with DISCOVER
}
