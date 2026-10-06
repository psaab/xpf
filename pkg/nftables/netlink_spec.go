package nftables

// netlink_spec.go defines the self-contained input specs the #6387 PR-2 netlink
// installer consumes. They MIRROR the daemon / dpuserspace types the exec-`nft`
// oracle consumes (dpuserspace.ZoneHostInboundView, dpuserspace.JunosHostProgram
// config.JunosHostDenyRule/L4, config.FirewallFilterTerm) but are declared here
// so pkg/nftables does not import pkg/dataplane/userspace (which imports
// pkg/nftables — an import cycle). The PR-3 daemon converter copies daemon
// values into these structs field-for-field; PR-2 constructs them directly in
// the parity tests.
//
// The high-level builders (netlink_hostinbound.go / netlink_lo0.go /
// netlink_fence.go) re-derive the low-level matches from these specs using the
// SAME shared SSOT the oracle uses (config.HostInboundServiceMatch,
// appid.ProtocolNumber, config.ParseTCPFlagsExpression, dataplane.DSCPValues),
// so the only thing that differs between oracle and netlink is the
// rendering-to-kernel step — which the T1 ruleset-parity test pins.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// PortRange mirrors config.PortRange: an inclusive [Lo,Hi] transport-port range
// (Lo==Hi is a single port).
type PortRange struct {
	Lo uint16
	Hi uint16
}

// HostInboundZoneView mirrors dpuserspace.ZoneHostInboundView. Addresses are
// bare host IPs; multicast rules carry the catalog groups admitted by the view.
type HostInboundZoneView struct {
	Zone                 string
	SystemServices       []string
	Protocols            []string
	MulticastRules       []config.HostInboundMulticastRule
	V4Addrs              []string
	V6Addrs              []string
	ICMPFloodThreshold   uint32
	UDPFloodThreshold    uint32
	SYNFloodThreshold    uint32
	SYNFloodSrcThreshold uint32
	AlarmWithoutDrop     bool
	IngressNetdevs       []string // #9637: see dpuserspace.ZoneHostInboundView
	// IngressDenyNetdevs lists effective ingress netdevs claimed by multiple
	// zone views (#10431). The renderer applies destination-owner service rights
	// before a counted fail-closed catch-all on those netdevs.
	IngressDenyNetdevs []string
}

// JunosHostDenyL4 mirrors config.JunosHostDenyL4.
type JunosHostDenyL4 struct {
	Proto       uint8
	Ports       []PortRange
	SourcePorts []PortRange
	ICMPType    *uint8
	ICMPCode    *uint8
}

// JunosHostDenyRule mirrors config.JunosHostDenyRule.
type JunosHostDenyRule struct {
	Family      string // "ip" or "ip6"
	SrcAny      bool
	SrcExcluded bool
	Src         []string
	Verdict     config.JunosHostVerdict // #9504
	DstAny      bool
	DstExcluded bool
	Dst         []string
	L4          []JunosHostDenyL4
}

// JunosHostProgram mirrors dpuserspace.JunosHostProgram. The IKE fields remain
// in this parity shape for config/projection tests and warning metadata; the
// netlink renderer never emits an IKE ACCEPT from them. IdentResetNetdevs is
// still rendered as the retained terminal RST scope.
type JunosHostProgram struct {
	Zone                  string
	IngressIfnames        []string
	RulesV4               []JunosHostDenyRule
	RulesV6               []JunosHostDenyRule
	CoarseAdmitsIKE       bool
	CoarseIdentResets     bool
	HasApplicationAnyDeny bool
	IKEExemptNetdevs      []string
	IdentResetNetdevs     []string
}

// Lo0FilterTerm mirrors one lowered config.FirewallFilterTerm for the kernel lo0
// input chain. Source/destination scopes are the RESOLVED (prefix-list-expanded)
// address lists exactly as dpuserspace.ResolveFilterPrefixListAddrs returns them
// — mixed-family and unfiltered; the netlink builder family-filters per chain
// pass (mirroring nftFamilyAddrs) and applies the Junos empty-set / except /
// match-nothing semantics (mirroring nftAddrPredicate). Every other field is a
// verbatim copy of the config term; the builder re-derives protocol numbers,
// DSCP values, and tcp-flags masks via the shared SSOT.
type Lo0FilterTerm struct {
	Name string

	SrcAddrs       []string
	SrcExcept      bool
	SrcConstrained bool
	DstAddrs       []string
	DstExcept      bool
	DstConstrained bool

	Protocols         []string
	SourcePorts       []string
	DestinationPorts  []string
	SourcePortsExcept []string
	DestPortsExcept   []string
	DSCPs             []string
	ICMPTypes         []int
	ICMPCodes         []int
	TCPFlags          []string
	IsFragment        bool

	// ICMPTypeUnrepresentable / ICMPCodeUnrepresentable mark a term carrying a
	// `from icmp-type` / `from icmp-code` token the compiler could not resolve
	// to a byte in 0..255 — a symbolic name with no mapping, or a numeric value
	// out of range (config.FirewallFilterTerm.UnknownICMPTypes /
	// UnknownICMPCodes, #3205/#3406).
	//
	// A marker is REQUIRED here, unlike protocol and address: ICMPTypes /
	// ICMPCodes above are already-resolved bytes, so an unresolvable token
	// leaves no trace in this DTO at all and the builder cannot re-derive it
	// (contrast filterFamilyAddrs and lo0Protocols, which see the raw string and
	// detect the bad token themselves). This is the same channel #6463 opened
	// for AddressUnrepresentable.
	//
	// Names deliberately match the userspace wire fields
	// (dpuserspace.FilterTermSnapshot.ICMPTypeUnrepresentable /
	// ICMPCodeUnrepresentable) so the two mirrors of the same config term are
	// greppable as one contract.
	//
	// Strict commit rejects these tokens; the tolerant load / peer-sync paths
	// only warn (#1960), so the mirror must still decide. It fails the netlink
	// plan CLOSED — see buildLo0TermNetlink (#6806).
	ICMPTypeUnrepresentable bool
	ICMPCodeUnrepresentable bool

	// FlexMatch carries a `from flexible-match-range` predicate (#6804). Before
	// it existed the lo0 mirror had NO field for it at all, so the predicate was
	// dropped at this boundary and the term rendered WITHOUT its narrowing — an
	// `accept` term meant to admit only packets whose header bytes match a
	// pattern admitted everything else in its scope. The XDP shim shunts
	// host-bound traffic to the kernel before userspace-dp, so this chain is the
	// PRIMARY enforcement for host traffic: that is a control-plane fail-OPEN,
	// the same class #5512 fixed for tcp-flags.
	//
	// Only `layer-3` match-start is representable, which is exactly what the
	// compiler accepts (FlexMatchConfig.MatchStart), and it maps to nft's
	// network-header payload base.
	FlexMatch *Lo0FlexMatch
	// FlexMatchUnrepresentable marks a term whose flexible-match-range could NOT
	// be resolved — an unknown range name, or a numeric token the compiler could
	// not parse (config.FilterTerm.UnknownFlexMatch). Strict commit rejects
	// those, but the tolerant load / peer-sync paths only warn (#1960), so the
	// mirror must still decide. It fails the TERM closed, mirroring the #5512
	// tcp-flags direction: rendering the term without its narrowing is the
	// fail-open this issue is about.
	FlexMatchUnrepresentable bool
	// FromUnrepresentable marks a term whose `from` block carried a match leaf
	// the dataplane does NOT enforce (config.FirewallFilterTerm.UnknownFrom,
	// #3307 — ttl / source-mac-address / ip-options / fragment-offset /
	// hop-limit / ...) or a value-bearing leaf written with NO operand
	// (config.FirewallFilterTerm.ValuelessFrom, #8480 — `from protocol;`).
	// #11896 reuses the same refusal channel for conflicting terminal actions:
	// applying their conservative internal discard would install a fresh drop.
	// The marker shares the userspace wire field
	// (dpuserspace.FirewallTermSnapshot.FromUnrepresentable) so both mirrors
	// refuse the same candidate. Strict commit rejects these shapes; tolerant
	// load / peer-sync warns (#1960) and refuses the netlink plan CLOSED, retaining
	// the existing ruleset.
	FromUnrepresentable bool

	Log   bool
	Count string

	Action          string
	NextTerm        bool
	RoutingInstance string
}

// Lo0FlexMatch is a resolved `flexible-match-range` predicate: compare
// BitLength bits at ByteOffset from the layer-3 header against Value, after
// masking with Mask. It is a verbatim copy of config.FlexMatchConfig's
// representable fields — the netlink builder re-derives the payload/bitwise/cmp
// expressions, so the two renderers share this input rather than each
// interpreting the config type.
type Lo0FlexMatch struct {
	ByteOffset uint8
	BitLength  uint8
	Value      uint32
	Mask       uint32
}

// Lo0FilterSpec is the full lo0 input-filter render request: the ordered v4 then
// v6 terms (each already family-scoped by the caller as the oracle emits — the
// v4 filter's terms rendered with family "ip", the v6 filter's with "ip6").
type Lo0FilterSpec struct {
	V4Terms []Lo0FilterTerm
	V6Terms []Lo0FilterTerm
}

// HostInputFenceOverlay is the generation-tagged master-interface revocation
// overlay. It is merged at the very head of the ordinary host-input chain so
// established/related accepts cannot bypass a revoked master. The marker fields
// are encoded into the named counter and are checked by readback before the
// daemon publishes the generation.
type HostInputFenceOverlay struct {
	MasterSet       []string
	Generation      uint64
	PermitEpoch     uint64
	CloseRequestSeq uint64
	CloseRequestKey string
	WatchGeneration uint64
	State           string
}

// CanonicalHostInputFenceOverlay returns an immutable-value copy with the
// master-interface set sorted and deduplicated. Every renderer and readback
// path uses this form so duplicate logical members cannot diverge from the
// content marker.
func CanonicalHostInputFenceOverlay(o HostInputFenceOverlay) HostInputFenceOverlay {
	o.MasterSet = append([]string(nil), o.MasterSet...)
	sort.Strings(o.MasterSet)
	uniq := o.MasterSet[:0]
	for _, name := range o.MasterSet {
		if len(uniq) == 0 || uniq[len(uniq)-1] != name {
			uniq = append(uniq, name)
		}
	}
	o.MasterSet = uniq
	return o
}

// HostInputFenceOverlayCounterName is a stable content marker. It hashes the
// canonical master set and every authority field, so marker presence is an
// exact candidate readback rather than a table-presence probe.
func HostInputFenceOverlayCounterName(o HostInputFenceOverlay) string {
	o = CanonicalHostInputFenceOverlay(o)
	var payload bytes.Buffer
	writeU64 := func(v uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		payload.Write(b[:])
	}
	writeString := func(v string) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(len(v)))
		payload.Write(b[:])
		payload.WriteString(v)
	}
	writeU64(o.Generation)
	writeU64(o.PermitEpoch)
	writeU64(o.CloseRequestSeq)
	writeU64(o.WatchGeneration)
	writeString(o.CloseRequestKey)
	writeString(o.State)
	for _, name := range o.MasterSet {
		writeString(name)
	}
	sum := sha256.Sum256(payload.Bytes())
	return "xpf_hif_" + hex.EncodeToString(sum[:12])
}

// HostInboundSpec is the full host-inbound render request (plan §5.1). It is the
// exact input set buildHostInboundFilterPayload consumes.
type HostInboundSpec struct {
	Views                   []HostInboundZoneView
	UnzonedV4               []string
	UnzonedV6               []string
	UnzonedIngressNetdevs   []string // #11409: unzoned physical input scope, before destination fallback
	UnzonedIngressVRFSlaves []string // #11409: LOCAL_IN slave scope before shared-master zone rules
	Programs                []JunosHostProgram
	WGListenPorts           []uint16 // global WG ports denied on zone/destination/ingress mismatch, also used by stale-reply guards.
	// WGZonePorts maps the unique owner zone of a WG tunnel's outer source
	// address to its ports. Admission also requires that zone's ingress and a
	// uniquely same-zone local destination.
	WGZonePorts map[string][]uint16
	// DataplaneFresh is the #9637-D1 pre-landing fail-closed gate: true iff
	// the userspace dataplane runs this generation's snapshot. When false the
	// reinject accept is omitted (byte-identical to the pre-#9637 ruleset).
	DataplaneFresh bool
	Overlay        *HostInputFenceOverlay
	// UnleasedV4/V6 are DHCP backstop netdevs. Unzoned DHCP units are listed
	// while their family has no resolved address; DHCP units in enforcing
	// zones stay listed while DHCP intent remains. DHCPv6 reply admits cover
	// clients whose effective host-inbound policy permits dhcpv6.
	UnleasedV4 []string
	UnleasedV6 []string
	// UnleasedVRFSlavesV4/V6 are the configured VRF-slave subset for sdifname
	// matches; they are present before kernel enslavement.
	UnleasedVRFSlavesV4 []string
	UnleasedVRFSlavesV6 []string
	// DHCPv6Admit are ordinary ingress devices whose effective policy permits
	// dhcpv6; matching link-local server replies may pass the backstop.
	DHCPv6Admit []string
	// DHCPv6AdmitVRFSlaves are the corresponding configured VRF members, matched
	// through sdifname at LOCAL_IN.
	DHCPv6AdmitVRFSlaves []string
}

// FenceSpec is the cold-boot fail-closed fence render request (#5644): address
// scopes, ingress scopes for catalog groups, and per-zone WireGuard inputs.
type FenceSpec struct {
	Views         []HostInboundZoneView
	UnzonedV4     []string
	UnzonedV6     []string
	WGListenPorts []uint16            // stale-reply guard only; WG accepts use WGZonePorts.
	WGZonePorts   map[string][]uint16 // per-zone daddr-scoped WG accepts.
	// UnleasedV4/V6 and UnleasedVRFSlavesV4/V6, as in HostInboundSpec.
	UnleasedV4          []string
	UnleasedV6          []string
	UnleasedVRFSlavesV4 []string
	UnleasedVRFSlavesV6 []string
	// DHCPv6Admit and DHCPv6AdmitVRFSlaves, as in HostInboundSpec.
	DHCPv6Admit []string
	// DHCPv6AdmitVRFSlaves are the configured members matched through sdifname.
	DHCPv6AdmitVRFSlaves []string
	// Unzoned ingress scopes for fail-closed catalog-group drops.
	UnzonedIngressNetdevs   []string
	UnzonedIngressVRFSlaves []string
}

// GapFenceSpec is the additive coverage-gap fence render request (#5789): the
// uncovered addresses to DROP plus scoped WireGuard admission inputs. Uncovered
// addresses shared with a lifeline are ALSO listed in SharedV4/V6: the gap
// denies them on data ingress (bare DROP) while a preceding exception
// admits them on lifeline ingress (M1 ingress-aware scope — a global
// withhold would leave them fail-open post-handoff, when no barrier
// stands behind the gap).
type GapFenceSpec struct {
	Views         []HostInboundZoneView // WG accepts intersect these addresses with Uncovered.
	UncoveredV4   []string
	UncoveredV6   []string
	WGListenPorts []uint16            // stale-reply guard only; WG accepts use WGZonePorts.
	WGZonePorts   map[string][]uint16 // per-zone daddr-scoped WG accepts.
	// UnleasedV4/V6 and UnleasedVRFSlavesV4/V6, as in HostInboundSpec.
	UnleasedV4          []string
	UnleasedV6          []string
	UnleasedVRFSlavesV4 []string
	UnleasedVRFSlavesV6 []string
	// DHCPv6Admit and DHCPv6AdmitVRFSlaves, as in HostInboundSpec.
	DHCPv6Admit []string
	// DHCPv6AdmitVRFSlaves are the configured members matched through sdifname.
	DHCPv6AdmitVRFSlaves []string
	// RetainedV4/V6 are destinations still covered by the installed main table.
	// The gap table's DHCP backstop must exclude them so it cannot override a
	// retained service permit in this later base chain.
	RetainedV4 []string
	RetainedV6 []string
	// SharedV4/V6 are the Uncovered subset shared with a lifeline,
	// admitted on lifeline ingress ahead of the bare DROP. Empty
	// omits the exception.
	SharedV4 []string
	SharedV6 []string
	// LifelineNetdevs is the exception's iifname set: linux LOCAL_IN
	// names of lifeline interfaces (HostInboundLifelineIngressNetdevs).
	// Empty with non-empty Shared omits the exception (fail-closed:
	// shared stays bare-DROPped on every ingress).
	LifelineNetdevs []string
}
