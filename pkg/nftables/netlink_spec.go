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
// bare host IPs (no prefix), as the daemon builder guarantees.
type HostInboundZoneView struct {
	Zone           string
	SystemServices []string
	Protocols      []string
	V4Addrs        []string
	V6Addrs        []string
	IngressNetdevs []string // #9637: see dpuserspace.ZoneHostInboundView
	// IngressDenyNetdevs is the #10431 fail-closed guard for an effective
	// ingress netdev whose zone claims are ambiguous.
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
	// Both compile to a term missing an entire authored constraint; without
	// the marker the mirror renders only the surviving predicates —
	// byte-identical to a term authored without the leaf — so an accept term
	// over-permits and a discard/reject term over-drops on the chain that is
	// the PRIMARY enforcement for host traffic. The name matches the
	// userspace wire field
	// (dpuserspace.FirewallTermSnapshot.FromUnrepresentable) so the two
	// mirrors of the same config term are greppable as one contract. Strict
	// commit rejects both spellings; the tolerant load / peer-sync paths only
	// warn (#1960), so the mirror must still decide. It fails the netlink
	// plan CLOSED — see buildLo0TermNetlink (#9875).
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
	Views         []HostInboundZoneView
	UnzonedV4     []string
	UnzonedV6     []string
	Programs      []JunosHostProgram
	WGListenPorts []uint16
	// DataplaneFresh is the #9637-D1 pre-landing fail-closed gate: true iff
	// the userspace dataplane runs this generation's snapshot. When false the
	// reinject accept is omitted (byte-identical to the pre-#9637 ruleset).
	DataplaneFresh bool
	Overlay        *HostInputFenceOverlay
}

// FenceSpec is the cold-boot fail-closed fence render request (#5644): the
// address sets to DROP plus the mandatory-admit WG ports.
type FenceSpec struct {
	Views         []HostInboundZoneView
	UnzonedV4     []string
	UnzonedV6     []string
	WGListenPorts []uint16
}

// GapFenceSpec is the additive coverage-gap fence render request (#5789): the
// uncovered addresses to DROP plus the mandatory-admit WG ports.
type GapFenceSpec struct {
	UncoveredV4   []string
	UncoveredV6   []string
	WGListenPorts []uint16
}
