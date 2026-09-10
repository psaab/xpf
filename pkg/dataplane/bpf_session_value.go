package dataplane

import "unsafe"

// ConntrackSessionValueSize / ConntrackSessionValueSizeV6 are the on-map
// conntrack ABI value sizes (bytes) for the shared `sessions` / `sessions_v6`
// BPF HASH maps. They EXCLUDE the sync-only Generation field — they mirror the
// C `struct session_value` / `session_value_v6` (bpf/headers/xpf_conntrack.h)
// and the Rust `BpfSessionValueV4` / `BpfSessionValueV6` (size-asserted at
// 152 / 200 in userspace-dp/src/afxdp/bpf_map_tests.rs (144 / 192 before the
// #9546 routing_domain append); 136 / 184 before the
// #4983 ingress-identity growth, 128 / 176 before the #5460 flags widen from
// __u8 to __u16).
//
// This is the SINGLE source of truth for the map value_size: the production
// registration (loader_userspace_shim.go) and every test fixture that creates a
// `sessions` map MUST use these constants, NOT sizeOf[SessionValue] (which is
// 8 bytes larger and would over-size the map → OOB copy into the helper's
// smaller lookup buffer, #2360).
var (
	ConntrackSessionValueSize   = uint32(unsafe.Sizeof(bpfSessionValue{}))
	ConntrackSessionValueSizeV6 = uint32(unsafe.Sizeof(bpfSessionValueV6{}))
)

// On-map conntrack ABI types (#2360).
//
// The shared kernel-visible `sessions` / `sessions_v6` BPF HASH maps store the
// C `struct session_value` / `struct session_value_v6` layout (bpf/headers/
// xpf_conntrack.h), which the Rust helper mirrors as BpfSessionValueV4 (152
// bytes) / BpfSessionValueV6 (200 bytes) — test-asserted at
// userspace-dp/src/afxdp/bpf_map_tests.rs.
//
// SessionValue / SessionValueV6 (types.go) carry EXTRA sync-only trailing
// fields the on-map ABI omits — `Generation uint64` (the #2170 HA
// deferred-delete install-generation guard), `PolicyCounterIdx uint32` (#3301),
// and (v6) `Nat64SnatV4 [4]byte` (#4565). Those live in the Go session table
// and travel on the cluster session-sync wire (pkg/cluster/sync_protocol.go,
// its own length-gated byte codec), and are deliberately NOT part of the BPF C
// conntrack struct. So SessionValue is strictly larger than the on-map layout.
//
// Registering the map at sizeof(SessionValue) (the previous behaviour) made the
// kernel value_size larger than every reader/writer's on-map struct. A
// bpf_map_lookup_elem from the Rust side into its 152/200-byte buffer then has
// the kernel copy the larger value_size bytes into the smaller buffer — a
// stack out-of-bounds write (latent because the trailing bytes are usually
// zero). See issue #2360.
//
// bpfSessionValue / bpfSessionValueV6 are the dedicated on-map ABI types:
// identical to SessionValue / SessionValueV6 minus the sync-only Generation.
// They are the size used for map registration AND for every map I/O (Update /
// Lookup / Iterate / Batch), so cilium/ebpf marshals exactly the C layout. The
// Go-facing accessors convert at the boundary; Generation never touches the
// BPF map (it is sourced from the Go session table / sync path).

// bpfSessionValue mirrors C `struct session_value` exactly (152 bytes; 144 before the #9546 routing_domain append, 136
// before the #4983 ingress-identity growth, 128 before the #5460 __u16 flags
// widen). It is SessionValue without the sync-only trailing fields. Keep
// field-for-field in sync with both SessionValue (types.go) and the C struct
// (xpf_conntrack.h); the parity test in bpf_session_value_test.go fails if the
// size drifts from 152.
//
// EXPLICIT PADDING (#6082): every byte the C/Go compiler inserts as implicit
// alignment padding is declared as a named `_ [N]byte` gap. This is NOT
// cosmetic — cilium/ebpf's map I/O (Lookup / Iterate / BatchLookup, via
// internal/sysenc.Unmarshal) takes a zero-copy fast path ONLY when
// binary.Size(T) == unsafe.Sizeof(T) (it compares encoding/binary's field-sum
// size against the native slice-element size). encoding/binary does not count
// implicit padding, so with the three head gaps left implicit binary.Size was
// 129 while unsafe.Sizeof was 136 (the struct's size at the time of #6082);
// sysenc then fell back to binary.Decode, which consumed only 129 of every 136
// kernel value bytes and failed the whole batch
// with "unmarshaling []dataplane.bpfSessionValue doesn't consume all data",
// breaking the 60s HA session-sync sweep. Making the padding explicit keeps
// binary.Size == unsafe.Sizeof (152 today, post-#9546) (blank `_` fields ARE counted by
// encoding/binary yet do NOT count as "unexported" for the fast path), so the
// zero-copy path stays engaged. The on-map ABI bytes are unchanged: these pads
// occupy the exact offsets the compiler already padded, so unsafe.Sizeof and
// every real field offset are byte-identical to before.
type bpfSessionValue struct {
	State uint8
	_     [1]byte // pad: C aligns __u16 flags after state (#5460 __u16 widen; #6082)
	// uint16 to match C `struct session_value.flags` (SessFlagNPTV6 = bit 8, #5460).
	Flags      uint16
	TCPState   uint8
	IsReverse  uint8
	_          [2]byte // pad: C aligns __u32 app_timeout (#6082)
	AppTimeout uint32
	_          [4]byte // pad: C aligns __u64 session_id to 8-byte boundary (#6082)

	SessionID uint64

	Created  uint64
	LastSeen uint64
	Timeout  uint32
	PolicyID uint32

	IngressZone uint16
	EgressZone  uint16

	NATSrcIP   uint32
	NATDstIP   uint32
	NATSrcPort uint16
	NATDstPort uint16

	FwdPackets uint64
	FwdBytes   uint64
	RevPackets uint64
	RevBytes   uint64

	ReverseKey SessionKey

	ALGType  uint8
	LogFlags uint8
	AppID    uint16

	FibIfindex uint32
	FibVlanID  uint16
	FibDmac    [6]byte
	FibSmac    [6]byte
	FibGen     uint16

	// IngressIfindex is the #4983 ingress-binding ifindex: the interface the
	// session's FIRST packet arrived on, stamped ONCE by the helper at install
	// (SessionMetadata.ingress_ifindex -> publish_conntrack) and never
	// re-derived from the zone. It is part of the C conntrack ABI
	// (session_value.ingress_ifindex), unlike the sync-only trailing fields on
	// SessionValue. 0 = no ingress identity carried; see
	// SessionValue.IngressIfindex for the full contract.
	IngressIfindex uint32
	// IngressVlanID is the #4983 ingress 802.1Q VLAN id. 0 means the first packet's VID was zero, which is BOTH an untagged frame AND an 802.1p priority-tagged one (a real 802.1Q tag with VID 0 and PCP/DEI set). The row stores a bare VID, so it does not distinguish them; the TX side does, via TxVlanTag on tag PRESENCE (#2149, userspace-dp/src/afxdp/README.md). Do not read 0 as "arrived untagged" (#6928).
	// It lands inside the tail padding IngressIfindex already forced, so the
	// pair costs 8 bytes total, not 16.
	IngressVlanID uint16
	_             [2]byte // pad: C aligns __u32 routing_domain to a 4-byte boundary (#9546)
	// RoutingDomain is the #9546 on-map copy of SessionValue.RoutingDomain (the
	// #7239 wire-encoded domain). See that field for the contract; the layout
	// reason it is appended here, not inserted earlier, is that no existing
	// offset may move.
	RoutingDomain uint32
	_             [4]byte // pad: C tail-pads the struct to its 8-byte alignment (#6082)
}

// bpfSessionValueV6 mirrors C `struct session_value_v6` exactly (200 bytes; 192 before the #9546 routing_domain append, 184
// before the #4983 ingress-identity growth, 176 before the #5460 __u16 flags
// widen). It is SessionValueV6 without the
// sync-only trailing fields. The head padding is declared explicitly for the
// same cilium/ebpf marshal-size reason as bpfSessionValue (#6082) — see that
// type's doc comment.
type bpfSessionValueV6 struct {
	State uint8
	_     [1]byte // pad: C aligns __u16 flags after state (#5460 __u16 widen; #6082)
	// uint16 to match C `struct session_value_v6.flags` (see bpfSessionValue, #5460).
	Flags      uint16
	TCPState   uint8
	IsReverse  uint8
	_          [2]byte // pad: C aligns __u32 app_timeout (#6082)
	AppTimeout uint32
	_          [4]byte // pad: C aligns __u64 session_id to 8-byte boundary (#6082)

	SessionID uint64

	Created  uint64
	LastSeen uint64
	Timeout  uint32
	PolicyID uint32

	IngressZone uint16
	EgressZone  uint16

	NATSrcIP   [16]byte
	NATDstIP   [16]byte
	NATSrcPort uint16
	NATDstPort uint16

	FwdPackets uint64
	FwdBytes   uint64
	RevPackets uint64
	RevBytes   uint64

	ReverseKey SessionKeyV6

	ALGType  uint8
	LogFlags uint8
	AppID    uint16

	FibIfindex uint32
	FibVlanID  uint16
	FibDmac    [6]byte
	FibSmac    [6]byte
	FibGen     uint16

	// IngressIfindex is the #4983 ingress-binding ifindex: the interface the
	// session's FIRST packet arrived on, stamped ONCE by the helper at install
	// (SessionMetadata.ingress_ifindex -> publish_conntrack) and never
	// re-derived from the zone. It is part of the C conntrack ABI
	// (session_value.ingress_ifindex), unlike the sync-only trailing fields on
	// SessionValue. 0 = no ingress identity carried; see
	// SessionValue.IngressIfindex for the full contract.
	IngressIfindex uint32
	// IngressVlanID is the #4983 ingress 802.1Q VLAN id. 0 means the first packet's VID was zero, which is BOTH an untagged frame AND an 802.1p priority-tagged one (a real 802.1Q tag with VID 0 and PCP/DEI set). The row stores a bare VID, so it does not distinguish them; the TX side does, via TxVlanTag on tag PRESENCE (#2149, userspace-dp/src/afxdp/README.md). Do not read 0 as "arrived untagged" (#6928).
	// It lands inside the tail padding IngressIfindex already forced, so the
	// pair costs 8 bytes total, not 16.
	IngressVlanID uint16
	_             [2]byte // pad: C aligns __u32 routing_domain to a 4-byte boundary (#9546)
	// RoutingDomain is the #9546 on-map copy of SessionValue.RoutingDomain (the
	// #7239 wire-encoded domain). See that field for the contract; the layout
	// reason it is appended here, not inserted earlier, is that no existing
	// offset may move.
	RoutingDomain uint32
	_             [4]byte // pad: C tail-pads the struct to its 8-byte alignment (#6082)
}

// toBPF projects a SessionValue onto the on-map ABI layout, dropping the
// sync-only Generation. Used before any write to the BPF sessions map.
func (v SessionValue) toBPF() bpfSessionValue {
	return bpfSessionValue{
		State:       v.State,
		Flags:       v.Flags,
		TCPState:    v.TCPState,
		IsReverse:   v.IsReverse,
		AppTimeout:  v.AppTimeout,
		SessionID:   v.SessionID,
		Created:     v.Created,
		LastSeen:    v.LastSeen,
		Timeout:     v.Timeout,
		PolicyID:    v.PolicyID,
		IngressZone: v.IngressZone,
		EgressZone:  v.EgressZone,
		NATSrcIP:    v.NATSrcIP,
		NATDstIP:    v.NATDstIP,
		NATSrcPort:  v.NATSrcPort,
		NATDstPort:  v.NATDstPort,
		FwdPackets:  v.FwdPackets,
		FwdBytes:    v.FwdBytes,
		RevPackets:  v.RevPackets,
		RevBytes:    v.RevBytes,
		ReverseKey:  v.ReverseKey,
		ALGType:     v.ALGType,
		LogFlags:    v.LogFlags,
		AppID:       v.AppID,
		FibIfindex:  v.FibIfindex,
		FibVlanID:   v.FibVlanID,
		FibDmac:     v.FibDmac,
		FibSmac:     v.FibSmac,
		FibGen:      v.FibGen,
		// #4983: the ingress-binding ifindex is part of the on-map C ABI, so it
		// round-trips in BOTH directions (unlike the sync-only trailing fields).
		IngressIfindex: v.IngressIfindex,
		IngressVlanID:  v.IngressVlanID,
		RoutingDomain:  v.RoutingDomain,
	}
}

// sessionValue lifts an on-map entry back to SessionValue. Generation is left
// zero — the BPF map never stores it; the authoritative Generation lives in the
// Go session table / cluster sync path.
func (v bpfSessionValue) sessionValue() SessionValue {
	return SessionValue{
		State:       v.State,
		Flags:       v.Flags,
		TCPState:    v.TCPState,
		IsReverse:   v.IsReverse,
		AppTimeout:  v.AppTimeout,
		SessionID:   v.SessionID,
		Created:     v.Created,
		LastSeen:    v.LastSeen,
		Timeout:     v.Timeout,
		PolicyID:    v.PolicyID,
		IngressZone: v.IngressZone,
		EgressZone:  v.EgressZone,
		NATSrcIP:    v.NATSrcIP,
		NATDstIP:    v.NATDstIP,
		NATSrcPort:  v.NATSrcPort,
		NATDstPort:  v.NATDstPort,
		FwdPackets:  v.FwdPackets,
		FwdBytes:    v.FwdBytes,
		RevPackets:  v.RevPackets,
		RevBytes:    v.RevBytes,
		ReverseKey:  v.ReverseKey,
		ALGType:     v.ALGType,
		LogFlags:    v.LogFlags,
		AppID:       v.AppID,
		FibIfindex:  v.FibIfindex,
		FibVlanID:   v.FibVlanID,
		FibDmac:     v.FibDmac,
		FibSmac:     v.FibSmac,
		FibGen:      v.FibGen,
		// #4983: the ingress-binding ifindex is part of the on-map C ABI, so it
		// round-trips in BOTH directions (unlike the sync-only trailing fields).
		IngressIfindex: v.IngressIfindex,
		IngressVlanID:  v.IngressVlanID,
		RoutingDomain:  v.RoutingDomain,
	}
}

// toBPF projects a SessionValueV6 onto the on-map ABI layout, dropping the
// sync-only Generation.
func (v SessionValueV6) toBPF() bpfSessionValueV6 {
	return bpfSessionValueV6{
		State:       v.State,
		Flags:       v.Flags,
		TCPState:    v.TCPState,
		IsReverse:   v.IsReverse,
		AppTimeout:  v.AppTimeout,
		SessionID:   v.SessionID,
		Created:     v.Created,
		LastSeen:    v.LastSeen,
		Timeout:     v.Timeout,
		PolicyID:    v.PolicyID,
		IngressZone: v.IngressZone,
		EgressZone:  v.EgressZone,
		NATSrcIP:    v.NATSrcIP,
		NATDstIP:    v.NATDstIP,
		NATSrcPort:  v.NATSrcPort,
		NATDstPort:  v.NATDstPort,
		FwdPackets:  v.FwdPackets,
		FwdBytes:    v.FwdBytes,
		RevPackets:  v.RevPackets,
		RevBytes:    v.RevBytes,
		ReverseKey:  v.ReverseKey,
		ALGType:     v.ALGType,
		LogFlags:    v.LogFlags,
		AppID:       v.AppID,
		FibIfindex:  v.FibIfindex,
		FibVlanID:   v.FibVlanID,
		FibDmac:     v.FibDmac,
		FibSmac:     v.FibSmac,
		FibGen:      v.FibGen,
		// #4983: the ingress-binding ifindex is part of the on-map C ABI, so it
		// round-trips in BOTH directions (unlike the sync-only trailing fields).
		IngressIfindex: v.IngressIfindex,
		IngressVlanID:  v.IngressVlanID,
		RoutingDomain:  v.RoutingDomain,
	}
}

// sessionValue lifts an on-map v6 entry back to SessionValueV6. Generation is
// left zero (not stored in the BPF map).
func (v bpfSessionValueV6) sessionValue() SessionValueV6 {
	return SessionValueV6{
		State:       v.State,
		Flags:       v.Flags,
		TCPState:    v.TCPState,
		IsReverse:   v.IsReverse,
		AppTimeout:  v.AppTimeout,
		SessionID:   v.SessionID,
		Created:     v.Created,
		LastSeen:    v.LastSeen,
		Timeout:     v.Timeout,
		PolicyID:    v.PolicyID,
		IngressZone: v.IngressZone,
		EgressZone:  v.EgressZone,
		NATSrcIP:    v.NATSrcIP,
		NATDstIP:    v.NATDstIP,
		NATSrcPort:  v.NATSrcPort,
		NATDstPort:  v.NATDstPort,
		FwdPackets:  v.FwdPackets,
		FwdBytes:    v.FwdBytes,
		RevPackets:  v.RevPackets,
		RevBytes:    v.RevBytes,
		ReverseKey:  v.ReverseKey,
		ALGType:     v.ALGType,
		LogFlags:    v.LogFlags,
		AppID:       v.AppID,
		FibIfindex:  v.FibIfindex,
		FibVlanID:   v.FibVlanID,
		FibDmac:     v.FibDmac,
		FibSmac:     v.FibSmac,
		FibGen:      v.FibGen,
		// #4983: the ingress-binding ifindex is part of the on-map C ABI, so it
		// round-trips in BOTH directions (unlike the sync-only trailing fields).
		IngressIfindex: v.IngressIfindex,
		IngressVlanID:  v.IngressVlanID,
		RoutingDomain:  v.RoutingDomain,
	}
}

// SessionValueCreatedOffset / SessionValueSessionIDOffset are the on-map byte
// offsets of `Created` and `SessionID` in the shared conntrack session value,
// DERIVED from the struct rather than written down (#6816).
//
// They are exported because a consumer outside this package
// (pkg/dataplane/userspace's initial-control cleanup) decodes those two fields
// out of a raw []byte read straight from the BPF map, and it had the offset
// WRONG: it read bytes [16:24] as `Created` on the strength of an in-comment sum
//
//	State(1) + Flags(1) + TCPState(1) + IsReverse(1) + AppTimeout(4) + SessionID(8) = 16
//
// which is wrong twice over. `Flags` is a uint16 since #5460, and the struct
// carries three explicit padding gaps (#6082) that the sum omits entirely.
// SessionID sits at 16 and Created at 24, so the cleanup was reading a session
// ID and comparing it against a seconds-since-boot cutoff.
//
// Deriving them with unsafe.Offsetof is the point: the offset and the layout
// MUST agree, and a derived value cannot disagree. A literal can — and did, for
// as long as it took two ABI changes to move the field out from under it. Any
// future field insertion, padding change or type widen moves these with it.
var (
	SessionValueCreatedOffset   = int(unsafe.Offsetof(bpfSessionValue{}.Created))
	SessionValueSessionIDOffset = int(unsafe.Offsetof(bpfSessionValue{}.SessionID))
)
