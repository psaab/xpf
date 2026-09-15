package userspace

// NatPortRangeWire is one inclusive [Low,High] L4 destination-port range on the
// Go->Rust source-NAT match wire (#3429). A single port is Low==High. Used by
// SourceNATRuleSnapshot.MatchDestinationPorts and inside NatAppTermWire.Ports.
type NatPortRangeWire struct {
	Low  uint16 `json:"low"`
	High uint16 `json:"high"`
}

// NatAppTermWire is one resolved source-NAT `match application` term (#3429): an
// L4 protocol (IANA number; 256 = any/unspecified — outside the 0-255 protocol
// range so it never aliases protocol 0/HOPOPT) and optional destination- and
// source-port ranges. The flow matches the term when its protocol equals
// Protocol (or Protocol==256) AND, if Ports is non-empty, its destination port
// falls in one of the dest ranges, AND, if SrcPorts is non-empty, its source
// port falls in one of the source ranges. An application-set expands to one term
// per resolved member.
//
// SrcPorts carries the application's `source-port` constraint (#3491). It is an
// additive wire field (#1961 skew-safe): an older Go binary omits it (omitempty)
// and an older Rust helper that does not know the field treats the term as
// source-port-unconstrained — the pre-#3491 over-match. Empty = match any source
// port. When the application configured a source-port but every value is
// unrepresentable, the Go builder substitutes the never-match sentinel
// ({Low:1,High:0}) so the term fails CLOSED rather than widening to any source
// port (mirrors the #3429 dest-port handling).
type NatAppTermWire struct {
	Protocol uint16             `json:"protocol"`
	Ports    []NatPortRangeWire `json:"ports,omitempty"`
	SrcPorts []NatPortRangeWire `json:"src_ports,omitempty"`
}

type SourceNATRuleSnapshot struct {
	Name     string `json:"name"`
	FromZone string `json:"from_zone,omitempty"`
	ToZone   string `json:"to_zone,omitempty"`
	// #3096: interface- and routing-instance-scoped rule-set matching.
	// FromInterface/ToInterface restrict the rule to traffic
	// ingressing/egressing the named logical interface (config name);
	// FromRoutingInstance/ToRoutingInstance restrict it to the named
	// ingress/egress routing instance (VRF). "" = unscoped on that axis (the
	// pre-#3096 behavior). Additive wire fields: an old Rust helper without
	// them treats every rule as zone-only-scoped (the pre-#3096 silent global
	// widening); an old Go binary omits them (omitempty). The Rust match path
	// AND-s every non-empty scope: a rule fires only when the flow's
	// ingress/egress interface and routing instance match every set field.
	FromInterface        string   `json:"from_interface,omitempty"`
	ToInterface          string   `json:"to_interface,omitempty"`
	FromRoutingInstance  string   `json:"from_routing_instance,omitempty"`
	ToRoutingInstance    string   `json:"to_routing_instance,omitempty"`
	SourceAddresses      []string `json:"source_addresses,omitempty"`
	DestinationAddresses []string `json:"destination_addresses,omitempty"`
	InterfaceMode        bool     `json:"interface_mode,omitempty"`
	Off                  bool     `json:"off,omitempty"`
	PoolName             string   `json:"pool_name,omitempty"`
	PoolAddresses        []string `json:"pool_addresses,omitempty"`
	PortLow              uint16   `json:"port_low,omitempty"`
	PortHigh             uint16   `json:"port_high,omitempty"`
	// PoolNoTranslation carries the source-pool `port no-translation` modifier
	// (#3906). When true the dataplane translates the source address but
	// PRESERVES the original source port (Junos 1:1 source-port behaviour): it
	// takes the address-only path and leaves rewrite_src_port unset, so the
	// packet keeps its L4 source port and PortLow/PortHigh are ignored. Before
	// #3906 the token was silently dropped and the pool PAT-translated the port
	// anyway. Additive wire field (#1961): an old helper without it
	// PAT-translates the port (pre-#3906 behaviour); an old Go binary omits it.
	PoolNoTranslation                bool `json:"pool_no_translation,omitempty"`
	AddressPersistent                bool `json:"address_persistent,omitempty"`
	PersistentNAT                    bool `json:"persistent_nat,omitempty"`
	PersistentNATPermitAnyRemoteHost bool `json:"persistent_nat_permit_any_remote_host,omitempty"`
	// PersistentNATPermit carries the full three-way Junos
	// `persistent-nat permit` enum (#2823): "any-remote-host",
	// "target-host", or "target-host-port". Empty => the helper falls back
	// to the PersistentNATPermitAnyRemoteHost bool (old-Go / old-helper
	// skew). #2823.
	PersistentNATPermit            string `json:"persistent_nat_permit,omitempty"`
	PersistentNATInactivityTimeout int    `json:"persistent_nat_inactivity_timeout,omitempty"`
	PoolUnusable                   bool   `json:"pool_unusable,omitempty"`
	PoolUnusableReason             string `json:"pool_unusable_reason,omitempty"`
	// MatchDestinationPorts carries the source-NAT rule's `match
	// destination-port` constraint as inclusive [Low,High] ranges (#3429).
	// Empty = unconstrained on destination port (match any port, the
	// pre-#3429 behaviour). Non-empty = the flow's destination port MUST fall
	// in one of the ranges, otherwise the rule does NOT match (so a port-scoped
	// SNAT — including a `then source-nat off` exemption — no longer silently
	// widens to every port). Additive wire field: an old helper without it
	// treats every rule as port-unconstrained (the pre-#3429 over-match); an
	// old Go binary omits it (omitempty).
	MatchDestinationPorts []NatPortRangeWire `json:"match_destination_ports,omitempty"`
	// MatchApplications carries the source-NAT rule's `match application`
	// constraint, pre-expanded to (protocol, destination-port ranges) terms at
	// snapshot build (#3429). Empty = unconstrained on application. Non-empty =
	// the flow's protocol/destination port MUST satisfy one of the terms,
	// otherwise the rule does NOT match. An application-set expands to one term
	// per resolved member. Additive wire field, same skew semantics as
	// MatchDestinationPorts.
	MatchApplications []NatAppTermWire `json:"match_applications,omitempty"`
	// DeterministicMode carries the source-pool `port deterministic block-size`
	// CGNAT mode (#4559). 0 = off (round-robin/sticky PAT, the pre-#4559
	// behaviour). 1 = IPv4-subscriber deterministic block allocation: each
	// in-range subscriber IPv4 maps to a fixed external pool address + port
	// block, so the (external IP, port) -> subscriber reverse mapping needs no
	// per-flow log (lawful-intercept / CGN audit). Mode 2 (IPv6 subscriber /
	// NAT64) is not yet enforced by the dataplane; the builder leaves this 0 for
	// an IPv6 host so the pool round-robins and the commit-time advisory
	// (compiler_validate_warn.go) still surfaces the gap. Additive wire field
	// (#1961 skew-safe): an old helper ignores it and round-robins.
	DeterministicMode uint8 `json:"deterministic_mode,omitempty"`
	// DeterministicBlockSize is the per-subscriber port block size (Junos
	// `block-size`, e.g. 2016). Meaningful only when DeterministicMode != 0.
	DeterministicBlockSize uint16 `json:"deterministic_block_size,omitempty"`
	// DeterministicBlocksPerIP is how many blocks each external pool address
	// carries ((PortHigh-PortLow+1)/BlockSize), precomputed against the SAME
	// defaulted port range this snapshot carries so block boundaries align
	// between the compiler and the dataplane (#4559).
	DeterministicBlocksPerIP uint16 `json:"deterministic_blocks_per_ip,omitempty"`
	// DeterministicHostBase is the subscriber-CIDR network address as a
	// host-order uint32 (IPv4). The subscriber index is
	// host_order(src) - DeterministicHostBase (#4559).
	DeterministicHostBase uint32 `json:"deterministic_host_base,omitempty"`
	// DeterministicHostCount is the number of subscriber addresses in the host
	// CIDR (1 << (32-prefix_len) for IPv4). A source whose index is >= this is
	// outside the deterministic range and the allocation fails closed (#4559).
	DeterministicHostCount uint32 `json:"deterministic_host_count,omitempty"`
	// CounterID is the compiler-assigned per-rule translation hit counter ID
	// (stable key-derived hash, non-zero; 0 means "no counter"). The userspace
	// dataplane attributes each SNAT translation on this rule to this slot, and
	// Manager.ReadNATRuleCounter reads it back for `show security nat source
	// rule` (#2218). The ID is stable across config reorder/removal (#2255), so
	// it is u32-wide; the JSON wire is unchanged (a number is width-agnostic).
	CounterID uint32 `json:"counter_id,omitempty"`
	// LenientMatchDropped carries the #9874 poison: the rule AUTHORED a
	// `match` container that constrains NOTHING, which the #8430 strict gate
	// rejects at commit and the tolerant load / peer-sync path downgrades to
	// a warning. The dataplane reads an empty match set as UNCONSTRAINED, so
	// without this marker the rule installs as a catch-all translator. The
	// Rust source-NAT table fails such a rule CLOSED (an in-scope flow gets
	// Unavailable / drop + count, never a translation — including for `off`
	// rules, whose exemption short-circuit would otherwise exempt every flow
	// in scope). A scope-only rule (no `match` at all) leaves this false and
	// still installs unconstrained, which is the legitimate catch-all.
	//
	// Additive wire field (#1961): an old Go binary omits it (omitempty) and
	// an old helper decodes it false. That pairing keeps the pre-#9874
	// catch-all, which is the defect rather than an acceptable degradation —
	// so this field rides the v19 protocol bump (the v9 rule), and the
	// exact-equality gate refuses the mismatched pairing instead of
	// degrading silently.
	LenientMatchDropped bool `json:"lenient_match_dropped,omitempty"`
}

type StaticNATRuleSnapshot struct {
	Name     string `json:"name"`
	FromZone string `json:"from_zone,omitempty"`
	// #3096: interface- / routing-instance-scoped static NAT. Static NAT has
	// only a `from` clause (no `to`); the scope is enforced on the inbound
	// (DNAT) direction against the ingress interface/VRF and, symmetrically,
	// on the reverse (SNAT) direction against the egress interface/VRF — the
	// same dual-direction treatment FromZone already gets. "" = unscoped on
	// that axis. Additive wire fields (see SourceNATRuleSnapshot).
	FromInterface       string `json:"from_interface,omitempty"`
	FromRoutingInstance string `json:"from_routing_instance,omitempty"`
	// SourceAddresses carries the static-NAT rule's `match source-address`
	// constraint (#3435). Junos static NAT `source-address` restricts which
	// client source IPs the 1:1/DNAT translation fires for; before #3435 the
	// constraint was parsed but DROPPED at this snapshot boundary, so the
	// dataplane installed an all-source mapping that exposed the internal
	// host to ANY source in the from-scope (fail-open, H01) — the static-NAT
	// analog of the DNAT #2394 fix. Each entry is a CIDR prefix
	// (198.51.100.0/24) or a bare host IP (198.51.100.42), carried verbatim.
	// An empty slice means "match any source" (unscoped, unchanged behavior);
	// a non-empty slice whose entries all fail to parse fails CLOSED (matches
	// no source) on the Rust side rather than reverting to match-any. The
	// inbound (DNAT) direction matches the packet SOURCE against this list;
	// the reverse (SNAT) direction matches the packet DESTINATION (the
	// original client). Additive wire field (#1961 skew-safe).
	SourceAddresses []string `json:"source_addresses,omitempty"`
	ExternalIP      string   `json:"external_ip"`
	InternalIP      string   `json:"internal_ip"`
	// MatchDestinationPort is the external (pre-translation) destination port
	// the inbound packet must carry for this port-mapped static-NAT rule
	// (Junos `match destination-port`). 0 = match any port (whole-address
	// 1:1, the legacy behaviour). #2491.
	MatchDestinationPort uint16 `json:"match_destination_port,omitempty"`
	// MappedPort is the internal (post-translation) destination port the 1:1
	// host receives (Junos `then static-nat prefix <ip> mapped-port <port>`).
	// 0 = no port translation. When set, the inbound DNAT rewrites the
	// destination port to this value and the reverse-path SNAT un-translates
	// it back to MatchDestinationPort. #2491.
	MappedPort uint16 `json:"mapped_port,omitempty"`
	// CounterID is the compiler-assigned per-rule translation hit counter ID
	// (stable key-derived hash, non-zero; 0 means "no counter") for this static
	// NAT rule (#2218; stable across reorder/removal, #2255).
	CounterID uint32 `json:"counter_id,omitempty"`
}

// DestinationNATRuleSnapshot captures a pre-expanded DNAT table entry for the
// userspace dataplane. Each snapshot is one (protocol, destination IP, destination port)
// tuple. The Go builder handles multi-port and protocol expansion.
type DestinationNATRuleSnapshot struct {
	Name     string `json:"name"`
	FromZone string `json:"from_zone,omitempty"`
	// #3096: interface- / routing-instance-scoped DNAT. DNAT has only a
	// `from` clause, enforced against the INGRESS interface/VRF (DNAT
	// translates the destination on inbound). "" = unscoped on that axis.
	// Additive wire fields (see SourceNATRuleSnapshot).
	FromInterface       string `json:"from_interface,omitempty"`
	FromRoutingInstance string `json:"from_routing_instance,omitempty"`
	// SourceAddresses carries the DNAT rule's `match source-address`
	// constraint (#2394). Junos DNAT `source-address` restricts which source
	// IPs the destination translation applies to; before #2394 the constraint
	// was parsed but DROPPED at this snapshot boundary, so the dataplane
	// installed a destination-only entry that DNAT'd traffic from ANY source
	// (a fail-open security broadening). Each entry is either a CIDR prefix
	// (e.g. 198.51.100.0/24) or a bare host IP (e.g. 198.51.100.42); the
	// compiler carries the configured value verbatim (no CIDR normalization).
	// The Rust DNAT parser tries IpNet first and falls back to a bare IP -> /32
	// or /128, since IpNet rejects a bare IP. An empty slice means "match any
	// source" (unscoped DNAT, unchanged behavior); a non-empty slice whose
	// entries all fail to parse fails CLOSED (matches no source) on the Rust
	// side rather than reverting to match-any.
	SourceAddresses    []string `json:"source_addresses,omitempty"`
	DestinationAddress string   `json:"destination_address"`
	// DestinationPrefix carries the DNAT `match destination-address` as a
	// non-host CIDR prefix (#3164). Junos permits a multi-host prefix (e.g.
	// 198.51.100.0/24) as a DNAT destination match: every host in the block
	// matches and is translated to the rule's pool. It is ADDITIVE over
	// DestinationAddress (#1961 byte-aligned wire evolution): for a host
	// destination (a bare IP, /32, or /128) this stays empty and the exact
	// DestinationAddress fast path is used unchanged. For a non-host prefix it
	// holds the canonical masked CIDR ("198.51.100.0/24") and DestinationAddress
	// holds that prefix's network address (the base, kept for back-compat with
	// an older helper — which would then match only the base, the pre-#3164
	// behavior — and as the local-address registration anchor). The Rust DNAT
	// table parses this into a prefix entry and matches with longest-prefix
	// semantics; a host destination still keys the O(1) exact hash map.
	DestinationPrefix string `json:"destination_prefix,omitempty"`
	DestinationPort   uint16 `json:"destination_port,omitempty"`
	// Protocol is the Junos config protocol token the DNAT rule matches:
	// "tcp", "udp", "icmp", "icmp6"/"icmpv6", "gre", another known name, a
	// bare 0-255 number, or "" (any). #2396: the Rust DNAT table resolves the
	// token through the shared SSOT (ip_proto::proto_number, which mirrors
	// appid.ProtocolNumber) so a non-TCP/UDP DNAT (e.g. GRE/ICMP) is honored
	// rather than silently dropped. A concrete number maps to its exact IANA
	// value — INCLUDING "0" (HOPOPT), which is a normal exact match, NOT the
	// wildcard. Only "" with no destination port is the IP-only / any-protocol
	// rule; the Rust table keys it under a wildcard sentinel (PROTO_ANY = 256,
	// outside the 0-255 protocol range, so it never aliases protocol 0) so it
	// covers ALL L4 protocols including ICMP/ICMPv6/GRE. The token is
	// normalized (trim + lower-case) on both sides before resolution, and an
	// unresolvable token is rejected at commit by
	// validateDestinationNATProtocolStrict.
	Protocol    string `json:"protocol,omitempty"`
	PoolAddress string `json:"pool_address"`
	PoolPort    uint16 `json:"pool_port,omitempty"`
	// MatchDestinationPorts carries a MULTI-port `match destination-port` range
	// as inclusive [Low,High] ranges (#3449) so a wide range is NOT expanded
	// into one exact-port snapshot per port (a control-plane amplification
	// hazard: `destination-port 1 to 65535` produced 65 535 table entries). A
	// single port keeps the exact `DestinationPort` O(1) fast path (this empty,
	// DestinationPort set); a multi-port range is emitted as ONE wildcard-port
	// entry (DestinationPort == 0) whose MatchDestinationPorts the Rust
	// l4_extra_matches AND-checks against the flow's destination port (mirroring
	// the DNAT MatchSourcePorts and source-NAT MatchDestinationPorts ranges).
	// Empty = no range constraint — the exact/wildcard DestinationPort governs
	// (unchanged behaviour for the common single-port and IP-only rules).
	// Additive wire field (#1961 skew-safe): an older helper that does not know
	// it treats a DestinationPort==0 entry as match-ANY-port (a transient
	// fail-OPEN widening of that one entry during the upgrade window — the same
	// tradeoff the source-NAT range field carries); an older Go binary omits it
	// (omitempty) and the newer helper falls back to the per-port DestinationPort
	// expansion such a binary still emits. A range with Low>High is an impossible
	// (never-match) constraint preserved verbatim, like the source-port sentinel.
	MatchDestinationPorts []NatPortRangeWire `json:"match_destination_ports,omitempty"`
	// MatchSourcePorts carries the source-port constraint of the DNAT rule's
	// `match application <app>` term as inclusive [Low,High] ranges (#3437,
	// H10). When a DNAT rule matches via an application that pins a
	// `source-port` (e.g. a back-channel data app), the translation must only
	// fire for flows whose source port falls in the application's range; the
	// pre-#3437 builder dropped it, so ANY source port hitting the destination
	// port was translated (a fail-open NAT widening). Empty = source-port
	// unconstrained (the common case; an application with no source-port). A
	// non-empty set whose only entry is the never-match sentinel ({Low:1,
	// High:0}) is the fail-CLOSED marker for a source-port that WAS configured
	// but coalesced to nothing (every value out of 1..65535) — it matches no
	// source port rather than widening to any. Additive wire field (#1961
	// skew-safe): an older helper without it treats every entry as
	// source-port-unconstrained (the pre-#3437 over-match); an older Go binary
	// omits it.
	MatchSourcePorts []NatPortRangeWire `json:"match_source_ports,omitempty"`
	// MatchICMPType / MatchICMPCode carry the ICMP/ICMPv6 type[,code]
	// constraint of the DNAT rule's `match application <app>` term (#3437,
	// H11). An ICMP application pins a single message type (e.g. junos-ping =
	// ICMP echo-request, type 8) and optionally a code; the pre-#3437 builder
	// reduced the app to protocol + (absent) destination-port only, so a
	// `match application junos-ping` DNAT rule translated EVERY ICMP type
	// (errors, replies, non-echo) to the VIP — regressing the #3020 / #3194
	// ICMP type/code parity already enforced on the policy path. nil = no ICMP
	// type/code constraint (match every type/code of the protocol, the
	// historical behavior the all-ICMP aliases keep). When MatchICMPType is
	// non-nil the flow's ICMP type MUST equal it, and when MatchICMPCode is
	// also non-nil the code MUST equal it, otherwise the rule does NOT match.
	// A non-ICMP flow never satisfies an ICMP-type-constrained entry, so it
	// fails CLOSED. Additive wire fields, same skew semantics as
	// MatchSourcePorts.
	MatchICMPType *uint8 `json:"match_icmp_type,omitempty"`
	MatchICMPCode *uint8 `json:"match_icmp_code,omitempty"`
	// Off carries a `then destination-nat off` no-translate EXEMPTION (#3844).
	// Junos DNAT rules are ordered; a rule whose action is `off` matches the
	// traffic but applies NO translation and STOPS evaluation, so a later DNAT
	// rule cannot re-translate it. Before #3844 the off rule compiled to an
	// empty Then and was dropped at this snapshot boundary — the "exempted"
	// traffic fell through and was DNAT'd by a later matching rule (a fail-open
	// security defect). An off entry carries its full destination/source/
	// protocol/port MATCH (so the exemption is scoped exactly like a translate
	// rule would be) but an empty PoolAddress; the Rust DnatTable recognizes
	// the Off flag, returns NO translation, and short-circuits the remaining
	// proto/port/prefix tiers for that flow. An off destination is NOT
	// registered as a firewall-local address (no proxy-ARP/ND) — it is a real
	// host reachable via routing, not a VIP the firewall owns. Additive wire
	// field (#1961 skew-safe): an older helper without it ignores the field
	// and (because an off entry carries no pool address) drops the entry as a
	// pool-less DNAT rule — reverting to the pre-#3844 fail-open, never a
	// crash; the commit-side compiles it identically on both binaries.
	Off bool `json:"off,omitempty"`
	// CounterID is the compiler-assigned per-rule translation hit counter ID
	// (stable key-derived hash, non-zero; 0 means "no counter"). All expanded
	// (protocol, port) tuples of the same DNAT rule share one counter ID so
	// every hit attributes to a single slot read back for `show security nat
	// destination rule` (#2218; stable across reorder/removal, #2255).
	CounterID uint32 `json:"counter_id,omitempty"`
}

// NAT64RuleSnapshot captures a NAT64 prefix and its IPv4 source pool for the
// userspace dataplane.
type NAT64RuleSnapshot struct {
	Name          string   `json:"name"`
	Prefix        string   `json:"prefix"`         // e.g. "64:ff9b::/96"
	PoolAddresses []string `json:"pool_addresses"` // resolved IPv4 pool addresses
	// NoV6FragHeader mirrors the global `security nat natv6v4
	// no-v6-frag-header` knob. This is an option-gated LOCAL DF policy (not the
	// size-driven RFC 7915 5.1 selection): when set, the IPv6->IPv4 translator
	// clears DF so the translated IPv4 packet stays fragmentable (DF=0,
	// non-atomic) and carries a generated non-zero, non-repeating
	// Identification (RFC 6864 4.1) instead of the default DF=1 atomic framing.
	// Replicated onto every NAT64 rule because the option is configured once at
	// the natv6v4 level, not per rule-set.
	NoV6FragHeader bool `json:"no_v6_frag_header,omitempty"`
	// #4559: IPv6-subscriber deterministic CGNAT (mode 2, NAPT64). These carry
	// the referenced source pool's `port deterministic` block-allocation params
	// so the userspace dataplane maps each IPv6 subscriber to a fixed external
	// IPv4 + port block (reversible from (external IPv4, port) without per-flow
	// state), enforcing the CGN-compliance mapping instead of round-robin PAT.
	// Non-zero / non-empty ONLY when the pool has an ENFORCED IPv6 host (a /32 or
	// /64 subscriber prefix); an unsupported prefix, a v4 host (mode 1, carried
	// on SourceNATRuleSnapshot), or no deterministic stanza leaves them zero and
	// the pool round-robins.
	//
	// DeterministicBlockSize is the per-subscriber port block size (Junos
	// `block-size`).
	DeterministicBlockSize uint16 `json:"deterministic_block_size,omitempty"`
	// DeterministicBlocksPerIP is how many blocks each external pool address
	// carries, computed against the FIXED NAT64 translated-port range
	// (1024..65535, nat64PortLow/High) so block boundaries align with the Rust
	// NAT64 allocator (which ignores the source pool's own port range).
	DeterministicBlocksPerIP uint16 `json:"deterministic_blocks_per_ip,omitempty"`
	// DeterministicHostPrefixLen is the IPv6 subscriber-prefix length: 32 or 64.
	// It selects the 32-bit subscriber-index word (offset 4 for /32, offset 8 for
	// /64), mirroring the retired-eBPF nat_pool_alloc_deterministic_v6 split.
	DeterministicHostPrefixLen uint8 `json:"deterministic_host_prefix_len,omitempty"`
	// DeterministicHostBaseV6 is the IPv6 subscriber-CIDR network base (canonical
	// string, e.g. "2001:db8::"). The dataplane parses it to the 16-octet base it
	// derives the subscriber word from and reverses against. Empty => not a
	// deterministic NAPT64 pool.
	DeterministicHostBaseV6 string `json:"deterministic_host_base_v6,omitempty"`
}

// Nptv6RuleSnapshot captures an NPTv6 (RFC 6296) stateless prefix translation
// rule for the userspace dataplane.
type Nptv6RuleSnapshot struct {
	Name           string `json:"name"`
	FromZone       string `json:"from_zone,omitempty"`
	InternalPrefix string `json:"internal_prefix"` // e.g. "fd35:1940:0027::/48"
	ExternalPrefix string `json:"external_prefix"` // e.g. "2602:fd41:0070::/48"
}
