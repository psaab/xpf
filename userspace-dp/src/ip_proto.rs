//! Canonical IANA IP protocol numbers shared across the dataplane.
//!
//! #1826: consolidates the per-module `const PROTO_*` duplicates (eight
//! files each carried their own `PROTO_TCP = 6` copy) into one crate-wide
//! home. These are load-bearing wire constants — the values must match
//! the IANA "Assigned Internet Protocol Numbers" registry and are used in
//! packet parsing, session keys, NAT/NAT64 translation, policy and filter
//! matching, and screen checks.

pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const PROTO_IGMP: u8 = 2;
pub(crate) const PROTO_IPIP: u8 = 4;
pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_EGP: u8 = 8;
pub(crate) const PROTO_UDP: u8 = 17;

/// Fixed UDP ports used by the IKE / NAT-T control plane.
pub(crate) const IKE_UDP_PORTS: [u16; 2] = [500, 4500];
pub(crate) const PROTO_IPV6: u8 = 41;
pub(crate) const PROTO_GRE: u8 = 47;
pub(crate) const PROTO_ESP: u8 = 50;
pub(crate) const PROTO_AH: u8 = 51;
pub(crate) const PROTO_ICMPV6: u8 = 58;
pub(crate) const PROTO_OSPF: u8 = 89;
pub(crate) const PROTO_PIM: u8 = 103;
pub(crate) const PROTO_VRRP: u8 = 112;
pub(crate) const PROTO_SCTP: u8 = 132;

/// Authoritative "this protocol carries a rewritable 16-bit L4 port pair"
/// predicate (#3111). True only for TCP and UDP — the protocols whose L4
/// header begins with a source port at offset +0 and a destination port at
/// +2 that source/destination NAT may translate.
///
/// Everything else is port-less for NAT purposes and MUST NOT have its
/// first L4 bytes rewritten:
///   - GRE (47) / ESP (50) / AH (51) / OSPF (89) / ICMP / ... have no port
///     field; writing a pseudo-port at offset +0/+2 corrupts the L4 header
///     (ESP SPI high half, GRE flags/version, OSPF type), breaking the
///     tunnel/adjacency.
///   - protocol 0 is the "L4 tuple unknown" sentinel used by the
///     address-only `match_source_nat` callers.
///   - SCTP (132) does have ports, but a CRC32c checksum rather than the
///     internet checksum the incremental-delta rewriters assume, so SNAT
///     has never rewritten SCTP ports — keeping it out of this predicate
///     preserves that long-standing behavior (one source of truth shared
///     by the allocator and the packet rewriters so the two cannot drift).
#[inline]
pub(crate) fn has_l4_ports(protocol: u8) -> bool {
    matches!(protocol, PROTO_TCP | PROTO_UDP)
}

/// Resolve a config-level protocol token to its IANA number.
///
/// #2396: the DNAT snapshot carries `protocol` as the Junos config string
/// (`"tcp"`, `"udp"`, `"icmp"`, `"icmp6"`/`"icmpv6"`, `"gre"`, ..., or a bare
/// 0-255 number). The Rust DNAT table used to recognize only `"tcp"`/`"udp"`
/// and silently DROP everything else (`_ => continue`), so a GRE/ICMP DNAT
/// rule compiled, committed, and never reached the dataplane. This resolver
/// mirrors the Go SSOT `appid.ProtocolNumber` (the table the commit-time gate
/// validates against) so the two views agree on the accepted set.
///
/// The specific `junos-*` protocol aliases the Go SSOT resolves
/// (`appid.ProtocolNumber`) are handled here too (#2505): a firewall
/// filter's `from protocol <token>` reaches the wire VERBATIM from the
/// parser (`compileFilterFrom` assigns `term.Protocol = nodeVal` with no
/// alias resolution), so a config `from protocol junos-gre` arrives as the
/// literal alias string. The Go filter commit gate
/// (`filterProtocolResolvable`, #2175/#2505) accepts exactly the
/// `appid.ProtocolNumber` set, so this resolver must accept the same aliases
/// or a gate-passing filter would silently lose its protocol constraint in
/// the dataplane (the #2505 fail-wide bug). An UNKNOWN `junos-foobar` is NOT
/// accepted (consistent with the gate, which rejects it). Returns `None` for
/// an unrecognized token; the DNAT commit gate
/// (validateDestinationNATProtocolStrict, #2396) and the filter commit gate
/// reject an unresolvable protocol so an inert rule never reaches the wire,
/// and the dataplane fails closed (rejecting the snapshot) on any that slip
/// through a tolerant load.
///
/// #2396 (Copilot fold): the token is trimmed and lower-cased before matching.
/// DNAT `match protocol` and an `application`'s `protocol` reach the wire
/// VERBATIM from the parser (`nodeVal`) — neither the parser nor the snapshot
/// builder normalizes — so a config `protocol GRE` or `protocol " icmp "`
/// would otherwise resolve to nothing here and be silently dropped. The Go
/// commit gate normalizes the same way (strings.TrimSpace + ToLower) before
/// validating, so the two views agree on the accepted set after normalization.
pub(crate) fn proto_number(name: &str) -> Option<u8> {
    match name.trim().to_ascii_lowercase().as_str() {
        "tcp" | "junos-tcp-any" => Some(PROTO_TCP),
        "udp" | "junos-udp-any" => Some(PROTO_UDP),
        "icmp" | "junos-icmp-all" | "junos-ping" => Some(PROTO_ICMP),
        "icmp6" | "icmpv6" | "icmp-v6" | "junos-icmp6-all" | "junos-pingv6" => Some(PROTO_ICMPV6),
        "gre" | "junos-gre" => Some(PROTO_GRE),
        "ospf" | "junos-ospf" => Some(PROTO_OSPF),
        "ipip" | "junos-ip-in-ip" | "junos-ipip" => Some(PROTO_IPIP),
        // #3393: IANA protocol 41 (IPv6 encapsulation). A firewall filter's
        // `from protocol ipv6` reaches the wire VERBATIM as the name "ipv6"
        // (filters.go emits term.Protocols unresolved; only the application
        // policy and NAT paths pre-canonicalize to a number). The Go filter
        // commit gate (filterProtocolResolvable) was widened to accept "ipv6"
        // when appid.ProtocolNumber("ipv6") was closed to 41, but proto_number
        // — the documented Rust mirror of appid.ProtocolNumber — was left
        // without the arm, so a gate-passing `from protocol ipv6` filter
        // committed yet failed snapshot compilation here with
        // UnrepresentableFilterProtocol (commit/apply drift, the #1961 class).
        // Resolving it restores the mirror invariant and closes the drift.
        "ipv6" => Some(PROTO_IPV6),
        "egp" => Some(PROTO_EGP),
        "igmp" => Some(PROTO_IGMP),
        "pim" => Some(PROTO_PIM),
        "ah" => Some(PROTO_AH),
        "esp" => Some(PROTO_ESP),
        "sctp" => Some(PROTO_SCTP),
        "vrrp" => Some(PROTO_VRRP),
        other => other.parse::<u8>().ok(),
    }
}
