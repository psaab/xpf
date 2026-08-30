// SessionKey + key-transform helpers extracted from session.rs (#1047 P2).
// Pure relocation — bodies are byte-for-byte identical except
// `reverse_wire_key` widened from `fn` (file-private) to
// `pub(super) fn` so session/mod.rs's SessionTable impl can still
// call it across the new module boundary.

use super::*;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct SessionKey {
    pub addr_family: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// #7188: the tunnel discriminator that participates in session identity
    /// for protocols with no L4 ports. `None` for every protocol that has no
    /// discriminator concept, which is everything but GRE — so this field
    /// leaves every existing protocol's identity byte-for-byte unchanged, and
    /// the `Hash`/`Eq` derives above keep doing the right thing for free.
    ///
    /// It is NOT a port: it is never matchable, never rendered in a port field,
    /// and never encoded onto a wire that carries ports (#7188 decision 5).
    pub discriminator: TunnelDiscriminator,
    /// #7160 (#2387): the ROUTING DOMAIN this flow belongs to — the
    /// discriminator that makes two tenants' identical 5-tuples two distinct
    /// sessions instead of one colliding entry.
    ///
    /// `0` is the default routing instance, so every single-VRF deployment
    /// keeps byte-identical session identity and the `Hash`/`Eq` derives above
    /// continue to do the right thing unchanged.
    ///
    /// Two properties make this field safe, and both are load-bearing:
    ///
    /// **It is CONFIG-DERIVED, never a kernel ifindex.** The value is
    /// `StableRoutingInstanceTableID(name)` — a pure FNV-1a function of the
    /// routing-instance NAME, gated at commit against collisions. Because it
    /// depends only on config, both HA nodes compute the SAME number for the
    /// same instance by construction, which is what makes it legal to put on
    /// the session-sync wire. #6928 settled the precedent in the other
    /// direction when it declined to sync `ingress_ifindex`: a node-local
    /// number names a different NIC on the peer, so carrying it across the
    /// cluster would produce a confidently wrong answer.
    ///
    /// **It is SAME-DIRECTION SYMMETRIC.** Every packet of a flow that
    /// arrives at the firewall the way the FORWARD packets did resolves the
    /// same domain, because it is a property of the ingress interface and
    /// nothing else (`forwarding::ingress_routing_domain`). Contrast
    /// `discriminator` above and #6928's `ingress_ifindex`/`ingress_vlan_id`,
    /// which sit on the session VALUE.
    ///
    /// **It is NOT reply-direction symmetric, and phase 2 (#7160) does not
    /// pretend otherwise.** A reply ingresses on the forward flow's EGRESS
    /// interface, and this dataplane's transit route lookup is not VRF-isolated
    /// — it uses the DEFAULT table unless a PBR term overrides it
    /// (`poll_descriptor/mod.rs`, and plan §3; per-VRF default FIB is Track
    /// B-ext, explicitly NOT a prerequisite). So a flow that ingresses on a
    /// routing-instance member interface and egresses out of the default
    /// instance is a real, working configuration whose two directions resolve
    /// DIFFERENT domains.
    ///
    /// That is why the transforms in this file split into two groups, and the
    /// split is load-bearing in both directions:
    ///
    ///   * `forward_wire_key`, `translated_session_key` and
    ///     `reverse_session_key` PRESERVE it. They name another key of the
    ///     SAME direction (the post-NAT forward tuple, a reverse entry's
    ///     translated alias) or navigate between the two halves of one flow,
    ///     so they must not lose the discriminator.
    ///   * `reverse_wire_key` and `reverse_canonical_key` deliberately ZERO
    ///     it. Those two build the REVERSE-MATCH index — the keys a REPLY is
    ///     looked up under — and a reply whose domain the forward direction
    ///     cannot predict must still find its session. Preserving the domain
    ///     there would blackhole every non-contained VRF flow's replies, which
    ///     is a forwarding outage, not a hardening.
    ///
    /// Zeroing the reverse-match keys does NOT give the cross-tenant collision
    /// back, and this is the part to check before touching either group.
    /// The collision #7160 exists to close is a FORWARD-direction one: tenant
    /// B's packets matching tenant A's conntrack entry and inheriting its
    /// cached egress, NAT and policy verdict. Forward lookups go through
    /// `key_to_handle` on this full key, domain included, so two tenants now
    /// hold two entries and neither can reach the other's. The reverse side
    /// keeps its isolation a different way: `find_forward_nat_match` walks the
    /// (1:N) reverse bucket in TWO passes and prefers a candidate whose
    /// forward session carries the reply's own domain, falling back to a
    /// domain-agnostic match only when no candidate shares it. Two contained
    /// tenants therefore demux exactly; a flow whose reply genuinely arrives
    /// in another domain still resolves, as it did before this field existed.
    ///
    /// Do not "optimise" the PRESERVING three to `Default::default()`, and do
    /// not "restore symmetry" on the zeroing two without also removing the
    /// two-pass preference in `session/lookup.rs` — each half is what makes
    /// the other correct, and every single-instance test passes either way.
    pub routing_domain: u32,
}

pub(crate) fn reply_matches_forward_session(
    forward_key: &SessionKey,
    nat: NatDecision,
    reply_key: &SessionKey,
) -> bool {
    reverse_wire_key(forward_key, nat) == *reply_key
        || reverse_canonical_key(forward_key, nat) == *reply_key
}

pub(crate) fn forward_wire_key(forward_key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        // #4074: the ICMP Query Identifier lives in `src_port` (`dst_port` is
        // always 0) and is a single symmetric field carried at the same offset
        // in both directions. Pool SNAT translates it (RFC 5508 §3.1), so the
        // forward wire key carries the translated id when the decision set one;
        // absent a translation this is `forward_key.src_port` — unchanged.
        (
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
            forward_key.dst_port,
        )
    } else {
        (
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
        )
    };
    let wire_src = nat.rewrite_src.unwrap_or(forward_key.src_ip);
    let wire_dst = nat.rewrite_dst.unwrap_or(forward_key.dst_ip);
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            std::net::IpAddr::V4(_) => libc::AF_INET as u8,
            std::net::IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        let proto = if af == libc::AF_INET as u8 && forward_key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && forward_key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            forward_key.protocol
        };
        (af, proto)
    } else {
        (forward_key.addr_family, forward_key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
        discriminator: Default::default(),
        routing_domain: forward_key.routing_domain,
    }
}

pub(crate) fn translated_session_key(key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        // #4074: translate the ICMP Query Identifier (in `src_port`) like a
        // port; `dst_port` stays 0. No translation => `key.src_port` unchanged.
        (nat.rewrite_src_port.unwrap_or(key.src_port), key.dst_port)
    } else {
        (
            nat.rewrite_src_port.unwrap_or(key.src_port),
            nat.rewrite_dst_port.unwrap_or(key.dst_port),
        )
    };
    SessionKey {
        addr_family: key.addr_family,
        protocol: key.protocol,
        src_ip: nat.rewrite_src.unwrap_or(key.src_ip),
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port,
        dst_port,
        discriminator: Default::default(),
        routing_domain: key.routing_domain,
    }
}

pub(super) fn reverse_wire_key(forward_key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        // #4074: the reply carries the SAME (translated) ICMP identifier at the
        // same offset, which the parser lifts into the reply's `src_port`. So
        // the reverse wire key's `src_port` is the translated id (not swapped
        // with `dst_port` the way a TCP/UDP port pair is), and `dst_port` stays
        // 0. This is what makes two hosts sharing a pool address + original id
        // demux — their translated ids differ, so their reverse keys differ.
        (
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
            forward_key.dst_port,
        )
    } else {
        (
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
        )
    };
    let wire_src = nat.rewrite_dst.unwrap_or(forward_key.dst_ip);
    let wire_dst = nat.rewrite_src.unwrap_or(forward_key.src_ip);
    // NAT64: the reverse (reply) packet is a different address family.
    // Determine the AF from the NAT-rewritten addresses.
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            std::net::IpAddr::V4(_) => libc::AF_INET as u8,
            std::net::IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        // ICMPv6 ↔ ICMP protocol mapping.
        let proto = if af == libc::AF_INET as u8 && forward_key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && forward_key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            forward_key.protocol
        };
        (af, proto)
    } else {
        (forward_key.addr_family, forward_key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
        discriminator: Default::default(),
        // #7160 (#2387): REVERSE-MATCH key — deliberately domain-agnostic.
        // See the `routing_domain` doc on SessionKey: a reply may legitimately
        // arrive in a different routing domain than the forward direction
        // resolved, so the bucket it is looked up under must not carry one.
        // The isolation lives in the two-pass preference in
        // `find_forward_nat_match`, not here.
        routing_domain: 0,
    }
}

pub(crate) fn reverse_canonical_key(forward_key: &SessionKey, _nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (forward_key.src_port, forward_key.dst_port)
    } else {
        (forward_key.dst_port, forward_key.src_port)
    };
    SessionKey {
        addr_family: forward_key.addr_family,
        protocol: forward_key.protocol,
        src_ip: forward_key.dst_ip,
        dst_ip: forward_key.src_ip,
        src_port,
        dst_port,
        discriminator: Default::default(),
        // #7160 (#2387): REVERSE-MATCH key — deliberately domain-agnostic, for
        // the same reason as `reverse_wire_key` above.
        routing_domain: 0,
    }
}

/// #7160 (#2387): the domain-agnostic form of a key, for looking one up in a
/// REVERSE-MATCH index.
///
/// `reverse_wire_key` / `reverse_canonical_key` build those index keys with
/// `routing_domain: 0`, so the arriving reply must be zeroed the same way
/// before it is used as a probe — otherwise a reply that DID resolve a domain
/// would look for a bucket that was never inserted. One named function so the
/// two halves of the convention cannot drift apart.
///
/// The reply's own domain is not discarded: the caller keeps it to run the
/// two-pass preference that restores per-domain demux (`find_forward_nat_match`).
pub(crate) fn reverse_match_key(key: &SessionKey) -> SessionKey {
    if key.routing_domain == 0 {
        return key.clone();
    }
    SessionKey {
        routing_domain: 0,
        ..key.clone()
    }
}

// Issue 70 / #994: `reverse_session_key` extracted from
// afxdp/session_glue (the audit's "abstraction-leak" junk drawer).
// Pure SessionKey + NatDecision → SessionKey transformation, fits
// alongside forward_wire_key / translated_session_key /
// reverse_canonical_key already in this file. Visibility widened
// from `pub(super)` (afxdp-internal) to `pub(crate)` so existing
// callers in afxdp/{ha,session_delta,session_glue}.rs continue to
// resolve through the session::* re-export.
//
// Note: the audit also called out resolution_target_for_session as
// a candidate to move here, but it takes &SessionFlow and SessionFlow
// lives in afxdp/types (46 references inside afxdp/ — moving it
// would be a much larger refactor). Left in session_glue for now.

pub(crate) fn reverse_session_key(key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        // #4074: the ICMP Query Identifier is a symmetric field, and this
        // function is called in BOTH directions:
        //   - forward→reverse (build the reverse companion key from the FORWARD
        //     entry + its FORWARD decision): the translated id lives in
        //     `rewrite_src_port` (= Y), so the companion is keyed on Y and the
        //     reply (which carries Y) demuxes to it.
        //   - reverse→forward (`account_packet` recovers the FORWARD entry key
        //     from the REVERSE entry + its REVERSE decision, session/mod.rs):
        //     `NatDecision::reverse` moved the ORIGINAL id into
        //     `rewrite_dst_port` (= X) and left `rewrite_src_port` None, so we
        //     must read `rewrite_dst_port` to recover X and hit the forward
        //     entry — reading only `rewrite_src_port` (=None → falls back to the
        //     reverse key's Y) misses it and mis-accounts the reply volume onto
        //     the reverse entry.
        // At most one of the two port fields is ever set for an ICMP flow (SNAT
        // sets only `rewrite_src_port` forward; its `.reverse()` sets only
        // `rewrite_dst_port`; ICMP DNAT is gated to no L4 port), so `.or()`
        // picks the right id in each direction. No translation => `key.src_port`
        // unchanged; `dst_port` stays 0.
        (
            nat.rewrite_src_port
                .or(nat.rewrite_dst_port)
                .unwrap_or(key.src_port),
            key.dst_port,
        )
    } else {
        (
            nat.rewrite_dst_port.unwrap_or(key.dst_port),
            nat.rewrite_src_port.unwrap_or(key.src_port),
        )
    };
    let wire_src = nat.rewrite_dst.unwrap_or(key.dst_ip);
    let wire_dst = nat.rewrite_src.unwrap_or(key.src_ip);
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        let proto = if af == libc::AF_INET as u8 && key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            key.protocol
        };
        (af, proto)
    } else {
        (key.addr_family, key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
        discriminator: Default::default(),
        routing_domain: key.routing_domain,
    }
}
