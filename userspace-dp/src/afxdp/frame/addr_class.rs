//! Address classification — is this address a broadcast, a multicast, a
//! directed broadcast, or an invalid ICMP-error source?
//!
//! Split out of `inspect.rs` per #6926, which crossed the 2000-LOC [REFACTOR]
//! tier. These seven functions were chosen because they are the one group in
//! that file with **zero** internal dependencies: they call nothing else defined
//! in `inspect.rs`, so the move carries the whole property rather than
//! scattering it. `inspect.rs` keeps header/offset walking, fragment
//! classification, and session-key parsing — each of which does depend on the
//! others.
//!
//! `v4_addr_is_directed_broadcast` is the group's private helper (no callers
//! outside it) and moves with the functions it serves.
//!
//! `inspect.rs` re-exports these so both call shapes in the tree keep working:
//! a bare `use` (icmp_ptb.rs) and the fully-qualified
//! `crate::afxdp::frame::inspect::l2_dst_is_group_or_broadcast` (tcp.rs).

use super::*;

/// #2314: RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e) — a router MUST NOT
/// originate an ICMP/ICMPv6 *error* in reply to a datagram whose IP
/// destination was a broadcast or multicast address. Reading the
/// destination straight off the L3-relative packet slice keeps this
/// cheap on the (cold-ish) error-generation arms: a single octet test
/// for the common cases.
///
///   - IPv4: multicast 224.0.0.0/4 (first octet 224..=239) OR the
///     limited broadcast 255.255.255.255. Subnet/directed broadcasts
///     require per-interface mask knowledge that is not available at the
///     generation site, so they are not detectable here — the limited
///     broadcast and the multicast block are the cases this gate covers.
///   - IPv6: multicast ff00::/8 (first byte 0xff). IPv6 has no broadcast.
///
/// Returns `true` when an ICMP error MUST be suppressed for this trigger
/// destination. Fails closed (`true`) on a too-short packet slice and on
/// an unknown/unexpected `addr_family`: a destination we cannot classify
/// must suppress the error rather than risk emitting backscatter for a
/// packet whose family (and therefore whose group/broadcast bits) we did
/// not parse.
#[inline]
pub(in crate::afxdp) fn dest_is_multicast_or_broadcast(addr_family: u8, packet: &[u8]) -> bool {
    match addr_family as i32 {
        libc::AF_INET => {
            let Some(dst) = packet.get(16..20) else {
                return true;
            };
            let dst = Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]);
            dst.is_multicast() || dst.is_broadcast()
        }
        libc::AF_INET6 => {
            let Some(dst) = packet.get(24..40) else {
                return true;
            };
            // ff00::/8 — the leading byte alone identifies all IPv6
            // multicast (link-local-all-nodes, solicited-node, etc.).
            dst[0] == 0xff
        }
        // Unknown family — fail closed (suppress). The error generators
        // never call this for a non-IP family in practice (their own
        // family dispatch rejects first), but the predicate's contract is
        // "suppress on anything we could not classify."
        _ => true,
    }
}

/// #2411: RFC 1812 §4.3.2.7 — a router MUST NOT originate an ICMP error
/// in reply to a datagram whose IP destination is a *directed* (subnet)
/// broadcast, e.g. `10.0.1.255` for a connected `10.0.1.0/24`. Unlike
/// the limited broadcast (`255.255.255.255`, caught by
/// [`dest_is_multicast_or_broadcast`]'s `is_broadcast()`), a directed
/// broadcast is a normal unicast address to the L3 destination test —
/// recognizing it requires the configured subnet MASK, which only the
/// forwarding state's connected-route table carries. This is the
/// per-interface-prefix sibling of [`dest_is_multicast_or_broadcast`]
/// (L3 group/limited-broadcast), [`l2_dst_is_group_or_broadcast`] (L2),
/// and [`source_is_invalid_for_icmp_error`] (L3 source); it is shared by
/// the reject / Time-Exceeded path (`can_generate_icmp_error_reply`) and
/// the PTB path (`ptb_reply_suppressed`) so every locally generated ICMP
/// error applies the SAME directed-broadcast gate.
///
/// IPv4-only: IPv6 has no broadcast (the v6 caller never invokes this).
/// `packet` is the L3 (IP-header-first) slice. Returns `true` when the
/// destination is the all-ones host address of a connected prefix and
/// the ICMP error MUST be suppressed. A too-short slice fails closed
/// (suppress). The connected table is reused from the forwarding path
/// (no new infrastructure); the scan is the same `connected_v4.iter()`
/// the FIB lookup already does, on a cold (error-generation) path only.
///
/// Prefixes shorter than /31 are the only ones with a meaningful
/// directed broadcast: a /31 (RFC 3021) has no broadcast and a /32's
/// host-all-ones value equals the host itself, so both are skipped to
/// avoid mis-suppressing a legitimate unicast to a /32 connected host.
#[inline]
pub(in crate::afxdp) fn dest_is_directed_broadcast(
    forwarding: &ForwardingState,
    packet: &[u8],
) -> bool {
    let Some(dst) = packet.get(16..20) else {
        // Fail closed: a destination we cannot read must suppress the
        // error rather than risk directed-broadcast backscatter.
        return true;
    };
    let dst = Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]);
    v4_addr_is_directed_broadcast(forwarding, dst)
}

/// Shared connected-table directed-broadcast test for a single IPv4
/// address, used by both the L3-DESTINATION gate
/// ([`dest_is_directed_broadcast`]) and the L3-SOURCE gate
/// ([`src_is_directed_broadcast`]). Returns `true` when `addr` is the
/// all-ones host (subnet-directed broadcast) of any connected prefix.
///
/// `directed_broadcast() == addr` already implies the prefix contains
/// `addr`: a directed broadcast is `network | !mask`, so `addr & mask ==
/// network` (the host bits are all-ones and masked off) — i.e.
/// `contains(addr)` is necessarily true. The explicit `contains` check
/// would be redundant, so only the broadcast-equality and the
/// prefix-length guard remain.
///
/// Prefixes shorter than /31 are the only ones with a meaningful
/// directed broadcast: a /31 (RFC 3021) has no broadcast and a /32's
/// host-all-ones value equals the host itself, so both are skipped to
/// avoid mis-classifying a legitimate unicast to a /32 connected host.
#[inline]
fn v4_addr_is_directed_broadcast(forwarding: &ForwardingState, addr: Ipv4Addr) -> bool {
    forwarding
        .connected_v4
        .iter()
        .any(|entry| entry.prefix.prefix_len() < 31 && entry.prefix.directed_broadcast() == addr)
}

/// #2487: RFC 1812 §4.3.2.7 — a router MUST NOT originate an ICMP error
/// in reply to a datagram whose IP SOURCE is a *directed* (subnet)
/// broadcast, e.g. `10.0.1.255` for a connected `10.0.1.0/24`. A locally
/// generated error is addressed TO the trigger's source, so a directed-
/// broadcast source produces an error sent to that directed broadcast —
/// delivered to every host on the segment (Smurf-style amplification /
/// backscatter). This is the L3-SOURCE sibling of the merged #2411
/// [`dest_is_directed_broadcast`] (L3 destination): the
/// [`source_is_invalid_for_icmp_error`] limited-broadcast test
/// (`is_broadcast()`) only catches `255.255.255.255`; a subnet-directed
/// broadcast is a plain unicast address to that test and needs the
/// configured subnet MASK from the connected-route table to recognize.
///
/// IPv4-only: IPv6 has no broadcast (the v6 caller never invokes this).
/// `packet` is the L3 (IP-header-first) slice. Returns `true` when the
/// source is the all-ones host address of a connected prefix and the
/// ICMP error MUST be suppressed. A too-short slice fails closed
/// (suppress). The connected table is reused from the forwarding path
/// (no new infrastructure), scanned only on the cold error-generation
/// path. The /31 and /32 prefix-length guards match
/// [`dest_is_directed_broadcast`].
#[inline]
pub(in crate::afxdp) fn src_is_directed_broadcast(
    forwarding: &ForwardingState,
    packet: &[u8],
) -> bool {
    let Some(src) = packet.get(12..16) else {
        // Fail closed: a source we cannot read must suppress the error
        // rather than risk directed-broadcast backscatter.
        return true;
    };
    let src = Ipv4Addr::new(src[0], src[1], src[2], src[3]);
    v4_addr_is_directed_broadcast(forwarding, src)
}

/// #2367: RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e) — a router MUST NOT
/// originate an ICMP/ICMPv6 *error* in response to a datagram whose IP
/// SOURCE address does not uniquely identify a single host. A locally
/// generated error is addressed to the trigger packet's source, so a
/// forbidden source (unspecified, loopback, multicast, or — for IPv4 —
/// broadcast) would produce spoofable ICMP backscatter aimed at an
/// address that is not a legitimate unicast host. This is the L3-SOURCE
/// sibling of [`dest_is_multicast_or_broadcast`] (the L3-destination
/// test) and [`l2_dst_is_group_or_broadcast`] (the L2 test); it is shared
/// by the reject / Time-Exceeded path (`can_generate_icmp_error_reply`)
/// and the PTB path (`ptb_reply_suppressed`) so every locally generated
/// ICMP error applies the SAME bad-source gate.
///
/// `packet` is the L3 (IP-header-first) slice of the trigger frame.
/// Returns `true` when the source is forbidden and the ICMP error MUST be
/// suppressed. A too-short or unknown-family slice fails closed
/// (suppress).
#[inline]
pub(in crate::afxdp) fn source_is_invalid_for_icmp_error(addr_family: u8, packet: &[u8]) -> bool {
    match addr_family as i32 {
        libc::AF_INET => {
            // IPv4 source is header bytes 12..16.
            let Some(src) = packet.get(12..16) else {
                return true;
            };
            let src = Ipv4Addr::new(src[0], src[1], src[2], src[3]);
            src.is_unspecified() || src.is_loopback() || src.is_multicast() || src.is_broadcast()
        }
        libc::AF_INET6 => {
            // IPv6 source is header bytes 8..24. IPv6 has no broadcast;
            // multicast (ff00::/8) covers the group case.
            let Some(src) = packet.get(8..24) else {
                return true;
            };
            let src = Ipv6Addr::from(match <[u8; 16]>::try_from(src) {
                Ok(addr) => addr,
                Err(_) => return true,
            });
            src.is_unspecified() || src.is_loopback() || src.is_multicast()
        }
        // Unknown family — fail closed (suppress). Mirrors the
        // destination predicate's "suppress on anything we could not
        // classify" contract.
        _ => true,
    }
}

/// #2325: RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e) — a router MUST NOT
/// originate an ICMP/ICMPv6 *error* in reply to a datagram that was
/// delivered as a link-layer (L2) broadcast or multicast. The IEEE 802
/// group (I/G) bit is the low bit of the first MAC octet; the all-ones
/// MAC (broadcast) is a special case of group, so a single bit test on
/// the first destination-MAC octet covers both. This is the L2 sibling
/// of [`dest_is_multicast_or_broadcast`] (the L3 destination test) and
/// is shared by the reject / Time-Exceeded path
/// (`can_generate_icmp_error_reply`) and the PTB path
/// (`ptb_reply_suppressed`) so both apply the same L2+L3 suppression.
///
/// Takes the trigger frame's 6-byte destination MAC. Returns `true` when
/// the L2 destination is group/broadcast and the ICMP error MUST be
/// suppressed.
#[inline]
pub(in crate::afxdp) fn l2_dst_is_group_or_broadcast(eth_dst: &[u8; 6]) -> bool {
    // The low bit of the first MAC octet is the I/G (group) bit; the
    // all-ones MAC is broadcast (a group address). A single bit test
    // catches both.
    (eth_dst[0] & 0x01) != 0
}

/// #2790: RFC 826 — a learned neighbor (ARP reply sender, NDP NA target)
/// MUST uniquely identify a single host before it is cached and
/// programmed into the kernel neighbor table. An ARP/NDP reply whose
/// advertised protocol address is unspecified (`0.0.0.0` / `::`),
/// loopback (`127/8` / `::1`), multicast (`224/4` / `ff00::/8`), or — for
/// IPv4 — the limited broadcast (`255.255.255.255`) does not name a
/// legitimate unicast peer; caching it pollutes both the userspace
/// `dynamic_neighbors` map and the kernel ARP/NDP table, enabling a
/// spoofed-reply DoS (routing disruption). Fail closed: such a reply is
/// not learnable and the caller drops/recycles it without caching.
///
/// This is the neighbor-learning sibling of
/// [`source_is_invalid_for_icmp_error`] (the ICMP-error L3-SOURCE gate);
/// it applies the SAME unicast-only posture the #2367 / #2487 ICMP-source
/// checks and the cold-neighbor warmer (`coordinator::warm_neighbors`)
/// already enforce, so every neighbor write — learned or warmed — rejects
/// the same illegitimate address classes.
///
/// Returns `true` when `ip` is a legitimate unicast address that MAY be
/// learned. IPv4 broadcast is rejected; IPv6 has no broadcast (multicast
/// covers the group case). Directed (subnet) broadcasts are NOT rejected
/// here: recognizing them needs the per-interface mask, the learned key
/// is already scoped to the ingress logical ifindex, and a directed
/// broadcast is a normal unicast address to this test — matching the
/// warmer's posture, which also only tests the limited broadcast.
/// Is this HARDWARE address one a neighbour entry may be learned FOR? (#9115)
///
/// Rejects the all-zero MAC and any address with the I/G group bit set — which
/// covers every multicast MAC and the broadcast address.
///
/// A neighbour entry programmed with a group address is a cache-poisoning
/// primitive, not merely a wrong entry: traffic for the victim IP is then
/// addressed to a group, so every station on the segment receives it, and the
/// firewall's own switch port can be MAC-flapped or err-disabled. The IP-side
/// predicate `neighbor_ip_is_learnable` below has always existed; this is its
/// missing L2 counterpart.
///
/// ONE predicate, called from every learn arm, deliberately: the RX-learn arm
/// in `neighbor_dispatch.rs` carried this exact test INLINE while the ARP-reply
/// and NDP-NA arms in `poll_stages.rs` had nothing, which is precisely the
/// drift a shared, named predicate prevents. A fourth learn arm inherits it
/// instead of having to remember it.
#[inline]
pub(in crate::afxdp) fn neighbor_mac_is_learnable(mac: [u8; 6]) -> bool {
    mac != [0u8; 6] && (mac[0] & 0x01) == 0
}

#[inline]
pub(in crate::afxdp) fn neighbor_ip_is_learnable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified() && !v4.is_loopback() && !v4.is_multicast() && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_loopback() && !v6.is_multicast(),
    }
}

/// #10689: transit source-class gate — `true` iff `ip` is a source class the
/// Linux forwarder this dataplane replaces refuses to TRANSIT. Such a source
/// may still be legitimately RECEIVED (LocalDelivery) but must never be
/// forwarded, and must never have forward+reverse sessions minted for it.
///
///   - IPv6: unspecified (`::`), loopback (`::1`), multicast (`ff00::/8`),
///     link-local (`fe80::/10`). RFC 4291 sections 2.5.2/2.5.3/2.5.5/2.5.6:
///     the first three are never a valid unicast source, and link-local is
///     single-link scope a router MUST NOT forward.
///   - IPv4: `0.0.0.0/8` (this network, RFC 1122 section 3.2.1.3), loopback
///     `127/8` (RFC 1122 section 3.2.1.3g — never appears on a wire),
///     link-local `169.254/16` (RFC 3927 section 2.1 — MUST NOT be
///     forwarded), multicast `224/4` (RFC 1112 — never a valid source),
///     reserved `240/4` up to and including the limited broadcast
///     `255.255.255.255` (RFC 1112 section 4), and connected subnet-directed
///     broadcasts.
///
/// TRANSIT-ONLY by construction: call sites apply this AFTER FIB resolution
/// and only to transit dispositions (ForwardCandidate / MissingNeighbor /
/// FabricRedirect), so firewall-local receptions that legitimately carry
/// these sources — DHCP (`0.0.0.0`), NDP/DAD (`::`, `fe80::/10`) — still
/// reach LocalDelivery. An ingress-wide drop here would break them; the
/// #10686 mapped/compat gate is the contrast (those classes are invalid
/// everywhere, so that gate sits at shared ingress).
/// Hot-path: octet compares plus standard address class tests and one O(1)
/// membership check in the build-time connected directed-broadcast index.
#[inline]
pub(in crate::afxdp) fn transit_src_is_martian(forwarding: &ForwardingState, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 0
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || o[0] >= 240
                || forwarding.connected_v4_directed_broadcasts.contains(&v4)
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
                return true;
            }
            let o = v6.octets();
            o[0] == 0xfe && (o[1] & 0xc0) == 0x80
        }
    }
}
