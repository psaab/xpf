//! Destination-qualified NDP kernel-pass predicate for the degraded XDP shim.
//!
//! The healthy shim only sends NDP to the kernel through the early destination
//! filter (multicast and link-local) or its local-destination check. The
//! degraded path must use the same destination qualification instead of
//! treating ICMPv6 types 133-137 as local control regardless of destination.

/// May an NDP packet use the degraded path's local-control kernel-pass arm?
///
/// The caller has already handled multicast and link-local destinations with
/// `should_fallback_early`; this predicate covers unicast NDP and only grants
/// the kernel pass when the destination is configured as local to this host.
#[inline(always)]
pub fn is_local_ndp_control(icmp_type: u8, hop_limit: u8, destination_is_local: bool) -> bool {
    // #15946: RFC4861 hop-limit 255 proof, matching healthy NAT-external arm.
    (133..=137).contains(&icmp_type) && hop_limit == 255 && destination_is_local
}

/// #15117: may an on-link NDP packet (ICMPv6 133-137, hop limit 255) use
/// the healthy shim's kernel-pass arm even when its destination is a NAT
/// external (interface-NAT map) rather than a firewall-local address?
/// Such a packet is destined for the kernel's proxy-NDP, which answers
/// for the external; destination-translating it in the worker would
/// forward it to the internal host and the proxy would never see it.
/// The hop-limit gate is the on-link proof: a forwarded NDP probe has
/// hop < 255 and keeps the ordinary worker path.
#[inline(always)]
pub fn is_nat_external_ndp_control(
    icmp_type: u8,
    hop_limit: u8,
    destination_is_interface_nat: bool,
) -> bool {
    (133..=137).contains(&icmp_type) && hop_limit == 255 && destination_is_interface_nat
}

/// #16660: may an on-link NDP packet (ICMPv6 133-137, hop limit 255) use
/// the healthy shim's kernel-pass arm when its destination is a v6
/// proxy-NDP target (a configured `proxy-arp`/`proxy-ndp` IPv6 address,
/// e.g. a static-NAT/DNAT external that is NOT an interface address)?
/// Such a packet is destined for the kernel's proxy-NDP, whose pneigh
/// lookup is keyed by the RECEIVE device: the entry sits on the WAN
/// netdev, so the NS must pass on its ingress netdev. Routing it to the
/// worker instead LocalDelivers it into the `xpf-usp0` TUN, where the
/// per-device lookup misses and no NA is ever sent. The hop-limit gate
/// is the on-link proof: a forwarded NDP probe has hop < 255 and keeps
/// the ordinary worker path. Same shape as the interface-NAT arm above,
/// qualified on the proxy-target map instead.
#[inline(always)]
pub fn is_proxy_ndp_ndp_control(
    icmp_type: u8,
    hop_limit: u8,
    destination_is_proxy_ndp: bool,
) -> bool {
    (133..=137).contains(&icmp_type) && hop_limit == 255 && destination_is_proxy_ndp
}
