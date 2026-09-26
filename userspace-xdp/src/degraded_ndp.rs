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
pub fn is_local_ndp_control(icmp_type: u8, destination_is_local: bool) -> bool {
    (133..=137).contains(&icmp_type) && destination_is_local
}
