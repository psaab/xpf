// #6386 leaf extraction: the new-flow session-admission predicates
// (#2134 per-IP session-limit, #4400/#10270 non-SYN TCP session-MISS drop),
// originally lifted verbatim out of poll_descriptor/mod.rs. Each moved bare fn
// becomes pub(super); both keep their existing #[inline] attributes. The
// extraction keeps the poll call site small; behavior-specific changes remain
// in this leaf and are covered by its tests.

use super::*;

/// #2134: per-IP session-limit enforcement at the NEW-FLOW decision.
///
/// Junos `limit-session source-ip-based <n>` / `destination-ip-based <n>`
/// caps the concurrent locally-admitted sessions a single source /
/// destination IP may hold. The decision MUST fire exactly once per new
/// flow, before that flow's own session exists — NOT in the per-packet
/// screen stage, which runs on every data packet of every flow and would
/// re-check an established flow's own counted session and self-drop it at
/// the limit boundary (#2134 r2 BLOCKER).
///
/// This is a read-only query on the per-worker `SessionTable` count
/// (maintained at the install/remove sinks + HA promote/demote), so it
/// preserves the #2128 leak-fix (closed by #2159) by construction: an IP
/// that never installs a session never gets a map entry. Returns the
/// screen-drop reason if the new flow must
/// be rejected, or `None` to proceed to install. Cold path (session
/// miss only); the profile lookup short-circuits on the common
/// no-`limit-session` zone.
#[inline]
pub(super) fn new_flow_session_limit_drop(
    forwarding: &ForwardingState,
    sessions: &SessionTable,
    from_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<&'static str> {
    // `screen_profiles` is keyed by zone NAME. An empty/absent zone or a
    // zone with no `limit-session` configured short-circuits with no cost
    // beyond the map probe.
    let profile = forwarding.screen_profiles.get(from_zone)?;
    if profile.session_limit_src > 0
        && sessions.session_limit_src_count(src_ip) >= profile.session_limit_src
    {
        return Some("session-limit-src");
    }
    if profile.session_limit_dst > 0
        && sessions.session_limit_dst_count(dst_ip) >= profile.session_limit_dst
    {
        return Some("session-limit-dst");
    }
    None
}

/// #4400/#10270/#10703: TCP session-MISS admission for transit new flows.
///
/// By default, TCP misses require SYN so stale ACK/data cannot create new
/// sessions (#10270), and bare RST/FIN misses are always dropped to prevent
/// closing-entry churn (#4400). `no-syn-check` opts into mid-stream pickup
/// for non-closing packets. Explicit `strict-syn-check` overrides that opt-out
/// and keeps the SYN-first requirement.
///
/// Established and HA-synced flows are session HITS and never reach this
/// predicate. LocalDelivery uses its separate cache-only SYN gate so peer
/// control traffic for firewall-originated connections still reaches the
/// local stack.
#[inline]
pub(super) fn strict_syn_check_drops_new_flow(
    protocol: u8,
    tcp_flags: u8,
    no_syn_check: bool,
    strict_syn_check: bool,
) -> bool {
    if !matches!(protocol, crate::ip_proto::PROTO_TCP) || crate::tcp_flags::has_syn(tcp_flags) {
        return false;
    }
    crate::tcp_flags::is_closing(tcp_flags) || !no_syn_check || strict_syn_check
}

#[cfg(test)]
#[path = "session_admission_tests.rs"]
mod tests;
