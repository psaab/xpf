// #6386 leaf extraction: the new-flow session-admission predicates
// (#2134 per-IP session-limit, #4400/#10270 non-SYN TCP session-MISS drop),
// originally lifted verbatim out of poll_descriptor/mod.rs. Each moved bare fn
// becomes pub(super); both keep their existing #[inline] attributes. The
// extraction keeps the poll call site small; behavior-specific changes remain
// in this leaf and are covered by its tests.

use super::*;

/// #2134/#10985/#11057: per-zone session-limit enforcement at the NEW-FLOW decision.
///
/// Junos `limit-session source-ip-based <n>` / `destination-ip-based <n>`
/// caps concurrent sessions from one source / to one destination IP. When
/// `source-ip-based` is unset or zero, a default per-source quota applies;
/// a positive configured value overrides it. Destination limits remain
/// opt-in. The decision MUST fire exactly once per new flow, before that
/// flow's own session exists — NOT in the per-packet screen stage, which runs
/// on every data packet and would re-check an established flow's own counted
/// session and self-drop it at the limit boundary (#2134 r2 BLOCKER).
///
/// This is a read-only query on the per-worker `SessionTable` count keyed by
/// `(ingress_zone_id, IP)` (maintained at the install/remove sinks + HA
/// promote/demote), so sessions admitted in another zone cannot consume this
/// zone's allowance. The source default is independently enforced in each
/// ingress zone and worker. It preserves the #2128 leak-fix by construction:
/// an IP that never installs a session never gets a map entry. Returns the
/// screen-drop reason if the new flow must be rejected, or `None` to proceed.
#[inline]
pub(super) fn new_flow_session_limit_drop(
    forwarding: &ForwardingState,
    sessions: &SessionTable,
    from_zone: &str,
    from_zone_id: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Option<&'static str> {
    // Profiles carry explicit overrides; absent profiles and zero source
    // thresholds use the safe default.
    let profile = forwarding.screen_profiles.get(from_zone);
    let src_limit = profile
        .map(|p| p.session_limit_src)
        .filter(|limit| *limit > 0)
        .unwrap_or(crate::session::DEFAULT_MAX_SESSIONS_PER_SOURCE);
    if sessions.session_limit_src_count(from_zone_id, src_ip) >= src_limit {
        return Some("session-limit-src");
    }
    if profile.is_some_and(|p| {
        p.session_limit_dst > 0
            && sessions.session_limit_dst_count(from_zone_id, dst_ip) >= p.session_limit_dst
    }) {
        return Some("session-limit-dst");
    }
    None
}

/// #4400/#10270/#10703/#16479: TCP session-MISS admission for transit new flows.
///
/// By default, TCP misses require SYN so stale ACK/data cannot create new
/// sessions (#10270), and bare RST/FIN misses are always dropped to prevent
/// closing-entry churn (#4400). `no-syn-check` opts into mid-stream pickup
/// for non-closing packets. Explicit `strict-syn-check` also drops SYN
/// segments carrying payload (Junos: "When you enable `strict-syn-check`
/// the SYN packets carrying data are dropped") and keeps the SYN-first
/// requirement. (#16479: strict no longer "overrides" no-syn-check at
/// commit — the compiler rejects the combination — but the dataplane keeps
/// the precedence so a leniently-loaded legacy config stays fail-closed.)
///
/// Established and HA-synced flows are session HITS and never reach this
/// predicate. LocalDelivery uses its separate cache-only SYN gate so peer
/// control traffic for firewall-originated connections still reaches the
/// local stack.

/// #16479 (a): payload-aware MISS gate. A SYN carrying TCP payload is
/// dropped only when `strict_syn_check` is set; without strict the
/// SYN+payload miss keeps its prior admission (TFO-style, and the #16042
/// ISN seed already accounts for SYN payload in the expected ack end).
/// All other arms are identical to the flags-only predicate.
#[inline]
pub(super) fn strict_syn_check_drops_new_flow_with_payload(
    protocol: u8,
    tcp_flags: u8,
    tcp_flags_unknown: bool,
    no_syn_check: bool,
    strict_syn_check: bool,
    payload_len: u32,
) -> bool {
    strict_syn_check_drops_new_flow_tunnel_with_payload(
        protocol,
        tcp_flags,
        tcp_flags_unknown,
        no_syn_check,
        strict_syn_check,
        false,
        false,
        payload_len,
    )
}


/// #16479: payload-aware tunnel variant — the production MISS gate.
#[inline]
pub(super) fn strict_syn_check_drops_new_flow_tunnel_with_payload(
    protocol: u8,
    tcp_flags: u8,
    tcp_flags_unknown: bool,
    no_syn_check: bool,
    strict_syn_check: bool,
    no_syn_check_in_tunnel: bool,
    is_tunnel: bool,
    payload_len: u32,
) -> bool {
    if !matches!(protocol, crate::ip_proto::PROTO_TCP) {
        return false;
    }
    // #16007: flags UNKNOWN (tiny first fragment, flags byte outside the
    // declared datagram) fails closed in EVERY mode — including
    // `no_syn_check` and the tunnel opt-out. The stamped 0 is not a
    // proven non-closing, non-SYN packet; it is no information at all,
    // and admitting it would let an 8-byte first fragment seed a session
    // on flags nobody has seen, with the reassembled SYN arriving only
    // in the offset-1 second fragment.
    if tcp_flags_unknown {
        return true;
    }
    if crate::tcp_flags::is_closing(tcp_flags) {
        return true;
    }
    if crate::tcp_flags::has_syn(tcp_flags) {
        // #16479 (a): Junos strict SYN checking drops SYN packets
        // carrying data. Only under strict — the default and
        // no-syn-check paths keep admitting SYN+payload misses.
        return strict_syn_check && payload_len > 0;
    }
    let effective_no_syn = no_syn_check || (is_tunnel && no_syn_check_in_tunnel);
    !effective_no_syn || strict_syn_check
}

/// #16479 (b): strict-SYN pre-handshake data drop on a session HIT.
///
/// With `strict_syn_check`, a data-bearing TCP segment must not be
/// forwarded while the session's three-way handshake is incomplete
/// (Junos: strict SYN checking "enhances security by dropping data
/// packets before the three-way handshake is done"). Only SYN-ACK and
/// the handshake-completing ACK pass; both carry no payload by
/// construction of this predicate, so they are never dropped here.
/// Segments on closing entries keep their teardown handling (a FIN
/// with payload drains the send buffer; RST handling is seq-gated
/// elsewhere), and SYN-bearing segments (retransmits) are handshake
/// control, not data injection.
///
/// `established`/`handshake_pending`/`syn_ack_first`/`closing` are the
/// matched entry's handshake state BEFORE this packet's lookup would
/// promote/complete it (the caller reads them via the read-only
/// `strict_pre_handshake_state` probe), so a completing ACK+data —
/// the segment that finishes the handshake while carrying the first
/// data — is dropped exactly as Junos drops it: data before the
/// handshake is done. A mid-stream pickup starts `established`, so it
/// is never gated here.
#[inline]
pub(super) fn strict_syn_check_drops_pre_handshake_data(
    strict_syn_check: bool,
    tcp_flags: u8,
    payload_len: u32,
    established: bool,
    handshake_pending: bool,
    syn_ack_first: bool,
    closing: bool,
) -> bool {
    if !strict_syn_check || payload_len == 0 {
        return false;
    }
    if closing || crate::tcp_flags::is_closing(tcp_flags) {
        return false;
    }
    if crate::tcp_flags::has_syn(tcp_flags) {
        return false;
    }
    // SYN-first session, handshake incomplete: either the SYN-ACK has
    // not been seen yet (!established, not a SYN-ACK-first pickup) or
    // it has and the completing ACK is still outstanding
    // (handshake_pending, which SYN-ACK-first also seeds).
    !established || handshake_pending || syn_ack_first
}

#[cfg(test)]
#[path = "session_admission_tests.rs"]
mod tests;
