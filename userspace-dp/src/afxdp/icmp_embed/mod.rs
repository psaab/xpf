//! Embedded ICMP error path: reverse-NAT and forwarding-resolution
//! for ICMP / ICMPv6 error packets (Time-Exceeded, Destination
//! Unreachable, etc.) whose embedded inner header matches an existing
//! session. The 8 `pub(super)` items below are the public surface
//! consumed by `afxdp/mod.rs` and `afxdp/poll_descriptor/mod.rs`.
//!
//! The 269-LOC `try_embedded_icmp_nat_match_from_frame` body has been
//! split by outer address family into private `nat_match_v4` /
//! `nat_match_v6` submodules. The 10-param
//! `embedded_icmp_return_resolution` collapses behind `NatMatchCtx`,
//! a borrow bundle threaded through all four embedded-ICMP NAT
//! match arms.
//!
//! Wrapper functions in this file delegate directly to children via
//! qualified-path calls (NOT `pub(super) use ...`) — that pattern
//! would trigger E0364 on `pub(super)` child items, as documented
//! in `afxdp/tx/mod.rs:38-42`.

use super::*;
use crate::session::TunnelDiscriminator;

mod builders;
mod nat64_match;
mod nat_match_v4;
mod nat_match_v6;
mod parse;
mod return_resolution;
mod session_match;

/// Information returned from an embedded ICMP error session match
/// that includes NAT reversal data needed to rewrite the ICMP error
/// packet back to the original pre-NAT client.
#[derive(Clone, Debug)]
pub(super) struct EmbeddedIcmpMatch {
    /// The forward session's NAT decision (has rewrite_src for SNAT).
    pub(super) nat: NatDecision,
    /// The original (pre-NAT) source IP of the client.
    pub(super) original_src: IpAddr,
    /// The original source port (if port SNAT was applied).
    pub(super) original_src_port: u16,
    /// The original (pre-DNAT/static) destination IP the client used —
    /// i.e. the public address before destination NAT. For a flow with
    /// NO destination NAT this equals the embedded packet's destination,
    /// so the destination rewrite in the builders is a no-op and
    /// SNAT-only / no-NAT behaviour stays byte-identical (#3112).
    pub(super) original_dst: IpAddr,
    /// The original (pre-DNAT) destination port. Equals the embedded
    /// destination port when no port DNAT was applied (no-op rewrite).
    pub(super) original_dst_port: u16,
    /// The embedded packet's L4 protocol.
    pub(super) embedded_proto: u8,
    /// Forwarding resolution toward the original client.
    pub(super) resolution: ForwardingResolution,
    /// Session metadata (zones, RG).
    pub(super) metadata: SessionMetadata,
    /// #6474: this match is an OUTBOUND ICMP error through source NAT — the
    /// internal host emitted the error about the session's REPLY packet, so
    /// the quote carries the PRE-NAT tuple and the session-fallback matched
    /// the FORWARD session via the quote's reply key (`is_reverse == false`,
    /// `rewrite_src` set, no destination NAT). The caller must re-NAT the
    /// outer source and the embedded quote to the session's external
    /// identity (RFC 5508 §4) with the `build_snat_outbound_icmp_error_*`
    /// builders — NOT the #5690 reversal, which would consume the
    /// descriptor with the internal (pre-NAT) source on the wire and an
    /// unassociable quote. `false` on every inbound match.
    pub(super) outbound_snat: bool,
}

/// Borrow bundle threaded through both v4/v6 NAT-match paths and the
/// embedded-ICMP return-resolution helper. ONE struct only — both
/// the NAT lookup path (which needs `shared_nat_sessions`) and the
/// return-resolution path (which doesn't) share the same `&mut`
/// borrow on `SessionTable`, so two structs holding `&mut sessions`
/// concurrently would be a borrow-checker error.
pub(in crate::afxdp::icmp_embed) struct NatMatchCtx<'a> {
    pub sessions: &'a mut SessionTable,
    pub forwarding: &'a ForwardingState,
    pub dynamic_neighbors: &'a Arc<ShardedNeighborMap>,
    pub shared_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
}

// ---------------------------------------------------------------
// Public surface — `pub(super)` wrappers delegating to children.
// ---------------------------------------------------------------

/// Parse the embedded IP+L4 headers from an ICMP error payload and
/// look up the corresponding session. Returns the session lookup if
/// found.
#[allow(dead_code)]
pub(super) fn try_embedded_icmp_session_match(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
    // #9162: the arriving interface's routing domain — see the child's doc.
    routing_domain: u32,
) -> Option<SessionLookup> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    session_match::try_embedded_icmp_session_match_from_frame(
        frame,
        meta,
        sessions,
        now_ns,
        routing_domain,
    )
}

/// Core embedded ICMP session match logic operating on a frame slice.
pub(super) fn try_embedded_icmp_session_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
    // #9162: the arriving interface's routing domain — see the child's doc.
    routing_domain: u32,
) -> Option<SessionLookup> {
    session_match::try_embedded_icmp_session_match_from_frame(
        frame,
        meta,
        sessions,
        now_ns,
        routing_domain,
    )
}

// #8271: `try_embedded_icmp_nat_match` -- the `(area, desc)` wrapper that
// sliced the UMEM frame at `desc.addr`/`desc.len` and called the `_from_frame`
// twin below -- was DELETED rather than left unused.
//
// It had exactly one behaviour: pair whatever frame `desc` points at with
// whatever `meta` it was handed. On a native-GRE-decapped packet those are
// different packets -- `stage_native_gre_decap` rebinds `meta` to the inner
// frame while `desc` still references the un-decapped outer one -- and its last
// caller (`try_reverse_embedded_icmp_error`) was doing precisely that, parsing
// outer bytes at inner offsets. Two sibling arms of
// `poll_binding_process_descriptor` had already been fixed for the same pairing
// (#1885, #1902); these two had not.
//
// Removing the wrapper removes the ability to make that mistake, which is worth
// more than removing this instance of it: every caller must now name the frame
// it means. Callers that genuinely hold only a descriptor slice it themselves
// and pass the bytes.

/// Core implementation of embedded ICMP NAT match operating on a
/// frame slice. Dispatches to the v4 / v6 outer family branch.
#[inline]
pub(super) fn try_embedded_icmp_nat_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let icmp_type = *frame.get(l4)?;
    if !is_icmp_error(meta.protocol, icmp_type) {
        return None;
    }
    let mut ctx = NatMatchCtx {
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
    };
    match meta.protocol {
        PROTO_ICMP => nat_match_v4::match_outer_v4(frame, meta, &mut ctx, now_ns),
        PROTO_ICMPV6 => nat_match_v6::match_outer_v6(frame, meta, &mut ctx, now_ns),
        _ => None,
    }
}

pub(super) use nat64_match::Nat64IcmpErrorMatch;

/// #6472: NAT64 flowless ICMP-error session match, operating on a frame
/// slice. Builds the `NatMatchCtx` borrow bundle exactly like
/// [`try_embedded_icmp_nat_match_from_frame`] and dispatches to the
/// cross-family matcher; the poll-side caller translates + forwards per
/// the returned direction. `None` = not a NAT64 session error (the
/// same-family reversal and normal flowless enforcement run unchanged).
#[allow(clippy::too_many_arguments)]
pub(super) fn try_nat64_icmp_error_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> Option<Nat64IcmpErrorMatch> {
    let mut ctx = NatMatchCtx {
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
    };
    nat64_match::try_nat64_icmp_error_match(frame, meta, &mut ctx, now_ns)
}

pub(super) fn build_nat_reversed_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_nat_reversed_icmp_error_v4(frame, meta, icmp_match)
}

/// #6474: OUTBOUND ICMP error through source NAT — rewrite the outer
/// source and the embedded quote to the session's external identity
/// (RFC 5508 §4). See [`builders::build_snat_outbound_icmp_error_v4`].
pub(super) fn build_snat_outbound_icmp_error_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_snat_outbound_icmp_error_v4(frame, meta, icmp_match)
}

/// #6474: IPv6 twin of [`build_snat_outbound_icmp_error_v4`].
pub(super) fn build_snat_outbound_icmp_error_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_snat_outbound_icmp_error_v6(frame, meta, icmp_match)
}

pub(super) fn build_nat_reversed_icmp_error_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    icmp_match: &EmbeddedIcmpMatch,
) -> Option<Vec<u8>> {
    builders::build_nat_reversed_icmp_error_v6(frame, meta, icmp_match)
}

pub(super) fn finalize_embedded_icmp_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_ifindex: i32,
    icmp_match: &EmbeddedIcmpMatch,
) -> ForwardingResolution {
    builders::finalize_embedded_icmp_resolution(
        forwarding,
        ha_state,
        now_secs,
        ingress_ifindex,
        icmp_match,
    )
}

/// #6472: (resolution, ingress-zone) form of the embedded-ICMP resolution
/// finalizer for the NAT64 flowless arm (its match is not an
/// [`EmbeddedIcmpMatch`]). See
/// [`builders::finalize_embedded_icmp_resolution_parts`].
pub(super) fn finalize_embedded_icmp_resolution_parts(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    ingress_ifindex: i32,
    resolution: ForwardingResolution,
    ingress_zone: u16,
) -> ForwardingResolution {
    builders::finalize_embedded_icmp_resolution_parts(
        forwarding,
        ha_state,
        now_secs,
        ingress_ifindex,
        resolution,
        ingress_zone,
    )
}

/// #9298: resolve a QUOTED PPTP Call ID to the local call handle, so an ICMP
/// error about a PPTP data tunnel can find its session.
///
/// #9031 threaded the quoted GRE discriminator into the embedded lookup keys and
/// closed the RFC 2890 half. It did not close the PPTP half, which that issue's
/// acceptance also named. `gre_transit_discriminator` returns `Unparseable` for
/// every version-1 (PPTP enhanced GRE) header -- correctly, because the 32 bits
/// after the flags word are `Payload Length | Call ID` and reading them with RFC
/// 2890 field order would promote a per-packet-varying length as a stable tunnel
/// identity. `Unparseable` equals no live session's discriminator, so the quote
/// MISSED. Fail-closed, and still a miss: PMTUD and unreachables for PPTP data
/// tunnels stayed unresolved, which is the suppression #9031 fixed for keyed GRE.
///
/// WHY THIS CANNOT BE COPIED FROM THE RFC 2890 HALF. `TunnelDiscriminator::Pptp`
/// carries a LOCALLY DERIVED handle, not the wire value. RFC 2637 s4.1 has each
/// side allocate its own Call ID naming the peer it sends to, so the two
/// directions of one call carry DIFFERENT wire values; a discriminator built
/// from the wire would differ per direction and never equal its reverse
/// companion. The wire id only becomes an identity through the per-worker
/// association table, which is why this is a RESOLVE and not a parse.
///
/// SPLIT SO THE PARSER STAYS PURE. `parse_embedded_v4/v6` extract the quoted
/// call id as bytes -- a pure read, bounded by the quoted datagram's declared
/// end exactly as the discriminator beside it -- and this function does the
/// impure half where `SessionTable` is already in scope. The issue's stated
/// obstacle, that the embedded path "needs access to per-worker state it does
/// not currently take", does not hold: the production arms already take
/// `ctx.sessions`.
///
/// `resolve`, NOT `resolve_and_touch`. The transit path refreshes the
/// association's idle clock because a data packet IS traffic on the call. An
/// ICMP error is traffic ABOUT the call, generated by a third party on the path,
/// and refreshing on it would let errors keep a dead association alive -- the
/// idle timeout means "no traffic", and it bounds reuse of a 16-bit call id.
/// Deliberate divergence from the sibling, not an oversight.
///
/// FAIL-CLOSED IS PRESERVED. Only `Unparseable` is ever upgraded, so a
/// `Keyed`/`Unkeyed`/`None` quote is returned untouched; and an unresolvable
/// call id stays `Unparseable`, which MISSES. A wildcard here would be worse
/// than a miss, because PPTP tunnels between one address pair are distinguished
/// by nothing else.
pub(in crate::afxdp::icmp_embed) fn resolve_quoted_pptp_discriminator(
    sessions: &SessionTable,
    quoted: TunnelDiscriminator,
    quoted_call_id: Option<u16>,
    quoted_dst: IpAddr,
) -> TunnelDiscriminator {
    if !matches!(quoted, TunnelDiscriminator::Unparseable) {
        return quoted;
    }
    let Some(call_id) = quoted_call_id else {
        return quoted;
    };
    // `quoted_dst` is the destination of the packet the error is ABOUT, i.e. the
    // peer the sender was transmitting to -- exactly the `(dst, call_id)` pair
    // the association table is indexed by.
    match sessions.pptp().resolve(quoted_dst, call_id) {
        Some(handle) => TunnelDiscriminator::Pptp(handle),
        None => quoted,
    }
}


// ---------------------------------------------------------------------------
// #9298 - resolving a QUOTED PPTP Call ID so an ICMP error about a PPTP data
// tunnel finds its session.
//
// #9031 closed the RFC 2890 half of the embedded-GRE lookup and left the PPTP
// half, which its own acceptance named. `gre_transit_discriminator` returns
// `Unparseable` for every version-1 header, so a PPTP-quoted ICMP error MISSED:
// fail-closed and correct as far as it goes, and still a miss.
//
// A MISS IS NOT A DROP, which is why this is an improvement and not a stricter
// policy: `try_reverse_embedded_icmp_error` returns `NotHandled` and the caller
// "falls through to normal flowless enforcement, unchanged". So the unresolved
// case is ordinary traffic that keeps being forwarded; what it loses is the NAT
// reversal, i.e. PMTUD and unreachables for the tunnel.
//
// The split: `parse_embedded_v4/v6` extract the quoted call id as BYTES (pure,
// bounded by the quoted datagram's declared end), and
// `resolve_quoted_pptp_discriminator` turns it into a handle where the
// association table is in scope.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod pptp_embedded_9298 {
    use super::*;
    use crate::session::TunnelDiscriminator;
    use std::net::IpAddr;

    const PEER_A: [u8; 4] = [10, 0, 0, 1];
    const PEER_B: [u8; 4] = [10, 0, 0, 2];

    fn install_call(sessions: &mut SessionTable, a_call_id: u16, b_call_id: u16) -> u32 {
        let call = crate::session::pptp::PptpCall::new(
            IpAddr::from(PEER_A),
            a_call_id,
            IpAddr::from(PEER_B),
            b_call_id,
        );
        let control = crate::session::pptp::ControlChannelId::new(
            IpAddr::from(PEER_A),
            49_152,
            IpAddr::from(PEER_B),
            1723,
        );
        sessions
            .pptp_mut()
            .install(call, control, 1_000)
            .expect("fixture: the association must install")
    }

    /// THE RESOLVE. A quoted PPTP data packet must reach the live call's handle.
    ///
    /// FAIL-ON-REVERT: return `quoted` unconditionally and this reds with
    /// `Unparseable`, which equals no live session's discriminator.
    #[test]
    fn a_quoted_pptp_call_id_resolves_to_the_live_handle_9298() {
        let mut sessions = SessionTable::new();
        let handle = install_call(&mut sessions, 100, 200);

        // The quote is of a packet A sent TO B, so it carries the call id B
        // allocated (RFC 2637 s4.1) and its destination is B.
        let got = resolve_quoted_pptp_discriminator(
            &sessions,
            TunnelDiscriminator::Unparseable,
            Some(200),
            IpAddr::from(PEER_B),
        );
        assert_eq!(
            got,
            TunnelDiscriminator::Pptp(handle),
            "a quoted PPTP Call ID must resolve to the LOCAL handle the live \
             session carries. Left `Unparseable` it equals no session and the \
             ICMP error stays unresolved - the PMTUD suppression #9031 fixed \
             for keyed GRE (#9298)"
        );
    }

    /// DIRECTION SYMMETRY - the property that motivated the handle design.
    ///
    /// Each side allocates its OWN Call ID naming the peer it sends to, so the
    /// two directions of one call carry DIFFERENT wire values. A discriminator
    /// built from the wire would differ per direction; the locally-derived
    /// handle must not. This is the cell that would red if anyone "simplified"
    /// the resolve into reading the wire id.
    #[test]
    fn both_directions_of_one_call_resolve_to_the_same_handle_9298() {
        let mut sessions = SessionTable::new();
        let handle = install_call(&mut sessions, 100, 200);

        let a_to_b = resolve_quoted_pptp_discriminator(
            &sessions,
            TunnelDiscriminator::Unparseable,
            Some(200),
            IpAddr::from(PEER_B),
        );
        let b_to_a = resolve_quoted_pptp_discriminator(
            &sessions,
            TunnelDiscriminator::Unparseable,
            Some(100),
            IpAddr::from(PEER_A),
        );
        assert_eq!(a_to_b, TunnelDiscriminator::Pptp(handle));
        assert_eq!(
            a_to_b, b_to_a,
            "the two directions of ONE call carry DIFFERENT wire Call IDs (200 \
             vs 100) and must resolve to the SAME handle. If these differ, the \
             reverse companion of a session can never match its forward key \
             (#9298)"
        );
    }

    /// FAIL-CLOSED - an unresolvable Call ID stays a MISS, never a wildcard.
    ///
    /// PPTP tunnels between one address pair are distinguished by nothing else,
    /// so guessing here would cross calls. This is the direction that must NOT
    /// change, and it is the reason the remedy is a resolve rather than a
    /// relaxation of the version-1 refusal.
    #[test]
    fn an_unresolvable_call_id_stays_unparseable_9298() {
        let mut sessions = SessionTable::new();
        install_call(&mut sessions, 100, 200);

        // Right peer, WRONG call id.
        assert_eq!(
            resolve_quoted_pptp_discriminator(
                &sessions,
                TunnelDiscriminator::Unparseable,
                Some(999),
                IpAddr::from(PEER_B),
            ),
            TunnelDiscriminator::Unparseable,
            "an unknown Call ID must MISS. Resolving it to any live handle \
             would attribute an ICMP error to a call it is not about (#9298)"
        );
        // Right call id, WRONG peer -- the association is keyed on the PAIR.
        assert_eq!(
            resolve_quoted_pptp_discriminator(
                &sessions,
                TunnelDiscriminator::Unparseable,
                Some(200),
                IpAddr::from([10, 0, 0, 3]),
            ),
            TunnelDiscriminator::Unparseable,
            "a known Call ID against the WRONG destination must MISS: the table \
             is keyed on (dst, call_id) and a 16-bit id is only unique per peer"
        );
        // No call id at all (a non-PPTP or version-0 quote).
        assert_eq!(
            resolve_quoted_pptp_discriminator(
                &sessions,
                TunnelDiscriminator::Unparseable,
                None,
                IpAddr::from(PEER_B),
            ),
            TunnelDiscriminator::Unparseable,
        );
    }

    /// ONLY `Unparseable` IS UPGRADED - every other quote is returned untouched.
    ///
    /// Without this the resolve could overwrite a correctly-parsed RFC 2890
    /// identity with a PPTP handle whenever a call id happened to be present,
    /// silently re-attributing keyed-GRE errors. The `Keyed` row is the one that
    /// matters; `None` is here because a non-GRE quote must be inert too.
    #[test]
    fn a_non_unparseable_quote_is_returned_untouched_9298() {
        let mut sessions = SessionTable::new();
        install_call(&mut sessions, 100, 200);

        for quoted in [
            TunnelDiscriminator::Keyed(7),
            TunnelDiscriminator::Unkeyed,
            TunnelDiscriminator::None,
            TunnelDiscriminator::Pptp(1),
        ] {
            assert_eq!(
                resolve_quoted_pptp_discriminator(
                    &sessions,
                    quoted,
                    // A resolvable id, deliberately: the guard must be the
                    // QUOTE'S CLASS, not the absence of a call id.
                    Some(200),
                    IpAddr::from(PEER_B),
                ),
                quoted,
                "{quoted:?} must be returned untouched. Only `Unparseable` - the \
                 class a version-1 header produces - may be upgraded, or a \
                 correctly-parsed RFC 2890 identity gets overwritten (#9298)"
            );
        }
    }

    /// THE IDLE CLOCK MUST NOT MOVE.
    ///
    /// The transit path uses `resolve_and_touch`, because a data packet IS
    /// traffic on the call. An ICMP error is traffic ABOUT the call, emitted by
    /// a third party on the path, so refreshing on it would let errors keep a
    /// dead association alive - and that association's lifetime is what bounds
    /// reuse of a 16-bit call id. This cell pins the divergence so a later
    /// "make it consistent with the sibling" edit has to argue with it.
    ///
    /// Observable: the association survives an expiry sweep iff it was touched.
    #[test]
    fn resolving_a_quote_does_not_refresh_the_association_idle_clock_9298() {
        let mut sessions = SessionTable::new();
        let handle = install_call(&mut sessions, 100, 200);
        let timeout = 10_000u64;

        // Resolve a quote far in the future. If this TOUCHED the association,
        // its last_seen would jump to `now` and the sweep below would spare it.
        let now = 1_000 + timeout * 4;
        assert_eq!(
            resolve_quoted_pptp_discriminator(
                &sessions,
                TunnelDiscriminator::Unparseable,
                Some(200),
                IpAddr::from(PEER_B),
            ),
            TunnelDiscriminator::Pptp(handle),
            "precondition: the quote must resolve, or this cell proves nothing \
             about touching"
        );

        let expired = sessions.pptp_mut().expire_idle(now, timeout);
        assert_eq!(
            expired, 1,
            "the association must still age out on its INSTALL time: an ICMP \
             error is traffic ABOUT the call, not ON it. If the resolve touched \
             the idle clock, errors would keep a dead call alive and hold a \
             16-bit id against reuse (#9298)"
        );
    }
}
