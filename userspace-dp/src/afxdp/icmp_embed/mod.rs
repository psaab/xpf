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
// #9901 (F-077): the quoted-L4 floor counter lives in the private `parse`
// submodule; the status vertical (`afxdp/coordinator/status.rs`) reads it
// through this re-export at the same visibility.
pub(in crate::afxdp) use parse::EMBEDDED_QUOTE_SUBMINIMAL_REFUSED_TOTAL;

/// Information returned from an embedded ICMP error session match,
/// including quoted-tuple NAT restoration and the forwarding resolution
/// needed to deliver the error toward its quoted sender.
#[derive(Clone, Debug)]
pub(super) struct EmbeddedIcmpMatch {
    /// The NAT decision for the matched session; builders use it to restore
    /// any translations in the quoted tuple.
    pub(super) nat: NatDecision,
    /// The quoted tuple's source IP after reversal of any source translation.
    /// For a forward quote this is usually the original client; for a reply
    /// quote it is the server.
    pub(super) original_src: IpAddr,
    /// The quoted tuple's source port after any source-port translation.
    pub(super) original_src_port: u16,
    /// The quoted tuple's destination IP after reversal of any destination
    /// translation.
    pub(super) original_dst: IpAddr,
    /// The quoted tuple's destination port after any destination-port
    /// translation.
    pub(super) original_dst_port: u16,
    /// The embedded packet's L4 protocol.
    pub(super) embedded_proto: u8,
    /// Forwarding resolution toward the quoted sender: the client for an
    /// error about a forward packet, or the server for an error about a reply.
    pub(super) resolution: ForwardingResolution,
    /// Session metadata (zones, RG).
    pub(super) metadata: SessionMetadata,
    /// #6474: this match is an OUTBOUND ICMP error through source NAT — the
    /// internal host emitted the error about the session's REPLY packet, so
    /// the quote carries the PRE-NAT tuple. The session-fallback matches
    /// either the FORWARD session via the quote's reply key
    /// (`is_reverse == false`, `rewrite_src` set — #14665: composed
    /// SNAT+DNAT included, the builders restore the wire destination
    /// from `rewrite_dst`) or —
    /// via its translated alias, in which case the match carries the
    /// recovered FORWARD decision. The caller must re-NAT the
    /// outer source and the embedded quote to the session's external
    /// identity (RFC 5508 §4) with the `build_snat_outbound_icmp_error_*`
    /// builders — NOT the #5690 reversal, which would consume the
    /// descriptor with the internal (pre-NAT) source on the wire and an
    /// unassociable quote. `false` on every inbound match.
    pub(super) outbound_snat: bool,
    /// #10667: the F-077 gating key this match was charged against. The
    /// poll arms refund it via
    /// `SessionTable::refund_icmp_error_not_delivered` on every post-match
    /// non-delivery terminal (TTL-expire, CoS drop, policy-refuse after
    /// `Queued`) so refused errors cannot starve permitted ones.
    /// `NotHandled` after a same-family BUILDER decline also refunds
    /// (#15152, the #14123 NAT64 precedent): the build failure is a
    /// non-delivery of a CHARGED match even though the descriptor then
    /// falls through to flowless enforcement, which re-adjudicates the
    /// original error without consuming this token again. `NotHandled`
    /// from `NoMatch` never charged, so there is nothing to refund there.
    pub(super) budget_key: SessionKey,
    /// #10671: the normalized arrival zone expected for the quoted packet's
    /// direction. A forward quote expects the session's egress zone; a reply
    /// quote expects its ingress zone (`via_reply_key XOR is_reverse`),
    /// including as-is reverse-half hits. The poll-side RELATED gate uses
    /// this for untranslated path errors and same-family NAT'd PMTUD, and
    /// admits only when the actual arrival zone is nonzero and equals this
    /// value. Zero means unresolved and falls through to ordinary
    /// arrival-to-egress policy.
    pub(super) related_expected_zone: u16,
}

/// Borrow bundle threaded through both v4/v6 NAT-match paths and the
/// embedded-ICMP return-resolution helper. ONE struct only — both the NAT
/// lookup path (which needs the shared NAT map and its ambiguity index) and
/// the return-resolution path (which doesn't) share the same `&mut` borrow on
/// `SessionTable`, so two structs holding `&mut sessions` concurrently would
/// be a borrow-checker error.
pub(in crate::afxdp::icmp_embed) struct NatMatchCtx<'a> {
    pub sessions: &'a mut SessionTable,
    pub forwarding: &'a ForwardingState,
    pub dynamic_neighbors: &'a Arc<ShardedNeighborMap>,
    pub shared_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub shared_owner_rg_indexes: Option<&'a crate::afxdp::types::SharedSessionOwnerRgIndexes>,
    pub shared_forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub ingress_zone_override: Option<u16>,
}

/// Outcome of an embedded-ICMP match attempt. THREE states, not two: a
/// session that MATCHED but is over its F-077 per-session error budget MUST
/// be distinguishable from a miss. Collapsing the denial to `None` would
/// fall through to ordinary flowless forwarding, which under an
/// ICMP-permitting policy keeps delivering the "suppressed" error (an
/// outbound-SNAT error past exhaustion would forward UNTRANSLATED rather
/// than drop). Callers map `BudgetDenied` to the descriptor-drop arm.
#[derive(Debug)]
pub(super) enum EmbeddedMatchOutcome<T> {
    /// A session matched and the error may be delivered.
    Match(T),
    /// A session matched but the per-session budget refused the error —
    /// the caller MUST drop the descriptor (fail-closed silent drop).
    BudgetDenied,
    /// No session matched — the caller falls through unchanged.
    NoMatch,
}

impl<T> EmbeddedMatchOutcome<T> {
    /// Collapse to `Option` (denial reads as no-match). Test-only: for
    /// cells with provably fresh budgets that assert match-vs-miss.
    /// Production callers must match all three arms.
    #[cfg(test)]
    pub(super) fn into_option(self) -> Option<T> {
        match self {
            EmbeddedMatchOutcome::Match(m) => Some(m),
            EmbeddedMatchOutcome::BudgetDenied | EmbeddedMatchOutcome::NoMatch => None,
        }
    }
}

/// #9901 (F-077): whether the OUTER (error-carrying) packet is atomic
/// (unfragmented) — the gate for the quoted-L4 adequacy floor. Read from the
/// presented frame at the meta L3 offset: v4 checks the frag word
/// (offset==0 && MF==0); v6 requires a NON-ATOMIC Fragment header
/// (`ipv6_is_nonatomically_fragmented`) — an offset-0/M-0 ATOMIC fragment
/// carries the whole datagram, so no later fragment can explain a short
/// quote and the floor stays on. Every `parse_embedded_v4/v6` call site
/// computes this and threads it in.
///
/// "Outer" is the error-carrying packet AS PRESENTED. Past GRE decap (#8271)
/// that is the INNER frame — which is the correct signal: the floor asks
/// whether the packet carrying the quote could legitimately carry a SHORT
/// quote (a first fragment), and that is a property of the presented packet,
/// not of the wire outer. An unreadable outer (short slice, incoherent meta)
/// or unknown family reads ATOMIC, so the floor applies — the quote of a
/// packet we cannot even frame is not adequate. (A declared-but-truncated v6
/// Fragment header is the one exception: its bits are unreadable, so the old
/// declares-fragmented behavior is kept — see the predicate's doc.)
///
/// Raw-stamp residual (#9900 follow-up): `meta.l3_offset` is read UNVERIFIED
/// here, not via `verified_l3_or_stamp`. A wrong stamp mis-slices the outer
/// bytes: short-slice → atomic → floor applies (fail-closed for quote
/// adequacy); a stamp landing on bytes with a set frag word → fragmented →
/// floor off (the residual — a short quote admitted it should have refused).
/// `get()` keeps this panic-free; full stamp verification is the #9900
/// follow-up. `outer_datagram_end` shares this residual (same stamp).
pub(in crate::afxdp::icmp_embed) fn outer_error_atomic(
    frame: &[u8],
    meta: &UserspaceDpMeta,
) -> bool {
    let outer = frame.get(meta.l3_offset as usize..).unwrap_or(&[]);
    let fragmented = match meta.addr_family as i32 {
        libc::AF_INET => crate::afxdp::frame::ipv4_is_any_fragment(outer),
        libc::AF_INET6 => crate::afxdp::frame::ipv6_is_nonatomically_fragmented(outer),
        _ => return true,
    };
    !fragmented
}

/// #9901 (F-077): the containing outer IP datagram's end offset (absolute in
/// `frame`), bounding every quote read. v4: L3 + total-length; v6: L3 + 40 +
/// payload-length. An incoherent or unreadable outer header (v4 total < 20,
/// v6 header truncated, v6 jumbo payload 0, unknown family) falls back to
/// `frame.len()` — pre-fix behavior, bounding only when boundable. WITHOUT
/// this, slack/padding beyond the outer datagram would satisfy the floor's
/// captured leg while the builders (which strip to the outer length,
/// `builders.rs`) ship a shorter quote — a 4-byte quote smuggled past the
/// 8-byte floor. Raw-stamp residual: like `outer_error_atomic` this reads at
/// the raw `meta.l3_offset` — see the disclosure there (#9900 follow-up).
pub(in crate::afxdp::icmp_embed) fn outer_datagram_end(
    frame: &[u8],
    meta: &UserspaceDpMeta,
) -> usize {
    let l3 = meta.l3_offset as usize;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let total = frame
                .get(l3 + 2..l3 + 4)
                .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
                .unwrap_or(0);
            if total >= 20 {
                l3.saturating_add(total)
            } else {
                frame.len()
            }
        }
        libc::AF_INET6 => {
            if frame.len() < l3 + 40 {
                return frame.len();
            }
            let payload = u16::from_be_bytes([frame[l3 + 4], frame[l3 + 5]]) as usize;
            if payload == 0 {
                // Jumbo (or empty): length lives in a HbH option / nowhere —
                // unboundable without a header walk, so pre-fix behavior.
                return frame.len();
            }
            l3.saturating_add(40).saturating_add(payload)
        }
        _ => frame.len(),
    }
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
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    now_ns: u64,
    routing_domain: u32,
) -> Option<SessionLookup> {
    let frame = area.slice(desc.addr as usize, desc.len as usize)?;
    session_match::try_embedded_icmp_session_match_from_frame(
        frame,
        meta,
        forwarding,
        sessions,
        now_ns,
        routing_domain,
    )
}

/// Core embedded ICMP session match logic operating on a frame slice.
pub(super) fn try_embedded_icmp_session_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    now_ns: u64,
    routing_domain: u32,
) -> Option<SessionLookup> {
    session_match::try_embedded_icmp_session_match_from_frame(
        frame,
        meta,
        forwarding,
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
/// frame slice. Dispatches to the v4 / v6 outer family branch. Returns
/// `BudgetDenied` when a session matched but the F-077 budget refused it —
/// the poll caller MUST drop the descriptor, never fall through.
#[allow(clippy::too_many_arguments)]
#[inline]
pub(super) fn try_embedded_icmp_nat_match_from_frame_with_owner_indexes(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &crate::afxdp::types::SharedSessionOwnerRgIndexes,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
    ingress_zone_override: Option<u16>,
) -> EmbeddedMatchOutcome<EmbeddedIcmpMatch> {
    try_embedded_icmp_nat_match_from_frame_inner(
        frame,
        meta,
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        Some(shared_owner_rg_indexes),
        shared_forward_wire_sessions,
        now_ns,
        ingress_zone_override,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn try_embedded_icmp_nat_match_from_frame_without_ingress_zone(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &crate::afxdp::types::SharedSessionOwnerRgIndexes,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> EmbeddedMatchOutcome<EmbeddedIcmpMatch> {
    try_embedded_icmp_nat_match_from_frame_inner(
        frame,
        meta,
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        Some(shared_owner_rg_indexes),
        shared_forward_wire_sessions,
        now_ns,
        None,
    )
}

#[cfg(test)]
#[inline]
pub(super) fn try_embedded_icmp_nat_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
) -> EmbeddedMatchOutcome<EmbeddedIcmpMatch> {
    try_embedded_icmp_nat_match_from_frame_inner(
        frame,
        meta,
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        None,
        shared_forward_wire_sessions,
        now_ns,
        None,
    )
}

#[cfg(test)]
pub(super) fn try_embedded_icmp_nat_match_from_frame_with_ingress_zone(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
    ingress_zone_override: Option<u16>,
) -> EmbeddedMatchOutcome<EmbeddedIcmpMatch> {
    try_embedded_icmp_nat_match_from_frame_inner(
        frame,
        meta,
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        None,
        shared_forward_wire_sessions,
        now_ns,
        ingress_zone_override,
    )
}

#[inline]
fn try_embedded_icmp_nat_match_from_frame_inner(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: Option<&crate::afxdp::types::SharedSessionOwnerRgIndexes>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
    ingress_zone_override: Option<u16>,
) -> EmbeddedMatchOutcome<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let Some(icmp_type) = frame.get(l4).copied() else {
        return EmbeddedMatchOutcome::NoMatch;
    };
    if !is_icmp_error(meta.protocol, icmp_type) {
        return EmbeddedMatchOutcome::NoMatch;
    }
    let mut ctx = NatMatchCtx {
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        shared_owner_rg_indexes,
        shared_forward_wire_sessions,
        ingress_zone_override,
    };
    match meta.protocol {
        PROTO_ICMP => nat_match_v4::match_outer_v4(frame, meta, &mut ctx, now_ns),
        PROTO_ICMPV6 => nat_match_v6::match_outer_v6(frame, meta, &mut ctx, now_ns),
        _ => EmbeddedMatchOutcome::NoMatch,
    }
}

pub(super) use nat64_match::Nat64IcmpErrorMatch;

/// #6472: NAT64 flowless ICMP-error session match, operating on a frame
/// slice. Builds the `NatMatchCtx` borrow bundle exactly like
/// [`try_embedded_icmp_nat_match_from_frame`] and dispatches to the
/// cross-family matcher; the poll-side caller translates + forwards per the
/// returned direction. `NoMatch` = not a NAT64 session error (the
/// same-family reversal and normal flowless enforcement run unchanged);
/// `BudgetDenied` = a half matched but the F-077 budget refused it (the
/// poll caller MUST drop the descriptor, never translate NOR fall through).
#[allow(clippy::too_many_arguments)]
pub(super) fn try_nat64_icmp_error_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    now_ns: u64,
    ingress_zone_override: Option<u16>,
) -> EmbeddedMatchOutcome<Nat64IcmpErrorMatch> {
    let mut ctx = NatMatchCtx {
        sessions,
        forwarding,
        dynamic_neighbors,
        shared_sessions,
        shared_nat_sessions,
        shared_owner_rg_indexes: Some(shared_owner_rg_indexes),
        shared_forward_wire_sessions,
        ingress_zone_override,
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
    resolve_quoted_pptp_discriminator_in_domain(sessions, 0, quoted, quoted_call_id, quoted_dst)
}

pub(in crate::afxdp::icmp_embed) fn resolve_quoted_pptp_discriminator_in_domain(
    sessions: &SessionTable,
    routing_domain: u32,
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
    match sessions
        .pptp()
        .resolve_in_domain(routing_domain, quoted_dst, call_id)
    {
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

    #[test]
    fn a_quoted_pptp_call_id_resolves_only_in_its_routing_domain_13681() {
        let mut sessions = SessionTable::new();
        let call_a = crate::session::pptp::PptpCall::new_in_domain(
            10,
            IpAddr::from(PEER_A),
            100,
            IpAddr::from(PEER_B),
            200,
        );
        let call_b = crate::session::pptp::PptpCall::new_in_domain(
            20,
            IpAddr::from(PEER_A),
            100,
            IpAddr::from(PEER_B),
            200,
        );
        let control_a = crate::session::pptp::ControlChannelId::new_in_domain(
            10,
            IpAddr::from(PEER_A),
            49_152,
            IpAddr::from(PEER_B),
            1723,
        );
        let control_b = crate::session::pptp::ControlChannelId::new_in_domain(
            20,
            IpAddr::from(PEER_A),
            49_152,
            IpAddr::from(PEER_B),
            1723,
        );
        let handle_a = sessions
            .pptp_mut()
            .install(call_a, control_a, 1_000)
            .expect("domain 10 call");
        let handle_b = sessions
            .pptp_mut()
            .install(call_b, control_b, 1_000)
            .expect("domain 20 call");

        for (domain, expected) in [(10, handle_a), (20, handle_b)] {
            assert_eq!(
                resolve_quoted_pptp_discriminator_in_domain(
                    &sessions,
                    domain,
                    TunnelDiscriminator::Unparseable,
                    Some(200),
                    IpAddr::from(PEER_B),
                ),
                TunnelDiscriminator::Pptp(expected)
            );
        }
        assert_eq!(
            resolve_quoted_pptp_discriminator_in_domain(
                &sessions,
                30,
                TunnelDiscriminator::Unparseable,
                Some(200),
                IpAddr::from(PEER_B),
            ),
            TunnelDiscriminator::Unparseable
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

// ---------------------------------------------------------------------------
// #15771: the companion-absent fallback of `embedded_icmp_return_resolution` /
// `embedded_icmp_quoted_reply_resolution` must resolve in the flow's own
// routing domain / installing table, never the default `inet.0`/`inet6.0`.
//
// Fixture shape (report §G36-03): the target prefix exists in BOTH the tenant
// table (egress 11) and the default table (egress 99), with distinct neighbors
// so a cross-table leak is observable as egress/neighbor, not just disposition.
// No companion session is installed, so the probe misses and the fresh
// fallback runs. Pre-fix both helpers called the table-free lookup and
// returned egress 99 (RED); post-fix they return egress 11.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod return_resolution_15771 {
    use super::return_resolution::{
        embedded_icmp_quoted_reply_resolution, embedded_icmp_return_resolution,
    };
    use super::*;
    use crate::prefix::{PrefixV4, PrefixV6};

    const TENANT_EGRESS: i32 = 11;
    const DEFAULT_EGRESS: i32 = 99;
    const TENANT_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 11];
    const DEFAULT_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 99];
    const TENANT_SRC_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 11];
    const DEFAULT_SRC_MAC: [u8; 6] = [0x02, 0xaa, 0, 0, 0, 99];

    fn tenant_identity() -> (u32, u32) {
        crate::session::install_table_identity("tenant-a")
    }

    fn v4_target() -> Ipv4Addr {
        Ipv4Addr::new(10, 99, 1, 50)
    }

    fn v6_target() -> Ipv6Addr {
        "2001:db8:99::50".parse().expect("v6 target")
    }

    fn egress_row(ifindex: i32, src_mac: [u8; 6]) -> EgressInterface {
        EgressInterface {
            bind_ifindex: 0,
            vlan_id: 0,
            mtu: 1500,
            src_mac,
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: None,
            primary_v6: None,
        }
    }

    /// Tenant table + conflicting default table, both families, plus the
    /// tenant install-table registry row. Egress rows give each route its
    /// source MAC so `populate_egress_resolution` completes the resolution.
    fn vrf_forwarding() -> ForwardingState {
        let (domain, check) = tenant_identity();
        let mut state = ForwardingState::default();
        state.has_routing_domains = true;
        state.install_tables.insert(
            domain,
            InstallTables {
                v4: Some("tenant-a.inet.0".to_string()),
                v6: Some("tenant-a.inet6.0".to_string()),
                h2: check,
            },
        );
        state
            .egress
            .insert(TENANT_EGRESS, egress_row(TENANT_EGRESS, TENANT_SRC_MAC));
        state
            .egress
            .insert(DEFAULT_EGRESS, egress_row(DEFAULT_EGRESS, DEFAULT_SRC_MAC));
        state.routes_v4.insert(
            "tenant-a.inet.0".to_string(),
            vec![RouteEntryV4::single(
                PrefixV4::from_net("10.99.1.0/24".parse().expect("tenant v4 prefix")),
                TENANT_EGRESS,
                0,
                Some(v4_target()),
                false,
                String::new(),
                0,
            )],
        );
        state.routes_v4.insert(
            "inet.0".to_string(),
            vec![RouteEntryV4::single(
                PrefixV4::from_net("10.99.1.0/24".parse().expect("default v4 prefix")),
                DEFAULT_EGRESS,
                0,
                Some(v4_target()),
                false,
                String::new(),
                0,
            )],
        );
        state.routes_v6.insert(
            "tenant-a.inet6.0".to_string(),
            vec![RouteEntryV6::single(
                PrefixV6::from_net("2001:db8:99::/64".parse().expect("tenant v6 prefix")),
                TENANT_EGRESS,
                0,
                Some(v6_target()),
                false,
                String::new(),
                0,
            )],
        );
        state.routes_v6.insert(
            "inet6.0".to_string(),
            vec![RouteEntryV6::single(
                PrefixV6::from_net("2001:db8:99::/64".parse().expect("default v6 prefix")),
                DEFAULT_EGRESS,
                0,
                Some(v6_target()),
                false,
                String::new(),
                0,
            )],
        );
        state
    }

    fn neighbors() -> Arc<ShardedNeighborMap> {
        let neighbors = Arc::new(ShardedNeighborMap::new());
        neighbors.insert(
            (TENANT_EGRESS, IpAddr::V4(v4_target())),
            crate::afxdp::types::NeighborEntry { mac: TENANT_MAC },
        );
        neighbors.insert(
            (DEFAULT_EGRESS, IpAddr::V4(v4_target())),
            crate::afxdp::types::NeighborEntry { mac: DEFAULT_MAC },
        );
        neighbors.insert(
            (TENANT_EGRESS, IpAddr::V6(v6_target())),
            crate::afxdp::types::NeighborEntry { mac: TENANT_MAC },
        );
        neighbors.insert(
            (DEFAULT_EGRESS, IpAddr::V6(v6_target())),
            crate::afxdp::types::NeighborEntry { mac: DEFAULT_MAC },
        );
        neighbors
    }

    struct Harness {
        sessions: SessionTable,
        forwarding: ForwardingState,
        dynamic_neighbors: Arc<ShardedNeighborMap>,
        shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        owner_indexes: crate::afxdp::types::SharedSessionOwnerRgIndexes,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                sessions: SessionTable::new(),
                forwarding: vrf_forwarding(),
                dynamic_neighbors: neighbors(),
                shared_sessions: Arc::new(Mutex::new(FastMap::default())),
                shared_nat_sessions: Arc::new(Mutex::new(FastMap::default())),
                shared_forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
                owner_indexes: crate::afxdp::types::SharedSessionOwnerRgIndexes::default(),
            }
        }

        fn ctx(&mut self) -> NatMatchCtx<'_> {
            NatMatchCtx {
                sessions: &mut self.sessions,
                forwarding: &self.forwarding,
                dynamic_neighbors: &self.dynamic_neighbors,
                shared_sessions: &self.shared_sessions,
                shared_nat_sessions: &self.shared_nat_sessions,
                shared_owner_rg_indexes: Some(&self.owner_indexes),
                shared_forward_wire_sessions: &self.shared_forward_wire_sessions,
                ingress_zone_override: None,
            }
        }
    }

    fn forward_key_v4(domain: u32) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: IpAddr::V4(v4_target()),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            src_port: 40_000,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: domain,
        }
    }

    fn forward_key_v6(domain: u32) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: 6,
            src_ip: IpAddr::V6(v6_target()),
            dst_ip: IpAddr::V6("2001:db8:ffff::7".parse().expect("v6 dst")),
            src_port: 40_000,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: domain,
        }
    }

    fn plain_decision() -> SessionDecision {
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::NoRoute,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        }
    }

    fn assert_tenant(resolution: &ForwardingResolution, what: &str) {
        assert_eq!(
            resolution.disposition,
            ForwardingDisposition::ForwardCandidate,
            "{what}: tenant route must forward, got {resolution:?}"
        );
        assert_eq!(
            resolution.egress_ifindex, TENANT_EGRESS,
            "{what}: must egress via tenant ifindex {TENANT_EGRESS}, not default {DEFAULT_EGRESS}"
        );
        assert_eq!(
            resolution.neighbor_mac,
            Some(TENANT_MAC),
            "{what}: tenant neighbor"
        );
    }

    #[test]
    fn return_resolution_no_companion_uses_tenant_table_v4_15771() {
        let (domain, _) = tenant_identity();
        let mut h = Harness::new();
        let key = forward_key_v4(domain);
        let resolution = embedded_icmp_return_resolution(
            &mut h.ctx(),
            &key,
            plain_decision(),
            IpAddr::V4(v4_target()),
            1_000,
        );
        assert_tenant(&resolution, "return v4");
    }

    #[test]
    fn return_resolution_no_companion_uses_tenant_table_v6_15771() {
        let (domain, _) = tenant_identity();
        let mut h = Harness::new();
        let key = forward_key_v6(domain);
        let resolution = embedded_icmp_return_resolution(
            &mut h.ctx(),
            &key,
            plain_decision(),
            IpAddr::V6(v6_target()),
            1_000,
        );
        assert_tenant(&resolution, "return v6");
    }

    #[test]
    fn quoted_reply_resolution_no_companion_uses_tenant_table_v4_15771() {
        let (domain, _) = tenant_identity();
        let mut h = Harness::new();
        let key = forward_key_v4(domain);
        let resolution = embedded_icmp_quoted_reply_resolution(
            &mut h.ctx(),
            &key,
            IpAddr::V4(v4_target()),
            1_000,
        );
        assert_tenant(&resolution, "quoted-reply v4");
    }

    #[test]
    fn quoted_reply_resolution_no_companion_uses_tenant_table_v6_15771() {
        let (domain, _) = tenant_identity();
        let mut h = Harness::new();
        let key = forward_key_v6(domain);
        let resolution = embedded_icmp_quoted_reply_resolution(
            &mut h.ctx(),
            &key,
            IpAddr::V6(v6_target()),
            1_000,
        );
        assert_tenant(&resolution, "quoted-reply v6");
    }

    /// A stamped installing table (PBR or native install stamp) scopes the
    /// return fallback even when the key itself carries domain 0.
    #[test]
    fn return_resolution_stamped_install_table_scopes_fallback_15771() {
        let (domain, check) = tenant_identity();
        let mut h = Harness::new();
        let key = forward_key_v4(0);
        let mut decision = plain_decision();
        decision.install_table_domain = domain;
        decision.install_table_check = check;
        let resolution = embedded_icmp_return_resolution(
            &mut h.ctx(),
            &key,
            decision,
            IpAddr::V4(v4_target()),
            1_000,
        );
        assert_tenant(&resolution, "stamped return v4");
    }

    /// An unresolvable stamp must fail closed, never probe the default table.
    #[test]
    fn return_resolution_unresolvable_stamp_fails_closed_15771() {
        let (domain, check) = tenant_identity();
        let mut h = Harness::new();
        h.forwarding.install_tables.remove(&domain);
        let key = forward_key_v4(domain);
        let mut decision = plain_decision();
        decision.install_table_domain = domain;
        decision.install_table_check = check;
        let resolution = embedded_icmp_return_resolution(
            &mut h.ctx(),
            &key,
            decision,
            IpAddr::V4(v4_target()),
            1_000,
        );
        assert_eq!(
            resolution.disposition,
            ForwardingDisposition::TableUnavailable,
            "unresolvable installing table must fail closed, got {resolution:?}"
        );
        assert_eq!(resolution.egress_ifindex, 0);
    }

    /// A nonzero routing domain with no registry row must fail closed.
    #[test]
    fn quoted_reply_unknown_domain_fails_closed_15771() {
        let (domain, _) = tenant_identity();
        let mut h = Harness::new();
        h.forwarding.install_tables.remove(&domain);
        let key = forward_key_v4(domain);
        let resolution = embedded_icmp_quoted_reply_resolution(
            &mut h.ctx(),
            &key,
            IpAddr::V4(v4_target()),
            1_000,
        );
        assert_eq!(
            resolution.disposition,
            ForwardingDisposition::TableUnavailable,
            "unknown routing domain must fail closed, got {resolution:?}"
        );
    }

    /// Control: domain 0 / unstamped keeps the historical default-table path.
    #[test]
    fn return_resolution_default_domain_still_uses_default_table_15771() {
        let mut h = Harness::new();
        let key = forward_key_v4(0);
        let resolution = embedded_icmp_return_resolution(
            &mut h.ctx(),
            &key,
            plain_decision(),
            IpAddr::V4(v4_target()),
            1_000,
        );
        assert_eq!(
            resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(
            resolution.egress_ifindex, DEFAULT_EGRESS,
            "control: default-domain flow must keep resolving in inet.0"
        );
        assert_eq!(resolution.neighbor_mac, Some(DEFAULT_MAC));
    }
}
