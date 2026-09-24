//! #6472: NAT64 (cross-family) embedded-ICMP error session match, wired
//! into the FLOWLESS poll arm — the path every non-query ICMP error takes
//! (#3290). The same-family reversal (`nat_match_v4`/`nat_match_v6`) cannot
//! serve a NAT64 session: its builders are single-family (the v4 builder
//! declines a V6 `original_src`, the v6 builder a V4 one), and the flowless
//! L3 enforcement that follows cannot route the synthetic Pref64
//! destination (case B) nor associate the pool-address destination with a
//! local socket (case A) — so PTB / Time-Exceeded / Dest-Unreachable toward
//! a NAT64 session dropped fail-closed and PMTUD + traceroute were dead
//! across the boundary even though the RFC 7915 §4.2/§5.2 translators in
//! `nat64.rs` existed (reachable only from the flow-backed arm, which an
//! ICMP error never enters).
//!
//! Two directions, distinguished by the QUOTE's direction (an ICMP error is
//! always addressed to the source of the offending packet — RFC 792 — so
//! the outer destination must equal the quote's source; that equality is
//! the fail-closed anti-spoof gate):
//!
//! * **V4ToV6** (RFC 7915 §4.2): an ICMPv4 error from a v4 hop addressed to
//!   the session's pool address, quoting the FORWARD wire packet
//!   `(pool:xlated_port → server:port)`. The quote's reply key is the
//!   installed v4 reverse companion's primary key. The error is translated
//!   to ICMPv6 toward the original v6 client: outer src = Pref64 ∷ router
//!   (§6 stateless source mapping), outer dst = `orig_src_v6`, and the
//!   embedded quote reads back as the ORIGINAL v6 forward packet
//!   `(client:orig_port → Pref64::server:port)` — the L4 source port/echo
//!   id is restored from the reverse decision's `rewrite_dst_port`.
//!
//! * **V6ToV4** (RFC 7915 §5.2): an ICMPv6 error from a v6 hop about the
//!   session's translated REPLY packet, addressed to the synthetic
//!   `Pref64::server` destination and quoting `(Pref64::server:port →
//!   client:orig_port)`. The quote's reply key is the installed forward
//!   session's primary key. The error is translated to ICMPv4 toward the
//!   v4 server: outer src = the translator's pool address (the session's
//!   own translated source — the translator's address for that session,
//!   used because the v6 hop's source has no IPv4 mapping, the RFC 6791
//!   §6 case), outer dst = the extracted server v4, and the embedded quote
//!   reads back as the v4 reply the server sent
//!   `(server:port → pool:xlated_port)` — the L4 destination port/echo id
//!   is restored from the forward decision's `rewrite_src_port`.
//!
//! Both directions ride the ADMITTED session (the flow was permitted by
//! policy; the error is that session's control traffic), mirroring the
//! #5690 same-family reversal's posture — and like it, the translated
//! error is queued as a prebuilt forward with `flow_key = None`, so the
//! #3290 no-fake-session invariant is preserved.

use super::parse::{embedded_reply_key, parse_embedded_v4, parse_embedded_v6};
use super::outer_error_atomic;
use super::*;
use crate::session::TunnelDiscriminator;

/// Outcome of [`try_nat64_icmp_error_match`]: the matched session plus
/// every datum the poll-side builder needs to translate and forward the
/// error, split by translation direction.
pub(in crate::afxdp) enum Nat64IcmpErrorMatch {
    /// ICMPv4 error → ICMPv6 toward the v6 client (RFC 7915 §4.2).
    V4ToV6 {
        /// Original IPv6 client (`Nat64ReverseInfo.orig_src_v6`) — the
        /// translated error's outer destination.
        orig_src_v6: Ipv6Addr,
        /// Original synthetic destination (`Nat64ReverseInfo.orig_dst_v6`)
        /// — its high 96 bits are the NAT64 prefix the outer source and
        /// the embedded destination compose onto.
        orig_dst_v6: Ipv6Addr,
        /// The v6 client's ORIGINAL L4 source port / echo id (reverse
        /// decision's `rewrite_dst_port`), restored into the quote.
        orig_client_port: u16,
        /// Forwarding resolution toward the v6 client (the reverse
        /// companion's cached decision resolution).
        resolution: ForwardingResolution,
        /// Reverse companion metadata (zones for the HA/fabric finalizer).
        metadata: SessionMetadata,
        /// #10667: the F-077 gating key this match was charged against
        /// (`reply_key`) — refunded on post-match non-delivery terminals.
        budget_key: SessionKey,
    },
    /// ICMPv6 error → ICMPv4 toward the v4 server (RFC 7915 §5.2).
    V6ToV4 {
        /// The session's translated pool source — the translated error's
        /// outer source (the translator's own v4 address for this session).
        pool_v4: Ipv4Addr,
        /// The extracted IPv4 server (`rewrite_dst`) — outer destination.
        server_v4: Ipv4Addr,
        /// The session's TRANSLATED L4 source port / echo id (forward
        /// decision's `rewrite_src_port`), restored into the quote's
        /// destination field so the server associates the error.
        translated_port: u16,
        /// Forwarding resolution toward the v4 server (the forward
        /// session's cached decision resolution).
        resolution: ForwardingResolution,
        /// Forward session metadata (zones for the HA/fabric finalizer).
        metadata: SessionMetadata,
        /// #10667: the F-077 gating key this match was charged against
        /// (`forward_key`) — refunded on post-match non-delivery terminals.
        budget_key: SessionKey,
    },
}

/// Match a flowless ICMP error against the NAT64 session tables. Returns
/// `NoMatch` (caller falls through to the same-family #5690 reversal and then
/// normal flowless enforcement, unchanged) when no NAT64 prefix is
/// configured, the packet is not an ICMP error carrying a parseable quote,
/// the outer-destination/quote-source consistency gate fails, or the quote
/// matches no live NAT64 session half. Returns `BudgetDenied` (caller MUST
/// drop the descriptor) when a half matched but the F-077 per-session budget
/// refused it — never a fallthrough.
pub(in crate::afxdp::icmp_embed) fn try_nat64_icmp_error_match(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ctx: &mut NatMatchCtx<'_>,
    now_ns: u64,
) -> EmbeddedMatchOutcome<Nat64IcmpErrorMatch> {
    // Zero-cost gate for non-NAT64 deployments: one Vec::is_empty() branch
    // before any parse (this match runs on the flowless arm, which also
    // serves ordinary non-first fragments).
    if ctx.forwarding.nat64.prefixes.is_empty() {
        return EmbeddedMatchOutcome::NoMatch;
    }
    let l4 = meta.l4_offset as usize;
    let Some(icmp_type) = frame.get(l4).copied() else {
        return EmbeddedMatchOutcome::NoMatch;
    };
    if !is_icmp_error(meta.protocol, icmp_type) {
        return EmbeddedMatchOutcome::NoMatch;
    }
    match meta.protocol {
        PROTO_ICMP => match_v4_error(frame, meta, ctx, now_ns),
        PROTO_ICMPV6 => match_v6_error(frame, meta, ctx, now_ns),
        _ => EmbeddedMatchOutcome::NoMatch,
    }
}

/// V4ToV6 arm: an ICMPv4 error about the session's forward wire packet.
fn match_v4_error(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ctx: &mut NatMatchCtx<'_>,
    now_ns: u64,
) -> EmbeddedMatchOutcome<Nat64IcmpErrorMatch> {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    // Outer destination: the address the error is addressed TO — for a
    // genuine error about the session's forward packet, the session's pool
    // address (the offending packet's source, RFC 792).
    let Some(outer_dst_v4) = frame
        .get(l3 + 16..l3 + 20)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(Ipv4Addr::from)
    else {
        return EmbeddedMatchOutcome::NoMatch;
    };

    let Some(hdr) = parse_embedded_v4(
        frame,
        l4 + 8,
        outer_error_atomic(frame, &meta),
        super::outer_datagram_end(frame, &meta),
    ) else {
        return EmbeddedMatchOutcome::NoMatch;
    };
    // Fail-closed consistency gate: the quote's source must BE the outer
    // destination. A mismatch means the error is not about this session's
    // wire packet (misrouted/forged) — decline to the same-family arm.
    if hdr.src != outer_dst_v4 {
        return EmbeddedMatchOutcome::NoMatch;
    }
    // #9162: the routing domain of the interface the error arrived on, the way
    // the same-family arms (`nat_match_v4.rs` / `nat_match_v6.rs`) resolve it.
    // This file carried ZERO `routing_domain` references while both siblings
    // carried one, and that asymmetry was the whole defect: the quote's reply
    // key resolves an INSTALLED NAT64 session half through
    // `lookup_session_across_scopes`, whose four probes are every one
    // domain-PRESERVING, so a domain-0 key could not reach a session in a
    // routing instance and the error was DROPPED by flowless enforcement --
    // PMTUD and traceroute dead across the NAT64 boundary in every VRF.
    //
    // The arriving interface is the right source for the same reason
    // `nat_match_v4.rs` gives: an ICMP error about a flow comes back on that
    // flow's EGRESS side, so for a flow contained in one routing instance this
    // resolves the flow's own domain. Unlike the same-family arms there is NO
    // domain-agnostic fallback here, and that is deliberate rather than an
    // omission -- the only fallback available would be a retry at domain 0,
    // which is not "domain-agnostic" but "the DEFAULT instance", i.e. a
    // different tenant's sessions. A non-contained flow therefore declines to
    // the same-family arm and then to ordinary flowless enforcement, exactly
    // as it did before this stamp existed; it never matches across tenants.
    let embedded_routing_domain = crate::afxdp::forwarding::ingress_routing_domain(
        ctx.forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        None,
    );
    // The quote is the forward wire packet (pool:xlated → server:port); its
    // reply key is the installed v4 reverse companion's primary key.
    let reply_key = embedded_reply_key(
        libc::AF_INET as u8,
        hdr.proto,
        IpAddr::V4(hdr.src),
        IpAddr::V4(hdr.dst),
        hdr.src_port,
        hdr.dst_port,
        // #9031: NAT64 translates the protocol across address families, so a
        // quoted GRE header on one side does not name a tunnel identity the
        // session on the other side carries. None is the CORRECT value here and
        // not an omission -- the constructors #9031 names are the same-family
        // ones. Stated so the next reader does not "fix" it into a mismatch.
        TunnelDiscriminator::None,
        embedded_routing_domain,
    );
    let Some(resolved) = probe_session_across_scopes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        &reply_key,
        now_ns,
    ) else {
        return EmbeddedMatchOutcome::NoMatch;
    };
    let sl = resolved.lookup;
    // Must be the v4 REVERSE companion of a NAT64 flow — a same-family
    // session half (or the forward half) is the #5690 arm's business.
    let Some(info) = sl.metadata.nat64_reverse else {
        return EmbeddedMatchOutcome::NoMatch;
    };
    if !sl.metadata.is_reverse || !sl.decision.nat.nat64 {
        return EmbeddedMatchOutcome::NoMatch;
    }
    // The reverse decision (produced by `NatDecision::reverse`) carries the
    // ORIGINAL client source port / echo id in `rewrite_dst_port`; absent a
    let orig_client_port = sl.decision.nat.rewrite_dst_port.unwrap_or(hdr.src_port);
    // #9901 (F-077): per-session error budget, keyed on the installed v4
    // reverse companion's primary key (the stable identity for this NAT64
    // flow's errors). Shared/peer resolutions budget via the side table.
    // Denial is BudgetDenied (drop arm), never a fallthrough.
    if !ctx.sessions.note_icmp_error_delivered(&reply_key, now_ns) {
        return EmbeddedMatchOutcome::BudgetDenied;
    }
    EmbeddedMatchOutcome::Match(Nat64IcmpErrorMatch::V4ToV6 {
        orig_src_v6: info.orig_src_v6,
        orig_dst_v6: info.orig_dst_v6,
        orig_client_port,
        resolution: sl.decision.resolution,
        metadata: sl.metadata,
        budget_key: reply_key,
    })
}

/// V6ToV4 arm: an ICMPv6 error about the session's translated reply packet.
fn match_v6_error(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ctx: &mut NatMatchCtx<'_>,
    now_ns: u64,
) -> EmbeddedMatchOutcome<Nat64IcmpErrorMatch> {
    let l3 = meta.l3_offset as usize;
    let l4 = meta.l4_offset as usize;
    let Some(outer_dst_v6) = frame
        .get(l3 + 24..l3 + 40)
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .map(Ipv6Addr::from)
    else {
        return EmbeddedMatchOutcome::NoMatch;
    };
    // Only an error addressed to a SYNTHETIC Pref64 destination can be a
    // NAT64 session error; an error addressed to a real v6 host (e.g. the
    // client, about the forward packet) is ordinary v6 traffic that the
    // flowless arm routes normally — do not intercept it.
    if ctx
        .forwarding
        .nat64
        .match_ipv6_dest(outer_dst_v6)
        .is_none()
    {
        return EmbeddedMatchOutcome::NoMatch;
    }

    let Some(hdr) = parse_embedded_v6(
        frame,
        l4 + 8,
        outer_error_atomic(frame, &meta),
        super::outer_datagram_end(frame, &meta),
    ) else {
        return EmbeddedMatchOutcome::NoMatch;
    };
    // Fail-closed consistency gate: the quote must be the session's
    // RETURN-direction wire packet — its source is the same synthetic
    // Pref64 address the error is addressed to (the offending packet's
    // source, RFC 792). A quote of the FORWARD packet (client → Pref64)
    // belongs to an error addressed to the client and fails this gate.
    if hdr.src_wire != outer_dst_v6 {
        return EmbeddedMatchOutcome::NoMatch;
    }
    // #9162: see the twin derivation in `match_v4_error`. This arm resolves the
    // installed FORWARD session, whose key has been domain-stamped since #7160
    // (`poll_descriptor/mod.rs`, "THE single site that populates
    // `SessionKey.routing_domain`"), so this direction has been dead in a VRF
    // since #7160 -- longer than the v4->v6 arm, which #9271 broke by stamping
    // the installed reverse companion while this probe still asked for 0.
    let embedded_routing_domain = crate::afxdp::forwarding::ingress_routing_domain(
        ctx.forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        None,
    );
    // The quote is the translated reply (Pref64::server:port → client:port);
    // its reply key is the installed forward session's primary key.
    let forward_key = embedded_reply_key(
        libc::AF_INET6 as u8,
        hdr.proto,
        IpAddr::V6(hdr.src_wire),
        hdr.dst,
        hdr.src_port,
        hdr.dst_port,
        // #9031: NAT64 translates the protocol across address families, so a
        // quoted GRE header on one side does not name a tunnel identity the
        // session on the other side carries. None is the CORRECT value here and
        // not an omission -- the constructors #9031 names are the same-family
        // ones. Stated so the next reader does not "fix" it into a mismatch.
        TunnelDiscriminator::None,
        embedded_routing_domain,
    );
    let Some(resolved) = probe_session_across_scopes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        &forward_key,
        now_ns,
    ) else {
        return EmbeddedMatchOutcome::NoMatch;
    };
    let sl = resolved.lookup;
    // Must be the FORWARD half of a NAT64 flow carrying the v4 translation.
    if sl.metadata.is_reverse
        || !sl.decision.nat.nat64
        || sl.metadata.nat64_reverse.is_none()
    {
        return EmbeddedMatchOutcome::NoMatch;
    }
    let pool_v4 = match sl.decision.nat.rewrite_src {
        Some(IpAddr::V4(v4)) => v4,
        _ => return EmbeddedMatchOutcome::NoMatch,
    };
    let server_v4 = match sl.decision.nat.rewrite_dst {
        Some(IpAddr::V4(v4)) => v4,
        _ => return EmbeddedMatchOutcome::NoMatch,
    };
    // The forward decision carries the TRANSLATED source port / echo id in
    // `rewrite_src_port`; absent a port translation the quote already
    let translated_port = sl.decision.nat.rewrite_src_port.unwrap_or(hdr.dst_port);
    // #9901 (F-077): per-session error budget, keyed on the installed
    // forward session's primary key. Shared/peer resolutions budget via
    // the side table. Denial is BudgetDenied (drop arm), never a fallthrough.
    if !ctx.sessions.note_icmp_error_delivered(&forward_key, now_ns) {
        return EmbeddedMatchOutcome::BudgetDenied;
    }
    EmbeddedMatchOutcome::Match(Nat64IcmpErrorMatch::V6ToV4 {
        pool_v4,
        server_v4,
        translated_port,
        resolution: sl.decision.resolution,
        metadata: sl.metadata,
        budget_key: forward_key,
    })
}
