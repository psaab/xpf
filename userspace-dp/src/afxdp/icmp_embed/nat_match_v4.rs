use super::*;
use super::parse::{embedded_reply_key, parse_embedded_v4};
use super::outer_error_atomic;
use super::return_resolution::{
    embedded_icmp_quoted_reply_resolution, embedded_icmp_return_resolution,
};

/// IPv4-outer branch of `try_embedded_icmp_nat_match_from_frame`.
/// Mirrors `icmp_embed.rs:210-332` literally. Tries the forward-NAT
/// (rewrite-aware) lookup first; on miss falls back to a plain
/// session lookup in either direction.
pub(in crate::afxdp::icmp_embed) fn match_outer_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ctx: &mut NatMatchCtx<'_>,
    now_ns: u64,
) -> EmbeddedMatchOutcome<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let embedded_ip_start = l4 + 8;

    let Some(hdr) = parse_embedded_v4(
        frame,
        embedded_ip_start,
        outer_error_atomic(frame, &meta),
        super::outer_datagram_end(frame, &meta),
    ) else {
        return EmbeddedMatchOutcome::NoMatch;
    };
    let emb_src = IpAddr::V4(hdr.src);
    let emb_dst = IpAddr::V4(hdr.dst);
    // #7160 (#2387): the embedded tuple names the ORIGINAL flow, so its key
    // needs that flow's routing domain or the plain (exact-key) lookups below
    // miss a session in a non-default routing instance. An ICMP error for a
    // forward flow comes back on the flow's EGRESS side, so the arriving
    // interface's domain is the right answer for a flow contained in one
    // routing instance. A flow that is not contained resolves a different
    // domain here and falls through to the forward-NAT lookup, whose index is
    // domain-agnostic by construction (session/key.rs) — degraded to the
    // pre-#7160 path, never mismatched to another tenant.
    let embedded_routing_domain = crate::afxdp::forwarding::ingress_routing_domain(
        ctx.forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        None,
    );
    // #9298: upgrade an `Unparseable` PPTP quote to the live call's handle.
    // No-op for every other quote; a miss stays `Unparseable`.
    let quoted_discriminator = super::resolve_quoted_pptp_discriminator(
        ctx.sessions,
        hdr.discriminator,
        hdr.pptp_call_id,
        emb_dst,
    );
    let embedded_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: hdr.proto,
        src_ip: emb_src,
        dst_ip: emb_dst,
        src_port: hdr.src_port,
        dst_port: hdr.dst_port,
        // #9031: the QUOTED tunnel's discriminator, not None. SessionKey's
        // Hash/Eq include it (#7188), so a hard-coded None made every
        // exact index probe for a GRE quote MISS.
        discriminator: quoted_discriminator,
        routing_domain: embedded_routing_domain,
    };
    let reverse_key = embedded_reply_key(
        libc::AF_INET as u8,
        hdr.proto,
        emb_src,
        emb_dst,
        hdr.src_port,
        hdr.dst_port,
        quoted_discriminator,
        // #9162: the SAME domain the forward `embedded_key` above carries, not
        // a hardcoded 0. This key is probed against both kinds of index and a
        // real domain is right for both — the exact
        // `lookup_session_across_scopes` fallback below could not otherwise
        // reach a session installed in a routing instance (which silently
        // disabled the #6474 outbound-SNAT reply-key arm there), and
        // `lookup_forward_nat_across_scopes` zeroes the probe itself before
        // hitting its bucket, spending the domain on the two-pass tenant
        // preference instead. See `embedded_reply_key`.
        embedded_routing_domain,
    );

    // Forward-NAT-by-reverse path: the embedded packet matches the
    // reply direction of a forward-NAT'd session. Recover the original
    // pre-NAT src + port from the forward key.
    if let Some(fwd) =
        lookup_forward_nat_across_scopes_at(
            ctx.sessions,
            ctx.shared_nat_sessions,
            &reverse_key,
            // #7169: no ingress constraint here, and the reason is not
            // that it is inconvenient. This path installs NO session —
            // it uses the match only to recover the pre-NAT tuple for
            // rewriting an embedded ICMP error — so there is no durable
            // state to endorse a spoof. And an ICMP error may legitimately
            // originate off-path from an intermediate router, so requiring
            // it to arrive from the flow's egress zone would break PMTUD.
            crate::afxdp::shared_ops::ReverseIngress::Unconstrained,
            now_ns,
        )
    {
        let nat = fwd.decision.nat;
        let original_src = fwd.key.src_ip;
        let original_src_port = fwd.key.src_port;
        // #3112: the forward session key carries the ORIGINAL (pre-NAT)
        // tuple, so its dst is the public address the client sent to. For
        // a DNAT/static flow this is the address the ICMP error must
        // appear to quote (and originate from); for an SNAT-only flow it
        // equals the embedded dst, making the builder's dst rewrite a
        // no-op.
        let original_dst = fwd.key.dst_ip;
        let original_dst_port = fwd.key.dst_port;
        let resolution = embedded_icmp_return_resolution(
            ctx,
            &fwd.key,
            fwd.decision,
            original_src,
            now_ns,
        );
        // #9901 (F-077): per-session error budget, keyed on the FORWARD
        // session's own key (the ORIGINAL pre-NAT tuple — the stable
        // identity across every error about this flow). Over budget the
        // error is BudgetDenied (descriptor-drop arm) — NOT a miss: falling
        // through to flowless forwarding would keep delivering it under an
        // ICMP-permitting policy.
        if !ctx.sessions.note_icmp_error_delivered(&fwd.key, now_ns) {
            return EmbeddedMatchOutcome::BudgetDenied;
        }
        return EmbeddedMatchOutcome::Match(EmbeddedIcmpMatch {
            nat,
            original_src,
            original_src_port,
            original_dst,
            original_dst_port,
            embedded_proto: hdr.proto,
            resolution,
            metadata: fwd.metadata,
            outbound_snat: false,
            budget_key: fwd.key.clone(),
        });
    }

    // Session-fallback path: look up the embedded packet as-is or in
    // reverse. An as-is hit on the forward half is a quote of the forward
    // packet and uses embedded_icmp_return_resolution. An as-is hit on the
    // reverse half is a quote of the REPLY packet; #10672 resolves it toward
    // the quoted sender, not via the reverse half's cached client-side route.
    //
    // #6474: the two lookups are mapped SEPARATELY so the direction of the
    // matched error is recoverable. An ICMP error is always addressed to
    // the source of the offending packet (RFC 792):
    //   * as-is hit with `is_reverse == false`: the quote is the session's
    //     FORWARD wire packet (forward-wire key match) — INBOUND error, the
    //     #5690 reversal applies.
    //   * as-is hit with `is_reverse == true`: quote of the REPLY wire
    //     packet — an error about the reply; route toward the quoted server
    //     with embedded_icmp_quoted_reply_resolution (#10672).
    //   * reply-key hit with `is_reverse == false` on a pure source-NAT
    //     flow: the quote is the session's reply in PRE-NAT form (the
    //     internal host emitted the error about the reply it declined) —
    //     OUTBOUND error. Marked `outbound_snat` so the caller re-NATs the
    //     outer source and the quote to the session's external identity
    //     (RFC 5508 §4) instead of leaking the internal source with an
    //     unassociable quote.
    //   * reply-key hit otherwise (a DNAT/composed flow): the pre-#6474
    //     behavior is preserved bit-for-bit.
    let found = probe_session_across_scopes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        &embedded_key,
        now_ns,
    )
    .map(|resolved| (resolved, false))
    .or_else(|| {
        probe_session_across_scopes(
            ctx.sessions,
            ctx.shared_sessions,
            ctx.shared_forward_wire_sessions,
            &reverse_key,
            now_ns,
        )
        .map(|resolved| (resolved, true))
    });
    let Some((resolved, via_reply_key)) = found else {
        return EmbeddedMatchOutcome::NoMatch;
    };
    // #9901 (F-077): per-session error budget. The gating key is the
    // MATCHED key — the canonical key when the resolver carries one
    // (forward-wire / shared hits), else the winning query key
    // (`via_reply_key` selects it). `SessionLookup` is never widened.
    // Denial is BudgetDenied (drop arm), never a miss — see above.
    let query_key = if via_reply_key {
        &reverse_key
    } else {
        &embedded_key
    };
    if !ctx
        .sessions
        .note_icmp_error_delivered(resolved.key.as_ref(query_key), now_ns)
    {
        return EmbeddedMatchOutcome::BudgetDenied;
    }
    // #10667: the F-077 gating key this match was charged against — carried
    // on the match so the poll arms can refund it on every post-match
    // non-delivery terminal (TTL-expire, CoS drop, policy-refuse).
    let budget_key = resolved.key.as_ref(query_key).clone();
    let sl = resolved.lookup;
    // #10672: an as-is hit on the REVERSE half means the quote IS the reply
    // wire packet (server → client) — the error is about the reply, so it is
    // addressed to the reply's source (the server, RFC 792) and must egress
    // toward the quoted sender, not back out the client leg. A reply-key hit
    // on a reverse half instead quotes the forward packet, so it keeps the
    // historical cached-reverse rule below.
    let resolution = if sl.metadata.is_reverse && !via_reply_key {
        embedded_icmp_quoted_reply_resolution(ctx, &reverse_key, emb_src, now_ns)
    } else if sl.metadata.is_reverse {
        sl.decision.resolution
    } else {
        embedded_icmp_return_resolution(ctx, &embedded_key, sl.decision, emb_src, now_ns)
    };
    let outbound_snat = via_reply_key
        && !sl.metadata.is_reverse
        && sl.decision.nat.rewrite_src.is_some()
        && sl.decision.nat.rewrite_dst.is_none();
    EmbeddedMatchOutcome::Match(EmbeddedIcmpMatch {
        nat: sl.decision.nat,
        original_src: emb_src,
        original_src_port: hdr.src_port,
        // Plain (non-forward-NAT) match: no pre-DNAT public dst to
        // recover, so the embedded dst stays as-is (#3112 no-op).
        original_dst: emb_dst,
        original_dst_port: hdr.dst_port,
        embedded_proto: hdr.proto,
        resolution,
        metadata: sl.metadata,
        outbound_snat,
        budget_key,
    })
}
