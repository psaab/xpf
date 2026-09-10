use super::*;
use super::parse::{embedded_reply_key, parse_embedded_v6};
use super::return_resolution::embedded_icmp_return_resolution;

/// IPv6-outer branch of `try_embedded_icmp_nat_match_from_frame`.
/// Mirrors `icmp_embed.rs:333-455` literally. The NPTv6 inbound
/// translation is applied AT THIS CALL SITE on a local copy of
/// `hdr.src_wire`. The wire source is preserved for the forward-NAT
/// reverse key; the translated source is used for embedded_key and
/// for the shared_reverse_key inside the fallback branch.
pub(in crate::afxdp::icmp_embed) fn match_outer_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ctx: &mut NatMatchCtx<'_>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let embedded_ip_start = l4 + 8;

    let hdr = parse_embedded_v6(frame, embedded_ip_start)?;

    // NPTv6 inbound translation: applied at the call site, not in the
    // parser. Preserves the wire-vs-translated asymmetry that the
    // forward-NAT reverse_key (uses wire) and the shared_reverse_key
    // (uses translated) depend on. Mirrors icmp_embed.rs:358-360.
    //
    // #5176: the reverse translation is zone-scoped like every NPTv6 lookup.
    // This ICMP error reverses an OUTBOUND source translation, whose rule was
    // scoped by the original flow's egress zone; the error returns ingressing
    // on that same external interface, so gate on THIS packet's ingress zone
    // (the inbound-direction zone per the #5176 invariant). A wildcard rule
    // (empty `from_zone`) still matches regardless.
    //
    // #6227 item 6: resolve the LOGICAL (parent, vlan) -> unit ifindex before
    // the zone lookup, per the same-SSOT rule in `afxdp/README.md` ("every
    // per-ingress map keyed by the logical unit ifindex must resolve through
    // `resolve_ingress_logical_ifindex` — not pass the raw
    // `meta.ingress_ifindex`"). `ifindex_to_zone_id` is keyed by the logical
    // unit (`forwarding_build/interfaces.rs`); the physical parent ifindex
    // only ever inherits its FIRST sub-interface's zone, so on a VLAN trunk
    // carrying multiple units in distinct zones this reverse lookup evaluated
    // the wrong zone for every unit but the first. `unwrap_or` falls back to
    // the physical ifindex, a no-op on a non-VLAN port (logical == physical).
    // Mirrors the #3021/#3022/#3026 sibling sites (forwarding zone-pair,
    // screen/SYN-cookie, generated ICMP) and `reject_reply.rs`'s identical
    // fallback shape.
    //
    // Scope note: this affects ONLY the ICMP-embedded-error REVERSE lookup in
    // this file. It does NOT affect policy/screen zone resolution on the
    // forward transit path (those sites already resolve the logical ifindex
    // via the same `resolve_ingress_logical_ifindex` SSOT, per #3021/#3022/
    // #3026) and does not gate any policy/permit decision — the consequence
    // of the pre-fix bug was that an ICMP error (e.g. Packet-Too-Big) arriving
    // on a VLAN trunk unit other than the trunk's first-configured unit was
    // attributed to that FIRST unit's zone instead of its own, so a
    // zone-scoped NPTv6 rule for its real zone never matched, the embedded
    // source stayed untranslated, and (absent an unrelated forward-NAT session
    // alias) the reverse lookup failed outright — PMTUD black-holing for that
    // flow rather than a security/policy-bypass effect.
    let logical_ingress_ifindex = resolve_ingress_logical_ifindex(
        ctx.forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let ingress_zone = ctx
        .forwarding
        .ifindex_to_zone_id
        .get(&logical_ingress_ifindex)
        .and_then(|id| ctx.forwarding.zone_id_to_name.get(id))
        .map(|s| s.as_str())
        .unwrap_or("");
    let mut emb_src_lookup_v6 = hdr.src_wire;
    let _nptv6_reverse = ctx
        .forwarding
        .nptv6
        .translate_inbound(&mut emb_src_lookup_v6, ingress_zone);
    let emb_src_lookup = IpAddr::V6(emb_src_lookup_v6);

    // #7160 (#2387): the embedded tuple names the ORIGINAL flow, so its key
    // needs that flow's routing domain or the plain (exact-key) lookups below
    // miss a session in a non-default routing instance. See the twin comment
    // in `nat_match_v4.rs` for why the arriving interface is the right source.
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
        hdr.dst,
    );
    let embedded_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: hdr.proto,
        src_ip: emb_src_lookup,
        dst_ip: hdr.dst,
        src_port: hdr.src_port,
        dst_port: hdr.dst_port,
        // #9031: the QUOTED tunnel's discriminator, not None. SessionKey's
        // Hash/Eq include it (#7188), so a hard-coded None made every
        // exact index probe for a GRE quote MISS.
        discriminator: quoted_discriminator,
        routing_domain: embedded_routing_domain,
    };
    // reverse_key for the forward-NAT lookup uses the WIRE source.
    // Mirrors icmp_embed.rs:369-376.
    let reverse_key = embedded_reply_key(
        libc::AF_INET6 as u8,
        hdr.proto,
        IpAddr::V6(hdr.src_wire),
        hdr.dst,
        hdr.src_port,
        hdr.dst_port,
        quoted_discriminator,
        // #9162: the same domain the forward `embedded_key` carries. See the
        // twin call in `nat_match_v4.rs` and `embedded_reply_key` for why a
        // real domain is correct in BOTH the exact and the reverse-match
        // index.
        embedded_routing_domain,
    );

    if let Some(fwd) =
        lookup_forward_nat_across_scopes(
            ctx.sessions,
            ctx.shared_nat_sessions,
            &reverse_key,
            // #7169: no ingress constraint here, and the reason is not
            // that it is inconvenient. This path installs NO session — it
            // uses the match only to recover the pre-NAT tuple for
            // rewriting an embedded ICMP error — so there is no durable
            // state to endorse a spoof. And an ICMP error may legitimately
            // originate off-path from an intermediate router, so requiring
            // it to arrive from the flow's egress zone would break PMTUD.
            crate::afxdp::shared_ops::ReverseIngress::Unconstrained,
        )
    {
        let nat = fwd.decision.nat;
        let original_src = fwd.key.src_ip;
        let original_src_port = fwd.key.src_port;
        // #3112: forward session key holds the ORIGINAL (pre-NAT) tuple;
        // its dst is the public address the client used. DNAT66/static
        // sets rewrite_dst so the builder un-NATs the embedded dst; for
        // an SNAT-only flow this equals the embedded dst (no-op).
        let original_dst = fwd.key.dst_ip;
        let original_dst_port = fwd.key.dst_port;
        let resolution = embedded_icmp_return_resolution(
            ctx,
            &fwd.key,
            fwd.decision,
            original_src,
            now_ns,
        );
        return Some(EmbeddedIcmpMatch {
            nat,
            original_src,
            original_src_port,
            original_dst,
            original_dst_port,
            embedded_proto: hdr.proto,
            resolution,
            metadata: fwd.metadata,
            outbound_snat: false,
        });
    }

    // Session-fallback path. Inside .or_else we build a SECOND reverse
    // key — this time using the TRANSLATED emb_src_lookup, mirroring
    // icmp_embed.rs:412-419 (shared_reverse_key).
    //
    // #6474: the two lookups are mapped SEPARATELY (the v4 twin of
    // `nat_match_v4`): a reply-key hit with `is_reverse == false` on a pure
    // source-NAT (SNAT66/NPTv6) flow is an OUTBOUND error from the internal
    // host about the session's reply — marked `outbound_snat` so the
    // caller re-NATs the outer source and the quote to the session's
    // external identity (RFC 5508 §4) instead of leaking the internal
    // source with an unassociable quote. Every other combination keeps the
    // pre-#6474 behavior bit-for-bit.
    lookup_session_across_scopes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        &embedded_key,
        now_ns,
        0,
    )
    .map(|resolved| (resolved, false))
    .or_else(|| {
        let shared_reverse_key = embedded_reply_key(
            libc::AF_INET6 as u8,
            hdr.proto,
            emb_src_lookup,
            hdr.dst,
            hdr.src_port,
            hdr.dst_port,
            quoted_discriminator,
            // #9162: this one feeds an EXACT `lookup_session_across_scopes`
            // only, which is domain-preserving on all four of its probes — so
            // a hardcoded 0 could not reach a session installed in a routing
            // instance, and the #6474 outbound-SNAT (SNAT66/NPTv6) reply-key
            // arm was dead for every VRF flow.
            embedded_routing_domain,
        );
        lookup_session_across_scopes(
            ctx.sessions,
            ctx.shared_sessions,
            ctx.shared_forward_wire_sessions,
            &shared_reverse_key,
            now_ns,
            0,
        )
        .map(|resolved| (resolved, true))
    })
    .map(|(resolved, via_reply_key)| {
        let sl = resolved.lookup;
        let resolution = if sl.metadata.is_reverse {
            sl.decision.resolution
        } else {
            embedded_icmp_return_resolution(
                ctx,
                &embedded_key,
                sl.decision,
                emb_src_lookup,
                now_ns,
            )
        };
        let outbound_snat = via_reply_key
            && !sl.metadata.is_reverse
            && sl.decision.nat.rewrite_src.is_some()
            && sl.decision.nat.rewrite_dst.is_none();
        EmbeddedIcmpMatch {
            nat: sl.decision.nat,
            original_src: emb_src_lookup,
            original_src_port: hdr.src_port,
            // Plain (non-forward-NAT) match: nothing to un-DNAT, so the
            // embedded dst is preserved unchanged (#3112 no-op).
            original_dst: hdr.dst,
            original_dst_port: hdr.dst_port,
            embedded_proto: hdr.proto,
            resolution,
            metadata: sl.metadata,
            outbound_snat,
        }
    })
}
