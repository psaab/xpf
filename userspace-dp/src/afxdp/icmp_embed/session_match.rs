use super::*;
use super::parse::{embedded_reply_key, parse_embedded_v4, parse_embedded_v6};

/// Core embedded ICMP session match logic operating on a frame slice.
/// Returns the session lookup if found. Unlike the NAT variant, this
/// path does not extract NAT reversal info — it only confirms a match
/// exists. Used by callers that need plain session presence.
///
/// `routing_domain` is the domain of the interface the ICMP error arrived on
/// — `crate::afxdp::forwarding::ingress_routing_domain(forwarding,
/// meta.ingress_ifindex as i32, meta.ingress_vlan_id, None)`, exactly as
/// `nat_match_v4` / `nat_match_v6` / `nat64_match` derive it. It is a
/// PARAMETER rather than a derivation because this function is handed no
/// `ForwardingState`: it has no non-test caller today
/// (`afxdp/mod.rs` imports it under `#[cfg(test)]`), so plumbing a whole
/// forwarding borrow through a path nothing runs would be churn.
///
/// #9162: it is also not allowed to be a hardcoded 0 any more. Both keys below
/// go into EXACT lookups, and every index behind `SessionTable::lookup` is
/// domain-preserving — so the old literals meant this path could never match a
/// session in a routing instance, and whoever wired it into production would
/// have inherited that silently. Making the domain an argument means the
/// wiring has to answer the question at its call site, the way the three
/// production arms do.
pub(in crate::afxdp::icmp_embed) fn try_embedded_icmp_session_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
    routing_domain: u32,
) -> Option<SessionLookup> {
    let l4 = meta.l4_offset as usize;

    let icmp_type = *frame.get(l4)?;
    if !is_icmp_error(meta.protocol, icmp_type) {
        return None;
    }

    let embedded_ip_start = l4 + 8;

    match meta.protocol {
        PROTO_ICMP => {
            let hdr = parse_embedded_v4(frame, embedded_ip_start)?;
            let emb_src = IpAddr::V4(hdr.src);
            let emb_dst = IpAddr::V4(hdr.dst);
            // #9298: kept in step with the two PRODUCTION arms
            // (`nat_match_v4` / `nat_match_v6`). This function has no non-test
            // caller, so the resolve here changes nothing today -- it is here so
            // whoever wires it does not inherit a path that silently misses
            // every PPTP quote.
            let quoted_discriminator = super::resolve_quoted_pptp_discriminator(
                sessions,
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
                // #9031: the QUOTED tunnel's discriminator, not None.
                // SessionKey's Hash/Eq include it (#7188), so a hard-coded
                // None made every exact index probe for a GRE quote MISS.
                // #9298: with the PPTP upgrade applied, above.
                discriminator: quoted_discriminator,
                // #9162: the arriving interface's domain, not 0. See
                // the doc comment above.
                routing_domain,
            };
            let reverse_key = embedded_reply_key(
                libc::AF_INET as u8,
                hdr.proto,
                emb_src,
                emb_dst,
                hdr.src_port,
                hdr.dst_port,
                quoted_discriminator,
                routing_domain,
            );
            lookup_embedded_session(sessions, &embedded_key, &reverse_key, now_ns)
        }
        PROTO_ICMPV6 => {
            let hdr = parse_embedded_v6(frame, embedded_ip_start)?;
            let emb_src = IpAddr::V6(hdr.src_wire);
            // #9298: see the v4 arm.
            let quoted_discriminator = super::resolve_quoted_pptp_discriminator(
                sessions,
                hdr.discriminator,
                hdr.pptp_call_id,
                hdr.dst,
            );
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: hdr.proto,
                src_ip: emb_src,
                dst_ip: hdr.dst,
                src_port: hdr.src_port,
                dst_port: hdr.dst_port,
                // #9031: the QUOTED tunnel's discriminator, not None.
                // SessionKey's Hash/Eq include it (#7188), so a hard-coded
                // None made every exact index probe for a GRE quote MISS.
                // #9298: with the PPTP upgrade applied, above.
                discriminator: quoted_discriminator,
                // #9162: the arriving interface's domain, not 0. See
                // the doc comment above.
                routing_domain,
            };
            let reverse_key = embedded_reply_key(
                libc::AF_INET6 as u8,
                hdr.proto,
                emb_src,
                hdr.dst,
                hdr.src_port,
                hdr.dst_port,
                quoted_discriminator,
                routing_domain,
            );
            lookup_embedded_session(sessions, &embedded_key, &reverse_key, now_ns)
        }
        _ => None,
    }
}

fn lookup_embedded_session(
    sessions: &mut SessionTable,
    embedded_key: &SessionKey,
    reverse_key: &SessionKey,
    now_ns: u64,
) -> Option<SessionLookup> {
    sessions
        .lookup(embedded_key, now_ns, 0)
        .or_else(|| sessions.lookup(reverse_key, now_ns, 0))
        .or_else(|| {
            sessions
                .find_forward_nat_match(reverse_key)
                .map(|m| SessionLookup {
                    decision: m.decision,
                    metadata: m.metadata,
                })
        })
}
