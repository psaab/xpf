use super::*;

/// Resolve the forwarding back to the original (pre-NAT) client for
/// an embedded ICMP error. Tries the reverse-key session lookup first
/// (matches the live session's egress resolution if still cached),
/// then falls back to a route + dynamic-neighbor lookup against the
/// original source.
///
/// Mirrors `icmp_embed.rs:460-483` semantics; the 10-param free
/// function collapses to 5 params behind `NatMatchCtx`.
#[inline]
pub(in crate::afxdp::icmp_embed) fn embedded_icmp_return_resolution(
    ctx: &mut NatMatchCtx<'_>,
    forward_key: &SessionKey,
    forward_decision: SessionDecision,
    original_src: IpAddr,
    now_ns: u64,
) -> ForwardingResolution {
    let reverse_key = reverse_session_key(forward_key, forward_decision.nat);
    if let Some(reverse) = probe_session_across_scopes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        &reverse_key,
        now_ns,
    ) {
        return reverse.lookup.decision.resolution;
    }
    lookup_forwarding_resolution_with_dynamic(ctx.forwarding, ctx.dynamic_neighbors, original_src)
}

/// #10672: resolve the forwarding for an ICMP error quoting a REPLY packet —
/// toward the QUOTED sender (the session's forward-destination side), not the
/// quoting/error-arrival side.
///
/// The session-fallback's historical rule (`is_reverse` → cached reverse
/// resolution, else return-to-client) assumes every error is about the forward
/// packet. For an error quoting the reply (server → client) that sends a
/// server-side PTB back out the client leg: the builder rewrites the outer
/// destination to the quoted source (the server) while the frame egresses
/// toward the client — a server-side PMTUD black hole for every un-NAT'd
/// inbound flow (essentially all IPv6 servers).
///
/// Prefer the installed forward companion's cached resolution (it already
/// points at the quoted sender); fall back to a fresh route + neighbor lookup
/// toward the quoted source when no forward half is installed. The probe is
/// read-only (`probe_session_across_scopes`), so it neither refreshes nor
/// completes session state (#9990).
#[inline]
pub(in crate::afxdp::icmp_embed) fn embedded_icmp_quoted_reply_resolution(
    ctx: &mut NatMatchCtx<'_>,
    forward_key: &SessionKey,
    quoted_src: IpAddr,
    now_ns: u64,
) -> ForwardingResolution {
    if let Some(fwd) = probe_session_across_scopes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        forward_key,
        now_ns,
    ) {
        if !fwd.lookup.metadata.is_reverse {
            return fwd.lookup.decision.resolution;
        }
    }
    lookup_forwarding_resolution_with_dynamic(ctx.forwarding, ctx.dynamic_neighbors, quoted_src)
}
