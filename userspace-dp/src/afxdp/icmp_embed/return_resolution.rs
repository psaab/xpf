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
