use super::*;

/// #15771: the fresh (companion-absent) fallback lookup for an embedded ICMP
/// error must resolve in the flow's OWN routing domain / installing table,
/// never the default `inet.0`/`inet6.0`.
///
/// The installing table (`install_table_domain`/`install_table_check` on the
/// forward decision, #9752) is the validated PBR/native installing identity;
/// `forward_key.routing_domain` is the native routing-instance identity
/// (#7160/#10312). Both name the same per-instance table registry
/// (`forwarding.install_tables`), keyed by the FNV-derived domain id.
///
/// * A stamped installing table wins (same classifier as session re-resolve:
///   `resolve_install_table_for_session`); an unresolvable stamp fails closed
///   (`TableUnavailable`) rather than probing MAIN.
/// * Otherwise a nonzero native routing domain resolves through its registry
///   row. A nonzero domain with no row / no family entry fails closed rather
///   than leaking into the default table.
/// * Domain 0 + unstamped keeps the historical default-table behaviour
///   bit-for-bit: single-instance deployments are unaffected.
fn domain_scoped_fallback_resolution(
    ctx: &NatMatchCtx<'_>,
    forward_key: &SessionKey,
    forward_decision: Option<SessionDecision>,
    target: IpAddr,
) -> ForwardingResolution {
    // Stamped installing table (#9752): reuse the ONE classifier.
    if let Some(decision) = forward_decision {
        match crate::afxdp::session_glue::resolve_install_table_for_session(
            ctx.forwarding,
            decision,
            target,
        ) {
            crate::afxdp::session_glue::InstallTable::Table(table) => {
                return lookup_forwarding_resolution_in_table_with_dynamic(
                    ctx.forwarding,
                    ctx.dynamic_neighbors,
                    target,
                    Some(table),
                )
                .resolution;
            }
            crate::afxdp::session_glue::InstallTable::Unresolvable => {
                return crate::afxdp::forwarding::table_unavailable_resolution();
            }
            crate::afxdp::session_glue::InstallTable::Default => {}
        }
    }
    // Native routing-instance domain (#7160): registry row for the domain.
    let domain = forward_key.routing_domain;
    if domain != 0 {
        let table = ctx
            .forwarding
            .install_tables
            .get(&domain)
            .and_then(|row| match target {
                IpAddr::V4(_) => row.v4.as_deref(),
                IpAddr::V6(_) => row.v6.as_deref(),
            });
        return match table {
            Some(table) => {
                lookup_forwarding_resolution_in_table_with_dynamic(
                    ctx.forwarding,
                    ctx.dynamic_neighbors,
                    target,
                    Some(table),
                )
                .resolution
            }
            None => crate::afxdp::forwarding::table_unavailable_resolution(),
        };
    }
    lookup_forwarding_resolution_with_dynamic(ctx.forwarding, ctx.dynamic_neighbors, target)
        .resolution
}

/// Resolve the forwarding back to the original (pre-NAT) client for
/// an embedded ICMP error. Tries the reverse-key session lookup first
/// (matches the live session's egress resolution if still cached),
/// then falls back to a domain-scoped route + dynamic-neighbor lookup
/// against the original source (#15771: never the default table for a
/// VRF flow).
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
    if let Some(reverse) = probe_session_across_scopes_with_wire_indexes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        ctx.shared_owner_rg_indexes,
        &reverse_key,
        now_ns,
    ) {
        return reverse.lookup.decision.resolution;
    }
    domain_scoped_fallback_resolution(ctx, forward_key, Some(forward_decision), original_src)
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
/// completes session state (#9990). #15771: that fallback is domain-scoped
/// like the return path (never the default table for a VRF flow).
#[inline]
pub(in crate::afxdp::icmp_embed) fn embedded_icmp_quoted_reply_resolution(
    ctx: &mut NatMatchCtx<'_>,
    forward_key: &SessionKey,
    quoted_src: IpAddr,
    now_ns: u64,
) -> ForwardingResolution {
    if let Some(fwd) = probe_session_across_scopes_with_wire_indexes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        ctx.shared_owner_rg_indexes,
        forward_key,
        now_ns,
    ) {
        if !fwd.lookup.metadata.is_reverse {
            return fwd.lookup.decision.resolution;
        }
    }
    domain_scoped_fallback_resolution(ctx, forward_key, None, quoted_src)
}
