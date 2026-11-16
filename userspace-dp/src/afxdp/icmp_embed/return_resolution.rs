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
/// and looks the matched reverse up FRESH, the way the reply path does
/// (#19164, `fresh_reverse_resolution`; before #19164 it returned the
/// stored resolution verbatim),
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
        return fresh_reverse_resolution(ctx, &reverse_key, &reverse);
    }
    domain_scoped_fallback_resolution(ctx, forward_key, Some(forward_decision), original_src)
}

/// #19164: the matched reverse's resolution, looked up FRESH the way a reply
/// on that reverse looks it up (`resolve.rs`'s hit arm), instead of the stored
/// value verbatim.
///
/// Before #19164 the return path returned the reverse's STORED resolution,
/// while the reply path looks it up again on every packet. The two disagreed
/// whenever the stored value was stale:
/// - after this node took over the client-side RG, an import-time
///   FabricRedirect sent the error over the fabric to the demoted peer;
/// - after a FIB change, the error left by the old route.
///
/// **It uses the SAME lookup variant the reply uses:**
/// - cache-free when the stored resolution's forwarding generation is stale;
/// - the synced-session variant for a peer-synced reverse;
/// - the cached variant otherwise.
///
/// **The stored value is served only where the reply would serve it.** The
/// cached and synced variants serve it through `cached_session_resolution`
/// (#11315: a ForwardCandidate with a live egress and the stored MAC still
/// live), as their fast path or when the FIB cannot forward. Nothing else
/// falls back to it (#19164 review, seat r23 P2-1). The return gets the
/// reply's answer, not the stored value:
/// - with a stale stamp;
/// - on a #11315 mismatch;
/// - on a #1873 re-owned tunnel (the gated NoRoute);
/// - when the installing table is gone (TableUnavailable).
///
/// **What this does NOT do: HA enforcement or fabric composition.** The poll
/// arm finalizes every matched resolution itself
/// (`finalize_embedded_icmp_resolution_parts`): the HA snapshot, the fabric
/// redirect of an HAInactive/NoRoute/DiscardRoute on a non-fabric ingress, and
/// then the #16053 owner-RG promotion that reads the finalized result. Running
/// the reply's whole pipeline here would apply HA twice and pre-empt that
/// accounting. So this supplies the un-enforced, fresh lookup the finalization
/// expects.
///
/// **Unless the connected ledger contradicts it** (#19164 review fold 2; see
/// `contradicts_connected_owner`). There the STORED resolution is kept, which
/// is master's value, and the finalization judges it with HA as it always
/// has.
///
/// **Residuals:**
/// - The #9951 leak-incarnation revocation arm is not mirrored. A revoked leak
///   gets the ordinary lookup here.
/// - A more-specific route that overrides a connected client's prefix, added
///   after the session's install, is not followed. The guard keeps the stored
///   value, while a reply follows the new route.
fn fresh_reverse_resolution(
    ctx: &NatMatchCtx<'_>,
    reverse_key: &SessionKey,
    reverse: &crate::afxdp::shared_ops::ResolvedSessionLookup,
) -> ForwardingResolution {
    let stored = reverse.lookup.decision;
    let flow = SessionFlow {
        src_ip: reverse_key.src_ip,
        dst_ip: reverse_key.dst_ip,
        forward_key: reverse_key.clone(),
    };
    let fresh = fresh_reverse_lookup(ctx, &flow, reverse, stored);
    let target = crate::afxdp::session_glue::resolution_target_for_session(&flow, stored);
    if contradicts_connected_owner(ctx.forwarding, stored, target, fresh) {
        return stored.resolution;
    }
    fresh
}

/// #19164 (review fold 2): whether a fresh answer for the client `target` is
/// contradicted by the connected ledger, so it must not be adopted.
///
/// **True when all of these hold:**
/// - the answer is a local candidate (ForwardCandidate or MissingNeighbor on a
///   non-fabric egress);
/// - the client has a KNOWN connected owner
///   (`connected_owner_rg_for_target_in_table`, the HA-independent ledger,
///   which still names a peer-owned prefix the FIB withholds);
/// - the answer's egress is not the client's connected interface
///   (`connected_ifindex_for_target_in_table`).
///
/// **That is a gateway-route mis-resolution of a connected destination**, the
/// reply's own #15958b term. On a split node the peer-owned LAN prefix is
/// withheld from the transit FIB (#15742), so the FIB answers the client with
/// the WAN default route, an active local ForwardCandidate. Adopting it sent
/// the error out the WAN to the client's private address (seat r23 P1-1) and,
/// for a local reverse whose RG had moved to the peer, admitted a #16053 PTB
/// that master denies.
///
/// **It is the HA-free core of the reply's retain verdict**
/// (`rehome_or_retain_fabric_redirect`: #15958b's connected-interface
/// equality, #16524's re-home for an unknown owner). It applies to every stored
/// shape and every arrival. The reply applies its verdict only to a stored
/// FabricRedirect and skips it on fabric-link ingress, and a reply inherits the
/// WAN answer in exactly those two gaps (#19171). HA is applied once, by the
/// finalization, to whatever this returns.
fn contradicts_connected_owner(
    forwarding: &ForwardingState,
    stored: SessionDecision,
    target: IpAddr,
    fresh: ForwardingResolution,
) -> bool {
    let local_candidate = matches!(
        fresh.disposition,
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
    ) && fresh.egress_ifindex > 0
        && !ingress_is_fabric(forwarding, fresh.egress_ifindex);
    if !local_candidate {
        return false;
    }
    let table =
        crate::afxdp::session_glue::install_table_name_for_session(forwarding, stored, target);
    if crate::afxdp::session_glue::connected_owner_rg_for_target_in_table(forwarding, target, table)
        <= 0
    {
        return false;
    }
    fresh.egress_ifindex
        != crate::afxdp::session_glue::connected_ifindex_for_target_in_table(
            forwarding, target, table,
        )
}

/// The reply path's lookup variant for `reverse` (see `fresh_reverse_resolution`).
fn fresh_reverse_lookup(
    ctx: &NatMatchCtx<'_>,
    flow: &SessionFlow,
    reverse: &crate::afxdp::shared_ops::ResolvedSessionLookup,
    stored: SessionDecision,
) -> ForwardingResolution {
    if ctx
        .sessions
        .forwarding_resolution_is_stale(reverse.lookup.forwarding_generation)
    {
        crate::afxdp::session_glue::lookup_forwarding_resolution_for_session_without_cache(
            ctx.forwarding,
            ctx.dynamic_neighbors,
            flow,
            stored,
        )
    } else if reverse.origin.is_peer_synced() {
        crate::afxdp::session_glue::lookup_forwarding_resolution_for_synced_session(
            ctx.forwarding,
            ctx.dynamic_neighbors,
            flow,
            stored,
        )
    } else {
        crate::afxdp::session_glue::lookup_forwarding_resolution_for_session(
            ctx.forwarding,
            ctx.dynamic_neighbors,
            flow,
            stored,
        )
    }
    .resolution
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
