// #6472: NAT64 (cross-family) ICMP error translation on the FLOWLESS poll
// arm — the path every non-query ICMP error takes (#3290). RFC 7915
// §4.2/§5.2 PMTUD/traceroute across the NAT64 boundary.
//
// Reachability bug this fixes: the RFC 7915 translators in `nat64.rs` were
// previously callable only via `build_nat64_forwarded_frame`, which runs on
// the FLOW-BACKED path — an ICMP error never has a flow, so PTB /
// Time-Exceeded / Dest-Unreachable toward a NAT64 session never reached
// them. The same-family #5690 reversal matched the NAT64 session but its
// single-family builders declined the cross-family `original_src`
// (`builders.rs` returns `None`), and the flowless L3 enforcement that
// followed dropped the error: a v4 error to the pool address resolved
// MissingNeighbor (the pool address is not a local v4 socket), a v6 error
// to the synthetic Pref64 destination resolved NoRoute. PMTUD and
// traceroute were dead across the boundary despite the #2219 doc claim.
//
// This arm runs BEFORE the same-family #5690 reversal and is NOT gated on
// `allow_embedded_icmp`: translating errors for the translator's OWN
// admitted sessions is core NAT64 translator behavior (RFC 7915 §4.2/§5.2),
// not the optional third-party embedded-ICMP passthrough that flag
// controls. Ordering is safe: a NAT64 session match is translated here and
// consumed; anything else falls through to the same-family reversal and
// then normal flowless enforcement, both unchanged.

use super::embedded_icmp::{
    actual_embedded_icmp_ingress_zone, EmbeddedIcmpReversal, queue_prebuilt_embedded_icmp_error,
};
use super::*;

/// Attempt the NAT64 ICMP-error translation for a non-query ICMP error on
/// the flowless poll path. Returns [`EmbeddedIcmpReversal`] telling the
/// caller how the descriptor was consumed (the same tri-state the
/// same-family arm uses). Only invoked when the packet is classified as an
/// ICMP error AND at least one NAT64 prefix is configured (both checked by
/// the caller); the match itself re-verifies the error class.
#[allow(clippy::too_many_arguments)]
pub(super) fn try_translate_nat64_icmp_error(
    desc: XdpDesc,
    // #8271: see the note on `try_reverse_embedded_icmp_error`. This is the
    // frame this function PARSES — the owned inner frame after native-GRE
    // decap, matching the inner `meta`. `desc` remains the OUTER descriptor and
    // is used only for queueing.
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    binding_index: usize,
    sessions: &mut SessionTable,
    worker_ctx: &WorkerContext,
    scratch_forwards: &mut Vec<PendingForwardRequest>,
    now_ns: u64,
    now_secs: u64,
    ingress_zone_override: Option<u16>,
) -> EmbeddedIcmpReversal {
    let nat64_match = match try_nat64_icmp_error_match_from_frame(
        packet_frame,
        meta,
        sessions,
        worker_ctx.forwarding,
        worker_ctx.dynamic_neighbors,
        worker_ctx.shared_sessions,
        worker_ctx.shared_nat_sessions,
        worker_ctx.shared_forward_wire_sessions,
        now_ns,
    ) {
        EmbeddedMatchOutcome::Match(m) => m,
        // #9901 (F-077): twin of the same-family arm — a matched-but-
        // over-budget NAT64 error drops; it must neither translate NOR
        // fall through to flowless forwarding.
        EmbeddedMatchOutcome::BudgetDenied => return EmbeddedIcmpReversal::Dropped,
        EmbeddedMatchOutcome::NoMatch => return EmbeddedIcmpReversal::NotHandled,
    };
    match nat64_match {
        Nat64IcmpErrorMatch::V4ToV6 {
            orig_src_v6,
            orig_dst_v6,
            orig_client_port,
            resolution,
            metadata: _,
            budget_key,
        } => {
            // SPARK-m6: verify L3 — a wrong stamp misreads the hop address.
            let l3 = crate::afxdp::frame::verified_l3_or_stamp(
                packet_frame,
                meta.l3_offset,
                meta.addr_family,
            );
            // RFC 7915 §4.1/§6: the translated error's outer source is the
            // stateless Pref64 mapping of the error's v4 source (the hop
            // that generated it). The NAT64 prefix is the high 96 bits of
            // the session's synthetic destination (`orig_dst_v6`) — NAT64
            // prefixes here are /96-only (config gate in `from_snapshots`),
            // so the split is exact.
            let Some(router_v4) = packet_frame.get(l3 + 12..l3 + 16) else {
                return EmbeddedIcmpReversal::NotHandled;
            };
            let mut src_v6_octets = [0u8; 16];
            src_v6_octets[..12].copy_from_slice(&orig_dst_v6.octets()[..12]);
            src_v6_octets[12..].copy_from_slice(router_v4);
            let src_v6 = Ipv6Addr::from(src_v6_octets);

            let icmp_resolution = finalize_embedded_icmp_resolution_parts(
                worker_ctx.forwarding,
                worker_ctx.ha_state,
                now_secs,
                meta.ingress_ifindex as i32,
                resolution,
                actual_embedded_icmp_ingress_zone(
                    worker_ctx.forwarding,
                    meta,
                    ingress_zone_override,
                ),
            );
            // The frame build needs the FINAL resolution's L2 addresses. A
            // FabricRedirect source MAC carries the actual ingress zone for
            // the peer; using the pre-finalization client MAC loses that stamp.
            let (Some(dst_mac), Some(src_mac)) =
                (icmp_resolution.neighbor_mac, icmp_resolution.src_mac)
            else {
                return EmbeddedIcmpReversal::NotHandled;
            };
            let Some(rewritten_frame) = crate::nat64::build_nat64_v4_to_v6_icmp_error_frame(
                packet_frame,
                src_v6,
                orig_src_v6,
                Some(orig_client_port),
                dst_mac,
                src_mac,
                icmp_resolution.tx_vlan_id,
            ) else {
                return EmbeddedIcmpReversal::NotHandled;
            };
            queue_prebuilt_embedded_icmp_error(
                desc,
                meta,
                binding_index,
                worker_ctx,
                scratch_forwards,
                now_ns,
                sessions,
                &budget_key,
                icmp_resolution,
                rewritten_frame,
                #[cfg(feature = "debug-log")]
                false,
            )
        }
        Nat64IcmpErrorMatch::V6ToV4 {
            pool_v4,
            server_v4,
            translated_port,
            resolution,
            metadata: _,
            budget_key,
        } => {
            let icmp_resolution = finalize_embedded_icmp_resolution_parts(
                worker_ctx.forwarding,
                worker_ctx.ha_state,
                now_secs,
                meta.ingress_ifindex as i32,
                resolution,
                actual_embedded_icmp_ingress_zone(
                    worker_ctx.forwarding,
                    meta,
                    ingress_zone_override,
                ),
            );
            let (Some(dst_mac), Some(src_mac)) =
                (icmp_resolution.neighbor_mac, icmp_resolution.src_mac)
            else {
                return EmbeddedIcmpReversal::NotHandled;
            };
            let Some(rewritten_frame) = crate::nat64::build_nat64_v6_to_v4_icmp_error_frame(
                packet_frame,
                pool_v4,
                server_v4,
                Some(translated_port),
                dst_mac,
                src_mac,
                icmp_resolution.tx_vlan_id,
                worker_ctx.forwarding.nat64.no_v6_frag_header,
            ) else {
                return EmbeddedIcmpReversal::NotHandled;
            };
            queue_prebuilt_embedded_icmp_error(
                desc,
                meta,
                binding_index,
                worker_ctx,
                scratch_forwards,
                now_ns,
                sessions,
                &budget_key,
                icmp_resolution,
                rewritten_frame,
                #[cfg(feature = "debug-log")]
                false,
            )
        }
    }
}
