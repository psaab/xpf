//! IPv4 arm of `build_forwarded_frame_into_from_frame`.
//!
//! Body is byte-identical to the AF_INET match arm at
//! `frame/mod.rs:285..341` before this split. The orchestrator at
//! `frame/build/mod.rs` computes the L2 prelude (eth header, payload
//! memcpy, ip_start, selected_tcp_mss, apply_nat) and dispatches here.

use super::super::tcp::clamp_tcp_mss_frame;
use super::super::{
    adjust_ipv4_header_checksum, apply_nat_ipv4, enforce_expected_ports_at,
    ipv4_is_non_first_fragment, recompute_l4_checksum_ipv4, restore_l4_tuple_from_meta,
};
use crate::afxdp::{ForwardPacketMeta, SessionDecision};
use std::net::Ipv4Addr;

#[inline(always)]
pub(in crate::afxdp::frame) fn build_forwarded_frame_into_ipv4(
    out: &mut [u8],
    ip_start: usize,
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    apply_nat: bool,
    expected_ports: Option<(u16, u16)>,
    selected_tcp_mss: u16,
    force_tunnel_l4_recompute: bool,
) -> Option<()> {
    let enforced_ports = expected_ports;
    if out.len() < ip_start + 20 {
        return None;
    }
    let ihl = ((out[ip_start] & 0x0f) as usize) * 4;
    if ihl < 20 || out.len() < ip_start + ihl {
        return None;
    }
    if (meta.meta_flags & 0x80) == 0 && out[ip_start + 8] <= 1 {
        return None;
    }
    let old_src = Ipv4Addr::new(
        out[ip_start + 12],
        out[ip_start + 13],
        out[ip_start + 14],
        out[ip_start + 15],
    );
    let old_dst = Ipv4Addr::new(
        out[ip_start + 16],
        out[ip_start + 17],
        out[ip_start + 18],
        out[ip_start + 19],
    );
    let old_ttl = out[ip_start + 8];
    // IHL already computed above — use directly instead of re-parsing.
    let rel_l4 = ihl;
    // #1852: non-first-fragment predicate, computed once and threaded.
    let non_first_fragment = ipv4_is_non_first_fragment(&out[ip_start..]);
    let repaired_ports =
        restore_l4_tuple_from_meta(&mut out[ip_start..], meta, rel_l4, non_first_fragment)
            .unwrap_or(false);
    // #9782: enforce BEFORE NAT (repair-then-translate; expected_ports is
    // the arrival tuple — enforcing after apply_nat clobbered PAT/DNAT
    // port translations with the original ports).
    let enforced = enforce_expected_ports_at(
        out,
        ip_start,
        ip_start + rel_l4,
        meta.addr_family,
        meta.protocol,
        enforced_ports,
        non_first_fragment,
    )
    .unwrap_or(false);
    if apply_nat {
        apply_nat_ipv4(
            &mut out[ip_start..],
            meta.protocol,
            decision.nat,
            non_first_fragment,
        )?;
    }
    let skip_ttl = (meta.meta_flags & 0x80) != 0;
    if !skip_ttl {
        out[ip_start + 8] -= 1;
    }
    adjust_ipv4_header_checksum(
        &mut out[ip_start..ip_start + ihl],
        old_src,
        old_dst,
        old_ttl,
    )?;
    if selected_tcp_mss > 0 {
        let _ = clamp_tcp_mss_frame(out, ip_start, selected_tcp_mss);
    }
    // #1852: skip the full L4 recompute on a non-first fragment — it
    // writes the checksum at ihl+16/+6, which is payload here. The forced
    // tunnel-egress recompute (tunnel_endpoint_id != 0) would otherwise
    // re-corrupt the very bytes the NAT/port gates above protected.
    // (`repaired_ports` is already false for fragments — the ICMP-ident
    // restore is gated — so only the forced-tunnel term can fire.)
    if !non_first_fragment && (force_tunnel_l4_recompute || (repaired_ports && !enforced)) {
        recompute_l4_checksum_ipv4(&mut out[ip_start..], ihl, meta.protocol, true)?;
    }
    Some(())
}
