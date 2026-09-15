//! IPv6 arm of `build_forwarded_frame_into_from_frame`.
//!
//! Body is byte-identical to the AF_INET6 match arm at
//! `frame/mod.rs:342..380` before this split. The orchestrator at
//! `frame/build/mod.rs` computes the L2 prelude (eth header, payload
//! memcpy, ip_start, selected_tcp_mss, apply_nat) and dispatches here.

use super::super::tcp::clamp_tcp_mss_frame;
use super::super::{
    apply_nat_ipv6, enforce_expected_ports_at, ipv6_is_non_first_fragment,
    recompute_l4_checksum_ipv6, restore_l4_tuple_from_meta, v6_rel_l4_offset,
};
use crate::afxdp::{ForwardPacketMeta, SessionDecision};

#[inline(always)]
pub(in crate::afxdp::frame) fn build_forwarded_frame_into_ipv6(
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
    if out.len() < ip_start + 40 {
        return None;
    }
    if (meta.meta_flags & 0x80) == 0 && out[ip_start + 7] <= 1 {
        return None;
    }
    // Use meta-derived L4 offset when valid (>= 40 for IPv6 base header,
    // avoids walking extension headers). Fall back to parsing otherwise.
    // Shared precedence rule via `v6_rel_l4_offset` (#1838).
    let rel_l4 = v6_rel_l4_offset(
        &out[ip_start..],
        meta.l3_offset,
        meta.l4_offset,
        meta.addr_family,
    )?;
    // #1852: non-first-fragment predicate, computed once and threaded.
    let non_first_fragment = ipv6_is_non_first_fragment(&out[ip_start..]);
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
        apply_nat_ipv6(
            &mut out[ip_start..],
            rel_l4,
            meta.protocol,
            decision.nat,
            non_first_fragment,
        )?;
    }
    if (meta.meta_flags & 0x80) == 0 {
        out[ip_start + 7] -= 1;
    }
    if selected_tcp_mss > 0 {
        let _ = clamp_tcp_mss_frame(out, ip_start, selected_tcp_mss);
    }
    // #1852: skip the full L4 recompute on a non-first fragment — it
    // writes the checksum at rel_l4+16/+6, which is payload here. The
    // forced tunnel-egress recompute would otherwise re-corrupt the bytes
    // the NAT/port gates above protected.
    if !non_first_fragment && (force_tunnel_l4_recompute || (repaired_ports && !enforced)) {
        recompute_l4_checksum_ipv6(&mut out[ip_start..], rel_l4, meta.protocol)?;
    }
    Some(())
}
