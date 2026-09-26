//! Orchestrator for `build_forwarded_frame_into_from_frame`.
//!
//! Computes the L2 prelude (eth header write + payload memcpy +
//! resolution of `apply_nat` / `selected_tcp_mss` / `force_tunnel_l4_recompute`)
//! and dispatches to the address-family helper.
//!
//! Codegen contract (see docs/pr/1352-frame-build-rewrite-split/plan.md):
//!   - This orchestrator is `#[inline(never)]` + concrete `meta:
//!     ForwardPacketMeta` to structurally guarantee ONE binary
//!     definition (no transitive duplication through the 5 caller
//!     wrappers, no generic monomorphization fanout).
//!   - Per-family helpers (`build/ipv4.rs`, `build/ipv6.rs`) are
//!     `#[inline(always)]` to fold into this orchestrator's body.

mod ipv4;
mod ipv6;

use ipv4::build_forwarded_frame_into_ipv4;
use ipv6::build_forwarded_frame_into_ipv6;

use super::{
    decode_frame_summary, frame_has_tcp_rst, ipv6_ah_sighted, nibble_checked_l3, select_tcp_mss,
    trim_l3_payload, verify_built_frame_checksums, write_eth_header_slice, ForwardPacketMeta,
    ForwardingDisposition, ForwardingState, SessionDecision,
};

#[inline(never)]
pub(in crate::afxdp) fn build_forwarded_frame_into_from_frame(
    out: &mut [u8],
    frame: &[u8],
    meta: ForwardPacketMeta,
    decision: &SessionDecision,
    forwarding: &ForwardingState,
    apply_nat_on_fabric: bool,
    expected_ports: Option<(u16, u16)>,
) -> Option<usize> {
    let dst_mac = decision.resolution.neighbor_mac?;
    // Trust the stamped L3 offset only when the nibble at it matches the
    // family (#9900 F-095); a wrong-but-plausible stamp falls back to the
    // wire parse instead of shifting the payload copy and every L3 rewrite.
    // GPT-5: the L4 stamp dies with a distrusted L3 (neutralize to `l3`,
    // forcing wire derivation in `v6_rel_l4_offset`).
    let checked = nibble_checked_l3(frame, meta.l3_offset, meta.addr_family)?;
    let l3 = checked.l3;
    let mut meta = meta;
    meta.l3_offset = l3 as u16;
    if !checked.stamp_trusted {
        meta.l4_offset = l3 as u16;
    }
    if l3 >= frame.len() {
        return None;
    }
    let raw_payload = &frame[l3..];
    let payload = trim_l3_payload(raw_payload, meta);
    let (src_mac, vlan_id, apply_nat) =
        if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                apply_nat_on_fabric,
            )
        } else {
            (
                decision.resolution.src_mac?,
                decision.resolution.tx_vlan_id,
                true,
            )
        };
    let eth_len = if vlan_id > 0 { 18 } else { 14 };
    let ether_type = match meta.addr_family as i32 {
        libc::AF_INET => 0x0800,
        libc::AF_INET6 => 0x86dd,
        _ => return None,
    };
    let frame_len = eth_len + payload.len();
    if frame_len > out.len() {
        return None;
    }
    write_eth_header_slice(
        out.get_mut(..eth_len)?,
        dst_mac,
        src_mac,
        vlan_id,
        ether_type,
    )?;
    let payload_out = out.get_mut(eth_len..frame_len)?;
    // SAFETY: source (payload) and destination (payload_out) are distinct
    // buffers — payload is from the ingress UMEM, payload_out is in the
    // egress UMEM. Lengths are equal because both span eth_len..frame_len.
    debug_assert_eq!(payload_out.len(), payload.len());
    unsafe {
        core::ptr::copy_nonoverlapping(payload.as_ptr(), payload_out.as_mut_ptr(), payload.len());
    }
    let out = &mut out[..frame_len];
    let force_tunnel_l4_recompute = decision.resolution.tunnel_endpoint_id != 0;
    // #2486: select the MSS clamp by per-packet forwarding context
    // (all-tcp / gre-in / tunnel-egress). #2299: tunnel egress still
    // dispatches by kind inside `select_tcp_mss` — WG needs the larger
    // WG-overhead-aware value, not the GRE formula (which would clamp too
    // high and get the peer's full-MSS data dropped at the WG encap MTU
    // guard). Plain forwarded SYNs now clamp to `all-tcp`; GRE-decapped
    // ingress SYNs clamp to `gre-in` (was previously dead config).
    // #10729 X2-F6: never clamp through AH (see the in-place path gate).
    let selected_tcp_mss = if ipv6_ah_sighted(frame, meta.addr_family, l3) {
        0
    } else {
        select_tcp_mss(forwarding, decision, &meta)
    };
    let ip_start = eth_len;
    match meta.addr_family as i32 {
        libc::AF_INET => build_forwarded_frame_into_ipv4(
            out,
            ip_start,
            meta,
            decision,
            apply_nat,
            expected_ports,
            selected_tcp_mss,
            force_tunnel_l4_recompute,
        )?,
        libc::AF_INET6 => build_forwarded_frame_into_ipv6(
            out,
            ip_start,
            meta,
            decision,
            apply_nat,
            expected_ports,
            selected_tcp_mss,
            force_tunnel_l4_recompute,
        )?,
        _ => return None,
    }
    // Debug: dump first N built frames' Ethernet + IP headers to see post-NAT on wire
    if cfg!(feature = "debug-log") {
        thread_local! {
            static BUILD_FWD_DBG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        BUILD_FWD_DBG_COUNT.with(|c| {
            let n = c.get();
            if n < 30 {
                c.set(n + 1);
                let pkt_detail = decode_frame_summary(out);
                eprintln!(
                    "DBG BUILT_ETH[{}]: vlan={} frame_len={} proto={} {}",
                    n, vlan_id, frame_len, meta.protocol, pkt_detail,
                );
                // For the first 3 frames, also dump the full IP+TCP header hex
                if n < 3 {
                    let dump_len = frame_len.min(out.len()).min(eth_len + 60);
                    let hex: String = out[..dump_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("DBG BUILT_HEX[{n}]: {hex}");
                }
            }
        });
    }
    // Checksum verification: recompute from scratch and compare to incremental update.
    if cfg!(feature = "debug-log") {
        verify_built_frame_checksums(&out[..frame_len]);
    }

    // RST corruption check: detect if frame building introduced a TCP RST
    // that wasn't in the source frame.
    if cfg!(feature = "debug-log") {
        let out_has_rst = frame_has_tcp_rst(&out[..frame_len]);
        let in_has_rst = frame_has_tcp_rst(frame);
        if out_has_rst && !in_has_rst {
            thread_local! {
                static BUILD_RST_CORRUPT_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
            }
            BUILD_RST_CORRUPT_COUNT.with(|c| {
                let n = c.get();
                if n < 20 {
                    c.set(n + 1);
                    let in_summary = decode_frame_summary(frame);
                    let out_summary = decode_frame_summary(&out[..frame_len]);
                    eprintln!(
                        "RST_CORRUPT BUILD[{}]: frame build INTRODUCED RST! in=[{}] out=[{}]",
                        n, in_summary, out_summary,
                    );
                    let in_hex_len = frame.len().min(80);
                    let in_hex: String = frame[..in_hex_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let out_hex_len = frame_len.min(out.len()).min(80);
                    let out_hex: String = out[..out_hex_len]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("RST_CORRUPT IN_HEX[{n}]: {in_hex}");
                    eprintln!("RST_CORRUPT OUT_HEX[{n}]: {out_hex}");
                }
            });
        }
    }
    Some(frame_len)
}
