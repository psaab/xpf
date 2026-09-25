//! #8274 step 3: WireGuard transport-data decap INSIDE the AF_XDP worker.
//!
//! # What this fixes
//!
//! WireGuard's two directions were asymmetric. Encap has always run inside the
//! worker, on a packet that has been through screen, session, route, policy and
//! NAT. Decap did not: the shim steered every datagram on the listen port to
//! the kernel, the control thread's socket read it, `try_decap` authenticated
//! it, and `slowpath::write_packet_nonblocking` put the plaintext straight onto
//! the `wgN` TUN for the kernel to route. Between `try_decap` and that write
//! there was an RFC 6040 ECN combine and nothing else — no zone lookup, no
//! session, no route/PBR/filter/NAT, no zone counter, no policy-deny event.
//!
//! A peer's `allowed-ips` is a cryptographic check on the inner SOURCE address.
//! It has no destination, no zone pair, no application and no direction. It is
//! not a security policy, and it was the only thing standing between an
//! authenticated peer and the kernel's forwarding path.
//!
//! # Why this half is cheap
//!
//! Every input was already here. `ForwardingState.wg_engines` holds the live
//! engine (the encap path reads it per packet); `try_decap` takes `&self` and is
//! internally synchronised, so N workers may call it concurrently on one `Arc`;
//! the tunnel's `logical_ifindex` is on the endpoint; and
//! `logical_ingress::build_logical_ingress_packet` (#8062) does the
//! synthesize / ECN-combine / reparse / logical-rebind tail that native GRE
//! already proves in production.
//!
//! Two things are strictly BETTER here than in the control thread:
//!
//!   * **the outer ECN bits.** The outer IP header is still in the frame, so
//!     `outer_ecn_bits` reads them directly. The socket path has to recover them
//!     out-of-band through `IP_RECVTOS` / `IPV6_RECVTCLASS` cmsg, because the
//!     kernel UDP stack stripped the header before the record arrived.
//!   * **the attachment generations.** `LogicalIngressParams` deliberately has
//!     no `Default` and no `Option` on `config_generation` / `fib_generation`,
//!     and its doc names the WireGuard control thread as the caller that has no
//!     value to inherit and would have to fabricate one — which "would compile,
//!     adjudicate, and violate the fencing invariant SILENTLY, because a
//!     fabricated generation always looks current". A worker caller inherits
//!     both from the triggering RX meta, exactly as GRE does.
//!
//! # Direction of the change
//!
//! This is a TIGHTENING, and it is visible on the first packet. Inner traffic
//! that an authenticated peer sends today is forwarded by the kernel with no
//! zone adjudication at all; after this it is adjudicated like any other
//! transit packet, under the tunnel's logical ingress zone. Traffic that flows
//! today can therefore start being DENIED — by the operator's own policy, which
//! previously never ran on it. That is the point of the issue, not a regression,
//! but it is availability-visible on upgrade and it is why this is a security
//! label rather than a cleanup.

use super::super::*;
use super::WG_TYPE_DATA;
use crate::afxdp::gre::{
    outer_datagram_end, outer_ecn_bits, packet_trimmed_len, parse_inner_protocol_and_offsets,
};

/// A decapsulated WireGuard transport-data record, ready to replace its outer
/// frame for the rest of the worker's pass.
///
/// Shaped exactly like `NativeGrePacket` because the consumer is the same: the
/// poll loop shadows `meta` and rebinds `packet_frame`, and everything
/// downstream adjudicates the INNER packet.
pub(in crate::afxdp) struct WgDecapPacket {
    pub(in crate::afxdp) frame: Vec<u8>,
    pub(in crate::afxdp) meta: UserspaceDpMeta,
    /// The peer whose session keys authenticated the record. Proven, not
    /// inferred: `try_decap` demuxes the session from `hdr.receiver_index`
    /// before any AEAD work and the record is authenticated by the time the
    /// outcome is built.
    pub(in crate::afxdp) peer_pubkey: [u8; 32],
}

/// The WireGuard tunnel endpoint listening on `dst_port`, with its live engine.
///
/// Walks `wg_engines` rather than `tunnel_endpoints` deliberately: that map IS
/// the WireGuard-only set, so the scan is over the number of WG tunnels (0, 1 or
/// 2 in practice) instead of over every tunnel endpoint on the box. A GRE-mode
/// row cannot appear in it, so no kind re-check is needed — but the mode is
/// checked anyway, for the same defence-in-depth reason `match_tunnel_endpoint`
/// re-checks `TunnelKind::Gre` against its own index.
fn wg_endpoint_for_listen_port(
    forwarding: &ForwardingState,
    dst_port: u16,
) -> Option<(&TunnelEndpoint, &std::sync::Arc<super::WgEngine>)> {
    for (id, engine) in forwarding.wg_engines.iter() {
        let endpoint = forwarding.tunnel_endpoints.get(id)?;
        if endpoint.wg_listen_port == dst_port
            && tunnel_mode_kind(&endpoint.mode) == TunnelKind::WireGuard
        {
            return Some((endpoint, engine));
        }
    }
    None
}

/// Is this a UDP datagram addressed to one of OUR OWN configured WireGuard
/// sockets — a listen port on a locally owned destination?
/// `poll_descriptor` uses this to keep an undecapsulated WG underlay datagram
/// outside inner IPv6 ingress policy classification (handshakes and records the
/// worker declines remain owned by the kernel/control socket). Successfully
/// decapsulated transport data is checked on its INNER frame instead.
///
/// #10686 (review advisory): the port match alone is NOT enough. A transit
/// datagram to an unrelated destination that merely shares the listen-port
/// number is not underlay — exempting it would let embedded-v4 IPv6 reach
/// policy via permit-any, the exact bypass the ingress gate closes. The
/// destination must be an address this box answers for
/// (`owns_configured_ip`: interface IPs plus NAT/DNAT locals).
#[inline]
pub(in crate::afxdp) fn is_wg_underlay_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
) -> bool {
    if !forwarding.has_wg_tunnels || meta.protocol != PROTO_UDP {
        return false;
    }
    let Some(end) = outer_datagram_end(frame, meta) else {
        return false;
    };
    let l4 = meta.l4_offset as usize;
    let Some(udp_end) = l4.checked_add(8) else {
        return false;
    };
    if udp_end > end {
        return false;
    }
    let Some(udp) = frame.get(l4..udp_end) else {
        return false;
    };
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if wg_endpoint_for_listen_port(forwarding, dst_port).is_none() {
        return false;
    }
    // This helper is reached only for a mapped/compatible IPv6 packet. Mirror
    // the ingress gate's wire-L3 derivation and version check before trusting
    // the destination address.
    if meta.addr_family as i32 != libc::AF_INET6 {
        return false;
    }
    let Some(l3) = frame_l3_offset(frame) else {
        return false;
    };
    let Some(v6_end) = l3.checked_add(40) else {
        return false;
    };
    let Some(hdr) = frame.get(l3..v6_end) else {
        return false;
    };
    if hdr[0] >> 4 != 6 {
        return false;
    }
    let Ok(raw_dst) = <[u8; 16]>::try_from(&hdr[24..40]) else {
        return false;
    };
    forwarding.owns_configured_ip(std::net::IpAddr::V6(
        std::net::Ipv6Addr::from(raw_dst),
    ))
}



/// Decapsulate an inbound WireGuard transport-data record, or `None`.
///
/// `None` means "not ours, or not decryptable" and the caller leaves the packet
/// alone — it is NOT a drop. Every rejection here is a record this stage has no
/// business claiming: a non-UDP packet, a datagram on no configured listen
/// port, a handshake record (which the shim still steers to the kernel, where
/// the control thread owns the state machine), or a record whose AEAD failed.
///
/// # The decap buffer
///
/// `scratch` is the per-worker `WgWorkerScratch`, whose module doc has named
/// this integration as its consumer since it was written: "No `vec![]` in
/// encap/decap." Allocating per packet on the decap path would be the hot-path
/// allocation `docs/engineering-style.md` treats as a defect by default.
pub(in crate::afxdp) fn try_wg_decap_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    forwarding: &ForwardingState,
    scratch: &super::WgWorkerScratch,
) -> Option<WgDecapPacket> {
    // #1432 §4.5's cheap gate first: a box with no WireGuard tunnel never
    // probes the engine map, and a non-UDP packet never reads a byte.
    if !forwarding.has_wg_tunnels || meta.protocol != PROTO_UDP {
        return None;
    }
    // #6748's bound, for the same reason GRE takes it: the outer IP header's
    // own declared length is the authoritative end of this datagram, and bytes
    // past it are a trailer the sender appended rather than part of the record.
    // Reading the WireGuard record out of the FRAME instead would let a peer
    // append bytes past the datagram and have them authenticated as ciphertext.
    let outer_end = outer_datagram_end(frame, meta)?;
    let outer = frame.get(..outer_end)?;

    let l4 = meta.l4_offset as usize;
    let udp = outer.get(l4..l4.checked_add(8)?)?;
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);

    let record = outer.get(meta.payload_offset as usize..)?;
    // Only TRANSPORT DATA. Handshake and cookie records (types 1, 2, 3) belong
    // to the control thread, which owns the handshake state machine and the
    // #1865 unknown-type accounting; the shim still steers those to the kernel.
    if record.first().copied() != Some(WG_TYPE_DATA) {
        return None;
    }

    let (endpoint, engine) = wg_endpoint_for_listen_port(forwarding, dst_port)?;

    let mut decap_buf = scratch.decap_out.borrow_mut();
    // #9018: `.ok()?` used to collapse EVERY error arm here, and two of them
    // carry the proven peer public key on purpose: `Keepalive` (#7230) and
    // `MalformedInner` (#7686) were both given a `[u8; 32]` payload precisely
    // so the identity would stop dying with the error. Both are POST-AEAD —
    // `try_decap` demuxes the session from `hdr.receiver_index` before any AEAD
    // work and the record is authenticated by the time either is constructed —
    // so the peer they name is proven, not guessed. That is the same basis the
    // success arm's roam report stands on a few dozen lines below.
    //
    // A keepalive is the case that matters. It is a type-4 transport record, so
    // `wg_worker_claims_record` claims it for the worker and the shim declines
    // `cpumap_or_pass`; the socket path in wg_control/dispatch.rs, which DOES
    // map both arms to `InboundOutcome::Authenticated(pk)`, never sees it. So a
    // keepalive from a NAT-rebound or roaming endpoint — the exact situation
    // WireGuard keepalives exist for — moved nothing.
    //
    // Scope: the endpoint is observed and the frame is then declined exactly as
    // before. There is no inner packet to adjudicate on either arm, so the "no
    // delivery" contract is unchanged; this is a cold path with no fast-path
    // cost.
    let outcome = match engine.try_decap(record, &mut decap_buf) {
        Ok(outcome) => outcome,
        Err(super::engine::DecapError::Keepalive(peer_pubkey))
        | Err(super::engine::DecapError::MalformedInner(peer_pubkey)) => {
            if let Some(src_ip) = outer_source_ip(outer, meta) {
                engine.note_worker_observed_endpoint(
                    &peer_pubkey,
                    std::net::SocketAddr::new(src_ip, src_port),
                );
            }
            return None;
        }
        // Every other arm is unauthenticated or carries no identity. An
        // unauthenticated datagram must never move a peer's endpoint, or anyone
        // who can reach the listen port could redirect a tunnel's egress.
        Err(_) => return None,
    };
    // The contract on `try_decap` is that `out` MUST NOT be inspected on Err —
    // every post-AEAD error arm zeroes it — which the `?` above honours by not
    // reaching this line.
    let inner = decap_buf.get(..outcome.len)?;
    // Defensive only. A keepalive does NOT arrive here: `try_decap` returns
    // `Err(DecapError::Keepalive(..))` for a zero-length plaintext before it can
    // produce an `Ok`, so `outcome.len` is never 0 today and this branch is
    // unreachable. It used to carry a comment saying the control thread's
    // endpoint learning "still wants it" — describing, on an unreachable arm,
    // the very work the `.ok()?` above was throwing away (#9018). The endpoint
    // observation now happens on the real keepalive arm; this stays as a guard
    // against a future `Ok` with an empty plaintext rather than as a claim about
    // what keepalives do.
    if inner.is_empty() {
        return None;
    }

    let (inner_family, inner_eth_proto) = match inner.first().map(|b| b >> 4) {
        // Same ethertypes `gre_inner_family_and_proto` writes, for the same
        // synthesized Ethernet header.
        Some(4) => (libc::AF_INET as u8, 0x0800u16),
        Some(6) => (libc::AF_INET6 as u8, 0x86ddu16),
        _ => return None,
    };
    let inner_len = packet_trimmed_len(inner, inner_family)?;
    let inner = inner.get(..inner_len)?;
    let (protocol, rel_l4_offset, payload_offset) =
        parse_inner_protocol_and_offsets(inner, inner_family)?;

    let (synthetic, inner_meta) = crate::afxdp::logical_ingress::build_logical_ingress_packet(
        forwarding,
        &crate::afxdp::logical_ingress::LogicalIngressParams {
            inner_packet: inner,
            inner_family,
            inner_eth_proto,
            protocol,
            rel_l4_offset,
            payload_offset,
            // The TUNNEL's logical ifindex, never the underlay's. This is what
            // makes the inner packet adjudicate under the tunnel's zone
            // (#7167 invariant 2) instead of the WAN's.
            logical_ifindex: endpoint.logical_ifindex,
            // Strictly better than the control thread has it: the outer IP
            // header is still in the frame.
            outer_ecn: outer_ecn_bits(frame, meta),
            ecn_illegal_drops: &crate::afxdp::gre::WG_DECAP_ECN_ILLEGAL_DROPS,
            // NOT `GRE_DECAP_INGRESS_FLAG`. The GRE flag selects the
            // `tcp-mss gre-in` clamp value (#2486), which is the wrong number
            // for a WireGuard tunnel — its clamp is computed from the endpoint
            // by `wg_tcp_mss` on the EGRESS side. "Whatever GRE passes" is
            // explicitly not an answer for another protocol.
            meta_flags: 0,
            rx_queue_index: meta.rx_queue_index,
            // Inherited from the triggering RX meta, which is the whole reason
            // this decap belongs in the worker. See the module comment.
            config_generation: meta.config_generation,
            fib_generation: meta.fib_generation,
        },
    )?;

    // #8274 step 3: the roam report, made HERE because this is where the
    // authentication is proven and the engine is already in hand. `try_decap`
    // demuxed the session from `hdr.receiver_index` before any AEAD work and
    // the record is authenticated by the time `outcome` exists, so the peer
    // this endpoint is attributed to is proven rather than guessed — the same
    // basis the control thread's own learning stands on.
    //
    // Reported only for a record that DECRYPTED. An unauthenticated datagram
    // must never move a peer's endpoint, or anyone who can send to the listen
    // port could redirect a tunnel's egress.
    if let Some(src_ip) = outer_source_ip(outer, meta) {
        engine.note_worker_observed_endpoint(
            &outcome.peer_pubkey,
            std::net::SocketAddr::new(src_ip, src_port),
        );
    }

    Some(WgDecapPacket {
        frame: synthetic,
        meta: inner_meta,
        peer_pubkey: outcome.peer_pubkey,
    })
}

/// The outer datagram's SOURCE address, for the roam report.
///
/// Read from the outer IP header still present in the frame — the same header
/// `outer_ecn_bits` reads. The control thread gets this from `recvfrom`; here
/// it is parsed, which is why it is bounds-checked rather than assumed.
/// Nibble-gated (#9900 F-095 SPARK-M6): the read feeds PERSISTENT roam
/// learning, so a wrong stamp fails closed (skip the observation) instead
/// of learning a garbage endpoint.
fn outer_source_ip(outer: &[u8], meta: UserspaceDpMeta) -> Option<std::net::IpAddr> {
    let l3 = crate::afxdp::frame::nibble_checked_l3(outer, meta.l3_offset, meta.addr_family)?.l3;
    match meta.addr_family as i32 {
        libc::AF_INET => {
            let b = outer.get(l3.checked_add(12)?..l3.checked_add(16)?)?;
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                b[0], b[1], b[2], b[3],
            )))
        }
        libc::AF_INET6 => {
            let b = outer.get(l3.checked_add(8)?..l3.checked_add(24)?)?;
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod outer_source_ip_tests_9900 {
    use super::*;

    /// #9900 F-095 (SPARK-M6): the roam source read falls back on a wrong
    /// stamp instead of learning a garbage endpoint. Pre-fix a stamp of 18
    /// read the DESTINATION (bytes 30..34) as the source.
    #[test]
    fn outer_source_ip_falls_back_on_wrong_stamp_9900() {
        let mut outer = vec![0u8; 14 + 20 + 8];
        outer[12..14].copy_from_slice(&[0x08, 0x00]);
        outer[14] = 0x45;
        outer[16..18].copy_from_slice(&[0x00, 0x1c]);
        outer[26..30].copy_from_slice(&[10, 0, 0, 1]);
        outer[30..34].copy_from_slice(&[10, 0, 0, 2]);
        let expected = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let meta_for = |l3_offset: u16| UserspaceDpMeta {
            l3_offset,
            addr_family: libc::AF_INET as u8,
            ..UserspaceDpMeta::default()
        };
        assert_eq!(
            outer_source_ip(&outer, meta_for(14)),
            Some(expected),
            "correct stamp reads the source"
        );
        assert_eq!(
            outer_source_ip(&outer, meta_for(18)),
            Some(expected),
            "wrong stamp falls back to the wire source, not the dst bytes"
        );
    }
}
