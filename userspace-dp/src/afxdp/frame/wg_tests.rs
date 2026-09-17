// Tests for afxdp/frame/wg.rs (#4671) — relocated verbatim out of the former
// inline `#[cfg(test)] mod wg_frame_tests { ... }` block to keep the production
// file (WG encap) readable. The production WG encap was DELIBERATELY not split
// (codex-review-174 #8): splitting it risks hiding the single-underlay-FIB-
// lookup invariant (#3992) / inviting duplicate lookups. Loaded as a sibling
// submodule via `#[path = "wg_tests.rs"]` from wg.rs. No test logic changed.

use super::super::super::test_fixtures::*;
use super::*;

#[test]
fn pad_to_16_rounds_up() {
    assert_eq!(pad_to_16(0), 0);
    assert_eq!(pad_to_16(1), 16);
    assert_eq!(pad_to_16(16), 16);
    assert_eq!(pad_to_16(17), 32);
}

#[test]
fn wg_encapped_size_is_pad_aware() {
    // inner 1 byte: pads to 16; record = 16 (hdr) + 16 (pad) + 16
    // (tag) = 48; + outer v4 IP(20) + UDP(8) = 76.
    assert_eq!(wg_encapped_size(1, false), 16 + 16 + 16 + 20 + 8);
    // v6 adds 20 more for the bigger outer IP header.
    assert_eq!(
        wg_encapped_size(1, true),
        wg_encapped_size(1, false) + 20
    );
    // An inner already a 16-multiple does not over-pad.
    assert_eq!(
        wg_encapped_size(32, false),
        WG_DATA_HEADER_LEN + 32 + POLY1305_TAG_LEN + 20 + 8
    );
}

// === #2680: the OUTER MTU guard gates against the PHYSICAL underlay
// egress MTU, not the tunnel LOGICAL ifindex MTU. ===

/// A tunnel-resolved `SessionDecision` whose resolution carries
/// `egress_ifindex` = the tunnel LOGICAL ifindex (what the resolver
/// stores) and `tunnel_endpoint_id` = the WG endpoint id.
fn wg_tunnel_decision(logical_ifindex: i32, tunnel_endpoint_id: u16) -> SessionDecision {
    SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::MissingNeighbor,
        local_ifindex: 0,
        egress_ifindex: logical_ifindex,
        tx_ifindex: 0,
        tunnel_endpoint_id,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }, nat: crate::nat::NatDecision::default(), install_table_domain: 0, install_table_check: 0 }
}

// The peer endpoint the WG fixture's single peer learns / is configured
// with — the REAL outer hop (the endpoint-level destination is zeroed for
// WG). The route to this IP egresses on the physical underlay (reth0.80).
const WG_PEER_OUTER_DST: IpAddr =
    IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));

#[test]
fn outer_mtu_uses_physical_egress_not_tunnel_logical() {
    // The WG endpoint's logical interface (wg0.0, ifindex 400) has MTU
    // 1420; the outer transport egresses on reth0.80 (ifindex 12, MTU
    // 1500) via the route to the peer endpoint. The guard must use the
    // PHYSICAL 1500, NOT the logical 1420.
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    // Sanity: both interfaces really do carry the distinct MTUs the
    // fixture claims, so the assertion below is meaningful.
    assert_eq!(state.egress.get(&400).map(|e| e.mtu), Some(1420));
    assert_eq!(state.egress.get(&12).map(|e| e.mtu), Some(1500));

    let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
    let decision = wg_tunnel_decision(400, 1);
    // The fix: the guard MTU is the physical underlay (1500). Reverting
    // to the logical-ifindex lookup would return 1420 → this fails red.
    assert_eq!(
        outer_physical_egress_mtu(&decision, &state, endpoint, WG_PEER_OUTER_DST),
        1500,
        "outer guard must use the PHYSICAL underlay MTU (reth0.80=1500), \
         not the tunnel LOGICAL ifindex MTU (wg0.0=1420)"
    );
}

#[test]
fn fits_physical_but_exceeds_logical_inner_is_not_dropped() {
    // An inner packet whose OUTER encapped size fits the PHYSICAL egress
    // (1500) but exceeds the tunnel LOGICAL MTU (1420) must NOT be
    // dropped. Pick an inner length whose encapped size is in (1420,
    // 1500].
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
    let decision = wg_tunnel_decision(400, 1);
    let physical_mtu =
        outer_physical_egress_mtu(&decision, &state, endpoint, WG_PEER_OUTER_DST);
    let logical_mtu = 1420usize;

    // 1400-byte inner → ~1460-ish outer (v4): fits 1500, exceeds 1420.
    let inner = 1400usize;
    let encapped = wg_encapped_size(inner, false);
    assert!(
        encapped > logical_mtu,
        "the test inner must exceed the logical MTU (else it proves nothing): \
         {encapped} <= {logical_mtu}"
    );
    // With the fix the guard compares against physical_mtu → NOT dropped.
    // Reverting to the logical MTU would make physical_mtu == 1420 and
    // this assertion would fail red (the silent drop the bug caused).
    assert!(
        encapped <= physical_mtu,
        "fits-physical-exceeds-logical inner must be forwarded, not dropped \
         ({encapped} > {physical_mtu})"
    );
}

#[test]
fn genuinely_oversized_outer_still_drops_against_physical() {
    // An inner whose OUTER encapped size exceeds even the PHYSICAL MTU
    // (1500) is still correctly dropped — the fix widens the guard to the
    // underlay, it does not disable it.
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
    let decision = wg_tunnel_decision(400, 1);
    let physical_mtu =
        outer_physical_egress_mtu(&decision, &state, endpoint, WG_PEER_OUTER_DST);
    assert_eq!(physical_mtu, 1500);
    // 1480-byte inner pads to 1488; record 1488+16+16=1520; +20+8 = 1548
    // > 1500 → drop.
    assert!(
        wg_encapped_size(1480, false) > physical_mtu,
        "a genuinely oversized outer must still exceed the physical MTU"
    );
}

#[test]
fn outer_mtu_falls_back_to_logical_when_outer_unresolvable() {
    // Conservative fallback: if the outer destination has no FIB entry the
    // route lookup NoRoutes → fall back to the resolution's own
    // egress_ifindex MTU (the pre-#2680 behaviour), never tighter.
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
    let decision = wg_tunnel_decision(400, 1);
    // 198.51.100.9 has no route → NoRoute → fall back to egress_ifindex
    // (400, the logical, MTU 1420).
    let unrouted = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9));
    assert_eq!(
        outer_physical_egress_mtu(&decision, &state, endpoint, unrouted),
        1420
    );
}

// === #2701: the OUTER IP SOURCE follows the PHYSICAL underlay egress,
// not the tunnel LOGICAL ifindex. ===

#[test]
fn outer_source_uses_physical_egress_not_tunnel_logical() {
    // The WG endpoint's logical interface (wg0.0, ifindex 400) carries a
    // TUNNEL address (10.123.0.1) and no WAN primary; the outer transport
    // egresses on reth0.80 (ifindex 12, primary 172.16.80.8) via the route
    // to the peer endpoint. The outer source must be the PHYSICAL WAN
    // primary, NOT the logical tunnel address (or None).
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
    let decision = wg_tunnel_decision(400, 1);

    // Sanity: the logical iface's primary really is the tunnel address —
    // sourcing from it (the bug) would leak a tunnel source / fail policy.
    assert_eq!(
        state.egress.get(&400).and_then(|e| e.primary_v4),
        Some(std::net::Ipv4Addr::new(10, 123, 0, 1)),
        "logical wg0.0 primary is the tunnel address (the wrong source)"
    );

    // The fix: resolve the physical egress (reth0.80, ifindex 12) and read
    // its WAN primary. Reverting to `decision.resolution.egress_ifindex`
    // (400) would read the tunnel address → this fails red.
    let physical =
        outer_physical_egress_ifindex(&decision, &state, endpoint, WG_PEER_OUTER_DST);
    assert_eq!(physical, 12, "outer source must follow the PHYSICAL egress");
    assert_eq!(
        state.egress.get(&physical).and_then(|e| e.primary_v4),
        Some(std::net::Ipv4Addr::new(172, 16, 80, 8)),
        "outer source must be the PHYSICAL WAN primary (172.16.80.8), \
         not the tunnel-logical address"
    );
}

#[test]
fn outer_source_falls_back_to_logical_when_outer_unresolvable() {
    // Conservative fallback parity with the MTU helper: an unresolvable
    // outer destination falls back to the resolution's own egress_ifindex
    // (the logical), so the source is no worse than the pre-#2701 lookup.
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
    let decision = wg_tunnel_decision(400, 1);
    let unrouted = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9));
    assert_eq!(
        outer_physical_egress_ifindex(&decision, &state, endpoint, unrouted),
        400,
        "unresolvable outer with no stored tx_ifindex falls back to the \
         logical egress_ifindex"
    );
}

// === #2837 (NON-REPRODUCING): the report claimed outer re-resolution
// drops the physical tx_ifindex and falls back to the logical wg ifindex
// for a dynamic-learned underlay neighbor. It does not reproduce: the
// FIRST arm of `outer_physical_egress_ifindex` re-resolves the route to the
// real peer endpoint and returns the PHYSICAL underlay egress even when the
// neighbor is unresolved (dynamic-learned), because the egress ifindex is
// ROUTE-derived, not neighbor-derived. These tests drive the helper with
// the REAL resolver values a WG session actually produces (tx_ifindex = 0,
// dynamic_neighbors visible only through the route). No fabricated
// tx_ifindex is used — the real resolver never produces a usable one for
// WG (it stores tx_ifindex = 0, or the VLAN parent which has no egress
// row). See the helper doc comment for the full analysis. ===

#[test]
fn outer_egress_returns_physical_for_dynamic_learned_underlay_neighbor() {
    // #2837 core claim, refuted. The fixture has NO static neighbor for the
    // peer-endpoint next-hop (172.16.80.1), so resolving the route to the
    // real peer endpoint with the dynamic-neighbor map elided (the
    // `outer_physical_egress_ifindex` helper passes `None`) yields
    // disposition `MissingNeighbor` — exactly the dynamic-learned-underlay
    // case the report worried about. The route still resolves the PHYSICAL
    // egress (reth0.80, ifindex 12), and the FIRST arm accepts
    // `MissingNeighbor`, so the helper returns the physical underlay (12),
    // NOT the logical wg ifindex (400). The dynamic map (if threaded) would
    // only change the disposition / neighbor_mac, never this ifindex.
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");

    // The real resolver value for this route, with the dynamic-neighbor map
    // elided: MissingNeighbor (no static neighbor) but the PHYSICAL egress.
    let real = lookup_forwarding_resolution_v4(
        &state,
        None,
        std::net::Ipv4Addr::new(203, 0, 113, 7),
        &endpoint.transport_table,
        1,
        false,
        None,
    );
    assert_eq!(
        real.disposition,
        ForwardingDisposition::MissingNeighbor,
        "the dynamic-learned-underlay case must be MissingNeighbor, not NoRoute"
    );
    assert_eq!(
        real.egress_ifindex, 12,
        "MissingNeighbor still carries the route-derived PHYSICAL egress"
    );

    let decision = wg_tunnel_decision(400, 1);
    assert_eq!(
        outer_physical_egress_ifindex(&decision, &state, endpoint, WG_PEER_OUTER_DST),
        12,
        "the first arm returns the PHYSICAL underlay (12) for a \
         dynamic-learned underlay neighbor, NOT the logical wg ifindex (400)"
    );
}

#[test]
fn wg_resolver_stores_zero_tx_ifindex_so_no_tx_fallback_is_possible() {
    // #2837 second leg, refuted: there is no admit-time physical
    // `tx_ifindex` to fall back TO for a WG session. The build zeroes the
    // WG endpoint destination, so `resolve_tunnel_forwarding_resolution`
    // NoRoutes the outer and stores `tx_ifindex = 0` with `egress_ifindex`
    // = the LOGICAL tunnel ifindex. A `tx_ifindex`-based fallback would be
    // dead code; the conservative fallback is the logical ifindex.
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
    // The build zeroed the WG outer destination.
    assert_eq!(
        endpoint.destination,
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        "WG endpoint destination is zeroed by the build (peer carries the hop)"
    );
    let real = resolve_tunnel_forwarding_resolution(&state, None, 1, 0);
    assert_eq!(
        real.disposition,
        ForwardingDisposition::NoRoute,
        "the WG admit-time outer resolution NoRoutes (zeroed destination)"
    );
    assert_eq!(
        real.tx_ifindex, 0,
        "the real WG resolver stores tx_ifindex = 0 — no physical underlay \
         tx_ifindex exists to fall back to"
    );
    assert_eq!(
        real.egress_ifindex, 400,
        "egress_ifindex is the LOGICAL tunnel ifindex"
    );
}

#[test]
fn outer_egress_falls_back_to_logical_when_peer_genuinely_unrouted() {
    // The only case that reaches the fallback: the peer endpoint genuinely
    // has no route (undeliverable). The helper falls back to the LOGICAL
    // egress_ifindex (400) — the conservative pre-#2680/#2701 behaviour. No
    // ifindex choice can rescue an undeliverable packet here.
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let endpoint = state.tunnel_endpoints.get(&1).expect("wg endpoint present");
    let decision = wg_tunnel_decision(400, 1);
    let unrouted = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9));
    assert_eq!(
        outer_physical_egress_ifindex(&decision, &state, endpoint, unrouted),
        400,
        "a genuinely unrouted peer endpoint falls back to the logical ifindex"
    );
}

// === #2701 END-TO-END: `wg_encap_frame` writes the PHYSICAL WAN primary
// into the BUILT outer IP header — the call-site guard, not just the
// helper. ===
//
// The helper tests above prove `outer_physical_egress_ifindex` resolves
// the physical egress, but they do NOT call `wg_encap_frame`: reverting
// ONLY the call-site source lookup (back to
// `forwarding.egress.get(&decision.resolution.egress_ifindex)`) leaves
// them green. These tests close that gap by asserting on the emitted
// outer-IP source bytes of a real built frame, for BOTH outer families.

use crate::afxdp::wg::session::{SessionRole, WgSession};
use crate::afxdp::wg::{WgEngine, WgEngineConfig, WgPeerConfig};
use std::sync::Arc;

fn wg_keypair() -> ([u8; 32], [u8; 32]) {
    let kp = snow::Builder::new(crate::afxdp::wg::WG_NOISE_PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let mut priv_k = [0u8; 32];
    let mut pub_k = [0u8; 32];
    priv_k.copy_from_slice(&kp.private);
    pub_k.copy_from_slice(&kp.public);
    (priv_k, pub_k)
}

/// Build an ESTABLISHED initiator engine whose single peer's endpoint is
/// `peer_ep` (the real outer hop, so `peer_for_dest` returns a concrete
/// destination that the FIB route resolves to the physical egress) and
/// whose AllowedIPs cover `peer_cidr` (so the inner dst LPM-selects it).
/// `try_encap` succeeds because a real Noise IKpsk2 handshake is driven.
fn established_initiator_engine(
    peer_ep: std::net::SocketAddr,
    peer_cidr: &str,
) -> WgEngine {
    let (init_priv, init_pub) = wg_keypair();
    let (resp_priv, resp_pub) = wg_keypair();

    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: Some(peer_ep),
            persistent_keepalive: 0,
            allowed_ips: vec![peer_cidr.parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let resp_engine = WgEngine::new(WgEngineConfig {
        local_private_key: resp_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });

    let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();
    let mut resp_hs = resp_engine.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();
    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let now = crate::afxdp::wg::counters::monotonic_now_ns();
    init_engine
        .install_session(
            &resp_pub,
            Arc::new(WgSession::new_with_role(
                init_xport,
                0xaaaa_0001u32,
                0xbbbb_0001u32,
                resp_pub,
                SessionRole::Initiator,
                now,
            )),
        )
        .unwrap();
    init_engine
}

/// Build an ESTABLISHED initiator/responder PAIR sharing one real Noise
/// handshake. The initiator (returned `.0`) encaps via `wg_encap_frame`;
/// the responder (returned `.1`) can `try_decap` the resulting WG record,
/// recovering the original inner IP packet. Used by the #2792 in-place
/// encrypt byte-identity / round-trip proof: if the in-place encrypt wrote
/// to the wrong slice offset (or the truncation/length math drifted), the
/// decap would fail to authenticate or recover the wrong plaintext.
fn established_pair(
    peer_ep: std::net::SocketAddr,
    peer_cidr: &str,
) -> (WgEngine, WgEngine) {
    let (init_priv, init_pub) = wg_keypair();
    let (resp_priv, resp_pub) = wg_keypair();

    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: Some(peer_ep),
            persistent_keepalive: 0,
            allowed_ips: vec![peer_cidr.parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let resp_engine = WgEngine::new(WgEngineConfig {
        local_private_key: resp_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });

    let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();
    let mut resp_hs = resp_engine.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();
    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
    let now = crate::afxdp::wg::counters::monotonic_now_ns();
    // Initiator: local index 0xaaaa_0001, sends to responder index
    // 0xbbbb_0001 (the value snow stamps into the WG data header as the
    // RECEIVER index). The responder must therefore be reachable in its
    // sessions_by_local_index under 0xbbbb_0001.
    init_engine
        .install_session(
            &resp_pub,
            Arc::new(WgSession::new_with_role(
                init_xport,
                0xaaaa_0001u32,
                0xbbbb_0001u32,
                resp_pub,
                SessionRole::Initiator,
                now,
            )),
        )
        .unwrap();
    resp_engine
        .install_session(
            &init_pub,
            Arc::new(WgSession::new_with_role(
                resp_xport,
                0xbbbb_0001u32,
                0xaaaa_0001u32,
                init_pub,
                SessionRole::Responder,
                now,
            )),
        )
        .unwrap();
    (init_engine, resp_engine)
}

/// A tunnel-resolved decision with the LOGICAL egress_ifindex (400, the
/// `wg0.0` tunnel iface — its primary is the tunnel address 10.123.0.1)
/// and both MACs resolved so `wg_encap_frame` builds rather than dropping
/// on a missing neighbor.
fn wg_encap_decision() -> SessionDecision {
    let mut d = wg_tunnel_decision(400, 1);
    d.resolution.disposition = ForwardingDisposition::ForwardCandidate;
    d.resolution.neighbor_mac = Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    d.resolution.src_mac = Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    d
}

/// Minimal L2/IPv4/UDP inner frame with dst in the WG peer's AllowedIPs
/// (10.123.0.0/24) so `peer_for_dest` selects the established peer.
fn inner_v4_frame() -> Vec<u8> {
    let src_ip = std::net::Ipv4Addr::new(10, 0, 61, 50);
    let dst_ip = std::net::Ipv4Addr::new(10, 123, 0, 9);
    let payload = [0xabu8; 32];
    let total_len = (20 + 8 + payload.len()) as u16;
    let mut frame = Vec::new();
    // eth
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    frame.extend_from_slice(&[0x08, 0x00]);
    // ipv4
    frame.extend_from_slice(&[
        0x45, 0x00,
        (total_len >> 8) as u8, total_len as u8,
        0x00, 0x01, 0x00, 0x00,
        64, PROTO_UDP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    // udp
    frame.extend_from_slice(&4000u16.to_be_bytes());
    frame.extend_from_slice(&5000u16.to_be_bytes());
    frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&payload);
    let ip_sum = crate::afxdp::frame::checksum::checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    frame
}

fn inner_v4_meta() -> ForwardPacketMeta {
    ForwardPacketMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..ForwardPacketMeta::default()
    }
}

#[test]
fn wg_encap_frame_sources_outer_from_physical_wan_primary_v4() {
    // Build the real forwarding state from the shared #2680 fixture:
    // reth0.80 (ifindex 12, primary 172.16.80.8) is the physical egress
    // via the route to the peer endpoint (203.0.113.7); wg0.0
    // (ifindex 400, primary 10.123.0.1) is the LOGICAL tunnel iface.
    let mut state = build_forwarding_state(&wg_outer_mtu_snapshot());
    // Swap in an ESTABLISHED engine (the snapshot one has no session, so
    // try_encap would NoSession) whose peer endpoint == the fixture route
    // target so the FIB resolves to the physical egress (ifindex 12).
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    state
        .wg_engines
        .insert(1, Arc::new(established_initiator_engine(peer_ep, "10.123.0.0/24")));

    let decision = wg_encap_decision();
    let frame = inner_v4_frame();
    let out = wg_encap_frame(&frame, inner_v4_meta(), &decision, &state)
        .expect("wg_encap_frame must build (established session, routed peer)");

    // #5292: the outer now correctly carries reth0.80's VLAN 80 tag (the
    // physical egress the peer routes out of), so the layout is
    // eth(18, 802.1Q) + IPv4(20). Pre-#5292 the frame was emitted UNTAGGED
    // (VLAN read from the zeroed-endpoint `decision.resolution`, VID 0) — that
    // was the bug. The IPv4 source is at bytes 18+12 ..= 18+15 and is sourced
    // from the PHYSICAL WAN primary (172.16.80.8). Reverting the call-site
    // source lookup to the LOGICAL egress_ifindex (400) would write the tunnel
    // address 10.123.0.1 → red.
    assert_eq!(&out[12..14], &[0x81, 0x00], "outer must carry reth0.80's 802.1Q tag");
    assert_eq!(
        u16::from_be_bytes([out[14], out[15]]) & 0x0fff,
        80,
        "outer VLAN must be reth0.80's VID 80 (the peer's physical egress)"
    );
    let outer_src = &out[30..34];
    assert_eq!(
        outer_src,
        &[172, 16, 80, 8],
        "outer IPv4 source must be the PHYSICAL WAN primary (172.16.80.8), \
         not the tunnel-logical address (10.123.0.1) — call-site #2701 guard"
    );
    // Sanity: it is NOT the logical tunnel address.
    assert_ne!(outer_src, &[10, 123, 0, 1], "outer source must not be the tunnel addr");
    // And the destination is the peer endpoint (203.0.113.7).
    assert_eq!(&out[34..38], &[203, 0, 113, 7], "outer dst is the peer endpoint");
}

#[test]
fn wg_encap_frame_resolves_outer_route_once_v4() {
    // #3992 RED-on-revert: `wg_encap_frame` must resolve the outer underlay
    // route (a FIB LPM via `outer_physical_egress_ifindex`) EXACTLY once
    // per encapped packet. Pre-#3992 the outer-MTU guard and the outer IP
    // SOURCE lookup each ran the IDENTICAL resolution (same peer endpoint,
    // same transport table) → 2 FIB LPMs per packet on the encrypt hot
    // path. Reverting the dedup makes this count 2 → red.
    //
    // #6294: `OUTER_ROUTE_RESOLVE_COUNT` is thread-local, so the reset/read
    // window is isolated to THIS test thread — a parallel sibling bumping the
    // counter can no longer corrupt the exact `== 1` assertion (this test no
    // longer relies on `--test-threads=1`). See the counter's doc in `wg.rs`.
    let mut state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    state
        .wg_engines
        .insert(1, Arc::new(established_initiator_engine(peer_ep, "10.123.0.0/24")));
    let decision = wg_encap_decision();
    let frame = inner_v4_frame();

    // Count only the resolutions performed INSIDE wg_encap_frame: reset
    // immediately before the single call, read immediately after.
    outer_route_resolve_count_reset();
    let out = wg_encap_frame(&frame, inner_v4_meta(), &decision, &state)
        .expect("wg_encap_frame must build (established session, routed peer)");
    let resolves = outer_route_resolve_count();
    assert_eq!(
        resolves, 1,
        "wg_encap_frame must resolve the outer underlay route ONCE per \
         packet (got {resolves}; pre-#3992 it resolved twice — MTU guard + \
         outer source)"
    );

    // Byte-identity of the outer header: the single-lookup dedup does NOT
    // change WHICH route is chosen, so the emitted outer L2/L3 header is
    // stable. #5292: the outer now carries reth0.80's VLAN 80 tag, so the
    // layout is eth(18, 802.1Q) + IPv4(20); dst/src MAC in the eth header,
    // TPID @ 12..14, TCI @ 14..16, ethertype @ 16..18, outer src @ 30..34,
    // outer dst @ 34..38, outer UDP dst port @ 40..42.
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], "outer dst MAC unchanged");
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08], "outer src MAC unchanged");
    assert_eq!(&out[12..14], &[0x81, 0x00], "outer 802.1Q TPID");
    assert_eq!(
        u16::from_be_bytes([out[14], out[15]]) & 0x0fff,
        80,
        "outer VLAN = reth0.80 VID 80"
    );
    assert_eq!(&out[16..18], &[0x08, 0x00], "outer ethertype IPv4");
    assert_eq!(
        &out[30..34],
        &[172, 16, 80, 8],
        "outer IPv4 source = PHYSICAL WAN primary (unchanged by the dedup)"
    );
    assert_eq!(&out[34..38], &[203, 0, 113, 7], "outer IPv4 dst = peer endpoint (unchanged)");
    assert_eq!(
        &out[40..42],
        &51820u16.to_be_bytes(),
        "outer UDP dst port = peer endpoint port (unchanged)"
    );
}

/// #6294 fail-on-revert: `OUTER_ROUTE_RESOLVE_COUNT` must be THREAD-LOCAL so
/// that two tests resolving outer routes in parallel cannot corrupt each
/// other's count. Before #6294 the counter was a process-global `AtomicUsize`;
/// under the default parallel `cargo test` a sibling `wg_encap_frame` /
/// `outer_*` test bumping it between `wg_encap_frame_resolves_outer_route_once_v4`'s
/// reset and read made the `== 1` assertion flake.
///
/// This test hammers the counter from two threads that each reset, bump
/// `ITERS` times, then read — concurrently, released from a barrier so their
/// bumps genuinely interleave. A thread-local counter makes each thread
/// observe EXACTLY its own `ITERS` bumps. Reverting the counter to a shared
/// atomic lets the sibling thread's bumps (and its racing reset) leak in, so
/// the per-thread `== ITERS` assertion fails — deterministic red on revert.
#[test]
fn outer_route_resolve_count_is_thread_local_isolated() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    const ITERS: usize = 50_000;
    let start = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let start = start.clone();
        handles.push(thread::spawn(move || {
            // Reset THIS thread's counter, then bump it ITERS times while the
            // sibling thread does the same — synchronized on the barrier so a
            // shared (reverted) counter reliably interleaves.
            outer_route_resolve_count_reset();
            start.wait();
            for _ in 0..ITERS {
                outer_route_resolve_count_bump();
            }
            outer_route_resolve_count()
        }));
    }
    for h in handles {
        let observed = h.join().expect("counter worker panicked");
        assert_eq!(
            observed, ITERS,
            "OUTER_ROUTE_RESOLVE_COUNT must be thread-local: each thread must \
             observe exactly its own {ITERS} bumps (got {observed}); a shared \
             process-global counter leaks the sibling thread's increments and \
             reintroduces the #6294 flake"
        );
    }
}

// === #5292: the outer L2/VLAN must follow the SELECTED peer's physical
// egress, NOT `decision.resolution` (resolved against the zeroed WG endpoint
// destination `0.0.0.0`/`::`, which NoRoutes → blackhole, or matches the WRONG
// default route's adjacency). The outer IP SOURCE already follows the peer
// (#2701); before #5292 the L2 (dst/src MAC) and VLAN were taken from
// `decision.resolution`, so a peer reached via a different underlay than the
// default emitted an internally inconsistent frame (peer source IP on the
// default route's L2/VLAN) or blackholed. ===

/// A tunnel-resolved decision whose stored resolution carries the WRONG
/// adjacency — mimicking the zeroed-endpoint admission resolving against a
/// default route on a DIFFERENT interface/VLAN: a bogus neighbor MAC, a bogus
/// source MAC, and VLAN 50 (not reth0.80's VID 80), plus the LOGICAL wg
/// egress_ifindex the resolver actually stores.
fn wg_decision_with_wrong_default_adjacency() -> SessionDecision {
    let mut d = wg_tunnel_decision(400, 1);
    d.resolution.disposition = ForwardingDisposition::ForwardCandidate;
    d.resolution.neighbor_mac = Some([0xde, 0xad, 0xde, 0xad, 0xde, 0xad]);
    d.resolution.src_mac = Some([0xba, 0xd0, 0xba, 0xd0, 0xba, 0xd0]);
    d.resolution.tx_vlan_id = 50;
    d
}

#[test]
fn wg_encap_outer_l2_vlan_follows_selected_peer_not_zeroed_decision() {
    // #5292 RED-on-revert: the emitted outer dst MAC, src MAC, and VLAN must
    // come from the SELECTED peer's physical egress (reth0.80, ifindex 12: src
    // MAC 02:bf:72:00:50:08, VLAN 80, next-hop 172.16.80.1), NOT the wrong
    // default-route adjacency stored on `decision.resolution`. Reverting any of
    // dst_mac/src_mac/vlan back to `decision.resolution` fails this red.
    let mut state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    state
        .wg_engines
        .insert(1, Arc::new(established_initiator_engine(peer_ep, "10.123.0.0/24")));
    // Static neighbor for the peer's outer next-hop so the outer route resolves
    // a real dst MAC (distinct from the wrong decision.resolution neighbor).
    const PEER_NEXTHOP_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    state.neighbors.insert(
        (12, IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 80, 1))),
        crate::afxdp::types::NeighborEntry { mac: PEER_NEXTHOP_MAC },
    );

    let decision = wg_decision_with_wrong_default_adjacency();
    let out = wg_encap_frame(&inner_v4_frame(), inner_v4_meta(), &decision, &state)
        .expect("wg_encap_frame must build against the SELECTED peer's underlay");

    // Outer eth (802.1Q): dst[0..6], src[6..12], TPID[12..14]=0x8100,
    // TCI[14..16] (VID low 12 bits), ethertype[16..18].
    assert_eq!(
        &out[0..6], &PEER_NEXTHOP_MAC,
        "outer dst MAC must be the SELECTED peer's outer next-hop neighbor, \
         not the zeroed-endpoint decision's default neighbor (de:ad:..)"
    );
    assert_eq!(
        &out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08],
        "outer src MAC must be the peer's physical egress reth0.80, not the \
         decision's default-route src MAC (ba:d0:..)"
    );
    assert_eq!(&out[12..14], &[0x81, 0x00], "outer must be 802.1Q VLAN-tagged");
    assert_eq!(
        u16::from_be_bytes([out[14], out[15]]) & 0x0fff,
        80,
        "outer VLAN must be the peer's physical egress VID 80 (reth0.80), not \
         the decision's wrong VLAN 50"
    );
    assert_eq!(&out[16..18], &[0x08, 0x00], "outer ethertype IPv4");
    // The outer IP source + dst prove the L2/VLAN and L3 are now consistent:
    // same physical egress (172.16.80.8) toward the same peer (203.0.113.7).
    assert_eq!(&out[30..34], &[172, 16, 80, 8], "outer IPv4 source = physical WAN primary");
    assert_eq!(&out[34..38], &[203, 0, 113, 7], "outer IPv4 dst = peer endpoint");
}

#[test]
fn wg_encap_builds_when_zeroed_decision_has_no_l2() {
    // #5292 RED-on-revert (the NoRoute-blackhole leg): even when the stored
    // `decision.resolution` carries NO usable L2 (neighbor_mac = None,
    // src_mac = None, VLAN 0 — exactly what the zeroed-endpoint admission
    // produces when 0.0.0.0/:: has no default route), the builder must still
    // resolve the peer's underlay and emit a valid frame — NOT drop. Pre-#5292
    // `decision.resolution.neighbor_mac?` / `src_mac?` short-circuited to None
    // (drop) — the blackhole. Reverting reintroduces the drop → `.expect()`
    // panics → red.
    let mut state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    state
        .wg_engines
        .insert(1, Arc::new(established_initiator_engine(peer_ep, "10.123.0.0/24")));
    const PEER_NEXTHOP_MAC: [u8; 6] = [0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f];
    state.neighbors.insert(
        (12, IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 80, 1))),
        crate::afxdp::types::NeighborEntry { mac: PEER_NEXTHOP_MAC },
    );

    // The blackhole shape: the admit-time resolution NoRoute'd the zeroed
    // endpoint, so it carries no L2 and the logical wg egress_ifindex.
    let mut decision = wg_tunnel_decision(400, 1);
    decision.resolution.disposition = ForwardingDisposition::ForwardCandidate;
    decision.resolution.neighbor_mac = None;
    decision.resolution.src_mac = None;
    decision.resolution.tx_vlan_id = 0;

    let out = wg_encap_frame(&inner_v4_frame(), inner_v4_meta(), &decision, &state)
        .expect("wg_encap_frame must build against the peer even when the \
                 zeroed-endpoint decision.resolution has no L2 (no blackhole)");

    // The emitted L2/VLAN is the peer's physical egress, recovered entirely
    // from the peer route (decision.resolution contributed nothing usable).
    assert_eq!(&out[0..6], &PEER_NEXTHOP_MAC, "dst MAC recovered from the peer route");
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08], "src MAC = reth0.80");
    assert_eq!(
        u16::from_be_bytes([out[14], out[15]]) & 0x0fff,
        80,
        "VLAN recovered from the peer's physical egress (VID 80)"
    );
}

// === #6308: the WG transit-egress TX DISPATCH must target the SELECTED peer's
// PHYSICAL egress NIC — the SAME physical egress #5292 resolved the frame BYTES
// against — even when the WG transport table carries ONLY a specific peer route
// and NO default route. The zeroed WG endpoint destination (#2837) resolves to
// tx_ifindex = 0 / egress_ifindex = the LOGICAL wgN ifindex, so the pre-#6308
// dispatch fallback `resolve_tx_binding_ifindex(logical wgN)` returned the
// logical ifindex (no XSK binding) and the TX dispatcher NO_EGRESS_BINDING-
// dropped a correctly-built frame. ===

#[test]
fn wg_transit_egress_dispatch_specific_peer_no_default_6308() {
    // The shared #2680 fixture is EXACTLY the #6308 scenario: the WG transport
    // table (inet.0) has ONLY the specific peer route 203.0.113.0/24 → reth0.80
    // (ifindex 12) and NO default route. Sanity-assert the no-default
    // precondition so the test can't silently stop exercising it.
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    assert!(
        state
            .routes_v4
            .values()
            .flatten()
            .all(|r| r.prefix.prefix_len() != 0),
        "fixture must carry NO default route (the #6308 specific-peer-route + \
         no-default-route case)"
    );

    // The resolution the SSOT actually stores for this flow (zeroed WG endpoint
    // destination → NoRoute for 0.0.0.0): tx_ifindex = 0, egress_ifindex = the
    // logical wgN ifindex (400).
    let decision = wg_tunnel_decision(400, 1);
    assert_eq!(
        decision.resolution.tx_ifindex, 0,
        "no-default-route WG resolution stores tx_ifindex 0"
    );
    assert_eq!(
        decision.resolution.egress_ifindex, 400,
        "WG resolution stores the LOGICAL wgN egress ifindex"
    );

    let frame = inner_v4_frame(); // dst 10.123.0.9 ∈ AllowedIPs 10.123.0.0/24
    let meta = inner_v4_meta();

    // The peer-route physical-egress SSOT resolves reth0.80 (ifindex 12) — the
    // SAME physical egress #5292 resolves the frame bytes against — NOT the
    // logical wgN ifindex (400).
    assert_eq!(
        wg_transit_egress_physical_egress_ifindex(
            &decision,
            &state,
            &frame,
            meta.addr_family,
            meta.l3_offset,
        ),
        Some(12),
        "WG dispatch must resolve the SELECTED peer's physical egress \
         (reth0.80 ifindex 12), not the logical wgN ifindex (400)"
    );

    // The DISPATCH target the TX dispatcher looks up an XSK binding for: the
    // physical PARENT NIC of reth0.80 (bind_ifindex, which HAS a binding), NOT
    // the logical wgN 400 (which does not → NO_EGRESS_BINDING drop).
    let expected_physical_bind = state
        .egress
        .get(&12)
        .map(|e| e.bind_ifindex)
        .expect("reth0.80 egress row present");
    let target = crate::afxdp::forward_request::resolve_forward_target_ifindex(
        &decision,
        &state,
        &frame,
        meta.addr_family,
        meta.l3_offset,
    );
    assert_eq!(
        target, expected_physical_bind,
        "dispatch must target reth0.80's physical parent NIC \
         (bind_ifindex {expected_physical_bind})"
    );
    assert_ne!(
        target, 400,
        "dispatch must NOT target the logical wgN ifindex (400) — the pre-#6308 \
         fallback that has no XSK binding and NO_EGRESS_BINDING-drops the frame"
    );

    // Common case (no regression): a WG transport table WITH a default route
    // resolves tx_ifindex > 0 (the default egress bind ifindex = the physical
    // WAN parent). In a SINGLE-underlay config the peer route resolves to that
    // same physical parent, so dispatch is unchanged (#6345 made the peer route
    // authoritative on this branch too — same NIC, same answer). Simulate the
    // resolved decision and assert dispatch returns it unchanged.
    let mut default_route_decision = decision;
    default_route_decision.resolution.tx_ifindex = expected_physical_bind;
    assert_eq!(
        crate::afxdp::forward_request::resolve_forward_target_ifindex(
            &default_route_decision,
            &state,
            &frame,
            meta.addr_family,
            meta.l3_offset,
        ),
        expected_physical_bind,
        "default-route WG flow (tx_ifindex > 0) must dispatch to the default \
         egress verbatim — the common case is unchanged"
    );

    // A non-WG (plain-forward) decision must NOT trigger the WG dispatch
    // resolution: the helper returns None so the caller keeps the pre-#6308
    // logical fallback for every non-tunnel flow.
    let mut plain = decision;
    plain.resolution.tunnel_endpoint_id = 0;
    plain.resolution.egress_ifindex = 12;
    plain.resolution.tx_ifindex = 0;
    assert_eq!(
        wg_transit_egress_physical_egress_ifindex(
            &plain,
            &state,
            &frame,
            meta.addr_family,
            meta.l3_offset,
        ),
        None,
        "a non-WG decision must not trigger the WG dispatch resolution"
    );
}

/// #6340: an engine with TWO cryptokey-routed peers on ONE wg interface, each
/// covering a DISTINCT AllowedIPs prefix that routes to a DISTINCT physical
/// underlay egress. `peer_for_dest` (the encap + dispatch peer selector) reads
/// the AllowedIPs trie + per-peer endpoint from config alone — no transport
/// session is required to resolve WHICH physical NIC a dst egresses — so this
/// builds the two peers without driving a handshake (the function under test
/// routes, it does not encrypt). Peer A: 10.123.0.0/24 → 203.0.113.7 (reth0.80);
/// peer B: 10.200.0.0/24 → 198.51.100.7 (reth0.50).
fn two_peer_config_engine() -> WgEngine {
    let (local_priv, _local_pub) = wg_keypair();
    let (_a_priv, a_pub) = wg_keypair();
    let (_b_priv, b_pub) = wg_keypair();
    WgEngine::new(WgEngineConfig {
        local_private_key: local_priv.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: a_pub,
                endpoint: Some("203.0.113.7:51820".parse().unwrap()),
                persistent_keepalive: 0,
                allowed_ips: vec!["10.123.0.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: b_pub,
                endpoint: Some("198.51.100.7:51820".parse().unwrap()),
                persistent_keepalive: 0,
                allowed_ips: vec!["10.200.0.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            },
        ],
    })
}

#[test]
fn wg_transit_egress_dispatch_follows_post_nat_peer_6308() {
    // #6340: the #6308 DNAT SSOT hole. A WG transit-egress flow where DNAT
    // rewrites the inner dst ACROSS two AllowedIPs peers that live on DISTINCT
    // physical underlay egresses. The encap builder applies DNAT into `out`
    // BEFORE `wg_encap_frame` selects the peer from the POST-NAT dst
    // (`inner_dst_ip(&out)`); DISPATCH must resolve the SAME (post-NAT) peer's
    // physical NIC, not the PRE-NAT peer's — otherwise dispatch targets one
    // NIC while the bytes carry the other peer's L2 (a wire mismatch).
    let mut state = build_forwarding_state(&wg_two_peer_dnat_snapshot());
    state
        .wg_engines
        .insert(1, Arc::new(two_peer_config_engine()));

    // The two peers really do resolve to DISTINCT physical egresses / binds.
    let peer_a_egress = 12; // reth0.80
    let peer_b_egress = 13; // reth0.50
    let bind_a = state
        .egress
        .get(&peer_a_egress)
        .map(|e| e.bind_ifindex)
        .expect("reth0.80 egress row present");
    let bind_b = state
        .egress
        .get(&peer_b_egress)
        .map(|e| e.bind_ifindex)
        .expect("reth0.50 egress row present");
    assert_ne!(
        bind_a, bind_b,
        "the two peers must live on DISTINCT physical NICs for this test to \
         distinguish pre- vs post-NAT dispatch"
    );

    // Ingress (PRE-NAT) frame: inner dst 10.123.0.9 ∈ peer A's AllowedIPs
    // (10.123.0.0/24). DNAT rewrites it to 10.200.0.9 ∈ peer B's AllowedIPs
    // (10.200.0.0/24) — a DIFFERENT physical underlay.
    let frame = inner_v4_frame(); // dst 10.123.0.9 (peer A)
    let meta = inner_v4_meta();
    let mut decision = wg_tunnel_decision(400, 1);
    decision.nat.rewrite_dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 0, 9)));

    // Baseline (no DNAT): the un-rewritten frame egresses peer A (reth0.80,
    // ifindex 12). Proves the fixture selects A on the pre-NAT dst so the
    // post-NAT assertion below is meaningful (not a fixture that always
    // resolves B).
    let mut no_nat = decision;
    no_nat.nat.rewrite_dst = None;
    assert_eq!(
        wg_transit_egress_physical_egress_ifindex(
            &no_nat,
            &state,
            &frame,
            meta.addr_family,
            meta.l3_offset,
        ),
        Some(peer_a_egress),
        "without DNAT the frame egresses peer A (reth0.80 ifindex 12)"
    );

    // The fix: DISPATCH follows the POST-NAT dst → peer B's physical egress
    // (reth0.50, ifindex 13) — the SAME NIC `wg_encap_frame` emits bytes for
    // (it reads `inner_dst_ip(&out)` on the DNAT'd `out`). Reverting the fold
    // (select from the pre-NAT frame dst) resolves peer A (12) → RED.
    assert_eq!(
        wg_transit_egress_physical_egress_ifindex(
            &decision,
            &state,
            &frame,
            meta.addr_family,
            meta.l3_offset,
        ),
        Some(peer_b_egress),
        "DNAT-across-peers: dispatch must follow the POST-NAT dst to peer B's \
         physical egress (reth0.50 ifindex 13), NOT the pre-NAT peer A (12)"
    );

    // And the full dispatch target (the XSK bind ifindex the TX dispatcher
    // looks up) is peer B's physical bind, not peer A's.
    let target = crate::afxdp::forward_request::resolve_forward_target_ifindex(
        &decision,
        &state,
        &frame,
        meta.addr_family,
        meta.l3_offset,
    );
    assert_eq!(
        target, bind_b,
        "dispatch must target peer B's physical bind ({bind_b})"
    );
    assert_ne!(
        target, bind_a,
        "dispatch must NOT target the pre-NAT peer A's physical bind ({bind_a})"
    );
}

/// Minimal L2/IPv6/UDP inner frame with dst in `fd00:123::/64` so
/// `peer_for_dest` selects the v6-endpoint peer.
fn inner_v6_frame() -> Vec<u8> {
    let src_ip: std::net::Ipv6Addr = "fd00:61::50".parse().unwrap();
    let dst_ip: std::net::Ipv6Addr = "fd00:123::9".parse().unwrap();
    let payload = [0xabu8; 32];
    let payload_len = (8 + payload.len()) as u16; // UDP header + data
    let mut frame = Vec::new();
    // eth
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    frame.extend_from_slice(&[0x86, 0xdd]);
    // ipv6: version/tc/flow, payload len, next header (UDP), hop limit
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.push(PROTO_UDP);
    frame.push(64);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    // udp
    frame.extend_from_slice(&4000u16.to_be_bytes());
    frame.extend_from_slice(&5000u16.to_be_bytes());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn inner_v6_meta() -> ForwardPacketMeta {
    ForwardPacketMeta {
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        ..ForwardPacketMeta::default()
    }
}

#[test]
fn wg_encap_frame_sources_outer_from_physical_wan_primary_v6() {
    // Clone the shared fixture and extend it with an IPv6 WAN primary on
    // reth0.80 + a v6 route to a v6 peer endpoint, so the outer family is
    // IPv6 and the physical egress (ifindex 12) carries a v6 primary
    // (2001:559:8585:80::8) distinct from the logical wg0.0 v6 address.
    let mut snap = wg_outer_mtu_snapshot();
    // reth0.80 gets the WAN v6 primary; wg0.0 gets a tunnel v6 address.
    snap.interfaces[0].addresses.push(crate::InterfaceAddressSnapshot {
        family: "inet6".to_string(),
        address: "2001:559:8585:80::8/64".to_string(),
        scope: 0,
    });
    snap.interfaces[1].addresses.push(crate::InterfaceAddressSnapshot {
        family: "inet6".to_string(),
        address: "fd00:dead::1/64".to_string(),
        scope: 0,
    });
    // v6 route to the peer endpoint prefix, egressing reth0.80.
    snap.routes.push(crate::RouteSnapshot {
        table: "inet6.0".to_string(),
        family: "inet6".to_string(),
        destination: "2001:db8:113::/48".to_string(),
        next_hops: vec!["2001:559:8585:80::1@reth0.80".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
        rule_priority: 0,
    });
    // The WG endpoint's transport table follows the v6 outer family.
    snap.tunnel_endpoints[0].outer_family = "inet6".to_string();
    snap.tunnel_endpoints[0].transport_table = "inet6.0".to_string();
    snap.tunnel_endpoints[0].source = "2001:559:8585:80::8".to_string();
    snap.tunnel_endpoints[0].destination = "2001:db8:113::7".to_string();
    snap.tunnel_endpoints[0].wg_peers[0].wg_allowed_ips = vec!["fd00:123::/64".to_string()];
    snap.tunnel_endpoints[0].wg_peers[0].wg_endpoint = "[2001:db8:113::7]:51820".to_string();

    let mut state = build_forwarding_state(&snap);
    let peer_ep: std::net::SocketAddr = "[2001:db8:113::7]:51820".parse().unwrap();
    state
        .wg_engines
        .insert(1, Arc::new(established_initiator_engine(peer_ep, "fd00:123::/64")));

    let decision = wg_encap_decision();
    let frame = inner_v6_frame();
    let out = wg_encap_frame(&frame, inner_v6_meta(), &decision, &state)
        .expect("wg_encap_frame must build a v6 outer (established session, routed peer)");

    // #5292: the outer now carries reth0.80's VLAN 80 tag, so the layout is
    // eth(18, 802.1Q) + IPv6(40). The IPv6 source is at bytes 18+8 ..= 18+23,
    // i.e. out[26..42]. It must be the PHYSICAL WAN v6 primary. Reverting the
    // call-site lookup to the LOGICAL ifindex (400) would write the tunnel v6
    // address (fd00:dead::1) → red.
    assert_eq!(&out[12..14], &[0x81, 0x00], "outer must carry reth0.80's 802.1Q tag");
    assert_eq!(
        u16::from_be_bytes([out[14], out[15]]) & 0x0fff,
        80,
        "outer VLAN must be reth0.80's VID 80"
    );
    assert_eq!(&out[16..18], &[0x86, 0xdd], "outer ethertype IPv6");
    let expected: std::net::Ipv6Addr = "2001:559:8585:80::8".parse().unwrap();
    let tunnel_addr: std::net::Ipv6Addr = "fd00:dead::1".parse().unwrap();
    assert_eq!(
        &out[26..42],
        &expected.octets(),
        "outer IPv6 source must be the PHYSICAL WAN v6 primary, not the tunnel-logical address"
    );
    assert_ne!(&out[26..42], &tunnel_addr.octets());
    // Destination is the v6 peer endpoint.
    let dst: std::net::Ipv6Addr = "2001:db8:113::7".parse().unwrap();
    assert_eq!(&out[42..58], &dst.octets(), "outer v6 dst is the peer endpoint");
}

#[test]
fn wg_encap_in_place_matches_separate_buffer() {
    // #2792 correctness lock: the in-place encrypt (the WG record is
    // written DIRECTLY into the output frame's UDP payload slot, removing
    // the pre-#2792 intermediate `wg_record` Vec + copy) must produce a
    // frame whose WG record (a) sits at the exact UDP payload offset, (b)
    // is the exact pad-aware record length, and (c) decrypts back to the
    // ORIGINAL inner IP packet under the paired peer's transport. A revert
    // that wrote the encrypt to the wrong offset, mis-sized the buffer, or
    // truncated incorrectly fails the decap (auth/length) → red.
    let mut state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    let (init_engine, resp_engine) = established_pair(peer_ep, "10.123.0.0/24");
    state.wg_engines.insert(1, Arc::new(init_engine));

    let decision = wg_encap_decision();
    let frame = inner_v4_frame();
    // The inner IP packet the encap path actually encrypts: strip L2,
    // trim to the IP total-length (mirrors wg_encap_frame's own slicing).
    let inner_l3 = 14usize;
    let inner_packet = &frame[inner_l3..];
    let inner_len =
        crate::afxdp::gre::packet_trimmed_len(inner_packet, libc::AF_INET as u8).unwrap();
    let expected_inner = inner_packet[..inner_len].to_vec();

    let out = wg_encap_frame(&frame, inner_v4_meta(), &decision, &state)
        .expect("wg_encap_frame must build (established session, routed peer)");

    // Outer framing: #5292 tags reth0.80's VLAN 80, so eth(18, 802.1Q) +
    // IPv4(20) + UDP(8) = 46-byte payload offset.
    let payload_start = 18 + 20 + 8;
    // The WG record is the remainder of the frame. Its length must be the
    // exact pad-aware record size (header + pad_to_16(inner) + tag).
    let expected_record_len =
        WG_DATA_HEADER_LEN + pad_to_16(expected_inner.len()) + POLY1305_TAG_LEN;
    let wg_record = &out[payload_start..];
    assert_eq!(
        wg_record.len(),
        expected_record_len,
        "in-place encrypt must leave exactly the pad-aware WG record at the UDP payload offset"
    );

    // Round-trip: the paired responder must decrypt the in-place-written
    // record back to the ORIGINAL inner IP packet. This proves the
    // ciphertext+tag landed at the correct offset and the framing is
    // byte-faithful to the pre-#2792 separate-buffer path.
    let mut recovered = vec![0u8; expected_record_len];
    let dec = resp_engine
        .try_decap(wg_record, &mut recovered)
        .expect("paired responder must authenticate the in-place WG record");
    assert_eq!(
        &recovered[..dec.len],
        &expected_inner[..],
        "decapped plaintext must equal the original inner IP packet (in-place encrypt is byte-faithful)"
    );

    // Outer total-length fields must agree with the truncated frame size
    // (the truncation math, not the max-sized scratch, drives the wire).
    // IPv4 total-length @ 18+2..18+4 (eth 18 incl. VLAN tag); UDP length @
    // 18+20+4..18+20+6.
    let ip_total = u16::from_be_bytes([out[20], out[21]]) as usize;
    assert_eq!(ip_total, 20 + 8 + expected_record_len, "IPv4 total length tracks the real record");
    let udp_len = u16::from_be_bytes([out[42], out[43]]) as usize;
    assert_eq!(udp_len, 8 + expected_record_len, "UDP length tracks the real record");
    assert_eq!(out.len(), payload_start + expected_record_len, "frame truncated to the real size");
}

#[test]
fn wg_mtu_guard_drops_oversize_inner() {
    // At a 1500-byte v4 outer MTU the largest inner that fits is
    // 1500 - 20 - 8 - 16 - 16 = 1440, padded to a 16-multiple. A
    // 1441-byte inner pads to 1456 and overflows.
    let mtu = 1500usize;
    assert!(
        wg_encapped_size(1440, false) <= mtu,
        "1440-byte inner must fit a 1500 v4 outer MTU"
    );
    assert!(
        wg_encapped_size(1441, false) > mtu,
        "1441-byte inner (pads to 1456) must overflow and be dropped"
    );
}

// === #2651: the WG IPv6 outer UDP checksum optimization. The
// production path swapped the scalar word-at-a-time `udp6_checksum`
// loop for the AVX2-backed `checksum16_ipv6` helper. These tests prove
// the swap is byte-identical on the wire and lock the output so a
// future regression in the optimized path is caught. ===

/// A small deterministic xorshift PRNG — no external `rand` dependency,
/// matching the multiply-hash style used by the `checksum.rs` tests.
/// Seeded for reproducibility; the parity property is exercised over a
/// wide, fixed sweep of sizes and contents.
struct Xorshift64(u64);
impl Xorshift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = (self.next_u64() & 0xff) as u8;
        }
    }
}

#[test]
fn udp6_checksum_matches_scalar_reference() {
    // Property: the optimized helper equals the independent scalar
    // one's-complement reference for EVERY input. Sweep lengths from 8
    // (a bare UDP header) through a jumbo payload, hitting every
    // odd/even boundary (odd-length tail handling) and many random
    // contents per length, across multiple distinct src/dst pairs.
    let mut rng = Xorshift64(0x2651_5151_a5a5_1234);
    let addr_pairs = [
        (
            std::net::Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200),
            std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0xdead, 0xbeef, 0, 1),
        ),
        (std::net::Ipv6Addr::UNSPECIFIED, std::net::Ipv6Addr::LOCALHOST),
        (
            std::net::Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
            std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        ),
    ];
    // The udp slice MUST be at least 8 bytes (UDP header). Sweep every
    // length in [8, 1500] plus a few large sizes for carry stress.
    let mut lengths: Vec<usize> = (8..=1500).collect();
    lengths.extend_from_slice(&[2048, 4096, 9000, 65000]);
    for &len in &lengths {
        for &(src, dst) in &addr_pairs {
            let mut udp = vec![0u8; len];
            rng.fill(&mut udp);
            // Zero the checksum field (bytes 6..8) as the production
            // path does before summing.
            udp[6] = 0;
            udp[7] = 0;
            let reference = udp6_checksum_scalar_reference(src, dst, &udp);
            let optimized = udp6_checksum_optimized(src, dst, &udp);
            assert_eq!(
                optimized, reference,
                "len={len} src={src} dst={dst}: optimized UDPv6 checksum \
                 diverged from the scalar reference"
            );
            // RFC 768 / RFC 8200: the transmitted UDPv6 checksum is
            // MANDATORY and must never be 0x0000 on the wire.
            assert_ne!(
                optimized, 0,
                "UDPv6 checksum must never be transmitted as 0x0000"
            );
        }
    }
}

#[test]
fn udp6_checksum_canonicalizes_zero_sum_to_ffff() {
    // Construct a UDP datagram + pseudo-header whose one's-complement
    // sum is 0xFFFF, so the raw complement is 0x0000 and MUST be
    // emitted as 0xFFFF. The simplest construction: an all-zero
    // pseudo-header (UNSPECIFIED src/dst, next-header byte 0 via... no
    // — next-header is fixed to UDP). Instead drive a payload whose
    // sum cancels the pseudo-header contribution. We brute-force a
    // tiny 2-byte tail so the raw sum hits 0xFFFF.
    let src = std::net::Ipv6Addr::UNSPECIFIED;
    let dst = std::net::Ipv6Addr::UNSPECIFIED;
    // Minimal 8-byte UDP header, checksum field zeroed; the pseudo-
    // header contributes len(8) + next-header(17 = PROTO_UDP). We want
    // the total one's-complement sum == 0xFFFF (-> complement 0x0000).
    // src_port + dst_port + udp_len(8) + 0(csum) + pseudo(len 8 +
    // proto 17) — choose ports so the folded sum is exactly 0xFFFF.
    let mut udp = vec![0u8; 8];
    udp[4] = 0;
    udp[5] = 8; // UDP length field = 8
    // pseudo-header sum so far: 8 (payload-len-u32 low) + 17 (proto)
    //   + udp_len field 8 = 33. Need ports summing to 0xFFFF - 33.
    let want: u32 = 0xffff - 33;
    let p0 = (want >> 16) as u16; // 0 here
    let _ = p0;
    let src_port = (want & 0xffff) as u16;
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    // dst_port left 0.
    let reference = udp6_checksum_scalar_reference(src, dst, &udp);
    let optimized = udp6_checksum_optimized(src, dst, &udp);
    assert_eq!(
        reference, 0xffff,
        "fixture must drive the raw complement to 0x0000 (emitted as 0xFFFF)"
    );
    assert_eq!(
        optimized, 0xffff,
        "optimized path must canonicalize a 0x0000 raw checksum to 0xFFFF"
    );
}

#[test]
fn udp6_checksum_locked_value_for_known_frame() {
    // FAIL-ON-REVERT: lock the exact wire checksum for a fixed WG IPv6
    // outer UDP datagram. Any divergence in the optimized helper (e.g.
    // a perturbed pseudo-header layout or a dropped odd-tail byte)
    // flips this constant and the test goes red. The literal below is
    // the value computed by the byte-identical scalar reference for
    // this exact input.
    let src = std::net::Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x8);
    let dst = std::net::Ipv6Addr::new(0x2001, 0x559, 0x8585, 0x80, 0, 0, 0, 0x200);
    // A 13-byte UDP datagram (8-byte header + 5-byte payload) — ODD
    // total length, so the odd-tail path is exercised. src_port 51820
    // (WG default), dst_port 51820, length 13, checksum field zeroed,
    // payload 0xDE 0xAD 0xBE 0xEF 0x42.
    let mut udp = vec![0u8; 13];
    udp[0..2].copy_from_slice(&51820u16.to_be_bytes());
    udp[2..4].copy_from_slice(&51820u16.to_be_bytes());
    udp[4..6].copy_from_slice(&13u16.to_be_bytes());
    // bytes 6..8 = checksum = 0
    udp[8..13].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x42]);
    let reference = udp6_checksum_scalar_reference(src, dst, &udp);
    let optimized = udp6_checksum_optimized(src, dst, &udp);
    // The two must agree (cross-check), and both must equal the locked
    // literal. If a future edit perturbs the optimized impl, optimized
    // != reference fails first; if both drift together (impossible for
    // a one's-complement sum), the literal lock catches it.
    assert_eq!(optimized, reference, "optimized must match the scalar reference");
    assert_eq!(
        optimized, LOCKED_WG_UDP6_CHECKSUM,
        "the WG IPv6 outer UDP checksum for the fixed known frame changed — \
         a regression in the optimized checksum path"
    );
}

/// Locked wire checksum for the `udp6_checksum_locked_value_for_known_frame`
/// fixture. Derived from the byte-identical scalar one's-complement
/// reference; a change here means the on-wire checksum changed.
const LOCKED_WG_UDP6_CHECKSUM: u16 = 0x3296;

// === #6345: the `tx_ifindex > 0` dispatch branch must ALSO follow the selected
// peer's physical egress. #6308 fixed only the `tx_ifindex == 0` branch, so a
// WG transit-egress flow whose transport table DOES carry a default route kept
// dispatching to the DEFAULT-route parent while `wg_encap_frame` built the
// outer L2/VLAN/src against the SELECTED PEER's more-specific route (#6306).
// With one underlay both are the same NIC; with several the frame went out one
// NIC carrying another segment's source MAC and VLAN. ===

#[test]
fn wg_transit_egress_dispatch_follows_peer_route_over_tx_ifindex_6345() {
    let mut state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    state
        .wg_engines
        .insert(1, Arc::new(established_initiator_engine(peer_ep, "10.123.0.0/24")));

    let frame = inner_v4_frame(); // dst 10.123.0.9 ∈ AllowedIPs 10.123.0.0/24
    let meta = inner_v4_meta();

    // The peer's physical egress: reth0.80 (ifindex 12) → its parent NIC.
    let peer_bind = state
        .egress
        .get(&12)
        .map(|e| e.bind_ifindex)
        .expect("reth0.80 egress row present");

    // The multi-underlay shape: the WG transport table also has a DEFAULT route,
    // and it resolves to a DIFFERENT physical NIC than the peer's specific
    // route. That is exactly what the stored resolution carries as
    // `tx_ifindex > 0`.
    const OTHER_UNDERLAY_BIND: i32 = 77;
    assert_ne!(
        peer_bind, OTHER_UNDERLAY_BIND,
        "premise: the two underlays must be distinguishable"
    );
    let mut decision = wg_tunnel_decision(400, 1);
    decision.resolution.tx_ifindex = OTHER_UNDERLAY_BIND;

    let target = crate::afxdp::forward_request::resolve_forward_target_ifindex(
        &decision,
        &state,
        &frame,
        meta.addr_family,
        meta.l3_offset,
    );
    assert_eq!(
        target, peer_bind,
        "dispatch must target the SELECTED PEER's physical egress ({peer_bind}) —          the same NIC wg_encap_frame builds the outer L2/VLAN/src against"
    );
    assert_ne!(
        target, OTHER_UNDERLAY_BIND,
        "dispatch followed the DEFAULT-route parent ({OTHER_UNDERLAY_BIND}) while the          frame bytes carry the peer route's egress — the frame leaves one NIC          carrying another segment's source MAC and VLAN (#6345)"
    );
}

#[test]
fn non_wg_forward_keeps_the_tx_ifindex_fast_path_6345() {
    // Anti-over-reject: #6345 must not change a plain (non-tunnel) forward. The
    // resolver's first act is `tunnel_endpoint_id == 0 -> None`, so such a flow
    // still takes `tx_ifindex` verbatim — asserting this pins the fast path a
    // future refactor could quietly route through the peer resolution.
    let state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let frame = inner_v4_frame();
    let meta = inner_v4_meta();

    let mut decision = wg_tunnel_decision(400, 1);
    decision.resolution.tunnel_endpoint_id = 0; // a plain forward
    decision.resolution.tx_ifindex = 77;

    assert_eq!(
        crate::afxdp::forward_request::resolve_forward_target_ifindex(
            &decision,
            &state,
            &frame,
            meta.addr_family,
            meta.l3_offset,
        ),
        77,
        "a non-tunnel forward must take tx_ifindex verbatim"
    );
}

// === #7167: the tunnel-kind DISPATCHER's WireGuard arm ===

/// FAIL-ON-REVERT for the WIRING, not the builder.
///
/// Every other WireGuard encap cell in this file calls `wg_encap_frame`
/// DIRECTLY. None of them drives `build_forwarded_frame_from_frame`, so none
/// of them can see the `match kind { Some(TunnelKind::WireGuard) => ... }` arm
/// in `frame/mod.rs` that actually reaches it. Deleting that arm leaves this
/// file's other 20+ WG cells green while every WireGuard packet on the box
/// falls to the #2327 fail-closed `None` and is silently dropped. Native GRE
/// has had `build_forwarded_frame_from_frame_encapsulates_native_gre` guarding
/// its arm of the same `match` since #2327; WireGuard had no counterpart.
///
/// This matters beyond the missing cell. #7167's adjudication rests on the
/// fact that WireGuard ENCAPSULATION already runs inside the AF_XDP worker,
/// post-adjudication, while DECAPSULATION runs in the control thread with no
/// adjudication at all — the asymmetry IS the defect, and the reason the fix
/// is "move decap to the side that already does encap" rather than "build a
/// bounded cross-thread packet handoff". If this arm were ever removed or
/// re-pointed, that argument would rot silently, exactly the way this issue's
/// other premises did (`docs/research/7167-tunnel-ingress/adjudication.md`).
///
/// Asserted STRUCTURALLY rather than by comparing against `wg_encap_frame`'s
/// own output: WireGuard encap is not deterministic (each call consumes a
/// fresh nonce counter and produces different ciphertext), so a byte-equality
/// pairing would fail for a reason that has nothing to do with the wiring.
/// The properties below are ones ONLY a WireGuard encapsulation has — the
/// sibling GRE arm of the same `match` emits IP protocol 47 with no UDP
/// header and no type-4 record, so re-pointing the arm reds here too.
#[test]
fn build_forwarded_frame_from_frame_encapsulates_wireguard_7167() {
    let mut state = build_forwarding_state(&wg_outer_mtu_snapshot());
    let peer_ep: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
    state
        .wg_engines
        .insert(1, Arc::new(established_initiator_engine(peer_ep, "10.123.0.0/24")));

    let decision = wg_encap_decision();
    let frame = inner_v4_frame();

    let built = crate::afxdp::frame::build_forwarded_frame_from_frame(
        &frame,
        inner_v4_meta(),
        &decision,
        &state,
        false,
        None,
    )
    .expect(
        "the tunnel-kind dispatcher must route TunnelKind::WireGuard to wg_encap_frame; \
         `None` here means the arm was deleted and every WG packet now fail-closed drops",
    );

    // Outer L2: reth0.80's 802.1Q tag, so the IPv4 header starts at 18.
    assert_eq!(
        &built[12..14],
        &[0x81, 0x00],
        "outer must carry the physical egress 802.1Q tag"
    );
    assert_eq!(&built[16..18], &[0x08, 0x00], "outer ethertype must be IPv4");

    // Outer L3: UDP to the peer endpoint. The GRE arm of the same `match`
    // would write PROTO_GRE (47) here and no UDP header at all.
    assert_eq!(built[18] >> 4, 4, "outer must be IPv4");
    assert_eq!(
        built[18 + 9],
        PROTO_UDP,
        "WireGuard's outer transport is UDP — PROTO_GRE here means the \
         dispatcher arm was re-pointed at the GRE builder"
    );
    assert_eq!(
        &built[34..38],
        &[203, 0, 113, 7],
        "outer destination must be the WG peer endpoint"
    );

    // Outer L4: the peer's listen port, then the WireGuard type-4
    // transport-data record (type=4, 3 reserved zero bytes).
    assert_eq!(
        u16::from_be_bytes([built[40], built[41]]),
        51820,
        "outer UDP destination port must be the peer's WG endpoint port"
    );
    assert_eq!(
        &built[46..50],
        &[0x04, 0x00, 0x00, 0x00],
        "the UDP payload must open with the WireGuard type-4 transport-data \
         header — this is what distinguishes a real WG encapsulation from any \
         other builder the dispatcher could have selected"
    );
}
