//! End-to-end tests for the WG engine.
//!
//! These tests build two engines (one initiator, one responder),
//! drive a Noise IK handshake between them, install the resulting
//! transport sessions, then verify encap/decap roundtrip and the
//! AllowedIPs / replay / VLAN / DSCP / MSS properties.

use super::allowed_ips::AllowedIps;
use super::dscp::tos_from_dscp;
use super::engine::{DecapError, EncapError, WgEngine, WgEngineConfig, WgPeerConfig};
use super::framing::{encode_data_header, parse_data_header};
use super::mss::wg_tcp_mss;
// #1440: outer.rs DELETED. The two surviving smoke tests that
// exercised the deleted wrappers (`outer_l2_with_vlan_when_set`
// and `outer_ipv4_tos_propagates_dscp`) now call the consolidated
// builders in `crate::afxdp::frame::headers` directly.
use crate::afxdp::frame::{eth_header_len, write_eth_header_slice, write_ipv4_header};
use super::scratch::WgWorkerScratch;
use super::session::WgSession;
use snow::Builder;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// Generate a fresh X25519 keypair using snow's resolver. Slow
/// path — fine for tests.
pub(super) fn keypair() -> ([u8; 32], [u8; 32]) {
    let kp = Builder::new(super::WG_NOISE_PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let mut priv_k = [0u8; 32];
    let mut pub_k = [0u8; 32];
    priv_k.copy_from_slice(&kp.private);
    pub_k.copy_from_slice(&kp.public);
    (priv_k, pub_k)
}

/// Set up two engines and drive the IK handshake between them.
/// Returns `(initiator_engine, responder_engine, init_pub, resp_pub)`.
///
/// The handshake is driven entirely on the slow path of both
/// sides — exactly the pattern a real worker would use to install
/// sessions for the hot path.
pub(super) fn established_pair(
    init_allowed_for_resp: Vec<ipnet::IpNet>,
    resp_allowed_for_init: Vec<ipnet::IpNet>,
) -> (WgEngine, WgEngine, [u8; 32], [u8; 32]) {
    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();

    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: init_allowed_for_resp,
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
            allowed_ips: resp_allowed_for_init,
            preshared_key: [0u8; 32].into(),
        }],
    });

    // Drive the IK handshake. Two messages: init→resp, then
    // resp→init. No further pumping needed; snow has no hidden
    // queues to drain.
    let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();
    let mut resp_hs = resp_engine.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];

    // Initiation.
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    let mut sink = [0u8; 1024];
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();

    // Response.
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();

    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();

    // Choose receiver indices. In real WG they're chosen at
    // handshake-message build time. For the engine tests we pick
    // them deterministically here and tell each side what the peer
    // chose.
    let init_local_index = 0xaaaa_0001;
    let resp_local_index = 0xbbbb_0001;
    // Initiator session is created with Initiator-role (confirmed at
    // install per WG spec — the initiator is the side that sends
    // first). Responder session is created with Responder-role to be
    // faithful to the wire contract; we then pre-confirm it so existing
    // round-trip tests that encap from the responder side continue
    // to function. The key-confirmation invariant itself is exercised
    // by `responder_session_blocks_encap_until_initiator_data_authenticated`
    // and `established_pair_responder_confirmation_flips_via_decap_path`
    // — see Copilot inline finding on the prior round of this PR.
    let init_session = Arc::new(WgSession::new_with_role(
        init_xport,
        init_local_index,
        resp_local_index,
        resp_pub,
        super::session::SessionRole::Initiator,
        super::counters::monotonic_now_ns(),
    ));
    let resp_session = Arc::new(WgSession::new_with_role(
        resp_xport,
        resp_local_index,
        init_local_index,
        init_pub,
        super::session::SessionRole::Responder,
        super::counters::monotonic_now_ns(),
    ));
    // Pre-confirm the responder so callers that don't want to drive
    // the gate (the bulk of the tests in this file) can encap from
    // either side immediately. The gate tests do NOT call this
    // helper and manage confirmation explicitly.
    resp_session.mark_confirmed();
    init_engine
        .install_session(&resp_pub, init_session)
        .unwrap();
    resp_engine
        .install_session(&init_pub, resp_session.clone())
        .unwrap();
    // #3882 3-slot lifecycle: a responder-role install parks the session
    // in `next`, NOT `current`. Model a fully-established (bidirectional)
    // tunnel by promoting it — the equivalent of the initiator's first
    // inbound data record confirming the keypair — so responder-side
    // encap works for the bulk of the round-trip tests. (The
    // confirm-on-first-inbound-data path itself is exercised by
    // `responder_session_blocks_encap_until_initiator_data_authenticated`
    // and the peer-initiated-rekey tests, which do NOT use this helper.)
    resp_engine.promote_next_for_test(&init_pub, &resp_session);

    (init_engine, resp_engine, init_pub, resp_pub)
}

/// Build a minimal IPv4 packet with the given src/dst and a 20-byte
/// payload. Returns the IP-header-onward bytes (no L2).
fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&40u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p
}

#[test]
fn handshake_completes_and_roundtrip_encap_decap() {
    let resp_allowed = vec!["10.0.0.0/24".parse().unwrap()];
    let init_allowed = vec!["10.0.1.0/24".parse().unwrap()];
    let (init_engine, resp_engine, init_pub, resp_pub) =
        established_pair(init_allowed, resp_allowed);

    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();

    // Wire image: header (16) + padded_plaintext (16-byte multiple
    // >= inner.len()) + tag (16). WG spec §5.4.6 mandates the
    // plaintext be zero-padded to a 16-byte multiple before AEAD.
    let padded = (inner.len() + 15) & !15;
    assert_eq!(enc.len, 16 + padded + 16);
    assert!(padded >= inner.len());
    assert_eq!(padded % 16, 0);

    let mut plain = [0u8; 2048];
    let dec = resp_engine.try_decap(&wire[..enc.len], &mut plain).unwrap();
    assert_eq!(dec.peer_pubkey, init_pub);
    // `dec.len` is the un-padded inner-IP packet length read from
    // the IPv4 `total_length` field. It must equal the original
    // sent inner packet length, not the padded plaintext length.
    assert_eq!(dec.len, inner.len());
    assert_eq!(&plain[..dec.len], &inner[..]);
}

#[test]
fn decap_rejects_inner_src_outside_allowed_ips() {
    // The responder's peer (the initiator) is allowed 10.0.0.0/24.
    // The initiator sends a packet with src 10.0.99.99 — must be
    // dropped by the AllowedIPs gate, NOT silently accepted.
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 99, 99), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    let err = resp_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .unwrap_err();
    assert_eq!(err, DecapError::AllowedIpsViolation);
}

#[test]
fn replay_window_rejects_duplicate_ciphertext() {
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    assert!(resp_engine.try_decap(&wire[..enc.len], &mut plain).is_ok());
    let err = resp_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .unwrap_err();
    assert_eq!(err, DecapError::ReplayDuplicate);
}

#[test]
fn encap_unknown_peer_returns_error_not_random_session() {
    // The cryptokey-routing safety property — if the caller asks
    // us to encrypt to a peer we don't have, we must error, NOT
    // fall back to some other peer.
    let (init_engine, _resp_engine, _init_pub, _resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let bogus = [0xcd; 32];
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let err = init_engine
        .try_encap(&bogus, &inner, &mut wire)
        .unwrap_err();
    assert_eq!(err, EncapError::UnknownPeer);
}

#[test]
fn cryptokey_routing_overlapping_allowed_ips() {
    let (init_priv, init_pub) = keypair();
    let (peer_a_priv, peer_a_pub) = keypair();
    let (peer_b_priv, peer_b_pub) = keypair();

    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: peer_a_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: peer_b_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            },
        ],
    });
    // Stand up real engines for both peers.
    let resp_a = WgEngine::new(WgEngineConfig {
        local_private_key: peer_a_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let resp_b = WgEngine::new(WgEngineConfig {
        local_private_key: peer_b_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });

    // Drive IK init↔A.
    let mut init_hs = init_engine.build_initiator_handshake(&peer_a_pub).unwrap();
    let mut resp_hs = resp_a.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();

    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
    let init_idx = 0x1111_2222;
    let resp_idx = 0x3333_4444;
    init_engine
        .install_session(
            &peer_a_pub,
            Arc::new(WgSession::new(init_xport, init_idx, resp_idx, peer_a_pub)),
        )
        .unwrap();
    resp_a
        .install_session(
            &init_pub,
            Arc::new(WgSession::new(resp_xport, resp_idx, init_idx, init_pub)),
        )
        .unwrap();

    // Drive IK init↔B.
    let mut init_hs = init_engine.build_initiator_handshake(&peer_b_pub).unwrap();
    let mut resp_hs = resp_b.build_responder_handshake().unwrap();
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();
    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
    let init_idx = 0x5555_6666;
    let resp_idx = 0x7777_8888;
    init_engine
        .install_session(
            &peer_b_pub,
            Arc::new(WgSession::new(init_xport, init_idx, resp_idx, peer_b_pub)),
        )
        .unwrap();
    resp_b
        .install_session(
            &init_pub,
            Arc::new(WgSession::new(resp_xport, resp_idx, init_idx, init_pub)),
        )
        .unwrap();

    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 9));
    let mut wire = [0u8; 2048];

    // Asking for A must use A's session, not silently route to B.
    let enc = init_engine
        .try_encap(&peer_a_pub, &inner, &mut wire)
        .unwrap();
    let mut plain = [0u8; 2048];
    let dec = resp_a.try_decap(&wire[..enc.len], &mut plain).unwrap();
    assert_eq!(dec.peer_pubkey, init_pub);
    let err = resp_b.try_decap(&wire[..enc.len], &mut plain).unwrap_err();
    assert_eq!(err, DecapError::UnknownSession);

    // Asking for B still works and decrypts only at B.
    let enc = init_engine
        .try_encap(&peer_b_pub, &inner, &mut wire)
        .unwrap();
    let dec = resp_b.try_decap(&wire[..enc.len], &mut plain).unwrap();
    assert_eq!(dec.peer_pubkey, init_pub);
}

#[test]
fn framing_layout_matches_spec() {
    // Belt-and-braces check that what try_encap emits has the
    // expected on-wire shape: type=4 in byte 0, receiver_index
    // little-endian in bytes 4..8, counter little-endian in 8..16.
    let (init_engine, _resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let parsed = parse_data_header(&wire[..enc.len]).unwrap();
    assert_eq!(parsed.receiver_index, enc.receiver_index);
    assert_eq!(parsed.counter, enc.counter);
    assert_eq!(wire[0], 4);
}

#[test]
fn outer_l2_with_vlan_when_set() {
    // VLAN-safe encap: when tx_vlan_id != 0, the outer L2 carries
    // an 802.1Q tag. This was the #1492 VLAN-unsafe miss. Now
    // exercises the consolidated builder in
    // `crate::afxdp::frame::headers` (#1440).
    let mut buf = [0u8; 64];
    write_eth_header_slice(&mut buf, [0; 6], [0; 6], 0, 0x0800).unwrap();
    // First 14 bytes are the no-VLAN eth header; assert byte 12..14 is
    // the inner ethertype.
    assert_eq!(&buf[12..14], &[0x08, 0x00]);
    assert_eq!(eth_header_len(0), 14);

    let mut buf = [0u8; 64];
    write_eth_header_slice(&mut buf, [0; 6], [0; 6], 100, 0x0800).unwrap();
    assert_eq!(&buf[12..14], &[0x81, 0x00]);
    assert_eq!(eth_header_len(100), 18);
}

#[test]
fn outer_ipv4_tos_propagates_dscp() {
    // EF (DSCP 46) must show up in the outer TOS byte as 0xb8.
    // ECN bits remain cleared. Now exercises the consolidated IPv4
    // outer builder (#1440); the previous `write_outer_ipv4_udp`
    // wrote IP+UDP into the same buffer — here we just gate the
    // TOS byte on the IPv4 header.
    let mut buf = [0u8; 20];
    let tos = tos_from_dscp(46);
    assert_eq!(tos, 0xb8);
    write_ipv4_header(
        &mut buf,
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        17, // UDP
        tos,
        64,
        128,
    )
    .unwrap();
    assert_eq!(buf[1], 0xb8);
    assert_eq!(buf[1] & 0x03, 0); // ECN cleared
}

#[test]
fn mss_clamp_matches_byte_breakdown() {
    // Sanity: 1500-byte outer MTU, v4-in-v4, MSS = 1385. The 1385
    // (vs the pre-padding-fix 1400) leaves room for the worst-case
    // 15 bytes of WG §5.4.6 padding the encap side may add. See
    // mss.rs for the byte-by-byte derivation. Repeated here in the
    // integration tests because review-time errors on MSS math
    // ship and silently fragment.
    assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET, 1500), 1385);
}

#[test]
fn worker_scratch_no_realloc_under_repeated_encap() {
    let (init_engine, _resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let scratch = WgWorkerScratch::new(2048);
    let initial_ptr = scratch.encap_out.borrow().as_ptr();
    for _ in 0..256 {
        let mut buf = scratch.encap_out.borrow_mut();
        let _ = init_engine.try_encap(&resp_pub, &inner, &mut buf).unwrap();
    }
    // No reallocation across 256 encaps. If a future change adds
    // a per-packet `vec![]` on the scratch buffer, this test will
    // catch it.
    //
    // TODO(#1499 r4 / hot-path-discipline): this test only proves
    // the scratch `Vec` doesn't grow. It does NOT prove that
    // `try_encap` itself avoids internal allocation (e.g. an
    // accidental `Vec::with_capacity` inside snow or the engine).
    // The proper instrumentation is `assert_no_alloc` or a custom
    // `GlobalAlloc` that panics on alloc during the hot section.
    // Adding it now would change crate-level test infra; deferred
    // to a follow-up PR that introduces the harness once the
    // integration PR has the full hot path under test.
    assert_eq!(scratch.encap_out.borrow().as_ptr(), initial_ptr);
}

#[test]
fn transport_plaintext_is_padded_to_16_byte_multiple() {
    // WG spec §5.4.6 — every plaintext input to the data-AEAD must
    // be zero-padded to a multiple of 16 before encryption. Test
    // several inner-packet lengths to cover both the "exact
    // multiple" and "needs padding" arms.
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    for inner_len in [20usize, 32, 33, 47, 48, 49, 1500] {
        let mut inner = vec![0u8; inner_len];
        inner[0] = 0x45; // IPv4
        inner[2..4].copy_from_slice(&(inner_len as u16).to_be_bytes());
        inner[9] = 17; // UDP
        inner[12..16].copy_from_slice(&[10, 0, 0, 5]);
        inner[16..20].copy_from_slice(&[10, 0, 1, 5]);
        let mut wire = [0u8; 4096];
        let enc = init_engine
            .try_encap(&resp_pub, &inner, &mut wire)
            .unwrap_or_else(|e| panic!("inner_len={inner_len}: {e:?}"));
        let expected_padded = (inner_len + 15) & !15;
        let ciphertext_len = enc.len - 16 /* hdr */ - 16 /* tag */;
        assert_eq!(
            ciphertext_len, expected_padded,
            "padding mismatch at inner_len={inner_len}: got {ciphertext_len}, want {expected_padded}",
        );
        // Roundtrip: decap returns the un-padded inner-IP length.
        // The first `inner_len` bytes of `plain` must equal the
        // original inner packet; `dec.len` must equal `inner_len`,
        // NOT `expected_padded`.
        let mut plain = [0u8; 4096];
        let dec = resp_engine.try_decap(&wire[..enc.len], &mut plain).unwrap();
        assert_eq!(&plain[..inner_len], &inner[..]);
        assert_eq!(
            dec.len, inner_len,
            "DecapOutcome.len must be the inner-IP packet length, not the padded plaintext length",
        );
    }
}

#[test]
fn decap_rejects_counter_at_reject_after_messages() {
    // WG spec §6.5 — receiver MUST refuse data messages whose
    // counter is at or above REJECT_AFTER_MESSAGES, without
    // attempting AEAD. Symmetric to the encap-side guard.
    use super::framing::encode_data_header;
    use super::session::REJECT_AFTER_MESSAGES;
    let (_init_engine, resp_engine, _init_pub, _resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    // Hand-craft a record with a counter at the spec limit. We
    // don't need real ciphertext — the counter check fires before
    // the demux lookup or AEAD attempt.
    let mut wire = [0u8; 64];
    encode_data_header(&mut wire, /*receiver_idx*/ 0xdead_beef, REJECT_AFTER_MESSAGES).unwrap();
    let mut plain = [0u8; 128];
    let err = resp_engine.try_decap(&wire[..32], &mut plain).unwrap_err();
    assert_eq!(err, DecapError::CounterRejectAfterMessages);
}

/// Cross-peer overlapping AllowedIPs MUST honor WG §5.4.6 global
/// LPM cryptokey routing. If peer A owns `10.0.0.0/8` and peer B
/// owns `10.1.1.0/24`, a packet authenticated by A with inner src
/// `10.1.1.5` must be rejected — the global LPM resolves that
/// address to B, not A. An earlier r4 revision used a per-peer
/// "any prefix covers" check that wrongly accepted A's spoofed
/// source; this regression test fails under that semantic.
#[test]
fn decap_lpm_rejects_spoofed_source_inside_more_specific_peer_prefix() {
    let (init_priv, init_pub) = keypair();
    let (peer_a_priv, peer_a_pub) = keypair();
    let (peer_b_priv, peer_b_pub) = keypair();

    // Initiator engine owns AllowedIPs for both peers: A=/8 (less
    // specific) and B=/24 (more specific, inside A's prefix).
    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: peer_a_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/8".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: peer_b_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.1.1.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            },
        ],
    });
    // Responder engines mirror that view from each peer's side.
    let resp_a = WgEngine::new(WgEngineConfig {
        local_private_key: peer_a_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/8".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let _resp_b = WgEngine::new(WgEngineConfig {
        local_private_key: peer_b_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.1.1.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });

    // We want to demonstrate: a packet that AUTHENTICATES under
    // peer A's session (because A's session was used to encrypt)
    // but whose inner src lies inside peer B's /24 must be
    // rejected by the DECAP-side AllowedIPs gate. Drive the
    // handshake init↔A, install sessions, and have A encrypt a
    // packet with src `10.1.1.5`. The init engine must then
    // verify on receive that the inner src doesn't belong to A.
    let mut init_hs = init_engine.build_initiator_handshake(&peer_a_pub).unwrap();
    let mut resp_hs = resp_a.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();
    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
    let init_idx = 0x1111_aaaa;
    let resp_idx = 0x2222_aaaa;
    init_engine
        .install_session(
            &peer_a_pub,
            Arc::new(WgSession::new(init_xport, init_idx, resp_idx, peer_a_pub)),
        )
        .unwrap();
    resp_a
        .install_session(
            &init_pub,
            Arc::new(WgSession::new(resp_xport, resp_idx, init_idx, init_pub)),
        )
        .unwrap();

    // A sends a packet with src 10.1.1.5 (inside B's /24, NOT
    // authoritative for A under global LPM) to init_engine.
    let inner = ipv4_packet(Ipv4Addr::new(10, 1, 1, 5), Ipv4Addr::new(10, 0, 0, 9));
    let mut wire = [0u8; 2048];
    let enc = resp_a.try_encap(&init_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    let err = init_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .unwrap_err();
    assert_eq!(
        err,
        DecapError::AllowedIpsViolation,
        "global LPM resolves 10.1.1.5 to peer B; A's /8 must NOT authorize that source"
    );
}

/// On every post-AEAD error arm, `out[..n]` must be wiped before
/// returning so the contract "on Err the caller MUST NOT inspect
/// `out`" is structurally enforced. Earlier r4 revisions covered
/// only 3 of 5 error arms; Codex r4 finding 3 / Gemini r4 finding F.
#[test]
fn decap_zeros_plaintext_on_allowed_ips_violation() {
    // Set the AllowedIPs trie so the responder's view of the
    // initiator covers `10.0.0.0/24` only. The initiator then
    // sends with inner src `10.0.99.99` — authenticates, fails
    // AllowedIPs gate, must return AllowedIpsViolation AND wipe.
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 99, 99), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    // Pre-fill `plain` with a recognizable pattern; the wipe must
    // overwrite any decrypted bytes back to zero by the time we
    // observe `plain` after the error return.
    plain.fill(0xa5);
    let err = resp_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .unwrap_err();
    assert_eq!(err, DecapError::AllowedIpsViolation);
    // The plaintext-bearing region — the first `padded_inner_len`
    // bytes that snow decrypted into `out` — must be all zeros.
    // Bytes past that region were never touched by the engine and
    // still hold the 0xa5 pre-fill. snow writes
    // `(inner.len() + 15) & !15` bytes (the padded plaintext).
    let padded_inner_len = (inner.len() + 15) & !15;
    assert!(
        plain[..padded_inner_len].iter().all(|&b| b == 0),
        "AllowedIpsViolation must zero out[..n] ({} bytes); first {} bytes are {:?}",
        padded_inner_len,
        padded_inner_len,
        &plain[..padded_inner_len],
    );
}

#[test]
fn decap_zeros_plaintext_on_malformed_inner() {
    // Force a `MalformedInner` arm: encap a payload whose first
    // byte has IP version != 4/6 so `inner_src_ip` returns None.
    // The packet authenticates (it's just bytes to the AEAD) but
    // the post-decrypt parse fails, and the engine must wipe.
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    // 32-byte payload, first nibble = 0 (no valid IP version).
    let mut inner = vec![0u8; 32];
    inner[0] = 0x05;
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    plain.fill(0xa5);
    let err = resp_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .unwrap_err();
    assert_eq!(err, DecapError::MalformedInner);
    let padded_inner_len = (inner.len() + 15) & !15;
    assert!(
        plain[..padded_inner_len].iter().all(|&b| b == 0),
        "MalformedInner must zero out[..n] ({} bytes); first {} bytes are {:?}",
        padded_inner_len,
        padded_inner_len,
        &plain[..padded_inner_len],
    );
}

/// r5 regression: the encap path stages plaintext through a
/// stack `MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]>` and writes it
/// via raw pointer (not via a `&mut [u8; N]` reference) to keep
/// the un-padded bytes truly uninitialized without crossing the
/// reference-validity invariant. This test bombards the path with
/// a range of inner-IP sizes (covering 0-byte padding, full-15-byte
/// padding, and the PADDED_PLAINTEXT_MAX upper bound) and verifies
/// every roundtrip succeeds with the correct un-padded length —
/// any UB in the raw-pointer write or any miscounted padding
/// boundary would either corrupt the AEAD (decap returns
/// CryptoFailed) or produce a wrong `dec.len`.
#[test]
fn encap_decap_varied_inner_sizes_roundtrip() {
    let (init_engine, resp_engine, init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    // Sizes chosen to span:
    //   - 20: minimum IPv4 header, padding = 12
    //   - 32: padding boundary, padding = 0
    //   - 33: padding = 15 (worst case)
    //   - 1280, 1500: typical MTU sizes
    //   - 4080: the PADDED_PLAINTEXT_MAX inner-payload cap (padded
    //     to 4080 + 0 = 4080, exercises the upper boundary of the
    //     raw-pointer write region)
    for size in [20usize, 32, 33, 64, 100, 256, 1280, 1500, 4080] {
        let mut inner = vec![0u8; size];
        // IPv4 header: version 4, IHL 5, total_length = size.
        inner[0] = 0x45;
        let len_be = (size as u16).to_be_bytes();
        inner[2] = len_be[0];
        inner[3] = len_be[1];
        // src 10.0.0.5 → must match the responder's allowed_ips for the initiator.
        inner[12..16].copy_from_slice(&[10, 0, 0, 5]);
        // dst 10.0.1.5
        inner[16..20].copy_from_slice(&[10, 0, 1, 5]);
        // Fill the rest with a non-zero marker so any uninitialized-
        // memory leak would visibly perturb the decapped output.
        for (i, b) in inner.iter_mut().enumerate().skip(20) {
            *b = ((i * 31) & 0xff) as u8;
        }

        // Pre-fill the output buffer with a non-zero marker — if the
        // raw-pointer write accidentally left a "hole" in the padded
        // plaintext, the AEAD would authenticate the marker bytes
        // and decap would either fail or return mismatched plaintext.
        let mut wire = [0xa5u8; 6000];
        let enc = init_engine
            .try_encap(&resp_pub, &inner, &mut wire)
            .unwrap_or_else(|e| panic!("encap failed at size={}: {:?}", size, e));
        let padded = (size + 15) & !15;
        assert_eq!(enc.len, 16 + padded + 16, "wire len off at size={}", size);

        let mut plain = [0u8; 6000];
        let dec = resp_engine
            .try_decap(&wire[..enc.len], &mut plain)
            .unwrap_or_else(|e| panic!("decap failed at size={}: {:?}", size, e));
        assert_eq!(dec.peer_pubkey, init_pub, "wrong peer at size={}", size);
        assert_eq!(dec.len, size, "wrong un-padded len at size={}", size);
        assert_eq!(
            &plain[..dec.len],
            &inner[..],
            "plaintext mismatch at size={}",
            size
        );
        // Bytes beyond the un-padded inner-IP length up to the
        // padded length must be zero — WG §5.4.6. The decap already
        // verifies this; we assert it explicitly here to anchor the
        // padding contract under the raw-pointer write path.
        for j in dec.len..padded {
            assert_eq!(
                plain[j], 0,
                "padding byte at plain[{}] should be 0, was 0x{:02x} (size={})",
                j, plain[j], size
            );
        }
    }
}

/// r5 regression: encap with an inner_ip whose padded length lands
/// exactly at PADDED_PLAINTEXT_MAX = 4096 must succeed; one byte
/// over must fail with `BufferTooSmall`. The boundary fixes the
/// raw-pointer write to the exact `[0..padded_len)` range — an
/// off-by-one would either write past the staging buffer (UB) or
/// fail to write enough padding bytes (mismatched AEAD tag).
#[test]
fn encap_padded_plaintext_max_boundary() {
    let (init_engine, resp_engine, init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );

    let make = |size: usize| -> Vec<u8> {
        let mut inner = vec![0u8; size];
        inner[0] = 0x45;
        let len_be = (size as u16).to_be_bytes();
        inner[2] = len_be[0];
        inner[3] = len_be[1];
        inner[12..16].copy_from_slice(&[10, 0, 0, 5]);
        inner[16..20].copy_from_slice(&[10, 0, 1, 5]);
        for (i, b) in inner.iter_mut().enumerate().skip(20) {
            *b = ((i * 17) & 0xff) as u8;
        }
        inner
    };

    // 4096 → padded to 4096 = PADDED_PLAINTEXT_MAX → fits at the
    // exact boundary. The raw-pointer write fills bytes
    // `[0..4096)` of the staging store, which is the maximum
    // legal range.
    let inner = make(4096);
    let mut wire = [0u8; 8000];
    let enc = init_engine
        .try_encap(&resp_pub, &inner, &mut wire)
        .expect("4096 must encap (at PADDED_PLAINTEXT_MAX boundary)");
    assert_eq!(enc.len, 16 + 4096 + 16);
    let mut plain = [0u8; 8000];
    let dec = resp_engine.try_decap(&wire[..enc.len], &mut plain).unwrap();
    assert_eq!(dec.len, 4096);
    assert_eq!(dec.peer_pubkey, init_pub);

    // 4097 → padded to 4112 > PADDED_PLAINTEXT_MAX; the engine
    // refuses with BufferTooSmall, preventing any write past the
    // staging buffer.
    let inner = make(4097);
    let mut wire = [0u8; 8000];
    let err = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap_err();
    assert_eq!(err, EncapError::BufferTooSmall);
}

/// r-final-fix regression for Codex final pre-merge finding 1:
/// `build_initiator_handshake` and `build_responder_handshake` MUST
/// call `.prologue(WG_PROTOCOL_ID_BYTES)` so the initial Noise hash
/// matches kernel WireGuard and wireguard-go. We can't reach inside
/// snow's `HandshakeState` to read the hash directly, but we CAN
/// prove the prologue is actually consumed by showing that two
/// engines that disagree on the prologue fail to authenticate each
/// other while two engines that agree complete the handshake.
///
/// The control engine in this test bypasses `WgEngine::build_*` and
/// constructs the `Builder` directly with an empty prologue. If our
/// production builders silently dropped the prologue, the control
/// peer would still authenticate them; with the prologue actually
/// mixed into the hash, the control peer's `read_message` rejects
/// the production initiator with a snow error.
#[test]
fn handshake_prologue_is_required_for_authentication() {
    use super::{WG_NOISE_PATTERN, WG_PROTOCOL_ID_BYTES, WG_ZERO_PSK};
    use snow::Builder;

    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();

    // Production initiator: prologue set via our `build_initiator_handshake`.
    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();

    // Bad responder: prologue OMITTED. If our engine doesn't actually
    // mix the prologue into the hash, this responder would still
    // authenticate the init message; with the prologue properly
    // mixed in, snow rejects.
    let mut bad_resp_hs = Builder::new(WG_NOISE_PATTERN.parse().unwrap())
        .local_private_key(&resp_priv)
        .unwrap()
        .psk(2, &WG_ZERO_PSK)
        .unwrap()
        .build_responder()
        .unwrap();

    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    let res = bad_resp_hs.read_message(&buf[..n1], &mut sink);
    assert!(
        res.is_err(),
        "responder without prologue must reject an initiator that mixed the WG prologue \
         (otherwise the prologue is silently dropped and the engine is not WireGuard-compat)"
    );

    // Sanity: a responder built via `build_responder_handshake`
    // (which sets the prologue) does authenticate the same init
    // message. This shows the rejection above is the prologue
    // difference, not some unrelated handshake mismatch.
    let good_resp_engine = WgEngine::new(WgEngineConfig {
        local_private_key: resp_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let mut init_hs2 = init_engine.build_initiator_handshake(&resp_pub).unwrap();
    let mut good_resp_hs = good_resp_engine.build_responder_handshake().unwrap();
    let n1 = init_hs2.write_message(&[], &mut buf).unwrap();
    good_resp_hs
        .read_message(&buf[..n1], &mut sink)
        .expect("matched-prologue responder must authenticate the initiator");

    // Verify the prologue bytes are exactly the WireGuard protocol
    // identifier — 34 bytes, no trailing NUL. The kernel WG source
    // (`drivers/net/wireguard/noise.c`) uses the same byte string.
    assert_eq!(WG_PROTOCOL_ID_BYTES.len(), 34);
    assert_eq!(WG_PROTOCOL_ID_BYTES, b"WireGuard v1 zx2c4 Jason@zx2c4.com");
}

/// r-final-fix regression for Codex final pre-merge finding 2:
/// responder key-confirmation. A responder-role session MUST NOT be
/// usable for `try_encap` until it has authenticated at least one
/// inbound transport packet (the initiator's first data record).
/// Initiator-role sessions are confirmed at install. After the
/// responder authenticates the initiator's first packet, the
/// responder's session flips to confirmed and egress is allowed.
#[test]
fn responder_session_blocks_encap_until_initiator_data_authenticated() {
    use super::session::SessionRole;

    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();

    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
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
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });

    // Drive the IK handshake.
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
    let init_local = 0xc0de_0001;
    let resp_local = 0xc0de_0002;

    // Install the initiator session as Initiator-role → confirmed.
    init_engine
        .install_session(
            &resp_pub,
            Arc::new(WgSession::new_with_role(
                init_xport,
                init_local,
                resp_local,
                resp_pub,
                SessionRole::Initiator,
                super::counters::monotonic_now_ns(),
            )),
        )
        .unwrap();
    // Install the responder session as Responder-role → unconfirmed.
    let resp_session = Arc::new(WgSession::new_with_role(
        resp_xport,
        resp_local,
        init_local,
        init_pub,
        SessionRole::Responder,
        super::counters::monotonic_now_ns(),
    ));
    assert!(
        !resp_session.is_confirmed(),
        "responder session must start unconfirmed"
    );
    resp_engine
        .install_session(&init_pub, resp_session.clone())
        .unwrap();

    // The responder MUST refuse to encap before the initiator's
    // first data record arrives — this is the WG anti-reflection
    // invariant. The caller sees `NoSession` and falls through to
    // its slow path.
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 9));
    let mut wire_pre = [0u8; 2048];
    let err = resp_engine
        .try_encap(&init_pub, &inner, &mut wire_pre)
        .unwrap_err();
    assert_eq!(
        err,
        EncapError::NoSession,
        "responder MUST NOT encap before authenticating initiator's first data record"
    );

    // Initiator sends the first transport packet. Responder
    // authenticates it — that flips `confirmed = true`.
    let mut wire_first = [0u8; 2048];
    let enc = init_engine
        .try_encap(&resp_pub, &inner, &mut wire_first)
        .unwrap();
    let mut plain = [0u8; 2048];
    let dec = resp_engine
        .try_decap(&wire_first[..enc.len], &mut plain)
        .unwrap();
    assert_eq!(dec.peer_pubkey, init_pub);
    assert!(
        resp_session.is_confirmed(),
        "successful AEAD authentication of inbound data must flip the responder \
         session's confirmation flag (WG key-confirmation invariant)"
    );

    // Responder can now encap to the initiator.
    let inner_reply = ipv4_packet(Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 5));
    let mut wire_post = [0u8; 2048];
    let enc_post = resp_engine
        .try_encap(&init_pub, &inner_reply, &mut wire_post)
        .expect("responder must be able to encap after confirmation flips");
    assert!(enc_post.len > 0);
}

/// r-final-fix regression for Codex final pre-merge finding 3:
/// `reconcile_peers` must update mutable per-peer config fields
/// (endpoint, persistent_keepalive) in place on an existing peer
/// Arc rather than silently keeping stale values. Pre-fix: the Peer
/// struct held immutable `endpoint` / `persistent_keepalive`, so a
/// config commit that changed those values for an existing pubkey
/// was lost.
#[test]
fn reconcile_peers_updates_endpoint_and_keepalive_for_existing_peer() {
    use std::net::SocketAddr;
    let (init_priv, _init_pub) = keypair();
    let (_peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: Some(SocketAddr::from(([192, 0, 2, 1], 51820))),
            persistent_keepalive: 25,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });

    // Sanity: initial fields applied. #2836: config lives in the
    // per-snapshot `PeerEntry.config` bundle, not on the peer Arc.
    {
        let table = engine.table_for_test();
        let idx = *table.peer_index_by_pubkey.get(&peer_pub).unwrap();
        let cfg = table.peers[idx as usize].config.clone();
        assert_eq!(cfg.endpoint, Some(SocketAddr::from(([192, 0, 2, 1], 51820))));
        assert_eq!(cfg.persistent_keepalive, 25);
    }

    // Commit a new config that changes the endpoint AND keepalive
    // for the SAME pubkey. The engine reuses the existing peer Arc
    // (same pubkey, so sessions survive) but publishes a FRESH
    // immutable config bundle in the new snapshot.
    engine.reconcile_peers(&[WgPeerConfig {
        pubkey: peer_pub,
        endpoint: Some(SocketAddr::from(([198, 51, 100, 7], 51900))),
        persistent_keepalive: 60,
        allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        preshared_key: [0u8; 32].into(),
    }]);

    let table = engine.table_for_test();
    let idx = *table.peer_index_by_pubkey.get(&peer_pub).unwrap();
    let cfg = table.peers[idx as usize].config.clone();
    assert_eq!(
        cfg.endpoint,
        Some(SocketAddr::from(([198, 51, 100, 7], 51900))),
        "reconcile must publish the endpoint update in the new snapshot"
    );
    assert_eq!(
        cfg.persistent_keepalive,
        60,
        "reconcile must publish the persistent_keepalive update in the new snapshot"
    );

    // Clearing the endpoint (responder-only) must also propagate.
    engine.reconcile_peers(&[WgPeerConfig {
        pubkey: peer_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        preshared_key: [0u8; 32].into(),
    }]);
    let table = engine.table_for_test();
    let idx = *table.peer_index_by_pubkey.get(&peer_pub).unwrap();
    let cfg = table.peers[idx as usize].config.clone();
    assert_eq!(cfg.endpoint, None);
    assert_eq!(cfg.persistent_keepalive, 0);
}

/// #2836 FAIL-ON-REVERT: a reader holding the OLD `PeerTable` snapshot
/// must observe the OLD endpoint/keepalive/PSK as a unit, even after a
/// concurrent `reconcile_peers` changes all three for the SAME pubkey.
///
/// Pre-fix, `reconcile_peers` reused the existing `Arc<Peer>` and
/// REWROTE its interior-mutable `endpoint`/`persistent_keepalive`/
/// `preshared_key` in place BEFORE the table swap. Because the same
/// peer Arc is shared between the old and the new published table, those
/// in-place writes were instantly visible through the OLD snapshot — so
/// this test, which captures the old snapshot's config, would see the
/// NEW values and FAIL. With the per-snapshot immutable `PeerConfig`
/// bundle the old snapshot keeps the old tuple, so the asserts hold.
///
/// This is the torn-read the issue describes: an old-prefix packet
/// (matched against the old AllowedIPs in the old snapshot) reading the
/// peer endpoint must get the OLD endpoint, never the half-committed
/// new one.
#[test]
fn old_snapshot_observes_old_config_after_concurrent_reconcile() {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::sync::Barrier;

    let psk_old = [0x11u8; 32];
    let psk_new = [0x22u8; 32];
    let ep_old = SocketAddr::from(([192, 0, 2, 1], 51820));
    let ep_new = SocketAddr::from(([198, 51, 100, 7], 51900));

    let (init_priv, _init_pub) = keypair();
    let (_peer_priv, peer_pub) = keypair();
    let engine = Arc::new(WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: Some(ep_old),
            persistent_keepalive: 25,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: psk_old.into(),
        }],
    }));

    // Capture the OLD snapshot's config bundle BEFORE the reconcile.
    // Holding the Arc<PeerTable> pins this snapshot for the test's
    // lifetime regardless of subsequent table swaps.
    let old_table = engine.table_for_test();
    let old_idx = *old_table.peer_index_by_pubkey.get(&peer_pub).unwrap();
    let old_cfg = old_table.peers[old_idx as usize].config.clone();
    // The reused-Arc peer identity, so we can prove the SAME Arc is
    // shared into the new table (the reuse that made the pre-fix bug
    // possible) while its observed config still differs per snapshot.
    let old_peer_arc = old_table.peers[old_idx as usize].peer.clone();

    // Drive a concurrent reconcile from another thread, synchronized so
    // the publish races a reader that already loaded the old snapshot.
    let barrier = Arc::new(Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let engine = Arc::clone(&engine);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            engine.reconcile_peers(&[WgPeerConfig {
                pubkey: peer_pub,
                endpoint: Some(ep_new),
                persistent_keepalive: 60,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                preshared_key: psk_new.into(),
            }]);
        })
    };

    // Reader loop: while the writer may be mid-publish, re-read the
    // PINNED old snapshot's config. It must be internally consistent and
    // unchanged — all-old, never a torn mix or the new values.
    barrier.wait();
    for _ in 0..200_000 {
        assert_eq!(
            old_cfg.endpoint,
            Some(ep_old),
            "old snapshot must keep the OLD endpoint across a concurrent reconcile"
        );
        assert_eq!(
            old_cfg.persistent_keepalive, 25,
            "old snapshot must keep the OLD keepalive across a concurrent reconcile"
        );
        assert_eq!(
            old_cfg.preshared_key(),
            psk_old,
            "old snapshot must keep the OLD PSK across a concurrent reconcile"
        );
        if stop.load(AtomicOrdering::Relaxed) {
            break;
        }
    }
    stop.store(true, AtomicOrdering::Relaxed);
    writer.join().unwrap();

    // After the reconcile, the OLD snapshot is STILL all-old...
    assert_eq!(old_cfg.endpoint, Some(ep_old));
    assert_eq!(old_cfg.persistent_keepalive, 25);
    assert_eq!(old_cfg.preshared_key(), psk_old);

    // ...and a FRESH load is all-new.
    let new_table = engine.table_for_test();
    let new_idx = *new_table.peer_index_by_pubkey.get(&peer_pub).unwrap();
    let new_entry = &new_table.peers[new_idx as usize];
    assert_eq!(new_entry.config.endpoint, Some(ep_new));
    assert_eq!(new_entry.config.persistent_keepalive, 60);
    assert_eq!(new_entry.config.preshared_key(), psk_new);

    // The peer Arc is REUSED across the commit (sessions survive), yet
    // its observed config differs per snapshot — proving the fix gives
    // copy-on-write config WITHOUT dropping the long-lived peer state.
    assert!(
        Arc::ptr_eq(&old_peer_arc, &new_entry.peer),
        "reconcile must reuse the same peer Arc for an unchanged pubkey"
    );
}

/// r-final-fix regression for Copilot inline finding on
/// `inner_ip_len_after_decap`: an IPv4 inner packet with a bogus
/// IHL (< 5) or a `total_length` shorter than the header length
/// MUST be rejected as `MalformedInner`. Pre-fix the engine
/// returned `Some(claimed)` for any `total_length <= pkt.len()`,
/// so a downstream parser could see `DecapOutcome.len < 20` and
/// mis-parse the bytes as a real IPv4 header.
#[test]
fn decap_rejects_inner_ipv4_with_invalid_ihl_or_total_length() {
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );

    // Case 1: IHL = 4 (impossible — < 5 means no room for the fixed
    // header). The first byte's low nibble holds IHL. version=4,
    // IHL=4 → byte 0 = 0x44.
    {
        let mut inner = vec![0u8; 32];
        inner[0] = 0x44; // version=4, IHL=4 (invalid)
        inner[2..4].copy_from_slice(&32u16.to_be_bytes());
        // Need a valid src for AllowedIPs gate to PASS so the
        // failure attributes to inner_ip_len_after_decap, not the
        // AllowedIPs gate. inner_src_ip reads bytes 12..16
        // unconditionally.
        inner[12..16].copy_from_slice(&[10, 0, 0, 5]);
        inner[16..20].copy_from_slice(&[10, 0, 1, 5]);
        let mut wire = [0u8; 2048];
        let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
        let mut plain = [0u8; 2048];
        let err = resp_engine
            .try_decap(&wire[..enc.len], &mut plain)
            .unwrap_err();
        assert_eq!(
            err,
            DecapError::MalformedInner,
            "IHL < 5 must be rejected as MalformedInner"
        );
    }

    // Case 2: IHL = 5, total_length = 10 (claims fewer bytes than
    // the fixed header). Must reject.
    {
        let mut inner = vec![0u8; 32];
        inner[0] = 0x45; // version=4, IHL=5
        inner[2..4].copy_from_slice(&10u16.to_be_bytes());
        inner[12..16].copy_from_slice(&[10, 0, 0, 5]);
        inner[16..20].copy_from_slice(&[10, 0, 1, 5]);
        let mut wire = [0u8; 2048];
        let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
        let mut plain = [0u8; 2048];
        let err = resp_engine
            .try_decap(&wire[..enc.len], &mut plain)
            .unwrap_err();
        assert_eq!(
            err,
            DecapError::MalformedInner,
            "total_length < ihl*4 must be rejected as MalformedInner"
        );
    }
}

/// #2910 fail-on-revert: WG §5.4.6 trailing padding is length-driven on
/// receive — the receiver reads the inner-IP length and discards the
/// remainder. It MUST NOT reject a transport record merely because the
/// trailing padding bytes are non-zero (kernel WireGuard / wireguard-go
/// do not require zero padding; the AEAD tag already authenticates the
/// whole plaintext so non-zero padding is not forgeable). Pre-fix,
/// `inner_ip_len_after_decap` ran `if pkt[claimed..].any(|b| b != 0) {
/// return None }` and the whole decap surfaced `MalformedInner` for such
/// a record — a real interop cliff. Post-fix it truncates to the inner
/// length and delivers.
///
/// We cannot drive this through `try_encap` (the encap path always
/// zero-pads). Instead we reach into the established session's snow
/// transport, encrypt a hand-crafted plaintext of `valid 40-byte IPv4
/// packet || 8 NON-ZERO padding bytes` (48 total = a 16-byte multiple),
/// frame it with the WG data header keyed on the peer-chosen
/// `receiver_index`, and decap it on the responder. The assertions:
///   - decap SUCCEEDS (RED before the fix — it returned MalformedInner),
///   - `dec.len == 40` (the inner-IP length, NOT the 48-byte padded
///     plaintext — proves the forwarded packet is bounded by the
///     AEAD-validated inner length, not the padded length),
///   - `plain[..40]` equals the original inner packet,
///   - `plain[40..48]` (the non-zero pad) is OUTSIDE `dec.len` and so is
///     never forwarded.
#[test]
fn decap_accepts_nonzero_trailing_padding_and_bounds_to_inner_len() {
    use super::framing::encode_data_header;
    use std::sync::atomic::Ordering;

    let (init_engine, resp_engine, init_pub, _resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );

    // Inner IPv4 packet: src 10.0.0.5 (inside the responder's AllowedIPs
    // for the initiator → passes the receive-side cryptokey gate),
    // total_length = 40.
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    assert_eq!(inner.len(), 40);

    // Plaintext to encrypt = inner || 8 non-zero padding bytes. 48 is a
    // 16-byte multiple, the WG §5.4.6 padded form — but with a non-zero
    // pad that a conforming sender is permitted to emit and that the old
    // code rejected.
    let mut plaintext = inner.clone();
    plaintext.extend_from_slice(&[0xAB; 8]);
    assert_eq!(plaintext.len() % 16, 0, "padded to a 16-byte multiple");

    // Grab the initiator's session and use its snow transport to encrypt
    // our crafted plaintext directly (the public encap API would zero the
    // pad). The session's `peer_index` is the receiver_index the
    // responder demuxes on.
    let init_session = init_engine
        .sessions_by_local_index
        .read()
        .unwrap()
        .get(&0xaaaa_0001)
        .cloned()
        .expect("initiator session installed by established_pair");
    let counter = init_session
        .next_tx_counter()
        .expect("fresh session has counter space");

    let mut wire = vec![0u8; super::WG_DATA_HEADER_LEN + plaintext.len() + super::POLY1305_TAG_LEN];
    encode_data_header(&mut wire, init_session.peer_index, counter)
        .expect("header buffer is large enough");
    let n = init_session
        .transport
        .write_message(counter, &plaintext, &mut wire[super::WG_DATA_HEADER_LEN..])
        .expect("snow encrypt of crafted plaintext");
    let record_len = super::WG_DATA_HEADER_LEN + n;

    let mut plain = [0u8; 2048];
    let dec = resp_engine
        .try_decap(&wire[..record_len], &mut plain)
        .expect(
            "decap must accept a record whose trailing WG padding is \
             non-zero (#2910); pre-fix this returned MalformedInner",
        );

    assert_eq!(dec.peer_pubkey, init_pub);
    assert_eq!(
        dec.len, 40,
        "forwarded length must be the inner-IP length (40), not the \
         48-byte padded plaintext — pad bytes are dropped, not forwarded"
    );
    assert_eq!(
        &plain[..dec.len],
        &inner[..],
        "delivered bytes must be exactly the inner IPv4 packet"
    );
    assert_eq!(
        resp_engine
            .counters()
            .decap_packets
            .load(Ordering::Relaxed),
        1,
        "the record counts as a successfully decapped data packet"
    );
}

/// r-final-fix regression for Copilot inline finding on
/// `TunnelEndpointSnapshot::wg_local_privkey_hex`: the private key
/// field MUST NOT be serialized into the on-disk state file, and a
/// `Debug` impl MUST redact it so accidental log calls cannot leak
/// key material.
#[test]
fn tunnel_endpoint_snapshot_private_key_is_skipped_and_redacted() {
    use crate::protocol::TunnelEndpointSnapshot;

    let snap = TunnelEndpointSnapshot {
        wg_local_privkey_hex: "deadbeef".repeat(8), // 64 hex chars = "private key"
        wg_peers: vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
            wg_peer_pubkey_hex: "abc123".to_string(),
            ..Default::default()
        }],
        wg_listen_port: 51820,
        ..Default::default()
    };

    // Serialization must NOT include the private key — this is the
    // surface that ends up in the state file on disk.
    let json = serde_json::to_string(&snap).expect("snapshot must serialize");
    assert!(
        !json.contains(&snap.wg_local_privkey_hex),
        "wg_local_privkey_hex must NOT appear in serialized output (state file would leak); \
         got: {json}"
    );

    // Debug must redact — accidental {:?} log lines can't leak.
    let debug_str = format!("{snap:?}");
    assert!(
        !debug_str.contains(&snap.wg_local_privkey_hex),
        "Debug for TunnelEndpointSnapshot must NOT include the raw private key bytes; \
         got: {debug_str}"
    );
    assert!(
        debug_str.contains("<redacted>"),
        "Debug for TunnelEndpointSnapshot must show <redacted> placeholder; got: {debug_str}"
    );

    // Empty-key case: must show <unset> placeholder.
    let empty = TunnelEndpointSnapshot::default();
    let debug_str = format!("{empty:?}");
    assert!(
        debug_str.contains("<unset>"),
        "empty privkey must Debug as <unset>; got: {debug_str}"
    );

    // Deserialization still accepts the field — the control plane
    // delivers the key on the control socket.
    let wire = serde_json::json!({
        "wg_local_privkey_hex": "0123456789abcdef".repeat(4),
        "wg_listen_port": 51820,
    });
    let snap: TunnelEndpointSnapshot = serde_json::from_value(wire).unwrap();
    assert_eq!(snap.wg_local_privkey_hex.len(), 64);
    assert_eq!(snap.wg_listen_port, 51820);
}

#[test]
fn allowed_ips_unit_check() {
    // Direct AllowedIps test — extra coverage on top of the
    // module's own unit tests, exercising the same API the engine
    // uses on the decap path.
    let mut t = AllowedIps::new();
    t.insert("10.0.0.0/24".parse().unwrap(), 0);
    t.insert("10.0.0.128/25".parse().unwrap(), 1);
    assert_eq!(t.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), Some(0));
    assert_eq!(t.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200))), Some(1));
}

/// Regression test for the truncated-record remote DoS that Codex
/// caught on the r-final-2 review (all 9 prior review rounds missed
/// it). A hostile peer that observes a valid `receiver_index` for a
/// live session can send 16..31-byte UDP datagrams; `parse_data_header`
/// accepts any record ≥ 16 bytes, leaving a sub-Poly1305-tag
/// ciphertext that snow 0.10's ChaCha-Poly1305 decrypt cannot handle
/// safely (the internal `ciphertext.len() - TAGLEN` either underflows
/// to a debug-assert or wraps to a huge usize that panics on the
/// subsequent slice op). The fix: reject sub-tag records with
/// `DecapError::ShortRecord` before invoking snow.
///
/// This test installs a live session, then walks `ciphertext.len()`
/// across {0, 1, 8, 14, 15} and asserts the engine returns the new
/// error variant rather than panicking. The assertion is on the
/// returned error — if the bug regressed, the test would panic
/// instead of failing with a wrong-error.
#[test]
fn try_decap_rejects_sub_poly1305_tag_records_without_panicking() {
    use super::framing::encode_data_header;

    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );

    // Encrypt one real packet through the engine to learn what
    // `receiver_index` the responder demuxes on. We extract that
    // index from the encrypted record so the hostile-attacker probe
    // uses a live session's index.
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine
        .try_encap(&resp_pub, &inner, &mut wire)
        .expect("baseline encap should succeed");
    let receiver_index = enc.receiver_index;

    // Walk ciphertext lengths from 0 through 15 (i.e. record lengths
    // 16..31). Every one of these must return ShortRecord, NOT panic.
    for ct_len in [0usize, 1, 8, 14, 15] {
        let mut probe = vec![0u8; super::WG_DATA_HEADER_LEN + ct_len];
        encode_data_header(&mut probe, receiver_index, 0xdead_beef).unwrap();
        // The header counter we used (0xdeadbeef) is well below
        // REJECT_AFTER_MESSAGES — so the rejection MUST come from the
        // short-record guard, not from the counter-ceiling guard or
        // from a panic inside snow.
        let mut plain = [0u8; 2048];
        let err = resp_engine.try_decap(&probe, &mut plain).unwrap_err();
        assert_eq!(
            err,
            DecapError::ShortRecord,
            "record with ciphertext.len()={ct_len} must reject as ShortRecord; \
             got {err:?}. If this test panics instead of asserting, the \
             truncated-record DoS has regressed and snow is being handed \
             a sub-tag ciphertext."
        );
    }

    // Boundary case: ciphertext.len() == POLY1305_TAG_LEN (16) is no
    // longer ShortRecord — it's an empty-payload record. Snow will
    // reject it for failing the AEAD tag (we haven't crafted a real
    // tag), which surfaces as CryptoFailed. Important contract: the
    // short-record guard's cutoff is `< POLY1305_TAG_LEN`, not `<=`.
    let mut sixteen_byte_ct = vec![0u8; super::WG_DATA_HEADER_LEN + super::POLY1305_TAG_LEN];
    encode_data_header(&mut sixteen_byte_ct, receiver_index, 0xdead_beef).unwrap();
    let mut plain = [0u8; 2048];
    let err = resp_engine.try_decap(&sixteen_byte_ct, &mut plain).unwrap_err();
    assert_ne!(
        err,
        DecapError::ShortRecord,
        "a ciphertext.len() == POLY1305_TAG_LEN record is NOT short — must \
         reach snow and reject as CryptoFailed (or similar) instead"
    );
}

/// Builds an `established_pair` where the responder session starts
/// unconfirmed (responder-role) and is confirmed by the engine's
/// own `try_decap` rather than by a manual `mark_confirmed` test
/// helper. This is what a real responder integration path will do
/// — the first authenticated inbound data record flips the gate.
///
/// Addresses the Copilot inline finding on `established_pair`: the
/// bulk of the file's round-trip tests use the helper which
/// pre-confirms the responder, so the key-confirmation gate is not
/// exercised by them. This test exercises it end-to-end without
/// touching `mark_confirmed`.
#[test]
fn established_pair_responder_confirmation_flips_via_decap_path() {
    use super::session::SessionRole;

    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();

    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
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
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
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
    let init_local = 0xc0de_4001;
    let resp_local = 0xc0de_4002;

    init_engine
        .install_session(
            &resp_pub,
            Arc::new(WgSession::new_with_role(
                init_xport,
                init_local,
                resp_local,
                resp_pub,
                SessionRole::Initiator,
                super::counters::monotonic_now_ns(),
            )),
        )
        .unwrap();
    let resp_session = Arc::new(WgSession::new_with_role(
        resp_xport,
        resp_local,
        init_local,
        init_pub,
        SessionRole::Responder,
        super::counters::monotonic_now_ns(),
    ));
    resp_engine
        .install_session(&init_pub, resp_session.clone())
        .unwrap();
    assert!(!resp_session.is_confirmed());

    // Initiator sends; engine `try_decap` MUST flip confirmation.
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 9));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    resp_engine.try_decap(&wire[..enc.len], &mut plain).unwrap();
    assert!(
        resp_session.is_confirmed(),
        "successful AEAD via try_decap must flip confirmation without any test-only mark_confirmed call"
    );

    // Responder can now encap; the gate is open.
    let reply = ipv4_packet(Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 5));
    let mut wire2 = [0u8; 2048];
    resp_engine
        .try_encap(&init_pub, &reply, &mut wire2)
        .expect("post-confirmation encap must succeed");
}

// ===================================================================
// Framed WG handshake — engine integration (#1709 S1)
//
// These exercise the full on-wire framed handshake (create_initiation /
// consume_response / consume_initiation_create_response) BOTH directions
// between two engines, and assert matching transport keys via a transport
// record round-trip. This is xpf-against-xpf — a REGRESSION GUARD for the
// engine integration, NOT the independent-peer interop proof. The live
// kernel-WireGuard-on-a-VM interop (the byte-compliance proof against an
// independent reference) is #1703 S2.
// ===================================================================
mod framed_handshake {
    use super::*;
    use crate::afxdp::wg::handshake::FramingError;
    use crate::afxdp::wg::handshake_session::HandshakeError;
    use crate::afxdp::wg::{WG_MSG_INIT_LEN, WG_MSG_RESPONSE_LEN};

    /// Build two engines that know each other's pubkey, allowing the full
    /// `0.0.0.0/0` so any inner src passes the AllowedIPs gate.
    fn engine_pair() -> (WgEngine, WgEngine, [u8; 32], [u8; 32]) {
        let (init_priv, init_pub) = keypair();
        let (resp_priv, resp_pub) = keypair();
        let any_v4: Vec<ipnet::IpNet> = vec!["0.0.0.0/0".parse().unwrap()];
        let init = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: resp_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: any_v4.clone(),
                preshared_key: [0u8; 32].into(),
            }],
        });
        let resp = WgEngine::new(WgEngineConfig {
            local_private_key: resp_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: init_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: any_v4,
                preshared_key: [0u8; 32].into(),
            }],
        });
        (init, resp, init_pub, resp_pub)
    }

    #[test]
    fn local_public_key_matches_snow_static() {
        // The engine derives its local public key via dalek
        // mul_base_clamped; it MUST equal the public key snow generated for
        // the same private key (which engine_pair returns as init_pub/
        // resp_pub from keypair()). A mismatch would mean inbound MAC1
        // verification keys on the wrong pubkey and every real handshake
        // would be dropped.
        let (init, resp, init_pub, resp_pub) = engine_pair();
        assert_eq!(
            init.local_public_key(),
            init_pub,
            "engine local_public_key must equal snow's static pub for the same private key"
        );
        assert_eq!(resp.local_public_key(), resp_pub);
    }

    /// Full framed handshake, xpf initiator -> xpf responder, then a
    /// transport record round-trip in BOTH directions proving the derived
    /// transport keys match.
    #[test]
    fn framed_handshake_both_directions_roundtrip() {
        let (init, resp, init_pub, resp_pub) = engine_pair();

        // 1. Initiator builds msg1.
        let mut msg1 = [0u8; WG_MSG_INIT_LEN];
        let init_idx = init.create_initiation(&resp_pub, &mut msg1).unwrap();
        assert_eq!(init.pending_count(), 1, "initiator holds one pending handshake");

        // 2. Responder consumes msg1, emits msg2, installs its session.
        let mut msg2 = [0u8; WG_MSG_RESPONSE_LEN];
        let (recovered_init_pub, resp_idx) =
            resp.consume_initiation_create_response(&msg1, &mut msg2).unwrap();
        assert_eq!(recovered_init_pub, init_pub,
            "responder must recover the initiator's static pubkey from msg1");
        assert_eq!(resp.pending_count(), 0, "responder completes synchronously");

        // 3. Initiator consumes msg2, installs its session.
        let (_peer, installed_idx) = init.consume_response(&msg2).unwrap();
        assert_eq!(installed_idx, init_idx);
        assert_eq!(init.pending_count(), 0, "initiator handshake promoted");

        // 4. Initiator -> responder transport record (initiator is confirmed
        //    at install; responder confirms on this first inbound record).
        let inner = ipv4_packet(Ipv4Addr::new(10, 9, 9, 1), Ipv4Addr::new(10, 9, 9, 2));
        let mut wire = [0u8; 2048];
        let enc = init.try_encap(&resp_pub, &inner, &mut wire).unwrap();
        let mut plain = [0u8; 2048];
        let dec = resp.try_decap(&wire[..enc.len], &mut plain).unwrap();
        assert_eq!(&plain[..dec.len], &inner[..], "init->resp inner packet must round-trip");
        assert_eq!(dec.peer_pubkey, init_pub);

        // 5. Responder -> initiator transport record (responder now confirmed).
        let reply = ipv4_packet(Ipv4Addr::new(10, 9, 9, 2), Ipv4Addr::new(10, 9, 9, 1));
        let mut wire2 = [0u8; 2048];
        let enc2 = resp.try_encap(&init_pub, &reply, &mut wire2).unwrap();
        let mut plain2 = [0u8; 2048];
        let dec2 = init.try_decap(&wire2[..enc2.len], &mut plain2).unwrap();
        assert_eq!(&plain2[..dec2.len], &reply[..], "resp->init inner packet must round-trip");
        assert_eq!(dec2.peer_pubkey, resp_pub);

        // Indices are distinct (each side chose its own).
        assert_ne!(init_idx, resp_idx);
    }

    /// #3882 RED-on-revert: a PEER-INITIATED rekey (xpf is the RESPONDER)
    /// must NOT blackhole the xpf→peer egress direction. Under the 3-slot
    /// keypair model the unconfirmed new responder keypair parks in
    /// `next`; egress keeps using the confirmed `current` until the
    /// peer's first inbound data record on the new keypair promotes it.
    ///
    /// On revert (responder keypair rotated straight into `current`, the
    /// pre-#3882 2-slot behavior) the marked egress `try_encap` returns
    /// `NoSession` and the `.expect(...)` below panics — the persistent,
    /// replayable egress DoS the F-019 defect described.
    #[test]
    fn peer_initiated_rekey_does_not_blackhole_egress() {
        let (xpf, peer, xpf_pub, peer_pub) = engine_pair();

        // --- Phase 1: initial handshake, xpf as INITIATOR → a confirmed
        //     `current` on xpf; xpf→peer egress works. ---
        let mut m1 = [0u8; WG_MSG_INIT_LEN];
        xpf.create_initiation(&peer_pub, &mut m1).unwrap();
        let mut m2 = [0u8; WG_MSG_RESPONSE_LEN];
        peer.consume_initiation_create_response(&m1, &mut m2)
            .unwrap();
        xpf.consume_response(&m2).unwrap();
        let initial_current = xpf
            .current_session_local_index(&peer_pub)
            .expect("xpf holds a confirmed current after the initial handshake");

        let inner = ipv4_packet(Ipv4Addr::new(10, 9, 9, 1), Ipv4Addr::new(10, 9, 9, 2));
        let mut wire = [0u8; 2048];
        let mut plain = [0u8; 2048];
        // Baseline egress + delivery (peer confirms/promotes its own
        // responder keypair on this first inbound record).
        let e0 = xpf
            .try_encap(&peer_pub, &inner, &mut wire)
            .expect("baseline xpf→peer egress works");
        peer.try_decap(&wire[..e0.len], &mut plain).unwrap();

        // --- Phase 2: PEER-INITIATED rekey — peer is initiator, xpf is
        //     responder; xpf builds a NEW (unconfirmed) responder keypair. ---
        let mut rk1 = [0u8; WG_MSG_INIT_LEN];
        peer.create_initiation(&xpf_pub, &mut rk1).unwrap();
        let mut rk2 = [0u8; WG_MSG_RESPONSE_LEN];
        xpf.consume_initiation_create_response(&rk1, &mut rk2)
            .unwrap();

        // RED-on-revert (the F-019 defect): xpf→peer egress must STILL
        // work right after the peer-initiated rekey — it uses the
        // confirmed `current`, NOT the unconfirmed new keypair. On revert
        // (responder keypair rotated into `current`) this returns
        // NoSession → the `.expect` panics → the persistent egress DoS.
        // During the window the peer's `current` is also still the old
        // keypair, so the record round-trips. Capture a peer→xpf record
        // on the OLD keypair here too, to prove the previous-keypair
        // decrypt grace after promotion below.
        let e1 = xpf
            .try_encap(&peer_pub, &inner, &mut wire)
            .expect("peer-initiated rekey must NOT blackhole xpf→peer egress");
        peer.try_decap(&wire[..e1.len], &mut plain)
            .expect("peer decrypts on the still-current phase-1 keypair");

        // The fix's mechanism: the unconfirmed rekey keypair parked in
        // `next`; `current` was UNCHANGED (still the confirmed phase-1
        // keypair) which is why the egress above did not blackhole.
        {
            let xp = xpf.peer_arc(&peer_pub).unwrap();
            assert!(
                xp.next.read().unwrap().is_some(),
                "the unconfirmed responder rekey keypair must park in `next`"
            );
            assert_eq!(
                xp.current.read().unwrap().as_ref().map(|s| s.local_index),
                Some(initial_current),
                "current must stay the confirmed phase-1 keypair — egress must not switch \
                 to the unconfirmed one"
            );
        }
        let mut wire_old = [0u8; 2048];
        let e_old = peer
            .try_encap(&xpf_pub, &inner, &mut wire_old)
            .expect("peer egress on its (still current) old keypair");
        let e_old_len = e_old.len;

        // --- Phase 3: peer completes its side and sends the first data
        //     record on the NEW keypair → xpf promotes next→current. ---
        peer.consume_response(&rk2).unwrap();
        let e_new = peer.try_encap(&xpf_pub, &inner, &mut wire).unwrap();
        xpf.try_decap(&wire[..e_new.len], &mut plain)
            .expect("xpf decrypts the first inbound data on the new keypair");

        let promoted_current = xpf.current_session_local_index(&peer_pub).unwrap();
        assert_ne!(
            promoted_current, initial_current,
            "first inbound data on `next` must promote it to `current`"
        );
        {
            let xp = xpf.peer_arc(&peer_pub).unwrap();
            assert!(
                xp.next.read().unwrap().is_none(),
                "`next` drained after promotion"
            );
            assert_eq!(
                xp.previous.read().unwrap().as_ref().map(|s| s.local_index),
                Some(initial_current),
                "old current demoted to previous (in-flight reverse-traffic grace)"
            );
        }

        // Previous-keypair grace: the peer→xpf record captured on the OLD
        // keypair during the window still decrypts now that that keypair
        // sits in `previous`.
        xpf.try_decap(&wire_old[..e_old_len], &mut plain)
            .expect("previous keypair must still decrypt in-flight reverse traffic");

        // Egress still works, now on the promoted keypair.
        let e2 = xpf
            .try_encap(&peer_pub, &inner, &mut wire)
            .expect("egress works on the promoted keypair");
        peer.try_decap(&wire[..e2.len], &mut plain).unwrap();
    }

    /// #3882 guard: an xpf-INITIATED rekey is confirmed by the peer's
    /// response, so its keypair goes straight to `current` (old
    /// current→previous) and egress switches immediately — the initiator
    /// lifecycle is UNCHANGED by the 3-slot responder fix, and `next`
    /// stays empty.
    #[test]
    fn initiator_rekey_switches_current_immediately() {
        let (xpf, peer, _xpf_pub, peer_pub) = engine_pair();

        let mut m1 = [0u8; WG_MSG_INIT_LEN];
        xpf.create_initiation(&peer_pub, &mut m1).unwrap();
        let mut m2 = [0u8; WG_MSG_RESPONSE_LEN];
        peer.consume_initiation_create_response(&m1, &mut m2)
            .unwrap();
        xpf.consume_response(&m2).unwrap();
        let first = xpf.current_session_local_index(&peer_pub).unwrap();

        // xpf initiates a REKEY. The peer builds a fresh responder
        // keypair + msg2; xpf.consume_response installs the new INITIATOR
        // keypair straight into `current`.
        let mut rm1 = [0u8; WG_MSG_INIT_LEN];
        xpf.create_initiation(&peer_pub, &mut rm1).unwrap();
        let mut rm2 = [0u8; WG_MSG_RESPONSE_LEN];
        peer.consume_initiation_create_response(&rm1, &mut rm2)
            .unwrap();
        xpf.consume_response(&rm2).unwrap();

        let second = xpf.current_session_local_index(&peer_pub).unwrap();
        assert_ne!(
            second, first,
            "initiator rekey switches `current` immediately"
        );
        {
            let xp = xpf.peer_arc(&peer_pub).unwrap();
            assert!(
                xp.next.read().unwrap().is_none(),
                "an initiator install must not populate `next`"
            );
            assert_eq!(
                xp.previous.read().unwrap().as_ref().map(|s| s.local_index),
                Some(first),
                "old current demoted to previous"
            );
            assert!(
                xp.current.read().unwrap().as_ref().unwrap().is_confirmed(),
                "the initiator keypair is confirmed at install"
            );
        }
        // Egress works immediately on the new keypair (no
        // wait-for-inbound as the responder path requires).
        let inner = ipv4_packet(Ipv4Addr::new(10, 9, 9, 1), Ipv4Addr::new(10, 9, 9, 2));
        let mut wire = [0u8; 2048];
        let mut plain = [0u8; 2048];
        let e = xpf
            .try_encap(&peer_pub, &inner, &mut wire)
            .expect("egress on the rekeyed initiator keypair");
        peer.try_decap(&wire[..e.len], &mut plain).unwrap();
    }

    /// msg1's mac1 keys on the RESPONDER's pubkey; a responder configured
    /// with a different identity rejects it with Mac1Mismatch.
    #[test]
    fn responder_rejects_initiation_with_wrong_mac1() {
        let (init, _resp, _init_pub, resp_pub) = engine_pair();
        let mut msg1 = [0u8; WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();

        // A different responder (different static key) must reject the mac1.
        let (other_priv, _other_pub) = keypair();
        let (_init2_priv, init2_pub) = keypair();
        let other = WgEngine::new(WgEngineConfig {
            local_private_key: other_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: init2_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            }],
        });
        let mut msg2 = [0u8; WG_MSG_RESPONSE_LEN];
        let err = other
            .consume_initiation_create_response(&msg1, &mut msg2)
            .unwrap_err();
        assert_eq!(err, HandshakeError::Framing(FramingError::Mac1Mismatch));
    }

    /// An initiation from a peer the responder does not know (valid mac1
    /// because it targets the responder's real pubkey, but the initiator
    /// static is unconfigured) is rejected as UnknownInitiator AFTER the
    /// Noise read recovers the static key.
    #[test]
    fn responder_rejects_unknown_initiator() {
        let (resp_priv, resp_pub) = keypair();
        // Responder knows only some OTHER peer, not our initiator.
        let (_known_priv, known_pub) = keypair();
        let resp = WgEngine::new(WgEngineConfig {
            local_private_key: resp_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: known_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            }],
        });
        // A stranger initiator that targets the real responder pubkey.
        let (stranger_priv, _stranger_pub) = keypair();
        let stranger = WgEngine::new(WgEngineConfig {
            local_private_key: stranger_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: resp_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            }],
        });
        let mut msg1 = [0u8; WG_MSG_INIT_LEN];
        stranger.create_initiation(&resp_pub, &mut msg1).unwrap();
        let mut msg2 = [0u8; WG_MSG_RESPONSE_LEN];
        let err = resp
            .consume_initiation_create_response(&msg1, &mut msg2)
            .unwrap_err();
        assert_eq!(err, HandshakeError::UnknownInitiator);
    }

    /// consume_response with a receiver_index that matches no pending
    /// reservation is rejected as NoPendingHandshake (stale/spoofed msg2).
    #[test]
    fn consume_response_no_pending_is_rejected() {
        let (init, resp, _init_pub, resp_pub) = engine_pair();
        // Drive a full handshake so we have a VALID msg2, then replay it: the
        // first consume promotes + clears the reservation; the second finds
        // no pending entry.
        let mut msg1 = [0u8; WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();
        let mut msg2 = [0u8; WG_MSG_RESPONSE_LEN];
        resp.consume_initiation_create_response(&msg1, &mut msg2).unwrap();
        init.consume_response(&msg2).unwrap();
        // Replay msg2 — reservation already promoted/cleared.
        let err = init.consume_response(&msg2).unwrap_err();
        assert_eq!(err, HandshakeError::NoPendingHandshake);
    }

    /// create_initiation toward an unconfigured peer is UnknownPeer and
    /// leaves no pending reservation.
    #[test]
    fn create_initiation_unknown_peer() {
        let (init, _resp, _init_pub, _resp_pub) = engine_pair();
        let (_x_priv, x_pub) = keypair();
        let mut msg1 = [0u8; WG_MSG_INIT_LEN];
        let err = init.create_initiation(&x_pub, &mut msg1).unwrap_err();
        assert_eq!(err, HandshakeError::UnknownPeer);
        assert_eq!(init.pending_count(), 0);
    }

    /// At-most-one-pending-per-peer: a SECOND create_initiation toward the
    /// same peer aborts the first reservation (pending stays at 1, not 2).
    /// The first msg1's reservation is gone, so consuming a response to it
    /// would fail — only the latest handshake survives.
    #[test]
    fn at_most_one_pending_per_peer() {
        let (init, resp, _init_pub, resp_pub) = engine_pair();
        let mut msg1_a = [0u8; WG_MSG_INIT_LEN];
        let idx_a = init.create_initiation(&resp_pub, &mut msg1_a).unwrap();
        assert_eq!(init.pending_count(), 1);

        let mut msg1_b = [0u8; WG_MSG_INIT_LEN];
        let idx_b = init.create_initiation(&resp_pub, &mut msg1_b).unwrap();
        assert_ne!(idx_a, idx_b, "second handshake gets a fresh index");
        assert_eq!(init.pending_count(), 1, "per-peer cap: only the latest pending survives");

        // The responder answers the SECOND msg1; the initiator can complete
        // it (its reservation survived).
        let mut msg2_b = [0u8; WG_MSG_RESPONSE_LEN];
        resp.consume_initiation_create_response(&msg1_b, &mut msg2_b).unwrap();
        assert_eq!(init.consume_response(&msg2_b).unwrap().1, idx_b);

        // A response to the FIRST (aborted) handshake has no reservation.
        // Build it by having a fresh responder answer msg1_a, then feeding
        // the initiator that msg2 — its idx_a reservation was aborted.
        let (init2, resp2, _ip2, rp2) = engine_pair();
        let mut m1 = [0u8; WG_MSG_INIT_LEN];
        let first = init2.create_initiation(&rp2, &mut m1).unwrap();
        let mut m1b = [0u8; WG_MSG_INIT_LEN];
        init2.create_initiation(&rp2, &mut m1b).unwrap(); // aborts `first`
        let mut m2 = [0u8; WG_MSG_RESPONSE_LEN];
        resp2.consume_initiation_create_response(&m1, &mut m2).unwrap();
        // m2's receiver_index echoes `first`, which is no longer pending.
        let _ = first;
        assert_eq!(
            init2.consume_response(&m2).unwrap_err(),
            HandshakeError::NoPendingHandshake,
            "a response to an aborted (superseded) reservation must be dropped"
        );
    }

    /// Reserve-before-send + promote: after a completed handshake BOTH
    /// sessions are live + demuxable on their reserved indices — a record
    /// the initiator sends decaps at the responder, and a record the
    /// responder sends decaps at the initiator. Exercising both promoted
    /// reservations proves the two-phase reserve→promote installs the demux
    /// entries correctly.
    #[test]
    fn reserve_before_send_then_promote() {
        let (init, resp, init_pub, resp_pub) = engine_pair();
        let mut msg1 = [0u8; WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();
        let mut msg2 = [0u8; WG_MSG_RESPONSE_LEN];
        resp.consume_initiation_create_response(&msg1, &mut msg2).unwrap();
        init.consume_response(&msg2).unwrap();
        assert_eq!(init.pending_count(), 0);
        assert_eq!(resp.pending_count(), 0);

        // init -> resp: decaps at the responder via its promoted index and
        // confirms the (initially unconfirmed) responder session.
        let fwd = ipv4_packet(Ipv4Addr::new(10, 9, 9, 1), Ipv4Addr::new(10, 9, 9, 2));
        let mut w = [0u8; 2048];
        let e = init.try_encap(&resp_pub, &fwd, &mut w).unwrap();
        let mut p = [0u8; 2048];
        let d = resp.try_decap(&w[..e.len], &mut p).unwrap();
        assert_eq!(d.peer_pubkey, init_pub);

        // resp -> init: decaps at the initiator via its promoted index.
        let reply = ipv4_packet(Ipv4Addr::new(10, 9, 9, 2), Ipv4Addr::new(10, 9, 9, 1));
        let mut w2 = [0u8; 2048];
        let e2 = resp.try_encap(&init_pub, &reply, &mut w2).unwrap();
        let mut p2 = [0u8; 2048];
        let d2 = init.try_decap(&w2[..e2.len], &mut p2).unwrap();
        assert_eq!(d2.peer_pubkey, resp_pub);
    }

    /// A forged/garbled msg2 (valid framing + valid MAC1, since MAC1 keys on
    /// the public initiator pubkey, but a corrupt Noise body) must NOT
    /// destroy the initiator's pending reservation: the real msg2 that
    /// arrives afterward must still complete the handshake. This is the
    /// Codex code-review-round-1 finding 2 regression (an on-path observer
    /// could otherwise DoS the handshake by racing a bogus msg2).
    #[test]
    fn forged_msg2_does_not_destroy_pending_reservation() {
        let (init, resp, init_pub, resp_pub) = engine_pair();
        let mut msg1 = [0u8; WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();
        assert_eq!(init.pending_count(), 1);

        // Produce the REAL msg2 from the responder.
        let mut real_msg2 = [0u8; WG_MSG_RESPONSE_LEN];
        resp.consume_initiation_create_response(&msg1, &mut real_msg2)
            .unwrap();

        // Forge a msg2: copy the real one (so type/receiver_index/MAC1
        // verify), then corrupt the Noise body so the snow read fails. MAC1
        // covers msg[0..60]; the Noise body is msg[12..60], so corrupting a
        // body byte breaks the Noise AEAD but NOT mac1... wait — mac1 DOES
        // cover the body. So instead corrupt a byte the Noise read
        // authenticates but mac1 also covers: to get a valid-mac1 forgery we
        // must recompute mac1 over the corrupted prefix. Simplest faithful
        // forgery: rebuild a msg2 with the right receiver_index + a random
        // Noise body + a correctly-recomputed mac1 over OUR pubkey.
        let mut forged = real_msg2;
        // Corrupt the encrypted-empty AEAD tag region (msg[44..60]) so the
        // Noise read fails, then recompute mac1 over msg[0..60] so framing
        // still authenticates (mac1 keys on the initiator = us, a public key,
        // so an attacker can do exactly this).
        forged[50] ^= 0xFF;
        let recomputed = crate::afxdp::wg::handshake::compute_mac1(&init_pub, &forged[..60]);
        forged[60..76].copy_from_slice(&recomputed);

        // The forged msg2 fails the Noise read but must leave the reservation
        // intact.
        let err = init.consume_response(&forged).unwrap_err();
        assert_eq!(err, HandshakeError::Crypto);
        assert_eq!(
            init.pending_count(),
            1,
            "a forged msg2 must NOT consume/destroy the pending reservation"
        );

        // The REAL msg2 still completes the handshake.
        init.consume_response(&real_msg2)
            .expect("real msg2 must still complete after a forged one was rejected");
        assert_eq!(init.pending_count(), 0);
    }

    /// reconcile_peers must drain a removed peer's in-flight handshake
    /// reservation from both `pending` and `pending_by_peer` (Copilot
    /// code-review finding). Otherwise the reservation + its consumed index
    /// leak until process restart.
    #[test]
    fn reconcile_drains_removed_peer_pending_reservation() {
        let (init, _resp, _init_pub, resp_pub) = engine_pair();
        // Start an initiation (reserves a pending handshake for resp_pub) but
        // do not complete it.
        let mut msg1 = [0u8; WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();
        assert_eq!(init.pending_count(), 1);

        // Reconcile the peer away (empty config removes resp_pub).
        init.reconcile_peers(&[]);

        // The pending reservation must be drained.
        assert_eq!(
            init.pending_count(),
            0,
            "removing a peer must drain its in-flight handshake reservation"
        );

        // Re-add the peer; a fresh initiation must succeed (the per-peer
        // marker was cleared, so the at-most-one-pending invariant is intact).
        init.reconcile_peers(&[WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }]);
        let mut msg1b = [0u8; WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut msg1b).unwrap();
        assert_eq!(init.pending_count(), 1);
    }

    /// reserve_pending_locked re-checks the peer UNDER reconcile_lock (Codex
    /// round-3 TOCTOU finding). The simple sequential case: create_initiation
    /// after the peer is removed returns UnknownPeer and reserves nothing.
    #[test]
    fn create_initiation_after_peer_removed_leaves_no_reservation() {
        let (init, _resp, _init_pub, resp_pub) = engine_pair();
        init.reconcile_peers(&[]);
        let mut msg1 = [0u8; WG_MSG_INIT_LEN];
        assert_eq!(
            init.create_initiation(&resp_pub, &mut msg1).unwrap_err(),
            HandshakeError::UnknownPeer
        );
        assert_eq!(init.pending_count(), 0);
    }

    /// Deterministic TOCTOU regression (Codex round-4): exercise the exact
    /// fixed branch — the under-lock peer recheck in reserve_pending_locked —
    /// rather than rely on a narrow race a concurrency test can't reliably
    /// hit. `try_reserve_pending_for_test` acquires reconcile_lock and calls
    /// reserve_pending_locked just as the completion paths do; after the peer
    /// is removed it must return UnknownPeer and create NO reservation.
    /// Without the under-lock recheck this reservation would be created and
    /// leak (reconcile's drain iterates the current table's pubkeys, which no
    /// longer include the removed peer).
    #[test]
    fn reserve_pending_locked_rejects_removed_peer() {
        use crate::afxdp::wg::session::SessionRole;
        let (init, _resp, _init_pub, resp_pub) = engine_pair();
        // Peer present: reserving succeeds.
        let idx = init
            .try_reserve_pending_for_test(resp_pub, SessionRole::Initiator)
            .expect("reserve must succeed while the peer is configured");
        assert_eq!(init.pending_count(), 1);
        // Drain it so we start clean.
        init.reconcile_peers(&[]);
        assert_eq!(init.pending_count(), 0);
        let _ = idx;

        // Re-add then remove to mimic the published-table state at the moment
        // a TOCTOU create would acquire the lock: peer absent from the table.
        init.reconcile_peers(&[]);
        // Now reserve under the lock for the (absent) peer — the under-lock
        // recheck must reject it.
        assert_eq!(
            init.try_reserve_pending_for_test(resp_pub, SessionRole::Initiator)
                .unwrap_err(),
            HandshakeError::UnknownPeer
        );
        assert_eq!(
            init.pending_count(),
            0,
            "reserve_pending_locked must not create a reservation for a removed peer"
        );
    }

    /// #6227 item 5, RED-on-revert: a prior panic while holding
    /// `reconcile_lock` poisons it. Before the fix every handshake-session
    /// call site did `self.reconcile_lock.lock().unwrap()`, so the NEXT
    /// caller — on the control thread, nothing to do with the panicking
    /// thread — would panic too, tearing down the whole tunnel's handshake
    /// path over one contained, unrelated panic. `lock_recover` (the #1807 /
    /// #2402 poison-recovery policy) must instead clear the poison and
    /// proceed. Reverting `lock_recover` back to `self.reconcile_lock.lock()
    /// .unwrap()` turns this RED (the call below panics instead of
    /// returning `Ok`).
    #[test]
    fn reserve_pending_recovers_from_a_poisoned_reconcile_lock() {
        use crate::afxdp::wg::handshake_session::WG_HANDSHAKE_LOCK_POISON_RECOVERIES;
        use crate::afxdp::wg::session::SessionRole;
        use std::sync::atomic::Ordering as AOrd;
        use std::sync::Arc as StdArc;

        let (init, _resp, _init_pub, resp_pub) = engine_pair();
        let init = StdArc::new(init);

        // Poison reconcile_lock: a thread takes it and panics while holding
        // it (the #1790/#1807 poisoning shape — a contained panic elsewhere,
        // NOT a corrupted invariant under the lock: the guarded state is `()`
        // for reconcile_lock, so there is nothing to corrupt).
        let poisoner = init.clone();
        let result = std::thread::spawn(move || {
            let _guard = poisoner.reconcile_lock.lock().unwrap();
            panic!("simulated panic while holding reconcile_lock");
        })
        .join();
        assert!(result.is_err(), "poisoning thread must panic");
        assert!(init.reconcile_lock.is_poisoned(), "lock must be poisoned");

        let before = WG_HANDSHAKE_LOCK_POISON_RECOVERIES.load(AOrd::Relaxed);

        // Any handshake-session call that takes reconcile_lock must recover,
        // not propagate the poison to this unrelated caller.
        let idx = init
            .try_reserve_pending_for_test(resp_pub, SessionRole::Initiator)
            .expect("reserve_pending must recover from a poisoned reconcile_lock, not panic");
        assert_eq!(init.pending_count(), 1);
        let _ = idx;

        assert!(
            WG_HANDSHAKE_LOCK_POISON_RECOVERIES.load(AOrd::Relaxed) > before,
            "a poisoned-lock recovery must bump the counter"
        );
        assert!(
            !init.reconcile_lock.is_poisoned(),
            "recovery must clear_poison so subsequent callers take the fast path"
        );
    }

    /// Liveness/soundness smoke: hammer full handshakes while a thread churns
    /// the peer in/out via reconcile_peers, exercising the lock serialization
    /// and the reconcile-drains-pending path. Must not panic/deadlock and a
    /// post-storm clean handshake must still carry traffic.
    #[test]
    fn create_initiation_toctou_under_concurrent_peer_removal() {
        use std::sync::atomic::{AtomicBool, Ordering as AOrd};
        use std::sync::Arc as StdArc;
        use std::thread;

        let (init_priv, _init_pub) = keypair();
        let (_resp_priv, resp_pub) = keypair();
        let cfg = vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }];
        let init = StdArc::new(WgEngine::new(WgEngineConfig {
            local_private_key: init_priv.into(),
            listen_port: 51820,
            peers: cfg.clone(),
        }));
        let stop = StdArc::new(AtomicBool::new(false));
        let initiator = {
            let init = init.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                for _ in 0..3000 {
                    let mut msg1 = [0u8; WG_MSG_INIT_LEN];
                    let _ = init.create_initiation(&resp_pub, &mut msg1);
                }
                stop.store(true, AOrd::Relaxed);
            })
        };
        let churner = {
            let init = init.clone();
            let stop = stop.clone();
            let cfg = cfg.clone();
            thread::spawn(move || {
                while !stop.load(AOrd::Relaxed) {
                    init.reconcile_peers(&[]);
                    init.reconcile_peers(&cfg);
                    thread::yield_now();
                }
            })
        };
        initiator.join().unwrap();
        churner.join().unwrap();
        // Settle peer-removed: no reservation may remain for the absent peer.
        init.reconcile_peers(&[]);
        assert_eq!(init.pending_count(), 0, "no orphan reservation after the storm");
    }

    /// Concurrency regression for the Codex round-2 finding: completing a
    /// handshake (create_initiation → consume_initiation_create_response →
    /// consume_response) must be sound under a concurrent thread hammering
    /// reconcile_peers (add/remove the peer), which exercises the
    /// reconcile-drains-pending path and the reconcile_lock serialization of
    /// the now-lock-held completion. Must not panic, deadlock, or corrupt the
    /// maps.
    ///
    /// Note we do NOT race a second same-peer create_initiation against the
    /// SAME in-flight handshake: that is the at-most-one-pending-per-peer
    /// abort (latest-initiation-wins), which legitimately starves the older
    /// reservation and is not a soundness violation. The reconcile thread is
    /// the right concurrency stressor for the lock discipline.
    #[test]
    fn concurrent_consume_response_and_reinitiation_is_sound() {
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as AOrd};
        use std::sync::Arc as StdArc;
        use std::thread;

        // Two engines that know each other. Wrap in Arc for sharing.
        let (init_priv, init_pub) = keypair();
        let (resp_priv, resp_pub) = keypair();
        let any_v4: Vec<ipnet::IpNet> = vec!["0.0.0.0/0".parse().unwrap()];
        let init = StdArc::new(WgEngine::new(WgEngineConfig {
            local_private_key: init_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: resp_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: any_v4.clone(),
                preshared_key: [0u8; 32].into(),
            }],
        }));
        let resp = StdArc::new(WgEngine::new(WgEngineConfig {
            local_private_key: resp_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: init_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: any_v4,
                preshared_key: [0u8; 32].into(),
            }],
        }));

        let stop = StdArc::new(AtomicBool::new(false));
        let completed = StdArc::new(AtomicU32::new(0));

        // Driver thread: full handshakes init<->resp, repeatedly.
        let driver = {
            let init = init.clone();
            let resp = resp.clone();
            let completed = completed.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                // #7650: loop until enough handshakes have COMPLETED, not for a
                // fixed iteration count.
                //
                // The floor below ("no handshake completed — the race path was
                // not exercised") is an anti-vacuity precondition, and with a
                // fixed 400 iterations it was a reading of the machine: the
                // reconciler removes the peer for part of every cycle, so on a
                // loaded box a run can spend all 400 attempts inside removal
                // windows, take the `continue` every time, and fire the floor
                // with zero completions — while soundness, the actual property,
                // was never in question.
                //
                // Running until the observation is made removes that
                // sensitivity without weakening anything: the reconciler churns
                // throughout, so every completion counted here is still a
                // CONTENDED one. The attempt cap only stops a genuinely broken
                // engine from hanging the suite, and is far above what a healthy
                // run needs (a healthy run reaches the target in well under 400).
                const TARGET_COMPLETIONS: u32 = 8;
                const MAX_ATTEMPTS: u32 = 200_000;
                let mut attempts = 0u32;
                while completed.load(AOrd::Relaxed) < TARGET_COMPLETIONS && attempts < MAX_ATTEMPTS
                {
                    attempts += 1;
                    let mut msg1 = [0u8; WG_MSG_INIT_LEN];
                    if init.create_initiation(&resp_pub, &mut msg1).is_err() {
                        thread::yield_now();
                        continue;
                    }
                    let mut msg2 = [0u8; WG_MSG_RESPONSE_LEN];
                    if resp
                        .consume_initiation_create_response(&msg1, &mut msg2)
                        .is_err()
                    {
                        thread::yield_now();
                        continue;
                    }
                    if init.consume_response(&msg2).is_ok() {
                        completed.fetch_add(1, AOrd::Relaxed);
                    }
                    thread::yield_now();
                }
                stop.store(true, AOrd::Relaxed);
            })
        };

        // Reconcile thread on the RESPONDER: churn the initiator peer in/out
        // while the driver completes handshakes, exercising the
        // reconcile-drains-pending path and the reconcile_lock serialization
        // concurrently with the lock-held responder completion.
        let reconciler = {
            let resp = resp.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let cfg = vec![WgPeerConfig {
                    pubkey: init_pub,
                    endpoint: None,
                    persistent_keepalive: 0,
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                    preshared_key: [0u8; 32].into(),
                }];
                let mut flip = false;
                while !stop.load(AOrd::Relaxed) {
                    // Alternate remove/re-add to exercise the
                    // reconcile-drains-pending path against in-flight
                    // responder reservations.
                    if flip {
                        resp.reconcile_peers(&[]);
                    } else {
                        resp.reconcile_peers(&cfg);
                    }
                    flip = !flip;
                    thread::yield_now();
                }
                // Leave the peer present so the post-storm handshake works.
                resp.reconcile_peers(&cfg);
            })
        };

        driver.join().unwrap();
        reconciler.join().unwrap();

        // The race must have exercised real completions. The driver loops until
        // it reaches this, so a failure here means the engine could not complete
        // a handshake in 200k contended attempts — a real defect, not a slow
        // machine (#7650).
        let done = completed.load(AOrd::Relaxed);
        assert!(
            done >= 8,
            "only {done} handshakes completed in up to 200k contended attempts — \
             the race path was not exercised, so the soundness checks below \
             cannot be interpreted. This is an anti-vacuity PRECONDITION, not \
             the property: nothing here says the maps are corrupt (#7650)"
        );

        // Soundness: after the storm, drive ONE clean handshake and a
        // transport round-trip; if the maps were corrupted the encap/decap
        // would fail.
        let mut m1 = [0u8; WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut m1).unwrap();
        let mut m2 = [0u8; WG_MSG_RESPONSE_LEN];
        resp.consume_initiation_create_response(&m1, &mut m2).unwrap();
        init.consume_response(&m2).unwrap();
        let pkt = ipv4_packet(Ipv4Addr::new(10, 9, 9, 1), Ipv4Addr::new(10, 9, 9, 2));
        let mut w = [0u8; 2048];
        let e = init.try_encap(&resp_pub, &pkt, &mut w).unwrap();
        let mut p = [0u8; 2048];
        let d = resp.try_decap(&w[..e.len], &mut p).unwrap();
        assert_eq!(&p[..d.len], &pkt[..], "post-storm handshake must still carry traffic");
    }
}

// ---------------------------------------------------------------------
// #1432 S2a — datapath wiring tests (control-thread coupling helpers).
// ---------------------------------------------------------------------

#[test]
fn wg_request_handshake_is_rate_limited_per_interval() {
    use super::engine::WG_HANDSHAKE_REQUEST_MIN_INTERVAL_NS;
    let (_resp_priv, pk) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: keypair().0.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: pk,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    // First edge at t=0 records.
    assert!(engine.request_handshake(&pk, 0), "first request must record an edge");
    // A flood within the interval must NOT record additional edges.
    for t in 1..1000u64 {
        assert!(
            !engine.request_handshake(&pk, t),
            "request within the rate-limit interval must be suppressed at t={t}"
        );
    }
    // After the interval elapses, a fresh edge is allowed again.
    assert!(
        engine.request_handshake(&pk, WG_HANDSHAKE_REQUEST_MIN_INTERVAL_NS + 1),
        "request after the interval must record a fresh edge"
    );
}

#[test]
fn wg_take_handshake_request_consumes_a_single_edge() {
    let (_resp_priv, pk) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: keypair().0.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: pk,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    assert!(!engine.take_handshake_request(&pk), "no edge pending initially");
    engine.request_handshake(&pk, 0);
    assert!(engine.take_handshake_request(&pk), "pending edge must be taken");
    assert!(
        !engine.take_handshake_request(&pk),
        "edge must be cleared after one take"
    );
}

/// #5164: build a two-peer engine whose peers sort A < B by pubkey, so A is
/// the "first-sorted" peer whose iteration runs first in the control thread's
/// pubkey-sorted per-peer loop (`engine.peer_pubkeys()` returns table order).
fn two_peer_engine_sorted() -> (WgEngine, [u8; 32], [u8; 32]) {
    let (_a, k1) = keypair();
    let (_b, k2) = keypair();
    let (peer_a, peer_b) = if k1 < k2 { (k1, k2) } else { (k2, k1) };
    assert!(peer_a < peer_b, "A must sort strictly before B");
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: keypair().0.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: peer_a,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: peer_b,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            },
        ],
    });
    (engine, peer_a, peer_b)
}

/// #5164 fail-on-revert: the NoSession handshake-request edge is PER PEER — an
/// edge raised by higher-sorted peer B must be consumed by B's own attempt
/// machine, and the lower-sorted peer A's iteration (which runs first in the
/// pubkey-sorted control loop) must NOT drain it. With the pre-#5164
/// engine-GLOBAL `AtomicBool`, A's `take_handshake_request` drained the single
/// shared edge, so B never saw its NoSession edge and — with no keepalive to
/// re-arm it — was BLACKHOLED. Reverting the per-peer scoping to a shared edge
/// makes the "A must not drain B" assertion RED.
#[test]
fn wg_handshake_request_edge_is_per_peer_not_drained_by_lower_sorted_sibling() {
    let (engine, peer_a, peer_b) = two_peer_engine_sorted();

    // Higher-sorted peer B's egress hit NoSession and armed ITS edge.
    assert!(
        engine.request_handshake(&peer_b, 0),
        "B arms its own handshake-request edge"
    );

    // The lower-sorted peer A runs FIRST in the control loop. It must NOT
    // consume B's edge (the #5164 blackhole).
    assert!(
        !engine.take_handshake_request(&peer_a),
        "lower-sorted peer A must NOT drain an edge raised for B (#5164 blackhole)"
    );
    // B's own iteration consumes B's edge.
    assert!(
        engine.take_handshake_request(&peer_b),
        "B's iteration consumes B's own handshake-request edge"
    );
    // Consume-once, per peer.
    assert!(
        !engine.take_handshake_request(&peer_b),
        "B's edge is cleared after B's own take"
    );

    // Symmetry: an edge for A is likewise private to A (B must not drain it).
    assert!(engine.request_handshake(&peer_a, 0), "A arms its own edge");
    assert!(
        !engine.take_handshake_request(&peer_b),
        "B must NOT drain an edge raised for A"
    );
    assert!(engine.take_handshake_request(&peer_a), "A consumes its own edge");
}

/// #5164 fail-on-revert (rekey edge): identical ownership contract for the
/// "session is stale, rekey" edge. A stale-session rekey armed by peer B must
/// drive B's attempt, not be drained by lower-sorted peer A. Reverting to the
/// engine-global rekey `AtomicBool` makes the "A must not drain B" assert RED.
#[test]
fn wg_rekey_request_edge_is_per_peer_not_drained_by_lower_sorted_sibling() {
    let (engine, peer_a, peer_b) = two_peer_engine_sorted();

    // Peer B's stale session armed ITS rekey edge (T1/T2/T3 use sites).
    engine.request_rekey(&peer_b);

    assert!(
        !engine.take_rekey_request(&peer_a),
        "lower-sorted peer A must NOT drain B's rekey edge (#5164)"
    );
    assert!(
        engine.take_rekey_request(&peer_b),
        "B's iteration consumes B's own rekey edge"
    );
    assert!(
        !engine.take_rekey_request(&peer_b),
        "B's rekey edge is cleared after B's own take"
    );

    // Symmetry.
    engine.request_rekey(&peer_a);
    assert!(
        !engine.take_rekey_request(&peer_b),
        "B must NOT drain an edge raised for A"
    );
    assert!(engine.take_rekey_request(&peer_a), "A consumes its own rekey edge");
}

#[test]
fn wg_no_session_encap_triggers_single_init_per_interval() {
    use super::engine::WG_HANDSHAKE_REQUEST_MIN_INTERVAL_NS;
    // Engine with a configured peer but no installed session: try_encap
    // returns NoSession, and the control-thread coupling fires exactly
    // one edge per interval under a flood (the rate-limiter bound).
    let (_init_priv, init_pub) = keypair();
    let (_resp_priv, resp_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: _init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let _ = init_pub;
    let pkt = ipv4_packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
    let mut out = [0u8; 2048];
    // Simulate a flood of NoSession packets at the same instant; the
    // control-thread edge must fire exactly once.
    let mut edges = 0usize;
    for _ in 0..256 {
        match engine.try_encap(&resp_pub, &pkt, &mut out) {
            Err(EncapError::NoSession) => {
                if engine.request_handshake(&resp_pub, 0) {
                    edges += 1;
                }
            }
            other => panic!("expected NoSession, got {other:?}"),
        }
    }
    assert_eq!(edges, 1, "exactly one handshake edge per interval under flood");
    // The control thread consumes the single edge.
    assert!(engine.take_handshake_request(&resp_pub));
    // After the interval, another flood produces one more edge.
    assert!(engine.request_handshake(&resp_pub, WG_HANDSHAKE_REQUEST_MIN_INTERVAL_NS + 1));
}

#[test]
fn wg_first_peer_pubkey_and_confirmed_session_helpers() {
    let (init_engine, _resp_engine, _init_pub, resp_pub) =
        established_pair(vec!["10.0.0.0/24".parse().unwrap()], vec!["10.0.0.0/24".parse().unwrap()]);
    assert_eq!(
        init_engine.first_peer_pubkey(),
        Some(resp_pub),
        "first_peer_pubkey returns the configured peer"
    );
    // The initiator session is installed pre-confirmed.
    assert!(
        init_engine.peer_has_confirmed_session(&resp_pub),
        "established initiator session is confirmed"
    );
    // An engine with a peer but no session reports no confirmed session.
    let no_session = WgEngine::new(WgEngineConfig {
        local_private_key: keypair().0.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![],
            preshared_key: [0u8; 32].into(),
        }],
    });
    assert!(!no_session.peer_has_confirmed_session(&resp_pub));
}

#[test]
fn wg_tai64n_high_water_seed_round_trips_across_engines() {
    // The reload path seeds a fresh engine's TAI64N high-water from the
    // prior engine so initiator-timestamp monotonicity survives a
    // config change rebuild.
    let priv_key = keypair().0;
    let resp_pub = keypair().1;
    let old = WgEngine::new(WgEngineConfig {
        local_private_key: priv_key.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![],
            preshared_key: [0u8; 32].into(),
        }],
    });
    // Drive an initiation so the clock advances past its initial state.
    let mut out = [0u8; super::WG_MSG_INIT_LEN];
    old.create_initiation(&resp_pub, &mut out).unwrap();
    let hw = old.tai64n_high_water().expect("clock advanced");

    let fresh = WgEngine::new(WgEngineConfig {
        local_private_key: priv_key.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![],
            preshared_key: [0u8; 32].into(),
        }],
    });
    fresh.seed_tai64n_high_water(hw);
    let fresh_hw = fresh.tai64n_high_water().expect("seeded");
    assert!(
        fresh_hw >= hw,
        "seeded high-water must be >= the prior engine's: {fresh_hw:?} >= {hw:?}"
    );
}

#[test]
fn wg_greatest_tai64n_carry_over_preserves_responder_anti_replay() {
    // #4103: the #4092 responder anti-replay high-water is per-peer, so
    // an identity-change engine rebuild must carry each surviving peer's
    // `greatest_tai64n` forward — keyed by pubkey — or the anti-replay is
    // silently disarmed. Reverting the engine carry-over API resets the
    // fresh peer to [0; 12] and the replayed-stamp assertions below go RED
    // (the replay would be accepted).
    let priv_key = keypair().0;
    let resp_pub = keypair().1;
    let mk = || WgEngineConfig {
        local_private_key: priv_key.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![],
            preshared_key: [0u8; 32].into(),
        }],
    };
    let old = WgEngine::new(mk());
    // Simulate a valid accepted initiation advancing the high-water.
    let t_last: [u8; super::tai64n::TAI64N_LEN] =
        [0x40, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    old.seed_greatest_tai64n(&[(resp_pub, t_last)]);
    assert_eq!(old.greatest_tai64n_by_pubkey(), vec![(resp_pub, t_last)]);

    // Identity-change rebuild starts from a fresh (all-zero) peer; carry
    // the prior engine's per-peer high-water forward.
    let fresh = WgEngine::new(mk());
    fresh.seed_greatest_tai64n(&old.greatest_tai64n_by_pubkey());
    assert_eq!(
        fresh.greatest_tai64n_by_pubkey(),
        vec![(resp_pub, t_last)],
        "carried-over high-water must equal the prior engine's"
    );

    // The carried value gates the anti-replay: a stamp `<= t_last` is a
    // replay (reject); a strictly greater stamp is fresh (accept).
    let table = fresh.load_table();
    let idx = table.peer_index_by_pubkey[&resp_pub];
    let peer = &table.peers[idx as usize].peer;
    assert!(
        !peer.check_and_update_tai64n(&t_last),
        "equal-stamp replay must be rejected after carry-over"
    );
    let older = [0x40u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(
        !peer.check_and_update_tai64n(&older),
        "older-stamp replay must be rejected after carry-over"
    );
    let newer: [u8; super::tai64n::TAI64N_LEN] =
        [0x40, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89];
    assert!(
        peer.check_and_update_tai64n(&newer),
        "strictly newer stamp must be accepted"
    );

    // A pubkey NOT in the snapshot (a re-keyed / new peer) correctly
    // starts fresh at [0; 12] — seeding is a no-op for it.
    let other_pub = keypair().1;
    let other = WgEngine::new(WgEngineConfig {
        local_private_key: priv_key.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: other_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![],
            preshared_key: [0u8; 32].into(),
        }],
    });
    other.seed_greatest_tai64n(&old.greatest_tai64n_by_pubkey());
    assert_eq!(
        other.greatest_tai64n_by_pubkey(),
        vec![(other_pub, [0u8; super::tai64n::TAI64N_LEN])],
        "a new/changed pubkey must NOT inherit another peer's high-water"
    );
}

#[test]
fn wg_request_handshake_single_edge_under_concurrent_callers() {
    // Copilot: a plain load+store let multiple concurrent NoSession
    // callers all observe the stale `last` and each re-arm the edge. The
    // CAS claim guarantees exactly one caller wins the rate-limit window
    // per interval. Spawn N threads all calling request_handshake(now=1)
    // simultaneously; exactly one must observe `true`.
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_resp_priv, pk) = keypair();
    let engine = StdArc::new(WgEngine::new(WgEngineConfig {
        local_private_key: keypair().0.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: pk,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    }));
    let wins = StdArc::new(AtomicUsize::new(0));
    let start = StdArc::new(std::sync::Barrier::new(16));
    let mut handles = Vec::new();
    for _ in 0..16 {
        let e = engine.clone();
        let w = wins.clone();
        let b = start.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            // All callers use the same timestamp inside one interval.
            if e.request_handshake(&pk, 1) {
                w.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        wins.load(Ordering::Relaxed),
        1,
        "exactly one concurrent caller must win the rate-limit window"
    );
    assert!(engine.take_handshake_request(&pk), "the winning edge is pending");
}

// ===================================================================
// #1865: operator-visible telemetry counter tests. Each asserts the
// EXACT counter that must move (and key neighbors that must NOT) for
// the plan §6 scenarios, plus the keepalive classification regression.
// ===================================================================
mod telemetry_counters {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Full framed handshake: created/completed counters both roles,
    /// completion stamp set, and the responder confirmation flip via
    /// the first inbound record.
    #[test]
    fn framed_handshake_moves_handshake_counters() {
        let (init, resp, _init_pub, resp_pub) = framed_engine_pair();

        let mut msg1 = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();
        let ic = init.counters();
        assert_eq!(ic.hs_initiations_created.load(Ordering::Relaxed), 1);
        assert_eq!(ic.hs_initiation_build_failures.load(Ordering::Relaxed), 0);
        assert_eq!(
            ic.last_handshake_complete_ns.load(Ordering::Relaxed),
            0,
            "creation alone is NOT completion"
        );

        let mut msg2 = [0u8; crate::afxdp::wg::WG_MSG_RESPONSE_LEN];
        resp.consume_initiation_create_response(&msg1, &mut msg2)
            .unwrap();
        let rc = resp.counters();
        assert_eq!(rc.hs_responses_created.load(Ordering::Relaxed), 1);
        assert!(
            rc.last_handshake_complete_ns.load(Ordering::Relaxed) > 0,
            "responder completion stamps the handshake time"
        );

        init.consume_response(&msg2).unwrap();
        assert_eq!(ic.hs_completions_initiator.load(Ordering::Relaxed), 1);
        assert!(ic.last_handshake_complete_ns.load(Ordering::Relaxed) > 0);

        // Transport round-trip moves packet/byte counters symmetrically.
        let inner = ipv4_packet(Ipv4Addr::new(10, 1, 1, 1), Ipv4Addr::new(10, 1, 1, 2));
        let mut wire = [0u8; 2048];
        let enc = init.try_encap(&resp_pub, &inner, &mut wire).unwrap();
        let mut plain = [0u8; 2048];
        resp.try_decap(&wire[..enc.len], &mut plain).unwrap();
        assert_eq!(ic.encap_packets.load(Ordering::Relaxed), 1);
        assert_eq!(
            ic.encap_bytes.load(Ordering::Relaxed),
            inner.len() as u64,
            "encap bytes are inner-IP (un-padded) bytes"
        );
        assert_eq!(rc.decap_packets.load(Ordering::Relaxed), 1);
        assert_eq!(rc.decap_bytes.load(Ordering::Relaxed), inner.len() as u64);
    }

    /// The keepalive regression (Codex r1 F1 + SMR r1 F1): an
    /// authenticated ZERO-length transport record counts as
    /// `decap_keepalives` — NOT `decap_drops_malformed_inner` — while
    /// the external contract (Err, replay window advanced) and the
    /// confirmation side-effect are unchanged.
    #[test]
    fn zero_length_record_counts_keepalive_not_malformed_inner() {
        let (init_engine, resp_engine, init_pub, resp_pub) = established_pair(
            vec!["0.0.0.0/0".parse().unwrap()],
            vec!["0.0.0.0/0".parse().unwrap()],
        );
        let mut wire = [0u8; 256];
        let enc = init_engine.try_encap(&resp_pub, &[], &mut wire).unwrap();
        // pad_to_16(0) == 0: header + tag only.
        assert_eq!(
            enc.len,
            crate::afxdp::wg::WG_DATA_HEADER_LEN + crate::afxdp::wg::POLY1305_TAG_LEN
        );
        let mut plain = [0u8; 256];
        let err = resp_engine
            .try_decap(&wire[..enc.len], &mut plain)
            .unwrap_err();
        assert_eq!(
            err,
            DecapError::MalformedInner,
            "external error contract unchanged (keepalive still not deliverable)"
        );
        let rc = resp_engine.counters();
        assert_eq!(rc.decap_keepalives.load(Ordering::Relaxed), 1);
        assert_eq!(
            rc.decap_drops_malformed_inner.load(Ordering::Relaxed),
            0,
            "keepalives must NOT inflate the malformed-inner drop counter"
        );
        // Replay window advanced: replaying the identical record is a
        // replay drop, not a second keepalive.
        let err2 = resp_engine
            .try_decap(&wire[..enc.len], &mut plain)
            .unwrap_err();
        assert!(matches!(
            err2,
            DecapError::ReplayDuplicate | DecapError::ReplayOutOfWindow
        ));
        assert_eq!(rc.decap_keepalives.load(Ordering::Relaxed), 1);
        assert_eq!(rc.decap_drops_replay.load(Ordering::Relaxed), 1);
        let _ = (init_pub, init_engine);
    }

    /// MAC1-corrupted initiation → hs_rx_drops_mac1_mismatch (the
    /// wrong-key-peer live-validation case).
    #[test]
    fn mac1_mismatch_counts_on_responder() {
        let (init, _resp, _init_pub, resp_pub) = framed_engine_pair();
        let mut msg1 = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();
        // A responder with a DIFFERENT static key: mac1 keys on the
        // recipient pubkey, so this is the wrong-key-peer shape.
        let (other_priv, _) = keypair();
        let (_, init2_pub) = keypair();
        let other = WgEngine::new(WgEngineConfig {
            local_private_key: other_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: init2_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            }],
        });
        let mut msg2 = [0u8; crate::afxdp::wg::WG_MSG_RESPONSE_LEN];
        let _ = other
            .consume_initiation_create_response(&msg1, &mut msg2)
            .unwrap_err();
        assert_eq!(
            other.counters().hs_rx_drops_mac1_mismatch.load(Ordering::Relaxed),
            1
        );
        assert_eq!(other.counters().hs_responses_created.load(Ordering::Relaxed), 0);
    }

    /// AllowedIPs-violating inner → decap_drops_allowed_ips.
    #[test]
    fn allowed_ips_violation_counts() {
        let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
            vec!["0.0.0.0/0".parse().unwrap()],
            // Responder only accepts 10.7.0.0/16 from the initiator.
            vec!["10.7.0.0/16".parse().unwrap()],
        );
        let inner = ipv4_packet(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 7, 0, 2));
        let mut wire = [0u8; 2048];
        let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
        let mut plain = [0u8; 2048];
        let err = resp_engine
            .try_decap(&wire[..enc.len], &mut plain)
            .unwrap_err();
        assert_eq!(err, DecapError::AllowedIpsViolation);
        assert_eq!(
            resp_engine
                .counters()
                .decap_drops_allowed_ips
                .load(Ordering::Relaxed),
            1
        );
    }

    /// Truncated (sub-tag) record → decap_drops_malformed_header
    /// (ShortRecord folds into the malformed-header class).
    #[test]
    fn short_record_counts_malformed_header() {
        let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
            vec!["0.0.0.0/0".parse().unwrap()],
            vec!["0.0.0.0/0".parse().unwrap()],
        );
        let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        let mut wire = [0u8; 2048];
        let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
        let mut plain = [0u8; 2048];
        // Header intact, ciphertext truncated below the Poly1305 tag.
        let truncated = &wire[..crate::afxdp::wg::WG_DATA_HEADER_LEN + 8];
        let err = resp_engine.try_decap(truncated, &mut plain).unwrap_err();
        assert_eq!(err, DecapError::ShortRecord);
        assert_eq!(
            resp_engine
                .counters()
                .decap_drops_malformed_header
                .load(Ordering::Relaxed),
            1
        );
        let _ = enc;
    }

    /// The unconfirmed-vs-no-session split (AGY r2 #1736) under the
    /// #3882 3-slot keypair model. A fresh responder handshake parks the
    /// UNCONFIRMED keypair in `next`, leaving `current` empty, so egress
    /// reports NO-SESSION (the confirmed `current` — here absent — is
    /// what egress uses; the unconfirmed keypair never enters `current`).
    /// The `is_confirmed()` gate survives as a defense-in-depth
    /// invariant, verified here by forcing an unconfirmed session into
    /// `current`. An engine with a peer but no session at all bumps
    /// `encap_drops_no_session`.
    #[test]
    fn encap_no_session_vs_unconfirmed_split() {
        // Drive the framed handshake so the responder holds a real
        // (unconfirmed) session — which the 3-slot model parks in `next`.
        let (init, resp, init_pub, resp_pub) = framed_engine_pair();
        let mut msg1 = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();
        let mut msg2 = [0u8; crate::afxdp::wg::WG_MSG_RESPONSE_LEN];
        resp.consume_initiation_create_response(&msg1, &mut msg2)
            .unwrap();
        let inner = ipv4_packet(Ipv4Addr::new(10, 2, 2, 1), Ipv4Addr::new(10, 2, 2, 2));
        let mut wire = [0u8; 2048];
        // Egress with the keypair in `next` and `current` empty → the
        // no-session arm (NOT the unconfirmed gate): the 3-slot fix keeps
        // egress off the unconfirmed keypair without blackholing a
        // confirmed one.
        let err = resp.try_encap(&init_pub, &inner, &mut wire).unwrap_err();
        assert_eq!(err, EncapError::NoSession, "wire error contract unchanged");
        let rc = resp.counters();
        assert_eq!(
            rc.encap_drops_no_session.load(Ordering::Relaxed),
            1,
            "3-slot model: the unconfirmed responder keypair sits in `next`, current is empty"
        );
        assert_eq!(
            rc.encap_drops_unconfirmed.load(Ordering::Relaxed),
            0,
            "an unconfirmed keypair in `next` must not reach the current-session confirmed gate"
        );

        // Defense-in-depth: the egress `is_confirmed()` gate still
        // refuses if an UNCONFIRMED session ever occupies `current`.
        // Force the unconfirmed responder session from `next` into
        // `current` and confirm the gate — not the no-session arm —
        // fires.
        let unconfirmed = resp
            .peer_arc(&init_pub)
            .unwrap()
            .next
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        assert!(!unconfirmed.is_confirmed());
        resp.force_current_for_test(&init_pub, unconfirmed);
        let err_gate = resp.try_encap(&init_pub, &inner, &mut wire).unwrap_err();
        assert_eq!(err_gate, EncapError::NoSession, "wire error contract unchanged");
        assert_eq!(
            rc.encap_drops_unconfirmed.load(Ordering::Relaxed),
            1,
            "an unconfirmed session in `current` must bump the unconfirmed gate"
        );
        assert_eq!(
            rc.encap_drops_no_session.load(Ordering::Relaxed),
            1,
            "the unconfirmed gate must NOT masquerade as no-session (no new no_session drop)"
        );

        // No session at all: fresh engine, configured peer, no handshake.
        let (fresh, _resp2, _ip2, rp2) = framed_engine_pair();
        let err2 = fresh.try_encap(&rp2, &inner, &mut wire).unwrap_err();
        assert_eq!(err2, EncapError::NoSession);
        assert_eq!(
            fresh.counters().encap_drops_no_session.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            fresh.counters().encap_drops_unconfirmed.load(Ordering::Relaxed),
            0
        );
    }

    /// create_initiation toward an unconfigured peer →
    /// hs_initiation_build_failures (previously discarded by the
    /// `if let Ok` at the drive_initiation call site).
    #[test]
    fn initiation_build_failure_counts() {
        let (init, _resp, _init_pub, _resp_pub) = framed_engine_pair();
        let (_, stranger_pub) = keypair();
        let mut msg1 = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
        let _ = init.create_initiation(&stranger_pub, &mut msg1).unwrap_err();
        let ic = init.counters();
        assert_eq!(ic.hs_initiation_build_failures.load(Ordering::Relaxed), 1);
        assert_eq!(ic.hs_initiations_created.load(Ordering::Relaxed), 0);
    }

    /// request_handshake edge accounting: exactly the accepted edges
    /// count (the rate-limited duplicates do not).
    #[test]
    fn handshake_request_edges_count_accepted_only() {
        let (init, _resp, _init_pub, resp_pub) = framed_engine_pair();
        assert!(init.request_handshake(&resp_pub, 10));
        assert!(!init.request_handshake(&resp_pub, 20), "inside the rate window");
        assert_eq!(
            init.counters().hs_requests_armed.load(Ordering::Relaxed),
            1
        );
    }

    /// Counters survive an identity-UNCHANGED reconcile (same engine
    /// object; reconcile_peers must not disturb telemetry).
    #[test]
    fn counters_survive_identity_unchanged_reconcile() {
        let (init, _resp, _init_pub, resp_pub) = framed_engine_pair();
        let mut msg1 = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();
        assert_eq!(init.counters().hs_initiations_created.load(Ordering::Relaxed), 1);
        init.reconcile_peers(&[WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            preshared_key: [0u8; 32].into(),
        }]);
        assert_eq!(
            init.counters().hs_initiations_created.load(Ordering::Relaxed),
            1,
            "reconcile with unchanged identity must not disturb counters"
        );
    }

    /// Hex render of a pubkey matches the house wire convention
    /// (lowercase, 64 chars; inverse of decode_wg_key_hex).
    #[test]
    fn encode_wg_key_hex_roundtrip_shape() {
        let (_, pubkey) = keypair();
        let hex = crate::afxdp::wg::encode_wg_key_hex(&pubkey);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        let mut nib = 0u8;
        for (i, c) in hex.bytes().enumerate() {
            let v = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => unreachable!(),
            };
            if i % 2 == 0 {
                nib = v << 4;
            } else {
                assert_eq!(pubkey[i / 2], nib | v);
            }
        }
    }

    /// Local copy of framed_handshake::engine_pair (that helper is
    /// mod-private): two engines that know each other, 0.0.0.0/0.
    fn framed_engine_pair() -> (WgEngine, WgEngine, [u8; 32], [u8; 32]) {
        let (init_priv, init_pub) = keypair();
        let (resp_priv, resp_pub) = keypair();
        let any_v4: Vec<ipnet::IpNet> = vec!["0.0.0.0/0".parse().unwrap()];
        let init = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: resp_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: any_v4.clone(),
                preshared_key: [0u8; 32].into(),
            }],
        });
        let resp = WgEngine::new(WgEngineConfig {
            local_private_key: resp_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: init_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: any_v4,
                preshared_key: [0u8; 32].into(),
            }],
        });
        (init, resp, init_pub, resp_pub)
    }
}

// ===========================================================================
// #1888 S5: deterministic timer-semantics tests (mock engine clock).
//
// Fixture discipline: `established_pair` stamps `created_ns` from the
// real CLOCK_MONOTONIC at fixture time; tests capture `t0` immediately
// after and drive `set_mock_now_ns(t0 + offset)` with offsets that
// carry >= 1s of margin against the fixture's microsecond setup skew,
// so no assertion sits on an exact threshold boundary.
// ===========================================================================
mod s5_timer_tests {
    use super::super::counters::monotonic_now_ns;
    use super::super::session::SessionRole;
    use super::super::timers::{InitiateReason, KeepaliveKind, WG_NO_DEADLINE_NS};
    use super::*;
    use std::sync::atomic::Ordering;

    const SEC: u64 = 1_000_000_000;

    fn pair() -> (WgEngine, WgEngine, [u8; 32], [u8; 32], u64) {
        let (init, resp, init_pub, resp_pub) = super::established_pair(
            vec!["10.0.1.0/24".parse().unwrap()],
            vec!["10.0.0.0/24".parse().unwrap()],
        );
        let t0 = monotonic_now_ns();
        (init, resp, init_pub, resp_pub, t0)
    }

    fn inner_from_init() -> Vec<u8> {
        super::ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5))
    }

    fn inner_from_resp() -> Vec<u8> {
        super::ipv4_packet(Ipv4Addr::new(10, 0, 1, 5), Ipv4Addr::new(10, 0, 0, 5))
    }

    /// T1: a send on an initiator-role session older than
    /// REKEY_AFTER_TIME arms the rekey edge; younger does not; a
    /// responder-role session NEVER arms on age (initiator-only rule);
    /// pure aging without a send arms nothing.
    #[test]
    fn t1_rekey_edge_arms_on_send_past_120s_initiator_only() {
        let (init, resp, init_pub, resp_pub, t0) = pair();
        let mut wire = [0u8; 2048];

        // Aging alone arms nothing.
        init.set_mock_now_ns(t0 + 130 * SEC);
        assert!(!init.take_rekey_request(&resp_pub));

        // 118s: send does not arm (margin below the 120s threshold).
        init.set_mock_now_ns(t0 + 118 * SEC);
        init.try_encap(&resp_pub, &inner_from_init(), &mut wire)
            .unwrap();
        assert!(!init.take_rekey_request(&resp_pub), "below REKEY_AFTER_TIME");

        // 121s: send arms.
        init.set_mock_now_ns(t0 + 121 * SEC);
        init.try_encap(&resp_pub, &inner_from_init(), &mut wire)
            .unwrap();
        assert!(init.take_rekey_request(&resp_pub), "at/after REKEY_AFTER_TIME");
        assert!(!init.take_rekey_request(&resp_pub), "edge is consume-once");

        // Responder-role session: same age, no arm.
        resp.set_mock_now_ns(t0 + 121 * SEC);
        resp.try_encap(&init_pub, &inner_from_resp(), &mut wire)
            .unwrap();
        assert!(!resp.take_rekey_request(&init_pub), "responder never age-rekeys");
    }

    /// T3 encap: refused at/after REJECT_AFTER_TIME with the session's
    /// tx_counter untouched (on-Err contract), the expired counter
    /// bumped, and the rekey edge armed (send-side initiates).
    #[test]
    fn t3_encap_refused_at_180s_counter_untouched() {
        let (init, _resp, _init_pub, resp_pub, t0) = pair();
        let mut wire = [0u8; 2048];
        init.set_mock_now_ns(t0 + 181 * SEC);
        let err = init
            .try_encap(&resp_pub, &inner_from_init(), &mut wire)
            .unwrap_err();
        assert_eq!(err, EncapError::NoSession, "caller contract unchanged");
        assert_eq!(
            init.counters().encap_drops_expired.load(Ordering::Relaxed),
            1
        );
        assert!(init.take_rekey_request(&resp_pub), "send-side T3 arms the edge");
        let session = init
            .sessions_by_local_index
            .read()
            .unwrap()
            .get(&0xaaaa_0001)
            .cloned()
            .unwrap();
        assert_eq!(
            session.tx_counter.load(Ordering::Relaxed),
            0,
            "on Err the tx counter must be untouched"
        );
    }

    /// An engine whose peer carries a Responder-role session forced
    /// into `current` but left UNCONFIRMED, so the `is_confirmed()`
    /// term of `peer_has_confirmed_session` is exercised with a session
    /// actually present in `current`. The #3882 3-slot model parks a
    /// natural unconfirmed responder keypair in `next` (never
    /// `current`), so `force_current_for_test` is used to reach the
    /// gate directly. Returns the engine, the peer pubkey, and the
    /// session's `created_ns` stamp.
    fn unconfirmed_responder_in_current() -> (WgEngine, [u8; 32], u64) {
        let (init_priv, init_pub) = super::keypair();
        let (resp_priv, resp_pub) = super::keypair();
        let init_engine = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: resp_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
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
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
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
        let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
        let created_ns = monotonic_now_ns();
        let resp_session = Arc::new(WgSession::new_with_role(
            resp_xport,
            0xdead_0001,
            0xdead_0002,
            init_pub,
            SessionRole::Responder,
            created_ns,
        ));
        assert!(
            !resp_session.is_confirmed(),
            "responder session starts unconfirmed"
        );
        resp_engine.force_current_for_test(&init_pub, resp_session);
        (resp_engine, init_pub, created_ns)
    }

    /// #4546: `peer_has_confirmed_session` — the gate the control loop
    /// consults on the NoSession edge — must honor REJECT_AFTER_TIME so
    /// a confirmed-but-expired session (aged past 180s but not yet GC'd
    /// by `expire_sessions`) no longer masquerades as confirmed and
    /// suppresses the rekey trigger, a bounded ~0-1s blackhole at the
    /// expiry boundary. The age check uses the same mock-aware
    /// `now_ns()` clock as `try_encap`'s T3 gate.
    #[test]
    fn peer_has_confirmed_session_honors_reject_after_time() {
        let (init, _resp, _init_pub, resp_pub, t0) = pair();

        // Fresh confirmed initiator session → reports confirmed.
        init.set_mock_now_ns(t0 + 1 * SEC);
        assert!(
            init.peer_has_confirmed_session(&resp_pub),
            "fresh confirmed session reports confirmed"
        );

        // 179s (just under REJECT_AFTER_TIME) → still confirmed.
        init.set_mock_now_ns(t0 + 179 * SEC);
        assert!(
            init.peer_has_confirmed_session(&resp_pub),
            "confirmed session younger than REJECT_AFTER_TIME stays confirmed"
        );

        // 181s (past REJECT_AFTER_TIME) → NOT confirmed, so the
        // NoSession-edge rekey fires promptly instead of waiting for the
        // ~1s GC tick. [RED on revert: the age-blind check returns true.]
        init.set_mock_now_ns(t0 + 181 * SEC);
        assert!(
            !init.peer_has_confirmed_session(&resp_pub),
            "confirmed session past REJECT_AFTER_TIME must not report confirmed"
        );

        // A session present in `current` but UNCONFIRMED reports false
        // regardless of age (the preserved is_confirmed() term).
        let (unconf, peer_pub, created_ns) = unconfirmed_responder_in_current();
        unconf.set_mock_now_ns(created_ns + 1 * SEC);
        assert!(
            !unconf.peer_has_confirmed_session(&peer_pub),
            "unconfirmed current session reports false"
        );
    }

    /// T3 decap: an inbound record addressed to an expired session is
    /// dropped BEFORE AEAD with DecapError::Expired and does NOT arm
    /// the rekey edge (replay at an expired session must not drive our
    /// handshake cadence).
    #[test]
    fn t3_decap_refused_drop_only_no_rekey_arm() {
        let (init, resp, init_pub, resp_pub, t0) = pair();
        let mut wire = [0u8; 2048];
        let mut out = [0u8; 2048];
        // Responder encrypts while its own clock is fresh.
        resp.set_mock_now_ns(t0 + 1 * SEC);
        let enc = resp
            .try_encap(&init_pub, &inner_from_resp(), &mut wire)
            .unwrap();
        // Initiator's demuxed session is past 180s.
        init.set_mock_now_ns(t0 + 181 * SEC);
        let err = init.try_decap(&wire[..enc.len], &mut out).unwrap_err();
        assert_eq!(err, DecapError::Expired);
        assert_eq!(
            init.counters().decap_drops_expired.load(Ordering::Relaxed),
            1
        );
        assert!(
            !init.take_rekey_request(&resp_pub),
            "decap T3 is drop-only — no rekey arm"
        );
    }

    /// T2: receiving a transport record on an initiator-role session
    /// past the 165s horizon arms the rekey edge; a responder-role
    /// session at the same age does not.
    #[test]
    fn t2_recv_horizon_arms_initiator_only() {
        let (init, resp, init_pub, resp_pub, t0) = pair();
        let mut wire = [0u8; 2048];
        let mut out = [0u8; 2048];

        // Peer-to-initiator record, initiator at 166s.
        resp.set_mock_now_ns(t0 + 1 * SEC);
        let enc = resp
            .try_encap(&init_pub, &inner_from_resp(), &mut wire)
            .unwrap();
        init.set_mock_now_ns(t0 + 166 * SEC);
        init.try_decap(&wire[..enc.len], &mut out).unwrap();
        assert!(init.take_rekey_request(&resp_pub), "initiator receive past 165s");

        // Initiator-to-responder record, responder at 166s: no arm.
        init.set_mock_now_ns(t0 + 2 * SEC);
        let enc2 = init
            .try_encap(&resp_pub, &inner_from_init(), &mut wire)
            .unwrap();
        // The encap above stamped/armed init-side state; drain its edge.
        let _ = init.take_rekey_request(&resp_pub);
        resp.set_mock_now_ns(t0 + 166 * SEC);
        resp.try_decap(&wire[..enc2.len], &mut out).unwrap();
        assert!(!resp.take_rekey_request(&init_pub), "responder never age-rekeys");
    }

    /// expire_sessions tears down current sessions past 180s, removes
    /// their demux entries, and counts them.
    #[test]
    fn expire_sessions_removes_demux_entries() {
        let (init, _resp, _init_pub, resp_pub, t0) = pair();
        let now = t0 + 181 * SEC;
        let removed = init.expire_sessions(now);
        assert_eq!(removed, 1, "one current session expired");
        assert!(
            init.sessions_by_local_index
                .read()
                .unwrap()
                .get(&0xaaaa_0001)
                .is_none(),
            "demux entry removed"
        );
        assert_eq!(init.current_session_local_index(&resp_pub), None);
        assert_eq!(
            init.counters().sessions_expired.load(Ordering::Relaxed),
            1
        );
        // Idempotent.
        assert_eq!(init.expire_sessions(now), 0);
    }

    /// Keepalive encode: 32-byte record, consumes a tx counter, does
    /// NOT count as a data packet, does NOT arm T7; the receiving side
    /// counts it as a keepalive, stamps last_recv_any, and does NOT
    /// arm T6 (no keepalive ping-pong).
    #[test]
    fn keepalive_roundtrip_semantics() {
        let (init, resp, init_pub, resp_pub, t0) = pair();
        let mut wire = [0u8; 2048];
        let mut out = [0u8; 2048];
        init.set_mock_now_ns(t0 + 1 * SEC);
        let enc = init.create_keepalive(&resp_pub, &mut wire).unwrap();
        assert_eq!(
            enc.len,
            super::super::WG_DATA_HEADER_LEN + super::super::POLY1305_TAG_LEN,
            "keepalive is header + tag only"
        );
        assert_eq!(
            init.counters().encap_packets.load(Ordering::Relaxed),
            0,
            "keepalive is not a data packet"
        );
        let init_peer = init.peer_arc(&resp_pub).unwrap();
        assert_eq!(
            init_peer.t7_armed_send_ns.load(Ordering::Relaxed),
            0,
            "a sent keepalive must not arm T7"
        );
        assert_eq!(
            init_peer.last_send_any_ns.load(Ordering::Relaxed),
            t0 + 1 * SEC,
            "keepalive is an authenticated send"
        );
        let session = init
            .sessions_by_local_index
            .read()
            .unwrap()
            .get(&0xaaaa_0001)
            .cloned()
            .unwrap();
        assert_eq!(
            session.tx_counter.load(Ordering::Relaxed),
            1,
            "keepalive consumes a tx counter"
        );

        resp.set_mock_now_ns(t0 + 2 * SEC);
        let err = resp.try_decap(&wire[..enc.len], &mut out).unwrap_err();
        assert_eq!(err, DecapError::MalformedInner, "existing keepalive arm");
        assert_eq!(
            resp.counters().decap_keepalives.load(Ordering::Relaxed),
            1
        );
        let resp_peer = resp.peer_arc(&init_pub).unwrap();
        assert_eq!(
            resp_peer.last_recv_any_ns.load(Ordering::Relaxed),
            t0 + 2 * SEC,
            "received keepalive is an authenticated receive"
        );
        assert_eq!(
            resp_peer.t6_armed_recv_ns.load(Ordering::Relaxed),
            0,
            "a received keepalive must not arm T6"
        );
    }

    /// T6 armed model: data receive arms (first unanswered receive,
    /// later receives don't push the deadline); fires at armed+10s
    /// (NOT immediately on first inbound after idle); any
    /// authenticated send clears it; an AllowedIPs-rejected but
    /// authenticated record still arms it.
    #[test]
    fn t6_armed_passive_keepalive_semantics() {
        let (init, resp, init_pub, _resp_pub, t0) = pair();
        let mut wire = [0u8; 2048];
        let mut out = [0u8; 2048];

        resp.set_mock_now_ns(t0 + 1 * SEC);
        let enc = resp
            .try_encap(&init_pub, &inner_from_resp(), &mut wire)
            .unwrap();
        init.set_mock_now_ns(t0 + 5 * SEC);
        init.try_decap(&wire[..enc.len], &mut out).unwrap();
        let armed = init
            .peer_arc(&_resp_pub)
            .unwrap()
            .t6_armed_recv_ns
            .load(Ordering::Relaxed);
        assert_eq!(armed, t0 + 5 * SEC, "first data receive arms T6");

        // A second receive does not push the arm forward.
        resp.set_mock_now_ns(t0 + 6 * SEC);
        let enc2 = resp
            .try_encap(&init_pub, &inner_from_resp(), &mut wire)
            .unwrap();
        init.set_mock_now_ns(t0 + 7 * SEC);
        init.try_decap(&wire[..enc2.len], &mut out).unwrap();
        assert_eq!(
            init.peer_arc(&_resp_pub)
                .unwrap()
                .t6_armed_recv_ns
                .load(Ordering::Relaxed),
            t0 + 5 * SEC,
            "subsequent receives must not push the T6 deadline"
        );

        // Not due 9s after arming: deadline reported, no action.
        let a = init.timer_pass(t0 + 14 * SEC, true);
        assert!(a.send_keepalive.is_none());
        assert_eq!(a.next_deadline_ns, t0 + 15 * SEC, "armed+10s deadline");
        // Due at armed+10s.
        let a = init.timer_pass(t0 + 15 * SEC, true);
        assert_eq!(a.send_keepalive, Some(KeepaliveKind::Passive));
        // A send clears the arm.
        init.set_mock_now_ns(t0 + 16 * SEC);
        init.create_keepalive(&_resp_pub, &mut wire).unwrap();
        let a = init.timer_pass(t0 + 30 * SEC, true);
        assert!(a.send_keepalive.is_none(), "send cleared the T6 arm");
    }

    /// T7 armed model — the Codex r3 F1 regression: continuous
    /// outbound-only traffic must NOT suppress the no-reply reinit.
    /// The arm sticks at the FIRST unanswered data send and fires at
    /// +15s regardless of later sends; an authenticated receive
    /// clears it.
    #[test]
    fn t7_outbound_only_stream_fires_at_first_send_plus_15s() {
        let (init, resp, init_pub, resp_pub, t0) = pair();
        let mut wire = [0u8; 2048];
        let mut out = [0u8; 2048];

        for i in 0..14u64 {
            init.set_mock_now_ns(t0 + (1 + i) * SEC);
            init.try_encap(&resp_pub, &inner_from_init(), &mut wire)
                .unwrap();
        }
        let peer = init.peer_arc(&resp_pub).unwrap();
        assert_eq!(
            peer.t7_armed_send_ns.load(Ordering::Relaxed),
            t0 + 1 * SEC,
            "arm pinned at the FIRST unanswered send"
        );
        // Due at first-send + 15s even though sends continued.
        let a = init.timer_pass(t0 + 16 * SEC, true);
        assert_eq!(a.initiate, Some(InitiateReason::DeadPeer));

        // An authenticated receive clears the arm.
        resp.set_mock_now_ns(t0 + 17 * SEC);
        let enc = resp
            .try_encap(&init_pub, &inner_from_resp(), &mut wire)
            .unwrap();
        init.set_mock_now_ns(t0 + 18 * SEC);
        init.try_decap(&wire[..enc.len], &mut out).unwrap();
        assert_eq!(peer.t7_armed_send_ns.load(Ordering::Relaxed), 0);
        let a = init.timer_pass(t0 + 40 * SEC, true);
        assert!(a.initiate.is_none(), "receive cleared T7");
    }

    /// T8: paces on authenticated traversal in EITHER direction; with
    /// a usable session emits a persistent keepalive; with no usable
    /// session initiates; 0 = fully off; the skip anchor advances the
    /// deadline.
    #[test]
    fn t8_persistent_keepalive_traversal_pacing() {
        let (init, resp, init_pub, resp_pub, t0) = pair();
        let mut wire = [0u8; 2048];
        let mut out = [0u8; 2048];

        // Off by default.
        let a = init.timer_pass(t0 + 1000 * SEC, true);
        assert!(a.send_keepalive.is_none() && a.initiate.is_none());

        // #2836: keepalive lives in the per-snapshot config bundle.
        init.set_keepalive_for_test(&resp_pub, 25);

        // Inbound-only traversal suppresses T8 (Codex r1 B1): a fresh
        // authenticated receive resets the pacing.
        resp.set_mock_now_ns(t0 + 1 * SEC);
        let enc = resp
            .try_encap(&init_pub, &inner_from_resp(), &mut wire)
            .unwrap();
        init.set_mock_now_ns(t0 + 2 * SEC);
        init.try_decap(&wire[..enc.len], &mut out).unwrap();
        let a = init.timer_pass(t0 + 20 * SEC, true);
        assert!(
            a.send_keepalive != Some(KeepaliveKind::Persistent),
            "recent inbound traversal paces T8"
        );
        assert_eq!(
            a.next_deadline_ns.min(t0 + 27 * SEC),
            a.next_deadline_ns,
            "deadline no later than traversal+25s"
        );

        // Due at traversal+25s with a usable session => Persistent.
        let a = init.timer_pass(t0 + 28 * SEC, true);
        assert_eq!(a.send_keepalive, Some(KeepaliveKind::Persistent));

        // Skip-pacing: advancing the attempt anchor defers the due.
        // (T6 — armed by the inbound data at t0+2 and never cleared by
        // a send in this test — remains due, so the pass still emits a
        // PASSIVE keepalive; the assertion is that T8 specifically is
        // no longer due.)
        init.note_t8_attempt(&resp_pub, t0 + 28 * SEC);
        let a = init.timer_pass(t0 + 29 * SEC, true);
        assert_eq!(
            a.send_keepalive,
            Some(KeepaliveKind::Passive),
            "skip anchor advanced T8; only the due T6 action remains"
        );
        assert_eq!(a.next_deadline_ns, t0 + 53 * SEC);

        // No usable session (expired) => initiate instead.
        let a = init.timer_pass(t0 + 300 * SEC, true);
        assert_eq!(a.initiate, Some(InitiateReason::KeepaliveNoSession));
    }

    /// Unknown endpoint: no actions, no deadlines (AGY r3 G1(b)).
    #[test]
    fn timer_pass_endpoint_unknown_emits_nothing() {
        let (init, resp, init_pub, resp_pub, t0) = pair();
        let mut wire = [0u8; 2048];
        let mut out = [0u8; 2048];
        // #2836: keepalive lives in the per-snapshot config bundle.
        init.set_keepalive_for_test(&resp_pub, 25);
        // Arm T6 + T7 via real traffic.
        init.set_mock_now_ns(t0 + 1 * SEC);
        init.try_encap(&resp_pub, &inner_from_init(), &mut wire)
            .unwrap();
        resp.set_mock_now_ns(t0 + 2 * SEC);
        let enc = resp
            .try_encap(&init_pub, &inner_from_resp(), &mut wire)
            .unwrap();
        init.set_mock_now_ns(t0 + 3 * SEC);
        init.try_decap(&wire[..enc.len], &mut out).unwrap();
        // T6 is armed (data received at +3, nothing sent since).
        let a = init.timer_pass(t0 + 1000 * SEC, false);
        assert!(a.initiate.is_none() && a.send_keepalive.is_none());
        assert_eq!(a.next_deadline_ns, WG_NO_DEADLINE_NS);
    }

    /// Skip-pacing for a due passive keepalive that cannot be sent:
    /// re-arming at `now` makes the recomputed deadline strictly
    /// future (AGY r3 G1(a)).
    #[test]
    fn pace_passive_keepalive_skip_defers_deadline() {
        let (init, resp, init_pub, resp_pub, t0) = pair();
        let mut wire = [0u8; 2048];
        let mut out = [0u8; 2048];
        resp.set_mock_now_ns(t0 + 1 * SEC);
        let enc = resp
            .try_encap(&init_pub, &inner_from_resp(), &mut wire)
            .unwrap();
        init.set_mock_now_ns(t0 + 2 * SEC);
        init.try_decap(&wire[..enc.len], &mut out).unwrap();
        let now = t0 + 20 * SEC;
        let a = init.timer_pass(now, true);
        assert_eq!(a.send_keepalive, Some(KeepaliveKind::Passive));
        init.pace_passive_keepalive_skip(&resp_pub, now);
        let a = init.timer_pass(now, true);
        assert!(a.send_keepalive.is_none());
        assert!(a.next_deadline_ns > now, "deadline strictly future");
    }

    /// T5 give-up regression (Codex r1 M5): aborting the pending
    /// reservation makes a LATER valid msg2 drop as
    /// NoPendingHandshake instead of completing a stale handshake.
    #[test]
    fn abort_pending_drops_late_msg2() {
        let (init_priv, init_pub) = super::keypair();
        let (resp_priv, resp_pub) = super::keypair();
        let init = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: resp_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            }],
        });
        let resp = WgEngine::new(WgEngineConfig {
            local_private_key: resp_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: init_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            }],
        });
        let mut msg1 = [0u8; 1024];
        let mut msg2 = [0u8; 1024];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();
        resp.consume_initiation_create_response(
            &msg1[..super::super::WG_MSG_INIT_LEN],
            &mut msg2,
        )
        .unwrap();
        assert_eq!(init.pending_count(), 1);
        init.abort_pending_for_peer(&resp_pub);
        assert_eq!(init.pending_count(), 0);
        assert_eq!(
            init.counters()
                .pending_aborted_attempt_window
                .load(Ordering::Relaxed),
            1
        );
        let err = init
            .consume_response(&msg2[..super::super::WG_MSG_RESPONSE_LEN])
            .unwrap_err();
        assert!(
            matches!(
                err,
                super::super::handshake_session::HandshakeError::NoPendingHandshake
            ),
            "late msg2 after give-up must not complete: {err:?}"
        );
    }

    /// Sessions installed via the real handshake-completion paths
    /// carry the role + created_ns the timers depend on.
    #[test]
    fn completion_paths_stamp_role_and_created() {
        let (init_priv, init_pub) = super::keypair();
        let (resp_priv, resp_pub) = super::keypair();
        let init = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: resp_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            }],
        });
        let resp = WgEngine::new(WgEngineConfig {
            local_private_key: resp_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: init_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                preshared_key: [0u8; 32].into(),
            }],
        });
        init.set_mock_now_ns(7_000 * SEC);
        resp.set_mock_now_ns(8_000 * SEC);
        let mut msg1 = [0u8; 1024];
        let mut msg2 = [0u8; 1024];
        init.create_initiation(&resp_pub, &mut msg1).unwrap();
        resp.consume_initiation_create_response(
            &msg1[..super::super::WG_MSG_INIT_LEN],
            &mut msg2,
        )
        .unwrap();
        init.consume_response(&msg2[..super::super::WG_MSG_RESPONSE_LEN])
            .unwrap();
        let init_peer = init.peer_arc(&resp_pub).unwrap();
        let resp_peer = resp.peer_arc(&init_pub).unwrap();
        {
            let cur = init_peer.current.read().unwrap();
            let s = cur.as_ref().unwrap();
            assert_eq!(s.role, SessionRole::Initiator);
            assert_eq!(s.created_ns, 7_000 * SEC);
        }
        {
            // #3882: a fresh responder-role session parks in `next`
            // (unconfirmed), NOT `current` — egress must not use it
            // until the initiator's first inbound data record confirms
            // and promotes it. `current` stays empty on this initial
            // handshake (no prior confirmed keypair to keep serving).
            assert!(
                resp_peer.current.read().unwrap().is_none(),
                "responder must not promote an unconfirmed keypair into current"
            );
            let next = resp_peer.next.read().unwrap();
            let s = next.as_ref().unwrap();
            assert_eq!(s.role, SessionRole::Responder);
            assert_eq!(s.created_ns, 8_000 * SEC);
        }
        // Both completions stamped last_recv_any (T7 clear rule).
        assert_eq!(
            init_peer.last_recv_any_ns.load(Ordering::Relaxed),
            7_000 * SEC,
            "valid msg2 is an authenticated receive"
        );
        assert_eq!(
            resp_peer.last_recv_any_ns.load(Ordering::Relaxed),
            8_000 * SEC,
            "valid msg1 is an authenticated receive"
        );
    }
}

/// #4092 responder handshake anti-replay. Drives the FULL framed
/// handshake entry points (`create_initiation` →
/// `consume_initiation_create_response`) so the responder's per-peer
/// greatest-TAI64N gate is exercised end to end.
mod tai64n_replay_tests {
    use super::super::engine::{WgEngine, WgEngineConfig, WgPeerConfig};
    use super::super::handshake_session::HandshakeError;
    use super::super::{WG_MSG_INIT_LEN, WG_MSG_RESPONSE_LEN};
    use super::keypair;
    use std::sync::atomic::Ordering;

    /// Two engines configured as each other's sole peer (no endpoints —
    /// the handshake is driven by hand, not over UDP).
    fn engine_pair() -> (WgEngine, WgEngine, [u8; 32], [u8; 32]) {
        let (init_priv, init_pub) = keypair();
        let (resp_priv, resp_pub) = keypair();
        let init = WgEngine::new(WgEngineConfig {
            local_private_key: init_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: resp_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![],
                preshared_key: [0u8; 32].into(),
            }],
        });
        let resp = WgEngine::new(WgEngineConfig {
            local_private_key: resp_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: init_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![],
                preshared_key: [0u8; 32].into(),
            }],
        });
        (init, resp, init_pub, resp_pub)
    }

    #[test]
    fn responder_rejects_replayed_initiation_by_tai64n() {
        let (init_engine, resp_engine, _init_pub, resp_pub) = engine_pair();

        // Build ONE framed type-1 initiation. Its TAI64N is stamped once
        // here, so replaying the identical bytes re-presents that exact
        // timestamp (no fresh monotonic tick).
        let mut msg1 = [0u8; WG_MSG_INIT_LEN];
        init_engine
            .create_initiation(&resp_pub, &mut msg1)
            .expect("initiator builds a framed initiation");

        // First delivery: fresh timestamp — the responder accepts and
        // builds a type-2 response.
        let mut resp_out = [0u8; WG_MSG_RESPONSE_LEN];
        let first = resp_engine.consume_initiation_create_response(&msg1, &mut resp_out);
        assert!(first.is_ok(), "fresh initiation must be accepted: {first:?}");

        // Replay the IDENTICAL initiation. Its TAI64N now equals the
        // greatest already accepted from this peer, so the responder MUST
        // reject it (#4092). On revert (no gate) this second call succeeds
        // and installs a duplicate session — the RED signal.
        let mut resp_out2 = [0u8; WG_MSG_RESPONSE_LEN];
        let second = resp_engine.consume_initiation_create_response(&msg1, &mut resp_out2);
        assert_eq!(
            second,
            Err(HandshakeError::ReplayedInitiation),
            "a replayed initiation (TAI64N <= greatest accepted) must be rejected"
        );

        // The dedicated replay-reject counter moved exactly once; the
        // response-created counter reflects only the one accepted msg1.
        let c = resp_engine.counters();
        assert_eq!(c.hs_rx_drops_replayed_init.load(Ordering::Relaxed), 1);
        assert_eq!(c.hs_responses_created.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn responder_accepts_strictly_newer_initiation() {
        // A DISTINCT, strictly-newer initiation (fresh monotonic TAI64N
        // from the initiator clock) is accepted after a first one — the
        // gate rejects only replays/reorders, never legitimate rekeys.
        let (init_engine, resp_engine, _init_pub, resp_pub) = engine_pair();

        let mut msg1a = [0u8; WG_MSG_INIT_LEN];
        init_engine
            .create_initiation(&resp_pub, &mut msg1a)
            .expect("first initiation");
        let mut out_a = [0u8; WG_MSG_RESPONSE_LEN];
        assert!(
            resp_engine
                .consume_initiation_create_response(&msg1a, &mut out_a)
                .is_ok()
        );

        // create_initiation stamps a strictly-greater monotonic TAI64N,
        // so this second framed initiation is a fresh (re)key, not a
        // replay.
        let mut msg1b = [0u8; WG_MSG_INIT_LEN];
        init_engine
            .create_initiation(&resp_pub, &mut msg1b)
            .expect("second initiation");
        let mut out_b = [0u8; WG_MSG_RESPONSE_LEN];
        let second = resp_engine.consume_initiation_create_response(&msg1b, &mut out_b);
        assert!(
            second.is_ok(),
            "a strictly-newer initiation must be accepted: {second:?}"
        );
        assert_eq!(
            resp_engine
                .counters()
                .hs_rx_drops_replayed_init
                .load(Ordering::Relaxed),
            0,
            "a legitimate rekey must not count as a replay"
        );
    }
}
