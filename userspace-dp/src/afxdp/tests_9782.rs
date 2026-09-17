//! #9782 regression cells: post-NAT port enforcement must not clobber
//! translations.
//!
//! `enforce_expected_ports` repairs DMA-race-torn arrival bytes against the
//! PRE-NAT expected tuple, so it must run BEFORE `apply_nat_*`
//! (repair-then-translate). Running it after overwrote every PAT/DNAT port
//! translation with the original port (valid checksum, unmatchable reverse
//! index): pool-PAT denied wan->wan, interface-PAT colliders misdelivered,
//! preserving flows unaffected.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::ip_proto::{PROTO_TCP, PROTO_UDP};
use crate::test_zone_ids::*;
use crate::{NeighborSnapshot, PolicyRuleSnapshot, SourceNATRuleSnapshot};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Recompute the L4 checksum in place so fixtures carry valid input
/// checksums (builders leave TCP/UDP checksum zero).
fn seed_l4_csum_v4(frame: &mut [u8], protocol: u8) {
    crate::afxdp::frame::checksum::recompute_l4_checksum_ipv4(
        &mut frame[14..],
        20,
        protocol,
        true,
    )
    .expect("seed v4 checksum");
}

fn seed_l4_csum_v6(frame: &mut [u8], protocol: u8) {
    crate::afxdp::frame::checksum::recompute_l4_checksum_ipv6(
        &mut frame[14..],
        40,
        protocol,
    )
    .expect("seed v6 checksum");
}

/// Verify L4 checksum validity of an L3-relative slice by recomputing from
/// a zeroed field and comparing. Returns false instead of asserting so
/// callers can name the failing direction.
fn l4_csum_valid(l3: &[u8], v6: bool, protocol: u8) -> bool {
    let (l4, csum_off) = if v6 {
        (40usize, if protocol == PROTO_TCP { 56 } else { 46 })
    } else {
        let ihl = ((l3[0] & 0x0f) as usize) * 4;
        (ihl, if protocol == PROTO_TCP { ihl + 16 } else { ihl + 6 })
    };
    if l3.len() < csum_off + 2 || l3.len() < l4 + 4 {
        return false;
    }
    // UDP zero means "no checksum" (RFC 768) — valid by definition.
    if protocol == PROTO_UDP && l3[csum_off] == 0 && l3[csum_off + 1] == 0 {
        return true;
    }
    let mut probe = l3.to_vec();
    let before = u16::from_be_bytes([probe[csum_off], probe[csum_off + 1]]);
    probe[csum_off] = 0;
    probe[csum_off + 1] = 0;
    let ok = if v6 {
        crate::afxdp::frame::checksum::recompute_l4_checksum_ipv6(&mut probe, l4, protocol)
    } else {
        let ihl = ((probe[0] & 0x0f) as usize) * 4;
        crate::afxdp::frame::checksum::recompute_l4_checksum_ipv4(&mut probe, ihl, protocol, true)
    };
    if ok.is_none() {
        return false;
    }
    // v4 recompute with zero=true zeroes again (idempotent); compare.
    let after = u16::from_be_bytes([probe[csum_off], probe[csum_off + 1]]);
    before == after
}

fn pool_9782_snapshot() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![
        SourceNATRuleSnapshot {
            name: "snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-snat-pool".to_string(),
            pool_addresses: vec!["172.16.80.7/32".to_string()],
            port_low: 30000,
            port_high: 30999,
            ..Default::default()
        },
        SourceNATRuleSnapshot {
            name: "snat6".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["::/0".to_string()],
            interface_mode: true,
            ..Default::default()
        },
    ];
    // .200 is inside reth0.80's connected /24: direct next-hop needs its MAC.
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.200".to_string(),
        mac: "00:11:22:33:44:66".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    snapshot
}

fn session_key_v4(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, proto: u8) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: proto,
        src_ip: IpAddr::V4(src),
        dst_ip: IpAddr::V4(dst),
        src_port: sport,
        dst_port: dport,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn fwd_nat_of(sessions: &mut SessionTable, key: &crate::session::SessionKey) -> crate::nat::NatDecision {
    sessions
        .lookup_with_origin(key, 123_000_000_000, TCP_FLAG_SYN)
        .expect("forward session must be installed")
        .0
        .decision
        .nat
}

/// Minimal hand-rolled v6/UDP frame (no txn builder exists for it).
fn build_v6_udp_frame(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    // eth
    frame.extend_from_slice(&[0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]);
    frame.extend_from_slice(&[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    frame.extend_from_slice(&[0x86, 0xdd]);
    // ipv6: ver, payload len 8, next UDP, hop 64
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x08, PROTO_UDP, 64]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&sport.to_be_bytes());
    frame.extend_from_slice(&dport.to_be_bytes());
    frame.extend_from_slice(&8u16.to_be_bytes());
    frame.extend_from_slice(&[0u8, 0u8]); // checksum (seeded by caller)
    frame
}

/// Minimal hand-rolled v4/UDP frame (no txn builder takes ports).
fn build_v4_udp_frame(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0xbf, 0x72, 0x01, 0x00, 0x01]);
    frame.extend_from_slice(&[0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]);
    frame.extend_from_slice(&[0x08, 0x00]);
    let s = src.octets();
    let d = dst.octets();
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, PROTO_UDP, 0x00, 0x00, s[0], s[1],
        s[2], s[3], d[0], d[1], d[2], d[3],
    ]);
    let ip_sum = crate::afxdp::frame::checksum::checksum16(&frame[14..34]);
    frame[24] = (ip_sum >> 8) as u8;
    frame[25] = ip_sum as u8;
    frame.extend_from_slice(&sport.to_be_bytes());
    frame.extend_from_slice(&dport.to_be_bytes());
    frame.extend_from_slice(&8u16.to_be_bytes());
    frame.extend_from_slice(&[0u8, 0u8]);
    frame
}

fn unit_decision_v4(nat: crate::nat::NatDecision) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat,
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn unit_decision_v6(nat: crate::nat::NatDecision) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat,
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn unit_meta_v4(proto: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: proto,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

fn unit_meta_v6(proto: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: proto,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

// ---------------------------------------------------------------------------
// 1. Promoted binder: pool PAT survives production-faithful expected ports.
// ---------------------------------------------------------------------------

#[test]
fn pool_snat_pat_survives_expected_ports_9782() {
    let snapshot = pool_9782_snapshot();
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let client_port: u16 = 59508;
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(172, 16, 80, 200),
        client_port,
        5201,
        TCP_FLAG_SYN,
    );
    seed_l4_csum_v4(&mut frame, PROTO_TCP);
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    assert_eq!(dbg.tx, 1, "pool SYN must forward");
    assert_eq!(binding.scratch.scratch_forwards.len(), 1);
    let fwd = &binding.scratch.scratch_forwards[0];
    let pat_port = fwd
        .decision
        .nat
        .rewrite_src_port
        .expect("pool PAT must set a translated source port");
    assert!((30000..=30999).contains(&pat_port));
    assert_eq!(
        fwd.decision.nat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 7)))
    );
    // Non-vacuity: the request carries the pre-NAT expectation the
    // production TX path enforces against (the trigger this binds).
    let key = session_key_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        client_port,
        Ipv4Addr::new(172, 16, 80, 200),
        5201,
        PROTO_TCP,
    );
    assert_eq!(
        fwd_nat_of(&mut sessions, &key).rewrite_src_port,
        Some(pat_port),
        "session must store the PAT port the forward used"
    );

    // Run the TX rewrite exactly as dispatch does, with the production
    // pre-NAT expectation, and read the wire bytes + checksum.
    let area = binding.umem.area();
    let desc = crate::afxdp::XdpDesc {
        addr: 128,
        len: frame.len() as u32,
        options: 0,
    };
    let result = crate::afxdp::frame::rewrite_forwarded_frame_in_place(
        area,
        desc,
        meta,
        &fwd.decision,
        false,
        Some((client_port, 5201)),
        0,
    )
    .expect("TX rewrite must succeed");
    let out = area
        .slice(result.offset as usize, result.len as usize)
        .expect("rewritten bytes");
    assert!(out.len() >= 40);
    let wire_sport = u16::from_be_bytes([out[38], out[39]]);
    let wire_dport = u16::from_be_bytes([out[40], out[41]]);
    assert_eq!(wire_sport, pat_port, "#9782: wire must carry the PAT port");
    assert_eq!(wire_dport, 5201, "dst port untouched");
    assert_eq!(
        Ipv4Addr::new(out[30], out[31], out[32], out[33]),
        Ipv4Addr::new(172, 16, 80, 7)
    );
    assert!(
        l4_csum_valid(&out[18..], false, PROTO_TCP),
        "rewritten TCP checksum must be valid (no stale-delta escape)"
    );
}

// ---------------------------------------------------------------------------
// 2. Interface-PAT collider twin: the second flow completes on its PAT port.
// ---------------------------------------------------------------------------

#[test]
fn interface_pat_collider_both_complete_9782() {
    let mut snapshot = nat_snapshot();
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.200".to_string(),
        mac: "00:11:22:33:44:66".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let sport: u16 = 45678;
    for (i, oct) in [102u8, 103u8].iter().enumerate() {
        let mut frame = build_txn_tcp_syn_frame_v4(
            Ipv4Addr::new(10, 0, 61, *oct),
            Ipv4Addr::new(172, 16, 80, 200),
            sport,
            5201,
            TCP_FLAG_SYN,
        );
        seed_l4_csum_v4(&mut frame, PROTO_TCP);
        let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
        let (_batch, dbg) = txn_run_descriptor(
            &mut binding,
            &mut sessions,
            &forwarding,
            &ha_state,
            &frame,
            meta,
        );
        assert_eq!(dbg.tx, 1, "flow {i} SYN must forward");
        let fwd = binding.scratch.scratch_forwards.last().expect("request");
        let area = binding.umem.area();
        let desc = crate::afxdp::XdpDesc {
            addr: 128,
            len: frame.len() as u32,
            options: 0,
        };
        // `expected_ports` is the ARRIVAL-tuple authority — the tuple each
        // flow carried when it arrived — so both collider flows correctly
        // share `Some((sport, 5201))`: flow .103 arrives as 45678→5201
        // exactly like flow .102. It is NOT the wire expectation: the
        // repair runs pre-NAT against arrivals, then NAT translates, so
        // flow 2's wire carries its PAT port. Under the pre-fix ordering
        // the post-NAT repair would restore 45678 on flow 2 and the
        // `wire_sport == pat` assert below goes RED — that flip is this
        // cell's regression signal, not a contradiction.
        let result = crate::afxdp::frame::rewrite_forwarded_frame_in_place(
            area,
            desc,
            meta,
            &fwd.decision,
            false,
            Some((sport, 5201)),
            0,
        )
        .expect("rewrite must succeed");
        let out = area
            .slice(result.offset as usize, result.len as usize)
            .expect("bytes");
        let wire_sport = u16::from_be_bytes([out[38], out[39]]);
        if i == 0 {
            assert!(
                fwd.decision.nat.rewrite_src_port.is_none(),
                "first flow preserves (no PAT)"
            );
            assert_eq!(wire_sport, sport, "preserved wire port");
        } else {
            let pat = fwd
                .decision
                .nat
                .rewrite_src_port
                .expect("collider must PAT");
            assert_ne!(pat, sport);
            assert_eq!(
                wire_sport, pat,
                "#9782: collider wire must carry its PAT port, not the preserved one"
            );
        }
        assert!(
            l4_csum_valid(&out[18..], false, PROTO_TCP),
            "flow {i} checksum valid"
        );
    }
    // Both sessions coexist with distinct reverse identities.
    let k1 = session_key_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        sport,
        Ipv4Addr::new(172, 16, 80, 200),
        5201,
        PROTO_TCP,
    );
    let k2 = session_key_v4(
        Ipv4Addr::new(10, 0, 61, 103),
        sport,
        Ipv4Addr::new(172, 16, 80, 200),
        5201,
        PROTO_TCP,
    );
    assert!(fwd_nat_of(&mut sessions, &k1).rewrite_src_port.is_none());
    assert!(fwd_nat_of(&mut sessions, &k2).rewrite_src_port.is_some());
}

// ---------------------------------------------------------------------------
// 3. Preserve control: untranslated flows are byte-identical (over-reach guard).
// ---------------------------------------------------------------------------

#[test]
fn interface_preserve_control_unchanged_9782() {
    let mut snapshot = nat_snapshot();
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.200".to_string(),
        mac: "00:11:22:33:44:66".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(172, 16, 80, 200),
        50001,
        5201,
        TCP_FLAG_SYN,
    );
    seed_l4_csum_v4(&mut frame, PROTO_TCP);
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let (_batch, dbg) = txn_run_descriptor(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );
    assert_eq!(dbg.tx, 1);
    let fwd = &binding.scratch.scratch_forwards[0];
    assert!(fwd.decision.nat.rewrite_src_port.is_none());
    let area = binding.umem.area();
    let desc = crate::afxdp::XdpDesc {
        addr: 128,
        len: frame.len() as u32,
        options: 0,
    };
    let result = crate::afxdp::frame::rewrite_forwarded_frame_in_place(
        area,
        desc,
        meta,
        &fwd.decision,
        false,
        Some((50001, 5201)),
        0,
    )
    .expect("rewrite ok");
    let out = area
        .slice(result.offset as usize, result.len as usize)
        .expect("bytes");
    assert_eq!(u16::from_be_bytes([out[38], out[39]]), 50001);
    assert!(l4_csum_valid(&out[18..], false, PROTO_TCP));
}

// ---------------------------------------------------------------------------
// 4-6. Unit cells: DNAT dst-port, v6 TCP, v6 UDP (+ zero-seed).
// ---------------------------------------------------------------------------

fn unit_rewrite_case(
    frame: &[u8],
    meta: UserspaceDpMeta,
    decision: &SessionDecision,
    expected: Option<(u16, u16)>,
) -> Vec<u8> {
    let mut area =
        crate::afxdp::MmapArea::new(4096).expect("mmap");
    area.slice_mut(256, frame.len())
        .expect("copy")
        .copy_from_slice(frame);
    let desc = crate::afxdp::XdpDesc {
        addr: 256,
        len: frame.len() as u32,
        options: 0,
    };
    let result = crate::afxdp::frame::rewrite_forwarded_frame_in_place(
        &area, desc, meta, decision, false, expected, 0,
    )
    .expect("unit rewrite must succeed");
    area.slice(result.offset as usize, result.len as usize)
        .expect("bytes")
        .to_vec()
}

#[test]
fn dnat_dst_port_survives_expected_ports_9782() {
    // Inbound: client -> VIP:443, DNAT to server:8443. Same reorder as SNAT.
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(172, 16, 80, 8),
        54321,
        443,
        TCP_FLAG_SYN,
    );
    seed_l4_csum_v4(&mut frame, PROTO_TCP);
    let nat = crate::nat::NatDecision {
        rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        rewrite_dst_port: Some(8443),
        ..Default::default()
    };
    // Egress toward lan (untagged here => l3 stays 14; read ports at 34).
    let mut decision = unit_decision_v4(nat);
    decision.resolution.tx_vlan_id = 0;
    let out = unit_rewrite_case(&frame, unit_meta_v4(PROTO_TCP), &decision, Some((54321, 443)));
    assert_eq!(u16::from_be_bytes([out[34], out[35]]), 54321);
    assert_eq!(
        u16::from_be_bytes([out[36], out[37]]),
        8443,
        "#9782: DNAT dst port must survive enforcement"
    );
    assert!(l4_csum_valid(&out[14..], false, PROTO_TCP));
}

#[test]
fn v6_tcp_snat_port_survives_expected_ports_9782() {
    let mut frame = build_txn_tcp_syn_frame_v6(
        "2001:559:8585:ef00::102".parse().unwrap(),
        "2001:559:8585:80::200".parse().unwrap(),
        59508,
        5201,
    );
    seed_l4_csum_v6(&mut frame, PROTO_TCP);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
        rewrite_src_port: Some(40001),
        ..Default::default()
    };
    let out = unit_rewrite_case(
        &frame,
        unit_meta_v6(PROTO_TCP),
        &unit_decision_v6(nat),
        Some((59508, 5201)),
    );
    // Pushed VLAN (eth 18) + 40B v6 header => sport at 58.
    assert_eq!(u16::from_be_bytes([out[58], out[59]]), 40001);
    assert!(l4_csum_valid(&out[18..], true, PROTO_TCP));
}

#[test]
fn v6_udp_snat_port_survives_expected_ports_9782() {
    let mut frame = build_v6_udp_frame(
        "2001:559:8585:ef00::102".parse().unwrap(),
        "2001:559:8585:80::200".parse().unwrap(),
        53001,
        53,
    );
    seed_l4_csum_v6(&mut frame, PROTO_UDP);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
        rewrite_src_port: Some(40002),
        ..Default::default()
    };
    let out = unit_rewrite_case(
        &frame,
        unit_meta_v6(PROTO_UDP),
        &unit_decision_v6(nat),
        Some((53001, 53)),
    );
    assert_eq!(u16::from_be_bytes([out[58], out[59]]), 40002);
    assert!(l4_csum_valid(&out[18..], true, PROTO_UDP));
}

#[test]
fn v6_udp_zero_checksum_computed_under_reorder_9782() {
    // #1840: the zero-checksum skip is IPv4-only (RFC 8200 §8.1 mandates
    // v6 UDP checksums), so a stored-0 v6 input gains a computed checksum
    // through NAT. NOTE (adjacent gap, pre-existing, NOT this fix): the
    // adjusters increment from the stored 0, which is not generally a
    // valid checksum — identical before/after the reorder (enforce no-ops
    // on untorn ports either way); a full recompute there is separate
    // work. This cell pins only that the reorder preserves the port and
    // the adjuster ran (nonzero) rather than skipped.
    let frame = build_v6_udp_frame(
        "2001:559:8585:ef00::102".parse().unwrap(),
        "2001:559:8585:80::200".parse().unwrap(),
        53001,
        53,
    );
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V6("2001:559:8585:80::8".parse().unwrap())),
        rewrite_src_port: Some(40002),
        ..Default::default()
    };
    let out = unit_rewrite_case(
        &frame,
        unit_meta_v6(PROTO_UDP),
        &unit_decision_v6(nat),
        Some((53001, 53)),
    );
    assert_eq!(u16::from_be_bytes([out[58], out[59]]), 40002);
    assert_ne!(u16::from_be_bytes([out[64], out[65]]), 0);
}

#[test]
fn v4_udp_zero_checksum_preserved_under_reorder_9782() {
    // RFC 768 / #1840: v4 UDP zero means "no checksum" — NAT preserves it
    // (keep_zero), and the reorder must not fabricate one via enforce.
    let mut frame = build_v4_udp_frame(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(172, 16, 80, 200),
        53001,
        53,
    );
    // Zero the checksum field (builder may seed one).
    let ihl = ((frame[14] & 0x0f) as usize) * 4;
    frame[14 + ihl + 6] = 0;
    frame[14 + ihl + 7] = 0;
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 7))),
        rewrite_src_port: Some(30001),
        ..Default::default()
    };
    let out = unit_rewrite_case(
        &frame,
        unit_meta_v4(PROTO_UDP),
        &unit_decision_v4(nat),
        Some((53001, 53)),
    );
    assert_eq!(u16::from_be_bytes([out[38], out[39]]), 30001);
    assert_eq!(
        u16::from_be_bytes([out[38 + 6], out[38 + 7]]),
        0,
        "v4 UDP zero checksum must stay zero"
    );
}

// ---------------------------------------------------------------------------
// 7. Anti-escape: untranslated torn ports are still repaired (enforce alive).
// ---------------------------------------------------------------------------

#[test]
fn untranslated_torn_dst_port_still_repaired_9782() {
    // No NAT: frame dst port torn (5201 -> 9999); enforce must repair it.
    // Kills the "skip all enforcement" escape that a fix-by-deletion takes.
    let mut frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(172, 16, 80, 200),
        50002,
        5201,
        TCP_FLAG_SYN,
    );
    frame[34 + 2] = 0x27;
    frame[34 + 3] = 0x0F; // 9999
    seed_l4_csum_v4(&mut frame, PROTO_TCP);
    // Re-tear AFTER seeding so input is torn-with-consistent-checksum.
    frame[34 + 2] = 0x27;
    frame[34 + 3] = 0x0F;
    let nat = crate::nat::NatDecision::default();
    let out = unit_rewrite_case(
        &frame,
        unit_meta_v4(PROTO_TCP),
        &unit_decision_v4(nat),
        Some((50002, 5201)),
    );
    assert_eq!(u16::from_be_bytes([out[38], out[39]]), 50002);
    assert_eq!(
        u16::from_be_bytes([out[40], out[41]]),
        5201,
        "enforce must repair the torn dst port when no NAT applies"
    );
    assert!(l4_csum_valid(&out[18..], false, PROTO_TCP));
}

// ---------------------------------------------------------------------------
// 8. post_nat_expected_ports matrix.
// ---------------------------------------------------------------------------

#[test]
fn post_nat_expected_ports_matrix_9782() {
    use crate::afxdp::frame::post_nat_expected_ports;
    use crate::nat::NatDecision;
    let pat = NatDecision {
        rewrite_src_port: Some(30001),
        ..Default::default()
    };
    let dnat = NatDecision {
        rewrite_dst_port: Some(8443),
        ..Default::default()
    };
    let both = NatDecision {
        rewrite_src_port: Some(30001),
        rewrite_dst_port: Some(8443),
        ..Default::default()
    };
    // Translated output compares against the translated tuple.
    assert_eq!(
        post_nat_expected_ports(Some((59508, 5201)), Some((59508, 5201)), pat, true),
        Some((30001, 5201))
    );
    assert_eq!(
        post_nat_expected_ports(Some((54321, 443)), Some((54321, 443)), dnat, true),
        Some((54321, 8443))
    );
    assert_eq!(
        post_nat_expected_ports(Some((1111, 2222)), Some((1111, 2222)), both, true),
        Some((30001, 8443))
    );
    // Untranslated flows: identity (diagnostic contract unchanged).
    assert_eq!(
        post_nat_expected_ports(
            Some((50001, 5201)),
            Some((50001, 5201)),
            NatDecision::default(),
            true
        ),
        Some((50001, 5201))
    );
    // Fabric-suppressed NAT: arrival tuple stands.
    assert_eq!(
        post_nat_expected_ports(Some((59508, 5201)), Some((59508, 5201)), pat, false),
        Some((59508, 5201))
    );
    // No authority anywhere: None (check skips, never fabricates).
    assert_eq!(
        post_nat_expected_ports(None, None, pat, true),
        None
    );
    // Source fallback translates too (not just expected).
    assert_eq!(
        post_nat_expected_ports(None, Some((59508, 5201)), pat, true),
        Some((30001, 5201))
    );
}
