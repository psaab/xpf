//! #18520 measurement: `SessionKey` hashes one cached TCP data packet costs
//! on the flow-cache hit path (`probe_hit_deferring_state_update_with_ack` +
//! the TX-admission `emit_probe_hit_state_update` +
//! `take_probe_stage_transition`), for an Established pair and for a pure
//! Opening pair (the shape a cross-worker split left the authoritative row
//! in before #18520). Single table, public API only, so the same cell runs
//! unchanged against the pre-fix tree for the before/after numbers in
//! `docs/log/18520.md`.

use super::*;
use crate::nat::NatDecision;
use std::net::{IpAddr, Ipv4Addr};

const MS: u64 = 1_000_000;
const CLIENT_ISN: u32 = 0x1000_0000;
const SERVER_ISN: u32 = 0x5000_0000;
const MSS: u32 = 1448;
const HITS: u64 = 64;
const ACK: u8 = crate::tcp_flags::TCP_ACK;
const SYN: u8 = crate::tcp_flags::TCP_SYN;
const PSH: u8 = crate::tcp_flags::TCP_PSH;

fn forward_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 55068,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn snat() -> NatDecision {
    NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(40_001),
        ..NatDecision::default()
    }
}

fn decision(nat: NatDecision) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat,
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn metadata(is_reverse: bool) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: if is_reverse { 2 } else { 1 },
        egress_zone: if is_reverse { 1 } else { 2 },
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    }
}

/// SYN install of both halves at `now`, as the poll new-flow path does.
fn syn(table: &mut SessionTable, now: u64) -> (SessionKey, SessionKey) {
    let fwd = forward_key();
    let rev = reverse_session_key(&fwd, snat());
    assert!(table.install_with_protocol_with_origin(fwd.clone(), decision(snat()), metadata(false), SessionOrigin::ForwardFlow, now, PROTO_TCP, SYN));
    table.seed_tcp_isn(&fwd, CLIENT_ISN, 0, SYN);
    let rev_nat = snat().reverse(fwd.src_ip, fwd.dst_ip, fwd.src_port, fwd.dst_port);
    assert!(table.install_with_protocol_with_origin(rev.clone(), decision(rev_nat), metadata(true), SessionOrigin::ReverseFlow, now, PROTO_TCP, SYN));
    (fwd, rev)
}

fn cached_hit(table: &mut SessionTable, key: &SessionKey, now: u64, flags: u8, payload: u32, ack: u32) {
    assert!(table.probe_hit_deferring_state_update_with_ack(key, now, u64::from(payload) + 52, flags, payload, 0, Some(ack)));
    table.emit_probe_hit_state_update(key);
    let _ = table.take_probe_stage_transition(key);
}

fn hashes_per_hit(table: &mut SessionTable, key: &SessionKey, start: u64) -> f64 {
    hashes_per_hit_with(table, key, start, ACK | PSH, MSS)
}

fn hashes_per_hit_with(table: &mut SessionTable, key: &SessionKey, start: u64, flags: u8, payload: u32) -> f64 {
    let before = SESSION_KEY_HASHES_FOR_TEST.with(|c| c.get());
    for i in 0..HITS {
        cached_hit(table, key, start + i * MS, flags, payload, SERVER_ISN + 1);
    }
    (SESSION_KEY_HASHES_FOR_TEST.with(|c| c.get()) - before) as f64 / HITS as f64
}

#[test]
fn cached_data_hit_session_key_hash_cost_18520() {
    let now = 1_000 * 1_000_000_000u64;
    // Established: SYN, SYN-ACK, completing ACK on one table.
    let mut est = SessionTable::new();
    let (fwd, rev) = syn(&mut est, now);
    assert!(est.lookup_with_origin_with_ack(&rev, now + MS, SYN | ACK, 0, Some(CLIENT_ISN + 1)).is_some());
    est.note_tcp_seq(&rev, SERVER_ISN, CLIENT_ISN + 1, 65_535, 0, SYN | ACK, 0);
    assert!(est.lookup_with_origin_with_ack(&fwd, now + 2 * MS, ACK, 0, Some(SERVER_ISN + 1)).is_some());
    assert_eq!(est.handshake_state_wire_for(&fwd), TcpHandshakeState::Established.to_wire());
    let established = hashes_per_hit(&mut est, &fwd, now + 3 * MS);
    // Pure Opening: SYN only, then cached data (the stuck pre-#18520 shape).
    let mut opening = SessionTable::new();
    let (fwd_o, _) = syn(&mut opening, now);
    let pure_opening = hashes_per_hit(&mut opening, &fwd_o, now + 3 * MS);
    assert_eq!(opening.handshake_state_wire_for(&fwd_o), TcpHandshakeState::Opening.to_wire());
    // Same Opening pair, bare ACKs: no payload, so no evidence scan — the
    // difference to `pure_opening` is one scan's cost.
    let bare_opening = hashes_per_hit_with(&mut opening, &fwd_o, now + 200 * MS, ACK, 0);
    eprintln!(
        "#18520 hash cost: established cached data hit = {established} SessionKey hashes/packet; \
         pure-Opening cached data hit = {pure_opening}; pure-Opening bare ACK = {bare_opening}"
    );
    assert!(established < pure_opening, "an established hit must be cheaper than the Opening evidence path");
}
