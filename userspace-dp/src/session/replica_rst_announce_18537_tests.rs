//! #18537: a blind RST seen only by a worker REPLICA of a split pair must
//! not announce the Reset class to the HA peer.
//!
//! On a split pair neither worker holds sequence state for the RST's
//! direction on the cache-served path, so the poll path admits a RST with
//! any sequence number on whichever worker RSS gives it (#18520). The
//! replica that takes it stamps `reset` locally (its rows keep the fixed
//! 2 s fuse, as before #18520) and — through the #9582 announce — used to
//! emit an HA Update carrying `TcpCloseClass::Reset`. The peer imports
//! that class, stamps `reset` on its standby copy of a still-live flow,
//! and puts it on the reset close window, so a failover shortly after can
//! lose the flow even though the local authoritative pair holds only the
//! refreshable CLOSING state the #18520 relay uses between workers.
//!
//! The replica's announce for a RST-originated close therefore carries
//! CLOSING, exactly the class the close relay stamps on siblings. Local
//! state on both ends is untouched: the replica still takes the RST on
//! its 2 s fuse and the authoritative pair still takes a genuine RST as
//! Reset. FIN and TIME_WAIT announcements are unchanged.

use super::tests::{decision, key_v4, metadata};
use super::*;
use crate::server::helpers::build_synced_session_entry;
use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use crate::test_zone_ids::*;
use crate::SessionSyncRequest;

const SEC: u64 = 1_000_000_000;
const INSTALLER_ID: u64 = 0x0003_0000_0000_0042;
const THIS_WORKER: u32 = 2;

fn replica_table() -> SessionTable {
    let mut table = SessionTable::new();
    table.set_session_id_namespace(0, THIS_WORKER);
    table
}

fn authoritative_table() -> SessionTable {
    let mut table = SessionTable::new();
    table.set_session_id_namespace(0, (INSTALLER_ID >> 48) as u32);
    table
}

fn install_worker_pair(
    table: &mut SessionTable,
    forward_origin: SessionOrigin,
    reverse_origin: SessionOrigin,
    now: u64,
) -> (SessionKey, SessionKey) {
    let forward = key_v4();
    let reverse = reverse_session_key(&forward, decision().nat);
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: decision(),
            metadata: metadata(),
            origin: forward_origin,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: TCP_ACK,
            session_id: INSTALLER_ID,
            tcp_close_class: 0,
            tcp_handshake_state: 0,
            persistent_lease_hold: None,
            fwd_packets: 0,
            rev_packets: 0,
            source_nat_static: None,
        },
        false,
    ));
    let mut reverse_metadata = metadata();
    reverse_metadata.is_reverse = true;
    reverse_metadata.ingress_zone = TEST_WAN_ZONE_ID;
    reverse_metadata.egress_zone = TEST_LAN_ZONE_ID;
    assert!(table.upsert_synced_with_origin(
        SessionInstall {
            key: reverse.clone(),
            decision: decision(),
            metadata: reverse_metadata,
            origin: reverse_origin,
            now_ns: now,
            protocol: PROTO_TCP,
            tcp_flags: TCP_ACK,
            session_id: 0,
            tcp_close_class: 0,
            tcp_handshake_state: 0,
            persistent_lease_hold: None,
            fwd_packets: 0,
            rev_packets: 0,
            source_nat_static: None,
        },
        false,
    ));
    let _ = table.drain_deltas(64);
    (forward, reverse)
}

fn rst_updates(table: &mut SessionTable, forward: &SessionKey, reverse: &SessionKey, now: u64) -> Vec<(u8, u64)> {
    assert!(
        table.lookup(reverse, now, TCP_RST | TCP_ACK).is_some(),
        "FIXTURE: the RST must match the reverse replica"
    );
    table
        .drain_deltas(64)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .map(|d| {
            assert_eq!(&d.key, forward, "an Update must name the forward key");
            (d.tcp_close_class, d.session_id)
        })
        .collect()
}

/// The HA record a sender on this node would put on the wire for a close
/// Update of `class`: JSON through the Go-side record shape, then the
/// production import builder the peer runs.
fn peer_record(class: u8, key: &SessionKey) -> SessionSyncRequest {
    let base = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: key.src_ip.to_string(),
        dst_ip: key.dst_ip.to_string(),
        src_port: key.src_port,
        dst_port: key.dst_port,
        ingress_zone_id: TEST_LAN_ZONE_ID,
        egress_zone_id: TEST_WAN_ZONE_ID,
        owner_rg_id: 1,
        session_id: INSTALLER_ID,
        ..SessionSyncRequest::default()
    };
    let mut v = serde_json::to_value(&base).expect("FIXTURE: serialize");
    v["tcp_close_class"] = serde_json::json!(class);
    serde_json::from_value(v).expect("FIXTURE: deserialize")
}

#[test]
fn blind_rst_on_a_replica_announces_closing_not_reset_18537() {
    let mut replica = replica_table();
    let mut authority = authoritative_table();
    let (forward, reverse) = install_worker_pair(
        &mut replica,
        SessionOrigin::WorkerLocalImport,
        SessionOrigin::WorkerLocalImport,
        SEC,
    );
    let (authoritative_forward, _) = install_worker_pair(
        &mut authority,
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
        SEC,
    );
    assert_eq!(authoritative_forward, forward, "FIXTURE: worker pairs share a tuple");
    assert_eq!(
        replica.tcp_closing_seq_verdict(
            &reverse,
            0x5000_0000u32.wrapping_add(0x4000_0000),
            TCP_RST | TCP_ACK
        ),
        SeqVerdict::Unknown,
        "premise: a replica of a split pair has no sequence evidence for this blind RST"
    );
    let updates = rst_updates(&mut replica, &forward, &reverse, SEC + 1_000);
    assert_eq!(
        replica.close_class_wire_for(&forward),
        TcpCloseClass::Reset.to_wire(),
        "FIXTURE: the replica's own table must still record RST locally"
    );
    assert_eq!(
        updates,
        vec![(TcpCloseClass::Closing.to_wire(), INSTALLER_ID)],
        "#18537: a RST seen only by a replica must announce CLOSING, never Reset"
    );

    // The sibling's production close-relay consumer puts the authoritative
    // pair on the same CLOSING state that the HA peer must import.
    let mut relays = Vec::new();
    replica.drain_handshake_relays_into(&mut relays);
    assert_eq!(relays.len(), 1, "FIXTURE: one close relay reaches the sibling");
    assert_eq!(relays[0].stage, HandshakeRelayStage::Closed);
    assert!(authority.apply_handshake_relay(&relays[0], SEC + 2_000));
    assert_eq!(
        authority.close_class_wire_for(&forward),
        TcpCloseClass::Closing.to_wire(),
        "FIXTURE: the local authoritative pair takes the RST as refreshable CLOSING"
    );

    // The peer imports exactly the class announced by the replica.
    let announced = updates[0].0;
    let mut peer = SessionTable::new();
    let zones = rustc_hash::FxHashMap::default();
    let entry = build_synced_session_entry(&peer_record(announced, &forward), &zones, 0)
        .expect("FIXTURE: announced record must import on the peer");
    let peer_key = entry.key.clone();
    assert!(peer.upsert_synced_with_origin(entry.into_session_install(SEC + 3_000), false));
    assert_eq!(peer.session_id_for(&peer_key), INSTALLER_ID, "peer keeps the carried id");
    assert_eq!(
        peer.close_class_wire_for(&peer_key),
        authority.close_class_wire_for(&forward),
        "#18537: the peer's copy must hold the class the local authoritative pair holds"
    );
    assert_eq!(
        peer.timeout_secs_for(&peer_key),
        authority.timeout_secs_for(&forward),
        "#18537: the peer must use the same refreshable window as the authoritative pair"
    );
    assert_ne!(
        peer.timeout_secs_for(&peer_key) as u64,
        crate::session::TCP_RST_TIMEOUT_NS_FOR_TEST / SEC,
        "#18537: the peer's copy must not be on the 2 s reset fuse"
    );
}

/// CONTROL: the same replica seeing a FIN still announces CLOSING (the
/// pre-existing class for a one-direction FIN), so the softening pinned
/// above does not alter other close transitions.
#[test]
fn fin_on_a_replica_still_announces_closing_18537() {
    let mut replica = replica_table();
    let (forward, reverse) = install_worker_pair(
        &mut replica,
        SessionOrigin::WorkerLocalImport,
        SessionOrigin::WorkerLocalImport,
        SEC,
    );
    assert!(replica.lookup(&reverse, SEC + 1_000, TCP_FIN | TCP_ACK).is_some());
    let updates: Vec<(u8, u64)> = replica
        .drain_deltas(64)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .map(|d| (d.tcp_close_class, d.session_id))
        .collect();
    assert_eq!(replica.close_class_wire_for(&forward), TcpCloseClass::Closing.to_wire());
    assert_eq!(
        updates,
        vec![(TcpCloseClass::Closing.to_wire(), INSTALLER_ID)],
        "#18537 control: a replica FIN still announces CLOSING once, with the installer's id"
    );
}

/// CONTROL: a sequence-validated RST on the authoritative worker still
/// announces Reset. Genuine owner resets keep the abort semantics on the peer.
#[test]
fn valid_rst_on_an_authoritative_pair_still_announces_reset_18537() {
    let mut table = authoritative_table();
    let (forward, reverse) = install_worker_pair(
        &mut table,
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
        SEC,
    );
    table.note_tcp_seq(&forward, 1000, 0, 4096, 0, TCP_SYN, 0);
    table.note_tcp_seq(&reverse, 5000, 1001, 4096, 0, TCP_SYN | TCP_ACK, 0);
    table.note_tcp_seq(&forward, 1001, 5001, 4096, 0, TCP_ACK, 0);
    assert_eq!(
        table.tcp_closing_seq_verdict(&reverse, 5001, TCP_RST | TCP_ACK),
        SeqVerdict::Valid,
        "FIXTURE: the owner has an exact, acknowledged RST sequence"
    );
    let updates = rst_updates(&mut table, &forward, &reverse, SEC + 1_000);
    assert_eq!(
        updates,
        vec![(TcpCloseClass::Reset.to_wire(), INSTALLER_ID)],
        "#18537 control: an authoritative valid RST still announces Reset"
    );
}
