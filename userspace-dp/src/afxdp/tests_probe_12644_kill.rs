//! #12644 killing probe — bound through the REAL poll path.
//!
//! The PR's resolver-level regression models the #9519 foreign discard by
//! hand; it cannot see the poll site's ordering. These cells drive the real
//! descriptor path with a seeded shared-session map so the authority verdict
//! itself decides whether promotion/materialization/purge writes land:
//!
//! * a FOREIGN hit must not materialize a local row, promote/re-tag the
//!   shared row, or purge a transient row (reds on master, which writes all
//!   three inside `resolve`, before the verdict);
//! * an OWNER hit must still apply every one of them (the deferral may not
//!   lose the owner's writes);
//! * the transient purge in particular must not be lost on the owner path.

use super::tests_support::*;
use super::*;
use crate::session::{SessionDecision, SessionKey, SessionMetadata, SessionOrigin};
use crate::tcp_flags::{TCP_ACK, TCP_SYN};
use crate::test_zone_ids::*;
use crate::{InterfaceSnapshot, PolicyRuleSnapshot, ZoneSnapshot};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const WAN_IFINDEX: i32 = 12;
const DMZ_IFINDEX: i32 = 26;
const PROBE_DMZ_MAC: [u8; 6] = [0x02, 0xbf, 0x72, 0x02, 0x00, 0x01];
const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const VIP: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 8);
const CLIENT_PORT: u16 = 54321;
const VIP_PORT: u16 = 443;
const PROBE_SESSION_ID: u64 = 0x1264_4126_4412_644;

fn probe_forwarding(dmz_permit: bool) -> ForwardingState {
    let mut s = inbound_dnat_snapshot(wan_to_lan_permit("10.0.61.102/32", "wan-in"));
    s.zones.push(ZoneSnapshot {
        name: "dmz".to_string(),
        id: TEST_DMZ_ZONE_ID,
        host_inbound_configured: true,
        host_inbound_system_services: vec!["any-service".to_string()],
        ..Default::default()
    });
    s.interfaces.push(InterfaceSnapshot {
        name: "reth2.0".to_string(),
        zone: "dmz".to_string(),
        linux_name: "ge-0-0-2".to_string(),
        ifindex: DMZ_IFINDEX,
        mtu: 1500,
        hardware_addr: "02:bf:72:02:00:01".to_string(),
        ..Default::default()
    });
    if dmz_permit {
        s.policies.push(PolicyRuleSnapshot {
            name: "dmz-in".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "lan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["10.0.61.102/32".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        });
    }
    build_forwarding_state(&s)
}

fn probe_tcp(flags: u8, arrival: i32) -> (Vec<u8>, UserspaceDpMeta) {
    let dst_mac = if arrival == WAN_IFINDEX {
        TEST_WAN_MAC
    } else {
        PROBE_DMZ_MAC
    };
    let mut frame = build_txn_tcp_syn_frame_v4(CLIENT, VIP, CLIENT_PORT, VIP_PORT, flags, dst_mac);
    let mut meta = txn_meta_v4(arrival as u32, flags, frame.len() as u16);
    if arrival == WAN_IFINDEX {
        // reth0.80 is tagged VID 80, in both the frame and the meta.
        frame.splice(12..12, [0x81, 0x00, 0x00, 80]);
        meta.ingress_vlan_id = 80;
        meta.ingress_vlan_present = 1;
        meta.l3_offset += 4;
        meta.l4_offset += 4;
        meta.payload_offset += 4;
        meta.pkt_len = frame.len() as u16;
    }
    (frame, meta)
}

fn probe_binding(ifindex: i32) -> BindingWorker {
    BindingWorker::new_for_mirror_test(0, 0, ifindex, 0)
}

fn probe_drive_shared(
    fw: &ForwardingState,
    sessions: &mut SessionTable,
    flags: u8,
    arrival: i32,
    shared: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
) -> DebugPollCounters {
    let packet = probe_tcp(flags, arrival);
    let mut b = probe_binding(arrival);
    let (batch, dbg) = txn_run_descriptor_with_shared_sessions(
        &mut b,
        sessions,
        fw,
        &txn_ha_state(),
        &packet.0,
        packet.1,
        shared,
    );
    assert_eq!(
        batch.validated_packets, 1,
        "probe packet must reach descriptor validation"
    );
    dbg
}

fn probe_count(sessions: &SessionTable) -> usize {
    let mut n = 0;
    sessions.iter_with_origin(|_k, _d, _m, _o| n += 1);
    n
}

/// Admit the DNAT'd client flow with a real WAN SYN so the copied decision
/// and metadata are exactly what the pipeline computed for this tuple.
fn admitted_forward_row(fw: &ForwardingState) -> (SessionKey, SessionDecision, SessionMetadata) {
    let mut sessions = SessionTable::new();
    let syn = probe_tcp(TCP_SYN, WAN_IFINDEX);
    let mut b = probe_binding(WAN_IFINDEX);
    let (_batch, dbg) = txn_run_descriptor_checked(
        &mut b,
        &mut sessions,
        fw,
        &txn_ha_state(),
        &syn.0,
        syn.1,
        true,
    );
    assert_eq!(
        dbg.tx, 1,
        "probe fixture: the WAN SYN must be admitted and forwarded"
    );
    let mut forward = None;
    sessions.iter_with_origin(|key, decision, metadata, _origin| {
        if !metadata.is_reverse && forward.is_none() {
            forward = Some((key.clone(), decision, metadata.clone()));
        }
    });
    forward.expect("probe fixture: admission installs a forward row")
}

type ProbeSharedMaps = (
    Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    SharedSessionOwnerRgIndexes,
);

fn probe_shared_maps() -> ProbeSharedMaps {
    (
        Arc::new(Mutex::new(FastMap::default())),
        Arc::new(Mutex::new(FastMap::default())),
        Arc::new(Mutex::new(FastMap::default())),
        SharedSessionOwnerRgIndexes::default(),
    )
}

fn probe_publish(
    maps: &ProbeSharedMaps,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
) {
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata,
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: libc::IPPROTO_TCP as u8,
        tcp_flags: TCP_ACK,
        generation: 0,
        session_id: PROBE_SESSION_ID,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        pptp_call_ids: 0,
        source_nat_static: None,
    };
    publish_shared_session(&maps.0, &maps.1, &maps.2, &maps.3, &entry);
}

/// PRIMARY KILL: a foreign hit must not materialize or promote.
#[test]
fn a_foreign_hit_does_not_materialize_or_promote_the_shared_row_12644() {
    for (dmz_permit, label) in [(false, "foreign deny"), (true, "foreign permit")] {
        let fw = probe_forwarding(dmz_permit);
        let (fkey, decision, metadata) = admitted_forward_row(&fw);
        let maps = probe_shared_maps();
        probe_publish(&maps, &fkey, decision, metadata);

        let mut sessions = SessionTable::new();
        let dbg = probe_drive_shared(&fw, &mut sessions, TCP_ACK, DMZ_IFINDEX, &maps.0);
        assert_eq!(
            probe_count(&sessions),
            0,
            "#12644 {label}: a foreign hit must not materialize a local row"
        );
        assert_eq!(
            maps.0
                .lock()
                .expect("shared sessions")
                .get(&fkey)
                .expect("the shared row must survive the foreign hit untouched")
                .origin,
            SessionOrigin::SyncImport,
            "#12644 {label}: a foreign hit must not promote/re-tag the shared row"
        );
        if dmz_permit {
            assert_eq!(dbg.tx, 1, "{label} verdict shape: the packet forwards");
        } else {
            assert_eq!(
                dbg.foreign_authority_drops, 1,
                "{label} verdict shape: the packet is dropped by its own zone"
            );
        }
    }
}

/// OWNER CONTROL: the very same fixture must still materialize and promote
/// when the packet arrives in the admitting zone — the deferral only moves
/// the writes after the verdict, it never drops the owner's.
#[test]
fn an_owner_hit_still_materializes_and_promotes_the_shared_row_12644() {
    let fw = probe_forwarding(false);
    let (fkey, decision, metadata) = admitted_forward_row(&fw);
    let maps = probe_shared_maps();
    probe_publish(&maps, &fkey, decision, metadata);

    let mut sessions = SessionTable::new();
    let dbg = probe_drive_shared(&fw, &mut sessions, TCP_ACK, WAN_IFINDEX, &maps.0);
    assert_eq!(
        dbg.tx, 1,
        "owner control: the owner ACK must forward on the entry"
    );
    assert!(
        probe_count(&sessions) >= 1,
        "#12644 owner path: the owner hit must still materialize the row"
    );
    assert_eq!(
        maps.0
            .lock()
            .expect("shared sessions")
            .get(&fkey)
            .expect("the shared row must still exist after promotion")
            .origin,
        SessionOrigin::SharedPromote,
        "#12644 owner path: the owner hit must still promote and republish the row"
    );
}

/// TRANSIENT PURGE: a foreign hit must not purge the translated transient
/// row (master purged pre-verdict), and the owner must still land the purge.
#[test]
fn a_transient_purge_waits_for_the_owner_verdict_12644() {
    let fw = probe_forwarding(true);
    let (fkey, mut decision, mut metadata) = admitted_forward_row(&fw);
    // Make the hit TRANSIENT: peer-synced + translated forward (the row's
    // source is its own SNAT rewrite) + an owner RG that is not locally
    // active (99 is absent from txn_ha_state's RGs 1 and 2).
    decision.nat.rewrite_src = Some(IpAddr::V4(CLIENT));
    metadata.owner_rg_id = 99;
    let maps = probe_shared_maps();
    probe_publish(&maps, &fkey, decision, metadata);

    // The transient row's owner RG (99) is deliberately unseeded, so the
    // packet's own enforced resolution is HA-inactive and may ride the
    // fabric redirect rather than count `tx`; this cell's subject is the
    // purge timing, not the verdict shape (the validated-packet assert in
    // probe_drive_shared pins arrival).
    let mut sessions = SessionTable::new();
    let _dbg = probe_drive_shared(&fw, &mut sessions, TCP_ACK, DMZ_IFINDEX, &maps.0);
    assert!(
        maps.0.lock().expect("shared sessions").get(&fkey).is_some(),
        "#12644: a foreign hit must not purge the transient row"
    );
    assert_eq!(
        probe_count(&sessions),
        0,
        "#12644: a foreign transient hit installs no local row"
    );

    let mut owner_sessions = SessionTable::new();
    let _ = probe_drive_shared(&fw, &mut owner_sessions, TCP_ACK, WAN_IFINDEX, &maps.0);
    assert!(
        maps.0.lock().expect("shared sessions").get(&fkey).is_none(),
        "#12644 owner path: the deferred transient purge must be applied, not lost"
    );
    assert_eq!(
        probe_count(&owner_sessions),
        0,
        "#12644 owner path: a transient purge installs no local row"
    );
}
