// #18550: late synced imports on an ACTIVE owner: what reaches the dataplane.
//
// The suspected gap: on a node that has already activated an RG, a peer-synced
// import for that RG (the in-flight backlog a new owner drains after takeover)
// is never made visible, because the coordinator skips its immediate
// USERSPACE_SESSIONS publish for an active-owned RG
// (`upsert_synced_session_with_policy`, the `synced_entry_allows_local_replace`
// gate before `publish_synced_entry_or_note_unpublished`) and the activation
// republish (`handle_activated_rgs`) has already run.
//
// These cells drive the whole import: coordinator import -> shared authority ->
// worker fan-out -> worker upsert -> steering-row publish, with the owner RG
// locally forwarding-active throughout, on a recorder-only steering map so the
// write the worker attempts is observable without a kernel map.

use super::*;
use crate::afxdp::bpf_map::{
    RECORDER_ONLY_MAP_FD, SteeringMap, clear_session_map_writes, session_map_writes,
};
use crate::afxdp::testfx::{test_forwarding_state, test_metadata, test_resolution};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const RG: i32 = 1;
const LATE_PORT: u16 = 40_001;
const LOCAL_PORT: u16 = 40_002;

fn active_rg(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

/// LAN (ifindex 6) and WAN (ifindex 12, primary 172.16.80.8 /
/// 2001:559:8585:80::8) egress, both owned by RG 1: the loss-cluster
/// interface-SNAT shape.
fn forwarding() -> ForwardingState {
    let mut forwarding = test_forwarding_state();
    if let Some(wan) = forwarding.egress.get_mut(&12) {
        wan.primary_v6 = Some(wan_v6());
    }
    if let Some(lan) = forwarding.egress.get_mut(&6) {
        lan.primary_v6 = Some("2001:559:8585:ef00::1".parse().expect("lan v6"));
    }
    forwarding
}

fn wan_v4() -> Ipv4Addr {
    Ipv4Addr::new(172, 16, 80, 8)
}

fn wan_v6() -> Ipv6Addr {
    "2001:559:8585:80::8".parse().expect("wan v6")
}

/// Client -> iperf3 server, interface-SNAT'd to the WAN address on
/// `snat_port`.
fn forward_entry(v6: bool, snat_port: u16, origin: SessionOrigin) -> SyncedSessionEntry {
    let (family, src, dst, snat) = if v6 {
        (
            libc::AF_INET6 as u8,
            IpAddr::V6("2001:559:8585:ef00::102".parse().expect("client v6")),
            IpAddr::V6("2001:559:8585:80::200".parse().expect("server v6")),
            IpAddr::V6(wan_v6()),
        )
    } else {
        (
            libc::AF_INET as u8,
            IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            IpAddr::V4(wan_v4()),
        )
    };
    let mut metadata = test_metadata();
    metadata.owner_rg_id = RG;
    SyncedSessionEntry {
        key: SessionKey {
            addr_family: family,
            protocol: PROTO_TCP,
            src_ip: src,
            dst_ip: dst,
            src_port: 55_068,
            dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(snat),
                rewrite_src_port: Some(snat_port),
                ..NatDecision::default()
            },
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata,
        leak_incarnation: 0,
        origin,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
        source_nat_static: None,
    }
}

struct Fixture {
    coordinator: Coordinator,
    commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    worker_sessions: crate::session::SessionTable,
    ha_state: BTreeMap<i32, HAGroupRuntime>,
}

/// One worker, RG 1 forwarding-active on the coordinator AND in the worker's
/// HA view, and a coordinator session map present (recorder-only), so a
/// coordinator-side steering write would be recorded as well.
fn fixture() -> Fixture {
    let mut coordinator = Coordinator::new();
    coordinator.set_forwarding_for_test(forwarding());
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        0,
        crate::afxdp::coordinator::WorkerRuntimeRecord::for_test(WorkerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            heartbeat: Arc::new(AtomicU64::new(0)),
            commands: commands.clone(),
            session_export_ack: Arc::new(AtomicU64::new(0)),
            cos_status: Arc::new(ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(super::worker_runtime::WorkerRuntimeAtomics::new()),
            cold_path_atomics: Arc::new(super::cold_path_hist::WorkerColdPathAtomics::new()),
        }),
        None,
    );
    coordinator
        .bpf_maps
        .store(Arc::new(crate::afxdp::coordinator::BpfMaps {
            session_map_fd: Some(crate::afxdp::bpf_map::OwnedFd {
                fd: RECORDER_ONLY_MAP_FD,
            }),
            ..Default::default()
        }));
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let ha_state = BTreeMap::from([(RG, active_rg(now_secs))]);
    coordinator.ha.rg_runtime.store(Arc::new(ha_state.clone()));
    assert!(
        !crate::afxdp::session_glue::synced_entry_allows_local_replace(&ha_state, RG, now_secs),
        "fixture must model an ACTIVE owner: the local-replace guard must refuse"
    );
    Fixture {
        coordinator,
        commands,
        worker_sessions: crate::session::SessionTable::new(),
        ha_state,
    }
}

fn drain_worker(fx: &mut Fixture) {
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut scratch = VecDeque::new();
    let _ = crate::afxdp::session_glue::apply_worker_commands(
        &fx.commands,
        &mut fx.worker_sessions,
        SteeringMap::unshared_for_test(RECORDER_ONLY_MAP_FD),
        -1,
        -1,
        &fx.coordinator.forwarding,
        &fx.ha_state,
        &dynamic_neighbors,
        0,
        &mut scratch,
    );
}

fn shared(fx: &Fixture, key: &SessionKey) -> Option<SyncedSessionEntry> {
    fx.coordinator
        .sessions
        .synced
        .lock()
        .expect("synced map")
        .get(key)
        .cloned()
}

fn redirect_written(key: &SessionKey) -> bool {
    session_map_writes()
        .iter()
        .any(|write| &write.key == key && write.value == Some(USERSPACE_SESSION_ACTION_REDIRECT))
}

fn any_write(key: &SessionKey) -> bool {
    session_map_writes().iter().any(|write| &write.key == key)
}

fn assert_late_import_visible(v6: bool) {
    clear_session_map_writes();
    let mut fx = fixture();
    let entry = forward_entry(v6, LATE_PORT, SessionOrigin::SyncImport);
    let key = entry.key.clone();
    let reverse_wire = reverse_session_key(&key, entry.decision.nat);
    assert_ne!(
        reverse_wire, key,
        "fixture must be SNAT'd so the reply tuple differs"
    );

    let outcome = fx.coordinator.upsert_synced_session(entry);
    assert_eq!(outcome, SyncedImportOutcome::Applied);

    // Worker-visible authority is synchronous with the import: a worker that
    // misses its local table consults these maps on the packet path.
    assert!(
        shared(&fx, &key).is_some(),
        "late import (v6={v6}) was not published to shared authority on the active owner"
    );
    assert!(
        shared(&fx, &reverse_wire).is_some_and(|reverse| reverse.metadata.is_reverse),
        "late import (v6={v6}) left no reverse companion in shared authority: the server's \
         segments would miss on the helper"
    );

    drain_worker(&mut fx);

    let installed = fx
        .worker_sessions
        .entry_with_origin(&key)
        .expect("worker must install the late import on the active owner");
    assert!(installed.2.is_peer_synced());
    assert!(
        fx.worker_sessions
            .entry_with_origin(&reverse_wire)
            .is_some(),
        "worker must install the reverse companion (v6={v6})"
    );
    assert!(
        redirect_written(&key),
        "late import (v6={v6}) never reached USERSPACE_SESSIONS for the forward key on the \
         active owner"
    );
    assert!(
        redirect_written(&reverse_wire),
        "late import (v6={v6}) never reached USERSPACE_SESSIONS for the reply tuple on the \
         active owner"
    );
    assert!(
        !session_map_writes()
            .iter()
            .any(|write| (write.key == key || write.key == reverse_wire) && write.value.is_none()),
        "a late import must not end with its steering rows deleted (v6={v6})"
    );
}

#[test]
fn late_import_after_activation_is_published_v4() {
    assert_late_import_visible(false);
}

#[test]
fn late_import_after_activation_is_published_v6() {
    assert_late_import_visible(true);
}

/// A late peer import must never displace a NEWER local session. Two shapes:
///
/// * `shared_local`: the shared map already holds the local session (the
///   ordinary promotion shape). The coordinator's #9678 gate stops the import.
/// * worker-only: the worker promoted the flow locally but its shared publish
///   has not landed yet, so the coordinator still sees the older peer row and
///   fans the import out. The worker's own local-replace guard must refuse it.
fn assert_late_import_keeps_local(v6: bool, shared_local: bool) {
    clear_session_map_writes();
    let mut fx = fixture();
    let local = forward_entry(v6, LOCAL_PORT, SessionOrigin::SharedPromote);
    let key = local.key.clone();
    let now_ns = monotonic_nanos();
    assert!(fx.worker_sessions.install_with_protocol_with_origin(
        key.clone(),
        local.decision,
        local.metadata.clone(),
        SessionOrigin::SharedPromote,
        now_ns,
        PROTO_TCP,
        0x10,
    ));
    let shared_seed = if shared_local {
        local.clone()
    } else {
        forward_entry(v6, LOCAL_PORT, SessionOrigin::SyncImport)
    };
    crate::afxdp::shared_ops::publish_shared_session(
        &fx.coordinator.sessions.synced,
        &fx.coordinator.sessions.nat,
        &fx.coordinator.sessions.forward_wire,
        &fx.coordinator.sessions.owner_rg_indexes,
        &shared_seed,
    );

    let late = forward_entry(v6, LATE_PORT, SessionOrigin::SyncImport);
    let late_reply = reverse_session_key(&key, late.decision.nat);
    // The SNAT'd forward tuple of the LATE decision. Only an accepted late
    // FORWARD publishes it (coordinator or worker `live_session_rows`); the
    // synthesized reverse companion publishes only its own key.
    let late_wire = crate::session::forward_wire_key(&key, late.decision.nat);
    assert_ne!(late_wire, key, "fixture must be SNAT'd");
    let outcome = fx.coordinator.upsert_synced_session(late);
    assert_eq!(outcome, SyncedImportOutcome::Applied);
    if shared_local {
        let kept = shared(&fx, &key).expect("shared local entry");
        assert_eq!(kept.origin, SessionOrigin::SharedPromote);
        assert_eq!(
            kept.decision.nat.rewrite_src_port,
            Some(LOCAL_PORT),
            "late import (v6={v6}) replaced the newer local session in shared authority"
        );
    }

    drain_worker(&mut fx);

    let (decision, _, origin) = fx
        .worker_sessions
        .entry_with_origin(&key)
        .expect("local session must survive");
    assert_eq!(
        origin,
        SessionOrigin::SharedPromote,
        "late import (v6={v6}, shared_local={shared_local}) clobbered the local session"
    );
    assert_eq!(decision.nat.rewrite_src_port, Some(LOCAL_PORT));
    assert!(
        !any_write(&late_wire),
        "late import (v6={v6}, shared_local={shared_local}) steered the stale forward \
         translation while a newer local session owns the flow"
    );
    if shared_local {
        assert!(
            !any_write(&late_reply),
            "late import (v6={v6}) steered the stale reply tuple although the #9678 gate \
             stopped the import"
        );
    }
    // Worker-only shape: the synthesized reverse companion is a separate
    // per-key `UpsertSynced`, and its key (the late reply tuple) has no local
    // row, so the worker installs it. That only arises when the late row names
    // a DIFFERENT translation than the local one (another incarnation of the
    // 5-tuple); a late import for the same flow carries the same translation
    // and the same reply tuple. Not asserted either way here — recorded as a
    // residual in the issue, not pinned.
}

#[test]
fn late_import_after_activation_keeps_shared_local_session_v4() {
    assert_late_import_keeps_local(false, true);
}

#[test]
fn late_import_after_activation_keeps_shared_local_session_v6() {
    assert_late_import_keeps_local(true, true);
}

#[test]
fn late_import_after_activation_keeps_worker_local_session_v4() {
    assert_late_import_keeps_local(false, false);
}

#[test]
fn late_import_after_activation_keeps_worker_local_session_v6() {
    assert_late_import_keeps_local(true, false);
}
