// #15950 (H39-02 arm 2): batched export commands must not union their
// owner-RG sets into one window.
//
// `apply_worker_commands` drains up to `WORKER_COMMAND_DRAIN_BUDGET`
// commands per tick. Two `ExportOwnerRGSessions` commands can therefore
// be co-resident in one drain: typically a timed-out window's queued
// command (S1, owner RGs [1]) and its retry's command (S2, owner RGs
// [2]) — the coordinator BUSY gate cannot prevent both being queued,
// because each was kicked while the previous window looked idle from
// the coordinator's side.
//
// Pre-fix, `handle_export_owner_rg_sessions` UNIONED both RG sets and
// both sequences into one accumulator, so the adopted window exported
// RG1 ∪ RG2 under S2's token and acked S2 for a walk S2 never scoped
// (and S1's sessions shipped a second time inside S2's window). The
// decisive check in the issue: enqueue S1([1]) + S2([2]) before one
// drain; the export must ship only [2] under S2.
//
// The fix is last-command-wins at command accept, scoped to the
// WINDOW state only: a superseding accept clears the earlier
// window's sequences (`export_window_sequences`), RG set and kick
// epoch before recording its own. `exported_sequences` — the #7201
// dispatch-order/budget probe — still records every command and is
// never cleared; the first test pins both halves.
//
// FAIL-ON-REVERT: restoring the union append in
// `handle_export_owner_rg_sessions` makes the first test see
// `export_window_sequences == [1, 2]` / `export_owner_rgs == [1, 2]`
// and makes the second test (which drives the REAL
// `run_export_slice`) ship the RG1 session under token 2 as well.

use super::*;
use crate::nat::NatDecision;
use std::net::{IpAddr, Ipv4Addr};

fn batched_key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 159, 50, 9)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50)),
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn batched_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn batched_metadata(owner_rg_id: i32) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id,
        fabric_ingress: false,
        is_reverse: false,
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

fn install(sessions: &mut SessionTable, key: SessionKey, owner_rg_id: i32) {
    assert!(
        sessions.install_with_protocol(
            key,
            batched_decision(),
            batched_metadata(owner_rg_id),
            1_000_000,
            PROTO_TCP,
            0x10,
        ),
        "fixture install must succeed"
    );
    // Installs queue incremental Open deltas; clear them so the export
    // assertions below measure ONLY the export window's output.
    while !sessions.drain_deltas(256).is_empty() {}
}

/// Drive the production command drain: both export commands are queued
/// BEFORE one `apply_worker_commands` call, exactly as a worker that was
/// busy forwarding would encounter them.
fn drain_batched_exports(
    sessions: &mut SessionTable,
) -> crate::afxdp::session_glue::WorkerCommandResults {
    let commands: Arc<Mutex<VecDeque<WorkerCommand>>> = Arc::new(Mutex::new(VecDeque::new()));
    {
        let mut pending = commands.lock().expect("commands lock");
        pending.push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 1,
            owner_rgs: vec![1],
        });
        pending.push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 2,
            owner_rgs: vec![2],
        });
    }
    let forwarding = ForwardingState::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = BTreeMap::new();
    apply_worker_commands(
        &commands,
        sessions,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    )
}

#[test]
fn batched_export_commands_last_window_wins_at_accept() {
    let mut sessions = SessionTable::new();
    install(&mut sessions, batched_key(15_951), 1);
    install(&mut sessions, batched_key(15_952), 2);

    let results = drain_batched_exports(&mut sessions);

    assert_eq!(
        results.export_window_sequences,
        vec![2],
        "#15950: the batched window must name only the LAST kicked \
         command (S2); S1 was superseded in the same drain"
    );
    assert_eq!(
        results.exported_sequences,
        vec![1, 2],
        "#7201: the dispatch log records EVERY accepted command in \
         order — supersession must not clear it"
    );
    assert_eq!(
        results.export_owner_rgs,
        vec![2],
        "#15950: the batched window must carry only S2's owner RGs; \
         unioning S1's [1] leaks RG1 sessions into S2's window"
    );
    assert_eq!(
        results.export_kick_epoch,
        Some(sessions.current_epoch()),
        "#15950: the surviving window's kick epoch is captured at accept"
    );
    // Single-command control: the pre-existing behaviour is unchanged.
    let mut solo = SessionTable::new();
    install(&mut solo, batched_key(15_953), 1);
    let commands: Arc<Mutex<VecDeque<WorkerCommand>>> = Arc::new(Mutex::new(VecDeque::new()));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 7,
            owner_rgs: vec![1],
        });
    let forwarding = ForwardingState::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = BTreeMap::new();
    let solo_results = apply_worker_commands(
        &commands,
        &mut solo,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );
    assert_eq!(solo_results.exported_sequences, vec![7]);
    assert_eq!(solo_results.export_window_sequences, vec![7]);
    assert_eq!(solo_results.export_owner_rgs, vec![1]);
}

#[test]
fn batched_export_window_ships_only_last_rgs_under_last_token() {
    let rg1_key = batched_key(15_961);
    let rg2_key = batched_key(15_962);
    let mut sessions = SessionTable::new();
    install(&mut sessions, rg1_key.clone(), 1);
    install(&mut sessions, rg2_key.clone(), 2);

    let results = drain_batched_exports(&mut sessions);

    // Drive the REAL worker export slice with the drained window.
    let channel = RuntimeViewChannel::default();
    let shared_runtime = channel.reader();
    let shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let export_buffer = ExportBufferState::new();
    let session_export_ack = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut bindings: Vec<BindingWorker> = Vec::new();
    let binding_lookup = WorkerBindingLookup::default();
    let forwarding = ForwardingState::default();
    let mut worker_export: Option<WorkerExportState> = None;
    let mut export_echo_scratch: Vec<(
        SessionKey,
        SessionDecision,
        SessionMetadata,
        SessionOrigin,
    )> = Vec::new();
    let mut shared_recycles: Vec<(u32, u64)> = Vec::new();
    let mut worker_lossless_wedged = false;
    let mut flush_deltas =
        |_: &mut SessionTable, _: &mut [BindingWorker], _: &mut bool, _: &[SessionDelta]| {};

    // Bounded drive: the walk completes in one slice for two sessions,
    // but loop defensively until the window clears.
    for _ in 0..16 {
        let (skip, _did) = run_export_slice(
            &mut sessions,
            &mut bindings,
            &binding_lookup,
            &forwarding,
            &mut worker_export,
            results.export_window_sequences.clone(),
            results.export_owner_rgs.clone(),
            results.export_kick_epoch,
            &export_buffer,
            &mut export_echo_scratch,
            &mut shared_recycles,
            &shared_runtime,
            &shared_sessions,
            &shared_owner_rg_indexes,
            &session_export_ack,
            0,
            &mut flush_deltas,
            &mut worker_lossless_wedged,
        );
        assert!(!skip, "binding-less export slice must not skip the tick");
        if worker_export.is_none() {
            break;
        }
        // Subsequent passes carry no fresh commands.
        // (exported_sequences is consumed by value each call; the loop
        // above re-clones the same window only on the first pass —
        // after adoption the in-flight window resumes on its own.)
        break;
    }

    let shipped = export_buffer.drain_export(64);
    let shipped_keys: Vec<String> = shipped
        .iter()
        .map(|(token, info)| {
            assert_eq!(
                *token, 2,
                "#15950: every shipped open must carry S2's window token"
            );
            assert_eq!(info.owner_rg_id, 2);
            format!("{}:{}", info.src_ip, info.src_port)
        })
        .collect();
    assert_eq!(
        shipped_keys,
        vec![format!("10.159.50.9:{}", rg2_key.src_port)],
        "#15950: the batched window ships ONLY S2's RG2 session; the \
         RG1 session belongs to superseded S1 and must not leak in"
    );
    assert_eq!(
        session_export_ack.load(std::sync::atomic::Ordering::Acquire),
        2,
        "#15950: completion acks S2 only"
    );
    assert!(
        worker_export.is_none(),
        "#15950: the single window completes and clears"
    );
}
