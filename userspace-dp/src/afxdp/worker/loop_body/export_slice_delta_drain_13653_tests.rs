// #13653 (D6-01): regression for the steady-state session-delta drain in
// `run_export_slice` (export_slice.rs).
//
// On tuple-gate contention `purge_queued_flows_for_closed_deltas` returns the
// handled prefix length: `deltas[..handled]` have already had their queued
// flows cancelled and must be flushed; only `deltas[handled..]` may be
// requeued. `drain_and_flush_all_impl` (housekeeping.rs) and the
// expiry-overflow chunk loop both flush `deltas[..handled]` before requeueing
// the suffix. The steady-state dispatch in `run_export_slice` must do the
// same; dropping `deltas[..handled]` loses those session deltas forever.

use super::*;
use crate::nat::NatDecision;
use std::net::{IpAddr, Ipv4Addr};

fn gate_key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 136, 53, 9)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn gate_decision() -> SessionDecision {
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

fn gate_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 1,
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

/// Queue one close delta for `key` through the production SessionTable API.
fn queue_close(sessions: &mut crate::session::SessionTable, key: SessionKey) {
    sessions.emit_close_delta_with_origin(
        key,
        gate_decision(),
        gate_metadata(),
        SessionOrigin::ForwardFlow,
        false,
        0,
    );
}

#[test]
fn steady_state_contention_flushes_prefix_and_requeues_suffix() {
    let channel = RuntimeViewChannel::default();
    let shared_runtime = channel.reader();
    let shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let export_buffer = ExportBufferState::new();
    let session_export_ack = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let mut sessions = SessionTable::new();
    let handled_key = gate_key(13_601);
    let blocked_key = gate_key(13_602);
    queue_close(&mut sessions, handled_key.clone());
    queue_close(&mut sessions, blocked_key.clone());
    assert!(
        sessions.has_pending_deltas(),
        "fixture must queue deltas before dispatch"
    );

    // Real tuple-gate contention on the second close's forward tuple.
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([blocked_key.clone()])
        .expect("test holds the blocked tuple's install permit");

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

    let mut flushed: Vec<SessionKey> = Vec::new();
    let mut flush_deltas =
        |_: &mut SessionTable, _: &mut [BindingWorker], _: &mut bool, deltas: &[SessionDelta]| {
            flushed.extend(deltas.iter().map(|d| d.key.clone()));
        };

    let (skip_tick, _did_work) = run_export_slice(
        &mut sessions,
        &mut bindings,
        &binding_lookup,
        &forwarding,
        &mut worker_export,
        Vec::new(),
        Vec::new(),
        None,
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

    // Release the gate before asserting so a RED run leaves no permit behind.
    drop(held);

    assert!(
        skip_tick,
        "gate contention leaves a requeued suffix that must retry next tick"
    );
    assert_eq!(
        flushed,
        vec![handled_key.clone()],
        "#13653: the handled prefix deltas[..handled] must be flushed, not dropped, \
         when the tuple gate blocks a later close"
    );
    assert!(
        sessions.has_pending_deltas(),
        "the gate-blocked suffix must remain queued for retry"
    );

    // The requeued suffix is exactly the blocked close — nothing duplicated.
    let requeued = sessions.drain_deltas(256);
    assert_eq!(
        requeued.len(),
        1,
        "#13653: exactly the blocked close must remain pending; got {requeued:?}"
    );
    assert_eq!(
        requeued[0].key, blocked_key,
        "#13653: requeued suffix must be the gate-blocked close delta"
    );
}
