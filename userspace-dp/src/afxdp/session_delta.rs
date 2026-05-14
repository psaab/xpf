// Session-delta processing extracted from afxdp.rs (Issue 67.1).
// `flush_session_deltas` is the workhorse: it drains the per-binding
// SessionDelta queues, applies them to the SessionTable, and emits
// the corresponding session-life events to the event-stream channel.
// `purge_queued_flows_for_closed_deltas` post-processes per-binding
// pending-forward queues to drop frames whose flow is now closed,
// and `session_delta_event` is a tiny string-mapping helper.
//
// Pure relocation. `use super::*;` brings every type, helper, and
// sibling-submodule item from afxdp.rs into scope.

use super::*;

pub(super) fn purge_queued_flows_for_closed_deltas(
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
    deltas: &[SessionDelta],
) {
    for delta in deltas {
        if delta.kind != SessionDeltaKind::Close {
            continue;
        }
        let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
        for binding in bindings.iter_mut() {
            cancel_queued_flow_on_binding(
                binding,
                &delta.key,
                &reverse_key,
                Some(shared_recycles),
            );
        }
        apply_shared_recycles_to_bindings(bindings, binding_lookup, shared_recycles);
    }
}

pub(super) fn flush_session_deltas(
    ident: &BindingIdentity,
    live: &BindingLiveState,
    session_map_fd: c_int,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    deltas: &[SessionDelta],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    event_stream: &Option<crate::event_stream::EventStreamWorkerHandle>,
    forwarding: &ForwardingState,
) {
    let zone_name_to_id = &forwarding.zone_name_to_id;
    let zone_id_to_name = &forwarding.zone_id_to_name;
    for delta in deltas {
        // #919/#922: emit both the resolved zone NAMES (legacy field,
        // empty when the ID is unknown) and the u16 IDs. New daemons
        // prefer the IDs; older daemons read the names. The previous
        // code wrote `metadata.ingress_zone.to_string()` here, which
        // produced "1"/"2" string literals that broke `zoneIDs[name]`
        // on the Go side.
        let ingress_name = zone_id_to_name
            .get(&delta.metadata.ingress_zone)
            .cloned()
            .unwrap_or_default();
        let egress_name = zone_id_to_name
            .get(&delta.metadata.egress_zone)
            .cloned()
            .unwrap_or_default();
        let info = SessionDeltaInfo {
            timestamp: Utc::now(),
            slot: ident.slot,
            queue_id: ident.queue_id,
            worker_id: ident.worker_id,
            interface: ident.interface.to_string(),
            ifindex: ident.ifindex,
            event: session_delta_event(delta.kind).to_string(),
            addr_family: delta.key.addr_family,
            protocol: delta.key.protocol,
            src_ip: delta.key.src_ip.to_string(),
            dst_ip: delta.key.dst_ip.to_string(),
            src_port: delta.key.src_port,
            dst_port: delta.key.dst_port,
            ingress_zone: ingress_name,
            egress_zone: egress_name,
            ingress_zone_id: delta.metadata.ingress_zone,
            egress_zone_id: delta.metadata.egress_zone,
            owner_rg_id: delta.metadata.owner_rg_id,
            disposition: match delta.decision.resolution.disposition {
                ForwardingDisposition::ForwardCandidate => "forward_candidate",
                ForwardingDisposition::LocalDelivery => "local_delivery",
                ForwardingDisposition::NoRoute => "no_route",
                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
                ForwardingDisposition::PolicyDenied => "policy_denied",
                ForwardingDisposition::FabricRedirect => "fabric_redirect",
                ForwardingDisposition::HAInactive => "ha_inactive",
                ForwardingDisposition::DiscardRoute => "discard_route",
                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
            }
            .to_string(),
            origin: delta.origin.as_str().to_string(),
            egress_ifindex: delta.decision.resolution.egress_ifindex,
            tx_ifindex: delta.decision.resolution.tx_ifindex,
            tunnel_endpoint_id: delta.decision.resolution.tunnel_endpoint_id,
            tx_vlan_id: delta.decision.resolution.tx_vlan_id,
            next_hop: delta
                .decision
                .resolution
                .next_hop
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            neighbor_mac: delta
                .decision
                .resolution
                .neighbor_mac
                .map(format_mac)
                .unwrap_or_default(),
            src_mac: delta
                .decision
                .resolution
                .src_mac
                .map(format_mac)
                .unwrap_or_default(),
            nat_src_ip: delta
                .decision
                .nat
                .rewrite_src
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            nat_dst_ip: delta
                .decision
                .nat
                .rewrite_dst
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            nat_src_port: delta.decision.nat.rewrite_src_port.unwrap_or(0),
            nat_dst_port: delta.decision.nat.rewrite_dst_port.unwrap_or(0),
            fabric_redirect: delta.fabric_redirect_sync
                || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect,
            fabric_ingress: delta.metadata.fabric_ingress,
        };
        live.push_session_delta(info.clone());
        // Push to event stream (new path) alongside existing RPC fallback.
        if let Some(es) = event_stream {
            es.push_delta(delta, zone_name_to_id);
        }
        if let Ok(mut recent) = recent_session_deltas.lock() {
            push_recent_session_delta(&mut recent, info);
        }
        if delta.kind == SessionDeltaKind::Close {
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "SESS_DELETE: proto={} {}:{} -> {}:{} nat_src={:?} nat_dst={:?} bpf_entries_before={}",
                    delta.key.protocol,
                    delta.key.src_ip,
                    delta.key.src_port,
                    delta.key.dst_ip,
                    delta.key.dst_port,
                    delta.decision.nat.rewrite_src,
                    delta.decision.nat.rewrite_dst,
                    count_bpf_session_entries(session_map_fd),
                );
            }
            delete_live_session_entry(
                session_map_fd,
                &delta.key,
                delta.decision.nat,
                delta.metadata.is_reverse,
            );
            delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, &delta.key);
            remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &delta.key,
            );
            let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
            delete_live_session_entry(session_map_fd, &reverse_key, delta.decision.nat, true);
            delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, &reverse_key);
            remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &reverse_key,
            );
            replicate_session_delete(peer_worker_commands, &delta.key);
            // #1069: reuse the reverse_key already computed above instead of
            // recomputing it. reverse_session_key is pure on its inputs and
            // delta + nat are not modified between the two replicate calls.
            replicate_session_delete(peer_worker_commands, &reverse_key);
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "SESS_DELETE_DONE: bpf_entries_after={}",
                    count_bpf_session_entries(session_map_fd),
                );
            }
        }
    }
}

fn session_delta_event(kind: SessionDeltaKind) -> &'static str {
    match kind {
        SessionDeltaKind::Open => "open",
        SessionDeltaKind::Close => "close",
    }
}
