// Daemon-loop helpers extracted from main.rs (Issue 69.1).
// 20 helper fns called by both main::run() and server::handlers::handle_stream.
//
// All widened from file-private `fn` to `pub(crate) fn` so main.rs can
// reach them via `use server::helpers::*;` and handlers.rs (a sibling
// of this module) reaches them via `use super::helpers::*` or via the
// `use super::super::*` chain that climbs to the crate root and back
// through main.rs's helpers re-import.
//
// Pure relocation. Bodies byte-for-byte identical.

use super::super::*;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub(crate) fn refresh_status(state: &mut ServerState) {
    state.afxdp.refresh_bindings(&mut state.status.bindings);
    let writer_status = state.state_writer.status();
    state.status.io_uring_active = writer_status.active;
    state.status.io_uring_mode = writer_status.mode;
    state.status.io_uring_last_error = writer_status.last_error;
    state.status.interface_addresses = state
        .snapshot
        .as_ref()
        .map(|s| s.interfaces.iter().map(|iface| iface.addresses.len()).sum())
        .unwrap_or(0);
    let (neighbor_entries, neighbor_generation) = state.afxdp.dynamic_neighbor_status();
    state.status.neighbor_entries = neighbor_entries;
    state.status.neighbor_generation = neighbor_generation;
    // #710: cluster-wide aggregate of cross-worker CoS no-owner-binding
    // drops. The per-binding increment site is mechanical; this is the
    // only operator-facing surface for the counter.
    state.status.cos_no_owner_binding_drops_total = state.afxdp.cos_no_owner_binding_drops_total();
    state.status.route_entries = state.snapshot.as_ref().map(|s| s.routes.len()).unwrap_or(0);
    state.status.fabrics = state
        .snapshot
        .as_ref()
        .map(|s| s.fabrics.clone())
        .unwrap_or_default();
    state.status.worker_heartbeats = state.afxdp.worker_heartbeats();
    // #869: per-worker busy/idle runtime telemetry.
    state.status.worker_runtime = state.afxdp.worker_runtime_snapshots();
    state.status.debug_worker_threads = state.afxdp.worker_count();
    state.status.debug_identity_slots = state.afxdp.identity_count();
    state.status.debug_live_slots = state.afxdp.live_count();
    let (planned_workers, planned_bindings) = state.afxdp.planned_counts();
    state.status.debug_planned_workers = planned_workers;
    state.status.debug_planned_bindings = planned_bindings;
    let (reconcile_calls, reconcile_stage) = state.afxdp.reconcile_debug();
    state.status.debug_reconcile_calls = reconcile_calls;
    state.status.debug_reconcile_stage = reconcile_stage;
    state.status.ha_groups = state.afxdp.ha_groups();
    // Report enabled when all bindings are registered+armed (XSKMAP slots
    // populated). The per-queue xsk_rx_confirmed heartbeat gating handles
    // queues whose XSK RQ hasn't been bootstrapped yet — those get XDP_PASS
    // until they bootstrap naturally from background traffic.
    // Previously this required all bindings to be `ready` (first RX packet
    // received), which created a deadlock: ctrl=0 → XDP_PASS → no XSK RX
    // → not ready → ctrl stays 0.
    state.status.enabled = state.status.forwarding_armed
        && state.status.capabilities.forwarding_supported
        && !state.status.bindings.is_empty()
        && state
            .status
            .bindings
            .iter()
            .all(|b| b.registered && b.armed);
    state.status.queues = summarize_queues(&state.status.bindings);
    // #802: focused per-binding ring-pressure snapshot. Projected from
    // the freshly-refreshed BindingStatus entries so this field tracks
    // the same data source the richer `bindings[]` view exposes.
    state.status.per_binding = state
        .status
        .bindings
        .iter()
        .map(BindingCountersSnapshot::from)
        .collect();
    state.status.recent_session_deltas = state.afxdp.recent_session_deltas();
    state.status.recent_exceptions = state.afxdp.recent_exceptions();
    state.status.cos_interfaces = state.afxdp.cos_statuses();
    state.status.policy_rule_counters = state.afxdp.policy_rule_counters();
    state.status.filter_term_counters = state.afxdp.filter_term_counters();
    let (flow_worker_map, flow_worker_map_truncated) = state.afxdp.flow_worker_map();
    state.status.flow_worker_map = flow_worker_map;
    state.status.flow_worker_map_truncated = flow_worker_map_truncated;
    let (cos_active_flow_counts, cos_active_flow_counts_truncated) =
        state.afxdp.cos_active_flow_counts();
    state.status.cos_active_flow_counts = cos_active_flow_counts;
    state.status.cos_active_flow_counts_truncated = cos_active_flow_counts_truncated;
    state.status.last_resolution = state.afxdp.last_resolution();
    state.status.slow_path = state.afxdp.slow_path_status().into();
    if let Some(es_stats) = state.afxdp.event_stream_stats() {
        state.status.event_stream_connected = es_stats.connected;
        state.status.event_stream_seq = es_stats.seq;
        state.status.event_stream_acked = es_stats.acked_seq;
        state.status.event_stream_sent = es_stats.sent;
        state.status.event_stream_dropped = es_stats.dropped;
    }
    state.status.last_cache_flush_at = state.afxdp.last_cache_flush_at();
}

pub(crate) fn forwarding_unsupported_error(cap: &UserspaceCapabilities) -> String {
    if cap.unsupported_reasons.is_empty() {
        return "userspace live forwarding is not supported for the current configuration"
            .to_string();
    }
    format!(
        "userspace live forwarding is not supported: {}",
        cap.unsupported_reasons.join("; ")
    )
}

pub(crate) fn build_synced_session_key(
    req: &SessionSyncRequest,
) -> Result<crate::session::SessionKey, String> {
    Ok(crate::session::SessionKey {
        addr_family: req.addr_family,
        protocol: req.protocol,
        src_ip: req
            .src_ip
            .parse()
            .map_err(|e| format!("parse src_ip {}: {e}", req.src_ip))?,
        dst_ip: req
            .dst_ip
            .parse()
            .map_err(|e| format!("parse dst_ip {}: {e}", req.dst_ip))?,
        src_port: req.src_port,
        dst_port: req.dst_port,
    })
}

pub(crate) fn build_synced_session_entry(
    req: &SessionSyncRequest,
    zone_name_to_id: &rustc_hash::FxHashMap<String, u16>,
) -> Result<SyncedSessionEntry, String> {
    let key = build_synced_session_key(req)?;
    let next_hop = if req.next_hop.is_empty() {
        None
    } else {
        Some(
            req.next_hop
                .parse()
                .map_err(|e| format!("parse next_hop {}: {e}", req.next_hop))?,
        )
    };
    let neighbor_mac = parse_session_sync_mac(&req.neighbor_mac)
        .map_err(|e| format!("parse neighbor_mac {}: {e}", req.neighbor_mac))?;
    let src_mac = parse_session_sync_mac(&req.src_mac)
        .map_err(|e| format!("parse src_mac {}: {e}", req.src_mac))?;
    let tx_ifindex = if req.tunnel_endpoint_id != 0 {
        req.tx_ifindex.max(0)
    } else if req.tx_ifindex > 0 {
        req.tx_ifindex
    } else {
        req.egress_ifindex
    };
    let nat_src = if req.nat_src_ip.is_empty() {
        None
    } else {
        Some(
            req.nat_src_ip
                .parse()
                .map_err(|e| format!("parse nat_src_ip {}: {e}", req.nat_src_ip))?,
        )
    };
    let nat_dst = if req.nat_dst_ip.is_empty() {
        None
    } else {
        Some(
            req.nat_dst_ip
                .parse()
                .map_err(|e| format!("parse nat_dst_ip {}: {e}", req.nat_dst_ip))?,
        )
    };
    let nat_src_port = if req.nat_src_port != 0 {
        Some(req.nat_src_port)
    } else {
        None
    };
    let nat_dst_port = if req.nat_dst_port != 0 {
        Some(req.nat_dst_port)
    } else {
        None
    };
    Ok(SyncedSessionEntry {
        protocol: req.protocol,
        tcp_flags: 0,
        key,
        decision: crate::session::SessionDecision {
            resolution: afxdp::ForwardingResolution {
                disposition: if req.egress_ifindex > 0
                    || req.tx_ifindex > 0
                    || req.tunnel_endpoint_id != 0
                {
                    afxdp::ForwardingDisposition::ForwardCandidate
                } else {
                    afxdp::ForwardingDisposition::NoRoute
                },
                local_ifindex: 0,
                egress_ifindex: req.egress_ifindex,
                tx_ifindex,
                tunnel_endpoint_id: req.tunnel_endpoint_id,
                next_hop,
                neighbor_mac,
                src_mac,
                tx_vlan_id: req.tx_vlan_id,
            },
            nat: crate::nat::NatDecision {
                rewrite_src: nat_src,
                rewrite_dst: nat_dst,
                rewrite_src_port: nat_src_port,
                rewrite_dst_port: nat_dst_port,
                ..crate::nat::NatDecision::default()
            },
        },
        metadata: crate::session::SessionMetadata {
            // #919: prefer the wire u16 IDs when populated; fall back
            // to name lookup for older peers that only sent strings.
            ingress_zone: if req.ingress_zone_id != 0 {
                req.ingress_zone_id
            } else {
                zone_name_to_id
                    .get(req.ingress_zone.as_str())
                    .copied()
                    .unwrap_or(0)
            },
            egress_zone: if req.egress_zone_id != 0 {
                req.egress_zone_id
            } else {
                zone_name_to_id
                    .get(req.egress_zone.as_str())
                    .copied()
                    .unwrap_or(0)
            },
            owner_rg_id: req.owner_rg_id,
            fabric_ingress: req.fabric_ingress,
            is_reverse: req.is_reverse,
            nat64_reverse: None,
        },
        origin: crate::session::SessionOrigin::SyncImport,
    })
}

pub(crate) fn parse_session_sync_mac(value: &str) -> Result<Option<[u8; 6]>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let mut out = [0u8; 6];
    let mut count = 0usize;
    for (i, part) in value.split(':').enumerate() {
        if i >= out.len() {
            return Err("too many octets".to_string());
        }
        out[i] = u8::from_str_radix(part, 16).map_err(|e| e.to_string())?;
        count += 1;
    }
    if count != out.len() {
        return Err("expected 6 octets".to_string());
    }
    Ok(Some(out))
}

pub(crate) fn reconcile_status_bindings(state: &mut ServerState) {
    if !should_run_afxdp(&state.status) {
        state.afxdp.stop();
        state.status.bindings.iter_mut().for_each(|binding| {
            binding.bound = false;
            binding.xsk_registered = false;
            binding.xsk_bind_mode.clear();
            binding.zero_copy = false;
            binding.socket_fd = 0;
            binding.ready = false;
            binding.last_error.clear();
        });
        return;
    }
    let snapshot = state.snapshot.clone();
    let ring_entries = state.status.ring_entries;
    let mut bindings = std::mem::take(&mut state.status.bindings);
    state
        .afxdp
        .reconcile(snapshot.as_ref(), &mut bindings, ring_entries);
    state.status.bindings = bindings;
}

pub(crate) fn should_run_afxdp(status: &ProcessStatus) -> bool {
    status.forwarding_armed && status.capabilities.forwarding_supported
}

pub(crate) fn set_bindings_forwarding_armed(status: &mut ProcessStatus, armed: bool) {
    for binding in &mut status.bindings {
        binding.armed = armed && binding.registered;
        binding.last_change = Some(Utc::now());
    }
}

pub(crate) fn wait_for_binding_settle(state: &mut ServerState, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        refresh_status(state);
        if bindings_settled(&state.status.bindings) || Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn bindings_settled(bindings: &[BindingStatus]) -> bool {
    bindings.iter().all(|binding| {
        if !binding.registered {
            return !binding.bound && !binding.xsk_registered;
        }
        binding.ready || !binding.last_error.is_empty()
    })
}

#[cfg(test)]
pub(crate) fn same_binding_plan(current: &ConfigSnapshot, next: &ConfigSnapshot) -> bool {
    snapshot_binding_plan_key(current) == snapshot_binding_plan_key(next)
}

pub(crate) fn snapshot_binding_plan_key(snapshot: &ConfigSnapshot) -> String {
    let mut hasher = Sha256::new();
    update_snapshot_binding_plan_key(&mut hasher, snapshot);
    let digest = hasher.finalize();
    format!("sha256:{digest:x}")
}

fn update_snapshot_binding_plan_key(hasher: &mut Sha256, snapshot: &ConfigSnapshot) {
    let workers = snapshot
        .userspace
        .get("workers")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    let ring_entries = snapshot
        .userspace
        .get("ring_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    hash_update(hasher, &format!("workers={workers};ring={ring_entries};"));
    if let Some(shared_umem) = snapshot.userspace.get("shared_umem") {
        hash_update(hasher, "shared_umem=");
        update_canonical_json_hash(hasher, shared_umem);
        hash_update(hasher, ";");
    }
    for iface in snapshot
        .interfaces
        .iter()
        .filter(|iface| include_userspace_binding_interface(iface))
    {
        hash_update(hasher, &format!(
            "iface={}/{}/{}/{}/{}/{};",
            iface.name,
            iface.linux_name,
            iface.ifindex,
            iface.parent_ifindex,
            iface.rx_queues,
            iface.tunnel
        ));
    }
    for fab in &snapshot.fabrics {
        hash_update(hasher, &format!(
            "fabric={}/{}/{}/{};",
            fab.name, fab.parent_linux_name, fab.parent_ifindex, fab.rx_queues
        ));
    }
}

fn hash_update(hasher: &mut Sha256, input: &str) {
    hasher.update(input.as_bytes());
}

struct Sha256Writer<'a>(&'a mut Sha256);

impl Write for Sha256Writer<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn update_json_encoded<T: serde::Serialize + ?Sized>(hasher: &mut Sha256, value: &T) {
    serde_json::to_writer(Sha256Writer(hasher), value)
        .expect("canonical JSON hashing uses an infallible writer");
}

fn update_canonical_json_hash(hasher: &mut Sha256, value: &serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            hash_update(hasher, "[");
            let mut items = values.iter().map(canonical_json_key).collect::<Vec<_>>();
            items.sort();
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    hash_update(hasher, ",");
                }
                hash_update(hasher, item);
            }
            hash_update(hasher, "]");
        }
        serde_json::Value::Object(values) => {
            hash_update(hasher, "{");
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (idx, (key, value)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    hash_update(hasher, ",");
                }
                update_json_encoded(hasher, key);
                hash_update(hasher, ":");
                update_canonical_json_hash(hasher, value);
            }
            hash_update(hasher, "}");
        }
        _ => update_json_encoded(hasher, value),
    }
}

fn canonical_json_key(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical_json(value, &mut out);
    out
}

fn write_canonical_json(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Array(values) => {
            out.push('[');
            let mut items = values.iter().map(canonical_json_key).collect::<Vec<_>>();
            items.sort();
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(item);
            }
            out.push(']');
        }
        serde_json::Value::Object(values) => {
            out.push('{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (idx, (key, value)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                write_canonical_json(value, out);
            }
            out.push('}');
        }
        _ => out.push_str(&serde_json::to_string(value).unwrap_or_default()),
    }
}

pub(crate) fn include_userspace_binding_interface(iface: &InterfaceSnapshot) -> bool {
    if iface.zone.is_empty() {
        return false;
    }
    if iface.tunnel {
        return false;
    }
    if !iface.local_fabric_member.is_empty() {
        return false;
    }
    let base = iface.name.split('.').next().unwrap_or(iface.name.as_str());
    if base.starts_with("fxp") || base.starts_with("em") || base.starts_with("fab") || base == "lo0"
    {
        return false;
    }
    !matches!(iface.zone.as_str(), "mgmt" | "control")
}

pub(crate) fn replan_queues(
    snapshot: Option<&ConfigSnapshot>,
    workers: usize,
    existing: &[BindingStatus],
) -> Vec<BindingStatus> {
    let mut candidates: Vec<(String, usize)> = Vec::new();
    let mut ifindex_by_name: BTreeMap<String, i32> = BTreeMap::new();
    let mut seen_linux: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(snapshot) = snapshot {
        for iface in &snapshot.interfaces {
            if !is_userspace_candidate_interface(&iface.name) {
                continue;
            }
            let linux_name = if iface.linux_name.is_empty() {
                linux_ifname(&iface.name)
            } else {
                iface.linux_name.clone()
            };
            let rx_queues = if iface.rx_queues > 0 {
                iface.rx_queues
            } else {
                rx_queue_count(&linux_name)
            };
            if rx_queues > 0 {
                ifindex_by_name.insert(linux_name.clone(), iface.ifindex);
                seen_linux.insert(linux_name.clone());
                candidates.push((linux_name, rx_queues));
            }
        }
        // Include fabric parent interfaces so the userspace DP can transmit
        // fabric-redirect packets via XSK TX (and receive fabric ingress).
        for fabric in &snapshot.fabrics {
            if fabric.parent_ifindex <= 0 || fabric.parent_linux_name.is_empty() {
                continue;
            }
            if seen_linux.contains(&fabric.parent_linux_name) {
                continue;
            }
            let rx_queues = if fabric.rx_queues > 0 {
                fabric.rx_queues
            } else {
                rx_queue_count(&fabric.parent_linux_name)
            };
            let rx_queues = rx_queues.max(1); // fabric needs at least 1 queue for TX
            ifindex_by_name.insert(fabric.parent_linux_name.clone(), fabric.parent_ifindex);
            seen_linux.insert(fabric.parent_linux_name.clone());
            candidates.push((fabric.parent_linux_name.clone(), rx_queues));
        }
    }
    replan_bindings_from_candidates(workers, existing, candidates, ifindex_by_name)
}

pub(crate) fn replan_bindings_from_candidates(
    workers: usize,
    existing: &[BindingStatus],
    candidates: Vec<(String, usize)>,
    ifindex_by_name: BTreeMap<String, i32>,
) -> Vec<BindingStatus> {
    let mut existing_by_slot = BTreeMap::new();
    for binding in existing {
        existing_by_slot.insert(binding.slot, binding.clone());
    }
    if candidates.is_empty() {
        return Vec::new();
    }
    let queue_count = candidates.iter().map(|(_, rx)| *rx).min().unwrap_or(0);
    let interfaces = candidates
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(queue_count * interfaces.len());
    let mut slot = 0u32;
    for queue_id in 0..queue_count {
        for iface in &interfaces {
            let mut binding = existing_by_slot.remove(&slot).unwrap_or_default();
            let had_existing = binding.last_change.is_some()
                || binding.registered
                || binding.armed
                || binding.ready
                || binding.bound
                || binding.xsk_registered;
            binding.slot = slot;
            binding.queue_id = queue_id as u32;
            binding.worker_id = (queue_id % workers.max(1)) as u32;
            binding.interface = iface.clone();
            binding.ifindex = *ifindex_by_name.get(iface).unwrap_or(&0);
            if binding.ifindex <= 0 {
                binding.registered = false;
                binding.armed = false;
                binding.ready = false;
            } else if !had_existing {
                binding.registered = true;
            }
            if binding.last_change.is_none() {
                binding.last_change = Some(Utc::now());
            }
            out.push(binding);
            slot += 1;
        }
    }
    out
}

pub(crate) fn summarize_queues(bindings: &[BindingStatus]) -> Vec<QueueStatus> {
    let mut by_queue: BTreeMap<u32, Vec<&BindingStatus>> = BTreeMap::new();
    for binding in bindings {
        by_queue.entry(binding.queue_id).or_default().push(binding);
    }
    let mut out = Vec::with_capacity(by_queue.len());
    for (queue_id, group) in by_queue {
        let worker_id = group.first().map(|b| b.worker_id).unwrap_or(0);
        let interfaces = group
            .iter()
            .map(|b| b.interface.clone())
            .collect::<Vec<_>>();
        let registered = !group.is_empty() && group.iter().all(|b| b.registered);
        let armed = !group.is_empty() && group.iter().all(|b| b.registered && b.armed);
        let ready = !group.is_empty() && group.iter().all(|b| b.registered && b.ready);
        let last_change = group.iter().filter_map(|b| b.last_change).max();
        out.push(QueueStatus {
            queue_id,
            worker_id,
            interfaces,
            registered,
            armed,
            ready,
            last_change,
        });
    }
    out
}

pub(crate) fn is_userspace_candidate_interface(name: &str) -> bool {
    name.starts_with("ge-") || name.starts_with("xe-") || name.starts_with("et-")
}

pub(crate) fn linux_ifname(name: &str) -> String {
    name.replace('/', "-")
}

pub(crate) fn rx_queue_count(name: &str) -> usize {
    let path = format!("/sys/class/net/{name}/queues");
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    let count = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|entry| entry.starts_with("rx-"))
        .count();
    count.max(1)
}

pub(crate) fn write_state(state_file: &str, state: &Arc<Mutex<ServerState>>) -> Result<(), String> {
    #[derive(Serialize)]
    struct Payload<'a> {
        status: &'a ProcessStatus,
        snapshot: &'a Option<ConfigSnapshot>,
    }

    let mut guard = state.lock().expect("state poisoned");
    refresh_status(&mut guard);
    let payload = Payload {
        status: &guard.status,
        snapshot: &guard.snapshot,
    };
    let data = serde_json::to_vec_pretty(&payload).map_err(|e| format!("encode state: {e}"))?;
    let mut bytes = data;
    bytes.push(b'\n');
    guard
        .state_writer
        .persist(state_file, bytes)
        .map_err(|e| format!("write state file: {e}"))?;
    Ok(())
}
