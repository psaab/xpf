use super::*;

const LOCAL_TUNNEL_SESSION_PRUNE_INTERVAL_NS: u64 = 5_000_000_000;
const LOCAL_TUNNEL_SESSION_STALE_NS: u64 = 30_000_000_000;
const LOCAL_TUNNEL_SESSION_PRUNE_THRESHOLD: usize = 4096;

fn local_tunnel_io_error_is_fatal(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code)
            if code == libc::EINVAL
                || code == libc::EBADF
                || code == libc::EBADFD
                || code == libc::ENODEV
                || code == libc::ENXIO
    )
}

pub(super) fn local_tunnel_source_loop(
    tunnel_name: String,
    tunnel_endpoint_id: u16,
    forwarding: ForwardingState,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    live: BTreeMap<u32, Arc<BindingLiveState>>,
    identities: BTreeMap<u32, BindingIdentity>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    delivery_rx: Receiver<Vec<u8>>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    stop: Arc<AtomicBool>,
) {
    let mut tun = match open_tun(&tunnel_name) {
        Ok((file, _actual_name)) => file,
        Err(err) => {
            record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
            return;
        }
    };
    if let Err(err) = set_fd_nonblocking(tun.as_raw_fd()) {
        record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
        return;
    }

    let mut packet = vec![0u8; 65_536];
    let mut next_slot = 0usize;
    let mut local_sessions = FastMap::<SessionKey, u64>::default();
    let mut local_sessions_last_prune_ns = 0u64;
    while !stop.load(Ordering::Relaxed) {
        loop {
            match delivery_rx.try_recv() {
                Ok(packet) => {
                    if let Err(err) = tun.write_all(&packet) {
                        record_local_tunnel_exception(
                            &recent_exceptions,
                            &tunnel_name,
                            format!("write_local_tunnel_delivery:{err}"),
                        );
                        if local_tunnel_io_error_is_fatal(&err) {
                            return;
                        }
                        break;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        match tun.read(&mut packet) {
            Ok(0) => thread::sleep(Duration::from_millis(1)),
            Ok(len) => {
                let packet = &packet[..len];
                match build_local_origin_tunnel_tx_request(
                    packet,
                    tunnel_endpoint_id,
                    &forwarding,
                    &ha_state,
                    &dynamic_neighbors,
                ) {
                    Ok(plan) => {
                        maybe_enqueue_local_tunnel_session(
                            &shared_sessions,
                            &shared_nat_sessions,
                            &shared_forward_wire_sessions,
                            &shared_owner_rg_indexes,
                            &worker_commands,
                            &mut local_sessions,
                            &mut local_sessions_last_prune_ns,
                            &plan,
                        );
                        if let Some(target_live) = select_live_binding_for_ifindex(
                            &identities,
                            &live,
                            plan.tx_ifindex,
                            next_slot,
                        ) {
                            next_slot = next_slot.wrapping_add(1);
                            if let Err(err) = target_live.enqueue_tx(plan.tx_request) {
                                record_local_tunnel_exception(
                                    &recent_exceptions,
                                    &tunnel_name,
                                    format!("enqueue_local_tunnel_tx:{err}"),
                                );
                            }
                        } else {
                            record_local_tunnel_exception(
                                &recent_exceptions,
                                &tunnel_name,
                                format!("no_live_binding_for_tx_ifindex:{}", plan.tx_ifindex),
                            );
                        }
                    }
                    Err(err) => {
                        #[cfg(not(feature = "debug-log"))]
                        let _ = &err;
                        debug_log!(
                            "LOCAL_TUNNEL[{}]: drop endpoint={} reason={}",
                            tunnel_name,
                            tunnel_endpoint_id,
                            err
                        );
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(err) => {
                record_local_tunnel_exception(
                    &recent_exceptions,
                    &tunnel_name,
                    format!("read_local_tunnel:{err}"),
                );
                if local_tunnel_io_error_is_fatal(&err) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

pub(super) fn build_local_origin_tunnel_tx_request(
    packet: &[u8],
    tunnel_endpoint_id: u16,
    forwarding: &ForwardingState,
    ha_state: &Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> Result<LocalTunnelTxPlan, String> {
    let mut meta = local_origin_packet_meta(packet)
        .ok_or_else(|| "unsupported_local_origin_packet".to_string())?;
    let inner_frame = wrap_raw_ip_packet_for_tunnel(packet, meta.addr_family);
    meta.l3_offset = 14;
    meta.l4_offset = meta.l4_offset.saturating_add(14);
    meta.payload_offset = meta.payload_offset.saturating_add(14);
    let resolution = enforce_ha_resolution_at(
        forwarding,
        ha_state,
        monotonic_nanos() / 1_000_000_000,
        resolve_tunnel_forwarding_resolution(
            forwarding,
            Some(dynamic_neighbors),
            tunnel_endpoint_id,
            0,
        ),
    );
    if resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return Err(format!(
            "local_tunnel_resolution:{}",
            resolution.status(None, forwarding).disposition
        ));
    }
    let decision = SessionDecision {
        resolution,
        nat: NatDecision::default(),
    };
    let flow = parse_session_flow_from_bytes(&inner_frame, meta)
        .ok_or_else(|| "parse_local_origin_session_flow_failed".to_string())?;
    // #921: zone_id is now a u16 field on EgressInterface — direct
    // load, no name round-trip.
    let zone_id = forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .map(|iface| iface.zone_id)
        .unwrap_or(0);
    let bytes = encapsulate_native_gre_frame(&inner_frame, meta, &decision, forwarding)
        .ok_or_else(|| "encapsulate_native_gre_frame_failed".to_string())?;
    let session_entry = SyncedSessionEntry {
        key: flow.forward_key,
        decision,
        metadata: SessionMetadata {
            ingress_zone: zone_id,
            egress_zone: zone_id,
            owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: meta.protocol,
        tcp_flags: if meta.protocol == PROTO_TCP {
            extract_tcp_flags_and_window(&inner_frame)
                .map(|(flags, _)| flags)
                .unwrap_or_default()
        } else {
            0
        },
    };
    let reverse_session_entry = synthesized_synced_reverse_entry(
        forwarding,
        ha_state.load().as_ref(),
        dynamic_neighbors,
        &session_entry,
        monotonic_nanos() / 1_000_000_000,
    );
    let now_ns = monotonic_nanos();
    let cos = resolve_cos_tx_selection_at(
        forwarding,
        decision.resolution.egress_ifindex,
        meta,
        Some(&session_entry.key),
        now_ns,
    );
    if cos.drop {
        return Err("local_tunnel_packet_dropped_by_three_color_policer".to_string());
    }
    Ok(LocalTunnelTxPlan {
        tx_ifindex: decision.resolution.tx_ifindex,
        tx_request: TxRequest {
            bytes,
            expected_ports: None,
            expected_addr_family: 0,
            expected_protocol: 0,
            flow_key: None,
            egress_ifindex: decision.resolution.egress_ifindex,
            cos_queue_id: cos.queue_id,
            dscp_rewrite: cos.dscp_rewrite,
            mirror_clone: false,
        },
        session_entry,
        reverse_session_entry,
    })
}

pub(super) fn local_origin_packet_meta(packet: &[u8]) -> Option<UserspaceDpMeta> {
    let version = packet.first()? >> 4;
    let addr_family = match version {
        4 => libc::AF_INET as u8,
        6 => libc::AF_INET6 as u8,
        _ => return None,
    };
    let (l4_offset, protocol) = packet_rel_l4_offset_and_protocol(packet, addr_family)?;
    Some(UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l4_offset: l4_offset.min(u16::MAX as usize) as u16,
        payload_offset: l4_offset.min(u16::MAX as usize) as u16,
        pkt_len: packet.len().min(u16::MAX as usize) as u16,
        addr_family,
        protocol,
        ..UserspaceDpMeta::default()
    })
}

pub(super) fn wrap_raw_ip_packet_for_tunnel(packet: &[u8], addr_family: u8) -> Vec<u8> {
    let mut frame = vec![0u8; 14 + packet.len()];
    frame[12..14].copy_from_slice(if addr_family as i32 == libc::AF_INET {
        &[0x08, 0x00]
    } else {
        &[0x86, 0xdd]
    });
    frame[14..].copy_from_slice(packet);
    frame
}

pub(super) fn maybe_enqueue_local_tunnel_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    local_sessions: &mut FastMap<SessionKey, u64>,
    local_sessions_last_prune_ns: &mut u64,
    plan: &LocalTunnelTxPlan,
) {
    let now_ns = monotonic_nanos();
    prune_local_tunnel_sessions(local_sessions, local_sessions_last_prune_ns, now_ns);
    let entry = &plan.session_entry;
    let refresh_after_ns = if matches!(entry.protocol, PROTO_TCP) {
        5_000_000_000
    } else {
        1_000_000_000
    };
    if matches!(
        local_sessions.get(&entry.key),
        Some(last) if now_ns.saturating_sub(*last) < refresh_after_ns
    ) {
        return;
    }
    local_sessions.insert(entry.key.clone(), now_ns);
    publish_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        entry,
    );
    if let Some(reverse) = &plan.reverse_session_entry {
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            reverse,
        );
    }
    for pending in worker_commands {
        if let Ok(mut pending) = pending.lock() {
            pending.push_back(WorkerCommand::UpsertLocal(entry.clone()));
            if let Some(reverse) = &plan.reverse_session_entry {
                pending.push_back(WorkerCommand::UpsertLocal(reverse.clone()));
            }
        }
    }
    wait_for_local_tunnel_session_install(worker_commands, now_ns + 1_000_000);
}

fn prune_local_tunnel_sessions(
    local_sessions: &mut FastMap<SessionKey, u64>,
    last_prune_ns: &mut u64,
    now_ns: u64,
) {
    if local_sessions.len() < LOCAL_TUNNEL_SESSION_PRUNE_THRESHOLD
        || now_ns.saturating_sub(*last_prune_ns) < LOCAL_TUNNEL_SESSION_PRUNE_INTERVAL_NS
    {
        return;
    }
    let cutoff_ns = now_ns.saturating_sub(LOCAL_TUNNEL_SESSION_STALE_NS);
    local_sessions.retain(|_, seen_ns| *seen_ns >= cutoff_ns);
    *last_prune_ns = now_ns;
}

pub(super) fn wait_for_local_tunnel_session_install(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    deadline_ns: u64,
) {
    while monotonic_nanos() < deadline_ns {
        let all_drained = worker_commands.iter().all(|pending| {
            pending
                .lock()
                .map(|pending| pending.is_empty())
                .unwrap_or(false)
        });
        if all_drained {
            break;
        }
        std::hint::spin_loop();
        thread::sleep(Duration::from_micros(50));
    }
}

pub(super) fn select_live_binding_for_ifindex(
    identities: &BTreeMap<u32, BindingIdentity>,
    live: &BTreeMap<u32, Arc<BindingLiveState>>,
    tx_ifindex: i32,
    next_slot: usize,
) -> Option<Arc<BindingLiveState>> {
    let mut candidate_count = 0usize;
    for identity in identities.values() {
        if identity.ifindex != tx_ifindex {
            continue;
        }
        if let Some(live_state) = live.get(&identity.slot) {
            if live_state.bound.load(Ordering::Relaxed) {
                candidate_count += 1;
            }
        }
    }
    if candidate_count == 0 {
        return None;
    }
    let target_index = next_slot % candidate_count;
    let mut current_index = 0usize;
    for identity in identities.values() {
        if identity.ifindex != tx_ifindex {
            continue;
        }
        if let Some(live_state) = live.get(&identity.slot) {
            if live_state.bound.load(Ordering::Relaxed) {
                if current_index == target_index {
                    return Some(live_state.clone());
                }
                current_index += 1;
            }
        }
    }
    None
}

pub(super) fn set_fd_nonblocking(fd: c_int) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "fcntl(F_GETFL) failed: {}",
            io::Error::last_os_error()
        ));
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(format!(
            "fcntl(F_SETFL,O_NONBLOCK) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tunnel_tests.rs"]
mod tests;

pub(super) fn record_local_tunnel_exception(
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    tunnel_name: &str,
    reason: String,
) {
    if let Ok(mut recent) = recent_exceptions.lock() {
        push_recent_exception(
            &mut recent,
            ExceptionStatus {
                timestamp: Utc::now(),
                interface: tunnel_name.to_string(),
                reason,
                ..ExceptionStatus::default()
            },
        );
    }
}
