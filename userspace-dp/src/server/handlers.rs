// Control-socket request dispatcher (#1048 P2 step 2 — relocated from
// src/server.rs into src/server/handlers.rs as part of the directory-
// module split). Pure relocation of `handle_stream`.
// All helper functions called by handle_stream remain in main.rs;
// they are private items at the crate root and thus accessible
// from this grandchild module via `use super::super::*` (which
// climbs server/handlers → server → crate root).

use super::super::*;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) fn handle_stream(
    stream: UnixStream,
    state_file: &str,
    state: Arc<Mutex<ServerState>>,
    running: Arc<AtomicBool>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set write timeout: {e}"))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("clone stream for read: {e}"))?,
    );
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read request: {e}"))?;
    let request: ControlRequest =
        serde_json::from_str(line.trim_end()).map_err(|e| format!("decode request: {e}"))?;

    let mut response = ControlResponse {
        ok: true,
        error: String::new(),
        status: None,
        session_deltas: Vec::new(),
    };
    let mut persist_state = false;

    {
        let mut guard = state.lock().expect("server state poisoned");
        match request.request_type.as_str() {
            "ping" | "status" => {}
            "apply_snapshot" => {
                if let Some(snapshot) = request.snapshot {
                    if snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION {
                        response.ok = false;
                        response.error = format!(
                            "unsupported snapshot protocol version {} (want {})",
                            snapshot.version, CONFIG_SNAPSHOT_PROTOCOL_VERSION
                        );
                    } else {
                        eprintln!(
                            "CTRL_REQ: apply_snapshot generation={} fib_generation={} forwarding_armed_before={}",
                            snapshot.generation,
                            snapshot.fib_generation,
                            guard.status.forwarding_armed
                        );
                        guard.status.last_snapshot_generation = snapshot.generation;
                        guard.status.last_fib_generation = snapshot.fib_generation;
                        guard.status.last_snapshot_at = Some(snapshot.generated_at);
                        guard.status.capabilities = snapshot.capabilities.clone();
                        let existing_bindings = guard.status.bindings.clone();
                        let previous_snapshot = guard.snapshot.as_ref();
                        let same_plan = previous_snapshot.is_some_and(|prev| {
                            let prev_key = snapshot_binding_plan_key(prev);
                            let next_key = snapshot_binding_plan_key(&snapshot);
                            let same = prev_key == next_key;
                            if !same {
                                eprintln!(
                                    "CTRL_REQ: binding plan changed prev_key={} next_key={}",
                                    prev_key, next_key
                                );
                            }
                            same
                        });
                        if same_plan {
                            guard.afxdp.refresh_runtime_snapshot(&snapshot);
                            guard.snapshot = Some(snapshot);
                            refresh_status(&mut guard);
                            persist_state = true;
                        } else {
                            let defer_workers = snapshot.defer_workers;
                            guard.snapshot = Some(snapshot);
                            let replanned = replan_queues(
                                guard.snapshot.as_ref(),
                                guard.status.workers,
                                &existing_bindings,
                            );
                            guard.status.bindings = replanned;
                            if defer_workers {
                                eprintln!(
                                    "CTRL_REQ: apply_snapshot defer_workers=true — skipping worker spawn (RETH MAC pending)"
                                );
                            } else {
                                reconcile_status_bindings(&mut guard);
                            }
                            refresh_status(&mut guard);
                            persist_state = true;
                        }
                    }
                } else {
                    response.ok = false;
                    response.error = "missing snapshot".to_string();
                }
            }
            "set_forwarding_state" => {
                if let Some(forwarding_req) = request.forwarding {
                    eprintln!(
                        "CTRL_REQ: set_forwarding_state armed={} forwarding_armed_before={}",
                        forwarding_req.armed, guard.status.forwarding_armed
                    );
                    if forwarding_req.armed && !guard.status.capabilities.forwarding_supported {
                        response.ok = false;
                        response.error = forwarding_unsupported_error(&guard.status.capabilities);
                    } else {
                        guard.status.forwarding_armed = forwarding_req.armed;
                        set_bindings_forwarding_armed(&mut guard.status, forwarding_req.armed);
                        reconcile_status_bindings(&mut guard);
                        if forwarding_req.armed {
                            wait_for_binding_settle(&mut guard, Duration::from_secs(2));
                        }
                        refresh_status(&mut guard);
                        persist_state = true;
                    }
                } else {
                    response.ok = false;
                    response.error = "missing forwarding state".to_string();
                }
            }
            "update_ha_state" => {
                if let Some(ha_req) = request.ha_state {
                    #[cfg(feature = "debug-log")]
                    eprintln!(
                        "CTRL_REQ: update_ha_state groups={} forwarding_armed={}",
                        ha_req.groups.len(),
                        guard.status.forwarding_armed
                    );
                    guard.status.ha_groups = ha_req.groups.clone();
                    match guard.afxdp.update_ha_state(&ha_req.groups) {
                        Ok(()) => {
                            refresh_status(&mut guard);
                            persist_state = true;
                        }
                        Err(err) => {
                            response.ok = false;
                            response.error = err;
                        }
                    }
                } else {
                    response.ok = false;
                    response.error = "missing HA state".to_string();
                }
            }
            "update_fabrics" => {
                if let Some(fabrics) = request.fabrics.as_ref() {
                    guard.afxdp.refresh_fabric_links(fabrics);
                    refresh_status(&mut guard);
                }
            }
            "update_neighbors" => {
                if let Some(neighbors) = request.neighbors.as_ref() {
                    let replace = request.neighbor_replace;
                    let mut resolved = Vec::with_capacity(neighbors.len());
                    for neigh in neighbors {
                        if neigh.ifindex <= 0 || neigh.mac.is_empty() {
                            continue;
                        }
                        let Ok(ip) = neigh.ip.parse::<std::net::IpAddr>() else {
                            continue;
                        };
                        let Some(mac) = afxdp::parse_mac_str(&neigh.mac) else {
                            continue;
                        };
                        if !afxdp::neighbor_state_usable_str(&neigh.state) {
                            continue;
                        }
                        resolved.push((neigh.ifindex, ip, afxdp::NeighborEntry { mac }));
                    }
                    guard.afxdp.apply_manager_neighbors(replace, &resolved);
                    refresh_status(&mut guard);
                }
            }
            "bump_fib_generation" => {
                // Lightweight FIB generation bump without a full snapshot.
                // Updates the generation counter so workers invalidate stale
                // flow cache entries, without the cost of rebuilding and
                // transmitting the entire config snapshot.
                if let Some(snapshot) = request.snapshot.as_ref() {
                    guard.status.last_fib_generation = snapshot.fib_generation;
                    if let Some(ref mut snap) = guard.snapshot {
                        snap.fib_generation = snapshot.fib_generation;
                    }
                    guard.afxdp.bump_fib_generation(snapshot.fib_generation);
                    refresh_status(&mut guard);
                } else {
                    response.ok = false;
                    response.error = "missing snapshot".to_string();
                }
            }
            "set_queue_state" => {
                if let Some(queue_req) = request.queue {
                    let mut found = false;
                    let mut registration_changed = false;
                    for binding in guard
                        .status
                        .bindings
                        .iter_mut()
                        .filter(|b| b.queue_id == queue_req.queue_id)
                    {
                        if binding.registered != queue_req.registered {
                            registration_changed = true;
                        }
                        binding.registered = queue_req.registered;
                        binding.armed = queue_req.armed && queue_req.registered;
                        binding.last_change = Some(Utc::now());
                        found = true;
                    }
                    if found {
                        if registration_changed {
                            reconcile_status_bindings(&mut guard);
                            wait_for_binding_settle(&mut guard, Duration::from_secs(2));
                        }
                        refresh_status(&mut guard);
                        persist_state = true;
                    } else {
                        response.ok = false;
                        response.error = format!("unknown queue {}", queue_req.queue_id);
                    }
                } else {
                    response.ok = false;
                    response.error = "missing queue state".to_string();
                }
            }
            "set_binding_state" => {
                if let Some(binding_req) = request.binding {
                    if let Some(binding) = guard
                        .status
                        .bindings
                        .iter_mut()
                        .find(|b| b.slot == binding_req.slot)
                    {
                        let registration_changed = binding.registered != binding_req.registered;
                        binding.registered = binding_req.registered;
                        binding.armed = binding_req.armed && binding_req.registered;
                        binding.last_change = Some(Utc::now());
                        if registration_changed {
                            reconcile_status_bindings(&mut guard);
                            wait_for_binding_settle(&mut guard, Duration::from_secs(2));
                        }
                        refresh_status(&mut guard);
                        persist_state = true;
                    } else {
                        response.ok = false;
                        response.error = format!("unknown binding slot {}", binding_req.slot);
                    }
                } else {
                    response.ok = false;
                    response.error = "missing binding state".to_string();
                }
            }
            "inject_packet" => {
                if let Some(packet_req) = request.packet {
                    match guard.afxdp.inject_test_packet(packet_req) {
                        Ok(()) => {
                            refresh_status(&mut guard);
                            persist_state = true;
                        }
                        Err(err) => {
                            response.ok = false;
                            response.error = err;
                        }
                    }
                } else {
                    response.ok = false;
                    response.error = "missing packet injection request".to_string();
                }
            }
            "sync_session" => {
                if let Some(sync_req) = request.session_sync {
                    match sync_req.operation.as_str() {
                        "upsert" => match build_synced_session_entry(
                            &sync_req,
                            guard.afxdp.zone_name_to_id_ref(),
                        ) {
                            Ok(entry) => {
                                guard.afxdp.upsert_synced_session(entry);
                            }
                            Err(err) => {
                                response.ok = false;
                                response.error = err;
                            }
                        },
                        "delete" => match build_synced_session_key(&sync_req) {
                            Ok(key) => {
                                guard.afxdp.delete_synced_session(key);
                            }
                            Err(err) => {
                                response.ok = false;
                                response.error = err;
                            }
                        },
                        other => {
                            response.ok = false;
                            response.error = format!("unknown session sync operation {other}");
                        }
                    }
                } else {
                    response.ok = false;
                    response.error = "missing session sync request".to_string();
                }
            }
            "drain_session_deltas" => {
                let max = request
                    .session_deltas
                    .as_ref()
                    .map(|req| req.max)
                    .unwrap_or(256)
                    .max(1) as usize;
                response.session_deltas = guard.afxdp.drain_session_deltas(max);
                refresh_status(&mut guard);
                persist_state = true;
            }
            "export_owner_rg_sessions" => {
                let export_req = request.session_export.unwrap_or_default();
                match guard
                    .afxdp
                    .export_owner_rg_sessions(&export_req.owner_rgs, export_req.max as usize)
                {
                    Ok(deltas) => {
                        response.session_deltas = deltas;
                        refresh_status(&mut guard);
                        persist_state = true;
                    }
                    Err(err) => {
                        response.ok = false;
                        response.error = err;
                    }
                }
            }
            "export_all_sessions" => match guard.afxdp.export_all_sessions_to_event_stream() {
                Ok(_count) => {
                    refresh_status(&mut guard);
                }
                Err(err) => {
                    response.ok = false;
                    response.error = err;
                }
            },
            "rebind" => {
                // After a link DOWN/UP cycle (e.g. RETH MAC programming),
                // the kernel destroys the XSK receive queue.  Stop all
                // workers, clear binding state, and reconcile to recreate
                // the AF_XDP sockets from scratch.
                //
                // No settle wait — worker threads create sockets async.
                // The response returns immediately; sockets become ready
                // within ~100ms as worker threads complete binding.
                eprintln!("rebind: stopping workers and recreating AF_XDP sockets");
                guard.afxdp.stop();
                for binding in &mut guard.status.bindings {
                    binding.bound = false;
                    binding.xsk_registered = false;
                    binding.xsk_bind_mode.clear();
                    binding.zero_copy = false;
                    binding.socket_fd = 0;
                    binding.ready = false;
                    binding.last_error.clear();
                }
                reconcile_status_bindings(&mut guard);
                refresh_status(&mut guard);
                persist_state = true;
                eprintln!(
                    "rebind: initiated, forwarding_armed={} bindings={}",
                    guard.status.forwarding_armed,
                    guard.status.bindings.len()
                );
            }
            "stop_workers" => {
                // Stop all AF_XDP workers without recreating them.
                // Used by PrepareLinkCycle: stops workers BEFORE link
                // DOWN/UP so they don't access DMA-mapped UMEM pages
                // that the NIC unmaps during link cycle. The subsequent
                // "rebind" request (sent by NotifyLinkCycle after the
                // link is back UP) recreates workers with fresh sockets.
                eprintln!("stop_workers: stopping all AF_XDP workers");
                guard.afxdp.stop();
                for binding in &mut guard.status.bindings {
                    binding.bound = false;
                    binding.xsk_registered = false;
                    binding.xsk_bind_mode.clear();
                    binding.zero_copy = false;
                    binding.socket_fd = 0;
                    binding.ready = false;
                    binding.last_error.clear();
                }
                refresh_status(&mut guard);
                persist_state = true;
                eprintln!(
                    "stop_workers: all workers stopped, bindings={}",
                    guard.status.bindings.len()
                );
            }
            "shutdown" => {
                guard.afxdp.stop_with_event_stream();
                running.store(false, Ordering::SeqCst);
                persist_state = true;
            }
            other => {
                response.ok = false;
                response.error = format!("unknown request type {other}");
            }
        }
        if !request.suppress_status {
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
    }

    if persist_state {
        write_state(state_file, &state)?;
    }

    let mut writer = BufWriter::new(stream);
    serde_json::to_writer(&mut writer, &response).map_err(|e| format!("encode response: {e}"))?;
    writer
        .write_all(b"\n")
        .map_err(|e| format!("write response newline: {e}"))?;
    writer.flush().map_err(|e| format!("flush response: {e}"))?;
    Ok(())
}
