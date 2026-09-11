// Control-socket request dispatcher.
//
// #1345 split: the original 415-LOC `handle_stream` body has been
// decomposed into per-verb files in this directory module. This
// `mod.rs` retains only:
//   - Stream timeout setup
//   - BufReader / size-capped read_until / decode (#2523)
//   - `state.lock()` critical section
//   - `match request.request_type.as_str()` dispatch into per-verb
//     handlers (substantive verbs) or inline bodies (trivial arms:
//     `ping`/`status`, `update_fabrics`, `clear_policy_counters`,
//     `clear_nat_counters`, `clear_zone_counters`, `shutdown`, catch-all)
//   - Post-match `refresh_status` + status attach (gated by
//     `!suppress_status`)
//   - Post-lock `write_state` (when `persist_state` is set)
//   - BufWriter / serde_json / newline / flush
//
// All per-verb files are byte-identical to the corresponding match
// arm in the pre-split `handlers.rs` modulo the `&mut ServerState`
// parameter substitution. See
// `docs/pr/1345-server-handlers-split/plan.md` for the full design.

mod session_counters;
mod binding;
mod export;
mod forwarding;
mod ha;
mod idle_leases;
mod inject_packet;
mod neighbors;
mod queue;
mod rebind;
mod session_deltas;
mod snapshot;
mod stop_workers;
mod sync_session;

use crate::afxdp::SessionDomain;
use super::super::*;
use super::helpers::{refresh_status, wait_for_binding_settle, write_state};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) fn handle_stream(
    stream: UnixStream,
    state_file: &str,
    state: Arc<Mutex<ServerState>>,
    running: Arc<AtomicBool>,
    // #7209: the session-domain handle, passed EXPLICITLY rather than derived
    // from `state` — deriving it would need the very mutex this exists to
    // avoid. Taking it as a parameter also puts the fact in the signature: this
    // dispatcher can serve one verb without `ServerState` at all.
    session_domain: SessionDomain,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set write timeout: {e}"))?;

    // Read one newline-delimited request body, capped at
    // MAX_CONTROL_REQUEST_BYTES (#2523). A malformed or compromised local
    // caller could otherwise stream a very large unterminated line and
    // force the read buffer to grow unbounded — the 5 s read timeout
    // bounds the worst case in time but not in allocation. `take` limits
    // the reader to the cap + 1 byte, so the read can never allocate
    // beyond that ceiling. The largest legitimate request is a body of up
    // to MAX bytes plus its single terminating newline (the Go encoder
    // always appends one), i.e. MAX+1 bytes ending in '\n'. If the read
    // stops at the cap WITHOUT a terminating newline the body is, by
    // construction, oversize: reject it before any decode and keep the
    // daemon alive (fail-closed).
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("clone stream for read: {e}"))?
            .take(MAX_CONTROL_REQUEST_BYTES as u64 + 1),
    );
    let mut line: Vec<u8> = Vec::new();
    let n = reader
        .read_until(b'\n', &mut line)
        .map_err(|e| format!("read request: {e}"))?;
    if n > MAX_CONTROL_REQUEST_BYTES && line.last() != Some(&b'\n') {
        return Err(format!(
            "control request exceeds maximum size of {MAX_CONTROL_REQUEST_BYTES} bytes; rejecting before decode"
        ));
    }
    let body = match line.last() {
        Some(&b'\n') => &line[..line.len() - 1],
        _ => &line[..],
    };
    let request: ControlRequest =
        serde_json::from_slice(body).map_err(|e| format!("decode request: {e}"))?;

    let mut response = ControlResponse {
        ok: true,
        error: String::new(),
        status: None,
        session_deltas: Vec::new(),
        session_export_more: false,
        idle_leases: Vec::new(),
        display_leases: Vec::new(),
        session_counters: Vec::new(),
    };
    let mut persist_state = false;
    // Capture suppress_status before the match — bool is Copy so this
    // is byte-identical, but reading it up front insulates the
    // dispatcher from future partial-move concerns on `request`.
    let suppress_status = request.suppress_status;
    let neighbor_replace = request.neighbor_replace;
    // #7919: two-phase like the exports — the locked arm only KICKS the
    // broadcast; the bounded wait runs after the lock drops, so a stalled
    // worker cannot hold the control plane for the wait's duration.
    let mut counter_query_wait: Option<crate::afxdp::SessionCounterQueryWait> = None;

    // #2962: the owner-RG session export must NOT block under the global
    // ServerState lock. The locked `match` arm only KICKS the export
    // (enqueues the per-worker command + captures the lock-free ack/delta
    // handles); the blocking 15 s ack-wait runs here, AFTER the lock is
    // dropped, so a slow/stalled worker can no longer freeze status polls,
    // session installs, snapshot/FIB bumps, and HA state updates. When set,
    // the post-match status attach is also deferred until after the wait so
    // the reported status reflects the drained state.
    let mut export_wait: Option<crate::afxdp::OwnerRgExportWait> = None;
    // #4054: the all-sessions bulk export follows the same off-lock split. The
    // locked `match` arm only SNAPSHOTS the export (session-table copy + Arc
    // handle + cloned zone map); the blocking `push_delta_lossless` loop runs
    // below, AFTER the lock is dropped, so a large/backpressured bulk export can
    // no longer freeze status polls, session installs, snapshot/FIB bumps, and
    // HA state updates. As with `export_wait`, the post-match status attach is
    // deferred until after the push.
    let mut all_export: Option<crate::afxdp::AllSessionsExport> = None;
    // #5862: the binding-settle wait follows the same split. The locked arm only
    // RECORDS that a settle is owed; the 2 s poll runs below with the lock
    // released and re-taken per iteration, so an HA `sync_session` on the
    // dedicated session socket — which dispatches through this same mutex — is
    // served in the gaps instead of timing out against its 3 s deadline (and
    // taking the rest of a #5380 bulk batch down with it).
    let mut settle_wait: Option<Duration> = None;

    // #7209: THE ONE VERB SERVED WITHOUT `state.lock()`.
    //
    // Everything below this block takes the snapshot-wide mutex, which
    // `apply_snapshot` holds across a 10 s worker-readiness barrier, a 500 ms
    // mlx5 teardown quiesce, worker `join()`s and BPF map-pin opens. Go budgets
    // 3 s for a session round-trip, and #5380 aborts the REST of a bulk batch on
    // the first transport failure — so a `sync_session` queued behind an
    // `apply_snapshot` did not arrive late, it took up to 255 session mirrors
    // down with it, during the failover this path exists to serve.
    //
    // The socket split (#452) gave this verb its own socket and thread but not
    // its own critical section. This is the split that was missing.
    //
    // NO STATUS ATTACH, AND THAT IS THE POINT. An earlier draft kept the
    // `!suppress_status` attach here, reasoning that a caller asking for status
    // is asking for a `refresh_status` and may pay for its own lock. That left
    // the verb STARVABLE — by a caller that simply omits the flag — and the
    // acceptance cell written for this issue asserts the property
    // unconditionally, which is the stronger and correct reading.
    //
    // Measured before removing it: NOTHING consumes `status` on a
    // `sync_session` response. Both daemon senders set `SuppressStatus`
    // (`pkg/dataplane/userspace/manager_sessionsync_transmit.go`), no Go caller
    // reads the field, and none of the 18 Rust cells driving this verb asserts
    // on it. So the attach was not a service being withdrawn; it was the last
    // remaining path by which an HA session mirror could queue behind a 10 s
    // worker-readiness barrier.
    let served_off_lock = request.request_type == "sync_session";
    if served_off_lock {
        sync_session::handle(&session_domain, request.session_sync, &mut response);
    }

    if !served_off_lock {
        let mut guard = state.lock().expect("server state poisoned");
        match request.request_type.as_str() {
            "ping" | "status" => {}
            "apply_snapshot" => snapshot::apply(
                &mut guard,
                request.snapshot,
                &mut response,
                &mut persist_state,
            ),
            "set_forwarding_state" => forwarding::set(
                &mut guard,
                request.forwarding,
                &mut response,
                &mut persist_state,
                &mut settle_wait,
            ),
            "update_ha_state" => ha::update(
                &mut guard,
                request.ha_state,
                &mut response,
                &mut persist_state,
            ),
            "update_fabrics" => {
                if let Some(fabrics) = request.fabrics.as_ref() {
                    guard.afxdp.refresh_fabric_links(fabrics);
                    // #3773 (L4): PERSIST the resolved fabric set. Before #3773
                    // this arm was the ONLY mutating handler that neither
                    // updated the persisted snapshot nor set `persist_state`, so
                    // the late-resolved peer/local MACs from the SyncFabricState
                    // path lived only in the coordinator's in-memory forwarding
                    // state — the published state file (read by the Go control
                    // plane's `show` surface) kept the stale apply-time fabric
                    // MACs, and any consumer of the last-written state saw them
                    // too. Fold the freshly-resolved FabricSnapshots into the
                    // stored snapshot (the persisted SSOT) so `show` reflects the
                    // truth, and flag a write ONLY when the set actually changed
                    // — the 30s periodic SyncFabricState refresh must not rewrite
                    // the state file on every unchanged tick.
                    //
                    // Restart continuity is provided by the Go control plane, not
                    // this file: the helper starts with `snapshot: None`
                    // (lifecycle.rs) and never self-restores; on restart the
                    // daemon re-applies the full snapshot and re-runs
                    // populateFabricFwd (500ms fast retries → 30s periodic), which
                    // re-resolves and re-syncs the fabric MACs. The persisted set
                    // is the observability snapshot, not the restore source.
                    if let Some(snapshot) = guard.snapshot.as_mut() {
                        if snapshot.fabrics != *fabrics {
                            snapshot.fabrics = fabrics.clone();
                            // #9520: the stored snapshot is no longer the full
                            // apply its content digest describes, so it must not
                            // vouch for a same-generation retry of that apply
                            // (handlers/snapshot.rs refuses one against an empty
                            // installed digest).
                            snapshot.content_digest.clear();
                            persist_state = true;
                        }
                    }
                    refresh_status(&mut guard);
                }
            }
            "update_neighbors" => neighbors::update(
                &mut guard,
                request.neighbors.as_ref(),
                request.neighbor_generation,
                neighbor_replace,
            ),
            "bump_fib_generation" => snapshot::bump_fib(
                &mut guard,
                request.snapshot.as_ref(),
                &mut response,
                &mut persist_state,
            ),
            "clear_policy_counters" => {
                guard.afxdp.clear_policy_counters();
                refresh_status(&mut guard);
                persist_state = true;
            }
            // #2218: reset the helper-side NAT translation hit atomics. This is
            // the LOAD-BEARING half of the operator clear: the Go side also
            // zeroes its offset map, but the helper reports cumulative-since-
            // start totals on every status poll and the Go side mirrors them
            // ABSOLUTELY (SetNATRuleCounterOffset overwrites). Without resetting
            // this store the cleared total would snap back on the next poll.
            "clear_nat_counters" => {
                guard.afxdp.clear_nat_counters();
                refresh_status(&mut guard);
                persist_state = true;
            }
            // #3651: reset the helper-side cumulative per-zone traffic totals.
            // Load-bearing half of the operator `clear` (the Go side also
            // drops its zone-counter offset map): the helper reports cumulative
            // totals every poll and the Go side REPLACES its map from that
            // snapshot (#6843), so a cleared zone reads as not-populated rather
            // than as zero. Historically the Go side mirrored them absolutely via
            // SetZoneCounterOffset, so without this reset the cleared value
            // would snap back on the next poll.
            "clear_zone_counters" => {
                guard.afxdp.clear_zone_counters();
                refresh_status(&mut guard);
                persist_state = true;
            }
            // #3651: reset the helper-side cumulative per-zone FLOOD-event
            // totals. Load-bearing half of the operator `clear` for the same
            // reason as clear_zone_counters above: the Go side drops its flood
            // offset map, but the helper reports cumulative totals every poll
            // and the Go side REPLACES its map from that snapshot, so without
            // this reset the cleared counts would snap back within <=1 s. A
            // cleared zone then reads as not-populated rather than as zero.
            // One-time (operator `clear firewall all` / REST / gRPC stats
            // reset) — never a periodic caller on this shared socket.
            "clear_flood_counters" => {
                guard.afxdp.clear_flood_counters();
                refresh_status(&mut guard);
                persist_state = true;
            }
            "set_queue_state" => {
                queue::set(
                    &mut guard,
                    request.queue,
                    &mut response,
                    &mut persist_state,
                    &mut settle_wait,
                )
            }
            "set_binding_state" => binding::set(
                &mut guard,
                request.binding,
                &mut response,
                &mut persist_state,
                &mut settle_wait,
            ),
            "inject_packet" => inject_packet::handle(
                &mut guard,
                request.packet,
                &mut response,
                &mut persist_state,
            ),
            // #8121 part 2: the idle persistent-NAT lease channel. Both verbs
            // take the clock from the coordinator, never from the request.
            "export_idle_leases" => idle_leases::export(&mut guard, &mut response),
            // #8615: the DISPLAY read. Separate verb, separate response field,
            // separate record type — the SHOW table needs `active_flows`, which
            // the sync record is forbidden to carry.
            "export_persistent_lease_display" => {
                idle_leases::export_display(&mut guard, &mut response)
            }
            "import_idle_leases" => {
                idle_leases::import(&mut guard, &request.idle_leases, &mut response)
            }
            "drain_session_deltas" => session_deltas::drain(
                &mut guard,
                request.session_deltas.as_ref(),
                &mut response,
                &mut persist_state,
            ),
            "export_owner_rg_sessions" => {
                // #2962: locked phase only — enqueue + capture the wait
                // handle. The blocking ack-wait runs after the lock drops.
                export_wait = Some(export::owner_rg_kick(&mut guard, request.session_export));
            }
            "export_all_sessions" => {
                // #4054: locked phase only — snapshot + capture the push
                // handle. The blocking push loop runs after the lock drops.
                all_export = export::all_kick(&mut guard, &mut response);
            }
            "session_counters" => {
                // #7919 READ-ONLY diagnostic. Locked phase only: broadcast the
                // query and capture the wait handle.
                counter_query_wait = session_counters::kick(
                    &mut guard,
                    request.session_counter_query.as_ref(),
                    &mut response,
                );
            }
            "rebind" => rebind::handle(&mut guard, &mut response, &mut persist_state),
            "stop_workers" => stop_workers::handle(&mut guard, &mut persist_state),
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
        // #2962/#4054: defer status attach for the export verbs — it is
        // computed after the lock-free ack-wait / push below so it reflects the
        // drained state (and is not produced while holding the lock across a
        // wait or a blocking push).
        if export_wait.is_none() && all_export.is_none() && settle_wait.is_none() && !suppress_status
        {
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
    }

    // #5862: the binding-settle poll runs here, with the global ServerState lock
    // RELEASED between iterations, so `sync_session` on the dedicated HA session
    // socket is served in the gaps rather than queued behind a 2 s wait it
    // cannot outlast (its round-trip deadline is 3 s and the #5380 batch abort
    // makes the first timeout drop the rest of the burst). Status is re-derived
    // afterwards under a fresh short-lived acquisition so the response reflects
    // the SETTLED bindings — which is what the pre-#5862 in-lock refresh gave,
    // and the reason the in-lock attach above is skipped when a settle is owed.
    if let Some(timeout) = settle_wait {
        wait_for_binding_settle(&state, timeout);
        if !suppress_status {
            let mut guard = state.lock().expect("server state poisoned");
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
    }

    // #2962: blocking owner-RG export ack-wait runs here, with the global
    // ServerState lock RELEASED, so the control plane stays responsive while
    // one export drains. Status is then re-derived under a fresh short-lived
    // lock acquisition (the wait is already done).
    // #7919: bounded wait for the per-worker replies, lock-free.
    if let Some(wait) = counter_query_wait {
        response.session_counters = session_counters::collect(wait);
    }
    if let Some(wait) = export_wait {
        export::owner_rg_collect(wait, &mut response, &mut persist_state);
        if !suppress_status {
            let mut guard = state.lock().expect("server state poisoned");
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
    }

    // #4054: all-sessions bulk export push runs here, with the global
    // ServerState lock RELEASED, so the control plane stays responsive while a
    // large/backpressured bulk export serializes. Status is then re-derived
    // under a fresh short-lived lock acquisition (the push is already done).
    if let Some(export) = all_export {
        export::all_push(export, &mut response);
        if !suppress_status {
            let mut guard = state.lock().expect("server state poisoned");
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
    }

    // #5294: the state-file persist must NOT gate delivery of the response.
    // `drain_session_deltas` (session_deltas::drain) and the owner-RG export
    // mirror (export::owner_rg_collect) DESTRUCTIVELY drain deltas out of the
    // per-binding fallback buffers / workers into `response.session_deltas`
    // before this point and set `persist_state`. The old order ran the FALLIBLE
    // `write_state` with `?` BEFORE encoding the response, so a local state-file
    // error short-circuited the send: the deltas were already popped off the
    // queue yet never reached the peer AND were not persisted — a permanent HA
    // session divergence (the standby never learns those open/close events and
    // the local copy is gone), with no loss-of-sync latch armed for a write_state
    // failure. The state file is best-effort observability, not a restore source
    // (the Go control plane re-applies the full snapshot on restart) and
    // self-corrects on the next periodic write_state, so it must never strand an
    // already-drained delta batch. Attempt the persist first (unchanged
    // ordering), but ALWAYS encode+flush the response so the drained deltas reach
    // the peer, then surface any persist error to the accept loop (logged) only
    // AFTER the response is on the wire. Delta order is preserved end-to-end:
    // the response carries the batch exactly as drained.
    let persist_result = if persist_state {
        write_state(state_file, &state)
    } else {
        Ok(())
    };

    let mut writer = BufWriter::new(stream);
    serde_json::to_writer(&mut writer, &response).map_err(|e| format!("encode response: {e}"))?;
    writer
        .write_all(b"\n")
        .map_err(|e| format!("write response newline: {e}"))?;
    writer.flush().map_err(|e| format!("flush response: {e}"))?;

    // #5294: surface a persist failure ONLY after the response — carrying the
    // drained session deltas — has been flushed to the peer.
    persist_result?;
    Ok(())
}
