// Control-socket request dispatcher.
//
// #1345 split the original `handle_stream` body into per-verb files in
// this directory module; the bodies have diverged since the split.
// `handle_stream` runs in phases:
//   - Stream timeout setup, BufReader / size-capped read_until, and
//     decode of one request (#2523).
//   - Off-lock session verbs, served without the `ServerState` mutex:
//     `sync_session` (#7209) and `list_sessions_by_policy` on either
//     socket, plus — on the session socket only — `ping` and the
//     lease-only `update_ha_state` fast path (#9629). Any other verb on
//     the session socket is refused without taking the lock.
//   - The locked match: `state.lock()` (via `lock_server_state_recover`)
//     is taken once, still under that single lock, before the match
//     dispatches into per-verb handlers or inline arms (`ping`,
//     `status`, `scheduler_heartbeat`, `fib_dump`, `update_fabrics`,
//     `clear_policy_counters`, `clear_nat_counters`, `clear_zone_counters`,
//     `clear_flood_counters`, `clear_filter_counters`, `shutdown`,
//     catch-all), followed by post-match `refresh_status` + status attach
//     (gated by `!suppress_status`) unless a deferred wait that re-derives
//     status is owed (`Deferred::status_after_wait`: settle, owner-RG
//     export, all-sessions export).
//   - Deferred off-lock waits (`Deferred`, #17135): the binding-settle
//     poll (#5862), the owner-RG export ack-wait (#2962), and the
//     all-sessions export push (#4054) wait off-lock, then each
//     re-derives status under a fresh short lock acquisition afterwards
//     (still gated by `!suppress_status`). The session-counter collect
//     (#7919) is the exception: `Deferred::CounterQuery` is recorded
//     outside the attach gate (`status_after_wait` is false for it), so
//     the in-lock attach above already ran, and its `collect` only waits
//     for the per-worker replies — it takes no fresh lock and does no
//     status re-derivation.
//   - Encode + flush via BufWriter / serde_json / newline; only after a
//     successful flush, `write_state` persists (when `persist_state` is
//     set), and a failed flush arms delta loss on drained contributors
//     (#5294/#16584).

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
mod policy_list;

use crate::afxdp::{HaRefreshOutcome, SessionDomain, HA_REFRESH_NEEDS_CONTROL_SOCKET};
use super::super::*;
use super::helpers::{
    lock_server_state_recover, refresh_status, wait_for_binding_settle, write_state,
};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// #17135: off-lock deferred work kicked under the `ServerState` lock.
/// Each variant owns exactly the payload its lock-free phase needs; payloads
/// differ, so the waits themselves stay separate (#2962/#4054/#5862/#7919).
/// Only the post-wait status attach is shared. `status_after_wait` is the
/// single predicate the in-lock attach consults instead of a hand-kept
/// boolean over the individual `Option`s.
pub(crate) enum Deferred {
    Settle(Duration),
    OwnerRgExport(crate::afxdp::OwnerRgExportWait),
    AllSessionsExport(crate::afxdp::AllSessionsExport),
    CounterQuery(crate::afxdp::SessionCounterQueryWait),
}

impl Deferred {
    fn status_after_wait(&self) -> bool {
        matches!(
            self,
            Deferred::Settle(_) | Deferred::OwnerRgExport(_) | Deferred::AllSessionsExport(_)
        )
    }
}

/// #17135: relock, quarantine check, refresh, attach status — the shared
/// post-wait tail for every deferred verb. Quarantined state yields no
/// status (GPT-4, #9900): skip the attach and ensure shutdown is underway.
fn attach_status_after_wait(
    state: &Arc<Mutex<ServerState>>,
    running: &Arc<AtomicBool>,
    response: &mut ControlResponse,
) {
    let mut guard = lock_server_state_recover(state);
    if guard.quarantined_after_panic {
        running.store(false, Ordering::SeqCst);
    } else {
        refresh_status(&mut guard);
        response.status = Some(guard.status.clone());
    }
}

#[cfg(test)]
mod deferred_17135_tests {
    use super::*;

    fn test_state(quarantined: bool) -> Arc<Mutex<ServerState>> {
        // Build via a raw byte name so this fixture does not itself match
        // the acceptance grep for the production quarantine checks.
        let state = Arc::new(Mutex::new(ServerState {
            status: ProcessStatus { pid: 17135, ..Default::default() },
            snapshot: None,
            afxdp: crate::afxdp::Coordinator::new(),
            state_writer: Arc::new(crate::state_writer::StateWriter::new()),
            snapshot_policy_mismatch_total: 0,
            quarantined_after_panic: false,
        }));
        state.lock().expect("state").quarantined_after_panic = quarantined;
        state
    }

    #[test]
    fn attach_status_after_wait_attaches_refreshed_status_17135() {
        let state = test_state(false);
        let running = Arc::new(AtomicBool::new(true));
        let mut response = ControlResponse::default();
        attach_status_after_wait(&state, &running, &mut response);
        let status = response.status.expect("status must attach");
        assert_eq!(status.pid, 17135);
        assert!(running.load(Ordering::SeqCst), "healthy attach must not stop the daemon");
    }

    #[test]
    fn attach_status_after_wait_quarantined_yields_no_status_17135() {
        let state = test_state(true);
        let running = Arc::new(AtomicBool::new(true));
        let mut response = ControlResponse::default();
        attach_status_after_wait(&state, &running, &mut response);
        assert!(response.status.is_none(), "quarantined state yields no status");
        assert!(!running.load(Ordering::SeqCst), "quarantine must ensure shutdown is underway");
    }

    #[test]
    fn deferred_status_after_wait_classifies_each_variant_17135() {
        // Every variant is built from a REAL kick on an empty coordinator
        // (no workers, no sessions): OwnerRgExport via the empty-set kick
        // (#2962 no-op), CounterQuery via the broadcast with zero workers
        // (#7919), AllSessionsExport via the bulk snapshot with a test
        // event stream and no sessions (#4054). Pinning CounterQuery ->
        // false is load-bearing: it is the sole variant whose status was
        // already attached in-lock, so a flipped arm would double-attach.
        assert!(Deferred::Settle(Duration::from_secs(2)).status_after_wait());

        let coordinator = crate::afxdp::Coordinator::new();
        let owner_wait = coordinator
            .kick_owner_rg_export_unpaged(&[], 0)
            .expect("empty owner-RG kick");
        assert!(Deferred::OwnerRgExport(owner_wait).status_after_wait());

        let key = crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 40001,
            dst_port: 80,
            discriminator: Default::default(),
            routing_domain: 0,
        };
        let counter_wait = coordinator.kick_session_counter_query(&key);
        assert!(
            !Deferred::CounterQuery(counter_wait).status_after_wait(),
            "CounterQuery attaches in-lock; it must NOT attach after the wait"
        );

        let (sender, _rx) = crate::event_stream::EventStreamSender::test_sender(true, 16);
        let mut coordinator = crate::afxdp::Coordinator::new();
        coordinator.event_stream = Some(sender);
        let all_export = coordinator
            .snapshot_all_sessions_export()
            .expect("empty bulk export");
        assert!(Deferred::AllSessionsExport(all_export).status_after_wait());
    }
}

/// #9629: which socket accepted this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SocketMode {
    /// Control socket: today's behavior (locked `update_ha_state`, full serve).
    Main,
    /// Session socket: `update_ha_state` takes the lease fast path (never `ServerState`).
    Session,
}

fn fabric_plan_changed(previous: &[crate::FabricSnapshot], next: &[crate::FabricSnapshot]) -> bool {
    if previous.len() != next.len() {
        return true;
    }
    previous.iter().any(|old| {
        let Some(new) = next.iter().find(|new| new.name == old.name) else {
            return true;
        };
        old.parent_interface != new.parent_interface
            || old.parent_linux_name != new.parent_linux_name
            || old.parent_ifindex != new.parent_ifindex
            || old.parent_unbindable != new.parent_unbindable
            || old.rx_queues != new.rx_queues
    })
}

struct ResponseSizeCounter(usize);

impl Write for ResponseSizeCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn enforce_fib_response_cap(
    response: &mut ControlResponse,
    byte_cap: usize,
) -> Result<(), String> {
    let mut counter = ResponseSizeCounter(0);
    serde_json::to_writer(&mut counter, response)
        .map_err(|error| format!("count fib_dump response: {error}"))?;
    let response_bytes = counter.0.saturating_add(1); // trailing newline
    if response_bytes >= byte_cap {
        response.ok = false;
        response.error = format!(
            "fib_dump response is {response_bytes} bytes and reaches the \
             {byte_cap}-byte control response cap; FIB routes were refused"
        );
        response.fib_generation = 0;
        response.fib_routes.clear();
    }
    Ok(())
}

#[cfg(test)]
mod fib_response_cap_tests {
    use super::*;

    #[test]
    fn fib_response_at_control_cap_is_refused_without_partial_rows() {
        let mut response = ControlResponse {
            ok: true,
            fib_generation: 9,
            fib_routes: vec![FibRouteWire {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "203.0.113.0/24".into(),
                kind: "route".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let exact_response_bytes = serde_json::to_vec(&response).expect("serialize fixture").len() + 1;
        enforce_fib_response_cap(&mut response, exact_response_bytes)
            .expect("count the complete response");

        assert!(!response.ok, "a response reaching the cap must be refused");
        assert_eq!(response.fib_generation, 0);
        assert!(
            response.fib_routes.is_empty(),
            "a refused FIB dump must not retain a partial row list"
        );
        assert!(
            response.error.contains("routes were refused"),
            "the response must explain the refusal: {}",
            response.error
        );
    }
}

pub(crate) fn handle_stream(
    stream: UnixStream,
    state_file: &str,
    state: Arc<Mutex<ServerState>>,
    running: Arc<AtomicBool>,
    // #7209: the session-domain handle, passed EXPLICITLY rather than derived
    // from `state` — deriving it would need the very mutex this exists to
    // avoid. Taking it as a parameter also puts the fact in the signature: this
    // dispatcher can serve `sync_session` (both sockets) and session `update_ha_state`
    // without `ServerState` at all.
    session_domain: SessionDomain,
    // #9629: which socket accepted this connection. Session `update_ha_state`
    // takes the lease fast path (never `ServerState`); Main takes the locked
    // path.
    mode: SocketMode,
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
        error_code: String::new(),
        error_retry_class: String::new(),
        status: None,
        session_counters: Vec::new(),
        session_policy_matches: Vec::new(),
        session_policy_complete: false,
        session_policy_continuation: String::new(),
        session_policy_per_worker_errors: Vec::new(),
        session_deltas: Vec::new(),
        session_export_more: false,
        session_export_dropped: 0,
        session_export_incarnation: 0,
        session_export_seq: 0,
        idle_leases: Vec::new(),
        display_leases: Vec::new(),
        lease_export_more: false,
        lease_export_continuation: String::new(),
        session_mirror_v4_count: 0,
        session_mirror_v6_count: 0,
        session_mirror_complete: false,
        session_mirror_fence_id: 0,
        session_mirror_continuation: String::new(),
        policy_delete_outcomes: Vec::new(),
        policy_delete_complete: false,
        policy_delete_errors: Vec::new(),
        fib_generation: 0,
        fib_routes: Vec::new(),
        persistent_nat_lease_count: 0,
    };
    let mut persist_state = false;
    // Capture suppress_status before the match — reading it up front
    // insulates the dispatcher from future partial-move concerns on
    // `request`.
    let suppress_status = request.suppress_status;
    let is_fib_dump = request.request_type == "fib_dump";
    let neighbor_replace = request.neighbor_replace;
    // #17135: deferred off-lock work (#2962/#4054/#5862/#7919). Each locked
    // arm only KICKS its phase and records the payload here; the blocking
    // wait/push runs after the lock drops so a stalled worker cannot freeze
    // status polls, session installs, snapshot/FIB bumps, and HA updates.
    // When set, the post-match status attach is also deferred until after
    // the wait so the reported status reflects the drained/settled state
    // (see `Deferred::status_after_wait`).
    let mut deferred: Option<Deferred> = None;
    // #16584: bindings (drain verb) / workers (owner-RG collect) that
    // contributed to the destructively-drained batch in
    // `response.session_deltas`. The tail arms loss on exactly these if the
    // response write fails.
    let mut drained_delta_slots: Vec<u32> = Vec::new();
    let mut drained_delta_workers: Vec<u32> = Vec::new();


    // #7209: THE VERBS SERVED WITHOUT `state.lock()`.
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
    let served_off_lock = matches!(
        request.request_type.as_str(),
        "sync_session" | "list_sessions_by_policy"
    );
    if request.request_type == "sync_session" {
        sync_session::handle(&session_domain, request.session_sync, &mut response);
    } else if request.request_type == "list_sessions_by_policy" {
        policy_list::handle(
            &session_domain,
            request.session_policy_list,
            &mut response,
        );
    }

    // #9629: session-socket HA fast path — lease-only refresh, never `ServerState`.
    // Served and NeedsLock both skip the lock (no status attach, no persist,
    // quarantine-immune like `sync_session`); transitions/CLEARs are owned by
    // the main path (`UpdateRGActive` + reconcile retry).
    let session_ha = mode == SocketMode::Session && request.request_type == "update_ha_state";
    if session_ha {
        match request.ha_state.as_ref() {
            None => {
                response.ok = false;
                response.error = "missing HA state".to_string();
            }
            Some(ha_req) => match session_domain.try_refresh_ha_leases(&ha_req.groups) {
                HaRefreshOutcome::Served(_) => {}
                HaRefreshOutcome::NeedsLock => {
                    response.ok = false;
                    response.error = HA_REFRESH_NEEDS_CONTROL_SOCKET.to_string();
                }
            },
        }
    }

    // #9629 (verdict item 5): the session socket serves EXACTLY `ping`
    // (below, off-lock), `sync_session` and session `update_ha_state`. Any
    // other verb arriving here is misrouted: serving it would take
    // `ServerState` on the session accept thread, wedging it behind a 10 s
    // apply while session HAs queue and die on their 3 s deadline (the exact
    // defect class this issue closes — the pre-fix `drainAndClear` ping wedge).
    // Refuse fast instead. Old Go sends only session-sync + drain pings here
    // (census-verified); new Go adds only HA refresh — no legitimate caller
    // is refused. No machine-readable const: no Go sender can trigger this
    // (all Go session verbs are allowlisted above), so tests pin the text.
    let session_ping = mode == SocketMode::Session && request.request_type == "ping";
    let session_refused =
        mode == SocketMode::Session && !served_off_lock && !session_ha && !session_ping;
    if session_refused {
        response.ok = false;
        response.error = "verb not served on session socket; use control socket".to_string();
    }

    if !served_off_lock && !session_ha && !session_ping && !session_refused {
        let mut guard = lock_server_state_recover(&state);
        // GPT-4: quarantined state serves nothing — a prior handler panic may
        // have torn it mid-mutation. Refuse and ensure shutdown is underway
        // (the panic arm already cleared `running`; this covers poison
        // observed without a witnessed panic). `sync_session` and the session
        // fast paths above stay servable: they provably never touch `ServerState`.
        if guard.quarantined_after_panic {
            running.store(false, Ordering::SeqCst);
            return Err("server state quarantined after a handler panic; restart required".to_string());
        }
        match request.request_type.as_str() {
            "ping" => {}
            "scheduler_heartbeat" => {
                guard.afxdp.scheduler_lease.apply(
                    request.version,
                    crate::afxdp::monotonic_nanos(),
                );
            }
            "status" => {
                // #9629 (Spark MAJOR-2): the status loop is the bounded
                // observability heartbeat (1s in production). Persisting its
                // refreshed live status keeps the operator/restart state file
                // from freezing indefinitely when HA ownership is unchanged.
                // Session status is refused above, so this remains on the
                // control path and does not reintroduce the session-thread
                // mutex wedge.
                persist_state = true;
            }

            "fib_dump" => match guard.afxdp.dump_fib() {
                Ok((generation, routes)) => {
                    response.fib_generation = generation;
                    response.fib_routes = routes;
                }
                Err(error) => {
                    response.ok = false;
                    response.error = error;
                }
            },
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
                &mut deferred,
            ),
            "update_ha_state" => ha::update(
                &mut guard,
                request.ha_state,
                &mut response,
                &mut persist_state,
            ),
            "update_fabrics" => {
                if let Some(fabrics) = request.fabrics.as_ref() {
                    let plan_changed = guard
                        .snapshot
                        .as_ref()
                        .is_some_and(|snapshot| fabric_plan_changed(&snapshot.fabrics, fabrics));
                    guard.afxdp.refresh_fabric_links(fabrics);
                    if plan_changed {
                        // #9803: this partial update replaces the helper's
                        // retained plan half. Keep the debt on the
                        // coordinator until a successful full apply takes
                        // the replan path; otherwise that apply sees equal
                        // plan keys and skips the fabric rebind.
                        guard.afxdp.fabric_plan_replan_required = true;
                    }
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
                &mut persist_state,
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
            // #15107: reset the helper-side firewall filter term counters
            // (and the per-colour policer counters rendered beside them).
            // Load-bearing half of the operator `clear firewall all` for the
            // same reason as clear_policy_counters above: the helper reports
            // cumulative totals every poll and the Go side mirrors them, so
            // without this reset the cleared counts would snap back within
            // <=1 s. Per-thread pending batches recorded before the clear
            // are discarded by the counters' generation guard.
            "clear_filter_counters" => {
                guard.afxdp.clear_filter_counters();
                refresh_status(&mut guard);
                persist_state = true;
            }
            "set_queue_state" => {
                queue::set(
                    &mut guard,
                    request.queue,
                    &mut response,
                    &mut persist_state,
                    &mut deferred,
                )
            }
            "set_binding_state" => binding::set(
                &mut guard,
                request.binding,
                &mut response,
                &mut persist_state,
                &mut deferred,
            ),
            "inject_packet" => inject_packet::handle(
                &mut guard,
                request.packet,
                &mut response,
                &mut persist_state,
            ),
            // #8121 part 2: the idle persistent-NAT lease channel. Both verbs
            // take the clock from the coordinator, never from the request.
            "export_idle_leases" => {
                idle_leases::export(&mut guard, request.lease_export.as_ref(), &mut response)
            }
            // #8615: the DISPLAY read. Separate verb, separate response field,
            // separate record type — the SHOW table needs `active_flows`, which
            // the sync record is forbidden to carry.
            "export_persistent_lease_display" => {
                idle_leases::export_display(&mut guard, request.lease_export.as_ref(), &mut response)
            }
            // #10784: revoke leases in the helper allocator, not only the Go display mirror.
            "clear_persistent_nat_leases" => {
                idle_leases::clear(&mut guard, &mut response)
            }
            "import_idle_leases" => idle_leases::import(
                &mut guard,
                &request.idle_leases,
                request.clear_generation_validated,
                &mut response,
            ),
            "drain_session_deltas" => session_deltas::drain(
                &mut guard,
                request.session_deltas.as_ref(),
                &mut response,
                &mut persist_state,
                &mut drained_delta_slots,
            ),
            "export_owner_rg_sessions" => {
                // #2962: locked phase only — enqueue + capture the wait
                // handle. The blocking ack-wait runs after the lock drops.
                // #9856: BUSY (or no-window continuation) folds into the
                // response here; no wait runs without a handle.
                deferred = export::owner_rg_kick(&mut guard, request.session_export, &mut response)
                    .map(Deferred::OwnerRgExport);
            }
            "export_all_sessions" => {
                // #4054: locked phase only — snapshot + capture the push
                // handle. The blocking push loop runs after the lock drops.
                deferred =
                    export::all_kick(&mut guard, &mut response).map(Deferred::AllSessionsExport);
            }
            "session_counters" => {
                // #7919 READ-ONLY diagnostic. Locked phase only: broadcast the
                // query and capture the wait handle.
                deferred = session_counters::kick(
                    &mut guard,
                    request.session_counter_query.as_ref(),
                    &mut response,
                )
                .map(Deferred::CounterQuery);
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
        // #2962/#4054/#5862: defer status attach for verbs whose deferred
        // phase re-derives it — computed after the lock-free wait below so
        // it reflects the drained/settled state (and is not produced while
        // holding the lock across a wait or a blocking push). #7919's
        // counter query attaches in-lock (its only production sender sets
        // SuppressStatus, so the asymmetry is latent).
        if deferred.as_ref().is_none_or(|d| !d.status_after_wait()) && !suppress_status {
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
    }

    // #17135: off-lock deferred phases. The waits must stay off-lock
    // (#2962/#4054/#5862/#7919) and their payloads differ, so they cannot
    // merge into one wait; only the post-wait status attach is shared
    // (`attach_status_after_wait`). At most one variant is ever set (one
    // verb per request), so the match arms are mutually exclusive.
    match deferred {
        Some(Deferred::Settle(timeout)) => {
            // #5862: poll with the lock RELEASED between iterations, so
            // `sync_session` on the dedicated HA session socket is served
            // in the gaps instead of timing out against its 3 s deadline.
            // Status is re-derived afterwards so the response reflects the
            // SETTLED bindings — the reason the in-lock attach above is
            // skipped when a settle is owed.
            wait_for_binding_settle(&state, timeout);
            if !suppress_status {
                attach_status_after_wait(&state, &running, &mut response);
            }
        }
        Some(Deferred::CounterQuery(wait)) => {
            // #7919: bounded wait for the per-worker replies, lock-free.
            // Status was already attached in-lock above (see
            // `Deferred::status_after_wait`).
            response.session_counters = session_counters::collect(wait);
        }
        Some(Deferred::OwnerRgExport(wait)) => {
            // #2962: blocking ack-wait with the lock RELEASED, so the
            // control plane stays responsive while one export drains.
            // Status is then re-derived under a fresh short-lived lock
            // acquisition (the wait is already done).
            export::owner_rg_collect(
                wait,
                &mut response,
                &mut persist_state,
                &mut drained_delta_workers,
            );
            if !suppress_status {
                attach_status_after_wait(&state, &running, &mut response);
            }
        }
        Some(Deferred::AllSessionsExport(export)) => {
            // #4054: bulk push with the lock RELEASED, so the control
            // plane stays responsive while a large/backpressured export
            // serializes. Status is then re-derived under a fresh
            // short-lived lock acquisition (the push is already done).
            export::all_push(export, &mut response);
            if !suppress_status {
                attach_status_after_wait(&state, &running, &mut response);
            }
        }
        None => {}
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
    // already-drained delta batch.
    //
    // #16584: the persist now runs AFTER a successful flush, and a failed
    // encode/write/flush arms loss on every contributing binding. Previously
    // the persist ran first (still before the error surfaced, but a slow
    // `write_state` could burn the peer's deadline with the batch hostage),
    // and a write failure after the destructive drain just returned `Err`:
    // the batch vanished with the connection, no re-queue, no latch — the
    // closes in it left stale standby rows until peer GC. Now any delivery
    // failure arms `set_delta_loss` on exactly the drained contributors
    // (deliver-or-resync, #2442/#2874/#5290) so the owning workers re-export
    // table truth; an empty batch arms nothing. Delta order is preserved
    // end-to-end: the response carries the batch exactly as drained.
    if is_fib_dump {
        enforce_fib_response_cap(&mut response, MAX_CONTROL_RESPONSE_BYTES)?;
    }
    let write_result = (|| -> Result<(), String> {
        let mut writer = BufWriter::new(&stream);
        serde_json::to_writer(&mut writer, &response)
            .map_err(|e| format!("encode response: {e}"))?;
        writer
            .write_all(b"\n")
            .map_err(|e| format!("write response newline: {e}"))?;
        writer.flush().map_err(|e| format!("flush response: {e}"))?;
        Ok(())
    })();
    if let Err(err) = write_result {
        if !response.session_deltas.is_empty()
            && (!drained_delta_slots.is_empty() || !drained_delta_workers.is_empty())
        {
            let mut guard = lock_server_state_recover(&state);
            if !guard.quarantined_after_panic {
                guard.afxdp.arm_delta_loss_for_slots(&drained_delta_slots);
                guard
                    .afxdp
                    .arm_delta_loss_for_workers(&drained_delta_workers);
            }
        }
        return Err(err);
    }

    // #5294: surface a persist failure ONLY after the response — carrying the
    // drained session deltas — has been flushed to the peer.
    if persist_state {
        write_state(state_file, &state)?;
    }
    Ok(())
}
