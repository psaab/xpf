// Colocated unit tests for the server/ control-plane handlers and
// helpers (#1653 Tier B / §3.1). Prior to this module `server/` had
// zero tests of its own — the only handler coverage lived in
// main_tests.rs and exercised apply_snapshot / queue-planner /
// session-sync paths. The #1642 status-field-parity drift lived in
// exactly this untested glue, so these tests assert handler behavior
// at the real `handle_stream` call site (not trivial getters): error
// arms, status-field population, HA gating, and the pure helper
// predicates.

use super::helpers::{
    bindings_settled, build_synced_session_entry, clear_pre_persist_lock_probe,
    forwarding_unsupported_error, parse_session_sync_mac, reconcile_status_bindings,
    refresh_status, set_bindings_forwarding_armed, should_run_afxdp, take_pre_persist_lock_free,
    write_state,
};
use super::{handle_stream, ServerState};
use crate::state_writer::StateWriter;
use crate::{
    afxdp, BindingControlRequest, BindingStatus, ControlRequest, ControlResponse, ForwardingControlRequest,
    HAGroupStatus, HAStateUpdateRequest, ProcessStatus, QueueControlRequest, SessionExportRequest,
    SessionSyncRequest, UserspaceCapabilities, MAX_CONTROL_REQUEST_BYTES,
};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

// --- harness ------------------------------------------------------------

fn unique_state_file(tag: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}/xpf-server-test-{}-{}-{}.json",
        std::env::temp_dir().display(),
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn new_state(status: ProcessStatus) -> Arc<Mutex<ServerState>> {
    Arc::new(Mutex::new(ServerState {
        status,
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }))
}

/// Drive a single control request through the real `handle_stream`
/// dispatcher over a socketpair, exactly as the daemon's accept loop
/// does. Returns the decoded `ControlResponse`.
fn run_request(state: Arc<Mutex<ServerState>>, request: ControlRequest) -> ControlResponse {
    // #7209: derived here, with nothing else holding the mutex — the same shape
    // as production, where `lifecycle.rs` clones ONE handle at startup and hands
    // it to both socket loops. A caller that is deliberately holding the lock
    // must use `run_request_with_domain` and take its handle first, or the
    // derivation itself becomes the thing that blocks and the cell measures the
    // harness rather than the dispatcher.
    let session_domain = state.lock().expect("state").afxdp.session_domain().clone();
    run_request_with_domain(state, request, session_domain)
}

/// `run_request` with the session-domain handle supplied by the caller, for a
/// cell that holds the `ServerState` mutex across the request (#7209).
fn run_request_with_domain(
    state: Arc<Mutex<ServerState>>,
    request: ControlRequest,
    session_domain: crate::afxdp::SessionDomain,
) -> ControlResponse {
    let state_file = unique_state_file(&request.request_type);
    let (mut client, server) =
        std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let handle = {
        let state_file = state_file.clone();
        std::thread::spawn(move || {
            handle_stream(server, &state_file, state, running, session_domain)
        })
    };

    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
    let _ = std::fs::remove_file(&state_file);
    response
}

/// Like `run_request` but drives against a caller-supplied `state_file`
/// and does NOT remove it, so a test can assert what the handler persisted
/// to disk (used by the #3767 M2 bump-persistence test).
fn run_request_on_file(
    state: Arc<Mutex<ServerState>>,
    request: ControlRequest,
    state_file: &str,
) -> ControlResponse {
    let (mut client, server) =
        std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let handle = {
        let state_file = state_file.to_string();
        {
            let sd = state.lock().expect("state").afxdp.session_domain().clone();
            std::thread::spawn(move || handle_stream(server, &state_file, state, running, sd))
        }
    };

    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
    response
}

fn req(request_type: &str) -> ControlRequest {
    ControlRequest {
        request_type: request_type.to_string(),
        ..ControlRequest::default()
    }
}

/// Drive a RAW byte payload through `handle_stream` and return the
/// handler's `Result<(), String>` directly. Unlike `run_request`, this
/// does not assume the handler replies — an oversize/undecodable request
/// is rejected before the reply is written, so the caller inspects the
/// returned error string. The client half writes `payload` then shuts
/// down the write side so a body WITHOUT a terminating newline still
/// reaches EOF (the `take` cap, not the missing newline, must be what
/// bounds the read).
/// #9549: `run_request`, but the WireGuard secrets survive the socket.
///
/// `wg_local_privkey_hex` is `#[serde(default, skip_serializing)]` so the key never
/// reaches the state file on disk, and the Go control plane writes it into the JSON
/// it sends. `run_request` serializes the request with serde, so the key is dropped
/// on the wire. The handler then hydrates no WireGuard endpoint at all, and any
/// assertion that no WG thread spawned passes because there was nothing to spawn.
/// This helper re-inserts each secret from the in-memory request before sending,
/// which is what the real control plane delivers.
fn run_request_delivering_wg_secrets(
    state: Arc<Mutex<ServerState>>,
    request: ControlRequest,
) -> ControlResponse {
    let mut payload = serde_json::to_value(&request).expect("request to json");
    if let Some(snapshot) = request.snapshot.as_ref() {
        let endpoints = payload
            .get_mut("snapshot")
            .and_then(|s| s.get_mut("tunnel_endpoints"))
            .and_then(|e| e.as_array_mut())
            .expect("serialized snapshot carries tunnel_endpoints");
        for (ep, ep_json) in snapshot.tunnel_endpoints.iter().zip(endpoints.iter_mut()) {
            if !ep.wg_local_privkey_hex.is_empty() {
                ep_json["wg_local_privkey_hex"] =
                    serde_json::Value::String(ep.wg_local_privkey_hex.clone());
            }
            if let Some(peers) = ep_json.get_mut("wg_peers").and_then(|p| p.as_array_mut()) {
                for (peer, peer_json) in ep.wg_peers.iter().zip(peers.iter_mut()) {
                    if !peer.wg_preshared_key_hex.is_empty() {
                        peer_json["wg_preshared_key_hex"] =
                            serde_json::Value::String(peer.wg_preshared_key_hex.clone());
                    }
                }
            }
        }
    }
    let state_file = unique_state_file(&request.request_type);
    let (mut client, server) =
        std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let session_domain = state.lock().expect("state").afxdp.session_domain().clone();
    let handle = {
        let state_file = state_file.clone();
        std::thread::spawn(move || {
            handle_stream(server, &state_file, state, running, session_domain)
        })
    };
    serde_json::to_writer(&mut client, &payload).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");
    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    handle
        .join()
        .expect("handler thread")
        .expect("handler result");
    let _ = std::fs::remove_file(&state_file);
    response
}

fn run_raw(state: Arc<Mutex<ServerState>>, payload: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let state_file = unique_state_file("raw");
    let (mut client, server) =
        std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let handle = {
        let state_file = state_file.clone();
        {
            let sd = state.lock().expect("state").afxdp.session_domain().clone();
            std::thread::spawn(move || handle_stream(server, &state_file, state, running, sd))
        }
    };
    client.write_all(payload).expect("write raw payload");
    // Drop the write half so the handler sees EOF; an oversize body with
    // no newline must still be bounded by the read cap, not block.
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");
    // Drain any response the handler may write so it never blocks on a
    // full socket buffer, then collect the handler result.
    let mut sink = Vec::new();
    let _ = std::io::Read::read_to_end(&mut client, &mut sink);
    let result = handle.join().expect("handler thread");
    let _ = std::fs::remove_file(&state_file);
    result
}

// --- request byte cap (#2523) -------------------------------------------

#[test]
fn oversize_request_is_rejected_before_decode() {
    // A body one byte past the cap with NO terminating newline. The cap
    // must reject it before the (unbounded) decode allocation; the read
    // itself is bounded to MAX+1 by the `take` in handle_stream.
    let payload = vec![b'a'; MAX_CONTROL_REQUEST_BYTES + 1];
    let err = run_raw(new_state(ProcessStatus::default()), &payload)
        .expect_err("oversize request must be rejected");
    assert!(
        err.contains("exceeds maximum size"),
        "expected oversize rejection, got: {err}"
    );
    // Fail-on-revert pin: if the cap is removed, `read_until` would slurp
    // all MAX+1 'a' bytes and serde would fail with a DECODE error, not an
    // "exceeds maximum size" error — so this assertion goes RED on revert.
}

#[test]
fn max_size_legitimate_request_still_succeeds() {
    // A real request padded with a large (but legal) field up to just
    // under the cap, terminated by the single newline the Go encoder
    // appends. The body is <= MAX bytes, so MAX+1 bytes on the wire ending
    // in '\n' — the largest legitimate read. It must decode and succeed.
    // Pad the request_type string so the serialized body approaches the
    // cap without crossing it (leave generous slack for the JSON
    // envelope). The body decodes as valid JSON and the dispatcher runs
    // its catch-all arm — handle_stream completes with Ok(()), proving a
    // max-size body is read, decoded, and handled rather than rejected.
    let pad_len = MAX_CONTROL_REQUEST_BYTES - 4096;
    let request = req(&"x".repeat(pad_len));
    let mut payload = serde_json::to_vec(&request).expect("serialize");
    assert!(
        payload.len() <= MAX_CONTROL_REQUEST_BYTES,
        "test payload {} must stay within the cap {}",
        payload.len(),
        MAX_CONTROL_REQUEST_BYTES
    );
    payload.push(b'\n');
    run_raw(new_state(ProcessStatus::default()), &payload)
        .expect("max-size legitimate request must succeed");
}

// --- #2744: feed-dimension cap raise (fail-on-revert) -------------------

/// The pre-#2744 ceiling. A legitimate feed-heavy apply_snapshot can
/// serialize past this (the #2744 case cited ~500K prefixes ≈ 20+ MiB);
/// such a request must now be ACCEPTED, not rejected. This constant is
/// hard-coded (NOT derived from MAX_CONTROL_REQUEST_BYTES) so the test
/// goes RED if the cap is reverted to 16 MiB.
const OLD_CONTROL_REQUEST_CAP_BYTES: usize = 16 * 1024 * 1024;

#[test]
fn legitimate_feed_above_old_16mib_cap_is_now_accepted() {
    // Build a body comfortably above the OLD 16 MiB ceiling but within the
    // raised cap — this models a large-but-legitimate feed-backed snapshot.
    // It must be read, decoded, and handled (not rejected at the cap).
    assert!(
        OLD_CONTROL_REQUEST_CAP_BYTES < MAX_CONTROL_REQUEST_BYTES,
        "cap must be raised above the old 16 MiB ceiling (got {MAX_CONTROL_REQUEST_BYTES})"
    );
    // 4 MiB above the old cap, with envelope slack below the new cap.
    let pad_len = OLD_CONTROL_REQUEST_CAP_BYTES + 4 * 1024 * 1024;
    assert!(
        pad_len < MAX_CONTROL_REQUEST_BYTES - 4096,
        "test body {pad_len} must stay within the raised cap {MAX_CONTROL_REQUEST_BYTES}"
    );
    let request = req(&"x".repeat(pad_len));
    let mut payload = serde_json::to_vec(&request).expect("serialize");
    assert!(
        payload.len() > OLD_CONTROL_REQUEST_CAP_BYTES,
        "test body {} must exceed the old 16 MiB cap to prove the raise",
        payload.len()
    );
    assert!(
        payload.len() <= MAX_CONTROL_REQUEST_BYTES,
        "test body {} must stay within the raised cap {}",
        payload.len(),
        MAX_CONTROL_REQUEST_BYTES
    );
    payload.push(b'\n');
    // Under the old 16 MiB cap this would be rejected with "exceeds
    // maximum size"; under #2744 it must read/decode/handle cleanly.
    run_raw(new_state(ProcessStatus::default()), &payload)
        .expect("a legitimate feed-heavy request above the old 16 MiB cap must now be accepted");
}

#[test]
fn request_above_new_cap_is_still_rejected() {
    // The DoS guard must still bound allocation: one byte past the raised
    // cap with no terminating newline is rejected before decode.
    let payload = vec![b'a'; MAX_CONTROL_REQUEST_BYTES + 1];
    let err = run_raw(new_state(ProcessStatus::default()), &payload)
        .expect_err("a request past the raised cap must still be rejected");
    assert!(
        err.contains("exceeds maximum size"),
        "expected oversize rejection past the raised cap, got: {err}"
    );
}

// --- dispatcher: ping / status / unknown --------------------------------

#[test]
fn ping_returns_ok_and_attaches_status() {
    let response = run_request(new_state(ProcessStatus::default()), req("ping"));
    assert!(response.ok, "ping should succeed: {}", response.error);
    assert!(
        response.status.is_some(),
        "ping must attach status when suppress_status is false"
    );
}

#[test]
fn unknown_request_type_is_rejected_with_message() {
    let response = run_request(new_state(ProcessStatus::default()), req("does_not_exist"));
    assert!(!response.ok);
    assert!(
        response.error.contains("unknown request type does_not_exist"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn suppress_status_omits_status_payload() {
    let mut request = req("ping");
    request.suppress_status = true;
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(response.ok);
    assert!(
        response.status.is_none(),
        "suppress_status=true must not attach a status payload"
    );
}

// --- update_ha_state (handler glue; coordinator logic is in ha_tests) ---

#[test]
fn update_ha_state_missing_payload_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("update_ha_state"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing HA state"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn update_ha_state_populates_status_ha_groups() {
    let groups = vec![HAGroupStatus {
        rg_id: 1,
        active: true,
        ..HAGroupStatus::default()
    }];
    let mut request = req("update_ha_state");
    request.ha_state = Some(HAStateUpdateRequest {
        groups: groups.clone(),
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(response.ok, "unexpected error: {}", response.error);
    let status = response.status.expect("status payload");
    // The handler copies the request groups into status.ha_groups, then
    // refresh_status re-reads ha_groups() from the coordinator. The
    // operator-facing rg_id must survive that round-trip — this is the
    // exact status-field-parity surface #1642 regressed in.
    assert_eq!(status.ha_groups.len(), 1, "expected one HA group");
    assert_eq!(status.ha_groups[0].rg_id, 1);
}

// --- set_forwarding_state ----------------------------------------------

#[test]
fn set_forwarding_state_missing_payload_is_rejected() {
    let response = run_request(
        new_state(ProcessStatus::default()),
        req("set_forwarding_state"),
    );
    assert!(!response.ok);
    assert!(
        response.error.contains("missing forwarding state"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_forwarding_state_arm_without_support_is_rejected() {
    // forwarding_supported defaults false; arming must be refused and
    // forwarding_armed must NOT flip.
    let mut request = req("set_forwarding_state");
    request.forwarding = Some(ForwardingControlRequest { armed: true });
    let state = new_state(ProcessStatus::default());
    let response = run_request(state.clone(), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("not supported"),
        "unexpected error: {}",
        response.error
    );
    assert!(
        !state.lock().expect("state").status.forwarding_armed,
        "rejected arm must not flip forwarding_armed"
    );
}

#[test]
fn set_forwarding_state_unarm_clears_armed_flag() {
    let state = new_state(ProcessStatus {
        forwarding_armed: true,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        ..ProcessStatus::default()
    });
    let mut request = req("set_forwarding_state");
    request.forwarding = Some(ForwardingControlRequest { armed: false });
    let response = run_request(state.clone(), request);
    assert!(response.ok, "unexpected error: {}", response.error);
    assert!(
        !state.lock().expect("state").status.forwarding_armed,
        "unarm must clear forwarding_armed"
    );
}

// --- sync_session -------------------------------------------------------

#[test]
fn sync_session_missing_request_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("sync_session"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing session sync request"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn sync_session_unknown_operation_is_rejected() {
    let mut request = req("sync_session");
    request.session_sync = Some(SessionSyncRequest {
        operation: "frobnicate".to_string(),
        ..SessionSyncRequest::default()
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok);
    assert!(
        response
            .error
            .contains("unknown session sync operation frobnicate"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn sync_session_delete_with_valid_key_succeeds() {
    let mut request = req("sync_session");
    request.session_sync = Some(SessionSyncRequest {
        operation: "delete".to_string(),
        addr_family: 2, // AF_INET
        protocol: 6,    // TCP
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 1234,
        dst_port: 80,
        ..SessionSyncRequest::default()
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(response.ok, "unexpected error: {}", response.error);
}

/// #9714: the helper must decode Go's peer-delete mark under the key Go sends. A
/// misspelled rename decodes every marked delete as unmarked, and the helper then
/// deletes a live local session on the peer's say-so. The key below is a literal
/// on the wire, so a rename typo cannot round-trip through this struct.
#[test]
fn a_sync_session_request_decodes_the_peer_delete_mark_9714() {
    let mut wire = serde_json::to_value(SessionSyncRequest {
        operation: "delete".to_string(),
        ..SessionSyncRequest::default()
    })
    .expect("encode a delete");
    wire["peer_delete"] = serde_json::Value::Bool(true);
    let marked: SessionSyncRequest =
        serde_json::from_value(wire.clone()).expect("decode a marked delete");
    assert!(
        marked.peer_delete,
        "the helper did not decode \"peer_delete\": true; Go's marked deletes would apply as \
         authoritative (#9714)"
    );
    wire.as_object_mut()
        .expect("a request encodes as an object")
        .remove("peer_delete");
    let unmarked: SessionSyncRequest =
        serde_json::from_value(wire).expect("decode an unmarked delete");
    assert!(
        !unmarked.peer_delete,
        "a request without the key (every v15 sender, and every authoritative delete) must decode \
         as unmarked"
    );
}

#[test]
fn sync_session_upsert_with_valid_entry_succeeds() {
    let mut request = req("sync_session");
    request.session_sync = Some(SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: 2,
        protocol: 6,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 1234,
        dst_port: 80,
        egress_ifindex: 7,
        neighbor_mac: "02:bf:72:01:02:03".to_string(),
        src_mac: "02:bf:72:0a:0b:0c".to_string(),
        ..SessionSyncRequest::default()
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(response.ok, "unexpected error: {}", response.error);
}

#[test]
fn sync_session_upsert_with_malformed_mac_is_rejected() {
    let mut request = req("sync_session");
    request.session_sync = Some(SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: 2,
        protocol: 6,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        neighbor_mac: "zz:zz:zz:zz:zz:zz".to_string(),
        ..SessionSyncRequest::default()
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("parse neighbor_mac"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn sync_session_delete_with_unparseable_ip_is_rejected() {
    let mut request = req("sync_session");
    request.session_sync = Some(SessionSyncRequest {
        operation: "delete".to_string(),
        addr_family: 2,
        protocol: 6,
        src_ip: "not-an-ip".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        ..SessionSyncRequest::default()
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("parse src_ip"),
        "unexpected error: {}",
        response.error
    );
}

// --- rebind (#1921) -----------------------------------------------------

#[test]
fn rebind_preserves_synced_sessions() {
    // #1921 regression. `rebind::handle` must NOT call `guard.afxdp.stop()`:
    // that runs `stop_inner(true)`, which clears `coord.workers.records`
    // before `tear_down` samples them (so the 500ms zero-copy teardown
    // quiesce is bypassed -> EBUSY/rebind loop) AND wipes the in-memory
    // synced-session map (mod.rs:488). The reconcile pipeline's `tear_down`
    // owns the worker stop via `stop_inner(false)`, which preserves synced
    // state for replay. This test pins the observable consequence: a synced
    // session installed before a rebind must survive it. If someone re-adds
    // the explicit stop to rebind::handle, the synced map is wiped and this
    // fails.
    //
    // Forwarding must be armed + supported so reconcile_status_bindings takes
    // the real afxdp.reconcile() path (tear_down -> stop_inner(false), which
    // preserves synced state). Its OTHER branch — the `!should_run_afxdp`
    // early return at helpers.rs — itself calls afxdp.stop() (stop_inner(true))
    // and would wipe synced regardless of rebind::handle, so an unarmed status
    // would not isolate the rebind path.
    let state = new_state(ProcessStatus {
        forwarding_armed: true,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        ..ProcessStatus::default()
    });

    let mut upsert = req("sync_session");
    upsert.session_sync = Some(SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: 2,
        protocol: 6,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 1234,
        dst_port: 80,
        egress_ifindex: 7,
        neighbor_mac: "02:bf:72:01:02:03".to_string(),
        src_mac: "02:bf:72:0a:0b:0c".to_string(),
        ..SessionSyncRequest::default()
    });
    let upsert_resp = run_request(state.clone(), upsert);
    assert!(upsert_resp.ok, "upsert failed: {}", upsert_resp.error);
    assert!(
        !state
            .lock()
            .unwrap()
            .afxdp
            .snapshot_shared_session_entries()
            .is_empty(),
        "synced session should be present after upsert"
    );

    let rebind_resp = run_request(state.clone(), req("rebind"));
    assert!(rebind_resp.ok, "rebind failed: {}", rebind_resp.error);
    assert!(
        !state
            .lock()
            .unwrap()
            .afxdp
            .snapshot_shared_session_entries()
            .is_empty(),
        "#1921: rebind wiped the synced-session map — did rebind::handle \
         regain a guard.afxdp.stop() call before reconcile_status_bindings?"
    );
}

// --- bump_fib_generation ------------------------------------------------

#[test]
fn bump_fib_generation_missing_snapshot_is_rejected() {
    let response = run_request(
        new_state(ProcessStatus::default()),
        req("bump_fib_generation"),
    );
    assert!(!response.ok);
    assert!(
        response.error.contains("missing snapshot"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn bump_fib_generation_updates_status_and_stored_snapshot() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    // Seed a stored snapshot via apply_snapshot first.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 1,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        let response = run_request(state.clone(), request);
        assert!(response.ok, "seed apply_snapshot: {}", response.error);
    }
    let mut request = req("bump_fib_generation");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        fib_generation: 7,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(response.ok, "unexpected error: {}", response.error);
    let status = response.status.expect("status payload");
    assert_eq!(status.last_fib_generation, 7);
    assert_eq!(
        state
            .lock()
            .expect("state")
            .snapshot
            .as_ref()
            .expect("stored snapshot")
            .fib_generation,
        7,
        "bump must rewrite the stored snapshot's fib_generation"
    );
}

/// #3767 H4: bump_fib_generation must version-gate exactly like
/// apply_snapshot. A mixed-version / corrupt client (version != protocol)
/// must be REJECTED before mutating any validation state — status,
/// stored snapshot, and worker FIB generation all stay at the prior value.
#[test]
fn bump_fib_generation_rejects_wrong_protocol_version() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    // Seed a stored snapshot at fib_generation 1.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 1,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    let worker_fib_before = state.lock().expect("state").afxdp.fib_generation();
    let mut request = req("bump_fib_generation");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION - 1,
        fib_generation: 7,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(!response.ok, "wrong-version bump must be rejected");
    assert!(
        response
            .error
            .contains("unsupported snapshot protocol version"),
        "unexpected error: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(
        guard.status.last_fib_generation, 1,
        "rejected bump must not advance last_fib_generation"
    );
    assert_eq!(
        guard.snapshot.as_ref().expect("stored snapshot").fib_generation,
        1,
        "rejected bump must not rewrite the stored snapshot"
    );
    assert_eq!(
        guard.afxdp.fib_generation(),
        worker_fib_before,
        "rejected bump must not advance the worker FIB generation"
    );
}

/// #3767 H5: bump_fib_generation must refuse a generation ROLLBACK. Flow-
/// cache validation is equality based, so publishing a strictly-lower
/// fib_generation would revive cache entries a prior bump invalidated
/// (stale forwarding after a route withdrawal / failover). The rejected
/// bump must leave status, stored snapshot, and worker FIB generation at
/// the last accepted value.
#[test]
fn bump_fib_generation_rejects_generation_rollback() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    // Seed a stored snapshot at fib_generation 5.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // A forward bump to 7 is accepted (monotone).
    {
        let mut request = req("bump_fib_generation");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            fib_generation: 7,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // A rollback to 3 (< current 7) must be refused.
    let mut request = req("bump_fib_generation");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        fib_generation: 3,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(!response.ok, "rollback bump must be rejected");
    assert!(
        response.error.contains("fib generation rollback rejected"),
        "unexpected error: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(
        guard.status.last_fib_generation, 7,
        "rejected rollback must not lower last_fib_generation"
    );
    assert_eq!(
        guard.snapshot.as_ref().expect("stored snapshot").fib_generation,
        7,
        "rejected rollback must not rewrite the stored snapshot"
    );
    assert_eq!(
        guard.afxdp.fib_generation(),
        7,
        "rejected rollback must not revive an old worker FIB generation"
    );
}

/// #3767 M2: an accepted bump_fib_generation must PERSIST the new
/// generation. Previously the handler mutated status + stored snapshot in
/// RAM only (no persist_state), so a route-only overlay bump to gen N left
/// the on-disk state at gen N-1 and a restart booted from a stale FIB
/// generation the control plane already considered applied.
#[test]
fn bump_fib_generation_persists_bumped_generation() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("bump-persist");
    // Seed apply persists the state file at fib_generation 1.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 1,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // Route-only bump to 7.
    {
        let mut request = req("bump_fib_generation");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            fib_generation: 7,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // The on-disk state a restart would boot from must carry gen 7, not the
    // seed apply's stale gen 1.
    let bytes = std::fs::read(&state_file).expect("read persisted state file");
    let persisted: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse persisted state file");
    assert_eq!(
        persisted["snapshot"]["fib_generation"].as_u64(),
        Some(7),
        "persisted snapshot must carry the bumped fib_generation"
    );
    assert_eq!(
        persisted["status"]["last_fib_generation"].as_u64(),
        Some(7),
        "persisted status must carry the bumped fib_generation"
    );
    let _ = std::fs::remove_file(&state_file);
}

// --- apply_snapshot integrity preflight (#1606 / #1642 class) -----------

#[test]
fn apply_snapshot_missing_payload_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("apply_snapshot"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing snapshot"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn apply_snapshot_integrity_preflight_rejects_without_mutating_state() {
    use crate::{AddressBookSnapshot, ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    // A reserved-sentinel address-book id (0) must fail the #1606
    // integrity preflight BEFORE any guard.status / guard.snapshot
    // mutation. The previous good config must survive intact.
    let state = new_state(ProcessStatus::default());
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 5,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        address_books: vec![AddressBookSnapshot {
            id: 0, // reserved sentinel -> AddressBookIdZero
            name: "bad".to_string(),
            ..AddressBookSnapshot::default()
        }],
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("snapshot integrity error"),
        "unexpected error: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert!(
        guard.snapshot.is_none(),
        "rejected snapshot must not be stored"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 0,
        "rejected snapshot must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 0,
        "rejected snapshot must not bump last_fib_generation"
    );
}

/// #3766 fail-closed same-plan refresh at the handler boundary: a
/// same-plan apply_snapshot that PASSES the policy preflight but whose full
/// forwarding build FAILS (here an unparseable interface address) must
/// report ok=false, keep the previously-stored snapshot as the persisted
/// baseline, and NOT advance the reported generation. The disarmed helper
/// (default ProcessStatus) takes the fallible refresh_runtime_snapshot_
/// disarmed leg.
///
/// Fail-on-revert: pre-#3766 the disarmed refresh returned () and the
/// handler unconditionally stored the snapshot, refreshed status, and set
/// persist_state=true — so response.ok stayed true (M1), the rejected
/// snapshot overwrote guard.snapshot as the persisted baseline, and
/// last_snapshot_generation advanced. Every assertion below flips.
#[test]
fn apply_snapshot_same_plan_build_failure_rejects_and_keeps_prior_3766() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // A tunnel interface is excluded from the binding plan, so both applies
    // share an (empty) binding-plan key -> the second apply takes the
    // same-plan refresh leg. Only the address differs (NOT a plan-key
    // input): valid on apply 1, unparseable on apply 2.
    let iface = |address: &str| crate::protocol::snapshot::InterfaceSnapshot {
        name: "gr-0/0/0".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 4300,
        tunnel: true,
        hardware_addr: "02:00:00:00:43:00".to_string(),
        addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: address.to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let snapshot = |generation: u64, address: &str| ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation,
        fib_generation: generation as u32,
        generated_at: chrono::Utc::now(),
        interfaces: vec![iface(address)],
        ..ConfigSnapshot::default()
    };

    // forwarding_armed defaults false -> the disarmed refresh leg.
    let state = new_state(ProcessStatus::default());

    // Apply 1 (first apply, NOT same-plan): valid baseline, generation 1.
    let mut first = req("apply_snapshot");
    first.snapshot = Some(snapshot(1, "10.0.0.1/24"));
    let response = run_request(state.clone(), first);
    assert!(response.ok, "baseline apply must succeed: {}", response.error);

    // Apply 2 (same-plan refresh leg): unparseable address -> build fails.
    let mut second = req("apply_snapshot");
    second.snapshot = Some(snapshot(2, "10.0.0.0/33"));
    let response = run_request(state.clone(), second);
    assert!(
        !response.ok,
        "a same-plan refresh whose forwarding build fails must report ok=false"
    );
    assert!(
        response.error.contains("snapshot integrity error"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(1),
        "the rejected snapshot must not overwrite the persisted baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 1,
        "rejected same-plan refresh must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 1,
        "rejected same-plan refresh must not bump last_fib_generation"
    );
}

/// Sentinel-OK map pins for the ARMED reconcile legs. The literal mirrors
/// `afxdp::TEST_MAP_PIN_OK` (pub(in crate::afxdp), not reachable here); the
/// `#[cfg(test)]` seam in `OwnedFd::open_bpf_map` short-circuits these to a
/// dummy fd so the reconcile passes `preflight_map_fds` and reaches the
/// fallible forwarding build without a real bpffs.
fn ok_map_pins() -> crate::protocol::snapshot::MapPins {
    crate::protocol::snapshot::MapPins {
        xsk: "test-map-pin-ok://xsk".to_string(),
        heartbeat: "test-map-pin-ok://heartbeat".to_string(),
        sessions: "test-map-pin-ok://sessions".to_string(),
        ..Default::default()
    }
}

fn forwarding_caps() -> UserspaceCapabilities {
    UserspaceCapabilities {
        forwarding_supported: true,
        ..Default::default()
    }
}

/// A zoned, non-tunnel DATA interface — the binding-plan candidate the
/// tunnel helper is NOT. `include_userspace_binding_interface` admits it
/// (non-empty data zone, non-tunnel, `ge-*` name), so `replan_queues`
/// plans exactly one worker for it (rx_queues=1 -> queue_count=1, ifindex>0
/// -> registered). Changing `name`/`linux_name`/`ifindex` between two
/// snapshots therefore CHANGES the binding plan key, selecting the
/// FULL-APPLY leg (not the address-only same-plan leg the tunnel helper
/// drives). A valid inet address keeps the pre-teardown forwarding build
/// green so the reconcile REACHES the post-teardown worker spawn.
fn data_iface_6140(name: &str, linux_name: &str, ifindex: i32) -> crate::protocol::snapshot::InterfaceSnapshot {
    crate::protocol::snapshot::InterfaceSnapshot {
        name: name.to_string(),
        linux_name: linux_name.to_string(),
        zone: "trust".to_string(),
        ifindex,
        rx_queues: 1,
        hardware_addr: "02:00:00:00:00:01".to_string(),
        addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.1.1/24".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// The `trust` zone the data interface references. The forwarding build
/// REFUSES an interface whose zone is absent from the zone table (it will
/// not fail open by collapsing to the unknown zone 0), so the snapshot must
/// declare it for the pre-teardown build to succeed and the reconcile to
/// reach the worker spawn.
fn trust_zone_6140() -> crate::protocol::snapshot::ZoneSnapshot {
    crate::protocol::snapshot::ZoneSnapshot {
        name: "trust".to_string(),
        id: 1,
        ..Default::default()
    }
}

/// A tunnel interface is excluded from the binding plan, so applies that
/// differ only in this interface's ADDRESS share a plan key. `address`
/// controls whether the forwarding build succeeds ("10.0.0.1/24") or fails
/// ("10.0.0.0/33", unparseable — a NON-policy integrity fault).
fn tunnel_iface_3789(address: &str) -> crate::protocol::snapshot::InterfaceSnapshot {
    crate::protocol::snapshot::InterfaceSnapshot {
        name: "gr-0/0/0".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 4300,
        tunnel: true,
        hardware_addr: "02:00:00:00:43:00".to_string(),
        addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: address.to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// #3789 fail-closed FULL-APPLY leg (the non-same-plan branch, the #2484
/// domain out of #3766's same-plan-refresh scope): an ARMED
/// forwarding-supported helper's first apply takes the else full-apply
/// leg -> reconcile_status_bindings -> the fallible afxdp.reconcile. A
/// snapshot that passes the policy preflight but whose forwarding build
/// FAILS (unparseable interface address) must report ok=false, NOT store
/// the rejected snapshot as the boot baseline, and NOT advance the
/// reported generation.
///
/// Fail-on-revert: before #3789 `afxdp.reconcile` returned () and the
/// handler unconditionally stored the snapshot, refreshed status, and set
/// persist_state=true -> response.ok stayed true (M1), the rejected
/// snapshot became guard.snapshot, and last_snapshot_generation advanced.
/// Every assertion below flips.
#[test]
fn apply_snapshot_full_reconcile_build_failure_rejects_and_keeps_prior_3789() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Armed so the reconcile takes the real afxdp.reconcile path (not the
    // disarmed stop arm). forwarding_supported comes from the snapshot.
    let state = new_state(ProcessStatus {
        forwarding_armed: true,
        ..ProcessStatus::default()
    });

    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 5,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.0/33")],
        ..ConfigSnapshot::default()
    });

    let response = run_request(state.clone(), request);
    assert!(
        !response.ok,
        "a full-apply reconcile whose forwarding build fails must report ok=false"
    );
    assert!(
        response.error.contains("snapshot integrity error"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert!(
        guard.snapshot.is_none(),
        "rejected snapshot must not be stored as the boot baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 0,
        "rejected full-apply must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 0,
        "rejected full-apply must not bump last_fib_generation"
    );
}

/// #3789 fail-closed SAME-PLAN NEEDS-RECONCILE leg: when the prior apply
/// deferred workers, the next same-plan apply reconciles the deferred
/// bindings via afxdp.reconcile (NOT the same-plan refresh leg #3766
/// fixed). A build failure on that reconcile must restore the prior
/// (deferred) snapshot, report ok=false, and NOT advance the generation.
///
/// Fail-on-revert: pre-#3789 this leg stored the snapshot then called
/// reconcile_status_bindings (returning ()) and fell through to
/// refresh_status + persist_state=true with ok=true — so the rejected
/// gen-2 snapshot overwrote the gen-1 baseline and last_snapshot_generation
/// advanced to 2. The generation/defer_workers assertions flip.
#[test]
fn apply_snapshot_same_plan_needs_reconcile_build_failure_rejects_and_keeps_prior_3789() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Prior snapshot deferred workers -> previous_defer_workers=true makes
    // same_plan_apply_needs_binding_reconcile return true on the next
    // (non-defer) same-plan apply. Tunnel-only interface set -> the plan
    // key is address-independent, so gen-1 and gen-2 are same-plan.
    let prior = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 1,
        fib_generation: 1,
        generated_at: chrono::Utc::now(),
        defer_workers: true,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.1/24")],
        ..ConfigSnapshot::default()
    };

    // Armed + supported + one runnable binding (registered, ifindex>0) so
    // the needs-reconcile runnable_bindings>0 gate holds.
    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: forwarding_caps(),
        last_snapshot_generation: 1,
        last_fib_generation: 1,
        bindings: vec![BindingStatus {
            slot: 0,
            registered: true,
            ifindex: 10,
            ..BindingStatus::default()
        }],
        ..ProcessStatus::default()
    };

    let state = Arc::new(Mutex::new(ServerState {
        status,
        snapshot: Some(prior),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));

    // New same-plan apply: defer_workers=false, unparseable address -> the
    // deferred-binding reconcile's forwarding build fails.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 2,
        fib_generation: 2,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.0/33")],
        ..ConfigSnapshot::default()
    });

    let response = run_request(state.clone(), request);
    assert!(
        !response.ok,
        "a same-plan needs-reconcile apply whose build fails must report ok=false"
    );
    assert!(
        response.error.contains("snapshot integrity error"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(1),
        "the rejected snapshot must not overwrite the persisted baseline"
    );
    assert!(
        guard.snapshot.as_ref().is_some_and(|s| s.defer_workers),
        "the prior (deferred) snapshot must be restored intact"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 1,
        "rejected same-plan needs-reconcile must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 1,
        "rejected same-plan needs-reconcile must not bump last_fib_generation"
    );
}

/// #4952 POST-TEARDOWN worker-spawn failure fails closed and does NOT
/// persist. The same-plan-needs-reconcile leg reconciles the ALREADY
/// registered binding directly (no replan_queues), so with all mandatory
/// pins open and a buildable snapshot the reconcile clears the pre-teardown
/// integrity legs, tears down the old workers, and REACHES the fallible
/// worker spawn. The per-instance `force_worker_spawn_fail` seam forces that
/// spawn to return EAGAIN/ENOMEM (a real pthread_create failure is not
/// provokable in-process), leaving the queue set with NO XSK-bound worker.
///
/// The handler MUST: (a) report ok=false with a descriptive error, (b) NOT
/// persist the broken snapshot as the boot baseline (persist_state stays
/// false -> the state file is never written), and (c) the coordinator's
/// `last_reconcile_stage` MUST retain the `spawn_worker_failed:..`
/// descriptor (NOT `spawned:workers=..`).
///
/// Fail-on-revert: before #4952 `bring_up_workers` returned () and swallowed
/// the spawn error (overwriting the stage with `spawned:..`), so
/// `afxdp.reconcile` returned Ok, the handler acked ok=true, PERSISTED the
/// snapshot (the state file appears), and advanced the stored baseline to
/// gen 2. Every assertion below flips.
#[test]
fn post_teardown_spawn_failure_fails_closed_no_persist_4952() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Prior snapshot deferred workers -> previous_defer_workers=true makes
    // same_plan_apply_needs_binding_reconcile return true on the next
    // (non-defer) same-plan apply. Tunnel-only interface set -> the plan
    // key is address-independent, so gen-1 and gen-2 are same-plan.
    let prior = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 1,
        fib_generation: 1,
        generated_at: chrono::Utc::now(),
        defer_workers: true,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.1/24")],
        ..ConfigSnapshot::default()
    };

    // Armed + supported + one runnable binding (registered, ifindex>0) so
    // the needs-reconcile gate fires AND bring_up plans exactly one worker.
    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: forwarding_caps(),
        last_snapshot_generation: 1,
        last_fib_generation: 1,
        bindings: vec![BindingStatus {
            slot: 0,
            registered: true,
            ifindex: 10,
            ..BindingStatus::default()
        }],
        ..ProcessStatus::default()
    };

    let state = Arc::new(Mutex::new(ServerState {
        status,
        snapshot: Some(prior),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));

    // Force the single planned worker's spawn to fail on the post-teardown
    // path (the destructive step the fix guards).
    state.lock().expect("state").afxdp.force_worker_spawn_fail = 1;

    // New same-plan apply: defer_workers=false, VALID address so the
    // forwarding build SUCCEEDS and the reconcile reaches the worker spawn.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 2,
        fib_generation: 2,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.1/24")],
        ..ConfigSnapshot::default()
    });

    let state_file = unique_state_file("spawn_fail_4952");
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "precondition: state file must not exist before the request"
    );

    let response = run_request_on_file(state.clone(), request, &state_file);

    // (a) fail closed with a non-empty, descriptive error.
    assert!(
        !response.ok,
        "a post-teardown worker-spawn failure must report ok=false"
    );
    assert!(
        !response.error.is_empty() && response.error.contains("worker spawn failed"),
        "unexpected error: {}",
        response.error
    );

    // (b) persist_state was NOT set -> the state file was never written.
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "a post-teardown spawn failure must NOT persist the broken snapshot as the boot baseline"
    );

    let guard = state.lock().expect("state");
    // The prior (gen 1, deferred) snapshot is still the boot baseline.
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(1),
        "the rejected snapshot must not overwrite the persisted baseline"
    );
    assert!(
        guard.snapshot.as_ref().is_some_and(|s| s.defer_workers),
        "the prior (deferred) snapshot must be restored intact"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 1,
        "rejected apply must not bump last_snapshot_generation"
    );
    // (c) last_reconcile_stage retains the spawn_worker_failed descriptor.
    assert!(
        matches!(
            guard.afxdp.last_reconcile_stage,
            crate::afxdp::ReconcileStage::SpawnWorkerFailed { .. }
        ),
        "the spawn-failure stage must be preserved (not the Spawned variant), got {:?}",
        guard.afxdp.last_reconcile_stage
    );
    // #6244: legacy operator string preserved byte-for-byte.
    assert!(
        guard
            .afxdp
            .last_reconcile_stage
            .to_string()
            .starts_with("spawn_worker_failed:")
    );

    let _ = std::fs::remove_file(&state_file);
}

/// #6140 (test-coverage follow-up to #4952): a dedicated regression for the
/// FULL-APPLY leg (`handlers/snapshot.rs` else branch, ~:341-369), the
/// PLAN-CHANGE path. The merged #4952 gates cover the coordinator
/// (`reconcile_post_teardown_worker_spawn_failure_fails_closed_4952`) and the
/// SAME-PLAN-needs_reconcile handler leg
/// (`post_teardown_spawn_failure_fails_closed_no_persist_4952`, ~:208). The
/// full-apply arm's WorkerSpawn handling (~:342-369) was covered only
/// TRANSITIVELY — verified equivalent to the same-plan arm by inspection, but
/// with no test asserting the full-apply leg SPECIFICALLY fails closed. This
/// closes that gap.
///
/// The two legs are selected by the binding PLAN KEY: same key -> same-plan
/// leg; changed key -> full-apply leg. This test installs a prior snapshot
/// whose sole binding interface (`ge-0/0/1`, ifindex 11) differs from the new
/// snapshot's (`ge-0/0/2`, ifindex 12), so `snapshot_binding_plan_key` differs
/// and `same_plan` is FALSE — the else full-apply branch runs `replan_queues`
/// (installing the NEW interface as the binding set), then
/// `reconcile_status_bindings` -> `afxdp.reconcile`. All mandatory pins open
/// and the address parses, so the reconcile clears the pre-teardown integrity
/// legs, tears down, and REACHES the fallible worker spawn. The
/// `force_worker_spawn_fail` seam forces that (unprovokable in-process)
/// EAGAIN/ENOMEM, leaving the queue set with NO XSK-bound worker.
///
/// The full-apply WorkerSpawn arm MUST: (a) report ok=false with a descriptive
/// error, (b) NOT persist the broken snapshot as the boot baseline
/// (persist_state stays false -> the state file is never written), (c) roll
/// the in-memory baseline back to the prior good snapshot + status generation
/// (guard.snapshot gen 1, last_snapshot/fib_generation 1), and (d) preserve the
/// coordinator's `spawn_worker_failed:..` stage (NOT overwritten with
/// `spawned:..`).
///
/// LEG PROOF: two observables pin this to the full-apply leg, not same-plan.
/// (1) `same_binding_plan(prior, next)` is asserted FALSE up front — the
/// handler's `same_plan` gate reads exactly that key, so a false key forces
/// the else branch. (2) The full-apply leg is the ONLY leg that runs
/// `replan_queues`, which rewrites `status.bindings` to the NEW snapshot's
/// interface; the WorkerSpawn arm deliberately does NOT restore
/// `existing_bindings`, so after the failure the surviving binding carries
/// `ge-0-0-2`/ifindex 12 (the new plan), which the same-plan leg — never
/// calling `replan_queues` — could not produce.
///
/// Fail-on-revert: neutralize the full-apply WorkerSpawn arm (drop the
/// ok=false + no-persist + baseline-rollback so it falls through to
/// refresh_status + persist_state=true with ok=true, exactly as pre-#4952
/// `bring_up_workers` swallowed the spawn error). Assertions (a)/(b)/(c)/(d)
/// all flip as ASSERTION failures.
#[test]
fn full_apply_post_teardown_spawn_failure_fails_closed_no_persist_6140() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Prior snapshot: one binding interface (ge-0/0/1, ifindex 11). NOT
    // deferred — a normal prior apply. Its only role here is to make
    // guard.snapshot Some with a DISTINCT plan key.
    let prior = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 1,
        fib_generation: 1,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![data_iface_6140("ge-0/0/1", "ge-0-0-1", 11)],
        zones: vec![trust_zone_6140()],
        ..ConfigSnapshot::default()
    };

    // New apply: a DIFFERENT binding interface (ge-0/0/2, ifindex 12) -> the
    // plan key changes -> the full-apply (non-same-plan) leg is taken.
    let next = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 2,
        fib_generation: 2,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![data_iface_6140("ge-0/0/2", "ge-0-0-2", 12)],
        zones: vec![trust_zone_6140()],
        ..ConfigSnapshot::default()
    };

    // LEG PROOF (1): a differing plan key is precisely what selects the
    // full-apply leg. `same_plan` in the handler reads this same key.
    assert!(
        !super::helpers::same_binding_plan(&prior, &next),
        "the prior/new binding plan keys MUST differ so the handler takes the \
         full-apply (non-same-plan) leg"
    );

    // Armed + supported so `should_run_afxdp` holds and the reconcile takes
    // the real afxdp.reconcile path (not the disarmed stop arm).
    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: forwarding_caps(),
        last_snapshot_generation: 1,
        last_fib_generation: 1,
        ..ProcessStatus::default()
    };

    let state = Arc::new(Mutex::new(ServerState {
        status,
        snapshot: Some(prior),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));

    // Force the single planned worker's spawn to fail on the post-teardown
    // path (the destructive step the fix guards).
    state.lock().expect("state").afxdp.force_worker_spawn_fail = 1;

    let mut request = req("apply_snapshot");
    request.snapshot = Some(next);

    let state_file = unique_state_file("full_apply_spawn_fail_6140");
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "precondition: state file must not exist before the request"
    );

    let response = run_request_on_file(state.clone(), request, &state_file);

    // (a) fail closed with a non-empty, descriptive error.
    assert!(
        !response.ok,
        "a post-teardown worker-spawn failure on the full-apply leg must report ok=false"
    );
    assert!(
        !response.error.is_empty() && response.error.contains("worker spawn failed"),
        "unexpected error: {}",
        response.error
    );

    // (b) persist_state was NOT set -> the state file was never written.
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "a full-apply post-teardown spawn failure must NOT persist the broken snapshot"
    );

    let guard = state.lock().expect("state");
    // (c) the prior (gen 1) snapshot is still the boot baseline; the reported
    // generation rolled back.
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(1),
        "the rejected snapshot must not overwrite the persisted baseline"
    );
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.interfaces[0].linux_name.as_str()),
        Some("ge-0-0-1"),
        "the prior snapshot (ge-0-0-1) must be restored intact as the baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 1,
        "rejected full-apply must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 1,
        "rejected full-apply must not bump last_fib_generation"
    );
    // (d) last_reconcile_stage retains the spawn_worker_failed descriptor.
    assert!(
        matches!(
            guard.afxdp.last_reconcile_stage,
            crate::afxdp::ReconcileStage::SpawnWorkerFailed { .. }
        ),
        "the spawn-failure stage must be preserved (not the Spawned variant), got {:?}",
        guard.afxdp.last_reconcile_stage
    );
    // #6244: legacy operator string preserved byte-for-byte.
    assert!(
        guard
            .afxdp
            .last_reconcile_stage
            .to_string()
            .starts_with("spawn_worker_failed:")
    );
    // LEG PROOF (2): only the full-apply leg runs replan_queues, which
    // rewrites status.bindings to the NEW snapshot's interface. The
    // WorkerSpawn arm does NOT restore existing_bindings, so the surviving
    // binding carries the new plan (ge-0-0-2 / ifindex 12) — an outcome the
    // same-plan leg (never calling replan_queues) cannot produce.
    assert_eq!(guard.status.bindings.len(), 1, "one worker was planned");
    assert_eq!(
        guard.status.bindings[0].interface, "ge-0-0-2",
        "the full-apply leg must have replanned onto the NEW snapshot's interface"
    );
    assert_eq!(
        guard.status.bindings[0].ifindex, 12,
        "the replanned binding must carry the new interface's ifindex"
    );

    let _ = std::fs::remove_file(&state_file);
}

/// #5143: the FULL-APPLY handler leg must fail closed on a POST-SPAWN in-thread
/// worker BIND failure — distinct from the #4952/#6140 SPAWN failure. A worker
/// that spawns but binds an INCOMPLETE queue set (a live-but-unbound worker
/// heartbeating past a broken bring-up) surfaces as
/// `ReconcileError::WorkerBindIncomplete`, which the handler special-cases the
/// SAME way as `WorkerSpawn`: report ok=false + "worker bring-up failed after
/// teardown", NOT persist the broken snapshot as the boot baseline, and roll
/// the in-memory baseline back to the prior good snapshot + generation. The
/// `force_worker_bind_incomplete` seam spawns a joinable stub worker that
/// reports a bound set missing one planned slot (a real XSK cannot bind
/// in-process), which the readiness barrier catches and fails closed.
///
/// Fail-on-revert: neutralize the barrier (the worker binds partially but the
/// reconcile commits Ok) OR drop the handler's `WorkerBindIncomplete` arm (so
/// it falls through to refresh_status + persist_state=true with ok=true).
/// Assertions (a)/(b)/(c)/(d) all flip as ASSERTION failures.
#[test]
fn full_apply_post_spawn_inthread_bind_failure_fails_closed_no_persist_5143() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Prior snapshot: one binding interface (ge-0/0/1, ifindex 11). Its only
    // role is to make guard.snapshot Some with a DISTINCT plan key so the new
    // apply takes the full-apply (non-same-plan) leg.
    let prior = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 1,
        fib_generation: 1,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![data_iface_6140("ge-0/0/1", "ge-0-0-1", 11)],
        zones: vec![trust_zone_6140()],
        ..ConfigSnapshot::default()
    };

    // New apply: a DIFFERENT binding interface (ge-0/0/2, ifindex 12) -> the
    // plan key changes -> the full-apply leg runs.
    let next = ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 2,
        fib_generation: 2,
        generated_at: chrono::Utc::now(),
        defer_workers: false,
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![data_iface_6140("ge-0/0/2", "ge-0-0-2", 12)],
        zones: vec![trust_zone_6140()],
        ..ConfigSnapshot::default()
    };

    assert!(
        !super::helpers::same_binding_plan(&prior, &next),
        "the prior/new binding plan keys MUST differ so the handler takes the \
         full-apply (non-same-plan) leg"
    );

    let status = ProcessStatus {
        forwarding_armed: true,
        capabilities: forwarding_caps(),
        last_snapshot_generation: 1,
        last_fib_generation: 1,
        ..ProcessStatus::default()
    };

    let state = Arc::new(Mutex::new(ServerState {
        status,
        snapshot: Some(prior),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));

    // Force the single planned worker to SPAWN but report an INCOMPLETE bound
    // set (the post-spawn in-thread bind failure the fix guards).
    state
        .lock()
        .expect("state")
        .afxdp
        .force_worker_bind_incomplete = 1;

    let mut request = req("apply_snapshot");
    request.snapshot = Some(next);

    let state_file = unique_state_file("full_apply_bind_incomplete_5143");
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "precondition: state file must not exist before the request"
    );

    let response = run_request_on_file(state.clone(), request, &state_file);

    // (a) fail closed with a descriptive post-teardown bring-up error.
    assert!(
        !response.ok,
        "a post-spawn in-thread bind failure on the full-apply leg must report ok=false"
    );
    assert!(
        response.error.contains("worker bind incomplete"),
        "unexpected error: {}",
        response.error
    );

    // (b) persist_state was NOT set -> the state file was never written.
    assert!(
        !std::path::Path::new(&state_file).exists(),
        "a full-apply post-spawn bind failure must NOT persist the broken snapshot"
    );

    let guard = state.lock().expect("state");
    // (d) the prior (gen 1) snapshot is still the boot baseline; the reported
    // generation rolled back.
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(1),
        "the rejected snapshot must not overwrite the persisted baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 1,
        "rejected full-apply must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 1,
        "rejected full-apply must not bump last_fib_generation"
    );
    // (c) the coordinator recorded the bind-incomplete verdict (not a spawn
    // success) and stopped/joined the partially-bound worker.
    assert!(
        matches!(
            guard.afxdp.last_reconcile_stage,
            crate::afxdp::ReconcileStage::WorkerBindIncomplete(_)
        ),
        "the bind-incomplete stage must be preserved (not the Spawned variant), got {:?}",
        guard.afxdp.last_reconcile_stage
    );
    // #6244: legacy operator string preserved byte-for-byte.
    assert!(
        guard
            .afxdp
            .last_reconcile_stage
            .to_string()
            .starts_with("worker_bind_incomplete:")
    );

    let _ = std::fs::remove_file(&state_file);
}

// --- apply_snapshot deferred-activation integrity build (#5171) ---------

/// #5171 fail-closed DEFERRED apply — MISSING MANDATORY MAP PIN: a
/// `defer_workers=true` apply skips worker bring-up (RETH MAC pending) but
/// still ACKs + persists the snapshot as the boot baseline. Before #5171 it
/// did so WITHOUT the mandatory-map + forwarding integrity build the
/// non-defer reconcile path runs, so a snapshot with NO xsk map pin was
/// acked ok=true and persisted, only to fail-OPEN at the later deferred
/// bring-up. The new `validate_snapshot_buildable` gate rejects it up front.
///
/// The helper is DISARMED (forwarding_armed=false), the realistic deferred
/// state — arming follows the deferred worker bring-up. This proves the gate
/// runs independent of arm state (a disarmed defer apply cannot borrow
/// reconcile_status_bindings, which would take the disarmed stop path with
/// no integrity build).
///
/// RED-on-revert: without the validate call the defer branch prunes, swaps
/// the snapshot in, replans, skips the spawn, refreshes, and sets
/// persist_state — acking ok=true and persisting the non-buildable config.
/// Every assertion below flips.
#[test]
fn apply_snapshot_defer_workers_missing_map_pin_fails_closed_5171() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    // Disarmed helper (the realistic deferred state). No prior snapshot.
    let state = new_state(ProcessStatus::default());

    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 5,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        capabilities: forwarding_caps(),
        // map_pins default -> empty xsk -> mandatory-map integrity failure.
        interfaces: vec![tunnel_iface_3789("10.0.0.1/24")], // config itself valid
        defer_workers: true,
        ..ConfigSnapshot::default()
    });

    let response = run_request(state.clone(), request);
    assert!(
        !response.ok,
        "a deferred apply of a config with a MISSING mandatory map pin must fail closed"
    );
    assert!(
        response.error.contains("missing_xsk_pin"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert!(
        guard.snapshot.is_none(),
        "rejected deferred snapshot must not be stored as the boot baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 0,
        "rejected deferred apply must not bump last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 0,
        "rejected deferred apply must not bump last_fib_generation"
    );
}

/// #5171 fail-closed DEFERRED apply — FORWARDING-BUILD INTEGRITY FAULT: a
/// `defer_workers=true` apply whose mandatory pins all open but whose full
/// forwarding build FAILS (here an unparseable interface address) must fail
/// closed too — the build fault the pre-#5171 defer path never surfaced.
///
/// RED-on-revert: as above, without the gate the defer branch acks ok=true
/// and persists the non-buildable config.
#[test]
fn apply_snapshot_defer_workers_forwarding_integrity_fails_closed_5171() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    let state = new_state(ProcessStatus::default());

    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 7,
        fib_generation: 7,
        generated_at: chrono::Utc::now(),
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(), // all mandatory pins open
        interfaces: vec![tunnel_iface_3789("10.0.0.0/33")], // unparseable addr
        defer_workers: true,
        ..ConfigSnapshot::default()
    });

    let response = run_request(state.clone(), request);
    assert!(
        !response.ok,
        "a deferred apply whose forwarding build fails must fail closed"
    );
    assert!(
        response.error.contains("snapshot integrity error"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert!(
        guard.snapshot.is_none(),
        "rejected deferred snapshot must not be stored as the boot baseline"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 0,
        "rejected deferred apply must not bump last_snapshot_generation"
    );
}

/// #5171 defer semantics preserved: a `defer_workers=true` apply of a
/// fully-BUILDABLE config (all mandatory pins open, valid addresses) still
/// applies + persists + ACKs ok=true, and STILL does NOT spawn workers
/// (`debug_reconcile_calls` stays 0). The gate adds integrity VALIDATION,
/// not activation.
#[test]
fn apply_snapshot_defer_workers_valid_config_applies_without_spawning_5171() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};

    let state = new_state(ProcessStatus::default());

    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 4,
        fib_generation: 4,
        generated_at: chrono::Utc::now(),
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.1/24")], // valid, buildable
        defer_workers: true,
        ..ConfigSnapshot::default()
    });

    let response = run_request(state.clone(), request);
    assert!(
        response.ok,
        "a deferred apply of a fully-buildable config must succeed: {}",
        response.error
    );
    let status = response.status.expect("status response");
    assert_eq!(
        status.debug_reconcile_calls, 0,
        "the deferred apply must NOT run the worker-spawning reconcile"
    );

    let guard = state.lock().expect("state");
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(4),
        "the buildable deferred snapshot must be stored as the boot baseline"
    );
    assert!(
        guard.snapshot.as_ref().is_some_and(|s| s.defer_workers),
        "the stored deferred snapshot keeps defer_workers set"
    );
    assert_eq!(
        guard.status.last_snapshot_generation, 4,
        "the accepted deferred apply advances last_snapshot_generation"
    );
}

// --- apply_snapshot generation monotonicity (#5169) ---------------------

/// #5169 fail-CLOSED: a ROLLED-BACK apply_snapshot generation must be refused.
/// The FULL apply path published (config_generation, fib_generation) VERBATIM
/// with no monotonicity gate, so re-publishing a pair a later apply already
/// superseded revived flow-cache entries that later generation invalidated —
/// a stale cached ALLOW (fail-open), because flow-cache validation is EQUALITY
/// based on the pair. This mirrors the #3767 H5 rollback guard on bump_fib.
///
/// RED-on-revert: without the guard the rollback publishes (5, 5) — the stored
/// snapshot, last_snapshot_generation, and persisted state all roll back to the
/// prior generation, so an entry stamped by that generation equality-matches
/// the published pair again and the cached ALLOW is revived. Every assertion
/// below flips.
#[test]
fn apply_snapshot_rejects_generation_rollback_5169() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("apply-rollback-5169");

    // Apply gen (config=5, fib=5): first apply, publishes the baseline pair.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 5,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // Advance to gen (config=6, fib=5): strictly monotonic, applies — this is
    // the apply that logically invalidates any (5, 5)-stamped flow-cache entry.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // Rollback to gen (config=5, fib=5) — a reused/rolled-back pair equal to a
    // prior published pair. Must be refused fail-closed.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 5,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request_on_file(state.clone(), request, &state_file);
    assert!(!response.ok, "rolled-back apply_snapshot must be rejected");
    assert!(
        response
            .error
            .contains("snapshot generation rollback rejected"),
        "unexpected error: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    // The published pair must NOT roll back.
    assert_eq!(
        guard.status.last_snapshot_generation, 6,
        "rejected rollback must not lower last_snapshot_generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 5,
        "rejected rollback must not lower last_fib_generation"
    );
    // The stored snapshot (boot baseline) must NOT roll back.
    assert_eq!(
        guard.snapshot.as_ref().map(|s| s.generation),
        Some(6),
        "rejected rollback must not overwrite the stored snapshot"
    );

    // Assert the ACTUAL defect via the flow-cache equality contract: an entry
    // stamped by the prior generation is a HIT only when the published pair
    // equals its stamp (afxdp/flow_cache.rs `lookup`; see
    // `stale_config_generation_causes_miss`). A lazily-unevicted cached ALLOW
    // stamped (5, 5) is revived iff the published pair rolls back to (5, 5).
    // The guard keeps the published pair at the post-invalidation (6, 5), so
    // the stale (5, 5)-stamped entry can NEVER equality-match — it stays
    // evicted and the cached ALLOW is not revived (no fail-open).
    let stale_entry_stamp = (5u64, 5u32);
    let published_pair = (
        guard.status.last_snapshot_generation,
        guard.status.last_fib_generation,
    );
    assert_ne!(
        published_pair, stale_entry_stamp,
        "published pair must NOT roll back to the stale entry's stamp — else the \
         flow-cache equality check revives the cached ALLOW (fail-open)"
    );
    drop(guard);

    // persist_state must NOT have been set by the rejected rollback: the
    // on-disk state a restart boots from stays at the last accepted (6, 5),
    // not the rolled-back (5, 5).
    let bytes = std::fs::read(&state_file).expect("read persisted state file");
    let persisted: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse persisted state file");
    assert_eq!(
        persisted["snapshot"]["generation"].as_u64(),
        Some(6),
        "rejected rollback must not persist the rolled-back generation"
    );
    assert_eq!(
        persisted["status"]["last_snapshot_generation"].as_u64(),
        Some(6),
        "rejected rollback must not persist a rolled-back last_snapshot_generation"
    );
    let _ = std::fs::remove_file(&state_file);
}

/// #5169 (review fold): an EXACT-EQUAL apply_snapshot (the new (config, fib)
/// pair equals the last published pair) must be ADMITTED, not refused. An equal
/// pair equality-matches only the CURRENT published pair, whose cache entries
/// are already valid, so re-publishing it revives NOTHING — refusing it buys no
/// security and breaks the #4036 "timeout-but-landed" idempotent retry (the
/// partial-republish Go paths recompute the SAME generation after a timed-out
/// apply that actually landed and must be ACKed ok, not fail-closed into a
/// non-converging loop). This mirrors `bump_fib`, which admits an equal fib.
///
/// #9520: the retry is admitted only when it also carries the same NON-EMPTY
/// content digest, which is what a Go retry of the same content does. The other
/// half is `apply_snapshot_refuses_reused_generation_with_different_content_9520`.
#[test]
fn apply_snapshot_admits_generation_reuse_5169() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());

    // Apply gen (config=6, fib=5).
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            content_digest: "digest-6".to_string(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // Re-apply the identical pair (6, 5) — the idempotent-retry path: admitted.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 6,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        content_digest: "digest-6".to_string(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(
        response.ok,
        "an exact-equal re-apply (idempotent retry) must be admitted: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(guard.status.last_snapshot_generation, 6);
    assert_eq!(guard.status.last_fib_generation, 5);
    assert_eq!(guard.snapshot.as_ref().map(|s| s.generation), Some(6));
}

/// #9520: a snapshot that REUSES the installed generation but carries a
/// DIFFERENT content digest is refused before any mutation, with the
/// machine-readable prefix the Go control plane reacts to. This is the
/// timeout-but-landed shape: a republish landed content A at gen 6 while Go saw
/// a deadline error, and Go's retry rebuilt content B and re-sent gen 6. The
/// equal pair used to be admitted content-blind, installing B under the
/// identity A's flow-cache entries and session policy stamps were minted under.
///
/// RED-on-revert: delete the content identity gate and the second apply is
/// ACKed, the installed digest and default policy flip to B, and B is persisted.
#[test]
fn apply_snapshot_refuses_reused_generation_with_different_content_9520() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION, SNAPSHOT_CONTENT_CONFLICT_PREFIX};
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("apply-content-conflict-9520");
    let snapshot = |digest: &str, default_policy: &str| ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 6,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        content_digest: digest.to_string(),
        default_policy: default_policy.to_string(),
        ..ConfigSnapshot::default()
    };

    let mut request = req("apply_snapshot");
    request.snapshot = Some(snapshot("digest-a", "permit"));
    assert!(run_request_on_file(state.clone(), request, &state_file).ok);

    let mut request = req("apply_snapshot");
    request.snapshot = Some(snapshot("digest-b", "deny"));
    let response = run_request_on_file(state.clone(), request, &state_file);
    assert!(
        !response.ok,
        "gen 6 is installed with digest-a; a gen 6 apply carrying digest-b must be refused"
    );
    assert!(
        response.error.starts_with(SNAPSHOT_CONTENT_CONFLICT_PREFIX),
        "the refusal must carry the prefix Go matches, or Go cannot tell that the helper \
         holds gen 6 and re-sends it forever: {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert_eq!(guard.status.last_snapshot_generation, 6);
    assert_eq!(guard.status.last_fib_generation, 5);
    let installed = guard.snapshot.as_ref().expect("installed snapshot");
    assert_eq!(
        installed.content_digest, "digest-a",
        "the refused content must not replace the installed snapshot"
    );
    assert_eq!(
        installed.default_policy, "permit",
        "the refused content must not be enforced under gen 6"
    );
    drop(guard);

    let bytes = std::fs::read(&state_file).expect("read persisted state file");
    let persisted: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse persisted state file");
    assert_eq!(
        persisted["snapshot"]["content_digest"].as_str(),
        Some("digest-a"),
        "the refused content must not become the boot baseline"
    );
    assert_eq!(persisted["snapshot"]["default_policy"].as_str(), Some("permit"));
    let _ = std::fs::remove_file(&state_file);
}

/// #9520: the content identity gate covers a reused generation at ANY fib, not
/// only the exact (generation, fib) pair. (6, 7) passes the #5169 gate as a fib
/// advance under a reused config, but the session policy stamp and the #8356
/// re-derivation are keyed on the config generation alone, so different content
/// at (6, 7) is exactly as unsafe as at (6, 5).
///
/// RED-on-revert: narrow the gate to `fib_generation == cur_fib` and this apply
/// is ACKed with the new content.
#[test]
fn apply_snapshot_refuses_reused_generation_with_different_content_at_advanced_fib_9520() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION, SNAPSHOT_CONTENT_CONFLICT_PREFIX};
    let state = new_state(ProcessStatus::default());
    let snapshot = |fib: u32, digest: &str, default_policy: &str| ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 6,
        fib_generation: fib,
        generated_at: chrono::Utc::now(),
        content_digest: digest.to_string(),
        default_policy: default_policy.to_string(),
        ..ConfigSnapshot::default()
    };

    let mut request = req("apply_snapshot");
    request.snapshot = Some(snapshot(5, "digest-a", "permit"));
    assert!(run_request(state.clone(), request).ok);

    let mut request = req("apply_snapshot");
    request.snapshot = Some(snapshot(7, "digest-b", "deny"));
    let response = run_request(state.clone(), request);
    assert!(
        !response.ok && response.error.starts_with(SNAPSHOT_CONTENT_CONFLICT_PREFIX),
        "a gen 6 apply at an advanced fib carrying different content must be refused with \
         the conflict prefix: ok={} error={}",
        response.ok,
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(guard.status.last_fib_generation, 5, "the refused apply must not advance fib");
    let installed = guard.snapshot.as_ref().expect("installed snapshot");
    assert_eq!(installed.content_digest, "digest-a");
    assert_eq!(installed.default_policy, "permit");
}

/// #9520 positive controls: the gate refuses only DIFFERENT content under a
/// REUSED generation. The #4036 idempotent retry (same digest, fresh
/// generated_at), a fib advance carrying the same digest, and a generation
/// advance carrying different content must all still be ACKed.
///
/// RED-on-revert of an over-strict gate: refusing every same-generation apply,
/// or comparing a field outside the digest, reds the first or second step.
#[test]
fn apply_snapshot_admits_reused_generation_with_identical_content_9520() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    let snapshot = |generation: u64, fib: u32, digest: &str, default_policy: &str| ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation,
        fib_generation: fib,
        generated_at: chrono::Utc::now(),
        content_digest: digest.to_string(),
        default_policy: default_policy.to_string(),
        ..ConfigSnapshot::default()
    };
    let steps = [
        ("first apply", snapshot(6, 5, "digest-a", "permit")),
        ("idempotent retry, same digest", snapshot(6, 5, "digest-a", "permit")),
        ("fib advance, same digest", snapshot(6, 7, "digest-a", "permit")),
        ("generation advance, different content", snapshot(7, 7, "digest-b", "deny")),
    ];
    for (step, snap) in steps {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(snap);
        let response = run_request(state.clone(), request);
        assert!(response.ok, "{step} must be admitted: {}", response.error);
    }
    let guard = state.lock().expect("state");
    assert_eq!(guard.status.last_snapshot_generation, 7);
    assert_eq!(guard.status.last_fib_generation, 7);
    let installed = guard.snapshot.as_ref().expect("installed snapshot");
    assert_eq!(installed.content_digest, "digest-b");
    assert_eq!(installed.default_policy, "deny");
}

/// #9520: an EMPTY content digest never proves identity at a reused
/// generation. Two applies that carry none compare equal as strings whatever
/// their content, which is exactly the content-blind admission the gate closes.
/// A first apply and a generation advance without a digest are still admitted.
///
/// RED-on-revert: drop the `installed_digest.is_empty()` arm and the second
/// apply is ACKed with the new content.
#[test]
fn apply_snapshot_refuses_reused_generation_without_a_digest_9520() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION, SNAPSHOT_CONTENT_CONFLICT_PREFIX};
    let state = new_state(ProcessStatus::default());
    let apply = |generation: u64, digest: &str, default_policy: &str| {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            content_digest: digest.to_string(),
            default_policy: default_policy.to_string(),
            ..ConfigSnapshot::default()
        });
        run_request(state.clone(), request)
    };

    let first = apply(6, "", "permit");
    assert!(first.ok, "a first apply has no baseline to conflict with: {}", first.error);
    let bare_retry = apply(6, "", "deny");
    assert!(
        !bare_retry.ok && bare_retry.error.starts_with(SNAPSHOT_CONTENT_CONFLICT_PREFIX),
        "two gen 6 applies without a digest must not be taken as identical: ok={} error={}",
        bare_retry.ok,
        bare_retry.error
    );
    let stamped_retry = apply(6, "digest-a", "deny");
    assert!(
        !stamped_retry.ok && stamped_retry.error.starts_with(SNAPSHOT_CONTENT_CONFLICT_PREFIX),
        "an installed snapshot without a digest cannot vouch for a retry that carries one: ok={} error={}",
        stamped_retry.ok,
        stamped_retry.error
    );
    let advance = apply(7, "", "deny");
    assert!(advance.ok, "a generation advance needs no digest: {}", advance.error);
    let guard = state.lock().expect("state");
    assert_eq!(guard.status.last_snapshot_generation, 7);
    assert_eq!(guard.snapshot.as_ref().map(|s| s.default_policy.as_str()), Some("deny"));
}

/// #9520: a partial update that changes content the helper enforces stops the
/// installed digest vouching for a retry. `update_fabrics` rewrites the stored
/// snapshot's fabrics and `update_neighbors` changes the coordinator's
/// neighbours; after either, the full apply the digest came from must not be
/// accepted again at the same generation. The identical retry BEFORE the partial
/// update is the positive control: it is ACKed, so the later refusal is the
/// update's doing.
///
/// RED-on-revert: drop either `content_digest.clear()` and that arm's retry is
/// ACKed.
#[test]
fn a_partial_update_stops_the_installed_digest_vouching_for_a_retry_9520() {
    use crate::{
        ConfigSnapshot, FabricSnapshot, NeighborSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        SNAPSHOT_CONTENT_CONFLICT_PREFIX,
    };
    let full_apply = || {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            content_digest: "digest-a".to_string(),
            ..ConfigSnapshot::default()
        });
        request
    };
    for arm in ["update_fabrics", "update_neighbors"] {
        let state = new_state(ProcessStatus::default());
        let baseline = run_request(state.clone(), full_apply());
        assert!(baseline.ok, "{arm}: baseline apply: {}", baseline.error);
        let control = run_request(state.clone(), full_apply());
        assert!(
            control.ok,
            "{arm}: before any partial update the identical retry must be ACKed: {}",
            control.error
        );

        let mut partial = req(arm);
        if arm == "update_fabrics" {
            partial.fabrics = Some(vec![FabricSnapshot::default()]);
        } else {
            partial.neighbors = Some(vec![NeighborSnapshot {
                ifindex: 5,
                ip: "10.0.61.2".to_string(),
                mac: "02:00:00:00:00:02".to_string(),
                state: "reachable".to_string(),
                ..NeighborSnapshot::default()
            }]);
            partial.neighbor_generation = 1;
        }
        let _ = run_request(state.clone(), partial);
        {
            let guard = state.lock().expect("state");
            assert_eq!(
                guard.snapshot.as_ref().map(|s| s.content_digest.as_str()),
                Some(""),
                "{arm}: the partial update must clear the installed digest"
            );
        }

        let replay = run_request(state.clone(), full_apply());
        assert!(
            !replay.ok && replay.error.starts_with(SNAPSHOT_CONTENT_CONFLICT_PREFIX),
            "{arm}: after the partial update a same-generation replay of the full apply must be \
             refused: ok={} error={}",
            replay.ok,
            replay.error
        );
    }
}

/// #5169 (review fold): a FIB ROLLBACK under a reused config (config == cur,
/// fib < cur_fib) must be REFUSED. This is the second rollback axis — the fib
/// half of the pair rolling back re-publishes a superseded pair whose stale
/// flow-cache entries would be revived, exactly the fail-open on the fib
/// dimension (the full-apply analogue of the #3767 H5 bump_fib rollback).
///
/// RED-on-revert: neutralize the guard and the (6, 6) rollback publishes over
/// the (6, 7) baseline — the assertions below flip.
/// #9520: every apply here carries the SAME content digest, because "config
/// reused" means the same content. A reused generation with a different or empty
/// digest is refused before this #5169 gate's fib comparison matters.
#[test]
fn apply_snapshot_rejects_fib_rollback_5169() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());

    // Baseline (config=6, fib=5).
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            content_digest: "digest-6".to_string(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // Fib advances 5 -> 7 (config reused at 6): admitted.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 7,
            generated_at: chrono::Utc::now(),
            content_digest: "digest-6".to_string(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // Fib rolls back 7 -> 6 under the reused config 6: must be refused.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 6,
        fib_generation: 6,
        generated_at: chrono::Utc::now(),
        content_digest: "digest-6".to_string(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(!response.ok, "a fib rollback under a reused config must be rejected");
    assert!(
        response
            .error
            .contains("snapshot generation rollback rejected"),
        "unexpected error: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(
        guard.status.last_snapshot_generation, 6,
        "rejected fib rollback keeps the published config generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 7,
        "rejected fib rollback must not lower last_fib_generation"
    );
    assert_eq!(guard.snapshot.as_ref().map(|s| s.fib_generation), Some(7));
}

/// #5169: a strictly-monotonic apply_snapshot whose CONFIG generation advances
/// (the normal full-apply path) must apply exactly as before — the guard must
/// not regress legitimate applies.
#[test]
fn apply_snapshot_monotonic_config_advance_applies_5169() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());

    // Baseline (config=5, fib=5).
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 5,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // Config advances 5 -> 6 (fib carried forward at 5): admitted.
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 6,
        fib_generation: 5,
        generated_at: chrono::Utc::now(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(
        response.ok,
        "strictly-monotonic config advance must apply: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(guard.status.last_snapshot_generation, 6);
    assert_eq!(guard.status.last_fib_generation, 5);
    assert_eq!(guard.snapshot.as_ref().map(|s| s.generation), Some(6));
}

/// #5169: a FIB-ONLY advance via apply_snapshot (config REUSED, fib
/// incremented) is LEGITIMATE — the route-only overlay case that `bump_fib`
/// handles — and must be ADMITTED, not falsely refused by an over-strict
/// guard. The pair-monotonicity relation is lexicographic strict-greater, so
/// (config==cur && fib>cur.fib) applies. Any advance of either generation
/// changes the flow-cache equality key and correctly invalidates the cache.
/// #9520: every apply here carries the SAME content digest, because "config
/// reused" means the same content. A reused generation with a different or empty
/// digest is refused before this #5169 gate's fib comparison matters.
#[test]
fn apply_snapshot_fib_only_advance_admitted_5169() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());

    // Baseline (config=6, fib=5).
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 6,
            fib_generation: 5,
            generated_at: chrono::Utc::now(),
            content_digest: "digest-6".to_string(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request(state.clone(), request).ok);
    }
    // Config REUSED at 6, fib advances 5 -> 6: admitted (route-only overlay).
    let mut request = req("apply_snapshot");
    request.snapshot = Some(ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 6,
        fib_generation: 6,
        generated_at: chrono::Utc::now(),
        content_digest: "digest-6".to_string(),
        ..ConfigSnapshot::default()
    });
    let response = run_request(state.clone(), request);
    assert!(
        response.ok,
        "a fib-only advance (config reused, fib incremented) must be admitted: {}",
        response.error
    );
    let guard = state.lock().expect("state");
    assert_eq!(
        guard.status.last_snapshot_generation, 6,
        "fib-only advance keeps the reused config generation"
    );
    assert_eq!(
        guard.status.last_fib_generation, 6,
        "fib-only advance publishes the incremented fib generation"
    );
    assert_eq!(guard.snapshot.as_ref().map(|s| s.fib_generation), Some(6));
}

// --- set_binding_state / set_queue_state error arms ---------------------

#[test]
fn set_binding_state_missing_payload_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("set_binding_state"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing binding state"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_binding_state_unknown_slot_is_rejected() {
    let mut request = req("set_binding_state");
    request.binding = Some(BindingControlRequest {
        slot: 999,
        registered: true,
        armed: false,
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("unknown binding slot 999"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_binding_state_toggles_registered_and_armed_on_known_slot() {
    // Seed one registered binding; arm it via set_binding_state and
    // assert the success arm flips armed (forwarding unarmed so the
    // reconcile is a safe no-op teardown).
    let state = new_state(ProcessStatus {
        bindings: vec![BindingStatus {
            slot: 3,
            registered: true,
            armed: false,
            ..BindingStatus::default()
        }],
        ..ProcessStatus::default()
    });
    let mut request = req("set_binding_state");
    request.binding = Some(BindingControlRequest {
        slot: 3,
        registered: true,
        armed: true,
    });
    let response = run_request(state.clone(), request);
    assert!(response.ok, "unexpected error: {}", response.error);
    let guard = state.lock().expect("state");
    let binding = guard
        .status
        .bindings
        .iter()
        .find(|b| b.slot == 3)
        .expect("seeded slot 3");
    assert!(binding.registered);
    assert!(binding.armed, "armed flag must flip on the known slot");
}

#[test]
fn set_queue_state_missing_payload_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("set_queue_state"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing queue state"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_queue_state_unknown_queue_is_rejected() {
    let mut request = req("set_queue_state");
    request.queue = Some(QueueControlRequest {
        queue_id: 42,
        registered: true,
        armed: false,
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok);
    assert!(
        response.error.contains("unknown queue 42"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_queue_state_toggles_armed_on_known_queue() {
    let state = new_state(ProcessStatus {
        bindings: vec![BindingStatus {
            slot: 0,
            queue_id: 2,
            registered: true,
            armed: false,
            ..BindingStatus::default()
        }],
        ..ProcessStatus::default()
    });
    let mut request = req("set_queue_state");
    request.queue = Some(QueueControlRequest {
        queue_id: 2,
        registered: true,
        armed: true,
    });
    let response = run_request(state.clone(), request);
    assert!(response.ok, "unexpected error: {}", response.error);
    let guard = state.lock().expect("state");
    assert!(
        guard
            .status
            .bindings
            .iter()
            .find(|b| b.queue_id == 2)
            .expect("seeded queue 2")
            .armed,
        "armed flag must flip on the known queue"
    );
}

// --- #5621: control-socket handlers must SURFACE a failed reconcile ------
//
// binding.rs / queue.rs / rebind.rs used to `let _ =
// reconcile_status_bindings(guard)` — discarding the `Result`. When the
// reconcile FAILED (a mandatory-pin preflight fault, or a forwarding-build
// integrity error on the ALREADY-ACCEPTED snapshot) the handler still acked
// ok=true, so the control-socket caller believed the AF_XDP sockets were
// (re)bound when they were not. These tests fault the reconcile with a stored
// snapshot whose forwarding build fails (an unparseable /33 interface address —
// the #3789 fixture) and pin ok=false + the surfaced error. Reverting the
// matching site to `let _ = reconcile_status_bindings(...)` flips the
// assertion RED (target-count 1 per site): the discard restores ok=true.
// Distinct from #5143 (that was the apply_snapshot rejected-snapshot leg).

/// A stored snapshot whose forwarding build FAILS (unparseable `/33` address).
/// With `forwarding_armed` + `forwarding_supported`, `reconcile_status_bindings`
/// takes the armed arm and `afxdp.reconcile` returns `Err` on this snapshot —
/// the same fault the #3789 apply-leg tests use.
fn failing_reconcile_snapshot() -> crate::ConfigSnapshot {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation: 7,
        fib_generation: 7,
        generated_at: chrono::Utc::now(),
        capabilities: forwarding_caps(),
        map_pins: ok_map_pins(),
        interfaces: vec![tunnel_iface_3789("10.0.0.0/33")],
        ..ConfigSnapshot::default()
    }
}

/// Armed + forwarding-supported helper carrying a stored snapshot that will
/// fault the reconcile. The already-accepted snapshot models the #5621
/// scenario: a registration toggle / rebind re-runs the reconcile, which
/// faults, and the handler must NOT report success.
fn armed_state_with_failing_reconcile(bindings: Vec<BindingStatus>) -> Arc<Mutex<ServerState>> {
    Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            forwarding_armed: true,
            capabilities: forwarding_caps(),
            bindings,
            ..ProcessStatus::default()
        },
        snapshot: Some(failing_reconcile_snapshot()),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }))
}

#[test]
fn set_binding_state_failed_reconcile_reports_error_5621() {
    // registered toggles false -> true so `registration_changed` fires the
    // reconcile; the stored bad snapshot makes that reconcile return Err.
    let state = armed_state_with_failing_reconcile(vec![BindingStatus {
        slot: 0,
        registered: false,
        ifindex: 10,
        ..BindingStatus::default()
    }]);
    let mut request = req("set_binding_state");
    request.binding = Some(BindingControlRequest {
        slot: 0,
        registered: true,
        armed: true,
    });
    let response = run_request(state, request);
    assert!(
        !response.ok,
        "#5621: set_binding_state must report ok=false when the reconcile fails"
    );
    assert!(
        response.error.contains("binding reconcile failed"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_queue_state_failed_reconcile_reports_error_5621() {
    // registered toggles false -> true so `registration_changed` fires the
    // reconcile; the stored bad snapshot makes that reconcile return Err.
    let state = armed_state_with_failing_reconcile(vec![BindingStatus {
        slot: 0,
        queue_id: 2,
        registered: false,
        ifindex: 10,
        ..BindingStatus::default()
    }]);
    let mut request = req("set_queue_state");
    request.queue = Some(QueueControlRequest {
        queue_id: 2,
        registered: true,
        armed: true,
    });
    let response = run_request(state, request);
    assert!(
        !response.ok,
        "#5621: set_queue_state must report ok=false when the reconcile fails"
    );
    assert!(
        response.error.contains("queue reconcile failed"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn rebind_failed_reconcile_reports_error_5621() {
    // rebind unconditionally reconciles; the stored bad snapshot makes that
    // reconcile return Err. Before #5621 rebind::handle took no `response`
    // and always acked ok=true.
    let state = armed_state_with_failing_reconcile(vec![BindingStatus {
        slot: 0,
        registered: true,
        ifindex: 10,
        ..BindingStatus::default()
    }]);
    let response = run_request(state, req("rebind"));
    assert!(
        !response.ok,
        "#5621: rebind must report ok=false when the reconcile fails"
    );
    assert!(
        response.error.contains("rebind reconcile failed"),
        "unexpected error: {}",
        response.error
    );
}

#[test]
fn set_forwarding_state_failed_reconcile_reports_error_6135() {
    // #6135 (the 4th site of #5621, excluded from the #6134 fix): the
    // set_forwarding_state handler used to `let _ =
    // reconcile_status_bindings(guard)`, acking ok=true even when the reconcile
    // of the ALREADY-ACCEPTED snapshot FAILED (a mandatory-pin preflight fault
    // or a forwarding-build integrity error). Arm forwarding on a registered
    // binding so the handler keeps forwarding_armed=true; the stored bad
    // snapshot (unparseable /33 interface address) makes
    // reconcile_status_bindings take the armed arm and return Err. Reverting
    // the matching site to `let _ = reconcile_status_bindings(...)` restores
    // ok=true and flips this assertion RED (target-count 1).
    let state = armed_state_with_failing_reconcile(vec![BindingStatus {
        slot: 0,
        registered: true,
        ifindex: 10,
        ..BindingStatus::default()
    }]);
    let mut request = req("set_forwarding_state");
    request.forwarding = Some(ForwardingControlRequest { armed: true });
    let response = run_request(state, request);
    assert!(
        !response.ok,
        "#6135: set_forwarding_state must report ok=false when the reconcile fails"
    );
    assert!(
        response.error.contains("forwarding reconcile failed"),
        "unexpected error: {}",
        response.error
    );
}

// --- #5862: the binding-settle wait must not hold the ServerState lock -----

/// A state whose bindings can never settle: one REGISTERED slot with no
/// worker, so `bindings_settled` (registered => ready || last_error) is false
/// on every poll and `wait_for_binding_settle` runs to its deadline.
fn never_settling_state() -> Arc<Mutex<ServerState>> {
    Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            forwarding_armed: true,
            capabilities: forwarding_caps(),
            bindings: vec![BindingStatus {
                slot: 0,
                registered: true,
                ifindex: 10,
                ..BindingStatus::default()
            }],
            ..ProcessStatus::default()
        },
        snapshot: None,
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }))
}

/// Fail-on-revert (#5862): `wait_for_binding_settle` must RELEASE the global
/// `ServerState` lock across each 50 ms sleep.
///
/// The HA session socket is a separate socket on a separate thread
/// (`lifecycle.rs`), but its one verb — `sync_session` — dispatches through the
/// same `Arc<Mutex<ServerState>>` as every main-socket verb, so the socket split
/// never split the critical section. A 2 s settle held under that lock is longer
/// than the Go side's 3 s session round-trip budget once queuing is added, and
/// #5380 makes the FIRST session timeout abort the rest of the bulk batch — so
/// this is a dropped-mirror bug at failover, not only a latency tail.
///
/// The assertion is deliberately about the LOCK, not about a timing average: it
/// takes the lock from another thread mid-wait and requires that acquisition to
/// be prompt. Reverting the helper to hold one guard across the loop makes this
/// block for the whole remaining deadline — RED.
#[test]
fn wait_for_binding_settle_releases_state_lock_between_polls() {
    use std::time::{Duration, Instant};

    let state = never_settling_state();
    let waiter = {
        let state = state.clone();
        std::thread::spawn(move || {
            crate::server::helpers::wait_for_binding_settle(&state, Duration::from_millis(900));
        })
    };

    // Let the waiter enter its poll loop.
    std::thread::sleep(Duration::from_millis(120));

    let t0 = Instant::now();
    {
        let guard = state.lock().expect("state lock");
        assert_eq!(guard.status.bindings.len(), 1, "fixture lost its binding");
    }
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(200),
        "acquiring the ServerState lock took {elapsed:?} while a binding-settle \
         wait was in flight — the wait is holding the lock across its sleep, so \
         every HA sync_session on the dedicated session socket queues behind it \
         (#5862)"
    );

    waiter.join().expect("settle waiter");
}

/// The end-to-end half: a `sync_session` request must be SERVED while a
/// `set_forwarding_state` settle wait is in flight. This drives both through the
/// real `handle_stream` dispatcher, which is what proves the handler wiring
/// (locked arm records the owed settle; `handle_request` runs it after the guard
/// drops) and not merely the helper in isolation.
#[test]
fn sync_session_is_served_during_a_forwarding_settle_wait() {
    use std::time::{Duration, Instant};

    let state = never_settling_state();

    let settle_state = state.clone();
    let settler = std::thread::spawn(move || {
        let mut request = req("set_forwarding_state");
        request.forwarding = Some(ForwardingControlRequest { armed: true });
        run_request(settle_state, request)
    });

    // Let set_forwarding_state reach its settle wait.
    std::thread::sleep(Duration::from_millis(150));

    let t0 = Instant::now();
    let resp = run_request(state.clone(), req("sync_session"));
    let elapsed = t0.elapsed();
    // The request is REJECTED (no payload) — irrelevant here. What is asserted
    // is that it was DISPATCHED promptly rather than queued behind the settle.
    assert!(
        elapsed < Duration::from_millis(600),
        "a sync_session request waited {elapsed:?} behind a set_forwarding_state \
         binding-settle wait; the settle is holding the global ServerState lock, \
         which is exactly the contention the dedicated session socket was \
         supposed to remove (#5862). error={}",
        resp.error
    );

    let settle_resp = settler.join().expect("settle thread");
    assert!(
        settle_resp.ok,
        "set_forwarding_state failed: {}",
        settle_resp.error
    );
}

// --- #7209: sync_session must not queue behind a ServerState lock holder ----

/// #7209: a `sync_session` request must be SERVED while another thread holds
/// the global `ServerState` mutex.
///
/// THE INSTRUMENT IS DELIBERATELY NOT `apply_snapshot`. The issue frames the
/// case as "sync_session served while apply_snapshot reconciles", but in this
/// suite the Coordinator is `Coordinator::new()` with no NICs, so a reconcile
/// does NOT reach the 10 s worker-readiness barrier and returns almost
/// immediately. A timing test built on it would pass whether or not
/// `sync_session` takes the global lock — it would be measuring nothing, which
/// is the failure mode where a green is indistinguishable from an absent test.
///
/// So this holds the lock DIRECTLY. That is the property the issue is actually
/// about — "`sync_session` does not queue behind a `ServerState` lock holder" —
/// rather than one instance of a slow holder, and it is deterministic: the hold
/// duration is the test's, not the reconcile path's. Every long holder the
/// issue enumerates (the 10 s barrier at `reconcile/bringup.rs`, the mlx5
/// teardown quiesce, the unbounded worker `join()`, the map-pin syscalls)
/// reaches `sync_session` through exactly this mutex, so binding the mutex
/// binds all four.
///
/// EXPECTED RED until #7209 is fixed. `handlers/mod.rs` dispatches every verb,
/// `sync_session` included, under one `state.lock()`, so today this request
/// blocks for the full hold. That is the point: the test is written before the
/// fix so the fix has a red to work against, rather than resting on a reading
/// of the lock graph — which is what failed on #7095.
///
/// The request is REJECTED (no payload) and that is irrelevant: what is
/// asserted is that it was DISPATCHED promptly rather than queued. Asserting on
/// the response would bind the wrong property.
/// UN-`#[ignore]`d by the change that satisfies it. It was written before the
/// fix so the fix had a red to work against; leaving the attribute on would
/// have left a guard whose stated reason names a condition that no longer
/// holds, which rots quietly and protects nothing.
#[test]
fn sync_session_is_served_while_the_state_lock_is_held_7209() {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    // How long the stand-in holder keeps the lock, and the bar the measured
    // request must beat. The gap between them is the test's whole signal, so
    // they are named together rather than buried as literals.
    const HOLD_MS: u64 = 1_200;
    const SERVED_WITHIN_MS: u64 = 500;

    let state = never_settling_state();
    // #7209: taken BEFORE the holder acquires, as `lifecycle.rs` takes it before
    // the daemon serves anything. Deriving it inside the measured request would
    // block on the holder and time the harness instead of the dispatcher.
    let session_domain = state.lock().expect("state").afxdp.session_domain().clone();

    // A holder standing in for any of the four long operations apply_snapshot
    // performs under the lock. `holding` reports that the lock is actually
    // taken, so the measurement below cannot start before contention exists —
    // a sleep here would race and could time an UNCONTENDED request, which
    // passes for the wrong reason.
    let (holding_tx, holding_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let holder_state = state.clone();
    let holder = std::thread::spawn(move || {
        let _guard = holder_state.lock().expect("state lock");
        holding_tx.send(()).expect("signal holding");
        // Released on the measurement's signal, or after HOLD_MS, whichever
        // comes first. The bound is not just a hang guard: waiting only on the
        // signal is CIRCULAR today, because the signal is sent after the
        // measured request returns and that request cannot return until this
        // lock drops. The bound is what makes the red cost HOLD_MS instead of
        // the full timeout, and it does not weaken the assertion — HOLD_MS is
        // comfortably above the threshold, so a queued request still reds.
        let _ = release_rx.recv_timeout(Duration::from_millis(HOLD_MS));
    });
    holding_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("holder never acquired the state lock");

    let t0 = Instant::now();
    let resp = run_request_with_domain(state.clone(), req("sync_session"), session_domain);
    let elapsed = t0.elapsed();
    let _ = release_tx.send(());
    holder.join().expect("holder thread");

    assert!(
        elapsed < Duration::from_millis(SERVED_WITHIN_MS),
        "a sync_session request waited {elapsed:?} behind a thread holding the \
         global ServerState mutex. apply_snapshot holds that same mutex across a \
         10 s worker-readiness barrier, an unbounded worker join() and the mlx5 \
         teardown quiesce, while the Go side budgets 3 s per session round-trip \
         and #5380 ABORTS the rest of a bulk batch on the first transport \
         failure — so this contention drops session mirrors (up to 255 in one \
         batch) during exactly the failover the path exists to serve (#7209). \
         error={}",
        resp.error
    );
}

/// #7209: the SECOND contention cell, driving a REAL payload.
///
/// WHY THE CELL ABOVE IS NOT ENOUGH, and why it is nonetheless correct. That
/// one sends `req("sync_session")` with no `session_sync`, so the handler
/// returns at its first `let Some(sync_req) = session_sync else { ... }`
/// (handlers/sync_session.rs). Its doc says so and calls the rejection
/// irrelevant, which is right for the property IT binds: the request was
/// DISPATCHED promptly rather than queued behind the global mutex. That
/// property is real and this cell does not replace it.
///
/// What it cannot see is the verb BODY. A fix that moves only the dispatch off
/// the snapshot-wide mutex — taking it again inside `sync_session::handle`, or
/// leaving the coordinator calls behind it — turns that cell GREEN while a real
/// peer session mirror still blocks for the whole reconcile. The distinction is
/// exactly the fail-open this issue is about, one level up: an instrument that
/// certifies a partial fix.
///
/// So this drives a real UPSERT and a real DELETE, and asserts two things per
/// operation:
///
///   1. it was served inside the bar (the timing property), and
///   2. it got PAST the payload guard — proving the verb body actually ran,
///      rather than the cell having silently degenerated into a copy of the one
///      above. Without (2) a future edit that drops the payload would leave
///      this cell passing for the first cell's reason.
///
/// Both operations, because #5380 aborts the remainder of a bulk batch on the
/// first transport failure and a batch carries both verbs; a fix that freed
/// only one would still drop mirrors.
/// UN-`#[ignore]`d by the change that satisfies it — the verb body now runs off
/// the mutex, not merely its dispatch.
#[test]
fn sync_session_real_payload_is_served_while_the_state_lock_is_held_7209() {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const HOLD_MS: u64 = 1_200;
    const SERVED_WITHIN_MS: u64 = 500;

    fn upsert_request() -> ControlRequest {
        let mut request = req("sync_session");
        request.session_sync = Some(SessionSyncRequest {
            operation: "upsert".to_string(),
            addr_family: 2,
            protocol: 6,
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port: 1234,
            dst_port: 80,
            egress_ifindex: 7,
            neighbor_mac: "02:bf:72:01:02:03".to_string(),
            src_mac: "02:bf:72:0a:0b:0c".to_string(),
            ..SessionSyncRequest::default()
        });
        request
    }

    fn delete_request() -> ControlRequest {
        let mut request = req("sync_session");
        request.session_sync = Some(SessionSyncRequest {
            operation: "delete".to_string(),
            addr_family: 2,
            protocol: 6,
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port: 1234,
            dst_port: 80,
            ..SessionSyncRequest::default()
        });
        request
    }

    for (op, build) in [
        ("upsert", upsert_request as fn() -> ControlRequest),
        ("delete", delete_request as fn() -> ControlRequest),
    ] {
        let state = never_settling_state();
        // #7209: taken before the holder acquires, as `lifecycle.rs` does.
        let session_domain = state.lock().expect("state").afxdp.session_domain().clone();

        // Same holder shape as the cell above: `holding` reports that the lock
        // is actually taken, so the measurement cannot start before contention
        // exists and time an UNCONTENDED request.
        let (holding_tx, holding_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let holder_state = state.clone();
        let holder = std::thread::spawn(move || {
            let _guard = holder_state.lock().expect("state lock");
            holding_tx.send(()).expect("signal holding");
            let _ = release_rx.recv_timeout(Duration::from_millis(HOLD_MS));
        });
        holding_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("holder never acquired the state lock");

        let t0 = Instant::now();
        let resp = run_request_with_domain(state.clone(), build(), session_domain);
        let elapsed = t0.elapsed();
        let _ = release_tx.send(());
        holder.join().expect("holder thread");

        // (2) first: a cell that measured promptly but never entered the verb
        // would otherwise report success for the wrong reason.
        assert!(
            !resp.error.contains("missing session sync request"),
            "the {op} payload did not reach the verb body — this cell has \
             degenerated into a copy of the empty-payload cell above and can no \
             longer distinguish a dispatch-only fix. error={}",
            resp.error
        );

        // (1) the contention property.
        assert!(
            elapsed < Duration::from_millis(SERVED_WITHIN_MS),
            "a sync_session {op} carrying a REAL payload waited {elapsed:?} behind a \
             thread holding the global ServerState mutex. Moving only the DISPATCH \
             off that mutex turns the empty-payload cell green while a real peer \
             session mirror still blocks for the whole reconcile — which is what \
             drops up to 255 mirrors in one #5380 batch during a failover (#7209). \
             error={}",
            resp.error
        );
    }
}

#[test]
fn stop_workers_clears_socket_fields_on_all_bindings() {
    // stop_workers must tear down per-binding socket state so the
    // subsequent rebind recreates fresh AF_XDP sockets.
    let mut seeded = BindingStatus {
        slot: 0,
        registered: true,
        bound: true,
        xsk_registered: true,
        zero_copy: true,
        socket_fd: 42,
        ready: true,
        ..BindingStatus::default()
    };
    seeded.xsk_bind_mode = "zerocopy".to_string();
    seeded.last_error = "stale".to_string();
    let state = new_state(ProcessStatus {
        bindings: vec![seeded],
        ..ProcessStatus::default()
    });
    let response = run_request(state.clone(), req("stop_workers"));
    assert!(response.ok, "unexpected error: {}", response.error);
    let guard = state.lock().expect("state");
    let binding = &guard.status.bindings[0];
    assert!(!binding.bound);
    assert!(!binding.xsk_registered);
    assert!(binding.xsk_bind_mode.is_empty());
    assert!(!binding.zero_copy);
    assert_eq!(binding.socket_fd, 0);
    assert!(!binding.ready);
    assert!(binding.last_error.is_empty());
}

#[test]
fn inject_packet_missing_payload_is_rejected() {
    let response = run_request(new_state(ProcessStatus::default()), req("inject_packet"));
    assert!(!response.ok);
    assert!(
        response.error.contains("missing packet injection request"),
        "unexpected error: {}",
        response.error
    );
}

// --- pure helper predicates --------------------------------------------

#[test]
fn forwarding_unsupported_error_uses_generic_text_without_reasons() {
    let cap = UserspaceCapabilities {
        forwarding_supported: false,
        unsupported_reasons: Vec::new(),
    };
    let msg = forwarding_unsupported_error(&cap);
    assert_eq!(
        msg,
        "userspace live forwarding is not supported for the current configuration"
    );
}

#[test]
fn forwarding_unsupported_error_joins_reasons() {
    let cap = UserspaceCapabilities {
        forwarding_supported: false,
        unsupported_reasons: vec!["reason a".to_string(), "reason b".to_string()],
    };
    let msg = forwarding_unsupported_error(&cap);
    assert!(msg.contains("reason a; reason b"), "got: {msg}");
}

#[test]
fn parse_session_sync_mac_round_trips_valid_mac() {
    let parsed = parse_session_sync_mac("02:bf:72:01:02:03").expect("valid mac");
    assert_eq!(parsed, Some([0x02, 0xbf, 0x72, 0x01, 0x02, 0x03]));
}

#[test]
fn parse_session_sync_mac_empty_is_none() {
    assert_eq!(parse_session_sync_mac("").expect("empty ok"), None);
}

#[test]
fn parse_session_sync_mac_rejects_short_mac() {
    assert!(parse_session_sync_mac("02:bf:72").is_err());
}

#[test]
fn parse_session_sync_mac_rejects_long_mac() {
    assert!(parse_session_sync_mac("02:bf:72:01:02:03:04").is_err());
}

#[test]
fn parse_session_sync_mac_rejects_non_hex() {
    assert!(parse_session_sync_mac("zz:bf:72:01:02:03").is_err());
}

#[test]
fn should_run_afxdp_requires_armed_and_supported() {
    let mut status = ProcessStatus {
        forwarding_armed: true,
        ..ProcessStatus::default()
    };
    status.capabilities.forwarding_supported = false;
    assert!(!should_run_afxdp(&status), "unsupported must not run");
    status.capabilities.forwarding_supported = true;
    assert!(should_run_afxdp(&status), "armed + supported must run");
    status.forwarding_armed = false;
    assert!(!should_run_afxdp(&status), "unarmed must not run");
}

#[test]
fn reconcile_disarmed_clears_full_stale_binding_survivors() {
    // #2794 fail-on-revert. When `should_run_afxdp` goes false
    // (forwarding disarmed), `reconcile_status_bindings` takes the early
    // return arm. Before #2794 that arm hand-cleared only a SUBSET of the
    // per-binding fields (`bound`/`xsk_registered`/`xsk_bind_mode`/
    // `zero_copy`/`socket_fd`/`ready`/`last_error`) and left the SAME
    // survivor class #2515 fixed on the no_snapshot reconcile arm stale:
    // `socket_ifindex`/`socket_queue_id`/`socket_bind_flags`,
    // `flow_cache_capacity`, and `active_flow_count`. Routing the arm
    // through `refresh_bindings` (which sends every now-workerless slot
    // through `zero_unbound_slot`) clears the FULL set.
    //
    // Seed a slot that looks like it was actively bound + forwarding, then
    // disarm and reconcile. If someone reverts to the partial hand-clear,
    // the survivor assertions below FAIL (the socket/flow-cache fields
    // stay non-zero).
    let state = new_state(ProcessStatus {
        // forwarding_armed = false -> should_run_afxdp() false -> early arm.
        forwarding_armed: false,
        capabilities: UserspaceCapabilities {
            forwarding_supported: true,
            unsupported_reasons: Vec::new(),
        },
        bindings: vec![BindingStatus {
            slot: 0,
            registered: true,
            // --- the subset the old hand-clear DID reset ---
            bound: true,
            xsk_registered: true,
            xsk_bind_mode: "zero-copy".to_string(),
            zero_copy: true,
            socket_fd: 42,
            ready: true,
            last_error: "stale".to_string(),
            // --- the #2794 survivor class the old hand-clear LEFT STALE ---
            socket_ifindex: 7,
            socket_queue_id: 3,
            socket_bind_flags: 0x4,
            flow_cache_capacity: 65536,
            active_flow_count: 123,
            // a representative counter gauge, also a survivor pre-#2794
            rx_packets: 999,
            ..BindingStatus::default()
        }],
        ..ProcessStatus::default()
    });

    {
        let mut guard = state.lock().expect("state");
        // #3789: disarmed reconcile is a teardown — always Ok.
        reconcile_status_bindings(&mut guard).expect("disarmed reconcile is infallible");
    }

    let guard = state.lock().expect("state");
    let b = &guard.status.bindings[0];
    // Subset the old arm already cleared (regression guard).
    assert!(!b.bound, "bound must be cleared");
    assert!(!b.xsk_registered, "xsk_registered must be cleared");
    assert!(b.xsk_bind_mode.is_empty(), "xsk_bind_mode must be cleared");
    assert!(!b.zero_copy, "zero_copy must be cleared");
    assert_eq!(b.socket_fd, 0, "socket_fd must be cleared");
    assert!(!b.ready, "ready must be cleared");
    assert!(b.last_error.is_empty(), "last_error must be cleared");
    // The #2794 survivor class — THESE go RED if the fix is reverted.
    assert_eq!(b.socket_ifindex, 0, "#2794: socket_ifindex left stale");
    assert_eq!(b.socket_queue_id, 0, "#2794: socket_queue_id left stale");
    assert_eq!(b.socket_bind_flags, 0, "#2794: socket_bind_flags left stale");
    assert_eq!(b.flow_cache_capacity, 0, "#2794: flow_cache_capacity left stale");
    assert_eq!(b.active_flow_count, 0, "#2794: active_flow_count left stale");
    assert_eq!(b.rx_packets, 0, "#2794: rx_packets counter left stale");
}

#[test]
fn set_bindings_forwarding_armed_only_arms_registered_bindings() {
    let mut status = ProcessStatus {
        bindings: vec![
            BindingStatus {
                slot: 0,
                registered: true,
                ..BindingStatus::default()
            },
            BindingStatus {
                slot: 1,
                registered: false,
                ..BindingStatus::default()
            },
        ],
        ..ProcessStatus::default()
    };
    set_bindings_forwarding_armed(&mut status, true);
    assert!(status.bindings[0].armed, "registered binding must arm");
    assert!(
        !status.bindings[1].armed,
        "unregistered binding must not arm"
    );
}

#[test]
fn bindings_settled_unregistered_settled_only_when_torn_down() {
    let settled = vec![BindingStatus {
        registered: false,
        bound: false,
        xsk_registered: false,
        ..BindingStatus::default()
    }];
    assert!(bindings_settled(&settled));

    let unsettled = vec![BindingStatus {
        registered: false,
        bound: true,
        ..BindingStatus::default()
    }];
    assert!(
        !bindings_settled(&unsettled),
        "unregistered-but-still-bound is not settled"
    );
}

#[test]
fn bindings_settled_registered_needs_ready_or_error() {
    let pending = vec![BindingStatus {
        registered: true,
        ready: false,
        ..BindingStatus::default()
    }];
    assert!(!bindings_settled(&pending), "registered + not ready is pending");

    let ready = vec![BindingStatus {
        registered: true,
        ready: true,
        ..BindingStatus::default()
    }];
    assert!(bindings_settled(&ready));

    let mut errored = BindingStatus {
        registered: true,
        ready: false,
        ..BindingStatus::default()
    };
    errored.last_error = "bind failed".to_string();
    assert!(
        bindings_settled(&[errored]),
        "registered with a terminal error counts as settled"
    );
}

// --- #1866: disarmed same-plan apply must not hold WG ports --------------

/// PR #1872 Codex code-r1 F1 regression: with forwarding DISARMED, a
/// same-plan apply_snapshot takes the refresh_runtime_snapshot leg
/// (needs_reconcile is false while disarmed), which reconciles WG
/// control threads for the running case — the handler must then stop
/// them so a disarmed helper never holds WG listen ports (mirrors the
/// reconcile_status_bindings → stop() semantics of the
/// NOT-same-plan path).
#[test]
fn wg1866_disarmed_same_plan_apply_does_not_hold_wg_ports() {
    use crate::{ConfigSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    // Hold the WG port for the whole test: a disarmed helper must not even
    // ATTEMPT a bind (Codex code-r2 — the transient spawn/bind would surface
    // here as a wg_bind_listen_port exception), so this blocker must never be
    // hit. #9549: the port is EPHEMERAL, read back from the holder. The property
    // needs a port this test holds, not a particular number, and a fixed number
    // collided with any second copy of this suite on the host.
    let (_blocker, _blocker_v4, port) = crate::test_ports::hold_ephemeral_udp_port();
    let wg_snapshot = |generation: u64| ConfigSnapshot {
        version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
        generation,
        interfaces: vec![crate::protocol::snapshot::InterfaceSnapshot {
            name: "wgt1866srv".to_string(),
            linux_name: "wgt1866srv".to_string(),
            ifindex: 4250,
            tunnel: true,
            ..Default::default()
        }],
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 1,
            interface: "wgt1866srv".to_string(),
            linux_name: "wgt1866srv".to_string(),
            ifindex: 4250,
            mode: "wireguard".to_string(),
            wg_listen_port: port,
            wg_local_privkey_hex:
                "a01010101010101010101010101010101010101010101010101010101010101a"
                    .to_string(),
            wg_peers: vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
                wg_peer_pubkey_hex:
                    "b02020202020202020202020202020202020202020202020202020202020202b"
                        .to_string(),
                wg_allowed_ips: vec!["10.77.0.0/24".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    // forwarding_armed defaults to false: disarmed throughout.
    let state = new_state(ProcessStatus::default());
    // Apply 1: NOT-same-plan (no previous snapshot) — the disarmed
    // reconcile path stops everything.
    let mut first = req("apply_snapshot");
    first.snapshot = Some(wg_snapshot(1));
    let response = run_request_delivering_wg_secrets(state.clone(), first);
    assert!(response.ok, "first apply: {}", response.error);
    // Apply 2: same-plan — takes the (disarmed) refresh leg.
    let mut second = req("apply_snapshot");
    second.snapshot = Some(wg_snapshot(2));
    let response = run_request_delivering_wg_secrets(state.clone(), second);
    assert!(response.ok, "second apply: {}", response.error);
    let guard = state.lock().expect("state");
    // #9549 precondition: the same-plan refresh must hold a WireGuard engine for
    // this endpoint. Without one the checks below pass vacuously: there is nothing a
    // disarmed helper could spawn, so they cannot see a revert of the #1866 rule.
    // Delivering the private key through the socket is what makes this hold.
    assert_eq!(
        guard.afxdp.wg_engine_count_for_test(),
        1,
        "precondition: the refresh holds no WireGuard engine, so the no-spawn checks below \
         would be vacuous (was the private key dropped on the control socket?)"
    );
    assert!(
        guard.afxdp.wg_control_threads.is_empty(),
        "disarmed helper must hold no WG control entries after a same-plan apply"
    );
    let exceptions = guard
        .afxdp
        .recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .filter(|e| e.reason().contains("wg_bind_listen_port"))
        .count();
    assert_eq!(
        exceptions, 0,
        "disarmed helper must not even attempt a WG bind (no transient spawn)"
    );
}

// --- #2962: owner-RG export must not hold the ServerState lock ----------

/// Fail-on-revert: the owner-RG session export must run its blocking 15 s
/// ack-wait WITHOUT holding the global `ServerState` lock, so a slow/stalled
/// worker cannot freeze the rest of the control plane. This test installs a
/// worker that never acks on its own, kicks an export (which blocks in
/// `wait_and_collect`), and proves a concurrent `status` poll is still served
/// promptly. If the wait runs under the lock again (the bug), the status poll
/// blocks until the ack arrives and this assertion goes RED.
#[test]
fn export_owner_rg_does_not_hold_state_lock_during_ack_wait() {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let state = new_state(ProcessStatus::default());

    // Install a worker whose export ack never advances on its own. A timer
    // thread acks it after 800ms so the export wait stays bounded in BOTH
    // the fixed and the reverted code paths (no 15 s hang on revert).
    let ack = {
        let mut guard = state.lock().expect("lock state");
        guard.afxdp.test_install_export_worker(0)
    };
    let ack_thread = {
        let ack = ack.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(800));
            ack.store(u64::MAX, Ordering::Release);
        })
    };

    // Run the export in the background: it kicks under the lock, releases the
    // lock, then blocks in the ack-wait until the timer thread acks (~800ms).
    let export_state = state.clone();
    let export_thread = std::thread::spawn(move || {
        let mut r = req("export_owner_rg_sessions");
        r.session_export = Some(SessionExportRequest {
            owner_rgs: vec![1],
            max: 0,
            continuation: false,
        });
        run_request(export_state, r)
    });

    // Let the export reach its wait.
    std::thread::sleep(Duration::from_millis(150));

    // The control plane MUST answer a status poll WHILE the export waits.
    // With the lock held across the wait (the #2962 bug) this would block
    // until the 800ms ack releases it (~650ms after t0).
    let t0 = Instant::now();
    let resp = run_request(state.clone(), req("status"));
    let elapsed = t0.elapsed();
    assert!(resp.ok, "status poll failed: {}", resp.error);
    assert!(
        elapsed < Duration::from_millis(400),
        "status poll blocked {elapsed:?} during owner-RG export — \
         ServerState lock held across the ack-wait (#2962 regression)"
    );

    let export_resp = export_thread.join().expect("export thread");
    assert!(export_resp.ok, "export failed: {}", export_resp.error);
    ack_thread.join().expect("ack thread");
}

/// #9344: the CONTROL-SOCKET path from a capped `export_owner_rg_sessions`
/// request to `ControlResponse.session_export_more`, and from
/// `SessionExportRequest.continuation` to a drain that does not re-kick.
///
/// This cell exists because a mutation found the gap: deleting the handler's
/// one `response.session_export_more = more;` assignment left the whole suite
/// GREEN. The Rust unit cells drive `wait_and_collect` directly and the Go
/// cells drive a fake helper that scripts the bit itself, so nothing connected
/// the two — the bit could be computed correctly and never reach the wire.
/// That is the "bind the WIRING, not the function" shape exactly.
#[test]
fn export_owner_rg_sessions_reports_more_and_a_continuation_pages_the_window() {
    use std::sync::atomic::Ordering;

    let state = new_state(ProcessStatus::default());
    let ack = {
        let mut guard = state.lock().expect("lock state");
        let ack = guard.afxdp.test_install_export_worker(0);
        // 5 pending deltas on one binding, against a cap of 3.
        guard.afxdp.test_seed_binding_session_deltas(0, 5);
        ack
    };
    // Ack every sequence up front so neither call blocks on the ack-wait.
    ack.store(u64::MAX, Ordering::Release);

    let mut page1_req = req("export_owner_rg_sessions");
    page1_req.session_export = Some(SessionExportRequest {
        owner_rgs: vec![1],
        max: 3,
        continuation: false,
    });
    let page1 = run_request(state.clone(), page1_req);
    assert!(page1.ok, "page 1 failed: {}", page1.error);
    assert_eq!(
        page1.session_deltas.len(),
        3,
        "page 1 must return exactly the cap"
    );
    assert!(
        page1.session_export_more,
        "the response must CARRY the more-bit. Computing it correctly and not \
         writing it to the wire leaves the caller unable to tell a complete \
         capped answer from a truncated one, which is the whole reason max=0 \
         was the only safe request"
    );

    let mut page2_req = req("export_owner_rg_sessions");
    page2_req.session_export = Some(SessionExportRequest {
        owner_rgs: vec![1],
        max: 3,
        continuation: true,
    });
    let page2 = run_request(state.clone(), page2_req);
    assert!(page2.ok, "page 2 failed: {}", page2.error);
    assert_eq!(
        page2.session_deltas.len(),
        2,
        "the continuation must drain the REMAINDER of the window page 1 opened, \
         not a freshly produced one"
    );
    assert!(
        !page2.session_export_more,
        "the buffers are empty, so the caller must be told to stop"
    );
    assert_eq!(
        page1.session_deltas.len() + page2.session_deltas.len(),
        5,
        "the two pages must partition the window exactly"
    );
}

/// The negative half, and the one that says the more-bit is not simply always
/// true: an UNCAPPED export over the control socket drains everything and
/// reports no remainder.
///
/// Without this arm, `response.session_export_more = true` unconditionally
/// would pass the cell above and send the Go caller into a paging loop that
/// only ends at its page bound.
#[test]
fn export_owner_rg_sessions_uncapped_reports_no_more() {
    use std::sync::atomic::Ordering;

    let state = new_state(ProcessStatus::default());
    let ack = {
        let mut guard = state.lock().expect("lock state");
        let ack = guard.afxdp.test_install_export_worker(0);
        guard.afxdp.test_seed_binding_session_deltas(0, 5);
        ack
    };
    ack.store(u64::MAX, Ordering::Release);

    let mut r = req("export_owner_rg_sessions");
    r.session_export = Some(SessionExportRequest {
        owner_rgs: vec![1],
        max: 0,
        continuation: false,
    });
    let resp = run_request(state, r);
    assert!(resp.ok, "export failed: {}", resp.error);
    assert_eq!(resp.session_deltas.len(), 5, "uncapped drains everything");
    assert!(
        !resp.session_export_more,
        "an uncapped export leaves nothing behind and must never report more"
    );
}

// --- #4054: all-sessions bulk export must not hold the ServerState lock ----

/// Fail-on-revert: the all-sessions bulk export (`export_all_sessions`) must run
/// its (potentially blocking) `push_delta_lossless` serialization WITHOUT
/// holding the global `ServerState` lock, so a large or backpressured bulk
/// export at failover cannot freeze the control plane and self-inflict a
/// needless helper restart. This installs a CONNECTED event stream whose
/// channel holds a single slot and several qualifying local forward sessions,
/// so after the first delta the push loop blocks against the full channel (up
/// to the 5 s lossless-queue timeout). It then proves a concurrent `status`
/// poll is still served promptly. If the push runs under the lock again (the
/// bug), the status poll blocks until the push drains/times out — RED.
#[test]
fn export_all_sessions_does_not_hold_state_lock_during_push() {
    use crate::event_stream::EventStreamSender;
    use std::time::{Duration, Instant};

    let state = new_state(ProcessStatus::default());

    // Connected event stream, single-slot channel: the first pushed delta fills
    // it, and every later delta retries against the full channel. Keep `rx`
    // alive — dropping it disconnects the channel, which makes push fail
    // IMMEDIATELY instead of blocking (and would mask the bug on revert).
    let rx = {
        let mut guard = state.lock().expect("lock state");
        let (sender, rx) = EventStreamSender::test_sender(true, 1);
        guard.afxdp.event_stream = Some(sender);
        for i in 0..4u16 {
            guard.afxdp.test_install_local_forward_session(i);
        }
        rx
    };

    // Kick the bulk export in the background: it snapshots the session set under
    // a BRIEF lock, releases the global ServerState lock, then blocks in the
    // push loop against the full channel.
    let export_state = state.clone();
    let export_thread =
        std::thread::spawn(move || run_request(export_state, req("export_all_sessions")));

    // Let the export reach its (blocked) push.
    std::thread::sleep(Duration::from_millis(150));

    // The control plane MUST answer a status poll WHILE the export's push loop
    // is blocked. With the push under the global lock (the #4054 bug) this
    // blocks until the 5 s lossless timeout releases the lock → RED.
    let t0 = Instant::now();
    let resp = run_request(state.clone(), req("status"));
    let elapsed = t0.elapsed();
    assert!(resp.ok, "status poll failed: {}", resp.error);
    assert!(
        elapsed < Duration::from_millis(1000),
        "status poll blocked {elapsed:?} during all-sessions bulk export — \
         ServerState lock held across push_delta_lossless (#4054 regression)"
    );

    // Drain the channel so the blocked push loop makes progress and the export
    // thread finishes promptly instead of waiting the full 5 s per-delta
    // timeout. Stop once no frame arrives for a short grace period (export done
    // pushing).
    let drainer = std::thread::spawn(move || {
        while rx.recv_timeout(Duration::from_millis(300)).is_ok() {}
    });

    let export_resp = export_thread.join().expect("export thread");
    drainer.join().expect("drainer thread");
    assert!(
        export_resp.ok,
        "bulk export failed: {}",
        export_resp.error
    );
}

/// #3773 (L4): an `update_fabrics` that CHANGES the fabric set must fold the
/// freshly-resolved FabricSnapshots into the STORED snapshot AND persist. The
/// helper starts with `snapshot: None` and never self-restores, so the
/// published state file (read by the Go control plane's `show` surface, and
/// the last-written record a consumer sees) is the observability SSOT. Before
/// #3773 the `update_fabrics` arm neither updated the stored snapshot nor set
/// `persist_state`, so a late-resolved peer/local MAC from the SyncFabricState
/// path lived only in the coordinator's in-memory forwarding state — the
/// persisted fabrics kept the stale apply-time (unresolved) values.
/// fail-on-revert: dropping the snapshot fold + `persist_state` leaves the
/// persisted `snapshot.fabrics` at the empty apply-time set (RED).
#[test]
fn update_fabrics_persists_resolved_fabric_set() {
    use crate::{ConfigSnapshot, FabricSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("fabric-persist");
    // Seed an apply_snapshot with NO fabrics (initial build before the peer
    // MAC resolved). This persists the state file with an empty fabric set.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 1,
            generated_at: chrono::Utc::now(),
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // SyncFabricState resolves a peer MAC and pushes it via update_fabrics.
    let resolved = FabricSnapshot {
        parent_unbindable: false,
        name: "fab0".into(),
        parent_interface: "ge-0/0/0".into(),
        parent_linux_name: "ge-0-0-0".into(),
        parent_ifindex: 21,
        overlay_linux_name: "fab0".into(),
        overlay_ifindex: 101,
        rx_queues: 2,
        peer_address: "10.99.13.2".into(),
        local_mac: "02:bf:72:ff:00:01".into(),
        peer_mac: "00:aa:bb:cc:dd:ee".into(),
        up: true,
    };
    {
        let mut request = req("update_fabrics");
        request.fabrics = Some(vec![resolved.clone()]);
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    // The stored (in-RAM) snapshot must now carry the resolved fabric.
    assert_eq!(
        state
            .lock()
            .expect("state")
            .snapshot
            .as_ref()
            .expect("stored snapshot")
            .fabrics,
        vec![resolved.clone()],
        "update_fabrics must fold the resolved fabric into the stored snapshot"
    );
    // The on-disk state a `show` reads (and the last record a restart-time
    // consumer sees) must carry the resolved peer MAC, not the empty
    // apply-time set.
    let bytes = std::fs::read(&state_file).expect("read persisted state file");
    let persisted: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse persisted state file");
    assert_eq!(
        persisted["snapshot"]["fabrics"][0]["peer_mac"].as_str(),
        Some("00:aa:bb:cc:dd:ee"),
        "persisted snapshot must carry the resolved fabric peer MAC (#3773 L4)"
    );
    let _ = std::fs::remove_file(&state_file);
}

/// #3773 (L4): an `update_fabrics` whose fabric set is UNCHANGED from the
/// stored snapshot must NOT rewrite the state file — the 30s periodic
/// SyncFabricState refresh must not churn the disk on every unchanged tick.
#[test]
fn update_fabrics_unchanged_set_does_not_rewrite_state_file() {
    use crate::{ConfigSnapshot, FabricSnapshot, CONFIG_SNAPSHOT_PROTOCOL_VERSION};
    let resolved = FabricSnapshot {
        parent_unbindable: false,
        name: "fab0".into(),
        parent_interface: "ge-0/0/0".into(),
        parent_linux_name: "ge-0-0-0".into(),
        parent_ifindex: 21,
        overlay_linux_name: "fab0".into(),
        overlay_ifindex: 101,
        rx_queues: 2,
        peer_address: "10.99.13.2".into(),
        local_mac: "02:bf:72:ff:00:01".into(),
        peer_mac: "00:aa:bb:cc:dd:ee".into(),
        up: true,
    };
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("fabric-nochurn");
    // Seed a snapshot that ALREADY carries the resolved fabric.
    {
        let mut request = req("apply_snapshot");
        request.snapshot = Some(ConfigSnapshot {
            version: CONFIG_SNAPSHOT_PROTOCOL_VERSION,
            generation: 1,
            fib_generation: 1,
            generated_at: chrono::Utc::now(),
            fabrics: vec![resolved.clone()],
            ..ConfigSnapshot::default()
        });
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    let before = std::fs::metadata(&state_file)
        .expect("state file exists after seed apply")
        .modified()
        .expect("mtime");
    // A same-set update_fabrics: nothing changed, so no rewrite.
    std::thread::sleep(std::time::Duration::from_millis(10));
    {
        let mut request = req("update_fabrics");
        request.fabrics = Some(vec![resolved.clone()]);
        assert!(run_request_on_file(state.clone(), request, &state_file).ok);
    }
    let after = std::fs::metadata(&state_file)
        .expect("state file still exists")
        .modified()
        .expect("mtime");
    assert_eq!(
        before, after,
        "an unchanged update_fabrics must not rewrite the state file"
    );
    let _ = std::fs::remove_file(&state_file);
}

/// #5469 fail-on-revert: `write_state` must hold the `ServerState` lock ONLY
/// long enough to refresh status and clone the owned payload — the expensive
/// serialization and the `persist` fsync must run with the lock RELEASED. The
/// pre-persist probe records, on `write_state`'s own thread, whether the lock
/// was free at the persist point (std `Mutex` is non-reentrant, so a same-thread
/// `try_lock` succeeds only if the guard was dropped). Revert the guard back
/// across `persist` (the lock-convoy bug) and the probe records `false`, turning
/// this test RED.
#[test]
fn write_state_releases_lock_before_persist() {
    let state = new_state(ProcessStatus::default());
    let state_file = unique_state_file("lock-free-persist");
    clear_pre_persist_lock_probe();
    write_state(&state_file, &state).expect("write_state must succeed");
    let lock_free =
        take_pre_persist_lock_free().expect("write_state must run the pre-persist lock probe");
    assert!(
        lock_free,
        "write_state must drop the ServerState guard before serialization + persist (#5469)"
    );
    let _ = std::fs::remove_file(&state_file);
}

// #4565: a peer-PROMOTED NAT64 session must rebuild its RFC 6146 reverse BIB
// from the wire-carried translated pool source (`nat64_snat_v4`) + the synced
// forward v6 key. Before #4565 `build_synced_session_entry` set `nat64: false`
// and `nat64_reverse: None`, so a promoted NAT64 session (a) never reached the
// NAT64 frame builder (tx dispatch keys `is_nat64` off `nat.nat64`), (b) could
// not translate the v4 reply back to IPv6 (the frame builder hard-requires
// `nat64_reverse`), and (c) synthesized a WRONG (v6-family) reverse companion
// key so the server's v4 reply never matched. RED-on-revert: dropping the
// helpers.rs reconstruction makes every NAT64 assertion below fail.
#[test]
fn nat64_synced_entry_rebuilds_reverse_bib_4565() {
    use crate::nat64::Nat64ReverseInfo;
    use crate::session::reverse_session_key;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let zones = rustc_hash::FxHashMap::default();

    // NAT64 forward flow: v6 client -> synthetic 64:ff9b::192.168.1.1
    // (dst_v4 = 192.168.1.1 by RFC 6052 /96), translated to pool source
    // 203.0.113.5:40000 on the active node.
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET6 as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "2001:db8::1".to_string(),
        dst_ip: "64:ff9b::c0a8:101".to_string(),
        src_port: 5001,
        dst_port: 80,
        ingress_zone_id: 2,
        egress_zone_id: 3,
        egress_ifindex: 12,
        // The generic NAT fields carry the mangled cross-family remnants on the
        // real wire; the NAT64 path must OVERRIDE them from nat64_snat_v4.
        nat_src_ip: "2001:db8:dead:beef::".to_string(),
        nat_src_port: 40000,
        nat64_snat_v4: "203.0.113.5".to_string(),
        ..SessionSyncRequest::default()
    };
    let entry = build_synced_session_entry(&req, &zones, 0).expect("build nat64 entry");

    // (a) NAT64 cross-family bit set -> tx dispatch reverse-translates + #4564
    // reserve arms.
    assert!(entry.decision.nat.nat64, "nat64 bit must be set");
    // (b) forward NAT decision rebuilt to the v4 pool binding (NOT the mangled
    // generic nat_src).
    assert_eq!(
        entry.decision.nat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
        "rewrite_src must be the translated pool source snat_v4"
    );
    assert_eq!(
        entry.decision.nat.rewrite_dst,
        Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        "rewrite_dst must be the /96-embedded v4 destination"
    );
    assert_eq!(
        entry.decision.nat.rewrite_src_port,
        Some(40000),
        "translated port rides nat_src_port"
    );
    // (c) original v6 src/dst captured for the reverse (v4->v6) translation.
    assert_eq!(
        entry.metadata.nat64_reverse,
        Some(Nat64ReverseInfo {
            orig_src_v6: "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            orig_dst_v6: "64:ff9b::c0a8:101".parse::<Ipv6Addr>().unwrap(),
        }),
        "nat64_reverse must carry the original v6 endpoints"
    );

    // (d) the synthesized reverse companion key is the v4 reply tuple
    // (server_v4 -> snat_v4), so the server's IPv4 reply matches after failover.
    let rk = reverse_session_key(&entry.key, entry.decision.nat);
    assert_eq!(rk.addr_family, libc::AF_INET as u8, "reverse key must be v4");
    assert_eq!(rk.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(rk.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
    assert_eq!(rk.dst_port, 40000, "reply dst port is the translated port");

    // A non-NAT64 synced session (empty nat64_snat_v4) is unaffected: no nat64
    // bit, no reverse info, generic nat_src preserved.
    let plain = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 1234,
        dst_port: 80,
        ingress_zone_id: 2,
        egress_zone_id: 3,
        egress_ifindex: 12,
        nat_src_ip: "203.0.113.9".to_string(),
        nat_src_port: 50000,
        ..SessionSyncRequest::default()
    };
    let plain_entry = build_synced_session_entry(&plain, &zones, 0).expect("build plain entry");
    assert!(!plain_entry.decision.nat.nat64, "non-nat64 stays non-nat64");
    assert_eq!(plain_entry.metadata.nat64_reverse, None);
    assert_eq!(
        plain_entry.decision.nat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
        "non-nat64 keeps the generic SNAT source"
    );
}

// --- #5864: authoritative empty NeighborReplace clears the table --------

/// Seed exactly one publishable manager neighbor through the real
/// `update_neighbors` handler path and return the driven state.
fn seed_one_manager_neighbor() -> Arc<Mutex<ServerState>> {
    let state = new_state(ProcessStatus::default());
    let mut seed = req("update_neighbors");
    seed.neighbor_replace = true;
    seed.neighbors = Some(vec![crate::NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 7,
        family: "inet".to_string(),
        ip: "10.0.0.1".to_string(),
        mac: "02:00:00:00:00:01".to_string(),
        state: "REACHABLE".to_string(),
        ..crate::NeighborSnapshot::default()
    }]);
    let resp = run_request(state.clone(), seed);
    assert!(resp.ok, "seed update_neighbors failed: {}", resp.error);
    assert_eq!(
        state
            .lock()
            .expect("state")
            .afxdp
            .dynamic_neighbor_status()
            .0,
        1,
        "seed must install exactly one manager neighbor"
    );
    state
}

/// #5864 fail-on-revert: an authoritative NeighborReplace with the field
/// ABSENT on the wire (Go drops the empty slice under omitempty →
/// neighbors=None) must CLEAR the manager-neighbor table, not early-return
/// and leave the stale entry installed. Reverting the None/empty handling
/// in `handlers::neighbors::update` (restoring `let Some(..) else return`)
/// makes the final assertion go RED — the stale neighbor survives.
#[test]
fn update_neighbors_absent_replace_clears_table_5864() {
    let state = seed_one_manager_neighbor();

    let mut clear = req("update_neighbors");
    clear.neighbor_replace = true;
    clear.neighbors = None;
    let resp = run_request(state.clone(), clear);
    assert!(resp.ok, "empty replace failed: {}", resp.error);

    assert_eq!(
        state
            .lock()
            .expect("state")
            .afxdp
            .dynamic_neighbor_status()
            .0,
        0,
        "authoritative replace with neighbors=None must clear the table"
    );
}

/// #5864 companion: an explicit present-but-empty slice (the post-fix Go
/// wire, `\"neighbors\":[]`) under NeighborReplace must clear identically.
#[test]
fn update_neighbors_explicit_empty_replace_clears_table_5864() {
    let state = seed_one_manager_neighbor();

    let mut clear = req("update_neighbors");
    clear.neighbor_replace = true;
    clear.neighbors = Some(Vec::new());
    let resp = run_request(state.clone(), clear);
    assert!(resp.ok, "empty-slice replace failed: {}", resp.error);

    assert_eq!(
        state
            .lock()
            .expect("state")
            .afxdp
            .dynamic_neighbor_status()
            .0,
        0,
        "authoritative replace with neighbors=[] must clear the table"
    );
}

/// #5864 guard: a NON-replace update with no neighbors must remain a
/// no-op — it carries nothing to add and must NOT touch the existing
/// table. Guards against the clear-on-empty fix over-reaching into the
/// (defensive) non-replace path.
#[test]
fn update_neighbors_none_without_replace_is_noop_5864() {
    let state = seed_one_manager_neighbor();

    let mut noop = req("update_neighbors");
    noop.neighbor_replace = false;
    noop.neighbors = None;
    let resp = run_request(state.clone(), noop);
    assert!(resp.ok, "noop update failed: {}", resp.error);

    assert_eq!(
        state
            .lock()
            .expect("state")
            .afxdp
            .dynamic_neighbor_status()
            .0,
        1,
        "non-replace update with no neighbors must not clear the table"
    );
}

// -------------------------------------------------------------
// #5294: a state-file write failure must NOT lose a drained
// session-delta batch (pop-then-fallible-write transactionality).
// -------------------------------------------------------------

/// #5294 fail-on-revert: `drain_session_deltas` DESTRUCTIVELY pops deltas out of
/// the per-binding RPC-fallback buffers into `response.session_deltas` and marks
/// `persist_state`. With the pre-#5294 pop-then-fallible-write order — the
/// dispatcher ran `write_state(...)?` BEFORE encoding the response — a local
/// state-file write error short-circuited the send via `?`: the deltas were
/// already gone from the queue yet never reached the peer AND were not persisted,
/// a PERMANENT HA session divergence (the standby never learns those open/close
/// events, the local copy is lost, and no loss-of-sync latch is armed for a
/// write_state failure). The fix always encodes+flushes the response (carrying
/// the drained deltas) BEFORE surfacing a persist error, so the peer still
/// receives every drained delta.
///
/// The owner-RG export mirror (`export_owner_rg_sessions` → `owner_rg_collect`)
/// populates `response.session_deltas` + `persist_state` and flows through the
/// SAME dispatcher tail, so this single test pins both paths.
///
/// Reverting the dispatcher to `write_state(state_file, &state)?` before the send
/// makes the handler return Err with NOTHING written, so the client read below
/// hits EOF and the decode `expect` panics — the RED signal.
#[test]
fn drain_session_deltas_survive_write_state_failure_5294() {
    let mut coord = afxdp::Coordinator::new();
    coord.seed_pending_session_deltas_for_test(0, 5);
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus::default(),
        snapshot: None,
        afxdp: coord,
        state_writer: Arc::new(StateWriter::new()),
    }));

    // A state_file inside a directory that does not exist makes write_state's
    // temp-file open fail => write_state returns Err (the local state-file
    // problem the bug is about), while the ServerState stays otherwise healthy.
    let bad_state_file = format!(
        "/nonexistent-xpf-5294-dir-{}/state.json",
        std::process::id()
    );

    let mut request = req("drain_session_deltas");
    request.session_deltas = Some(crate::SessionDeltaDrainRequest { max: 256 });

    let (mut client, server) =
        std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let handle = {
        let bad = bad_state_file.clone();
        {
            let sd = state.lock().expect("state").afxdp.session_domain().clone();
            std::thread::spawn(move || handle_stream(server, &bad, state, running, sd))
        }
    };

    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    // The response MUST be delivered even though the persist will fail. On the
    // pre-#5294 pop-then-fallible-write order the handler returns Err before
    // writing anything, so this read hits EOF and the decode fails — the RED
    // signal that a drained delta batch was silently lost.
    let response: ControlResponse = serde_json::from_reader(std::io::BufReader::new(&client))
        .expect("drained deltas must reach the peer despite the write_state failure (#5294)");

    let handler_result = handle.join().expect("handler thread");

    // Test premise: write_state actually failed (else we would not be exercising
    // the failure path at all). The error is surfaced to the accept loop, but
    // only AFTER the response was flushed.
    let err = handler_result.expect_err("write_state must fail on a missing state dir");
    assert!(
        err.contains("write state file"),
        "expected a state-file persist error, got: {err}"
    );

    // The deltas were NOT lost: every drained delta reached the peer.
    assert!(response.ok, "drained-batch response must report ok");
    assert_eq!(
        response.session_deltas.len(),
        5,
        "all 5 drained deltas must reach the peer even though the persist failed \
         — the pre-#5294 pop-then-fallible-write order dropped the whole batch"
    );
}

// ---------------------------------------------------------------------------
// #3651 / #6938: the flood-counter PRODUCTION call sites, not the helpers.
//
// The helpers were already exhaustively covered — `flush_recorded_flood_counters`
// has 13 call sites across flood_counters.rs, tests_slow_path_disposition.rs,
// forwarding_build/tests.rs and coordinator/tests.rs, and every one of them
// calls it DIRECTLY. What nothing observed was production calling it. Measured
// on this head: deleting the worker-loop fold at
// afxdp/worker/loop_body/mod.rs:1095, or replacing the publication at
// server/helpers/status.rs:320 with an empty vec, each left the whole
// userspace-dp suite at 4256 passed / 0 failed — byte-identical to baseline.
//
// The tests below close the publication and clear links by driving the REAL
// control-socket dispatcher (`handle_stream` via `run_request`), which is what
// the daemon's accept loop calls, so the assertion rides `refresh_status`'s own
// use of the coordinator rather than calling the coordinator itself.
//
// The worker-loop fold is not reachable this way — `worker_loop` takes five
// heavyweight parameters and is spawned only from coordinator bringup with real
// AF_XDP sockets — so it is pinned structurally in
// `flood_fold_is_wired_into_the_worker_loop_6938` below, and that limitation is
// stated rather than papered over.

/// Seed a coordinator so one zone holds a recorded flood event, exactly as a
/// worker would leave it after `record_zone_flood_drop` + a flush.
fn seed_flood_counter(coord: &mut afxdp::Coordinator, zone: u16, name: &str) {
    coord.seed_flood_counter_for_test(zone, name);
}

/// The status REFRESH must publish the coordinator's flood rows onto the wire
/// status. Binds server/helpers/status.rs's call, not Coordinator::zone_flood_counters.
///
/// RED on revert: replace that line with `Vec::new()` (or delete it) and this
/// fails — the request still succeeds and every other server test stays green,
/// which is exactly how the gap survived.
#[test]
fn status_refresh_publishes_flood_counters_6938() {
    const Z: u16 = 50675; // config::StableZoneID("trust")

    let state = new_state(ProcessStatus::default());
    {
        let mut guard = state.lock().expect("state");
        seed_flood_counter(&mut guard.afxdp, Z, "trust");
        // Precondition: the wire status starts EMPTY, so a pass cannot be
        // explained by the fixture having pre-populated it.
        assert!(
            guard.status.zone_flood_counters.is_empty(),
            "fixture invalid: status already carried flood rows before any refresh"
        );
    }

    // `ping` is the minimal REAL verb: the dispatcher's post-match block runs
    // refresh_status for every non-export request and attaches the result, so
    // this rides the production path without needing a status-specific verb.
    let response = run_request(state.clone(), req("ping"));
    assert!(response.ok, "ping failed: {}", response.error);

    // Assert on the WIRE payload the daemon actually returns, not only on the
    // in-memory state: the attach is the half an operator sees.
    let wire = response.status.expect("dispatcher attached no status to the reply");
    assert!(
        wire.zone_flood_counters.iter().any(|r| r.zone_id == Z),
        "the reply's status carries no flood row for zone {Z}: {:?}",
        wire.zone_flood_counters
    );

    let guard = state.lock().expect("state");
    let rows = &guard.status.zone_flood_counters;
    assert!(
        !rows.is_empty(),
        "refresh_status published NO flood rows although the coordinator holds one \
         for zone {Z}. The publication line in server/helpers/status.rs is not \
         reached — deleting it is invisible to every other test because they all \
         call Coordinator::zone_flood_counters directly (#6938)"
    );
    assert!(
        rows.iter().any(|r| r.zone_id == Z),
        "flood rows published but zone {Z} is not among them: {rows:?}"
    );
}

/// The operator clear must reach the helper's cumulative store, not just the
/// Go-side offset map. Binds the `clear_flood_counters` handler arm.
///
/// RED on revert: delete `guard.afxdp.clear_flood_counters();` from
/// server/handlers/mod.rs and this fails — the request still returns ok, which
/// is the whole failure mode (a clear that reports success and snaps back
/// within one poll).
#[test]
fn clear_flood_counters_request_empties_the_store_6938() {
    const Z: u16 = 50675;

    let state = new_state(ProcessStatus::default());
    {
        let mut guard = state.lock().expect("state");
        seed_flood_counter(&mut guard.afxdp, Z, "trust");
    }

    // Control: the row is published BEFORE the clear, so a post-clear absence
    // cannot be explained by it never having been there.
    let before = run_request(state.clone(), req("ping"));
    assert!(before.ok, "ping failed: {}", before.error);
    assert!(
        state
            .lock()
            .expect("state")
            .status
            .zone_flood_counters
            .iter()
            .any(|r| r.zone_id == Z),
        "control failed: zone {Z} was not published before the clear, so the \
         assertion after it would prove nothing"
    );

    let cleared = run_request(state.clone(), req("clear_flood_counters"));
    assert!(cleared.ok, "clear_flood_counters failed: {}", cleared.error);

    let guard = state.lock().expect("state");
    assert!(
        !guard.status.zone_flood_counters.iter().any(|r| r.zone_id == Z),
        "zone {Z} still publishes a flood row after `clear_flood_counters`. The \
         handler's clear_flood_counters() call does not reach the helper's \
         cumulative store, so the operator's clear is undone by the next 1 s \
         status poll (#6938)"
    );
}

/// The per-RX-batch fold is on the worker loop's own path.
///
/// STRUCTURAL, and deliberately so: `worker_loop` takes five heavyweight
/// parameters (`WorkerLaunchPlan`, `WorkerSharedDataplane`, ...) and is spawned
/// only from `coordinator/reconcile/bringup.rs` against real AF_XDP sockets, so
/// no test can drive it. A source pin is the honest instrument for a claim that
/// is itself syntactic — "the loop body calls this" — and it is what the sibling
/// traffic-counter fold lacks.
///
/// It asserts the fold sits alongside `flush_recorded_zone_counters`, because
/// the comment's load-bearing claim is that the two share a cadence and a
/// `forwarding` snapshot: separating them would silently fold the two counter
/// families against different slot maps.
#[test]
fn flood_fold_is_wired_into_the_worker_loop_6938() {
    let src = include_str!("../afxdp/worker/loop_body/mod.rs");
    let fold = "crate::afxdp::flood_counters::flush_recorded_flood_counters(";
    let sibling = "crate::afxdp::zone_counters::flush_recorded_zone_counters(";

    let fold_at = src.find(fold).unwrap_or_else(|| {
        panic!(
            "the worker loop does not call flush_recorded_flood_counters. Every \
             recorded flood event stays in the per-worker cache and the shared \
             store reads zero forever — and no behavioural test sees it, because \
             all 13 of the helper's other call sites are tests calling it \
             directly (#6938)"
        )
    });
    let sibling_at = src.find(sibling).unwrap_or_else(|| {
        panic!("the worker loop no longer calls flush_recorded_zone_counters — this \
                guard's adjacency claim names a sibling that is gone")
    });
    assert!(
        fold_at > sibling_at && fold_at - sibling_at < 800,
        "the flood fold is no longer adjacent to the zone-counter fold \
         (offsets {sibling_at} vs {fold_at}). They must share one cadence and one \
         `forwarding` snapshot, or the two counter families fold against \
         different slot maps (#6938)"
    );
}

/// OVER-REACH CONTROL for `flood_fold_is_wired_into_the_worker_loop_6938`.
///
/// Its own test body deliberately: a control sharing a body with its binder
/// never runs once the binder fails, so it would be silent in exactly the
/// situation it exists to describe.
///
/// The risk it guards is the guard being WIDENED. The binder searches for the
/// flood-specific symbol; loosening it to "some flush happened" — matching
/// `flush_recorded_` and catching the SIBLING zone-counter fold on the line
/// above — would keep the binder green with the flood fold deleted, which is
/// the failure the binder exists to catch. The two folds sit four lines apart,
/// so that widening is a plausible edit, not a contrived one.
///
/// This runs the binder's own matching logic against a synthetic body that
/// contains ONLY the sibling, and requires it to find nothing. It is
/// independent of the production file, so it stays GREEN when the production
/// flood line is deleted — which is what makes it a control rather than a
/// second copy of the binder.
#[test]
fn flood_fold_guard_does_not_accept_the_sibling_fold_6938() {
    const SIBLING_ONLY: &str = r#"
        crate::afxdp::zone_counters::flush_recorded_zone_counters(
            &forwarding.zone_counter_store,
            &forwarding.zone_counter_slot_map,
        );
    "#;
    let fold = "crate::afxdp::flood_counters::flush_recorded_flood_counters(";
    assert!(
        SIBLING_ONLY.find(fold).is_none(),
        "the flood-fold guard matches a body containing ONLY the zone-counter \
         fold, so it would report the flood fold as wired after that line was \
         deleted. The guard must name the flood-counter symbol, not any flush \
         (#6938)"
    );

    // And the converse, so this control cannot pass by matching nothing ever:
    // the binder's needle MUST be found in a body that does contain it.
    const FLOOD_PRESENT: &str = r#"
        crate::afxdp::flood_counters::flush_recorded_flood_counters(
            &forwarding.flood_counter_store,
            &forwarding.flood_counter_slot_map,
        );
    "#;
    assert!(
        FLOOD_PRESENT.find(fold).is_some(),
        "the guard's needle does not match even a body that plainly contains the \
         call — the binder is searching for something unreachable and would pass \
         nothing, ever"
    );
}


/// #6983: the zone-TRAFFIC status publication, the twin of
/// `status_refresh_publishes_flood_counters_6938` above.
///
/// WHAT THE ISSUE GOT RIGHT AND WHAT IT GOT WRONG, both measured on this
/// branch. #6983 says the worker-loop zone fold "can be severed and nothing
/// reds". That half is FALSE at this head: deleting
/// `crate::afxdp::zone_counters::flush_recorded_zone_counters(...)` from the
/// loop reds `flood_fold_is_wired_into_the_worker_loop_6938`, whose adjacency
/// assertion looks the zone fold up as its sibling and panics with "the worker
/// loop no longer calls flush_recorded_zone_counters". So that property is
/// already owned, incidentally, and this file does NOT add a second pin for it.
///
/// The PUBLICATION half is the real gap and it is exactly the shape #6938
/// closed for flood: replacing `state.afxdp.zone_traffic_counters()` at
/// server/helpers/status.rs with `Vec::new()` left the entire crate green
/// (4722 passed / 0 failed). `Coordinator::zone_traffic_counters` itself is
/// well covered (#6843 binds the accessor's slot-loss filtering), and that is
/// precisely why the gap survived: every one of those tests calls the accessor
/// DIRECTLY, so none of them observes `refresh_status` calling it.
///
/// Rides the REAL control-socket dispatcher (`handle_stream` via
/// `run_request`), like its flood twin — `ping` is the minimal real verb,
/// because the dispatcher's post-match block runs `refresh_status` for every
/// non-export request.
///
/// RED on revert: replace that line with `Vec::new()` (or delete it) and this
/// fails while the request still succeeds and every other test stays green,
/// which is exactly how the gap survived.
#[test]
fn status_refresh_publishes_zone_traffic_counters_6983() {
    const Z: u16 = 50675; // config::StableZoneID("trust")
    const BYTES: u64 = 1500;

    let state = new_state(ProcessStatus::default());
    {
        let mut guard = state.lock().expect("state");
        guard.afxdp.seed_zone_traffic_counter_for_test(Z, "trust", BYTES);
        // Precondition: the wire status starts EMPTY, so a pass cannot be
        // explained by the fixture having pre-populated it.
        assert!(
            guard.status.zone_traffic_counters.is_empty(),
            "fixture invalid: status already carried zone-traffic rows before any refresh"
        );
    }

    let response = run_request(state.clone(), req("ping"));
    assert!(response.ok, "ping failed: {}", response.error);

    // Assert on the WIRE payload the daemon actually returns: the attach is the
    // half an operator sees.
    let wire = response
        .status
        .expect("dispatcher attached no status to the reply");
    let row = wire
        .zone_traffic_counters
        .iter()
        .find(|r| r.zone_id == Z)
        .unwrap_or_else(|| {
            panic!(
                "the reply's status carries no zone-traffic row for zone {Z}: {:?}. \
                 refresh_status is not publishing the coordinator's rows, so every \
                 per-zone byte and packet an operator reads is zero while forwarding \
                 is perfectly healthy (#6983)",
                wire.zone_traffic_counters
            )
        });

    // The VALUE, not merely the row's presence. A publication that attached an
    // empty-but-present row, or the wrong zone's totals, would satisfy an
    // existence check — and existence standing in for content is the failure
    // this whole family of issues is about.
    assert!(
        row.ingress_bytes >= BYTES,
        "zone {Z} publishes {} ingress bytes, expected at least the {BYTES} the \
         fixture recorded: the row reaches the wire but its totals do not (#6983)",
        row.ingress_bytes
    );
}

/// #6971: the two per-publish-tick counter refreshes in `worker_loop`.
///
/// Measured on this branch's mutation matrix: deleting EITHER line left the
/// whole userspace-dp suite at 4850 collected / 0 failed. The callee arithmetic
/// is now covered on both sides (`afxdp/worker/mod.rs` tests, one of which this
/// branch adds), but a bound callee says nothing about production still calling
/// it — which is the entire defect class here.
///
/// STRUCTURAL for the #6938 reason, unchanged: nothing drives `worker_loop`.
///
/// THE TICK ADJACENCY IS PART OF THE CLAIM, not decoration. Both refreshes must
/// sit INSIDE the `WR_PUBLISH_INTERVAL_NS` block. Above it they would run every
/// loop iteration — a per-packet-batch sum over every binding on the hot path,
/// which is what the ~1 s cadence exists to avoid; in the per-RX-batch section
/// ~32 KB further down they would leave the publish tick reading stale values.
/// So the pin asserts position relative to the tick guard, not mere presence.
#[test]
fn worker_loop_refreshes_publish_tick_counters_6971() {
    let src = include_str!("../afxdp/worker/loop_body/mod.rs");
    let tick = "if loop_now_ns.saturating_sub(wr_last_publish_ns) >= WR_PUBLISH_INTERVAL_NS {";
    let cos = "refresh_worker_cos_queue_lease_runtime_counters(&mut wr_counters, &bindings);";
    let newflow = "refresh_worker_new_flow_install_counters(&mut wr_counters, &bindings);";

    let tick_at = src.find(tick).unwrap_or_else(|| {
        panic!(
            "the worker loop's publish-tick guard is gone — this guard's position \
             claim is anchored to a line that no longer exists (#6971)"
        )
    });
    for (needle, what, why) in [
        (
            cos,
            "refresh_worker_cos_queue_lease_runtime_counters",
            "the #1782 CoS lease / wheel-catch-up / under-grant counters stay at \
             zero on the wire for every worker, so the per-cause under-grant \
             attribution an operator uses to tell a shaping ceiling from a \
             misconfiguration reports nothing at all",
        ),
        (
            newflow,
            "refresh_worker_new_flow_install_counters",
            "the per-worker `new_flow_installs` wire field pins at 0, and BOTH \
             #4800 cross-worker analyzer gates key on that series — \
             `active_workers < 3` and `max_worker_share > 0.60` — so the ceiling \
             analyzer silently stops discriminating and reports a ceiling with a \
             dead distribution input",
        ),
    ] {
        let at = src.find(needle).unwrap_or_else(|| {
            panic!("the worker loop does not call {what}: {why} (#6971)")
        });
        assert!(
            at > tick_at,
            "{what} is called BEFORE the publish-tick guard (offset {at} vs \
             {tick_at}), so it runs on every loop iteration instead of once per \
             ~1 s tick — a per-binding sum moved onto the hot path (#6971)"
        );
        assert!(
            at - tick_at < 2500,
            "{what} is {} bytes past the publish-tick guard, far enough that it \
             is no longer inside that block — it would then run at a different \
             cadence than the counters published alongside it (#6971)",
            at - tick_at
        );
    }
}

/// OVER-REACH CONTROL for `worker_loop_refreshes_publish_tick_counters_6971`.
///
/// Own body, same reason as the two controls above.
///
/// The plausible widening here is a shared prefix: both refreshes begin
/// `refresh_worker_`, and they sit eleven lines apart, so a needle trimmed to
/// that prefix would match the SIBLING and report a deleted refresh as wired.
/// This runs each of the binder's two needles against a body containing only
/// the other, and requires no match — then the converse, so the control cannot
/// pass by matching nothing ever.
#[test]
fn publish_tick_refresh_guard_does_not_accept_its_sibling_6971() {
    const COS_ONLY: &str =
        "refresh_worker_cos_queue_lease_runtime_counters(&mut wr_counters, &bindings);";
    const NEWFLOW_ONLY: &str =
        "refresh_worker_new_flow_install_counters(&mut wr_counters, &bindings);";

    assert!(
        COS_ONLY.find(NEWFLOW_ONLY).is_none(),
        "the new-flow needle matches a body containing ONLY the CoS refresh, so \
         the binder would report the new-flow refresh as wired after that line \
         was deleted (#6971)"
    );
    assert!(
        NEWFLOW_ONLY.find(COS_ONLY).is_none(),
        "the CoS needle matches a body containing ONLY the new-flow refresh, so \
         the binder would report the CoS refresh as wired after that line was \
         deleted (#6971)"
    );
    assert!(
        COS_ONLY.find(COS_ONLY).is_some() && NEWFLOW_ONLY.find(NEWFLOW_ONLY).is_some(),
        "a needle does not match even a body that plainly contains it — the \
         binder is searching for something unreachable and would pass nothing, \
         ever"
    );
}

/// #5189 (A1-b8-F5): the ~1 s report tick must not build its diagnostics
/// string in a RELEASE build.
///
/// STRUCTURAL, and for the same reason the #6938 fold pin above is: `worker_loop`
/// takes five heavyweight parameters and is spawned only from
/// `coordinator/reconcile/bringup.rs` against real AF_XDP sockets, so no test can
/// drive it. And the property is itself syntactic — "this work is compiled out
/// unless the feature is on" — with no black-box observation available: the
/// summary is a `String` nobody reads and two `getsockopt`s whose results are
/// discarded, so a release build behaves identically apart from cost.
///
/// What went wrong: #1776 moved the report tick's `eprintln!` into the
/// `#[cfg(feature = "debug-log")]` module `debug_report`, but deliberately left
/// the `binding_summary` BUILD inline in `mod.rs`, ungated. Release builds
/// therefore paid, per worker per second: a heap `String` plus every `write!`
/// that grows it, one `statistics_v2()` (`XDP_STATISTICS` `getsockopt`) per
/// binding, and one `SO_ERROR` `getsockopt` per binding — for a value whose only
/// consumer (`emit_periodic_report`) was compiled out.
///
/// The binder pins the exact post-fix shape: the build is a call into the gated
/// module, and the call itself carries the cfg attribute. Reverting the block
/// inline drops the call line → RED. Dropping the cfg attribute → RED (and, as a
/// second line of defence, a hard compile error in the default build, because
/// `debug_report` does not exist without the feature).
#[test]
fn report_tick_summary_is_not_built_in_release_5189() {
    let src = include_str!("../afxdp/worker/loop_body/mod.rs");
    assert!(
        report_tick_summary_build_is_gated(src),
        "the ~1s report tick's `binding_summary` build is no longer a cfg-gated \
         call into `debug_report`. Release builds are back to allocating a \
         String and issuing a statistics_v2 + SO_ERROR getsockopt per binding \
         per second for a value nothing reads (#5189 A1-b8-F5)"
    );

    // The syscalls must have MOVED into the gated module, not been deleted:
    // under `--features debug-log` the summary still has to carry them.
    let gated = include_str!("../afxdp/worker/loop_body/debug_report.rs");
    assert!(
        gated.contains("pub(super) fn build_binding_summary("),
        "debug_report.rs no longer owns the binding-summary build"
    );
    for needle in ["statistics_v2()", "libc::SO_ERROR", "FRAME_LEAK"] {
        assert!(
            gated.contains(needle),
            "`{needle}` vanished from the gated summary build — the release-build \
             cost was removed by DELETING the diagnostic rather than by gating \
             it, so `--features debug-log` lost coverage it used to have"
        );
    }
}

/// The binder's matching logic, factored out so the control below can run it
/// against a synthetic pre-fix body without re-implementing it (a re-implemented
/// matcher is a second binder, not a control).
///
/// True iff the file binds `binding_summary` exactly once, from a call into the
/// gated `debug_report` module, on a line whose immediately preceding
/// non-blank line is the `debug-log` cfg attribute.
fn report_tick_summary_build_is_gated(src: &str) -> bool {
    let lines: Vec<&str> = src.lines().collect();
    let mut bindings = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim_start().starts_with("let ") && l.contains("binding_summary"));
    let Some((idx, line)) = bindings.next() else {
        return false;
    };
    if bindings.next().is_some() {
        return false;
    }
    if !line.contains("debug_report::build_binding_summary(") {
        return false;
    }
    lines[..idx]
        .iter()
        .rev()
        .find(|l| !l.trim().is_empty())
        .is_some_and(|prev| prev.trim() == r#"#[cfg(feature = "debug-log")]"#)
}

/// OVER-REACH / VACUITY CONTROL for `report_tick_summary_is_not_built_in_release_5189`.
///
/// Its own test body deliberately: a control sharing a body with its binder
/// never runs once the binder fails, so it would be silent in exactly the
/// situation it exists to describe.
///
/// It runs the binder's OWN matcher against the pre-fix source shape — the
/// ungated `let mut binding_summary = String::new();` #1776 left inline — and
/// requires it to REJECT. Without this, a matcher that returned `true` for
/// everything (or that searched for a needle present in both shapes) would keep
/// the binder green with the defect fully restored. The converse case pins that
/// the matcher is not simply always-false.
#[test]
fn report_tick_summary_guard_rejects_the_pre_fix_shape_5189() {
    const PRE_FIX: &str = r#"
                #[cfg(feature = "debug-log")]
                let session_count = sessions.len();
                let mut binding_summary = String::new();
                for (i, b) in bindings.iter().enumerate() {
                    let xsk_stats = b.xsk.device.statistics_v2().ok();
                }
"#;
    assert!(
        !report_tick_summary_build_is_gated(PRE_FIX),
        "the guard accepts the PRE-FIX shape — an ungated `String::new()` build \
         sitting under an unrelated cfg-gated `let session_count` line. It would \
         stay green with the release-build cost fully restored (#5189 A1-b8-F5)"
    );

    // A cfg attribute on the WRONG statement must not launder the build either:
    // the attribute has to sit on the binding_summary line itself.
    const CFG_ON_NEIGHBOUR: &str = r#"
                #[cfg(feature = "debug-log")]
                let session_count = sessions.len();
                let binding_summary = debug_report::build_binding_summary(&bindings, &mut dbg);
"#;
    assert!(
        !report_tick_summary_build_is_gated(CFG_ON_NEIGHBOUR),
        "the guard accepts a build whose cfg attribute is attached to the \
         PRECEDING statement, which does not gate the build at all"
    );

    // Converse, so the control cannot pass by rejecting everything.
    const POST_FIX: &str = r#"
                #[cfg(feature = "debug-log")]
                let binding_summary = debug_report::build_binding_summary(&bindings, &mut dbg);
"#;
    assert!(
        report_tick_summary_build_is_gated(POST_FIX),
        "the guard rejects even the shape the fix installs — it matches nothing, \
         ever, and would pin no property"
    );
}

/// #6750: a FAILED reconcile must not leave the requested state committed.
///
/// All three control handlers — `set_forwarding_state`, `set_binding_state`,
/// `set_queue_state` — write the requested arm / registration bits into
/// `guard.status` and only then call `reconcile_status_bindings`. #5621/#6135
/// made the failure honest to the CALLER (the cells above assert ok=false plus
/// the error), but the committed state stayed committed: the helper went on
/// reporting a posture its AF_XDP sockets had never been reconciled to.
///
/// THAT RETENTION IS WHAT SUPPRESSES RECOVERY, and the second half is on the Go
/// side. `syncDesiredForwardingStateLocked` short-circuits on
/// `if m.lastStatus.ForwardingArmed == desired { return nil }`, and the 1 Hz
/// status poll feeds `m.lastStatus` straight from the helper
/// (`applyHelperStatusLocked` -> `recordHelperStatusLocked`, maps_sync.go). So
/// the poll adopts the retained "armed" the failed reconcile left behind, the
/// equality then holds, and the retry that would have fixed it is never sent.
///
/// Restoring is all automatic recovery needs: the helper reports the truth, the
/// equality fails, the next tick retries. No new retry machinery, no persisted
/// debt — which is why this is the narrow fix rather than the desired/applied
/// split the issue also offers.
///
/// Each cell pairs the ok=false assertion with a STATE assertion, because the
/// two are independent: #5621 already delivers the first, and it is exactly the
/// combination "honest to the caller, dishonest in the status" that made this
/// survive the earlier fix.
#[test]
fn failed_forwarding_reconcile_restores_the_prior_arm_state_6750() {
    // Start DISARMED so the request is a real transition and the rollback is
    // observable: a fixture that was already armed could not tell "restored"
    // from "never changed".
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            forwarding_armed: false,
            capabilities: forwarding_caps(),
            bindings: vec![BindingStatus {
                slot: 0,
                registered: true,
                armed: false,
                ifindex: 10,
                ..BindingStatus::default()
            }],
            ..ProcessStatus::default()
        },
        snapshot: Some(failing_reconcile_snapshot()),
        afxdp: afxdp::Coordinator::new(),
        state_writer: Arc::new(StateWriter::new()),
    }));

    let mut request = req("set_forwarding_state");
    request.forwarding = Some(ForwardingControlRequest { armed: true });
    let response = run_request(state.clone(), request);

    assert!(!response.ok, "premise: the reconcile must have failed");
    assert!(
        response.error.contains("forwarding reconcile failed"),
        "premise: unexpected error {}",
        response.error
    );

    let guard = state.lock().expect("state");
    assert!(
        !guard.status.forwarding_armed,
        "the helper still reports forwarding_armed=true after a reconcile that \
         FAILED. Go's 1 Hz poll adopts that into m.lastStatus, its \
         `lastStatus.ForwardingArmed == desired` short-circuit then holds, and \
         the retry that would reconcile the sockets is never sent — the box \
         stays un-reconciled indefinitely (#6750)",
    );
    assert!(
        !guard.status.bindings[0].armed,
        "the per-binding arm bit was left committed after a failed reconcile",
    );
}

/// #6750 for `set_binding_state`: the registration bit must roll back too.
#[test]
fn failed_binding_reconcile_restores_the_prior_registration_6750() {
    let state = armed_state_with_failing_reconcile(vec![BindingStatus {
        slot: 0,
        registered: false,
        armed: false,
        ifindex: 10,
        ..BindingStatus::default()
    }]);
    let mut request = req("set_binding_state");
    request.binding = Some(BindingControlRequest {
        slot: 0,
        registered: true,
        armed: true,
    });
    let response = run_request(state.clone(), request);
    assert!(!response.ok, "premise: the reconcile must have failed");

    let guard = state.lock().expect("state");
    assert!(
        !guard.status.bindings[0].registered,
        "slot 0 still reports registered=true after a reconcile that FAILED — the \
         helper is advertising a binding its sockets never took (#6750)",
    );
    assert!(!guard.status.bindings[0].armed, "the arm bit was left committed too");
}

/// #6750 for `set_queue_state`, which mutates EVERY binding on the queue — so
/// the rollback has to be per-slot, not a single scalar.
#[test]
fn failed_queue_reconcile_restores_every_binding_on_the_queue_6750() {
    let state = armed_state_with_failing_reconcile(vec![
        BindingStatus {
            slot: 0,
            queue_id: 2,
            registered: false,
            armed: false,
            ifindex: 10,
            ..BindingStatus::default()
        },
        BindingStatus {
            slot: 1,
            queue_id: 2,
            registered: false,
            armed: false,
            ifindex: 11,
            ..BindingStatus::default()
        },
        // A binding on a DIFFERENT queue: untouched by the request, and it must
        // stay untouched by the rollback. Without it, "restore what changed"
        // and "stamp the whole table back to some baseline" look the same.
        BindingStatus {
            slot: 2,
            queue_id: 7,
            registered: true,
            armed: true,
            ifindex: 12,
            ..BindingStatus::default()
        },
    ]);
    let mut request = req("set_queue_state");
    request.queue = Some(QueueControlRequest {
        queue_id: 2,
        registered: true,
        armed: true,
    });
    let response = run_request(state.clone(), request);
    assert!(!response.ok, "premise: the reconcile must have failed");

    let guard = state.lock().expect("state");
    for slot in [0usize, 1] {
        assert!(
            !guard.status.bindings[slot].registered,
            "slot {slot} on the requested queue still reports registered=true after \
             a FAILED reconcile (#6750)",
        );
        assert!(!guard.status.bindings[slot].armed, "slot {slot} arm bit left committed");
    }
    assert!(
        guard.status.bindings[2].registered && guard.status.bindings[2].armed,
        "the binding on the UNTOUCHED queue was rolled back too — the restore \
         must put back what THIS request changed, not stamp a baseline over the \
         whole table",
    );
}

// #6785: THE WIRING CELL. `upsert_synced_session` now returns a typed outcome,
// but a typed outcome the handler discards is exactly the bug: the three
// semantic refusal paths already bumped counters and returned, and the control
// response still said `ok = true`, so Go recorded a success and kept a BPF
// mirror row for a session this helper never took.
//
// The Coordinator-level cells in ha_tests.rs prove the outcome is COMPUTED. They
// stay green if this handler drops it on the floor. This drives the real
// `handle_stream` dispatcher and asserts what actually goes back on the wire.
//
// The refusal is provoked through the aggregate import cap because it is the one
// refusal reachable from a single request pair with no worker fan-out: set the
// logical ceiling to zero-plus-one entry's worth and push a second NEW forward.
#[test]
fn sync_session_upsert_reports_a_semantic_refusal_on_the_wire_6785() {
    fn upsert_request(src_port: u16) -> ControlRequest {
        let mut request = req("sync_session");
        request.session_sync = Some(SessionSyncRequest {
            operation: "upsert".to_string(),
            addr_family: 2,
            protocol: 6,
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port,
            dst_port: 80,
            egress_ifindex: 7,
            neighbor_mac: "02:bf:72:01:02:03".to_string(),
            src_mac: "02:bf:72:0a:0b:0c".to_string(),
            ..SessionSyncRequest::default()
        });
        request
    }

    let state = new_state(ProcessStatus::default());
    // One LOGICAL session fits (2 entries: the forward and its synthesized
    // reverse companion); the second NEW forward is drop-newest rejected.
    state
        .lock()
        .expect("state")
        .afxdp
        .synced_import_cap_override
        .store(1, std::sync::atomic::Ordering::Relaxed);

    // Control on the SAME state: the first import must still answer ok, so this
    // cell cannot pass on a handler that reports a refusal unconditionally.
    let first = run_request(state.clone(), upsert_request(1234));
    assert!(
        first.ok,
        "the first import is within the ceiling and must succeed: {}",
        first.error
    );

    let second = run_request(state.clone(), upsert_request(5678));
    assert!(
        !second.ok,
        "a cap-REFUSED import answered ok=true — Go records a success and keeps \
         a BPF mirror row for a session this helper never took (#6785)"
    );
    assert!(
        second.error.starts_with(crate::afxdp::SYNCED_IMPORT_REFUSED_PREFIX),
        "a refusal must carry the machine-readable prefix Go classifies on, or \
         it is indistinguishable from a transport failure and would disarm HA \
         takeover-readiness on a healthy node; got {:?}",
        second.error
    );
    assert_eq!(
        second.error,
        format!(
            "{}{}",
            crate::afxdp::SYNCED_IMPORT_REFUSED_PREFIX,
            crate::afxdp::SyncedImportOutcome::RejectedCapacity
                .refusal_reason()
                .expect("capacity is a refusal")
        ),
        "the wire error must name WHICH refusal happened — an operator cannot \
         tell a capacity problem from a stale peer otherwise"
    );
}

/// #6751 PR 2/3: `refresh_status` must PROJECT each interface-mode SNAT
/// registry counter onto its OWN status field.
///
/// The accessor and the counter can both be correct while the projection is
/// missing or cross-wired, and nothing else in the tree would notice: the
/// Prometheus test feeds `ProcessStatus` directly, and the wire test feeds
/// `serde`. This is the one seam that binds the helper the coordinator exposes
/// to the field the Go side reads.
///
/// Three DISTINCT increments, so a projection wired to the wrong member of the
/// trio fails rather than coincidentally matching. Read as deltas because the
/// counters are cumulative process-globals shared with every other test in the
/// binary (the same posture `NAT_REVERSE_KEY_SHARED_DISPLACEMENTS` tests take);
/// `make test-rust` runs `--test-threads=1`, so no sibling can move them
/// between the read and the refresh.
#[test]
fn refresh_status_projects_interface_snat_registry_counters_6751() {
    use std::sync::atomic::Ordering;

    let state = new_state(ProcessStatus::default());
    let mut guard = state.lock().expect("server state");

    let before_pat = crate::nat::INTERFACE_SNAT_PAT_COLLISIONS.load(Ordering::Relaxed);
    let before_identity = crate::nat::INTERFACE_SNAT_IDENTITY_EXHAUSTION.load(Ordering::Relaxed);
    let before_cap = crate::nat::INTERFACE_SNAT_REGISTRY_CAP_EXHAUSTION.load(Ordering::Relaxed);
    let before_sync =
        crate::nat::INTERFACE_SNAT_SYNC_IDENTITY_CONFLICT_DROPS.load(Ordering::Relaxed);

    crate::nat::INTERFACE_SNAT_PAT_COLLISIONS.fetch_add(3, Ordering::Relaxed);
    crate::nat::INTERFACE_SNAT_IDENTITY_EXHAUSTION.fetch_add(5, Ordering::Relaxed);
    crate::nat::INTERFACE_SNAT_REGISTRY_CAP_EXHAUSTION.fetch_add(7, Ordering::Relaxed);
    crate::nat::INTERFACE_SNAT_SYNC_IDENTITY_CONFLICT_DROPS.fetch_add(11, Ordering::Relaxed);

    refresh_status(&mut guard);

    assert_eq!(
        guard.status.interface_snat_pat_collisions_total,
        before_pat + 3,
        "the PAT-collision counter must reach its own status field"
    );
    assert_eq!(
        guard.status.interface_snat_identity_exhaustion_total,
        before_identity + 5,
        "the identity-exhaustion counter must reach its own status field"
    );
    assert_eq!(
        guard.status.interface_snat_registry_cap_exhaustion_total,
        before_cap + 7,
        "the registry-cap counter must reach its own status field"
    );
    assert_eq!(
        guard
            .status
            .interface_snat_sync_identity_conflict_drops_total,
        before_sync + 11,
        "the sync-import conflict counter must reach its own status field"
    );
}

// --- #7095: a peer-imported session carries a LOCALLY RESOLVED ingress identity

/// #6928 imported `ingress_ifindex: 0` on purpose: the originating node's
/// ifindex is node-local and would name a different NIC here. #7095 does not
/// ship an ifindex — it ships a fold of the reth-relative name both chassis
/// agree on, and the Go side resolves it against THIS node's config and ifindex
/// table before building the request. So what arrives here is already local, and
/// storing it is what makes the identity survive a failover.
#[test]
fn session_sync_import_stores_locally_resolved_ingress_7095() {
    let zones = rustc_hash::FxHashMap::default();
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 5001,
        dst_port: 80,
        ingress_zone_id: 2,
        egress_zone_id: 3,
        ingress_ifindex: 42,
        ingress_vlan_id: 50,
        ..SessionSyncRequest::default()
    };
    let entry = build_synced_session_entry(&req, &zones, 0).expect("build entry");
    assert_eq!(
        entry.metadata.ingress_ifindex, 42,
        "a peer-imported session must carry the ingress ifindex the Go side \
         resolved LOCALLY from the peer's cluster-stable fold; dropping it here \
         is what made every synced session fall back to the zone approximation \
         after a failover (#7095)"
    );
    assert_eq!(
        entry.metadata.ingress_vlan_id, 50,
        "the VLAN is half the identity: {{ifindex, vlan}} is the key the CLI \
         resolves an interface name by, so two units of one trunk NIC alias \
         onto each other without it"
    );
}

/// The unknown case still imports nothing, and it arrives from three places
/// that all want the same answer: a legacy peer that sent no wire field, an
/// interface with no cluster-stable name, and a fabric-redirected session, whose
/// ingress interface is not knowable on this node at all (#7096 — the fabric
/// stamp carries a u16 zone id and nothing else).
#[test]
fn session_sync_import_keeps_zero_ingress_when_unknown_7095() {
    let zones = rustc_hash::FxHashMap::default();
    let req = SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 5001,
        dst_port: 80,
        ingress_zone_id: 2,
        egress_zone_id: 3,
        // No ingress_ifindex / ingress_vlan_id: exactly what an older daemon
        // sends, since serde defaults them.
        ..SessionSyncRequest::default()
    };
    let entry = build_synced_session_entry(&req, &zones, 0).expect("build entry");
    assert_eq!(
        entry.metadata.ingress_ifindex, 0,
        "an absent ingress identity must stay 0 — the consumer falls back to the \
         zone approximation, which is approximate but never confidently wrong"
    );
    assert_eq!(entry.metadata.ingress_vlan_id, 0);
}

// #7160 (#2387) — the domain-aware delete sweep.
//
// A Go "delete" built from a bare 5-tuple (`deleteHelperSessionsV4`, the
// `clear security flow session` / batch-revoke path) carries NO ingress
// identity, so the imported key resolves domain 0 and an exact-key delete
// cannot reach a session that lives in a routing instance. The operator is
// told the clear succeeded while the helper keeps forwarding the flow.
//
// This drives the REAL control-socket dispatcher, so it binds the retry loop in
// the handler and not just the `routing_domains()` reader that loop calls.
mod routing_domain_delete_7160 {
    use super::*;

    const DOMAIN: u32 = 100_007;

    fn upsert_request() -> SessionSyncRequest {
        SessionSyncRequest {
            operation: "upsert".to_string(),
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port: 1234,
            dst_port: 80,
            egress_ifindex: 7,
            neighbor_mac: "02:bf:72:01:02:03".to_string(),
            src_mac: "02:bf:72:0a:0b:0c".to_string(),
            ..SessionSyncRequest::default()
        }
    }

    /// The bare-5-tuple delete `deleteHelperSessionsV4` actually sends: "a
    /// delete request built with a nil value carries only the 5-tuple", so
    /// there is no ingress identity to resolve a domain from.
    fn bare_five_tuple_delete() -> ControlRequest {
        let mut request = req("sync_session");
        request.session_sync = Some(SessionSyncRequest {
            operation: "delete".to_string(),
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port: 1234,
            dst_port: 80,
            ..SessionSyncRequest::default()
        });
        request
    }

    fn state_holding_a_session_in(routing_domain: u32) -> Arc<Mutex<ServerState>> {
        let mut afxdp = afxdp::Coordinator::new();
        if routing_domain != 0 {
            afxdp.seed_routing_domain_for_test(24, routing_domain);
        }
        let entry = crate::server::helpers::build_synced_session_entry(
            &upsert_request(),
            afxdp.zone_name_to_id_ref(),
            routing_domain,
        )
        .expect("build the synced entry the delete must reach");
        let key = entry.key.clone();
        afxdp.upsert_synced_session(entry);
        assert!(
            afxdp.synced_session_entry_count_for_test() > 0,
            "setup: the session must exist before the delete, or the assertion \
             below passes for the wrong reason"
        );
        assert_eq!(key.routing_domain, routing_domain);
        Arc::new(Mutex::new(ServerState {
            status: ProcessStatus::default(),
            snapshot: None,
            afxdp,
            state_writer: Arc::new(StateWriter::new()),
        }))
    }

    /// #8636: two tenants holding the SAME 5-tuple in DIFFERENT routing
    /// instances — the normal case, since routing instances exist to carry
    /// overlapping address space.
    fn state_holding_the_same_tuple_in(domains: &[u32]) -> Arc<Mutex<ServerState>> {
        let mut afxdp = afxdp::Coordinator::new();
        for (idx, rd) in domains.iter().enumerate() {
            afxdp.seed_routing_domain_for_test(24 + idx as i32, *rd);
        }
        for rd in domains {
            let entry = crate::server::helpers::build_synced_session_entry(
                &upsert_request(),
                afxdp.zone_name_to_id_ref(),
                *rd,
            )
            .expect("build the synced entry");
            afxdp.upsert_synced_session(entry);
        }
        // TWO map entries per session: the forward key and its reverse
        // companion (the dual-entry design). Asserting the doubled count rather
        // than relaxing to `> 0` keeps the setup check able to notice a domain
        // that silently failed to install.
        assert_eq!(
            afxdp.synced_session_entry_count_for_test(),
            domains.len() * 2,
            "setup: each domain must hold its own forward+reverse copy of the \
             tuple, or the ambiguity this cell is about does not exist"
        );
        Arc::new(Mutex::new(ServerState {
            status: ProcessStatus::default(),
            snapshot: None,
            afxdp,
            state_writer: Arc::new(StateWriter::new()),
        }))
    }

    /// #8636 THE ANTI-OVER-REFUSE CONTROL, and it is the cell that decides
    /// whether the change is safe rather than merely careful.
    ///
    /// Refusing is the NEW behaviour, so the risk is that it fires on ordinary
    /// deletes and turns every policy invalidation into a session leak. When
    /// exactly one routing instance holds the tuple, the bare 5-tuple names it
    /// unambiguously and it must still be deleted — and deleted through the
    /// SCOPED key, which is strictly better than the old fan-out because it
    /// touches no other domain.
    ///
    /// Without this cell, "always refuse" passes the ambiguity cell below.
    #[test]
    fn an_unambiguous_bare_tuple_delete_still_removes_the_session_8636() {
        let state = state_holding_a_session_in(DOMAIN);
        // forward + reverse companion
        assert_eq!(synced_key_count(&state), 2, "setup");

        let response = run_request(state.clone(), bare_five_tuple_delete());
        assert!(
            response.ok,
            "a delete naming exactly one routing instance must succeed; got {:?}",
            response.error
        );
        assert_eq!(
            synced_key_count(&state),
            0,
            "the session lives in exactly ONE routing instance, so the bare \
             5-tuple names it unambiguously and it must still be removed — the \
             #7160 guarantee that a clear the operator was told succeeded \
             actually revoked the session"
        );
    }

    /// #8636 THE FEATURE. The same 5-tuple live in two routing instances is
    /// two tenants, and nothing in a bare-5-tuple delete says which one is
    /// meant. Deleting in every domain — what this replaces — tore down the
    /// other tenant's live session.
    ///
    /// FAIL-ON-REVERT: restore the `for rd in view.routing_domains()` delete
    /// loop and both sessions disappear, reddening the count assertion.
    #[test]
    fn an_ambiguous_bare_tuple_delete_is_refused_and_touches_nothing_8636() {
        let state = state_holding_the_same_tuple_in(&[100_007, 100_008]);
        // two tenants x (forward + reverse companion)
        assert_eq!(synced_key_count(&state), 4, "setup");

        let response = run_request(state.clone(), bare_five_tuple_delete());
        assert!(
            !response.ok,
            "a delete whose 5-tuple matches live sessions in TWO routing \
             instances cannot be resolved from the request, and guessing tears \
             down another tenant's session"
        );
        assert!(
            response.error.contains("ambiguous-routing-domain"),
            "the refusal needs its own stable token so an operator can tell a \
             cross-tenant guard firing from an import problem or a transport \
             failure; got {:?}",
            response.error
        );
        assert_eq!(
            synced_key_count(&state),
            4,
            "a refused delete must touch NEITHER tenant. Removing even the \
             'right' one on a guess is the defect — the request does not say \
             which is right"
        );
    }

    /// #8636: a tuple in NO routing instance is unchanged — the exact delete
    /// above it was the whole job. Guards against the probe loop turning a
    /// plain miss into a refusal.
    #[test]
    fn a_bare_tuple_delete_matching_no_instance_still_succeeds_8636() {
        let state = state_holding_a_session_in(0);
        let response = run_request(state.clone(), bare_five_tuple_delete());
        assert!(
            response.ok,
            "no routing-instance copy exists, so there is nothing to \
             disambiguate and nothing to refuse; got {:?}",
            response.error
        );
    }

    /// #9714 review round 2, finding 2: a sender that STATES the default routing
    /// instance has named exactly ONE domain, and must not be routed into the
    /// ambiguity probe.
    ///
    /// `routing_domain_from_wire` separates `Present(0)` from `Absent` deliberately,
    /// and `resolved_domain` carries that distinction right up to the `unwrap_or(0)`
    /// that flattens it for the key. `bare` used to be `key.routing_domain == 0`,
    /// which reads the FLATTENED value and so cannot tell the two apart: an
    /// authoritative single-domain delete was refused for naming too many tenants
    /// while naming exactly one — a guard refusing the very case it exists to permit.
    ///
    /// THE AXIS THIS CELL EXISTS FOR. Every other delete cell sends wire
    /// `routing_domain: 0`, which decodes to ABSENT — `WIRE_DEFAULT_INSTANCE` is 1,
    /// not 0. With only that value in the fixture set, `resolved_domain.is_none()`
    /// and `key.routing_domain == 0` agree on every input, so the fix had no cell
    /// that could distinguish it from the defect. The axis had one value, so the row
    /// did not exist.
    ///
    /// The wire value comes from `routing_domain_to_wire(0)` rather than a literal,
    /// so the cell tracks the encoder a real sender uses instead of a copy of it.
    #[test]
    fn a_stated_default_instance_delete_is_not_ambiguous_9714() {
        // The same fixture the ambiguity cell uses: the tuple is live in TWO tenants,
        // so an ABSENT delete is refused. A STATED default instance must not be.
        let state = state_holding_the_same_tuple_in(&[100_007, 100_008]);
        assert_eq!(synced_key_count(&state), 4, "setup: two tenants x (forward + reverse)");

        let mut request = bare_five_tuple_delete();
        request
            .session_sync
            .as_mut()
            .expect("a sync_session request")
            .routing_domain = crate::session::routing_domain_to_wire(0);

        let response = run_request(state.clone(), request);

        assert!(
            response.ok,
            "a delete that STATED the default routing instance was refused as ambiguous. It named \
             exactly one domain; the ambiguity probe exists for requests that named NONE (#9714 r2 \
             F2). Got {:?}",
            response.error
        );
        assert_eq!(
            synced_key_count(&state),
            4,
            "the stated-default delete removed a TENANT's rows: it names domain 0 only, and neither \
             tenant's session lives there"
        );
    }

    /// #9714 review round 2, finding 4: a MARKED delete with NO shared authority must
    /// do NOTHING — not even the domain-0 delete the handler used to send regardless.
    ///
    /// With routing instances configured and no shared-map match, the old handler
    /// still fanned `DeleteSynced(domain 0)` out to every worker. A worker whose real
    /// local session lives in a NONZERO domain misses the scoped lookup and takes the
    /// unconditional key-only arm, tearing out the steering row of a live flow.
    ///
    /// "No shared entry" does NOT mean "no session", which is what makes this
    /// reachable rather than theoretical: on the install path the BPF publish precedes
    /// the shared-map publish, so there is a real window in which the kernel row
    /// exists and the shared entry does not.
    ///
    /// The unmarked arm is the CONTROL. Without it, a handler that fanned nothing out
    /// for any delete would pass the marked assertion while silently breaking every
    /// operator clear.
    #[test]
    fn a_marked_delete_with_no_shared_authority_fans_out_nothing_9714() {
        for peer_delete in [true, false] {
            let mut afxdp = afxdp::Coordinator::new();
            afxdp.seed_routing_domain_for_test(24, DOMAIN);
            let queued_deletes = afxdp.register_counting_worker_for_test(0);
            assert_eq!(
                afxdp.synced_session_entry_count_for_test(),
                0,
                "setup (peer_delete={peer_delete}): this cell is about the NO-shared-authority \
                 case, so the shared map must start empty"
            );
            let state = Arc::new(Mutex::new(ServerState {
                status: ProcessStatus::default(),
                snapshot: None,
                afxdp,
                state_writer: Arc::new(StateWriter::new()),
            }));
            let mut request = bare_five_tuple_delete();
            request
                .session_sync
                .as_mut()
                .expect("a sync_session request")
                .peer_delete = peer_delete;

            let response = run_request(state.clone(), request);

            assert!(
                response.ok,
                "(peer_delete={peer_delete}) a miss is not a refusal; got {:?}",
                response.error
            );
            if peer_delete {
                assert_eq!(
                    queued_deletes(),
                    0,
                    "a MARKED delete with no shared authority fanned DeleteSynced out anyway. The \
                     worker no-entry arm then deletes the kernel steering row of a live local flow \
                     whose shared entry has not been published yet (#9714 r2 F4)"
                );
            } else {
                assert!(
                    queued_deletes() > 0,
                    "control: an AUTHORITATIVE delete must keep its plain-miss kernel cleanup, or \
                     the marked arm's zero proves only that nothing ever fans out"
                );
            }
        }
    }

    /// #9714: the handler routes a MARKED delete to the refusing path at BOTH of its
    /// delete calls, the exact key and the #8636 single-domain retry, and an unmarked
    /// delete to the authoritative path. The domain-level cells call the domain
    /// directly, so a handler that ignored the mark at either call would pass them.
    #[test]
    fn the_handler_honours_the_peer_delete_mark_at_both_delete_calls_9714() {
        for (arm, domain) in [("exact key", 0u32), ("#8636 single-domain retry", DOMAIN)] {
            for peer_delete in [true, false] {
                let mut afxdp = afxdp::Coordinator::new();
                if domain != 0 {
                    afxdp.seed_routing_domain_for_test(24, domain);
                }
                let forward = crate::server::helpers::build_synced_session_entry(
                    &upsert_request(),
                    afxdp.zone_name_to_id_ref(),
                    domain,
                )
                .expect("build the local entry");
                afxdp.seed_live_local_session_for_test(forward, 7, true);
                let queued_deletes = afxdp.register_counting_worker_for_test(0);
                assert_eq!(
                    afxdp.synced_session_entry_count_for_test(),
                    2,
                    "setup ({arm}): the live local forward entry and its reverse companion"
                );
                let state = Arc::new(Mutex::new(ServerState {
                    status: ProcessStatus::default(),
                    snapshot: None,
                    afxdp,
                    state_writer: Arc::new(StateWriter::new()),
                }));
                let mut request = bare_five_tuple_delete();
                request
                    .session_sync
                    .as_mut()
                    .expect("a sync_session request")
                    .peer_delete = peer_delete;

                let response = run_request(state.clone(), request);

                assert_eq!(
                    synced_key_count(&state),
                    if peer_delete { 2 } else { 0 },
                    "({arm}, peer_delete={peer_delete}) a MARKED delete of a live local session \
                     whose owner RG is active must be refused, and an UNMARKED one (an operator \
                     clear) must still remove it (#9714)"
                );
                if peer_delete {
                    assert!(
                        !response.ok
                            && response.error == "synced-delete-refused:peer-delete-local-owned",
                        "({arm}) a refused peer delete must be answered in-band with its token, or \
                         the Go side deletes its own mirror and DNAT rows for a flow the helper \
                         kept (#9714); got ok={} error={:?}",
                        response.ok,
                        response.error
                    );
                    assert_eq!(
                        queued_deletes(),
                        0,
                        "({arm}) a refused peer delete still fanned DeleteSynced out to the \
                         workers, whose no-entry arm deletes the live flow's steering row (#9714)"
                    );
                } else {
                    assert!(
                        response.ok,
                        "({arm}) an unmarked delete must succeed: {:?}",
                        response.error
                    );
                    assert!(
                        queued_deletes() > 0,
                        "({arm}) control: an applied delete must fan DeleteSynced out, or the \
                         refused arm's zero proves nothing"
                    );
                }
            }
        }
    }

    fn synced_key_count(state: &Arc<Mutex<ServerState>>) -> usize {
        state
            .lock()
            .expect("server state")
            .afxdp
            .synced_session_entry_count_for_test()
    }

    /// The defect this branch closes, measured rather than argued.
    ///
    /// A peer-synced session whose ingress identity the sender could not name
    /// (#7096 fabric-redirected, or no cluster-stable name) used to import at
    /// domain 0. On a node that runs routing instances that is not a neutral
    /// placeholder — 0 is the DEFAULT routing instance — so the session was
    /// filed in the default instance's identity space and became reachable
    /// from it: `lookup_shared_forward_nat_match` probes the exact key and
    /// then falls back to the domain-agnostic one, which is exactly the key
    /// such a mis-filed session sits at.
    ///
    /// FAIL-ON-REVERT: return `Some(0)` from `synced_routing_domain` instead
    /// of `None`, or drop the refusal arm in the handler, and the import
    /// succeeds — leaving an entry in the shared map under a domain nothing
    /// verified.
    #[test]
    fn an_unnamed_peer_ingress_is_refused_on_a_node_with_routing_instances() {
        let mut afxdp = afxdp::Coordinator::new();
        afxdp.seed_routing_domain_for_test(24, DOMAIN);
        let state = Arc::new(Mutex::new(ServerState {
            status: ProcessStatus::default(),
            snapshot: None,
            afxdp,
            state_writer: Arc::new(StateWriter::new()),
        }));

        let mut request = req("sync_session");
        // No ingress_ifindex / ingress_vlan_id: this is what a #7096
        // fabric-redirected session, and any session with no cluster-stable
        // ingress name, actually sends.
        request.session_sync = Some(upsert_request());

        let response = run_request(state.clone(), request);
        assert!(
            !response.ok,
            "a synced session with no resolvable routing domain was ACCEPTED on \
             a node that runs routing instances. It is now filed under the \
             default instance, where a reply that resolved its own domain \
             reaches it through the domain-agnostic fallback probe."
        );
        assert!(
            response.error.contains("unknown-routing-domain"),
            "the refusal must carry its own stable reason token so Go can tell \
             it from a transport failure and from the other semantic \
             refusals; got {:?}",
            response.error
        );

        let guard = state.lock().expect("server state");
        assert_eq!(
            guard.afxdp.synced_session_entry_count_for_test(),
            0,
            "the refusal must leave NOTHING in the shared map — a refusal that \
             still published is the defect wearing an error message"
        );
        assert_eq!(
            guard.afxdp.synced_import_unknown_routing_domain_total(),
            1,
            "the refusal must be counted; an uncounted fail-closed path is \
             indistinguishable from one that never fires"
        );
    }

    /// The same request on a node with NO routing instances must still import.
    /// This is the half that keeps the fix from being a fail-closed regression
    /// for every single-instance cluster — which is all of them today.
    ///
    /// FAIL-ON-REVERT: gate the refusal on `ingress_ifindex <= 0` alone,
    /// without the `has_routing_domains` precondition, and this goes red.
    #[test]
    fn an_unnamed_peer_ingress_still_imports_with_no_routing_instances() {
        let state = Arc::new(Mutex::new(ServerState {
            status: ProcessStatus::default(),
            snapshot: None,
            afxdp: afxdp::Coordinator::new(),
            state_writer: Arc::new(StateWriter::new()),
        }));
        let mut request = req("sync_session");
        request.session_sync = Some(upsert_request());

        let response = run_request(state.clone(), request);
        assert!(
            response.ok,
            "a single-instance node must keep importing sessions with no \
             ingress identity exactly as it did pre-#7160; got {:?}",
            response.error
        );
        let guard = state.lock().expect("server state");
        assert!(
            guard.afxdp.synced_session_entry_count_for_test() > 0,
            "the session must actually be in the shared map"
        );
        assert_eq!(
            guard.afxdp.synced_import_unknown_routing_domain_total(),
            0,
            "nothing may be counted as refused on a node with no routing \
             instances — 0 is the only domain there, and it is correct"
        );
    }

    /// A NAMED ingress on a VRF node imports at its own domain, so the
    /// refusal above is scoped to the unresolvable case and does not simply
    /// turn off HA session sync for VRF deployments.
    #[test]
    fn a_named_peer_ingress_imports_at_its_own_domain() {
        let state = state_holding_a_session_in(DOMAIN);
        let guard = state.lock().expect("server state");
        assert!(
            guard.afxdp.synced_session_entry_count_for_test() > 0,
            "a session whose ingress THIS node resolved must import"
        );
        assert_eq!(
            guard.afxdp.synced_import_unknown_routing_domain_total(),
            0,
            "a resolvable ingress must not be counted as unknown"
        );
    }

    /// #7239, and the cell the mutation matrix said was missing: the import must
    /// USE the domain the sender stated, not one it derives locally.
    ///
    /// The fixture is the recycle, staged: this node's ingress map says
    /// ifindex 24 is in DOMAIN (so the derivation would answer DOMAIN), and the
    /// request carries ingress_ifindex 24 together with a DIFFERENT stated
    /// domain. That is exactly what a recycled ifindex produces — the fold
    /// resolves to a sibling this node knows, while the sender's install-time
    /// domain is the truth. If the import derives, the session is filed under
    /// DOMAIN; if it uses what was carried, under CARRIED.
    ///
    /// A fixture where the two AGREE proves nothing, which is why they differ.
    ///
    /// FAIL-ON-REVERT: make the `Present` arm derive instead of using the
    /// carried value and this reds. (The matrix caught that mutation escaping:
    /// its only "failure" was an unrelated flake.)
    #[test]
    fn an_import_uses_the_carried_domain_not_the_derived_one_7239() {
        const DERIVED: u32 = 100_001;
        const CARRIED: u32 = 100_009;
        assert_ne!(DERIVED, CARRIED, "fixture: the two must differ to discriminate");

        let mut afxdp = afxdp::Coordinator::new();
        afxdp.seed_routing_domain_for_test(24, DERIVED);
        let state = Arc::new(Mutex::new(ServerState {
            status: ProcessStatus::default(),
            snapshot: None,
            afxdp,
            state_writer: Arc::new(StateWriter::new()),
        }));

        let mut request = req("sync_session");
        let mut sync = upsert_request();
        // The ingress identity the fold resolved to on THIS node...
        sync.ingress_ifindex = 24;
        // ...and the domain the SENDER stamped at install, encoded.
        sync.routing_domain = CARRIED;
        request.session_sync = Some(sync);

        let response = run_request(state.clone(), request);
        assert!(response.ok, "unexpected error: {}", response.error);

        let guard = state.lock().expect("server state");
        let domains = guard.afxdp.synced_session_routing_domains_for_test();
        assert!(
            domains.contains(&CARRIED),
            "the session was NOT filed under the domain the sender stated \
             ({CARRIED}); found {domains:?}. Deriving instead means a recycled \
             ifindex files a tenant's session in a sibling's routing instance — \
             the #7239 defect."
        );
        assert!(
            !domains.contains(&DERIVED),
            "the session was filed under the LOCALLY DERIVED domain ({DERIVED}) \
             even though the sender stated {CARRIED}; found {domains:?}"
        );
    }

    /// FAIL-ON-REVERT: drop the per-domain retry in
    /// `server/handlers/sync_session.rs` and the domain-scoped session survives
    /// a delete whose caller was told it succeeded.
    #[test]
    fn a_bare_five_tuple_delete_reaches_a_domain_scoped_session() {
        let state = state_holding_a_session_in(DOMAIN);
        let before = synced_key_count(&state);
        assert!(before > 0, "setup: the shared map must hold the session");

        let response = run_request(state.clone(), bare_five_tuple_delete());
        assert!(response.ok, "unexpected error: {}", response.error);

        assert_eq!(
            synced_key_count(&state),
            0,
            "a session in routing domain {DOMAIN} survived a bare-5-tuple \
             delete. The request carries no ingress identity, so the key the \
             handler builds is in domain 0 and the exact-key delete misses — \
             without the per-domain retry the helper keeps forwarding a flow \
             the operator was told had been cleared."
        );
    }

    /// The gate: with no routing-instance interface membership the retry loop
    /// has nothing to iterate, and the ordinary domain-0 delete still works.
    #[test]
    fn a_bare_five_tuple_delete_still_works_with_no_membership() {
        let state = state_holding_a_session_in(0);
        assert!(
            state
                .lock()
                .expect("server state")
                .afxdp
                .routing_domains()
                .is_empty(),
            "with no membership the retry loop must have nothing to iterate"
        );
        let response = run_request(state.clone(), bare_five_tuple_delete());
        assert!(response.ok, "unexpected error: {}", response.error);
        assert_eq!(
            synced_key_count(&state),
            0,
            "the default-instance delete path regressed"
        );
    }
}

/// The needle for the #7699 drain call, and the anchor it must sit after.
/// Module-level so the guard and its over-reach control search for the SAME
/// strings — a control that retypes the needle stops controlling the guard the
/// first time one of them is edited.
const PPTP_DRAIN_NEEDLE: &str = "crate::afxdp::worker_queue::drain_pptp_control_inbox(";
const PPTP_EXPIRY_NEEDLE: &str =
    "let expired_entries = sessions.expire_stale_entries_ha(loop_now_ns";
/// #7699: the DATA-channel resolve's call site. Same module-level treatment and
/// the same reason: the guard and its over-reach control must search for one
/// string, not two copies of it.
const PPTP_RESOLVE_NEEDLE: &str =
    "flow = crate::afxdp::gre_discriminator::pptp_data_session_flow(";

/// Find the 0-based line whose trimmed start IS `needle` — a real statement,
/// not a mention. Shared by the guard and its control for the same reason the
/// needles are.
fn pptp_drain_line(src: &str, needle: &str) -> Option<usize> {
    src.lines().position(|l| l.trim_start().starts_with(needle))
}

/// OVER-REACH CONTROL for `worker_loop_drains_the_pptp_control_inbox_7699`.
///
/// A source guard that asserts "the call appears in the periodic region" is
/// satisfied by a MENTION as easily as by a call, and a deleted call most
/// plausibly leaves behind exactly that: a comment, or the call itself commented
/// out. This runs the guard's own matcher over synthetic bodies where the only
/// occurrence is a mention, and requires NO match — then over a body with the
/// real statement, and requires one, so the control cannot pass by matching
/// nothing ever.
///
/// This is not decoration. Written as a substring search, the guard DID accept
/// the commented-out body; the line-wise matcher exists because this control
/// failed first.
#[test]
fn pptp_drain_guard_does_not_accept_a_mention_7699() {
    const COMMENTED_OUT: &str = "        // crate::afxdp::worker_queue::drain_pptp_control_inbox(\n        //     &pptp_control,\n";
    const PROSE: &str =
        "        // the drain rides crate::afxdp::worker_queue::drain_pptp_control_inbox( periodic work\n";
    const REAL: &str =
        "        crate::afxdp::worker_queue::drain_pptp_control_inbox(\n            &pptp_control,\n";

    assert!(
        pptp_drain_line(COMMENTED_OUT, PPTP_DRAIN_NEEDLE).is_none(),
        "the guard accepts a COMMENTED-OUT drain call, so deleting the call by \
         commenting it out would report the dispatch as wired (#7699)"
    );
    assert!(
        pptp_drain_line(PROSE, PPTP_DRAIN_NEEDLE).is_none(),
        "the guard accepts a PROSE mention of the drain, so a comment naming \
         the function would report the dispatch as wired (#7699)"
    );
    assert!(
        pptp_drain_line(REAL, PPTP_DRAIN_NEEDLE).is_some(),
        "the guard does not match even a body that plainly contains the real \
         call — it is searching for something unreachable and would pass \
         nothing, ever (#7699)"
    );
    assert!(
        pptp_drain_line(REAL, PPTP_EXPIRY_NEEDLE).is_none()
            && pptp_drain_line(
                "        let expired_entries = sessions.expire_stale_entries_ha(loop_now_ns, Some(&ha_ctx));\n",
                PPTP_EXPIRY_NEEDLE
            )
            .is_some(),
        "the two needles are not distinct: one matches the other's body, so the \
         position assertion could compare a line against itself (#7699)"
    );
}

/// #7699: the worker loop must actually CALL the PPTP control drain, and the
/// interval gate must NOT be written at that call site.
///
/// # Why this is a source guard rather than an execution cell
///
/// The dispatch is a two-hop join and the hops are bound differently. The PUSH
/// is bound by execution — `pptp_dispatch_join_tests_7699` drives the real
/// `stage_parse_flow_and_learn` over real frame bytes, so deleting it reds four
/// cells. The DRAIN CALL SITE cannot be: `worker_loop` needs live AF_XDP
/// bindings, and every cell that exercises the drain calls
/// `drain_pptp_control_inbox` directly — which is exactly why they cannot
/// notice that the worker loop stopped calling it.
///
/// That is not a hypothesis. Deleting the call from `loop_body` was run as a
/// mutation and **SURVIVED** the whole suite: the parser, the inbox, the drain,
/// the broadcast and the table all still passed while the running dataplane
/// learned nothing. The same two-correct-halves-and-no-join shape this whole
/// change exists to close, reproduced one level up. This guard is the detector.
///
/// # The second assertion is the #8399 shape
///
/// `CONTROL_DRAIN_INTERVAL_NS` must not appear in the worker loop at all. The
/// gate lives inside `PptpControlInbox::take_pending` deliberately — the caller
/// runs at packet rate, so a gate written at the call site is one edit from
/// per-poll work, which is what #8399 shipped when the association expiry
/// landed above `expire_stale_entries_ha`'s gc-interval gate. A call-site gate
/// would also be invisible to the frequency cell, which calls the drain
/// directly.
///
/// That assertion is a PROXY, and a deliberately crude one: naming the interval
/// constant is the only way to write the gate correctly, so its absence from
/// this file is evidence no correct call-site gate exists here. A hand-rolled
/// gate on a bare literal would slip past — a different and much more visible
/// defect — and the loop's own comment says not to name the constant there, so
/// the proxy keeps meaning what it says.
/// The needles are matched LINE-WISE, against a line whose trimmed start IS the
/// needle. A plain `src.find` would accept a commented-out call — the single
/// most plausible thing a deleted call leaves behind — and the over-reach
/// control below is what forced that: written as a substring search, the guard
/// passed for a body whose only occurrence was `// crate::afxdp::…`.
#[test]
fn worker_loop_drains_the_pptp_control_inbox_7699() {
    let src = include_str!("../afxdp/worker/loop_body/mod.rs");

    let expiry_at = pptp_drain_line(src, PPTP_EXPIRY_NEEDLE).unwrap_or_else(|| {
        panic!(
            "the worker loop's session-expiry call is gone — this guard's \
             position claim is anchored to a line that no longer exists (#7699)"
        )
    });
    let drain_at = pptp_drain_line(src, PPTP_DRAIN_NEEDLE).unwrap_or_else(|| {
        panic!(
            "the worker loop does not call drain_pptp_control_inbox: control \
             segments the data path copies into the inbox are never parsed, so \
             no PPTP association is ever learned on a live box — while the \
             parser, inbox, drain, broadcast and table cells all stay green \
             (#7699)"
        )
    });
    assert!(
        drain_at > expiry_at,
        "the PPTP control drain (line {drain_at}) is not in the periodic region \
         beside the association expiry (line {expiry_at}) it is the counterpart \
         of (#7699)"
    );
    assert!(
        !src.contains("CONTROL_DRAIN_INTERVAL_NS"),
        "the drain's interval gate has been written at the CALL SITE. It \
         belongs inside PptpControlInbox::take_pending: this loop runs at \
         packet rate, so a call-site gate is one edit from per-poll work — the \
         defect #8399 shipped — and it is invisible to the frequency cell, \
         which calls the drain directly (#7699)"
    );
}

/// #7699: the DATA-channel resolve must be CALLED from the descriptor loop.
///
/// The sibling guard above exists because deleting the drain call survived the
/// entire suite — every cell called the drain directly, so none could see the
/// worker loop stop calling it. This resolve is in exactly that position: its
/// parser and table cells drive `pptp_data_session_flow` by name, and all of
/// them stay green with the production call deleted, while a live box resolves
/// nothing and every PPTP data packet stays flowless and aliasing.
///
/// Anchored to the flow-parsing stage rather than to a line number: the resolve
/// is only correct AFTER `stage_parse_flow_and_learn`, because it is gated on
/// that stage having produced no flow. Ordering the other way round would make
/// it unreachable for every packet, which is a silent no-op rather than a
/// failure.
#[test]
fn descriptor_loop_resolves_the_pptp_data_channel_7699() {
    let src = include_str!("../afxdp/poll_descriptor/mod.rs");

    let stage_at = pptp_drain_line(src, "let mut flow = stage_parse_flow_and_learn(")
        .unwrap_or_else(|| {
            panic!(
                "the descriptor loop's flow-parsing stage is gone — this guard's \
                 ordering claim is anchored to a line that no longer exists (#7699)"
            )
        });
    let resolve_at = pptp_drain_line(src, PPTP_RESOLVE_NEEDLE).unwrap_or_else(|| {
        panic!(
            "the descriptor loop does not call pptp_data_session_flow: a GRE \
             version-1 data packet never consults the association table, so two \
             simultaneous PPTP calls between one endpoint pair still alias onto \
             one session — while the parser, table and resolve cells all stay \
             green (#7699)"
        )
    });
    assert!(
        resolve_at > stage_at,
        "the PPTP data resolve (line {resolve_at}) runs BEFORE the flow-parsing \
         stage (line {stage_at}). It is gated on that stage having produced no \
         flow, so ordering it first makes it unreachable for every packet — a \
         silent no-op, not a failure (#7699)"
    );
}

/// OVER-REACH CONTROL for the guard above, on the same matcher and the same
/// needle for the same reason its sibling states: a control that retypes the
/// needle stops controlling the guard the first time one of them is edited.
#[test]
fn pptp_resolve_guard_does_not_accept_a_mention_7699() {
    const COMMENTED_OUT: &str =
        "        // flow = crate::afxdp::gre_discriminator::pptp_data_session_flow(\n";
    const PROSE: &str =
        "        // the resolve rides flow = crate::afxdp::gre_discriminator::pptp_data_session_flow( here\n";
    const REAL: &str =
        "        flow = crate::afxdp::gre_discriminator::pptp_data_session_flow(\n            packet_frame,\n";

    assert!(
        pptp_drain_line(COMMENTED_OUT, PPTP_RESOLVE_NEEDLE).is_none(),
        "the guard accepts a COMMENTED-OUT resolve, so deleting the call by \
         commenting it out would report the data channel as wired (#7699)"
    );
    assert!(
        pptp_drain_line(PROSE, PPTP_RESOLVE_NEEDLE).is_none(),
        "the guard accepts a PROSE mention, so a comment naming the function \
         would report the data channel as wired (#7699)"
    );
    assert!(
        pptp_drain_line(REAL, PPTP_RESOLVE_NEEDLE).is_some(),
        "the guard does not match a body that plainly contains the real call — \
         it is searching for something unreachable and would pass nothing, \
         ever (#7699)"
    );
    assert!(
        pptp_drain_line(REAL, PPTP_DRAIN_NEEDLE).is_none(),
        "the resolve needle and the drain needle are not distinct, so one \
         guard's body satisfies the other's and neither binds what it names \
         (#7699)"
    );
}

// --- #7919: the session_counters verb -----------------------------------

// The Go side classifies an OLD helper's refusal by matching the literal
// prefix "unknown request type" (`isUnknownVerbError`,
// pkg/dataplane/userspace/manager_sessions.go). That match is against wording
// produced by binaries ALREADY RELEASED, which cannot be changed retroactively
// — so the wording is a wire contract in everything but name, and rewording it
// here would silently downgrade "unsupported, ask a newer helper" to a generic
// error on every mixed-version pair.
//
// Pinned as a PREFIX rather than the whole string: the verb name is appended,
// and pinning the full sentence would red on any new verb for no reason.
#[test]
fn the_unknown_verb_wording_the_go_side_matches_on_is_pinned_7919() {
    let response = run_request(new_state(ProcessStatus::default()), req("session_counters_typo"));
    assert!(!response.ok);
    assert!(
        response.error.starts_with("unknown request type"),
        "the Go side's isUnknownVerbError matches this prefix on binaries that \
         are already released; got: {}",
        response.error
    );
}

// A `session_counters` request with NO 5-tuple is REFUSED, not answered with an
// empty row set. An empty answer to a malformed question is indistinguishable
// from "no worker holds this session", which is one of the two states the verb
// exists to separate.
#[test]
fn session_counters_without_a_query_is_refused_not_empty_7919() {
    let response = run_request(new_state(ProcessStatus::default()), req("session_counters"));
    assert!(
        !response.ok,
        "a query with no 5-tuple must be refused, not silently answered"
    );
    assert!(
        response.error.contains("no session_counter_query"),
        "the refusal must say what was missing; got: {}",
        response.error
    );
    assert!(
        response.session_counters.is_empty(),
        "a refused query must carry no rows"
    );
}

// An unparseable address is likewise refused rather than defaulted. A
// `0.0.0.0` fallback would be a plausible-looking key that resolves to no
// session, reporting "not held" for a question that was never asked.
#[test]
fn session_counters_refuses_an_unparseable_address_7919() {
    let mut request = req("session_counters");
    request.session_counter_query = Some(crate::protocol::SessionCounterQueryRequest {
        src_ip: "not-an-ip".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40001,
        dst_port: 5201,
        protocol: 6,
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok, "an unparseable address must be refused");
    assert!(
        response.error.contains("unparseable src_ip"),
        "the refusal must name the field; got: {}",
        response.error
    );

    // POSITIVE CONTROL: the SAME request with a valid address is accepted, so
    // the refusal above is about the address and not about the verb being
    // unreachable or the request shape being wrong.
    let mut ok_request = req("session_counters");
    ok_request.session_counter_query = Some(crate::protocol::SessionCounterQueryRequest {
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 40001,
        dst_port: 5201,
        protocol: 6,
    });
    let ok_response = run_request(new_state(ProcessStatus::default()), ok_request);
    assert!(
        ok_response.ok,
        "control: a well-formed query must be accepted (no workers registered \
         here, so it simply returns no rows); got: {}",
        ok_response.error
    );
}

// Mixed address families are refused: a v4 source with a v6 destination is not
// a session key this dataplane can hold, and building one would query a tuple
// that cannot exist.
#[test]
fn session_counters_refuses_mixed_address_families_7919() {
    let mut request = req("session_counters");
    request.session_counter_query = Some(crate::protocol::SessionCounterQueryRequest {
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "2001:559:8585:80::200".to_string(),
        src_port: 40001,
        dst_port: 5201,
        protocol: 6,
    });
    let response = run_request(new_state(ProcessStatus::default()), request);
    assert!(!response.ok, "mixed families must be refused");
    assert!(
        response.error.contains("families differ"),
        "got: {}",
        response.error
    );
}

// --- #7209: `sync_session` served WHILE `apply_snapshot` holds the mutex -----
//
// THIS IS THE ONE THE ISSUE'S SCOPE ITEM 4 ASKS FOR, and nothing covered it.
// The two existing deadline cells assert a `status` poll, and #5862's pair only
// covers the binding settle. Neither drives the verb whose starvation is the
// defect.
//
// WHY THE STARVATION COSTS SESSIONS RATHER THAN LATENCY. `apply_snapshot` holds
// `ServerState` across a 10 s worker-readiness barrier, a 500 ms mlx5 teardown
// quiesce, worker `join()`s and BPF map-pin opens. Go budgets 3 s for a session
// round-trip (`sessionSyncRoundtripDeadline`) and #5380 ABORTS the remainder of
// a bulk batch on the first transport failure — so one blocked import takes up
// to 255 session mirrors with it, during the failover the path exists to serve.
//
// THE ASSERTION IS THE SERVICE, NOT THE ABSENCE OF A STALL. A cell that merely
// timed the request would pass on a build where the dispatch change never took
// effect but the lock happened to be free. This one holds the lock for the whole
// request and asserts the import was ANSWERED and APPLIED anyway.

/// Hold the `ServerState` mutex the way a long `apply_snapshot` does, and
/// require a `sync_session` to complete anyway.
///
/// FAIL-ON-REVERT: route the verb back through `state.lock()` and the request
/// blocks until this guard drops, so the bounded receive below times out. The
/// bound is what makes the mutant a KILL rather than a hang — a test whose
/// subject fails by blocking forever reports nothing at all.
#[test]
fn sync_session_import_is_applied_while_the_state_lock_is_held_7209() {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let state = new_state(ProcessStatus::default());
    let session_domain = state
        .lock()
        .expect("state")
        .afxdp
        .session_domain()
        .clone();

    let mut request = req("sync_session");
    // DELIBERATELY NOT setting `suppress_status`, though both daemon senders do.
    // The property is that this verb never queues behind the mutex — full stop,
    // not "provided the caller asked for no status". An implementation that
    // took the lock for a status attach would leave the verb starvable by any
    // caller that omitted the flag, and this cell would not see it.
    request.session_sync = Some(SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: 2,
        protocol: 6,
        src_ip: "10.0.0.1".to_string(),
        dst_ip: "10.0.0.2".to_string(),
        src_port: 4321,
        dst_port: 80,
        egress_ifindex: 7,
        neighbor_mac: "02:bf:72:01:02:03".to_string(),
        src_mac: "02:bf:72:0a:0b:0c".to_string(),
        ..SessionSyncRequest::default()
    });

    // The barrier `apply_snapshot` would be sitting in. Held for the WHOLE
    // request, not merely overlapping its start: a guard released early would
    // let the old locked dispatch pass too.
    let blocker = state.lock().expect("state");

    let state_file = unique_state_file("sync_session_contention_7209");
    let (mut client, server) =
        std::os::unix::net::UnixStream::pair().expect("control socket pair");
    let running = Arc::new(AtomicBool::new(true));
    let (tx, rx) = mpsc::channel();
    let handler = {
        let state = state.clone();
        let state_file = state_file.clone();
        std::thread::spawn(move || {
            let result = handle_stream(server, &state_file, state, running, session_domain);
            let _ = tx.send(());
            result
        })
    };

    serde_json::to_writer(&mut client, &request).expect("write request");
    std::io::Write::write_all(&mut client, b"\n").expect("newline");

    // Well inside Go's 3 s round-trip budget, and generous enough that a loaded
    // CI box does not flake. The defect is an unbounded wait on a 10 s barrier,
    // so the gap between pass and fail is not marginal.
    let started = Instant::now();
    let served = rx.recv_timeout(Duration::from_secs(2));
    assert!(
        served.is_ok(),
        "a sync_session was NOT served while the ServerState mutex was held. \
         That is the defect: the HA session socket has its own thread (#452) but \
         dispatched through the snapshot-wide mutex, so an import arriving during \
         an apply_snapshot waits on a 10 s barrier against a 3 s deadline — and \
         #5380 drops the rest of the bulk batch behind it. Waited {:?}",
        started.elapsed()
    );

    let response: ControlResponse =
        serde_json::from_reader(std::io::BufReader::new(client)).expect("read response");
    assert!(
        response.ok,
        "the import must be APPLIED, not merely answered — a handler that \
         returned early without importing would satisfy the timing assertion \
         above while losing the session: {}",
        response.error
    );

    // And it really did land in the shared session map, read through the SAME
    // handle the off-lock dispatch used. Asserting on the response alone would
    // pass for a handler that acked without publishing.
    assert!(
        blocker.afxdp.session_domain().synced_entry_count() > 0,
        "the imported session must be present in the shared synced map while the \
         mutex is still held, which is what proves the import ran off-lock \
         rather than after this guard dropped"
    );

    drop(blocker);
    handler
        .join()
        .expect("handler thread")
        .expect("handler result");
    let _ = std::fs::remove_file(&state_file);
}

/// #8586 THE WIRING: the DELETE-replica counters must reach their own status
/// fields, and not each other's.
///
/// The protocol cell pins that the two fields SERIALIZE under distinct keys;
/// this pins that `refresh_status` fills them from the right sources. Both are
/// needed and neither implies the other — a `refresh_status` that assigned the
/// same accessor to both would leave the wire cell green while making
/// `dropped - repaired` (the unattributed remainder #8586 reads) identically 0.
///
/// Distinct increments so a transposition is visible; equal ones would let a
/// swap pass.
///
/// The counters are process-wide, so the deltas are measured against a read
/// taken in this same test binary — the same posture the #6751 cell above
/// takes, and `make test-rust` runs `--test-threads=1`.
#[test]
fn refresh_status_projects_the_delete_replica_counters_8586() {
    use std::sync::atomic::Ordering;

    let state = new_state(ProcessStatus::default());
    let mut guard = state.lock().expect("server state");

    let before_dropped =
        crate::afxdp::SESSION_DELETE_REPLICA_DROPPED.load(Ordering::Relaxed);
    let before_repaired =
        crate::afxdp::SESSION_DELETE_REPLICA_DROP_REPAIRED.load(Ordering::Relaxed);

    crate::afxdp::SESSION_DELETE_REPLICA_DROPPED.fetch_add(13, Ordering::Relaxed);
    crate::afxdp::SESSION_DELETE_REPLICA_DROP_REPAIRED
        .fetch_add(5, Ordering::Relaxed);

    refresh_status(&mut guard);

    assert_eq!(
        guard.status.session_delete_replica_dropped,
        before_dropped + 13,
        "the refused-delete counter must reach its own status field"
    );
    assert_eq!(
        guard.status.session_delete_replica_drop_repaired,
        before_repaired + 5,
        "the repaired-delete counter must reach its own status field, not the \
         drop counter's"
    );
    assert_eq!(
        guard.status.session_delete_replica_dropped
            - guard.status.session_delete_replica_drop_repaired,
        (before_dropped + 13) - (before_repaired + 5),
        "the UNATTRIBUTED remainder is the difference of the two; a refresh that \
         filled both from one accessor reports 0 here for a box that is losing \
         deletes and repairing none of them"
    );
}
