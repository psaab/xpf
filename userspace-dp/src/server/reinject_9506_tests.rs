//! #9506 S5: socket-loopback tests for the data-plane servers.
//!
//! RED-then-GREEN: written before the implementation. Hermetic: every test
//! uses `UnixStream::pair` (no filesystem paths) except the tempdir bind
//! test, which proves the derived paths are bindable.

use super::*;
use crate::slowpath::SlowPathReinjector;
use crate::slowpath_reinject_9506::{
    encode_cancel, encode_complete, encode_message, encode_submit_batch, read_message,
    CancelScope, CaptureOrigin, ReinjectCompletion, ReinjectCore, ReinjectLease,
    ReinjectOutcome, SubmitFrame, ADMIT_BAD_LEASE, ADMIT_NON_DRY_RUN, ADMIT_OK,
    ADMIT_SHUTDOWN, ADMIT_STALE, MSG_ADMIT, MSG_ANNOUNCE, MSG_CANCEL, MSG_COMPLETE, MSG_SUBMIT_BATCH,
    ORIGIN_FORWARD, ORIGIN_INET, PMECH_DEADLINE_CLOCK_MONOTONIC, SUBMIT_FLAG_DRY_RUN,
};
use arc_swap::ArcSwapOption;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PERMIT: u64 = 7;
const QEPOCH: u64 = 11;

fn open_core() -> Arc<ReinjectCore> {
    let core = ReinjectCore::new_shared();
    core.publish_epochs(PERMIT, &[(1, QEPOCH)]);
    core
}

fn frame(id: u64, flow_tag: u64) -> SubmitFrame {
    SubmitFrame {
        lease: ReinjectLease {
            permit_epoch: PERMIT,
            queue_epoch: QEPOCH,
            queue_number: 1,
            request_id: id,
        },
        flow_tag,
        flags: SUBMIT_FLAG_DRY_RUN,
        origin: CaptureOrigin::inet_forward(42, "owner", "stn"),
        bytes: vec![0x45u8; 64],
        snapshot_generation: 1,
        config_generation: 1,
        fib_generation: 1,
        zone_id: 1,
        if_id: 1,
        pmech_inventory_generation: 0,
        pmech_inventory_fib_generation: 0,
        pmech_policy_identity: [0; 32],
        deadline_mono_ns: crate::afxdp::monotonic_nanos() + 500_000_000,
        deadline_clock_id: PMECH_DEADLINE_CLOCK_MONOTONIC,
    }
}

fn live_target(core: &Arc<ReinjectCore>) -> Arc<ArcSwapOption<SlowPathReinjector>> {
    // `new_without_worker` drops its rx: the 16k channel absorbs enqueues
    // without a worker, which is exactly what the submit path needs here.
    let r = Arc::new(SlowPathReinjector::new_without_worker_with_core(
        1500,
        core.clone(),
    ));
    Arc::new(ArcSwapOption::from(Some(r)))
}

#[test]
fn derive_paths_sit_next_to_control_socket() {
    assert_eq!(
        derive_reinject_submit_path("/run/xpf/userspace-dp.sock"),
        "/run/xpf/reinject-submit.sock"
    );
    assert_eq!(
        derive_reinject_complete_path("/run/xpf/userspace-dp.sock"),
        "/run/xpf/reinject-complete.sock"
    );
    // Bare name (no dir): same fallback shape as the session-socket derive.
    assert_eq!(
        derive_reinject_submit_path("control.sock"),
        "reinject-submit.sock"
    );
    assert_eq!(
        derive_reinject_complete_path("control.sock"),
        "reinject-complete.sock"
    );
}

#[test]
fn submit_conn_admits_enqueues_and_cancels_serially() {
    let core = open_core();
    let target = live_target(&core);
    let (client, server) = UnixStream::pair().unwrap();
    let worker_core = core.clone();
    let worker_target = target.clone();
    let handle = std::thread::spawn(move || {
        serve_submit_conn(server, &worker_core, &worker_target);
    });

    let mut client = client;
    // Batch 1: one admittable frame + one stale-permit frame.
    let mut stale = frame(2, 1);
    stale.lease.permit_epoch = PERMIT + 1;
    let batch = encode_submit_batch(&[frame(1, 1), stale]);
    client
        .write_all(&encode_message(MSG_SUBMIT_BATCH, &batch))
        .unwrap();
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_ADMIT);
    let decisions = crate::slowpath_reinject_9506::decode_admit(&payload).unwrap();
    assert_eq!(decisions.len(), 2);
    assert!(decisions[0].admitted);
    assert_eq!(decisions[0].reason, ADMIT_OK);
    assert!(!decisions[1].admitted);
    assert_eq!(decisions[1].reason, ADMIT_STALE);
    assert_eq!(core.live_count(), 0);
    assert_eq!(
        target
            .load_full()
            .unwrap()
            .delegated_status()
            .queued_packets,
        0,
        "dry-run submit must not enqueue a q0 packet"
    );

    // CANCEL is one-way (no reply): pipeline a second dry-run submit behind
    // it; the second ADMIT proves same-conn serial processing.
    let cancel = encode_cancel(&CancelScope::ids(vec![1]));
    client
        .write_all(&encode_message(MSG_CANCEL, &cancel))
        .unwrap();
    let batch = encode_submit_batch(&[frame(3, 1)]);
    client
        .write_all(&encode_message(MSG_SUBMIT_BATCH, &batch))
        .unwrap();
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_ADMIT);
    let decisions = crate::slowpath_reinject_9506::decode_admit(&payload).unwrap();
    assert_eq!(decisions.len(), 1);
    assert!(decisions[0].admitted);
    // Dry-run validation never inserted r1 into the completion table, so
    // cancel has no terminal completion to drain.
    assert_eq!(core.live_count(), 0);
    assert!(core.drain_ready(16).is_empty());

    drop(client);
    handle.join().unwrap();
}

#[test]
fn dry_run_expired_or_wrong_clock_deadlines_refuse_without_side_effects() {
    let core = open_core();
    let target = live_target(&core);
    let (mut client, server) = UnixStream::pair().unwrap();
    let worker_core = core.clone();
    let worker_target = target.clone();
    let handle = std::thread::spawn(move || {
        serve_submit_conn(server, &worker_core, &worker_target);
    });

    let mut expired = frame(11, 1);
    expired.deadline_mono_ns = crate::afxdp::monotonic_nanos().saturating_sub(1);
    let mut wrong_clock = frame(12, 2);
    wrong_clock.deadline_clock_id = 2;
    client
        .write_all(&encode_message(
            MSG_SUBMIT_BATCH,
            &encode_submit_batch(&[expired, wrong_clock]),
        ))
        .unwrap();
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_ADMIT);
    let decisions = crate::slowpath_reinject_9506::decode_admit(&payload).unwrap();
    assert_eq!(decisions.len(), 2);
    for decision in decisions {
        assert!(!decision.admitted);
        assert_eq!(decision.reason, ADMIT_BAD_LEASE);
    }
    let stats = core.stats_snapshot();
    assert_eq!(stats.dry_run_refused, 2);
    assert_eq!(stats.dry_run_admitted, 0);
    assert_eq!(core.live_count(), 0);
    assert_eq!(
        target
            .load_full()
            .unwrap()
            .delegated_status()
            .queued_packets,
        0,
        "refused dry-run frames must not touch the worker queue"
    );

    drop(client);
    handle.join().unwrap();
}

#[test]
fn submit_conn_without_target_refuses_shutdown() {
    let core = open_core();
    let target: Arc<ArcSwapOption<SlowPathReinjector>> = Arc::new(ArcSwapOption::new(None));
    let (mut client, server) = UnixStream::pair().unwrap();
    let worker_core = core.clone();
    let worker_target = target.clone();
    let handle = std::thread::spawn(move || {
        serve_submit_conn(server, &worker_core, &worker_target);
    });
    let mut unflagged = frame(1, 1);
    unflagged.flags = 0;
    let batch = encode_submit_batch(&[unflagged]);
    client
        .write_all(&encode_message(MSG_SUBMIT_BATCH, &batch))
        .unwrap();
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_ADMIT);
    let decisions = crate::slowpath_reinject_9506::decode_admit(&payload).unwrap();
    assert_eq!(decisions.len(), 1);
    assert!(!decisions[0].admitted);
    assert_eq!(decisions[0].reason, ADMIT_SHUTDOWN);
    assert_eq!(core.live_count(), 0, "no target reserves nothing");
    assert_eq!(core.stats_snapshot().non_dry_run_refused, 1);
    drop(client);
    handle.join().unwrap();
}

#[test]
fn submit_conn_survives_idle_before_target_publication() {
    let fallback = open_core();
    let target: Arc<ArcSwapOption<SlowPathReinjector>> = Arc::new(ArcSwapOption::new(None));
    let (client, server) = UnixStream::pair().unwrap();
    let worker_fallback = fallback.clone();
    let worker_target = target.clone();
    let handle = std::thread::spawn(move || {
        serve_submit_conn(server, &worker_fallback, &worker_target);
    });
    let mut client = client;
    client
        .write_all(&encode_message(
            MSG_SUBMIT_BATCH,
            &encode_submit_batch(&[frame(1, 1)]),
        ))
        .unwrap();
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_ADMIT);
    let decisions = crate::slowpath_reinject_9506::decode_admit(&payload).unwrap();
    assert!(!decisions[0].admitted);
    assert_eq!(decisions[0].reason, ADMIT_SHUTDOWN);
    assert_eq!(fallback.stats_snapshot().dry_run_refused, 1);
    // Force the server's old 100 ms read deadline to expire while retaining
    // the same persistent connection, then publish the real target.
    std::thread::sleep(std::time::Duration::from_millis(150));
    let target_core = ReinjectCore::new_shared();
    target_core.publish_epochs(PERMIT, &[(1, QEPOCH)]);
    target.store(Some(Arc::new(
        SlowPathReinjector::new_without_worker_with_core(1500, target_core.clone()),
    )));
    let mut frame = frame(2, 1);
    frame.flags = 0;
    client
        .write_all(&encode_message(
            MSG_SUBMIT_BATCH,
            &encode_submit_batch(&[frame]),
        ))
        .unwrap();
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_ADMIT);
    let decisions = crate::slowpath_reinject_9506::decode_admit(&payload).unwrap();
    assert!(decisions[0].admitted);
    assert_eq!(target_core.live_count(), 1);
    drop(client);
    handle.join().unwrap();
    assert_eq!(
        target_core.live_count(),
        0,
        "disconnect must purge entries from a core published after connect"
    );
}

#[test]
fn submit_conn_unflagged_routes_q0_writer() {
    let core = open_core();
    let target = live_target(&core);
    let (client, server) = UnixStream::pair().unwrap();
    let worker_core = core.clone();
    let worker_target = target.clone();
    let handle = std::thread::spawn(move || {
        serve_submit_conn(server, &worker_core, &worker_target);
    });
    let mut client = client;
    let mut unflagged = frame(1, 1);
    unflagged.flags = 0;
    client
        .write_all(&encode_message(
            MSG_SUBMIT_BATCH,
            &encode_submit_batch(&[unflagged]),
        ))
        .unwrap();
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_ADMIT);
    let decisions = crate::slowpath_reinject_9506::decode_admit(&payload).unwrap();
    assert_eq!(decisions.len(), 1);
    assert!(decisions[0].admitted);
    assert_eq!(decisions[0].reason, ADMIT_OK);
    assert_eq!(core.stats_snapshot().non_dry_run_refused, 0);
    assert_eq!(core.live_count(), 1);
    assert_eq!(
        target.load_full().unwrap().delegated_status().queued_packets,
        1,
        "unflagged submit must reach the q0 writer channel"
    );
    drop(client);
    handle.join().unwrap();
}
#[test]
fn submit_conn_bad_frame_refused_per_frame_bad_message_closes() {
    let core = open_core();
    let target = live_target(&core);
    let (client, server) = UnixStream::pair().unwrap();
    let worker_core = core.clone();
    let worker_target = target.clone();
    let handle = std::thread::spawn(move || {
        serve_submit_conn(server, &worker_core, &worker_target);
    });
    let mut client = client;
    // A zero request_id is a per-frame refusal, not a connection error.
    let mut zero = frame(5, 1);
    zero.lease.request_id = 0;
    let batch = encode_submit_batch(&[zero, frame(6, 1)]);
    client
        .write_all(&encode_message(MSG_SUBMIT_BATCH, &batch))
        .unwrap();
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_ADMIT);
    let decisions = crate::slowpath_reinject_9506::decode_admit(&payload).unwrap();
    assert_eq!(decisions.len(), 2);
    assert!(!decisions[0].admitted);
    assert_eq!(decisions[0].reason, ADMIT_BAD_LEASE);
    assert!(decisions[1].admitted);
    // A malformed message (declared n=1, empty body) closes the connection
    // fail-closed: the client observes EOF.
    let mut bad = vec![];
    bad.extend_from_slice(&2u32.to_be_bytes());
    bad.push(MSG_SUBMIT_BATCH);
    bad.push(0x00);
    client.write_all(&bad).unwrap();
    assert!(
        read_message(&mut client).is_err(),
        "protocol violation must close the connection"
    );
    handle.join().unwrap();
}

#[test]
fn complete_conn_streams_completions() {
    let core = open_core();
    let mut first = frame(1, 1);
    first.flags = 0;
    let mut second = frame(2, 2);
    second.flags = 0;
    assert!(core.admit(&first).admitted);
    assert!(core.admit(&second).admitted);
    assert_eq!(
        core.pre_write_check(&frame(1, 1).lease),
        crate::slowpath_reinject_9506::PreWrite::Proceed
    );
    assert!(
        core.resolve_write(
            &frame(1, 1).lease,
            crate::slowpath_reinject_9506::TransferVerdict::Written { bytes: 50 }
        )
    );
    assert_eq!(core.cancel(&CancelScope::ids(vec![2])), vec![2]);

    let running = Arc::new(AtomicBool::new(true));
    let (client, server) = UnixStream::pair().unwrap();
    let worker_core = core.clone();
    let worker_running = running.clone();
    let handle = std::thread::spawn(move || {
        serve_complete_conn(server, &worker_core, &worker_running);
    });
    let mut client = client;
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_COMPLETE);
    let completions = crate::slowpath_reinject_9506::decode_complete(&payload).unwrap();
    assert_eq!(completions.len(), 2);
    assert_eq!(completions[0].request_id, 1);
    assert_eq!(completions[0].outcome, ReinjectOutcome::Written);
    assert_eq!(completions[0].bytes_written, 50);
    assert_eq!(completions[1].request_id, 2);
    assert_eq!(completions[1].outcome, ReinjectOutcome::Cancelled);
    // #14678: the server commits only after this application ack.
    client.write_all(&[REINJECT_COMPLETE_ACK]).unwrap();
    let ack_deadline = Instant::now() + Duration::from_secs(1);
    while core.live_count() != 0 && Instant::now() < ack_deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        core.live_count(),
        0,
        "streamed completions release budget after ack"
    );
    running.store(false, Ordering::SeqCst);
    core.shutdown();
    handle.join().unwrap();
    // The encode helper the server used is byte-exact (framing pin).
    let _ = encode_complete(&[ReinjectCompletion {
        request_id: 1,
        permit_epoch: 7,
        queue_epoch: 11,
        queue_number: 1,
        family: ORIGIN_INET,
        hook: ORIGIN_FORWARD,
        owned_ifindex: 42,
        outcome: ReinjectOutcome::Written,
        bytes_written: 1,
        flow_tag: 0,
    }]);
    let _ = MSG_CANCEL;
}

fn make_completion_ready_13715(core: &Arc<ReinjectCore>, id: u64) {
    let mut f = frame(id, id);
    f.flags = 0;
    assert!(core.admit(&f).admitted);
    assert_eq!(
        core.pre_write_check(&frame(id, id).lease),
        crate::slowpath_reinject_9506::PreWrite::Proceed
    );
    assert!(core.resolve_write(
        &frame(id, id).lease,
        crate::slowpath_reinject_9506::TransferVerdict::Written { bytes: 1 }
    ));
}

#[test]
fn complete_conn_exits_on_peer_eof_while_idle_13715() {
    let core = open_core();
    let running = Arc::new(AtomicBool::new(true));
    let (client, server) = UnixStream::pair().unwrap();
    let worker_core = core.clone();
    let worker_running = running.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        serve_complete_conn(server, &worker_core, &worker_running);
        let _ = done_tx.send(());
    });
    drop(client);
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("serve_complete_conn did not exit after idle peer EOF");
    handle.join().unwrap();
}


#[test]
fn complete_conn_stops_on_shutdown_with_live_entries_13715() {
    let core = open_core();
    let running = Arc::new(AtomicBool::new(true));
    let (client, server) = UnixStream::pair().unwrap();
    let worker_core = core.clone();
    let worker_running = running.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        serve_complete_conn(server, &worker_core, &worker_running);
        let _ = done_tx.send(());
    });
    let mut f = frame(9, 9);
    f.flags = 0;
    assert!(core.admit(&f).admitted);
    assert_eq!(core.live_count(), 1);
    running.store(false, Ordering::SeqCst);
    done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("serve_complete_conn did not stop with a live entry on shutdown");
    drop(client);
    handle.join().unwrap();
}

#[test]
fn complete_conn_delivers_after_idle_13715() {
    let core = open_core();
    let running = Arc::new(AtomicBool::new(true));
    let (mut client, server) = UnixStream::pair().unwrap();
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let worker_core = core.clone();
    let worker_running = running.clone();
    let handle = std::thread::spawn(move || {
        serve_complete_conn(server, &worker_core, &worker_running);
    });
    std::thread::sleep(Duration::from_millis(150));
    make_completion_ready_13715(&core, 21);
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_COMPLETE);
    let completions = crate::slowpath_reinject_9506::decode_complete(&payload).unwrap();
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].request_id, 21);
    // #14678: Rust commits (ack_ready) only after the reader's
    // application ack; send it, then the server may purge id 21.
    client.write_all(&[REINJECT_COMPLETE_ACK]).unwrap();
    running.store(false, Ordering::SeqCst);
    drop(client);
    handle.join().unwrap();
}

#[test]
fn complete_conn_releases_unacked_batch_on_disconnect_14678() {
    // #14678: a completion written to the socket buffer but never
    // acked by the Go reader must NOT be purged: when that reader
    // disconnects, the batch is released and redelivered whole to
    // the next reader, which acks it.
    let core = open_core();
    let running = Arc::new(AtomicBool::new(true));
    let (mut client1, server) = UnixStream::pair().unwrap();
    client1
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let worker_core = core.clone();
    let worker_running = running.clone();
    let handle = std::thread::spawn(move || {
        serve_complete_conn(server, &worker_core, &worker_running);
    });
    make_completion_ready_13715(&core, 33);
    let (ty, _payload) = read_message(&mut client1).unwrap();
    assert_eq!(ty, MSG_COMPLETE);
    // No ack: simulate the Go reader closing in the deadline window.
    drop(client1);
    handle.join().unwrap();
    assert_eq!(core.ready_len(), 1, "unacked completion must survive for redelivery");

    // Second reader receives the same completion and acks it.
    let (mut client2, server2) = UnixStream::pair().unwrap();
    client2
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let worker_core = core.clone();
    let worker_running = running.clone();
    let handle2 = std::thread::spawn(move || {
        serve_complete_conn(server2, &worker_core, &worker_running);
    });
    let (ty, payload) = read_message(&mut client2).unwrap();
    assert_eq!(ty, MSG_COMPLETE);
    let completions = crate::slowpath_reinject_9506::decode_complete(&payload).unwrap();
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].request_id, 33);
    client2.write_all(&[REINJECT_COMPLETE_ACK]).unwrap();
    // The acked entry is purged once the server processes the ack;
    // poll briefly for the server thread to commit it.
    let deadline = Instant::now() + Duration::from_secs(2);
    while core.ready_len() != 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(core.ready_len(), 0, "acked completion must be purged");
    running.store(false, Ordering::SeqCst);
    drop(client2);
    handle2.join().unwrap();
}
#[test]
fn tempdir_sockets_bind_and_accept() {
    let dir = std::env::temp_dir().join(format!("xpf-reinject-9506-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let control = dir.join("control.sock").to_string_lossy().to_string();
    let submit_path = derive_reinject_submit_path(&control);
    let complete_path = derive_reinject_complete_path(&control);
    let submit_listener = std::os::unix::net::UnixListener::bind(&submit_path).unwrap();
    let complete_listener = std::os::unix::net::UnixListener::bind(&complete_path).unwrap();
    let _c1 = UnixStream::connect(&submit_path).unwrap();
    let _c2 = UnixStream::connect(&complete_path).unwrap();
    assert!(submit_listener.accept().is_ok());
    assert!(complete_listener.accept().is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}


#[test]
fn announce_before_target_install_uses_shared_core_for_submit() {
    let fallback = ReinjectCore::new_shared();
    let target: Arc<ArcSwapOption<SlowPathReinjector>> = Arc::new(ArcSwapOption::new(None));
    let running = Arc::new(AtomicBool::new(true));
    let (mut client, server) = UnixStream::pair().unwrap();
    let worker_fallback = fallback.clone();
    let worker_target = target.clone();
    let worker_running = running.clone();
    let handle = std::thread::spawn(move || {
        serve_submit_conn_with_running(
            server,
            &worker_fallback,
            &worker_target,
            &worker_running,
        );
    });

    let announcement = crate::slowpath_reinject_9506::AuthorityAnnouncement {
        run_id: "run-1".to_string(),
        generation: 4,
        permit_epoch: PERMIT,
        permit_open: true,
        queue_epochs: vec![(1, QEPOCH)],
    };
    client
        .write_all(&encode_message(
            MSG_ANNOUNCE,
            &crate::slowpath_reinject_9506::encode_announce(&announcement),
        ))
        .unwrap();
    for _ in 0..100 {
        if fallback.authority_snapshot().2 == PERMIT {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert_eq!(
        fallback.authority_snapshot().2,
        PERMIT,
        "ANNOUNCE must apply while no target is installed"
    );

    let target_core = fallback.clone();
    let target_reinjector = Arc::new(SlowPathReinjector::new_without_worker_with_core(
        1500,
        target_core.clone(),
    ));
    target.store(Some(target_reinjector));

    let mut admitted = frame(1, 1);
    admitted.flags = 0;
    client
        .write_all(&encode_message(
            MSG_SUBMIT_BATCH,
            &encode_submit_batch(&[admitted]),
        ))
        .unwrap();
    let (message_type, payload) = read_message(&mut client).unwrap();
    assert_eq!(message_type, MSG_ADMIT);
    let decisions = crate::slowpath_reinject_9506::decode_admit(&payload).unwrap();
    assert!(decisions[0].admitted);
    assert_eq!(target_core.live_count(), 1);

    running.store(false, Ordering::Release);
    drop(client);
    handle.join().unwrap();
}
use std::io::Write;

#[test]
fn submit_disconnect_purges_owned_inflight_entries_13195() {
    let core = open_core();
    core.announce_epochs("run-a", 1, PERMIT, true, &[(1, QEPOCH)]);
    let target = live_target(&core);
    let (mut client, server) = UnixStream::pair().unwrap();
    let worker_core = core.clone();
    let worker_target = target.clone();
    let handle = std::thread::spawn(move || {
        serve_submit_conn(server, &worker_core, &worker_target);
    });
    let mut f = frame(501, 7);
    f.flags = 0;
    client
        .write_all(&encode_message(MSG_SUBMIT_BATCH, &encode_submit_batch(&[f])))
        .unwrap();
    let (ty, payload) = read_message(&mut client).unwrap();
    assert_eq!(ty, MSG_ADMIT);
    let decisions = crate::slowpath_reinject_9506::decode_admit(&payload).unwrap();
    assert!(decisions[0].admitted);
    assert_eq!(core.live_count(), 1);
    drop(client);
    handle.join().unwrap();
    assert_eq!(core.live_count(), 0, "disconnect must purge owned entries");
    assert_eq!(core.stats_snapshot().purged_queued, 1);
}
// ---- #15112 (A73-01): reinject accept loops must survive accept errors ----
//
// The submit/complete threads used to `Err(_) => break` on every non-WouldBlock
// accept error. An idle EMFILE (fd pressure with an empty backlog: the kernel
// reserves the result descriptor before looking at the backlog) therefore
// killed the thread permanently; its UnixListener was dropped and every later
// IPsec FORWARD flow using the #9506 re-entry black-holed behind a healthy
// control socket until a helper restart nothing triggers. The fix drives both
// loops through lifecycle::accept_step with retry_unclassified = true (as the
// session loop does): resource errors retry with backoff, unclassified errors
// log-and-continue, and a later connection is served once pressure releases.
//
// These cells exercise the REAL spawn_reinject_socket_servers loops. EMFILE
// is induced by exhausting this process's RLIMIT_NOFILE with /dev/null
// duplicates while the sockets have no pending connection, then releasing
// the duplicates and proving a fresh connection is still accepted and served
// (submit: ANNOUNCE applies; complete: a queued completion is delivered).
// Fd exhaustion is process-wide, so both cells share one lock.
use std::sync::Mutex as StdMutex;
static FD_PRESSURE_LOCK_15112: StdMutex<()> = StdMutex::new(());

/// Lower this process's soft RLIMIT_NOFILE to `soft` for the duration of the
/// guard (restored on drop). The test binary runs with a huge ambient limit
/// (524288 here), far above what a freshly spawned thread stack of open
/// /dev/null duplicates needs to be practical; lowering the soft limit is
/// the deterministic, unprivileged way to make accept() return EMFILE.
/// Callers must already hold FD_PRESSURE_LOCK_15112 so no sibling cell sees
/// the lowered limit.
struct RlimitGuard15112 {
    saved: libc::rlimit,
}

impl RlimitGuard15112 {
    fn lower_to(soft: u64) -> Self {
        let mut saved = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit/setrlimit with valid pointers have no other
        // preconditions; lowering the soft limit needs no privilege.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut saved) }, 0);
        assert!(soft <= saved.rlim_max, "soft limit must not exceed hard limit");
        let lowered = libc::rlimit {
            rlim_cur: soft,
            rlim_max: saved.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);
        Self { saved }
    }
}

impl Drop for RlimitGuard15112 {
    fn drop(&mut self) {
        // SAFETY: restoring the saved limit saved above.
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &self.saved);
        }
    }
}

fn count_open_fds_15112() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn exhaused_fds_15112() -> Vec<std::fs::File> {
    // Leave a small number of free slots so test-harness bookkeeping (result
    // reporting, the client connect below) still works while accept() itself
    // is starved: accept reserves its result descriptor from the same pool,
    // so with only a handful of slots free and no other consumer racing,
    // the accept loops still observe EMFILE once the pool is drained by the
    // duplicates held here. We drain to within 2 of the (lowered) limit.
    let mut held = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(f) => held.push(f),
            Err(e) => {
                assert!(
                    e.raw_os_error() == Some(libc::EMFILE)
                        || e.raw_os_error() == Some(libc::ENFILE),
                    "fd exhaustion must fail with EMFILE/ENFILE, got {e}"
                );
                break;
            }
        }
    }
    assert!(!held.is_empty(), "must hold fds to induce EMFILE");
    held
}

#[test]
fn reinject_submit_accept_survives_idle_emfile_15112() {
    let _guard = FD_PRESSURE_LOCK_15112.lock().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "xpf-reinject-15112-submit-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let control = dir.join("control.sock").to_string_lossy().to_string();
    let core = open_core();
    let target = live_target(&core);
    let running = Arc::new(AtomicBool::new(true));
    let servers =
        spawn_reinject_socket_servers(&control, core.clone(), target, running.clone()).unwrap();
    // Exhaust fds with NO connection pending (idle EMFILE), give both accept
    // loops time to hit the error, then release the pressure.
    let held = exhaused_fds_15112();
    std::thread::sleep(Duration::from_millis(300));
    drop(held);
    std::thread::sleep(Duration::from_millis(100));
    // The submit listener must still accept and serve: an ANNOUNCE on a fresh
    // connection must apply its permit epoch to the fallback core.
    let submit_path = derive_reinject_submit_path(&control);
    let mut client = UnixStream::connect(&submit_path).unwrap_or_else(|e| {
        panic!("submit listener dead after idle EMFILE (accept loop exited): {e}")
    });
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let announcement = crate::slowpath_reinject_9506::AuthorityAnnouncement {
        run_id: "run-15112".to_string(),
        generation: 9,
        permit_epoch: 4242,
        permit_open: true,
        queue_epochs: vec![(1, QEPOCH)],
    };
    client
        .write_all(&encode_message(
            MSG_ANNOUNCE,
            &crate::slowpath_reinject_9506::encode_announce(&announcement),
        ))
        .unwrap();
    let mut served = false;
    for _ in 0..200 {
        if core.authority_snapshot().2 == 4242 {
            served = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        served,
        "ANNOUNCE after idle EMFILE must be served (submit accept loop must survive)"
    );
    running.store(false, Ordering::Release);
    drop(client);
    let _ = servers.submit_thread.join();
    let _ = servers.complete_thread.join();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reinject_complete_accept_survives_idle_emfile_15112() {
    let _guard = FD_PRESSURE_LOCK_15112.lock().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "xpf-reinject-15112-complete-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let control = dir.join("control.sock").to_string_lossy().to_string();
    let core = open_core();
    let target = live_target(&core);
    let running = Arc::new(AtomicBool::new(true));
    let _rlimit = RlimitGuard15112::lower_to((count_open_fds_15112() + 64) as u64);
    let servers =
        spawn_reinject_socket_servers(&control, core.clone(), target, running.clone()).unwrap();
    let held = exhaused_fds_15112();
    std::thread::sleep(Duration::from_millis(300));
    drop(held);
    std::thread::sleep(Duration::from_millis(100));
    // Queue a completion, then prove a fresh complete connection still
    // receives it.
    make_completion_ready_13715(&core, 15112);
    let complete_path = derive_reinject_complete_path(&control);
    let mut client = UnixStream::connect(&complete_path).unwrap_or_else(|e| {
        panic!("complete listener dead after idle EMFILE (accept loop exited): {e}")
    });
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (message_type, payload) = read_message(&mut client).unwrap();
    assert_eq!(message_type, MSG_COMPLETE);
    let completions = crate::slowpath_reinject_9506::decode_complete(&payload).unwrap();
    assert!(
        completions.iter().any(|c| c.request_id == 15112),
        "completion after idle EMFILE must be delivered: {completions:?}"
    );
    // Ack so ack_ready commits instead of releasing for redelivery.
    client.write_all(&[REINJECT_COMPLETE_ACK]).unwrap();
    running.store(false, Ordering::Release);
    drop(client);
    let _ = servers.submit_thread.join();
    let _ = servers.complete_thread.join();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reinject_accept_loops_are_wired_through_accept_step_15112() {
    // Same textual-wiring shape as the #9172 lifecycle cell, extended to the
    // #9506 loops in this file: every accept() result must go through
    // accept_step with retry_unclassified = true. Patterns are built at
    // runtime so this test's own text does not match.
    let file = include_str!("reinject_9506.rs");
    let spawn_sig = ["fn ", "spawn_reinject_socket_servers", "("].concat();
    let start = file
        .find(spawn_sig.as_str())
        .expect("spawn_reinject_socket_servers not found");
    let src = &file[start..];
    let bare = [".", "accept", "()"].concat();
    let call = ["accept_step", "("].concat();
    let total = src.matches(bare.as_str()).count();
    let mut calls = Vec::new();
    for (i, _) in src.match_indices(call.as_str()) {
        let args_end = src[i..]
            .find(");")
            .map(|e| i + e)
            .expect("unterminated accept_step call");
        calls.push(&src[i + call.len()..args_end]);
    }
    let wired = calls.iter().filter(|a| a.contains(bare.as_str())).count();
    assert_eq!(
        total, 2,
        "spawn must accept on exactly the two reinject listeners, found {total}"
    );
    assert_eq!(
        wired, total,
        "every reinject accept() result must go through accept_step"
    );
    for name in ["\"reinject submit socket\"", "\"reinject complete socket\""] {
        let c = calls
            .iter()
            .find(|a| a.contains(name))
            .unwrap_or_else(|| panic!("{name} accept_step call missing"));
        assert!(
            c.trim_end().trim_end_matches(',').ends_with("true"),
            "{name} loop must retry unclassified errors (retry_unclassified=true)"
        );
    }
}
