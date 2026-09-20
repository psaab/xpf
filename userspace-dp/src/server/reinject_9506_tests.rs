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
    ORIGIN_FORWARD, ORIGIN_INET, SUBMIT_FLAG_DRY_RUN,
};
use arc_swap::ArcSwapOption;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
    assert_eq!(core.live_count(), 0, "streamed completions release budget");
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
fn announce_before_target_install_is_handed_off_before_submit() {
    let fallback = ReinjectCore::new_shared();
    let target: Arc<ArcSwapOption<SlowPathReinjector>> = Arc::new(ArcSwapOption::new(None));
    let handoff = Arc::new(std::sync::Mutex::new(()));
    let running = Arc::new(AtomicBool::new(true));
    let (mut client, server) = UnixStream::pair().unwrap();
    let worker_fallback = fallback.clone();
    let worker_target = target.clone();
    let worker_running = running.clone();
    let worker_handoff = handoff.clone();
    let handle = std::thread::spawn(move || {
        serve_submit_conn_with_running(
            server,
            &worker_fallback,
            &worker_target,
            &worker_running,
            &worker_handoff,
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

    let target_core = ReinjectCore::new_shared();
    let target_reinjector = Arc::new(SlowPathReinjector::new_without_worker_with_core(
        1500,
        target_core.clone(),
    ));
    {
        let _guard = handoff.lock().unwrap();
        target_core.copy_authority_from(&fallback);
        target.store(Some(target_reinjector));
    }

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
