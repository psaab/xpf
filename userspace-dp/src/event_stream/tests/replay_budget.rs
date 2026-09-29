// Sequence-number allocation, replay-buffer trim/eviction, telemetry
// queue-budget hold/release, and lossless-producer seq accounting tests.
// Split from event_stream/tests.rs (#4664).

use super::*;

// #5267: build a header-only SESSION_OPEN wire frame carrying `seq`. Used as a
// realistic session-sync backlog delta whose seq must be ordered below the
// replay-gap FullResync barrier on the wire.
fn session_open_frame(seq: u64) -> EventFrame {
    let mut data = [0u8; super::codec::EVENT_FRAME_CAPACITY];
    data[4] = super::codec::MSG_SESSION_OPEN;
    data[8..16].copy_from_slice(&seq.to_le_bytes());
    EventFrame {
        data,
        len: FRAME_HEADER_SIZE as u16,
        seq,
    }
}

#[test]
fn test_sequence_monotonicity() {
    let shared = Arc::new(EventStreamShared::new());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let s = shared.clone();
            std::thread::spawn(move || {
                let mut seqs = Vec::with_capacity(100);
                for _ in 0..100 {
                    let seq = s.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
                    seqs.push(seq);
                }
                seqs
            })
        })
        .collect();

    let mut all_seqs: Vec<u64> = Vec::new();
    for h in handles {
        all_seqs.extend(h.join().unwrap());
    }
    all_seqs.sort();
    all_seqs.dedup();
    // All 400 sequences should be unique
    assert_eq!(all_seqs.len(), 400);
    // Should be 1..=400
    assert_eq!(*all_seqs.first().unwrap(), 1);
    assert_eq!(*all_seqs.last().unwrap(), 400);
}

#[test]
fn test_replay_buffer_trim() {
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Add 10 frames with seq 1..=10
    for seq in 1..=10u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    assert_eq!(replay_buf.len(), 10);

    // Simulate Ack seq=5: trim frames <= 5
    let acked_seq = 5u64;
    while let Some(front) = replay_buf.front() {
        if front.seq <= acked_seq {
            replay_buf.pop_front();
        } else {
            break;
        }
    }
    assert_eq!(replay_buf.len(), 5);
    assert_eq!(replay_buf.front().unwrap().seq, 6);
}

#[test]
fn test_replay_gap_at_zero_ack_sends_full_resync() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Simulate a replay buffer overrun before the daemon ever ACKed anything:
    // seq 1 has been trimmed, so replaying seq 2.. would silently lose the
    // first audit/session event unless the helper requests FullResync.
    for seq in 2..=REPLAY_BUFFER_CAPACITY as u64 + 1 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }

    // #5267: the gap branch no longer writes the FullResync directly to the
    // socket. It allocates the barrier's seq under `producer_seq_lock` and PARKS
    // it in `pending_resync`; the connected loop's drain emits it in seq order.
    let mut pending_resync: Option<EventFrame> = None;
    replay_buffered(
        &helper_side,
        &mut replay_buf,
        0,
        &shared,
        &mut pending_resync,
    )
    .expect("replay gap");
    {
        let barrier = pending_resync
            .as_ref()
            .expect("gap must park a FullResync barrier");
        assert_eq!(barrier.as_bytes()[4], MSG_FULL_RESYNC);
    }
    assert_eq!(
        shared.frames_sent.load(Ordering::Relaxed),
        0,
        "parking the barrier must NOT count it as sent until it is flushed"
    );
    assert_eq!(
        replay_buf.front().map(|f| f.seq),
        Some(2),
        "full resync keeps stale replay window until the daemon ACKs"
    );

    // Drain an empty channel: the parked barrier flushes into the write path in
    // order (it is the current max seq) and reaches the socket.
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(8);
    let mut write_buf = WriteBacklog::with_capacity(4096);
    let outcome = drain_channel_into_write_buf(
        &rx,
        &shared,
        &mut replay_buf,
        &mut write_buf,
        false,
        &mut pending_resync,
    );
    assert!(outcome.drained_any, "flushing the barrier is output");
    assert!(pending_resync.is_none(), "barrier consumed on flush");
    (&helper_side)
        .set_nonblocking(false)
        .expect("blocking for the write");
    (&helper_side)
        .write_all(write_buf.pending())
        .expect("write barrier");

    let mut hdr = [0u8; FRAME_HEADER_SIZE];
    daemon_side.read_exact(&mut hdr).expect("full resync frame");
    assert_eq!(hdr[4], MSG_FULL_RESYNC);
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 1);
}

// #5267 fail-on-revert guard: a replay-gap FullResync must be written to the
// wire AFTER every lower-seq session delta already queued in the channel — wire
// order == seq order. The old gap branch allocated the barrier's seq with a
// bare `fetch_add` and wrote it DIRECTLY to the socket, ahead of the still-
// queued lower-seq deltas the connected loop drains later, so a HIGHER seq
// landed on the wire before a LOWER one. The Go reader (zero reorder tolerance)
// then diagnoses a session gap on the first post-barrier delta, drops the
// connection, and churns resyncs on the very HA-recovery barrier.
//
// This drives the exact interleave deterministically: three session deltas
// (seq 11,12,13) are committed to the channel during a disconnect, then a
// replay-buffer hole (empty buffer, acked=10) forces the FullResync (seq 14).
// The assertion is that the emitted wire order is strictly monotonic by seq
// with the FullResync LAST. Reverting the fix (direct out-of-lock write in
// `replay_buffered`) writes seq 14 to the socket before 11,12,13 -> the socket
// read loop sees 14 first, expects 11 -> RED.
#[test]
fn test_full_resync_orders_after_channel_backlog_5267() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();

    let capacity = 64;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(EventStreamShared::new());

    // The daemon ACKed through seq 10, but the replay buffer was fully evicted
    // (empty + acked>0) -> a genuine hole -> the gap branch fires. `next_seq`
    // reflects the deltas already allocated (through 13), so the FullResync
    // takes seq 14.
    shared.acked_seq.store(10, Ordering::Release);
    shared.next_seq.store(13, Ordering::Release);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Backlog: session-sync deltas committed to the channel during the
    // disconnect, all with seqs strictly BELOW the imminent FullResync (14).
    for seq in 11..=13u64 {
        tx.try_send(session_open_frame(seq)).expect("seed backlog");
    }

    // Gap branch: the FIX parks a FullResync barrier (seq 14, allocated under
    // the producer lock) instead of writing it. A revert to the old out-of-lock
    // direct write instead pushes seq 14 straight to the socket HERE — ahead of
    // the still-queued backlog — which is the inversion this guards.
    let mut pending_resync: Option<EventFrame> = None;
    replay_buffered(
        &helper_side,
        &mut replay_buf,
        10,
        &shared,
        &mut pending_resync,
    )
    .expect("replay gap");

    // Drain the backlog. Under the fix the drain merges the parked barrier LAST,
    // so write_buf holds 11,12,13,14 in order; under a revert the barrier is not
    // parked and write_buf holds only 11,12,13 (14 is already on the socket).
    let mut write_buf = WriteBacklog::with_capacity(4096);
    let _ = drain_channel_into_write_buf(
        &rx,
        &shared,
        &mut replay_buf,
        &mut write_buf,
        false,
        &mut pending_resync,
    );

    // Flush whatever the drain produced, then read the FULL wire in order. This
    // is the #5267 ordering invariant, observed on the real socket: every seq is
    // strictly increasing and the higher-seq FullResync never precedes a
    // committed lower-seq delta. Under the out-of-lock revert the socket already
    // holds seq 14 (written by `replay_buffered`) ahead of 11,12,13, so the read
    // sees (14,11,12,13) and this assertion goes RED.
    (&helper_side)
        .set_nonblocking(false)
        .expect("blocking for the write");
    (&helper_side)
        .write_all(write_buf.pending())
        .expect("write frames");

    let mut wire: Vec<(u8, u64)> = Vec::new();
    for _ in 0..4 {
        let mut hdr = [0u8; FRAME_HEADER_SIZE];
        if daemon_side.read_exact(&mut hdr).is_err() {
            break;
        }
        let payload_len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
        if payload_len > 0 {
            let mut sink = vec![0u8; payload_len];
            daemon_side.read_exact(&mut sink).expect("payload");
        }
        wire.push((hdr[4], u64::from_le_bytes(hdr[8..16].try_into().unwrap())));
    }
    assert_eq!(
        wire,
        vec![
            (super::codec::MSG_SESSION_OPEN, 11),
            (super::codec::MSG_SESSION_OPEN, 12),
            (super::codec::MSG_SESSION_OPEN, 13),
            (MSG_FULL_RESYNC, 14),
        ],
        "wire order must be monotonic by seq with the FullResync barrier LAST; \
         an inversion (higher-seq FullResync before a lower-seq delta) is exactly \
         what the Go reader diagnoses as a session gap"
    );
    // The strictly-increasing invariant, stated explicitly.
    let mut prev = 0u64;
    for (_typ, seq) in &wire {
        assert!(
            *seq > prev,
            "wire seq must be strictly increasing (no inversion): {seq} after {prev}"
        );
        prev = *seq;
    }
    assert_eq!(
        wire.last().unwrap().0,
        MSG_FULL_RESYNC,
        "the FullResync barrier must be the LAST frame on the wire"
    );
}

// #5267 fail-on-revert guard for the OTHER half of the fix: parking the
// barrier is insufficient unless its sequence allocation participates in the
// same producer critical section as allocate+enqueue. Hold that lock from this
// thread and prove the replay-gap path cannot allocate until it is released.
// Removing the lock while retaining the park-and-merge code makes the worker
// complete during the held interval and this test fail.
#[test]
fn test_replay_gap_seq_allocation_waits_for_producer_lock_5267() {
    let (_daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    let shared = Arc::new(EventStreamShared::new());
    shared.acked_seq.store(10, Ordering::Release);
    shared.next_seq.store(13, Ordering::Release);

    let producer_guard = shared
        .producer_seq_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let worker_shared = Arc::clone(&shared);
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut replay_buf = VecDeque::new();
        let mut pending_resync = None;
        started_tx.send(()).expect("announce replay start");
        replay_buffered(
            &helper_side,
            &mut replay_buf,
            10,
            &worker_shared,
            &mut pending_resync,
        )
        .expect("replay gap");
        done_tx
            .send(pending_resync.expect("gap must park a barrier").seq)
            .expect("publish barrier seq");
    });

    started_rx.recv().expect("worker started");
    assert!(
        done_rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "replay-gap allocation must block while producer_seq_lock is held"
    );
    assert_eq!(
        shared.next_seq.load(Ordering::Acquire),
        13,
        "blocked replay-gap allocation must not advance next_seq"
    );

    drop(producer_guard);
    assert_eq!(
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("replay allocation must finish after lock release"),
        14
    );
    worker.join().expect("replay worker");
}

#[test]
fn dataplane_event_budget_stays_held_after_connected_loop_drains_channel() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    helper_side.set_nonblocking(true).unwrap();

    let capacity = 1;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(
        EventStreamShared::new_with_dataplane_event_rate_and_queue_capacity(
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
            capacity,
        ),
    );
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Queued { seq: 1 }
    );

    let loop_shared = shared.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        let reconnect = run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            &mut None,
            Duration::from_secs(10),
        );
        drain_remaining(&rx, &loop_shared);
        release_replay_dataplane_event_queue_budget(&loop_shared, &mut replay_buf);
        reconnect
    });

    let mut hdr = [0u8; FRAME_HEADER_SIZE];
    daemon_side
        .read_exact(&mut hdr)
        .expect("dataplane frame header");
    let payload_len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; payload_len];
    daemon_side
        .read_exact(&mut payload)
        .expect("dataplane frame payload");

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Dropped {
            reason: DataplaneEventDropReason::QueueFull
        },
        "draining the mpsc channel into replay must not release telemetry budget"
    );

    daemon_side
        .write_all(&build_raw_ack_frame(1))
        .expect("send ACK");
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match handle
            .try_emit_dataplane_event_at(test_dataplane_event(DataplaneEventKind::PolicyDeny, 7), 0)
        {
            DataplaneEventEmitOutcome::Queued { seq: 2 } => break,
            DataplaneEventEmitOutcome::Dropped {
                reason: DataplaneEventDropReason::QueueFull,
            } if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            other => panic!("telemetry budget should release after ACK, got {other:?}"),
        }
    }

    shared.stop.store(true, Ordering::Release);
    assert!(
        !loop_join.join().expect("connected loop thread"),
        "test loop should stop without requesting reconnect"
    );
}

#[test]
fn dataplane_event_budget_releases_when_replay_eviction_drops_frame() {
    let capacity = 1;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(
        EventStreamShared::new_with_dataplane_event_rate_and_queue_capacity(
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
            capacity,
        ),
    );
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Queued { seq: 1 }
    );
    let frame = rx.try_recv().expect("queued dataplane frame");
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
    push_replay_frame(&shared, &mut replay_buf, frame);

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Dropped {
            reason: DataplaneEventDropReason::QueueFull
        }
    );

    for seq in 2..=REPLAY_BUFFER_CAPACITY as u64 {
        push_replay_frame(
            &shared,
            &mut replay_buf,
            EventFrame::encode_drain_complete(seq),
        );
    }
    push_replay_frame(
        &shared,
        &mut replay_buf,
        EventFrame::encode_drain_complete(REPLAY_BUFFER_CAPACITY as u64 + 1),
    );

    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_dataplane_event(DataplaneEventKind::PolicyDeny, 7),
            0
        ),
        DataplaneEventEmitOutcome::Queued { seq: 2 },
        "replay eviction is a definitive drop and must release telemetry budget"
    );

    drain_remaining(&rx, &shared);
    release_replay_dataplane_event_queue_budget(&shared, &mut replay_buf);
}

// #2382: replay-buffer eviction (buffer wrapped at capacity before ACK) is a
// real telemetry loss and must be counted; ACK-trim (acknowledged-frame
// removal) is NOT a loss and must NOT bump the eviction counter. These tests
// fail if the increment is removed or moved into the shared pop path.

#[test]
fn replay_buffer_eviction_counts_telemetry_loss_2382() {
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);

    // Fill the replay buffer exactly to capacity — no eviction yet.
    for seq in 1..=REPLAY_BUFFER_CAPACITY as u64 {
        push_replay_frame(
            &shared,
            &mut replay_buf,
            EventFrame::encode_drain_complete(seq),
        );
    }
    assert_eq!(replay_buf.len(), REPLAY_BUFFER_CAPACITY);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        0,
        "filling to capacity must not evict anything"
    );

    // Push N more frames past capacity: each wraps the buffer and evicts the
    // oldest unACKed frame. The counter must go 0 -> N. This assertion FAILS
    // (stays 0) if the eviction increment in `evict_replay_frame` is removed.
    let overflow = 5u64;
    for seq in 0..overflow {
        push_replay_frame(
            &shared,
            &mut replay_buf,
            EventFrame::encode_drain_complete(REPLAY_BUFFER_CAPACITY as u64 + 1 + seq),
        );
    }
    assert_eq!(replay_buf.len(), REPLAY_BUFFER_CAPACITY);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        overflow,
        "each buffer-full wrap must count exactly one replay eviction"
    );
    // And the surviving window starts past the evicted prefix.
    assert_eq!(replay_buf.front().map(|f| f.seq), Some(overflow + 1));
}

#[test]
fn ack_trim_does_not_count_as_replay_eviction_2382() {
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Buffer well under capacity so no wrap occurs.
    for seq in 1..=10u64 {
        push_replay_frame(
            &shared,
            &mut replay_buf,
            EventFrame::encode_drain_complete(seq),
        );
    }
    assert_eq!(shared.frames_replay_evicted.load(Ordering::Relaxed), 0);

    // Simulate the MSG_ACK trim path: acked_seq = 5 removes the first 5 frames
    // via `pop_replay_frame`. Those frames were DELIVERED (acknowledged), not
    // lost — the eviction counter must stay 0.
    let acked_seq = 5u64;
    while let Some(front) = replay_buf.front() {
        if front.seq <= acked_seq {
            pop_replay_frame(&shared, &mut replay_buf);
        } else {
            break;
        }
    }
    assert_eq!(replay_buf.len(), 5);
    assert_eq!(replay_buf.front().unwrap().seq, 6);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        0,
        "ACK-trim is acknowledged removal, not a telemetry loss — must not \
         bump the replay-eviction counter"
    );

    // Shutdown drain (release_replay_dataplane_event_queue_budget → pop) also
    // must not count as eviction.
    release_replay_dataplane_event_queue_budget(&shared, &mut replay_buf);
    assert_eq!(replay_buf.len(), 0);
    assert_eq!(
        shared.frames_replay_evicted.load(Ordering::Relaxed),
        0,
        "shutdown drain must not bump the replay-eviction counter"
    );
}

#[test]
fn replay_evictions_surface_in_event_stream_stats_2382() {
    let sender = EventStreamSender {
        tx: mpsc::sync_channel(1).0,
        shared: Arc::new(EventStreamShared::new()),
        io_thread: None,
    };
    sender
        .shared
        .frames_replay_evicted
        .store(42, Ordering::Relaxed);
    assert_eq!(sender.stats().replay_evictions, 42);
}

// #2874: the HA session-sync delta must route through the LOSSLESS producer
// (which surfaces a queue failure) while RT_FLOW telemetry stays best-effort
// (silently drops on a full channel). This documents the lossless-vs-telemetry
// split that `flush_session_deltas` relies on.
#[test]
fn session_delta_lossless_surfaces_failure_while_telemetry_drops() {
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new()); // connected=false
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };
    let zone_map = FxHashMap::default();
    let open = test_close_delta(crate::session::SessionDeltaKind::Open);

    // Session-sync delta: lossless surfaces the failure (NOT silently dropped).
    let err = handle
        .push_delta_lossless(&open, &zone_map)
        .expect_err("session-sync delta must not be silently dropped");
    assert!(err.contains("not connected"), "unexpected error: {err}");

    // Telemetry stays best-effort: try_send fills then silently drops.
    assert!(
        handle.try_send(EventFrame::encode_drain_complete(1)),
        "first telemetry frame fills the channel"
    );
    assert!(
        !handle.try_send(EventFrame::encode_drain_complete(2)),
        "telemetry frame must silently drop on a full channel"
    );
    assert_eq!(
        shared.frames_dropped.load(Ordering::Relaxed),
        1,
        "the silently-dropped telemetry frame is counted in frames_dropped"
    );
}

#[test]
fn test_lossless_send_fails_when_not_connected() {
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle { tx, shared };

    let err = handle
        .send_frame_lossless(EventFrame::encode_drain_complete(1))
        .expect_err("lossless send should fail when disconnected");
    assert!(err.contains("not connected"));
}

// #3878 F-153: a full-channel drop of a lossy session delta must NOT burn a
// sequence number. The producer allocates the seq atomically with the enqueue
// and, on a `Full` `try_send`, rolls the seq back — so the next successfully
// sent frame stays contiguous and the Go reader never sees a spurious gap that
// would force a full owner-RG resync.
//
// RED-on-revert: without the rollback, the dropped frame's seq is burned;
// `next_seq` advances to 2 after the drop and the next frame lands on seq 3,
// leaving a hole at seq 2.
#[test]
fn push_delta_full_channel_drop_does_not_burn_seq_3878() {
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };
    let zone_map = FxHashMap::default();
    let delta = test_close_delta(crate::session::SessionDeltaKind::Open);

    // Frame 1 fills the capacity-1 channel (seq 1).
    handle.push_delta(&delta, &zone_map);
    assert_eq!(shared.next_seq.load(Ordering::Relaxed), 1);

    // Frame 2: the channel is full -> `try_send` returns Full. The seq must be
    // rolled back, not burned.
    handle.push_delta(&delta, &zone_map);
    assert_eq!(
        shared.next_seq.load(Ordering::Relaxed),
        1,
        "#3878 F-153: a full-channel drop must not burn a sequence number",
    );

    // Drain frame 1, then send frame 2 for real: it must be seq 2 (contiguous
    // with seq 1), never seq 3 (a reader-visible gap -> spurious resync).
    let f1 = rx.try_recv().expect("frame 1 queued");
    assert_eq!(f1.seq, 1);
    handle.push_delta(&delta, &zone_map);
    let f2 = rx.try_recv().expect("frame 2 queued");
    assert_eq!(
        f2.seq, 2,
        "seq after a full-channel drop must stay contiguous (no gap)"
    );
    assert!(rx.try_recv().is_err(), "no extra frame should be queued");
}

// #3878 F-152: seq allocation and channel enqueue are atomic under the producer
// lock, so the seq embedded in each frame is strictly monotonic in wire
// (channel-FIFO) order even when many workers push concurrently. Without the
// lock two workers can allocate N and N+1 but enqueue them inverted, so a lower
// seq lands after a higher one and the Go reader treats the inversion as a
// session-sync gap -> spurious full owner-RG resync + disconnect.
//
// RED-on-revert: this is a concurrency stress test. With the non-atomic
// allocate-then-enqueue restored, the wide window between `next_seq()` and
// `try_send` (a full session-open encode) lets two of the eight workers invert
// within the few thousand frames, and the monotonicity assertion fails.
#[test]
fn concurrent_push_delta_preserves_monotonic_wire_order_3878() {
    // 8-way contention over the wide next_seq()->try_send window reorders very
    // early on revert (observed at seq ~192); 500 per thread keeps a large
    // margin while bounding the CPU burst so this does not starve co-scheduled
    // timing-sensitive tests in a module-only test run.
    const THREADS: u64 = 8;
    const PER_THREAD: u64 = 500;
    let total = (THREADS * PER_THREAD) as usize;

    // Channel sized to hold every frame: the I/O thread is not draining in this
    // unit test, so a smaller channel would exercise drops, not ordering.
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(total);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle { tx, shared };

    let mut joins = Vec::new();
    for _ in 0..THREADS {
        let worker = handle.clone();
        joins.push(std::thread::spawn(move || {
            let zone_map = FxHashMap::default();
            let delta = test_close_delta(crate::session::SessionDeltaKind::Open);
            for _ in 0..PER_THREAD {
                worker.push_delta(&delta, &zone_map);
            }
        }));
    }
    for join in joins {
        join.join().expect("worker thread");
    }

    // Drain the channel in FIFO (wire) order; the embedded seqs must be strictly
    // increasing and form a contiguous 1..=total run (no inversions, no burns).
    let mut prev = 0u64;
    let mut count = 0u64;
    while let Ok(frame) = rx.try_recv() {
        assert!(
            frame.seq > prev,
            "wire seq went backwards: {} after {} (non-atomic allocate+enqueue reordered a frame)",
            frame.seq,
            prev,
        );
        prev = frame.seq;
        count += 1;
    }
    assert_eq!(
        count,
        THREADS * PER_THREAD,
        "every delta must reach the channel"
    );
    assert_eq!(
        prev,
        THREADS * PER_THREAD,
        "seqs must be a contiguous 1..=N run with no gaps or burns",
    );
}

// #3878 F-153 (lossless path): concurrent lossless flushers that all hit a FULL
// channel must NOT strand a sequence number. Each failed attempt's rollback
// runs UNDER the producer lock, so allocations+rollbacks are strictly LIFO and
// every drop returns `next_seq` to where it started. Before the follow-up fix
// the rollback ran AFTER the lock was released, so two flushers could interleave
// alloc(6)/alloc(7)/rollback(6)-CAS-fails/rollback(7)-CAS-succeeds and leave
// `next_seq` at 6 with seq 6 stranded — a wire hole → spurious owner-RG resync
// (reachable because `flush_session_deltas` → `push_delta_lossless` runs
// per-worker, up to 6 concurrent flushers on the mlx5 VF).
//
// RED-on-revert: with the rollback moved back outside the guard, the non-LIFO
// CAS failures strand seqs and `next_seq` ends well above the base.
#[test]
fn concurrent_lossless_full_drops_do_not_strand_seq_3878() {
    const CAP: usize = 5;
    const THREADS: usize = 3;

    // rx is HELD (never dropped/drained) so every `try_send` returns Full, not
    // Disconnected — the flushers stay in the retry loop.
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(CAP);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };
    let zone_map = FxHashMap::default();
    let delta = test_close_delta(crate::session::SessionDeltaKind::Open);

    // Fill the channel so every lossless attempt hits Full; base next_seq = CAP.
    for _ in 0..CAP {
        handle.push_delta(&delta, &zone_map);
    }
    assert_eq!(shared.next_seq.load(Ordering::Relaxed), CAP as u64);

    // Mark connected so the flushers enter the retry loop rather than bailing at
    // the initial connected check.
    shared.connected.store(true, Ordering::Release);

    let mut joins = Vec::new();
    for _ in 0..THREADS {
        let worker = handle.clone();
        joins.push(std::thread::spawn(move || {
            let zm = FxHashMap::default();
            let d = test_close_delta(crate::session::SessionDeltaKind::Open);
            // Retries on Full; gives up (Err) once `connected` is cleared below.
            let _ = worker.push_delta_lossless(&d, &zm);
        }));
    }

    // Let the flushers churn concurrently on the Full channel (this is where the
    // non-LIFO rollback strands seqs on the buggy version), then make them give
    // up quickly instead of waiting out the 5s lossless timeout. The flushers
    // sleep LOSSLESS_QUEUE_RETRY_DELAY (50us) between attempts, so this window is
    // low-CPU (mostly sleeping) yet still runs hundreds of interleaved attempts.
    std::thread::sleep(std::time::Duration::from_millis(20));
    shared.connected.store(false, Ordering::Release);
    for join in joins {
        join.join().expect("lossless flusher");
    }

    // Every lossless attempt was dropped and rolled back UNDER the lock, so the
    // counter must be back at the base with no stranded hole.
    assert_eq!(
        shared.next_seq.load(Ordering::Relaxed),
        CAP as u64,
        "#3878: concurrent lossless Full-drops must not strand a sequence number",
    );
}
