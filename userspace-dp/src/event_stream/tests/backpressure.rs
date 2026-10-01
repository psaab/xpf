// Channel + write-backlog backpressure tests: bounded shedding, stall
// counting, paused drain, and lossless capacity waiting.
// Split from event_stream/tests.rs (#4664).

use super::*;
use std::os::unix::io::AsRawFd;

/// Force a small kernel socket buffer on both ends of a test AF_UNIX pair.
///
/// The end-to-end wedged-reader test relies on a never-reading peer causing
/// `write()` to return `WouldBlock` quickly, so the I/O thread's `write_buf`
/// backs up and reaches `WRITE_BACKLOG_MAX_BYTES`. That only happens if the
/// kernel socket buffer is SMALLER than the volume we pump. Linux defaults are
/// ~208 KiB, but a host that tunes `net.core.{r,w}mem_default` high (this test
/// fleet runs on boxes set to 64 MiB) lets a wedged AF_UNIX socket absorb
/// ~53 MiB before `WouldBlock` — MORE than the frames the test pumps — so the
/// backlog never fills and the cap under test is never reached (#6103, a
/// host-sysctl-dependent deterministic failure, not a product regression).
///
/// Requesting 64 KiB (the kernel doubles it and enforces a floor, yielding an
/// effective ~100-130 KiB) makes the wedged reader back up well below the
/// 16 MiB cap regardless of the host default, so the test is deterministic.
fn shrink_socket_buffers(reader: &UnixStream, writer: &UnixStream) {
    let sz: libc::c_int = 64 * 1024;
    // AF_UNIX stream send is gated by the sender's SO_SNDBUF and the peer's
    // SO_RCVBUF; shrink both so neither can hide the backpressure.
    for (fd, opt) in [
        (writer.as_raw_fd(), libc::SO_SNDBUF),
        (reader.as_raw_fd(), libc::SO_RCVBUF),
    ] {
        // SAFETY: `fd` is a valid, open socket borrowed for this call only.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &sz as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt(SO_*BUF) must succeed on the test socket");
    }
}

#[test]
fn test_channel_backpressure() {
    let (tx, _rx) = mpsc::sync_channel::<EventFrame>(2);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    // Fill the channel (capacity 2)
    let frame = EventFrame::encode_drain_complete(1);
    assert!(handle.try_send(frame.clone()));
    assert!(handle.try_send(frame.clone()));

    // Third send should fail (channel full)
    assert!(!handle.try_send(frame));
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 2);
    assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 1);
}

// #2381: the write-backlog cap converts a wedged daemon reader from
// unbounded helper heap growth into bounded, counted telemetry loss at the
// already-bounded mpsc channel. These tests fail if the cap is removed or the
// stall is not counted.

#[test]
fn write_backlog_cap_halts_drain_and_counts_stall() {
    // Channel holds frames the I/O thread would normally migrate into the
    // pending write backlog. With the backlog already at the cap, the drain
    // must stop, count the stall, and LEAVE the frames in the channel.
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(8);
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    for seq in 1..=4u64 {
        tx.send(EventFrame::encode_drain_complete(seq))
            .expect("seed channel");
    }

    // Simulate a wedged consumer: the backlog is already at the cap because
    // prior socket writes returned WouldBlock.
    let mut write_buf = WriteBacklog::with_capacity(WRITE_BACKLOG_MAX_BYTES);
    write_buf.extend_from_slice(&vec![0u8; WRITE_BACKLOG_MAX_BYTES]);

    let outcome = drain_channel_into_write_buf(
        &rx,
        &shared,
        &mut replay_buf,
        &mut write_buf,
        false,
        &mut None,
    );

    assert!(outcome.stalled, "drain must report the backlog stall");
    assert!(!outcome.disconnected);
    assert!(
        !outcome.drained_any,
        "no frame may move into a full backlog"
    );
    assert_eq!(
        write_buf.pending_len(),
        WRITE_BACKLOG_MAX_BYTES,
        "backlog must not grow past the cap"
    );
    assert_eq!(
        shared.frames_write_stalled.load(Ordering::Relaxed),
        1,
        "the stall must be counted"
    );
    // Frames stay in the channel (the real backpressure surface), not silently
    // relocated into one unbounded heap buffer.
    assert_eq!(rx.try_recv().map(|f| f.seq).ok(), Some(1));
}

#[test]
fn write_backlog_stall_makes_channel_the_backpressure_surface() {
    // Once the backlog is capped, the bounded channel fills and worker
    // try_send drops the NEWEST events with the existing frames_dropped
    // counter — bounded, counted loss instead of unbounded growth.
    let capacity = 4;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx: tx.clone(),
        shared: shared.clone(),
    };
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let mut write_buf = WriteBacklog::with_capacity(WRITE_BACKLOG_MAX_BYTES);
    write_buf.extend_from_slice(&vec![0u8; WRITE_BACKLOG_MAX_BYTES]);

    // Fill the channel to capacity.
    for seq in 1..=capacity as u64 {
        assert!(handle.try_send(EventFrame::encode_drain_complete(seq)));
    }

    // I/O thread cannot drain into the full backlog: channel stays full.
    let outcome = drain_channel_into_write_buf(
        &rx,
        &shared,
        &mut replay_buf,
        &mut write_buf,
        false,
        &mut None,
    );
    assert!(outcome.stalled);
    assert!(!outcome.drained_any);

    // Subsequent producer sends now drop (newest-first) and are counted.
    assert!(
        !handle.try_send(EventFrame::encode_drain_complete(99)),
        "producer must drop, never block, when the channel is full"
    );
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), capacity as u64);
    assert_eq!(
        shared.frames_dropped.load(Ordering::Relaxed),
        1,
        "the bounded channel drop must be counted"
    );
}

#[test]
fn paused_drain_ignores_backlog_cap_and_never_stalls() {
    // While paused, frames are consumed into the already-bounded replay
    // buffer only (never the write backlog), so the cap must not engage even
    // with a pre-filled write_buf.
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(8);
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let mut write_buf = WriteBacklog::with_capacity(WRITE_BACKLOG_MAX_BYTES);
    write_buf.extend_from_slice(&vec![0u8; WRITE_BACKLOG_MAX_BYTES]);

    for seq in 1..=3u64 {
        tx.send(EventFrame::encode_drain_complete(seq))
            .expect("seed channel");
    }

    let outcome = drain_channel_into_write_buf(
        &rx,
        &shared,
        &mut replay_buf,
        &mut write_buf,
        true,
        &mut None,
    );
    assert!(!outcome.stalled, "paused drain must not stall on the cap");
    assert!(outcome.drained_any);
    assert_eq!(
        write_buf.pending_len(),
        WRITE_BACKLOG_MAX_BYTES,
        "paused frames must not be added to the write backlog"
    );
    assert_eq!(replay_buf.len(), 3, "paused frames go to the replay buffer");
    assert_eq!(shared.frames_write_stalled.load(Ordering::Relaxed), 0);
}

// The writer handles EventFrame as opaque bytes. Fill its fixed wire buffer
// with a correctly framed session-open envelope so this byte-cap test reaches
// 16 MiB in 32K frames instead of over a million header-only frames.
fn backpressure_frame(seq: u64) -> EventFrame {
    let mut data = [0u8; super::codec::EVENT_FRAME_CAPACITY];
    let payload_len = (data.len() - FRAME_HEADER_SIZE) as u32;
    data[..4].copy_from_slice(&payload_len.to_le_bytes());
    data[4] = super::codec::MSG_SESSION_OPEN;
    data[8..16].copy_from_slice(&seq.to_le_bytes());
    let len = data.len() as u16;
    EventFrame { data, len, seq }
}

#[test]
fn stalled_consumer_does_not_grow_backlog_unbounded_end_to_end() {
    // End-to-end: a daemon that connects but never reads (socket buffer fills
    // → write returns WouldBlock). Pump far more than the backlog cap worth of
    // frames through the channel and assert the loop SHEDS at the bounded
    // channel (frames_dropped grows, stalls counted) instead of migrating
    // every frame into an unbounded write_buf.
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    // Force a small kernel socket buffer so the wedged reader trips `WouldBlock`
    // (and thus the write-backlog cap) independent of the host's tuned
    // `net.core.{r,w}mem_default`; see `shrink_socket_buffers` (#6103).
    shrink_socket_buffers(&daemon_side, &helper_side);
    helper_side.set_nonblocking(true).unwrap();
    // Never read on the daemon side: let the socket buffer wedge.

    let capacity = 64;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx: tx.clone(),
        shared: shared.clone(),
    };

    let loop_shared = shared.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            &mut None,
            Duration::from_secs(10),
        )
    });

    // Use a full-size frame so the loop must process far fewer events to reach
    // the byte-based cap; this keeps the end-to-end liveness check useful on
    // heavily loaded runners without changing the 16 MiB production bound.
    let frame_bytes = backpressure_frame(1).as_bytes().len();
    let cap_frames = (WRITE_BACKLOG_MAX_BYTES / frame_bytes) as u64;
    // Accepted sends that must accumulate before the unwritten backlog reaches
    // the 16 MiB cap (~1x cap worth of full-size frames).

    // #6148: the liveness wait is PROGRESS-GATED, not a fixed wall-clock. We
    // feed a SUSTAINED source and stop as soon as the loop thread has actually
    // migrated WRITE_BACKLOG_MAX_BYTES of unwritten frames into its backlog
    // (frames_write_stalled > 0) AND shed at the bounded channel
    // (frames_dropped > 0) — the two safety conditions the asserts below check.
    //
    // Why this is robust under CPU contention: `try_send` succeeds ONLY when
    // the loop thread has freed channel space by draining, and every drained
    // frame lands permanently in `write_buf` (the wedged socket never drains
    // it). So `sent_ok` self-paces to the loop's real drain progress and tracks
    // the write_buf frame count to within the 64-slot channel depth — we cannot
    // overrun a starved loop, we simply feed it exactly as fast as it drains
    // and wait longer. The old fixed 20s-pump + 5s-stall-wait intermittently
    // failed on a loaded full-suite runner (#6148) because a starved background
    // thread had not accumulated the 16 MiB cap before the clock expired, and
    // the producer had already burned through its bounded pump (one try_send
    // per seq once frames_dropped>0) leaving no sustained source for the
    // 1-per-ms stall-wait to lean on — a load-sensitive timing flake, not a
    // product bug. The bound/shedding safety asserts are unchanged.
    //
    // `max_accepted` bounds a *regressed* (cap-removed) build: a working cap
    // trips the stall at ~1x cap worth of accepted frames, so reaching 2x cap
    // accepted with frames_write_stalled still 0 can only mean the safety cap
    // is gone — stop feeding (capping write_buf at ~2x cap of memory) and let
    // the assert fail fast instead of growing the backlog without bound.
    let max_accepted = cap_frames * 2 + 4096;
    // Generous, parallelism-aware backstop: it fires only if the loop is
    // catastrophically starved. More hardware threads => more concurrent tests
    // in the default parallel `cargo test` run => a smaller CPU share for this
    // background thread, so scale the deadline up with parallelism. This is a
    // should-eventually-happen liveness check; a generous deadline is correct.
    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as u32;
    let deadline = Instant::now() + Duration::from_secs(30) + Duration::from_secs(3) * parallelism;

    let mut sent_ok = 0u64;
    let mut attempts = 0u64;
    loop {
        // Stop the moment BOTH states the safety asserts require are observed.
        // Requiring the drop too avoids an early break at the instant the stall
        // trips (before the now-idle loop lets the channel fill and shed) — the
        // channel fills and drops within <= 64 further sends, no wall-clock.
        let stalled = shared.frames_write_stalled.load(Ordering::Relaxed) > 0;
        let shed = shared.frames_dropped.load(Ordering::Relaxed) > 0;
        if stalled && shed {
            break;
        }
        // Fed 2x the cap and still no stall => the cap regressed; fail fast.
        if sent_ok >= max_accepted {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        // Sustained, non-blocking source. A full channel is the intended
        // backpressure once the backlog caps; try_send counts the drop in
        // frames_dropped. Retry (loop) rather than give up so the loop always
        // has frames to migrate into write_buf.
        attempts += 1;
        if handle.try_send(backpressure_frame(sent_ok + 1)) {
            sent_ok += 1;
        }
        // Yield so the (possibly starved) background loop thread gets CPU to
        // drain the channel into write_buf.
        thread::yield_now();
    }

    shared.stop.store(true, Ordering::Release);
    let _ = loop_join.join();

    let frames_write_stalled = shared.frames_write_stalled.load(Ordering::Relaxed);
    let frames_dropped = shared.frames_dropped.load(Ordering::Relaxed);
    assert!(
        frames_write_stalled > 0,
        "a wedged reader with a sustained source must trip the backlog cap \
         (accepted={sent_ok}, attempts={attempts}, dropped={frames_dropped}, \
         deadline_expired={})",
        Instant::now() >= deadline
    );
    assert!(
        shared.frames_dropped.load(Ordering::Relaxed) > 0,
        "shedding must happen at the bounded channel (counted), not via \
         unbounded write_buf growth"
    );
    // The channel is bounded, so accepted frames are bounded by capacity +
    // whatever the (capped) backlog/replay absorbed — never every frame we
    // offered once backpressure engaged.
    assert!(
        sent_ok < attempts,
        "not every offered frame can be accepted once backpressure engages"
    );
    drop(daemon_side);
}

#[test]
fn keeping_up_consumer_sees_full_fidelity_and_no_stalls() {
    // A daemon that drains the socket promptly must lose nothing: no stalls,
    // no drops, every byte delivered in order.
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let capacity = 16;
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(capacity);
    let shared = Arc::new(EventStreamShared::new());
    let handle = EventStreamWorkerHandle {
        tx: tx.clone(),
        shared: shared.clone(),
    };

    let total: u64 = 5000;
    let mut expected: Vec<u8> = Vec::new();
    for seq in 1..=total {
        expected.extend_from_slice(EventFrame::encode_drain_complete(seq).as_bytes());
    }

    let loop_shared = shared.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::with_capacity(REPLAY_BUFFER_CAPACITY);
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            &mut None,
            Duration::from_secs(10),
        )
    });

    let frame_bytes = EventFrame::encode_drain_complete(1).as_bytes().len();
    let want = total as usize * frame_bytes;

    // Reader thread drains promptly so the helper never backs up.
    let mut reader = daemon_side;
    let read_join = thread::spawn(move || {
        let mut got: Vec<u8> = Vec::with_capacity(want);
        let mut chunk = [0u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(15);
        while got.len() < want && Instant::now() < deadline {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        got
    });

    for seq in 1..=total {
        // Lossless producer-side feed paced by the bounded channel; the prompt
        // reader keeps it draining so this never has to drop.
        let mut frame = EventFrame::encode_drain_complete(seq);
        loop {
            match tx.try_send(frame) {
                Ok(()) => {
                    shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(mpsc::TrySendError::Full(returned)) => {
                    frame = returned;
                    thread::yield_now();
                }
                Err(mpsc::TrySendError::Disconnected(_)) => panic!("channel closed"),
            }
        }
    }

    let got = read_join.join().expect("reader thread");
    shared.stop.store(true, Ordering::Release);
    let _ = loop_join.join();

    assert_eq!(got.len(), want, "every frame byte must be delivered");
    assert_eq!(got, expected, "frames must arrive in order, unmodified");
    assert_eq!(
        shared.frames_write_stalled.load(Ordering::Relaxed),
        0,
        "a keeping-up consumer must never trip the backlog cap"
    );
    assert_eq!(
        shared.frames_dropped.load(Ordering::Relaxed),
        0,
        "a keeping-up consumer must see zero drops"
    );
}

#[test]
fn test_lossless_send_waits_for_capacity() {
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(1);
    let shared = Arc::new(EventStreamShared::new());
    shared.connected.store(true, Ordering::Release);
    let handle = EventStreamWorkerHandle {
        tx,
        shared: shared.clone(),
    };

    assert!(handle.try_send(EventFrame::encode_drain_complete(1)));

    let (release_tx, release_rx) = mpsc::sync_channel::<()>(0);
    let (attempt_tx, attempt_rx) = mpsc::sync_channel::<()>(0);
    let (done_tx, done_rx) = mpsc::sync_channel::<Result<(), String>>(0);
    let (hold_tx, hold_rx) = mpsc::sync_channel::<()>(0);

    let consumer_join = thread::spawn(move || {
        release_rx.recv().expect("release consumer");
        rx.recv().expect("drain queued frame");
        hold_rx
            .recv()
            .expect("hold consumer open until sender finishes");
    });

    let sender_handle = handle.clone();
    let sender_join = thread::spawn(move || {
        attempt_tx
            .send(())
            .expect("notify that lossless send is about to start");
        let result = sender_handle.send_frame_lossless(EventFrame::encode_drain_complete(2));
        done_tx.send(result).expect("send lossless result");
    });

    attempt_rx
        .recv()
        .expect("wait for sender thread to begin lossless send");

    assert!(
        done_rx.recv_timeout(Duration::from_millis(20)).is_err(),
        "lossless send should still be waiting while the channel remains full"
    );

    release_tx.send(()).expect("allow consumer to drain");

    done_rx
        .recv_timeout(Duration::from_millis(100))
        .expect("lossless send should finish once capacity is available")
        .expect("lossless send should wait for capacity");

    hold_tx.send(()).expect("release consumer thread");
    sender_join.join().expect("sender thread");
    consumer_join.join().expect("consumer thread");
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 2);
    assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 0);
}

// ---------------------------------------------------------------------------
// #5189 (A1-b10-F4) — the idle keepalive is a backlog producer and must obey
// the same WRITE_BACKLOG_MAX_BYTES ceiling the channel drain enforces.
// ---------------------------------------------------------------------------

use super::super::connection::append_idle_keepalive_if_due;

/// #5189 (A1-b10-F4) fail-on-revert guard.
///
/// `drain_channel_into_write_buf` halts at `WRITE_BACKLOG_MAX_BYTES` so a
/// live-but-non-reading consumer cannot migrate unbounded bytes into the
/// heap-backed backlog (#2381). #2883 then routed the idle keepalive through
/// the SAME `write_buf` — but without the cap check. A consumer wedged at the
/// cap keeps `drained_any == false` forever, which is exactly the condition
/// that arms the idle keepalive, and the socket write returns `WouldBlock`
/// forever, so nothing ever reclaims those bytes: the backlog grew by one
/// frame header per keepalive interval, monotonically and without bound,
/// falsifying the documented `cap + one max EventFrame` ceiling.
///
/// This drives the SAME function the connected loop calls for its keepalive
/// (`connection.rs`'s idle branch has no other keepalive path), so the site is
/// production-reachable rather than a test-only shim.
///
/// It pins the BOUNDARY, not merely "never appends": the first call sits one
/// frame below the cap and MUST append (otherwise the suppression assertion
/// below would be vacuous — a helper that never appends would pass it), and
/// only the call that would cross the cap is suppressed. Dropping the
/// `pending_len() >= WRITE_BACKLOG_MAX_BYTES` guard makes the backlog grow past
/// the cap on the very first post-cap attempt → RED.
#[test]
fn idle_keepalive_stops_at_the_write_backlog_cap_5189() {
    let mut write_buf = WriteBacklog::with_capacity(WRITE_BACKLOG_MAX_BYTES);
    write_buf.extend_from_slice(&vec![0u8; WRITE_BACKLOG_MAX_BYTES - FRAME_HEADER_SIZE]);
    let mut last_write = Instant::now();

    // One frame of headroom left: the keepalive is due and MUST be appended.
    assert!(
        append_idle_keepalive_if_due(&mut write_buf, &mut last_write, Duration::ZERO),
        "a due keepalive with headroom below the cap must still be appended — \
         otherwise the suppression assertion below proves nothing"
    );
    assert_eq!(
        write_buf.pending_len(),
        WRITE_BACKLOG_MAX_BYTES,
        "the appended keepalive must be exactly one frame header"
    );
    assert_eq!(
        write_buf.pending()[write_buf.pending_len() - FRAME_HEADER_SIZE + 4],
        MSG_KEEPALIVE,
        "the appended bytes must be a keepalive frame"
    );

    // Now at the cap with a wedged consumer (no `advance`, so nothing is ever
    // reclaimed). Every further keepalive must be suppressed.
    for attempt in 0..64 {
        assert!(
            !append_idle_keepalive_if_due(&mut write_buf, &mut last_write, Duration::ZERO),
            "keepalive attempt {attempt} appended past WRITE_BACKLOG_MAX_BYTES"
        );
        assert_eq!(
            write_buf.pending_len(),
            WRITE_BACKLOG_MAX_BYTES,
            "the write backlog grew past the cap on keepalive attempt {attempt}: \
             a stalled consumer must degrade telemetry, never grow helper heap \
             without bound (#5189 A1-b10-F4)"
        );
    }
}

/// #5189 (A1-b10-F4): a suppressed keepalive must NOT re-arm `last_write`.
///
/// The keepalive stays DUE while the backlog is capped, so the first cycle
/// after the backlog drains below the cap emits it immediately instead of
/// waiting out another full interval — otherwise a consumer that unwedges just
/// after a suppressed attempt goes a further `KEEPALIVE_IDLE_INTERVAL` with no
/// liveness signal on an otherwise-idle stream. Re-arming `last_write` inside
/// the suppression branch makes the final assertion RED.
#[test]
fn suppressed_idle_keepalive_does_not_rearm_the_interval_5189() {
    let interval = Duration::from_millis(50);
    let mut write_buf = WriteBacklog::with_capacity(WRITE_BACKLOG_MAX_BYTES);
    write_buf.extend_from_slice(&vec![0u8; WRITE_BACKLOG_MAX_BYTES]);
    let mut last_write = Instant::now();

    // Not yet due: the interval gate, not the cap, is what declines here.
    assert!(
        !append_idle_keepalive_if_due(&mut write_buf, &mut last_write, interval),
        "a keepalive that is not yet due must not be appended"
    );

    thread::sleep(interval + Duration::from_millis(10));
    assert!(
        !append_idle_keepalive_if_due(&mut write_buf, &mut last_write, interval),
        "a due keepalive must be suppressed while the backlog is at the cap"
    );

    // The consumer starts reading again: one frame's worth of backlog is
    // written out, so there is headroom below the cap.
    write_buf.advance(FRAME_HEADER_SIZE);
    assert!(
        write_buf.pending_len() < WRITE_BACKLOG_MAX_BYTES,
        "control: the advance must put the backlog below the cap"
    );
    assert!(
        append_idle_keepalive_if_due(&mut write_buf, &mut last_write, interval),
        "the keepalive was still due when the backlog drained below the cap, so \
         it must fire immediately — the suppressed attempt must not have \
         re-armed last_write (#5189 A1-b10-F4)"
    );
}
