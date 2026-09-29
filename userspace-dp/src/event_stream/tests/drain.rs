// DrainRequest / demotion-pause tests: fence filtering (#2876/#2882),
// stuck-reader backpressure (#2877/#2883), and paused-eviction drain
// poisoning (#2875). Split from event_stream/tests.rs (#4664).

use super::*;

// Build a benign header-only replay frame (MSG_SESSION_OPEN type) carrying the
// given seq. Used so drain replay frames are NOT mistaken for the type-8
// DrainComplete signal under test.
fn replay_seq_frame(seq: u64) -> EventFrame {
    let mut data = [0u8; super::codec::EVENT_FRAME_CAPACITY];
    // payload_len = 0, msg_type = MSG_SESSION_OPEN (1)
    data[4] = super::codec::MSG_SESSION_OPEN;
    data[8..16].copy_from_slice(&seq.to_le_bytes());
    EventFrame {
        data,
        len: FRAME_HEADER_SIZE as u16,
        seq,
    }
}

// Helper: read one wire frame header from a stream (header-only frames).
// Returns (msg_type, seq) or None if no frame arrives within the read timeout.
fn try_read_frame_header(stream: &mut std::os::unix::net::UnixStream) -> Option<(u8, u64)> {
    let mut hdr = [0u8; FRAME_HEADER_SIZE];
    match stream.read_exact(&mut hdr) {
        Ok(()) => {
            let payload_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
            // Consume any payload so the next header read is aligned.
            if payload_len > 0 {
                let mut sink = vec![0u8; payload_len];
                stream.read_exact(&mut sink).ok()?;
            }
            let msg_type = hdr[4];
            let seq = u64::from_le_bytes([
                hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
            ]);
            Some((msg_type, seq))
        }
        Err(_) => None,
    }
}

// #2876 fail-on-revert guard (Rust helper side): when the drain channel never
// reaches the target fence, handle_drain_request must time out and WITHHOLD
// DrainComplete -- it must NOT emit a DrainComplete carrying a below-target seq.
// This goes RED if the `reached_target` gate is removed and the helper falls
// back to sending DrainComplete with replay_buf.back().seq below the fence.
#[test]
fn test_drain_below_fence_withholds_drain_complete() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Channel holds only seq 3, but the fence target is 5: the drain can never
    // reach the fence and must time out (200ms) below it.
    let (tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    tx.send(replay_seq_frame(3)).unwrap();

    handle_drain_request(5, &rx, &helper_side, &shared, &mut replay_buf);

    // No DrainComplete must reach the daemon side.
    if let Some((msg_type, seq)) = try_read_frame_header(&mut daemon_side) {
        // The replayed frame (seq 3) may be written, but a DrainComplete must
        // never appear below the fence. Walk any non-drain frames first.
        let mut t = msg_type;
        let mut s = seq;
        loop {
            assert_ne!(
                t, MSG_DRAIN_COMPLETE,
                "helper emitted DrainComplete seq {} below fence 5 (#2876 regression)",
                s
            );
            match try_read_frame_header(&mut daemon_side) {
                Some((nt, ns)) => {
                    t = nt;
                    s = ns;
                }
                None => break,
            }
        }
    }
}

// #2876: when the channel reaches the fence, handle_drain_request must emit a
// DrainComplete whose seq is >= the target.
#[test]
fn test_drain_at_fence_emits_drain_complete() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    let (tx, rx) = mpsc::sync_channel::<EventFrame>(8);
    for seq in 1..=5u64 {
        tx.send(replay_seq_frame(seq)).unwrap();
    }

    handle_drain_request(5, &rx, &helper_side, &shared, &mut replay_buf);

    // Drain frames until we observe the DrainComplete at/above the fence.
    let mut saw_complete = false;
    while let Some((msg_type, seq)) = try_read_frame_header(&mut daemon_side) {
        if msg_type == MSG_DRAIN_COMPLETE {
            assert!(seq >= 5, "DrainComplete seq {} must be >= fence 5", seq);
            saw_complete = true;
            break;
        }
    }
    assert!(saw_complete, "helper did not emit DrainComplete at fence");
}

// #2882 fail-on-revert guard: DrainRequest is contracted as "flush all
// buffered events UP TO target seq". With a replay buffer holding seqs 1..=10
// and a fence target of 5, handle_drain_request must write ONLY seqs 1..=5 and
// report DrainComplete == 5 (the fence) — not every buffered frame and not
// replay_buf.back().seq (10). Reverting the `frame.seq <= target_seq` filter
// makes 6..=10 leak onto the wire; reverting the drain_seq fix reports 10 ->
// either makes this RED.
#[test]
fn test_drain_filters_to_target_and_reports_target_2882() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());

    // Buffer holds frames newer than the fence (1..=10, fence = 5).
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=10u64 {
        replay_buf.push_back(replay_seq_frame(seq));
    }
    // Keep tx alive so the drain loop sees Empty (not Disconnected) and reaches
    // the fence via replay_buf.back().seq (10) >= target (5).
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);

    handle_drain_request(5, &rx, &helper_side, &shared, &mut replay_buf);

    // Collect everything the helper wrote until DrainComplete.
    let mut data_seqs: Vec<u64> = Vec::new();
    let mut drain_complete_seq: Option<u64> = None;
    while let Some((msg_type, seq)) = try_read_frame_header(&mut daemon_side) {
        if msg_type == MSG_DRAIN_COMPLETE {
            drain_complete_seq = Some(seq);
            break;
        }
        data_seqs.push(seq);
    }

    assert_eq!(
        data_seqs,
        vec![1, 2, 3, 4, 5],
        "drain must write only frames with seq <= target fence (#2882)"
    );
    assert_eq!(
        drain_complete_seq,
        Some(5),
        "DrainComplete must report the fence target, not replay_buf.back().seq (#2882)"
    );
}

// Fill a nonblocking socket's send buffer so subsequent writes return
// WouldBlock. Used to simulate a daemon that connected but stopped reading.
fn fill_send_buffer(stream: &std::os::unix::net::UnixStream) {
    let junk = [0u8; 65536];
    loop {
        match (&*stream).write(&junk) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

// #2877 fail-on-revert guard: a daemon that connects but stops reading must NOT
// wedge the I/O thread during REPLAY. With the old blocking `write_all`
// (set_nonblocking(false)) the replay write blocks forever on a full socket and
// cannot observe the stop flag, so `EventStreamSender::stop` (which joins the
// I/O thread) hangs. The fixed `write_all_backpressured` keeps the socket
// nonblocking and polls `shared.stop`, so replay returns promptly once stop is
// raised. Reverting to the blocking write makes this time out -> RED.
#[test]
fn test_replay_does_not_wedge_on_stuck_reader_2877() {
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    // Daemon never reads -> fill the send buffer so every write WouldBlocks.
    fill_send_buffer(&helper_side);

    let shared = Arc::new(EventStreamShared::new());
    // One buffered frame to replay (seq 1 > acked 0, no gap).
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    replay_buf.push_back(replay_seq_frame(1));

    let (done_tx, done_rx) = mpsc::channel::<bool>();
    let h_shared = shared.clone();
    let handle = thread::spawn(move || {
        let r = replay_buffered(&helper_side, &mut replay_buf, 0, &h_shared, &mut None);
        done_tx.send(r.is_err()).ok();
    });

    // Let the replay write block on the full socket, then ask the helper to
    // stop. A stop-aware writer must observe this within one poll interval.
    thread::sleep(Duration::from_millis(50));
    shared.stop.store(true, Ordering::Release);

    let completed = done_rx.recv_timeout(Duration::from_secs(2));
    assert!(
        completed.is_ok(),
        "replay wedged on a stuck reader and never observed stop (#2877 regression)"
    );
    assert!(
        completed.unwrap(),
        "replay against a stuck/stopping reader must return Err, not succeed"
    );

    drop(daemon_side);
    let _ = handle.join();
}

// #2877 fail-on-revert guard: a stuck daemon reader must NOT wedge the I/O
// thread during DRAIN either. handle_drain_request used to flip the socket to
// blocking and `write_all` all frames; on a full socket that blocks forever and
// the stop flag is never seen. The fixed path uses `write_all_backpressured`,
// which bails on stop. Reverting makes this time out -> RED.
#[test]
fn test_drain_does_not_wedge_on_stuck_reader_2877() {
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    fill_send_buffer(&helper_side);

    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=3u64 {
        replay_buf.push_back(replay_seq_frame(seq));
    }
    // Keep `tx` alive so the drain loop sees Empty (not Disconnected) and
    // reaches the fence via replay_buf.back().seq (3) >= target (3).
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);

    let (done_tx, done_rx) = mpsc::channel::<()>();
    let h_shared = shared.clone();
    let handle = thread::spawn(move || {
        handle_drain_request(3, &rx, &helper_side, &h_shared, &mut replay_buf);
        done_tx.send(()).ok();
    });

    thread::sleep(Duration::from_millis(50));
    shared.stop.store(true, Ordering::Release);

    assert!(
        done_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
        "drain wedged on a stuck reader and never observed stop (#2877 regression)"
    );

    drop(daemon_side);
    let _ = handle.join();
}

// #2883 fail-on-revert guard: the idle keepalive must ride the normal write_buf
// backpressure path. The old code called write_all directly on the nonblocking
// socket and returned true (immediate reconnect) on ANY error, including
// WouldBlock when the kernel send buffer is full under a slow reader. Here a
// connected daemon stops reading (send buffer filled) and the keepalive fires
// (interval 0): the fixed loop enqueues it into write_buf as ordinary
// backpressure and keeps running; the old loop reconnects. We assert the loop
// does NOT report reconnect. Reverting to the write_all + `return true`
// keepalive makes the loop return true -> RED.
#[test]
fn test_idle_keepalive_wouldblock_is_backpressure_not_reconnect_2883() {
    let (daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    helper_side.set_nonblocking(true).unwrap();
    // Daemon connects but never reads -> fill the send buffer so the keepalive
    // write returns WouldBlock.
    fill_send_buffer(&helper_side);

    // Empty channel + alive tx -> the connected loop is idle (no data frames),
    // so the idle keepalive path is exercised.
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    let shared = Arc::new(EventStreamShared::new());

    let loop_shared = shared.clone();
    let loop_join = thread::spawn(move || {
        let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
        let mut ctrl_read_buf: Vec<u8> = Vec::new();
        // keepalive_interval 0 -> the keepalive fires as soon as the loop is
        // idle, against the already-full socket.
        run_connected_loop(
            &rx,
            &helper_side,
            &loop_shared,
            &mut replay_buf,
            &mut ctrl_read_buf,
            &mut None,
            Duration::from_millis(0),
        )
    });

    // Give the idle keepalive several chances to fire against the full socket.
    // The buggy write_all keepalive would have reconnected (returned true) by
    // now; the fixed path keeps running as backpressure.
    thread::sleep(Duration::from_millis(200));
    shared.stop.store(true, Ordering::Release);
    let reconnect = loop_join.join().expect("connected loop thread");

    assert!(
        !reconnect,
        "idle keepalive WouldBlock must be backpressure, not a fatal reconnect (#2883)"
    );
    drop(daemon_side);
}

// ---------------------------------------------------------------------------
// #2875 — paused-demotion drain must not silently lose session-sync deltas
// ---------------------------------------------------------------------------

// Build a benign header-only TELEMETRY frame (RT_FLOW screen-drop type) so we
// can prove that evicting it while paused does NOT poison the drain. Unlike
// `replay_seq_frame` (a SESSION_OPEN), this msg_type is not a session-sync
// delta, so `EventFrame::is_session_sync()` returns false for it.
fn telemetry_seq_frame(seq: u64) -> EventFrame {
    let mut data = [0u8; super::codec::EVENT_FRAME_CAPACITY];
    data[4] = super::codec::MSG_SCREEN_DROP;
    data[8..16].copy_from_slice(&seq.to_le_bytes());
    EventFrame {
        data,
        len: FRAME_HEADER_SIZE as u16,
        seq,
    }
}

// Inject a telemetry frame into the replay buffer AND seed the per-kind queue
// budget the producer's `emit` would have charged for it (#4607). The #2875
// tests build the buffer directly via `push_replay_frame`, bypassing `emit`;
// a telemetry frame (SCREEN_DROP etc.) carries a `dataplane_event_kind()`, so
// when it is evicted/popped the I/O path calls `release()` on its budget. In
// production that release balances the acquire taken at emit; without the seed
// here the release decrements a zero counter and trips the #1826 underflow
// guard (`decrement_if_positive`) — the actual #4607 panic. Session-sync
// frames (`replay_seq_frame`) have no `dataplane_event_kind()`, so they never
// touch the budget and do not need this.
fn push_budgeted_replay_frame(
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
    frame: EventFrame,
) {
    if let Some(kind) = frame.dataplane_event_kind() {
        shared.dataplane_event_queue.acquire_for_test(kind);
    }
    push_replay_frame(shared, replay_buf, frame);
}

// #2875 fail-on-revert guard: pause the helper, overrun the bounded replay
// buffer so a SESSION-SYNC delta is evicted, then issue DrainRequest. The drain
// MUST be poisoned — it withholds DrainComplete and emits a FullResync instead,
// forcing the daemon to full-resync rather than complete demotion with lost
// session mutations. Reverting the poison gate makes the helper emit
// DrainComplete here -> this goes RED.
#[test]
fn test_paused_session_eviction_poisons_drain_2875() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Fill the replay buffer to capacity with SESSION-SYNC deltas (no eviction
    // yet: the buffer holds exactly REPLAY_BUFFER_CAPACITY frames).
    for seq in 1..=REPLAY_BUFFER_CAPACITY as u64 {
        push_replay_frame(&shared, &mut replay_buf, replay_seq_frame(seq));
    }
    assert_eq!(replay_buf.len(), REPLAY_BUFFER_CAPACITY);
    assert!(!shared.session_evicted_while_paused.load(Ordering::Acquire));

    // Demotion pause window begins, then one more session delta arrives and
    // evicts the OLDEST session frame (seq 1) — a lost session mutation.
    shared.paused.store(true, Ordering::Release);
    push_replay_frame(
        &shared,
        &mut replay_buf,
        replay_seq_frame(REPLAY_BUFFER_CAPACITY as u64 + 1),
    );
    assert!(
        shared.session_evicted_while_paused.load(Ordering::Acquire),
        "evicting a session delta while paused must poison the drain (#2875)"
    );

    // Keep tx alive so the drain loop sees Empty (not Disconnected) and reaches
    // the fence via replay_buf.back().seq >= target.
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    handle_drain_request(5, &rx, &helper_side, &shared, &mut replay_buf);

    // The daemon must observe a FullResync and NEVER a DrainComplete.
    let mut saw_full_resync = false;
    while let Some((msg_type, _seq)) = try_read_frame_header(&mut daemon_side) {
        assert_ne!(
            msg_type, MSG_DRAIN_COMPLETE,
            "poisoned drain must NOT report DrainComplete (#2875 regression)"
        );
        if msg_type == MSG_FULL_RESYNC {
            saw_full_resync = true;
        }
    }
    assert!(
        saw_full_resync,
        "poisoned drain must emit a FullResync so the daemon full-resyncs (#2875)"
    );
    // Poison is consumed once the resync is sent.
    assert!(!shared.session_evicted_while_paused.load(Ordering::Acquire));
}

// #2875: a TELEMETRY-only eviction while paused must NOT poison the drain — the
// drain still completes normally (no spurious FullResync / FullResync storm).
#[test]
fn test_paused_telemetry_eviction_does_not_poison_drain_2875() {
    let (mut daemon_side, helper_side) = std::os::unix::net::UnixStream::pair().unwrap();
    daemon_side
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let shared = Arc::new(EventStreamShared::new());
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();

    // Fill to capacity with TELEMETRY frames, then evict one while paused.
    // Each frame is injected with its queue budget seeded (#4607) so the
    // eviction's `release` is balanced, exactly as production emit/release is.
    for seq in 1..=REPLAY_BUFFER_CAPACITY as u64 {
        push_budgeted_replay_frame(&shared, &mut replay_buf, telemetry_seq_frame(seq));
    }
    shared.paused.store(true, Ordering::Release);
    push_budgeted_replay_frame(
        &shared,
        &mut replay_buf,
        telemetry_seq_frame(REPLAY_BUFFER_CAPACITY as u64 + 1),
    );
    assert!(
        !shared.session_evicted_while_paused.load(Ordering::Acquire),
        "telemetry eviction while paused must NOT poison the drain (#2875)"
    );

    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    handle_drain_request(5, &rx, &helper_side, &shared, &mut replay_buf);

    // The drain must complete normally — DrainComplete present, no FullResync.
    let mut saw_complete = false;
    while let Some((msg_type, _seq)) = try_read_frame_header(&mut daemon_side) {
        assert_ne!(
            msg_type, MSG_FULL_RESYNC,
            "telemetry eviction must not cause a spurious FullResync (#2875)"
        );
        if msg_type == MSG_DRAIN_COMPLETE {
            saw_complete = true;
        }
    }
    assert!(
        saw_complete,
        "non-poisoned drain must still report DrainComplete (#2875)"
    );
}

// #2875: a fresh pause window must start lossless — MSG_PAUSE clears any poison
// left by a previous drain so a stale flag cannot withhold this window's
// DrainComplete.
#[test]
fn test_pause_start_clears_drain_poison_2875() {
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();

    // Simulate a leftover poison from a prior window.
    shared
        .session_evicted_while_paused
        .store(true, Ordering::Release);

    // A PAUSE control frame must clear it.
    let mut pause = [0u8; FRAME_HEADER_SIZE];
    pause[4] = MSG_PAUSE;
    let (action, consumed) = process_control_frames(&pause, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    assert!(shared.paused.load(Ordering::Acquire));
    assert!(
        !shared.session_evicted_while_paused.load(Ordering::Acquire),
        "MSG_PAUSE must clear stale drain poison (#2875)"
    );
}
