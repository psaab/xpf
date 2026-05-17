// Tests for event_stream/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from mod.rs.

use super::codec::MSG_FULL_RESYNC;
use super::*;
use std::io::Read;

fn build_raw_ack_frame(seq: u64) -> [u8; FRAME_HEADER_SIZE] {
    let mut buf = [0u8; FRAME_HEADER_SIZE];
    // payload_len = 0 (header-only)
    buf[0..4].copy_from_slice(&0u32.to_le_bytes());
    buf[4] = MSG_ACK;
    // reserved bytes 5..8 stay zero
    buf[8..16].copy_from_slice(&seq.to_le_bytes());
    buf
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

    replay_buffered(&helper_side, &mut replay_buf, 0, &shared).expect("replay gap");

    let mut hdr = [0u8; FRAME_HEADER_SIZE];
    daemon_side.read_exact(&mut hdr).expect("full resync frame");
    assert_eq!(hdr[4], MSG_FULL_RESYNC);
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 1);
    assert_eq!(
        replay_buf.front().map(|f| f.seq),
        Some(2),
        "full resync keeps stale replay window until the daemon ACKs"
    );
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

#[test]
fn test_partial_read_accumulation() {
    // Simulate a partial Unix stream read: first 8 bytes, then the
    // remaining 8 bytes of a 16-byte ACK frame.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    // Seed replay buffer so we can observe the trim from the ACK.
    for seq in 1..=5u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }

    let raw = build_raw_ack_frame(3);
    let mut ctrl_buf: Vec<u8> = Vec::new();

    // We don't have a real stream for this unit test, so call
    // process_control_frames directly with partial data.

    // First "read": only the first 8 bytes arrive.
    ctrl_buf.extend_from_slice(&raw[..8]);
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, 0, "partial frame must not be consumed");
    // Replay buffer untouched -- no ACK processed yet
    assert_eq!(replay_buf.len(), 5);

    // Second "read": remaining 8 bytes arrive.
    ctrl_buf.extend_from_slice(&raw[8..]);
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    // ACK seq=3 should have trimmed frames 1,2,3
    assert_eq!(replay_buf.len(), 2);
    assert_eq!(replay_buf.front().unwrap().seq, 4);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 3);

    // Drain consumed bytes as the real loop would.
    ctrl_buf.drain(..consumed);
    assert!(ctrl_buf.is_empty());
}

#[test]
fn test_two_frames_in_one_read() {
    // Two complete ACK frames arrive in a single read.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=10u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }

    let ack5 = build_raw_ack_frame(5);
    let ack8 = build_raw_ack_frame(8);
    let mut ctrl_buf: Vec<u8> = Vec::new();
    ctrl_buf.extend_from_slice(&ack5);
    ctrl_buf.extend_from_slice(&ack8);

    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, 2 * FRAME_HEADER_SIZE);
    // ACK 5, then ACK 8 -- replay should have frames 9,10
    assert_eq!(replay_buf.len(), 2);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 8);
}

#[test]
fn test_one_and_half_frames() {
    // 1.5 frames: one complete ACK + first 4 bytes of next frame.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=5u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }

    let ack2 = build_raw_ack_frame(2);
    let ack4 = build_raw_ack_frame(4);
    let mut ctrl_buf: Vec<u8> = Vec::new();
    ctrl_buf.extend_from_slice(&ack2);
    ctrl_buf.extend_from_slice(&ack4[..4]); // partial second frame

    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE); // only first frame consumed
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 2);
    assert_eq!(replay_buf.len(), 3); // frames 3,4,5 remain

    // Drain consumed, then "read" remaining bytes of second frame.
    ctrl_buf.drain(..consumed);
    assert_eq!(ctrl_buf.len(), 4);
    ctrl_buf.extend_from_slice(&ack4[4..]);

    let (action, consumed) =
        process_control_frames(&ctrl_buf, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 4);
    assert_eq!(replay_buf.len(), 1); // only frame 5 remains
}
