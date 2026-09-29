// Daemon->helper control-frame parsing tests: ACK watermark validation
// (#2959), partial/multi-frame reads, and bounded control payloads (#2879).
// Split from event_stream/tests.rs (#4664).

use super::*;

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
    // next_seq reflects the highest allocated seq so the ACK is in-range
    // for the #2959 watermark validation.
    shared.next_seq.store(5, Ordering::Relaxed);

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
    shared.next_seq.store(10, Ordering::Relaxed);

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
    shared.next_seq.store(5, Ordering::Relaxed);

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

#[test]
fn test_future_ack_beyond_next_seq_ignored_2959() {
    // A daemon ACKs a sequence the helper never allocated (seq > next_seq).
    // The helper must fail closed: leave acked_seq and the replay buffer
    // intact and bump invalid_acks.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=5u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    // Highest allocated seq is 5; ACK 99 is impossible.
    shared.next_seq.store(5, Ordering::Relaxed);
    shared.acked_seq.store(2, Ordering::Relaxed);

    let raw = build_raw_ack_frame(99);
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) = process_control_frames(&raw, &shared, &rx, &sock_a, &mut replay_buf);

    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE, "frame is still consumed");
    // Watermark unchanged, replay buffer fully intact (no frames suppressed).
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 2);
    assert_eq!(
        replay_buf.len(),
        5,
        "future ACK must not trim replay buffer"
    );
    assert_eq!(replay_buf.front().unwrap().seq, 1);
    assert_eq!(shared.frames_invalid_acks.load(Ordering::Relaxed), 1);
}

#[test]
fn test_backward_ack_below_watermark_ignored_2959() {
    // A daemon ACKs a sequence below the current watermark. The helper must
    // ignore it: acked_seq stays put and the replay buffer is untouched.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 6..=10u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    shared.next_seq.store(10, Ordering::Relaxed);
    shared.acked_seq.store(5, Ordering::Relaxed);

    let raw = build_raw_ack_frame(3); // below acked_seq=5
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, consumed) = process_control_frames(&raw, &shared, &rx, &sock_a, &mut replay_buf);

    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    assert_eq!(
        shared.acked_seq.load(Ordering::Relaxed),
        5,
        "watermark intact"
    );
    assert_eq!(
        replay_buf.len(),
        5,
        "backward ACK must not trim replay buffer"
    );
    assert_eq!(replay_buf.front().unwrap().seq, 6);
    assert_eq!(shared.frames_invalid_acks.load(Ordering::Relaxed), 1);
}

#[test]
fn test_future_ack_does_not_suppress_lower_buffered_frames_2959() {
    // The core impact in #2959: an ACK above next_seq while the replay buffer
    // holds lower-seq frames must NOT trim/suppress those lower frames.
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=3u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    shared.next_seq.store(3, Ordering::Relaxed);
    shared.acked_seq.store(0, Ordering::Relaxed);

    // ACK 7 is beyond next_seq=3; without validation this would pop all three
    // buffered frames (1,2,3 <= 7) and store an impossible acked_seq=7.
    let raw = build_raw_ack_frame(7);
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
    let (action, _consumed) = process_control_frames(&raw, &shared, &rx, &sock_a, &mut replay_buf);

    assert!(action.is_none());
    assert_eq!(replay_buf.len(), 3, "lower buffered frames must survive");
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 0);
    assert_eq!(shared.frames_invalid_acks.load(Ordering::Relaxed), 1);
}

#[test]
fn test_valid_acks_trim_as_before_no_regression_2959() {
    // Boundary cases that MUST still be accepted:
    //   - seq == acked_seq (duplicate ACK, benign no-op)
    //   - acked < seq < next (normal forward ACK, trims)
    //   - seq == next_seq (ACK of the latest allocated frame)
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(16);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    for seq in 1..=5u64 {
        replay_buf.push_back(EventFrame::encode_drain_complete(seq));
    }
    shared.next_seq.store(5, Ordering::Relaxed);
    shared.acked_seq.store(0, Ordering::Relaxed);
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();

    // Duplicate ACK of the current watermark (0): benign no-op, no trim.
    let dup = build_raw_ack_frame(0);
    process_control_frames(&dup, &shared, &rx, &sock_a, &mut replay_buf);
    assert_eq!(replay_buf.len(), 5);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 0);

    // Normal forward ACK of 3: trims frames 1,2,3.
    let ack3 = build_raw_ack_frame(3);
    process_control_frames(&ack3, &shared, &rx, &sock_a, &mut replay_buf);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 3);
    assert_eq!(replay_buf.len(), 2);
    assert_eq!(replay_buf.front().unwrap().seq, 4);

    // ACK of the latest allocated seq (== next_seq=5): trims the rest.
    let ack5 = build_raw_ack_frame(5);
    process_control_frames(&ack5, &shared, &rx, &sock_a, &mut replay_buf);
    assert_eq!(shared.acked_seq.load(Ordering::Relaxed), 5);
    assert_eq!(replay_buf.len(), 0);

    // No invalid ACKs were recorded across the valid sequence.
    assert_eq!(shared.frames_invalid_acks.load(Ordering::Relaxed), 0);
}

// ---------------------------------------------------------------------------
// #2879 — daemon→helper control frames must have a bounded payload
// ---------------------------------------------------------------------------

// Build a control header with an arbitrary payload_len and opcode.
fn build_ctrl_header(payload_len: u32, msg_type: u8) -> [u8; FRAME_HEADER_SIZE] {
    let mut buf = [0u8; FRAME_HEADER_SIZE];
    buf[0..4].copy_from_slice(&payload_len.to_le_bytes());
    buf[4] = msg_type;
    buf
}

// #2879 fail-on-revert guard: a daemon that declares payload_len = 1<<30 and
// trickles bytes must be DISCONNECTED before the helper buffers the (never
// completing) frame, so ctrl_read_buf cannot grow without bound. Reverting the
// cap makes process_control_frames return (None, 0) — incomplete-frame break —
// and the bytes accumulate -> this goes RED.
#[test]
fn test_oversized_control_payload_disconnects_2879() {
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();

    let mut ctrl: Vec<u8> = Vec::new();
    ctrl.extend_from_slice(&build_ctrl_header(1u32 << 30, MSG_PAUSE));
    // Trickle a few payload bytes — far short of 1<<30.
    ctrl.extend_from_slice(&[0u8; 8]);

    let (action, _consumed) = process_control_frames(&ctrl, &shared, &rx, &sock_a, &mut replay_buf);
    assert_eq!(
        action,
        Some(true),
        "oversized payload_len must force a disconnect, not unbounded buffering (#2879)"
    );
    // The bogus PAUSE frame must NOT have been processed before the disconnect.
    assert!(
        !shared.paused.load(Ordering::Acquire),
        "an invalid oversized frame must not be applied (#2879)"
    );
}

// #2879: the current daemon→helper opcodes (Ack/Pause/Resume/DrainRequest) are
// header-only; a NONZERO payload_len on any of them is invalid and must be
// rejected (disconnect).
#[test]
fn test_nonzero_payload_on_header_only_opcodes_rejected_2879() {
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();

    for opcode in [MSG_ACK, MSG_PAUSE, MSG_RESUME, MSG_DRAIN_REQUEST] {
        let mut ctrl: Vec<u8> = Vec::new();
        // payload_len = 8 (nonzero) plus 8 payload bytes so the frame is fully
        // present — proving the rejection is on the length, not on completeness.
        ctrl.extend_from_slice(&build_ctrl_header(8, opcode));
        ctrl.extend_from_slice(&[0u8; 8]);
        let (action, _consumed) =
            process_control_frames(&ctrl, &shared, &rx, &sock_a, &mut replay_buf);
        assert_eq!(
            action,
            Some(true),
            "nonzero payload on header-only opcode {opcode} must be rejected (#2879)"
        );
    }
}

// #2879 no-regression: a legitimate header-only control frame whose HEADER is
// split across two reads must still parse once complete — the cap only rejects
// an invalid payload_len, never a merely-incomplete header.
#[test]
fn test_split_header_only_frame_still_parses_2879() {
    let shared = Arc::new(EventStreamShared::new());
    let (_tx, rx) = mpsc::sync_channel::<EventFrame>(4);
    let mut replay_buf: VecDeque<EventFrame> = VecDeque::new();
    let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();

    let header = build_ctrl_header(0, MSG_PAUSE); // header-only, zero payload
    let mut ctrl: Vec<u8> = Vec::new();

    // First read: only the first 8 bytes of the 16-byte header.
    ctrl.extend_from_slice(&header[..8]);
    let (action, consumed) = process_control_frames(&ctrl, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(
        action.is_none(),
        "partial header must not disconnect (#2879)"
    );
    assert_eq!(consumed, 0, "partial header must not be consumed");
    assert!(!shared.paused.load(Ordering::Acquire));

    // Second read: the rest of the header arrives; the PAUSE now applies.
    ctrl.extend_from_slice(&header[8..]);
    let (action, consumed) = process_control_frames(&ctrl, &shared, &rx, &sock_a, &mut replay_buf);
    assert!(action.is_none());
    assert_eq!(consumed, FRAME_HEADER_SIZE);
    assert!(
        shared.paused.load(Ordering::Acquire),
        "a header-only frame split across reads must still parse (#2879)"
    );
}
