//! Daemon->helper control-frame decode and the drain/resync state machine.
//!
//! Pure code motion out of `mod.rs` (#6235); no logic change. `process_control_frames`
//! parses the accumulated control-read buffer (ACK watermark validation #2959,
//! Pause/Resume, DrainRequest) and `handle_drain_request` runs the DORMANT
//! seq-fenced drain (#2876/#2882/#2875 drain poison). Both write through the
//! stop-aware backpressured writer so a stuck reader can never wedge the I/O
//! thread.

use super::*;

/// Process control frames received from the daemon.
/// Returns (action, bytes_consumed) where action is Some(true) to reconnect,
/// Some(false) to stop, or None to continue. Only complete frames are consumed;
/// any trailing partial frame is left for the next read cycle.
pub(super) fn process_control_frames(
    data: &[u8],
    shared: &Arc<EventStreamShared>,
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    replay_buf: &mut VecDeque<EventFrame>,
) -> (Option<bool>, usize) {
    let mut offset = 0;
    while offset + FRAME_HEADER_SIZE <= data.len() {
        let payload_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        // #2879: reject an impossible payload_len BEFORE waiting for the rest of
        // the frame. The full header is present (loop guard above), so we can
        // validate the declared length on the header alone, regardless of how
        // few payload bytes have arrived. Every current daemon->helper opcode is
        // header-only, so any payload_len beyond MAX_CONTROL_PAYLOAD_LEN can
        // never form a valid frame. Disconnecting (Some(true) -> reconnect,
        // which clears ctrl_read_buf) stops a buggy/compromised daemon from
        // trickling a 1<<30-length header and growing ctrl_read_buf without
        // bound on the forwarding plane. A legitimately partial header-only
        // frame still works: a payload_len of 0 passes here, and a split HEADER
        // never reaches this point (the loop guard requires a full 16-byte
        // header first). `offset` is returned so any complete frames parsed
        // before the bad one are still accounted as consumed.
        if payload_len as usize > MAX_CONTROL_PAYLOAD_LEN {
            eprintln!(
                "xpf-event-stream: control frame opcode {} declared payload_len={} \
                 exceeds max {} -- disconnecting (#2879)",
                data[offset + 4],
                payload_len,
                MAX_CONTROL_PAYLOAD_LEN
            );
            return (Some(true), offset);
        }
        let frame_len = FRAME_HEADER_SIZE + payload_len as usize;
        if offset + frame_len > data.len() {
            break; // incomplete frame -- wait for more data
        }
        let msg_type = data[offset + 4];
        let seq = u64::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        offset += frame_len;

        match msg_type {
            MSG_ACK => {
                // Validate the ACK watermark BEFORE mutating acked_seq or
                // trimming the replay buffer (#2959). A correct daemon ACKs
                // only frames it has applied, so the sequence must lie in the
                // window [acked_seq, next_seq]:
                //   - seq == acked_seq  -> duplicate ACK, benign no-op
                //   - seq == next_seq   -> ACK of the latest allocated frame
                //   - acked < seq < next -> normal forward ACK
                // A backward ACK (seq < acked_seq) or a future ACK of a
                // sequence the helper never allocated (seq > next_seq) means
                // the peer's view is corrupt (buggy / mixed-version /
                // corrupted listener). Trusting it would poison acked_seq and
                // trim or permanently suppress replay of frames the daemon has
                // not actually acknowledged. Fail closed: ignore the impossible
                // ACK, leave the watermark and replay buffer intact, and
                // surface it via the invalid_acks counter. Ignoring (rather
                // than disconnecting) preserves the live connection and avoids
                // a reconnect-thrash loop against a peer that keeps emitting
                // bad ACKs; valid ACKs interleaved with the bad ones still
                // advance the watermark normally.
                let acked = shared.acked_seq.load(Ordering::Acquire);
                let next = shared.next_seq.load(Ordering::Acquire);
                if seq < acked || seq > next {
                    shared.frames_invalid_acks.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "xpf-event-stream: ignoring out-of-range ACK seq={} \
                         (acked={}, next={})",
                        seq, acked, next
                    );
                } else {
                    shared.acked_seq.store(seq, Ordering::Release);
                    // Trim replay buffer: remove frames with seq <= acked
                    while let Some(front) = replay_buf.front() {
                        if front.seq <= seq {
                            pop_replay_frame(shared, replay_buf);
                        } else {
                            break;
                        }
                    }
                }
            }
            MSG_PAUSE => {
                // #2875: a fresh pause window starts lossless. Clear any poison
                // left from a previous drain so only an eviction WITHIN this
                // pause window can withhold the upcoming DrainComplete.
                shared
                    .session_evicted_while_paused
                    .store(false, Ordering::Release);
                shared.paused.store(true, Ordering::Release);
                eprintln!("xpf-event-stream: paused by daemon");
            }
            MSG_RESUME => {
                shared.paused.store(false, Ordering::Release);
                eprintln!("xpf-event-stream: resumed by daemon");
                // Flush any buffered-during-pause frames on next write cycle
            }
            MSG_DRAIN_REQUEST => {
                // Drain channel until we have all events up to target seq,
                // then send DrainComplete.
                let target_seq = seq;
                handle_drain_request(target_seq, rx, stream, shared, replay_buf);
            }
            _ => {
                eprintln!("xpf-event-stream: unknown control frame type {}", msg_type);
            }
        }
    }
    (None, offset)
}

/// Handle DrainRequest: drain channel, write all buffered events up to target
/// seq, then send DrainComplete.
///
/// RESERVED / DORMANT: the Go daemon never sends `MSG_DRAIN_REQUEST` in
/// production (`EventStream.SendDrainRequest` has no live caller). Graceful
/// demotion synchronizes via the session-sync peer barrier plus the continuous
/// lossless event stream; bulk republish on loss-of-sync uses the unbounded
/// `ExportOwnerRGSessions` snapshot triggered by a FullResync, not this
/// seq-fenced drain. This handler (and the `MSG_DRAIN_REQUEST=7` /
/// `MSG_DRAIN_COMPLETE=8` frames) is retained — hardened by #2876/#2920 — for a
/// possible future fenced-drain use. See docs/session-sync-architecture.md.
pub(super) fn handle_drain_request(
    target_seq: u64,
    rx: &mpsc::Receiver<EventFrame>,
    stream: &UnixStream,
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
) {
    let deadline = Instant::now() + Duration::from_millis(200);
    let was_paused = shared.paused.load(Ordering::Acquire);

    // Drain channel until we've seen target_seq or timeout. `reached_target`
    // records whether the fence was actually reached: a timeout below the fence
    // (#2876) must NOT be reported as a successful DrainComplete, because the
    // events after the fence have not been flushed to the daemon/peer.
    let mut reached_target = false;
    loop {
        match rx.try_recv() {
            Ok(frame) => {
                let frame_seq = frame.seq;
                push_replay_frame(shared, replay_buf, frame);
                if frame_seq >= target_seq {
                    reached_target = true;
                    break;
                }
            }
            Err(TryRecvError::Empty) => {
                // Check if we already have the target in replay buf
                if replay_buf
                    .back()
                    .map(|f| f.seq >= target_seq)
                    .unwrap_or(false)
                {
                    reached_target = true;
                    break;
                }
                if Instant::now() >= deadline {
                    eprintln!(
                        "xpf-event-stream: drain timeout below fence, highest_seq={} target={}",
                        replay_buf.back().map(|f| f.seq).unwrap_or(0),
                        target_seq
                    );
                    break;
                }
                thread::sleep(Duration::from_micros(100));
            }
            Err(TryRecvError::Disconnected) => break,
        }
    }

    // Write replay-buffered frames to the socket using the canonical
    // nonblocking + stop-aware backpressure writer (#2877). The socket stays
    // nonblocking (the connected loop set it so); a stuck reader can no longer
    // wedge the I/O thread in a blocking write, and a raised stop flag is
    // observed within one poll interval. A shared deadline bounds the whole
    // drain write.
    let write_deadline = Instant::now() + REPLAY_DRAIN_WRITE_DEADLINE;
    let mut write_failed = false;
    // #2882: honor the fence — write only frames UP TO the requested target,
    // not the whole replay head. DrainRequest is contracted (see
    // docs/session-sync-design.md) as "flush all buffered events up to target
    // seq". Frames newer than the fence belong to a later drain/replay;
    // flushing (and reporting) them here changes the contract to "dump current
    // replay head", which masks holes and couples demotion correctness to
    // unrelated later-buffered frames. `drained_up_to` tracks the highest seq
    // <= target actually written (the replay buffer is seq-ordered).
    let mut drained_up_to = 0u64;
    for frame in replay_buf.iter() {
        if frame.seq > target_seq {
            continue; // beyond the fence — not part of this drain
        }
        if let Err(e) = write_all_backpressured(stream, frame.as_bytes(), shared, write_deadline) {
            eprintln!("xpf-event-stream: drain write error: {e}");
            write_failed = true;
            break;
        }
        drained_up_to = frame.seq;
    }

    // Send DrainComplete ONLY when the target fence was reached AND every frame
    // up to it was flushed. If the drain timed out below the fence, or a write
    // failed against a stuck/stopping reader, withhold DrainComplete: the
    // daemon's SendDrainRequest then times out (or rejects a below-target seq)
    // and refuses to proceed with demotion, rather than silently losing the
    // post-fence sessions on failover (#2876/#2877).
    //
    // #2882: report the fence the daemon requested, not replay_buf.back().seq
    // (which could exceed the target). Everything with seq <= target_seq is now
    // flushed, so report the highest such seq actually written; if the buffer
    // held nothing at/below the fence (all already ACK-trimmed), the fence is
    // still satisfied, so report target_seq.
    let drain_seq = if drained_up_to == 0 {
        target_seq
    } else {
        drained_up_to
    };

    // #2875: a SESSION-SYNC delta was evicted from the bounded replay buffer
    // while paused, so this drain window is missing mutations the new owner
    // needs. The drain is POISONED: it must NOT report DrainComplete (that
    // would complete demotion with lost sessions on the peer). Checked AFTER
    // the drain+write loops so an eviction during this drain's own
    // push_replay_frame calls is also caught.
    let session_evicted = shared.session_evicted_while_paused.load(Ordering::Acquire);

    if session_evicted {
        // Surface the poison the same way as #2874 / the replay-gap path: emit
        // a FullResync so the daemon re-exports full session state. The
        // daemon's SendDrainRequest receives no DrainComplete, times out, and
        // refuses to proceed with demotion until the resync re-establishes
        // state. Allocate a fresh seq (mirrors replay_buffered's resync).
        let resync_seq = shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let resync_frame = EventFrame::encode_full_resync(resync_seq);
        if let Err(e) =
            write_all_backpressured(stream, resync_frame.as_bytes(), shared, write_deadline)
        {
            eprintln!("xpf-event-stream: drain-poison FullResync write error: {e}");
        } else {
            shared.frames_sent.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "xpf-event-stream: drain POISONED -- session delta evicted while paused; \
                 sent FullResync seq {} instead of DrainComplete (demotion must full-resync)",
                resync_seq
            );
        }
        // Window consumed: clear so a later clean drain in this pause window can
        // complete (a fresh session-frame eviction re-poisons).
        shared
            .session_evicted_while_paused
            .store(false, Ordering::Release);
    } else if reached_target && !write_failed {
        let complete_frame = EventFrame::encode_drain_complete(drain_seq);
        if let Err(e) =
            write_all_backpressured(stream, complete_frame.as_bytes(), shared, write_deadline)
        {
            eprintln!("xpf-event-stream: drain complete write error: {e}");
        } else {
            shared.frames_sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Restore pause state
    if was_paused {
        shared.paused.store(true, Ordering::Release);
    }

    if session_evicted {
        // Already logged above (poison + FullResync).
    } else if reached_target {
        eprintln!("xpf-event-stream: drain complete up to seq {}", drain_seq);
    } else {
        eprintln!(
            "xpf-event-stream: drain incomplete (below fence), highest_seq={} target={} -- DrainComplete withheld",
            drain_seq, target_seq
        );
    }
}
