//! Channel-drain mechanics: move produced frames from the bounded mpsc channel
//! into the pending socket-write backlog and the replay buffer, merge the parked
//! ordered FullResync barrier (#5267), and drain the channel on shutdown.
//!
//! Pure code motion out of `mod.rs` (#6235); no logic change. The
//! `WRITE_BACKLOG_MAX_BYTES` cap (#2381/#4974) is enforced here on the UNWRITTEN
//! backlog length so a wedged reader cannot migrate the whole channel into the
//! heap-backed write backlog.

use super::*;

/// Drain remaining events from the channel on shutdown.
pub(super) fn drain_remaining(rx: &mpsc::Receiver<EventFrame>, shared: &Arc<EventStreamShared>) {
    loop {
        match rx.try_recv() {
            Ok(frame) => release_dataplane_event_queue_budget(shared, &frame),
            Err(_) => break,
        }
    }
}

/// Outcome of one channel-drain pass in the connected loop.
pub(super) struct DrainOutcome {
    /// At least one frame was pulled from the channel this pass.
    pub(super) drained_any: bool,
    /// The channel sender side was dropped (helper shutting down).
    pub(super) disconnected: bool,
    /// The write backlog hit `WRITE_BACKLOG_MAX_BYTES` and the drain was
    /// halted before emptying the channel (stalled-consumer signal). Exposed
    /// for tests; the loop relies on the side-effect counter.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) stalled: bool,
}

/// Drain the bounded channel into `replay_buf` and (when not paused) into the
/// pending socket-write backlog `write_buf`.
///
/// The drain halts once the UNWRITTEN backlog (`write_buf.pending_len()`, #4974)
/// reaches `WRITE_BACKLOG_MAX_BYTES` (#2381). Without that cap a wedged daemon
/// (socket open but not reading → the socket `write` returns `WouldBlock`) lets
/// this loop migrate the entire bounded channel into the heap-backed `write_buf`
/// every cycle; the channel then refills from worker `try_send`, the loop drains
/// it again, and `write_buf` grows without bound → helper OOM / allocator
/// pressure on the forwarding plane. Halting the drain leaves the frames in the
/// bounded channel, which becomes the real backpressure surface: worker
/// `try_send` then fails and increments the existing `frames_dropped` / per-kind
/// `queue_full` counters (oldest queued/replay frames are preserved; newest
/// producer events are shed — keeping RT_FLOW current). Each pass that hits the
/// cap bumps `frames_write_stalled` so a wedged consumer is observable rather
/// than a silent OOM.
///
/// The cap is measured on `pending_len()` (unwritten bytes), not the raw
/// `WriteBacklog` `Vec` length: the cursor-backed backlog keeps a reclaimable
/// prefix of already-written bytes, so raw length can sit at ~2× pending until
/// the next geometric compaction. Measuring raw length would trip the cap early
/// and drift the pause/resume accounting.
///
/// The cap does not apply while paused: paused frames are consumed into the
/// already-bounded replay buffer only, never into `write_buf`, so they cannot
/// grow the backlog.
///
/// #16570: each frame pulled here releases its dataplane-event queue budget
/// (the budget bounds this channel, not the replay buffer that retains the
/// copy for ACK/replay — that retention is bounded separately by
/// `REPLAY_BUFFER_CAPACITY` and counted by eviction, #2382).
pub(super) fn drain_channel_into_write_buf(
    rx: &mpsc::Receiver<EventFrame>,
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
    write_buf: &mut WriteBacklog,
    paused: bool,
    pending_resync: &mut Option<EventFrame>,
) -> DrainOutcome {
    let mut drained_any = false;
    loop {
        // #4974: the cap measures UNWRITTEN bytes (`pending_len`), not the raw
        // backing-Vec length, which also counts the reclaimable written prefix.
        if !paused && write_buf.pending_len() >= WRITE_BACKLOG_MAX_BYTES {
            shared.frames_write_stalled.fetch_add(1, Ordering::Relaxed);
            return DrainOutcome {
                drained_any,
                disconnected: false,
                stalled: true,
            };
        }
        match rx.try_recv() {
            Ok(frame) => {
                drained_any = true;
                // #16570: the frame has left the bounded channel — that is
                // the queue this budget bounds. Release its telemetry slot
                // here, not on ACK trim: with the connected Go ACK on a
                // 100 ms tick, holding the slot until ACK shed every
                // close/create burst above the per-kind in-channel budget
                // (ceil((8192/2)/5)=820) within one ACK interval, defeating
                // the #14609 "below channel capacity a close is never shed"
                // contract. Replay retention stays bounded and counted by
                // REPLAY_BUFFER_CAPACITY eviction (#2382), which is a
                // separate bound and no longer double-counts this slot:
                // `push_replay_frame`/`pop_replay_frame` must therefore NOT
                // release again (see replay.rs). The release is placed
                // before `push_replay_frame` so an eviction of an older
                // frame triggered by this push cannot take the slot.
                release_dataplane_event_queue_budget(shared, &frame);
                // #5267: flush a parked FullResync barrier just BEFORE the first
                // channel frame whose seq exceeds it, so the wire stays
                // monotonic. The barrier's seq was allocated under
                // `producer_seq_lock`, so every delta already queued has a lower
                // seq and is emitted first; only a delta committed AFTER the
                // barrier has a higher seq and must follow it.
                let flush_before_frame = match pending_resync.as_ref() {
                    Some(barrier) => frame.seq > barrier.seq,
                    None => false,
                };
                if flush_before_frame {
                    flush_pending_resync(shared, replay_buf, write_buf, paused, pending_resync);
                }
                if !paused {
                    write_buf.extend_from_slice(frame.as_bytes());
                }
                push_replay_frame(shared, replay_buf, frame);
            }
            Err(TryRecvError::Empty) => {
                // Channel fully drained: every delta with a lower seq than the
                // barrier has been emitted (the barrier is the current max — its
                // seq was allocated under the producer lock), so it is safe to
                // flush the barrier now (#5267). Without a trailing higher-seq
                // delta this is the ONLY place the barrier is emitted.
                let flushed =
                    flush_pending_resync(shared, replay_buf, write_buf, paused, pending_resync);
                return DrainOutcome {
                    drained_any: drained_any || flushed,
                    disconnected: false,
                    stalled: false,
                };
            }
            Err(TryRecvError::Disconnected) => {
                return DrainOutcome {
                    drained_any,
                    disconnected: true,
                    stalled: false,
                };
            }
        }
    }
}

/// #5267: move a parked replay-gap FullResync barrier out of `pending_resync`
/// into the ordered write/replay path so ACK-trim and a later reconnect treat
/// it like any other accepted frame while keeping the replay buffer seq-ordered.
///
/// `frames_sent` is bumped HERE, when the ordered drain accepts the barrier,
/// not when `replay_buffered` merely parks it. This matches the existing
/// producer accounting, which counts a successful channel enqueue before the
/// socket write. When paused, the barrier is appended to the replay buffer only
/// (like every other paused frame) and NOT to `write_buf`; a reconnect replays
/// it, while #5328 tracks the pre-existing defect that plain `MSG_RESUME` does
/// not schedule the intact paused replay suffix on the same connection.
/// Returns true if a barrier was consumed into the ordered output/replay path.
pub(super) fn flush_pending_resync(
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
    write_buf: &mut WriteBacklog,
    paused: bool,
    pending_resync: &mut Option<EventFrame>,
) -> bool {
    if let Some(barrier) = pending_resync.take() {
        if !paused {
            write_buf.extend_from_slice(barrier.as_bytes());
        }
        shared.frames_sent.fetch_add(1, Ordering::Relaxed);
        push_replay_frame(shared, replay_buf, barrier);
        true
    } else {
        false
    }
}
