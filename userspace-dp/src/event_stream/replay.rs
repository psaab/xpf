//! Replay-buffer admission, eviction, and retirement.
//!
//! Pure code motion out of `mod.rs` (#6235); no logic change. The I/O thread
//! keeps accepted-and-enqueued frames in a bounded `VecDeque` replay buffer so a
//! reconnect can re-send everything the daemon has not yet ACKed. This module
//! owns admission (`push_replay_frame`), the two removal paths (buffer-full
//! `evict_replay_frame` which counts a telemetry loss, and the non-loss
//! `pop_replay_frame` used by ACK-trim / shutdown), and the shutdown bulk drain
//! (`release_replay_dataplane_event_queue_budget`).
//!
//! #16570: the dataplane-event queue budget is an IN-CHANNEL budget — it is
//! released when a frame leaves the bounded mpsc channel
//! (`drain_channel_into_write_buf`, `handle_drain_request`, or the shutdown
//! `drain_remaining`), NOT when the frame leaves this replay buffer. Replay
//! retention is bounded separately by `REPLAY_BUFFER_CAPACITY` and counted by
//! `frames_replay_evicted` on wrap (#2382). Frames therefore carry NO budget
//! slot while retained here, so eviction/ACK-trim/shutdown pops below must NOT
//! release the budget — doing so would double-release the channel-exit release
//! and trip the #1826 underflow guard. (Before #16570 the slot was held across
//! replay retention and released only on ACK trim, which shed every
//! SessionClose/SessionCreate burst above 820 frames per ~100 ms ACK interval.)

use super::*;

pub(super) fn push_replay_frame(
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
    frame: EventFrame,
) {
    if replay_buf.len() >= REPLAY_BUFFER_CAPACITY {
        // Buffer-full eviction: the oldest accepted-and-enqueued frame is
        // dropped before the daemon ACKed it. It was already counted in
        // `frames_sent`, so it must be counted as a telemetry loss here
        // (#2382). This is distinct from ACK-trim / shutdown drain, which
        // remove frames via `pop_replay_frame` WITHOUT bumping the eviction
        // counter (an ACKed frame is delivered, not lost).
        evict_replay_frame(shared, replay_buf);
    }
    replay_buf.push_back(frame);
}

/// Evict the oldest replay frame because the buffer wrapped at capacity. This
/// is the ONLY telemetry-loss removal path: it increments
/// `frames_replay_evicted` (#2382). It does NOT release the queue budget —
/// the evicted frame's slot was already released when it left the channel
/// (#16570); replay retention never held one.
fn evict_replay_frame(
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
) -> Option<EventFrame> {
    let frame = pop_replay_frame(shared, replay_buf);
    if let Some(evicted) = frame.as_ref() {
        shared.frames_replay_evicted.fetch_add(1, Ordering::Relaxed);
        // #2875: evicting a SESSION-SYNC delta WHILE PAUSED loses a session
        // mutation the future owner needs to take over cleanly. Poison the
        // pending demotion drain so `handle_drain_request` withholds
        // DrainComplete and forces a FullResync instead of silently
        // completing demotion. Telemetry eviction is a tolerated loss and
        // must NOT poison (no spurious resync). Read `paused` here so the
        // poison fires for evictions both in the connected-loop paused drain
        // and in the drain-request drain loop (both run while paused).
        if evicted.is_session_sync() && shared.paused.load(Ordering::Acquire) {
            shared
                .session_evicted_while_paused
                .store(true, Ordering::Release);
        }
    }
    frame
}

/// Remove the oldest replay frame WITHOUT counting it as an eviction and
/// WITHOUT releasing the queue budget (the slot was released at channel exit,
/// #16570). Used by ACK-trim (the frame was acknowledged — delivered, not
/// lost) and shutdown drain. The buffer-full loss path is
/// `evict_replay_frame`.
pub(super) fn pop_replay_frame(
    _shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
) -> Option<EventFrame> {
    replay_buf.pop_front()
}

/// Remove every retained replay frame at shutdown. Despite the historical
/// name, this no longer releases any queue budget: since #16570 no frame
/// retained here holds a budget slot (each was released when it left the
/// channel, or — for frames still in the channel at shutdown — by
/// `drain_remaining`, which runs before this call). It simply empties the
/// buffer; the #2382 eviction counter is not bumped.
pub(super) fn release_replay_dataplane_event_queue_budget(
    shared: &Arc<EventStreamShared>,
    replay_buf: &mut VecDeque<EventFrame>,
) {
    while pop_replay_frame(shared, replay_buf).is_some() {}
}
