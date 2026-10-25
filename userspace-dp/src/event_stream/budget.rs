//! Dataplane-event queue-budget release for frames leaving the channel.
//!
//! Pure code motion out of `mod.rs` (#6235); no logic change. Queue-budget
//! ADMISSION happens on producer threads (`producer.rs`); this is the I/O-thread
//! RETIREMENT side.
//!
//! #16570: every telemetry frame releases exactly the per-kind budget slot it
//! acquired at emit, exactly once, when it LEAVES THE BOUNDED CHANNEL — in the
//! steady-state drain (`drain_channel_into_write_buf`), in the dormant
//! drain-request channel drain (`handle_drain_request`), or in the shutdown
//! channel drain (`drain_remaining`). A frame retained for replay carries no
//! slot: replay retention is bounded separately by `REPLAY_BUFFER_CAPACITY`
//! and counted by eviction (#2382), so ACK-trim / eviction / shutdown pops in
//! `replay.rs` must NOT release again. (Before #16570 the slot was held across
//! replay retention until ACK trim, shedding bursts above 820 closes per
//! ~100 ms ACK interval.)

use super::*;

pub(super) fn release_dataplane_event_queue_budget(
    shared: &Arc<EventStreamShared>,
    frame: &EventFrame,
) {
    if let Some(kind) = frame.dataplane_event_kind() {
        shared.dataplane_event_queue.release(kind);
    }
}
