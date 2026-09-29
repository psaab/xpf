//! Wire codec for the event stream binary protocol.
//!
//! Pure encoding/decoding functions with zero I/O — all frame construction
//! happens on a stack-allocated fixed buffer sized for a session's stable
//! policy-rule identity.

mod decode;
mod rt_flow;
mod session_sync;
mod wire;

// Re-export the full wire-contract surface so every pre-split `codec::<item>`
// path (external consumers + the relocated test module via `use super::*`)
// resolves unchanged. Glob re-exports cap each name at its own visibility, so
// the pub(super) internals stay codec-internal while the pub(crate) surface
// stays crate-visible. `EventFrame` itself is defined below (kept in the
// module root so its pub(super) fields/methods keep `pub(in event_stream)`
// visibility unchanged).
pub(crate) use decode::*;
pub(crate) use rt_flow::*;
pub(crate) use session_sync::*;
pub(crate) use wire::*;

// ---------------------------------------------------------------------------
// EventFrame -- zero-allocation stack-buffered wire frame
// ---------------------------------------------------------------------------

pub(super) const EVENT_FRAME_CAPACITY: usize = 512;
/// Pre-serialized event frame ready for socket write.
#[derive(Clone)]
pub(crate) struct EventFrame {
    pub(super) data: [u8; EVENT_FRAME_CAPACITY],
    pub(super) len: u16,
    pub(crate) seq: u64,
}

impl EventFrame {
    /// The raw bytes of this frame (header + payload).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    #[allow(dead_code)]
    pub(crate) fn dataplane_event_payload(&self) -> Option<&[u8]> {
        DataplaneEventKind::from_msg_type(self.data[4])?;
        let payload_len = u32::from_le_bytes(self.data[0..4].try_into().ok()?) as usize;
        if payload_len != SECURITY_EVENT_PAYLOAD_SIZE {
            return None;
        }
        let end = FRAME_HEADER_SIZE + payload_len;
        if (self.len as usize) < end {
            return None;
        }
        Some(&self.data[FRAME_HEADER_SIZE..end])
    }

    pub(super) fn dataplane_event_kind(&self) -> Option<DataplaneEventKind> {
        DataplaneEventKind::from_msg_type(self.data[4])
    }

    /// True for the correctness-critical HA session-sync deltas
    /// (`SessionOpen` / `SessionUpdate` / `SessionClose`). These mutate peer
    /// session state on failover, so they must not be silently dropped from a
    /// paused demotion drain window (#2875). Telemetry / RT_FLOW frames
    /// (deny / screen / filter, RT_FLOW session create+close) return `false`:
    /// evicting them is a tolerated telemetry loss, not a demotion-correctness
    /// failure, and must not trigger a spurious FullResync. Same discriminator
    /// (`data[4]` msg_type) the budget/release path keys on (#2874).
    pub(super) fn is_session_sync(&self) -> bool {
        matches!(
            self.data[4],
            MSG_SESSION_OPEN | MSG_SESSION_CLOSE | MSG_SESSION_UPDATE
        )
    }

    #[allow(dead_code)]
    pub(crate) fn decode_dataplane_event(&self) -> Option<DataplaneEventPayload> {
        decode_dataplane_event(self.data[4], self.dataplane_event_payload()?)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
