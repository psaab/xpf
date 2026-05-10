# userspace-dp/src/event_stream/

Push-based binary session-delta stream. Replaces the previous polled
`drain_session_deltas` RPC: the helper sends frames to a Go-side
listener as session events occur, with monotonic sequence numbers and a
periodic ACK from the daemon.

## Files

- `mod.rs` — `EventStreamSender` owns its own I/O thread, connects to
  the daemon's listener, sends frames, handles reconnect on EPIPE.
- `codec.rs` — frame layout: 16-byte header
  `[length:u32 LE][type:u8][reserved:3][seq:u64 LE]` followed by the
  payload. Message types: `MSG_SESSION_OPEN`, `MSG_SESSION_CLOSE`,
  `MSG_SESSION_UPDATE`, `MSG_ACK`, `MSG_PAUSE`, `MSG_RESUME`,
  `MSG_DRAIN_REQUEST`, `MSG_DRAIN_COMPLETE`, `MSG_FULL_RESYNC`,
  `MSG_KEEPALIVE` (1..10).
- `codec_tests.rs`, `tests.rs` — co-located.

## Why push

Polled deltas at 1 Hz were missing fast-cycling sessions (open + close
between ticks). The push stream sees every transition. The Go listener
buffers and batches before forwarding to syslog / NetFlow.

## Gotchas

- The sequence number is monotonic across reconnects; the daemon ACKs
  the highest seen so the helper can prune its retransmit buffer.
- The default `push_delta()` path is **non-blocking** (`try_send`) and
  **silently drops** when the channel is full. The internal counter
  is `EventStreamShared.frames_dropped` (`mod.rs`); the surface
  exported through the daemon status JSON is `event_stream_dropped`
  (see `protocol.rs`). Use `push_delta_lossless()` only when
  correctness requires every frame and the producer can tolerate
  back-pressure.
