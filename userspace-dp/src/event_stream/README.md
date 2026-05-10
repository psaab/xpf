# userspace-dp/src/event_stream/

Push-based binary session-delta stream. Replaces the previous polled
`drain_session_deltas` RPC: the helper sends frames to a Go-side
listener as session events occur, with monotonic sequence numbers and a
periodic ACK from the daemon.

## Files

- `mod.rs` — `EventStreamSender` owns its own I/O thread, connects to
  the daemon's listener, sends frames, handles reconnect on EPIPE.
- `codec.rs` — frame layout: `(op, seq, payload_len, payload)` where
  `op` ∈ `OPEN`, `UPDATE`, `CLOSE`, `ACK`. Little-endian, fixed-width
  header.
- `codec_tests.rs`, `tests.rs` — co-located.

## Why push

Polled deltas at 1 Hz were missing fast-cycling sessions (open + close
between ticks). The push stream sees every transition. The Go listener
buffers and batches before forwarding to syslog / NetFlow.

## Gotchas

- The sequence number is monotonic across reconnects; the daemon ACKs
  the highest seen so the helper can prune its retransmit buffer.
- If the daemon is slow to drain, the helper's send queue fills and
  blocks the worker thread that produced the event. That's intentional
  back-pressure — there is no silent drop.
