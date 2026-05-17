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
  `MSG_KEEPALIVE` (1..10), plus RT_FLOW dataplane telemetry frames
  `MSG_POLICY_DENY`, `MSG_SCREEN_DROP`, and `MSG_FILTER_LOG` (11..13).
  The telemetry frame payload is not a userspace-specific schema: it is
  the same 136-byte `dataplane.Event` layout consumed by the Go ringbuf
  logger, including AF values 2/10 and big-endian L4 ports. Userspace
  telemetry may also populate the non-session metadata slots used by
  the Go adapter for action, rule ID, term ID, reason, owner RG,
  ingress ifindex, and application ID.
- `codec_tests.rs`, `tests.rs` — co-located.

## Why push

Polled deltas at 1 Hz were missing fast-cycling sessions (open + close
between ticks). The push stream sees every transition. The Go listener
feeds RT_FLOW dataplane events through the same `logging.EventReader`
path as ringbuf records, so EventBuffer, callbacks, local writers,
syslog, NetFlow/IPFIX consumers, and name resolution stay consistent
between eBPF and userspace transports. The listener is wired in both HA
cluster and standalone userspace modes; only session replication remains
cluster-scoped.

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
- The Go daemon must know every helper→daemon frame type that carries a
  sequence number. For RT_FLOW-style dataplane telemetry, the daemon
  decodes valid frames through the same RT_FLOW adapter used for ringbuf
  records into `logging.EventRecord`; malformed or
  forward-version unknown frames are explicitly counted, dropped, and
  ACKed so the helper replay buffer cannot churn forever on an
  unconsumable event.
- Callback-dependent frames are ACKed only after the relevant daemon
  callback has consumed them. If the helper connects before session-sync
  or RT_FLOW callbacks are wired, the daemon queues a bounded prefix and
  withholds the cumulative ACK; overflow closes the stream so the helper
  replays instead of silently losing audit or HA session events. If the
  replay buffer no longer contains `acked_seq + 1`, the helper sends a
  FullResync request even when `acked_seq == 0`; this covers the
  boot-time queue-overflow case where seq 1 was trimmed before any ACK.
- Session callbacks and FullResync callbacks are ACK gates. A callback
  that returns false means the daemon is not ready or did not complete
  the side effect, so ACK remains withheld and the helper must replay.
- Daemon-side transport counters are exported as
  `xpf_userspace_event_stream_*` Prometheus metrics from
  `ProcessStatus.EventStream`. Helper-side send/drop counters remain in
  the helper status fields.
