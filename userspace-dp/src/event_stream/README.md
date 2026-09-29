# userspace-dp/src/event_stream/

Push-based binary session-delta stream. Replaces the previous polled
`drain_session_deltas` RPC: the helper sends frames to a Go-side
listener as session events occur, with monotonic sequence numbers and a
periodic ACK from the daemon.

## Files

- `mod.rs` — the module facade: `EventStreamSender` (owns the I/O thread),
  the shared `EventStreamShared` atomics/state, `EventStreamStats`, the
  `EventStreamWorkerHandle` producer core (sequence reservation/rollback,
  bounded/lossless channel admission, `push_delta`/`push_delta_lossless`),
  config constants, and the I/O-thread bootstrap. The transport/producer
  state machine was split into the cohesive submodules below (#6235, pure
  code motion); `mod.rs` re-exports the moved helpers so callers and the
  test tree resolve unchanged.
- `clock.rs` — monotonic-to-wall-clock conversion for the flow-export wire
  fields (`read_mono_and_wall_clocks`, `monotonic_ns_to_unix_ns/_secs/
  _secs_subnanos`, `mono_ns_to_wall_clock_unix_ns`; #2465/#2853/#2470).
- `backlog.rs` — the cursor-backed `WriteBacklog` (geometric compaction,
  #4974) and the `WRITE_BACKLOG_MAX_BYTES` cap (#2381).
- `producer.rs` — non-blocking helper-side producer API for RT_FLOW
  telemetry: per-kind/per-zone rate limiter, queue-budget ADMISSION and
  counters, and `try_emit_dataplane_frame` (see below).
- `rt_flow.rs` — the RT_FLOW SESSION_CLOSE/SESSION_CREATE projection
  emitters (`emit_session_close_rt_flow`, `emit_session_create_rt_flow`).
- `connection.rs` — the I/O thread: reconnect loop (`io_thread_main`,
  `try_connect`), un-ACKed replay (`replay_buffered`), the stop-aware
  backpressured writer (`write_all_backpressured`, #2877), and the
  steady-state `run_connected_loop`.
- `control.rs` — daemon->helper control-frame decode (`process_control_frames`:
  ACK-window #2959, Pause/Resume) and the DORMANT seq-fenced drain
  (`handle_drain_request`, #2876/#2882/#2875).
- `drain.rs` — channel-drain mechanics: `drain_channel_into_write_buf` (the
  `WRITE_BACKLOG_MAX_BYTES` cap + ordered FullResync merge #5267),
  `flush_pending_resync`, `DrainOutcome`, and the shutdown `drain_remaining`.
- `replay.rs` — replay-buffer admission/eviction/retirement
  (`push_replay_frame`, `evict_replay_frame`, `pop_replay_frame`,
  `release_replay_dataplane_event_queue_budget`; #2382/#2875).
- `budget.rs` — the I/O-thread queue-budget RETIREMENT side
  (`release_dataplane_event_queue_budget`), paired with `producer.rs`
  admission.
- `codec.rs` — frame layout: 16-byte header
  `[length:u32 LE][type:u8][reserved:3][seq:u64 LE]` followed by the
  payload. Message types: `MSG_SESSION_OPEN`, `MSG_SESSION_CLOSE`,
  `MSG_SESSION_UPDATE`, `MSG_ACK`, `MSG_PAUSE`, `MSG_RESUME`,
  `MSG_DRAIN_REQUEST`, `MSG_DRAIN_COMPLETE`, `MSG_FULL_RESYNC`,
  `MSG_KEEPALIVE` (1..10), plus RT_FLOW dataplane telemetry frames
  (`MSG_DRAIN_REQUEST=7` / `MSG_DRAIN_COMPLETE=8` are **reserved/dormant** —
  the Go daemon has no live caller; graceful demotion uses the session-sync
  peer barrier + continuous event stream, and loss-of-sync republish uses the
  unbounded `ExportOwnerRGSessions` snapshot via `MSG_FULL_RESYNC`. The drain
  fence below is retained, hardened, and tested for a possible future use —
  see `docs/session-sync-architecture.md`)
  `MSG_POLICY_DENY`, `MSG_SCREEN_DROP`, and `MSG_FILTER_LOG` (11..13),
  (#2460) `MSG_SESSION_CLOSE_RT_FLOW` (14), and (#2508)
  `MSG_SESSION_CREATE_RT_FLOW` (15).
  The telemetry frame payload is not a userspace-specific schema: it is
  the same `dataplane.Event` layout consumed by the Go ringbuf logger,
  including AF values 2/10 and big-endian L4 ports. The payload is 160
  bytes (`SECURITY_EVENT_PAYLOAD_SIZE`): #3056 grew it 136 -> 144 (the
  trailing [136:140] u32 carries the admitting policy ID on the
  SESSION_CLOSE frame, whose [44:48] policy_id slot is occupied by the
  #2853 created-subsec-nanos and so cannot hold the policy ID the way
  every other frame does; [140:144] is reserved padding), and #2749 grew
  it again 144 -> 152 with an ADDITIVE class-of-service / interface block
  at [144:152] on the SESSION_CLOSE RT_FLOW frame: [144] src ToS byte
  (DSCP<<2), [145] cumulative TCP control bits, [146:148] reserved
  (flowDirection, deferred), [148:152] egress ifindex (LITTLE-endian u32).
  #4915 grew it once more 152 -> 160 with an ADDITIVE [152:160] u64
  (LITTLE-endian) carrying the dataplane's STABLE session id on BOTH the
  SESSION_CREATE and SESSION_CLOSE frames (`encode_session_create_rt_flow`
  / `encode_session_close_rt_flow`, threaded from the session's
  `SessionEntry.session_id` via the Open/Close `SessionDelta`), so a SIEM
  can join a session's open and close records — the per-event ordinal the
  Go side stamped before could never match across the two events, nor
  disambiguate a reused 5-tuple. deny/screen/filter frames have no session
  and leave [152:160] zero.
  The growth is additive and rolling-upgrade-safe: the Go reader keeps its
  minimum-frame acceptance at the legacy 144 bytes and decodes the
  [144:152] block ONLY when the frame carries it (`len >= 152`) AND on a
  SESSION_CLOSE, and the [152:160] session id ONLY when `len >= 160` AND on
  a SESSION_CREATE/CLOSE, so a new daemon still accepts an old helper's
  144/152-byte frames and an old daemon ignores the trailing bytes (#1961).
  Every frame encoder emits 160 bytes; non-close frames leave [144:152]
  zero and non-session frames leave [152:160] zero. NOTE (#4915 scope): a
  peer-synced session gets a FRESH node-local id on import — cross-HA-node
  id identity (the same id on both cluster nodes) is a documented follow-up
  needing a session-sync wire change. `show security flow session` is now
  UNIFIED (#5213): `publish_conntrack` stamps the conntrack-map `session_id`
  from the same `SessionEntry.session_id`, so the live-session view shows the
  SAME id these frames carry (the iteration-index fallback survives only for a
  `val.SessionID == 0` row).
  Userspace telemetry may also populate the non-session metadata slots
  used by the Go adapter for action, rule ID, term ID, reason, owner RG,
  ingress ifindex, and application ID.
  (#2470) the `MSG_POLICY_DENY` / `MSG_SCREEN_DROP` (incl. the #2234
  scan-table-pressure ALARM) / `MSG_FILTER_LOG` emitters
  (`afxdp/event_emit.rs`) stamp `timestamp_ns` (offset 0, absolute Unix
  nanoseconds, little-endian u64 — same field/format as the close frame)
  with the dataplane DECISION instant, converting the poll loop's
  `CLOCK_MONOTONIC` `now_ns`/`now_secs` to wall-clock via
  `mono_ns_to_wall_clock_unix_ns` (one anchored `(monotonic, wall)` read
  per emit, reusing #2465's `read_mono_and_wall_clocks` +
  `monotonic_ns_to_unix_ns`). These fire on drops/denies/log-matched
  packets (not per normal packet), so a clock read per emit is cheap.
  Before #2470 all three wrote 0 → the Go decoder fell back to RECEIVE
  time, skewing the logged event time to consumption time under helper
  backlog / reconnect / CPU contention. A 0 (clock-read failure) still
  falls back to receive time on the Go side.
  (#2520) the cold-path RT_FLOW emitters also populate the `application id`
  slot (offset 132, little-endian u16) instead of hardcoding 0. The
  `emit_policy_deny_event` / `emit_filter_log_event` call sites and the
  `emit_session_close_rt_flow` (#2520) AND `emit_session_create_rt_flow`
  (#2615) callers resolve the AppID with the SAME direction-aware
  `app_catalog` the forwarding hot path runs when it stamps the conntrack
  entry on session create (see `afxdp::event_emit::resolve_flow_app_id`), so
  a policy-deny / filter-log / session-create / session-close record shows
  `application=<name>` for a resolvable 5-tuple instead of
  `application="UNKNOWN"`.
  (#3321) the lookup is DIRECTIONAL: `lookup_forward` matches the service on
  the DESTINATION port for a forward-keyed 5-tuple, and `lookup_directional`
  matches the source slot when the caller knows the entry is reverse-keyed
  (`metadata.is_reverse`). The cold-path resolvers (`resolve_flow_app_id` /
  `resolve_policy_deny_app_id`) use `lookup_forward`; the session-create /
  -close stamps pass the binding's own direction flag. A forward flow whose
  SOURCE port coincides with a service port (e.g. tcp `src=443`) is no longer
  mislabeled — the old probe matched the service on either slot.
  (#3058) a DNAT / static-NAT / inbound-NPTv6 policy-DENY record now reflects
  what the policy was actually evaluated against (the #2345 post-translation
  tuple), mirroring the permit / SESSION_CLOSE convention exactly: the
  RT_FLOW 5-tuple carries the ORIGINAL (received) addresses/ports and the
  `nat src/dst` slots (offsets 72/88 ip, 104/106 port) carry the TRANSLATED
  values — populated from the deny site's `decision.nat`
  (`rewrite_src/rewrite_dst/rewrite_*_port`) instead of the old hardcoded
  None/0. The deny AppID is resolved from the POST-translation destination
  port (`resolve_policy_deny_app_id` against `policy_dst_port`), so a public
  `:2222` DNAT'd to inside `:22` logs the inside `nat dst 10.0.0.10:22` +
  `application=junos-ssh` instead of an empty NAT dst + `UNKNOWN(2222)`. A
  deny with NO translation passes a default `NatDecision` (all-None) and a
  `policy_dst_port` equal to the original dst port, so its record stays
  byte-identical to the pre-#3058 wire — only NAT'd denies change.
  (#2615) the SESSION_CREATE and SESSION_CLOSE frames ALSO populate the
  ingress ifindex slot (offset 128, little-endian u32) from the admitting
  binding's `ident.ifindex`, so the Go decoder resolves
  `packet-incoming-interface=<name>` instead of `"N/A"`. A kernel ifindex
  is always positive, so the i32 -> u32 cast is loss-free, and this is a
  full-width u32 slot distinct from the i16 egress/TX ifindex width bug
  (#2467). 0 stays the UNKNOWN sentinel when the
  catalog has no match. The screen emitters (`emit_screen_drop_event` /
  `emit_screen_alarm_event`) deliberately keep 0: the screen parse-error
  fail-closed path (#2146) and the L4-less screen drops legitimately lack a
  resolvable 5-tuple, so fabricating an AppID there would be wrong.
  #5190: "lacks a resolvable 5-tuple" is not the same as "lacks everything".
  The FLOWLESS fail-closed screen drop (`screen_parse_error_info_flowless`,
  taken by a non-first fragment / ICMP control message whose L3 chain will
  not parse) now carries the authoritative `protocol` from the shim
  metadata and the real source/destination read out of the IP header, and
  only the L4 PORTS stay 0. It used to hard-code `protocol: 0` and an
  UNSPECIFIED address pair while both authoritative values sat unused at
  its single call site, so every such drop reached syslog/NetFlow as
  `protocol=0` from `0.0.0.0`. The helper takes `&UserspaceDpMeta` plus the
  caller-derived addresses precisely so that omission is unrepresentable;
  when the header is too short to read at all, the caller's
  `flowless_l3_addrs` still hands over the family-correct UNSPECIFIED pair,
  so a wholly unreadable frame degrades exactly as before.
  `MSG_SESSION_CLOSE_RT_FLOW` (14) carries that same 152-byte payload
  with the event-type byte set to RT_FLOW SESSION_CLOSE (2), plus the
  #3056 admitting policy ID in the trailing [136:140] slot and the #2749
  class-of-service / interface block at [144:152] (src ToS, cumulative TCP
  control bits, egress ifindex). It is
  emitted once per session close (via `emit_session_close_rt_flow`,
  paired 1:1 with — and ADDITIVE to — the unchanged minimal type-2
  `MSG_SESSION_CLOSE` HA session-sync delta), and is what drives the Go
  NetFlow v9 / IPFIX session-close exporters in userspace mode (they only
  fire on a `Type == "SESSION_CLOSE"` record; before #2460 none was
  produced). It carries the real 5-tuple, NAT tuple, zones, and protocol
  (and, #2520, the resolved application id at offset 132).
  (#2465) it ALSO carries the real session timestamps: the
  session-creation instant in the `created` field (offset 108, absolute
  Unix **seconds**, little-endian u32) and the close instant in
  `timestamp_ns` (offset 0, absolute Unix **nanoseconds**, little-endian
  u64). The session table tracks these as `CLOCK_MONOTONIC` instants
  (`SessionEntry.created_ns`, write-once at install, +
  `last_seen_ns`); the close `SessionDelta` carries them, and
  `emit_session_close_rt_flow` converts them to wall-clock at emit time
  (one anchored `(monotonic, wall)` reading — see `monotonic_ns_to_unix_*`
  in `mod.rs`). The Go exporters use `created` as the flow StartTime
  directly, falling back to the packet-count
  `estimateSessionDuration(SessionPkts)` heuristic only when it is 0 (an
  explicit-delete / HA-purge close that carried no creation instant).
  (#2853) the `created` second is too coarse on its own — every flow
  opened in the same second exported the same StartTime, flattening IPFIX
  `flowStartMilliseconds` for short flows. The close frame now ALSO carries
  the creation instant's sub-second **nanosecond** remainder
  (0..=999,999,999) in the close-unused `policy_id` slot (offset 44,
  little-endian u32), produced by `monotonic_ns_to_unix_secs_subnanos`. The
  Go decoder reads it as `EventRecord.CreatedNanos` (and zeroes `PolicyID`,
  which a close never carried) so `flowStartTime` builds a
  millisecond-accurate `time.Unix(Created, CreatedNanos)`. The
  byte/packet **volume** counters remain 0 pending the per-session
  accounting follow-up #2501 — only the timing is real. (#2512) the close
  frame now rides the SAME per-kind rate limiter + queue budget +
  sent/dropped counters as the deny/screen/filter frames, under
  `DataplaneEventKind::SessionClose`, via
  `EventStreamWorkerHandle::try_emit_dataplane_frame` — NOT a bare
  unaccounted `try_send`. It stays telemetry-lossy by design: a dropped
  close loses exactly one flow-export/syslog record. That is safe because
  the type-2 `MSG_SESSION_CLOSE` HA session-sync delta is a SEPARATE frame
  (`push_delta`) that is never rate-limited, so consumer session state
  self-heals through the daemon's 1s session sweep; the lossy budget bounds
  a GC-time close storm instead of letting it consume channel / replay
  capacity outside the producer's backpressure model. A shed close is
  counted under the SessionClose `sent`/`dropped` counters surfaced in
  `ProcessStatus.event_stream_session_close_{sent,dropped}` (and the
  `xpf_userspace_event_stream_producer_frames_total{outcome="session_close_*"}`
  Prometheus series).
  (#2508) per-policy RT_FLOW SYSLOG logging: the admitting policy's
  `then log session-init` / `session-close` selection is stamped onto the
  session metadata at install. A close ALWAYS emits the type-14 frame
  (flowexport needs every close), but its final payload byte (offset 135)
  carries a per-policy SYSLOG gate — the Go `logEvent` path emits the
  RT_FLOW_SESSION_CLOSE SYSLOG record only when the bit is set, while the
  registered callbacks (NetFlow/IPFIX, #2460) always run. There is NO
  flowexport consumer of session opens, so `MSG_SESSION_CREATE_RT_FLOW`
  (15) is producer-gated: it is emitted (via `emit_session_create_rt_flow`)
  ONLY when the admitting policy requested `then log session-init`, carries
  the same 152-byte payload with the event-type byte set to SESSION_OPEN
  (1, rendered as RT_FLOW_SESSION_CREATE on the Go side; the create frame
  leaves the #2749 [144:152] class-of-service block zero). The SESSION_CREATE
  frame carries the #3056 admitting policy ID in the usual [44:48] slot (it
  has no created-subsec-nanos), and always sets
  the gate byte. (#2615) the create frame now also threads the resolved
  application id (offset 132) and the admitting binding's ingress ifindex
  (offset 128), mirroring the close-side #2520/#2615 fix — so a logged
  session-create no longer logs `application="UNKNOWN"` /
  `packet-incoming-interface="N/A"` for a resolvable session. The volume
  counters stay 0 (a create has no volume yet). (#2512) like the close
  frame, the create frame rides the
  per-kind budget path under `DataplaneEventKind::SessionCreate` (counters
  `event_stream_session_create_{sent,dropped}`), not a bare `try_send`.
  `MSG_FILTER_LOG` intentionally reuses the RT_FLOW `reason` byte as
  a filter-log source discriminator (`pbr`, `input`, `output`,
  `cached-output`, or `lo0`). Close events still interpret that byte as
  a close reason. The helper and daemon must therefore be upgraded
  lockstep for this event-stream semantic; it is not governed by the
  config snapshot protocol version.
- `producer.rs` — non-blocking helper-side producer API for RT_FLOW
  dataplane telemetry. It rate-limits each `(event type, ingress
  zone)` bucket, encodes fixed-size frames only after the limiter
  admits the event, and accounts sent/rate-limited/queue-full/
  disconnected outcomes per event type. Dataplane telemetry can occupy
  only a bounded share of the shared event-stream channel, and each
  event type has its own in-flight cap so one deny/drop/log storm cannot
  monopolize queue capacity. (#2512) the kind set is `PolicyDeny`,
  `ScreenDrop`, `FilterLog`, `SessionClose`, `SessionCreate` (5). The two
  RT_FLOW session frames (types 14/15) carry their own payload layout, so
  they enter the budget via `try_emit_dataplane_frame(kind, zone, now,
  encode)` (a generalization of `try_emit_dataplane_event_at` that accepts
  a caller-supplied frame encoder); the I/O-thread budget release keys each
  frame by its `msg_type` byte through `DataplaneEventKind::from_msg_type`,
  so all five kinds balance their per-kind reservation.
- `codec_tests.rs`, `producer_tests.rs`, `tests.rs` — co-located.

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
- **MSG_ACK watermark is validated before it is trusted (#2959).** The
  `MSG_ACK` arm in `process_control_frames` rejects any ACK whose sequence
  falls outside the valid `[acked_seq, next_seq]` window BEFORE mutating
  `acked_seq` or trimming the replay buffer. The contract is:
  `seq == acked_seq` is a benign duplicate (no-op); `seq == next_seq` is an
  ACK of the latest allocated frame (valid); `acked_seq < seq < next_seq`
  is a normal forward ACK (trims). A **backward** ACK (`seq < acked_seq`) or
  a **future** ACK of a sequence the helper never allocated
  (`seq > next_seq`) comes from a buggy, mixed-version, or corrupted daemon
  listener — trusting it would poison `acked_seq` and trim or permanently
  suppress replay of frames the daemon never actually acknowledged. The
  helper **fails closed**: it ignores the impossible ACK, leaves the
  watermark and replay buffer intact, and increments `frames_invalid_acks`
  (surfaced as `event_stream_invalid_acks` in the daemon status JSON). It
  does NOT disconnect: ignoring keeps the live connection and avoids a
  reconnect-thrash loop against a peer that keeps emitting bad ACKs, while
  valid ACKs interleaved with the bad ones still advance the watermark
  normally. (A disconnect+FullResync response is a possible future
  hardening if a corrupt peer ever needs to be actively reset, but it is
  more disruptive than the value gained here.)
- The default `push_delta()` path is **non-blocking** (`try_send`) and
  **silently drops** when the channel is full. The internal counter
  is `EventStreamShared.frames_dropped` (`mod.rs`); the surface
  exported through the daemon status JSON is `event_stream_dropped`
  (see `protocol.rs`). Use `push_delta_lossless()` only when
  correctness requires every frame and the producer can tolerate
  back-pressure.
- **Seq allocation is atomic with the channel enqueue (#3878).** Every
  producer path (`push_delta`, `push_delta_lossless`, and the RT_FLOW
  `try_emit_dataplane_*` telemetry path) allocates its `next_seq` value and
  calls `tx.try_send` while holding `EventStreamShared.producer_seq_lock`, so
  the seq embedded in a frame is monotonic in wire (channel-FIFO) order. Before
  #3878 the seq was allocated in `encode_delta_frame` and enqueued in a
  separate step, so two workers could allocate N and N+1 but enqueue them
  inverted — the Go reader (zero reorder tolerance) treats a seq inversion as a
  session-sync gap and forces a spurious full owner-RG resync + disconnect,
  which is self-amplifying during recovery (F-152). On a **full-channel drop**
  the allocated seq is **rolled back** (a compare-exchange on `next_seq`, safe
  under the lock) rather than burned, so a saturation drop never leaves a hole
  that trips the reader's gap check on the NEXT frame (F-153). The lock covers
  only the atomic allocate + non-blocking `try_send`; the lossless retry loop
  drops it before every sleep so a backpressured export never stalls the other
  producers, and re-allocates (rolling back the failed attempt) on each retry so
  the eventual wire seq matches the successful enqueue position.
- **`producer_seq_lock` is the #4800 model's FOURTH contention site (#9169).**
  Because seq allocation and the channel enqueue must be atomic together
  (F-152 above), the frame ENCODE runs inside that critical section, for every
  session delta — Open as well as Close — on a mutex that lives on `shared`
  and is therefore process-global across every producer thread. That makes it
  a cross-worker serialization point on the new-flow install path, and
  `docs/userspace-newflow-ceiling.md` named three sites and not this one, so a
  run bound here WOULD report a new-flows/sec plateau with every named site
  cold, which reads as "not lock-bound". That is a counterfactual and not a
  result — no such run has been performed (the harness doc's own status line
  says so); the static bound and the missing counter are what is established.
  `EventStreamShared::lock_producer_seq`
  counts acquisitions and the blocked subset (`try_lock()` first, so the
  uncontended lock costs the single CAS it always did) and the pair is exported
  as `xpf_userspace_event_stream_producer_seq_lock_{acquisitions,contended}_total`.
  Only the two PRODUCER sites are counted; the I/O thread's replay-gap
  allocation below takes the same mutex and is deliberately excluded from the
  denominator so the ratio is not diluted with the observer. #9169 is an
  INSTRUMENT, not a remedy — the bound is static and proven, no benchmark is
  claimed, and "encode outside the lock" is not directly available because the
  encode closure consumes the sequence number.
- **The replay-gap FullResync is ordered under the same lock (#5267).** The I/O
  thread's replay-gap barrier (`replay_buffered`) used to allocate its seq with
  a bare `fetch_add` and write it DIRECTLY to the socket, bypassing the channel.
  On a reconnect the channel still holds the deltas committed during the
  disconnect (LOWER seqs) which the connected loop drains AFTER the direct write,
  so a HIGHER-seq FullResync landed on the wire before those lower-seq deltas —
  wire order != seq order. The Go reader (zero reorder tolerance) then diagnosed
  a session-sync gap on the first post-barrier delta, dropped the connection, and
  churned resyncs on the very HA-recovery barrier (a self-amplifying failover
  data-loss risk). The fix allocates the FullResync's seq **under
  `producer_seq_lock`** (just the `fetch_add`, no socket write, so producers are
  never stalled and there is no deadlock) and **parks** the frame in a
  per-connection `pending_resync` slot instead of writing it. The connected
  loop's channel drain (`drain_channel_into_write_buf`) then **merges** the
  barrier into the write stream in seq order: it flushes the barrier just before
  the first channel frame whose seq exceeds it (a delta committed AFTER the
  barrier), or when the channel drains empty (the barrier is the current max) —
  so every lower-seq delta is written first and the wire stays monotonic. Because
  the seq is allocated under the lock, every delta already committed to the
  channel has a strictly lower seq (channel commit is atomic under the same lock)
  and every delta committed afterward a strictly higher one, so the merge is
  total. `connected` stays published BEFORE `replay_buffered`: it gates only the
  lossless producer path, and deferring it would make `push_delta_lossless`
  fail-closed ("not connected") during the non-gap replay window —
  `flush_session_deltas` latches that as loss-of-sync and forces a spurious full
  resync on every clean reconnect. Ordering is guaranteed by the lock, not by the
  `connected` timing, so the two are kept orthogonal. If the connection is
  already paused, the barrier follows the existing paused-frame behavior: it is
  retained in replay rather than written. The latent `MSG_RESUME` replay-suffix
  scheduling gap is tracked separately in #5328; #5267 does not redefine the
  dormant Pause/Resume protocol.
- **Only the DORMANT drain-poison resync still allocates outside the lock.**
  `handle_drain_request`'s poison-FullResync (the `MSG_DRAIN_REQUEST` path has no
  live caller — graceful demotion uses the session-sync barrier, not the fenced
  drain) still allocates with a bare `fetch_add` and writes directly; it precedes
  a reader reset and the rollback CAS tolerates the rare interleave. If that path
  is ever made live it must adopt the same #5267 ordered-barrier treatment.
- **HA session open/close deltas are correctness-critical and use the
  LOSSLESS path (#2874).** `flush_session_deltas` (`afxdp/session_delta.rs`)
  routes the type-2 session-sync open/close delta through
  `push_delta_lossless`, NOT `push_delta`. The lossy `push_delta` DROPS the
  frame on a full channel (since #3878 it rolls the seq back rather than burning
  it, so the drop no longer leaves a seq hole — but the delta CONTENT is still
  lost), so the standby permanently misses that session open/close until an
  unrelated full-sync runs. The lossless path instead waits briefly for
  capacity and surfaces a give-up as an `Err`, which the worker turns into a
  resync (below) rather than a silent miss. When the
  lossless push cannot enqueue (peer disconnected / queue timeout — a
  genuinely wedged consumer), `flush_session_deltas` returns `true` and the
  worker loop latches loss-of-sync via `SessionTable::set_delta_loss`, which
  drives the existing #2442 `take_delta_loss` resync (a full owner-RG
  snapshot re-export). Within a single `flush_session_deltas` call it stops
  attempting further lossless pushes for the rest of that batch, so one call
  incurs at most one lossless wait — the snapshot supersedes the remaining
  incremental deltas.
  - **#5290: the RPC-fallback drain feeds the SAME resync.** When the event
    stream is down and the Go control plane polls `drain_session_deltas`, that
    fallback path uses a fair rotating-cursor drain
    (`session_delta::drain_session_deltas_fair`) so a low-slot worker cannot
    consume the whole caller budget and starve higher slots. On budget overflow
    (undrained deltas remain) — or a per-binding `pending_session_deltas` buffer
    overflow that drops a delta — it arms `BindingLiveState::set_delta_loss`,
    which the worker loop folds into `SessionTable::set_delta_loss` so the same
    `take_delta_loss` owner-RG resync recovers the lost/undrained deltas.
    Debounced by a single `AtomicBool` per binding: one episode → one resync.
  - **#5468: the worker-loop lossless wait is BOUNDED — per call AND in
    aggregate.** `flush_session_deltas` runs on the packet worker loop, so it
    uses `push_delta_lossless_within` with a short `WORKER_LOSSLESS_QUEUE_BUDGET`
    (one fifth of `HEARTBEAT_STALE_AFTER`, ~1 s) instead of the 5 s
    `LOSSLESS_QUEUE_TIMEOUT`. A connected-but-UNREAD peer (slow/stalled reader,
    queue full) that blocked the worker for the full 5 s would stop the loop
    stamping its heartbeat, the peer would then see this node as stale
    (`HEARTBEAT_STALE_AFTER` = 5 s) and trigger a FALSE failover. On the bounded
    timeout the delta is not dropped — the same loss-of-sync latch fires and
    forces a full resync (deliver-or-resync).
    - The per-call bound is NOT enough on its own: the drain region calls
      `flush_session_deltas` once for the steady-state batch, but the #2442
      resync and the #2653 command export call it ONCE PER 256-delta batch
      across the whole owned-session set (`chunked_drain_as_you_export!` →
      `drain_and_flush_all!`). For K owned sessions that is ~K/256 calls, so at
      one budget each an unread peer would still stall the worker ~(K/256)
      budgets — past K≈1280 that re-crosses `HEARTBEAT_STALE_AFTER` and
      re-triggers the same false failover via the resync path. The worker loop
      therefore threads a per-drain-cycle `worker_lossless_wedged` latch through
      every `flush_session_deltas` call: the first wedged batch waits one budget
      and sets it; every later call this cycle inherits it and SKIPS the
      lossless wait entirely (still draining each delta to the live RPC buffer,
      the shared conntrack/session tables, and peer-worker delete replication).
      So the AGGREGATE worker-loop lossless wait per drain cycle is ~1 budget
      regardless of K; every wedged batch still returns out-of-sync, so the
      latch stays set and the resync RETRIES next cycle (never a silent drop).
    - Only the off-worker-loop paths (bulk export on connect
      `AllSessionsExport::push`, tunnel-remap purge `push_purge_close_deltas`)
      keep the longer 5 s `LOSSLESS_QUEUE_TIMEOUT` via `push_delta_lossless`,
      since they run with the worker heartbeat unaffected.
  The RT_FLOW
  SESSION_CLOSE/SESSION_CREATE telemetry frames (types 14/15) stay
  best-effort (`try_send` via the per-kind budget) — a dropped flow-export
  record is not a correctness loss and MUST NOT force a resync.
- **Go consumer: a sequence gap on a session-sync frame is a HARD sync
  break (#2874).** `pkg/dataplane/userspace/eventstream.go` treats a gap on a
  correctness-critical session-sync frame (`EventTypeSessionOpen` / `Update`
  / `Close`) as a desync: it triggers `onFullResync`
  (`handleEventStreamFullResync` → bulk owner-RG export, the only path that
  recovers a producer-dropped delta) and returns from the read loop WITHOUT
  advancing `lastAppliedSeq` past the hole, so the cumulative ACK never moves
  past the missing sequence and the reconnect replays from the last
  contiguous ack. A gap on a TELEMETRY frame (`EventFrameType*`, types 11-15)
  is merely counted in `SeqGaps` and the frame is still dispatched — telemetry
  is lossy by design and a gap there must NOT force a resync (no
  thundering-resync regression). Session-sync resyncs are counted separately
  in `EventStreamStatus.session_sync_resyncs`.
- **Write-backlog cap (#2381).** The bounded mpsc channel
  (`CHANNEL_CAPACITY`) is the ONLY intended backpressure surface. The
  I/O thread's pending socket-write backlog (`write_buf`) is capped at
  `WRITE_BACKLOG_MAX_BYTES` (16 MiB ≈ 4× a fully-drained 8192×512 B
  channel) in `drain_channel_into_write_buf()`. The cap is checked at the
  top of the drain loop, so the effective bound is `cap + one max
  EventFrame` (≤ 512 B) — the in-flight frame already pulled may carry
  the backlog just past 16 MiB before the drain halts. **Every producer
  into `write_buf` is subject to the cap, the idle keepalive included
  (#5189 A1-b10-F4)** — see the keepalive bullet below; before #5189 the
  keepalive was the one unchecked producer and the `cap + one frame`
  bound above was false. A wedged daemon
  (socket open but not
  reading → `write_buf` writes return `WouldBlock`) would otherwise let
  the I/O thread migrate the whole channel into the heap-backed
  `write_buf` every cycle; the channel refills from worker `try_send`,
  the thread drains it again, and `write_buf` grows without bound →
  helper OOM / allocator pressure on the **forwarding plane**. Once the
  backlog reaches the cap the drain STOPS pulling from the channel, the
  channel becomes the real backpressure surface (newest producer events
  shed via `try_send`, counted in `frames_dropped` / per-kind
  `queue_full`; oldest queued + replay frames are preserved so RT_FLOW
  stays current), and each capped pass bumps `frames_write_stalled`
  (wire key `event_stream_write_stalls`, Prometheus
  `xpf_userspace_event_stream_producer_frames_total{result="write_stalled"}`).
  The cap does not apply while paused — paused frames go only to the
  already-bounded replay buffer, never to `write_buf`. **Invariant: the
  data plane never stalls because a telemetry consumer is slow; a stuck
  consumer degrades telemetry (counted drops), nothing else.**
- **Cursor-backed write backlog — amortized-linear drain (#4974).** The
  pending backlog is a `WriteBacklog` (cursor over a `Vec<u8>`), not a
  bare `Vec`. Each successful short socket write advances a `start`
  cursor in O(1) (`write_buf.advance(n)`) instead of memmoving the whole
  remaining suffix to offset 0 (`write_buf.drain(..n)`). Under a slow
  reader that accepts only a few bytes per write, the old `drain(..n)`
  was O(backlog) per write → O(backlog²) total copy work on the single
  event I/O thread during exactly the slow-consumer condition. The
  consumed prefix is reclaimed by GEOMETRIC compaction — one copy of the
  (smaller) pending suffix once `start ≥ len/2` — so total compaction
  work is O(total bytes) and per-write cost is amortized O(1), while the
  backing `Vec` stays within ~2× the pending length (bounded, distinct
  from the #2381 unbounded-growth failure). **The `WRITE_BACKLOG_MAX_BYTES`
  cap and every pause/backpressure decision now measure the UNWRITTEN
  length (`write_buf.pending_len()` = `Vec.len() − start`), not the raw
  `Vec` length** — measuring the raw length would trip the cap early and
  drift the pause/resume accounting because it also counts the
  reclaimable written prefix. Byte order and exactly-once delivery are
  unchanged: appends only ever go to the tail and compaction never
  reorders the pending suffix. Regression gate:
  `partial_write_backlog_is_amortized_linear_4974` asserts total
  compaction copy work stays within a linear (3×) bound; reverting
  `advance` to a per-write `drain(..n)` memmove blows it.
- **Lossless-demotion fence for session deltas (#2875). RESERVED/DORMANT —
  not wired to the live demotion path; see the codec note above.** A paused
  drain is the stable window the future owner reads before demotion completes
  (`docs/session-sync-design.md`). The replay buffer is bounded, so a long
  pause that overruns `REPLAY_BUFFER_CAPACITY` evicts the oldest frames —
  and an evicted frame may be an HA session-sync delta
  (`MSG_SESSION_OPEN`/`UPDATE`/`CLOSE`). Bumping `frames_replay_evicted` and
  reporting `DrainComplete` anyway would finish demotion with **lost session
  mutations on the new owner**. The fix is poison-on-loss, NOT an unbounded
  buffer (that would be a memory DoS on the forwarding plane):
  `evict_replay_frame()` sets `session_evicted_while_paused` when it evicts a
  frame for which `EventFrame::is_session_sync()` is true AND the helper is
  paused. `handle_drain_request()` then WITHHOLDS `DrainComplete` and emits a
  `FullResync` instead, so the daemon re-exports full session state (the same
  recovery path as #2874 / the replay-gap resync) and refuses to proceed with
  demotion. **Telemetry eviction does NOT poison** (RT_FLOW deny/screen/filter
  + session create/close frames return `is_session_sync() == false`) — that
  would cause spurious resyncs. Lifecycle: set on a session-frame eviction
  during pause; cleared at pause-start (`MSG_PAUSE`, so each window starts
  clean) and after the poisoned drain emits its `FullResync`.
- **Idle keepalive rides write_buf, not write_all (#2883).** The connected
  loop enqueues its idle keepalive frame into `write_buf` (the same path data
  frames use), so a `WouldBlock` on a full kernel send buffer is ordinary
  backpressure (retained for the next flush), not a fatal reconnect. The old
  keepalive called `write_all` directly and `return true`d on any error,
  including WouldBlock under a slow reader — causing reconnect churn -> replay
  storms (which then hit the blocking replay path, #2877). A genuinely dead
  consumer is still caught by the normal socket-error / EOF path. The keepalive
  interval is `KEEPALIVE_IDLE_INTERVAL` (10s), passed into `run_connected_loop`
  (injectable so tests can fire it immediately).
- **The keepalive obeys the write-backlog cap (#5189 A1-b10-F4).** Routing the
  keepalive into `write_buf` (#2883) made it a PRODUCER into the backlog, and it
  was the only producer that did not check `WRITE_BACKLOG_MAX_BYTES` — that cap
  was enforced solely in `drain_channel_into_write_buf`. The two conditions
  compose badly: a live-but-non-reading consumer stalls the drain AT the cap,
  which keeps `drained_any == false` forever, which is exactly what arms the
  idle keepalive; and the socket write returns `WouldBlock` forever, so
  `advance` is never called and nothing reclaims the appended bytes. The backlog
  therefore grew by one `FRAME_HEADER_SIZE` frame per keepalive interval,
  monotonically and without bound. The growth RATE is slow (8 B / 10 s ≈ 25 MB
  per year of continuous stall), so this was never a near-term OOM — but it is
  unbounded, and it falsified the `cap + one max EventFrame` ceiling the section
  above states. `append_idle_keepalive_if_due` now declines the append while
  `write_buf.pending_len() >= WRITE_BACKLOG_MAX_BYTES` (the same UNWRITTEN-bytes
  measure #4974 established for every other backpressure decision). Nothing is
  lost: a backlog at the cap already holds ≥ 16 MiB of unwritten frames, so
  pending DATA supplies all the liveness the keepalive exists to signal. A
  suppressed attempt deliberately does NOT re-arm `last_write`, so the keepalive
  stays due and fires on the first cycle after the backlog drains below the cap
  rather than waiting out another full interval. Regression gates:
  `idle_keepalive_stops_at_the_write_backlog_cap_5189` (pins the boundary — the
  call with one frame of headroom must still append, only the crossing one is
  suppressed) and `suppressed_idle_keepalive_does_not_rearm_the_interval_5189`.
- **Replay/drain writes are nonblocking + stop-aware (#2877).** The reconnect
  replay (`replay_buffered`) and demotion drain (`handle_drain_request`) paths
  push frames through `write_all_backpressured`, which keeps the socket
  NONBLOCKING (the same mode steady-state data-frame writes use) and, on
  `WouldBlock`, retries with a `REPLAY_DRAIN_WRITE_POLL` sleep while polling the
  shared stop flag and bailing at a `REPLAY_DRAIN_WRITE_DEADLINE` (5s) shared
  across the pass. They MUST NOT flip the socket to blocking and call
  `write_all`: a daemon that connects but stops reading would wedge the I/O
  thread in the unbounded blocking write, and since `EventStreamSender::stop`
  joins that thread, helper stop / RG demotion would hang (the slow-consumer
  invariant: a stalled consumer degrades telemetry, never wedges the helper).
  The stop flag lives in `EventStreamShared.stop` so every I/O-thread function
  (connect, replay, the connected loop, drain) observes it. A stuck reader
  during replay returns Err -> reconnect; during drain it withholds
  DrainComplete so the daemon times out and refuses demotion (#2876) rather
  than reporting a false drain.
- **Control-frame payload cap (#2879).** `process_control_frames()` reads a
  32-bit `payload_len` from each daemon→helper frame and waits for the full
  `FRAME_HEADER_SIZE + payload_len` bytes before parsing. Every current
  daemon→helper opcode (Ack/Pause/Resume/DrainRequest) is HEADER-ONLY (zero
  payload), so `MAX_CONTROL_PAYLOAD_LEN` is `0`. Without a cap a buggy or
  compromised local daemon sends a header with `payload_len = 1<<30` and
  trickles bytes; the helper would keep extending `ctrl_read_buf` (consuming
  nothing, since the frame never completes) and grow the heap without bound on
  the **forwarding plane**. The parser validates `payload_len` on the header
  alone (the loop guard guarantees a full 16-byte header) BEFORE waiting for
  the rest of the frame: any `payload_len > MAX_CONTROL_PAYLOAD_LEN`
  disconnects (returns `Some(true)` → reconnect, which clears `ctrl_read_buf`)
  instead of buffering. A legitimately partial header-only frame still works —
  `payload_len == 0` passes, and a split HEADER never reaches the check. The
  constant is named so a future payload-carrying opcode raises it deliberately
  rather than the parser honoring an arbitrary 32-bit length.
- RT_FLOW dataplane telemetry producers must use
  `try_emit_dataplane_event_at()` (or, for a producer that builds its own
  frame layout such as the session-close/create frames,
  `try_emit_dataplane_frame()`), not hand-rolled `try_send()`
  wrappers (#2512 removed the last two bare-`try_send` producers). The API
  applies the per-kind/per-ingress-zone limiter
  before sequence allocation, increments the generic producer drop
  counter for rate-limited events, and records per-event loss reason
  counters for later status surfacing. It also enforces the telemetry
  queue budget before sequence allocation or shared-channel enqueue;
  event budget drops are reported as queue-full drops. Accepted
  telemetry holds that budget while retained for replay, releasing it
  only when an ACK trims the frame or the helper definitively drops it
  during replay eviction, enqueue failure, or shutdown. Budget release
  saturates at zero; an underflow (accounting invariant broken) bumps a
  local-only diagnostic counter and logs one stderr line on first hit
  (#1826 — release builds compile out the debug_assert, the counter is
  intentionally not wire-plumbed). The invariant is symmetric: every
  telemetry frame that reaches the replay buffer acquired one budget slot
  at emit, so its release on eviction/ACK-trim/shutdown is always balanced.
  A unit test that injects telemetry frames directly (`push_replay_frame`,
  bypassing `emit`) MUST seed that slot with
  `DataplaneEventQueueBudget::acquire_for_test()` for each frame, or the
  eviction's release trips the debug_assert on a zero counter (#4607 — the
  #2875 telemetry-eviction test bypassed the seed; session-sync frames need
  no seed because they carry no `dataplane_event_kind()`).
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
- Producer outcome counters are exported for all five telemetry kinds
  (`policy_deny`, `screen_drop`, `filter_log`, `session_close`,
  `session_create`) as `event_stream_<kind>_<outcome>` status fields and
  `xpf_userspace_event_stream_producer_frames_total{outcome="<kind>_<outcome>"}`
  Prometheus series. Outcomes are `sent`, `dropped`, `rate_limited`,
  `queue_full`, and `disconnected`; `dropped` is the sum of the three
  reason-specific drop counters.
