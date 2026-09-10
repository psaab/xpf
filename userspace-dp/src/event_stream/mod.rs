//! Event stream producer for session sync.
//!
//! Replaces the polled `drain_session_deltas` RPC with a push-based binary
//! event stream over a dedicated Unix socket. The Go daemon creates a listener
//! at the event socket path; the helper connects and pushes binary-framed
//! session events (open/close/update) with monotonic sequence numbers.
//!
//! Wire format (per docs/session-sync-design.md):
//!   Frame header: [length:u32 LE][type:u8][reserved:3][seq:u64 LE]
//!   Payload: type-specific binary (see codec module)

mod backlog;
mod budget;
pub(crate) mod codec;
mod clock;
mod connection;
mod control;
mod drain;
mod producer;
mod replay;
mod rt_flow;

// #6235 split: re-export the moved intra-crate helpers back into the
// `event_stream` namespace so the sibling submodules (each `use super::*`) and
// the `#[cfg(test)] mod tests` tree resolve them unchanged. Several are consumed
// only by siblings/tests, not by mod.rs directly.
#[allow(unused_imports)]
use backlog::{WRITE_BACKLOG_MAX_BYTES, WriteBacklog};
#[allow(unused_imports)]
use budget::release_dataplane_event_queue_budget;
#[allow(unused_imports)]
use connection::{io_thread_main, replay_buffered, run_connected_loop, write_all_backpressured};
#[allow(unused_imports)]
use control::{handle_drain_request, process_control_frames};
#[allow(unused_imports)]
use drain::{DrainOutcome, drain_channel_into_write_buf, drain_remaining, flush_pending_resync};
#[allow(unused_imports)]
use replay::{pop_replay_frame, push_replay_frame, release_replay_dataplane_event_queue_budget};

#[allow(unused_imports)] // monotonic_ns_to_unix_secs is consumed only by the rt_flow tests
pub(crate) use clock::{
    mono_ns_to_wall_clock_unix_ns, monotonic_ns_to_unix_ns, monotonic_ns_to_unix_secs,
    monotonic_ns_to_unix_secs_subnanos,
};
// read_mono_and_wall_clocks / DataplaneEventKind resolve for rt_flow.rs (which
// `use super::*`) after the #6235 split; mod.rs no longer references them directly.
// NS_PER_SEC is likewise consumed only by the rt_flow test module via super::*.
#[allow(unused_imports)]
use clock::read_mono_and_wall_clocks;
#[allow(unused_imports)]
use clock::NS_PER_SEC;
pub(crate) use codec::{EventFrame, close_flags};
#[allow(unused_imports)]
use codec::DataplaneEventKind;
#[allow(unused_imports)] // public API for later policy/screen/filter producer wiring
pub(crate) use producer::{
    DataplaneEventDropReason, DataplaneEventEmitOutcome, DataplaneEventRateLimitConfig,
    DataplaneEventStats,
};

use crate::session::{SessionDelta, SessionDeltaKind};
// FRAME_HEADER_SIZE / MSG_* resolve for the connection + control submodules
// (each `use super::*`) and the test tree; several are not used by mod.rs itself.
#[allow(unused_imports)]
use codec::{FRAME_HEADER_SIZE, MSG_ACK, MSG_DRAIN_REQUEST, MSG_KEEPALIVE, MSG_PAUSE, MSG_RESUME};
use producer::{DataplaneEventCounters, DataplaneEventQueueBudget, DataplaneEventRateLimiter};
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
// std types consumed by the connection / control / drain / replay submodules
// (each `use super::*`) after the #6235 split; mod.rs no longer references them
// directly.
#[allow(unused_imports)]
use std::collections::VecDeque;
#[allow(unused_imports)]
use std::io;
#[allow(unused_imports)]
use std::os::unix::net::UnixStream;
#[allow(unused_imports)]
use std::sync::mpsc::TryRecvError;

/// Idle interval after which the connected loop enqueues a keepalive frame to
/// keep the Go listener from treating the stream as dead. The keepalive is
/// routed through the normal `write_buf` backpressure path (#2883), so this is
/// the cadence of enqueue, not of a guaranteed flush.
const KEEPALIVE_IDLE_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum event frames buffered in the mpsc channel (shared across workers).
const CHANNEL_CAPACITY: usize = 8192;

/// Maximum frames retained for replay after disconnect.
const REPLAY_BUFFER_CAPACITY: usize = 4096;

/// Hard ceiling on any single daemon->helper control-frame payload (#2879).
///
/// `process_control_frames` reads a 32-bit `payload_len` from the wire and waits
/// for `FRAME_HEADER_SIZE + payload_len` bytes before parsing. Every current
/// daemon->helper opcode (Ack / Pause / Resume / DrainRequest) is HEADER-ONLY --
/// zero payload -- so this is 0 today. Without a cap a buggy or compromised local
/// daemon sends a header with `payload_len = 1<<30` and trickles bytes; the
/// helper would keep extending `ctrl_read_buf` (consuming nothing, since the
/// frame never completes) and grow the heap without bound on the forwarding
/// plane. Any `payload_len` above this ceiling can never form a valid control
/// frame, so the helper disconnects (reconnect resets `ctrl_read_buf`) instead
/// of buffering. It is a NAMED constant so a future payload-carrying opcode
/// raises it deliberately, rather than the parser silently honoring an arbitrary
/// 32-bit length.
const MAX_CONTROL_PAYLOAD_LEN: usize = 0;

/// Upper bound for explicit lossless queueing operations such as full
/// session export on connect. Normal packet-path delta export remains
/// non-blocking via `try_send`.
const LOSSLESS_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
const LOSSLESS_QUEUE_RETRY_DELAY: Duration = Duration::from_micros(50);

/// Bounded time the stop-aware replay/drain writer (`write_all_backpressured`)
/// will spend backpressured on a slow/stuck reader before giving up — i.e.
/// reconnecting (replay) or withholding DrainComplete (drain). This caps how
/// long a wedged daemon can hold the I/O thread in the replay/drain write even
/// if the stop flag is never raised (#2877). The replay/drain paths used to
/// flip the socket to BLOCKING and `write_all` with no deadline, so a daemon
/// that stopped reading wedged the I/O thread indefinitely — and because
/// `EventStreamSender::stop` joins that thread, stop/demotion hung.
const REPLAY_DRAIN_WRITE_DEADLINE: Duration = Duration::from_secs(5);
/// Sleep between `WouldBlock` retries in `write_all_backpressured`. Also the
/// worst-case latency for that writer to observe a raised stop flag, so
/// stop/demotion never waits more than one poll interval on a stuck reader.
const REPLAY_DRAIN_WRITE_POLL: Duration = Duration::from_millis(1);

// ---------------------------------------------------------------------------
// Shared state between I/O thread and workers
// ---------------------------------------------------------------------------

/// Statistics exposed to coordinator / status reporting.
pub(crate) struct EventStreamStats {
    pub(crate) connected: bool,
    pub(crate) seq: u64,
    pub(crate) acked_seq: u64,
    pub(crate) sent: u64,
    pub(crate) dropped: u64,
    /// Count of I/O cycles in which the pending socket-write backlog reached
    /// `WRITE_BACKLOG_MAX_BYTES` and the I/O thread therefore stopped pulling
    /// frames from the channel (a wedged/stalled daemon reader, #2381). A
    /// non-zero, growing value means telemetry is being shed at the bounded
    /// channel because the consumer is not draining the socket — the dataplane
    /// is unaffected.
    pub(crate) write_stalls: u64,
    /// Count of accepted frames evicted from the replay buffer on wrap before
    /// the daemon ACKed them (#2382). These were counted as `sent` but are
    /// permanently lost; a non-zero, growing value means RT_FLOW / dataplane
    /// telemetry was dropped via replay-buffer eviction (a daemon that
    /// disconnected or withheld ACKs long enough for the window to wrap).
    /// ACK-trim does NOT increment this — only the buffer-full eviction.
    pub(crate) replay_evictions: u64,
    /// Count of MSG_ACK control frames rejected because the daemon ACKed a
    /// sequence outside the valid `[acked_seq, next_seq]` window — either a
    /// backward ACK (`seq < acked_seq`) or a future ACK of a sequence the
    /// helper never allocated (`seq > next_seq`) (#2959). Such an ACK comes
    /// from a buggy, mixed-version, or corrupted daemon listener; the helper
    /// fails closed by ignoring it (watermark + replay buffer left intact). A
    /// non-zero, growing value means the peer's ACK view is corrupt.
    pub(crate) invalid_acks: u64,
    #[allow(dead_code)] // stats field for future reporting
    pub(crate) replayed: u64,
    /// #9169 / #4800 site 4: acquisitions of the process-global
    /// `producer_seq_lock` taken by a producer, and the blocked subset. Read as
    /// a pair — a contended count without its denominator is not interpretable,
    /// and a site with zero acquisitions is "never taken", which is a different
    /// finding from "taken but never blocked".
    pub(crate) producer_seq_lock_acquisitions: u64,
    pub(crate) producer_seq_lock_contended: u64,
    #[allow(dead_code)] // producer-call-site wiring will surface these fields
    pub(crate) dataplane_events: DataplaneEventStats,
}

struct EventStreamShared {
    /// Workers fetch_add to get globally monotonic sequence numbers.
    next_seq: AtomicU64,
    /// Serializes seq allocation with channel enqueue across all producer
    /// threads (#3878). Held ONLY around `next_seq` allocation + the single
    /// `tx.try_send`, so the wire (channel-FIFO) order equals seq order and two
    /// workers cannot allocate N and N+1 but enqueue them inverted (F-152). The
    /// critical section is non-blocking (an atomic + a byte-copy encode + a
    /// non-blocking `try_send`); the lossless retry path releases it before any
    /// sleep so a backpressured export never stalls the other producers.
    ///
    /// #5267: the I/O thread's replay-gap FullResync now ALSO allocates its seq
    /// under this lock (`replay_buffered`). Holding the lock across just the
    /// `fetch_add` guarantees every delta already committed to the channel has a
    /// strictly LOWER seq (the channel commit is atomic under the same lock), so
    /// no producer-committed lower seq can be assigned between the barrier's
    /// allocation and those deltas. The FullResync is NOT written directly to
    /// the socket; it is parked in `pending_resync` and emitted by the connected
    /// loop's drain in seq order (`drain_channel_into_write_buf`), restoring the
    /// wire==seq invariant the Go reader (zero reorder tolerance) depends on. No
    /// socket write happens under the lock — the barrier is written later, on
    /// the I/O thread's own write path — so a wedged reader cannot stall the
    /// producers through this path. Only the DORMANT drain-poison resync
    /// (`handle_drain_request`, which has no live caller) still allocates
    /// outside this lock; the rollback CAS below tolerates that rare interleave.
    producer_seq_lock: Mutex<()>,
    /// #9169 / #4800 SITE 4: acquisitions of `producer_seq_lock` taken by a
    /// PRODUCER — the denominator.
    ///
    /// `docs/userspace-newflow-ceiling.md` named three cross-worker
    /// synchronization points on the new-flow install path and this was not one
    /// of them, so a run that saturated here could not be attributed: the
    /// harness would report a new-flows/sec plateau with every named site cold.
    /// Every session delta, Open as well as Close, passes through this mutex
    /// with the frame ENCODE inside the critical section, and the mutex lives
    /// on `shared` — it is process-global across every producer thread.
    ///
    /// SCOPE, and it is load-bearing exactly as the sibling sites' is. Only the
    /// two PRODUCER acquisitions are counted (`send_sequenced`, and each
    /// attempt of `send_lossless_encoded`'s retry loop). The I/O thread's
    /// replay-gap FullResync allocation (`connection.rs`, #5267) takes the same
    /// mutex and is deliberately EXCLUDED: it is not a producer, it fires once
    /// per reconnect, and folding it into the denominator would dilute the
    /// ratio with the observer — the same reasoning that keeps
    /// `remove_shared_session` out of the publish denominator. Its blocking
    /// effect on producers is still visible, because it shows up as producer
    /// CONTENTION, which is the number that matters.
    producer_seq_lock_acquisitions: AtomicU64,
    /// The subset of [`Self::producer_seq_lock_acquisitions`] that found the
    /// mutex held and had to block.
    ///
    /// `try_lock()` first — on an uncontended mutex that is the same single CAS
    /// `lock()` already cost, so the LOCK ITSELF is unchanged. The acquisition
    /// counter above it is unconditional, so an uncontended acquisition is 2
    /// relaxed RMWs where it was 1; a failed CAS pays one more increment on top
    /// of a block that was going to happen anyway.
    producer_seq_lock_contended: AtomicU64,
    /// Updated by I/O thread from Ack frames.
    acked_seq: AtomicU64,
    /// Set by Pause, cleared by Resume.
    paused: AtomicBool,
    /// #2875: poison flag for the paused demotion drain. Set when a SESSION-SYNC
    /// delta (`SessionOpen`/`SessionUpdate`/`SessionClose`) is evicted from the
    /// bounded replay buffer at `REPLAY_BUFFER_CAPACITY` WHILE PAUSED.
    ///
    /// A paused drain is meant to be a lossless, stable window the future owner
    /// reads before demotion completes (`docs/session-sync-design.md`). The
    /// replay buffer is bounded, so a long pause that overruns it evicts the
    /// oldest frames (bumping `frames_replay_evicted` only). If an evicted frame
    /// is a session mutation, that mutation never reaches the new owner — yet
    /// `handle_drain_request` would still report `DrainComplete` and demotion
    /// would finish with lost sessions on the peer.
    ///
    /// When set, `handle_drain_request` WITHHOLDS `DrainComplete` and emits a
    /// `FullResync` instead, forcing the daemon to re-export full session state
    /// (the same recovery path as #2874 / the replay-gap resync). Telemetry
    /// eviction does NOT set this — it must not trigger a spurious resync.
    ///
    /// Lifecycle: set on a session-frame eviction during pause
    /// (`evict_replay_frame`); cleared at pause-start (`MSG_PAUSE`) so each
    /// fresh pause window starts clean, and after a poisoned drain emits its
    /// `FullResync` (window consumed — a later eviction re-poisons). NOT a
    /// substitute for bounding the buffer: the fix is poison-on-loss, the buffer
    /// stays bounded (no unbounded growth / memory DoS).
    session_evicted_while_paused: AtomicBool,
    /// Raised once by `EventStreamSender::stop` (and `Drop`) to ask the I/O
    /// thread to exit. Lives in the shared state — rather than as a separately
    /// threaded `Arc<AtomicBool>` — so every I/O-thread function that already
    /// holds `shared` (connect, replay, drain, the connected loop) can observe
    /// it. This is what makes the bounded replay/drain writer
    /// (`write_all_backpressured`) stop-aware: a write that keeps hitting
    /// `WouldBlock` against a stuck reader bails out as soon as this is set, so
    /// the stop-join can never deadlock behind a wedged write (#2877).
    stop: AtomicBool,
    /// True when the event socket is connected.
    connected: AtomicBool,
    /// Counters.
    frames_sent: AtomicU64,
    frames_dropped: AtomicU64,
    /// I/O cycles in which `write_buf` hit `WRITE_BACKLOG_MAX_BYTES` and the
    /// channel drain was halted (stalled consumer signal, #2381).
    frames_write_stalled: AtomicU64,
    /// Accepted-and-enqueued frames evicted from the replay buffer when it
    /// wrapped at `REPLAY_BUFFER_CAPACITY` before the daemon ACKed them
    /// (#2382). These frames were counted in `frames_sent` at enqueue but are
    /// unrecoverable after reconnect — a real telemetry loss. Distinct from
    /// ACK-trim (frames removed because they were acknowledged, which is NOT a
    /// loss): only the buffer-full eviction path increments this.
    frames_replay_evicted: AtomicU64,
    /// MSG_ACK frames rejected because the daemon ACKed a sequence outside the
    /// valid `[acked_seq, next_seq]` window (#2959). See `invalid_acks` in
    /// `EventStreamStats`.
    frames_invalid_acks: AtomicU64,
    frames_replayed: AtomicU64,
    dataplane_event_counters: DataplaneEventCounters,
    #[allow(dead_code)] // consumed by producer call sites once they are wired
    dataplane_event_limiter: DataplaneEventRateLimiter,
    dataplane_event_queue: DataplaneEventQueueBudget,
}

impl EventStreamShared {
    fn new() -> Self {
        Self::new_with_dataplane_event_rate(DataplaneEventRateLimitConfig::default())
    }

    fn new_with_dataplane_event_rate(config: DataplaneEventRateLimitConfig) -> Self {
        Self::new_with_dataplane_event_rate_and_queue_capacity(config, CHANNEL_CAPACITY)
    }

    fn new_with_dataplane_event_rate_and_queue_capacity(
        config: DataplaneEventRateLimitConfig,
        channel_capacity: usize,
    ) -> Self {
        Self {
            next_seq: AtomicU64::new(0),
            producer_seq_lock: Mutex::new(()),
            producer_seq_lock_acquisitions: AtomicU64::new(0),
            producer_seq_lock_contended: AtomicU64::new(0),
            acked_seq: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            session_evicted_while_paused: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            frames_sent: AtomicU64::new(0),
            frames_dropped: AtomicU64::new(0),
            frames_write_stalled: AtomicU64::new(0),
            frames_replay_evicted: AtomicU64::new(0),
            frames_invalid_acks: AtomicU64::new(0),
            frames_replayed: AtomicU64::new(0),
            dataplane_event_counters: DataplaneEventCounters::new(),
            dataplane_event_limiter: DataplaneEventRateLimiter::new(config),
            dataplane_event_queue: DataplaneEventQueueBudget::new(channel_capacity),
        }
    }

    /// #9169: acquire `producer_seq_lock` WITH contention accounting.
    ///
    /// The poison policy is reproduced from the call sites this replaced, not
    /// changed: a poisoned mutex is recovered with `into_inner()` and the
    /// producer continues. `producer_seq_lock` guards a `()` — there is no
    /// invariant a panicking holder could have left half-written — so refusing
    /// the lock would turn a survivable panic into a permanently mute event
    /// stream.
    ///
    /// `try_lock()` reports `Poisoned` only when the mutex is FREE, so the
    /// poisoned arm is handled on both branches, exactly as
    /// `lock_shared_publish` does for the #4800 publish site.
    #[inline]
    fn lock_producer_seq(&self) -> MutexGuard<'_, ()> {
        self.producer_seq_lock_acquisitions
            .fetch_add(1, Ordering::Relaxed);
        match self.producer_seq_lock.try_lock() {
            Ok(guard) => return guard,
            Err(TryLockError::Poisoned(poisoned)) => return poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {}
        }
        self.producer_seq_lock_contended
            .fetch_add(1, Ordering::Relaxed);
        self.producer_seq_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventStreamSendError {
    Full,
    Disconnected,
}

// ---------------------------------------------------------------------------
// EventStreamSender -- coordinator-level handle
// ---------------------------------------------------------------------------

/// Coordinator-level event stream handle. Owns the I/O thread.
pub(crate) struct EventStreamSender {
    tx: SyncSender<EventFrame>,
    shared: Arc<EventStreamShared>,
    io_thread: Option<JoinHandle<()>>,
}

impl EventStreamSender {
    /// Create a new event stream sender and spawn the I/O thread.
    /// The helper connects to the daemon listener at `socket_path`.
    pub(crate) fn new(socket_path: &str) -> Self {
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let shared = Arc::new(EventStreamShared::new());

        let shared_clone = shared.clone();
        let path = socket_path.to_string();

        let io_thread = thread::Builder::new()
            .name("xpf-event-stream".to_string())
            .spawn(move || {
                io_thread_main(rx, shared_clone, path);
            })
            .expect("spawn event stream I/O thread");

        Self {
            tx,
            shared,
            io_thread: Some(io_thread),
        }
    }

    /// Get a lightweight handle to pass to worker threads.
    pub(crate) fn worker_handle(&self) -> EventStreamWorkerHandle {
        EventStreamWorkerHandle {
            tx: self.tx.clone(),
            shared: self.shared.clone(),
        }
    }

    /// Current event stream statistics.
    pub(crate) fn stats(&self) -> EventStreamStats {
        EventStreamStats {
            connected: self.shared.connected.load(Ordering::Relaxed),
            seq: self.shared.next_seq.load(Ordering::Relaxed),
            acked_seq: self.shared.acked_seq.load(Ordering::Relaxed),
            sent: self.shared.frames_sent.load(Ordering::Relaxed),
            dropped: self.shared.frames_dropped.load(Ordering::Relaxed),
            write_stalls: self.shared.frames_write_stalled.load(Ordering::Relaxed),
            replay_evictions: self.shared.frames_replay_evicted.load(Ordering::Relaxed),
            invalid_acks: self.shared.frames_invalid_acks.load(Ordering::Relaxed),
            replayed: self.shared.frames_replayed.load(Ordering::Relaxed),
            producer_seq_lock_acquisitions: self
                .shared
                .producer_seq_lock_acquisitions
                .load(Ordering::Relaxed),
            producer_seq_lock_contended: self
                .shared
                .producer_seq_lock_contended
                .load(Ordering::Relaxed),
            dataplane_events: self.shared.dataplane_event_counters.snapshot(),
        }
    }

    /// #2880 test seam: build an `EventStreamSender` WITHOUT spawning the I/O
    /// thread, with the connected flag forced to `connected`. The returned
    /// `Receiver` must be kept alive by the test so the channel does not
    /// disconnect; `push_delta_lossless` then succeeds (connected + live rx)
    /// or fails immediately (`connected = false`) exactly like the production
    /// disconnected / connected paths, without a real socket.
    #[cfg(test)]
    pub(crate) fn test_sender(
        connected: bool,
        capacity: usize,
    ) -> (Self, mpsc::Receiver<EventFrame>) {
        let (tx, rx) = mpsc::sync_channel(capacity);
        let shared = Arc::new(EventStreamShared::new());
        shared.connected.store(connected, Ordering::Release);
        (
            Self {
                tx,
                shared,
                io_thread: None,
            },
            rx,
        )
    }

    /// Signal the I/O thread to stop and wait for it to exit.
    ///
    /// The stop flag lives in `shared`, so a replay/drain write that is
    /// currently backpressured against a stuck reader observes it within one
    /// `REPLAY_DRAIN_WRITE_POLL` and bails out — the join below cannot deadlock
    /// behind a wedged blocking write (#2877).
    pub(crate) fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Some(join) = self.io_thread.take() {
            let _ = join.join();
        }
    }
}

impl Drop for EventStreamSender {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
pub(crate) fn test_worker_handle(
    capacity: usize,
    config: DataplaneEventRateLimitConfig,
) -> (EventStreamWorkerHandle, mpsc::Receiver<EventFrame>) {
    let (tx, rx) = mpsc::sync_channel(capacity);
    let shared = Arc::new(
        EventStreamShared::new_with_dataplane_event_rate_and_queue_capacity(config, capacity),
    );
    (EventStreamWorkerHandle { tx, shared }, rx)
}

/// #5468 test seam: build a CONNECTED worker handle (connected flag forced
/// `true`) whose bounded mpsc channel has `capacity` slots. The returned
/// `Receiver` is never drained by the test, so filling the channel to capacity
/// models a connected-but-unread peer — exactly the state that drives the
/// bounded backpressure retry loop in `push_delta_lossless_within` (rather than
/// the immediate `!connected` early return that `test_worker_handle` exercises).
/// The `Receiver` must be kept alive so the channel stays connected.
#[cfg(test)]
pub(crate) fn test_worker_handle_connected(
    capacity: usize,
    config: DataplaneEventRateLimitConfig,
) -> (EventStreamWorkerHandle, mpsc::Receiver<EventFrame>) {
    let (handle, rx) = test_worker_handle(capacity, config);
    handle.shared.connected.store(true, Ordering::Release);
    (handle, rx)
}

// ---------------------------------------------------------------------------
// EventStreamWorkerHandle -- lightweight clone for worker threads
// ---------------------------------------------------------------------------

/// Worker-thread handle. Cheap to clone (Arc + SyncSender clone).
#[derive(Clone)]
pub(crate) struct EventStreamWorkerHandle {
    tx: SyncSender<EventFrame>,
    shared: Arc<EventStreamShared>,
}

impl EventStreamWorkerHandle {
    /// Allocate the next globally-monotonic sequence number.
    pub(crate) fn next_seq(&self) -> u64 {
        self.shared.next_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Non-blocking send. Returns false if the channel is full (event dropped).
    pub(crate) fn try_send(&self, frame: EventFrame) -> bool {
        self.try_send_frame(frame).is_ok()
    }

    /// #2880: record `n` deltas that could not be queued through the LOSSLESS
    /// producer (event stream disconnected / saturated). `send_frame_lossless`
    /// returns the failure as an `Err` rather than bumping `frames_dropped`
    /// (its caller decides whether the loss matters), so a caller that treats
    /// the drop as a tolerated cleanup miss — the tunnel-remap purge, #2880 —
    /// records it here so it surfaces in the same dropped-frames metric the
    /// lossy `try_send` path uses, instead of being silently swallowed.
    pub(crate) fn record_dropped_frames(&self, n: u64) {
        self.shared.frames_dropped.fetch_add(n, Ordering::Relaxed);
    }

    fn try_send_frame(&self, frame: EventFrame) -> Result<(), EventStreamSendError> {
        match self.tx.try_send(frame) {
            Ok(()) => {
                self.shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::TrySendError::Full(_)) => {
                self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                Err(EventStreamSendError::Full)
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                Err(EventStreamSendError::Disconnected)
            }
        }
    }

    /// Roll back a sequence number allocated by `next_seq()` when the frame it
    /// was allocated for could NOT be committed to the channel (#3878 F-153).
    ///
    /// Called ONLY while `producer_seq_lock` is held, so no other producer
    /// thread can have allocated after us — `seq` is the highest
    /// producer-allocated value and rolling it back frees it for the next
    /// enqueue, keeping the wire seq contiguous. The compare-exchange guards
    /// the rare race with the I/O thread's own FullResync allocation (the
    /// DORMANT drain-poison path in `handle_drain_request`, which does not take
    /// this lock; #5267 moved `replay_buffered`'s FullResync allocation UNDER
    /// this lock, so it no longer races here): if it
    /// bumped `next_seq` past `seq`, the CAS fails and we leave the counter
    /// alone — that seq is burned, but a FullResync is already in flight so the
    /// reader resets and the hole is moot. The CAS can never create a duplicate
    /// wire seq.
    fn rollback_seq(&self, seq: u64) {
        let _ = self.shared.next_seq.compare_exchange(
            seq,
            seq - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Allocate the next wire sequence number and enqueue `encode(seq)` to the
    /// shared channel ATOMICALLY under `producer_seq_lock`, so seq order ==
    /// channel (wire) order across every producer thread (#3878 F-152). On a
    /// `Full` drop the seq is rolled back so a saturation drop never burns a
    /// sequence number and trips the reader's gap check (#3878 F-153). A
    /// `Disconnected` drop leaves the counter advanced: the stream tears down
    /// and the reader reconnects from `lastRecvSeq = 0`, so the burn is benign
    /// and rolling it back would only risk racing a fresh reconnect.
    fn send_sequenced<F>(&self, encode: F) -> Result<u64, EventStreamSendError>
    where
        F: FnOnce(u64) -> EventFrame,
    {
        let _guard = self.shared.lock_producer_seq();
        let seq = self.next_seq();
        let frame = encode(seq);
        match self.try_send_frame(frame) {
            Ok(()) => Ok(seq),
            Err(EventStreamSendError::Full) => {
                self.rollback_seq(seq);
                Err(EventStreamSendError::Full)
            }
            Err(EventStreamSendError::Disconnected) => Err(EventStreamSendError::Disconnected),
        }
    }

    /// Lossless retry core shared by `send_frame_lossless` (pre-built control
    /// frames) and `push_delta_lossless` (session deltas). On EACH attempt the
    /// `encode` closure runs and the frame is enqueued while
    /// `producer_seq_lock` is held, so a delta's seq is allocated in the same
    /// critical section as its enqueue (#3878) even across the retry loop and
    /// concurrent lossy producers. The lock is dropped before any sleep so a
    /// backpressured lossless export never stalls the other producers.
    ///
    /// `encode` returns `(frame, rollback_seq)`; `rollback_seq` is `Some(seq)`
    /// for frames whose seq came from `next_seq()` (roll it back on a drop,
    /// #3878 F-153) and `None` for control frames that carry a fixed, non-
    /// allocated seq (e.g. `DrainComplete`).
    ///
    /// `timeout` bounds the total backpressure wait before this gives up and
    /// returns `Err`. Off-worker-loop callers (bulk export on connect, the
    /// tunnel-remap purge) pass the full `LOSSLESS_QUEUE_TIMEOUT` (5 s). The
    /// packet-worker-loop caller (`flush_session_deltas` via
    /// `push_delta_lossless_within`) passes a SHORT budget well below
    /// `HEARTBEAT_STALE_AFTER` so a connected-but-unread peer cannot stall the
    /// worker past the heartbeat-stale threshold and self-inflict a spurious
    /// failover (#5468). Either way the give-up is a genuine `Err` the caller
    /// latches as loss-of-sync (forcing a full resync) — never a silent drop.
    fn send_lossless_encoded<F>(&self, timeout: Duration, mut encode: F) -> Result<(), String>
    where
        F: FnMut() -> (EventFrame, Option<u64>),
    {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err("event stream not connected".to_string());
        }
        let deadline = Instant::now() + timeout;
        loop {
            // Raw `tx.try_send` (NOT `try_send_frame`): a `Full` here is a
            // RETRY, not a drop, so it must not bump `frames_dropped` — the
            // lossless caller decides whether an eventual give-up counts as a
            // loss (#2880). Allocation, enqueue, AND the rollback-on-drop all
            // happen together under the producer lock (#3878): the rollback
            // MUST stay inside the guard so allocations+rollbacks are strictly
            // LIFO and `rollback_seq`'s CAS always targets the top of the
            // stack. Rolling back after the lock is released lets two
            // concurrent flushers interleave alloc(N)/alloc(N+1)/rollback(N)-
            // fails/rollback(N+1)-succeeds and STRAND seq N — the exact F-153
            // hole this fix targets (flush_session_deltas runs push_delta_
            // lossless per-worker, so >=2 concurrent flushers on a Full channel
            // is the normal recovery-churn regime).
            let outcome = {
                let _guard = self.shared.lock_producer_seq();
                let (frame, rollback_seq) = encode();
                let reported_seq = frame.seq;
                match self.tx.try_send(frame) {
                    Ok(()) => Ok(()),
                    Err(mpsc::TrySendError::Full(_)) => {
                        // The next attempt re-allocates, so this attempt's seq
                        // must be freed for the next successful enqueue (and a
                        // give-up must leave no burned seq). Control frames
                        // carry a fixed seq (None).
                        if let Some(seq) = rollback_seq {
                            self.rollback_seq(seq);
                        }
                        Err((EventStreamSendError::Full, reported_seq))
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        if let Some(seq) = rollback_seq {
                            self.rollback_seq(seq);
                        }
                        Err((EventStreamSendError::Disconnected, reported_seq))
                    }
                }
            };
            match outcome {
                Ok(()) => {
                    self.shared.frames_sent.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err((EventStreamSendError::Full, reported_seq)) => {
                    if !self.shared.connected.load(Ordering::Acquire) {
                        return Err(format!(
                            "event stream disconnected while queuing seq {reported_seq}"
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "timed out queuing event stream frame seq {reported_seq}"
                        ));
                    }
                    thread::sleep(LOSSLESS_QUEUE_RETRY_DELAY);
                }
                Err((EventStreamSendError::Disconnected, reported_seq)) => {
                    return Err(format!(
                        "event stream channel disconnected while queuing seq {reported_seq}"
                    ));
                }
            }
        }
    }

    /// Lossless send of a caller-encoded frame that carries its own seq (a
    /// control frame such as `DrainComplete`). Retries on a full channel until
    /// capacity frees, the deadline expires, or the peer disconnects. Test-only
    /// after #3878 rerouted `push_delta_lossless` through the seq-allocating
    /// `send_lossless_encoded` closure.
    #[cfg_attr(not(test), allow(dead_code))]
    fn send_frame_lossless(&self, frame: EventFrame) -> Result<(), String> {
        self.send_lossless_encoded(LOSSLESS_QUEUE_TIMEOUT, move || (frame.clone(), None))
    }

    fn encode_delta_frame(
        seq: u64,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) -> EventFrame {
        match delta.kind {
            SessionDeltaKind::Open => EventFrame::encode_session_open(
                seq,
                &delta.key,
                &delta.decision,
                &delta.metadata,
                zone_name_to_id,
                delta.fabric_redirect_sync,
                // #5212: the delta's stable RT_FLOW session id, carried on the
                // HA session-sync open frame so the peer adopts it on import.
                delta.session_id,
                // #9412: the session's current close class.
                delta.tcp_close_class,
            ),
            // #9412: a close-state update rides the OPEN record layout on its own
            // message type (3), which the Go decoder already reads as an upsert.
            SessionDeltaKind::Update => EventFrame::encode_session_update(
                seq,
                &delta.key,
                &delta.decision,
                &delta.metadata,
                zone_name_to_id,
                delta.fabric_redirect_sync,
                delta.session_id,
                delta.tcp_close_class,
            ),
            SessionDeltaKind::Close => EventFrame::encode_session_close(
                seq,
                &delta.key,
                delta.metadata.owner_rg_id,
                close_flags(delta),
                delta.metadata.ingress_zone,
                delta.metadata.egress_zone,
            ),
        }
    }

    /// Encode and send a session delta as an event frame. The seq is allocated
    /// atomically with the channel enqueue (#3878) so a concurrent producer
    /// cannot invert wire order, and a full-channel drop rolls the seq back
    /// rather than burning it into a reader-visible gap.
    pub(crate) fn push_delta(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) {
        let _ = self.send_sequenced(|seq| Self::encode_delta_frame(seq, delta, zone_name_to_id));
    }

    /// Lossless variant used for explicit bootstrap/replay exports. This path
    /// may wait briefly for queue capacity, but it never silently drops. The
    /// seq is (re)allocated under the producer lock on each retry (#3878), so
    /// the delta's wire seq matches its enqueue order even under backpressure
    /// and concurrent lossy producers.
    pub(crate) fn push_delta_lossless(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
    ) -> Result<(), String> {
        self.push_delta_lossless_within(delta, zone_name_to_id, LOSSLESS_QUEUE_TIMEOUT)
    }

    /// #5468: worker-loop variant of [`push_delta_lossless`] that bounds the
    /// backpressure wait to `budget` instead of the fixed 5 s
    /// `LOSSLESS_QUEUE_TIMEOUT`.
    ///
    /// `flush_session_deltas` runs on the packet worker loop, so a
    /// connected-but-unread peer (a slow/stalled reader whose channel is full)
    /// must NOT be able to block the loop for the full `LOSSLESS_QUEUE_TIMEOUT`
    /// — that exceeds `HEARTBEAT_STALE_AFTER`, so the peer marks this node stale
    /// and triggers a false failover. The caller passes a `budget` well below
    /// the heartbeat-stale threshold (`WORKER_LOSSLESS_QUEUE_BUDGET`); on
    /// timeout this returns `Err` exactly like the 5 s path and the caller
    /// latches loss-of-sync (a full owner-RG resync). Losslessness is preserved
    /// — the delta is either delivered or a resync is forced, never a silent
    /// drop (the #2874 contract).
    pub(crate) fn push_delta_lossless_within(
        &self,
        delta: &SessionDelta,
        zone_name_to_id: &FxHashMap<String, u16>,
        budget: Duration,
    ) -> Result<(), String> {
        self.send_lossless_encoded(budget, || {
            let seq = self.next_seq();
            (
                Self::encode_delta_frame(seq, delta, zone_name_to_id),
                Some(seq),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
