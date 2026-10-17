#![allow(dead_code)] // status surfaces still consume only part of the producer API

use super::codec::{DataplaneEventKind, DataplaneEventPayload};
use super::{EventFrame, EventStreamSendError, EventStreamWorkerHandle};
use std::array;
use std::sync::atomic::{AtomicU64, Ordering};

// #2512: 5 kinds — PolicyDeny, ScreenDrop, FilterLog, SessionClose,
// SessionCreate. SessionClose/SessionCreate were added so the RT_FLOW
// close/create frames share the same per-kind limiter, queue budget, and
// counters instead of a bare `try_send` side channel.
const DATAPLANE_EVENT_KIND_COUNT: usize = 5;
const DATAPLANE_EVENT_ZONE_BUCKETS: usize = 256;
const DATAPLANE_EVENT_RATE_BUCKETS: usize =
    DATAPLANE_EVENT_KIND_COUNT * DATAPLANE_EVENT_ZONE_BUCKETS;
const DATAPLANE_EVENT_QUEUE_SHARE_DIVISOR: usize = 2;
const NS_PER_SEC: u64 = 1_000_000_000;

const DEFAULT_DATAPLANE_EVENT_RATE_PER_SEC: u64 = 1_000;
const DEFAULT_DATAPLANE_EVENT_BURST: u64 = 1_024;

// #14609: SessionClose is the sole input to NetFlow/IPFIX flow export
// (session_delta.rs: "flowexport still needs every close"), so it must not
// share the 1000/s deny-flood GCRA: above ~1000 closes/s/zone the export
// was systematically undercounted while the IPFIX sampler record still
// advertised 1-in-N over the survivors only. The close kind gets its own
// GCRA sized at the session channel's drain capacity (CHANNEL_CAPACITY
// frames per second sustained, same burst) so a conforming close stream
// is never rate-shed; the bounded queue budget below remains the flood
// bound, and any queue/disconnect shed stays counted in
// ProcessStatus.event_stream_session_close_{dropped,queue_full,
// disconnected} and the matching Prometheus series (#10979). The other
// telemetry kinds keep the shared 1000/s flood limit unchanged.
const DEFAULT_SESSION_CLOSE_RATE_PER_SEC: u64 = 8_192;
const DEFAULT_SESSION_CLOSE_BURST: u64 = 8_192;

/// Per-kind/per-source-zone rate-limit configuration for dataplane telemetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DataplaneEventRateLimitConfig {
    /// Sustained event rate per `(event kind, ingress zone)` bucket. Zero
    /// disables limiting for tests and emergency builds.
    pub(crate) events_per_second: u64,
    /// Instantaneous burst per `(event kind, ingress zone)` bucket.
    pub(crate) burst: u64,
    /// #14609: sustained SessionClose rate per `(SessionClose, ingress
    /// zone)` bucket; zero disables limiting for that kind. Kept separate
    /// from `events_per_second` so flow export is not starved by the
    /// shared telemetry flood limit.
    pub(crate) session_close_events_per_second: u64,
    /// #14609: instantaneous SessionClose burst per bucket.
    pub(crate) session_close_burst: u64,
}

impl Default for DataplaneEventRateLimitConfig {
    fn default() -> Self {
        Self {
            events_per_second: DEFAULT_DATAPLANE_EVENT_RATE_PER_SEC,
            burst: DEFAULT_DATAPLANE_EVENT_BURST,
            session_close_events_per_second: DEFAULT_SESSION_CLOSE_RATE_PER_SEC,
            session_close_burst: DEFAULT_SESSION_CLOSE_BURST,
        }
    }
}

impl DataplaneEventRateLimitConfig {
    fn unlimited(self) -> bool {
        self.events_per_second == 0
    }

    fn runtime_for(events_per_second: u64, burst: u64) -> DataplaneEventRateLimit {
        if events_per_second == 0 {
            return DataplaneEventRateLimit {
                interval_ns: 0,
                burst_horizon_ns: 0,
            };
        }

        let interval_ns = NS_PER_SEC
            .saturating_add(events_per_second.saturating_sub(1))
            .saturating_div(events_per_second)
            .max(1);
        let burst = burst.max(1);
        DataplaneEventRateLimit {
            interval_ns,
            burst_horizon_ns: interval_ns.saturating_mul(burst.saturating_sub(1)),
        }
    }

    fn runtime(self) -> DataplaneEventRateLimit {
        Self::runtime_for(self.events_per_second, self.burst)
    }

    // #14609: the SessionClose GCRA; a zero rate disables limiting for
    // that kind even when the shared telemetry limit stays finite.
    fn session_close_runtime(self) -> DataplaneEventRateLimit {
        Self::runtime_for(
            self.session_close_events_per_second,
            self.session_close_burst,
        )
    }
}

#[derive(Clone, Copy)]
struct DataplaneEventRateLimit {
    interval_ns: u64,
    burst_horizon_ns: u64,
}

impl DataplaneEventRateLimit {
    fn unlimited(self) -> bool {
        self.interval_ns == 0
    }
}

#[derive(Default)]
struct DataplaneEventRateBucket {
    theoretical_arrival_ns: AtomicU64,
}

impl DataplaneEventRateBucket {
    fn allow_at(&self, limit: DataplaneEventRateLimit, now_ns: u64) -> bool {
        if limit.unlimited() {
            return true;
        }

        // GCRA form of a token bucket: one atomic TAT gives fixed memory,
        // no locks, and no per-packet heap work on the producer path.
        let mut tat = self.theoretical_arrival_ns.load(Ordering::Relaxed);
        loop {
            if tat.saturating_sub(limit.burst_horizon_ns) > now_ns {
                return false;
            }
            let next_tat = tat.max(now_ns).saturating_add(limit.interval_ns);
            match self.theoretical_arrival_ns.compare_exchange_weak(
                tat,
                next_tat,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => tat = actual,
            }
        }
    }
}

pub(super) struct DataplaneEventRateLimiter {
    limit: DataplaneEventRateLimit,
    // #14609: separate GCRA parameters for SessionClose buckets. Only the
    // SessionClose row of `buckets` reads this limit (see `limit_for`); the
    // buckets themselves stay one fixed array, so no allocation is added.
    session_close_limit: DataplaneEventRateLimit,
    buckets: [DataplaneEventRateBucket; DATAPLANE_EVENT_RATE_BUCKETS],
}

impl DataplaneEventRateLimiter {
    pub(super) fn new(config: DataplaneEventRateLimitConfig) -> Self {
        Self {
            limit: config.runtime(),
            session_close_limit: config.session_close_runtime(),
            buckets: array::from_fn(|_| DataplaneEventRateBucket::default()),
        }
    }

    fn limit_for(&self, kind: DataplaneEventKind) -> DataplaneEventRateLimit {
        match kind {
            DataplaneEventKind::SessionClose => self.session_close_limit,
            _ => self.limit,
        }
    }

    fn allow_at(&self, kind: DataplaneEventKind, ingress_zone_id: u16, now_ns: u64) -> bool {
        self.buckets[rate_bucket_index(kind, ingress_zone_id)]
            .allow_at(self.limit_for(kind), now_ns)
    }
}

pub(super) struct DataplaneEventQueueBudget {
    max_total_queued: u64,
    max_kind_queued: u64,
    total_queued: AtomicU64,
    kind_queued: [AtomicU64; DATAPLANE_EVENT_KIND_COUNT],
}

impl DataplaneEventQueueBudget {
    pub(super) fn new(channel_capacity: usize) -> Self {
        // Dataplane telemetry is lossy by design: bound it to roughly half of
        // the shared channel for normal capacities, then split that telemetry
        // share across event kinds so one storm cannot monopolize it.
        let max_total_queued = (channel_capacity / DATAPLANE_EVENT_QUEUE_SHARE_DIVISOR) as u64;
        let max_total_queued = if channel_capacity == 0 {
            0
        } else {
            max_total_queued.max(1)
        };
        let kind_count = DATAPLANE_EVENT_KIND_COUNT as u64;
        let max_kind_queued = if max_total_queued == 0 {
            0
        } else {
            max_total_queued
                .saturating_add(kind_count.saturating_sub(1))
                .saturating_div(kind_count)
                .max(1)
        };

        Self {
            max_total_queued,
            max_kind_queued,
            total_queued: AtomicU64::new(0),
            kind_queued: array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn try_acquire(&self, kind: DataplaneEventKind) -> bool {
        if !try_increment_below(&self.total_queued, self.max_total_queued) {
            return false;
        }
        if !try_increment_below(&self.kind_queued[kind_index(kind)], self.max_kind_queued) {
            self.total_queued.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub(super) fn release(&self, kind: DataplaneEventKind) {
        decrement_if_positive(&self.kind_queued[kind_index(kind)]);
        decrement_if_positive(&self.total_queued);
    }

    /// Test-only budget seed: increment the per-kind (and total) queue budget
    /// that a real `emit`/`try_acquire` would have charged for a frame.
    ///
    /// The mod-level replay/drain tests build the replay buffer directly (via
    /// `push_replay_frame`) to construct a full-buffer eviction scenario,
    /// deliberately bypassing the producer's `emit` path. Any injected frame
    /// carrying a `dataplane_event_kind()` (telemetry: deny/screen/filter/
    /// RT_FLOW) is released through `release()` when it is evicted or popped;
    /// without the matching acquire the release decrements a zero counter and
    /// trips the #1826 underflow guard (`decrement_if_positive`). Seeding the
    /// budget here mirrors production, where every buffered telemetry frame
    /// holds exactly one budget slot from emit until removal.
    ///
    /// Bypasses the admission caps on purpose: the direct-injection tests build
    /// buffer states larger than a single kind's admission budget (which
    /// `try_acquire` would refuse), so this is a raw counter bump, not an
    /// admission decision.
    #[cfg(test)]
    pub(super) fn acquire_for_test(&self, kind: DataplaneEventKind) {
        self.total_queued.fetch_add(1, Ordering::Relaxed);
        self.kind_queued[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataplaneEventDropReason {
    RateLimited,
    QueueFull,
    Disconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataplaneEventEmitOutcome {
    Queued { seq: u64 },
    Dropped { reason: DataplaneEventDropReason },
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DataplaneEventKindStats {
    pub(crate) sent: u64,
    pub(crate) dropped: u64,
    pub(crate) rate_limited: u64,
    pub(crate) queue_full: u64,
    pub(crate) disconnected: u64,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DataplaneEventStats {
    pub(crate) policy_deny: DataplaneEventKindStats,
    pub(crate) screen_drop: DataplaneEventKindStats,
    pub(crate) filter_log: DataplaneEventKindStats,
    // #2512: per-kind sent/dropped accounting for the RT_FLOW close/create
    // frames, previously emitted via an unaccounted bare `try_send`.
    pub(crate) session_close: DataplaneEventKindStats,
    pub(crate) session_create: DataplaneEventKindStats,
}

pub(super) struct DataplaneEventCounters {
    sent: [AtomicU64; DATAPLANE_EVENT_KIND_COUNT],
    rate_limited: [AtomicU64; DATAPLANE_EVENT_KIND_COUNT],
    queue_full: [AtomicU64; DATAPLANE_EVENT_KIND_COUNT],
    disconnected: [AtomicU64; DATAPLANE_EVENT_KIND_COUNT],
}

impl DataplaneEventCounters {
    pub(super) fn new() -> Self {
        Self {
            sent: array::from_fn(|_| AtomicU64::new(0)),
            rate_limited: array::from_fn(|_| AtomicU64::new(0)),
            queue_full: array::from_fn(|_| AtomicU64::new(0)),
            disconnected: array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn record_sent(&self, kind: DataplaneEventKind) {
        self.sent[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    fn record_drop(&self, kind: DataplaneEventKind, reason: DataplaneEventDropReason) {
        let counters = match reason {
            DataplaneEventDropReason::RateLimited => &self.rate_limited,
            DataplaneEventDropReason::QueueFull => &self.queue_full,
            DataplaneEventDropReason::Disconnected => &self.disconnected,
        };
        counters[kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self) -> DataplaneEventStats {
        DataplaneEventStats {
            policy_deny: self.kind_snapshot(DataplaneEventKind::PolicyDeny),
            screen_drop: self.kind_snapshot(DataplaneEventKind::ScreenDrop),
            filter_log: self.kind_snapshot(DataplaneEventKind::FilterLog),
            session_close: self.kind_snapshot(DataplaneEventKind::SessionClose),
            session_create: self.kind_snapshot(DataplaneEventKind::SessionCreate),
        }
    }

    fn kind_snapshot(&self, kind: DataplaneEventKind) -> DataplaneEventKindStats {
        let idx = kind_index(kind);
        let rate_limited = self.rate_limited[idx].load(Ordering::Relaxed);
        let queue_full = self.queue_full[idx].load(Ordering::Relaxed);
        let disconnected = self.disconnected[idx].load(Ordering::Relaxed);
        DataplaneEventKindStats {
            sent: self.sent[idx].load(Ordering::Relaxed),
            dropped: rate_limited
                .saturating_add(queue_full)
                .saturating_add(disconnected),
            rate_limited,
            queue_full,
            disconnected,
        }
    }
}

impl EventStreamWorkerHandle {
    /// Fixed-size, non-blocking dataplane telemetry emission.
    ///
    /// `now_ns` is a caller-supplied monotonic timestamp used only for rate
    /// limiting; `event.timestamp_ns` remains the on-wire event timestamp.
    pub(crate) fn try_emit_dataplane_event_at(
        &self,
        event: DataplaneEventPayload,
        now_ns: u64,
    ) -> DataplaneEventEmitOutcome {
        let kind = event.kind;
        let ingress_zone_id = event.ingress_zone_id;
        self.try_emit_dataplane_frame(kind, ingress_zone_id, now_ns, |seq| {
            EventFrame::encode_dataplane_event(seq, &event)
        })
    }

    /// #2512: shared budget path for an already-shaped dataplane-event frame.
    ///
    /// Runs the SAME per-kind/per-ingress-zone rate limiter, queue-budget
    /// reservation, and sent/dropped counters as `try_emit_dataplane_event_at`
    /// but lets the caller supply its own frame encoder (the RT_FLOW
    /// session-close/create frames have a distinct payload layout from the
    /// generic deny/screen/filter frame). The sequence number is allocated
    /// only AFTER the limiter and budget pass, matching the generic path, so a
    /// rate-limited or budget-exhausted close/create never burns a seq. The
    /// frame's msg_type byte MUST map back to `kind` via
    /// `DataplaneEventKind::from_msg_type` so the I/O thread releases the
    /// per-kind budget when the frame leaves the channel.
    pub(crate) fn try_emit_dataplane_frame<F>(
        &self,
        kind: DataplaneEventKind,
        ingress_zone_id: u16,
        now_ns: u64,
        encode: F,
    ) -> DataplaneEventEmitOutcome
    where
        F: FnOnce(u64) -> EventFrame,
    {
        if !self
            .shared
            .dataplane_event_limiter
            .allow_at(kind, ingress_zone_id, now_ns)
        {
            self.shared
                .dataplane_event_counters
                .record_drop(kind, DataplaneEventDropReason::RateLimited);
            self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
            return DataplaneEventEmitOutcome::Dropped {
                reason: DataplaneEventDropReason::RateLimited,
            };
        }

        if !self.shared.dataplane_event_queue.try_acquire(kind) {
            self.shared
                .dataplane_event_counters
                .record_drop(kind, DataplaneEventDropReason::QueueFull);
            self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
            return DataplaneEventEmitOutcome::Dropped {
                reason: DataplaneEventDropReason::QueueFull,
            };
        }

        // #3878: allocate the seq and enqueue the frame atomically under the
        // producer lock so wire order == seq order across producers (F-152),
        // and roll the seq back on a full-channel drop so a saturation drop
        // never burns a seq into a reader-visible gap (F-153). The rate-limit
        // and queue-budget gates above stay lock-free and still refuse before
        // any seq is allocated.
        match self.send_sequenced(encode) {
            Ok(seq) => {
                self.shared.dataplane_event_counters.record_sent(kind);
                DataplaneEventEmitOutcome::Queued { seq }
            }
            Err(err) => {
                self.shared.dataplane_event_queue.release(kind);
                let reason = match err {
                    EventStreamSendError::Full => DataplaneEventDropReason::QueueFull,
                    EventStreamSendError::Disconnected => DataplaneEventDropReason::Disconnected,
                };
                self.shared
                    .dataplane_event_counters
                    .record_drop(kind, reason);
                DataplaneEventEmitOutcome::Dropped { reason }
            }
        }
    }

    #[allow(dead_code)] // surfaced through EventStreamSender::stats for now
    pub(crate) fn dataplane_event_stats(&self) -> DataplaneEventStats {
        self.shared.dataplane_event_counters.snapshot()
    }
}

fn kind_index(kind: DataplaneEventKind) -> usize {
    match kind {
        DataplaneEventKind::PolicyDeny => 0,
        DataplaneEventKind::ScreenDrop => 1,
        DataplaneEventKind::FilterLog => 2,
        DataplaneEventKind::SessionClose => 3,
        DataplaneEventKind::SessionCreate => 4,
    }
}

fn rate_bucket_index(kind: DataplaneEventKind, ingress_zone_id: u16) -> usize {
    // #3075: FOLD the zone id into the bucket space (modulo) rather than
    // CLAMP it. Stable name-hash zone ids span [1,65533]; a `min(255)`
    // clamp collapsed ~99.6% of zones into the single last bucket, losing
    // the per-zone isolation of this HA-delta flood limiter. `% 256`
    // spreads distinct ids across all buckets (collisions are possible but
    // graceful — two zones sharing a rate bucket, not all zones sharing one).
    let zone_bucket = usize::from(ingress_zone_id) % DATAPLANE_EVENT_ZONE_BUCKETS;
    kind_index(kind) * DATAPLANE_EVENT_ZONE_BUCKETS + zone_bucket
}

fn try_increment_below(counter: &AtomicU64, limit: u64) -> bool {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current >= limit {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// #1826 (#1663 finding 1.11): release-visible invariant-violation counter
/// for the queue-budget underflow guard in `decrement_if_positive`. The
/// `debug_assert!` below is compiled out in release builds, so without
/// this the violation (saturate-at-0 + continue) is invisible in
/// production. Local-only diagnostic — intentionally NOT plumbed into the
/// wire status protocol; read via the first-hit stderr line.
static DATAPLANE_EVENT_BUDGET_UNDERFLOWS: AtomicU64 = AtomicU64::new(0);

fn decrement_if_positive(counter: &AtomicU64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current == 0 {
            debug_assert!(false, "dataplane event queue budget underflow");
            // Cold path: never taken unless the accounting invariant is
            // already broken. First hit logs once to journald (stderr).
            if DATAPLANE_EVENT_BUDGET_UNDERFLOWS.fetch_add(1, Ordering::Relaxed) == 0 {
                eprintln!(
                    "xpf-userspace-dp: invariant violation: dataplane event \
                     queue budget underflow (local counter only)"
                );
            }
            return;
        }
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

#[cfg(test)]
#[path = "producer_tests.rs"]
mod tests;
