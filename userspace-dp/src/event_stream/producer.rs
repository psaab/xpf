#![allow(dead_code)] // producer call sites are intentionally wired in later slices

use super::codec::{DataplaneEventKind, DataplaneEventPayload};
use super::{EventFrame, EventStreamSendError, EventStreamWorkerHandle};
use std::array;
use std::sync::atomic::{AtomicU64, Ordering};

const DATAPLANE_EVENT_KIND_COUNT: usize = 3;
const DATAPLANE_EVENT_ZONE_BUCKETS: usize = 256;
const DATAPLANE_EVENT_RATE_BUCKETS: usize =
    DATAPLANE_EVENT_KIND_COUNT * DATAPLANE_EVENT_ZONE_BUCKETS;
const NS_PER_SEC: u64 = 1_000_000_000;

const DEFAULT_DATAPLANE_EVENT_RATE_PER_SEC: u64 = 1_000;
const DEFAULT_DATAPLANE_EVENT_BURST: u64 = 1_024;

/// Per-kind/per-source-zone rate-limit configuration for dataplane telemetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DataplaneEventRateLimitConfig {
    /// Sustained event rate per `(event kind, ingress zone)` bucket. Zero
    /// disables limiting for tests and emergency builds.
    pub(crate) events_per_second: u64,
    /// Instantaneous burst per `(event kind, ingress zone)` bucket.
    pub(crate) burst: u64,
}

impl Default for DataplaneEventRateLimitConfig {
    fn default() -> Self {
        Self {
            events_per_second: DEFAULT_DATAPLANE_EVENT_RATE_PER_SEC,
            burst: DEFAULT_DATAPLANE_EVENT_BURST,
        }
    }
}

impl DataplaneEventRateLimitConfig {
    fn unlimited(self) -> bool {
        self.events_per_second == 0
    }

    fn interval_ns(self) -> u64 {
        if self.unlimited() {
            return 0;
        }
        NS_PER_SEC
            .saturating_add(self.events_per_second.saturating_sub(1))
            .saturating_div(self.events_per_second)
            .max(1)
    }

    fn burst_horizon_ns(self) -> u64 {
        let burst = self.burst.max(1);
        self.interval_ns().saturating_mul(burst.saturating_sub(1))
    }
}

#[derive(Default)]
struct DataplaneEventRateBucket {
    theoretical_arrival_ns: AtomicU64,
}

impl DataplaneEventRateBucket {
    fn allow_at(&self, config: DataplaneEventRateLimitConfig, now_ns: u64) -> bool {
        if config.unlimited() {
            return true;
        }

        // GCRA form of a token bucket: one atomic TAT gives fixed memory,
        // no locks, and no per-packet heap work on the producer path.
        let interval_ns = config.interval_ns();
        let burst_horizon_ns = config.burst_horizon_ns();
        let mut tat = self.theoretical_arrival_ns.load(Ordering::Relaxed);
        loop {
            if tat.saturating_sub(burst_horizon_ns) > now_ns {
                return false;
            }
            let next_tat = tat.max(now_ns).saturating_add(interval_ns);
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
    config: DataplaneEventRateLimitConfig,
    buckets: [DataplaneEventRateBucket; DATAPLANE_EVENT_RATE_BUCKETS],
}

impl DataplaneEventRateLimiter {
    pub(super) fn new(config: DataplaneEventRateLimitConfig) -> Self {
        Self {
            config,
            buckets: array::from_fn(|_| DataplaneEventRateBucket::default()),
        }
    }

    fn allow_at(&self, kind: DataplaneEventKind, ingress_zone_id: u16, now_ns: u64) -> bool {
        self.buckets[rate_bucket_index(kind, ingress_zone_id)].allow_at(self.config, now_ns)
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
        if !self
            .shared
            .dataplane_event_limiter
            .allow_at(kind, event.ingress_zone_id, now_ns)
        {
            self.shared
                .dataplane_event_counters
                .record_drop(kind, DataplaneEventDropReason::RateLimited);
            self.shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
            return DataplaneEventEmitOutcome::Dropped {
                reason: DataplaneEventDropReason::RateLimited,
            };
        }

        let seq = self.next_seq();
        let frame = EventFrame::encode_dataplane_event(seq, &event);
        match self.try_send_frame(frame) {
            Ok(()) => {
                self.shared.dataplane_event_counters.record_sent(kind);
                DataplaneEventEmitOutcome::Queued { seq }
            }
            Err(EventStreamSendError::Full) => {
                self.shared
                    .dataplane_event_counters
                    .record_drop(kind, DataplaneEventDropReason::QueueFull);
                DataplaneEventEmitOutcome::Dropped {
                    reason: DataplaneEventDropReason::QueueFull,
                }
            }
            Err(EventStreamSendError::Disconnected) => {
                self.shared
                    .dataplane_event_counters
                    .record_drop(kind, DataplaneEventDropReason::Disconnected);
                DataplaneEventEmitOutcome::Dropped {
                    reason: DataplaneEventDropReason::Disconnected,
                }
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
    }
}

fn rate_bucket_index(kind: DataplaneEventKind, ingress_zone_id: u16) -> usize {
    let zone_bucket = usize::from(ingress_zone_id).min(DATAPLANE_EVENT_ZONE_BUCKETS - 1);
    kind_index(kind) * DATAPLANE_EVENT_ZONE_BUCKETS + zone_bucket
}

#[cfg(test)]
#[path = "producer_tests.rs"]
mod tests;
