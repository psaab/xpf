// Per-binding telemetry counters: TX/RX latency histograms, drain
// invocation counts, redirect-acquire histograms, owner/peer pps.
// Single-writer (owner worker) for `OwnerProfileOwnerWrites`;
// peer-writer for `OwnerProfilePeerWrites` (cross-binding redirect
// completion path). All stats use `Ordering::Relaxed`.

use std::sync::atomic::AtomicU64;

use super::{DRAIN_HIST_BUCKETS, TX_BATCH_BUCKETS, TX_SUBMIT_LAT_BUCKETS};

#[repr(align(64))]
pub(in crate::afxdp) struct OwnerProfileOwnerWrites {
    pub(in crate::afxdp) drain_latency_hist: [AtomicU64; DRAIN_HIST_BUCKETS],
    pub(in crate::afxdp) drain_invocations: AtomicU64,
    pub(in crate::afxdp) drain_noop_invocations: AtomicU64,
    /// #812: per-queue submit→completion latency histogram. Bucket
    /// layout is shared with `drain_latency_hist` via
    /// `bucket_index_for_ns`; see `TX_SUBMIT_LAT_BUCKETS` for the
    /// wire-contract const-asserts. The histogram is written only
    /// by the owner worker's `reap_tx_completions` site (plan §3.1
    /// completion-ts site) — single-writer, so `Relaxed` atomics on
    /// writer AND reader are sufficient; the snapshot path documents
    /// the bounded read-skew semantics at plan §3.6 R2 and mirrors
    /// the existing `drain_latency_hist` pattern at
    /// `binding_state/snapshot.rs`.
    pub(in crate::afxdp) tx_submit_latency_hist: [AtomicU64; TX_SUBMIT_LAT_BUCKETS],
    /// #812: count of completions observed since process start (the
    /// histogram is monotonic, never reset on snapshot — plan §3.6).
    /// Within a single-threaded unit test this equals
    /// `sum(tx_submit_latency_hist)` exactly; across threads the
    /// relation is `|sum - count| ≤ K_skew` per plan §3.6 R2
    /// (K_skew = 3 at λ = 3 Mpps and W_read ≤ 1 µs). Unstamped
    /// completions (plan §5.4) bump neither this counter nor the
    /// histogram.
    pub(in crate::afxdp) tx_submit_latency_count: AtomicU64,
    /// #812: running sum of observed completion-minus-submit deltas
    /// in nanoseconds. Paired with `tx_submit_latency_count` yields a
    /// discretization-free mean without reconstructing it from
    /// per-bucket midpoints (plan §12 item 10). `saturating_add` is
    /// not used — we accept wraparound at ~584 years of accumulated
    /// monotonic delta time, which is beyond any deployment
    /// lifetime.
    pub(in crate::afxdp) tx_submit_latency_sum_ns: AtomicU64,
    /// #825: per-kick `sendto` latency histogram. Bucket layout is
    /// shared with `tx_submit_latency_hist` / `drain_latency_hist`
    /// via `bucket_index_for_ns`; see `TX_SUBMIT_LAT_BUCKETS` for
    /// the wire-contract const-asserts. The histogram is written
    /// only by the owner worker's `maybe_wake_tx` site (plan §3.3
    /// site 1) — single-writer, so `Relaxed` atomics on writer AND
    /// reader are sufficient; the snapshot path documents the
    /// bounded read-skew semantics at plan §4 and mirrors the
    /// existing `tx_submit_latency_hist` pattern.
    pub(in crate::afxdp) tx_kick_latency_hist: [AtomicU64; TX_SUBMIT_LAT_BUCKETS],
    /// #825: count of `sendto` kicks observed (whether EAGAIN or
    /// not). Within a single-threaded unit test this equals
    /// `sum(tx_kick_latency_hist)` exactly; across threads the
    /// relation is `|sum - count| ≤ K_skew` per plan §4 (K_skew
    /// inherited from #812's bound as a conservative upper bound
    /// — kicks occur strictly less frequently than completions).
    pub(in crate::afxdp) tx_kick_latency_count: AtomicU64,
    /// #825: running sum of kick latencies in nanoseconds. Paired
    /// with `tx_kick_latency_count` yields a discretization-free
    /// mean of the per-kick `sendto` syscall cost.
    pub(in crate::afxdp) tx_kick_latency_sum_ns: AtomicU64,
    /// #825: count of `sendto` returns where `errno ∈
    /// {EAGAIN, EWOULDBLOCK}` — the semantic "ring pushed back"
    /// signal that T1 (#819 §4.1) keys off. Parallel to
    /// `binding.dbg_sendto_eagain` (worker-local debug-tick
    /// counter), but surfaced on the `BindingLiveSnapshot` so it
    /// reaches the operator-facing protocol.
    pub(in crate::afxdp) tx_kick_retry_count: AtomicU64,
    /// #16242: descriptors-per-commit histogram (see
    /// `TX_BATCH_BUCKETS` for the layout). Written once per TX-ring
    /// `writer.commit()` with `inserted > 0` by `record_tx_commit` —
    /// single-writer (owner worker), `Relaxed` like the latency
    /// histograms above. `sum(tx_batch_hist)` equals
    /// `tx_batch_commits` single-threaded; the descriptor total is
    /// `tx_batch_descriptors`, so the mean batch is
    /// `descriptors / commits` and the full-batch share is
    /// `tx_batch_hist[10] / tx_batch_commits`.
    pub(in crate::afxdp) tx_batch_hist: [AtomicU64; TX_BATCH_BUCKETS],
    /// #16242: number of TX-ring commits with `inserted > 0`.
    pub(in crate::afxdp) tx_batch_commits: AtomicU64,
    /// #16242: total descriptors across those commits.
    pub(in crate::afxdp) tx_batch_descriptors: AtomicU64,
    /// #16242: per-kick descriptor histogram — same bucket layout,
    /// sampled in `maybe_wake_tx` as the descriptors committed since
    /// the previous actual `sendto` kick on this binding. This is the
    /// per-kick view of the same commits: a kick that follows no new
    /// commit records nothing (it carries no batch-depth signal), so
    /// `sum(tx_kick_batch_hist) <= tx_batch_commits`.
    pub(in crate::afxdp) tx_kick_batch_hist: [AtomicU64; TX_BATCH_BUCKETS],
    /// #16242: kicks that carried at least one newly-committed
    /// descriptor (`sum(tx_kick_batch_hist)` single-threaded).
    pub(in crate::afxdp) tx_kick_batch_kicks: AtomicU64,
    /// #16242: descriptors attributed to those kicks; equals
    /// `tx_batch_descriptors` once every commit has been kicked.
    pub(in crate::afxdp) tx_kick_batch_descriptors: AtomicU64,
    /// #709: owner-local pps window. Formerly `pps_owner_vs_peer[0]`;
    /// split by writer for cacheline isolation (#746). The owner is
    /// the only writer; peers read through `snapshot()`.
    pub(in crate::afxdp) owner_pps: AtomicU64,
    /// #760 instrumentation (Codex adversarial review, PR #773):
    /// moved here from `BindingLiveState` so owner-only writes
    /// don't ping-pong on the cacheline that holds multi-writer
    /// `redirect_inbox_overflow_drops`.
    ///
    /// Bytes observed at the three `apply_*` tx_bytes sites,
    /// incremented unconditionally. Sum of this + `post_drain_backup_bytes`
    /// equals `tx_bytes` on the shaped path. Gap vs the per-queue
    /// `drain_sent_bytes` reveals apply_* queue-miss bytes.
    ///
    /// Read skew note (Codex adversarial review, PR #773): these
    /// three atomics (`tx_bytes`, `drain_sent_bytes_shaped_unconditional`,
    /// `post_drain_backup_bytes`) are written at separate sites
    /// and loaded at separate scrape instants. A snapshot that
    /// lands between the `tx_bytes.fetch_add` and the companion
    /// `fetch_add` will show a transient "bypass gap" that is
    /// pure read skew, not a real bypass event. Interpret these
    /// as DELTA-OVER-WINDOW diagnostics rather than point-in-
    /// time equalities. The window needs to span many cache-line
    /// writes (microseconds) to amortise the skew to negligible.
    pub(in crate::afxdp) drain_sent_bytes_shaped_unconditional: AtomicU64,
    /// #760 instrumentation. Bytes delivered by the post-CoS
    /// backup transmit paths in `drain_pending_tx`
    /// (transmit_prepared_batch + transmit_batch). Post-fix (PR
    /// #773) this reflects non-CoS traffic only; CoS-bound items
    /// are dropped before reaching those sites.
    pub(in crate::afxdp) post_drain_backup_bytes: AtomicU64,
    /// #760 (PR #773) drop-filter counters: items with
    /// `cos_queue_id.is_some()` that reached the post-drain
    /// backup paths and were dropped instead of transmitted
    /// unshaped. Non-zero indicates a cross-worker routing
    /// failure that the bounded ingest-drain loop did not
    /// absorb.
    pub(in crate::afxdp) post_drain_backup_cos_drops: AtomicU64,
    pub(in crate::afxdp) post_drain_backup_cos_drop_bytes: AtomicU64,
}

/// #746: peer-worker-written owner-profile telemetry. Every redirecting
/// worker is a writer of these atomics. Isolated onto its own 64-byte
/// cacheline so peer writes do not invalidate the owner's cacheline
/// (see `OwnerProfileOwnerWrites`) and so the sampled-op histogram
/// writes do not ping-pong unrelated `BindingLiveState` fields.
///
/// The owner reads the peer-written counters only via `snapshot()`;
/// there is no owner-write path into this struct.
///
/// #5160: the redirect-sample SEQUENCE counter is NOT here — it moved to a
/// producer-local thread-local (`REDIRECT_SAMPLE_SEQ`, binding_state/latency.rs) so the
/// many-producer redirect hot path pays no shared RMW per enqueue. Only the
/// sampled op writes `redirect_acquire_hist` (the destination's aggregate).
#[repr(align(64))]
pub(in crate::afxdp) struct OwnerProfilePeerWrites {
    pub(in crate::afxdp) redirect_acquire_hist: [AtomicU64; DRAIN_HIST_BUCKETS],
    /// #709: peer-redirect pps window. Formerly `pps_owner_vs_peer[1]`;
    /// split by writer for cacheline isolation (#746). Any worker that
    /// redirects into this binding is a writer; the owner reads via
    /// `snapshot()`.
    pub(in crate::afxdp) peer_pps: AtomicU64,
}

// #746: compile-time layout enforcement. A silent drop of the
// `#[repr(align(64))]` attribute — or a future refactor that inlines
// a packed neighbor — is caught at build time, not at runtime.
const _: () = assert!(core::mem::align_of::<OwnerProfileOwnerWrites>() == 64);
const _: () = assert!(core::mem::align_of::<OwnerProfilePeerWrites>() == 64);
// Size ceiling. Pre-#812 owner struct shape: 16 drain hist + several
// scalar AtomicU64 (drain_invocations/noop/owner_pps/
// drain_sent_bytes_shaped_unconditional/post_drain_backup_bytes/
// post_drain_backup_cos_drops/post_drain_backup_cos_drop_bytes)
// = 128 + 56 = 184 B → 192 B padded (3 cachelines). #812 adds 16
// submit-latency hist atomics (128 B) + 2 scalars (count + sum_ns,
// 16 B) = 144 B more, landing the struct at 328 B → 384 B padded
// (6 cachelines). #825 adds 16 kick-latency hist atomics (128 B)
// + 3 scalars (count, sum_ns, retry_count; 24 B) = 152 B more,
// landing the struct at 480 B → 512 B padded (8 cachelines).
// #16242 adds 2×11 batch hist atomics (176 B) + 4 scalars (32 B) =
// 208 B more, landing at 688 B → 704 B padded (11 cachelines).
// Ceiling raised to 704 B. `#[repr(align(64))]` alignment invariant
// is unchanged — the separate align assert above still holds.
// Peer struct: 16 hist + 1 scalar AtomicU64 (peer_pps) = 136 B, padded
// to 192 B (#5160 dropped the shared redirect_sample_counter — now a
// producer-local thread-local, not a per-binding atomic).
const _: () = assert!(core::mem::size_of::<OwnerProfileOwnerWrites>() <= 704);
const _: () = assert!(core::mem::size_of::<OwnerProfilePeerWrites>() <= 320);

impl OwnerProfileOwnerWrites {
    /// Inline zero-init. `AtomicU64` is not `Copy`, so `[AtomicU64::new(0); N]`
    /// does not compile; `from_fn` builds the array inline on the caller's
    /// stack — no heap.
    #[inline]
    pub(super) fn new() -> Self {
        Self {
            drain_latency_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            drain_invocations: AtomicU64::new(0),
            drain_noop_invocations: AtomicU64::new(0),
            // #812: zero-init owner-written TX submit latency telemetry.
            tx_submit_latency_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            tx_submit_latency_count: AtomicU64::new(0),
            tx_submit_latency_sum_ns: AtomicU64::new(0),
            // #825: zero-init owner-written TX kick latency telemetry.
            tx_kick_latency_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            tx_kick_latency_count: AtomicU64::new(0),
            tx_kick_latency_sum_ns: AtomicU64::new(0),
            tx_kick_retry_count: AtomicU64::new(0),
            // #16242: zero-init descriptors-per-commit/kick telemetry.
            tx_batch_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            tx_batch_commits: AtomicU64::new(0),
            tx_batch_descriptors: AtomicU64::new(0),
            tx_kick_batch_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            tx_kick_batch_kicks: AtomicU64::new(0),
            tx_kick_batch_descriptors: AtomicU64::new(0),
            owner_pps: AtomicU64::new(0),
            drain_sent_bytes_shaped_unconditional: AtomicU64::new(0),
            post_drain_backup_bytes: AtomicU64::new(0),
            post_drain_backup_cos_drops: AtomicU64::new(0),
            post_drain_backup_cos_drop_bytes: AtomicU64::new(0),
        }
    }
}

impl OwnerProfilePeerWrites {
    #[inline]
    pub(super) fn new() -> Self {
        Self {
            redirect_acquire_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            peer_pps: AtomicU64::new(0),
        }
    }
}
