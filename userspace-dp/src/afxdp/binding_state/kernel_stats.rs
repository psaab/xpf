// #9168: publish the kernel's AF_XDP socket statistics into the per-binding
// atomics the status/monitor chain already reads.
//
// THE DEFECT THIS CLOSES. `kernel_rx_dropped` and `kernel_rx_invalid_descs`
// were plumbed end to end — atomics here, snapshot fields, wire encoding, Go
// decode, and the `Kernel RX dropped:` / `Kernel RX invalid:` lines in
// `pkg/monitoriface/monitor.go` — and NOTHING ever wrote the producer end. The
// worker loop sampled `statistics_v2()` once per second per binding and stored
// exactly one of the six counters it returns, discarding the rest. So an
// operator saw a permanent hard `0` on both lines: the value that is
// indistinguishable from healthy, on the instrument that exists to reveal a
// NIC dropping every packet. That is the observability form of a fail-open.
//
// WHY THIS IS A DESTRUCTURE AND NOT THREE `store` CALLS AT THE SAMPLE SITE.
// The defect was a field with a complete consumer and no producer, and nothing
// could have caught it: a consumer test passes on a hard zero, and a producer
// that simply forgets a field compiles. An exhaustive destructure of
// `XdpStatisticsV2` makes forgetting one a COMPILE ERROR — a field added to
// the kernel-statistics struct cannot reach the wire unwritten, because it
// cannot reach this function unnamed.
//
// #15285: `rx_ring_full` joins the plumbed set. The kernel distinguishes it
// from `rx_dropped` (if_xdp.h), but the publisher discarded it, so
// "Kernel RX dropped: 0" could not establish zero ring-full loss — the
// suspected silent micro-drop point for -P12 retransmit bursts. It is now
// carried per binding/queue as `kernel_rx_ring_full` through snapshot, wire,
// Go decode, status/monitor, and the
// `xpf_userspace_binding_kernel_rx_ring_full_total` counter metric.

use super::BindingLiveState;
use crate::xsk_ffi::XdpStatisticsV2;
use std::sync::atomic::Ordering;

impl BindingLiveState {
    /// Publish one `statistics_v2()` sample into the per-binding atomics.
    ///
    /// Kernel XDP statistics are ABSOLUTE (kernel-cumulative per socket), so
    /// every field is published with `store()` and not `fetch_add()` — the
    /// same contract `rx_fill_ring_empty_descs` has carried since #802. A
    /// sampling failure is handled by the caller simply not calling: the
    /// atomics retain their last good value rather than reporting a zero.
    ///
    /// PLUMBED, in the order the kernel struct declares them:
    ///   - `rx_dropped`               -> `kernel_rx_dropped`
    ///   - `rx_invalid_descs`         -> `kernel_rx_invalid_descs`
    ///   - `rx_ring_full`             -> `kernel_rx_ring_full` (#15285)
    ///   - `rx_fill_ring_empty_descs` -> `rx_fill_ring_empty_descs`
    ///
    /// NOT PLUMBED, deliberately, and named here so the omission is a decision
    /// rather than an oversight — `tx_invalid_descs` and
    /// `tx_ring_empty_descs` have no `BindingLiveState` atomic, no snapshot
    /// field, no wire field and no reader anywhere in the tree. Adding them is
    /// a WIRE change (new `BindingLiveSnapshot` fields crossing the Go/Rust
    /// protocol boundary), not a store, and a counter with no reader is the
    /// same as no counter. They are absent from the operator's view rather
    /// than present and permanently zero, which is the honest failure of the
    /// two this function exists to fix.
    ///
    /// `kernel_stats_9168_tests.rs` holds this list to the source: it reads
    /// the destructure below and asserts every BOUND name is stored and every
    /// `_`-dropped name appears in `UNPLUMBED_KERNEL_STAT_FIELDS`. Prose can
    /// go stale; that pair cannot.
    pub(in crate::afxdp) fn publish_kernel_xdp_statistics(&self, stats: XdpStatisticsV2) {
        // Exhaustive by construction: a new field on `XdpStatisticsV2` breaks
        // this binding and forces a decision at the one site that could
        // otherwise silently drop it.
        let XdpStatisticsV2 {
            rx_dropped,
            rx_invalid_descs,
            tx_invalid_descs: _,
            rx_ring_full,
            rx_fill_ring_empty_descs,
            tx_ring_empty_descs: _,
        } = stats;
        self.kernel_rx_dropped.store(rx_dropped, Ordering::Relaxed);
        self.kernel_rx_invalid_descs
            .store(rx_invalid_descs, Ordering::Relaxed);
        self.kernel_rx_ring_full
            .store(rx_ring_full, Ordering::Relaxed);
        self.rx_fill_ring_empty_descs
            .store(rx_fill_ring_empty_descs, Ordering::Relaxed);
    }
}

/// The `XdpStatisticsV2` fields deliberately dropped by
/// `publish_kernel_xdp_statistics` — no `BindingLiveState` atomic, no snapshot
/// field, no wire field, no reader.
///
/// This is the machine-readable half of the doc comment above, and it exists
/// so the omission is CHECKED rather than described: the #9168 guard asserts
/// that the set of `_`-bound names in the destructure is exactly this list, so
/// silently dropping a third field reds a cell instead of reading as a
/// decision somebody made.
#[cfg(test)]
pub(in crate::afxdp) const UNPLUMBED_KERNEL_STAT_FIELDS: [&str; 2] =
    ["tx_invalid_descs", "tx_ring_empty_descs"];
