// Shared pacing rationale and limits for the worker loop's extracted slices.
//
// #9856 owner-RG CommandExport visits one bounded slice per worker-loop pass,
// interleaving RX/TX/heartbeat. The scan budget caps slab slots visited; the
// emit cap limits conversions and sizes `export_echo_scratch`; the deadline
// bounds the slice's work.
pub(super) const EXPORT_SLICE_BUDGET: usize = 1024; // max slab slots scanned per slice
pub(super) const EXPORT_SLICE_EMITS: usize = 256; // max sessions converted per slice
pub(super) const EXPORT_SLICE_DEADLINE_NS: u64 = 500_000; // 500us slice cap
// The pre-sized echo scratch must hold every session that one slice can emit.
const _: () = assert!(EXPORT_SLICE_EMITS <= EXPORT_SLICE_BUDGET);

// #333/#5287: refresh BPF conntrack last_seen values incrementally so session
// idle-time and volume reads stay current without a per-second syscall per
// session. A full-table sweep near the 131072-entry cap used to issue tens of
// thousands of synchronous BPF lookups and updates between RX/TX polls.
// Bound each slice by CT_REFRESH_SLICE_BUDGET and pace slices by
// CT_SLICE_INTERVAL_NS; full cycles target CT_REFRESH_WINDOW_NS, preserving the
// old 10s steady-state cadence. With the default cap, 2048 slots per 100ms
// complete in about 64 slices (~6.4s <= 10s). If max_sessions rises much higher,
// freshness degrades gracefully while per-slice cost stays bounded.
pub(super) const CT_REFRESH_WINDOW_NS: u64 = 10_000_000_000; // full-table freshness target
pub(super) const CT_SLICE_INTERVAL_NS: u64 = 100_000_000; // 100ms between slices
pub(super) const CT_REFRESH_SLICE_BUDGET: usize = 2048; // max slab slots per slice
// #18655: the ct-slice shared-evidence leg (`run_shared_evidence_leg`) runs
// once per refresh cycle, on the cycle's first slice. A pair that completes
// right after that slice has its shared stage advanced at the next cycle start,
// which is at most
//     max(CT_REFRESH_WINDOW_NS, ceil(slab / CT_REFRESH_SLICE_BUDGET) * CT_SLICE_INTERVAL_NS)
// later. At the default cap that is the 10 s window. It must stay inside the
// 20 s TCP opening window, because sibling replicas still marked Opening/Pending
// are reaped on that window, and #16223 exists to stop reaping live pairs. A cap
// increase that pushes a full cycle past the window, or a window at or over the
// opening timeout, would quietly reopen those reaps, so it fails the build here.
// (A larger runtime `max_sessions` than the default is not covered by this
// compile-time check. Freshness then degrades as the comment above describes.)
const _: () = assert!(
    (crate::session::DEFAULT_MAX_SESSIONS.div_ceil(CT_REFRESH_SLICE_BUDGET) as u64)
        * CT_SLICE_INTERVAL_NS
        <= CT_REFRESH_WINDOW_NS
        && CT_REFRESH_WINDOW_NS < crate::session::DEFAULT_TCP_OPENING_TIMEOUT_NS
);
