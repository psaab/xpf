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
/// #18662: fixed upper bound on rows advanced by the shared-evidence
/// worker-table cursor in one ct-slice. Stage/count indexed reads separately
/// cap map-lock row visits and combined lookup/fold work at 128 per chunk.
pub(super) const CT_EVIDENCE_CHUNK: usize = 2048;
/// Maximum interval between shared-evidence visits to a worker row.
/// The worker cursor advances `CT_EVIDENCE_CHUNK` slots on the first due
/// slice and each paced slice while work remains; a large slab stretches
/// the full sweep beyond its 10 s target.
pub(super) fn shared_evidence_max_cadence_ns(slab_len: usize) -> u64 {
    CT_REFRESH_WINDOW_NS.max(
        (slab_len.div_ceil(CT_EVIDENCE_CHUNK) as u64)
            .saturating_mul(CT_SLICE_INTERVAL_NS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_evidence_max_cadence_tracks_live_slab_18722() {
        assert_eq!(
            shared_evidence_max_cadence_ns(crate::session::DEFAULT_MAX_SESSIONS),
            CT_REFRESH_WINDOW_NS
        );
        assert_eq!(shared_evidence_max_cadence_ns(300_000), 14_700_000_000);
    }
}
// #18655/#18662: the shared-evidence leg runs on the first due slice and
// resumes on each paced slice while its worker cursor is nonzero, advancing
// at most CT_EVIDENCE_CHUNK slots. A row completing before its slot is visited
// may be advanced later in the current cycle; after its slot has passed, it
// waits for the next cycle. The maximum row-visit interval is
//     max(CT_REFRESH_WINDOW_NS, ceil(slab / CT_EVIDENCE_CHUNK) * CT_SLICE_INTERVAL_NS)
// which is 10 s at the default cap; HA imports can stretch it to about 13 s
// at the usual 2x population. Static asserts below guard the default-cap
// contract against the 20 s TCP opening window. Imports have no per-table cap,
// so production expiry also computes the current cycle from this same slab
// bound; a larger population receives a correspondingly longer short-window
// evidence grace instead of a hard-coded 13 s ceiling. The only hard import
// bound, #5674's shared-map ceiling, is looser; see #18687.
const _: () = assert!(
    (crate::session::DEFAULT_MAX_SESSIONS.div_ceil(CT_REFRESH_SLICE_BUDGET) as u64)
        * CT_SLICE_INTERVAL_NS
        <= CT_REFRESH_WINDOW_NS
        && CT_REFRESH_WINDOW_NS < crate::session::DEFAULT_TCP_OPENING_TIMEOUT_NS
);
const _: () = assert!(
    CT_REFRESH_WINDOW_NS <= crate::session::NODE_SERVED_EVIDENCE_DEFAULT_CADENCE_NS
        && 2 * (crate::session::DEFAULT_MAX_SESSIONS.div_ceil(CT_REFRESH_SLICE_BUDGET) as u64)
            * CT_SLICE_INTERVAL_NS
            <= crate::session::NODE_SERVED_EVIDENCE_DEFAULT_CADENCE_NS
);
