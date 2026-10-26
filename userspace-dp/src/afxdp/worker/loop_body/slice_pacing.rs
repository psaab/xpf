// Single source for the pacing limits shared by worker_loop and its extracted slices.
pub(super) const EXPORT_SLICE_BUDGET: usize = 1024; // max slab slots scanned per slice
pub(super) const EXPORT_SLICE_EMITS: usize = 256; // max sessions converted per slice
pub(super) const EXPORT_SLICE_DEADLINE_NS: u64 = 500_000; // 500us slice cap

pub(super) const CT_REFRESH_WINDOW_NS: u64 = 10_000_000_000; // full-table freshness target
pub(super) const CT_SLICE_INTERVAL_NS: u64 = 100_000_000; // 100ms between slices
pub(super) const CT_REFRESH_SLICE_BUDGET: usize = 2048; // max slab slots per slice
