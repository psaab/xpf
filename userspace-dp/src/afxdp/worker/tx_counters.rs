//! #959 Phase 4 — extracts the per-binding `pending_*_tx_*` and
//! `pending_direct_tx_*_fallback_*` packet counters out of
//! `BindingWorker` into a dedicated `WorkerTxCounters` sub-struct.
//!
//! These six counters track the disposition of TX-bound packets
//! (direct, copy, in-place) and the three fallback paths the direct
//! TX engine takes when the fast-path is unavailable. They're
//! incremented from the descriptor loop and the TX dispatch
//! pipeline, then drained to the `BindingLiveState` atomics on the
//! per-second debug tick.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-4. Field names preserved so the
//! `binding.tx_counters.pending_*_tx_*` access pattern keeps the
//! same grep-friendly suffix as the original
//! `binding.pending_*_tx_*`.

use crate::afxdp::types::InPlaceL2Rewrite;

/// Per-binding TX-disposition packet counters. Drained on the
/// per-second debug tick into `BindingLiveState` atomic mirrors.
///
/// **Intentionally NOT `Default`** — for consistency with the
/// `WorkerScratch` (#1168) and `WorkerCos` (#1169) decomposition
/// pattern. Only legal construction is the explicit literal in
/// `BindingWorker::create`.
pub(crate) struct WorkerTxCounters {
    pub(crate) pending_direct_tx_packets: u64,
    pub(crate) pending_copy_tx_packets: u64,
    pub(crate) pending_in_place_tx_packets: u64,
    pub(crate) pending_in_place_vlan_push_desc_packets: u64,
    pub(crate) pending_in_place_vlan_pop_desc_packets: u64,
    pub(crate) pending_in_place_vlan_push_no_headroom_packets: u64,
    pub(crate) pending_in_place_l2_memmove_fallback_packets: u64,
    pub(crate) pending_direct_tx_no_frame_fallback_packets: u64,
    pub(crate) pending_direct_tx_build_fallback_packets: u64,
    pub(crate) pending_direct_tx_disallowed_fallback_packets: u64,
}

impl WorkerTxCounters {
    #[inline]
    pub(in crate::afxdp) fn record_in_place_l2_rewrite(&mut self, rewrite: InPlaceL2Rewrite) {
        match rewrite {
            InPlaceL2Rewrite::SameLength => {}
            InPlaceL2Rewrite::VlanPushDescriptor => {
                self.pending_in_place_vlan_push_desc_packets += 1;
            }
            InPlaceL2Rewrite::VlanPopDescriptor => {
                self.pending_in_place_vlan_pop_desc_packets += 1;
            }
            InPlaceL2Rewrite::VlanPushMemmoveNoHeadroom => {
                self.pending_in_place_vlan_push_no_headroom_packets += 1;
            }
            InPlaceL2Rewrite::UnsupportedMemmove => {
                self.pending_in_place_l2_memmove_fallback_packets += 1;
            }
        }
    }
}
