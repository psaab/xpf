use super::*;

mod fast_path;
mod resolver;

pub(in crate::afxdp) use fast_path::{
    enqueue_admitted_mirror_clone_to_live, enqueue_sampled_mirror_clone,
};
// `enqueue_mirror_clone`, `enqueue_mirror_clone_to_live`, and
// `enqueue_sampled_mirror_clone_to_live` are reachable from `crate::afxdp` but
// are dead in non-test builds (the live/cross-worker fallbacks are exercised by
// tests and conditional call sites). The functions themselves carry
// `#[cfg_attr(not(test), allow(dead_code))]`; suppress the matching re-export
// lint here, mirroring the monolithic mirror.rs glob visibility.
#[cfg_attr(not(test), allow(unused_imports))]
pub(in crate::afxdp) use fast_path::{
    enqueue_mirror_clone, enqueue_mirror_clone_to_live, enqueue_sampled_mirror_clone_to_live,
};
pub(in crate::afxdp) use resolver::{
    admit_mirror_clone_to_live, mirror_cos_queue_id, mirror_output_filter_drops,
    record_mirror_clone_result, sample_then_admit_mirror_clone, MirrorSampleAdmission,
};
// Sibling-only helper (mirror-module-internal). A plain (private) `use` keeps
// it out of the wider `crate::afxdp` surface while still letting the fast
// path's `use super::*` resolve it across the split (children see parent-
// private items). `pub(super) use` of a `pub(super)` item would trip E0364,
// the same constraint documented in tx/mod.rs.
use resolver::mirror_target_binding_index;

pub(in crate::afxdp) const MIRROR_TX_FRAME_RESERVE: usize = TX_BATCH_SIZE;
const MIRROR_PENDING_LIMIT: usize = TX_BATCH_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum MirrorCloneResult {
    Enqueued,
    OutputFiltered,
    NoBinding,
    NoFrame,
    TxFrameReserve,
    QueueFullSameWorker,
    QueueFullCrossWorker,
}

#[inline]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::afxdp) fn select_mirror_config(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    sample_counter: &mut u64,
) -> Option<MirrorRuntimeConfig> {
    let config = resolve_mirror_config(forwarding, ingress_ifindex, ingress_vlan_id)?;
    mirror_sample_allows(config.rate, sample_counter).then_some(config)
}

#[inline]
pub(in crate::afxdp) fn resolve_mirror_config(
    forwarding: &ForwardingState,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
) -> Option<MirrorRuntimeConfig> {
    let logical_ifindex =
        resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, ingress_vlan_id)
            .filter(|ifindex| *ifindex > 0)
            .unwrap_or(ingress_ifindex);
    forwarding
        .mirror_configs
        .get(&logical_ifindex)
        .or_else(|| forwarding.mirror_configs.get(&ingress_ifindex))
        .copied()
}

#[inline]
pub(in crate::afxdp) fn mirror_sample_allows(rate: u32, sample_counter: &mut u64) -> bool {
    if rate <= 1 {
        return true;
    }
    let current = *sample_counter;
    *sample_counter = sample_counter.wrapping_add(1);
    let rate = u64::from(rate);
    if rate.is_power_of_two() {
        current & (rate - 1) == 0
    } else {
        current % rate == 0
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
