use super::*;

mod fast_path;
mod resolver;

pub(in crate::afxdp) use fast_path::{
    commit_staged_mirror_clone, enqueue_admitted_mirror_clone_to_live, snapshot_staged_mirror_clone, stage_sampled_mirror_clone,
};
// `enqueue_mirror_clone` and `enqueue_mirror_clone_to_live` are production-live
// (#17195: their false test-only labels are gone).
// `enqueue_sampled_mirror_clone_to_live` is dead in every build, so fast_path.rs
// gates it `#[cfg(test)]`; the re-export follows that gate (#17195).

#[cfg_attr(not(test), allow(unused_imports))]
pub(in crate::afxdp) use fast_path::{enqueue_mirror_clone, enqueue_mirror_clone_to_live};
#[cfg(test)]
pub(in crate::afxdp) use fast_path::enqueue_sampled_mirror_clone_to_live;
#[cfg(test)]
pub(in crate::afxdp) use fast_path::enqueue_sampled_mirror_clone;
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
#[cfg(test)]
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
    // #15113: a unit-scoped row matches only its own VID. It wins over
    // the bare fallback on the same bind port; a different VID must
    // not fall through to a unit-0 row keyed by the shared ifindex.
    // VID 0 also covers the native VID: ingress_logical resolution
    // maps native traffic to its unit, whose scoped row is keyed by
    // the parent bind ifindex here, so check both the raw and the
    // logical bind keys at VID 0 and at the packet VID.
    // #16063: a unit-scoped row whose (ifindex, VID) is shared by
    // sibling tunnel units is never published by the Go builder (it
    // refuses the input), so a scoped row here always keys a unit the
    // packet's VID + logical resolution can identify (VLAN units, unit
    // 0). Match the packet's unit when its logical ingress is a unit
    // row; otherwise fall through to the bare table only.
    let unit = forwarding
        .ingress_unit_by_logical
        .get(&logical_ifindex)
        .copied();
    if let Some(unit) = unit {
        if let Some(cfg) = forwarding
            .mirror_configs_scoped
            .get(&(ingress_ifindex, ingress_vlan_id, unit))
            .or_else(|| {
                forwarding
                    .mirror_configs_scoped
                    .get(&(logical_ifindex, ingress_vlan_id, unit))
            })
        {
            return Some(*cfg);
        }
    }
    // Scoped rows live only in the scoped map, so the bare fallback
    // below cannot return one: pre-fix the unit-0 row lived in the
    // bare map under the shared ifindex and captured every VID.
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
