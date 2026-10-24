// Per-binding lookup table split from forwarding.rs (#16209):
// BindingIdentity and WorkerBindingLookup. Pure code motion
// behind `forwarding/mod.rs`'s `use forwarding::*` glob; zero
// layout or access-site change. Visibility bill: no widening.

use super::super::*;

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct BindingIdentity {
    pub(in crate::afxdp) slot: u32,
    pub(in crate::afxdp) queue_id: u32,
    pub(in crate::afxdp) worker_id: u32,
    pub(in crate::afxdp) interface: Arc<str>,
    pub(in crate::afxdp) ifindex: i32,
}

#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct WorkerBindingLookup {
    pub(in crate::afxdp) by_if_queue: FastMap<(i32, u32), usize>,
    pub(in crate::afxdp) first_by_if: FastMap<i32, usize>,
    pub(in crate::afxdp) all_by_if: FastMap<i32, Vec<usize>>,
    pub(in crate::afxdp) by_slot: FastMap<u32, usize>,
}

impl WorkerBindingLookup {
    pub(in crate::afxdp) fn from_bindings(bindings: &[BindingWorker]) -> Self {
        let mut lookup = Self::default();
        for (index, binding) in bindings.iter().enumerate() {
            lookup
                .by_if_queue
                .insert((binding.ifindex, binding.queue_id), index);
            lookup.first_by_if.entry(binding.ifindex).or_insert(index);
            lookup
                .all_by_if
                .entry(binding.ifindex)
                .or_default()
                .push(index);
            lookup.by_slot.insert(binding.slot, index);
        }
        lookup
    }

    pub(in crate::afxdp) fn target_index(
        &self,
        current_index: usize,
        current_ifindex: i32,
        ingress_queue_id: u32,
        egress_ifindex: i32,
    ) -> Option<usize> {
        if current_ifindex == egress_ifindex {
            return Some(current_index);
        }
        self.by_if_queue
            .get(&(egress_ifindex, ingress_queue_id))
            .copied()
            .or_else(|| self.first_by_if.get(&egress_ifindex).copied())
    }

    pub(in crate::afxdp) fn slot_index(&self, slot: u32) -> Option<usize> {
        self.by_slot.get(&slot).copied()
    }

    pub(in crate::afxdp) fn fabric_target_index(
        &self,
        egress_ifindex: i32,
        flow_hash: u64,
    ) -> Option<usize> {
        let indices = self.all_by_if.get(&egress_ifindex)?;
        if indices.is_empty() {
            return None;
        }
        Some(indices[(flow_hash as usize) % indices.len()])
    }
}
