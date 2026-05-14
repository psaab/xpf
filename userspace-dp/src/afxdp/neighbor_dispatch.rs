// Neighbor-dispatch helpers extracted from afxdp.rs (Issue 67.2).
//
// `retry_pending_neigh` is the post-poll loop that walks the
// per-binding pending-neighbor queue, re-issues bpf_fib_lookup +
// neighbor lookups, and resumes any flow whose neighbor has now
// resolved (or drops it if the cap is exceeded).
//
// `learn_dynamic_neighbor*` are called from the RX descriptor
// path when an inbound ARP/NDP advert resolves a previously
// missing neighbor — they upsert into the dynamic neighbor map.
//
// `build_missing_neighbor_session_metadata` constructs the
// SessionMetadata stub used while the neighbor is unresolved
// so subsequent retries have the full forward context.
//
// Pure relocation. `use super::*;` brings every type, helper,
// and sibling-submodule item from afxdp.rs into scope.

use super::*;

/// GEMINI-NEXT.md Section 3 cold-start: re-fire ARP/NDP solicitation
/// at exponential intervals after the initial probe in
/// `poll_descriptor.rs`. Each entry is the cumulative ns delay from
/// `PendingNeighPacket::queued_ns` at which to issue the next
/// `trigger_kernel_arp_probe()`. After all entries elapse, no further
/// probes — the packet just waits for kernel resolution or the
/// PENDING_NEIGH_TIMEOUT.
///
/// 10/60/260 ms covers a 4-probe schedule (initial + 3 retries) over
/// 260 ms total. The deltas (10, 50, 200 ms) match the cold-start
/// exponential design in GEMINI-NEXT.md and give the kernel three
/// retransmits if the first solicitation is dropped.
const PROBE_SCHEDULE_NS: &[u64] = &[
    10_000_000,  // first retry at queued + 10 ms
    60_000_000,  // second retry at queued + 60 ms (delta 50 ms)
    260_000_000, // third retry at queued + 260 ms (delta 200 ms)
];

/// Returns true when the next scheduled probe is due. Pure function —
/// no side effects, easy to unit-test the schedule edges.
fn probe_due(elapsed_ns: u64, attempts: u8) -> bool {
    PROBE_SCHEDULE_NS
        .get(attempts as usize)
        .is_some_and(|&target| elapsed_ns >= target)
}

pub(super) fn retry_pending_neigh(
    binding: &mut BindingWorker,
    left: &mut [BindingWorker],
    binding_index: usize,
    right: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_ns: u64,
    area: &MmapArea,
) {
    if binding.pending_neigh.is_empty() {
        return;
    }
    // GEMINI-NEXT.md Section 3 cold start: in-place pop_front/push_back
    // rotation. The previous version did `binding.pending_neigh.remove(i)`
    // inside a while-i-loop, which is O(n) per removal — scaled O(n²) in
    // the queue depth. With MAX_PENDING_NEIGH bumped to 4096 (was 64), the
    // quadratic cost becomes a real fairness hazard during connection
    // bursts; even at the 64-cap it was wasteful relative to the cap.
    //
    // We pop exactly the snapshotted-len items off the front and either
    // (a) drop the packet (recycle frame), (b) push it back on the SAME
    // VecDeque (FIFO order preserved for retained items), or (c) dispatch
    // it. Items pushed back go to the tail and are NOT re-visited in this
    // sweep because we iterate exactly `pending_len` times. Reusing the
    // existing backing buffer avoids per-sweep alloc/free churn that the
    // earlier `mem::take` + `reserve` draft would have introduced.
    let pending_len = binding.pending_neigh.len();
    let ingress_slot = binding.slot;
    let ingress_ifindex = binding.ifindex;
    let ingress_queue = binding.queue_id;
    // Per-sweep dedup of probe re-fires by `(egress_ifindex, next_hop)`.
    // Without this, N packets queued for the same unresolved neighbor
    // would each re-fire `trigger_kernel_arp_probe()` at the same
    // schedule slot — N redundant socket opens + N kernel ARP/NDP
    // entries. The kernel coalesces solicits, but we still pay the
    // syscall + alloc per call. Mirrors the dedup at the initial-probe
    // site in poll_descriptor.rs (which uses `pending_neigh.iter().any`).
    //
    // BTreeSet is used because IpAddr is Ord and we expect the set to
    // be small (handful of neighbors at most during cold start) — the
    // log-N insert dominates over hash setup for tiny N.
    let mut probed_this_sweep: std::collections::BTreeSet<(i32, IpAddr)> =
        std::collections::BTreeSet::new();
    for _ in 0..pending_len {
        let pkt = binding
            .pending_neigh
            .pop_front()
            .expect("pending_neigh shrank during retry sweep");
        // Timeout: recycle frame and drop.
        if now_ns.saturating_sub(pkt.queued_ns) > PENDING_NEIGH_TIMEOUT_NS {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        }
        // Check if neighbor MAC is now available, mirroring the lookup
        // order from lookup_neighbor_entry(): static/permanent neighbors
        // first, then dynamic_neighbors.
        let mac = if let Some(hop) = pkt.decision.resolution.next_hop {
            let neigh_key = (pkt.decision.resolution.egress_ifindex, hop);
            forwarding
                .neighbors
                .get(&neigh_key)
                .map(|e| e.mac)
                .or_else(|| dynamic_neighbors.get(&neigh_key).map(|e| e.mac))
        } else {
            None
        };
        let Some(neighbor_mac) = mac else {
            // Still pending — re-fire ARP/NDP probe if the next slot
            // in the exponential schedule is due (GEMINI-NEXT.md
            // Section 3 cold-start). Each retry advances
            // probe_attempts so each schedule entry fires at most
            // once per packet. Per-sweep dedup keyed on
            // (egress_ifindex, next_hop) prevents probe-storm when
            // many packets share the same unresolved neighbor.
            let mut pkt = pkt;
            if probe_due(
                now_ns.saturating_sub(pkt.queued_ns),
                pkt.probe_attempts,
            ) {
                if let Some(hop) = pkt.decision.resolution.next_hop {
                    let key = (pkt.decision.resolution.egress_ifindex, hop);
                    if probed_this_sweep.contains(&key) {
                        // Another pkt for this (egress, hop) already
                        // fired the probe this sweep. Advance this
                        // pkt's schedule so it doesn't busy-loop on
                        // the same slot next sweep.
                        pkt.probe_attempts = pkt.probe_attempts.saturating_add(1);
                    } else if let Some(name) = forwarding.ifindex_to_name.get(&key.0) {
                        // First pkt for this (egress, hop) AND iface
                        // resolves → fire the probe, mark the slot
                        // consumed for the rest of this sweep, and
                        // advance this pkt's schedule.
                        trigger_kernel_arp_probe(name, hop);
                        probed_this_sweep.insert(key);
                        pkt.probe_attempts = pkt.probe_attempts.saturating_add(1);
                    }
                    // else: not yet probed AND iface lookup miss → no
                    // probe fires, key NOT inserted, probe_attempts
                    // NOT advanced. Subsequent same-key pkts will
                    // also fall here, and the whole batch retries
                    // this slot next sweep.
                }
                // else: no next_hop → cannot probe; do not advance.
            }
            binding.pending_neigh.push_back(pkt);
            continue;
        };
        let mut decision = pkt.decision;
        decision.resolution.neighbor_mac = Some(neighbor_mac);
        decision.resolution.disposition = ForwardingDisposition::ForwardCandidate;
        let expected_ports = None;
        let Some(rewrite_result) = rewrite_forwarded_frame_in_place(
            &*area,
            pkt.desc,
            pkt.meta,
            &decision,
            false,
            expected_ports,
        ) else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        };
        let target_ifindex = if decision.resolution.tx_ifindex > 0 {
            decision.resolution.tx_ifindex
        } else {
            resolve_tx_binding_ifindex(forwarding, decision.resolution.egress_ifindex)
        };
        let Some(target_idx) = binding_lookup.target_index(
            binding_index,
            ingress_ifindex,
            ingress_queue,
            target_ifindex,
        ) else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
            continue;
        };
        let cos = resolve_cos_tx_selection(
            forwarding,
            decision.resolution.egress_ifindex,
            pkt.meta,
            None,
        );
        let req = PreparedTxRequest {
            offset: rewrite_result.offset,
            len: rewrite_result.len,
            recycle: PreparedTxRecycle::fill_on_slot(
                ingress_slot,
                rewrite_result.offset,
                pkt.desc.addr,
            ),
            expected_ports: None,
            expected_addr_family: pkt.meta.addr_family,
            expected_protocol: pkt.meta.protocol,
            flow_key: None,
            egress_ifindex: decision.resolution.egress_ifindex,
            cos_queue_id: cos.queue_id,
            dscp_rewrite: cos.dscp_rewrite,
        };
        if target_idx == binding_index {
            binding.tx_pipeline.pending_tx_prepared.push_back(req);
            binding.tx_counters.pending_in_place_tx_packets += 1;
            binding
                .tx_counters
                .record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
        } else if let Some(target) =
            binding_by_index_mut(left, binding_index, binding, right, target_idx)
        {
            target.tx_pipeline.pending_tx_prepared.push_back(req);
            bound_pending_tx_prepared(target);
            target.tx_counters.pending_in_place_tx_packets += 1;
            target
                .tx_counters
                .record_in_place_l2_rewrite(rewrite_result.l2_rewrite);
        } else {
            binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
        }
    }
}

pub(super) fn learn_dynamic_neighbor_from_packet(
    area: &MmapArea,
    desc: XdpDesc,
    meta: UserspaceDpMeta,
    src_ip: IpAddr,
    last_learned_neighbor: &mut Option<LearnedNeighborKey>,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) {
    let Some(frame) = area.slice(desc.addr as usize, desc.len as usize) else {
        return;
    };
    if frame.len() < 12 {
        return;
    }
    if frame[6] == 0x02
        && frame[7] == 0xbf
        && frame[8] == 0x72
        && frame[9] == FABRIC_ZONE_MAC_MAGIC
        && frame[10] == 0x00
    {
        return;
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    if src_mac == [0; 6] || (src_mac[0] & 1) != 0 {
        return;
    }
    let learned = LearnedNeighborKey {
        ingress_ifindex: meta.ingress_ifindex as i32,
        ingress_vlan_id: meta.ingress_vlan_id,
        src_ip,
        src_mac,
    };
    if last_learned_neighbor.as_ref() == Some(&learned) {
        return;
    }
    learn_dynamic_neighbor(
        forwarding,
        dynamic_neighbors,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        src_ip,
        src_mac,
    );
    *last_learned_neighbor = Some(learned);
}

pub(super) fn learn_dynamic_neighbor(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    src_ip: IpAddr,
    src_mac: [u8; 6],
) {
    let mut ifindexes = vec![ingress_ifindex];
    if let Some(logical_ifindex) =
        resolve_ingress_logical_ifindex(forwarding, ingress_ifindex, ingress_vlan_id)
    {
        if logical_ifindex > 0 && logical_ifindex != ingress_ifindex {
            ifindexes.push(logical_ifindex);
        }
    }
    // #949: multi-ifindex insert atomically vs readers — both
    // ingress_ifindex and the resolved logical (VLAN sub-) ifindex
    // get the same MAC under one bulk acquisition so a reader sees
    // either both or neither, never a stale half.
    dynamic_neighbors.with_all_shards(|bulk| {
        for ifindex in ifindexes {
            bulk.insert((ifindex, src_ip), NeighborEntry { mac: src_mac });
        }
    });
}

pub(super) fn build_missing_neighbor_session_metadata(
    forwarding: &ForwardingState,
    ingress_zone: u16,
    egress_zone: u16,
    fabric_ingress: bool,
    decision: SessionDecision,
) -> SessionMetadata {
    SessionMetadata {
        ingress_zone,
        egress_zone,
        owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
        fabric_ingress,
        is_reverse: false,
        nat64_reverse: None,
    }
}

#[cfg(test)]
mod cold_start_probe_schedule_tests {
    use super::{PROBE_SCHEDULE_NS, probe_due};

    #[test]
    fn schedule_values_match_design() {
        // Pin the exact schedule so accidental edits fail the build
        // rather than silently regressing the cold-start design from
        // GEMINI-NEXT.md Section 3.
        assert_eq!(
            PROBE_SCHEDULE_NS,
            &[10_000_000u64, 60_000_000u64, 260_000_000u64],
        );
    }

    #[test]
    fn schedule_is_strictly_monotonic() {
        for window in PROBE_SCHEDULE_NS.windows(2) {
            assert!(
                window[0] < window[1],
                "PROBE_SCHEDULE_NS must be strictly increasing: {:?}",
                PROBE_SCHEDULE_NS
            );
        }
    }

    #[test]
    fn probe_due_fires_only_at_or_after_schedule_boundary() {
        let first = PROBE_SCHEDULE_NS[0];
        assert!(!probe_due(first - 1, 0));
        assert!(probe_due(first, 0));
        assert!(probe_due(first + 1, 0));
    }

    #[test]
    fn probe_due_walks_each_schedule_slot() {
        // After attempts=0 fires, probe_due(elapsed, 1) must wait until
        // PROBE_SCHEDULE_NS[1]; same for each subsequent slot.
        for (idx, &target) in PROBE_SCHEDULE_NS.iter().enumerate() {
            let attempts = idx as u8;
            assert!(
                !probe_due(target.saturating_sub(1), attempts),
                "slot {idx} should not fire one ns before target",
            );
            assert!(
                probe_due(target, attempts),
                "slot {idx} should fire at target",
            );
        }
    }

    #[test]
    fn probe_due_returns_false_after_schedule_exhausted() {
        let exhausted = PROBE_SCHEDULE_NS.len() as u8;
        // Even with elapsed_ns = u64::MAX, no further probes once
        // every slot has fired.
        assert!(!probe_due(u64::MAX, exhausted));
        assert!(!probe_due(u64::MAX, exhausted.saturating_add(1)));
    }

    #[test]
    fn schedule_total_window_under_pending_neigh_timeout() {
        // The schedule must finish before PENDING_NEIGH_TIMEOUT_NS
        // (2 s, see types/mod.rs) so all 3 retries fire while the
        // packet is still queued. Otherwise the last retry is dead
        // code: the packet will already be expired by then.
        let last = *PROBE_SCHEDULE_NS.last().expect("schedule non-empty");
        assert!(
            last < super::PENDING_NEIGH_TIMEOUT_NS,
            "last probe slot {last}ns must be < PENDING_NEIGH_TIMEOUT_NS",
        );
    }

    /// Pure-function model of the per-sweep dedup logic in
    /// `retry_pending_neigh`'s still-pending branch. Mirrors the
    /// real code path closely enough to test burst-coalescing
    /// behavior — including the ifindex-miss path — without spinning
    /// up a full `BindingWorker`.
    ///
    /// Returns (probes_fired, attempts_advanced).
    fn simulate_sweep_for_neighbor(
        packets_for_same_neigh: u32,
        slot_idx: u8,
        iface_resolves: bool,
    ) -> (u32, u32) {
        let mut probed: std::collections::BTreeSet<(i32, std::net::IpAddr)> =
            std::collections::BTreeSet::new();
        let mut probes_fired = 0u32;
        let mut attempts_advanced = 0u32;
        let key: (i32, std::net::IpAddr) = (
            42,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        );
        let elapsed = PROBE_SCHEDULE_NS[slot_idx as usize];
        for _ in 0..packets_for_same_neigh {
            if probe_due(elapsed, slot_idx) {
                if probed.contains(&key) {
                    // Slot consumed by an earlier pkt this sweep.
                    attempts_advanced += 1;
                } else if iface_resolves {
                    // First pkt + iface resolves → fire + mark + advance.
                    probes_fired += 1;
                    probed.insert(key);
                    attempts_advanced += 1;
                }
                // else: iface miss + not yet probed → drop through,
                // no probe, no insert, no advance.
            }
        }
        (probes_fired, attempts_advanced)
    }

    #[test]
    fn dedup_emits_one_probe_per_neighbor_per_slot() {
        // 50 packets queued for the same (egress_ifindex, next_hop)
        // must produce exactly ONE probe per schedule slot. All 50
        // pkts still advance their probe_attempts so they don't
        // re-trigger the same slot next sweep.
        let (fired, advanced) = simulate_sweep_for_neighbor(50, 0, true);
        assert_eq!(
            fired, 1,
            "expected 1 probe for 50 same-neighbor packets, got {fired}",
        );
        assert_eq!(advanced, 50, "all 50 pkts must advance probe_attempts");
    }

    #[test]
    fn dedup_holds_across_all_schedule_slots() {
        // Same dedup property for every slot, not just slot 0.
        for slot in 0..(PROBE_SCHEDULE_NS.len() as u8) {
            let (fired, _) = simulate_sweep_for_neighbor(8, slot, true);
            assert_eq!(fired, 1, "slot {slot}: expected 1 probe, got {fired}",);
        }
    }

    #[test]
    fn iface_miss_does_not_burn_slot_for_any_packet() {
        // When ifindex_to_name lookup fails (e.g. iface flapped),
        // NONE of the queued packets should consume their schedule
        // slot — every pkt must stay at the same probe_attempts so
        // the next sweep can re-try once the iface is back. Earlier
        // bug: first pkt inserted into dedup set then bailed,
        // causing later pkts to think the slot was consumed by a
        // probe that never fired.
        let (fired, advanced) = simulate_sweep_for_neighbor(50, 0, false);
        assert_eq!(fired, 0, "no probes when iface lookup fails");
        assert_eq!(
            advanced, 0,
            "no pkt should advance probe_attempts on iface miss",
        );
    }
}
