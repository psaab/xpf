// #6433: the flow-cache SEED (write) path, extracted from the inline
// body of `poll_binding_process_descriptor` where it sat fused to the
// forward-request push. The READ path already lives in the
// `flow_cache_hit.rs` sibling (#1327 Step 1); colocating the seed here
// lets the cache's eviction invariants — the #1861 §5.4 refused-install
// gate, the #3048/#3918/#5147 pre-resolve shard-epoch stamp, the
// #3073/#3322 policy-counter stamps — be reviewed as ONE contract
// against the hit path that consumes them.
//
// Pure code-motion: the helper body is the verbatim inline block (only
// the enclosing module and the `#[inline]` hint changed). The seed runs
// once per cache-miss forward (the session-install slow path), never per
// established-flow packet, so it is cold-ish; `#[inline]` keeps the body
// in the caller's CGU — the same hint the #946 Phase-1
// `poll_stages.rs` extractions carry — so LLVM is free to produce the
// same IR as the original inline code.
//
// Epoch-handling contract (moved verbatim from the inline block): the
// stamped neighbor-MAC epoch MUST come from the caller's PRE-RESOLVE
// whole-vector snapshot (`neighbor_epoch_snapshot`), keyed by the SAME
// `outer_neighbor_ifindex(.., None, ..)` ifindex that
// `FlowCacheEntry::from_forward_decision` derives internally and that
// `insert_if_changed` bumps on — never from a fresh post-resolve read
// (#3918 TOCTOU) and never keyed by the logical egress ifindex for a
// tunnel flow (#5147 review MAJOR).

use super::super::sharded_neighbor::ShardEpochSnapshot;
use super::filter::{
    evaluate_non_pbr_input_filter_counters_cached, evaluate_non_pbr_input_filter_log_only,
};
use super::*;
use crate::filter::TermMatchExtra;

#[inline]
#[allow(clippy::too_many_arguments)]
pub(super) fn stage_flow_cache_seed(
    flow_cache: &mut FlowCache,
    flow: &Option<SessionFlow>,
    meta: UserspaceDpMeta,
    validation: ValidationState,
    decision: SessionDecision,
    request_target_binding_index: Option<usize>,
    flow_cache_owner_rg_id: i32,
    session_ingress_zone: Option<u16>,
    flow_cache_install_failed: bool,
    // #10566: true when a counted evaluator already charged this seed
    // packet. Hit-path static ACCEPTs return false; miss-path evaluation
    // charges before reaching this common seed.
    seed_packet_already_counted: bool,
    flow_cache_policy_counter_idx: u32,
    flow_cache_policy_counter: &Option<std::sync::Arc<crate::policy::PolicyRuleCounter>>,
    filter_match_extra: TermMatchExtra<'static>,
    ingress_zone_override: Option<u16>,
    apply_nat_on_fabric: bool,
    neighbor_epoch_snapshot: &ShardEpochSnapshot,
    worker_ctx: &WorkerContext,
) {
    // ── Flow cache population ────────────────────
    // Cache ForwardCandidate decisions for established
    // TCP/UDP flows. Skip NAT64/NPTv6 (non-cacheable).
    // #1861 §5.4: never cache a decision whose backing
    // session install was attempted and refused
    // (flow_cache_install_failed) — a cached
    // sessionless decision would suppress the
    // per-packet reply repair until cache
    // invalidation. "No install required" paths
    // (DNS fast-path, fabric-return) keep the flag
    // false and cache as before.
    //
    // #5147: extract the pre-resolve epoch of THIS flow's
    // resolved next-hop shard from the whole-vector
    // snapshot taken before the resolve. Computed here,
    // while `decision` is still owned (it is moved into
    // `from_forward_decision` below), from the neighbor's
    // ACTUAL key ifindex — the OUTER transport ifindex for a
    // tunnel egress, the `egress_ifindex` for a direct
    // resolution — via `outer_neighbor_ifindex`, the same
    // ifindex `insert_if_changed` bumps on. `from_forward_decision`
    // derives `neighbor_shard` with the IDENTICAL
    // `outer_neighbor_ifindex(.., None, ..)` call, so the
    // stamped epoch and the hit-path re-read agree on the
    // shard (both `None` for the neighbor handle: the outer
    // ifindex is route-derived, so `None` yields the same
    // ifindex as the live resolve and keeps the two sites
    // coupled). Keying on the logical `egress_ifindex` for
    // tunnels was the review MAJOR — it stamped a different
    // shard than the bump, so a tunnel flow never evicted on
    // its outer gateway's MAC change (#3048 blackhole). A
    // resolution with no next-hop stamps 0 (paired with a
    // `NEIGHBOR_SHARD_NONE` shard → never MAC-stale).
    let neighbor_mac_epoch_at_resolve = match decision.resolution.next_hop {
        Some(nh) => neighbor_epoch_snapshot.epoch_for(&(
            outer_neighbor_ifindex(worker_ctx.forwarding, None, &decision.resolution),
            nh,
        )),
        None => 0,
    };
    if !flow_cache_install_failed
        && let Some(flow) = flow.as_ref()
    {
        let input_filter_counters = evaluate_non_pbr_input_filter_counters_cached(
            worker_ctx.forwarding,
            Some(flow),
            meta,
        );
        if let Some(mut entry) = FlowCacheEntry::from_forward_decision(
            flow,
            meta,
            validation,
            decision,
            flow_cache_owner_rg_id,
            session_ingress_zone,
            request_target_binding_index,
            evaluate_non_pbr_input_filter_log_only(
                worker_ctx.forwarding,
                filter_match_extra,
                Some(flow),
                meta,
                ingress_zone_override,
            ),
            // #3777/#10566: capture the input `then count` handles so cache
            // hits replay them. A miss-path seed was already counted by the
            // cold evaluator; a hit-path static ACCEPT was not. Charge the
            // latter only after the cache entry exists, so refused installs,
            // foreign/non-cacheable packets, and failed descriptor builds
            // cannot charge a packet that was not seeded.
            input_filter_counters.clone(),
            worker_ctx.forwarding,
            worker_ctx.ha_state,
            apply_nat_on_fabric,
            worker_ctx.rg_epochs,
            // #3048/#3918/#5147: stamp the PER-SHARD
            // neighbor-MAC-change epoch snapshotted BEFORE
            // the resolve above (the resolved shard's slot
            // of `neighbor_epoch_snapshot`), not a fresh
            // post-resolve read. A later kernel ARP/NDP MAC
            // change to THIS descriptor's next-hop neighbor
            // advances that shard's live epoch past this
            // stamp, evicting the cached stale dst_mac on
            // its next fast-path hit
            // (`neighbor_mac_epoch_stale`) — while a change
            // to an unrelated neighbor (a different shard)
            // leaves this flow cached (#5147). A MAC change
            // racing the resolve is caught too, because the
            // pre-resolve snapshot cannot already reflect it
            // (closes the #3918 TOCTOU).
            neighbor_mac_epoch_at_resolve,
        )
    {
        if !seed_packet_already_counted {
            // Charge the original capture, not the entry's post-dedup set:
            // `from_forward_decision` removes handles duplicated in TX
            // selection so cache hits replay them only once, but the seed
            // packet still owes each matching INPUT term once.
            input_filter_counters.for_each(|counter| {
                crate::filter::record_filter_counter(counter, meta.pkt_len as u64);
            });
        }
        // #3073: stamp the admitting rule's hit-counter handle
        // onto the cached entry (the seed constructor leaves
        // it 0). The flow-cache hit path
        // (`stage_flow_cache_hit`) then re-counts every cached
        // packet against the same policy, so cacheable flows
        // count their full load — not just the first frame.
        entry.metadata.policy_counter_idx = flow_cache_policy_counter_idx;
        // #3322: stamp the reorder-stable bound handle so the
        // flow-cache hit path counts against the admitting
        // rule even after a live policy reorder.
        entry.metadata.policy_counter = flow_cache_policy_counter.clone();
        flow_cache.insert(entry);
    }
    }
    // ── End flow cache population ────────────────
}
