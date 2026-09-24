use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU32;

const FLOW_CACHE_SIZE: usize = 4096;
// #918: 4-way set-associative layout. Total entry count stays
// at 4096 (1024 sets × 4 ways) so memory footprint is unchanged
// in the entries array; the new `lru: [u8; 4]` per set adds 4 KB
// of bookkeeping. Per-set scan touches ~6 cache lines (4 × ~96 B
// + 4 B lru) which is prefetcher-friendly. Compare to the old
// 1-way direct-mapped layout where any 2 flows that hashed to the
// same slot evicted each other on every packet.
const FLOW_CACHE_WAYS: usize = 4;
const FLOW_CACHE_SETS: usize = FLOW_CACHE_SIZE / FLOW_CACHE_WAYS;
const FLOW_CACHE_SET_MASK: usize = FLOW_CACHE_SETS - 1;
pub(super) const ACTIVE_WINDOW_EPOCHS: u16 = 10;
pub(super) const FLOW_WORKER_MAP_MAX_PER_BINDING: usize = 256;
const _: () = assert!(FLOW_CACHE_SETS.is_power_of_two());
const _: () = assert!(FLOW_CACHE_WAYS == 4);
const _: () = assert!(FLOW_CACHE_SETS * FLOW_CACHE_WAYS == FLOW_CACHE_SIZE);

pub(super) const fn flow_cache_capacity() -> usize {
    FLOW_CACHE_SIZE
}

/// Maximum number of redundancy groups for epoch-based cache invalidation.
pub(super) const MAX_RG_EPOCHS: usize = 16;

/// Map an owner redundancy-group id to the index of the per-RG epoch slot
/// used for flow-cache invalidation.
///
/// A valid per-RG index (`1 ..= MAX_RG_EPOCHS-1`) uses its own slot; every
/// other owner — `rg <= 0` (fabric / unresolved-owner reverse) AND
/// out-of-range high RG ids (`>= MAX_RG_EPOCHS`, #2466) — falls back to the
/// node-level `rg_epochs[0]` activation edge. This mirrors the worker
/// session-expiry gate (`epoch_of` in worker/loop_body/mod.rs): the two MUST
/// agree so a flow stamped here is invalidated on the same edge the gate
/// uses. Before #2466 an out-of-range owner stamped epoch 0 literally (never
/// invalidated by any per-RG bump), so a cached decision for an RG >= 16
/// survived failover until the lease/session-expiry backstop caught it.
#[inline]
pub(super) fn rg_epoch_index(owner_rg_id: i32) -> usize {
    if owner_rg_id > 0 && (owner_rg_id as usize) < MAX_RG_EPOCHS {
        owner_rg_id as usize
    } else {
        0
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct CachedTxSelectionDescriptor {
    pub(super) queue_id: Option<u8>,
    pub(super) dscp_rewrite: Option<u8>,
    pub(super) drop: bool,
    // #3608: `drop` collapses `then discard` and `then reject` (both
    // non-`Accept` terminal actions) into one bit. `reject` isolates the
    // `then reject` subset so the flow-cache-hit consumer can synthesize the
    // active reject reply (TCP RST / ICMP admin-prohibited) rather than the
    // silent drop `then discard` produces. Only ever true when `drop` is true.
    pub(super) reject: bool,
    // #6854: the ICMP codes the cached `then reject <message-type>` resolved
    // to. Meaningless unless `reject` is true; defaults to
    // administratively-prohibited, matching pre-#6854 behaviour.
    pub(super) reject_message: crate::filter::RejectMessage,
    // #2573: all matched `then count` term counters for this flow, not just the
    // last — the cached replay must increment every fall-through count term.
    pub(super) filter_counters: crate::filter::CachedFilterCounters,
    pub(super) three_color_policers: crate::filter::CachedThreeColorPolicers,
    pub(super) filter_log: Option<crate::filter::FilterLogMatch>,
    // #3778: the cached `queue_id` is resolved from the SEED packet's DSCP /
    // 802.1p PCP. Behavior-aggregate (BA) classifiers are per-packet in vSRX
    // and the flow-cache key excludes DSCP/PCP, so when the queue was chosen by
    // a BA classifier (NOT a 5-tuple-stable filter forwarding-class) it must be
    // re-resolved per packet on the hit path. True iff a BA classifier is
    // configured on the egress interface AND no filter forwarding-class pinned
    // the queue; false keeps the frozen `queue_id` (default-queue / filter-FC /
    // no-CoS flows), so the per-packet re-classify cost is paid only when it can
    // change the queue.
    pub(super) ba_reclassify: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CachedInputFilterLog {
    pub(super) log_match: crate::filter::FilterLogMatch,
    pub(super) ingress_zone_id: u16,
}

/// Precomputed rewrite descriptor for an established flow.
/// All fields are constant for the lifetime of the session.
/// Per-packet cost: write MACs + TTL-- + apply precomputed csum deltas.
#[derive(Clone, Debug)]
pub(super) struct RewriteDescriptor {
    pub(super) dst_mac: [u8; 6],
    pub(super) src_mac: [u8; 6],
    pub(super) fabric_redirect: bool,
    pub(super) tx_vlan_id: u16,
    pub(super) ether_type: u16,
    pub(super) rewrite_src_ip: Option<std::net::IpAddr>,
    pub(super) rewrite_dst_ip: Option<std::net::IpAddr>,
    pub(super) rewrite_src_port: Option<u16>,
    pub(super) rewrite_dst_port: Option<u16>,
    pub(super) ip_csum_delta: u16,
    pub(super) l4_csum_delta: u16,
    #[allow(dead_code)] // populated for future flow-cache fast-path TX
    pub(super) egress_ifindex: i32,
    #[allow(dead_code)] // populated for future flow-cache fast-path TX
    pub(super) tx_ifindex: i32,
    #[allow(dead_code)] // populated for future flow-cache fast-path TX
    pub(super) target_binding_index: Option<usize>,
    pub(super) input_filter_log: Option<CachedInputFilterLog>,
    // #3777/#10566: interface INPUT `then count` term handles matched by this
    // flow's 5-tuple, replayed on every cache HIT so an input `then count`
    // reports the full N-packet load (mirrors `tx_selection.filter_counters`
    // for the OUTPUT side, #2573). Captured once at seed; the seed path
    // charges it either in the cold evaluator or in the seed insert arm.
    pub(super) input_filter_counters: crate::filter::CachedFilterCounters,
    pub(super) tx_selection: CachedTxSelectionDescriptor,
    pub(super) nat64: bool,
    pub(super) nptv6: bool,
    #[allow(dead_code)] // populated for future flow-cache fast-path TX
    pub(super) apply_nat_on_fabric: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FlowCacheStamp {
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
    pub(super) owner_rg_id: i32,
    pub(super) owner_rg_epoch: u32,
    pub(super) owner_rg_lease_until: u64,
}

impl FlowCacheStamp {
    #[inline]
    pub(super) fn capture(
        config_generation: u64,
        fib_generation: u32,
        owner_rg_id: i32,
        ha_state: &BTreeMap<i32, HAGroupRuntime>,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    ) -> Self {
        Self {
            config_generation,
            fib_generation,
            owner_rg_id,
            // #2466: route every owner (including out-of-range high RG ids
            // >= MAX_RG_EPOCHS and rg <= 0) through rg_epoch_index so the
            // stamp records the same epoch slot the lookup guard re-checks,
            // matching the worker session-expiry gate. Out-of-range owners
            // fall back to the node-level rg_epochs[0] edge instead of a
            // literal epoch 0 that no per-RG bump ever moves.
            owner_rg_epoch: rg_epochs[rg_epoch_index(owner_rg_id)].load(Ordering::Relaxed),
            owner_rg_lease_until: ha_state
                .get(&owner_rg_id)
                .map(|group| match group.lease {
                    HAForwardingLease::ActiveUntil(until) if group.active => until,
                    _ => 0,
                })
                .unwrap_or(0),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct FlowCacheLookup {
    /// PHYSICAL parent ingress ifindex (`meta.ingress_ifindex`). Used for set
    /// placement (`set_index`) and invalidation — the value the GC / RST
    /// teardown paths pass (`binding.ifindex`), so those stay coherent.
    pub(super) ingress_ifindex: i32,
    /// #5139: LOGICAL ingress ifindex — the VLAN-unit ifindex that selects the
    /// security zone. On a non-VLAN interface this equals `ingress_ifindex`.
    /// It is an ADDITIONAL in-set match discriminator (see `FlowCacheEntry`) so
    /// two VLAN units co-parented on ONE physical interface with the SAME
    /// 5-tuple do NOT alias to one entry (cross-zone policy/NAT replay).
    pub(super) logical_ingress_ifindex: i32,
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
}

impl FlowCacheLookup {
    #[inline]
    pub(super) fn for_packet(
        meta: UserspaceDpMeta,
        validation: ValidationState,
        forwarding: &ForwardingState,
    ) -> Self {
        // #5139: resolve the LOGICAL (VLAN-selecting) ingress ifindex the same
        // way the cache-insert path does (`from_forward_decision`), so the
        // lookup identity matches the stamped entry identity for the same
        // packet. Non-VLAN ingress (no mapping) falls back to the physical
        // ifindex, so co-parented VLANs differ but bare interfaces are
        // unchanged.
        let physical = meta.ingress_ifindex as i32;
        let logical = resolve_ingress_logical_ifindex(forwarding, physical, meta.ingress_vlan_id)
            .unwrap_or(physical);
        Self {
            ingress_ifindex: physical,
            logical_ingress_ifindex: logical,
            config_generation: validation.config_generation,
            fib_generation: validation.fib_generation,
        }
    }
}

/// Per-flow cache entry with key validation.
#[derive(Clone)]
pub(super) struct FlowCacheEntry {
    pub(super) key: crate::session::SessionKey,
    /// PHYSICAL parent ingress ifindex — hashed by `set_index` for set
    /// placement and matched by `invalidate_slot` (which the GC / RST teardown
    /// paths drive with `binding.ifindex`). Keeping this physical keeps those
    /// invalidations coherent (they cannot recover the logical ifindex from a
    /// bare session key). Invalidate matches physical-only, so it over-evicts
    /// co-5-tuple VLAN siblings — safe (a re-miss re-evaluates from policy),
    /// never stranding a stale entry.
    pub(super) ingress_ifindex: i32,
    /// #5139: LOGICAL (VLAN-unit) ingress ifindex that selects the security
    /// zone. An ADDITIONAL in-set match key (alongside `key` + `ingress_ifindex`)
    /// so a HIT requires the SAME logical VLAN, not just the same physical
    /// parent — closing the co-parented-VLAN cross-zone policy/NAT replay.
    /// Equals `ingress_ifindex` on a non-VLAN interface.
    pub(super) logical_ingress_ifindex: i32,
    pub(super) descriptor: RewriteDescriptor,
    pub(super) decision: SessionDecision,
    pub(super) metadata: SessionMetadata,
    /// Validation stamp captured at insert time. Stale entries are treated as
    /// misses without requiring per-entry scans at RG transition.
    pub(super) stamp: FlowCacheStamp,
    /// #1264: cumulative bytes observed for this cached flow by the
    /// worker-owned flow cache. Updated only while the entry is already
    /// mutably borrowed on cache insert/hit, so the telemetry adds no shared
    /// atomics and no cross-worker cache-line traffic.
    pub(super) observed_bytes: u64,
    /// #1219: per-hit recency counter. Owner-only single u16 store on every
    /// `lookup()` hit — see `FlowCache::current_epoch` for the comparison
    /// reference. The ~65ms-tick scan in `count_active_flows()` counts
    /// entries with `(current_epoch - last_used_epoch) < 10` (~650ms
    /// window). The hot path reaches that cadence by poll counter; the idle
    /// RX-empty path uses a wall-clock cadence so active-flow telemetry also
    /// ages while traffic is quiet. u16 wraps every 65536 epochs × 65ms ≈ 71
    /// minutes, far past any concern. Value 0 = "never touched" sentinel
    /// (epoch 0 is skipped by `tick_advance_epoch`); freshly inserted entries
    /// carry 0 until their first lookup hit.
    ///
    /// #1741: entries are NOT removed when a flow dies, so this stamp can
    /// freeze at a nonzero value. The per-scan clamp in
    /// `active_flow_debug_entries` sentinel-clears stamps that leave the
    /// active window, so a wrapped `current_epoch` can never re-match a
    /// dead flow ("ghost resurrection" over-count).
    pub(super) last_used_epoch: u16,
    /// #3048/#5147: the per-shard `ShardedNeighborMap` MAC-change epoch
    /// captured (from the pre-resolve snapshot) when this descriptor was
    /// built — the epoch of the SPECIFIC shard `neighbor_shard` this flow's
    /// resolved next-hop lives in. The descriptor caches the resolved
    /// next-hop `dst_mac`; if a kernel ARP/NDP update later REPLACES that
    /// neighbor's MAC, the neighbor map advances ONLY that shard's epoch past
    /// this stamp. The worker fast path compares the two on every hit
    /// (`neighbor_mac_epoch_stale`) and evicts a stale descriptor so the next
    /// packet re-resolves the current MAC — closing the post-failover
    /// stale-MAC blackhole. A periodic refresh that re-learns the SAME MAC
    /// does NOT advance the epoch, so steady-state traffic never re-misses;
    /// and a MAC change to an UNRELATED neighbor (a different shard) no longer
    /// evicts this entry (the #5147 map-wide-thrash fix).
    pub(super) neighbor_mac_epoch: u32,
    /// #5147: index of the neighbor shard `neighbor_mac_epoch` was stamped
    /// against — the shard that holds this flow's resolved next-hop
    /// `(egress_ifindex, next_hop)`. Precomputed once at cache-miss time so
    /// the fast-path hit is a single indexed atomic load, no hashing.
    /// `NEIGHBOR_SHARD_NONE` marks a flow with no dynamic-neighbor dependency
    /// (no resolved next-hop, e.g. a fabric/local disposition); such a flow
    /// is never MAC-stale.
    pub(super) neighbor_shard: u16,
}

/// #5147: sentinel `neighbor_shard` for a cached flow with no resolved
/// next-hop neighbor (no dynamic-neighbor MAC dependency). Such an entry is
/// never invalidated by a neighbor MAC change. `NUM_SHARDS` is 64, far below
/// this value, so it can never collide with a real shard index.
pub(super) const NEIGHBOR_SHARD_NONE: u16 = u16::MAX;

impl FlowCacheEntry {
    /// #3048/#5147: true when the neighbor table has recorded a genuine MAC
    /// change to THIS flow's next-hop neighbor since the descriptor was
    /// cached, i.e. its captured `dst_mac` may be stale. Reads the live epoch
    /// of only the flow's own shard (`neighbor_shard`) — a single indexed
    /// relaxed atomic load + compare on the hot path. Equal epochs (the
    /// steady-state case, including same-MAC ARP refreshes which never advance
    /// the counter, AND a MAC change to any neighbor in a DIFFERENT shard)
    /// keep the entry; an advance of this flow's own shard evicts it. A flow
    /// with no resolved next-hop (`NEIGHBOR_SHARD_NONE`) has no
    /// dynamic-neighbor dependency and is never MAC-stale.
    #[inline]
    pub(super) fn neighbor_mac_epoch_stale(
        &self,
        neighbors: &crate::afxdp::sharded_neighbor::ShardedNeighborMap,
    ) -> bool {
        if self.neighbor_shard == NEIGHBOR_SHARD_NONE {
            return false;
        }
        self.neighbor_mac_epoch != neighbors.shard_mac_epoch(self.neighbor_shard as usize)
    }
}

#[derive(Clone, Debug)]
pub(super) struct FlowCacheDebugEntry {
    pub(super) ingress_ifindex: i32,
    pub(super) egress_ifindex: i32,
    pub(super) tx_ifindex: i32,
    pub(super) session_key: crate::protocol::FlowTupleStatus,
    pub(super) forward_wire_key: crate::protocol::FlowTupleStatus,
    pub(super) reverse_canonical_key: crate::protocol::FlowTupleStatus,
    pub(super) cos_queue_id: Option<u8>,
    pub(super) dscp_rewrite: Option<u8>,
    pub(super) age_epochs: u16,
    pub(super) observed_bytes: u64,
}

#[derive(Clone, Debug)]
pub(super) struct CoSActiveFlowCount {
    pub(super) ifindex: i32,
    pub(super) queue_id: u8,
    pub(super) active_flow_count: u32,
}

/// #963 PR-A: defense-in-depth check for `from_forward_decision`.
///
/// Returns `true` if every `Some(_)` IP in `nat.rewrite_src` /
/// `nat.rewrite_dst` is the same address family as `addr_family`.
/// `None` IPs match any family (they're "no rewrite for this slot").
///
/// `addr_family` MUST be `AF_INET` or `AF_INET6`. Any other value
/// (junk meta from a malformed packet, uninitialised stack memory)
/// returns `false` so the descriptor is rejected and the flow falls
/// through to the generic in-place rewrite path. Without the
/// explicit third arm, a `addr_family != AF_INET` value would
/// silently pretend to be V6 (the `ether_type` derivation in
/// `from_forward_decision` collapses the same way for any non-V4
/// `meta.addr_family`), which is exactly the kind of latent
/// invariant violation this guard is supposed to refuse.
///
/// Called once per cache miss, not per packet.
fn nat_family_matches_addr_family(addr_family: i32, nat: &NatDecision) -> bool {
    let want_v4 = match addr_family {
        libc::AF_INET => true,
        libc::AF_INET6 => false,
        _ => return false,
    };
    let slot_ok = |opt: &Option<IpAddr>| match opt {
        None => true,
        Some(IpAddr::V4(_)) => want_v4,
        Some(IpAddr::V6(_)) => !want_v4,
    };
    slot_ok(&nat.rewrite_src) && slot_ok(&nat.rewrite_dst)
}

impl FlowCacheEntry {
    #[inline]
    pub(super) fn packet_eligible(meta: UserspaceDpMeta) -> bool {
        // #2151: `is_ack_only` == the prior `(meta.tcp_flags & 0x17) == 0x10`
        // — only established TCP (pure ACK) and UDP are cacheable.
        (meta.protocol == PROTO_TCP && crate::tcp_flags::is_ack_only(meta.tcp_flags))
            || meta.protocol == PROTO_UDP
    }

    #[inline]
    pub(super) fn should_cache(meta: UserspaceDpMeta, decision: SessionDecision) -> bool {
        // #2363: admission must use the IDENTICAL eligibility predicate the
        // LOOKUP path gates on (`packet_eligible`: UDP or established-TCP pure
        // ACK). Without this, a TCP control segment (SYN/SYN-ACK/FIN/RST) that
        // produces a ForwardCandidate decision would seed a cache entry; a
        // later pure-ACK on the same 5-tuple then takes the fast path and skips
        // the session lookup that observes/advances TCP closing state on
        // FIN/RST. The cached decision is the legitimately-computed forward
        // decision (so this is NOT a policy fail-open) — the harm is the
        // skipped flag-sensitive session-state observation. Keeping the gate in
        // `should_cache` makes admission and lookup share a single source of
        // truth for cacheability (see `packet_eligible`); PSH+ACK data segments
        // remain cacheable because `is_ack_only` ignores PSH/URG, so
        // steady-state data and UDP still fast-path.
        //
        // #2652: NPTv6 (RFC 6296 stateless prefix translation) IS cacheable.
        // It is a same-family IPv6 address byte-rewrite that is checksum-neutral
        // by design, so the descriptor fast path (`apply_rewrite_descriptor` →
        // `apply_rewrite_descriptor_ipv6`) reproduces it byte-for-byte: it
        // writes the new IPv6 address(es) and, because `compute_l4_csum_delta`
        // returns 0 for nptv6, leaves the L4 checksum untouched — exactly what
        // the slow-path `apply_nat_ipv6` does (`skip_l4_csum = nat.nptv6`).
        //
        // NAT64 stays EXCLUDED. It is a version-changing translation (IPv6 40B
        // header <-> IPv4 20B header, fragment-header handling) built by
        // `build_nat64_*_frame` which allocates a fresh frame of a different
        // size. The in-place `RewriteDescriptor` byte-write fast path cannot
        // express a header rebuild, so NAT64 must remain on the generic path.
        Self::packet_eligible(meta)
            && matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
            && !decision.nat.nat64
            && decision.resolution.disposition.is_cacheable()
    }

    pub(super) fn from_forward_decision(
        flow: &SessionFlow,
        meta: UserspaceDpMeta,
        validation: ValidationState,
        decision: SessionDecision,
        flow_owner_rg_id: i32,
        ingress_zone: Option<u16>,
        target_binding_index: Option<usize>,
        input_filter_log: Option<CachedInputFilterLog>,
        input_filter_counters: crate::filter::CachedFilterCounters,
        forwarding: &ForwardingState,
        ha_state: &BTreeMap<i32, HAGroupRuntime>,
        apply_nat_on_fabric: bool,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
        // #3918: the caller's PRE-RESOLVE snapshot of
        // `ShardedNeighborMap::mac_change_epoch()` — read BEFORE the neighbor
        // MAC backing `decision.resolution` was resolved. Passed as a value so
        // this constructor cannot re-read the live epoch (it has no
        // `dynamic_neighbors` handle): the only source is the caller's
        // pre-resolve capture. Stamping this instead of a post-resolve read
        // closes the resolve→stamp TOCTOU that re-opened the #3048 stale-MAC
        // blackhole on a VRRP gateway MAC failover.
        neighbor_mac_epoch: u32,
    ) -> Option<Self> {
        if !Self::should_cache(meta, decision) {
            return None;
        }
        // #963 PR-A: refuse to *cache* a fast-path descriptor whose
        // ether_type (derived from `meta.addr_family` below) is
        // inconsistent with the address family of `decision.nat`'s
        // rewrite IPs. `apply_rewrite_descriptor`'s v4 arm only
        // writes V4 NAT and its v6 arm only writes V6 NAT, so a
        // mismatched descriptor would silently skip IP NAT while
        // still applying port NAT and a port-only checksum delta —
        // a forwarding-correctness bug, not a memory or checksum
        // bug, but still a bug.
        //
        // Scope of this guard: it prevents the *fast path from
        // persisting* a mismatched descriptor in the flow cache.
        // The generic in-place rewrite path
        // (`rewrite_forwarded_frame_in_place`) and its NAT helpers
        // (`apply_nat_ipv4` / `apply_nat_ipv6`) also gate IP NAT
        // on family-match, so the first packet that triggers the
        // bug still has its IP NAT silently skipped on either
        // path. What PR-A buys is that the bug stays
        // first-packet-only — without this guard, every subsequent
        // packet on the same flow would re-hit the bad cached
        // descriptor and re-skip IP NAT. The flow falls through
        // uncached, gets re-evaluated from policy on each miss,
        // and the upstream NAT pipeline (which should produce a
        // family-consistent decision) gets another chance.
        //
        // The upstream invariant is that NAT rules are typed by
        // family in the policy compiler, so this guard should not
        // fire in practice. We don't rely on the upstream proof:
        // a release-strength check converts unbounded persistent
        // skip into bounded first-packet-only skip. Cost is two
        // enum-discriminant compares per cache miss, not per packet.
        if !nat_family_matches_addr_family(meta.addr_family as i32, &decision.nat) {
            debug_assert!(
                false,
                "RewriteDescriptor af-mismatch refused: addr_family={} \
                 rewrite_src={:?} rewrite_dst={:?}",
                meta.addr_family, decision.nat.rewrite_src, decision.nat.rewrite_dst,
            );
            return None;
        }
        // The flow-cache key is a 5-tuple and does not include DSCP.
        // DSCP-sensitive filters must be re-evaluated on every packet,
        // otherwise a first-packet accept/drop/log/classification
        // decision could be replayed for later packets in the same flow
        // with a different DSCP value.
        let is_v6 = meta.addr_family as i32 == libc::AF_INET6;
        let ingress_ifindex = resolve_ingress_logical_ifindex(
            forwarding,
            meta.ingress_ifindex as i32,
            meta.ingress_vlan_id,
        )
        .unwrap_or(meta.ingress_ifindex as i32);
        if crate::filter::interface_input_filter_has_dscp_match(
            &forwarding.filter_state,
            ingress_ifindex,
            is_v6,
        ) {
            return None;
        }
        if crate::filter::interface_output_filter_has_dscp_match(
            &forwarding.filter_state,
            decision.resolution.egress_ifindex,
            is_v6,
        ) {
            return None;
        }
        // #2362: same coherency hazard for per-packet L4 match terms
        // (tcp-flags / is-fragment / icmp-type / icmp-code). They are not in
        // the 5-tuple flow-cache key and vary per packet within a flow, so a
        // cached first-packet decision must not be replayed. Decline the cache
        // whenever the ingress input filter or the resolved egress output
        // filter carries such a term.
        if crate::filter::interface_input_filter_has_per_packet_l4_match(
            &forwarding.filter_state,
            ingress_ifindex,
            is_v6,
        ) {
            return None;
        }
        if crate::filter::interface_output_filter_has_per_packet_l4_match(
            &forwarding.filter_state,
            decision.resolution.egress_ifindex,
            is_v6,
        ) {
            return None;
        }
        // Keep cache invalidation tied to the flow owner RG, not the current
        // fabric parent ifindex. During split-RG operation a live flow can
        // temporarily resolve to FabricRedirect, but failback must still evict
        // that cached redirect as soon as the owning RG flips locally.
        let owner_rg_id = if flow_owner_rg_id > 0 {
            flow_owner_rg_id
        } else {
            owner_rg_for_resolution(forwarding, decision.resolution)
        };
        // #3642: the egress output firewall filter matches the POST-NAT on-wire
        // tuple (Junos applies output filters AFTER NAT). Feed the cached
        // TX-selection the egress wire key derived from the pre-NAT session key
        // + this flow's NAT decision, not the raw pre-NAT `forward_key`. NAT64
        // is never cached (`should_cache` excludes it), so this only rewrites
        // the SNAT/DNAT address/port fields; the cache LOOKUP `key` below stays
        // the pre-NAT tuple (matched against the parsed ingress flow).
        // #5158: the post-NAT wire key is correct for the egress OUTPUT filter,
        // but the ingress INPUT filter matched this packet on its PRE-NAT ingress
        // tuple (Junos applies input filters BEFORE NAT). Seed the cached
        // descriptor with the post-NAT wire key for TX selection and the pre-NAT
        // `forward_key` as the ingress re-walk key so a NAT'd flow's cached
        // descriptor still carries the ingress `then forwarding-class` /
        // dscp-rewrite / three-color policer.
        let tx_selection_wire_key = forward_wire_key(&flow.forward_key, decision.nat);
        let tx_selection = resolve_cached_cos_tx_selection_prenat(
            forwarding,
            decision.resolution.egress_ifindex,
            meta,
            &tx_selection_wire_key,
            &flow.forward_key,
        );
        // #3777: the cos TX-selection rebuild folds an interface INPUT filter's
        // `then count` handles into `tx_selection.filter_counters` when the
        // egress interface has no output filter. Drop those from the dedicated
        // input replay set so a count-plus-forwarding-class input term is
        // recorded once per hit, not twice.
        let mut input_filter_counters = input_filter_counters;
        input_filter_counters.retain_absent_from(&tx_selection.filter_counters);
        // #5147: the shard of this flow's resolved next-hop neighbor
        // `(neighbor_ifindex, next_hop)`, where `neighbor_ifindex` is the
        // ifindex the neighbor is actually keyed under in the ShardedNeighborMap
        // — the OUTER transport ifindex for a tunnel (gr-/wg-) egress, NOT the
        // logical tunnel `egress_ifindex`. `outer_neighbor_ifindex` returns
        // `egress_ifindex` unchanged for a direct/connected/static resolution
        // (identical to the pre-#5147-review behavior) and the outer ifindex for
        // a tunnel, matching the `(ifindex, ip)` key `insert_if_changed` bumps
        // on when the kernel updates the OUTER neighbor. Keying on the logical
        // `egress_ifindex` for tunnels (the review MAJOR) stamped a DIFFERENT
        // shard than the bump, so a tunnel flow never evicted on its outer
        // gateway's MAC change — a #3048 stale-MAC blackhole. `neighbor_shard`
        // scopes the MAC-change invalidation: only a change to a neighbor in
        // THIS shard evicts the entry (targeted, per #5147), not every neighbor
        // change. A cacheable disposition (ForwardCandidate / FabricRedirect)
        // always carries a next-hop; the `None` arm marks a
        // no-dynamic-neighbor-dependency flow that is never MAC-stale. NOTE:
        // this MUST use the IDENTICAL computation as the pre-resolve epoch
        // snapshot key in poll_descriptor (`outer_neighbor_ifindex(.., None,
        // ..)`), or the stamped epoch and this shard would key different shards.
        let neighbor_shard = match decision.resolution.next_hop {
            Some(nh) => crate::afxdp::sharded_neighbor::ShardedNeighborMap::shard_index(&(
                crate::afxdp::forwarding::outer_neighbor_ifindex(
                    forwarding,
                    None,
                    &decision.resolution,
                ),
                nh,
            )) as u16,
            None => NEIGHBOR_SHARD_NONE,
        };
        Some(Self {
            key: flow.forward_key.clone(),
            // Physical parent for set placement / invalidation coherence.
            ingress_ifindex: meta.ingress_ifindex as i32,
            // #5139: the LOGICAL (VLAN-selecting) ingress ifindex resolved above
            // (`ingress_ifindex` local) is the zone-selecting identity; stamp it
            // as the additional in-set match discriminator.
            logical_ingress_ifindex: ingress_ifindex,
            descriptor: RewriteDescriptor {
                dst_mac: decision.resolution.neighbor_mac.unwrap_or([0; 6]),
                src_mac: decision.resolution.src_mac.unwrap_or([0; 6]),
                fabric_redirect: decision.resolution.disposition
                    == ForwardingDisposition::FabricRedirect,
                tx_vlan_id: decision.resolution.tx_vlan_id,
                ether_type: if meta.addr_family as i32 == libc::AF_INET {
                    0x0800
                } else {
                    0x86dd
                },
                rewrite_src_ip: decision.nat.rewrite_src,
                rewrite_dst_ip: decision.nat.rewrite_dst,
                rewrite_src_port: decision.nat.rewrite_src_port,
                rewrite_dst_port: decision.nat.rewrite_dst_port,
                ip_csum_delta: compute_ip_csum_delta(flow, &decision.nat),
                l4_csum_delta: compute_l4_csum_delta(flow, &decision.nat),
                egress_ifindex: decision.resolution.egress_ifindex,
                tx_ifindex: decision.resolution.tx_ifindex,
                target_binding_index,
                input_filter_log,
                input_filter_counters,
                tx_selection,
                nat64: false,
                // #2652: carry the NPTv6 flag so the descriptor fast path
                // routes through the IPv6 arm with a zero L4 csum delta
                // (checksum-neutral). NAT64 is never cached (gated out in
                // `should_cache`), so its flag stays false here.
                nptv6: decision.nat.nptv6,
                apply_nat_on_fabric,
            },
            decision,
            metadata: SessionMetadata {
                ingress_zone: ingress_zone.unwrap_or(0),
                egress_zone: 0,
                ingress_zone_check: crate::session::zone_vintage_check_for_id(
                    &forwarding.zone_id_to_name,
                    ingress_zone.unwrap_or(0),
                ),
                egress_zone_check: 0,
                ingress_ifindex: 0,
                ingress_vlan_id: 0,
                owner_rg_id,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
                // #2508: flow-cache seed carries no per-policy `then log`.
                log_session_init: false,
                log_session_close: false,
                // #3056: the flow-cache descriptor metadata is replay state for an
                // already-installed session (the install on the slow path stamps
                // the real policy ID); this seed value is never published itself.
                policy_id: 0,
                // #3227: the real per-app idle timeout is stamped by the
                // slow-path install; the flow-cache seed uses the global one.
                inactivity_timeout_ns: None,
                // #3073: the flow-cache hit path re-counts every packet against
                // the admitting policy, so the seed needs the real handle. This
                // constructor leaves it 0; the population site
                // (`poll_descriptor`) stamps `entry.metadata.policy_counter_idx`
                // from the established flow's metadata after construction.
                policy_counter_idx: 0,
                policy_counter: None,
            },
            stamp: FlowCacheStamp::capture(
                validation.config_generation,
                validation.fib_generation,
                owner_rg_id,
                ha_state,
                rg_epochs,
            ),
            observed_bytes: u64::from(meta.pkt_len),
            // #1219: 0 = "never touched"; first lookup hit will stamp
            // it with the current epoch.
            last_used_epoch: 0,
            // #3048/#3918/#5147: the neighbor-MAC-change epoch is captured by
            // the caller BEFORE it resolves the neighbor MAC for `decision`
            // (the caller owns the `dynamic_neighbors` handle) and passed in
            // as `neighbor_mac_epoch` — the pre-resolve snapshot value for the
            // resolved neighbor's OWN shard (`neighbor_shard`, above). Reading
            // it pre-resolve — instead of a fresh post-resolve shard read at
            // stamp time — closes the resolve→stamp TOCTOU: a MAC change
            // landing between the resolve and here advances the live shard
            // epoch past this stamped (older) value, so the entry is treated
            // stale on its next fast-path hit (`neighbor_mac_epoch_stale`) and
            // re-resolved to the current MAC instead of blackholing on the
            // pre-failover MAC.
            neighbor_mac_epoch,
            neighbor_shard,
        })
    }
}

/// Per-worker flow cache. 4-way set-associative with LRU eviction
/// within each set (#918). Layout: `FLOW_CACHE_SETS = 1024` sets,
/// each holding `FLOW_CACHE_WAYS = 4` ways. The `entries` vec
/// is stored row-major: set `s` occupies indices
/// `[s * WAYS, s * WAYS + WAYS)`. Per set, `lru[s]` is a
/// permutation of `[0, 1, 2, 3]` where index 0 is MRU and
/// index 3 is LRU.
pub(super) struct FlowCache {
    pub(super) entries: Vec<Option<FlowCacheEntry>>,
    /// Per-set LRU permutation. `lru[s][0]` = MRU way, `lru[s][3]` = LRU way.
    /// Initialized to `[0, 1, 2, 3]` for every set so eviction order on a
    /// fresh set is deterministic.
    pub(super) lru: Vec<[u8; FLOW_CACHE_WAYS]>,
    pub(super) hits: u64,
    pub(super) misses: u64,
    pub(super) evictions: u64,
    /// Collision evictions = inserts that displaced a different-key entry
    /// (i.e. the set was full and we kicked out the LRU way). Tracked
    /// separately from `evictions` (which also counts stale-on-lookup
    /// evictions) for hot-set diagnosis.
    pub(super) collision_evictions: u64,
    /// #1219: per-binding epoch counter for the active-flow-count signal.
    /// Owner-only state. Incremented on the existing ~65ms worker tick via
    /// `tick_advance_epoch()`. `lookup()` writes this value into
    /// `entry.last_used_epoch` on every hit so `count_active_flows()` can
    /// distinguish entries touched within the last `ACTIVE_WINDOW_EPOCHS`
    /// ticks (= 10 × ~65ms ≈ 650ms window).
    pub(super) current_epoch: u16,
}

impl FlowCache {
    pub(super) fn new() -> Self {
        Self {
            entries: (0..FLOW_CACHE_SIZE).map(|_| None).collect(),
            lru: vec![[0u8, 1, 2, 3]; FLOW_CACHE_SETS],
            hits: 0,
            misses: 0,
            evictions: 0,
            collision_evictions: 0,
            current_epoch: 1,
        }
    }

    /// #1219: advance the per-binding active-flow epoch counter.
    /// Called from the worker's existing ~65ms tick. Wrapping u16
    /// arithmetic; `count_active_flows` uses `wrapping_sub` to be
    /// safe across the wrap boundary. Epoch 0 is reserved as the
    /// "never touched" sentinel in `FlowCacheEntry::last_used_epoch`;
    /// skip it on wraparound so the sentinel invariant holds forever.
    pub(super) fn tick_advance_epoch(&mut self) {
        self.current_epoch = match self.current_epoch.wrapping_add(1) {
            0 => 1, // skip sentinel value
            n => n,
        };
    }

    /// #1219: count cache entries hit in the last `ACTIVE_WINDOW_EPOCHS`
    /// ticks. Epoch advance is driven by the umem debug-publish gate:
    /// hot polling uses the 0xFFFF-call counter, while RX-empty idle polling
    /// uses a ~65ms wall-clock cadence. 10 epochs ≈ 650 ms. Owner-only
    /// periodic scan; not on the hot path.
    /// O(N) over `FLOW_CACHE_SIZE` (4096 entries, see top of this file).
    #[cfg(test)]
    pub(super) fn count_active_flows(&self) -> u32 {
        let mut active = 0u32;
        for slot in self.entries.iter() {
            if let Some(entry) = slot {
                if self.active_entry_age(entry).is_some() {
                    active = active.saturating_add(1);
                }
            }
        }
        active
    }

    /// Age predicate for the test-only `count_active_flows` counter.
    /// The production scan (`active_flow_debug_entries`) inlines the
    /// same math so it can clamp under the `iter_mut` borrow.
    /// NOTE (#1741): this helper does NOT clamp; the wrap-ghost
    /// protection lives in `active_flow_debug_entries`, which
    /// sentinel-clears out-of-window stamps on every scan.
    #[cfg(test)]
    fn active_entry_age(&self, entry: &FlowCacheEntry) -> Option<u16> {
        // last_used_epoch == 0 marks "never touched"; skip.
        if entry.last_used_epoch == 0 {
            return None;
        }
        let age = self.current_epoch.wrapping_sub(entry.last_used_epoch);
        (age < ACTIVE_WINDOW_EPOCHS).then_some(age)
    }

    /// #1249: return a bounded active-flow debug map from the same
    /// owner-only scan that backs `count_active_flows`. This runs on
    /// the worker's debug/status cadence, not in the packet path.
    ///
    /// #1741: the scan also SENTINEL-CLEARS (`last_used_epoch = 0`) every
    /// entry whose age has left the `ACTIVE_WINDOW_EPOCHS` window. Both
    /// stamps are u16 with a 65535-tick cycle, so without the clamp a
    /// dead entry's frozen stamp re-enters the window for exactly
    /// `ACTIVE_WINDOW_EPOCHS` ticks once per wrap ("ghost resurrection"),
    /// intermittently inflating `cos_active_flow_count` and every derived
    /// fairness gauge. The clamp is airtight because `tick_advance_epoch`
    /// and this scan are co-located at the single production call site
    /// (`umem/debug_state.rs::publish_binding_debug_state`, reached from
    /// both the hot mask path and the #1294 idle wall-clock path): an
    /// entry is cleared on the first scan after leaving the window and a
    /// wrapped `current_epoch` can never re-match it. A clamped entry is
    /// NOT evicted — a later lookup hit re-stamps it and it counts again.
    /// Restored invariant: counted active ⇔ hit within the last
    /// `ACTIVE_WINDOW_EPOCHS` ticks, with no wrap exception.
    pub(super) fn active_flow_debug_entries(
        &mut self,
        limit: usize,
    ) -> (u32, Vec<FlowCacheDebugEntry>, Vec<CoSActiveFlowCount>, bool) {
        let limit = limit.min(FLOW_CACHE_SIZE);
        let mut active = 0u32;
        let mut truncated = false;
        let mut rows = Vec::with_capacity(limit.min(64));
        let mut cos_counts = BTreeMap::<(i32, u8), u32>::new();
        // Copy the epoch to a local: the age math must run inside the
        // `iter_mut` borrow below, where `self.active_entry_age` (a
        // `&self` method) is not callable.
        let current_epoch = self.current_epoch;
        for slot in self.entries.iter_mut() {
            let Some(entry) = slot else {
                continue;
            };
            if entry.last_used_epoch == 0 {
                continue;
            }
            let age_epochs = current_epoch.wrapping_sub(entry.last_used_epoch);
            if age_epochs >= ACTIVE_WINDOW_EPOCHS {
                // #1741: out of the active window — sentinel-clear so the
                // u16 wrap can never resurrect this stamp. Owner-only
                // store on the debug cadence; not on the packet path.
                entry.last_used_epoch = 0;
                continue;
            }
            active = active.saturating_add(1);
            if let Some(queue_id) = entry.descriptor.tx_selection.queue_id {
                let key = (entry.descriptor.egress_ifindex, queue_id);
                let count = cos_counts.entry(key).or_insert(0);
                *count = count.saturating_add(1);
            }
            if rows.len() >= limit {
                truncated = true;
                continue;
            }
            let forward_wire = forward_wire_key(&entry.key, entry.decision.nat);
            let reverse_canonical = reverse_canonical_key(&entry.key, entry.decision.nat);
            rows.push(FlowCacheDebugEntry {
                ingress_ifindex: entry.ingress_ifindex,
                egress_ifindex: entry.descriptor.egress_ifindex,
                tx_ifindex: entry.descriptor.tx_ifindex,
                session_key: crate::protocol::FlowTupleStatus::from_session_key(&entry.key),
                forward_wire_key: crate::protocol::FlowTupleStatus::from_session_key(&forward_wire),
                reverse_canonical_key: crate::protocol::FlowTupleStatus::from_session_key(
                    &reverse_canonical,
                ),
                cos_queue_id: entry.descriptor.tx_selection.queue_id,
                dscp_rewrite: entry.descriptor.tx_selection.dscp_rewrite,
                age_epochs,
                observed_bytes: entry.observed_bytes,
            });
        }
        let cos_counts = cos_counts
            .into_iter()
            .map(
                |((ifindex, queue_id), active_flow_count)| CoSActiveFlowCount {
                    ifindex,
                    queue_id,
                    active_flow_count,
                },
            )
            .collect();
        (active, rows, cos_counts, truncated)
    }

    /// Set index = low bits of the FxHasher-produced flow hash.
    ///
    /// #2364: the hasher is now SEEDED with the per-boot, per-process
    /// secret (`crate::hot_hash_seed::hot_path_hash_seed`) instead of
    /// `FxHasher::default()`. The set index is keyed by the
    /// attacker-controllable 5-tuple + ingress ifindex; with the unseeded
    /// default an off-box sender could precompute keys whose low
    /// `FLOW_CACHE_SET_MASK` bits all collide in one 4-way set, forcing
    /// steady eviction churn (algorithmic-complexity DoS). Folding the
    /// per-boot seed in (FxHasher writes the seed first, so the cost is a
    /// single extra word write — no per-packet allocation) makes the
    /// mapping unknowable offline and reshuffled on every restart. The
    /// seed is WORKER/PROCESS-LOCAL: the flow cache is never synced and is
    /// not part of any wire protocol, so a per-node seed is correct (HA
    /// peers re-derive their own sets from the explicit SessionKey). The
    /// seed is stable for the process lifetime, so a given flow maps to a
    /// stable set across its whole lifetime — cache consistency is
    /// preserved. The `& FLOW_CACHE_SET_MASK` masking and 4-way layout are
    /// unchanged.
    #[inline]
    pub(super) fn set_index(key: &crate::session::SessionKey, ingress_ifindex: i32) -> usize {
        Self::set_index_seeded(crate::hot_hash_seed::hot_path_hash_seed(), key, ingress_ifindex)
    }

    /// Seed-parameterized core of `set_index`. Split out so adversarial
    /// tests can pin the seed and assert (a) intra-seed stability and
    /// (b) cross-seed reshuffling of the set distribution. Production
    /// always calls through `set_index`, which supplies the per-boot
    /// process seed.
    #[inline]
    pub(super) fn set_index_seeded(
        seed: u64,
        key: &crate::session::SessionKey,
        ingress_ifindex: i32,
    ) -> usize {
        use std::hash::{Hash, Hasher};

        let mut hasher = rustc_hash::FxHasher::with_seed(seed as usize);
        key.hash(&mut hasher);
        (ingress_ifindex as u32).hash(&mut hasher);
        hasher.finish() as usize & FLOW_CACHE_SET_MASK
    }

    /// Promote `way` to the MRU position in `lru[set]`, shifting the
    /// preceding entries down by one. Branchless 3-element shuffle.
    #[inline]
    fn promote_lru(&mut self, set: usize, way: u8) {
        let row = &mut self.lru[set];
        // Find current position of `way`.
        let mut pos = 0usize;
        for i in 0..FLOW_CACHE_WAYS {
            if row[i] == way {
                pos = i;
                break;
            }
        }
        if pos == 0 {
            return; // already MRU
        }
        // Shift row[0..pos] down by one, write `way` at row[0].
        for i in (1..=pos).rev() {
            row[i] = row[i - 1];
        }
        row[0] = way;
    }

    /// Demote `way` to the LRU position in `lru[set]`, shifting the
    /// following entries up by one.
    #[inline]
    fn demote_lru(&mut self, set: usize, way: u8) {
        let row = &mut self.lru[set];
        let mut pos = 0usize;
        for i in 0..FLOW_CACHE_WAYS {
            if row[i] == way {
                pos = i;
                break;
            }
        }
        if pos == FLOW_CACHE_WAYS - 1 {
            return; // already LRU
        }
        for i in pos..(FLOW_CACHE_WAYS - 1) {
            row[i] = row[i + 1];
        }
        row[FLOW_CACHE_WAYS - 1] = way;
    }

    #[cfg(test)]
    #[inline]
    pub(super) fn lookup(
        &mut self,
        key: &crate::session::SessionKey,
        lookup: FlowCacheLookup,
        now_secs: u64,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    ) -> Option<&FlowCacheEntry> {
        self.lookup_with_observed_bytes(key, lookup, now_secs, rg_epochs, 0)
    }

    #[inline]
    pub(super) fn lookup_counted(
        &mut self,
        key: &crate::session::SessionKey,
        lookup: FlowCacheLookup,
        now_secs: u64,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
        packet_len: u16,
    ) -> Option<&FlowCacheEntry> {
        self.lookup_with_observed_bytes(key, lookup, now_secs, rg_epochs, u64::from(packet_len))
    }

    #[inline]
    fn lookup_with_observed_bytes(
        &mut self,
        key: &crate::session::SessionKey,
        lookup: FlowCacheLookup,
        now_secs: u64,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
        observed_bytes: u64,
    ) -> Option<&FlowCacheEntry> {
        let set = Self::set_index(key, lookup.ingress_ifindex);
        let base = set * FLOW_CACHE_WAYS;
        // Key-first, generation-second: scan the set for a key match.
        // A key-match with stale generation is a guaranteed-bad cache
        // entry under the §3.4.2 dedup invariant (at most one way per
        // set holds a given key), so it's safe to evict immediately
        // and return MISS.
        for way in 0..FLOW_CACHE_WAYS {
            let entry_idx = base + way;
            if let Some(entry) = &self.entries[entry_idx] {
                // #5139: identity requires the SAME logical (VLAN-selecting)
                // ingress ifindex, not just the same 5-tuple + physical parent
                // — otherwise two co-parented VLAN units with one 5-tuple alias
                // and VLAN B replays VLAN A's decision/NAT/egress before the
                // slow-path zone-pair policy runs (cross-zone fail-open).
                if entry.key != *key
                    || entry.ingress_ifindex != lookup.ingress_ifindex
                    || entry.logical_ingress_ifindex != lookup.logical_ingress_ifindex
                {
                    continue;
                }
                // Key match. Validate generation/epoch/lease.
                if entry.stamp.config_generation != lookup.config_generation
                    || entry.stamp.fib_generation != lookup.fib_generation
                {
                    self.entries[entry_idx] = None;
                    self.evictions += 1;
                    self.demote_lru(set, way as u8);
                    self.misses += 1;
                    return None;
                }
                // #2466: re-check against the SAME epoch slot capture stamped
                // (rg_epoch_index), so out-of-range high RG ids and rg <= 0
                // both invalidate on the node-level rg_epochs[0] edge instead
                // of never. Mirrors the worker session-expiry gate.
                let owner = entry.stamp.owner_rg_id;
                let current_epoch = rg_epochs[rg_epoch_index(owner)].load(Ordering::Relaxed);
                if current_epoch != entry.stamp.owner_rg_epoch {
                    self.entries[entry_idx] = None;
                    self.evictions += 1;
                    self.demote_lru(set, way as u8);
                    self.misses += 1;
                    return None;
                }
                if entry.stamp.owner_rg_lease_until != 0
                    && now_secs > entry.stamp.owner_rg_lease_until
                {
                    self.entries[entry_idx] = None;
                    self.evictions += 1;
                    self.demote_lru(set, way as u8);
                    self.misses += 1;
                    return None;
                }
                // Fresh hit.
                self.promote_lru(set, way as u8);
                self.hits += 1;
                // #1219: stamp the entry with the current epoch so the
                // periodic count_active_flows scan can recognize this
                // flow as active in the last ~650 ms window. Single u16 store
                // on a struct already in cache from the key check above.
                // Use a single mutable borrow: stamp the epoch and coerce
                // to &FlowCacheEntry in one index, eliminating the
                // redundant second `self.entries[entry_idx]` access.
                let now = self.current_epoch;
                let entry = self.entries[entry_idx].as_mut().expect(
                    "BUG: entry at entry_idx is None after key match — impossible cache state",
                );
                entry.last_used_epoch = now;
                entry.observed_bytes = entry.observed_bytes.saturating_add(observed_bytes);
                return Some(entry);
            }
        }
        self.misses += 1;
        None
    }

    pub(super) fn insert(&mut self, entry: FlowCacheEntry) {
        let set = Self::set_index(&entry.key, entry.ingress_ifindex);
        let base = set * FLOW_CACHE_WAYS;
        // Dedup-on-insert: if this set already holds the same key
        // (e.g. a stale entry that the caller is about to overwrite
        // with a fresh decision), find-and-replace that way rather
        // than allocating a new way. Preserves the "at most one way
        // per set holds a given key" invariant the lookup path relies
        // on.
        for way in 0..FLOW_CACHE_WAYS {
            let entry_idx = base + way;
            if let Some(existing) = &self.entries[entry_idx] {
                // #5139: an in-place update targets the SAME identity — same
                // 5-tuple, same physical parent, AND same logical VLAN — so a
                // second VLAN's insert allocates a distinct way instead of
                // overwriting the first VLAN's entry.
                if existing.key == entry.key
                    && existing.ingress_ifindex == entry.ingress_ifindex
                    && existing.logical_ingress_ifindex == entry.logical_ingress_ifindex
                {
                    self.entries[entry_idx] = Some(entry);
                    self.promote_lru(set, way as u8);
                    return;
                }
            }
        }
        // No matching key: prefer an empty way; otherwise evict LRU.
        for way in 0..FLOW_CACHE_WAYS {
            let entry_idx = base + way;
            if self.entries[entry_idx].is_none() {
                self.entries[entry_idx] = Some(entry);
                self.promote_lru(set, way as u8);
                return;
            }
        }
        // Set is full — evict the LRU way.
        let lru_way = self.lru[set][FLOW_CACHE_WAYS - 1];
        let entry_idx = base + (lru_way as usize);
        self.entries[entry_idx] = Some(entry);
        self.evictions += 1;
        self.collision_evictions += 1;
        self.promote_lru(set, lru_way);
    }

    /// Nuclear invalidation — clears every entry. Reserved for rare events
    /// like link-cycle or full config reload where epoch-based invalidation
    /// is insufficient (e.g. routing table rebuild, interface renumbering).
    #[allow(dead_code)]
    pub(super) fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            *entry = None;
        }
        // LRU permutations are reset to canonical order; eviction
        // order on the next inserts to a cleared set is deterministic.
        for row in &mut self.lru {
            *row = [0, 1, 2, 3];
        }
    }

    /// #5190 (A1-b1-F6): the caller's DYNAMIC validation rejected a candidate
    /// that `lookup_with_observed_bytes` had already accounted as a served
    /// hit.
    ///
    /// The lookup commits `hits += 1` (plus the LRU promote, the
    /// `last_used_epoch` stamp and the `observed_bytes` add) the moment
    /// key/generation/epoch/lease pass, because it must hand the caller a
    /// borrow of the entry and cannot hold a mutable borrow across the
    /// caller's own validation. The caller then re-checks two things the
    /// cache cannot see — the per-shard neighbor MAC epoch (#3048/#5147) and
    /// the HA/fabric decision validity — and on failure evicts the slot and
    /// falls through to the slow path. That packet was NOT served from the
    /// cache, so counting it as a hit inflates the published hit rate exactly
    /// when it should be falling: during gateway VRRP failover, a NIC swap or
    /// an RG transition, i.e. the moments an operator looks at the hit rate to
    /// diagnose a stall.
    ///
    /// The per-entry state (`last_used_epoch`, `observed_bytes`, the LRU
    /// promote) needs no undo — the caller's `invalidate_slot` removes the
    /// entry outright, taking that state with it. Only the three tallies
    /// outlive it, so only they are corrected here. This runs on the REJECT
    /// branch only (a neighbor MAC change / HA invalidation), never on the
    /// steady-state hit path, so the fast path is untouched.
    #[inline]
    pub(super) fn reclassify_hit_as_miss(&mut self) {
        self.hits = self.hits.saturating_sub(1);
        self.misses += 1;
        self.evictions += 1;
    }

    pub(super) fn invalidate_slot(
        &mut self,
        key: &crate::session::SessionKey,
        ingress_ifindex: i32,
    ) {
        let set = Self::set_index(key, ingress_ifindex);
        let base = set * FLOW_CACHE_WAYS;
        for way in 0..FLOW_CACHE_WAYS {
            let entry_idx = base + way;
            if let Some(existing) = &self.entries[entry_idx] {
                if existing.key == *key && existing.ingress_ifindex == ingress_ifindex {
                    self.entries[entry_idx] = None;
                    self.demote_lru(set, way as u8);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "flow_cache_tests.rs"]
mod tests;
