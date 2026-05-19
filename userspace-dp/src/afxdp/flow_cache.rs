use super::*;
use std::collections::BTreeMap;
use std::sync::Arc;
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

/// Maximum number of redundancy groups for epoch-based cache invalidation.
pub(super) const MAX_RG_EPOCHS: usize = 16;

#[derive(Clone, Debug, Default)]
pub(super) struct CachedTxSelectionDescriptor {
    pub(super) queue_id: Option<u8>,
    pub(super) dscp_rewrite: Option<u8>,
    pub(super) filter_counter: Option<Arc<crate::filter::FilterTermCounter>>,
    pub(super) three_color_policers: crate::filter::CachedThreeColorPolicers,
    pub(super) filter_log: Option<crate::filter::FilterLogMatch>,
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
            owner_rg_epoch: if owner_rg_id > 0 && (owner_rg_id as usize) < MAX_RG_EPOCHS {
                rg_epochs[owner_rg_id as usize].load(Ordering::Relaxed)
            } else {
                0
            },
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
    pub(super) ingress_ifindex: i32,
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
}

impl FlowCacheLookup {
    #[inline]
    pub(super) fn for_packet(meta: UserspaceDpMeta, validation: ValidationState) -> Self {
        Self {
            ingress_ifindex: meta.ingress_ifindex as i32,
            config_generation: validation.config_generation,
            fib_generation: validation.fib_generation,
        }
    }
}

/// Per-flow cache entry with key validation.
#[derive(Clone)]
pub(super) struct FlowCacheEntry {
    pub(super) key: crate::session::SessionKey,
    pub(super) ingress_ifindex: i32,
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
    pub(super) last_used_epoch: u16,
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
        (meta.protocol == PROTO_TCP && (meta.tcp_flags & 0x17) == 0x10)
            || meta.protocol == PROTO_UDP
    }

    #[inline]
    pub(super) fn should_cache(meta: UserspaceDpMeta, decision: SessionDecision) -> bool {
        matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
            && !decision.nat.nat64
            && !decision.nat.nptv6
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
        forwarding: &ForwardingState,
        ha_state: &BTreeMap<i32, HAGroupRuntime>,
        apply_nat_on_fabric: bool,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
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
        // Keep cache invalidation tied to the flow owner RG, not the current
        // fabric parent ifindex. During split-RG operation a live flow can
        // temporarily resolve to FabricRedirect, but failback must still evict
        // that cached redirect as soon as the owning RG flips locally.
        let owner_rg_id = if flow_owner_rg_id > 0 {
            flow_owner_rg_id
        } else {
            owner_rg_for_resolution(forwarding, decision.resolution)
        };
        Some(Self {
            key: flow.forward_key.clone(),
            ingress_ifindex: meta.ingress_ifindex as i32,
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
                tx_selection: resolve_cached_cos_tx_selection(
                    forwarding,
                    decision.resolution.egress_ifindex,
                    meta,
                    Some(&flow.forward_key),
                ),
                nat64: false,
                nptv6: false,
                apply_nat_on_fabric,
            },
            decision,
            metadata: SessionMetadata {
                ingress_zone: ingress_zone.unwrap_or(0),
                egress_zone: 0,
                owner_rg_id,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
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
    pub(super) fn active_flow_debug_entries(
        &self,
        limit: usize,
    ) -> (
        u32,
        Vec<FlowCacheDebugEntry>,
        Vec<CoSActiveFlowCount>,
        bool,
    ) {
        let limit = limit.min(FLOW_CACHE_SIZE);
        let mut active = 0u32;
        let mut truncated = false;
        let mut rows = Vec::with_capacity(limit.min(64));
        let mut cos_counts = BTreeMap::<(i32, u8), u32>::new();
        for slot in self.entries.iter() {
            let Some(entry) = slot else {
                continue;
            };
            let Some(age_epochs) = self.active_entry_age(entry) else {
                continue;
            };
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
            .map(|((ifindex, queue_id), active_flow_count)| CoSActiveFlowCount {
                ifindex,
                queue_id,
                active_flow_count,
            })
            .collect();
        (active, rows, cos_counts, truncated)
    }

    /// Set index = low bits of the FxHasher-produced flow hash.
    /// Same hash function as the prior 1-way layout to preserve
    /// behavior for non-collision keys.
    #[inline]
    pub(super) fn set_index(key: &crate::session::SessionKey, ingress_ifindex: i32) -> usize {
        use std::hash::{Hash, Hasher};

        let mut hasher = rustc_hash::FxHasher::default();
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
                if entry.key != *key || entry.ingress_ifindex != lookup.ingress_ifindex {
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
                let owner = entry.stamp.owner_rg_id;
                if owner > 0 && (owner as usize) < MAX_RG_EPOCHS {
                    let current_epoch = rg_epochs[owner as usize].load(Ordering::Relaxed);
                    if current_epoch != entry.stamp.owner_rg_epoch {
                        self.entries[entry_idx] = None;
                        self.evictions += 1;
                        self.demote_lru(set, way as u8);
                        self.misses += 1;
                        return None;
                    }
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
                let entry = self.entries[entry_idx]
                    .as_mut()
                    .expect("BUG: entry at entry_idx is None after key match — impossible cache state");
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
                if existing.key == entry.key
                    && existing.ingress_ifindex == entry.ingress_ifindex
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
