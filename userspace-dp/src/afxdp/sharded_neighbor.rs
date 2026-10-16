//! #949 PR1: sharded mutex for the dynamic neighbor cache.
//!
//! Replaces the single `Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>`
//! with `Arc<ShardedNeighborMap>` — 64 cache-line-padded shards. Reduces
//! cache-line bouncing on the hot path: every flow-cache miss does a
//! neighbor lookup that previously contended on one mutex.
//!
//! ## Design
//!
//! - 64 shards (`NUM_SHARDS = 64`). Standard choice; matches `dashmap`.
//! - Shard selection uses the per-process keyed hash state shared by the
//!   hot-path placement code, then masks to one of 64 shards (#12794).
//! - Cache-line padding via `#[repr(align(64))]` ensures adjacent
//!   shards do not share cache lines (false-sharing prevention).
//! - Bulk operations via `BulkShardGuard`: locks all 64 shards in
//!   shard-index order. Deadlock-free as long as every other caller
//!   that wants more than one shard also locks in ascending order.
//! - Poison policy: `lock().unwrap_or_else(|e| e.into_inner())`.
//!   Workers DO have a `catch_unwind` supervisor as of #925 Phase 1
//!   (`spawn_supervised_worker` in `coordinator/supervisor.rs`), and #925
//!   Phase 2 surfaces panics on Prometheus
//!   (`xpf_userspace_worker_dead`). But a poisoned `Mutex` here is
//!   operationally worse than a stale MAC for the *surviving* threads:
//!   `NeighborEntry` is plain `[u8; 6]` with no invariants to corrupt,
//!   so the safer choice is to recover-from-poison and keep forwarding.

use super::types::{FastMap, FastSet, NeighborEntry};
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(test)]
thread_local! {
    static LEN_AFTER_SHARD_HOOK: std::cell::RefCell<Option<Box<dyn FnMut(usize)>>> =
        const { std::cell::RefCell::new(None) };
}

use std::sync::{LazyLock, Mutex, MutexGuard};
pub(super) const NUM_SHARDS: usize = 64;

/// #5673: per-shard cap on the number of dynamically LEARNED neighbor
/// entries. Bounds the shared `dynamic_neighbors` map against a
/// spoofed-source pre-policy flood.
///
/// Source-address learning runs on RX (`stage_parse_flow_and_learn`, stage
/// 7+8) BEFORE the screen/policy admission stages, so an attacker on an
/// untrusted segment can send a stream of packets whose L3 source is a
/// distinct, otherwise-plausible unicast IP and — without ever passing a
/// policy check — grow this map by one entry per fake source (codex-review
/// M02 / #5673). Two harms: unbounded memory growth, and every genuine
/// first-sighting insert taking the 64-shard `with_all_shards` bulk lock,
/// serializing all workers (CPU DoS).
///
/// The cap makes a NEW data-path learn whose target shard is already at
/// `MAX_DYNAMIC_NEIGHBORS_PER_SHARD` a no-op (the packet still forwards —
/// this is a learn-path guard, not a packet filter). An UPDATE to an
/// already-learned neighbor (a real MAC failover) is not growth and is
/// never refused, so legitimate established flows keep resolving. The
/// authoritative control-plane push (`bulk_replace_neighbors`) and the
/// on-demand resolver (`insert_confirmed_if_unchanged`) bypass the cap:
/// they install real, topology-bounded next-hops, not attacker-driven ones.
///
/// Sizing and the residual shard-concentration risk: keyed multiply-mix hash prevents an
/// attacker from preparing a fixed address family offline and choosing its
/// target shard. It does not remove the per-shard cap's online or operational
/// limits. Attacker-driven dynamic learns remain bounded to
/// `MAX_DYNAMIC_NEIGHBORS_PER_SHARD` (2048) per shard and
/// `MAX_DYNAMIC_NEIGHBORS` (131072) in aggregate; a flood that manages to
/// concentrate on one live shard can still consume that shard's capacity.
/// Opportunistic pre-warm LEARNING of a legit neighbor whose IP lands on a
/// victim-full shard can be denied, but forwarding to it is NOT lost: the
/// uncapped on-demand resolver (`insert_confirmed_if_unchanged`) still installs
/// the real next-hop at the cost of extra resolver round-trips. Related minor
/// residual: `learn_pair_if_changed` refuses the WHOLE pair if EITHER key is
/// new-at-cap, so a desynced-pair UPDATE could be dropped under concentration
/// (rare; resolver-recovered). The aggregate cap remains far above any
/// realistic learned population (a firewall resolves neighbors for directly
/// connected subnets — a /15 of on-link hosts — not the Internet).
pub(super) const MAX_DYNAMIC_NEIGHBORS_PER_SHARD: usize = 2048;

/// #5673: aggregate cap on dynamically learned neighbor entries. Derived
/// from the per-shard cap and shard count (see
/// `MAX_DYNAMIC_NEIGHBORS_PER_SHARD`, which bounds concentration even when
/// traffic is highly skewed). Exposed for tests and operator capacity reasoning.
pub(crate) const MAX_DYNAMIC_NEIGHBORS: usize = MAX_DYNAMIC_NEIGHBORS_PER_SHARD * NUM_SHARDS;

const _: () = assert!(
    MAX_DYNAMIC_NEIGHBORS_PER_SHARD > 0,
    "per-shard dynamic-neighbor cap must be positive so a genuine learn can land"
);
/// #10704: solicited window for ARP-reply learns (monotonic ns).
///
/// An ARP reply for `(ifindex, ip)` counts as SOLICITED when this router
/// recently asked for it — i.e. a userspace-driven probe from the neighbor
/// warmer, MissingNeighbor path, pending-neighbor retry, or on-demand
/// resolver recorded the key via `ShardedNeighborMap::record_neighbor_probe`
/// within this window. Solicited replies keep the pre-#10704
/// unconditional-learn behavior (they may create, refresh, or overwrite — a
/// re-probed failover converges through this leg).
///
/// Sizing: a MissingNeighbor episode lasts `PENDING_NEIGH_TIMEOUT_NS` (2 s
/// fallback, 800 ms fast) and the kernel runs its own ARP retransmit tail
/// behind each triggered probe, so 5 s covers the whole episode with margin;
/// it also matches `WARM_PER_KEY_RATE_LIMIT_NS`, so a warmer-probed key stays
/// solicited until it becomes re-probeable. An on-segment attacker can still
/// race a solicited reply it observes us request (inherent to any
/// solicited-preference scheme, NDP included) — the gate removes the
/// fire-and-forget unsolicited overwrite, not the race.
pub(super) const ARP_SOLICITED_WINDOW_NS: u64 = 5_000_000_000;

/// Configured idle lease age for an RX source-learned entry that is not
/// subsequently confirmed by the kernel neighbor monitor. Aging adds the
/// coalescing grace below to preserve this minimum idle protection.
pub(crate) const RX_LEARNED_NEIGHBOR_MAX_AGE_NS: u64 = 60_000_000_000;
/// Matching packet lease writes may coalesce for this interval. The aging
/// predicate adds the same grace so stored packet timestamps remain truthful
/// without shortening the configured idle protection.
pub(crate) const RX_LEARNED_NEIGHBOR_REFRESH_INTERVAL_NS: u64 = 1_000_000_000;
pub(crate) const RX_LEARNED_NEIGHBOR_COALESCE_GRACE_NS: u64 =
    RX_LEARNED_NEIGHBOR_REFRESH_INTERVAL_NS;
/// Bound the delay between an entry reaching its idle age and being removed.
pub(crate) const RX_LEARNED_NEIGHBOR_SWEEP_INTERVAL_NS: u64 = 5_000_000_000;

/// #10704: per-shard bound on recorded solicitation keys (see
/// `record_neighbor_probe`). Records are created only after successful local
/// probes; the per-shard cap and amortized pruning bound memory even when many
/// distinct unreachable IPv4 next hops are probed over a long-lived process.
pub(super) const MAX_SOLICITED_KEYS_PER_SHARD: usize = 1024;

/// One mutex-guarded shard of ARP solicitation evidence.
#[repr(align(64))]
struct SolicitedShard(Mutex<FastMap<(i32, IpAddr), u64>>);

impl SolicitedShard {
    fn new() -> Self {
        Self(Mutex::new(FastMap::default()))
    }
}

/// Dynamic-neighbor metadata kept private to the sharded map. RX source
/// learns are the only entries with an age lease; kernel and control-plane
/// updates clear it.
#[derive(Clone, Copy)]
pub(crate) struct NeighborRecord {
    entry: NeighborEntry,
    last_rx_learned_ns: Option<u64>,
}

impl NeighborRecord {
    fn authoritative(entry: NeighborEntry) -> Self {
        Self {
            entry,
            last_rx_learned_ns: None,
        }
    }
}

/// One mutex-guarded shard, padded to 64 bytes so adjacent shards do
/// not share cache lines.
#[repr(align(64))]
pub(super) struct PaddedShard(Mutex<FastMap<(i32, IpAddr), NeighborRecord>>);

impl PaddedShard {
    fn new() -> Self {
        Self(Mutex::new(FastMap::default()))
    }
}

/// 64-shard mutex map for the dynamic neighbor cache.
pub(crate) struct ShardedNeighborMap {
    shards: [PaddedShard; NUM_SHARDS],
    /// #7156: monotonic count of neighbour INSERTS across all shards.
    ///
    /// Read by each worker's `pending_neigh` sweep to answer one question in a
    /// single relaxed load: "could any buffered next-hop have become resolvable
    /// since I last looked?" If not, the sweep skips the resolution walk over
    /// every pending key -- which is where its whole O(all-keys) cost lived,
    /// one shard MUTEX per key.
    ///
    /// Deliberately a COUNTER over the whole map, not a per-shard epoch. It is
    /// read once per sweep and never keyed, so per-shard resolution would buy
    /// nothing: a worker cannot know which shard a pending key hashes to
    /// without walking its keys, which is the walk being avoided.
    ///
    /// Distinct from the per-shard neighbor-resolution epoch above, which
    /// advances on an existing neighbor's MAC replacement or actual removal.
    /// This is the wrong signal here: a pending key is waiting for its
    /// neighbor to APPEAR, and a first insert changes no existing mapping.
    insert_generation: AtomicU64,
    /// #5147: PER-SHARD neighbor-resolution epochs. Bumped only when an
    /// existing neighbor's MAC changes or an existing key is removed, and
    /// only on the epoch of the shard holding that key. The worker flow cache
    /// stamps the resolved next-hop shard into each cached forwarding
    /// descriptor and re-reads that slot on every fast-path hit; a mismatch
    /// means the descriptor's destination MAC or neighbor liveness may be
    /// stale, so the entry is evicted and the next packet re-resolves.
    ///
    /// This replaces the single global `mac_change_epoch` that made ANY
    /// neighbor change invalidate EVERY cached flow. An on-link sender
    /// alternating one IP's MAC advanced that global counter faster than
    /// entries could warm, collapsing the whole flow cache to ~1 packet
    /// (attacker-driven cache thrash / DoS, #5147). With a per-shard epoch a
    /// change on neighbor A evicts a cached flow using neighbor B only in the
    /// rare event A and B hash to the SAME shard (1/NUM_SHARDS), never
    /// map-wide.
    ///
    /// First inserts and same-MAC refreshes do not bump: no existing cached
    /// decision can be stale in either case. An attempted removal of an absent
    /// key also does not bump, while an actual removal does because cached
    /// flows may still depend on that neighbor. `insert_if_changed` checks the
    /// prior entry under the shard lock before overwriting.
    ///
    /// The fast-path read is a single indexed relaxed atomic load + compare
    /// (the shard is precomputed at cache-miss time) — allocation-free per
    /// docs/engineering-style.md hot-path rules.
    shard_mac_epochs: [AtomicU32; NUM_SHARDS],

    /// #5673: cumulative count of data-path neighbor LEARNS refused because
    /// the target shard was already at `MAX_DYNAMIC_NEIGHBORS_PER_SHARD`. A
    /// nonzero, growing value means the aggregate neighbor-map cap is
    /// bounding a spoofed-source pre-policy flood (source learning runs on
    /// RX before screen/policy admission). Relaxed — observability only, and
    /// off the fast path except on an actual refusal.
    learn_cap_drops: AtomicU64,
    /// #10704: bounded evidence that this router recently probed an ARP key.
    /// Entries are keyed/sharded exactly like `shards`; no allocation or
    /// extra work occurs for non-ARP packets.
    arp_solicited_at: [SolicitedShard; NUM_SHARDS],
    /// #10704: cumulative count of unsolicited ARP/neighbor updates refused
    /// because they tried to replace a live differing MAC.
    arp_overwrite_refusals: AtomicU64,
    /// #11069: cumulative count of unsolicited Override=1 NAs refused
    /// because they tried to replace a live differing LLA (solicited
    /// Override=1 still converges legitimate failover).
    na_unsolicited_override_refusals: AtomicU64,
    /// #10854: cumulative count of pre-policy RX source-learns refused
    /// because they tried to overwrite a live entry's differing MAC.
    /// Source learning runs on RX before screen/policy admission, so the
    /// pre-policy arm is create-only; an admitted packet re-learns through
    /// the post-admission legs (slow-path forward choke + flow-cache-hit
    /// forward), which is what keeps a refusal from wedging a genuine MAC
    /// move. Relaxed — observability only, off the fast path except on a
    /// refusal.
    rx_learn_overwrite_refusals: AtomicU64,
}

/// Seeded keyed-hash shard selection prevents offline targeting of the
/// per-shard learn cap (#7752/#12794). The process seed is node-local and stable
/// for this process.
const _: () = assert!(NUM_SHARDS.is_power_of_two());
static SHARD_SEED: LazyLock<u64> = LazyLock::new(crate::hot_hash_seed::hot_path_hash_seed);

#[inline]
fn shard_idx_with(seed: u64, key: &(i32, IpAddr)) -> usize {
    let mut hasher = crate::hot_hash_seed::HotPathSeededState::new(seed).build_hasher();
    key.hash(&mut hasher);
    (hasher.finish() as usize) & (NUM_SHARDS - 1)
}

fn shard_idx(key: &(i32, IpAddr)) -> usize {
    shard_idx_with(*SHARD_SEED, key)
}

impl ShardedNeighborMap {
    pub(crate) fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| PaddedShard::new()),
            arp_solicited_at: std::array::from_fn(|_| SolicitedShard::new()),
            shard_mac_epochs: std::array::from_fn(|_| AtomicU32::new(0)),
            learn_cap_drops: AtomicU64::new(0),
            insert_generation: AtomicU64::new(0),
            arp_overwrite_refusals: AtomicU64::new(0),
            na_unsolicited_override_refusals: AtomicU64::new(0),
            rx_learn_overwrite_refusals: AtomicU64::new(0),
        }
    }
    /// #10854: refused pre-policy transit learns that would overwrite a
    /// neighbor with a different MAC.
    #[cfg(test)]
    pub(crate) fn rx_learn_overwrite_refusals(&self) -> u64 {
        self.rx_learn_overwrite_refusals.load(Ordering::Relaxed)
    }
    /// #10854: account one pre-policy source learn refused because it would
    /// replace an existing neighbor's MAC. Kept distinct from capacity
    /// refusals so existing learn-cap telemetry retains its meaning.
    #[inline]
    pub(crate) fn note_rx_learn_overwrite_refusal(&self) {
        self.rx_learn_overwrite_refusals
            .fetch_add(1, Ordering::Relaxed);
    }

    /// #5673: cumulative data-path learns refused by the aggregate
    /// neighbor-map cap (see `MAX_DYNAMIC_NEIGHBORS_PER_SHARD`). Read by the
    /// operator status surface; a growing value is the signal that a
    /// spoofed-source pre-policy flood is being bounded.
    #[inline]
    pub(crate) fn learn_cap_drops(&self) -> u64 {
        self.learn_cap_drops.load(Ordering::Relaxed)
    }

    /// #5673: account one refused data-path learn. Called from the RX-learn
    /// caller-side short-circuit (`learn_dynamic_neighbor`), which skips the
    /// bulk lock for the all-new-at-cap flood fast path, so the refusal it
    /// makes is still counted exactly like the one `learn_pair_if_changed`
    /// makes under the bulk lock. Relaxed; off the fast path except on a
    /// refusal.
    #[inline]
    pub(crate) fn note_learn_cap_drop(&self) {
        self.learn_cap_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// #10704: record a successfully-issued neighbor-resolution probe so an
    /// ARP reply can be distinguished from a fire-and-forget advert.
    pub(crate) fn record_neighbor_probe(&self, key: (i32, IpAddr), now_ns: u64) {
        // Family-agnostic: IPv4 ARP (#10704) and IPv6 kernel-neighbor
        // solicitation (#13660) share this one-shot evidence store.
        let idx = shard_idx(&key);
        let mut shard = self.arp_solicited_at[idx]
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !shard.contains_key(&key) && shard.len() >= MAX_SOLICITED_KEYS_PER_SHARD {
            shard.retain(|_, probed_at| {
                now_ns.saturating_sub(*probed_at) <= ARP_SOLICITED_WINDOW_NS
            });
            if shard.len() >= MAX_SOLICITED_KEYS_PER_SHARD {
                return;
            }
        }
        shard.insert(key, now_ns);
    }

    /// #13661: peek at recent-probe evidence WITHOUT consuming it.
    /// Authorization is only needed for accepted updates (a first learn or a
    /// differing-MAC replacement); a same-MAC refresh needs no authorization,
    /// so burning the token there makes a genuine MAC move milliseconds later
    /// look unsolicited. Callers peek before insertion and consume the token
    /// only when the insert changed the map.
    pub(crate) fn peek_arp_reply_solicited(&self, key: &(i32, IpAddr), now_ns: u64) -> bool {
        let idx = shard_idx(key);
        let shard = self.arp_solicited_at[idx]
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match shard.get(key) {
            Some(probed_at) => now_ns.saturating_sub(*probed_at) <= ARP_SOLICITED_WINDOW_NS,
            None => false,
        }
    }

    /// #10704: consume the recent-probe evidence for one ARP reply.
    pub(crate) fn take_arp_reply_solicited(&self, key: &(i32, IpAddr), now_ns: u64) -> bool {
        let idx = shard_idx(key);
        let mut shard = self.arp_solicited_at[idx]
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match shard.remove(key) {
            Some(probed_at) => now_ns.saturating_sub(probed_at) <= ARP_SOLICITED_WINDOW_NS,
            None => false,
        }
    }

    /// #10704: count a refused unsolicited ARP overwrite for diagnostics.
    pub(crate) fn note_arp_overwrite_refusal(&self) -> u64 {
        self.arp_overwrite_refusals
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }

    #[cfg(test)]
    pub(crate) fn arp_overwrite_refusals(&self) -> u64 {
        self.arp_overwrite_refusals.load(Ordering::Relaxed)
    }

    /// #11069: count a refused unsolicited Override=1 NA. Returns the new total.
    pub(crate) fn note_na_unsolicited_override_refusal(&self) -> u64 {
        self.na_unsolicited_override_refusals
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }

    #[cfg(test)]
    pub(crate) fn na_unsolicited_override_refusals(&self) -> u64 {
        self.na_unsolicited_override_refusals
            .load(Ordering::Relaxed)
    }

    /// #5673: `get` plus whether the key's shard is at the per-shard learn
    /// cap, under ONE shard lock (same cost as `get`). This plain-read form is
    /// useful to capacity checks; the RX source-learn path uses
    /// `get_with_capacity_for_rx_learn` to also refresh an existing age lease.
    pub(crate) fn get_with_capacity(&self, key: &(i32, IpAddr)) -> (Option<NeighborEntry>, bool) {
        let shard = self.lock_shard(shard_idx(key));
        let entry = shard.get(key).map(|record| record.entry);
        let at_cap = shard.len() >= MAX_DYNAMIC_NEIGHBORS_PER_SHARD;
        (entry, at_cap)
    }

    /// RX source-learn precheck that monotonically refreshes the lease only
    /// when the packet's MAC agrees with the current RX-learned entry. A
    /// differing pre-policy source must not keep a stale entry alive.
    pub(crate) fn get_with_capacity_for_rx_learn(
        &self,
        key: &(i32, IpAddr),
        mac: [u8; 6],
        now_ns: u64,
    ) -> (Option<NeighborEntry>, bool) {
        let mut shard = self.lock_shard(shard_idx(key));
        let entry = shard.get_mut(key).map(|record| {
            if record.entry.mac == mac && record.last_rx_learned_ns.is_some() {
                record.last_rx_learned_ns = record.last_rx_learned_ns.map(|seen| seen.max(now_ns));
            }
            record.entry
        });
        let at_cap = shard.len() >= MAX_DYNAMIC_NEIGHBORS_PER_SHARD;
        (entry, at_cap)
    }

    /// #5147: shard index for a neighbor key. Exposed so the worker flow
    /// cache can precompute (once, on the cold cache-miss path) the shard
    /// its resolved next-hop lives in and stamp it onto the cache entry —
    /// avoiding a hash on every fast-path hit. Same function the map uses
    /// internally to route a key to its shard, so the stamp and the live
    /// bump agree on which shard a neighbor belongs to.
    #[inline]
    pub(crate) fn shard_index(key: &(i32, IpAddr)) -> usize {
        shard_idx(key)
    }

    /// #5147: current neighbor-resolution epoch for one shard. Read by the
    /// worker flow cache on every fast-path hit (single indexed relaxed
    /// atomic load; the shard is precomputed at insert). Mirrors the old
    /// global `mac_change_epoch` accessor but scoped to the neighbor's shard.
    #[inline]
    pub(crate) fn shard_mac_epoch(&self, shard: usize) -> u32 {
        self.shard_mac_epochs[shard].load(Ordering::Relaxed)
    }

    /// #5147: neighbor-resolution epoch for the shard that holds `key`.
    /// Convenience over `shard_mac_epoch(shard_index(key))`; used by tests
    /// and by the pre-resolve snapshot's `epoch_for`.
    #[inline]
    pub(crate) fn mac_change_epoch_for(&self, key: &(i32, IpAddr)) -> u32 {
        self.shard_mac_epoch(shard_idx(key))
    }

    /// #5147/#3918: snapshot every shard's neighbor-resolution epoch. The
    /// worker takes this BEFORE it resolves a packet's next-hop (it does not
    /// yet know which shard the resolve will land in), then stamps the
    /// resolved shard's snapshotted value onto the new cache entry. Reading
    /// pre-resolve — the whole vector — preserves the #3918 resolve→stamp
    /// TOCTOU fix per shard: the snapshot cannot already reflect a mapping
    /// change that lands during/after the resolve, so the live shard epoch
    /// advances past the stamp and the entry is evicted on its next hit.
    /// NUM_SHARDS relaxed loads, on the cold cache-miss path only.
    #[inline]
    pub(crate) fn snapshot_shard_epochs(&self) -> ShardEpochSnapshot {
        ShardEpochSnapshot(std::array::from_fn(|i| {
            self.shard_mac_epochs[i].load(Ordering::Relaxed)
        }))
    }

    /// #5147: advance the neighbor-resolution epoch of the shard that holds
    /// `key`. Called under the shard lock on a MAC replacement or actual
    /// removal so a concurrent fast-path hit cannot retain a stale decision.
    #[inline]
    fn bump_shard_epoch(&self, shard: usize) {
        self.shard_mac_epochs[shard].fetch_add(1, Ordering::Relaxed);
    }

    fn lock_shard(&self, idx: usize) -> MutexGuard<'_, FastMap<(i32, IpAddr), NeighborRecord>> {
        match self.shards[idx].0.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Get a copy of the entry for `key`, if present.
    pub(crate) fn get(&self, key: &(i32, IpAddr)) -> Option<NeighborEntry> {
        self.lock_shard(shard_idx(key))
            .get(key)
            .map(|record| record.entry)
    }

    /// Insert (or overwrite) `key → val`. Unit-returning.
    /// #7156: read the map-wide insert generation. One relaxed load; see the
    /// field for why the pending-neigh sweep gates its resolution walk on it.
    #[inline]
    pub(crate) fn insert_generation(&self) -> u64 {
        self.insert_generation.load(Ordering::Acquire)
    }

    pub(crate) fn insert(&self, key: (i32, IpAddr), val: NeighborEntry) {
        self.lock_shard(shard_idx(&key))
            .insert(key, NeighborRecord::authoritative(val));
        // #7156: AFTER the map write, Release-ordered — a worker that observes
        // this generation is guaranteed to see the entry it announces.
        self.insert_generation.fetch_add(1, Ordering::Release);
    }

    /// Remove `key` if present.
    pub(crate) fn remove(&self, key: &(i32, IpAddr)) {
        let _ = self.remove_if_present(key);
    }

    /// #1769: race-safe confirmed insert for the on-demand resolver.
    ///
    /// Locks the key's shard and, **while holding the lock**, re-reads
    /// `generation`. If it still equals `expected_generation` (no monitor
    /// event has begun since the resolver snapshotted the epoch before
    /// its GET), inserts `key → val` and returns `true`. Otherwise makes
    /// no change and returns `false`.
    ///
    /// This is the AGY-F1 / Codex epoch-guard fix: the monitor bumps the
    /// generation **before** it mutates the map (bump-first ordering in
    /// `neigh_monitor_thread`), so any concurrent RTM_{NEW,DEL}NEIGH that
    /// could invalidate the GET-derived MAC is observable as a generation
    /// advance *under this same shard lock*. The previous lock-free
    /// load-then-insert could resurrect a stale MAC when a monitor
    /// removal landed between the post-GET load and the insert (and
    /// missed entirely when a DELNEIGH for an already-absent key did not
    /// bump at all). Reading the generation inside the lock plus
    /// bump-first closes both.
    pub(crate) fn insert_confirmed_if_unchanged(
        &self,
        key: (i32, IpAddr),
        val: NeighborEntry,
        generation: &std::sync::atomic::AtomicU64,
        expected_generation: u64,
    ) -> bool {
        let idx = shard_idx(&key);
        let mut shard = self.lock_shard(idx);
        if generation.load(std::sync::atomic::Ordering::Acquire) != expected_generation {
            return false;
        }
        // #3048: if the confirmed GETNEIGH result REPLACES an existing
        // neighbor's MAC, that is a genuine MAC change — advance the
        // mac_change_epoch so cached forwarding descriptors holding the
        // old dst_mac are evicted on their next fast-path hit. The
        // resolver normally services a missing next-hop (prior == None,
        // first insert, no bump), but a re-resolution that observes a new
        // MAC must invalidate just like the monitor path. A re-confirm of
        // the SAME MAC does not bump.
        let prior = shard.get(&key).map(|record| record.entry);
        let changed_mac = prior.is_some_and(|prior| prior.mac != val.mac);
        if changed_mac
            && !self.peek_arp_reply_solicited(&key, super::neighbor::monotonic_nanos())
        {
            // A kernel GETNEIGH result is not evidence that an unsolicited
            // ARP/NA update was solicited. Only the monitor's probe token may
            // authorize the resolver's second write conduit.
            return false;
        }
        if changed_mac {
            // #5147: bump only THIS neighbor's shard epoch.
            self.bump_shard_epoch(idx);
        }
        shard.insert(key, NeighborRecord::authoritative(val));
        if changed_mac {
            self.take_arp_reply_solicited(&key, super::neighbor::monotonic_nanos());
        }
        // #7156: AFTER the map write, Release-ordered — a worker that observes
        // this generation is guaranteed to see the entry it announces.
        self.insert_generation.fetch_add(1, Ordering::Release);
        true
    }

    /// Insert `key → val` and return whether the cache changed.
    /// Returns `false` if the key already existed with the same MAC.
    /// Mirrors `neighbor::update_dynamic_neighbor` semantics.
    pub(crate) fn insert_if_changed(&self, key: (i32, IpAddr), val: NeighborEntry) -> bool {
        // #9893: the Override-unconditional leg of the CAS below. This is
        // used by other RX learns whose protocol allows replacement.
        // `None` arm is a defined fallback, not a panic: a future `None`
        // variant degrades to no-change (no insert happened, so `false` is
        // accurate) instead of panicking a cold worker path. The
        // `debug_assert` keeps the invariant loud in tests.
        let result = self.insert_ndp_na_if_override_allows(key, val, true, true);
        debug_assert!(
            result.is_some(),
            "override=true never refuses an NDP-NA-shaped insert"
        );
        result.unwrap_or(false)
    }

    /// #10704: atomic ARP-reply learn with solicited preference.
    ///
    /// A reply from a recent local probe may replace a differing MAC;
    /// an unsolicited reply gets NDP Override=0 semantics and can only
    /// create a first binding or refresh the same MAC. The check and write
    /// share one shard lock, so an intervening update cannot be overwritten.
    pub(crate) fn insert_arp_reply_if_solicited_allows(
        &self,
        key: (i32, IpAddr),
        val: NeighborEntry,
        solicited: bool,
    ) -> Option<bool> {
        self.insert_ndp_na_if_override_allows(key, val, true, solicited)
    }

    /// #9893: atomic NDP Neighbor-Advertisement learn honoring RFC 4861 §7.2.5
    /// Override under the key's shard lock.
    /// Returns `None` when an Override=0 NA meets a live entry with a
    /// DIFFERENT MAC — the unsolicited-NA next-hop hijack primitive (#4475).
    /// The refusal makes no change: no insert, no `mac_change_epoch` bump,
    /// no `learn_cap_drops` bump, no `insert_generation` bump. Otherwise
    /// inserts exactly as `insert_if_changed` (same-MAC refresh → `Some(false)`,
    /// cap refusal → `Some(false)`, first insert / MAC change → `Some(true)`
    /// with the #3048/#5147/#5673/#7156 side effects) and returns `Some(changed)`.
    ///
    /// This closes the #4475 best-effort TOCTOU: the pre-#9893 call site did
    /// `get` (lock #1) then `insert_if_changed` (lock #2), so a concurrent
    /// insert of a differing MAC between the two locks was overwritten by
    /// the Override=0 NA. The check and the write now share one shard lock,
    /// so no interleave can slip between them. Costs nothing on the normal
    /// path — one lock either way, one extra MAC compare on the NDP arm.
    pub(crate) fn insert_ndp_na_if_override_allows(
        &self,
        key: (i32, IpAddr),
        val: NeighborEntry,
        override_flag: bool,
        solicited: bool,
    ) -> Option<bool> {
        let idx = shard_idx(&key);
        let mut shard = self.lock_shard(idx);
        let prior_mac = shard.get(&key).map(|existing| existing.entry.mac);
        // #11069: an UNSOLICITED Override=1 NA gets Override=0 semantics
        // (ARP #10704 parity): it may create or refresh, never replace a
        // live differing LLA — the unsolicited-NA next-hop hijack primitive.
        let effective_override = override_flag && solicited;
        // #9893 CAS: Override=0 creates or refreshes but never replaces a
        // live differing LLA. Under the same lock as the write below.
        if !effective_override && prior_mac.is_some_and(|old| old != val.mac) {
            // No counter bump here: the single counting point is the
            // caller's report (report_na_unsolicited_override_refusal),
            // mirroring the ARP path — bumping here AND there would count
            // each production refusal twice, and ARP callers funneling
            // through this gate must never inflate the NA counter.
            return None;
        }
        if prior_mac == Some(val.mac) {
            return Some(false);
        }
        // #5673: a NEW learn (no prior entry for this key) that would grow
        // the shard past the per-shard cap is refused — the spoofed-source
        // pre-policy flood bound. This arm is the RX ARP-reply / NDP-NA
        // data-path learn (poll_stages.rs); an attacker can flood distinct
        // learnable source IPs here just as on the transit-source arm, and
        // both share this map. An UPDATE to an existing neighbor
        // (`prior_mac.is_some()`, e.g. a real MAC failover) is not growth and
        // is never refused, so a legitimate learned neighbor keeps working.
        if prior_mac.is_none() && shard.len() >= MAX_DYNAMIC_NEIGHBORS_PER_SHARD {
            self.learn_cap_drops.fetch_add(1, Ordering::Relaxed);
            return Some(false);
        }
        // #3048: a genuine MAC CHANGE (an existing entry whose hwaddr is
        // being replaced by a different one) invalidates any flow-cache
        // forwarding descriptor that captured the old MAC. Advance the
        // epoch so the worker fast path evicts those entries on their next
        // hit. A FIRST insert (`prior_mac == None`) does NOT advance it:
        // no cached flow can hold a stale MAC for a neighbor that did not
        // exist. The same-MAC refresh case already returned above.
        if let Some(old_mac) = prior_mac {
            debug_assert_ne!(old_mac, val.mac, "same-MAC case must have returned early");
            // #5147: bump only THIS neighbor's shard epoch, so a change here
            // does not invalidate cached flows resolved to other shards.
            self.bump_shard_epoch(idx);
        }
        shard.insert(key, NeighborRecord::authoritative(val));
        // #7156: AFTER the map write, Release-ordered — a worker that observes
        // this generation is guaranteed to see the entry it announces.
        self.insert_generation.fetch_add(1, Ordering::Release);
        Some(true)
    }

    /// Remove `key` if present and return whether it was actually removed.
    /// A successful removal advances that neighbor's shard epoch so cached
    /// descriptors cannot keep forwarding through the deleted member.
    pub(crate) fn remove_if_present(&self, key: &(i32, IpAddr)) -> bool {
        let shard_idx = shard_idx(key);
        let mut shard = self.lock_shard(shard_idx);
        let removed = shard.remove(key).is_some();
        if removed {
            self.bump_shard_epoch(shard_idx);
        }
        removed
    }

    /// Expire idle RX source-learned entries after the configured age plus
    /// coalescing grace. Manager-owned keys are excluded even if a packet
    /// learn temporarily wrote the same key into this map. Removal advances
    /// only the affected shard's MAC epoch so cached flows cannot continue
    /// forwarding to the aged MAC; it does not signal an insertion to pending
    /// neighbor sweeps.
    pub(crate) fn age_rx_learned_neighbors(
        &self,
        now_ns: u64,
        max_age_ns: u64,
        manager_keys: &FastSet<(i32, IpAddr)>,
    ) -> usize {
        let mut removed = 0;
        for idx in 0..NUM_SHARDS {
            let mut shard = self.lock_shard(idx);
            let before = shard.len();
            shard.retain(|key, record| {
                manager_keys.contains(key)
                    || !record.last_rx_learned_ns.is_some_and(|seen| {
                        now_ns.saturating_sub(seen)
                            >= max_age_ns.saturating_add(RX_LEARNED_NEIGHBOR_COALESCE_GRACE_NS)
                    })
            });
            let shard_removed = before - shard.len();
            if shard_removed != 0 {
                self.bump_shard_epoch(idx);
                removed += shard_removed;
            }
        }
        removed
    }

    /// A matching kernel monitor update proves that the current MAC is
    /// backed by the kernel neighbor table, so it no longer needs the RX
    /// source-learn lease.
    pub(crate) fn mark_kernel_backed_if_same(&self, key: &(i32, IpAddr), mac: [u8; 6]) {
        let mut shard = self.lock_shard(shard_idx(key));
        if let Some(record) = shard.get_mut(key)
            && record.entry.mac == mac
        {
            record.last_rx_learned_ns = None;
        }
    }

    /// Refresh the lease monotonically for an unchanged RX-learned VLAN key
    /// pair. Returns false if any key disappeared or no longer maps to the
    /// packet's MAC, allowing the caller to fall through to the normal learn
    /// path.
    pub(crate) fn refresh_rx_learned_pair(
        &self,
        keys: &[(i32, IpAddr)],
        mac: [u8; 6],
        now_ns: u64,
    ) -> bool {
        for key in keys {
            let mut shard = self.lock_shard(shard_idx(key));
            let Some(record) = shard.get_mut(key) else {
                return false;
            };
            if record.entry.mac != mac {
                return false;
            }
            if record.last_rx_learned_ns.is_some() {
                record.last_rx_learned_ns = record.last_rx_learned_ns.map(|seen| seen.max(now_ns));
            }
        }
        !keys.is_empty()
    }

    /// Lock every shard in shard-index order and run the closure with
    /// access to all of them. Used for atomic-vs-readers bulk
    /// operations: replace, clear, multi-key insert.
    ///
    /// Deadlock-free as long as every other caller that wants more
    /// than one shard locks in ascending shard-index order.
    ///
    /// **Non-reentrant**: the closure MUST NOT call any other method
    /// on the same `ShardedNeighborMap` (or any of its `Arc` clones) —
    /// every shard is already locked, so a per-key call would
    /// self-deadlock waiting on a shard the same thread holds.
    pub(crate) fn with_all_shards<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut BulkShardGuard<'_>) -> R,
    {
        // Lock all 64 shards in ascending order. Use a Vec then convert
        // to a fixed-size array because MutexGuard doesn't impl Default,
        // ruling out `array::from_fn`.
        let mut guards: Vec<MutexGuard<'_, FastMap<(i32, IpAddr), NeighborRecord>>> =
            Vec::with_capacity(NUM_SHARDS);
        for i in 0..NUM_SHARDS {
            guards.push(self.lock_shard(i));
        }
        let mut bulk = BulkShardGuard {
            guards: guards
                .try_into()
                .ok()
                .expect("exactly NUM_SHARDS guards pushed"),
        };
        f(&mut bulk)
    }

    /// #3048: atomic bulk neighbor replace used by the Go control-plane
    /// snapshot push (`Coordinator::apply_manager_neighbors`, the #1197
    /// authoritative neighbor mechanism). Removes `remove_keys`, then
    /// inserts `insert_entries`, all under a single all-shard lock so
    /// readers see either the pre- or post-replace set, never a partial
    /// one. Bumps each affected shard once if an incoming key REPLACES an
    /// existing neighbor's MAC or an existing key is removed without being
    /// reinserted.
    ///
    /// This is the FOURTH neighbor-MAC write path and the only one that
    /// removes the prior entry BEFORE installing the new one (a Go
    /// snapshot push uses `NeighborReplace: true`). The prior MAC for
    /// each incoming key is therefore snapshotted UNDER the bulk lock
    /// BEFORE the removes — reading it at insert time would always see
    /// `None` (the old entry is already gone) and never detect a change,
    /// which is exactly the bulk-path gap #3048's first cut missed.
    ///
    /// Semantics match the per-key paths: a pure refresh where every key
    /// keeps the same MAC does NOT bump; a brand-new key with no prior
    /// does NOT force a bump on its own; and a removal bumps only when the
    /// key existed and is not reinserted. Reachable on a
    /// VRRP-failover RTM_NEWNEIGH burst when the in-process monitor's
    /// bounded rcvbuf overflows and the Go neighbor listener pushes the
    /// new gateway MAC through this path.
    pub(crate) fn bulk_replace_neighbors(
        &self,
        remove_keys: &[(i32, IpAddr)],
        insert_entries: &[(i32, IpAddr, NeighborEntry)],
    ) {
        let _ = self.bulk_replace_neighbors_inner(remove_keys, insert_entries, None);
    }

    /// Apply a manager mirror while preserving an existing dynamic MAC when
    /// the snapshot disagrees. The comparison and write share the bulk lock,
    /// so a concurrent monitor update cannot be overwritten after a stale
    /// pre-check. NUD_PERMANENT rows are allowed to replace it.
    pub(crate) fn bulk_replace_neighbors_preserving_changes(
        &self,
        remove_keys: &[(i32, IpAddr)],
        insert_entries: &[(i32, IpAddr, NeighborEntry)],
        permanent_keys: &[(i32, IpAddr)],
    ) -> Vec<(i32, IpAddr, NeighborEntry)> {
        self.bulk_replace_neighbors_inner(remove_keys, insert_entries, Some(permanent_keys))
    }

    fn bulk_replace_neighbors_inner(
        &self,
        remove_keys: &[(i32, IpAddr)],
        insert_entries: &[(i32, IpAddr, NeighborEntry)],
        permanent_keys: Option<&[(i32, IpAddr)]>,
    ) -> Vec<(i32, IpAddr, NeighborEntry)> {
        let mut effective_entries = Vec::with_capacity(insert_entries.len());
        self.with_all_shards(|bulk| {
            let mut changed_shards = [false; NUM_SHARDS];
            for (ifindex, ip, entry) in insert_entries {
                let key = (*ifindex, *ip);
                let effective = match (permanent_keys, bulk.get(&key)) {
                    (Some(permanent_keys), Some(prior))
                        if !permanent_keys.contains(&key) && prior.mac != entry.mac =>
                    {
                        prior
                    }
                    _ => *entry,
                };
                if bulk.get(&key).is_some_and(|prior| prior.mac != effective.mac) {
                    changed_shards[shard_idx(&key)] = true;
                }
                effective_entries.push((key.0, key.1, effective));
            }

            let reinserted_keys = if remove_keys.is_empty() || effective_entries.is_empty() {
                None
            } else {
                let mut keys = FastSet::default();
                keys.reserve(effective_entries.len());
                for (ifindex, ip, _) in &effective_entries {
                    keys.insert((*ifindex, *ip));
                }
                Some(keys)
            };
            for key in remove_keys {
                let removed = bulk.remove_if_present(key).is_some();
                let reinserted = reinserted_keys
                    .as_ref()
                    .is_some_and(|keys| keys.contains(key));
                if removed && !reinserted {
                    changed_shards[shard_idx(key)] = true;
                }
            }
            for (ifindex, ip, entry) in &effective_entries {
                bulk.insert((*ifindex, *ip), *entry);
            }
            for (shard, &changed) in changed_shards.iter().enumerate() {
                if changed {
                    self.bump_shard_epoch(shard);
                }
            }
        });
        self.bump_insert_generation_9071(!effective_entries.is_empty());
        effective_entries
    }

    /// #3169: bump-aware atomic multi-key insert for the #1787 RX
    /// source-MAC data-path learn (`learn_dynamic_neighbor`). Installs
    /// the SAME MAC under up to N keys (the #949 pair-write: the physical
    /// ingress ifindex plus the resolved logical VLAN sub-ifindex) under
    /// ONE all-shard lock so a reader sees either both or neither, never a
    /// stale half — and bumps `mac_change_epoch` exactly once if ANY key
    /// REPLACES an existing neighbor's MAC with a different one.
    ///
    /// This is the FIFTH neighbor-MAC write path. Its `pair_write_needed`
    /// caller gate fires on a genuine MAC change (`current != Some(mac)`),
    /// not just first sighting, so the learn really does mutate an
    /// existing neighbor's MAC — and `lookup_neighbor_entry` falls back to
    /// `dynamic_neighbors` for a next-hop the kernel never ARP-resolves
    /// (the common AF_XDP fast-path case), so a stale cached `dst_mac`
    /// would blackhole until session expiry without this bump (#3169).
    ///
    /// Semantics match the per-key paths exactly: a first insert
    /// (`prior == None`) and a same-MAC re-learn do NOT bump; only a
    /// differing prior MAC does. The prior MAC is read via
    /// `BulkShardGuard::get` under the same bulk lock as the insert and
    /// the bump, so a concurrent fast-path hit never observes the new MAC
    /// paired with the old epoch.
    pub(crate) fn learn_pair_if_changed(&self, keys: &[(i32, IpAddr)], val: NeighborEntry) {
        self.learn_pair_if_changed_at(keys, val, super::neighbor::monotonic_nanos());
    }

    pub(crate) fn learn_pair_if_changed_at(
        &self,
        keys: &[(i32, IpAddr)],
        val: NeighborEntry,
        now_ns: u64,
    ) {
        let installed = self.with_all_shards(|bulk| {
            // #5673: refuse the WHOLE pair-write if ANY new key's shard is at
            // the per-shard cap. This is the transit-source RX learn arm
            // (`learn_dynamic_neighbor`), the primary M02/#5673 vector: an
            // attacker floods distinct spoofed L3 sources pre-policy. A key
            // that already exists is an UPDATE (real MAC failover), not
            // growth, and never counts against the cap. Refusing the whole
            // pair rather than a partial preserves this method's documented
            // both-or-neither invariant (a reader sees both keys or neither).
            // The authoritative check lives here under the bulk lock; the
            // caller (`learn_dynamic_neighbor`) additionally skips this bulk
            // acquisition entirely when its pre-check already saw every key
            // new-and-at-cap, so a steady flood never reaches this lock.
            let blocked = keys.iter().any(|key| {
                bulk.get(key).is_none() && bulk.len_for(key) >= MAX_DYNAMIC_NEIGHBORS_PER_SHARD
            });
            if blocked {
                self.learn_cap_drops.fetch_add(1, Ordering::Relaxed);
                // #9071: a refused pair-write changed nothing.
                return false;
            }
            // #5147: mark the SHARD of each key that genuinely changed MAC.
            // The pair-write can straddle two shards (the physical and the
            // logical VLAN sub-ifindex hash independently), so a change must
            // bump each affected shard, not one global epoch.
            let mut changed_shards = [false; NUM_SHARDS];
            for key in keys {
                if let Some(prior) = bulk.get(key)
                    && prior.mac != val.mac
                {
                    changed_shards[shard_idx(key)] = true;
                }
            }
            for key in keys {
                bulk.insert_rx_learned(*key, val, now_ns);
            }
            // #5147: bump each shard whose neighbor MAC changed exactly once,
            // so cached flows resolved to an unrelated shard survive.
            for (shard, &changed) in changed_shards.iter().enumerate() {
                if changed {
                    self.bump_shard_epoch(shard);
                }
            }
            // #9071: reaching here means the pair-write was NOT refused, so
            // entries were installed. Reported separately from changed_shards,
            // which marks only a key whose MAC changed -- a brand-new key has
            // no prior MAC to differ from, and a freshly learned neighbour is
            // exactly what the poll loop is waiting for.
            !keys.is_empty()
        });
        // #9071: see bulk_replace_neighbors. Same omission, same consequence,
        // and the same "only when something changed" condition.
        self.bump_insert_generation_9071(installed);
    }
    /// #10854: create-only variant for RX source-learns, which run before
    /// screen and policy admission. Creates missing keys and refreshes the
    /// same MAC, but atomically refuses a differing live MAC so an unadmitted
    /// packet cannot poison a neighbor used by another flow. The admitted
    /// forward path uses `learn_pair_if_changed` to allow genuine MAC moves.
    ///
    /// Like `learn_pair_if_changed`, installs a VLAN physical/logical pair
    /// atomically and enforces the per-shard cap. Same-MAC callers are
    /// expected to elide this all-shard lock with their single-shard precheck.
    pub(crate) fn learn_pair_if_absent_or_same(
        &self,
        keys: &[(i32, IpAddr)],
        val: NeighborEntry,
    ) -> bool {
        self.learn_pair_if_absent_or_same_at(keys, val, super::neighbor::monotonic_nanos())
    }

    pub(crate) fn learn_pair_if_absent_or_same_at(
        &self,
        keys: &[(i32, IpAddr)],
        val: NeighborEntry,
        now_ns: u64,
    ) -> bool {
        let installed = self.with_all_shards(|bulk| {
            if keys
                .iter()
                .any(|key| bulk.get(key).is_some_and(|prior| prior.mac != val.mac))
            {
                self.rx_learn_overwrite_refusals
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }
            let blocked = keys.iter().any(|key| {
                bulk.get(key).is_none() && bulk.len_for(key) >= MAX_DYNAMIC_NEIGHBORS_PER_SHARD
            });
            if blocked {
                self.learn_cap_drops.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            for key in keys {
                bulk.insert_rx_learned(*key, val, now_ns);
            }
            !keys.is_empty()
        });
        self.bump_insert_generation_9071(installed);
        installed
    }

    /// #9071: advance the insert generation.
    ///
    /// Named rather than inlined so the two bulk paths and the three per-key
    /// paths are greppable as one set -- the defect was that two members of a
    /// five-member set did not do this, and a bare `fetch_add` at five sites is
    /// how a sixth gets added without it.
    /// `installed` gates the bump: the two bulk callers pass whether the call
    /// actually installed any entry. A no-op sync must not advance it, or the
    /// poll-loop gate fires every sweep and #7156's optimisation is gone.
    fn bump_insert_generation_9071(&self, installed: bool) {
        if installed {
            self.insert_generation.fetch_add(1, Ordering::Release);
        }
    }

    /// Total entry count summed across shards, releasing each shard lock
    /// before acquiring the next. This is an informational status gauge;
    /// it does not require a single atomic cross-shard snapshot.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len_each_shard(|index| {
            #[cfg(test)]
            LEN_AFTER_SHARD_HOOK.with(|hook| {
                if let Some(hook) = hook.borrow_mut().as_mut() {
                    hook(index);
                }
            });
        })
    }

    #[inline]
    fn len_each_shard(&self, mut after_shard: impl FnMut(usize)) -> usize {
        let mut total = 0;
        for i in 0..NUM_SHARDS {
            total += self.lock_shard(i).len();
            after_shard(i);
        }
        total
    }

    /// True iff the map has zero entries across all shards.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True iff `key` is present in its shard.
    pub(crate) fn contains_key(&self, key: &(i32, IpAddr)) -> bool {
        self.lock_shard(shard_idx(key)).contains_key(key)
    }
}

impl Default for ShardedNeighborMap {
    fn default() -> Self {
        Self::new()
    }
}

/// #5147/#3918: immutable snapshot of every shard's neighbor-resolution
/// epoch, captured by the worker BEFORE it resolves a packet's next-hop.
/// Because the resolved shard is not known until after the resolve, the
/// worker snapshots the whole vector first, then stamps the resolved shard's
/// value onto the new flow-cache entry (`epoch_for`). Taking the snapshot
/// pre-resolve preserves the #3918 TOCTOU fix per shard: a MAC replacement or
/// removal that lands during/after the resolve cannot already be reflected
/// in this snapshot, so the entry's stamped epoch is < the live shard epoch
/// and is evicted on its next hit rather than using the stale mapping.
pub(crate) struct ShardEpochSnapshot([u32; NUM_SHARDS]);

impl ShardEpochSnapshot {
    /// The snapshotted neighbor-resolution epoch for the shard holding `key`
    /// (the flow's resolved next-hop `(egress_ifindex, next_hop)`).
    #[inline]
    pub(crate) fn epoch_for(&self, key: &(i32, IpAddr)) -> u32 {
        self.0[shard_idx(key)]
    }
}

/// Holds all 64 shard `MutexGuard`s so a bulk closure can mutate
/// across shards safely. Provides key-routed `insert`/`remove` plus
/// raw shard iteration for `clear` and friends.
pub(crate) struct BulkShardGuard<'a> {
    guards: [MutexGuard<'a, FastMap<(i32, IpAddr), NeighborRecord>>; NUM_SHARDS],
}

impl<'a> BulkShardGuard<'a> {
    /// Insert `key → val` into the appropriate shard as a non-RX entry.
    pub(crate) fn insert(&mut self, key: (i32, IpAddr), val: NeighborEntry) {
        let i = shard_idx(&key);
        self.guards[i].insert(key, NeighborRecord::authoritative(val));
    }

    /// Insert or refresh an RX source-learned entry monotonically. A same-MAC
    /// refresh of an entry already backed by the kernel preserves that status;
    /// a new or changed MAC starts a userspace-only lease.
    fn insert_rx_learned(&mut self, key: (i32, IpAddr), val: NeighborEntry, now_ns: u64) {
        let i = shard_idx(&key);
        let last_rx_learned_ns = match self.guards[i].get(&key).copied() {
            Some(prior) if prior.entry.mac == val.mac => {
                prior.last_rx_learned_ns.map(|seen| seen.max(now_ns))
            }
            Some(prior) => Some(
                prior
                    .last_rx_learned_ns
                    .map_or(now_ns, |seen| seen.max(now_ns)),
            ),
            None => Some(now_ns),
        };
        self.guards[i].insert(
            key,
            NeighborRecord {
                entry: val,
                last_rx_learned_ns,
            },
        );
    }

    /// Remove `key` from the appropriate shard if present.
    pub(crate) fn remove_if_present(&mut self, key: &(i32, IpAddr)) -> Option<NeighborEntry> {
        let i = shard_idx(key);
        self.guards[i].remove(key).map(|record| record.entry)
    }

    /// Remove `key` from the appropriate shard.
    pub(crate) fn remove(&mut self, key: &(i32, IpAddr)) {
        let _ = self.remove_if_present(key);
    }

    /// #3048: read the entry for `key` from its shard while every shard
    /// is locked. Used by `bulk_replace_neighbors` to snapshot a prior
    /// MAC BEFORE the replace removes it.
    pub(crate) fn get(&self, key: &(i32, IpAddr)) -> Option<NeighborEntry> {
        let i = shard_idx(key);
        self.guards[i].get(key).map(|record| record.entry)
    }

    /// Iterate every shard's underlying map mutably. Used for
    /// shard-wide operations like `clear`.
    pub(crate) fn each_shard_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut FastMap<(i32, IpAddr), NeighborRecord>> {
        self.guards.iter_mut().map(|g| &mut **g)
    }

    /// #1782: iterate every shard's underlying map immutably. Used by
    /// `Coordinator::dynamic_neighbor_keys` to dump the present key set
    /// for the cold-start capture harness without needing mutable
    /// access.
    pub(crate) fn each_shard_ref(
        &self,
    ) -> impl Iterator<Item = &FastMap<(i32, IpAddr), NeighborRecord>> {
        self.guards.iter().map(|g| &**g)
    }

    /// Sum of `len()` across all shards.
    pub(crate) fn total_len(&self) -> usize {
        self.guards.iter().map(|g| g.len()).sum()
    }

    /// #5673: entry count of the shard that holds `key`, while every shard
    /// is locked. Used by `learn_pair_if_changed` to enforce the per-shard
    /// learn cap on a NEW key under the same bulk lock as the insert (so the
    /// cap decision and the insert cannot race).
    pub(crate) fn len_for(&self, key: &(i32, IpAddr)) -> usize {
        self.guards[shard_idx(key)].len()
    }
}

#[cfg(test)]
#[path = "sharded_neighbor_tests.rs"]
mod tests;
