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
//! - Shard hash mixes FxHash output with a Knuth multiplier so the
//!   shard index is decorrelated from `hashbrown`'s internal bucket
//!   selection (which uses high hash bits).
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

use super::types::{FastMap, NeighborEntry};
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
/// Sizing and the shard-concentration residual: the shard hash (`shard_idx`,
/// FxHash + Knuth mix) is FIXED, PUBLIC and UNKEYED. It spreads a RANDOM flood
/// ~evenly across shards, but an attacker who PRECOMPUTES source IPs CAN
/// concentrate them onto one shard — filling that shard's
/// `MAX_DYNAMIC_NEIGHBORS_PER_SHARD` (2048) while the aggregate stays far below
/// `MAX_DYNAMIC_NEIGHBORS` (131072). The cap's PRIMARY guarantees still hold
/// under concentration: bounded memory and no all-shard serialization. The
/// residual is that opportunistic pre-warm LEARNING of a legit neighbor whose
/// IP hashes to a victim shard can be denied while that shard is attacker-full
/// — but forwarding to it is NOT lost: the uncapped on-demand resolver
/// (`insert_confirmed_if_unchanged`) still installs the real next-hop, at the
/// cost of extra resolver round-trips. Related minor residual:
/// `learn_pair_if_changed` refuses the WHOLE pair if EITHER key is new-at-cap,
/// so a desynced-pair UPDATE could be dropped under concentration (vanishingly
/// rare; resolver-recovered). A keyed/seeded shard hash would close the
/// concentration residual if it ever matters. 2048/shard → 131072 aggregate is
/// well above any realistic learned population (a firewall resolves neighbors
/// for its directly-connected subnets — a /15 of on-link hosts — not the
/// Internet).
pub(super) const MAX_DYNAMIC_NEIGHBORS_PER_SHARD: usize = 2048;

/// #5673: aggregate cap on dynamically learned neighbor entries. Derived
/// from the per-shard cap and the shard count (see
/// `MAX_DYNAMIC_NEIGHBORS_PER_SHARD`, which also documents the
/// shard-concentration residual on the fixed/unkeyed shard hash). Exposed
/// for tests and any operator surface that wants to reason about the bound.
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

/// One mutex-guarded shard, padded to 64 bytes so adjacent shards do
/// not share cache lines.
#[repr(align(64))]
pub(super) struct PaddedShard(Mutex<FastMap<(i32, IpAddr), NeighborEntry>>);

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
    /// Distinct from the per-shard `mac_change_epoch` above, which fires only
    /// when an EXISTING neighbour's hwaddr is replaced. That is the wrong
    /// signal here: a pending key is waiting for its neighbour to APPEAR, and
    /// a first insert changes no existing hwaddr, so it bumps no epoch.
    insert_generation: AtomicU64,
    /// #5147: PER-SHARD monotonic MAC-change epochs. Bumped ONLY when a
    /// kernel ARP/NDP update REPLACES an existing neighbor's hwaddr with a
    /// different MAC (gateway VRRP failover, host NIC swap, upstream MAC
    /// change), and ONLY on the epoch of the shard that holds the changed
    /// neighbor key. The worker flow cache stamps the epoch of the SPECIFIC
    /// shard its resolved next-hop lives in
    /// (`FlowCacheEntry::neighbor_shard`) into each cached forwarding
    /// descriptor and re-reads that one slot on every fast-path hit; a
    /// mismatch means the descriptor's `dst_mac` may be stale, so the entry
    /// is evicted and the next packet re-resolves the current MAC.
    ///
    /// This replaces the single global `mac_change_epoch` that made ANY
    /// neighbor's MAC change invalidate EVERY cached flow. An on-link sender
    /// alternating one IP's MAC advanced that global counter faster than
    /// entries could warm, collapsing the whole flow cache to ~1 packet
    /// (attacker-driven cache thrash / DoS, #5147). With a per-shard epoch a
    /// change on neighbor A evicts a cached flow using neighbor B only in the
    /// rare event A and B hash to the SAME shard (1/NUM_SHARDS), never
    /// map-wide.
    ///
    /// Same #3048 non-bump discipline, now applied per shard. It is
    /// deliberately NOT bumped on:
    ///   * a first insert of a brand-new neighbor (no cached flow can
    ///     reference a neighbor that did not previously exist), nor
    ///   * a periodic ARP/NDP REFRESH that re-learns the SAME MAC (the
    ///     overwhelmingly common case) — bumping there would flush that
    ///     shard's cached flows on every neighbor refresh and collapse the
    ///     fast-path hit rate.
    /// `insert_if_changed` distinguishes these because it reads the prior
    /// entry under the shard lock before overwriting.
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

/// Shard index for a key. The Knuth multiplier `0x9E3779B97F4A7C15`
/// (the 64-bit golden ratio) spreads entropy into the HIGH bits of
/// the product, so we extract the top `log2(NUM_SHARDS) = 6` bits
/// rather than the low bits. This decorrelates shard selection from
/// `hashbrown`'s internal SwissTable bucket selection (which also
/// uses high hash bits) by feeding it a freshly-rotated hash, and it
/// produces a uniform distribution for adversarial input patterns
/// like `/24` LANs (constant ifindex + sequential last octet).
const SHARD_BITS: u32 = NUM_SHARDS.trailing_zeros();

/// #7752: per-process random seed mixed into shard selection.
///
/// The Knuth post-multiply above closes the ACCIDENTAL clustering case — a
/// `/24` of neighbours whose low bits are correlated still spreads across
/// shards. It cannot close the CHOSEN-input case, because `FxHash` is a fixed
/// public function with no per-process secret: an attacker who can pick
/// neighbour addresses can compute, offline, a set that lands in one shard.
///
/// That matters here specifically because of the #5673 per-shard learn cap.
/// With `NUM_SHARDS = 64` and `MAX_DYNAMIC_NEIGHBORS_PER_SHARD = 2048`, filling
/// ONE shard costs 2048 entries against an aggregate capacity of 131,072 — so
/// an unkeyed hash hands the attacker a 64x discount AND lets them choose WHICH
/// addresses are denied, since a new learn into a full shard is refused
/// (`prior_mac.is_none() && shard.len() >= MAX`) while updates to already-known
/// neighbours are not. Source learning runs on RX before screen/policy
/// admission, so an L2-adjacent host spoofing sources reaches it.
///
/// The seed does not make `FxHash` a keyed MAC and this is NOT claimed as
/// cryptographic keying. What it removes is OFFLINE precomputation: without the
/// seed an attacker must probe the live mapping, which is slow and observable,
/// instead of arriving with a prepared address set.
///
/// Seeded once per process. A `getrandom` failure does not refuse to start — a
/// firewall that will not boot because the RNG hiccuped is a worse outcome than
/// a weaker shard seed — but the fallback is still process-varying rather than
/// a compile-time constant, and it says so on stderr.
static SHARD_SEED: LazyLock<u64> = LazyLock::new(|| {
    let mut b = [0u8; 8];
    if getrandom::getrandom(&mut b).is_ok() {
        return u64::from_ne_bytes(b);
    }
    eprintln!(
        "xpf-dp: getrandom failed seeding the neighbor shard index; falling \
         back to a process-varying seed (#7752)"
    );
    let mut h = FxHasher::default();
    std::process::id().hash(&mut h);
    (&b as *const u8 as usize).hash(&mut h);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        .hash(&mut h);
    h.finish()
});

/// The seeded shard computation is split out so its seed contribution can be
/// tested independently; reading the process seed inside this function would
/// make "does the seed change the mapping?" unaskable — the property
/// would make "does the seed change the mapping?" unaskable — the property
/// would be true by construction and unfalsifiable, which is how a guard ends
/// up unable to notice its own subject being deleted.
#[inline]
fn shard_idx_with(seed: u64, key: &(i32, IpAddr)) -> usize {
    let mut hasher = FxHasher::default();
    hasher.write_u64(seed);
    key.hash(&mut hasher);
    let h = hasher.finish();
    let mixed = h.wrapping_mul(0x9E3779B97F4A7C15);
    (mixed >> (64 - SHARD_BITS)) as usize
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
            rx_learn_overwrite_refusals: AtomicU64::new(0),
        }
    }
    /// #10854: refused pre-policy transit learns that would overwrite a
    /// neighbor with a different MAC.
    #[cfg(test)]
    pub(crate) fn rx_learn_overwrite_refusals(&self) -> u64 {
        self.rx_learn_overwrite_refusals
            .load(Ordering::Relaxed)
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
        if !matches!(key.1, IpAddr::V4(_)) {
            return;
        }
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

    /// #5673: `get` plus whether the key's shard is at the per-shard learn
    /// cap, under ONE shard lock (same cost as `get`). The RX-learn
    /// pre-check (`learn_dynamic_neighbor`) uses this to detect that every
    /// candidate key is a NEW learn whose shard is full and skip the
    /// all-shard bulk write — avoiding the 64-shard serialization a
    /// spoofed-source flood would otherwise inflict on every packet.
    pub(crate) fn get_with_capacity(&self, key: &(i32, IpAddr)) -> (Option<NeighborEntry>, bool) {
        let shard = self.lock_shard(shard_idx(key));
        let entry = shard.get(key).copied();
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

    /// #5147: current MAC-change epoch for one shard. Read by the worker
    /// flow cache on every fast-path hit (single indexed relaxed atomic
    /// load; the shard is precomputed at insert). Mirrors the old global
    /// `mac_change_epoch` accessor but scoped to the neighbor's own shard.
    #[inline]
    pub(crate) fn shard_mac_epoch(&self, shard: usize) -> u32 {
        self.shard_mac_epochs[shard].load(Ordering::Relaxed)
    }

    /// #5147: MAC-change epoch for the shard that holds `key`. Convenience
    /// over `shard_mac_epoch(shard_index(key))`; used by tests and by the
    /// pre-resolve snapshot's `epoch_for`.
    #[inline]
    pub(crate) fn mac_change_epoch_for(&self, key: &(i32, IpAddr)) -> u32 {
        self.shard_mac_epoch(shard_idx(key))
    }

    /// #5147/#3918: snapshot every shard's MAC-change epoch at once. The
    /// worker takes this BEFORE it resolves a packet's next-hop MAC (it does
    /// not yet know which shard the resolve will land in), then stamps the
    /// resolved shard's snapshotted value onto the new cache entry. Reading
    /// pre-resolve — the whole vector — preserves the #3918 resolve→stamp
    /// TOCTOU fix per shard: the snapshot cannot already reflect a MAC change
    /// that lands during/after the resolve, so such a change advances the
    /// live shard epoch past the stamp and the entry is evicted on its next
    /// hit rather than serving the stale MAC. NUM_SHARDS relaxed loads, on
    /// the cold cache-miss path only.
    #[inline]
    pub(crate) fn snapshot_shard_epochs(&self) -> ShardEpochSnapshot {
        ShardEpochSnapshot(std::array::from_fn(|i| {
            self.shard_mac_epochs[i].load(Ordering::Relaxed)
        }))
    }

    /// #5147: advance the MAC-change epoch of the shard that holds `key`.
    /// Called under the shard lock on a genuine MAC replacement so a
    /// concurrent fast-path hit never observes the new MAC paired with the
    /// old shard epoch.
    #[inline]
    fn bump_shard_epoch(&self, shard: usize) {
        self.shard_mac_epochs[shard].fetch_add(1, Ordering::Relaxed);
    }

    fn lock_shard(
        &self,
        idx: usize,
    ) -> MutexGuard<'_, FastMap<(i32, IpAddr), NeighborEntry>> {
        match self.shards[idx].0.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Get a copy of the entry for `key`, if present.
    pub(crate) fn get(&self, key: &(i32, IpAddr)) -> Option<NeighborEntry> {
        self.lock_shard(shard_idx(key)).get(key).copied()
    }

    /// Insert (or overwrite) `key → val`. Unit-returning.
    /// #7156: read the map-wide insert generation. One relaxed load; see the
    /// field for why the pending-neigh sweep gates its resolution walk on it.
    #[inline]
    pub(crate) fn insert_generation(&self) -> u64 {
        self.insert_generation.load(Ordering::Acquire)
    }

    pub(crate) fn insert(&self, key: (i32, IpAddr), val: NeighborEntry) {
        self.lock_shard(shard_idx(&key)).insert(key, val);
        // #7156: AFTER the map write, Release-ordered — a worker that observes
        // this generation is guaranteed to see the entry it announces.
        self.insert_generation.fetch_add(1, Ordering::Release);
    }

    /// Remove `key` if present. Unit-returning.
    pub(crate) fn remove(&self, key: &(i32, IpAddr)) {
        self.lock_shard(shard_idx(key)).remove(key);
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
        if let Some(prior) = shard.get(&key)
            && prior.mac != val.mac
        {
            // #5147: bump only THIS neighbor's shard epoch.
            self.bump_shard_epoch(idx);
        }
        shard.insert(key, val);
        // #7156: AFTER the map write, Release-ordered — a worker that observes
        // this generation is guaranteed to see the entry it announces.
        self.insert_generation.fetch_add(1, Ordering::Release);
        true
    }

    /// Insert `key → val` and return whether the cache changed.
    /// Returns `false` if the key already existed with the same MAC.
    /// Mirrors `neighbor::update_dynamic_neighbor` semantics.
    pub(crate) fn insert_if_changed(
        &self,
        key: (i32, IpAddr),
        val: NeighborEntry,
    ) -> bool {
        // #9893: the Override-unconditional leg of the CAS below. This is
        // used by other RX learns whose protocol allows replacement.
        // `None` arm is a defined fallback, not a panic: a future `None`
        // variant degrades to no-change (no insert happened, so `false` is
        // accurate) instead of panicking a cold worker path. The
        // `debug_assert` keeps the invariant loud in tests.
        let result = self.insert_ndp_na_if_override_allows(key, val, true);
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
        self.insert_ndp_na_if_override_allows(key, val, solicited)
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
    ) -> Option<bool> {
        let idx = shard_idx(&key);
        let mut shard = self.lock_shard(idx);
        let prior_mac = shard.get(&key).map(|existing| existing.mac);
        // #9893 CAS: Override=0 creates or refreshes but never replaces a
        // live differing LLA. Under the same lock as the write below.
        if !override_flag && prior_mac.is_some_and(|old| old != val.mac) {
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
        shard.insert(key, val);
        // #7156: AFTER the map write, Release-ordered — a worker that observes
        // this generation is guaranteed to see the entry it announces.
        self.insert_generation.fetch_add(1, Ordering::Release);
        Some(true)
    }

    /// Remove `key` if present and return whether it was actually
    /// removed. Mirrors `neighbor::remove_dynamic_neighbor` semantics.
    pub(crate) fn remove_if_present(&self, key: &(i32, IpAddr)) -> bool {
        self.lock_shard(shard_idx(key)).remove(key).is_some()
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
        let mut guards: Vec<MutexGuard<'_, FastMap<(i32, IpAddr), NeighborEntry>>> =
            Vec::with_capacity(NUM_SHARDS);
        for i in 0..NUM_SHARDS {
            guards.push(self.lock_shard(i));
        }
        let mut bulk = BulkShardGuard {
            guards: guards.try_into().ok().expect("exactly NUM_SHARDS guards pushed"),
        };
        f(&mut bulk)
    }

    /// #3048: atomic bulk neighbor replace used by the Go control-plane
    /// snapshot push (`Coordinator::apply_manager_neighbors`, the #1197
    /// authoritative neighbor mechanism). Removes `remove_keys`, then
    /// inserts `insert_entries`, all under a single all-shard lock so
    /// readers see either the pre- or post-replace set, never a partial
    /// one. Bumps `mac_change_epoch` exactly once if ANY incoming key
    /// REPLACES an existing neighbor's MAC with a different one.
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
    /// does NOT force a bump on its own (no cached flow can reference a
    /// neighbor that did not previously exist). Reachable on a
    /// VRRP-failover RTM_NEWNEIGH burst when the in-process monitor's
    /// bounded rcvbuf overflows and the Go neighbor listener pushes the
    /// new gateway MAC through this path.
    pub(crate) fn bulk_replace_neighbors(
        &self,
        remove_keys: &[(i32, IpAddr)],
        insert_entries: &[(i32, IpAddr, NeighborEntry)],
    ) {
        self.with_all_shards(|bulk| {
            // Snapshot the prior MAC for every INCOMING key BEFORE any
            // removal — the replace removes the old entry before the
            // matching insert, so reading after would always miss it.
            // #5147: mark the SHARD of each key that genuinely changed MAC,
            // so the bump below is per-shard, not a single global epoch.
            let mut changed_shards = [false; NUM_SHARDS];
            for (ifindex, ip, entry) in insert_entries {
                if let Some(prior) = bulk.get(&(*ifindex, *ip))
                    && prior.mac != entry.mac
                {
                    changed_shards[shard_idx(&(*ifindex, *ip))] = true;
                }
            }
            for key in remove_keys {
                bulk.remove(key);
            }
            for (ifindex, ip, entry) in insert_entries {
                bulk.insert((*ifindex, *ip), *entry);
            }
            // Bump under the same bulk lock as the mutation so a
            // concurrent fast-path hit never observes the new MAC with
            // the old epoch. #5147: bump each shard that had a genuine MAC
            // change exactly once — a change to a neighbor in shard S
            // invalidates only cached flows resolved to shard S, not the
            // whole flow cache. (Two changed keys colliding in one shard
            // bump it once.)
            for (shard, &changed) in changed_shards.iter().enumerate() {
                if changed {
                    self.bump_shard_epoch(shard);
                }
            }
        });
        // #9071: bump the INSERT GENERATION too. The three per-key insert paths
        // do; the two bulk paths did not, so #7156's poll-loop gate --
        // `neigh_generation != binding.last_neigh_generation` -- never fired for
        // a neighbour learned through here, and the buffered packet for that hop
        // waited for the RESOLUTION_RECHECK_INTERVAL_NS backstop instead.
        //
        // The shard epoch and the insert generation answer DIFFERENT questions
        // and neither substitutes for the other: the epoch invalidates cached
        // flows resolved to one shard, and the generation tells the poll loop a
        // resolution pass is worth running at all.
        //
        // ONLY WHEN SOMETHING WAS INSTALLED. Bumping unconditionally makes the
        // gate fire on every netlink sync, empty or not -- the #7156
        // optimisation removed while looking like a fix, since a counter that
        // advances on every call carries the same information as one that never
        // advances.
        //
        // The condition is "did we install anything", NOT the `changed_shards`
        // set the epoch uses. Those answer different questions and reusing the
        // epoch's set was my first attempt and wrong: changed_shards marks a key
        // whose MAC CHANGED, and a brand-new key has no prior MAC to differ
        // from -- so a freshly resolved neighbour, the exact case the poll loop
        // is waiting for, would not have bumped.
        self.bump_insert_generation_9071(!insert_entries.is_empty());
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
    pub(crate) fn learn_pair_if_changed(
        &self,
        keys: &[(i32, IpAddr)],
        val: NeighborEntry,
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
                bulk.insert(*key, val);
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
        let installed = self.with_all_shards(|bulk| {
            if keys.iter().any(|key| {
                bulk.get(key).is_some_and(|prior| prior.mac != val.mac)
            }) {
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
                bulk.insert(*key, val);
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

    /// Total entry count summed across shards. Locks all shards in
    /// order. Used by `coordinator::dynamic_neighbor_status`.
    pub(crate) fn len(&self) -> usize {
        self.with_all_shards(|bulk| bulk.total_len())
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

/// #5147/#3918: an immutable snapshot of every shard's MAC-change epoch,
/// captured by the worker BEFORE it resolves a packet's next-hop neighbor
/// MAC. Because the resolved shard is not known until after the resolve, the
/// worker snapshots the whole vector first, then stamps the resolved shard's
/// snapshotted value onto the new flow-cache entry (`epoch_for`). Taking the
/// snapshot pre-resolve preserves the #3918 TOCTOU fix per shard: a MAC
/// change that lands during/after the resolve cannot already be reflected in
/// this snapshot, so the entry's stamped epoch is < the live shard epoch and
/// the entry is evicted on its next hit rather than serving the stale MAC.
pub(crate) struct ShardEpochSnapshot([u32; NUM_SHARDS]);

impl ShardEpochSnapshot {
    /// The snapshotted MAC-change epoch for the shard that holds `key` (the
    /// flow's resolved next-hop `(egress_ifindex, next_hop)`).
    #[inline]
    pub(crate) fn epoch_for(&self, key: &(i32, IpAddr)) -> u32 {
        self.0[shard_idx(key)]
    }
}

/// Holds all 64 shard `MutexGuard`s so a bulk closure can mutate
/// across shards safely. Provides key-routed `insert`/`remove` plus
/// raw shard iteration for `clear` and friends.
pub(crate) struct BulkShardGuard<'a> {
    guards: [MutexGuard<'a, FastMap<(i32, IpAddr), NeighborEntry>>; NUM_SHARDS],
}

impl<'a> BulkShardGuard<'a> {
    /// Insert `key → val` into the appropriate shard.
    pub(crate) fn insert(&mut self, key: (i32, IpAddr), val: NeighborEntry) {
        let i = shard_idx(&key);
        self.guards[i].insert(key, val);
    }

    /// Remove `key` from the appropriate shard.
    pub(crate) fn remove(&mut self, key: &(i32, IpAddr)) {
        let i = shard_idx(key);
        self.guards[i].remove(key);
    }

    /// #3048: read the entry for `key` from its shard while every shard
    /// is locked. Used by `bulk_replace_neighbors` to snapshot a prior
    /// MAC BEFORE the replace removes it.
    pub(crate) fn get(&self, key: &(i32, IpAddr)) -> Option<NeighborEntry> {
        let i = shard_idx(key);
        self.guards[i].get(key).copied()
    }

    /// Iterate every shard's underlying map mutably. Used for
    /// shard-wide operations like `clear`.
    pub(crate) fn each_shard_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut FastMap<(i32, IpAddr), NeighborEntry>> {
        self.guards.iter_mut().map(|g| &mut **g)
    }

    /// #1782: iterate every shard's underlying map immutably. Used by
    /// `Coordinator::dynamic_neighbor_keys` to dump the present key set
    /// for the cold-start capture harness without needing mutable
    /// access.
    pub(crate) fn each_shard_ref(
        &self,
    ) -> impl Iterator<Item = &FastMap<(i32, IpAddr), NeighborEntry>> {
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

