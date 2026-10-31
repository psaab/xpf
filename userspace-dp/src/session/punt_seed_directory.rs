// #18562: node-wide, read-only view of this node's live #7770 punt seeds, for
// the embedded-ICMP matcher ONLY.
//
// The defect. During an RG split (LAN RG here, WAN RG on the peer) the only
// record this node holds for a NEW punted flow is the worker-local
// `FabricPuntSeed` that the LAN packet's worker minted (#7770). The hop's ICMP
// error for that flow comes back over the fabric already reversed by the WAN
// owner, and the fabric NIC RSS-hashes it independently of the LAN probe, so it
// usually lands on ANOTHER worker. That worker's own table is empty and the
// node's shared maps hold nothing (seeds are transient-local and never
// published), so the embedded matcher returned `NoMatch` and the error fell
// through to flowless `wan -> lan` default deny — every UDP traceroute / `mtr -u`
// probe is a new flow, so hop 2 read `???` for the whole split.
//
// What this is. A map `forward key -> snapshot of the seed row`, written ONLY by
// `SessionTable` at its choke points — `insert_record` publishes a
// `FabricPuntSeed` forward row, and `remove_entry` (the table's sole removal
// sink: expiry, explicit delete, replacement, take_synced_local) retires it,
// fenced by the inserting table and the row's write-once session id. An
// in-place refresh of a seed (`refresh_in_place`: HA transition, promotion)
// also retires it, and so does dropping the table. So a row exists only while
// the table that minted it still holds THAT seed incarnation, unmodified.
//
// What this is NOT. It is not session authority and never becomes any: it is
// not a shared-session map, so nothing materializes, promotes, exports, sweeps,
// replicates, or demotes from it; no packet other than an embedded-ICMP error
// quoting the punted FORWARD packet, arriving on the fabric, ever reads it
// (`icmp_embed/nat_match_v4.rs` / `nat_match_v6.rs` fallback arm, consulted
// only after the local table AND the shared maps both missed). Data-path
// returns keep exactly today's #7770 semantics.
//
// Lifetime. A row stops matching at the EARLIER of the seed's idle deadline as
// installed and `PUNT_SEED_ROW_TTL_NS` after install. The row only has to
// bridge the gap until the WAN owner's HA import lands in the shared maps
// (normally well under a second), after which the ordinary shared probe
// answers. A seed that outlives its row (refreshed by traffic, or simply older
// than the bridge window) just stops being answered here — fail closed, the
// pre-#18562 verdict.
//
// Cost (#18562 review seat L). Publish runs on the punted new-flow path of a
// worker, so every operation under a shard lock is O(1) amortized:
//  * 32 shards by seeded key hash, so concurrent workers rarely meet;
//  * expiry is a per-shard FIFO of `(deadline, key, incarnation)` popped from
//    the front while expired — each entry is pushed once and popped once. The
//    fixed bridge TTL keeps deadlines near-monotone in push order; a row with a
//    shorter deadline behind a longer one is filtered at probe time and
//    reclaimed when its predecessor pops (at most one TTL later);
//  * a retire removes the row only (O(1)); its queue entry is dropped lazily,
//    and a queue that reaches twice the shard cap is compacted to the live rows
//    in one pass, which frees at least a shard-cap of entries — amortized O(1)
//    per publish;
//  * a shard reserves its full cap on first use, so a populated map never
//    grows or rehashes under the lock;
//  * a full shard REFUSES in O(1) (no scan), and publish takes its shard with
//    `try_lock`, so a worker never waits on the directory: a contended or full
//    shard simply leaves that seed unmirrored (counted), i.e. the
//    pre-#18562 verdict for that one flow's cross-worker errors.
// The pre-review design scanned the whole map under one node-wide mutex on
// every publish at the cap (measured 139-284 us per publish).
//
// Memory (measured sizes: `SessionKey` 52 B, `PuntSeedRow` 256 B). A shard's
// first publish reserves its full cap: hashbrown rounds 1024 rows up to 2048
// buckets of ~310 B (~620 KiB) plus a 2048-slot expiry queue of ~80 B
// (~160 KiB) — ~0.8 MiB of address space per active shard, ~25 MiB if all 32
// are active. Pages are touched only as rows land, so resident memory tracks
// the rows actually held, and a drained shard frees its reservation; an
// unsplit node holds 32 empty shards.

use super::{SessionDecision, SessionKey, SessionMetadata};
use crate::hot_hash_seed::HotPathSeededState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Shard count (power of two, see `shard_index`).
const SHARDS: usize = 32;
const _: () = assert!(SHARDS.is_power_of_two());

/// Upper bound on resident rows, node-wide (`SHARDS` x `SHARD_CAP`). With the
/// bridge TTL below this holds ~3.2k new punted flows/s sustained before a
/// shard starts refusing.
pub(crate) const PUNT_SEED_DIRECTORY_CAP: usize = 32_768;
const SHARD_CAP: usize = PUNT_SEED_DIRECTORY_CAP / SHARDS;
const _: () = assert!(SHARD_CAP * SHARDS == PUNT_SEED_DIRECTORY_CAP);
/// A shard's lazily-pruned expiry queue is compacted when it reaches this.
const QUEUE_COMPACT_AT: usize = 2 * SHARD_CAP;

/// The bridge window: a row is answered at most this long after install.
pub(crate) const PUNT_SEED_ROW_TTL_NS: u64 = 10_000_000_000;

/// #18562: publishes refused because the row's shard was full of live rows.
pub(crate) static PUNT_SEED_DIRECTORY_FULL_TOTAL: AtomicU64 = AtomicU64::new(0);
/// #18562: publishes skipped because the row's shard lock was held (the
/// worker never waits on the directory).
pub(crate) static PUNT_SEED_DIRECTORY_CONTENDED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Distinguishes the tables sharing one directory, so a retire from one table
/// can never remove a row another table published (session ids are only
/// namespaced per worker in production; tests share namespace 0).
static NEXT_TABLE_TOKEN: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_punt_seed_table_token() -> u64 {
    NEXT_TABLE_TOKEN.fetch_add(1, Ordering::Relaxed)
}

/// The snapshot a match needs: the seed's adjudicated zone pair (in
/// `metadata`, always a forward row) and its NAT-free decision (the return
/// resolution reads its installing table). Taken at insert and never updated —
/// any in-place change to the seed retires the row instead.
#[derive(Clone, Debug)]
pub(crate) struct PuntSeedRow {
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) session_id: u64,
    pub(crate) table_token: u64,
    pub(crate) expires_at_ns: u64,
}

impl PuntSeedRow {
    /// The row's deadline: the seed's installed idle deadline, capped at the
    /// bridge TTL.
    pub(crate) fn deadline(created_ns: u64, idle_window_ns: u64) -> u64 {
        created_ns.saturating_add(idle_window_ns.min(PUNT_SEED_ROW_TTL_NS))
    }
}

struct ExpirySlot {
    deadline_ns: u64,
    key: SessionKey,
    table_token: u64,
    session_id: u64,
}

struct Shard {
    rows: HashMap<SessionKey, PuntSeedRow, HotPathSeededState>,
    expiry: VecDeque<ExpirySlot>,
}

pub(crate) struct PuntSeedDirectory {
    shards: [Mutex<Shard>; SHARDS],
    hasher: HotPathSeededState,
    /// Idle gate: the matcher Relaxed-loads it and skips every lock while no
    /// seed is resident (every node outside an RG split). A stale read can only
    /// miss a row being published concurrently, which is today's verdict, never
    /// a false match. Updated under the shard lock that changed the count.
    live: AtomicUsize,
    /// Test-only: queue entries and rows touched by prune / compaction /
    /// shrink, so a cell can pin the amortized bound without timing.
    #[cfg(test)]
    work: AtomicU64,
}

impl Default for PuntSeedDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl Shard {
    fn matches(&self, slot: &ExpirySlot) -> bool {
        self.rows
            .get(&slot.key)
            .is_some_and(|r| r.table_token == slot.table_token && r.session_id == slot.session_id)
    }
}

impl PuntSeedDirectory {
    pub(crate) fn new() -> Self {
        let state = HotPathSeededState::new(crate::hot_hash_seed::hot_path_hash_seed());
        Self {
            shards: std::array::from_fn(|_| {
                Mutex::new(Shard {
                    rows: HashMap::with_hasher(state),
                    expiry: VecDeque::new(),
                })
            }),
            hasher: state,
            live: AtomicUsize::new(0),
            #[cfg(test)]
            work: AtomicU64::new(0),
        }
    }

    #[inline]
    fn shard_index(&self, key: &SessionKey) -> usize {
        (self.hasher.hash_one(key) as usize) & (SHARDS - 1)
    }

    fn lock(&self, index: usize) -> std::sync::MutexGuard<'_, Shard> {
        self.shards[index]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[inline]
    fn note_work(&self, _n: usize) {
        #[cfg(test)]
        self.work.fetch_add(_n as u64, Ordering::Relaxed);
    }

    /// Resident rows, node-wide (status gauge and the idle gate).
    pub(crate) fn len(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Pop expired queue entries (removing their rows if still this
    /// incarnation), compact a queue bloated by lazily-retired entries, and
    /// shrink allocations a drained shard no longer needs. Every step is paid
    /// for by earlier pushes or removals, so it is O(1) amortized per publish.
    fn maintain(&self, shard: &mut Shard, now_ns: u64) {
        let mut removed = 0usize;
        let mut popped = 0usize;
        while shard.expiry.front().is_some_and(|s| s.deadline_ns <= now_ns) {
            let slot = shard.expiry.pop_front().expect("front checked");
            popped += 1;
            if shard.matches(&slot) {
                shard.rows.remove(&slot.key);
                removed += 1;
            }
        }
        if shard.expiry.len() >= QUEUE_COMPACT_AT {
            // In place, so the queue's reserved capacity is reused, never
            // reallocated under the lock.
            popped += shard.expiry.len();
            let Shard { rows, expiry } = &mut *shard;
            expiry.retain(|slot| {
                rows.get(&slot.key).is_some_and(|r| {
                    r.table_token == slot.table_token && r.session_id == slot.session_id
                })
            });
        }
        // A fully drained shard (no rows AND no pending queue slots) gives its
        // reservation back; a populated one never resizes (see
        // `reserve_on_first_publish`). Waiting for the queue too keeps one-flow-
        // at-a-time churn from freeing and re-reserving on every publish: the
        // lazy slots hold the reservation until they pop (one TTL) or compact.
        if shard.rows.is_empty() && shard.expiry.is_empty() && shard.rows.capacity() > 0 {
            shard.rows.shrink_to(0);
            shard.expiry.shrink_to(0);
        }
        if removed > 0 {
            self.live.fetch_sub(removed, Ordering::Relaxed);
        }
        self.note_work(popped);
    }

    /// Review seat L (LOW): growing a hash map rehashes it under the lock
    /// (measured: a 97 us worst single publish while one shard filled). A
    /// shard therefore reserves its full cap once, on its first publish into an
    /// empty map — one allocation, nothing to rehash — and never grows again,
    /// because `SHARD_CAP` is enforced before every insert. The pages are
    /// touched only as rows land, so an active-but-light shard stays small in
    /// resident memory; `maintain` frees the reservation when the shard drains.
    fn reserve_on_first_publish(shard: &mut Shard) {
        if shard.rows.capacity() == 0 {
            shard.rows.reserve(SHARD_CAP);
        }
        if shard.expiry.capacity() == 0 {
            shard.expiry.reserve(QUEUE_COMPACT_AT);
        }
    }

    /// Publish (or replace) `key`'s row. Called only from
    /// `SessionTable::insert_record` for a forward `FabricPuntSeed`. Never
    /// blocks: a contended shard is skipped and counted.
    pub(crate) fn publish(&self, key: &SessionKey, row: PuntSeedRow, now_ns: u64) -> bool {
        let index = self.shard_index(key);
        let mut shard = match self.shards[index].try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                PUNT_SEED_DIRECTORY_CONTENDED_TOTAL.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        };
        self.maintain(&mut shard, now_ns);
        Self::reserve_on_first_publish(&mut shard);
        let replacing = shard.rows.contains_key(key);
        if !replacing && shard.rows.len() >= SHARD_CAP {
            PUNT_SEED_DIRECTORY_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        shard.expiry.push_back(ExpirySlot {
            deadline_ns: row.expires_at_ns,
            key: key.clone(),
            table_token: row.table_token,
            session_id: row.session_id,
        });
        shard.rows.insert(key.clone(), row);
        if !replacing {
            self.live.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    /// Retire `key`'s row iff it is still the incarnation `(table_token,
    /// session_id)` published. A later seed for the same key from another
    /// table, or a re-install with a fresh id, survives. O(1): the queue entry
    /// is dropped lazily.
    pub(crate) fn retire(&self, key: &SessionKey, table_token: u64, session_id: u64) {
        if self.live.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut shard = self.lock(self.shard_index(key));
        if shard
            .rows
            .get(key)
            .is_some_and(|r| r.table_token == table_token && r.session_id == session_id)
        {
            shard.rows.remove(key);
            self.live.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Retire every row `table_token` published (its table is being dropped or
    /// re-wired). Cold: worker teardown only.
    pub(crate) fn retire_table(&self, table_token: u64) {
        if self.live.load(Ordering::Relaxed) == 0 {
            return;
        }
        for index in 0..SHARDS {
            let mut shard = self.lock(index);
            let before = shard.rows.len();
            shard.rows.retain(|_, r| r.table_token != table_token);
            let removed = before - shard.rows.len();
            if removed > 0 {
                self.live.fetch_sub(removed, Ordering::Relaxed);
            }
        }
    }

    /// The matcher's read: a live row for the quoted FORWARD key, or `None`.
    /// Read-only — it neither refreshes nor extends the row.
    pub(crate) fn probe(&self, key: &SessionKey, now_ns: u64) -> Option<PuntSeedRow> {
        if self.live.load(Ordering::Relaxed) == 0 {
            return None;
        }
        self.lock(self.shard_index(key))
            .rows
            .get(key)
            .filter(|r| r.expires_at_ns > now_ns)
            .cloned()
    }

    #[cfg(test)]
    pub(crate) fn work_for_test(&self) -> u64 {
        self.work.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn shard_of_for_test(&self, key: &SessionKey) -> usize {
        self.shard_index(key)
    }

    #[cfg(test)]
    pub(crate) fn shard_cap_for_test() -> usize {
        SHARD_CAP
    }

    #[cfg(test)]
    pub(crate) fn queue_len_for_test(&self, index: usize) -> usize {
        self.lock(index).expiry.len()
    }

    #[cfg(test)]
    pub(crate) fn rows_capacity_for_test(&self, index: usize) -> usize {
        self.lock(index).rows.capacity()
    }

    /// Run `f` while holding shard `index`'s lock (contention cell).
    #[cfg(test)]
    pub(crate) fn with_shard_held_for_test(&self, index: usize, f: impl FnOnce()) {
        let _held = self.lock(index);
        f();
    }
}
