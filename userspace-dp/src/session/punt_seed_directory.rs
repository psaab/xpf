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
//  * a retire removes the row only (O(1)); its queue slot is dropped lazily
//    when it reaches the front;
//  * ONE call pops at most `MAINTAIN_BUDGET` (32) slots, expired or stale, so
//    no single publish holds its shard for long (`retire` and `probe` wait on
//    the same lock); each publish pushes one slot, so the queue still drains,
//    and a queue at `QUEUE_CAP` refuses further publishes rather than being
//    compacted in one pass. Known bounded residual (review seat L r3): a slot
//    is reclaimed only from the front, so a long-lived live row at the front
//    with heavy churn behind it — more than `QUEUE_CAP` (2048) publishes into
//    ONE shard within a TTL, nearly all retired (~32k/s node-wide) — can fill
//    a nearly empty shard's queue; further publishes there are refused (fail
//    closed, counted) until the front expires, at most one TTL (2 s);
//  * a shard reserves its table once, on first use, for TWICE its 1024-row
//    live cap (`ROWS_RESERVE`; hashbrown gives 3584 item capacity), and admits
//    at most half of that capacity as live rows (`Shard::row_cap`, derived
//    from `capacity()` right after the reservation). Review seat L (r3): with
//    more than half the capacity live, churn that leaves hashbrown tombstones
//    makes `reserve_rehash` RESIZE (an allocation plus a full rehash under the
//    lock: measured 339-383 us once per shard) instead of rehashing in place.
//    At or below half it can only rehash in place, and at ~29% load deletes
//    rarely leave tombstones, so it practically never does (bench: 0 rehashes
//    in 100k churn publishes) — a populated shard never grows;
//  * a full shard REFUSES in O(1) (no scan), and publish takes its shard with
//    `try_lock`, so a worker never waits on the directory: a contended or full
//    shard simply leaves that seed unmirrored (counted), i.e. the
//    pre-#18562 verdict for that one flow's cross-worker errors.
// The pre-review design scanned the whole map under one node-wide mutex on
// every publish at the cap (measured 139-284 us per publish).
//
// Memory (measured sizes: `SessionKey` 52 B, `PuntSeedRow` 256 B). A shard's
// first publish reserves a 2048-row table, which hashbrown rounds up to 4096
// buckets of ~310 B (~1.27 MiB), plus a 2048-slot expiry queue of ~80 B
// (~160 KiB) — ~1.43 MiB of address space per used shard, ~46 MiB if all 32
// are used — and that table never resizes (live rows <= half its capacity). Pages are touched as rows land, and rows land at random bucket
// positions, so a shard holding a few hundred rows is already close to fully
// resident (review seat L). Once a shard has been used its reservation is KEPT
// for the life of the directory (the helper process): freeing it on drain
// bought nothing, because the only place a drained shard is noticed is its next
// publish, which would re-reserve at once. An unsplit node that never punted
// holds 32 empty shards; the bound after any split is the ~25 MiB above.

use super::{SessionDecision, SessionKey, SessionMetadata};
use crate::hot_hash_seed::HotPathSeededState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Shard count (power of two, see `shard_index`).
const SHARDS: usize = 32;
const _: () = assert!(SHARDS.is_power_of_two());

/// Live rows node-wide (`SHARDS` x `SHARD_CAP`, 1024 per shard; each shard's
/// table is reserved for twice that, `ROWS_RESERVE`). With the 2 s bridge TTL
/// this sustains ~16k new punted flows/s before a shard starts refusing (fail
/// closed, counted in `PUNT_SEED_DIRECTORY_FULL_TOTAL`).
pub(crate) const PUNT_SEED_DIRECTORY_CAP: usize = 32_768;
const SHARD_CAP: usize = PUNT_SEED_DIRECTORY_CAP / SHARDS;
const _: () = assert!(SHARD_CAP * SHARDS == PUNT_SEED_DIRECTORY_CAP);
/// Rows a shard's table is reserved for: twice the live-row cap (review seat L
/// r3, measured). Live rows stay at or below HALF the reserved table's item
/// capacity (`Shard::row_cap`), so hashbrown can only rehash in place, never
/// resize; and at the resulting ~29% load, deletes rarely leave tombstones, so
/// even the in-place rehash practically never runs. Reserving exactly the cap
/// and keeping half live (896 rows) removed the resize too, but kept a
/// recurring ~50 us in-place rehash of ~900 rows under the lock (bench), and
/// cut capacity to ~28.7k rows; this costs ~0.6 MiB more per used shard.
const ROWS_RESERVE: usize = 2 * SHARD_CAP;
/// Hard bound on a shard's expiry queue (live slots plus lazily retired
/// ones). A publish that would exceed it is refused (counted as full): the
/// queue is never compacted in one pass under the lock.
const QUEUE_CAP: usize = 2 * SHARD_CAP;
/// Review seat L (r2): the most queue slots ONE `maintain` call may pop, so a
/// publish never holds its shard for more than a bounded, small amount of work
/// — `retire` and `probe` take the same lock blocking. Each publish pushes
/// exactly one slot and may pop up to this many, so the queue still drains
/// faster than it fills; expired rows not yet popped are already invisible to
/// `probe` (deadline filter) and are reclaimed by later calls.
const MAINTAIN_BUDGET: usize = 32;

/// The bridge window: a row is answered at most this long after install.
///
/// What the row bridges is short by construction: the error it exists for is
/// the FIRST one about a punted flow's forward packet, generated by a hop on
/// that packet's path, so it arrives one hop RTT after the probe (sub-second
/// on any terrestrial path; ~600 ms over geostationary satellite). Every
/// later error for the same flow is answered by the WAN owner's HA import,
/// which reaches the shared maps on the incremental sync path within a few
/// hundred ms (#18562 issue: "~200 ms"). Two seconds covers both with margin
/// and, with the 32768 live-row cap, sustains ~16k new punted flows/s before
/// a shard refuses. Past it — HA sync down, or a seed whose import never lands — the
/// row stops answering and the pre-#18562 verdict applies (fail closed).
pub(crate) const PUNT_SEED_ROW_TTL_NS: u64 = 2_000_000_000;

/// #18562: publishes refused at a full shard — its live rows at `row_cap`, or
/// its expiry queue at `QUEUE_CAP` (live rows plus lazily retired slots; see
/// the bounded residual in the module doc). Either way the seed is left
/// unmirrored and its cross-worker errors keep the pre-#18562 verdict.
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
    /// Live-row cap: `SHARD_CAP`, but never more than half the reserved
    /// table's item capacity; set by `reserve_on_first_publish` (0 until the
    /// shard is first used). Items at or below half mean hashbrown can only
    /// purge tombstones by an in-place rehash, never resize under the lock.
    row_cap: usize,
}

pub(crate) struct PuntSeedDirectory {
    shards: [Mutex<Shard>; SHARDS],
    hasher: HotPathSeededState,
    /// Idle gate: the matcher Relaxed-loads it and skips every lock while no
    /// seed is resident (every node outside an RG split). A stale read can only
    /// miss a row being published concurrently, which is today's verdict, never
    /// a false match. Updated under the shard lock that changed the count.
    live: AtomicUsize,
    /// Test-only: queue slots touched by prune /
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
                    row_cap: 0,
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

    /// Resident rows, node-wide (status gauge and the idle gate). Includes rows
    /// past their deadline that `maintain` has not reclaimed yet (they no
    /// longer match: `probe` filters on the deadline).
    pub(crate) fn len(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Pop up to `MAINTAIN_BUDGET` expired or stale queue slots from the front,
    /// removing a row only if the slot is still its incarnation. Bounded per
    /// call; each publish pushes one slot, so the queue drains faster than it
    /// fills. (No shrink: `maintain` only runs on a publish, which would at once
    /// re-reserve what a drained shard freed — see the memory note.)
    fn maintain(&self, shard: &mut Shard, now_ns: u64) {
        let mut removed = 0usize;
        let mut popped = 0usize;
        // Pop from the front while the front slot is expired OR stale (its row
        // was retired or replaced), at most `MAINTAIN_BUDGET` per call.
        while popped < MAINTAIN_BUDGET
            && shard
                .expiry
                .front()
                .is_some_and(|s| s.deadline_ns <= now_ns || !shard.matches(s))
        {
            let slot = shard.expiry.pop_front().expect("front checked");
            popped += 1;
            if shard.matches(&slot) {
                shard.rows.remove(&slot.key);
                removed += 1;
            }
        }
        if removed > 0 {
            self.live.fetch_sub(removed, Ordering::Relaxed);
        }
        self.note_work(popped);
    }

    /// Review seat L: growing a hash map rehashes it under the lock (r1: a
    /// 97 us worst publish while a shard filled; r3: a 339-383 us RESIZE once
    /// per shard under churn at the old 1024-row cap, because tombstones forced
    /// `reserve_rehash` with more than half the capacity live). A shard
    /// therefore reserves its table once, on its first publish into an empty
    /// map, for `ROWS_RESERVE` (twice the live cap), and admits at most half
    /// of that table's item capacity as live rows (`row_cap`). At or below half
    /// hashbrown can only rehash in place (bounded by `row_cap` rows, no
    /// reallocation), never resize, and at the resulting ~29% load it
    /// practically never needs to; the queue's reservation is never exceeded
    /// (`QUEUE_CAP`). The reservation is kept once made (see the memory note).
    fn reserve_on_first_publish(shard: &mut Shard) {
        if shard.rows.capacity() == 0 {
            shard.rows.reserve(ROWS_RESERVE);
            // Right after reserving into an EMPTY map, `capacity()` is the
            // table's full item capacity (no tombstones yet). Derived, not
            // hardcoded: hashbrown's rounding is its own business.
            shard.row_cap = SHARD_CAP.min(shard.rows.capacity() / 2);
        }
        if shard.expiry.capacity() == 0 {
            shard.expiry.reserve(QUEUE_CAP);
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
        if (!replacing && shard.rows.len() >= shard.row_cap) || shard.expiry.len() >= QUEUE_CAP {
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

    /// The live-row cap a shard derives at its first publish (half the
    /// reserved table's item capacity), computed the same way.
    #[cfg(test)]
    pub(crate) fn row_cap_for_test() -> usize {
        let mut m: HashMap<SessionKey, PuntSeedRow, HotPathSeededState> =
            HashMap::with_hasher(HotPathSeededState::new(1));
        m.reserve(ROWS_RESERVE);
        SHARD_CAP.min(m.capacity() / 2)
    }

    #[cfg(test)]
    pub(crate) fn maintain_budget_for_test() -> usize {
        MAINTAIN_BUDGET
    }

    #[cfg(test)]
    pub(crate) fn queue_cap_for_test() -> usize {
        QUEUE_CAP
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
