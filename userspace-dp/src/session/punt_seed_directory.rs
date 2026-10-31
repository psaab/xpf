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
// `SessionTable` at its two choke points — `insert_record` publishes a
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
// Lifetime is bounded twice: by the hooks above, and by `expires_at_ns` — the
// seed's own idle deadline AT INSTALL (`created_ns + expires_after_ns`). A seed
// refreshed by traffic outlives its row; the row then simply stops matching
// (fail closed, today's behaviour), by which time the WAN owner's HA import is
// in the shared maps and the ordinary shared probe answers instead.

use super::{SessionDecision, SessionKey, SessionMetadata};
use crate::hot_hash_seed::HotPathSeededState;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Upper bound on resident rows. A full directory first prunes rows past their
/// deadline (cold: only reached at cap) and then REFUSES the publish — the
/// refused seed's errors on other workers keep today's verdict. Rows are
/// a few hundred bytes; 65536 bounds the directory near 16 MiB per node.
pub(crate) const PUNT_SEED_DIRECTORY_CAP: usize = 65_536;

/// #18562: publishes refused because the directory stayed full after pruning.
pub(crate) static PUNT_SEED_DIRECTORY_FULL_TOTAL: AtomicU64 = AtomicU64::new(0);

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

pub(crate) struct PuntSeedDirectory {
    rows: Mutex<HashMap<SessionKey, PuntSeedRow, HotPathSeededState>>,
    /// Idle gate: the matcher Relaxed-loads it and skips the lock entirely
    /// while no seed is resident (every node outside an RG split). A stale
    /// read can only miss a row being published concurrently, which is
    /// today's verdict, never a false match.
    live: AtomicUsize,
}

impl Default for PuntSeedDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl PuntSeedDirectory {
    pub(crate) fn new() -> Self {
        Self {
            rows: Mutex::new(HashMap::with_hasher(HotPathSeededState::new(
                crate::hot_hash_seed::hot_path_hash_seed(),
            ))),
            live: AtomicUsize::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SessionKey, PuntSeedRow, HotPathSeededState>> {
        self.rows.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Resident rows (test observability; production reads the `live` idle
    /// gate directly).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Publish (or replace) `key`'s row. Called only from
    /// `SessionTable::insert_record` for a forward `FabricPuntSeed`.
    pub(crate) fn publish(&self, key: &SessionKey, row: PuntSeedRow, now_ns: u64) -> bool {
        let mut rows = self.lock();
        if rows.len() >= PUNT_SEED_DIRECTORY_CAP && !rows.contains_key(key) {
            rows.retain(|_, r| r.expires_at_ns > now_ns);
            if rows.len() >= PUNT_SEED_DIRECTORY_CAP {
                self.live.store(rows.len(), Ordering::Relaxed);
                PUNT_SEED_DIRECTORY_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        rows.insert(key.clone(), row);
        self.live.store(rows.len(), Ordering::Relaxed);
        true
    }

    /// Retire `key`'s row iff it is still the incarnation `(table_token,
    /// session_id)` published. A later seed for the same key from another
    /// table, or a re-install with a fresh id, survives.
    pub(crate) fn retire(&self, key: &SessionKey, table_token: u64, session_id: u64) {
        if self.live.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut rows = self.lock();
        if rows
            .get(key)
            .is_some_and(|r| r.table_token == table_token && r.session_id == session_id)
        {
            rows.remove(key);
            self.live.store(rows.len(), Ordering::Relaxed);
        }
    }

    /// Retire every row `table_token` published (its table is being dropped).
    pub(crate) fn retire_table(&self, table_token: u64) {
        if self.live.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut rows = self.lock();
        rows.retain(|_, r| r.table_token != table_token);
        self.live.store(rows.len(), Ordering::Relaxed);
    }

    /// The matcher's read: a live row for the quoted FORWARD key, or `None`.
    /// Read-only — it neither refreshes nor extends the row.
    pub(crate) fn probe(&self, key: &SessionKey, now_ns: u64) -> Option<PuntSeedRow> {
        if self.live.load(Ordering::Relaxed) == 0 {
            return None;
        }
        self.lock()
            .get(key)
            .filter(|r| r.expires_at_ns > now_ns)
            .cloned()
    }
}
