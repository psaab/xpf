// #19026 (fold cycle 3) — the node's ONE owner of "close old incarnation A"
// for restored `SharedPromote` sessions.
//
// Before this directory the obligation to emit a restored session's single
// Close lived in places that other paths could rewrite: a mark on the
// REPLACEABLE shared row, a worker-local fence-hold flag, the claimant's
// ring/overflow/parked slot, and the G1 install's best-effort ring push. A
// replacement erased it (Codex R16 F2), a full ring dropped it (F3), and two
// installers each produced it (F4).
//
// Now every producer goes through one entry, keyed by A's SESSION ID (not by
// the tuple, so replacing or removing the forwarding row cannot touch it),
// that carries the Close delta itself (so no copy of A has to survive):
//
// - CREATE is a compare-and-insert: only the first producer for A wins and
//   emits; every later producer (a second claimant, a G1 replacement, a late
//   installer) finds the entry, Pending or Flushed, and emits nothing.
// - The entry turns Pending -> Flushed only when the flush loop has run the
//   Close's emit legs (`afxdp/session_delta.rs`). A full ring, a requeue or a
//   park leaves it Pending. Flushed tombstones expire after two fence holds,
//   longer than any lingering crossed copy of A can still be replaced or
//   claimed, so a late producer still loses.
// - TAKEOVER: every worker sweeps once per GC interval. A Pending entry past
//   its `retry_at_ns` is taken (owner = the sweeper, new deadline) and its
//   stored Close is pushed again. A live owner renews its own entries at the
//   same cadence while their Closes are still parked or deferred, so it never
//   loses one to takeover: exactly once while the owner lives, at least once
//   only if it dies or wedges mid-flush.
// - A Pending entry whose owner RG this node no longer forwards is dropped:
//   the RG's new owner closes the session through its own copy and expiry.
// - BOUNDED at `CLOSE_RETIREMENT_CAP` entries. At the cap a producer gets
//   `Full` and must emit its Close directly anyway (fail safe: at-least-once,
//   never a silent drop); only the duplicate suppression is lost.
// - Lock order: the shared-primary map lock, then this directory's lock
//   (a leaf: nothing is locked while it is held). The fence claim compares
//   the shared row and creates the entry under both.
// - Node-local and in memory: lost on a helper restart, like every worker's
//   ring and parked Closes (see session/README.md for what covers that).

use super::{SessionDelta, SessionKey};
use rustc_hash::FxHashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Maximum entries (Pending + Flushed). A 24k-session RG bounce whose
/// restored sessions all idle out at once needs 24k; 65,536 leaves room for
/// two such bursts plus tombstones (~0.3 KiB each: ~20 MiB at the cap).
pub(crate) const CLOSE_RETIREMENT_CAP: usize = 65_536;

/// Default fence hold (13 s cadence + 1 s GC) until a worker publishes its own.
const DEFAULT_HOLD_NS: u64 = 14_000_000_000;

#[derive(Clone, Debug)]
pub(crate) enum Retirement {
    /// The Close is owed and not yet flushed.
    Pending {
        key: SessionKey,
        owner_worker: u32,
        owner_rg: i32,
        retry_at_ns: u64,
        close: SessionDelta,
    },
    /// The Close was flushed; the tombstone fences late producers.
    Flushed { key: SessionKey, until_ns: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CreateOutcome {
    /// This producer owns the obligation: emit the Close.
    Created,
    /// Another producer owns (or already flushed) it: emit nothing.
    Exists,
    /// The directory is at its cap: emit the Close anyway (fail safe).
    Full,
}

impl CreateOutcome {
    /// Whether the producer must emit the Close.
    pub(crate) fn emits(self) -> bool {
        !matches!(self, Self::Exists)
    }
}

#[derive(Debug)]
pub(crate) struct CloseRetirementDirectory {
    entries: Mutex<FxHashMap<u64, Retirement>>,
    /// Idle gate for the per-worker sweep: 0 means nothing to scan.
    live: AtomicUsize,
    /// The current fence hold (cadence + GC), published by housekeeping.
    hold_ns: AtomicU64,
    cap: usize,
}

impl Default for CloseRetirementDirectory {
    fn default() -> Self {
        Self::with_cap(CLOSE_RETIREMENT_CAP)
    }
}

impl CloseRetirementDirectory {
    pub(crate) fn with_cap(cap: usize) -> Self {
        Self {
            entries: Mutex::new(FxHashMap::default()),
            live: AtomicUsize::new(0),
            hold_ns: AtomicU64::new(DEFAULT_HOLD_NS),
            cap,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FxHashMap<u64, Retirement>> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn hold_ns(&self) -> u64 {
        self.hold_ns.load(Ordering::Relaxed)
    }

    pub(crate) fn set_hold_ns(&self, hold_ns: u64) {
        self.hold_ns.store(hold_ns.max(1), Ordering::Relaxed);
    }

    pub(crate) fn len(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Whether any entry (Pending or Flushed) exists for `session_id`.
    pub(crate) fn contains(&self, session_id: u64) -> bool {
        self.len() != 0 && self.lock().contains_key(&session_id)
    }

    /// The compare-and-insert. `retry_at_ns` is when another worker may take
    /// the obligation over if this producer has not flushed it.
    pub(crate) fn try_create(
        &self,
        session_id: u64,
        owner_worker: u32,
        retry_at_ns: u64,
        close: &SessionDelta,
    ) -> CreateOutcome {
        let mut entries = self.lock();
        if entries.contains_key(&session_id) {
            return CreateOutcome::Exists;
        }
        if entries.len() >= self.cap {
            return CreateOutcome::Full;
        }
        entries.insert(
            session_id,
            Retirement::Pending {
                key: close.key.clone(),
                owner_worker,
                owner_rg: close.metadata.owner_rg_id,
                retry_at_ns,
                close: close.clone(),
            },
        );
        self.live.store(entries.len(), Ordering::Relaxed);
        CreateOutcome::Created
    }

    /// The flush ran this Close's emit legs: Pending -> Flushed (a tombstone
    /// for two holds). No-op without a matching entry.
    pub(crate) fn mark_flushed(&self, session_id: u64, key: &SessionKey, now_ns: u64) {
        if self.len() == 0 {
            return;
        }
        let until_ns = now_ns.saturating_add(self.hold_ns().saturating_mul(2));
        let mut entries = self.lock();
        if let Some(entry) = entries.get_mut(&session_id) {
            let matches = match entry {
                Retirement::Pending { key: k, .. } | Retirement::Flushed { key: k, .. } => k == key,
            };
            if matches {
                *entry = Retirement::Flushed {
                    key: key.clone(),
                    until_ns,
                };
            }
        }
    }

    /// The owner could not even queue its Close (a full ring): make the entry
    /// due at once so the next sweep pushes it.
    pub(crate) fn retry_now(&self, session_id: u64, now_ns: u64) {
        if let Some(Retirement::Pending { retry_at_ns, .. }) = self.lock().get_mut(&session_id) {
            *retry_at_ns = now_ns;
        }
    }

    /// One worker's sweep (once per GC interval). Renews the entries this
    /// worker still holds a Close for (`held_ids`: its parked and deferred
    /// Closes), takes over every other expired Pending entry of a forwarded
    /// RG, drops Pending entries of RGs this node no longer forwards, and
    /// expires tombstones. Returns the Closes this worker must now push.
    pub(crate) fn sweep(
        &self,
        worker_id: u32,
        now_ns: u64,
        held_ids: &[u64],
        forwards_rg: &dyn Fn(i32) -> bool,
    ) -> Vec<SessionDelta> {
        if self.len() == 0 {
            return Vec::new();
        }
        let renew_to = now_ns.saturating_add(self.hold_ns());
        let mut take = Vec::new();
        let mut entries = self.lock();
        for id in held_ids {
            if let Some(Retirement::Pending {
                owner_worker,
                retry_at_ns,
                ..
            }) = entries.get_mut(id)
                && *owner_worker == worker_id
            {
                *retry_at_ns = renew_to;
            }
        }
        entries.retain(|_, entry| match entry {
            Retirement::Flushed { until_ns, .. } => now_ns < *until_ns,
            Retirement::Pending {
                owner_worker,
                owner_rg,
                retry_at_ns,
                close,
                ..
            } => {
                if !forwards_rg(*owner_rg) {
                    return false;
                }
                if now_ns >= *retry_at_ns {
                    *owner_worker = worker_id;
                    *retry_at_ns = renew_to;
                    take.push(close.clone());
                }
                true
            }
        });
        self.live.store(entries.len(), Ordering::Relaxed);
        take
    }

    /// Test seam: the entry for `session_id`.
    #[cfg(test)]
    pub(crate) fn entry_for_test(&self, session_id: u64) -> Option<Retirement> {
        self.lock().get(&session_id).cloned()
    }
}

#[cfg(test)]
#[path = "close_retirement_19026_tests.rs"]
mod close_retirement_19026_tests;
