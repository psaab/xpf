//! #9856: dedicated per-worker owner-RG export buffer.
//!
//! The incremental RPC-fallback buffer (`BindingLiveState::pending_session_deltas`,
//! 4096 slots) cannot carry an export: past the cap the push drops and the
//! `more` bit cannot see the drop, so a FullResync ACKs a partial window.
//! The export rides here instead — one page-sized FIFO per worker, keyed by
//! worker (not binding: binding-less workers must still export, W-F10),
//! drained incrementally by the control thread while workers produce.
//!
//! Entries are `(token, info)` tuples: the token stays OUTSIDE
//! `SessionDeltaInfo` (W-F12 — no serde wire change, no fingerprint trip).
//! Full policy is SPLIT: export OPENS report Full without counting (the
//! worker pauses without advancing its cursor and retries next pass — never
//! a drop); TOMBSTONES drop with a metric (the incremental Close + fresh
//! take-generation backstop repairs them).

use super::*;

/// #9856: Full signal for export opens — pause, never drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::afxdp) struct ExportBufferFull;

/// #9856: dedicated per-worker export FIFO. See module docs.
pub(in crate::afxdp) struct ExportBufferState {
    pending: Mutex<VecDeque<(u64, SessionDeltaInfo)>>,
    export_generated: AtomicU64,
    export_dropped: AtomicU64,
    export_drained: AtomicU64,
    export_high_water: AtomicU64,
    export_discarded_foreign: AtomicU64,
}

impl ExportBufferState {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            pending: Mutex::new(VecDeque::new()),
            export_generated: AtomicU64::new(0),
            export_dropped: AtomicU64::new(0),
            export_drained: AtomicU64::new(0),
            export_high_water: AtomicU64::new(0),
            export_discarded_foreign: AtomicU64::new(0),
        }
    }

    /// Push an export OPEN for `token`. Full → `Err(Full)`, uncounted: the
    /// worker pauses without advancing its cursor and retries — never a drop.
    pub(in crate::afxdp) fn push_export_open(
        &self,
        token: u64,
        info: SessionDeltaInfo,
    ) -> Result<(), ExportBufferFull> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.len() >= EXPORT_BUFFER_CAP_ENTRIES {
            return Err(ExportBufferFull);
        }
        self.export_generated.fetch_add(1, Ordering::Relaxed);
        pending.push_back((token, info));
        self.export_high_water
            .fetch_max(pending.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Push an export TOMBSTONE for `token`. Full → drop + metric and
    /// return `Err(Full)`. The worker leaves the tombstone queued for a
    /// retry, while the per-window drop counter makes the eventual
    /// control response fail closed even if the retry cannot complete.
    pub(in crate::afxdp) fn push_export_tombstone(
        &self,
        token: u64,
        info: SessionDeltaInfo,
    ) -> Result<(), ExportBufferFull> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.len() >= EXPORT_BUFFER_CAP_ENTRIES {
            self.export_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(ExportBufferFull);
        }
        self.export_generated.fetch_add(1, Ordering::Relaxed);
        pending.push_back((token, info));
        self.export_high_water
            .fetch_max(pending.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Drain up to `max` entries oldest-first. Token-filtered collection
    /// lands with M2c; this raw drain serves tests and transitional callers.
    pub(in crate::afxdp) fn drain_export(&self, max: usize) -> Vec<(u64, SessionDeltaInfo)> {
        let drain = max.max(1);
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let count = drain.min(pending.len());
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(entry) = pending.pop_front() {
                out.push(entry);
            }
        }
        self.export_drained
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        out
    }

    /// #9856: drop every buffered entry NOT tagged `token` (superseded-window
    /// leftovers after a timeout-then-rekick; the worker calls this on accept).
    /// Uncounted: these belong to a dead window, and M3 terminal accounting
    /// attributes them there. Returns the purged count.
    pub(in crate::afxdp) fn purge_foreign(&self, token: u64) -> usize {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let before = pending.len();
        pending.retain(|(t, _)| *t == token);
        before - pending.len()
    }

    /// Tombstone drops (opens never drop — Full is a pause signal).
    pub(in crate::afxdp) fn export_dropped(&self) -> u64 {
        self.export_dropped.load(Ordering::Relaxed)
    }

    /// Record tombstones that overflowed the bounded session-side harvest
    /// before they could reach this buffer. The active export fails closed on
    /// the same cumulative metric as direct buffer drops.
    pub(in crate::afxdp) fn note_export_tombstone_drops(&self, drops: u64) {
        self.export_dropped.fetch_add(drops, Ordering::Relaxed);
    }

    /// True when the buffer holds an entry tagged `token`. Non-popping
    /// probe for the collect-loop terminal check: with it the terminal
    /// decision never over-drains past `max` (exact-fit pages stay exact).
    pub(in crate::afxdp) fn has_pending_export_for(&self, token: u64) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|(t, _)| *t == token)
    }

    /// Drain up to `max` entries tagged `token`, skipping any stale
    /// (foreign-token) prefix WITHOUT charging it against `max`, so a
    /// superseded window's leftovers can neither starve the current page
    /// nor fake an empty round. Foreign is always a prefix, never
    /// interleaved (single-producer FIFO order + purge-on-accept); the
    /// per-pop match below is defense-in-depth that stops rather than
    /// consuming past an unexpected boundary. Discards count in
    /// `export_discarded_foreign` — NEVER in `export_dropped`, which is
    /// the current-window fail-closed signal.
    pub(in crate::afxdp) fn drain_export_skipping_foreign(
        &self,
        token: u64,
        max: usize,
    ) -> Vec<SessionDeltaInfo> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        while matches!(pending.front(), Some((t, _)) if *t != token) {
            pending.pop_front();
            self.export_discarded_foreign
                .fetch_add(1, Ordering::Relaxed);
        }
        let mut out = Vec::new();
        for _ in 0..max {
            let front_matches = matches!(pending.front(), Some((t, _)) if *t == token);
            if !front_matches {
                break;
            }
            // Front is `token` (checked just above); the held lock means the
            // pop cannot fail.
            let (_, info) = pending.pop_front().expect("front checked above");
            out.push(info);
        }
        self.export_drained
            .fetch_add(out.len() as u64, Ordering::Relaxed);
        out
    }

    /// Superseded-window entries discarded by filtering (timeout-then-rekick
    /// leftovers). Distinct from `export_dropped` (current-window tombstone
    /// drops): only the latter fails an export closed.
    pub(in crate::afxdp) fn export_discarded_foreign(&self) -> u64 {
        self.export_discarded_foreign.load(Ordering::Relaxed)
    }
}

impl Default for ExportBufferState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opens report Full WITHOUT counting a drop (pause, never drop).
    #[test]
    fn export_opens_pause_without_counting_drops_9856() {
        let b = ExportBufferState::new();
        for i in 0..EXPORT_BUFFER_CAP_ENTRIES {
            assert!(
                b.push_export_open(7, SessionDeltaInfo::default()).is_ok(),
                "slot {i} must accept"
            );
        }
        assert_eq!(
            b.push_export_open(7, SessionDeltaInfo::default()),
            Err(ExportBufferFull)
        );
        assert_eq!(
            b.export_dropped(),
            0,
            "Full opens pause; nothing is dropped"
        );
        assert_eq!(b.drain_export(usize::MAX).len(), EXPORT_BUFFER_CAP_ENTRIES);
    }

    /// Tombstones drop WITH a metric on a full buffer (incremental backstop).
    #[test]
    fn export_tombstones_drop_with_metric_on_full_9856() {
        let b = ExportBufferState::new();
        for _ in 0..EXPORT_BUFFER_CAP_ENTRIES {
            let _ = b.push_export_open(7, SessionDeltaInfo::default());
        }
        let _ = b.push_export_tombstone(7, SessionDeltaInfo::default());
        assert_eq!(b.export_dropped(), 1);
    }

    /// Stale-prefix/current-suffix: foreign-tagged leftovers are skipped
    /// WITHOUT charging the quantum and WITHOUT touching `export_dropped`
    /// (that counter is the current-window fail-closed signal).
    #[test]
    fn drain_export_skips_foreign_prefix_without_charging_quantum_9856() {
        let b = ExportBufferState::new();
        for _ in 0..3 {
            b.push_export_open(7, SessionDeltaInfo::default())
                .expect("fixture fits");
        }
        for _ in 0..5 {
            b.push_export_open(9, SessionDeltaInfo::default())
                .expect("fixture fits");
        }
        let got = b.drain_export_skipping_foreign(9, 8);
        assert_eq!(got.len(), 5, "all current-token entries collected");
        assert_eq!(
            b.export_discarded_foreign(),
            3,
            "stale prefix counted separately"
        );
        assert_eq!(
            b.export_dropped(),
            0,
            "foreign discards must never trip the fail-closed drop counter"
        );
        assert!(
            b.drain_export(usize::MAX).is_empty(),
            "buffer fully drained — nothing left behind"
        );
    }
}
