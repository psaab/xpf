//! #17084: the single lifecycle implementation shared by the GRE
//! local-origin and WG control aux-thread families.
//!
//! Before #17084 `tunnel_supervision.rs` held two hand-mirrored copies
//! of the #1866/#1881 lifecycle (finished sweep, bulk stop/join,
//! stop-all, defer-branch prune) plus two further inline copies in
//! `stop_inner`; they diverged in the defer-branch stale rule (GRE
//! reaped same-id attachment drift since `b2f5560fa9`, WG did not) and
//! in stop/join shape (WG bulk signal-then-join since #1889, GRE
//! serial). This module is the one source of truth: a
//! `TunnelThreadRegistry<E: TunnelThreadEntry>` owns the
//! `BTreeMap<u16, E>` and provides `sweep_finished`, bulk
//! `stop_remove`, `stop_all`, `clear`, the defer-prune batch
//! computation and the live-delivery iterators. The family-specific
//! stale PREDICATES and spawn bodies stay in `tunnel_supervision.rs`
//! — those are the real differences (see coordinator README "Aux
//! tunnel threads").
//!
//! Invariants enforced here, once, for both families:
//! - unpublish-before-join: callers exclude the stale set from the
//!   published delivery map before `stop_remove` joins any thread;
//! - bulk stop/join: signal ALL handles first, then join each, so a
//!   batch costs ~one poll cap, not N caps (#1889);
//! - the finished sweep tombstones (handle + delivery cleared,
//!   backoff stamp and spawned attachment retained) and never removes;
//! - `stop_all`/`clear` signal-then-join every live handle, then clear
//!   tombstones too — the `stop_inner` no-mutation-after-stop fence.

use super::*;

/// One aux-thread lifecycle entry. Both families share the handle,
/// spawned attachment, delivery endpoint and backoff stamp; WG adds
/// engine/crypto captures that only its stale predicate reads.
pub(crate) trait TunnelThreadEntry {
    #[allow(private_interfaces)]
    fn handle(&self) -> &Option<LocalTunnelSourceHandle>;
    #[allow(private_interfaces)]
    fn handle_mut(&mut self) -> &mut Option<LocalTunnelSourceHandle>;
    fn spawned_ifindex(&self) -> i32;
    fn spawned_tunnel_name(&self) -> &str;
    fn delivery_tx_mut(&mut self) -> &mut Option<LocalTunnelDelivery>;
    fn delivery_tx(&self) -> Option<&LocalTunnelDelivery>;
    /// Family label for lifecycle log lines ("GRE local-origin" / "WG control").
    fn family_label() -> &'static str;

    fn is_tombstone(&self) -> bool {
        self.handle().is_none()
    }
    fn handle_finished(&self) -> bool {
        self.handle()
            .as_ref()
            .is_some_and(|h| h.join.as_ref().is_none_or(|j| j.is_finished()))
    }
}

#[allow(private_interfaces)]
impl TunnelThreadEntry for LocalTunnelSourceEntry {
    fn handle(&self) -> &Option<LocalTunnelSourceHandle> {
        &self.handle
    }
    fn handle_mut(&mut self) -> &mut Option<LocalTunnelSourceHandle> {
        &mut self.handle
    }
    fn spawned_ifindex(&self) -> i32 {
        self.spawned_ifindex
    }
    fn spawned_tunnel_name(&self) -> &str {
        &self.spawned_tunnel_name
    }
    fn delivery_tx_mut(&mut self) -> &mut Option<LocalTunnelDelivery> {
        &mut self.delivery_tx
    }
    fn delivery_tx(&self) -> Option<&LocalTunnelDelivery> {
        self.delivery_tx.as_ref()
    }
    fn family_label() -> &'static str {
        "GRE local-origin"
    }
}

#[allow(private_interfaces)]
impl TunnelThreadEntry for WgControlEntry {
    fn handle(&self) -> &Option<LocalTunnelSourceHandle> {
        &self.handle
    }
    fn handle_mut(&mut self) -> &mut Option<LocalTunnelSourceHandle> {
        &mut self.handle
    }
    fn spawned_ifindex(&self) -> i32 {
        self.spawned_ifindex
    }
    fn spawned_tunnel_name(&self) -> &str {
        &self.spawned_tunnel_name
    }
    fn delivery_tx_mut(&mut self) -> &mut Option<LocalTunnelDelivery> {
        &mut self.delivery_tx
    }
    fn delivery_tx(&self) -> Option<&LocalTunnelDelivery> {
        self.delivery_tx.as_ref()
    }
    fn family_label() -> &'static str {
        "WG control"
    }
}

/// Snapshot-row label: linux_name with fallback to the logical name
/// (mirrors forwarding_build/interfaces.rs). Shared by both defer
/// prunes and both tombstone-respawn coherence checks.
pub(crate) fn snapshot_row_label(row: &crate::protocol::snapshot::TunnelEndpointSnapshot) -> &str {
    if row.linux_name.is_empty() {
        row.interface.as_str()
    } else {
        row.linux_name.as_str()
    }
}

/// The one aux-thread registry: owns one family's entry map and every
/// lifecycle operation whose shape must not diverge again.
pub(crate) struct TunnelThreadRegistry<E: TunnelThreadEntry> {
    entries: BTreeMap<u16, E>,
}

impl<E: TunnelThreadEntry> Default for TunnelThreadRegistry<E> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<E: TunnelThreadEntry> TunnelThreadRegistry<E> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get(&self, id: &u16) -> Option<&E> {
        self.entries.get(id)
    }

    #[cfg(test)]
    pub(crate) fn get_mut(&mut self, id: &u16) -> Option<&mut E> {
        self.entries.get_mut(id)
    }
    pub(crate) fn insert(&mut self, id: u16, entry: E) -> Option<E> {
        self.entries.insert(id, entry)
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, id: &u16) -> bool {
        self.entries.contains_key(id)
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&u16, &E)> {
        self.entries.iter()
    }

    #[cfg(test)]
    pub(crate) fn keys(&self) -> impl Iterator<Item = &u16> {
        self.entries.keys()
    }
    /// Pass 1 (shared): join threads that already exited and tombstone
    /// their entries (keep backoff stamp + attachment; never remove).
    /// Returns the number of entries tombstoned.
    pub(crate) fn sweep_finished(&mut self) -> usize {
        let finished: Vec<u16> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.handle_finished())
            .map(|(id, _)| *id)
            .collect();
        let swept = finished.len();
        for id in finished {
            if let Some(entry) = self.entries.get_mut(&id) {
                if let Some(mut handle) = entry.handle_mut().take() {
                    handle.request_stop();
                    if let Some(join) = handle.join.take() {
                        let _ = join.join();
                    }
                }
                *entry.delivery_tx_mut() = None;
                eprintln!(
                    "xpf-userspace-dp: {} thread exited endpoint={id} tun={} — tombstoned (respawn if still configured)",
                    E::family_label(),
                    entry.spawned_tunnel_name()
                );
            }
        }
        swept
    }

    /// Bulk stop + join + REMOVE (shared). Signals ALL listed live
    /// handles FIRST, then joins each — a serial stop+join would cost
    /// N poll caps on the control-socket thread; signal-then-join
    /// bounds the batch at ~one cap (#1889). Callers MUST unpublish
    /// the batch from the delivery map before invoking this
    /// (unpublish-before-join). Tombstones are removed and logged too.
    /// `before_join` runs after signal, immediately before the first
    /// join (test-only #10553 probe; production passes a no-op).
    pub(crate) fn stop_remove(&mut self, batch: &[(u16, &str)], before_join: impl Fn()) {
        let mut removed: Vec<(u16, &str, LocalTunnelSourceHandle, String)> = Vec::new();
        for (id, reason) in batch {
            if let Some(mut entry) = self.entries.remove(id) {
                let name = entry.spawned_tunnel_name().to_string();
                if let Some(handle) = entry.handle_mut().take() {
                    handle.request_stop();
                    removed.push((*id, reason, handle, name));
                } else {
                    eprintln!(
                        "xpf-userspace-dp: stopped {} thread endpoint={id} tun={name} reason={reason}",
                        E::family_label()
                    );
                }
            }
        }
        before_join();
        for (id, reason, mut handle, name) in removed {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
            eprintln!(
                "xpf-userspace-dp: stopped {} thread endpoint={id} tun={name} reason={reason}",
                E::family_label()
            );
        }
    }

    /// Stop + join + remove ALL entries (live and tombstoned).
    pub(crate) fn stop_all(&mut self, reason: &str, before_join: impl Fn()) {
        let batch: Vec<(u16, &str)> = self.entries.keys().map(|id| (*id, reason)).collect();
        self.stop_remove(&batch, before_join);
    }

    /// `stop_inner` teardown: signal all live handles, join each, then
    /// clear everything (tombstones too — after a stop the next
    /// reconcile re-legitimates entries). One implementation for both
    /// maps; this is the no-mutation-after-stop fence.
    pub(crate) fn clear(&mut self) {
        for entry in self.entries.values_mut() {
            if let Some(handle) = entry.handle().as_ref() {
                handle.request_stop();
            }
        }
        for entry in self.entries.values_mut() {
            if let Some(handle) = entry.handle_mut().as_mut() {
                if let Some(join) = handle.join.take() {
                    let _ = join.join();
                }
            }
        }
        self.entries.clear();
    }

    /// Defer-branch stale batch (shared shape): apply the family
    /// predicate to every entry and collect (id, reason) pairs. The
    /// caller unpublishes these ids, then calls `stop_remove`.
    pub(crate) fn deferred_stale_batch(
        &self,
        stale_reason: impl Fn(u16, &E) -> Option<&'static str>,
    ) -> Vec<(u16, &'static str)> {
        self.entries
            .iter()
            .filter_map(|(id, entry)| stale_reason(*id, entry).map(|r| (*id, r)))
            .collect()
    }

    /// Live-handle-only delivery publication source: yields
    /// (spawned_ifindex, delivery) for entries with a live handle not
    /// in `exclude`. The coordinator merges both families into the
    /// one published map.
    pub(crate) fn live_deliveries_excluding<'a>(
        &'a self,
        exclude: &'a [u16],
    ) -> impl Iterator<Item = (i32, LocalTunnelDelivery)> + 'a {
        self.entries.iter().filter_map(move |(id, entry)| {
            if exclude.contains(id) || entry.is_tombstone() {
                return None;
            }
            entry
                .delivery_tx()
                .map(|d| (entry.spawned_ifindex(), d.clone()))
        })
    }

    /// Tombstone ids (entries with no live handle) — liveness passes
    /// respawn from this set only, never create entries.
    pub(crate) fn tombstone_ids(&self) -> Vec<u16> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.is_tombstone())
            .map(|(id, _)| *id)
            .collect()
    }
}
