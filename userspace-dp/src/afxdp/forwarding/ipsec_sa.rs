//! Shared inbound XFRM-SA existence snapshot for Stage-11 ESP-in-UDP.
//!
//! The packet path only reads the atomically published map.  The monitor is
//! deliberately the sole writer: kernel changes are folded into a fresh map
//! and published in one ArcSwap operation, so a worker cannot observe a
//! partially applied SA update.

use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum number of inbound ESP states retained by the control-plane cache.
pub(in crate::afxdp) const IPSEC_SA_SNAPSHOT_CAP: usize = 4096;

/// Compact key used by the data-plane lookup. Addresses are in network byte
/// order (IPv4 occupies the low four bytes of the u128); `family` prevents
/// IPv4/IPv6 numeric-tail collisions.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(in crate::afxdp) struct IpsecSaKey {
    pub(in crate::afxdp) family: u8,
    pub(in crate::afxdp) dst: u128,
    pub(in crate::afxdp) spi: u32,
    pub(in crate::afxdp) src: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::afxdp) struct IpsecSaEpoch {
    generation: u64,
    /// Presence-episode identifier. Fresh whenever the key transitions from
    /// absent to present; preserved across updates and redump retention, so
    /// a remove→re-add always reconciles as a different episode.
    incarnation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::afxdp) enum IpsecSaLookup {
    Hit,
    Miss,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::afxdp) enum IpsecSaMissReason {
    NoSa,
    Truncated,
    MalformedIke,
    Keepalive,
    Stale,
}

/// Process-wide counters owned by the SA monitor and read by status/tests.
/// The hot path updates only the miss atomics; it never takes a lock.
#[derive(Default)]
pub(in crate::afxdp) struct IpsecSaCounters {
    pub(in crate::afxdp) sa_miss_dropped_packets: AtomicU64,
    pub(in crate::afxdp) sa_miss_no_sa: AtomicU64,
    pub(in crate::afxdp) sa_miss_truncated: AtomicU64,
    pub(in crate::afxdp) sa_miss_malformed_ike: AtomicU64,
    pub(in crate::afxdp) sa_miss_keepalive: AtomicU64,
    pub(in crate::afxdp) sa_snapshot_stale_deny: AtomicU64,
    pub(in crate::afxdp) sa_inserts: AtomicU64,
    pub(in crate::afxdp) sa_removes: AtomicU64,
    pub(in crate::afxdp) sa_expiry_removes: AtomicU64,
    pub(in crate::afxdp) sa_evictions: AtomicU64,
    pub(in crate::afxdp) sa_multi_source_collisions: AtomicU64,
    pub(in crate::afxdp) netlink_enobufs: AtomicU64,
    pub(in crate::afxdp) netlink_redumps: AtomicU64,
    pub(in crate::afxdp) netlink_redump_upserts: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IpsecSaCounterSnapshot {
    pub(crate) sa_miss_dropped_packets: u64,
    pub(crate) sa_miss_no_sa: u64,
    pub(crate) sa_miss_truncated: u64,
    pub(crate) sa_miss_malformed_ike: u64,
    pub(crate) sa_miss_keepalive: u64,
    pub(crate) sa_snapshot_stale_deny: u64,
    pub(crate) sa_inserts: u64,
    pub(crate) sa_removes: u64,
    pub(crate) sa_expiry_removes: u64,
    pub(crate) sa_evictions: u64,
    pub(crate) sa_multi_source_collisions: u64,
    pub(crate) netlink_enobufs: u64,
    pub(crate) netlink_redumps: u64,
    pub(crate) netlink_redump_upserts: u64,
}

impl IpsecSaCounters {
    #[inline]
    pub(in crate::afxdp) fn record_miss(&self, reason: IpsecSaMissReason) {
        self.sa_miss_dropped_packets.fetch_add(1, Ordering::Relaxed);
        match reason {
            IpsecSaMissReason::NoSa => {
                self.sa_miss_no_sa.fetch_add(1, Ordering::Relaxed);
            }
            IpsecSaMissReason::Truncated => {
                self.sa_miss_truncated.fetch_add(1, Ordering::Relaxed);
            }
            IpsecSaMissReason::MalformedIke => {
                self.sa_miss_malformed_ike.fetch_add(1, Ordering::Relaxed);
            }
            IpsecSaMissReason::Keepalive => {
                self.sa_miss_keepalive.fetch_add(1, Ordering::Relaxed);
            }
            IpsecSaMissReason::Stale => {
                self.sa_snapshot_stale_deny.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    #[inline]
    fn record_multi_source_collisions(&self, count: u64) {
        if count != 0 {
            self.sa_multi_source_collisions
                .fetch_add(count, Ordering::Relaxed);
        }
    }

    pub(in crate::afxdp) fn snapshot(&self) -> IpsecSaCounterSnapshot {
        IpsecSaCounterSnapshot {
            sa_miss_dropped_packets: self.sa_miss_dropped_packets.load(Ordering::Relaxed),
            sa_miss_no_sa: self.sa_miss_no_sa.load(Ordering::Relaxed),
            sa_miss_truncated: self.sa_miss_truncated.load(Ordering::Relaxed),
            sa_miss_malformed_ike: self.sa_miss_malformed_ike.load(Ordering::Relaxed),
            sa_miss_keepalive: self.sa_miss_keepalive.load(Ordering::Relaxed),
            sa_snapshot_stale_deny: self.sa_snapshot_stale_deny.load(Ordering::Relaxed),
            sa_inserts: self.sa_inserts.load(Ordering::Relaxed),
            sa_removes: self.sa_removes.load(Ordering::Relaxed),
            sa_expiry_removes: self.sa_expiry_removes.load(Ordering::Relaxed),
            sa_evictions: self.sa_evictions.load(Ordering::Relaxed),
            sa_multi_source_collisions: self.sa_multi_source_collisions.load(Ordering::Relaxed),
            netlink_enobufs: self.netlink_enobufs.load(Ordering::Relaxed),
            netlink_redumps: self.netlink_redumps.load(Ordering::Relaxed),
            netlink_redump_upserts: self.netlink_redump_upserts.load(Ordering::Relaxed),
        }
    }
}

/// Immutable payload published as one unit to the packet path. Keeping the
/// map, generation, and stale fence together prevents a reader from observing
/// a new map with an old readiness decision.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct IpsecSaSnapshot {
    entries: FastMap<IpsecSaKey, IpsecSaEpoch>,
    generation: u64,
    stale: bool,
    /// Hard readiness/outage transition fence. Any mismatch invalidates the
    /// loaded batch, even when the queried key is retained.
    stale_epoch: u64,
    /// Selective deletion fence. On mismatch the lookup reconciles the
    /// queried key's presence incarnation against the current map: absent
    /// or re-created (remove→re-add) keys fence, untouched keys stay Hit.
    removal_epoch: u64,
}

/// `stale_epoch` advances on stale-state transitions and `removal_epoch`
/// advances on publications that remove an observed SA. Additive NEWSA/UPDSA
/// updates and unchanged redumps keep both epochs, so an in-flight batch can
/// retain its positive verdict during rekey overlap. Per-key `incarnation`
/// values identify presence episodes with no bounded history to evict: any
/// remove→re-add reconciles as a different episode no matter how much churn
/// separates the batch load from the lookup.
/// `revoked` is the teardown fence: set before the monitor join, it denies
/// lookups even if a racing in-flight dump publishes fresh state.
pub(in crate::afxdp) struct IpsecSaStore {
    snapshot: arc_swap::ArcSwap<IpsecSaSnapshot>,
    insertion_order: AtomicU64,
    incarnation: AtomicU64,
    stale_epoch: AtomicU64,
    removal_epoch: AtomicU64,
    revoked: AtomicBool,
    writer: Mutex<()>,
    pub(in crate::afxdp) counters: IpsecSaCounters,
}
impl std::fmt::Debug for IpsecSaStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snapshot = self.snapshot.load();
        f.debug_struct("IpsecSaStore")
            .field("generation", &snapshot.generation)
            .field("stale", &snapshot.stale)
            .field("ready", &(snapshot.generation != 0 && !snapshot.stale))
            .field("entries", &snapshot.entries.len())
            .finish()
    }
}

impl Default for IpsecSaStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IpsecSaStore {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            snapshot: arc_swap::ArcSwap::from_pointee(IpsecSaSnapshot {
                entries: FastMap::default(),
                generation: 0,
                stale: true,
                stale_epoch: 0,
                removal_epoch: 0,
            }),
            insertion_order: AtomicU64::new(0),
            incarnation: AtomicU64::new(0),
            stale_epoch: AtomicU64::new(0),
            removal_epoch: AtomicU64::new(0),
            revoked: AtomicBool::new(false),
            writer: Mutex::new(()),
            counters: IpsecSaCounters::default(),
        }
    }

    #[inline]
    fn lock_writer(&self) -> std::sync::MutexGuard<'_, ()> {
        self.writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[inline]
    pub(in crate::afxdp) fn load_snapshot(&self) -> Arc<IpsecSaSnapshot> {
        self.snapshot.load_full()
    }

    #[inline]
    fn next_stale_epoch(&self) -> u64 {
        self.stale_epoch.load(Ordering::Relaxed).wrapping_add(1)
    }

    #[inline]
    fn next_removal_epoch(&self) -> u64 {
        self.removal_epoch.load(Ordering::Relaxed).wrapping_add(1)
    }

    #[inline]
    fn publish_snapshot_at_epochs(
        &self,
        mut snapshot: IpsecSaSnapshot,
        stale_epoch: u64,
        removal_epoch: u64,
    ) {
        snapshot.stale_epoch = stale_epoch;
        snapshot.removal_epoch = removal_epoch;
        self.snapshot.store(Arc::new(snapshot));
    }

    #[inline]
    fn publish_snapshot_with_fences(
        &self,
        snapshot: IpsecSaSnapshot,
        stale_fence: bool,
        removal_fence: bool,
    ) {
        self.publish_snapshot_with_fences_hook(snapshot, stale_fence, removal_fence, || {});
    }

    #[inline]
    fn publish_snapshot_with_fences_hook<F>(
        &self,
        snapshot: IpsecSaSnapshot,
        stale_fence: bool,
        removal_fence: bool,
        after_snapshot: F,
    ) where
        F: FnOnce(),
    {
        let next_stale_epoch = if stale_fence {
            self.next_stale_epoch()
        } else {
            self.stale_epoch.load(Ordering::Relaxed)
        };
        let next_removal_epoch = if removal_fence {
            self.next_removal_epoch()
        } else {
            self.removal_epoch.load(Ordering::Relaxed)
        };
        // Publish the replacement snapshot first. Each release epoch store is
        // the corresponding revocation linearization point; an acquiring
        // reader that observes it must therefore load this snapshot, never
        // the old one.
        self.publish_snapshot_at_epochs(snapshot, next_stale_epoch, next_removal_epoch);
        after_snapshot();
        if stale_fence {
            self.stale_epoch.store(next_stale_epoch, Ordering::Release);
        }
        if removal_fence {
            self.removal_epoch
                .store(next_removal_epoch, Ordering::Release);
        }
    }

    #[cfg(test)]
    fn publish_snapshot_with_removal_fence_paused(
        &self,
        snapshot: IpsecSaSnapshot,
        snapshot_published: &std::sync::Barrier,
        release_epoch: &std::sync::Barrier,
    ) {
        self.publish_snapshot_with_fences_hook(snapshot, false, true, || {
            drop(snapshot_published.wait());
            drop(release_epoch.wait());
        });
    }

    pub(in crate::afxdp) fn mark_stale(&self) {
        let _writer = self.lock_writer();
        let current = self.snapshot.load_full();
        if current.stale {
            return;
        }
        let mut next = (*current).clone();
        next.stale = true;
        self.publish_snapshot_with_fences(next, true, false);
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::afxdp) fn lookup(&self, key: IpsecSaKey) -> IpsecSaLookup {
        let snapshot = self.snapshot.load_full();
        self.lookup_loaded(&snapshot, key)
    }

    #[inline]
    pub(in crate::afxdp) fn lookup_loaded(
        &self,
        snapshot: &IpsecSaSnapshot,
        key: IpsecSaKey,
    ) -> IpsecSaLookup {
        // Teardown revocation denies even a fresh snapshot: a racing
        // in-flight dump may publish fresh state after stop begins.
        if self.revoked.load(Ordering::Acquire) {
            return IpsecSaLookup::Stale;
        }
        // A hard stale-state transition invalidates every lookup in the
        // loaded batch, even when the queried key survives recovery.
        if self.stale_epoch.load(Ordering::Acquire) != snapshot.stale_epoch {
            return IpsecSaLookup::Stale;
        }
        // Removal fences are selective so a rekey-overlap batch can retain a
        // positive verdict for a surviving/new SA. The incarnation check
        // fences a removed key even if it was re-added before this batch is
        // drained: re-creation always mints a fresh presence episode.
        if self.removal_epoch.load(Ordering::Acquire) != snapshot.removal_epoch {
            let current = self.snapshot.load();
            if current.stale || current.generation == 0 {
                return IpsecSaLookup::Stale;
            }
            if let Some(loaded) = snapshot.entries.get(&key) {
                let reincarnated = current
                    .entries
                    .get(&key)
                    .is_none_or(|live| live.incarnation != loaded.incarnation);
                if reincarnated {
                    return IpsecSaLookup::Stale;
                }
            }
        }
        Self::lookup_snapshot(snapshot, key)
    }

    #[inline]
    pub(in crate::afxdp) fn lookup_snapshot(
        snapshot: &IpsecSaSnapshot,
        key: IpsecSaKey,
    ) -> IpsecSaLookup {
        if snapshot.stale || snapshot.generation == 0 {
            return IpsecSaLookup::Stale;
        }
        if snapshot.entries.contains_key(&key) {
            IpsecSaLookup::Hit
        } else {
            IpsecSaLookup::Miss
        }
    }

    #[inline]
    fn next_insertion_order(&self) -> u64 {
        self.insertion_order
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    #[inline]
    fn next_incarnation(&self) -> u64 {
        self.incarnation
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    fn normalize_dump_entries(
        &self,
        entries: FastMap<IpsecSaKey, IpsecSaEpoch>,
    ) -> FastMap<IpsecSaKey, IpsecSaEpoch> {
        // A complete dump carries per-record XFRM `add_time` as the incoming
        // `generation`. Sort oldest-first (ties by key for determinism), then
        // assign one shared monotonic domain in that sequence: cap eviction
        // keeps "oldest SA first", while later incremental upserts — drawn
        // from the same counter — always sort newer.
        let mut ordered: Vec<(IpsecSaKey, u64)> = entries
            .iter()
            .map(|(key, epoch)| (*key, epoch.generation))
            .collect();
        ordered.sort_unstable_by(|(key_a, age_a), (key_b, age_b)| {
            age_a.cmp(age_b).then_with(|| key_a.cmp(key_b))
        });
        let mut normalized = FastMap::default();
        for (key, _) in ordered {
            normalized.insert(
                key,
                IpsecSaEpoch {
                    generation: self.next_insertion_order(),
                    // Placeholder: the publisher reconciles presence episodes
                    // below, preserving retained keys and minting new ones.
                    incarnation: 0,
                },
            );
        }
        normalized
    }

    /// Publish a complete dump. The generation becomes non-zero only after
    /// the new map is visible, which makes the first successful dump the
    /// readiness gate for data-plane lookups.
    pub(in crate::afxdp) fn publish_full_dump(&self, entries: FastMap<IpsecSaKey, IpsecSaEpoch>) {
        let _writer = self.lock_writer();
        let current = self.snapshot.load();
        let generation = current.generation.saturating_add(1).max(1);
        let collisions = multi_source_collision_count(&entries);
        self.counters.record_multi_source_collisions(collisions);
        let entries = self.normalize_dump_entries(entries);
        let mut entries = cap_entries(entries, &self.counters);
        // Presence-episode reconciliation: retained keys keep their
        // incarnation so in-flight batches stay Hit; keys absent from the
        // current map mint a fresh episode. Cap eviction counts as removal.
        for (key, epoch) in entries.iter_mut() {
            epoch.incarnation = current
                .entries
                .get(key)
                .map(|live| live.incarnation)
                .unwrap_or_else(|| self.next_incarnation());
        }
        let removal_fence = current.entries.keys().any(|key| !entries.contains_key(key));
        // Stale→fresh and fresh→fresh deletion are both revocation
        // transitions. A fresh redump with no deletion is benign drift sync.
        let next = IpsecSaSnapshot {
            entries,
            generation,
            stale: false,
            stale_epoch: 0,
            removal_epoch: 0,
        };
        self.publish_snapshot_with_fences(next, current.stale, removal_fence);
    }
    pub(in crate::afxdp) fn reset_for_monitor_start(&self) {
        let _writer = self.lock_writer();
        // A (re)started monitor establishes a new baseline. Publish the
        // generation-zero stale fence while revocation is still asserted,
        // then clear the independent teardown fence. There is never a
        // ready-looking window in which old readers can race a reset.
        self.publish_snapshot_with_fences(
            IpsecSaSnapshot {
                entries: FastMap::default(),
                generation: 0,
                stale: true,
                stale_epoch: 0,
                removal_epoch: 0,
            },
            true,
            false,
        );
        self.revoked.store(false, Ordering::Release);
    }

    pub(in crate::afxdp) fn wait_ready(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while {
            let snapshot = self.snapshot.load();
            snapshot.generation == 0 || snapshot.stale
        } {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    pub(in crate::afxdp) fn upsert(&self, key: IpsecSaKey) {
        let _writer = self.lock_writer();
        let current = self.snapshot.load_full();
        let collision = current.entries.keys().any(|existing| {
            existing.family == key.family
                && existing.dst == key.dst
                && existing.spi == key.spi
                && existing.src != key.src
        });
        let mut entries = current.entries.clone();
        let generation = current.generation.saturating_add(1).max(1);
        // An update of a live key preserves its presence episode; only a
        // transition from absent mints a fresh incarnation.
        let incarnation = current
            .entries
            .get(&key)
            .map(|live| live.incarnation)
            .unwrap_or_else(|| self.next_incarnation());
        entries.insert(
            key,
            IpsecSaEpoch {
                generation: self.next_insertion_order(),
                incarnation,
            },
        );
        let entries = cap_entries(entries, &self.counters);
        let removal_fence = current
            .entries
            .keys()
            .any(|existing| !entries.contains_key(existing));
        let next = IpsecSaSnapshot {
            entries,
            generation,
            // Incremental NEWSA/UPDSA observations never clear a stale fence.
            stale: current.stale,
            stale_epoch: 0,
            removal_epoch: 0,
        };
        self.publish_snapshot_with_fences(next, false, removal_fence);
        if collision {
            self.counters.record_multi_source_collisions(1);
        }
        self.counters.sa_inserts.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn remove(&self, key: IpsecSaKey) -> bool {
        let _writer = self.lock_writer();
        let current = self.snapshot.load_full();
        let mut entries = current.entries.clone();
        let removed = entries.remove(&key).is_some();
        if removed {
            self.publish_snapshot_with_fences(
                IpsecSaSnapshot {
                    entries,
                    generation: current.generation,
                    stale: current.stale,
                    stale_epoch: 0,
                    removal_epoch: 0,
                },
                false,
                true,
            );
            self.counters.sa_removes.fetch_add(1, Ordering::Relaxed);
        }
        removed
    }

    pub(in crate::afxdp) fn remove_dst_spi(&self, family: u8, dst: u128, spi: u32) -> u64 {
        let _writer = self.lock_writer();
        let current = self.snapshot.load_full();
        let mut entries = current.entries.clone();
        let before = entries.len();
        entries.retain(|key, _| !(key.family == family && key.dst == dst && key.spi == spi));
        let removed = before.saturating_sub(entries.len());
        if removed != 0 {
            self.publish_snapshot_with_fences(
                IpsecSaSnapshot {
                    entries,
                    generation: current.generation,
                    stale: current.stale,
                    stale_epoch: 0,
                    removal_epoch: 0,
                },
                false,
                true,
            );
            self.counters
                .sa_removes
                .fetch_add(removed as u64, Ordering::Relaxed);
        }
        removed as u64
    }

    #[cfg(test)]
    fn entries_len(&self) -> usize {
        self.snapshot.load().entries.len()
    }

    #[cfg(test)]
    pub(crate) fn publish_empty_dump_for_test(&self) {
        self.publish_full_dump(FastMap::default());
    }
}

fn multi_source_collision_count(entries: &FastMap<IpsecSaKey, IpsecSaEpoch>) -> u64 {
    let mut groups: FastMap<(u8, u128, u32), u64> = FastMap::default();
    for key in entries.keys() {
        *groups.entry((key.family, key.dst, key.spi)).or_default() += 1;
    }
    groups.values().map(|count| count.saturating_sub(1)).sum()
}

fn cap_entries(
    mut entries: FastMap<IpsecSaKey, IpsecSaEpoch>,
    counters: &IpsecSaCounters,
) -> FastMap<IpsecSaKey, IpsecSaEpoch> {
    if entries.len() <= IPSEC_SA_SNAPSHOT_CAP {
        return entries;
    }
    let remove_count = entries.len() - IPSEC_SA_SNAPSHOT_CAP;
    let mut oldest: Vec<(IpsecSaKey, u64)> = entries
        .iter()
        .map(|(key, epoch)| (*key, epoch.generation))
        .collect();
    oldest.sort_unstable_by(|(key_a, epoch_a), (key_b, epoch_b)| {
        epoch_a.cmp(epoch_b).then_with(|| key_a.cmp(key_b))
    });
    for (key, _) in oldest.into_iter().take(remove_count) {
        entries.remove(&key);
        counters.sa_evictions.fetch_add(1, Ordering::Relaxed);
    }
    entries
}

#[inline]
pub(in crate::afxdp) fn ipsec_sa_key(dst: IpAddr, spi: u32, src: IpAddr) -> Option<IpsecSaKey> {
    let family = match (dst, src) {
        (IpAddr::V4(_), IpAddr::V4(_)) => libc::AF_INET as u8,
        (IpAddr::V6(_), IpAddr::V6(_)) => libc::AF_INET6 as u8,
        _ => return None,
    };
    Some(IpsecSaKey {
        family,
        dst: ip_to_u128(dst),
        spi,
        src: ip_to_u128(src),
    })
}

#[inline]
fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u128,
        IpAddr::V6(v6) => u128::from_be_bytes(v6.octets()),
    }
}

/// Classify and extract a UDP-4500 ESP SPI.  The caller handles positive IKE
/// first; this helper is deliberately defensive so a marker can never be
/// interpreted as an ESP SPI.
#[inline]
pub(in crate::afxdp) fn esp_in_udp_spi(
    packet_frame: &[u8],
    l4_offset: usize,
    dst_port: u16,
    declared_end: usize,
) -> Option<u32> {
    if dst_port != 4500 {
        return None;
    }
    let payload = esp_in_udp_payload(packet_frame, l4_offset, declared_end)?;
    if payload == [0xff] {
        return None;
    }
    let spi = u32::from_be_bytes(payload.get(0..4)?.try_into().ok()?);
    if spi == 0 {
        return None;
    }
    Some(spi)
}

fn esp_in_udp_payload(packet_frame: &[u8], l4_offset: usize, declared_end: usize) -> Option<&[u8]> {
    let packet = packet_frame.get(..declared_end)?;
    let header_end = l4_offset.checked_add(8)?;
    let header = packet.get(l4_offset..header_end)?;
    let udp_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    if udp_len < 8 {
        return None;
    }
    let packet_end = l4_offset.checked_add(udp_len)?;
    packet.get(header_end..packet_end)
}

#[inline]
pub(in crate::afxdp) fn esp_in_udp_miss_reason(
    packet_frame: &[u8],
    l4_offset: usize,
    dst_port: u16,
    declared_end: usize,
) -> IpsecSaMissReason {
    // Deliberately coarse: any non-4500 input (e.g. UDP/500 non-IKE data
    // that survived the IKE screens) cannot be ESP-in-UDP and is counted
    // as truncated. Drop-correct; no finer counter exists for this shape.
    if dst_port != 4500 {
        return IpsecSaMissReason::Truncated;
    }
    let Some(payload) = esp_in_udp_payload(packet_frame, l4_offset, declared_end) else {
        return IpsecSaMissReason::Truncated;
    };
    if payload == [0xff] {
        return IpsecSaMissReason::Keepalive;
    }
    if payload.len() < 4 {
        IpsecSaMissReason::Truncated
    } else {
        IpsecSaMissReason::NoSa
    }
}

/// Minimal monitor state used by the coordinator lifecycle.  Socket parsing
/// is intentionally isolated below so deterministic tests can drive the store
/// without requiring NETLINK_XFRM privileges.
pub(in crate::afxdp) struct IpsecSaMonitor {
    pub(in crate::afxdp) store: Arc<IpsecSaStore>,
    pub(in crate::afxdp) stop: Option<Arc<AtomicBool>>,
    pub(in crate::afxdp) join: Option<std::thread::JoinHandle<()>>,
}

impl IpsecSaMonitor {
    pub(in crate::afxdp) fn new() -> Self {
        Self {
            store: Arc::new(IpsecSaStore::new()),
            stop: None,
            join: None,
        }
    }

    pub(in crate::afxdp) fn stop_and_join(&mut self) {
        // Revoke FIRST: lookups deny from here on even if a racing in-flight
        // dump publishes fresh state before the join completes. The stale
        // fences below keep the stored snapshot consistent for direct
        // readers; revocation is what makes "fence immediately" true.
        self.store.revoked.store(true, Ordering::Release);
        self.store.mark_stale();
        if let Some(stop) = self.stop.take() {
            stop.store(true, Ordering::Release);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        self.store.mark_stale();
    }
}
const NLMSG_OVERRUN: u16 = 4;

const NLMSG_HDR_LEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const XFRM_MSG_NEWSA: u16 = 0x10;
const XFRM_MSG_DELSA: u16 = 0x11;
const XFRM_MSG_GETSA: u16 = 0x12;
const XFRM_MSG_EXPIRE: u16 = 0x18;
const XFRM_MSG_UPDSA: u16 = 0x1a;
const XFRM_MSG_FLUSHSA: u16 = 0x1c;
const XFRMA_SA_DIR: u16 = 33;
const XFRM_SA_DIR_IN: u8 = 1;
const XFRMGRP_EXPIRE: u32 = 2;
const XFRMGRP_SA: u32 = 4;
const XFRM_INFO_LEN: usize = 224;
const XFRM_MSG_ID_LEN: usize = 24;

enum XfrmEventResult {
    Idle,
    NeedRedump,
    Stop,
}

/// Receive one multicast XFRM event. A timeout returns control to the outer
/// monitor so it can re-check the periodic drift-redump deadline.
fn recv_xfrm_events(fd: libc::c_int, store: &IpsecSaStore, stop: &AtomicBool) -> XfrmEventResult {
    if stop.load(Ordering::Acquire) {
        return XfrmEventResult::Stop;
    }
    let mut buf = [0u8; 64 * 1024];
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        let err = std::io::Error::last_os_error().raw_os_error();
        if err == Some(libc::EAGAIN) {
            return XfrmEventResult::Idle;
        }
        if err == Some(libc::ENOBUFS) {
            store
                .counters
                .netlink_enobufs
                .fetch_add(1, Ordering::Relaxed);
        }
        store.mark_stale();
        return XfrmEventResult::NeedRedump;
    }
    if n == 0 {
        store.mark_stale();
        return XfrmEventResult::NeedRedump;
    }
    if apply_xfrm_messages(store, &buf[..n as usize]) {
        store.mark_stale();
        XfrmEventResult::NeedRedump
    } else {
        XfrmEventResult::Idle
    }
}

/// Run the event-driven XFRM-SA monitor.  A failed socket, dump, or receive
/// operation immediately sets the stale fence; only a later complete dump
/// clears it.  The 500 ms receive timeout is the lifecycle join bound.
pub(in crate::afxdp) fn ipsec_sa_monitor_loop(store: Arc<IpsecSaStore>, stop: Arc<AtomicBool>) {
    let fd = match open_xfrm_socket() {
        Some(fd) => fd,
        None => {
            store.mark_stale();
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(500));
            }
            return;
        }
    };
    let mut seq = 1u32;
    let mut next_drift = std::time::Instant::now() + Duration::from_secs(30);
    let mut dump_ready = false;
    while !stop.load(Ordering::Acquire) {
        if !dump_ready || std::time::Instant::now() >= next_drift {
            store
                .counters
                .netlink_redumps
                .fetch_add(1, Ordering::Relaxed);
            let ok = full_dump(fd, &store, seq);
            seq = seq.wrapping_add(1).max(1);
            if ok {
                dump_ready = true;
                next_drift = std::time::Instant::now() + Duration::from_secs(30);
            } else {
                store.mark_stale();
                dump_ready = false;
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        }
        match recv_xfrm_events(fd, &store, &stop) {
            XfrmEventResult::Stop => break,
            XfrmEventResult::NeedRedump => dump_ready = false,
            XfrmEventResult::Idle => {}
        }
    }
    unsafe {
        libc::close(fd);
    }
}

fn open_xfrm_socket() -> Option<libc::c_int> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_XFRM,
        )
    };
    if fd < 0 {
        return None;
    }
    let groups = XFRMGRP_SA | XFRMGRP_EXPIRE;
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = groups;
    let bound = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        unsafe {
            libc::close(fd);
        }
        return None;
    }
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 500_000,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        unsafe {
            libc::close(fd);
        }
        return None;
    }
    Some(fd)
}

/// #10647: can this test process drive the IPsec SA monitor baseline?
/// Worker bring-up waits up to 5s for the monitor's first GETSA dump, and
/// the monitor needs a privileged NETLINK_XFRM bind (groups SA|EXPIRE).
/// Unprivileged, bring-up aborts with `IpsecSaNotReady` before the test's
/// subject — so XFRM-dependent lifecycle tests gate on this probe and
/// return early with an explicit SKIP instead of failing on sandbox
/// privilege. This probes the CAPABILITY (bind it, close it), never the
/// uid: root in a restricted net namespace still fails, and a
/// capability-granted non-root still passes.
#[cfg(test)]
pub(crate) fn xfrm_monitor_usable() -> bool {
    match open_xfrm_socket() {
        Some(fd) => {
            unsafe {
                libc::close(fd);
            }
            true
        }
        None => false,
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XfrmLifecycleSkipAction {
    Continue,
    Skip,
    Fail,
}

#[cfg(test)]
fn xfrm_lifecycle_skip_action(monitor_usable: bool, must_run: bool) -> XfrmLifecycleSkipAction {
    match (monitor_usable, must_run) {
        (true, _) => XfrmLifecycleSkipAction::Continue,
        (false, false) => XfrmLifecycleSkipAction::Skip,
        (false, true) => XfrmLifecycleSkipAction::Fail,
    }
}

#[cfg(test)]
fn apply_xfrm_lifecycle_skip_action(action: XfrmLifecycleSkipAction) -> bool {
    match action {
        XfrmLifecycleSkipAction::Continue => true,
        XfrmLifecycleSkipAction::Skip => {
            eprintln!("SKIP: needs NETLINK_XFRM bind privilege for the SA-monitor baseline");
            false
        }
        XfrmLifecycleSkipAction::Fail => {
            panic!(
                "XPF_REQUIRE_XFRM_LIFECYCLE is set, but NETLINK_XFRM bind is unavailable; \
                 this lifecycle test must run in the privileged gate"
            );
        }
    }
}

/// Run from every lifecycle test whose setup requires the kernel XFRM monitor.
/// Ordinary unprivileged suites keep their documented SKIP behavior; the
/// privileged `make test-xfrm-lifecycle` leg sets the must-run gate so a missing
/// NETLINK_XFRM capability fails the test instead of silently passing it.
#[cfg(test)]
pub(crate) fn require_xfrm_monitor_for_lifecycle_test() -> bool {
    let must_run = std::env::var_os("XPF_REQUIRE_XFRM_LIFECYCLE").is_some();
    apply_xfrm_lifecycle_skip_action(xfrm_lifecycle_skip_action(xfrm_monitor_usable(), must_run))
}

#[cfg(test)]
#[test]
fn xfrm_lifecycle_unprivileged_skip_is_preserved_10868() {
    assert!(!apply_xfrm_lifecycle_skip_action(
        xfrm_lifecycle_skip_action(false, false,)
    ));
}

#[cfg(test)]
#[test]
#[should_panic(expected = "XPF_REQUIRE_XFRM_LIFECYCLE is set")]
fn xfrm_lifecycle_must_run_gate_rejects_skip_10868() {
    apply_xfrm_lifecycle_skip_action(xfrm_lifecycle_skip_action(false, true));
}

#[cfg(test)]
#[test]
fn xfrm_lifecycle_must_run_gate_runs_with_xfrm_10868() {
    assert!(apply_xfrm_lifecycle_skip_action(
        xfrm_lifecycle_skip_action(true, true,)
    ));
}

fn full_dump(fd: libc::c_int, store: &IpsecSaStore, seq: u32) -> bool {
    let mut request = [0u8; NLMSG_HDR_LEN + XFRM_MSG_ID_LEN];
    let request_len = request.len() as u32;
    put_u32(&mut request[0..4], request_len);
    put_u16(&mut request[4..6], XFRM_MSG_GETSA);
    put_u16(&mut request[6..8], NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH);
    put_u32(&mut request[8..12], seq);
    put_u32(&mut request[12..16], 0);
    // The all-zero xfrm_usersa_id is the kernel's dump selector.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = 0;
    let sent = unsafe {
        libc::sendto(
            fd,
            request.as_ptr().cast(),
            request.len(),
            libc::MSG_NOSIGNAL,
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent != request.len() as isize {
        return false;
    }
    let mut entries = FastMap::default();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOBUFS) {
                store
                    .counters
                    .netlink_enobufs
                    .fetch_add(1, Ordering::Relaxed);
            }
            return false;
        }
        let bytes = &buf[..n as usize];
        let mut offset = 0usize;
        while offset + NLMSG_HDR_LEN <= bytes.len() {
            let len = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            if len < NLMSG_HDR_LEN || offset + len > bytes.len() {
                return false;
            }
            let msg_type = u16::from_ne_bytes(bytes[offset + 4..offset + 6].try_into().unwrap());
            let flags = u16::from_ne_bytes(bytes[offset + 6..offset + 8].try_into().unwrap());
            let msg_seq = u32::from_ne_bytes(bytes[offset + 8..offset + 12].try_into().unwrap());
            // A multicast event interleaving a dump, or the kernel's
            // NLM_F_DUMP_INTR marker, invalidates the candidate snapshot.
            // Abort and retry rather than publishing a pre-delete map.
            if msg_seq != seq || (flags & 0x0010) != 0 {
                return false;
            }
            let payload = &bytes[offset + NLMSG_HDR_LEN..offset + len];
            if msg_type == NLMSG_DONE {
                if offset + ((len + 3) & !3) != bytes.len() {
                    return false;
                }
                store
                    .counters
                    .netlink_redump_upserts
                    .fetch_add(entries.len() as u64, Ordering::Relaxed);
                store.publish_full_dump(entries);
                return true;
            }
            if msg_type == NLMSG_ERROR || msg_type == NLMSG_OVERRUN {
                return false;
            }
            if msg_type == XFRM_MSG_NEWSA {
                if let Some((key, add_time)) = parse_sa_payload_with_epoch(payload, true) {
                    entries.insert(
                        key,
                        IpsecSaEpoch {
                            generation: add_time,
                            incarnation: 0,
                        },
                    );
                }
            }
            offset += (len + 3) & !3;
        }
        if offset != bytes.len() {
            return false;
        }
    }
}

/// Return true when a full dump is required after applying these event
/// messages (FLUSHSA or a malformed/uncertain event).
fn apply_xfrm_messages(store: &IpsecSaStore, bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + NLMSG_HDR_LEN <= bytes.len() {
        let len = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        if len < NLMSG_HDR_LEN || offset + len > bytes.len() {
            return true;
        }
        let msg_type = u16::from_ne_bytes(bytes[offset + 4..offset + 6].try_into().unwrap());
        let payload = &bytes[offset + NLMSG_HDR_LEN..offset + len];
        match msg_type {
            NLMSG_ERROR | NLMSG_OVERRUN | NLMSG_DONE => return true,
            XFRM_MSG_NEWSA | XFRM_MSG_UPDSA => {
                if let Some(key) = parse_sa_payload(payload, true) {
                    store.upsert(key);
                } else if let Some((family, dst, spi, _src, proto)) = parse_info_identity(payload) {
                    // A well-formed but ineligible ESP record (wrong
                    // direction or expired) revokes a prior observation.
                    // AH and other protocols are unrelated to this ESP cache.
                    if proto == libc::IPPROTO_ESP as u8 {
                        store.remove_dst_spi(family, ip_to_u128(dst), spi);
                    }
                } else {
                    return true;
                }
            }
            XFRM_MSG_DELSA => {
                if let Some((family, dst, spi, proto)) = parse_id_identity(payload) {
                    if proto == libc::IPPROTO_ESP as u8 {
                        store.remove_dst_spi(family, dst, spi);
                    }
                } else {
                    return true;
                }
            }
            XFRM_MSG_EXPIRE => {
                if payload.len() < XFRM_INFO_LEN + 1 {
                    return true;
                }
                if let Some((family, dst, spi, _src, proto)) = parse_info_identity(payload) {
                    if proto == libc::IPPROTO_ESP as u8 {
                        // Both soft and hard expiry revoke the cache proof
                        // immediately; a later complete dump may re-add a
                        // replacement SA after rekey.
                        let removed = store.remove_dst_spi(family, ip_to_u128(dst), spi);
                        if removed != 0 {
                            store
                                .counters
                                .sa_expiry_removes
                                .fetch_add(removed, Ordering::Relaxed);
                        }
                    }
                } else {
                    return true;
                }
            }
            XFRM_MSG_FLUSHSA => return true,
            _ => {}
        }
        offset += (len + 3) & !3;
    }
    offset != bytes.len()
}

fn parse_sa_payload(payload: &[u8], require_direction: bool) -> Option<IpsecSaKey> {
    parse_sa_payload_with_epoch(payload, require_direction).map(|(key, _)| key)
}

fn parse_sa_payload_with_epoch(
    payload: &[u8],
    require_direction: bool,
) -> Option<(IpsecSaKey, u64)> {
    let (family, dst, spi, src, proto) = parse_info_identity(payload)?;
    if family != libc::AF_INET as u8 && family != libc::AF_INET6 as u8 {
        return None;
    }
    if proto != libc::IPPROTO_ESP as u8 {
        return None;
    }
    let hard_bytes = read_u64_ne(payload, 96 + 8)?;
    let hard_packets = read_u64_ne(payload, 96 + 24)?;
    let hard_add = read_u64_ne(payload, 96 + 40)?;
    let hard_use = read_u64_ne(payload, 96 + 56)?;
    let cur_bytes = read_u64_ne(payload, 160)?;
    let cur_packets = read_u64_ne(payload, 168)?;
    let add_time = read_u64_ne(payload, 176)?;
    let use_time = read_u64_ne(payload, 184)?;
    if (hard_bytes != u64::MAX && cur_bytes >= hard_bytes)
        || (hard_packets != u64::MAX && cur_packets >= hard_packets)
        || (hard_add != 0
            && hard_add != u64::MAX
            && add_time
                .checked_add(hard_add)
                .is_none_or(|deadline| now_secs() >= deadline))
        || (hard_use != 0
            && hard_use != u64::MAX
            && use_time != 0
            && use_time
                .checked_add(hard_use)
                .is_none_or(|deadline| now_secs() >= deadline))
    {
        return None;
    }
    if require_direction && parse_sa_direction(&payload[XFRM_INFO_LEN..]) != Some(XFRM_SA_DIR_IN) {
        return None;
    }
    Some((ipsec_sa_key(dst, spi, src)?, add_time))
}

fn parse_info_identity(payload: &[u8]) -> Option<(u8, IpAddr, u32, IpAddr, u8)> {
    if payload.len() < XFRM_INFO_LEN {
        return None;
    }
    let family = u16::from_ne_bytes(payload[212..214].try_into().ok()?) as u8;
    let spi = u32::from_be_bytes(payload[72..76].try_into().ok()?);
    let proto = payload[76];
    let dst = parse_address(family, payload.get(56..72)?)?;
    let src = parse_address(family, payload.get(80..96)?)?;
    Some((family, dst, spi, src, proto))
}

fn parse_id_identity(payload: &[u8]) -> Option<(u8, u128, u32, u8)> {
    if payload.len() < XFRM_MSG_ID_LEN {
        return None;
    }
    let family = u16::from_ne_bytes(payload[20..22].try_into().ok()?) as u8;
    let proto = payload[22];
    let spi = u32::from_be_bytes(payload[16..20].try_into().ok()?);
    let dst = parse_address(family, payload.get(0..16)?)?;
    Some((family, ip_to_u128(dst), spi, proto))
}

fn parse_address(family: u8, bytes: &[u8]) -> Option<IpAddr> {
    match family as i32 {
        libc::AF_INET if bytes.len() >= 4 => {
            let octets: [u8; 4] = bytes[0..4].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        libc::AF_INET6 if bytes.len() >= 16 => {
            let octets: [u8; 16] = bytes[0..16].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn parse_sa_direction(attrs: &[u8]) -> Option<u8> {
    let mut offset = 0usize;
    while offset + 4 <= attrs.len() {
        let len = u16::from_ne_bytes(attrs[offset..offset + 2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(attrs[offset + 2..offset + 4].try_into().ok()?) & 0x3fff;
        if len < 4 || offset + len > attrs.len() {
            return None;
        }
        if kind == XFRMA_SA_DIR {
            // XFRMA_SA_DIR carries one u8 payload (NLA length 5). A
            // zero-payload attribute must not read the next NLA/padding byte
            // as its direction.
            if len != 5 {
                return None;
            }
            return attrs.get(offset + 4).copied();
        }
        offset += (len + 3) & !3;
    }
    None
}

fn read_u64_ne(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn put_u16(dst: &mut [u8], value: u16) {
    dst.copy_from_slice(&value.to_ne_bytes());
}

fn put_u32(dst: &mut [u8], value: u32) {
    dst.copy_from_slice(&value.to_ne_bytes());
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn multi_source_collision_counter_tracks_wildcard_group() {
        let store = IpsecSaStore::new();
        let dst = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let first = ipsec_sa_key(dst, 0x1122_3344, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
            .expect("same-family SA fixture");
        let second = ipsec_sa_key(dst, 0x1122_3344, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
            .expect("same-family SA fixture");
        let third = ipsec_sa_key(dst, 0x1122_3344, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)))
            .expect("same-family SA fixture");
        let mut entries = FastMap::default();
        entries.insert(
            first,
            IpsecSaEpoch {
                generation: 0,
                incarnation: 0,
            },
        );
        entries.insert(
            second,
            IpsecSaEpoch {
                generation: 0,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        assert_eq!(store.counters.snapshot().sa_multi_source_collisions, 1);
        store.upsert(third);
        assert_eq!(store.counters.snapshot().sa_multi_source_collisions, 2);
    }
    #[test]
    fn fenced_publication_orders_snapshot_before_epoch() {
        let store = Arc::new(IpsecSaStore::new());
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        let batch = store.load_snapshot();

        let snapshot_published = Arc::new(Barrier::new(2));
        let release_epoch = Arc::new(Barrier::new(2));
        let worker_store = Arc::clone(&store);
        let worker_snapshot_published = Arc::clone(&snapshot_published);
        let worker_release_epoch = Arc::clone(&release_epoch);
        let worker = thread::spawn(move || {
            let current = worker_store.snapshot.load_full();
            let mut next_entries = current.entries.clone();
            next_entries.remove(&key(1));
            worker_store.publish_snapshot_with_removal_fence_paused(
                IpsecSaSnapshot {
                    entries: next_entries,
                    generation: current.generation,
                    stale: current.stale,
                    stale_epoch: current.stale_epoch,
                    removal_epoch: 0,
                },
                &worker_snapshot_published,
                &worker_release_epoch,
            );
        });

        // The deleting snapshot is already published, but the release epoch
        // is deliberately withheld. Capture the staged-ahead-of-released
        // observations now and assert after release/join: the old batch may
        // still linearize before revocation, but it must never see a new
        // epoch with the old map — and an order reversal must fail the
        // staged asserts below instead of stranding the worker on the
        // barrier.
        snapshot_published.wait();
        let staged = store.snapshot.load();
        let staged_has_key = staged.entries.contains_key(&key(1));
        let staged_removal_epoch = store.removal_epoch.load(Ordering::Relaxed);
        let pre_release = store.lookup_loaded(&batch, key(1));
        release_epoch.wait();
        worker.join().expect("fenced publication worker");
        assert!(!staged_has_key);
        assert_eq!(staged_removal_epoch, batch.removal_epoch);
        assert_eq!(pre_release, IpsecSaLookup::Hit);
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Stale);
    }

    fn key(n: u32) -> IpsecSaKey {
        let page = (n / 256) as u8;
        let host = n as u8;
        ipsec_sa_key(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2 + page, host)),
            n,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100 + page, host)),
        )
        .expect("same-family SA fixture")
    }
    #[test]
    fn mixed_family_key_is_rejected() {
        assert_eq!(
            ipsec_sa_key(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                7,
                IpAddr::V6("2001:db8::7".parse().expect("v6 fixture")),
            ),
            None
        );
    }

    #[test]
    fn empty_store_denies_until_first_full_dump() {
        let store = IpsecSaStore::new();
        assert_eq!(store.lookup(key(1)), IpsecSaLookup::Stale);
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        assert_eq!(store.lookup(key(1)), IpsecSaLookup::Hit);
        assert_eq!(store.lookup(key(2)), IpsecSaLookup::Miss);
    }

    #[test]
    fn stale_denies_existing_entry_immediately() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        store.mark_stale();
        assert_eq!(store.lookup(key(1)), IpsecSaLookup::Stale);
    }

    #[test]
    fn loaded_batch_snapshot_fences_after_store_update() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        let batch = store.load_snapshot();
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Hit);
        assert!(store.remove(key(1)));
        // DELSA is a revocation event: an in-flight batch must deny
        // immediately, while a refreshed snapshot reports a plain miss.
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Stale);
        let refreshed = store.load_snapshot();
        assert_eq!(store.lookup_loaded(&refreshed, key(1)), IpsecSaLookup::Miss);
    }
    #[test]
    fn loaded_batch_keeps_rekey_overlap_key_but_fences_removed_key() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        entries.insert(
            key(2),
            IpsecSaEpoch {
                generation: 2,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        let batch = store.load_snapshot();

        assert!(store.remove(key(1)));
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Stale);
        // The replacement/new SA remains valid through the same in-flight
        // batch, preserving the rekey-overlap zero-miss requirement.
        assert_eq!(store.lookup_loaded(&batch, key(2)), IpsecSaLookup::Hit);
    }

    #[test]
    fn loaded_batch_keeps_verdict_across_additive_upsert_but_fences_redump_delete() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        let batch = store.load_snapshot();
        store.upsert(key(2));
        // Additive NEWSA does not revoke an in-flight positive batch.
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Hit);

        let mut redump = FastMap::default();
        redump.insert(
            key(3),
            IpsecSaEpoch {
                generation: 2,
                incarnation: 0,
            },
        );
        store.publish_full_dump(redump);
        // The redump deleted key(1), so the old batch is fenced immediately.
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Stale);
        let refreshed = store.load_snapshot();
        assert_eq!(store.lookup_loaded(&refreshed, key(1)), IpsecSaLookup::Miss);
    }
    #[test]
    fn loaded_batch_survives_redump_retaining_sibling_but_fences_deleted_key() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        entries.insert(
            key(2),
            IpsecSaEpoch {
                generation: 2,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        let batch = store.load_snapshot();

        let mut redump = FastMap::default();
        redump.insert(
            key(2),
            IpsecSaEpoch {
                generation: 3,
                incarnation: 0,
            },
        );
        store.publish_full_dump(redump);

        // Retention preserves key(2)'s presence episode across the redump:
        // the old batch stays Hit for the survivor and fences only the
        // deleted key.
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Stale);
        assert_eq!(store.lookup_loaded(&batch, key(2)), IpsecSaLookup::Hit);
    }
    #[test]
    fn loaded_batch_fences_cap_evicted_key_but_keeps_survivor() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        for n in 0..IPSEC_SA_SNAPSHOT_CAP {
            entries.insert(
                key(n as u32),
                IpsecSaEpoch {
                    generation: n as u64,
                    incarnation: 0,
                },
            );
        }
        store.publish_full_dump(entries);
        let batch = store.load_snapshot();

        // The store is exactly at cap: one more insert evicts key(0), the
        // oldest by dump order. Eviction is a removal and must fence.
        store.upsert(key(IPSEC_SA_SNAPSHOT_CAP as u32));

        assert_eq!(store.lookup_loaded(&batch, key(0)), IpsecSaLookup::Stale);
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Hit);
        let refreshed = store.load_snapshot();
        assert_eq!(store.lookup_loaded(&refreshed, key(0)), IpsecSaLookup::Miss);
    }

    #[test]
    fn loaded_batch_snapshot_fences_after_mark_stale() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        let batch = store.load_snapshot();
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Hit);
        store.mark_stale();
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Stale);
        assert_eq!(store.lookup(key(1)), IpsecSaLookup::Stale);
    }
    #[test]
    fn loaded_batch_stays_fenced_across_stale_recovery_with_retained_key() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        let batch = store.load_snapshot();

        store.mark_stale();
        let mut recovery = FastMap::default();
        recovery.insert(
            key(1),
            IpsecSaEpoch {
                generation: 2,
                incarnation: 0,
            },
        );
        store.publish_full_dump(recovery);

        // Hard stale transitions fence the whole old batch, even when the
        // recovered dump contains the same SA key.
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Stale);
        assert_eq!(store.lookup(key(1)), IpsecSaLookup::Hit);
    }

    #[test]
    fn loaded_batch_stays_fenced_across_remove_and_readd() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        let batch = store.load_snapshot();

        assert!(store.remove(key(1)));
        store.upsert(key(1));

        // Presence-episode reconciliation fences the old key even after the
        // current map re-adds it; a newly loaded batch can use the replacement.
        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Stale);
        assert_eq!(store.lookup(key(1)), IpsecSaLookup::Hit);
    }
    #[test]
    fn loaded_batch_stays_fenced_across_mass_removal_readd() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        let batch = store.load_snapshot();

        assert!(store.remove(key(1)));
        // Churn past any bounded deletion history, then re-add the key. The
        // old batch must still be fenced: its presence episode ended.
        for n in 2..=(IPSEC_SA_SNAPSHOT_CAP as u32 + 1002) {
            let churn = key(n);
            store.upsert(churn);
            assert!(store.remove(churn));
        }
        store.upsert(key(1));

        assert_eq!(store.lookup_loaded(&batch, key(1)), IpsecSaLookup::Stale);
        assert_eq!(store.lookup(key(1)), IpsecSaLookup::Hit);
    }
    #[test]
    fn stopping_monitor_fences_existing_snapshot() {
        let mut monitor = IpsecSaMonitor::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        monitor.store.publish_full_dump(entries);
        assert_eq!(monitor.store.lookup(key(1)), IpsecSaLookup::Hit);
        monitor.stop_and_join();
        assert_eq!(monitor.store.lookup(key(1)), IpsecSaLookup::Stale);
        // The independent teardown revocation remains authoritative even if
        // a racing dump publishes a fresh snapshot after stop begins.
        monitor.store.publish_empty_dump_for_test();
        assert_eq!(monitor.store.lookup(key(1)), IpsecSaLookup::Stale);
    }
    #[test]
    fn monitor_stop_reset_dump_restores_ready() {
        let mut monitor = IpsecSaMonitor::new();
        let mut entries = FastMap::default();
        entries.insert(
            key(1),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        monitor.store.publish_full_dump(entries);
        assert_eq!(monitor.store.lookup(key(1)), IpsecSaLookup::Hit);

        monitor.stop_and_join();
        assert_eq!(monitor.store.lookup(key(1)), IpsecSaLookup::Stale);
        assert!(!monitor.store.wait_ready(Duration::from_millis(50)));

        monitor.store.reset_for_monitor_start();
        assert_eq!(monitor.store.lookup(key(1)), IpsecSaLookup::Stale);

        let mut redump = FastMap::default();
        redump.insert(
            key(1),
            IpsecSaEpoch {
                generation: 2,
                incarnation: 0,
            },
        );
        monitor.store.publish_full_dump(redump);
        assert!(monitor.store.wait_ready(Duration::from_secs(5)));
        assert_eq!(monitor.store.lookup(key(1)), IpsecSaLookup::Hit);
    }

    #[test]
    fn full_dump_and_incremental_upsert_share_cap_order_domain() {
        let store = IpsecSaStore::new();
        let mut entries = FastMap::default();
        for n in 0..IPSEC_SA_SNAPSHOT_CAP {
            entries.insert(
                key(n as u32),
                IpsecSaEpoch {
                    // Deliberately make the final key oldest so this test
                    // proves age ordering rather than key ordering.
                    generation: if n == IPSEC_SA_SNAPSHOT_CAP - 1 {
                        0
                    } else {
                        n as u64 + 1
                    },
                    incarnation: 0,
                },
            );
        }
        store.publish_full_dump(entries);
        let newest = key((IPSEC_SA_SNAPSHOT_CAP + 1) as u32);
        store.upsert(newest);
        assert_eq!(store.entries_len(), IPSEC_SA_SNAPSHOT_CAP);
        assert_eq!(
            store.lookup(key((IPSEC_SA_SNAPSHOT_CAP - 1) as u32)),
            IpsecSaLookup::Miss
        );
        assert_eq!(store.lookup(key(0)), IpsecSaLookup::Hit);
        assert_eq!(store.lookup(newest), IpsecSaLookup::Hit);
    }

    #[test]
    fn esp_parser_distinguishes_keepalive_and_marker() {
        let mut frame = vec![0u8; 8];
        frame[4..6].copy_from_slice(&9u16.to_be_bytes());
        frame.extend_from_slice(&[0xff, 0, 0]);
        assert_eq!(esp_in_udp_spi(&frame, 0, 4500, frame.len()), None);
        assert_eq!(
            esp_in_udp_miss_reason(&frame, 0, 4500, frame.len()),
            IpsecSaMissReason::Keepalive
        );
        frame.truncate(8);
        frame[4..6].copy_from_slice(&12u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            esp_in_udp_miss_reason(&frame, 0, 4500, frame.len()),
            IpsecSaMissReason::NoSa
        );
    }
    #[test]
    fn esp_parser_bounds_spi_by_declared_ipv4_ipv6_end() {
        for l4_offset in [34usize, 54usize] {
            let mut frame = vec![0u8; l4_offset + 8 + 4];
            frame[l4_offset + 4..l4_offset + 6].copy_from_slice(&12u16.to_be_bytes());
            frame[l4_offset + 8..l4_offset + 12].copy_from_slice(&0x1122_3344u32.to_be_bytes());
            let declared_end = l4_offset + 8;
            assert_eq!(
                esp_in_udp_spi(&frame, l4_offset, 4500, declared_end),
                None,
                "SPI beyond declared IPv{} end must not be read",
                if l4_offset == 34 { 4 } else { 6 }
            );
            assert_eq!(
                esp_in_udp_miss_reason(&frame, l4_offset, 4500, declared_end),
                IpsecSaMissReason::Truncated
            );
            assert_eq!(
                esp_in_udp_spi(&frame, l4_offset, 4500, frame.len()),
                Some(0x1122_3344)
            );
        }
    }

    #[test]
    fn esp_parser_rejects_tiny_first_fragment_spi_slack() {
        let l4_offset = 34usize;
        let mut frame = vec![0u8; l4_offset + 8 + 4];
        frame[l4_offset + 4..l4_offset + 6].copy_from_slice(&10u16.to_be_bytes());
        frame[l4_offset + 8..l4_offset + 12].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        let tiny_first_fragment_end = l4_offset + 8 + 2;
        assert_eq!(
            esp_in_udp_spi(&frame, l4_offset, 4500, tiny_first_fragment_end),
            None
        );
        assert_eq!(
            esp_in_udp_miss_reason(&frame, l4_offset, 4500, tiny_first_fragment_end),
            IpsecSaMissReason::Truncated
        );
    }
    #[test]
    fn non_4500_miss_is_counted_truncated() {
        // Pins the deliberately coarse label: non-NAT-T ports cannot be
        // ESP-in-UDP and share the truncated counter.
        let frame = vec![0u8; 64];
        assert_eq!(
            esp_in_udp_miss_reason(&frame, 0, 500, frame.len()),
            IpsecSaMissReason::Truncated
        );
    }

    #[test]
    fn parses_usersa_info_offsets_and_inbound_direction() {
        let mut payload = vec![0u8; XFRM_INFO_LEN + 8];
        payload[56..60].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        payload[72..76].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        payload[76] = libc::IPPROTO_ESP as u8;
        payload[80..84].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 20).octets());
        payload[212..214].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        for offset in [96 + 8, 96 + 24] {
            payload[offset..offset + 8].copy_from_slice(&u64::MAX.to_ne_bytes());
        }
        payload[224..226].copy_from_slice(&5u16.to_ne_bytes());
        payload[226..228].copy_from_slice(&XFRMA_SA_DIR.to_ne_bytes());
        payload[228] = XFRM_SA_DIR_IN;
        // A zero hard-add lifetime is disabled by XFRM, not immediately
        // expired. The parser must retain this ordinary unlimited SA.
        payload[136..144].fill(0);
        assert!(parse_sa_payload(&payload, true).is_some());
        // Hard-use lifetime is inactive before the SA is first used.
        payload[152..160].copy_from_slice(&10u64.to_ne_bytes());
        payload[184..192].fill(0);
        assert!(parse_sa_payload(&payload, true).is_some());
        // An already-started use lifetime with an elapsed deadline is
        // ineligible even when byte/packet/add lifetimes remain unlimited.
        payload[184..192].copy_from_slice(&1u64.to_ne_bytes());
        assert!(parse_sa_payload(&payload, true).is_none());
        payload[184..192].fill(0);
        payload[136..144].copy_from_slice(&u64::MAX.to_ne_bytes());
        // A present direction attribute is required by the gate.
        payload[224..232].fill(0);
        assert!(parse_sa_payload(&payload, true).is_none());
        payload[224..226].copy_from_slice(&5u16.to_ne_bytes());
        payload[226..228].copy_from_slice(&XFRMA_SA_DIR.to_ne_bytes());
        payload[228] = 2;
        assert!(parse_sa_payload(&payload, true).is_none());
        payload[228] = XFRM_SA_DIR_IN;
        // A zero-payload DIR NLA must not consume the next attribute or
        // padding byte as an inbound direction.
        payload[224..226].copy_from_slice(&4u16.to_ne_bytes());
        assert!(parse_sa_payload(&payload, true).is_none());
        payload[224..226].copy_from_slice(&5u16.to_ne_bytes());
        let parsed = parse_sa_payload(&payload, true).expect("eligible inbound SA");
        assert_eq!(
            parsed,
            ipsec_sa_key(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                0x1122_3344,
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            )
            .expect("same-family SA fixture"),
        );
    }

    #[test]
    fn usersa_id_delete_layout_is_not_treated_as_usersa_info() {
        let mut payload = vec![0u8; XFRM_MSG_ID_LEN];
        payload[0..4].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        payload[16..20].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        payload[20..22].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        payload[22] = libc::IPPROTO_ESP as u8;
        assert_eq!(
            parse_id_identity(&payload),
            Some((
                libc::AF_INET as u8,
                ip_to_u128(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                0x1122_3344,
                libc::IPPROTO_ESP as u8,
            ))
        );
        assert!(parse_info_identity(&payload).is_none());
    }

    fn one_netlink_message(msg_type: u16, payload: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDR_LEN + payload.len();
        let aligned = (len + 3) & !3;
        let mut message = vec![0u8; aligned];
        message[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        message[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        message[NLMSG_HDR_LEN..NLMSG_HDR_LEN + payload.len()].copy_from_slice(payload);
        message
    }

    fn xfrm_id_payload(dst: Ipv4Addr, spi: u32, proto: u8) -> Vec<u8> {
        let mut payload = vec![0u8; XFRM_MSG_ID_LEN];
        payload[0..4].copy_from_slice(&dst.octets());
        payload[16..20].copy_from_slice(&spi.to_be_bytes());
        payload[20..22].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        payload[22] = proto;
        payload
    }

    fn xfrm_info_payload(dst: Ipv4Addr, spi: u32, proto: u8) -> Vec<u8> {
        let mut payload = vec![0u8; XFRM_INFO_LEN + 1];
        payload[56..60].copy_from_slice(&dst.octets());
        payload[72..76].copy_from_slice(&spi.to_be_bytes());
        payload[76] = proto;
        payload[80..84].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 1).octets());
        payload[212..214].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        payload
    }

    fn xfrm_news_payload(dst: Ipv4Addr, spi: u32) -> Vec<u8> {
        let mut payload = xfrm_info_payload(dst, spi, libc::IPPROTO_ESP as u8);
        payload.resize(XFRM_INFO_LEN + 8, 0);
        payload[104..112].copy_from_slice(&u64::MAX.to_ne_bytes());
        payload[120..128].copy_from_slice(&u64::MAX.to_ne_bytes());
        payload[224..226].copy_from_slice(&5u16.to_ne_bytes());
        payload[226..228].copy_from_slice(&XFRMA_SA_DIR.to_ne_bytes());
        payload[228] = XFRM_SA_DIR_IN;
        payload
    }

    #[test]
    fn socketpair_monitor_receive_publishes_then_stales_10516() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixDatagram;

        let store = IpsecSaStore::new();
        store.publish_empty_dump_for_test();
        let (rx, tx) = UnixDatagram::pair().expect("socketpair");
        let stop = AtomicBool::new(false);
        let dst = Ipv4Addr::new(192, 0, 2, 1);
        let src = Ipv4Addr::new(198, 51, 100, 1);
        let key = ipsec_sa_key(IpAddr::V4(dst), 0x1122_3344, IpAddr::V4(src))
            .expect("same-family SA fixture");

        tx.send(&one_netlink_message(
            XFRM_MSG_NEWSA,
            &xfrm_news_payload(dst, 0x1122_3344),
        ))
        .expect("send NEWSA");
        assert!(matches!(
            recv_xfrm_events(rx.as_raw_fd(), &store, &stop),
            XfrmEventResult::Idle
        ));
        assert_eq!(store.lookup(key), IpsecSaLookup::Hit);

        tx.send(&one_netlink_message(XFRM_MSG_FLUSHSA, &[]))
            .expect("send FLUSHSA");
        assert!(matches!(
            recv_xfrm_events(rx.as_raw_fd(), &store, &stop),
            XfrmEventResult::NeedRedump
        ));
        assert_eq!(store.lookup(key), IpsecSaLookup::Stale);
    }

    #[test]
    fn ah_events_do_not_revoke_esp_snapshot_or_count_expiry() {
        let store = IpsecSaStore::new();
        let esp = key(1);
        let mut entries = FastMap::default();
        entries.insert(
            esp,
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);

        let ah_delete = one_netlink_message(
            XFRM_MSG_DELSA,
            &xfrm_id_payload(Ipv4Addr::new(192, 0, 2, 1), 1, libc::IPPROTO_AH as u8),
        );
        assert!(!apply_xfrm_messages(&store, &ah_delete));
        assert_eq!(store.lookup(esp), IpsecSaLookup::Hit);

        let ah_expire = one_netlink_message(
            XFRM_MSG_EXPIRE,
            &xfrm_info_payload(Ipv4Addr::new(192, 0, 2, 1), 1, libc::IPPROTO_AH as u8),
        );
        assert!(!apply_xfrm_messages(&store, &ah_expire));
        assert_eq!(store.lookup(esp), IpsecSaLookup::Hit);
        assert_eq!(store.counters.snapshot().sa_expiry_removes, 0);

        let esp_expire = one_netlink_message(
            XFRM_MSG_EXPIRE,
            &xfrm_info_payload(Ipv4Addr::new(192, 0, 2, 1), 1, libc::IPPROTO_ESP as u8),
        );
        assert!(!apply_xfrm_messages(&store, &esp_expire));
        assert_eq!(store.lookup(esp), IpsecSaLookup::Miss);
        assert_eq!(store.counters.snapshot().sa_expiry_removes, 1);
    }

    #[test]
    fn incremental_upsert_does_not_clear_stale() {
        let store = IpsecSaStore::new();
        store.mark_stale();
        store.upsert(key(7));
        assert_eq!(store.lookup(key(7)), IpsecSaLookup::Stale);
        let mut entries = FastMap::default();
        entries.insert(
            key(7),
            IpsecSaEpoch {
                generation: 1,
                incarnation: 0,
            },
        );
        store.publish_full_dump(entries);
        assert_eq!(store.lookup(key(7)), IpsecSaLookup::Hit);
    }
}
