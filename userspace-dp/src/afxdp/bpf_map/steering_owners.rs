//! #9560: owners of the rows in the XDP steering map (`userspace_sessions`).
//!
//! The steering key is a bare 40-byte tuple (`UserspaceSessionMapKey`). It carries
//! neither `routing_domain` nor the tunnel `discriminator`, so two sessions that the
//! authoritative `SessionKey` keeps apart can occupy ONE row (#9517). Publishing is
//! an identity-blind `BPF_ANY` overwrite. The OVERWRITE harm was closed by #9517's
//! REDIRECT demotion, but a plain delete let either session's teardown remove the row
//! the other still needed. With an `lo0` input filter configured, the survivor's next
//! packet then missed in the shim, went to the kernel and skipped the filter.
//!
//! This registry records which entries own each row, so a row is deleted from the BPF
//! map only when its LAST owner goes. The owner is the ENTRY key handed to the
//! entry-level wrapper, never the derived row key: `reverse_canonical_key` zeroes
//! `routing_domain` (#7160), so two domains' reverse-canonical rows are identical
//! `SessionKey`s and an owner set keyed by row key would merge them.
//!
//! One registry lives exactly as long as one `BpfMaps`. Worker-local sessions die at a
//! bringup, and `replay_preserved_sessions` re-registers the surviving synced sessions
//! before workers spawn. A row the registry never saw is `Unregistered`, and the caller
//! keeps today's delete for it.

use std::hash::Hasher;
use std::sync::{LazyLock, Mutex};

use rustc_hash::FxHasher;
use smallvec::SmallVec;

use crate::afxdp::types::FastMap;
use crate::session::SessionKey;

/// The steering-map row a key occupies: the 40 bytes the shim looks up.
pub(crate) type SteeringRow = [u8; 40];

const NUM_SHARDS: usize = 64;
const SHARD_BITS: u32 = NUM_SHARDS.trailing_zeros();
const _: () = assert!(
    NUM_SHARDS.is_power_of_two(),
    "shard selection takes the top bits of the hash"
);

/// Owners of one row. One owner is the common case, so it is stored inline and a row
/// costs no heap allocation.
type Owners = SmallVec<[SessionKey; 1]>;

/// One mutex-guarded shard, padded so adjacent shards do not share a cache line
/// (the `sharded_neighbor.rs` shape).
#[repr(align(64))]
struct PaddedShard(Mutex<FastMap<SteeringRow, Owners>>);

/// Result of removing one owner from a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnerRemoval {
    /// Another entry still owns the row: the BPF row must stay.
    Remaining,
    /// That was the last owner: the BPF row may be deleted.
    Emptied,
    /// The registry never saw this row, for example one written by an earlier helper
    /// incarnation into the pinned map. The caller keeps today's delete.
    Unregistered,
}

pub(crate) struct SteeringRowOwners {
    shards: [PaddedShard; NUM_SHARDS],
}

impl Default for SteeringRowOwners {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| PaddedShard(Mutex::new(FastMap::default()))),
        }
    }
}

/// Per-process seed for shard selection. As with the neighbour map (#7752), a fixed
/// public hash would let chosen tuples be precomputed into ONE shard. There is no
/// per-shard cap here, so the cost would be lock contention on connection setup, not
/// refusal; the seed removes the offline precomputation all the same.
static SHARD_SEED: LazyLock<u64> = LazyLock::new(|| {
    let mut b = [0u8; 8];
    if getrandom::getrandom(&mut b).is_ok() {
        return u64::from_ne_bytes(b);
    }
    eprintln!(
        "xpf-dp: getrandom failed seeding the steering-row owner shard index; falling \
         back to a process-varying seed (#9560)"
    );
    let mut h = FxHasher::default();
    h.write_u32(std::process::id());
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    h.finish()
});

fn shard_idx(row: &SteeringRow) -> usize {
    let mut hasher = FxHasher::default();
    hasher.write_u64(*SHARD_SEED);
    hasher.write(row);
    let mixed = hasher.finish().wrapping_mul(0x9E3779B97F4A7C15);
    (mixed >> (64 - SHARD_BITS)) as usize
}

impl SteeringRowOwners {
    fn shard(&self, row: &SteeringRow) -> std::sync::MutexGuard<'_, FastMap<SteeringRow, Owners>> {
        // Poison-tolerant (engineering-style): a panic under one shard's lock must not
        // wedge every later steering write that lands in the same shard.
        self.shards[shard_idx(row)]
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Record `owner` as an owner of `row`, then run `write` (the BPF update) while the
    /// row's shard is still locked. Idempotent in the owner.
    ///
    /// Holding the lock across the write is what makes the registry an exclusion rather
    /// than a hint. A sibling's teardown decides and issues its BPF delete under the same
    /// lock (`remove_then`), so it cannot find the row ownerless, release, and then delete
    /// a row this publish wrote in between. The cost is one map syscall inside a lock that
    /// only rows hashing to the same one of 64 shards contend on.
    pub(crate) fn add_then<R>(
        &self,
        row: &SteeringRow,
        owner: &SessionKey,
        write: impl FnOnce() -> R,
    ) -> R {
        let mut shard = self.shard(row);
        let owners = shard.entry(*row).or_default();
        if !owners.iter().any(|existing| existing == owner) {
            owners.push(owner.clone());
        }
        write()
    }

    /// Remove `owner` from `row` and, unless other owners remain, run `delete` (the BPF
    /// delete) before the shard lock is released; `add_then` says why it must be inside
    /// the lock. A caller that is not an owner of a row others still own gets
    /// `Remaining`: the redirect-delete path also removes derived rows a session never
    /// published, and those must not take a sibling's row with them. A row the registry
    /// never saw is `Unregistered`, and is deleted as it was before #9560.
    pub(crate) fn remove_then(
        &self,
        row: &SteeringRow,
        owner: &SessionKey,
        delete: impl FnOnce(),
    ) -> OwnerRemoval {
        let mut shard = self.shard(row);
        let outcome = match shard.get_mut(row) {
            None => OwnerRemoval::Unregistered,
            Some(owners) => {
                if let Some(position) = owners.iter().position(|existing| existing == owner) {
                    owners.swap_remove(position);
                }
                if owners.is_empty() {
                    shard.remove(row);
                    OwnerRemoval::Emptied
                } else {
                    OwnerRemoval::Remaining
                }
            }
        };
        if outcome != OwnerRemoval::Remaining {
            delete();
        }
        outcome
    }

    #[cfg(test)]
    pub(crate) fn add(&self, row: &SteeringRow, owner: &SessionKey) {
        self.add_then(row, owner, || ())
    }

    #[cfg(test)]
    pub(crate) fn remove(&self, row: &SteeringRow, owner: &SessionKey) -> OwnerRemoval {
        self.remove_then(row, owner, || ())
    }

    /// Whether `row`'s shard is locked at this instant. Meaningful only inside an
    /// `add_then`/`remove_then` closure, where it must be true.
    #[cfg(test)]
    pub(crate) fn shard_is_locked(&self, row: &SteeringRow) -> bool {
        self.shards[shard_idx(row)].0.try_lock().is_err()
    }

    #[cfg(test)]
    pub(crate) fn owner_count(&self, row: &SteeringRow) -> usize {
        self.shard(row).get(row).map_or(0, |owners| owners.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(domain: u32, src_port: u16) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 61, 1)),
            src_port,
            dst_port: 22,
            discriminator: Default::default(),
            routing_domain: domain,
        }
    }

    fn row(byte: u8) -> SteeringRow {
        [byte; 40]
    }

    #[test]
    fn a_single_owner_empties_its_row_9560() {
        let owners = SteeringRowOwners::default();
        owners.add(&row(1), &key(0, 1000));
        assert_eq!(owners.remove(&row(1), &key(0, 1000)), OwnerRemoval::Emptied);
        assert_eq!(owners.owner_count(&row(1)), 0);
    }

    #[test]
    fn a_shared_row_survives_until_its_last_owner_goes_9560() {
        let owners = SteeringRowOwners::default();
        owners.add(&row(2), &key(1, 1000));
        owners.add(&row(2), &key(2, 1000));
        assert_eq!(
            owners.remove(&row(2), &key(1, 1000)),
            OwnerRemoval::Remaining,
            "the other domain's session still owns the row"
        );
        assert_eq!(owners.remove(&row(2), &key(2, 1000)), OwnerRemoval::Emptied);
    }

    #[test]
    fn a_non_owner_cannot_empty_a_row_others_own_9560() {
        let owners = SteeringRowOwners::default();
        owners.add(&row(3), &key(1, 1000));
        assert_eq!(
            owners.remove(&row(3), &key(9, 1000)),
            OwnerRemoval::Remaining
        );
        assert_eq!(owners.owner_count(&row(3)), 1);
    }

    #[test]
    fn an_unknown_row_is_unregistered_9560() {
        let owners = SteeringRowOwners::default();
        assert_eq!(
            owners.remove(&row(4), &key(0, 1000)),
            OwnerRemoval::Unregistered
        );
    }

    #[test]
    fn adding_the_same_owner_twice_is_idempotent_9560() {
        let owners = SteeringRowOwners::default();
        owners.add(&row(5), &key(0, 1000));
        owners.add(&row(5), &key(0, 1000));
        assert_eq!(owners.owner_count(&row(5)), 1);
        assert_eq!(owners.remove(&row(5), &key(0, 1000)), OwnerRemoval::Emptied);
    }

    #[test]
    fn shard_selection_stays_in_bounds_9560() {
        for byte in 0..=u8::MAX {
            let mut r = [0u8; 40];
            r[39] = byte;
            r[0] = byte.wrapping_mul(31);
            assert!(shard_idx(&r) < NUM_SHARDS);
        }
    }

    #[test]
    fn a_poisoned_shard_is_still_usable_9560() {
        let owners = std::sync::Arc::new(SteeringRowOwners::default());
        let poisoner = owners.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.shard(&row(6));
            panic!("poison the shard that row 6 lives in");
        })
        .join();
        owners.add(&row(6), &key(0, 1000));
        assert_eq!(owners.remove(&row(6), &key(0, 1000)), OwnerRemoval::Emptied);
    }
}
