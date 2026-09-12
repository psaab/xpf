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
//! This registry records who owns each row, so a row is deleted from the BPF map only
//! when its LAST owner goes.
//!
//! **An owner is an entry key held by a worker.**
//! - The ENTRY key, never the derived row key: `reverse_canonical_key` zeroes
//!   `routing_domain` (#7160), so two domains' reverse-canonical rows are identical
//!   `SessionKey`s, and owners keyed by row key would merge them.
//! - Held by a WORKER, because every entry is replicated. Each worker applies the same
//!   session (synced imports and local installs alike, via `replicate_session_upsert`),
//!   publishes its rows, and reaps its replica on its own schedule (#6211). Owned by
//!   the key alone, the first idle replica's reap emptied the row and deleted it under
//!   the worker still forwarding the flow.
//!
//! A row stores each entry key once, with a bitmask of the workers holding it, so N
//! replicas of one entry cost one slot. Worker ids at or above `MAX_NAT_HOLDER_WORKERS`
//! (128) are refused when bindings are planned (#6211 F2). An id outside the mask
//! registers nothing, which is the pre-#9560 behaviour rather than a wrong owner.
//!
//! **Only workers register.** A coordinator write (HA import, bringup replay, RG
//! activation) leaves its row unowned. The coordinator's one delete, the HA synced
//! delete, removes a row only while no worker holds it; the `DeleteSynced` fan-out that
//! follows releases the workers' own holdings. A coordinator owner would otherwise have
//! to be released at every shared-map removal path. The cost is the replica window:
//! from the coordinator's write until a worker applies the queued upsert, the row is
//! unowned and an alias's teardown deletes it, exactly as before #9560.
//!
//! **Holdings move with the entry.** The registry also records, per entry key, the
//! rows each worker holds. An entry publish releases the rows the worker held for that
//! key and the new publish does not name. A same-key replacement (a NAT change, or a
//! kernel-local <-> live row set on refresh, demote or promote) therefore moves
//! ownership without its call site remembering the old decision.
//!
//! **One registry per `Coordinator`, never replaced.** `sync_session` runs without the
//! `ServerState` mutex (#7209), so an HA delete can race a teardown and bringup. With
//! one registry it sees the owners the new workers register. Once `stop_inner` has
//! joined every worker, `retire_workers` drops every claim WITHOUT a BPF delete: those
//! sessions died with their workers, and their rows linger unowned as they did before
//! #9560. A worker that panics is not respawned, so its claims stay until that stop.
//!
//! **Locking.** An operation for a worker takes its key's holdings shard, then one row
//! shard at a time; row-shard code never takes a holdings lock. Each BPF write or
//! delete runs inside its row's shard lock, so a sibling's teardown cannot find a row
//! ownerless and delete it after a publish landed in between. A claim is recorded only
//! after its write succeeded.

use std::hash::{Hash, Hasher};
use std::io;
use std::sync::{LazyLock, Mutex, MutexGuard};

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
const _: () = assert!(
    crate::nat::MAX_NAT_HOLDER_WORKERS == u128::BITS,
    "every plannable worker id must have a bit in the u128 holder mask"
);

/// Who is writing or deleting a steering row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SteeringHolder {
    /// A packet worker. It registers what it publishes.
    Worker(u32),
    /// The coordinator: HA import and delete, bringup replay, RG activation. It
    /// registers its writes too (#9560 round 3), and releases them where the shared
    /// authority they stand for is removed.
    Coordinator,
}

impl SteeringHolder {
    /// The holder as a one-member claim. A worker id the plan should have refused
    /// yields an EMPTY claim (the `NatHolder::bit` shape).
    fn claim(self) -> Claim {
        match self {
            Self::Coordinator => Claim {
                workers: 0,
                coordinator: true,
            },
            Self::Worker(id) => {
                debug_assert!(
                    id < crate::nat::MAX_NAT_HOLDER_WORKERS,
                    "worker_id {id} exceeds MAX_NAT_HOLDER_WORKERS; \
                     replan_bindings_from_candidates must refuse the plan"
                );
                Claim {
                    workers: 1u128.checked_shl(id).unwrap_or(0),
                    coordinator: false,
                }
            }
        }
    }
}

/// The holders of one row, as a set: one bit per plannable worker id, plus the single
/// out-of-worker holder.
///
/// The coordinator cannot live in `workers`. The assert above pins
/// `MAX_NAT_HOLDER_WORKERS == u128::BITS`, so every bit is already a plannable worker
/// id and there is no spare one to take.
///
/// ROUND 2 GAVE THE COORDINATOR NO CLAIM, and that is what this replaces. Its writes
/// (the HA import, the bringup replay, the RG-activation prewarm) left the row
/// unowned, so an aliased session's teardown deleted the row the imported session was
/// still using — the original #9560 defect, surviving inside the handoff window
/// between the coordinator's synchronous write and the first worker claim, and
/// surviving permanently when every queued upsert was dropped. A claim closes the
/// window; what keeps it from outliving its session is that every authoritative
/// removal of the shared entry releases it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Claim {
    workers: u128,
    coordinator: bool,
}

impl Claim {
    fn is_empty(self) -> bool {
        self.workers == 0 && !self.coordinator
    }

    fn insert(&mut self, other: Self) {
        self.workers |= other.workers;
        self.coordinator |= other.coordinator;
    }

    fn remove(&mut self, other: Self) {
        self.workers &= !other.workers;
        if other.coordinator {
            self.coordinator = false;
        }
    }

    fn intersects(self, other: Self) -> bool {
        self.workers & other.workers != 0 || (self.coordinator && other.coordinator)
    }

    fn count(self) -> usize {
        self.workers.count_ones() as usize + usize::from(self.coordinator)
    }
}

/// The owners of one row: each entry key once, with the holders claiming it. One entry
/// is the common case, so it is stored inline and a row costs no heap allocation.
type Owners = SmallVec<[(SessionKey, Claim); 1]>;

/// The rows one entry key's holders hold, each with the holders claiming it.
type Held = SmallVec<[(SteeringRow, Claim); 4]>;

/// Result of removing one holder from a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnerRemoval {
    /// Another owner still holds the row: the BPF row must stay.
    Remaining,
    /// That was the last owner: the BPF row is deleted.
    Emptied,
    /// No owner holds the row: one whose claims were retired, or one an earlier helper
    /// incarnation wrote into the pinned map. It is deleted as it was before #9560.
    /// Before round 3 a coordinator write also landed here, which is the defect that
    /// round closed.
    Unregistered,
}

/// One mutex-guarded shard, padded so adjacent shards do not share a cache line
/// (the `sharded_neighbor.rs` shape).
#[repr(align(64))]
struct PaddedShard<T>(Mutex<T>);

impl<T: Default> Default for PaddedShard<T> {
    fn default() -> Self {
        Self(Mutex::new(T::default()))
    }
}

pub(crate) struct SteeringRowOwners {
    rows: [PaddedShard<FastMap<SteeringRow, Owners>>; NUM_SHARDS],
    holdings: [PaddedShard<FastMap<SessionKey, Held>>; NUM_SHARDS],
}

impl Default for SteeringRowOwners {
    fn default() -> Self {
        Self {
            rows: std::array::from_fn(|_| PaddedShard::default()),
            holdings: std::array::from_fn(|_| PaddedShard::default()),
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

fn seeded_hasher() -> FxHasher {
    let mut hasher = FxHasher::default();
    hasher.write_u64(*SHARD_SEED);
    hasher
}

fn shard_of(hasher: FxHasher) -> usize {
    let mixed = hasher.finish().wrapping_mul(0x9E3779B97F4A7C15);
    (mixed >> (64 - SHARD_BITS)) as usize
}

fn row_shard_idx(row: &SteeringRow) -> usize {
    let mut hasher = seeded_hasher();
    hasher.write(row);
    shard_of(hasher)
}

fn key_shard_idx(key: &SessionKey) -> usize {
    let mut hasher = seeded_hasher();
    key.hash(&mut hasher);
    shard_of(hasher)
}

fn lock<T>(shard: &PaddedShard<T>) -> MutexGuard<'_, T> {
    // Poison-tolerant (engineering-style): a panic under one shard's lock must not
    // wedge every later steering write that lands in the same shard.
    shard.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Clear `claim` from `owner`'s claim on `row` and report what is left of the row.
fn remove_claim(
    rows: &mut FastMap<SteeringRow, Owners>,
    row: &SteeringRow,
    owner: &SessionKey,
    claim: Claim,
) -> OwnerRemoval {
    let Some(owners) = rows.get_mut(row) else {
        return OwnerRemoval::Unregistered;
    };
    if let Some(position) = owners.iter().position(|(key, _)| key == owner) {
        owners[position].1.remove(claim);
        if owners[position].1.is_empty() {
            owners.swap_remove(position);
        }
    }
    if owners.is_empty() {
        rows.remove(row);
        OwnerRemoval::Emptied
    } else {
        OwnerRemoval::Remaining
    }
}

/// The rows `claim`'s holder holds for `owner`.
fn held_rows(
    holdings: &FastMap<SessionKey, Held>,
    owner: &SessionKey,
    claim: Claim,
) -> SmallVec<[SteeringRow; 4]> {
    holdings
        .get(owner)
        .into_iter()
        .flatten()
        .filter(|(_, held)| held.intersects(claim))
        .map(|(row, _)| *row)
        .collect()
}

impl SteeringRowOwners {
    fn row_shard(&self, row: &SteeringRow) -> MutexGuard<'_, FastMap<SteeringRow, Owners>> {
        lock(&self.rows[row_shard_idx(row)])
    }

    fn holdings_shard(&self, key: &SessionKey) -> MutexGuard<'_, FastMap<SessionKey, Held>> {
        lock(&self.holdings[key_shard_idx(key)])
    }

    /// Write ONE row for `owner` as `holder`, releasing nothing else the holder has
    /// for `owner`. `write` (the BPF update) runs under the row's shard lock, and a
    /// worker's claim is recorded only if it succeeds.
    pub(crate) fn publish_row(
        &self,
        row: &SteeringRow,
        owner: &SessionKey,
        holder: SteeringHolder,
        write: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        let claim = holder.claim();
        let mut holdings = self.holdings_shard(owner);
        self.write_and_claim(&mut holdings, row, owner, claim, write)
    }

    /// Publish every row of one entry as `holder`. `write` issues the BPF update for one
    /// row's payload. Each row whose write succeeds is claimed, and once every row is
    /// written the rows the holder held for `owner` that `rows` does not name are
    /// released; `delete` issues the BPF delete of one no other owner holds.
    ///
    /// A failed write stops the publish and releases nothing, so the holder still owns
    /// every row it may have written for the entry.
    pub(crate) fn publish_entry<T>(
        &self,
        owner: &SessionKey,
        holder: SteeringHolder,
        rows: &[(SteeringRow, T)],
        mut write: impl FnMut(&T) -> io::Result<()>,
        mut delete: impl FnMut(&SteeringRow),
    ) -> io::Result<()> {
        let claim = holder.claim();
        let mut holdings = self.holdings_shard(owner);
        for (row, payload) in rows {
            self.write_and_claim(&mut holdings, row, owner, claim, || write(payload))?;
        }
        let stale: SmallVec<[SteeringRow; 4]> = held_rows(&holdings, owner, claim)
            .into_iter()
            .filter(|held| !rows.iter().any(|(row, _)| row == held))
            .collect();
        for row in &stale {
            self.release_locked(Some(&mut holdings), row, owner, claim, &mut delete);
        }
        Ok(())
    }

    /// Give up one entry's rows as `holder`: every row in `rows` (the rows the entry's
    /// current decision derives) and every other row the holder holds for `owner`. Each
    /// row goes from the BPF map (`delete`) unless another owner holds it. A row in
    /// `rows` that no owner holds is deleted too, as it was before #9560.
    ///
    /// An EMPTY `rows` therefore means "give up everything held for this owner", which
    /// is what the recovery paths need: they have no decision left to derive rows from.
    pub(crate) fn release_entry(
        &self,
        owner: &SessionKey,
        holder: SteeringHolder,
        rows: &[SteeringRow],
        mut delete: impl FnMut(&SteeringRow),
    ) {
        let claim = holder.claim();
        let mut released: SmallVec<[SteeringRow; 8]> = SmallVec::new();
        let mut holdings = self.holdings_shard(owner);
        let held = held_rows(&holdings, owner, claim);
        for row in rows.iter().chain(held.iter()) {
            if !released.contains(row) {
                released.push(*row);
                self.release_locked(Some(&mut holdings), row, owner, claim, &mut delete);
            }
        }
    }

    /// Give up ONE row as `holder`; see `release_entry`.
    pub(crate) fn release_row(
        &self,
        row: &SteeringRow,
        owner: &SessionKey,
        holder: SteeringHolder,
        mut delete: impl FnMut(&SteeringRow),
    ) -> OwnerRemoval {
        let claim = holder.claim();
        let mut holdings = self.holdings_shard(owner);
        self.release_locked(Some(&mut holdings), row, owner, claim, &mut delete)
    }

    /// Drop every claim WITHOUT a BPF delete. Call only once every worker is joined
    /// (`Coordinator::stop_inner`): no worker may register after it. Rows are cleared
    /// first, so a racing coordinator delete that finds a row unowned deletes it as
    /// before #9560 rather than skipping it for a claim about to vanish.
    pub(crate) fn retire_workers(&self) {
        for shard in &self.rows {
            std::mem::take(&mut *lock(shard));
        }
        for shard in &self.holdings {
            std::mem::take(&mut *lock(shard));
        }
    }

    /// Retire ONE holder's claims everywhere, deleting each row whose last owner it was.
    ///
    /// A worker the supervisor declared dead never runs its own teardown (#8069), so its
    /// bit would otherwise suppress every later delete of the rows it held: the registry
    /// entry and the fixed-size BPF row would both survive for the life of the process,
    /// and an aliased session's teardown would keep finding an owner that cannot come
    /// back. Returns the number of claims released, for the operator line.
    ///
    /// Walks every holdings shard once. It runs behind the `holders_retired` CAS in
    /// `retire_worker_holders_where`, once per dead worker, never on a packet path.
    pub(crate) fn retire_worker(
        &self,
        worker_id: u32,
        mut delete: impl FnMut(&SteeringRow),
    ) -> usize {
        let claim = SteeringHolder::Worker(worker_id).claim();
        if claim.is_empty() {
            return 0;
        }
        let mut retired = 0;
        for shard in &self.holdings {
            let mut holdings = lock(shard);
            let owners: SmallVec<[SessionKey; 8]> = holdings.keys().cloned().collect();
            for owner in &owners {
                for row in held_rows(&holdings, owner, claim) {
                    self.release_locked(Some(&mut holdings), &row, owner, claim, &mut delete);
                    retired += 1;
                }
            }
        }
        retired
    }

    /// Under the caller's holdings guard for `owner`: run `write` under the row's shard
    /// lock, then record the claim if it succeeded.
    fn write_and_claim(
        &self,
        holdings: &mut FastMap<SessionKey, Held>,
        row: &SteeringRow,
        owner: &SessionKey,
        claim: Claim,
        write: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        {
            let mut rows = self.row_shard(row);
            write()?;
            let owners = rows.entry(*row).or_default();
            match owners.iter_mut().find(|(key, _)| key == owner) {
                Some((_, held)) => held.insert(claim),
                None => owners.push((owner.clone(), claim)),
            }
        }
        match holdings.get_mut(owner) {
            Some(rows_held) => match rows_held.iter_mut().find(|(held_row, _)| held_row == row) {
                Some((_, held)) => held.insert(claim),
                None => rows_held.push((*row, claim)),
            },
            None => {
                let mut held = Held::new();
                held.push((*row, claim));
                holdings.insert(owner.clone(), held);
            }
        }
        Ok(())
    }

    /// Clear `claim` from `owner`'s claim on `row` and, unless another owner remains, run
    /// `delete` before the row's shard lock is released. Then drop the row from that
    /// holder's holding. `holdings` is `None` only where the caller has no guard to
    /// lend; every holder, the coordinator included, records what it holds.
    fn release_locked(
        &self,
        holdings: Option<&mut FastMap<SessionKey, Held>>,
        row: &SteeringRow,
        owner: &SessionKey,
        claim: Claim,
        delete: &mut impl FnMut(&SteeringRow),
    ) -> OwnerRemoval {
        let outcome = {
            let mut rows = self.row_shard(row);
            let outcome = remove_claim(&mut rows, row, owner, claim);
            if outcome != OwnerRemoval::Remaining {
                delete(row);
            }
            outcome
        };
        if let Some(holdings) = holdings
            && let Some(held) = holdings.get_mut(owner)
        {
            if let Some(position) = held.iter().position(|(held_row, _)| held_row == row) {
                held[position].1.remove(claim);
                if held[position].1.is_empty() {
                    held.swap_remove(position);
                }
            }
            if held.is_empty() {
                holdings.remove(owner);
            }
        }
        outcome
    }

    /// Whether `row`'s shard is locked at this instant. Meaningful only inside a write
    /// or delete closure, where it must be true.
    #[cfg(test)]
    pub(crate) fn shard_is_locked(&self, row: &SteeringRow) -> bool {
        self.rows[row_shard_idx(row)].0.try_lock().is_err()
    }

    /// The owners of `row`, counted as (entry key, holder) claims.
    #[cfg(test)]
    pub(crate) fn owner_count(&self, row: &SteeringRow) -> usize {
        self.row_shard(row)
            .get(row)
            .map_or(0, |owners| owners.iter().map(|(_, held)| held.count()).sum())
    }

    /// The rows `worker` holds for `owner`.
    #[cfg(test)]
    pub(crate) fn held_row_count(&self, owner: &SessionKey, worker: u32) -> usize {
        self.held_row_count_for(owner, SteeringHolder::Worker(worker))
    }

    /// The rows `holder` holds for `owner`, BY IDENTITY.
    ///
    /// #9560 R12: a COUNT cannot answer an identity question. The first cell written to
    /// close the forward install's gap failed at base with "4 before, 4 after" — the
    /// real forward decision names as many rows as a seeded predecessor did, so neither
    /// an absolute count nor a delta can separate "released the old set and claimed a
    /// same-size new one" from "kept everything". Naming the rows is the only dimension
    /// in which those two differ.
    #[cfg(test)]
    pub(crate) fn held_rows_for(
        &self,
        owner: &SessionKey,
        holder: SteeringHolder,
    ) -> SmallVec<[SteeringRow; 4]> {
        held_rows(&self.holdings_shard(owner), owner, holder.claim())
    }

    /// The rows `holder` holds for `owner`.
    ///
    /// Derived from `held_rows_for` so the count and the identity answer cannot drift
    /// apart: a count that disagreed with the set it counts would make both untrustworthy.
    #[cfg(test)]
    pub(crate) fn held_row_count_for(&self, owner: &SessionKey, holder: SteeringHolder) -> usize {
        self.held_rows_for(owner, holder).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W0: SteeringHolder = SteeringHolder::Worker(0);
    const W1: SteeringHolder = SteeringHolder::Worker(1);
    const COORDINATOR: SteeringHolder = SteeringHolder::Coordinator;

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

    /// Publish rows `bytes` for `owner` as `holder`; returns the rows the publish
    /// deleted, by their fill byte.
    fn publish(owners: &SteeringRowOwners, owner: &SessionKey, holder: SteeringHolder, bytes: &[u8]) -> Vec<u8> {
        let rows: Vec<(SteeringRow, ())> = bytes.iter().map(|b| (row(*b), ())).collect();
        let mut deleted = Vec::new();
        owners
            .publish_entry(owner, holder, &rows, |_| Ok(()), |r| deleted.push(r[0]))
            .expect("a publish whose every write succeeds");
        deleted.sort_unstable();
        deleted
    }

    /// Release rows `bytes` (plus whatever `holder` holds for `owner`); returns the
    /// rows deleted, by their fill byte.
    fn release(owners: &SteeringRowOwners, owner: &SessionKey, holder: SteeringHolder, bytes: &[u8]) -> Vec<u8> {
        let rows: Vec<SteeringRow> = bytes.iter().map(|b| row(*b)).collect();
        let mut deleted = Vec::new();
        owners.release_entry(owner, holder, &rows, |r| deleted.push(r[0]));
        deleted.sort_unstable();
        deleted
    }

    #[test]
    fn a_single_owner_empties_its_row_9560() {
        let owners = SteeringRowOwners::default();
        publish(&owners, &key(0, 1000), W0, &[1]);
        assert_eq!(release(&owners, &key(0, 1000), W0, &[1]), vec![1]);
        assert_eq!(owners.owner_count(&row(1)), 0);
    }

    #[test]
    fn a_shared_row_survives_until_its_last_owner_goes_9560() {
        let owners = SteeringRowOwners::default();
        publish(&owners, &key(1, 1000), W0, &[2]);
        publish(&owners, &key(2, 1000), W0, &[2]);
        assert_eq!(
            release(&owners, &key(1, 1000), W0, &[2]),
            Vec::<u8>::new(),
            "the other domain's session still owns the row"
        );
        assert_eq!(release(&owners, &key(2, 1000), W0, &[2]), vec![2]);
    }

    /// The round-1 defect: one entry replicated to two workers. Owned by the key alone,
    /// the idle replica's reap emptied the row under the forwarding worker.
    #[test]
    fn a_replica_reap_keeps_the_row_the_forwarding_worker_holds_9560() {
        let owners = SteeringRowOwners::default();
        publish(&owners, &key(0, 1000), W0, &[3]);
        publish(&owners, &key(0, 1000), W1, &[3]);
        assert_eq!(owners.owner_count(&row(3)), 2, "each replica must claim the row");
        assert_eq!(
            release(&owners, &key(0, 1000), W1, &[3]),
            Vec::<u8>::new(),
            "worker 1's reap of its idle replica deleted the steering row worker 0 still \
             forwards the flow on (#9560)"
        );
        assert_eq!(release(&owners, &key(0, 1000), W0, &[3]), vec![3]);
    }

    #[test]
    fn a_non_owner_cannot_empty_a_row_others_own_9560() {
        let owners = SteeringRowOwners::default();
        publish(&owners, &key(1, 1000), W0, &[4]);
        assert_eq!(release(&owners, &key(9, 1000), W0, &[4]), Vec::<u8>::new());
        assert_eq!(owners.owner_count(&row(4)), 1);
    }

    #[test]
    fn an_unowned_row_is_deleted_9560() {
        let owners = SteeringRowOwners::default();
        assert_eq!(release(&owners, &key(0, 1000), W0, &[5]), vec![5]);
        assert_eq!(
            owners.release_row(&row(5), &key(0, 1000), W0, |_| ()),
            OwnerRemoval::Unregistered
        );
    }

    #[test]
    fn publishing_the_same_claim_twice_is_idempotent_9560() {
        let owners = SteeringRowOwners::default();
        publish(&owners, &key(0, 1000), W0, &[6]);
        publish(&owners, &key(0, 1000), W0, &[6]);
        assert_eq!(owners.owner_count(&row(6)), 1);
        assert_eq!(release(&owners, &key(0, 1000), W0, &[6]), vec![6]);
    }

    /// Round 3 inverts round 2's rule here. A coordinator write CLAIMS its row, and the
    /// claim is what stops an unrelated session's teardown from deleting a row the
    /// imported session is still using — the #9560 defect, which round 2 left alive for
    /// every row between the coordinator's write and a worker's first claim.
    #[test]
    fn a_coordinator_write_claims_the_row_9560() {
        let owners = SteeringRowOwners::default();
        publish(&owners, &key(0, 1000), COORDINATOR, &[7]);
        assert_eq!(owners.owner_count(&row(7)), 1);
        assert_eq!(
            release(&owners, &key(3, 1000), W0, &[7]),
            Vec::<u8>::new(),
            "another session's teardown deleted the row the coordinator holds; that is the \
             aliased-row delete #9560 exists to prevent"
        );
        assert_eq!(owners.owner_count(&row(7)), 1);
        assert_eq!(
            release(&owners, &key(0, 1000), COORDINATOR, &[7]),
            vec![7],
            "the coordinator's own release is the last owner's, so the row goes"
        );
    }

    /// The claim is per (entry key, holder): a worker claiming the same row the
    /// coordinator published keeps the row alive until BOTH give it up, in either order.
    #[test]
    fn a_coordinator_and_a_worker_both_hold_the_same_row_9560() {
        let owners = SteeringRowOwners::default();
        let owner = key(0, 1000);
        publish(&owners, &owner, COORDINATOR, &[19]);
        publish(&owners, &owner, W0, &[19]);
        assert_eq!(owners.owner_count(&row(19)), 2);
        assert_eq!(
            release(&owners, &owner, COORDINATOR, &[19]),
            Vec::<u8>::new(),
            "the worker still forwards on this row"
        );
        assert_eq!(owners.held_row_count_for(&owner, COORDINATOR), 0);
        assert_eq!(release(&owners, &owner, W0, &[19]), vec![19]);
    }

    /// A dead worker's claims are retired, and a row it was the last owner of is deleted.
    /// Without this its bit suppresses every later delete of that row for the life of the
    /// process, because the worker never runs its own teardown.
    #[test]
    fn retiring_a_dead_worker_releases_its_claims_9560() {
        let owners = SteeringRowOwners::default();
        let owner = key(0, 1000);
        publish(&owners, &owner, W0, &[20, 21]);
        publish(&owners, &owner, W1, &[21]);
        let mut deleted: Vec<u8> = Vec::new();
        let retired = owners.retire_worker(0, |r| deleted.push(r[0]));
        assert_eq!(retired, 2, "both of worker 0's claims must be retired");
        assert_eq!(
            deleted,
            vec![20],
            "only the row worker 0 was the LAST owner of is deleted; worker 1 still holds \
             the other"
        );
        assert_eq!(owners.held_row_count(&owner, 0), 0);
        assert_eq!(owners.owner_count(&row(21)), 1);
    }

    #[test]
    fn a_coordinator_delete_skips_a_worker_held_row_and_deletes_an_unowned_one_9560() {
        let owners = SteeringRowOwners::default();
        publish(&owners, &key(0, 1000), W0, &[8]);
        assert_eq!(
            release(&owners, &key(0, 1000), COORDINATOR, &[8, 9]),
            vec![9],
            "the coordinator's delete must leave a row a worker holds (its DeleteSynced \
             fan-out releases it) and delete an unowned one"
        );
        assert_eq!(owners.owner_count(&row(8)), 1);
    }

    #[test]
    fn a_failed_write_claims_nothing_9560() {
        let owners = SteeringRowOwners::default();
        let owner = key(0, 1000);
        let result = owners.publish_entry(
            &owner,
            W0,
            &[(row(10), ())],
            |_| Err(io::Error::other("no map")),
            |_| panic!("a failed publish must delete nothing"),
        );
        assert!(result.is_err());
        assert_eq!(owners.owner_count(&row(10)), 0, "a claim was kept for a failed write");
        assert_eq!(owners.held_row_count(&owner, 0), 0);
    }

    #[test]
    fn a_republish_releases_the_rows_the_new_decision_does_not_name_9560() {
        let owners = SteeringRowOwners::default();
        let owner = key(0, 1000);
        publish(&owners, &owner, W0, &[11, 12]);
        assert_eq!(
            publish(&owners, &owner, W0, &[11, 13]),
            vec![12],
            "a same-key republish (a NAT change) must release the row only the old decision \
             named, or it leaks a REDIRECT row and blocks the next owner's delete"
        );
        assert_eq!(owners.held_row_count(&owner, 0), 2);
        assert_eq!(owners.owner_count(&row(12)), 0);
    }

    #[test]
    fn a_republish_keeps_a_released_row_another_owner_holds_9560() {
        let owners = SteeringRowOwners::default();
        publish(&owners, &key(1, 1000), W0, &[14, 15]);
        publish(&owners, &key(2, 1000), W1, &[15]);
        assert_eq!(publish(&owners, &key(1, 1000), W0, &[14]), Vec::<u8>::new());
        assert_eq!(owners.owner_count(&row(15)), 1);
    }

    #[test]
    fn a_failed_republish_releases_nothing_9560() {
        let owners = SteeringRowOwners::default();
        let owner = key(0, 1000);
        publish(&owners, &owner, W0, &[16, 17]);
        let result = owners.publish_entry(
            &owner,
            W0,
            &[(row(18), ())],
            |_| Err(io::Error::other("no map")),
            |_| panic!("a failed republish must release nothing"),
        );
        assert!(result.is_err());
        assert_eq!(owners.held_row_count(&owner, 0), 2);
    }

    #[test]
    fn releasing_an_entry_also_releases_rows_its_old_decision_held_9560() {
        let owners = SteeringRowOwners::default();
        let owner = key(0, 1000);
        publish(&owners, &owner, W0, &[19, 20]);
        assert_eq!(
            release(&owners, &owner, W0, &[19]),
            vec![19, 20],
            "a teardown that derives rows from the current decision must still release a row \
             an earlier decision published"
        );
        assert_eq!(owners.held_row_count(&owner, 0), 0);
    }

    #[test]
    fn retiring_workers_drops_claims_without_deleting_9560() {
        let owners = SteeringRowOwners::default();
        publish(&owners, &key(0, 1000), W0, &[21]);
        owners.retire_workers();
        assert_eq!(owners.owner_count(&row(21)), 0);
        assert_eq!(owners.held_row_count(&key(0, 1000), 0), 0);
        assert_eq!(
            release(&owners, &key(5, 1000), W1, &[21]),
            vec![21],
            "a retired claim must not block a later delete of the row"
        );
    }

    #[test]
    fn shard_selection_stays_in_bounds_9560() {
        for byte in 0..=u8::MAX {
            let mut r = [0u8; 40];
            r[39] = byte;
            r[0] = byte.wrapping_mul(31);
            assert!(row_shard_idx(&r) < NUM_SHARDS);
            assert!(key_shard_idx(&key(u32::from(byte), u16::from(byte))) < NUM_SHARDS);
        }
    }

    #[test]
    fn a_poisoned_shard_is_still_usable_9560() {
        let owners = std::sync::Arc::new(SteeringRowOwners::default());
        let poisoner = owners.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.row_shard(&row(22));
            panic!("poison the shard that row 22 lives in");
        })
        .join();
        publish(&owners, &key(0, 1000), W0, &[22]);
        assert_eq!(release(&owners, &key(0, 1000), W0, &[22]), vec![22]);
    }
}
