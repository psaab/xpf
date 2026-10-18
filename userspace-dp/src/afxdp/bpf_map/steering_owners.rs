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
//! **Coordinator writes claim too (#9560 round 3).** A coordinator write (HA
//! import, bringup replay, RG activation) claims its row with the coordinator
//! bit, so an aliased teardown cannot delete it in the handoff window; every
//! authoritative removal of the shared entry releases that claim.
//!
//! **Actions are recorded (#14650).** Each owner records the action byte it
//! published. A physical row shared by owners with different actions is
//! coalesced fail-safe — REDIRECT wins over PASS_TO_KERNEL — on publish, and
//! a release/retire restores the surviving owners' action instead of leaving
//! the removed owner's PASS value behind. Before this the registry was
//! action-blind: a PASS publish overwrote a shared REDIRECT row and the PASS
//! release stranded the survivor at PASS permanently.
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
//! joined every worker, `retire_workers` drops every WORKER claim WITHOUT a BPF
//! delete (coordinator claims survive, #14650): worker sessions died with their
//! workers and their rows linger unowned as before #9560, while coordinator rows
//! still stand for live shared authority. A worker that panics is not respawned,
//! so its claims stay until that stop.
//!
//! **Locking.** An operation for a worker takes its key's holdings shard, then one row
//! shard at a time; row-shard code never takes a holdings lock. Each BPF write or
//! delete runs inside its row's shard lock, so a sibling's teardown cannot find a row
//! ownerless and delete it after a publish landed in between. A claim is recorded only
//! after its write succeeded.

use std::hash::BuildHasher;
use std::io;
use std::sync::{LazyLock, Mutex, MutexGuard};

use smallvec::SmallVec;

use crate::afxdp::types::FastMap;
use crate::session::SessionKey;

/// The steering-map row a key occupies: the 40 bytes the shim looks up.
pub(crate) type SteeringRow = [u8; 40];

const NUM_SHARDS: usize = 64;
const _: () = assert!(
    NUM_SHARDS.is_power_of_two(),
    "shard selection masks keyed hash bits"
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

/// The owners of one row: each entry key once, with the holders claiming it and
/// the action byte that entry last published (#14650). One entry is the common
/// case, so it is stored inline and a row costs no heap allocation.
///
/// #14650: before this, owners stored `(SessionKey, Claim)` with NO action, so
/// a `PASS_TO_KERNEL` (2) publish blindly overwrote a shared `REDIRECT` (1)
/// row and the PASS owner's release left the survivor at 2 permanently — a
/// cross-session kernel-pass hijack. The recorded action lets a release (or
/// retire) restore the surviving owner's value, and lets two owners of the
/// SAME entry key with different actions stay distinct claims.
type Owners = SmallVec<[(SessionKey, Claim, u8); 1]>;

/// The rows one entry key's holders hold, each with the holders claiming it and
/// the action published for that row. The action rides here too so a stale-row
/// release in `publish_entry` can tell whether the physical row still carries
/// this holder's value or a survivor's.
type Held = SmallVec<[(SteeringRow, Claim, u8); 4]>;

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

/// Seeded keyed-hash selection prevents offline shard targeting (#12794).
static SHARD_SEED: LazyLock<u64> =
    LazyLock::new(crate::hot_hash_seed::hot_path_hash_seed);

fn shard_of(hash: u64) -> usize {
    (hash as usize) & (NUM_SHARDS - 1)
}

fn row_shard_idx_with(seed: u64, row: &SteeringRow) -> usize {
    let state = crate::hot_hash_seed::HotPathSeededState::new(seed);
    shard_of(state.hash_one(row))
}

fn key_shard_idx_with(seed: u64, key: &SessionKey) -> usize {
    let state = crate::hot_hash_seed::HotPathSeededState::new(seed);
    shard_of(state.hash_one(key))
}

fn row_shard_idx(row: &SteeringRow) -> usize {
    row_shard_idx_with(*SHARD_SEED, row)
}

fn key_shard_idx(key: &SessionKey) -> usize {
    key_shard_idx_with(*SHARD_SEED, key)
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
    if let Some(position) = owners.iter().position(|(key, _, _)| key == owner) {
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

/// The action the surviving owners of a row need in the BPF map. REDIRECT (1)
/// wins over PASS_TO_KERNEL (2): steering to the policy engine is the
/// fail-safe direction (#9517), so a mixed-action row must never sit at PASS
/// while a REDIRECT owner survives (#14650).
fn surviving_action(owners: &Owners) -> Option<u8> {
    if owners.iter().any(|(_, _, action)| *action == 1) {
        Some(1)
    } else {
        owners.first().map(|(_, _, action)| *action)
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
        .filter(|(_, held, _)| held.intersects(claim))
        .map(|(row, _, _)| *row)
        .collect()
}

impl SteeringRowOwners {
    fn row_shard(&self, row: &SteeringRow) -> MutexGuard<'_, FastMap<SteeringRow, Owners>> {
        lock(&self.rows[row_shard_idx(row)])
    }

    fn holdings_shard(&self, key: &SessionKey) -> MutexGuard<'_, FastMap<SessionKey, Held>> {
        lock(&self.holdings[key_shard_idx(key)])
    }

    /// Write ONE row for `owner` as `holder` with action byte `action`,
    /// releasing nothing else the holder has for `owner`. `write(action)`
    /// (the BPF update) runs under the row's shard lock, and a claim is
    /// recorded only if it succeeds.
    ///
    /// #14650: the registry is action-aware. If the row already has owners
    /// whose recorded action differs, the physical write is COALESCED to the
    /// fail-safe surviving action (REDIRECT wins): the caller still believes
    /// it wrote `action`, but the shim never sees PASS while a REDIRECT
    /// owner shares the row. The claim records the caller's `action` so a
    /// later release can recompute what the survivor needs.
    pub(crate) fn publish_row(
        &self,
        row: &SteeringRow,
        owner: &SessionKey,
        holder: SteeringHolder,
        action: u8,
        write: impl FnOnce(u8) -> io::Result<()>,
    ) -> io::Result<()> {
        let claim = holder.claim();
        let mut holdings = self.holdings_shard(owner);
        self.write_and_claim(&mut holdings, row, owner, claim, action, write)
    }

    /// Test-only action-less publish (recorded action 0 = unknown; fixtures
    /// using it never share a row across actions). Production steering writes
    /// go through the `u8`-payload `publish_entry` / action-explicit
    /// `publish_row` above.
    #[cfg(test)]
    pub(crate) fn publish_row_for_test(
        &self,
        row: &SteeringRow,
        owner: &SessionKey,
        holder: SteeringHolder,
        write: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        self.publish_row(row, owner, holder, 0, |_| write())
    }

    /// Publish every row of one entry as `holder`. The payload is carried
    /// through to `write`; `action_of` extracts its BPF action byte and
    /// `with_action` rebuilds it with the (possibly coalesced) action, so
    /// the physical write never carries PASS while a REDIRECT owner shares
    /// the row (#14650). Each row whose write succeeds is claimed, and once
    /// every row is written the rows the holder held for `owner` that `rows`
    /// does not name are released; `delete`/`restore` run under the row lock.
    ///
    /// A failed write stops the publish and releases nothing.
    pub(crate) fn publish_entry<T: Copy>(
        &self,
        owner: &SessionKey,
        holder: SteeringHolder,
        rows: &[(SteeringRow, T)],
        action_of: impl Fn(&T) -> u8,
        with_action: impl Fn(&T, u8) -> T,
        mut write: impl FnMut(&T) -> io::Result<()>,
        mut delete: impl FnMut(&SteeringRow),
        mut restore: impl FnMut(&SteeringRow, u8),
    ) -> io::Result<()> {
        let claim = holder.claim();
        let mut holdings = self.holdings_shard(owner);
        for (row, payload) in rows {
            let action = action_of(payload);
            let payload = *payload;
            self.write_and_claim(&mut holdings, row, owner, claim, action, |a| {
                write(&with_action(&payload, a))
            })?;
        }
        let stale: SmallVec<[SteeringRow; 4]> = held_rows(&holdings, owner, claim)
            .into_iter()
            .filter(|held| !rows.iter().any(|(row, _)| row == held))
            .collect();
        for row in &stale {
            self.release_locked(Some(&mut holdings), row, owner, claim, &mut delete, &mut restore);
        }
        Ok(())
    }

    /// Give up one entry's rows as `holder`: every row in `rows` and every
    /// other row the holder holds for `owner`. Each row goes from the BPF
    /// map (`delete`) unless another owner holds it; when owners remain but
    /// the removed claim may have overwritten the row, `restore(row, action)`
    /// rewrites the survivor's fail-safe action (#14650). A row in `rows`
    /// that no owner holds is deleted too, as it was before #9560.
    pub(crate) fn release_entry(
        &self,
        owner: &SessionKey,
        holder: SteeringHolder,
        rows: &[SteeringRow],
        mut delete: impl FnMut(&SteeringRow),
        mut restore: impl FnMut(&SteeringRow, u8),
    ) {
        let claim = holder.claim();
        let mut released: SmallVec<[SteeringRow; 8]> = SmallVec::new();
        let mut holdings = self.holdings_shard(owner);
        let held = held_rows(&holdings, owner, claim);
        for row in rows.iter().chain(held.iter()) {
            if !released.contains(row) {
                released.push(*row);
                self.release_locked(Some(&mut holdings), row, owner, claim, &mut delete, &mut restore);
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
        mut restore: impl FnMut(&SteeringRow, u8),
    ) -> OwnerRemoval {
        let claim = holder.claim();
        let mut holdings = self.holdings_shard(owner);
        self.release_locked(Some(&mut holdings), row, owner, claim, &mut delete, &mut restore)
    }

    /// Drop every WORKER claim WITHOUT a BPF delete, preserving coordinator
    /// claims (#14650). Call only once every worker is joined
    /// (`Coordinator::stop_inner`): no worker may register after it.
    ///
    /// Before #14650 this `mem::take`n EVERY shard, wiping the coordinator
    /// claims #9560 round 3 added precisely so coordinator rows survive —
    /// contradicting the module contract and desynchronising rows vs
    /// holdings against a concurrent lock-free `sync_session` coordinator
    /// publish (#7209). Now only the worker bits are cleared, per shard
    /// under that shard's lock; entries left with no holder are dropped,
    /// coordinator-only entries survive intact in both maps.
    pub(crate) fn retire_workers(&self) {
        // Rows first (mirrors the old ordering rationale): a racing
        // coordinator delete that finds a row workerless still sees any
        // coordinator claim, so it cannot delete a coordinator-held row.
        for shard in &self.rows {
            let mut rows = lock(shard);
            rows.retain(|_, owners| {
                owners.retain_mut(|(_, claim, _)| {
                    claim.workers = 0;
                    !claim.is_empty()
                });
                !owners.is_empty()
            });
        }
        for shard in &self.holdings {
            let mut holdings = lock(shard);
            holdings.retain(|_, held| {
                held.retain_mut(|(_, claim, _)| {
                    claim.workers = 0;
                    !claim.is_empty()
                });
                !held.is_empty()
            });
        }
    }

    /// Retire ONE holder's claims everywhere, deleting each row whose last
    /// owner it was (and restoring the survivor's action where one remains).
    pub(crate) fn retire_worker(
        &self,
        worker_id: u32,
        mut delete: impl FnMut(&SteeringRow),
        mut restore: impl FnMut(&SteeringRow, u8),
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
                    self.release_locked(Some(&mut holdings), &row, owner, claim, &mut delete, &mut restore);
                    retired += 1;
                }
            }
        }
        retired
    }

    /// Under the caller's holdings guard for `owner`: run `write` under the
    /// row's shard lock, then record the claim if it succeeded. The physical
    /// action written is the fail-safe coalesce of the caller's `action`
    /// with every existing owner's recorded action (#14650).
    fn write_and_claim(
        &self,
        holdings: &mut FastMap<SessionKey, Held>,
        row: &SteeringRow,
        owner: &SessionKey,
        claim: Claim,
        action: u8,
        write: impl FnOnce(u8) -> io::Result<()>,
    ) -> io::Result<()> {
        {
            let mut rows = self.row_shard(row);
            write(coalesce_action(rows.get(row), owner, action))?;
            let owners = rows.entry(*row).or_default();
            match owners.iter_mut().find(|(key, _, _)| key == owner) {
                Some((_, held_claim, held_action)) => {
                    held_claim.insert(claim);
                    *held_action = action;
                }
                None => owners.push((owner.clone(), claim, action)),
            }
        }
        match holdings.get_mut(owner) {
            Some(rows_held) => match rows_held.iter_mut().find(|(held_row, _, _)| held_row == row) {
                Some((_, held_claim, held_action)) => {
                    held_claim.insert(claim);
                    *held_action = action;
                }
                None => rows_held.push((*row, claim, action)),
            },
            None => {
                let mut held = Held::new();
                held.push((*row, claim, action));
                holdings.insert(owner.clone(), held);
            }
        }
        Ok(())
    }

    /// Clear `claim` from `owner`'s claim on `row` and, unless another owner
    /// remains, run `delete` before the row's shard lock is released; when
    /// owners remain, run `restore(row, surviving_action)` under the same
    /// lock so the physical row can never sit at the removed owner's PASS
    /// value while a REDIRECT survivor exists (#14650). Then drop the row
    /// from that holder's holding.
    fn release_locked(
        &self,
        holdings: Option<&mut FastMap<SessionKey, Held>>,
        row: &SteeringRow,
        owner: &SessionKey,
        claim: Claim,
        delete: &mut impl FnMut(&SteeringRow),
        restore: &mut impl FnMut(&SteeringRow, u8),
    ) -> OwnerRemoval {
        let outcome = {
            let mut rows = self.row_shard(row);
            // Capture survivors BEFORE removal for the restore decision.
            let outcome = remove_claim(&mut rows, row, owner, claim);
            if outcome != OwnerRemoval::Remaining {
                delete(row);
            } else if let Some(survivors) = rows.get(row) {
                if let Some(action) = surviving_action(survivors) {
                    restore(row, action);
                }
            }
            outcome
        };
        if let Some(holdings) = holdings
            && let Some(held) = holdings.get_mut(owner)
        {
            if let Some(position) = held.iter().position(|(held_row, _, _)| held_row == row) {
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

    /// Whether `row`'s shard is locked at this instant.
    #[cfg(test)]
    pub(crate) fn shard_is_locked(&self, row: &SteeringRow) -> bool {
        self.rows[row_shard_idx(row)].0.try_lock().is_err()
    }

    /// The owners of `row`, counted as (entry key, holder) claims.
    #[cfg(test)]
    pub(crate) fn owner_count(&self, row: &SteeringRow) -> usize {
        self.row_shard(row)
            .get(row)
            .map_or(0, |owners| owners.iter().map(|(_, held, _)| held.count()).sum())
    }

    /// The fail-safe action the surviving owners of `row` require, or `None`
    /// if no owner remains (#14650). Production restore writes exactly this.
    #[cfg(test)]
    pub(crate) fn recorded_action(&self, row: &SteeringRow) -> Option<u8> {
        self.row_shard(row).get(row).and_then(|owners| surviving_action(owners))
    }


    /// The rows `worker` holds for `owner`.
    #[cfg(test)]
    pub(crate) fn held_row_count(&self, owner: &SessionKey, worker: u32) -> usize {
        self.held_row_count_for(owner, SteeringHolder::Worker(worker))
    }

    #[cfg(test)]
    pub(crate) fn held_rows_for(
        &self,
        owner: &SessionKey,
        holder: SteeringHolder,
    ) -> SmallVec<[SteeringRow; 4]> {
        held_rows(&self.holdings_shard(owner), owner, holder.claim())
    }

    #[cfg(test)]
    pub(crate) fn held_row_count_for(&self, owner: &SessionKey, holder: SteeringHolder) -> usize {
        self.held_rows_for(owner, holder).len()
    }
}

/// #14650 fail-safe coalesce: REDIRECT (1) if the incoming action or ANY
/// existing owner (other than a same-owner re-publish, whose old action is
/// being replaced) wants REDIRECT; otherwise the incoming action.
fn coalesce_action(existing: Option<&Owners>, owner: &SessionKey, incoming: u8) -> u8 {
    if incoming == 1 {
        return 1;
    }
    if let Some(owners) = existing {
        if owners.iter().any(|(k, _, a)| k != owner && *a == 1) {
            return 1;
        }
    }
    incoming
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

    /// Publish rows `bytes` for `owner` as `holder` (action 1); returns deleted.
    fn publish(owners: &SteeringRowOwners, owner: &SessionKey, holder: SteeringHolder, bytes: &[u8]) -> Vec<u8> {
        let rows: Vec<(SteeringRow, u8)> = bytes.iter().map(|b| (row(*b), 1u8)).collect();
        let mut deleted = Vec::new();
        owners
            .publish_entry(owner, holder, &rows, |a| *a, |_, a| a, |_| Ok(()), |r| deleted.push(r[0]), |_, _| {})
            .expect("a publish whose every write succeeds");
        deleted.sort_unstable();
        deleted
    }

    /// Release rows `bytes` (plus whatever `holder` holds for `owner`); returns deleted.
    fn release(owners: &SteeringRowOwners, owner: &SessionKey, holder: SteeringHolder, bytes: &[u8]) -> Vec<u8> {
        let rows: Vec<SteeringRow> = bytes.iter().map(|b| row(*b)).collect();
        let mut deleted = Vec::new();
        owners.release_entry(owner, holder, &rows, |r| deleted.push(r[0]), |_, _| {});
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
            owners.release_row(&row(5), &key(0, 1000), W0, |_| (), |_, _| ()),
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
        let retired = owners.retire_worker(0, |r| deleted.push(r[0]), |_, _| {});
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
            &[(row(10), 1u8)],
            |a: &u8| *a,
            |_, a| a,
            |_| Err(io::Error::other("no map")),
            |_| panic!("a failed publish must delete nothing"),
            |_, _| {},
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
            &[(row(18), 1u8)],
            |a: &u8| *a,
            |_, a| a,
            |_| Err(io::Error::other("no map")),
            |_| panic!("a failed republish must release nothing"),
            |_, _| {},
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
    /// #14650 decisive cell (registry level): the registry stores no action
    /// byte, so a PASS publish overwrites a REDIRECT row shared by an aliased
    /// owner, and the PASS release then leaves the survivor's row at PASS.
    /// The `RefCell<u8>` models the BPF row value: `write` sets it,
    /// `release_entry`'s delete sets it to 0, and a correct registry must
    /// restore the surviving owner's action via its write seam on release
    /// (or refuse/coalesce the conflicting publish so 2 is never written).
    #[test]
    fn aliased_pass_publish_restores_redirect_on_release_14650() {
        use std::cell::Cell;
        let owners = SteeringRowOwners::default();
        let redirect_owner = key(1, 1000);
        let pass_owner = key(2, 1000);
        let shared = row(30);
        let bpf_value = Cell::new(0u8);
        let bpf_deleted = Cell::new(false);
        owners
            .publish_entry(
                &redirect_owner,
                W0,
                &[(shared, 1u8)],
                |a: &u8| *a,
                |_, a| a,
                |v: &u8| { bpf_value.set(*v); Ok(()) },
                |_| panic!("publish must not delete"),
                |_, _| {},
            )
            .expect("redirect publish");
        assert_eq!(bpf_value.get(), 1, "control: REDIRECT must be written first");
        owners
            .publish_entry(
                &pass_owner,
                W0,
                &[(shared, 2u8)],
                |a: &u8| *a,
                |_, a| a,
                |v: &u8| { bpf_value.set(*v); Ok(()) },
                |_| panic!("publish must not delete"),
                |_, _| {},
            )
            .expect("pass publish");
        assert_eq!(
            bpf_value.get(), 1,
            "the PASS publish must be coalesced to REDIRECT while a REDIRECT \
             owner shares the row; writing 2 hijacks the survivor to the kernel (#14650)"
        );
        // Release the PASS owner through the same seam production uses:
        // delete_live/release paths have no write callback, so the registry
        // itself must restore via the restore seam (see fix). For RED this
        // uses release_entry + rewrites observed through a fresh publish of
        // the survivor only if the registry exposes the survivor's action.
        owners.release_entry(&pass_owner, W0, &[shared], |_| bpf_deleted.set(true), |_, a| bpf_value.set(a));
        assert!(
            !bpf_deleted.get(),
            "releasing one aliased owner must not delete the shared row"
        );
        assert_eq!(
            owners.recorded_action(&shared),
            Some(1),
            "after the PASS owner releases, the surviving REDIRECT owner's \
             recorded action must be REDIRECT (1), not PASS_TO_KERNEL (2): the \
             registry is action-blind today (#14650)"
        );
        assert_eq!(
            owners.owner_count(&shared), 1,
            "the REDIRECT owner must still hold the shared row"
        );
    }

    #[test]
    fn retire_workers_preserves_coordinator_claims_14650() {
        let owners = SteeringRowOwners::default();
        publish(&owners, &key(0, 1000), COORDINATOR, &[31]);
        publish(&owners, &key(0, 1001), W0, &[32]);
        owners.retire_workers();
        assert_eq!(
            owners.owner_count(&row(31)), 1,
            "retire_workers wiped the coordinator claim; coordinator rows must survive worker retirement (#14650)"
        );
        assert_eq!(owners.held_row_count_for(&key(0, 1000), COORDINATOR), 1);
        assert_eq!(owners.owner_count(&row(32)), 0, "worker claims must still be retired");
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

    #[test]
    fn keyed_shards_disperse_and_depend_on_seed_12794() {
        let rows: Vec<SteeringRow> = (0..256u16)
            .map(|i| {
                let mut r = [0u8; 40];
                r[14..16].copy_from_slice(&i.to_be_bytes());
                r
            })
            .collect();
        let assignment = |seed| rows.iter().map(|r| row_shard_idx_with(seed, r)).collect::<Vec<_>>();
        for seed in [1u64, 42, 0x0123_4567_89AB_CDEF, u64::MAX] {
            let distinct: std::collections::BTreeSet<_> =
                rows.iter().map(|r| row_shard_idx_with(seed, r)).collect();
            assert!(
                distinct.len() > 32,
                "#12794: steering row clique collapsed to {} shards under seed {seed:#x}",
                distinct.len()
            );
        }
        assert_eq!(assignment(42), assignment(42));
        assert_ne!(assignment(42), assignment(43));
        assert_eq!(row_shard_idx_with(42, &row(1)), 51, "pinned row shard");
        assert_eq!(key_shard_idx_with(42, &key(1, 1000)), 33, "pinned key shard");
    }
}
