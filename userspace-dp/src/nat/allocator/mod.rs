// Pool-mode SNAT port allocator + persistent lease state machine.
//
// #2852 Phase 1 (lock-free port claim): per-pool-address occupancy is an
// atomic bitmap (`AddressOccupancy`, `Vec<AtomicU64>` + keyed fresh-port
// probe, #16011); a CAS on the bit IS the port-ownership token, replacing
// the pre-#2852 `owner_by_translated` / `addr_index_by_translated` maps and
// per-address `next_port_offset_by_addr` cursor. Port CLAIM remains outside
// the retained `live` RwLock, but the non-persistent fast path now attempts
// `live.try_write()` after claiming a candidate and holds it through the
// reverse-identity check, flow-shard insert, and PAT-owner publication.
// If that try-write contends, the unpublished claim is released and the
// allocation enters the serialized fallback, which may wait. The microbench
// `benches/snat_allocator.rs` (results in docs/research/2852-portalloc/)
// proved the pre-Phase-1 single mutex negative-scales (2.87M->0.62M
// allocs/sec, M=1->8); those historical results do not measure this
// contention fallback.
//
// What stays under `RwLock<PortAllocatorLiveState>`: persistent-lease
// lifecycle (`persistent_by_source` + expiration indexes), ownership
// indexes, and `gc_counter`. #15956 Phase 2 sharded `live_by_flow` in
// flows.rs (16 shards); each new non-persistent PAT flow now briefly
// takes the write guard too, so the identity check and owner publication
// cannot diverge. Under contention the try-only fast path gives way to
// the existing serialized writer path; distinct flows can therefore
// serialize behind `live` under contention. Read-only consumers still
// take the shared guard, concurrently when no writer is active.
//
// F4 (global tracked-flow cap): kept EXACT with no overshoot. The cap is
// the sharded map's atomic count — bumped only on actual insert/remove
// under the shard write lock — re-checked under that lock, where the
// count is authoritative, so it never overshoots and a tiny pool near
// capacity is NOT falsely exhausted.
//
// FIFO recycle (#3011): freed ports still recycle oldest-first to spread
// reuse across the upstream 2MSL/TIME_WAIT window. The queue is a per-ADDRESS
// `Mutex<VecDeque<u16>>` (`AddressOccupancy::recycle`) — a much smaller,
// per-address critical section than the pre-#2852 global mutex, and it
// preserves the EXACT `push_back`/`pop_front` ordering the #3011 tests pin
// (a fully lock-free MPMC recycle ring is a Phase-2 option; `crossbeam` is
// not a dependency and a hand-rolled lock-free ring is not worth the risk on
// this hot NAT path). Lock ordering is always global -> recycle (the recycle
// mutex is innermost, never held while acquiring the global mutex), so there
// is no deadlock (plan F5 is sidestepped entirely: Phase 1 has no two-map-
// shard path).
//
// Port claim (AddressOccupancy::claim) collision handling (#3047/#16011):
// - Keyed phase: the per-flow RFC 6056 keyed start offset is probed
//   FORWARD over at most `range` distinct offsets, until a free port is
//   CAS-claimed or the range is genuinely exhausted. A single collision
//   with an out-of-band occupant (a persistent lease or an HA-synced
//   install whose bit sits at the probed offset) advances past it
//   instead of aborting the whole allocation (062-05). The common case
//   claims on the first probe.
// - Recycled phase: when the sequential range is spent, recycled ports are
//   drained FIFO (oldest-freed first, pop_front) so a just-freed port is the
//   LAST to be reassigned — this spreads port reuse across the upstream's
//   2MSL/TIME_WAIT window instead of immediately recycling the most recent
//   port (#3011). A popped port whose bit is already set is RETAINED (re-
//   queued at the back), never discarded, so a transient collision cannot
//   permanently shrink the reusable pool (062-10). The retain buffer
//   allocates lazily only when a collision actually occurs.
//
// Aggregate construction budget (#6812): `PortAllocator::new` is the memory
// heavyweight — one `AddressOccupancy` word array per pool address, sized to
// the port range (one bit per port slot). Construction is therefore gated
// TWICE upstream in `source.rs`: the Go #5877 strict commit gate rejects an
// over-budget config outright, and `resolve_pool_allocators` enforces the
// same budgets (pool count / total addresses / total port slots, charged
// per distinct allocator key, reuse-before-build, nothing built for a
// failed pool) at this apply boundary — the final backstop for a tolerated
// (lenient-load / peer-synced) or hand-crafted snapshot. Three full-range
// /16 pools would otherwise materialise 12,683,575,296 bitmap bits
// (~1.48 GiB) during apply.
//
// Cross-submodule visibility (per #1542 plan v3):
// - PortAllocator and PortAllocatorSnapshot are pub(crate) at definition
//   (re-exported by nat/mod.rs).
// - PortAllocator's state-machine methods (try_next_port, address_index,
//   allocate_translation, release_flow, rollback_flow, snapshot) are
//   pub(super) so source.rs / status.rs can drive them.
// - Live state struct + the fields that white-box tests inspect
//   (persistent_by_source, lease_expirations, lease_expirations_by_addr) are
//   pub(super). Port-ownership is inspected via the `#[cfg(test)]` debug
//   accessors (debug_is_port_occupied / debug_recycled_ports /
//   debug_set_recycled / debug_occupied_count).
// - PersistentLease + its fields are pub(super) for the same reason.
// - The remaining types (LiveAllocation, PortAllocatorShared
//   and its private fields, GC constants, capacity/sticky helpers) stay
//   fully private to this file.
//
// #16135: deterministic -> occupancy split (first two phases of the
// P5 order; persistent/live/gc phases NOT done — rest optional). This
// file is now nat/allocator/mod.rs, the PortAllocator facade.
//   deterministic.rs: DeterministicV4/V6, deterministic_indices_v4/v6,
//     reverse_deterministic_v4/v6, PoolReverseIndex,
//     build_pool_reverse_index — ZERO visibility widenings (all were
//     already pub(crate); re-exported below so crate::nat::* and
//     super::allocator::* paths are unchanged).
//   occupancy.rs: AddressOccupancy + RecycleRing — 25 widenings, all
//     private -> pub(in crate::nat::allocator), enumerated in that
//     file's header. Nothing outside nat::allocator can name them.
// At the split commit (b0ff071c29, 2026-10-22) this was pure code
// motion only: the allocator.rs:1-43 invariants above, every atomic
// ordering and the global -> recycle lock order were untouched.
// Verified at that commit by
// scripts/verify-nat-allocator-split-16135.py, which reconstructs
// the pre-split allocator.rs byte-for-byte after un-applying
// exactly the enumerated widenings; re-run it there (pinned
// --base/--split refs) — it checks the split commit, not this tree.
//
// Accounting against the issue's "124-item visibility bill" (the
// pre-split population, measured on the base file, not a count of
// items this move had to pay): the base allocator.rs contains 124
// textual `pub(super)` occurrences — 119 on code declarations plus
// 5 in comments (3 in the visibility note at old lines 80/83/86,
// 2 in a doc comment at old lines 5406-5407). A `pub(super)` item
// in the old file was visible in nat:: (its parent is nat), so the
// bill is only due on an item that MOVES one module deeper, where
// the same spelling would silently narrow to the new parent.
// Disposition of all 119 code declarations:
//   - 0 moved into deterministic.rs (0 of its items are pub(super);
//     all were already pub(crate), see that file's header), and
//     0 moved into occupancy.rs (AddressOccupancy/RecycleRing and
//     their members were all fully private, never pub(super)).
//   - 119 stayed in this file at the same module depth
//     (nat::allocator is still a direct child of nat::), so their
//     pub(super) spelling kept its exact pre-split meaning
//     (visible in nat::) and needed no widening. The base
//     file carried 124 occurrences (119 code + 5 comment);
//     that was a split-time count, not a current-tree invariant —
//     the file has been edited since (e.g. #15956 added flows.rs).
// The cost actually paid by this move was therefore NOT the 124:
// it was 25 private -> pub(in crate::nat::allocator) widenings in
// occupancy.rs (plus 0 in deterministic.rs), enumerated there and
// verified at the split commit by the verifier above.

mod deterministic;
mod flows;
mod lease_table;
mod occupancy;

#[cfg(test)]
mod tests_deterministic_vectors_17124;
#[cfg(test)]
mod tests_occupancy_seam_16135;

pub(crate) use deterministic::{
    DeterministicV4, DeterministicV6, deterministic_indices_v4, deterministic_indices_v6,
};
#[cfg(test)]
pub(crate) use deterministic::{
    build_pool_reverse_index, reverse_deterministic_v4, reverse_deterministic_v6,
};
#[cfg(test)]
pub(crate) const LIVE_SHARDS_FOR_TEST: usize = flows::LIVE_SHARDS;
#[cfg(test)]
pub(crate) fn live_shard_index_for_test(flow: &SourceNatFlowKey) -> usize {
    flows::live_shard_index(flow)
}
impl PortAllocator {
    #[cfg(test)]
    pub(super) fn debug_hold_flow_shard(
        &self,
        flow: &SourceNatFlowKey,
    ) -> MutexGuard<'_, flows::LiveFlowShard> {
        self.shared.flows.shard_guard(flow)
    }
}
use occupancy::{
    AddressOccupancy, occupancy_next_probe, pat_keyed_offset, pat_mix, pat_secret,
};
#[cfg(test)]
use occupancy::{PAT_PORT_QUARANTINE_NS, RecycleRing, SMALL_POOL_QUARANTINE_MAX_RANGE};
#[cfg(test)]
pub(crate) const PAT_PORT_QUARANTINE_NS_FOR_TEST: u64 = PAT_PORT_QUARANTINE_NS;
#[cfg(test)]
pub(super) const SMALL_POOL_QUARANTINE_MAX_RANGE_FOR_TEST: u32 = SMALL_POOL_QUARANTINE_MAX_RANGE;
#[cfg(test)]
pub(super) use occupancy::{
    pat_keyed_offset as pat_keyed_offset_for_test, pat_mix as pat_mix_for_test,
};

use super::source::{PersistentNatPermit, SourceNatFlowKey};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};
use std::sync::{MutexGuard, RwLockReadGuard, RwLockWriteGuard, TryLockError};

pub(super) const NS_PER_SEC: u64 = 1_000_000_000;
// The lease sync stream re-primes every 30s and retires a silent connection
// after its 10s read deadline. Keep clear tombstones across two full-set ticks
// so an already in-flight pre-clear record cannot immediately restore a lease.
pub(super) const PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS: u64 = 60 * 1_000_000_000;
const ACTIVE_PERSISTENT_NAT_CLEAR_TOMBSTONE_NS: u64 = u64::MAX;

pub(crate) const MIN_PERSISTENT_NAT_LEASE_TIMEOUT_NS: u64 = NS_PER_SEC;
// Persistent-NAT source config caps this at 24 hours (schema_security.go).
// Idle-lease records cross an unauthenticated-capable peer channel, so the
// allocator enforces the same ceiling even when a caller bypasses config.
pub(crate) const MAX_PERSISTENT_NAT_LEASE_LIFETIME_NS: u64 = 86_400 * NS_PER_SEC;

pub(super) fn bounded_persistent_nat_timeout_ns(timeout_ns: u64) -> u64 {
    timeout_ns
        .max(MIN_PERSISTENT_NAT_LEASE_TIMEOUT_NS)
        .min(MAX_PERSISTENT_NAT_LEASE_LIFETIME_NS)
}
const MAX_SOURCE_NAT_POOL_TRACKED_FLOWS: usize = 262_144;
/// #16013: per-source fairness for NEW persistent leases, in one allocator.
/// `PersistentSourceKey` identifies one lease, but a single host churns leases
/// by varying its source port/protocol/routing scope, so the pool-global
/// `max_tracked_flows` cap alone lets one host retain the whole table after
/// its flows have closed. Charging is keyed by `(src_ip, routing_scope)` —
/// the pre-NAT source identity the session quota keys on, without the zone —
/// and counts live AND idle-retained leases: an idle lease still holds its
/// translated port/address and counts against the pool, so it must count
/// against its source too. The value mirrors the session layer's default
/// per-source ceiling (`DEFAULT_MAX_SESSIONS_PER_SOURCE`, 4096). On small
/// pools the pool cap binds first; on large pools this stops one host from
/// taking the entire lease table. Spoofability residual: a host that can
/// forge many source IPs is outside any claimed-source budget; ingress
/// SAV / zone session quotas remain the bound there (see S2-01).
pub(super) const MAX_PERSISTENT_LEASES_PER_SOURCE: usize = 4096;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PersistentSourceKey {
    pub(crate) protocol: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) src_port: u16,
    /// #10018: routing domain partition (see PersistentLease docs).
    pub(crate) routing_scope: u32,
    /// Always-None compatibility field; grants live in persistent_permissions.
    pub(crate) remote: Option<(IpAddr, u16)>,
}

/// Exact ownership of one inbound reference on one persistent lease.
///
/// `allocator_id` prevents a hold from crossing pools; `incarnation` prevents
/// an old hold from decrementing a lease re-minted under the same source key.
/// `owner` distinguishes the worker's copied publication token from an
/// independently acquired coordinator-import reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PersistentLeaseOwner {
    LocalWorker,
    CoordinatorImported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PersistentLeaseHold {
    pub(crate) key: PersistentSourceKey,
    pub(crate) allocator_id: usize,
    pub(crate) incarnation: u64,
    pub(crate) owner: PersistentLeaseOwner,
}

impl PersistentLeaseHold {
    pub(crate) fn same_lease(self, other: Self) -> bool {
        self.key == other.key
            && self.allocator_id == other.allocator_id
            && self.incarnation == other.incarnation
    }

    pub(crate) fn with_owner(self, owner: PersistentLeaseOwner) -> Self {
        Self { owner, ..self }
    }
}

/// #14322: egress-zone scope for persistent-NAT inbound PERMISSIONS.
/// `0` is the unscoped sentinel (NAT64 BIBs, legacy/imported records, direct
/// allocator calls). Lease identity (`PersistentSourceKey`) intentionally
/// excludes this: two rules sharing one pool must share one lease/tuple
/// (#9389), while their grants must not merge.
pub(super) const PERSISTENT_NAT_EGRESS_UNSCOPED: u32 = 0;
const EGRESS_SCOPE_OFFSET_BASIS: u32 = 0x811c_9dc5;
const EGRESS_SCOPE_PRIME: u32 = 0x0100_0193;
const EGRESS_SCOPE_TAG_V1: u32 = 1;
/// Deterministically folds (from, to). Never returns 0.
pub(super) fn persistent_egress_scope(from_zone: &str, to_zone: &str) -> u32 {
    let mut hash = EGRESS_SCOPE_OFFSET_BASIS;
    for byte in std::iter::once(0u8)
        .chain(from_zone.bytes())
        .chain(std::iter::once(0))
        .chain(to_zone.bytes())
    {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(EGRESS_SCOPE_PRIME);
    }
    hash.wrapping_add(1)
}

/// #15133 v2: folds the six authored scope fields followed by the packet
/// (from, to). Empty authored zones are replaced by the packet zone BEFORE
/// folding, so an interface-, routing-instance- or global-scoped rule-set
/// (empty from_zone) is never collapsed into the unscoped sentinel, while a
/// zone-scoped rule keys by its authored zones under any caller spelling.
/// The `1` tag domain-separates v2 from v1 so a persisted v1 hash cannot
/// alias a v2 hash (the offset-basis fold is not injective across the tag
/// boundary). `0` never folds to a bucket: callers substitute the rule's
/// normalized key, and the literal `0` stays reserved for NAT64 BIBs,
/// legacy/imported records and direct allocator calls whose grants share
/// one bucket by design. Never returns 0.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(super) fn persistent_egress_scope_v2(
    from_zone: &str,
    to_zone: &str,
    from_interface: &str,
    to_interface: &str,
    from_routing_instance: &str,
    to_routing_instance: &str,
    packet_from_zone: &str,
    packet_to_zone: &str,
) -> u32 {
    let eff_from = if from_zone.is_empty() {
        packet_from_zone
    } else {
        from_zone
    };
    let eff_to = if to_zone.is_empty() {
        packet_to_zone
    } else {
        to_zone
    };
    let fields: [&str; 8] = [
        eff_from,
        eff_to,
        from_interface,
        to_interface,
        from_routing_instance,
        to_routing_instance,
        packet_from_zone,
        packet_to_zone,
    ];
    let mut hash = EGRESS_SCOPE_OFFSET_BASIS;
    let feed = |byte: u8, hash: &mut u32| {
        *hash ^= u32::from(byte);
        *hash = hash.wrapping_mul(EGRESS_SCOPE_PRIME);
    };
    feed(EGRESS_SCOPE_TAG_V1 as u8, &mut hash);
    for field in fields {
        for byte in field.bytes() {
            feed(byte, &mut hash);
        }
        feed(0, &mut hash);
    }
    if hash == PERSISTENT_NAT_EGRESS_UNSCOPED {
        hash = hash.wrapping_add(1);
    }
    hash
}

/// Narrow on-wire translation between the v1 (six-field) and v2
/// (eight-field) `IdleLeaseWire.egress_scope` encodings. The v1..v2
/// boundary folds differently for the same rule, so a v1-encoded record
/// must never be compared against a v2-folded lookup. `None` until the
/// control-plane helper that owns the lease-control version knows which
/// encoding the peer used. FOLLOWUP(#15133): the coordinator-side
/// re-encode site, once the lease-control version negotiation carries it.
#[expect(dead_code, reason = "#17195: dead in every build checked (release and --tests stripped probes in docs/log/17195.md); retained deliberately, so expect fires if a caller appears and the item should then lose this attribute instead of regaining allow(dead_code)")]
pub(super) fn persistent_egress_scope_reencode_for_peer(_scope: u32) -> Option<u32> {
    None
}

/// One egress zone's inbound grants for a lease.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct PersistentPermissionScope {
    pub(super) any_remote: bool,
    pub(super) remotes: FxHashSet<(IpAddr, u16)>,
    /// #15936: packet from_zone the mint folded into this bucket's key,
    /// recorded verbatim so the non-zone inbound reader — which knows
    /// only the arrival zone and cannot invert the bucket hash — can
    /// verify a held bucket belongs to its rule by re-folding with
    /// (recorded_from, arrival). None for legacy idle-lease frames
    /// (before #16877) and NAT64 BIBs; those without provenance never
    /// take the fallback.
    pub(super) mint_from_zone: Option<String>,
    /// #16017: authorizing rule's permit epoch when `any_remote` was
    /// granted or explicitly re-authorized after an import. `remotes`
    /// never needs one (see `PersistentPermissions::permits`).
    pub(super) any_remote_permit_epoch: u64,
    /// #16017 fold 2: the permit epoch this stored grant is authorized
    /// for. A permit-change sync revokes grants by setting this to 0
    /// (demotion), and writers at an older epoch cannot restore a
    /// nonzero value. Only a writer whose epoch equals this bucket's
    /// current allocator epoch can re-authorize it.
    pub(super) permit_change_authorized: bool,
    /// #16017 fold 2: allocator permit epoch at which `permit_change_authorized`
    /// was last (re)authorized. Defaults to 0 = never revoked.
    pub(super) authorized_epoch: u64,
}

/// Grants bucketed by egress scope, with the 1024-remote cap across all buckets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct PersistentPermissions {
    pub(super) scopes: FxHashMap<u32, PersistentPermissionScope>,
}

pub(super) const MAX_PERSISTENT_PERMITTED_REMOTES: usize = 1024;
impl PersistentPermissions {
    fn scope(&self, egress_scope: u32) -> Option<&PersistentPermissionScope> {
        self.scopes.get(&egress_scope)
    }
    fn total_remotes(&self) -> usize {
        self.scopes.values().map(|s| s.remotes.len()).sum()
    }
    fn can_record(
        &self,
        permit: PersistentNatPermit,
        flow: SourceNatFlowKey,
        egress_scope: u32,
    ) -> bool {
        match permit {
            PersistentNatPermit::AnyRemoteHost => true,
            PersistentNatPermit::TargetHost => {
                self.scope(egress_scope)
                    .is_some_and(|s| s.remotes.contains(&(flow.dst_ip, 0)))
                    || self.total_remotes() < MAX_PERSISTENT_PERMITTED_REMOTES
            }
            PersistentNatPermit::TargetHostPort => {
                self.scope(egress_scope)
                    .is_some_and(|s| s.remotes.contains(&(flow.dst_ip, flow.dst_port)))
                    || self.total_remotes() < MAX_PERSISTENT_PERMITTED_REMOTES
            }
        }
    }
    fn record_with_zones(
        &mut self,
        permit: PersistentNatPermit,
        flow: SourceNatFlowKey,
        egress_scope: u32,
        mint_from_zone: Option<&str>,
        permit_epoch: u64,
    ) -> bool {
        if !self.can_record(permit, flow, egress_scope) {
            return false;
        }
        // Fold 2: a writer stamped with an epoch older than the bucket's
        // authorized epoch is stale. Its remotes may still be recorded
        // (exact grants are permit-mode independent), but it must not
        // restore any_remote authorization after a permit-change sync.
        let stale_any_remote_writer = permit == PersistentNatPermit::AnyRemoteHost
            && self
                .scope(egress_scope)
                .is_some_and(|s| s.authorized_epoch != 0 && permit_epoch < s.authorized_epoch);
        let scope = self.scopes.entry(egress_scope).or_default();
        if scope.mint_from_zone.is_none() {
            scope.mint_from_zone = mint_from_zone.map(str::to_string);
        }
        match permit {
            PersistentNatPermit::AnyRemoteHost => {
                scope.any_remote = true;
                if stale_any_remote_writer {
                    // Demoted: record the attempted grant but keep the
                    // newer authorization epoch so permits() rejects it.
                    scope.any_remote_permit_epoch = permit_epoch;
                } else {
                    scope.any_remote_permit_epoch = permit_epoch;
                    scope.permit_change_authorized = true;
                    scope.authorized_epoch = permit_epoch;
                }
            }
            PersistentNatPermit::TargetHost => {
                scope.remotes.insert((flow.dst_ip, 0));
            }
            PersistentNatPermit::TargetHostPort => {
                scope.remotes.insert((flow.dst_ip, flow.dst_port));
            }
        }
        true
    }
    /// #16017: does the current rule permit still authorize this bucket's
    /// any-remote grant? Fresh grants authorize at their mint epoch; a
    /// permit-change sync moves each covered bucket's authorized epoch to
    /// the new current epoch (preserving rules) or 0 (revoked, demoted to
    /// remotes-only), so a stale writer can no longer re-authorize it.
    fn any_remote_current(
        scope: &PersistentPermissionScope,
        permit: PersistentNatPermit,
        permit_epoch: u64,
        current_epoch: u64,
    ) -> bool {
        if !scope.any_remote {
            return false;
        }
        // A current AnyRemoteHost rule authorizes its own bucket.
        if permit == PersistentNatPermit::AnyRemoteHost {
            return permit_epoch == current_epoch || current_epoch <= 1;
        }
        if scope.authorized_epoch == 0 {
            return current_epoch == 0;
        }
        // Otherwise the grant must have been authorized for the current
        // epoch (a preserved or freshly re-granted bucket) or explicitly
        // minted at exactly the querying rule's epoch before any sync.
        scope.authorized_epoch == current_epoch
            || (current_epoch == 0 && scope.authorized_epoch == permit_epoch)
    }
    pub(super) fn permits(
        &self,
        egress_scope: u32,
        remote_ip: IpAddr,
        remote_port: u16,
        permit: PersistentNatPermit,
        permit_epoch: u64,
        current_epoch: u64,
    ) -> bool {
        let granted = |s: &PersistentPermissionScope| {
            Self::any_remote_current(s, permit, permit_epoch, current_epoch)
                || s.remotes.contains(&(remote_ip, 0))
                || s.remotes.contains(&(remote_ip, remote_port))
        };
        if egress_scope != PERSISTENT_NAT_EGRESS_UNSCOPED {
            return self.scope(egress_scope).is_some_and(granted);
        }
        self.scopes.values().any(granted)
    }
    /// #15133: does this lease hold ANY grant under `egress_scope`? A rule
    /// whose bucket is absent never minted on this lease, so its lookup
    /// must answer Miss (not Denied) and let a sibling rule that DID mint
    /// decide. Without this, the first sibling in snapshot order vetoes
    /// every inbound packet on a shared lease.
    pub(super) fn has_scope(&self, egress_scope: u32) -> bool {
        egress_scope == PERSISTENT_NAT_EGRESS_UNSCOPED || self.scopes.contains_key(&egress_scope)
    }
    /// #15936: admission for the non-zone inbound reader, which knows only
    /// the arrival zone and therefore hashed (arrival, arrival) — a bucket
    /// the mint (internal, arrival) never wrote. The mint pair cannot be
    /// re-derived from a hash, so each bucket records its mint packet pair
    /// (`PersistentPermissionScope::mint_from_zone`) at record time and this
    /// check re-folds THIS rule with that recorded pair: a held bucket
    /// belongs to the rule iff the re-fold reproduces the bucket key.
    /// Current imported records preserve provenance (#16877); legacy imported
    /// buckets without it never match. A sibling whose authored fields differ
    /// re-folds differently for every pair, so the fallback never widens to
    /// UNSCOPED/any-bucket. Returns Some(permitted) when such a bucket exists,
    /// None when the lease holds no bucket for this rule (caller treats it as
    /// a Miss so the minting sibling decides).
    pub(super) fn permits_authored_any_from(
        &self,
        rule: &super::source::SourceNatRule,
        arrival_zone: &str,
        remote_ip: IpAddr,
        remote_port: u16,
        permit: PersistentNatPermit,
        permit_epoch: u64,
        current_epoch: u64,
    ) -> Option<bool> {
        let mut saw = false;
        let mut permitted = false;
        for (bucket, scope) in &self.scopes {
            let Some(mint_from) = &scope.mint_from_zone else {
                continue;
            };
            let key = rule.persistent_rule_scope(
                mint_from,
                arrival_zone,
                arrival_zone,
                &super::NatScopeCtx::default(),
            );
            if key != *bucket {
                continue;
            }
            saw = true;
            if Self::any_remote_current(scope, permit, permit_epoch, current_epoch)
                || scope.remotes.contains(&(remote_ip, 0))
                || scope.remotes.contains(&(remote_ip, remote_port))
            {
                permitted = true;
            }
        }
        saw.then_some(permitted)
    }
    #[cfg(test)]
    pub(super) fn any_remote(&self) -> bool {
        self.scopes.values().any(|s| s.any_remote)
    }
    #[cfg(test)]
    pub(super) fn remotes_len(&self) -> usize {
        self.total_remotes()
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct TranslatedTuple {
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
}

/// #6751: how many PAT candidates one `live`-mutex acquisition may probe
/// before releasing it and yielding. A full-cycle probe on an exhausted
/// identity space is 64512 map lookups; holding the mutex across all of them
/// would stall every other worker's admission on this egress address for the
/// whole walk. The #4676 `gc_expired_chunked` budget discipline, applied to the
/// only other unbounded loop under this mutex.
const INTERFACE_PAT_PROBE_CHUNK: u32 = 64;

/// #6751: the outcome of an interface-mode identity mint.
///
/// `patted` is the discriminator the caller needs and cannot re-derive: it
/// decides whether the decision carries `rewrite_src_port: Some(port)` (the
/// wire moves) or leaves it unset (the wire is byte-identical to pre-#6751).
/// Returning the port alone would force the caller to compare it against the
/// flow's source port, which is the same thing said less directly and goes
/// wrong the moment a port-less protocol reports 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InterfaceIdentity {
    pub(super) port: u16,
    pub(super) patted: bool,
}

/// #6751 §5.3: a domain's answer to "do you own this translated identity?".
///
/// The tri-state distinction lives in [`super::source::SyncedReserveOutcome`]
/// for the whole synced-reserve scan; this is the per-allocator half of it, and
/// deliberately carries only the two answers an allocator that HAS been asked
/// can give. "Not this domain" is decided one level up, by whether the registry
/// holds an allocator for the address at all — an allocator cannot report that
/// about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InterfaceDomainReserve {
    /// The reservation is held for this flow.
    Owned,
    /// A DIFFERENT flow owns the requested identity. The caller must fail
    /// closed — never fall through to another domain, or the two domains both
    /// hand out one identity.
    IdentityConflict,
    /// The allocator could not create a further ownership record (its
    /// per-address tracked-flow cap). Kept SEPARATE from `IdentityConflict`
    /// because the two have different remedies and different §5.8 counters:
    /// this one says the node is out of bookkeeping capacity, that one says a
    /// live flow already owns this exact translated identity. Folding them
    /// would leave an operator unable to tell "raise capacity" from "a peer's
    /// session lost a race with a local flow".
    RegistryCap,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum PoolAddressFamily<'a> {
    V4(&'a [Ipv4Addr]),
    V6(&'a [Ipv6Addr]),
}

impl PoolAddressFamily<'_> {
    fn len(self) -> usize {
        match self {
            Self::V4(addrs) => addrs.len(),
            Self::V6(addrs) => addrs.len(),
        }
    }

    fn ip_at(self, index: usize) -> IpAddr {
        match self {
            Self::V4(addrs) => IpAddr::V4(addrs[index]),
            Self::V6(addrs) => IpAddr::V6(addrs[index]),
        }
    }
}

/// #6211 F2: the widest `worker_id` the [`LiveAllocation::holders`] bitmask can
/// represent. A worker whose id does not fit could set no bit on reserve and
/// clear no bit on release — self-consistent, but it collapses that worker back
/// to the pre-#6211-F2 single-holder behaviour (first release frees a port a
/// still-forwarding worker holds). The bound is therefore enforced where worker
/// ids are MINTED (`server::helpers::planning::replan_bindings_from_candidates`,
/// which refuses the whole plan), not here — an out-of-range id must never reach
/// the allocator in the first place.
///
/// Enforced at the mint site rather than on the raw `--workers` value because
/// the effective id range is `min(queue_count, workers)`: `queue_count` is the
/// per-interface RX-queue minimum, computed independently of `workers`, and the
/// id is `queue_id % workers` with `queue_id < queue_count`. Capping `--workers`
/// alone would refuse a SAFE configuration (`--workers 200` on a 16-queue NIC
/// mints ids 0..15).
pub(crate) const MAX_NAT_HOLDER_WORKERS: u32 = 128;

/// Tie the mask WIDTH to the constant so the two cannot drift apart: widening
/// `holders` without raising the bound (or vice versa) fails the build here
/// rather than silently truncating a holder bit at runtime.
const _: () = assert!(u128::BITS == MAX_NAT_HOLDER_WORKERS);

/// #6765: what a `reseed_retained_from` pass carried and what it could not.
/// Returned rather than logged inside the allocator so the caller can report it
/// once per apply with the pool name attached — and so a drop is never silent,
/// which is the same class of defect the re-seed exists to fix.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReseedOutcome {
    /// Live allocations re-seeded onto a retained address.
    pub(crate) reseeded: usize,
    /// Skipped: the port falls outside the NEW port range (range narrowed).
    pub(crate) skipped_out_of_range: usize,
    /// An address-only (`port no-translation`) token that could NOT be
    /// carried — the new allocator already owns that reverse identity.
    ///
    /// #8597 K11 narrowed this from "deliberately skipped". The old reading was
    /// true about PORTS (the record holds no bit, so it is outside the
    /// port-reissue defect) and did not cover what the record DOES hold: the
    /// `address_only_owners` entry that denies a second flow the same public
    /// reverse identity. Dropping it downgraded a fail-closed guard on an
    /// ordinary pool edit, so the pass now carries it and this counts the
    /// residual refusals.
    pub(crate) skipped_address_only: usize,
    /// `reserve_flow` refused — the tuple is already owned in the new
    /// allocator. Expected to be zero on a freshly built allocator.
    pub(crate) refused: usize,
    /// #7560: persistent-NAT leases the rebuild DROPPED whose address was
    /// RETAINED by the pool change.
    ///
    /// This is the population the #7560 policy decision is about, and the one
    /// that surprises an operator: they added or removed a DIFFERENT address,
    /// and a subscriber pinned to an address that is still in the pool loses
    /// its binding anyway. Carry-over is keyed on the whole
    /// `SourceNatPoolAllocatorKey` (pool name + the full address lists + port
    /// range), so ANY address change misses that lookup and drops every lease —
    /// including leases on addresses the change never touched.
    ///
    /// Counted, not carried. Whether it SHOULD be carried is the open decision;
    /// this makes the population measurable first, which is the precondition
    /// that decision was waiting on.
    pub(crate) dropped_persistent_on_retained: usize,
    /// #7560: persistent-NAT leases dropped whose address the pool change
    /// REMOVED. Unavoidable — the address is gone, so the binding cannot be
    /// honoured — and counted separately for exactly that reason: conflating it
    /// with the retained-address population above would make an unavoidable
    /// drop look like the policy surprise, and hide the real number inside it.
    pub(crate) dropped_persistent_on_removed: usize,
    /// #16481: deterministic leases whose tuple still satisfies the NEW
    /// deterministic geometry and whose port bit was re-reserved in the
    /// fresh allocator with the NEW `DeterministicPortedIdentity`. Only
    /// populated by `reseed_retained_deterministic_v6_from`.
    pub(crate) reseeded_deterministic: usize,
    /// #16481: deterministic leases considered for the carry whose tuple
    /// does NOT satisfy the NEW geometry (block moved, address removed,
    /// mode/geometry changed). Their sessions are left for session-hit
    /// revalidation to tear down; counted so the drop is not silent.
    pub(crate) skipped_deterministic_invalid: usize,
}

impl ReseedOutcome {
    /// #7560 residual: does the carried/skipped accounting have anything to say?
    ///
    /// DERIVED from the struct rather than restated at each call site, because
    /// it was already wrong at two of the three. `nat64.rs` gated on
    /// `reseeded || skipped_out_of_range || refused` and omitted
    /// `skipped_address_only` entirely, so a pass that skipped ONLY
    /// address-only tokens printed nothing at all; the #6979 rename site
    /// printed a line but left that count out of it. A per-site condition has
    /// to be updated everywhere a field is added, and was not — twice.
    ///
    /// This is deliberately NOT "fix the two sites". Two corrected conditions
    /// are still three places to forget next time; a derived gate makes a
    /// silently-ungated population unrepresentable.
    ///
    /// SCOPE: the populations THIS line accounts for. Dropped leases are a
    /// different population with its own note (`dropped_persistent_lease_note`)
    /// and its own condition, deliberately — see that file for why they are not
    /// a column on this line. Folding them in here would print a
    /// "0 not carried, 0 skipped, 0 refused" line on a lease-only drop, which
    /// is the noise that teaches an operator to skip the line.
    ///
    /// `reseeded` alone does not make the line interesting: the carry
    /// succeeding is the expected case. Every population that was NOT carried
    /// does, because each is state the operator has lost.
    pub(crate) fn needs_report(&self) -> bool {
        // EXHAUSTIVE DESTRUCTURE, no `..` rest pattern, deliberately. Adding a
        // field to ReseedOutcome FAILS TO COMPILE here until it is classified,
        // so a new population cannot be silently ungated.
        //
        // Without this the gate is merely CENTRALISED: one hand-written
        // disjunction that a new field slips past exactly as it slipped past
        // three per-site conditions. I verified that by adding a field and
        // populating it — needs_report() did not pick it up and no site's
        // message mentioned it. One place to forget is better than three and is
        // still a place to forget; the destructure makes it none.
        let Self {
            // Carried, not lost: the carry succeeding is the expected case and
            // is not on its own a reason to print.
            reseeded: _,
            skipped_out_of_range,
            skipped_address_only,
            refused,
            // Leases are a different population with their own note and its own
            // condition (dropped_persistent_lease_note). Classified here as NOT
            // gating this line, which is a decision rather than an omission —
            // that is the whole point of being forced to name them.
            dropped_persistent_on_retained: _,
            dropped_persistent_on_removed: _,
            // #16481: carried deterministic leases are the expected case
            // (like `reseeded`); invalid ones are lost state the operator
            // should see, like the other skipped populations.
            reseeded_deterministic: _,
            skipped_deterministic_invalid,
        } = *self;
        skipped_out_of_range > 0
            || skipped_address_only > 0
            || refused > 0
            || skipped_deterministic_invalid > 0
    }
}

/// #6211 F2: which worker is taking or dropping a reservation.
///
/// `Untracked` reproduces the pre-#6211-F2 contract exactly — a reserve sets no
/// holder bit and a release frees on the first call.
///
/// #7093: it is NOT "what every LOCAL allocation path uses", and the reason
/// given for that — "RSS steers a given 5-tuple to exactly ONE worker so a local
/// allocation has exactly one holder" — is false. A locally-born session is
/// replicated to every OTHER worker and each sibling reserves against the
/// owner's record, so the mask named every worker except the one forwarding.
/// #6522 fixed that: `allocate_translation` and friends now take a `holder` and
/// production passes `Worker(id)`. `Untracked` is what the `#[cfg(test)]` entry
/// points and the read-only fragment probe pass, and nothing else.
///
/// `Worker(id)` is used by the HA-synced reservation path, where the SAME
/// `(flow, translated)` is reserved once per worker: `handle_upsert_synced` runs
/// on every worker (`afxdp/ha/session_import.rs` fans the entry out to each
/// worker's command queue) against ONE shared allocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NatHolder {
    Untracked,
    Worker(u32),
}

impl NatHolder {
    /// The holder's bit in [`LiveAllocation::holders`]. `Untracked` — and any id
    /// the mint-site check should have refused — contributes no bit.
    fn bit(self) -> u128 {
        match self {
            Self::Untracked => 0,
            Self::Worker(id) => {
                debug_assert!(
                    id < MAX_NAT_HOLDER_WORKERS,
                    "worker_id {id} exceeds MAX_NAT_HOLDER_WORKERS; \
                     replan_bindings_from_candidates must refuse the plan"
                );
                1u128.checked_shl(id).unwrap_or(0)
            }
        }
    }
}

/// #17046: persistent-NAT parameters for [`AllocRequest`]. `Some` on the
/// request IS the former `persistent_nat=true` flag: it keys the lease by
/// `permit`, authorizes at `epoch`, and expires after `timeout_ns`. `None`
/// is an ordinary (non-persistent) PAT allocation and moves neither
/// #8447 admission counter.
#[derive(Clone, Copy, Debug)]
pub(super) struct PersistentParams {
    pub(super) permit: super::source::PersistentNatPermit,
    pub(super) epoch: u64,
    pub(super) timeout_ns: u64,
}

/// #17046: the single allocation request consumed by
/// [`PortAllocator::allocate`]. Replaces the three 12-/13-argument
/// `allocate_translation*` wrappers, whose positional `u64` triples
/// (permit epoch / timeout / now) and adjacent `bool`s were guarded only
/// by comments. Field order mirrors the former argument order so every
/// migrated call site is a mechanical field-for-argument transcription.
pub(super) struct AllocRequest<'a> {
    pub(super) flow: SourceNatFlowKey,
    pub(super) family_addresses: PoolAddressFamily<'a>,
    pub(super) family_offset: usize,
    pub(super) address_persistent: bool,
    pub(super) persistent: Option<PersistentParams>,
    pub(super) now_ns: u64,
    pub(super) holder: NatHolder,
    pub(super) egress_scope: u32,
    pub(super) mint_from_zone: Option<&'a str>,
    pub(super) excluded: &'a dyn Fn(usize, u16) -> bool,
}

#[derive(Clone, Copy, Debug)]
struct LiveAllocation {
    translated: TranslatedTuple,
    persistent_key: Option<PersistentSourceKey>,
    // #2852 F7: the pool-address index this translation was claimed on, stored
    // in the record so release is O(1) — the pre-#2852 `addr_index_by_translated`
    // reverse map is gone (the occupancy bitmap is per-address, so freeing the
    // bit needs the address index, and reading it off the record avoids a map
    // lookup). For a persistent flow the authoritative index is on the lease;
    // this copy mirrors it so the non-persistent / deterministic release paths
    // are uniform.
    addr_index: usize,
    // #4559: a deterministic CGNAT block allocation. The deterministic claim
    // scans its subscriber block against the occupancy bitmap directly, so a
    // freed port becomes claimable again the moment its bit clears. #14625:
    // its port IS pushed onto the per-address recycle queue on release like
    // any other port -- the ring is bounded to one token per offset (#7174)
    // and `claim_in_block` ignores it, while a pool that later flips to
    // round-robin PAT on this reused allocator can only reach the freed
    // port through the ring. `false` for every round-robin/persistent
    // allocation.
    deterministic: bool,
    // #5269: an address-only occupancy token (port no-translation / port-less
    // source NAT). No pool PORT is consumed on the occupancy bitmap — the packet
    // keeps its own source port on the wire — so release must NOT free a port
    // bit; instead it clears the reverse-identity entry in `address_only_owners`.
    // `false` for every PAT / deterministic / persistent allocation.
    address_only: bool,
    // #6211 F2: the set of WORKERS holding this reservation, one bit per
    // `worker_id` (see `NatHolder` / `MAX_NAT_HOLDER_WORKERS`). An HA-synced
    // session is pushed to EVERY worker's session table while the source-NAT
    // allocator is a single shared `Arc`, so N workers reserve the same
    // `(flow, translated)` and each releases it independently — the reap, the
    // fanned-out `DeleteSynced`, and the alias purge all run per worker.
    //
    // Before this field the N reserves collapsed into one record (`reserve_flow`
    // returns `true` and does nothing when the flow already holds this exact
    // tuple) and the FIRST release freed the port while the other N-1 workers
    // still held the session and forwarded through it. That is the steady state
    // after any failover carrying a synced SNAT session older than the
    // inactivity timeout: the active's periodic `UpsertSynced` refresh stops,
    // RSS lands the traffic on exactly one worker, and the other N-1 replicas
    // idle out with nothing refreshing them.
    //
    // `0` means "untracked" — a LOCAL allocation, which by construction has a
    // single holder (RSS steers a 5-tuple to one worker) — and keeps the
    // pre-#6211-F2 contract: the first release frees. A non-zero mask frees only
    // when the LAST holder's bit clears.
    //
    // A bitmask rather than a counter because `reserve_flow`'s idempotent early
    // return is BOTH where workers 2..N first land AND the path every refresh
    // from an ALREADY-holding worker takes (each HA session-sync reconnect, each
    // periodic re-`UpsertSynced`). OR is idempotent there; increment is not, and
    // would inflate without bound and never drain to zero.
    //
    // `u128` keeps `LiveAllocation` `Copy` (both read paths use `.copied()`), so
    // no `Vec`/`HashSet` allocation enters the per-flow record.
    // A local flow adopting an imported idle lease or joining an imported
    // active lease is tentative until admitted. Carry its local timeout on the
    // per-flow record; only ordinary `release_flow` completion promotes.
    promotion_timeout_ns: Option<u64>,
    holders: u128,
}

// #15956: Phase-2 sharding lives in flows.rs (`LiveFlowMap`):
// 16 shards of the former `live_by_flow`, exact `live_flow_count`
// cap accounting, shard->live lock order. See that file.

/// #5269: reverse-identity ownership key for an address-only (port
/// no-translation / port-less) source-NAT translation. The reverse conntrack
/// demux keys a reply on (protocol, translated source IP, translated source
/// port, remote IP, remote port); two forward flows that would produce the SAME
/// reverse identity cannot coexist because their replies are indistinguishable,
/// so the allocator grants each identity to exactly ONE flow and denies a
/// genuinely-colliding second flow as exhaustion. `translated_port` is the
/// PRESERVED source port for a port-bearing protocol, or 0 for a port-less
/// protocol (GRE/ESP/AH/...). This is the address-only analogue of the PAT
/// occupancy bit: PAT keeps `(pool_addr, port)` unique by handing out a fresh
/// port; address-only cannot move the port, so it enforces uniqueness on the
/// full reverse identity instead.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) struct AddressOnlyReverseKey {
    pub(super) protocol: u8,
    pub(super) translated_ip: IpAddr,
    pub(super) translated_port: u16,
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
}

impl AddressOnlyReverseKey {
    /// #6751: the ONE construction the interface-mode registry uses, for the
    /// occupancy CHECK, the record INSERT and the synced RESERVE alike.
    ///
    /// These three must agree by construction, not by three literals that
    /// happen to match. A check keyed differently from its insert is invisible
    /// to every behavioural test: the check finds nothing, so every flow
    /// preserves and every mint "succeeds" — which is exactly the pre-#6751
    /// behaviour the fix exists to remove, restored silently. (The pool-mode
    /// paths keep their own inline literals; they are the shipped shape, and
    /// re-keying them is not this change's business. The end-to-end release
    /// test binds this constructor against what
    /// `unlink_live_allocation_locked` removes.)
    pub(super) fn for_flow(
        flow: &SourceNatFlowKey,
        translated_ip: IpAddr,
        translated_port: u16,
    ) -> Self {
        Self {
            protocol: flow.protocol,
            translated_ip,
            translated_port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
        }
    }
}
/// Prefixes of reverse identities for wildcard imported-lease scopes. The
/// aggregate indexes below keep host/any-remote checks O(1), not a scan over
/// every live flow for each received lease.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct ReverseIdentityBaseKey {
    protocol: u8,
    translated_ip: IpAddr,
    translated_port: u16,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct ReverseIdentityHostKey {
    base: ReverseIdentityBaseKey,
    dst_ip: IpAddr,
}

/// Scoped keys for idle address-only persistent leases. Unlike live reverse
/// owners, these leases have no flow entry to index them.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(super) enum PersistentAddressOnlyOwnerKey {
    Exact(AddressOnlyReverseKey),
    Host(ReverseIdentityHostKey),
    HostWildcard(ReverseIdentityHostKey),
    Any(ReverseIdentityBaseKey),
    AnyWildcard(ReverseIdentityBaseKey),
}

/// #10190: the exact PAT reverse identity used by the same-allocator
/// cross-domain guard. PAT allocations normally need only the per-address
/// bitmap, but an address-only reservation keys the full reverse tuple
/// (including the remote endpoint). Keeping this compact key in a count map
/// gives address-only admission an O(1) PAT-domain lookup without changing
/// the bitmap's address/port semantics.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct PatReverseKey {
    protocol: u8,
    translated_ip: IpAddr,
    translated_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

impl PatReverseKey {
    fn for_flow(flow: &SourceNatFlowKey, translated: TranslatedTuple) -> Self {
        Self {
            protocol: flow.protocol,
            translated_ip: translated.ip,
            translated_port: translated.port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
        }
    }
}

/// Owns the PAT reverse-identity map and its broad-scope count indexes.
/// Keeping these maps behind one mutation seam prevents an exact owner from
/// being published without also updating the prefix indexes used by imports.
#[derive(Debug, Default)]
struct ReverseIdentityIndex {
    pat_owners: FxHashMap<PatReverseKey, u32>,
    pat_owners_by_base: FxHashMap<ReverseIdentityBaseKey, u32>,
    pat_owners_by_host: FxHashMap<ReverseIdentityHostKey, u32>,
}

impl ReverseIdentityIndex {
    fn publish_pat(&mut self, flow: &SourceNatFlowKey, translated: TranslatedTuple) {
        let key = PatReverseKey::for_flow(flow, translated);
        let count = self.pat_owners.entry(key).or_insert(0);
        *count = count.saturating_add(1);

        let base = ReverseIdentityBaseKey {
            protocol: key.protocol,
            translated_ip: key.translated_ip,
            translated_port: key.translated_port,
        };
        let host = ReverseIdentityHostKey {
            base,
            dst_ip: key.dst_ip,
        };
        let count = self.pat_owners_by_base.entry(base).or_insert(0);
        *count = count.saturating_add(1);
        let count = self.pat_owners_by_host.entry(host).or_insert(0);
        *count = count.saturating_add(1);
    }

    fn retract_pat(&mut self, flow: &SourceNatFlowKey, translated: TranslatedTuple) {
        let key = PatReverseKey::for_flow(flow, translated);
        let Some(count) = self.pat_owners.get_mut(&key) else {
            return;
        };
        if *count <= 1 {
            self.pat_owners.remove(&key);
        } else {
            *count -= 1;
        }

        let base = ReverseIdentityBaseKey {
            protocol: key.protocol,
            translated_ip: key.translated_ip,
            translated_port: key.translated_port,
        };
        let host = ReverseIdentityHostKey {
            base,
            dst_ip: key.dst_ip,
        };
        if let Some(count) = self.pat_owners_by_base.get_mut(&base) {
            if *count <= 1 {
                self.pat_owners_by_base.remove(&base);
            } else {
                *count -= 1;
            }
        }
        if let Some(count) = self.pat_owners_by_host.get_mut(&host) {
            if *count <= 1 {
                self.pat_owners_by_host.remove(&host);
            } else {
                *count -= 1;
            }
        }
    }

    fn owns_wire_identity(&self, flow: &SourceNatFlowKey, translated: TranslatedTuple) -> bool {
        self.pat_owners
            .contains_key(&PatReverseKey::for_flow(flow, translated))
    }

    fn owns_exact(&self, key: &PatReverseKey) -> bool {
        self.pat_owners.contains_key(key)
    }

    fn owns_host(&self, key: &ReverseIdentityHostKey) -> bool {
        self.pat_owners_by_host.contains_key(key)
    }

    fn owns_base(&self, key: &ReverseIdentityBaseKey) -> bool {
        self.pat_owners_by_base.contains_key(key)
    }
}

/// #17099: single source for the NAT64 BIB idle-lease lifetime. Every
/// NAT64 mint/reserve/import site uses this constant instead of spelling
/// the 300-second literal, so the value cannot drift between arms.
pub(crate) const DETERMINISTIC_NAT64_BIB_TIMEOUT_NS: u64 = 300 * NS_PER_SEC;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PersistentLease {
    pub(super) translated: TranslatedTuple,
    /// Unique in-process identity for this lease incarnation. Zero is reserved
    /// for newly constructed records until `insert_persistent_lease` stamps it.
    pub(super) incarnation: u64,
    pub(super) addr_index: usize,
    pub(super) expires_at_ns: u64,
    pub(super) timeout_ns: u64,
    pub(super) active_flows: u32,
    // #15111: inbound persistent sessions holding this binding. Counted
    // separately from active_flows (outbound/synced joins) so lease expiry,
    // GC, clear, and lookup treat an inbound-only binding as live. Released
    // via release_persistent_inbound when the inbound session tears down.
    pub(super) inbound_flows: u32,
    pub(super) completed_flows: u64,
    // Rollback needs per-activation completion state, not a comparison
    // against lifetime completion counters. The latter can saturate over
    // long-lived persistent leases and make a fresh completion invisible.
    pub(super) activation_saw_completion: bool,
    pub(super) activation_previous_expires_at_ns: u64,
    pub(super) activation_had_previous_lease: bool,
    // #10789-F4/B2: the timeout snapshot restores the pre-activation idle
    // state if no flow completed. Locally-owned 0 -> 1 reuse applies the
    // current local timeout immediately; imported leases defer timeout changes
    // until a local completion consumes their per-flow promotion marker.
    pub(super) activation_previous_timeout_ns: u64,
    // #6041: an ADDRESS-ONLY persistent lease (`persistent-nat` + `port
    // no-translation` / a port-less protocol). It pins a public ADDRESS across
    // the permit scope but consumes NO pool port — `translated.port` carries the
    // FIRST flow's preserved source port for status/debug only and is never a
    // bit on the occupancy bitmap. So every lease teardown site
    // (`reuse_existing_lease_locked` expired, `rollback_flow` remove-lease,
    // `reclaim_expired_lease_locked` GC) MUST skip `free_translated_port` when
    // this is set — there is no port bit to free, and freeing address `port`
    // would clear a DIFFERENT flow's PAT bit that happens to share the offset.
    // Per-flow reverse-identity collision ownership (#5269) is still tracked in
    // `address_only_owners`, minted/cleared per flow, independent of the lease.
    // `false` for every port-translating PAT lease (unchanged behaviour).
    pub(super) deterministic: bool,
    pub(super) deterministic_identity:
        Option<super::idle_lease_sync_8121::DeterministicPortedIdentity>,
    pub(super) address_only: bool,
    // #10789-F4: local-only origin tag. `true` when this lease was (re)built
    // from something the PEER sent — a synced session (#7360/#8132) or an
    // imported idle lease (#8121) — rather than minted by a local lookup.
    // The idle-lease export skips imported leases, which is what makes the
    // channel one-directional per lease: without it a standby re-pushes what
    // it learned and the set echoes forever, each bounce re-deriving the
    // remaining lifetime from the receiver's clock so a lease is refreshed
    // indefinitely instead of expiring — and a lease the originator retired
    // is reinstalled by the next re-push (retire-resurrection).
    //
    // NEVER serialized: this struct has no `Serialize` derive and neither
    // `IdleLeaseRecord` nor `DisplayLeaseRecord` carries the bit (wire
    // unchanged, no new record type), so a receiver always marks what it
    // installs rather than trusting a carried value. Local reserves for
    // imported idle (0 -> 1) or active (N -> N+1) leases keep this bit set and
    // carry a per-flow marker. Only successful final-holder `release_flow`
    // completion promotes the lease; `rollback_flow`, synced joins, worker
    // retirement, and stale-tuple eviction do not. This prevents tentative
    // reserves from echoing peer-owned state.
    // Rolling upgrade (accepted window): a peer on an older helper has no
    // filter and echoes our pushes back until it upgrades. The echo heals on
    // full upgrade; inside the window an old peer can still reinstall a lease
    // this node retired — no tombstone exists, the window closes by upgrade.
    pub(super) imported: bool,
    // #10784: sticky revocation marker for a lease the operator cleared while
    // it still held live flows. The time-bounded fence against IMPORTS lives
    // in `revoked_persistent` (per-key, survives lease absence); THIS bit
    // lives on the retained draining shell and answers a different question:
    // "may local flows rejoin / display / export this record?" Never — a
    // revoked shell drains and dies, while a replacement minted after the
    // clear (`revoked: false`) is live truth even while the key's preserved
    // tombstone still fences imports. Set only by `clear_persistent_leases`;
    // every mint/install path constructs `false`.
    pub(super) revoked: bool,
}

/// Incumbent reservation metadata needed to undo a rejected synced replacement.
/// The holder mask is carried only so the caller can replay it through the
/// worker-specific reserve path; `restore_metadata` deliberately never writes it.
#[derive(Clone, Debug)]
pub(crate) struct SourceNatReservationSnapshot {
    allocator: PortAllocator,
    flow: SourceNatFlowKey,
    translated: TranslatedTuple,
    persistent_key: Option<PersistentSourceKey>,
    promotion_timeout_ns: Option<u64>,
    holders: u128,
    persistent_lease: Option<PersistentLease>,
    // #15145: the complete incumbent record, captured so a post-reserve
    // refusal (peer/static/interface ownership) can restore it exactly
    // instead of leaving the flow with no reservation.
    allocation: Option<LiveAllocation>,
    addr_index: usize,
    deterministic: bool,
    address_only: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PersistentLeaseDebugState {
    pub(crate) translated: TranslatedTuple,
    pub(crate) incarnation: u64,
    pub(crate) addr_index: usize,
    pub(crate) expires_at_ns: u64,
    pub(crate) timeout_ns: u64,
    pub(crate) active_flows: u32,
    pub(crate) inbound_flows: u32,
    pub(crate) completed_flows: u64,
    pub(crate) activation_saw_completion: bool,
    pub(crate) activation_previous_expires_at_ns: u64,
    pub(crate) activation_had_previous_lease: bool,
    pub(crate) activation_previous_timeout_ns: u64,
    pub(crate) address_only: bool,
    pub(crate) deterministic: bool,
    pub(crate) deterministic_identity:
        Option<super::idle_lease_sync_8121::DeterministicPortedIdentity>,
    pub(crate) imported: bool,
}

#[derive(Debug, Default)]
pub(super) struct PortAllocatorLiveState {
    // #15956: `live_by_flow` moved to `PortAllocatorShared::flows`
    // (16 Mutex shards). This struct retains lease/ownership state.
    pub(super) persistent_by_source: FxHashMap<PersistentSourceKey, PersistentLease>,
    /// #16013: number of leases (live or idle-retained) charged to each
    /// `(src_ip, routing_scope)` source in this allocator. Maintained ONLY
    /// by `insert_persistent_lease` / `remove_persistent_lease`, the single
    /// mutation seam for `persistent_by_source`, so every mint, import,
    /// carry and removal stays in step. Bounded by the lease table itself:
    /// one entry per distinct source holding at least one lease.
    pub(super) persistent_leases_by_source: FxHashMap<(std::net::IpAddr, u32), usize>,
    pub(super) lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
    pub(super) persistent_permissions: FxHashMap<PersistentSourceKey, PersistentPermissions>,
    pub(super) persistent_by_translated:
        FxHashMap<ReverseIdentityBaseKey, FxHashSet<PersistentSourceKey>>,
    pub(super) lease_expirations_by_addr: Vec<BTreeSet<(u64, PersistentSourceKey)>>,
    // #10784: time-bounded per-key fence for cleared lease imports. Entries
    // survive local replacement until their deadline; the live marker is also
    // used to keep revoked draining shells out of normal reuse/export.
    pub(super) revoked_persistent: BTreeMap<PersistentSourceKey, u64>,
    // Per-allocator barrier for pre-clear records whose key was not installed
    // when clear ran. The Go cluster envelope carries durable generations;
    // only its validated import path bypasses this generation-less helper
    // barrier, while the per-key markers remain authoritative.
    last_persistent_nat_clear_ns: Option<u64>,
    // #5269: address-only occupancy tokens — the translated reverse identity of a
    // `port no-translation` / port-less flow mapped to its owning FORWARD flow.
    // Populated by `reserve_address_only` (which denies a second flow that would
    // claim an already-owned identity) and cleared by `release_flow` /
    // `rollback_flow` for an `address_only` `LiveAllocation`. Distinct from the
    // per-address occupancy bitmap, which tracks PAT port ownership.
    address_only_owners: FxHashMap<AddressOnlyReverseKey, SourceNatFlowKey>,
    // #10190 / #11475: exact PAT reverse identities and their broad-scope
    // counts are one typed owner so publication and retraction cannot update
    // only part of the index.
    reverse_identities: ReverseIdentityIndex,
    // #11475: address-only prefix indexes support broad remote scopes without
    // scanning the exact owner map.
    address_only_owner_counts_by_base: FxHashMap<ReverseIdentityBaseKey, u32>,
    address_only_owner_counts_by_host: FxHashMap<ReverseIdentityHostKey, u32>,
    /// #11496: idle address-only leases remain reverse-identity owners between
    /// flow releases and expiry, so peer import checks need their own index.
    persistent_address_only_owner_counts: FxHashMap<PersistentAddressOnlyOwnerKey, u32>,
    gc_counter: u32,
}

impl PortAllocatorLiveState {
    fn new(addr_count: usize) -> Self {
        Self {
            lease_expirations_by_addr: vec![BTreeSet::new(); addr_count],
            ..Self::default()
        }
    }

    /// #16713 test seam: a full `persistent_by_source` iteration is
    /// starting. Bumps the thread-local scan counter.
    #[cfg(test)]
    fn note_persistent_by_source_scan(&self) {
        PERSISTENT_BY_SOURCE_SCANS.with(|c| c.set(c.get() + 1));
    }

    pub(super) fn increment_persistent_address_only_owner(
        &mut self,
        key: PersistentAddressOnlyOwnerKey,
    ) {
        let count = self
            .persistent_address_only_owner_counts
            .entry(key)
            .or_insert(0);
        *count = count.saturating_add(1);
    }

    fn decrement_persistent_address_only_owner(&mut self, key: PersistentAddressOnlyOwnerKey) {
        if let Some(count) = self.persistent_address_only_owner_counts.get_mut(&key) {
            if *count <= 1 {
                self.persistent_address_only_owner_counts.remove(&key);
            } else {
                *count -= 1;
            }
        }
    }

    pub(super) fn persistent_address_only_owner_keys(
        &self,
        key: &PersistentSourceKey,
        lease: &PersistentLease,
    ) -> Vec<PersistentAddressOnlyOwnerKey> {
        if !lease.address_only || lease.revoked {
            return Vec::new();
        }
        // #14322: derive from stored permission buckets; key.remote is always None.
        let base = ReverseIdentityBaseKey {
            protocol: key.protocol,
            translated_ip: lease.translated.ip,
            translated_port: lease.translated.port,
        };
        let mut out = vec![PersistentAddressOnlyOwnerKey::Any(base)];
        let Some(permissions) = self.persistent_permissions.get(key) else {
            return out;
        };
        let mut any_remote = false;
        let mut remotes = std::collections::BTreeSet::new();
        for scope in permissions.scopes.values() {
            any_remote |= scope.any_remote;
            remotes.extend(scope.remotes.iter().copied());
        }
        if any_remote {
            out.push(PersistentAddressOnlyOwnerKey::AnyWildcard(base));
        }
        for (dst_ip, dst_port) in remotes {
            let host = ReverseIdentityHostKey { base, dst_ip };
            out.push(PersistentAddressOnlyOwnerKey::Host(host));
            if dst_port == 0 {
                out.push(PersistentAddressOnlyOwnerKey::HostWildcard(host));
            } else {
                out.push(PersistentAddressOnlyOwnerKey::Exact(
                    AddressOnlyReverseKey {
                        protocol: key.protocol,
                        translated_ip: lease.translated.ip,
                        translated_port: lease.translated.port,
                        dst_ip,
                        dst_port,
                    },
                ));
            }
        }
        out.sort_by_key(|k| match k {
            PersistentAddressOnlyOwnerKey::Exact(a) => {
                (0, a.translated_ip, a.translated_port, a.dst_ip, a.dst_port)
            }
            PersistentAddressOnlyOwnerKey::Host(h) => {
                (1, h.base.translated_ip, h.base.translated_port, h.dst_ip, 0)
            }
            PersistentAddressOnlyOwnerKey::HostWildcard(h) => {
                (2, h.base.translated_ip, h.base.translated_port, h.dst_ip, 0)
            }
            PersistentAddressOnlyOwnerKey::Any(b) => (
                3,
                b.translated_ip,
                b.translated_port,
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                0,
            ),
            PersistentAddressOnlyOwnerKey::AnyWildcard(b) => (
                4,
                b.translated_ip,
                b.translated_port,
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                0,
            ),
        });
        out.dedup();
        out
    }
    fn add_persistent_address_only_owner(
        &mut self,
        key: PersistentSourceKey,
        lease: PersistentLease,
    ) {
        for owner_key in self.persistent_address_only_owner_keys(&key, &lease) {
            self.increment_persistent_address_only_owner(owner_key);
        }
    }
    fn remove_persistent_address_only_owner(
        &mut self,
        key: PersistentSourceKey,
        lease: PersistentLease,
    ) {
        for owner_key in self.persistent_address_only_owner_keys(&key, &lease) {
            self.decrement_persistent_address_only_owner(owner_key);
        }
    }

    fn remove_persistent_reverse_owner(
        &mut self,
        base: ReverseIdentityBaseKey,
        key: &PersistentSourceKey,
    ) {
        if let Some(owners) = self.persistent_by_translated.get_mut(&base) {
            owners.remove(key);
            if owners.is_empty() {
                self.persistent_by_translated.remove(&base);
            }
        }
    }

    /// #16013: leases (live or idle-retained) charged to one source.
    pub(super) fn persistent_lease_count_for_source(
        &self,
        src_ip: std::net::IpAddr,
        routing_scope: u32,
    ) -> usize {
        self.persistent_leases_by_source
            .get(&(src_ip, routing_scope))
            .copied()
            .unwrap_or(0)
    }

    /// #16013: refuse a NEW lease key for `key`'s source when that source is
    /// at its per-source ceiling. Re-joining an EXISTING key never refuses;
    /// expired-but-unreclaimed keys still refuse until reclaimed (the caller
    /// runs its pressure-GC pass first). Call only under the `live` guard.
    pub(super) fn persistent_source_at_lease_cap(&self, key: &PersistentSourceKey) -> bool {
        !self.persistent_by_source.contains_key(key)
            && self.persistent_lease_count_for_source(key.src_ip, key.routing_scope)
                >= MAX_PERSISTENT_LEASES_PER_SOURCE
    }

    pub(super) fn insert_persistent_lease(
        &mut self,
        key: PersistentSourceKey,
        mut lease: PersistentLease,
    ) -> Option<PersistentLease> {

        // A copied lease (e.g. reservation rollback snapshot) retains its
        // identity. Freshly built/imported records receive a new one here.
        if lease.incarnation == 0 {
            lease.incarnation = next_persistent_lease_incarnation();
        }
        let previous = self.persistent_by_source.insert(key, lease);
        if let Some(previous) = previous {
            self.remove_persistent_address_only_owner(key, previous);
            self.persistent_permissions.remove(&key);
            self.remove_persistent_reverse_owner(
                ReverseIdentityBaseKey {
                    protocol: key.protocol,
                    translated_ip: previous.translated.ip,
                    translated_port: previous.translated.port,
                },
                &key,
            );
        } else {
            // #16013: a NEW key charges its source; replacing an existing
            // key under the same source key is count-neutral.
            *self
                .persistent_leases_by_source
                .entry((key.src_ip, key.routing_scope))
                .or_insert(0) += 1;
        }
        self.persistent_by_translated
            .entry(ReverseIdentityBaseKey {
                protocol: key.protocol,
                translated_ip: lease.translated.ip,
                translated_port: lease.translated.port,
            })
            .or_default()
            .insert(key);
        self.add_persistent_address_only_owner(key, lease);
        previous
    }

    pub(super) fn remove_persistent_lease(
        &mut self,
        key: &PersistentSourceKey,
    ) -> Option<PersistentLease> {
        let lease = self.persistent_by_source.remove(key)?;
        // #16013: release this source's charge for the removed lease.
        match self
            .persistent_leases_by_source
            .get_mut(&(key.src_ip, key.routing_scope))
        {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                self.persistent_leases_by_source
                    .remove(&(key.src_ip, key.routing_scope));
            }
            None => debug_assert!(
                false,
                "#16013: per-source lease count missing for removed lease"
            ),
        }
        self.remove_persistent_address_only_owner(*key, lease);
        self.remove_persistent_reverse_owner(
            ReverseIdentityBaseKey {
                protocol: key.protocol,
                translated_ip: lease.translated.ip,
                translated_port: lease.translated.port,
            },
            key,
        );
        self.persistent_permissions.remove(key);
        Some(lease)
    }

    fn record_persistent_permission_with_zones(
        &mut self,
        key: PersistentSourceKey,
        permit: PersistentNatPermit,
        flow: SourceNatFlowKey,
        egress_scope: u32,
        mint_from_zone: Option<&str>,
        permit_epoch: u64,
    ) -> bool {
        let lease = self.persistent_by_source.get(&key).copied();
        let before = lease
            .map(|l| self.persistent_address_only_owner_keys(&key, &l))
            .unwrap_or_default();
        let recorded = self
            .persistent_permissions
            .entry(key)
            .or_default()
            .record_with_zones(permit, flow, egress_scope, mint_from_zone, permit_epoch);
        if recorded {
            if let Some(l) = lease {
                if l.address_only && !l.revoked {
                    let after = self.persistent_address_only_owner_keys(&key, &l);
                    for owner_key in after {
                        if !before.contains(&owner_key) {
                            self.increment_persistent_address_only_owner(owner_key);
                        }
                    }
                }
            }
        }
        recorded
    }
    /// Drop expired clear fences during the cold-path lease snapshot refresh.
    /// This keeps the replay guard bounded even when no later clear occurs.
    pub(super) fn prune_expired_persistent_nat_clear_fences(&mut self, now_ns: u64) {
        self.revoked_persistent
            .retain(|_, until_ns| *until_ns > now_ns);
        if self.last_persistent_nat_clear_ns.is_some_and(|clear_ns| {
            now_ns >= clear_ns.saturating_add(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS)
        }) {
            self.last_persistent_nat_clear_ns = None;
        }
    }
    pub(super) fn persistent_nat_import_is_key_clear_fenced(
        &self,
        key: &PersistentSourceKey,
        now_ns: u64,
    ) -> bool {
        self.revoked_persistent
            .get(key)
            .is_some_and(|until_ns| *until_ns > now_ns)
    }
    pub(super) fn persistent_nat_import_is_clear_fenced(
        &self,
        key: &PersistentSourceKey,
        now_ns: u64,
    ) -> bool {
        self.persistent_nat_import_is_key_clear_fenced(key, now_ns)
            || self.last_persistent_nat_clear_ns.is_some_and(|clear_ns| {
                now_ns < clear_ns.saturating_add(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS)
            })
    }
    /// #10190: the allocator intentionally has two ownership domains:
    /// `address_only_owners` for preserved ports and the occupancy bitmap for
    /// PAT. The cross-allocator overlap guard skips peers sharing this
    /// allocator because one allocator normally is one wire-identity domain.
    /// A `no-translation` rule and a PAT rule are the exception: they share
    /// the allocator key but issue different tokens. Keep this check local to
    /// the allocator rather than widening the key — key widening would split
    /// live leases and would require a carry-over migration.
    /// Does a live flow or persistent address-only lease own this reverse tuple?
    fn address_only_owns_wire_identity(
        &self,
        flow: &SourceNatFlowKey,
        translated: TranslatedTuple,
    ) -> bool {
        self.idle_import_identity_contended(
            flow.protocol,
            translated,
            Some((flow.dst_ip, flow.dst_port)),
            false,
        )
    }
    /// #14671: is this reverse tuple held by an IDLE persistent
    /// address-only lease OTHER than `candidate_key`'s own lease? Scoped by
    /// the recorded permit grants (`PersistentPermissions::permits` over
    /// all egress scopes): an Exact grant blocks only that remote
    /// endpoint, a Host grant that host at any port, and AnyRemoteHost
    /// any remote. Live leases are excluded — their flows hold live
    /// `address_only_owners` tokens the caller checks exactly. The
    /// candidate's own lease never blocks its rejoin.
    pub(super) fn persistent_address_only_contended_except(
        &self,
        flow: &SourceNatFlowKey,
        translated: TranslatedTuple,
        candidate_key: Option<PersistentSourceKey>,
    ) -> bool {
        let base = ReverseIdentityBaseKey {
            protocol: flow.protocol,
            translated_ip: translated.ip,
            translated_port: translated.port,
        };
        #[cfg(test)]
        self.note_persistent_by_source_scan();
        self.persistent_by_source.iter().any(|(key, lease)| {
            // Only IDLE leases contend here: a live lease's flows hold live
            // address_only_owners tokens, which the caller already checks
            // with exact remote scoping. Counting live leases by their
            // (often AnyRemoteHost) grants would refuse flows to remotes
            // the live lease does not own a token for (#9131).
            if Some(*key) == candidate_key
                || !lease.address_only
                || lease.revoked
                || lease.active_flows > 0
                || lease.inbound_flows > 0
            {
                return false;
            }
            if lease.translated != translated {
                return false;
            }
            let Some(permissions) = self.persistent_permissions.get(key) else {
                return false;
            };
            permissions.permits(
                PERSISTENT_NAT_EGRESS_UNSCOPED,
                flow.dst_ip,
                flow.dst_port,
                PersistentNatPermit::AnyRemoteHost,
                0,
                0,
            )
        }) || self
            .persistent_by_translated
            .get(&base)
            .is_some_and(|keys| {
                keys.iter().any(|key| {
                    Some(*key) != candidate_key
                        && self.persistent_by_source.get(key).is_some_and(|lease| {
                            lease.address_only
                                && !lease.revoked
                                && lease.active_flows == 0
                                && lease.inbound_flows == 0
                                && lease.translated == translated
                                && !self.persistent_permissions.contains_key(key)
                        })
                })
            })
    }
    /// #11475: address-only idle imports claim no bitmap bit, so check both
    /// live ownership domains for their exact, target-host, or any-remote scope.
    pub(super) fn import_idle_address_only_contended(
        &self,
        protocol: u8,
        translated: TranslatedTuple,
        remote: Option<(IpAddr, u16)>,
    ) -> bool {
        self.idle_import_identity_contended(protocol, translated, remote, true)
    }

    /// PAT's bitmap already reports PAT-versus-PAT contention as PortBusy.
    /// This extra check mirrors local/synced PAT admission against address-only
    /// owners, which hold no bitmap bit.
    pub(super) fn import_idle_pat_address_only_contended(
        &self,
        protocol: u8,
        translated: TranslatedTuple,
        remote: Option<(IpAddr, u16)>,
    ) -> bool {
        self.idle_import_identity_contended(protocol, translated, remote, false)
    }

    fn idle_import_identity_contended(
        &self,
        protocol: u8,
        translated: TranslatedTuple,
        remote: Option<(IpAddr, u16)>,
        check_pat_owners: bool,
    ) -> bool {
        let base = ReverseIdentityBaseKey {
            protocol,
            translated_ip: translated.ip,
            translated_port: translated.port,
        };
        match remote {
            Some((dst_ip, dst_port)) if dst_port != 0 => {
                let address_key = AddressOnlyReverseKey {
                    protocol,
                    translated_ip: translated.ip,
                    translated_port: translated.port,
                    dst_ip,
                    dst_port,
                };
                let host = ReverseIdentityHostKey { base, dst_ip };
                self.address_only_owners.contains_key(&address_key)
                    || self
                        .persistent_address_only_owner_counts
                        .contains_key(&PersistentAddressOnlyOwnerKey::Exact(address_key))
                    || self
                        .persistent_address_only_owner_counts
                        .contains_key(&PersistentAddressOnlyOwnerKey::HostWildcard(host))
                    || self
                        .persistent_address_only_owner_counts
                        .contains_key(&PersistentAddressOnlyOwnerKey::AnyWildcard(base))
                    || (check_pat_owners
                        && self.reverse_identities.owns_exact(&PatReverseKey {
                            protocol,
                            translated_ip: translated.ip,
                            translated_port: translated.port,
                            dst_ip,
                            dst_port,
                        }))
            }
            Some((dst_ip, _)) => {
                let host = ReverseIdentityHostKey { base, dst_ip };
                self.address_only_owner_counts_by_host.contains_key(&host)
                    || self
                        .persistent_address_only_owner_counts
                        .contains_key(&PersistentAddressOnlyOwnerKey::Host(host))
                    || self
                        .persistent_address_only_owner_counts
                        .contains_key(&PersistentAddressOnlyOwnerKey::AnyWildcard(base))
                    || (check_pat_owners && self.reverse_identities.owns_host(&host))
            }
            None => {
                self.address_only_owner_counts_by_base.contains_key(&base)
                    || self
                        .persistent_address_only_owner_counts
                        .contains_key(&PersistentAddressOnlyOwnerKey::Any(base))
                    || (check_pat_owners && self.reverse_identities.owns_base(&base))
            }
        }
    }

    /// #16713: is the translated base owned by anyone OTHER than
    /// `candidate_key`'s idle lease, for an any-remote widening? Live
    /// owners (either live map) and other idle address-only leases
    /// count; the candidate's own counted Any key does not.
    ///
    /// The idle address-only part is answered through
    /// `persistent_by_translated` (the per-tuple key set maintained by
    /// `insert_persistent_lease` / `remove_persistent_lease`) instead
    /// of walking the whole `persistent_by_source` table: the set for
    /// one `(protocol, translated)` base holds exactly the leases that
    /// can contend for that base. This preserves the pre-index
    /// predicate term-for-term — every lease in the set has
    /// `translated == translated` by construction of the index, and
    /// the remaining filters (`address_only`, `!revoked`, idle) are
    /// re-checked per owner — so `persistent_address_only_owner_counts`
    /// (which is keyed per remote scope, not per base) could not
    /// answer this base question alone.
    pub(super) fn idle_merge_any_contended_by_other(
        &self,
        protocol: u8,
        translated: TranslatedTuple,
        candidate_key: &PersistentSourceKey,
    ) -> bool {
        let base = ReverseIdentityBaseKey {
            protocol,
            translated_ip: translated.ip,
            translated_port: translated.port,
        };
        if self.address_only_owner_counts_by_base.contains_key(&base)
            || self.reverse_identities.owns_base(&base)
        {
            return true;
        }
        // The candidate's own counted `Any` key would self-hit, so the
        // counted index alone cannot answer "by OTHER". The
        // `persistent_address_only_owner_counts` map is keyed per
        // remote scope (Any/Host/Exact variants), not per base, so it
        // cannot be consulted for a base-scoped "other owner" question
        // without distinguishing the candidate's contribution. Walking
        // the small per-base owner set from `persistent_by_translated`
        // and excluding `candidate_key` preserves the original
        // semantics exactly.
        let Some(owners) = self.persistent_by_translated.get(&base) else {
            return false;
        };
        #[cfg(test)]
        self.note_persistent_by_source_scan();
        owners.iter().any(|k| {
            k != candidate_key
                && self.persistent_by_source.get(k).is_some_and(|l| {
                    l.address_only
                        && !l.revoked
                        && l.active_flows == 0
                        && l.inbound_flows == 0
                        && l.translated == translated
                })
        })
    }

    /// #16713: does an IDLE PAT lease (address_only == false) hold
    /// `translated` with a grant covering `remote` (or any remote when
    /// `remote` is None)? An idle PAT lease keeps its occupancy bit
    /// and its permission grants until expiry — exactly the identity a
    /// fresh PAT import refuses via the bitmap claim — but it has no
    /// live PAT owner count and no address-only owner keys, so
    /// idle_import_identity_contended cannot see it. The merge path
    /// must refuse the same grant overlap the fresh path would.
    /// `candidate_key`'s own lease never contends.
    ///
    /// Answered through `persistent_by_translated`: the per-tuple key
    /// set for this base holds exactly the leases whose `translated`
    /// equals `translated` (by construction of the index), so the
    /// per-owner predicate below is term-for-term the pre-index one
    /// with the `lease.translated != translated` check discharged by
    /// the index lookup.
    pub(super) fn idle_pat_lease_covers(
        &self,
        translated: TranslatedTuple,
        candidate_key: &PersistentSourceKey,
        remote: Option<(IpAddr, u16)>,
        protocol: u8,
    ) -> bool {
        let base = ReverseIdentityBaseKey {
            protocol,
            translated_ip: translated.ip,
            translated_port: translated.port,
        };
        let Some(owners) = self.persistent_by_translated.get(&base) else {
            return false;
        };
        #[cfg(test)]
        self.note_persistent_by_source_scan();
        owners.iter().any(|k| {
            if k == candidate_key {
                return false;
            }
            let Some(lease) = self.persistent_by_source.get(k) else {
                return false;
            };
            if lease.address_only
                || lease.revoked
                || lease.active_flows != 0
                || lease.inbound_flows != 0
                || lease.translated != translated
            {
                return false;
            }
            let Some(permissions) = self.persistent_permissions.get(k) else {
                // No grants recorded: a PAT lease without permission
                // buckets still owns the tuple itself (bitmap bit);
                // treat it as covering every remote for merge safety.
                return true;
            };
            match remote {
                None => true,
                Some((dst_ip, dst_port)) => permissions.permits(
                    PERSISTENT_NAT_EGRESS_UNSCOPED,
                    dst_ip,
                    dst_port,
                    PersistentNatPermit::AnyRemoteHost,
                    0,
                    0,
                ),
            }
        })
    }

    fn add_address_only_owner_count(
        &mut self,
        protocol: u8,
        translated_ip: IpAddr,
        translated_port: u16,
        dst_ip: IpAddr,
    ) {
        let base = ReverseIdentityBaseKey {
            protocol,
            translated_ip,
            translated_port,
        };
        let host = ReverseIdentityHostKey { base, dst_ip };
        let count = self
            .address_only_owner_counts_by_base
            .entry(base)
            .or_insert(0);
        *count = count.saturating_add(1);
        let count = self
            .address_only_owner_counts_by_host
            .entry(host)
            .or_insert(0);
        *count = count.saturating_add(1);
    }

    fn remove_address_only_owner_count(
        &mut self,
        protocol: u8,
        translated_ip: IpAddr,
        translated_port: u16,
        dst_ip: IpAddr,
    ) {
        let base = ReverseIdentityBaseKey {
            protocol,
            translated_ip,
            translated_port,
        };
        let host = ReverseIdentityHostKey { base, dst_ip };
        if let Some(count) = self.address_only_owner_counts_by_base.get_mut(&base) {
            if *count <= 1 {
                self.address_only_owner_counts_by_base.remove(&base);
            } else {
                *count -= 1;
            }
        }
        if let Some(count) = self.address_only_owner_counts_by_host.get_mut(&host) {
            if *count <= 1 {
                self.address_only_owner_counts_by_host.remove(&host);
            } else {
                *count -= 1;
            }
        }
    }

    fn insert_address_only_owner(&mut self, key: AddressOnlyReverseKey, flow: SourceNatFlowKey) {
        if self.address_only_owners.insert(key, flow).is_none() {
            self.add_address_only_owner_count(
                key.protocol,
                key.translated_ip,
                key.translated_port,
                key.dst_ip,
            );
        }
    }

    fn remove_address_only_owner(&mut self, key: &AddressOnlyReverseKey) {
        if self.address_only_owners.remove(key).is_some() {
            self.remove_address_only_owner_count(
                key.protocol,
                key.translated_ip,
                key.translated_port,
                key.dst_ip,
            );
        }
    }

    fn record_pat_owner(&mut self, flow: &SourceNatFlowKey, translated: TranslatedTuple) {
        self.reverse_identities.publish_pat(flow, translated);
    }

    fn remove_pat_owner(&mut self, flow: &SourceNatFlowKey, translated: TranslatedTuple) {
        self.reverse_identities.retract_pat(flow, translated);
    }

    /// #10190: O(1) lookup for a PAT owner of the exact reverse wire
    /// identity an address-only flow would preserve. The destination endpoint
    /// remains part of the key, so another remote is admissible.
    fn pat_owns_wire_identity(&self, flow: &SourceNatFlowKey, translated: TranslatedTuple) -> bool {
        self.reverse_identities.owns_wire_identity(flow, translated)
    }
}

/// Run bounded lease-expiration GC every N release_flow calls.
const GC_PERIOD: u32 = 10;
pub(super) const ALLOCATION_GC_BUDGET: usize = 8;
const RELEASE_GC_BUDGET: usize = 64;
const PRESSURE_GC_BUDGET: usize = 64;
/// #4676: leases reclaimed per short `live` critical section by the chunked
/// opportunistic GC (`gc_expired_chunked`). The sweep drops the alloc mutex
/// and frees the reclaimed ports on the lock-free occupancy bitmap between
/// chunks, so a concurrent `allocate_translation` map-insert is not blocked
/// for the full sweep. Sized to `ALLOCATION_GC_BUDGET` so the hot-path amortized
/// GC (budget 8) is a single chunk (no extra lock churn) while the larger
/// release/idle budgets (64) yield the mutex several times.
const GC_CHUNK: usize = 8;

/// #9902 F-026: process-global allocator-instance counter. Each
/// `PortAllocatorShared` takes the next id at construction; the id travels
/// with the status row so the control plane can tell a rebuilt allocator
/// (fresh zeroed counters) from the one it baselined. 0 is never assigned —
/// it means "no id reported" (a helper older than this field).
///
/// Monotonic `fetch_add`, never reused: an id identifies one counter instance
/// for the helper's lifetime. Tests assert only distinctness/equality of ids
/// from constructions they perform themselves, never absolute values, so
/// parallel `cargo test` threads cannot flake on the shared sequence (#6819).
static NEXT_ALLOCATOR_ID: AtomicU64 = AtomicU64::new(1);

/// In-process lease-incarnation identity, never serialized. A stale session
/// hold must not release a later lease that reused its `PersistentSourceKey`.
static NEXT_PERSISTENT_LEASE_INCARNATION: AtomicU64 = AtomicU64::new(1);

fn next_persistent_lease_incarnation() -> u64 {
    let incarnation = NEXT_PERSISTENT_LEASE_INCARNATION.fetch_add(1, Ordering::Relaxed);
    if incarnation == 0 {
        NEXT_PERSISTENT_LEASE_INCARNATION.fetch_add(1, Ordering::Relaxed)
    } else {
        incarnation
    }
}

fn next_allocator_id() -> u64 {
    NEXT_ALLOCATOR_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug)]
struct PortAllocatorShared {
    /// #9902 F-026: this shared state's instance id (see `NEXT_ALLOCATOR_ID`).
    /// Immutable after construction; `Clone` shares the `Arc`, so a reused
    /// allocator keeps its id WITH its counters (comparable), while every
    /// fresh build — reconcile, runtime refresh, disarmed refresh, reseed-new —
    /// mints a new one (rebaseline). Echoed per pool row in the status.
    allocator_id: u64,
    /// One atomic counter per pool address, used for the stateless round-robin
    /// `try_next_port` (address-only / `port no-translation` paths). Separate
    /// from `occupancy` (which tracks flow-keyed pool-mode PAT allocation).
    counters: Vec<AtomicU32>,
    /// Index for IPv4 round-robin address selection.
    addr_counter_v4: AtomicU32,
    /// Index for IPv6 round-robin address selection.
    addr_counter_v6: AtomicU32,
    /// #2852 Phase 1: lock-free per-address occupancy bitmap + recycle ring.
    /// One entry per pool address; the port claim/free run WITHOUT the global
    /// `live` mutex.
    occupancy: Vec<AddressOccupancy>,
    // #15956: sharded live-flow map (flows.rs, Mutex shards).
    flows: flows::LiveFlowMap,
    live: RwLock<PortAllocatorLiveState>,
    /// FOLD (#16350 fold-2): set when the most recent (per-allocator,
    /// racy best-effort) claim probe skipped at least one excluded
    /// candidate. Lets the non-persistent caller report
    /// PoolPeerAddressOverlap instead of AllocatorExhausted when the
    /// probe advanced past a peer-owned port into exhaustion. Reset at
    /// the start of every allocate_translation*_inner call.
    probe_excluded_hit: std::sync::atomic::AtomicBool,
    allocations_total: AtomicU64,
    reuses_total: AtomicU64,
    exhaustion_total: AtomicU64,
    /// #11496: idle-lease imports refused at the persistent-table capacity.
    idle_lease_import_capacity_total: AtomicU64,
    // #8447: the persistent-NAT ADMISSION pair. Both arms are counted, never
    // just the failure: a lone "declined" counter reading zero is equally
    // consistent with "nothing was declined" and with "this path never ran",
    // and those are the two answers the question is between. A zero on
    // `declined` is only informative next to a non-zero on `admitted`.
    persistent_admitted_total: AtomicU64,
    persistent_declined_total: AtomicU64,
    /// #4800/#17036: production lock acquisitions, split by lock domain
    /// since #15956. `flow_shard_lock_*` counts counted flow-shard mutex
    /// acquisitions (`lock_flow_shard_counted`); `live_write_lock_*`
    /// counts `RwLock<PortAllocatorLiveState>` write acquisitions
    /// (`lock_live()` plus the non-persistent fast path's counted
    /// `try_write`, including a contended try that falls back). Together
    /// they give per-domain contention RATIOS: a raw acquisition rate
    /// says nothing without its denominator, and mixing the 16-way
    /// sharded mutex with the global write guard made the ratio
    /// uninterpretable. Read guards and uncounted `get_mut_shard` sites
    /// are deliberately NOT counted, so neither split pair is a total
    /// of every lock acquisition.
    ///
    /// Counted helpers try-lock first — the LOCK on the uncontended
    /// path costs exactly one CAS, the same as `lock()` did. It is not
    /// free, though: the acquisition counter is bumped unconditionally,
    /// so an uncontended acquisition is 2 relaxed atomic RMWs where it
    /// used to be 1. The contended path pays one further relaxed
    /// increment on top of a block that was already going to happen.
    ///
    /// Deliberately NOT counted: `snapshot()` (the ~1s status poll that
    /// READS these counters — the observer must not appear in its own
    /// observation) and the `debug_*` test/diagnostic accessors.
    /// The legacy `live_lock_*` snapshot totals are the documented sum
    /// of these two domains, kept for one release (#17036).
    flow_shard_lock_acquisitions: AtomicU64,
    flow_shard_lock_contended: AtomicU64,
    live_write_lock_acquisitions: AtomicU64,
    live_write_lock_contended: AtomicU64,
    /// #16017: current permit epoch for this allocator (starts at 1; 0 = legacy/no-rule epoch).
    persistent_permit_epoch: AtomicU64,
    max_tracked_flows: usize,
    /// #4676 test seam: counts how many times `gc_expired_chunked` acquired the
    /// `live` mutex. A std `Mutex` is non-reentrant, so N > 1 acquisitions over
    /// a single sweep is proof the sweep RELEASED the lock between chunks (you
    /// cannot re-acquire a lock you still hold). Reverting the chunking to a
    /// single critical section collapses this to 1.
    #[cfg(test)]
    gc_lock_acquisitions: AtomicUsize,
}

/// Bounded pool-mode SNAT allocator.
///
/// Address selection uses atomics for stable round-robin/sticky starting
/// points; port ownership is a lock-free per-address occupancy bitmap so ports
/// are not reused while sessions are alive, and only the flow map + persistent
/// leases are guarded by the per-pool mutex (#2852 Phase 1). Persistent NAT
/// leases are keyed by source tuple and retained until their inactivity timeout
/// after the last live flow releases them.
#[derive(Clone, Debug)]
pub(crate) struct PortAllocator {
    shared: Arc<PortAllocatorShared>,
    pub(crate) port_low: u16,
    pub(crate) port_high: u16,
}
/// A live-state guard that atomically captures one flow's complete incumbent
/// reservation before a replacement mutates its allocation or persistent lease.
///
/// `PortAllocator::capture_and_replace` acquires `lock_live`, captures the
/// promotion marker, holder mask, and full persistent lease record, then returns
/// this guard still holding the mutex. The caller performs eviction and
/// installation through the same guard, so a worker release/upsert cannot land
/// in a capture-to-reserve gap.
pub(super) struct CapturedLiveGuard<'a> {
    live: RwLockWriteGuard<'a, PortAllocatorLiveState>,
    shard: MutexGuard<'a, flows::LiveFlowShard>,
    previous_snapshot: Option<SourceNatReservationSnapshot>,
}

impl CapturedLiveGuard<'_> {
    fn previous_snapshot(&self) -> Option<SourceNatReservationSnapshot> {
        self.previous_snapshot.clone()
    }
}

impl std::ops::Deref for CapturedLiveGuard<'_> {
    type Target = PortAllocatorLiveState;

    fn deref(&self) -> &Self::Target {
        &self.live
    }
}

impl std::ops::DerefMut for CapturedLiveGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.live
    }
}

impl Default for PortAllocator {
    fn default() -> Self {
        Self {
            shared: Arc::new(PortAllocatorShared {
                allocator_id: next_allocator_id(),
                counters: Vec::new(),
                addr_counter_v4: AtomicU32::new(0),
                addr_counter_v6: AtomicU32::new(0),
                occupancy: Vec::new(),
                flows: flows::LiveFlowMap::new(),
                live: RwLock::new(PortAllocatorLiveState::default()),
                probe_excluded_hit: std::sync::atomic::AtomicBool::new(false),
                allocations_total: AtomicU64::new(0),
                reuses_total: AtomicU64::new(0),
                exhaustion_total: AtomicU64::new(0),
                idle_lease_import_capacity_total: AtomicU64::new(0),
                persistent_admitted_total: AtomicU64::new(0),
                persistent_declined_total: AtomicU64::new(0),
                flow_shard_lock_acquisitions: AtomicU64::new(0),
                flow_shard_lock_contended: AtomicU64::new(0),
                live_write_lock_acquisitions: AtomicU64::new(0),
                live_write_lock_contended: AtomicU64::new(0),
                persistent_permit_epoch: AtomicU64::new(1),
                max_tracked_flows: 0,
                #[cfg(test)]
                gc_lock_acquisitions: AtomicUsize::new(0),
            }),
            port_low: 1024,
            port_high: 65535,
        }
    }
}

// Test-only PortAllocator CONSTRUCTION counter (#6812 F3 round 4).
//
// The #6812 guards previously asserted only on the FINAL allocator a rule
// carries — its identity, or its occupancy-word count. Both are end-state
// assertions, and both are blind to the exact defect the reuse-before-build
// and no-bitmap-for-a-failed-pool rules exist to prevent: a `PortAllocator::
// new` that is built and then discarded. A throwaway construction immediately
// before the reuse lookup restores the pre-#6812 build-then-discard behaviour
// with every one of those assertions still green.
//
// THREAD-LOCAL, deliberately. A process-global counter is shared by every test
// `cargo test` runs in parallel and produced a master-red flake once already
// (#6819). `resolve_pool_allocators` and everything it calls are synchronous
// on the caller's thread, so a thread-local counts exactly the constructions
// the test under it caused, with no serialisation and no cross-test coupling.
#[cfg(test)]
thread_local! {
    static PORT_ALLOCATOR_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

// #16713 test seam: thread-local count of contention-helper visits
// (full `persistent_by_source` scans and indexed owner-set walks).
// Thread-local (like `PORT_ALLOCATOR_BUILDS`) so parallel
// `cargo test` threads cannot flake each other's counts (#6819).
#[cfg(test)]
thread_local! {
    static PERSISTENT_BY_SOURCE_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test-only: reset the calling thread's construction counter and return a
/// probe that reports constructions since the reset.
#[cfg(test)]
pub(super) fn reset_port_allocator_build_count() {
    PORT_ALLOCATOR_BUILDS.with(|c| c.set(0));
}

/// Test-only: PortAllocator constructions on this thread since the last reset.
#[cfg(test)]
pub(super) fn port_allocator_build_count() -> usize {
    PORT_ALLOCATOR_BUILDS.with(|c| c.get())
}

/// #9536: the three outcomes of offering a flow an existing persistent lease on
/// the PORT-BEARING path (`reuse_existing_lease_locked`).
///
/// A bare `Option` could say "reused" or "not reused", and "not reused" made the
/// caller mint and insert a fresh lease over the key. That is right when no
/// usable lease exists and wrong when a LIVE address-only lease does, so the
/// caller needs the third answer.
enum LeaseReuse {
    /// The flow joined the live, same-mode lease.
    Reused(TranslatedTuple),
    /// No usable lease: none existed, or an idle one was torn down. Mint one.
    NoLease,
    /// A LIVE address-only lease holds this source. It is left standing, and the
    /// caller must serve the flow WITHOUT persistence (no lease insert).
    LiveModeMismatch,
    /// The existing PAT lease's exact reverse identity is held by an
    /// address-only flow in this allocator. Leave the lease untouched and
    /// allocate this flow without joining it.
    WireIdentityConflict,
}

/// #17033: whether an idempotent re-entry bumps `reuses_total`.
///
/// A future path that must not count refreshes passes `Uncounted` here,
/// at the call site, rather than quietly omitting the bump — the
/// pre-fix synced-PAT copy did exactly that (see #17033).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReuseCount {
    /// Count the re-entry (the ordinary idempotent-reuse return).
    Counted,
    /// Record the holder only, without bumping `reuses_total`.
    #[expect(dead_code, reason = "#17195: dead in every build checked (release and --tests stripped probes in docs/log/17195.md); retained deliberately, so expect fires if a caller appears and the item should then lose this attribute instead of regaining allow(dead_code)")]
    Uncounted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PersistentInbound {
    Miss,
    Denied,
    Permitted {
        internal_ip: IpAddr,
        internal_port: u16,
        address_only: bool,
        lease_key: Option<PersistentSourceKey>,
    },
}
impl PortAllocator {
    pub(crate) fn new(num_addresses: usize, port_low: u16, port_high: u16) -> Self {
        #[cfg(test)]
        PORT_ALLOCATOR_BUILDS.with(|c| c.set(c.get() + 1));
        let counters = (0..num_addresses).map(|_| AtomicU32::new(0)).collect();
        let range = if port_low == 0 || port_high == 0 || port_low > port_high {
            0
        } else {
            (port_high as u32) - (port_low as u32) + 1
        };
        let occupancy = (0..num_addresses)
            .map(|_| AddressOccupancy::new(port_low, range))
            .collect();
        // #16840: a 0/0 range is an address-only allocator (pure
        // `port no-translation` pool): it builds no bitmap, but its flows
        // are tracked by reverse identity, not by port slot, so the cap
        // must not collapse to 0. Give it the global tracked-flow ceiling.
        // Other degenerate ranges keep the historical 0 (fail-closed PAT).
        let max_tracked_flows = if port_low == 0 && port_high == 0 && num_addresses > 0 {
            MAX_SOURCE_NAT_POOL_TRACKED_FLOWS
        } else {
            allocator_capacity(num_addresses, port_low, port_high)
                .min(MAX_SOURCE_NAT_POOL_TRACKED_FLOWS)
        };
        Self {
            shared: Arc::new(PortAllocatorShared {
                allocator_id: next_allocator_id(),
                counters,
                addr_counter_v4: AtomicU32::new(0),
                addr_counter_v6: AtomicU32::new(0),
                occupancy,
                flows: flows::LiveFlowMap::new(),
                live: RwLock::new(PortAllocatorLiveState::new(num_addresses)),
                probe_excluded_hit: std::sync::atomic::AtomicBool::new(false),
                allocations_total: AtomicU64::new(0),
                reuses_total: AtomicU64::new(0),
                exhaustion_total: AtomicU64::new(0),
                idle_lease_import_capacity_total: AtomicU64::new(0),
                persistent_admitted_total: AtomicU64::new(0),
                persistent_declined_total: AtomicU64::new(0),
                flow_shard_lock_acquisitions: AtomicU64::new(0),
                flow_shard_lock_contended: AtomicU64::new(0),
                live_write_lock_acquisitions: AtomicU64::new(0),
                live_write_lock_contended: AtomicU64::new(0),
                persistent_permit_epoch: AtomicU64::new(1),
                max_tracked_flows,
                #[cfg(test)]
                gc_lock_acquisitions: AtomicUsize::new(0),
            }),
            port_low,
            port_high,
        }
    }

    /// #4800/#17036: acquire the `live` RwLock write guard for serialized
    /// operations, counting attempts in the live-write domain and those
    /// whose initial `try_write` found contention. The non-persistent
    /// fast path counts its no-wait `try_write` in the same domain, then
    /// abandons that path on contention and falls back here (counted
    /// again as the serialized acquisition it is). Flow-shard write
    /// acquisitions count separately (`lock_flow_shard_counted`).
    ///
    /// Poison policy is preserved from the existing call sites:
    /// `unwrap_or_else(|e| e.into_inner())` lets later allocations continue
    /// after a worker panics mid-mutation. A poisoned try-write supplies the
    /// guard directly; on `WouldBlock`, this serialized path records contention
    /// and proceeds to the blocking write.
    ///
    /// `snapshot()` deliberately does NOT count as an acquisition — it is the
    /// ~1s status poll that reads these counters, and counting it would inject
    /// the observer into the observation.
    pub(super) fn lock_live(&self) -> RwLockWriteGuard<'_, PortAllocatorLiveState> {
        self.shared
            .live_write_lock_acquisitions
            .fetch_add(1, Ordering::Relaxed);
        match self.shared.live.try_write() {
            Ok(guard) => return guard,
            Err(TryLockError::Poisoned(poisoned)) => return poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {}
        }
        self.shared
            .live_write_lock_contended
            .fetch_add(1, Ordering::Relaxed);
        self.shared.live.write().unwrap_or_else(|e| e.into_inner())
    }
    /// #16017: current permit epoch (1 before first reuse sync).
    pub(crate) fn persistent_permit_epoch(&self) -> u64 {
        self.shared
            .persistent_permit_epoch
            .load(Ordering::Relaxed)
    }
    /// #16017: allocate the next permit epoch for a reused allocator.
    pub(crate) fn next_persistent_permit_epoch(&self) -> u64 {
        self.shared
            .persistent_permit_epoch
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }
    /// #16017: re-derive stored grants under the rules now sharing this
    /// allocator. Each covered bucket is revoked unless at least one
    /// rule covering it still permits `AnyRemoteHost`; preserving rules
    /// restamp it with their own version. Unlike the prior sync, imported
    /// grants (stamped 0) are revoked too: the next repeated import can
    /// explicitly re-authorize them under a still-permissive rule.
    pub(crate) fn sync_persistent_permit_scopes(
        &self,
        scopes: &[(u32, super::source::PersistentNatPermit, u64)],
    ) {
        if scopes.is_empty() {
            return;
        }
        let mut live = self.lock_live();
        for permissions in live.persistent_permissions.values_mut() {
            for (scope_id, grant) in &mut permissions.scopes {
                let covering: Vec<&(u32, super::source::PersistentNatPermit, u64)> =
                    scopes.iter().filter(|(id, _, _)| id == scope_id).collect();
                if covering.is_empty() {
                    continue;
                }
                // Fold 2 demotion: a covered grant loses authorization
                // before any preserving rule is considered. Stale writers
                // carrying an older epoch therefore write authorized_epoch
                // values that permits() rejects at the new current epoch.
                grant.permit_change_authorized = false;
                grant.authorized_epoch = 0;
                if let Some((_, _, version)) = covering
                    .iter()
                    .find(|(_, permit, _)| {
                        *permit == super::source::PersistentNatPermit::AnyRemoteHost
                    })
                    .copied()
                {
                    if grant.any_remote {
                        grant.any_remote_permit_epoch = *version;
                        grant.permit_change_authorized = true;
                        grant.authorized_epoch = *version;
                    }
                }
            }
        }
    }

    /// Shared access to the retained lease/ownership state for read-only
    /// queries. PAT admission does not use this guard: it needs the write
    /// guard to make the reverse-identity check and owner publication atomic.
    /// Deliberately NOT #4800-counted: a shared acquisition is not the
    /// serialized critical section the pair measures.
    pub(super) fn read_live(&self) -> RwLockReadGuard<'_, PortAllocatorLiveState> {
        self.shared.live.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Test seam: hold the `live` WRITE guard so a test can exercise
    /// allocation's serialized fallback behind a live writer.
    #[cfg(test)]
    pub(super) fn debug_hold_live_write(&self) -> RwLockWriteGuard<'_, PortAllocatorLiveState> {
        self.lock_live()
    }
    /// Test seam: hold the `live` READ guard to force the fast
    /// `try_write` to refuse and exercise its claim-release fallback.
    #[cfg(test)]
    pub(super) fn debug_hold_live_read(&self) -> RwLockReadGuard<'_, PortAllocatorLiveState> {
        self.read_live()
    }

    #[cfg(test)]
    pub(super) fn debug_live_lock_contended_total(&self) -> u64 {
        // Legacy test seam: the summed contended total across both
        // counted domains (flow-shard + live-write).
        self.shared.flow_shard_lock_contended.load(Ordering::Relaxed)
            + self.shared.live_write_lock_contended.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn debug_pat_owns_wire_identity(
        &self,
        flow: &SourceNatFlowKey,
        translated: TranslatedTuple,
    ) -> bool {
        self.read_live().pat_owns_wire_identity(flow, translated)
    }

    /// Counted flow-shard write guard (#4800/#17036): counted in the
    /// flow-shard domain so shard acquisitions stay comparable as a
    /// pair (acquisitions vs contended) without mixing in live-write
    /// acquisitions.
    pub(super) fn lock_flow_shard_counted(
        &self,
        flow: &SourceNatFlowKey,
    ) -> MutexGuard<'_, flows::LiveFlowShard> {
        self.shared.flows.write_shard_counted(
            flow,
            &self.shared.flow_shard_lock_acquisitions,
            &self.shared.flow_shard_lock_contended,
        )
    }
    pub(super) fn flows_len(&self) -> usize {
        self.shared.flows.len()
    }
    pub(super) fn flows_get(&self, flow: &SourceNatFlowKey) -> Option<LiveAllocation> {
        self.shared.flows.get(flow)
    }

    /// Fold 2 test seam: current shared admission-counter value.
    #[cfg(test)]
    pub(super) fn debug_admission_count(&self) -> usize {
        self.shared.flows.admission_count()
    }
    /// #15133: inbound lookup keyed by the ADMITTING RULE's normalized
    /// effective scope (see `SourceNatRule::persistent_rule_scope`). This is
    /// the production entry point: an interface-, routing-instance- or
    /// global-scoped rule-set has empty `from_zone`, and the legacy
    /// zone-pair lookup below collapsed that to UNSCOPED (any grant bucket
    /// admits), widening a strict sibling's `target-host-port` binding to
    /// `any-remote-host` when the two share one pool.
    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    pub(crate) fn persistent_inbound_lookup_for_rule(
        &self,
        protocol: u8,
        translated_ip: IpAddr,
        translated_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        now_ns: u64,
        rule: &super::source::SourceNatRule,
        ingress_zone: &str,
        packet_from_zone: &str,
        packet_to_zone: &str,
        scope: &super::NatScopeCtx<'_>,
    ) -> PersistentInbound {
        let arrival_scope =
            rule.persistent_rule_scope(packet_from_zone, packet_to_zone, ingress_zone, scope);
        self.persistent_inbound_lookup_scoped_for_rule(
            protocol,
            translated_ip,
            translated_port,
            remote_ip,
            remote_port,
            now_ns,
            arrival_scope,
            rule,
            ingress_zone,
        )
    }

    /// #17197: non-counting twin of
    /// [`persistent_inbound_lookup_for_rule`] for pure classification
    /// callers (the Stage-11 DNAT verdict). Same rule-scoped admission,
    /// but the lease tables are read under `read_live`, so no
    /// `live_write_lock_acquisitions` / `live_write_lock_contended`
    /// telemetry is charged and no write guard is taken. The returned
    /// lease key is a plain key copy; holding it is the caller's
    /// separate `acquire_persistent_inbound*` step, which the verdict
    /// path never performs.
    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    pub(crate) fn persistent_inbound_peek_for_rule(
        &self,
        protocol: u8,
        translated_ip: IpAddr,
        translated_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        now_ns: u64,
        rule: &super::source::SourceNatRule,
        ingress_zone: &str,
        packet_from_zone: &str,
        packet_to_zone: &str,
        scope: &super::NatScopeCtx<'_>,
    ) -> PersistentInbound {
        let arrival_scope =
            rule.persistent_rule_scope(packet_from_zone, packet_to_zone, ingress_zone, scope);
        self.persistent_inbound_peek_scoped_for_rule(
            protocol,
            translated_ip,
            translated_port,
            remote_ip,
            remote_port,
            now_ns,
            arrival_scope,
            rule,
            ingress_zone,
        )
    }

    /// #17197: read-only peek twin of the scoped-for-rule lookup:
    /// identical admission logic under a shared `live` read guard
    /// instead of the counted write guard (`lock_live`). The lookup
    /// body only reads `persistent_by_translated` /
    /// `persistent_by_source` / `persistent_permissions` and never
    /// mutates lease state, so a read guard is sufficient;
    /// `read_live` is deliberately NOT #4800-counted (see its doc),
    /// so this path bumps no `live_write_lock_acquisitions` /
    /// `live_write_lock_contended` telemetry. Pure classification
    /// callers (the Stage-11 verdict) use it; the committed-install
    /// path keeps the counting entry point so its telemetry is
    /// unchanged.
    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    fn persistent_inbound_peek_scoped_for_rule(
        &self,
        protocol: u8,
        translated_ip: IpAddr,
        translated_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        now_ns: u64,
        arrival_scope: u32,
        rule: &super::source::SourceNatRule,
        ingress_zone: &str,
    ) -> PersistentInbound {
        let live = self.read_live();
        self.persistent_inbound_lookup_scoped_for_rule_locked(
            &live,
            protocol,
            translated_ip,
            translated_port,
            remote_ip,
            remote_port,
            now_ns,
            arrival_scope,
            rule,
            ingress_zone,
        )
    }

    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    fn persistent_inbound_lookup_scoped_for_rule(
        &self,
        protocol: u8,
        translated_ip: IpAddr,
        translated_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        now_ns: u64,
        arrival_scope: u32,
        rule: &super::source::SourceNatRule,
        ingress_zone: &str,
    ) -> PersistentInbound {
        let live = self.lock_live();
        self.persistent_inbound_lookup_scoped_for_rule_locked(
            &live,
            protocol,
            translated_ip,
            translated_port,
            remote_ip,
            remote_port,
            now_ns,
            arrival_scope,
            rule,
            ingress_zone,
        )
    }

    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    fn persistent_inbound_lookup_scoped_for_rule_locked(
        &self,
        live: &PortAllocatorLiveState,
        protocol: u8,
        translated_ip: IpAddr,
        translated_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        now_ns: u64,
        arrival_scope: u32,
        rule: &super::source::SourceNatRule,
        ingress_zone: &str,
    ) -> PersistentInbound {
        let reverse = ReverseIdentityBaseKey {
            protocol,
            translated_ip,
            translated_port,
        };
        let Some(keys) = live.persistent_by_translated.get(&reverse) else {
            return PersistentInbound::Miss;
        };
        // #15936: the exact arrival_scope encodes the caller's pair. When it
        // does not grant, the loop below falls through to the provenance
        // re-fold (`permits_authored_any_from`): each bucket records its mint
        // from_zone, so this rule's buckets re-fold and reproduce their keys
        // without the caller ever knowing the internal zone. Buckets of a
        // sibling rule re-fold differently for every pair (authored fields
        // are folded verbatim), so they never reproduce and never admit.
        let mut matched = None;
        let mut saw_lease = false;
        for key in keys {
            let Some(lease) = live.persistent_by_source.get(key) else {
                continue;
            };
            if lease.revoked
                || (lease.active_flows == 0
                    && lease.inbound_flows == 0
                    && lease.expires_at_ns <= now_ns)
            {
                continue;
            }
            let permissions = live.persistent_permissions.get(key);
            // Admission is ANY granting bucket, never first-bucket-terminal:
            // the exact caller's-pair bucket is tried first, but a hit there
            // that does not grant this remote must not shadow a granting
            // bucket minted under another internal pair for the same rule
            // (e.g. trust->wan and wan->wan mints on one global lease, the
            // reader spelling (wan,wan)). The provenance re-fold recovers
            // those; it only runs for non-zone rules, whose authored
            // from_zone does not pin the pair. Zone-authored rules keep the
            // exact bucket as the whole answer.
            let exact_permitted = permissions.is_some_and(|p| {
                p.permits(
                    arrival_scope,
                    remote_ip,
                    remote_port,
                    rule.persistent_nat_permit,
                    rule.persistent_permit_epoch,
                    self.persistent_permit_epoch(),
                )
            });
            let (has, permitted) = if exact_permitted {
                (true, true)
            } else if rule.from_zone.is_empty() {
                match permissions.and_then(|p| {
                    p.permits_authored_any_from(
                        rule,
                        ingress_zone,
                        remote_ip,
                        remote_port,
                        rule.persistent_nat_permit,
                        rule.persistent_permit_epoch,
                        self.persistent_permit_epoch(),
                    )
                }) {
                    Some(permitted) => (true, permitted),
                    None => (
                        permissions.is_some_and(|p| p.has_scope(arrival_scope)),
                        false,
                    ),
                }
            } else {
                (
                    permissions.is_some_and(|p| p.has_scope(arrival_scope)),
                    false,
                )
            };
            if !has {
                continue;
            }
            saw_lease = true;
            if !permitted {
                continue;
            }
            let candidate = PersistentInbound::Permitted {
                internal_ip: key.src_ip,
                internal_port: key.src_port,
                address_only: lease.address_only,
                lease_key: Some(*key),
            };
            if matched.is_some_and(|previous| previous != candidate) {
                return PersistentInbound::Denied;
            }
            matched = Some(candidate);
        }
        match matched {
            Some(c) => c,
            None if saw_lease => PersistentInbound::Denied,
            None => PersistentInbound::Miss,
        }
    }
    fn persistent_inbound_lookup_scoped(
        &self,
        protocol: u8,
        translated_ip: IpAddr,
        translated_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        now_ns: u64,
        arrival_scope: u32,
    ) -> PersistentInbound {
        let reverse = ReverseIdentityBaseKey {
            protocol,
            translated_ip,
            translated_port,
        };
        let live = self.lock_live();
        let Some(keys) = live.persistent_by_translated.get(&reverse) else {
            return PersistentInbound::Miss;
        };
        let mut matched = None;
        let mut saw_lease = false;
        for key in keys {
            let Some(lease) = live.persistent_by_source.get(key) else {
                continue;
            };
            if lease.revoked
                || (lease.active_flows == 0
                    && lease.inbound_flows == 0
                    && lease.expires_at_ns <= now_ns)
            {
                continue;
            }
            // #15133: a lease this rule never minted on (no bucket for its
            // scope) is not this rule's to deny — skip it as a miss so a
            // sibling that DID mint can still admit. Only a lease holding
            // this rule's bucket can terminally Deny.
            let permissions = live.persistent_permissions.get(key);
            if !permissions.is_some_and(|p| p.has_scope(arrival_scope)) {
                continue;
            }
            saw_lease = true;
            let permitted = permissions.is_some_and(|permissions| {
                permissions.permits(
                    arrival_scope,
                    remote_ip,
                    remote_port,
                    PersistentNatPermit::AnyRemoteHost,
                    0,
                    0,
                )
            });
            if !permitted {
                continue;
            }
            let candidate = PersistentInbound::Permitted {
                internal_ip: key.src_ip,
                internal_port: key.src_port,
                address_only: lease.address_only,
                lease_key: Some(*key),
            };
            if matched.is_some_and(|previous| previous != candidate) {
                return PersistentInbound::Denied;
            }
            matched = Some(candidate);
        }
        match matched {
            Some(c) => c,
            None if saw_lease => PersistentInbound::Denied,
            None => PersistentInbound::Miss,
        }
    }
    /// #16615: find the lease key owning a translated tuple, regardless of
    /// routing scope. Used by HA synced acquire, which must not re-derive
    /// scope from the synced session's arrival domain.
    pub(crate) fn persistent_lease_key_for_translated(
        &self,
        protocol: u8,
        translated_ip: std::net::IpAddr,
        translated_port: u16,
        now_ns: u64,
    ) -> Option<PersistentSourceKey> {
        let reverse = ReverseIdentityBaseKey {
            protocol,
            translated_ip,
            translated_port,
        };
        let live = self.lock_live();
        let keys = live.persistent_by_translated.get(&reverse)?;
        // Prefer a live (non-revoked, non-expired-idle) lease; if multiple,
        // the first live one wins — cross-tenant ambiguity is resolved by
        // the caller acquiring only on the allocator that holds it.
        for key in keys {
            if let Some(lease) = live.persistent_by_source.get(key) {
                if !lease.revoked
                    && !(lease.active_flows == 0
                        && lease.inbound_flows == 0
                        && lease.expires_at_ns <= now_ns)
                {
                    return Some(*key);
                }
            }
        }
        keys.iter().next().copied()
    }

    /// Return the exact live lease owner and incarnation for a source key.
    /// The caller still validates the translated tuple before acquiring it.
    pub(crate) fn persistent_lease_hold(
        &self,
        key: PersistentSourceKey,
    ) -> Option<PersistentLeaseHold> {
        let incarnation = self.lock_live().persistent_by_source.get(&key)?.incarnation;
        Some(PersistentLeaseHold {
            key,
            allocator_id: self.debug_shared_identity(),
            owner: PersistentLeaseOwner::LocalWorker,
            incarnation,
        })
    }

    /// #15111: take an inbound reference on a persistent lease. Returns
    /// false if the lease is gone/revoked/expired-idle. On the 0->1 inbound
    /// edge with no outbound flows, removes the idle expiry index entry.
    pub(crate) fn acquire_persistent_inbound(&self, key: PersistentSourceKey, now_ns: u64) -> bool {
        self.acquire_persistent_inbound_checked(key, None, None, now_ns)
            .is_some()
    }

    /// Take an inbound reference and return the exact allocator/lease owner.
    pub(crate) fn acquire_persistent_inbound_with_hold(
        &self,
        key: PersistentSourceKey,
        now_ns: u64,
    ) -> Option<PersistentLeaseHold> {
        self.acquire_persistent_inbound_checked(key, None, None, now_ns)
    }

    /// Acquire from a recorded hold. Both allocator and lease incarnation must
    /// still match, and the wire tuple must still name this lease.
    pub(crate) fn acquire_persistent_inbound_for_hold(
        &self,
        hold: PersistentLeaseHold,
        expected_translated: TranslatedTuple,
        now_ns: u64,
    ) -> bool {
        if hold.allocator_id != self.debug_shared_identity() {
            return false;
        }
        self.acquire_persistent_inbound_checked(
            hold.key,
            Some(hold.incarnation),
            Some(expected_translated),
            now_ns,
        )
        .is_some()
    }

    fn acquire_persistent_inbound_checked(
        &self,
        key: PersistentSourceKey,
        expected_incarnation: Option<u64>,
        expected_translated: Option<TranslatedTuple>,
        now_ns: u64,
    ) -> Option<PersistentLeaseHold> {
        let mut live = self.lock_live();
        let Some(lease) = live.persistent_by_source.get(&key).copied() else {
            return None;
        };
        if expected_incarnation.is_some_and(|incarnation| incarnation != lease.incarnation)
            || expected_translated.is_some_and(|translated| translated != lease.translated)
            || lease.revoked
            || (lease.active_flows == 0
                && lease.inbound_flows == 0
                && lease.expires_at_ns <= now_ns)
        {
            return None;
        }
        if lease.inbound_flows == 0 && lease.active_flows == 0 {
            Self::remove_lease_expiration_locked(
                &mut live,
                lease.addr_index,
                lease.expires_at_ns,
                key,
            );
        }
        if let Some(l) = live.persistent_by_source.get_mut(&key) {
            l.inbound_flows = l.inbound_flows.saturating_add(1);
        }
        Some(PersistentLeaseHold {
            key,
            allocator_id: self.debug_shared_identity(),
            owner: PersistentLeaseOwner::LocalWorker,
            incarnation: lease.incarnation,
        })
    }
    /// #15111: release one inbound reference; on last holder re-arms expiry.
    /// #16652: on last holder of a revoked lease, also downgrade the
    /// `u64::MAX` clear tombstone to `now + horizon` (mirrors
    /// `complete_persistent_lease_locked` / `rollback_flow`), otherwise the
    /// key stays clear-fenced forever and is never pruned.
    pub(crate) fn release_persistent_inbound(&self, key: PersistentSourceKey, now_ns: u64) {
        let _ = self.release_persistent_inbound_checked(key, None, now_ns);
    }

    /// Release only if this exact lease incarnation remains installed.
    pub(crate) fn release_persistent_inbound_for_hold(
        &self,
        hold: PersistentLeaseHold,
        now_ns: u64,
    ) -> bool {
        if hold.allocator_id != self.debug_shared_identity() {
            return false;
        }
        self.release_persistent_inbound_checked(hold.key, Some(hold.incarnation), now_ns)
    }

    fn release_persistent_inbound_checked(
        &self,
        key: PersistentSourceKey,
        expected_incarnation: Option<u64>,
        now_ns: u64,
    ) -> bool {
        let mut live = self.lock_live();
        let Some(current) = live.persistent_by_source.get(&key).copied() else {
            return false;
        };
        if expected_incarnation.is_some_and(|incarnation| incarnation != current.incarnation)
            || current.inbound_flows == 0
        {
            return false;
        }
        let mut refresh = None;
        let revoked_until_ns = live.revoked_persistent.get(&key).copied();
        let revoked = if let Some(lease) = live.persistent_by_source.get_mut(&key) {
            lease.inbound_flows = lease.inbound_flows.saturating_sub(1);
            if lease.inbound_flows == 0 && lease.active_flows == 0 {
                let old = lease.expires_at_ns;
                let new = if lease.revoked {
                    now_ns
                } else {
                    now_ns.saturating_add(lease.timeout_ns)
                };
                lease.expires_at_ns = new;
                refresh = Some((lease.addr_index, old, new));
            }
            lease.revoked
        } else {
            return false;
        };
        if revoked
            && revoked_until_ns == Some(ACTIVE_PERSISTENT_NAT_CLEAR_TOMBSTONE_NS)
            && refresh.is_some()
        {
            live.revoked_persistent.insert(
                key,
                now_ns.saturating_add(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS),
            );
        }
        if let Some((addr, old, new)) = refresh {
            Self::remove_lease_expiration_locked(&mut live, addr, old, key);
            Self::insert_lease_expiration_locked(&mut live, addr, new, key);
        }
        true
    }
    /// #15111: rollback an inbound hold for a failed install (same as release).
    pub(crate) fn rollback_persistent_inbound(&self, key: PersistentSourceKey, now_ns: u64) {
        self.release_persistent_inbound(key, now_ns);
    }

    /// Resolve an unsolicited packet addressed to a persistent NAT tuple.
    /// A leased tuple with no matching remote permission is terminally denied.
    ///
    /// Legacy zone-pair entry point, retained for direct allocator calls and
    /// NAT64 BIBs whose grants share the unscoped bucket by design. An empty
    /// `from_zone` or `ingress_zone` still selects UNSCOPED here — never
    /// route a source-NAT rule through this spelling; production rule
    /// lookups go through `persistent_inbound_lookup_for_rule` (#15133).
    pub(crate) fn persistent_inbound_lookup(
        &self,
        protocol: u8,
        translated_ip: IpAddr,
        translated_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        now_ns: u64,
        from_zone: &str,
        ingress_zone: &str,
    ) -> PersistentInbound {
        let arrival_scope = if from_zone.is_empty() || ingress_zone.is_empty() {
            PERSISTENT_NAT_EGRESS_UNSCOPED
        } else {
            persistent_egress_scope(from_zone, ingress_zone)
        };
        self.persistent_inbound_lookup_scoped(
            protocol,
            translated_ip,
            translated_port,
            remote_ip,
            remote_port,
            now_ns,
            arrival_scope,
        )
    }

    pub(super) fn record_synced_persistent_permission(
        &self,
        flow: SourceNatFlowKey,
        permit: PersistentNatPermit,
        egress_scope: u32,
    ) {
        self.record_synced_persistent_permission_with_zones(flow, permit, egress_scope, None, 0)
    }

    pub(super) fn record_synced_persistent_permission_with_zones(
        &self,
        flow: SourceNatFlowKey,
        permit: PersistentNatPermit,
        egress_scope: u32,
        mint_from_zone: Option<&str>,
        permit_epoch: u64,
    ) {
        let key = flow.persistent_source_key(permit);
        let mut live = self.lock_live();
        if live.persistent_by_source.contains_key(&key) {
            live.record_persistent_permission_with_zones(
                key,
                permit,
                flow,
                egress_scope,
                mint_from_zone,
                permit_epoch,
            );
        }
    }
    /// Atomically capture a flow's complete incumbent snapshot and retain the
    /// live guard for the caller's replacement operation.
    ///
    /// The caller must perform eviction and installation through the returned
    /// guard; releasing it and reserving separately recreates the worker
    /// upsert/release gap this operation closes. `capture_holders` keeps the
    /// ordinary worker reserve path from doing an unused state read.
    fn capture_and_replace(
        &self,
        flow: &SourceNatFlowKey,
        capture_holders: bool,
    ) -> CapturedLiveGuard<'_> {
        let live = self.lock_live();
        // #15956: `live` THEN the flow's shard (the uniform order).
        // The shard guard is carried in the returned guard so reserve
        // paths mutate the flow under the same locks the legacy single
        // mutex gave them — callers must use `live.shard`, never
        // re-acquire this flow's shard while the guard lives.
        let __capture_shard = self.shared.flows.shard_guard(flow);
        let previous_snapshot = if capture_holders {
            __capture_shard.map.get(flow).copied().map(|allocation| {
                let persistent_lease = allocation
                    .persistent_key
                    .and_then(|key| live.persistent_by_source.get(&key).copied());
                SourceNatReservationSnapshot {
                    allocator: self.clone(),
                    flow: *flow,
                    translated: allocation.translated,
                    persistent_key: allocation.persistent_key,
                    promotion_timeout_ns: allocation.promotion_timeout_ns,
                    holders: allocation.holders,
                    persistent_lease,
                    allocation: Some(allocation),
                    addr_index: allocation.addr_index,
                    deterministic: allocation.deterministic,
                    address_only: allocation.address_only,
                }
            })
        } else {
            None
        };
        CapturedLiveGuard {
            live,
            shard: __capture_shard,
            previous_snapshot,
        }
    }

    /// Revoke every persistent lease held by this allocator (#10784).
    ///
    /// Idle leases are removed and their PAT occupancy is released. Leases
    /// with live flows become revoked draining shells; the returned count is
    /// only newly revoked leases, not shells from an earlier clear. Per-key
    /// tombstones fence known cleared leases; the batch fence protects
    /// generation-less records whose key was not installed at clear time.
    pub(crate) fn clear_persistent_leases(&self, now_ns: u64) -> usize {
        let replay_until_ns = now_ns.saturating_add(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS);
        let (count, freed) = {
            let mut live = self.lock_live();
            live.prune_expired_persistent_nat_clear_fences(now_ns);
            live.last_persistent_nat_clear_ns = Some(
                live.last_persistent_nat_clear_ns
                    .map_or(now_ns, |last_ns| last_ns.max(now_ns)),
            );
            let leases: Vec<_> = live
                .persistent_by_source
                .iter()
                .map(|(key, lease)| (*key, *lease))
                .collect();
            let mut count = 0;
            let mut freed = Vec::new();
            for (key, lease) in leases {
                let newly_revoked = !lease.revoked;
                if newly_revoked {
                    count += 1;
                }
                let revoked_until_ns = if lease.active_flows == 0 && lease.inbound_flows == 0 {
                    replay_until_ns
                } else {
                    ACTIVE_PERSISTENT_NAT_CLEAR_TOMBSTONE_NS
                };
                live.revoked_persistent.insert(key, revoked_until_ns);
                if lease.active_flows != 0 || lease.inbound_flows != 0 {
                    if newly_revoked {
                        live.remove_persistent_address_only_owner(key, lease);
                        if let Some(stored_lease) = live.persistent_by_source.get_mut(&key) {
                            stored_lease.revoked = true;
                        }
                    }
                    continue;
                }
                // #17028: shared retire (Deferred: ports freed after
                // the guard drops, stamped at clear time below).
                if let Some(retired) = lease_table::retire_idle_lease_locked(&mut live, &key) {
                    if let Some(port) = retired.freed_port {
                        freed.push(port);
                    }
                }
            }
            (count, freed)
        };
        for (addr_index, port) in freed {
            // #16035 fold: stamped at the clear time. The previous
            // unstamped shape bypassed the delay entirely for leases
            // cleared while still young (a clear 1s after mint would
            // free the port for instant reuse); the lease's idle
            // retention is operator/config dependent, not a guaranteed
            // quarantine, so the stamped delay is the only bound.
            self.free_translated_port_at(addr_index, port, now_ns);
        }
        count
    }

    /// #6751: live ownership records held by this allocator.
    ///
    /// The interface-mode registry uses it as its reclamation predicate — an
    /// allocator with no live records holds no occupancy any session depends
    /// on, so it can be dropped; one with live records must be retained until
    /// their releases have reached it. Takes the `live` mutex, so it belongs on
    /// apply / cap-saturation paths only, never per packet.
    pub(crate) fn live_flow_count(&self) -> usize {
        self.flows_len()
    }

    /// White-box access to the live state for tests. NOT for production
    /// callers — they should use the typed `allocate_translation` /
    /// `release_flow` / `rollback_flow` / `snapshot` entry points. Port
    /// ownership is inspected via the dedicated debug accessors below (the
    /// bitmap lives outside this mutex).
    /// Test-only: hold BOTH allocator locks (`live` then the flow's
    /// shard, the uniform order) so a test can park the insert
    /// critical section and inject a winning record into it.
    #[cfg(test)]
    pub(super) fn debug_capture(&self, flow: &SourceNatFlowKey) -> CapturedLiveGuard<'_> {
        self.capture_and_replace(flow, false)
    }
    #[cfg(test)]
    pub(super) fn debug_live(&self) -> RwLockWriteGuard<'_, PortAllocatorLiveState> {
        self.shared.live.write().unwrap_or_else(|e| e.into_inner())
    }
    /// Test-only: total persistent address-only identity reference count.
    #[cfg(test)]
    pub(super) fn debug_persistent_address_only_owner_count(&self) -> u32 {
        self.lock_live()
            .persistent_address_only_owner_counts
            .values()
            .copied()
            .sum()
    }
    /// #16013 test seam: leases charged to one source, and the distinct-source
    /// count. Lets the fairness cells assert the charge moves on mint/release
    /// without scanning `persistent_by_source`.
    #[cfg(test)]
    pub(super) fn debug_persistent_lease_count_for_source(
        &self,
        src_ip: IpAddr,
        routing_scope: u32,
    ) -> usize {
        self.lock_live()
            .persistent_lease_count_for_source(src_ip, routing_scope)
    }

    #[cfg(test)]
    pub(super) fn debug_persistent_source_count(&self) -> usize {
        self.lock_live().persistent_leases_by_source.len()
    }

    /// Test-only: total occupancy-bitmap WORDS across every pool address.
    /// The #6812 aggregate-budget tests assert a refused / failed pool
    /// materialised ZERO words (no eager bitmap) while an admitted pool
    /// carries `addresses x div_ceil(port_range, 64)` — the direct white-box
    /// proof the bitmap was (or was not) allocated.
    #[cfg(test)]
    pub(super) fn debug_occupancy_words(&self) -> usize {
        self.shared.occupancy.iter().map(|o| o.words.len()).sum()
    }

    /// #16713 test seam: reset / read the full-table scan counter.
    #[cfg(test)]
    pub(crate) fn debug_reset_persistent_by_source_scans(&self) {
        PERSISTENT_BY_SOURCE_SCANS.with(|c| c.set(0));
    }

    #[cfg(test)]
    pub(crate) fn debug_persistent_by_source_scans(&self) -> usize {
        PERSISTENT_BY_SOURCE_SCANS.with(|c| c.get())
    }

    /// Test-only: identity of the shared allocator state, for proving a
    /// re-apply REUSED the previous allocator (same Arc) instead of building
    /// a fresh bitmap (#6812 reuse-before-build).
    pub(crate) fn debug_shared_identity(&self) -> usize {
        Arc::as_ptr(&self.shared) as usize
    }

    /// Test-only: mark a translated tuple as owned (set its occupancy bit)
    /// without advancing the sequential cursor. Models an out-of-band occupant
    /// (a persistent lease or an HA-synced install) sitting inside the
    /// sequential port range — the precondition for the #3047 collision paths.
    /// `_translated_ip` is retained for call-site clarity; the bitmap is keyed
    /// by `addr_index`.
    #[cfg(test)]
    pub(super) fn debug_seed_owner(&self, addr_index: usize, _translated_ip: IpAddr, port: u16) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            occ.reserve(port);
        }
    }

    /// Test-only: insert a live allocation directly, into a guard the caller
    /// already holds.
    ///
    /// This exists to make the #9130 insert-critical-section idempotency race
    /// DETERMINISTIC. That arm fires only when another worker installs the flow
    /// between this one's lock-free port claim and its insert — a window no
    /// single-threaded test can enter, and a stress test would hit it once in
    /// many runs, which scores a mutation as "survived" most of the time. With
    /// this the test parks on `debug_live()`, waits for the worker to claim its
    /// port (observable lock-free on the occupancy bitmap), injects the winning
    /// record, and releases: the worker takes the race arm on EVERY run.
    #[cfg(test)]
    pub(super) fn debug_insert_live_locked(
        &self,
        live: &mut CapturedLiveGuard<'_>,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        addr_index: usize,
        deterministic: bool,
    ) {
        let _ = self.shared.flows.try_insert_in_shard(
            &mut live.shard,
            flow,
            LiveAllocation {
                translated,
                persistent_key: None,
                addr_index,
                deterministic,
                address_only: false,
                promotion_timeout_ns: None,
                holders: NatHolder::Untracked.bit(),
            },
            usize::MAX,
        );
        live.record_pat_owner(&flow, translated);
    }

    /// Test-only: clear a synthetic owner seeded via `debug_seed_owner`
    /// (clear its occupancy bit) without pushing the port onto the recycle
    /// queue.
    #[cfg(test)]
    pub(super) fn debug_clear_owner(&self, addr_index: usize, _translated_ip: IpAddr, port: u16) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            occ.free_no_recycle(port);
        }
    }

    /// #6979 F6: how many pool-address occupancy slots does this allocator have?
    ///
    /// ZERO for `PortAllocator::default()`, which is what every rule that never
    /// received a real allocator carries — a non-pool rule, and a pool rule that
    /// failed without a previous generation to drain. Such an allocator can
    /// never hold a port, so the overlap index skips it rather than treating
    /// each one as its own occupancy domain (Codex round 2 on PR #8111,
    /// finding 1: `PortAllocator::default()` builds a FRESH `Arc` per rule, so
    /// counting them as distinct made the index's dedup scan quadratic in the
    /// RULE count, which no budget bounds).
    pub(crate) fn address_slots(&self) -> usize {
        self.shared.occupancy.len()
    }

    /// #6979 F6: do these two handles refer to the SAME allocator?
    ///
    /// Allocator sharing between rules is by `Arc`, so pointer identity is the
    /// question — not key equality. The resolver reaches a shared allocator by
    /// several routes (an exact previous-generation key, a this-apply key
    /// already assigned, a rename carry), and the peer-overlap wiring must
    /// treat every one of them as "one occupancy domain, nothing to check".
    pub(crate) fn same_allocator(&self, other: &PortAllocator) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    /// #6979 F6: is `port` currently OWNED on pool address `addr_index` in this
    /// allocator?
    ///
    /// The occupancy bit is the sole ownership token for a PAT allocation, so
    /// this is the question a PEER allocator over the same pool address has to
    /// ask before it may publish that identity: two pools covering one address
    /// are two independent bitmaps, and without this each is blind to the
    /// other's live translations.
    ///
    /// A port outside this address's configured range, or an `addr_index` past
    /// the end (an empty default allocator), answers `false` — it owns nothing
    /// there, which is the honest answer and the fail-open direction only in
    /// the sense that there is nothing to protect.
    pub(crate) fn holds_port(&self, addr_index: usize, port: u16) -> bool {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => match occ.offset_of(port) {
                Some(offset) => occ.is_occupied(offset),
                None => false,
            },
            None => false,
        }
    }

    /// #8115 R1: is this allocator holding the ADDRESS-ONLY reverse identity
    /// `rkey`?
    ///
    /// The sibling of [`Self::holds_port`] for the OTHER ownership space. A
    /// live port no-translation flow records its reverse token in
    /// `address_only_owners`; an idle lease is tracked by the persistent
    /// identity index. Neither claims a PAT occupancy bit, so a bitmap-only
    /// peer check can miss both owners.
    ///
    /// `rkey` is an exact candidate. It conflicts with an exact owner at the
    /// same remote endpoint or a persistent host/any-remote owner that covers
    /// it; another exact remote port remains distinct.
    pub(crate) fn holds_address_only_identity(&self, rkey: &AddressOnlyReverseKey) -> bool {
        let translated = TranslatedTuple {
            ip: rkey.translated_ip,
            port: rkey.translated_port,
        };
        self.lock_live().idle_import_identity_contended(
            rkey.protocol,
            translated,
            Some((rkey.dst_ip, rkey.dst_port)),
            false,
        )
    }

    /// Test-only alias of [`Self::holds_port`]. Kept as an ALIAS rather than a
    /// second copy of the lookup so the tests that pin occupancy keep asking
    /// the production question (#6979).
    #[cfg(test)]
    pub(crate) fn debug_is_port_occupied(&self, addr_index: usize, port: u16) -> bool {
        self.holds_port(addr_index, port)
    }

    /// Test-only: map a bitmap `offset` to its port on pool address
    /// `addr_index`, exercising the #5660 range-checked `port_of`. Returns
    /// `None` for an unknown address OR an out-of-range offset (the value a bare
    /// `offset as u16` would silently truncate).
    #[cfg(test)]
    pub(super) fn debug_port_of(&self, addr_index: usize, offset: u32) -> Option<u16> {
        self.shared
            .occupancy
            .get(addr_index)
            .and_then(|occ| occ.port_of(offset))
    }

    /// Test-only: total occupied ports across all pool addresses.
    #[cfg(test)]
    pub(super) fn debug_occupied_count(&self) -> usize {
        self.shared
            .occupancy
            .iter()
            .map(AddressOccupancy::occupied_count)
            .sum()
    }

    /// Test-only: snapshot the FIFO recycle queue for pool address `addr_index`.
    #[cfg(test)]
    pub(super) fn debug_recycled_ports(&self, addr_index: usize) -> Vec<u16> {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => occ
                .recycle
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .queue
                .iter()
                .map(|&(port, _)| port)
                .collect(),
            None => Vec::new(),
        }
    }

    /// Test-only: replace the FIFO recycle queue for pool address `addr_index`.
    /// Goes through `RecycleRing::push` so the #7174 M13 dedup bitset stays
    /// consistent with the queue — an injected duplicate is dropped exactly as
    /// a production duplicate would be.
    #[cfg(test)]
    pub(super) fn debug_set_recycled(&self, addr_index: usize, ports: Vec<u16>) {
        if let Some(occ) = self.shared.occupancy.get(addr_index) {
            let mut recycle = occ.recycle.lock().unwrap_or_else(|e| e.into_inner());
            *recycle = RecycleRing::new(occ.range);
            for port in ports {
                let offset = occ.offset_of(port);
                recycle.push(port, offset);
            }
        }
    }

    /// Test-only: free `port` on pool address `addr_index` through the
    /// RECYCLING path — the same path every record takes in
    /// `unlink_live_allocation_locked` (#14625). Returns true iff the
    /// occupancy bit was set.
    #[cfg(test)]
    pub(super) fn debug_free_recycle(&self, addr_index: usize, port: u16) -> bool {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => occ.free_recycle(port),
            None => false,
        }
    }

    /// Test-only: free `port` at monotonic `now_ns` (#16035), so a
    /// fixture can stamp a token's quarantine clock.
    #[cfg(test)]
    pub(super) fn debug_free_recycle_at(&self, addr_index: usize, port: u16, now_ns: u64) -> bool {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => occ.free_recycle_at(port, now_ns),
            None => false,
        }
    }

    /// Test-only VIEW of a PRODUCTION counter (#7174 M13, promoted in #9392).
    /// Tokens popped by the recycled phase of `claim` on pool address
    /// `addr_index` since construction. The seam that makes the
    /// exhausted-address short-circuit MEASURABLE — the return value is `None`
    /// with or without it.
    ///
    /// The accessor stays `#[cfg(test)]` because it is PER-ADDRESS and the
    /// production surface is per POOL (`PortAllocatorSnapshot`); the field it
    /// reads is now compiled into release builds.
    #[cfg(test)]
    pub(super) fn debug_recycle_scan_pops(&self, addr_index: usize) -> u64 {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => occ.recycle_scan_pops.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// Test-only: `claim_in_block` attempt accounting for pool address
    /// `addr_index` since construction: (bitmap words loaded, `claim_offset`
    /// attempts). The seam that makes the #9902 word-skip MEASURABLE — the
    /// return value (first-free port) is identical with or without it. Use
    /// `debug_seed_owner` to prepare dense-prefix fixtures: it sets bits
    /// without touching these counters, so one measured allocation reads exact.
    #[cfg(test)]
    pub(super) fn debug_probe_attempts(&self, addr_index: usize) -> (u64, u64) {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => (
                occ.probe_word_loads.load(Ordering::Relaxed),
                occ.probe_claim_rmws.load(Ordering::Relaxed),
            ),
            None => (0, 0),
        }
    }

    /// Test-only: the #7174 M13 live occupancy counter for pool address
    /// `addr_index`, read WITHOUT the popcount. Paired with
    /// `debug_occupied_count` (which popcounts the bitmap) it binds the
    /// agreement between the counter and the bitmap it summarises.
    #[cfg(test)]
    pub(super) fn debug_occupied_counter(&self, addr_index: usize) -> u32 {
        match self.shared.occupancy.get(addr_index) {
            Some(occ) => occ.occupied.load(Ordering::Relaxed),
            None => 0,
        }
    }

    /// #16011 test seam: drive ONLY the recycle phase of a claim on
    /// `addr_index` (the keyed probe is bypassed), so FIFO retain /
    /// scan-cost fixtures keep measuring the ring in isolation.
    #[cfg(test)]
    pub(super) fn debug_claim_recycled_only(&self, addr_index: usize) -> Option<u16> {
        self.shared.occupancy.get(addr_index)?.claim_recycled_only()
    }

    /// Test-only: recycled phase at monotonic `now_ns` (#16035).
    #[cfg(test)]
    pub(super) fn debug_claim_recycled_only_at(
        &self,
        addr_index: usize,
        now_ns: u64,
    ) -> Option<u16> {
        self.shared
            .occupancy
            .get(addr_index)?
            .claim_recycled_only_at(now_ns)
    }

    /// Test-only: drive the #4676 chunked opportunistic GC directly (the same
    /// entry point the hot allocation path and the periodic release path use),
    /// so a white-box test can assert both the reclaim result and the seam
    /// (`debug_gc_lock_acquisitions`).
    #[cfg(test)]
    pub(crate) fn debug_gc_expired_chunked(&self, now_ns: u64, budget: usize) -> usize {
        self.gc_expired_chunked(now_ns, budget)
    }

    /// Test-only: how many times `gc_expired_chunked` has acquired the `live`
    /// mutex. Because a std `Mutex` is non-reentrant, a value > 1 over a single
    /// sweep is direct proof the sweep RELEASED the lock between chunks.
    #[cfg(test)]
    pub(super) fn debug_gc_lock_acquisitions(&self) -> usize {
        self.shared.gc_lock_acquisitions.load(Ordering::Relaxed)
    }

    /// Pick a pool address index for the current address family.
    pub(super) fn address_index(
        &self,
        src_ip: IpAddr,
        family_offset: usize,
        family_len: usize,
        address_persistent: bool,
    ) -> usize {
        if family_len == 0 {
            return 0;
        }
        if address_persistent {
            return family_offset + sticky_pool_index(src_ip, family_len);
        }
        let counter = match src_ip {
            IpAddr::V4(_) => &self.shared.addr_counter_v4,
            IpAddr::V6(_) => &self.shared.addr_counter_v6,
        };
        let idx = counter.fetch_add(1, Ordering::Relaxed);
        family_offset + ((idx as usize) % family_len)
    }

    /// #16011: fold a flow tuple into the keyed-probe key. Every tuple
    /// field is folded through the splitmix finalizer so no single-field
    /// delta survives; the per-boot secret is applied inside
    /// `pat_keyed_offset` / `AddressOccupancy::claim`.
    /// FOLD (#16350 fold-2): did the last allocation probe skip an
    /// excluded (peer-owned) candidate? See `probe_excluded_hit`.
    pub(super) fn probe_excluded_hit(&self) -> bool {
        self.shared.probe_excluded_hit.load(Ordering::Relaxed)
    }

    pub(super) fn pat_key(flow: &SourceNatFlowKey) -> u64 {
        let mut h = pat_mix(u64::from(flow.protocol) ^ 0x1601_0001);
        fn ip_fold(h: &mut u64, ip: IpAddr) {
            match ip {
                IpAddr::V4(v4) => *h = pat_mix(*h ^ u64::from(u32::from(v4))),
                IpAddr::V6(v6) => {
                    let o = v6.octets();
                    *h = pat_mix(*h ^ u64::from_be_bytes(o[0..8].try_into().unwrap()));
                    *h = pat_mix(*h ^ u64::from_be_bytes(o[8..16].try_into().unwrap()));
                }
            }
        }
        ip_fold(&mut h, flow.src_ip);
        ip_fold(&mut h, flow.dst_ip);
        h = pat_mix(h ^ u64::from(flow.src_port));
        h = pat_mix(h ^ u64::from(flow.dst_port));
        pat_mix(h ^ u64::from(flow.routing_scope))
    }

    /// Allocate the next port for the given address index, reporting
    /// unusable allocator state to the caller instead of producing a
    /// no-op translation.
    ///
    /// #16011: keyed (RFC 6056) instead of sequential `fetch_add % range`.
    /// This stateless path claims no occupancy bit (its callers are the
    /// synthetic tuple-unknown wrappers whose port is never written to a
    /// frame), so it cannot probe the bitmap; keying the counter value
    /// through the per-boot secret is what removes predictability here.
    /// Callers that know the flow SHOULD use `try_next_port_for`.
    pub(super) fn try_next_port(
        &self,
        addr_index: usize,
    ) -> Result<u16, super::source::SourceNatFailureReason> {
        self.try_next_port_keyed(addr_index, addr_index as u64)
    }

    /// Flow-keyed variant of [`Self::try_next_port`] (RFC 6056 Alg 3:
    /// the hash input is the flow tuple, not a shared counter alone).
    pub(super) fn try_next_port_for(
        &self,
        addr_index: usize,
        flow: &SourceNatFlowKey,
    ) -> Result<u16, super::source::SourceNatFailureReason> {
        self.try_next_port_keyed(addr_index, Self::pat_key(flow))
    }

    fn try_next_port_keyed(
        &self,
        addr_index: usize,
        key: u64,
    ) -> Result<u16, super::source::SourceNatFailureReason> {
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(super::source::SourceNatFailureReason::InvalidPortRange);
        }
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        if range == 0 || addr_index >= self.shared.counters.len() {
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        let counter = &self.shared.counters[addr_index];
        let nonce = counter.fetch_add(1, Ordering::Relaxed);
        let offset = pat_keyed_offset(pat_secret(), key ^ u64::from(nonce), range);
        Ok(self.port_low + offset as u16)
    }

    /// #8121: CLAIM one specific `(addr_index, port)` for the idle-lease
    /// import — the mirror of `free_translated_port`. `None` when the index is
    /// out of range; `Some(false)` when the bit is already held. An idle lease still holds its
    /// bit on the active node (it is freed on the expiry path, not when the
    /// last flow closes), so importing without the bit would let a local flow
    /// mint the same translated identity.
    // #8121 part 1: reached only from `idle_lease_sync_8121` and its tests
    // until the transport lands (see that module's header).
    pub(super) fn try_claim_translated_port(&self, addr_index: usize, port: u16) -> Option<bool> {
        Some(self.shared.occupancy.get(addr_index)?.reserve(port))
    }
    /// Undo an idle import whose post-claim peer-overlap check found a racing
    /// owner. Keep the table and occupancy-token rollback under `live` so no
    /// same-allocator operation can reuse the lease between those mutations.
    pub(super) fn rollback_idle_lease_import(
        &self,
        rec: &super::idle_lease_sync_8121::IdleLeaseRecord,
    ) -> bool {
        let key = PersistentSourceKey {
            protocol: rec.protocol,
            src_ip: rec.src_ip,
            src_port: rec.src_port,
            routing_scope: rec.routing_scope,
            remote: None,
        };
        let mut live = self.lock_live();
        let Some(lease) = live.persistent_by_source.get(&key).copied() else {
            return false;
        };
        if !lease.imported
            || lease.active_flows != 0
            || lease.inbound_flows != 0
            || lease.translated.ip != rec.translated_ip
            || lease.translated.port != rec.translated_port
            || lease.address_only != rec.address_only
        {
            return false;
        }
        // #17028: shared retire; unstamped free preserved.
        if let Some(retired) = lease_table::retire_idle_lease_locked(&mut live, &key) {
            if let Some((addr_index, port)) = retired.freed_port {
                self.free_translated_port(addr_index, port);
            }
        }
        true
    }
    /// #11475/#11495: make room for an imported lease or a synced-session
    /// persistent mint using one bounded persistent-table pressure sweep.
    ///
    /// Called with `live` held after the caller has checked for an existing
    /// source key. The table length is authoritative under this guard; no
    /// persistent insertion can race another past the cap.
    pub(super) fn persistent_lease_capacity_reached(
        &self,
        live: &mut PortAllocatorLiveState,
        now_ns: u64,
    ) -> bool {
        if live.persistent_by_source.len() < self.shared.max_tracked_flows {
            return false;
        }
        self.gc_expired_locked(live, now_ns, PRESSURE_GC_BUDGET);
        live.persistent_by_source.len() >= self.shared.max_tracked_flows
    }
    /// #16013: per-source twin of `persistent_lease_capacity_reached` — one
    /// bounded pressure-GC pass, then refuse a NEW lease key whose source is
    /// at `MAX_PERSISTENT_LEASES_PER_SOURCE`. GC runs first so expired idle
    /// leases stop charging their source before the refusal is decided.
    pub(super) fn persistent_source_lease_capacity_reached(
        &self,
        live: &mut PortAllocatorLiveState,
        key: &PersistentSourceKey,
        now_ns: u64,
    ) -> bool {
        if !live.persistent_source_at_lease_cap(key) {
            return false;
        }
        self.gc_expired_locked(live, now_ns, PRESSURE_GC_BUDGET);
        live.persistent_source_at_lease_cap(key)
    }

    /// Free a translated port's occupancy bit, pushing it onto the FIFO
    /// reuse ring (#3011). Returns true iff the bit was set.
    ///
    /// #14625: deterministic ports recycle too. The pre-#14625 split
    /// (`free_no_recycle` for deterministic records) was sound only while
    /// an allocator served deterministic rules for its whole life, because
    /// `claim_in_block` scans the bitmap directly and never drains the
    /// ring. But `SourceNatPoolAllocatorKey` excludes mode, so removing
    /// `port deterministic` reuses the SAME allocator for round-robin PAT,
    /// whose `claim()` -- once its fresh cursor is spent -- reaches free
    /// ports ONLY through this ring. A no-recycle free after the flip
    /// cleared the bit with no token, stranding the port until the pool
    /// key changed. Recycling is harmless for a still-deterministic pool:
    /// `claim_in_block` ignores the ring, the ring holds at most one
    /// token per offset (#7174), and a PAT claim that later pops the
    /// token finds the bit via the normal claim path.
    fn free_translated_port(&self, addr_index: usize, port: u16) -> bool {
        self.free_translated_port_at(addr_index, port, 0)
    }

    /// [`Self::free_translated_port`] stamping the recycle token at
    /// monotonic `now_ns` (#16035). Paths that carry a real clock
    /// (flow release, allocation give-backs, expiry GC) pass it so a
    /// small pool's minimum reuse delay is measured from the actual
    /// free. Clock-less internal frees stamp 0, which the quarantine
    /// treats as unstamped (no delay) — every production flow free
    /// (release / rollback / give-back / expiry GC) carries a clock,
    /// so the unstamped path is only internal bookkeeping frees whose
    /// port was never exposed to a remote endpoint.
    fn free_translated_port_at(&self, addr_index: usize, port: u16, now_ns: u64) -> bool {
        let Some(occ) = self.shared.occupancy.get(addr_index) else {
            return false;
        };
        occ.free_recycle_at(port, now_ns)
    }
    /// Release a newly claimed candidate that never became a live PAT mapping.
    /// Use an unstamped recycle token: it bypasses the small-pool quarantine
    /// while keeping concurrent bitmap/recycle claims exact.
    fn free_unpublished_translated_port(&self, addr_index: usize, port: u16) -> bool {
        self.free_translated_port_at(addr_index, port, 0)
    }

    /// #17033 (#9145/#6211 F2): the single-sourced idempotent-reuse return.
    ///
    /// Records `holder` on the existing record and returns its translated
    /// tuple. This early return is where workers 2..N land — a synced
    /// entry is fanned out to every worker against the ONE shared
    /// allocator — and where an already-holding worker lands on every
    /// refresh. Without the holder bit a worker-0 `release_flow` clears
    /// the occupancy bit for a translation another worker still holds:
    /// the NAT source collision the mask exists to prevent.
    ///
    /// OR is idempotent, so a refresh cannot inflate the mask; that is
    /// why this is a bitmask and not a counter. The direction is the
    /// safe one `drop_holder_locked` prefers: this can only ever cause
    /// an UNDER-release, never an over-release.
    ///
    /// `count` decides whether the re-entry bumps `reuses_total`, which
    /// is exported as `xpf_userspace_source_nat_pool_reuses_total` and
    /// used as a test discriminator for the idempotent path. Callers
    /// keep their own give-back of any candidate they claimed before
    /// discovering the incumbent (recycling free, unpublished free, or
    /// nothing) — that difference stays at the call site, after this
    /// returns.
    fn reenter_existing_locked(
        &self,
        slot: &mut LiveAllocation,
        holder: NatHolder,
        count: ReuseCount,
    ) -> TranslatedTuple {
        slot.holders |= holder.bit();
        if count == ReuseCount::Counted {
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
        }
        slot.translated
    }

    /// #17046: single entry point for every pool allocation. The
    /// `AllocRequest` bundles the dozen positional arguments the three
    /// former `allocate_translation*` wrappers threaded separately, and
    /// the #8447 persistent-admission epilogue lives ONLY here so it
    /// observes EVERY return of `allocate_translation_inner_with_zones`
    /// — including the early config-shape refusals
    /// (`InvalidPortRange`, `WrongAddressFamily`) that sit above the
    /// locked path. Counting inside the body instead would have missed
    /// exactly those, and "declined = 0" would then have been reported
    /// for a pool that refused every flow before it reached the
    /// allocator. Prior to #17046 the epilogue was copy-pasted into
    /// two of three wrappers and the NAT64 persistent mint
    /// (`allocate_translation_with_exclusions`, #16011) carried none.
    pub(super) fn allocate(
        &self,
        req: &AllocRequest<'_>,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let out = self.allocate_translation_inner_with_zones(
            req.flow,
            req.family_addresses,
            req.family_offset,
            req.address_persistent,
            req.persistent.is_some(),
            req.persistent
                .as_ref()
                .map(|p| p.permit)
                .unwrap_or_default(),
            req.persistent.as_ref().map(|p| p.epoch).unwrap_or(0),
            req.persistent.as_ref().map(|p| p.timeout_ns).unwrap_or(0),
            req.now_ns,
            req.mint_from_zone,
            req.holder,
            req.egress_scope,
            req.excluded,
        );
        if req.persistent.is_some() {
            let counter = if out.is_ok() {
                &self.shared.persistent_admitted_total
            } else {
                &self.shared.persistent_declined_total
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }
        out
    }

    /// #8447/#17046: test-only shorthand for `allocate` with no zone and
    /// no probe exclusions. Production callers MUST use `allocate`
    /// directly so the persistent-admission epilogue stays single-sourced;
    /// this wrapper exists only to keep the ~70 test call sites terse.
    #[cfg(test)]
    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    pub(super) fn allocate_translation(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_permit_epoch: u64,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        holder: NatHolder,
        egress_scope: u32,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        self.allocate(&AllocRequest {
            flow,
            family_addresses,
            family_offset,
            address_persistent,
            persistent: persistent_nat.then_some(PersistentParams {
                permit: persistent_nat_permit,
                epoch: persistent_permit_epoch,
                timeout_ns: persistent_nat_timeout_ns,
            }),
            now_ns,
            holder,
            egress_scope,
            mint_from_zone: None,
            excluded: &|_, _| false,
        })
    }

    /// #17046: test-only shorthand for `allocate` with probe exclusions
    /// and no zone. Production NAT64 mint goes through `allocate`
    /// directly (see `allocate_nat64_pool_port_excluding`).
    #[cfg(test)]
    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    pub(super) fn allocate_translation_with_exclusions(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_permit_epoch: u64,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        holder: NatHolder,
        egress_scope: u32,
        excluded: &dyn Fn(usize, u16) -> bool,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        self.allocate(&AllocRequest {
            flow,
            family_addresses,
            family_offset,
            address_persistent,
            persistent: persistent_nat.then_some(PersistentParams {
                permit: persistent_nat_permit,
                epoch: persistent_permit_epoch,
                timeout_ns: persistent_nat_timeout_ns,
            }),
            now_ns,
            holder,
            egress_scope,
            mint_from_zone: None,
            excluded,
        })
    }

    fn allocate_translation_inner_with_zones(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_permit_epoch: u64,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        mint_from_zone: Option<&str>,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
        egress_scope: u32,
        excluded: &dyn Fn(usize, u16) -> bool,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(super::source::SourceNatFailureReason::InvalidPortRange);
        }
        let family_len = family_addresses.len();
        if family_len == 0 {
            return Err(super::source::SourceNatFailureReason::WrongAddressFamily);
        }
        let range = (self.port_high as u32).saturating_sub(self.port_low as u32) + 1;
        if range == 0 || self.shared.max_tracked_flows == 0 {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        self.shared
            .probe_excluded_hit
            .store(false, Ordering::Relaxed);

        // ---- Non-persistent hot path: lock-free port claim, tiny map lock. ----
        //
        // The port claim (forward-probe cursor + bitmap CAS + FIFO recycle) runs
        // WITHOUT the global mutex; the mutex is taken only for the tiny
        // reuse-check + exact-cap-check + `live_by_flow` insert critical section.
        // A GC-of-expired-leases-first pass is preserved for the near-capacity
        // case by falling through to `allocate_translation_locked` when every
        // target address's bitmap is full (the fast, non-GC'd view).
        if !persistent_nat {
            let start_abs =
                self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
            let start_rel = start_abs.saturating_sub(family_offset);
            let address_attempts = if address_persistent { 1 } else { family_len };
            'addresses: for offset in 0..address_attempts {
                let rel = (start_rel + offset) % family_len;
                let abs = family_offset + rel;
                let Some(occ) = self.shared.occupancy.get(abs) else {
                    continue;
                };
                let mut rejected_ports = Vec::new();
                // FOLD (#16350 fold-2/3): excluded + rejected candidates
                // advance the probe key (pat_key ^ attempt), never retry
                // the same keyed port, and never enter the bitmap claim.
                let mut claim_attempt: u64 = 0;
                'ports: loop {
                    let attempt = claim_attempt;
                    claim_attempt += 1;
                    let ex = |off: u32| {
                        let port = occ.port_of(off).unwrap_or(0);
                        let is_excluded = excluded(abs, port);
                        if is_excluded {
                            self.shared
                                .probe_excluded_hit
                                .store(true, Ordering::Relaxed);
                        }
                        is_excluded || rejected_ports.contains(&port)
                    };
                    let claim = occ.claim_filtered_at(
                        Self::pat_key(&flow) ^ occupancy_next_probe(attempt),
                        &ex,
                        now_ns,
                    );
                    let Some(port) = claim else {
                        for rejected_port in rejected_ports.drain(..) {
                            self.free_unpublished_translated_port(abs, rejected_port);
                        }
                        break;
                    };
                    let translated = TranslatedTuple {
                        ip: family_addresses.ip_at(rel),
                        port,
                    };
                    // #4676: run the amortized expiry GC OFF the insert critical
                    // section — chunked, the alloc mutex released between batches,
                    // reclaimed ports freed lock-free. GC touches only the
                    // persistent-lease maps + occupancy while the insert CS below
                    // touches only `live_by_flow`, so the two are disjoint and the
                    // insert CS stays genuinely tiny (the port is already claimed on
                    // the lock-free bitmap, so GC here is opportunistic cleanup, not
                    // load-bearing for this allocation).
                    self.gc_expired_chunked(now_ns, ALLOCATION_GC_BUDGET);
                    // #15956 fold: try the `live` write guard before its flow
                    // shard, then hold both in live->shard order across the
                    // ownership check, exact cap, insert, and PAT-owner update.
                    // A contended try-write releases this claim and falls back
                    // to the serialized path; the try itself is nonblocking,
                    // but the shard mutex and serialized fallback may wait.
                    self.shared
                        .live_write_lock_acquisitions
                        .fetch_add(1, Ordering::Relaxed);
                    let mut live = match self.shared.live.try_write() {
                        Ok(live) => live,
                        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                        Err(TryLockError::WouldBlock) => {
                            self.shared
                                .live_write_lock_contended
                                .fetch_add(1, Ordering::Relaxed);
                            self.free_unpublished_translated_port(abs, port);
                            for rejected_port in rejected_ports.drain(..) {
                                self.free_unpublished_translated_port(abs, rejected_port);
                            }
                            break 'addresses;
                        }
                    };
                    let mut __shard = self.lock_flow_shard_counted(&flow);
                    if let Some(slot) = __shard.map.get_mut(&flow) {
                        // Record this worker as a holder before giving back
                        // the candidate it claimed (#17033 helper).
                        let existing =
                            self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
                        drop(__shard);
                        drop(live);
                        self.free_unpublished_translated_port(abs, port);
                        for rejected_port in rejected_ports.drain(..) {
                            self.free_unpublished_translated_port(abs, rejected_port);
                        }
                        return Ok(existing);
                    }
                    // Exact remote endpoint remains part of the reverse identity.
                    if live.address_only_owns_wire_identity(&flow, translated) {
                        drop(__shard);
                        drop(live);
                        // The colliding port is unavailable to this reverse
                        // identity, but another PAT port on the same address may
                        // still be free. Keep it claimed while probing so the
                        // reuse ring cannot return it to this loop.
                        rejected_ports.push(port);
                        continue 'ports;
                    }
                    // Exact cap (F4) + insert, atomically under the held
                    // shard: count is bumped only on actual insert under
                    // a shard write lock, so this can never overshoot.
                    if !self.shared.flows.try_insert_in_shard(
                        &mut __shard,
                        flow,
                        LiveAllocation {
                            translated,
                            persistent_key: None,
                            addr_index: abs,
                            deterministic: false,
                            address_only: false,
                            // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                            // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                            // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                            // this worker) and each sibling reserves against this same record, so
                            // without this bit the mask holds every worker EXCEPT the one actually
                            // forwarding — and the last sibling replica to age-reap frees a
                            // `(pool_addr, port)` still in use. Recording the owner here makes the
                            // mask complete, so the port survives until the owner itself releases.
                            promotion_timeout_ns: None,
                            holders: holder.bit(),
                        },
                        self.shared.max_tracked_flows,
                    ) {
                        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                        drop(__shard);
                        drop(live);
                        self.free_unpublished_translated_port(abs, port);
                        for rejected_port in rejected_ports.drain(..) {
                            self.free_unpublished_translated_port(abs, rejected_port);
                        }
                        return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
                    }
                    live.record_pat_owner(&flow, translated);
                    drop(__shard);
                    drop(live);
                    self.shared
                        .allocations_total
                        .fetch_add(1, Ordering::Relaxed);
                    for rejected_port in rejected_ports.drain(..) {
                        self.free_unpublished_translated_port(abs, rejected_port);
                    }
                    return Ok(translated);
                }
            }
            // Every target address's bitmap was full on the fast (non-GC'd)
            // view. Fall through to the pressured, GC-first locked path.
        }

        self.allocate_translation_locked(
            flow,
            family_addresses,
            family_offset,
            address_persistent,
            persistent_nat,
            persistent_nat_permit,
            persistent_permit_epoch,
            persistent_nat_timeout_ns,
            now_ns,
            holder,
            egress_scope,
            mint_from_zone,
            excluded,
        )
    }

    /// The persistent-NAT path (lease decision + claim MUST be atomic so two
    /// flows sharing a lease cannot both claim a port) and the non-persistent
    /// near-capacity pressure fallback (bounded expiry GC per address, then
    /// retry). Both hold the global mutex; the port claim uses the same lock-
    /// free bitmap (correctness is unaffected by whether the mutex is held).
    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    fn allocate_translation_locked(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_permit_epoch: u64,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
        egress_scope: u32,
        mint_from_zone: Option<&str>,
        excluded: &dyn Fn(usize, u16) -> bool,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let family_len = family_addresses.len();
        // #15956 fold: shard-first re-check before the write lock.
        // A flow inserted by the shard path while this call was on
        // its way here (bitmap full / persistent) must be answered
        // without the `live` write lock at all; only a genuine
        // miss proceeds to the lease-coupled section below.
        {
            let mut __shard = self.shared.flows.get_mut_shard(&flow);
            if let Some(slot) = __shard.map.get_mut(&flow) {
                let existing = self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
                return Ok(existing);
            }
            if !persistent_nat && self.shared.flows.len() >= self.shared.max_tracked_flows {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
            }
        }
        let mut live = self.lock_live();
        self.gc_expired_locked(&mut live, now_ns, ALLOCATION_GC_BUDGET);

        let mut __shard = self.shared.flows.get_mut_shard(&flow);
        if let Some(slot) = __shard.map.get_mut(&flow) {
            let existing = self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
            return Ok(existing);
        }
        // Fold 2: the len() check is NOT the admission — two
        // shards at cap-1 could both pass it. The atomic admit
        // below (after the permission refusal) is.

        let mut persistent_key =
            persistent_nat.then(|| flow.persistent_source_key(persistent_nat_permit));
        if let Some(key) = persistent_key {
            if live.persistent_by_source.get(&key).is_some_and(|lease| {
                !lease.revoked
                    && (lease.active_flows > 0
                        || lease.inbound_flows > 0
                        || lease.expires_at_ns > now_ns)
                    && live
                        .persistent_permissions
                        .get(&key)
                        .is_some_and(|permissions| {
                            !permissions.can_record(persistent_nat_permit, flow, egress_scope)
                        })
            }) {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
            }
        }
        // Fold 2: claim the tracked-flow slot atomically before
        // any insert on this path (lease-reuse join or fresh
        // mint below both consume it; removal of the record
        // releases it). Racers on other shards lose here, not
        // at a stale len() read.
        if !self.shared.flows.admit_one(self.shared.max_tracked_flows) {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        if let Some(key) = persistent_key {
            match self.reuse_existing_lease_locked(
                &mut live,
                &mut __shard,
                key,
                flow,
                persistent_nat_timeout_ns,
                now_ns,
                holder,
            ) {
                LeaseReuse::Reused(translated) => {
                    live.record_persistent_permission_with_zones(
                        key,
                        persistent_nat_permit,
                        flow,
                        egress_scope,
                        mint_from_zone,
                        persistent_permit_epoch,
                    );
                    return Ok(translated);
                }
                LeaseReuse::NoLease => {}
                // #9536: an ADDRESS-ONLY lease is LIVE for this source -- a
                // `port no-translation` flip under a flow that is still using it.
                // The lease is left standing and this PAT flow is served WITHOUT
                // persistence: it still claims its own occupancy bit below
                // (#8597 K10), but it inserts no lease over the key and joins
                // none, so `unlink_live_allocation_locked` frees that bit when
                // the flow releases (`persistent_key.is_none()`). Without this,
                // the insert below would overwrite the live lease even if the
                // reuse function had kept it -- the #9158 trap.
                LeaseReuse::LiveModeMismatch => persistent_key = None,
                // #10190: an address-only flow already owns the exact reverse
                // identity of the existing PAT lease. Keep that lease pinned,
                // but serve this flow through the fresh unpinned path so it
                // chooses a different available PAT port.
                LeaseReuse::WireIdentityConflict => persistent_key = None,
            }
        }

        // __shard from the reuse check above is still held (uniform
        // live->shard order); the fresh insert below reuses it.
        let start_abs =
            self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
        let start_rel = start_abs.saturating_sub(family_offset);
        let address_attempts = if address_persistent { 1 } else { family_len };
        for offset in 0..address_attempts {
            let rel = (start_rel + offset) % family_len;
            let abs = family_offset + rel;
            if abs >= self.shared.occupancy.len() {
                continue;
            }
            let translated_ip = family_addresses.ip_at(rel);
            if let Some(key) = persistent_key {
                // #16013: per-source fairness gate for a FRESH lease. Runs
                // before any port is claimed on this address attempt so a
                // refused mint leaves no occupancy bit behind; the existing
                // pool-global pressure pass below then runs only when this
                // per-source pass left room.
                if self.persistent_source_lease_capacity_reached(&mut live, &key, now_ns) {
                    continue;
                }
                if live.persistent_by_source.len() >= self.shared.max_tracked_flows {
                    // Lease-table pressure is also budgeted. A full persistent
                    // table gets one global PRESSURE_GC_BUDGET pass before this
                    // address attempt is treated as unavailable.
                    self.gc_expired_locked(&mut live, now_ns, PRESSURE_GC_BUDGET);
                    if live.persistent_by_source.len() >= self.shared.max_tracked_flows {
                        continue;
                    }
                }
            }

            let mut rejected_ports = Vec::new();
            let mut claim_attempt: u64 = 0;
            'ports: loop {
                let attempt = claim_attempt;
                claim_attempt += 1;
                let ex = |off: u32| {
                    let port = self.shared.occupancy[abs].port_of(off).unwrap_or(0);
                    let is_excluded = excluded(abs, port);
                    if is_excluded {
                        self.shared
                            .probe_excluded_hit
                            .store(true, Ordering::Relaxed);
                    }
                    is_excluded || rejected_ports.contains(&port)
                };
                let mut port = self.shared.occupancy[abs].claim_filtered_at(
                    Self::pat_key(&flow) ^ occupancy_next_probe(attempt),
                    &ex,
                    now_ns,
                );
                if port.is_none() {
                    // Pressure handling is budgeted, not strict O(1). A
                    // non-address-persistent full family can visit each
                    // family-compatible address and run at most
                    // PRESSURE_GC_BUDGET expiry checks for that selected
                    // address before declaring exhaustion.
                    self.gc_expired_for_addr_locked(&mut live, abs, now_ns, PRESSURE_GC_BUDGET);
                    port = self.shared.occupancy[abs].claim_filtered_at(
                        Self::pat_key(&flow) ^ occupancy_next_probe(claim_attempt),
                        &ex,
                        now_ns,
                    );
                    claim_attempt += 1;
                }
                let Some(port) = port else {
                    for rejected_port in rejected_ports.drain(..) {
                        self.free_unpublished_translated_port(abs, rejected_port);
                    }
                    break;
                };
                let translated = TranslatedTuple {
                    ip: translated_ip,
                    port,
                };
                // #10190: the address-only token is a second ownership domain
                // inside this allocator. Treat its exact reverse identity as
                // occupied before a PAT record or persistent lease is inserted.
                if live.address_only_owns_wire_identity(&flow, translated) {
                    // Keep colliding claims held while probing so the reuse ring
                    // cannot return the same rejected port indefinitely.
                    rejected_ports.push(port);
                    continue 'ports;
                }
                if let Some(key) = persistent_key {
                    let timeout_ns = bounded_persistent_nat_timeout_ns(persistent_nat_timeout_ns);
                    let expires_at_ns = now_ns.saturating_add(timeout_ns);
                    // Keep the clear fence through its original deadline. The
                    // fresh lease remains local truth while it exists; peer
                    // imports stay fenced if it expires before the window.
                    live.insert_persistent_lease(
                        key,
                        PersistentLease {
                            translated,
                            incarnation: 0,
                            addr_index: abs,
                            expires_at_ns,
                            timeout_ns,
                            active_flows: 1,
                            inbound_flows: 0,
                            completed_flows: 0,
                            activation_saw_completion: false,
                            activation_previous_expires_at_ns: 0,
                            activation_had_previous_lease: false,
                            activation_previous_timeout_ns: 0,
                            address_only: false,
                            deterministic: false,
                            deterministic_identity: None,
                            // #10789-F4: minted by a local lookup — exportable.
                            imported: false,
                            revoked: false,
                        },
                    );
                    live.record_persistent_permission_with_zones(
                        key,
                        persistent_nat_permit,
                        flow,
                        egress_scope,
                        mint_from_zone,
                        persistent_permit_epoch,
                    );
                }
                self.shared.flows.insert_in_shard(
                    &mut __shard,
                    flow,
                    LiveAllocation {
                        translated,
                        persistent_key,
                        addr_index: abs,
                        deterministic: false,
                        address_only: false,
                        // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                        // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                        // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                        // this worker) and each sibling reserves against this same record, so
                        // without this bit the mask holds every worker EXCEPT the one actually
                        // forwarding — and the last sibling replica to age-reap frees a
                        // `(pool_addr, port)` still in use. Recording the owner here makes the
                        // mask complete, so the port survives until the owner itself releases.
                        promotion_timeout_ns: None,
                        holders: holder.bit(),
                    },
                );
                live.record_pat_owner(&flow, translated);
                self.shared
                    .allocations_total
                    .fetch_add(1, Ordering::Relaxed);
                for rejected_port in rejected_ports.drain(..) {
                    self.free_unpublished_translated_port(abs, rejected_port);
                }
                return Ok(translated);
            }
        }

        self.shared.flows.unadmit_one();
        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(super::source::SourceNatFailureReason::AllocatorExhausted)
    }

    /// #2397 persistent-NAT lease reuse, run under the live-state lock as the
    /// first persistent-key step of `allocate_translation_locked`.
    ///
    /// When a lease already exists for `key`:
    ///   - a still-valid lease (an active flow, or one whose inactivity timeout
    ///     has not yet elapsed) is REUSED — on the 0 -> 1 active-flow edge its
    ///     activation-rollback bookkeeping is re-armed and its old expiry index
    ///     entry is dropped, its inactivity expiry is pushed out, the flow is
    ///     recorded in `live_by_flow`, `reuses_total` is bumped, and the reused
    ///     translated tuple is returned as `Some(_)` (the caller returns it
    ///     directly);
    ///   - an expired lease is torn down (expiry index entry removed, translated
    ///     tuple released, lease dropped) and `None` is returned so the caller
    ///     falls through to a fresh allocation.
    ///
    /// Returns `None` when no lease exists for `key` or the lease was expired and
    /// reclaimed.
    fn reuse_existing_lease_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        shard: &mut flows::LiveFlowShard,
        key: PersistentSourceKey,
        flow: SourceNatFlowKey,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
    ) -> LeaseReuse {
        if let Some(lease) = live.persistent_by_source.get(&key).copied() {
            if lease.revoked {
                if lease.active_flows != 0 || lease.inbound_flows != 0 {
                    return LeaseReuse::LiveModeMismatch;
                }
                // A revoked idle shell retires before a fresh same-key
                // insert can overwrite its only ownership record
                // (#17028: shared retire; clocked free preserved).
                if let Some(retired) =
                    lease_table::retire_idle_lease_locked(live, &key)
                {
                    if let Some((addr_index, port)) = retired.freed_port {
                        self.free_translated_port_at(addr_index, port, now_ns);
                    }
                }
                return LeaseReuse::NoLease;
            }
        }
        if !live.persistent_by_source.contains_key(&key) {
            return LeaseReuse::NoLease;
        }
        // #10190: joining an existing PAT lease is another PAT admission
        // path, so it must check the same-allocator address-only index before
        // mutating the lease. This catches an idle lease (still within its
        // timeout) and a live lease whose prior flow used another remote.
        if let Some(lease) = live.persistent_by_source.get(&key) {
            if !lease.address_only
                && (lease.active_flows > 0
                    || lease.inbound_flows > 0
                    || lease.expires_at_ns > now_ns)
                && live.address_only_owns_wire_identity(&flow, lease.translated)
            {
                return LeaseReuse::WireIdentityConflict;
            }
        }
        // #8597 K10: the lease's MODE must agree with this port-bearing
        // path. An ADDRESS-ONLY lease owns no occupancy bit, so reusing
        // it here would publish a PAT decision `(A, S)` with NO bit
        // held (#9536: a LIVE one is left standing; an IDLE one is
        // retired mode-correctly below). Mode can flip under a live
        // lease by ordinary operator action (`allocator_key()` does
        // not include `no_translation`).
        let local_timeout_ns = bounded_persistent_nat_timeout_ns(persistent_nat_timeout_ns);
        let lease = live.persistent_by_source.get(&key).copied();
        match lease {
            Some(lease)
                if !lease.address_only
                    && (lease.active_flows > 0
                        || lease.inbound_flows > 0
                        || lease.expires_at_ns > now_ns) =>
            {
                // #17028: the shared 0->1 / N->N+1 join (snapshot,
                // de-index, timeout/promotion, refcount).
                let lease_table::JoinOutcome::Joined {
                    translated,
                    addr_index,
                    promotion_timeout_ns,
                    ..
                } = lease_table::join_persistent_lease_locked(
                    live,
                    key,
                    lease_table::JoinPolicy {
                        timeout_ns: local_timeout_ns,
                        promote_imported: true,
                        refresh_expiry: true,
                    },
                    now_ns,
                )
                else {
                    return LeaseReuse::NoLease;
                };
                self.shared.flows.insert_in_shard(
                    shard,
                    flow,
                    LiveAllocation {
                        translated,
                        persistent_key: Some(key),
                        addr_index,
                        deterministic: false,
                        address_only: false,
                        promotion_timeout_ns,
                        holders: holder.bit(),
                    },
                );
                live.record_pat_owner(&flow, translated);
                self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
                return LeaseReuse::Reused(translated);

            }
            Some(lease)
                if lease.address_only
                    && (lease.active_flows > 0 || lease.inbound_flows > 0) =>
            {
                // #9536: leave the live address-only lease standing;
                // the caller serves this flow unpinned.
                return LeaseReuse::LiveModeMismatch;
            }
            Some(_) => {
                // Expired or idle mode-mismatched: retire mode-
                // correctly (#17028 shared retire) and mint fresh.
                if let Some(retired) = lease_table::retire_idle_lease_locked(live, &key) {
                    if let Some((addr_index, port)) = retired.freed_port {
                        self.free_translated_port_at(addr_index, port, now_ns);
                    }
                }
                LeaseReuse::NoLease
            }
            None => LeaseReuse::NoLease,
        }
    }
    /// does, or an imported lease is invisible to GC and outlives what the
    /// active node held.
    pub(super) fn insert_lease_expiration_locked(
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        expires_at_ns: u64,
        key: PersistentSourceKey,
    ) {
        live.lease_expirations.insert((expires_at_ns, key));
        if let Some(by_addr) = live.lease_expirations_by_addr.get_mut(addr_index) {
            by_addr.insert((expires_at_ns, key));
        }
    }
    /// Retire stale idle leases before HA admission. Revoked active shells
    /// remain owned until their final flow releases.
    /// #17028: the predicate + removal live in `lease_table`; this
    /// wrapper keeps the clocked bitmap free (stamped at `now_ns`).
    pub(super) fn reclaim_expired_idle_lease_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        key: PersistentSourceKey,
        now_ns: u64,
    ) -> bool {
        let Some(retired) =
            lease_table::reclaim_expired_idle_lease_locked(live, key, now_ns)
        else {
            return false;
        };
        if let Some((addr_index, port)) = retired.freed_port {
            self.free_translated_port_at(addr_index, port, now_ns);
        }
        true
    }

    pub(super) fn remove_lease_expiration_locked(
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        expires_at_ns: u64,
        key: PersistentSourceKey,
    ) {
        live.lease_expirations.remove(&(expires_at_ns, key));
        if let Some(by_addr) = live.lease_expirations_by_addr.get_mut(addr_index) {
            by_addr.remove(&(expires_at_ns, key));
        }
    }

    /// #6211 F2: drop `holder` from a reservation's holder set and report
    /// whether the reservation must SURVIVE this release.
    ///
    /// Returns `true` when other workers still hold the flow, in which case the
    /// caller returns without touching `live_by_flow`, the occupancy bitmap, the
    /// persistent lease, or the address-only reverse-identity token — the port
    /// stays claimed for the holders that remain.
    ///
    /// Returns `false` (proceed to free) in exactly two cases:
    ///   - `holders == 0`, an untracked record — one nothing has ever claimed a
    ///     bit on. #7093: an earlier revision of this line justified that arm
    ///     with "RSS steers a 5-tuple to one worker, so a local allocation has a
    ///     single holder by construction". **That premise is false and #6522
    ///     refuted it**: a locally-born session is replicated to every OTHER
    ///     worker (`replicate_session_upsert` over `peer_worker_commands`, a
    ///     list built with `.filter(|(id, _)| **id != worker_id)`), and
    ///     `SessionOrigin::is_peer_synced()` is TRUE for `WorkerLocalImport`, so
    ///     every sibling reserved and took a bit on the owner's record while the
    ///     owner held none. Since #6522 the allocating worker records its own
    ///     bit, so no PRODUCTION path reaches this arm any more — every reserve
    ///     names a `Worker(id)`. It survives for the `#[cfg(test)]` entry points
    ///     and the read-only fragment probe, which pass `Untracked`.
    ///   - clearing this holder's bit empties the mask: the LAST worker holding
    ///     the reservation is releasing it.
    ///
    /// [`NatHolder::Untracked`] contributes no bit, so an untracked release of a
    /// TRACKED reservation keeps it. That is the deliberate direction for a
    /// release site that was never taught its worker id: an under-release leaks
    /// a pool port (bounded, observable as `AllocatorExhausted`), whereas an
    /// over-release hands a live worker's `(pool_addr, port)` to a new flow —
    /// the NAT source collision this whole mechanism exists to prevent.
    fn drop_holder_locked(
        flows: &flows::LiveFlowMap,
        shard: &mut flows::LiveFlowShard,
        flow: &SourceNatFlowKey,
        existing: LiveAllocation,
        holder: NatHolder,
    ) -> bool {
        flows.drop_holder_in_shard(shard, flow, existing, holder.bit())
    }

    /// #6528: unlink ONE flow's `live_by_flow` record, applying the teardown its
    /// allocation MODE requires. This is the half of a teardown that is
    /// IDENTICAL across all THREE paths that retire a record — `release_flow`,
    /// `rollback_flow`, and `reserve_flow`'s stale-tuple eviction — and it exists
    /// so a fourth cannot diverge from the other three.
    ///
    /// Three modes, three different obligations, and getting the mode wrong is
    /// not a no-op — it mutates state belonging to an UNRELATED flow:
    ///
    ///   - ADDRESS-ONLY (`port no-translation` / port-less, #5269/#6041): owns
    ///     NO occupancy bit. `addr_index` names its pool address (#14622;
    ///     interface-mode records use 0, their only address) and `translated.port`
    ///     is the PRESERVED internal source port, so calling
    ///     `free_translated_port` on it clears whatever bit pool address 0
    ///     happens to hold at that offset — which, when a PAT rule shares the
    ///     allocator (`allocator_key()` is pool name + addresses + port range;
    ///     it does NOT include `no_translation`), is a LIVE PAT flow's port, and
    ///     `free_recycle` then hands it to the next allocation. What it owns
    ///     instead is the reverse-identity token in `address_only_owners`, which
    ///     must be cleared or that public identity is denied forever.
    ///   - PERSISTENT (`persistent_key = Some`): the port/address belongs to the
    ///     LEASE, not the flow. Freeing the bit here hands out a port the lease
    ///     still claims. Only the lease teardown frees it — see the caller-owned
    ///     lease arms below.
    ///   - Plain PAT / deterministic: owns its port outright — free the bit
    ///     and recycle it (#14625).
    ///
    /// The LEASE arm is deliberately NOT here: `release_flow` completes a flow
    /// (bump `completed_flows`, refresh the idle expiry) while `rollback_flow`
    /// undoes an activation (restore or remove the lease). Each caller runs its
    /// own; this helper owns only what they share.
    fn unlink_live_allocation_captured(
        &self,
        live: &mut CapturedLiveGuard<'_>,
        flow: &SourceNatFlowKey,
        existing: LiveAllocation,
        now_ns: u64,
    ) {
        self.unlink_live_allocation_locked(&mut live.live, &mut live.shard, flow, existing, now_ns);
    }

    fn unlink_live_allocation_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        shard: &mut flows::LiveFlowShard,
        flow: &SourceNatFlowKey,
        existing: LiveAllocation,
        now_ns: u64,
    ) {
        self.shared.flows.remove_in_shard(shard, flow);
        // #6041: the address-only reverse-identity token (#5269) is orthogonal
        // to the persistent lease — it exists for BOTH a non-persistent
        // address-only flow AND an address-only PERSISTENT flow
        // (`persistent_key = Some` AND `address_only = true`). The key mirrors
        // what `reserve_address_only` / `reserve_address_only_roundrobin` /
        // `reserve_address_only_persistent` inserted (stored translated tuple +
        // the flow's remote endpoint).
        if existing.address_only {
            live.remove_address_only_owner(&AddressOnlyReverseKey {
                protocol: flow.protocol,
                translated_ip: existing.translated.ip,
                translated_port: existing.translated.port,
                dst_ip: flow.dst_ip,
                dst_port: flow.dst_port,
            });
        } else {
            // #10190: keep the O(1) same-allocator PAT identity index in
            // lockstep with the shared live-record teardown. Persistent NAT
            // decrements a count because several flows may share one tuple.
            live.remove_pat_owner(flow, existing.translated);
        }
        if existing.persistent_key.is_none() && !existing.address_only {
            self.free_translated_port_at(existing.addr_index, existing.translated.port, now_ns);
        }
    }

    /// #6528: the RELEASE-semantics persistent-lease arm — a flow that WAS in
    /// service on this translation has finished with it.
    ///
    /// Shared by `release_flow` and `reserve_flow`'s stale-tuple eviction: an
    /// evicted reservation was in service on the tuple it is being replaced on,
    /// so the flow completed on it. Dropping the refcount is what makes the
    /// lease reclaimable — a leaked refcount is never idle, so the lease never
    /// enters `lease_expirations` and NO GC path can reclaim it.
    ///
    /// No-op for a non-persistent record.
    fn complete_persistent_lease_locked(
        live: &mut PortAllocatorLiveState,
        existing: LiveAllocation,
        now_ns: u64,
    ) {
        let Some(key) = existing.persistent_key else {
            return;
        };
        let mut refresh_expiry = None;
        let revoked_until_ns = live.revoked_persistent.get(&key).copied();
        let mut revoked = false;
        if let Some(lease) = live.persistent_by_source.get_mut(&key) {
            revoked = lease.revoked;
            lease.completed_flows = lease.completed_flows.saturating_add(1);
            lease.activation_saw_completion = true;
            lease.active_flows = lease.active_flows.saturating_sub(1);
            if lease.active_flows == 0 && lease.inbound_flows == 0 {
                let old_expires_at_ns = lease.expires_at_ns;
                let expires_at_ns = if revoked {
                    now_ns
                } else {
                    now_ns.saturating_add(lease.timeout_ns)
                };
                lease.expires_at_ns = expires_at_ns;
                refresh_expiry = Some((lease.addr_index, old_expires_at_ns, expires_at_ns));
            }
        }
        if revoked
            && revoked_until_ns == Some(ACTIVE_PERSISTENT_NAT_CLEAR_TOMBSTONE_NS)
            && refresh_expiry.is_some()
        {
            live.revoked_persistent.insert(
                key,
                now_ns.saturating_add(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS),
            );
        }
        if let Some((addr_index, old_expires_at_ns, expires_at_ns)) = refresh_expiry {
            Self::remove_lease_expiration_locked(live, addr_index, old_expires_at_ns, key);
            Self::insert_lease_expiration_locked(live, addr_index, expires_at_ns, key);
        }
    }

    #[cfg(test)]
    pub(crate) fn debug_persistent_lease_for_flow(
        &self,
        flow: &SourceNatFlowKey,
        permit: super::source::PersistentNatPermit,
    ) -> Option<PersistentLeaseDebugState> {
        let key = flow.persistent_source_key(permit);
        let live = self.lock_live();
        let lease = *live.persistent_by_source.get(&key)?;
        Some(PersistentLeaseDebugState {
            translated: lease.translated,
            incarnation: lease.incarnation,
            addr_index: lease.addr_index,
            expires_at_ns: lease.expires_at_ns,
            timeout_ns: lease.timeout_ns,
            active_flows: lease.active_flows,
            inbound_flows: lease.inbound_flows,
            completed_flows: lease.completed_flows,
            activation_saw_completion: lease.activation_saw_completion,
            activation_previous_expires_at_ns: lease.activation_previous_expires_at_ns,
            activation_had_previous_lease: lease.activation_had_previous_lease,
            activation_previous_timeout_ns: lease.activation_previous_timeout_ns,
            address_only: lease.address_only,
            deterministic: lease.deterministic,
            deterministic_identity: lease.deterministic_identity,
            imported: lease.imported,
        })
    }

    /// Test-only: the worker-holder mask recorded for a live flow.
    #[cfg(test)]
    pub(crate) fn holder_mask_for_flow(&self, flow: &SourceNatFlowKey) -> Option<u128> {
        self.shared
            .flows
            .get(flow)
            .map(|allocation| allocation.holders)
    }

    pub(super) fn release_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        now_ns: u64,
        holder: NatHolder,
    ) -> bool {
        // #15956: `live` THEN the flow's shard; both are held for
        // the whole release so the record, its holder mask and the
        // lease/index side effects move as one critical section.
        let mut live = self.lock_live();
        let mut __shard = self.shared.flows.get_mut_shard(&flow);
        let Some(existing) = self.shared.flows.get_in_shard(&__shard, &flow) else {
            return false;
        };
        if existing.translated != translated {
            return false;
        }
        if existing.persistent_key.is_none() {
            if Self::drop_holder_locked(&self.shared.flows, &mut __shard, &flow, existing, holder) {
                return false;
            }
            self.unlink_live_allocation_locked(&mut live, &mut __shard, &flow, existing, now_ns);
            live.gc_counter = live.gc_counter.wrapping_add(1);
            let run_gc = live.gc_counter % GC_PERIOD == 0;
            drop(__shard);
            drop(live);
            if run_gc {
                self.gc_expired_chunked(now_ns, RELEASE_GC_BUDGET);
            }
            return true;
        }
        if Self::drop_holder_locked(&self.shared.flows, &mut __shard, &flow, existing, holder) {
            return false;
        }
        self.unlink_live_allocation_locked(&mut live, &mut __shard, &flow, existing, now_ns);
        // Q2 ownership transfers only on the ordinary final-holder release.
        // Keep this out of the shared completion helper: stale-tuple eviction
        // and worker retirement also use that helper but are not local proof.
        if let (Some(key), Some(timeout_ns)) =
            (existing.persistent_key, existing.promotion_timeout_ns)
        {
            if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                lease.imported = false;
                lease.timeout_ns = timeout_ns;
            }
        }
        Self::complete_persistent_lease_locked(&mut live, existing, now_ns);
        live.gc_counter = live.gc_counter.wrapping_add(1);
        let run_gc = live.gc_counter % GC_PERIOD == 0;
        // #4676: drop the release guard BEFORE the periodic idle-lease sweep so
        // the (up to RELEASE_GC_BUDGET) sweep runs chunked with the alloc mutex
        // released between batches instead of blocking concurrent allocations
        // for the whole sweep. The release mutations above are already committed
        // under this guard, so the GC re-locking a fresh guard observes them.
        drop(__shard);
        drop(live);
        if run_gc {
            self.gc_expired_chunked(now_ns, RELEASE_GC_BUDGET);
        }
        true
    }
    /// free any record the clear empties. Returns the number of records freed.
    ///
    /// THE LEAK THIS EXISTS FOR. A bit is SET on reserve and cleared only when
    /// that same worker later runs its own release. A worker that never runs one
    /// strands every reservation it holds for the life of the allocator, and
    /// both ways that happens are reachable:
    ///
    ///   * PANIC. `spawn_supervised_worker` (`coordinator/supervisor.rs`)
    ///     catches the unwind, sets `runtime_atomics.dead = true` and lets the
    ///     thread exit. Nothing respawns it — the only other consumer of `.dead`
    ///     is `coordinator/status.rs`, which REPORTS it — so its `SessionTable`
    ///     dies with the thread and never reaps.
    ///   * REPLAN. `worker_id` is minted as `queue_id % workers`
    ///     (`server/helpers/planning.rs`), so a plan that shrinks the worker set
    ///     retires ids that still hold bits. The allocator itself is carried
    ///     forward across the reload by `parse_source_nat_rules_with_previous`,
    ///     so the bits survive with it.
    ///
    /// There is no sweep, no TTL and no reconcile that clears them, so the pool
    /// addresses' occupancy bitmap never gets those ports back and SNAT for new
    /// flows eventually fails `AllocatorExhausted`.
    ///
    /// WHY THIS IS SAFE TO DO, and why it would NOT have been before #6522.
    /// Clearing one holder's bit is only sound if an empty mask really means no
    /// live holder remains. Under #6211 F2 it did not: the allocating worker
    /// recorded NO bit, so the mask named every worker EXCEPT the one actually
    /// forwarding, and emptying it would have freed a `(pool_addr, port)` still
    /// in use — the over-release this whole mechanism exists to prevent. #6522
    /// made the owner a holder of its own allocation, so an empty mask now means
    /// exactly what it says. This function is the last-holder release path
    /// applied to a worker that will never call it.
    ///
    /// UNTRACKED RECORDS ARE NOT TOUCHED. `holders == 0` is a record no worker
    /// ever claimed; `bit & 0 == 0`, so the filter below skips it and no
    /// `Untracked` allocation can be freed by a retirement it never joined.
    ///
    /// WIRED SINCE #6979, for the PANIC route only. The call site is the 1 Hz
    /// status tick, which this doc previously named as the candidate with a
    /// hazard: it "would walk `live_by_flow` under the alloc mutex on every tick
    /// unless it also carries 'already retired' state". It now carries exactly
    /// that -- `WorkerRuntimeAtomics::holders_retired`, a one-shot
    /// compare-and-swap -- so the sweep runs ONCE per dead worker and every
    /// later tick pays one relaxed atomic load per record and stops.
    ///
    /// THE REPLAN ROUTE IS STILL NOT COVERED, and that is stated rather than
    /// implied. `worker_id` is minted as `queue_id % workers`
    /// (`server/helpers/planning.rs`), so a plan that SHRINKS the worker set
    /// retires ids that still hold bits, and the allocator is carried across the
    /// reload by `parse_source_nat_rules_with_previous` so the bits survive with
    /// it. That route sets NO flag -- not `dead`, not anything -- so there is no
    /// signal for this sweep to react to, and the plan-application path that
    /// knows the retired ids does not hold the allocator. Closing it needs a
    /// signal that does not exist yet, which is why it is not in #6979.
    pub(crate) fn retire_worker(&self, worker_id: u32, now_ns: u64) -> usize {
        // An id too wide for the mask never SET a bit, so it holds nothing to
        // clear. Checked HERE rather than through `NatHolder::bit()`, whose
        // `debug_assert!` would fire on the very id this arm exists to tolerate.
        // `planning.rs` refuses a plan that would mint one, so this is a
        // total-function guard rather than a live case.
        //
        // ITS VALUE IS PROFILE-DEPENDENT, measured rather than assumed. In a
        // RELEASE build it is redundant: `debug_assert!` is compiled out and
        // `1u128.checked_shl(id >= 128)` returns `None` -> `unwrap_or(0)`, so the
        // `holders & 0 != 0` filter matches nothing and the walk frees nothing
        // anyway. Deleting these three lines leaves the whole release suite green
        // (mutation cell M3). In a DEBUG profile the `debug_assert!` panics, so
        // the guard is what keeps this function total there. Stated because the
        // boundary assertion in
        // `retire_worker_is_idempotent_and_ignores_out_of_range_ids_7092`
        // documents that intent without binding it under `make test-rust`, which
        // runs `--release`.
        if worker_id >= MAX_NAT_HOLDER_WORKERS {
            return 0;
        }
        let bit = NatHolder::Worker(worker_id).bit();
        let mut live = self.lock_live();
        let held: Vec<(SourceNatFlowKey, LiveAllocation)> = self
            .shared
            .flows
            .entries()
            .into_iter()
            .filter(|(_, alloc)| alloc.holders & bit != 0)
            .collect();
        let mut freed = 0usize;
        for (flow, existing) in held {
            let remaining = existing.holders & !bit;
            if remaining != 0 {
                let mut __shard = self.shared.flows.get_mut_shard(&flow);
                if let Some(slot) = __shard.map.get_mut(&flow) {
                    slot.holders = remaining;
                }
                continue;
            }
            // Last holder retired: the same unlink + lease completion
            // `release_flow` performs, so the two cannot drift.
            let mut __shard = self.shared.flows.get_mut_shard(&flow);
            self.unlink_live_allocation_locked(&mut live, &mut __shard, &flow, existing, now_ns);
            drop(__shard);
            Self::complete_persistent_lease_locked(&mut live, existing, now_ns);
            freed += 1;
        }
        freed
    }

    pub(super) fn rollback_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        now_ns: u64,
        holder: NatHolder,
    ) -> bool {
        let mut live = self.lock_live();
        let mut __shard = self.shared.flows.get_mut_shard(&flow);
        let Some(existing) = self.shared.flows.get_in_shard(&__shard, &flow) else {
            return false;
        };
        if existing.translated != translated {
            return false;
        }
        if Self::drop_holder_locked(&self.shared.flows, &mut __shard, &flow, existing, holder) {
            return false;
        }
        // #6528: the shared mode-correct unlink. Rollback keeps its OWN lease
        // arm below — it undoes an activation rather than completing a flow.
        self.unlink_live_allocation_locked(&mut live, &mut __shard, &flow, existing, now_ns);
        drop(__shard);
        if let Some(key) = existing.persistent_key {
            let mut remove_lease = false;
            let revoked = live
                .persistent_by_source
                .get(&key)
                .is_some_and(|lease| lease.revoked);
            let mut insert_expiry = None;
            if let Some(lease) = live.persistent_by_source.get_mut(&key) {
                lease.active_flows = lease.active_flows.saturating_sub(1);
                if lease.active_flows == 0 && lease.inbound_flows == 0 {
                    if revoked {
                        lease.expires_at_ns = now_ns;
                        insert_expiry = Some((lease.addr_index, now_ns));
                    } else if lease.activation_saw_completion {
                        let expires_at_ns = now_ns.saturating_add(lease.timeout_ns);
                        lease.expires_at_ns = expires_at_ns;
                        insert_expiry = Some((lease.addr_index, expires_at_ns));
                    } else if lease.activation_had_previous_lease {
                        lease.expires_at_ns = lease.activation_previous_expires_at_ns;
                        lease.timeout_ns = lease.activation_previous_timeout_ns;
                        insert_expiry = Some((lease.addr_index, lease.expires_at_ns));
                    } else {
                        remove_lease = true;
                    }
                }
            }
            if revoked
                && live
                    .persistent_by_source
                    .get(&key)
                    .is_some_and(|lease| lease.active_flows == 0 && lease.inbound_flows == 0)
            {
                live.revoked_persistent.insert(
                    key,
                    now_ns.saturating_add(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS),
                );
            }
            if remove_lease {
                live.remove_persistent_lease(&key);
                // #6041: an address-only lease holds no pool port bit — only a
                // PAT lease frees its port when the fresh-activation rollback
                // removes it.
                if !existing.address_only {
                    self.free_translated_port_at(existing.addr_index, translated.port, now_ns);
                }
            }
            if let Some((addr_index, expires_at_ns)) = insert_expiry {
                Self::insert_lease_expiration_locked(&mut live, addr_index, expires_at_ns, key);
            }
        }
        true
    }

    /// #4559: allocate a deterministic CGNAT port from the subscriber's fixed
    /// block. The external pool IP and the port block are a pure function of the
    /// subscriber's internal IPv4 address (`deterministic_indices_v4`), so the
    /// `(external IP, port)` → subscriber reverse mapping needs no per-flow log.
    /// A live flow re-allocates its existing tuple (reuse); a fresh flow claims
    /// the first free port in `[port_start, port_end]` via the occupancy bitmap
    /// (collision-free CAS). Unlike round-robin PAT this does NOT touch the
    /// per-address fresh cursor, the recycle queue, or persistent leases — a
    /// deterministic pool is mutually exclusive with persistent-nat /
    /// address-persistent (enforced at commit). Returns the subscriber-out-of-
    /// range / exhaustion failure to the caller instead of silently falling back
    /// to round-robin.
    pub(super) fn allocate_deterministic_v4(
        &self,
        flow: SourceNatFlowKey,
        pool_v4: &[Ipv4Addr],
        params: DeterministicV4,
        src: Ipv4Addr,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        use super::source::SourceNatFailureReason;
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(SourceNatFailureReason::InvalidPortRange);
        }
        let (ip_idx, block_idx) = deterministic_indices_v4(&params, src)
            .ok_or(SourceNatFailureReason::DeterministicSubscriberOutOfRange)?;
        if ip_idx >= pool_v4.len() || ip_idx >= self.shared.occupancy.len() {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let translated_ip = IpAddr::V4(pool_v4[ip_idx]);
        // Block boundaries: [port_low + block_idx*block_size,
        // that + block_size - 1], clamped to port_high. Widths align with the Go
        // compiler because both use the SAME defaulted port range.
        let port_start = self.port_low as u32 + block_idx * params.block_size as u32;
        if port_start > self.port_high as u32 {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let port_end = (port_start + params.block_size as u32 - 1).min(self.port_high as u32);

        // #9130: the block probe runs BEFORE the mutex is taken, and every
        // critical section below it is O(1) — the shape #4676 gave the sibling
        // PAT path (`allocate_translation_inner`), which the deterministic arms
        // never received. Holding the map mutex across the linear scan made the
        // hold time O(occupied prefix of the block), so one subscriber near its
        // own block budget serialized every other flow through this pool.
        //
        // Claim the first free port in the subscriber's block, LOCK-FREE: the
        // occupancy bitmap is CAS-based and lives outside the map mutex, and
        // nothing above this point takes the mutex, so no thread ever holds it
        // across the scan. #9902 F-098: word-skipping probe — one load per
        // fully-occupied word instead of one CAS per occupied port; the claimed
        // port is still the first free one, ascending.
        // (`port_start`/`port_end` are clamped to `port_high <= u16::MAX` above,
        // so the narrowing casts cannot truncate — the same casts the naive
        // per-port loop made.)
        // Claim ports in the subscriber's block in ascending order, LOCK-FREE.
        // If an address-only token owns the candidate's reverse identity, skip
        // that port and continue the same block; exhaustion is reported only
        // after every candidate has been considered. The cursor avoids a
        // temporary rejected-port allocation, and rejected bitmap claims are
        // released without recycling.
        let mut probe_start = Some(port_start as u16);
        loop {
            let claimed = probe_start.and_then(|start| {
                self.shared.occupancy[ip_idx].claim_in_block(start, port_end as u16)
            });
            let Some(port) = claimed else {
                // No usable free port remains in the subscriber's block. A live
                // flow may own its only occupied port, so check idempotent reuse
                // before reporting exhaustion.
                let _live = self.lock_live();
                let mut __shard = self.shared.flows.get_mut_shard(&flow);
                if let Some(slot) = __shard.map.get_mut(&flow) {
                    let existing = self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
                    return Ok(existing);
                }
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(SourceNatFailureReason::AllocatorExhausted);
            };
            let translated = TranslatedTuple {
                ip: translated_ip,
                port,
            };

            // Insert critical section: O(1). The idempotency check lives here
            // rather than before the probe, because probing is lock-free.
            let mut live = self.lock_live();
            let mut __shard = self.shared.flows.get_mut_shard(&flow);
            if let Some(slot) = __shard.map.get_mut(&flow) {
                // Give back the port we just claimed through the normal
                // recycling free (#14625, as on the v6 twin: the ring is
                // bounded and `claim_in_block` ignores it; a later PAT
                // phase on this allocator needs it).
                let existing = self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
                drop(live);
                self.free_translated_port(ip_idx, port);
                return Ok(existing);
            }
            // #10190: deterministic PAT claims only the bitmap. Reject a
            // same-allocator address-only token for this exact reverse identity,
            // then probe the next candidate in this subscriber's block (#10721).
            if live.address_only_owns_wire_identity(&flow, translated) {
                drop(live);
                self.free_translated_port(ip_idx, port);
                probe_start = port.checked_add(1);
                continue;
            }
            if !self.shared.flows.admit_one(self.shared.max_tracked_flows) {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                drop(live);
                self.free_translated_port(ip_idx, port);
                return Err(SourceNatFailureReason::AllocatorExhausted);
            }
            self.shared.flows.insert_in_shard(
                &mut __shard,
                flow,
                LiveAllocation {
                    translated,
                    persistent_key: None,
                    addr_index: ip_idx,
                    deterministic: true,
                    address_only: false,
                    // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                    // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                    // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                    // this worker) and each sibling reserves against this same record, so
                    // without this bit the mask holds every worker EXCEPT the one actually
                    // forwarding — and the last sibling replica to age-reap frees a
                    // `(pool_addr, port)` still in use. Recording the owner here makes the
                    // mask complete, so the port survives until the owner itself releases.
                    promotion_timeout_ns: None,
                    holders: holder.bit(),
                },
            );
            drop(__shard);
            live.record_pat_owner(&flow, translated);
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(translated);
        }
    }

    pub(crate) fn deterministic_v6_tuple_matches(
        &self,
        params: DeterministicV6,
        src: Ipv6Addr,
        pool_v4: &[Ipv4Addr],
        addr_index: usize,
        translated_ip: Ipv4Addr,
        port: u16,
    ) -> bool {
        let Some((expected_index, block_index)) = deterministic_indices_v6(&params, src) else {
            return false;
        };
        if expected_index != addr_index
            || pool_v4.get(expected_index) != Some(&translated_ip)
            || expected_index >= self.shared.occupancy.len()
            || port < self.port_low
            || port > self.port_high
        {
            return false;
        }
        let start = self.port_low as u32 + block_index * params.block_size as u32;
        let end = (start + params.block_size as u32 - 1).min(self.port_high as u32);
        (start..=end).contains(&(port as u32))
    }

    pub(crate) fn deterministic_v4_tuple_matches(
        &self,
        params: DeterministicV4,
        src: Ipv4Addr,
        pool_v4: &[Ipv4Addr],
        addr_index: usize,
        translated_ip: Ipv4Addr,
        port: u16,
    ) -> bool {
        let Some((expected_index, block_index)) = deterministic_indices_v4(&params, src) else {
            return false;
        };
        if expected_index != addr_index
            || pool_v4.get(expected_index) != Some(&translated_ip)
            || expected_index >= self.shared.occupancy.len()
            || port < self.port_low
            || port > self.port_high
        {
            return false;
        }
        let start = self.port_low as u32 + block_index * params.block_size as u32;
        let end = (start + params.block_size as u32 - 1).min(self.port_high as u32);
        (start..=end).contains(&(port as u32))
    }

    /// #4559: allocate a deterministic CGNAT port for a NAPT64 (mode 2) flow
    /// from the IPv6 subscriber's fixed block. Like
    /// [`allocate_deterministic_v4`], a live flow re-allocates its tuple and a
    /// fresh flow claims the first free port in the subscriber's block via the
    /// occupancy bitmap (collision-free, RFC 6146 BIB). Unlike the v4 arm —
    /// which records no lease (`persistent_key: None`) — this arm mints,
    /// joins, and expires a persistent BIB lease for the subscriber
    /// (`allocate_deterministic_v6_at`): flows sharing a BIB join the existing
    /// lease, an idle lease is reclaimed or re-armed on expiry, and release
    /// completes the lease rather than simply freeing the tuple. The other
    /// divergence is the subscriber-index derivation
    /// ([`deterministic_indices_v6`]: the 32-bit word after the IPv6 prefix).
    /// A freed port IS recycled onto the per-address queue (#14625,
    /// [`Self::free_translated_port`]): `claim_in_block` scans the bitmap
    /// directly and ignores the ring, so recycling is harmless while the pool
    /// stays deterministic, and a pool that later flips to round-robin PAT on
    /// this reused allocator can only reach the freed port through the ring.
    /// The external IPv4 pool address and the port block are a pure function
    /// of the subscriber's IPv6 prefix, so [`reverse_deterministic_v6`]
    /// recovers it from `(external IPv4, port)` with no per-flow log. An
    /// out-of-range subscriber fails closed.
    pub(super) fn allocate_deterministic_v6(
        &self,
        flow: SourceNatFlowKey,
        pool_v4: &[Ipv4Addr],
        params: DeterministicV6,
        src: Ipv6Addr,
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        self.allocate_deterministic_v6_at(flow, pool_v4, params, src, 1, holder)
    }
    /// #17028: the one deterministic-BIB join both `allocate_
    /// deterministic_v6_at` branches share. The caller has already
    /// classified the lease (deterministic identity, address, block
    /// range, not revoked, live-or-unexpired) and admitted the flow;
    /// the branches differed only in `refresh_expiry` (the full-block
    /// copy refreshed the idle expiry, the claimed-port copy
    /// deliberately did not — #15948) and in their cap-fail counter
    /// (the claimed-port copy returned `AllocatorExhausted` WITHOUT
    /// bumping `exhaustion_total`). Policy: every cap failure in
    /// `allocate_deterministic_v6_at` bumps the counter; the claimed-
    /// port caller now does so too, and still frees the candidate
    /// port IT claimed (never the lease's port).
    fn join_bib_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        shard: &mut flows::LiveFlowShard,
        bib_key: PersistentSourceKey,
        flow: SourceNatFlowKey,
        lease: PersistentLease,
        refresh_expiry: bool,
        now_ns: u64,
        holder: NatHolder,
    ) -> TranslatedTuple {
        let lease_table::JoinOutcome::Joined {
            promotion_timeout_ns,
            ..
        } = lease_table::join_persistent_lease_locked(
            live,
            bib_key,
            lease_table::JoinPolicy {
                timeout_ns: DETERMINISTIC_NAT64_BIB_TIMEOUT_NS,
                promote_imported: true,
                refresh_expiry,
            },
            now_ns,
        )
        else {
            // The caller read this lease under the same guard; a
            // missing lease here is unreachable in practice.
            return lease.translated;
        };
        self.shared.flows.insert_in_shard(
            shard,
            flow,
            LiveAllocation {
                translated: lease.translated,
                persistent_key: Some(bib_key),
                addr_index: lease.addr_index,
                deterministic: true,
                address_only: false,
                promotion_timeout_ns,
                holders: holder.bit(),
            },
        );
        live.record_pat_owner(&flow, lease.translated);
        self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
        lease.translated
    }
    pub(super) fn allocate_deterministic_v6_at(
        &self,
        flow: SourceNatFlowKey,
        pool_v4: &[Ipv4Addr],
        params: DeterministicV6,
        src: Ipv6Addr,
        now_ns: u64,
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        use super::source::SourceNatFailureReason;
        if self.port_low == 0 || self.port_high == 0 || self.port_low > self.port_high {
            return Err(SourceNatFailureReason::InvalidPortRange);
        }
        let (ip_idx, block_idx) = deterministic_indices_v6(&params, src)
            .ok_or(SourceNatFailureReason::DeterministicSubscriberOutOfRange)?;
        if ip_idx >= pool_v4.len() || ip_idx >= self.shared.occupancy.len() {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let translated_ip = IpAddr::V4(pool_v4[ip_idx]);
        // Block boundaries mirror the v4 path: [port_low + block_idx*block_size,
        // that + block_size - 1], clamped to port_high. The NAT64 allocator's
        // port_low/port_high are the pool's translated-port range, the same
        // range the Go builder computes blocks_per_ip against (#15283), so
        // boundaries align.
        let port_start = self.port_low as u32 + block_idx * params.block_size as u32;
        if port_start > self.port_high as u32 {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(SourceNatFailureReason::AllocatorExhausted);
        }
        let port_end = (port_start + params.block_size as u32 - 1).min(self.port_high as u32);
        let bib_key = flow.persistent_source_key(super::source::PersistentNatPermit::AnyRemoteHost);
        // #9130: the block probe runs BEFORE the mutex is taken, and every
        // critical section below it is O(1) — the shape #4676 gave the sibling
        // PAT path (`allocate_translation_inner`), which the deterministic arms
        // never received. Holding the map mutex across the linear scan made the
        // hold time O(occupied prefix of the block), so one subscriber near its
        // own block budget serialized every other flow through this pool.
        //
        // Claim ports in the subscriber's block in ascending order, LOCK-FREE.
        // If an address-only token owns the candidate's reverse identity, skip
        // that port and continue the same block; exhaustion is reported only
        // after every candidate has been considered. The cursor avoids a
        // temporary rejected-port allocation, and rejected bitmap claims are
        // released without recycling.
        let mut probe_start = Some(port_start as u16);
        loop {
            let claimed = probe_start.and_then(|start| {
                self.shared.occupancy[ip_idx].claim_in_block(start, port_end as u16)
            });
            let Some(port) = claimed else {
                // No usable free port remains in the subscriber's block. A live
                // flow may own its only occupied port, so check idempotent reuse
                // before reporting exhaustion.
                let mut live = self.lock_live();
                let mut __shard = self.shared.flows.get_mut_shard(&flow);
                if let Some(slot) = __shard.map.get_mut(&flow) {
                    let existing = self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
                    return Ok(existing);
                }
                // #14670: a block full of expired idle BIBs under OTHER
                // source ports must not report permanent exhaustion. The
                // per-address sweep is bounded (PRESSURE_GC_BUDGET); expired
                // entries are the earliest in the per-address index, so one
                // pass reclaims this address's expired frontier. Only retry
                // the lock-free claim when something was actually reclaimed.
                let reclaimed =
                    self.gc_expired_for_addr_locked(&mut live, ip_idx, now_ns, PRESSURE_GC_BUDGET);
                if reclaimed > 0 {
                    drop(live);
                    probe_start = Some(port_start as u16);
                    continue;
                }

                if let Some(retired) =
                    lease_table::reclaim_expired_idle_lease_locked(&mut live, bib_key, now_ns)
                {
                    if let Some((addr_index, port)) = retired.freed_port {
                        self.free_translated_port_at(addr_index, port, now_ns);
                    }
                    drop(live);
                    probe_start = Some(port_start as u16);
                    continue;
                }
                if let Some(lease) = live.persistent_by_source.get(&bib_key).copied() {
                    if lease.deterministic
                        && lease.deterministic_identity
                            == Some(
                                super::idle_lease_sync_8121::DeterministicPortedIdentity::V6(
                                    params,
                                ),
                            )
                        && lease.addr_index == ip_idx
                        && lease.translated.ip == translated_ip
                        && (port_start..=port_end).contains(&(lease.translated.port as u32))
                        && !lease.revoked
                        && (lease.active_flows > 0
                            || lease.inbound_flows > 0
                            || lease.expires_at_ns > now_ns)
                    {
                        // #14670: joining an existing BIB is a tracked
                        // flow too; both branches enforce this cap.
                        if !self.shared.flows.admit_one(self.shared.max_tracked_flows) {
                            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                            return Err(SourceNatFailureReason::AllocatorExhausted);
                        }
                        // #15948: full-block refreshes idle expiry.
                        return Ok(self.join_bib_locked(
                            &mut live,
                            &mut __shard,
                            bib_key,
                            flow,
                            lease,
                            true,
                            now_ns,
                            holder,
                        ));
                    }
                    return Err(SourceNatFailureReason::AllocatorExhausted);
                }
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(SourceNatFailureReason::AllocatorExhausted);
            };
            let translated = TranslatedTuple {
                ip: translated_ip,
                port,
            };

            // Insert critical section: O(1). The idempotency check lives here
            // rather than before the probe, because probing is lock-free.
            let mut live = self.lock_live();
            let mut __shard = self.shared.flows.get_mut_shard(&flow);
            if let Some(slot) = __shard.map.get_mut(&flow) {
                // This flow already has a translation — a second packet racing the
                // session install, or a sibling worker that inserted it while the
                // probe ran. Give the port back through the normal recycling
                // free (#14625: the ring is bounded and `claim_in_block`
                // ignores it; a later PAT phase on this allocator needs it).
                let existing = self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
                drop(live);
                self.free_translated_port(ip_idx, port);
                return Ok(existing);
            }
            if let Some(retired) =
                lease_table::reclaim_expired_idle_lease_locked(&mut live, bib_key, now_ns)
            {
                if let Some((addr_index, port)) = retired.freed_port {
                    self.free_translated_port_at(addr_index, port, now_ns);
                }
            }
            if let Some(lease) = live.persistent_by_source.get(&bib_key).copied() {
                if lease.deterministic
                    && lease.deterministic_identity
                        == Some(
                            super::idle_lease_sync_8121::DeterministicPortedIdentity::V6(params),
                        )
                    && lease.addr_index == ip_idx
                    && lease.translated.ip == translated_ip
                    && (port_start..=port_end).contains(&(lease.translated.port as u32))
                    && !lease.revoked
                    && (lease.active_flows > 0
                        || lease.inbound_flows > 0
                        || lease.expires_at_ns > now_ns)
                {
                    if !self.shared.flows.admit_one(self.shared.max_tracked_flows) {
                        // #17028 divergence-1 fix: the pre-consolidation
                        // copy returned AllocatorExhausted WITHOUT
                        // bumping exhaustion_total. Every cap failure
                        // bumps it now (see join_bib_locked docs).
                        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                        drop(live);
                        self.free_translated_port_at(ip_idx, port, now_ns);
                        return Err(SourceNatFailureReason::AllocatorExhausted);
                    }
                    // Claimed-port: keep expires_at unchanged (#15948);
                    // release_flow re-arms on completion.
                    let joined = self.join_bib_locked(
                        &mut live,
                        &mut __shard,
                        bib_key,
                        flow,
                        lease,
                        false,
                        now_ns,
                        holder,
                    );
                    drop(live);
                    self.free_translated_port_at(ip_idx, port, now_ns);
                    return Ok(joined);
                }
                drop(live);
                self.free_translated_port(ip_idx, port);
                return Err(SourceNatFailureReason::AllocatorExhausted);
            }
            // #10190: deterministic NAT64 PAT claims only the bitmap. Reject a
            // same-allocator address-only token for this exact reverse identity,
            // then probe the next candidate in this subscriber's block (#10721).
            if live.address_only_owns_wire_identity(&flow, translated) {
                drop(live);
                self.free_translated_port(ip_idx, port);
                probe_start = port.checked_add(1);
                continue;
            }
            // #16013: a fresh deterministic BIB is a new persistent lease for
            // its source, so the per-source fairness gate applies alongside
            // the pool-global table cap.
            if live.persistent_by_source.len() >= self.shared.max_tracked_flows
                || self.persistent_source_lease_capacity_reached(&mut live, &bib_key, now_ns)
                || !self.shared.flows.admit_one(self.shared.max_tracked_flows)
            {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                drop(live);
                self.free_translated_port(ip_idx, port);
                return Err(SourceNatFailureReason::AllocatorExhausted);
            }
            let expires_at_ns = now_ns.saturating_add(DETERMINISTIC_NAT64_BIB_TIMEOUT_NS);
            live.insert_persistent_lease(
                bib_key,
                PersistentLease {
                    translated,
                    incarnation: 0,
                    addr_index: ip_idx,
                    expires_at_ns,
                    timeout_ns: DETERMINISTIC_NAT64_BIB_TIMEOUT_NS,
                    active_flows: 1,
                    inbound_flows: 0,
                    completed_flows: 0,
                    activation_saw_completion: false,
                    activation_previous_expires_at_ns: 0,
                    activation_had_previous_lease: false,
                    activation_previous_timeout_ns: 0,
                    deterministic: true,
                    deterministic_identity: Some(
                        super::idle_lease_sync_8121::DeterministicPortedIdentity::V6(params),
                    ),
                    address_only: false,
                    imported: false,
                    revoked: false,
                },
            );
            self.shared.flows.insert_in_shard(
                &mut __shard,
                flow,
                LiveAllocation {
                    translated,
                    persistent_key: Some(bib_key),
                    addr_index: ip_idx,
                    deterministic: true,
                    address_only: false,
                    promotion_timeout_ns: None,
                    holders: holder.bit(),
                },
            );
            // #15948 (H31-03): a freshly minted BIB is ACTIVE
            // (active_flows=1); it must not enter the idle-expiry index.
            // release/rollback re-arms the index when the last flow
            // completes, exactly as the sibling PAT/persistent mints do.
            live.record_pat_owner(&flow, translated);
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(translated);
        }
    }

    /// Carry only clear-replay fences into a replacement allocator. A renamed
    /// pool can have no live-flow reservations after clear removes idle leases,
    /// while stale HA records still need to be rejected.
    pub(crate) fn carry_persistent_nat_clear_fences_from(&self, prev: &PortAllocator, now_ns: u64) {
        let fence_capacity = self.shared.max_tracked_flows;
        let (clear_fences, previous_clear_ns, overflow_fence_until_ns) = {
            let prev_live = prev.lock_live();
            let mut fences =
                Vec::with_capacity(prev_live.revoked_persistent.len().min(fence_capacity));
            let mut overflow_until_ns = None;
            for (key, raw_until_ns) in &prev_live.revoked_persistent {
                // Active shells are not carried with the persistent lease map.
                // Their permanent marker therefore becomes one finite replay
                // horizon from this reseed; otherwise a missing shell could
                // leave the key fenced forever.
                let until_ns = if *raw_until_ns == ACTIVE_PERSISTENT_NAT_CLEAR_TOMBSTONE_NS {
                    now_ns.saturating_add(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS)
                } else {
                    *raw_until_ns
                };
                if until_ns <= now_ns {
                    continue;
                }
                if fences.len() < fence_capacity {
                    fences.push((*key, until_ns));
                } else {
                    overflow_until_ns =
                        Some(overflow_until_ns.map_or(until_ns, |old: u64| old.max(until_ns)));
                }
            }
            (
                fences,
                prev_live.last_persistent_nat_clear_ns,
                overflow_until_ns,
            )
        };
        let mut clear_ns = previous_clear_ns.filter(|clear_ns| {
            now_ns < clear_ns.saturating_add(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS)
        });
        if let Some(until_ns) = overflow_fence_until_ns {
            let widened_clear_ns = until_ns.saturating_sub(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS);
            clear_ns = Some(clear_ns.map_or(widened_clear_ns, |old| old.max(widened_clear_ns)));
        }
        {
            let mut live = self.lock_live();
            live.revoked_persistent
                .retain(|_, until_ns| *until_ns > now_ns);
            for (key, until_ns) in clear_fences {
                live.revoked_persistent
                    .entry(key)
                    .and_modify(|old| *old = (*old).max(until_ns))
                    .or_insert(until_ns);
            }
            let existing_clear_ns = live.last_persistent_nat_clear_ns.filter(|clear_ns| {
                now_ns < clear_ns.saturating_add(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS)
            });
            let mut carried_clear_ns = match (existing_clear_ns, clear_ns) {
                (Some(left), Some(right)) => Some(left.max(right)),
                (Some(clear_ns), None) | (None, Some(clear_ns)) => Some(clear_ns),
                (None, None) => None,
            };
            let mut retained = 0;
            let mut overflow_until_ns = None;
            live.revoked_persistent.retain(|_, until_ns| {
                if retained < fence_capacity {
                    retained += 1;
                    true
                } else {
                    overflow_until_ns =
                        Some(overflow_until_ns.map_or(*until_ns, |old: u64| old.max(*until_ns)));
                    false
                }
            });
            if let Some(until_ns) = overflow_until_ns {
                let widened_clear_ns =
                    until_ns.saturating_sub(PERSISTENT_NAT_CLEAR_REPLAY_HORIZON_NS);
                carried_clear_ns = Some(
                    carried_clear_ns.map_or(widened_clear_ns, |old| old.max(widened_clear_ns)),
                );
            }
            live.last_persistent_nat_clear_ns = carried_clear_ns;
        }
    }

    /// #4388: reserve a SPECIFIC translated `(ip, port)` for `flow` WITHOUT
    /// running the round-robin allocator, so a peer-synced session's NAT pool
    /// port is marked allocated in this node's LOCAL allocator. Without this,
    /// the standby never learns that the active node handed `(pool_ip, port)`
    /// to a synced session (the standby imports the pre-computed NAT decision;
    /// it never calls `allocate_translation`), so post-failover a fresh local
    /// flow could `allocate_translation` the SAME `(pool_ip, port)` — two
    /// sessions colliding on one NAT source tuple (reply mis-delivery / session
    /// hijack surface).
    ///
    /// The reservation sets the occupancy bit (the ownership token) and records
    /// `live_by_flow` using the synced session's flow key, so:
    ///   - the fresh cursor skips the port when it later reaches that offset
    ///     (the #3047 forward-probe), and
    ///   - the EXISTING teardown path (`release_flow` / `rollback_flow` via
    ///     `release_source_nat_allocation`, already called for every reaped or
    ///     delete-synced session) frees it with the SAME flow key — no new
    ///     release site is needed.
    ///
    /// Idempotent: re-reserving the same `(flow, translated)` (a synced-session
    /// refresh) is a no-op that returns `true`. Returns `false` and leaves the
    /// incumbent untouched if the port is already owned by a DIFFERENT live
    /// allocation (the bit is set — a local flow raced ahead of the sync on the
    /// standby); the caller then tries the next pool rule.
    ///
    /// #5178: `deterministic` mirrors the ACTIVE node's allocation mode for this
    /// synced flow — `true` when the reservation belongs to a deterministic
    /// CGNAT (mode 1) / NAPT64 (mode 2) pool, `false` for round-robin PAT. It is
    /// stored on the `LiveAllocation` for mode-correct bookkeeping (BIB /
    /// lease identity, overlap checks). Before #5178 this was hardcoded
    /// `false`. #14625: release recycles every port regardless of this flag
    /// (see `free_translated_port`), so the flag no longer selects the free
    /// path; it is retained because lease/BIB identity still depends on it.
    /// #6765: carry live port ownership across a PARTIAL-OVERLAP pool change.
    ///
    /// THE DEFECT. The allocator carry-over is keyed on the whole address list
    /// (`SourceNatPoolAllocatorKey`), so adding or removing ONE address from a
    /// pool of ten misses the reuse lookup and builds a fresh allocator for the
    /// WHOLE pool — including every RETAINED address. `AddressOccupancy::new`
    /// is all-zero with `cursor: 0` and the set bit is the sole ownership
    /// token, so the next new flow on a retained address is issued
    /// `(retained_addr, port_low)` — a tuple a pre-change live session may still
    /// hold, with the bit that would have blocked it now zeroed. Two sessions on
    /// one translated tuple is reply mis-delivery: traffic to the wrong host.
    ///
    /// WHY THIS SHAPE. The obvious fix — loosen the key and share the allocator
    /// when the pools overlap — is NOT available: `occupancy` is a `Vec` indexed
    /// by pool-address POSITION, so a changed list changes the indices and reuse
    /// would misindex. And the rebuild site holds the previous rules but NOT the
    /// session table, so the carry has to come from the previous allocator's own
    /// live state. That is exactly what the HA session-import path already does
    /// through `reserve_flow` — seed an allocator with a tuple someone else owns
    /// — so the mechanism is audited and exercised; only the caller is new.
    ///
    /// `index_map` maps a PREVIOUS pool-address index to its index in THIS
    /// allocator, for the addresses present in both pools. The caller owns that
    /// mapping because only it knows the address lists; this method owns the
    /// walk, so `live_by_flow` stays private to this module.
    ///
    /// Bounds, deliberately narrow:
    ///   - only addresses in `index_map` (retained) are re-seeded;
    ///   - only ports inside THIS allocator's range — a narrowed port range
    ///     cannot re-seed everything, and what is dropped is RETURNED to the
    ///     caller to log rather than silently discarded;
    ///   - `address_only` allocations hold no port bit (their token is the
    ///     `address_only_owners` reverse identity, not the occupancy bitmap), so
    ///     they are outside the port-reissue defect and are counted, not
    ///     re-seeded. Carrying them is the same class of question as the
    ///     persistent leases and is tracked separately.
    ///
    /// Runs at config-apply only. It does not touch `claim()` and adds no
    /// per-packet work.
    /// #16481: carry DETERMINISTIC (NAPT64 mode-2) live ownership across a
    /// pool-length change into a FRESH allocator.
    ///
    /// `reseed_retained_from` deliberately excludes deterministic leases
    /// (their BIB identity is not reconstructible from a flow record
    /// alone), and #15178 skipped the reseed entirely for deterministic
    /// prefixes on the premise that revalidation tears every old session
    /// down. That premise fails when the pool only grows/shrinks: a
    /// retained subscriber's (pool index, block) does not move, so
    /// `deterministic_v6_tuple_matches` still validates its tuple under
    /// the NEW params, revalidation keeps the session, and the fresh
    /// allocator re-mints its lowest block port — the port the surviving
    /// session still holds.
    ///
    /// This carry is the deterministic twin: for each live flow in `prev`
    /// whose translated address is retained (`index_map`) and whose tuple
    /// still satisfies `deterministic_v6_tuple_matches` under the NEW
    /// `new_params`/`new_pool_v4`, re-reserve the port bit in `self` and
    /// join/rebuild its BIB lease with the NEW identity
    /// `DeterministicPortedIdentity::V6(new_params)`. Flows whose tuple
    /// no longer validates (block moved, address removed, geometry
    /// changed) are NOT carried — revalidation tears those sessions down
    /// (#15178) — and are counted in `skipped_deterministic_invalid` /
    /// `dropped_persistent_on_*` so the drop is not silent.
    ///
    /// Unlike the generic carry, sibling flows sharing one BIB key join
    /// ONE lease here (each flow still reserves its own `live_by_flow`
    /// record; `reserve_flow_maybe_persistent_with_identity` joins the
    /// lease on the second sibling instead of refusing on the bit).
    /// Idle BIB leases (no live flow) are not carried: they hold no
    /// session, and a later same-socket flow re-derives the identical
    /// tuple deterministically from the new geometry.
    ///
    /// Runs at config-apply only; no per-packet work.
    pub(crate) fn reseed_retained_deterministic_v6_from(
        &self,
        prev: &PortAllocator,
        index_map: &FxHashMap<usize, usize>,
        new_pool_v4: &[Ipv4Addr],
        new_params: DeterministicV6,
        now_ns: u64,
    ) -> ReseedOutcome {
        let mut out = ReseedOutcome::default();
        if index_map.is_empty() {
            return out;
        }
        self.carry_persistent_nat_clear_fences_from(prev, now_ns);
        // Snapshot prev live flows + leases, then release prev's lock
        // before touching this allocator's (never hold both).
        let (carried, prev_leases) = {
            let prev_live = prev.lock_live();
            let carried: Vec<_> = prev.shared.flows.entries();
            let prev_leases = prev_live.persistent_by_source.clone();
            (carried, prev_leases)
        };
        let mut lease_counted: std::collections::HashSet<PersistentSourceKey> =
            std::collections::HashSet::new();
        for (flow, alloc) in carried {
            if alloc.address_only || !alloc.deterministic {
                continue;
            }
            let Some(bib_key) = alloc.persistent_key else {
                continue;
            };
            // Only count each BIB lease's validity once; sibling flows
            // sharing the key are carried flow-by-flow below.
            let first_for_lease = lease_counted.insert(bib_key);
            let IpAddr::V6(src_v6) = flow.src_ip else {
                if first_for_lease {
                    out.skipped_deterministic_invalid += 1;
                    if index_map.contains_key(&alloc.addr_index) {
                        out.dropped_persistent_on_retained += 1;
                    } else {
                        out.dropped_persistent_on_removed += 1;
                    }
                }
                continue;
            };
            let IpAddr::V4(translated_v4) = alloc.translated.ip else {
                if first_for_lease {
                    out.skipped_deterministic_invalid += 1;
                    if index_map.contains_key(&alloc.addr_index) {
                        out.dropped_persistent_on_retained += 1;
                    } else {
                        out.dropped_persistent_on_removed += 1;
                    }
                }
                continue;
            };
            let Some(&new_index) = index_map.get(&alloc.addr_index) else {
                if first_for_lease {
                    out.skipped_deterministic_invalid += 1;
                    out.dropped_persistent_on_removed += 1;
                }
                continue;
            };
            if !self.deterministic_v6_tuple_matches(
                new_params,
                src_v6,
                new_pool_v4,
                new_index,
                translated_v4,
                alloc.translated.port,
            ) {
                if first_for_lease {
                    out.skipped_deterministic_invalid += 1;
                    out.dropped_persistent_on_retained += 1;
                }
                continue;
            }
            // Preserve the lease timeout when the old lease is visible;
            // fall back to the deterministic BIB timeout (mirrors the
            // local mint in allocate_deterministic_v6_at).
            let timeout_ns = prev_leases
                .get(&bib_key)
                .map(|lease| lease.timeout_ns)
                .unwrap_or(DETERMINISTIC_NAT64_BIB_TIMEOUT_NS);
            let mut previous_snapshot = None;
            let mut reserved = false;
            if alloc.holders == 0 {
                reserved = self.reserve_flow_maybe_persistent_with_identity(
                    flow,
                    alloc.translated,
                    new_index,
                    true,
                    Some(super::idle_lease_sync_8121::DeterministicPortedIdentity::V6(new_params)),
                    now_ns,
                    NatHolder::Untracked,
                    Some((bib_key, timeout_ns)),
                    false,
                    &mut previous_snapshot,
                );
            } else {
                for worker in 0..MAX_NAT_HOLDER_WORKERS {
                    if alloc.holders & (1u128 << worker) == 0 {
                        continue;
                    }
                    reserved |= self.reserve_flow_maybe_persistent_with_identity(
                        flow,
                        alloc.translated,
                        new_index,
                        true,
                        Some(
                            super::idle_lease_sync_8121::DeterministicPortedIdentity::V6(
                                new_params,
                            ),
                        ),
                        now_ns,
                        NatHolder::Worker(worker),
                        Some((bib_key, timeout_ns)),
                        false,
                        &mut previous_snapshot,
                    );
                }
            }
            if reserved {
                out.reseeded += 1;
                if first_for_lease {
                    out.reseeded_deterministic += 1;
                }
            } else {
                out.refused += 1;
            }
        }
        out
    }

    pub(crate) fn reseed_retained_from(
        &self,
        prev: &PortAllocator,
        index_map: &FxHashMap<usize, usize>,
        now_ns: u64,
    ) -> ReseedOutcome {
        let mut out = ReseedOutcome::default();
        if index_map.is_empty() {
            return out;
        }
        self.carry_persistent_nat_clear_fences_from(prev, now_ns);
        // Snapshot the previous live set and RELEASE its lock before touching
        // this allocator's, so the two mutexes are never held at once.
        let (carried, carried_leases) = {
            let prev_live = prev.lock_live();
            let carried: Vec<_> = prev
                .shared
                .flows
                .entries()
                .into_iter()
                .filter(|(_, a)| index_map.contains_key(&a.addr_index))
                .collect();
            // #15110: a persistent lease is CARRIED (not dropped) only when
            // at least one of its live flows is itself carried in range.
            // Deterministic leases stay on the old counted-drop path: their
            // BIB identity (`deterministic_identity`) is not reconstructible
            // from a flow record, and minting a plain lease under the key
            // would corrupt that linkage.
            let carried_lease_keys: std::collections::HashSet<PersistentSourceKey> = carried
                .iter()
                .filter_map(|(_, a)| {
                    let key = a.persistent_key?;
                    let lease = prev_live.persistent_by_source.get(&key)?;
                    if lease.deterministic {
                        return None;
                    }
                    let &new_index = index_map.get(&a.addr_index)?;
                    if a.address_only || self.port_in_range(new_index, a.translated.port) {
                        Some(key)
                    } else {
                        None
                    }
                })
                .collect();
            let carried_leases: rustc_hash::FxHashMap<PersistentSourceKey, PersistentLease> =
                carried_lease_keys
                    .iter()
                    .filter_map(|key| {
                        prev_live
                            .persistent_by_source
                            .get(key)
                            .map(|lease| (*key, *lease))
                    })
                    .collect();
            // #7560: count the persistent leases this pass is about to drop,
            // split by whether their address survived the pool change. Done
            // under the SAME lock acquisition as the live-set snapshot so the
            // two counts describe one consistent instant, and so no second
            // lock/release is added to a config-apply path. #15110: a lease
            // in `carried_leases` is rejoined by its live flows below, so it
            // is not dropped and must not be counted (or reported) as such.
            for (key, lease) in &prev_live.persistent_by_source {
                if carried_leases.contains_key(key) {
                    continue;
                }
                if index_map.contains_key(&lease.addr_index) {
                    out.dropped_persistent_on_retained += 1;
                } else {
                    out.dropped_persistent_on_removed += 1;
                }
            }
            (carried, carried_leases)
        };
        for (flow, alloc) in carried {
            let Some(&new_index) = index_map.get(&alloc.addr_index) else {
                continue;
            };
            if alloc.address_only {
                // #8597 K11: CARRY the reverse-identity token instead of
                // dropping it.
                //
                // The record holds no port bit, which is why the port-reissue
                // work skipped it — that reasoning is sound and is about PORTS.
                // What it does not cover is what an address-only record DOES
                // hold: an `address_only_owners` entry, the #5269 guard that
                // denies a second flow the same public reverse identity.
                // Dropping it left the carried session forwarding with that
                // guard silently gone, so a colliding arrival was ADMITTED
                // instead of refused as exhaustion — a fail-closed protection
                // downgraded by an ordinary pool edit.
                //
                // Holders are preserved the same way the port-bearing carry
                // below preserves them: an HA-synced flow is reserved once per
                // WORKER (#6211 F2), and re-seeding with a single untracked
                // holder would let the first release drop a token the other
                // N-1 still forward through.
                let mut carried_ok = false;
                if alloc.holders == 0 {
                    // #14622: thread `new_index` — the remapped position of
                    // the address this record holds — instead of letting
                    // `reserve_address_only` stamp 0. Without it a second
                    // pool edit filters the record out by its lying stamp
                    // and drops the #5269 guard it was carried to keep.
                    carried_ok = self
                        .reserve_address_only(
                            flow,
                            alloc.translated.ip,
                            new_index,
                            NatHolder::Untracked,
                        )
                        .is_ok();
                } else {
                    for worker in 0..MAX_NAT_HOLDER_WORKERS {
                        if alloc.holders & (1u128 << worker) == 0 {
                            continue;
                        }
                        carried_ok |= self
                            .reserve_address_only(
                                flow,
                                alloc.translated.ip,
                                new_index,
                                NatHolder::Worker(worker),
                            )
                            .is_ok();
                    }
                }
                if carried_ok {
                    out.reseeded += 1;
                } else {
                    // Still counted, and the field keeps its place in the
                    // report — its MEANING narrows from "deliberately skipped"
                    // to "could not be carried", which is the honest reading
                    // once carrying is attempted.
                    out.skipped_address_only += 1;
                }
                continue;
            }
            if !self.port_in_range(new_index, alloc.translated.port) {
                out.skipped_out_of_range += 1;
                continue;
            }
            // #15110: a record naming a persistent lease must be carried as
            // a LEASE JOIN, not through the non-persistent `reserve_flow`.
            // Two flows from one source share one lease and one tuple, so
            // the snapshot holds one entry per sibling: the first claimed
            // the bit as a plain PAT record and every later sibling was
            // REFUSED by the occupied-bit check, and the survivor's release
            // then freed a tuple the refused siblings still forwarded on —
            // the #6765 reissue hazard through an ordinary pool edit.
            // Joining via `reserve_flow_maybe_persistent` mints the lease
            // on the first sibling and joins it on the rest, so the bit
            // frees only when the lease's last flow releases. This also
            // exactly covers single-flow persistent records, which the old
            // path carried lease-less (their release freed the bit with no
            // lease behind it). NOT carried this way: deterministic
            // leases (`carried_leases` excludes them above — their BIB
            // identity cannot be rebuilt from a flow record), which keep
            // the plain path and the #7560 counted drop.
            //
            // Preserve the holder set: an HA-synced flow is reserved once per
            // WORKER (#6211 F2) and the port must not be freed until the LAST
            // one lets go. Re-seeding with a single untracked holder would let
            // the first release free a port the other N-1 still forward
            // through. Untracked (holders == 0) is a LOCAL allocation and
            // re-seeds once.
            let persistent = alloc.persistent_key.and_then(|key| {
                carried_leases
                    .get(&key)
                    .map(|lease| (key, lease.timeout_ns))
            });
            let mut previous_snapshot = None;
            let mut reserved = false;
            if alloc.holders == 0 {
                reserved = match persistent {
                    Some(persistent) => self.reserve_flow_maybe_persistent(
                        flow,
                        alloc.translated,
                        new_index,
                        alloc.deterministic,
                        now_ns,
                        NatHolder::Untracked,
                        Some(persistent),
                        false,
                        &mut previous_snapshot,
                    ),
                    None => self.reserve_flow(
                        flow,
                        alloc.translated,
                        new_index,
                        alloc.deterministic,
                        now_ns,
                        NatHolder::Untracked,
                    ),
                };
            } else {
                for worker in 0..MAX_NAT_HOLDER_WORKERS {
                    if alloc.holders & (1u128 << worker) == 0 {
                        continue;
                    }
                    reserved |= match persistent {
                        Some(persistent) => self.reserve_flow_maybe_persistent(
                            flow,
                            alloc.translated,
                            new_index,
                            alloc.deterministic,
                            now_ns,
                            NatHolder::Worker(worker),
                            Some(persistent),
                            false,
                            &mut previous_snapshot,
                        ),
                        None => self.reserve_flow(
                            flow,
                            alloc.translated,
                            new_index,
                            alloc.deterministic,
                            now_ns,
                            NatHolder::Worker(worker),
                        ),
                    };
                }
            }
            if reserved {
                out.reseeded += 1;
            } else {
                out.refused += 1;
            }
        }
        out
    }

    /// True when `port` falls inside the configured range of the pool address
    /// at `index`. Read off that address's own `AddressOccupancy` rather than a
    /// shared field, because the range lives per-address — asking the wrong
    /// address would be the same class of positional mistake the whole re-seed
    /// exists to avoid. A zero-range occupancy (unset/invalid
    /// `port_low`/`port_high`) admits nothing.
    fn port_in_range(&self, index: usize, port: u16) -> bool {
        let Some(occ) = self.shared.occupancy.get(index) else {
            return false;
        };
        if occ.range == 0 {
            return false;
        }
        matches!((port as u32).checked_sub(occ.port_low as u32), Some(o) if o < occ.range)
    }

    /// #7360: the non-persistent entry point, unchanged in shape and semantics.
    ///
    /// `pub(crate)` because `afxdp` and the NAT64 port domain drive it, and it
    /// deliberately does NOT mention `PersistentSourceKey` — that type is
    /// `pub(super)` on purpose (see this file's visibility note), so the
    /// lease-aware form is a `pub(super)` sibling reached only from
    /// `nat::source`, where the rule's persistence config actually lives.
    pub(crate) fn reserve_flow(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        addr_index: usize,
        deterministic: bool,
        now_ns: u64,
        holder: NatHolder,
    ) -> bool {
        let mut previous_holders = None;
        self.reserve_flow_maybe_persistent(
            flow,
            translated,
            addr_index,
            deterministic,
            now_ns,
            holder,
            None,
            false,
            &mut previous_holders,
        )
    }

    /// Reserve a synced flow, joining its source's persistent lease when
    /// configured. When `capture_previous_holders` is true, the incumbent mask
    /// is captured by `capture_and_replace` while the same live-state guard
    /// remains held through eviction and installation.
    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    pub(super) fn reserve_flow_maybe_persistent_with_identity(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        addr_index: usize,
        deterministic: bool,
        deterministic_identity: Option<super::idle_lease_sync_8121::DeterministicPortedIdentity>,
        now_ns: u64,
        holder: NatHolder,
        persistent: Option<(PersistentSourceKey, u64)>,
        capture_previous_holders: bool,
        previous_snapshot: &mut Option<SourceNatReservationSnapshot>,
    ) -> bool {
        self.reserve_flow_maybe_persistent_inner(
            flow,
            translated,
            addr_index,
            deterministic,
            deterministic_identity,
            now_ns,
            holder,
            persistent,
            capture_previous_holders,
            previous_snapshot,
        )
    }

    pub(super) fn reserve_flow_maybe_persistent(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        addr_index: usize,
        deterministic: bool,
        now_ns: u64,
        holder: NatHolder,
        persistent: Option<(PersistentSourceKey, u64)>,
        capture_previous_holders: bool,
        previous_snapshot: &mut Option<SourceNatReservationSnapshot>,
    ) -> bool {
        self.reserve_flow_maybe_persistent_inner(
            flow,
            translated,
            addr_index,
            deterministic,
            None,
            now_ns,
            holder,
            persistent,
            capture_previous_holders,
            previous_snapshot,
        )
    }

    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    fn reserve_flow_maybe_persistent_inner(
        &self,
        flow: SourceNatFlowKey,
        translated: TranslatedTuple,
        addr_index: usize,
        deterministic: bool,
        deterministic_identity: Option<super::idle_lease_sync_8121::DeterministicPortedIdentity>,
        now_ns: u64,
        holder: NatHolder,
        persistent: Option<(PersistentSourceKey, u64)>,
        capture_previous_holders: bool,
        previous_snapshot: &mut Option<SourceNatReservationSnapshot>,
    ) -> bool {
        if addr_index >= self.shared.occupancy.len() {
            return false;
        }
        let mut live = self.capture_and_replace(&flow, capture_previous_holders);
        // A refresh of the same synced flow: if it already holds this exact
        // translated tuple, it is reserved — nothing to do. A changed tuple is
        // fully admitted below before the stale reservation is retired, so a
        // refused re-decision preserves the incumbent.
        let existing = self.shared.flows.get_in_shard(&live.shard, &flow);
        if let Some(existing) = existing {
            if existing.translated == translated {
                // #17033: count a synced PAT refresh as a reuse, like the
                // synced address-only twin below; the pre-fix copy here was
                // the only one of the 13 that skipped `reuses_total`.
                if let Some(slot) = live.shard.map.get_mut(&flow) {
                    self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
                }
                *previous_snapshot = live.previous_snapshot();
                return true;
            }
        }
        // #13691: all refusals must happen before stale-incumbent teardown.
        // #10190: synced PAT reservations share the allocator with
        // address-only mints, which have no bitmap bit.
        if live.address_only_owns_wire_identity(&flow, translated) {
            return false;
        }
        // The incumbent already consumes one tracked-flow slot; replacing it
        // does not add another.
        if self
            .shared
            .flows
            .len()
            .saturating_sub(if existing.is_some() { 1 } else { 0 })
            >= self.shared.max_tracked_flows
        {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // #7360: a PERSISTENT synced flow joins its source's lease instead of
        // reserving the port again.
        //
        // Two flows from one client under persistent NAT share ONE translated
        // tuple — that is what a lease is for. They are DIFFERENT
        // `SourceNatFlowKey`s (the destination differs), so the refresh
        // early-return above does not catch the second one, and before this it
        // fell through to the occupancy CAS below and failed on the bit its own
        // lease already held. `reserve_synced_on_first_pool_owner` read that as
        // `Refused`, and `handle_upsert_synced` returns `RejectedReserve`
        // BEFORE `publish_shared_session` — so a persistent client's 2nd..Nth
        // sessions were not merely un-leased on the standby, they were never
        // imported at all.
        //
        // The local path never had this problem because
        // `reuse_existing_lease_locked` does not call `reserve`: it points a new
        // `LiveAllocation` at the tuple the lease already owns and bumps the
        // refcount. This is the synced twin of that, and it is what makes the
        // lease's `active_flows` mean what it says.
        // A synced live flow may join a still-draining shell to retain its
        // active wire tuple. If clear removed the lease, reserve this session
        // without persistence instead of recreating the cleared pin.
        // #16035 fold: capture whether the caller's own lease owns the
        // candidate tuple BEFORE the reclaim and liveness filter below
        // can remove/drop it (an expired own lease is reclaimed and
        // filtered out, but re-joining it on the same port is still
        // not a new owner).
        let caller_lease_owns_tuple = persistent.is_some_and(|(key, _)| {
            // A lease that survives a persistent CLEAR (tombstoned in
            // `revoked_persistent`) is not exempt: its replacement was
            // minted locally after the clear, and a stale pre-clear
            // synced session re-joining it is exactly #10784.
            !live.revoked_persistent.contains_key(&key)
                && live.persistent_by_source.get(&key).is_some_and(|lease| {
                    lease.translated == translated && lease.addr_index == addr_index
                })
        });
        if let Some((key, _)) = persistent {
            if !live.persistent_nat_import_is_clear_fenced(&key, now_ns) {
                self.reclaim_expired_idle_lease_locked(&mut live, key, now_ns);
            }
        }
        // Session sync has no durable batch-generation proof, so retain the global clear fence.
        let persistent = persistent.filter(|(key, _)| {
            match live.persistent_by_source.get(key) {
                // #10784 R2B1: a synced session may join a LIVE lease only. An
                // expired idle replacement still awaiting GC must not be
                // reactivated by a stale pre-clear session. The lease liveness
                // test matches the local reuse predicate.
                Some(lease) => {
                    (!lease.revoked || lease.active_flows > 0 || lease.inbound_flows > 0)
                        && (lease.active_flows > 0
                            || lease.inbound_flows > 0
                            || lease.expires_at_ns > now_ns)
                }
                None => !live.persistent_nat_import_is_clear_fenced(key, now_ns),
            }
        });
        // Refuse a stale lease tuple before retiring this flow's current
        // reservation. The branch below can then join only a compatible lease.
        if let Some((key, _)) = persistent {
            if live.persistent_by_source.get(&key).is_some_and(|lease| {
                lease.translated != translated || lease.addr_index != addr_index
            }) {
                return false;
            }
        }
        // A mint's persistent-table capacity check may run pressure GC; do it
        // before any incumbent mutation, so a refusal preserves its state.
        // #16013: the per-source gate sits beside the pool-global one for the
        // same reason — a synced mint for an at-cap source is refused before
        // it can displace the incumbent.
        let mints_persistent_lease =
            persistent.is_some_and(|(key, _)| !live.persistent_by_source.contains_key(&key));
        if mints_persistent_lease && self.persistent_lease_capacity_reached(&mut live, now_ns) {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if let Some((key, _)) = persistent {
            if mints_persistent_lease
                && self.persistent_source_lease_capacity_reached(&mut live, &key, now_ns)
            {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        // Check bitmap ownership before teardown. The one allowed occupied
        // case is the incumbent's own plain-PAT bit, which teardown releases
        // immediately before this same guarded operation reserves it anew.
        let incumbent_owns_candidate_bit = existing.is_some_and(|incumbent| {
            incumbent.addr_index == addr_index
                && incumbent.translated.port == translated.port
                && incumbent.persistent_key.is_none()
                && !incumbent.address_only
        });
        // #16035 fold: a specific-port reserve CASes the named port
        // directly, bypassing both claim paths' quarantine. Refuse
        // while that port's recycle token is still inside its reuse
        // delay (small ranges only; `port_quarantined` is false on
        // large ranges and for unqueued ports) — UNLESS the caller's
        // own persistent lease already owns that exact tuple: a synced
        // flow re-joining its source's lease on the same port is not a
        // new owner, so the misdelivery the delay guards against
        // cannot occur.
        let own_lease_owns = caller_lease_owns_tuple;
        if !own_lease_owns
            && self.shared.occupancy[addr_index].port_quarantined(translated.port, now_ns)
        {
            return false;
        }
        if !incumbent_owns_candidate_bit
            && self.shared.occupancy[addr_index]
                .offset_of(translated.port)
                .is_none_or(|offset| self.shared.occupancy[addr_index].is_occupied(offset))
            && !persistent.is_some_and(|(key, _)| {
                live.persistent_by_source.get(&key).is_some_and(|lease| {
                    lease.translated == translated && lease.addr_index == addr_index
                })
            })
        {
            return false;
        }
        if let Some(existing) = existing {
            // #6528: mode-correct release only after the new tuple has passed
            // admission; a refusal above leaves the incumbent untouched.
            self.unlink_live_allocation_captured(&mut live, &flow, existing, now_ns);
            Self::complete_persistent_lease_locked(&mut live, existing, now_ns);
        }
        // A synced persistent flow joins its existing source lease when present.
        if let Some((persistent_key, timeout_ns)) = persistent {
            if let Some(lease) = live.persistent_by_source.get(&persistent_key).copied() {
                // #8132/#17028: the shared 0->1 join re-arms the
                // activation-rollback snapshot exactly as the local
                // reuse path does (an idle #8121 import carries no
                // previous state, so without it rollback deletes the
                // lease and frees its port). Synced joins preserve
                // peer origin: no promotion marker, no expiry refresh.
                let lease_table::JoinOutcome::Joined { was_idle, .. } =
                    lease_table::join_persistent_lease_locked(
                        &mut live,
                        persistent_key,
                        lease_table::JoinPolicy {
                            timeout_ns: bounded_persistent_nat_timeout_ns(timeout_ns),
                            promote_imported: false,
                            refresh_expiry: false,
                        },
                        now_ns,
                    )
                else {
                    return false;
                };
                if !self.shared.flows.try_insert_in_shard(
                    &mut live.shard,
                    flow,
                    LiveAllocation {
                        translated,
                        persistent_key: Some(persistent_key),
                        addr_index,
                        deterministic,
                        address_only: false,
                        promotion_timeout_ns: None,
                        holders: holder.bit(),
                    },
                    self.shared.max_tracked_flows,
                ) {
                    // Fold 2: admission lost — undo the join (refcount;
                    // idle-edge expiry re-registered from the copy).
                    if let Some(slot) = live.persistent_by_source.get_mut(&persistent_key) {
                        slot.active_flows = slot.active_flows.saturating_sub(1);
                    }
                    if was_idle {
                        Self::insert_lease_expiration_locked(
                            &mut live,
                            lease.addr_index,
                            lease.expires_at_ns,
                            persistent_key,
                        );
                    }
                    self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                live.record_pat_owner(&flow, translated);
                *previous_snapshot = live.previous_snapshot();
                return true;
            }
        }
        // Never steal a port owned by a DIFFERENT live allocation: the bit CAS
        // fails when the port is already occupied, so `reserve` returns false
        // and we leave the incumbent (and the caller falls through to the next
        // rule). The synced decision is authoritative on the wire, but on a
        // healthy standby the owning RG is passive so no local flow should hold
        // the port; if one does, not stealing is the safe choice.
        // A synced session may mint a fresh persistent lease only while the
        // persistent table has room. Existing leases returned through the
        // join path above and do not consume another entry.
        // Fold 3: claim the tracked-flow slot BEFORE the bitmap
        // reserve and BEFORE the lease mint below. The mint
        // creates a lease with `active_flows = 1` that is in no
        // expiry index; if admission were only discovered lost
        // at the insert (fold 2), that lease could never drain
        // or be reclaimed. Admitting here means a loser never
        // mints at all. (The bitmap reserve right after can
        // still refuse — that path un-admits.)
        if !self.shared.flows.admit_one(self.shared.max_tracked_flows) {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if !self.shared.occupancy[addr_index].reserve(translated.port) {
            self.shared.flows.unadmit_one();
            return false;
        }
        // #7360: the FIRST session for this source mints the lease the rest will
        // join. `active_flows` starts at 1 and is DERIVED from imports that
        // actually succeeded — never carried from the peer, because the standby
        // installs a strict subset of what the active sends (#6600 reserve
        // refusal, #5674 capacity, #2170 stale generation, #7188's
        // discriminator withhold). A carried count would credit the lease for
        // sessions this node does not hold, and a refcount that never reaches
        // zero is never idle, so the lease would never enter `lease_expirations`
        // and no GC path could reclaim it.
        //
        // `expires_at_ns` is synthesized from the LOCAL clock, and that is
        // sound rather than approximate: the reuse predicate is
        // `active_flows > 0 || expires_at_ns > now_ns`, so while any flow is
        // active the expiry is never consulted, and
        // `complete_persistent_lease_locked` re-arms it from the local clock the
        // moment the last flow releases. The peer's value could not be used
        // anyway — it derives from `monotonic_nanos()` (CLOCK_MONOTONIC), which
        // is boot-relative and meaningless across nodes.
        //
        // An IDLE lease (`active_flows == 0`, still inside its timeout) has no
        // session to be rebuilt from and is out of scope here — see #8121.
        // #10789-F4 (Q1, verified by call graph): the lease-touching branches
        // of this function run only when `persistent` is `Some`. Production
        // constructs it in `reserve_synced_on_first_pool_owner` (synced.rs)
        // and in the NAT64 synced reserve (`nat64_ports.rs`) — the `None`
        // wrapper (`reserve_flow`) never touches `persistent_by_source`. So
        // every lease minted here is peer-derived and needs no origin
        // parameter: `imported: true`. #15179: the NAT64 deterministic arm
        // threads its prefix identity so the minted BIB is joinable by the
        // local deterministic allocator after failover.
        let persistent_key = persistent.map(|(persistent_key, timeout_ns)| {
            let timeout_ns = bounded_persistent_nat_timeout_ns(timeout_ns);
            live.insert_persistent_lease(
                persistent_key,
                PersistentLease {
                    translated,
                    incarnation: 0,
                    addr_index,
                    expires_at_ns: now_ns.saturating_add(timeout_ns),
                    timeout_ns,
                    active_flows: 1,
                    inbound_flows: 0,
                    completed_flows: 0,
                    activation_saw_completion: false,
                    activation_previous_expires_at_ns: 0,
                    activation_had_previous_lease: false,
                    activation_previous_timeout_ns: 0,
                    address_only: false,
                    deterministic,
                    deterministic_identity: if deterministic {
                        deterministic_identity
                    } else {
                        None
                    },
                    // #10789-F4: rebuilt from a synced session — never re-exported.
                    imported: true,
                    revoked: false,
                },
            );
            persistent_key
        });
        self.shared.flows.insert_admitted_in_shard(
            &mut live.shard,
            flow,
            LiveAllocation {
                translated,
                persistent_key,
                addr_index,
                deterministic,
                address_only: false,
                // #6211 F2: the first holder. A stale-tuple replace lands here
                // too, and correctly starts a FRESH mask — the previous tuple's
                // holders were holding that tuple, not this one.
                promotion_timeout_ns: None,
                holders: holder.bit(),
            },
        );
        live.record_pat_owner(&flow, translated);
        *previous_snapshot = live.previous_snapshot();
        true
    }

    /// #5269: mint an ADDRESS-ONLY occupancy token for a `port no-translation`
    /// or port-less source-NAT flow. Unlike PAT ([`allocate_translation`]) no
    /// pool PORT is consumed — the packet keeps its own source port on the wire
    /// — but the translated REVERSE identity (protocol, chosen pool address,
    /// PRESERVED source port, remote endpoint) is claimed so a SECOND flow that
    /// would map to the SAME public reverse tuple is DENIED as exhaustion
    /// instead of silently receiving an unowned duplicate whose replies the
    /// reverse (1:N) index cannot disambiguate.
    ///
    /// The FIRST flow owns the identity and succeeds; a genuinely-colliding
    /// second flow (same pool address, same preserved port, same remote — for a
    /// port-less protocol, same pool address + remote) fails closed, mirroring
    /// how a full port-translating pool reports exhaustion and the vSRX
    /// address-only / persistent capacity limit. A NON-colliding address-only
    /// flow (different preserved port, pool address, or remote) mints its own
    /// token and succeeds.
    ///
    /// The token is recorded in `live_by_flow` (flagged `address_only`) AND in
    /// `address_only_owners`, so the EXISTING teardown path
    /// (`release_flow`/`rollback_flow` via `release_source_nat_allocation`,
    /// already called for every reaped or delete-synced session) frees it — no
    /// new delete site. Idempotent: a second packet of the SAME flow returns its
    /// existing translated tuple.
    pub(super) fn reserve_address_only(
        &self,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        // #14622: the pool index of `translated_ip` in the caller's pool
        // (0 for single-address interface-mode allocators, whose only
        // address is index 0). Stored verbatim on the live record so
        // `reseed_retained_from` filters/remaps on the address the record
        // actually holds — hardcoding 0 here re-stamped every carried or
        // deterministically-minted record onto pool[0] and a later pool
        // edit dropped its #5269 guard.
        addr_index: usize,
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let mut previous_holders = None;
        self.reserve_address_only_maybe_persistent(
            flow,
            translated_ip,
            addr_index,
            0,
            holder,
            None,
            false,
            &mut previous_holders,
        )
    }

    /// #8132: the ADDRESS-ONLY twin of [`reserve_flow_maybe_persistent`] — mint
    /// the reverse-identity token AND join (or create) the source's persistent
    /// lease AT THE ADDRESS THE WIRE NAMED.
    ///
    /// Why this is a third variant rather than a call-site swap to
    /// [`reserve_address_only_persistent`]: that function CHOOSES the pool
    /// address, via `address_index` over the family. A synced reservation must
    /// not choose. The active node already did, and the standby's only job is
    /// to honour that choice — recomputing it lands on a different address in
    /// exactly the configuration this issue is about (`address-persistent`
    /// OFF, where the choice is round-robin over live occupancy rather than a
    /// pure function of the source), so the client's public address would move
    /// across the failover the lease exists to survive.
    ///
    /// The session-DROP half of #7360 has no counterpart here: an address-only
    /// allocation claims no pool port, so a client's 2nd..Nth sessions never
    /// compete for a bit their own lease holds, and the
    /// `AddressOnlyReverseKey` folds in the remote endpoint, so two flows from
    /// one client to different servers never collide.
    pub(super) fn reserve_address_only_maybe_persistent(
        &self,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        addr_index: usize,
        now_ns: u64,
        holder: NatHolder,
        persistent: Option<(PersistentSourceKey, u64)>,
        capture_previous_holders: bool,
        previous_snapshot: &mut Option<SourceNatReservationSnapshot>,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let translated = TranslatedTuple {
            ip: translated_ip,
            // Port-bearing protocols preserve their source port; a port-less
            // protocol carries 0 here. This value is NOT written to the wire
            // (the caller leaves `rewrite_src_port` unset); it keys the reverse
            // identity and lets the SAME `release_flow` free the token.
            port: flow.src_port,
        };
        let rkey = AddressOnlyReverseKey {
            protocol: flow.protocol,
            translated_ip,
            translated_port: flow.src_port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
        };
        let mut live = self.capture_and_replace(&flow, capture_previous_holders);
        // Idempotent re-entry: a second packet of the same flow (racing session
        // install) reuses its first decision rather than re-keying.
        //
        // #6211 F2: this is also where workers 2..N land when a synced
        // ADDRESS-ONLY (#5338) token is fanned out, and where an already-holding
        // worker lands on every refresh — so record the holder here, exactly as
        // `reserve_flow` does on its own early return.
        let existing = self.shared.flows.get_in_shard(&live.shard, &flow);
        if let Some(existing) = existing {
            if existing.translated == translated {
                if let Some(slot) = live.shard.map.get_mut(&flow) {
                    self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
                }
                *previous_snapshot = live.previous_snapshot();
                return Ok(existing.translated);
            }
        }
        // Collision: the reverse identity is already owned by a DIFFERENT flow.
        // Two flows sharing one public reverse tuple cannot coexist (their
        // replies are indistinguishable), so deny the second — the address-only
        // capacity limit. `flow` is not in `live_by_flow` here (checked above),
        // so any existing owner is necessarily a different flow.
        // #14671: idle persistent address-only leases still own their wire
        // identity for the permit scope after the live token is released.
        // Minting a duplicate puts two source keys under one
        // persistent_by_translated entry and denies inbound for both. The
        // synced candidate's own lease (if any) never blocks its rejoin.
        let candidate_key = persistent.map(|(key, _)| key);
        if live.address_only_owners.contains_key(&rkey)
            || live.pat_owns_wire_identity(&flow, translated)
            || live.persistent_address_only_contended_except(&flow, translated, candidate_key)
        {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        // The incumbent is already tracked; replacing it uses the same slot.
        if self
            .shared
            .flows
            .len()
            .saturating_sub(usize::from(existing.is_some()))
            >= self.shared.max_tracked_flows
        {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        // #8132: resolve the lease BEFORE inserting the token, so a refused
        // flow leaves BOTH the lease and the reverse-identity map untouched —
        // the ordering `reserve_address_only_persistent` documents for the same
        // reason on the local path.
        //
        // `addr_index` is bounds-checked here rather than trusted: it indexes
        // `lease_expirations_by_addr`, whose accessors are `get_mut`, so an
        // out-of-range value would silently skip the per-address index and
        // leave it disagreeing with the global `lease_expirations` — a lease
        // the per-address GC sweep can never reap. Mirrors the
        // `addr_index >= occupancy.len()` guard on the port-bearing arm.
        // Match the port-bearing path: live sessions may join a draining shell,
        // but a removed tombstoned lease must not be minted again by session sync.
        if let Some((key, _)) = persistent {
            if !live.persistent_nat_import_is_clear_fenced(&key, now_ns) {
                self.reclaim_expired_idle_lease_locked(&mut live, key, now_ns);
            }
        }
        // Session sync likewise has no durable batch-generation proof; keep the global clear fence.
        let persistent = persistent.filter(|(key, _)| {
            match live.persistent_by_source.get(key) {
                // #10784 R2B1: address-only twin of the PAT liveness gate above.
                // An expired idle replacement still awaiting GC must not be
                // reactivated by a stale pre-clear session.
                Some(lease) => {
                    (!lease.revoked || lease.active_flows > 0 || lease.inbound_flows > 0)
                        && (lease.active_flows > 0
                            || lease.inbound_flows > 0
                            || lease.expires_at_ns > now_ns)
                }
                None => !live.persistent_nat_import_is_clear_fenced(key, now_ns),
            }
        });
        // The persistent-table budget is independent of the live-flow budget:
        // an address-only synced session may mint a lease only if a bounded
        // pressure-GC pass leaves room for its new source key. Joining an
        // existing lease below does not add a table entry. #16013: the same
        // per-source fairness gate as the local paths.
        if persistent.is_some_and(|(key, _)| !live.persistent_by_source.contains_key(&key))
            && self.persistent_lease_capacity_reached(&mut live, now_ns)
        {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        if let Some((key, _)) = persistent {
            if !live.persistent_by_source.contains_key(&key)
                && self.persistent_source_lease_capacity_reached(&mut live, &key, now_ns)
            {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
            }
        }
        if let Some((persistent_key, _)) = persistent {
            if addr_index >= live.lease_expirations_by_addr.len() {
                return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
            }
            if let Some(lease) = live.persistent_by_source.get(&persistent_key).copied() {
                // A lease naming a DIFFERENT address than the wire does is
                // config drift or a stale import. Refuse rather than retarget —
                // the same posture #7360 takes on the port-bearing arm, and the
                // caller falls through to the next rule. Deliberately NOT
                // counted as exhaustion: nothing is full. (The caller discards
                // the reason; the `Err` itself is the signal.)
                if lease.translated != translated || lease.addr_index != addr_index {
                    return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
                }
            }
        }
        if let Some(existing) = existing {
            // #13691: retain the incumbent until collision, capacity, and lease
            // admission have all succeeded.
            self.unlink_live_allocation_captured(&mut live, &flow, existing, now_ns);
            Self::complete_persistent_lease_locked(&mut live, existing, now_ns);
        }
        // Fold 2: claim the tracked slot atomically BEFORE the
        // owner/lease commit below (the earlier len() check is
        // not atomic across shards). On loss, nothing has been
        // committed except an incumbent unlink (snapshot-held).
        if !self.shared.flows.admit_one(self.shared.max_tracked_flows) {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        live.insert_address_only_owner(rkey, flow);
        // #8132: join the source's lease, or mint it on the first session for
        // that source. `active_flows` starts at 1 and is DERIVED from imports
        // that actually succeeded, never carried from the peer — the standby
        // installs a strict subset of what the active sends, and a refcount
        // that never reaches zero is never idle, so a credited-but-absent flow
        // would strand the lease outside every GC path.
        //
        // `expires_at_ns` comes from the LOCAL clock: the peer's value derives
        // from CLOCK_MONOTONIC and is meaningless across nodes. That is sound
        // rather than approximate, because the reuse predicate is
        // `active_flows > 0 || expires_at_ns > now_ns` — while any flow is
        // active the expiry is never consulted, and
        // `complete_persistent_lease_locked` re-arms it from the local clock
        // the moment the last flow releases.
        // #10789-F4 (Q1): as on the port-bearing arm — `persistent` is `Some`
        // only from `reserve_synced_on_first_pool_owner` (the `None` wrapper
        // `reserve_address_only` never touches `persistent_by_source`), so a
        // lease minted here is peer-derived: `imported: true`.
        let persistent_key = persistent.map(|(persistent_key, timeout_ns)| {
            let timeout_ns = bounded_persistent_nat_timeout_ns(timeout_ns);
            if live.persistent_by_source.contains_key(&persistent_key) {
                // #8132/#17028: the shared 0->1 join re-arms the
                // activation-rollback snapshot (an idle #8121 import
                // carries no previous state, so rollback would delete
                // it) and de-indexes the idle expiry — replacing the
                // open-coded `idle_lease_to_deindex` tail below.
                // Synced joins preserve peer origin.
                let _ = lease_table::join_persistent_lease_locked(
                    &mut live,
                    persistent_key,
                    lease_table::JoinPolicy {
                        timeout_ns,
                        promote_imported: false,
                        refresh_expiry: false,
                    },
                    now_ns,
                );
            } else {
                live.insert_persistent_lease(
                    persistent_key,
                    PersistentLease {
                        translated,
                        incarnation: 0,
                        addr_index,
                        expires_at_ns: now_ns.saturating_add(timeout_ns),
                        timeout_ns,
                        active_flows: 1,
                        inbound_flows: 0,
                        completed_flows: 0,
                        activation_saw_completion: false,
                        activation_previous_expires_at_ns: 0,
                        activation_had_previous_lease: false,
                        activation_previous_timeout_ns: 0,
                        deterministic: false,
                        deterministic_identity: None,
                        address_only: true,
                        imported: true,
                        revoked: false,
                    },
                );
            }
            persistent_key
        });
        self.shared.flows.insert_in_shard(
            &mut live.shard,
            flow,
            LiveAllocation {
                translated,
                persistent_key,
                // Inert for the release of an address-only record, which frees
                // no port bit — but it is what the LOCAL
                // `reserve_address_only_persistent` stores, and the standby's
                // allocator state has to be readable as the same thing.
                addr_index,
                deterministic: false,
                address_only: true,
                // #6211 F2: the first holder of this synced address-only token.
                promotion_timeout_ns: None,
                holders: holder.bit(),
            },
        );
        self.shared
            .allocations_total
            .fetch_add(1, Ordering::Relaxed);
        *previous_snapshot = live.previous_snapshot();
        Ok(translated)
    }

    /// #6751: mint the translated identity for an INTERFACE-mode source-NAT
    /// flow — preserve the source port when its reverse identity is free, PAT
    /// the LATER collider when it is not.
    ///
    /// This is [`reserve_address_only`] plus the fallback pool mode cannot
    /// have. Pool mode denies a colliding address-only flow as exhaustion
    /// because `port no-translation` means what it says: the port must not
    /// move. Interface mode carries no such promise, so instead of dropping the
    /// second host it moves its port and both flows keep a UNIQUE reverse
    /// identity — which is the whole point, since the reply
    /// `(server -> egress:port)` carries nothing else to tell them apart.
    ///
    /// Occupancy is the full reverse identity `(protocol, egress address,
    /// translated port, remote ip, remote port)` — the shipped
    /// [`AddressOnlyReverseKey`]. So:
    ///   * the same source port to two DIFFERENT servers: BOTH preserve;
    ///   * TCP and UDP on the same numeric port: BOTH preserve;
    ///   * a source port below 1024: PRESERVED when free (PAT candidates are
    ///     drawn from the ephemeral range, but preservation is not);
    ///   * two hosts, one port, one server: the first preserves, the second
    ///     PATs. Only the second flow's wire tuple changes.
    ///
    /// No pool PORT bit is claimed (`address_only: true`), so the record is
    /// byte-identical in shape to every other address-only token and the
    /// EXISTING teardown (`release_flow` / `rollback_flow` via
    /// `release_source_nat_allocation*`) frees it — no new delete site. That is
    /// load-bearing: `release_source_nat_allocation_with_mode` reconstructs
    /// `translated.port` as `rewrite_src_port.unwrap_or(key.src_port)`, which
    /// is the preserved port for a preserved mint and the PAT'd port for a
    /// PAT'd one, matching `LiveAllocation::translated` in both cases.
    ///
    /// Idempotent: a second packet of the same flow returns its first decision.
    pub(super) fn allocate_interface_identity(
        &self,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        holder: NatHolder,
    ) -> Result<InterfaceIdentity, super::source::SourceNatFailureReason> {
        self.allocate_interface_identity_excluding(flow, translated_ip, holder, false, &|_| false)
    }

    /// #15109: must-PAT variant of [`Self::allocate_interface_identity`].
    ///
    /// When a peer pool/NAT64 allocator already owns the preserved port,
    /// the caller must not preserve it, and the PAT walk must not select
    /// any other peer-owned candidate either. `must_pat` skips the
    /// preserve-first arm; `excluded` is consulted for every PAT
    /// candidate so a peer-owned candidate is skipped rather than
    /// minted and rolled back.
    ///
    /// No synthetic flow key is fabricated: the real `flow` is the only
    /// record minted, so no rollback can unlink a real host's record
    /// that happens to alias a made-up key.
    pub(super) fn allocate_interface_identity_excluding(
        &self,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        holder: NatHolder,
        must_pat: bool,
        excluded: &dyn Fn(u16) -> bool,
    ) -> Result<InterfaceIdentity, super::source::SourceNatFailureReason> {
        let rkey_for = |port: u16| AddressOnlyReverseKey::for_flow(&flow, translated_ip, port);
        let preserved = flow.src_port;
        // #13944: the reverse NAT key for UDP H:source -> P:destination
        // is P:destination -> egress:source. For the firewall's fixed
        // IKE/NAT-T ports this aliases the host-local LocalDelivery key when
        // both ports match. Force PAT before preserve-first for exact control
        // tuples; the PAT loop also excludes a matching fixed-port candidate.
        let reserved_local_tuple = crate::nat::iface_registry::conflicts_with_local_control_tuple(
            flow.protocol,
            flow.src_port,
            flow.dst_port,
        );
        {
            let mut live = self.lock_live();
            let mut __shard = self.shared.flows.get_mut_shard(&flow);
            // Idempotent re-entry, and the point every already-holding worker
            // lands on for a refresh.
            if let Some(identity) =
                self.reenter_interface_record_locked(&mut __shard, &flow, holder, preserved)
            {
                return Ok(identity);
            }
            if self.shared.flows.len() >= self.shared.max_tracked_flows {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::InterfaceRegistryCap);
            }
            // PRESERVE-FIRST. Identity check and insert happen under ONE
            // acquisition, so two workers cannot both observe the port free.
            if !must_pat
                && !reserved_local_tuple
                && !excluded(preserved)
                && !live.address_only_owners.contains_key(&rkey_for(preserved))
            {
                if self.insert_interface_record_locked(
                    &mut live,
                    &mut __shard,
                    flow,
                    translated_ip,
                    preserved,
                    holder,
                ) {
                    return Ok(InterfaceIdentity {
                        port: preserved,
                        patted: false,
                    });
                }
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::InterfaceRegistryCap);
            }
        }
        // The preserved identity is owned by a DIFFERENT flow: this is the
        // #6751 shape. Walk the ephemeral range for a free identity.
        //
        // #16011: the start offset is the RFC 6056 keyed hash of this
        // flow's tuple under the per-boot secret, captured ONCE and
        // walked locally from there. The pre-fix start was a shared
        // round-robin counter (`addr_counter_v4 % span`), so successive
        // PAT mints handed out successive ports an observer could
        // predict. The walk stays bounded (one full cycle, chunked).
        crate::nat::iface_registry::INTERFACE_SNAT_PAT_COLLISIONS.fetch_add(1, Ordering::Relaxed);
        let span = u32::from(self.port_high) - u32::from(self.port_low) + 1;
        let start = pat_keyed_offset(pat_secret(), Self::pat_key(&flow), span);
        let mut probed = 0u32;
        while probed < span {
            let mut live = self.lock_live();
            let mut __shard = self.shared.flows.get_mut_shard(&flow);
            // A chunk boundary released the mutex, so re-check the two
            // preconditions the first critical section established. Without
            // this a racing install of the SAME flow (a bulk-sync fan-out
            // landing while a local packet probes) would mint a SECOND record
            // for one flow, and only one of them would ever be released.
            if let Some(identity) =
                self.reenter_interface_record_locked(&mut __shard, &flow, holder, preserved)
            {
                return Ok(identity);
            }
            if self.shared.flows.len() >= self.shared.max_tracked_flows {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::InterfaceRegistryCap);
            }
            let chunk_end = (probed + INTERFACE_PAT_PROBE_CHUNK).min(span);
            while probed < chunk_end {
                // `span <= 65536` always (`port_high - port_low + 1`), so
                // `offset` fits a u16 and `port_low + offset <= port_high`
                // by construction — the saturating add is belt-and-braces,
                // never a reachable clamp.
                let offset = (start + probed) % span;
                let candidate = self.port_low.saturating_add(offset as u16);
                probed += 1;
                if excluded(candidate)
                    || crate::nat::iface_registry::conflicts_with_local_control_tuple(
                        flow.protocol,
                        candidate,
                        flow.dst_port,
                    )
                    || live.address_only_owners.contains_key(&rkey_for(candidate))
                {
                    continue;
                }
                if self.insert_interface_record_locked(
                    &mut live,
                    &mut __shard,
                    flow,
                    translated_ip,
                    candidate,
                    holder,
                ) {
                    return Ok(InterfaceIdentity {
                        port: candidate,
                        patted: true,
                    });
                }
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::InterfaceRegistryCap);
            }
            // #4676 discipline: yield between chunks so a full-cycle probe
            // cannot hold the mutex against every other worker's admission.
            drop(live);
            std::thread::yield_now();
        }
        // Every port in the range is owned for this `(egress, remote)`
        // identity. Fail CLOSED — an unowned duplicate is precisely what this
        // function exists to prevent.
        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(super::source::SourceNatFailureReason::InterfaceIdentityExhausted)
    }

    /// #6751: reserve a PEER-SYNCED interface-mode translated identity — the
    /// standby's mirror of [`allocate_interface_identity`], with the port
    /// already decided by the active node.
    ///
    /// The standby must hold the identities the active minted BEFORE it ever
    /// mints locally, or its first post-failover admission would preserve a
    /// port an imported live session is already using and reintroduce the
    /// ambiguity on the promoted node.
    ///
    /// Mirrors [`reserve_flow`]'s stale-tuple semantics rather than inventing
    /// new ones: a re-sync that carries a DIFFERENT translated port for a flow
    /// already on record replaces the record (freeing the old identity), so a
    /// tuple-changing refresh cannot strand an identity no release will ever
    /// name. `Owned` on success or idempotent re-entry; `IdentityConflict` when
    /// a DIFFERENT flow owns the requested identity.
    pub(super) fn reserve_interface_identity(
        &self,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        translated_port: u16,
        now_ns: u64,
        holder: NatHolder,
        capture_previous_holders: bool,
        previous_snapshot: &mut Option<SourceNatReservationSnapshot>,
    ) -> InterfaceDomainReserve {
        if crate::nat::iface_registry::conflicts_with_local_control_tuple(
            flow.protocol,
            translated_port,
            flow.dst_port,
        ) {
            // #13944: HA imports must obey the active node's local-service
            // exclusion too; never publish an interface-SNAT identity that
            // aliases the local IKE/NAT-T session.
            return InterfaceDomainReserve::IdentityConflict;
        }
        let rkey = AddressOnlyReverseKey::for_flow(&flow, translated_ip, translated_port);
        let mut live = self.capture_and_replace(&flow, capture_previous_holders);
        if let Some(existing) = self.shared.flows.get_in_shard(&live.shard, &flow) {
            if existing.translated.ip == translated_ip
                && existing.translated.port == translated_port
            {
                if let Some(slot) = live.shard.map.get_mut(&flow) {
                    self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
                }
                *previous_snapshot = live.previous_snapshot();
                return InterfaceDomainReserve::Owned;
            }
            // A different flow may already own the NEW identity; refuse before
            // tearing down the old record so a refused reserve is a no-op.
            if live
                .address_only_owners
                .get(&rkey)
                .is_some_and(|o| *o != flow)
            {
                return InterfaceDomainReserve::IdentityConflict;
            }
            self.unlink_live_allocation_captured(&mut live, &flow, existing, now_ns);
            Self::complete_persistent_lease_locked(&mut live, existing, now_ns);
        } else if live
            .address_only_owners
            .get(&rkey)
            .is_some_and(|o| *o != flow)
        {
            return InterfaceDomainReserve::IdentityConflict;
        } else if self.shared.flows.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return InterfaceDomainReserve::RegistryCap;
        }
        if !self.insert_interface_record_captured(
            &mut live,
            flow,
            translated_ip,
            translated_port,
            holder,
        ) {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return InterfaceDomainReserve::RegistryCap;
        }
        *previous_snapshot = live.previous_snapshot();
        InterfaceDomainReserve::Owned
    }

    /// #6751: the idempotent-re-entry answer, shared by the first critical
    /// section and the chunk-boundary re-check.
    ///
    /// ONE body, because a divergence between the two is always a bug: the
    /// chunk re-check exists precisely to catch a racing install of the SAME
    /// flow, and a copy that computed `patted` differently would hand one flow
    /// two different wire decisions depending on which acquisition saw it.
    /// Records the holder on the way through, exactly as `reserve_address_only`
    /// does on its own early return.
    fn reenter_interface_record_locked(
        &self,
        shard: &mut flows::LiveFlowShard,
        flow: &SourceNatFlowKey,
        holder: NatHolder,
        preserved: u16,
    ) -> Option<InterfaceIdentity> {
        let existing = shard.map.get_mut(flow)?;
        let translated = self.reenter_existing_locked(existing, holder, ReuseCount::Counted);
        Some(InterfaceIdentity {
            port: translated.port,
            patted: translated.port != preserved,
        })
    }

    /// The record shape shared by every interface-mode mint and reserve, so a
    /// preserved token, a PAT'd token and a synced token cannot drift apart in
    /// the one field that decides how they are torn down (`address_only`).
    fn insert_interface_record_captured(
        &self,
        live: &mut CapturedLiveGuard<'_>,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        translated_port: u16,
        holder: NatHolder,
    ) -> bool {
        self.insert_interface_record_locked(
            &mut live.live,
            &mut live.shard,
            flow,
            translated_ip,
            translated_port,
            holder,
        )
    }

    fn insert_interface_record_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        shard: &mut flows::LiveFlowShard,
        flow: SourceNatFlowKey,
        translated_ip: IpAddr,
        translated_port: u16,
        holder: NatHolder,
    ) -> bool {
        // Fold 2: claim the slot atomically BEFORE publishing
        // the owner token; callers refuse/skip on false.
        if !self.shared.flows.admit_one(self.shared.max_tracked_flows) {
            return false;
        }
        live.insert_address_only_owner(
            AddressOnlyReverseKey::for_flow(&flow, translated_ip, translated_port),
            flow,
        );
        self.shared.flows.insert_in_shard(
            shard,
            flow,
            LiveAllocation {
                translated: TranslatedTuple {
                    ip: translated_ip,
                    port: translated_port,
                },
                persistent_key: None,
                // Interface mode claims no pool-port bit, so no address index
                // is meaningful; `address_only` routes the teardown to the
                // reverse-identity arm of `unlink_live_allocation_locked`.
                addr_index: 0,
                deterministic: false,
                address_only: true,
                promotion_timeout_ns: None,
                holders: holder.bit(),
            },
        );
        self.shared
            .allocations_total
            .fetch_add(1, Ordering::Relaxed);
        true
    }

    /// #6226: reserve a non-deterministic, non-persistent ADDRESS-ONLY token
    /// probing the WHOLE pool from the round-robin start, mirroring the
    /// port-translating [`allocate_translation`] loop.
    ///
    /// The pre-#6226 caller picked ONE round-robin address via [`address_index`]
    /// and called [`reserve_address_only`] on it — a single probe that returned
    /// `AllocatorExhausted` (→ drop) the moment that one address's reverse
    /// identity collided for this remote, even though a SIBLING pool address was
    /// free for the same remote. The shared round-robin counter is oblivious to
    /// per-remote occupancy, so an unrelated flow advancing it trivially lands a
    /// later flow on an already-owned address. This loops from the caller's
    /// round-robin start (`start_abs`, already resolved via [`address_index`] so
    /// the counter is advanced EXACTLY ONCE per flow — same as the old single
    /// probe) across every pool address and mints the token on the FIRST address
    /// whose reverse identity is free; it fails as exhaustion ONLY when EVERY
    /// pool address collides for this remote.
    ///
    /// `address_persistent` keeps the single-probe contract for sticky-by-source
    /// pools (`address_attempts == 1`): the sticky address is intentional, not
    /// round-robin, so it is not rotated away from on a collision. The
    /// deterministic-CGNAT (#5341) and address-only persistent-NAT (#6041)
    /// branches are untouched — they correctly single-probe their chosen address.
    ///
    /// The minted token is byte-identical in shape to [`reserve_address_only`]'s
    /// (`translated = (chosen address, preserved source port)`, `address_only =
    /// true`, `persistent_key = None`, `addr_index = family_offset + rel` — the
    /// selected index, #13690/#14622), so the SAME
    /// `release_flow`/`rollback_flow` teardown frees it — no new leak, no new
    /// delete site. Idempotent re-entry (a racing second packet of the same
    /// flow) returns the existing translation regardless of the round-robin
    /// start.
    pub(super) fn reserve_address_only_roundrobin(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        start_abs: usize,
        address_persistent: bool,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let family_len = family_addresses.len();
        if family_len == 0 {
            return Err(super::source::SourceNatFailureReason::WrongAddressFamily);
        }
        let start_rel = start_abs.saturating_sub(family_offset) % family_len;
        // Sticky-by-source pools single-probe their chosen address; round-robin
        // pools rotate through the whole pool (mirrors `allocate_translation`).
        let address_attempts = if address_persistent { 1 } else { family_len };

        let mut live = self.lock_live();
        // Idempotent re-entry: a second packet of the same flow (racing session
        // install) reuses its first decision rather than re-keying.
        let mut __shard = self.shared.flows.get_mut_shard(&flow);
        if let Some(slot) = __shard.map.get_mut(&flow) {
            let existing = self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
            return Ok(existing);
        }
        // Global flow-table cap (the address-only token lives in `live_by_flow`);
        // one successful probe inserts exactly one entry, so check it once here.
        if self.shared.flows.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        // Probe each pool address from the round-robin start; the FIRST whose
        // reverse identity is free for this remote wins.
        for offset in 0..address_attempts {
            let rel = (start_rel + offset) % family_len;
            let translated_ip = family_addresses.ip_at(rel);
            let rkey = AddressOnlyReverseKey {
                protocol: flow.protocol,
                translated_ip,
                translated_port: flow.src_port,
                dst_ip: flow.dst_ip,
                dst_port: flow.dst_port,
            };
            let translated = TranslatedTuple {
                ip: translated_ip,
                // Port-bearing protocols preserve their source port; a port-less
                // protocol carries 0. NOT written to the wire (the caller leaves
                // `rewrite_src_port` unset); it keys the reverse identity and lets
                // the SAME `release_flow` free the token.
                port: flow.src_port,
            };
            // #14671: a live token, an idle persistent lease (scoped to its
            // permit grants), or a PAT owner of this reverse identity for
            // this remote — try the next sibling instead of dropping.
            if live.address_only_owners.contains_key(&rkey)
                || live.pat_owns_wire_identity(&flow, translated)
                || live.persistent_address_only_contended_except(&flow, translated, None)
            {
                continue;
            }
            live.insert_address_only_owner(rkey, flow);
            if !self.shared.flows.try_insert_in_shard(
                &mut __shard,
                flow,
                LiveAllocation {
                    translated,
                    persistent_key: None,
                    // No pool-port bit is claimed for an address-only token.
                    // Address-only allocations still retain the selected pool
                    // index for pool-reseed remapping; this is an absolute index
                    // across the combined v4/v6 address family.
                    addr_index: family_offset + rel,
                    deterministic: false,
                    address_only: true,
                    // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                    // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                    // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                    // this worker) and each sibling reserves against this same record, so
                    // without this bit the mask holds every worker EXCEPT the one actually
                    // forwarding — and the last sibling replica to age-reap frees a
                    // `(pool_addr, port)` still in use. Recording the owner here makes the
                    // mask complete, so the port survives until the owner itself releases.
                    promotion_timeout_ns: None,
                    holders: holder.bit(),
                },
                self.shared.max_tracked_flows,
            ) {
                // Fold 2: admission lost — retract the owner
                // token just published and report exhaustion.
                live.remove_address_only_owner(&rkey);
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
            }
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(translated);
        }
        // Every pool address's reverse identity is already owned by a different
        // flow for this remote — genuine address-only exhaustion.
        self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
        Err(super::source::SourceNatFailureReason::AllocatorExhausted)
    }

    /// #6041: reserve an ADDRESS-ONLY PERSISTENT-NAT lease for a `port
    /// no-translation` (or port-less) flow whose pool also configures
    /// `persistent-nat`. Unlike [`reserve_address_only`] (the per-flow #5269
    /// collision token with NO lease) this PINS a public pool ADDRESS across the
    /// configured permit scope: every flow keyed to the same
    /// [`PersistentSourceKey`] reuses the SAME public address for the lease's
    /// lifetime, so persistence no longer depends on the global
    /// `address-persistent` hash (the #5819/#6041 defect the fail-closed reject
    /// stood in for). No pool PORT is consumed — the packet keeps its own source
    /// port on the wire — so the lease records `address_only = true` and every
    /// lease teardown site skips `free_translated_port`.
    ///
    /// Lifecycle mirrors the port-translating persistent lease
    /// ([`allocate_translation_locked`] + [`reuse_existing_lease_locked`]):
    ///   - a live/valid lease REUSES its pinned address, bumps `active_flows`,
    ///     re-arms the activation-rollback bookkeeping on the 0->1 edge, drops
    ///     its idle expiry-index entry, and pushes the inactivity expiry out;
    ///   - an EXPIRED idle lease is torn down (NO port to free) and a fresh
    ///     address is picked via [`address_index`];
    ///   - no lease => a fresh address is picked and a new lease created.
    ///
    /// The #5269 reverse-identity collision guard still runs PER FLOW: THIS
    /// flow's `(protocol, chosen address, preserved source port, remote)` token
    /// is claimed in `address_only_owners` and DENIED as exhaustion if a
    /// DIFFERENT flow already owns it (two flows sharing one public reverse tuple
    /// cannot coexist). On a collision the lease is left untouched. The token AND
    /// the lease refcount are torn down PER FLOW by the SAME teardown path
    /// (`release_flow`/`rollback_flow`) — no new delete site. Idempotent: a
    /// second packet of the same flow returns its existing translated tuple.
    ///
    /// #9131: on that collision a FRESH, non-sticky lease now probes the
    /// REMAINING pool addresses before reporting exhaustion, the same `continue`
    /// [`reserve_address_only_roundrobin`] makes. Only the retry was missing —
    /// the refusal is correct and is kept for the two PINNED cases, an
    /// `address-persistent` pool (the address is a pure function of the source)
    /// and an EXISTING lease (the address is pinned by `persistent-nat` for the
    /// permit scope's lifetime). A blanket fallback would break both.
    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    pub(super) fn reserve_address_only_persistent(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_permit_epoch: u64,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        // #6522: the worker performing this LOCAL allocation, so the record
        // it inserts already names its own holder before any sibling replica
        // reserves against it. `NatHolder::Untracked` reproduces the
        // pre-#6522 single-holder contract and is what the test entry points
        // and the read-only fragment probe pass.
        holder: NatHolder,
        egress_scope: u32,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        self.reserve_address_only_persistent_with_zones(
            flow,
            family_addresses,
            family_offset,
            address_persistent,
            persistent_nat_permit,
            persistent_permit_epoch,
            persistent_nat_timeout_ns,
            now_ns,
            holder,
            egress_scope,
            None,
        )
    }

    #[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
    pub(super) fn reserve_address_only_persistent_with_zones(
        &self,
        flow: SourceNatFlowKey,
        family_addresses: PoolAddressFamily<'_>,
        family_offset: usize,
        address_persistent: bool,
        persistent_nat_permit: super::source::PersistentNatPermit,
        persistent_permit_epoch: u64,
        persistent_nat_timeout_ns: u64,
        now_ns: u64,
        holder: NatHolder,
        egress_scope: u32,
        mint_from_zone: Option<&str>,
    ) -> Result<TranslatedTuple, super::source::SourceNatFailureReason> {
        let family_len = family_addresses.len();
        if family_len == 0 {
            return Err(super::source::SourceNatFailureReason::WrongAddressFamily);
        }
        let key = flow.persistent_source_key(persistent_nat_permit);
        let timeout_ns = bounded_persistent_nat_timeout_ns(persistent_nat_timeout_ns);

        let mut live = self.lock_live();
        self.gc_expired_locked(&mut live, now_ns, ALLOCATION_GC_BUDGET);

        // Idempotent re-entry: a second packet of the same flow reuses its first
        // decision rather than re-keying / double-counting the lease refcount.
        let mut __shard = self.shared.flows.get_mut_shard(&flow);
        if let Some(slot) = __shard.map.get_mut(&flow) {
            let existing = self.reenter_existing_locked(slot, holder, ReuseCount::Counted);
            return Ok(existing);
        }
        drop(__shard);
        if self.shared.flows.len() >= self.shared.max_tracked_flows {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        // Resolve the lease's pinned address: reuse a still-valid lease, tear down
        // a reclaimable one, else pick fresh.
        let mut reuse_addr: Option<(IpAddr, usize)> = None;
        // #9158: the teardown tuple now carries the lease's PORT and its MODE,
        // mirroring the port-bearing `expired` tuple in
        // `reuse_persistent_lease_locked`. Before this it was
        // `(addr_index, expires_at_ns)` and the arm freed nothing, so every
        // PAT -> address-only flip orphaned the lease's occupancy bit.
        let mut expired: Option<(TranslatedTuple, usize, u64, bool, bool)> = None;
        // #9158: a LIVE PAT lease must be left standing. See the arm below.
        let mut live_mode_mismatch = false;
        // #8597 K10, the mirror of the port-bearing gate: this is the
        // ADDRESS-ONLY path, so a PAT lease must not be reused here either.
        // A PAT lease's port belongs to the lease, and adopting its pinned
        // address for an address-only flow would leave the two modes'
        // bookkeeping disagreeing about who owns the identity. A mismatch
        // falls to the expired arm, which tears down mode-correctly.
        if let Some(lease) = live.persistent_by_source.get(&key).copied() {
            if lease.revoked {
                if lease.active_flows > 0 || lease.inbound_flows > 0 {
                    live_mode_mismatch = true;
                } else {
                    expired = Some((
                        lease.translated,
                        lease.addr_index,
                        lease.expires_at_ns,
                        lease.address_only,
                        lease.deterministic,
                    ));
                }
            } else if lease.address_only
                && (lease.active_flows > 0
                    || lease.inbound_flows > 0
                    || lease.expires_at_ns > now_ns)
            {
                reuse_addr = Some((lease.translated.ip, lease.addr_index));
            } else if !lease.address_only && (lease.active_flows > 0 || lease.inbound_flows > 0) {
                // #9158: MODE MISMATCH UNDER A LIVE LEASE. An ordinary operator
                // commit reaches here -- `allocator_key()` is built from the pool
                // name, addresses and range and does NOT include
                // `no_translation`, so flipping that leaf keeps the SAME
                // allocator and carries the leases across (stated at
                // `reuse_persistent_lease_locked`).
                //
                // Neither other arm is correct here, and both are harmful:
                //
                //   * REUSE is what #8597 K10 forbids: an address-only flow
                //     adopting a PAT lease leaves the two modes' bookkeeping
                //     disagreeing about who owns the identity.
                //   * TEAR DOWN cannot free the port, because a live PAT flow is
                //     still forwarding on it -- freeing the bit would let
                //     `claim()` hand the same `(address, port)` to a second flow,
                //     the duplicate this allocator exists to prevent. And NOT
                //     freeing it is the #9158 leak: removing the record puts the
                //     bit beyond BOTH recovery paths
                //     (`reclaim_expired_lease_locked` starts from
                //     `persistent_by_source.get(&key)`, and
                //     `unlink_live_allocation_locked` frees a port only when
                //     `persistent_key.is_none()`), so it is held for the
                //     allocator's lifetime. Measured, not inferred: the #9158
                //     cell sweeps GC 10000 s past every timeout AND releases the
                //     live flow, and the bit survives both.
                //
                // So the lease is LEFT STANDING and this flow is served without
                // persistence: `persistent_key: None` below, no lease insert, no
                // refcount. The lease keeps owning its bit until its own flows
                // drain, at which point `complete_persistent_lease_locked` takes
                // `active_flows` to 0, the lease enters `lease_expirations` and
                // `reclaim_expired_lease_locked` frees the port correctly.
                //
                // The cost is bounded and it is the right one: this flow loses
                // its ADDRESS PINNING until the stale lease drains. It is not
                // dropped, nothing is over-released, and the state converges with
                // no operator action. Refusing the flow instead would turn a
                // supported config edit into an outage.
                live_mode_mismatch = true;
            } else {
                expired = Some((
                    lease.translated,
                    lease.addr_index,
                    lease.expires_at_ns,
                    lease.address_only,
                    lease.deterministic,
                ));
            }
        }
        if expired.is_some() {
            // Reclaimable: idle and past its inactivity window, or an
            // IDLE lease in the other mode. #17028: the shared retire
            // drops the expiry entries + lease and reports the port
            // to free by-mode (a PAT lease's bit, #9158; an
            // address-only lease holds none, #6041).
            if let Some(retired) = lease_table::retire_idle_lease_locked(&mut live, &key) {
                if let Some((addr_index, port)) = retired.freed_port {
                    self.free_translated_port_at(addr_index, port, now_ns);
                }

            }
        }

        let reusing = reuse_addr.is_some();
        if reusing
            && live
                .persistent_permissions
                .get(&key)
                .is_some_and(|permissions| {
                    !permissions.can_record(persistent_nat_permit, flow, egress_scope)
                })
        {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        // #5269 reverse-identity collision guard for THIS flow, checked BEFORE any
        // lease mutation so a denied flow leaves the lease untouched. The
        // preserved source port keys the reverse identity (0 for a port-less
        // protocol); it is never written to the wire (the caller leaves
        // `rewrite_src_port` unset).
        //
        // #9131: on a collision a FRESH, non-sticky lease probes the remaining
        // pool addresses instead of reporting exhaustion, mirroring
        // `reserve_address_only_roundrobin`'s `continue`. For a PORT-LESS
        // protocol (GRE/ESP/ICMP) the identity degenerates to
        // `(proto, translated_ip, 0, dst_ip, 0)`, so two tunnels from different
        // subscribers to the SAME popular remote — a VPN concentrator, a cloud
        // SASE endpoint — collide the moment they land on one pool address, and
        // the second was denied while other pool addresses sat idle.
        //
        // The refusal itself is correct and is KEPT for the two PINNED cases;
        // only the missing retry was the defect:
        //   * `address_persistent` — the address is `sticky_pool_index(src_ip)`,
        //     a pure function of the source (#14627). Probing on would break the
        //     `address-persistent` contract, so the sibling
        //     `reserve_address_only_roundrobin` likewise sets
        //     `address_attempts = 1` here.
        //   * an EXISTING lease (`reusing`) — the address is pinned by
        //     `persistent-nat` for the permit scope's lifetime and must not
        //     move. Two flows sharing one public reverse identity are genuinely
        //     ambiguous on the return path, so this stays fail-CLOSED.
        let rkey_for = |ip: IpAddr| AddressOnlyReverseKey {
            protocol: flow.protocol,
            translated_ip: ip,
            translated_port: flow.src_port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
        };
        let chosen = match reuse_addr {
            // Pinned by an existing lease: single probe, no rotation.
            Some((ip, idx)) => {
                let rkey = rkey_for(ip);
                let translated = TranslatedTuple {
                    ip,
                    port: flow.src_port,
                };
                (!live.address_only_owners.contains_key(&rkey)
                    && !live.pat_owns_wire_identity(&flow, translated)
                    && !live.persistent_address_only_contended_except(&flow, translated, Some(key)))
                .then_some((ip, idx, rkey))
            }
            None => {
                let abs =
                    self.address_index(flow.src_ip, family_offset, family_len, address_persistent);
                let start_rel = abs.saturating_sub(family_offset) % family_len;
                // Sticky-by-source pools single-probe their chosen address;
                // round-robin pools rotate through the whole pool.
                let attempts = if address_persistent { 1 } else { family_len };
                (0..attempts)
                    .map(|offset| (start_rel + offset) % family_len)
                    .find_map(|rel| {
                        let ip = family_addresses.ip_at(rel);
                        let rkey = rkey_for(ip);
                        let translated = TranslatedTuple {
                            ip,
                            port: flow.src_port,
                        };
                        (!live.address_only_owners.contains_key(&rkey)
                            && !live.pat_owns_wire_identity(&flow, translated)
                            && !live
                                .persistent_address_only_contended_except(&flow, translated, None))
                        .then_some((ip, family_offset + rel, rkey))
                    })
            }
        };
        let Some((translated_ip, addr_index, rkey)) = chosen else {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        };

        // Lease-table pressure cap for a FRESH lease, mirroring
        // `allocate_translation_locked`: one bounded GC pass, then treat a still-
        // full table as exhaustion.
        // #9158: `live_mode_mismatch` inserts NO lease (see the arm above), so the
        // LEASE-table pressure cap does not apply to it -- gating it here would
        // refuse a flow on behalf of a table it is not about to grow.
        // #16013: per-source fairness for the same fresh lease, checked after
        // the pool-global pass so both get their pressure-GC chance; like that
        // pass it does not apply to a mode-mismatch flow (no lease is minted).
        if !reusing
            && !live_mode_mismatch
            && live.persistent_by_source.len() >= self.shared.max_tracked_flows
        {
            self.gc_expired_locked(&mut live, now_ns, PRESSURE_GC_BUDGET);
            if live.persistent_by_source.len() >= self.shared.max_tracked_flows {
                self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
                return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
            }
        }
        if !reusing
            && !live_mode_mismatch
            && self.persistent_source_lease_capacity_reached(&mut live, &key, now_ns)
        {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }

        let translated = TranslatedTuple {
            ip: translated_ip,
            port: flow.src_port,
        };
        let expires_at_ns = now_ns.saturating_add(timeout_ns);

        // Fold 2: claim the tracked slot atomically BEFORE the
        // owner/lease commit below.
        if !self.shared.flows.admit_one(self.shared.max_tracked_flows) {
            self.shared.exhaustion_total.fetch_add(1, Ordering::Relaxed);
            return Err(super::source::SourceNatFailureReason::AllocatorExhausted);
        }
        // Commit this flow's reverse-identity token (freed per flow on teardown).
        live.insert_address_only_owner(rkey, flow);

        let mut promotion_timeout_ns = None;
        if reusing {
            // #17028: the shared 0->1 join (snapshot, de-index,
            // timeout/promotion, refcount, expiry push-out).
            let outcome = lease_table::join_persistent_lease_locked(
                &mut live,
                key,
                lease_table::JoinPolicy {
                    timeout_ns,
                    promote_imported: true,
                    refresh_expiry: true,
                },
                now_ns,
            );
            if let lease_table::JoinOutcome::Joined {
                promotion_timeout_ns: marker,
                ..
            } = outcome
            {
                promotion_timeout_ns = marker;
            }
            self.shared.reuses_total.fetch_add(1, Ordering::Relaxed);
        } else if live_mode_mismatch {
            // #9158: the stale PAT lease is STILL IN THE MAP and still owns its
            // occupancy bit. Inserting here would overwrite that record under the
            // same `PersistentSourceKey` -- the same orphan this fix removes,
            // reached by a different route. This flow is served unpinned instead;
            // `persistent_key: None` below keeps its teardown from touching a
            // lease it does not own.
            //
            // `allocations_total` is deliberately NOT bumped: it counts LEASES
            // minted, and this path mints none.
        } else {
            // The batch/per-key clear fence survives this fresh local lease.
            live.insert_persistent_lease(
                key,
                PersistentLease {
                    translated,
                    incarnation: 0,
                    addr_index,
                    expires_at_ns,
                    timeout_ns,
                    active_flows: 1,
                    inbound_flows: 0,
                    completed_flows: 0,
                    activation_saw_completion: false,
                    activation_previous_expires_at_ns: 0,
                    activation_had_previous_lease: false,
                    activation_previous_timeout_ns: 0,
                    deterministic: false,
                    deterministic_identity: None,
                    address_only: true,
                    imported: false,
                    revoked: false,
                },
            );
            self.shared
                .allocations_total
                .fetch_add(1, Ordering::Relaxed);
        }

        if !live_mode_mismatch {
            live.record_persistent_permission_with_zones(
                key,
                persistent_nat_permit,
                flow,
                egress_scope,
                mint_from_zone,
                persistent_permit_epoch,
            );
        }
        let mut __shard = self.shared.flows.get_mut_shard(&flow);
        self.shared.flows.insert_in_shard(
            &mut __shard,
            flow,
            LiveAllocation {
                translated,
                // #9158: a flow served AROUND a live mode-mismatched lease owns no
                // lease, so it must not name one. With `Some(key)` its release
                // would run `complete_persistent_lease_locked` against the
                // SURVIVING PAT lease and decrement a refcount this flow never
                // incremented -- driving `active_flows` to 0 while that lease's
                // own PAT flows are still forwarding, which hands the lease to GC
                // and frees a port still in use.
                persistent_key: if live_mode_mismatch { None } else { Some(key) },
                addr_index,
                deterministic: false,
                address_only: true,
                // #6522: the ALLOCATING worker's holder bit. A locally-born session is
                // replicated to every SIBLING worker (`replicate_session_upsert` fans a
                // `WorkerLocalImport` entry to `peer_worker_commands`, which EXCLUDES
                // this worker) and each sibling reserves against this same record, so
                // without this bit the mask holds every worker EXCEPT the one actually
                // forwarding — and the last sibling replica to age-reap frees a
                // `(pool_addr, port)` still in use. Recording the owner here makes the
                // mask complete, so the port survives until the owner itself releases.
                promotion_timeout_ns,
                holders: holder.bit(),
            },
        );
        Ok(translated)
    }

    /// Test-only: a live flow's `(persistent_key, address_only)` pair.
    ///
    /// #9158: `live_by_flow` is private (unlike its sibling
    /// `persistent_by_source`), and whether a record NAMES a lease is exactly
    /// what distinguishes a flow served AROUND a live mode-mismatched lease from
    /// one that joined it. The outer `None` means no record for that flow, which
    /// a test must be able to tell from "a record that names no lease".
    #[cfg(test)]
    pub(super) fn debug_live_flow_lease(
        &self,
        flow: &SourceNatFlowKey,
    ) -> Option<(Option<PersistentSourceKey>, bool)> {
        self.shared
            .flows
            .get(flow)
            .map(|rec| (rec.persistent_key, rec.address_only))
    }

    /// Test-only: the translated tuple a live flow's record holds.
    ///
    /// #9536: releasing a flow through the allocator's own `release_flow` needs
    /// the tuple the allocator STORED, and for an address-only flow that is not
    /// derivable from the decision alone. Reading it back is what lets a test
    /// drain a lease deterministically instead of guessing the tuple and
    /// releasing nothing.
    #[cfg(test)]
    pub(super) fn debug_live_flow_translated(
        &self,
        flow: &SourceNatFlowKey,
    ) -> Option<TranslatedTuple> {
        self.flows_get(flow).map(|rec| rec.translated)
    }
    /// Test-only: the absolute pool index recorded for a live flow.
    #[cfg(test)]
    pub(super) fn debug_live_flow_addr_index(&self, flow: &SourceNatFlowKey) -> Option<usize> {
        self.flows_get(flow).map(|rec| rec.addr_index)
    }

    /// Test-only: snapshot the address-only reverse-identity ownership map so a
    /// white-box test can assert the reverse index resolves each public tuple to
    /// exactly one owning forward flow (#5269).
    #[cfg(test)]
    pub(super) fn debug_address_only_owners(
        &self,
    ) -> Vec<(AddressOnlyReverseKey, SourceNatFlowKey)> {
        let live = self.shared.live.read().unwrap_or_else(|e| e.into_inner());
        live.address_only_owners
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    pub(crate) fn snapshot(&self) -> PortAllocatorSnapshot {
        let live = self.shared.live.read().unwrap_or_else(|e| e.into_inner());
        let live_flows = self.shared.flows.len() as u64;
        let persistent_leases = live.persistent_by_source.len() as u64;
        drop(live);
        // used_ports is the total set bits across the lock-free occupancy
        // bitmaps (popcount). Cold path (1/s status poll), so recomputing it
        // is fine — and deliberate even though #7174 M13 now maintains a live
        // `occupied` counter per address: keeping this a popcount leaves the
        // bitmap an INDEPENDENT oracle for that counter rather than a second
        // name for it (`pool_snat_occupancy_counter_agrees_with_bitmap_7174_m13`
        // asserts they agree).
        let used_ports: u64 = self
            .shared
            .occupancy
            .iter()
            .map(|occ| occ.occupied_count() as u64)
            .sum();
        PortAllocatorSnapshot {
            allocator_id: self.shared.allocator_id,
            live_flows,
            used_ports,
            persistent_leases,
            max_tracked_flows: self.shared.max_tracked_flows as u64,
            allocations_total: self.shared.allocations_total.load(Ordering::Relaxed),
            reuses_total: self.shared.reuses_total.load(Ordering::Relaxed),
            exhaustion_total: self.shared.exhaustion_total.load(Ordering::Relaxed),
            idle_lease_import_capacity_total: self
                .shared
                .idle_lease_import_capacity_total
                .load(Ordering::Relaxed),
            persistent_admitted_total: self
                .shared
                .persistent_admitted_total
                .load(Ordering::Relaxed),
            persistent_declined_total: self
                .shared
                .persistent_declined_total
                .load(Ordering::Relaxed),
            flow_shard_lock_acquisitions_total: self
                .shared
                .flow_shard_lock_acquisitions
                .load(Ordering::Relaxed),
            flow_shard_lock_contended_total: self
                .shared
                .flow_shard_lock_contended
                .load(Ordering::Relaxed),
            live_write_lock_acquisitions_total: self
                .shared
                .live_write_lock_acquisitions
                .load(Ordering::Relaxed),
            live_write_lock_contended_total: self
                .shared
                .live_write_lock_contended
                .load(Ordering::Relaxed),
            // #17036: legacy summed totals, kept for one release.
            live_lock_acquisitions_total: self
                .shared
                .flow_shard_lock_acquisitions
                .load(Ordering::Relaxed)
                + self
                    .shared
                    .live_write_lock_acquisitions
                    .load(Ordering::Relaxed),
            live_lock_contended_total: self
                .shared
                .flow_shard_lock_contended
                .load(Ordering::Relaxed)
                + self
                    .shared
                    .live_write_lock_contended
                    .load(Ordering::Relaxed),
            // #9392: the recycled-phase walk cost, summed over the pool's
            // addresses. A POOL-level pair rather than per-address: the
            // operator surface is per pool, and the reachability question
            // ("does any address in this pool reach K-large / F-small") is
            // answered by the ratio crossing 1, which a sum preserves. A pool
            // where one address is pathological and nine are healthy shows a
            // ratio above 1, which is the signal; the per-address breakdown is
            // a follow-up an operator asks for only after that fires.
            recycle_scan_pops_total: self
                .shared
                .occupancy
                .iter()
                .map(|occ| occ.recycle_scan_pops.load(Ordering::Relaxed))
                .sum(),
            recycle_scan_walks_total: self
                .shared
                .occupancy
                .iter()
                .map(|occ| occ.recycle_scan_walks.load(Ordering::Relaxed))
                .sum(),
        }
    }

    pub(super) fn record_idle_lease_import_capacity(&self) {
        self.shared
            .idle_lease_import_capacity_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// #4676: run the opportunistic global expiry GC WITHOUT holding the alloc
    /// mutex across the whole sweep.
    ///
    /// The sweep is chunked: each chunk collects up to `GC_CHUNK` expired
    /// leases from the global expiration index under a SHORT `live` critical
    /// section (the map mutations that MUST be serialized), releases the guard,
    /// then frees those ports on the lock-free occupancy bitmap
    /// (`AddressOccupancy::free_recycle`, a `fetch_and` + per-address recycle
    /// push) with `live` NOT held. Releasing `live` between chunks lets a
    /// concurrent `allocate_translation` acquire the mutex for its tiny
    /// `live_by_flow` insert instead of blocking for the full sweep — the
    /// Phase-1 (#2852) residual this addresses.
    ///
    /// Safety: each reclaim stays idempotent. Under the short CS the lease is
    /// re-checked (`active_flows == 0 && expires_at_ns` matches) before removal,
    /// so a concurrent `release_flow`/`rollback_flow` that refreshed or bumped
    /// the lease is skipped. The port bit is the ownership token and stays SET
    /// from lease removal until we free it, so a concurrent `claim()` cannot
    /// re-hand-out the port in the gap (no double-claim); once freed it returns
    /// to the pool. `budget` bounds total reclaims (amortized GC). This is
    /// disjoint from the caller's insert CS: GC touches only
    /// `persistent_by_source` + the expiration indexes + occupancy, never
    /// `live_by_flow`, so running it in its own lock scope is behaviorally
    /// equivalent to the pre-#4676 nested call.
    fn gc_expired_chunked(&self, now_ns: u64, budget: usize) -> usize {
        if now_ns == 0 || budget == 0 {
            return 0;
        }
        // #15956 fold + #17041: GC is opportunistic on the new-flow
        // path — never stall admission behind a `live` writer for it.
        // Try the shared read guard: no expired lease (empty index or
        // earliest expiry in the future) skips the sweep with no write
        // acquisition; a contended lock (writer active) also skips,
        // and the next admission or release retries.
        // #17041: peek the earliest expiry, not just emptiness. With one
        // non-expired idle lease the old emptiness check fell through to
        // the blocking `lock_live()` write on every fast-path allocation,
        // re-serializing the #15956 hot path behind readers/writers.
        // `lease_expirations` is ordered by expiry, so `first()` is the
        // earliest; nothing is expired iff it is absent or lies in the
        // future (`> now_ns`, mirroring `collect_expired_global_locked`).
        match self.shared.live.try_read() {
            Ok(live)
                if live
                    .lease_expirations
                    .first()
                    .is_none_or(|(expires_at_ns, _)| *expires_at_ns > now_ns) =>
            {
                return 0;
            }
            Ok(_) => {}
            Err(_) => return 0,
        }
        let mut reclaimed = 0;
        let mut freed: Vec<(usize, u16)> = Vec::new();
        while reclaimed < budget {
            let chunk = (budget - reclaimed).min(GC_CHUNK);
            freed.clear();
            let collected = {
                // #17041: take the write guard with `try_write` and skip
                // on contention, as the opportunistic-GC contract above
                // promises. The pre-check only proves something WAS
                // expired at peek time; a contended re-check loses
                // nothing — the next admission or release retries.
                // A poisoned guard is still usable, mirroring
                // `lock_live()`.
                let mut live = match self.shared.live.try_write() {
                    Ok(guard) => guard,
                    Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                    Err(TryLockError::WouldBlock) => return reclaimed,
                };
                self.shared
                    .live_write_lock_acquisitions
                    .fetch_add(1, Ordering::Relaxed);
                #[cfg(test)]
                self.shared
                    .gc_lock_acquisitions
                    .fetch_add(1, Ordering::Relaxed);
                self.collect_expired_global_locked(&mut live, now_ns, chunk, &mut freed)
                // `live` guard dropped here, BEFORE the lock-free port frees
                // below and BEFORE the loop re-acquires it for the next chunk.
            };
            for &(addr_index, port) in &freed {
                // #16035 fold: stamped, same short-timeout argument as
                // `gc_expired_locked`.
                self.free_translated_port_at(addr_index, port, now_ns);
            }
            reclaimed += collected;
            if collected < chunk {
                // A short chunk means the expired frontier is exhausted (the
                // earliest remaining lease is not yet expired, or the index is
                // empty). Stop instead of re-locking for a guaranteed-empty
                // chunk. Any lease that expires later is reclaimed by a
                // subsequent amortized GC pass — GC is opportunistic, never the
                // sole reclaim path.
                break;
            }
        }
        reclaimed
    }

    /// Nested (guard-held) global expiry GC for the near-capacity pressure
    /// fallback in `allocate_translation_locked`, where `live` is held across
    /// the whole claim+insert and cannot be released mid-flight. Shares the
    /// `collect_expired_global_locked` primitive with the chunked path; the
    /// only difference is that the reclaimed ports are freed inline while the
    /// caller still holds `live` (unchanged pre-#4676 behavior).
    fn gc_expired_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        now_ns: u64,
        budget: usize,
    ) -> usize {
        let mut freed: Vec<(usize, u16)> = Vec::new();
        let reclaimed = self.collect_expired_global_locked(live, now_ns, budget, &mut freed);
        for (addr_index, port) in freed {
            // #16035 fold: stamped at GC time (see
            // `clear_persistent_leases`): a short-timeout lease (the
            // 1s schema floor) has not held its port anywhere near the
            // reuse delay when GC reclaims it, so the unstamped shape
            // bypassed the quarantine. The pressure claim that
            // triggered this GC may therefore have to wait out the
            // delay on this port; other ports/addresses still serve
            // it, and on large pools nothing changes.
            self.free_translated_port_at(addr_index, port, now_ns);
        }
        reclaimed
    }

    /// Nested (guard-held) per-address expiry GC for the pressure fallback.
    /// Same guard-held free discipline as `gc_expired_locked`.
    fn gc_expired_for_addr_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        now_ns: u64,
        budget: usize,
    ) -> usize {
        let mut freed: Vec<(usize, u16)> = Vec::new();
        let reclaimed =
            self.collect_expired_for_addr_locked(live, addr_index, now_ns, budget, &mut freed);
        for (addr_index, port) in freed {
            // #16035 fold: stamped, same short-timeout argument as
            // `gc_expired_locked`.
            self.free_translated_port_at(addr_index, port, now_ns);
        }
        reclaimed
    }

    /// Collect up to `budget` expired idle leases from the GLOBAL expiration
    /// index under a HELD `live` guard: pop the earliest-expiring entries,
    /// remove them from `persistent_by_source` and both expiration indexes, and
    /// record each reclaimed lease's `(addr_index, port)` in `freed` for the
    /// caller to release on the lock-free occupancy bitmap. Returns the count
    /// collected. Does NOT touch the occupancy bitmap — port release is
    /// deferred so it need not be serialized behind the alloc mutex (#4676).
    fn collect_expired_global_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        now_ns: u64,
        budget: usize,
        freed: &mut Vec<(usize, u16)>,
    ) -> usize {
        if now_ns == 0 || budget == 0 {
            return 0;
        }
        let mut reclaimed = 0;
        for _ in 0..budget {
            let Some((expires_at_ns, key)) = live.lease_expirations.iter().next().copied() else {
                break;
            };
            if expires_at_ns > now_ns {
                break;
            }
            live.lease_expirations.remove(&(expires_at_ns, key));
            if let Some(lease) = live.persistent_by_source.get(&key).copied() {
                if let Some(by_addr) = live.lease_expirations_by_addr.get_mut(lease.addr_index) {
                    by_addr.remove(&(expires_at_ns, key));
                }
            }
            if self.reclaim_expired_lease_locked(live, key, expires_at_ns, freed) {
                reclaimed += 1;
            }
        }
        reclaimed
    }

    /// Per-address variant of `collect_expired_global_locked`: pops from
    /// `lease_expirations_by_addr[addr_index]` (and mirrors the removal into the
    /// global index). Records reclaimed ports into `freed`.
    fn collect_expired_for_addr_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        addr_index: usize,
        now_ns: u64,
        budget: usize,
        freed: &mut Vec<(usize, u16)>,
    ) -> usize {
        if now_ns == 0 || budget == 0 || addr_index >= live.lease_expirations_by_addr.len() {
            return 0;
        }
        let mut reclaimed = 0;
        for _ in 0..budget {
            let Some((expires_at_ns, key)) = live.lease_expirations_by_addr[addr_index]
                .iter()
                .next()
                .copied()
            else {
                break;
            };
            if expires_at_ns > now_ns {
                break;
            }
            live.lease_expirations_by_addr[addr_index].remove(&(expires_at_ns, key));
            live.lease_expirations.remove(&(expires_at_ns, key));
            if self.reclaim_expired_lease_locked(live, key, expires_at_ns, freed) {
                reclaimed += 1;
            }
        }
        reclaimed
    }

    /// Remove one expired idle lease from `persistent_by_source` under a HELD
    /// `live` guard and RECORD its `(addr_index, port)` in `freed` — it does NOT
    /// clear the occupancy bit (the caller frees the collected ports, possibly
    /// after dropping `live`, keeping the lock-free bitmap op off the alloc
    /// mutex, #4676). Re-checks the lease is still idle and its expiry still
    /// matches so a concurrent refresh/rollback is not clobbered. Returns true
    /// iff a lease was reclaimed.
    fn reclaim_expired_lease_locked(
        &self,
        live: &mut PortAllocatorLiveState,
        key: PersistentSourceKey,
        expires_at_ns: u64,
        freed: &mut Vec<(usize, u16)>,
    ) -> bool {
        let Some(lease) = live.persistent_by_source.get(&key).copied() else {
            return false;
        };
        if lease.active_flows != 0
            || lease.inbound_flows != 0
            || lease.expires_at_ns != expires_at_ns
        {
            return false;
        }
        // The lease is idle and its bit is still set (the ownership
        // token), so no claim can re-hand-out the port in the gap
        // before the caller frees it. #17028: shared retire, port
        // Deferred into `freed` (address-only holds none, #6041).
        // The collect_* callers already popped both expiry indexes.
        let Some(retired) = lease_table::retire_idle_lease_locked(live, &key) else {
            return false;
        };
        if let Some(port) = retired.freed_port {
            freed.push(port);
        }
        true
    }
}

impl SourceNatReservationSnapshot {
    /// The holder mask is replayed by calling the worker-specific reserve path;
    /// metadata restoration never writes this mask directly.
    pub(crate) fn holder_mask(&self) -> u128 {
        self.holders
    }

    /// Restore the incumbent's promotion marker and, when this transaction
    /// displaced exactly one live persistent flow, its complete lease snapshot.
    /// A concurrent allocator change is left untouched and reported to the
    /// caller rather than overwritten.
    pub(crate) fn restore_metadata(&self) -> bool {
        let mut live = self.allocator.lock_live();
        let mut __shard = self.allocator.shared.flows.get_mut_shard(&self.flow);
        let Some(current) = self
            .allocator
            .shared
            .flows
            .get_in_shard(&__shard, &self.flow)
        else {
            return false;
        };
        if current.translated != self.translated || current.persistent_key != self.persistent_key {
            return false;
        }

        let restore_lease = match (self.persistent_key, self.persistent_lease) {
            (None, None) => None,
            (Some(key), Some(previous)) => {
                let Some(current) = live.persistent_by_source.get(&key).copied() else {
                    return false;
                };
                if current == previous {
                    None
                } else {
                    let completion_preserved_activation = current.activation_saw_completion
                        && current.expires_at_ns == previous.expires_at_ns
                        && current.activation_previous_expires_at_ns
                            == previous.activation_previous_expires_at_ns
                        && current.activation_had_previous_lease
                            == previous.activation_had_previous_lease
                        && current.activation_previous_timeout_ns
                            == previous.activation_previous_timeout_ns;
                    // Displacing the last active flow refreshes the idle expiry;
                    // the replay reserve then re-arms the 0 -> 1 activation and
                    // clears `activation_saw_completion`. Recognize that exact
                    // completed-then-reactivated shape as well.
                    let reactivated_after_completion = !current.activation_saw_completion
                        && current.activation_had_previous_lease
                        && current.activation_previous_expires_at_ns == current.expires_at_ns
                        && current.activation_previous_timeout_ns == previous.timeout_ns;
                    if previous.active_flows > 0
                        && current.active_flows == previous.active_flows
                        && current.completed_flows == previous.completed_flows.saturating_add(1)
                        && current.translated == previous.translated
                        && current.addr_index == previous.addr_index
                        && current.timeout_ns == previous.timeout_ns
                        && current.imported == previous.imported
                        && current.address_only == previous.address_only
                        && current.deterministic == previous.deterministic
                        && current.deterministic_identity == previous.deterministic_identity
                        && (completion_preserved_activation || reactivated_after_completion)
                    {
                        Some((key, previous))
                    } else {
                        return false;
                    }
                }
            }
            _ => return false,
        };

        if let Some((key, previous)) = restore_lease {
            // Both records are active here, so neither the displaced lease nor
            // its saved snapshot belongs in the idle-expiry index.
            let Some(lease) = live.persistent_by_source.get_mut(&key) else {
                return false;
            };
            *lease = previous;
        }
        let Some(current) = __shard.map.get_mut(&self.flow) else {
            return false;
        };
        current.promotion_timeout_ns = self.promotion_timeout_ns;
        true
    }
    /// #15145: restore the incumbent captured by `capture_and_replace` after
    /// a post-reserve refusal rolled back the replacement. The snapshot must
    /// have been taken with `capture_previous_holders` (the coordinator path);
    /// without the full allocation record there is nothing exact to restore.
    ///
    /// Returns false — leaving whatever state is present untouched — when
    /// the flow no longer names the replacement tuple, when its slot was
    /// retaken, or when the incumbent's tuple / persistent lease was claimed
    /// by another flow in the interim.
    pub(crate) fn restore_displaced(&self, replacement: TranslatedTuple, now_ns: u64) -> bool {
        let Some(previous) = self.allocation else {
            return false;
        };
        if previous.translated == replacement {
            return true;
        }
        let previous_lease = match (self.persistent_key, self.persistent_lease) {
            (None, None) => None,
            (Some(key), Some(lease)) => Some((key, lease)),
            _ => return false,
        };
        let owns_old_bit = previous.persistent_key.is_none() && !previous.address_only;
        if owns_old_bit {
            let Some(occ) = self.allocator.shared.occupancy.get(previous.addr_index) else {
                return false;
            };
            match occ.offset_of(previous.translated.port) {
                Some(offset) => {
                    if occ.is_occupied(offset) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        let mut live = self.allocator.lock_live();
        let mut __shard = self.allocator.shared.flows.get_mut_shard(&self.flow);
        // Address-only retake: the old reverse identity may have been
        // claimed live by another flow while the snapshot was
        // outstanding (owns_old_bit is false for address-only, so the
        // bitmap precheck cannot see it). Refuse rather than let
        // insert_address_only_owner overwrite that flow below.
        if previous.address_only {
            let old_key = AddressOnlyReverseKey {
                protocol: self.flow.protocol,
                translated_ip: previous.translated.ip,
                translated_port: previous.translated.port,
                dst_ip: self.flow.dst_ip,
                dst_port: self.flow.dst_port,
            };
            if live
                .address_only_owners
                .get(&old_key)
                .is_some_and(|owner| *owner != self.flow)
            {
                return false;
            }
            // #15948 fold 4: persistent retake. An idle address-only
            // LEASE imported during the rollback gap owns the same
            // reverse identity through the persistent indexes
            // (owner counts / persistent_by_translated + grants), not
            // the live map checked above. insert_address_only_owner
            // would not touch those, but restoring would leave two
            // owners of one reverse tuple — the imported lease for
            // revalidation/GC, this flow live — and the lease's
            // expiry could later free state under the live flow.
            // Refuse when any OTHER idle address-only lease covers
            // (translated, flow.dst) or any idle PAT lease covers it.
            let no_lease_key = PersistentSourceKey {
                protocol: self.flow.protocol,
                src_ip: self.flow.src_ip,
                src_port: 0,
                routing_scope: self.flow.routing_scope,
                remote: None,
            };
            let candidate = previous.persistent_key.as_ref().unwrap_or(&no_lease_key);
            if live.persistent_address_only_contended_except(
                &self.flow,
                previous.translated,
                previous.persistent_key,
            ) || live.idle_pat_lease_covers(
                previous.translated,
                candidate,
                Some((self.flow.dst_ip, self.flow.dst_port)),
                self.flow.protocol,
            ) {
                return false;
            }
        }
        // #15948 (H31-01): after a sole-holder rollback_flow the flow
        // entry is already unlinked, so absence is the expected
        // sole-holder shape, not a refusal. A present entry must still
        // name the replacement; a different tuple means retaken. A
        // present entry with SURVIVING holders means rollback
        // deliberately retained the replacement for those holders
        // (drop_holder_locked) — overwriting it would strand their
        // occupancy bit / reverse-owner token and erase their mask,
        // so refuse and leave the replacement untouched.
        if let Some(current) = self
            .allocator
            .shared
            .flows
            .get_in_shard(&__shard, &self.flow)
        {
            if current.translated != replacement || current.holders != 0 {
                return false;
            }
        }
        if let Some((key, previous_lease_rec)) = previous_lease {
            let Some(cur_lease) = live.persistent_by_source.get(&key).copied() else {
                return false;
            };
            if cur_lease.translated != previous_lease_rec.translated
                || cur_lease.addr_index != previous_lease_rec.addr_index
                || cur_lease.active_flows == 0
            {
                return false;
            }
            if cur_lease != previous_lease_rec {
                PortAllocator::remove_lease_expiration_locked(
                    &mut live,
                    previous_lease_rec.addr_index,
                    cur_lease.expires_at_ns,
                    key,
                );
                live.insert_persistent_lease(key, previous_lease_rec);
            }
            if let Some(slot) = __shard.map.get_mut(&self.flow) {
                slot.holders |= previous.holders;
            }
            let _ = now_ns;
            return true;
        }
        // #15956 fold: displaced-restore cap. Restoring an ABSENT
        // incumbent consumes a tracked-flow slot, so it must
        // refuse at the cap exactly like a fresh insert — the
        // pre-fold tail inserted unconditionally and could push
        // the sharded count past `max_tracked_flows`. A PRESENT
        // entry (the not-yet-unlinked replacement, checked above)
        // is replaced in its own slot and consumes nothing.
        // Checked under the held shard + `live` write guard, so
        // no same-flow insert can race past it; on refusal the
        // bitmap bit reserved above is handed back.
        let slot_present = __shard.map.contains_key(&self.flow);
        // Fold 2: the slot claim is the shared atomic admission
        // counter, not a len() read — a fast-path insert on
        // another shard at cap-1 races this fetch_add, and
        // exactly one of the two wins.
        if !slot_present
            && !self
                .allocator
                .shared
                .flows
                .admit_one(self.allocator.shared.max_tracked_flows)
        {
            if owns_old_bit {
                self.allocator
                    .free_translated_port(previous.addr_index, previous.translated.port);
            }
            return false;
        }
        if previous.address_only {
            live.insert_address_only_owner(
                AddressOnlyReverseKey {
                    protocol: self.flow.protocol,
                    translated_ip: previous.translated.ip,
                    translated_port: previous.translated.port,
                    dst_ip: self.flow.dst_ip,
                    dst_port: self.flow.dst_port,
                },
                self.flow,
            );
        } else if previous.persistent_key.is_none() {
            live.record_pat_owner(&self.flow, previous.translated);
        }
        self.allocator
            .shared
            .flows
            .insert_in_shard(&mut __shard, self.flow, previous);
        true
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PortAllocatorSnapshot {
    /// #9902 F-026: the snapshotted allocator's instance id: two snapshots
    /// with the same id came from the same counter instance (cumulative
    /// counters comparable); different ids mean a rebuild happened between
    /// them (rebaseline, never delta).
    pub(crate) allocator_id: u64,
    pub(crate) live_flows: u64,
    pub(crate) used_ports: u64,
    pub(crate) persistent_leases: u64,
    pub(crate) max_tracked_flows: u64,
    pub(crate) allocations_total: u64,
    pub(crate) reuses_total: u64,
    pub(crate) exhaustion_total: u64,
    /// #11496: cumulative imports refused because the shared persistent-lease
    /// table remained full after its bounded pressure-GC pass.
    pub(crate) idle_lease_import_capacity_total: u64,
    /// #8447: persistent-NAT admissions that produced a translation.
    pub(crate) persistent_admitted_total: u64,
    /// #8447: persistent-NAT admissions that returned a failure instead.
    pub(crate) persistent_declined_total: u64,
    /// #4800/#17036: counted lock acquisitions split by domain since
    /// #15956. `flow_shard_lock_*` is the counted flow-shard mutex pair;
    /// `live_write_lock_*` is the `live` RwLock write pair. Read each as
    /// a ratio (`contended / acquisitions`) for its own domain. See
    /// `PortAllocator::lock_live` and `lock_flow_shard_counted`.
    pub(crate) flow_shard_lock_acquisitions_total: u64,
    pub(crate) flow_shard_lock_contended_total: u64,
    pub(crate) live_write_lock_acquisitions_total: u64,
    pub(crate) live_write_lock_contended_total: u64,
    /// Legacy summed totals (flow-shard + live-write), kept for one
    /// release (#17036). Do not use for the #15956 perf-gate ratio:
    /// the population mixes two lock domains.
    pub(crate) live_lock_acquisitions_total: u64,
    pub(crate) live_lock_contended_total: u64,
    /// #9392: tokens popped by the recycled phase of `claim`, and the number of
    /// recycled-phase FIFO WALKS that popped them, summed across the pool's
    /// addresses.
    ///
    /// Read as `pops / walks` — pops per walk. ~1 means a freed token was
    /// claimable at the head, which is the healthy shape. Materially above 1
    /// means the #9327 cliff is REACHED in production: K out-of-band-occupied
    /// tokens sit ahead of F free ones and retained tokens go to the BACK, so
    /// the cost is (K+F)/F per claim and degrades to K+1 as F -> 1 — worst
    /// exactly as an address approaches exhaustion. #9327 proved the mechanism
    /// on a fixture and could not answer the reachability, because the counter
    /// was `#[cfg(test)]`.
    ///
    /// A PAIR, always: a cumulative pop count on its own cannot distinguish a
    /// busy pool doing cheap walks from an idle one doing pathological ones,
    /// and that distinction IS the question.
    pub(crate) recycle_scan_pops_total: u64,
    pub(crate) recycle_scan_walks_total: u64,
}

pub(crate) fn allocator_capacity(num_addresses: usize, port_low: u16, port_high: u16) -> usize {
    if num_addresses == 0 || port_low == 0 || port_high == 0 || port_low > port_high {
        return 0;
    }
    let ports = (u64::from(port_high) - u64::from(port_low)) + 1;
    ports
        .saturating_mul(num_addresses as u64)
        .min(usize::MAX as u64) as usize
}

/// Fixed, domain-separated seed for `address-persistent` sticky pool
/// selection (#14627). Unlike node-local hot-path placement
/// (`hot_path_hash_seed`, #2364/#12789), this mapping is a cross-node
/// contract: Junos `address-persistent` promises one pool address per
/// internal host, and after an HA failover the new node must place a
/// host's NEW flows on the same pool address its synced sessions use.
/// Both nodes run identical config (same pool, same order), so a pure
/// function of `(src_ip, pool_len)` under a FIXED seed computes the
/// same slot everywhere and across restarts — the ECMP precedent
/// (`ECMP_FLOW_HASH_SEED`). The seed is stable, not secret: sticky
/// placement runs only at first-flow allocation, its output (the
/// translated pool address) is observable on the wire in every packet,
/// and it indexes no attacker-growable table, so predictable selection
/// enables no collision eviction or chain amplification. The hash
/// itself remains the keyed multiply-mix (`HotPathSeededState`), whose
/// splitmix64 folds destroy the seed-independent v4/v6 collision
/// families that broke seed-additive FxHash (#12789/#12989) — only the
/// seed source changes, from per-process secret to this fixed domain
/// constant. Existing allocations are unchanged (sessions/leases pin
/// their translated tuple); only a fresh recomputation moves, and it
/// now moves to the same slot on every node.
pub(super) const STICKY_POOL_HASH_SEED: u64 = 0x5354_4943_4b59_0001;

/// Map a source IP to a sticky pool-address slot for `address-persistent`
/// SNAT. A pure function of `(src_ip, pool_len)`: identical on every
/// node running the same pool config and across process restarts, so
/// the address survives an HA failover for new flows as well as for
/// synced sessions (#14627).
pub(crate) fn sticky_pool_index(src_ip: IpAddr, pool_len: usize) -> usize {
    sticky_pool_index_seeded(src_ip, pool_len, STICKY_POOL_HASH_SEED)
}

/// Seed-pinned core for deterministic placement tests.
pub(super) fn sticky_pool_index_seeded(src_ip: IpAddr, pool_len: usize, seed: u64) -> usize {
    if pool_len <= 1 {
        return 0;
    }

    use std::hash::{BuildHasher, Hash, Hasher};
    let mut hasher = crate::hot_hash_seed::HotPathSeededState::new(seed).build_hasher();
    src_ip.hash(&mut hasher);
    (hasher.finish() % pool_len as u64) as usize
}
