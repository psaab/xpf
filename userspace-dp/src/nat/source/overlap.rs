//! #6979 F6 — pool-vs-pool translated-identity collisions on the local PAT
//! mint path.
//!
//! `SourceNatPoolAllocatorKey` carries the pool NAME, so two rules whose pools
//! share an address under DIFFERENT names are two keys and therefore two
//! `PortAllocator`s. Each allocator's occupancy bitmap is the sole ownership
//! token for its own addresses and neither can see the other's, so both publish
//! `203.0.113.1:20000` for a different live flow — one wire identity, two
//! sessions, replies the reverse index cannot attribute.
//!
//! This module owns the apply-time index and the query the mint path uses; the
//! refusal itself lives at the three PAT allocation sites in `match_rules.rs`
//! (`reject_peer_owned_identity`).
//!
//! # What this covers, and what it does NOT
//!
//! COVERED: the LOCAL, port-translating (PAT) mint — v4 round-robin/persistent,
//! v6 round-robin/persistent, and deterministic-v4 — where the occupancy bit is
//! the ownership token.
//!
//! NOT COVERED, and each is a separate route to the same duplicate rather than
//! a rounding error (Codex round 1 on PR #8111):
//!   - the ADDRESS-ONLY path (`port no-translation`, port-less protocols) mints
//!     an `address_only_owners` reverse-identity token and claims NO occupancy
//!     bit, so it is invisible to this query in both directions;
//!   - the HA synced reserve (`synced.rs`) calls `reserve_flow` on one
//!     allocator directly and never reaches this check, so an imported flow can
//!     take a tuple a LOCAL flow already owns in a peer pool;
//!   - NAT64 prefixes are their own allocators (`nat64.rs`) and are not indexed
//!     here at all.
//! All three are reachable only from the same tolerated / peer-synced /
//! handcrafted population as the covered case (the Go #5144 strict gate rejects
//! overlapping pools at commit) and are tracked as follow-up work.

use super::*;

/// One allocator that covers a pool address, and the index that address has in
/// THAT allocator's occupancy vector.
///
/// The index is recorded per OCCURRENCE, not per address: `expand_pool_address`
/// does not deduplicate, so a pool whose configured members overlap can carry
/// one address at several positions and `PortAllocator::new` gives each
/// position its own bitmap. Recording only the first (`.position()`) would let
/// a peer's SECOND position hand out an identity this query reports free.
#[derive(Clone, Debug)]
struct PoolAddressOwner {
    allocator: PortAllocator,
    index: usize,
}

/// #6979 F6: the apply-time index of pool addresses that MORE THAN ONE distinct
/// allocator covers.
///
/// Only SHARED addresses are stored. A config with no overlapping pools — every
/// config a strict commit accepts — produces no index at all and no rule holds
/// one, so the mint path stays an `Option::is_none`.
///
/// # Cost, bounded honestly
///
/// The counting pass is keyed by DISTINCT ALLOCATOR, not by rule, so its size
/// is the sum of each distinct pool's expanded address count — exactly the
/// quantity #6812's aggregate budget caps (`max_addresses`, 1,048,576). A
/// `/16` pool referenced by a thousand rules is ONE allocator and costs 65536
/// counter entries, not a thousand times that. The owner lists built in the
/// second pass cover only the addresses the first pass found shared, so a
/// config with no overlap allocates none of them.
///
/// This replaces a first version that indexed per RULE and materialised a
/// directed rule-peer map per pair; that was NOT bounded by the budget (a
/// strict-VALID config of 1024 rules over one `/16` pool built 67,108,864
/// owner entries) and is the defect Codex round 1 finding 4 measured.
#[derive(Debug, Default)]
pub(crate) struct PoolAddressOwners {
    v4: FxHashMap<Ipv4Addr, Vec<PoolAddressOwner>>,
    v6: FxHashMap<Ipv6Addr, Vec<PoolAddressOwner>>,
}

impl PoolAddressOwners {
    /// Is `(addr, port)` held by an allocator OTHER than `own`?
    ///
    /// Skipping by allocator INSTANCE (`Arc` pointer identity) rather than by
    /// key is what keeps two rules naming one pool a single occupancy domain,
    /// through every route the resolver takes to share one allocator — an exact
    /// previous-generation key, a this-apply key already assigned, or a #7858
    /// rename carry.
    ///
    /// It also means a pool's own duplicate positions are NOT compared against
    /// each other. That intra-pool case is a distinct, pre-existing defect
    /// (one pool, no peer, `[X, X]` mints `X:P` twice) that this change neither
    /// introduces nor is required to fix; it is tracked separately.
    fn peer_holds(&self, own: &PortAllocator, addr: IpAddr, port: u16) -> bool {
        let owners = match addr {
            IpAddr::V4(v4) => self.v4.get(&v4),
            IpAddr::V6(v6) => self.v6.get(&v6),
        };
        owners.into_iter().flatten().any(|owner| {
            !owner.allocator.same_allocator(own) && owner.allocator.holds_port(owner.index, port)
        })
    }
}

impl SourceNatRule {
    /// #6979 F6: is `(addr, port)` already OWNED by a PEER pool's allocator?
    ///
    /// `None` index — the overwhelmingly common case — means this rule's pool
    /// shares no address with any other allocator, so the caller's
    /// `Option::is_none` is the whole cost.
    pub(crate) fn peer_holds_identity(&self, addr: IpAddr, port: u16) -> bool {
        match &self.overlap_owners {
            Some(owners) => owners.peer_holds(&self.pool_allocator, addr, port),
            None => false,
        }
    }
}

/// #6979 F6: build the shared-address index and hand it to the rules that need
/// it, so a mint can refuse an identity a peer pool already owns.
///
/// # The defect, measured
///
/// Two rules whose pools carry one address under DIFFERENT names are two
/// allocator keys and therefore two `PortAllocator`s. Each allocator's
/// occupancy bitmap is the sole ownership token for its own addresses and
/// neither can see the other's, so both mint `203.0.113.1:20000` for two live
/// flows. Measured on master with single-address pools `a`/`b` and a one-port
/// range.
///
/// F6 attributes that to a MATCH-ONLY rule edit moving a flow from one rule to
/// another. Measured, the edit is NOT load-bearing — the same two pools produce
/// the same duplicate with no edit at all — and the SINGLE-pool version of the
/// edit produces no defect whatsoever: the allocator key does not change, the
/// allocator is reused by `Arc`, and its live reservation answers
/// `AllocatorExhausted`. So the key's ignorance of match criteria and zone
/// scope is not itself the bug, and adding them to the key would have broken
/// that carryover across every match-only edit while fixing nothing.
///
/// # Why a mint-time check, and not a wider key, a merge, or a quarantine
///
/// - **A wider key** breaks retention. Retention must stay WIDER than minting
///   (`drain_allocator_key`, #7717): a key change changes carryover for every
///   allocator in a running process, and one that failed to carry over would
///   strand the live flows it was holding on the first reconcile after an
///   upgrade. The key here is left byte-identical, which is the whole upgrade
///   story — no allocator's carryover moves.
/// - **Merging the two allocators** is not available: `occupancy` is a `Vec`
///   indexed by pool-address POSITION, so pools whose address lists differ
///   cannot share one. That is the same reason #6765 re-seeds instead of
///   loosening the key.
/// - **Quarantining the later pool with `pool_failure`** breaks #6211: the
///   synced reserve skips a `pool_failure` allocator entirely
///   (`synced.rs`), and `overlapping_pool_rules_6211` requires the second of
///   two overlapping pools to ACCEPT the active-selected synced reservation so
///   a post-failover local flow skips that port. Measured: that quarantine reds
///   16 merged tests. It does NOT follow that every no-new-mint design is
///   excluded — a state that refuses new local mints while still accepting
///   synced reservations remains viable, and Codex round 1 is right to say so;
///   it is simply a larger change than this one.
pub(super) fn wire_overlap_peers(out: &mut [SourceNatRule]) {
    // Fast out: fewer than two pool-mode rules cannot overlap, and nothing is
    // built at all.
    if out.iter().filter(|rule| rule.pool_mode).take(2).count() < 2 {
        return;
    }

    // One entry per DISTINCT allocator. Bounded by #6812's `max_pools` (1024),
    // and the linear `same_allocator` scan is over that, not over rules.
    let mut distinct: Vec<usize> = Vec::new();
    for (idx, rule) in out.iter().enumerate() {
        if !rule.pool_mode
            || (rule.pool_addresses_v4.is_empty() && rule.pool_addresses_v6.is_empty())
        {
            continue;
        }
        if distinct
            .iter()
            .any(|&seen| out[seen].pool_allocator.same_allocator(&rule.pool_allocator))
        {
            continue;
        }
        distinct.push(idx);
    }
    if distinct.len() < 2 {
        return;
    }

    // PASS 1 — count owners per address. Keyed by distinct allocator, so the
    // total is the #6812 aggregate ADDRESS budget and no `Vec` is allocated
    // per address.
    let mut count_v4 = FxHashMap::<Ipv4Addr, u32>::default();
    let mut count_v6 = FxHashMap::<Ipv6Addr, u32>::default();
    for &idx in &distinct {
        for addr in &out[idx].pool_addresses_v4 {
            *count_v4.entry(*addr).or_insert(0) += 1;
        }
        for addr in &out[idx].pool_addresses_v6 {
            *count_v6.entry(*addr).or_insert(0) += 1;
        }
    }
    let shared_v4 = count_v4.values().any(|&n| n > 1);
    let shared_v6 = count_v6.values().any(|&n| n > 1);
    if !shared_v4 && !shared_v6 {
        return;
    }

    // PASS 2 — owner lists, for the SHARED addresses only.
    let mut owners = PoolAddressOwners::default();
    for &idx in &distinct {
        let allocator = &out[idx].pool_allocator;
        let v4_len = out[idx].pool_addresses_v4.len();
        for (pos, addr) in out[idx].pool_addresses_v4.iter().enumerate() {
            if count_v4.get(addr).copied().unwrap_or(0) < 2 {
                continue;
            }
            owners.v4.entry(*addr).or_default().push(PoolAddressOwner {
                allocator: allocator.clone(),
                index: pos,
            });
        }
        for (pos, addr) in out[idx].pool_addresses_v6.iter().enumerate() {
            if count_v6.get(addr).copied().unwrap_or(0) < 2 {
                continue;
            }
            // The occupancy vector is v4 addresses first, then v6 — the same
            // layout `retained_pool_index_map` builds.
            owners.v6.entry(*addr).or_default().push(PoolAddressOwner {
                allocator: allocator.clone(),
                index: v4_len + pos,
            });
        }
    }

    // Hand the index only to the rules whose pool actually touches a shared
    // address, so every other rule keeps the `Option::is_none` fast path.
    //
    // The address scan runs once per DISTINCT ALLOCATOR, not once per rule, for
    // the same reason the counting pass does: rules are not bounded by #6812
    // and addresses are. Doing it per rule would reintroduce the round-1 cost
    // defect one loop later — 1024 rules over two overlapping `/16` pools is
    // 67,108,864 hash lookups when it is 131,072. The per-rule step that
    // remains is a pointer compare against the (at most `max_pools`) allocators
    // that touch a shared address.
    let touching: Vec<usize> = distinct
        .iter()
        .copied()
        .filter(|&idx| {
            out[idx]
                .pool_addresses_v4
                .iter()
                .any(|addr| owners.v4.contains_key(addr))
                || out[idx]
                    .pool_addresses_v6
                    .iter()
                    .any(|addr| owners.v6.contains_key(addr))
        })
        .collect();
    if touching.is_empty() {
        return;
    }
    let owners = Arc::new(owners);
    let touching_allocators: Vec<PortAllocator> = touching
        .iter()
        .map(|&idx| out[idx].pool_allocator.clone())
        .collect();
    for rule in out.iter_mut() {
        if !rule.pool_mode {
            continue;
        }
        if touching_allocators
            .iter()
            .any(|alloc| alloc.same_allocator(&rule.pool_allocator))
        {
            rule.overlap_owners = Some(Arc::clone(&owners));
        }
    }
}
