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
//! COVERED: every LOCAL mint, in BOTH ownership spaces.
//!   - the port-translating (PAT) mint — v4 round-robin/persistent, v6
//!     round-robin/persistent, and deterministic-v4 — where the occupancy bit
//!     is the ownership token (#6979 F6);
//!   - the ADDRESS-ONLY mint (`port no-translation`, port-less protocols) on
//!     the same three arms, where the token is an `address_only_owners`
//!     reverse-identity entry and NO occupancy bit is claimed (#8115 R1).
//!
//! Both mints ask BOTH questions, through `peer_owns_wire_identity`. Wiring
//! only the bitmap left the address-only route open in both directions: a peer
//! preserving `X:P` toward a remote did not stop a PAT mint of `X:P` toward it,
//! and two address-only flows in different pools collided whenever protocol and
//! remote matched.
//!
//! The two questions are not equally precise. `peer_holds` is REMOTE-AGNOSTIC —
//! an occupancy bit means "this allocator may publish `X:P`", not "toward this
//! remote" — so refusing on it can decline a flow that is not a wire collision;
//! that is F6's shipped posture and costs a PAT mint one port rotation.
//! `peer_holds_address_only` is REMOTE-SPECIFIC (the key carries
//! `dst_ip`/`dst_port`), so it over-rejects nothing.
//!
//! ALSO COVERED: the HA synced reserve, on PASS 1 ONLY (#8115 R2). `synced.rs`
//! called `reserve_flow_maybe_persistent` / `reserve_address_only` on ONE
//! allocator, so an imported flow narrowed to pool B took a tuple a LOCAL flow
//! already owned in pool A; both arms now ask `peer_owns_wire_identity` and roll
//! back into the existing `Refused` outcome.
//!
//! The PASS-1 gate is the design constraint, not an optimisation. PASS 2 is
//! reached when the zone pair cannot be resolved — an HA node's entire first
//! sync, before any snapshot is applied — where the active's rule choice cannot
//! be reproduced and "which rule's pool contains the address" is the only
//! available question. Refusing there rejects EVERY import on such a node.
//! #6979 F1 already measured that PASS 2 accepts into the wrong allocator and
//! left it deliberately; ungating this reds its cell plus the #6211/#6600
//! contract cells.
//!
//! Refusing on PASS 1 is not a new disposition: `Refused` is what this function
//! already returns for the same conflict inside ONE allocator, and it is
//! observable — `may_publish()` false, `SyncedImportOutcome::RejectedReserve`,
//! and `xpf_userspace_synced_import_reserve_refused_total`, whose help text
//! already says those flows will not survive a failover (#8101).
//!
//! ALSO COVERED: NAT64 prefixes, as INDEX MEMBERS (#8115 R3). A `Nat64Prefix`
//! owns its own `port_allocator`, keyed by `(prefix_bytes, pool_v4)`, so a
//! source-NAT pool sharing one of those addresses — or a second prefix over the
//! same pool — is a second occupancy domain over one address.
//!
//! This was a REGISTRY gap rather than a missing caller: the query worked, the
//! domain was simply absent from the population it searches. `wire_overlap_peers`
//! runs inside `parse_source_nat_rules_with_previous`, before `state.nat64`
//! exists, so a prefix could never have been added there. `wire_nat64_overlap_peers`
//! is the second pass, called from `forwarding_build` once both are built; it
//! REPLACES the source-only index with a combined one (a strict superset, so no
//! rule loses coverage) and hands it to both features. Both directions are
//! closed: the NAT64 mint asks before publishing, and the source-NAT rules carry
//! the combined view so their mint sees NAT64's allocations.
//!
//! The NAT64 mint asks ONCE, after both of its arms — round-robin PAT and
//! deterministic NAPT64 (#4559) — because the arms differ in how they CHOOSE
//! the tuple, not in what makes it a duplicate. The deterministic arm still
//! earns its own cell, for the ROLLBACK: #6528 frees a block port with
//! `free_no_recycle`, and a skipped rollback strands it.
//!
//! Everything is reachable only from the same tolerated / peer-synced /
//! handcrafted population as the covered case (the Go #5144 strict gate rejects
//! overlapping independent pools at commit on address overlap alone). That
//! population is real and verified: `lenientCompileOpts` is wired at
//! `configstore.Store` load and SyncApply. The dataplane keeps only each
//! address's first occurrence within one pool (#10700), but separate allocators
//! with overlapping addresses still install and can collide as described above.

use super::*;
use crate::nat::allocator::AddressOnlyReverseKey;

/// One allocator that covers a pool address, and the index that address has in
/// THAT allocator's occupancy vector.
///
/// The source-NAT pool parser now deduplicates expanded addresses in first-seen
/// order (#10700), so an address has one slot per allocator. Keeping its exact
/// slot here is required by the peer bitmap lookup.
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
/// is the sum of each distinct pool's expanded address count — the quantity
/// #6812's aggregate budget caps (`max_addresses`, 1,048,576). A `/16` pool
/// referenced by a thousand rules is ONE allocator, so `distinct.len() == 1`
/// and the function returns before building any counters at all. The owner
/// lists in the second pass cover only the addresses the first pass found
/// SHARED, so a config with no overlap allocates none of them.
///
/// Two costs are bounded by a DIFFERENT quantity and are stated rather than
/// folded into the budget claim, because the first version of this comment did
/// fold them in and was wrong (Codex round 2 on PR #8111, findings 1 and 4):
/// the `distinct` dedup is a linear `same_allocator` scan per candidate rule,
/// which the `address_slots() == 0` skip below keeps proportional to the number
/// of REAL allocators (`max_pools`) rather than to the rule count; and the
/// final assignment pass compares each rule's allocator pointer against the
/// touching set, which is rule count x `max_pools` pointer compares and touches
/// no addresses.
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
    /// The parser stores each pool address only once (#10700). Skipping this
    /// allocator instance is still required because rules sharing one pool
    /// intentionally share one occupancy domain.
    fn peer_holds(&self, own: &PortAllocator, addr: IpAddr, port: u16) -> bool {
        let owners = match addr {
            IpAddr::V4(v4) => self.v4.get(&v4),
            IpAddr::V6(v6) => self.v6.get(&v6),
        };
        owners.into_iter().flatten().any(|owner| {
            !owner.allocator.same_allocator(own) && owner.allocator.holds_port(owner.index, port)
        })
    }

    /// #8115 R1: is the ADDRESS-ONLY reverse identity `rkey` held by an
    /// allocator OTHER than `own`?
    ///
    /// Indexed by `rkey.translated_ip` — the same shared-address key the bitmap
    /// query uses, so a config with no overlapping pools builds no index and
    /// this is never reached. The owner's stored `index` is NOT used: an
    /// address-only token claims no occupancy bit, so its ownership is keyed by
    /// the reverse identity alone.
    fn peer_holds_address_only(&self, own: &PortAllocator, rkey: &AddressOnlyReverseKey) -> bool {
        let owners = match rkey.translated_ip {
            IpAddr::V4(v4) => self.v4.get(&v4),
            IpAddr::V6(v6) => self.v6.get(&v6),
        };
        owners.into_iter().flatten().any(|owner| {
            !owner.allocator.same_allocator(own)
                && owner.allocator.holds_address_only_identity(rkey)
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

    /// #8115 R1: is the ADDRESS-ONLY reverse identity `rkey` already owned by a
    /// PEER pool's allocator?
    ///
    /// Same index, same `Option::is_none` fast path, other ownership space.
    pub(crate) fn peer_holds_address_only_identity(&self, rkey: &AddressOnlyReverseKey) -> bool {
        match &self.overlap_owners {
            Some(owners) => owners.peer_holds_address_only(&self.pool_allocator, rkey),
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
/// One occupancy domain, as the index sees it: an allocator plus the addresses
/// it covers.
///
/// #8115 R3: this exists so the source-NAT-only pass and the cross-feature pass
/// share ONE index implementation. Two copies of the counting/owner-list logic
/// would be free to drift, and a drifted copy is invisible — the query still
/// answers, just about a different population.
struct OwnerView<'a> {
    allocator: &'a PortAllocator,
    v4: &'a [Ipv4Addr],
    v6: &'a [Ipv6Addr],
}

/// PASS 1 + PASS 2 over an already-DEDUPED list of occupancy domains.
///
/// `None` when fewer than two domains exist or no address is shared, which is
/// every config a strict commit accepts.
fn build_owner_index(views: &[OwnerView<'_>]) -> Option<PoolAddressOwners> {
    if views.len() < 2 {
        return None;
    }

    // PASS 1 — count how many DISTINCT ALLOCATORS cover each address.
    //
    // Each entry carries the last domain that incremented it, so a pool whose
    // own configured members repeat an address counts ONCE. Counting per
    // OCCURRENCE instead reported `[X, X]` as shared with itself: the rule then
    // received the index and paid the `SeqCst` fence and a map probe on every
    // mint, for a pool with no peer at all (Codex round 2 on PR #8111,
    // finding 2). Every occurrence is still INDEXED in pass 2 — that half is
    // required, and is what round-1 finding 3 was about.
    let mut count_v4 = FxHashMap::<Ipv4Addr, (u32, usize)>::default();
    let mut count_v6 = FxHashMap::<Ipv6Addr, (u32, usize)>::default();
    for (i, view) in views.iter().enumerate() {
        for addr in view.v4 {
            let slot = count_v4.entry(*addr).or_insert((0, usize::MAX));
            if slot.1 != i {
                slot.0 += 1;
                slot.1 = i;
            }
        }
        for addr in view.v6 {
            let slot = count_v6.entry(*addr).or_insert((0, usize::MAX));
            if slot.1 != i {
                slot.0 += 1;
                slot.1 = i;
            }
        }
    }
    if !count_v4.values().any(|&(n, _)| n > 1) && !count_v6.values().any(|&(n, _)| n > 1) {
        return None;
    }

    // PASS 2 — owner lists, for the SHARED addresses only.
    let mut owners = PoolAddressOwners::default();
    for view in views {
        let v4_len = view.v4.len();
        for (pos, addr) in view.v4.iter().enumerate() {
            if count_v4.get(addr).map_or(0, |&(n, _)| n) < 2 {
                continue;
            }
            owners.v4.entry(*addr).or_default().push(PoolAddressOwner {
                allocator: view.allocator.clone(),
                index: pos,
            });
        }
        for (pos, addr) in view.v6.iter().enumerate() {
            if count_v6.get(addr).map_or(0, |&(n, _)| n) < 2 {
                continue;
            }
            // The occupancy vector is v4 addresses first, then v6 — the same
            // layout `retained_pool_index_map` builds.
            owners.v6.entry(*addr).or_default().push(PoolAddressOwner {
                allocator: view.allocator.clone(),
                index: v4_len + pos,
            });
        }
    }
    Some(owners)
}

/// The DISTINCT source-NAT occupancy domains, as indices into `out`.
///
/// The `address_slots() == 0` skip is load-bearing, not tidiness:
/// `PortAllocator::default()` builds a FRESH `Arc` per rule, and every rule that
/// never received a real allocator carries one — a pool rule that failed with no
/// previous generation to drain, in particular. Counting those as distinct makes
/// this linear `same_allocator` scan quadratic in the RULE count, which no budget
/// bounds (Codex round 2 on PR #8111, finding 1: R(R-1)/2 comparisons). An empty
/// allocator can never answer `holds_port` true, so it is not an occupancy domain
/// and indexing it buys nothing. A #7717 draining pool keeps its RETAINED
/// allocator, which has slots, so it is still indexed — the case that matters.
fn distinct_source_owners(out: &[SourceNatRule]) -> Vec<usize> {
    let mut distinct: Vec<usize> = Vec::new();
    for (idx, rule) in out.iter().enumerate() {
        if !rule.pool_mode
            || (rule.pool_addresses_v4.is_empty() && rule.pool_addresses_v6.is_empty())
            || rule.pool_allocator.address_slots() == 0
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
    distinct
}

/// Hand the index to every pool-mode rule whose allocator touches a SHARED
/// address, so every other rule keeps the `Option::is_none` fast path.
///
/// The address scan runs once per DISTINCT ALLOCATOR, not once per rule: rules
/// are not bounded by #6812 and addresses are. Doing it per rule would
/// reintroduce the round-1 cost defect one loop later — 1024 rules over two
/// overlapping `/16` pools is 67,108,864 hash lookups when it is 131,072. The
/// per-rule step that remains is a pointer compare against the (at most
/// `max_pools`) allocators that touch a shared address.
fn assign_source_owners(out: &mut [SourceNatRule], distinct: &[usize], owners: PoolAddressOwners) {
    assign_source_owners_shared(out, distinct, Arc::new(owners));
}

fn assign_source_owners_shared(
    out: &mut [SourceNatRule],
    distinct: &[usize],
    owners: Arc<PoolAddressOwners>,
) {
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

pub(super) fn wire_overlap_peers(out: &mut [SourceNatRule]) {
    // Fast out: fewer than two pool-mode rules cannot overlap, and nothing is
    // built at all.
    if out.iter().filter(|rule| rule.pool_mode).take(2).count() < 2 {
        return;
    }
    let distinct = distinct_source_owners(out);
    let owners = {
        let views: Vec<OwnerView<'_>> = distinct
            .iter()
            .map(|&i| OwnerView {
                allocator: &out[i].pool_allocator,
                v4: &out[i].pool_addresses_v4,
                v6: &out[i].pool_addresses_v6,
            })
            .collect();
        build_owner_index(&views)
    };
    let Some(owners) = owners else {
        return;
    };
    assign_source_owners(out, &distinct, owners);
}

/// #8115 R1/R2: does a PEER pool's allocator already own this WIRE identity, in
/// EITHER ownership space?
///
/// #6979 F6 asked only the bitmap question, which is the right one for a PAT
/// mint against a PAT peer and blind in both directions to the OTHER space: a
/// `port no-translation` / port-less flow claims no occupancy bit at all. So a
/// peer preserving `X:P` did not stop a PAT mint of `X:P`, and two address-only
/// flows in different pools collided whenever protocol and remote matched.
///
/// The two sub-questions are not equally precise, and the difference is worth
/// stating because it decides where an over-rejection can occur:
///
///   - `peer_holds_identity` is REMOTE-AGNOSTIC. The occupancy bit means "this
///     allocator may publish `X:P`", not "toward this remote". Refusing on it
///     can therefore decline a flow whose remote differs from the peer flow's,
///     which is not a wire collision. That is #6979 F6's shipped posture and is
///     kept: for a PAT mint the cost is one rotation to another port, and the
///     conservative direction is the safe one for a token that is the sole
///     ownership word.
///   - `peer_holds_address_only_identity` is REMOTE-SPECIFIC — the key carries
///     `dst_ip`/`dst_port` — so a match is an exact duplicate of the wire
///     5-tuple and carries no over-rejection at all.
///
/// The key is built by `AddressOnlyReverseKey::for_flow`, the SAME constructor
/// the reserve paths insert with. Building it from three literals here would
/// reproduce the #6751 defect that constructor exists to prevent: a check keyed
/// differently from its insert finds nothing, every mint "succeeds", and no
/// behavioural test can see it.
///
/// #8115 R2: the HA synced reserve asks this too. It lives here rather than in
/// `match_rules` because it is the composed PEER QUERY, and its two consumers —
/// the local mint and the synced import — must not drift on what "a peer owns
/// this" means. A synced import that reserved on a different answer than the
/// local mint uses would be the two-domains-one-identity split all over again,
/// one layer up.
///
/// `false` on every config with no overlapping pools — `overlap_owners` is
/// `None` there and this is one `Option::is_none`.
pub(super) fn peer_owns_wire_identity(
    rule: &SourceNatRule,
    flow: SourceNatFlowKey,
    translated: TranslatedTuple,
) -> bool {
    peer_owns_identity_in(
        rule.overlap_owners.as_deref(),
        &rule.pool_allocator,
        flow,
        translated,
    )
}

/// The implementation behind [`peer_owns_wire_identity`], for a caller that
/// holds an index and an allocator rather than a `SourceNatRule`.
///
/// #8115 R3: NAT64 has no `SourceNatRule` — a `Nat64Prefix` owns its allocator
/// directly — so it needs this entry point. It is the SAME body rather than a
/// second one on purpose: a NAT64 mint that asked a differently-composed
/// question than a source-NAT mint would reproduce the split both are here to
/// close, one feature over.
pub(crate) fn peer_owns_identity_in(
    owners: Option<&PoolAddressOwners>,
    own: &PortAllocator,
    flow: SourceNatFlowKey,
    translated: TranslatedTuple,
) -> bool {
    let Some(owners) = owners else {
        return false;
    };
    std::sync::atomic::fence(Ordering::SeqCst);
    owners.peer_holds(own, translated.ip, translated.port)
        || owners.peer_holds_address_only(
            own,
            &AddressOnlyReverseKey::for_flow(&flow, translated.ip, translated.port),
        )
}

/// #8115 R3: rebuild the peer index with NAT64 prefixes as MEMBERS, and hand it
/// to both features.
///
/// `wire_overlap_peers` runs inside `parse_source_nat_rules_with_previous`,
/// where `state.nat64` does not exist yet, so a NAT64 prefix could never have
/// been added there. This is the second pass, called once both are built. It is
/// not a different query — it is the same index over a larger population, which
/// is exactly what "a missing registry member" means.
///
/// The source-only index built by the first pass is REPLACED, not merged: the
/// combined index is a strict superset (every source-NAT domain is still a
/// member), so a rule that held the narrow one gets the wider one and no rule
/// loses coverage.
///
/// Fast out before any work when no prefix contributes an occupancy domain,
/// which is every config without NAT64 and every NAT64 config whose prefixes
/// were refused by the #6982 budget (an over-budget prefix keeps a DEFAULT
/// allocator with no slots — it can never answer `holds_port` true, so it is
/// not a domain, the same reason the source-NAT pass skips those).
pub(crate) fn wire_nat64_overlap_peers(
    rules: &mut [SourceNatRule],
    prefixes: &mut [crate::nat64::Nat64Prefix],
) {
    let mut distinct_n64: Vec<usize> = Vec::new();
    for (idx, prefix) in prefixes.iter().enumerate() {
        if prefix.pool_v4.is_empty() || prefix.port_allocator.address_slots() == 0 {
            continue;
        }
        if distinct_n64.iter().any(|&seen| {
            prefixes[seen]
                .port_allocator
                .same_allocator(&prefix.port_allocator)
        }) {
            continue;
        }
        distinct_n64.push(idx);
    }
    if distinct_n64.is_empty() {
        return;
    }
    let distinct_src = distinct_source_owners(rules);
    let owners = {
        let mut views: Vec<OwnerView<'_>> = distinct_src
            .iter()
            .map(|&i| OwnerView {
                allocator: &rules[i].pool_allocator,
                v4: &rules[i].pool_addresses_v4,
                v6: &rules[i].pool_addresses_v6,
            })
            .collect();
        views.extend(distinct_n64.iter().map(|&i| OwnerView {
            allocator: &prefixes[i].port_allocator,
            v4: &prefixes[i].pool_v4,
            // A NAT64 pool is always v4 (`allocate_nat64_pool_port` fails closed
            // on a v6 translated tuple), so there is no v6 half to index.
            v6: &[],
        }));
        build_owner_index(&views)
    };
    let Some(owners) = owners else {
        return;
    };
    let owners = Arc::new(owners);
    for &i in &distinct_n64 {
        if prefixes[i]
            .pool_v4
            .iter()
            .any(|addr| owners.v4.contains_key(addr))
        {
            let allocator = prefixes[i].port_allocator.clone();
            // Every prefix SHARING that allocator gets it, not just the
            // representative the dedup kept.
            for prefix in prefixes.iter_mut() {
                if prefix.port_allocator.same_allocator(&allocator) {
                    prefix.overlap_owners = Some(Arc::clone(&owners));
                }
            }
        }
    }
    assign_source_owners_shared(rules, &distinct_src, owners);
}
