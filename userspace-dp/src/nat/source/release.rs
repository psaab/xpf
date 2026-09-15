//! Allocation release and rollback.
//!
//! The four public release/rollback entry points and the shared
//! `release_source_nat_allocation_with_mode` they funnel into. No in-file
//! callers, and no private items outside this module are touched.
//!
//! #6988 PURE CODE MOTION: every line below was moved verbatim from
//! `nat/source.rs` lines 1580-1836. The only edits are the visibility
//! widenings enumerated in `source/mod.rs`; no logic, no ordering and no
//! signature changed.

use super::*;

/// Release an UNTRACKED (single-holder) source-NAT allocation — the
/// pre-#6211-F2 contract, where the first release frees the port.
///
/// Production forwarding paths must use
/// [`release_source_nat_allocation_for_worker`] instead: an HA-synced session is
/// reserved once per worker against one shared allocator, and only the LAST
/// holder may free the port. This entry point remains for tests that exercise
/// the single-holder semantics directly.
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin.
///
/// The one permitted untracked production use — a coordinator import-time
/// reservation withdrawn before any worker adopts it (the #6600 NAT64-refusal
/// rollback and the #8138 tunnel-purge release, where there is no worker_id to
/// thread) — goes through the NAMED production entry
/// [`release_synced_source_nat_allocation_untracked`], not here.
#[cfg(test)]
pub(crate) fn release_source_nat_allocation(
    // #6751: the interface-mode identity registry. Passed EXPLICITLY rather
    // than reached through `rules`, because a teardown must free the identity
    // even after a commit that removed every source-NAT rule — a rules-derived
    // registry would be unreachable exactly then, and the identity would be
    // held for the node's lifetime.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) -> bool {
    // #8138: returns whether a reservation was actually freed, so the tunnel-remap
    // purge can count repairs it performed rather than repairs it attempted.
    // Statement-position callers are unaffected.
    release_source_nat_allocation_with_mode(
        iface_allocs,
        rules,
        key,
        nat,
        is_reverse,
        now_ns,
        false,
        NatHolder::Untracked,
    )
}

/// Release a coordinator's import-time UNTRACKED reservation — the ONLY
/// permitted untracked production use (#9902 F-097).
///
/// The coordinator takes import-time reservations as `NatHolder::Untracked`
/// ([`reserve_synced_source_nat_allocation_untracked`]); when the import is
/// withdrawn before any worker adopts it — the #6600 NAT64-refusal rollback
/// and the #8138 tunnel-purge release — there is no worker_id to thread, so
/// the holder-aware twins are the wrong call, not a safer one. Records a
/// worker HAS adopted survive: `Untracked.bit()` is 0, so `drop_holder_locked`
/// keeps any record with holders set. That is the deliberate direction for a
/// release site that cannot name a worker: an under-release leaks a bounded
/// pool port, an over-release hands a live worker's port to a new flow.
///
/// Behavior-identical to the pre-#9902 direct `release_source_nat_allocation`
/// calls at those two sites (a release, not a rollback). Returns whether a
/// reservation was actually freed (#8138 counting).
pub(crate) fn release_synced_source_nat_allocation_untracked(
    // #6751: see `release_source_nat_allocation`.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) -> bool {
    release_source_nat_allocation_with_mode(
        iface_allocs,
        rules,
        key,
        nat,
        is_reverse,
        now_ns,
        false,
        NatHolder::Untracked,
    )
}

/// #6211 F2: release THIS worker's hold on a source-NAT allocation.
///
/// For a local allocation (no holder set) this is bit-identical to
/// [`release_synced_source_nat_allocation_untracked`] — the port is freed. For
/// an HA-synced reservation, which every worker took against the single shared
/// allocator, only `worker_id`'s bit is cleared and the port survives until the
/// last worker releases it.
/// #6979: clear `worker_id`'s holder bit across every POOL-mode rule allocator,
/// freeing any record the clear empties. Returns records freed.
///
/// The counterpart to [`release_source_nat_allocation_for_worker`] for a worker
/// that will never call it. That function clears one bit for one flow when the
/// worker runs its own release; this clears the same worker's bit across every
/// flow it still holds, for a worker that has stopped.
///
/// Sound only because #6522 made the allocating worker a holder of its own
/// allocation: before that the mask named every worker EXCEPT the one
/// forwarding, so emptying it would have freed a tuple still in use. The
/// direction-of-error rule is stated at `PortAllocator::drop_holder_locked` --
/// an under-release leaks a bounded port, an over-release hands a live worker's
/// `(pool_addr, port)` to a new flow -- and clearing a STOPPED worker's bit
/// cannot over-release, because that worker will never forward again.
pub(crate) fn retire_worker_from_pool_rules(
    rules: &[SourceNatRule],
    worker_id: u32,
    now_ns: u64,
) -> usize {
    // Every rule is swept, not just pool-mode ones: a non-pool rule's allocator
    // holds no bits, so its retire is a no-op returning 0. Filtering on
    // `pool_mode` here would re-derive a predicate the allocator already answers
    // correctly, and would go wrong for a rule whose mode changed while it still
    // held live allocations.
    rules
        .iter()
        .map(|rule| rule.pool_allocator.retire_worker(worker_id, now_ns))
        .sum()
}

pub(crate) fn release_source_nat_allocation_for_worker(
    // #6751: see `release_source_nat_allocation`.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    worker_id: u32,
) {
    release_source_nat_allocation_with_mode(
        iface_allocs,
        rules,
        key,
        nat,
        is_reverse,
        now_ns,
        false,
        NatHolder::Worker(worker_id),
    );
}

/// Roll back an UNTRACKED (single-holder) source-NAT allocation. See
/// [`release_synced_source_nat_allocation_untracked`]; production paths use
/// [`rollback_source_nat_allocation_for_worker`].
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin.
#[cfg(test)]
pub(crate) fn rollback_source_nat_allocation(
    // #6751: see `release_source_nat_allocation`.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) {
    release_source_nat_allocation_with_mode(
        iface_allocs,
        rules,
        key,
        nat,
        is_reverse,
        now_ns,
        true,
        NatHolder::Untracked,
    );
}

/// #6211 F2: roll back THIS worker's hold on a source-NAT allocation. The
/// holder-aware twin of [`rollback_source_nat_allocation`].
pub(crate) fn rollback_source_nat_allocation_for_worker(
    // #6751: see `release_source_nat_allocation`.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    worker_id: u32,
) {
    release_source_nat_allocation_with_mode(
        iface_allocs,
        rules,
        key,
        nat,
        is_reverse,
        now_ns,
        true,
        NatHolder::Worker(worker_id),
    );
}

#[allow(clippy::too_many_arguments)]
fn release_source_nat_allocation_with_mode(
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    rollback: bool,
    holder: NatHolder,
) -> bool {
    // #8138: report whether anything was ACTUALLY freed. A caller that counts a
    // repair it did not perform is worse than one that counts nothing — the
    // operator gets a number that says the leak is being handled while the port
    // stays held. `release_flow` / `rollback_flow` already return exactly this
    // (false unless `live_by_flow[flow].translated` matches), so the signal was
    // present and discarded.
    if is_reverse {
        return false;
    }
    let Some(rewrite_src) = nat.rewrite_src else {
        return false;
    };
    // #5269: a PAT decision carries its translated port in `rewrite_src_port`; an
    // ADDRESS-ONLY decision (`port no-translation` / port-less) leaves it unset
    // but minted an occupancy token keyed on the PRESERVED source port. Fall back
    // to the flow's own source port so the SAME `release_flow` / `rollback_flow`
    // frees that token. A non-pool address translation (interface-mode / static
    // SNAT) also reaches here now, but owns no pool `live_by_flow` entry, so the
    // per-rule release is a harmless no-op.
    let rewrite_src_port = nat.rewrite_src_port.unwrap_or(key.src_port);
    let translated = TranslatedTuple {
        ip: rewrite_src,
        port: rewrite_src_port,
    };
    let flow = SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: nat.rewrite_dst.unwrap_or(key.dst_ip),
        src_port: key.src_port,
        // #9388: the POST-DNAT destination port, for the same reason the line
        // above takes the post-DNAT destination ADDRESS. #9034 moved the
        // source-NAT match/allocate call site onto `policy_dst_port`
        // (`pre_routing_dnat.rewrite_dst_port.unwrap_or(forward_key.dst_port)`,
        // `afxdp/poll_descriptor/mod.rs`), so `live_by_flow` is now INSERTED
        // under the translated port. This teardown is handed the installed
        // `SessionKey`, whose `dst_port` is the ORIGINAL wire port, so keeping
        // it here made every ordinary expiry of a port-moving twice-NAT flow
        // (`198.51.100.7:443` -> `10.10.10.7:8443`, the VIP shape) miss the
        // record it was meant to free — a permanent `(pool_addr, port)` +
        // `live_by_flow` slot leak counted against `max_tracked_flows`, and, on
        // a `persistent-nat` rule, a lease refcount that never reaches idle so
        // no GC path can reclaim the pinned pool ADDRESS either. It also leaks
        // the interface-mode identity 90 lines below, which shares this `flow`.
        //
        // Idempotent on the ROLLBACK callers, which pass
        // `nat_match_flow.forward_key` (already post-DNAT on BOTH axes): there
        // `rewrite_dst_port` either equals `key.dst_port` or is `None`, so this
        // reproduces the value #9034's own analysis relies on.
        //
        // MUST move together with the identical line in `synced.rs` — the two
        // sites are the reserve and the release of ONE record, and fixing
        // either alone leaves them keyed differently while the whole `nat::`
        // suite stays green. `snat_9388_reserve_and_release_agree_on_post_dnat_port`
        // is the cell that reds on a one-file landing.
        dst_port: nat.rewrite_dst_port.unwrap_or(key.dst_port),
        // #9062: the same domain the session layer stamped, so this key matches
        // the one the match path built.
        routing_scope: key.routing_domain,
    };
    // #6211: free from EVERY allocator that holds this exact
    // `(flow, translated)` — do NOT stop at the first.
    //
    // State the reason accurately, because the sweep rests on it (#6876): the
    // reserve has NEVER been a pure function of `rules`, so the "at most one
    // allocator holds a given flow" invariant did not hold even against an
    // UNCHANGED rule set. `reserve_synced_on_first_pool_owner` takes the first
    // rule whose allocator ACCEPTS and skips one that refuses — selection is
    // OCCUPANCY-dependent. That is pre-#6211 behaviour, not something this fix
    // introduced: the pre-#6211 loop had the same per-rule fall-through and its
    // own comment described it ("a collision on the standby ... leaves the rule
    // untouched and tries the next"). So a rule that refused while an unrelated
    // local flow held the identity, and accepted later once that flow retired,
    // could ALREADY put one flow in two allocators across a re-upsert — every
    // live session re-upserts on HA session-sync reconnect and on a
    // post-delete-journal-overflow resync — with the rule set untouched.
    //
    // Two other routes reach the same state. `parse_source_nat_rules_with_previous`
    // carries allocators over keyed on `allocator_key()` alone, so an edit that
    // reshuffled which rule a session matched could strand a flow in a
    // carried-over allocator. And #6211's two-pass selection adds a third:
    // pass 1 and pass 2 can choose DIFFERENT rules for the same session at
    // different times (a zone delete/renumber, or a rule-set `from zone` /
    // `match` edit, flips `synced_zones` to `None` or moves pass 1's candidate
    // set), and the two rules' allocators are independent.
    //
    // A first-hit `break` was never sufficient under any of them, and the cost
    // of getting it wrong is unbounded: the teardown freed one allocator and
    // left the other holding its `(pool_addr, port)` forever — a permanent
    // standby pool leak that also counted against `max_tracked_flows` until
    // the allocator reported `AllocatorExhausted`. Nothing reaps it —
    // `live_by_flow` is only
    // removed by `release_flow` / `rollback_flow` / the stale-tuple replace in
    // `reserve_flow`, and `gc_expired_chunked` sweeps persistent LEASES, not
    // live flows. A config change does not rebuild the allocator either:
    // carryover is keyed on `allocator_key()` (pool name + addresses + port
    // range), so the very edit that flips pass 1's outcome preserves the leak.
    //
    // Sweeping every rule is safe and cannot over-free: `release_flow` /
    // `rollback_flow` return false unless `live_by_flow[flow].translated`
    // equals THIS `translated` tuple, so an allocator holding a different
    // flow — or the same flow under a different translation — is untouched.
    // For the single-reservation case — whenever selection never moved, which
    // is the overwhelmingly common one — the outcome is bit-identical; only
    // the early exit is gone. Note this is NOT the same as "every pre-#6211
    // config": occupancy-dependent selection predates #6211, so a pre-#6211
    // config could already hold one flow in two allocators (see above).
    //
    // That early exit was NOT on a cold path, so state the cost honestly rather
    // than waving it off. This body backs `rollback_source_nat_allocation_for_worker`
    // as well as the releases, and that has five production call sites, all of
    // them on the packet path in `afxdp/poll_descriptor/mod.rs` — including the
    // admission-refusal arm, i.e. the flood regime. (Pre-#9902 this comment named
    // the TEST-ONLY `rollback_source_nat_allocation`, which has no production
    // callers.)
    // Per refused SNAT'ed flow the sweep takes K allocator locks instead of
    // (owning index + 1), where K is the pool-mode rule count. This is a
    // mechanism statement: no throughput measurement was taken and none is
    // claimed. The correctness argument above is what justifies it — a leaked
    // `(pool_addr, port)` is permanent and counts against `max_tracked_flows`
    // until exhaustion, while the extra locks are bounded and per-teardown.
    let mut freed = false;
    for rule in rules {
        if !rule.pool_mode {
            continue;
        }
        if rollback {
            freed |= rule
                .pool_allocator
                .rollback_flow(flow, translated, now_ns, holder);
        } else {
            freed |= rule
                .pool_allocator
                .release_flow(flow, translated, now_ns, holder);
        }
    }
    // #6751: free the INTERFACE-mode translated identity. LOOKUP-ONLY — a
    // release for an address that owns no allocator has nothing to free, and
    // creating one here would let a teardown storm fill the registry with
    // empty allocators.
    //
    // Safe to run unconditionally alongside the pool sweep for the same reason
    // the pool sweep cannot over-free: `release_flow`/`rollback_flow` return
    // without mutating unless `live_by_flow[flow].translated` equals THIS
    // `translated` tuple, and a pool address is never an interface egress
    // address's allocator key (the registry is keyed by the egress address the
    // interface decision actually wrote). `translated.port` above is
    // `rewrite_src_port.unwrap_or(key.src_port)`, which is the PRESERVED port
    // for a preserved mint and the PAT'd port for a PAT'd one — matching what
    // `allocate_interface_identity` stored in both cases.
    if let Some(alloc) = iface_allocs.allocator_if_present(rewrite_src) {
        if rollback {
            freed |= alloc.rollback_flow(flow, translated, now_ns, holder);
        } else {
            freed |= alloc.release_flow(flow, translated, now_ns, holder);
        }
    }
    freed
}
