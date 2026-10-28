//! NAT64 allocation reserve/release/rollback facade.
//!
//! Synced (HA) and local reserve, release, and rollback entry points
//! over the per-prefix `PortAllocator`s.
//!
//! #16188 PURE CODE MOTION: every line below was moved verbatim from
//! `nat64.rs` lines 2070-2682 (doc block included; it moved with its fn). The only edits are the visibility
//! widenings enumerated in `nat64/mod.rs`; no logic, no ordering and
//! no signature changed.

use super::*;

/// #4381: release (`rollback == false`) or roll back (`rollback == true`) a
/// NAT64 forward flow's translated pool port on session teardown / install
/// failure, mirroring `crate::nat::release_source_nat_allocation`.
///
/// A no-op unless this is the FORWARD entry of a NAT64 flow carrying a
/// translated source port (`is_reverse == false && nat.nat64 &&
/// rewrite_src == V4 && rewrite_src_port.is_some()`). The flow key is rebuilt
/// EXACTLY as `Nat64State::allocate_source` built it — `dst_ip` is the
/// translated IPv4 destination (`nat.rewrite_dst`), NOT the synthetic v6
/// destination stored on the session key — so the same-key `release_flow` /
/// `rollback_flow` frees the port the forward flow reserved.
///
/// #6876: EVERY prefix holding this exact `(flow, translated)` is freed — the
/// loop does NOT stop at the first one that frees it. This mirrors the
/// source-NAT sibling (`release_source_nat_allocation_with_mode`) and for the
/// same reason: `reserve_synced_nat64_allocation` takes the first prefix whose
/// allocator ACCEPTS, so selection is OCCUPANCY-dependent, not a pure function
/// of the prefix list. A prefix whose port is transiently held by an unrelated
/// local flow is skipped and the reservation lands on a later prefix; when the
/// earlier one frees and the synced session REFRESHES — every HA session-sync
/// reconnect and every periodic re-upsert re-runs the reserve — the SAME flow
/// becomes held in BOTH. A first-hit `break` then freed one and left the other
/// holding its `(pool_addr, port)` forever: nothing else removes a
/// `live_by_flow` entry (`release_flow` / `rollback_flow` / the stale-tuple
/// replace in `reserve_flow` are the only removers, and `gc_expired_chunked`
/// sweeps persistent LEASES, not live flows).
///
/// Sweeping every prefix cannot over-free: `release_flow` / `rollback_flow`
/// return false unless `live_by_flow[flow].translated` equals THIS `translated`
/// tuple, so a prefix holding a different flow — or the same flow under a
/// different translation — is untouched. For the single-reservation case the
/// outcome is bit-identical; only the early exit is gone. Pinned by
/// `nat64_6876_release_frees_every_prefix_holding_the_flow`.
#[allow(clippy::too_many_arguments)]
pub(super) fn release_nat64_allocation_with_mode(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    rollback: bool,
    holder: crate::nat::NatHolder,
) -> bool {
    if is_reverse || !nat.nat64 {
        return false;
    }
    let Some(IpAddr::V4(snat_v4)) = nat.rewrite_src else {
        return false;
    };
    let Some(port) = nat.rewrite_src_port else {
        return false;
    };
    // #17072: ONE builder for the BIB key (see nat64_bib_flow_key).
    let flow = nat64_bib_flow_key(key, nat.rewrite_dst.unwrap_or(key.dst_ip));
    let mut freed = false;
    // #6876: no first-hit `break` — see the doc comment above. A flow can be
    // held in more than one prefix's allocator, and a prefix that does not hold
    // it is a cheap no-op (`release_flow` returns false on a tuple mismatch).
    for prefix in &nat64.prefixes {
        freed |= release_nat64_pool_port(
            &prefix.port_allocator,
            flow,
            snat_v4,
            port,
            now_ns,
            rollback,
            holder,
        );
    }
    freed
}

/// Roll back a coordinator's import-time NAT64 reservation when strict mirror
/// publication refuses the unaccepted entry. This uses `rollback_flow` so a
/// newly created lease is removed rather than retained as an idle BIB mapping.
pub(crate) fn rollback_synced_nat64_allocation_untracked(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) -> bool {
    release_nat64_allocation_with_mode(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        true,
        crate::nat::NatHolder::Untracked,
    )
}

/// Test-only release helper for coordinator imports. Normal teardown preserves
/// the persistent BIB as an idle lease.
///
/// Returns whether the active flow reference was released.
#[cfg(test)]
pub(crate) fn release_synced_nat64_allocation_untracked(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) -> bool {
    release_nat64_allocation_with_mode(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        false,
        crate::nat::NatHolder::Untracked,
    )
}

/// #14961 (D26-05): production untracked release twin of
/// [`release_synced_nat64_allocation_untracked`] for the tunnel-remap purge,
/// mirroring `release_synced_source_nat_allocation_untracked` on the SNAT
/// side. The coordinator's import-time reservation is `NatHolder::Untracked`
/// (no holder bit), so a worker-id release is the wrong call: `Untracked`
/// contributes no bit and `drop_holder_locked` keeps any record a worker
/// HAS adopted, freeing only a record no worker ever claimed. That is the
/// deliberate direction — an under-release leaks a bounded pool port, an
/// over-release hands a live worker's port to a new flow. Returns whether
/// the active flow reference was actually released (for honest counting).
pub(crate) fn release_synced_nat64_allocation_untracked_for_purge(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) -> bool {
    release_nat64_allocation_with_mode(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        false,
        crate::nat::NatHolder::Untracked,
    )
}

/// #4381: release a NAT64 forward flow's translated pool port on session
/// teardown (reap / purge / delete-sync), mirroring
/// `release_source_nat_allocation`.
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin or `rollback_synced_nat64_allocation_untracked` for the
/// coordinator's strict-import rollback.
#[cfg(test)]
pub(crate) fn release_nat64_allocation(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) {
    release_synced_nat64_allocation_untracked(nat64, key, nat, is_reverse, now_ns);
}

/// #6211 F2: release THIS worker's hold on a NAT64 reservation. The
/// holder-aware twin of [`release_nat64_allocation`] — the synced NAT64 entry is
/// reserved once per worker against one shared allocator, so only the last
/// holder may free the translated `(pool v4, port)`.
pub(crate) fn release_nat64_allocation_for_worker(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    worker_id: u32,
) {
    release_nat64_allocation_with_mode(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        false,
        crate::nat::NatHolder::Worker(worker_id),
    );
}

/// #4381: roll back a NAT64 forward flow's translated pool port on an
/// install-failure / admission-refusal / ICMP-error-bounce path, mirroring
/// `rollback_source_nat_allocation_for_worker`.
///
/// #7094: this used to have an `Untracked` twin, kept `#[cfg(test)]` as the
/// #6211 F2 completeness guard — a production caller that forgot to thread its
/// `worker_id` would fail the non-test build rather than silently release a
/// reservation every worker holds. The twin had no caller left, in tests or
/// anywhere else, and rustc warned. Deleting it does not weaken that guard: an
/// undefined name is a build failure in every profile, which is strictly
/// stronger than a name that exists under `cfg(test)`.
///
/// The holder argument is the whole point and is bound by
/// `nat64_7094_rollback_for_worker_frees_only_that_holder`: a rollback releases
/// only THIS worker's hold, so a reservation several workers share survives
/// until the last one lets go.
pub(crate) fn rollback_nat64_allocation_for_worker(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    worker_id: u32,
) {
    release_nat64_allocation_with_mode(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        true,
        crate::nat::NatHolder::Worker(worker_id),
    );
}

/// #4512: reserve a peer-synced NAT64 forward flow's translated pool port in
/// THIS node's NAT64 allocator so a post-failover local allocation cannot hand
/// the same `(snat_v4, port/identifier)` to a fresh flow — the #4388 treatment
/// applied to NAT64.
///
/// The active node picks the translated `(pool v4, port)` via `allocate_source`
/// and syncs the finished [`NatDecision`] over the fabric (the translated port
/// rides `rewrite_src_port`, which IS synced — no new wire field). The standby
/// imports that pre-computed decision and never runs `allocate_source` itself,
/// so its NAT64 allocator has no record that `(snat_v4, port)` is in use.
/// Post-failover the standby-turned-active would then `allocate_source` the
/// SAME tuple for a new local flow — two forward flows colliding on one
/// translated source, so the 1:N reverse (v4→v6) index bucket mis-demuxes the
/// server's replies (reply mis-delivery / session-hijack surface, the exact
/// RFC 6146 BIB violation #4381 closed for the same-node case).
///
/// This is a no-op unless this is the FORWARD entry of a NAT64 flow carrying a
/// translated source port (`is_reverse == false && nat.nat64 &&
/// rewrite_src == V4 && rewrite_src_port.is_some()`). The flow key is rebuilt
/// EXACTLY as `Nat64State::allocate_source` built it and
/// `release_nat64_allocation` frees it — `dst_ip` is the translated IPv4
/// destination (`nat.rewrite_dst`), NOT the synthetic v6 destination on the
/// session key — so the SAME-key release on the standard teardown path
/// (`handle_delete_synced` / reap / purge, already calling
/// `release_nat64_allocation`) returns the reservation with no new delete site.
/// If the synced pool address is not a member of ANY local NAT64 pool (config
/// drift between nodes) the reserve is skipped gracefully — no panic, no
/// reservation on the wrong pool.
/// Compile-time completeness guard for #6211 F2: this untracked entry point is
/// TEST-ONLY, so a production caller that forgot to thread its `worker_id` is a
/// BUILD FAILURE in the non-test profile rather than a silent single-holder
/// release of a reservation every worker holds. Production uses the
/// `_for_worker` twin.
///
/// #6600: no longer test-only. The COORDINATOR takes an untracked reservation
/// before publishing a peer-synced import, and the per-worker reservations that
/// follow are absorbed by `reserve_flow`'s idempotent early return, so the
/// release semantics the comment above warns about are unchanged — the last
/// worker still frees.
pub(crate) fn reserve_synced_nat64_allocation(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) -> bool {
    let mut previous_holders = None;
    reserve_synced_nat64_allocation_with_holder(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        crate::nat::NatHolder::Untracked,
        false,
        &mut previous_holders,
    )
}
/// Coordinator twin that captures the incumbent worker-holder mask before a
/// same-flow translated-tuple replacement can retire it.
pub(crate) fn reserve_synced_nat64_allocation_untracked_with_holder_snapshot(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) -> (bool, Option<u128>) {
    let mut previous_holders = None;
    let reserved = reserve_synced_nat64_allocation_with_holder(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        crate::nat::NatHolder::Untracked,
        true,
        &mut previous_holders,
    );
    (reserved, previous_holders)
}

/// #6211 F2: reserve a synced NAT64 translation and record `worker_id` as a
/// HOLDER. `handle_upsert_synced` runs on every worker against ONE shared NAT64
/// allocator, so without the holder bit the first worker to reap or delete-sync
/// frees a translated `(pool v4, port)` the other workers still forward through.
pub(crate) fn reserve_synced_nat64_allocation_for_worker(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    // #6528: the stale-tuple eviction inside `reserve_flow` retires the
    // incumbent with release semantics, which re-arms a persistent lease's idle
    // expiry off a real clock.
    now_ns: u64,
    worker_id: u32,
) -> bool {
    let mut previous_holders = None;
    reserve_synced_nat64_allocation_with_holder(
        nat64,
        key,
        nat,
        is_reverse,
        now_ns,
        crate::nat::NatHolder::Worker(worker_id),
        false,
        &mut previous_holders,
    )
}

/// #9021: reserve a synced NAT64 translation, then apply the SAME peer-ownership
/// refusal the other three arms apply.
///
/// `reserve_synced_nat64_allocation_with_holder` was the one arm of four that
/// never asked whether a PEER allocator already owns the translated identity.
/// Both SNAT synced arms call `peer_owns_wire_identity`, and the local NAT64
/// mint calls `nat64_refuse_if_peer_owns` — this path returned
/// `reserve_nat64_pool_port` directly on BOTH of its routes.
///
/// The refusal was not one level down: `reserve_nat64_pool_port` ends at
/// `allocator.reserve_flow`, and `PortAllocator` has no `PoolAddressOwners`
/// logic at all. A NAT64 prefix is its own occupancy domain, so a source-NAT
/// pool sharing one of these addresses can already hold this identity for a
/// LIVE flow: the import then succeeded, the coordinator published, and the
/// reverse (1:N) index carried TWO LIVE FLOWS ON ONE TRANSLATED IDENTITY —
/// exactly the split #8115 R2/R3 closed for the other three.
///
/// The two consumers are why the returned bool has to be right here rather than
/// being re-checked downstream: the coordinator (`afxdp/ha/session_import.rs`)
/// uses it as its ONLY refusal point, and the worker twin
/// (`upsert_synced.rs`) discards it entirely.
///
/// ONE function rather than a copy in each of the two routes, for the reason
/// `nat64_refuse_if_peer_owns` itself gives: the routes differ in how they
/// CHOOSE the prefix, not in what makes the tuple a duplicate, and a check
/// duplicated into both is free to drift — a drifted copy still answers, just
/// about a different question.
///
/// Rollback is the helper's job (`rollback_flow`, not `release_flow`): the
/// activation is being WITHDRAWN, and the deterministic arm's block port must go
/// back through the recycling free (#14625) rather than being dropped.
#[allow(clippy::too_many_arguments)]
fn reserve_synced_nat64_port_unless_peer_owns(
    prefix: &Nat64Prefix,
    flow: crate::nat::SourceNatFlowKey,
    snat_v4: std::net::Ipv4Addr,
    port: u16,
    addr_index: usize,
    now_ns: u64,
    holder: crate::nat::NatHolder,
    capture_previous_holders: bool,
    previous_holders: &mut Option<u128>,
) -> bool {
    if let Some(params) = prefix.deterministic_v6 {
        let IpAddr::V6(source) = flow.src_ip else {
            return false;
        };
        if !prefix.port_allocator.deterministic_v6_tuple_matches(
            params,
            source,
            &prefix.pool_v4,
            addr_index,
            snat_v4,
            port,
        ) {
            return false;
        }
    }
    // #15145: ownership is known before the reserve — ask first so a
    // peer/static refusal never evicts this flow's incumbent NAT64
    // reservation. The post-reserve rechecks below stay for races; on that
    // path the incumbent snapshot is not plumbed to this twin (the
    // coordinator's strict-mirror rollback restores it), so the recheck
    // helpers keep their rollback-only behaviour. The interface-registry
    // refusal (#15146) likewise stays post-reserve: its helper rolls back.
    {
        let tuple = TranslatedTuple {
            ip: IpAddr::V4(snat_v4),
            port,
        };
        if peer_owns_identity_in(
            prefix.overlap_owners.as_deref(),
            &prefix.port_allocator,
            flow,
            tuple,
        ) || static_owns_wire_identity(
            prefix.static_externals.as_deref(),
            IpAddr::V4(snat_v4),
            port,
        ) {
            return false;
        }
    }
    let (reserved, captured_holders) = if capture_previous_holders {
        #[cfg(test)]
        crate::nat::gap_barrier_11478::fire_at_capture_gap(capture_previous_holders);
        crate::nat::reserve_nat64_pool_port_capture_and_replace(
            &prefix.port_allocator,
            flow,
            snat_v4,
            port,
            addr_index,
            prefix.deterministic_v6,
            now_ns,
            holder,
        )
    } else {
        (
            reserve_nat64_pool_port(
                &prefix.port_allocator,
                flow,
                snat_v4,
                port,
                addr_index,
                prefix.deterministic_v6,
                now_ns,
                holder,
            ),
            None,
        )
    };
    *previous_holders = captured_holders;
    if !reserved {
        return false;
    }
    // #15146: refuse a synced import the interface registry already owns.
    // This is the synced twin of the #14367 mint-time check in
    // `allocate_source_with_holder`; without it an import lands on an
    // identity a local interface-SNAT flow holds.
    if let Some(ia) = prefix.iface_allocs.as_deref() {
        let eff_owners = prefix
            .iface_overlap_owners
            .as_deref()
            .or(prefix.overlap_owners.as_deref());
        if crate::nat::nat64_refuse_if_interface_owns(
            &prefix.port_allocator,
            eff_owners,
            ia,
            flow,
            (snat_v4, port),
            now_ns,
            holder,
        )
        .is_err()
        {
            return false;
        }
    }
    // #14368: refuse a synced import a static external already covers.
    if crate::nat::nat64_refuse_if_static_owns(
        &prefix.port_allocator,
        prefix.static_externals.as_deref(),
        flow,
        (snat_v4, port),
        now_ns,
        holder,
    )
    .is_err()
    {
        return false;
    }
    crate::nat::nat64_refuse_if_peer_owns(
        &prefix.port_allocator,
        prefix.overlap_owners.as_deref(),
        flow,
        (snat_v4, port),
        now_ns,
        holder,
    )
    .is_ok()
}

fn reserve_synced_nat64_allocation_with_holder(
    nat64: &Nat64State,
    key: &crate::session::SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    holder: crate::nat::NatHolder,
    capture_previous_holders: bool,
    previous_holders: &mut Option<u128>,
) -> bool {
    // #6600: returns whether the translation is RESERVED — true when a prefix
    // took it, and true when there was nothing to reserve. `false` means every
    // pool prefix REFUSED, i.e. a different live allocation already owns the
    // (pool v4, port). The bool `reserve_nat64_pool_port` already computed was
    // discarded before #6600.
    if is_reverse || !nat.nat64 {
        return true;
    }
    let Some(IpAddr::V4(snat_v4)) = nat.rewrite_src else {
        return true;
    };
    let Some(port) = nat.rewrite_src_port else {
        return true;
    };
    // #17072: ONE builder for the BIB key (see nat64_bib_flow_key).
    let flow = nat64_bib_flow_key(key, nat.rewrite_dst.unwrap_or(key.dst_ip));
    // #6892: narrow to the prefix the ACTIVE node would have used, by the SAME
    // discriminator it uses, BEFORE falling back to the pool scan below.
    //
    // The scan alone takes the first prefix whose `pool_v4` contains `snat_v4`
    // -- the #6211 shape. That is not merely too loose: each `Nat64Prefix` owns
    // its OWN `port_allocator`, and the active selected its prefix with
    // `match_ipv6_dest`, i.e. on `prefix_bytes` against the IPv6 destination.
    // Two prefixes sharing one pool address therefore diverge because the
    // standby is matching on the WRONG FIELD, and a divergent pick reserves in a
    // different allocator than the one the session actually occupies -- so the
    // port stays free in the allocator that matters and a post-failover local
    // flow can be handed the same translated `(pool v4, port)`.
    //
    // `key.dst_ip` is the PRE-translation synthetic IPv6 destination, not the
    // extracted v4: a NAT64 forward flow is always keyed on the original IPv6
    // 5-tuple (`build_nat64_reverse_rebuild` in the server helpers already
    // extracts the RFC 6052 embedded v4 out of this same field), and
    // `forward_wire_key` exists precisely because the post-translation view is a
    // DIFFERENT key. That is also why `flow.dst_ip` above substitutes
    // `nat.rewrite_dst` for it.
    //
    // The scan is kept as a fallback rather than replaced: a v4-keyed or
    // prefix-less key (config drift between nodes, an old peer) still gets
    // today's behaviour instead of silently reserving nothing.
    let narrowed = match key.dst_ip {
        IpAddr::V6(dst_v6) => nat64.match_ipv6_dest(dst_v6).map(|(idx, _)| idx),
        IpAddr::V4(_) => None,
    };
    if let Some(prefix) = narrowed.and_then(|idx| nat64.prefixes.get(idx)) {
        if let Some(addr_index) = prefix.pool_index_v4.get(&snat_v4).copied() {
            // #9021: peer-ownership refusal applies here too.
            return reserve_synced_nat64_port_unless_peer_owns(
                prefix,
                flow,
                snat_v4,
                port,
                addr_index,
                now_ns,
                holder,
                capture_previous_holders,
                previous_holders,
            );
        }
    }

    for prefix in &nat64.prefixes {
        // The NAT64 allocator is sized to `pool_v4.len()` with
        // `family_offset == 0`, so the absolute allocator index equals the
        // address's position in `pool_v4` (mirrors `allocate_nat64_pool_port`).
        let Some(addr_index) = prefix.pool_index_v4.get(&snat_v4).copied() else {
            continue;
        };
        // #5178: a NAPT64 (mode 2) deterministic prefix must tag its synced
        // reservation deterministic (mode identity for BIB/lease bookkeeping;
        // #14625: release recycles every port, bounded to one token per
        // offset), mirroring the active node's `allocate_deterministic_v6`.
        // #9021: and on the fallback scan, which is the route a v4-keyed or
        // prefix-less key takes. Leaving it out here would be the partial-fix
        // shape on a path whose whole purpose is to keep working when the
        // narrowed pick cannot.
        if reserve_synced_nat64_port_unless_peer_owns(
            prefix,
            flow,
            snat_v4,
            port,
            addr_index,
            now_ns,
            holder,
            capture_previous_holders,
            previous_holders,
        ) {
            return true;
        }
    }
    // No prefix owned the address, or every owner refused. Not distinguished on
    // purpose: from the coordinator's point of view both mean "this node does
    // not own the translation this session names", and publishing a session for
    // either is the thing #6600 fixes.
    false
}
