//! NAT64 pool-port lifecycle.
//!
//! allocate / release / reserve for NAT64 pool ports. Zero private dependencies
//! in either direction; every item is already `pub(crate)`.
//!
//! #6988 PURE CODE MOTION: every line below was moved verbatim from
//! `nat/source.rs` lines 2354-2493. The only edits are the visibility
//! widenings enumerated in `source/mod.rs`; no logic, no ordering and no
//! signature changed.

use super::*;

/// #4381: allocate a UNIQUE translated `(pool v4 address, L4 port/identifier)`
/// for a NAT64 forward flow, reusing the pool-mode SNAT [`PortAllocator`].
///
/// NAT64 is a many-to-one (v6→v4) translation exactly like pool-mode source
/// NAT: several IPv6 clients are hidden behind one IPv4 pool address, so two
/// clients that share a source port (TCP/UDP) or ICMP echo identifier MUST get
/// DISTINCT translated values or their reverse (v4→v6) 5-tuples collide and the
/// server's replies are mis-associated — the missing RFC 6146 BIB. Rather than
/// hand-roll a parallel allocator, the crate-root `nat64` module drives the
/// same collision-free `PortAllocator` the pool-mode SNAT path uses.
///
/// This thin wrapper keeps the module-private `TranslatedTuple` /
/// `PoolAddressFamily` types out of `nat64.rs`. NAT64 never uses persistent NAT
/// or address-persistent stickiness, so those knobs are fixed off.
pub(crate) fn allocate_nat64_pool_port(
    allocator: &PortAllocator,
    flow: SourceNatFlowKey,
    pool_v4: &[Ipv4Addr],
    now_ns: u64,
    // #6522: the allocating worker — see `match_source_nat_result_for_tuple`.
    holder: NatHolder,
) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
    let translated = allocator.allocate_translation(
        flow,
        PoolAddressFamily::V4(pool_v4),
        0,     // family_offset — the v4 pool starts at index 0
        false, // address_persistent
        false, // persistent_nat
        PersistentNatPermit::default(),
        0, // persistent_nat_timeout_ns — unused when persistent_nat is false
        now_ns,
        holder,
    )?;
    match translated.ip {
        IpAddr::V4(v4) => Ok((v4, translated.port)),
        // The pool is always v4 for NAT64, so this is unreachable; fail closed.
        IpAddr::V6(_) => Err(SourceNatFailureReason::WrongAddressFamily),
    }
}

/// #4559: allocate a DETERMINISTIC translated `(pool v4 address, L4 port)` for
/// a NAPT64 (mode 2) forward flow — the IPv6 subscriber deterministically maps
/// to a fixed external IPv4 + port block ([`allocate_deterministic_v6`]).
/// Thin wrapper mirroring [`allocate_nat64_pool_port`] so the module-private
/// `TranslatedTuple` stays out of `nat64.rs`; `flow` carries the original IPv6
/// subscriber (`flow.src_ip`), from which the subscriber block is derived. The
/// pool is always v4 for NAT64, so a v6 translated tuple is unreachable and
/// fails closed.
pub(crate) fn allocate_nat64_pool_port_deterministic_v6(
    allocator: &PortAllocator,
    flow: SourceNatFlowKey,
    pool_v4: &[Ipv4Addr],
    params: DeterministicV6,
    src_v6: Ipv6Addr,
    // #6522: the allocating worker — see `match_source_nat_result_for_tuple`.
    holder: NatHolder,
) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
    let translated =
        allocator.allocate_deterministic_v6(flow, pool_v4, params, src_v6, holder)?;
    match translated.ip {
        IpAddr::V4(v4) => Ok((v4, translated.port)),
        IpAddr::V6(_) => Err(SourceNatFailureReason::WrongAddressFamily),
    }
}

/// #4381: release (or roll back) a NAT64 forward flow's translated pool port,
/// mirroring [`release_synced_source_nat_allocation_untracked`]'s flow-key /
/// translated-tuple construction so the SAME `release_flow` / `rollback_flow`
/// forward flow allocated. Returns whether the allocation was found and freed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn release_nat64_pool_port(
    allocator: &PortAllocator,
    flow: SourceNatFlowKey,
    snat_v4: Ipv4Addr,
    port: u16,
    now_ns: u64,
    rollback: bool,
    // #6211 F2: the worker letting go. `NatHolder::Untracked` keeps the
    // pre-#6211-F2 first-release-frees contract for a local NAT64 flow; a synced
    // reservation taken by N workers frees only on the last one.
    holder: NatHolder,
) -> bool {
    let translated = TranslatedTuple {
        ip: IpAddr::V4(snat_v4),
        port,
    };
    if rollback {
        allocator.rollback_flow(flow, translated, now_ns, holder)
    } else {
        allocator.release_flow(flow, translated, now_ns, holder)
    }
}

/// #4512: reserve a peer-synced NAT64 forward flow's translated `(pool v4,
/// port/identifier)` in THIS node's NAT64 [`PortAllocator`] WITHOUT running the
/// round-robin cursor, mirroring [`reserve_synced_source_nat_allocation`] for
/// the pool-mode SNAT allocator (#4388).
///
/// The standby imports the active node's pre-computed NAT64 decision but never
/// calls `allocate_source`, so without this its allocator has no record that
/// `(snat_v4, port)` is in use — post-failover a fresh local NAT64 flow could
/// `allocate_source` the SAME tuple, two flows colliding on one translated
/// source (the exact RFC 6146 BIB violation #4381 closed, reappearing across a
/// cross-node failover). The reservation is stored EXACTLY like a normal
/// allocation and freed by the SAME `release_nat64_pool_port` on the standard
/// teardown path (`release_nat64_allocation`, already called on reap / purge /
/// delete-sync), so no new delete site is needed.
///
/// `addr_index` is the position of `snat_v4` in the prefix's `pool_v4` — the
/// NAT64 allocator uses `family_offset == 0`, so the absolute allocator index
/// equals the pool position. Returns whether the reservation took (`false` if
/// the port is already owned by a DIFFERENT live allocation — the caller then
/// tries the next prefix).
///
/// #5178: `deterministic` is `true` when the prefix runs a NAPT64 (mode 2)
/// deterministic pool (`prefix.deterministic_v6.is_some()`), so the reservation
/// is tagged deterministic and released via `free_no_recycle` — matching the
/// active node's `allocate_deterministic_v6` release. A round-robin NAT64 pool
/// passes `false` and keeps today's recycle behaviour.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reserve_nat64_pool_port(
    allocator: &PortAllocator,
    flow: SourceNatFlowKey,
    snat_v4: Ipv4Addr,
    port: u16,
    addr_index: usize,
    deterministic: bool,
    // #6528: threaded to `reserve_flow` for its stale-tuple eviction.
    now_ns: u64,
    // #6211 F2: the worker taking this reservation. The synced NAT64 entry is
    // fanned out to every worker against ONE shared allocator, exactly like the
    // pool-mode SNAT reservation.
    holder: NatHolder,
) -> bool {
    let translated = TranslatedTuple {
        ip: IpAddr::V4(snat_v4),
        port,
    };
    // #7360: NAT64 pools have no persistent-NAT lease concept — the lease is a
    // source-NAT rule property (`SourceNatRule::persistent_nat`) and this is the
    // NAT64 translated-port domain — so this stays the non-persistent entry point.
    allocator.reserve_flow(flow, translated, addr_index, deterministic, now_ns, holder)
}

/// #8115 R3: refuse a NAT64 mint whose translated identity a PEER allocator
/// already owns, and undo the reservation before failing.
///
/// One function rather than a copy in each mint arm. NAT64 has two —
/// round-robin PAT and deterministic NAPT64 (#4559) — and a check duplicated
/// into both is free to drift; a drifted copy still answers, just about a
/// different question. The caller applies this to whichever arm produced the
/// tuple.
///
/// Keeps the module-private `TranslatedTuple` out of `nat64.rs`, the same reason
/// [`allocate_nat64_pool_port`] exists.
///
/// `rollback_flow` rather than `release_flow`: this activation is being
/// WITHDRAWN, not completing, and the two take different persistent-lease arms
/// (#6528). It also matters for the DETERMINISTIC arm, whose block port must go
/// back through `free_no_recycle` rather than onto the recycle ring the
/// deterministic mapping never draws from.
pub(crate) fn nat64_refuse_if_peer_owns(
    allocator: &PortAllocator,
    owners: Option<&PoolAddressOwners>,
    flow: SourceNatFlowKey,
    translated: (Ipv4Addr, u16),
    now_ns: u64,
    holder: NatHolder,
) -> Result<(), SourceNatFailureReason> {
    let tuple = TranslatedTuple {
        ip: IpAddr::V4(translated.0),
        port: translated.1,
    };
    if !peer_owns_identity_in(owners, allocator, flow, tuple) {
        return Ok(());
    }
    allocator.rollback_flow(flow, tuple, now_ns, holder);
    Err(SourceNatFailureReason::PoolPeerAddressOverlap)
}
