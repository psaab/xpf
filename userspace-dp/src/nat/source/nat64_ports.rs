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

/// RFC 6146 §3.5.2 binding-independent mapping for the standard round-robin
/// NAT64 pool path: allocate one translated tuple per IPv6 transport address
/// (protocol, source IPv6, source port), not per remote endpoint. Reuse the
/// source-NAT allocator's persistent lease table with `AnyRemoteHost`; its
/// active-flow refcount keeps the binding reserved until every session using
/// it closes, then the 300-second idle lease preserves the BIB as required by
/// RFC 6146. Deterministic NAPT64 uses a separate block allocator; its
/// per-remote allocation residual is tracked by #14091.
///
/// This thin wrapper keeps the module-private `TranslatedTuple` /
/// `PoolAddressFamily` types out of `nat64.rs`. NAT64 uses no address stickiness.
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
        0,     // family_offset — NAT64 pool addresses start at index 0
        false, // address_persistent
        true,  // persistent_nat: BIB identity excludes the remote endpoint
        PersistentNatPermit::AnyRemoteHost,
        300 * 1_000_000_000, // RFC 6146 idle BIB lifetime
        now_ns,
        holder,
        0,
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
    now_ns: u64,
    // #6522: the allocating worker — see `match_source_nat_result_for_tuple`.
    holder: NatHolder,
) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
    let translated =
        allocator.allocate_deterministic_v6_at(flow, pool_v4, params, src_v6, now_ns, holder)?;
    match translated.ip {
        IpAddr::V4(v4) => Ok((v4, translated.port)),
        IpAddr::V6(_) => Err(SourceNatFailureReason::WrongAddressFamily),
    }
}

/// #4381: release (or roll back) a NAT64 forward flow's translated pool port,
/// mirroring the flow-key / translated-tuple construction used by source NAT.
/// Normal release drops this flow's active reference; a persistent BIB lease
/// keeps the tuple allocated for its idle timeout. Rollback removes a
/// speculative activation that was never published.
#[allow(clippy::too_many_arguments)]
pub(crate) fn release_nat64_pool_port(
    allocator: &PortAllocator,
    flow: SourceNatFlowKey,
    snat_v4: Ipv4Addr,
    port: u16,
    now_ns: u64,
    rollback: bool,
    // #6211 F2: the worker letting go. Synced reservations taken by N workers
    // are released once per holder; the final release retains the idle lease.
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
/// calls `allocate_source`, so this joins the same endpoint-independent BIB
/// lease as a local flow. Multiple synchronized flows from the same IPv6
/// transport address share its translated tuple and active reference count.
/// The final flow release retains the 300-second idle lease.
///
/// `addr_index` is the position of `snat_v4` in the prefix's `pool_v4` — the
/// NAT64 allocator uses `family_offset == 0`, so the absolute allocator index
/// equals the pool position. Returns whether the reservation took (`false` if
/// another flow or incompatible BIB lease owns the translated tuple, in which
/// case the caller tries the next prefix).
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
    let persistent = Some((
        flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
        300 * 1_000_000_000,
    ));
    let mut previous_snapshot = None;
    allocator.reserve_flow_maybe_persistent(
        flow,
        translated,
        addr_index,
        deterministic,
        now_ns,
        holder,
        persistent,
        false,
        &mut previous_snapshot,
    )
}

/// #11478: coordinator form of [`reserve_nat64_pool_port`]. The holder mask is
/// captured by the allocator's same live guard that evicts and installs the
/// reservation, so worker OR/release operations cannot land between them.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reserve_nat64_pool_port_capture_and_replace(
    allocator: &PortAllocator,
    flow: SourceNatFlowKey,
    snat_v4: Ipv4Addr,
    port: u16,
    addr_index: usize,
    deterministic: bool,
    now_ns: u64,
    holder: NatHolder,
) -> (bool, Option<u128>) {
    let translated = TranslatedTuple {
        ip: IpAddr::V4(snat_v4),
        port,
    };
    let mut previous_snapshot = None;
    let reserved = allocator.reserve_flow_maybe_persistent(
        flow,
        translated,
        addr_index,
        deterministic,
        now_ns,
        holder,
        Some((
            flow.persistent_source_key(PersistentNatPermit::AnyRemoteHost),
            300 * 1_000_000_000,
        )),
        true,
        &mut previous_snapshot,
    );
    (reserved, previous_snapshot.map(|snapshot| snapshot.holder_mask()))
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

/// #14367: refuse a NAT64 mint whose identity the interface registry owns.
/// `owners` when Some restricts to shared addresses; otherwise direct query.
pub(crate) fn nat64_refuse_if_interface_owns(
    allocator: &PortAllocator,
    owners: Option<&PoolAddressOwners>,
    iface_allocs: &InterfaceNatAllocators,
    flow: SourceNatFlowKey,
    translated: (Ipv4Addr, u16),
    now_ns: u64,
    holder: NatHolder,
) -> Result<(), SourceNatFailureReason> {
    let tuple = TranslatedTuple { ip: IpAddr::V4(translated.0), port: translated.1 };
    let owned = if let Some(o) = owners {
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        o.interface_holds(flow, tuple, allocator) || direct_iface_owns(iface_allocs, flow, tuple)
    } else {
        direct_iface_owns(iface_allocs, flow, tuple)
    };
    if !owned {
        return Ok(());
    }
    allocator.rollback_flow(flow, tuple, now_ns, holder);
    Err(SourceNatFailureReason::PoolPeerAddressOverlap)
}

pub(crate) fn direct_iface_owns(iface_allocs: &InterfaceNatAllocators, flow: SourceNatFlowKey, translated: TranslatedTuple) -> bool {
    match iface_allocs.allocator_if_present(translated.ip) {
        Some(a) => a.holds_address_only_identity(&super::super::allocator::AddressOnlyReverseKey::for_flow(&flow, translated.ip, translated.port)),
        None => false,
    }
}

/// #14367: does any pool/NAT64 peer own candidate for interface mint?
/// PAT bitmap remote-agnostic (PAT'd away), address-only remote-specific.
pub(crate) fn peer_owns_for_interface(owners: Option<&PoolAddressOwners>, own_iface: &PortAllocator, flow: SourceNatFlowKey, translated: TranslatedTuple) -> bool {
    let Some(o) = owners else { return false; };
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    o.holds_for_interface(flow, translated, own_iface)
}

pub(crate) fn iface_owns_for_pool(iface_allocs: &InterfaceNatAllocators, flow: SourceNatFlowKey, translated: TranslatedTuple) -> bool {
    direct_iface_owns(iface_allocs, flow, translated)
}

/// #14368: the static twin of [`nat64_refuse_if_peer_owns`]. A static
/// external covering the minted tuple publishes it unconditionally, so the
/// mint rolls back and fails with the same reason rather than publishing a
/// duplicate the reverse index cannot attribute. One helper for both NAT64
/// mint arms and the synced reserve, for the same anti-drift reason as the
/// peer helper above.
pub(crate) fn nat64_refuse_if_static_owns(
    allocator: &PortAllocator,
    statics: Option<&crate::nat::StaticExternalIdentities>,
    flow: SourceNatFlowKey,
    translated: (Ipv4Addr, u16),
    now_ns: u64,
    holder: NatHolder,
) -> Result<(), SourceNatFailureReason> {
    if !static_owns_wire_identity(statics, IpAddr::V4(translated.0), translated.1) {
        return Ok(());
    }
    let tuple = TranslatedTuple {
        ip: IpAddr::V4(translated.0),
        port: translated.1,
    };
    allocator.rollback_flow(flow, tuple, now_ns, holder);
    Err(SourceNatFailureReason::PoolPeerAddressOverlap)
}
