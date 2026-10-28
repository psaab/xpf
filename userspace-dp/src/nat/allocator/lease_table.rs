//! #17028 (R4-Q11-02): the single owner of the persistent-lease
//! 0 -> 1 join and idle-retire transitions.
//!
//! Before this module the activation-snapshot / expiry-index /
//! refcount / free-by-mode sequence was hand-copied at six join
//! sites (local PAT, both deterministic-BIB branches, synced PAT,
//! synced address-only, local address-only) and the retire sequence
//! at nine more; missed copies shipped #9158, #9536 and #14670, and
//! the copies had already diverged on exhaustion accounting
//! (claimed-port BIB cap-fail skipped `exhaustion_total`) and on
//! revoked-live handling (BIB copies filtered `!revoked` into a bare
//! exhaustion where PAT returned a mode mismatch). Both divergences
//! are decided ONCE here / at the one remaining exhaustion site:
//!
//!   - Revoked-live: a revoked lease with live flows is NEVER joined
//!     and never retired. On a mode-gated path the caller maps it to
//!     its "leave standing / serve unpinned" answer (PAT:
//!     `LeaseReuse::LiveModeMismatch`, local address-only: the
//!     `live_mode_mismatch` arm); the deterministic BIB, which has no
//!     unpinned fallback, refuses with `AllocatorExhausted` — and now
//!     bumps `exhaustion_total` exactly like every other refusal.
//!   - Cap-fail counter: every `AllocatorExhausted` return in
//!     `allocate_deterministic_v6_at` bumps `exhaustion_total`,
//!     including the join-cap failure the claimed-port copy used to
//!     return silently (its free of the claimed candidate port is
//!     kept — that port was claimed by THIS call, not by the lease).
//!
//! This module only mutates `PortAllocatorLiveState` fields (the map
//! + both expiry indexes, via the one `remove_persistent_lease`
//! seam). Bitmap frees stay with the caller because their TIMING
//! differs by site (inline under `live`, stamped, deferred past the
//! guard drop, or through `free_translated_port` unstamped); the
//! retire helpers therefore REPORT the lease's port to free and the
//! caller frees by-mode. Visibility: `pub(in crate::nat::allocator)`
//! spells exactly "visible inside nat::allocator" — `pub(super)`
//! would mean the same today and silently narrow if this file moves
//! deeper (the occupancy.rs / #6988 trap).

use super::{PersistentLease, PersistentSourceKey, PortAllocatorLiveState, TranslatedTuple};

/// #17028: the per-caller knobs of the 0 -> 1 / N -> N+1 join. The
/// modes really differ in exactly these three parameters; everything
/// else (snapshot, de-index, refcount) is the shared invariant.
#[derive(Clone, Copy, Debug)]
pub(in crate::nat::allocator) struct JoinPolicy {
    /// Timeout applied on the join. Local paths pass their bounded
    /// local timeout; the deterministic BIB passes its fixed
    /// `DETERMINISTIC_NAT64_BIB_TIMEOUT_NS`; synced joins pass the
    /// synced timeout (used only to mint — an existing lease's
    /// `timeout_ns` is never overwritten by a synced join).
    pub(in crate::nat::allocator) timeout_ns: u64,
    /// A locally-minted lease adopts the local timeout immediately on
    /// the 0 -> 1 edge; an imported lease defers promotion to a
    /// completing `release_flow` via the per-flow marker.
    pub(in crate::nat::allocator) promote_imported: bool,
    /// Whether the 0 -> 1 edge moves `expires_at_ns` to
    /// `now + timeout`. PAT and local address-only refresh (their
    /// lease is out of the idle index once active, and
    /// `complete_persistent_lease_locked` re-arms on drain); the
    /// full-block BIB also refreshes (#15948: only on the idle edge,
    /// never while active); the claimed-port BIB and both synced
    /// joins deliberately do NOT move an expiry they did not
    /// de-index / do not own — `release_flow` re-arms it.
    pub(in crate::nat::allocator) refresh_expiry: bool,
}

/// #17028: the result of the shared join. `Joined` carries everything
/// the caller needs to insert its `LiveAllocation` and publish its
/// owner records without re-reading the lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::nat::allocator) enum JoinOutcome {
    Joined {
        translated: TranslatedTuple,
        addr_index: usize,
        /// `true` on the 0 -> 1 edge (snapshot armed, idle expiry
        /// de-indexed). Callers with their own expiry bookkeeping
        /// (synced address-only) key their de-index on this.
        was_idle: bool,
        /// Per-flow timeout-promotion marker for an imported lease,
        /// consumed by a completing `release_flow`.
        promotion_timeout_ns: Option<u64>,
    },
    /// No lease under `key`.
    NoLease,
}

/// #17028: the shared 0 -> 1 / N -> N+1 lease join.
///
/// On the idle edge: snapshot `activation_previous_*`, clear
/// `activation_saw_completion`, set `activation_had_previous_lease`,
/// remove the idle expiry-index entries (an ACTIVE lease is never
/// indexed), apply the timeout per `promote_imported`, optionally
/// refresh the expiry, and bump `active_flows`. On an already-active
/// lease only the refcount and the imported-promotion marker move
/// (an active lease is not in either index, so its expiry must not
/// move without re-keying — #15948).
///
/// The caller has already decided this lease MAY be joined (mode,
/// revoked-live, identity and admission gates stay at the call
/// sites, where their refusal shapes differ). This helper performs
/// no admission and touches no flow shard, bitmap or counter.
pub(in crate::nat::allocator) fn join_persistent_lease_locked(
    live: &mut PortAllocatorLiveState,
    key: PersistentSourceKey,
    policy: JoinPolicy,
    now_ns: u64,
) -> JoinOutcome {
    let Some(lease) = live.persistent_by_source.get(&key).copied() else {
        return JoinOutcome::NoLease;
    };
    let was_idle = lease.active_flows == 0 && lease.inbound_flows == 0;
    if was_idle {
        super::PortAllocator::remove_lease_expiration_locked(
            live,
            lease.addr_index,
            lease.expires_at_ns,
            key,
        );
    }
    let mut promotion_timeout_ns = None;
    if let Some(slot) = live.persistent_by_source.get_mut(&key) {
        if was_idle {
            slot.activation_saw_completion = false;
            slot.activation_previous_expires_at_ns = slot.expires_at_ns;
            slot.activation_previous_timeout_ns = slot.timeout_ns;
            slot.activation_had_previous_lease = true;
            if policy.refresh_expiry {
                slot.expires_at_ns = now_ns.saturating_add(policy.timeout_ns);
            }
        }
        if slot.imported {
            // Imported leases never adopt the local timeout here:
            // the joining flow carries the promotion marker and a
            // completing `release_flow` applies it. Non-promoting
            // (synced) joins preserve peer origin and carry none.
            if policy.promote_imported {
                promotion_timeout_ns = Some(policy.timeout_ns);
            }
        } else if was_idle && policy.promote_imported {
            slot.timeout_ns = policy.timeout_ns;
        }
        slot.active_flows = slot.active_flows.saturating_add(1);
    }
    JoinOutcome::Joined {
        translated: lease.translated,
        addr_index: lease.addr_index,
        was_idle,
        promotion_timeout_ns,
    }
}

/// #17028: what a successful idle-retire removed, so the caller can
/// free by-mode: a PAT/deterministic lease's `(addr_index, port)`
/// must be freed on the occupancy bitmap; an address-only lease
/// holds no bit (`None` — freeing its preserved port would clear an
/// unrelated PAT flow's bit, #6041).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::nat::allocator) struct RetiredLease {
    pub(in crate::nat::allocator) lease: PersistentLease,
    pub(in crate::nat::allocator) freed_port: Option<(usize, u16)>,
}

fn retired(lease: PersistentLease) -> RetiredLease {
    let freed_port = (!lease.address_only).then_some((lease.addr_index, lease.translated.port));
    RetiredLease { lease, freed_port }
}

/// #17028: retire an idle lease UNCONDITIONALLY on liveness apart
/// (the caller has classified it expired / mode-mismatched-idle /
/// revoked-idle): drop its expiry-index entries, remove it through
/// the one `remove_persistent_lease` seam, and report the port to
/// free. Returns `None` when no lease (any more) sits under `key`.
pub(in crate::nat::allocator) fn retire_idle_lease_locked(
    live: &mut PortAllocatorLiveState,
    key: &PersistentSourceKey,
) -> Option<RetiredLease> {
    let lease = live.persistent_by_source.get(key).copied()?;
    super::PortAllocator::remove_lease_expiration_locked(
        live,
        lease.addr_index,
        lease.expires_at_ns,
        *key,
    );
    live.remove_persistent_lease(key)?;
    Some(retired(lease))
}

/// #17028 (FreeMode::Clocked semantic): retire `key` iff its lease
/// is idle and expired at `now_ns` — or revoked, in which case an
/// idle shell retires regardless of its expiry (`reclaim_expired_
/// idle_lease_locked`'s exact predicate, now shared by the idle-
/// lease import path and both synced joins). Live leases (either
/// flow count non-zero) are never touched.
pub(in crate::nat::allocator) fn reclaim_expired_idle_lease_locked(
    live: &mut PortAllocatorLiveState,
    key: PersistentSourceKey,
    now_ns: u64,
) -> Option<RetiredLease> {
    let lease = live.persistent_by_source.get(&key).copied()?;
    if lease.active_flows != 0
        || lease.inbound_flows != 0
        || (!lease.revoked && lease.expires_at_ns > now_ns)
    {
        return None;
    }
    retire_idle_lease_locked(live, &key)
}
