//! #8121: export/import for an IDLE persistent-NAT lease.
//!
//! #7360 reconstructs a persistent lease on the standby by deriving it from the
//! synced sessions that hold it. That reaches every lease with live flows —
//! which is every lease session sync can observe, since a lease is learned FROM
//! a session. An idle lease (`active_flows == 0`, `expires_at_ns > now_ns`) has
//! no session to be derived from, yet on the active node it is still live and
//! still reusable: `reuse_existing_lease_locked` admits it on
//! `active_flows > 0 || expires_at_ns > now_ns`. That population is what this
//! module carries.
//!
//! # Four things a lease record must not do
//!
//! 1. **Never carry `active_flows`.** The standby installs a strict SUBSET of
//!    what the active sends (#6600 `RejectedReserve`, #5674 `RejectedCapacity`,
//!    #2170 stale-generation, #7188's discriminator withhold). A carried count
//!    credits the lease for sessions this node does not hold, so it never
//!    reaches zero, never enters `lease_expirations`, and no GC path can
//!    reclaim it. An imported idle lease starts at 0 — legitimately, which is
//!    what makes this a different record shape rather than an extension of the
//!    session one.
//!
//!    #8615 needs that count for the SHOW table and does NOT relax this rule:
//!    it adds a SEPARATE `DisplayLeaseRecord` / `DisplayLeaseWire` with its own
//!    one-way verb, and no conversion into `IdleLeaseRecord` exists. So the
//!    count is not merely unused on the import path — it is unrepresentable
//!    there, which is the difference between a rule and a convention.
//!
//! 2. **Never carry `expires_at_ns` verbatim.** It is derived from
//!    `monotonic_nanos()` (`CLOCK_MONOTONIC`), which is boot-relative and
//!    node-local: a node up ten days reads a value sent by a node up one hour
//!    as long expired. The record carries REMAINING lifetime and the receiver
//!    computes `now_ns + remaining_ns` — the #7095 hazard class.
//!
//! 3. **Never carry `addr_index`.** It is a POSITION in the pool address list,
//!    and the same position is the same address only while both nodes hold
//!    identical pool ordering. The record carries the translated ADDRESS and
//!    the receiver resolves the index locally, refusing a lease whose address
//!    its own pool does not contain. Same hazard class as 2, one level over.
//!
//! 4. **Never install a lease without claiming its port.** An idle lease still
//!    HOLDS its occupancy bit — the bit is freed on the EXPIRY path
//!    (`free_translated_port` in `reuse_existing_lease_locked`'s expired arm),
//!    not when the last flow closes, which is precisely why the tuple is still
//!    reusable. Installing the lease without the bit would let a local flow
//!    mint the same `(address, port)` — the duplicate translated identity this
//!    allocator exists to prevent — and would then have the lease's own expiry
//!    free a bit belonging to that other flow. So the import claims the bit and
//!    REFUSES the lease if it cannot.

// PART 1 OF #8121. This is the helper core — the two operations and every
// invariant that makes them safe. Nothing calls it yet: the cluster transport
// that drives it (a `syncMsgPersistentNatLease` record type in `pkg/cluster`,
// plus the control-socket commands that reach these two methods) is part 2, and
// #8121 stays OPEN until it lands.
//
// The split is deliberate rather than convenient. Every hazard in this feature
// lives HERE — the local refcount, the two node-local quantities that must not
// be carried, and the occupancy bit — and each one is now pinned by a
// mutation-bound test. A transport built on an unsettled core would have to be
// re-reviewed when the core moved.
#![allow(dead_code)]

use super::allocator::{PersistentLease, PersistentSourceKey, PortAllocator, TranslatedTuple};
use std::net::IpAddr;

/// One idle lease, in the shape a peer can act on: identity and lifetime only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IdleLeaseRecord {
    pub(crate) protocol: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) src_port: u16,
    /// #10018: source-identity lease reuse is partitioned by routing domain,
    /// while the allocator's translated `(address, port)` occupancy remains
    /// shared across tenants. This value must cross the idle-lease channel;
    /// dropping it would make the standby merge two VRFs back into one lease.
    pub(crate) routing_scope: u32,
    /// `None` => `permit-any-remote-host`; `Some` => bound to that remote.
    pub(crate) remote: Option<(IpAddr, u16)>,
    /// The translated ADDRESS, never the pool index (see module note 3).
    pub(crate) translated_ip: IpAddr,
    pub(crate) translated_port: u16,
    /// #6041: an address-only lease owns no occupancy bit.
    pub(crate) address_only: bool,
    /// REMAINING lifetime, never an absolute deadline (see module note 2).
    pub(crate) remaining_ns: u64,
    pub(crate) timeout_ns: u64,
}

/// #8615: one persistent lease as the SHOW table needs it — identity, lifetime,
/// AND the live-flow count.
///
/// Deliberately NOT an extension of `IdleLeaseRecord`, and deliberately without
/// a conversion into it. `IdleLeaseRecord` is what a peer can IMPORT, and
/// design note 1 forbids carrying `active_flows` on that record for a reason
/// that has nothing to do with display. Keeping the two types separate is what
/// makes the rule structural: there is no widening of the import record to
/// review, and no path by which a count can arrive at `import_idle_lease`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DisplayLeaseRecord {
    pub(crate) protocol: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) src_port: u16,
    /// #10018: display rows retain the lease's routing domain too, so the
    /// operator can distinguish overlapping subscriber identities.
    pub(crate) routing_scope: u32,
    /// `None` => `permit-any-remote-host`; `Some` => bound to that remote.
    pub(crate) remote: Option<(IpAddr, u16)>,
    pub(crate) translated_ip: IpAddr,
    pub(crate) translated_port: u16,
    pub(crate) address_only: bool,
    /// RAW remaining lifetime. Meaningful only when `active_flows == 0`; see
    /// `export_display_leases`.
    pub(crate) remaining_ns: u64,
    pub(crate) timeout_ns: u64,
    /// The whole reason this record exists. Never sent to a peer.
    pub(crate) active_flows: u32,
}

/// What an import did. Every refusal is named rather than folded into a bool,
/// because they have different operator remedies: a busy port means the two
/// nodes disagree about who owns an identity, while an unknown address just
/// means config has not converged yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdleLeaseImport {
    Installed,
    /// A lease already exists for this source. The LOCAL one wins — it may hold
    /// live flows this node is forwarding, and those outrank a remote idle
    /// record by definition.
    SkippedExisting,
    /// Already expired by the time it arrived (or sent with no lifetime left).
    SkippedExpired,
    /// This node's pool does not contain the translated address.
    SkippedUnknownAddress,
    /// The occupancy bit is already held here, so installing the lease would
    /// duplicate a translated identity (module note 4).
    SkippedPortBusy,
}

impl PortAllocator {
    /// Every lease that is idle AND still inside its persistence timeout — the
    /// population #7360 cannot reach. A lease with live flows is deliberately
    /// NOT exported: the peer rebuilds it from the sessions themselves, and
    /// sending both would race two mechanisms onto one key.
    pub(crate) fn export_idle_leases(&self, now_ns: u64) -> Vec<IdleLeaseRecord> {
        let live = self.lock_live();
        live.persistent_by_source
            .iter()
            .filter(|(_, lease)| lease.active_flows == 0 && lease.expires_at_ns > now_ns)
            .map(|(key, lease)| IdleLeaseRecord {
                protocol: key.protocol,
                src_ip: key.src_ip,
                src_port: key.src_port,
                routing_scope: key.routing_scope,
                remote: key.remote,
                translated_ip: lease.translated.ip,
                translated_port: lease.translated.port,
                address_only: lease.address_only,
                remaining_ns: lease.expires_at_ns.saturating_sub(now_ns),
                timeout_ns: lease.timeout_ns,
            })
            .collect()
    }

    /// #8615: every persistent lease this node would HONOUR, for DISPLAY only.
    ///
    /// The filter is `reuse_existing_lease_locked`'s own admission predicate —
    /// `active_flows > 0 || expires_at_ns > now_ns` (`allocator.rs:2020`) — so
    /// the table answers exactly "which bindings will this node reuse", rather
    /// than a separate notion of liveness that could disagree with the
    /// allocator's.
    ///
    /// THIS RECORD MUST NEVER REACH THE SYNC PATH. It carries `active_flows`,
    /// which this module's design note 1 forbids on the record a peer imports:
    /// the standby installs a strict SUBSET, so a carried count credits a lease
    /// for sessions that node does not hold, it never reaches zero, never
    /// enters `lease_expirations`, and no GC path can reclaim it. That rule is
    /// about the record an IMPORT can receive. It is kept true here by keeping
    /// the two record types DISTINCT rather than by discipline at call sites:
    /// `import_idle_lease` takes an `IdleLeaseRecord`, and no conversion from
    /// this type to that one exists, so the count is not merely unused on the
    /// import path — it is unrepresentable there.
    pub(crate) fn export_display_leases(&self, now_ns: u64) -> Vec<DisplayLeaseRecord> {
        let live = self.lock_live();
        live.persistent_by_source
            .iter()
            .filter(|(_, lease)| lease.active_flows > 0 || lease.expires_at_ns > now_ns)
            .map(|(key, lease)| DisplayLeaseRecord {
                protocol: key.protocol,
                src_ip: key.src_ip,
                src_port: key.src_port,
                routing_scope: key.routing_scope,
                remote: key.remote,
                translated_ip: lease.translated.ip,
                translated_port: lease.translated.port,
                address_only: lease.address_only,
                // RAW remaining, not a display decision. While
                // `active_flows > 0` this is routinely 0 or negative-clamped,
                // because `expires_at_ns` was last written at the most recent
                // reuse and is NOT refreshed per packet — the countdown only
                // (re)starts when the last flow closes
                // (`allocator.rs:2246-2250`). Interpreting that is the
                // presentation layer's job and is done there; carrying a
                // pre-interpreted number would make the wire disagree with the
                // allocator it is reporting on.
                remaining_ns: lease.expires_at_ns.saturating_sub(now_ns),
                timeout_ns: lease.timeout_ns,
                active_flows: lease.active_flows,
            })
            .collect()
    }

    /// Install one exported idle lease. `pool_addresses` is this node's pool
    /// for the owning rule, in its own order — the record's address is resolved
    /// against it rather than trusting a carried index.
    pub(crate) fn import_idle_lease(
        &self,
        rec: &IdleLeaseRecord,
        pool_addresses: &[IpAddr],
        now_ns: u64,
    ) -> IdleLeaseImport {
        if rec.remaining_ns == 0 {
            return IdleLeaseImport::SkippedExpired;
        }
        let Some(addr_index) = pool_addresses.iter().position(|a| *a == rec.translated_ip) else {
            return IdleLeaseImport::SkippedUnknownAddress;
        };
        let key = PersistentSourceKey {
            protocol: rec.protocol,
            src_ip: rec.src_ip,
            src_port: rec.src_port,
            routing_scope: rec.routing_scope,
            remote: rec.remote,
        };
        let mut live = self.lock_live();
        if live.persistent_by_source.contains_key(&key) {
            return IdleLeaseImport::SkippedExisting;
        }
        // Module note 4: take the occupancy bit BEFORE installing, and refuse
        // rather than install a lease over an identity someone else holds.
        if !rec.address_only {
            match self.try_claim_translated_port(addr_index, rec.translated_port) {
                None => return IdleLeaseImport::SkippedUnknownAddress,
                Some(false) => return IdleLeaseImport::SkippedPortBusy,
                Some(true) => {}
            }
        }
        let expires_at_ns = now_ns.saturating_add(rec.remaining_ns);
        live.persistent_by_source.insert(
            key,
            PersistentLease {
                translated: TranslatedTuple {
                    ip: rec.translated_ip,
                    port: rec.translated_port,
                },
                addr_index,
                expires_at_ns,
                timeout_ns: rec.timeout_ns,
                // Module note 1: rebuilt locally, and legitimately zero here.
                active_flows: 0,
                completed_flows: 0,
                activation_saw_completion: false,
                activation_previous_expires_at_ns: 0,
                activation_had_previous_lease: false,
                address_only: rec.address_only,
            },
        );
        // Without this the lease is invisible to GC and outlives what the
        // active held — the acceptance criterion's third bullet.
        PortAllocator::insert_lease_expiration_locked(&mut live, addr_index, expires_at_ns, key);
        IdleLeaseImport::Installed
    }
}
