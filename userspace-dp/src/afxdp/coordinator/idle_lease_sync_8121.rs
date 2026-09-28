//! #8121 part 2: the coordinator's view of idle persistent-NAT lease sync.
//!
//! Part 1 (`nat::idle_lease_sync_8121`) settled the per-allocator operations and
//! the invariants that make them safe. This layer answers the question those
//! operations cannot: WHICH allocator. A lease with live flows is resolved to a
//! rule through its flow; an idle lease has no flow, so the record has to carry
//! a pool identity of its own.
//!
//! It carries `pool_name` — the same component `SourceNatPoolAllocatorKey` is
//! built from, and stable across the pair because HA requires identical config.
//! It is deliberately NOT an index into the rule list: that is the same
//! position-versus-identity hazard part 1 avoids for `addr_index`, one level up.

use super::super::monotonic_nanos;
use super::Coordinator;
use crate::nat::{DisplayLeaseRecord, IdleLeaseImport, IdleLeaseRecord};
use std::collections::HashSet;
use std::net::IpAddr;

/// One idle lease plus the pool it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PoolIdleLease {
    pub(crate) pool_name: String,
    pub(crate) lease: IdleLeaseRecord,
}

/// #8615: a display lease tagged with the pool it belongs to. Separate from
/// `PoolIdleLease` for the same reason its inner record is separate from
/// `IdleLeaseRecord` — the import path must remain unable to receive a count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PoolDisplayLease {
    pub(crate) pool_name: String,
    pub(crate) lease: DisplayLeaseRecord,
}

/// What one import batch did. Counted rather than logged per record: a batch
/// runs on every sync push, and a per-record log on a bulk window is the
/// control-socket noise CLAUDE.md's logging rules exist to prevent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IdleLeaseImportCounts {
    pub(crate) installed: u32,
    pub(crate) skipped_existing: u32,
    pub(crate) skipped_expired: u32,
    pub(crate) skipped_unknown_address: u32,
    pub(crate) skipped_port_busy: u32,
    pub(crate) skipped_identity_busy: u32,
    pub(crate) skipped_capacity: u32,
    /// No rule on this node owns a pool by that name. Distinct from
    /// `skipped_unknown_address`: the pool is missing entirely rather than
    /// present with a different address list, which is what a config that has
    /// not converged yet looks like.
    pub(crate) skipped_unknown_pool: u32,
}

impl Coordinator {
    /// Export using THIS node's clock.
    ///
    /// The clock is taken here rather than passed in, so no caller can hand the
    /// lease path a peer's `CLOCK_MONOTONIC` value by accident — the property
    /// part 1 depends on becomes structural rather than a convention. The
    /// `now_ns` forms below stay for tests, which need to drive time.
    pub(crate) fn export_idle_persistent_leases_now(&self) -> Vec<PoolIdleLease> {
        self.export_idle_persistent_leases(monotonic_nanos())
    }

    /// Import using THIS node's clock. See `export_idle_persistent_leases_now`.
    pub(crate) fn import_idle_persistent_leases_now(
        &self,
        records: &[PoolIdleLease],
    ) -> IdleLeaseImportCounts {
        self.import_idle_persistent_leases(records, monotonic_nanos())
    }

    /// Every idle lease this node holds, tagged with its pool.
    ///
    /// Deduplicated by pool name because several rules can share one allocator
    /// (`SourceNatPoolAllocatorKey` is built from the pool, not the rule), and
    /// exporting once per RULE would send the same lease as many times as there
    /// are rules pointing at that pool.
    /// #10789-F4: the allocator export is local-origin only. Imported idle
    /// leases are not echoed; the coordinator neither retracts records missing
    /// from a later push nor carries tombstones for early retirement.
    pub(crate) fn export_idle_persistent_leases(&self, now_ns: u64) -> Vec<PoolIdleLease> {
        let mut seen: HashSet<&str> = HashSet::new();
        let mut out = Vec::new();
        for rule in &self.forwarding.source_nat_rules {
            if !rule.pool_mode || !seen.insert(rule.pool_name.as_str()) {
                continue;
            }
            for lease in rule.pool_allocator.export_idle_leases(now_ns) {
                out.push(PoolIdleLease {
                    pool_name: rule.pool_name.clone(),
                    lease,
                });
            }
        }
        out
    }

    /// #8615: every persistent lease this node would honour, tagged with its
    /// pool, for the SHOW table.
    ///
    /// Deduplicated by pool name for the same reason the idle export is:
    /// several rules can share one allocator (`SourceNatPoolAllocatorKey` is
    /// built from the pool, not the rule), so iterating RULES would emit the
    /// same lease once per rule pointing at that pool.
    pub(crate) fn export_display_persistent_leases(&self, now_ns: u64) -> Vec<PoolDisplayLease> {
        let mut seen: HashSet<&str> = HashSet::new();
        let mut out = Vec::new();
        for rule in &self.forwarding.source_nat_rules {
            if !rule.pool_mode || !seen.insert(rule.pool_name.as_str()) {
                continue;
            }
            for lease in rule.pool_allocator.export_display_leases(now_ns) {
                out.push(PoolDisplayLease {
                    pool_name: rule.pool_name.clone(),
                    lease,
                });
            }
        }
        out
    }

    /// Export using THIS node's clock — see `export_idle_persistent_leases_now`
    /// for why the clock is taken here rather than accepted from a caller.
    pub(crate) fn export_display_persistent_leases_now(&self) -> Vec<PoolDisplayLease> {
        self.export_display_persistent_leases(monotonic_nanos())
    }

    /// Install a batch of peer idle leases.
    /// Imported records are additive reservations only; an empty or shorter
    /// batch never removes leases already installed on this node.
    pub(crate) fn import_idle_persistent_leases(
        &self,
        records: &[PoolIdleLease],
        now_ns: u64,
    ) -> IdleLeaseImportCounts {
        let mut counts = IdleLeaseImportCounts::default();
        for rec in records {
            let Some(rule) = self
                .forwarding
                .source_nat_rules
                .iter()
                .find(|r| r.pool_mode && r.pool_name == rec.pool_name)
            else {
                counts.skipped_unknown_pool += 1;
                continue;
            };
            // This node's OWN pool order — the record carries an address, and
            // the index is resolved here (part 1, module note 3).
            let addrs: Vec<IpAddr> = rule
                .pool_addresses_v4
                .iter()
                .copied()
                .map(IpAddr::V4)
                .chain(rule.pool_addresses_v6.iter().copied().map(IpAddr::V6))
                .collect();
            match rule
                .pool_allocator
                .import_idle_lease(&rec.lease, &addrs, rule.persistent_nat_timeout_ns, now_ns)
            {
                IdleLeaseImport::Installed => counts.installed += 1,
                IdleLeaseImport::SkippedExisting => counts.skipped_existing += 1,
                IdleLeaseImport::SkippedExpired => counts.skipped_expired += 1,
                IdleLeaseImport::SkippedUnknownAddress => counts.skipped_unknown_address += 1,
                IdleLeaseImport::SkippedPortBusy => counts.skipped_port_busy += 1,
                IdleLeaseImport::SkippedIdentityBusy => counts.skipped_identity_busy += 1,
                IdleLeaseImport::SkippedCapacity => counts.skipped_capacity += 1,
            }
        }
        counts
    }
}

#[cfg(test)]
#[path = "idle_lease_sync_8121_tests.rs"]
mod tests;
