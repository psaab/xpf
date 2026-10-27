//! #8121 part 2: the coordinator's view of idle persistent-NAT lease sync.
//!
//! Part 1 (`nat::idle_lease_sync_8121`) settled the per-allocator operations and
//! the invariants that make them safe. This layer answers the question those
//! operations cannot: WHICH allocator. A lease with live flows is resolved to a
//! rule through its flow; an idle lease has no flow, so the record has to carry
//! a pool identity of its own.
//!
//! #17099: that identity is typed ([`LeasePoolId`]), not a positional string.
//! A source pool carries its Junos pool name; a NAT64 allocator carries its
//! stable prefix bytes plus its mode (deterministic / round-robin). The legacy
//! wire strings (`nat64-deterministic-{idx}`, `nat64-{idx}`) survive only as
//! display labels and as a decode fallback for records whose typed field is
//! absent — they are never parsed back into a NAT64 identity when a typed
//! field or a real source pool of that name exists. This is the same
//! position-versus-identity hazard part 1 avoids for `addr_index`, one level
//! up: an index means the same allocator only while both nodes hold identical
//! prefix ordering, and an in-band string collides with an operator pool of
//! the same name.
//!
//! The set of allocators that hold persistent leases has ONE definition:
//! [`Coordinator::persistent_lease_pools`]. Export, display, clear and
//! promotion all iterate it; import resolves through
//! [`Coordinator::lease_pool`]. Adding a population edits that one function.

use super::super::monotonic_nanos;
use super::Coordinator;
use crate::nat::{
    DETERMINISTIC_NAT64_BIB_TIMEOUT_NS, DeterministicV6, DisplayLeaseRecord, IdleLeaseImport,
    IdleLeaseRecord, PortAllocator, SourceNatRule,
};
use crate::nat64::Nat64Prefix;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};

/// #17099: stable identity of one persistent-lease allocator population.
///
/// Carried as typed fields on the control wire (`pool_kind` / `nat64_prefix`
/// / `nat64_scope`) so a Junos source pool literally named
/// `nat64-deterministic-0` can never be routed into the NAT64 import arms,
/// and two scoped NAT64 rule-sets sharing one /96 never collapse into one
/// pool. `scope` is the canonical Nat64ScopeKey text (rule-set name plus
/// normalized zone/RI/source scope; see `Nat64ScopeKey::scope_text`).
/// The string form is kept only as a decode fallback for one release
/// (legacy records without the typed field).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum LeasePoolId {
    /// Pool-mode source-NAT allocator, keyed by its Junos pool name.
    /// Explicit (wire kind 1) — never falls through to NAT64.
    Source(String),
    /// Legacy string-only record (wire kind 0): the string may be a source
    /// pool name or a positional NAT64 label; resolved Source-first, then
    /// NAT64, at import. Only this variant may use the legacy parse.
    Legacy(String),
    /// NAT64 allocator, keyed by its stable /96 prefix bytes plus its
    /// scope identity, never by list position.
    Nat64 {
        prefix: [u8; 12],
        scope: String,
        mode: LeasePoolMode,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum LeasePoolMode {
    Deterministic,
    RoundRobin,
}

impl LeasePoolId {
    /// Wire kind code (`IdleLeaseWire.pool_kind` / Go `PoolKind`).
    pub(crate) fn wire_kind(&self) -> u8 {
        match self {
            LeasePoolId::Source(_) => 1,
            LeasePoolId::Legacy(_) => 0,
            LeasePoolId::Nat64 { mode, .. } => match mode {
                LeasePoolMode::Deterministic => 2,
                LeasePoolMode::RoundRobin => 3,
            },
        }
    }

    /// Stable NAT64 prefix text for the wire (`64:ff9b::`), `""` otherwise.
    pub(crate) fn nat64_prefix_text(&self) -> String {
        match self {
            LeasePoolId::Source(_) | LeasePoolId::Legacy(_) => String::new(),
            LeasePoolId::Nat64 { prefix, .. } => {
                let mut octets = [0u8; 16];
                octets[..12].copy_from_slice(prefix);
                Ipv6Addr::from(octets).to_string()
            }
        }
    }

    /// NAT64 scope text for the wire, `""` otherwise.
    pub(crate) fn nat64_scope_text(&self) -> String {
        match self {
            LeasePoolId::Source(_) | LeasePoolId::Legacy(_) => String::new(),
            LeasePoolId::Nat64 { scope, .. } => scope.clone(),
        }
    }
}

/// One allocator population that can hold persistent leases (#17099).
///
/// The single enumeration every verb consumes. `deterministic` is `Some`
pub(crate) struct LeasePool<'a> {
    pub(crate) id: LeasePoolId,
    pub(crate) allocator: &'a PortAllocator,
    pub(crate) deterministic: Option<DeterministicV6>,
    pub(crate) timeout_ns: u64,
    /// Borrow of the first pool-mode rule sharing a source allocator (first
    /// in rule order, matching the historical import `find`). `None` for NAT64.
    pub(crate) source_rule: Option<&'a SourceNatRule>,
    /// Borrow of the NAT64 prefix. `None` for source pools.
    pub(crate) nat64_prefix: Option<&'a Nat64Prefix>,
    /// Positional index of this NAT64 prefix, for the legacy display
    /// label only. Never part of identity or routing.
    pub(crate) nat64_index: usize,
}

impl<'a> LeasePool<'a> {
    /// Legacy/display label for this population.
    pub(crate) fn display_name(&self) -> String {
        match &self.id {
            LeasePoolId::Source(name) | LeasePoolId::Legacy(name) => name.clone(),
            LeasePoolId::Nat64 { mode, .. } => legacy_nat64_label(*mode, self.nat64_index),
        }
    }
}

/// Positional display label for a NAT64 population at `idx`. Kept for SHOW /
/// legacy wire compatibility; identity is the typed `LeasePoolId`.
fn legacy_nat64_label(mode: LeasePoolMode, idx: usize) -> String {
    match mode {
        LeasePoolMode::Deterministic => format!("nat64-deterministic-{idx}"),
        LeasePoolMode::RoundRobin => format!("nat64-{idx}"),
    }
}

/// One idle lease plus the pool it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PoolIdleLease {
    pub(crate) pool: LeasePoolId,
    /// Legacy/display pool label (`pool` on the wire). For source pools this
    /// equals the pool name; for NAT64 it is the positional legacy label.
    /// Import routes on `pool`; this field is filled from `pool` at the wire
    /// boundary and retained for display/sort compatibility.
    pub(crate) pool_name: String,
    pub(crate) lease: IdleLeaseRecord,
}

impl PoolIdleLease {
    pub(crate) fn new(pool: LeasePoolId, pool_name: String, lease: IdleLeaseRecord) -> Self {
        Self {
            pool,
            pool_name,
            lease,
        }
    }
}

/// #8615: a display lease tagged with the pool it belongs to. Separate from
/// `PoolIdleLease` for the same reason its inner record is separate from
/// `IdleLeaseRecord` — the import path must remain unable to receive a count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PoolDisplayLease {
    pub(crate) pool: LeasePoolId,
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
    pub(crate) skipped_clear_fenced: u32,
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

impl IdleLeaseImportCounts {
    /// #17099: the one outcome→count mapping. Every import arm records
    /// through here so the mapping cannot diverge between arms.
    fn record(&mut self, outcome: IdleLeaseImport) {
        match outcome {
            IdleLeaseImport::Installed => self.installed += 1,
            IdleLeaseImport::SkippedClearFenced => self.skipped_clear_fenced += 1,
            IdleLeaseImport::SkippedExisting => self.skipped_existing += 1,
            IdleLeaseImport::SkippedExpired => self.skipped_expired += 1,
            IdleLeaseImport::SkippedUnknownAddress => self.skipped_unknown_address += 1,
            IdleLeaseImport::SkippedPortBusy => self.skipped_port_busy += 1,
            IdleLeaseImport::SkippedIdentityBusy => self.skipped_identity_busy += 1,
            IdleLeaseImport::SkippedCapacity => self.skipped_capacity += 1,
        }
    }
}

impl Coordinator {
    /// #17099: THE persistent-lease allocator population — the single
    /// definition export, display, clear, promotion and import resolution
    /// all consume.
    ///
    /// Source pools are deduplicated by pool name because several rules can
    /// share one allocator (`SourceNatPoolAllocatorKey` is built from the
    /// pool, not the rule); the borrowed `source_rule` is the first such
    /// rule, matching the historical import `find`. NAT64 prefixes are
    /// one allocator each, keyed by stable prefix bytes. Deterministic
    /// prefixes carry their params; round-robin prefixes (#16488/#13946)
    /// are included with `deterministic: None` — gating them out was the
    /// #16488 population gap, now impossible without editing this function.
    pub(crate) fn persistent_lease_pools(&self) -> Vec<LeasePool<'_>> {
        let mut pools: Vec<LeasePool<'_>> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for rule in &self.forwarding.source_nat_rules {
            if !rule.pool_mode || !seen.insert(rule.pool_name.as_str()) {
                continue;
            }
            pools.push(LeasePool {
                id: LeasePoolId::Source(rule.pool_name.clone()),
                allocator: &rule.pool_allocator,
                deterministic: None,
                timeout_ns: rule.persistent_nat_timeout_ns,
                source_rule: Some(rule),
                nat64_prefix: None,
                nat64_index: 0,
            });
        }
        for (idx, prefix) in self.forwarding.nat64.prefixes.iter().enumerate() {
            let mode = if prefix.deterministic_v6.is_some() {
                LeasePoolMode::Deterministic
            } else {
                LeasePoolMode::RoundRobin
            };
            let scope = crate::nat64::Nat64ScopeKey::of_prefix(prefix)
                .scope_text(&prefix.name);
            pools.push(LeasePool {
                id: LeasePoolId::Nat64 {
                    prefix: prefix.prefix_bytes,
                    scope,
                    mode,
                },
                allocator: &prefix.port_allocator,
                deterministic: prefix.deterministic_v6,
                timeout_ns: DETERMINISTIC_NAT64_BIB_TIMEOUT_NS,
                source_rule: None,
                nat64_prefix: Some(prefix),
                nat64_index: idx,
            });
        }
        pools
    }

    /// #17099: resolve a typed identity to its population, for import.
    /// `None` = no allocator on this node owns that identity (import counts
    /// it `skipped_unknown_pool`). A `Legacy` identity is first tried as a
    /// source pool name, then as a positional NAT64 label; an explicit
    /// `Source` identity never reaches the NAT64 parse.
    pub(crate) fn lease_pool(&self, id: &LeasePoolId) -> Option<LeasePool<'_>> {
        match id {
            LeasePoolId::Legacy(name) => {
                if let Some(pool) = self
                    .persistent_lease_pools()
                    .into_iter()
                    .find(|pool| pool.id == LeasePoolId::Source(name.clone()))
                {
                    return Some(pool);
                }
                self.legacy_nat64_pool(name)
            }
            _ => self
                .persistent_lease_pools()
                .into_iter()
                .find(|pool| &pool.id == id),
        }
    }

    /// Legacy decode fallback: resolve an in-band `nat64-…-{idx}` string to
    /// a NAT64 population. Used ONLY for `Legacy` records (one-release wire
    /// compatibility).
    fn legacy_nat64_pool(&self, pool_name: &str) -> Option<LeasePool<'_>> {
        let (idx, mode) = if let Some(s) = pool_name.strip_prefix("nat64-deterministic-") {
            (s.parse::<usize>().ok()?, LeasePoolMode::Deterministic)
        } else if let Some(rest) = pool_name.strip_prefix("nat64-") {
            if rest.starts_with("deterministic-") {
                return None;
            }
            (rest.parse::<usize>().ok()?, LeasePoolMode::RoundRobin)
        } else {
            return None;
        };
        self.persistent_lease_pools().into_iter().find(|pool| {
            pool.nat64_index == idx
                && matches!(&pool.id, LeasePoolId::Nat64 { mode: m, .. } if *m == mode)
        })
    }

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
    /// Import a batch after the Go control plane has durably validated its
    /// origin generation. Per-key clear tombstones still apply.
    pub(crate) fn import_idle_persistent_leases_after_generation_now(
        &self,
        records: &[PoolIdleLease],
    ) -> IdleLeaseImportCounts {
        self.import_idle_persistent_leases_inner(records, monotonic_nanos(), true)
    }

    /// Every idle lease this node holds, tagged with its pool.
    ///
    /// #10789-F4: the allocator export is local-origin only while this node
    /// is a standby. Once every group in the configured HA inventory is
    /// forwarding-active, imported leases are promoted and eligible for
    /// re-export.
    pub(crate) fn export_idle_persistent_leases(&self, now_ns: u64) -> Vec<PoolIdleLease> {
        let mut out = Vec::new();
        for pool in self.persistent_lease_pools() {
            for mut lease in pool.allocator.export_idle_leases(now_ns) {
                let pool_name = pool.display_name();
                if let Some(params) = pool.deterministic {
                    lease.deterministic = true;
                    lease.deterministic_identity =
                        Some(crate::nat::DeterministicPortedIdentity::V6(params));
                }
                out.push(PoolIdleLease {
                    pool: pool.id.clone(),
                    pool_name,
                    lease,
                });
            }
        }
        out
    }

    /// #16876: primary activation transfers this node's imported persistent
    /// leases to local ownership. Iterates the single population (#17099).
    pub(crate) fn promote_imported_persistent_nat_leases(&self) {
        for pool in self.persistent_lease_pools() {
            pool.allocator.promote_imported_persistent_leases();
        }
    }

    /// #8615: every persistent lease this node would honour, tagged with its
    /// pool, for the SHOW table.
    pub(crate) fn export_display_persistent_leases(&self, now_ns: u64) -> Vec<PoolDisplayLease> {
        let mut out = Vec::new();
        for pool in self.persistent_lease_pools() {
            for mut lease in pool.allocator.export_display_leases(now_ns) {
                let pool_name = pool.display_name();
                if let Some(params) = pool.deterministic {
                    lease.deterministic = true;
                    lease.deterministic_identity =
                        Some(crate::nat::DeterministicPortedIdentity::V6(params));
                }
                out.push(PoolDisplayLease {
                    pool: pool.id.clone(),
                    pool_name,
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

    /// Revoke every persistent source-NAT lease owned by the current
    /// forwarding snapshot. Shared pool allocators are cleared exactly once
    /// (the population deduplicates them, #17099).
    pub(crate) fn clear_persistent_nat_leases(&self) -> usize {
        let now_ns = monotonic_nanos();
        let mut cleared = 0;
        for pool in self.persistent_lease_pools() {
            cleared += pool.allocator.clear_persistent_leases(now_ns);
        }
        cleared
    }

    /// Install a batch of peer idle leases.
    /// Imported records are additive reservations only; an empty or shorter
    /// batch never removes leases already installed on this node.
    pub(crate) fn import_idle_persistent_leases(
        &self,
        records: &[PoolIdleLease],
        now_ns: u64,
    ) -> IdleLeaseImportCounts {
        self.import_idle_persistent_leases_inner(records, now_ns, false)
    }

    fn import_idle_persistent_leases_inner(
        &self,
        records: &[PoolIdleLease],
        now_ns: u64,
        generation_validated: bool,
    ) -> IdleLeaseImportCounts {
        let mut counts = IdleLeaseImportCounts::default();
        let mut imported_to_promote: Vec<(&PortAllocator, &IdleLeaseRecord)> = Vec::new();
        for rec in records {
            // #17099: route on the typed identity. Explicit Source (kind 1)
            // resolves source-or-unknown and NEVER falls through to NAT64;
            // only Legacy (kind 0) records may use the Source-first then
            // positional NAT64 fallback. Nat64 resolves by prefix+scope+mode.
            let resolved: Option<LeasePool<'_>> = self.lease_pool(&rec.pool);
            let Some(pool) = resolved else {
                // Deterministic-shaped records under unknown pools keep the
                // #14638 identity-busy posture handled below only when a
                // source pool exists; an entirely unknown identity is an
                // unknown pool.
                counts.skipped_unknown_pool += 1;
                continue;
            };
            match pool.id.clone() {
                LeasePoolId::Nat64 {
                    mode: LeasePoolMode::Deterministic,
                    ..
                } => {
                    let prefix = pool.nat64_prefix.expect("NAT64 pool carries prefix");
                    let params = pool
                        .deterministic
                        .expect("deterministic pool carries params");
                    if !rec.lease.deterministic
                        || rec.lease.deterministic_identity
                            != Some(crate::nat::DeterministicPortedIdentity::V6(params))
                    {
                        counts.skipped_identity_busy += 1;
                        continue;
                    }
                    let (IpAddr::V6(src), IpAddr::V4(translated)) =
                        (rec.lease.src_ip, rec.lease.translated_ip)
                    else {
                        counts.skipped_identity_busy += 1;
                        continue;
                    };
                    let addr_index = prefix.pool_v4.iter().position(|a| *a == translated);
                    let Some(idx) = addr_index else {
                        counts.skipped_unknown_address += 1;
                        continue;
                    };
                    if !prefix.port_allocator.deterministic_v6_tuple_matches(
                        params,
                        src,
                        &prefix.pool_v4,
                        idx,
                        translated,
                        rec.lease.translated_port,
                    ) {
                        counts.skipped_identity_busy += 1;
                        continue;
                    }
                    let outcome = if generation_validated {
                        prefix
                            .port_allocator
                            .import_idle_lease_at_after_generation_permit_any(
                                &rec.lease,
                                addr_index,
                                pool.timeout_ns,
                                now_ns,
                            )
                    } else {
                        prefix.port_allocator.import_idle_lease_at(
                            &rec.lease,
                            addr_index,
                            pool.timeout_ns,
                            now_ns,
                        )
                    };
                    let installed = matches!(outcome, IdleLeaseImport::Installed);
                    counts.record(outcome);
                    if installed {
                        imported_to_promote.push((&prefix.port_allocator, &rec.lease));
                    }
                    continue;
                }
                LeasePoolId::Nat64 {
                    mode: LeasePoolMode::RoundRobin,
                    ..
                } => {
                    // #16488: round-robin NAT64 BIB import. Validate the
                    // tuple against the LIVE prefix (pool membership, the
                    // allocator's port range) and refuse identities a
                    // peer/static/interface owner already holds, then
                    // install through the allocator so the clear fence
                    // applies exactly as for deterministic/SNAT leases.
                    let prefix = pool.nat64_prefix.expect("NAT64 pool carries prefix");
                    if rec.lease.deterministic || rec.lease.deterministic_identity.is_some() {
                        counts.skipped_identity_busy += 1;
                        continue;
                    }
                    // A round-robin BIB is AnyRemoteHost by construction
                    // (#13946); a record that does not claim the wildcard
                    // is not a NAT64 BIB export.
                    if !rec.lease.permit_any_remote {
                        counts.skipped_identity_busy += 1;
                        continue;
                    }
                    let (IpAddr::V6(_src), IpAddr::V4(translated)) =
                        (rec.lease.src_ip, rec.lease.translated_ip)
                    else {
                        counts.skipped_identity_busy += 1;
                        continue;
                    };
                    let addr_index = prefix.pool_v4.iter().position(|a| *a == translated);
                    let Some(idx) = addr_index else {
                        counts.skipped_unknown_address += 1;
                        continue;
                    };
                    if rec.lease.translated_port < prefix.port_allocator.port_low
                        || rec.lease.translated_port > prefix.port_allocator.port_high
                    {
                        counts.skipped_identity_busy += 1;
                        continue;
                    }
                    if crate::nat::static_owns_wire_identity(
                        prefix.static_externals.as_deref(),
                        IpAddr::V4(translated),
                        rec.lease.translated_port,
                    ) {
                        counts.skipped_identity_busy += 1;
                        continue;
                    }
                    // Pre-claim peer/interface fast path (advisory; the
                    // post-claim recheck below closes the race).
                    if crate::nat::nat64_peer_or_interface_owns_idle_import(
                        prefix,
                        rec.lease.protocol,
                        IpAddr::V4(translated),
                        rec.lease.translated_port,
                    ) {
                        counts.skipped_identity_busy += 1;
                        continue;
                    }
                    if let Some(ia) = prefix.iface_allocs.as_deref() {
                        if crate::nat::iface_peer_idle_any_contended(
                            ia,
                            rec.lease.protocol,
                            crate::nat::TranslatedTuple {
                                ip: IpAddr::V4(translated),
                                port: rec.lease.translated_port,
                            },
                        ) {
                            counts.skipped_identity_busy += 1;
                            continue;
                        }
                    }
                    let outcome = if generation_validated {
                        prefix
                            .port_allocator
                            .import_idle_lease_at_after_generation_permit_any(
                                &rec.lease,
                                addr_index,
                                pool.timeout_ns,
                                now_ns,
                            )
                    } else {
                        prefix.port_allocator.import_idle_lease_at(
                            &rec.lease,
                            addr_index,
                            pool.timeout_ns,
                            now_ns,
                        )
                    };
                    // Post-claim recheck: a racing peer/static/interface
                    // mint may have published the same wire identity while
                    // we claimed ours. Roll our claim back rather than
                    // publish a duplicate (the SNAT path's posture).
                    if matches!(outcome, IdleLeaseImport::Installed) {
                        let peer_now = crate::nat::nat64_peer_or_interface_owns_idle_import(
                            prefix,
                            rec.lease.protocol,
                            IpAddr::V4(translated),
                            rec.lease.translated_port,
                        );
                        let static_now = crate::nat::static_owns_wire_identity(
                            prefix.static_externals.as_deref(),
                            IpAddr::V4(translated),
                            rec.lease.translated_port,
                        );
                        let iface_now = prefix.iface_allocs.as_deref().is_some_and(|ia| {
                            crate::nat::iface_peer_idle_any_contended(
                                ia,
                                rec.lease.protocol,
                                crate::nat::TranslatedTuple {
                                    ip: IpAddr::V4(translated),
                                    port: rec.lease.translated_port,
                                },
                            )
                        });
                        if (peer_now || static_now || iface_now)
                            && crate::nat::nat64_rollback_idle_import(prefix, &rec.lease)
                        {
                            counts.skipped_identity_busy += 1;
                            continue;
                        }
                    }
                    let installed = matches!(outcome, IdleLeaseImport::Installed);
                    counts.record(outcome);
                    if installed {
                        imported_to_promote.push((&prefix.port_allocator, &rec.lease));
                    }
                    continue;
                }
                LeasePoolId::Source(_) | LeasePoolId::Legacy(_) => {
                    // #14638 remaining validation: a deterministic-shaped lease must
                    // never install through the generic source-NAT path as a dynamic
                    // lease. Only the NAT64 deterministic arm above may install
                    // one, and only after its identity/tuple gates pass.
                    if rec.lease.deterministic || rec.lease.deterministic_identity.is_some() {
                        counts.skipped_identity_busy += 1;
                        continue;
                    }
                    let rule = pool.source_rule.expect("source pool carries rule");
                    // Fast path only: skip records a stable peer already owns before
                    // touching this allocator. Racy peer mints are settled by the
                    // allocator's post-claim recheck, which rolls our claim back.
                    let lease = &rec.lease;
                    if rule.peer_holds_idle_import_identity(
                        lease.protocol,
                        lease.translated_ip,
                        lease.translated_port,
                        lease.remote,
                        lease.address_only,
                    ) {
                        counts.skipped_identity_busy += 1;
                        continue;
                    }
                    // #16017 fold 3: generation validation proves provenance, not
                    // local permit consent. The wildcard is authorized only when a
                    // rule sharing this allocator permits AnyRemoteHost under the
                    // record's scope; otherwise the import installs demoted and a
                    // later sync under an AnyRemoteHost rule restamps it.
                    let permit_any_authorized = self
                        .forwarding
                        .source_nat_rules
                        .iter()
                        .filter(|candidate| {
                            candidate.pool_mode
                                && candidate.persistent_nat
                                && candidate
                                    .pool_allocator
                                    .same_allocator(&rule.pool_allocator)
                        })
                        .any(|candidate| {
                            candidate.persistent_nat_permit
                                == crate::nat::PersistentNatPermit::AnyRemoteHost
                                && candidate.persistent_rule_scope(
                                    &candidate.from_zone.clone(),
                                    &candidate.to_zone.clone(),
                                    &candidate.to_zone.clone(),
                                    &crate::nat::NatScopeCtx::default(),
                                ) == lease.egress_scope
                        });
                    let outcome = if generation_validated {
                        if permit_any_authorized {
                            rule.pool_allocator
                                .import_idle_lease_at_after_generation_permit_any(
                                    lease,
                                    rule.pool_index_of(lease.translated_ip),
                                    rule.persistent_nat_timeout_ns,
                                    now_ns,
                                )
                        } else {
                            rule.pool_allocator.import_idle_lease_at_after_generation(
                                lease,
                                rule.pool_index_of(lease.translated_ip),
                                rule.persistent_nat_timeout_ns,
                                now_ns,
                            )
                        }
                    } else {
                        rule.pool_allocator.import_idle_lease_with_permit(
                            lease,
                            rule.pool_index_of(lease.translated_ip),
                            rule.persistent_nat_timeout_ns,
                            now_ns,
                            permit_any_authorized,
                        )
                    };
                    if matches!(outcome, IdleLeaseImport::Installed)
                        && rule.peer_holds_idle_import_identity(
                            lease.protocol,
                            lease.translated_ip,
                            lease.translated_port,
                            lease.remote,
                            lease.address_only,
                        )
                        && rule.rollback_idle_lease_import(lease)
                    {
                        counts.skipped_identity_busy += 1;
                        continue;
                    }
                    let installed = matches!(outcome, IdleLeaseImport::Installed);
                    counts.record(outcome);
                    if installed {
                        imported_to_promote.push((&rule.pool_allocator, &rec.lease));
                    }
                    continue;
                }
            }
        }
        // A generation batch can arrive after this node became primary.
        // Promote only records this batch actually installed; a refused or
        // partial batch must not sweep unrelated peer-owned entries.
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let local_groups = self.ha.rg_runtime.load();
        if !local_groups.is_empty()
            && local_groups
                .values()
                .all(|group| group.is_forwarding_active(now_secs))
        {
            for (allocator, record) in imported_to_promote {
                allocator.promote_imported_persistent_lease_record(record);
            }
        }
        counts
    }
}

#[cfg(test)]
#[path = "idle_lease_sync_8121_tests.rs"]
mod tests;
