// Source NAT (SNAT) rules + matching + lookup.
//
// Owns rule parsing from snapshots, the address/port-pool match
// pipeline, and the public release/rollback entry points that
// drive the allocator. Pool ownership / persistent lease state
// machine lives in the sibling allocator.rs.
//
// #3111: pool-mode SNAT only allocates/translates an L4 port for
// protocols that actually carry one (TCP/UDP, via
// `crate::ip_proto::has_l4_ports`). A port-less protocol
// (GRE/ESP/AH/OSPF/ICMP/...) gets IP-only translation — no pool port
// is consumed and `rewrite_src_port` is left unset, so the packet
// rewriters never overwrite its first two L4 bytes (GRE flags / ESP
// SPI). The out-of-band `None` protocol (#5687) is the "L4 tuple unknown"
// signal used by the address-only `match_source_nat` callers; it keeps its
// historical round-robin `try_next_port` behavior (never frame-written,
// because the rewriters gate every L4 write on `has_l4_ports`). A genuine
// IPv4 protocol 0 (HOPOPT) arrives as `Some(0)` and is NOT the sentinel —
// it takes the real port-less address-only path and its reverse tuple is
// matchable.
//
// #5269: the address-only branch (`port no-translation` on a port-bearing
// protocol, or a port-less protocol) selects a pool address but PRESERVES the
// source port on the wire, so — unlike PAT — it cannot make the translated
// `(pool_addr, port)` unique by handing out a fresh port. It therefore MINTS an
// occupancy token via `PortAllocator::reserve_address_only`, keyed on the
// translated REVERSE identity (protocol, pool address, preserved source port,
// remote endpoint). The first flow to claim an identity owns it; a genuinely-
// colliding second flow (same identity) is DENIED as exhaustion
// (`AllocatorExhausted` -> `SourceNatLookup::Unavailable` -> the same drop /
// `nat_alloc_fail` path a full port-translating pool takes) rather than
// receiving an unowned duplicate whose replies the reverse (1:N) index cannot
// disambiguate — the vSRX address-only / persistent capacity limit. A non-
// colliding flow (different preserved port, pool address, or remote) mints its
// own token and succeeds. The token is freed by the SAME teardown path as a PAT
// port (`release_source_nat_allocation`), which now derives the preserved port
// from the flow key when the decision carried no port rewrite. The
// tuple-unknown (`None`) wrapper mints NO token (never a real framed flow /
// reverse session entry).

use super::allocator::{
    DeterministicV4, DeterministicV6, InterfaceDomainReserve, NS_PER_SEC, NatHolder,
    PersistentSourceKey, PoolAddressFamily, PortAllocator, TranslatedTuple,
    deterministic_indices_v4,
};
use super::iface_registry::InterfaceNatAllocators;
use super::{NatCounterStore, NatDecision, NatRuleCounter, NatScopeCtx};
use crate::SourceNATRuleSnapshot;
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6};
use crate::prefix::{PrefixV4, PrefixV6};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rustc_hash::{FxHashMap, FxHashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

// #6988: source.rs crossed the 2000-line REFACTOR tier and reached 3315.
// Six clusters moved out as PURE CODE MOTION. Each was chosen for its
// dependency cost, not its name: the ratio of lines moved to visibility
// widenings required. The whole split needs exactly TWO widenings, both in
// `failure.rs`:
//
//   SourceNatFailure::for_rule                -> pub(super)  (19 callers in match_rules)
//   source_nat_failure_reason_from_snapshot   -> pub(super)  (1 caller in parse_inner, here)
//
// Nothing else changed visibility, because a PRIVATE item is visible to its
// own module AND that module's descendants: everything that stayed here and is
// called from a submodule (SourceNatRule::matches, matches_ignoring_scope,
// address_has_draining_pool_occupancy, parse_match_prefix, port_in_ranges,
// nets_match_v4/v6) needed no edit at all.
//
// DECLINED seam, recorded because it is the one the issue named first: the
// pending-allocator resolution pass (PreviousPool / PendingPoolAllocator /
// resolve_pool_allocators, ~360 lines). Moving it costs SEVENTEEN visibility
// widenings, including making two private structs and all six of their fields
// pub(super) because `parse_source_nat_rules_inner` CONSTRUCTS them. That is
// not a seam; it is a property scattered across two files. It stays here with
// the parse pipeline it is part of, along with the aggregate-budget cluster
// that shares `SourceNatAggregateUse::saturating_with` with it.
//
// Re-exported with `pub(crate) use <m>::*` per the nat/mod.rs contract, so
// every existing `crate::nat::X`, `super::source::X` and `nat::source::X` path
// resolves unchanged. The afxdp/forwarding/mod.rs split is the precedent.

mod failure;
mod expand;
mod release;
mod synced;
mod nat64_ports;
mod match_rules;
mod overlap;
pub(crate) use failure::*;
pub(crate) use expand::*;
pub(crate) use release::*;
pub(crate) use synced::*;
pub(crate) use nat64_ports::*;
pub(crate) use match_rules::*;
pub(crate) use overlap::*;


const DEFAULT_PERSISTENT_NAT_TIMEOUT_SECS: i64 = 300;


#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct SourceNatFlowKey {
    pub(crate) protocol: u8,
    pub(crate) src_ip: IpAddr,
    pub(crate) dst_ip: IpAddr,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
}

/// #2823: remote-endpoint scope of a persistent NAT lease, the full
/// three-way Junos `persistent-nat permit` enum. Replaces the pre-#2823
/// binary `permit_any_remote_host` bool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum PersistentNatPermit {
    /// `any-remote-host`: lease keyed by the local source tuple ONLY — any
    /// remote host reuses the same translated mapping.
    AnyRemoteHost,
    /// `target-host`: lease keyed by source tuple + remote destination IP
    /// (the destination PORT is dropped) — a second flow from the same
    /// source to a NEW port on the SAME remote host reuses the binding.
    TargetHost,
    /// `target-host-port`: lease keyed by source tuple + remote destination
    /// IP + destination port — a new remote port keys to a distinct lease
    /// and gets a fresh mapping. The pre-#2823 disabled-flag behavior, the
    /// default mode, and the fallback for an empty wire value.
    #[default]
    TargetHostPort,
}

impl PersistentNatPermit {
    /// Decode the wire fields. Prefer the explicit `persistent_nat_permit`
    /// string; when it is empty (an older control plane that predates the
    /// enum) fall back to the legacy `persistent_nat_permit_any_remote_host`
    /// bool: true => AnyRemoteHost, false => TargetHostPort (the pre-#2823
    /// disabled-flag (dst_ip, dst_port) keying).
    pub(crate) fn from_wire(permit: &str, permit_any_remote_host: bool) -> Self {
        match permit {
            "any-remote-host" => Self::AnyRemoteHost,
            "target-host" => Self::TargetHost,
            "target-host-port" => Self::TargetHostPort,
            _ if permit_any_remote_host => Self::AnyRemoteHost,
            _ => Self::TargetHostPort,
        }
    }

    /// Junos wire string for the status surface (#3193). The control plane
    /// renders this verbatim as `Permit:` in `show security nat source`, so
    /// the operator sees the actual three-way mode rather than a binary flag.
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Self::AnyRemoteHost => "any-remote-host",
            Self::TargetHost => "target-host",
            Self::TargetHostPort => "target-host-port",
        }
    }
}

impl SourceNatFlowKey {
    /// #2397: build the persistent-NAT lease key for this flow.
    ///
    /// #2823: the scope is selected by the three-way `permit` enum:
    ///   - `AnyRemoteHost`   -> `remote = None`: source-tuple-only key, any
    ///     remote host reuses the mapping.
    ///   - `TargetHost`      -> `remote = Some((dst_ip, 0))`: the destination
    ///     IP is folded in but the port is dropped, so a second flow from the
    ///     same source to a NEW port on the SAME remote host keys to the same
    ///     lease and reuses the mapping.
    ///   - `TargetHostPort`  -> `remote = Some((dst_ip, dst_port))`: the full
    ///     remote endpoint is folded in, so a different remote port keys to a
    ///     distinct lease and gets a fresh mapping (the pre-#2823 behavior).
    pub(super) fn persistent_source_key(self, permit: PersistentNatPermit) -> PersistentSourceKey {
        PersistentSourceKey {
            protocol: self.protocol,
            src_ip: self.src_ip,
            src_port: self.src_port,
            remote: match permit {
                PersistentNatPermit::AnyRemoteHost => None,
                PersistentNatPermit::TargetHost => Some((self.dst_ip, 0)),
                PersistentNatPermit::TargetHostPort => Some((self.dst_ip, self.dst_port)),
            },
        }
    }
}

/// #3429: source-NAT `match application` protocol wildcard. 256 is outside the
/// 0-255 protocol range so it never aliases protocol 0 (HOPOPT); a term carrying
/// it matches any L4 protocol. The Go builder emits it for an application whose
/// protocol token is empty/unresolvable. A reserved 0xFFFF sentinel (any value
/// in 257..=65535 works) can never equal a real protocol and is not the
/// wildcard, so a term carrying it matches nothing — the fail-closed marker the
/// Go builder emits for a configured-but-unresolvable `match application`.
pub(crate) const SOURCE_NAT_PROTO_ANY: u16 = 256;

/// #3429/#3491: one resolved source-NAT `match application` term — an L4
/// protocol (IANA number, or `SOURCE_NAT_PROTO_ANY` for any) and optional
/// inclusive destination- and source-port ranges. The flow matches the term when
/// its protocol equals `protocol` (or `protocol == SOURCE_NAT_PROTO_ANY`) AND,
/// when `ports` is non-empty, its destination port falls in one of the ranges,
/// AND, when `src_ports` is non-empty (#3491), its source port falls in one of
/// the source ranges. An empty axis is unconstrained on that axis.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SourceNatAppTerm {
    pub(crate) protocol: u16,
    pub(crate) ports: Vec<(u16, u16)>,
    pub(crate) src_ports: Vec<(u16, u16)>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SourceNatRule {
    pub(crate) name: String,
    pub(crate) from_zone: String,
    pub(crate) to_zone: String,
    /// #3096: interface-/routing-instance-scoped rule-set matching. A
    /// non-empty value restricts the rule to flows whose ingress (`from_*`) or
    /// egress (`to_*`) interface config-name / routing-instance equals it.
    /// Empty = unscoped on that axis. Enforced in `scope_matches`.
    pub(crate) from_interface: String,
    pub(crate) to_interface: String,
    pub(crate) from_routing_instance: String,
    pub(crate) to_routing_instance: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) destination_v4: Vec<PrefixV4>,
    pub(crate) destination_v6: Vec<PrefixV6>,
    /// #2398: whether the rule carried a `match source-address` constraint at
    /// all (snapshot source list non-empty), independent of how many entries
    /// parsed. `false` = unscoped source -> match any source (unchanged
    /// behavior). `true` but BOTH `source_v4`/`source_v6` empty (every
    /// configured prefix failed to parse) => match NOTHING (fail closed), never
    /// the pre-#2398 collapse-to-match-any fail-open broadening.
    pub(crate) source_constrained: bool,
    /// #2398: whether the rule carried a `match destination-address`
    /// constraint at all. Same fail-closed semantics as `source_constrained`,
    /// for the destination match set.
    pub(crate) destination_constrained: bool,
    /// #3429: source-NAT `match destination-port` constraint as inclusive
    /// (low, high) ranges. Empty = port-unconstrained (match any destination
    /// port, the pre-#3429 behavior). Non-empty = the flow's destination port
    /// MUST fall in one range or the rule does not match. Enforced in
    /// `l4_matches`, before translation AND before an `off` exemption.
    pub(crate) match_dst_ports: Vec<(u16, u16)>,
    /// #3429: source-NAT `match application` constraint, pre-expanded by the Go
    /// builder to (protocol, port-range) terms. Empty = app-unconstrained.
    /// Non-empty = the flow MUST satisfy one term. Enforced in `l4_matches`.
    pub(crate) match_apps: Vec<SourceNatAppTerm>,
    pub(crate) interface_mode: bool,
    pub(crate) off: bool,
    pub(crate) pool_name: String,
    pub(crate) pool_mode: bool,
    /// #3906: `port no-translation` — translate the source ADDRESS but PRESERVE
    /// the original source port. When true a pool-mode rule takes the
    /// address-only path (pick a pool address, leave `rewrite_src_port` unset so
    /// the packet keeps its L4 source port); no pool port is allocated and
    /// `pool_allocator.port_low/high` are irrelevant. Default false = the
    /// pre-#3906 PAT behaviour (allocate a port from the pool range).
    pub(crate) no_translation: bool,
    pub(crate) pool_failure: Option<SourceNatFailureReason>,
    pub(crate) address_persistent: bool,
    pub(crate) persistent_nat: bool,
    /// #2823: the three-way persistent-NAT remote scope (was a binary
    /// `permit_any_remote_host` bool).
    pub(crate) persistent_nat_permit: PersistentNatPermit,
    pub(crate) persistent_nat_inactivity_timeout_secs: i64,
    pub(crate) persistent_nat_timeout_ns: u64,
    pub(crate) pool_addresses_v4: Vec<Ipv4Addr>,
    pub(crate) pool_addresses_v6: Vec<Ipv6Addr>,
    /// The pool's CONFIGURED port range after snapshot defaulting (1024-65535
    /// when unset). Carried on the rule — config, not allocator state — so the
    /// pool status view (`source_nat_pool_statuses`) and the allocator key
    /// read the same values for a healthy pool AND keep reporting the
    /// configured range for a FAILED pool, whose `pool_allocator` is the
    /// empty default since #6812 (failed pools build no bitmap). The
    /// allocator of a healthy pool is always built with exactly these values
    /// (`resolve_pool_allocators`), so the two can never diverge.
    pub(crate) pool_port_low: u16,
    pub(crate) pool_port_high: u16,
    /// #4559: deterministic CGNAT (mode 1, IPv4 subscriber) block-allocation
    /// parameters. `Some` => this rule's pool maps each in-range subscriber IPv4
    /// to a fixed external IP + port block (`allocate_deterministic_v4`) instead
    /// of round-robin/sticky PAT. `None` => the pre-#4559 behaviour (unchanged).
    /// Mode 2 (IPv6 subscriber / NAT64) is deferred — the Go compiler does not
    /// set the snapshot fields for it, so it stays `None` and round-robins with
    /// the commit-time advisory still surfacing the gap.
    pub(crate) deterministic_v4: Option<DeterministicV4>,
    pub(crate) pool_allocator: PortAllocator,
    /// #2218: per-rule translation hit counter, shared from the
    /// coordinator's `NatCounterStore`. `None` when the rule carries no
    /// per-rule counter (`counter_id == 0`). Captured at build time; the
    /// cold-path commit site clones the `Arc` and calls `.add(len)` once
    /// per committed translated forward flow.
    pub(crate) hit_counter: Option<Arc<NatRuleCounter>>,
    /// #6979 F6: the apply-time index of pool addresses that more than one
    /// distinct allocator covers, shared by every rule that touches one. Wired
    /// by `wire_overlap_peers` (`source/overlap.rs`).
    ///
    /// The address relation is static (a property of the snapshot) so it is
    /// resolved once, at apply. The OCCUPANCY is not — it changes with every
    /// mint and release — so a peer's bit is read at mint time, never
    /// snapshotted.
    ///
    /// `None` for every rule of a config with no overlapping pools, which is
    /// every config a strict commit accepts (#5144). The mint-path cost there
    /// is one `Option::is_none`.
    pub(crate) overlap_owners: Option<Arc<PoolAddressOwners>>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct SourceNatPoolAllocatorKey {
    pool_name: String,
    pool_addresses_v4: Vec<Ipv4Addr>,
    pool_addresses_v6: Vec<Ipv6Addr>,
    port_low: u16,
    port_high: u16,
}

impl SourceNatRule {
    fn allocator_key(&self) -> Option<SourceNatPoolAllocatorKey> {
        let total_pool = self.pool_addresses_v4.len() + self.pool_addresses_v6.len();
        (self.pool_mode && total_pool > 0 && self.pool_failure.is_none()).then(|| {
            self.allocator_key_for(self.pool_port_low, self.pool_port_high)
        })
    }

    /// #7717: the carry-over key that IGNORES `pool_failure`.
    ///
    /// `allocator_key` refuses a failed pool, which is right for MINTING and
    /// wrong for RETENTION. A pool quarantined because its address overlaps an
    /// interface-SNAT egress still has live flows holding real identities; if
    /// its allocator is not carried into the next generation those flows lose
    /// the state that releases them, which is the stranding the merged config
    /// gate names as the reason the quarantine could not ship alone.
    ///
    /// This is a strict WIDENING of `allocator_key`: for a healthy pool the two
    /// return the same key, so retention is unchanged there. It must also
    /// survive REPEATED quarantined snapshots — every rebuild while the overlap
    /// persists re-derives the previous generation through this key, and a
    /// key that dropped on the second one would strand exactly the flows the
    /// first one preserved.
    fn drain_allocator_key(&self) -> Option<SourceNatPoolAllocatorKey> {
        let total_pool = self.pool_addresses_v4.len() + self.pool_addresses_v6.len();
        (self.pool_mode && total_pool > 0)
            .then(|| self.allocator_key_for(self.pool_port_low, self.pool_port_high))
    }

    /// #7717: is this rule a quarantined pool whose allocator is DRAINING —
    /// refusing new mints while live flows still release into it?
    fn is_draining_pool(&self) -> bool {
        self.pool_failure == Some(SourceNatFailureReason::PoolIfaceEgressOverlap)
            && self.pool_mode
            && (self.pool_addresses_v4.len() + self.pool_addresses_v6.len()) > 0
    }

    /// Does this rule's pool contain `addr` as a member address?
    fn pool_contains_address(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.pool_addresses_v4.contains(&v4),
            IpAddr::V6(v6) => self.pool_addresses_v6.contains(&v6),
        }
    }

    /// Build the allocator key with an EXPLICIT port range. The resolve pass
    /// (#6812) keys a rule BEFORE its allocator exists, so it cannot read the
    /// range back off `pool_allocator` (still the empty default there); the
    /// range must come from the snapshot defaulting the parse loop applied.
    fn allocator_key_for(&self, port_low: u16, port_high: u16) -> SourceNatPoolAllocatorKey {
        SourceNatPoolAllocatorKey {
            pool_name: self.pool_name.clone(),
            pool_addresses_v4: self.pool_addresses_v4.clone(),
            pool_addresses_v6: self.pool_addresses_v6.clone(),
            port_low,
            port_high,
        }
    }
}

/// #7717: does any QUARANTINED pool still hold live allocations on `addr`?
///
/// Scans the rule slice rather than consulting a precomputed set because the
/// answer is time-varying: the same rule flips from draining to drained when
/// its last flow closes, and a set computed at apply would pin the pre-drain
/// answer forever — a permanent quarantine wearing the shape of a working
/// drain. The scan is bounded by the rule count and runs only on the
/// interface-mode mint path (new flows), and the `is_draining_pool` test is a
/// cheap `Option::is_some` that is false for every rule in a healthy config, so
/// the common case never reaches the address comparison.
fn address_has_draining_pool_occupancy(rules: &[SourceNatRule], addr: IpAddr) -> bool {
    rules.iter().any(|candidate| {
        candidate.is_draining_pool()
            && candidate.pool_contains_address(addr)
            && candidate.pool_allocator.live_flow_count() > 0
    })
}

/// #6812: source-NAT AGGREGATE allocator budget at the apply boundary — the
/// Rust mirror of the Go #5877 strict commit gate
/// (`validateSourceNATAggregateCardinalityStrict`, pkg/config). The Go gate
/// rejects an over-budget config at strict commit, but the TOLERANT load /
/// peer-sync path only warns (#1960 no-brick), so an over-budget config can
/// still reach this apply boundary; before this gate the boundary expanded
/// every pool and built each address's occupancy bitmap EAGERLY — three
/// full-range /16 pools materialise 12,683,575,296 bitmap bits (~1.48 GiB)
/// and can stall or OOM the dataplane during an upgrade boot / HA convergence.
///
/// WHAT THIS BOUNDS, precisely, because the ordering invites a wrong reading:
/// the budget is checked in `resolve_pool_allocators`, which runs AFTER the
/// parse loop — so the pools' ADDRESS VECTORS (`pool_addresses_v4/v6`) are
/// already expanded when it runs, and only the per-address occupancy BITMAP is
/// gated (`PortAllocator::new` is reached solely from the `admitted_with(..) ==
/// Some` arm). That is deliberate and it is the right split: the bitmap is the
/// exhaustion vector by roughly three orders of magnitude. A full-range /16
/// pool costs 65536 x 4 B = ~262 KB as addresses against 65536 x 64512 bits =
/// ~528 MB as bitmap. Bounding the address vectors too would mean restructuring
/// the parse loop to defer expansion, for ~0.05% of the memory. Do not "fix"
/// the ordering on the theory that the guard sits downstream of the growth it
/// limits — for the quantity that matters it sits upstream (#6812).
/// The values MUST match the Go constants
/// (`MaxSourceNATPoolCount` / `MaxSourceNATAggregatePoolAddresses` /
/// `MaxSourceNATAggregatePortCapacity`); the parity is pinned by
/// `real_budget_matches_go_5877_constants` in tests_aggregate_budget.rs.
#[derive(Clone, Copy, Debug)]
pub(super) struct SourceNatAggregateBudget {
    /// Max DISTINCT pool allocator instances (one per referenced pool key).
    pub(super) max_pools: u64,
    /// Max SUM of every referenced pool's expanded address count.
    pub(super) max_addresses: u64,
    /// Max SUM of (addresses x port range) = occupancy bitmap SLOTS.
    pub(super) max_port_capacity: u64,
}

pub(super) const SOURCE_NAT_AGGREGATE_BUDGET: SourceNatAggregateBudget = SourceNatAggregateBudget {
    max_pools: 1024,
    max_addresses: 16 * MAX_POOL_PREFIX_HOSTS, // 1,048,576
    max_port_capacity: 1 << 33,                // 8,589,934,592
};

/// Running aggregate charge across the distinct allocator keys one apply will
/// hold live. u64 with saturating adds: a hand-crafted snapshot can claim
/// absurd cardinalities, and saturation (never wrap) keeps the over-budget
/// verdict fail-closed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SourceNatAggregateUse {
    pub(super) pools: u64,
    pub(super) addresses: u64,
    pub(super) port_capacity: u64,
}

impl SourceNatAggregateUse {
    /// Cumulative use UNCONDITIONALLY including `charge` (saturating adds —
    /// the one add formula). Used directly for keys that must be accepted
    /// regardless of budget (reused last-good state), and as the candidate
    /// inside `admitted_with`.
    fn saturating_with(self, charge: Self) -> Self {
        Self {
            pools: self.pools.saturating_add(charge.pools),
            addresses: self.addresses.saturating_add(charge.addresses),
            port_capacity: self.port_capacity.saturating_add(charge.port_capacity),
        }
    }

    /// Cumulative use IF `charge` is admitted. Returns None when admitting it
    /// would cross any budget — the caller then refuses the key WITHOUT
    /// committing the charge (first-fit: a later, smaller key may still fit).
    pub(super) fn admitted_with(
        self,
        charge: Self,
        budget: &SourceNatAggregateBudget,
    ) -> Option<Self> {
        let next = self.saturating_with(charge);
        (next.pools <= budget.max_pools
            && next.addresses <= budget.max_addresses
            && next.port_capacity <= budget.max_port_capacity)
            .then_some(next)
    }
}

/// Per-rule deferred allocator inputs, captured by the parse loop for every
/// rule that passes the `allocator_key()` gate (`pool_mode && total_pool > 0
/// && pool_failure.is_none()`). `total_pool` is the EXPANDED address count
/// (v4 + v6); `port_low`/`port_high` are the snapshot-defaulted range.
/// #6765: a previous generation's pool, kept so a PARTIAL-OVERLAP change can
/// carry live port ownership onto the addresses it retains. Held by pool NAME,
/// because the exact-match `SourceNatPoolAllocatorKey` cannot answer this
/// question — a changed address list is exactly what makes that key miss.
struct PreviousPool {
    addresses_v4: Vec<Ipv4Addr>,
    addresses_v6: Vec<Ipv6Addr>,
    allocator: PortAllocator,
}

/// Map PREVIOUS pool-address indices to their index in the NEW pool, for the
/// addresses present in both.
///
/// The index model is positional and shared with the allocator: v4 addresses
/// occupy `0..v4.len()`, and a v6 address at position `i` is index
/// `v4.len() + i` (see `SourceNatRule::allocator_key` / the v6_offset arithmetic
/// on the match path). Both sides are re-derived here rather than assumed equal,
/// because the whole point is that the two lists differ.
///
/// Returns an empty map when nothing is retained — a fully-disjoint swap, which
/// must keep resetting.
/// v4-only wrapper for NAT64, whose pools carry no v6 addresses. It calls the
/// SAME formula rather than restating the positional rule — a second copy of
/// "which previous index is this address now at" is exactly the drift that makes
/// a position-indexed carry-over unsafe.
pub(crate) fn retained_pool_index_map_v4(
    prev_v4: &[Ipv4Addr],
    new_v4: &[Ipv4Addr],
) -> FxHashMap<usize, usize> {
    let prev = PreviousPool {
        addresses_v4: prev_v4.to_vec(),
        addresses_v6: Vec::new(),
        allocator: PortAllocator::new(0, 0, 0),
    };
    retained_pool_index_map(&prev, new_v4, &[])
}

pub(crate) fn retained_pool_index_map(
    prev: &PreviousPool,
    new_v4: &[Ipv4Addr],
    new_v6: &[Ipv6Addr],
) -> FxHashMap<usize, usize> {
    let mut map = FxHashMap::default();
    let prev_v4_len = prev.addresses_v4.len();
    let new_v4_len = new_v4.len();
    for (new_i, addr) in new_v4.iter().enumerate() {
        if let Some(prev_i) = prev.addresses_v4.iter().position(|a| a == addr) {
            map.insert(prev_i, new_i);
        }
    }
    for (new_i, addr) in new_v6.iter().enumerate() {
        if let Some(prev_i) = prev.addresses_v6.iter().position(|a| a == addr) {
            map.insert(prev_v4_len + prev_i, new_v4_len + new_i);
        }
    }
    map
}

struct PendingPoolAllocator {
    port_low: u16,
    port_high: u16,
    total_pool: usize,
}

impl PendingPoolAllocator {
    fn charge(&self) -> SourceNatAggregateUse {
        SourceNatAggregateUse {
            pools: 1,
            addresses: self.total_pool as u64,
            // One formula for "port slots this allocator materialises" —
            // shared with PortAllocator::new's own capacity arithmetic.
            port_capacity: super::allocator::allocator_capacity(
                self.total_pool,
                self.port_low,
                self.port_high,
            ) as u64,
        }
    }
}

/// #6765: carry live port ownership onto the addresses a changed pool RETAINS.
///
/// A no-op unless the previous generation had an UNAMBIGUOUS pool of this name
/// whose address list overlaps the new one. A fully-disjoint swap yields an
/// empty index map and re-seeds nothing, which is the reset the existing
/// `nat64_4518_pool_change_resets_allocator` behaviour depends on.
///
/// What could not be carried is logged ONCE per pool per apply — a config-apply
/// event, not a per-packet path. A silent drop here would be the same class of
/// defect as the reissue this exists to prevent.
fn reseed_retained_pool(
    pool_name: &str,
    allocator: &PortAllocator,
    previous_pools: &FxHashMap<String, Option<PreviousPool>>,
    rule: &SourceNatRule,
    now_ns: u64,
) {
    let Some(slot) = previous_pools.get(pool_name) else {
        return;
    };
    let Some(prev) = slot.as_ref() else {
        // Ambiguous: this name resolved to more than one address list in the
        // previous generation. Carrying from an arbitrary one of them could
        // move ownership between pools, so carry nothing and say so.
        eprintln!(
            "xpf-dp: source-nat pool {pool_name:?} changed but the previous generation had \
             more than one address list under that name; live translations are NOT carried \
             onto retained addresses (#6765)"
        );
        return;
    };
    let map = retained_pool_index_map(prev, &rule.pool_addresses_v4, &rule.pool_addresses_v6);
    if map.is_empty() {
        return;
    }
    let outcome = allocator.reseed_retained_from(&prev.allocator, &map, now_ns);
    if outcome.skipped_out_of_range > 0 || outcome.skipped_address_only > 0 || outcome.refused > 0 {
        eprintln!(
            "xpf-dp: source-nat pool {pool_name:?} changed: carried {} live translation(s) onto \
             {} retained address(es); {} not carried (port outside the new range), {} \
             address-only token(s) skipped, {} refused (#6765)",
            outcome.reseeded,
            map.len(),
            outcome.skipped_out_of_range,
            outcome.skipped_address_only,
            outcome.refused,
        );
    } else if outcome.reseeded > 0 {
        eprintln!(
            "xpf-dp: source-nat pool {pool_name:?} changed: carried {} live translation(s) onto \
             {} retained address(es) (#6765)",
            outcome.reseeded,
            map.len(),
        );
    }
}

/// #6979 F6: carry live reservations out of a previous allocator whose pool was
/// RENAMED into this generation's allocator for the same addresses and range.
///
/// THE DEFECT. `previous_allocators` is keyed by
/// `SourceNatPoolAllocatorKey` = pool NAME + address vectors + port range. Two
/// rules with identical addresses under DIFFERENT pool names are two keys; give
/// one of them a live flow and then rename it to the other's name, and both new
/// rules collapse onto the surviving name's key. The renamed pool's allocator is
/// simply dropped, so its live translated identity becomes free and reissuable
/// while the session that owns it is still in the table.
///
/// Measured on master: gen 1 with pools `a` (idle) and `b` (holding
/// `203.0.113.1:20000`); gen 2 renames `b` -> `a`; both rules come back with
/// ZERO live flows. The control — the same rebuild WITHOUT the rename — carries
/// the flow correctly, so the loss is caused by the collapse and not by the
/// rebuild.
///
/// WHY MERGING IS THE RIGHT ANSWER AND NOT A WIDER KEY. Two rules naming one
/// pool SHOULD share one allocator — that is the point of the key, and widening
/// it to keep them apart would hand the same address two independent occupancy
/// domains, which is the collision this whole structure exists to prevent. The
/// bug is not the sharing; it is that the OTHER generation's live state is
/// discarded rather than carried. Addresses and range are identical by
/// construction here (they are part of the key we matched on), so the index map
/// is the identity and every carried reservation stays on the address it was
/// minted for.
///
/// A conflict — two previous pools that each held the SAME (address, port) —
/// cannot be resolved by carrying both, and `reseed_retained_from` refuses the
/// loser and counts it. That is the conservative direction: one owner survives
/// and is logged, versus today's outcome where BOTH are freed.
fn carry_renamed_pool_reservations(
    key: &SourceNatPoolAllocatorKey,
    allocator: &PortAllocator,
    previous_allocators: &FxHashMap<SourceNatPoolAllocatorKey, PortAllocator>,
    live_pool_names: &FxHashSet<String>,
    now_ns: u64,
) {
    let total = key.pool_addresses_v4.len() + key.pool_addresses_v6.len();
    if total == 0 {
        return;
    }
    for (prev_key, prev) in previous_allocators.iter() {
        // The exact key is the allocator we already reused or reseeded from.
        if prev_key == key {
            continue;
        }
        // Only a RENAME: everything except the name must match, or the indices
        // would not line up and a carried reservation would land on a different
        // address than the one it was minted for.
        if prev_key.pool_addresses_v4 != key.pool_addresses_v4
            || prev_key.pool_addresses_v6 != key.pool_addresses_v6
            || prev_key.port_low != key.port_low
            || prev_key.port_high != key.port_high
        {
            continue;
        }
        // A RENAME, not two coexisting pools. If the previous name is STILL a
        // live pool in this generation, these are two distinct pools that
        // merely share an address, and carrying between them would be an
        // over-reach in the other direction: the source pool keeps its own
        // allocator, so the copy here is never released when the original is,
        // and it leaks a phantom reservation on an address the peer pool owns.
        // Measured while building this: without the check the control case (the
        // same rebuild WITHOUT a rename) cross-pollinated `a` and `b`.
        if live_pool_names.contains(&prev_key.pool_name) {
            continue;
        }
        if prev.live_flow_count() == 0 {
            continue;
        }
        let map: FxHashMap<usize, usize> = (0..total).map(|i| (i, i)).collect();
        let outcome = allocator.reseed_retained_from(prev, &map, now_ns);
        eprintln!(
            "xpf-dp: source-nat pool {:?} appears to be pool {:?} renamed (same addresses and \
             port range): carried {} live translation(s) across the rename; {} refused \
             (another pool already owns the identity), {} out of range (#6979)",
            key.pool_name, prev_key.pool_name, outcome.reseeded, outcome.refused,
            outcome.skipped_out_of_range,
        );
    }
}

/// #6812: assign pool allocators AFTER parsing, under the aggregate budget.
///
/// Three invariants the pre-#6812 inline block violated:
///
/// 1. REUSE BEFORE BUILD — the this-apply and previous-apply allocator maps
///    are consulted FIRST; only a miss constructs `PortAllocator::new`. The
///    old code built a full per-address occupancy bitmap per rule and THEN
///    discarded it on a reuse hit.
/// 2. FAILED POOLS BUILD NOTHING — a rule whose pool already failed
///    (missing/empty/invalid/Go-poisoned) keeps the empty default allocator;
///    the match path short-circuits on `pool_failure` before touching the
///    allocator and `reserve_flow` on an empty allocator returns false
///    gracefully, so no consumer can observe the difference.
/// 3. AGGREGATE BUDGET — distinct keys are charged (count / addresses /
///    port capacity). A REUSED key consumes budget but is ALWAYS accepted: a
///    no-op re-apply must not kill live state, and charging it stops a
///    two-step apply from creeping past the cap one generation at a time (two
///    full-range /16 pools, then the same two plus a third — the review's
///    1.48 GiB scenario via incremental applies). A NEW key is admitted only
///    if it fits the remaining budget (first-fit: a refused key consumes
///    nothing, so a later smaller key can still install); a refused key marks
///    every referencing rule `OverBudget` — fail-closed with a dataplane
///    diagnostic — and builds no bitmap.
///
/// # Reused keys are RESERVED before any new key is admitted (#6812 F2 round 4)
///
/// Invariant 3 above is order-sensitive if reuse is charged where it is met.
/// A single pass charging in snapshot order lets a NEW key be admitted against
/// a `used` total that does not yet include reused keys appearing LATER in the
/// slice — and those keys are then accepted unconditionally, so the live set
/// ends up over the cap. Measured, with two live pools A and B at 160 of a
/// 200-slot budget and a new C worth 80:
///
/// | snapshot order | C | live |
/// |---|---|---|
/// | `A, B, C` | refused | 160 |
/// | `C, A, B` | **admitted, bitmap built** | **240 — over the cap** |
///
/// Same pools, same reuse map, opposite outcome from ORDER alone; and it
/// repeats, one extra pool per apply. The Go-side poison hides it for
/// snapshots this control plane generates, which is precisely why it mattered:
/// this boundary exists as the INDEPENDENT backstop for a tolerated,
/// older-control-plane, or handcrafted snapshot, where no Go poison is coming.
///
/// Phase 1 therefore charges every DISTINCT key that will be reused, before
/// phase 2 admits anything. Reused keys are still always accepted and are
/// charged exactly once; new-key admission now sees the true live total
/// whatever order the snapshot arrives in.
fn resolve_pool_allocators(
    out: &mut [SourceNatRule],
    pendings: &[Option<PendingPoolAllocator>],
    previous_allocators: &FxHashMap<SourceNatPoolAllocatorKey, PortAllocator>,
    previous_pools: &FxHashMap<String, Option<PreviousPool>>,
    budget: &SourceNatAggregateBudget,
    now_ns: u64,
) {
    let mut pool_allocators = FxHashMap::<SourceNatPoolAllocatorKey, PortAllocator>::default();
    let mut refused_keys = FxHashMap::<SourceNatPoolAllocatorKey, ()>::default();
    let mut used = SourceNatAggregateUse::default();

    // PHASE 1: reserve the reused keys. These are accepted unconditionally in
    // phase 2, so their charge is not a prediction — it is live state this
    // apply is already committed to holding.
    let mut reserved = FxHashMap::<SourceNatPoolAllocatorKey, ()>::default();
    for (rule, pending) in out.iter().zip(pendings.iter()) {
        let Some(pending) = pending else {
            continue;
        };
        let key = rule.allocator_key_for(pending.port_low, pending.port_high);
        if !previous_allocators.contains_key(&key) || reserved.contains_key(&key) {
            continue;
        }
        used = used.saturating_with(pending.charge());
        reserved.insert(key, ());
    }

    // PHASE 1b (#7717): DRAIN retention. A quarantined pool gets no pending, so
    // phase 2 never assigns it an allocator and its previous one would be
    // dropped — stranding the flows still holding identities from it. Reuse the
    // previous allocator for such a rule, REUSE-ONLY: never create one, because
    // a quarantined pool that never had live state has nothing to drain and
    // fabricating an allocator for it would just be a new occupancy domain on
    // an address we are quarantining precisely to stop that.
    //
    // Charged in phase 1 alongside the other reused keys: a draining allocator
    // holds real ports for as long as its flows live, and omitting it would let
    // the aggregate budget admit new keys against capacity that is still in use.
    for rule in out.iter() {
        if !rule.is_draining_pool() {
            continue;
        }
        let Some(key) = rule.drain_allocator_key() else {
            continue;
        };
        if !previous_allocators.contains_key(&key) || reserved.contains_key(&key) {
            continue;
        }
        // Charged through the SAME `PendingPoolAllocator::charge` formula the
        // healthy rules use, rather than a second copy of the arithmetic — a
        // draining pool occupies exactly what it occupied before it was
        // quarantined.
        used = used.saturating_with(
            PendingPoolAllocator {
                port_low: rule.pool_port_low,
                port_high: rule.pool_port_high,
                total_pool: rule.pool_addresses_v4.len() + rule.pool_addresses_v6.len(),
            }
            .charge(),
        );
        reserved.insert(key, ());
    }

    // PHASE 1c (#7717): hand the retained allocator to the draining rule. It
    // mints nothing — `pool_failure` is set, so the match path returns the
    // exception before it reaches the allocator — but releases from live flows
    // resolve through `rule.pool_allocator`, and the interface-side quarantine
    // reads its live count to know when the drain is done.
    for rule in out.iter_mut() {
        if !rule.is_draining_pool() {
            continue;
        }
        let Some(key) = rule.drain_allocator_key() else {
            continue;
        };
        if let Some(existing) = previous_allocators.get(&key) {
            rule.pool_allocator = existing.clone();
        }
    }

    // #6979 F6: the pool names this generation still has. A previous allocator
    // whose name is absent here was RENAMED (or removed); one whose name is
    // still present is a peer pool that merely shares an address.
    let live_pool_names: FxHashSet<String> = out
        .iter()
        .filter(|r| r.pool_mode && !r.pool_name.is_empty())
        .map(|r| r.pool_name.clone())
        .collect();

    // PHASE 2: assign. Reused keys were charged in phase 1 and must NOT be
    // charged again here.
    for (rule, pending) in out.iter_mut().zip(pendings.iter()) {
        let Some(pending) = pending else {
            continue;
        };
        let key = rule.allocator_key_for(pending.port_low, pending.port_high);
        if refused_keys.contains_key(&key) {
            rule.pool_failure = Some(SourceNatFailureReason::OverBudget);
            rule.deterministic_v4 = None;
            continue;
        }
        if let Some(existing) = pool_allocators.get(&key) {
            rule.pool_allocator = existing.clone();
            continue;
        }
        let charge = pending.charge();
        if let Some(existing) = previous_allocators.get(&key) {
            // Reuse preserves last-good live state: always accepted. Its
            // budget was charged in PHASE 1 — charging it again here would
            // double-count, and charging it ONLY here is the #6812 F2 defect
            // (a new key earlier in the slice would be admitted against a
            // `used` that omits it). A reused key that alone overflows (legacy
            // pre-cap state) saturated `used` in phase 1, which only refuses
            // NEW keys.
            debug_assert!(
                reserved.contains_key(&key),
                "a previously-allocated key must have been reserved in phase 1",
            );
            // #6979 F6: a pool RENAMED onto this key brings its live state with
            // it. Without this the renamed pool's allocator is dropped and its
            // translated identities become free while their sessions live.
            carry_renamed_pool_reservations(&key, existing, previous_allocators, &live_pool_names, now_ns);
            pool_allocators.insert(key, existing.clone());
            rule.pool_allocator = existing.clone();
            continue;
        }
        match used.admitted_with(charge, budget) {
            Some(next) => {
                used = next;
                let allocator = PortAllocator::new(
                    pending.total_pool,
                    pending.port_low,
                    pending.port_high,
                );
                // #6765: a FRESH allocator over a pool that RETAINS addresses
                // would reissue `(retained_addr, port_low)` — the occupancy
                // bitmap that was the sole ownership token is all-zero and the
                // cursor starts at 0. Carry the retained addresses' live port
                // ownership across before publishing.
                //
                // Only reached on this arm, so the two cases that must keep
                // resetting are untouched by construction: an exact-key match
                // returns above (full Arc share), and a cold start has no
                // `previous` at all, so `previous_pools` is empty.
                reseed_retained_pool(
                    &key.pool_name,
                    &allocator,
                    previous_pools,
                    rule,
                    now_ns,
                );
                // #6979 F6: the same carry for a key with no exact predecessor —
                // a rename onto a name that did not previously exist.
                carry_renamed_pool_reservations(&key, &allocator, previous_allocators, &live_pool_names, now_ns);
                pool_allocators.insert(key, allocator.clone());
                rule.pool_allocator = allocator;
            }
            None => {
                // One journald line per refused key per apply — a one-time
                // config-apply event, not a per-packet path.
                eprintln!(
                    "xpf-dp: source-nat pool {:?} refused at apply: aggregate allocator \
                     budget exceeded (count {}/{}, addresses {}/{}, port slots {}/{} would \
                     grow by {}/{}/{}); rule(s) referencing it fail closed (#6812)",
                    key.pool_name,
                    used.pools,
                    budget.max_pools,
                    used.addresses,
                    budget.max_addresses,
                    used.port_capacity,
                    budget.max_port_capacity,
                    charge.pools,
                    charge.addresses,
                    charge.port_capacity,
                );
                refused_keys.insert(key, ());
                rule.pool_failure = Some(SourceNatFailureReason::OverBudget);
                // Keep the parse-loop invariant `deterministic_v4.is_some() =>
                // pool_failure.is_none()` that the resolve-time refusal would
                // otherwise break (the match path is safe either way — it
                // short-circuits on pool_failure first).
                rule.deterministic_v4 = None;
            }
        }
    }

    // #6979 F6: record, per rule, which PEER pools cover the same addresses.
    // Runs last, after every allocator — retained, reused or freshly built —
    // has been assigned, because it captures the peers' handles.
    wire_overlap_peers(out);
}

impl SourceNatRule {
    /// #3096: does the flow satisfy every non-empty interface /
    /// routing-instance scope on this rule? Empty scope fields are wildcards.
    /// All present scopes are AND-ed (Junos restricts a from/to clause to one
    /// kind, but a hostile multi-kind clause fails closed — it must match
    /// every set field).
    fn scope_matches(&self, scope: &NatScopeCtx) -> bool {
        if !self.from_interface.is_empty() && self.from_interface != scope.ingress_ifname {
            return false;
        }
        if !self.to_interface.is_empty() && self.to_interface != scope.egress_ifname {
            return false;
        }
        if !self.from_routing_instance.is_empty()
            && self.from_routing_instance != scope.ingress_routing_instance
        {
            return false;
        }
        if !self.to_routing_instance.is_empty()
            && self.to_routing_instance != scope.egress_routing_instance
        {
            return false;
        }
        true
    }

    /// #3429: does the flow satisfy this rule's L4 `match destination-port` /
    /// `match application` constraints? An empty constraint set is a wildcard
    /// (unchanged match-any behavior). A non-empty set is AND-ed across the two
    /// kinds (destination-port AND application), mirroring Junos.
    ///
    /// #5687: `tuple_unknown` is the OUT-OF-BAND "L4 tuple unknown" signal (the
    /// address-only `match_source_nat` wrapper, `protocol == None`) — NOT the
    /// numeric value 0. A rule that carries ANY L4 constraint cannot be
    /// satisfied by an unknown tuple, so it fails closed (an L4-scoped rule must
    /// never fire on traffic whose port/protocol the caller could not supply).
    /// A genuine HOPOPT packet (`Some(0)`, `tuple_unknown == false`) is NOT
    /// short-circuited here: it falls through to the normal port/protocol
    /// checks, which reject an L4-port-scoped rule anyway (its ports are 0) — so
    /// the fail-closed behavior is preserved without conflating it with the
    /// unknown sentinel. An unconstrained rule is unaffected.
    ///
    /// #3491: a `match application` term may also constrain the SOURCE port (an
    /// application defined with `source-port`). It is AND-ed with the protocol
    /// and destination-port checks INSIDE the same term: the flow satisfies the
    /// term only when its protocol, destination port, AND source port all match.
    /// Before #3491 the source-port axis was dropped, so an app-scoped rule fired
    /// regardless of source port — the fail-open this fix closes.
    fn l4_matches(&self, tuple_unknown: bool, protocol: u8, src_port: u16, dst_port: u16) -> bool {
        if self.match_dst_ports.is_empty() && self.match_apps.is_empty() {
            return true;
        }
        // #5687: fail closed on the OUT-OF-BAND unknown tuple, not `protocol == 0`
        // (a real HOPOPT flows through to the normal checks below).
        if tuple_unknown {
            return false;
        }
        if !self.match_dst_ports.is_empty() && !port_in_ranges(dst_port, &self.match_dst_ports) {
            return false;
        }
        if !self.match_apps.is_empty() {
            let proto16 = protocol as u16;
            let ok = self.match_apps.iter().any(|t| {
                (t.protocol == SOURCE_NAT_PROTO_ANY || t.protocol == proto16)
                    && (t.ports.is_empty() || port_in_ranges(dst_port, &t.ports))
                    && (t.src_ports.is_empty() || port_in_ranges(src_port, &t.src_ports))
            });
            if !ok {
                return false;
            }
        }
        true
    }

    /// Does the flow satisfy this rule's `from zone` / `to zone` clause? An
    /// empty zone on the rule is a wildcard (unscoped rule-set).
    fn zone_matches(&self, from_zone: &str, to_zone: &str) -> bool {
        (self.from_zone.is_empty() || self.from_zone == from_zone)
            && (self.to_zone.is_empty() || self.to_zone == to_zone)
    }

    /// Does the flow satisfy this rule's `match source-address` /
    /// `match destination-address` sets? A cross-family (v4 source, v6
    /// destination or vice versa) tuple can never match a rule.
    fn address_matches(&self, src_ip: IpAddr, dst_ip: IpAddr) -> bool {
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                nets_match_v4(self.source_constrained, &self.source_v4, src)
                    && nets_match_v4(self.destination_constrained, &self.destination_v4, dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                nets_match_v6(self.source_constrained, &self.source_v6, src)
                    && nets_match_v6(self.destination_constrained, &self.destination_v6, dst)
            }
            _ => false,
        }
    }

    fn matches(
        &self,
        scope: &NatScopeCtx,
        from_zone: &str,
        to_zone: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tuple_unknown: bool,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        self.zone_matches(from_zone, to_zone)
            && self.scope_matches(scope)
            && self.l4_matches(tuple_unknown, protocol, src_port, dst_port)
            && self.address_matches(src_ip, dst_ip)
    }

    /// #6211: [`matches`] minus the #3096 interface / routing-instance
    /// `scope_matches` axis, for the HA STANDBY's synced-reservation rule
    /// selection ([`reserve_synced_source_nat_allocation`]).
    ///
    /// The standby re-derives which source-NAT rule the ACTIVE node matched
    /// from the synced session alone. Every axis except the scope is carried
    /// on (or derivable from) the HA session-sync wire: the zone pair rides as
    /// `ingress_zone_id`/`egress_zone_id`, and the 5-tuple is the session key
    /// itself. The scope axis is NOT: `NatScopeCtx` is built from the LOCAL
    /// `ifindex_to_config_name` / `ifindex_to_routing_instance` maps keyed on
    /// the ACTIVE node's ingress/egress ifindices, which the standby does not
    /// have (a synced entry's ifindices are the peer's and are re-resolved
    /// locally on import).
    ///
    /// So the scope is treated as UNCONSTRAINED here rather than as a
    /// mismatch. Rejecting an interface-scoped rule the standby cannot confirm
    /// would push the selection PAST the rule the active actually used and
    /// onto a later one — strictly worse than the pre-#6211 first-pool-match.
    /// Ignoring the axis only declines to narrow on it: every other axis still
    /// narrows, and the pre-#6211 selection narrowed on none of them.
    #[allow(clippy::too_many_arguments)]
    fn matches_ignoring_scope(
        &self,
        from_zone: &str,
        to_zone: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tuple_unknown: bool,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        self.zone_matches(from_zone, to_zone)
            && self.l4_matches(tuple_unknown, protocol, src_port, dst_port)
            && self.address_matches(src_ip, dst_ip)
    }
}


#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_source_nat_rules(snaps: &[SourceNATRuleSnapshot]) -> Vec<SourceNatRule> {
    parse_source_nat_rules_with_previous(snaps, None, &NatCounterStore::default(), 0)
}

/// `now_ns` is the caller's MONOTONIC clock, threaded through to the #6765
/// retained-address re-seed (`reseed_retained_from` -> `reserve_flow`, which
/// re-arms a persistent lease's idle expiry on the eviction path). The
/// production call site is `afxdp::forwarding_build`, which has
/// `monotonic_nanos()`; tests that do not exercise the re-seed pass 0.
pub(crate) fn parse_source_nat_rules_with_previous(
    snaps: &[SourceNATRuleSnapshot],
    previous: Option<&[SourceNatRule]>,
    nat_counters: &NatCounterStore,
    now_ns: u64,
) -> Vec<SourceNatRule> {
    parse_source_nat_rules_inner(
        snaps,
        previous,
        nat_counters,
        &SOURCE_NAT_AGGREGATE_BUDGET,
        now_ns,
    )
}

/// Test-only entry with an injectable aggregate budget: the production budget
/// (2^33 port slots) cannot be exercised end-to-end in a unit test without
/// materialising ~1 GiB of real bitmaps, so the budget-gate WIRING tests
/// scale the budget down and drive the identical resolve path. The budget
/// VALUES are pinned separately against the Go #5877 constants.
#[cfg(test)]
pub(crate) fn parse_source_nat_rules_with_budget(
    snaps: &[SourceNATRuleSnapshot],
    previous: Option<&[SourceNatRule]>,
    nat_counters: &NatCounterStore,
    budget: &SourceNatAggregateBudget,
) -> Vec<SourceNatRule> {
    parse_source_nat_rules_inner(snaps, previous, nat_counters, budget, 0)
}

fn parse_source_nat_rules_inner(
    snaps: &[SourceNATRuleSnapshot],
    previous: Option<&[SourceNatRule]>,
    nat_counters: &NatCounterStore,
    budget: &SourceNatAggregateBudget,
    now_ns: u64,
) -> Vec<SourceNatRule> {
    // Persistent SNAT allocator state is helper-local runtime state. A
    // compatible in-process refresh may reuse the previous allocator below,
    // but a helper cold start passes `None` here and intentionally resets live
    // tuple ownership, persistent leases, and allocator counters instead of
    // replaying unproven translated tuple ownership.
    let mut out = Vec::with_capacity(snaps.len());
    let mut pendings: Vec<Option<PendingPoolAllocator>> = Vec::with_capacity(snaps.len());
    let mut previous_allocators = FxHashMap::<SourceNatPoolAllocatorKey, PortAllocator>::default();
    // #6765: the PARTIAL-OVERLAP index, keyed by pool NAME rather than by the
    // whole address list. `previous_allocators` above is the exact-match reuse
    // path and is unchanged; this one exists to answer a different question —
    // "was there a previous allocator for this same pool whose address list has
    // since changed?" — which the exact key can never answer, because a changed
    // list is precisely what makes it miss.
    //
    // A pool name that resolved to MORE THAN ONE distinct address list in the
    // previous generation is ambiguous, and re-seeding from an arbitrary one of
    // them would carry ownership from a pool the operator may not have meant.
    // Such a name is recorded as ambiguous and re-seeds nothing.
    let mut previous_pools = FxHashMap::<String, Option<PreviousPool>>::default();
    if let Some(prev_rules) = previous {
        for prev in prev_rules {
            // #7717: keyed on `drain_allocator_key`, which ignores
            // `pool_failure`. A QUARANTINED pool's allocator must survive into
            // the next generation or its live flows lose the state that
            // releases them. Widening only: a healthy pool keys identically.
            if let Some(key) = prev.drain_allocator_key() {
                previous_allocators
                    .entry(key)
                    .or_insert_with(|| prev.pool_allocator.clone());
            }
            if prev.pool_name.is_empty() || !prev.pool_mode {
                continue;
            }
            let candidate = PreviousPool {
                addresses_v4: prev.pool_addresses_v4.clone(),
                addresses_v6: prev.pool_addresses_v6.clone(),
                allocator: prev.pool_allocator.clone(),
            };
            match previous_pools.get_mut(&prev.pool_name) {
                None => {
                    previous_pools.insert(prev.pool_name.clone(), Some(candidate));
                }
                Some(Some(existing))
                    if existing.addresses_v4 == candidate.addresses_v4
                        && existing.addresses_v6 == candidate.addresses_v6 => {}
                Some(slot) => *slot = None,
            }
        }
    }
    for snap in snaps {
        let timeout_secs = if snap.persistent_nat_inactivity_timeout > 0 {
            snap.persistent_nat_inactivity_timeout
        } else {
            DEFAULT_PERSISTENT_NAT_TIMEOUT_SECS
        };
        let mut rule = SourceNatRule {
            name: snap.name.clone(),
            from_zone: snap.from_zone.clone(),
            to_zone: snap.to_zone.clone(),
            from_interface: snap.from_interface.clone(),
            to_interface: snap.to_interface.clone(),
            from_routing_instance: snap.from_routing_instance.clone(),
            to_routing_instance: snap.to_routing_instance.clone(),
            interface_mode: snap.interface_mode,
            off: snap.off,
            pool_name: snap.pool_name.clone(),
            pool_mode: !snap.pool_name.is_empty() || !snap.pool_addresses.is_empty(),
            // #3906: `port no-translation` preserves the source port.
            no_translation: snap.pool_no_translation,
            address_persistent: snap.address_persistent,
            persistent_nat: snap.persistent_nat,
            // #2823: prefer the enum string; fall back to the legacy bool.
            persistent_nat_permit: PersistentNatPermit::from_wire(
                &snap.persistent_nat_permit,
                snap.persistent_nat_permit_any_remote_host,
            ),
            persistent_nat_inactivity_timeout_secs: timeout_secs,
            persistent_nat_timeout_ns: (timeout_secs as u64).saturating_mul(NS_PER_SEC),
            // #2218: resolve the per-rule hit counter (None for counter_id 0).
            hit_counter: nat_counters.rule_counter(snap.counter_id),
            ..SourceNatRule::default()
        };
        // #2398: record whether each match set was scoped at all (snapshot list
        // non-empty), independent of how many prefixes parse. These flags drive
        // the fail-closed distinction in `nets_match_*`: a rule that WAS scoped
        // but whose configured prefixes ALL fail to parse must match NOTHING,
        // not collapse to match-any (the pre-#2398 fail-open broadening). An
        // unscoped (empty) set keeps "match any" (anti-over-restrict).
        rule.source_constrained = !snap.source_addresses.is_empty();
        rule.destination_constrained = !snap.destination_addresses.is_empty();
        // #2398: parse each match prefix as a CIDR, falling back to a bare host
        // IP -> /32 (v4) or /128 (v6). Junos carries source/destination-address
        // verbatim and the Go compiler does NOT normalize it, so a bare host
        // reaches the wire with no `/prefix`; `IpNet::from_str` REQUIRES
        // `addr/prefix` and rejects a bare IP. Without the fallback a bare-host
        // match would skip its only entry, leave the list empty, and (pre-#2398)
        // silently match ANY address — the exact fail-open this fix closes (and
        // the same bare-IP live bug fixed for DNAT in #2394).
        for prefix in &snap.source_addresses {
            parse_match_prefix(
                prefix,
                &mut rule.source_v4,
                &mut rule.source_v6,
                nat_counters,
                &snap.name,
                "source-address",
            );
        }
        for prefix in &snap.destination_addresses {
            parse_match_prefix(
                prefix,
                &mut rule.destination_v4,
                &mut rule.destination_v6,
                nat_counters,
                &snap.name,
                "destination-address",
            );
        }
        // #3429: source-NAT L4 match constraints. `match destination-port`
        // ranges and the pre-expanded `match application` terms. Ranges are kept
        // VERBATIM — including a deliberately impossible `low > high` range,
        // which `port_in_ranges` can never satisfy. The Go builder emits exactly
        // such a range (natNeverMatchPortRange = {1,0}) as a fail-CLOSED sentinel
        // when a port constraint was configured but every value is out of range:
        // dropping it here would empty the list, and an empty list is read as
        // "unconstrained" by `l4_matches` (match any port) — re-opening the
        // fail-open this fix closes (AGY finding on PR #3471). A non-empty list
        // that is purely such sentinels therefore matches NOTHING; an empty list
        // (no constraint configured) leaves the rule unconstrained on that axis.
        for r in &snap.match_destination_ports {
            rule.match_dst_ports.push((r.low, r.high));
        }
        for term in &snap.match_applications {
            let ports = term.ports.iter().map(|r| (r.low, r.high)).collect();
            // #3491: source-port ranges are kept VERBATIM, same as the
            // destination-port ranges above — including a deliberately
            // impossible `low > high` never-match sentinel the Go builder emits
            // when the application configured a source-port that coalesced to
            // nothing. Dropping such a range would empty the list and re-open the
            // source-port over-match.
            let src_ports = term.src_ports.iter().map(|r| (r.low, r.high)).collect();
            rule.match_apps.push(SourceNatAppTerm {
                protocol: term.protocol,
                ports,
                src_ports,
            });
        }
        // Parse pool addresses and port range for pool-mode SNAT.
        let mut invalid_pool_address = false;
        for addr_str in &snap.pool_addresses {
            // #3049: a pool entry may be a bare IP, a host CIDR (/32, /128), or
            // a subnet CIDR. A subnet must enumerate the FULL prefix range — the
            // pre-#3049 code stripped the mask and kept only the network host, so
            // a `203.0.113.0/28` pool collapsed to a single address. A single-
            // host prefix still yields exactly one address.
            if !expand_pool_address(
                addr_str,
                &mut rule.pool_addresses_v4,
                &mut rule.pool_addresses_v6,
            ) {
                invalid_pool_address = true;
            }
        }
        let total_pool = rule.pool_addresses_v4.len() + rule.pool_addresses_v6.len();
        let port_low = if snap.port_low > 0 {
            snap.port_low
        } else {
            1024
        };
        let port_high = if snap.port_high > 0 {
            snap.port_high
        } else {
            65535
        };
        // #6812: carry the configured (snapshot-defaulted) port range on the
        // rule itself — config, not allocator state — so the status view and
        // the allocator key keep reading it even when no allocator is built
        // (failed / over-budget pool).
        rule.pool_port_low = port_low;
        rule.pool_port_high = port_high;
        if snap.pool_unusable {
            rule.pool_failure = Some(source_nat_failure_reason_from_snapshot(
                &snap.pool_unusable_reason,
            ));
        } else if rule.pool_mode && invalid_pool_address {
            rule.pool_failure = Some(SourceNatFailureReason::InvalidPool);
        } else if rule.pool_mode && total_pool == 0 {
            rule.pool_failure = Some(if snap.pool_addresses.is_empty() {
                SourceNatFailureReason::EmptyPool
            } else {
                SourceNatFailureReason::MissingPool
            });
        } else if rule.pool_mode && port_low > port_high {
            rule.pool_failure = Some(SourceNatFailureReason::InvalidPortRange);
        }
        // #4559: deterministic CGNAT (mode 1, IPv4 subscriber). The Go compiler
        // precomputes block_size / blocks_per_ip / host_base / host_count against
        // the SAME defaulted port range this snapshot carries, so block
        // boundaries align. Only mode 1 is wired here; an unknown mode (2 = IPv6
        // subscriber / NAT64, deferred) leaves `deterministic_v4` None so the
        // pool round-robins as before (the commit-time advisory covers the gap).
        // Guard against a degenerate snapshot (blocks_per_ip 0 / block_size 0):
        // treat it as non-deterministic rather than build a pool that fails every
        // allocation.
        if snap.deterministic_mode == 1
            && snap.deterministic_block_size > 0
            && snap.deterministic_blocks_per_ip > 0
            && snap.deterministic_host_count > 0
            && !rule.pool_addresses_v4.is_empty()
            && rule.pool_failure.is_none()
        {
            rule.deterministic_v4 = Some(DeterministicV4 {
                block_size: snap.deterministic_block_size,
                blocks_per_ip: snap.deterministic_blocks_per_ip,
                host_base: snap.deterministic_host_base,
                host_count: snap.deterministic_host_count,
            });
        }
        // #6812: allocator construction is DEFERRED to `resolve_pool_allocators`
        // (reuse-before-build, nothing for a failed pool, aggregate budget
        // enforced). The parse loop only records the deferred inputs for rules
        // that pass the `allocator_key()` gate — a failed or pool-less rule
        // keeps the empty default allocator and never builds a bitmap.
        pendings.push(
            (rule.pool_mode && total_pool > 0 && rule.pool_failure.is_none()).then_some(
                PendingPoolAllocator {
                    port_low,
                    port_high,
                    total_pool,
                },
            ),
        );
        out.push(rule);
    }
    resolve_pool_allocators(
        &mut out,
        &pendings,
        &previous_allocators,
        &previous_pools,
        budget,
        now_ns,
    );
    out
}

#[allow(dead_code)]
fn source_nat_runtime_compatible(new_rule: &SourceNatRule, old_rule: &SourceNatRule) -> bool {
    new_rule.name == old_rule.name
        && new_rule.pool_name == old_rule.pool_name
        && new_rule.pool_mode == old_rule.pool_mode
        && new_rule.no_translation == old_rule.no_translation
        && new_rule.pool_failure == old_rule.pool_failure
        && new_rule.address_persistent == old_rule.address_persistent
        && new_rule.persistent_nat == old_rule.persistent_nat
        && new_rule.persistent_nat_permit == old_rule.persistent_nat_permit
        && new_rule.persistent_nat_inactivity_timeout_secs
            == old_rule.persistent_nat_inactivity_timeout_secs
        && new_rule.pool_addresses_v4 == old_rule.pool_addresses_v4
        && new_rule.pool_addresses_v6 == old_rule.pool_addresses_v6
        && new_rule.pool_port_low == old_rule.pool_port_low
        && new_rule.pool_port_high == old_rule.pool_port_high
}





/// #2398: parse one match prefix into the family-appropriate prefix vec. A CIDR
/// (`10.0.0.0/24`) is parsed directly; a bare host IP (`10.0.0.5`) — which
/// `IpNet::from_str` rejects — falls back to a /32 (v4) or /128 (v6). A prefix
/// that parses as neither is dropped (it narrows the match rather than widening
/// it); the `*_constrained` flag, set from the snapshot list being non-empty,
/// makes an all-malformed set fail closed in `nets_match_*`.
fn parse_match_prefix(
    prefix: &str,
    v4: &mut Vec<PrefixV4>,
    v6: &mut Vec<PrefixV6>,
    nat_counters: &NatCounterStore,
    rule_name: &str,
    axis: &str,
) {
    // #7481: normalize the prefix-length spelling before any parser sees it.
    // `ipnet` accepts `2001:db8::/064` but refuses `10.0.0.0/024` — it
    // disagrees with itself across families — and the Go gate accepts both,
    // so `/024` committed clean and was then DROPPED here, leaving a rule that
    // matched nothing. Normalizing makes every end answer the same way.
    let normalized = crate::nat::normalize_nat_prefix_len(prefix);
    let prefix: &str = &normalized;
    match prefix.parse::<IpNet>() {
        Ok(IpNet::V4(net)) => v4.push(PrefixV4::from_net(net)),
        Ok(IpNet::V6(net)) => v6.push(PrefixV6::from_net(net)),
        Err(_) => match prefix.parse::<IpAddr>() {
            Ok(IpAddr::V4(addr)) => {
                if let Ok(net) = Ipv4Net::new(addr, 32) {
                    v4.push(PrefixV4::from_net(net));
                }
            }
            Ok(IpAddr::V6(addr)) => {
                if let Ok(net) = Ipv6Net::new(addr, 128) {
                    v6.push(PrefixV6::from_net(net));
                }
            }
            // #4718: a prefix that parses as neither a CIDR nor a bare host IP
            // is dropped from the match set. The `*_constrained` flag keeps this
            // fail-closed (an all-malformed set matches NOTHING, never the
            // pre-#2398 fail-open collapse to match-any), but the drop was
            // SILENT — surface it loudly + count it so an operator sees the
            // configured match prefix that never reached the dataplane.
            Err(_) => nat_counters.record_parse_error(&format!(
                "source-NAT rule {rule_name:?}: unparseable {axis} match prefix {prefix:?}"
            )),
        },
    }
}

/// #3429: is `port` within any inclusive (low, high) range in `ranges`?
fn port_in_ranges(port: u16, ranges: &[(u16, u16)]) -> bool {
    ranges.iter().any(|&(lo, hi)| port >= lo && port <= hi)
}

/// #2398: match a v4 IP against a rule's match set.
///
/// - `constrained == false` (unscoped match set): match any IP (unchanged).
/// - `constrained == true` but `nets` empty (every configured prefix failed to
///   parse): match NOTHING — fail closed, never the pre-#2398 collapse to
///   match-any fail-open broadening.
/// - otherwise: the IP must fall in one of the parsed prefixes.
fn nets_match_v4(constrained: bool, nets: &[PrefixV4], ip: Ipv4Addr) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return false;
    }
    nets.iter().any(|net| net.contains(ip))
}

/// #2398: match a v6 IP against a rule's match set. See `nets_match_v4`.
fn nets_match_v6(constrained: bool, nets: &[PrefixV6], ip: Ipv6Addr) -> bool {
    if !constrained {
        return true;
    }
    if nets.is_empty() {
        return false;
    }
    nets.iter().any(|net| net.contains(ip))
}
