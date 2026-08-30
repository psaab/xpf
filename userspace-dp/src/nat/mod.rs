// NAT runtime module — split per #1542.
//
// The previous single-file `userspace-dp/src/nat.rs` (~1605 LOC)
// mixed six independent concerns: NatDecision (the cross-cutting
// output type), source NAT rule parsing/matching, pool-mode port
// allocator + persistent lease state machine, destination NAT
// table, static 1:1 NAT, and pool status aggregation. The split
// localizes the allocator's rollback/release/expiration invariants
// to `allocator.rs`, keeps DNAT and static NAT tables in their own
// files, and aggregates pool status alongside the cross-cutting
// type at the module root.
//
// Submodules are intentionally private; `mod.rs` is the curated
// public namespace and re-exports the `pub(crate)` symbols that
// external callers reach as `crate::nat::*`. Cross-submodule
// internal items use `pub(super)` and are NOT re-exported here.
//
// #6988: `source` is itself a directory now. It reached 3315 LOC —
// the [REFACTOR] tier is 2000 — so six clusters moved into
// `source/{failure,expand,release,synced,nat64_ports,match_rules}.rs`
// as PURE CODE MOTION, leaving `source/mod.rs` at 1367. The clusters
// were chosen by dependency COST, not by name: the whole split needs
// two visibility widenings and one respelling, all enumerated in
// `source/mod.rs` and machine-checked by
// `scripts/verify-nat-source-split-6988.py`, which reconstructs the
// pre-split file byte-for-byte.
//
// A CAUTION this split paid for: `pub(super)` means something
// different at each depth. `expand_pool_address` was `pub(super)` in
// `nat::source` — i.e. visible HERE — and moving it one level deeper
// silently narrowed it to `pub(in crate::nat::source)`, breaking
// `tests_aggregate_budget.rs` with E0603. Anything moved deeper that
// this module still names must be spelled `pub(in crate::nat)`.

use crate::protocol::NatRuleCounterStatus;
use rustc_hash::FxHashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

mod allocator;
mod destination;
// #6751 PR 2/3: the node-lifetime interface-mode translated-identity registry.
mod iface_registry;
mod source;
mod static_nat;
mod status;

// Tests split out of nat/tests.rs into per-subject sibling files
/// #7481: rewrite a tolerated prefix-length spelling to its canonical decimal
/// form — `/+24`, `/024` and `/0024` all become `/24`.
///
/// THE GRAMMAR IS STATED HERE RATHER THAN INHERITED, because no parser we build
/// on is self-consistent about it. Measured over one corpus:
///
/// | literal            | Go net.ParseCIDR | ipnet::IpNet | u8::from_str |
/// |--------------------|------------------|--------------|--------------|
/// | `10.0.0.0/024`     | accept           | **reject**   | accept       |
/// | `2001:db8::/064`   | accept           | **ACCEPT**   | accept       |
/// | `2001:db8::/0064`  | accept           | reject       | accept       |
/// | `10.0.0.0/+24`     | reject           | reject       | **accept**   |
///
/// `ipnet` disagrees with ITSELF across address families on zero padding — v6
/// takes a three-digit `064`, v4 refuses `024`. Nobody would choose that; it is
/// an artifact of two parse paths inside a dependency, and it means single-
/// sourcing the Rust side onto `IpNet` still would not have produced one
/// grammar.
///
/// NORMALIZE RATHER THAN REJECT. Refusing the odd spellings is the reject-only
/// direction and would normally win, but #7145's test says why it does not
/// here: a box committed with `match source-address 1.2.3.4/024` is forwarding
/// today, and a validator widened to refuse a working value bricks that
/// operator's next commit (#1960). Both spellings are UNAMBIGUOUS, so
/// normalizing loses no information and there is no wrong interpretation to
/// pick. The danger was never the spelling — it was the DISAGREEMENT.
///
/// `pkg/config`'s `normalizeNATPrefixLen` is the twin;
/// `testdata/nat_match_prefix_corpus.txt` is the shared corpus binding them.
pub(crate) fn normalize_nat_prefix_len(s: &str) -> String {
    let Some(i) = s.find('/') else {
        return s.to_string(); // bare host address; nothing to normalize
    };
    let (addr, rest) = s.split_at(i + 1);
    let mut mask = rest.strip_prefix('+').unwrap_or(rest);
    // Strip leading zeros but keep the last digit, so "/0" survives.
    while mask.len() > 1 && mask.starts_with('0') {
        mask = &mask[1..];
    }
    format!("{addr}{mask}")
}

// (#4409, pure code motion); each is a `#[path]` child module of `nat`.
#[cfg(test)]
#[path = "tests_source.rs"]
mod tests_source;
#[cfg(test)]
#[path = "tests_static.rs"]
mod tests_static;
#[cfg(test)]
#[path = "tests_destination.rs"]
mod tests_destination;
#[cfg(test)]
#[path = "tests_pool.rs"]
mod tests_pool;
// #7481: the Rust half of the shared NAT match-prefix corpus differential.
#[cfg(test)]
#[path = "tests_prefix_corpus_7481.rs"]
mod tests_prefix_corpus_7481;
#[cfg(test)]
#[path = "tests_iface.rs"]
mod tests_iface;
#[cfg(test)]
#[path = "tests_iface_pool_overlap_7717.rs"]
mod tests_iface_pool_overlap_7717;
#[cfg(test)]
#[path = "tests_pool_overlap_6979.rs"]
mod tests_pool_overlap_6979;
#[cfg(test)]
#[path = "tests_iface_pool_drain_7717.rs"]
mod tests_iface_pool_drain_7717;
#[cfg(test)]
#[path = "tests_counter.rs"]
mod tests_counter;
#[cfg(test)]
#[path = "tests_dnat_proto.rs"]
mod tests_dnat_proto;
#[cfg(test)]
#[path = "tests_scope.rs"]
mod tests_scope;
#[cfg(test)]
#[path = "tests_l4_match.rs"]
mod tests_l4_match;
#[cfg(test)]
#[path = "tests_aggregate_budget.rs"]
mod tests_aggregate_budget;

// #4800: SNAT pool allocator `live` map-mutex contention accounting.
#[cfg(test)]
#[path = "tests_newflow_lock.rs"]
mod tests_newflow_lock;

/// #3096: per-flow interface / routing-instance identity passed into the NAT
/// match path so an interface- or routing-instance-scoped rule-set matches
/// only its named traffic. The forwarding layer resolves each ifindex to its
/// config name and routing-instance (VRF) before matching; the strings are
/// borrowed for the duration of the lookup (no per-flow allocation). All
/// fields default to "" (the unscoped / default-VRF case), so a zone-only or
/// global rule-set is unaffected.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NatScopeCtx<'a> {
    pub(crate) ingress_ifname: &'a str,
    pub(crate) egress_ifname: &'a str,
    pub(crate) ingress_routing_instance: &'a str,
    pub(crate) egress_routing_instance: &'a str,
}

pub(crate) use allocator::{
    DeterministicV6, MAX_NAT_HOLDER_WORKERS, NatHolder, PortAllocator, PortAllocatorSnapshot,
};
pub(crate) use destination::{DnatKey, DnatTable, DnatValue};
pub(crate) use iface_registry::{
    INTERFACE_SNAT_IDENTITY_EXHAUSTION, INTERFACE_SNAT_PAT_COLLISIONS,
    INTERFACE_SNAT_REGISTRY_CAP_EXHAUSTION, INTERFACE_SNAT_SYNC_IDENTITY_CONFLICT_DROPS,
    InterfaceNatAllocators,
};
pub(crate) use allocator::allocator_capacity;
pub(crate) use source::{
    MAX_POOL_PREFIX_HOSTS,
    SourceNatFailure, SourceNatFailureReason, SourceNatFlowKey, SourceNatLookup, SourceNatRule,
    SyncedNatZones, allocate_nat64_pool_port, allocate_nat64_pool_port_deterministic_v6,
    match_source_nat,
    match_source_nat_result, match_source_nat_result_for_tuple, parse_source_nat_rules,
    parse_source_nat_rules_with_previous, release_nat64_pool_port,
    release_source_nat_allocation, release_source_nat_allocation_for_worker,
    reserve_nat64_pool_port, reserve_synced_source_nat_allocation_for_worker,
    // #6600: the coordinator's pre-publish reservation and its rollback. NOT
    // test-only, unlike the untracked entry points below — these are the
    // production import path.
    reserve_synced_source_nat_allocation_untracked, retained_pool_index_map,
    retained_pool_index_map_v4,
    rollback_source_nat_allocation_for_worker,
};
// #6211 F2: test-only untracked entry points (see their doc comments).
#[cfg(test)]
pub(crate) use source::{reserve_synced_source_nat_allocation, rollback_source_nat_allocation};
pub(crate) use source::retire_worker_from_pool_rules;
// #6979: reachable from the afxdp coordinator test that binds the retirement
// wiring; the primitive itself stays covered by nat::tests_pool.
pub(crate) use allocator::TranslatedTuple;
pub(crate) use static_nat::{StaticNatEntry, StaticNatTable};
pub(crate) use status::source_nat_pool_statuses;

/// NatDecision is the cross-cutting output type for every NAT
/// concern (DNAT, SNAT, static, NAT64, NPTv6). It lives at the
/// `nat` module root because it is the only type all submodules
/// produce or consume. Wire-serialized over the HA fabric via
/// `SessionDecision`/`SessionDelta`; field shape and derive set
/// must be preserved bit-for-bit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NatDecision {
    pub(crate) rewrite_src: Option<IpAddr>,
    pub(crate) rewrite_dst: Option<IpAddr>,
    pub(crate) rewrite_src_port: Option<u16>,
    pub(crate) rewrite_dst_port: Option<u16>,
    /// When true, this is a NAT64 cross-address-family translation.
    /// The forward session key is IPv6 and the reverse session key is IPv4
    /// (or vice versa for the return direction).
    pub(crate) nat64: bool,
    /// When true, this is an NPTv6 (RFC 6296) stateless prefix translation.
    /// No L4 checksum update is needed -- the prefix rewrite is checksum-neutral.
    pub(crate) nptv6: bool,
}

impl NatDecision {
    pub(crate) fn reverse(
        self,
        original_src: IpAddr,
        original_dst: IpAddr,
        original_src_port: u16,
        original_dst_port: u16,
    ) -> Self {
        Self {
            rewrite_src: self.rewrite_dst.map(|_| original_dst),
            rewrite_dst: self.rewrite_src.map(|_| original_src),
            rewrite_src_port: self.rewrite_dst_port.map(|_| original_dst_port),
            rewrite_dst_port: self.rewrite_src_port.map(|_| original_src_port),
            nat64: self.nat64,
            nptv6: self.nptv6,
        }
    }

    /// Merge two NAT decisions, preferring fields already set in `self`.
    /// Used to combine a pre-routing DNAT decision with a post-policy SNAT decision.
    pub(crate) fn merge(self, other: NatDecision) -> Self {
        Self {
            rewrite_src: self.rewrite_src.or(other.rewrite_src),
            rewrite_dst: self.rewrite_dst.or(other.rewrite_dst),
            rewrite_src_port: self.rewrite_src_port.or(other.rewrite_src_port),
            rewrite_dst_port: self.rewrite_dst_port.or(other.rewrite_dst_port),
            nat64: self.nat64 || other.nat64,
            nptv6: self.nptv6 || other.nptv6,
        }
    }
}

/// #2218: one per-rule NAT translation hit counter. Lock-free atomic
/// packets+bytes pair, captured at rule-build time as an `Arc` and
/// incremented from the cold (session-miss) path only — exactly the
/// `PolicyRuleCounter` pattern (policy.rs). `add` is the only mutation on
/// the increment side: a single `fetch_add(1)` for packets plus a
/// conditional bytes add, no allocation, no lock.
///
/// #3830 — `reset` (operator `clear` of NAT hit counters) removes the
/// observed pre-clear total with an atomic `fetch_sub` rather than a
/// `store(0)`. A `store(0)` unconditionally overwrites the field, so a
/// per-flow `add` (the cold-path relaxed `fetch_add`) landing in the same
/// instant as a `clear` would be clobbered — the clear silently ate a real
/// post-clear hit. `fetch_sub(observed)` subtracts only the amount `reset`
/// read: because both the increment and the subtraction are atomic RMWs on
/// the same location they serialize in the modification order (no lost
/// update), so a concurrent post-clear increment survives. This mirrors the
/// #3782 `PolicyRuleCounter::reset` fix; it is NARROWER here — the NAT
/// counter increments once per-flow on the cold path with no coalescer and
/// no generation/epoch guard, so there is no pending-batch replay to fence.
/// Like the policy counter it keeps the write side off a lock/seqcount
/// (#3451); the only residual is a bounded ns-scale attribution skew for a
/// count landing exactly at the clear instant, consistent with the
/// advisory-telemetry eventual-consistency contract these counters accept.
#[derive(Debug, Default)]
pub(crate) struct NatRuleCounter {
    packets: AtomicU64,
    bytes: AtomicU64,
}

impl NatRuleCounter {
    /// Count one committed translated flow: +1 packet and +packet_len bytes.
    /// Per-flow semantic (not per-packet) — fired once when a new translated
    /// session is installed, so the bytes are the trigger packet's length.
    #[inline]
    pub(crate) fn add(&self, packet_len: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        if packet_len != 0 {
            self.bytes.fetch_add(packet_len, Ordering::Relaxed);
        }
    }

    fn reset(&self) {
        // #3830: observe the current (pre-clear) totals, then remove EXACTLY
        // that amount with an atomic `fetch_sub` rather than `store(0)`.
        //
        // A `store(0)` unconditionally overwrites the field, so a legitimate
        // per-flow hit recorded by a worker on the cold path in the same
        // instant as this clear (a relaxed `fetch_add` via `add`) would be
        // clobbered — the clear silently ate a real post-clear packet.
        // `fetch_sub(observed)` subtracts only the pre-clear amount we read:
        // whatever a concurrent worker `fetch_add`s survives, because both
        // are atomic RMWs on the same location and serialize in the
        // modification order (no lost update). See the type doc and #3782
        // (`PolicyRuleCounter::reset`, the same clobber class).
        let observed_packets = self.packets.load(Ordering::Relaxed);
        let observed_bytes = self.bytes.load(Ordering::Relaxed);
        self.subtract_observed(observed_packets, observed_bytes);
    }

    /// #3830: remove exactly `observed_*` from the shared totals with atomic
    /// `fetch_sub`s rather than a `store(0)` (see [`reset`](Self::reset) for
    /// why). Split out as the clear's subtraction step so the reset/increment
    /// interleaving can be driven deterministically in tests: the invariant is
    /// that a concurrent post-clear `add` applied between the observation in
    /// `reset` and this call is preserved, not wiped.
    ///
    /// `observed_*` is always `<=` the current total — the cold-path increment
    /// only ever `fetch_add`s (monotonic) and `reset` is the sole subtractor,
    /// called from `NatCounterStore::clear` under the registry mutex so clears
    /// are serialized — therefore neither `fetch_sub` can underflow.
    #[inline]
    fn subtract_observed(&self, observed_packets: u64, observed_bytes: u64) {
        if observed_packets != 0 {
            self.packets.fetch_sub(observed_packets, Ordering::Relaxed);
        }
        if observed_bytes != 0 {
            self.bytes.fetch_sub(observed_bytes, Ordering::Relaxed);
        }
    }

    pub(crate) fn snapshot(&self, counter_id: u32) -> NatRuleCounterStatus {
        NatRuleCounterStatus {
            counter_id,
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

type NatCounterRegistry = FxHashMap<u32, Arc<NatRuleCounter>>;

/// #2218: registry of per-rule NAT hit counters keyed by the
/// compiler-assigned `counter_id`. Cheaply cloneable (`Arc`), so the
/// coordinator owns one and threads `&self.nat_counters` into the
/// forwarding-state build, exactly mirroring `PolicyCounterStore`.
/// `counter_id == 0` is the "no per-rule counter" sentinel and is never
/// stored — `rule_counter(0)` returns `None`.
///
/// #2255: the `counter_id` is a STABLE key-derived hash (a function of the
/// rule's identity, not its config position), so a config reorder/removal can
/// no longer reuse a numeric id for a different rule. `reconcile_ids` retains
/// only the ids present in the new snapshot, and a retained id always refers to
/// the SAME rule it did before — no cross-rule mis-attribution by construction.
#[derive(Clone, Debug, Default)]
pub(crate) struct NatCounterStore {
    counters: Arc<Mutex<NatCounterRegistry>>,
    /// #4718: cumulative count of NAT reconcile PARSE failures — a rule or
    /// match prefix the Go control plane sent whose IP/prefix/pool field this
    /// helper could not parse, so the offending rule/prefix was dropped from
    /// the rebuilt forwarding state. Shared behind an `Arc` so a clone handed
    /// to `from_snapshots` increments the SAME atomic the coordinator (and the
    /// fail-on-revert test) reads. Monotonic error counter, not a gauge: it is
    /// only bumped, never reset by a reconcile.
    parse_errors: Arc<AtomicU64>,
    /// #6823: the `record_parse_error` DETAILS, captured in test builds so a
    /// test can bind what the operator is told and not merely how many drops
    /// happened. Two drops with different causes are indistinguishable by
    /// `parse_errors` alone, and the message is the whole operator-facing
    /// half of #4718's loud-skip doctrine — an actionless DNAT rule reported
    /// as an "unparseable pool address" sends someone hunting a
    /// serialization bug instead of the malformed config rule that
    /// `xpf_nat_rules_lenient_terminal_action` (#7640) is already flagging.
    /// Compiled out of production builds entirely.
    #[cfg(test)]
    parse_error_details: Arc<Mutex<Vec<String>>>,
}

impl NatCounterStore {
    /// Resolve (get-or-insert) the shared counter for `counter_id`. Returns
    /// `None` for the reserved id 0 so a rule without a per-rule counter
    /// carries `hit_counter: None` and the increment site skips it.
    pub(crate) fn rule_counter(&self, counter_id: u32) -> Option<Arc<NatRuleCounter>> {
        if counter_id == 0 {
            return None;
        }
        // #6568 (member 6): a poisoned lock must not PANIC here. This runs on
        // the NAT translation path, so `.expect` turned one unrelated panic
        // (whatever poisoned the mutex) into a panic on every subsequent
        // packet that consults a rule counter — panic amplification that
        // converts a single worker fault into a forwarding outage.
        //
        // A counter is DIAGNOSTIC state: losing an increment is a reporting
        // gap, never a forwarding decision. Recover the guard and carry on —
        // `PoisonError::into_inner` yields the map, which is structurally
        // intact (the poisoning thread panicked, it did not corrupt the
        // BTreeMap), so the counters keep working through the incident.
        let mut counters = match self.counters.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(counter) = counters.get(&counter_id) {
            return Some(counter.clone());
        }
        let counter = Arc::new(NatRuleCounter::default());
        counters.insert(counter_id, counter.clone());
        Some(counter)
    }

    /// #6995: the stored counter ids, for the rejected-build rollback in
    /// `forwarding_build`.
    ///
    /// `rule_counter` GET-OR-INSERTS, and the source / static / destination NAT
    /// reconcilers call it inside the fallible builder AHEAD of the NPTv6,
    /// filter and CoS belts — so a build those belts reject used to leave a row
    /// per candidate-only NAT rule behind here. Unlike the policy half that is
    /// NOT memory-only: `snapshots()` below emits one row per stored id
    /// regardless of value, and that feeds `ProcessStatus.nat_rule_counters`,
    /// so the residue reached the operator status surface. The builder captures
    /// this set before it starts and restores it via `reconcile_ids` on `Err`.
    pub(crate) fn tracked_ids(&self) -> Vec<u32> {
        let Ok(counters) = self.counters.lock() else {
            return Vec::new();
        };
        let mut ids: Vec<u32> = counters.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Retain only counters whose id is in `active_ids`, dropping the
    /// `Arc<NatRuleCounter>` for rules removed by a config change. Mirrors
    /// `PolicyCounterStore::reconcile_rules`.
    ///
    /// #6995 also uses this as the rejected-build ROLLBACK, passing the id set
    /// captured before the build. That reuse is sound because the operation is
    /// a retain: handing it the pre-build set can only evict ids the rejected
    /// build itself created, never a row carrying live cumulative totals.
    pub(crate) fn reconcile_ids(&self, active_ids: &[u32]) {
        let active: rustc_hash::FxHashSet<u32> =
            active_ids.iter().copied().filter(|&id| id != 0).collect();
        if let Ok(mut counters) = self.counters.lock() {
            counters.retain(|id, _| active.contains(id));
        }
    }

    /// Reset every stored counter to zero (operator `clear` of NAT hit
    /// counters). Mirrors `PolicyCounterStore::clear`.
    pub(crate) fn clear(&self) {
        if let Ok(counters) = self.counters.lock() {
            for counter in counters.values() {
                counter.reset();
            }
        }
    }

    /// One status row per stored counter_id, regardless of whether its
    /// packet/byte value is zero. Every stored id is non-zero: counter_id 0 is
    /// the "no per-rule counter" sentinel and is never stored (see
    /// `rule_counter`), so it never appears as a row. Matches
    /// `PolicyState::counter_snapshots`, which emits one row per rule.
    pub(crate) fn snapshots(&self) -> Vec<NatRuleCounterStatus> {
        let Ok(counters) = self.counters.lock() else {
            return Vec::new();
        };
        counters
            .iter()
            .map(|(&id, counter)| counter.snapshot(id))
            .collect()
    }

    /// #4718: record one NAT reconcile PARSE failure and surface it LOUDLY.
    ///
    /// The three sibling NAT snapshot reconcilers — `DnatTable::from_snapshots`
    /// (destination.rs), `StaticNatTable::from_snapshots` (static_nat.rs), and
    /// `parse_source_nat_rules_with_previous` via `parse_match_prefix`
    /// (source.rs) — drop a rule or match prefix whose IP/prefix/pool field the
    /// Go control plane emitted but this helper cannot parse. That data path is
    /// an INTERNAL inconsistency: the Go commit-check already validates operator
    /// config, so an unparseable field here means a mixed-version peer-sync, a
    /// serialization bug, or a missed Go validation edge — never an
    /// operator-present commit. The correct posture is defense-in-depth: DROP
    /// ONLY the bad rule so the VALID rules in the same batch still install (a
    /// single malformed rule must not take down all NAT — that would be a worse
    /// availability outcome than one silently-absent translation), but make the
    /// drop OBSERVABLE.
    ///
    /// Pre-#4718 each of these skips was a bare `continue`/`{}` with no
    /// diagnostic, so an operator debugging a config/sync drift got ZERO signal
    /// that a NAT rule had vanished. This restores the loud-skip doctrine the
    /// NAT64 builder already documents and follows (nat64.rs #3888): the
    /// `eprintln!` reaches journald via stderr and NAMES the offending rule +
    /// field; the atomic counter is a cumulative metric and the testable seam
    /// the fail-on-revert test asserts. These reconcilers run only during
    /// control-plane config apply / peer-sync, never the packet hot path, so
    /// the log adds no forwarding latency.
    pub(crate) fn record_parse_error(&self, detail: &str) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        if let Ok(mut d) = self.parse_error_details.lock() {
            d.push(detail.to_string());
        }
        eprintln!("xpf nat reconcile: dropping rule (unparseable field): {detail}");
    }

    /// #6823: the details recorded by [`record_parse_error`](Self::record_parse_error),
    /// in call order. The testable seam for the MESSAGE, alongside
    /// [`parse_errors`](Self::parse_errors) for the count.
    #[cfg(test)]
    pub(crate) fn parse_error_details(&self) -> Vec<String> {
        self.parse_error_details
            .lock()
            .map(|d| d.clone())
            .unwrap_or_default()
    }

    /// #4718: cumulative NAT reconcile parse-failure count (see
    /// [`record_parse_error`](Self::record_parse_error)). A `> 0` value means
    /// at least one configured NAT rule/prefix was dropped at the helper
    /// boundary and did NOT reach the dataplane. The operator-facing surface is
    /// the per-drop `eprintln!` (journald); this accessor is the testable seam
    /// the fail-on-revert tests assert, so it is gated to test builds to avoid
    /// a dead-code warning until a metrics surface consumes it.
    #[cfg(test)]
    pub(crate) fn parse_errors(&self) -> u64 {
        self.parse_errors.load(Ordering::Relaxed)
    }
}
