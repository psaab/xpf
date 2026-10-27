//! NAT64 prefix/state construction and matching.
//!
//! `Nat64Prefix` / `Nat64State` built from config snapshots, the
//! aggregate allocator budget, and the forward/reverse match verdicts.
//!
//! #16188 PURE CODE MOTION: every line below was moved verbatim from
//! `nat64.rs` lines 198-2069. The only edits are the visibility
//! widenings enumerated in `nat64/mod.rs`; no logic, no ordering and
//! no signature changed.

use super::*;

/// #4381: NAT64 DEFAULT translated-port allocation range. RFC 6146 does not
/// mandate a specific range; the ephemeral 1024..=65535 window (matching the
/// pool-mode SNAT default) maximizes the distinct-flow capacity behind a
/// single pool address while staying clear of the well-known ports. A
/// source pool referenced by a NAT64 rule-set may narrow it with its own
/// `port range` (#15283, `NAT64RuleSnapshot.port_low/port_high`); the
/// allocator then honours that window. The constants remain the fallback
/// when the snapshot carries no range (port_low == 0).
pub(super) const NAT64_PORT_LOW: u16 = 1024;
pub(super) const NAT64_PORT_HIGH: u16 = 65535;

/// #15283: the effective translated-port range for one NAT64 rule: the
/// snapshot's pool `port range` when it carries a valid one, else the fixed
/// default. A hand-crafted or peer-synced snapshot can carry a zero,
/// reversed, or otherwise invalid pair (the Go builder never stamps one on
/// a usable pool — it marks the pool unusable instead); falling back to the
/// default keeps the allocator total rather than building a zero-range
/// allocator that would refuse every flow for a reason the operator never
/// configured.
pub(crate) fn nat64_effective_port_range(snap: &NAT64RuleSnapshot) -> (u16, u16) {
    if snap.port_low != 0 && snap.port_high != 0 && snap.port_low <= snap.port_high {
        (snap.port_low, snap.port_high)
    } else {
        (NAT64_PORT_LOW, NAT64_PORT_HIGH)
    }
}

fn nat64_pool_index(pool: &[Ipv4Addr]) -> Arc<FxHashMap<Ipv4Addr, usize>> {
    let mut index = FxHashMap::default();
    index.reserve(pool.len());
    for (position, address) in pool.iter().enumerate() {
        index.entry(*address).or_insert(position);
    }
    Arc::new(index)
}

/// NAT64 prefix configuration — one per `security nat nat64` rule.
#[derive(Debug)]
pub(crate) struct Nat64Prefix {
    /// #16484: the snapshot rule-set name. The live reload lookups
    /// (allocator reuse, deterministic probe, #6765 reseed) key on
    /// this identity so several scoped rule-sets sharing one /96
    /// never select a sibling's allocator. Empty only for prefixes
    /// built outside the snapshot loop (test constructors).
    pub(crate) name: String,
    /// First 96 bits of the NAT64 prefix (e.g. 64:ff9b::).
    pub(crate) prefix_bytes: [u8; 12],
    /// #15678: optional ingress scoping, resolved once at build by
    /// `union_scope` (the singular pre-#15932/#16049 wire spellings are
    /// folded into these lists, so no singular copy survives on the
    /// built prefix). Empty list = unscoped on that axis.
    /// `source_prefixes` empty = match any IPv6 source; a rule that AUTHORED
    /// source entries but every one failed to parse sets
    /// `source_constrained` with an empty vec and matches NOTHING (never
    /// silently widened to any-source).
    /// #15932: every authored zone for this prefix (the union).
    pub(crate) from_zones: Vec<String>,
    /// #16049: every authored routing-instance for this prefix (the
    /// union).
    pub(crate) from_routing_instances: Vec<String>,
    pub(crate) source_prefixes: Vec<PrefixV6>,
    pub(crate) source_constrained: bool,
    /// IPv4 source pool addresses for SNAT.
    pub(crate) pool_v4: Vec<Ipv4Addr>,
    /// #16537: contiguous spans covering `pool_v4`, computed once at build.
    pub(crate) pool_ranges_v4: Vec<(Ipv4Addr, Ipv4Addr)>,
    /// Live-drain allocators whose configured pool intersects this prefix's
    /// `pool_v4`; occupancy is time-varying, but this address relation is not.
    pub(crate) draining_pool_allocators: Vec<PortAllocator>,
    /// Address-to-position index; `pool_v4` remains the allocator's ordering.
    pub(crate) pool_index_v4: Arc<FxHashMap<Ipv4Addr, usize>>,
    /// Round-robin index for pool allocation (atomic for thread safety).
    ///
    /// #4381: retained for the empty-pool / liveness probe only. The
    /// authoritative source selection is now the stateful `port_allocator`,
    /// which picks the pool address AND a unique translated port together.
    pool_index: AtomicUsize,
    /// #4381: stateful pool-mode allocator that hands every NAT64 forward flow
    /// a UNIQUE `(pool v4 address, translated L4 port / ICMP identifier)`. Two
    /// v6 clients sharing a source port behind one pool address get distinct
    /// translated ports, so their reverse (v4→v6) tuples never collide (the
    /// RFC 6146 BIB). Reuses the exact `PortAllocator` the pool-mode source-NAT
    /// path uses (`nat/allocator.rs`); the `Arc`-backed live state is SHARED
    /// across the per-worker `Nat64State` clones, so a port claimed on one
    /// worker is visible to every other worker.
    pub(crate) port_allocator: PortAllocator,
    /// #4559: IPv6-subscriber deterministic CGNAT (mode 2, NAPT64). `Some` when
    /// the referenced source pool carries `port deterministic` with an enforced
    /// IPv6 host (/32 or /64 prefix); the forward `allocate_source` then maps
    /// each IPv6 subscriber to a fixed external IPv4 + port block
    /// (`allocate_deterministic_v6`) instead of round-robin PAT, so the
    /// `(external IPv4, port)` → subscriber reverse needs no per-flow log
    /// (lawful-intercept / CGN audit). `None` => the pre-#4559 round-robin path.
    pub(crate) deterministic_v6: Option<DeterministicV6>,
    /// #6982: this prefix was REFUSED by the aggregate allocator budget, so it
    /// carries an empty pool and no bitmap.
    ///
    /// It is installed rather than skipped on purpose: a skipped prefix does not
    /// match, so its traffic falls through to `NoPrefixMatch` and is ROUTED as
    /// ordinary IPv6 — a memory guard that turns into a translation bypass.
    /// Installed-with-an-empty-pool drops fail-closed instead.
    ///
    /// The flag exists because that makes a refusal LOOK like the legitimate
    /// empty-pool rule the Go side emits for a no-source-pool config: both
    /// classify `MatchUnavailable`. The two have opposite remedies (raise the
    /// budget or split the config vs. add a source pool), so the state is
    /// carried explicitly rather than inferred from `pool_v4.is_empty()`.
    /// Asserted at the CONSUMPTION boundary by
    /// `nat64_6982_over_budget_is_distinguishable_from_empty_pool`.
    pub(crate) over_budget: bool,
    /// #14962: the Go-stamped pool-unusable reason when the prefix was
    /// installed with an empty pool because its source pool failed the
    /// definition verdict (SourceNATPoolUnusableReason) or the
    /// interface-SNAT overlap quarantine. Empty when the pool is usable
    /// (including the legitimate no-source-pool empty state and the
    /// #6982 over-budget refusal, whose reason is the budget itself and
    /// which is counted separately). Distinguishes the three empty-pool
    /// states at consumption, like `over_budget` does for its own.
    pub(crate) pool_unusable_reason: String,
    /// #8115 R3: which OTHER allocators cover this prefix's `pool_v4`
    /// addresses.
    ///
    /// A NAT64 prefix is its own occupancy domain — `port_allocator` is keyed by
    /// `(prefix_bytes, pool_v4)` — so a source-NAT pool sharing one of these
    /// addresses, or a second NAT64 prefix over the same pool, mints the same
    /// `X:P` for a different live flow. #6979 F6 built the peer index from
    /// source-NAT rules only, so NAT64 was never a MEMBER of it: the query
    /// worked, the domain was simply absent.
    ///
    /// `None` on every config with no cross-domain overlap, which is every
    /// config a strict commit accepts (#5144 names a source pool that also backs
    /// a NAT64 rule-set, and two rule-sets sharing a pool under different
    /// prefixes, as distinct collision owners).
    ///
    /// Populated by `wire_nat64_overlap_peers` AFTER both `source_nat_rules` and
    /// `nat64` are built — `wire_overlap_peers` runs inside
    /// `parse_source_nat_rules_with_previous`, before this state exists, which
    /// is why R3 needed a second pass rather than one more line in the first.
    pub(crate) overlap_owners: Option<std::sync::Arc<crate::nat::PoolAddressOwners>>,
    /// #14367: interface registry synced at forwarding-build (egress addrs).
    pub(crate) iface_allocs: Option<std::sync::Arc<crate::nat::InterfaceNatAllocators>>,
    /// #14367: pool+NAT64 combined index incl. interface members, for the
    /// NAT64->interface check. Synced alongside iface_allocs.
    pub(crate) iface_overlap_owners: Option<std::sync::Arc<crate::nat::PoolAddressOwners>>,
    /// #14368: the static table's external identities covering this prefix's
    /// pool (see `SourceNatRule::static_externals`). `None` on every config
    /// a strict commit accepts. Wired by `wire_static_overlap_peers`.
    pub(crate) static_externals: Option<std::sync::Arc<crate::nat::StaticExternalIdentities>>,
}

impl Nat64Prefix {
    /// #7092: minimal constructor for tests that need a prefix holding a live
    /// allocator. `pool_index` is private, so a struct literal cannot be built
    /// outside this module; this keeps that field private rather than widening
    /// it for one fixture.
    #[cfg(test)]
    pub(crate) fn for_test(
        prefix_bytes: [u8; 12],
        pool_v4: Vec<Ipv4Addr>,
        port_allocator: PortAllocator,
    ) -> Self {
        Self {
            name: String::new(),
            prefix_bytes,
            from_zones: Vec::new(),
            from_routing_instances: Vec::new(),
            source_prefixes: Vec::new(),
            source_constrained: false,
            pool_ranges_v4: crate::nat::pool_address_ranges_v4(&pool_v4),
            pool_index_v4: nat64_pool_index(&pool_v4),
            pool_v4,
            pool_index: AtomicUsize::new(0),
            port_allocator,
            deterministic_v6: None,
            over_budget: false,
            pool_unusable_reason: String::new(),
            overlap_owners: None,
            iface_allocs: None,
            iface_overlap_owners: None,
            static_externals: None,
            draining_pool_allocators: Vec::new(),
        }
    }
}

impl Clone for Nat64Prefix {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            prefix_bytes: self.prefix_bytes,
            from_zones: self.from_zones.clone(),
            from_routing_instances: self.from_routing_instances.clone(),
            source_prefixes: self.source_prefixes.clone(),
            source_constrained: self.source_constrained,
            pool_ranges_v4: self.pool_ranges_v4.clone(),
            pool_v4: self.pool_v4.clone(),
            pool_index_v4: self.pool_index_v4.clone(),
            pool_index: AtomicUsize::new(self.pool_index.load(Ordering::Relaxed)),
            // Clone shares the Arc-backed allocator state (see field doc).
            port_allocator: self.port_allocator.clone(),
            deterministic_v6: self.deterministic_v6,
            over_budget: self.over_budget,
            pool_unusable_reason: self.pool_unusable_reason.clone(),
            overlap_owners: self.overlap_owners.clone(),
            iface_allocs: self.iface_allocs.clone(),
            iface_overlap_owners: self.iface_overlap_owners.clone(),
            static_externals: self.static_externals.clone(),
            draining_pool_allocators: self.draining_pool_allocators.clone(),
        }
    }
}

/// Aggregated NAT64 state built from config snapshots.
#[derive(Clone, Debug, Default)]
pub(crate) struct Nat64State {
    pub(crate) prefixes: Vec<Nat64Prefix>,
    /// Mirrors the global `security nat natv6v4 no-v6-frag-header` option.
    /// When set, header-less IPv6→IPv4 outputs stay fragmentable regardless of
    /// size. Otherwise RFC 7915 §5.1 keys DF on the translated IPv4 total length
    /// (DF clear through 1260 bytes, set above it). The Go side replicates the
    /// global option onto every NAT64 rule snapshot.
    pub(crate) no_v6_frag_header: bool,
    /// #2562: cross-family fragment-association cache. Lets non-first NAT64
    /// fragments inherit the first fragment's translation instead of being
    /// dropped fail-closed (#4617). Arc-backed, so all per-worker clones share
    /// one cache (cross-worker visible) and it survives a config reload (the
    /// Arc is threaded in `from_snapshots_with_previous`). NOT rebuilt from the
    /// snapshot — fragment associations are runtime state, not config.
    pub(crate) frag_assoc: crate::fragment_assoc::FragAssoc,
    /// #9950 (F-035): fragment-overlap tracker. Drops overlapping fragments (RFC 5722
    /// tear-drop semantics) so enforcement never runs on bytes a later fragment rewrites.
    /// Family-neutral like `frag_assoc` post-#7899 (it was never NAT64-only either) — it
    /// hangs here only to reuse the Arc-shared cross-worker + reload-threaded lifecycle
    /// (`from_snapshots_with_previous` below); re-homing is a lifecycle change, not motion.
    pub(crate) frag_overlap: crate::fragment_overlap::OverlapTracker,
    /// #5624: the config-snapshot generation THIS state was built under. The
    /// `frag_assoc` cache is Arc-shared across config reloads (so in-flight
    /// datagrams keep translating), but each association is a per-flow
    /// deny/NAT64 verdict resolved under one config generation. A commit that
    /// changes deny/NAT64 rules bumps `snapshot.generation`, rebuilding this
    /// `Nat64State` with the new value while the shared cache still holds
    /// PRIOR-generation associations. Stamping every install and re-checking it
    /// on lookup (see `FragAssoc::install`/`lookup`) invalidates a stale
    /// association whose generation != the current one — mirroring the
    /// flow-cache `config_generation` guard (afxdp/flow_cache.rs). Lives on
    /// `Nat64State` (NOT inside the shared Arc) precisely because it must change
    /// per reload while the cache persists.
    pub(crate) build_generation: u64,
}

/// Reverse-direction state stored with NAT64 sessions so IPv4 replies can be
/// translated back to IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Nat64ReverseInfo {
    pub(crate) orig_src_v6: Ipv6Addr,
    pub(crate) orig_dst_v6: Ipv6Addr,
}

/// Tri-state result of a NAT64 destination lookup (#2291).
///
/// The pre-fix lookup collapsed "prefix matched but no source could be
/// allocated" into "no NAT64 match" (a bare `Option<...>` whose `None`
/// meant both), so a matched-but-unallocatable destination fell through to
/// ordinary IPv6 route lookup on the SYNTHETIC NAT64 destination
/// (`64:ff9b::a.b.c.d`). With a permissive default IPv6 route present, that
/// silently leaked untranslated synthetic-destination traffic upstream — a
/// fail-OPEN at the NAT64 boundary.
///
/// Splitting the result into three states lets the caller fail CLOSED on the
/// unallocatable case (drop + counter) while still routing genuinely
/// non-matching IPv6 normally. Consistent with the project's fail-closed
/// family (#2124/#2142/#2173/#2175).
impl Nat64Prefix {
    /// #16045: is this prefix constrained on an ingress-scope axis
    /// (zone / routing-instance)? Source-address constraints are tuple
    /// selectors, not ingress-identity scope.
    pub(super) fn ingress_scope_constrained(&self) -> bool {
        !self.from_zones.is_empty() || !self.from_routing_instances.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Nat64Match {
    /// The destination does not match any configured NAT64 prefix — continue
    /// ordinary IPv6 route lookup. This is the ONLY arm that routes as IPv6.
    NoPrefixMatch,
    /// A prefix matched AND its source pool is non-empty — translate.
    ///
    /// #4381: this no longer PRE-ALLOCATES a source address. The pre-fix code
    /// round-robin-picked a pool address here (before the security policy ran),
    /// but the authoritative selection is now the stateful per-flow allocation
    /// at the Permit branch (`Nat64State::allocate_source`), which picks the
    /// pool address AND a unique translated port/identifier together — only
    /// after the flow is admitted. This arm now just confirms the prefix
    /// matched and a pool exists; the route lookup keys on `dst_v4` (the
    /// destination), not the source, so no source is needed this early.
    MatchReady {
        /// Index of the matched NAT64 prefix in `prefixes`.
        prefix_idx: usize,
        /// IPv4 destination extracted from the synthetic NAT64 address.
        dst_v4: Ipv4Addr,
        /// Original synthetic IPv6 destination (kept for the reverse path).
        dst_v6: Ipv6Addr,
    },
    /// A prefix matched but its source pool is empty (a legitimate wire state
    /// the Go side emits for a no-source-pool rule) OR the stateful allocator
    /// is exhausted. The packet MUST be dropped, not routed as IPv6.
    MatchUnavailable,
    /// #5623: the IPv6 SOURCE is Pref64-INELIGIBLE — it lies within a configured
    /// NAT64 prefix, i.e. a looping/synthesized "already-translated" source (the
    /// RFC 6146 §5 hairpin-loop construction). RFC 6146 §3.5 mandates dropping
    /// every incoming IPv6 packet whose source contains Pref64. The high-96-bit
    /// match subsumes the degenerate boundaries the issue calls out — the lower
    /// boundary `<prefix>::` (embedded v4 `0.0.0.0`), the upper boundary
    /// `<prefix>::ffff:ffff` (embedded v4 `255.255.255.255`), and any source
    /// whose embedded v4 is non-global/looping (still inside the prefix). The
    /// caller MUST drop fail-closed with a distinct counter BEFORE route lookup,
    /// policy, or `allocate_source`, so no session/BIB/allocation state is minted
    /// for a spoofed or looping source. A legitimate global-unicast source
    /// outside every Pref64 never reaches this arm, so eligible traffic is
    /// untouched.
    IneligibleSource,
    /// #6475: the extracted embedded IPv4 DESTINATION is non-global per
    /// RFC 6052 §3.1 — one of `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`,
    /// `224.0.0.0/4`, or `240.0.0.0/4` (which subsumes `255.255.255.255/32`).
    /// Pre-gate, `64:ff9b::127.0.0.1` classified `MatchReady(127.0.0.1)` and,
    /// with lo0 configured, resolved LocalDelivery to the localhost-only
    /// control plane (gRPC 50051 / REST 8080) — reachable from any NAT64
    /// client, bidirectionally, through a minted session. The caller MUST drop
    /// fail-closed with a distinct counter BEFORE route lookup (which precedes
    /// the FIB walk AND the `local_v4` LocalDelivery resolution), policy, or
    /// `allocate_source`, so no session/BIB/allocation state is minted for a
    /// non-global embedded destination. The destination-side sibling of
    /// [`Nat64Match::IneligibleSource`] (#5623); a global embedded destination
    /// never reaches this arm, so eligible traffic is untouched.
    IneligibleDestination,
}

/// Parse a NAT64 source-pool IPv4 address that may carry a canonical host
/// mask (`x.x.x.x/32`). Address-range expansion stamps `/32` on every pool
/// IP and `Ipv4Addr::from_str` rejects CIDR, so the mask is stripped before
/// parse (#2123). The pool holds exact host source addresses, so only a bare
/// address or the host mask (`/32`) is accepted; a non-host mask (`/24`) or
/// garbage suffix returns `None` and is filtered, surfacing a misconfigured
/// entry rather than silently coercing it to a host address.
pub(super) fn parse_pool_v4(s: &str) -> Option<Ipv4Addr> {
    let mut parts = s.splitn(2, '/');
    let addr: Ipv4Addr = parts.next()?.parse().ok()?;
    match parts.next() {
        None => Some(addr),
        Some("32") => Some(addr),
        Some(_) => None,
    }
}

/// #6227 item 1: incremented whenever a NAT64 rule's snapshot requested
/// deterministic NAPT64 mapping (a non-empty `deterministic_host_base_v6`) but
/// [`build_deterministic_v6`] returned `None` — the rule silently downgrades to
/// round-robin PAT and a subscriber's external mapping is no longer
/// deterministic (a CGN compliance loss). A real deployment also sees the
/// paired `eprintln!` at the call site; this counter gives tests (and, via
/// future stats plumbing, operators) a signal that does not require scraping
/// stderr.
/// #6982: aggregate ceiling on the NAT64 allocator bitmaps ONE apply may hold
/// live. The SNAT sibling (#6812, `nat::source::SOURCE_NAT_AGGREGATE_BUDGET`).
///
/// WHY NAT64 NEEDS ITS OWN. #6812 caps `PortAllocator::new` at the SNAT apply
/// boundary, but there are exactly two production construction sites and the
/// other one is here — gated by nothing. A NAT64 prefix costs
/// `pool_v4.len() * (effective port range)` occupancy bits; since #15283 the
/// range is the pool's own `port range` (defaulting to the fixed
/// 1024..=65535, i.e. `len * 64512` — the maximum), and the charge follows
/// the honoured range via `nat64_prefix_charge_for_range`.
/// The ~1.48 GiB scenario #6812 exists to prevent was reachable through this
/// path with #6812 fully in place.
///
/// The three limits are the SNAT values unchanged. Deliberate: the two paths
/// draw on one machine's memory, so a NAT64-specific relaxation would just move
/// the ceiling. They are charged SEPARATELY rather than against one shared
/// counter — see the PR discussion; a shared counter would make a NAT64 apply's
/// admissibility depend on SNAT rule ordering in a different snapshot.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Nat64AggregateBudget {
    /// Max DISTINCT prefix allocator instances.
    pub(crate) max_prefixes: u64,
    /// Max SUM of every prefix's pool address count.
    pub(crate) max_addresses: u64,
    /// Max SUM of (addresses x effective port range) = occupancy bitmap SLOTS.
    pub(crate) max_port_capacity: u64,
}

pub(crate) const NAT64_AGGREGATE_BUDGET: Nat64AggregateBudget = Nat64AggregateBudget {
    max_prefixes: 1024,
    max_addresses: 16 * crate::nat::MAX_POOL_PREFIX_HOSTS, // 1,048,576
    max_port_capacity: 1 << 33,                            // 8,589,934,592
};

/// Running aggregate charge. u64 with SATURATING adds: a hand-crafted or
/// HA-peer-synced snapshot can claim absurd cardinalities, and saturating
/// (never wrapping) keeps the over-budget verdict fail-closed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Nat64AggregateUse {
    pub(crate) prefixes: u64,
    pub(crate) addresses: u64,
    pub(crate) port_capacity: u64,
}

impl Nat64AggregateUse {
    /// Cumulative use UNCONDITIONALLY including `charge`. Used for keys that
    /// must be accepted regardless of budget (reused live state), and as the
    /// candidate inside `admitted_with`.
    pub(crate) fn saturating_with(self, charge: Self) -> Self {
        Self {
            prefixes: self.prefixes.saturating_add(charge.prefixes),
            addresses: self.addresses.saturating_add(charge.addresses),
            port_capacity: self.port_capacity.saturating_add(charge.port_capacity),
        }
    }

    /// Cumulative use IF `charge` is admitted, or `None` when admitting it
    /// would cross any limit. First-fit: a refused prefix commits NOTHING, so a
    /// later smaller one can still install.
    pub(crate) fn admitted_with(
        self,
        charge: Self,
        budget: &Nat64AggregateBudget,
    ) -> Option<Self> {
        let next = self.saturating_with(charge);
        (next.prefixes <= budget.max_prefixes
            && next.addresses <= budget.max_addresses
            && next.port_capacity <= budget.max_port_capacity)
            .then_some(next)
    }
}

/// The charge one prefix's pool costs. Separated so the test suite can cross a
/// limit by POOL COUNT without materialising 2^33 port slots — a fixture that
/// genuinely allocates the bitmap is a test that gets deleted for being slow,
/// and a deleted guard is no guard (#6982).
pub(crate) fn nat64_prefix_charge(pool_len: usize) -> Nat64AggregateUse {
    nat64_prefix_charge_for_range(pool_len, NAT64_PORT_LOW, NAT64_PORT_HIGH)
}

/// #15283: the charge one prefix with the given effective port range costs.
/// `nat64_prefix_charge` is the fixed-default-range special case.
pub(crate) fn nat64_prefix_charge_for_range(
    pool_len: usize,
    port_low: u16,
    port_high: u16,
) -> Nat64AggregateUse {
    Nat64AggregateUse {
        prefixes: 1,
        addresses: pool_len as u64,
        port_capacity: crate::nat::allocator_capacity(pool_len, port_low, port_high) as u64,
    }
}

/// #17059: THE single parse of one NAT64 rule snapshot, shared by the
/// #6982 phase-1 budget pass and the build loop below.
///
/// The two copies this replaces diverged on #14962 `pool_unusable`:
/// phase 1 returned `None` (no identity, no charge, no reuse) while the
/// loop installed the prefix with an EMPTY pool and could then
/// `reuse_allocator` that empty allocator unconditionally on the next
/// apply. Which copy is right was decided from the callers:
///
///   * install — the loop. A referenced-but-unusable pool must still
///     INSTALL (Go builder `nat64.go`: `SourceNATPoolUnusableReason`
///     stamps `pool_unusable` on the snapshot; skipping the rule would
///     leave no prefix to match, so prefix traffic falls through to
///     `NoPrefixMatch` and is ROUTED untranslated instead of dropping
///     `MatchUnavailable`). Pinned at consumption by
///     `nat64_pool_unusable_installs_prefix_and_drops_14962`.
///   * empty pool — both copies. The wire members of an unusable rule
///     must NEVER mint: `pool_v4` is empty, `deterministic_v6` is
///     `None`, and the loop logs `pool_unusable_reason` once.
///   * budget/reuse — neither copy verbatim. Phase 1's `None` made
///     the installed prefix invisible to the budget; the loop's reuse
///     arm then accepted it "unconditionally (it was charged in
///     phase 1)" — the false premise behind the apply-count-dependent
///     verdict. The unified rule keeps TWO charges per identity and
///     never mixes them (see [`Nat64RuleIdentity::wire_pool_v4`]):
///     a FIRST install is charged its wire charge
///     (`nat64_prefix_charge_for_range(wire_pool_v4.len(), lo, hi)` —
///     for an unusable 1-address pool, 1/1/64512; the healthy charge),
///     because apply-count invariance requires the first verdict to
///     already account for everything later applies will hold; a
///     REUSED allocator — healthy or empty-unusable — is charged its
///     installed charge in phase 1 (unusable: 1/0/0) iff
///     `reuse_allocator` actually matches it, and accepted
///     unconditionally in phase 2. An unusable rule therefore costs
///     its full wire charge exactly once (first apply) and its empty
///     installed charge on every reuse, so no later apply can admit a
///     prefix the first refused. Pinned by
///     `nat64_17059_unusable_reapply_does_not_grow_past_the_prefix_cap`.
///
/// SILENT by design on the `Err` side. The build loop logs each skip
/// loudly (#3888 all-or-nothing); phase 1 runs first over the same
/// snapshots purely to learn which prefixes will REUSE a live
/// allocator. Logging here would double every malformed-rule warning,
/// so the skip is returned, not printed; the loop matches on it and
/// owns the log.
///
/// #15178: the reuse identity carries prefix bytes, deduped pool, AND
/// the deterministic identity the new prefix will carry. `None`
/// deterministic covers round-robin and the over-budget/unusable
/// downgrade (both install `deterministic_v6: None`); including the
/// derived `DeterministicV6` (which folds in pool length via
/// `host_count`) makes any geometry change a reuse miss while a true
/// no-op re-apply still hits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Nat64RuleIdentity {
    pub(super) prefix_bytes: [u8; 12],
    /// Pool as installed: empty iff `unusable`, else the deduped pool
    /// exactly as parsed (before any over-budget clear).
    pub(super) pool_v4: Vec<Ipv4Addr>,
    /// Deduped wire pool BEFORE the unusable clear (`[]` when usable
    /// parsing was skipped for another reason — there is none: usable
    /// rules always parse, unusable rules always fill this). The
    /// distinction installed-vs-wire is what the budget charges:
    /// first-install charges the wire charge (the rule the operator
    /// configured costs what it claims until the budget refuses it),
    /// reuse charges the installed charge (what actually lives).
    /// See the charge note on [`parse_nat64_rule`].
    pub(super) wire_pool_v4: Vec<Ipv4Addr>,
    /// Deterministic identity the installed prefix will carry;
    /// `None` when `unusable` (install downgrades it, #14962).
    pub(super) deterministic_v6: Option<DeterministicV6>,
    /// #14962: Go stamped this pool unusable; loop installs it empty.
    pub(super) unusable: bool,
}

/// Why [`parse_nat64_rule`] refused the rule. The build loop logs the
/// payload loudly and skips the rule; phase 1 drops it silently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Nat64RuleSkip {
    EmptyPrefix,
    /// Not exactly `<ipv6>/96`: wrong part count (missing mask, extra
    /// slash) or a mask that does not parse to 96.
    BadPrefixShape,
    /// The address part before `/` is not an IPv6 address.
    BadPrefixAddress,
    /// One usable-pool member [`parse_pool_v4`] rejects; the whole
    /// rule is skipped (#3888 all-or-nothing, #2212 anti-narrowing).
    BadPoolAddress(String),
}


/// #16484: the normalized ingress scope of a snapshot / prefix: the
/// zone and routing-instance UNIONS (plural wire fields, singular
/// folded in), so a pre-#15932/#16049 singular-only spelling and the
/// plural spelling of the same scope compare equal. Source-address
/// constraints are part of the identity too: two same-/96 rule-sets
/// admitted from the same zone/RI but disjoint source prefixes are
/// distinct rules for ownership purposes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Nat64ScopeKey {
    from_zones: Vec<String>,
    from_routing_instances: Vec<String>,
    source_prefixes: Vec<PrefixV6>,
    source_constrained: bool,
}

impl Nat64ScopeKey {
    fn of_prefix(prefix: &Nat64Prefix) -> Self {
        // The prefix already stores normalized unions (build loop
        // folds the singular into the plural), so read them back.
        Self {
            from_zones: prefix.from_zones.clone(),
            // #16604/#17677: preserve the explicit-master token separately
            // from a named routing-instance literally called `default`.
            from_routing_instances: prefix
                .from_routing_instances
                .iter()
                .map(|ri| crate::nat::nat_ri_key(ri).to_string())
                .collect(),
            source_prefixes: prefix.source_prefixes.clone(),
            source_constrained: prefix.source_constrained,
        }
    }
}

/// #17076: resolve one ingress-scope axis to its single stored form:
/// the plural list when authored, else the singular pre-#15932/#16049
/// wire spelling as a one-element list, else empty (unscoped). The
/// union is resolved HERE, at snapshot read, so `Nat64Prefix` stores
/// only the plural lists and no reader re-checks a singular copy.
pub(super) fn union_scope(list: &[String], single: &str) -> Vec<String> {
    if !list.is_empty() {
        list.to_vec()
    } else if single.is_empty() {
        Vec::new()
    } else {
        vec![single.to_string()]
    }
}

/// #16484: normalize a snapshot's scope exactly as the build loop
/// installs it on the prefix: plural unions with the singular folded
/// in, and source prefixes parsed with the same wildcard
/// normalisation (#15930). An unparseable source entry is dropped
/// here exactly as there; the installed prefix carries the same
/// result, so the keys stay comparable.
pub(super) fn nat64_snapshot_scope(snap: &NAT64RuleSnapshot) -> Nat64ScopeKey {
    let from_zones = union_scope(&snap.from_zones, &snap.from_zone);
    let from_routing_instances =
        union_scope(&snap.from_routing_instances, &snap.from_routing_instance);
    // Mirror the build loop's source normalisation verbatim in
    // effect: `any` spellings clear the constraint, parseable nets
    // are kept, unparseable entries are dropped.
    let mut source_constrained = snap.source_constrained || !snap.source_addresses.is_empty();
    let mut source_prefixes: Vec<PrefixV6> = Vec::new();
    for a in &snap.source_addresses {
        let parsed = if a == "any" || a == "any6" || a == "any-ipv6" {
            source_constrained = false;
            None
        } else if let Ok(net) = a.parse::<ipnet::Ipv6Net>() {
            Some(PrefixV6::from_net(net))
        } else if let Ok(addr) = a.parse::<Ipv6Addr>() {
            Some(PrefixV6::from_net(
                ipnet::Ipv6Net::new(addr, 128).expect("host net"),
            ))
        } else {
            None
        };
        if let Some(p) = parsed {
            source_prefixes.push(p);
        }
    }
    if !source_constrained {
        source_prefixes.clear();
    }
    // #16604/#17677: preserve named `default` separately from the master token.
    let from_routing_instances: Vec<String> = from_routing_instances
        .iter()
        .map(|ri| crate::nat::nat_ri_key(ri).to_string())
        .collect();
    Nat64ScopeKey {
        from_zones,
        from_routing_instances,
        source_prefixes,
        source_constrained,
    }
}

pub(super) fn parse_nat64_rule(snap: &NAT64RuleSnapshot) -> Result<Nat64RuleIdentity, Nat64RuleSkip> {
    if snap.prefix.is_empty() {
        return Err(Nat64RuleSkip::EmptyPrefix);
    }
    // Parse "64:ff9b::/96" — require EXACTLY `<ipv6>/96`: two
    // '/'-split parts AND a /96 mask. This backstop is the corrupt /
    // lenient-snapshot path (a #1960 leniently-loaded or HA
    // peer-synced config the Go #3886/#3887 commit gate did not vet),
    // so it must be strict: a missing mask (one part), an EXTRA slash
    // ("64:ff9b::/96/garbage" → three parts, whose trailing garbage
    // would otherwise be silently ignored), or a non-/96 length skips
    // the whole rule (#3888). Mirrors the exact-2-parts `parse_prefix`
    // in nptv6.rs.
    //
    // #8597 K62, MEASURED — this check is strict, but it is not
    // IDENTICAL to the Go gate it backstops, and the difference is
    // exactly one character. Go validates the same token with
    // `strconv.ParseUint(parts[1], 10, 8)`
    // (pkg/config/compiler_validate_strict_nat.go), and Go's ParseUint
    // permits NO sign, while Rust's integer FromStr permits a leading
    // '+'. So `64:ff9b::/+96` is REJECTED at a strict commit and
    // ACCEPTED here.
    //
    // Swept exhaustively over all 7240 strings of length <= 3 drawn
    // from [0-9 + - _ space x X . e E]: 110 tokens differ, every one of
    // them a leading '+', and there is NO token that Go accepts and
    // this parse rejects. Rust's accepted language is a strict superset
    // of Go's, and both agree on the VALUE wherever both accept.
    //
    // It is REACHABLE. An earlier revision of this note called it
    // unreachable, reasoning that no xpf version can persist a `/+96`
    // because the commit gate rejects it. That is a COMMIT-path
    // argument, and the commit path does not bound what reaches this
    // loader — the same mistake #8597 K51 documents one file over.
    // Measured end to end instead:
    //
    //   1. strict commit           -> REJECTED.
    //   2. Store.Load / SyncApply  -> compiles LENIENTLY; the rule is
    //      not dropped and not zeroed, so NAT64RuleSnapshot.prefix
    //      arrives here as "64:ff9b::/+96" verbatim.
    //   3. this loader             -> INSTALLS it: is_active=true, one
    //      prefix, prefix_bytes = 00:64:ff:9b:00.. — BYTE-IDENTICAL to
    //      the state a canonical "64:ff9b::/96" produces. (Packets were
    //      not driven through it; the claim is that the installed rule
    //      is the same rule, not a separate datapath observation.)
    //      Control: "/64" gives is_active=false, 0 prefixes, so the
    //      loader does reject a bad length — the acceptance of "/+96"
    //      is attributable to the '+' specifically.
    //
    // So a hand-edited or peer-synced config reaches a state where the
    // dataplane is running a NAT64 rule the control plane rejected at
    // commit. #8667 fixed the half that was doing active harm: the
    // lenient path used to WARN that this rule "will not reach the
    // dataplane until it is corrected" while it was installed, so the
    // operator was steered away from the config that was running. The
    // Go side now mirrors this parse and stays silent for exactly the
    // tokens this parse accepts.
    //
    // DO NOT TIGHTEN THIS PARSE UNILATERALLY. Not because tightening is
    // wrong — an earlier revision of this note claimed that, and the
    // claim did not survive: it argued a stricter backstop would strand
    // a cleanly-committed rule, but the commit gate rejects every one of
    // those 110 tokens, so no such rule exists and the hazard is vacuous
    // over exactly this set.
    //
    // The real reason is that tightening converts a fail-OPEN into a
    // fail-CLOSED, and which of those is correct here is a genuine
    // behaviour decision, not a cleanup. Today a leniently-loaded
    // `/+96` translates with the right prefix. Tightened, it would be
    // rejected at this loader and NAT64 would be off for that rule-set
    // — a defensible posture ("the rule you were warned about is not
    // running") and arguably better than the current one. That choice
    // belongs to #8667, which weighs it against normalising the token
    // when the snapshot is built or accepting the spelling at commit.
    // Making it here in isolation also papers over the live defect,
    // which is on the Go side of the lenient path.
    //
    // Whatever is chosen, the two grammars should be bound by a test
    // that reds on divergence in EITHER direction; a one-directional
    // cell lets the next drift through on the other side. #17059: with
    // ONE parser there is no second grammar left in this file to bind.
    let parts: Vec<&str> = snap.prefix.split('/').collect();
    if parts.len() != 2 || parts[1].parse::<u8>().ok() != Some(96) {
        return Err(Nat64RuleSkip::BadPrefixShape);
    }
    let addr: Ipv6Addr = parts[0].parse().map_err(|_| Nat64RuleSkip::BadPrefixAddress)?;
    let octets = addr.octets();
    let mut prefix_bytes = [0u8; 12];
    prefix_bytes.copy_from_slice(&octets[..12]);
    // Pool addresses may carry a canonical host mask: an
    // address-range source pool (`address A to B`) is expanded by
    // the Go compiler into per-IP `/32` entries (#2123), and
    // `Ipv4Addr::from_str` rejects CIDR notation. Strip the host mask
    // before parse so range-form pools are not silently dropped,
    // leaving pool_v4 empty and NAT64 forward translation
    // non-functional. A non-host mask (`/24`) or garbage suffix is
    // unparseable: skip the WHOLE rule (#3888, all-or-nothing) rather
    // than silently NARROWING the pool by dropping just the bad entry
    // (the #2212 fail-open).
    //
    // #14624: keep only the FIRST occurrence of each pool address.
    // A tolerated load (legacy / mixed-version / lenient
    // configstore) can carry the same address twice — bare and
    // with the /32 host mask range-expansion stamps — and each
    // duplicate position got an INDEPENDENT occupancy bitmap, so
    // round-robin placement minted the same (address, port) BIB
    // for two IPv6 subscribers (RFC 6146 §3.5; the #10700 class,
    // whose fix covered only the SNAT parser). One address is one
    // allocator slot here, exactly as the strict message
    // ("the dataplane keeps only the first occurrence … on
    // tolerated loads") and the overlap.rs #10700 note claim.
    // First-seen order is preserved, so the #6982 charge and
    // `build_deterministic_v6`'s host_count see the same deduped
    // pool the loop installs.
    //
    // #14962: a Go-stamped unusable pool installs EMPTY — the same
    // posture as the #6982 budget refusal. Returning the rule with an
    // empty pool (rather than skipping it) means an unparseable member
    // no longer skips the whole rule: the prefix still installs, so
    // prefix traffic classifies MatchUnavailable (drop) instead of
    // falling through to NoPrefixMatch and being ROUTED as ordinary
    // IPv6. It also means no allocator bitmap is materialised for a
    // pool that must never mint. The loop logs the reason once.
    // For an unusable rule the members are parsed LENIENTLY into
    // `wire_pool_v4` (bad members dropped, never a skip): they exist
    // only to size the first-install budget charge, and the installed
    // pool stays empty regardless. For a usable rule they are parsed
    // STRICTLY into `pool_v4` (one bad member skips the whole rule).
    let mut seen = FxHashSet::default();
    let mut wire_pool_v4 = Vec::with_capacity(snap.pool_addresses.len());
    let mut pool_v4 = Vec::with_capacity(snap.pool_addresses.len());
    if snap.pool_unusable {
        for s in &snap.pool_addresses {
            if let Some(addr) = parse_pool_v4(s) {
                if seen.insert(addr) {
                    wire_pool_v4.push(addr);
                }
            }
        }
    } else {
        for s in &snap.pool_addresses {
            match parse_pool_v4(s) {
                Some(addr) => {
                    if seen.insert(addr) {
                        pool_v4.push(addr);
                    }
                }
                None => return Err(Nat64RuleSkip::BadPoolAddress(s.clone())),
            }
        }
        wire_pool_v4.clone_from(&pool_v4);
    }
    // #14962: an unusable prefix carries no deterministic mapping even
    // if the snapshot still names one (the downgrade warning in the
    // loop is likewise suppressed for it).
    let deterministic_v6 = if snap.pool_unusable {
        None
    } else {
        build_deterministic_v6(snap, pool_v4.len())
    };
    Ok(Nat64RuleIdentity {
        prefix_bytes,
        pool_v4,
        wire_pool_v4,
        deterministic_v6,
        unusable: snap.pool_unusable,
    })
}

/// #6982: prefixes refused by the aggregate budget since boot.
///
/// A refused prefix is INSTALLED with an empty pool rather than skipped, so
/// traffic to it drops fail-closed (`MatchUnavailable`) instead of falling
/// through to `NoPrefixMatch` and being ROUTED as ordinary IPv6 — skipping
/// would turn a memory guard into a translation bypass. But that makes the
/// refusal look exactly like the legitimate empty-pool rule the Go side emits
/// for a no-source-pool config, which is why the state is ALSO carried
/// explicitly on the prefix (`Nat64Prefix::over_budget`) and counted here.
/// Three states, not two: healthy, empty-by-config, refused-by-budget.
pub(crate) static NAT64_OVER_BUDGET_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(crate) static DETERMINISTIC_V6_DOWNGRADE_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// #4559: build the mode-2 (NAPT64) deterministic block-allocation params for a
/// NAT64 prefix from its snapshot + the parsed pool size. Returns `None` (the
/// pre-#4559 round-robin fallback) when the pool is not a deterministic NAPT64
/// pool (empty base string, zero block size), the base is unparseable, the
/// prefix length is unsupported (only /32 and /64 map to a subscriber word, per
/// the retired-eBPF split), the block math is degenerate, or the pool is empty.
/// `host_count` is bounded by pool capacity (`num_pool_ips * blocks_per_ip`) —
/// an IPv6 subscriber word extends far beyond the pool, so a subscriber past
/// that fails closed rather than aliasing another subscriber's block.
pub(super) fn build_deterministic_v6(snap: &NAT64RuleSnapshot, num_pool_ips: usize) -> Option<DeterministicV6> {
    if snap.deterministic_host_base_v6.is_empty() || snap.deterministic_block_size == 0 {
        return None;
    }
    if snap.deterministic_host_prefix_len != 32 && snap.deterministic_host_prefix_len != 64 {
        return None;
    }
    if snap.deterministic_blocks_per_ip == 0 || num_pool_ips == 0 {
        return None;
    }
    let base: Ipv6Addr = snap.deterministic_host_base_v6.parse().ok()?;
    let host_count = (num_pool_ips as u32).checked_mul(snap.deterministic_blocks_per_ip as u32)?;
    if host_count == 0 {
        return None;
    }
    Some(DeterministicV6 {
        block_size: snap.deterministic_block_size,
        blocks_per_ip: snap.deterministic_blocks_per_ip,
        host_prefix_len: snap.deterministic_host_prefix_len,
        host_base: base.octets(),
        host_count,
    })
}

impl Nat64State {
    /// Build from config snapshot NAT64 rules, SKIPPING (fail-scoped) any
    /// unparseable rule (#2212, refined by #3888).
    ///
    /// In a retired-eBPF world (#1373) the userspace helper is the enforcement
    /// plane. The pre-#2212 parser silently `continue`d past a bad prefix and
    /// `filter_map`ped malformed pool entries away, so a mixed-version control
    /// plane, a serialization bug, or a missed Go validation edge could install
    /// a NAT64 rule whose prefix is present but whose pool is silently empty —
    /// `allocate_v4_source` then returns `None` and NAT64 forward translation
    /// stops with no failure surfaced. The primary gate is the Go commit-time
    /// validation (`pkg/config/compiler_nat.go`, #2173/#3886, host-mask + pool
    /// representability); this is the helper-boundary backstop.
    ///
    /// #3888: this is INFALLIBLE (`-> Self`) and skips the offending rule
    /// all-or-nothing, mirroring the sibling `DnatTable::from_snapshots` /
    /// `StaticNatTable::from_snapshots` / source-NAT skip-and-continue posture
    /// (#1960 lenient-load doctrine). Each skip logs a loud one-line
    /// `eprintln!` naming the rule and the reason, so a leniently-loaded bad
    /// rule is VISIBLE, not silent. This preserves #2212's anti-silent-pool-
    /// narrowing intent — a single bad pool entry drops its WHOLE rule rather
    /// than narrowing the pool — while scoping the blast radius to that one
    /// NAT64 rule: the remaining NAT64 rules and every OTHER rule type in the
    /// forwarding snapshot still publish. Pre-#3888 the fallible variant
    /// returned a `SnapshotIntegrityError` that propagated via `?` out of
    /// `build_reconcile_forwarding`, aborting the whole rebuild and freezing
    /// the dataplane on one malformed NAT64 rule.
    ///
    /// An empty pool that is genuinely UNCONFIGURED (no `pool_addresses` on the
    /// wire — the legitimate "no source-pool" state the Go side emits) is NOT
    /// an error and installs a poolless prefix as before: only a pool that was
    /// non-empty on the wire but had an UNPARSEABLE entry drops its rule.
    pub(crate) fn from_snapshots(snaps: &[NAT64RuleSnapshot]) -> Self {
        // Generation 0: this convenience wrapper is used only by tests and the
        // no-previous cold path where the frag-association generation guard is
        // not exercised. The production reconcile path uses
        // `from_snapshots_with_previous` with the real `snapshot.generation`.
        Self::from_snapshots_with_previous(snaps, None, 0, 0)
    }

    /// #4518: build the NAT64 state, PRESERVING live translated-port
    /// reservations across a same-node config reload/commit.
    ///
    /// Identical to [`from_snapshots`] except that, for each new NAT64 prefix
    /// whose `(prefix bytes, source pool)` is byte-identical to a prefix in
    /// `previous`, it REUSES that prefix's `PortAllocator` (an `Arc`-backed
    /// clone) instead of building a fresh one at port-offset 0. The allocator's
    /// live tuple-ownership set lives behind the `Arc`, so the reservations held
    /// by pre-reload NAT64 sessions carry into the rebuilt state: the first
    /// post-commit flows no longer deterministically reclaim the LOW translated
    /// ports still owned by live sessions, which previously double-populated the
    /// (1:N) reverse index bucket and mis-demuxed v4→v6 replies until the old
    /// session aged out.
    ///
    /// The reuse is keyed on the EXACT pool (order-sensitive `Vec` equality):
    /// the allocator's per-address round-robin counters are indexed by pool
    /// position, so a pool with addresses added, removed, or reordered gets a
    /// FRESH allocator — the old reservations reference a different pool and
    /// starting clean is correct. This mirrors source NAT's
    /// `parse_source_nat_rules_with_previous` + `previous_allocators`
    /// (`nat/source.rs`), where an unchanged pool reuses the live allocator and
    /// a changed pool resets. The COMPLEMENTARY HA-failover path — syncing
    /// `Nat64ReverseInfo` and reserving the translated port on the standby so
    /// the reservation survives a cross-node failover — is tracked separately in
    /// #4512; this fix is the same-node reload path only.
    ///
    /// #5624: `generation` is the config-snapshot generation this state is built
    /// under (`snapshot.generation`). It is recorded as `build_generation` and
    /// stamped onto every fragment association installed while this state is
    /// live, so associations minted under a prior generation are invalidated on
    /// lookup after a commit changes deny/NAT64 rules.
    /// `now_ns` is the caller's MONOTONIC clock, threaded to the #6765
    /// retained-address re-seed. Callers that cannot reach one (tests that do
    /// not exercise a pool change) pass 0.
    pub(crate) fn from_snapshots_with_previous(
        snaps: &[NAT64RuleSnapshot],
        previous: Option<&Nat64State>,
        generation: u64,
        now_ns: u64,
    ) -> Self {
        let mut prefixes = Vec::with_capacity(snaps.len());
        // The natv6v4 no-v6-frag-header option is global; the Go side stamps it
        // onto every rule snapshot. Treat the state as enabled if any rule
        // carries the flag (they all carry the same value in practice).
        let no_v6_frag_header = snaps.iter().any(|s| s.no_v6_frag_header);
        // #6982 PHASE 1: reserve every prefix that will REUSE a live allocator,
        // BEFORE any new one is admitted.
        //
        // This ordering is the #6812 F2-round-4 invariant, and it is not
        // optional. Charging reuse where it is MET lets a NEW prefix be admitted
        // against a total that does not yet include reused prefixes appearing
        // LATER in the slice — and those are then accepted unconditionally, so
        // the live set ends up over the cap. Same snapshots, opposite outcome
        // from ORDER alone, repeating one prefix per apply. Bound by
        // `nat64_6982_reuse_is_charged_before_new_prefixes_regardless_of_order`.
        let mut used = Nat64AggregateUse::default();
        if let Some(prev) = previous {
            for snap in snaps {
                // #17059: phase 1 and the loop call the SAME parser;
                // a skip here is the loop's skip too, dropped silently.
                if let Ok(identity) = parse_nat64_rule(snap) {
                    let (lo, hi) = nat64_effective_port_range(snap);
                    let scope = nat64_snapshot_scope(snap);
                    // #17059: reuse uses the INSTALLED identity — an
                    // unusable rule's empty pool + `None` deterministic,
                    // never the wire pool. The empty allocator is a
                    // reuse candidate like any other, and if it is
                    // reused it is CHARGED here like any other reuse:
                    // `nat64_prefix_charge_for_range(identity.pool_v4.len(), lo, hi)`
                    // is 1 prefix / 0 addresses / 0 port slots. Accepting
                    // it uncharged in the loop is the #17059 divergence:
                    // it let the same snapshots admit one more healthy
                    // prefix per re-apply past `max_prefixes`.
                    if prev
                        .reuse_allocator(
                            &snap.name,
                            &identity.prefix_bytes,
                            &identity.pool_v4,
                            identity.deterministic_v6,
                            (lo, hi),
                            &scope,
                        )
                        .is_some()
                    {
                        used = used.saturating_with(nat64_prefix_charge_for_range(
                            identity.pool_v4.len(),
                            lo,
                            hi,
                        ));
                    }
                }
            }
        }
        // Labeled so a bad pool entry can skip the WHOLE rule (all-or-nothing,
        // #3888) rather than narrowing the pool (the #2212 fail-open).
        'rules: for snap in snaps {
            // #17059: THE parse. Phase 1 above called the same fn and
            // dropped `Err` silently; the loop owns the loud log for
            // each skip kind (#3888) and skips the WHOLE rule.
            let identity = match parse_nat64_rule(snap) {
                Ok(identity) => identity,
                Err(skip) => {
                    match skip {
                        Nat64RuleSkip::EmptyPrefix => eprintln!(
                            "xpf nat64: skipping malformed rule {:?}: empty prefix",
                            snap.name
                        ),
                        Nat64RuleSkip::BadPrefixShape => eprintln!(
                            "xpf nat64: skipping malformed rule {:?}: prefix {:?} (only <ipv6>/96 is supported)",
                            snap.name, snap.prefix
                        ),
                        // Log-only: recover the address part without a
                        // second grammar — everything before the last
                        // '/' (the shape check already passed the 2-part
                        // split, so this is the part [0] string).
                        Nat64RuleSkip::BadPrefixAddress => {
                            let addr_part = match snap.prefix.rfind('/') {
                                Some(idx) => &snap.prefix[..idx],
                                None => &snap.prefix,
                            };
                            eprintln!(
                                "xpf nat64: skipping malformed rule {:?}: unparseable prefix address {:?}",
                                snap.name, addr_part
                            )
                        }
                        Nat64RuleSkip::BadPoolAddress(bad) => eprintln!(
                            "xpf nat64: skipping malformed rule {:?}: unparseable source-pool address {:?}",
                            snap.name, bad
                        ),
                    }
                    continue 'rules;
                }
            };
            let prefix_bytes = identity.prefix_bytes;
            let mut pool_v4 = identity.pool_v4;
            let new_deterministic_v6 = identity.deterministic_v6;
            // #14962: a Go-stamped unusable pool installed EMPTY above
            // (the parser cleared it); log the reason once here — it is
            // the operator's remedy.
            if identity.unusable {
                eprintln!(
                    "xpf nat64: rule {:?} source pool is UNUSABLE ({}); installing it with an \
                     EMPTY pool so its traffic drops fail-closed rather than minting from the \
                     pool or routing untranslated (#14962)",
                    snap.name, snap.pool_unusable_reason
                );
            }
            let (eff_low, eff_high) = nat64_effective_port_range(snap);
            // #16484: this rule's identity for every previous-state
            // lookup below (reuse, deterministic probe, reseed).
            let scope_key = nat64_snapshot_scope(snap);
            let reused = previous.and_then(|prev| {
                prev.reuse_allocator(
                    &snap.name,
                    &prefix_bytes,
                    &pool_v4,
                    new_deterministic_v6,
                    (eff_low, eff_high),
                    &scope_key,
                )
            });
            // #17059: a NEW prefix is charged its WIRE charge (see
            // `wire_pool_v4`); a reused one was already charged its
            // installed charge in phase 1 and is accepted above.
            let mut over_budget = false;
            if reused.is_none() {
                match used.admitted_with(
                    nat64_prefix_charge_for_range(identity.wire_pool_v4.len(), eff_low, eff_high),
                    &NAT64_AGGREGATE_BUDGET,
                ) {
                    Some(next) => used = next,
                    None => {
                        over_budget = true;
                        NAT64_OVER_BUDGET_COUNT.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "xpf nat64: rule {:?} REFUSED by the aggregate allocator budget \
                             (prefixes {}/{}, addresses {}/{}, port slots {}/{} would be \
                             exceeded by a {}-address pool); installing it with an EMPTY pool so \
                             its traffic drops fail-closed rather than routing untranslated \
                             (#6982)",
                            snap.name,
                            used.prefixes,
                            NAT64_AGGREGATE_BUDGET.max_prefixes,
                            used.addresses,
                            NAT64_AGGREGATE_BUDGET.max_addresses,
                            used.port_capacity,
                            NAT64_AGGREGATE_BUDGET.max_port_capacity,
                            pool_v4.len(),
                        );
                        // Drop the pool BEFORE any allocator is built: the whole
                        // point is that no occupancy bitmap is materialised.
                        pool_v4.clear();
                    }
                }
            }
            let port_allocator = reused
                .unwrap_or_else(|| {
                    let fresh = PortAllocator::new(pool_v4.len(), eff_low, eff_high);
                    // #6765: the comment above is right that stale reservations
                    // must not be replayed against a DIFFERENT pool — the
                    // counters and the occupancy bitmap are pool-position
                    // indexed. But a pool that RETAINS an address is not a
                    // different pool for that address, and a fresh allocator
                    // reissues its port-offset 0 to a new flow while a
                    // pre-reload session still owns it. Carry the retained
                    // addresses' live ownership across, REMAPPED to their new
                    // indices, rather than replaying raw positions.
                    //
                    // A fully-disjoint pool yields an empty map and re-seeds
                    // nothing, which is the reset
                    // `nat64_4518_pool_change_resets_allocator` pins.
                    // #15178: a deterministic geometry/mode change must NOT
                    // reseed through the generic path either.
                    // `reseed_retained_from` carries live flows lease-less
                    // (deterministic leases are excluded there) and a later
                    // same-socket flow would re-mint a BIB under the new
                    // identity while the carried flow still forwards on
                    // the old tuple — the exact stale lease that issue
                    // retires.
                    //
                    // #16481: #15178's premise — revalidation tears every
                    // deterministic session down — fails for a pool-LENGTH
                    // change: a retained subscriber's (pool index, block)
                    // does not move, so its tuple still validates under
                    // the NEW params and revalidation KEEPS the session
                    // while the fresh allocator re-mints its port. Carry
                    // exactly those still-valid deterministic flows (and
                    // their BIB leases, rebuilt with the NEW identity)
                    // via `reseed_retained_deterministic_v6_from`; tuples
                    // that no longer validate are left for revalidation.
                    // Either side round-robin keeps the #6765 generic
                    // carry below.
                    //
                    // #16484: the previous prefix is selected by rule
                    // identity (`find_previous_prefix`), never /96 bytes
                    // alone, so a same-/96 sibling's allocator is never
                    // carried into this rule.
                    let prev_prefix = previous.and_then(|prev| {
                        prev.find_previous_prefix(&snap.name, &prefix_bytes, &scope_key)
                    });
                    if let Some(prev_prefix) = prev_prefix {
                        let map = crate::nat::retained_pool_index_map_v4(
                            &prev_prefix.pool_v4,
                            &pool_v4,
                        );
                        if !map.is_empty() {
                            // Mode flips keep #15178's fresh start: a
                            // carried round-robin bit would be re-minted
                            // as a BIB by a later deterministic flow (and
                            // vice versa), so only same-mode transitions
                            // carry — det->det via the #16481 deterministic
                            // carry, RR->RR via the #6765 generic carry.
                            let outcome = match (
                                prev_prefix.deterministic_v6,
                                new_deterministic_v6,
                            ) {
                                (Some(_), Some(new_params)) => fresh
                                    .reseed_retained_deterministic_v6_from(
                                        &prev_prefix.port_allocator,
                                        &map,
                                        &pool_v4,
                                        new_params,
                                        now_ns,
                                    ),
                                (None, None) => fresh.reseed_retained_from(
                                    &prev_prefix.port_allocator,
                                    &map,
                                    now_ns,
                                ),
                                _ => crate::nat::ReseedOutcome::default(),
                            };
                            // #7560 residual: the third reseed call site. The
                            // counters are in the allocator so they are
                            // populated here, but the note was wired only at
                            // the SNAT pool-change site. Latent today — nothing
                            // in nat64.rs allocates through the persistent-lease
                            // path, so this should always be None — and wired
                            // anyway, because "the counter exists but nobody
                            // prints it" is the defect being fixed.
                            crate::nat::report_dropped_leases(&snap.name, &outcome);
                            // #7560 residual: this condition omitted
                            // `skipped_address_only`, so a pass that skipped
                            // ONLY address-only tokens printed NOTHING — the
                            // population was counted and then swallowed by the
                            // gate. Derived from ReseedOutcome now, so a new
                            // population cannot be silently ungated here again.
                            if outcome.reseeded > 0 || outcome.needs_report() {
                                eprintln!(
                                    "xpf nat64: pool for rule {:?} changed: carried {} live \
                                     translation(s) onto {} retained address(es); {} not \
                                     carried (port outside the range), {} refused (#6765)",
                                    snap.name,
                                    outcome.reseeded,
                                    map.len(),
                                    outcome.skipped_out_of_range,
                                    outcome.refused,
                                );
                            }
                        }
                    }
                    fresh
                });
            // #4559: build the mode-2 (NAPT64) deterministic block-allocation
            // params when the referenced source pool carried `port deterministic`
            // with an enforced IPv6 host. The Go builder sends a non-empty base +
            // block-size + prefix-len (32/64) + blocks-per-ip (computed against
            // the NAT64 port range); `host_count` is pool-bounded, so it is
            // derived HERE from the parsed pool (`pool_v4.len() * blocks_per_ip`)
            // rather than trusted from the wire — the authoritative pool count is
            // whatever survived `parse_pool_v4`. A malformed base, an unsupported
            // prefix length, degenerate block math, or a `host_count` `u32`
            // overflow leaves it `None` (round-robin fallback) — #6227 item 1:
            // when the rule DID request deterministic mapping (a non-empty
            // `deterministic_host_base_v6`), that fallback is an operator-
            // visible compliance loss (CGN mapping stops being deterministic),
            // so it must not be silent.
            // #6982: a refused prefix has no pool, so it has no deterministic
            // mapping either — and it must NOT emit the downgrade warning below,
            // which would attribute a budget refusal to bad deterministic config.
            // #17059: `new_deterministic_v6` already encodes the
            // unusable downgrade (the parser forced it `None`); only
            // the over-budget clear remains loop-local.
            let deterministic_v6 = if over_budget {
                None
            } else {
                new_deterministic_v6
            };
            if !over_budget
                && !identity.unusable
                && deterministic_v6.is_none()
                && !snap.deterministic_host_base_v6.is_empty()
            {
                DETERMINISTIC_V6_DOWNGRADE_COUNT.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "xpf nat64: rule {:?} requested deterministic NAPT64 mapping (host-base {:?}) but failed to build (bad base / unsupported prefix-len / degenerate block math / pool-size overflow) — falling back to round-robin PAT; subscriber mappings are no longer deterministic",
                    snap.name, snap.deterministic_host_base_v6
                );
            }
            // #15678: parse the authored source-address scoping. Empty list =
            // unconstrained; a non-empty list whose entries all fail to parse
            // stays constrained with no prefixes and matches NOTHING.
            // #15930: the explicit `source_constrained` flag is OR'd in, so
            // an authored constraint stays constrained even if the list
            // arrives empty; `any`/family wildcards are normalised here too
            // (defence in depth for a hand-built or older snapshot) so the
            // wildcard matches any source instead of nothing. An IPv4-only
            // wildcard can never match an IPv6 source and stays a
            // never-match entry.
            // #16484: installed scope is the normalized key computed
            // above, so a later reload compares like with like.
            let source_constrained = scope_key.source_constrained;
            let source_prefixes = scope_key.source_prefixes.clone();
            let pool_index_v4 = nat64_pool_index(&pool_v4);
            prefixes.push(Nat64Prefix {
                name: snap.name.clone(),
                prefix_bytes,
                from_zones: scope_key.from_zones.clone(),
                from_routing_instances: scope_key.from_routing_instances.clone(),
                source_prefixes,
                source_constrained,
                pool_ranges_v4: crate::nat::pool_address_ranges_v4(&pool_v4),
                pool_v4,
                pool_index_v4,
                pool_index: AtomicUsize::new(0),
                port_allocator,
                deterministic_v6,
                over_budget,
                pool_unusable_reason: if snap.pool_unusable {
                    snap.pool_unusable_reason.clone()
                } else {
                    String::new()
                },
                // Filled in by `wire_nat64_overlap_peers` once source-NAT rules
                // and NAT64 prefixes both exist (#8115 R3).
                overlap_owners: None,
                iface_allocs: None,
                iface_overlap_owners: None,
                static_externals: None,
                draining_pool_allocators: Vec::new(),
            });
        }
        Self {
            prefixes,
            no_v6_frag_header,
            // #2562: preserve the live fragment-association cache across a
            // config reload (share the Arc) so in-flight fragmented datagrams
            // keep translating; a first commit with no previous state starts a
            // fresh (empty) cache.
            frag_assoc: previous
                .map(|prev| prev.frag_assoc.clone())
                .unwrap_or_default(),
            // #9950: same Arc-threading for the overlap tracker so a commit does not
            // open a 2s evasion window (in-flight datagrams keep their ranges).
            frag_overlap: previous
                .map(|prev| prev.frag_overlap.clone())
                .unwrap_or_default(),
            // #5624: record the generation this state was built under. The
            // shared `frag_assoc` cache above persists across the reload, but
            // every association it holds carries the generation it was installed
            // under; a lookup on this rebuilt state compares against
            // `build_generation`, so any association from a prior generation is
            // treated as a miss + evicted.
            build_generation: generation,
        }
    }

    /// #4518: find a previous NAT64 prefix whose prefix bytes AND source pool
    /// are byte-identical, returning its `Arc`-backed [`PortAllocator`] so live
    /// translated-port reservations survive a config reload.
    ///
    /// Order-sensitive `Vec` equality on `pool_v4` is deliberate: the
    /// allocator's per-address counters are indexed by pool position, so any
    /// change to the pool set OR its order must NOT reuse the old allocator (see
    /// [`from_snapshots_with_previous`]). Returns `None` when no compatible
    /// prefix exists (rule added, prefix changed, or pool changed) — the caller
    /// then builds a fresh allocator.
    ///
    /// #15178: the deterministic identity must ALSO match. `DeterministicV6`
    /// folds in mode (`Some` vs `None`), block_size, blocks_per_ip,
    /// host_prefix_len, host_base and the pool-derived host_count, so a
    /// block-size, host-base, /32<->/64 or round-robin<->deterministic edit
    /// on an unchanged pool is a reuse miss and the stale BIB leases in the
    /// old allocator are abandoned with it. A no-op re-apply derives the
    /// identical params and still reuses, preserving EIM.
    ///
    /// #15283: the port range must ALSO match: an allocator built for a
    /// different port window has its occupancy bitmap and block boundaries
    /// indexed by that window, so reusing it under a changed `port range`
    /// would mint outside the new window. A changed range falls through to
    /// a fresh allocator, whose #6765 retained-address reseed drops
    /// out-of-range reservations.
    ///
    /// #16484: the previous prefix is selected by RULE IDENTITY
    /// (`find_previous_prefix`: name, else bytes + normalized scope),
    /// never by /96 bytes alone. Several scoped rule-sets may share
    /// one /96 with disjoint pools (#15678); a bytes-only first match
    /// could charge/reuse a sibling's allocator for this rule.
    fn find_previous_prefix(
        &self,
        name: &str,
        prefix_bytes: &[u8; 12],
        scope: &Nat64ScopeKey,
    ) -> Option<&Nat64Prefix> {
        // A known name is authoritative when either side carries one:
        // rule-set names are unique in a committed config, and a
        // renamed rule must not steal the old name's live ownership
        // (nor keep its own under the new spelling).
        if !name.is_empty() || self.prefixes.iter().any(|p| !p.name.is_empty()) {
            if let Some(found) = self
                .prefixes
                .iter()
                .find(|p| p.name == name && &p.prefix_bytes == prefix_bytes)
            {
                return Some(found);
            }
            if !name.is_empty() {
                return None;
            }
        }
        // Legacy path: no names on either side. Bytes + normalized
        // scope; an ambiguous legacy match (several byte+scope-equal
        // prefixes with different names would have returned above)
        // refuses to guess.
        let mut found: Option<&Nat64Prefix> = None;
        for p in &self.prefixes {
            if &p.prefix_bytes == prefix_bytes && Nat64ScopeKey::of_prefix(p) == *scope {
                if found.is_some() {
                    return None;
                }
                found = Some(p);
            }
        }
        found
    }

    fn reuse_allocator(
        &self,
        name: &str,
        prefix_bytes: &[u8; 12],
        pool_v4: &[Ipv4Addr],
        deterministic_v6: Option<DeterministicV6>,
        range: (u16, u16),
        scope: &Nat64ScopeKey,
    ) -> Option<PortAllocator> {
        self.find_previous_prefix(name, prefix_bytes, scope)
            .filter(|p| {
                p.pool_v4.as_slice() == pool_v4
                    && p.deterministic_v6 == deterministic_v6
                    && p.port_allocator.port_low == range.0
                    && p.port_allocator.port_high == range.1
            })
            .map(|p| p.port_allocator.clone())
    }

    /// #15178: is a stored NAT64 source translation still produced by the
    /// live deterministic geometry for the session's synthetic v6
    /// destination? Read-only; never allocates.
    ///
    /// The prefix is selected exactly as the forward mint selects it —
    /// `match_ipv6_dest` on the PRE-translation synthetic destination —
    /// so a session whose destination matches no live prefix (or whose
    /// prefix no longer holds the translated address) fails closed, and
    /// a session is never judged against an unrelated prefix that merely
    /// shares a pool address.
    ///
    /// Round-robin prefixes (`deterministic_v6: None`) carry no geometry
    /// to invalidate a tuple — pool membership + in-range port stays
    /// valid (the pre-#15178 behaviour for that mode). A deterministic
    /// prefix validates through `deterministic_v6_tuple_matches`, the
    /// same predicate the synced reserve and idle-lease import already
    /// use: the translated address must be the subscriber's deterministic
    /// pool address (at its pool index) and the port must lie in the
    /// subscriber's CURRENT block. A missing translated port fails closed.
    pub(crate) fn nat64_source_translation_still_valid_scoped(
        &self,
        src_v6: Ipv6Addr,
        dst_v6: Ipv6Addr,
        translated_src: Ipv4Addr,
        translated_port: Option<u16>,
        from_zone: &str,
        routing_instance: &str,
    ) -> bool {
        let Some(port) = translated_port else {
            return false;
        };
        let Some((prefix_idx, _)) =
            self.match_ipv6_dest_scoped(src_v6, dst_v6, from_zone, routing_instance)
        else {
            return false;
        };
        let Some(prefix) = self.prefixes.get(prefix_idx) else {
            return false;
        };
        let Some(&addr_index) = prefix.pool_index_v4.get(&translated_src) else {
            return false;
        };
        match prefix.deterministic_v6 {
            Some(params) => prefix.port_allocator.deterministic_v6_tuple_matches(
                params,
                src_v6,
                &prefix.pool_v4,
                addr_index,
                translated_src,
                port,
            ),
            // #15932 (Codex): honour the pool's live effective range
            // (#15283), not the global default — a pool narrowed to
            // e.g. 500..=600 must not validate a tuple at port 4000,
            // and a tuple inside the narrowed range must not be kept
            // alive after the range is edited away from it.
            None => {
                (prefix.port_allocator.port_low..=prefix.port_allocator.port_high).contains(&port)
            }
        }
    }

    /// #15178/#15932: provenance-aware form of
    /// [`Self::nat64_source_translation_still_valid`]. The admitting
    /// prefix is re-selected with the session's recorded ingress scope
    /// (zone / routing-instance) and its IPv6 source — the same inputs
    /// the mint used (`classify_ipv6_packet_scoped`) — instead of the
    /// first destination-only /96. Two same-/96 rule-sets in different
    /// scopes with disjoint pools therefore judge a session against its
    /// own owner. `scope_known == false` (legacy/imported row with no
    /// recorded NAT scope) keeps the destination-only behaviour so such
    /// rows are never revoked against an invented empty scope.
    pub(crate) fn nat64_revalidation_still_valid(
        &self,
        src_v6: Ipv6Addr,
        dst_v6: Ipv6Addr,
        translated_src: Ipv4Addr,
        translated_port: Option<u16>,
        from_zone: &str,
        routing_instance: &str,
        scope_known: bool,
    ) -> bool {
        if scope_known {
            // U1 (#15932): scope tightening must revoke. If no live
            // prefix matches the recorded scope+source any more, the
            // translation is no longer admitted — for round-robin and
            // deterministic owners alike. If a scoped owner DOES match
            // but no longer holds the translated tuple (pool/geometry
            // edit), that is invalid too.
            if self
                .match_ipv6_dest_scoped(src_v6, dst_v6, from_zone, routing_instance)
                .is_none()
            {
                return false;
            }
            return self.nat64_source_translation_still_valid_scoped(
                src_v6,
                dst_v6,
                translated_src,
                translated_port,
                from_zone,
                routing_instance,
            );
        }
        // Legacy leg: keep when there is no destination owner to judge
        // against (mirrors the #15178 positive-mismatch exemption the
        // production caller applies); otherwise judge the tuple against
        // the destination-selected prefix.
        if self.match_ipv6_dest(dst_v6).is_none() {
            return true;
        }
        self.nat64_source_translation_still_valid(src_v6, dst_v6, translated_src, translated_port)
    }

    /// #15178: is a stored NAT64 source translation still produced by the
    /// live deterministic geometry for the session's synthetic v6
    /// destination? Read-only; never allocates.
    ///
    /// The prefix is selected exactly as the forward mint selects it —
    /// `match_ipv6_dest` on the PRE-translation synthetic destination —
    /// so a session whose destination matches no live prefix (or whose
    /// prefix no longer holds the translated address) fails closed, and
    /// a session is never judged against an unrelated prefix that merely
    /// shares a pool address.
    ///
    /// Round-robin prefixes (`deterministic_v6: None`) carry no geometry
    /// to invalidate a tuple — pool membership + in-range port stays
    /// valid (the pre-#15178 behaviour for that mode). A deterministic
    /// prefix validates through `deterministic_v6_tuple_matches`, the
    /// same predicate the synced reserve and idle-lease import already
    /// use: the translated address must be the subscriber's deterministic
    /// pool address (at its pool index) and the port must lie in the
    /// subscriber's CURRENT block. A missing translated port fails closed.
    pub(crate) fn nat64_source_translation_still_valid(
        &self,
        src_v6: Ipv6Addr,
        dst_v6: Ipv6Addr,
        translated_src: Ipv4Addr,
        translated_port: Option<u16>,
    ) -> bool {
        let Some(port) = translated_port else {
            return false;
        };
        let Some((prefix_idx, _)) = self.match_ipv6_dest(dst_v6) else {
            return false;
        };
        let Some(prefix) = self.prefixes.get(prefix_idx) else {
            return false;
        };
        let Some(&addr_index) = prefix.pool_index_v4.get(&translated_src) else {
            return false;
        };
        match prefix.deterministic_v6 {
            Some(params) => prefix.port_allocator.deterministic_v6_tuple_matches(
                params,
                src_v6,
                &prefix.pool_v4,
                addr_index,
                translated_src,
                port,
            ),
            // #15932 (Codex): honour the pool's live effective range
            // (#15283), not the global default — a pool narrowed to
            // e.g. 500..=600 must not validate a tuple at port 4000,
            // and a tuple inside the narrowed range must not be kept
            // alive after the range is edited away from it.
            None => {
                (prefix.port_allocator.port_low..=prefix.port_allocator.port_high).contains(&port)
            }
        }
    }

    /// #15178: positive-mismatch form for session-hit revalidation.
    /// Returns `true` ONLY when the live prefix selected by `dst_v6` is
    /// deterministic, carries the translated port, and the stored tuple
    /// is outside the subscriber's CURRENT deterministic block (or the
    /// prefix no longer holds the translated address). Every other shape
    /// — no live prefix for the destination, a round-robin prefix, a
    /// missing translated port — is NOT a positive mismatch: those were
    /// exempt before #15178 and stay exempt here, so neighbouring
    /// zone-policy revalidation (#9604/#13910 fixtures included) keeps
    /// its own verdict instead of being pre-empted by a source-NAT
    /// revocation it never had.
    pub(crate) fn nat64_deterministic_translation_mismatch(
        &self,
        src_v6: Ipv6Addr,
        dst_v6: Ipv6Addr,
        translated_src: Ipv4Addr,
        translated_port: Option<u16>,
    ) -> bool {
        let Some(port) = translated_port else {
            return false;
        };
        let Some((prefix_idx, _)) = self.match_ipv6_dest(dst_v6) else {
            return false;
        };
        let Some(prefix) = self.prefixes.get(prefix_idx) else {
            return false;
        };
        let Some(params) = prefix.deterministic_v6 else {
            return false;
        };
        let Some(&addr_index) = prefix.pool_index_v4.get(&translated_src) else {
            return true;
        };
        !prefix.port_allocator.deterministic_v6_tuple_matches(
            params,
            src_v6,
            &prefix.pool_v4,
            addr_index,
            translated_src,
            port,
        )
    }

    /// Returns true if any NAT64 prefixes are configured.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_active(&self) -> bool {
        !self.prefixes.is_empty()
    }

    /// Check if an IPv6 destination matches any NAT64 prefix.
    /// Returns (prefix_index, extracted_ipv4_dest) on match.
    /// #6979: clear `worker_id`'s holder bit across every NAT64 prefix
    /// allocator, freeing any record the clear empties. Returns records freed.
    ///
    /// The NAT64 half of the retirement sweep. Each `Nat64Prefix` owns its OWN
    /// `port_allocator`, so a stopped worker's bits are stranded per prefix and
    /// every prefix has to be swept -- the same reason the standby reserve had
    /// to stop guessing which prefix a synced flow belonged to (#6892).
    pub(crate) fn retire_worker(&self, worker_id: u32, now_ns: u64) -> usize {
        self.prefixes
            .iter()
            .map(|prefix| prefix.port_allocator.retire_worker(worker_id, now_ns))
            .sum()
    }

    pub(crate) fn match_ipv6_dest(&self, dst: Ipv6Addr) -> Option<(usize, Ipv4Addr)> {
        let octets = dst.octets();
        for (idx, prefix) in self.prefixes.iter().enumerate() {
            if octets[..12] == prefix.prefix_bytes {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return Some((idx, v4));
            }
        }
        None
    }

    /// #15678: scope test for one prefix against the packet's ingress
    /// identity. Empty authored fields are unscoped on that axis; a scoped
    /// field must equal the packet's resolved zone / routing-instance name
    /// exactly (an unknown name therefore never matches). Source: an
    /// unconstrained prefix matches any source; a constrained one matches
    /// only a source inside one of its prefixes (an all-unparseable list
    /// has none and matches nothing — fail-closed, never widened).
    fn prefix_scope_matches(
        prefix: &Nat64Prefix,
        src: Ipv6Addr,
        from_zone: &str,
        routing_instance: &str,
    ) -> bool {
        // #15932/#17076: zone list is the resolved union — empty is
        // unscoped, otherwise any authored zone admits.
        if !prefix.from_zones.is_empty()
            && !prefix.from_zones.iter().any(|z| z == from_zone)
        {
            return false;
        }
        // #16049/#17076: routing-instance list is the resolved union —
        // empty is unscoped, otherwise any authored RI admits.
        // #16604/#17677: the explicit-master token matches main only; the
        // literal `default` matches only the declared named instance.
        if !prefix.from_routing_instances.is_empty()
            && !prefix
                .from_routing_instances
                .iter()
                .any(|ri| crate::nat::nat_ri_matches(ri, routing_instance))
        {
            return false;
        }
        if !prefix.source_constrained {
            return true;
        }
        prefix.source_prefixes.iter().any(|p| p.contains(src))
    }

    /// #15678: scoped destination match — the first prefix (config order)
    /// whose /96, ingress scope, and source constraint all match.
    pub(crate) fn match_ipv6_dest_scoped(
        &self,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        from_zone: &str,
        routing_instance: &str,
    ) -> Option<(usize, Ipv4Addr)> {
        let octets = dst.octets();
        for (idx, prefix) in self.prefixes.iter().enumerate() {
            if octets[..12] == prefix.prefix_bytes
                && Self::prefix_scope_matches(prefix, src, from_zone, routing_instance)
            {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return Some((idx, v4));
            }
        }
        None
    }

    /// #15678: scoped classification — the scoped sibling of
    /// `classify_ipv6_packet`. The Pref64 source-eligibility gate stays
    /// destination-prefix based (any configured prefix), then the scoped
    /// destination match decides.
    pub(crate) fn classify_ipv6_packet_scoped(
        &self,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        from_zone: &str,
        routing_instance: &str,
    ) -> Nat64Match {
        if self.source_within_pref64(src) {
            return Nat64Match::IneligibleSource;
        }
        match self.match_ipv6_dest_scoped(src, dst, from_zone, routing_instance) {
            None => Nat64Match::NoPrefixMatch,
            Some((prefix_idx, dst_v4)) => {
                if Self::embedded_v4_is_non_global(dst_v4) {
                    return Nat64Match::IneligibleDestination;
                }
                match self.prefixes.get(prefix_idx) {
                    Some(prefix) if !prefix.pool_v4.is_empty() => Nat64Match::MatchReady {
                        prefix_idx,
                        dst_v4,
                        dst_v6: dst,
                    },
                    _ => Nat64Match::MatchUnavailable,
                }
            }
        }
    }

    /// #16045: like [`classify_ipv6_packet_scoped`], but for an
    /// ambiguous-provenance scope: the Pref64 source-eligibility gate
    /// is unchanged (identity-independent), then whenever the matched
    /// prefix is constrained on an ingress-scope axis (zone /
    /// routing-instance) under the caller's withheld-provenance
    /// identity, return `MatchUnavailable` (fail closed) instead of
    /// `MatchReady` — a translation keyed to that identity would
    /// escape the zone the later policy adjudicates. Unscoped matches
    /// classify exactly as the ordinary form.
    pub(crate) fn classify_ipv6_packet_ambiguous_provenance_scoped(
        &self,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        from_zone: &str,
        routing_instance: &str,
    ) -> Nat64Match {
        match self.classify_ipv6_packet_scoped(src, dst, from_zone, routing_instance) {
            ready @ Nat64Match::MatchReady { prefix_idx, .. } => {
                let constrained = self
                    .prefixes
                    .get(prefix_idx)
                    .is_some_and(|prefix| prefix.ingress_scope_constrained());
                if constrained {
                    Nat64Match::MatchUnavailable
                } else {
                    ready
                }
            }
            other => other,
        }
    }

    /// #5623: RFC 6146 §3.5 source-eligibility test. A NAT64 translator MUST
    /// drop an incoming IPv6 packet whose SOURCE address itself lies within a
    /// configured Pref64 — such a source is a synthesized / "already-translated"
    /// address, the RFC 6146 §5 hairpin-loop construction. Comparing the high 96
    /// bits against every configured prefix subsumes the degenerate cases the
    /// issue enumerates:
    ///   * the lower boundary `<prefix>::` (embedded v4 `0.0.0.0`),
    ///   * the upper boundary `<prefix>::ffff:ffff` (embedded v4 `255.255.255.255`),
    ///   * any source whose embedded v4 is non-global / looping (it is still
    ///     inside the prefix, so it matches here).
    ///
    /// A legitimate global-unicast source outside every Pref64 never matches, so
    /// eligible traffic is untouched (no over-reject). The scan is one pass over
    /// the small prefix list — identical cost and shape to `match_ipv6_dest` —
    /// and allocation-free, so it is safe on the session-miss hot path.
    pub(crate) fn source_within_pref64(&self, src: Ipv6Addr) -> bool {
        let octets = src.octets();
        self.prefixes
            .iter()
            .any(|prefix| octets[..12] == prefix.prefix_bytes)
    }

    /// #6475: RFC 6052 §3.1 non-global embedded-IPv4 screen. §3.1 is normative
    /// for the Well-Known Prefix 64:ff9b::/96 — an address translator "MUST NOT
    /// translate packets in which an address is composed of the Well-Known
    /// Prefix and a non-global IPv4 address; they MUST drop these packets".
    /// Any configured Pref64 is held to the same bar here, which is stricter
    /// than the RFC requires and is a deliberate hardening choice, not a
    /// restatement of §3.1. Pre-gate, `match_ipv6_dest` extracted the
    /// low 32 bits unconditionally, so `64:ff9b::127.0.0.1` classified
    /// `MatchReady(127.0.0.1)` and — with lo0 configured, whose addresses land
    /// in `state.local_v4` (`afxdp/forwarding_build/interfaces.rs`) — resolved
    /// LocalDelivery: a NAT64 client reached a socket bound to 127.0.0.1 on the
    /// firewall itself (the localhost-only admin plane: gRPC 50051, REST 8080).
    ///
    /// The screened classes (first-octet checks, allocation-free, one short
    /// compare chain per classified packet):
    ///   * `0.0.0.0/8`        — "this host on this network" (RFC 1122 §3.2.1.3);
    ///                          includes the `<prefix>::` lower boundary.
    ///   * `127.0.0.0/8`      — loopback (RFC 1122 §3.2.1.3) — the LocalDelivery
    ///                          exposure above.
    ///   * `169.254.0.0/16`   — link-local (RFC 3927).
    ///   * `224.0.0.0/4`      — multicast (RFC 5771); a translated multicast dst
    ///                          has no unicast FIB/BIB semantics.
    ///   * `240.0.0.0/4`      — reserved (RFC 1112 §4); subsumes
    ///                          `255.255.255.255/32` limited broadcast and the
    ///                          `<prefix>::ffff:ffff` upper boundary.
    ///
    /// §3.1 does not enumerate the non-global ranges itself: it defines them by
    /// reference, as "those defined in [RFC1918] or listed in Section 3 of
    /// [RFC5735]". Every class screened above is an RFC 5735 §3 entry, cited to
    /// its defining RFC rather than to the reference chain.
    ///
    /// That reference also reaches RFC 1918 private space; the issue scopes
    /// screening it to OPTIONAL even for the WKP (an NSP deployment may
    /// legitimately translate to internal v4), so RFC 1918 / TEST-NET embedded
    /// destinations still translate — pinned by the global-control test.
    pub(super) fn embedded_v4_is_non_global(v4: Ipv4Addr) -> bool {
        let o = v4.octets();
        o[0] == 0
            || o[0] == 127
            || (o[0] == 169 && o[1] == 254)
            || (o[0] & 0xF0) == 0xE0
            || (o[0] & 0xF0) == 0xF0
    }

    /// #5623: source-eligibility-gated NAT64 classification. Runs the RFC 6146
    /// §3.5 source drop BEFORE the destination match, so a Pref64-sourced
    /// (looping/synthesized) packet returns the distinct fail-closed
    /// [`Nat64Match::IneligibleSource`] the caller counts and drops — it never
    /// reaches route lookup, policy, or `allocate_source`, so no session, BIB,
    /// or allocation state is minted for it. An eligible (non-Pref64) source
    /// falls through to the unchanged [`Self::classify_ipv6_dest`], preserving
    /// the exact forward v6→v4 behavior for every legitimate global-unicast
    /// source.
    pub(crate) fn classify_ipv6_packet(&self, src: Ipv6Addr, dst: Ipv6Addr) -> Nat64Match {
        if self.source_within_pref64(src) {
            return Nat64Match::IneligibleSource;
        }
        self.classify_ipv6_dest(dst)
    }

    /// Tri-state NAT64 destination lookup (#2291).
    ///
    /// Returns [`Nat64Match::NoPrefixMatch`] when `dst` matches no configured
    /// prefix (the caller continues IPv6 routing), [`Nat64Match::MatchReady`]
    /// when a prefix matched and a source IPv4 was allocated (translate), or
    /// [`Nat64Match::MatchUnavailable`] when a prefix matched but the pool
    /// could not yield a source (caller MUST drop, never route the synthetic
    /// IPv6 destination upstream). This is the fail-closed replacement for the
    /// `match_ipv6_dest(...).and_then(allocate_v4_source)` chain that
    /// collapsed the unallocatable case into "no match".
    ///
    /// #5623: this stays destination-only; the source-eligibility gate lives in
    /// [`Self::classify_ipv6_packet`], which calls this after clearing the
    /// source. Callers on the forward IPv6 path should use `classify_ipv6_packet`
    /// so an ineligible source is rejected before translation.
    ///
    /// #6475: a prefix-matched destination whose extracted embedded IPv4 is
    /// non-global per RFC 6052 §3.1 (see [`Self::embedded_v4_is_non_global`])
    /// now returns [`Nat64Match::IneligibleDestination`] — fail-closed with a
    /// distinct counter — BEFORE the pool check, so input validation precedes
    /// the capacity/config report and the packet never reaches route lookup,
    /// policy, `allocate_source`, or the `local_v4` LocalDelivery resolution.
    pub(crate) fn classify_ipv6_dest(&self, dst: Ipv6Addr) -> Nat64Match {
        match self.match_ipv6_dest(dst) {
            None => Nat64Match::NoPrefixMatch,
            Some((prefix_idx, dst_v4)) => {
                if Self::embedded_v4_is_non_global(dst_v4) {
                    return Nat64Match::IneligibleDestination;
                }
                match self.prefixes.get(prefix_idx) {
                    // #4381: liveness probe only — a non-empty pool means a source
                    // CAN be allocated at Permit; the actual `(snat_v4, port)`
                    // allocation is deferred to `allocate_source` so a denied flow
                    // never consumes a pool port. An empty pool fails closed.
                    Some(prefix) if !prefix.pool_v4.is_empty() => Nat64Match::MatchReady {
                        prefix_idx,
                        dst_v4,
                        dst_v6: dst,
                    },
                    _ => Nat64Match::MatchUnavailable,
                }
            }
        }
    }

    /// #4381: test-only round-robin address pick, retained so the pre-existing
    /// pool-selection tests still exercise the pool wiring. Production source
    /// selection now goes through `allocate_source` (stateful, port-unique).
    #[cfg(test)]
    pub(crate) fn allocate_v4_source(&self, prefix_idx: usize) -> Option<Ipv4Addr> {
        let prefix = self.prefixes.get(prefix_idx)?;
        if prefix.pool_v4.is_empty() {
            return None;
        }
        let idx = prefix.pool_index.fetch_add(1, Ordering::Relaxed);
        let addr = prefix.pool_v4[idx % prefix.pool_v4.len()];
        Some(addr)
    }

    /// Allocate an UNTRACKED NAT64 source translation — the pre-#6522
    /// single-holder contract, where the first release frees the pool port.
    ///
    /// Compile-time completeness guard (the #6211 F2 idiom): this untracked
    /// entry point is TEST-ONLY, so a production caller that forgot to thread
    /// its `worker_id` is a BUILD FAILURE in the non-test profile rather than a
    /// silent single-holder allocation that every sibling replica can free.
    /// Production uses [`Nat64State::allocate_source_for_worker`].
    #[cfg(test)]
    pub(crate) fn allocate_source(
        &self,
        prefix_idx: usize,
        protocol: u8,
        src_v6: Ipv6Addr,
        dst_v4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        now_ns: u64,
    ) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
        // #7799: no draining-rule context at this entry point. It has no
        // production callers — every caller is a test — so the runtime drain
        // quarantine is threaded through `allocate_source_for_worker`, which
        // the poll path actually uses.
        self.allocate_source_with_holder(
            prefix_idx,
            protocol,
            src_v6,
            dst_v4,
            src_port,
            dst_port,
            now_ns,
            crate::nat::NatHolder::Untracked,
            &[],
            0,
            None,
        )
    }

    /// #6522: allocate a NAT64 source translation and record `worker_id` as its
    /// holder. The resulting session is replicated to every sibling worker,
    /// each of which reserves against this same record, so an allocation that
    /// does not name its own owner ends up with a holder mask covering every
    /// worker EXCEPT the one forwarding — and the last sibling replica to
    /// age-reap frees a live `(pool_v4, port)`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn allocate_source_for_worker(
        &self,
        prefix_idx: usize,
        protocol: u8,
        src_v6: Ipv6Addr,
        dst_v4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        now_ns: u64,
        worker_id: u32,
        // #7799: the live source-NAT rules, so a NAT64 mint can refuse an
        // address a DRAINING pool still holds allocations on.
        draining_rules: &[crate::nat::SourceNatRule],
        // #9680: the flow's routing domain (`SessionKey.routing_domain`). It keys
        // the BIB, so identical IPv6 5-tuples in two routing instances get two
        // translated bindings instead of sharing one.
        routing_scope: u32,
        iface_allocs: Option<&crate::nat::InterfaceNatAllocators>,
    ) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
        self.allocate_source_with_holder(
            prefix_idx,
            protocol,
            src_v6,
            dst_v4,
            src_port,
            dst_port,
            now_ns,
            crate::nat::NatHolder::Worker(worker_id),
            draining_rules,
            routing_scope,
            iface_allocs,
        )
    }

    /// #4381: allocate a UNIQUE translated `(pool v4 source, L4 port/identifier)`
    /// for a NAT64 forward flow, reusing the pool-mode SNAT `PortAllocator`
    /// (RFC 6146 BIB). Called at the Permit branch — after the flow is admitted
    /// — so a denied flow never consumes a pool port.
    ///
    /// `protocol` / `src_port` / `dst_port` are the ORIGINAL IPv6 forward-flow
    /// L4 tuple (for ICMP echo, `src_port` is the query identifier and
    /// `dst_port` is 0, per `parse_flow_ports`); `dst_v4` is the extracted IPv4
    /// destination. The returned `(snat_v4, translated)` becomes the forward
    /// decision's `rewrite_src` / `rewrite_src_port`. The reverse (v4→v6) path
    /// maps the translated value back via `NatDecision::reverse` on the reverse
    /// session's decision.
    ///
    /// #6522: `holder` is the WORKER taking the allocation — see
    /// [`Nat64State::allocate_source_for_worker`].
    #[allow(clippy::too_many_arguments)]
    fn allocate_source_with_holder(
        &self,
        prefix_idx: usize,
        protocol: u8,
        src_v6: Ipv6Addr,
        dst_v4: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        now_ns: u64,
        // #6522: the allocating worker. A locally-born NAT64 session is
        // replicated to every SIBLING worker, each of which reserves against
        // this same allocator record; without the owner's own bit the mask
        // holds every worker EXCEPT the one forwarding, and the last sibling
        // replica to age-reap frees a live `(pool_v4, port)`.
        holder: crate::nat::NatHolder,
        // #7799: see `Nat64OverlapDraining`.
        draining_rules: &[crate::nat::SourceNatRule],
        routing_scope: u32,
        iface_allocs: Option<&crate::nat::InterfaceNatAllocators>,
    ) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
        let prefix = self
            .prefixes
            .get(prefix_idx)
            .ok_or(SourceNatFailureReason::AllocatorExhausted)?;
        // #7799 RUNTIME MINT QUARANTINE for NAT64, the third occupancy domain.
        //
        // The address relation is precomputed at forwarding-build time, so
        // this packet-path gate only checks the live counts of draining
        // allocators that share at least one pool address. Those counts remain
        // dynamic and the refusal lifts when the last draining flow closes.
        //
        // Placed BEFORE the deterministic branch so both mint paths are
        // covered. The deterministic (NAPT64 mode 2) path allocates from the
        // same `pool_v4` and has the same collision.
        if prefix
            .draining_pool_allocators
            .iter()
            .any(|allocator| allocator.live_flow_count() > 0)
        {
            return Err(SourceNatFailureReason::Nat64OverlapDraining);
        }
        let flow = SourceNatFlowKey {
            protocol,
            src_ip: IpAddr::V6(src_v6),
            dst_ip: IpAddr::V4(dst_v4),
            src_port,
            dst_port,
            // #9680: the routing domain keys the BIB. #9062 scoped the v4
            // source-NAT allocator and deferred NAT64; release and the synced
            // reserve read the same field off the session key, so all three
            // sites agree and a release never misses its allocation.
            routing_scope,
        };
        // #4559: a deterministic NAPT64 pool maps the IPv6 subscriber to a fixed
        // external IPv4 + port block (reversible without per-flow state) instead
        // of the round-robin PAT below. An out-of-range subscriber fails CLOSED
        // (DeterministicSubscriberOutOfRange) rather than silently round-robining
        // — the compliance mapping must never quietly degrade.
        let translated = if let Some(det) = prefix.deterministic_v6 {
            allocate_nat64_pool_port_deterministic_v6(
                &prefix.port_allocator,
                flow,
                &prefix.pool_v4,
                det,
                src_v6,
                now_ns,
                holder,
            )?
        } else {
            allocate_nat64_pool_port(&prefix.port_allocator, flow, &prefix.pool_v4, now_ns, holder)?
        };
        // #8115 R3: a NAT64 prefix is its own occupancy domain, so a source-NAT
        // pool sharing one of these addresses — or a second prefix over the same
        // pool — can already hold this identity for a live flow. ONE check after
        // both arms rather than one inside each: the two arms differ in how they
        // CHOOSE the tuple, not in what makes it a duplicate.
        crate::nat::nat64_refuse_if_peer_owns(
            &prefix.port_allocator,
            prefix.overlap_owners.as_deref(),
            flow,
            translated,
            now_ns,
            holder,
        )?;
        // #14367 Check C: refuse if interface registry owns this identity.
        // Prefer explicit caller handle; fall back to build-synced prefix fields.
        let eff_iface = iface_allocs.or(prefix.iface_allocs.as_deref());
        if let Some(ia) = eff_iface {
            let eff_owners = prefix.iface_overlap_owners.as_deref().or(prefix.overlap_owners.as_deref());
            crate::nat::nat64_refuse_if_interface_owns(
                &prefix.port_allocator,
                eff_owners,
                ia,
                flow,
                translated,
                now_ns,
                holder,
            )?;
        }
        // #14368: a static external covering this tuple publishes it
        // unconditionally; refuse alongside the peer check.
        crate::nat::nat64_refuse_if_static_owns(
            &prefix.port_allocator,
            prefix.static_externals.as_deref(),
            flow,
            translated,
            now_ns,
            holder,
        )?;
        Ok(translated)
    }

    /// Create a NAT64 forward decision: IPv6 packet → IPv4 translated.
    /// `snat_v4` is the SNAT pool address, `dst_v4` is extracted from the
    /// prefix, and `translated_port` (#4381) is the unique per-flow translated
    /// TCP/UDP source port or ICMP echo identifier carried in `rewrite_src_port`
    /// so the frame builder rewrites the L4 field on the forward path and
    /// `NatDecision::reverse` restores the original on the reverse path.
    pub(crate) fn forward_decision(
        snat_v4: Ipv4Addr,
        dst_v4: Ipv4Addr,
        translated_port: u16,
    ) -> NatDecision {
        NatDecision {
            rewrite_src: Some(IpAddr::V4(snat_v4)),
            rewrite_dst: Some(IpAddr::V4(dst_v4)),
            rewrite_src_port: Some(translated_port),
            rewrite_dst_port: None,
            source_nat_icmp: None,
            nat64: true,
            nptv6: false,
        }
    }
}

