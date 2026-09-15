//! NAT rule snapshots (Source/Destination/Static/NAT64/Nptv6) and
//! per-pool status (`SourceNatPoolStatus`). Leaf module — no cross-domain
//! protocol refs.

use serde::{Deserialize, Serialize};

/// #3429: one inclusive [low,high] L4 destination-port range on the source-NAT
/// match wire. A single port is `low == high`. Mirrors the Go NatPortRangeWire.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub(crate) struct NatPortRangeWire {
    #[serde(default)]
    pub low: u16,
    #[serde(default)]
    pub high: u16,
}

/// #3429: one resolved source-NAT `match application` term — an L4 protocol
/// (IANA number; 256 = any, 0xFFFF = never/fail-closed sentinel) and optional
/// destination-port ranges. `src_ports` (#3491) carries the application's
/// `source-port` constraint; empty = source-port-unconstrained (match any source
/// port). Additive wire field (#1961 skew-safe): an older control plane omits it
/// and `#[serde(default)]` leaves it empty, so version skew degrades to the
/// pre-#3491 source-port over-match rather than failing to decode. Mirrors the
/// Go NatAppTermWire.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct NatAppTermWire {
    #[serde(default)]
    pub protocol: u16,
    #[serde(default)]
    pub ports: Vec<NatPortRangeWire>,
    #[serde(default)]
    pub src_ports: Vec<NatPortRangeWire>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SourceNATRuleSnapshot {
    pub name: String,
    /// #2218: compiler-assigned per-rule translation hit-counter id (non-zero;
    /// 0 = no per-rule counter). Mirrors the policy rule_id -> PolicyRuleCounter
    /// design; the helper resolves an `Arc<NatRuleCounter>` from the
    /// coordinator's `NatCounterStore` and increments it once per committed
    /// translated forward flow. #2255: the id is a STABLE key-derived hash, so
    /// it is u32-wide and survives a config reorder/removal — the cumulative
    /// store stays correctly attributed. The JSON wire is unchanged (a number).
    #[serde(rename = "counter_id", default)]
    pub counter_id: u32,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "to_zone", default)]
    pub to_zone: String,
    /// #3096: interface-/routing-instance-scoped rule-set matching. A
    /// non-empty value restricts the rule to flows ingressing/egressing the
    /// named logical interface (config name) or in the named
    /// ingress/egress routing instance (VRF). Empty = unscoped on that axis
    /// (pre-#3096 behavior). The match path AND-s every non-empty scope.
    /// Additive wire fields (#1961): an older control plane omits them; this
    /// helper defaults them to empty (zone-only scope).
    #[serde(rename = "from_interface", default)]
    pub from_interface: String,
    #[serde(rename = "to_interface", default)]
    pub to_interface: String,
    #[serde(rename = "from_routing_instance", default)]
    pub from_routing_instance: String,
    #[serde(rename = "to_routing_instance", default)]
    pub to_routing_instance: String,
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    pub destination_addresses: Vec<String>,
    #[serde(rename = "interface_mode", default)]
    pub interface_mode: bool,
    #[serde(default)]
    pub off: bool,
    #[serde(rename = "pool_name", default)]
    pub pool_name: String,
    #[serde(rename = "pool_addresses", default)]
    pub pool_addresses: Vec<String>,
    #[serde(rename = "port_low", default)]
    pub port_low: u16,
    #[serde(rename = "port_high", default)]
    pub port_high: u16,
    /// #3906: `port no-translation` — translate the source ADDRESS but PRESERVE
    /// the original source port (Junos 1:1 source-port behaviour). When true the
    /// match path takes the address-only branch and leaves `rewrite_src_port`
    /// unset, so the packet keeps its L4 source port and `port_low`/`port_high`
    /// are ignored. Additive wire field (#1961): an older control plane omits it
    /// and this helper defaults it to false (the pre-#3906 PAT behaviour).
    #[serde(rename = "pool_no_translation", default)]
    pub pool_no_translation: bool,
    #[serde(rename = "address_persistent", default)]
    pub address_persistent: bool,
    #[serde(rename = "persistent_nat", default)]
    pub persistent_nat: bool,
    #[serde(rename = "persistent_nat_permit_any_remote_host", default)]
    pub persistent_nat_permit_any_remote_host: bool,
    /// #2823: full three-way Junos `persistent-nat permit` enum as a string
    /// ("any-remote-host" | "target-host" | "target-host-port"). Empty =>
    /// fall back to `persistent_nat_permit_any_remote_host` for wire skew
    /// against an older control plane that predates this field.
    #[serde(rename = "persistent_nat_permit", default)]
    pub persistent_nat_permit: String,
    #[serde(rename = "persistent_nat_inactivity_timeout", default)]
    pub persistent_nat_inactivity_timeout: i64,
    #[serde(rename = "pool_unusable", default)]
    pub pool_unusable: bool,
    #[serde(rename = "pool_unusable_reason", default)]
    pub pool_unusable_reason: String,
    /// #3429: source-NAT `match destination-port` constraint as inclusive
    /// [low,high] ranges. Empty = port-unconstrained (match any port). A
    /// non-empty set requires the flow's destination port to fall in one of the
    /// ranges, otherwise the rule does NOT match — so a port-scoped SNAT
    /// (including a `then source-nat off` exemption) no longer silently widens
    /// to every port. Additive wire field (#1961): an older control plane omits
    /// it; this helper defaults it empty (the pre-#3429 over-match).
    #[serde(rename = "match_destination_ports", default)]
    pub match_destination_ports: Vec<NatPortRangeWire>,
    /// #3429: source-NAT `match application` constraint, pre-expanded by the Go
    /// builder to (protocol, destination-port range) terms (an application-set
    /// expands to one term per resolved member). Empty = unconstrained. A
    /// non-empty set requires the flow's protocol/destination port to satisfy
    /// one term. Additive wire field, same skew semantics.
    #[serde(rename = "match_applications", default)]
    pub match_applications: Vec<NatAppTermWire>,
    /// #4559: deterministic CGNAT port-block allocation mode. 0 = off (regular
    /// round-robin/sticky PAT, the pre-#4559 behaviour). 1 = IPv4-subscriber
    /// deterministic block allocation (mode 1): the subscriber's internal IPv4
    /// address deterministically maps to a fixed external IP + port block, so
    /// the (external IP, port) → subscriber reverse mapping needs no per-flow
    /// log (lawful-intercept / CGN audit). Mode 2 (IPv6 subscriber / NAT64) is
    /// carried by the Go compiler but NOT yet implemented here — an unknown
    /// mode falls back to round-robin (the commit-time advisory still fires).
    /// Additive wire field (#1961 skew-safe): an older control plane omits it
    /// and `#[serde(default)]` leaves it 0 (round-robin).
    #[serde(rename = "deterministic_mode", default)]
    pub deterministic_mode: u8,
    /// #4559: per-subscriber port block size (Junos `block-size`, e.g. 2016).
    /// Only meaningful when `deterministic_mode != 0`.
    #[serde(rename = "deterministic_block_size", default)]
    pub deterministic_block_size: u16,
    /// #4559: number of blocks each external pool address carries
    /// (`(port_high - port_low + 1) / block_size`). Precomputed by the Go
    /// builder against the SAME defaulted port range this snapshot carries, so
    /// block boundaries align between compiler and dataplane.
    #[serde(rename = "deterministic_blocks_per_ip", default)]
    pub deterministic_blocks_per_ip: u16,
    /// #4559: subscriber-CIDR network address as a host-order u32 (IPv4). The
    /// subscriber index is `host_order(src) - host_base`.
    #[serde(rename = "deterministic_host_base", default)]
    pub deterministic_host_base: u32,
    /// #4559: number of subscriber addresses in the host CIDR
    /// (`1 << (32 - prefix_len)` for IPv4). A source whose index is `>=` this is
    /// outside the deterministic range and the allocation fails closed.
    #[serde(rename = "deterministic_host_count", default)]
    pub deterministic_host_count: u32,
    /// #9874: the fail-closed poison for a rule whose AUTHORED `match`
    /// constrains nothing. The #8430 strict gate rejects such a rule at commit;
    /// the tolerant load / peer-sync path downgrades to a warning and ships it
    /// with this marker. An empty match set reads as UNCONSTRAINED
    /// (`source_constrained = false` → match-any), so without the marker the
    /// rule would install as a catch-all translator. The source-NAT table fails
    /// a marked rule CLOSED (an in-scope flow gets `Unavailable`, drop +
    /// count, never a translation — including for `off` rules). A scope-only
    /// rule (no `match` at all) leaves this false and still installs
    /// unconstrained, which is the legitimate catch-all.
    ///
    /// Additive wire field (#1961): an older control plane omits it and
    /// `#[serde(default)]` leaves it false — but that pairing keeps the
    /// pre-#9874 catch-all, which is the defect rather than an acceptable
    /// degradation, so this field rides the v19 protocol bump and the
    /// exact-equality gate refuses the mismatched pairing instead.
    #[serde(rename = "lenient_match_dropped", default)]
    pub lenient_match_dropped: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct StaticNATRuleSnapshot {
    pub name: String,
    /// #2218: per-rule translation hit-counter id (see SourceNATRuleSnapshot).
    #[serde(rename = "counter_id", default)]
    pub counter_id: u32,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    /// #3096: interface-/routing-instance-scoped static NAT. Enforced on the
    /// inbound (DNAT) direction against the ingress interface/VRF and on the
    /// reverse (SNAT) direction against the egress interface/VRF. Empty =
    /// unscoped on that axis. Additive wire fields (#1961).
    #[serde(rename = "from_interface", default)]
    pub from_interface: String,
    #[serde(rename = "from_routing_instance", default)]
    pub from_routing_instance: String,
    /// #3435: the static-NAT rule's `match source-address` constraint. Junos
    /// static NAT `source-address` restricts which client source IPs the
    /// 1:1/DNAT translation applies to; before #3435 the Go snapshot dropped
    /// it, so the helper built an all-source mapping that exposed the internal
    /// host to ANY source (fail-open, H01) — the static-NAT analog of the DNAT
    /// #2394 fix. Each entry is a CIDR prefix (`198.51.100.0/24`) or a bare
    /// host IP (`198.51.100.42`), carried verbatim. The inbound (DNAT)
    /// direction matches the packet SOURCE against this list; the reverse
    /// (SNAT) direction matches the packet DESTINATION (the original client).
    /// Empty = unscoped (match any source, unchanged behavior). A non-empty
    /// list whose entries ALL fail to parse fails CLOSED (matches no source)
    /// rather than reverting to match-any. Additive wire field (#1961).
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "external_ip", default)]
    pub external_ip: String,
    #[serde(rename = "internal_ip", default)]
    pub internal_ip: String,
    /// #2491: external (pre-translation) destination port the inbound packet
    /// must carry for a port-mapped static-NAT rule. 0 = match any port
    /// (whole-address 1:1, the legacy behaviour).
    #[serde(rename = "match_destination_port", default)]
    pub match_destination_port: u16,
    /// #2491: internal (post-translation) destination port the 1:1 host
    /// receives (`then static-nat prefix <ip> mapped-port <port>`). 0 = no
    /// port translation. When set, the inbound DNAT rewrites the destination
    /// port to this value and the reverse-path SNAT un-translates it back to
    /// `match_destination_port`.
    #[serde(rename = "mapped_port", default)]
    pub mapped_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct DestinationNATRuleSnapshot {
    pub name: String,
    /// #2218: per-rule translation hit-counter id (see SourceNATRuleSnapshot).
    #[serde(rename = "counter_id", default)]
    pub counter_id: u32,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    /// #3096: interface-/routing-instance-scoped DNAT, enforced against the
    /// INGRESS interface/VRF (DNAT translates the destination on inbound).
    /// Empty = unscoped on that axis. Additive wire fields (#1961).
    #[serde(rename = "from_interface", default)]
    pub from_interface: String,
    #[serde(rename = "from_routing_instance", default)]
    pub from_routing_instance: String,
    /// #2394: the DNAT rule's `match source-address` constraint. Junos DNAT
    /// `source-address` restricts which source IPs the destination translation
    /// applies to; before #2394 the Go snapshot dropped it, so the helper built
    /// a destination-only entry that DNAT'd traffic from ANY source (fail-open).
    /// Each entry is either a CIDR prefix (`198.51.100.0/24`) or a bare host IP
    /// (`198.51.100.42`); the Go compiler carries the value verbatim. The DNAT
    /// table parser (`nat/destination.rs`) tries `IpNet` first and falls back to
    /// a bare `IpAddr` -> /32 or /128, since `IpNet::from_str` rejects a bare IP.
    /// An empty vec = unscoped DNAT (match any source, unchanged behavior). A
    /// non-empty list whose entries ALL fail to parse fails CLOSED (matches no
    /// source) rather than reverting to match-any.
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_address", default)]
    pub destination_address: String,
    /// #3164: a non-host DNAT `match destination-address` prefix
    /// (`198.51.100.0/24`). ADDITIVE over `destination_address` (#1961): for a
    /// host destination (bare IP, /32, /128) this is empty and the table keys
    /// the O(1) exact `destination_address` map (unchanged fast path). For a
    /// non-host prefix the Go compiler sets this to the canonical masked CIDR
    /// and puts the prefix network address in `destination_address`; the DNAT
    /// table installs a longest-prefix-match entry so every host in the block
    /// is translated to the rule's pool (many:1). An older helper that does not
    /// know this field ignores it and keys only `destination_address` (the
    /// network base) — the pre-#3164 narrowed behavior, never a crash.
    #[serde(rename = "destination_prefix", default)]
    pub destination_prefix: String,
    #[serde(rename = "destination_port", default)]
    pub destination_port: u16,
    #[serde(default)]
    pub protocol: String,
    #[serde(rename = "pool_address", default)]
    pub pool_address: String,
    #[serde(rename = "pool_port", default)]
    pub pool_port: u16,
    /// #3437 (H10): the source-port constraint of the DNAT rule's `match
    /// application` term as inclusive [low,high] ranges. Empty =
    /// source-port-unconstrained (the common case). A non-empty set requires
    /// the flow's source port to fall in one range, otherwise the rule does
    /// NOT match — so an application-scoped DNAT no longer translates every
    /// source port hitting the destination port. A low>high range is the
    /// fail-CLOSED never-match sentinel and survives the wire verbatim.
    /// Additive wire field (#1961): an older control plane omits it; this
    /// helper defaults it empty (the pre-#3437 over-match).
    #[serde(rename = "match_source_ports", default)]
    pub match_source_ports: Vec<NatPortRangeWire>,
    /// #3449: a MULTI-port `match destination-port` range as inclusive
    /// [low,high] ranges. Empty = no range constraint (the exact/wildcard
    /// `destination_port` governs — the common single-port and IP-only case,
    /// unchanged). Non-empty: the entry is keyed under the wildcard port
    /// (`destination_port == 0`) and the flow's destination port MUST fall in
    /// one range, otherwise the rule does NOT match. This lets a wide range
    /// (`destination-port 1 to 65535`) install ONE wildcard-port entry instead
    /// of 65 535 exact-port entries (the control-plane amplification #3449
    /// closes). A low>high range is the impossible never-match form, preserved
    /// verbatim. Additive wire field (#1961): an older control plane omits it;
    /// this helper defaults it empty, treating a `destination_port == 0` entry
    /// as match-ANY-port (the pre-#3449 wildcard) — the transient upgrade-skew
    /// fail-open the source-NAT range fields also carry.
    #[serde(rename = "match_destination_ports", default)]
    pub match_destination_ports: Vec<NatPortRangeWire>,
    /// #3437 (H11): the ICMP/ICMPv6 type[,code] constraint of the DNAT rule's
    /// `match application` term (e.g. junos-ping = type 8). None = no ICMP
    /// type/code constraint (match every type/code of the protocol, the
    /// historical behavior). When `match_icmp_type` is Some the flow's ICMP
    /// type MUST equal it, and when `match_icmp_code` is also Some the code
    /// MUST equal it, otherwise the rule does NOT match; a non-ICMP flow never
    /// satisfies an ICMP-type-constrained entry (fail closed). Additive wire
    /// fields, same skew semantics as `match_source_ports`.
    #[serde(rename = "match_icmp_type", default)]
    pub match_icmp_type: Option<u8>,
    #[serde(rename = "match_icmp_code", default)]
    pub match_icmp_code: Option<u8>,
    /// #3844: a `then destination-nat off` no-translate EXEMPTION. Junos DNAT
    /// rules are ordered; a rule whose action is `off` matches the traffic but
    /// applies NO translation and STOPS evaluation, so a later DNAT rule cannot
    /// re-translate it. When true the DNAT table installs the entry with its
    /// full match (destination/source/protocol/port) but NO pool translation:
    /// on a match the lookup returns no DNAT decision AND short-circuits the
    /// remaining proto/port/prefix tiers for that flow, and the off
    /// destination is NOT registered as a firewall-local address (it is a real
    /// routed host, not a VIP). Before #3844 the Go builder dropped the
    /// pool-less off rule, so the "exempted" traffic fell through and was
    /// DNAT'd by a later rule (fail-open). Additive wire field (#1961): an
    /// older control plane omits it and this helper defaults it false (a normal
    /// translate entry); a pool-less non-off entry still fails its `pool_address`
    /// parse and is dropped as before.
    #[serde(default)]
    pub off: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct NAT64RuleSnapshot {
    pub name: String,
    #[serde(default)]
    pub prefix: String,
    // #2214: null-tolerant. A NAT64 rule with no resolvable source pool
    // makes the Go builder emit `pool_addresses:null` (nil slice, no
    // `,omitempty`); plain `default` would only cover an ABSENT key, so an
    // explicit null would abort the whole snapshot decode (#1961 no-transit).
    #[serde(
        rename = "pool_addresses",
        default,
        deserialize_with = "crate::protocol::null_tolerant_vec"
    )]
    pub pool_addresses: Vec<String>,
    /// Mirrors `security nat natv6v4 no-v6-frag-header`. This is an
    /// option-gated LOCAL DF policy (not the size-driven RFC 7915 5.1
    /// selection): when set, the IPv6->IPv4 translator clears DF so the
    /// translated IPv4 packet stays fragmentable (DF=0, non-atomic) and carries
    /// a generated non-zero, non-repeating Identification (RFC 6864 4.1),
    /// instead of the default DF=1 atomic framing.
    #[serde(rename = "no_v6_frag_header", default)]
    pub no_v6_frag_header: bool,
    /// #4559: IPv6-subscriber deterministic CGNAT (mode 2, NAPT64) per-subscriber
    /// port block size (Junos `block-size`). Non-zero ONLY when the referenced
    /// source pool carries `port deterministic` with an IPv6 host and is enforced
    /// (a /32 or /64 subscriber prefix). Zero => the NAT64 pool round-robins (the
    /// pre-#4559 behaviour + the commit-time advisory). Additive wire field
    /// (#1961 skew-safe): an older control plane omits it and `default` leaves it
    /// 0 (round-robin).
    #[serde(rename = "deterministic_block_size", default)]
    pub deterministic_block_size: u16,
    /// #4559: blocks each external pool address carries, computed by the Go
    /// builder against the fixed NAT64 translated-port range so block boundaries
    /// align with the allocator. Meaningful only when `deterministic_block_size
    /// != 0`.
    #[serde(rename = "deterministic_blocks_per_ip", default)]
    pub deterministic_blocks_per_ip: u16,
    /// #4559: IPv6 subscriber-prefix length (32 or 64). Selects the 32-bit
    /// subscriber-index word offset (32 → octets[4..8], 64 → octets[8..12]).
    #[serde(rename = "deterministic_host_prefix_len", default)]
    pub deterministic_host_prefix_len: u8,
    /// #4559: IPv6 subscriber-CIDR network base (canonical string). Empty => not
    /// a deterministic NAPT64 pool. Parsed to the 16-octet base the allocator
    /// derives the subscriber word from and reverses against.
    #[serde(rename = "deterministic_host_base_v6", default)]
    pub deterministic_host_base_v6: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct Nptv6RuleSnapshot {
    pub name: String,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "internal_prefix", default)]
    pub internal_prefix: String,
    #[serde(rename = "external_prefix", default)]
    pub external_prefix: String,
}

/// #2218: one per-rule NAT translation hit-counter row reported back to the
/// Go control plane inside `ProcessStatus.nat_rule_counters`. Mirrors
/// `PolicyRuleCounterStatus` (security.rs) but keys on the compiler-assigned
/// `counter_id` rather than a rule_id string. The Go struct is
/// `NATRuleCounterStatus` with json tags `counter_id`/`packets`/`bytes`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct NatRuleCounterStatus {
    #[serde(rename = "counter_id", default)]
    pub counter_id: u32,
    #[serde(rename = "packets", default)]
    pub packets: u64,
    #[serde(rename = "bytes", default)]
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct SourceNatPoolStatus {
    #[serde(rename = "rule_name", default)]
    pub rule_name: String,
    #[serde(rename = "pool_name", default)]
    pub pool_name: String,
    #[serde(rename = "address_count", default)]
    pub address_count: usize,
    #[serde(rename = "port_low", default)]
    pub port_low: u16,
    #[serde(rename = "port_high", default)]
    pub port_high: u16,
    #[serde(rename = "persistent_nat", default)]
    pub persistent_nat: bool,
    #[serde(rename = "persistent_nat_permit_any_remote_host", default)]
    pub persistent_nat_permit_any_remote_host: bool,
    /// #3193: the full three-way Junos `persistent-nat permit` mode
    /// ("any-remote-host" / "target-host" / "target-host-port"). An empty
    /// string (older helper) falls back to the binary flag above on the
    /// control-plane render side.
    #[serde(rename = "persistent_nat_permit", default)]
    pub persistent_nat_permit: String,
    #[serde(rename = "persistent_nat_inactivity_timeout", default)]
    pub persistent_nat_inactivity_timeout: i64,
    #[serde(rename = "live_flows", default)]
    pub live_flows: u64,
    #[serde(rename = "used_ports", default)]
    pub used_ports: u64,
    #[serde(rename = "persistent_leases", default)]
    pub persistent_leases: u64,
    #[serde(rename = "max_tracked_flows", default)]
    pub max_tracked_flows: u64,
    #[serde(rename = "allocations_total", default)]
    pub allocations_total: u64,
    #[serde(rename = "reuses_total", default)]
    pub reuses_total: u64,
    #[serde(rename = "exhaustion_total", default)]
    pub exhaustion_total: u64,
    /// #9902 F-026: the reporting allocator's instance id (see
    /// `PortAllocatorShared::allocator_id`). Lets the control plane tell a
    /// rebuilt allocator (fresh zeroed counters) from the one it baselined.
    /// 0 from a helper older than this field (serde default).
    #[serde(rename = "allocator_id", default)]
    pub allocator_id: u64,
    /// #8447: persistent-NAT admissions that produced a translation. Reported
    /// as a PAIR with the decline counter below — a zero decline count is
    /// equally consistent with "nothing declined" and "this path never ran",
    /// and only the admitted count separates them.
    #[serde(rename = "persistent_admitted_total", default)]
    pub persistent_admitted_total: u64,
    /// #8447: persistent-NAT admissions that returned a failure instead.
    #[serde(rename = "persistent_declined_total", default)]
    pub persistent_declined_total: u64,
    /// #4800: acquisitions of this pool's residual `live` map mutex on the
    /// production allocate/reserve/release/rollback/GC paths, and the
    /// subset of those that found it already held. The connection-rate
    /// harness scrapes the PAIR — a contended count without its
    /// denominator cannot distinguish "the allocator mutex saturated" from
    /// "the allocator ran hot but never blocked". `default` so an older
    /// helper that predates the counters decodes as 0.
    #[serde(rename = "live_lock_acquisitions_total", default)]
    pub live_lock_acquisitions_total: u64,
    #[serde(rename = "live_lock_contended_total", default)]
    pub live_lock_contended_total: u64,
    /// #9392: the recycled-phase walk cost of `PortAllocator::claim`, summed
    /// across this pool's addresses — tokens POPPED and the number of FIFO
    /// WALKS that popped them.
    ///
    /// `pops / walks` is pops per walk: ~1 when a freed token is claimable at
    /// the head (healthy), materially above 1 when the #9327 cliff is reached
    /// (K out-of-band-occupied tokens ahead of F free ones, retained tokens
    /// pushed to the BACK, so (K+F)/F per claim degrading to K+1 as F -> 1 —
    /// worst exactly as an address approaches exhaustion).
    ///
    /// #9327 measured the mechanism on a fixture and could not answer whether
    /// a production pool ever gets there, because the pop counter was
    /// `#[cfg(test)]`. ADDED as new keys, never by redefining an existing one:
    /// the helper and the daemon roll independently, so a redefined field is a
    /// rolling-upgrade break. `default` so an older helper decodes 0 — and the
    /// render side distinguishes that from a measured zero by requiring a
    /// non-zero WALK count before it prints a ratio at all.
    #[serde(rename = "recycle_scan_pops_total", default)]
    pub recycle_scan_pops_total: u64,
    #[serde(rename = "recycle_scan_walks_total", default)]
    pub recycle_scan_walks_total: u64,
}
