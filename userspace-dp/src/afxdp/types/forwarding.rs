// Forwarding/routing types extracted from afxdp/types/mod.rs (Issue 68.2).
// Includes the forwarding-state aggregator, connected/non-connected
// route entries, egress and tunnel-endpoint descriptors, fabric-link
// descriptor, forwarding disposition + resolution enums, and the
// per-binding lookup table.
//
// Pure relocation. Original `pub(super)` widened to `pub(in crate::afxdp)`
// in this file; types/mod.rs re-exports via `pub(in crate::afxdp) use
// forwarding::*;` so external call sites resolve unchanged.

use super::*;

/// SYN-cookie master key (16 bytes) wrapped so its `Debug` never renders
/// the secret bytes (#4484 L-7). `ForwardingState` derives `Debug`; the
/// auto-derived `Debug` on a bare `Option<[u8; 16]>` would print the raw
/// key into any log/trace that formats the forwarding state. This wrapper
/// redacts in `Debug` — `Some(<redacted>)` / `None`, never the bytes —
/// while staying a transparent `Option<[u8; 16]>` at every read/write site
/// (access `.0`). Mirrors the manual-redaction discipline the WireGuard
/// key fields use (`TunnelEndpoint`/`WgRuntimePeer` in this file).
#[derive(Clone, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct SynCookieMasterKey(pub(in crate::afxdp) Option<[u8; 16]>);

impl std::fmt::Debug for SynCookieMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(_) => f.write_str("Some(<redacted>)"),
            None => f.write_str("None"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ForwardingState {
    pub(in crate::afxdp) local_v4: FastSet<Ipv4Addr>,
    pub(in crate::afxdp) local_v6: FastSet<Ipv6Addr>,
    /// #3769: table (VRF) attribution for the local-delivery DECISION.
    /// `local_v4`/`local_v6` are GLOBAL membership sets ("some subsystem
    /// answers for this IP somewhere"); before #3769 the local-delivery
    /// shortcut in `lookup_forwarding_resolution_inner_ecmp` keyed the
    /// DECISION on that global membership, so a packet in VRF A destined to a
    /// local address owned only in VRF B short-circuited to `LocalDelivery`,
    /// skipping the VRF-A FIB + zone/security-policy + HA-RG owner
    /// classification. #3151 table-scoped only the ifindex ATTRIBUTION, and
    /// only via the connected-route scan — which cannot recover a NAT/DNAT
    /// external IP's owning routing-instance (no connected route) nor a
    /// non-/32 interface host IP (`ConnectedRouteV*` stores the MASKED network
    /// address, so `prefix.addr() == host` matches only a /32). These maps
    /// record, for EVERY `local_v*` member (interface host address AND
    /// static-NAT/DNAT external IP), the set of canonical route tables that
    /// own it, so the shortcut is gated on the resolving table. Every
    /// `local_v*` insert has a paired `local_tables_v*` / `local_nat_any_table_v*`
    /// insert: interface addresses in `populate_interfaces` (keyed by the host
    /// `.addr()`, not the connected prefix), NAT/DNAT externals in the
    /// `forwarding_build` late-stage NAT append. The connected scan is still
    /// used for the ifindex ATTRIBUTION (the #3151 /32-HA case); the membership
    /// DECISION now uses these maps.
    ///
    /// A named-routing-instance NAT/DNAT rule (or an interface) records the
    /// specific canonical table here — that is the correct cross-VRF
    /// isolation. An UNSCOPED (`from routing-instance` empty) NAT/DNAT rule is
    /// a WILDCARD that `scope_ok` matches against ANY ingress routing-instance
    /// (`nat/destination.rs`, `nat/static_nat.rs`, `nat/source.rs`) — and the
    /// common `from zone` / `from interface` inbound-DNAT rule leaves the
    /// routing instance empty (`compiler_nat.go`). Attributing such an external
    /// IP to `inet.0` only (via `connected_route_tables("")`) would
    /// over-isolate it when its zone lives in a non-default VRF, so the
    /// wildcard case goes into `local_nat_any_table_v*` instead — a
    /// table-agnostic membership set the local-delivery DECISION treats as
    /// owned in EVERY table, mirroring `scope_ok`'s empty-instance wildcard.
    /// Interface host addresses are NEVER wildcarded (an interface IP genuinely
    /// lives in exactly one VRF).
    pub(in crate::afxdp) local_tables_v4: FastMap<Ipv4Addr, FastSet<String>>,
    pub(in crate::afxdp) local_tables_v6: FastMap<Ipv6Addr, FastSet<String>>,
    pub(in crate::afxdp) local_nat_any_table_v4: FastSet<Ipv4Addr>,
    pub(in crate::afxdp) local_nat_any_table_v6: FastSet<Ipv6Addr>,
    /// #3182: EVERY configured interface address, decoupled from the
    /// NAT-aware `local_v*` exclusion. `local_v4`/`local_v6` drop the IP of
    /// any interface whose zone is an interface-mode-SNAT `to_zone`
    /// (`nat_translated_local_exclusions`), so they are NOT a complete
    /// "addresses this router owns" set — the SNAT/WAN interface IP is
    /// missing. The anti-poison `owns_configured_ip` predicate is driven
    /// from this full set instead so an unsolicited ARP/NDP (or RX-learn)
    /// claiming the router's own WAN/SNAT interface IP is still rejected.
    /// Built alongside `local_v*` in `populate_interfaces`, BEFORE the NAT
    /// exclusion branch, from the same per-interface address list.
    pub(in crate::afxdp) configured_iface_v4: FastSet<Ipv4Addr>,
    pub(in crate::afxdp) configured_iface_v6: FastSet<Ipv6Addr>,
    pub(in crate::afxdp) interface_nat_v4: FastMap<Ipv4Addr, i32>,
    pub(in crate::afxdp) interface_nat_v6: FastMap<Ipv6Addr, i32>,
    pub(in crate::afxdp) connected_v4: Vec<ConnectedRouteV4>,
    pub(in crate::afxdp) connected_v6: Vec<ConnectedRouteV6>,
    pub(in crate::afxdp) routes_v4: FastMap<String, Vec<RouteEntryV4>>,
    pub(in crate::afxdp) routes_v6: FastMap<String, Vec<RouteEntryV6>>,
    pub(in crate::afxdp) tunnel_endpoints: FastMap<u16, TunnelEndpoint>,
    pub(in crate::afxdp) tunnel_endpoint_by_ifindex: FastMap<i32, u16>,
    /// #2327: kind-segregated, outer-tuple-keyed index for the GRE
    /// decap fast path. Keyed by the OUTER tuple as seen FROM THE
    /// ENDPOINT's perspective — `(outer_family, endpoint.source,
    /// endpoint.destination)` — so a received GRE frame is matched with
    /// `(meta.addr_family, outer_dst, outer_src)`. Only `mode == "gre"`
    /// / `"ip6gre"` endpoints are indexed (kind-segregation): a GRE
    /// (proto-47) packet can NEVER be decapped against a WireGuard or
    /// any non-GRE row even if its outer tuple/key collide. Each bucket
    /// is a `Vec<u16>` of endpoint IDs so a duplicate outer tuple
    /// (keyed vs unkeyed, or different logical ifindex) is disambiguated
    /// by the GRE key at lookup rather than resolved non-deterministically
    /// by a first-match scan. Replaces the per-packet O(N)
    /// `tunnel_endpoints.values().find(...)` scan (agy #4).
    pub(in crate::afxdp) gre_decap_index: FastMap<(i32, IpAddr, IpAddr), Vec<u16>>,
    /// WireGuard engines keyed by tunnel_endpoint_id (#1432 S2a). One
    /// per `mode == "wireguard"` endpoint. Shared (`Arc`) so workers
    /// hold the engine across a forwarding-state ArcSwap; engine
    /// identity is reused across reloads when the endpoint config is
    /// unchanged (see `forwarding_build::wg`), so the TAI64N clock and
    /// live sessions survive a commit that does not touch the tunnel.
    pub(in crate::afxdp) wg_engines: FastMap<u16, std::sync::Arc<crate::afxdp::wg::WgEngine>>,
    /// True iff any WG engine is configured. Cheap single-bool gate so
    /// non-WG paths never probe `wg_engines` per packet (#1432 §4.5).
    pub(in crate::afxdp) has_wg_tunnels: bool,
    pub(in crate::afxdp) neighbors: FastMap<(i32, IpAddr), NeighborEntry>,
    pub(in crate::afxdp) ifindex_to_name: FastMap<i32, String>,
    pub(in crate::afxdp) ifindex_to_config_name: FastMap<i32, String>,
    /// #3096: ifindex → routing-instance (VRF) name. Built at config-commit
    /// from each interface snapshot's `routing_instance` ("" = the default
    /// instance). Used by the NAT match path to enforce a
    /// `from`/`to routing-instance` scope against the flow's ingress/egress
    /// interface VRF. An ifindex absent here resolves to "" (default).
    pub(in crate::afxdp) ifindex_to_routing_instance: FastMap<i32, String>,
    /// #7160 (#2387): LOGICAL ifindex -> routing DOMAIN id, the numeric twin of
    /// `ifindex_to_routing_instance` above. Built at config-commit from
    /// `InterfaceSnapshot::routing_domain`, which Go derives from the instance
    /// NAME (`StableRoutingInstanceTableID`). Absent / default instance = 0.
    ///
    /// It is a SEPARATE map rather than a lookup through the name map because
    /// this one is read on the packet path: the name map answers a
    /// config-matching question on the NAT slow path and hashes a `String`,
    /// while this answers "which routing domain does this flow belong to" for
    /// every session key built from a received frame.
    pub(in crate::afxdp) ifindex_to_routing_domain: FastMap<i32, u32>,
    /// #7160 (#2387): zone id -> routing DOMAIN, defined ONLY for a zone whose
    /// member interfaces all agree on one domain. Read on the fabric-ingress
    /// path, where the arriving interface is the fabric link rather than the
    /// flow's real ingress and the peer's zone encoding is the only ingress
    /// identity available (`ingress_routing_domain`).
    ///
    /// A zone whose interfaces span two routing instances is ABSENT rather than
    /// arbitrarily assigned — the same "identifies exactly one, or nothing"
    /// discipline as #6722's `ifindex_unambiguous_zone_id`. Absent reads as
    /// domain 0, which is the pre-#7160 answer.
    pub(in crate::afxdp) zone_routing_domain: FastMap<u16, u32>,
    /// #7160: true iff ANY interface resolves to a non-zero routing domain,
    /// i.e. iff at least one interface is a member of a named routing
    /// instance. Single-bool gate so a deployment with no routing-instance
    /// interface membership — every deployment before this change, and the
    /// overwhelming majority after it — never probes the map at all and its
    /// session identity stays bit-identical to pre-#7160.
    pub(in crate::afxdp) has_routing_domains: bool,
    /// #921: ifindex → zone ID (was `FastMap<i32, String>`). Built
    /// at config-commit time from the snapshot's per-interface
    /// zone NAME via the `zone_name_to_id` lookup. Hot-path callers
    /// read u16 directly; slow-path display sites translate via
    /// `zone_id_to_name`. Unknown / dropped zones map to `0`.
    pub(in crate::afxdp) ifindex_to_zone_id: FastMap<i32, u16>,
    /// #6722: ifindex → the nonzero zone id this ifindex EGRESSES into, or
    /// ABSENT when it identifies no single zone.
    ///
    /// This is NOT `ifindex_to_zone_id` with fewer entries by accident; it
    /// answers a different question. `ifindex_to_zone_id` answers "what zone
    /// should a packet ARRIVING on this ifindex be attributed to", and it
    /// deliberately takes the last zoned row plus the child→parent propagation
    /// so a trunk parent inherits its unit's zone (#921/#3618). This map answers
    /// "does this ifindex identify exactly one zone", which is the only question
    /// the EGRESS half may safely ask: several logical identities share one
    /// ifindex (`snapshotLinuxName` collapses a non-VLAN unit 0 onto its base
    /// netdev, a RETH onto its member, every unit of an interface-level tunnel
    /// onto the tunnel device), so an ifindex several differently-zoned
    /// identities share identifies no single zone at all, and guessing one
    /// adjudicates transit under a policy the operator never wrote for that
    /// interface.
    ///
    /// DECIDED IN GO, CORROBORATED HERE. The answer is `stampEgressZones`
    /// (`pkg/dataplane/userspace/interfaces.go`), which has the two inputs this
    /// side does not: the operator's AUTHORED `security-zone <z> interfaces
    /// <ref>` bindings before `buildInterfaceZoneMap` fanned them UP to bases
    /// (the fan-DOWN onto a bare reference's units is kept — that is what the
    /// reference means), and `snapshotLinuxName` itself. It arrives as
    /// `InterfaceSnapshot::egress_zone`, identical on every row of an ifindex.
    /// `forwarding_build::interfaces::populate_interfaces` admits it only when a
    /// row on that ifindex literally names that zone — a corroboration, so a
    /// drifted or hostile snapshot can never conjure a zone no row named — and
    /// otherwise leaves the ifindex absent, which resolves the 0 sentinel.
    ///
    /// Rounds 4 through 9 of #6722 instead built this map HERE by polling the
    /// rows and exempting the ones whose vote was an artefact. That approach
    /// produced nine successive spellings, each closed by adding a case to a
    /// predicate and each holed by a config shape it had not enumerated, because
    /// a row's `zone` is the OUTCOME of the Go derivation and the outcome cannot
    /// say whether the operator zoned THIS identity or whether the row inherited
    /// another's words. There is no per-row classification left on this side.
    ///
    /// Read by BOTH arms of the egress path: [`ForwardingState::egress_zone_id`]
    /// (now a single read of this map — see its doc for why the `egress` arm
    /// went away) and `forwarding_build::interfaces::populate_egress`, which
    /// sources each `EgressInterface::zone_id` from here rather than from the
    /// row, because `state.egress` is written last-write-wins per ifindex and a
    /// row-sourced zone let the final row re-arm an ifindex this map holds
    /// ambiguous.
    pub(in crate::afxdp) ifindex_unambiguous_zone_id: FastMap<i32, u16>,
    pub(in crate::afxdp) zone_name_to_id: FastMap<String, u16>,
    pub(in crate::afxdp) zone_id_to_name: FastMap<u16, String>,
    /// #6458: zone ID → deduplicated redundancy-group IDs (> 0) of the
    /// zone's member interfaces, built at config-commit from
    /// `ifindex_to_zone_id` x `EgressInterface.redundancy_group`. A zone is
    /// ABSENT here when none of its members is RG-bound (mgmt/fxp0,
    /// control/em0+fab, unzoned-member zones, empty zones). Read on the
    /// fabric-ingress zone-stamp validation path
    /// (`forwarding::fabric::zone_encoded_fabric_stamp_valid`): a stamped
    /// zone claim is legitimate only when the zone could have been
    /// ingressed on the PEER, which requires the zone to be RG-bound and
    /// none of its RGs to be forwarding-active locally.
    pub(in crate::afxdp) zone_to_rgs: FastMap<u16, Vec<i32>>,
    /// #3070: per-zone host-inbound-traffic admission set, keyed by the same
    /// validated zone id as `zone_id_to_name`. A zone is present here only when
    /// the config declared a `host-inbound-traffic` stanza for it; an absent
    /// entry means "not configured" → the dataplane preserves admit-all for
    /// host-bound (local-delivery) traffic ingressing that zone. Read on the
    /// local-delivery admit path (session miss AND session hit) to default-deny
    /// host-bound traffic whose service/protocol is not listed.
    pub(in crate::afxdp) zone_host_inbound: FastMap<u16, ZoneHostInbound>,
    /// #3362: per-INTERFACE host-inbound-traffic OVERRIDE admission set, keyed by
    /// ingress ifindex. Populated only for an interface that declared an
    /// interface-level `host-inbound-traffic` stanza (and is not a lifeline); the
    /// carried set is the EFFECTIVE set computed in Go, where the interface stanza
    /// REPLACES the zone-level one (#6515). When
    /// a packet's ingress ifindex is present here the local-delivery admit path
    /// uses THIS set instead of the from-zone's `zone_host_inbound` entry, so a
    /// service exposed on one interface of a zone is admitted there while the
    /// zone-default set governs the zone's other interfaces. An absent ifindex
    /// falls back to the zone-keyed check (pre-#3362 behaviour).
    pub(in crate::afxdp) ifindex_host_inbound: FastMap<i32, ZoneHostInbound>,
    /// #3071: zone IDs (from `ZoneSnapshot.tcp_rst`) with Junos `tcp-rst`
    /// enabled. A TCP flow DENIED by policy/default-deny whose ingress
    /// (from) zone is present here is answered with a TCP RST toward the
    /// source instead of a silent drop. Absent zone ⇒ tcp-rst off.
    pub(in crate::afxdp) zone_tcp_rst: FastMap<u16, bool>,
    /// #3618: per-(from-)zone rate-limit buckets for locally-generated `reject`
    /// replies (policy `then reject`, firewall-filter / lo0 `then reject`, and
    /// a zone `tcp-rst` deny). One GCRA `TokenBucket` per CONFIGURED zone id,
    /// built in `populate_zones` from the SAME validated zone set as
    /// `zone_id_to_name` (cardinality = configured zones, Go-capped ≤ 65533 —
    /// not attacker-growable). Before #3618 a SINGLE process-global bucket
    /// rate-limited every reject, so a rejected-flow flood ingressing one zone
    /// drained it and starved legitimate reject-generation in a DIFFERENT zone;
    /// per-zone buckets remove that cross-zone starvation while keeping each
    /// ingress path capped at the same rate.
    ///
    /// Keyed by the ingress interface's configured zone id
    /// (`ifindex_to_zone_id`); an unzoned (id 0) or unknown from-zone falls back
    /// to the process-global `REJECT_FALLBACK_BUCKET` at the gate (never
    /// fail-open). Held as `Arc<TokenBucket>` so the shared atomics survive
    /// `ForwardingState::clone()` — the coordinator re-stores a clone of the
    /// forwarding state at runtime cadence (fabric refresh), and a plain-value
    /// clone would snapshot stale coordinator-side atomics and effectively reset
    /// the limiter every refresh. A genuine config rebuild re-runs
    /// `populate_zones` and installs fresh buckets (reset-on-commit, accepted
    /// for a diagnostic limiter). See `docs/generated-reply-rate-limit.md`.
    pub(in crate::afxdp) reject_buckets:
        FastMap<u16, std::sync::Arc<crate::afxdp::icmp_ratelimit::TokenBucket>>,
    /// #5856: per-(from-)zone rate-limit buckets for locally-generated ICMP
    /// Time-Exceeded / Hop-Limit-Exceeded replies, and for Packet-Too-Big /
    /// Frag-Needed PMTUD replies. Built in `populate_zones` from the SAME
    /// validated zone set as `reject_buckets` (#3618) — one GCRA `TokenBucket`
    /// per configured zone id, keyed by the ingress interface's configured
    /// zone id (`ifindex_to_zone_id`); an unzoned (id 0) or unknown from-zone
    /// falls back to the process-global `TIME_EXCEEDED_FALLBACK_BUCKET` /
    /// `PACKET_TOO_BIG_FALLBACK_BUCKET` at the gate (never fail-open).
    ///
    /// Before #5856 these two reasons shared a SINGLE process-global bucket, so
    /// an attacker flooding TTL=1/hop-limit=1 (→ Time-Exceeded) or oversized-DF
    /// (→ Packet-Too-Big) traffic through ONE ingress zone drained the shared
    /// bucket and suppressed legitimate traceroute / PMTUD replies for EVERY
    /// other zone (a cross-zone denial of the generated-error service). Per-zone
    /// buckets remove that starvation exactly as #3618 did for Reject. Held as
    /// `Arc<TokenBucket>` for the same reason `reject_buckets` is — the shared
    /// atomics must survive `ForwardingState::clone()` (fabric refresh). Cardin-
    /// ality is config-bounded (Go-capped ≤ 65533), never attacker-growable.
    pub(in crate::afxdp) time_exceeded_buckets:
        FastMap<u16, std::sync::Arc<crate::afxdp::icmp_ratelimit::TokenBucket>>,
    pub(in crate::afxdp) packet_too_big_buckets:
        FastMap<u16, std::sync::Arc<crate::afxdp::icmp_ratelimit::TokenBucket>>,
    pub(in crate::afxdp) egress: FastMap<i32, EgressInterface>,
    pub(in crate::afxdp) ingress_logical_ifindex: FastMap<(i32, u16), i32>,
    pub(in crate::afxdp) fabrics: Vec<FabricLink>,
    /// #3773 (M13): fabric links this build/refresh pass SKIPPED because a
    /// value was malformed (`parent_ifindex <= 0`, an unparseable
    /// `peer_address`, or a NON-EMPTY unparseable local/peer MAC) or because
    /// the peer/local MAC could not be resolved yet (an EMPTY MAC field
    /// awaiting neighbor/interface resolution — the expected transient of the
    /// late-resolution `SyncFabricState` path). Before #3773 each skip was a
    /// bare `continue` with no counter, log, or status, so an HA cross-chassis
    /// fabric link that silently failed to install was invisible to the
    /// operator. Populated by `populate_fabrics` (snapshot build) and
    /// `resolve_fabric_links_from_snapshots` (runtime refresh); each push also
    /// bumps the cumulative `FABRIC_LINK_SKIPPED_MALFORMED` /
    /// `FABRIC_LINK_UNRESOLVED_PEER` diagnostic atomics surfaced in
    /// status/Prometheus, and a transition (`log_fabric_skip_transition`)
    /// names the link in the journal. This list is the most-recent
    /// resolution pass's skips — the coordinator prunes an entry whose
    /// parent is re-added by the preserved-fabric merge (snapshot_refresh).
    pub(in crate::afxdp) fabric_skips: Vec<FabricLinkSkip>,
    pub(in crate::afxdp) allow_dns_reply: bool,
    pub(in crate::afxdp) allow_embedded_icmp: bool,
    /// `security alg <proto> disable` bitfield (#2008 H3/H4): bit 0 DNS,
    /// bit 1 FTP, bit 2 SIP, bit 3 TFTP. Read at session-create time to
    /// suppress ALG-type tagging for a disabled ALG. Junos `alg disable`
    /// turns the ALG off; it never drops traffic, so a set bit only
    /// changes the session's reported alg_type to 0 (none).
    pub(in crate::afxdp) alg_disable_flags: u8,
    /// #2008 M5: L3/L4 application-identification catalog. Resolves a session's
    /// 5-tuple to the numeric app_id stamped on the conntrack session at
    /// create time, so `show security flow session` reports a real application
    /// name. Empty when the Go snapshot carries no catalog (AppID disabled or
    /// an old Go binary) — sessions then keep app_id 0 (unknown).
    pub(in crate::afxdp) app_catalog: AppCatalog,
    pub(in crate::afxdp) session_timeouts: crate::session::SessionTimeouts,
    /// #3527: per-ingress-zone override (zone id → ns) of the global half-open
    /// (`tcp_opening_ns`) TCP window, built from each screened zone's
    /// `syn-flood timeout`. Pushed onto the worker `SessionTable` via
    /// `set_opening_overrides` alongside `session_timeouts`. Empty when no zone
    /// configures a syn-flood timeout (the common case), byte-identical to
    /// pre-#3527.
    pub(in crate::afxdp) session_opening_overrides: FastMap<u16, u64>,
    pub(in crate::afxdp) policy: PolicyState,
    pub(in crate::afxdp) source_nat_rules: Vec<SourceNatRule>,
    /// #6751: the interface-mode source-NAT translated-identity registry.
    ///
    /// NODE-LIFETIME, not per-build. Held as an `Arc` and CARRIED OVER by
    /// `build_forwarding_state_*` from the `previous` state (both production
    /// build sites pass `Some(&self.forwarding)`), for the same reason
    /// `time_exceeded_buckets` is an `Arc` — the shared state must survive
    /// `ForwardingState::clone()` and every apply. Rebuilding it on commit
    /// would discard the occupancy of every live interface-SNAT session and
    /// let the next flow preserve a source port that is still on the wire,
    /// which is exactly the ambiguity #6751 closes.
    ///
    /// Reached by the MINT path (`match_source_nat_result_for_tuple`) and by
    /// the RELEASE path (`release_source_nat_allocation*`) — the latter
    /// explicitly rather than through `source_nat_rules`, because a release
    /// must still find the registry after a commit that removed every
    /// source-NAT rule.
    pub(in crate::afxdp) iface_nat_allocators: std::sync::Arc<crate::nat::InterfaceNatAllocators>,
    pub(in crate::afxdp) static_nat: StaticNatTable,
    pub(in crate::afxdp) dnat_table: DnatTable,
    pub(in crate::afxdp) nat64: Nat64State,
    pub(in crate::afxdp) nptv6: Nptv6State,
    pub(in crate::afxdp) screen_profiles: FastMap<String, ScreenProfile>,
    /// #3082: zone → name of a screen profile the zone REFERENCES but that was
    /// undefined when the snapshot was built. Distinct from `screen_profiles`
    /// (which only holds resolved profiles): a zone present here but absent
    /// from `screen_profiles` is a lenient-path fail-open — the dataplane
    /// emits a rate-limited runtime WARN for it (verdict still Pass). A zone
    /// in neither map simply has no screen configured (legit Pass).
    pub(in crate::afxdp) screen_missing_profiles: FastMap<String, String>,
    /// #7888: zone -> screen profile name for zones whose profile IS DEFINED
    /// but enables no check. Kept separate from `screen_missing_profiles`
    /// because the two select different runtime WARN texts.
    pub(in crate::afxdp) screen_inert_profiles: FastMap<String, String>,
    pub(in crate::afxdp) syn_cookie_master_key: SynCookieMasterKey,
    pub(in crate::afxdp) tunnel_interfaces: FastSet<i32>,
    pub(in crate::afxdp) filter_state: crate::filter::FilterState,
    pub(in crate::afxdp) cos: CoSState,
    pub(in crate::afxdp) tx_selection_enabled_v4: bool,
    pub(in crate::afxdp) tx_selection_enabled_v6: bool,
    /// `security flow gre-performance-acceleration` (#3360). On vSRX this
    /// extracts the GRE key/call-id into the session tuple so multiple GRE
    /// tunnels between the same endpoints map to distinct sessions. The
    /// userspace dataplane keys GRE flows on the 5-tuple only, so this flag is
    /// threaded into ForwardingState for config truth/parity but is NOT yet read
    /// by any packet/forwarding path — hence `#[allow(dead_code)]`. The consumer
    /// #7188: READ by stage_parse_flow_and_learn, which gives transit GRE an
    /// identity keyed on the RFC 2890 discriminator when this is set. Off, the
    /// packet stays flowless exactly as #6837 left it.
    pub(in crate::afxdp) gre_acceleration: bool,
    /// #9054: the daemon withheld this snapshot's kernel-learned route import
    /// (the #8355 cap), so this FIB is deliberately missing the dynamic table
    /// and `NoRoute` does not mean "no route exists". Read only by
    /// `noroute_policy_denial_gated`, which carries the reasoning.
    pub(in crate::afxdp) learned_route_import_capped: bool,
    /// `security flow power-mode-disable` (#2008 H14). vSRX power-mode is an
    /// express datapath; this flag forces the regular flow path when set. The
    /// userspace dataplane has a single forwarding path, so the flag is held
    /// for config truth/parity and does not currently switch behavior (there
    /// is no express/regular split to select between).
    #[allow(dead_code)]
    pub(in crate::afxdp) power_mode_disable: bool,
    // #2130: the dead Rust FlowExporter + its flow_export_config field were
    // removed. Flow export is owned by the Go control plane (pkg/flowexport);
    // the dataplane emits no flow records.
    pub(in crate::afxdp) mirror_configs: FastMap<i32, MirrorRuntimeConfig>,
    pub(in crate::afxdp) tcp_mss_all_tcp: u16,
    pub(in crate::afxdp) tcp_mss_ipsec_vpn: u16,
    pub(in crate::afxdp) tcp_mss_gre_in: u16,
    pub(in crate::afxdp) tcp_mss_gre_out: u16,
    /// #1620: cold-path latency histogram sample mask delivered via
    /// `ConfigSnapshot.cold_path_sample_mask`. `0xff` = 1-in-256
    /// (default); `0` = 1-in-1 (bounded-cohort microbench only,
    /// requires operator-explicit `--enable-cold-path-1-in-1-sampling`
    /// on the Go side). Read by the poll_descriptor pre-eval gate;
    /// updated atomically via ArcSwap on every snapshot apply.
    pub(in crate::afxdp) cold_path_sample_mask: u64,
    /// #1636 option D: how long a queued packet with an unresolved
    /// neighbor is held before being dropped + recycled. Computed per
    /// snapshot in `build_forwarding_state_with_policy_counters_and_previous`
    /// (`compute_pending_neigh_timeout_ns`): 800ms when the kernel
    /// `retrans_time_ms` is <= NEIGH_RETRANS_FAST_THRESHOLD_MS (300ms —
    /// the daemon writes 250 but the kernel jiffy-rounds it to 252 on
    /// HZ=100) on all dataplane interfaces (v4 AND v6) so a dropped SYN is
    /// re-driven before the client's first TCP RTO; otherwise the safe
    /// 2000ms default (sysctl unapplied → fail closed). Re-evaluated every
    /// snapshot so a mid-life sysctl change is picked up. `0` (the
    /// Default) means "unset" — callers fall back to
    /// `PENDING_NEIGH_TIMEOUT_NS`.
    pub(in crate::afxdp) pending_neigh_timeout_ns: u64,
    /// #6710: egress ifindexes that can NEVER resolve a link-layer neighbor,
    /// because the netdev has no link-layer address by construction.
    ///
    /// Today this is exactly the IPsec `xfrmi` set, carried by the existing
    /// authoritative `InterfaceSnapshot.secure_tunnel` flag — no wire change:
    /// the Go control plane already computes it (`snapshotSecureTunnel`, the
    /// union of "some `security ipsec vpn <n> bind-interface` names this
    /// device" and "the netdev's kernel link kind is `xfrm`") and this plane
    /// reads the one flag rather than re-deriving a name grammar, exactly as
    /// `userspace_unbindable_netdev` already does for binding planning.
    ///
    /// WHY THE FORWARDING PLANE NEEDS IT. A connected route to such an ifindex
    /// resolves `MissingNeighbor` forever: `lookup_neighbor_entry` can never
    /// hit, so the packet takes the cold arm, is buffered in `pending_neigh`,
    /// probes, times out — and the timeout is what ARMS the dead-host negative
    /// cache. For a real dead host that cache is a 3 s penalty that ends when
    /// the host answers; here the "host" is a device that has nothing to answer
    /// with, so `neg_neigh_gate`'s resolved-neighbor-wins escape can never
    /// fire and the arm/expire cycle repeats indefinitely. Every armed window
    /// recycles the frame BEFORE the slow-path reinject that is the only way
    /// LAN→tunnel traffic reaches the kernel XFRM stack at all.
    pub(in crate::afxdp) lladdrless_egress: FastSet<i32>,
    /// #1635: direct `(from_zone_id, to_zone_id) → slot` map for the
    /// cold-path histogram, built at config apply from the configured
    /// policy zone-pairs. Replaces the splitmix64 16-slot hash. Shared
    /// by all bindings on a worker; read on every sampled session-miss
    /// via `lookup_slot`. Rotated via the ForwardingState ArcSwap.
    pub(in crate::afxdp) cold_path_slot_map:
        std::sync::Arc<crate::afxdp::cold_path_hist::ColdPathSlotMap>,
    /// #3651: flat zone-id → hot-path slot LUT for per-zone traffic counters,
    /// rebuilt from the configured zone set at each config apply. Read on every
    /// forwarded packet via `record_zone_traffic` (two array reads, no hash).
    /// Rotated via the ForwardingState ArcSwap alongside `cold_path_slot_map`.
    pub(in crate::afxdp) zone_counter_slot_map:
        std::sync::Arc<crate::afxdp::zone_counters::ZoneCounterSlotMap>,
    /// #3651: coordinator-owned cumulative per-zone traffic totals. Keyed by
    /// stable zone id, `Clone` shares the inner `Arc<Mutex>`, so cloning this
    /// state (worker publish) and carrying it forward across config applies
    /// (`forwarding_build`) keeps totals alive until the operator
    /// `clear_zone_counters` IPC resets them.
    pub(in crate::afxdp) zone_counter_store: crate::afxdp::zone_counters::ZoneCounterStore,
    /// #3651: flat zone-id → slot LUT for the per-zone SYN/ICMP/UDP flood-event
    /// counters, rebuilt from the same configured zone set as
    /// `zone_counter_slot_map` at each config apply. Read on a screen DROP (not
    /// on the forward path) via `record_zone_flood_drop`. Rotated via the
    /// ForwardingState ArcSwap alongside its siblings.
    pub(in crate::afxdp) flood_counter_slot_map:
        std::sync::Arc<crate::afxdp::flood_counters::FloodCounterSlotMap>,
    /// #3651: coordinator-owned cumulative per-zone flood-event totals. Keyed by
    /// stable zone id, `Clone` shares the inner `Arc<Mutex>`, so cloning this
    /// state (worker publish) and carrying it forward across config applies
    /// keeps totals alive until the operator `clear_flood_counters` IPC resets
    /// them.
    pub(in crate::afxdp) flood_counter_store: crate::afxdp::flood_counters::FloodCounterStore,
    /// #8291: cumulative GRE decap refusal totals. `Clone` shares the inner
    /// `Arc`, so a worker publish and a config apply both keep the total alive
    /// — the same contract as the two #3651 stores above, and carried at the
    /// same site by `forwarding_build::attach_carried_counters`.
    pub(in crate::afxdp) gre_decap_counters: crate::afxdp::gre::GreDecapCounters,
}

/// #3070/#3405: a zone's compiled host-inbound-traffic admission set. Built from
/// the raw Junos `system-services` / `protocols` tokens on the wire
/// (`ZoneSnapshot`) at config-apply time (`zone_host_inbound_from_snapshot`),
/// then read on the per-packet local-delivery admit path. At the map level an
/// absent `ZoneHostInbound` still means admit-all (the pre-#3070 behaviour) for
/// that zone id — but that no longer describes a configured no-stanza zone.
/// Post-#3405 the Go control plane sends HostInboundConfigured=true for EVERY
/// configured zone (security.go:70, zones.go:448), so a zone with NO
/// `host-inbound-traffic` stanza produces a PRESENT entry with an EMPTY token
/// set (`admits()` -> false for every service/protocol => default-DENY, Junos
/// parity). The absent-entry admit-all branch therefore now applies only to a
/// zone not present in the snapshot at all (legacy / truly-unconfigured).
/// Lifeline interfaces (fxp0/em0/fab*) never reach this classifier (#3682).
/// SSOT for the token semantics: docs/host-inbound-service-matrix.md.
///
/// Service tokens are classified to L4 signatures: TCP/UDP services contribute
/// destination ports; ICMP-bearing services (ping, router-discovery) contribute
/// the specific ICMP/ICMPv6 *types* they imply (#3201/#3240 — not the whole
/// protocol); the raw `protocols` routing tokens contribute an IP-protocol
/// number. `all_services` (Junos `any-service` ONLY — `system-services { all }`
/// is NOT a full admit since #3226, it expands to the named service union)
/// short-circuits to a full admit. `protocols { all }` is NOT a
/// blanket admit (#3199): it expands at classify time to the routing-protocol
/// signatures (ospf/bgp/rip/.../router-discovery), so it admits routing
/// protocols but never a system service (SSH/HTTPS/SNMP/...) that was not
/// separately permitted. An UNRECOGNISED token contributes nothing
/// (fail-closed: it does not broaden the admit set), so a host-bound packet
/// matching no listed service/protocol is denied.
#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ZoneHostInbound {
    /// `system-services { any-service }` — admit every host-bound packet
    /// regardless of service. Junos defines `any-service` as "all system
    /// services on an entire port range including the system services that are
    /// not defined", the explicit escape hatch for traffic the named set does
    /// not cover; xpf reads it as a superset (every IP protocol, not just the
    /// TCP/UDP port range), which is the fail-safe direction for a token whose
    /// purpose is to over-admit.
    ///
    /// #3226: `system-services { all }` NO LONGER sets this. Junos scopes `all`
    /// to "traffic from the defined system services available on the Routing
    /// Engine", so it now EXPANDS at classify time to the named-service
    /// signatures (`system_service_all_expansion`, host_inbound.rs) exactly as
    /// `protocols { all }` expands to the routing-protocol set (#3199).
    /// Previously `all` short-circuited here, so an `all` zone admitted every
    /// IP protocol — GRE/ESP/AH/OSPF/PIM/VRRP and arbitrary future protocol
    /// numbers — to its local addresses with no default deny.
    pub(in crate::afxdp) all_services: bool,
    /// Admitted TCP destination ports (ssh=22, https=443, bgp=179, ...).
    pub(in crate::afxdp) tcp_ports: FastSet<u16>,
    /// Admitted DUAL-FAMILY UDP destination ports (dns=53, ike=500/4500, ...).
    /// Family-specific UDP services live in `udp_ports_v4` / `udp_ports_v6`.
    pub(in crate::afxdp) udp_ports: FastSet<u16>,
    /// #3225: IPv4-ONLY admitted UDP ports (dhcp/bootp=67/68, rip=520). Consulted
    /// by `admits` only when the packet is IPv4, so a `system-services dhcp` zone
    /// does not open udp/67-68 on the IPv6 path.
    pub(in crate::afxdp) udp_ports_v4: FastSet<u16>,
    /// #3225: IPv6-ONLY admitted UDP ports (dhcpv6=546/547, ripng=521). Consulted
    /// by `admits` only when the packet is IPv6.
    pub(in crate::afxdp) udp_ports_v6: FastSet<u16>,
    /// #3201/#3240: admitted ICMPv4 *types* (not the whole protocol). A service
    /// contributes only the ICMP subtypes it implies — `ping` → echo-request
    /// (8); `router-discovery` → router-advertisement/solicitation (9, 10) —
    /// mirroring the kernel nft chain (`pkg/daemon/daemon_nft.go`
    /// `hostInboundServiceMatches` / `hostInboundProtocolMatches`), so the
    /// AF_XDP fast-path admit set equals the nft chain's per-service type set.
    /// ICMP *error* / PMTUD subtypes are admitted globally and unconditionally
    /// by `is_icmp_host_inbound_global_accept` (#3171), so they are NOT carried
    /// per-zone here.
    pub(in crate::afxdp) icmp_types_v4: FastSet<u8>,
    /// #3201/#3240: admitted ICMPv6 *types* — `ping` → echo-request (128).
    /// `router-discovery` adds nothing on v6 (RS/RA ride the globally-accepted
    /// ND set in `is_icmp_host_inbound_global_accept`, matching the nft chain
    /// which returns nil for v6 router-discovery).
    pub(in crate::afxdp) icmp_types_v6: FastSet<u8>,
    /// Admitted DUAL-FAMILY bare IP protocol numbers (gre=47, esp=50, ah=51,
    /// vrrp=112, pim=103, ...). Checked for non-TCP/UDP/ICMP packets.
    /// Family-specific protocols live in `ip_protocols_v4` / `ip_protocols_v6`.
    pub(in crate::afxdp) ip_protocols: FastSet<u8>,
    /// #3225: IPv4-ONLY admitted IP protocol numbers (ospf=OSPFv2=89, igmp=2).
    /// Consulted by `admits` only when the packet is IPv4.
    pub(in crate::afxdp) ip_protocols_v4: FastSet<u8>,
    /// #3225: IPv6-ONLY admitted IP protocol numbers (ospf3=OSPFv3=89). Consulted
    /// by `admits` only when the packet is IPv6, so a `protocols ospf` (v2) zone
    /// does not open proto 89 on IPv6 and vice versa.
    pub(in crate::afxdp) ip_protocols_v6: FastSet<u8>,
}

impl ZoneHostInbound {
    /// Returns true iff a host-bound packet with the given L4 protocol,
    /// destination port and (for ICMP/ICMPv6) type is admitted by this zone's
    /// host-inbound set. `icmp_type` is the first L4 byte for protocol 1 / 58
    /// and is ignored for every other protocol.
    pub(in crate::afxdp) fn admits(
        &self,
        protocol: u8,
        dst_port: u16,
        is_v6: bool,
        icmp_type: u8,
    ) -> bool {
        // Only `system-services { any-service }` is a full admit. NEITHER
        // `system-services { all }` (#3226) NOR `protocols { all }` (#3199) is
        // a blanket bypass: each expands to its concrete signatures at classify
        // time and is matched below via tcp/udp/icmp/ip_protocols, so a
        // `system-services all` zone can never admit a raw IP protocol
        // (GRE/ESP/OSPF/PIM/VRRP/...) that was not separately permitted, and a
        // `protocols all` zone can never admit a system service (SSH, HTTPS,
        // SNMP, ...) that was not separately permitted.
        if self.all_services {
            return true;
        }
        match protocol {
            // TCP
            6 => self.tcp_ports.contains(&dst_port),
            // UDP — dual-family ports OR the family-scoped set for this packet's
            // family (#3225: dhcp/rip are v4-only, dhcpv6/ripng v6-only).
            17 => {
                self.udp_ports.contains(&dst_port)
                    || if is_v6 {
                        self.udp_ports_v6.contains(&dst_port)
                    } else {
                        self.udp_ports_v4.contains(&dst_port)
                    }
            }
            // ICMPv4 — admit only the configured subtypes (#3201/#3240), e.g.
            // `ping` → echo-request (8), `router-discovery` → 9/10. Error /
            // PMTUD subtypes are admitted earlier by the global exemption.
            1 => self.icmp_types_v4.contains(&icmp_type),
            // ICMPv6 — admit only the configured subtypes (#3201/#3240).
            58 => self.icmp_types_v6.contains(&icmp_type),
            other => {
                // Bare IP protocol — dual-family OR the family-scoped set
                // (#3225: ospf=OSPFv2 v4-only, ospf3=OSPFv3 v6-only, igmp v4).
                self.ip_protocols.contains(&other)
                    || if is_v6 {
                        self.ip_protocols_v6.contains(&other)
                    } else {
                        self.ip_protocols_v4.contains(&other)
                    }
            }
        }
    }
}

impl ForwardingState {
    /// #3071: true iff zone `zone_id` has Junos `tcp-rst` enabled. Used by the
    /// policy-deny path to decide whether a denied TCP flow whose ingress
    /// (from) zone is `zone_id` gets a TCP RST instead of a silent drop. An
    /// unconfigured / unknown zone (e.g. `0`) is always tcp-rst off.
    pub(in crate::afxdp) fn zone_tcp_rst_enabled(&self, zone_id: u16) -> bool {
        self.zone_tcp_rst.get(&zone_id).copied().unwrap_or(false)
    }

    /// #3651: the egress (to) zone id for `egress_ifindex`, or `0` when the
    /// interface is unknown / unzoned. THE single egress-zone resolver: the
    /// zone-pair resolver (`zone_pair_ids_for_flow_with_override`), the
    /// per-zone traffic counter (`record_zone_traffic`), the filter-log
    /// egress-zone field (BOTH the flow-cache-hit path via
    /// `filter_log_egress_zone_id` and `forward_request`'s own independent
    /// call) and the local-origin tunnel `SyncedSessionEntry` zones all read
    /// through here, so the adjudicated zone and the logged/counted zone do not
    /// disagree.
    ///
    /// That is true BY ENUMERATION of the callers, not by construction —
    /// nothing prevents a new site from reading `state.egress` directly and
    /// silently reintroducing the #6713 split. Three of the sites are pinned by
    /// tests (`zoned_macless_unit_still_reaches_policy_6713`,
    /// `filter_log_egress_zone_id_reports_a_macless_tunnels_zone_6713`,
    /// `build_live_forward_request_logs_a_macless_egress_zone_6713`); the
    /// zone-accounting readers are not, so a new direct read there would not be
    /// caught by this suite. Route new consumers through this fn.
    ///
    /// #6713: `egress` is NOT the authoritative ifindex -> zone map —
    /// `ifindex_to_zone_id` is. `populate_egress` skips any interface whose
    /// link-layer address cannot be resolved (`interfaces.rs`, the `src_mac`
    /// gate), which for an IPsec secure tunnel (xfrmi) is UNCONDITIONAL: it is
    /// `ARPHRD_NONE`, so `hardware_addr` is empty, the parent is itself a
    /// MAC-less xfrmi, and `iface.tunnel` means a Junos `tunnel {source
    /// destination}` stanza that `st0` does not have. Reading only `egress`
    /// therefore returned `0` for a correctly-zoned tunnel, and zone id 0 is
    /// the reserved "unknown" sentinel that `evaluate_policy_result_l3_aware`
    /// refuses to match ANY exact, wildcard or `junos-global` rule against — so
    /// no operator-authored permit could ever apply to LAN->tunnel transit and
    /// every packet fell to the default policy.
    ///
    /// #6722, WHY THIS IS NOT `ifindex_to_zone_id`. Several rows can share ONE
    /// ifindex, by THREE distinct mechanisms in
    /// `pkg/dataplane/userspace/interfaces.go`'s `snapshotLinuxName`:
    ///
    /// (a) a non-VLAN unit 0 collapses onto its base netdev, so `st0` and
    ///     `st0.0` are one ifindex, as are `ge-0/0/1` and `ge-0/0/1.0`;
    /// (b) an interface-level tunnel maps EVERY unit onto the base device via
    ///     `TunnelNameMap`, so `wg0`, `wg0.0` and `wg0.1` are one ifindex;
    /// (c) `ResolveReth` (`pkg/config/types.go`) resolves a RETH to its
    ///     PHYSICAL MEMBER, so `reth1`, `reth1.0` and the member row
    ///     `ge-0/0/1` are one ifindex — and a member's own units alias the
    ///     matching reth unit the same way (`ge-0/0/1.100` onto `reth1.100`).
    ///
    /// (c) is the one that reaches a SHIPPED topology: `docs/ha-cluster-
    /// userspace.conf` is what `test/incus/loss-userspace-cluster.env` points
    /// every HA smoke test at, and it measures `ifindex 24: [ge-0/0/1=""
    /// reth1="lan" reth1.0="lan"]`. `fab0` is NOT a fourth mechanism: the fabric
    /// IPVLAN is its own netdev with its own ifindex (`snapshotLinuxName` never
    /// calls `ResolveFab`), so it never shares one with its physical parent.
    ///
    /// `ifindex_to_zone_id` is therefore a per-NETDEV map, not a per-unit one:
    /// it holds the LAST zoned row's zone plus the zone `populate_interfaces`
    /// propagates from a zoned child unit onto `parent_ifindex`. Reading it
    /// here would hand an interface a nonzero zone it was never configured
    /// with, which is the fail-OPEN direction — a permit the operator wrote for
    /// a different interface would start matching this one's transit. Three
    /// producible shapes:
    ///
    /// 1. Zone only `st0.1` and the Go builder still emits the `st0` BASE row
    ///    carrying that zone (`buildInterfaceZoneMap`,
    ///    `pkg/dataplane/userspace/zones.go` — a unit-suffixed zone reference
    ///    writes `out[base]` as well), while `st0.0` — which the operator left
    ///    in NO zone — shares the base's ifindex. `ifindex_to_zone_id` says
    ///    `vpnb` for that ifindex.
    /// 2. Two units in DIFFERENT zones on one `st0` with unit 0 unzoned. The Go
    ///    `out[base]` write is FIRST-write-wins over sorted zone names, so the
    ///    base — and thus unit 0's ifindex — carries the alphabetically-first
    ///    sibling's zone.
    /// 3. StableZoneID quarantine (`zones_quarantine.go`). It unzones the
    ///    interfaces of a colliding zone AFTER `buildInterfaceSnapshots` ran,
    ///    precisely so they fail CLOSED. A base whose zone was quarantined
    ///    arrives unzoned beside a surviving zoned child, the Rust child→parent
    ///    propagation re-zones the parent's ifindex, and reading
    ///    `ifindex_to_zone_id` would hand the quarantine's deliberate
    ///    default-deny back the survivor's zone.
    ///
    /// So this reads `ifindex_unambiguous_zone_id`, which carries an ifindex
    /// only when the Go builder decided that ifindex identifies exactly one
    /// zone AND a row on it corroborated the name (`stampEgressZones` /
    /// `forwarding_build::interfaces::populate_interfaces`). An ambiguous
    /// ifindex resolves to the 0 sentinel — the pre-#6713 answer, against which
    /// no rule matches and the default policy decides.
    ///
    /// This deliberately makes the two DIRECTIONS disagree for an ambiguous
    /// ifindex: ingress still attributes a packet arriving on it to
    /// `ifindex_to_zone_id`'s zone (#921/#3618, unchanged here), while egress
    /// answers 0. That asymmetry is the point, and the reason is NOT that the
    /// ingress surface is unreachable — stated carefully, because it is only
    /// unreachable in one of the two shapes:
    ///
    /// - In the QUARANTINE shape every row on the ifindex is unzoned, and an
    ///   unzoned row is given no AF_XDP bind target: BOTH Go-side derivations
    ///   open with the same `if iface.Zone == "" || userspaceSkipsIngressInterface(iface)`
    ///   guard — `UserspaceBoundLinuxInterfaces`
    ///   (`pkg/dataplane/userspace/interfaces.go:133`, guard at `:164`), which
    ///   scopes the ethtool allowlist, and `buildUserspaceIngressIfindexes`
    ///   (`pkg/dataplane/userspace/maps_sync.go:1585`, guard at `:1592`), which
    ///   writes the ingress ifindex map the shim keys on. So no packet ever
    ///   ingresses there and only the PROPAGATED `ifindex_to_zone_id` entry
    ///   exists.
    /// - In the sibling / divergent shapes the BASE row is zoned, so the
    ///   ifindex genuinely is a bind target and ingress really does answer
    ///   `vpnb` for traffic arriving on it.
    ///
    /// The asymmetry is justified by direction, not by reachability: ingress
    /// answering wide is PRE-EXISTING behaviour this change does not touch,
    /// whereas egress answering wide is a NEW fail-open on the exact interface
    /// class #6713 just routed through the fallback — a to-zone is what makes a
    /// permit match. Whether the ingress half should be narrowed the same way is
    /// a separate question about #921/#3618 and is not settled here. Where the
    /// ifindex is UNambiguous — the #6713 case itself, `bind-interface st0` with
    /// its unit in the same zone — both halves still answer the same zone.
    ///
    /// Junos zones LOGICAL UNITS, so two same-zone units sharing one ifindex is
    /// still a parity gap in the other direction: `st0.0` and `st0.1` cannot be
    /// given DIFFERENT zones and both forward. Closing that needs per-unit
    /// identity end to end (the snapshot's unit-0 ifindex collapse, both halves
    /// of the zone resolver, and the AF_XDP bind keying) — it is tracked
    /// separately and deliberately NOT papered over at this single read. Until
    /// then such a pair fails closed rather than guessing.
    ///
    /// WHY THERE IS NO LONGER AN `egress` ARM. Through #6722 round 9 this read
    /// `self.egress` first and fell back to the ledger, with a `Some(0)`
    /// short-circuit documented as load-bearing. It stopped being either once
    /// `populate_egress` began sourcing `EgressInterface::zone_id` from THIS
    /// SAME ledger: `egress[i].zone_id` is then the ledger's value for `i`, or 0
    /// where the ledger has no entry, so both arms returned the same number and
    /// the short-circuit could not fire on a state the other arm would have
    /// answered differently. The claimed binder,
    /// `unzoned_interface_with_egress_row_stays_zone_zero_6713`, had gone
    /// VACUOUS accordingly — its mutation (filter zero before `or_else`) still
    /// returned 0. Collapsing to the single map read is exactly equivalent for
    /// every state and leaves no branch to mutate; the binder that survives is
    /// on the map this reads, not on the arm order (see that test's rewritten
    /// body).
    #[inline]
    pub(in crate::afxdp) fn egress_zone_id(&self, egress_ifindex: i32) -> u16 {
        self.ifindex_unambiguous_zone_id
            .get(&egress_ifindex)
            .copied()
            .unwrap_or(0)
    }

    /// #3618/#5856: the per-zone generated-error rate-limit bucket for `reason`
    /// and ingress (from) zone `from_zone_id`, or `None` if the zone is
    /// unconfigured / unknown (the gate then falls back to the reason's shared
    /// `*_FALLBACK_BUCKET`). Returns a plain `&TokenBucket` (deref of the held
    /// `Arc`) so the limiter gate treats a per-zone bucket and the `&'static`
    /// fallback uniformly. Used by `icmp_ratelimit::allow_generated_error_zoned*`
    /// (and, via that, the `allow_generated_reject*` convenience wrappers).
    pub(in crate::afxdp) fn generated_error_bucket(
        &self,
        reason: crate::afxdp::icmp_ratelimit::GeneratedErrorReason,
        from_zone_id: u16,
    ) -> Option<&crate::afxdp::icmp_ratelimit::TokenBucket> {
        use crate::afxdp::icmp_ratelimit::GeneratedErrorReason;
        let buckets = match reason {
            GeneratedErrorReason::TimeExceeded => &self.time_exceeded_buckets,
            GeneratedErrorReason::PacketTooBig => &self.packet_too_big_buckets,
            GeneratedErrorReason::Reject => &self.reject_buckets,
        };
        buckets.get(&from_zone_id).map(|b| b.as_ref())
    }

    /// #2851/#3182: true iff `ip` is one of the router's OWN configured
    /// interface IPs — i.e. an address this firewall must never learn from a
    /// link-local advertisement. The dynamic
    /// neighbor-learn path (ARP reply / NDP NA, and the #1787 RX source-MAC
    /// learn) uses this as an
    /// anti-poisoning gate: a host on the local link must never be able to
    /// teach us `(ifindex, our_own_ip) -> attacker_mac`. RFC 826 / RFC 4861:
    /// a node does not install a neighbor entry for an address it owns from
    /// an unsolicited advertisement.
    ///
    /// The membership test is intentionally global (not routing-table
    /// scoped): if `ip` is one of our addresses in ANY routing-instance,
    /// refusing to learn it is always correct — we resolve our own
    /// addresses via the to-self path, never via a dynamic neighbor entry.
    ///
    /// #3182: the gate is driven from the NAT-DECOUPLED `configured_iface_v*`
    /// set, NOT `local_v*`. `local_v*` excludes the IP of an interface whose
    /// zone is an interface-mode-SNAT `to_zone`
    /// (`nat_translated_local_exclusions` — e.g. the WAN `reth0.80` IP), so
    /// reusing it left the router's own SNAT/WAN interface IP poisonable. The
    /// `local_v*` membership is still OR-ed in so the static-NAT-external and
    /// DNAT-destination addresses appended to `local_v*` (late-stage
    /// local-delivery targets the router also answers for) keep their #2851
    /// protection; `configured_iface_v*` adds the genuine interface IPs that
    /// the NAT exclusion stripped. NAT-translated POOL addresses are in
    /// neither set, so the gate still scopes to addresses the router owns.
    #[inline]
    pub(in crate::afxdp) fn owns_configured_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.configured_iface_v4.contains(&v4) || self.local_v4.contains(&v4),
            IpAddr::V6(v6) => self.configured_iface_v6.contains(&v6) || self.local_v6.contains(&v6),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct MirrorRuntimeConfig {
    pub(in crate::afxdp) output_ifindex: i32,
    pub(in crate::afxdp) rate: u32,
}

/// One resolved equal-cost next-hop candidate for a static route (#2389).
/// A route with multiple configured next-hops retains every resolved
/// candidate so the lookup can distribute flows across them and skip a
/// dead candidate. `next_hop == None` with a non-zero `ifindex` is an
/// interface-only ("via <if>") candidate.
#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct RouteNextHopV4 {
    pub(in crate::afxdp) next_hop: Option<Ipv4Addr>,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct RouteNextHopV6 {
    pub(in crate::afxdp) next_hop: Option<Ipv6Addr>,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ConnectedRouteV4 {
    pub(in crate::afxdp) prefix: PrefixV4,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    /// #2388: canonical routing-table name this connected route belongs to
    /// (e.g. "inet.0" or "tenant-a.inet.0"). The lookup filters connected
    /// routes by table so a per-VRF / next-table lookup never matches a
    /// connected prefix owned by a different routing-instance. The
    /// connected vec holds one entry per interface address, so the
    /// per-packet linear scan plus a string compare stays cheap.
    pub(in crate::afxdp) table: String,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ConnectedRouteV6 {
    pub(in crate::afxdp) prefix: PrefixV6,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    /// #2388: canonical routing-table name. See `ConnectedRouteV4::table`.
    pub(in crate::afxdp) table: String,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct RouteEntryV4 {
    pub(in crate::afxdp) prefix: PrefixV4,
    /// #2389: all resolved equal-cost next-hops. Always non-empty for a
    /// forwarding (non-discard, non-next-table) route; built from the full
    /// `RouteSnapshot.next_hops` vector. The legacy single `next_hop` /
    /// `ifindex` / `tunnel_endpoint_id` accessors below select the FIRST
    /// candidate so existing call sites are unchanged; the multipath
    /// selector reads the whole slice.
    pub(in crate::afxdp) next_hops: Vec<RouteNextHopV4>,
    pub(in crate::afxdp) discard: bool,
    pub(in crate::afxdp) next_table: String,
    /// #2390: Junos route preference (admin distance; lower = preferred).
    pub(in crate::afxdp) preference: i32,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct RouteEntryV6 {
    pub(in crate::afxdp) prefix: PrefixV6,
    /// #2389: all resolved equal-cost next-hops. See `RouteEntryV4`.
    pub(in crate::afxdp) next_hops: Vec<RouteNextHopV6>,
    pub(in crate::afxdp) discard: bool,
    pub(in crate::afxdp) next_table: String,
    /// #2390: Junos route preference (admin distance; lower = preferred).
    pub(in crate::afxdp) preference: i32,
}

impl RouteEntryV4 {
    /// First (primary) next-hop ifindex, or 0 if the route has no resolved
    /// next-hop (discard / next-table). Preserves the pre-#2389 single
    /// next-hop accessor for call sites that do not multipath-select.
    pub(in crate::afxdp) fn ifindex(&self) -> i32 {
        self.next_hops.first().map(|nh| nh.ifindex).unwrap_or(0)
    }
    pub(in crate::afxdp) fn tunnel_endpoint_id(&self) -> u16 {
        self.next_hops
            .first()
            .map(|nh| nh.tunnel_endpoint_id)
            .unwrap_or(0)
    }
    pub(in crate::afxdp) fn next_hop(&self) -> Option<Ipv4Addr> {
        self.next_hops.first().and_then(|nh| nh.next_hop)
    }
}

impl RouteEntryV6 {
    pub(in crate::afxdp) fn ifindex(&self) -> i32 {
        self.next_hops.first().map(|nh| nh.ifindex).unwrap_or(0)
    }
    pub(in crate::afxdp) fn tunnel_endpoint_id(&self) -> u16 {
        self.next_hops
            .first()
            .map(|nh| nh.tunnel_endpoint_id)
            .unwrap_or(0)
    }
    pub(in crate::afxdp) fn next_hop(&self) -> Option<Ipv6Addr> {
        self.next_hops.first().and_then(|nh| nh.next_hop)
    }
}

#[cfg(test)]
impl RouteEntryV4 {
    /// Test-only single-next-hop constructor preserving the pre-#2389
    /// `{ ifindex, tunnel_endpoint_id, next_hop }` shape so existing FIB
    /// tests read straightforwardly.
    pub(in crate::afxdp) fn single(
        prefix: PrefixV4,
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv4Addr>,
        discard: bool,
        next_table: String,
        preference: i32,
    ) -> Self {
        RouteEntryV4 {
            prefix,
            next_hops: vec![RouteNextHopV4 {
                next_hop,
                ifindex,
                tunnel_endpoint_id,
            }],
            discard,
            next_table,
            preference,
        }
    }
}

#[cfg(test)]
impl RouteEntryV6 {
    pub(in crate::afxdp) fn single(
        prefix: PrefixV6,
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv6Addr>,
        discard: bool,
        next_table: String,
        preference: i32,
    ) -> Self {
        RouteEntryV6 {
            prefix,
            next_hops: vec![RouteNextHopV6 {
                next_hop,
                ifindex,
                tunnel_endpoint_id,
            }],
            discard,
            next_table,
            preference,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborEntry {
    pub mac: [u8; 6],
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct EgressInterface {
    pub(in crate::afxdp) bind_ifindex: i32,
    pub(in crate::afxdp) vlan_id: u16,
    pub(in crate::afxdp) mtu: usize,
    pub(in crate::afxdp) src_mac: [u8; 6],
    /// #921: u16 zone ID (was `zone: String`). `0` means "unknown".
    ///
    /// #7025: THIS IS A DEBUG-ONLY MIRROR OF
    /// [`ForwardingState::ifindex_unambiguous_zone_id`], NOT a second opinion on
    /// the egress zone. Do not reach for it when you want the egress zone —
    /// call [`ForwardingState::egress_zone_id`], which reads the ledger.
    ///
    /// Before #6722 this field WAS the answer: `egress_zone_id` was
    /// `state.egress.get(&ifx).map(|i| i.zone_id)`. #6722 moved the answer into
    /// the ledger and pointed both `egress_zone_id` and `populate_egress` at it,
    /// so the two are equal by construction — `populate_egress` writes this
    /// field with the identical `ifindex_unambiguous_zone_id.get(..).unwrap_or(0)`
    /// expression `egress_zone_id` evaluates.
    ///
    /// The reader census is the COMPILER's, not a grep's: deleting this field
    /// and building the crate yields, in a DEFAULT build, seven `E0609` field
    /// reads and every one of them is in a test file — zero production readers.
    /// Building `--features debug-log` adds exactly one,
    /// `forwarding_build/mod.rs`'s `FWD_STATE: egress[..]` dump, which is
    /// compiled out of a normal build. That is why the field is retained with
    /// this note rather than dropped: the only thing it does is make one debug
    /// line self-describing, and removing it would rewrite 66 struct literals,
    /// 63 of them in unrelated test fixtures, to delete a value that cannot
    /// currently be wrong.
    ///
    /// "Cannot currently be wrong" is enforced, not asserted:
    /// `egress_zone_id_mirrors_the_unambiguous_ledger_7025` fails if the two
    /// ever diverge, so the drift this note warns a reader about cannot be
    /// introduced silently. That cell pins the INVARIANT over every egress row;
    /// specific expected zone values for specific shapes are pinned separately
    /// by the #6713/#6722 cells, and its own doc records which mutations each
    /// of them catches rather than assuming the new one is the only guard.
    pub(in crate::afxdp) zone_id: u16,
    pub(in crate::afxdp) redundancy_group: i32,
    pub(in crate::afxdp) primary_v4: Option<Ipv4Addr>,
    pub(in crate::afxdp) primary_v6: Option<Ipv6Addr>,
}

#[allow(dead_code)]
#[derive(Clone)]
pub(in crate::afxdp) struct TunnelEndpoint {
    pub(in crate::afxdp) id: u16,
    pub(in crate::afxdp) logical_ifindex: i32,
    /// #1865: the snapshot row's attachment label (linux_name, else
    /// the logical interface name) carried so the telemetry row name
    /// fallback chain matches the plan: ifindex_to_name -> this ->
    /// wg-endpoint-<id>. Same convention as
    /// `wg_tombstone_respawn_coherent`'s row_label.
    pub(in crate::afxdp) interface_label: String,
    /// #1873 R-D: the LOGICAL config interface name (snapshot row's
    /// `interface`, e.g. "wg0.0") — the purge-owner identity. NEVER
    /// linux_name (a cosmetic kernel rename must not purge sessions)
    /// and NEVER interface_label (which prefers linux_name).
    pub(in crate::afxdp) interface: String,
    pub(in crate::afxdp) redundancy_group: i32,
    pub(in crate::afxdp) mode: String,
    pub(in crate::afxdp) outer_family: i32,
    pub(in crate::afxdp) source: IpAddr,
    pub(in crate::afxdp) destination: IpAddr,
    pub(in crate::afxdp) key: u32,
    pub(in crate::afxdp) ttl: u8,
    pub(in crate::afxdp) transport_table: String,
    // WireGuard (#1432 S2a, multi-peer #1434). Populated only when
    // mode == "wireguard".
    pub(in crate::afxdp) wg_listen_port: u16,
    /// Local static X25519 private key, hex-decoded. Zeroized on drop
    /// and redacted in Debug — must never leak via `{:?}` or the
    /// on-disk state snapshot.
    pub(in crate::afxdp) wg_local_privkey: zeroize::Zeroizing<[u8; 32]>,
    /// Ordered per-peer set (#1434). Built from the sorted-by-pubkey
    /// wire slice; the engine peer table is fed from this, and the
    /// encap path LPM-selects the peer by inner-dst (#1434 B1b).
    pub(in crate::afxdp) wg_peers: Vec<WgRuntimePeer>,
}

/// One WireGuard peer as hydrated into the runtime forwarding state
/// (#1434). Decoded/parsed from the wire `TunnelWgPeerSnapshot`.
#[derive(Clone)]
pub(in crate::afxdp) struct WgRuntimePeer {
    pub(in crate::afxdp) pubkey: [u8; 32],
    pub(in crate::afxdp) allowed_ips: Vec<ipnet::IpNet>,
    pub(in crate::afxdp) endpoint: Option<std::net::SocketAddr>,
    /// #7158: the authored `host:port` when the endpoint is a DNS HOSTNAME
    /// rather than a literal, so a peer behind a dynamic WAN (DDNS) is
    /// authorable. `None` for a literal endpoint, which is every peer that
    /// existed before #7158.
    ///
    /// `endpoint` stays `None` for such a peer until the tunnel's resolver
    /// produces an address — the same state a learn-only/roaming peer is in at
    /// spawn, which the per-peer outer-MTU resolution already handles by
    /// falling back to the interface MTU.
    pub(in crate::afxdp) endpoint_host: Option<String>,
    pub(in crate::afxdp) keepalive_secs: u16,
    /// Per-peer preshared key (#1434 B2), hex-decoded. 32 zero bytes =
    /// no PSK. Zeroized on drop; redacted in the Debug impl. Must never
    /// leak via `{:?}` or the on-disk state snapshot.
    pub(in crate::afxdp) preshared_key: zeroize::Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for WgRuntimePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let psk_state = if *self.preshared_key == [0u8; 32] {
            "<unset>"
        } else {
            "<redacted>"
        };
        f.debug_struct("WgRuntimePeer")
            .field("pubkey", &self.pubkey)
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint)
            .field("keepalive_secs", &self.keepalive_secs)
            .field("preshared_key", &psk_state)
            .finish()
    }
}

impl std::fmt::Debug for TunnelEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact wg_local_privkey end-to-end (#1432 S2a invariant).
        f.debug_struct("TunnelEndpoint")
            .field("id", &self.id)
            .field("logical_ifindex", &self.logical_ifindex)
            .field("interface_label", &self.interface_label)
            .field("redundancy_group", &self.redundancy_group)
            .field("mode", &self.mode)
            .field("outer_family", &self.outer_family)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("key", &self.key)
            .field("ttl", &self.ttl)
            .field("transport_table", &self.transport_table)
            .field("wg_listen_port", &self.wg_listen_port)
            .field(
                "wg_local_privkey",
                &if self.mode == "wireguard" {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            // wg_peers uses WgRuntimePeer's own Debug, which redacts
            // each peer's PSK.
            .field("wg_peers", &self.wg_peers)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::afxdp) struct FabricLink {
    pub(in crate::afxdp) parent_ifindex: i32,
    pub(in crate::afxdp) overlay_ifindex: i32,
    pub(in crate::afxdp) peer_addr: IpAddr,
    pub(in crate::afxdp) peer_mac: [u8; 6],
    pub(in crate::afxdp) local_mac: [u8; 6],
    /// #4082: the local fabric parent link's carrier/oper state, threaded from
    /// `FabricSnapshot.up`. `resolve_fabric_redirect_from_list` prefers a fabric
    /// with `up == true` so a dual-fabric cluster fails the cross-chassis
    /// redirect over to the secondary when the primary parent carrier drops.
    pub(in crate::afxdp) up: bool,
}

/// #3773 (M13): why a configured fabric link was skipped during a forwarding
/// build/refresh pass. `is_malformed()` partitions the reasons into the two
/// cumulative counters: a MALFORMED value (an unusable parent ifindex, an
/// unparseable peer address, or a NON-EMPTY MAC string that fails to parse) vs
/// an UNRESOLVED peer/local MAC (an EMPTY MAC field still awaiting neighbor /
/// interface resolution — the expected transient the late-resolution
/// `SyncFabricState` path fills in). A persistently non-zero UNRESOLVED count
/// is a distinct, benign-until-persistent state; a non-zero MALFORMED count is
/// a config/environment fault an operator must fix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum FabricSkipReason {
    /// `parent_ifindex <= 0` — the fabric parent netdev index is unusable.
    InvalidParentIfindex,
    /// `peer_address` does not parse as an IP address.
    UnparseablePeerAddress,
    /// A NON-EMPTY `local_mac` string failed to parse (and no parent-ifindex
    /// MAC fallback was available).
    MalformedLocalMac,
    /// An EMPTY `local_mac` with no resolvable parent-ifindex MAC — awaiting
    /// interface MAC resolution.
    UnresolvedLocalMac,
    /// A NON-EMPTY `peer_mac` string failed to parse (and no neighbor entry
    /// resolved it).
    MalformedPeerMac,
    /// An EMPTY `peer_mac` with no resolved neighbor — awaiting ARP/NDP
    /// resolution (the common startup transient).
    UnresolvedPeerMac,
}

impl FabricSkipReason {
    /// True for a malformed value (a config/environment fault that will not
    /// self-heal), false for an unresolved-but-well-formed peer/local MAC (the
    /// expected late-resolution transient).
    pub(in crate::afxdp) fn is_malformed(self) -> bool {
        matches!(
            self,
            FabricSkipReason::InvalidParentIfindex
                | FabricSkipReason::UnparseablePeerAddress
                | FabricSkipReason::MalformedLocalMac
                | FabricSkipReason::MalformedPeerMac
        )
    }

    pub(in crate::afxdp) fn as_str(self) -> &'static str {
        match self {
            FabricSkipReason::InvalidParentIfindex => "invalid-parent-ifindex",
            FabricSkipReason::UnparseablePeerAddress => "unparseable-peer-address",
            FabricSkipReason::MalformedLocalMac => "malformed-local-mac",
            FabricSkipReason::UnresolvedLocalMac => "unresolved-local-mac",
            FabricSkipReason::MalformedPeerMac => "malformed-peer-mac",
            FabricSkipReason::UnresolvedPeerMac => "unresolved-peer-mac",
        }
    }
}

/// #3773 (M13): a skipped fabric link, named for operator diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct FabricLinkSkip {
    /// The configured fabric name (`FabricSnapshot.name`, e.g. `fab0`).
    pub(in crate::afxdp) name: String,
    /// The parent netdev ifindex the skip pertained to (`<= 0` for an
    /// `InvalidParentIfindex` skip). Used by the preserved-fabric merge to
    /// prune a skip whose parent was re-added from the prior resolved set.
    pub(in crate::afxdp) parent_ifindex: i32,
    pub(in crate::afxdp) reason: FabricSkipReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForwardingDisposition {
    LocalDelivery,
    ForwardCandidate,
    FabricRedirect,
    HAInactive,
    PolicyDenied,
    NoRoute,
    MissingNeighbor,
    DiscardRoute,
    NextTableUnsupported,
}

impl ForwardingDisposition {
    /// Whether this disposition produces a stable forwarding decision that can
    /// be stored in the per-worker flow cache.
    ///
    /// Cacheable:
    ///   - `ForwardCandidate`: Normal forwarded traffic with a resolved
    ///     neighbor and egress interface. The common fast path.
    ///   - `FabricRedirect`: Targets a fabric overlay binding. Cacheable
    ///     because each cache entry captures the owning RG epoch into
    ///     `FlowCacheStamp::owner_rg_epoch` at insert time
    ///     (`flow_cache.rs:60-83`), and `FlowCache::lookup`
    ///     (`flow_cache.rs:314-347`) treats the entry as a miss when
    ///     `current_epoch != entry.stamp.owner_rg_epoch`. The owning RG
    ///     bumps its epoch on every active/standby flip, so the window
    ///     in which a cached `FabricRedirect` could point at a stale
    ///     fabric peer is bounded by the next RG epoch bump (#1065).
    ///
    /// Not cacheable:
    ///   - `LocalDelivery`: Delivered to the kernel stack, not forwarded
    ///     through XSK bindings. No rewrite descriptor to cache.
    ///   - `HAInactive`: The owning RG is not active on this node. Transient
    ///     state that changes on failover — must never be cached.
    ///   - `PolicyDenied`: Packet was denied by policy. Drop decisions are
    ///     not cached to allow policy changes to take effect immediately.
    ///   - `NoRoute`: No route to destination. Transient — may resolve when
    ///     FIB is updated.
    ///   - `MissingNeighbor`: Route exists but ARP/NDP is unresolved.
    ///     Transient — resolves when the neighbor entry appears.
    ///   - `DiscardRoute`: Matched a discard/reject route. Not cacheable for
    ///     the same reason as PolicyDenied.
    ///   - `NextTableUnsupported`: Inter-VRF route leaking hit an
    ///     unsupported next-table. Permanent miss, not worth caching.
    pub(in crate::afxdp) fn is_cacheable(self) -> bool {
        matches!(
            self,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
        )
    }

    /// Whether a frame with this disposition is eligible for the generic
    /// kernel slow-path reinjection (the filtered wrapper
    /// `maybe_reinject_slow_path` and the trailing chokepoint at
    /// `poll_descriptor::poll_binding_process_descriptor`).
    ///
    /// This is the single source of truth for the slow-path allow-list
    /// (#1913). A disposition that is NOT eligible must be dropped, NOT
    /// handed to the kernel FIB.
    ///
    /// Eligible (reinject to the kernel slow path):
    ///   - `LocalDelivery`: terminate at the kernel stack (or a local
    ///     tunnel-delivery channel) — this is the intended destination.
    ///   - `NoRoute`: userspace has no route, but the kernel FIB may
    ///     (e.g. a route the helper has not yet learned); let the kernel
    ///     try, rate-limited. #7480: eligibility here is necessary but no
    ///     longer sufficient — the NoRoute arm in `poll_descriptor`
    ///     adjudicates the computable zone pair first and downgrades a
    ///     denied frame to `PolicyDenied`, so only a POLICY-PERMITTED
    ///     NoRoute frame reaches the kernel. The disposition stays eligible
    ///     because #7409's importer bounds the FIB divergence without
    ///     closing it; dropping it outright would black-hole every learned
    ///     destination between snapshot pushes.
    ///   - `MissingNeighbor`: route exists, ARP/NDP unresolved; the kernel
    ///     can resolve and forward (the userspace prober runs in parallel).
    ///

    /// NOT eligible (drop — do NOT reinject):
    ///   - `PolicyDenied`: a zone-policy DENY. Reinjecting would silently
    ///     bypass the firewall by forwarding the packet via the kernel FIB
    ///     (the bug #1913 fixes).
    ///   - `HAInactive`: the owning RG is not active on this node;
    ///     reinjecting hands the packet to the standby's kernel FIB
    ///     (duplicate/asymmetric forwarding, wrong-node plaintext send).
    ///   - `DiscardRoute`: matched a discard/reject route whose entire
    ///     purpose is to drop the traffic.
    ///   - `NextTableUnsupported`: an inter-VRF next-table chain the helper
    ///     cannot resolve — deeper than `MAX_NEXT_TABLE_DEPTH`, or a cycle
    ///     (`fib.rs`). Reinjecting handed it to the kernel FIB, which forwards
    ///     with no zone policy, session, NAT or screen (#6664).
    ///
    ///     Unlike `NoRoute` this is NOT transient, so the #7409 "do not
    ///     black-hole a destination the kernel can still reach" argument does
    ///     not apply: no FIB refresh resolves an over-deep or cyclic chain, so
    ///     delegating it was a STANDING policy bypass for that config rather
    ///     than a window. Failing closed matches the posture this codebase
    ///     already takes when the dataplane cannot represent a config.
    ///
    ///     This is defense-in-depth, not a live exposure fix, and the
    ///     distinction is worth stating honestly: no config that reaches the
    ///     dataplane can currently produce this disposition. Every
    ///     `next_table`-bearing route in the FIB lives in the GLOBAL table --
    ///     the only two producers are the global static-route pass and the
    ///     synthetic ip-rule leak pass, and a next-table authored UNDER a
    ///     routing-instance is hard-rejected at commit (#5830) and dropped
    ///     from the snapshot even on the tolerant load / peer-sync path
    ///     (`pkg/dataplane/userspace/routes.go`). So the recursion is at most
    ///     one hop, global -> instance, and it terminates there: neither the
    ///     depth cap nor a cycle is reachable. That safety is an EMERGENT
    ///     property of two guards in a different language and package, not an
    ///     invariant this predicate enforces -- a third `next_table` producer,
    ///     or one relaxed guard, would silently reopen the bypass. Fail closed
    ///     here so the dataplane's own posture is correct on its own terms.
    ///   - `ForwardCandidate` / `FabricRedirect`: handled by the forward /
    ///     fabric path, never the generic slow path. Some callers bypass
    ///     this predicate on purpose; the authoritative enumeration lives
    ///     on `maybe_reinject_slow_path_from_frame` and is pinned by
    ///     `raw_reinject_primitive_caller_set_is_pinned_7480`. Deliberately
    ///     NOT restated here — this comment carried a stale count of its
    ///     own until #7480, which is what a restatement does. (#1946: `FabricRedirect`
    ///     with no fabric XSK binding, or whose build/enqueue failed, is
    ///     dropped fail-closed + counted, never reinjected — a
    ///     cross-chassis L2 redirect is not kernel-FIB routable.)
    pub(in crate::afxdp) fn is_slow_path_eligible(self) -> bool {
        matches!(
            self,
            ForwardingDisposition::LocalDelivery
                | ForwardingDisposition::NoRoute
                | ForwardingDisposition::MissingNeighbor
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ForwardingResolution {
    pub(crate) disposition: ForwardingDisposition,
    pub(crate) local_ifindex: i32,
    pub(crate) egress_ifindex: i32,
    pub(crate) tx_ifindex: i32,
    pub(crate) tunnel_endpoint_id: u16,
    pub(crate) next_hop: Option<IpAddr>,
    pub(crate) neighbor_mac: Option<[u8; 6]>,
    pub(crate) src_mac: Option<[u8; 6]>,
    pub(crate) tx_vlan_id: u16,
}

impl ForwardingResolution {
    pub(in crate::afxdp) fn status(
        self,
        debug: Option<&ResolutionDebug>,
        forwarding: &ForwardingState,
    ) -> PacketResolution {
        PacketResolution {
            disposition: match self.disposition {
                ForwardingDisposition::LocalDelivery => "local_delivery",
                ForwardingDisposition::ForwardCandidate => "forward_candidate",
                ForwardingDisposition::FabricRedirect => "fabric_redirect",
                ForwardingDisposition::HAInactive => "ha_inactive",
                ForwardingDisposition::PolicyDenied => "policy_denied",
                ForwardingDisposition::NoRoute => "no_route",
                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
                ForwardingDisposition::DiscardRoute => "discard_route",
                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
            }
            .to_string(),
            local_ifindex: self.local_ifindex,
            egress_ifindex: self.egress_ifindex,
            ingress_ifindex: debug.map(|d| d.ingress_ifindex).unwrap_or_default(),
            next_hop: self.next_hop.map(|ip| ip.to_string()).unwrap_or_default(),
            neighbor_mac: self.neighbor_mac.map(format_mac).unwrap_or_default(),
            src_ip: debug
                .and_then(|d| d.src_ip)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            dst_ip: debug
                .and_then(|d| d.dst_ip)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            src_port: debug.map(|d| d.src_port).unwrap_or_default(),
            dst_port: debug.map(|d| d.dst_port).unwrap_or_default(),
            from_zone: debug
                .and_then(|d| d.from_zone)
                .and_then(|id| forwarding.zone_id_to_name.get(&id).cloned())
                .unwrap_or_default(),
            to_zone: debug
                .and_then(|d| d.to_zone)
                .and_then(|id| forwarding.zone_id_to_name.get(&id).cloned())
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct BindingIdentity {
    pub(in crate::afxdp) slot: u32,
    pub(in crate::afxdp) queue_id: u32,
    pub(in crate::afxdp) worker_id: u32,
    pub(in crate::afxdp) interface: Arc<str>,
    pub(in crate::afxdp) ifindex: i32,
}

#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct WorkerBindingLookup {
    pub(in crate::afxdp) by_if_queue: FastMap<(i32, u32), usize>,
    pub(in crate::afxdp) first_by_if: FastMap<i32, usize>,
    pub(in crate::afxdp) all_by_if: FastMap<i32, Vec<usize>>,
    pub(in crate::afxdp) by_slot: FastMap<u32, usize>,
}

impl WorkerBindingLookup {
    pub(in crate::afxdp) fn from_bindings(bindings: &[BindingWorker]) -> Self {
        let mut lookup = Self::default();
        for (index, binding) in bindings.iter().enumerate() {
            lookup
                .by_if_queue
                .insert((binding.ifindex, binding.queue_id), index);
            lookup.first_by_if.entry(binding.ifindex).or_insert(index);
            lookup
                .all_by_if
                .entry(binding.ifindex)
                .or_default()
                .push(index);
            lookup.by_slot.insert(binding.slot, index);
        }
        lookup
    }

    pub(in crate::afxdp) fn target_index(
        &self,
        current_index: usize,
        current_ifindex: i32,
        ingress_queue_id: u32,
        egress_ifindex: i32,
    ) -> Option<usize> {
        if current_ifindex == egress_ifindex {
            return Some(current_index);
        }
        self.by_if_queue
            .get(&(egress_ifindex, ingress_queue_id))
            .copied()
            .or_else(|| self.first_by_if.get(&egress_ifindex).copied())
    }

    pub(in crate::afxdp) fn slot_index(&self, slot: u32) -> Option<usize> {
        self.by_slot.get(&slot).copied()
    }

    pub(in crate::afxdp) fn fabric_target_index(
        &self,
        egress_ifindex: i32,
        flow_hash: u64,
    ) -> Option<usize> {
        let indices = self.all_by_if.get(&egress_ifindex)?;
        if indices.is_empty() {
            return None;
        }
        Some(indices[(flow_hash as usize) % indices.len()])
    }
}
