// Forwarding-state aggregator split from forwarding.rs (#16209):
// ForwardingState (the 128-field definition, intact — this split
// does NOT discharge the accepted-debt obligation to split that
// definition itself), its inherent impl, the paired-insert tests,
// and the small state-adjacent identities (SynCookieMasterKey,
// InstallTables, FabricNatScopeIdentity). Sibling type definitions
// live in forwarding/{fib,local,tunnels,zones,fabric,disposition,
// binding}.rs and are re-exported by forwarding/mod.rs's
// `pub(in crate::afxdp) use forwarding::*` glob, so every access
// site resolves unchanged. Zero layout change.
//
// Visibility bill: no widening. ForwardingState and its neighbours
// keep `pub(in crate::afxdp)`; cross-file references to sibling
// types resolve through the parent glob (`use super::super::*`
// reaches types::*, whose forwarding glob re-exports every sibling).

use super::super::*;
use crate::protocol::{PolicyRenameAncestry, PolicySessionRebind};

/// SYN-cookie master key (16 bytes) wrapped so its `Debug` never renders
/// the secret bytes (#4484 L-7). `ForwardingState` derives `Debug`; the
/// auto-derived `Debug` on a bare `Option<[u8; 16]>` would print the raw
/// key into any log/trace that formats the forwarding state. This wrapper
/// redacts in `Debug` — `Some(<redacted>)` / `None`, never the bytes —
/// while staying a transparent `Option<[u8; 16]>` at every read/write site
/// (access `.0`). Mirrors the manual-redaction discipline the WireGuard
/// key fields use (`TunnelEndpoint`/`WgRuntimePeer` in tunnels.rs).
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

/// #9752: one installing-table registry row: the instance's canonical
/// per-family route tables, preformed at build so re-resolve borrows them
/// with zero per-packet allocation.
///
/// `None` per family means that family has no dataplane presence (no routes,
/// connected, or local attribution) — re-resolve treats it as absent-family
/// (local-or-terminal, never a wrong-table lookup and never a stale cached
/// serve). `h2` is the owner check for the row's instance name, verified on
/// every use (see [`install_table_identity`](crate::session::install_table_identity)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct InstallTables {
    pub(in crate::afxdp) v4: Option<String>,
    pub(in crate::afxdp) v6: Option<String>,
    pub(in crate::afxdp) h2: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct FabricNatScopeIdentity {
    pub(in crate::afxdp) zone_id: u32,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) redundancy_group: i32,
}

#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ForwardingState {
    pub(in crate::afxdp) local_v4: FastSet<Ipv4Addr>,
    pub(in crate::afxdp) local_v6: FastSet<Ipv6Addr>,
    /// #11574: the unique configured security zone owning each local interface
    /// address. Zero is the fail-closed sentinel for absent or cross-zone
    /// ambiguous owners; WG underlay admission compares this with arrival zone.
    pub(in crate::afxdp) wg_local_address_zone_v4: FastMap<Ipv4Addr, u32>,
    pub(in crate::afxdp) wg_local_address_zone_v6: FastMap<Ipv6Addr, u32>,
    /// #3769: table (VRF) attribution for the local-delivery DECISION.
    /// `local_v4`/`local_v6` are GLOBAL membership sets ("some subsystem
    /// answers for this IP somewhere"); before #3769 the local-delivery
    /// shortcut in `lookup_forwarding_resolution_inner_ecmp` keyed the
    /// DECISION on that global membership, so a packet in VRF A destined to a
    /// local address owned only in VRF B short-circuited to `LocalDelivery`,
    /// skipping the VRF-A FIB + zone/security-policy + HA-RG owner
    /// classification. #3151 table-scoped only the ifindex ATTRIBUTION, and
    /// only via the connected-route scan — which cannot recover a NAT/DNAT
    /// external IP's owning routing-instance (no connected route). (A non-/32
    /// interface host IP was likewise unrecoverable until #10645:
    /// `ConnectedRouteV*` stored only the MASKED network address, so
    /// `prefix.addr() == host` matched only a /32.) These maps
    /// record, for EVERY `local_v*` member (interface host address AND
    /// static-NAT/DNAT external IP), the set of canonical route tables that
    /// own it, so the shortcut is gated on the resolving table. Production
    /// writers MUST add members only through
    /// [`Self::insert_local_iface_addr`] (interface addresses, keyed by the
    /// host `.addr()`, not the connected prefix) or
    /// [`Self::insert_nat_external`] (NAT/DNAT externals in the
    /// `forwarding_build` late-stage NAT append), which perform the paired
    /// `local_tables_v*` / `local_nat_any_table_v*` attribution atomically
    /// with the `local_v*` insert; a direct field insert would silently
    /// drop the VRF gate. The connected scan is still
    /// used for the ifindex ATTRIBUTION — matching the row's unmasked host
    /// address since #10645 (any width, not just the #3151 /32-HA case);
    /// the membership DECISION now uses these maps.
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
    /// #16131: interned twin of the string set below, kept ONLY as a
    /// dual-carry agreement source while the string form remains
    /// authoritative. Derived once per build by
    /// `forwarding_build::intern_route_tables` from the authoritative
    /// string sets and the published `route_table_identities`; never
    /// written by any other code, never read on the packet path. The
    /// agreement cell in `forwarding_build/intern.rs` proves both
    /// carries agree on every built state — a disagreement fails the
    /// build closed rather than letting an unproven interned form
    /// near a lookup.
    pub(in crate::afxdp) local_table_ids_v4: FastMap<Ipv4Addr, FastSet<RouteIdentity>>,
    pub(in crate::afxdp) local_table_ids_v6: FastMap<Ipv6Addr, FastSet<RouteIdentity>>,
    pub(in crate::afxdp) local_tables_v4: FastMap<Ipv4Addr, FastSet<String>>,
    pub(in crate::afxdp) local_tables_v6: FastMap<Ipv6Addr, FastSet<String>>,
    pub(in crate::afxdp) local_nat_any_table_v4: FastSet<Ipv4Addr>,
    pub(in crate::afxdp) local_nat_any_table_v6: FastSet<Ipv6Addr>,
    /// #11439: per-NAT-external ownership metadata, keyed only for addresses
    /// appended to `local_v*` by the late NAT-target build. `true` means every
    /// configured translation for the external address targets one of our
    /// configured interface addresses; `false` means at least one target is a
    /// transit host. Proxy-ARP ownership alone must not claim a local XFRM
    /// destination.
    pub(in crate::afxdp) local_nat_to_self_v4: FastMap<Ipv4Addr, bool>,
    pub(in crate::afxdp) local_nat_to_self_v6: FastMap<Ipv6Addr, bool>,
    /// #3182: EVERY configured interface address, decoupled from the
    /// NAT-aware `local_v*` exclusion. `local_v4`/`local_v6` drop egress
    /// addresses selected by interface-mode SNAT's to-side matrix
    /// (`to-zone`, `to-interface`, `to-routing-instance`, or unscoped;
    /// `nat_translated_local_exclusions`), so they are NOT a complete
    /// "addresses this router owns" set — the SNAT/WAN interface IP is
    /// missing. The anti-poison `owns_configured_ip` predicate is driven
    /// from this full set instead so an unsolicited ARP/NDP (or RX-learn)
    /// claiming the router's own WAN/SNAT interface IP is still rejected.
    /// Built alongside `local_v*` in `populate_interfaces`, BEFORE the NAT
    /// exclusion branch, from the same per-interface address list.
    pub(in crate::afxdp) configured_iface_v4: FastSet<Ipv4Addr>,
    pub(in crate::afxdp) configured_iface_v6: FastSet<Ipv6Addr>,
    /// #14662: per-table interface-NAT ifindex: host address -> (canonical
    /// connected table -> ifindex), mirroring the #3769 `(table, addr)`
    /// local-delivery attribution. The flat `addr -> ifindex` form was
    /// last-write-wins when two VRFs configured the same address on
    /// different interfaces. The nested form also keeps the per-packet
    /// lookup allocation-free (borrowed `&str` table key).
    /// #16131: dual-carry interned twin of the nested string-keyed map
    /// below; the inner map is keyed by the interned `RouteIdentity`
    /// instead of the canonical table string. Derived at build by
    /// `forwarding_build::intern_route_tables`; the string form stays
    /// authoritative (see `local_table_ids_v4`).
    pub(in crate::afxdp) interface_nat_ids_v4: FastMap<Ipv4Addr, FastMap<RouteIdentity, i32>>,
    pub(in crate::afxdp) interface_nat_ids_v6: FastMap<Ipv6Addr, FastMap<RouteIdentity, i32>>,
    pub(in crate::afxdp) interface_nat_v4: FastMap<Ipv4Addr, FastMap<String, i32>>,
    pub(in crate::afxdp) interface_nat_v6: FastMap<Ipv6Addr, FastMap<String, i32>>,
    /// #16131: dual-carry interned twins of the string sets below;
    /// derived at build by `forwarding_build::intern_route_tables`.
    /// The string form stays authoritative.
    pub(in crate::afxdp) interface_nat_table_ids_v4: FastMap<Ipv4Addr, FastSet<RouteIdentity>>,
    pub(in crate::afxdp) interface_nat_table_ids_v6: FastMap<Ipv6Addr, FastSet<RouteIdentity>>,
    /// #12086: owning routing tables for interface-NAT local-delivery
    /// addresses. Like `local_tables_v*`, these interface addresses are not
    /// wildcarded across routing instances.
    pub(in crate::afxdp) interface_nat_tables_v4: FastMap<Ipv4Addr, FastSet<String>>,
    pub(in crate::afxdp) interface_nat_tables_v6: FastMap<Ipv6Addr, FastSet<String>>,
    /// #13644: ingress-keyed connected prefixes used by post-admission
    /// neighbor learning. Kept separate from the route vector so cache hits
    /// inspect only the ingress interface's prefixes, not every interface.
    pub(in crate::afxdp) connected_v4_by_ifindex: FastMap<i32, Vec<PrefixV4>>,
    pub(in crate::afxdp) connected_v6_by_ifindex: FastMap<i32, Vec<PrefixV6>>,
    pub(in crate::afxdp) connected_v4: Vec<ConnectedRouteV4>,
    pub(in crate::afxdp) connected_v6: Vec<ConnectedRouteV6>,
    /// #16217/#17053: build-time cache of the canonical
    /// `connected_lpm_ifindex(.., RowsThenLedger)` owner answer,
    /// keyed by (prefix_len, network) with per-table-key slots.
    /// `connected_owner_rg_for_target_in_table` probes it from the
    /// longest length down instead of linearly scanning every
    /// connected row per flow-cache hit. Built by
    /// `rebuild_connected_owner_index` at forwarding-state build;
    /// empty when the state was assembled without that call (unit
    /// fixtures), in which case callers use the canonical LPM scan
    /// — same answer, old cost. Slot shape:
    /// `(table_key, winning_ifindex, winning_rg)`; the rebuild keeps
    /// the LOWEST ifindex at equal (table, len, network) for both
    /// FIB and ledger entries (#17053). Ledger slots store the
    /// ifindex negated as `-ifindex - 1` (always negative, so the
    /// probe's `>= 0` / `< 0` split never confuses them with FIB
    /// slots). INVARIANT (#17053 fold, Rev18099 F2): ledger keys are
    /// kernel ifindexes and are therefore > 0 in every production
    /// state (populated from `iface.ifindex` in
    /// `forwarding_build`); the negation is computed with
    /// `checked_neg` and skips (never wraps) the one value it cannot
    /// encode, `i32::MIN`, whose wrap would alias a FIB slot.
    pub(in crate::afxdp) connected_owner_index_v4:
        FastMap<(u8, u32), Vec<(Box<str>, i32, i32)>>,
    pub(in crate::afxdp) connected_owner_index_v6:
        FastMap<(u8, u128), Vec<(Box<str>, i32, i32)>>,
    /// #16217 (GLM F1): row counts the index was built from
    /// (FIB rows + ledger prefixes, both families). A post-build
    /// mutation of the connected vecs/ledger (unit fixtures) makes
    /// the counts disagree and the owner probe falls back to the
    /// exact legacy scan instead of trusting a stale Miss.
    pub(in crate::afxdp) connected_owner_index_rows: (usize, usize),
    /// #10689: build-time index of IPv4 connected-prefix directed broadcasts,
    /// keyed by routing domain so overlapping prefixes do not poison other
    /// routing instances.
    pub(in crate::afxdp) connected_v4_directed_broadcasts: FastSet<(u32, Ipv4Addr)>,
    /// #11033: egress-scoped index for rejecting neighbor resolution of a
    /// connected subnet-directed broadcast on its own interface. Unlike the
    /// domain-keyed source martian index above, this key includes ifindex.
    pub(in crate::afxdp) connected_v4_directed_broadcast_neighbor_keys: FastSet<(i32, Ipv4Addr)>,
    pub(in crate::afxdp) routes_v4: FastMap<String, Vec<RouteEntryV4>>,
    pub(in crate::afxdp) routes_v6: FastMap<String, Vec<RouteEntryV6>>,
    /// Canonical tables explicitly typed by Go as forwarding instances. In
    /// these tables, qualified gateways and interface-only members may bind
    /// to explicit default-instance interfaces in routing domain zero;
    /// quarantined and ordinary foreign-VRF cross-table scopes remain refused
    /// (#11074, #11420, #11684, #12036).
    pub(in crate::afxdp) forwarding_tables: FastSet<String>,
    /// #9955: synthetic next-table entries are kernel ip rules, not peers
    /// in the destination table's FIB. Keep a priority-ordered per-source-
    /// table collection so lookup can perform the kernel's rule stage before
    pub(in crate::afxdp) leak_rules_v4: FastMap<String, Vec<LeakRuleV4>>,
    pub(in crate::afxdp) leak_rules_v6: FastMap<String, Vec<LeakRuleV6>>,
    /// #9951: O(1)-candidate liveness indexes for stamped session hits.
    /// Values retain the prefix needed for the final destination check; the
    /// incarnation key avoids scanning every source-table rule on each packet.
    pub(in crate::afxdp) leak_incarnations_v4: FastMap<u64, Vec<PrefixV4>>,
    pub(in crate::afxdp) leak_incarnations_v6: FastMap<u64, Vec<PrefixV6>>,
    /// #9752: installing-table registry: stable domain id → the instance's
    /// canonical per-family route tables + owner check. Re-resolve looks the
    /// session's `install_table_domain` up here to recover the table string;
    /// a nonzero domain with no row (retired/unknown instance) or a check
    /// mismatch (successive-config aliasing) fails closed instead of
    /// resolving in the default table. Domain 0 (default) is by rule, never
    /// a row. Built once per config in `forwarding_build` (scan of route
    /// keys + connected tables + local attributions); read on re-resolve
    /// paths only, never per packet.
    pub(in crate::afxdp) install_tables: FastMap<u32, InstallTables>,
    /// Explicit canonical-table identity authority captured with this immutable
    /// FIB generation. Missing keys are never interpreted as the default table.
    pub(in crate::afxdp) route_table_identities: FastMap<String, RouteIdentity>,
    /// #16131: false when any table name interned into the dual-carry
    /// `*_ids_*` twins lacked a published `route_table_identities` row
    /// (identity is never synthesized in that case — the name is simply
    /// absent from the interned carry). Diagnostic only: the string
    /// carry stays authoritative and the packet path never reads this.
    pub(in crate::afxdp) route_table_interning_complete: bool,
    /// False when any selectable FIB table lacks an authoritative identity.
    pub(in crate::afxdp) route_table_identity_map_complete: bool,
    pub(in crate::afxdp) tunnel_endpoints: FastMap<u16, TunnelEndpoint>,
    pub(in crate::afxdp) tunnel_endpoint_by_ifindex: FastMap<i32, u16>,
    /// Outer L3 egress RG for fixed-destination GRE/ip6gre endpoints, derived
    /// once from this forwarding snapshot. Enforcement uses this instead of
    /// repeating an outer FIB lookup on each tunnel packet. Missing entries
    /// mean the endpoint has no usable outer egress mapping.
    pub(in crate::afxdp) tunnel_outer_egress_rgs: FastMap<u16, i32>,
    /// Per-peer WireGuard outer RGs keyed by the next-hop in each peer's
    /// transport table. Configured peers are indexed at snapshot build time;
    /// absent entries may represent a runtime-learned endpoint.
    pub(in crate::afxdp) wireguard_peer_outer_egress_rgs: FastMap<(u16, IpAddr), i32>,
    /// #11423: endpoint ids whose tunnel devices are explicitly down in the
    /// snapshot. Missing liveness remains compatible with older snapshots.
    pub(in crate::afxdp) tunnel_endpoints_down: FastSet<u16>,
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
    /// #9587: the bounded SET of WireGuard listen ports the shim steers (at
    /// most `WG_STEERED_PORT_SET_MAX`). Read at control-thread spawn, never
    /// per packet — see `WgKernelTransport` (types/runtime.rs). Fixed array
    /// (spawn-path only, no allocator pressure); only [0..count] are valid.
    pub(in crate::afxdp) wg_steered_listen_ports: [u16; WG_STEERED_PORT_SET_MAX],
    pub(in crate::afxdp) wg_steered_listen_port_count: u8,
    pub(in crate::afxdp) neighbors: FastMap<(i32, IpAddr), NeighborEntry>,
    pub(in crate::afxdp) ifindex_to_name: FastMap<i32, String>,
    pub(in crate::afxdp) ifindex_to_config_name: FastMap<i32, String>,
    /// #3096: ifindex → routing-instance (VRF) name. Built at config-commit
    /// from each interface snapshot's `routing_instance` ("" = the default
    /// instance). Used by the NAT match path to enforce a
    /// `from`/`to routing-instance` scope against the flow's ingress/egress
    /// interface VRF. An ifindex absent here resolves to "" (default).
    pub(in crate::afxdp) ifindex_to_routing_instance: FastMap<i32, String>,
    /// Stable fabric-stamp id for each logical ingress interface whose
    /// zone/interface/routing-instance identity is unambiguous.
    pub(in crate::afxdp) ifindex_to_fabric_nat_scope_id: FastMap<i32, u32>,
    /// Receiver-side resolution for the 24-bit fabric NAT-scope stamp.
    /// The value is this node's local logical ifindex for the same configured
    /// zone/interface/routing-instance identity.
    pub(in crate::afxdp) fabric_nat_scope_id_to_identity: FastMap<u32, FabricNatScopeIdentity>,
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
    /// discipline as #6722's `ifindex_unambiguous_zone_id`. `ingress_routing_domain`
    /// maps this missing fabric identity to a per-zone nonzero sentinel outside
    /// the install-table ID band, so it cannot alias the default-domain session
    /// key; native route resolution then fails closed (#11061).
    pub(in crate::afxdp) zone_routing_domain: FastMap<u32, u32>,
    /// Zone IDs whose member interfaces disagree on routing domain. Retained
    /// separately from `zone_routing_domain` so status and transition logs can
    /// report the quarantine without guessing whether an absent mapping is
    /// ambiguous or simply has no routed member.
    pub(in crate::afxdp) ambiguous_fabric_zone_ids: FastSet<u32>,
    /// #7160: true iff ANY interface resolves to a non-zero routing domain,
    /// i.e. iff at least one interface is a member of a named routing
    /// instance. Single-bool gate so a deployment with no routing-instance
    /// interface membership — every deployment before this change, and the
    /// overwhelming majority after it — never probes the map at all and its
    /// session identity stays bit-identical to pre-#7160.
    pub(in crate::afxdp) has_routing_domains: bool,
    /// #16026: true iff the snapshot carries more than one configured
    /// security zone. The XDP steering key is a bare 5-tuple with no
    /// zone, so a `PASS_TO_KERNEL` row published for one zone's
    /// peer-synced LocalDelivery session can be honoured for a packet
    /// presenting the same tuple in another zone — the shared/ambiguous
    /// netdev residual the nft ingress-scope re-judgement cannot kill.
    /// Demoting such rows to REDIRECT on multi-zone nodes routes them
    /// through `session_hit_authority` (#9519), which judges by live
    /// arrival zone. Single-bool gate in the #7160 shape: a single-zone
    /// deployment — the overwhelming majority — never changes its
    /// publish behaviour at all.
    pub(in crate::afxdp) has_multiple_zones: bool,
    /// #921: ifindex → zone ID (was `FastMap<i32, String>`). Built
    /// at config-commit time from the snapshot's per-interface
    /// zone NAME via the `zone_name_to_id` lookup. Hot-path callers
    /// read u16 directly; slow-path display sites translate via
    /// `zone_id_to_name`. Unknown / dropped zones map to `0`.
    pub(in crate::afxdp) ifindex_to_zone_id: FastMap<i32, u32>,
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
    pub(in crate::afxdp) ifindex_unambiguous_zone_id: FastMap<i32, u32>,
    pub(in crate::afxdp) zone_name_to_id: FastMap<String, u32>,
    pub(in crate::afxdp) zone_id_to_name: FastMap<u32, String>,
    /// The zone maps passed the snapshot-level duplicate/collision validator.
    /// Hand-built test states leave this false, so removed-zone purging is
    /// fail-closed unless the maps came from the real forwarding builder.
    pub(in crate::afxdp) zone_set_validated: bool,
    /// #6458/#13181/#15916: zone ID → deduplicated redundancy-group IDs
    /// (> 0) from admitted snapshot member rows. Ingress parent aliases
    /// are excluded, and each shared-ifindex row contributes its own RG.
    /// A zone without RG-bound members is absent. Read on the
    /// fabric-ingress zone-stamp validation path
    /// (`forwarding::fabric::zone_encoded_fabric_stamp_disposition`): a
    /// stamped zone claim is a proved peer punt only when at least one
    /// bound RG is not forwarding-active locally; all-locally-active is
    /// the #15916 ambiguous shape (owner-RG promotion decides).
    pub(in crate::afxdp) zone_to_rgs: FastMap<u32, Vec<i32>>,
    /// #3070: per-zone host-inbound-traffic admission set, keyed by the same
    /// validated zone id as `zone_id_to_name`. A zone is present here only when
    /// the config declared a `host-inbound-traffic` stanza for it; an absent
    /// entry means "not configured" → the dataplane preserves admit-all for
    /// host-bound (local-delivery) traffic ingressing that zone. Read on the
    /// local-delivery admit path (session miss AND session hit) to default-deny
    /// host-bound traffic whose service/protocol is not listed.
    pub(in crate::afxdp) zone_host_inbound: FastMap<u32, ZoneHostInbound>,
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
    /// enabled. A non-SYN TCP transit packet dropped for a session miss whose
    /// ingress (from) zone is present here may receive a TCP RST toward the
    /// source. Policy denies stay silent. Absent zone ⇒ tcp-rst off.
    pub(in crate::afxdp) zone_tcp_rst: FastMap<u32, bool>,
    /// #3618: per-(from-)zone rate-limit buckets for locally-generated reject
    /// replies (policy `then reject`, firewall-filter / lo0 `then reject`, and
    /// zone `tcp-rst` session-miss resets). One GCRA `TokenBucket` per CONFIGURED zone id,
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
    /// to the process-global `REJECT_FALLBACK_LIMITER` at the gate (never
    /// fail-open). Held as `Arc<ZoneLimiter>` so the shared atomics survive
    /// `ForwardingState::clone()` — the coordinator re-stores a clone of the
    /// forwarding state at runtime cadence (fabric refresh), and a plain-value
    /// clone would snapshot stale coordinator-side atomics and effectively reset
    /// the limiter every refresh. A genuine config rebuild re-runs
    /// `populate_zones` and installs fresh limiters (reset-on-commit, accepted
    /// for a diagnostic limiter). See `docs/generated-reply-rate-limit.md`.
    pub(in crate::afxdp) reject_buckets:
        FastMap<u32, std::sync::Arc<crate::afxdp::icmp_ratelimit::ZoneLimiter>>,
    /// #5856: per-(from-)zone rate-limit limiters for locally-generated ICMP
    /// Time-Exceeded / Hop-Limit-Exceeded replies, and for Packet-Too-Big /
    /// Frag-Needed PMTUD replies. Built in `populate_zones` from the SAME
    /// validated zone set as `reject_buckets` (#3618) — one #9901 (F-074)
    /// per-source-fair `ZoneLimiter` per configured zone id, keyed by the
    /// ingress interface's configured zone id (`ifindex_to_zone_id`); an
    /// unzoned (id 0) or unknown from-zone falls back to the process-global
    /// `TIME_EXCEEDED_FALLBACK_LIMITER` / `PACKET_TOO_BIG_FALLBACK_LIMITER` at
    /// the gate (never fail-open).
    ///
    /// Before #5856 these two reasons shared a SINGLE process-global bucket, so
    /// an attacker flooding TTL=1/hop-limit=1 (→ Time-Exceeded) or oversized-DF
    /// (→ Packet-Too-Big) traffic through ONE ingress zone drained the shared
    /// bucket and suppressed legitimate traceroute / PMTUD replies for EVERY
    /// other zone (a cross-zone denial of the generated-error service). Per-zone
    /// limiters remove that starvation exactly as #3618 did for Reject. Held as
    /// `Arc<ZoneLimiter>` for the same reason `reject_buckets` is — the shared
    /// atomics must survive `ForwardingState::clone()` (fabric refresh). Cardin-
    /// ality is config-bounded (Go-capped ≤ 65533), never attacker-growable.
    pub(in crate::afxdp) time_exceeded_buckets:
        FastMap<u32, std::sync::Arc<crate::afxdp::icmp_ratelimit::ZoneLimiter>>,
    pub(in crate::afxdp) packet_too_big_buckets:
        FastMap<u32, std::sync::Arc<crate::afxdp::icmp_ratelimit::ZoneLimiter>>,
    pub(in crate::afxdp) egress: FastMap<i32, EgressInterface>,
    /// #16513: ifindexes whose merged egress primary came from an
    /// operator DESIGNATION (a marked address on some row sharing the
    /// ifindex), per family. Build-time merge bookkeeping for
    /// `populate_egress`: a designated primary wins over undesignated
    /// order-based picks in either row order, and only a second,
    /// different designation conflicts. Not read after the build.
    pub(in crate::afxdp) egress_primary_v4_designated: FastSet<i32>,
    pub(in crate::afxdp) egress_primary_v6_designated: FastSet<i32>,
    /// Logical units whose configured VLAN is carried untagged on the wire
    /// because their VLAN is the parent's native VLAN (#13979).
    pub(in crate::afxdp) native_vlan_egress_ifindexes: FastSet<i32>,
    /// #11404: positive ifindexes whose snapshot rows explicitly report the
    /// egress link down. Missing state remains compatible with legacy snapshots.
    pub(in crate::afxdp) egress_link_down: FastSet<i32>,
    pub(in crate::afxdp) ingress_logical_ifindex: FastMap<(i32, u16), i32>,

    /// #11297/#11434: ifindexes where VID 0 is rejected: tagged-only physical
    /// bind targets and tagged VLAN children, plus native-VLAN parents without
    /// a unique matching unit. A valid native mapping or explicit unit 0
    /// exempts its parent so untagged traffic cannot inherit a sibling zone.
    pub(in crate::afxdp) tagged_only_ingress_ifindexes: FastSet<i32>,
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
    /// #16841 (correcting #15707): `system internet-options
    /// no-ipv6-reject-zero-hop-limit`. When true, hop-limit-0 IPv6
    /// packets addressed to the local host are ADMITTED; when false
    /// (the Junos default) they are dropped at local delivery. Transit
    /// Time Exceeded is unconditional and never reads this flag.
    /// IPv4 TTL handling is unaffected.
    pub(in crate::afxdp) no_ipv6_reject_zero_hop_limit: bool,
    /// `security flow allow-unstamped-fabric-ingress` preserves the historical
    /// domain-0 behavior for absent fabric stamps on routing-instance nodes.
    /// False is fail-closed; single-table deployments still retain legacy
    /// absence behavior because the receive gate is conditional on RI presence.
    pub(in crate::afxdp) allow_unstamped_fabric_ingress: bool,
    /// #16023: when true, a V1/V2 stamp is honoured only on a
    /// link-authenticated fabric; otherwise it is Invalid (stage-9 drop).
    pub(in crate::afxdp) require_authenticated_fabric_stamps: bool,
    /// #16044: `security flow drop-foreign-session-hits`. When true, a
    /// session hit whose live arrival zone is not the zone that admitted
    /// the session (including a differently-stamped fabric arrival) is
    /// dropped outright instead of being adjudicated in place under the
    /// arrival zone's policy and forwarded on the owner's entry, NAT and
    /// egress. Off by default: adjudicate-in-place (#9519) is preserved,
    /// so legitimately multi-homed / asymmetric arrivals keep forwarding.
    /// Only the packet is dropped; the session is never revoked by it.
    pub(in crate::afxdp) drop_foreign_session_hits: bool,
    /// `security alg <proto> disable` bitfield (#2008 H3/H4): bit 0 DNS,
    /// bit 1 FTP, bit 2 SIP, bit 3 TFTP, bit 4 PPTP (#15655). Read at
    /// session-create time to suppress ALG-type tagging for a disabled ALG
    /// (DNS/FTP/SIP) and to gate PPTP control learning / GRE association.
    /// Junos `alg disable` turns the ALG off; it never drops traffic.
    pub(in crate::afxdp) alg_disable_flags: u8,
    /// Publisher-stamped PPTP enable-epoch (coordinator, at view publish):
    /// monotonic per helper incarnation, advances whenever pptp_enabled
    /// flips across publishes. Workers read it atomically with the
    /// enabled bit from their loaded view; they never infer transitions.
    pub(in crate::afxdp) pptp_epoch: u64,
    /// #2008 M5: L3/L4 application-identification catalog. Resolves a session's
    /// 5-tuple to the numeric app_id stamped on the conntrack session at
    /// create time, so `show security flow session` reports a real application
    /// name. Empty when the Go snapshot carries no catalog (AppID disabled or
    /// an old Go binary) — sessions then keep app_id 0 (unknown).
    pub(in crate::afxdp) app_catalog: AppCatalog,
    pub(in crate::afxdp) session_timeouts: crate::session::SessionTimeouts,
    /// `security flow tcp-session no-syn-check`, controls transit session-miss
    /// admission. Strict mode wins if both flags are set.
    pub(in crate::afxdp) tcp_no_syn_check: bool,
    pub(in crate::afxdp) tcp_strict_syn_check: bool,
    /// #15753: tunnel-only mid-stream admission + RST/sequence fidelity.
    pub(in crate::afxdp) tcp_no_syn_check_in_tunnel: bool,
    pub(in crate::afxdp) tcp_rst_invalidate_session: bool,
    pub(in crate::afxdp) tcp_no_sequence_check: bool,
    pub(in crate::afxdp) tcp_rst_sequence_check: bool,
    pub(in crate::afxdp) tcp_maximum_window: u32,
    pub(in crate::afxdp) tcp_time_wait_session_ageout: bool,
    pub(in crate::afxdp) tcp_time_wait_apply_to_half_closed: bool,
    /// #3527: per-ingress-zone override (zone id → ns) of the global half-open
    /// (`tcp_opening_ns`) TCP window, built from each screened zone's
    /// `syn-flood timeout`. Pushed onto the worker `SessionTable` via
    /// `set_opening_overrides` alongside `session_timeouts`. Empty when no zone
    /// configures a syn-flood timeout (the common case), byte-identical to
    /// pre-#3527.
    pub(in crate::afxdp) session_opening_overrides: FastMap<u32, u64>,
    pub(in crate::afxdp) policy: PolicyState,
    /// Configuration generation whose policy table is held by `policy`.
    /// RT_FLOW closes re-resolve a rule ID against this table and stamp the
    /// same generation on the resulting event frame.
    pub(in crate::afxdp) config_generation: u64,
    /// Extensive policy-rematch metadata carried by the control plane for a
    /// zone/policy rename. Kept on the immutable forwarding generation so
    /// rotation can consume it before the next generation is published.
    pub(in crate::afxdp) policy_rematch_extensive: bool,
    /// #15188 (C08-02): single-use rename metadata. These two fields are
    /// shipped on exactly one full-apply publish; the coordinator strips
    /// them from its retained state immediately afterwards
    /// (`Coordinator::clear_single_use_policy_metadata`) and each worker
    /// consumes a generation's rebinds at most once
    /// (`last_rebind_generation` in `worker/loop_body`), so helper-internal
    /// republishes never re-apply them.
    pub(in crate::afxdp) policy_rename_ancestry: Vec<PolicyRenameAncestry>,
    pub(in crate::afxdp) policy_session_rebinds: Vec<PolicySessionRebind>,
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
    /// Shared inbound XFRM-SA existence snapshot used by Stage 11's
    /// ESP-in-UDP gate. The Arc is carried across forwarding rebuilds so a
    /// config apply cannot transiently empty the monitor's live table.
    pub(in crate::afxdp) ipsec_sa: std::sync::Arc<crate::afxdp::forwarding::IpsecSaStore>,
    /// Immutable bind-less IPsec selector fence compiled from the snapshot.
    /// Deliberately has no SA-state dependency: matching cleartext is dropped
    /// during both SA-up and SA-down windows.
    pub(in crate::afxdp) bindless_ipsec_selector_fence:
        crate::afxdp::ipsec_selector_fence::BindlessIpsecSelectorFence,
    pub(in crate::afxdp) nptv6: Nptv6State,
    pub(in crate::afxdp) screen_profiles: FastMap<String, ScreenProfile>,
    /// #3082: zone → name of a screen profile the zone REFERENCES but that was
    /// undefined when the snapshot was built. Distinct from `screen_profiles`
    /// (which only holds resolved profiles): a zone present here but absent
    /// from `screen_profiles` is a lenient-path fail-open — the dataplane
    /// emits a rate-limited runtime WARN for it (verdict still Pass). A zone
    /// in neither map simply has no screen configured (legit Pass).
    pub(in crate::afxdp) screen_missing_profiles: FastMap<String, UnresolvedProfileRef>,
    /// #7888: zone -> screen profile name for zones whose profile IS DEFINED
    /// but enables no check. Kept separate from `screen_missing_profiles`
    /// because the two select different runtime WARN texts.
    pub(in crate::afxdp) screen_inert_profiles: FastMap<String, UnresolvedProfileRef>,
    pub(in crate::afxdp) syn_cookie_master_key: SynCookieMasterKey,
    /// #9173: the key ring from `ConfigSnapshot::syn_cookie_key_ring`, resolved:
    /// the published bases, from which the helper derives each rotation period's
    /// key itself. Its `Debug` renders no key bytes.
    pub(in crate::afxdp) syn_cookie_key_ring: crate::screen::SynCookieKeyRing,
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
    /// #9522: the daemon withheld this snapshot's kernel-learned route import
    /// (the #8355 cap), so the FIB is deliberately incomplete and status/metric
    /// surfaces report the capped state. It does NOT alter NoRoute disposition:
    /// `noroute_policy_denial_gated` adjudicates capped and uncapped misses
    /// identically; only a policy Permit result keeps slow-path delegation.
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
    /// #15113: unit-scoped mirror rows keyed by (bind_ifindex, vlan_id).
    /// A row here matches only that VID (VID 0 covers untagged/native);
    /// it is consulted before the bare `mirror_configs` fallback so a
    /// unit-0 input never mirrors tagged siblings on the same port.
    /// #16063: the key also carries the logical unit number — every
    /// tunnel unit on one netdev has VID 0, so (ifindex, VID) alone
    /// cannot tell wg0.1 from wg0.0.
    pub(in crate::afxdp) mirror_configs_scoped: FastMap<(i32, u16, i32), MirrorRuntimeConfig>,
    /// #16063: logical ifindex -> configured unit number, for unit rows
    /// whose logical ifindex is distinct (VLAN units, unit 0). Built
    /// from the snapshot's interface rows at forwarding-build time —
    /// never from name-suffix parsing of a last-wins name map. Tunnel
    /// units sharing one netdev have no distinct logical ifindex and
    /// are absent here; the Go builder refuses mirroring them.
    pub(in crate::afxdp) ingress_unit_by_logical: FastMap<i32, i32>,
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


/// #16217: one connected-owner index probe result. `Hit` carries the
/// owning RG (0 = matched prefix whose interface has no RG — the
/// legacy scan returns that 0 as its answer, it is not a miss);
/// `Miss` means no indexed prefix contained the target at any
/// length, which is exactly the legacy scan's no-match outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum ConnectedOwnerIndex {
    Hit(i32),
    Miss,
}

impl ForwardingState {
    /// #17053: (re)build the connected-owner longest-prefix indexes
    /// from `connected_v4`/`connected_v6` plus the by-ifindex ledger
    /// rows. Called once per forwarding-state build (after the
    /// connected vecs are final). The index answers the canonical
    /// `connected_lpm_ifindex(.., RowsThenLedger)` (owner RG at
    /// build time) with an indexed probe:
    ///   1. FIB rows in table scope (row.table empty matches every
    ///      scope), longest prefix wins, LOWEST ifindex wins ties
    ///      (#17053, #10645 precedent). Ties are decided by ifindex,
    ///      never by insertion order: a stored slot keeps the lowest
    ///      ifindex at equal (table, len, network).
    ///   2. The by-ifindex ledger is consulted ONLY when no FIB row
    ///      matched in scope, so a ledger row fills a probe only
    ///      when no FIB row covers that (table, len, network); its
    ///      scope follows `instance_owns_table_{v4,v6}` (empty
    ///      instance -> family defaults ONLY; named R -> `<R>.inet.*`
    ///      ONLY). Equal-length ledger ties likewise keep the lowest
    ///      ifindex.
    pub(in crate::afxdp) fn rebuild_connected_owner_index(&mut self) {
        self.connected_owner_index_v4.clear();
        self.connected_owner_index_v6.clear();
        self.connected_owner_index_rows = (0, 0);
        // #17053: the ledger scope keys must mirror the canonical
        // per-family predicate EXACTLY (`instance_owns_table_v4` for
        // v4 rows, `instance_owns_table_v6` for v6 rows). A probe for
        // table `want` includes a ledger row iff that predicate holds
        // for the row's instance: empty instance owns only the family
        // default; a named R owns only `<R>.inet.0` (v4) /
        // `<R>.inet6.0` (v6). The probe must therefore use the
        // ORIGINAL want verbatim (no remap to the default key):
        // remapping a named want to "inet.0" would hide that
        // instance's own ledger rows and wrongly surface
        // default-instance rows under a named scope.
        // Empty-table FIB rows are visible in EVERY scope; they are
        // filed under the sentinel key "" and the probe considers
        // want-key and sentinel entries together. Within one
        // (table-key, len, network) slot the LOWEST ifindex wins
        // (#17053 canonical tie), stored in the slot's second field;
        // the third field is the winning interface's RG.
        for row in &self.connected_v4 {
            let rg = crate::afxdp::forwarding::owner_rg_for_flow(self, row.ifindex);
            let len = row.prefix.prefix_len();
            let net = u32::from(row.prefix.addr());
            let key: &str = if row.table.is_empty() {
                ""
            } else {
                row.table.as_str()
            };
            let slot = self
                .connected_owner_index_v4
                .entry((len, net))
                .or_default();
            if let Some(existing) = slot.iter_mut().find(|(k, _, _)| &**k == key) {
                if row.ifindex < existing.1 {
                    existing.1 = row.ifindex;
                    existing.2 = rg;
                }
            } else {
                slot.push((key.into(), row.ifindex, rg));
            }
        }
        for row in &self.connected_v6 {
            let rg = crate::afxdp::forwarding::owner_rg_for_flow(self, row.ifindex);
            let len = row.prefix.prefix_len();
            let net = u128::from(row.prefix.addr());
            let key: &str = if row.table.is_empty() {
                ""
            } else {
                row.table.as_str()
            };
            let slot = self
                .connected_owner_index_v6
                .entry((len, net))
                .or_default();
            if let Some(existing) = slot.iter_mut().find(|(k, _, _)| &**k == key) {
                if row.ifindex < existing.1 {
                    existing.1 = row.ifindex;
                    existing.2 = rg;
                }
            } else {
                slot.push((key.into(), row.ifindex, rg));
            }
        }
        // Ledger fallback rows: a ledger entry must NEVER displace
        // a FIB entry at the same (len, network, table) — the
        // canonical precedence is FIB-then-ledger at ANY length
        // (a shorter FIB row beats a longer ledger prefix), so the
        // probe needs two distinguishable phases. Ledger entries
        // therefore store their ifindex NEGATED (`-ifindex - 1`, so
        // ifindex 0 stays negative) in the slot's second field; FIB
        // entries store their raw (>= 0) ifindex. Scope per the
        // canonical per-family predicate (see above); within one
        // scoped key the LOWEST ifindex wins (#17053).
        // #17053 fold (Rev18099 F2): the negation MUST NOT wrap.
        // Ledger keys are kernel ifindexes (> 0 in production; see
        // the slot-shape invariant on the index fields), but
        // `-i32::MIN - 1` overflows (debug panic / release wrap to a
        // positive value the probe would misread as a FIB slot).
        // Encode via `checked_neg(..).map(|n| n - 1)` and skip the
        // unencodable `i32::MIN` key entirely; decoding an existing
        // slot (`-existing - 1`) is exact because stored ledger
        // values are in `i32::MIN..=-1` by construction.
        for (ifindex, prefixes) in &self.connected_v4_by_ifindex {
            let rg = crate::afxdp::forwarding::owner_rg_for_flow(self, *ifindex);
            let instance = self
                .ifindex_to_routing_instance
                .get(ifindex)
                .map(String::as_str)
                .unwrap_or("");
            let scoped: String = if instance.is_empty() {
                "inet.0".to_string()
            } else {
                format!("{instance}.inet.0")
            };
            for prefix in prefixes {
                let len = prefix.prefix_len();
                let net = u32::from(prefix.addr());
                let slot = self
                    .connected_owner_index_v4
                    .entry((len, net))
                    .or_default();
                // F2: skip the unencodable i32::MIN ledger key.
                let Some(encoded) = ifindex.checked_neg().map(|n| n - 1) else {
                    continue;
                };
                if let Some(existing) = slot.iter_mut().find(|(k, _, _)| &**k == scoped.as_str()) {
                    if existing.1 < 0 && *ifindex < -existing.1 - 1 {
                        existing.1 = encoded;
                        existing.2 = rg;
                    }
                } else {
                    slot.push((scoped.clone().into_boxed_str(), encoded, rg));
                }
            }
        }
        for (ifindex, prefixes) in &self.connected_v6_by_ifindex {
            let rg = crate::afxdp::forwarding::owner_rg_for_flow(self, *ifindex);
            let instance = self
                .ifindex_to_routing_instance
                .get(ifindex)
                .map(String::as_str)
                .unwrap_or("");
            let scoped: String = if instance.is_empty() {
                "inet6.0".to_string()
            } else {
                format!("{instance}.inet6.0")
            };
            for prefix in prefixes {
                let len = prefix.prefix_len();
                let net = u128::from(prefix.addr());
                let slot = self
                    .connected_owner_index_v6
                    .entry((len, net))
                    .or_default();
                // F2: skip the unencodable i32::MIN ledger key.
                let Some(encoded) = ifindex.checked_neg().map(|n| n - 1) else {
                    continue;
                };
                if let Some(existing) = slot.iter_mut().find(|(k, _, _)| &**k == scoped.as_str()) {
                    if existing.1 < 0 && *ifindex < -existing.1 - 1 {
                        existing.1 = encoded;
                        existing.2 = rg;
                    }
                } else {
                    slot.push((scoped.clone().into_boxed_str(), encoded, rg));
                }
            }
        }
        self.connected_owner_index_rows = (
            self.connected_v4.len() + self.connected_v6.len(),
            self.connected_v4_by_ifindex
                .values()
                .map(|v| v.len())
                .sum::<usize>()
                + self
                    .connected_v6_by_ifindex
                    .values()
                    .map(|v| v.len())
                    .sum::<usize>(),
        );
    }

    /// #16217 (GLM F1): was the index built from the current row
    /// sets? Counts FIB rows + ledger prefixes at build vs now.
    pub(in crate::afxdp) fn connected_owner_index_current(&self) -> bool {
        let fib = self.connected_v4.len() + self.connected_v6.len();
        let ledger: usize = self
            .connected_v4_by_ifindex
            .values()
            .map(|v| v.len())
            .sum::<usize>()
            + self
                .connected_v6_by_ifindex
                .values()
                .map(|v| v.len())
                .sum::<usize>();
        self.connected_owner_index_rows == (fib, ledger)
    }

    /// #16217/#17053: longest-prefix owner probe over the build-time
    /// index. Returns `None` when the index is empty (state never
    /// built it — unit fixtures), so the caller uses the canonical
    /// LPM scan. Otherwise `Hit(rg)`/`Miss` mirror the canonical
    /// `RowsThenLedger` outcome for (target, table) INCLUDING the
    /// two-phase precedence: the FIB pass runs first (empty-table
    /// rows visible in every scope via the "" key, per-length winner
    /// by LOWEST ifindex) and the ledger pass runs only when no FIB
    /// row matched at any length — a longer ledger prefix never
    /// beats a shorter FIB row. The rebuild marks ledger entries by
    /// storing `-ifindex - 1` (always negative) in the slot; FIB
    /// entries store their raw ifindex. The probe uses the ORIGINAL
    /// want verbatim (no remap to the default key — a named scope
    /// must not see default-instance ledger rows, and must see its
    /// own). Hot path: borrowed `&str` keys, no allocation per probe.
    pub(in crate::afxdp) fn connected_owner_index_lookup(
        &self,
        target: IpAddr,
        table: Option<&str>,
    ) -> Option<ConnectedOwnerIndex> {
        match target {
            IpAddr::V4(ip) => {
                if self.connected_owner_index_v4.is_empty() {
                    return None;
                }
                let want: &str = table.unwrap_or("inet.0");
                let addr = u32::from(ip);
                for len in (0..=32u8).rev() {
                    let net = if len == 0 {
                        0
                    } else {
                        addr & (u32::MAX << (32 - len))
                    };
                    if let Some(rg) = self
                        .connected_owner_index_v4
                        .get(&(len, net))
                        .and_then(|slot| {
                            slot.iter()
                                .filter(|(k, ifindex, _)| {
                                    *ifindex >= 0 && (&**k == want || k.is_empty())
                                })
                                .min_by_key(|(_, ifindex, _)| *ifindex)
                        })
                        .map(|(_, _, rg)| rg)
                    {
                        return Some(ConnectedOwnerIndex::Hit(*rg));
                    }
                }
                for len in (0..=32u8).rev() {
                    let net = if len == 0 {
                        0
                    } else {
                        addr & (u32::MAX << (32 - len))
                    };
                    if let Some(rg) = self
                        .connected_owner_index_v4
                        .get(&(len, net))
                        .and_then(|slot| {
                            slot.iter().find(|(k, ifindex, _)| *ifindex < 0 && &**k == want)
                        })
                        .map(|(_, _, rg)| rg)
                    {
                        return Some(ConnectedOwnerIndex::Hit(*rg));
                    }
                }
                Some(ConnectedOwnerIndex::Miss)
            }
            IpAddr::V6(ip) => {
                if self.connected_owner_index_v6.is_empty() {
                    return None;
                }
                let want: &str = table.unwrap_or("inet6.0");
                let addr = u128::from(ip);
                for len in (0..=128u8).rev() {
                    let net = if len == 0 {
                        0
                    } else {
                        addr & (u128::MAX << (128 - len))
                    };
                    if let Some(rg) = self
                        .connected_owner_index_v6
                        .get(&(len, net))
                        .and_then(|slot| {
                            slot.iter()
                                .filter(|(k, ifindex, _)| {
                                    *ifindex >= 0 && (&**k == want || k.is_empty())
                                })
                                .min_by_key(|(_, ifindex, _)| *ifindex)
                        })
                        .map(|(_, _, rg)| rg)
                    {
                        return Some(ConnectedOwnerIndex::Hit(*rg));
                    }
                }
                for len in (0..=128u8).rev() {
                    let net = if len == 0 {
                        0
                    } else {
                        addr & (u128::MAX << (128 - len))
                    };
                    if let Some(rg) = self
                        .connected_owner_index_v6
                        .get(&(len, net))
                        .and_then(|slot| {
                            slot.iter().find(|(k, ifindex, _)| *ifindex < 0 && &**k == want)
                        })
                        .map(|(_, _, rg)| rg)
                    {
                        return Some(ConnectedOwnerIndex::Hit(*rg));
                    }
                }
                Some(ConnectedOwnerIndex::Miss)
            }
        }
    }
}

impl ForwardingState {
    /// #15655: PPTP ALG is enabled unless `security alg pptp disable`
    /// (bit 0x10) is set. Gates both TCP/1723 control learning and GRE v1
    /// data association; neither is gated on gre-performance-acceleration.
    pub(in crate::afxdp) fn pptp_enabled(&self) -> bool {
        self.alg_disable_flags & 0x10 == 0
    }

    /// #16208: paired insert for an interface host address: adds `addr`
    /// to the family `local_v*` set AND records `table` as its owning
    /// canonical route table in `local_tables_v*`, atomically. This is
    /// the ONLY production writer for interface addresses; interface
    /// addresses are never wildcarded (an interface IP lives in exactly
    /// one VRF). Replaces the open-coded pair at the
    /// `forwarding_build/interfaces.rs` writer site.
    pub(in crate::afxdp) fn insert_local_iface_addr(&mut self, addr: IpAddr, table: String) {
        match addr {
            IpAddr::V4(v4) => {
                self.local_v4.insert(v4);
                self.local_tables_v4.entry(v4).or_default().insert(table);
            }
            IpAddr::V6(v6) => {
                self.local_v6.insert(v6);
                self.local_tables_v6.entry(v6).or_default().insert(table);
            }
        }
    }

    /// #16208: paired insert for a static-NAT/DNAT external address:
    /// adds `addr` to the family `local_v*` set, accumulates the
    /// `local_nat_to_self_*` conjunction (`true` only if every
    /// configured translation for the external targets a configured
    /// interface address, #11439), AND records its table attribution,
    /// atomically. A wildcard (unscoped, `Some(None)`) rule is recorded
    /// in the table-agnostic `local_nat_any_table_v*` set — owned in
    /// EVERY table, mirroring `scope_ok`'s empty-instance wildcard;
    /// `Some(Some(table))` records the specific canonical table in
    /// `local_tables_v*`; `None` adds the address with no attribution
    /// (fail-closed: the table-scoped local-delivery decision will not
    /// own it). This is the ONLY production writer for NAT externals;
    /// replaces the open-coded triple at the
    /// `forwarding_build/mod.rs` late-stage writer site.
    pub(in crate::afxdp) fn insert_nat_external(
        &mut self,
        addr: IpAddr,
        table: Option<Option<String>>,
        to_self: bool,
    ) {
        match addr {
            IpAddr::V4(v4) => {
                self.local_nat_to_self_v4
                    .entry(v4)
                    .and_modify(|all_to_self| *all_to_self &= to_self)
                    .or_insert(to_self);
                self.local_v4.insert(v4);
                match table {
                    Some(Some(table)) => {
                        self.local_tables_v4.entry(v4).or_default().insert(table);
                    }
                    Some(None) => {
                        self.local_nat_any_table_v4.insert(v4);
                    }
                    None => {}
                }
            }
            IpAddr::V6(v6) => {
                self.local_nat_to_self_v6
                    .entry(v6)
                    .and_modify(|all_to_self| *all_to_self &= to_self)
                    .or_insert(to_self);
                self.local_v6.insert(v6);
                match table {
                    Some(Some(table)) => {
                        self.local_tables_v6.entry(v6).or_default().insert(table);
                    }
                    Some(None) => {
                        self.local_nat_any_table_v6.insert(v6);
                    }
                    None => {}
                }
            }
        }
    }


    /// #3071: true iff zone `zone_id` has Junos `tcp-rst` enabled. Used by the
    /// strict-SYN transit session-miss path to decide whether a non-SYN TCP
    /// packet whose ingress (from) zone is `zone_id` gets a TCP RST. An
    /// unconfigured / unknown zone (e.g. `0`) is always tcp-rst off.
    pub(in crate::afxdp) fn zone_tcp_rst_enabled(&self, zone_id: u32) -> bool {
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
    /// Wire VID for an egress logical interface. Native-VLAN units map to
    /// VID 0 on TX while retaining their configured VID for ingress lookup.
    #[inline]
    pub(in crate::afxdp) fn egress_tx_vlan_id(&self, ifindex: i32) -> u16 {
        if self.native_vlan_egress_ifindexes.contains(&ifindex) {
            0
        } else {
            self.egress.get(&ifindex).map(|iface| iface.vlan_id).unwrap_or(0)
        }
    }

    #[inline]
    pub(in crate::afxdp) fn egress_zone_id(&self, egress_ifindex: i32) -> u32 {
        self.ifindex_unambiguous_zone_id
            .get(&egress_ifindex)
            .copied()
            .unwrap_or(0)
    }

    /// #3618/#5856: the per-zone generated-error rate limiter for `reason`
    /// and ingress (from) zone `from_zone_id`, or `None` if the zone is
    /// unconfigured / unknown (the gate then falls back to the reason's shared
    /// `*_FALLBACK_LIMITER`). Returns a plain `&ZoneLimiter` (deref of the held
    /// `Arc`) so the limiter gate treats a per-zone limiter and the `&'static`
    /// fallback uniformly. Used by `icmp_ratelimit::allow_generated_error_zoned*`
    /// (and, via that, the `allow_generated_reject*` convenience wrappers).
    pub(in crate::afxdp) fn generated_error_bucket(
        &self,
        reason: crate::afxdp::icmp_ratelimit::GeneratedErrorReason,
        from_zone_id: u32,
    ) -> Option<&crate::afxdp::icmp_ratelimit::ZoneLimiter> {
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
    /// set, NOT `local_v*`. `local_v*` excludes egress addresses selected by
    /// interface-mode SNAT's to-side matrix (`to-zone`, `to-interface`,
    /// `to-routing-instance`, or unscoped; `nat_translated_local_exclusions`),
    /// e.g. the WAN `reth0.80` IP, so reusing it left the router's own
    /// SNAT/WAN interface IP poisonable. The `local_v*` membership is still
    /// OR-ed in so the static-NAT-external and DNAT-destination addresses
    /// appended to `local_v*` (late-stage local-delivery targets the router
    /// also answers for) keep their #2851 protection; `configured_iface_v*`
    /// adds the genuine interface IPs that the NAT exclusion stripped.
    /// NAT-translated POOL addresses are in
    /// neither set, so the gate still scopes to addresses the router owns.

    #[inline]
    pub(in crate::afxdp) fn owns_configured_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.configured_iface_v4.contains(&v4) || self.local_v4.contains(&v4),
            IpAddr::V6(v6) => self.configured_iface_v6.contains(&v6) || self.local_v6.contains(&v6),
        }
    }
    /// #13644: source-MAC learning from admitted L3 traffic is valid only
    /// when the claimed address lies in a connected prefix on this ingress.
    /// Match the VLAN-resolved ingress identity, not a different subnet on
    /// its physical parent; RX may store aliases separately after validation.
    #[inline]
    pub(in crate::afxdp) fn src_ip_on_link_for_ingress(
        &self,
        ingress_ifindex: i32,
        ingress_vlan_id: u16,
        ip: IpAddr,
    ) -> bool {
        let ingress_logical_ifindex =
            super::super::super::forwarding::resolve_ingress_logical_ifindex(
                self,
                ingress_ifindex,
                ingress_vlan_id,
            )
            .unwrap_or(ingress_ifindex);
        match ip {
            IpAddr::V4(ip) => self
                .connected_v4_by_ifindex
                .get(&ingress_logical_ifindex)
                .is_some_and(|prefixes| prefixes.iter().any(|prefix| prefix.contains(ip))),
            IpAddr::V6(ip) => self
                .connected_v6_by_ifindex
                .get(&ingress_logical_ifindex)
                .is_some_and(|prefixes| prefixes.iter().any(|prefix| prefix.contains(ip))),
        }
    }
    /// Base address ownership for Stage 11: interface addresses remain local
    /// (including interface-mode-SNAT/WAN exclusions), while NAT external
    /// addresses are local only when their configured translations target
    /// configured interface addresses. Because a DNAT rule can use an interface
    /// address as a transit VIP, Stage 11 also probes the packet's actual DNAT
    /// match and lets a matching transit translation override this base result.
    #[inline]
    pub(in crate::afxdp) fn owns_ipsec_local_destination(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                self.configured_iface_v4.contains(&v4)
                    || self.local_nat_to_self_v4.get(&v4).copied().unwrap_or(false)
            }
            IpAddr::V6(v6) => {
                self.configured_iface_v6.contains(&v6)
                    || self.local_nat_to_self_v6.get(&v6).copied().unwrap_or(false)
            }
        }
    }
    /// #14124: VRF-scoped form of [`Self::owns_ipsec_local_destination`].
    /// The unscoped predicate is address-global: an address configured
    /// only in another routing instance (or a NAT-to-self external whose
    /// translations are scoped to another instance) still reads as
    /// locally terminated, so Stage 11 claimed the packet for XFRM and
    /// applied the wrong VRF's admission. This form additionally
    /// requires the destination to be locally owned in the ingress
    /// packet's own routing table, mirroring the table-scoped
    /// local-delivery decision (`local_*_owned_by_table` in fib.rs):
    ///
    /// - interface addresses and interface-NAT addresses are owned
    ///   only in their interface's connected table (never wildcarded);
    /// - NAT externals are owned in their rule's scoped table, or in
    ///   every table for an unscoped (wildcard) rule.
    ///
    /// `ingress_table` is the ingress interface's canonical table
    /// (`connected_route_tables(routing_instance)` for the ingress
    /// logical ifindex). An address with no table attribution at all
    /// (hand-built test states, lo0 helpers) is NOT owned here —
    /// fail-closed: Stage 11 returns `NotClaimed` and the packet
    /// takes ordinary forwarding/policy instead of XFRM reinjection.
    #[inline]
    pub(in crate::afxdp) fn owns_ipsec_local_destination_in_table(
        &self,
        ip: IpAddr,
        ingress_table: &str,
    ) -> bool {
        if !self.owns_ipsec_local_destination(ip) {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => {
                self.local_nat_any_table_v4.contains(&v4)
                    || self
                        .local_tables_v4
                        .get(&v4)
                        .is_some_and(|tables| tables.contains(ingress_table))
                    || self
                        .interface_nat_tables_v4
                        .get(&v4)
                        .is_some_and(|tables| tables.contains(ingress_table))
            }
            IpAddr::V6(v6) => {
                self.local_nat_any_table_v6.contains(&v6)
                    || self
                        .local_tables_v6
                        .get(&v6)
                        .is_some_and(|tables| tables.contains(ingress_table))
                    || self
                        .interface_nat_tables_v6
                        .get(&v6)
                        .is_some_and(|tables| tables.contains(ingress_table))
            }
        }
    }
}
#[cfg(test)]
mod paired_insert_16208_tests {
    use super::*;

    #[test]
    fn insert_local_iface_addr_pairs_local_and_table_v4() {
        let mut state = ForwardingState::default();
        let addr = Ipv4Addr::new(192, 0, 2, 1);
        state.insert_local_iface_addr(IpAddr::V4(addr), "tenant.inet.0".to_string());
        assert!(state.local_v4.contains(&addr));
        assert!(state
            .local_tables_v4
            .get(&addr)
            .is_some_and(|t| t.contains("tenant.inet.0")));
        assert!(!state.local_nat_any_table_v4.contains(&addr));
        // Second table accumulates without dropping the first.
        state.insert_local_iface_addr(IpAddr::V4(addr), "inet.0".to_string());
        let tables = state.local_tables_v4.get(&addr).unwrap();
        assert_eq!(tables.len(), 2);
    }

    #[test]
    fn insert_local_iface_addr_pairs_local_and_table_v6() {
        let mut state = ForwardingState::default();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        state.insert_local_iface_addr(IpAddr::V6(addr), "tenant.inet6.0".to_string());
        assert!(state.local_v6.contains(&addr));
        assert!(state
            .local_tables_v6
            .get(&addr)
            .is_some_and(|t| t.contains("tenant.inet6.0")));
        assert!(!state.local_nat_any_table_v6.contains(&addr));
        assert!(state.local_v4.is_empty());
    }

    #[test]
    fn insert_nat_external_scoped_records_table_and_to_self() {
        let mut state = ForwardingState::default();
        let addr = Ipv4Addr::new(198, 51, 100, 7);
        state.insert_nat_external(
            IpAddr::V4(addr),
            Some(Some("tenant.inet.0".to_string())),
            true,
        );
        assert!(state.local_v4.contains(&addr));
        assert!(state
            .local_tables_v4
            .get(&addr)
            .is_some_and(|t| t.contains("tenant.inet.0")));
        assert!(!state.local_nat_any_table_v4.contains(&addr));
        assert_eq!(state.local_nat_to_self_v4.get(&addr), Some(&true));
    }

    #[test]
    fn insert_nat_external_wildcard_records_any_table() {
        let mut state = ForwardingState::default();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);
        state.insert_nat_external(IpAddr::V6(addr), Some(None), false);
        assert!(state.local_v6.contains(&addr));
        assert!(state.local_nat_any_table_v6.contains(&addr));
        assert!(!state.local_tables_v6.contains_key(&addr));
        assert_eq!(state.local_nat_to_self_v6.get(&addr), Some(&false));
    }

    #[test]
    fn insert_nat_external_to_self_is_conjunction() {
        let mut state = ForwardingState::default();
        let addr = Ipv4Addr::new(203, 0, 113, 5);
        state.insert_nat_external(IpAddr::V4(addr), Some(None), true);
        assert_eq!(state.local_nat_to_self_v4.get(&addr), Some(&true));
        // A later transit target flips the conjunction to false and
        // it never flips back.
        state.insert_nat_external(IpAddr::V4(addr), Some(None), false);
        assert_eq!(state.local_nat_to_self_v4.get(&addr), Some(&false));
        state.insert_nat_external(IpAddr::V4(addr), Some(None), true);
        assert_eq!(state.local_nat_to_self_v4.get(&addr), Some(&false));
    }

    #[test]
    fn insert_nat_external_no_table_is_fail_closed() {
        let mut state = ForwardingState::default();
        let addr = Ipv4Addr::new(192, 0, 2, 99);
        state.insert_nat_external(IpAddr::V4(addr), None, true);
        assert!(state.local_v4.contains(&addr));
        assert!(!state.local_tables_v4.contains_key(&addr));
        assert!(!state.local_nat_any_table_v4.contains(&addr));
        assert_eq!(state.local_nat_to_self_v4.get(&addr), Some(&true));
    }
}

