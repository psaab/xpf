# userspace-dp/src/afxdp/forwarding/

The "decide where this packet goes" stage. Validates the parsed
packet metadata against the live `ValidationState` (snapshot
installed, config generation matches, FIB generation matches), then
runs FIB lookup, next-hop selection, VRF / next-table inter-VRF
leaking traversal, and produces a `ForwardingResolution` for the TX
side.

Packets that fail validation never reach FIB lookup — they get a
`PacketDisposition` (`NoSnapshot`, `ConfigGenerationMismatch`,
`FibGenerationMismatch`, `UnsupportedPacket`) and are dropped or
slow-path-injected.

## Files

The forwarding stage was split from a single ~2800-LOC `mod.rs` into
cohesive submodules by fused responsibility (#5650). The split is pure
code-motion — functions moved verbatim, visibility preserved
(`pub(in crate::afxdp)`), `#[inline]` attributes kept exactly — and
`mod.rs` glob-re-exports every submodule (`pub(in crate::afxdp) use
<m>::*`), so every external call site (`crate::afxdp::forwarding::…`,
`use self::forwarding::*`) resolves unchanged.

| File | Purpose |
|------|---------|
| `mod.rs` | Submodule wiring + re-exports, and the small zone-pair / DNS-reply / ingress-logical-ifindex helpers (`zone_pair_for_flow*`, `zone_pair_ids_for_flow*`, `allow_unsolicited_dns_reply`, `resolve_ingress_logical_ifindex`). |
| `fib.rs` | Core FIB resolution hot path: `classify_metadata`, `canonical_route_table`, packet-destination parse, the `lookup_forwarding_resolution*` table / next-table walk, per-family v4/v6 resolution + `_inner` helpers, ECMP hashing (`ecmp_hash_*`), route choice (`choose_v4_route`/`choose_v6_route`, `ResolvedRouteV4/V6`), `select_route_next_hop`, `tunnel_next_hop_live`, `no_route_resolution`, and the `DEFAULT_V4_TABLE`/`DEFAULT_V6_TABLE`/`MAX_NEXT_TABLE_DEPTH` constants. |
| `fabric.rs` | Fabric cross-chassis forwarding: link resolution/skip classification (`build_fabric_link_or_skip`, `resolve_fabric_links_from_snapshots`, the skip counters), fabric-redirect selection (`resolve_fabric_redirect*`, zone-encoded variants), `redirect_via_fabric_if_needed`, `prefer_local_forward_candidate_for_fabric_ingress`, and the shared kernel-neighbor-state classifier (`classify_neighbor_state`, `neighbor_state_usable`, `NeighborStateClass`). (The HA `cluster_peer_return_fast_path` was removed in #6478.) |
| `nat.rs` | Source-NAT flow matching (`nat_scope_ctx_for_flow`, `match_source_nat_for_flow*`) and interface-NAT local resolution (`interface_nat_local_resolution*`, `should_block_tunnel_interface_nat_session_miss`). |
| `ha.rs` | HA redundancy-group resolution enforcement (`enforce_ha_resolution*`, `cached_flow_decision_valid`, `finalize_new_flow_ha_resolution`), owner-RG attribution (`owner_rg_for_flow`, `owner_rg_for_resolution`), and demoted/activated owner-RG set diffs. |
| `mss.rs` | TCP MSS clamp + tunnel/GRE outer-MTU derivation (`effective_tcp_mss`, `native_gre_*`, `tunnel_outer_mtu`, `tunnel_tcp_mss`, `select_tcp_mss`). |
| `ipsec.rs` | IPsec traffic classification + inbound admission (`is_ipsec_traffic` (`#[inline]`), `IpsecAdmissionClass`, `classify_ipsec_admission`, the #6471 live-IKE-exchange table `IkeExchangeTable`/`SharedIkeExchangeTable` + SPI extractors + outbound-seed helper). |
| `pbr.rs` | Policy-based routing: `ingress_route_table_override` and its `PbrRejectSink` / `RouteOverride` support types. |
| `local_delivery.rs` | Host-local delivery session caching on session-miss (`should_cache_local_delivery_session_on_miss`, `install_helper_local_session_on_miss`, `ingress_interface_local_resolution*`, the `LOCAL_DELIVERY_IFINDEX0` counter). |
| `tunnel.rs` | Tunnel outer-header forwarding resolution (`resolve_tunnel_outer`, `resolve_tunnel_forwarding_resolution`, `outer_neighbor_ifindex`) and neighbor-entry lookup/parse (`lookup_neighbor_entry`, `parse_neighbor_entries`). |
| `host_inbound.rs` | #3070 host-inbound-traffic admission: classifies a zone's Junos `system-services` / `protocols` tokens into a `ZoneHostInbound` set and provides `host_inbound_admits` for the local-delivery path. |
| `tests.rs` | Co-located unit tests covering classify, FIB lookup, multi-table next-table leaking. |

## Constants

- `DEFAULT_V4_TABLE = "inet.0"`, `DEFAULT_V6_TABLE = "inet6.0"` —
  the default routing tables a packet starts in when no
  routing-instance scopes it. `canonical_route_table` (#4674) returns
  `Cow<'static, str>`: the default-table remaps (`inet.0`↔`inet6.0`)
  and the lookup-path default both borrow these `'static` constants and
  allocate nothing on the per-new-flow FIB resolution path; only the
  rare per-VRF suffix rewrite (`<inst>.inet.0`↔`<inst>.inet6.0`) or a
  non-canonical passthrough owns a heap `String`.
- `MAX_NEXT_TABLE_DEPTH = 8` — bounded recursion across `next-table`
  chains to keep a misconfigured loop from running forever.

## FIB route model

Route metadata crosses the Go→Rust snapshot boundary as `RouteSnapshot`
(`protocol/snapshot.rs`) and is built into per-table FIBs by
`forwarding_build/fib.rs`. Three correctness rules govern selection:

- **Connected routes are table-scoped (#2388).** Connected prefixes are
  rebuilt from interface addresses into the global `connected_v[46]`
  vectors, but each entry carries its routing-table name
  (`ConnectedRouteV4::table`), derived from the interface's
  `routing_instance` (`""` = default → `inet.0`/`inet6.0`; a named
  instance → `<ri>.inet.0`/`<ri>.inet6.0`). The lookup filters connected
  candidates on the resolving table, so a per-VRF / `next-table` lookup
  never matches another routing-instance's connected prefix. Gateway →
  egress inference at build time (`infer_connected_route_target_*`,
  "which interface reaches this bare-gateway IP") is **also** table-scoped
  (#4446): it filters `connected_v[46]` on the route's own canonical
  install table before the prefix match, so a bare-gateway static route in
  VRF A never binds VRF B's overlapping connected prefix. The inferred
  ifindex is baked into `RouteEntryV*.next_hops` and consumed verbatim at
  lookup, so this scoping MUST happen at build time — the lookup-time
  #2388 connected filter cannot re-scope an already-resolved next-hop. A
  route-leak / `next-table` cross-VRF reach is unaffected: a leaked route
  carries no forwarding next-hop (it is a `NextTable` snapshot), so it
  never reaches this inference and is re-resolved in the target table's
  own scope by the recursion.
  - **Local-delivery (to-self) attribution is table-scoped too (#3151).**
    The `lookup_forwarding_resolution_inner_ecmp` shortcut for a
    destination in `local_v[46]` resolves `local_ifindex` /
    `egress_ifindex` / `tx_ifindex` by scanning `connected_v[46]`. That
    scan applies the SAME `entry.table == table` filter as the route path
    (canonicalizing the ingress table FIRST, before the local-address
    check). Without it, when the same local IP is configured in more than
    one routing-instance, a to-self packet in VRF A could attribute its
    local/egress/tx ifindex to VRF B's interface — mis-feeding
    zone/security-policy selection and HA RG ownership
    (`owner_rg_for_flow(egress_ifindex)`). The default routing-instance
    (`inet.0`/`inet6.0`) case still matches default-table connected
    routes.
  - **Local-delivery DECISION is table-scoped too (#3769).** #3151 fixed
    the ifindex ATTRIBUTION but the membership DECISION stayed global:
    `local_v[46]` is a global set, and it also carries NAT/DNAT external
    targets (static-NAT external IPs + DNAT destination IPs). The
    connected scan cannot recover the owning table for the DECISION —
    a NAT-only IP has no connected route at all, and `ConnectedRouteV*`
    stores the MASKED network address so `prefix.addr() == host` matches
    only a /32/128 interface. A packet in VRF A destined to a local
    address owned only in VRF B therefore hit the global `local_v[46]`
    membership and short-circuited to `LocalDelivery`, bypassing the
    VRF-A FIB + zone/policy + HA-RG owner check. The build now records
    per-address table ownership in `local_tables_v[46]` (a `FastMap<Ip,
    FastSet<table>>` with an insert paired to EVERY `local_v*` insert:
    interface host addresses in `populate_interfaces`, keyed by the host
    `.addr()`; NAT/DNAT externals in the `forwarding_build` late-stage
    append, keyed by the rule's `from routing-instance` → canonical table
    via `connected_route_tables`). The shortcut delivers locally ONLY
    when the RESOLVING table is in that owning set; an address owned only
    in another table falls through to the route lookup (VRF-A FIB). This
    also generalizes #3151 to a single-owner interface IP (present in
    exactly one VRF, not the same IP in both). The ifindex ATTRIBUTION
    still uses the table-scoped connected scan (the /32-HA case).
    **Empty-scope = wildcard:** a NAT/DNAT rule whose `from
    routing-instance` is empty is a wildcard `scope_ok` matches against
    ANY ingress routing-instance (and the common `from zone` / `from
    interface` inbound-DNAT rule leaves it empty — `compiler_nat.go`).
    Its external IP is recorded in the table-agnostic
    `local_nat_any_table_v[46]` set (treated as owned in EVERY table by
    the DECISION), NOT attributed to `inet.0` only — otherwise an external
    whose zone lives in a non-default VRF would be over-isolated. Interface
    host addresses are never wildcarded (an interface IP lives in exactly
    one VRF).
    **L5:** a NAT-only external target (or a non-/32 interface IP whose
    ingress-interface resolution was bypassed) has no exact connected
    match, so its LocalDelivery carries ifindex 0 — now reached ONLY when
    the table genuinely owns the address, and counted by the
    `LOCAL_DELIVERY_IFINDEX0` diagnostic atomic.
- **ECMP: all next-hops retained, dead ones skipped (#2389), per-FLOW
  spread (#2734).** A static route keeps EVERY configured next-hop
  (`RouteEntryV4::next_hops: Vec<RouteNextHopV4>`). `select_route_next_hop`
  prefers a candidate with a resolved neighbor (so a dead first next-hop
  no longer blackholes a route with a healthy alternate), then distributes
  across the live candidates by a spread hash. **#5161: liveness is
  next-hop-shape-aware.** A member with an EXPLICIT gateway (`next_hop ==
  Some`) is live once that gateway's neighbor resolves — the coordinator
  warmer (`queue_warm_pass`) proactively ARP/ND-probes every explicit
  next-hop, so a genuinely-dead gateway never resolves and stays correctly
  skipped. An INTERFACE-ONLY member (`next_hop == None`, a "via <if>"
  candidate) resolves its neighbor from the PER-FLOW destination itself,
  which the warmer cannot pre-resolve (the on-link destination is a whole
  prefix, unknown at route-sweep time — so interface-only members are NOT
  warmed). Gating such a member on an already-present destination neighbor
  starved it out of the live set the moment any explicit member resolved,
  collapsing ECMP to width-1; instead it is live whenever its interface is
  up (`ifindex > 0`), and the MissingNeighbor cold path resolves each
  destination lazily per flow (mirroring the single-member interface-only
  path). Tunnel members use their own type-aware liveness (#2923). **#2734:
  the spread key is
  per-FLOW.** The session resolution path
  (`lookup_forwarding_resolution_with_dynamic_for_flow`) hashes the forward
  5-tuple with `ecmp_hash_flow` — the SAME per-boot seeded `FxHasher` the
  flow cache uses (`hot_hash_seed::hot_path_hash_seed`, #2364), so distinct
  flows to the same destination spread across equal-cost members while
  every packet of one flow pins to one member (flow-consistent, no
  intra-flow reordering; the resolution is cached on the session entry).
  The hash reduces modulo the LIVE-member count, so the spread tracks the
  live pool and the dead-NH fallback is preserved. Callers without a flow
  context (tunnel/WG outer resolution, `inject`, bare-dst lookups) pass
  `ecmp_flow_hash = None`, which falls back to the per-DESTINATION hash
  (`ecmp_hash_v4`/`ecmp_hash_v6`, the #2389 behavior). The seed is
  node-local (ECMP picks among THIS node's members and is not wire/HA
  state), so an HA peer re-derives its own pick under its own seed — the
  same property the flow cache and fabric-queue hash already rely on. The
  legacy `RouteEntryV4::{ifindex,next_hop,tunnel_endpoint_id}` accessors
  return the FIRST candidate for non-multipath call sites.
- **Preference tie-break before insertion order (#2390).**
  `RouteSnapshot.preference` (Junos admin distance; lower = more
  preferred, default 5) is carried on the wire and used as the secondary
  sort key in `sort_routes` (descending prefix length, then ascending
  preference). Two same-prefix routes in a table select by operator
  preference, not insertion order; same-prefix/same-preference routes
  keep insertion order (stable sort).
- **Qualified-next-hop backups lower as distinct-preference standby
  routes (#5678).** A Junos floating static (a primary `next-hop` plus a
  `qualified-next-hop <gw> { preference N; }` backup, #3871) carries a
  PER-next-hop admin distance. The Go snapshot builder
  (`pkg/dataplane/userspace/routes.go`) groups a route's next-hops by
  their EFFECTIVE preference (the qualified `nh.Preference` when
  `HasPreference`, else the route-level `Preference`) and emits ONE
  `RouteSnapshot` per distinct preference. So the backup arrives as a
  SEPARATE, higher-preference route for the same prefix — the #2390
  tie-break above then selects the primary and holds the backup as a
  standby entry (first-match lookup never reaches it while the primary
  route is present). Before #5678 the builder collapsed every next-hop
  onto ONE route-level-preference snapshot, so the backup was installed
  as an equal-cost ECMP member and traffic load-balanced across both
  tiers — a silent routing-semantics change. Next-hops that SHARE a
  preference (a plain `next-hop [ a b ]` list, or qualified next-hops at
  the same distance) still collapse to one equal-cost ECMP snapshot, so
  real ECMP is unaffected. This mirrors the FRR renderer
  (`pkg/frr/config_render.go`), which emits one `ip route` line per
  next-hop at `dist = nh.Preference` when `HasPreference` else the
  route-level distance.

All three wire fields (`routing_instance`, `next_hops`, `preference`)
are additive: an old Rust helper ignores them (pre-fix behavior) and an
old Go binary omits them (serde defaults: default instance, empty
next-hops, preference 0). The wire specimen lives in
`tests/fixtures/protocol_wire_v1.json`.

- **Route / neighbor wire-struct integrity (#3771).** `populate_routes`
  and `populate_neighbors` are fallible and fail the snapshot CLOSED —
  the apply preflight then keeps the previous live forwarding state —
  on a wire-struct whose metadata contradicts itself, consistent with
  the #2410/#2409 fail-closed family:
    - **Route family/destination (M4).** A `RouteSnapshot` whose
      NON-EMPTY `family` does not match the address family its
      `destination` prefix parses as is rejected
      (`SnapshotIntegrityError::RouteFamilyMismatch`) instead of being
      installed into the prefix-parsed FIB while the metadata claims the
      other family. This is NOT the #2448 malformed-destination case
      (the prefix is a valid CIDR). An EMPTY `family` is unconstrained
      (parse-only, the pre-fix behavior) and never a mismatch.
    - **Route preference range (L1).** A NEGATIVE `preference` is
      rejected (`RoutePreferenceOutOfRange`): the `sort_routes`
      tie-break is ascending preference, so a negative value would sort
      ahead of every route and hijack selection for the prefix. The Go
      commit boundary (`schema_routing.go`, `ValidateInteger(0, i32max)`
      on the route `preference` leaf) is the primary gate; this is the
      helper-boundary backstop.
    - **Neighbor family/IP (M11).** A `NeighborSnapshot` whose NON-EMPTY
      `family` contradicts its parsed `ip` is rejected
      (`NeighborFamilyMismatch`) instead of being installed under a
      contradicting family.
    - **Neighbor state allowlist (M12).** `neighbor_state_usable` /
      `classify_neighbor_state` are an ALLOWLIST
      (`reachable`/`stale`/`delay`/`probe`/`permanent`/`noarp`), NOT the
      pre-fix denylist. `failed`/`incomplete` are known-unusable (skipped
      silently); an empty / `none` / future / corrupt state is UNKNOWN —
      skipped AND counted by the `NEIGHBOR_UNKNOWN_STATE_SKIPPED`
      diagnostic atomic (the pre-fix denylist installed every
      unrecognized state that carried a parseable IP+MAC). The
      snapshot-refresh manager-key set, the `update_neighbors` handler,
      and `parse_neighbor_entries` share the same gate so an installed
      neighbor is never pruned as a stale key.
    - **Authoritative empty replace clears (#5864).** An
      `update_neighbors` request with `neighbor_replace=true` is an
      AUTHORITATIVE replacement of the manager-neighbor table, so a
      request with ZERO entries CLEARS it — the last usable neighbor
      disappearing (kernel neighbor deletion) must drop the helper's
      stale entry, not leave it forwarding to a dead MAC. The handler
      therefore treats an absent/`null`/`[]` neighbors field under
      `replace` as "clear", NOT as "no-op": it does not early-return on
      `None` when `replace` is set. Go stopped sending the field with
      `omitempty` so a present-empty set encodes as `"neighbors":[]`
      (distinct from absent) rather than being dropped; the helper
      accepts both the absent and explicit-empty forms as a clear. A
      NON-replace update with no neighbors stays a no-op (nothing to
      add). NOTE: this is the bounded clear-on-empty fix; it does NOT add
      a replace-generation envelope / ACK / retry-debt (deferred
      robustness, tracked separately).
    - **Fabric-link skips (#3773 M13).** `build_fabric_link_or_skip` is the
      SHARED classifier for both fabric-resolution passes
      (`populate_fabrics` snapshot build, `resolve_fabric_links_from_snapshots`
      runtime refresh). A skipped fabric link is no longer a silent
      `continue`: it is counted by the `FABRIC_LINK_SKIPPED_MALFORMED`
      (invalid parent ifindex / unparseable peer address / non-empty
      unparseable local|peer MAC) or `FABRIC_LINK_UNRESOLVED_PEER` (empty MAC
      awaiting neighbor/interface resolution — the expected `SyncFabricState`
      transient) diagnostic atomic, recorded by name in
      `ForwardingState.fabric_skips`, and named once-per-change in the journal
      by `log_fabric_skip_transition`. Both atomics surface in status/Prometheus
      (`xpf_userspace_fabric_link_{skipped_malformed,unresolved_peer}_total`).
      Fabric is an HA optimization, so a malformed link is
      skipped-with-visibility, NOT fail-closed-whole-snapshot. See
      `docs/fabric-cross-chassis-fwd.md`.
    - **Same-parent peer replacement (#5686 M01).** The snapshot/refresh
      paths PRESERVE a resolved `FabricLink` across a pass that could not
      re-resolve it (peer MAC not yet learned). That preserve MUST NOT keep a
      link whose peer has been REPLACED: if the incoming snapshots configure
      the SAME parent but a DIFFERENT peer address, the old link is SUPERSEDED
      and dropped (`fabric_link_superseded_by_snapshots`) — otherwise the stale
      old peer stays a valid `resolve_fabric_redirect` target while the
      replacement peer is still unresolved, and fabric-forwarded traffic is
      sent to a peer that is no longer current. Once dropped, redirect for that
      parent yields NO target during the resolution window and the packet takes
      its normal non-fabric disposition (safe) rather than a wrong-peer
      redirect; when the replacement resolves it installs normally. A snapshot
      that still names the same peer (steady-state refresh) or omits the parent
      (fabric removed, not replaced) is not a supersession, so the working link
      survives. The prune runs in both `refresh_fabric_links` (SyncFabricState)
      and `refresh_runtime_snapshot_inner` (config apply); the pruned set is
      stored into BOTH the full `ha.runtime` view's forwarding Arc AND the worker fast-path
      `ha.fabrics` Arc so no reader retains the stale peer.

## Session identity is VRF-POPULATED (#2387 / #7160)

The FIB route model above is table-scoped for route + local-delivery
*selection*. Session/flow *identity* is table-scoped to match, in two
phases. **Both have landed.** Phase 1 (PR #8098) put the field on the key;
phase 2 populates it, which is what actually closes the cross-tenant
forward-direction collision.

- **`SessionKey` carries a `routing_domain: u32`** (`session/key.rs`,
  #7160). `0` is the default routing instance, so every deployment with no
  routing-instance interface membership keeps byte-identical session
  identity.
- **It is stamped from the LOGICAL ingress interface**, at one site — the
  poll path's stage 9b, immediately after fabric-ingress classification
  (`poll_descriptor/mod.rs`, `forwarding::ingress_routing_domain`). Every
  key the descriptor derives (lookup key, installed forward key, reverse
  companion, index entries) therefore carries one consistent domain. The
  NUMBER is `StableRoutingInstanceTableID(name)` — a pure, collision-gated
  function of the instance NAME — computed in Go
  (`routingInstanceDomain`, `pkg/dataplane/userspace/routes.go`) and shipped
  per interface on the config snapshot, never re-hashed in Rust: both HA
  nodes run the same function over the same config, so the value cannot
  drift between them.
- **Why the ingress interface and nothing else.** The reverse key is built
  by swapping the forward key's fields and never observes the reply, so the
  domain must be a quantity a packet resolves from its own arrival. A PBR
  `then routing-instance` ASSIGNMENT is not one — the reply ingresses on an
  interface the PBR term never touches — so PBR-steered flows on an
  `instance-type forwarding` instance with no member interfaces stay domain
  0 in both directions, and #7924's strict-path rejection of overlap + PBR
  remains what covers that shape.
- **Forward isolation is exact; reverse matching is domain-PREFERRING.**
  The collision #7160 exists to close is a forward-direction one — tenant
  B's packets hitting tenant A's conntrack entry and inheriting its cached
  egress, NAT and **policy** verdict. Forward lookups go through
  `key_to_handle` on the full key, so two tenants now hold two entries.
  The reverse side cannot be keyed the same way: this dataplane's transit
  route lookup is **not** VRF-isolated (see the PBR bullet below), so a flow
  that ingresses on a routing-instance member interface and egresses out of
  the default instance is a real, working configuration whose reply resolves
  a DIFFERENT domain. `reverse_wire_key` / `reverse_canonical_key`
  therefore build the reverse-match index with `routing_domain: 0`, and
  `find_forward_nat_match` walks the (1:N) bucket in two passes — preferring
  a candidate whose forward session carries the reply's own domain, and
  falling back to a domain-agnostic match only when none does. Two
  contained tenants demux exactly; a non-contained flow keeps forwarding as
  it did before the field existed. `forward_wire_key`,
  `translated_session_key` and `reverse_session_key` still PRESERVE the
  domain — they name another key of the same direction, or navigate between
  the two halves of one flow.
- **HA import DERIVES the domain; it is not carried as its own wire field.**
  The domain is a pure function of the flow's ingress interface and the
  config, both nodes run identical config, and #7095 already resolves the
  peer's cluster-stable ingress NAME into this node's own ifindex/vlan
  before the request reaches the helper
  (`Coordinator::synced_routing_domain`). Sending the number as well would
  be a second spelling of one fact that could disagree with the first.
- **An import whose domain cannot be resolved is REFUSED, not defaulted.**
  `synced_routing_domain` returns THREE states, and the third is the point:
  `Some(0)` = the default routing instance (and the only domain on a node
  with no routing-instance membership, so nothing is ever refused there);
  `Some(n)` = a tenant's; `None` = *this node runs routing instances and the
  request named no ingress identity to resolve one from*
  (#7096 fabric-redirected, or no cluster-stable name). The upsert verb
  refuses `None` — `SyncedImportOutcome::RejectedUnknownRoutingDomain`,
  counted by `synced_import_unknown_routing_domain_total` and exported as
  `xpf_userspace_synced_import_unknown_routing_domain_total`. Alert on
  sustained growth: it is the only signal that a VRF cluster is silently not
  taking over a subset of its peer's sessions, and it is always 0 on a
  single-instance node.

  This bullet previously said such a session "imports at domain 0 — the
  pre-#7160 identity … a correctness-preserving degradation, not a bypass".
  **That was wrong, and the error is worth keeping visible.** 0 is not a
  neutral placeholder on a VRF node; it is the DEFAULT ROUTING INSTANCE. An
  import filed there sits at exactly the key the domain-agnostic fallback
  probe in `lookup_shared_forward_nat_match` reaches, so a reply that DID
  resolve its own domain could match a session that was only keyed at 0
  because nothing knew its domain — the HA half of the collision #7160
  closes. The fallback probe is not the defect (it is what keeps a
  non-contained flow's reply resolving); manufacturing wrong domain-0 keys
  on the sync path was.

  The DELETE verb answers `None` the other way, on purpose: it proceeds at
  domain 0 and lets the per-domain sweep run, because a refused delete LEAKS
  a session while an over-broad sweep removes nothing the 5-tuple did not
  already name.
- **Residuals, named.** (a) The Go-side session store is still keyed on the
  bare 5-tuple (`dataplane.SessionKeyV4`), so two tenants' identical
  5-tuples still collide THERE; that bounds HA sync fidelity for such a
  config, and is unchanged by this work. (b) A `clear security flow session`
  delete arrives as a bare 5-tuple with no ingress identity, so the helper
  retries the delete once per configured domain
  (`Coordinator::routing_domains`) rather than missing a VRF session.
  (c) Per-VRF default FIB — the thing that would make the reply direction
  symmetric by construction — is Track B-ext and remains out of scope.
  (d) **#9517: the XDP steering map (`userspace_sessions`) is keyed on a BARE
  5-tuple.** `UserspaceSessionMapKey` (`afxdp/bpf_map/mod.rs`) carries neither
  `routing_domain` nor the GRE `discriminator`, so two sessions the
  authoritative `SessionKey` keeps apart produce byte-identical 40-byte rows —
  measured, with a `src_port` positive control, in
  `bpf_map_tests.rs::steering_key_aliases_routing_domain_and_gre_discriminator_9517`.
  Publish is an identity-blind `BPF_ANY` overwrite and delete is keyed on the
  same bare tuple. #9517 closed the OVERWRITE arm that could flip a sibling
  session's `REDIRECT` row to `PASS_TO_KERNEL`: a node with routing domains no
  longer publishes `PASS_TO_KERNEL` at all, and neither does any session whose
  key carries a tunnel discriminator. The GRE arm needs no routing domains —
  two keyed tunnels between one endpoint pair alias on a single-instance box.
  The DELETE arm is NOT closed (#9560): two aliased sessions still share one
  row, so either one's ordinary teardown removes it, and with an `lo0` input
  filter the survivor's next packet misses, reaches the kernel and skips the
  filter. Closing it needs identity in the key, and the shim cannot compute
  the domain inside the #1864 verifier budget.
- **PBR `then routing-instance` is the ONLY per-VRF forwarding path.** An
  interface's native `routing_instance` selects only the connected-route
  table NAME (#2388 above) — it does NOT scope a transit packet's
  destination-FIB lookup. Only a PBR interface filter's
  `ingress_route_table_override` (`forwarding/mod.rs`, callers in
  `poll_descriptor/mod.rs`) actually steers a transit packet to a per-VRF
  table. In default (non-PBR) mode the destination FIB is the global
  `inet.0`/`inet6.0` and local-delivery uses the global `local_v[46]` sets,
  so overlapping-address multi-VRF does not forward correctly there at all.
- **PBR `routing-instance` + a drop action is a DENY, not a forward (#4392).**
  A term `from { ... } then { routing-instance X; reject | discard; }` carries
  BOTH a routing-instance override AND a terminating drop action. Before #4392
  `ingress_route_table_override` applied the override unconditionally and the
  packet was FORWARDED into VRF X — a VRF leak plus a false audit (the filter
  log recorded a deny while the data plane forwarded). It now returns a
  three-way `RouteOverride { None | Table(<ri>) | Drop }`: a `reject`/`discard`
  action returns `Drop`, so the caller recycles the frame and never
  route-looks-up/forwards. On the flow-backed session-miss path a
  `PbrRejectSink` is supplied, so a `reject` synthesizes the TCP RST /
  ICMP-unreachable reply exactly like a non-PBR `then reject` (and the filter
  log reports the truthful REJECT); a `discard`, and the flowless path (a
  non-first fragment / L3-only packet has no L4 header to reflect), drop
  silently. An accept-only routing-instance term still returns `Table(<ri>)`
  and forwards — normal PBR is unchanged.
- **PBR per-VRF forwarding is still not session-isolated BY THE PBR TERM.**
  The established-session fast path (`resolve_flow_session_decision`) runs
  BEFORE the PBR table override, and #7160 did not change that ordering —
  it changed the identity the fast path looks up. Where the routing
  instances have MEMBER INTERFACES, the ingress-derived `routing_domain`
  now separates the two flows before the fast path can conflate them. Where
  the steering instance is `instance-type forwarding` with no member
  interfaces (the `test/incus/fbf-two-upstream-config.set` shape), both
  directions resolve domain 0 and the identity is unchanged — that shape is
  covered by #7924's strict-path rejection of overlap + PBR, not by the
  key.
- **#3096 NAT-scope-vs-session-cache coherence contract.** #3096 made NAT
  rule *selection* routing-instance-aware at session CREATE
  (`ifindex_to_routing_instance` + `NatScopeCtx`). But the established fast
  path returns the cached hit's decision by the bare 5-tuple WITHOUT
  re-running the scope gate, so a colliding second flow reuses the first
  flow's NAT/policy/forwarding decision — defeating #3096's scoping for that
  flow. The invariant the real fix must restore: **a cached fast-path
  decision is only reused for a flow in the same scope it was admitted
  under.**
- **There are TWO ifindex-less collision surfaces, not one (#9517).** This
  line used to read "The conntrack table is now the SOLE collision surface",
  and that completeness claim was false: the XDP steering map is a second one
  (residual (d) above). It is corrected rather than softened because a
  completeness claim in a module README is how the next reader decides not to
  look — which is how the steering map was missed. The flow cache used to
  alias too; it is keyed on the LOGICAL (VLAN unit) ingress ifindex since
  `42bc6bc88`, so two units of one parent no longer share a cache entry. What
  remains are the ifindex-less conntrack table and the bare-5-tuple XDP
  steering map.
- **Interim mitigation + candidate real fix (UNDECIDED).** The Go compiler
  emits a commit WARNING (`validateVRFOverlap`, `pkg/config`) when two
  distinct routing-instances carry overlapping L3 address space, so the
  operator is told the topology is not session-isolated. Plain overlap still
  COMMITS — an overlapping-subnet PBR VRF is a legitimate working design —
  but since **#7924** the narrow COMBINATION of overlap *and* a PBR `then
  routing-instance` term is a strict-path **rejection**, because that
  combination is the one the dataplane cannot forward correctly.

  The strict rejection is not the whole story, and the residual is what
  **#7991** surfaces. The tolerant load / peer-sync path
  (`lenientVRFOverlapPBR`, #1960 no-brick) still admits the combination — a
  config persisted before #7924 and loaded at upgrade, or one arriving from a
  peer — so the condition is live on exactly the boxes that upgrade INTO the
  fix. `config.TolerantVRFOverlapAdmissions` + the
  `xpf_vrf_overlap_pbr_admitted{instance_a,instance_b,prefix}` gauge make that
  state observable rather than a log line on apply, mirroring what #3718 does
  for the structurally identical host-inbound case. Alert with
  `max_over_time(xpf_vrf_overlap_pbr_admitted[1h]) > 0`; the reporter shares
  the commit gate's detector, so the metric and the advisory can never describe
  different detections. If #7160's Option B lands, the metric goes to zero and
  stays there, which is itself the confirmation.

  The warning states the limitation and points at #2387. Track B is no
  longer a candidate — it is decided and shipped (#7160 phases 1 and 2), and
  the discriminator is the routing-domain id exactly as the plan required:
  config-derived, never a kernel ifindex (#6928 declined to sync one for the
  reason that a node-local number names a different NIC on the peer), and
  never zone or ingress-ifindex on the key. What #7160 did NOT do is make
  the reply direction symmetric by construction; that is per-VRF default FIB
  (Track B-ext) and stays out of scope.
- **The HA session-sync wire does NOT need a version bump**, and #7160
  phase 2 did not take one (corrected in plan v5 §0a; the plan's own §4d
  said otherwise, and #7160's issue text quotes §4d). Two independent
  reasons, and the second is the one that shipped:
  - the domain never had to live in the fixed-width wire KEY block. It
    could ride as a length-gated trailing **value** field, exactly like
    #2170 `Generation`, #3301 `AppTimeout`/`PolicyCounterIdx`, #4565
    `Nat64SnatV4`, #5274 `ConfigEpoch` and #5212 `RTFlowSessionID`
    (`pkg/cluster/sync_protocol.go`; the `SessionSyncRequest`
    control-socket struct is all `#[serde(default)]`), with the receiver
    folding it into the key it reconstructs.
  - it does not ride at all. The importing node DERIVES it from the
    cluster-stable ingress identity #7095 already carries and already
    resolves to a LOCAL ifindex, so there is no new field to keep in sync
    and no mixed-version window to reason about.
  Interning **domain 0 = the default routing-instance** is what makes both
  safe: an absent or unresolvable ingress identity decodes to the default
  VRF, a non-VRF cluster is bit-identical either way, and
  `CurrentHAProtocolVersion` never moves.
- **The trailing-value shape has since been USED, by #7188** — by the GRE
  tunnel discriminator, which took the route the domain considered and
  declined. It rides as `SessionValue{,V6}.TunnelDiscriminator` on the cluster
  wire (after the #7095 `IngressIfaceFold`),
  `SessionSyncRequest.tunnel_discriminator` to the peer helper, and a trailing
  u64 on both binary HA delta frames; the receiver folds it into the key it
  reconstructs. No `CurrentHAProtocolVersion` bump, as the bullet above says
  there need not be.

  The two identity axes are carried by OPPOSITE mechanisms, and the reason is
  worth stating because it is not a preference. The routing domain is
  DERIVABLE on the importing node — #7095 already carries a cluster-stable
  ingress identity and already resolves it locally — so #7160 derives it and
  ships no field. An RFC 2890 Key is not derivable from anything the peer
  sends: it lives in the GRE header of a packet only the ORIGINATING node saw.
  It has to ride, or it is lost.

  That forces a distinction the derived axis never needs: **`0` must be
  RESERVED for "the peer did not carry this field", separate from the field's
  own zero-value class.** `serde(default)` and a short record both yield `0`,
  so `0` is the one value a peer emits without meaning to; if it also spells a
  real class, a peer that cannot express the identity is indistinguishable from
  one that deliberately said "default", and #7188 must tell those apart to
  WITHHOLD a protocol-47 session from a peer that predates the field rather
  than importing it aliased. Interning "domain 0 = the default
  routing-instance" spends exactly that distinction — which costs #7160
  nothing, because an unresolvable ingress identity and a legacy session are
  both genuinely in the default instance, whereas for a tunnel key they are
  not the same statement at all. Full write-up:
  `docs/session-sync-architecture.md`, "Tunnel Session-Identity Discriminator".
- **Do NOT "decline the hit and fall through"** as a cheap mitigation.
  `install_with_protocol_with_origin` opens with an unconditional
  `remove_entry(&key)` (`session/install.rs`), so the session-miss path
  would re-install under the same bare 5-tuple and evict the incumbent
  VRF's session — the two flows then evict each other per packet
  (per-packet SNAT re-allocation breaks both). The only coherent
  end-states are a fail-closed DROP or a widened identity.
- Decision record: `docs/research/2387-vrf-flow-identity/plan.md` (read §0
  first — it supersedes §4d and narrows the open call).

## Where it sits

- Reads the live snapshot Arcs (FIB, NAT, neighbor table) supplied
  by `worker_loop`.
- Output (`ForwardingResolution`) is consumed by the TX path
  (`tx/dispatch.rs`, `tx/transmit.rs`) to pick the egress binding
  and encode the L2 header.
- Has no cross-binding back-edges — the per-worker hot path stays
  on its own UMEM.

## Host-inbound-traffic enforcement (#3070)

`security zones <z> host-inbound-traffic { system-services ...; protocols
...; }` controls which host-bound services are admitted to a firewall-local
interface IP (SSH, ping, routing protocols on the box itself).

**Two enforcement layers — kernel is primary, this userspace check is the
secondary edge-case path.** Ordinary host-bound traffic to an interface IP /
VRRP VIP is shunted to the LINUX KERNEL by the XDP shim
(`is_local_destination` → `cpumap_or_pass`/`PASS_TO_KERNEL` in
`userspace-xdp/src/lib.rs`) BEFORE it reaches userspace-dp, so the
authoritative host-inbound enforcement for those packets lives in the kernel
`chain input` (table `inet xpf_hostinbound`, built in
`pkg/daemon/daemon_nft.go` from `userspace.BuildZoneHostInboundViews`,
mirroring the lo0-filter precedent). The userspace LocalDelivery check below
covers only the subset that actually reaches the XSK — DNAT-to-self,
static-NAT to a firewall service, embedded-ICMP, DNS edge cases. **Both layers
share the same per-zone token set; keep the Go nft token→match mapping
(`hostInboundServiceMatches`/`hostInboundProtocolMatches`) in sync with the
Rust classifier here.**

**The gate judges the POST-translation tuple (#9529).** Most traffic that reaches
this secondary path is host-bound only BECAUSE of a destination translation
(DNAT-to-self, static NAT to a firewall service), so which tuple it is judged on
decides the verdict. The service gate's port and `to-zone junos-host` policy's
address and port are the post-translation ones (`host_bound_policy_dst` in
`poll_descriptor/host_inbound_policy.rs`): the tuple the local listener actually
receives, and the one transit policy already judges (#2345). Judging the wire tuple
let a fine deny written on the firewall address or on the translated port match
nothing, and the kernel cannot catch that miss, because its fine DROP rules are
`iifname`-scoped to the zone's physical netdevs and the reinject arrives on the
slow-path TUN. Some things stay on the WIRE tuple on purpose: the `lo0` filter
(Junos filters are pre-NAT), and the reject reply and deny record, because the
client is addressing the pre-translation tuple. A translation that changes address
family (NAT64) keeps the wire address.

**ident-reset (#3310).** `system-services ident-reset` is special-cased: Junos
does NOT permit the ident (auth/TCP-113) service, it actively RESETS inbound
ident probes. On the PRIMARY (kernel) path the nft chain emits
`tcp dport 113 reject with tcp reset` so the kernel synthesizes an RFC-correct
RST — 113 is never opened to the host. On THIS secondary AF_XDP path the
`ident-reset` classifier arm is a deliberate NO-OP: it contributes nothing to
the admit set, so `admits()` returns false for TCP/113 and the rare
AF_XDP-reached ident packet (DNAT/static-NAT-to-113 — an edge of an edge) is
DROPPED rather than reset. This is a documented divergence from the kernel
reset; both layers stop the prior plain-admit of 113. `any-service` precedence
still wins (a fully-open zone admits 113); `system-services all` does not,
since #3226 scoped it to the named union and ident is not in it. The token set stays in
sync (ident-reset remains a recognized token on both layers); only the
secondary-path action diverges (drop vs reset).

The set is parsed and modeled in Go
(`config.ZoneConfig.HostInboundTraffic`) and crosses the snapshot boundary on
`ZoneSnapshot`
(`host_inbound_configured` + the raw `host_inbound_system_services` /
`host_inbound_protocols` token slices — JSON keys byte-identical on both
sides per #1961). `forwarding_build::zones::populate_zones` classifies the
tokens into a `ZoneHostInbound` (`host_inbound.rs`) keyed by the same
validated zone id and stores it in `ForwardingState::zone_host_inbound`.

**Per-interface override (#3362).** Junos also models `host-inbound-traffic`
at the INTERFACE level (`security zones <z> interfaces <if>
host-inbound-traffic { ... }`); the effective admission set for an interface is
its interface-level stanza when it declares one, which REPLACES the zone-level
set (#6515), otherwise the zone-level set. The Go
control plane computes that effective set and carries it on
`InterfaceSnapshot` (`host_inbound_configured` +
`host_inbound_system_services` / `host_inbound_protocols`), populated only for
an interface that declared an interface-level stanza and is not a
management/cluster-control lifeline. `forwarding_build::interfaces`
classifies it into `ForwardingState::ifindex_host_inbound`, keyed by the
interface's own **LOGICAL** unit ifindex (`iface.ifindex`). The local-delivery
admit path calls `host_inbound_admits_iface`, which prefers the per-INTERFACE
set when the ingress ifindex has one and otherwise falls back to the
zone-keyed `host_inbound_admits` — so a service exposed on one interface of a
zone is admitted there while the zone-default set (possibly empty →
fail-closed deny-all) governs the zone's other interfaces.

**Logical-ifindex keying on the poll path (#3609).** Because the override map
is keyed by the logical unit ifindex, the local-delivery gate MUST look it up
with the resolved logical ingress ifindex — NOT the raw physical bind port in
`meta.ingress_ifindex`. For a frame on a VLAN sub-interface (e.g.
`reth1.100`), `meta.ingress_ifindex` is the parent port and
`meta.ingress_vlan_id` selects the unit; the caller resolves `(parent, vlan) →
logical` once via `resolve_ingress_logical_ifindex` (untagged ports resolve
physical == logical) and threads it into `host_inbound_gated_lo0_action`, which
forwards it to `host_inbound_admits_iface`. This mirrors the sibling
input-filter, zone-pair (#3021), screen (#3022), and CoS (#3026) sites — every
per-ingress map keyed by the logical unit resolves first. Before #3609 the gate
passed the raw physical ifindex, so a VLAN sub-interface's override was missed
and it silently fell back to the zone set (over-/under-permitting the control
plane). A zone enforcing host-inbound ONLY via an interface override is
still marked `host_inbound_configured` on its `ZoneSnapshot` (with an empty
zone-keyed set), so a non-overridden interface in that zone fail-closes —
matching the kernel-nft primary path, where `BuildZoneHostInboundViews` emits
one address-scoped view per distinct effective token set (the overridden
interface's addresses accept its services; the others get a catch-all drop).

Enforcement runs on the **local-delivery admit path only** (transit
traffic never pays for it), at BOTH sites in `poll_descriptor`:

- **session miss** — a host-bound packet whose service/protocol is not in
  the ingress zone's set is dropped and never cached.
- **session hit** — re-checked every packet (mirroring the lo0-filter
  re-check) so a tightened host-inbound config tears down an
  already-established host-bound session WITHOUT an explicit purge.

**Ordering: host-inbound gates the lo0 filter (#3485).** Both sites route
the host-inbound check and the lo0 (host-bound) firewall filter through one
helper, `poll_descriptor::filter::host_inbound_gated_lo0_action`, which runs
the host-inbound gate FIRST. A packet the gate denies is a silent fail-closed
drop with NO lo0 side-effects — no synthesized TCP RST / ICMP-unreachable
reject reply, no lo0 term counter bump, no lo0 filter log, and (session-hit)
no host-bound session teardown attributed to the filter. Only an ADMITTED
packet pays the lo0 evaluation. Before #3485 (codex-review-118 M1)
`apply_lo0_filter_action` ran first, so a service host-inbound would have
silently denied still triggered the lo0 reject/RST/teardown/counter/log. The
`junos-host` security policy (#3019) still runs AFTER host-inbound admission
(Junos order); the net local-delivery order is host-inbound → lo0 → junos-host.

`host_inbound_admits` **denies by default** for every configured security zone
(#3405 — Junos/vSRX parity). A zone with **no** `host-inbound-traffic` stanza is
treated as an empty stanza: the Go control plane marks it
`host_inbound_configured`, so it enters `zone_host_inbound` with an empty
admission set and `admits()` returns deny for every service/protocol not
explicitly permitted. Before #3405 a no-stanza zone was absent from the map and
`host_inbound_admits` returned admit (`None => true`) — a permit-all
management-plane exposure on any zone the operator never locked down.

**Fail-closed for a nil / configured=false known zone (#3705).**
`forwarding_build::zones::populate_zones` inserts a `ZoneHostInbound` for
**every KNOWN zone** — a zone present in the snapshot with a valid, addressable
id — regardless of `host_inbound_configured`. The insert is deliberately NOT
gated on that flag: a KNOWN zone whose snapshot carries
`host_inbound_configured == false` — the tolerant / HA nil-zone shape
(`Security.Zones[name] == nil` ships a valid name+id but configured=false;
#3493), or an old pre-#3405 Go control plane that omits the field — would
otherwise be left absent from the table and hit the `None => true` admit-all
arm, making that known configured zone admit ALL host-bound traffic (reopening
#3405 on the nil-object shape). A configured=false zone carries empty token
vecs, so it inserts an empty `ZoneHostInbound` → default-DENY, identical to a
no-stanza zone. The Go builder also ships configured=true for a nil zone
(`buildZoneSnapshots`); this insert is the dataplane fail-closed backstop for a
mismatched-version control plane. `host_inbound_configured` therefore now
selects only WHICH tokens a zone admits, never WHETHER it is enforced.

Consequently `None`
now means only a genuinely unknown / global ingress zone (id not in the table),
which keeps the admit default. The global ICMP/ND/PMTUD accepts precede the
per-zone deny, and lifeline interfaces (`fxp*`/`em*`/`fab*`/`lo0`) never reach this AF_XDP
classifier (the kernel serves their host-bound traffic and excludes them from
the deny address sets), so the default-deny cannot strand management or break
HA.

**Empty-zone addressed-interface backstop (#5659).** The #2391 zone-id backstop
in `forwarding_build::interfaces::populate_interfaces` (fail-closed on a
NON-EMPTY unknown zone name) is guarded by `!iface.zone.is_empty()`, so an
ADDRESSED interface with an EMPTY `security-zone` string is skipped: it gets no
`ifindex_to_zone_id` entry and resolves to the global `zone_id 0`, while its IP
is STILL registered into `local_v4`/`local_v6` as a local-delivery target. On
its own that would let `host_inbound_admits(0)` hit the `None => true`
global-zone admit arm and admit every host-bound service (SSH/NETCONF/BGP/SNMP)
on that interface — an asymmetry vs the #2391/#3405 fail-closed posture. To
restore symmetry, `populate_interfaces` inserts an EMPTY `ZoneHostInbound`
sentinel into `ifindex_host_inbound` keyed by that interface's logical ifindex,
so the ingress-interface-keyed `host_inbound_admits_iface` DENIES host-bound
services there. The insert is scoped to an interface that (a) is unzoned, (b)
actually registered a `local_v4`/`local_v6` target, (c) has no explicit
per-interface `host_inbound_configured` override (never clobber the operator's
set), and (d) is not a lifeline (`fxp*`/`em*`/`fab*` prefixes plus `lo0`, matched
by base name to mirror the authoritative Go SSOT `userspaceSkipsIngressInterface`
— never arm a deny on a management/HA/loopback link; the earlier `fxp0`/`em0`-only
form was narrower than the SSOT and would have stranded an unzoned-addressed `lo0`
router-id/BGP-`update-source` loopback in the exact future case this backstop
hardens). Keying by ifindex — rather than inserting
`zone_host_inbound[0]` — deliberately leaves the genuinely-global `zone_id 0`
path untouched, so a legitimately-zoneless NON-addressed control interface keeps
its admit default and the global ICMP/ND/PMTUD accepts (checked before the set)
still deliver control traffic. Reachability today is bind-gated
(`buildUserspaceBindNetdevs` skips a zoneless interface), so this is a
fail-closed-SYMMETRY / defense-in-depth hardening: it closes the asymmetry so a
future change that binds a zoneless-addressed interface (or a quarantine path,
#3719, that keeps an interface bound while stripping its zone) cannot silently
become a host-inbound bypass.

Token
classification covers the common Junos `system-services` (ssh, ping, dns,
dhcp/dhcpv6, ike, ntp, snmp, ...) and `protocols` (ospf, bgp,
router-discovery, ...) names; `any-service` short-circuits to a full admit
(`system-services all` does NOT — #3226 narrowed it to the named service
union, so it classifies token-by-token); an unrecognised token contributes nothing
(fail-closed). ICMP-based services admit only the specific ICMP **sub-types**
they imply (#3201/#3240), matching the nft chain exactly — see "ICMP admission
is sub-type specific" below.

**Service/protocol matches are address-family aware (#3225).** Several Junos
host-inbound tokens are family-SPECIFIC in intent: `system-services dhcp` is
DHCPv4 (udp 67/68 over IPv4) while `dhcpv6` is DHCPv6 (udp 546/547 over IPv6);
`protocols rip` is RIPv2 (IPv4) and `ripng` is RIPng (IPv6); `protocols ospf` is
OSPFv2 (IPv4) and `ospf3` is OSPFv3 (IPv6) — both ride IP protocol 89 but on
different families; `igmp` is IPv4 group membership (the IPv6 equivalent is MLD,
carried over ICMPv6 / the always-accepted ND set). Before #3225 both enforcement
layers compiled these into family-NEUTRAL matches, so a v4-only `dhcp` opened
udp/67-68 on the IPv6 path and `ripng` opened udp/521 on IPv4 — wrong-family host
exposure. `ZoneHostInbound` now carries family-scoped sets (`udp_ports_v4` /
`udp_ports_v6`, `ip_protocols_v4` / `ip_protocols_v6`) alongside the dual-family
`udp_ports` / `ip_protocols`; `admits(protocol, port, is_v6)` consults the
dual-family set OR the set matching the packet's family. The single source of
truth for a token's family is `config.HostInboundServiceFamily` /
`config.HostInboundProtocolFamily` (Go side): the nft kernel mirror gates
`hostInboundServiceMatches` / `hostInboundProtocolMatches` on it directly, and
the Rust classifier mirrors the same families into the scoped sets — so both
layers agree exactly. Dual-family services (ssh/https/ping/dns/bgp/...) are
absent from the maps and admit on both families as before. `protocols all`
expands to the routing set INCLUDING both `ospf` and `ospf3`, so it admits proto
89 on each family (and rip on v4, ripng on v6).

**ICMP admission is sub-type specific (#3201/#3240).** A host-inbound service
admits only the ICMP **types** it implies, mirroring the nft chain's named-type
matches (`pkg/daemon/daemon_nft.go`) rather than opening the whole ICMP/ICMPv6
L4 protocol. `ZoneHostInbound` carries per-family type sets `icmp_types_v4` /
`icmp_types_v6`, and `admits(protocol, port, is_v6, icmp_type)` checks membership
for protocol 1 / 58:

- `ping` → echo-request only (v4 type 8 / v6 type 128) — nft `icmp/icmpv6 type
  echo-request`. A ping zone NO LONGER admits redirect / timestamp /
  router-advertisement.
- `router-discovery` → IPv4 router-advertisement (9) + router-solicitation (10)
  only — nft `icmp type { 9, 10 }`. On v6 it contributes NOTHING per-zone: v6
  RS/RA ride the global ND accept (below), exactly as the nft chain returns nil
  for v6 router-discovery and relies on the global ND accept (#3240).

Before #3201 both `ping` and `router-discovery` set a protocol-wide `icmp` /
`icmpv6` bit, so the AF_XDP fast path admitted ANY ICMP type the nft chain would
drop (a ping zone admitted router-advertisement / timestamp; a router-discovery
zone admitted echo). The per-zone Rust admit set now equals the nft chain's
per-service type set.

**ICMP error / PMTUD + IPv6 ND are always admitted (#3171/#3201).** Before the
per-zone lookup, `host_inbound_admits` exempts a global ICMP set
(`is_icmp_host_inbound_global_accept`) regardless of which services the ingress
zone lists, mirroring the kernel `chain input` global accepts
(`pkg/daemon/daemon_nft.go`):

- ICMPv4 *error* subtypes — destination-unreachable (3) / time-exceeded (11) /
  parameter-problem (12) — so PMTUD / unreachable / traceroute-to-self landing
  on the XSK LocalDelivery path is not fail-toward-dropped on a ping-less zone.
- ICMPv6 *error* (1/2/3/4) PLUS the **Neighbor Discovery** set (133 RS, 134 RA,
  135 NS, 136 NA, 137 Redirect). ND is core L3 operation accepted globally by
  the nft chain; admitting it here is what lets per-zone `router-discovery` carry
  nothing on v6 while still matching nft.

ECHO-REQUEST (v4 8 / v6 128) and IPv4 router-advert/solicit (9/10) are **not** in
the global set — they stay gated on the `ping` / `router-discovery` tokens, so a
zone that omits them still drops those types. Keep
`is_icmp_host_inbound_global_accept` in lock-step with the kernel chain's
`icmp`/`icmpv6` global accept lines.

**`protocols all` is scoped, NOT a blanket bypass (#3199).** In Junos
`host-inbound-traffic protocols all` admits every supported ROUTING protocol
(the entries under the `protocols` stanza) — it is NOT `system-services all`
and NOT a blanket accept. The classifier expands the `all` token to the
concrete routing-protocol set via `routing_protocol_all_expansion()`
(`KNOWN_ROUTING_PROTOCOL_TOKENS`:
ospf/ospf3/bgp/rip/ripng/igmp/pim/vrrp/bfd/ldp/msdp/nhrp/router-discovery,
each family-scoped per #3225) instead
of setting a short-circuit flag, so a `protocols all` zone admits routing
protocols but still DENIES SSH/HTTPS/SNMP/NETCONF unless the matching
`system-services` token is also present.

**L2/non-IP protocols are excluded from the `all` expansion (#3311).** IS-IS
rides OSI/CLNP directly over L2 (LLC, not IP) and cannot be expressed as an IP
host-inbound match, so it is a recognized-but-no-op token. The `all` expansion
filters out `HOST_INBOUND_L2_PROTOCOLS` (the Rust mirror of the Go SSOT
`config.HostInboundL2Protocols`), so adding a new L2 protocol to that set is the
only edit needed to keep it out of the IP expansion on both surfaces. The Go nft
mirror (`hostInboundProtocolMatches("all", ...)` over
`config.HostInboundAllExpansionProtocols()`) derives the same exclusion and
still emits the per-zone catch-all drop, so the kernel and userspace decisions
stay consistent.

## `junos-host` self-traffic security policy (#3019)

Host-bound (LocalDelivery) traffic is also subject to the Junos
`from-zone <z> to-zone junos-host` security policy. Junos order is
**host-inbound admission FIRST, then security policy** — so the
`junos_host_local_policy` gate runs immediately AFTER `host_inbound_admits`
at BOTH local-delivery sites in `poll_descriptor` (session miss and session
hit). A packet host-inbound already rejected never reaches policy, so a
`to-zone junos-host then permit` cannot re-admit it.

**Permit metadata propagation (#3706).** `junos_host_local_policy` returns a
`JunosHostLocalPolicy` verdict — `Dropped` (deny/reject), `Permit(result)`, or
`NoMatch`. On a matching PERMIT the session-MISS install stamps the admitting
policy's `then log session-init`/`session-close` selection, its `policy_id`, and
its per-rule hit-counter handle onto the installed host-local session (and the
published conntrack row) — exactly like a transit permit, so a
`to-zone junos-host then permit log session-init session-close` session emits the
RT_FLOW SESSION_CREATE/CLOSE records and is attributable to the admitting policy.
Before #3706 the gate collapsed to a bare `bool` and discarded the permit result,
so host-bound permit sessions installed with both log flags off, `policy_id` 0,
and no counter handle (unlogged + unattributable). The session-HIT path only
needs the `Dropped` verdict (the session is already installed with the miss-time
permit metadata); the flowless (`l4_present = false`) arm never installs a
session, so a flowless permit simply delivers with no metadata to carry.
`NoMatch` keeps the default no-policy host-local metadata (log off, `policy_id`
0, no counter) — the historical host-local behavior for a genuinely
unattributed local session.

**Exactly-once hit counting (#3706).** The LocalDelivery session-HIT path
re-evaluates the junos-host policy on every packet (the mandatory teardown
re-check), and that re-eval's `try_match_rule` counts the packet against the
admitting rule's hit counter — as it did pre-#3706, when a host-local session
carried no bound counter and the generic session-hit
`record_policy_hit_counter` was a no-op (`resolve_session_hit_counter(None, 0)`
→ `None`). Because #3706 now stamps a bound counter onto a junos-host permit
session, the generic session-hit counter site would count a SECOND time, so
`poll_descriptor` skips it for `LocalDelivery` (the `!= LocalDelivery` guard) and
lets the per-hit junos-host re-eval be the single counter. Transit has no per-hit
re-eval and counts solely at the generic site, so both paths count exactly once
(the bound counter is still stamped for close-time `policy_id` re-resolution and
HA sync). The first (miss) packet counts once via the session-MISS junos-host
gate's `try_match_rule`.

`policy::evaluate_junos_host_policy` resolves the reserved `junos-host` zone
name to `JUNOS_HOST_ZONE_ID` (`u16::MAX-1`, the bottom of the reserved range,
never on the wire because zone ids are u8) and looks up the
`(ingress_zone_id, JUNOS_HOST_ZONE_ID)` zone pair in the SAME `zone_pair_index`
as transit rules — `parse_policy_state_with_counters` now INDEXES junos-host rules
via `resolve_policy_zone_id` (pre-#3019 they were kept-but-not-indexed, like the
wildcard-`any` case). A matched deny/reject drops the packet, emits the
policy-deny RT_FLOW (egress zone reported as `0`/host since the synthetic id
does not fit the u8 wire slot), synthesizes a `reject`/zone-`tcp-rst` reply, and
on the hit path tears down the cached host-local session.

Enforcement is MATCH-DRIVEN and fail-safe: the gate is a NO-OP unless
`PolicyState::has_junos_host_rules` is set (some junos-host rule configured),
and a no-match falls through to today's behavior (local delivery proceeds).
There is NO implicit junos-host default-deny — the deliberate lifeline
guarantee that configuring junos-host policy can never silently brick
management/host traffic. `from-zone junos-host` (host-ORIGINATED) rules are
indexed but not consulted here (locally-generated traffic does not traverse
this ingress path) — a documented follow-up.

## Host-terminated IPsec passthrough

`is_ipsec_traffic(protocol, dst_port)` recognizes packets destined for
the local kernel XFRM stack so the IPsec passthrough stage
(`poll_stages::stage_ipsec_passthrough_check`) reinjects them via the
slow-path TUN device instead of running them through ordinary transit
forwarding. The recognized set is:

- ESP — protocol 50 (`PROTO_ESP`)
- AH — protocol 51 (`PROTO_AH`)
- IKE / NAT-T — UDP destination port 500 or 4500

ESP and AH carry no transport port, so only the protocol-number arm
applies to them. The predicate keys solely on `meta.protocol` and is
therefore family-symmetric in form — but `meta.protocol == PROTO_AH`
(51) only ever occurs for **IPv4 AH**. The XDP shim's IPv6 parser
treats AH as an extension header and walks THROUGH it (the
`NEXTHDR_AUTH` arm in `userspace-xdp/src/lib.rs`), setting
`meta.protocol` to AH's inner next-header rather than 51. So the AH arm
is a **v4-only backstop**; it never fires for IPv6 AH. ESP (proto 50)
is parsed as a terminal protocol on both families, so ESP is recognized
for v4 and v6 alike.

This is not a functional gap. IPv6 host-terminated AH-to-self still
reaches the kernel XFRM stack via the shim's `is_local_destination`
shunt, which fires for any local-destination packet *before* the
userspace dataplane runs this predicate; transit AH (v4 or v6) takes
ordinary forwarding. AH was omitted entirely before #2385, which
silently broke host-terminated **IPv4** AH SAs (configurable via
`set security ipsec proposal ... protocol ah`); the AH arm is
regression-guarded in `tests.rs`. Giving this predicate true IPv6 AH
coverage would require the shim to surface an "AH present" signal
instead of walking past the header — out of scope here, and
unnecessary given the local-dest shunt.

### Host-inbound ordering: ESP/AH exempt, IKE gated on a live exchange (#3616 Option A + #4323 Option B + #6471)

Stage 11 runs BEFORE the per-zone host-inbound admission gate
(`host_inbound_admits_iface`) and, on a match, short-circuits the poll
loop (`Passthrough`/`Denied`), so a packet it claims never reaches the
later local-delivery gate. Within Stage 11 the admission split is by
class (`classify_ipsec_admission`):

- **ESP (50) / AH (51) and the IPsec data plane are unconditionally
  EXEMPT** — always passed through (`Passthrough`), regardless of the
  zone's `host-inbound-traffic system-services ike`/`ipsec`. The
  negotiated SA is the authorization (Junos parity), mirroring the
  kernel chain's global `meta l4proto { 50, 51 } accept`. ESP-in-UDP on
  4500 (a non-zero ESP SPI in the first payload word) and the 1-byte
  NAT-T keepalive are demuxed as data plane and stay exempt too.
- **A NEW inbound IKE initiation is GATED (#4323 Option B).** The FIRST
  packet of a new IKE exchange — an ISAKMP header whose **Responder
  SPI/cookie is all-zero** (IKEv2 IKE_SA_INIT request / IKEv1 Main- or
  Aggressive-mode first message; on UDP 4500 the ISAKMP follows the RFC
  3948 4-byte non-ESP marker) — is admitted only if the resolved ingress
  zone lists `ike`/`ipsec`. A zone that omits the token DROPS it
  (`Denied`, silent, `host_inbound_denied_packets` accounted +
  `RT_FLOW_CLOSE_REASON_HOST_INBOUND` event) so an unsolicited inbound
  IKE never reaches the local IKE daemon (strongSwan). An ADMITTED
  initiation SEEDS the shared live-exchange table
  (`IkeExchangeTable`, #6471) — a denied initiation never seeds.
- **A Responder-SPI-nonzero IKE packet is admitted ONLY with a matching
  live-exchange seed (#6471).** The SPI bytes are attacker-controlled, so
  a non-zero Responder SPI alone does NOT prove "established" — a forged
  one otherwise rode the #4323 `Exempt` class straight to strongSwan on a
  zone the operator closed to IKE (the pre-#6471 residual, now closed).
  The seed table plays the conntrack role the secondary path lacks (it
  installs no session for a passthrough flow): seeded inbound on an
  admitted initiation, seeded outbound in the native-GRE local-origin
  path when the firewall initiates IKE through a tunnel (the peer's
  replies arrive GRE-inner on Stage 11 with the Responder SPI set and no
  inbound seed), matched (and sliding-window refreshed) per packet on the
  (Initiator SPI, peer/local address pair) key — ports deliberately
  excluded so an RFC 5996 NAT-T float does not strand the seed. A
  Responder-SPI-nonzero packet matching NOTHING faces the SAME
  host-inbound gate as a NEW initiation: denied on a zone omitting `ike`,
  admitted on a zone listing `ike` (config-sanctioned openness —
  primary-path parity, since the kernel chain also admits NEW IKE there).
  Bounded: 4096-entry cap (least-recently-touched evicted on full) + 24h
  sliding idle reap; NOT HA-synced (the primary path's kernel conntrack
  for host-terminated IKE is not synced either — same failover posture);
  an xpfd restart drops the seeds, which self-heal on the next admitted
  initiation or firewall-outbound IKE packet, with the ESP data plane
  exempt throughout.
- **Eviction is O(1) (#6747).** The victim used to be found with
  `entries.iter().min_by_key(seen)` — a full traversal of all 4096
  entries plus the empty hashbrown slots, under a lock `matches` takes on
  the hot admission path for every Responder-SPI IKE packet, on a table
  `Arc`-shared by every packet worker. One worker's scan stalled the
  others. The scan was reachable exactly when 4096 DISTINCT live
  exchanges were resident, which is also precisely the state a forged-
  initiation flood produces — the worst case and the attack case are the
  same case, so an "amortised reap of the idle ones first" would not have
  helped (under a flood every entry is fresh). The table is now an
  intrusive LRU over a fixed slab: `matches`/`seed` re-append at the
  tail, eviction pops the head. **Semantics are unchanged** —
  `min_by_key(seen)` with `matches` refreshing `seen` already WAS LRU,
  just computed by scanning — so the availability reasoning above holds
  verbatim. FIFO was rejected: it removes the scan just as well but would
  evict a long-lived exchange that DPD refreshes in favour of a brand-new
  forged initiation, which is worse under the flood the cap exists for
  (`exchange_eviction_is_recency_not_insertion_order_6747`). The
  previously unobservable eviction condition now has a counter
  (`IkeExchangeTable::evictions`).

**Two enforcement paths.** The PRIMARY host-inbound enforcement for
IPsec-to-self is the kernel nftables chain (`pkg/daemon/daemon_nft.go`).
The XDP shim shunts direct local-destination IPsec to the kernel BEFORE
userspace-dp sees it — raw outer ESP is shunted unconditionally
(`userspace-xdp/src/lib.rs`), and IKE/AH to a local address ride the
`is_local_destination` shunt. That chain accepts raw ESP/AH globally,
gates NEW inbound IKE on `system-services ike`/`ipsec`, and lets
established/return IKE ride `ct established,related accept` first.
`TestHostInboundFilterExemptsIPsecAndV6Errors` guards that ordering. The
SECONDARY AF_XDP path (Stage 11) is reached only when IPsec is NOT
shunted to the kernel: DNAT/static-NAT-to-self IKE, native-GRE inner
IPsec whose inner destination is a firewall-local address (redirected to
the XSK and decapped in userspace), and transit/NAT IPv4 AH and IKE
(UDP 500/4500) that the shim steered to the helper. The #4323 gate
closes the NEW-inbound-IKE host-inbound parity gap on this path, and the
#6471 live-exchange discriminator closes the residual established-parity
gap (a forged non-zero Responder SPI can no longer mint "established"
the way kernel conntrack NEW/ESTABLISHED cannot be faked on the primary
path).

### #5620: the passthrough claim is scoped to a firewall-local destination

Stage 11 claims the kernel-XFRM passthrough short-circuit ONLY when the
packet's destination is an address the firewall itself answers for
(`ForwardingState::owns_configured_ip(flow.dst_ip)` — the configured
interface IPs incl. the SNAT/WAN IP and VIPs, PLUS the static-NAT/DNAT
externals appended to `local_v*`). Before #5620 the stage claimed ANY
ESP/AH/IKE packet the shim steered to the helper regardless of
destination, so a TRANSIT UDP/500, UDP/4500 or IPv4 AH packet routed to
a remote host was reinjected to the local XFRM stack and SKIPPED transit
zone-policy enforcement (codex-review-181 M03; raw outer ESP was never
affected because the shim shunts it to the kernel unconditionally, so
only the shim-steered UDP-IKE and IPv4-AH transit classes were
reachable).

Stage 11 runs BEFORE NAT resolution (only native-GRE decap precedes it),
so `flow.dst_ip` is the RAW on-the-wire destination. Gating on the raw
dst is nonetheless correct for the DNAT/static-NAT-to-self cases: the NAT
externals are already members of `local_v*` (appended in
`forwarding_build`), so `owns_configured_ip` recognises a DNAT-to-self
external without needing the post-NAT address. GRE-inner-local IPsec is
likewise covered — the decapped inner destination is a firewall
interface address. A remote/transit destination is owned by nobody here,
so the packet returns `NotClaimed` and continues to normal transit
forwarding + zone policy. The predicate runs BEFORE the #4323
host-inbound admission block, which only makes sense for genuinely
host-inbound (local-destined) IKE. Regression-guarded by
`stage_ipsec_passthrough_rejects_remote_transit_dst_5620` (remote dst →
NotClaimed) and `stage_ipsec_passthrough_claims_local_and_nat_to_self_dst_5620`
(local / WAN-IP / DNAT-to-self dst → Passthrough).

**Zone resolution.** The gate resolves the LOGICAL ingress ifindex +
from-zone exactly as the local-delivery resolver does
(`resolve_ingress_logical_ifindex` + `zone_pair_ids_for_flow_with_override`
with the `ingress_zone_override` from fabric-ingress classification), so
a VLAN sub-interface keys its own unit and a per-interface host-inbound
override governs where present — not a raw physical-ifindex zone lookup.

**The synthetic reinject decision keeps `local_ifindex` = 0**
(`ipsec_passthrough_decision`). It MUST: a non-zero `local_ifindex`
makes `maybe_reinject_slow_path_from_frame` route the reinject through
the GRE `local_tunnel_deliveries` channel instead of the generic kernel
TUN injector (`tx/dispatch/slow_path.rs`), mis-delivering IPsec-to-self.
The #4323 gate is a SEPARATE admit check BEFORE the reinject, never a
change to the routing decision's `local_ifindex`. See
`docs/research/3616-ipsec-host-inbound/plan.md` (Option B).
