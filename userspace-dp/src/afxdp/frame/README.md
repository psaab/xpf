# userspace-dp/src/afxdp/frame/

Packet parsing + L3/L4 byte-level mutation + checksum recomputation.
The bottom layer that the rest of the pipeline reaches into to
inspect or rewrite a packet sitting in a UMEM frame.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub + cross-module helpers (`apply_dscp_rewrite_to_frame`, `decode_frame_summary`, `frame_has_tcp_rst`, etc.). |
| `byte_writes.rs` | In-place IP and L4 port rewrites (`write_ipv4_dst`, `write_ipv4_src`, `write_ipv6_dst`, `write_ipv6_src`, `write_l4_dst_port`, `write_l4_src_port`). |
| `checksum.rs` | IPv4 header + L4 checksum incremental adjust + recompute. Owns the `checksum16_*` family, the `ChecksumFamily` enum, and the two zero-checksum predicates (`l4_udp_checksum_optional` — RFC 768 received-0 skip, IPv4 UDP only (#1840); `adjust_zero_checksum_illegal` — computed-0 → 0xFFFF canonicalization, v4 UDP / v6 UDP+ICMPv6 (#1839)). The v6 adjusters/recompute take a caller-supplied `rel_l4` (ext-aware offset, #1838). |
| `inspect.rs` | Read-only parsers / matchers used by screen, policy, conntrack hot paths. |
| `addr_class.rs` | Address classification (#6926) — broadcast / multicast / directed-broadcast / invalid-ICMP-error-source predicates, split out of `inspect.rs` when it crossed the 2000-LOC [REFACTOR] tier. Chosen as the seam because it is the one group in that file with **zero** internal dependencies, so the move carried the whole property rather than scattering it. `inspect.rs` re-exports the six `pub(in crate::afxdp)` names, because the tree reaches them by both a bare `use` and a fully-qualified `frame::inspect::` path. |
| `generated.rs` | #2238: `generated_reply_session_key()` — parse a LOCALLY-GENERATED reply frame (Time Exceeded / policy-reject RST/ICMP-unreachable / SYN-cookie SYN-ACK/ACK-RST) back into its OWN egress `(SessionKey, ForwardPacketMeta)` so the output classifier (`tx::classify_generated_reply`) keys on the reply's real tuple, not the trigger's. Reuses `frame_l3_offset` + the bounded v6 ext-header walk (one wire parser). Cold path only; `None` on a parse failure → caller fails CLOSED. |
| `generated_tests.rs` | Co-located unit tests for `generated.rs`. |
| `tcp.rs` | TCP-specific inspection + mutation kernels (#989) — flags, MSS clamp, header munging. |
| `tcp_segmentation.rs` | TCP segmentation kernels for forwarded over-MSS frames; re-exported from `mod.rs`. The `#[cold]` annotation is on the TX-side wrapper in `tx/tcp_segmentation.rs` that calls into these kernels, not on the kernels themselves. The tunnel egress path is **mode-aware on both axes** (#2329): the inner-L3 MTU is `native_gre_inner_mtu` for GRE and `wg::mss::wg_inner_mtu` for WireGuard, and the encap dispatch is GRE→`encapsulate_native_gre_frame` / WireGuard→`wg::wg_encap_frame` / unknown→drop, mirroring the #2327 `frame/mod.rs` build-egress dispatch (no unconditional GRE). **#5141 IP-declared-length clamp:** the payload the kernels chunk is `&frame[l3..declared_l3_end]`, NOT the full `&frame[l3..]` backing — the datagram's authoritative end is the IP header's declared length (IPv4 `total_len` / IPv6 `40 + payload_len`), clamped to the backing slice by the shared `inspect::declared_l3_end`. Slicing the raw backing promoted trailing Ethernet slack / attacker-appended bytes into fresh segments with valid IP lengths and TCP checksums (bytes injected into a valid checksummed stream). The MTU admission (`payload.len() <= mtu`), the TCP header parse, the data slice, and the per-segment copy loop are all bounded by this clamped `payload`; a declaration too short to cover the IP+TCP headers fails closed (not segmented). The `tx/dispatch.rs` admission predicate `forwarded_tcp_may_need_segmentation` clamps identically (`declared_l3_end - l3 > mtu`, not `frame.len() - l3 > mtu`) so admission and the builders stay in lockstep. RED-on-revert: `ipv4_segmentation_ignores_trailing_slack_beyond_total_len`, `ipv6_segmentation_ignores_trailing_slack_beyond_payload_len`, `ipv4_segmentation_rejects_declaration_shorter_than_headers`. **#5191 per-segment header fidelity:** both builders clone the ORIGINAL IP + TCP headers verbatim into every output, so everything that must NOT be cloned is repaired by ONE shared helper, `finalize_tcp_segment_headers` — called by the copy path here AND by the prepared-TX twin, which is why the two cannot drift. It owns seq, PSH (last segment only), **CWR** (first segment only — RFC 3168 §6.1.2 makes it a one-shot; a cloned CWR retracts an ECE the receiver re-raised for a NEW congestion event, and the sender never reduces cwnd. Same rule as a TSO NIC / Linux `tcp_gso_segment`), **URG + urgent pointer** (the pointer is relative to the segment's OWN seq, so cloning it invents urgent data one chunk further in per segment and a receiver with `SO_OOBINLINE` off pulls a byte OUT of the data stream — the ABSOLUTE urgent point `seq + urg_ptr` is preserved instead and URG is cleared once a segment starts past it), and the **IPv4 Identification** (`id + segment_index` when DF is CLEAR — RFC 6864 §4.1 requires a unique Identification for a non-atomic datagram, since a downstream fragmenting router would otherwise produce fragments of DIFFERENT segments sharing one reassembly key; an ATOMIC DF-set datagram keeps its ID, the field being ignored there). Ordering contract: both twins call it BEFORE the IPv4 header checksum recompute and BEFORE `recompute_l4_checksum_ipv4/6`, so the written fields are covered by the fresh checksums. RED-on-revert: `segments_keep_cwr_on_the_first_segment_only_5191`, `segments_get_distinct_ipv4_ids_when_df_is_clear_5191`, `segments_keep_the_ipv4_id_when_df_is_set_5191`, `segments_rebase_the_urgent_pointer_5191`. |
| `wg.rs` | WireGuard transit-egress encap for the AF_XDP copy path (`wg_encap_frame`). The outer IPv6 UDP checksum is computed by the AVX2-backed `checksum::checksum16_ipv6` helper (the same routine the inner TCP/UDP/ICMPv6 paths use), NOT a hand-rolled scalar loop (#2651 — replaced the per-packet word-at-a-time `udp6_checksum` summation; byte-identical wire output, faster on the hot path). The RFC 768 / RFC 8200 mandatory `0x0000 → 0xFFFF` canonicalization is applied at the call site (UDPv6 checksum is MANDATORY, unlike v4). The IPv4 outer UDP checksum is left 0 (optional/disabled per RFC 768). **Outer underlay resolution (#2680/#2701/#3992):** the outer-MTU guard and outer-source lookup both need the PHYSICAL underlay egress via `outer_physical_egress_ifindex` (route to the selected peer endpoint in the endpoint's transport table), NOT `decision.resolution.egress_ifindex` (the tunnel LOGICAL ifindex, MTU ~1420 / tunnel-address primary). **#3992:** `wg_encap_frame` resolves that route ONCE per packet (a single FIB LPM via `outer_physical_egress_resolution`), caches the full resolution + `egress` row, and reuses them for the guard, the source, AND the L2/VLAN — pre-#3992 it resolved the identical route twice (MTU guard + source), a redundant per-packet FIB LPM on the encrypt hot path. `outer_physical_egress_mtu` stays the SSOT for the separate PTB path (`wg_endpoint_physical_outer_mtu`). RED-on-revert: `wg_encap_frame_resolves_outer_route_once_v4` (test-only `OUTER_ROUTE_RESOLVE_COUNT` seam) asserts exactly 1 resolution + outer-header byte-identity. **Outer L2/VLAN (#5292):** the outer Ethernet header (dst MAC / src MAC / VLAN) ALSO follows the selected peer's physical egress, derived from the SAME single resolution snapshot — NOT `decision.resolution`. The WG endpoint destination is zeroed (`0.0.0.0`/`::`), so `decision.resolution` was resolved against that placeholder BEFORE the AllowedIPs peer selection: it is either NoRoute (no L2 → blackhole) or the WRONG default route's adjacency (its neighbor MAC / src MAC / VLAN describe a different egress than the selected peer needs). `src_mac` + VLAN come from the resolved physical egress row (consistent with the outer IP source); the outer next-hop `neighbor_mac` comes from the peer route's resolution and — since the lookup passes `None` for dynamic neighbors — falls back to `decision.resolution.neighbor_mac` when the underlay next-hop is not yet statically resolved (a dynamic-learned hop shared with the default route, the common single-underlay case). RED-on-revert: `wg_encap_outer_l2_vlan_follows_selected_peer_not_zeroed_decision` (a peer reached via a different VLAN/adjacency than the stored decision emits the peer's L2/VLAN, not the decision's) and `wg_encap_builds_when_zeroed_decision_has_no_l2` (the frame builds against the peer even when the stored decision has no usable L2 — no blackhole). The route lookup passes `None` for dynamic neighbors and that does NOT lose the physical egress even for a dynamic-learned underlay next-hop: the egress ifindex is route-derived (a missing neighbor resolves to `MissingNeighbor` with the physical egress, which the guard accepts), so the dynamic map would only change the disposition/`neighbor_mac` — and `neighbor_mac` now has the explicit `decision.resolution` fallback above. **#2837 (NON-REPRODUCING):** the report claimed this re-resolution drops the physical egress and falls back to the logical wg ifindex for a dynamic-learned underlay neighbor. It does not reproduce — the first arm already returns the physical underlay egress for the `MissingNeighbor` (dynamic-learned) case (above), and there is no admit-time physical `tx_ifindex` to fall back to: the build zeroes the WG endpoint destination so `resolve_tunnel_forwarding_resolution` stores `tx_ifindex = 0` (and even on a routable transport `tx_ifindex` is the VLAN parent, which has no `egress` row). The fallback (genuine NoRoute to the peer endpoint = undeliverable) returns the conservative LOGICAL `egress_ifindex`; no ifindex choice can rescue an unrouted packet there. See the `outer_physical_egress_ifindex` doc comment and the `outer_egress_*`/`wg_resolver_stores_zero_tx_ifindex_*` tests. **TX DISPATCH SSOT (#6308):** #5292 fixed the frame BYTES; the egress-NIC DISPATCH is the other half. The TX dispatcher selects the egress binding from `decision.resolution.tx_ifindex` (the physical bind ifindex) or, when that is 0, from `resolve_tx_binding_ifindex(egress_ifindex)`. For a WG transit-egress flow the zeroed-endpoint resolution stores `tx_ifindex = 0` and `egress_ifindex =` the LOGICAL wgN ifindex, so — with a default route in the WG transport table — `tx_ifindex > 0` resolves to the default egress (= the physical WAN parent) and dispatch works (the **common case, unchanged**); but with ONLY a specific peer route and NO default, `tx_ifindex = 0` → the fallback `resolve_tx_binding_ifindex(logical wgN)` returns the logical ifindex, which has **no XSK binding**, so the TX dispatcher `NO_EGRESS_BINDING`-drops a frame #5292 built correctly. `wg::wg_transit_egress_physical_egress_ifindex` (re-exported from `frame`, consumed by `forward_request::resolve_forward_target_ifindex`) resolves the physical underlay egress against the SAME selected-peer route #5292 uses for the bytes (`wg_peer_outer_dst` → `outer_physical_egress_resolution` → `outer_egress_ifindex_or_fallback`), so the dispatch SSOT and the frame-bytes SSOT agree on one physical NIC. The peer-route resolution runs ONLY on the `tx_ifindex == 0` (previously-dropped) path — default-route WG traffic and every non-WG forward keep the zero-extra-work `tx_ifindex > 0` fast path. RED-on-revert: `wg_transit_egress_dispatch_specific_peer_no_default_6308` (a specific-peer-route + no-default WG flow dispatches to reth0.80's physical parent NIC, not the logical wgN 400 → `NO_EGRESS_BINDING`; and a default-route flow with `tx_ifindex > 0` still dispatches to the default egress verbatim). **#6340 (dispatch peer follows the POST-NAT dst):** at the dispatch site the frame in hand is the PRE-NAT ingress frame, but `wg_encap_frame` selects its peer from the POST-NAT frame — the build applies DNAT into `out` (`nat.rewrite_dst`) BEFORE its own peer LPM (`inner_dst_ip(&out)`). So `wg_transit_egress_physical_egress_ifindex` keys the peer selection on `decision.nat.rewrite_dst` (the post-DNAT dst) when a same-family DNAT applies, else the frame's parsed inner dst — the SAME key the encap bytes use — so a DNAT rewriting the inner dst ACROSS two AllowedIPs peers on distinct physical underlays cannot split the dispatch NIC from the byte NIC. NAT64 (`nat.nat64`) is excluded (address-family change → `None`, the logical fallback). RED-on-revert: `wg_transit_egress_dispatch_follows_post_nat_peer_6308` (DNAT-across-peers dispatches to the POST-NAT peer's physical NIC, not the pre-NAT peer's). |
| `tests.rs` | Co-located unit tests; relocated out of `mod.rs` in #1046 Phase 1. |
| `prop_tests/` | #1824 proptest property harness — parse no-panic/bounds/round-trip, NAT round-trip + descriptor-vs-generic differential, TSO reassembly. `cfg(all(test, not(miri)))` — and note that no gate runs this module under Miri today (#9499); see "Property tests" below. |

## Where it sits

- Read by every stage that inspects a packet (screen, policy,
  conntrack, NAT, forwarding).
- Mutated by NAT / NAT64 / NPTv6 to rewrite addresses + ports +
  checksums.
- Mutated by CoS for ECN CE-marking and DSCP rewrite.

## Notable invariants

- Visibility is tight: `adjust_l4_checksum_ipv6_addr_bytes` is
  file-private to `checksum.rs` (only the local SNAT/DNAT rewrites
  use it) and is pulled into `mod.rs` via a non-pub `use` so it
  doesn't leak via a glob re-export.
- All byte-level helpers assume the caller has already validated the
  packet bounds. The validation lives in `inspect.rs` and the worker
  hot path; do not call a `byte_writes` fn on an unvalidated frame.
- IPv4 checksum is incrementally adjusted (`adjust_*`) on each
  per-field rewrite. The `recompute_*` helpers exist for the rare
  case where the previous checksum is unknown (e.g. NAT64 from
  scratch in generic XDP — the BPF-side handling of this case is
  documented in `bpf/headers/` and the `xdp_nat64.c` source).
- **IPv6 L4 offset is caller-threaded (#1838)**: `apply_nat_ipv6`,
  the v6 checksum adjusters, and `recompute_l4_checksum_ipv6` take a
  `rel_l4` parameter instead of assuming the fixed 40-byte base
  header. The single source of offset truth is `v6_rel_l4_offset` in
  `mod.rs` (meta-led when `meta_rel >= 40 && l4 > l3`, else the
  extension-chain walk) — shared by the descriptor fast path, the
  generic in-place rewrite, the copy builder, the slow path, and the
  ICMPv6-error NAT reversal builder, so the offset precedence rule
  cannot drift between paths. Every adjuster call within one
  `apply_nat_ipv6` invocation uses the SAME threaded `rel_l4` as the
  byte writes it balances — never re-derive mid-function.
- **Zero-checksum rules are predicate-routed (#1839/#1840)**: the
  RFC 768 received-0 skip (`l4_udp_checksum_optional`) is IPv4-UDP
  only; the computed-0 → 0xFFFF canonicalization
  (`adjust_zero_checksum_illegal`) covers v4 UDP and v6 UDP+ICMPv6
  (NOT TCP — a computed TCP 0x0000 is wire-valid in both families).
  Both rewrite paths route through the same predicates;
  `apply_nat_port_rewrite` additionally applies the no-op-port parity
  rule (v6 UDP stored 0x0000 + any port-NAT decision → 0xFFFF, even
  when the port value is identical) so the descriptor's ≡0-delta
  behavior matches byte-for-byte.
- **Non-first fragments skip all L4 byte ops (#1852)**: a non-first IP
  fragment has no L4 header at the post-IP offset — those bytes are
  payload. The orchestrators compute the predicate ONCE
  (`is_non_first_fragment` / `ipv4_is_non_first_fragment` /
  `ipv6_is_non_first_fragment` in `inspect.rs`) and thread a
  `non_first_fragment: bool` into `apply_nat_ipv4`/`apply_nat_ipv6`,
  `enforce_expected_ports`/`_at`, and `restore_l4_tuple_from_meta`. On a
  non-first fragment the IP address is still rewritten (every fragment
  carries the IP header and must stay consistent for reassembly), but the
  L4-checksum adjust, port rewrite, port enforcement and ICMP ident
  restore are SKIPPED — the address-change delta is folded into the first
  fragment's L4 checksum, which covers the whole datagram and is correct.
  The descriptor fast path returns `None` for non-first fragments so the
  caller falls back to the generic path (preserving the #1838 P-N3
  byte parity). The pre-rewrite dynamic pool SNAT allocation
  (`nat/source.rs`) is gated separately — a non-first fragment that would
  need a pool allocation is dropped (`SourceNatFailureReason::NonFirstFragment`)
  rather than leaking a pool port; static / interface (address-only) SNAT
  is unaffected. `clamp_tcp_mss` self-gates the fragment case (both
  families) AND derives the v6 L4 offset via the ext-aware
  `packet_rel_l4_offset_and_protocol` so MSS clamping reaches
  ext-headered v6 SYNs (the shared helper is left unchanged — GRE decap
  and tunnel local-origin read it to forward fragmented inner packets).
- **Both in-place rewrites are transactional / preflight-then-commit
  (#5466 descriptor, #4965 generic)**: `rewrite/mod.rs` splits the eth
  preamble into a pure plan (`rewrite_plan_eth_from_parts`) and a mutating
  commit (`rewrite_commit_eth_from_plan`, the eth-header write + VLAN-push
  `copy_within` memmove). ALL bail gates run against the PRISTINE frame at
  `plan.l3` BEFORE the commit, so a `None` return leaves the UMEM frame
  byte-identical (L2 included). This is the ATOMICITY INVARIANT: a declined
  rewrite mutates ZERO UMEM bytes.
    - **Descriptor fast path** (`apply_rewrite_descriptor`, #5466): gates are
      `is_non_first_fragment` + `validate_rewrite_descriptor_ipv4/ipv6`
      (header length, TTL/hop-limit, DMA-race port mismatch).
    - **Generic in-place rewrite** (`rewrite_forwarded_frame_in_place`,
      #4965): gates are `validate_generic_rewrite_v4/v6` (header length,
      TTL/hop-limit, IPv6 ext-chain L4-offset resolvability via
      `v6_rel_l4_offset`, and — when NAT folds into the L4 checksum — the
      checksum field at `ihl/rel_l4 + {16 TCP, 6 UDP, 2 ICMPv6}` being in
      bounds, derived from the SAME `l4_checksum_field_delta_v4/v6` SSOT the
      mutation half writes at). The validators cover EVERY `?` in
      `rewrite_apply_v4/v6` (`apply_nat_ipv4/ipv6`,
      `adjust_ipv4_header_checksum`, `recompute_l4_checksum_*`), so the
      post-commit `apply_*` calls can no longer decline — no UMEM byte is
      mutated before any possible `None`.
  Atomicity is REQUIRED because BOTH declining callers re-read the same UMEM:
  the flow cache chains `apply_rewrite_descriptor(...).or_else(generic)`
  (`poll_descriptor/flow_cache_hit.rs`) and, on a generic `None`, falls into
  the `build_live_forward_request_from_frame(packet_frame, ...)` path; and
  `tx/dispatch/mod.rs` runs `build_forwarded_frame_from_frame(source_frame)`
  over the SAME `ingress_area` slice after a generic `None`. A frame mutated
  before the bail (scribbled L2 / shifted payload / partial NAT+checksum)
  would corrupt that reprocessing (the #4965 bug). The gates read from the
  original L3 offset (before the commit's memmove relocates the payload) and
  use the plan's `frame_len`/`payload_len` for length checks, so their
  decisions are byte-identical to the pre-split post-commit checks; the
  `apply_*` mutation halves reproduce the success-path output exactly
  (guarded by the P-N3 differential + the `pin_5466_*` /
  `declined_rewrite_leaves_umem_byte_identical_4965` /
  `pin_*_declines` fail-on-revert pins).
- **Port-less protocols never get an L4 port written (#3111)**: only
  TCP/UDP carry a rewritable 16-bit port pair at L4 offset +0/+2. Every
  port-write site — the generic `apply_nat_port_rewrite` and the
  descriptor fast-path arms (`rewrite/ipv4.rs`, `rewrite/ipv6.rs`) — gates
  on the single `crate::ip_proto::has_l4_ports` predicate (TCP|UDP) so a
  GRE/ESP/AH/OSPF/ICMP packet's first two L4 bytes (GRE flags, ESP SPI)
  are NEVER overwritten with a NAT port. The allocator side is gated too:
  pool-mode SNAT in `nat/source.rs` allocates NO pool port and leaves
  `rewrite_src_port` unset for a port-less protocol (IP-only translation),
  so the descriptor never even carries a stray port for these.
- **Non-first fragments build NO ported SessionFlow (#2344)**: #1852
  gated only the NAT rewrite leaves; the generic session-flow parsers
  (`parse_session_flow_from_bytes` / `parse_session_flow_from_frame` /
  `parse_ipv4_session_flow_from_frame`) still called `parse_flow_ports`
  on a non-first fragment, reading payload bytes as TCP/UDP ports and
  feeding that fake tuple to policy eval, the flow cache, and the
  session/reverse indexes. The parsers now reuse the same
  `is_non_first_fragment` / `ipv4_is_non_first_fragment` /
  `ipv6_is_non_first_fragment` predicates and return `None` for a
  non-first fragment. `parse_session_flow_from_bytes` runs the check
  ONCE at the top (`frame_is_non_first_fragment`) as the single
  chokepoint, so the meta fast path cannot admit a fragment either — the
  XDP shim does NOT gate fragments, so `meta.flow_*_port` may carry
  payload bytes stamped at the post-IP offset. A flowless (`None`)
  packet follows the existing route-based, session-less forward path
  (the pre-#1913 "no flow tuple" behavior in `poll_descriptor`), so xpf
  forwards fragments statelessly per route without policy-on-fake-ports.
  GRE decap (`gre.rs`) inherits this automatically: with `flow == None`
  it stamps `(0, 0)` ports instead of synthesizing them. Composes with
  the #2293-era screen fragment classification (`extract_screen_info`),
  which independently sees and screens non-first fragments. For a FIRST
  IPv6 fragment (`extract_screen_info`, #3120) the screen walk continues
  past the Fragment header through any trailing extension headers (e.g. a
  `Fragment → Destination-Options → TCP` chain, valid per RFC 8200) so the
  TCP flags/seq/MSS still reach the TCP-flag screens and the SYN-cookie
  flood challenge; a non-first fragment carries no L4 here and stays
  flowless.
- **A protocol with no shim-resolved L4 identity is flowless (#6837)**:
  `metadata_tuple_complete` returns true only for the protocols the XDP
  shim actually parses an L4 identity for — TCP, UDP, ICMP and ICMPv6.
  The shim's `parse_l4` catch-all stamps `Some((l4_offset, 0, 0, 0, 0))`
  for everything else, and those zeros are a PLACEHOLDER, not a parse.
  Before #6837 the predicate asked only whether both addresses were set,
  so GRE (47), ESP (50), AH (51), OSPF (89) and every other portless
  protocol were declared complete on the strength of that placeholder —
  overriding the frame side, which had already refused them
  (`parse_flow_ports` has no arm for them). The packet then took the
  flow-backed arm and, on permit, installed
  `SessionKey { protocol, src_port: 0, dst_port: 0, .. }` plus its reverse
  companion: measured at **two entries per transit flow**, aliasing every
  distinct flow between one endpoint pair onto one key, one policy
  decision, one NAT state and one timeout.

  **Flowless is not a drop and not a bypass.** The packet still forwards
  (measured: an unchanged `tx=1` across the change), and since #3291 the
  flowless transit arm applies zone policy, interface input filters and
  PBR through the *same* helpers the flow-backed arm uses
  (`evaluate_non_pbr_input_filter`, `ingress_route_table_override`,
  `evaluate_policy_result_l3_aware`). The flowless arm is additionally
  stricter in one respect that matters here: it evaluates with
  `l4_present = false`, so port-bearing policy terms fail closed instead
  of being compared against fabricated port 0.

  What IS given up is **stateful return admission** for these protocols,
  and their appearance in `show security flow session` — an observable
  behaviour change on upgrade, not a pure correctness fix. Restoring a
  session for them needs a discriminator that is the SAME in both
  directions: the RFC 2890 GRE Key qualifies, an RFC 2637 PPTP Call ID and
  an ESP SPI do not (both are allocated per-direction — see
  `docs/userspace-native-gre-plan.md` §6e). That belongs on the PARSE
  side (#7188's typed discriminator), never as a metadata-side default.
- **L4 ports are bounded by the IP-DECLARED packet length (#2361)**: the
  live ingress parsers (`parse_ipv4_session_flow_from_frame`, the IPv6 arm
  of `parse_session_flow_from_frame`, the meta-offset fallback in
  `parse_session_flow_from_bytes`, and the meta fast-path readers
  `live_frame_ports_from_meta_bytes` / `live_frame_ports_bytes`) read the
  L4 ports via `parse_flow_ports(frame, l4, proto, declared_end)`, where
  `declared_end` is `ipv4_declared_l3_end` (`l3 + total_len`) /
  `ipv6_declared_l3_end` (`l3 + 40 + payload_len`), each CLAMPED to the
  backing slice. The 4 port bytes (2 ident bytes for ICMP) MUST lie inside
  `declared_end` — a frame whose `total_len` / `payload_len` declares a
  short datagram but carries trailing slack (NIC zero-pad on a sub-60-byte
  frame, or attacker-supplied bytes) returns `None` rather than reading the
  out-of-datagram bytes as ports. Before #2361 the read was bounded only by
  the slice (and the fragment gate), so out-of-packet padding could spell a
  TCP/UDP port pair that then drove port-based policy, firewall-filter
  matching, CoS queue selection, and session installation. A `None` result
  is flowless (the same route-based, session-less forward path #2344 uses).
  This MIRRORS the sibling generated-reply parser, which already enforced
  the identical bound as a fail-closed security invariant
  (`generated.rs::generated_l4_ports`, clamping to
  `total_len` / `40+payload_len` before extracting ports, #2238/#2321) — so
  the live ingress path and the generated path now treat an out-of-IP-bound
  L4 identically. The meta fast path is gated too: the XDP shim stamps
  `meta.l4_offset` but does NOT enforce the IP-declared bound, so the meta
  readers re-derive `declared_end` from the L3 header in the frame before
  reading ports (mirroring #2357's meta-fast-path chokepoint concern).
- **The forwarded L4 payload is trimmed to the IP-DECLARED length (#5149)**:
  `trim_l3_payload` (`frame/mod.rs`, called by the `build/mod.rs` orchestrator
  and the in-place `rewrite_plan_eth_from_parts`) determines both the copied
  frame length AND the extent the tunnel-forced L4 recompute checksums. It is
  now **IP-declared-length authoritative**: it returns `&raw_payload[..declared_l3_end]`
  (the same `inspect::declared_l3_end` SSOT as the #2361 port bound and the
  #5141 segmentation clamp — IPv4 `total_len` / IPv6 `40 + payload_len`,
  clamped to the backing). Metadata `pkt_len` is only a FALLBACK, reached when
  `declared_l3_end` is unavailable (truncated/malformed L3 header — bad
  version/IHL or a buffer shorter than the declared IHL — or an unknown
  addr_family). Before #5149 it was metadata-led: when `pkt_len` yielded a
  length equal to the full backing slice (i.e. it INCLUDED trailing Ethernet
  slack), it returned the slack-inclusive suffix and never reached the
  IP-header clamp. On the tunnel-forced recompute path
  (`force_tunnel_l4_recompute`, `build/ipv4.rs` / `build/ipv6.rs`, consumed by
  `wg::wg_encap_frame` / `encapsulate_native_gre_frame`), the L4 checksum then
  covered the slack, but encap transmits only the IP-declared inner length, so
  the peer verified the checksum over bytes no longer present and DROPPED the
  packet. A no-slack common frame is unaffected (its `total_len` already equals
  the metadata-derived L3 length → byte-identical trim). A declaration too
  short to cover the L4 header fails closed downstream (the recompute helpers
  return `None` → drop — never a checksum over garbage). RED-on-revert:
  `trim_l3_payload_excludes_ethernet_slack_beyond_ip_declared_len_5149`.
- **ICMP pseudo-port is only emitted for identifier-bearing query types
  (#3067)**: in `parse_flow_ports` the 2-byte ICMP/ICMPv6 word at
  `[l4+4, l4+6)` is the protocol Identifier ONLY for the query types — for
  ICMPv4 that is Echo Request/Reply (8/0) and the Timestamp/Information
  query+reply pairs (13/14/15/16, identical Identifier offset per RFC 792);
  for ICMPv6 only Echo Request/Reply (128/129) per RFC 4443. For every other
  type — the errors (Dest-Unreachable, Packet-Too-Big, Time-Exceeded,
  Parameter-Problem), Redirect, and the ND/MLD control types — those two
  bytes are part of a gateway address, the next-hop MTU, a pointer, or an
  unused/reserved field, NOT a port. `parse_flow_ports` reads the ICMP type
  byte at `l4` (bounded by `declared_end`) and returns `None` (flowless) for
  every non-query type, so transit ICMP error/control packets follow the
  route-based, session-less forward path instead of installing a bogus
  identifier-keyed stateful session that would pollute the session table and
  risk spurious collisions. Matching an ICMP error to its embedded inner flow
  for NAT reversal (#2393 model) does NOT need a session: the generic
  embedded-ICMP NAT reversal runs on the FLOWLESS poll arm
  (`poll_descriptor/embedded_icmp.rs::try_reverse_embedded_icmp_error`, #5690),
  reverse-translating the inner quoted packet and forwarding the error to the
  real internal host WITHOUT seeding a session (the prebuilt forward carries
  `flow_key = None`) — so the flowless routing here is preserved, not bypassed.
  **#3290 — the
  metadata path honors the SAME gate:** the XDP shim stamps
  `meta.flow_src_port = bytes[l4+4..l4+6]` for EVERY ICMP type with no
  query-type gate, so `parse_session_flow_from_bytes` could otherwise
  reconstruct a fake session from that control word when the frame parser
  returned `None` (the meta fallback fired). The gate is now shared: the
  query-type predicate is factored into `icmp_identifier_bearing(protocol,
  type)` (used by both `parse_flow_ports` and the meta fallback), and
  `parse_session_flow_from_bytes` discards `meta_flow` for a non-query ICMP
  type (`meta_icmp_identifier_bearing`, type byte read from the frame bounded
  by `declared_end`, fail-closed on truncation) so the packet stays flowless
  on the metadata path too. `meta_icmp_identifier_bearing` requires the FULL
  identifier range `[l4..l4+6)` inside `declared_end` — frame-equivalent to
  `parse_flow_ports` (a query packet truncated between the type byte and the
  identifier fails closed, not just the type byte). **All FOUR metadata
  consumers gate identically** so the shim's ungated pseudo-port can never
  reach a session/flow key OR the wire: (1) the conntrack-side
  `parse_session_flow_from_bytes`; (2) the immediate
  `build_live_forward_request_from_frame` TX/CoS meta-fallback
  (`afxdp/forward_request.rs`); and (3) the pending-neighbor buffering
  fallback (`afxdp/neighbor_dispatch.rs::pending_neigh_flow_key`, used at the
  `MissingNeighbor` handler in `poll_descriptor`) — a non-query ICMP packet
  whose next-hop is unresolved buffers `flow_key = None`, so
  `retry_pending_neigh` flushes it to the interface default queue with no
  output-filter eval; and (4) — #5191 — the only consumer that WRITES the
  pseudo-port back onto the wire, `restore_l4_tuple_from_meta`. The first
  three decide a KEY; the fourth mutates BYTES, which is why it was the
  costly omission: it stamped `meta.flow_src_port` into `[l4+4, l4+6)` for
  every ICMP type. On a GRE-decapped Redirect / Parameter-Problem / RA /
  MLD message (whose synthesized `flow_src_port` is 0 precisely BECAUSE
  `parse_flow_ports` declines a non-query type) that zeroed the gateway
  address / pointer / Maximum Response Delay. Both writers of that field —
  the NAT identifier translation (#4074) and this restore — now route
  through ONE helper, `write_icmp_identifier`, which owns the query-type
  gate AND the incremental (RFC 1624) ICMP-checksum repair.
- **The ICMP identifier field has exactly ONE writer (#5191)**:
  `write_icmp_identifier` (`mod.rs`). It repairs the ICMP/ICMPv6 checksum
  INCREMENTALLY over the single changed 16-bit word rather than deferring
  to `recompute_l4_checksum_ipv4/6`, for two independent reasons. First,
  `recompute_l4_checksum_ipv4` has NO ICMP arm (only TCP and UDP, with a
  `_ => {}` fallthrough) — the v4 `repaired_ports` recompute was therefore a
  silent no-op and every restored ICMPv4 message left the box carrying its
  PRE-change checksum, which the receiver discards. Second, the in-place
  rewrite path hands the helper a slice bounded by the RX descriptor length,
  which includes Ethernet min-frame zero-pad; a from-scratch recompute would
  fold that pad into the checksum, whereas the incremental delta is immune to
  trailing slack. (The v6 side's `PROTO_ICMPV6` arm in
  `recompute_l4_checksum_ipv6` is unchanged and still runs on the
  `repaired_ports` path; the incremental write is idempotent with it.)
- **TCP inspection helpers are ext-header-aware (#2148)**: the read-only
  diagnostic/telemetry helpers `frame_has_tcp_rst`,
  `extract_tcp_flags_and_window`, and `extract_tcp_window` (`tcp.rs`) all
  derive the IPv6 L4 offset via the shared `packet_rel_l4_offset_and_protocol`
  ext-header walker, NOT a fixed L3+40. Before #2148 they hard-coded the
  TCP header at L3+40, so an IPv6 flow carrying any extension header
  (hop-by-hop, routing, fragment, dest-opts) had its RST/flags/window read
  from inside the extension header — operator-visible RST and zero-window
  diagnostics (cos queue service, rx telemetry, tx transmit, frame build
  corruption check, tunnel inner inspection) were false on those flows.
  The walker is bounded (`MAX_IPV6_EXT_HEADERS` (8) iterations, #2292),
  allocation-free (no per-packet heap), and fails safe — a
  truncated/malformed/looping chain yields
  "no RST" / "flags unknown" (false / None) rather than panicking or
  reading OOB. Today these helpers are diagnostics-only, but routing them
  through the shared walker means the next caller cannot reintroduce the
  fixed-40 bug. IPv4 and plain (no-ext-header) IPv6 behavior is unchanged.
- **Canonical L2 / IPv6 parse contract + drift canaries (#2150)**: the
  userspace dataplane still has FIVE distinct Ethernet-L2 offset parsers
  (`afxdp/parser.rs::parse_eth_offsets` [learning], `inspect.rs::frame_l3_offset`
  [forwarding], `cos/ecn.rs::ethernet_l3` [CoS ECN], `nat64.rs::frame_l3_offset`
  [NAT64], `afxdp/icmp.rs::ingress_reply_l2` [ICMP reply VID]). The IPv6
  extension-header walk, by contrast, is ONE shared loop since #6435:
  `inspect.rs::walk_ipv6_ext_chain` (an `#[inline(always)]` core returning an
  `ExtChainOutcome` verdict — `L4` / `NoNextHeader` / `Truncated` /
  `OverLimit` — plus the recorded first Fragment-header sighting). Every
  forwarding L4 resolver (`frame_l4_offset`, `packet_rel_l4_offset`,
  `packet_rel_l4_offset_and_protocol`), the #4743 over-limit gate
  (`ipv6_ext_chain_over_limit`), both fragment predicates
  (`ipv6_is_non_first_fragment` / `ipv6_is_any_fragment`), the NAT64
  resolvers (`ipv6_l4_offset_and_protocol`, `ipv6_is_non_first_fragment`,
  `ipv6_fragment_header`), and the embedded-ICMP resolver
  (`icmp_embed/parse.rs::parse_embedded_v6_l4`, #1838) FOLD that one walk,
  so the #4517 ext-header set, the AH `(len + 2) * 4` arithmetic, and the
  fail-closed-at-the-bound posture (#2292/#4435/#4533) can never drift
  between copies again. Two walkers deliberately keep their own loops:
  `screen/extract.rs` (#2189 — it extracts screen-specific state into its
  parse struct and fails with a screen-specific `Err`, a different
  contract than L4 resolution) and `nat64.rs::nat64_v6_translation_ineligible`
  (#5625 — per-type translation-eligibility verdicts incl. the Routing
  Segments-Left read, not an L4-resolution walk). All of them share the
  `MAX_IPV6_EXT_HEADERS` (8) bound AND fail CLOSED when the chain is
  still on an extension header at that bound — the shared walk yields
  `OverLimit` (its wrappers return `None`/`false`), `screen/extract.rs`
  returns `Err` (drop, #2189). The CANONICAL CONTRACT they MUST agree on:
  - **L2**: untagged → l3 = 14; a single 0x8100 (802.1Q) OR 0x88a8 (802.1ad)
    tag → l3 = 18 (the inner ethertype, possibly still a VLAN TPID for a
    QinQ double tag, is returned as-is). A QinQ DOUBLE tag is NOT unwound in
    userspace — and crucially the upstream XDP shim
    (`userspace-xdp/src/lib.rs::parse_l2`) strips exactly ONE tag (an `if`,
    not a `while`), so after the outer tag the dispatched `eth_proto` is the
    inner TPID (0x8100), which is neither `ETH_P_IP` nor `ETH_P_IPV6`. It
    therefore hits the `_` arm at `lib.rs:376` and is handed to the kernel via
    `pass_non_ip_l2_direct()` (XDP_PASS) — NOT delivered to the XSK and NOT
    XDP_DROPped. So a double-tagged frame never reaches these userspace
    parsers: there is no reachable misparse divergence on the transit path
    (the "returned as-is" inner-TPID-at-l3=18 case below is unreachable in
    production, kept only as a contract invariant). Adding real double-tag
    transit would require changing BOTH the shim and the userspace parsers and
    is out of scope (tracked: #2354). NOTE: earlier revisions of this file
    said the shim "drops" QinQ-double frames — that was inaccurate; it
    XDP_PASSes them to the kernel.
  - **IPv6 ext-headers**: walk the chain (shared #2148 engine, `MAX_IPV6_EXT_HEADERS`
    bound) to the terminal L4 offset + protocol; do NOT assume L4 at a fixed
    L3+40. The extension-header SET every walker recognizes is Hop-by-Hop (0),
    Routing (43), Fragment (44), AH (51), Destination Options (60), and — since
    **#4517** — Mobility (135, RFC 6275), HIP (139, RFC 7401), Shim6 (140, RFC
    5533), and the experimental/testing values (253/254, RFC 3692 / RFC 4727),
    all of which share the generic `(HdrExtLen + 1) * 8` advance. ESP (50) is
    deliberately NOT walked (encrypted payload, unreadable inner next-header) —
    the walk STOPS at it. Before #4517 the exotic length-prefixed headers fell
    to the terminal `_` arm, so a chain like `HOP → MOBILITY → FRAGMENT → TCP`
    was classified proto=135 with no L4/fragment status — the screens never saw
    the SYN and forwarding never saw the flow (an ext-header IDS evasion).
    Since #6435 the forwarding/fragment/NAT64/embedded-ICMP walkers share the
    ONE `walk_ipv6_ext_chain` loop, so they recognize the same set by
    construction; the two deliberate keep-outs (`screen/extract.rs`,
    `nat64_v6_translation_ineligible`) MUST keep the SAME set or the screen,
    meta, forwarding, and NAT64 paths disagree on the same packet.
  PR-1 of #2150 fixed the three parsers that DISAGREED on a single 0x88a8
  tag / ext-headered NDP (`parse_eth_offsets` treated 0x88a8 as the inner
  ethertype → l3=14; `nat64::frame_l3_offset` treated it as untagged →
  l3=14; `parse_ndp_neighbor_advert` read a fixed L3+40 and missed an NA
  behind a hop-by-hop header) and added drift-guard CANARIES
  (`parser_tests.rs::l2_offset_canary_all_parsers_agree`,
  `ipv6_walk_canary_learning_agrees_with_forwarding`,
  `nat64_tests.rs::nat64_l2_offset_canary`) that FAIL the instant any parser
  drifts from the contract. These bugs were LATENT not live: the shim
  XDP_PASSes ARP / diverts NDP control / XDP_PASSes QinQ-double to the kernel,
  so the buggy
  learning/NAT64 parsers never received the trap frames — the fix closes the
  trap before a future steering change springs it. **PR-2 (deferred
  follow-up)** is the full unification: collapse all five L2 parsers + three
  IPv6 walkers onto one canonical `parse_l2` + one `walk_ipv6_ext` (the
  issue's `afxdp/frame/parse/` tree), gated on these PR-1 canaries staying
  green so the refactor is provably behavior-preserving. Two parallel
  implementations stay DELIBERATELY separate and are NOT part of either PR:
  the XDP shim `parse_l2`/`parse_ipv6` (kernel/no_std/verifier; authority for
  `meta.l3_offset`) and the Go `pkg/vrrp::walkIPv6ExtHeaders` (different
  language + socket).

## Property tests (`prop_tests/`, #1824)

In-tree proptest harness (plan:
`docs/research/1824-fuzz-harness/plan.md`) covering three surfaces:

- **S1 parse** (`prop_tests/inspect.rs`): no input of length 0..2048
  with arbitrary metadata can panic the inspect parsers; offsets stay
  in bounds; the frame-level and packet-relative ext-header walks
  agree; synthesized valid packets (incl. structured IPv6
  extension-header chains) round-trip to the exact built tuple.
- **S2 NAT rewrite** (`prop_tests/rewrite.rs`): NAT apply/undo
  round-trip identity on non-checksum bytes; a full-recompute
  checksum validity oracle (`prop_tests/oracle.rs` — NOT the
  v4-TCP-only `verify_built_frame_checksums`); randomized
  descriptor-vs-generic differential proving the flow-cache fast
  path's byte-equivalence claim with FULL byte equality (empty
  exclusion mask since the #1838/#1839/#1840 trio fix); payload
  immutability.
- **S4 TSO splitter** (`prop_tests/segment.rs`): reassembly identity,
  per-segment wellformedness (seq arithmetic incl. u32 wrap, PSH /
  CWR / URG handling and the IPv4 Identification per #5191 — the flag
  generator samples CWR|ACK and URG|ACK so the fixture actually varies
  the axis those expectations pin,
  handling, length fields incl. the ext-chain bytes in the v6
  payload-length field, oracle checksums, segment count), NAT
  composition.

The #1838/#1839/#1840 defect trio is fixed and the domain gates that
encoded it are lifted: NAT-applying and segmentation generators emit
v6 extension-header chains, and the differential runs unmasked. The
former defect pins are flipped to positive regression pins
(`pin_1838_*_rewrites_real_l4`, `pin_1839_*_parity`,
`pin_1840_*_family_gated` + the v4-skip counterpart and the
same-port stored-zero parity pin). Valid-packet generators still
never emit v6 UDP 0x0000 checksums — malformed per RFC 8200 §8.1 —
so that encoding lives only in the deterministic pins.

Conventions:

- Passing runs use a fresh random seed per run; the committed
  `userspace-dp/proptest-regressions/**` corpus is replayed first on
  every run and is the actual regression-pinning mechanism. Never
  hand-edit or delete those files; review them like code.
- Case counts are explicit per property (512 parse / 256 rewrite+TSO
  / 128 differential); the whole harness adds well under the 10s
  `cargo test --release` budget. Soak:
  `PROPTEST_CASES=100000 cargo test --release prop_tests::`.
- `cfg(all(test, not(miri)))` — proptest case loops are intractable
  under the targeted miri passes.
- **No gate runs this module under Miri (#9499).** This bullet used to
  end "the deterministic pins and the existing `tests.rs` examples keep
  miri coverage of the same fns", which described the pins' shape and
  not any executed run: at the time, nothing in the tree ran Miri.
  `make test-miri` now runs a registered subset
  (`userspace-dp/MIRI.registry`); `afxdp::frame::` is not in it, because
  measured at `16df7c8c7` it ran 1021 s under Miri and then stopped on
  an `unsupported operation: open ... when isolation is enabled` from a
  test that reads a file. `userspace-dp/MIRI.unregistered` records that,
  and `make miri-census` fails if the record is dropped. The pins are
  still the right shape to run under Miri; running them is future work,
  not a present guarantee.
