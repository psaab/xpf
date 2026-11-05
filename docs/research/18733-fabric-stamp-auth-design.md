# #18733 — Keyed fabric stamp authentication: decision-complete design

- **Issue**: #18733 (design; blocks #16023 closure after implementation + live proof)
- **Parent**: #16023 (ZP-01 — fabric zone MAC stamp is public/FNV-forgeable by a third L2 speaker)
- **Sibling**: #18734 (carry forwarding class in the stamp; sequenced PR-B, §11)
- **Base**: `master` `6c9098dcfbbf85fb953f0c19da06df0aad8cef39` (2026-11-05). Every
  `file:line` anchor below was re-derived at this commit. The stale candidate
  `/var/worktrees/campaign-drive/wt-16023/docs/log/16023.md` (base `fed39c4bc1`)
  was input only; §13 lists where it is now wrong.
- **Status**: design for Sol/GLM/Kimi plan seats. No code in this lane. No PR
  (direct-commit rule: branch `research/18733-fabric-stamp-auth`, parent lands).

---

## 0. Decision summary (the eight forks, decided)

| # | Fork | Decision |
|---|---|---|
| D1 | Wire placement | Fixed-tail 34-byte `XPF3` trailer plus a **distinct authenticated source marker** (`02:bf:74`/`02:bf:75`), required by the old-receiver rule in `docs/log/10105.md:124`. Legacy V1/V2 markers remain byte-identical only when no authenticated envelope is emitted (§4). |
| D2 | Tag input | Post-NAT final wire bytes: MAC the final egress L2/VLAN/IP header plus the first 8 bytes after the final IP header, with resolved zone/scope/node/link/direction context. Punt-time tuple binding is disproved on NAT paths (§3/§5). |
| D3 | Verify placement | Verify **every marked frame at stage 9, before every claim consumer, hits and misses alike**. Several consumers act before session-miss policy; miss-only verification is unsound (§2). |
| D4 | PRF | **Measurement-gated**: two domain-separated SipHash-2-4 64-bit outputs (in-tree primitive) vs AES-CMAC-128. No 128-bit SipHash implementation or workstation folklore selects the winner; §7.4 sets lab budgets and the decision rule. |
| D5 | Freshness | Signed minute epoch, inclusive ±5-minute acceptance, cached/latching wall clock (the poll-loop `now_secs` is monotonic and invalid for this; §8.1). No sequence/nonce in PR-A; in-window replay is an accepted residual (§8.2). |
| D6 | Key shape | Derived bases from `chassis cluster authentication-key`, Go→Rust snapshot secret field only; primary signs and additional is accept-only. Raw PSK never crosses to Rust; snapshot content digest uses salted HMAC fingerprints, not clear base bytes (§7.2). |
| D7 | Modes | One leaf `security flow fabric-stamp-authentication { disabled | permissive | required }`, **default `disabled`**. Snapshot v77→v78 is exact lockstep (§9). |
| D8 | Sequencing | PR-A (#18733) authenticates identity with all class bytes zero and semantic class `0xffff=absent`. PR-B (#18734) carries class only after A; third-host live proof is separate and blocks #16023 closure until complete (§11–12). |

PLAN-KILL alternatives are in §12.4 (accept private-L2/attestation as terminal,
or reject this trailer and continue research). Kill criteria K1–K8 are in §12.5.

---

## 1. Mechanism today (re-derived at `6c9098dcfb`)

| Fact | Anchor |
|---|---|
| V1 stamp src MAC `02:bf:72:fe:<low16 of u32 zone id>`; `FABRIC_ZONE_MAC_MAGIC = 0xfe` | `userspace-dp/src/afxdp/mod.rs:550`; encode `userspace-dp/src/afxdp/forwarding/fabric.rs:758-760` (`resolve_zone_encoded_fabric_redirect_by_id`) |
| V2 stamp src MAC `02:bf:73:<24-bit scope id>`; scope id is a public FNV-1a fold of `(zone_id, ifname, routing-instance)` | `userspace-dp/src/afxdp/mod.rs:552`; `fabric.rs:782-801` (`fabric_nat_scope_stamp_id`), encode `fabric.rs:819-826` |
| `StableZoneID` is a public FNV-1a/64 xor-fold of the zone **name** into `[1, 0xFFFFFFFD]` — computable offline by anyone | `pkg/config/zoneid.go:19-62` |
| Receiver parse: V2 checked at `frame[6..9]`, V1 at `frame[6..10]`; low-16 resolved via `zone_id_for_stamp` (collision ⇒ Invalid, #18518) | `userspace-dp/src/afxdp/frame/inspect.rs:2950-3042` (`parse_zone_encoded_fabric_ingress_from_frame`) |
| Stamp outcome enum: `Absent / Invalid / Valid(u32) / ValidScoped{zone_id,ifindex} / Ambiguous{zone_id,ifindex}` | `inspect.rs:2910-2923` (`ZoneEncodedFabricStamp`) |
| Disposition: V1a destination-MAC check → V0 link-auth gate (#16023) → V1b owner-RG proof ⇒ `ProvedPeerPunt` / `AmbiguousLocalZone` (#15916) / `Invalid` | `forwarding/fabric.rs:411-451` (`zone_encoded_fabric_stamp_disposition`; V1a `:427-429`, V0 `:431-433`) |
| In-code admission: on a shared segment a clone is *"indistinguishable from the real thing at L2"* | `fabric.rs:352-361` |
| Stage 9 classification runs per packet on the poll path; outcome struct carries override/scope/ambiguous/fabric/invalid to the packet loop | `userspace-dp/src/afxdp/poll_stages.rs:844-888` (`stage_classify_fabric_ingress`); `FabricIngressOutcome` `poll_stages.rs:73-80`; call site `userspace-dp/src/afxdp/poll_descriptor/mod.rs:1416-1423` |
| Stage-9 invalid drop is terminal before neighbour/session/cache lookup | `poll_descriptor/mod.rs:1449-1453` (`record_invalid_fabric_stamp_drop`) |
| Snapshot ABI is exact-equality fenced: Rust `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 77`, Go `ProtocolVersion = 77`; v69 was the #16023 fence | `userspace-dp/src/protocol/control.rs:343` (changelog `:305-343`); `pkg/dataplane/userspace/protocol.go:530`; refusal `userspace-dp/src/server/handlers/snapshot.rs:25-32`; lockstep pin `pkg/dataplane/userspace/scoped_global_zoneset_protocol_5488_test.go:378` (`TestSnapshotProtocolVersionLockstepWithRust`) + shape pin `snapshot_shape_version_8892_test.go:702` |
| Poll-loop clock is **monotonic**: `loop_now_secs = loop_now_ns / 1e9`, `loop_now_ns` from `monotonic_nanos()` (`CLOCK_MONOTONIC`) | `userspace-dp/src/afxdp/worker/loop_body/mod.rs:715`; `userspace-dp/src/afxdp/bpf_map/mod.rs:1165` |
| Fabric snapshot has a stable configured `name` but Rust `FabricLink` drops it and has no ordinal; Go sorts snapshot names, while runtime resolution can skip a link. Never derive an auth ordinal from the resolved `Vec` index. | `pkg/dataplane/userspace/fabric.go:91-149`; `userspace-dp/src/afxdp/forwarding/fabric.rs:114-124`; `types/forwarding/fabric.rs:10-25` |
| Rust snapshot carries local `node_id: u8`, but `ForwardingState` has no sender identity; PR-A must plumb it and define the expected peer ID from the two-node 0/1 cluster contract. | `userspace-dp/src/protocol/snapshot.rs:966-974`; `userspace-dp/src/afxdp/types/forwarding/state.rs:64` |
| Interim posture already landed (do not redo): opt-in `security flow require-authenticated-fabric-stamps` + `fabric-interface-authenticated` attestation (Rust V0 gate above), snapshot v69 fence; #10105 document-and-constrain advisory; #18719 acknowledgeable/change-scoped reminders; #18751 `pkg/fabricsegment` third-speaker detector | `pkg/config/compiler_security_flow.go:900-902`; `pkg/config/schema_security.go:1404`; `pkg/config/types_security.go:284-289`; `pkg/config/compiler_chassis.go:470-473`; `pkg/config/compiler_fabric_stamp_10105.go:14`; decisive cell `userspace-dp/src/afxdp/tests_fabric_zone_stamp.rs:177` |

---

## 2. Consumer census (re-derived; security consequence and required gate)

Stage 9 parses the stamp into `FabricIngressOutcome` (`poll_stages.rs:844-888`)
and the descriptor loop fans the claim into consumers. The older C1-C15 list
was **not exhaustive**: routing-domain, martian, overlap, pre-routing NAT,
PBR, IPsec scope, cache-hit and deferred paths read the claim outside the
`transit_policy` gate chain. In `required`, stage 9 therefore verifies every
prefix-matched stamp before any of these consumers run; invalid/missing/stale
claims drop terminally. The existing owner-RG gates remain additional policy
gates, not substitutes for authentication.

All Rust paths in this census are relative to
`userspace-dp/src/afxdp/`; tests use the same root unless fully qualified.
Callsites shown in `poll_descriptor/mod.rs` are in
`poll_binding_process_descriptor_in_view` unless another function is named.

| # | Consumer | Exact current anchor | Security consequence | Required-mode gate |
|---|---|---|---|---|
| C1 | Stage-9 parse/disposition and terminal invalid drop | `stage_classify_fabric_ingress`, `poll_stages.rs:844-888`; terminal handling in `poll_binding_process_descriptor_in_view`, `poll_descriptor/mod.rs:1416-1453` | Invalid, missing, malformed, bad-tag or stale claimed identity must not reach lookups. | **MUST-GATE** at stage 9; terminal drop before fan-out. |
| C2 | Session-miss zone pair, transit policy/NAT and host-inbound | `admission_zone_override`, `poll_descriptor/transit_policy.rs:66-107`; `session_miss_zone_pair_ids`, `poll_descriptor/mod.rs:423-444`; `gate_fabric_zone_override_on_owner_rg` / `promote_ambiguous_fabric_zone`, `forwarding/fabric.rs:486-532`; callsites in `poll_binding_process_descriptor_in_view` | The claimed zone selects the from-zone and can change policy, NAT, host-service and owner-RG promotion outcomes. | **MUST-GATE** before claim use; preserve the owner-RG predicate. |
| C3 | Session-hit authority | `session_hit_authority`, `poll_descriptor/session_hit_authority.rs:179-214,399-483`; callsite `poll_binding_process_descriptor_in_view`, `poll_descriptor/mod.rs:1463-1473` | Forged arrival zone can turn a foreign hit into `Owner`, bypassing the arrival zone's policy and allowing owner-session revalidation/re-stamping. It is not inherited trust. | **MUST-GATE** before hit adjudication. |
| C4 | Flow-cache seed | `stage_flow_cache_seed`, `poll_descriptor/flow_cache_seed.rs:32,254-260`; caller `poll_binding_process_descriptor_in_view`, `poll_descriptor/mod.rs:11228-11231` | Claim can stamp a cached decision/session under the wrong zone. | **MUST-GATE** before seed. |
| C5 | Flow-cache preflight, lookup and reclassification | `stage_flow_cache_hit`, `poll_descriptor/flow_cache_hit.rs:139-204`; cache preflight/reclassification `:293-307,586-630,1007-1038` | Claim fences a live session before cache lookup and influences cache validation, eviction, BA/LP selection and output handling; a forged owner claim can evade the foreign-hit path. | **MUST-GATE** before cache lookup or touching the entry. |
| C6 | Fragment-association lookup/install | `frag_ingress_authority_with_nat_scope`, `nat64_install_forward_fragment_assoc`, `nat64_consult_forward_fragment_assoc`, `same_family_or_plain_install_forward_fragment_assoc`, `same_family_or_plain_consult_forward_fragment_assoc`, `poll_descriptor/frag_assoc.rs:42-98,126-220,246-369`; callers `poll_binding_process_descriptor_in_view`, `poll_descriptor/mod.rs:4497-4521,6795-6801,7893-7920,8920-8956` | `FragAuthority` includes the claimed zone/scope; non-first fragments can inherit a cached NAT/rewrite or delivery decision. | **MUST-GATE** before association key creation/lookup. |
| C7 | Fragment-overlap membership/quota partition | `poll_binding_process_descriptor_in_view`, `poll_descriptor/mod.rs:1778-1786`; `frag_ingress_zone`, `poll_descriptor/frag_assoc.rs:92-98`; deferred `retry_pending_neigh`, `neighbor_dispatch.rs:745-756` | Claim partitions overlap admission and quota state; a forged identity can separate or join fragment sets. | **MUST-GATE** before overlap key/accounting. |
| C8 | Screen zone roles and SYN-cookie ACK screen | `screen_zone_roles`, `stage_screen_check_with_ambiguous`, `stage_screen_syn_cookie_ack_on_session_miss_with_ambiguous`, `poll_stages.rs:1010,1100,1599`; flood/ACK callsites `:1133-1141` and `poll_descriptor/mod.rs:1693,4704` | Ambiguous claim contributes a stateless union-veto (extra drop, not extra admit); it can still DoS by naming a screened zone. | **MUST-GATE**; unverified claims never contribute a veto. |
| C9 | SYN-cookie reply admission | `syn_cookie_final_admission_with_fence`, `poll_descriptor/cookie_reply.rs:84-157`; cookie verdict `transit_class_verdict`, `poll_descriptor/session_admission.rs:361-410` | `ingress_zone_override` participates in the cookie-reply zone pair. | **MUST-GATE** before admission. |
| C10 | IKE host-inbound and IPsec local-claim scope/table | `ike_host_inbound_gate_context_with_ambiguous`, `stage_ipsec_passthrough_check_with_scope`, `ipsec_destination_claimed_local`, `poll_stages.rs:1885-1912,2072-2188,2279-2328`; callers `poll_descriptor/mod.rs:1925-1932,2237,2267`; `gate_fabric_zone_override_on_local_owner_rg`, `forwarding/fabric.rs:568-586` | Zone gates local IKE; V2 scope selects the IPsec destination table/local-claim interface. | **MUST-GATE** before either gate or table selection. |
| C11 | Embedded ICMP and NAT64 ICMP reversal | `try_reverse_embedded_icmp_error` / `queue_prebuilt_embedded_icmp_error`, `poll_descriptor/embedded_icmp.rs:85-199,355-513`; `try_translate_nat64_icmp_error`, `poll_descriptor/nat64_icmp_error.rs:38-151,250-275` | Claimed zone/scope selects a quoted-session reversal and effective arrival zone; a forged claim can change related/error authority. | **MUST-GATE** before quoted-session match/reversal and promotion. |
| C12 | PPTP GRE data-channel routing-domain lookup | `pptp_resolve_routing_domain`, `poll_descriptor/mod.rs:158-180`; regression `poll_descriptor/pptp_domain_16055_tests.rs:123-180` | Claim selects the domain used to associate GRE control/data sessions. | **MUST-GATE**; an unverified claim is no claim (existing domain-0 fallback). |
| C13 | General routing-domain/session-key derivation | `ingress_routing_domain`, `forwarding/mod.rs:462-482`; `transit_class_routing_domain`, `poll_descriptor/mod.rs:328-347` | `ingress_zone_override.or(ambiguous_zone)` re-keys the session; contested zones use `AMBIGUOUS_FABRIC_DOMAIN_BASE | zone`. | **MUST-GATE** before deriving/looking up the session key. |
| C14 | PBR / next-table / FBF selection | `ingress_route_table_override`, `forwarding/pbr.rs:89-233`; production callsites in `poll_binding_process_descriptor_in_view`, `poll_descriptor/mod.rs:1887-1901,1978-1992,5277-5290,9099-9112,9371-9384` | Claimed zone and V2 scope choose a policy-routing table/filter, potentially changing destination reachability. Several calls bypass C2. | **MUST-GATE** before every PBR call. |
| C15 | Pre-routing NAT scope | `prerouting_ingress_scope`, `poll_descriptor/prerouting_scope.rs:64-165`; caller `poll_binding_process_descriptor_in_view`, `poll_descriptor/mod.rs:4815-4830` (before C2 shadow at `:5506`) | Claim/scope selects DNAT, static-NAT and NPTv6 source zone/interface/routing-instance matching. | **MUST-GATE** before scope resolution. |
| C16 | Transit source/destination class (martian) checks | `transit_class_verdict`, `transit_source_class_drop`, `transit_destination_class_drop`, `poll_descriptor/session_admission.rs:361-410`; callers in `poll_descriptor/mod.rs:6047-6055,3003-3049,9908-9951,10507-10541`; cache `poll_descriptor/flow_cache_hit.rs:586-630`; retry `neighbor_dispatch.rs:498-506` | Arrival zone chooses the domain in which source/destination class checks run and can cause allow/drop. | **MUST-GATE** on miss/flowless; hit/cache/retry consume only an already verified claim. |
| C17 | CoS BA trust and effective ingress interface | `ba_ingress_trust_for_packet`, `resolve_trusted_ba_class_queue_id`, `tx/cos_classify_ba.rs:33-47,88-129`; producer `stage_classify_fabric_ingress`, `poll_stages.rs:872`; cache hit `stage_flow_cache_hit`, `poll_descriptor/flow_cache_hit.rs:1007-1038` | V2 scope selects peer-unit classifier bindings and queue/LP; cache hits reclassify too. | **MUST-GATE** before setting/using `meta.fabric_ingress_ifindex`; PR-A authenticates scope, PR-B alone carries class. |
| C18 | Pending-neighbor deferred provenance/retry | Store in `poll_binding_process_descriptor_in_view`, `poll_descriptor/mod.rs:13473-13476`; consumer `retry_pending_neigh`, `neighbor_dispatch.rs:210,498-506,621-650,745-756`; fragment drop guard `poll_descriptor/frag_assoc.rs:1559-1562` | A parked packet re-derives routing domain, class, fragment/NAT/overlap decisions from its saved arrival zone. | **MUST-GATE** before parking; retain the verified identity with the request. |
| C19 | Synthetic-source reply and neighbor-learn suppression | `is_synthetic_fabric_source_mac`, `forwarding/fabric.rs:194-210`; `ptb_reply_suppressed`, `icmp_ptb.rs:532-569`; `enqueue_reject_reply`, `poll_descriptor/reject_reply.rs:298`; `enqueue_syn_cookie_reply`, `poll_descriptor/cookie_reply.rs:262,289-295`; `learn_dynamic_neighbor_from_frame` / `learn_dynamic_neighbor_with_mac`, `neighbor_dispatch.rs:1394-1455` | Stamp **shape** suppresses generated replies/neighbor learning only; it cannot admit traffic. | Shape-only **SUPPRESS**. Required-mode stage-9 rejection prevents bad stamped claims reaching these paths; no independent zone verdict is needed. |
| C20 | Fabric-arrival flag side effects | `stage_classify_fabric_ingress`, `poll_stages.rs:844-888`; flood skip `stage_screen_check_with_ambiguous`, `poll_stages.rs:1100-1141`; TTL expiry `packet_ttl_would_expire`, `icmp.rs:194-198`; TTL rewrite plan `rewrite_plan_eth_from_parts`, `frame/mod.rs:1153-1195` | Physical fabric/overlay provenance skips flood re-counting and peer-side TTL handling; this flag is not the claimed zone. | Not a stamp-auth gate. Preserve as transport behavior; explicitly residual for raw unstamped fabric traffic. |
| C21 | Absent/unstamped fabric handling | `parse_zone_encoded_fabric_ingress_from_frame`, `frame/inspect.rs:2950-3042`; fallback in `poll_binding_process_descriptor_in_view`, `poll_descriptor/mod.rs:1458-1462,1628-1656` | No stamp claim; `allow_unstamped_fabric_ingress` and the unique-established-NAT-match exception retain current behavior. | No tag verdict exists. Do not parse trailer-shaped bytes without a stamp prefix; existing policy remains authoritative. |

### 2.1 Closing census for PR-A

Re-run this source census at implementation and classify every production hit:

```sh
grep -rn "ingress_zone_override\\|ambiguous_zone\\|ingress_nat_scope_ifindex\\|fabric_arrival_zone\\|fabric_ingress_scope_ifindex\\|fabric_ingress_ifindex\\|fabric_ingress_zone\\|packet_fabric_ingress\\|fabric_link_ingress\\|FragAuthority\\|ingress_routing_domain" userspace-dp/src/afxdp --include='*.rs' | grep -v tests
grep -rn "ZoneEncodedFabricStamp\\|FabricIngressOutcome" userspace-dp/src --include='*.rs' | grep -v tests
```

The only acceptable result is that every production use maps to C1-C21 or a
new row. The central owner-RG helpers have production callers in
`transit_policy.rs`; that centralization does **not** mean every raw claim
consumer passes through those helpers.
---

## 3. TX seam proof — two late sinks, no single append seam

### 3.1 Stamp origins and all current egress paths

Legacy stamp MACs originate in `forwarding/fabric.rs:758-760` (V1 zone) and
`:819-826` (V2 scope); embedded ICMP re-stamps V1 at
`poll_descriptor/embedded_icmp.rs:677-693`. Paths below are relative to
`userspace-dp/src/afxdp/`. The `build_live_forward_request_from_frame_with_dynamic`
request builder (`forward_request.rs:207,287-333`) selects/preserves the source
marker in `decision.resolution.src_mac`; it is metadata selection, not final
frame assembly. A base fabric redirect at `forwarding/fabric.rs:714-727`
uses the local MAC and is not a stamp claim.

The V2 preserve helper at `forwarding/fabric.rs:853-870` currently accepts
only legacy `02:bf:73`; PR-A must decode `02:bf:75` too, validate the same
scope-map/zone/RG relation, normalize to legacy V2 identity, then let the
finalizer choose the outgoing authenticated marker. In `permissive`, it must
also retain the incoming auth verdict so an invalid/missing claim is never
re-signed (auth-laundered) on a repunt.

The current TX architecture has **two distinct late sinks**, not one universal
append site: `transmit_prepared_queue` (`tx/transmit/mod.rs:501-538`) applies
the staged DSCP rewrite at `:525`, then verifies UMEM slices at `:526`; the
owned-`TxRequest` `transmit_batch` (`:210-319`) applies DSCP at `:277-279`,
checks capacity, then copies to UMEM. PR-A calls the same no-allocation
finalizer after that last DSCP rewrite and before verification/copy at the
appropriate sink. It must update `PreparedTxRequest.len` or `TxRequest.bytes`
length and validate the additional 34 bytes. The output builders split across
these two request types; an implementation that unifies them could replace
the two hooks only if it proves every P1-P8 route passes the unified hook.

| # | Path and exact anchors | Current stamp/frame behavior | PR-A final-byte obligation |
|---|---|---|---|
| P0 | Request-level identity choice: `build_live_forward_request_from_frame_with_dynamic`, `forward_request.rs:207,287-333` | Preserves a validated V2 source MAC or resolves a fresh V1/V2 `src_mac`; no final bytes exist yet. | Carry full `StampContext`, provenance and verdict through the request. Do not tag here; never re-sign an unverified peer claim. |
| P1 | Prepared/direct TCP segmentation: `segment_forwarded_tcp_frames_into_prepared`, `tx/tcp_segmentation.rs:4-19,348-371`; dispatcher `tx/dispatch/mod.rs` | Writes Ethernet, applies NAT/TTL/checksums, and makes a separate prepared UMEM frame per segment. | Carry one context per segment; finalize in `transmit_prepared_queue` after DSCP and before UMEM verification. Segment to fabric MTU minus 34. |
| P2 | Copy TCP segmentation: `segment_forwarded_tcp_frames_from_frame`, `frame/tcp_segmentation.rs:122`; immediate dispatch caller `tx/dispatch/mod.rs:1611-1681`; deferred caller `neighbor_dispatch.rs:970-1010` | Builds an owned frame per segment, applies NAT, and enqueues `TxRequest`; deferred retry currently has no stamped fabric context (§3.2). | Finalize each stamped segment in `transmit_batch` after DSCP; reserve 34 bytes in each owned buffer. Keep the retry negative cell; never mint a claim there without a context. |
| P3 | Dispatch in-place rewrite: `tx/dispatch/mod.rs:1778-1817`; `rewrite_forwarded_frame_in_place`, `frame/mod.rs:1536`; plan/commit `frame/mod.rs:1153,1215` | Rewrites ingress UMEM in place, including NAT and final Ethernet header, then queues prepared TX. | Carry context/space to the prepared sink; finalize after DSCP, update length and check the UMEM chunk bound before verification. |
| P4 | Direct TX: `tx/dispatch/mod.rs:1924-2037` → `build_forwarded_frame_into_from_frame`, `frame/build/mod.rs:28` | Writes into a popped target UMEM frame; NAT is applied inside the builder; queues prepared TX. | Carry context to the prepared sink; finalize after DSCP, update length and include the tail in `tx_frame_capacity()`. |
| P5 | Copy fallback: `enqueue_copy_fallback_frame`, `tx/dispatch/mod.rs:747-820` → `frame/mod.rs:959` / `frame/build/mod.rs` | Builds an owned pooled copy; optional wrappers can change it after the inner builder, then queues `TxRequest`. | Finalize in `transmit_batch` after DSCP; reserve 34 bytes in the pool/buffer up front, with no per-packet growth allocation. |
| P6 | NAT64 forwarding: `build_nat64_forwarded_frames`, `frame/mod.rs:381`; caller `tx/dispatch/mod.rs:764-820`; owned enqueue `:908-930` | Rebuilds IP family/address/ports and may fragment; each translated frame becomes an owned `TxRequest`. | Finalize in `transmit_batch` after DSCP and after translation/final fragmentation; one tag per emitted frame, reduced MTU and 34-byte capacity. |
| P7 | Flow-cache inline hit: `stage_flow_cache_hit`, `poll_descriptor/flow_cache_hit.rs:139,1233-1255`; descriptor writer `apply_rewrite_descriptor`, `frame/rewrite/mod.rs:52-77` | Bypasses `enqueue_pending_forwards`; descriptor and in-place fallback write final Ethernet/IP headers inline, then queue prepared TX. | Carry context in the cached decision/request; finalize at the prepared sink after DSCP. Never cache a per-packet tag. |
| P8 | Prebuilt embedded ICMP: `build_nat_reversed_icmp_error_v4/v6` and `build_snat_outbound_icmp_error_v4/v6`, `icmp_embed/builders.rs:7,186,400,554`; `try_translate_nat64_icmp_error`, `poll_descriptor/nat64_icmp_error.rs:38`; common `queue_prebuilt_embedded_icmp_error`, `poll_descriptor/embedded_icmp.rs:355-513`; prebuilt dispatch `tx/dispatch/mod.rs:1246-1367` | Finished translated frames enter `PendingForwardRequest`, then dispatch as owned `TxRequest`; later egress DSCP rewrite still changes the wire header. | Carry context through queue and dispatch; finalize in `transmit_batch` after DSCP, not in the earlier common queue. Reserve space and append/MAC once per output. |

**Explicit non-paths / deferred obligations:**

- `neighbor_dispatch::retry_pending_neigh` does not currently emit a stamped
  fabric redirect: a resolvable fabric redirect already has the peer MAC and
  does not enter `MissingNeighbor`; retry changes the decision to ordinary
  `ForwardCandidate`. The retry may use P2 TCP segmentation, but no stamped
  context may enter it. Preserve a negative cell. If a future path parks a
  stamped redirect, it must carry `StampContext` and reach a late TX finalizer.
- `tx/dispatch/slow_path.rs:25,81-83` drops unsendable `FabricRedirect`
  fail-closed; it does not reinject a stamped frame.
- Generated reject/SYN-cookie/PTB replies use local egress source MACs and
  are not peer stamp mints (`reject_reply.rs:298`, `cookie_reply.rs:262`,
  `tx/dispatch/mod.rs:596`). Mirror clones go to the analyzer binding, not
  the peer fabric.

**Verdict:** P1-P8 are distinct assembly families split between two late TX
sinks. A shared append/MAC helper is reusable, but it needs one hook per sink;
there is no single current seam. Carry context through all listed request
types and require exactly one post-DSCP finalization for every stamped output.
The stale candidate's assumed “single fabric-redirect build chokepoint” is
refuted. Each path's structural/output cell is required (§10).

### 3.2 Carry metadata once; sign only the final assembled output

At stamp mint, attach a small `StampContext` to the resolution/decision:
`stamp_kind`, full resolved `zone_id_u32`, V2 `scope_id` (zero for V1),
stable `fabric_ordinal`, local `sender_node_id`, direction, the PR-A
absent-class marker, ingress auth verdict, and provenance (`LocallyResolved`,
`VerifiedPeerClaim`, or `UnverifiedPeerClaim`). Propagate it through
`PendingForwardRequest`, `RewriteDescriptor`, cache entries and prebuilt
requests. Never put a punt-time tag in those objects: packet bytes, NAT,
segmentation and NAT64 change later.

There are two late hooks, one for each current TX request type. On the prepared
path, call a shared no-allocation
`finalize_fabric_stamp(out, &mut len, context, current_mode,
current_peer_capability, keyring, wall_minute)` after
`rewrite::apply_dscp_rewrites_to_staged` and before
`verify::verify_umem_slices_for_staged` in `transmit_prepared_queue`
(`tx/transmit/mod.rs:525-526`). It appends in the staged UMEM slice, validates
`offset + len + 34 <= chunk_end`, and updates `PreparedTxRequest.len` before
verification/write. On the owned path, call that same core in
`transmit_batch` after `apply_dscp_rewrite_to_frame` and before its capacity
check/copy (`tx/transmit/mod.rs:277-319`); require 34 bytes of pre-reserved
capacity in `TxRequest.bytes`, append without growth allocation, and update
its length before capacity validation.

At either hook the finalizer reads the **current** immutable mode/capability
state, not a stale request copy. If it emits an authenticated stamp, it first
rewrites the legacy source marker to the distinct authenticated V1/V2 marker
(§4.1), then MACs the final bytes and appends exactly 34 bytes. `disabled`
leaves today's marker/bytes unchanged. `permissive` can sign local claims and
verified incoming claims, but MUST preserve an unverified incoming claim as
legacy marker without a trailer; otherwise it launders an unauthenticated
zone/scope into a valid signature. A capable peer in `required` then drops
that legacy claim. `required` MUST drop a stamped output rather than emit a
legacy claim if provenance is unverified or capability, primary key, clock,
space or PRF is unavailable. No path may enqueue an auth marker without its
trailer or lose `StampContext`.

Every P1-P8 path carries its context to exactly one of these hooks, after all
NAT, family translation, segmentation, fragmentation, TTL/checksum, final
Ethernet and egress-DSCP rewrites. This is one reusable finalizer core, but
two distinct call sites and buffer-boundary contracts, not one common append
seam.

### 3.3 Punt-time vs final wire tuple: punt-time equivalence is disproved

`forward_request.rs:380-408` derives a post-NAT `forward_wire_key` for
output-filter matching, but it is not proof the request frame is the final
wire tuple. P3/P4/P5 apply `decision.nat` inside the rewrite/build;
P1/P2 apply it per segment; P6 synthesizes a translated family/tuple and
fragments it; P8 builders perform embedded reversal, re-NAT or NAT64 before
the prebuilt request is queued. The owned path then applies egress DSCP in
`transmit_batch`; the prepared path applies it in `transmit_prepared_queue`.
`apply_nat_on_fabric` can intentionally suppress some rewrites, so signer
and receiver must bind the bytes actually emitted, not a prediction of
whether NAT will run.

The tag therefore binds the **final wire L2/IP/L4 prefix** (§5), computed
after all NAT, segmentation, family translation, fragmentation, TTL/checksum,
Ethernet and egress-DSCP rewrites for that output frame. The receiver sees
those same wire bytes. NAT-final-tuple cell X1 exercises every applicable
path (including SNAT/DNAT/port rewrite, fabric-NAT suppression, NAT64,
prebuilt embedded errors, egress DSCP and segments); a punt-time tuple design
fails that cell.

### 3.4 Trailer size, MTU and buffer obligations

The 34-byte tail is outside IP-declared length but increases physical Ethernet
frame size and AF_XDP buffer use. Reduce every fabric egress MTU by 34 before
PTB, TCP segmentation and NAT64-fragment decisions, including
`compute_forwarded_egress_ptb[_with_dynamic]`, `forwarded_egress_mtu`,
`forwarded_tcp_may_need_segmentation`, NAT64 MTU helpers and the flow-cache
hit path (`flow_cache_hit_requires_pending_forward`) that can bypass dispatch
PTB. This prevents frames legal at the old MTU from exceeding the peer's
physical MTU.

Every prepared UMEM chunk and owned buffer/pool must have 34 bytes of
pre-reserved tail capacity; neither late hook may allocate per packet. Both
hooks check `len + 34 <= tx_frame_capacity()` and the UMEM offset/chunk bound,
then count/drop oversize rather than truncate. Oversize counters are per-link,
aggregated by stable fabric ordinal. R9/X2 cover both hooks and every P1-P8
route; X3 verifies every resulting segment.

---

## 4. Wire format

### 4.1 Layout (34-byte trailer plus a distinct authenticated marker)

The trailer is fixed-tail, located at `frame.len() - 34`:

```
offset  field
0..4    magic "XPF3"
4       version = 3
5       flags: bit0 class_present (PR-A: always 0); bits1..7 reserved,
        MUST be zero on send and receive (no key-id/key-role hint)
6..10   sender minute-epoch: u32 BE, floor(unix_secs/60) at mint
10..26  tag: 16 bytes (§5, §7)
26..34  class_word: u16 BE || reserved u48; PR-A sends eight zero bytes.
        The exact bytes are MAC-bound; class_semantic_u16 is the absent
        sentinel 0xffff (§5). PR-B can populate the reserved bytes later.
```

Two deliberately different source-marker namespaces are required. The
existing legacy V1/V2 markers remain unchanged only when no authenticated
trailer is sent; an authenticated output replaces them before signing:

| Stamp kind | Legacy marker (still emitted in disabled / eligible permissive fallback) | Authenticated marker (must accompany XPF3) |
|---|---|---|
| V1 full-zone low16 | `02:bf:72:fe:<lo16>` | `02:bf:74:fe:<lo16>` |
| V2 scope24 | `02:bf:73:<scope24>` | `02:bf:75:<scope24>` |

The current parser recognizes only legacy `02:bf:72`/`02:bf:73`
(`frame/inspect.rs:2960-3008`); the new authenticated marker must remain
disjoint so a pre-#18733 receiver cannot mistake an armed sender's frame for a
legacy authenticated stamp. Reserve the proposed `02:bf:74`/`02:bf:75`
prefixes, add them to the new parser/synthetic-source predicate, and reject
configured real local/peer fabric MACs in either reserved prefix. Pin both
their disjointness from legacy markers and the absence of real-MAC ambiguity
in R10/X12. The `docs/log/10105.md:124`
mixed-version requirement is therefore **preserved**, not waived. New
receivers in `disabled` map either authenticated marker back to the same
legacy V1/V2 identity without parsing its trailer; disabled mode expressly
does not claim authentication.

Ethernet/VLAN/EtherType and IP-declared length stay unchanged; the marker
rewrite is within source MAC only. The trailer is outside IP length at the
very end of the AF_XDP frame, not searched for (fixed-tail discipline as
`XPFA`, `pkg/cluster/heartbeat_wire.go:88-96`). A legacy receiver sees the
new source marker as no zone/scope override; it must not treat the trailer as
a legacy identity.

### 4.2 MTU

The trailer adds 34 B on the fabric hop only. **Sender MUST never truncate**:
if `frame_len + 34 > egress binding frame capacity` (UMEM frame /
`tx_frame_capacity()`, `tx/dispatch/mod.rs:84-90`), drop + count
(`fabric_stamp_trailer_oversize_drops`, per-link, aggregated by stable fabric ordinal). Arming `required`
strict-warns when fabric parent MTU − 34 < largest member MTU. Typical jumbo
fabrics are unaffected; a 1500-B fabric pays visibly, in the counter, never
silently.

### 4.3 Receiver parse

Stage 9 recognizes legacy and authenticated V1/V2 marker families on a
fabric link. In `disabled`, it resolves the marker as the legacy claim and
does not read the trailer. In `permissive`/`required`, every recognized
marker is a claimed identity: it locates/parses the fixed trailer, and a
legacy marker or authenticated marker without a valid trailer is `Missing`
(not `Absent`). An authenticated marker without XPF3 is never downgraded to
legacy in `required`. Frames without any marker never have trailer-shaped
bytes interpreted (C21). A new authenticated marker is intentionally
unrecognized by a pre-#18733 parser (R10); that failure is safe no-override,
not seamless interoperability.

---

## 5. Tag input (canonical identity plus final wire tuple)

```
tag = PRF128(K_epoch, DOM || ctx || class_wire[8] || frame_prefix)
DOM        = "xpf-fabric-stamp-v3" (fixed)
ctx        = version(1)=3 || flags(1) || stamp_kind(1: 1=V1, 2=V2)
             || sender_node_id(1: local ConfigSnapshot.node_id)
             || fabric_ordinal(1: explicit configured slot, stable if a link
                is skipped; receiver uses the ordinal of the ingress FabricLink)
             || direction(1: 0=node0→node1, 1=node1→node0)
             || zone_id_u32_be (sender's resolved full zone ID; receiver must
                resolve the same full ID from the marker/scope or fail closed)
             || scope_id_u24_be (V2 scope; 0 for V1)
             || minute_epoch_u32_be
             || class_semantic_u16_be (PR-A: 0xffff means absent)
             || final_frame_prefix_len_u16_be
class_wire = the exact eight bytes at trailer[26..34]; PR-A MUST send zeroes
             and include those zero bytes in the tag input
frame_prefix = final egress bytes from frame[0 .. l3_offset+ip_header_len+8]:
             destination || authenticated source marker || VLAN/EtherType ||
             final IP header (including IPv6 extension/fragment headers) ||
             first 8 bytes after the final IP header; for a non-first fragment
             these are fragment-payload bytes
```

`ip_header_len` is parsed from the final output bytes through the validated
IPv4 header or IPv6 extension chain to the transport/fragment payload; it is
not copied from ingress metadata. Thus the bytes bind final source/destination
addresses, protocol, available ports/ICMP identifiers, fragment identity,
final L2/VLAN, and the direction/link context. This is the final wire tuple,
not the punt-time tuple.

`fabric_ordinal` is not the index of `ForwardingState.fabrics`: add an
explicit 0/1 ordinal to Go `FabricSnapshot` from the primary/secondary
configured fabric slots, preserve it through sort/skip, then carry it into
Rust `FabricLink`. `sender_node_id` is already present in the snapshot but
must be plumbed to the forwarding state; receiver expects the other node in
the supported 0/1 pair and requires `direction` to agree with the sender.
If the same low-16 V1 stamp resolves to different full zone IDs on the two
nodes, the tag fails closed; PR-A requires zone-ID/scope-map parity for
`required`, rather than treating a peer-only alias as authenticated.

The final frame prefix includes the *authenticated* source marker, not the
legacy V1/V2 marker. The exact `class_wire` bytes are MAC-bound even in PR-A;
the absent semantic sentinel is not a claim that the zeroed wire bytes are
`0xffff`. PR-B may populate them only after A; a modified class field then
fails verification. Payload bytes beyond this prefix are deliberately not
authenticated (§8.2).

The minute epoch is also clear in the trailer header so the receiver can
reject stale frames before invoking the PRF; its signed copy in `ctx` makes
editing the clear epoch fail. A sender must not emit if the final frame cannot
provide the required validated header prefix. The receiver verifies every
prefix-matched frame, including non-first fragments; each emitted fragment
has its own tag over its final IP header and first eight fragment-payload
bytes. Fragment association remains an additional stateful decision, not a
substitute for per-frame tag verification.

---

## 6. Verification placement, failure mode and observability

### 6.1 Stage-9 verification (all stamp consumers, hits and misses)

Stage 9 recognizes both legacy and authenticated V1/V2 markers. In
`disabled` it resolves either marker using the legacy claim and never reads
the trailer. In `permissive`/`required`, it validates the fixed tail, version,
zero reserved bits, zero PR-A class bytes, epoch and tag; a recognized marker
with no trailer is `Missing`, not `NoClaim`. It records
`stamp_auth: Disabled | NoClaim | Verified | Missing | Malformed | BadTag |
StaleEpoch | KeyUnavailable | ClockUnavailable`, plus the stable ingress
ordinal in `FabricIngressOutcome`. Run the full PRF for every marked frame in
`permissive`/`required`: C2-C18 consume claims on paths before the session-miss
gate, so miss-only verification is unsound.

### 6.2 Mode semantics at the verdict boundary

- `disabled`: no trailer read/PRF/auth counter; exact legacy adjudication for
  legacy markers, and the authenticated marker decodes to the same V1/V2
  claim without asserting authentication.
- `permissive`: compute/count a verdict for every marked frame, but preserve
  legacy claim adjudication even for missing/bad/stale/key/clock failures.
  A repunted unverified inbound claim must remain legacy and untagged; signing
  is allowed only for a local claim or a previously verified peer claim.
  Measurement only; not safe against the third-speaker threat.
- `required`: only `Verified` marked claims proceed to any claim consumer.
  Missing, malformed, bad-tag, stale, unavailable-key or unavailable-clock
  claims are terminally dropped at stage 9 before session/cache/fragment/
  policy/screen/PPTP/IKE/CoS use. An unmarked frame is not a claim and remains
  governed by existing `allow_unstamped_fabric_ingress`/other controls;
  `required` does not silently add a stamp requirement to every packet.

At TX, `required` also drops a stamped output rather than sending an
unauthenticated legacy claim when peer capability, primary key, wall clock,
capacity or PRF is unavailable (§3.2). `permissive` can still emit the
legacy marker in those cases. These are asymmetric and deliberate: local
receive enforcement never downgrades, and required TX never signs with the
additional key or falls back to a raw claim.

Authentication does not replace owner-RG rules: a verified ambiguous claim
still requires the existing `promote_ambiguous_fabric_zone` predicate, and
IKE still requires local owner-RG proof. Conversely, an invalid claim cannot
contribute the screen union-veto. No hit/cache/fragment path gets a bypass.


### 6.3 Failure accounting — per fabric link, never aggregate-only

Add per-link counters carried through binding status and aggregated by the
stable configured fabric ordinal, then exported with a bounded `fabric` label
(at most the configured two links). `BindingStatus` itself is per binding,
not per link; aggregation must preserve the ordinal and keep fab0/fab1
independently visible. Add Prometheus descriptors beside
`pkg/api/metrics_descriptors_userspace_drops.go:270-287` and extend the Go/Rust
binding status schema beside `pkg/dataplane/userspace/protocol_binding.go:118-120`.

| Per-link counter/status | Meaning |
|---|---|
| `fabric_stamp_auth_verified_total` | Valid tags; no key or raw tag logged. |
| `fabric_stamp_auth_missing_total` | Recognized marker with no valid trailer. |
| `fabric_stamp_auth_malformed_total` | Wrong version/length/reserved/class shape. |
| `fabric_stamp_auth_bad_tag_total` | Tag mismatch against all accepted bases. |
| `fabric_stamp_auth_stale_epoch_total` | Epoch outside the accepted window. |
| `fabric_stamp_auth_key_unavailable_total` | No usable local verification/signing base. |
| `fabric_stamp_auth_clock_unavailable_total` | Wall clock unavailable for epoch/tag. |
| `fabric_stamp_auth_required_drops_total` | Required RX terminal drop, by bounded reason. |
| `fabric_stamp_auth_send_drops_total` | Required TX drop when auth cannot be emitted, by bounded reason. |
| `fabric_stamp_auth_unverified_accepted_total` | Permissive legacy claim accepted without a valid tag. |
| `fabric_stamp_trailer_oversize_drops_total` | Egress cannot fit trailer/reduced MTU. |

`show chassis cluster status` (`pkg/cluster/status.go:14` `FormatStatus`)
adds one row per configured fabric ordinal above the node table (format
position discipline at `:71-80`): local mode, peer capability
(`yes/no/unknown`), primary/key readiness without key material, and the
verified/missing/malformed/bad/stale/clock/required-RX/required-TX/oversize
counters. A single aggregate line is insufficient: a fab1-only failure must
not hide inside fab0 traffic.

---

## 7. Cryptography

### 7.1 Threat model (unchanged from #16023, restated for the tag)

Attacker: third L2 speaker on the fabric segment; observes frames, injects
arbitrary Ethernet frames, and replays captured frames. It does **not** hold
`chassis cluster authentication-key` or compromise either cluster node (a
node compromise owns every channel that key protects — out of scope). Asset:
the receiver's zone/scope adjudication and its binding to the final tuple
prefix (§2, §5). The tag proves that a cluster peer holding the cluster key
asserted that identity for this final egress tuple. It does **not** prove
full-payload integrity or make the stamp a full-frame MAC (§8.2). Out of
scope: confidentiality; non-repudiation (signatures stay rejected,
`docs/log/10105.md:77-109`); L2 DoS; replay inside the accepted window; raw
unstamped-fabric behavior when `allow_unstamped_fabric_ingress` permits it.

### 7.2 Key derivation — derived bases, never raw PSK

Use the existing SYN-cookie key plumbing as the precedent, not as evidence
that the stamp PRF is fast:

- **Go derivation**: a new `pkg/dataplane/userspace/fabric_stamp_key.go`
  derives `base = HMAC-SHA256(PSK, "xpf-fabric-stamp\x00v1-base\x00" ||
  len32BE(identity) || identity)`, with the established
  `identity = "cluster-id=<id>"` framing. The source patterns are
  `screens.go:594-683` (`buildSYNCookieKeys`, `synCookieKeyMaterial`,
  `deriveSYNCookieBase`) and the corresponding KATs
  `syncookie_key_9173_test.go:200-223`. This is a new domain label; do not
  claim it is already in use.
- Derive primary from `ControlLinkAuthKey`; derive `ControlLinkAuthKeyAlt`
  as `accept_only=true`. A primary signs; an additional key is **accept
  only, never sign**, matching `pkg/cluster/manager.go:1120-1146`,
  `heartbeat.go:996-998`, and `screens.go:594-614`. The stamp wire has no
  key-id/hint; the receiver tries the at-most-two configured bases.
- **Snapshot**: add a distinct `FabricStampKeyBaseSnapshot { base,
  accept_only }` with a redacted secret wrapper, following
  `SynCookieKeyBaseSnapshot` (`userspace-dp/src/protocol/snapshot.rs:583-592`).
  Go sends only derived bases; Rust must never receive the raw PSK. Rust
  fields are deserialize-only and `skip_serializing`, like
  `syn_cookie_key_ring` (`snapshot.rs:895-901`); `Debug`, status, logs and
  errors reveal neither base nor tag.
- **Snapshot and digest hygiene**: the Go→Rust `ConfigSnapshot` carries only
  these derived bases in its secret field (and only while mode is enabled);
  the raw cluster PSK is never in the snapshot. Rust must redact bases when
  reserializing state (`skip_serializing` as for `syn_cookie_key_ring`,
  `snapshot.rs:895-901`). `builder.go:500-520` replaces visible SYN-cookie
  secrets with per-daemon-start salted HMAC fingerprints before JSON hashing.
  Add the stamp bases to that same redaction path: the snapshot content-digest
  input contains only a purpose-separated salted HMAC fingerprint of each
  base, never raw PSK/base bytes or an unsalted hash. Extend
  `helperVisibleSecretDigest9161` (`manager_overlay.go:630-681`) with those
  enabled-mode primary/additional bases so a helper-visible rotation cannot
  be coarsened away by `configsContentEqual`. Extend
  `protocol_wire_fixture_completeness_16132_test.go`'s
  `goOnlyKeys["ConfigSnapshot"]`, audit map and `secretWireKeys`; the current
  census does not list the SYN-cookie ring in `secretWireKeys` (it is covered
  by the Go-only map/audit). The cell proves: no raw PSK in any snapshot;
  derived bases only in Go→Rust secret carriage, absent from fixtures/status/
  Rust reserialization/digest preimage; salted snapshot digest changes on
  base rotation.
- **Rust key use**: carry ≤2 decoded bases into forwarding state at the
  snapshot build. Sign with the primary only; verify against every accepted
  base with constant-time tag comparison. Cache epoch keys per base/minute;
  do not derive/allocate them per packet.
- **Identity/ordinal plumbing**: snapshot `node_id` exists, but
  `ForwardingState` does not contain it (`protocol/snapshot.rs:966-974`,
  `types/forwarding/state.rs:64`). Likewise `FabricSnapshot.name` is lost
  when `FabricLink` is built (`userspace-dp/src/afxdp/forwarding/fabric.rs:114-124`).
  PR-A must plumb the local node ID and an explicit primary/secondary fabric
  ordinal into the output and input forwarding state (§5).
- **Domain separation**: the new base and tag labels are independent of
  heartbeat HMAC (which signs the heartbeat frame plus auth nonce,
  `heartbeat_wire.go:647-683`), fabric gRPC token (`fabric_auth.go:148,
  300-320`), key-id tag (`control_key_rotation.go:78`), sync Noise PSK and
  SYN-cookie base label (`screens.go:662-670`). The PSK remains a shared
  secret; derived bases are still secrets, not publishable identifiers.

### 7.3 PRF candidates

The in-tree `SipHash24` is a 64-bit SipHash-2-4 implementation
(`userspace-dp/src/screen/syncookie.rs:624-741`), not a ready-made 128-bit
function. Candidate A is two domain-separated 64-bit outputs over the same
tag input (`...-t0` and `...-t1`, matching the two-domain MAC pattern at
`syncookie.rs:346-371`), concatenated to 128 bits. Candidate B is AES-CMAC
with a 128-bit epoch key and a full 128-bit output. Derive each epoch key as
`HMAC-SHA256(base, "xpf-fabric-stamp\x00v1-epoch\x00" ||
minute_epoch_u32_be)[..16]`, once per minute/key, not per packet.

Before G-PRF, an implementation spike must build both candidates against the
same production-shaped input and API. For SipHash, prove reuse of the in-tree
64-bit primitive with two domain-separated outputs and constant-time compare.
For AES-CMAC, name and review the maintained implementation/dependency, its
constant-time tag check, CPU-feature dispatch/fallback and its allocation
behavior. Both candidates need Go/Rust key/epoch/tag KATs and no-allocation
finalizer integration. Reject a candidate with no accepted implementation;
do not turn a library or feature-detection unknown into an unmeasured
performance assumption. The implementation/library choice is a spike gate,
not an already-made algorithm decision.

### 7.4 The measurement gate (implementation-blocking)

No workstation estimate selects the algorithm. The existing source's
“tens of nanoseconds” SipHash comment is explicitly provisional
(`screen/syncookie.rs:71-75`); the HMAC/Ed25519 numbers in
`docs/log/10105.md:86-88` are not measurements of either candidate over this
input. Record no present-day PRF result as measured.

**G-PRF** must run in Rust on both the loss and TCP cluster nodes (with
`loadavg` and CPU model recorded, per `docs/log/10105.md:143-219`):

1. Benchmark sign and verify over the exact §5 input for V1/V2, IPv4/IPv6,
   extension-header, fragment, NAT64 and maximum supported prefix shapes.
   Verify both primary-only and primary+additional worst case. Include
   output assembly, not just the primitive.
2. Budgets: (a) median single-base verify and sign each ≤250 ns; two-base
   verify ≤500 ns; (b) with authentication `required`, measured sustained
   packet rate at the declared fabric load (64-byte and 1500-byte frames,
   session hits and misses) loses no more than 5% vs `disabled` on either
   cluster; (c) tag append/verify allocates nothing and reads no OS clock per
   packet; (d) segmented output adds ≤250 ns per segment. Measure the real
   full stage-9 path because authentication is per stamped packet, not at
   miss-only rates.
3. **Decision rule**: use the two-pass SipHash candidate only if it meets
   every budget on both nodes. Choose AES-CMAC only if SipHash fails and
   AES-CMAC meets every budget on both nodes, with its implementation,
   CPU-feature detection and fallback documented. If both fail, K2 fires:
   return to the seats for a different placement/design; do not soften the
   consumer gate or claim workstation performance predicts the lab.
4. PR-A is not mergeable without the harness and recorded G-PRF results.

---

## 8. Freshness, replay, rotation

### 8.1 Minute epoch and wall-clock steps

The trailer carries `floor(UNIX_seconds/60)` as `u32`; receiver acceptance
is inclusive **±5 minutes**. The poll loop's `now_secs` is monotonic
(`worker/loop_body/mod.rs:542,715`), so it cannot validate this wall epoch.

Add a per-worker cached wall clock, following the established SYN-cookie
pattern: sample `SystemTime` at most once per monotonic second, derive the
wall epoch from that cached value, then latch
`current_epoch = max(previous_epoch, raw_wall_epoch)` while the worker lives.
The precedent is `screen/mod.rs:696-723` and
`screen/syncookie.rs:595-598`; `screen/tests.rs:3930-3959` pins that wall
time, not monotonic seconds, determines the epoch. No per-packet syscall,
allocation or shared atomic is allowed. Before UNIX epoch / on unavailable
wall time, the signer emits no authenticated trailer and `required` fails
closed with a visible clock-unavailable verdict.

- A forward wall step can make legitimate peer epochs stale until the
  sender/receiver clocks converge; count and expose the drops, never fall
  back to unauthenticated acceptance.
- A backward step cannot lower the in-process latch, so it does not reopen
  old epochs while that worker lives. The latch is not durable across process
  restart; a reboot plus backward wall step can widen the replay interval
  until the clock recovers, an explicit residual.
- Existing cluster operation already depends on NTP: fabric gRPC uses a
  30-second window and accepts current ±1 (`pkg/cluster/README.md:1385-1388`);
  the current clock monitor warns at 15-second local offset and documents
  the 30-second inter-node bound (`README.md:1452-1465`). The stamp's
  ±5-minute window is wider, not a substitute for that clock alarm.

### 8.2 Replay scope (explicit)

**PR-A rejects stale replay after the ±5-minute window. It does not provide
per-frame anti-replay within the window.** A captured valid trailer can be
replayed while fresh, but it cannot be transplanted onto a different bound
zone/scope, link, direction, or final tuple. The tag authenticates the
claimed identity and the §5 header/tuple prefix, not every payload byte after
that prefix; it is not a full-frame MAC. Duplicate/replayed packets and
payload bytes outside the authenticated prefix are residuals, not silently
claimed as protected.

Per-packet sequence/nonce, a sharded receiver replay window and failover
high-water transfer are not in PR-A. If seats require them, K3 must re-cost
the `AtomicU64`/42-byte trailer and transfer semantics before implementation;
do not quietly add that state mid-flight. The ±5-minute epoch is the selected
bounded replay horizon.

### 8.3 Key rotation (#6630, accept-never-sign)

Stamp auth follows the existing primary/additional semantics:
`additional-authentication-key` is verify-only and never signs
(`control_key_rotation.go:20-33`; `manager.go:1120-1146`;
`heartbeat.go:996-998`). There is no wire key hint; the receiver tries the
primary, then the at-most-one accept-only additional base. An additional-only
or missing-primary local config cannot sign; `required` never substitutes a
process secret or silently disables verification.

PR-A's key-preservation rule (§8.4) makes both auth leaves node-local, so the
five #6630 steps are applied to **each node**, not propagated from the primary:

1. node0 adds B as additional (sign A; accept A+B).
2. node1 adds B as additional (sign A; accept A+B).
3. node0 makes B primary and A additional (sign B; accept B+A).
4. node1 does the same.
5. after both sign B, remove A from node0, then node1 (operator finalize).

The retiring additional base stops verifying on the next local snapshot;
the existing 7-day stale-window alarm remains `control_key_rotation.go:107-117`.
The role of the key is never selected by a trailer bit or by attacker input.

### 8.4 Peer-pushed key-clear protection (current gap and PR-A decision)

At this head, `handleConfigSyncWithAncestry` passes
`preserveNodeLocalChassis(...)` (`pkg/daemon/daemon_ha_sync.go:1089-1097`),
but `nodeLocalChassisLeaves` contains only `strict-session-auth`
(`daemon_ha_node_local_7441.go:91-95`). Its contract explicitly says the PSK
is still cluster-wide synced state (`:38-42`). The #6630 comment that the
production caller passed `nil` is stale; the current hook is present but does
not preserve either auth-key leaf or the new stamp mode. `SyncApply` patches
then promotes the received tree (`pkg/configstore/store.go:1310-1345`), and
the peer compile is lenient; the strict auth-key check does not prevent a
peer push from clearing the key (`compiler_validate_strict_cluster_auth.go:
326-329`). Current state therefore has **no peer-pushed key-clear protection**.

PR-A decision: make primary key, additional key, and
`fabric-stamp-authentication` local posture. Extend the node-local preservation
contract used at `handleConfigSyncWithAncestry` to preserve their exact
set/absent values in both directions; a tree with no local key must not adopt
one from the peer. Provision both nodes locally before enabling stamp auth.
Because `security flow` is outside the current chassis-only path, add its
narrow preservation path explicitly rather than pretending the existing
chassis list already covers it. Normalize the parsed peer tree through these
preservation rules **before** the duplicate/equivalence fast path too, or a
primary's different key/mode will cause endless re-applies even though the
effective local config is unchanged.

The migration consequence is intentional: config-sync no longer rotates
these three leaves. Operators apply the #6630 sequence and each mode change
on both nodes. Add cells proving peer-push attempts cannot clear, set or
replace local auth keys/mode; strict local commits remain the only way to
change them. This is the explicit #6629/#6630 local-provisioning posture, not
“lenient absence is safe.”

### 8.5 Capability advertisement and mixed-version behavior

- Add `capFlag2FabricStampAuth = 1<<4` to the existing second capability
  byte: first-byte bits are full; second-byte bits 0-3 are used
  (`pkg/cluster/sync_fence_ack_7147.go:146-232`). Advertise it through
  `syncMsgPeerCapabilities` (`sync.go:151-166`; send layout
  `sync_conn_write.go:997-1050`). It means “this peer build understands the
  authenticated marker/trailer,” not “this peer has a key” or “this peer is
  in `required`.” No heartbeat/session-sync schema or `HAProtocolVersion`
  bump is needed; the capability record is additive.
- Capability is peer-incarnation scoped and clears on reconnect, downgrade
  or boot switch (`sync_peer_incarnation.go:167-211`;
  `sync_failover_recv.go:268-271`). Carry the current bit into
  `FlowSnapshot`; every transition must force a snapshot publish even if
  ordinary `ActiveMatches`/`ForceUnchanged` dedup suppresses it. The final TX
  helper reads the current mode/capability snapshot, not a stale bit copied
  into a pending request.
- Emission:
  - `disabled`: legacy source marker, no trailer.
  - `permissive`: authenticated marker+trailer only for a local or previously
    verified peer claim when peer capability, primary key, clock and space
    are usable; otherwise legacy marker (never re-sign an unverified claim).
  - `required`: authenticated marker+trailer under those same conditions;
    otherwise drop/count the stamped output. Never downgrade TX.
- Reception is controlled only by local mode. In `disabled`, authenticated
  markers decode as legacy claims; in `permissive`, all claims are verified
  and counted but retain legacy adjudication; in `required`, only a verified
  claim is usable. Capability never relaxes RX enforcement.

| Sender ↓ / receiver → | Old build/helper | New `disabled` | New `permissive` | New `required` |
|---|---|---|---|---|
| Old sender (legacy marker, no trailer) | Today | Today | Legacy claim accepted, `missing` counted | Missing claim drops |
| New sender, peer not capable | `disabled`/`permissive` sends legacy; `required` drops | Today | Legacy claim accepted, `missing` counted | Missing claim drops; local required TX also drops |
| New sender, peer capable | If a stale/raced capability ever sends auth marker, old parser sees no stamp override (R10) | Auth marker maps to legacy claim; no trailer read | Verify/count; no enforcement | Verified claim accepted; missing/bad/stale drops |

The normal rollout prevents a new sender from emitting an auth marker to an
old peer because the old peer cannot advertise the bit. The distinct marker
still makes a stale-capability race fail as no-override at an old receiver,
not as a forged legacy zone claim (`docs/log/10105.md:124`). Snapshot v77
helpers refuse v78 before receiving mode/key data
(`server/handlers/snapshot.rs:25-32`, `protocol/control.rs:305-343`); this
local helper ABI fence is separate from peer capability.

## 9. Modes, config plumbing, snapshot, advisory interaction

### 9.1 One leaf, three modes

```
set security flow fabric-stamp-authentication disabled|permissive|required
```

- Schema: `pkg/config/schema_security.go:1404`; compiler:
  `pkg/config/compiler_security_flow.go:900-902`; type:
  `pkg/config/types_security.go:284-289`. Use one string enum, not two bools.
- Default is **`disabled`**. Default `required` breaks old peers during
  rolling upgrade; default `permissive` accepts unauthenticated claims and
  only measures them. Existing #10105 private-L2/attestation guidance stays
  the default until an operator opts in, matching the existing attestation
  leaf's default-off posture (`types_security.go:288`).
- Semantics are exact:
  - `disabled`: preserve legacy marker/adjudication and do no auth work.
  - `permissive`: verify/count, but retain the legacy claim on every auth
    failure. Sign only local or previously verified peer claims when
    capability, primary key, clock and space are usable; otherwise send the
    legacy marker. Never launder an unverified inbound claim.
  - `required`: reject unauthenticated marked claims at RX and drop a stamped
    TX output if the authenticated envelope cannot be emitted. It does not
    require a stamp on every unmarked fabric packet.
- Strict commit rejects enabling `permissive`/`required` without a two-node
  cluster and primary `authentication-key`; additional-only is invalid.
  Lenient snapshot/config load with missing key remains fail-closed in
  `required` and visible as key-unavailable, never process-secret fallback.
  The leaf is node-local under §8.4.
- Plumb `FlowSnapshot.fabric_stamp_auth_mode` (`u8` 0/1/2), derived bases
  (only when mode is enabled), and peer capability to Rust
  `ForwardingState`. Mode changes use the normal snapshot, no latch or durable
  state.

### 9.2 Snapshot v77 → v78 exact lockstep

| Change | File |
|---|---|
| `CONFIG_SNAPSHOT_PROTOCOL_VERSION = 78` + changelog | `userspace-dp/src/protocol/control.rs:343` |
| Go `ProtocolVersion = 78` | `pkg/dataplane/userspace/protocol.go:530` |
| Go `FlowSnapshot`: mode, derived-base ring, current peer-capability bit | `pkg/dataplane/userspace/protocol.go`: `FlowSnapshot` type starts `:1335`; existing attestation bool is `:1339`, keyed fields belong beside it. |
| Rust mirrors: mode, secret ring, peer bit; redacted/deserialize-only bases | `userspace-dp/src/protocol/snapshot.rs`: `FlowSnapshot` starts `:385`; existing attestation field is `:398`, keyed fields belong beside it. |
| Snapshot-shape and version golden | `snapshot_shape_version_8892_test.go:702` |
| Lockstep pin | `scoped_global_zoneset_protocol_5488_test.go:378` |
| Secret-wire census | `protocol_wire_fixture_completeness_16132_test.go`: Go-only key map, audit map and secret-key census |
| Capability update bypasses snapshot dedup | `snapshotRefreshDecision`, `ForceUnchanged`, `ActiveMatches` call chain in Go publisher; capability transition forces publish |

The existing `snapshot.node_id` is plumbed into Rust `ForwardingState`;
Go's fabric snapshot's configured slot is copied explicitly into `FabricLink`
as `fabric_ordinal`. Raw `authentication-key`/additional key never enter the
wire. Exact Go/Rust v78 equality refuses an old helper that cannot honor
`required` mode; the v69 fence precedent is `control.rs:305-308`.

### 9.3 Interaction with existing controls (#10105/#18719/#18751)

- `require-authenticated-fabric-stamps` (link attestation) and keyed mode
  are independent trust roots. Keep the V0 attestation gate's exact semantics
  (`forwarding/fabric.rs:431-433`): `required` still requires a valid keyed
  verdict; link attestation does not substitute. This design explicitly
  decides **NO either-root-admits**.
- #10105's reminder is acknowledged only by existing private-link/attestation
  conditions or keyed mode `required`; `permissive` is not safe and must not
  silence it. Add the new required posture to
  `pkg/config/compiler_fabric_stamp_10105.go:14-54` per-link acknowledgment.
  Add the mode to `pkg/config/advisory_scope_18719.go:69-79` fingerprint so
  toggling/removing it re-emits the change-scoped reminder. The private flag
  by itself remains documentation, not authentication.
- #18751's third-speaker monitor stays complementary and unchanged. It cannot
  see forged xpf-namespace sources (`docs/fabric-cross-chassis-fwd.md:
  1606-1608`); authenticated markers close that stamp-claim blind spot only.
- The strict cluster config requires a primary key (#6611). Standalone/no
  cluster cannot arm either active mode; process-local cookie secrets are
  never repurposed as a cross-node stamp key (`screens.go:631-637`).

### 9.4 Rollout and rollback

1. Upgrade both nodes with Go/Rust v78 paired locally; leave mode `disabled`.
   Verify each node has the locally provisioned primary key and that each
   peer-incarnation capability is `yes`. Do not arm `required` while either
   capability is `no/unknown`.
2. Apply `permissive` on **both nodes** (node-local commit). Verify per-link
   `verified` counters rise on legitimate inter-chassis traffic; the
   unverified-accepted counter remains visible for legacy/misconfigured
   senders. `permissive` with no peer capability emits legacy markers.
3. Set `required` on both nodes after the capability and key checks; one
   node may be armed first because a `permissive` peer already emits a valid
   trailer to a capable receiver. Watch per-link missing/bad/stale/clock/TX
   drop counters through at least one epoch window.
4. If a required node finds a capability/key/clock mismatch, it drops
   stamped TX and marked RX claims; operator rollback is local mode to
   `disabled` or `permissive`, not a silent fallback.
5. Code rollback requires compatible daemon/helper versions on each node;
   snapshot v78 refuses v77 helper pairing. Disable both modes before
   rollback. No replay latch or persistent state needs unwinding.
---

## 10. Cells (implementation acceptance; names are the contract)

Existing decisive cell to mirror:
`forged_stamp_drops_when_link_authentication_required_16023`
(`tests_fabric_zone_stamp.rs:177-252`, both placements, fail-on-revert).
Classes: **U** hermetic (workstation/CI), **R** live-cluster only.

### 10.1 Candidate R1–R10, re-anchored at current master

| # | Cell / current anchor | Class | Decisive acceptance |
|---|---|---|---|
| R1 | `forged_stamp_drops_when_link_authentication_required_16023`, `tests_fabric_zone_stamp.rs:177-252` | U | Extend both existing split-RG/all-local placements to `required`: forged legacy V1/V2 marker and forged authenticated marker/no tag drop at stage 9 before session lookup/install/forward; forged tag transplanted across zone/scope drops `BadTag`. |
| R2 | New `fabric_stamp_auth` parser/KAT module; source parser `frame/inspect.rs:2950-3042` | U | Flip every bound field (authenticated source marker, L2/VLAN bytes, resolved zone, scope, ordinal, direction, sender, final IP/ports/fragment tuple, epoch, flags, class bytes), truncate/misplace XPF3, or corrupt its tag: `required` drops. Control: changing only TCP payload beyond the authenticated prefix still verifies by design; pin this as the explicit non-full-frame-MAC residual (§8.2). |
| R3 | Go derivation `syncookie_key_9173_test.go:200-223`; Rust epoch KAT `screen/tests.rs:9221-9225`; rotation model `control_key_rotation.go:20-33` | U | Exercise all five #6630 steps on each locally provisioned node: accept primary/additional during overlap, sign primary only, accept new primary after swap, reject retired additional after finalize; Go/Rust base, epoch and tag KATs match. |
| R4 | `legitimate_fabric_punted_host_inbound_still_admitted_6458` (`tests_fabric_zone_stamp.rs:992-1026`); `legitimate_fabric_punted_flow_still_admitted_6458` (`:1138-1169`); `co_moved_punt_admitted_when_all_data_rgs_local_15916` (`:1184-1266`); `co_moved_v2_scoped_stamp_is_ambiguous_without_scope_15916` (`:1329-1371`) | U | Valid local V1/V2 claims in host-inbound, split-RG, all-local/co-moved, and scoped V2 placement verify then retain today's owner-RG result under `permissive` and `required`; authenticated markers preserve scope on repunt. |
| R5 | `session_hit_authority.rs:180-214,399-483`; descriptor hit site `poll_descriptor/mod.rs:1463-1473` | U | Forged owner claim cannot turn a foreign session hit into `Owner`; in required it drops before hit adjudication. A valid tag still follows the existing foreign-hit rule; no unsigned hit exception. |
| R6 | Fragment authority `frag_assoc.rs:42-98,126-402`; current fragment cells `tests_fabric_zone_stamp.rs:5482-5569` | U | A valid first fragment installs the association only after tag verification; bad/missing first or non-first fragment drops before lookup/install, even if a matching association exists. Every emitted fragment has its own verified tag. |
| R7 | Wall clock precedent `screen/mod.rs:696-723`; PR-A clock cell | U | Inject ±5-minute inclusive boundaries, +6-minute stale, forward step then recovery, backward step (latch never decreases), unavailable clock, and restart with a backward wall clock. No per-packet OS clock; restart-reset residual is explicit. |
| R8 | Capability `sync_fence_ack_7147.go:146-232`; incarnation `sync_peer_incarnation.go:167-211`; snapshot v77 fence `snapshot.rs:25-32` | U | Cover old→new legacy missing (permissive counts/required drops), new→old no emission, peer-incarnation revoke/downgrade/boot-switch forcing current snapshot publish, raced auth marker no-override at old parser, and v77 helper refusal by v78. |
| R9 | Egress capacity `tx/dispatch/mod.rs:84-90`; MTU/segmentation obligations §3.4 | U | Near-capacity frame/segment at every P1-P8 output: include 34-byte tail in space and effective MTU; `required` drops/counts oversize, never truncates or emits a legacy fallback. |
| R10 | Old parser `frame/inspect.rs:2950-3042`; legacy marker constants in `forwarding/fabric.rs` | U | Pre-#18733 parser sees `02:bf:74`/`02:bf:75` as absent/no zone override even with XPF3 tail; it never mistakes an armed frame for legacy V1/V2. New `disabled` maps those markers to the matching legacy claim without reading the tail. Reject actual configured local/peer fabric MACs in those prefixes. |

### 10.2 One decisive cell per census row (§2)

All rows below are separate hermetic cells; no consumer is “covered” only by
the central session-miss test.

| Census row | Decisive cell and required assertion | Class |
|---|---|---|
| C1 stage-9 classifier/drop | `c1_stage9_terminal_before_fanout`: forged/malformed marked frame increments terminal auth drop and produces no session/cache/fragment/screen/policy side effect (`poll_stages.rs:848-888`, terminal `poll_descriptor/mod.rs:1449-1453`). | U |
| C2 session miss / policy / NAT / host-inbound | `c2_miss_policy_zone_is_gated`: forged claim that would change an allow/NAT/host-service result drops; verified claim retains existing policy and owner-RG result (`transit_policy.rs:54-107`). | U |
| C3 session-hit authority | `c3_foreign_hit_cannot_be_forged_owner`: forged owner-zone marker cannot reclassify a foreign hit; valid tag retains existing hit policy (`session_hit_authority.rs:180-214,399-483`). | U |
| C4 flow-cache seed | `c4_bad_claim_cannot_seed`: forged tuple matching a seedable flow installs no cache entry (`flow_cache_seed.rs:32-65,240-282`). | U |
| C5 cache preflight/hit/reclassification | `c5_bad_claim_drops_before_cache_touch`: prove no lookup, validation, eviction, BA/LP reclass or output decision runs on bad tag (`flow_cache_hit.rs:139-204,586-630,1007-1038`). | U |
| C6 fragment association | `c6_fragment_claim_is_per_frame`: bad/missing first and non-first tags drop before association creation/lookup; verified fragments use existing `FragAuthority` (`frag_assoc.rs:42-98,126-402`). | U |
| C7 overlap/quota partition | `c7_bad_claim_cannot_partition_overlap`: invalid claim reaches neither overlap membership nor quota accounting (`poll_descriptor/mod.rs:1778-1786`; `frag_assoc.rs:92-98`). | U |
| C8 screen zone roles / SYN-cookie ACK | `c8_unverified_claim_no_screen_veto`: invalid ambiguous claim cannot add #16051's union-veto drop or charge cookie screen state; valid claim retains today's screen behavior (`poll_stages.rs:1010,1100,1133-1141,1599`). | U |
| C9 SYN-cookie reply admission | `c9_cookie_reply_requires_verdict`: forged claimed zone cannot admit a cookie ACK; valid claim preserves current cookie-pair verdict (`cookie_reply.rs:83-157`). | U |
| C10 IKE / IPsec local scope | `c10_ike_and_ipsec_scope_gated`: forged claim cannot pass local IKE zone/owner-RG or select V2 IPsec local table; verified scope still resolves (`poll_stages.rs:1885-1912,2133-2177`; `poll_descriptor/mod.rs:1925-1932`). | U |
| C11 embedded ICMP / NAT64 reversal | `c11_bad_claim_no_icmp_reversal`: forged claim cannot select quoted-session reversal or effective arrival scope (`embedded_icmp.rs:78-199,538-606`; `nat64_icmp_error.rs:51-151,250-275`). | U |
| C12 PPTP GRE domain | `c12_bad_claim_domain_zero`: forged GRE claim resolves domain 0/no association; verified stamp resolves its configured domain (`poll_descriptor/mod.rs:1519-1531`; `pptp_domain_16055_tests.rs:123-180`). | U |
| C13 general routing domain/session key | `c13_bad_claim_no_session_key`: bad tag drops before deriving the zone/domain session key; verified tag selects the exact domain (`poll_descriptor/mod.rs:1615-1626`; `forwarding/mod.rs:462-482`). | U |
| C14 PBR/next-table/FBF | `c14_bad_claim_no_pbr`: forged V1/V2 claim cannot select any production `ingress_route_table_override` path; verified claim retains configured PBR (`forwarding/pbr.rs:89-233`; callers `poll_descriptor/mod.rs:1887-1901,1978-1992,5277-5290,9099-9112,9371-9384`). | U |
| C15 prerouting NAT scope | `c15_bad_claim_no_prerouting_nat`: invalid claim cannot choose DNAT/static-NAT/NPTv6 source zone/interface/routing instance (`prerouting_scope.rs:64-165`; caller `poll_descriptor/mod.rs:4815-4830`). | U |
| C16 transit martian/source-destination class | `c16_bad_claim_no_martian_override`: invalid zone cannot alter source/destination class result on miss/flowless admission; hits/retries use only previously verified provenance (`session_admission.rs:361-410`; `neighbor_dispatch.rs:498-506`). | U |
| C17 CoS BA trust/effective ingress | `c17_only_verified_v2_sets_scope`: invalid V2 drops before assigning peer `fabric_ingress_ifindex`; valid tag preserves peer BA selection, while PR-A class remains absent/local fallback (`cos_classify_ba.rs:33-47`; `flow_cache_hit.rs:1007-1038`). | U |
| C18 pending-neighbor provenance | `c18_unverified_never_parked`: invalid claim cannot enter `PendingForwardRequest`; verified zone/verdict survives a legitimate deferred retry and cannot be re-derived from raw bytes (`poll_descriptor/mod.rs:13473-13476`; `neighbor_dispatch.rs:498-506,621-650,745-756`). | U |
| C19 reply/neighbor-learn suppression | `c19_shape_only_never_admits`: known stamp-shaped source still suppresses generated PTB/reject/cookie/neighbor-learn only; a bad marked packet is already terminally dropped and suppression never grants a zone (`fabric.rs:194-210`; `icmp_ptb.rs:532-569`; `neighbor_dispatch.rs:1416-1417,1453-1455`). | U |
| C20 fabric-arrival flag side effects | `c20_transport_flag_not_auth`: invalid marked packet stops before later flood/TTL/reply effects; raw unmarked fabric arrival keeps existing physical-provenance behavior. The flag itself never becomes a claim verdict (`poll_stages.rs:877-879`; `icmp.rs:195-198`; `frame/mod.rs:1186-1189`). | U |
| C21 absent/unstamped handling | `c21_absent_not_trailer`: unmarked frame with XPF3-shaped tail is `NoClaim`, never trailer-parsed; existing `allow_unstamped_fabric_ingress` and unique-established-NAT exception remain unchanged (`poll_descriptor/mod.rs:1458-1462,1628-1656`). | U |

### 10.3 Cross-cutting cells

| # | Cell / assertion | Class |
|---|---|---|
| X1 | **NAT-final-tuple**: receiver verifies the final bytes for SNAT, DNAT, port rewrite, fabric-NAT suppression, NAT64, prebuilt embedded ICMP, egress DSCP and every segment/fragment; punt-time tuple tags fail. | U |
| X2 | **All TX paths**: exercise P1-P8 and prove each reaches exactly one of the two post-DSCP hooks; detect bypass/double-finalization, marker rewrite, length/capacity failure and per-path drops. | U |
| X3 | **TCP segmentation**: every direct/prepared and copy segment verifies independently; no segment uses a parent-frame tag. | U |
| X4 | **Neighbor retry negative**: `retry_pending_neigh` does not accept a `FabricRedirect`/stamp context today; prove no stamped fabric frame emits on retry. Any future path must add a separate finalizer arm. | U |
| X5 | **Capability/incarnation**: bit set enables auth marker only after snapshot publish; disconnect/downgrade/boot-switch clears it and required TX drops; stale capability cannot survive snapshot dedup. | U |
| X6 | **Secret/digest hygiene**: raw PSK absent everywhere; derived bases only in Go→Rust secret carriage, redacted from fixture/status/echo; `snapshotContentHash` preimage contains only per-start-salted HMAC fingerprints, while internal `helperVisibleSecretDigest` follows the existing one-way SHA-256 derived-key precedent (§7.2). | U |
| X7 | **Peer-push protection**: config sync cannot clear, set or replace either local auth key or mode; normalized duplicate push causes no repeated apply (§8.4). | U |
| X8 | **Third-host live proof**: a physically separate third host on a switched fabric VLAN forges R1 in split-RG and all-RGs-local placements with `required`; DROP and per-link counters move, while legitimate split-RG traffic forwards. Record loss + TCP cluster, both placements and load. | **R — lab only** |
| X9 | **G-PRF measurement**: record both candidates and full-path budgets on the loss/TCP cluster nodes (§7.4). | **R — lab only** |
| X10 | **Observability/advisory**: fab0/fab1 failures remain separate in status/metrics; `required` acknowledges #10105, `permissive` does not, and changing/removing mode re-emits the #18719-scoped reminder. | U |
| X11 | **No permissive auth laundering**: bad/missing/stale inbound claim repunted in permissive leaves legacy marker/no trailer; verified incoming or local claim may be signed; a required peer drops the unverified repunt. | U |
| X12 | **Marker namespace reservation**: configuration rejects actual local/peer fabric MACs beginning `02:bf:74` or `02:bf:75`; legacy `02:bf:72`/`02:bf:73` and new authenticated markers remain distinct in parser and synthetic-source classification (§4.1). | U |

No clusters are run by this design lane; X8/X9 are implementation gates.

---

## 11. #18734 forwarding class — authenticated placeholder only in PR-A

- PR-A reserves trailer bytes 26..34 and MAC-binds all eight bytes, but
  always sends them as zero, sets `class_present=0`, and uses semantic
  `class_semantic_u16=0xffff` for “absent.” It does not populate, parse as a
  forwarding class, or act on class. This makes later carriage possible
  without an unauthenticated class surface or a second wire-version change.
- PR-B is #18734 only and may begin **after PR-A lands**. Its design can write
  a resolved post-BA/post-ingress-filter class (queue ID + loss-priority) in
  the reserved bytes; egress firewall/`forwarding-class` remains final
  (#14663), and only a verified class may affect queue selection. Unknown IDs
  fall back locally and never drop. PR-B must define its own cells for
  egress queue, filter precedence and tag tampering; none of that carriage is
  implemented or required for #18733 closure.

---

## 12. Sequencing, closure, PLAN-KILL

### 12.1 PR-A (#18733 only)

Only the keyed identity stamp is in scope:

- Snapshot v78 lockstep (§9.2); Go derivation and secret/digest hygiene
  (§7.2); Rust codec/PRF module; stage-9 parse/verdict before every C1-C21
  consumer; local node ID/fabric ordinal; primary-only signing and
  accept-only additional key.
- Mint metadata at `forwarding/fabric.rs:758-760,819-826`, preserve validated
  V2 scope on repunt at `forward_request.rs:287-333`, then wire the shared
  finalizer into P1-P8 (§3). Reserve distinct `02:bf:74`/`02:bf:75`
  authenticated markers; never sign a permissive unverified peer claim.
- Add config mode, local key/mode push-preservation, capability bit and
  snapshot publication; per-link counters/status; wall-clock epoch and
  required TX/RX fail-closed behavior.
- R1-R10, each C1-C21, X1-X12 and G-PRF are acceptance gates. G-PRF lab
  measurements precede merge. No PR-B class field behavior.

Complexity cap: one Rust auth module plus plumbing; G-PRF alone selects the
PRF implementation. If SipHash wins, share/move the existing 64-bit
`SipHash24` into a `pub(crate)` home and do not duplicate it. If AES-CMAC
wins, implementation/library, CPU-feature detection, constant-time behavior,
KAT and fallback require explicit spike/review acceptance; do not invent a
128-bit SipHash variant. Keep legacy V1/V2 marker bytes unchanged whenever no
authenticated envelope is emitted; authenticated output uses new markers.
No eBPF, userspace-XDP shim or heartbeat-wire change; no `StableZoneID`
change.

### 12.2 Three plan-seat questions (each has a proposed decision)

1. **Replay:** accept the minute epoch with ±5-minute window and no
   per-frame replay state (including exact in-window replay), or require K3
   sequence/transfer semantics before PR-A? Proposed decision: accept the
   bounded replay residual; full-frame/payload integrity is not claimed.
2. **Node-local key posture:** accept primary/additional auth keys and
   `fabric-stamp-authentication` as locally provisioned/preserved leaves,
   rotated and mode-armed independently on both nodes (§8.4)? Proposed
   decision: yes; an authenticated peer push must not clear/change a
   receiver's key or disarm required mode. If seats reject this, stop and
   redesign sync authority rather than shipping the current unprotected
   peer-push path.
3. **Terminal default:** is `disabled`-by-default plus explicit operator
   `required` rollout the accepted terminal posture for #16023? Proposed
   decision: yes, with X8 live proof. If field data/default-on is required,
   file that follow-up and leave #16023 open until it is resolved.

Attestation interaction is not a seat question: keyed `required` remains
required even when the link is attested; the trust roots are independent.

### 12.3 #16023 closure criteria

Close #16023 only after all of the following:

1. PR-A (#18733 only) has landed with v78 lockstep, all hermetic cells and
   the recorded G-PRF gate. #18734 class carriage is not folded into PR-A.
2. X8 records a third host physically separate from the cluster on a
   **switched** fabric VLAN. With `required`, forged claims drop in both
   split-RG and all-RGs-local placements; per-link counters move; legitimate
   split-RG traffic forwards on the loss and TCP clusters.
3. Seats accept the terminal default in Q3. If not, file the exact default
   change as a follow-up and keep #16023 open until that work and proof land.

PR-B (#18734) may start after PR-A, but it is a separate class-carriage
change and neither substitutes for nor blocks the #18733 third-host proof.

### 12.4 PLAN-KILL alternatives

- **PK-A — accept the interim as terminal.** Decide #10105's
  document-and-constrain plus #16023 link-attestation/private-L2 opt-in and
  #18751 detector are sufficient. Close #16023 as PLAN-KILLED with the
  switched-fabric shared-L2 residual explicit; do not claim #18733 was
  implemented or that the third-host spoof is blocked.
- **PK-B — reject the appended trailer, continue research.** If marker,
  compatibility or measured cost gates fail, reject this wire design but
  keep #16023 open; continue with a distinct authenticated envelope/placement
  or a MACsec-terminating fabric design. Do not patch around a failed gate by
  accepting the old legacy marker as authenticated.

### 12.5 Kill criteria (any one ⇒ stop and return to seats)

- **K1 — census:** any additional production consumer of stage-9 identity
  appears outside C1-C21 and cannot be gated before use; do not ship
  miss-only verification.
- **K2 — cost:** neither PRF meets G-PRF on both cluster nodes, or the full
  stage-9 required path exceeds the 5% throughput budget.
- **K3 — replay:** seats require per-packet anti-replay; re-cost sequence,
  shared state and failover high-water transfer before code.
- **K4 — TX seam:** any stamped egress path exists outside P1-P8 or any path
  can send after its finalizer; redesign rather than patching opportunistically.
- **K5 — key plumbing:** raw PSK reaches Rust, a secret base appears in the
  digest preimage, or the v78 fence is skipped.
- **K6 — old receiver:** R10 shows a pre-#18733 parser recognizes an
  authenticated marker as legacy V1/V2. Capability gating alone is not a
  substitute for the distinct-marker requirement.
- **K7 — scope/provenance:** V2 `02:bf:75` repunt cannot preserve the validated
  scope, or permissive mode can re-sign a missing/bad/stale peer claim.
- **K8 — peer push:** primary/additional key or mode can be cleared/replaced
  by sync after local provisioning; redesign the protection before required
  mode is allowed.

### 12.6 Migration, rollback and residuals

Migration is §9.4. Roll back a node's mode to `disabled` (or
`permissive`) locally; the finalizer reads current snapshot state, so queued
requests cannot keep an obsolete auth decision. `disabled` TX returns to
legacy source markers/no trailer, and a new disabled receiver decodes an
authenticated marker as the same legacy claim without verifying it. Required
mode never silently falls back. For code downgrade, daemon/helper pairing
must be compatible on each node; the v78 exact-equality fence rejects v77
helper pairing. Keys/mode remain local across config sync.

Residuals after rollout are explicit: exact replay within ±5 minutes,
payload bytes beyond the authenticated tuple prefix (not a full-frame MAC),
raw unmarked fabric traffic under existing `allow_unstamped_fabric_ingress`,
L2 denial of service, compromise of a node/cluster PSK, and a backward wall
clock step across process restart. Required mode fails closed on capability,
key, clock, capacity or PRF failure, with availability loss visible by link.

---

## 13. Stale-candidate corrections (input `wt-16023/docs/log/16023.md` @ `fed39c4bc1`)

| Candidate claim / omission | Re-derived at `6c9098dcfb` |
|---|---|
| Snapshot v77 → v78 | Still exact: Rust `userspace-dp/src/protocol/control.rs:343`, Go `pkg/dataplane/userspace/protocol.go:530`; PR-A must bump both in lockstep. |
| One fabric-redirect build chokepoint | Refuted: P1-P8 split across two TX sink hooks; invoke the shared finalizer once after DSCP at the appropriate sink (§3). |
| Punt-time pre-NAT tuple is identical on wire | False: NAT, segmentation, NAT64 and embedded ICMP transform after request construction; sign final output bytes (§3.3/§5). |
| 26-byte trailer; class not on wire | Replaced by 34-byte XPF3 trailer with MAC-bound reserved class bytes (§4.1/§11). |
| Preserve V1/V2 source MAC and append tag | Unsafe for mixed versions: `docs/log/10105.md:124` requires a distinct non-legacy marker for an armed sender. PR-A uses `02:bf:74`/`02:bf:75`; old parser recognizes only `02:bf:72`/`02:bf:73` (`inspect.rs:2960-3008`). |
| `FabricIngressOutcome` is `(present, epoch, tag)` | Current six fields include override, NAT scope, fabric provenance, invalid, ambiguous zone and ambiguous scope (`poll_stages.rs:73-80`); PR-A adds an auth verdict/ordinal, not the stale tuple. |
| Consumer list is complete after session-miss gate | False: C1-C21 includes hit/cache, fragments/overlap, screen/cookie, IKE/IPsec, ICMP, PPTP/domain, PBR, prerouting NAT, martian, CoS, deferred and shape/provenance rows. |
| Single unauthed-drop counter | Replace with per-link verified/missing/malformed/bad/stale/clock/required-RX/required-TX/oversize counts and per-link status (§6.3). |
| Current anchor examples | Parser `inspect.rs:2950-3042`; disposition `forwarding/fabric.rs:411-451`; stage 9 `poll_stages.rs:844-888`; Go key precedent `screens.go:594-683`; Rust SipHash `screen/syncookie.rs:624-741`; Rust KAT `screen/tests.rs:9221-9225`; Go KAT `syncookie_key_9173_test.go:200-223`. |

---

## 14. Non-goals

No code, no cluster runs, no PR in this lane. No change to #10105/#16023/
#18719/#18751 landed behaviour before PR-A. #18734 class semantics are
PR-B's design surface (§11 reserves only the bytes). Confidentiality,
signatures, per-packet sequencing (unless K3), and MACsec implementation
remain out of scope.
