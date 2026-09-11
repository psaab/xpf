# Native GRE In The Userspace Dataplane

## Goal

Move GRE and `ip6gre` transit traffic fully onto the Rust userspace dataplane on
the physical NIC path.

That means:

- decapsulate GRE on the physical WAN AF_XDP ingress path
- run policy, session, NAT, and forwarding on the inner packet in Rust
- encapsulate GRE on the physical WAN AF_XDP egress path
- stop depending on `gr-0-0-0` for transit forwarding

The current `gr-0-0-0` netdevice may still exist for host-originated/control-plane
handoff, but it must not be the transit dataplane path.

## Status

Implemented on the native GRE branch:

- logical tunnel endpoint snapshots and route resolution
- native GRE decapsulation on physical NIC ingress
- native GRE encapsulation on physical NIC egress
- tunnel-aware session sync so synced userspace sessions preserve tunnel context
- ingress PBR steering into tunnel routing-instances
- tunnel-zone visibility preserved for policy evaluation
- userspace XDP now keeps outer GRE on the physical NIC path when native GRE is enabled
- tunnel netdevices are no longer userspace ingress interfaces for transit
- live isolated-cluster GRE transit validation now passes:
  - `cluster-userspace-host -> 10.255.192.41` ping succeeds
  - outer GRE packets move on `ge-*-0-2.80`
  - `gr-0-0-0` transit RX/TX deltas stay at zero

Validated on the native GRE branch:

- clean post-deploy isolated-cluster validation after primaries re-elect
- transit TCP connect from `cluster-userspace-host` to `10.255.192.41:22` works
- transit `iperf3 -c 10.255.192.41` stays up without zero-throughput intervals
- active GRE failover from `node1 -> node0` now recovers and passes the native
  GRE validator tail gate
- active GRE failover from `node0 -> node1` now recovers and passes the native
  GRE validator tail gate
- manual `request chassis cluster failover redundancy-group 1 node ...` keeps
  the single-stream `iperf3` flow alive in both directions with no
  zero-throughput intervals
- clean bidirectional failover validation on the isolated userspace cluster:
  - `PREFERRED_ACTIVE_NODE=0 ... --deploy --failover --count 3`: pass
  - `PREFERRED_ACTIVE_NODE=1 ... --failover --count 3`: pass

Now validated beyond basic transit:

- local-origin tunnel handoff works through a persistent TUN anchor on the active
  firewall without reintroducing kernel GRE transit
- firewall-originated ICMP and TCP connect to `10.255.192.41` work on the active
  node
- firewall-originated single-stream `iperf3` over GRE stays up on the active node
- post-failover firewall-originated ICMP and TCP connect still work on the new
  active node
- full `--failover --udp --traceroute --iperf` validation is now green on the
  isolated userspace cluster for `node0 -> node1`

Still required for full migration parity:

- final cleanup of remaining hybrid tunnel assumptions outside transit forwarding
- broader repeated failover/failback stress with the expanded native GRE gates
- explicit post-failover firewall-originated `iperf3` stress beyond the current
  single validation run

Current blocker:

- a broader simultaneous multi-RG move is still stricter than the exact RG1
  manual failover case and remains a separate follow-up if we want that covered
- firewall-originated GRE currently depends on the persistent TUN anchor and is
  not yet a fully TUN-free host-origin path

## Why This Is Necessary

The current tunnel path is hybrid:

- userspace owns Ethernet AF_XDP ingress/egress
- Linux tunnel devices do GRE decap/encap
- legacy XDP/TC/kernel glue handles tunnel exceptions and return traffic

That hybrid split is the source of the current failure mode:

- outer GRE reply reaches the WAN NIC
- decapsulated inner packet appears on `gr-0-0-0`
- the return packet does not reliably re-enter the intended BPF/userspace
  reverse-NAT path

As long as transit depends on Linux tunnel devices:

- tunnel decap timing is kernel-owned
- tunnel ingress hooks are split across XDP, TC, and kernel routing
- reverse-path bugs remain hard to reason about

Native GRE in userspace removes that split.

## Non-Goals

- ESP/XFRM in pure userspace
- replacing Linux routing for control-plane protocols
- deleting tunnel config syntax from the control plane

This is only about plaintext GRE/ip6gre dataplane transit.

## Current Baseline

Today the code explicitly treats tunnels as non-userspace transit:

- [manager.go](../pkg/dataplane/userspace/manager.go)
  says tunnel interfaces are handled by the eBPF pipeline
- [afxdp.rs](../userspace-dp/src/afxdp.rs)
  forces tunnel egress to slow-path so the kernel handles encapsulation
- [tc_main.c](../bpf/tc/tc_main.c)
  bypasses tunnel egress because kernel tunnel encapsulation happens after TC

So the required work is architectural, not a small bugfix.

## Target Architecture

### 1. Replace Tunnel Netdevices With Logical Tunnel Endpoints

Do not model GRE transit as “forward to Linux interface `gr-0-0-0`”.

Instead model GRE as a logical egress object in the userspace forwarding state:

- `TunnelEndpointId`
- outer family: IPv4 or IPv6
- outer source and destination addresses
- GRE key / checksum / sequence options if configured
- inner routing-instance / zone binding
- tunnel MTU / effective payload MTU
- outer egress resolution policy

Routes should point to a logical tunnel endpoint, not a kernel tunnel ifindex.

### 2. Ingress Decapsulation On Physical NICs

On AF_XDP ingress for physical WAN bindings:

1. parse outer Ethernet
2. parse outer IPv4 or IPv6
3. detect GRE protocol
4. parse GRE header and optional key
5. validate tunnel endpoint match
6. strip outer headers in userspace
7. produce an inner packet plus tunnel metadata
8. continue through the normal userspace session/policy/NAT path

The decapsulated packet should carry metadata like:

- `ingress_tunnel_id`
- `outer_src_ip`
- `outer_dst_ip`
- `gre_key`
- `tunnel_zone`
- `tunnel_routing_table`
- `meta_flags |= META_FLAG_TUNNEL`

The inner packet should never need to appear on `gr-0-0-0` for transit.

### 3. Egress Encapsulation On Physical NICs

When the forwarding resolution selects a tunnel endpoint:

1. perform policy/session/NAT on the inner packet first
2. compute outer route using the configured outer transport routing-instance
3. resolve outer next-hop MAC on the physical egress interface
4. prepend outer IPv4/IPv6 + GRE header in Rust
4a. enforce the outer MTU before emitting (see "Outer MTU / DF guard")
5. transmit the final encapsulated packet through the physical NIC AF_XDP TX path

This replaces the current “mark as `MissingNeighbor` and hand to kernel
slow-path because tunnel AF_XDP TX does not exist”.

#### Outer MTU / DF guard (#2331)

`encapsulate_native_gre_frame` (userspace-dp/src/afxdp/gre.rs) writes
the IPv4 outer with `DF=1` (#1440), and the IPv6 outer cannot be
fragmented in-path either. So once the full outer datagram is sized —
`outer IP + GRE header (incl. the optional 4-byte key) + inner packet`
(the `gre_encapped_outer_len` helper; the L2 eth/VLAN header is NOT part
of the MTU budget) — the builder compares it against the resolved
transport/egress MTU via `tunnel_outer_mtu` (forwarding/mss.rs, the
#2300 SSOT used by the inner MSS clamp and `native_gre_inner_mtu`: real
transport ifindex → stored-resolution egress → endpoint logical ifindex,
`unwrap_or(1500)`). If the outer exceeds that MTU the frame is **not
emitted**: it would be a downstream blackhole (NIC/router drop, no PMTUD
signal back to the inner source). The drop bumps
`GRE_ENCAP_DF_OVERSIZE_DROPS`, surfaced as the Prometheus counter
`xpf_userspace_gre_encap_df_oversize_drops_total`.

A nonzero counter flags inner flows whose encapped size exceeds the
tunnel path MTU — typically a missing/too-high inner MSS clamp
(`native_gre_tcp_mss`), or a non-TCP inner (UDP/ICMP/ESP) with no
segmentation lever.

#### Post-transform PMTUD (#2330, closes the #2331-deferred signal)

The inner-source PTB that #2331 deferred is now generated in the TX
dispatcher (`tx/dispatch/mod.rs`). #2301's plain-forward PTB compared the
SOURCE frame against the egress MTU — correct only for a size-preserving
forward — and deliberately excluded `!uses_native_tunnel` / `!is_nat64`
because the source-vs-egress check produces a FALSE PTB for a transformed
path (the frame grows on encap / changes header size on NAT64). #2330
replaces that exclusion with a PRE-build `post_transform_inner_mtu`
decision: it derives the INNER MTU (the largest inner IP packet whose
TRANSFORMED frame fits the egress/transport MTU) from the same SSOT this
guard uses —

- **GRE**: `native_gre_inner_mtu` (== `tunnel_outer_mtu − outer_ip − gre`,
  the exact inverse of this guard's comparison),
- **WireGuard**: `wg::mss::wg_inner_mtu` (pad-aware, the inverse of
  `frame::wg::wg_encapped_size`),
- **NAT64**: the egress MTU ± 20 for the v6↔v4 header delta (RFC 7915),

— and runs the existing `forwarded_egress_mtu_decision` + ICMP builders
(`build_frag_needed_v4` / `build_packet_too_big_v6`) against the inner
`source_frame` (the pre-encap / pre-translate inner packet, `meta`'s
family = the inner family). The PTB carries the inner MTU and routes
through `classify_generated_reply` (#2328) at the finalizer, identically
to the plain path.

Coordination with this drop guard: when a PTB is owed (inner IPv4 DF or
IPv6) the decision sets `mtu_signalled` and SKIPS the encap build, so
`GRE_ENCAP_DF_OVERSIZE_DROPS` is NOT bumped — no double-drop / double-
count. The guard's drop+count now fires only for the residual case where
no PTB is owed (a non-DF IPv4 inner, `ForwardOversizeNoDf`; this dataplane
does not fragment it before encapsulation, #9758) whose encapped outer
still exceeds the DF-set transport MTU. Inner TCP-segment sizing remains #2329.

### 4. Session Model

Sessions must represent both:

- inner flow identity
- tunnel transport context

For GRE transit, the session key should remain the inner flow key.
The tunnel should be part of the forwarding metadata, not the primary session key.

Recommended session additions:

- `tunnel_endpoint_id`
- `tunnel_ingress`
- `tunnel_egress`
- `outer_routing_table`
- `outer_ifindex`
- `outer_vlan_id`
- `outer_neighbor_mac`
- `gre_key` when configured

That lets a reply flow continue without recomputing tunnel selection from scratch.

### 5. NAT Semantics

NAT remains an inner-packet decision.

Correct order:

1. decapsulate outer GRE
2. parse inner flow
3. apply session hit / reverse-NAT / policy / NAT
4. route inner packet
5. if next-hop is a tunnel, encapsulate the rewritten inner packet

Do not NAT the outer GRE transport headers except where explicitly configured
by transport policy. The normal case is inner-packet NAT only.

### 6. HA / Fabric Semantics

Tunnel endpoint ownership must be explicit in userspace state.

Required behavior:

- if the logical tunnel endpoint belongs to an inactive RG on this node,
  fabric-redirect before encapsulation
- synced sessions must carry tunnel endpoint metadata, not only plain egress
  ifindex/NAT fields
- failover pickup must preserve tunnel egress information so the new owner can
  encapsulate immediately

Without that, the same HA parity gap reappears in another form.

### 6a. Tunnel-Kind Segregation & Fail-Closed Dispatch (#2327)

`state.tunnel_endpoints` is a MIXED-KIND table: GRE/`ip6gre` and
WireGuard rows coexist (and future kinds may be added). Two invariants
keep that table from crossing security boundaries:

- **GRE decap is kind-segregated.** `match_tunnel_endpoint`
  (`afxdp/gre.rs`) resolves a received proto-47 outer tuple ONLY through
  `state.gre_decap_index` — a per-build index that contains ONLY
  `mode == "gre"`/`"ip6gre"` endpoints, keyed by the endpoint's own
  `(outer_family, source, destination)` and queried with the frame's
  mirrored `(addr_family, outer_dst, outer_src)`. A GRE frame whose
  outer tuple/key happen to collide with a WireGuard (or any non-GRE)
  row is NEVER decapsulated as GRE — it finds no GRE candidate and is
  dropped / falls through. The candidate list per bucket disambiguates a
  duplicate outer tuple by GRE key instead of a non-deterministic
  first-match scan, and replaces the former per-packet O(N)
  `tunnel_endpoints.values().find(...)` linear scan (agy #4). A
  per-candidate `tunnel_mode_kind` re-check is kept as defense in depth.
- **Egress encap fails closed on an unknown mode.** The egress
  dispatcher (`afxdp/frame/mod.rs`) matches on the typed `TunnelKind`
  (`afxdp/forwarding_build/tunnels.rs::tunnel_mode_kind`): `WireGuard` →
  WG encap, `Gre` → native GRE encap, and `Unknown`/missing-row → DROP.
  The pre-#2327 `_ => GRE` arm fail-OPEN-encapsulated any unrecognized
  or future mode as GRE; that is now a drop, matching the appliance's
  fail-closed parser doctrine. Add a new tunnel kind in exactly one
  place — `tunnel_mode_kind` — and the dispatcher will keep failing
  closed until the new arm is added deliberately.

### 6b. Inner-L4 Minimum-Header Bounds On Decap (#2376)

`parse_inner_protocol_and_offsets` (`afxdp/gre.rs`) builds the synthetic
inner metadata (`protocol`, `l4_offset`, `payload_offset`) for the
decapsulated inner. The inner is first trimmed to its IP-declared total
length (`packet_trimmed_len`), so an inner whose declared length ends
before its L4 header survives to the parse.

**That trim is bounded by the OUTER datagram, not by the frame (#6748).**
`packet_trimmed_len` keeps the inner extent inside the slice it is given,
and until #6748 that slice ran to the end of the FRAME — so a peer that
appended a trailer past the outer IP datagram AND inflated the inner IP
Total Length to cover it had those out-of-datagram bytes promoted into
the decapsulated packet. The frame length is not a bound worth having
here: `raw_frame` is the AF_XDP descriptor length, `classify_metadata`
performs no length validation at all, and the XDP shim declares
`tot_len`/`payload_len` in its header structs but never reads either.
`outer_datagram_end` now computes the authoritative end once — IPv4 Total
Length, or 40 + IPv6 Payload Length, refused rather than clamped when it
exceeds the capture — and the GRE option-field skips and the inner
extraction both run on `frame[..outer_end]`. An inner header that reaches
past it is refused, not trimmed: it is lying about the datagram it
arrived in. An HONEST inner under ordinary trailing padding still decaps
byte-identically, which is the negative control that separates this from
rejecting padded frames outright.

The bound was not new — `gre_checksum_region` already applied it, and
said why (item 2 of the flag-handling list below). It was applied to the
checksum only, so checksummed GRE got an incidental outer-length sanity
check that non-checksummed GRE did not; that asymmetry is what made #6748
an oversight rather than a design choice. Both now share one computation
rather than two possibly-divergent notions of "outer end".

Inner TCP was always length-validated (the IHL + 20-byte TCP-header
check). UDP, ICMP, and ICMPv6, however, advanced the payload offset by 8
unconditionally — with NO check that the inner actually contained the
8-byte L4 minimum header (RFC 768 UDP, RFC 792 ICMP, RFC 4443 ICMPv6).
A malformed inner (e.g. IPv4 `total_len = ihl + 2`, `protocol = UDP`)
therefore left decap with internally inconsistent metadata: `protocol`
claiming UDP/ICMP while `l4_offset`/`payload_offset` were derived from —
and pointed past — bytes that are not a real L4 header. Decap is a
trusted chokepoint that reinjects the synthetic frame into the worker
pipeline (`poll_descriptor`), so every downstream consumer of
`meta.protocol`/`l4_offset`/`payload_offset` (policy, logging, slow-path,
generated-reply) then operated on a packet shape that should have failed
closed.

The fix mirrors the TCP guard for the other three protocols: IPv4 UDP/
ICMP require `packet.len() >= ihl + 8`, IPv6 UDP/ICMPv6 require
`packet.len() >= rel_l4 + 8`, and `parse_inner_protocol_and_offsets`
returns `None` (no decap / drop) otherwise. A well-formed GRE-tunneled
UDP/ICMP inner still decaps and stamps correct ports (anti-over-reject).

This is **distinct from #2361**: #2361 hardened the live frame parser
(`parse_session_flow_from_frame`) so it no longer fabricates ports from
bytes past the IP-declared length, so a *ported SessionFlow* is no longer
produced from a short inner. #2376 is narrower — the synthetic inner
*metadata* (`protocol`/`l4_offset`/`payload_offset`) stamped by the GRE
decap stage itself, which #2361 did not touch.

### 6c. Checksum-Present GRE On Decap (#2782)

The GRE flags word (`afxdp/gre.rs`) carries optional-field bits per RFC
2784 + RFC 2890: Checksum-Present (`C`, 0x8000), Routing-Present (`R`,
0x4000), Key (0x2000), Sequence (0x1000). When a bit is set its field
appears in a FIXED order right after the 4-byte flags/protocol word:
**Checksum (2B) + Reserved1 (2B), then Key (4B), then Sequence (4B)**.

`try_native_gre_decap_from_frame` already skipped the Key and Sequence
fields to locate the inner payload, but it previously rejected the
Checksum (and Routing) bit outright — `return None` the instant `C` was
seen, BEFORE the field was even parsed. That made any checksummed peer
(notably a **vSRX with GRE checksum enabled**) an **uncounted silent
blackhole**: the frame was dropped with no `show` reason and no counter.

The fix handles the `C` bit like the other optional fields, and adds the
RFC-2784 checksum validation the bit implies:

1. When `C` is set, the 4-byte Checksum+Reserved1 field is FIRST — skip
   it (advance the inner offset by 4) before Key/Sequence, with a
   bounds-check so a header truncated past the field fails closed.
2. The 16-bit Checksum is the IP-style one's-complement checksum of the
   **GRE header + payload** (checksum field counted as-is; a conformant
   frame folds to 0). The region is bounded by the OUTER IP length
   (`gre_checksum_region`) so trailing Ethernet min-frame padding is not
   folded into the sum — folding pad would spuriously fail valid frames.
3. A frame whose checksum does NOT verify is a **counted** drop:
   `GRE_DECAP_CHECKSUM_INVALID_DROPS` → the Prometheus counter
   `xpf_userspace_gre_decap_checksum_invalid_drops_total`. A valid
   checksummed frame decaps normally (router-interop / vSRX parity).

The **Routing-Present (`R`) bit stays a drop** — the Source Route Entry
list is variable-length with no fixed offset and is effectively dead on
the modern Internet; parsing it is out of scope.

### 6d. Post-Decap Single-Authoritative-Buffer Invariant (#5140)

`stage_native_gre_decap` returns a **synthetic inner frame** (a fresh
`owned_packet_frame: Vec<u8>` = 14-byte synthetic Ethernet + inner
packet) together with an inner meta whose `l3_offset`/`l4_offset` are
**inner-relative** (`l3_offset = 14`, `l4_offset = 14 + inner IHL`). The
original `raw_frame` (the UMEM slice for `desc`) stays the **outer**
encapsulated frame. The worker binds

```
let packet_frame = owned_packet_frame.as_deref().unwrap_or(raw_frame);
```

so `packet_frame` is the inner frame after a GRE decap and the live
`raw_frame` otherwise. **After decap, `meta` offsets are authoritative
ONLY against `packet_frame`.** Indexing the outer `raw_frame` with an
inner-relative offset reads the wrong bytes.

This bites hardest on an UNTAGGED underlay: the inner `l4_offset`
(`14 + 20 = 34` for a 20-byte inner IPv4 header) lands EXACTLY on the
outer GRE flags byte (`eth 14 + outer IP 20 = 34`). The GRE flags low
bits (Recur / reserved) are attacker-controllable and ignored by the
decap parser (only C/R/K/S/version are checked), so `raw_frame[34]` is an
attacker-seeded byte. Reading it as an "ICMP type" can misclassify an
ordinary inner ICMP echo (type 8) as an exempt error/PMTUD control
message — bypassing the host-inbound admission gate on a ping-less zone
(`is_icmp_host_inbound_global_accept`, #3171) or the `allow-embedded-icmp`
policy-check exemption.

The rule, enforced in `poll_descriptor/mod.rs` +
`poll_descriptor/flow_cache_hit.rs`: every post-decap INNER read uses
`packet_frame` —

- the host-inbound / lo0 ICMP-type byte (session-hit + session-miss),
- the `is_embedded_icmp_error` ICMP-type classification,
- the TTL/hop-limit test + generated Time Exceeded
  (`packet_ttl_would_expire` / `build_local_time_exceeded_request`, in
  the session-hit, session-miss, AND flow-cache-hit paths).

`raw_frame` is retained ONLY for genuinely outer/live reads: source-MAC
neighbour learning (`learn_from_live_frame` is gated on
`owned_packet_frame.is_none()`), the `pending_neigh_flow_key` buffer
(also `owned_packet_frame.is_none()`-guarded), the debug-log wire-vs-meta
diagnostic, and the embedded-ICMP-NAT match/build pair
(`try_embedded_icmp_nat_match` reads the outer UMEM via `desc`, so its
sibling `build_nat_reversed_icmp_error_*` MUST stay on the same outer
buffer — for a GRE inner the outer bytes at the inner offset do not parse
as a matching ICMP error, so that path is inert on decap rather than
mis-firing). Fail-on-revert coverage:
`gre_decap_inner_icmp_echo_denied_by_host_inbound_reads_inner_type` drives
a real GRE-tunnelled inner echo through `poll_binding_process_descriptor`
and asserts the host-inbound DENY that only the `packet_frame` read
produces.

### 6e. GRE Version Is A Decap Discriminator — RFC 2637 (PPTP) Is Refused (#6842)

Everything in 6a-6d above parses an RFC 2784/2890 header, which is GRE
**version 0**. RFC 2637 (PPTP) "enhanced GRE" is **version 1**, and it is
not a superset — it re-purposes the same 32 bits RFC 2890 defines as an
opaque Key, and adds a field RFC 2890 does not know to skip:

```text
  RFC 2890 :  |                     Key (32)                    |
  RFC 2637 :  |   Payload Length (16)   |       Call ID (16)     |

  RFC 2890 field order :  Checksum+Reserved1, Key, Sequence
  RFC 2637 field order :  Key, Sequence, Acknowledgment      (A bit = 0x0080)
```

The version check at the top of `try_native_gre_decap_from_frame` runs
BEFORE any Key read or offset arithmetic, and closes two distinct
failures:

1. **Identity.** The high half of a version-1 "Key" is Payload Length,
   which changes with every packet. Any code that reads those 32 bits as
   a stable tunnel discriminator gets a different value per packet. That
   is the load-bearing finding behind #6842: a version-blind 32-bit read
   is **strictly worse than aliasing**, because aliasing bounds the damage
   to one session per endpoint pair while a per-packet discriminator mints
   a session per packet. Today the only 32-bit Key read is
   `match_tunnel_endpoint`; **#7188 adds a second one on the session path
   and the same version branch has to gate it.**
2. **Promotion.** With `A` set, an RFC 2890 reader skips Key and Sequence
   only, so `inner_offset` lands on the Acknowledgment Number — four bytes
   the peer chose. If they open a well-formed IPv4/IPv6 header the parser
   promotes an attacker-authored packet as the tunnel's decapsulated inner
   frame. `gre_version_1_ack_field_cannot_promote_an_injected_inner_packet`
   drives exactly that frame and pairs it with a version-0 control that
   DOES promote the injected packet, so the injection is demonstrably
   reachable and the version field is demonstrably the only guard.

A refused frame is **not** dropped: `try_native_gre_decap_from_frame`
returns `None`, `stage_native_gre_decap` leaves `meta` unchanged, and the
frame continues on the ordinary transit / host-inbound path. So the
counter `GRE_DECAP_UNSUPPORTED_VERSION_REFUSALS` →
`xpf_userspace_gre_decap_unsupported_version_refusals_total` is bumped
**only when the outer tuple names a configured GRE tunnel endpoint** (a
cold-path lookup in the existing `gre_decap_index`, plus the #2327 kind
re-check). Counting unconditionally would turn ordinary TRANSIT PPTP —
which is forwarded, not refused — into a permanent nonzero alarm and make
the metric a traffic gauge instead of a fault signal.

**What this does NOT do.** Terminating PPTP requires pairing the two
directions of a call, and the Call ID in a version-1 header is the
*peer's* — each side allocates its own during the TCP 1723
control-connection exchange, so the two directions carry different values
and no symmetric reverse-key transform can pair them. That needs a
stateful PPTP control-channel ALG, which does not exist in this codebase
(`alg_type` is none/FTP/SIP/DNS) and which is sequenced behind the #7188
`TunnelDiscriminator` work — tracked as **#7699**. Until then, PPTP
offered to a configured GRE endpoint is refused and counted, and PPTP
crossing the firewall is forwarded as ordinary proto-47 transit — with
the pre-existing GRE session-aliasing behaviour #7188 owns.

#### Which header discriminators can key a session, and which cannot

The tempting shortcut for the GRE aliasing in #6837/#7188 is "read the
discriminator out of the header and put it in the `SessionKey`". Whether
that works is **not** decided by whether the field exists in the header.
It is decided by whether the field is **symmetric** — the same value in
both directions of one flow. A session key installs a forward entry and a
reverse companion derived from it (`reverse_wire_key` /
`reverse_canonical_key`, `userspace-dp/src/session/key.rs`); an asymmetric
discriminator has no reverse transform, so the return direction lands on a
DIFFERENT key and the two halves of one conversation never pair.

Quoted verbatim from the standards, because this is exactly the kind of
claim that gets paraphrased into its own opposite:

| Discriminator | Symmetric? | Authority |
|---|---|---|
| RFC 2890 GRE Key (v0, K bit) | **YES** | RFC 2890 §2.1: "Packets belonging to a traffic flow are encapsulated using the **same Key value** and the decapsulating tunnel endpoint identifies packets belonging to a traffic flow based on the Key Field value." It "defines a logical traffic flow between encapsulator and decapsulator" — a per-flow constant. |
| RFC 2637 PPTP Call ID (v1) | **NO** | RFC 2637 §4.1, Key field: "Call ID — (Low 2 octets) Contains the **Peer's** Call ID for the session to which this packet belongs." Each side allocates its own during the TCP 1723 control exchange, so the two directions carry different values. |
| ESP / AH SPI | **NO** | RFC 4303 §2.1: "Because the **SPI value is generated by the receiver** for a unicast SA..." The inbound and outbound SAs of one pair carry different SPIs. |

So the RFC 2890 Key is header-keyable, and is exactly what #7188 should
key on. The PPTP Call ID and the ESP/AH SPI are **not**: each needs an
association learned from a control plane (PPTP: the TCP 1723 channel,
#7699; IPsec: IKE / the SAD, which the control plane already tracks in
`pkg/ipsec`). Reading either straight into a `SessionKey` yields a forward
entry whose reverse companion no peer will ever match — a per-call session
that only ever sees one direction, which is worse than the aliasing it
was meant to replace.

Two consequences for #7188's predicate:

- The protocol set that gets a header-derived discriminator must be an
  **allowlist of SYMMETRIC discriminators** — never a denylist, and never
  "every protocol carrying a 32-bit field at this offset". A denylist
  defaults each unknown protocol back to the degenerate `0/0` key; an
  existence-based allowlist admits the SPI and the Call ID.
- GRE version 0 and version 1 are **different classes, not a value range**
  of one. A v0 tunnel has no Call ID at all, so the predicate must decline
  rather than synthesize one; a v1 packet has no RFC 2890 Key, so its 32
  bits must not be read as one. That is the branch section 6e enforces on
  the decap path, and #7188 inherits it on the session path.

For the record on the adjacent issue: **this section changes nothing about
#6837.** GRE is flow-backed today because `metadata_tuple_complete`
(`frame/inspect.rs`) ends in `_ => true` while `parse_flow_ports` in the
same file ends in `_ => None` — the metadata arm admits the zero-ported
tuple that the frame arm refuses. This change does not touch either
predicate. Note also that a flowless packet is not stranded: it takes the
route-based, session-less forward path (`frame/README.md`) and is still
policy-evaluated — `flowless_non_first_fragment_transit_dropped_by_deny_all_3291`
pins that a deny-all zone pair DROPS it. What flowless actually costs is
**stateful return admission**, not reachability.

## Policy-Based Routing Without A Tunnel Netdevice

This is the most important control-plane question.

The right answer is:

- PBR should target a routing table / logical next-hop selection
- not a kernel tunnel interface

### Recommended Model

Keep PBR exactly as an inner-packet routing decision.

Example:

- firewall filter says `then routing-instance sfmix`
- userspace sets `routing_table = sfmix.inet.0`
- inner FIB lookup in the userspace forwarding state uses that table
- the resulting next-hop is a `TunnelEndpointId`, not `gr-0-0-0`

So PBR still works, but the route result becomes:

- `ForwardPhysical(ifindex, neigh, vlan)`
- or `ForwardTunnel(tunnel_endpoint_id)`

instead of:

- `ForwardKernelTunnel(ifindex=gr-0-0-0)`

### Why This Is Better

It keeps policy semantics unchanged:

- filters still choose routing-instance
- routing-instances still choose routing tables
- routes still resolve next-hops

But the dataplane object on the result side is now native userspace instead of a
Linux netdevice.

## Should We Use Dummy Interfaces?

Dummy interfaces are acceptable only as control-plane anchors.

They are not the right dataplane object for tunnel transit.

### Good Uses For Anchor Interfaces

1. address ownership anchors
- hold tunnel local addresses if Linux services need them

2. host-originated traffic anchors
- give the host stack a place to bind/source addresses for local tools,
  keepalives, or diagnostics

3. VRF membership anchors
- keep Linux routing-instance structure sane for non-dataplane consumers

### Bad Uses For Dummy Interfaces

1. transit forwarding target
- that just recreates the kernel path under a different name

2. PBR egress object
- PBR should resolve to a logical tunnel endpoint, not a dummy ifindex

3. reverse-path dataplane dependency
- if reverse-NAT correctness depends on the dummy interface, the design is still
  hybrid and still fragile

### Recommended Compromise

Use a persistent TUN anchor if Linux host-originated traffic must keep working.

Example:

- `gr-0-0-0` as a persistent `tun` device in `vrf-sfmix`
- owns `10.255.192.42/30`
- carries only host-originated/control-plane handoff traffic
- never carries transit packets

Transit still uses native userspace GRE on the physical WAN NICs.

That gives:

- stable local addresses for host tools
- a clean host-originated handoff path
- no kernel GRE device in the transit dataplane

## Required Code Changes

### Compiler / Snapshot / Protocol

Add native tunnel objects to the userspace snapshot:

- `TunnelEndpointSnapshot`
- inner zone binding
- outer transport routing-instance
- outer local/remote addresses
- GRE options
- payload MTU

Update:

- [pkg/dataplane/userspace/protocol.go](../pkg/dataplane/userspace/protocol.go)
- [pkg/dataplane/userspace/manager.go](../pkg/dataplane/userspace/manager.go)
- compiler route emission so route next-hops can point to logical tunnel IDs

### Rust Forwarding State

Add:

- tunnel endpoint table
- inner-table route entries whose next-hop is a tunnel endpoint
- outer route resolution cache
- GRE encap/decap helpers

Primary files:

- [userspace-dp/src/afxdp.rs](../userspace-dp/src/afxdp.rs)
- [userspace-dp/src/afxdp/frame.rs](../userspace-dp/src/afxdp/frame.rs)
- likely a new [userspace-dp/src/afxdp/gre.rs](../userspace-dp/src/afxdp/gre.rs)

### Session Sync

Extend cluster sync for tunnel-aware sessions:

- tunnel endpoint ID
- outer route metadata
- GRE key if used
- transport egress metadata

Files:

- [pkg/daemon/daemon.go](../pkg/daemon/daemon.go)
- [pkg/dataplane/userspace/manager.go](../pkg/dataplane/userspace/manager.go)
- [userspace-dp/src/main.rs](../userspace-dp/src/main.rs)

### Slow-Path Reduction

After native GRE lands, remove tunnel transit dependence on:

- `MissingNeighbor` tunnel egress coercion
- `gr-0-0-0` transit path
- tunnel TC egress bypass as the primary encapsulation path

Kernel slow-path should remain only for:

- host-originated traffic if still needed
- control-plane exceptions
- migration fallback

## Migration Plan

### Phase 0: Design Lock

- define `TunnelEndpointId`
- define route result types
- decide whether dummy anchor interfaces are needed for host-originated traffic

### Phase 1: Read-Only Native Ingress Parser

- parse outer GRE on physical NIC ingress
- identify matching tunnel endpoint
- count / trace only
- do not change forwarding yet

Exit criteria:

- counters show the same GRE traffic now seen on `gr-0-0-0`

### Phase 2: Native Decap + Inner Pipeline

- decapsulate and process inner packet in userspace
- still use kernel path for tunnel egress

Exit criteria:

- tunnel return traffic like `10.255.192.41 -> 10.255.192.42` is reverse-NATed
  correctly back to LAN clients

### Phase 3: Native GRE Egress

- encapsulate in Rust
- transmit outer packet on physical WAN AF_XDP TX
- stop using `gr-0-0-0` for transit egress

Exit criteria:

- `lan -> sfmix` forward path no longer depends on kernel tunnel TX

### Phase 4: Remove Tunnel Netdevice From Transit Path

- keep `gr-0-0-0` only for host/control-plane if still needed
- transit counters on `gr-0-0-0` must stay at zero

Exit criteria:

- tunnel transit works with `gr-0-0-0` administratively present but dataplane-idle

### Phase 5: PBR / HA / Stress Validation

- routing-instance based tunnel selection
- failover/failback under load
- mixed IPv4/IPv6 tunnel traffic
- ICMP, TCP, UDP, traceroute, iperf, failover tests

Current state:

- PBR-based tunnel selection: done
- isolated-cluster ICMP transit + dataplane-idle `gr-0-0-0`: done
- isolated-cluster TCP connect transit/failover validation: done
- isolated-cluster `iperf3` transit/failover validation: done for single-stream
  TCP over GRE with manual RG1 failover
- failover/failback validation for transit traffic: done on the isolated
  userspace cluster
- isolated-cluster UDP burst transit validation: done in steady state on the
  active native GRE path, with the logical tunnel anchor kept dataplane-idle
- isolated-cluster traceroute/mtr transit validation: done in steady state on
  the active native GRE path, with the logical tunnel anchor kept dataplane-idle
- remaining work: broader failover/failback stress and any future decision to
  remove the TUN-based host-originated handoff entirely

## Validation Plan

Minimum validation matrix:

1. `lan -> sfmix` ICMP over GRE
2. `lan -> sfmix` TCP and UDP over GRE
3. reverse-NAT on tunnel replies
4. PBR selecting tunnel routing-instance
5. failover/failback with active tunnel sessions
6. traceroute / ICMP TE through tunnel path
7. host-originated traffic if TUN anchors are kept

Specific acceptance checks:

- no transit packets on `gr-0-0-0`
- GRE transit counters move on the physical WAN binding only
- reverse session hit counters increase on tunnel replies
- no `vrf-sfmix` local `ICMP host unreachable` for valid tunnel replies
- HA failover keeps tunnel sessions alive

Scripted gate:

- [`scripts/userspace-native-gre-validation.sh`](../scripts/userspace-native-gre-validation.sh)
  validates GRE transit reachability and asserts that the physical WAN device
  moves GRE packets while `gr-0-0-0` stays dataplane-idle

## Recommendation

If the goal is truly “userspace dataplane owns GRE”, then the project should:

1. stop investing in tunnel-netdevice transit fixes
2. keep only enough hybrid behavior to avoid regressions during migration
3. implement native GRE as a physical-NIC userspace feature
4. treat TUN or dummy anchors as host/control-plane objects, not transit dataplane objects

That is the clean architecture.
