# #1838 + #1839 + #1840 — IPv6 NAT/checksum defect trio: plan of action

## 1. Status

DRAFT v3 — round-2 folds applied; pending round-3 convergence on the §5.7
deltas (Codex).

Round-2 verdicts: AGY PLAN-READY ×3 (Q1/Q8/Q9 explicitly ACCEPTED; 3
compile-level nits folded into §5.7 notes); Claude SMR PLAN-READY
(worked-trace table over every §5.5 corner in claude-smr-plan-r2.md);
Codex PLAN-NEEDS-REVISION with two §5.7 mediums, both folded in v3:
1. the embedded walk must be **fragment-aware** (non-first quoted
   fragments must return None — bare `packet_rel_l4_offset_and_protocol`
   would expose payload bytes as ports and create false matches that
   today's fixed-40 read accidentally avoids);
2. the v6 builder's final ICMPv6 checksum recompute gains the
   `0 → 0xFFFF` canonicalization + a stored-field representation test.

Codex r2 also confirmed Q8 (generic-side rule is the right shape) and the
v2 premises in code.

Round-1 verdicts: Codex PLAN-NEEDS-REVISION (2 findings), AGY
PLAN-NEEDS-REVISION on #1838 / PLAN-READY on #1839+#1840 (5 findings),
Claude SMR PLAN-NEEDS-REVISION (F1-F3). All three converged on the same two
deltas; v2 folds:

- **icmp_embed v6 fixed-40 pair pulled INTO #1838 scope** (Codex high + AGY
  1/2 + SMR F2): the outer ICMPv6-error NAT match is ext-aware
  (`icmp_embed/mod.rs:135-150` uses `meta.l4_offset`; the XDP shim walks ext
  headers) but `build_nat_reversed_icmp_error_v6` hardcodes
  `icmp_offset = 40` (`builders.rs:170-178`) — outer-ext errors are MATCHED
  then corrupted (reachable, valid traffic). New §5.7 spec; new §5.1 G8 row.
- **Same-port × stored-zero v6 UDP residual divergence closed by a parity
  rule** (Codex medium + SMR F1): §5.6 matrix split + the no-op-port
  canonicalization rule in §5.5.
- AGY 3 (test-caller updates), AGY 4/Q1 resolution (meta-led precedence
  kept, with rationale), AGY 5 + Codex Q7 (empty mask achievable) folded
  into §5.2/§9/§11.

One plan, one future PR. The three defects live in the same files
(`userspace-dp/src/afxdp/frame/{mod.rs,checksum.rs,rewrite/ipv6.rs}`), share
the descriptor-vs-generic parity contract, and share the test flip (the three
#1824 pins in `frame/prop_tests/rewrite.rs`). Fixing them separately would
re-open path divergence between PRs and force the prop-test domain gates to
be lifted piecemeal.

All file/line references are to master `2ab3220f0` (worktree
`.claude/worktrees/research-1838-trio`).

## 2. Issue framing

Three divergences between the **generic** NAT rewrite path and the
**descriptor fast path**, found by the #1824 property-harness plan review
(plan §10-D, D1–D3) and pinned by deterministic tests when the harness merged:

- **#1838 (D3, headline)** — the generic IPv6 NAT path assumes the L4 header
  sits at fixed offset 40 from the IPv6 header. The port rewrite
  (`frame/mod.rs:841` — `apply_nat_port_rewrite(packet, 40, ...)`) and the v6
  checksum adjusters (`checksum.rs:490`, `:517` — `40usize.checked_add(delta)`)
  land inside the first extension header on any valid IPv6 packet carrying
  ext headers, corrupting it, while the real L4 ports/checksum are left
  un-rewritten. The descriptor path parses the real offset
  (`rewrite/ipv6.rs:35-41`). Corrupts VALID traffic.
- **#1839 (D1)** — zero-checksum canonicalization scope mismatch: the
  descriptor v6 arm canonicalizes a freshly-computed 0x0000 to 0xFFFF for ALL
  protocols (`rewrite/ipv6.rs:96-98`), the generic adjusters only for
  UDP/ICMPv6 (`checksum.rs:85-90`). Wire-harmless (both encodings of
  one's-complement zero verify), but breaks the byte-exact path-equivalence
  the descriptor module header claims (`rewrite/mod.rs:31-33`).
- **#1840 (D2)** — `adjust_l4_checksum_port` (`frame/mod.rs:905-907`) skips
  the incremental update for `UDP && current == 0` without a family gate, so
  the IPv4-only RFC 768 "no checksum" bypass also applies to (malformed)
  IPv6 UDP zero-checksum datagrams, while the descriptor v6 arm applies its
  delta. Malformed-input-only divergence.

## 3. Honest scope/value framing

- **#1838 is a real correctness defect on valid traffic.** Severity is bounded
  by reachability (full map in §5.1): it requires a v6 NAT decision (NAT66
  SNAT/DNAT or port rewrite) on a packet that carries extension headers AND
  takes the generic path. NAT66 interface/pool SNAT with port allocation is
  producible by the runtime NAT engine today (`nat/source.rs:434` interface
  SNAT, `:502-531` v6 pool with `rewrite_src: Some(IpAddr::V6(..)),
  rewrite_src_port: Some(port)`), and the generic path carries every flow's
  first packets, all descriptor fallbacks, all TCP segmentation, the
  pending-neighbor flush, the slow path, and (round-1 addition) the
  ICMPv6-error NAT reversal builder. Ext-headered TCP/UDP is rare in
  the wild but trivially peer-constructible; the consequence is per-packet
  corruption (receiver discard), not a panic or memory-safety issue (all
  writes are bounds-checked within the packet).
- **#1839/#1840 are engineering hygiene**: they cost nothing on the wire but
  block the byte-exact differential property (P-N3 masks checksum bytes) that
  is the permanent guard against future path divergence. Fixing them is what
  lets the harness assert full byte equality.
- There is no performance win here and none is claimed. The value is
  correctness + an unmasked differential oracle.
- *If reviewers conclude the fix shape is wrong or the trio should not ship
  as one PR, PLAN-KILL (per defect) is an acceptable verdict.*

## 4. What's already shipped / partially batched

- **#1824 property harness (merged)** — `frame/prop_tests/` with:
  - three deterministic pins asserting CURRENT buggy behavior:
    `pin_1838_generic_v6_nat_ext_header_corruption` (rewrite.rs:408),
    `pin_1839_v6_tcp_zero_encoding_divergence` (:491),
    `pin_1840_v6_udp_zero_skip_not_family_gated` (:552);
  - domain gates encoding the defects (rewrite.rs:10-13): NAT-applying
    generators are v6-ext-free (#1838), byte comparisons exclude L4 checksum
    bytes via `checksum_byte_ranges` (oracle.rs:162) (#1839), generators never
    emit v6 UDP zero checksums (#1840);
  - a structured v6 ext-chain generator (`strategies.rs` `ExtHdr`) and a
    full-recompute validity oracle — both reusable as-is for the flipped
    properties.
- **Family-aware predicate pair (already in checksum.rs:70-90)** —
  `l4_udp_checksum_optional` (RFC 768 received-0 skip) and
  `adjust_zero_checksum_illegal(protocol, ChecksumFamily)` (computed-0
  canonicalization) already keep the two RFC concepts separate for the
  address-rewrite adjusters. #1839/#1840 are completed by routing the two
  remaining sites (descriptor v6 canonicalization; port-adjust skip) through
  these predicates. The `ChecksumFamily` enum is currently private to
  `checksum.rs` (:26).
- **Descriptor path is the correctness reference for #1838** — it already
  computes `rel_l4` meta-led-or-parsed (`rewrite/ipv6.rs:35-41`) and applies
  ports + checksum delta at the parsed offset.
- **`packet_rel_l4_offset` (inspect.rs:86)** — the existing ext-header walk
  (hop-by-hop/routing/dest-opts 0/43/60, AH 51, fragment 44, no-next 59,
  6-header loop bound). Both paths already share it; the fix threads its
  result into the helpers that ignore it today.

## 5. Concrete design

### 5.1 Reachability map (which traffic hits which path) — severity input for #1838

**Descriptor fast path** (`apply_rewrite_descriptor`,
`poll_descriptor/flow_cache_hit.rs:264`): flow-cache HITS only, and the flow
cache gates on ACK-only TCP + UDP; NAT64 and NPTv6 decline up front
(`rewrite/mod.rs:53-55`).

**Generic path** (`apply_nat_ipv6` + the fixed-40 helpers) — everything else:

| # | Caller | Traffic class |
|---|--------|---------------|
| G1 | `tx/dispatch/mod.rs:447` → `rewrite_forwarded_frame_in_place` → `rewrite_apply_v6` (mod.rs:535) | flow-cache MISS, in-place arm: first packets of every flow, post-idle, post-failover |
| G2 | `tx/dispatch/mod.rs:496/640/774` → `build_forwarded_frame_(into_)from_frame` → `build_forwarded_frame_into_ipv6` (build/ipv6.rs:16) | flow-cache MISS, copy arm (cross-UMEM, tunnel encap, headroom) |
| G3 | `poll_descriptor/flow_cache_hit.rs:272` (fallback `or_else`) | flow-cache HIT but descriptor declined: expected-port mismatch (DMA race), NAT64, NPTv6 |
| G4 | `neighbor_dispatch.rs:241` | pending-neighbor flush after resolution |
| G5 | `tx/tcp_segmentation.rs:231/244` + `frame/tcp_segmentation.rs:291/304` | oversized forwarded TCP (> egress MTU) — per-segment NAT + full recompute |
| G6 | `tx/dispatch/slow_path.rs:142` → `extract_l3_packet_with_nat` (:288) | slow-path reinject + local tunnel delivery |
| G7 | fabric forwards with `apply_nat_on_fabric` (via G1/G2) | cross-chassis HA path |
| G8 | ICMPv6-error NAT reversal: `icmp_embed/mod.rs:124-150` match (ext-aware via `meta.l4_offset`) → `poll_descriptor/mod.rs:867-919` → `icmp_embed/builders.rs:123` `build_nat_reversed_icmp_error_v6` (fixed-40 outer + embedded offsets) | inbound ICMPv6 errors (unreachable/too-big/etc.) for NAT-ed v6 flows — own builder, not `apply_nat_ipv6`, but same fixed-40 class (§5.7) |

**Severity verdict**: every v6 NAT66/port-NAT flow's early packets traverse
G1/G2; a cached flow's packets revert to generic on G3 conditions. So the
defect is reachable whenever v6 NAT is configured and a peer sends
ext-headered segments — valid traffic, attacker-constructible at will,
corrupted per-packet. MEDIUM severity: correctness (not safety), rare
organically, deterministic under attacker control. NPTv6 is *always* generic
(G3) but is checksum-neutral by design and does not rewrite ports, so its
exposure is limited to the (now-fixed) recompute/restore interactions.

### 5.2 #1838 fix spec — thread the parsed `rel_l4` (Option A)

**Decision: thread the caller's ext-aware `rel_l4` into the generic helpers,
with offset selection factored into ONE shared helper used by both paths.**

Rejected alternatives:
- *Re-parse inside `apply_nat_ipv6`* — hides a second offset source: callers
  already compute a meta-led `rel_l4` for `restore_l4_tuple_from_meta` /
  `enforce_expected_ports_at`; an internal re-parse could disagree with it
  when metadata is meta-led (≥40 but ≠ parsed), silently splitting one packet
  rewrite across two offsets. Also does redundant work.
- *Unify generic onto the descriptor path* — different abstractions
  (`NatDecision` live computation vs `RewriteDescriptor` precomputed deltas);
  the generic path must serve NAT64/NPTv6/ICMP/fragments that the descriptor
  path deliberately declines. Out of proportion for this fix.

**New shared offset helper** (in `frame/mod.rs`, near
`packet_rel_l4_offset`'s re-export; serves both `ForwardPacketMeta` and
`UserspaceDpMeta` call sites via scalars):

```rust
/// IPv6 L4 offset relative to the L3 header: trust meta when it is
/// plausible (>= 40 and l4 > l3), else walk the extension chain.
/// SINGLE source of offset truth for both rewrite paths (#1838).
#[inline(always)]
pub(in crate::afxdp) fn v6_rel_l4_offset(
    packet: &[u8],
    l3_offset: u16,
    l4_offset: u16,
    addr_family: u8,
) -> Option<usize> {
    let meta_rel = l4_offset.wrapping_sub(l3_offset) as usize;
    if meta_rel >= 40 && l4_offset > l3_offset {
        Some(meta_rel)
    } else {
        packet_rel_l4_offset(packet, addr_family)
    }
}
```

This is byte-for-byte the precedence already used at `rewrite/ipv6.rs:36-41`,
`frame/mod.rs:550-555`, and `build/ipv6.rs:35-40`; those three duplicated
triads collapse onto the helper (the descriptor arm keeps its behavior,
mechanically).

**Signature changes** (all crate-internal):

```rust
// frame/mod.rs — gains rel_l4 (mirrors apply_nat_ipv4's ihl, which is
// derived internally for v4 because IHL lives in the header itself;
// v6's offset requires the ext walk, so the caller supplies it).
pub(super) fn apply_nat_ipv6(packet: &mut [u8], rel_l4: usize,
                             protocol: u8, nat: NatDecision) -> Option<()>;
// internal port-rewrite call becomes:
//   apply_nat_port_rewrite(packet, rel_l4, protocol, family, nat)

// frame/checksum.rs — fixed `40usize` replaced by caller-supplied offset.
pub(in crate::afxdp) fn adjust_l4_checksum_ipv6_words(
    packet: &mut [u8], rel_l4: usize, protocol: u8,
    old_words: &[u16], new_words: &[u16]) -> Option<()>;
pub(super) fn adjust_l4_checksum_ipv6_addr_bytes(
    packet: &mut [u8], rel_l4: usize, protocol: u8,
    old_addr: &[u8; 16], new_addr: &[u8; 16]) -> Option<()>;
// checksum offset: rel_l4.checked_add(delta)?

// frame/checksum.rs — L4 segment + pseudo-header at the real offset.
pub(in crate::afxdp) fn recompute_l4_checksum_ipv6(
    packet: &mut [u8], rel_l4: usize, protocol: u8) -> Option<()>;
// segment = packet.get(rel_l4..)?; pseudo-header upper-layer length =
// packet.len() - rel_l4; Next Header value = `protocol` (the final L4
// protocol — exactly what RFC 8200 §8.1 prescribes when ext headers
// are present); checksum field at rel_l4 + {16,6,2}.
```

**Dead-code trio**: `adjust_l4_checksum_ipv6` (checksum.rs:369),
`adjust_l4_checksum_ipv6_src` (:461), `adjust_l4_checksum_ipv6_dst` (:471)
are all `#[allow(dead_code)]` with zero non-test callers — **delete** them
(and `ipv6_words` if it becomes orphaned) rather than thread offsets through
helpers nobody calls. If `frame/tests.rs` references them, port those tests
to `_words`.

**Caller updates** (every caller, with its `rel_l4` source):

| Caller | rel_l4 source | Notes |
|--------|---------------|-------|
| `rewrite_apply_v6` (mod.rs:535) | already computed (:550-555) → use `v6_rel_l4_offset`, pass to `apply_nat_ipv6` AND `recompute_l4_checksum_ipv6` (:567) | the issue's noted irony: parsed-then-ignored, now parsed-then-used |
| `build_forwarded_frame_into_ipv6` (build/ipv6.rs:16) | already computed (:35-40) → same threading (:44, :62) | |
| `apply_rewrite_descriptor_ipv6` (rewrite/ipv6.rs:18) | switch :36-41 to `v6_rel_l4_offset` | behavior-preserving refactor; locks offset-precedence parity |
| segmentation v6 arms (`tx/tcp_segmentation.rs:231,244`; `frame/tcp_segmentation.rs:291,304`) | `ip_header_len` IS the ext-aware rel_l4 (`frame_l4_offset − l3`, and segments copy the full IP header incl. ext chain) | ALSO fix §5.3 payload-length defect |
| `extract_l3_packet_with_nat` (slow_path.rs:288) | meta in hand → `v6_rel_l4_offset(&packet, meta.l3_offset, meta.l4_offset, meta.addr_family)?` on the extracted L3 slice (the helper takes the L3-relative packet plus the frame-relative l3/l4 scalars — the same shapes the existing triads feed) | only the v6 arm changes |
| syn-cookie v6 reply builder (`frame/tcp.rs:479`) | literal `40` — builds a fresh base-40 header, no ext chain by construction | |

Bounds/semantics preserved as-is: `apply_nat_port_rewrite` keeps its
skip-on-short `Some(())` (mod.rs:858-860); the adjusters keep `?`-fail on
short reads. `restore_l4_tuple_from_meta` (mod.rs:996) is already
rel_l4-correct and unchanged; the recompute fix makes the repaired-ICMPv6
checksum correct for ext-headered packets.

### 5.3 #1838 blast-radius extension found during this research (fold in)

The v6 segmentation arm writes the IPv6 **payload-length field** as
`tcp_header_len + chunk_len` (`frame/tcp_segmentation.rs:284-286`, same in
`tx/tcp_segmentation.rs`), but each segment carries the full copied IP header
*including ext headers* (`ip_header_len = tcp_offset`, the parsed L4 offset —
tcp_segmentation.rs:66-70, header copy at :147). For an ext-headered
oversized TCP frame every emitted segment under-states its payload length by
`ip_header_len − 40`. Same fixed-40 root cause, same trigger class
(ext-header × forwarded TCP), so it belongs in this PR:

```rust
// v6 arm: payload length = ext bytes + TCP header + chunk
let v6_payload_len = (ip_header_len - 40) + tcp_header_len + chunk_len;
packet.get_mut(4..6)?.copy_from_slice(&(v6_payload_len as u16).to_be_bytes());
```

(For the no-ext case `ip_header_len == 40` and this is bit-identical to
today.) The per-segment oracle test in §9 covers it.

NAT64 is NOT in the blast radius: `nat64.rs` carries its own local
`checksum16*` helpers (nat64.rs:323-438) and builds fresh base-header frames
with full recomputes; it never calls the `frame/checksum.rs` adjusters.
`build_injected_ipv6` and the syn-cookie builders construct base-40 headers
from scratch — correct at 40 by construction. `gre.rs:41` reads only the
fixed-offset v6 addresses (correct regardless of ext headers);
`icmp.rs:196-221` builds a fresh base-40 error packet.

Two further same-class sites found in round 1 are dispositioned as follows:
the icmp_embed v6 pair is IN scope (§5.7, reachable corruption); the MSS
clamp v6 arm (`frame/tcp.rs:213` — `(40, packet[6])` then bails when
`packet[6]` is an ext type) is a safe-bail feature gap, OUT of scope (§10).

### 5.4 #1839 fix spec — scope the descriptor canonicalization to the shared predicate

**Decision: make the DESCRIPTOR arm match the generic predicate**
(`adjust_zero_checksum_illegal(protocol, ChecksumFamily::V6)` — UDP+ICMPv6),
not the other way around.

```rust
// frame/checksum.rs — widen visibility (rewrite/ipv6.rs is inside frame/):
pub(in crate::afxdp::frame) enum ChecksumFamily { V4, V6 }
pub(in crate::afxdp::frame) fn adjust_zero_checksum_illegal(...) -> bool;

// frame/rewrite/ipv6.rs:96-98 — was: canonicalize for ALL protocols.
let final_csum = if new_l4 == 0
    && adjust_zero_checksum_illegal(meta.protocol, ChecksumFamily::V6)
{
    0xFFFFu16
} else {
    new_l4
};
```

Direction rationale (the issue allows either):
- RFC-grounded: RFC 8200 §8.1 mandates the 0→0xFFFF substitution for **UDP
  only**; a computed TCP checksum of 0x0000 is valid on the wire. The generic
  predicate already encodes this (plus the project's deliberate ICMPv6
  inclusion).
- Cross-family consistency: v4 TCP does not canonicalize (pinned by
  `ipv4_tcp_zero_not_canonicalized`, checksum.rs:895); after this fix v6 TCP
  matches.
- Minimal diff: one descriptor line + visibility, vs touching three generic
  adjusters and changing generic TCP behavior.

**Recommended-include rider**: `recompute_l4_checksum_ipv6`'s ICMPv6 arm
(checksum.rs:596-605) writes the raw sum without canonicalizing 0→0xFFFF — a
documented within-generic asymmetry (SCOPE note, checksum.rs:80-83). One line
(`let sum = if sum == 0 { 0xffff } else { sum };`) completes a single
coherent v6 matrix; wire-harmless either way. It never produces a cross-path
divergence (the descriptor path declines ICMP entirely), so reviewers may
strike it — flagged as Open Question Q2.

### 5.5 #1840 fix spec — family-gate the RFC 768 skip

```rust
// frame/checksum.rs — predicate gains the family it always conceptually had:
pub(in crate::afxdp::frame) fn l4_udp_checksum_optional(
    protocol: u8, family: ChecksumFamily) -> bool {
    family == ChecksumFamily::V4 && protocol == PROTO_UDP
}
// existing caller adjust_l4_checksum_ipv4_words:445 passes ChecksumFamily::V4
// → behavior identical.

// frame/mod.rs — adjust_l4_checksum_port gains family:
pub(super) fn adjust_l4_checksum_port(
    packet: &mut [u8], l4_offset: usize, protocol: u8,
    family: ChecksumFamily, old_port: u16, new_port: u16) -> Option<()>;
// skip:   if l4_udp_checksum_optional(protocol, family) && current == 0
// canon:  if adjust_zero_checksum_illegal(protocol, family) && updated == 0
//         (UDP-only reachable here — identical output to today's
//          `matches!(protocol, PROTO_UDP)` for both families; routed
//          through the predicate for one-source-of-truth uniformity)
```

**No-op-port parity rule (round-1 fold — Codex medium / SMR F1).** The
generic path's `old_port != new_port` short-circuits (`frame/mod.rs:870`,
`:879`) never call the adjuster, while the descriptor applies its ≡0 delta
(`l4_csum_delta == 0xFFFF` passes the `rewrite/ipv6.rs:81` `!= 0` gate —
pinned at `prop_tests/rewrite.rs:526`) and canonicalizes. On the one input
where that is byte-visible — **malformed v6 UDP stored 0x0000 × identity
port rewrite** — the paths would stay divergent (generic 0x0000, descriptor
0xFFFF) even after the family gate. Close it with one slow-path branch at
the end of `apply_nat_port_rewrite`:

```rust
// v6 UDP: a port-NAT decision is present (even if value-identity) —
// mirror the descriptor's ≡0-delta application, which canonicalizes a
// stored 0x0000 to 0xFFFF. v4 UDP stored-0 keeps the RFC 768 skip.
if family == ChecksumFamily::V6
    && protocol == PROTO_UDP
    && (nat.rewrite_src_port.is_some() || nat.rewrite_dst_port.is_some())
    && stored_l4_checksum(packet, l4_offset) == Some(0)
{
    write_l4_checksum(packet, l4_offset, 0xFFFF);
}
```

(If an old≠new adjust already ran, the stored value is no longer literal
0x0000 — the adjusters canonicalize their own computed zeros — so the rule
only fires on the short-circuited identity case. v4 behavior untouched.)

Plumbing: `apply_nat_port_rewrite` gains `family: ChecksumFamily`
(`apply_nat_ipv4` passes `V4`, `apply_nat_ipv6` passes `V6`);
`enforce_expected_ports` / `enforce_expected_ports_at` map their
`addr_family: u8` via a tiny `checksum_family_of(addr_family) ->
Option<ChecksumFamily>` (AF_INET→V4, AF_INET6→V6, else None → return
`Some(false)` — unreachable in practice because `frame_l4_offset` already
fails other families). `enforce_expected_ports_at`'s currently-unused
`_addr_family` parameter finally earns its keep.

### 5.6 Combined v6 UDP checksum behavior matrix (post-fix, both paths)

| Case | Generic path | Descriptor path | Identical? |
|------|--------------|-----------------|------------|
| v4 UDP stored 0x0000 (RFC 768 "no checksum") + NAT | skip update, stays 0 | skip (`rewrite/ipv4.rs:104`) | yes |
| v6 UDP stored 0x0000 (malformed per RFC 8200) + port NAT, old≠new | adjust from 0 (#1840 fix), canonicalize if result 0 | apply delta, canonicalize | yes — `checksum16_adjust(0, …)` and the delta fold are the same one's-complement arithmetic, and for a pre-complement sum ≥ 1 the fold maps each congruence class to a unique representative, so the representations match |
| v6 UDP stored 0x0000 + IDENTITY port NAT (old==new) | short-circuit would keep 0x0000 → **no-op-port parity rule (§5.5) writes 0xFFFF** | ≡0 delta applied, canonicalize → 0xFFFF | yes (after the §5.5 rule; divergent without it — round-1 catch) |
| v6 UDP stored 0x0000 + address-only NAT | adjust (no skip exists in `_words`/`_addr_bytes` today — unchanged) | apply delta | yes |
| v6 UDP/ICMPv6 computed 0x0000 | → 0xFFFF (`adjust_zero_checksum_illegal` V6) | → 0xFFFF (#1839 fix, same predicate) | yes |
| v6 TCP computed 0x0000 | stays 0x0000 | stays 0x0000 (#1839 fix) | yes |
| v4 TCP computed 0x0000 | stays 0x0000 | stays 0x0000 | yes |

Deliberate non-goal: the generic path does NOT drop v6-UDP-zero datagrams
(RFC 8200 says *receivers* should discard; this is a middlebox rewrite layer
and admission/screen owns drop policy — Open Question Q6).

### 5.7 #1838 scope extension — ICMPv6-error NAT reversal (icmp_embed)

Round-1 fold (Codex high; AGY findings 1+2; SMR F2). Reachability, verified
against the code:

- The outer match IS ext-aware: `try_embedded_icmp_nat_match_from_frame`
  reads the ICMP type at `meta.l4_offset` (`icmp_embed/mod.rs:135-137`) and
  the XDP shim's parser walks v6 ext chains, so a valid outer-ext ICMPv6
  error matches a NAT-ed session.
- The v6 builder then hardcodes `let icmp_offset = 40;` and
  `emb_ip_offset = icmp_offset + 8` / `emb_l4_offset = emb_ip_offset + 40`
  (`icmp_embed/builders.rs:170-178`): for an outer-ext error the embedded
  un-NAT writes and the full ICMPv6 checksum recompute land inside the
  outer ext chain → **matched-then-corrupted, valid traffic** (worse than
  the parse-gated theory: only the EMBEDDED-ext case is gated).
- The embedded parser reads `proto = frame[embedded_ip_start + 6]` and
  `l4_off = embedded_ip_start + 40` (`icmp_embed/parse.rs:93-100`): an
  embedded-ext quoted packet yields an ext-header type as "proto" → tuple
  garbage → session lookup miss → NAT reversal silently skipped (feature
  gap, no corruption).

Fix spec (same PR, separate logical commit; r2 folds marked):

1. `parse_embedded_v6` (parse.rs:87): derive `(rel, proto)` via a
   **fragment-aware** embedded walker, NOT bare
   `packet_rel_l4_offset_and_protocol` (Codex r2 medium 1: that helper's
   fragment arm advances past the header without checking the
   fragment-offset bits, inspect.rs:184-193 — a quoted NON-FIRST fragment
   would have payload bytes exposed as "ports", enabling false NAT/session
   matches where today's fixed-40 read leaves proto=44 and accidentally
   never matches). Spec: a small `parse_embedded_v6_l4(packet) ->
   Option<(usize, u8)>` in `icmp_embed/parse.rs` that walks the chain like
   `packet_rel_l4_offset_and_protocol(.., libc::AF_INET6 as u8)` but, on
   the fragment header (44), reads the fragment-offset bits and returns
   `None` unless they are zero (first/atomic fragments allowed). Then
   `l4_off = embedded_ip_start + rel`. The existing
   `embedded_ip_start + 48` minimum-length guard stays; port/ident reads
   keep their `.get()?` bounds style.
2. `build_nat_reversed_icmp_error_v6` (builders.rs:123): outer
   `icmp_offset` = `v6_rel_l4_offset(pkt, meta.l3_offset, meta.l4_offset,
   meta.addr_family)?` (the same shared helper from §5.2 — meta is already
   a parameter; the helper must be declared `pub(in crate::afxdp)` in
   `frame/mod.rs` so the `icmp_embed` sibling sees it — AGY r2 nit 3);
   `emb_ip_offset = icmp_offset + 8`; embedded L4 offset via the same
   fragment-aware walker on `pkt[emb_ip_offset..]` (a `None` skips the
   embedded port restore, as today's non-matching protos do). The final
   ICMPv6 checksum recompute (`checksum16_ipv6(src, dst, PROTO_ICMPV6,
   pkt[icmp_offset..])`) gets correct coverage automatically (upper-layer
   length = `len − icmp_offset`, Next Header = ICMPv6) — **and gains the
   `0 → 0xFFFF` canonicalization** (Codex r2 medium 2: builders.rs:202-209
   writes the raw sum today; a computed-zero would contradict the §5.6
   matrix, and the recompute-oracle alone cannot see the representation —
   the test must assert the stored field).
3. The v4 builder is already IHL-correct (`builders.rs:6` uses `ihl`) — no
   change.
4. Outer v6 addresses at fixed `8..40` are correct regardless of ext
   headers — unchanged.

Implementation notes from AGY r2 (compile-level): use
`libc::AF_INET6 as u8` (no bare `AF_INET6` constant exists in
icmp_embed); the §5.5 rule's `stored_l4_checksum`/`write_l4_checksum`
pseudo-helpers are to be inlined as bounds-checked two-byte slice reads/
writes in the style of the surrounding code (or added as tiny private
helpers) — they do not exist today.

This subsystem has no descriptor-path twin (errors always take the
exception path), so the parity property does not extend here; coverage is
deterministic example tests (§9.4).

## 6. Public API preservation

- All changed functions are `pub(super)` / `pub(in crate::afxdp)` /
  `pub(in crate::afxdp::frame)` — nothing crosses the crate boundary.
- **No wire/control-protocol change**: `NatDecision`, `RewriteDescriptor`,
  `UserspaceDpMeta`, `ForwardPacketMeta` layouts untouched; zero Go-side
  changes; no control-socket message changes.
- `apply_rewrite_descriptor`'s signature and decline contract (None on
  NAT64/NPTv6/port-mismatch → caller falls back) unchanged.
- Deleted symbols are exclusively `#[allow(dead_code)]` helpers with no
  callers.

## 7. Hidden invariants the change must preserve

1. **Descriptor↔generic parity contract** (`rewrite/mod.rs:31-33` "Mirrors
   the byte-level rewrite semantics…"): after this PR the claim becomes
   byte-exact and the un-masked P-N3 differential is its permanent guard. A
   fix landing in one path only re-opens divergence — hence one PR, one flip.
2. **Offset-source precedence parity**: meta-led when `meta_rel >= 40 &&
   l4_offset > l3_offset`, else parse — must be the SAME rule in both paths
   (enforced structurally by the shared `v6_rel_l4_offset`).
3. **v4 byte-identity**: every v4 path must produce bit-identical output
   pre/post PR (only predicate plumbing touches v4; `l4_udp_checksum_optional
   (UDP, V4)` ≡ old `protocol == UDP`). The existing v4 unit tests + P-N3
   over v4 inputs prove it.
4. **Skip-vs-fail semantics**: `apply_nat_port_rewrite` returns `Some(())`
   (skip) on short packets; adjusters return `None` (caller drops). Both
   preserved exactly — changing either silently alters drop accounting.
5. **NPTv6 checksum-neutrality** (`skip_l4_csum`, mod.rs:788): preserved; the
   port-rewrite call still runs after it with the (now-correct) offset.
6. **Incremental-update soundness when the offset moves**: every adjuster
   call must use the SAME `rel_l4` as the byte-writes it is balancing within
   one `apply_nat_ipv6` invocation — guaranteed by passing one value down,
   never re-deriving mid-function.
7. **Hot-path discipline** (docs/engineering-style.md): no allocation, no
   `dyn`, helpers stay `#[inline(always)]`/`#[inline]`; the common no-ext
   case stays O(1) via the meta-led shortcut (no new parsing added anywhere —
   the callers that gain a parse already had one). One extra `usize`
   parameter on inlined helpers; no probestack-class stack temps.
8. **ICMP ident restore composition**: `restore_l4_tuple_from_meta` writes at
   `rel_l4 + 4` and its repaired-checksum recompute must operate on the same
   offset — threading `rel_l4` into `recompute_l4_checksum_ipv6` closes the
   currently-broken half of this pair.
9. **Pre-existing, family-symmetric non-first-fragment behavior**: a
   non-first fragment has no L4 header; both paths (and v4 today, via IHL)
   would write "ports" into payload bytes if a port-NAT decision reaches one.
   This PR makes v6 match v4/descriptor behavior (parity) and does NOT try to
   solve fragment NAT — Open Question Q4 proposes the follow-up issue.

## 8. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | **MED-LOW** | v6-ext NAT traffic: corrupted→correct (the point). v6 no-ext NAT: bit-identical (offset 40 selected by the same meta-led shortcut). v4: bit-identical (§7.3). Zero-checksum edges: wire-valid both before/after; only encodings change. Segmentation payload-length: bit-identical for no-ext. |
| Lifetime / borrow-checker | **LOW** | Parameter threading only; no new borrows across calls; `packet` remains one `&mut [u8]` per call chain. |
| Performance regression | **LOW** | One scalar param through inlined fns; no new parse on any path; the deleted dead helpers shrink the crate. If reviewers want proof: objdump size-compare of `apply_nat_ipv6`/`rewrite_apply_v6` before/after (release). |
| Architectural mismatch | **LOW** | Moves the generic path TOWARD the descriptor path's existing, correct semantics; no new abstraction. The shared offset helper removes a 3-way duplication rather than adding a layer. |

## 9. Test plan

1. **Flip the three pins** (`frame/prop_tests/rewrite.rs`) to positive
   properties:
   - `pin_1838…` → real dst port rewritten at parsed `rel_l4`; ext-header
     bytes byte-identical to input; checksum adjusted at `rel_l4 + 16`;
     generic output byte-identical to descriptor output on the same input.
   - `pin_1839…` → both paths emit 0x0000 for the v6 TCP computed-zero case;
     full-frame byte equality.
   - `pin_1840…` → generic adjusts the malformed v6-UDP-zero checksum;
     byte-equal to descriptor. Add the v4 counterpart (stored-0 stays 0 on
     BOTH paths) as the family-gate regression guard.
2. **Re-admit ext-header packets to the NAT generators** (lift the rewrite.rs
   :10-13 domain gates): `arb_packet_with_nat` gains v6 ext chains (reusing
   `ExtHdr`/`arb_ext_chain`), running P-N1 round-trip, P-N2 oracle-validity,
   P-N3 differential, P-N4 payload-immutability, P-T4 over the new domain.
3. **Narrow the P-N3 byte mask**: drop the L4-checksum exclusion from
   `checksum_byte_ranges` usage in the descriptor-vs-generic property → full
   byte equality (the v4 header-checksum bytes stay masked only if review
   finds a legitimate residual divergence; expectation is an EMPTY mask —
   Open Question Q7).
4. **New deterministic unit tests**:
   - per-ext-kind (hop-by-hop, routing, dest-opts, AH, fragment-atomic) port
     rewrite + checksum-offset placement through `apply_nat_ipv6`;
   - `recompute_l4_checksum_ipv6` with ext chain: oracle-valid output,
     pseudo-header length = `len − rel_l4`;
   - `l4_udp_checksum_optional` family table + `adjust_l4_checksum_port` v4
     skip / v6 no-skip pair;
   - descriptor canonicalization scope per protocol (TCP no, UDP/ICMPv6 yes);
   - segmentation: ext-headered oversized v6 TCP → every segment passes the
     full-recompute oracle AND carries the correct payload-length field;
   - **same-port residual pin** (round-1): malformed v6 UDP stored-0 ×
     identity port rewrite → BOTH paths emit 0xFFFF (§5.5 rule); v4
     counterpart stays 0x0000 on both;
   - **icmp_embed** (§5.7): outer-ext ICMPv6 error NAT reversal → embedded
     un-NAT lands at the real offsets, output passes the full-recompute
     oracle; embedded-ext quoted packet → parse now recovers the true
     proto/ports (match succeeds where it silently missed before);
     **embedded first/atomic fragment** → match allowed; **embedded
     NON-FIRST fragment** → must NOT match or rewrite (Codex r2 —
     negative coverage guarding the fragment-aware walker);
     **builder computed-zero ICMPv6 checksum** → balancing test forcing
     the recomputed sum to zero, asserting the STORED field is 0xFFFF
     (representation assertion — the oracle alone accepts both).
   All existing test callers of the re-signatured helpers (e.g. the
   `recompute_l4_checksum_ipv6` calls in `frame/tests.rs`) are updated in
   the same commit as the signature change — AGY r1 finding 3.
5. **Suites/gates**: `cargo build` clean; full `userspace-dp` cargo test
   (incl. the not(miri) prop tests, 256 cases each); 5× repeat of the flipped
   pins + new prop properties (flake guard); `make test` (Go untouched but
   run); smoke v4 + v6 iperf3 on the loss userspace cluster + per-class CoS
   5201-5211 (standard refactor gate — ext-header traffic is not iperf3-able;
   the prop harness is the functional evidence for the ext domain).
6. **Doc updates in the same PR** (module-doc contract):
   `frame/README.md` (checksum.rs row + invariants: offset threading, the
   predicate pair's new scope), `frame/prop_tests` README/mod-doc domain
   notes, the SCOPE comment at checksum.rs:80-83, and the stale
   `rewrite/ipv6.rs:97` comment ("use 0xFFFF for all").

## 10. Out of scope (explicitly)

- **NAT64 builders** (`nat64.rs`) — separate full-recompute implementation,
  not touched (verified no use of the affected helpers).
- **>6-ext-header chains**: `packet_rel_l4_offset`'s post-loop
  `Some(offset)` (inspect.rs:134) can return an ext-header offset as "L4" for
  pathological chains — pre-existing, shared by both paths (parity holds),
  pinned by the #1824 parse properties. Not changed here.
- **Non-first-fragment NAT** (§7.9) — pre-existing on v4 AND v6 AND the
  descriptor path; needs its own admission-layer answer. Follow-up issue
  filed at PR time (round-1 consensus: Codex Q4 + plan).
- **MSS clamp v6 ext-header gap** (`frame/tcp.rs:213` — safe bail, no
  corruption: `packet[6]` ext type ≠ TCP → clamp no-ops on ext-headered
  SYNs). Folded into the same follow-up issue as the fragment item.
- **Drop policy for malformed v6-UDP-zero ingress** — admission/screen
  domain, not the rewrite layer.
- **`verify_built_frame_checksums` being v4-TCP-only** (mod.rs:1120) —
  debug-only helper, already superseded by the prop-test oracle.

## 11. Open questions — round-1 resolutions + remaining

Resolved in round 1 (all three reviewers consistent unless noted):

1. **Q1 — meta-trust precedence: RESOLVED, keep meta-led.** Codex verified
   no producer emits a ≥40-but-wrong `l4_offset`. AGY proposed a
   `meta_rel == 40 && packet[6] != meta.protocol → re-parse` coherence
   check; REJECTED with rationale: it validates only the no-ext claim while
   leaving every `meta_rel > 40` value unvalidated — a partial defense that
   implies distrust without delivering it, and a behavior change to the
   descriptor hot path with no demonstrated producer. The systemic guards
   are (a) the shared helper making both paths identical, (b) the existing
   #1824 P-I5 meta-arbitration pin, (c) the un-masked differential. If AGY
   r2 still wants it, the bar is a quoted producer that emits contradictory
   meta.
2. **Q2 — recompute ICMPv6 canonicalization rider: RESOLVED, include**
   (Codex: include if recompute is touched — it is, for #1838 offset
   threading).
3. **Q3 — dead-trio deletion: RESOLVED, delete** (Codex concurs).
4. **Q4 — fragment follow-up: RESOLVED, file separately at PR time**, with
   a pin documenting current behavior (Codex), plus the MSS-clamp gap
   (§10).
5. **Q5 — segmentation payload-length fold-in: RESOLVED, fold in**
   ("arithmetic is right" — Codex).
6. **Q6 — middlebox stance on v6-UDP-zero: RESOLVED, adjust-for-parity**,
   now including the §5.5 no-op-port rule so parity holds on the identity
   corner too (Codex's caveat).
7. **Q7 — empty P-N3 mask: RESOLVED, achievable.** AGY verified the v4
   `ip_csum_delta + 0xFEFF` application equals the incremental adjust;
   Codex concurs for the valid domain given the same-port fix. The
   fold-representation argument (§5.6 row 2) covers the L4 side.

Resolved in round 2:

8. **Q8 — §5.5 no-op-port rule shape: RESOLVED, generic-side rule.** Codex
   r2: "the generic-side no-op-port rule is the right shape"; AGY r2
   ACCEPTED with the no-counter-example confirmation; SMR r2 worked-trace
   table covers every corner.
9. **Q9 — icmp_embed spec: RESOLVED with two r2 amendments** (now in
   §5.7): the embedded walk is fragment-aware (non-first quoted fragments
   → None, preserving today's accidental never-match safety), and the
   builder's ICMPv6 recompute canonicalizes computed-zero with a
   stored-field representation test. AGY r2 ACCEPTED the outer/embedded
   offset split as such.

Remaining for round 3: none new — round 3 is a targeted Codex confirmation
of the two §5.7 amendments.
