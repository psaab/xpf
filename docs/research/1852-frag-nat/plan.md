# #1852 — Non-first-fragment port-NAT exposure + MSS-clamp v6 ext-header gap: plan of action

## 1. Status

**PLAN v2** — round-1 3-way review folded (Codex PLAN-NEEDS-REVISION ×6,
AGY PLAN-NEEDS-REVISION, Claude SMR PLAN-NEEDS-REVISION F1-F4). All three
converged: **revise, then Path A, do NOT kill** (AGY: "Proceed with Path
A"; Codex/SMR findings are all revision, not kill). Two pre-existing,
family-symmetric defects collected from the #1838/#1839/#1840 trio plan
(`docs/research/1838-nat-v6-trio/plan.md` §7.9, §10, §5.7 note 3 — merged
as #1853 on master `36dc00953`).

Round-1 deltas folded in v2:
- **Port-write narrowing RETRACTED** (Codex HIGH + AGY): new-flow pool
  SNAT (`nat/source.rs:478-498`) and wildcard DNAT
  (`nat/destination.rs:92-121`) emit port-rewriting decisions WITHOUT an
  established-session lookup, so S3/S6/S7 port writes ARE reachable on
  non-first fragments — §4 + §5 re-graded up.
- **Shim partial-drop nuance added** (AGY): the shim drops a substantial
  fraction of non-first fragments before userspace (TCP `data_offset < 20`
  ≈31%, short reads), narrowing — not eliminating — reachability.
- **TCP segmentation orchestrator added as an exposure site** (Codex MED)
  with an explicit no-segment gate.
- **Defect-2 fix changed** to make `packet_rel_l4_offset_and_protocol`
  fragment-aware (Codex + AGY MED), which also gates other inspect callers.
- S5 re-graded LOW (no cross-fragment shim state — SMR F3 / Codex / AGY);
  A′ text corrected (parse_ipv4 does NOT read frag_off today; free
  `meta_flags` bits 0x01-0x40 named); S9 line range fixed; predicate
  threaded once per orchestrator (SMR F1); descriptor fall-back call site
  confirmed (SMR F2, `poll_descriptor/flow_cache_hit.rs:264-280`).

All file/line references are to master `5b3f9501e` (worktree
`.claude/worktrees/1852-research`).

## 2. Issue framing

Two divergences that the trio PR (#1853) deliberately left untouched:

1. **Non-first-fragment L4 rewrite (both families, all rewrite paths)** —
   a non-first fragment has no L4 header at the post-IP-header offset.
   Every NAT/rewrite path that writes ports or adjusts an L4 checksum at
   that offset interprets *payload* bytes as the L4 header. The trio PR
   added a fragment-offset guard ONLY to the embedded ICMPv6 walk
   (`parse_embedded_v6_l4`, shipped #1853); the forwarding-path rewrite
   sites and the embedded ICMPv4 walk were explicitly deferred here.

2. **MSS-clamp v6 extension-header gap (safe bail, feature gap)** —
   `clamp_tcp_mss` derives the v6 L4 offset as the fixed pair
   `(40, packet[6])`; when `packet[6]` is an extension-header type the
   protocol check (`protocol != PROTO_TCP`) fails and the clamp silently
   no-ops. No corruption — but `tcp-mss` clamping is not applied to
   ext-headered v6 SYNs.

## 3. Blast-radius inventory (per-site, file:line @ `5b3f9501e`)

### 3a. Defect 1 — L4-offset interpretation sites in the rewrite path

The XDP shim (`userspace-xdp/src/lib.rs`) parses every packet and writes
`UserspaceDpMeta`. It does **not** check the fragment-offset bits:

- `parse_ipv4` (lib.rs:1100-1142) reads `protocol = iph[9]` then calls
  `parse_l4` at `l3 + ihl` regardless of `frag_off`. For a non-first
  fragment, `parse_l4` (lib.rs:1388) reads payload bytes as ports /
  TCP-data-offset → `meta.flow_src_port` / `flow_dst_port` = garbage,
  `meta.l4_offset = l3 + ihl`.
- `parse_ipv6` (lib.rs:1144-1219) walks `NEXTHDR_FRAGMENT` (44) at
  lib.rs:1185 advancing 8 bytes **without** reading the offset bits, then
  `parse_l4` at the post-fragment offset → same garbage ports,
  `meta.l4_offset` points past the fragment header.

So the metadata handed to userspace already mis-describes a non-first
fragment as a normal L4 packet. Every downstream rewrite leaf then trusts
`rel_l4`:

| # | Site | file:line | What it writes at the L4 offset |
|---|------|-----------|---------------------------------|
| S1 | `apply_nat_ipv4` (IP-only NAT branch) | `frame/mod.rs:751/755/767/776` | `adjust_l4_checksum_ipv4_*` reads+writes 2 bytes at `ihl+16` (TCP) / `ihl+6` (UDP) for the address-change delta |
| S2 | `apply_nat_ipv6` (IP-only NAT branch) | `frame/mod.rs:833/846/872/879` | `adjust_l4_checksum_ipv6_*` at `rel_l4+16/+6/+2` |
| S3 | `apply_nat_port_rewrite` | `frame/mod.rs:913-973` | writes ports at `rel_l4`/`rel_l4+2` and adjusts the port-delta checksum (only when `nat.rewrite_*_port = Some`) |
| S4 | `enforce_expected_ports` / `_at` | `frame/mod.rs:1020/1066` | writes `expected_ports` at `rel_l4` + adjusts checksum (only when `expected_ports = Some` and current != expected) |
| S5 | `restore_l4_tuple_from_meta` (ICMP) | `frame/mod.rs:1108-1127` | writes `meta.flow_src_port` (echo id) at `rel_l4+4` |
| S6 | descriptor fast path v4 | `rewrite/ipv4.rs:62-121` | inline port writes + precomputed L4-csum delta at `l4+16/+6` |
| S7 | descriptor fast path v6 | `rewrite/ipv6.rs:63-108` | inline port writes + precomputed L4-csum delta |
| S8 | `parse_embedded_v4` | `icmp_embed/parse.rs:36-81` | reads ports at `ihl` (no frag-offset check) — the v4 twin of the #1853 v6 fix |
| S9 | `build_nat_reversed_icmp_error_v4` | `icmp_embed/builders.rs:7-119` | embedded un-NAT at `emb_ip_offset + emb_ihl` (no frag check on the QUOTED v4 packet); reads `emb_l4_offset` directly, NOT via `parse_embedded_v4`, so it needs its OWN guard (SMR nit) |
| S10 | TCP segmentation orchestrator | `tx/dispatch/mod.rs:1031-1055` (admission) → `frame/tcp_segmentation.rs:48-79,192-303` + `tx/tcp_segmentation.rs:201-237` | segmentation admission gates only on `meta.protocol != PROTO_TCP` + `len-l3 > mtu` — fragment-blind. `meta.protocol` for a non-first TCP fragment IS `PROTO_TCP` (shim reads it from the IP header / v6 frag header next-hdr), so a large non-first fragment can enter segmentation, which parses "TCP" at `frame_l4_offset` and runs NAT/checksum at the fake offset (Codex MED) |

Orchestrators that reach S1-S7/S10 (each is a distinct entry that needs a
gate; Path A gates the shared leaves + the descriptor path + the
segmentation admission):

- `rewrite_apply_v4` / `rewrite_apply_v6` (generic in-place, mod.rs:504/560)
- `build_forwarded_frame_into_ipv4` / `_ipv6` (copy builder, build/ipv4.rs / ipv6.rs)
- `apply_rewrite_descriptor_ipv4` / `_ipv6` (descriptor fast path; reached
  only for flow-cached entries, falls back to generic via
  `apply_rewrite_descriptor(...).or_else(rewrite_forwarded_frame_in_place)`
  at `poll_descriptor/flow_cache_hit.rs:264-280` — confirmed)
- `extract_l3_packet_with_nat` (slow_path.rs:278)
- TCP segmentation v4/v6 (S10) — separate admission gate, not a leaf

The forwarding/NAT pipeline has **zero** fragment awareness today
(`grep is_fragment userspace-dp/src/afxdp` → only `event_emit.rs`). Only
the **screen** layer reads frag bits (`screen/extract.rs:50-55,99-109`)
and only acts on them for the optional teardrop / icmp-fragment / syn-frag
checks — it does not unconditionally drop non-first fragments.

### 3b. Defect 2 — MSS clamp

- `clamp_tcp_mss` (`frame/tcp.rs:192-271`), v6 arm at tcp.rs:209-214 uses
  the fixed `(40, packet[6])`. Single function; both build arms reach it
  via `clamp_tcp_mss_frame` (`build/ipv4.rs:78`, `build/ipv6.rs:60`),
  gated by `tunnel_tcp_mss > 0`. No other production caller
  (`grep clamp_tcp_mss`). The `#1853` `v6_rel_l4_offset` helper is NOT
  used here — the clamp keeps its own fixed-40 derivation, so the gap
  remains in exactly this one function.

## 4. Reachability analysis (round-1-corrected)

The filed issue says "the REAL exposure may be narrower than filed." Two
opposing corrections from round 1: the shim drops *some* non-first
fragments (narrows), but port writes are reachable via NEW-flow NAT
allocation (widens — my v1 narrowing was wrong).

### 4a. Shim partial-drop (AGY) — narrows, does not eliminate

The shim parses every fragment without checking the fragment-offset bits
(`userspace-xdp/src/lib.rs:1115-1117` v4; `:1185-1188` v6 walks past
NEXTHDR_FRAGMENT without offset inspection), so a non-first fragment is
parsed as if it had an L4 header at the post-IP offset. But `parse_l4`'s
own length/sanity checks drop a fraction:

- TCP: `read_bytes(.., 14)?` + `data_offset = (bytes[12]>>4)*4; if
  data_offset < 20 { return None }` (`lib.rs:1396-1400`) → ~31% of
  non-first TCP fragments (those whose payload byte 12 high-nibble < 5)
  are dropped at the shim → packet dropped (`lib.rs:378-380`
  `drop_degraded_transit`).
- short non-first fragments (< 14 B TCP / < 8 B UDP/ICMP payload at the
  fake L4 offset) fail `read_bytes` → dropped.

So NOT every non-first fragment reaches userspace — but **large-payload
fragments with surviving garbage bit patterns DO**, which is the common
case for bulk-data fragmentation (large MTU-exceeding payloads). The
exposure is real, just not 100% of fragments.

### 4b. Port-write sites ARE reachable via new-flow NAT (Codex HIGH + AGY)

My v1 claim that S3/S6/S7 port writes are unreachable (garbage-port
session miss) was WRONG. Port-rewriting decisions are produced WITHOUT an
established-session lookup:

- **Pool-mode dynamic SNAT**: the cold path matches a SNAT rule by
  IP/zone (`nat/source.rs:151` `matches(from_zone, to_zone, src_ip,
  dst_ip)` — port-blind) and ALLOCATES a fresh translation
  (`nat/source.rs:478-498` → `rewrite_src: Some(ip), rewrite_src_port:
  Some(translated.port)`). A non-first fragment misses the session cache
  (garbage ports), hits the cold path, the rule matches on src IP, a new
  port is allocated, and `apply_nat_port_rewrite` writes that port into
  payload bytes at the fake L4 offset — AND leaks an allocator port per
  fragment.
- **Wildcard DNAT**: `nat/destination.rs:92-121` exact-then-wildcard
  (port=0) lookup → `rewrite_dst_port: Some(value.new_dst_port)`. A
  non-first fragment to a wildcard-DNAT'd dst → port write into payload.

So S3 (`apply_nat_port_rewrite` writes at `rel_l4` / `rel_l4+2`), S6/S7
(descriptor inline port writes) are reachable. S4 (`enforce_expected_ports`)
remains gated by `expected_ports` (set only on a flow-cache hit, which a
non-first fragment misses) — S4 stays LOW.

### 4c. Address-only NAT (S1/S2 IP-NAT branch) — reachable, corrupts

Static 1:1 NAT (`nat/static_nat.rs:49-75`) and interface NAT produce
port-blind IP-only decisions (`match_dnat`/`match_snat` set
`rewrite_dst`/`rewrite_src`, ports `None`). The shim redirects to
userspace via the port-blind `USERSPACE_INTERFACE_NAT_V4/V6` /
`USERSPACE_LOCAL_V4/V6` maps; static external IPs register for local
delivery (`StaticNatTable::external_ips`). The userspace miss path
installs the decision (`poll_descriptor/mod.rs:543-550,682-685`).
`apply_nat_ipv4`/`_ipv6` then (1) rewrites the IP (CORRECT — every
fragment carries the IP header and must be rewritten consistently), then
(2) calls `adjust_l4_checksum_ipv4_dst`/`_ipv6_*` at the L4 offset
(`frame/mod.rs:748-755` v4; `:833-846` v6) folding the address-change
delta into "the L4 checksum" — 2 **payload** bytes on a non-first
fragment.

The L4 checksum lives only in the FIRST fragment; it is NAT'd correctly
there. Each non-first fragment gets correct IP rewrite **plus 2 corrupted
payload bytes** → on reassembly the receiver's L4 checksum (carried in
fragment 1) no longer matches → **silent drop of fragmented NAT'd TCP/UDP
flows.** Reachable with static/interface NAT + any flow ≥ 2 fragments
(modulo §4a shim drop). **MED.**

### 4d. ICMP ident restore (S5) — LOW, no cross-fragment state

The shim is stateless per-packet (`lib.rs:646` `meta_flags: 0`; `parse_l4`
ICMP arm `:1420-1426` reads the ident from each packet's OWN bytes). So a
non-first ICMP fragment's `meta.flow_src_port` = its own payload bytes,
not fragment 1's echo id. `restore_l4_tuple_from_meta` (`frame/mod.rs:
1116-1122`) writes `meta.flow_src_port` at `rel_l4+4` only if it differs
from the current bytes — for the shim-origin same-packet path that is a
no-op. My v1 "writes the echo id from frag 1" claim was wrong (SMR F3 /
Codex / AGY). **S5 → LOW.** S8/S9 (embedded ICMPv4) likewise narrow but
are the v4 twin of the #1853 v6 fix — closing them restores family
symmetry cheaply. **LOW.**

### 4e. Defect 2 — not corruption, but its FIX has a fragment trap

An ext-headered v6 SYN whose clamp is skipped keeps its original MSS — a
feature gap, **LOW**. BUT the naive fix (swap the fixed `(40, packet[6])`
for `packet_rel_l4_offset_and_protocol`) introduces a NEW corruption risk:
that helper ALSO walks past the fragment header without an offset check
(`inspect.rs:184-188`), so a non-first TCP fragment would resolve
protocol=TCP at a fake offset, and if the payload's "TCP flags" byte
happens to set SYN, the clamp mutates payload (Codex + AGY MED). The fix
MUST make the helper fragment-aware (see §7).

## 5. Severity — honest framing

| Defect / site | Reachable? | Impact | Severity |
|---------------|-----------|--------|----------|
| S3/S6/S7 port writes on non-first frag (new-flow pool SNAT / wildcard DNAT) | YES (cold path allocates a port; §4b) | payload corruption + per-fragment SNAT allocator-port LEAK | **MED-HIGH** |
| S1/S2 address-NAT L4-csum adjust on non-first frag (static/interface NAT) | YES (§4c) | 2 payload bytes/frag corrupted → reassembly checksum mismatch → silent drop of fragmented NAT'd flows | **MED** |
| S10 TCP segmentation on a large non-first frag | YES (`meta.protocol==TCP`; admission fragment-blind) | parses payload as TCP, runs NAT/checksum at fake offset | **MED** |
| Defect 2 FIX trap (naive helper swap walks past fragment) | YES if fix is naive | new payload-corruption risk on non-first frag | **MED** (avoided by the §7 fragment-aware helper) |
| S4 `enforce_expected_ports` | NO (expected_ports only on flow-cache hit, which a non-first frag misses) | — | **LOW** |
| S5 / S8 / S9 ICMP ident + embedded v4 | YES (narrow) | shim same-packet no-op (§4d) / session miss; family asymmetry vs #1853 | **LOW** |
| Defect 2 baseline — MSS clamp v6 ext gap | YES | clamp silently skipped; no corruption | **LOW** |

No defect is a security-critical RCE/escape; the headline is a
**correctness + resource-leak** bug: NAT silently breaks fragmented flows
AND pool SNAT leaks an allocator port per surviving non-first fragment.
The SNAT port leak (§4b) is the most operationally serious consequence —
sustained fragmented traffic through pool SNAT can exhaust the port pool.
This was masked because (a) fragmentation is uncommon on the loss-cluster
smoke path (MSS-clamped, MTU-clean), (b) ~31% of TCP non-first fragments
drop at the shim (§4a), and (c) the trio prop harness pins *current*
behavior, so none of this is a regression.

## 6. Design — the correct rewrite semantics for fragments

Without datapath reassembly (the dataplane has none — confirmed no
reassembly code), the correct, minimal, flow-preserving behavior is:

- **First / atomic fragment** (offset == 0): full L4 rewrite as today
  (real L4 header present; port writes + checksum deltas are correct).
- **Non-first fragment** (offset != 0): rewrite the **IP address only**
  (consistent across all fragments — required for reassembly), and
  **skip every L4-offset byte operation** (port writes, IP-change L4
  checksum adjust, port enforcement, ICMP ident restore, MSS clamp). The
  address-change delta is folded into the L4 checksum exactly once, on
  the first fragment, which is correct for the whole datagram.

This keeps statically-NAT'd fragmented flows working (today they break),
adds no drop, and needs no reassembly state.

The discriminator is a single per-packet predicate:

- **v4**: `(frag_off & 0x1FFF) != 0` where `frag_off =
  u16::from_be_bytes([ip[6], ip[7]])` (IP-header-relative, trivial).
- **v6**: walk the ext chain for a fragment header (44); non-first iff
  present AND `(frag_off_field & 0xFFF8) != 0`. The shim's meta-led
  `rel_l4` shortcut hides this (the shim already advances past the
  fragment header, so `meta_rel >= 48`), so v6 detection requires either
  an explicit walk or a meta flag (see §7 path options).

## 7. Path options

### Path A — orchestrator-computed, threaded fragment guard (RECOMMENDED)

Compute the non-first-fragment predicate ONCE per packet in each
orchestrator and thread a `non_first_fragment: bool` into the leaves
(SMR F1 — never re-derive; one bounded read/walk per packet, not per
leaf).

- New private helpers in `frame/inspect.rs` (read-only):
  `ipv4_is_non_first_fragment(packet: &[u8]) -> bool` (reads `frag_off =
  u16::from_be_bytes([ip[6], ip[7]]); (frag_off & 0x1FFF) != 0`) and
  `ipv6_is_non_first_fragment(packet: &[u8]) -> bool` (bounded ext walk
  for header 44, `(frag_off_field & 0xFFF8) != 0`; mirrors
  `screen/extract.rs:50-55,99-109`).
- The five orchestrators (`rewrite_apply_v4`/`v6`,
  `build_forwarded_frame_into_*`, `extract_l3_packet_with_nat`) compute
  the predicate once and pass it down.
- `apply_nat_ipv4`/`apply_nat_ipv6` gain a `non_first_fragment: bool`
  param: keep the IP byte writes always; wrap the L4-checksum-adjust call
  AND `apply_nat_port_rewrite` in `if !non_first_fragment { … }`.
- `enforce_expected_ports` / `_at`: early `return Some(false)` when
  `non_first_fragment` (S4 stays LOW but gate it for defense-in-depth).
- `restore_l4_tuple_from_meta`: early `return Some(false)` when
  `non_first_fragment` (ICMP arm).
- Descriptor fast path: compute the predicate in `apply_rewrite_descriptor`
  (orchestrator, `rewrite/mod.rs`) and **return `None`** on a non-first
  fragment so the caller falls back to the generic path. The fall-back is
  CONFIRMED real: `poll_descriptor/flow_cache_hit.rs:264-280`
  `apply_rewrite_descriptor(...).or_else(|| rewrite_forwarded_frame_in_place(...))`
  re-runs the generic rewrite (which carries the leaf-level gate). This
  avoids re-deriving `rd.l4_csum_delta`/`ip_csum_delta` (precomputed
  assuming a normal L4 header) and preserves the #1838 P-N3 byte parity
  by construction (both reviewers confirmed §2).
- **S10 — TCP segmentation**: add an explicit non-first-fragment check to
  the segmentation admission (`tx/dispatch/mod.rs:1031-1055`): a non-first
  fragment must NOT be segmented (it has no TCP header). Treat it as the
  normal forwarding path (which then applies the leaf gate), or pass it
  un-segmented. Leaf gates alone do not cover this orchestrator (Codex
  MED).
- `parse_embedded_v4` (S8): add the IPv4 fragment-offset check, mirroring
  #1853's `parse_embedded_v6_l4` — return `None` for a quoted non-first
  fragment. `build_nat_reversed_icmp_error_v4` (S9) reads `emb_l4_offset`
  DIRECTLY (not via `parse_embedded_v4`), so it needs its OWN symmetric
  guard (SMR nit) — add a fragment-offset check on the quoted v4 header
  before the embedded un-NAT writes.
- **Defect 2**: make `packet_rel_l4_offset_and_protocol`
  (`inspect.rs:145`) **fragment-aware** — on the fragment header (44),
  read the offset bits and `return None` unless zero (the same guard
  #1853 added to `parse_embedded_v6_l4`):
  ```
  44 => {
      let frag = packet.get(offset..offset + 8)?;
      if (u16::from_be_bytes([frag[2], frag[3]]) & 0xFFF8) != 0 {
          return None;
      }
      protocol = frag[0];
      offset = offset.checked_add(8)?;
      …
  }
  ```
  Then `clamp_tcp_mss`'s v6 arm derives the offset via this now-safe
  helper instead of fixed `(40, packet[6])`. This closes the ext-header
  feature gap AND naturally gates the clamp (and every other inspect
  caller of this helper) from misinterpreting non-first-fragment payload
  as L4 (Codex + AGY MED). NOTE: audit the helper's existing callers
  (GRE inner parse, `parse_tcp_reply_source` v6 at `tcp.rs:355`) — none
  should legitimately want a non-first fragment's L4, so `None` is the
  correct answer for all; confirm in implementation.

Pros: one predicate per packet (threaded); IP NAT of fragmented flows
starts working; preserves descriptor↔generic parity by fall-back;
contained to `userspace-dp` (issue scope). Cons: per-packet v6 ext-walk
on the NAT path (bounded 6 iterations); if review flags the cost,
escalate to Path A′.

### Path A′ — meta-flag from the shim (perf-optimal variant of A)

Have `parse_ipv4`/`parse_ipv6` in `userspace-xdp/src/lib.rs` set a
`UserspaceDpMeta.meta_flags` non-first-fragment bit during parse.
Correction (Codex/SMR): `parse_ipv4` does NOT read the v4 `frag_off`
field today (`lib.rs:1103-1117` reads version/IHL/protocol only) — A′
must ADD that 2-byte read; `parse_ipv6` already walks the fragment header
(`:1185`) but does not read the offset bits. A free `meta_flags` bit
exists: only `FABRIC_INGRESS_FLAG = 0x80` is used (`afxdp/icmp.rs:3`), so
e.g. `0x40` is free. Userspace then checks one bit — zero extra parsing.
This is arguably "the admission-layer answer" the trio plan asked for
(the shim IS the admission layer). Cons: wire-protocol extension —
touches the shim + the meta struct (`protocol.rs`/`protocol.go` BOTH
sides per `feedback_wire_protocol_both_sides`). Broader blast radius than
the issue scope; defer unless the v6 ext-walk cost in Path A is shown to
matter.

### Path B — fragment-aware offset helpers that DROP

Make `v6_rel_l4_offset` and the v4 IHL derivation return `None` (drop the
fragment) for non-first fragments at the rewrite entry. Simpler code, but
**changes drop accounting**: today fragmented NAT'd flows partly work
(first frag) / partly corrupt; under B they would be dropped entirely.
For static NAT, dropping all fragments breaks the flow MORE than the
status quo for the first fragment, and contradicts the "rewrite IP on all
fragments" correctness in §6. Also collides with `apply_nat_*`'s
documented skip-vs-fail contract (Some=skip, None=caller drops — invariant
#4 of the trio plan). REJECT as the primary, but viable as an explicit
operator policy (drop fragments through NAT) if §6's IP-only-rewrite is
deemed too clever.

### Path C — partial / document

Fix only the reachable MED corruption (S1/S2 address-NAT L4-csum adjust
gate) + the cheap family-symmetry restore (S8/S9 embedded v4) + the MSS
ext-aware fix (defect 2), and **document** S3/S4/S5/S6/S7 as
known-narrow-residual in `frame/README.md`. Smaller diff, leaves the
ICMP-ident (S5) corruption and the descriptor-path edge unfixed. Viable
if review judges A too broad for the realized risk.

## 8. Recommended path

**Path A** (leaf-level gate + descriptor-path fallback-to-generic +
embedded-v4 parse guard + ext-aware MSS clamp), with **Path A′ held in
reserve** if the v6 ext-walk cost is shown to regress the NAT path. Path A
is the smallest change that (a) stops the reachable MED payload
corruption, (b) makes statically-NAT'd fragmented flows actually work
rather than just "not corrupt," (c) restores v4/v6 embedded symmetry, and
(d) closes defect 2 — all within the issue's `userspace-dp/src/afxdp/`
scope, with the descriptor↔generic parity invariant preserved by
fall-back rather than delta re-derivation.

## 9. Test plan

1. **Extend the #1842 prop harness** (`frame/prop_tests/`): the NAT domain
   currently emits `ExtHdr::Fragment` only with offset 0 (first/atomic —
   `strategies.rs:220` encodes the frag header's offset bytes as 0). Add a
   non-first-fragment generator (offset bits != 0) to `arb_packet_with_nat`
   and assert:
   - P-FRAG-1: address-only NAT on a non-first fragment rewrites the IP
     bytes and leaves every byte at/after the (fictitious) L4 offset
     **identical** to input (no payload corruption);
   - P-FRAG-2: descriptor path returns `None` (falls back) on a non-first
     fragment, and the generic path's output is the IP-only rewrite;
   - P-FRAG-3: first/atomic fragment (offset 0) behavior is byte-identical
     to today (regression guard);
   - keep the existing P-N3 descriptor-vs-generic parity (the fallback
     keeps them equal on the shared non-fragment domain).
2. **Deterministic unit tests**:
   - `ipv4_is_non_first_fragment` / `ipv6_is_non_first_fragment` truth
     table (offset 0 MF=0/1, offset>0, no-frag-header, truncated chain);
   - **pool-SNAT on a non-first fragment**: NO port allocated (no leak),
     payload byte-identical (the §4b regression guard);
   - **wildcard-DNAT on a non-first fragment**: no port write;
   - static-DNAT on a 2-fragment TCP flow: fragment 1 fully NAT'd
     (IP+checksum), fragment 2 IP-only, payload byte-identical;
   - **S10 segmentation**: a large non-first TCP fragment is NOT segmented
     / not NAT-parsed at the fake offset;
   - ICMP echo non-first fragment: `restore_l4_tuple_from_meta` no-ops;
   - `parse_embedded_v4` + `build_nat_reversed_icmp_error_v4` return
     `None` / skip for a quoted non-first fragment; first/atomic quoted
     fragment still parses (mirror the #1853 v6 tests at
     `icmp_embed/parse.rs:262-298`);
   - `packet_rel_l4_offset_and_protocol` returns `None` for a non-first
     fragment (first/atomic still walks) + every existing caller audited
     (GRE inner, `parse_tcp_reply_source` v6) behaves correctly;
   - `clamp_tcp_mss` on an ext-headered v6 SYN now finds + clamps the MSS;
     a non-first fragment / non-SYN still no-ops.
3. **Suites/gates**: `cargo build --release` clean; full `cargo test
   --release` with awk-aggregated pass/fail over all `test result` lines;
   `go test ./...`; the known-flaky ledger (inplace_*, worker_queue
   concurrent_recovery, tx_latency_hist, wg reconcile_peers) must pass
   standalone before attribution. Smoke v4+v6 iperf3 on the loss userspace
   cluster + per-class CoS (parent runs serialized smoke; fragmented
   traffic is not iperf3-able — the prop harness is the functional
   evidence). `make test-failover` if any cluster/forwarding-shared code
   is touched (it is not expected to be).
4. **Never `cargo fmt`** the focused change (per the #1769 reflow gotcha).

## 10. Hidden invariants to preserve

1. **Descriptor↔generic parity (#1838 P-N3, empty mask)** — Path A keeps
   it by making the descriptor path FALL BACK (`None`) on non-first
   fragments rather than re-deriving the precomputed deltas; the generic
   path's IP-only rewrite is then the single source of truth.
2. **Skip-vs-fail contract (trio invariant #4)** — `apply_nat_*` keeps
   returning `Some(())` (skip the L4 work), never `None`, on non-first
   fragments. `None` stays reserved for genuine truncation/short-packet.
3. **v4 byte-identity / first-fragment byte-identity** — the gate only
   changes non-first-fragment output; offset-0 and non-fragmented packets
   are bit-identical (P-FRAG-3).
4. **Hot-path discipline** — predicate is a bounded read (v4: 2 bytes;
   v6: ≤6-iteration walk), only on the NAT/enforce path; no allocation, no
   `dyn`, helpers `#[inline]`. If review flags the v6 walk cost, escalate
   to Path A′.
5. **#1853 embedded-v6 fragment guard** — unchanged; the v4 guard mirrors
   it for symmetry (`embedded_reply_key`/`parse_embedded_v6_l4` semantics).
6. **MSS clamp**: `clamp_tcp_mss` must stay byte-identical for v4 and for
   non-ext v6 (offset 40); only ext-headered v6 changes (gap → clamped).

## 11. Open questions / PLAN-KILL invitation

- **Q1** — Is the §6 "rewrite IP on all fragments, skip L4 on non-first"
  semantics the right firewall behavior, or should NAT'd fragments be
  **dropped** (Path B) to match a "no reassembly ⇒ no fragment NAT"
  stance? Junos SRX default is flow-based reassembly; we have none.
  IP-only-rewrite keeps flows alive and is checksum-correct — but is it
  the behavior operators expect? **This is the kill-or-pick decision.**
- **Q2** — Is the descriptor-path **fall-back-to-generic** (return `None`)
  acceptable, or must the descriptor path handle fragments inline?
  Fall-back is rare (fragments are uncommon) and preserves parity for
  free; inline handling re-opens the delta-derivation divergence #1838
  just closed.
- **Q3** — Path A (contained, per-packet v6 walk) vs Path A′ (meta flag,
  wire-protocol change, zero walk)? Default A; A′ only if walk cost bites.
- **Q4** — Scope: fix both defects in one PR (they share `frame/` and the
  fragment predicate), or split defect 2 (MSS, trivial, independent) into
  its own commit/PR? Lean: one PR, two logical commits.
- **Q5 (PLAN-KILL) — RESOLVED round 1: proceed with Path A, do NOT kill.**
  AGY: "Proceed with Path A (do NOT kill) … silent dropping of fragmented
  transit flows through static NAT / interface NAT is highly disruptive
  and difficult for operators to diagnose; Path A's implementation is
  low-risk and localized." Codex/SMR findings were all revision, none a
  kill. The round-1 retraction of the port-write narrowing (§4b) plus the
  SNAT port-leak (§5) RAISED the realized severity to MED-HIGH, removing
  the doc-only option. Path C is no longer recommended.

## Appendix — reviewer task IDs

See `docs/research/1852-frag-nat/reviewer-ids.md`.
