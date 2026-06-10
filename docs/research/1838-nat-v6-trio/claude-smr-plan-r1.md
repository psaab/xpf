# Claude SMR hostile plan review — round 1

Target: `docs/research/1838-nat-v6-trio/plan.md` v1 (`1db189c5aad0`).
Reviewer stance: hostile domain SMR (dataplane/NAT/checksum semantics),
per `feedback_triple_review_includes_claude_smr`.

## Verdict

**PLAN-NEEDS-REVISION** (revisable in-round; no KILL). The core fix shapes
for all three defects survive hostile reading, but the §5.6 parity matrix
overclaims byte-identity in one reachable corner, and the blast-radius hunt
missed two same-class sites in adjacent subsystems that §10 must own
explicitly.

## Findings

### F1 (MAJOR — matrix overclaim): residual divergence on stored-zero v6 UDP × identity port rewrite

Plan §5.6 row 2 ("v6 UDP stored 0x0000 + port NAT → identical") implicitly
assumes `old_port != new_port`. For an **identity** port rewrite
(`rewrite_src_port == current src port` — reachable via port-preserving
SNAT), the generic path short-circuits BEFORE the adjuster
(`frame/mod.rs:870` `if old_port != new_src_port`, `:879` for dst) and never
touches the checksum → emits 0x0000. The descriptor path applies its ≡0
delta unconditionally (`l4_csum_delta == 0xFFFF != 0` passes the
`rewrite/ipv6.rs:81` gate; pinned at `prop_tests/rewrite.rs:526`), lands on
computed 0, and canonicalizes → 0xFFFF. The planned #1839/#1840 fixes do NOT
close this corner: post-fix outputs remain 0x0000 (generic) vs 0xFFFF
(descriptor).

- Reachability: malformed input only (v6 UDP stored 0) × identity rewrite —
  the same input class as #1840, narrower trigger. Valid-packet generators
  never produce it, so the un-masked P-N3 property is NOT blocked.
- v4 counterpart is parity-clean (generic short-circuit keeps 0; descriptor
  v4 arm skips on `old_l4_csum == 0`, `rewrite/ipv4.rs:104`).
- v6 TCP stored-0 (valid) × identity rewrite is parity-clean AFTER the #1839
  fix (descriptor maps C→C, keeps 0 under the TCP predicate).

Required plan change: correct the §5.6 matrix (split row 2 into
`old≠new` / identity sub-rows), add a deterministic pin-style example test
documenting the residual, and add an open question on whether to accept the
residual (recommended: yes — malformed-only, wire-meaningless either way)
or pursue full parity via a stored-0 skip in BOTH paths for v6 UDP (which
would contradict #1840 as filed).

### F2 (MINOR — missed same-class site): icmp_embed fixed-40 pair

`icmp_embed/parse.rs:100` (`let l4_off = embedded_ip_start + 40;`) and
`icmp_embed/builders.rs:172-178` (`emb_ip_offset + 40`,
`emb_l4_offset = emb_ip_offset + 40`) assume no ext headers on either the
outer ICMPv6 error or the embedded packet when matching and un-NAT-ing
allow-embedded-icmp replies. Internally consistent (the fixed-40 parse gates
what the fixed-40 builder sees, so ext-headered embedded packets fail the
session MATCH and never reach the rewrite), a separate subsystem, and not
part of the descriptor↔generic parity surface — but the plan's §5.3 "blast
radius" / §10 must name it and commit to a follow-up issue, since the next
reader grepping for fixed-40 will find it and ask.

### F3 (MINOR — missed same-class site, safe-bail flavor): MSS clamp v6 arm

`frame/tcp.rs:213` (`(40, packet[6])` then `if protocol != PROTO_TCP {
return false; }`): an ext-headered TCP SYN has `packet[6]` = ext-header type
≠ TCP, so the clamp silently no-ops. No corruption (safe bail), but it is a
fixed-40 feature gap in the same family. §10 should list it (out of scope,
optionally folded into the F2 follow-up issue).

### F4 (NIT): §5.2 caller-table wording

The `extract_l3_packet_with_nat` row should state explicitly that
`v6_rel_l4_offset` is called with the L3-relative slice + frame-relative
meta scalars, same as every other site — current wording is fine after the
v1 edit but the "only the v6 arm changes" note belongs in the design text,
not just the table.

### Verified-clean (hostile checks that PASSED)

- §5.3 segmentation payload-length arithmetic: confirmed against
  `frame/tcp_segmentation.rs:66-70` (ip_header_len = ext-aware tcp_offset),
  `:147` (full header copy incl. ext chain), v6 arm payload-length write
  (`tcp_header_len + chunk_len`). The proposed
  `(ip_header_len - 40) + tcp_header_len + chunk_len` is correct and
  degenerates to today's value for no-ext.
- §5.4 direction: RFC 8200 §8.1 mandates 0→0xFFFF for UDP only; v6 TCP
  0x0000 is valid; matches the pinned v4 TCP behavior
  (`checksum.rs:895` test). Descriptor-adopts-predicate is the right
  direction.
- §5.6 rows 1, 3-6 arithmetic: one's-complement fold associativity makes
  `checksum16_adjust(current, old, new)` and the precomputed-delta
  application equal for `old≠new`; identity corners checked separately (F1).
- NAT64 exclusion: `nat64.rs` uses only its local `checksum16*`
  (nat64.rs:323-438); no use of the affected helpers.
- `gre.rs:41` (v6 address slice for keying) and `icmp.rs:196-221`
  (from-scratch base-40 error builder) are correct at fixed offsets.
- Reachability map G1-G7: matches every non-test caller of
  `apply_nat_ipv6` / `rewrite_forwarded_frame_in_place` /
  `extract_l3_packet_with_nat` / segmentation in the tree.
- v6 NAT66+port production reachability: `nat/source.rs:434` (interface
  SNAT v6), `:502-531` (v6 pool SNAT with `rewrite_src_port: Some(port)`).

## Round-1 disposition

Fold F1 (matrix split + residual pin + open question Q8), F2/F3 (§10
entries + follow-up-issue commitment) into plan v1.1 alongside Codex/AGY
round-1 findings.
