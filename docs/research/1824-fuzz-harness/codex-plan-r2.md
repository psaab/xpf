# Codex hostile plan review — #1824 r2

Task: task-mq8evi7r-vd8x4k (Codex session 019eb2d3-80ec-7f61-8763-a038c01692a8).
Plan reviewed: v2.1 @ 86e6b1a5e9f1. Verdict: **PLAN-NEEDS-REVISION**, 2 HIGH
findings. Both independently re-verified in source by Claude before
acceptance — both REAL, and finding 1's blast radius is larger than Codex
stated: not just `apply_nat_port_rewrite(packet, 40, …)`
(frame/mod.rs:840–841 "IPv6 header is always 40 bytes (no IHL)"), but ALSO
both generic v6 checksum adjusters hardcode the L4 checksum offset as
`40usize.checked_add(delta)` (`adjust_l4_checksum_ipv6_words`
checksum.rs:490, `adjust_l4_checksum_ipv6_addr_bytes` checksum.rs:516–517
"40 + {16,6,2} reproduces the previous absolute constants 56/46/42"), so the
generic v6 NAT path assumes ext-header-free packets even for address-only
NAT. Recorded as §10-D D3.

---

PLAN-NEEDS-REVISION

**High Findings**
1. P-N3 is still unsound for valid IPv6 packets with extension headers plus port NAT. The plan claims P-N3 frames are "byte-identical except ALL checksum fields" (plan.md:272), while also requiring structured v6 ext-header generation (plan.md:236).

Descriptor path computes/parses actual L4 offset and writes ports there: ipv6.rs:35, ipv6.rs:65. Generic v6 computes `rel_l4` (mod.rs:550) but `apply_nat_ipv6` hardcodes port rewrite at `40` (mod.rs:839), and the helper writes at that offset (mod.rs:867). Counterexample: valid IPv6 TCP/UDP with hop-by-hop/dest/routing/AH header so L4 > 40, plus `rewrite_src_port` or `rewrite_dst_port`. Both paths can return `Some`; descriptor rewrites the real L4 port, generic rewrites extension-header bytes. Divergence is outside checksum bytes.

2. P-N3b "decline means untouched" is false. The plan says TTL/hop-limit <= 1 means both return `None` and "neither writes," and port mismatch leaves descriptor frame "untouched" (plan.md:273).

Both paths do L2 prep before TTL/port validation: generic calls prep before family rewrite (mod.rs:581); descriptor calls prep before dispatch (rewrite/mod.rs:56). Prep writes Ethernet/VLAN bytes (mod.rs:403, mod.rs:413). TTL checks happen later (mod.rs:495, ipv4.rs:31); descriptor port mismatch is also after prep (ipv4.rs:36). Revise examples to allow L2 mutation, pre-seed identical L2, or assert only no L3/NAT mutation.

**Q1-Q5**
Q1: No; valid IPv6 ext-header + port NAT is a concrete non-checksum divergence.
Q2: Add an explicit frame-diff mask; it is cheap and removes ambiguity.
Q3: D1/D2 document-and-file is acceptable, but the new v6-ext port-NAT divergence must be fixed or P-N3 must exclude that class.
Q4: Counts are acceptable if ext-header coverage is weighted/deterministic and llvm-cov confirms branch reach.
Q5: Not PLAN-KILL overall, but P-N3/P-N3b need revision before this is ready.
