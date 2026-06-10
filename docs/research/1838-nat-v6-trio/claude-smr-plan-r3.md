# Claude SMR hostile plan review — round 3

Target: plan.md v3 (`3a767a91cdc9` + the §5.7 v4-parser note). Scope: the
two Codex-r2 amendments only.

## Verdict

**PLAN-READY** (all three defects).

## Checks

1. **Fragment-aware embedded walker (§5.7 step 1)** — semantics verified
   against RFC 8200 §4.5 and `inspect.rs:184-193`: the fragment header is
   `[next, reserved, offset(13b)+res+M, ident(4B)]`; offset bits
   (`bytes[2..4] & 0xFFF8`) zero ⇒ first/atomic fragment, L4 header
   present at the walk's landing offset — allowing the match is correct;
   nonzero ⇒ no L4 header, `None` is the only safe answer. The amendment
   preserves today's accidental safety (fixed-40 read leaves proto=44 →
   never matches) while gaining the ext-header coverage. One addendum
   folded into §5.7: `parse_embedded_v4` (parse.rs:36-60) carries the same
   PRE-EXISTING exposure on the v4 side (no fragment-offset check before
   port reads) — assigned to the Q4 follow-up issue, explicitly not
   regressed or silently absorbed.
2. **Builder ICMPv6 computed-zero canonicalization (§5.7 step 2)** —
   consistent with `adjust_zero_checksum_illegal(PROTO_ICMPV6, V6) ==
   true` and the Q2 recompute rider: after this PR every v6
   ICMPv6-checksum producer in the tree (incremental adjusters, recompute
   helper, icmp_embed builder) emits the same encoding for computed zero.
   The stored-field representation test is the right assertion shape (the
   sum-to-0xFFFF oracle is representation-blind by design).

No new defects found in the v3 deltas.
