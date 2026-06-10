# Codex Adversarial Review

Target: branch diff against origin/master
Verdict: needs-attention

PLAN-NEEDS-REVISION. Verified v2 premises in code: ICMPv6 outer match uses `meta.l4_offset` (`icmp_embed/mod.rs:135-137`), the v6 builder is fixed-40 today (`builders.rs:170-178`), `parse_embedded_v6` is fixed +6/+40 today (`parse.rs:93-100`), and Q8's generic port short-circuit vs descriptor delta/canonicalization is real (`frame/mod.rs:867-883`; `rewrite/ipv6.rs:81-99`). Q8: the generic-side no-op-port rule is the right shape. Q9: not sound yet; the fold needs the guards below.

Findings:
- [medium] Embedded non-first fragments would be parsed as TCP/UDP headers (docs/research/1838-nat-v6-trio/plan.md:415-419)
  The §5.7 spec tells `parse_embedded_v6` to call `packet_rel_l4_offset_and_protocol` and then keep reading ports. That helper's Fragment arm sets `protocol = frag[0]` and advances `offset += 8` without checking the fragment-offset bits (`userspace-dp/src/afxdp/frame/inspect.rs:184-187`), then returns that protocol at `:193`. For a quoted non-first IPv6 fragment, there is no L4 header there; those bytes are payload. Current `parse_embedded_v6` leaves `proto = frame[embedded_ip_start + 6]` and `l4_off = embedded_ip_start + 40` (`userspace-dp/src/afxdp/icmp_embed/parse.rs:93-100`), so Fragment stays protocol 44 instead of synthesizing TCP/UDP ports. v2 would enable false NAT/session matches and builder writes into quoted payload for valid ICMPv6 errors.
  Recommendation: Specify a fragment-aware embedded IPv6 walker: allow atomic/first fragments with fragment offset 0, but return `None` before exposing proto/ports for non-first fragments. Add deterministic icmp_embed tests for embedded first/atomic fragments and embedded non-first fragments that must not match or rewrite.
- [medium] ICMPv6 builder checksum recompute still misses zero canonicalization (docs/research/1838-nat-v6-trio/plan.md:425-427)
  §5.7 says the final ICMPv6 checksum recompute becomes RFC-correct automatically by calling `checksum16_ipv6(..., pkt[icmp_offset..])`, but the current builder writes that raw result directly (`userspace-dp/src/afxdp/icmp_embed/builders.rs:202-209`). v2's Q2 rider only updates `recompute_l4_checksum_ipv6` (`plan.md:310-314`); this builder does not call that helper. If the rewritten ICMPv6 error computes to 0, the builder still emits `0x0000`, contradicting the plan's own v6 UDP/ICMPv6 computed-zero matrix (`plan.md:384`). A full recompute oracle can still pass this representation, so the gap needs a stored-value assertion.
  Recommendation: Canonicalize `icmp6_csum` in `build_nat_reversed_icmp_error_v6` with the same `0 -> 0xffff` rule, and add a deterministic balancing test that forces the builder's recomputed ICMPv6 checksum to zero and asserts the stored field is `0xffff`.

Next steps:
- Revise §5.7 before implementation to make embedded IPv6 parsing fragment-aware.
- Extend the icmp_embed test plan with non-first-fragment negative coverage and stored-zero ICMPv6 checksum coverage.
