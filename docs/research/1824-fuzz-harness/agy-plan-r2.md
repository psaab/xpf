# AGY adversarial plan review — #1824 r2

Job: adversarial-review-mq8euds7-fy9qg1. Plan reviewed: v2.1 @ 86e6b1a5e9f1.

NOTE (Claude, post-review): AGY's Q1 answer (byte-equality provable, 'identical write helpers') is REFUTED by Codex r2's verified counterexample — generic apply_nat_ipv6 hardcodes L4 at offset 40 (frame/mod.rs:840-841) and the v6 checksum adjusters hardcode 40+delta (checksum.rs:490/517), while the descriptor path parses real ext-header offsets (rewrite/ipv6.rs:35-41). AGY r2 therefore counts as PLAN-READY on the folds it verified (F1-F5 all accurate) but NOT on round-2 Q1; round 3 requires AGY to confront the counterexample.

PLAN-READY

F1: userspace-dp/src/protocol/snapshot.rs:183
`ConfigSnapshot` derives `Clone, Debug, Serialize, Deserialize, Default` but lacks `PartialEq`, verifying that the S3 property would fail compilation and that the descope is structurally necessary.

F2: userspace-dp/src/nat/mod.rs:71-74
`NatDecision::reverse` maps `rewrite_src` using `rewrite_dst` and vice-versa for return-flow replies, confirming that using it as a same-packet inverse is unsound and requires a custom harness-defined field-by-field undo.

F3: userspace-dp/src/afxdp/frame/mod.rs:495
`rewrite_apply_v4` checks `if !skip_ttl && packet[ip_start + 8] <= 1 { return None; }` (and similarly for v6 hop limit at line 547), confirming both generic and descriptor paths decline TTL/hop-limit <= 1.

F4: userspace-dp/src/afxdp/frame/mod.rs:906
`adjust_l4_checksum_port` implements family-ungated skip `if matches!(protocol, PROTO_UDP) && current == 0 { return Some(()); }`, confirming the D2 divergence on malformed IPv6 UDP frames.

F5: userspace-dp/src/afxdp/frame/rewrite/ipv6.rs:98
`let final_csum = if new_l4 == 0 { 0xFFFFu16 } else { new_l4 };` is applied to all IPv6 protocols in the descriptor path, whereas generic path at `checksum.rs:88` only canonicalizes UDP/ICMPv6, verifying the D1 divergence.

Q1: Yes, the remaining byte-equality is provable because both paths use identical write helpers to modify addresses/ports, decrement TTL/hop limit identically, and utilize the same L2 prepare/shifting logic.
Q2: Yes, it is sufficiently covered; P-N4 guarantees payload immutability, and P-N1 guarantees round-trip identity of all non-checksum header bytes without needing an explicit frame-diff mask.
Q3: Yes, documenting and accommodating in tests while filing separate production issues is correct, as it avoids coupling the test-harness introduction to production modifications.
Q4: No, the counts are appropriate because continuous execution of different random seeds in local test gates, regression file replay, and the manual soak knob provide sufficient coverage.
Q5: No, the plan is highly valuable for pinning critical parsing and NAT invariants, and the descope of state_writer serialization keeps the scope clean.
