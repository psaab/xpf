# AGY adversarial plan review — #1824 r1

Job: adversarial-review-mq8eiccu-dallbv (retry; first attempt adversarial-review-mq8ea0yw-jue1qe timed out).
Plan reviewed: v1.1 @ 8e0c13e894ad. Verdict + findings verbatim below (tool-narration preamble stripped).
frame/mod.rs:906 quote independently re-verified by Claude — accurate (family-ungated UDP current==0 bypass, comment admits 'optional for IPv4 UDP').

PLAN-NEEDS-REVISION

userspace-dp/src/afxdp/frame/rewrite/ipv6.rs:98
Quote: "let final_csum = if new_l4 == 0 { 0xFFFFu16 } else { new_l4 };"
Why: The descriptor path unconditionally maps new_l4 == 0 to 0xFFFF for all L4 protocols (including TCP), whereas the generic path (adjust_zero_checksum_illegal in frame/checksum.rs:88) only canonicalizes for UDP and ICMPv6. This causes byte-level divergence (P-N3 failure).
Fix: Restrict the 0xFFFF mapping in the descriptor path to UDP and ICMPv6 protocols.

userspace-dp/src/afxdp/frame/mod.rs:906
Quote: "if matches!(protocol, PROTO_UDP) && current == 0 {"
Why: adjust_l4_checksum_port is shared by IPv4 and IPv6. For UDP, it bypasses the checksum update if the current checksum is 0x0000. In IPv6 UDP, a 0 checksum is malformed; the generic path will bypass it on port-rewrite (keeping it 0), while the descriptor path will update it, causing divergence.
Fix: Restrict the current == 0 bypass in adjust_l4_checksum_port to IPv4 UDP only.

docs/research/1824-fuzz-harness/plan.md:242
Quote: "after apply_nat(apply_nat(pkt, D), inverse(D)) the addresses, ports... are byte-identical"
Why: NatDecision::reverse swaps the src and dst associations to apply to the reverse-flow reply packet. Using it as inverse(D) on the same packet will fail to restore it (e.g. leaving src rewritten and corrupting dst).
Fix: Specify that inverse(D) must be a custom test-only decision mapping rewritten values directly back to their originals without swapping.

docs/research/1824-fuzz-harness/plan.md:215
Quote: "IPv6 with 0–2 extension headers (hop-by-hop/dest-opts) and optional fragment header."
Why: The proposed arb_valid_packet generator only lists hop-by-hop, dest-opts, and fragment headers, completely omitting Routing Header (43) and AH (51). It will fail to exercise the corresponding parse arms in inspect.rs:52 and inspect.rs:60-67.
Fix: Expand the IPv6 extension header strategy to generate Routing (43) and AH (51) headers.

Q1: Yes, the property tests are highly valuable because they establish permanent regression guards for parser panic-freedom and checksum correctness across boundary conditions that example-based tests miss.
Q2: No, it is unsound as specified due to the TCP/IPv6 zero-checksum mapping divergence (descriptor maps all zero L4 checksums to 0xFFFF, generic only does so for UDP/ICMPv6) and IPv6 UDP zero-checksum port-rewrite bypass divergence.
Q3: The garbage generator will not reliably reach AH (51) or Fragment (44) arms; a structured extension header strategy is required, and we should verify code coverage via llvm-cov during initial development.
Q4: Drop S3 entirely as it represents test ballast with low value; the Rust crate lacks a decoder, and state snapshot serialization is already covered by Go contract tests and existing unit tests.
Q5: Keep the committed regressions in-repo to guarantee deterministic regression-pinning on CI, but enforce strict path prefix filtering so only minimal, shrunk failures are checked in.
Q6: The layout contract demands grouping them in a single frame/prop_tests/ directory module to prevent parent-directory clutter and maintain module boundary organization.
