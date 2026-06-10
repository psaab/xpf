# Codex hostile plan review — #1824 r3 (final)

Task: task-mq8f5joq-qmbo0i (Codex session 019eb2da-adca-7270-839e-be408f18020b).
Plan reviewed: v3 @ 6d3db69b5851. Verdict and findings verbatim below.

---

PLAN-READY

**Findings**

No blocking findings.

- D3 fold is correct. v3 excludes ext-header IPv6 from NAT-applying generators: `docs/research/1824-fuzz-harness/plan.md:257-262`, and P-N3/P-T4 repeat that restriction at `plan.md:299` and `plan.md:326`. Source matches the defect: generic IPv6 NAT hardcodes `apply_nat_port_rewrite(packet, 40, ...)` at `userspace-dp/src/afxdp/frame/mod.rs:839-841`; checksum offsets hardcode `40usize.checked_add(delta)` at `userspace-dp/src/afxdp/frame/checksum.rs:490` and `:516-517`. Descriptor IPv6 uses real `rel_l4` at `userspace-dp/src/afxdp/frame/rewrite/ipv6.rs:35-42`. Non-blocking nit: the plan's `checksum.rs` shorthand means `frame/checksum.rs`, not top-level `afxdp/checksum.rs`.

- P-N3b fold is correct. v3 now says declined cases assert "bytes from the L3 offset onward are untouched," not whole-frame untouched: `plan.md:300`. Source confirms L2 prep happens before TTL/port validation: generic calls prep at `frame/mod.rs:581`, prep writes/moves L2 at `frame/mod.rs:403` and `:413`, descriptor calls the same prep at `frame/rewrite/mod.rs:56`. NAT64/NPTv6 decline is before prep at `frame/rewrite/mod.rs:51-53`, and flow cache excludes those descriptors at `userspace-dp/src/afxdp/flow_cache.rs:221-224`.

- I do not see a remaining valid-input divergence in the v3 domain. VLAN and tx-offset shifts go through shared `rewrite_prepare_eth_from_parts` and shared `classify_in_place_l2_rewrite` (`frame/mod.rs:367-388`, `:345-363`). IPv4 options are handled by IHL on both paths: generic `apply_nat_ipv4` uses `ihl` for checksum and ports (`frame/mod.rs:713-760`), descriptor uses `l4 = ip + ihl` (`frame/rewrite/ipv4.rs:27-34`). Trim/payload length is shared through `trim_l3_payload` (`frame/mod.rs:383`, `:651-692`). With `expected_ports=None`, generic enforcement returns false immediately (`frame/mod.rs:919-927`).

Q1: Yes, v3 folds both r2 findings; I cannot construct a valid-input divergence inside the restricted domain.

Q2: Nothing else blocks PLAN-READY; implementation should compare returned `offset,len` output slices and use the promised shared byte-mask helper.
