# Codex hostile plan review — #1824 r1

Task: task-mq8eallo-ig9zmu (Codex session 019eb2c4-a385-7043-82d0-0db8ba72c8de).
Plan reviewed: v1.1 @ 8e0c13e894ad. Verdict and findings verbatim below.
All file:line quotes independently re-verified against the worktree by Claude
before acceptance (verify_built_frame_checksums v4-TCP-only early returns at
frame/mod.rs:1129-1131; ConfigSnapshot derive without PartialEq at
protocol/snapshot.rs:182; NatDecision::reverse reverse-flow semantics at
nat/mod.rs:71-74; flow_cache should_cache nat64/nptv6 gates at
flow_cache.rs:223-224; generic-path NAT-before-enforce_expected_ports
ordering at frame/mod.rs:514-526) — all accurate.

---

PLAN-NEEDS-REVISION.

**Findings**

1. **HIGH - P-N3 is false/vacuous as specified.**
Evidence: plan.md:244: `assert the resulting frames are byte-identical and both pass verify_built_frame_checksums (frame/mod.rs:1120).` But frame/mod.rs:1129: `// Only handle IPv4 TCP for now (main traffic under test).` and frame/mod.rs:1131: `return (true, true);` for IPv6. Also descriptor IPv6 canonicalizes zero for all protocols: rewrite/ipv6.rs:97: `// IPv6 UDP must have non-zero checksum; use 0xFFFF for all.` while generic checksum policy excludes TCP: checksum.rs:88: `ChecksumFamily::V6 => matches!(protocol, PROTO_UDP | PROTO_ICMPV6),`
Fix: replace `verify_built_frame_checksums` with a real v4/v6 recompute oracle, and either exclude v6 TCP checksum-zero boundary from byte equality or make checksum bytes validity-only like P-N1.

2. **HIGH - P-N3 conflates fallback cases and expected-port semantics.**
Evidence: descriptor validates ports before NAT: rewrite/ipv4.rs:36: `// Port validation (DMA race guard).`; generic applies NAT before enforcing ports: frame/mod.rs:514: `if apply_nat {` and frame/mod.rs:526: `let enforced = enforce_expected_ports(packet, meta.addr_family, meta.protocol, expected_ports)`. TTL is not "generic only writer": rewrite/ipv4.rs:31: `if !skip_ttl && packet[ip + 8] <= 1 {`; frame/mod.rs:495: `if !skip_ttl && packet[ip_start + 8] <= 1 {`. NAT64/NPTv6 are not cacheable: flow_cache.rs:223: `&& !decision.nat.nat64` and flow_cache.rs:224: `&& !decision.nat.nptv6`.
Fix: split P-N3 into "both succeed with `expected_ports=None` or post-NAT expected ports" and separate deterministic fallback tests for port mismatch, TTL expiry, NAT64, and NPTv6.

3. **MED - P-N1 still leaves `inverse(D)` underspecified.**
Evidence: plan.md:242: `after apply_nat(apply_nat(pkt, D), inverse(D))`. The available `NatDecision::reverse` is reverse-flow, not same-packet undo: nat/mod.rs:71: `rewrite_src: self.rewrite_dst.map(|_| original_dst),` and nat/mod.rs:72: `rewrite_dst: self.rewrite_src.map(|_| original_src),`.
Fix: define an explicit same-packet undo `NatDecision` in the harness. Keep checksum bytes excluded and accept IPv4 UDP zero-checksum as valid zero after both hops.

4. **MED - §5.2 does not actually force AH coverage.**
Evidence: plan.md:215: `IHL ∈ {20, 24, 60}, optional VLAN tag, IPv6 with 0–2 extension`; plan.md:216: `headers (hop-by-hop/dest-opts) and optional fragment header.` AH is a distinct parser arm: inspect.rs:60: `51 => {`; fragment is inspect.rs:68: `44 => {`.
Fix: add a structured IPv6 chain strategy with forced AH, forced fragment, `No Next Header`, and >6-extension cases. Do not rely on stamped garbage to hit these.

5. **MED - S3 ConfigSnapshot round-trip cannot compile as written and adds little.**
Evidence: plan.md:251: `serde_json::from_*(serde_json::to_*(x)) == x`. But snapshot.rs:182: `#[derive(Clone, Debug, Serialize, Deserialize, Default)]` for `ConfigSnapshot`, no `PartialEq`.
Fix: drop S3 from this plan. If desired, keep only a small ordinary `StateWriter::persist` unit test outside the fuzz/property scope.

6. **LOW - Runtime/determinism and cargo-fuzz wording need tightening.**
Evidence: plan.md:288: `Determinism: proptest's default RNG is deterministic per-seed with`; passing runs are not fixed-seed by default. Also main.rs:1: `mod afxdp;` confirms private bin-root modules, but "structurally blocked" overstates it: ugly source-inclusion/cfg-fuzz shims exist.
Fix: either set fixed seeds or remove the deterministic-run claim; keep committed `proptest-regressions`. Reword cargo-fuzz as "not worth the lib facade or hacks now," not "impossible."

External docs checked: cargo-fuzz README, proptest Config docs, proptest FileFailurePersistence docs.

**§11 Answers**

Q1: Worth it after revision for S1/S2/S4; not PLAN-KILL.
Q2: P-N3 is not sound as written; split success, fallback, and checksum-oracle cases.
Q3: Need dedicated structured IPv6 extension-header generation plus coverage spot-check.
Q4: Drop S3.
Q5: Commit regressions; default SourceParallel path is fine, but fix the RNG determinism claim.
Q6: Use `frame/prop_tests/` directory with private shared strategies, not cross-imports from `prop_inspect_tests.rs`.
