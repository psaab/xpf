I will start by listing the contents of the target directory to verify the presence of the files in the plan and to check the worktree path.
I will view the first 800 lines of the `plan.md` file to read the v2 delta specs.
I will search for `parse_embedded_v6` to locate the source code files for the icmp_embed module.
I will list the files in the `icmp_embed` directory to identify the relevant source files.
I will view `parse.rs` in `icmp_embed` to inspect `parse_embedded_v6`.
I will view the first 70 lines of `parse.rs` to understand the structs defined there.
I will search the codebase for `packet_rel_l4_offset_and_protocol` to verify if it is defined and how it is imported.
I will view the contents of `builders.rs` to see `build_nat_reversed_icmp_error_v6` and verify section 5.7's findings.
I will search for the definition of `UserspaceDpMeta` to confirm its fields.
I will view `userspace-dp/src/afxdp/types/mod.rs` to see `UserspaceDpMeta`'s fields.
I will search for `packet_rel_l4_offset` to check if it expects a frame-relative or L3-relative slice.
I will view `userspace-dp/src/afxdp/frame/inspect.rs` to understand the offset helper's expectations.
I will view `userspace-dp/src/afxdp/frame/mod.rs` around line 550 to see the context of the v6 offset parsing.
I will view the contents of `userspace-dp/src/afxdp/frame/rewrite/ipv6.rs` around line 18.
I will search for `extract_l3_packet_with_nat` to find the exact location of this function and see how it parses offsets.
I will view `slow_path.rs` to see `extract_l3_packet_with_nat`.
I will view the contents of `userspace-dp/src/afxdp/icmp_embed/mod.rs` to see the module declarations and imports.
I will search for `const AF` or `AF_INET` to see what constants represent address families.
I will search for `meta.addr_family` in the `userspace-dp` directory to see how the code maps address families.
I will search for `AF_INET6` or `AF_INET` in the `icmp_embed` directory to see how family constants are referenced.
I will view the parent module `userspace-dp/src/afxdp/mod.rs` to understand the submodule structure.
I will search for references to `frame::` in `userspace-dp/src/afxdp/mod.rs` to see if `frame`'s internals are re-exported or called with the `frame::` prefix.
I will view `userspace-dp/src/afxdp/icmp_embed/session_match.rs` to see if there are other fixed-40 assumptions.
I will view `userspace-dp/src/afxdp/icmp_embed/nat_match_v6.rs` to see if there are any other fixed-40 or offset assumptions.
I will search for `stored_l4_checksum` or `write_l4_checksum` to see if they already exist or how checksums are read and written.
I will search for `write_l4_checksum` in `userspace-dp/src/afxdp/frame` to see if there is any similar function.
I will search for the word `checksum` in `frame/mod.rs` to find how ports or checksums are modified.
I will view `userspace-dp/src/afxdp/frame/mod.rs` around lines 846 to 925 to see how checksum values are read and written.
I will view the rest of `rewrite/ipv6.rs` to see the details of checksum delta application and canonicalization.
I will search for `l4_offset =` in `userspace-xdp` to see where the metadata is populated.
I will view `userspace-xdp/src/lib.rs` from lines 1100 to 1220 to see exactly how metadata is populated in XDP.
I will search for `l4_offset` assignments in the test directory to see if any tests generate dummy or contradictory metadata.
I will view `userspace-dp/src/afxdp/frame/tests.rs` around line 5094 to see how the metadata and frames are mock-configured.
I will search for `recompute_l4_checksum_ipv6` in `frame/tests.rs` to see the callers.
I will search for `adjust_l4_checksum_ipv6_words` to find all of its callers.
I will search for `adjust_l4_checksum_ipv6_addr_bytes` to find all of its callers.
I will view `userspace-dp/src/afxdp/frame/checksum.rs` around line 506 to see its current definition.
I will view `userspace-dp/src/afxdp/frame/checksum.rs` around lines 570-620 to check `recompute_l4_checksum_ipv6`.
I will search for `ipv6_words` to see if it is used outside the deleted helpers or in tests.
### Verdicts

* **#1838 (Ext-header generic NAT)**: **PLAN-READY**
* **#1839 (Zero-checksum canonicalization)**: **PLAN-READY**
* **#1840 (UDP zero-csum family gate)**: **PLAN-READY**

---

### Findings

#### 1. Bare `AF_INET6` Constant in `icmp_embed/parse.rs`
* **Quote**: [plan.md:416](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/docs/research/1838-nat-v6-trio/plan.md#L416)
  ```rust
  packet_rel_l4_offset_and_protocol(&frame[embedded_ip_start..], AF_INET6)
  ```
* **Impact**: The constant `AF_INET6` is not defined or imported in `userspace-dp/src/afxdp/icmp_embed/parse.rs`. The code uses `libc::AF_INET6 as u8` elsewhere in the module. Using a bare `AF_INET6` will trigger a compilation error.
* **Fix**: Change it to `libc::AF_INET6 as u8` in the implementation.

#### 2. Undefined helper symbols `stored_l4_checksum` and `write_l4_checksum` in Section 5.5
* **Quote**: [plan.md:357-359](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/docs/research/1838-nat-v6-trio/plan.md#L357-L359)
  ```rust
  && stored_l4_checksum(packet, l4_offset) == Some(0)
  ...
  write_l4_checksum(packet, l4_offset, 0xFFFF);
  ```
* **Impact**: The helper symbols `stored_l4_checksum` and `write_l4_checksum` do not exist in the `frame` module. Implementing them verbatim will cause compilation errors.
* **Fix**: Clarify that they should either be defined as helper functions or inlined using safe byte slicing (e.g. `let checksum_offset = l4_offset.checked_add(6)?` and bounds-checked slice access).

#### 3. Visibility of `v6_rel_l4_offset` across submodules
* **Quote**: [plan.md:172](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/docs/research/1838-nat-v6-trio/plan.md#L172) and [plan.md:421](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/docs/research/1838-nat-v6-trio/plan.md#L421)
  ```rust
  pub(in crate::afxdp) fn v6_rel_l4_offset
  ```
* **Impact**: The helper `v6_rel_l4_offset` is defined in `frame/mod.rs` and consumed in `icmp_embed/builders.rs`. Because `userspace-dp/src/afxdp/mod.rs` includes `use self::frame::*;`, the helper is correctly exposed to the parent module namespace and visible to the `icmp_embed` submodule. However, the plan must ensure it is declared as `pub(in crate::afxdp)` inside `frame/mod.rs` (or re-exported there) rather than being hidden in sub-modules.

---

### Responses to Open Questions

#### Q1: Precedence of meta-trust (Accept vs. Re-litigate)
* **Status**: **ACCEPTED**
* **Rationale**: The production metadata generator (the XDP parser program in [userspace-xdp/src/lib.rs:1158-1208](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/userspace-xdp/src/lib.rs#L1158-L1208)) correctly walks extension chains to set `l4_offset` and `protocol` to their final values. No contradictory metadata producer exists in the production codebase or test suite; thus, trusting `meta_rel` when `meta_rel >= 40` is correct and does not pose a corruption risk.

#### Q8: Shape of the §5.5 identity-port rule
* **Status**: **ACCEPTED**
* **Rationale**: The generic-side rule is correct. In the descriptor path, `l4_csum_delta == 0xFFFF` is applied unconditionally to stored-0 UDP packets to produce `0xFFFF` for any port-NAT decision (even if it's value-identity). Unifying this on the generic side by rewriting stored `0x0000` to `0xFFFF` when a port-NAT decision is present ensures exact parity. There are no address/port-canceling or identity scenarios where this rule fails to match descriptor output.

#### Q9: `icmp_embed` spec
* **Status**: **ACCEPTED**
* **Rationale**: The spec is correct. Reusing the metadata-led `v6_rel_l4_offset` for the outer header is correct because the outer IPv6 error frame starts at `l3_offset` and its L4 header offset relative to L3 is correctly derived. Re-walking the embedded packet using `packet_rel_l4_offset` is also correct because the embedded packet does not have its own metadata, requiring a raw parser walk.
