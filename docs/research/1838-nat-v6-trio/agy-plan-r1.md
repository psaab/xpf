### Verdicts

*   **#1838 (Ext-header generic NAT)**: **PLAN-NEEDS-REVISION**
*   **#1839 (Zero-checksum canonicalization)**: **PLAN-READY**
*   **#1840 (UDP zero-csum family gate)**: **PLAN-READY**

---

### Findings

#### 1. Missed Fixed-40 Site in ICMPv6 NAT Error Embedding
*   **Quote**: [builders.rs:178](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/userspace-dp/src/afxdp/icmp_embed/builders.rs#L178)
    ```rust
    let emb_l4_offset = emb_ip_offset + 40;
    ```
*   **Impact**: When NAT'ing an ICMPv6 error reply for a flow that carries IPv6 extension headers, the embedded packet has the same extension headers. Hardcoding 40-byte offset here causes the port rewrite to corrupt the first extension header at `emb_ip_offset + 40` and leaves the actual L4 port un-translated.

#### 2. Missed Fixed-40 & Ungated Parsing in ICMPv6 Error Parsing
*   **Quote**: [parse.rs:100](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/userspace-dp/src/afxdp/icmp_embed/parse.rs#L100)
    ```rust
    let l4_off = embedded_ip_start + 40;
    ```
    (along with line 93 `let proto = frame[embedded_ip_start + 6];`)
*   **Impact**: Inbound ICMPv6 error session/NAT matching fails to parse the embedded packet's L4 protocol (reads the first extension header type instead of TCP/UDP/ICMPv6) and ports (reads at `+40`). NAT matching for ICMPv6 errors on ext-headered flows will fail entirely.

#### 3. Compilation Failure in Test Suite (Missing Test Callers Update)
*   **Quote**: [tests.rs:1174](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/userspace-dp/src/afxdp/frame/tests.rs#L1174)
    ```rust
    recompute_l4_checksum_ipv6(&mut frame[14..], PROTO_TCP).expect("tcp sum");
    ```
*   **Impact**: The plan signature change of `recompute_l4_checksum_ipv6(packet, rel_l4, protocol)` does not include updating the 20+ test callers in `frame/tests.rs`, causing immediate build failure.

#### 4. Q1: Contradictory Metadata Precedence Bypass
*   **Quote**: [mod.rs:550-555](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/userspace-dp/src/afxdp/frame/mod.rs#L550-L555) (and proposed `v6_rel_l4_offset` helper)
*   **Impact**: If metadata specifies `l4_offset = l3_offset + 40` (i.e. `meta_rel = 40`), but the packet's Next Header `packet[6]` is an extension header type, the metadata is contradictory. The proposed `v6_rel_l4_offset` would trust `meta_rel` and return 40, leading to extension header corruption. The helper must fallback to parsing if `packet[6] != protocol`.

#### 5. Q7: IP Checksum Math Parity Achieved
*   **Quote**: [ipv4.rs:78-91](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/userspace-dp/src/afxdp/frame/rewrite/ipv4.rs#L78-L91) vs [checksum.rs:305-307](file:///home/ps/git/bpfrx/.claude/worktrees/research-1838-trio/userspace-dp/src/afxdp/frame/checksum.rs#L305-L307)
*   **Impact**: Confirms that full byte-equality (empty P-N3 mask for IP checksum) is mathematically achievable, as adding precomputed `ip_csum_delta` plus `0xFEFF` is equivalent to the incremental ones-complement sum adjustments.
