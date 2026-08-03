# AGY hostile plan review — #6751 (round 13)

# Verdict

**PLAN-READY-WITH-NITS**

---

### Adversarial Evaluation of Round 13 (v13) Attack Vectors

1. **Signature Computability — VERIFIED**
   - **Analysis**: At the cluster receive boundary ([`pkg/cluster/sync_conn_read.go:109-110`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go#L109-L110) for V4, [`sync_conn_read.go:136-137`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go#L136-L137) for V6), `decodeSessionV4Payload` / `decodeSessionV6Payload` ([`pkg/cluster/sync_protocol.go:380-440`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go#L380-L440), [`sync_protocol.go:510-570`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go#L510-L570)) populates all fields required by the self-wire signature:
     - `key.SrcIP` / `key.SrcPort` (bytes 0–11)
     - `val.IsReverse` (`payload[off]`, byte 19 for V4 / byte 43 for V6)
     - `val.Flags` (`uint16(payload[off])`, byte 17 for V4 / byte 41 for V6, carrying low-byte `SESS_FLAG_SNAT` = `0x01`)
     - `val.NATSrcIP` (bytes 61–64 for V4 / bytes 85–100 for V6)
     - `val.NATSrcPort` (bytes 69–70 for V4 / bytes 117–118 for V6)
   - **Conclusion**: The decoded `key` and `val` structs carry the complete key and NAT payload immediately after decode, before `bulkRecvV4/V6` tracking or store/helper installation. The self-wire predicate (`IsReverse == 0` ∧ sync-derived ∧ `SESS_FLAG_SNAT` set ∧ `key.SrcIP == val.NATSrcIP`) is fully computable at the `pkg/cluster` decode boundary.

2. **Signature Precision — VERIFIED**
   - **Analysis**: We tested all other NAT classes against the signature predicate (`forward` ∧ `sync-derived` ∧ `rewrite_src` ∧ `key.SrcIP == val.NATSrcIP`):
     - **Direct / No-NAT**: `SESS_FLAG_SNAT` is `0`, `val.NATSrcIP` is zero/unmodified. Clean.
     - **DNAT**: Rewrites `DstIP`/`DstPort`. `SESS_FLAG_SNAT` is `0`. Clean.
     - **NAT64**: `key.SrcIP` is IPv6 (16 bytes), `val.NATSrcIP` is IPv4 (4 bytes / mapped). `key.SrcIP != val.NATSrcIP`. Clean.
     - **Static 1:1 NAT**: `key.SrcIP` (internal host IP) `!= val.NATSrcIP` (external mapped IP). Clean.
     - **Pool SNAT / Interface SNAT**: `key.SrcIP` (internal IP) `!= val.NATSrcIP` (pool/egress IP). Clean.
     - **Fabric Alias**: Synthesized by `userspaceForwardWireAliasV4` ([`pkg/daemon/daemon_ha_userspace_convert.go:399`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go#L399)) with `wireKey.SrcIP = val.NATSrcIP`. Matches signature.
     - **Genuine Self-NAT**: Internal host IP equals the WAN egress IP (`key.SrcIP == val.NATSrcIP`). Matches signature.
   - **Conclusion**: No other NAT class false-positives under the self-wire signature.

3. **Delete Suppression Safety — VERIFIED ACCURATE**
   - **Analysis**: Walk of the uncovered corner (alias delete delayed past the 4096-entry LRU window):
     - On the new path, all signature-matching upserts (both fabric aliases and genuine self-NAT) are dropped at decode in `pkg/cluster`. Thus, no signature-matching row can ever exist in `s.sessions` or the helper store.
     - The only entry that could exist at key `(WAN_IP:src_port -> S:dst_port)` is a signature-clean direct no-NAT session initiated by a local process bound to `WAN_IP`.
     - If a peer's alias delete arrives after eviction from the 4096 LRU, it could delete that direct no-NAT session.
     - **Comparison to status quo**: Pre-v13 (`shared_ops.rs:907`), the alias **UPSERT** unconditionally clobbered that direct no-NAT occupant at publish time ($t=0$, 100% probability). In v13, the upsert is dropped at $t=0$ (0% clobber), and the delete only affects an occupant if it is delayed past 4096 churn events AND an occupant was created at that exact key in the window.
   - **Conclusion**: The plan's claim that v13 is "strictly safer than today ([`shared_ops.rs:907`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs#L907))" is mathematically and operationally accurate.

4. **Uniform Collateral Trade-off — EVALUATED ACCEPTABLE**
   - **Analysis**: Dropping genuine self-NAT synced rows (`key.SrcIP == val.NATSrcIP`) on cluster import across all windows is an intentional trade-off to keep the cluster wire format 100% unchanged (avoiding additive wire fields or protocol version bumps). Genuine self-NAT forward paths are already ambiguous at the reverse index pre-change. Documenting the behavior and counting drops via `xpf_userspace_session_sync_forward_wire_alias_ignored_total` ([`plan.md:761-768`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L761-L768)) is an acceptable engineering decision.

---

### Numbered Findings

1. **NIT**: Stale Vestigial Reference to Retired Alias Flag in Section 6 ([`plan.md:792`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L792))
   - *Detail*: Line 792 reads: `Additive-only wire change (beyond the alias flag named above): the five §5.8 status counters...`. In v13, the carried alias flag was retired in favor of the receiver-derived signature. The parenthetical phrase `(beyond the alias flag named above)` is a leftover artifact from v12 and should be removed.

2. **NIT**: Counter Plumbing Description Clarification ([`plan.md:785-787`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L785-L787))
   - *Detail*: Line 785 states `the four helper-side §5.8 status counters`, while line 792 lists `the five §5.8 status counters`. Section 5.8 ([`plan.md:750-768`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L750-L768)) correctly explains that 4 counters are helper-side and the 5th (`xpf_userspace_session_sync_forward_wire_alias_ignored_total`) is Go-side Prometheus. Simplifying lines 785–793 to consistently distinguish the 4 helper-side counters from the 1 Go-side counter will improve clarity.
