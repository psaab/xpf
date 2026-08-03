# AGY hostile plan review — #6751 plan v11 (round 11)

**PLAN-READY-WITH-NITS**

### Summary of Round-11 Attack Analysis

1. **Redundancy Claim Verification**: Confirmed. No consumer of the explicit canonical alias row in `shared_sessions` exists that the derived `shared_forward_wire_sessions` index row (inserted by the base's publish at [`shared_ops.rs:943-957`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L943-L957)) does NOT serve. 
   - `lookup_session_across_scopes` ([`shared_ops.rs:594-636`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L594-L636)): If a local session is a `is_fabric_wire_placeholder` ([`shared_ops.rs:583-592`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L583-L592)), it checks `shared_forward_wire_sessions`. If no local session hits, it checks `shared_sessions` (miss) and falls back to `lookup_shared_forward_wire_match` in `shared_forward_wire_sessions` ([`shared_ops.rs:633`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L633)), returning the base session's lookup and redirect disposition.
   - `lookup_forward_nat_across_scopes` ([`shared_ops.rs:638-665`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L638-L665)): Resolves reverse NAT lookups via `shared_nat_sessions` (`S -> E`), which the base's publish populates ([`shared_ops.rs:920-921`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L920-L921)).
   - BPF Republish / RG Promote (`republish_bpf_session_entries_for_owner_rgs` at [`shared_ops.rs:432-437`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L432-L437)): Indexed via `shared_owner_rg_indexes.forward_wire_sessions` ([`shared_ops.rs:950`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L950)).
   - Activation Prewarm ([`shared_ops.rs:340-420`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L340-L420)): Publishes base forward, reverse companion, and derived wire index. Dropping flagged aliases at import leaves base entries to populate all required structures.

2. **Broken-Companion Side-Fix Verification**: Verified as a live shipped hazard.
   - For an explicit alias entry (`key = E -> S`), `synthesized_synced_reverse_entry` ([`shared_ops.rs:750`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L750)) calls `build_reverse_session_from_forward_match` ([`shared_ops.rs:668`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L668)) with `forward_match.key.src_ip = E`.
   - `nat.reverse(src_ip=E, dst_ip=S, ...)` ([`shared_ops.rs:740-745`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L740-L745)) derives `rewrite_dst = E` (the firewall's WAN IP) instead of `rewrite_dst = H` (the client's IP).
   - Upon alias publication ([`shared_ops.rs:920-922`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L920-L922)), `shared_nat_sessions[S -> E]` was overwritten by the alias's broken reverse companion.
   - Return traffic (`S -> E`) looking up `shared_nat_sessions` was un-NATed to `E` (the firewall itself) rather than client `H`. This displacement occurred every sweep in shipped code, requiring the explicit exclusion in `record_shared_nat_displacement` ([`shared_ops.rs:92-120`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L92-L120)). Dropping flagged aliases at import permanently closes this hazard.

3. **Mixed-Version Matrix Verification**: Confirmed safe across all four cells (#1961-safe wire compatibility).
   - *Old Sender + Old Receiver*: Status quo.
   - *Old Sender + New Receiver*: Unflagged aliases (`is_forward_wire_alias = false`) follow the explicit legacy fallback rule and import as canonical (status quo).
   - *New Sender + Old Receiver*: Wire protocol flag is ignored by old receivers (#1961-safe protobuf/wire addition); alias imports as canonical (status quo).
   - *New Sender + New Receiver*: Flag recognized; alias dropped at import; base derived index handles wire lookups without alias hazards.

4. **Remaining Ownership Model Verification**: Sound.
   - With aliases dropped at import, `HolderSet` multiplicity collapses cleanly to base sessions.
   - Staged replacement sweeps derived index rows using `pub_token` compare-and-remove ([`shared_ops.rs:897`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/shared_ops.rs#L897)), preventing race conditions against third-party occupants.
   - Drain + uniform quarantine fail closed across all NAT modes.
   - Five production counters in §5.8 supply complete operational visibility.

---

### Numbered Findings

1. **NIT**: IPv4 and IPv6 Alias Flag Test Parity ([`userspace-dp/src/afxdp/ha/session_import.rs:133`](file:///home/ps/git/kimi-xpf/userspace-dp/src/afxdp/ha/session_import.rs#L133))
   - *Detail*: Ensure the §9 test suite explicitly exercises flag dropping and derived-index fallback symmetrically for both `userspaceForwardWireAliasFromDeltaV4` and `userspaceForwardWireAliasV6` paths.

2. **NIT**: Prometheus Metric Labeling Refinement ([`userspace-dp/src/nat/allocator.rs:1955`](file:///home/ps/git/kimi-xpf/userspace-dp/src/nat/allocator.rs#L1955))
   - *Detail*: As noted in §5.8, attaching an optional `reason` label (`flow_cap` vs `allocator_cap`) to `xpf_userspace_interface_snat_registry_cap_exhaustion_total` will help operators differentiate between hitting the 64,512 per-address flow limit versus the 256 retained allocator instance cap.
