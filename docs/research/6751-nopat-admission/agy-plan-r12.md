# AGY hostile plan review — #6751 plan v12 (round 12)

PLAN-READY-WITH-NITS

---

### Verification Summary

1. **Codex r11 B1 (carrier)** ([`docs/research/6751-nopat-admission/plan.md:535-642`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L535-L642)):
   - **Carrier**: Marker defined as a new bit `SessFlagForwardWireAlias` in the existing `SessionValue.Flags` `uint16` (`pkg/dataplane/types.go:22`). Keeps the 136-byte ABI size (`pkg/dataplane/bpf_session_value_test.go:17-28`), riding the cluster wire, BPF mirror, and helper request without wire format breaking changes.
   - **End-to-End & Unknown-Bit Tolerance**: Pinned as an implementation gate for all flag decoders (Go mirror decode, Rust helper decode, `BpfSessionValueV4` ABI assert) using mask/truncate decoding for unknown bits (#5460 precedent).
   - **Receiver Drop Boundary**: Positioned in the Go daemon at the cluster receive boundary, preceding helper forwarding (`syncSessionRequestLocked`), eBPF map update, local daemon session store insertion, and bulk replay.
   - **Sticky Gate**: Operates on receiver state. For legacy peers (no flagged rows received yet), applies the self-wire signature heuristic (`forward && sync-derived && key.src_ip == decision.rewrite_src`). Once any flagged row arrives from a peer, switches stickily to flag-exact dropping for that peer.

2. **Codex r11 B2 (regression)** ([`docs/research/6751-nopat-admission/plan.md:614-642`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L614-L642)):
   - **Old-Sender + New-Receiver Cell**: Alias rows are dropped in the Go daemon at the cluster boundary via the self-wire signature heuristic before reaching the helper. Because no alias row reaches the helper in any matrix cell, alias rows cannot enter the helper's ownership reservation or displace the real base.
   - **Delete Scenario**: Alias deletes carry `(wire_key, generation)`. On the new path, the alias was dropped at cluster import and never published to `shared_sessions` or helper maps. The wire-key delete in `remove_shared_session` safely no-ops. Derived index entries under the base session's key remain untouched and clean up only when the base session itself is deleted.

3. **Codex r11 M3 (pub_token chain restored)** ([`docs/research/6751-nopat-admission/plan.md:480-501`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L480-L501)):
   - Restored into the staged-replacement alias sweep bullet. `SyncedSessionEntry` gains an additive helper-internal `pub_token: u64`. Ownership is validated atomically under map locks against the comparison hierarchy: equal non-zero `RTFlowSessionID`, else equal non-zero `pub_token`, else (for legacy token-0 rows) full `SyncedSessionEntry` field equality excluding counters.

4. **Codex r11 n4 (stale artifacts)** ([`docs/research/6751-nopat-admission/plan.md:371-391`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L371-L391), [`plan.md:791-835`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L791-L835)):
   - `HolderSet` doc comments explicitly clarify legacy-window alias counting.
   - Helper-side wire-alias predicate and base-record marker attachment are removed from the Section 6 inventory.
   - Production counter inventory updated to five across Sections 5.8, 6, and 7.

5. **Round-11 AGY Verification**:
   - The explicit alias row in `shared_sessions` has no unique Rust forwarding consumer; the derived `shared_forward_wire_sessions` index row (populated at base publication, `shared_ops.rs:943-957`) handles all fabric-redirect return lookups (`shared_ops.rs:585-635`).
   - Receiver-side dropping eliminates the synthesized reverse companion (`synthesized_synced_reverse_entry`, `shared_ops.rs:750`), closing the `shared_nat_sessions` displacement hazard (`shared_ops.rs:92-120`).

---

### Numbered Findings

1. **NIT**: Counter Count Typo in Section 9 Test Plan ([`docs/research/6751-nopat-admission/plan.md:1013`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L1013))
   - *Detail*: Line 1013 states "the four §5.8 counters bump exactly on their events", whereas Section 5.8 (lines 750-784) and Section 6 (lines 807, 833) list five production status counters (`pat_collisions_total`, `identity_exhaustion_total`, `registry_cap_exhaustion_total`, `sync_identity_conflict_drops_total`, and `forward_wire_alias_ignored_total`). Update line 1013 to read "the five §5.8 counters".
