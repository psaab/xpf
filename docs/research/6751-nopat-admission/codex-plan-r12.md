# Codex hostile plan review — #6751 plan v12 (round 12)

# PLAN-NEEDS-REVISION

Two BLOCKERs remain open.

## Findings

1. **BLOCKER — the proposed high-bit carrier is truncated by the cluster wire.**

   The plan claims `SessFlagForwardWireAlias` can occupy a new high bit in `SessionValue.Flags uint16` and ride the existing cluster payload without a wire-format change ([plan.md:550](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:550>)).

   That is contradicted explicitly by both codecs:

   - V4 serializes only `byte(val.Flags)` and documents that bits ≥8 are lost ([sync_protocol.go:116](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:116>), [sync_protocol.go:122](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:122>)).
   - V6 does the same ([sync_protocol.go:231](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:231>), [sync_protocol.go:237](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:237>)).
   - The decoders reconstruct `Flags` from only that byte ([sync_protocol.go:396](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:396>), [sync_protocol.go:525](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:525>)).
   - A low-byte substitute is unavailable: bits 0–7 are already assigned `SNAT`, `DNAT`, `LOG`, `COUNT`, `ALG`, `PREDICTED`, `STATIC_NAT`, and `NAT64` ([xpf_common.h:191](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/bpf/headers/xpf_common.h:191>)).
   - The Go→helper `SessionSyncRequest` has no raw flags field at all ([protocol_ha.go:33](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_ha.go:33>)); request construction merely interprets the existing SNAT/DNAT bits ([manager_ha.go:1648](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1648>)).

   The BPF ABI itself is fine: Go and Rust store raw `u16` values without enum validation, and the 136/184-byte assertions remain valid ([bpf_session_value.go:75](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/bpf_session_value.go:75>), [bpf_map/mod.rs:144](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/mod.rs:144>)). The failure is loss before those consumers, not strict unknown-bit rejection.

   Therefore new→new never observes the exact flag, the sticky capability never trips, and v12 falls back permanently to the heuristic. The plan needs an additive length-gated cluster payload field or equivalent receiver-visible carrier; it cannot claim “no wire-format change.”

2. **BLOCKER — the unmarked alias delete can still delete a genuine canonical occupant.**

   V12 says an alias delete no-ops because the alias upsert was dropped, while acknowledging a genuine self-NAT occupant at that key ([plan.md:614](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:614>)).

   The no-op is correct only when the key is genuinely absent:

   - `DeleteWithCompanionsV4/V6` first looks up the presented key; absence falls through to a key delete ([session_store.go:537](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/session_store.go:537>)).
   - `Manager.DeleteSession` returns when the BPF-key deletion reports absent, before issuing the helper delete ([manager_ha.go:1338](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1338>)). Thus the base’s helper-only derived index is safe in the empty-key case.

   But if a genuine self-NAT session occupies the alias wire key, the lookup succeeds and the cluster delete removes that occupant and its derived companions through `DeleteKnown` ([session_store.go:391](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/session_store.go:391>)); the userspace adapter then sends the same key to the helper ([manager_ha.go:1392](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1392>)), where deletion is unconditional ([sync_session.rs:29](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/handlers/sync_session.rs:29>)).

   “Today the alias upsert already clobbers it” establishes baseline severity, but it does not make the v12 delete a no-op or support the new→new claim that genuine self-NAT is preserved. Alias provenance must cover deletes, or the receiver must retain sufficient dropped-alias/generation state to suppress the matching delete.

3. **MAJOR — the sticky capability gate has an unavoidable bootstrap false-positive window.**

   The plan promises that once any flagged row arrives, genuine self-NAT rows from a flag-capable peer are never dropped ([plan.md:565](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:565>), [plan.md:625](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:625>)).

   A new peer’s genuine self-NAT canonical row can arrive before its first fabric alias—or it may never emit an alias. Until a flagged alias has been observed, that row matches the legacy signature and is dropped. With finding 1, the flag is never observed at all.

   Per-peer sticky state is mechanically implementable on `SessionSync`, which already owns both peer fabric connections and atomic lifecycle state ([sync.go:295](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:295>)); observation-based capability discovery simply cannot guarantee the stated new→new behavior. This needs negotiated capability or broader documented collateral.

4. **MINOR — the drop hook must be named in `pkg/cluster`, before bulk bookkeeping, not merely in `manager_ha.go`.**

   The first bulk consumer records the decoded key before invoking installation ([sync_conn_read.go:109](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:109>)). `manager_ha.go` is downstream: `installClusterSyncedV4/V6` calls the store, which writes the BPF mirror and helper transactionally ([sync_conn_gen.go:435](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:435>), [manager_ha.go:1112](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1112>)).

   The required ordering is implementable, but the predicate must run immediately after decode and before `bulkRecvV4/V6` insertion. A drop inside `SetClusterSyncedSession*` would be too late for authoritative bulk reconciliation.

5. **NIT — most r11 text folds landed, but counter inventory remains stale.**

   - `HolderSet` now correctly describes legacy-window duplicates ([plan.md:371](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:371>)).
   - The precise non-zero RT-flow ID → non-zero `pub_token` → token-zero full-entry-ex-counters chain is restored and coherent ([plan.md:484](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:484>)).
   - §6 no longer inventories a helper alias predicate/new wire field ([plan.md:797](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:797>)).
   - The test plan still says “four §5.8 counters” ([plan.md:1013](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1013>)).
   - §5.8 says all five ride the helper status wire, although the fifth is explicitly Go-side ([plan.md:751](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:751>), [plan.md:776](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:776>)).

## Independent AGY verification

AGY’s two substantive claims remain confirmed:

- The explicit alias has no unique forwarding consumer. Exact shared lookup falls through to the base-populated forward-wire index ([shared_ops.rs:630](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:630>)); base publication creates that index ([shared_ops.rs:943](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:943>)); materialization carries the base canonical key ([shared_ops.rs:549](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:549>)); BPF publication already emits canonical, forward-wire, reverse-wire, and reverse-canonical keys ([bpf_map/mod.rs:76](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/mod.rs:76>)).

- The poisoned companion is live. Every forward import synthesizes a reverse entry with no alias test ([shared_ops.rs:750](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:750>)); reverse NAT rewrites the destination to the supplied original source ([nat/mod.rs:106](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/mod.rs:106>)); base and alias share the reverse key construction ([key.rs:94](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/key.rs:94>)); canonical then alias export ordering is explicit ([daemon_ha_userspace_stream.go:370](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370>)); shared publication is last-write-wins ([shared_ops.rs:907](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:907>)).

The alias-removal direction remains correct, but v12’s carrier and delete lifecycle are not yet implementable as claimed.

Codex session ID: 019fc8ac-0d94-7772-adc4-46db74a88c5b
Resume in Codex: codex resume 019fc8ac-0d94-7772-adc4-46db74a88c5b
