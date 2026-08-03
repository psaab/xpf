# Codex hostile plan review — #6751 (round 13)

# PLAN-NEEDS-REVISION

Reviewed target commit `9990fa62f`. Two BLOCKERs remain.

1. **BLOCKER — the key-only delete LRU cannot distinguish alias deletes from genuine deletes.**

   v13 suppresses every delete whose five-tuple is in the 4096-entry set ([plan.md:569](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:569)). But delete messages carry only the key and a per-key generation ([sync_protocol.go:326](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:326)); both canonical and alias closes enqueue `QueueDelete` for that same key ([daemon_ha_userspace_stream.go:393](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:393)).

   Counterexample:

   1. Alias A at K is dropped; K enters the LRU.
   2. A signature-clean direct/DNAT canonical row D is installed at K.
   3. D closes before A.
   4. D’s own delete is suppressed, leaving stale forwarding state.

   Today, with A then D ordering, D overwrites A and D’s delete applies because shared publication is last-write-wins ([shared_ops.rs:897](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:897)). Therefore “strictly safer than today” is false.

   Clearing K when D arrives merely restores the round-12 failure: A’s later delete can delete D. Eviction after 4096 other aliases has the same result. Generation cannot help because it is keyed only by K and a delete draws a fresh value ([sync_conn_gen.go:156](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:156)); the receiver only rejects strictly older generations ([sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:263)).

   Exact delete provenance—or negotiated sender-side alias omission—is required. An upsert-only marker plus bounded key state is insufficient.

2. **BLOCKER — NAT64 can match the proposed source-only signature.**

   v13 categorically excludes NAT64 because “v6 src ≠ v4 rewrite” ([plan.md:550](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:550)). In reality, an IPv4 NAT64 rewrite in a V6 event is written into the first four bytes of a zero-padded 16-byte slot ([wire.rs:182](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/codec/wire.rs:182), [session_sync.rs:128](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/codec/session_sync.rs:128)). Go formats that slot as IPv6 ([eventstream.go:1350](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/eventstream.go:1350)) and copies it into `SessionValueV6.NATSrcIP` ([daemon_ha_userspace_convert.go:462](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:462)).

   Example: pool IPv4 `35.0.0.1` becomes decoded IPv6 `2300:1::`. A legitimate NAT64 client sourced at `2300:1::`, using another Pref64, passes the source gate ([nat64.rs:1035](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat64.rs:1035)) and its canonical row satisfies `key.src_ip == NATSrcIP`. It is then incorrectly dropped.

   `Nat64SnatV4` is already available after cluster decode ([sync_protocol.go:616](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:616)), so NAT64 can be explicitly excluded. v13’s four-term predicate does not do so.

3. **MAJOR — the collateral is broader than documented and includes bijective sessions.**

   The predicate compares only source addresses, although source/destination ports and NAT fields are decoded ([sync_protocol.go:552](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:552)).

   Consequently, same-address pool/interface PAT and same-IP static mapped-port sessions match even though their translated tuple differs by port and is unambiguous; static SNAT explicitly rewrites both address and mapped port ([static_nat.rs:746](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/static_nat.rs:746)). Full rewritten-tuple equality would exclude these false positives.

   Identity NPTv6 remains problematic even with full-tuple equality: matching returns true and emits `rewrite_src` even when identical prefixes leave the source unchanged ([nptv6.rs:413](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nptv6.rs:413), [poll_descriptor/mod.rs:2220](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2220)). Because canonical and wire keys are identical, no alias is emitted ([daemon_ha_userspace_convert.go:511](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:511)); the sole canonical row is nevertheless dropped.

   The uniform-collateral posture is therefore not acceptable as currently priced.

4. **NIT — marker-era prose remains.**

   The numeric inventory is now correct: four helper-wire counters plus one Go-side counter ([plan.md:733](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:733)), and §9 says five. However, §5.8 still describes “unflagged,” “new flagged,” and `flagged-exact` causes despite v13 having no marker ([plan.md:754](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:754)).

Verified folds:

- Full keys and NAT fields survive decode; only the Flags high byte is truncated.
- The proposed V4/V6 hook is correctly positioned immediately after decode and before authoritative `bulkRecvV4/V6` insertion ([sync_conn_read.go:110](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:110)).
- Store, BPF mirror, helper publication, and companion synthesis are downstream.
- The sticky bootstrap gate is gone.

The exact carrier, if chosen, must cover delete provenance too. A length-gated upsert/delete marker or negotiated alias omission can resolve both blockers; refining only the heuristic cannot resolve the key-collision delete ambiguity.

Scope note: the branch advanced during review to `55dfba995` (“v13.1 textual nits”). That commit fixes one counter-wording nit but does not address either blocker.

Codex session ID: 019fc8c2-c4d8-7933-ba77-c4bd47f1cb10
Resume in Codex: codex resume 019fc8c2-c4d8-7933-ba77-c4bd47f1cb10
