# Codex hostile plan review — #6751 plan v8 (round 8)

# PLAN-NEEDS-REVISION

1. **BLOCKER — The zero/legacy `session_id` fallback is not a safe or complete ownership equivalence.**

   The non-zero-ID path fixes the round-7 A/B counterexample: current helpers encode the stable RT_FLOW ID ([session_sync.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/codec/session_sync.rs:186)), Go carries it into the helper request ([manager_ha.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1645)), and Rust stores it in `SyncedSessionEntry` ([session_sync.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/helpers/session_sync.rs:274)). Thus B’s different non-zero ID fails clause 4 and drops.

   However, v8 falls back to “base canonical row present with identical value” when either ID is zero ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:524)). That fallback has no safe interpretation:

   - Base and alias are independently passed through `QueueSessionV4` ([daemon_ha_userspace_stream.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370)), and each call stamps a fresh generation ([sync_conn_write.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:53), [sync_conn_gen.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:113)). Therefore their received values are not fully identical if generation is included.
   - If “identical value” excludes generation and key, legacy colliding B can match A on all compared fields, reproducing the false attachment from round 7.
   - Requiring the base row to remain present also breaks base-first deletion: after the base canonical row is removed, the remaining zero-ID alias has no specified persistent row→base-record membership with which to release its final counted holder.
   - The cited #6198 test only proves equality of Go’s node-local `SessionValue.SessionID` ([userspace_sync_session_id_6198_test.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/userspace_sync_session_id_6198_test.go:350)); that field is not the Rust ownership `session_id`. The latter comes from `RTFlowSessionID`.

   Zero-ID alias attachment must fail closed or use a genuine persistent alias-group identity. Value equality is insufficient.

2. **MAJOR — “key + NatDecision” is not a sufficient compare-and-remove identity.**

   V8 specifies only key plus `NatDecision` when validating swept occupants ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:564)). A same-five-tuple replacement can legitimately have the same key and NAT decision but a different stable session identity. Shared publication also locks and updates the canonical, reverse, and forward-wire maps separately ([shared_ops.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:897)), allowing another publisher to replace a derived slot between canonical replacement and sweep.

   The sweep can consequently mistake a newer same-key/same-NAT session for the displaced session and delete its derived row. Compare-and-remove should include `session_id` when non-zero and define an equally safe legacy rule.

3. **MINOR — §9 still does not enumerate the fixed-path quarantine tests claimed by v8.**

   The normative design now names sticky, port-translating persistent, address-only persistent, deterministic CGNAT, and deterministic NAT64 paths ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:661)). The port-translating lease really does bypass the address loop ([allocator.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1114)).

   But §9 only specifies a generic re-enabled-pool quarantine test ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:874)); it does not explicitly enumerate those five cases. Add them as separate test cases.

The counting `HolderSet` resolves base-plus-alias multiplicity for the non-zero-ID path; I found no remaining early-free ordering when acquisitions and releases follow actual row transitions. NAT64 scoping is acceptable and does not worsen its existing reconstruction behavior. The explicit-release wording is fixed, and both-direction adopt/merge plus the predicate documentation are present.

Codex session ID: 019fc83b-6d00-7790-9542-2eb2ab337ffc
Resume in Codex: codex resume 019fc83b-6d00-7790-9542-2eb2ab337ffc
