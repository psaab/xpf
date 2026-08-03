# Codex hostile plan review — #6751 plan v5 (round 5)

# PLAN-NEEDS-REVISION

1. **BLOCKER — Staged tuple replacement still cannot represent `T_old` and `T_new` simultaneously.**

   V5 explicitly retains one holder set on each flow’s `live_by_flow` record, then requires pre-reserving `T_new` while `T_old` remains held ([plan.md:327](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:327>), [plan.md:382](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:382>)). The actual allocator remains keyed only by `SourceNatFlowKey`:

   [allocator.rs:480](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:480>)

   Existing reserve therefore finds the same flow and removes/frees its old tuple before inserting the new one:

   [allocator.rs:1671](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1671>)

   Adding holders to `LiveAllocation` does not change that cardinality. The plan must specify tuple-versioned ownership—such as `(flow, translated)` records or multiple translated records per flow—and update release, rollback, caps, per-index counts, and idempotence accordingly.

   On open question 3: `upsert_synced_with_origin` may keep its `bool` install-result return. Returning the previous decision from it is too late for pre-reservation. The wrapper instead needs a new pre-read accessor because `entry_by_key` is currently private ([mod.rs:1093](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:1093>)). That accessor is straightforward; the allocator record shape is the blocker.

2. **BLOCKER — Coordinator tuple replacement frees `T_old` before all old shared aliases become unreachable, and the publish choke does not remove those aliases.**

   The specified order is `reserve T_new → −Shared(T_old) → publish T_new` ([plan.md:387](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:387>)). But v5 explicitly permits canonical rows with `{Shared}` and no worker holder after worker rejection ([plan.md:374](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:374>)). In that state, `−Shared(T_old)` frees the identity while the old canonical row is still reachable.

   Worse, current publication replaces the primary key but only inserts aliases derived from `T_new`; it never removes the old reverse-NAT or forward-wire aliases derived from `T_old`:

   [shared_ops.rs:907](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:907>), [shared_ops.rs:918](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:918>), [shared_ops.rs:943](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:943>)

   V5 needs a transactional shared replacement choke: reserve `T_new`, replace the canonical row and remove every alias derived from the displaced entry, then release `{Shared}` on `T_old`. Until then, a reachable shared alias can lack ownership indefinitely.

3. **BLOCKER — Re-enabling an edited pool while an older allocator generation drains creates two minting domains for the same address.**

   V5 correctly retains multiple draining allocators and asks about this exact hazard at [plan.md:681](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:681>), but does not close it.

   The allocator compatibility key includes the complete pool address vectors and port range ([source.rs:327](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:327>)); carry-over is exact-key based ([source.rs:549](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:549>), [source.rs:726](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:726>)).

   Counterexample:

   1. `A0`, for pool `[E,A]`, holds live identity `T` and enters the drain.
   2. While quarantined, the pool changes to `[E,B]`, producing a distinct allocator generation.
   3. The interface overlap disappears before `A0` drains, so `[E,B]` is re-enabled.
   4. New pool admission mints solely through the re-enabled rule’s allocator; the plan’s mint quarantine applies only to interface admission.
   5. The new allocator can allocate `T` while `A0` still owns it.

   The reserve/release drain-vector scan does not protect fresh pool mints. Re-enable must either reattach/merge all compatible generations or quarantine every newly active pool/NAT64 mint on an address until all older generations for that address drain.

4. **MAJOR — `Option::None` from materialization does not mean the packet drops.**

   V5 says reserve failure becomes a lookup miss and “the reply packet … drops” ([plan.md:369](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:369>)). Propagating `None` from the materialization call at [session_glue/mod.rs:1227](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:1227>) makes `resolve_flow_session_decision` return `None`. Its caller interprets that as an ordinary session miss and enters the full cold policy/NAT/admission path—not an unconditional drop:

   [poll_descriptor/mod.rs:432](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:432>), [poll_descriptor/mod.rs:903](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:903>)

   Materialization conflict needs a distinct outcome propagated to an explicit recycle/drop branch.

The other requested folds verify:

- Tri-state scanning stops at the draining allocator’s `IdentityConflict`; it does not reach the interface registry.
- Pre-store drain-marker ordering and atomic lift close the original transition/resurrection race.
- Authoritative `addr_index` is sufficient for O(1) per-index counting once tuple-versioned records are defined.
- `teardown.rs:56` snapshots canonical shared entries, `stop_inner(false)` preserves them, and `coordinator/mod.rs:810` replays them.
- `publish_shared_session` is the local and HA-import choke; the removal inventory covers nine call expressions across seven production contexts. Reverse companions can remain holder-neutral.
- Empty to-side scope is a wildcard: interface/RI checks and zone checks only reject non-empty constraints.
- The four counter names and full status/Prometheus plumbing inventory resolve round-4 MINOR 9 and NIT 10.
- Both reserve and release drain scans and the accepted `{Shared}`-without-worker asymmetry are documented.

The architecture remains endorsed, but the ownership invariant is still falsifiable on tuple-changing refresh and edited-drain re-enable.

Codex session ID: 019fc7e7-9d1d-72f1-9ccc-e64dbeeb62ed
Resume in Codex: codex resume 019fc7e7-9d1d-72f1-9ccc-e64dbeeb62ed
