# Codex — hostile plan review r1 — #5858 (verdict: PLAN-NEEDS-MAJOR)

VERDICT: PLAN-NEEDS-MAJOR

The ungated detector is sound, but the proposed family-wide reuse of the existing purge is not production-safe. It can disrupt permitted SNAT sessions, has a one-iteration flow-cache bypass race, and cannot reliably propagate large purges to the HA peer.

1. non-blocking — The detector catches attach, detach, and static edits

Dropping the `has_dscp_match_terms` / `has_per_packet_l4_match_terms` filters is correct. The two-sided `is_none_or` walk detects:

- detach from the old-map walk;
- attach from the new-map walk;
- any comparator-visible edit when both keys exist.

That follows directly from [cache_sensitive.rs:439](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/engine/cache_sensitive.rs:439). The fast maps contain only successfully resolved interface attachments, populated at [compiler.rs:153](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/compiler.rs:153).

Term reorder is caught positionally by `zip` at [cache_sensitive.rs:431](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/engine/cache_sensitive.rs:431), with term names also compared at line 376.

2. BLOCKING — Rotation is not actually gap-free

The local ordering is partly correct: the worker installs the new `ForwardingState` and purges before its RX sweep at [loop_body/mod.rs:454](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:454) and [loop_body/mod.rs:777](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:777).

But:

- Workers observe the Arc independently at line 372. There is no global rotation barrier. Different workers can forward different generations until each reaches its next loop.
- RSS pinning is operationally typical, not an invariant encoded by this design. A flow landing on a lagging worker during queue/RSS/binding movement can still use that worker’s old state.
- Previously admitted queued TX is drained after rotation at [lifecycle.rs:69](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/lifecycle.rs:69), while Close-delta-driven queued-flow cancellation happens only after the packet sweep at [loop_body/mod.rs:961](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:961).

The plan must define the cutover contract accurately: per-worker classification cutover within a loop tick, not global atomic publication. If post-publication queued transmission is forbidden, additional queue cancellation/order work is required.

3. BLOCKING — Flow cache can survive the session purge for one iteration

Flow-cache generations normally work: each full userspace compile increments the generation at [manager_generation.go:33](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/dataplane/userspace/manager_generation.go:33), entries capture it at [flow_cache.rs:535](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/flow_cache.rs:535), and lookup evicts mismatches at [flow_cache.rs:873](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/flow_cache.rs:873).

However, validation and forwarding are separate ArcSwaps, stored consecutively at [snapshot_refresh.rs:354](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:354). The worker reads validation before forwarding at [loop_body/mod.rs:364](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:364).

A legal race is:

1. Worker reads old validation.
2. Coordinator publishes new validation and new forwarding.
3. Worker reads new forwarding and purges sessions.
4. Packet processing still uses old validation.
5. An old-generation flow-cache entry hits before session lookup at [poll_descriptor/mod.rs:870](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/poll_descriptor/mod.rs:870).

The purge does not clear flow caches. Thus an old cached allow can bypass the newly installed input filter until the next worker iteration updates validation. The plan needs coherent forwarding/generation publication or explicit flow-cache invalidation during rotation.

4. BLOCKING — The HA delete claim is wrong at scale

`replicate_session_delete` is only a sibling-worker command broadcast at [session_glue/mod.rs:751](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/session_glue/mod.rs:751). Cross-node propagation occurs later through the forward Close delta, Go event handling, and `QueueDeleteV4/V6` at [daemon_ha_userspace_stream.go:378](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/daemon/daemon_ha_userspace_stream.go:378).

A worker can hold 131,072 entries, but its delta ring holds only 4,096 at [session/mod.rs:60](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/session/mod.rs:60) and [session/mod.rs:312](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/session/mod.rs:312). The purge emits all Close deltas before draining; excess deltas are dropped at [session/mod.rs:1656](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/session/mod.rs:1656).

The recovery path re-exports surviving sessions as incremental opens at [loop_body/mod.rs:927](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/worker/loop_body/mod.rs:927). It does not delimit an authoritative BulkStart/BulkEnd snapshot. Only `SessionSync.BulkSync` supplies absence-based stale deletion, as documented at [sync_bulk.go:14](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/cluster/sync_bulk.go:14).

Therefore a large family purge can lose peer deletes and leave revoked sessions on the standby. The plan also does not surface local BPF deletion failures; return codes are discarded at [bpf_map/mod.rs:569](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/bpf_map/mod.rs:569).

5. BLOCKING — There is a real failover window

Config sync only writes the config message at [sync_conn.go:1089](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/cluster/sync_conn.go:1089). The standby enqueues it non-blockingly at [sync_conn.go:1626](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/cluster/sync_conn.go:1626) and applies it asynchronously in `configApplyLoop` at [sync_conn.go:1157](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/cluster/sync_conn.go:1157).

There is no acknowledgement connecting:

- local worker purge completion;
- peer receipt of all Close deltas;
- successful standby config apply;
- automatic failover eligibility.

So failover after the primary commit but before either peer mechanism completes can forward the revoked session. The config high-water mark orders configs; it is not a purge/failover fence. Manual demotion has a session-stream barrier at [daemon_ha_userspace_readiness.go:181](/home/ps/git/bpfrx/.claude/worktrees/5858-research/pkg/daemon/daemon_ha_userspace_readiness.go:181), but that only orders messages already queued onto that stream.

6. BLOCKING — Family-wide purge is connection-destructive for ordinary SNAT

The purge releases source-NAT before deleting every selected session at [session_glue/mod.rs:354](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/session_glue/mod.rs:354).

The cited `nat/source.rs:16-43` does not prove general port stability; it discusses address-only/port-preserving translation. Ordinary non-persistent PAT claims a fresh cursor port before consulting the recycle FIFO at [allocator.rs:534](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/nat/allocator.rs:534), while release appends the old port to the recycle queue at [allocator.rs:590](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/nat/allocator.rs:590). Pool-address selection may also round-robin at [allocator.rs:851](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/nat/allocator.rs:851).

A permitted midstream TCP flow can therefore reinstall with a different translated address/port and break. This invalidates the plan’s “availability-safe” premise. Per-interface granularity alone does not fix permitted flows on the changed interface; the design needs precise affected-session re-evaluation or a NAT-preserving revalidation mechanism.

7. BLOCKING — Telemetry-only over-purge is not acceptable under these costs

The reused comparator explicitly includes filter counter/log summary flags at [cache_sensitive.rs:420](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/engine/cache_sensitive.rs:420), and term `count`, `has_count`, and `log` at [cache_sensitive.rs:408](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/filter/engine/cache_sensitive.rs:408). Names are compared too.

Given the SNAT disruption, synchronous full-table walk, sibling-worker broadcast amplification, and bounded HA delta ring, telemetry-only family purge is not a harmless efficiency tradeoff. Preserve the exhaustive-destructure invariant with a comparison mode or exhaustive semantic classification; the plan’s “single comparator or unsafe second comparator” fork is a false dichotomy.

Non-blocking scope conclusions:

- Output-filter exclusion is reasonable because output enforcement is part of TX selection, e.g. [cos_classify.rs:157](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/tx/cos_classify.rs:157).
- lo0 exclusion is reasonable because the current lo0 filter is evaluated on the host-bound path at [poll_descriptor/filter.rs:509](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/poll_descriptor/filter.rs:509).
- The DSCP/per-packet-L4 interface sets must remain: both the session-hit gate at [poll_descriptor/filter.rs:356](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/poll_descriptor/filter.rs:356) and flow-cache admission at [flow_cache.rs:411](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/afxdp/flow_cache.rs:411) consume them.
- The granularity diagnosis is correct: `SessionKey` is only the 5-tuple at [session/key.rs:10](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/session/key.rs:10), and `SessionMetadata` has zone but no logical ifindex at [session/entry.rs:24](/home/ps/git/bpfrx/.claude/worktrees/5858-research/userspace-dp/src/session/entry.rs:24).

The core ungated change detector is reusable, but the purge, cache-coherency, HA, and availability architecture must be revised before implementation.
EXIT=0
