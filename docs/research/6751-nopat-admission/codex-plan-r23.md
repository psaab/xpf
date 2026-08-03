# Codex hostile plan review — #6751 (round 23)

# PLAN-NEEDS-REVISION

Reviewed `9b6fb6633`. Two BLOCKER-rated parts of the effect-commit contract remain open, based on new code evidence.

1. **BLOCKER — The callback’s already-triggered work is not uniformly convergent.**

   The plan says an already-triggered `OnPeerConnected` callback only performs work that reads current state and therefore cannot commit stale effects ([plan.md:775](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:775)). That is true for config reconciliation and the deferred DHCP/IPsec passes: they re-read active configuration/state at execution.

   But the actual callback first invokes `onSessionSyncPeerConnected` ([daemon_ha_sync.go:934](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:934)), which unconditionally:

   - stores `syncPeerConnected=true`,
   - advances the connection epoch,
   - resets heartbeat-suppression state,
   - may clear both bulk-prime flags,
   - may set sync readiness false and arm the readiness timer.

   Evidence: [daemon_ha_sync.go:51](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:51), [daemon_ha_sync.go:68](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:68), [daemon_ha_sync.go:81](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:81).

   Concrete race: the intent validates and launches the callback; abort then advances the generation and the disconnect callback stores `syncPeerConnected=false` ([daemon_ha_sync.go:109](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:109)); the already-launched connect callback subsequently stores it back to true. Nothing re-derives that write from the current slot or abort generation.

   The plan must generation-order these daemon lifecycle mutations—not merely validate before spawning the goroutine—and test abort after callback launch but before its state commit.

2. **BLOCKER — #2170 does not universally order journal replay; both sender and receiver deliberately degrade to unguarded behavior.**

   The plan claims every replayed message carries a usable monotonic per-key generation and that every older replay is rejected ([plan.md:785](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:785)). Current code disproves both absolutes:

   - Generation maps are capped at 200,000 keys; a new key at capacity is deliberately not recorded ([sync_conn_gen.go:23](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:23), [sync_conn_gen.go:45](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:45)).
   - If the sender has no recorded stamp, `takeDeleteGenV4/V6` returns generation 0 ([sync_conn_gen.go:176](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:176)). That encoded delete can be journaled and replayed ([sync_conn_write.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:69)).
   - At the receiver, a generation-0 delete is unconditional and removes the stored tombstone ([sync_conn_gen.go:263](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:263)). The tests explicitly pin that behavior even against a generation-bearing live entry ([sync_gen_guard_test.go:128](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_gen_guard_test.go:128)).
   - Independently, when the receiver map is full, a new replacement’s high-water generation is not recorded ([sync_conn_gen.go:233](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:233), [sync_gen_guard_test.go:635](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_gen_guard_test.go:635)). An older nonzero replay therefore also sees no stored generation and applies.
   - Once a zero-generation delete clears the tombstone, a delayed older install can be accepted and resurrect the closed session—the exact reorder #2221’s tombstone was added to prevent ([sync_gen_guard_test.go:830](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_gen_guard_test.go:830)). Alternatively, a late zero-generation delete can simply kill a newer replacement.

   The plan needs an explicit disposition for untracked/zero-generation replay—such as abort-generation-bound queue envelopes, guaranteed replay metadata, or suppress-and-authoritatively-reconcile. The journal race test must include sender-cap, receiver-cap, and zero-generation delete/install reorder cases.

3. **MINOR — The boundedness tests are named, but not actually in §9 as claimed.**

   All requested names appear in §5.6’s prose at [plan.md:804](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:804) and [plan.md:846](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:846). The §9 test list beginning at [plan.md:1310](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1310) does not enumerate them. Move or duplicate the concrete cases into §9, including the stronger callback and generation-cap races above.

Fold checks:

- **Provisional bulk installs:** no new forwarding-invalid counterexample found. Sent sessions are live sender sessions, receive-side config-epoch fencing rejects installs invalidated by newer applied policy ([sync_conn_gen.go:398](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:398)), and only a valid `BulkEnd` reconciles and ACKs ([sync_conn_read.go:205](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:205)).
- **§11 NIT:** correctly folded. It now says self-NAT **and** non-fabric identity-NPTv6, both timeout-admitted rather than dropped ([plan.md:1505](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1505)).
- **Core #6751 design:** no new BLOCKER found in registry/mint/holder/tri-state/staged-replacement/drain/quarantine/probe/counter design. The remaining blockers are in the alias abort/effect contract.

Codex session ID: 019fc9a4-2f5e-7d83-b4dc-fb1493447a58
Resume in Codex: codex resume 019fc9a4-2f5e-7d83-b4dc-fb1493447a58
