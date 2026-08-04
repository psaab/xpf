# Codex hostile plan review — #6751 (round 44)

# PLAN-NEEDS-REVISION

1. **BLOCKER — The evidence/authority design is sound, but the normative alias rules remain contradictory.**

   The exact old-sender trace is behaviorally safe: legacy `RTFlowSessionID` decodes to zero ([sync_protocol.go:491](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:491), pinned at [sync_rtflow_session_id_5212_test.go:64](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_rtflow_session_id_5212_test.go:64)), so equal-NONZERO insertion confirmation cannot fire.

   The pre-learn new-sender case correctly should confirm: base is queued before alias ([daemon_ha_userspace_stream.go:370](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370)); the alias copies the base value, including its nonzero RT-flow ID ([daemon_ha_userspace_convert.go:338](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:338), [daemon_ha_userspace_convert.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:399)).

   But the detailed plan still says a non-capability window performs “no confirmation, no purge” ([plan.md:704](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:704), [plan.md:2423](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2423)), while insertion confirms immediately ([plan.md:2490](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2490)) and §7 authorizes that on any window ([plan.md:3071](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3071)). P1 also remains “every completed BulkEnd” locally ([plan.md:2561](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2561)) despite the later capable-only qualification ([plan.md:3081](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3081)). The poisoned-companion absolute likewise survives at [plan.md:2644](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2644), immediately before the corrected id-capable limitation.

   This is not fork relitigation; the chosen split is correct. Its older implementation clauses still need to be rewritten consistently.

2. **BLOCKER — The never-connected release contradicts its own commit predicate.**

   The new rule requires the readiness-timeout event to commit while never connected ([plan.md:785](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:785)). The surviving lifecycle rule still requires commit-time validation of connected state, calls the callback connected-only, and names connected state as the second gate ([plan.md:1791](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1791), [plan.md:1815](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1815)). Current code returns on exactly that predicate ([daemon_ha_sync.go:40](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:40)).

   No `never-connected`/zero-connection-epoch event mode is defined. Removing the connected check wholesale would threaten the warm-disconnect invariant pinned at [session_sync_readiness_test.go:33](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/session_sync_readiness_test.go:33). A mode-aware predicate and explicit transition invalidation are required.

3. **BLOCKER — The cold terminal is not armed across the expanded gate domain.**

   The proposed gate covers `NoRethVRRP || PrivateRGElection` with either endpoint pair ([plan.md:860](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:860)). Current startup arms only `PrivateRGElection && fabric-pair` ([daemon_run_bringup.go:229](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_run_bringup.go:229)); the other arm requires a successful connection ([daemon_ha_sync.go:81](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:81)), while failed dials only retry ([sync_conn.go:462](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:462)).

   Therefore control-link-only private RG and `NoRethVRRP && !PrivateRGElection` never-connected starts can still remain gated indefinitely. One shared `sessionSyncConfigured` predicate must govern both gate engagement and cold-start timer arming.

4. **MINOR — The cold-start bound and regression matrix are not pinned.**

   The apparent intended bound is the existing five-second `syncReadyTimeout` ([daemon.go:1148](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon.go:1148)), but the plan leaves it to implementation ([plan.md:798](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:798)). §9 also lacks the simultaneous-never-connected, control-only, whole-direct-domain, and peer-dead election-state cases ([plan.md:3206](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3206)).

5. **NIT — The claimed seven-event §9 recap still enumerates six.**

   The canonical inventory includes `abort` ([plan.md:1751](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1751)); §9’s recap omits it ([plan.md:3264](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3264)). The stale fence-expiry assertion itself is substantively present at [plan.md:2397](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2397).

Verified closed:

- The gate-domain, control-or-fabric endpoint predicate, and peer-dead bypass match production ([daemon_ha_vip.go:103](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_vip.go:103), [daemon_ha_sync.go:774](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:774), [election.go:427](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/election.go:427)).
- If heartbeat remains fresh while only sync TCP is partitioned, normal priority/tie-break decides. If heartbeat also fails, its detector marks the peer dead and enters the readiness-bypassing single-node path.
- BLOCKER 4 is closed: v15.32 forbids the current untagged `AfterFunc` re-arm race ([manager.go:354](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/vrrp/manager.go:354), [plan.md:829](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:829)).
- No new kill shot exists against PATH A or the option-(a) registry/occupancy/holder core.
