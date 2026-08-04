# Codex hostile plan review — #6751 (round 43)

# PLAN-NEEDS-REVISION

Reviewed the clean `a74b81dad` blob. Four BLOCKERs remain in the surviving alias/readiness machinery. No new kill shot exists against PATH A or the option-(a) allocation core.

1. **BLOCKER — Capability-gated alias resolution remains contradictory.**

   The governing rule says non-capability windows perform disposition only—never confirmation, purge, or lineage clearing ([plan.md:700](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:700), [plan.md:2363](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2363)). Retained rules still:

   - Confirm immediately at insertion from the base-identity index without a capability condition ([plan.md:2430](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2430)); §9 repeats that unconditional confirmation ([plan.md:3425](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3425)).
   - Promise deferred entries resolution at a “definitive BulkEnd” regardless of peer capability ([plan.md:2079](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2079), [plan.md:2480](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2480)).
   - Require P1 re-evaluation against a definitive snapshot at every completed BulkEnd ([plan.md:2501](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2501)).
   - Claim legacy quarantine prevents poisoned companions, while the mixed-version contract says old-sender aliases are not confirmable and may remain installed until expiry ([plan.md:2584](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2584), [plan.md:2588](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2588)).

   Exact conflicting trace: non-capable BulkStart → base decoded first → alias decoded second → insertion rule confirms immediately, while the governing rule forbids confirmation. BLOCKER 1 was not fully folded.

2. **BLOCKER — The readiness gate uses neither production predicate.**

   The plan gates only private-RG mode with fabric endpoints ([plan.md:818](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:818), [plan.md:829](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:829)). Production differs in two dimensions:

   - Session sync prefers `ControlInterface + PeerAddress` and falls back to fabric only when the control pair is unavailable ([daemon_ha_sync.go:774](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:774)). A valid control-link-only sync deployment is incorrectly classified as “not configured.”
   - The direct/no-VRRP takeover domain is `NoRethVRRP || PrivateRGElection` ([daemon_ha_vip.go:100](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_vip.go:100), [vrrp.go:139](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/vrrp/vrrp.go:139)). `no-private-rg-election + no-reth-vrrp` is explicitly supported ([compiler_validate_strict_reth_vrrp_4826_test.go:116](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_reth_vrrp_4826_test.go:116)), but receives neither classic VRRP hold nor the proposed private-only gate.

   Peer-dead election also explicitly bypasses readiness ([election.go:427](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/election.go:427)); the plan must state whether that bypass survives and test election state, not merely `RG.Ready`.

   The literal default private-RG/no-endpoint case is correctly a no-op and is not stranded. The broader gate domain remains incomplete.

3. **BLOCKER — Configured, never-connected cold startup has no bounded terminal.**

   `syncReady` begins false ([manager.go:299](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/manager.go:299)). Startup arms the private readiness timer ([daemon_run_bringup.go:234](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_run_bringup.go:234)), but its one-shot callback returns when session sync has never connected ([daemon_ha_sync.go:40](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:40)). Failed TCP dials merely retry and create no disconnect/fence event ([sync_conn.go:462](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:462)).

   With heartbeat working, election continues enforcing readiness ([election.go:322](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/election.go:322)). Simultaneous cold boot with healthy heartbeat but failed session-sync TCP can therefore leave both nodes secondary indefinitely. The plan’s disconnected-eligible terminal is fence-owned ([plan.md:753](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:753)); never-connected startup never engages that fence.

4. **BLOCKER — Re-arming through `SetSyncHold` imports an untagged stale-timer release.**

   Fence engagement re-arms the classic hold “via the startup path” ([plan.md:789](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:789)). That path stops the old timer and installs an independent `time.AfterFunc` which directly releases the hold ([manager.go:354](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/vrrp/manager.go:354), [manager.go:372](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/vrrp/manager.go:372)).

   Exact race: old callback starts → new fence calls `SetSyncHold` and installs its hold/timer → old callback resumes, observes `syncHold == true`, releases the new hold, and stops the new timer through the shared pointer ([manager.go:389](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/vrrp/manager.go:389)). This bypasses the lifecycle tag/CAS discipline. The manager timeout must be generation-bound to the fence cycle or replaced by the sole fence-owned terminal.

5. **MINOR — §9 does not directly pin stale fence expiry after re-arm.**

   The detailed prose claims an exact pin ([plan.md:1745](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1745)), but §9 contains only generic “nested abort re-arm” wording ([plan.md:3172](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3172)). It should explicitly fire the old expiry after a higher-generation re-arm and assert no readiness, VRRP-hold, or private-gate release.

Verified folds:

- The seven-event inventory and readiness commit’s fence-state revalidation are present ([plan.md:1696](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1696), [plan.md:1740](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1740)).
- Fence engagement now normatively sets readiness false and re-arms the hold; ordinary #466 warm disconnect remains disjoint ([plan.md:797](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:797), [daemon_ha_sync.go:113](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:113)).
- Behavior-change pricing and the permissive-test update are present ([plan.md:3042](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3042), [plan.md:3127](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3127)).
- The decode-time index replaces the impossible BPF-store lineage source, and the quiet-interval formula is in the parameter summary ([plan.md:3001](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3001), [plan.md:3476](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3476)).

No new BLOCKER was found in §4.0.1/§4.0.2 or the option-(a) registry/occupancy/holder core. The open blockers are confined to retained alias text and gate/fence integration; this is not PLAN-KILL evidence.
