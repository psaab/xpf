# Codex hostile plan-review — #6371 r3 (VERDICT: PLAN-NEEDS-REVISION)

NEW BLOCKER: stale-active-restart reactivation (pinned rg_active=1 + fresh applied=false -> reconcile never clears -> poll/watchdog re-arm -> indefinite). Firsthand-confirmed. Drove the r4 rewrite.

---

R3 is not plan-ready. It faithfully fixes the specific r2 blocker—the decouple is harmful, and the current per-call map-first ordering is correct—but it misses a separate, reachable reactivation defect.

### BLOCKER: stale-active restart is never reconciled

A former owner can restart after its peer has taken ownership:

1. `rg_active=1` survives because the map is pinned ([loader_userspace_shim.go:602](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/loader_userspace_shim.go:602)).
2. Startup reads that value and publishes `active=true` to the fresh helper ([manager_compile.go:360](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_compile.go:360)).
3. The daemon’s fresh state machine starts `desired=false`, `applied=false`, with no pending apply ([rg_state.go:75](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/rg_state.go:75)).
4. A normal non-preempt boot starts Secondary and may emit no initial transition ([group_state.go:23](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/cluster/group_state.go:23), [election.go:113](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/cluster/election.go:113)). Initial BACKUP/Secondary reconciliation remains false→false.
5. Reconciliation calls `SetRGActive` only for `Changed || NeedsApply`, so it performs no corrective clear ([daemon_ha.go:806](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:806)). This makes the startup-repair comment at line 605 false.
6. The watchdog then republishes map-derived `active=true`; Rust grants a fresh ten-second lease on every active update ([manager_ha.go:781](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/dataplane/userspace/manager_ha.go:781), [state.rs:4](/home/ps/git/bpfrx/.claude/worktrees/6371-research/userspace-dp/src/afxdp/ha/state.rs:4)).

That is indefinite reactivation with a live socket. No clear is attempted, so the proposed alarm also sees nothing. It directly disproves the plan’s “no HA-path defect” conclusion and its claimed bounded pre-latch window.

### Answers to the hostile questions

- **Current `UpdateRGActive` ordering:** Correct locally. Map-first/return-on-map-error keeps the map, `haGroups`, and helper consistent; the r2 decouple would indeed be undone by the poll. But calling the map the daemon’s “single Active authority” obscures the split between daemon desired state and persisted manager state. Require startup persisted-vs-desired reconciliation or an ownership gate, including explicit hitless-restart semantics. A full authority redesign can be deferred; this narrower startup defect should not be.

- **Conditional ~11 seconds:** Correct only when no further `active=true` update is applied—after inactive is latched, or while the socket is continuously unreachable through expiry. The watchdog sends full group state, but Rust renews the lease only for groups marked active ([runtime.rs:343](/home/ps/git/bpfrx/.claude/worktrees/6371-research/userspace-dp/src/afxdp/types/runtime.rs:343)). Phrase the condition in terms of IPC application, not merely an error returned: a request can be applied before its response fails. Also, ~11 seconds bounds ordinary new admission, not final egress of already-admitted queued packets. [Plan lines 104–107](/home/ps/git/bpfrx/.claude/worktrees/6371-research/docs/research/6371-rgactive-fence/plan.md:104) still overstate the overall dual-forwarding bound.

- **Security-risk deferral:** The security label does not automatically require the entire single-authority redesign now. The proposed acceptance is nevertheless indefensible as written: a two-second retry cadence is not a success bound. Persistent map-write failure with a live socket, stale-map restart, and genuinely stuck ownership can all remain active indefinitely. Any deferral needs accurate unbounded-mode disclosure, accountable security/HA-owner signoff, and a tracked follow-up now—not “if later required.”

- **Alarm versus doc-only:** A persistence alarm is directionally better than doc-only, because known potentially unbounded failures deserve operational detection. The proposed alarm is not implementable as described. `fenceAllRedundancyGroups` bypasses `rgStateMachine` and records no retry debt ([daemon_ha_sync.go:1267](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha_sync.go:1267)); a failed peer-fence clear therefore produces neither consecutive reconcile failures nor a later retry. Restart also produces no attempted clear. Define shared unresolved-clear debt, exact time-based hysteresis, supersession/removal/restart semantics, and actual requested-value classification.

Additional corrections:

- There is no generic existing alarm manager; the cited implementation is NAT-specific, with NAT-specific CLI and gRPC callbacks ([daemon.go:199](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon.go:199)). The 40–70 LOC estimate is not credible.
- Shutdown is a fifth explicit false site ([daemon_run_shutdown.go:145](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_run_shutdown.go:145)). It may reasonably be excluded from runtime hysteresis, but the “complete four sites” claim needs qualification.
- Documentation scope still misses the canonical stale #5640 account in [session-sync-architecture.md:1358](/home/ps/git/bpfrx/.claude/worktrees/6371-research/docs/session-sync-architecture.md:1358), the “peer never promotes” comment in [daemon_ha.go:168](/home/ps/git/bpfrx/.claude/worktrees/6371-research/pkg/daemon/daemon_ha.go:168), and matching sync-test rationale.
- Killing Option D, Path A′, and the decouple remains sound. The `cluster-event` taxonomy and #5079 relabel are also correct.

VERDICT: PLAN-NEEDS-REVISION
