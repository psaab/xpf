# Codex hostile plan review — #6751 (round 45)

PLAN-NEEDS-REVISION

Review pinned to committed v15.33, `277230cd8`. A later uncommitted worktree edit fixes only finding 4’s `0→1` wording.

1. **BLOCKER — The r44 evidence/authority contradiction survives.**

   Committed `plan.md:2461-2471` still says a non-capability window “never confirms,” while `plan.md:704-717` and `:2528-2547` authorize equal-nonzero insertion confirmation on every window class.

   The intended split remains code-sound: legacy frames decode with ID zero ([sync_protocol.go:491](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:491), [sync_rtflow_session_id_5212_test.go:64](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_rtflow_session_id_5212_test.go:64)); new aliases copy the base’s nonzero ID ([daemon_ha_userspace_convert.go:334](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:334), [daemon_ha_userspace_convert.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:399)), with base queued first ([daemon_ha_userspace_stream.go:370](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370)).

   The surviving clause must say the non-capability epoch pass never performs snapshot-authority confirmation/purge/clear; decode-time evidence confirmation remains allowed.

2. **BLOCKER — Deferred incremental-index entries still have contradictory legacy-window semantics.**

   Committed `plan.md:2172-2178`, `:2588-2597`, and `:3409-3413` promise definitive resolution at the next re-prime/BulkEnd. But `:3134-3143` correctly says only capability-advertising windows are definitive. Section 9 additionally says a deferred real alias never installs a broken companion at `:3453-3457`.

   For a true old sender, IDs remain zero. Therefore the plan must choose explicitly:

   - provisionally admit at the legacy BulkEnd with `alias-suspect`, accepting the documented companion residual; or
   - retain quarantine until a capable bulk or close, revising the “never left uninstalled indefinitely” guarantee.

3. **BLOCKER — The shared predicate has no live false→true arming transition.**

   Initial boot is covered at committed `plan.md:795-806`, but gate engagement follows configuration at `:890-904`. Production supports live transport changes ([daemon_apply_tail.go:238](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_apply_tail.go:238)). Heartbeat can start before session-sync construction ([daemon_ha_sync.go:767](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:767)); address resolution can fail before a sync object exists ([daemon_ha_sync.go:786](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:786)), and failed TCP dials merely retry ([sync_conn.go:435](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:435)). Consequently the connection-time arm at [daemon_ha_sync.go:51](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:51) may never occur after session sync becomes configured.

   Require generation-bound arming on every `sessionSyncConfigured: false→true` transition/new comms epoch, cancellation on true→false, and a day-2 regression. Also cover the zero-transport restart guard at [daemon_apply_tail.go:243](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_apply_tail.go:243).

4. **MINOR — The committed mode partition omits `arming=0,current=1`.**

   Committed `plan.md:1821-1831` defines `(0,0)`, `arming>0 && changed`, and unchanged-connected. A cold start that connects during the bound matches none. The intended result is INVALIDATED; connect advances the epoch and rearms the timer ([daemon_ha_sync.go:51](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:51)).

   This is not presently a safety blocker because arming-generation and lifecycle-tag checks invalidate the old event. The uncommitted worktree edit already fixes the `0→1` wording. Implementation must also avoid reusing `syncPeerConnEpoch` unchanged: it advances on connect, not disconnect ([daemon_ha_sync.go:57](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:57), [daemon_ha_sync.go:109](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:109)).

5. **NIT — Two terminology cleanups remain.**

   Committed `plan.md:2707-2712` calls an old sender’s bulk “definitive” and says it encodes zero; the old sender actually omits the field and the receiver decodes zero. The FRAMING-ONLY paragraph also duplicates the reconciliation-hold sentence at `:708-720`.

Verified closed:

- The epoch-zero stale-boot collision is blocked by `abortGeneration`, lifecycle ordering, and arming-generation validation.
- No proposed bare-boolean connected check survives; the committed text defines connected state as the epoch comparison. The warm-disconnect regression remains pinned at [session_sync_readiness_test.go:33](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/session_sync_readiness_test.go:33).
- P1 is capability-qualified, and poisoned-companion prevention is scoped to ID-capable windows.
- The bound is the existing five-second `syncReadyTimeout` ([daemon.go:1148](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon.go:1148)); all four requested regressions and all seven lifecycle events are named.
- No new kill shot exists against PATH A or the option-(a) registry/occupancy/holder core. The full reverse-identity key exists at [allocator.rs:165](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:165), and the unreserved interface branch remains exactly the planned seam at [source.rs:1226](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1226).
