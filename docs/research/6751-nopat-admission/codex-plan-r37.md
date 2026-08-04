# Codex hostile plan review — #6751 (round 37)

# PLAN-NEEDS-REVISION

Reviewed committed v15.25 at `1139d4153`. A concurrent uncommitted `plan.md` edit appeared during review and was not credited.

1. **BLOCKER — Listener closure does not fence already-accepted, pre-install TCP children.**

   v15.25 claims that closing the listener means no setup or install can complete and starts the fixed quiet interval at fence engagement (`plan.md@1139d4153:563-575`). That is true for SYNs arriving after closure, so the exact round-36 late-retry trace is closed.

   However, `Accept` returns a child before `beginSetup` tracks it ([sync_conn.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:388)). After the handshake, `finishSetup` removes that child from tracking before pending-frame dispatch and `installConn` ([sync_conn.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:100), [sync_admission.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_admission.go:86)). `Stop` explicitly closes listeners, registered slots, and setup children separately, confirming listener closure does not close accepted children ([sync_conn.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:349)).

   Counterexample: C0 is accepted immediately before fencing; the old unkeyed initiator installs locally because setup is immediate ([sync_auth.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_auth.go:329)); the receiver stalls before tracking or between `finishSetup` and `installConn`. C0 survives listener/slot teardown. After quiet expiry, another fabric connects while the old peer still has C0, so `wasDisconnected` is false and `needColdPrime` is not armed ([sync_conn.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:248)). A stale C0 can also resume after fence release and be stamped as a current admission because no generation was captured at `Accept`.

   Required fold: generation-bind `Accept`/dial completion through install, close every pre-fence child, reject stale children after fence release, and start the drain interval only after those children are killed. Pin both `Accept→beginSetup` and `finishSetup→installConn` stalls.

2. **MAJOR — The two-stage lineage gives the 5-second incremental verdict contradictory semantics.**

   Rule 7 clears `alias-suspect` on a “BulkEnd/window” genuine verdict and expressly includes the lost-base class ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:456)). Elsewhere, the 5-second current-store check is called definitive (`plan.md@1139d4153:2099-2103`), yet timeout-admitted aliases remain provisional until a later BulkEnd (`:2184-2191`, `:2207-2224`).

   The lost-base alias is indistinguishable at that timeout: it copies the base value exactly ([daemon_ha_userspace_convert.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:399)). If the window verdict clears the mark, the original trace remains: alias-only arrival → timeout → clear → normal import → `SharedPromote` ([promote.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:99)) → immediate Open export ([session/mod.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:1516)).

   Keeping it unresolved until “the next BulkEnd” does not provide the claimed bound: a stable connection may never run another authoritative bulk; its normal sweep sends individual session frames ([sync_conn_sweep.go](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_sweep.go:142)). Thus a genuine self-NAT/NPTv6 row can remain suppressed despite a connected peer.

   The timeout must remain `UNRESOLVED` and actively owe/request a complete inbound prime—or obtain another definitive proof—with an explicit bound for genuine-row release. Verdict-transition atomicity itself is sound once this is fixed: suspect→permanent suppresses on both sides, and genuine clear is safe only after a genuinely definitive verdict.

3. **MINOR — Alias stage propagation is missing from the concrete helper/export inventory.**

   Rule 7 requires stickiness through promotion, demotion, replication, and reconciliation ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:442)), but retained §5.6 says the helper has “NO alias-specific handling” (`plan.md@1139d4153:2290-2292`). Section 6 names only `pub_token` as a new helper-internal field and does not inventory the stage carrier through `SessionMetadata`, `SyncedSessionEntry`, worker replication, direct promotion Open emission, and every exporter (`:2546-2585`).

   Name those surfaces and add suspect→promote suppression, genuine-clear/export, stage-preservation, and concurrent-export tests.

4. **MINOR — The promised §9 failure-path regressions are absent.**

   Rules 2–3 correctly specify worker outcomes and purge semantics (`plan.md@1139d4153:246-313`), and §5.6 now explicitly supersedes the old “not fed back” acceptance (`:1031-1044`). But §9 does not pin worker refusal before barrier ACK, purge failure→`Failed`, or timeout/unknown→`Pending` with teardown and no reconcile/ACK.

   Those seams are real: the handler currently returns `()` ([upsert_synced.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:18)), installation can refuse ([install.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/install.rs:310)), and deletion reports no result ([delete_synced.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs:20)).

5. **NIT — Rule 6’s claimed incarnation fold exists only in the status summary.**

   Normative Rule 6 still says merely “helper INCARNATION (boot epoch)” and does not state daemon issuance or atomic binding to both lanes at the barriered handoff ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:405)). Section 9 also lacks `(E2,1)` after retained `(E1,100)`. This matters because Rust sequencing restarts at zero ([event_stream/mod.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/mod.rs:275)).

6. **NIT — Refresh origin projection is folded, but its regression is not.**

   The iterator signature now explicitly gains origin ([plan.md](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:379)); current code indeed exposes none ([lookup.rs](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/lookup.rs:501)). Section 9 still lacks the stale-replica `last_seen` non-regression test.

Mutual fencing and repeated re-fencing remain live through deterministic dial ownership and one-second retry. The three receiver-side protections are collectively sufficient against old-peer write-completion clearing once Finding 1 is fixed. No new blocker or kill shot was found in option-(a)’s registry, holder/drain core, or the settled PATH-A fork.
