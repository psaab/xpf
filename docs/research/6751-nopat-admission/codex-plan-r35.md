# Codex hostile plan review — #6751 (round 35)

PLAN-NEEDS-REVISION

Reviewed the immutable v15.23 blob at `fbca4ab8f`; concurrent uncommitted edits to `plan.md` were not credited. One BLOCKER remains. PATH A and option (a) remain viable, so this is not `PLAN-KILL`.

1. **BLOCKER — F10’s quiet interval controls outbound dialing, not inbound admission.**

   `plan.md@fbca4ab8f:467–481` says the fencing side waits before reconnecting, but the detailed contract clears the fence before applying backoff (`:1921–1928`). Dial ownership is address-selected ([sync_conn.go:12](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:12), [sync_conn.go:319](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:319)); the non-initiator always accepts inbound connections ([sync_conn.go:388](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:388)), while the initiator retries each empty fabric every second ([sync_conn.go:435](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:435)).

   If the capable fencing node is the non-initiator, the old peer can redial fabric 0 after its first disconnect callback but before fabric 1 clears. Its registry never becomes both-empty, so `installConn` never arms `needColdPrime` ([sync_conn.go:244](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:244), [sync_conn.go:480](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:480)).

   Required fold: retain the admission fence throughout the quiet interval, refusing authenticated inbound and suppressing outbound admission on both fabrics until the peer’s disconnect bound has elapsed.

2. **MAJOR — Rule 2/3 exact results contradict retained §5.6’s “not fed back” worker drop.**

   Rules 2–3 require per-worker barriers, exact per-key outcomes, and fencing on every refusal (`plan.md@fbca4ab8f:243–294`). Retained §5.6 instead permits a worker reserve failure to drop `UpsertSynced` and calls the missing replica an accepted asymmetry “not fed back” (`:911–937`).

   This is reachable: the worker handler returns `()` ([upsert_synced.rs:18](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:18)), the table can refuse an import ([install.rs:310](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/install.rs:310)), and `WorkerCommandResults` has no import result channel ([session_glue/mod.rs:250](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:250)). An implementation could therefore mark `Applied` and ACK despite a worker refusal.

   Every worker must record an outcome before its barrier ACK; reserve/install failure must aggregate to `Failed` or remain `Pending`, never disappear.

3. **MAJOR — F7 does not define lineage for an indistinguishable timeout-admitted suspect.**

   Rule 7 requires sticky alias lineage (`plan.md@fbca4ab8f:393–417`), but timeout admission can be a genuine self-NAT row, genuine identity-NPTv6 row, or lost-base alias (`:2100–2117`). The old sender gives the alias the base’s identical value ([daemon_ha_userspace_stream.go:370](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370), [daemon_ha_userspace_convert.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:399)); no legacy field distinguishes them.

   Marking only known aliases leaves the original alias→promote→export leak. Marking every suspect sticky forever silently suppresses downstream HA export of genuine false positives, beyond the currently priced five-second delay. Promotion and demotion overwrite only origin ([promote.rs:99](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:99), [shared_ops.rs:161](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:161)).

   Define provisional `alias-suspect` lineage before import, its export suppression, the proof required to clear it, and the permanent sticky transition for confirmed aliases. Demote→repromote is safe once that metadata exists.

4. **MINOR — F6 lacks a non-reusable incarnation issuer and validation authority.**

   Go-side arbiter placement is implementable: v15.23 explicitly draws #2170 generations inside the arbiter (`plan.md@fbca4ab8f:352–385`). But “boot epoch” and “restart bumps it” do not specify how reuse is prevented or how a tuple is bound to the currently accepted helper.

   Rust source sequencing restarts at zero ([event_stream/mod.rs:261](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/mod.rs:261)); current status exposes only PID/start time ([control.rs:141](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/protocol/control.rs:141)). Reusing incarnation `E` makes retained `(E,100)` reject genuine restarted `(E,1..100)`. Name a daemon-issued monotonic generation or collision-resistant nonce and bind both lanes to that independently validated instance.

5. **MINOR — `ConfirmedAliasNoop` can become terminal before P2’s purge result.**

   Rule 3 treats it as successful (`plan.md@fbca4ab8f:291–294`), while P1/P2 may require deleting a previously admitted publication (`:2067–2098`). Current BulkEnd reconciles and immediately ACKs ([sync_conn_read.go:242](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:242)); current helper deletion returns no result ([delete_synced.rs:20](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs:20)).

   Terminalize the noop only after P2 reports deleted, absent, or publication-mismatch-to-newer. Failure is `Failed`; timeout/unknown remains `Pending` and fences before reconcile.

6. **MINOR — F5 protects static fields, but replica-owned refresh fields remain underspecified.**

   The named-field RMW correctly preserves FIB, zones, NAT and rewrite fields (`plan.md@fbca4ab8f:336–346`). However, every worker refreshes ([loop_body/mod.rs:975](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:975)), imports fan out to every worker ([session_import.rs:233](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:233)), and replicas share the adopted session ID, so ID gating cannot identify the owner.

   Define the executable owner/origin predicate: only the owner merges policy and counters; replica `last_seen` must be monotonic, e.g. `max(current, candidate)`, rather than overwriting with a stale replica value.

7. **NIT — Rule 2 names a nonexistent NACK alternative.**

   `plan.md@fbca4ab8f:267–272` says “NACK or forced authoritative re-bulk,” but the protocol has no bulk NACK type ([sync.go:38](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:38)). The detailed fence already selects connection teardown and cold-prime, so Rule 2 should name that single mechanism.

The remaining attacks close:

- F1’s inventory is complete; #5305 already uses the dedicated socket ([manager_ha.go:1154](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1154), [process_control.go:181](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/process_control.go:181)), and `maps_sync` runs after helper status with that listener available.
- An unresolved quarantine remains decode-recorded in `bulkRecv`; its epoch deadline drops the hold and fences without ACK. On dispatch it enters the confirmation ledger.
- F4’s current-table identity predicate closes both the mirror-write-failure inverse and stale policy enumeration, provided the request carries the copied expected ID; same-worker table access is single-threaded ([session/mod.rs:429](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:429)).
- F8’s copy-time `(key, publication ID, generation)` binding is sufficient.
- F9 has a clean point-in-time helper snapshot precedent ([export.rs:85](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/export.rs:85)); SharedPromote inclusion, alias exclusion, and full bulk framing complete it.
- M11/P2 ownership and the no-close-toward-owner exception are correctly settled in-helper.

Final adjudication: both forks stay settled and option (a) is untouched, but F10 remains BLOCKER-rated. v15.23 is therefore not converged.
