# Codex hostile plan review — #6751 (round 36)

# PLAN-NEEDS-REVISION

Reviewed immutable v15.24 at `5e664a8ee`. A concurrent uncommitted `plan.md` edit appeared during review and was not credited.

1. **BLOCKER — Post-auth refusal still cannot prove the old peer observed both slots empty.**

   `plan.md@5e664a8ee:513-522` claims the admission fence prevents any reconnect during the quiet interval. But refusal remains an `installConn` verdict after setup (`:1208-1217`). Both endpoints independently complete setup and then install locally ([sync_conn.go:100](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:100), [sync_conn.go:130](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:130)); unkeyed setup returns immediately ([sync_auth.go:329](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_auth.go:329)).

   Remaining trace:

   - The fencing node is the non-initiator.
   - The old initiator retries each fabric every second ([sync_conn.go:435](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:435)).
   - A retry completes setup and is installed at the old peer before the fencing side returns `REFUSED` and closes it.
   - A retry begun within one disconnect bound of fence expiry may therefore still occupy one old-peer slot when another connection is admitted post-interval. `installConn` then observes a nonempty registry, so `wasDisconnected` is false and does not arm `needColdPrime` ([sync_conn.go:248](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:248), [sync_conn.go:278](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:278)).
   - Even if an earlier refused retry briefly observed both-empty, the old implementation treats writing `BulkEnd` as bulk success without waiting for ACK ([sync_bulk.go:169](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:169), [sync_conn.go:194](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:194)). Small writes can complete before the close is observed, clearing `needColdPrime`; the historically set `outboundBulkAcked` is sticky ([sync.go:479](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:479)) and suppresses survivor re-drive ([sync_conn.go:572](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:572)).

   A fixed timer therefore has a late-retry race; restarting it on every refusal livelocks against the one-second retry. The fence needs an old-peer-compatible mechanism preventing remote setup/install during the terminal quiet phase—for example, transport-level listener/SYN refusal—or another explicit quiescence proof.

   Mutual simultaneous fencing itself is live: both sides suppress dialing until release, and address ordering leaves one dial owner per fabric ([sync_conn.go:12](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:12)). The blocker is specifically the old-initiator/post-auth retry case.

2. **MAJOR — The second r35 MAJOR, timeout-admitted alias-suspect lineage, was not folded.**

   The checked-in r35 review contains another MAJOR at `codex-plan-r35.md:23-29`, despite the prompt’s one-MAJOR summary. v15.24 still requires sticky alias lineage (`plan.md@5e664a8ee:426-450`) while admitting an unresolved suspect as canonical on timeout (`:2140-2158`) and acknowledging that old-sender aliases may remain unconfirmable until session expiry (`:2205-2219`).

   The legacy alias copies the base value exactly ([daemon_ha_userspace_convert.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:399)). Promotion changes origin to `SharedPromote` ([promote.rs:99](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:99)), which is not peer-synced ([entry.rs:245](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs:245)) and is therefore exportable ([export.rs:114](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/export.rs:114)).

   Marking only confirmed aliases permits alias→promote→export; marking every suspect permanently suppresses genuine self-NAT/NPTv6 export beyond the priced delay. Define provisional `alias-suspect` lineage, export suppression while unresolved, proof for clearing it, and transition to permanent alias lineage. This is surviving alias machinery, not fork relitigation.

3. **MINOR — Worker outcomes are semantically fixed, but contradictory §5.6 text remains.**

   Rule 2 correctly requires every worker outcome before barrier ACK and maps reserve/install failure to `Failed` or `Pending` (`plan.md@5e664a8ee:248-259`). That closes the current `()`/refusal/no-result-channel gap ([upsert_synced.rs:18](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:18), [install.rs:310](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/install.rs:310), [session_glue/mod.rs:250](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:250)).

   However, §5.6 still calls the dropped worker import an accepted asymmetry “not fed back” (`plan.md@5e664a8ee:971-978`). Explicit `SUPERSEDED` wording resolves precedence, so this is no longer the original MAJOR, but the requested “no remaining contradictory §5.6 text” check fails. Replace that paragraph.

4. **MINOR — New failure semantics are not pinned in §9.**

   The test plan covers successful alias purge and newer-publication survival (`plan.md@5e664a8ee:2756-2763`), but not worker refusal-before-barrier-ACK, purge failure→`Failed`, or timeout/unknown→`Pending` with teardown and no reconcile/ACK.

5. **NIT — Put the daemon-issued incarnation contract in normative Rule 6.**

   The daemon-issued monotonic generation appears only in the status summary (`plan.md@5e664a8ee:15-17`); Rule 6 still says merely “helper INCARNATION (boot epoch)” (`:398-415`). The composition is semantically sufficient, but it should explicitly name the issuer and barrier binding there and pin restarted `(E2,1)` after retained `(E1,100)`. The code confirms the need: sequencing restarts at zero ([event_stream/mod.rs:275](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/mod.rs:275)) and status currently exposes only PID/start time ([control.rs:141](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/protocol/control.rs:141)).

6. **NIT — Replica refresh needs its required iterator projection named.**

   The origin-gated owner rule and monotonic replica `last_seen` are sound (`plan.md@5e664a8ee:354-378`); origin conversion distinguishes local/promoted owners from replicas ([entry.rs:216](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs:216), [shared_ops.rs:212](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:212)). But the current refresh iterator exposes no origin ([lookup.rs:501](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/lookup.rs:501)); add that internal signature change and a stale-replica regression.

`ConfirmedAliasNoop` terminalization itself now composes correctly with the five-outcome ledger, including mismatch-to-newer. NACK naming is also closed: connection teardown is the sole mechanism. No new blocker was found in option-(a)’s registry core, so this is revision—not `PLAN-KILL`.
