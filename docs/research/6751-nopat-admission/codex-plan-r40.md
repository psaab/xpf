# Codex hostile plan review — #6751 (round 40)

# PLAN-NEEDS-REVISION

1. **BLOCKER — The framing-only capability rule is contradicted by the detailed alias state machine, and bootstrap can exercise that contradiction.**

   The new top-level rule correctly forbids non-capability windows from clearing lineage or running the definitive pass at [plan.md:679](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:679). But the implementation contract still requires every quarantined entry to resolve at its own supposedly definitive `BulkEnd` at [plan.md:2221](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2221), runs P1 against every completed `BulkEnd` at [plan.md:2338](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2338), and repeats both requirements in §9 at [plan.md:3113](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3113) and [plan.md:3239](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3239).

   The exact old-sender trace is therefore ambiguous:

   - Ordinary frames are currently recorded/imported immediately at [sync_conn_read.go:98](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:98).
   - Matching `BulkEnd` currently reconciles, ACKs and fires the hold-release callback at [sync_conn_read.go:205](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:205).
   - Under the new rule, alias suspects must remain marked and the window must not confirm, purge or clear them. The lower-level rules instead demand resolution before ACK.

   Bootstrap makes this reachable on new↔new connections. Capability is specified only on a periodic 5–10-second ticker with state initially `UNKNOWN` at [plan.md:1292](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1292). The current connection path exposes the connection, sends only clock sync, and immediately starts cold-prime at [sync_conn.go:130](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:130). Thus the first new-sender window can finish before advertisement. The isolated “pre-data” adjective at [plan.md:2821](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2821) supplies no ordered send contract.

   Framing-only need not regress the legacy table if quarantined candidates are provisionally admitted with `alias-suspect` retained. The plan does not currently specify that terminal; holding or dropping them can regress genuine self-NAT/NPT rows versus today.

   Required: bind authority to each window, define non-capability `BulkEnd` as disposition-only, retain/coalesce prime debt, and force a fresh capable prime when capability is first learned.

2. **BLOCKER — The retained-C0 degraded terminal is not code-real, and the cap is shorter than the actual known-peer detector.**

   The honesty statement is correct: the cited deadline is a write deadline at [sync_protocol.go:63](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_protocol.go:63); no-ACK peers never increment missed-heartbeat count at [sync_conn_read.go:27](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:27); the compatibility test keeps them connected at [sync_test.go:4655](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_test.go:4655); and a registered slot suppresses redial at [sync_conn.go:446](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:446).

   However:

   - The `min(...)` cap fixes the literal 7.5s-versus-5s arithmetic, but production’s ACK-capable detector is a 10-second read deadline with teardown after two misses—approximately 20 seconds—at [sync.go:90](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:90) and [sync_conn_read.go:33](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:33). A five-second fence therefore cannot prove mode-(i) both-empty.
   - The five-second readiness timer requires `syncPeerConnected` and only calls `SetSyncReady(true)` at [daemon_ha_sync.go:40](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:40). Disconnect stops it at [daemon_ha_sync.go:109](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_sync.go:109); the regression explicitly pins no timeout release without reconnect at [session_sync_readiness_test.go:33](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/session_sync_readiness_test.go:33). The plan preserves connected-state revalidation at [plan.md:1597](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1597).
   - Classic RETH VRRP has a separate 30-second hold timer at [manager.go:351](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/vrrp/manager.go:351), not the claimed five-second release.

   A fence-owned, disconnected-eligible degraded terminal with explicit classic-VRRP/private-RG effects and a defined timer origin is required.

3. **MAJOR — A genuine both-empty transition cannot discharge alias-proof debt for the same non-capable peer.**

   Suspects owe a definitive snapshot at [plan.md:484](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:484), while every snapshot from that legacy peer remains permanently framing-only at [plan.md:679](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:679). Consequently, an OS failure, restart or later both-empty followed by reconnection to the same peer cannot discharge lineage debt as claimed at [plan.md:705](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:705).

   Sender delivery/ACK debt and receiver alias-proof debt need separate terminals. Alias-proof debt ends only on a capable definitive snapshot or the suspect row’s own close.

4. **MINOR — The promised retained-C0 regression remains absent.**

   [plan.md:717](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:717) says §9 pins delayed/lost C0 close. The liveness suite at [plan.md:2935](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2935) only says an old peer triggers fence/re-fence; it does not assert retained C0, disconnected timeout release, or the separate debt terminals.

The other r39 folds are present: §6 correctly names both `pub_token` and the wire-carried optional lineage stage at [plan.md:2725](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2725); §9 pins the exact accept trace and named mutex at [plan.md:2947](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:2947); and the CURRENT-store tail is correctly disposition-only at [plan.md:3247](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:3247).

No new blocker was found in the option-(a) registry/holder/drain core. The open blockers are in the surviving capability/alias discipline and legacy fence terminal.
