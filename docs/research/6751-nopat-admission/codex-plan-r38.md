# Codex hostile plan review — #6751 (round 38)

# PLAN-NEEDS-REVISION

Reviewed committed v15.26 at `917f84481`. A concurrent uncommitted `plan.md` edit appeared during review and was not credited. All plan line numbers below refer to the committed blob.

1. **BLOCKER — Accepts during the kill sweep can receive the current generation and escape after fence release.**

   Fence engagement advances the generation first (`plan.md@917f84481:1328-1331`). A child accepted afterward is stamped with that current generation (`:609-611`), while the sweep kills only “pre-fence” children and later stages reject only stamps predating the current generation (`:612-618`). No release-side generation advance or listener-quiescence barrier is specified before the fence clears (`:2086-2093`).

   Trace: sweep snapshots children → `Accept` returns C1 with current G1 → C1 stalls before `beginSetup` → fence releases still at G1 → C1 resumes and passes every stale-stamp check. Current code exposes the interval between [Accept](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:390) and [beginSetup](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:409); the existing child sweep snapshots and unlocks before closing sockets ([sync_admission.go:111](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_admission.go:111)). Section 9 pins only pre-fence children (`plan.md@917f84481:2812-2823`).

   Required fold: atomically reject/register every accept while fenced, or advance the admission generation after listener quiescence plus a final sweep. Pin accept-after-sweep-start → resume-after-release.

2. **BLOCKER — The claimed peer-side C0 disconnect bound does not exist for a supported legacy no-heartbeat-ACK peer.**

   The plan relies on a heartbeat/keepalive bound to prove both old-peer slots became empty (`plan.md@917f84481:576-582,623-630`). Current `receiveLoop`, however, increments missed heartbeats only after `peerHeartbeatAckEver` becomes true; otherwise it sends another heartbeat and continues indefinitely ([sync_conn_read.go:27](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:27)). The rolling-upgrade regression explicitly requires a no-ACK peer to remain connected, healthy, and installed past the silence limit ([sync_test.go:4655](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_test.go:4655), [sync_test.go:4736](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_test.go:4736)).

   If our C0 close notification is delayed or lost, the initiator retains C0 and does not redial while its slot remains registered ([sync_conn.go:446](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:446)). Listener refusal therefore cannot kill C0—the retry never occurs. A later connection sees `wasDisconnected == false` and does not arm `needColdPrime` ([sync_conn.go:244](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:244)).

   Required fold: establish an actual finite legacy-peer detector or observable remote-empty proof, derive the quiet interval from it, and pin no-ACK C0 with delayed/lost close notification.

3. **MAJOR — The 5-second verdict remains normatively contradictory.**

   Rule 7 correctly says the window is not definitive, timeout admission retains `alias-suspect`, and only COMPLETE-PRIME or the row’s close clears it (`plan.md@917f84481:471-490`). Retained §5.6 nevertheless calls the 5-second current-store result “definitive” (`:2157-2161`), and §9 repeats that wording (`:3098-3100`).

   That permits the original trace: alias-only → timeout interpreted as definitive genuine → clear → import → promote → export. The alias copies its base unchanged ([daemon_ha_userspace_convert.go:399](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:399)); promotion creates `SharedPromote` ([promote.rs:99](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:99)) and emits an Open directly ([session/mod.rs:1516](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:1516)).

   Required fold: state in §5.6 and §9 that the timer resolves only quarantine disposition; it never clears lineage. Add a direct fail-on-timeout-clear regression.

4. **MAJOR — The alias-stage carrier still lacks its Go→helper ingress and contradicts §6.**

   Section 5.6 and §9 claim coverage through `SessionMetadata`, an additive `SyncedSessionEntry` extension, replication, promotion, and every exporter (`plan.md@917f84481:2348-2358,2798-2811`). Section 6 instead says `SyncedSessionEntry` gains exactly one helper-internal field—`pub_token`—and inventories no alias-stage request/update path (`:2612-2651`).

   The missing bridge is load-bearing:

   - `SyncedSessionEntry` embeds `SessionMetadata` ([worker/mod.rs:375](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/mod.rs:375)).
   - Import moves only `entry.metadata` into `SessionTable` ([upsert_synced.rs:64](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64)).
   - Neither the Go nor Rust `SessionSyncRequest` carries an alias stage ([protocol_ha.go:33](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_ha.go:33), [control.rs:1008](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/protocol/control.rs:1008)).
   - Promotion can emit an Open before any Go exporter is consulted ([session/mod.rs:1516](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:1516)).

   Required fold: choose one authoritative stage carrier, specify its Go/Rust request mapping and update transaction, reconcile §6, and explicitly gate promotion Open, owner-RG export, helper snapshot export, Go bulk, and Go sweep.

5. **MINOR — Prime-request/re-fence liveness is not directly pinned.**

   The explicit debt is necessary because stable sweeps normally emit individual frames rather than another bulk ([sync_conn_sweep.go:142](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_sweep.go:142)). But §9’s alias suite (`plan.md@917f84481:2798-2811`) lacks timeout → prime-REQUEST, capable-peer completion, ignored request → fence, multiple-suspect coalescing, and post-prime re-arming tests. Add them to prevent a legacy-alias storm from becoming a tight re-fence loop.

6. **NIT — AGY r37’s export-skip counter did not land in the committed taxonomy.**

   Rule 7 requires a distinct helper-side counter/label for skips of either lineage mark (`plan.md@917f84481:501-505`). Section 5.8 still inventories five helper counters and eight total, none for these skips (`:2524-2546,3183-3188`).

The original pre-fence C0 receiver seams are otherwise folded and pinned, and the failure-semantics suite, daemon-issued Rule 6 incarnation, `(E2,1)` restart case, stale-replica regression, and `S_new` reverse-resolution pin are genuinely present (`plan.md@917f84481:419-435,2784-2823`). No new defect was found in the option-(a) registry/holder/drain core.
