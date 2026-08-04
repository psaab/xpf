# Codex hostile plan review — #6751 (round 33, fork adjudication)

Fork adjudication: **PATH A** for the design actually specified in v15.20.

Standard verdict: **PLAN-NEEDS-REVISION**.

The control-socket contention foreclose is disproved by the repository. PATH A is implementable over the existing dedicated session socket. It is not yet correctly specified, but it requires less new foundational machinery than §4.0.1’s PATH B. A strategically cleaner “B2” may be possible, but it would need a different durable source and cut protocol; that is not the PATH B currently on the ballot.

1. **BLOCKER — PATH A is not foreclosed by the shared-control-socket budget, but its worker import channel has no bound or completion contract.**

   `CLAUDE.md` limits high-frequency use of the shared control socket ([CLAUDE.md:44](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/CLAUDE.md:44)). HA imports do not use that socket. Go derives `userspace-dp-sessions.sock`, serializes through `sessionMu`, and performs a synchronous request there ([process_control.go:172-216](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/process_control.go:172)). Rust binds it separately and services it on a dedicated thread ([lifecycle.rs:165-180](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/lifecycle.rs:165), [lifecycle.rs:344-381](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/lifecycle.rs:344)).

   `SetClusterSyncedSessionV4/V6` already writes the mirror and then sends the same import to that helper socket ([manager_ha.go:1112-1167](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1112), [manager_ha.go:1265-1303](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1265)). Policy invalidation likewise already reaches helper deletes ([daemon_policy_invalidate.go:357-386](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_policy_invalidate.go:357), [manager_ha.go:1392-1412](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1392)). Making Rust the sole mirror writer changes where the mutation occurs; it does not add bulk traffic to the main socket.

   The cited `session_import.rs:238` seam is not cross-process transport. It is an in-process push into each worker’s `Mutex<VecDeque<WorkerCommand>>` ([session_import.rs:233-242](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:233)). The deques are unbounded ([bringup.rs:426-432](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:426)); replacements, deletes, and the zero-worker case bypass the distinct-session cap ([session_import.rs:108-120](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:108), [session_import.rs:337-345](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:337)). Each forward import creates forward and reverse commands for every worker, and repeated same-key replacements have no absolute bound. Workers `mem::take` and process the entire accumulated queue in one loop turn ([session_glue/mod.rs:663-704](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:663)).

   PATH A therefore needs bounded admission, explicit refusal, an import sequence, and a per-worker `ImportBarrier` ACK. The existing two-phase owner export—enqueue under `ServerState`, release the global mutex, then wait on worker ACKs—is the correct precedent ([export.rs:22-66](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/export.rs:22), [export.rs:237-264](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/export.rs:237)).

2. **BLOCKER — PATH A still lacks an authoritative “applied” transaction and exact Close publication.**

   Today the receiver adds a key to the bulk received-set before attempting installation ([sync_conn_read.go:109-147](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:109)). Installation returns no error to that layer, while helper errors are only logged ([sync_conn_gen.go:435-490](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:435)). `BulkEnd` then reconciles and ACKs unconditionally ([sync_conn_read.go:241-247](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:241)). Rust’s import-cap branch silently returns, leaving the session handler’s response successful ([session_import.rs:115-120](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:115), [sync_session.rs:19-32](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/handlers/sync_session.rs:19)).

   Policy invalidation has a separate stale-close race:

   1. Go enumerates `K/Iold`.
   2. `K/Inew` replaces it.
   3. A helper exact-ID arbiter correctly refuses deletion of `Inew`.
   4. Go nevertheless invokes `QueueDeleteV4/V6` for every enumerated row ([daemon_policy_invalidate.go:357-386](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_policy_invalidate.go:357)).
   5. `QueueDelete` draws a new generation after the replacement ([sync_conn_gen.go:156-197](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:156)), so the peer deletes the live replacement.

   The helper must publish the Close inside the successful exact-incarnation delete transaction, or return an exact per-key result plus a reserved generation token. Aggregate counts are insufficient.

   “Reroute two Go sites” also understates the writer inventory. Reverse imports still mutate BPF directly ([manager_ha.go:1125-1126](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1125)); generic store operations construct reverse and DNAT companions in Go ([session_store.go:274-350](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/session_store.go:274)); and the current worker handler does not write the conntrack mirror—its FDs are unused ([session_glue/mod.rs:663-668](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:663)). PATH A must inventory local publish, refresh, close, imported forward/reverse, DNAT/session-map companions, policy clear, filtered clear, and clear-all.

   Thus PATH A is proportionate at the transport level, but it is not a two-call-site change.

3. **BLOCKER — PATH B’s named authoritative source is neither singular nor durable, and its claimed mutation sequence does not exist.**

   Each worker owns a private, single-threaded `SessionTable` on its stack ([setup.rs:28-42](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/setup.rs:28), [session/mod.rs:429-434](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:429)). The coordinator owns a different replicated shared-map aggregate ([session_manager.rs:3-17](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/session_manager.rs:3)).

   A normal reconcile snapshots that shared map, destroys every worker/table, and replays the entries ([teardown.rs:54-97](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs:54), [coordinator/mod.rs:802-835](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/mod.rs:802)). Replay retags locally originated entries as `WorkerLocalImport` ([session_glue/mod.rs:868-878](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:868), [entry.rs:242-261](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs:242)); the existing owner-RG table export excludes that origin as peer-synced ([session_glue/mod.rs:608-635](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:608)). Reusing that export after reconcile can therefore omit valid local sessions.

   The alleged “RT_FLOW mutation sequence” is also false:

   - `install_epoch` is private, per-worker, and resets with every table ([session/mod.rs:343-349](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:343), [session/mod.rs:746-773](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:746)).
   - `session_id` is a write-once incarnation identifier, not a mutation sequence ([session/mod.rs:459-470](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:459)).
   - The #2170 generation horizon is assigned later by Go when it queues a delta ([sync_conn_gen.go:113-154](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:113)); local Rust entries carry generation zero ([worker/mod.rs:383-389](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/mod.rs:383)).

   No existing field can order worker-table pages against a Go generation horizon.

   Pagination can omit a live entry entirely: the only resumable iterator uses reusable slab indices, so a post-cut insertion or reinstall can occupy a slot already passed by the cursor ([lookup.rs:463-540](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/lookup.rs:463)). That is safe only if the corresponding `>H` delta is guaranteed through End, which §4.0.1 does not provide. A hash-page cursor is worse because rehash can skip an unchanged `≤H` row.

   The existing coordinator-shared vector snapshot is a useful ingredient ([export.rs:69-175](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/export.rs:69)), but promoting it to durable authority with provenance/version preservation is a materially different B2 substrate—not the SessionTable design in §4.0.1.

4. **BLOCKER — PATH B’s horizon is not a snapshot cut; both the post-horizon Open and during-snapshot Close have executable failures.**

   A post-horizon Open is not guaranteed to enter the received-set. Current bulk frames release `writeMu` between Start, rows, and End, while the incremental send loop independently acquires the same mutex ([sync_bulk.go:81-158](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:81), [sync_conn_write.go:268-301](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:268)). Therefore:

   1. Sender samples `H`.
   2. `K` opens and receives `G > H`.
   3. Its delta lands before `SnapshotStart`; the receiver installs it outside the bulk window, so it is not in `bulkRecv`.
   4. Start clears receiver generation state and creates empty received sets ([sync_conn_read.go:183-203](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:183), [sync_conn_gen.go:324-344](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:324)).
   5. The snapshot omits post-horizon `K`.
   6. End reconciles solely against the received sets and deletes it ([sync.go:1080-1126](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync.go:1080)).

   A delta landing during the window is recorded and safe. One landing after End eventually reinstalls the row, but only after an avoidable delete window, and ACK/readiness can precede that correction.

   For a Close during the snapshot:

   - Page then Close is safe: the Close deletes the row; retaining its key in the received-set does not reinstall it.
   - Close then page is unsafe under current generation behavior. Bulk rows receive a fresh generation when serialized ([sync_bulk.go:103-107](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:103)). A delayed page can therefore get `Gsnapshot > Gclose`, resurrect the row, and its received-set membership prevents End from deleting it.
   - Close after End is merely eventual delta convergence; End itself deletes nothing that was present in the snapshot.

   Correct PATH B semantics require a sender-incarnation field, a Start-before-`>H` barrier, no same-incarnation generation reset, snapshot rows stamped `≤H`, reconciliation that retains any currently admitted generation `>H` regardless of arrival relative to Start, and an End watermark proving all omitted post-cut mutations were delivered/applied.

5. **BLOCKER — The same-worker stale-close proof holds only on the binary event-stream lane; the actual end-to-end merge is unordered.**

   The narrow claim is verified. Worker deltas are FIFO ([session/mod.rs:1713-1722](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/mod.rs:1713)); flush preserves that order ([session_delta.rs:184-200](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_delta.rs:184)); event-stream sequence allocation and enqueue are atomic ([event_stream/mod.rs:172-197](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/mod.rs:172), [event_stream/mod.rs:507-533](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/mod.rs:507)); and Go synchronously dispatches frames in order ([eventstream.go:559-615](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/eventstream.go:559), [eventstream.go:938-961](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/eventstream.go:938)). On that lane alone, `[Close, Open]` produces `Gdel < Gnew`.

   But Rust first clones every delta into the RPC fallback buffer and then emits it on the event stream ([session_delta.rs:276-317](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_delta.rs:276)). Go continues draining that duplicate buffer every five seconds while the event stream is connected ([daemon_ha_userspace_stream.go:254-320](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:254)); only the polling lane takes `userspaceDeltaSyncMu`. A delayed fallback Close can therefore arrive after the event-stream replacement Open, draw a fresh generation above it, and delete the replacement. This requires no rebalance and remains in the same table epoch.

   A table epoch must cover more than “steering rebalance”: every full snapshot replan/worker teardown, worker-count or queue/RSS mapping change, link-cycle stop/rebind, helper restart, and any worker table loss/replacement. The current reconcile tears down the complete worker set ([reconcile/mod.rs:330-398](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:330)). No such epoch presently exists, and a worker-local check cannot suppress late Go fallback/policy producers.

   PATH B must disable the fallback lane after a barriered handoff or deduplicate/serialize both lanes by one Rust source sequence and incarnation.

6. **BLOCKER — PATH B’s “helper tables never contain aliases” premise is false.**

   Go derives explicit forward-wire aliases ([daemon_ha_userspace_stream.go:370-389](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:370)). At the receiver they are ordinary HA rows: the helper publishes the exact supplied key and queues it to every worker ([session_import.rs:133-139](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:133), [session_import.rs:233-242](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:233)); the worker installs that exact key into its table ([upsert_synced.rs:64-78](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64)). The plan also explicitly allows timeout-admitted legacy aliases through `UpsertSynced` ([plan.md:1831-1879](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1831)).

   After promotion, such an alias becomes locally originated for export purposes, so a table snapshot can propagate it. New+new can become alias-free only after negotiated sender omission and a proven drain/purge of transition-era rows.

   Consequently, quarantine and provisional purge have no steady-state purpose in a clean new+new cell, but they remain required for mixed-version and timeout-admission transitions. They cannot “survive unchanged”; they need explicit legacy gating and alias provenance/filtering.

7. **BLOCKER — The mirror cannot become cosmetic after only replacing HA bulk. Multiple correctness consumers still enumerate it.**

   Userspace `SessionStore.ForEachV4/V6` still delegates to the BPF batch iterators ([session_store.go:118-129](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/session_store.go:118)), and the userspace manager does not override iteration ([manager.go:387-391](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager.go:387)).

   | Classification | Remaining consumers |
   |---|---|
   | HA correctness | Existing bulk and sweep ([sync_bulk.go:95-158](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:95), [sync_conn_sweep.go:137-190](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_sweep.go:137)); receiver absence reconciliation ([session_store.go:613-672](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/session_store.go:613)). |
   | Security/mutation | Commit-time policy invalidation ([daemon_policy_invalidate.go:285-380](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_policy_invalidate.go:285)); clear-all ([maps_session.go:405-528](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/maps_session.go:405)); CLI filtered clear ([cli_clear.go:336-550](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cli/cli_clear.go:336)); gRPC filtered clear ([server_sessions.go:1293-1543](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/grpcapi/server_sessions.go:1293)). |
   | Legacy correctness | Conntrack GC ([gc.go:288-363](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/conntrack/gc.go:288)); userspace disables this sweep ([daemon_run.go:230-240](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_run.go:230)), so it remains only for the legacy backend. |
   | Operational readiness | Neighbor warming ([daemon_ha.go:1509-1556](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha.go:1509)); best-effort, but not cosmetic display. |
   | Observational/cosmetic | NAT show ([source.go:40-55](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/natshow/source.go:40), [dest.go:43-58](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/natshow/dest.go:43), [persistent.go:65-92](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/natshow/persistent.go:65)); REST session/NAT/metrics ([sessions.go:222-260](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/api/sessions.go:222), [nat.go:369-398](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/api/nat.go:369), [metrics_sessions.go:152-193](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/api/metrics_sessions.go:152)); gRPC/CLI show paths ([server_show_flow.go:312-363](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/grpcapi/server_show_flow.go:312), [cli_show_flow.go:392-519](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cli/cli_show_flow.go:392), [cli_show_nat.go:142-274](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cli/cli_show_nat.go:142)). |

   PATH B would need table-native receiver reconciliation, policy-filtered invalidation, filtered clear, and clear-all APIs before the mirror is cosmetic. That is substantially broader than a sender snapshot channel.

8. **BLOCKER — PATH B does not replace the sweep, carry-forward, and recovery duties as written.**

   `syncSweep` performs three distinct jobs: connected delete-journal flushing, delete-overflow authoritative resync, and mirror scanning to recover Opens dropped by Go’s outbound queue ([sync_conn_sweep.go:89-190](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_sweep.go:89)). The helper latch cannot observe the last failure: `queueMessage` may drop and arm Go backfill ([sync_conn_write.go:36-49](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:36)), but `QueueSession` discards the result and the event callback reports success ([daemon_ha_userspace_stream.go:181-214](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:181)). Rust then ACKs/trims the source event. The existing FullResync path re-emits Opens but provides no absence reconciliation for a missed Close.

   Under a correct B2:

   - Keep journal flushing.
   - Convert delete overflow, every Go `sendCh` Open failure, and helper FullResync into daemon-lifetime authoritative-snapshot debt.
   - Remove only the userspace mirror-created-time scan.
   - Retain legacy-backend sweeping.

   Carry-forward can retire only after the real `>H` retention and End fence described in finding 4. Under §4.0.1 as written, a carried set is still needed; horizon alone does not replace it.

   The detailed §5 debt machinery closes the r28 write-completion problem in principle: exact `(epoch,debtGen)` attribution and ACK-only compare-and-clear ([plan.md:1564-1609](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1564)). The PATH B rewrite must still distinguish local helper `SnapshotEnd` from peer completion. Record the debt pair before the peer-facing End; page/checksum failure, write failure, disconnect, or receive abort preserves debt; only the matching peer ACK clears it. Current code still clears `needColdPrime` merely because `doBulkSync` returned after writing End ([sync_conn.go:194-206](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:194)).

9. **MAJOR — PATH B assumes an existing Rust gRPC server that does not exist.**

   Rust has no tonic/prost/gRPC dependency ([Cargo.toml:10-23](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/Cargo.toml:10)). The helper serves newline-delimited JSON over Unix streams ([handlers/mod.rs:44-89](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/handlers/mod.rs:44)), with control and session Unix listeners ([lifecycle.rs:163-180](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/lifecycle.rs:163)). `server/helpers/` is a Rust module, not a gRPC service.

   A third Unix socket or a real gRPC service is feasible, but the plan must specify request limits, retained-snapshot memory, cancellation, worker ACKs, cursor lifetime, timeout/backpressure, and lock release. This further favors PATH A for the present fork.

### Conditional §5.x surgery if a redesigned B2 is later selected

This condition is not met by my adjudication. For scope clarity, B would require at least:

- **Survive essentially verbatim:** §§5.1–5.3 ([plan.md:409-594](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:409)), §5.5 ([plan.md:613-620](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:613)), the registry/holder core of §5.6 through line 787, and most of §5.7 ([plan.md:1984-2121](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1984)).

- **Die:** the mirror V1–V4 reread, Close-before-mirror invariant, cross-process incarnation arbiter, failed-delete omission index, mirror carry-forward, and mirror equality/backfill proof ([plan.md:1286-1517](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:1286)).

- **Require edits:** §5.4 mixed-version capability negotiation; alias/quarantine text at lines 788–905; epoch/barrier/lifecycle and debt text at lines 906–1285 and 1518–1738; alias P1/P2 at lines 1739–1906; the mixed-version proof at lines 1907–1982; and §5.8 recovery counters.

- **Require new, currently missing design:** durable table ownership across reconcile, a coherent cross-worker cut, page cursor/copy semantics, helper-event-sequence/End fencing, table epochs, dual-stream deduplication, alias provenance, receiver table reconciliation, policy/clear APIs, and sweep-to-debt conversion.

No option-(a) registry-core kill shot against B was found: admission, allocator ownership, holders, drain, and static accounting live in Rust/helper state and do not read the BPF mirror. The kill shot against the written PATH B is system integration: its named table is ephemeral, its horizon is disconnected from #2170, and several security/correctness operations still derive their targets from the mirror. Alias P2 and generation/barrier machinery also do not survive “unchanged”; their implementations are substrate-dependent.

The convergent next revision should select PATH A, specify the dedicated-session-socket import barrier and complete sole-writer transaction, and fold the still-open round-32 findings. If the project prefers table truth strategically, it should request a new B2 design round rather than treating §4.0.1 as a surgical rewrite.
