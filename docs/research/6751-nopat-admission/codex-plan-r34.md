# Codex hostile plan review — #6751 (round 34)

# PLAN-NEEDS-REVISION

Scope: I reviewed the immutable v15.21 blob at `db492cf1f`. The working copy of `plan.md` concurrently acquired an uncommitted v15.22 edit; I preserved it and did not use it for this verdict.

1. **BLOCKER — Rule 1’s “complete” writer inventory is incomplete.**

   The eleventh live mutator is initial-control cleanup: [maps_sync.go:577](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/maps_sync.go:577) directly iterates `sessions`/`sessions_v6` and calls `ctMap.Delete` at line 642. It has neither exact-incarnation comparison nor Close publication, so it creates another batch-copy→callback stale window outside §4.0.2’s claimed sole window.

   It also interprets bytes `[16:24]` as `Created` at [maps_sync.go:609](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/maps_sync.go:609), but the current padded ABI puts `SessionID` there and `Created` at bytes 24–31: [bpf_session_value.go:75](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/bpf_session_value.go:75). Thus the cleanup’s keep/delete decision currently reads the session ID as a timestamp.

   The inventory also omits:

   - Import rollback writers at [manager_ha.go:1204](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/manager_ha.go:1204) and line 1319.
   - Idle reaping at [loop_body/mod.rs:1615](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1615).
   - Terminal/DSCP teardown at [session_glue/mod.rs:546](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:546), reaching mirror deletion at [bpf_map/mod.rs:704](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/mod.rs:704).
   - `ExpiredSession` carries no session ID for the required comparison: [entry.rs:337](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs:337).

   Negative inventory result: `bpf_map/mod.rs:48–97` and `600–683` mutate the separate `userspace_sessions` steering map; the optional conntrack path at `531–583` has no production `Some(ConntrackCtx)` caller. Fabric-forward and DNAT maps are distinct, and I found no separate NAT64/NPTv6 conntrack writer.

2. **BLOCKER — Rule 2 lacks atomic admission, a coherent deadline, and terminal refusal recovery.**

   Enqueue-release-wait is implementable without an inherent self-deadlock: the session socket has a dedicated thread ([lifecycle.rs:344](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/lifecycle.rs:344)), and the precedent releases `ServerState` before waiting ([handlers/mod.rs:270](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/handlers/mod.rs:270)).

   But the proposed contract is not bounded consistently:

   - Export waits 15 seconds: [export.rs:237](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/export.rs:237).
   - Go abandons a session request after roughly 3 seconds: [process_control.go:73](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/process_control.go:73).
   - Rust installs 5-second socket deadlines: [handlers/mod.rs:44](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/handlers/mod.rs:44).

   Literal precedent reuse permits an unknown late commit after Go has declared failure. The design needs one end-to-end deadline and explicit cancellation/late-result semantics.

   Admission is also non-atomic today: shared state and companion maps are mutated before per-worker fanout ([session_import.rs:133](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:133), fanout at line 233). Rule 2 must reserve capacity across every affected worker for forward, reverse, and barrier commands before any mutation, with reserved control capacity or separate lanes.

   For the 50,001st refused key, “no ACK” is insufficient. A missing ACK merely remains pending ([sync_conn_read.go:249](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:249)); survivor re-drive is triggered by disconnect, not by an ACK timeout ([sync_conn.go:572](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:572)). The first 50,000 provisional installs can therefore remain indefinitely while both fabrics stay connected. Any refusal, timeout, or unknown result must abort/fence that receive epoch: no reconcile, ACK, or hold release, followed by an explicit NACK or forced authoritative re-bulk.

3. **BLOCKER — Rule 3 contradicts the retained quarantine invariant.**

   `plan.md@db492cf1f:227–234` says bulk membership is recorded only after confirmed installation. Retained §5 says the opposite at `plan.md@db492cf1f:1831–1841`: quarantined keys must be recorded at decode time even though installation is gated.

   Current code records membership before install at [sync_conn_read.go:109](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:109), then BulkEnd reconciles and ACKs at [sync_conn_read.go:205](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go:205). Reconciliation deletes live rows absent from that membership set.

   The applied transaction therefore needs two ledgers:

   - Decode-time received membership, used for quarantine and absence reconciliation.
   - Applied-result state, with explicit terminal outcomes such as `Applied`, `AlreadyNewer`, `ConfirmedAliasNoop`, and `Failed/Pending`.

   A confirmed alias is intentionally not installed, so literal “confirmed install” cannot define BulkEnd success.

4. **BLOCKER — Rule 4’s “absent mirror row” predicate is not exact-incarnation safe, and Close ownership is ambiguous.**

   An absent mirror is not proof that the closing incarnation remains current. v15.21 retains Open-before-mirror and mirror-failure windows; current mirror publication logs and continues on update failure at [publish_conntrack.rs:141](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs:141).

   Surviving trace:

   1. B replaces A and publishes Open G2.
   2. B’s mirror write fails, leaving the mirror absent.
   3. Delayed Close(A) takes Rule 4’s “absent” branch and publishes Close.
   4. `takeDeleteGenV4` consumes B’s sender stamp and draws G3 ([sync_conn_gen.go:179](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:179)).
   5. The peer accepts G3 and deletes B ([sync_conn_gen.go:282](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:282)).

   The transaction must also consult the helper’s authoritative live key→publication identity. Mirror absence is safe only when no different live helper entry exists.

   v15.21 also says both that the helper publishes Close inside the commit (`plan.md:235–249`) and that Go fires `QueueDelete` from the confirmed result (`plan.md:250–251`). A helper Close already reaches `QueueDelete` through [daemon_ha_userspace_stream.go:393](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:393). Implementing both producers can generate a later duplicate Close that kills a replacement. The plan must select exactly one producer.

   Finally, the comparison identity is underspecified: node-local `SessionID` and cross-node `RTFlowSessionID` are distinct ([types.go:27](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/types.go:27)); conversion mints the former while carrying the latter separately ([daemon_ha_userspace_convert.go:328](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:328)). Rule 4 must name the authoritative identity domain for every local, imported, clear, and policy-delete transaction.

   The requested policy-invalidation trace is otherwise sound once those defects are fixed: a refused stale enumeration must publish no Close. The peer learns the POLICY change through config sync—local policy apply and invalidation precede peer push ([daemon_apply_commit.go:245](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_apply_commit.go:245)); replacement Open carries policy metadata, and queue loss arms backfill ([sync_conn_write.go:36](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_write.go:36)). No special Close should describe the surviving replacement.

5. **BLOCKER — Rule 5’s “field-targeted update” is not an implementable atomic operation as specified.**

   `sessions` and `sessions_v6` are ordinary hash maps ([xpf_maps.h:96](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/bpf/headers/xpf_maps.h:96)); the syscall replaces the entire value. Current refresh performs lookup/full-value update and legitimately changes `last_seen`, `policy_id`, and four counter fields ([bpf_map/mod.rs:394](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/bpf_map/mod.rs:394)).

   Safe “field targeting” therefore means semantic read-modify-write under the same global per-key stripe, gated by the refreshing entry’s expected session ID, followed by a named-field merge. The iterator currently does not expose that ID ([lookup.rs:501](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/lookup.rs:501)), and every worker invokes refresh ([loop_body/mod.rs:975](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:975)). The plan must also designate one counter owner or define aggregation; otherwise a replica can preserve B’s ID while overwriting B’s legitimate policy, timestamp, or counters with stale values.

6. **BLOCKER — Rule 6 does not serialize deduplication through generation allocation and has no reconnect-safe namespace.**

   The event callback discards `seq` ([daemon_ha_userspace_stream.go:159](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_stream.go:159)); only fallback polling takes the existing mutex. Thus:

   1. Fallback Close source 11 passes dedup, then stalls.
   2. Event Open source 12 passes and receives `Gnew`.
   3. Close 11 resumes and receives `Gdel > Gnew`.
   4. The peer deletes the replacement.

   One arbiter must cover source admission, high-water update, and `QueueSession`/`QueueDelete` generation draw, with the watermark advanced by either lane.

   The proposed ordering tuple does not exist on both lanes. JSON fallback has `worker_id` but no source sequence or table epoch ([binding.rs:1147](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/protocol/binding.rs:1147)); binary payloads likewise lack them ([session_sync.rs:15](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/codec/session_sync.rs:15)). The existing header sequence is a separate process-global transport sequence ([wire.rs:175](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/event_stream/codec/wire.rs:175)), allocated after the fallback clone.

   Rule 6 must specify:

   - High-water preservation across an ordinary event-stream reconnect.
   - A helper incarnation carried on both lanes.
   - Reset only after validating a new incarnation/table epoch.

   Otherwise resetting admits delayed pre-reconnect fallback frames, while retaining the watermark across helper restart drops genuine new low sequences. Supplying these fields also conflicts with v15.21 §6’s “no wire change” statement (`plan.md:2251–2270`) unless that section is revised.

7. **BLOCKER — Rule 7’s alias provenance is neither sticky across promotion nor visible to all exporters.**

   Current imported rows use `SyncImport`; promotion overwrites that with `SharedPromote` ([promote.rs:99](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:99)), while demotion overwrites it back to `SyncImport` ([shared_ops.rs:161](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:161)). Helper export excludes only origins satisfying `is_peer_synced` ([export.rs:107](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/export.rs:107)); `SharedPromote` does not satisfy it ([entry.rs:242](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/entry.rs:242)).

   The resulting leak is:

   `old-peer alias → timeout admission → local promotion → export to a new capable peer as canonical`

   Alias lineage must therefore be orthogonal, sticky metadata preserved across promotion, demotion, replication, and reconciliation.

   The retained Go bulk/sweep paths cannot see any such provenance: the BPF value contains no provenance field ([xpf_conntrack.h:17](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/bpf/headers/xpf_conntrack.h:17)), while Go bulk and sweep filter only ordinary row fields ([sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:95), [sync_conn_sweep.go:137](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_sweep.go:137)). The design needs either a mirror-visible bit or an exact lifecycle-managed side index consulted by every export path.

8. **BLOCKER — §4.0.2’s known-stale omission check lacks enough state to make its decision.**

   Batch iteration copies 256 rows before invoking callbacks ([maps_session.go:231](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/maps_session.go:231)). A consumed Close deletes the sender generation record ([sync_conn_gen.go:179](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_gen.go:179)); absence is indistinguishable from cold start, first sight, or generation-map overflow. If Close(A) is followed by Open(B), the map instead contains B’s generation while the copied value is still A.

   Therefore key presence/absence cannot decide whether the callback should omit A, send a legitimate untracked row, or accidentally stamp A after B. The design needs durable copy-time identity binding—e.g. key plus publication ID and generation—or a Close tombstone ledger. The raw startup deletion in finding 1 is additionally a close-less mutation, so the stated “Go-consumed Close is the only window” claim is currently false.

9. **BLOCKER — Failed-delete omission overflow has no authoritative recovery source.**

   `plan.md@db492cf1f:299–303` says overflow arms latch plus debt, but the retained authoritative retry is `doBulkSync`, which scans the dirty mirror ([sync_bulk.go:95](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go:95)). That mirror contains precisely the stale rows whose delete results overflowed.

   The helper’s current table export is only a sequence of Open deltas ([export.rs:143](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/export.rs:143)); it has no BulkStart/BulkEnd absence reconciliation and excludes peer-synced origins. Thus “helper TABLE-TRUTH export,” retained elsewhere in §5, is not currently the authoritative `doBulkSync` source.

   Debt guarantees acknowledgement of the bytes sent; it cannot make a dirty source authoritative. The plan must select one recovery source, make it include every valid promoted/local row while excluding aliases and stale mirror rows, and wrap it in full bulk absence-reconciliation semantics.

10. **BLOCKER — The prime-REQUEST old-peer fallback does not guarantee a cold-prime.**

   An old peer ignores prime-REQUEST, so recovery depends on that peer observing a full-disconnect edge. Its cold-prime latch is armed only when both local connection slots are empty at installation ([sync_conn.go:244](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:244)); full teardown state is reached only when both become nil ([sync_conn.go:480](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go:480)).

   Receiver-local fencing does not prove the old peer observed that state. It can reconnect one fabric between the two disconnect callbacks—the dual-slot race already documented at `plan.md:968–995`—and therefore never arm its outbound cold-prime. The fallback needs remote quiescence confirmation or a specified refusal/quiet interval proven to force both remote slots empty before reconnect is accepted.

11. **MAJOR — P2 ownership remains contradictory.**

   §4.0.2 places P2 inside the helper (`plan.md@db492cf1f:304–307`), while retained §5 places its read-compare-delete on Go’s serialized receiver loop under `SessionStore` locking (`plan.md:1919–1933`). Pick one ownership model and remove the other text.

   It also needs an explicit publication exception: purging a receiver-local sync-imported alias must not emit a Close back toward the canonical owner. The existing helper deletion shape is intentionally local-only at [delete_synced.rs:20](/home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/delete_synced.rs:20).

Final adjudication: PATH A remains the adjudicated substrate, and I found no new evidence against the option-(a) core. The debt correction—record before End, discharge only on the matching ACK—is sound. But blocker-rated gaps remain in Rules 1–7, the known-stale/authoritative-recovery consequence map, old-peer re-prime, and alias discipline. These are fixable within PATH A, so this is not `PLAN-KILL`, but v15.21 is not plan-ready.
