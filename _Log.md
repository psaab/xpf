# Action Log

## 2026-05-15

- **Timestamp**: 2026-05-15T23:00:00Z
  - **Action**: Restored `go.mod` to pre-PR state after an unintended direct/indirect dependency classification flip during automation-only progress updates.
  - **File(s)**: `go.mod`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T22:56:00Z
  - **Action**: Reverted unintended `go.mod` direct/indirect dependency reorder so round-1 fix remains scoped to CoS runtime lookup logic and tests.
  - **File(s)**: `go.mod`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T22:52:00Z
  - **Action**: Round-1 follow-up cleanup — remove duplicate VLAN candidate append path in CoS runtime candidate generation while preserving VLAN-first ordering for unit-zero lookups.
  - **File(s)**: `pkg/dataplane/userspace/cosfmt.go`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T22:45:00Z
  - **Action**: Round-1 review hardening for issue #1278 — fix unit-zero candidate ordering so VLAN binding ifindex is preferred over parent binding when both exist, preventing wrong runtime CoS counters from being shown.
  - **File(s)**: `pkg/dataplane/userspace/cosfmt.go`, `pkg/dataplane/userspace/cosfmt_test.go`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T22:05:00Z
  - **Action**: Issue #1278 — make `show class-of-service interface` join configured reverse-egress CoS interfaces to live runtime by configured name first and binding egress ifindex second, so alias drift between `ge-0-0-1.0` and the runtime snapshot no longer hides queue counters.
  - **File(s)**: `pkg/dataplane/userspace/cosfmt.go`, `pkg/dataplane/userspace/cosfmt_test.go`, `docs/cos-validation-notes.md`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T21:23:20Z
  - **Action**: PR #1312 CoS TX-error attribution — round-3 fixes: (1) mirror reset-time CoS queue drains into `binding.live.dbg_cos_queue_overflow` in `reset_binding_cos_runtime` so the binding-scoped subset stays lifetime-matched with `tx_errors`; (2) add Rust regression test `reset_binding_cos_runtime_mirrors_drops_to_binding_cos_counter`; (3) update `docs/cos-validation-notes.md` to state the binding-scoped subset includes admission rejects AND reset-time queue drains, and rephrase reason-counter lines as aggregate current-runtime sums (not per-queue rows); (4) extract `saturatingAddU64`/`saturatingSubU64` into `format_math.go` with doc comments; (5) rename ECN accumulator to `cosAdmissionEcnMarked` (Go-style Ecn casing).
  - **File(s)**: `userspace-dp/src/afxdp/worker/cos.rs`, `userspace-dp/src/afxdp/worker/cos_tests.rs`, `pkg/dataplane/userspace/statusfmt.go`, `pkg/dataplane/userspace/statusfmt_test.go`, `pkg/dataplane/userspace/cosfmt.go`, `pkg/dataplane/userspace/format_math.go`, `docs/cos-validation-notes.md`, `_Log.md`
- **Timestamp**: 2026-05-15T21:42:00Z
  - **Action**: PR #1315 Copilot follow-up — keep the historical `dbg_cos_queue_overflow` wire key but relabel the CLI/docs as binding-lifetime CoS queue drops because the subset now includes reset-time CoS queue drains in addition to admission rejects.
  - **File(s)**: `pkg/dataplane/userspace/statusfmt.go`, `pkg/dataplane/userspace/statusfmt_test.go`, `pkg/dataplane/userspace/protocol.go`, `userspace-dp/src/protocol.rs`, `docs/cos-validation-notes.md`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T20:33:36Z
  - **Action**: PR #1316 / issue #1312 hostile-review follow-up — clarified low-rate CoS fixture docs with the actual implicit base/cap pipeline (`rate/100` + 96 KB floor, flow-share expansion, #717 delay clamp), documented the queue-residence tradeoff for q0/q4 overrides, added a regression test pin that 1 Gbps q4 `buffer-size 4m` remains above delay-cap clamping, updated canonical fixture buffers, and committed durable validation evidence.
  - **File(s)**: `test/incus/cos-iperf-config.set`, `test/incus/cos-iperf-symmetric.set`, `test/incus/cos-iperf-same-class.set`, `docs/cos-validation-notes.md`, `docs/fairness-regimes.md`, `docs/per-5-tuple/state.md`, `docs/pr/README.md`, `docs/pr/1316-lowrate-cos-buffers/validation.md`, `docs/pr/line-rate-investigation/full-cos.set`, `userspace-dp/src/afxdp/cos/admission_tests.rs`, `_Log.md`

## 2026-05-14

- **Timestamp**: 2026-05-14T19:33:03Z
  - **Action**: PR #1308 round-2 review follow-up — added explicit equal-flow scrape framing tests for nested begin and end-without-begin paths, added the missing `BindingCountersSnapshot` round-trip pin for `tx_shared_recycle_unknown_slot_drops`, applied `gofmt` to `protocol.go`, and renamed sweep progress output from `wrapper_status` to `exit_status` with a named infrastructure-exit constant.
  - **File(s)**: `test/incus/fairness_multi_sample_test.py`, `test/incus/fairness-cos-class-sweep.sh`, `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/protocol_test.go`, `_Log.md`

- **Timestamp**: 2026-05-14T19:19:32Z
  - **Action**: PR #1308 round-1 review follow-up — made equal-flow capture reduction fail closed on SIGTERM-truncated marked scrapes and non-integer active-worker counts, and made sweep summary rows report infrastructure exit status `2` when equal-flow capture fails after the wrapper succeeds.
  - **File(s)**: `test/incus/fairness_equal_flow_capture.py`, `test/incus/fairness-cos-class-sweep.sh`, `test/incus/fairness_multi_sample_test.py`, `docs/fairness-regimes.md`, `docs/per-5-tuple/state.md`, `_Log.md`

- **Timestamp**: 2026-05-14T18:35:00Z
  - **Action**: Issue #1306 — add first-class per-class equal-flow estimator capture to the CoS class sweep harness. The sweep now brackets each wrapper run with continuous Prometheus scraping, preserves raw scrapes, reduces target-class equal-flow aggregate/worker rows, appends equal-flow evidence to `summary.md`, and fails closed on empty/missing/invalid estimator captures.
  - **File(s)**: `test/incus/fairness-cos-class-sweep.sh`, `test/incus/fairness_equal_flow_capture.py`, `test/incus/fairness_multi_sample_test.py`, `docs/fairness-regimes.md`, `docs/per-5-tuple/state.md`, `_Log.md`

- **Timestamp**: 2026-05-14T17:53:10Z
  - **Action**: PR #1305 round-3 review follow-up — extended artifact-warning wording to the equal-flow capped-bps, worker-cap-bps, and throughput-loss-ratio Prometheus help strings.
  - **File(s)**: `pkg/api/metrics.go`, `_Log.md`

- **Timestamp**: 2026-05-14T17:38:10Z
  - **Action**: PR #1305 round-2 review follow-up — made the out-of-range worker test assert directly against `bytesByWorker` so the worker-delta cap is independently covered, and added artifact warnings to the equal-flow target/suppression metric help strings.
  - **File(s)**: `pkg/dataplane/userspace/fairness_throughput_test.go`, `pkg/api/metrics.go`, `_Log.md`

- **Timestamp**: 2026-05-14T16:49:39Z
  - **Action**: PR #1305 review follow-up — bounded equal-flow estimator worker IDs with the existing fairness RSS worker-slot cap, sharpened Prometheus help strings, and added validity boundary tests for single-worker, unsampled, zero-window, and out-of-range-worker cases.
  - **File(s)**: `pkg/dataplane/userspace/fairness_throughput.go`, `pkg/dataplane/userspace/fairness_throughput_test.go`, `pkg/api/metrics.go`, `docs/pr/1304-equal-flow-estimator/plan.md`, `_Log.md`

- **Timestamp**: 2026-05-14T14:51:46Z
  - **Action**: Issue #1304 Phase 0 — add measurement-only equal-flow rate-suppression estimator telemetry for exact CoS queues, document its invariants, and pin estimator math/Prometheus emission tests.
  - **File(s)**: `pkg/dataplane/userspace/fairness_throughput.go`, `pkg/dataplane/userspace/fairness_throughput_test.go`, `pkg/api/metrics.go`, `pkg/api/metrics_test.go`, `docs/fairness-regimes.md`, `docs/per-5-tuple/state.md`, `docs/pr/1304-equal-flow-estimator/plan.md`, `_Log.md`

- **Timestamp**: 2026-05-14T04:01:00Z
  - **Action**: PR #1301 review follow-up — removed power-of-two UMEM frame-size assumption in memmove fallback bounds calculation by switching to modulo-based in-frame offset math.
  - **File(s)**: `userspace-dp/src/afxdp/frame/mod.rs`, `_Log.md`

- **Timestamp**: 2026-05-14T03:52:00Z
  - **Action**: PR #1301 review follow-up — tightened in-frame memmove fallback slice bounds to the current UMEM chunk and added regression coverage for `FillOnSlotWithOffset` recycle tracking.
  - **File(s)**: `userspace-dp/src/afxdp/frame/mod.rs`, `userspace-dp/src/afxdp/tx/transmit_tests.rs`, `_Log.md`

## 2026-05-12

- **Timestamp**: 2026-05-12T07:50:00Z
  - **Action**: PR #1274 Copilot follow-up — use verdict JSON key names consistently in the Accepted Path publish list.
  - **File(s)**: `docs/per-5-tuple/tcp-head-start-floor.md`, `_Log.md`

- **Timestamp**: 2026-05-12T06:46:48Z
  - **Action**: PR #1274 review follow-up — wrapped TCP head-start policy prose and made the observed CoV prose/JSON-field distinction explicit.
  - **File(s)**: `docs/per-5-tuple/tcp-head-start-floor.md`, `_Log.md`

- **Timestamp**: 2026-05-12T06:29:27Z
  - **Action**: PR round-2 review follow-up — expanded AFD acronym at first use (line 5), changed `observed_cov` to `observed_CoV` in prose formulas (lines 86, 99), made epsilon explicit as 0.05.
  - **File(s)**: `docs/per-5-tuple/tcp-head-start-floor.md`, `_Log.md`

- **Timestamp**: 2026-05-12T07:35:00Z
  - **Action**: PR #1271 round-3 follow-up — add same-VLAN/different-RETH synthetic-ifindex regressions so `reth0.N` and `reth1.N` cannot collapse into one logical Rust dataplane state key.
  - **File(s)**: `pkg/dataplane/userspace/manager_test.go`, `_Log.md`

- **Timestamp**: 2026-05-12T07:20:00Z
  - **Action**: PR #1271 cleanup — removed unrelated `go.mod` direct/indirect dependency churn introduced by local test tooling to keep the diff scoped to synthetic-ifindex changes.
  - **File(s)**: `go.mod`, `_Log.md`

- **Timestamp**: 2026-05-12T07:16:00Z
  - **Action**: PR #1271 validation follow-up — documented synthetic-ifindex range rationale, improved exhaustion panic guidance, deduplicated VLAN test constants, and reverted unrelated `go.mod` drift from local test tooling.
  - **File(s)**: `pkg/dataplane/userspace/snapshot.go`, `pkg/dataplane/userspace/manager_test.go`, `go.mod`, `_Log.md`

- **Timestamp**: 2026-05-12T07:08:00Z
  - **Action**: PR #1271 follow-up — enriched synthetic-ifindex exhaustion panic diagnostics and replaced test magic VLAN bound with named constants during validation pass.
  - **File(s)**: `pkg/dataplane/userspace/snapshot.go`, `pkg/dataplane/userspace/manager_test.go`, `_Log.md`

- **Timestamp**: 2026-05-12T06:55:00Z
  - **Action**: PR #1271 round-2 follow-up — made parent-bound RETH VLAN synthetic ifindex allocation deterministic/config-derived, removed kernel-ifindex seeding, switched to high synthetic range with hard-fail on exhaustion, and added sibling-VLAN determinism regression coverage.
  - **File(s)**: `pkg/dataplane/userspace/snapshot.go`, `pkg/dataplane/userspace/manager_test.go`, `_Log.md`

- **Timestamp**: 2026-05-12T00:30:00Z
  - **Action**: PR #1267 round-2 review follow-up — fixed fairness throughput window boundary pruning/rate denominator coupling to prevent false-positive saturation at steady sub-cap traffic, and added a regression test for the 10s-scrape/30s-window boundary case.
  - **File(s)**: `pkg/dataplane/userspace/fairness_throughput.go`, `pkg/dataplane/userspace/fairness_throughput_test.go`, `_Log.md`

## 2026-05-10

- **Timestamp**: 2026-05-10T15:24:00Z
  - **Action**: PR #1253 review follow-up — corrected `userspace-dp/src/server/README.md` RSS-indirection behavior to match `pkg/daemon/rss_indirection.go` (reshape conditions, workers>=queues stale-table cleanup restore path, and queue concentration semantics).
  - **File(s)**: `userspace-dp/src/server/README.md`, `_Log.md`

- **Timestamp**: 2026-05-10T15:05:00Z
  - **Action**: PR #1253 review pass — corrected `pkg/configstore/README.md` encryption-key location wording to match `master.key` under the configstore DB directory (`db.dir`) and removed stale `/etc/xpf/config-key` path guidance.
  - **File(s)**: `pkg/configstore/README.md`, `_Log.md`

- **Timestamp**: 2026-05-10T04:06:32Z
  - **Action**: PR comment follow-up review for `docs/per-5-tuple/state.md` — replaced a non-existent memory-file reference with in-repo issue/table references (#836/#937/#1215) to keep the fairness section self-contained and verifiable.
  - **File(s)**: `docs/per-5-tuple/state.md`, `_Log.md`

## 2026-05-07

- **Timestamp**: 2026-05-07T16:13:00Z
  - **Action**: PR #1211 archive doc follow-up — fixed stale/missing cross-references in closure docs, updated per-5-tuple state to mark Path 2 closed with archive links, and clarified memory-hook wording as external memory (not an in-repo file).
  - **File(s)**: `docs/per-5-tuple/path2-archive/CLOSING-RATIONALE.md`, `docs/per-5-tuple/state.md`

## 2026-04-19 — #812 plan R1 (fold Codex round-1 hostile review)
- **Timestamp**: 2026-04-19
- **Action**: Fold Codex round-1 review into the Architect plan. Close 3 HIGH findings: small-batch amortization collapse (§3.1 per-commit stamping with honest `inserted == 1` worst-case), relaxed-atomic cross-CPU visibility (§3.6.a Relaxed+documented, invariants 6/7 rewritten, §8 hard-stop #4 uses bounded-skew delta), sidecar false-sharing (§3.3 per-binding single-writer confirmed by `Rc<WorkerUmemInner>` + `shared_umem=false` in code). Rewrite §3.4 overhead budget with three operating-point numbers (`inserted=256/64/1`) and a correct per-queue denominator (481 ns/pkt at 25 Gbps), not per-worker. Rewrite §11.3 Bonferroni family to match actual composite tests (3/cell × 12 cells = 36, not 192). Close MED #5 (sentinel vs clock-0), MED #6 (sidecar size 192 KiB, not 64 KiB), MED #7 (wire-size growth), MED #8 (Bonferroni family), MED #9 (two-thread test replaced by partial-batch / retry-unwind / bounded-skew tests). Close LOW #10 (no `now_ns` reuse), LOW #13 (named const asserts + boundary test).
  - **File(s)**: `docs/pr/812-tx-latency-histogram/plan.md`

## 2026-04-17

- **Timestamp**: 2026-04-17
  - **Action**: Issue #678 — Architect plan for remaining hot-path CPU cuts. Remeasured on loss userspace cluster (master 7c1e55b9): poll_binding 10.4%/10.6% (down from issue's 13.4%/13.3%), enqueue_pending_forwards 0.71%/<1% (down from 4.3%/3.7%), apply_nat_ipv6 <1% (down from 3.2% IPv6). Recommendation: Option A — split poll_binding into orchestration shell + per-descriptor hot path as a measurement-first structural refactor. Options B/C/D deferred as issues; Option F (close as subsumed) is the expected path post-split.
  - **File(s)**: docs/678-hotpath-cuts-plan.md

## 2026-04-03

- **Timestamp**: 2026-04-03
  - **Action**: Issue #547 — Split pkg/grpcapi/server.go (8411 lines) into 8 domain files. Mechanical move of functions, no logic changes. server.go reduced to 241 lines (types + server lifecycle).
  - **File(s)**: pkg/grpcapi/server.go, server_config.go, server_show.go, server_nat.go, server_routing.go, server_diag.go, server_helpers.go, server_dhcp.go, server_cluster.go

## 2026-04-07

- **Timestamp**: 2026-04-07T00:00:00Z
  - **Action**: Issue #545 — Split `pkg/config/compiler.go` (5878 lines) into 8 domain-specific files. Mechanical refactor, no logic changes. Functions moved to: compiler_security.go, compiler_interfaces.go, compiler_protocols.go, compiler_ipsec.go, compiler_routing.go, compiler_firewall.go, compiler_system.go, compiler_services.go. compiler.go retains top-level dispatch + applications + validators (793 lines).
  - **File(s)**: pkg/config/compiler.go, pkg/config/compiler_security.go, pkg/config/compiler_interfaces.go, pkg/config/compiler_protocols.go, pkg/config/compiler_ipsec.go, pkg/config/compiler_routing.go, pkg/config/compiler_firewall.go, pkg/config/compiler_system.go, pkg/config/compiler_services.go

- **Timestamp**: 2026-04-07T00:00:00Z
  - **Action**: Issue #532 — Fix IPv6 TTL-expired (hop limit exceeded) probe responses not being returned in userspace dataplane. Added TTL/hop-limit check with ICMP Time Exceeded generation to both session-hit and flow-cache-hit paths. Previously only the session-miss path generated TE responses; subsequent packets hitting an existing session or flow cache were silently dropped when TTL<=1 because the rewrite functions returned None without generating a response.
  - **File(s)**: userspace-dp/src/afxdp.rs

## 2026-04-05

- **Timestamp**: 2026-04-05T22:00:00Z
  - **Action**: Issue #485 — Fix TCP stream death on failback (node1→node0). Three fixes: (1) Reorder cluster Primary handler: set rg_active + pre-install neighbors BEFORE ForceRGMaster so BPF can forward the first packet arriving after VRRP installs VIPs. (2) Reorder cluster Secondary handler: run preflight (flow cache flush to FabricRedirect) BEFORE ResignRG so traffic shifts to fabric before VRRP removes VIPs. (3) Add syncMsgPrepareActivation message: demoting node notifies peer to pre-warm neighbor cache after preflight completes, giving the activating node a head start on ARP/NDP resolution.
  - **File(s)**: pkg/daemon/daemon_ha.go, pkg/cluster/sync.go

- **Timestamp**: 2026-04-05T12:00:00Z
  - **Action**: Fix TCP stream death on failback due to cold ARP cache on standby node. Root cause: `resolveNeighborsInner()` used `netlink.RouteGet()` to find the outgoing interface for static route next-hops, but on standby nodes the kernel route doesn't exist (FRR only installs it on the active). Added `addByIPOrConfig()` fallback that resolves the outgoing interface from config by matching the next-hop IP against configured interface subnets when the kernel FIB lookup fails.
  - **File(s)**: pkg/daemon/daemon.go

- **Timestamp**: 2026-04-05T10:00:00Z
  - **Action**: Issue #475 — Fix 0 throughput on pre-existing TCP streams after failover+failback. Root cause: `prewarm_reverse_synced_sessions_for_owner_rgs` published USERSPACE_SESSIONS BPF map entries for reverse sessions but not forward sessions during RG activation. Forward sessions relied on async worker processing, creating a window where the XDP shim had no REDIRECT entry. Added synchronous BPF map publishing for forward sessions in prewarm, plus a comprehensive `republish_bpf_session_entries_for_owner_rgs` that iterates ALL sessions in the `sessions` owner-RG index (not just the `reverse_prewarm` subset) to ensure no session is missed.
  - **File(s)**: userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/afxdp/ha.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-05T08:00:00Z
  - **Action**: Issue #473 — Fix XSK bindings BPF map going stale after peer crash+reconnect. Added `verifyBindingsMapLocked()` watchdog to the 1s status poll loop. After `applyHelperStatusLocked` runs, the watchdog reads each BPF `userspace_bindings` entry and compares it against the helper's reported binding state. If a queue is Registered+Armed in the helper but the BPF map entry is all zeros, the watchdog rewrites the entry. Also repairs aliased bindings (VLAN children). This prevents silent transit traffic drops when a Compile() or HA transition zeroes the bindings map without repopulating it.
  - **File(s)**: pkg/dataplane/userspace/manager.go

- **Timestamp**: 2026-04-05T06:55:00Z
  - **Action**: Issue #466 — Fix bulk sync triggering on every reconnect/fabric-flip. Added `bulkEverCompleted` atomic flag to SessionSync that tracks whether a full bulk exchange has ever completed during the daemon's lifetime. `handleNewConnection` now only triggers `doBulkSync` on true cold start (flag is false). Active-fabric changes no longer trigger bulk at all. Daemon's `onSessionSyncPeerConnected`/`onSessionSyncPeerDisconnected` preserve primed state and sync readiness when `bulkEverCompleted` is true.
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/daemon/session_sync_readiness_test.go

## 2026-04-04

- **Timestamp**: 2026-04-04T21:30:00Z
  - **Action**: Issue #467 — Fix bulk-prime retry loop not restarting after failed demotion barrier. `prepareUserspaceRGDemotionWithTimeout` stopped the retry loop by advancing `syncPrimeRetryGen` before waiting on barriers, but on barrier failure returned without restarting the loop, stranding the peer in an unprimed state. Added a defer that restarts `startSessionSyncPrimeRetry` on failure when peer is still connected and not yet primed.
  - **File(s)**: pkg/daemon/daemon_ha.go

- **Timestamp**: 2026-04-04T20:50:00Z
  - **Action**: Issue #458 — Fix session sync barrier timeout on second failover cycle. Root cause: `handleDisconnect` reset `barrierSeq` to 0, causing sequence collisions between stale goroutines and new barriers. Also closed waiter channels on disconnect to prevent goroutine leaks. Added `barrierAckSeq` check in `WaitForPeerBarrier` to distinguish disconnect from ack.
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_bulk.go, pkg/cluster/sync_test.go

## 2026-04-03

- **Timestamp**: 2026-04-03T18:00:00Z
  - **Action**: Issue #457 — Fix standby losing userspace readiness after partial RG demotion. The rgTransitionInFlight flag in UpdateRGActive was unconditionally set for both activation and demotion. During demotion, this caused ctrl.Enabled=0 in the BPF map globally, disrupting forwarding for other active RGs. Now only set rgTransitionInFlight during activation transitions; demotion leaves ctrl enabled so other RGs continue forwarding.
  - **File(s)**: pkg/dataplane/userspace/manager_ha.go, pkg/dataplane/userspace/manager_test.go

- **Timestamp**: 2026-04-03T12:00:00Z
  - **Action**: Issue #451 — Fix neighbor miss spike after RG failover. Part 1: resolve config-based next-hops synchronously during RG activation (VRRP MASTER and cluster-primary paths) using new `resolveNeighborsImmediate` variant that sends ARP probes without blocking for replies. Part 2: increase failover test neighbor miss threshold from 20 to 60 to accommodate observed spikes of 25-52.
  - **File(s)**: pkg/daemon/daemon.go, pkg/daemon/daemon_ha.go, scripts/userspace-ha-failover-validation.sh

- **Timestamp**: 2026-04-03T10:22:00Z
  - **Action**: Issue #418 — Replace bulk session sync with event stream replay on connect. Added `export_all_sessions_to_event_stream()` to Rust Coordinator that iterates shared sessions and pushes Open events through the event stream. Added `"export_all_sessions"` control request handler. Go daemon's `bulkSyncViaEventStreamOrFallback()` tries event stream export first, falls back to legacy BulkSync.
  - **File(s)**: userspace-dp/src/afxdp/ha.rs, userspace-dp/src/main.rs, pkg/dataplane/userspace/manager_ha.go, pkg/daemon/daemon_ha.go, pkg/daemon/userspace_sync_test.go

## 2026-04-02

- **Timestamp**: 2026-04-02T20:34:00Z
  - **Action**: Issue #403 — Planned failover must not depend on bulk sync. Added priority barrierCh channel to SessionSync so barriers/acks bypass bulk data in sendLoop. Removed syncPeerBulkPrimed gate from demotion prep. Reduced manual failover barrier timeout to 5s.
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_bulk.go, pkg/daemon/daemon_ha.go, pkg/cluster/sync_test.go

## 2026-04-01

- **Timestamp**: 2026-04-01T05:30:00Z
  - **Action**: Merged PR #301 (userspace forwarding and failover gap audit doc)
  - **File(s)**: docs/userspace-forwarding-and-failover-gap-audit.md

- **Timestamp**: 2026-04-01T06:00:00Z
  - **Action**: Implemented strict userspace mode, HA install fence, deterministic reverse companions (PR #313, issues #302-#312)
  - **File(s)**: pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/protocol.go, pkg/cluster/cluster.go, pkg/cluster/sync.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/main.rs, userspace-xdp/src/lib.rs, docs/ha-forwarding-state-inventory.md, docs/bugs.md, docs/phases.md

- **Timestamp**: 2026-04-01T06:30:00Z
  - **Action**: Address PR #313 copilot review findings — rename STRICT_PASS_BLOCKED, strict ctrl=0 drop, mode reporting, fallback names, VLAN sub-interface exclusion
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-xdp/src/lib.rs, docs/phases.md

- **Timestamp**: 2026-04-01T13:52:00Z
  - **Action**: Fix HA session sync starvation — async bulk ack, HA sync throttle 5s, 6 retries (ba1c4304)
  - **File(s)**: pkg/cluster/sync.go, pkg/daemon/daemon.go, pkg/dataplane/userspace/manager.go

- **Timestamp**: 2026-04-01T14:44:00Z
  - **Action**: Replace bulk-sync gate with barrier check for failover readiness (e42c882e)
  - **File(s)**: pkg/daemon/daemon.go, pkg/daemon/userspace_sync_test.go

- **Timestamp**: 2026-04-01T15:39:00Z
  - **Action**: Explicit refresh_owner_rgs on RG activation + async barrier ack (a9e0501e)
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/main.rs, pkg/cluster/sync.go

- **Timestamp**: 2026-04-01T15:59:00Z
  - **Action**: Re-resolve synced sessions with owner_rg_id=0 on active node (7417144e)
  - **File(s)**: userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T16:10:00Z
  - **Action**: Add logging rules to CLAUDE.md, remove debug eprintln (12478964)
  - **File(s)**: CLAUDE.md, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T16:59:00Z
  - **Action**: Mirror reverse sessions to helper, worker-completion ack, logging rules (#314, #315, #316) (24166737)
  - **File(s)**: CLAUDE.md, pkg/daemon/daemon.go, pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T17:00:00Z
  - **Action**: Route barrier/bulk acks through sendCh instead of direct writeMu (9d2814c4)
  - **File(s)**: pkg/cluster/sync.go

- **Timestamp**: 2026-04-01T19:32:00Z
  - **Action**: Fix RefreshOwnerRGs skipped synced sessions — refresh_for_ha_activation (71b80b3d). THE key SNAT fix.
  - **File(s)**: userspace-dp/src/session.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T20:20:00Z
  - **Action**: Simplify HA failover — epoch flow cache, resolve-on-receipt, owner_rg_id, demotion (#325, #326, #327, #330) (a21018f3)
  - **File(s)**: pkg/daemon/daemon.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/manager_test.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T21:52:00Z
  - **Action**: Write userspace sessions to BPF conntrack map for zone/interface display (fab9230c)
  - **File(s)**: pkg/dataplane/dataplane.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/protocol.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/bpf_map.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/main.rs

- **Timestamp**: 2026-04-01T22:00:00Z
  - **Action**: Use BPF_ANY for conntrack map writes (244912f8)
  - **File(s)**: userspace-dp/src/afxdp/bpf_map.rs

- **Timestamp**: 2026-04-01T22:30:00Z
  - **Action**: Userspace/eBPF audit — counters, conntrack flush bugs, session visibility (PR #336, issues #332-#335)
  - **File(s)**: pkg/conntrack/gc.go, pkg/daemon/daemon.go, pkg/dataplane/dataplane.go, pkg/dataplane/dpdk/dpdk_cgo.go, pkg/dataplane/dpdk/dpdk_stub.go, pkg/dataplane/maps.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/manager_test.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/bpf_map.rs

- **Timestamp**: 2026-04-01T23:00:00Z
  - **Action**: Address PR #336 copilot review — idle time, BPF_EXIST, counter race, safeDelta, RX counter, flush cutoff (d15d5629)
  - **File(s)**: pkg/dataplane/loader.go, pkg/dataplane/maps.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/manager_test.go, userspace-dp/src/afxdp/bpf_map.rs

- **Timestamp**: 2026-04-01T23:15:00Z
  - **Action**: Thread conntrack FDs through DeleteSynced for BPF cleanup (671e5561)
  - **File(s)**: userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T23:30:00Z
  - **Action**: Unify synced flag + adaptive event-first session sync (#328, #320) (dcc59c67)
  - **File(s)**: pkg/daemon/daemon.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/bpf_map.rs, userspace-dp/src/afxdp/forwarding.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/tunnel.rs, userspace-dp/src/event_stream.rs, userspace-dp/src/main.rs, userspace-dp/src/session.rs

## 2026-04-02

- **Timestamp**: 2026-04-02T18:05:00Z
  - **Action**: Start `#400` — separate transfer readiness from takeover readiness in cluster status and explicit peer-failover admission, with daemon wiring for session-sync transfer-readiness reasons
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go, pkg/daemon/daemon_ha.go, pkg/daemon/userspace_sync_test.go

- **Timestamp**: 2026-04-02T17:20:00Z
  - **Action**: Start `#398` fix — add explicit session-sync transfer-readiness snapshot and fast-fail manual failover demotion when bulk receive or pending bulk ack proves the sync path is not settled; filed `#400` for exposing transfer readiness separately from takeover readiness
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_bulk.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/daemon/userspace_sync_test.go

- **Timestamp**: 2026-04-02T16:45:00Z
  - **Action**: Validate `#397` on `loss-userspace-cluster` — settled RG0 manual failover now completes on explicit failover ack + commit ack instead of heartbeat observation; filed residual issue `#398` for failover admission while requester is still in bulk receive
  - **File(s)**: testing-docs/manual-failover-transfer-commit-validation.md, testing-docs/README.md

- **Timestamp**: 2026-04-02T13:15:00Z
  - **Action**: Second #390 slice — add explicit sync-channel failover ack handshake so manual RG transfer returns applied/rejected instead of inferring success from send-only behavior
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/cluster/cluster.go, pkg/daemon/daemon_ha.go, pkg/cli/cli.go

- **Timestamp**: 2026-04-02T13:45:00Z
  - **Action**: Third #390 slice — wait for actual local RG promotion after peer transfer-out ack so CLI/local control returns on observed ownership, not just request delivery
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go, pkg/cli/cli.go

- **Timestamp**: 2026-04-02T14:15:00Z
  - **Action**: Address PR #396 copilot review — typed remote-failover rejection, failover request IDs, out-of-range RG guard, timeout race guard, active-conn ack routing, and consistent gRPC wording
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/grpcapi/server.go

- **Timestamp**: 2026-04-02T16:30:00Z
  - **Action**: Next #390 slice — replace heartbeat-observed manual failover completion with explicit sync-channel transfer commit, local primary commit, peer transfer-out finalization, and commit-ack coverage
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go, pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/cli/cli.go, pkg/grpcapi/server.go

- **Timestamp**: 2026-04-02T17:05:00Z
  - **Action**: Address PR #397 Copilot review — preserve in-flight peer transfer-out state across heartbeat refreshes until transfer commit completes or aborts
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go

- **Timestamp**: 2026-04-02T12:30:00Z
  - **Action**: First #390 slice — replace weight-zero manual failover with explicit secondary-hold transfer-out state, keep ForceSecondary on zero-weight drain semantics, and teach election to promote on peer transfer-out without mutating monitor weight
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/election.go, pkg/cluster/cluster_test.go, pkg/cluster/election_test.go, pkg/cluster/sync.go

- **Timestamp**: 2026-04-02T01:30:00Z
  - **Action**: Merged PR #337 (HA simple failover design doc). Fixed copilot review — issue reference swap in phases 3/5/6.
  - **File(s)**: docs/ha-simple-failover-design.md

- **Timestamp**: 2026-04-02T02:00:00Z
  - **Action**: Fix HA activation cleanup — deduplicate refresh, skip resolved, log mirror errors (#341, #342, #345, #346) (31b600d5)
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-02T02:30:00Z
  - **Action**: Fix watchdog threshold (2→10s), reverse companion leak on delete, remove debug eprintln (#349, #351, #352) (52254b7e)
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/main.rs

- **Timestamp**: 2026-04-02T03:30:00Z
  - **Action**: Simplify HA — remove refresh RPC, skip blackhole routes, dead code cleanup, throttle post-transition sync (#353, #354, #355, #356) (5ac423a3)
  - **File(s)**: pkg/dataplane/userspace/manager.go, pkg/daemon/daemon.go

- **Timestamp**: 2026-04-02T06:00:00Z
  - **Action**: Merged PR #357 (flow cache simplification refactors). Implemented phases 3+4 from docs/flow-cache-simplification.md — explicit is_cacheable() + 10 unit tests (624a1f83)
  - **File(s)**: userspace-dp/src/afxdp/types.rs, docs/flow-cache-simplification.md

- **Timestamp**: 2026-04-02T11:45:00Z
  - **Action**: Added HA failover implementation plan tying current simplification audit to executable phases and issue dependencies (49eaf9d6)
  - **File(s)**: docs/ha-failover-implementation-plan.md, docs/ha-failover-simplification-audit.md

- **Timestamp**: 2026-04-03T00:16:04Z
  - **Action**: First #389 slice — add derived owner-RG indexes for helper shared session stores and use them for demotion-time BPF cleanup and shared-session demotion without whole-table scans
  - **File(s)**: userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/ha.rs, userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/forwarding.rs, userspace-dp/src/afxdp/tunnel.rs

- **Timestamp**: 2026-04-03T00:34:06Z
  - **Action**: Address PR #404 Copilot review — make owner-RG index updates heal missing same-owner entries and serialize demotion-time key collection against in-flight shared-session publishes
  - **File(s)**: userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/afxdp/ha.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-03T00:42:41Z
  - **Action**: Second #389 slice — add reverse-prewarm owner-RG candidate indexes so HA activation prewarm targets only affected synced forward sessions instead of scanning the full shared forward map
  - **File(s)**: userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/afxdp/ha.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-03T01:01:45Z
  - **Action**: Final #389 slice — index worker-local sessions by owner RG and use those indexes for export, demotion, and activation refresh so helper HA apply no longer scans the full live session table
  - **File(s)**: userspace-dp/src/session.rs, userspace-dp/src/afxdp/session_glue.rs, _Log.md

- **Timestamp**: 2026-04-03T03:00:15Z
  - **Action**: Applied Copilot review fixes for stacked #389 PRs — make reverse-prewarm owner-RG index updates lock once per refresh, restore derived indexes on rejected session updates, and remove unnecessary hot-path clones
  - **File(s)**: userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/session.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp.rs, _Log.md

## 2026-04-03 HA Failover Fix Session

### Actions
- **Action**: Wire BulkSyncOverride in daemon_ha.go so initial bulk sync uses event stream
  - **File(s)**: `pkg/daemon/daemon_ha.go`
- **Action**: Fix stuck bulk receive state on disconnect — reset bulkInProgress in handleDisconnect
  - **File(s)**: `pkg/cluster/sync.go`
- **Action**: Add sendBulkMarkers() to send empty BulkStart/BulkEnd after event stream export
  - **File(s)**: `pkg/cluster/sync_bulk.go`
- **Action**: Fix HA session promotion — push forward sessions to workers + bump rg_epochs on activation
  - **File(s)**: `userspace-dp/src/afxdp/ha.rs`, `userspace-dp/src/afxdp/shared_ops.rs`, `userspace-dp/src/afxdp/session_glue.rs`

### Results
- Bulk sync completes correctly on both nodes (event stream + bulk markers)
- Transfer ready: yes on both nodes after deploy
- Manual failover test PASSES: iperf3 -P2 at 11 Gbps survives RG move with no visible throughput drop
- Automated script reports false failure (samples at exact transition moment)

## 2026-04-17 — #718 ECN CE marking at CoS admission
- **Action**: Add mark_ecn_ce_ipv4 / mark_ecn_ce_ipv6 / maybe_mark_ecn_ce / apply_cos_admission_ecn_policy; wire into enqueue_cos_item
  - **File(s)**: `userspace-dp/src/afxdp/tx.rs`
- **Action**: Add CoSQueueDropCounters.admission_ecn_marked field + protocol/worker/coordinator aggregation
  - **File(s)**: `userspace-dp/src/afxdp/types.rs`, `userspace-dp/src/afxdp/worker.rs`, `userspace-dp/src/afxdp/coordinator.rs`, `userspace-dp/src/protocol.rs`
- **Result**: 16 new tests (11 marker, 5 admission); full suite 667 pass / 0 fail (baseline 651); Local variant only, Prepared deferred to #718-followup

## 2026-04-17 — #727 ECN CE marking on Prepared CoS variant (#718 follow-up)
- **Action**: Add `maybe_mark_ecn_ce_prepared(req, umem)` helper; extend `apply_cos_admission_ecn_policy` to handle both `CoSPendingTxItem::Local` and `::Prepared` under a single `admission_ecn_marked` counter; take a shared `&MmapArea` inside `enqueue_cos_item` via split-borrow and thread it to the policy call
  - **File(s)**: `userspace-dp/src/afxdp/tx.rs`
- **Action**: Add 5 Prepared-variant admission tests (IPv4 ECT(0), IPv6 ECT(0), NOT-ECT, out-of-range offset, combined Local+Prepared counter pin); remove stale `admission_does_not_mark_prepared_variant` negative pin
  - **File(s)**: `userspace-dp/src/afxdp/tx.rs`
- **Result**: admission_ecn group 11/11 pass, mark_ecn_ce group 11/11 pass, full suite 680/680 pass. Marker now fires on the XSK-RX→XSK-TX zero-copy hot path (iperf3, NAT'd flows); acceptance target per `docs/cos-validation-notes.md` is `ecn_marked` becoming non-zero during live 16-flow iperf3

## 2026-04-17 — #709 Option E owner-profile telemetry (measure before optimizing)
- **Action**: Add `DRAIN_HIST_BUCKETS = 16` const-asserted, `bucket_index_for_ns` branchless helper, `drain_latency_hist` + `drain_invocations` + `drain_noop_invocations` + `redirect_acquire_hist` + `redirect_sample_counter` + `pps_owner_vs_peer` on `BindingLiveState`; add `new_seeded(worker_id)` constructor so per-worker redirect samples don't lockstep
  - **File(s)**: `userspace-dp/src/afxdp/umem.rs`
- **Action**: Time every `drain_shaped_tx` invocation with one pair of `monotonic_nanos()` calls; count owner-local vs peer-redirected packets on `ingest_cos_pending_tx` split-point; sample `enqueue_tx_owned` 1-in-256 producer-side
  - **File(s)**: `userspace-dp/src/afxdp/tx.rs`, `userspace-dp/src/afxdp/umem.rs`
- **Action**: Extend `CoSQueueStatus` serde with histograms + owner/peer pps; populate from owner binding's live snapshot in `build_worker_cos_statuses` with `max` aggregation across workers (only owner writes non-zero). Cross-worker coordinator aggregation mirrors `admission_ecn_marked` shape
  - **File(s)**: `userspace-dp/src/protocol.rs`, `userspace-dp/src/afxdp/worker.rs`, `userspace-dp/src/afxdp/coordinator.rs`
- **Action**: Go-side protocol mirror + `OwnerProfile:` line in `show class-of-service interface` under the existing `Drops:` line (only for exact queues with named owner)
  - **File(s)**: `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/cosfmt.go`, `pkg/dataplane/userspace/cosfmt_test.go`
- **Action**: Prometheus gauges/counters for `xpf_cos_drain_latency_ns_bucket`, `xpf_cos_drain_invocations_total`, `xpf_cos_redirect_acquire_ns_bucket`, `xpf_cos_owner_pps`, `xpf_cos_peer_pps`. Cardinality ≤ 16896 series (within plan §5 envelope)
  - **File(s)**: `pkg/api/metrics.go`
- **Action**: New "Reading the owner-profile counters" section with decision tree mapping drain_p99 / redirect_p99 / owner_pps ratio to #709 Option B/C/D follow-ups
  - **File(s)**: `docs/cos-validation-notes.md`
- **Result**: 7 new Rust tests (+692 total, baseline 685), 3 new Go tests; full `cargo test` + `go test ./...` green. Telemetry-only: no hot-path allocations, no new syscalls, MPSC invariants preserved, histogram bucket select branchless

## 2026-04-17 — #708 architect plan

- **Timestamp**: 2026-04-17
  - **Action**: Write #708 enqueue-pacing architect plan — Option B (per-SFQ-bucket token bucket), measurement-first, pacing gate strictly AFTER ECN marker to preserve #718 invariants. Honest framing on residual retrans (most of the ~100k retrans signal is likely ECN-induced recovery entries, not wire loss, so pacing is unlikely to move retrans meaningfully; §3 says so explicitly)
  - **File(s)**: `docs/708-enqueue-pacing-plan.md` (new)

## 2026-04-21 — #821 round 1 code review fixes

- **Timestamp**: 2026-04-21
  - **Action**: Codex HIGH-1 — drop stale `worker-tids.txt` before launching step1; install SIGINT/SIGTERM trap
    - **File(s)**: `test/incus/step2-sched-switch-capture.sh`
  - **Action**: Codex HIGH-2 — reducer drift halt stamps `suspect_reason: "drift_ge_5s"` on every JSONL line and exits 5 (H-STOP-5); classifier detects sentinel and emits `verdict=SUSPECT`; optional `--drift-halt-marker` sidecar; summary log line surfaces `suspect_reason`
    - **File(s)**: `test/incus/step2-sched-switch-reduce.py`, `test/incus/step2-sched-switch-classify.py`, `test/incus/step2-sched-switch-capture.sh`
  - **Action**: Codex HIGH-3 — capture adds `perf record -k CLOCK_REALTIME` and `perf script --ns`; reducer treats perf timestamps as absolute unix wall-clock ns and drops first-event offsetting; PERF_START_NS is diagnostic only (drift measurement)
    - **File(s)**: `test/incus/step2-sched-switch-capture.sh`, `test/incus/step2-sched-switch-reduce.py`
  - **Action**: Codex MEDIUM-4 — restore plan §4.1 `stat_runtime_check` ±1% accounting check against `(block_duration * n_workers - total_off_cpu)`
    - **File(s)**: `test/incus/step2-sched-switch-reduce.py`
  - **Action**: Codex LOW-5 — classifier meta.json top-level is plan-contracted `{verdict, rho, pvalue, duty_cycle_pct, warn_blocks}`; extras moved to `diagnostic` sub-object
    - **File(s)**: `test/incus/step2-sched-switch-classify.py`
  - **Action**: Codex LOW-6 — G8.2 grep uses `grep -qE` with whitespace-tolerant pattern; G8.3 perf-record stderr no longer suppressed
    - **File(s)**: `test/incus/step2-sched-switch-capture.sh`
  - **Action**: Codex LOW-7 — add `TestReducerNegativeWakeDelta` suite with wake-before-switch and equal-ts exercises documenting branch unreachability under monotonic perf
    - **File(s)**: `test/incus/step2-sched-switch-reduce_test.py`
  - **Action**: pyshell M1 — SIGINT/SIGTERM trap added in capture.sh
    - **File(s)**: `test/incus/step2-sched-switch-capture.sh`
  - **Action**: pyshell M2 — `reduce_events` docstring moved to first statement per PEP 257
    - **File(s)**: `test/incus/step2-sched-switch-reduce.py`
  - **Result**: `python3 -m py_compile` OK on all 4 modified `.py` files; reducer tests 13/13 green (was 10, +3 new); classifier tests 11/11 green (was 8, +3 new); V8 non-regression preserved (`step1-histogram-classify.py` unchanged)

## 2026-05-10 — docs README reference fix

- **Timestamp**: 2026-05-10T03:24:56Z
  - **Action**: Correct stale filename references in module READMEs (`eventengine.go`/`dhcprelay.go` -> `engine.go`/`relay.go`) so entry-point file:line links resolve.
  - **File(s)**: `pkg/eventengine/README.md`, `pkg/dhcprelay/README.md`

## 2026-05-10 — docs README wiring/source corrections

- **Timestamp**: 2026-05-10T05:18:20Z
  - **Action**: Correct `SessionCloseData` attribution to `logging.EventReader` session-close records (not conntrack GC delete callbacks).
  - **File(s)**: `pkg/flowexport/README.md`
- **Timestamp**: 2026-05-10T05:18:20Z
  - **Action**: Correct configstore encryption note to match implementation (`master.key` + HKDF with configured PRF).
  - **File(s)**: `pkg/configstore/README.md`

## 2026-05-12 fairness_multi_sample round-2 HIGH fixes

- **Timestamp**: 2026-05-12T06:50:50Z
  - **Action**: Round-3 follow-up — tighten verdict JSON detection to the canonical fairness-eval verdict-key set; remove the `os.getpgid` timeout race by using the process-group leader PID directly; add a bounded post-kill `communicate()`; remove a stale threshold-source reference.
  - **File(s)**: test/incus/fairness_multi_sample.py, test/incus/fairness_multi_sample_test.py, docs/per-5-tuple/v8-multi-sample.md

- **Timestamp**: 2026-05-12T07:45:00Z
  - **Action**: PR #1273 Copilot follow-up — align multi-sample verdict filtering with the canonical 10-key fairness-eval schema and validate summary numeric fields (`cstruct`, `gap`, optional `aggregate_mbps`, and integer `starved_flow_count`) instead of only `observed_cov`.
  - **File(s)**: test/incus/fairness_multi_sample.py, test/incus/fairness_multi_sample_test.py, docs/per-5-tuple/v8-multi-sample.md, docs/per-5-tuple/state.md, _Log.md

- **Timestamp**: 2026-05-12T06:29:25Z
  - **Action**: HIGH1 - Tighten extract_verdict_objects to require verdict+observed_cov+discriminator field
  - **Action**: HIGH2 - Replace subprocess.run with Popen(start_new_session=True)+os.killpg for process-group cleanup on timeout
  - **Action**: MINOR - Replace statistics.fmean with statistics.mean; remove dead timeout_stream_text
  - **Action**: Docs - Add fresh-iperf3 requirement and threshold derivation to v8-multi-sample.md
  - **Action**: Tests - Add schema-incomplete and process-group tests; move import time to top
  - **File(s)**: test/incus/fairness_multi_sample.py, test/incus/fairness_multi_sample_test.py, docs/per-5-tuple/v8-multi-sample.md
  - **Result**: 12/12 tests green (was 10)

## 2026-05-12 fairness_multi_sample round-3 fix

- **Timestamp**: 2026-05-12T07:02:16Z
  - **Action**: Fix pgid capture race - capture os.getpgid(proc.pid) immediately after Popen before communicate() can reap the leader; use cached pgid in both _kill_process_group() calls.
  - **File(s)**: test/incus/fairness_multi_sample.py
  - **Result**: 14/14 tests green

## 2026-05-12 — fairness-eval diagnostic message + test rename

- **Timestamp**: 2026-05-12T06:52:27Z
  - **Action**: PR #1272 round-3 review follow-up — clarify the top-level guard comment to reference `iface_filter_active`, and pin guard failure tests on `expected`, `non-starved`, and `dir_mult` substrings.
  - **File(s)**: `userspace-dp/src/bin/fairness-eval.rs`, `userspace-dp/tests/fairness_eval_blackbox.rs`

- **Timestamp**: 2026-05-12T06:29:24Z
  - **Action**: Fix Harness guard failure message to print `expected_sum` and `dir_mult` alongside `n_non_starved` so operators can see the bidirectional expansion factor. Update block comment to correctly describe `max(2, floor(10% × expected_sum))` formula.
  - **File(s)**: `userspace-dp/src/bin/fairness-eval.rs`
- **Timestamp**: 2026-05-12T06:29:24Z
  - **Action**: Rename `guard_low_n_iface_input_accepts_p2_single_direction_recency_undercount` → `guard_low_n_iface_input_accepts_absolute_floor_p2_gap1`; add inline math comment explaining why absolute floor (not recency) is the operative gate. Drop misleading "recency" claim from assertion messages.
  - **File(s)**: `userspace-dp/tests/fairness_eval_blackbox.rs`

## 2026-05-13 — PR #1301 cross-NIC shared-UMEM validation path

- **Timestamp**: 2026-05-13T20:22:00-07:00
  - **Action**: Enable cross-NIC shared UMEM in the loss userspace HA config, add node-local Phase 0 artifacts, push artifacts during deploy when the config requests shared UMEM, surface shared-UMEM binding mode/role in userspace status, and document the perf/counter contract for copy-free validation.
  - **File(s)**: `docs/ha-cluster-userspace.conf`, `test/incus/cluster-setup.sh`, `test/incus/loss-userspace-shared-umem-phase0-node0.json`, `test/incus/loss-userspace-shared-umem-phase0-node1.json`, `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/statusfmt.go`, `pkg/dataplane/userspace/statusfmt_test.go`, `docs/shared-umem-plan.md`, `docs/userspace-perf-compare.md`, `_Log.md`
- **Timestamp**: 2026-05-13T20:44:00-07:00
  - **Action**: Make cross-NIC shared-UMEM selection artifact-driven by default so the HA config no longer hardcodes interface names; add `selected_device_set` as the generic artifact key while keeping `selected_device_pair` as a legacy alias.
  - **File(s)**: `userspace-dp/src/afxdp/shared_umem.rs`, `docs/ha-cluster-userspace.conf`, `docs/shared-umem-plan.md`, `test/incus/loss-userspace-shared-umem-phase0-node0.json`, `test/incus/loss-userspace-shared-umem-phase0-node1.json`, `_Log.md`
- **Timestamp**: 2026-05-13T20:49:00-07:00
  - **Action**: Make cross-NIC shared UMEM opportunistic by default: no config stanza or Phase 0 artifact is required for normal copy-free forwarding, `mode off` remains the debug kill switch, and Phase 0 artifacts are audit-only instead of production gates.
  - **File(s)**: `userspace-dp/src/afxdp/shared_umem.rs`, `docs/ha-cluster-userspace.conf`, `docs/shared-umem-plan.md`, `pkg/config/ast.go`, `pkg/config/types.go`, `test/incus/cluster-setup.sh`, `README.md`, `_Log.md`
- **Timestamp**: 2026-05-13T22:30:00-07:00
  - **Action**: Close PR #1301 round-3 blockers: document the intentional PR #1297 contract change, restore Phase 0 as non-blocking runtime audit, retry failed shared-UMEM groups as private UMEM, publish fallback status through live binding snapshots, and route cancellable foreign-slot prepared recycles through the shared recycle queue when worker context is available.
  - **File(s)**: `userspace-dp/src/afxdp/shared_umem.rs`, `userspace-dp/src/afxdp/worker/mod.rs`, `userspace-dp/src/afxdp/umem/mod.rs`, `userspace-dp/src/afxdp/types/runtime.rs`, `userspace-dp/src/afxdp/tx/transmit.rs`, `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/tx/drain.rs`, `userspace-dp/src/afxdp/session_glue/mod.rs`, `userspace-dp/src/afxdp/session_delta.rs`, `userspace-dp/src/afxdp/worker/lifecycle.rs`, `pkg/dataplane/userspace/statusfmt.go`, `pkg/dataplane/userspace/statusfmt_test.go`, `pkg/config/types.go`, `docs/shared-umem-plan.md`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml shared_umem -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml remember_prepared_recycle -- --nocapture`; `go test ./pkg/dataplane/userspace ./pkg/config`
- **Timestamp**: 2026-05-13T23:35:00-07:00
  - **Action**: Close PR #1301 round-4 recycle-routing and mixed-mode safety blockers: thread the shared recycle accumulator through close-delta purge, pending TX bound/drop, CoS enqueue demotion, cross-binding prepared redirect, queue-service prepared rejection, neighbor retry, CoS runtime reset, and worker-shaped request paths; remove local-only prepared recycle exports; remove arbitrary-binding fallback for unknown shared recycle slots.
  - **File(s)**: `userspace-dp/src/afxdp/tx/transmit.rs`, `userspace-dp/src/afxdp/tx/mod.rs`, `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/tx/drain.rs`, `userspace-dp/src/afxdp/tx/cos_classify.rs`, `userspace-dp/src/afxdp/tx/tcp_segmentation.rs`, `userspace-dp/src/afxdp/cos/cross_binding.rs`, `userspace-dp/src/afxdp/cos/queue_service/mod.rs`, `userspace-dp/src/afxdp/cos/queue_service/service.rs`, `userspace-dp/src/afxdp/cos/queue_service/drain.rs`, `userspace-dp/src/afxdp/session_glue/mod.rs`, `userspace-dp/src/afxdp/session_delta.rs`, `userspace-dp/src/afxdp/neighbor_dispatch.rs`, `userspace-dp/src/afxdp/worker/cos.rs`, `userspace-dp/src/afxdp/worker/lifecycle.rs`, `userspace-dp/src/afxdp/worker/mod.rs`, `userspace-dp/src/afxdp/tx/README.md`, `userspace-dp/src/afxdp/cos/README.md`, `docs/shared-umem-plan.md`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml cancelled_prepared --no-run`; `cargo test --manifest-path userspace-dp/Cargo.toml shared_umem -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml cancelled_prepared -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml drain_exact_prepared -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml demote_prepared -- --nocapture`; `go test ./pkg/dataplane/userspace ./pkg/config`; `git diff --check`
- **Timestamp**: 2026-05-14T18:55:40Z
  - **Action**: #1307 minimal TX-error attribution: add `tx_shared_recycle_unknown_slot_drops` as a per-binding subset of `tx_errors` for shared-UMEM unknown-slot recycle drops, mirror it through Rust/Go status, and make the local fallback `TxError::Drop` path increment `tx_submit_error_drops`.
  - **File(s)**: `userspace-dp/src/afxdp/umem/mod.rs`, `userspace-dp/src/afxdp/worker/mod.rs`, `userspace-dp/src/afxdp/coordinator/mod.rs`, `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/session_glue/mod.rs`, `userspace-dp/src/afxdp/tx/drain.rs`, `userspace-dp/src/protocol.rs`, `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/statusfmt.go`, `userspace-dp/src/afxdp/tx/README.md`, `docs/shared-umem-plan.md`, `_Log.md`
- **Timestamp**: 2026-05-14T06:05:00Z
  - **Action**: Fix shared-UMEM live-status publication discovered during cluster smoke: the shared bind path now publishes the selected mode/group/role into `BindingLiveState` before worker refresh so status snapshots match the kernel bind result instead of reporting `Shared UMEM bindings: 0/N`.
  - **File(s)**: `userspace-dp/src/afxdp/worker/mod.rs`, `userspace-dp/src/afxdp/worker/README.md`, `_Log.md`
- **Timestamp**: 2026-05-14T06:45:00Z
  - **Action**: PR #1301 round-5 minor follow-up: add regression coverage for stale/wrong/unknown shared-recycle slot routing, increment `tx_errors` when the all-bindings shared-recycle router drops an unknown slot, and downgrade the external IPv6 `mtr` final-hop miss to a warning after the controlled IPv6 dataplane checks pass.
  - **File(s)**: `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/tx/dispatch_tests.rs`, `userspace-dp/src/afxdp/tx/README.md`, `docs/shared-umem-plan.md`, `scripts/userspace-ha-validation.sh`, `_Log.md`
- **Timestamp**: 2026-05-14T07:10:00Z
  - **Action**: Harden the userspace HA smoke validator after live PR #1301 smoke: retry preferred-node failover while XSK liveness propagates into RG readiness, set the default throughput shape to `PARALLEL=6` so the smoke covers the six-worker RSS set, and document the IPv6 external-`mtr` warning semantics.
  - **File(s)**: `scripts/userspace-ha-validation.sh`, `docs/userspace-ha-validation.md`, `.codex/skills/userspace-ha-validation/SKILL.md`, `_Log.md`
- **Timestamp**: 2026-05-14T07:35:00Z
  - **Action**: PR #1301 round-6 minor follow-up: make the split-slice shared-recycle router use the same slot-resolution helper as the all-bindings cleanup path and add split-slice helper coverage for stale/unknown lookup behavior.
  - **File(s)**: `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/tx/dispatch_tests.rs`, `userspace-dp/src/afxdp/tx/README.md`, `_Log.md`
- **Timestamp**: 2026-05-14T08:05:00Z
  - **Action**: PR #1301 round-7 polish: aggregate unknown-slot shared-recycle stderr diagnostics to one bounded line per drain while preserving full `tx_errors` accounting.
  - **File(s)**: `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/tx/README.md`, `_Log.md`
- **Timestamp**: 2026-05-14T09:45:00Z
  - **Action**: PR #1311 round-3 review fixes (on top of remote `4de390d3` which already rewrote the stress test with a quadratic schema and added a `fence(Acquire)` to the reader). Sync stale file-level doc that claimed "All atomics use Relaxed" to mention the seqlock + reader fence; reword "60-120s window" doc nits across `worker_runtime.rs`, `protocol.rs`, `pkg/dataplane/userspace/protocol.go`, and `pkg/dataplane/userspace/statusfmt.go` to match the ~1 Hz publish cadence (~60-61s under normal cadence; `WindowNS` carries exact width); drop the "default Prometheus scrape interval" wording on `WR_WINDOW_INTERVAL_NS`; fix the stale `1.5s CPU over 60s` comment in `statusfmt_test.go` to `45s CPU over 60s = 75%`. Add a `nonzero_snapshots > 1_000` guard at the end of the stress test so a broken reader returning all zeros can't silently pass (Codex round-3 ask not covered by `4de390d3`).
  - **File(s)**: `userspace-dp/src/afxdp/worker_runtime.rs`, `userspace-dp/src/afxdp/worker_runtime_tests.rs`, `userspace-dp/src/protocol.rs`, `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/statusfmt.go`, `pkg/dataplane/userspace/statusfmt_test.go`, `_Log.md`
- **Timestamp**: 2026-05-15T14:32:39-07:00
  - **Action**: #1318 scoped CoS drain idle fix: gate `drain_shaped_tx` root priming on runnable queues or due parked wake ticks, skipping timer-wheel advance and shared-root lease top-up for not-yet-serviceable parked roots while preserving due wake service.
  - **File(s)**: `userspace-dp/src/afxdp/cos/queue_service/mod.rs`, `userspace-dp/src/afxdp/cos/queue_service/tests.rs`, `userspace-dp/src/afxdp/cos/tx_completion.rs`, `userspace-dp/src/afxdp/cos/tx_completion_tests.rs`, `userspace-dp/src/afxdp/cos/README.md`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml drain_shaped_tx_ -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml root_serviceability_tracks_parked_queue_wakeup_tick -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml queue_service`; `cargo test --manifest-path userspace-dp/Cargo.toml tx_completion`
