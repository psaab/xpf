# Codex plan review r1 — #1829 (task-mq8el2ib-h0qksu, spark/high)

**Verdict: PLAN-NEEDS-MAJOR**

1. **[HIGH] Dequeue-time CoDel cannot be implemented from current dataplane data shape (missing enqueue time in hot path).**  
   Evidence:  
   - `[userspace-dp/src/afxdp/types/tx.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/types/tx.rs:24-95)` (`TxRequest` / `PreparedTxRequest` have no enqueue timestamp field).  
   - `[userspace-dp/src/afxdp/cos/queue_ops/push.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_ops/push.rs:18-110)` pushes request payload into queue objects that also do not carry enqueue time.  
   - `[userspace-dp/src/afxdp/cos/ecn.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/ecn.rs:1-120)` contains only admission-side ECN marking helpers (`maybe_mark_ecn_ce`/`should_mark_ecn`).  
   Remedy: add immutable enqueue timestamp to the queued item payload (or per-item metadata) captured once at enqueue, then consume it during dequeue-time AQM decisions.

2. **[HIGH] Open Question Q2 is not resolved in the current plan by evidence: existing admission AQM is not a substitute for dequeue-time CoDel.**  
   Evidence:  
   - `[userspace-dp/src/afxdp/cos/admission.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/admission.rs:30-110)` defines `COS_FLOW_FAIR_MAX_QUEUE_DELAY_NS = 5_000_000` and ECN ratio constants (`1/3`) and applies them during admission.  
   - Those checks are pre-enqueue decisions only; there is no dequeue-sojourn control loop in this module.  
   Remedy: treat admission and dequeue AQM as complementary, not redundant; do not PLAN-KILL on Q2 unless explicitly proving that downstream latency goals are already met without dequeue-time control.

3. **[MED] #1828’s “AF_XDP TX bypasses kernel qdisc” claim is only conditionally true and needs plan language to be narrower.**  
   Evidence:  
   - `[userspace-dp/src/afxdp/tx/rings.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/tx/rings.rs:1-170)` uses AF_XDP socket TX ring completion and `sendto` wake on that socket; no direct `dev_queue_xmit`/qdisc enqueue logic is visible in this file.  
   - `[userspace-dp/src/afxdp/tx/dispatch/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/tx/dispatch/mod.rs:1-220)` and related exception paths use separate slow-path handling that is not this ring path.  
   Remedy: constrain the claim to the AF_XDP ring TX data-path only, and explicitly document which control/exception traffic can still traverse host stack behavior.

4. **[MED] Phase-2 value gate is under-specified in terms of safe rollout and backward compatibility.**  
   Evidence:  
   - `[userspace-dp/src/afxdp/types/cos.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/types/cos.rs:50-190)` carries `codel_target_ns` in queue runtime config, but no explicit enable bit is present at this layer.  
   - `[pkg/config/types_cos.go](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/pkg/config/types_cos.go:1-220)` and `[pkg/config/compiler_class_of_service.go](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/pkg/config/compiler_class_of_service.go:1-260)` show only parameter transport, not phase gating semantics.  
   Remedy: define and document a deterministic phase-2 gate (`enabled + target`), with defaults that preserve existing behavior, and enforce it in a single place (compiler + userspace runtime).

5. **[MED] Protocol-wire parity for CoDel telemetry is incomplete versus current implementation and current plan expectations.**  
   Evidence:  
   - `[userspace-dp/src/protocol/cos.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/protocol/cos.rs:1-180)` includes `codel_target_ns` in `CoSSchedulerSnapshot` but no dequeue AQM counters/marks.  
   - `[pkg/dataplane/userspace/protocol.go](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/pkg/dataplane/userspace/protocol.go:1-260)` mirrors this shape and also lacks CoDel-specific counters.  
   Remedy: if plan promises observability or control-plane status, add explicit optional fields on both Rust and Go protocol snapshots/status structs (counts/last drop-mark timestamp/epoch-safe state).

6. **[LOW] #1734 no mid-pass clock-advance constraint is currently respected by structure, but CoDel integration can violate it unless called out in the design contract.**  
   Evidence:  
   - Existing dequeue loops in `[userspace-dp/src/afxdp/cos/queue_service/service.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_service/service.rs:1-220)` are pass-budget based and do not currently show repeated `now()` drift in hot loops.  
   Remedy: lock to one monotonic clock sample per dequeue pass and only pass elapsed-derived state forward to per-packet decisions.

7. **[LOW] #1763 / #913 / #1355 invariants are currently codified, but the plan must explicitly preserve them when adding AQM state mutations.**  
   Evidence:  
   - `[userspace-dp/src/afxdp/cos/queue_ops/pop.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_ops/pop.rs:1-260)` has peek/pop split and snapshot support used by drain.  
   - `[userspace-dp/src/afxdp/cos/queue_service/drain.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_service/drain.rs:1-280)` and `[userspace-dp/src/afxdp/cos/queue_service/mod.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/userspace-dp/src/afxdp/cos/queue_service/mod.rs:1-240)` enforce/consume snapshot-stack behavior.  
   Remedy: defer all CoDel state writes to pop-commit points and ensure rollback/clear hooks also run on CoDel drops and demotion paths (`clear_orphan_snapshot_after_drop` / lifecycle transitions in `[userspace-dp/src/afxdp/cos/queue_service/flow_fair/drain.rs]`-style paths).

8. **[LOW] Hot-path allocation/perf rules from engineering-style are at risk if CoDel introduces per-dequeue heap writes/vecs; current plan text needs an explicit zero-allocation implementation strategy.**  
   Evidence:  
   - Current queue service/drain paths are built around preexisting fixed queue structures (`FlowFairState`, snapshots) and not ephemeral allocation at dequeue.  
   Remedy: require fixed-capacity or embedded counters only; no allocations or per-packet map lookups in enqueue/dequeue hot paths.

---

### Open Questions (section 12) — answers

1. **Q1 (AF_XDP qdisc bypass):** Airtight only for the tx/rings AF_XDP path; not universal for all TX in this codebase.  
2. **Q2 (admission AQM redundancy):** No. Admission AQM is guard-rail only; it does not replace dequeue-time queue-time control.  
3. **Q3 (when to enable dequeue AQM):** Gate explicitly (`enabled && target_ns > 0`) and keep scope/version compatibility.  
4. **Q4 (clocking strategy):** One sampled clock per dequeue pass, no per-packet mid-pass clock churn.  
5. **Q5 (peek+pop invariant):** Must hold; any CoDel state mutation must happen at commit-pop stage with snapshot rollback safety.  
6. **Q6 (lifecycle + snapshots):** Demote/orphan transitions must explicitly clear/rollback AQM state with same rigor as existing drop/rollback paths.  
7. **Q7 (wire/protocol claims):** Current protocol is not telemetry-complete for dequeue AQM; if plan expects control-plane visibility, add fields now (both Rust and Go protocol structs).

Codex session ID: 019eb2cc-2ce8-7171-bd3d-4c23cf623fde
Resume in Codex: codex resume 019eb2cc-2ce8-7171-bd3d-4c23cf623fde
