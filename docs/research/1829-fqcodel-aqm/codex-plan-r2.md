### Verdict: **PLAN-READY-WITH-FINDINGS**

## 1) Round-1 finding-by-finding verification

1. **[HIGH] R1F1 Dequeue-time requires enqueue timestamp — RESOLVED (design-only)**
   - v2 quote: "`Option A (preferred): enqueue_ns: u64 field on TxRequest AND PreparedTxRequest...`" at [`plan.md:231-238`]( /home/ps/git/bpfrx/.claude/worktrees/research-1829-aqm/docs/research/1829-fqcodel-aqm/plan.md:231 ) and explicit `codel_target_ns` write-only status.
   - Code re-check: `TxRequest`/`PreparedTxRequest` still have no enqueue time (`tx.rs:12-95`), so this is not yet implemented in branch `d30cfab84`.  
   - Remediation status: accepted by plan; implementation still pending.

2. **[HIGH] R1F2 Admission is not a substitute for dequeue-time control — RESOLVED**
   - v2 quote: Section 3 reframes CoDel as targeted remedy and says admission is guard-rail/instrumented, not replacement; plus attribution gate in `1d` before phase-2 (`plan.md:88-95`, `1d` at `:265-276`).
   - Code re-check: admission-only checks remain in `admission.rs`; no dequeue-time control loop yet (`admission.rs:324-375` only marks at enqueue).
   - Remediation status: addressed in plan text and sequencing.

3. **[MED] R1F3 #1828 path scope narrowness — RESOLVED**
   - v2 quote: `#1828 claims narrowed` + explicit scope and caveat sections, e.g. all forwarded traffic via AF_XDP TX ring; control-plane caveat (`plan.md:130-140`, `:174-181`, `:572-590`).
   - Code re-check: `forwarding_build` wires `codel_target_ns` into queue runtime only; TX path evidence in v2 aligns with existing AF_XDP transmit model.
   - Remediation status: resolved in v2 wording and threat model.

4. **[MED] R1F4 Phase-2 gate semantics — RESOLVED**
   - v2 quote: `Single-place enable gate: queue.config.codel_target_ns > 0` and `state allocation keyed to same predicate` (`plan.md:353-361`).
   - Code re-check: current queue runtime uses single-source enable pattern elsewhere (`flow_fair()` is `flow_fair_state.is_some()`), so this aligns structurally (`types/cos.rs:601-614`).
   - Remediation status: resolved as design contract; implementation still pending.

5. **[MED] R1F5 Protocol telemetry parity — PARTIALLY RESOLVED**
   - v2 quote: explicit optional fields added in Rust/Go protocol snapshots (`plan.md:469-477`) + `coS status`/Prometheus plumbing mention.
   - Code re-check: `codel_target_ns` is currently present and user-facing only (`protocol/cos.rs:118-119`, `userspace-dp/src/protocol/cos.rs` and Go counterpart), no dequeue counters yet.
   - Remediation status: addressed on plan side; runtime/proto plumbing deferred and to be implemented.

6. **[LOW] R1F6 Mid-pass clock advance — RESOLVED**
   - v2 quote: no new `clock_gettime` and one-pass `now_ns` threading (`plan.md:56-57` and `502-504` type text references).
   - Code re-check: hot paths already pass `now_ns` through service functions and existing behavior is pass-scoped (`service.rs:12-19`, `userspace-dp/src/afxdp/cos/queue_service/service.rs`).
   - Remediation status: resolved.

7. **[LOW] R1F7 Preserve #1763/#913/#1355 invariants — RESOLVED WITH TESTING REQUIREMENT**
   - v2 quote: state writes only at pop-commit, rollback and snapshot cleanup callouts (`plan.md:363-370`, `390-406`, `8c?` via side-effect table).
   - Code re-check: `debug_assert!(!queue.flow_fair())` in FIFO helpers and pop/clear-orphan patterns already exist (`drain.rs:46`, `:313`, and `drain.rs:256-266`, `:537`).
   - Remediation status: resolved conceptually, but depends on new diff tests to verify every field transition (caller already requested in `plan.md:534-535`).

8. **[LOW] R1F8 Hot-path allocation/perf discipline — PARTIALLY RESOLVED**
   - v2 quote: no allocations at dequeue and zero-allocation per-byte path, plus perf gates and fallback (`plan.md:257-263`, `:502-504`, `:524-525`, `:551-552`).
   - Code re-check: current paths use fixed scratch vectors/slots and no per-dequeue heap ops in the shown hot loops.
   - Remediation status: resolved in design; still to be validated by implementation and benchmark gate.

## 2) Hostile re-check of your new v2 deltas

1. **[PASS] (a) FIFO index-walk drain reachability**
   - v2 quote: "`drain_exact_*_fifo_items_to_scratch` are production-unreachable post-#1735`" (`plan.md:317-323`, `:324-328`).
   - Code re-check: exact local/prepared service explicitly checks `flow_fair()` and takes flow-fair drain when true (`service.rs:20-35`, `:380-388`), while exact queues are eagerly promoted (`admission.rs:525-532`).
   - Result: **No production path observed** from exact queues to index-walk FIFO drains now.

2. **[MED-HIGH] (2c-bis) potential signal gap when phase-2 not active**
   - v2 quote: bypasses per-flow admission ECN when `codel_target_ns > 0` (`plan.md:413-417`), with mark-only fallback to aggregate arm.
   - Code re-check: enqueue/dequeue codel enforcement is still deferred (`types/cos.rs:690-695`), so until phase-2 lands there is no dequeue-time replacement for removed per-flow admission behavior.
   - Remediation: gate bypass behind explicit phase-2 enablement, or retain per-flow admission when phase-2 is disabled (even when target>0) to avoid a zero-signal window on `target_ns>0` configs.

3. **[PASS] (2c table) nonempty/runnable table ownership**
   - v2 quote: `nonempty_queues/runnable_queues` row says “NOT touched inline” and re-evaluated on exit (`plan.md:401-402`, `:405-407`).
   - Code re-check: full recomputation function exists and is used as normalization boundary (`cos/tx_completion.rs:576-605`).
   - Result: consistent with design if all dequeue and drop paths eventually route through refresh path; tests should enforce.

4. **[PASS-with-caveat] (gate/state pairing #1735 lifecycle)**
   - v2 quote: `state.is_some() ↔ target_ns > 0` mirror pattern (`plan.md:353-361`) and demotion/drop clear logic notes in v2 test plan (`plan.md:405-406` etc.).
   - Code re-check: current `flow_fair()` invariant already structurally binds gate to allocation state (`types/cos.rs:601-607`) and exact never demotes (`queue_ops/mod.rs:311-313`).
   - Caveat: no production enforcement of this exact pattern for CoDel exists yet; must explicitly validate on queue rebuild/reconfig transitions and lifecycle of `QueueRuntime` objects.

### Bottom line
- Round-1 findings are **noted as addressed in v2** textually (or scoped as addressed-by-design).
- Blocking gap for hostile sign-off remains: **(2c-bis timing window / phase coupling)** unless explicitly guarded, so final status should stay **PLAN-READY-WITH-FINDINGS** pending that fix.

Codex session ID: 019eb2dd-0b77-7a83-880e-86b7f7dd102d
Resume in Codex: codex resume 019eb2dd-0b77-7a83-880e-86b7f7dd102d
