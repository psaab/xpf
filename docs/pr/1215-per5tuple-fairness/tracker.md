---
status: TRACKER — granular session state for #1215
issue: https://github.com/psaab/xpf/issues/1215
branch: feature/1215-per5tuple-fairness
created: 2026-05-06
mandate-source: user, this session
---

# Per-5-tuple fairness drive — running tracker

This doc is the source of truth for the per-5-tuple fairness drive.
Updated after every meaningful milestone. If a session burns out
mid-work, the next session reads this + recent commits + the
`project_per5tuple_fairness_drive.md` memory entry to resume.

## Mandate (verbatim)

> What I mean by flow is dport:dip <-> sport:sip and making sure each
> one of these flows which may happen to fall on distinct RSS queues
> or even multiple flows on the same RSS queue, each flow does not
> consume more than any other flow. This is what we are marching
> towards.
>
> Do everything you propose and keep a running document/memory of
> what you're doing so we don't forget until we burn it all down with
> triple review and smoke tests. We need to make sure we keep moving
> until we have achieved proper fairness.

## Why a new mechanism is needed

V_min sweep this session (24 cells × 60s) showed current defaults
(lag=1ms, cadence=8) near-optimal at 25.7% CoV on iperf-c P=12.
Tighter throttling regresses (e.g., lag=100µs cadence=8 → 9686
retransmits at 21.7% CoV).

Codex retrospective (`docs/pr/789-fairness-disposition/plan.md` on
`experiment/789-vmin-tuning`) framed the gap as structural:

> V_min synchronizes per-worker queue virtual time. It does not make
> a global per-flow scheduler. (Worker A 1 flow vs Worker B 3 flows
> example.) That is not a bug in the current V_min implementation.
> It is the structural limit of per-worker fair queueing under
> RSS-skewed flow placement.

Two paths in the retro: #936 (shared per-flow vtime) or #937 (ingress
XDP_REDIRECT). #1215 commits to path 1.

## Acceptance gates (from #1215)

| Cell | Gate |
|---|---|
| iperf-c P=12 t=120 -R, 5 reps mean | per-flow CoV ≤ 20% |
| iperf-b P=12 t=120 push, 5 reps mean | per-flow CoV ≤ 20% |
| iperf-d P=12 t=120 push (currently passes) | no regression beyond ±2pp |
| Aggregate on iperf-c | ≥ 22 Gb/s OR documented regression |
| Aggregate on degenerate {6,0,0,0,0,6} distribution | accepted regression up to ~33% |
| `make test-failover` | passes |

## Phases

### Phase 0 — foundations (in flight)

- [x] #1210 doc scrub (PR #1212 merged 2026-05-06): removes
      `flow_fair = queue.exact && !shared_exact` and 1024-bucket
      strings that misled 3 plan-review cycles.
- [x] #1205 drift CI guard (PR #1213 merged 2026-05-06): prevents
      reintroduction of stale CoS scheduler text.
- [x] #1208 refactoring-audit refresh (PR #1214 merged 2026-05-06):
      includes BPF C heatmap. Visibility for #1206 + future fairness
      file growth.
- [x] V_min sweep dispositive measurement (TSV on
      `experiment/789-vmin-tuning`). Codex retrospective embedded
      in the disposition doc.

### Phase 1 — refactor foundation ✓ DONE

- [x] **#1206 (CoSQueueRuntime split) merged 2026-05-06 (PR #1216, squash merge a1688792).**
      Worktree: `.claude/worktrees/1206-cosqueueruntime-split`.
      Plan v3 PLAN-READY both Codex (task-mou8wztc) and Gemini.
      Splits into:
      - `CoSQueueConfigState` (immutable post-build: capacity, mode, exact, weight)
      - `CoSQueueHotState` (per-tick: queue_vtime is FlowFair-only, depth, etc.)
      - `FlowFairState` (boxed; flow_hash_seed, queue_vtime, flow_bucket_items inline)
      - `VMinQueueState` (worker_id, vtime_floor)
      - `CoSQueueTelemetry`
      Box-deref hoisting at hot-path branch entry. Pure code motion + struct redirection.
      Smoke matrix: full /triple-review per-class CoS smoke on loss cluster.

### Phase 2 — design (after Phase 1 merges)

- [ ] **#1215 plan v1** drafted at `docs/pr/1215-per5tuple-fairness/plan.md`
      against master tip + #1206. Must enumerate:
      1. Cross-worker hash seed coordination (current `flow_hash_seed`
         is per-runtime; shared table needs shared seed allocated by
         coordinator at queue-build time).
      2. AtomicU64 + Ordering::Relaxed race-safety. Plain u64 read while
         atomic-write concurrent = UB in Rust. All cross-worker
         finish-time loads/stores are atomic.
      3. Pop hot-path stall mechanism. Local vtime exceeds shared V_min
         by slack budget → defer to FIFO-yield rather than emit. Slack
         budget tunable via knob.
      4. HA failover saturating_sub semantics on every counter diff
         (PR #1203 Phase 2 died on uint64 underflow at role flip).
      5. Reset-epoch / fair-share denominator / rollback / batch-latency
         holes from #838-afd-lite retrospective (`838-afd-lite/findings.md`).
      6. Telemetry: per-flow stall counter, per-queue V_min lag
         distribution, per-flow finish-time max-min skew.
- [ ] **Plan v1 → triple-review** (Codex hostile + Gemini Pro 3
      adversarial). Iterate to PLAN-READY both.

### Phase 3 — implementation

- [ ] **Implement** on `feature/1215-per5tuple-fairness` branch.
      Pure code motion not possible (data structure addition); follow
      plan exactly.
- [ ] cargo build clean, full test suite, 5×flake on named test.
- [ ] Go suite green.
- [ ] **Smoke matrix** on `loss:xpf-userspace-fw0/fw1` (per
      /triple-review): Pass A CoS-disabled v4+v6 push+reverse +
      multi-stream `-P 12 -R`; Pass B CoS-enabled per-class
      5201-5206 v4+v6 push+reverse.
- [ ] **5-rep CoV measurement** on iperf-c P=12 t=120 -R (the gate).
- [ ] **make test-failover** passes (any cluster-touching change).

### Phase 4 — review

- [ ] PR opened with full smoke + 5-rep CoV table.
- [ ] Copilot polled to review and every comment addressed.
- [ ] Codex hostile code review.
- [ ] Gemini Pro 3 adversarial code review.
- [ ] All three concur → merge.

### Phase 5 — residual variance reducers (optional)

- [ ] #1209 telemetry double-buffer (per-flow stall counters surface).
- [ ] #1211 AFD/CSFQ ECN overlay (residual-variance reducer).

## State pointers (don't lose)

- **Codex retro + V_min sweep**: `docs/pr/789-fairness-disposition/plan.md`
  on branch `experiment/789-vmin-tuning`.
- **#1206 plan v3 PLAN-READY**: `docs/pr/1206-cosqueueruntime-split/plan.md`
  on branch `refactor/1206-cosqueueruntime-split`.
- **This tracker**: `docs/pr/1215-per5tuple-fairness/tracker.md` on
  branch `feature/1215-per5tuple-fairness`.
- **Memory entries** kept in lockstep:
  - `~/.claude/projects/-home-ps-git-bpfrx/memory/project_per5tuple_fairness_drive.md`
    (high-level mandate)
  - MEMORY.md index line for that file
  - When state changes meaningfully, update both this tracker AND
    the memory file.

## Verified-on-master claims (don't drift)

Master tip 638c9d07. Verified this session:

| Claim | File:line | State |
|---|---|---|
| `pop` uses `max(vtime, served_finish)` | `userspace-dp/src/afxdp/cos/queue_ops/pop.rs:112` | shipped (#913 fix in PR #928) |
| `flow_fair = queue.exact` for owner-local AND shared_exact | `userspace-dp/src/afxdp/cos/admission.rs:478-486` | shipped #785 Phase 3 |
| `vtime_floor.clone()` for cross-worker V_min sync | `admission.rs:478-486` | shipped #917 |
| Rate-aware admission cap | `admission.rs` | shipped #914 |
| `COS_FLOW_FAIR_BUCKETS = 4096` | `userspace-dp/src/afxdp/cos/types/mod.rs` | shipped #785 |

## Prior art digest (read before drafting plan v1)

### #836 — shared MQFQ HOL-finish-time array (CLOSED 2026-04-22, no impl)

Naive instinct for #1215. **DOES NOT WORK** because HOL-finish-time
is non-commutative under concurrent writers:

- Per-packet timestamp; changes non-additively on every dequeue.
- Rollback (push_front on submit failure) needs snapshot state.
- Concurrent writers can corrupt ordering.

**Implication for #1215 v1**: a literal "shared finish-time table
indexed by flow bucket, with each worker writing its head_finish
on pop" reproduces #836's mistake. Plan v1 must address the
commutativity problem head-on or pick a commutative quantity.

### #838 — per-flow bytes-served counter w/ periodic reset (PLAN-ONLY, killed)

5 plan rounds, 14+ HIGH cumulatively. Three known race surfaces
that any cross-worker shared-atomic plan must answer:

1. **Period reset coherence** — when one worker resets the
   counter, others may still be writing into the old period.
2. **Fair-share denominator staleness** — N (active flow count)
   moves; one gate can bump for a new flow while another reads
   stale N.
3. **Rollback semantics** — submit failure returns items to the
   queue but the per-flow counter has already been decremented.

Plus a 4th surface found at R5 (Q9): batch-latency mismatch
between selection (per-packet) and accounting (per-batch settle,
TX_BATCH_SIZE up to 256). Selector can ship multiple
periods-worth before counter reflects them.

### #840 — RSS rebalance from per-binding RX signal (REVERTED)

Implemented + benchmarked + reverted at commit 1c611d01. Made
fairness WORSE: CoV 37.7% with vs 18.5% baseline. Don't do
"shift the hash" — it's not a substitute for per-flow scheduling.

### Pattern across #836/#838/#840

> "We can encode fairness as additional state read/written in
>  the existing per-binding hot path."

That assumption has not held. The hot path is batch-shaped
(TX_BATCH_SIZE ~256) so per-packet accounting has one-batch
latency. flow_bucket_bytes is a queue-backlog counter, not a
bytes-served counter — past plans repeatedly conflated the two.

### What this means for #1215 v1

Two design routes that survive the prior-art:

**Route A — commutative quantity**: pick a per-flow signal that
IS commutative under concurrent writes. Examples:
- Per-flow byte counter via `fetch_add` (aggregates monotonically;
  no rollback if we accept "served bytes" never decreases on
  push_front because the bytes were actually served — submit
  failure resets to free pool but the wire transmit may already
  have hit nic).
- Per-flow last-served-vtime via `fetch_max` (idempotent under
  reordering).

**Route B — message-passing not shared state**: workers publish
their per-flow served counts to a coordinator (single writer)
that periodically computes a global v-min view and broadcasts
back via RCU/ArcSwap. No cross-worker writes to the same
atomic. Costs: extra hop, snapshot epoch, periodic reset.

**Reject**: any design that shares HOL-finish-time directly
(repeats #836). Any design with cross-worker rollback semantics
on shared atomic counters (repeats #838's #2 + #3).

### #900 measurement-first finding

Empirical baseline showed "streams collapse to 0 bps" symptom
doesn't reproduce on standard test conditions. The ACTUAL
problem reduces to per-flow throughput CoV under saturation.
**Today's measurement (this session)**: 47% per-flow CoV on
iperf-c P=12 t=10 -R. That's the gap #1215 closes; the
measurement justifies algorithm work.

## Withdrawn / killed approaches (don't repeat)

- **#936 v1**: per-runtime hash seed prevented cross-worker bucket
  consistency. v2 (this drive) must coordinate seed via
  coordinator-owned per-shared-exact-queue value.
- **#838-afd-lite**: race-safety holes broader than "multiple writers" —
  period reset coherence, fair-share denominator staleness, rollback
  semantics, batch-latency. v1 plan must enumerate each and answer.
- **PR #1203 (n-tuple steering)**: built inter-queue load balancer to
  mask intra-queue scheduling. Architectural anti-pattern. Withdrawn.
- **PR #1203 Phase 2 (byte-rate diffing)**: uint64 underflow at HA
  role flip. v1 plan must use saturating_sub everywhere.

## Session log

| Date | Event | Notes |
|---|---|---|
| 2026-05-06 | Issue #1215 filed | Cites Codex retro + user mandate |
| 2026-05-06 | Tracker doc created | This file |
| 2026-05-06 | Memory entry created | `project_per5tuple_fairness_drive.md` + MEMORY.md index line |
| 2026-05-06 | #1206 worktree rebased onto master 638c9d07 | Clean rebase of plan v3 (3 commits) |
| 2026-05-06 | Codex dispatched for #1206 implementation | task-mouau0b5-k4xhoa; bulk migration of ~1500 field accesses |
| 2026-05-06 | #1206 PR #1216 opened | commit 1c60d825; smoke pass A (CoS off) 22.8/22.5 Gbps -P 12 -R 0 retrans; Pass B (CoS on) 24/24 cells 0 retrans, iperf-a shaped 960Mbps |
| 2026-05-06 | #1206 fix commit f16a68b6 | Codex MERGE-NEEDS-MINOR (vtime comment, 6 stale field-paths) + Copilot HIGH (silent flow_fair invariant violation in pop/push) addressed; .expect() now panics on invariant break |
| 2026-05-06 | Re-dispatched: Codex task-moujrj05-kidabk + Gemini Pro 3 task-moujr55d-kz8dl6; Copilot @-pinged | Round-2 review on f16a68b6 |
| 2026-05-06 | Codex round-2 NEW-FINDINGS, Gemini Pro 3 MERGE-READY | 4 LOW comment fixes in 31daea5e + Copilot SWE Agent autocommit df09c8e6 |
| 2026-05-06 | Copilot round-2: 4 comments (3 invariant + 1 dedup) | Fixed in df478df9: 7 .expect() panic sites; dedup deferred (out of pure code-motion scope) |
| 2026-05-06 | Codex round-3 (task-moumzrae): MERGE-NEEDS-MINOR | 3 LOW (cos_queue_front silent-None, panic msg fn name, 2 stale comments) → cd0390ed |
| 2026-05-06 | **PR #1216 squash-merged to master as a1688792** | Triple-review consensus: Gemini MERGE-READY, Codex 3 rounds converged, Copilot 8 comments addressed; smoke clean |
| 2026-05-06 | #1206 worktree removed | feature/1215 starts #1215 plan v1 against post-merge master |
