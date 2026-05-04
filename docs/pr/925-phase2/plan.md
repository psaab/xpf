---
status: DRAFT v3 — Codex round-2 PLAN-NEEDS-MINOR (doc-consistency only) addressed; Gemini PLAN-READY
issue: https://github.com/psaab/xpf/issues/925
phase: Phase 2 — Prometheus gauge + decision-doc closeout
---

## Changelog v3
- Codex round-2 (`task-morpr2ic-xar6ai`) PLAN-NEEDS-MINOR — three doc-consistency issues, no design changes:
  - **Q-1 partial**: §8 said the metric test "MUST" exist but §2 still
    described it as "Optional". Fixed: §2 now matches §8 (mandatory).
  - **Q-5 partial**: previous §6 wording said "alert-to-page latency
    is `scrape_interval + worker_publish_lag (≤1 s) + control_rt`"
    and the v2 changelog said `min(scrape_interval, socket_rt)`.
    Both wrong — the `dead` bit is read directly by the status
    handler (`userspace-dp/src/server/handlers.rs:413-415` →
    `coordinator/status.rs:144-147`), NOT batched via the per-worker
    counter publish cadence. Corrected to:
    `latency ≤ scrape_interval + control_socket_rt`, where the worker
    publish cadence is irrelevant to the `dead` bit.
  - **NEW-1**: §3 said "no Rust changes required" and §7 risk table
    said "No Rust change" — but §4.3 adds a Rust source-comment edit.
    Reworded to "no Rust behavior/API change" so scope text matches
    the actual implementation footprint.
- Gemini round-1 (`task-morpts70-37oq7l`) returned PLAN-READY on all 8 questions.

## Changelog v2

## Changelog
- **v2**: Codex round-1 (`task-morpduik-e7wr83`) returned PLAN-NEEDS-MINOR. Addressed:
  - §8 metric test promoted from "Optional" to MANDATORY (Codex Q-1).
  - §6 corrected the false "1s snapshot lag" invariant — `xpfCollector.Collect`
    calls `provider.Status()` per scrape, which synchronously hits the
    userspace-dp control socket (`pkg/api/metrics.go:394-410, 416-428`,
    `pkg/dataplane/userspace/manager.go:839-860`). The 1s cadence is the
    manager's separate `statusLoop` (`process.go:342-360`) and per-worker
    publishes (`userspace-dp/src/afxdp/worker/mod.rs:687-717`), neither of
    which the gauge reads from. Cadence-to-alert is `min(scrape_interval,
    socket_round_trip)`; for typical 15-30s scrapes the 1s publish lag is
    within noise (Codex Q-5).
  - §4 / §10 Q3 acknowledged safe alternatives for panic_message (fixed
    `panic_class` enum, fingerprint hash) but kept the JSON-status-only
    decision (Codex Q-7).
  - §4.3 NEW: stale wire-doc comments at `pkg/dataplane/userspace/protocol.go:539-542`
    and `userspace-dp/src/afxdp/worker_runtime.rs:71-73` say "Phase 2
    (respawn) will clear on relaunch" — but THIS Phase 2 is closeout, not
    respawn. Update those comments in the same PR (Codex Q-8).

# #925 Phase 2 — `xpf_userspace_worker_dead{worker_id}` gauge + no-respawn decision

> *If reviewers conclude the perf gain is too small to justify the
> churn, PLAN-KILL is an acceptable verdict.*

## 1. Issue framing

#925 asked for a worker thread supervisor: catch panics, report
liveness, optionally respawn. Phase 1 (already shipped via the
`#925-A`/`#925-B` commit stream that landed before #1183) covered:

- `spawn_supervised_worker` and `spawn_supervised_aux` helpers
  in `userspace-dp/src/afxdp/coordinator/mod.rs` (~`:1894`/~`:1922`),
  both wrapping the body in `catch_unwind`.
- `WorkerRuntimeAtomics.dead` (atomic) and `panic_message` (Mutex<Option<String>>)
  per worker.
- All three production worker-spawn sites switched to the
  supervised helper.
- 4 panic-injection unit tests in `userspace-dp/src/afxdp/coordinator/tests.rs`
  (`spawn_supervised_worker_catches_string_panic_and_marks_dead`,
  `spawn_supervised_aux_catches_string_panic_and_returns_cleanly`,
  `spawn_supervised_aux_runs_body_to_completion_when_no_panic`,
  `spawn_supervised_aux_catches_non_string_panic_payload`).
- `WorkerRuntimeStatus.Dead` (bool) and `WorkerRuntimeStatus.PanicMessage`
  (string) on the userspace-dp control-socket JSON wire
  (`pkg/dataplane/userspace/protocol.go:541-545`,
  `userspace-dp/src/protocol.rs:1076-1077`).
- The `cli show userspace-dp ...` text/JSON renderer already
  surfaces both fields.

What Phase 1 did NOT do (and Phase 2 closes out):

- **Prometheus exposure of the dead state.** The xpfCollector
  in `pkg/api/metrics.go:308-340` exposes 7 worker counters
  (wall, active, idle-spin, idle-block, thread-cpu, work-loops,
  idle-loops) but does **not** expose `dead` as a gauge. An
  operator running a Prometheus alert on this fleet can't
  detect a dead worker without scraping the JSON status.
- **No-respawn rationale recorded in tree.** Issue #925 lists
  "automatic respawn implementation OR documented decision NOT
  to respawn (with rationale)" as an acceptance criterion. We
  decided NOT to respawn (rationale below) but didn't record it.
- **HA interaction note.** Issue #925 acceptance criterion
  requires "HA interaction documented and tested." Current
  behavior: a dead worker does NOT trigger chassis-cluster
  failover. That's a deliberate choice and needs a doc note.

## 2. Honest scope/value framing

This is a **doc + 1 Prometheus gauge** PR. Scope:

- ~30 LOC change in `pkg/api/metrics.go` (one new `*prometheus.Desc`,
  one `Describe` send, one emit-loop call).
- ~50 LOC of documentation in `docs/operations/worker-supervisor.md`
  (no-respawn rationale + HA interaction + how to alert on `dead`).
- **Required**: 1 Go unit test in `pkg/api/metrics_test.go` (or a
  sibling test file) asserting the metric appears in the `/metrics`
  endpoint output with value `1` when a `ProcessStatus` fixture has
  `WorkerRuntime[i].Dead = true`, and `0` otherwise. (Codex round-1
  Q-1 + round-2 confirmation: the metric is the entire point of the
  PR; not having a test is unacceptable.)

Win at absolute scale:

- The change does NOT improve throughput; this is reliability/
  operability closeout, not perf.
- The fleet-wide value is "one less alert blind spot." A worker
  panic without Prometheus exposure means an SRE has to know to
  poll the JSON status — they won't, so the panic stays invisible
  until it manifests as user-visible packet loss on that
  binding's flows.
- Cost is small (~80 LOC across two files + docs). PLAN-KILL is
  on the table if reviewers think this should just be folded into
  a future #925 Phase 3 that ships respawn too.

## 3. What's already shipped / partially batched

See §1 issue framing — Phase 1 is fully landed in master at
`753d4e8f` (current HEAD as of this plan). Phase 2 builds
strictly on top with no Rust **behavior or API** change. The
only Rust touchpoint is a stale-comment update in
`worker_runtime.rs:71-73` (see §4.3) — pure doc, no semantics.

## 4. Concrete design

### 4.1 Prometheus gauge

```go
// pkg/api/metrics.go (additions)

type xpfCollector struct {
    // ... existing fields ...
    workerDeadGauge *prometheus.Desc  // NEW
}

func newXPFCollector(...) *xpfCollector {
    return &xpfCollector{
        // ... existing init ...
        workerDeadGauge: prometheus.NewDesc(
            "xpf_userspace_worker_dead",
            "1 if the userspace-dp worker thread has panicked and been "+
                "caught by the supervisor; 0 otherwise. Cleared by daemon "+
                "restart (Phase 1 has no automatic respawn).",
            []string{"worker_id"}, nil,
        ),
    }
}

func (c *xpfCollector) Describe(ch chan<- *prometheus.Desc) {
    // ... existing sends ...
    ch <- c.workerDeadGauge  // NEW
}

func (c *xpfCollector) emitWorkerRuntime(
    ch chan<- prometheus.Metric, status dpuserspace.ProcessStatus,
) {
    for _, w := range status.WorkerRuntime {
        label := strconv.FormatUint(uint64(w.WorkerID), 10)
        // ... existing 7 emit calls ...
        var deadValue float64
        if w.Dead {
            deadValue = 1
        }
        ch <- prometheus.MustNewConstMetric(c.workerDeadGauge,
            prometheus.GaugeValue, deadValue, label)
    }
}
```

Metric type: `GaugeValue` (binary 0/1, can transition both ways
in principle — only daemon restart clears it today, but a future
Phase 3 respawn would also clear it).

### 4.3 Stale-wire-doc cleanup

Both wire-doc strings currently claim "Phase 2 (respawn) will clear
on relaunch":
- `pkg/dataplane/userspace/protocol.go:539-542`
- `userspace-dp/src/afxdp/worker_runtime.rs:71-73`

Update both to reflect actual state: Phase 1 set-only; cleared by
daemon restart; Phase 2 (this PR) adds Prometheus exposure but does
NOT add respawn. Hypothetical Phase 3 (deferred indefinitely) would
clear by replacing `WorkerRuntimeAtomics` on respawn.

### 4.2 Operations doc

New file: `docs/operations/worker-supervisor.md`. Contents:

- One-paragraph summary of Phase 1 supervisor (catch_unwind,
  mark-dead, no respawn).
- Suggested Prometheus alert:
  ```yaml
  - alert: XpfUserspaceWorkerDead
    expr: xpf_userspace_worker_dead == 1
    for: 30s
    labels: { severity: critical }
    annotations:
      summary: "userspace-dp worker {{ $labels.worker_id }} panicked"
      description: |
        Restart xpfd to recover. Investigation: check
        `cli show userspace-dp status | json` for panic_message.
  ```
- **No-respawn rationale.** Three reasons we chose not to
  auto-respawn in Phase 1/Phase 2:
  1. **Reentrancy hazard.** A panic mid-`poll_binding_process_descriptor`
     leaves the XSK rings, UMEM frame allocator, and conntrack
     entries in an arbitrary state. Re-entering the same worker
     loop without rebuilding all of that risks corruption that's
     worse than the outage.
  2. **Sticky-failure trap.** If the panic is deterministic
     (assert tripwire on a specific config / packet shape /
     session entry), an unconditional respawn loops forever and
     turns into a CPU-hot livelock. Sticky-failure detection
     adds enough complexity that it deserves its own design pass
     (deferred to Phase 3 if observability shows we need it).
  3. **Operator visibility.** A dead worker with a Prometheus
     gauge alert + clear panic_message is more actionable than a
     respawn that masks the bug. We'd rather page once than have
     an undebuggable flaky binding.
- **HA interaction.** Current state: a dead worker on the
  chassis-cluster primary does NOT trigger failover. Reasons:
  - The chassis-cluster failover state machine watches VRRP
    advertisements and the userspace-dp helper's "alive"
    heartbeat; it doesn't watch per-worker liveness.
  - A single dead worker affects only the bindings owned by that
    worker — not the whole node. The other 5 workers continue
    to forward.
  - Deliberately escalating to a node-level failover for a
    partial-outage condition would be a regression in HA
    semantics. If the operator wants that behavior, the right
    path is a node-level health check (Prometheus alert →
    operator-driven failover), not an in-daemon decision.

  This is documented; tested by inspection (no specific
  failover test added — the existing `make test-failover`
  harness exercises the VRRP path which is unchanged).

## 5. Public API preservation

- No Rust public API change.
- No protocol-wire change (Phase 1 already added `Dead` /
  `PanicMessage`).
- `pkg/api/metrics.go` exposes one NEW Prometheus metric name
  (`xpf_userspace_worker_dead`); the metrics endpoint adds a
  series, no removals.

## 6. Hidden invariants the change must preserve

- **xpfCollector cadence is the Prometheus scrape interval, NOT
  1 s.** Codex rounds 1+2 corrected earlier drafts of this plan:
  `xpfCollector.Collect` calls `provider.Status()` per scrape,
  which is a synchronous control-socket request with no internal
  cache. For the `dead` bit specifically, the userspace-dp's
  status handler reads `runtime_atomics.dead` directly
  (`userspace-dp/src/server/handlers.rs:413-415` →
  `coordinator/status.rs:144-147`), NOT batched through the per-
  worker counter publish cadence. Alert-to-page latency is
  therefore bounded by `scrape_interval + control_socket_rt`
  (typically 15-30 s + ~10 ms). The worker publish cadence (1 s
  in `worker/mod.rs:687-717`) does NOT add to `dead`-bit
  latency. The `for: 30s` alert clause absorbs both components.
- **Worker IDs are stable for the lifetime of the daemon.** The
  `worker_id` label values match the existing 7 metric series,
  so users grouping by `worker_id` get a coherent view.
- **`Dead` is set-only in Phase 1** — once flipped, only daemon
  restart clears it. The gauge will therefore read `1` until
  process restart even after the panic-causing condition is
  resolved. Document this on the metric description so SREs
  don't expect auto-clearing.

## 7. Risk assessment

| Class | Verdict | Notes |
|---|---|---|
| Behavioral regression | **LOW** | Pure additive metric + docs. No code path on the dataplane hot path is touched. |
| Lifetime / borrow-checker | **LOW** | No Rust behavior/API change (only the stale-comment refresh in `worker_runtime.rs:71-73`). |
| Performance regression | **LOW** | One extra `MustNewConstMetric` call per scrape (≤6 workers, scraped at 15s/30s typical). Negligible. |
| Architectural mismatch (#961 / #946-Phase-2 dead-end) | **LOW** | This is closeout of an already-shipped Phase 1; not a new architecture. |

## 8. Test plan

- `cargo build` clean (no Rust change beyond the 2 comment
  updates per §4.3, but build sanity).
- `cargo test --release`: unchanged from Phase 1 (954+ pass).
- `go test ./pkg/api/...` MUST include a new test asserting the
  `xpf_userspace_worker_dead{worker_id=...}` series appears in
  the `/metrics` output with value `1` when a `ProcessStatus`
  fixture has `WorkerRuntime[i].Dead = true`, and value `0`
  otherwise. (Codex round-1 Q-1: the metric is the entire point
  of the PR; not having a test is unacceptable.)
- Smoke matrix (per `triple-review` SKILL.md Step 6): full Pass A
  + Pass B 30 measurements (the change is fleet-side metrics; no
  expected throughput delta, but we still smoke to confirm zero
  regression).
- Optional manual verification: deploy, force a panic in a worker
  via a debug knob (or wait for an org-internal panic-injection
  fixture if available), `curl localhost:8080/metrics | grep
  xpf_userspace_worker_dead` — should show `1` for the affected
  worker_id, `0` for the rest.

## 9. Out of scope (explicitly)

- Automatic respawn (Phase 3 if ever needed).
- Sticky-failure detection.
- Coordinated state recovery (re-bind dead worker's queues to
  surviving workers).
- HA escalation rules ("dead worker → chassis-cluster failover").
- Test that exercises the metric end-to-end on the cluster (the
  manual-fixture path above is fine for now).

## 10. Open questions for adversarial review

1. Is the gauge alone enough value to justify a PR, or should
   this wait until Phase 3 ships actual respawn? (PLAN-KILL is
   acceptable if the reviewer thinks the gauge can wait.)
2. Should the gauge default to `0` for healthy workers, or be
   ABSENT until the first panic? (This plan: emit `0` always so
   the metric is always present in the time series and alerts
   don't fire on metric absence.)
3. Should `panic_message` be a separate Prometheus metric (as a
   `_info` gauge with the message in a label)? Or is the JSON
   status enough? **This plan: JSON status only.** Codex round-1
   Q-7 validated that putting raw panic-payload text in a
   Prometheus label is a cardinality + privacy trap. Codex also
   noted two safer alternatives that we DEFER (not in scope for
   Phase 2):
   - **Fixed `panic_class` enum** — add a small enum (e.g.
     `OOM`, `AssertTripwire`, `IOError`, `Other`) emitted as a
     label on `xpf_userspace_worker_dead`. Bounded cardinality,
     but requires panic-classification logic the supervisor
     doesn't have today.
   - **Fingerprint hash** — emit the first N bytes of a SHA-256
     of `panic_message` as a label. Bounded cardinality, more
     specific than an enum, but creates per-incident churn and
     makes alert deduplication harder.
   Both are real options; both belong in a future Phase 3 if
   alerting evidence shows the JSON-only diagnosis path is
   insufficient.
4. Is the no-respawn decision the right one? Reviewers should
   stress-test the rationale in §4.2 — particularly the
   sticky-failure-trap argument.
5. Should we add ANY automated test for the HA interaction, or
   is the "documented + manual verification" approach OK? Issue
   #925 acceptance criterion says "documented and tested" —
   reviewer call on whether the existing failover test plus the
   documented note is sufficient.
