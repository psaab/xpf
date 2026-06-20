# AGY adversarial plan review r8 — #2079

Job: adversarial-review-mqmtgce3-ao2bh6

## Verdict: PLAN-REVISE (1 MAJOR; all other r8 folds confirmed)

**MAJOR — `HelperCaughtUp` predicate still admits the skew.** r8 defined
`HelperCaughtUp := status.LastSnapshotGeneration == m.publishedSnapshot`. In the
deferred snapshot apply window (XSK startup, `manager.go:642/648`), `m.lastSnapshot`
is advanced to the new gen (e.g. 7) while `m.publishedSnapshot` still lags (e.g. 6).
If the helper reports gen 6, `status == publishedSnapshot` (6==6) passes TRUE, so
`numericEval` runs and evaluates the new gen-7 `view.Config` capacity against gen-6
counters — the exact skew r8 was meant to kill.
FIX: `HelperCaughtUp := status.LastSnapshotGeneration == view.Generation`
(= `m.lastSnapshot.Generation`, the gen `view.Config` belongs to).

Confirmed correct: §6.1 uses only `view.*` (no store.ActiveConfig()); numericEval
gates numeric eval while the config-derived prune runs; `view.Available==false`
returns early holding all alarms; dedup inside the view is correct (shared Arc →
identical UsedPorts).

Folded into r9.
