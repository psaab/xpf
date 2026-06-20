# Claude SMR — Hostile Plan Review r7 — #2079

Reviewing plan.md r7 after folding: the Codex r5-retry cross-check #2/#3
(gen-coherency, stuck-pct) and the Codex r6 two NITs (stale §9 row, defensive
nil-skip).

## Verdict: PLAN-READY

r7 closes the two remaining substantive issues plus the cosmetic NITs. Codex r6
itself returned PLAN-READY-WITH-NITS (no MAJOR) on the r6 base, and the r7 deltas
are correct.

- **#2 (gen-coherency):** real and correctly handled. `ProcessStatus.
  LastSnapshotGeneration` (protocol.go:618) can trail the manager's applied
  `lastSnapshot.Generation` during apply/XSK-startup; evaluating fresh config
  capacity against stale counters would misfire. r7's `numericEval := status.
  LastSnapshotGeneration >= dp.AppliedSnapshotGeneration()` gate HOLDs numeric
  raise/clear when the helper lags, while the config-derived prune still runs
  (correct — config-removal/unreference clears don't depend on dataplane
  counters). The accessor is a cheap lock-guarded read, consistent with the
  LastStatus() pattern. RESOLVED.
- **#3 (stuck pct):** real consistency gap — §6.3 advertised a live pct but only
  transitions updated state. r7's `updatePct` refreshes the displayed value for a
  held pool with NO syslog (no transition). Correctly placed in the
  else-if-raised branch so it never runs on a transition tick. RESOLVED.
- **Codex r6 NIT1 (stale §9 row):** reworded to rule-referenced. RESOLVED.
- **Codex r6 NIT2 (defensive nil-skip):** §6.1 scan now skips nil `rs`/`rule`,
  mirroring `buildSourceNATSnapshots`. RESOLVED.

## Independent re-trace
The else-if chain (raise / else-if clear / else-if-raised updatePct) is mutually
exclusive and correct: a transition takes exactly one of raise/clear; a held pool
above clear takes updatePct; a held pool below raise but above clear with no prior
alarm takes none. The `numericEval` gate sits before the per-pool sample logic and
after eligibility marking, so eligibility (and thus the prune) is unaffected by
helper lag — exactly the intended separation. No new edge.

## New issues from r7 — none
The generation gate is the standard "don't mix fresh config with stale dataplane
state" guard; updatePct is a pure display refresh. Both are minimal and correct.

PLAN-READY. Codex's MAJOR-finding streak ended at r6 (PLAN-READY-WITH-NITS); r7
folds the cross-check's two substantive items + the two NITs. The design is
complete: eligibility (rule-referenced), coherency (generation-gated), hysteresis
(exact comparators + commit validation), withdrawal symmetry (all clears emit
syslog), display freshness (updatePct), concurrency (snapshot-keys-then-emit), and
both render sites — every dimension a reviewer raised across 6 rounds is closed.
