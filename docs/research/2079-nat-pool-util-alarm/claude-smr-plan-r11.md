# Claude SMR — Hostile Plan Review r11 — #2079

Reviewing plan.md r11 after folding Codex r10's BLOCKER (deferred-apply
reconcile-skew) + #3 (first-boot gen==0) + #4 (NIT).

## Verdict: PLAN-READY

The Codex r10 BLOCKER was real and I (and the premature r10 "converged" call)
missed it. I independently verified it against source and the r11 fix is correct.

- **BLOCKER (deferred-apply reconcile-skew):** Verified `apply_snapshot` sets
  `guard.status.last_snapshot_generation = snapshot.generation` unconditionally on
  accept (`snapshot.rs:63`), while the `defer_workers` branch
  (`snapshot.rs:113-144`) stores the snapshot, does a prune-only WG/GRE pass, and
  SKIPS `reconcile_status_bindings` (only the non-deferred branch at :143 calls
  it). NAT pool status comes from `state.afxdp.source_nat_pool_statuses()`
  (`helpers.rs:244`) — coordinator forwarding state replaced only on reconcile.
  Go sets `DeferWorkers` from `m.deferWorkers` (`manager.go:677-679`), cleared on
  `NotifyLinkCycle`. So r10's `status==appliedGen` could be true with stale NAT
  counters. r11 closes it two ways: (a) record `appliedSnapshot` ONLY on a
  RECONCILED apply (non-deferred, or post-NotifyLinkCycle), never on a
  deferred-but-accepted apply; (b) `Coherent` also requires `!m.deferWorkers`.
  Both are needed — (a) ensures the stored Config matches reconciled counters,
  (b) closes the window between accept and reconcile. RESOLVED.
- **#3 (first-boot/restart gen==0):** treating gen==0 (no reconciled applied
  snapshot) as `Available=false` HOLD rather than `cfg==nil` clear-all is correct
  — a helper restart must not false-clear pre-restart alarms before the first
  reconcile. RESOLVED.
- **#4 (NIT):** verified the plan's setter ref is the correct
  `server/handlers/snapshot.rs:63`; no stale `afxdp/coordinator/snapshot.rs` path
  remains. RESOLVED.

## Independent re-trace of r11
- View source: `appliedSnapshot` (RECONCILED apply only). Config + Pools the
  reconciled gen. ✓
- `!Available` (dp nil / helper down / gen==0 no-reconciled) → HOLD-all. ✓
- `!Coherent` (status!=appliedGen OR deferWorkers) → HOLD-all. ✓
- cfg nil / disabled → clear-all (deferred if not coherent/available). ✓
- Once Available+Coherent: numericEval true (reconciled config+counters coherent). ✓
- Eligibility rule-referenced; dedup in view; raise/clear/updatePct; prune; lock
  discipline; both render sites; commit validation; uint cast. ✓
- FIB/neighbor bump AND deferred-accept both do NOT make the view Coherent with a
  newer gen → the alarm holds, never evaluates stale counters, never false-fires. ✓

## New issues from r11 — none
The reconcile-gated applied source + `!deferWorkers` is the complete coherency
condition: the view reflects exactly the forwarding state whose counters the
helper is reporting.

## Process note (important)
The r10 "3-way converged" was WRONG — driven by a fast retry's "No findings"
while the slower original Codex pass (which found the BLOCKER) was still running.
The plan doc, ledger, and issue will be corrected to show r11 as the true
convergence target. Lesson recorded in the r11 changelog.

PLAN-READY (pending r11 external re-confirm).
