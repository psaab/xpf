# Claude SMR — Hostile Plan Review r3 — #2079

Reviewer: Claude SMR (hostile). Reviewing plan.md r3 after folding Codex r2's
PLAN-REVISE (NEW-1/2/3 + FOLD-5).

## Verdict: PLAN-READY

Codex r2's three NEW findings were legitimate pseudocode-quality defects (not
infra noise — the agent completed, just slowly). All are correctly folded in r3,
and I independently confirm the underlying facts:

- **NEW-3 (nil cfg):** verified `Store.ActiveConfig()` returns `s.compiled` which
  is nil when no config is compiled (`store.go:1573-1577`; fail-closed nil is a
  documented invariant). r3 §6.1 nil-guards `cfg` first and clears-all-silently.
  RESOLVED.
- **NEW-2 (prune gap):** correct catch — in r2 a pool that stayed in the cached
  snapshot but was removed from config (or flipped to deterministic) hit
  `continue` and was never pruned, so its alarm stuck. r3 introduces an
  `eligible` set (in-config AND non-deterministic) populated only for pools that
  pass all guards, and prunes any active alarm not in `eligible`. This now covers
  removed/renamed/det-changed/underflow-guarded-out pools. RESOLVED.
- **NEW-1 (clear comparator):** r2's text ("drops below") and pseudocode (`<=`)
  disagreed. r3 uses RAISE `>=`, CLEAR strict `<` consistently in both §6.2 and
  the pseudocode, with a boundary unit test. RESOLVED.
- **FOLD-5 (uint cast order):** real — `uint64(s.PortHigh - s.PortLow + 1)` does
  the uint16 math before promotion. r3 casts operands first
  (`uint64(PortHigh)-uint64(PortLow)+1`) and the guard likewise. RESOLVED.

## New issues from r3 edits — none
The `eligible`-set reconcile is the standard desired-state pattern (the backing
set equals the desired set after every tick — matches the project's repeated
"membership must be atomic with the action" lesson). The nil-guard and
clear-all-silently are straightforward. No regressions.

## One NIT (engineer-time, non-blocking)
- **n1:** "clear-all-silently" on the disabled/nil-cfg early returns must iterate
  and remove every entry in `activeAlarms` (not just stop firing), so a config
  that turns the alarm off actually withdraws already-raised alarms from `show
  security alarms`. The pseudocode says "clear-all-silently-and-return"; ensure
  the implementation empties the map (and, if syslog-on-clear is desired for the
  config-disable transition, that is a design choice — silent is fine and
  matches "operator turned it off"). Covered by the NEW-3 unit test if it asserts
  the active set is empty after a nil/disabled tick.

PLAN-READY from my side. The plan is now tight enough to implement directly.
