# Claude SMR — Hostile Plan Review r5 — #2079

Reviewing plan.md r5 after folding Codex r4's PLAN-REVISE (#4/#5/#7).

## Verdict: PLAN-READY

Codex r4's #4 was a real and subtle gap, and the r5 fix is architecturally the
right one — making eligibility config-derived rather than snapshot-derived. I
independently agree.

- **#4 (absent-snapshot clear):** correct catch. In r4, `eligible` was still
  built by iterating `status.SourceNATPools`, so a configured pool that simply had
  no snapshot row this tick (transient — e.g. helper restart, mid-apply, a pool
  with zero rules momentarily) fell out of `eligible` and got pruned/cleared even
  though it was never removed from config. r5 inverts the iteration: it walks
  `cfg.Security.NAT.SourcePools` (config = source of truth for eligibility), marks
  every non-deterministic configured pool eligible, then looks up the snapshot per
  pool — absent (case b) and bad-sample (case c) both HOLD, only config-removal/
  det-conversion (case a) clears. This is the clean three-state model. The prune
  loop now correctly clears only case (a) because `eligible` no longer depends on
  snapshot presence. RESOLVED.
- **#5 (lock discipline):** correct and important for implementation — the
  active-alarm map is shared with the render sites, and syslog I/O can block. r5
  mandates snapshot-keys-under-mutex then emit-outside-lock. RESOLVED.
- **#7 (stale deterministic wording):** §9 fixed. RESOLVED.

## Independent re-check of the r5 loop
I traced the r5 pseudocode for the regressions Codex's earlier rounds found:
- Double-count (dedup): still correct — `byPool` dedups, capacity from one entry.
- Double-emit: a pool cleared in the per-pool loop is removed from `activeAlarms`;
  the prune snapshots keys and clears only not-in-`eligible` pools; a
  per-pool-cleared pool IS eligible, so never double-cleared. OK.
- nil-cfg / disabled: early-return clears all + empties, before touching snapshot. OK.
- comparators: raise `>=`, clear strict `<`. OK.
- uint cast order: operands cast first. OK.

## New issues from r5 — none
Config-driven iteration is the correct inversion; the lock note is standard. No
new edges.

## Residual NIT (engineer-time)
- The case-(b) HOLD means a configured pool that NEVER appears in the snapshot
  (e.g. misconfigured so the helper never instantiates it) can never RAISE (it has
  no UsedPorts to measure) — which is correct (no data = no alarm), and it also
  won't spuriously clear an existing alarm. Worth a one-line doc note that "a pool
  the dataplane never reports is simply never alarmed", but not blocking.

PLAN-READY. The plan has now absorbed three consecutive rounds of hostile
second-order review (r2/r3/r4 each found a real pseudocode defect) and the design
is stable.
