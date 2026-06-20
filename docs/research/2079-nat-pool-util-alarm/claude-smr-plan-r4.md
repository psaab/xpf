# Claude SMR — Hostile Plan Review r4 — #2079

Reviewing plan.md r4 after folding Codex r3's PLAN-REVISE (#5/#6/#7).

## Verdict: PLAN-READY

Codex r3's two NEW MAJORs were legitimate second-order defects, and r4 resolves
both cleanly. I independently agree with the analysis and the fixes.

- **#5 (transient-sample clear):** correct and important. In r3, marking
  `eligible` only after the capacity guard meant one bad snapshot (mid-reconfig
  `AddressCount==0`, or a transient bad port range) would drop the pool from
  `eligible` and the prune step would CLEAR a legitimately-raised alarm — a
  spurious clear/flap. r4 splits the two concerns: SEMANTIC eligibility (in cfg +
  non-deterministic) is marked BEFORE the sample guards, so an uncomputable
  sample now HOLDS (no raise, no clear, no prune) and re-evaluates next tick. This
  is the correct "if you can't measure it, don't change the asserted state"
  semantics. RESOLVED.
- **#6 (silent withdraw vs syslog contract):** correct. A monitoring contract
  that emits a raise on syslog must emit the matching clear, else external
  consumers leak a stuck "raised" state. r4 makes every withdrawal path
  (drop-below, prune for removed/renamed/det-changed, and the disabled/nil-config
  early-return) emit a clear; only the no-transition HOLD is silent. §6.4 now
  states this symmetry explicitly. RESOLVED.
- **#7 (stale text):** §9 risk table and §10 now reflect the resolved hard
  commit-error (`0 < clear < raise <= 100`) instead of the stale "commit-warn" /
  open-question wording. RESOLVED.

## New issues from r4 edits — none
The eligibility-before-sample-guard restructuring is a clean separation; the
clear-on-withdrawal is the standard symmetric-notification pattern. No
regressions, no new edge introduced.

## Residual NITs (engineer-time, non-blocking)
- The clear-on-feature-disable design choice (emit clears when the operator
  removes `pool-utilization-alarm` from config) is defensible and now explicit;
  an implementer could alternatively treat operator-disable as silent, but the
  plan's symmetric choice is the safer default and is what r4 specifies — keep it.
- §6.1 should ensure the disabled/nil early-return also emits clears (the
  pseudocode now says "clear EVERY activeAlarms entry (emit clear, then empty)")
  — consistent.

PLAN-READY from my side. The plan has now survived two rounds of hostile
second-order review (r2 + r3 each surfaced real pseudocode defects) and is tight.
