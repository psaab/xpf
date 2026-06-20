# AGY adversarial plan review r6 — #2079

Job: adversarial-review-mqmsy5w7-s7r6et

## Verdict: PLAN-READY

"The plan at revision r6 is complete, correct, and successfully addresses all
prior findings without introducing new risks."

1. **Eligibility rule-referencing (§6.1):** builds `referenced` from
   `cfg.Security.NAT.Source` rules (not all SourcePools); eligible = referenced
   AND exists AND non-deterministic. Removing a pool's last referencing rule
   excludes it → prune clears.
2. **§9 wording:** updated to "rule-referenced config semantics".
3. **Missing pools / transient holds:** rules referencing missing pools excluded
   from eligible (no stuck alarm for invalid config); transient absent-snapshot
   HOLDs (no accidental clear).
4. **Dedup & double-emit:** hysteresis (raise `>=`, clear strict `<`) and
   pool-name dedup intact and robust.

No new issues.
