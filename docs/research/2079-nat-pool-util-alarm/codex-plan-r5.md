# Codex hostile plan review r5 — #2079

Agent: ae09617e55b8e5564 (slow ~5.5 min, returned a full verdict — NOT wedged).
A fresh-session retry (aa74838bb97bb7ff7) was also dispatched as a cross-check.

## Verdict: PLAN-REVISE (confirmed all 3 r4 folds; 1 NEW MAJOR + 1 NIT)

### Confirmed (r4 folds all resolved)
- #4 config-derived eligibility: CONFIRMED-FOLDED.
- #5 lock discipline: CONFIRMED-FOLDED.
- #7 deterministic/persistent wording: CONFIRMED-FOLDED.
- Re-confirmed: config-removed/det-converted still clear; no double-emit; dedup
  by pool name intact (shared allocator source.rs:281-290).

### NEW findings (folded into r6)
1. **MAJOR — rule-unreferenced configured pool keeps a stale alarm FOREVER.**
   The status PRODUCER is rule-derived: `source_nat_pool_statuses(rules)` iterates
   `rules` (`userspace-dp/src/nat/status.rs:9-17`); Go `buildSourceNATSnapshots`
   iterates `cfg.Security.NAT.Source` (`pkg/dataplane/userspace/nat.go:11-45`).
   So a pool configured but referenced by NO source-NAT rule never appears in
   `SourceNATPools`. r5 marked every `cfg.SourcePools` entry eligible → such a
   pool HOLDs (case b) forever and the prune never clears it. Concrete: pool P
   has an active alarm; a commit removes every rule referencing P but leaves P
   configured → alarm sticks, violating the clear-on-withdrawal contract.
   FIX (r6): eligibility = referenced by ≥1 configured source-NAT rule AND pool
   exists AND non-deterministic. Verified the rule-derived producer in source.
2. **NIT — stale §9 wording:** "Prune activeAlarms for absent pools each tick"
   reads like the r4 bug; r6 reworded to "pools no longer eligible by
   rule-referenced config semantics".

Codex confirmed: no wrong-raise for a never-sampled pool (it `continue`s before
`pct`); the defect is only the stuck-alarm-on-unreference case. Both folded r6.
