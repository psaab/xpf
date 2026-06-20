# Claude SMR — Hostile Plan Review r6 — #2079

Reviewing plan.md r6 after folding Codex r5's PLAN-REVISE (#1 rule-referenced
eligibility + #2 stale §9 wording).

## Verdict: PLAN-READY

Codex r5 #1 was a genuinely deep, correct finding that both AGY and I missed at
r5 — it required reading the status PRODUCER, not just the consumer. The r6 fix
is correct, and I independently verified the underlying fact.

- **#1 (rule-unreferenced pool stuck alarm):** I confirmed
  `source_nat_pool_statuses(rules)` (`userspace-dp/src/nat/status.rs:9-17`) emits
  one entry per `rule` in `rules.filter(pool_mode)` — keyed by the rule's
  `pool_name`. So the snapshot only ever contains pools that a source-NAT rule
  references. A pool in `cfg.SourcePools` with no referencing rule is invisible to
  the monitor. r5's "eligible = every SourcePools entry" therefore HELD such a
  pool's alarm forever (it stayed eligible → never pruned, and never sampled →
  never cleared by the per-pool path). r6 makes eligibility RULE-REFERENCED
  (iterate `cfg.Security.NAT.Source` rules → `referenced` set → eligible only if
  referenced AND pool exists AND non-deterministic). Now removing the last
  referencing rule drops the pool from `eligible` → prune clears with a syslog
  clear. This also correctly handles "rule references a missing pool" (not
  eligible). RESOLVED.
- **#2 (stale §9):** reworded. RESOLVED.

## Independent re-trace of the r6 loop (all prior regressions still fixed)
- Eligibility source: now `referenced` (rule-derived), matching the producer. ✓
- Dedup: `byPool` dedups; capacity from one entry. ✓
- States: (a) unreferenced/removed/det → prune CLEARS; (b) referenced-but-absent
  → HOLD; (c) referenced-bad-sample → HOLD. The producer guarantees a referenced,
  rule-active pool DOES appear, so case (b) is genuinely transient (mid-apply /
  helper restart), not permanent. ✓
- Double-emit: per-pool clear removes the entry before prune ranges a key
  snapshot; prune clears only not-in-eligible. ✓
- Comparators / uint cast / nil-cfg / disabled / lock discipline / both render
  sites / commit validation: all unchanged from r5, all correct. ✓

## New issues from r6 — none
The rule-referenced predicate is the runtime-meaningful definition of "a pool
that can have utilization", and it aligns the monitor's eligibility with the
exact set the dataplane reports. This closes the eligibility-source question
completely (config-pools ⊋ rule-referenced-pools = the reportable set).

PLAN-READY. The plan has absorbed FOUR consecutive rounds of hostile second-order
review (r2→r5 each found one real defect, progressively narrower: dedup → nil/
prune/comparator → sample-vs-eligibility/syslog-symmetry → config-vs-snapshot →
config-vs-rule-referenced). The eligibility model is now exhausted.
