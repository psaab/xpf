# AGY adversarial plan review r5 — #2079

Job: adversarial-review-mqmsmreo-eadvka

## Verdict: PLAN-READY

All three Codex-r4 findings verified folded; the r5 config-driven inversion was
stress-tested with no new issue:

- **#4 (absent-snapshot clear):** config-derived eligibility (iterates
  `cfg.Security.NAT.SourcePools`); configured-but-absent (b) and bad-sample (c)
  HOLD via `continue` while staying in `eligible` (not pruned).
- **#5 (lock discipline):** active keys snapshotted under the mutex; per-key
  syslog emitted outside the lock.
- **#7:** deterministic skipped in r1, persistent-NAT uses raw UsedPorts.

Inversion analysis (AGY-initiated):
- Config-only pools never in the snapshot cannot wrongly raise (`!present` →
  continue).
- Config-removed / det-converted pools ARE cleared (absent from `eligible` →
  prune clears).
- No double-emit (prune clears only pools omitted from evaluation; per-pool
  clears already removed their entry).
