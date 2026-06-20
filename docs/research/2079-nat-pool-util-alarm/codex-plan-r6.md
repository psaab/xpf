# Codex hostile plan review r6 — #2079

Agent: a5e91c91c6bb8319a. ~198s.

## Verdict: PLAN-READY-WITH-NITS (no MAJOR — first round Codex found no MAJOR)

The r5 MAJOR (#1 rule-referenced eligibility) is confirmed folded. Codex
independently cross-checked the rule-derived producer
(`userspace-dp/src/nat/status.rs:9-17`, `pkg/dataplane/userspace/nat.go:11-45`)
and confirmed §6.1 is consistent with it. "No blocking issues found."

Verbatim summary: "§6.1 builds `referenced` from `cfg.Security.NAT.Source` /
`rule.Then.PoolName`, iterates `referenced`, requires pool exists and is
non-deterministic, clears when the last referencing rule is removed, and missing
pool references contribute nothing. ... The transition logic and lock discipline
are adequate: raise `>=`, clear strict `<`, HOLD for absent/bad samples, prune
clears ineligible pools, `LastStatus()` is under manager lock, and active alarm
state is mutex-protected for both render sites."

### NITs (folded into r7)
1. Stale §9 row still said "Eligibility is CONFIG-derived / only config-removal
   /det-convert clears" — leftover r5 wording. r7: reworded to rule-referenced.
2. The referenced-rule scan should mirror `buildSourceNATSnapshots`' defensive
   `rs == nil` / `rule == nil` skips (`nat.go:16-22`) to avoid a panic on
   synthetic/partial configs. r7: nil-guards added to the §6.1 scan.

NOTE: separately, the fresh-session Codex r5 cross-check (aa74838bb97bb7ff7)
found two MORE substantive issues (gen-coherency #2, stuck-pct #3) that also
apply to r6; those are folded into r7 alongside these two NITs.
