# Claude SMR — hostile plan review r6 (#3607) — CONVERGED

Reviewing `plan.md` v6 (adds `saturating_add` on the token accumulation).

## Verdict: PLAN-READY on Option B (reduced scope) — CONVERGED 3/3

v6 is v5 + one overflow-hardening (`tokens_q.saturating_add(refill_q).min(cap)`).
Codex round-6 = PLAN-READY (no remaining findings); AGY round-5 = PLAN-READY (the
v6 delta is a strict hardening consistent with the `saturating_sub` AGY itself
prescribed). No new hostile finding from me: the accumulation is now overflow-safe
at both ends (delta `saturating_sub`, accumulation `saturating_add`, clamp `.min`),
and no design element changed.

## Convergence summary (all three reviewers PLAN-READY)
- **Recommendation:** Option B — a monotonic-ns `TokenBucket` primitive for the
  single-threshold pure-drop / validate-budget limiters: **ICMP flood, UDP flood,
  the standby SYN-cookie ACK validation limiter (4096/s), and the SYN-flood
  aggregate DROP path when `syn-cookie` is OFF** (a per-zone bucket that is the
  SOLE drop authority there, so no cookie bypass and no double-quota). The
  SYN-flood aggregate under `syn-cookie` ON, the alarm measurement, the
  missing-profile warn dampener, and the #3315 per-source/per-dest sketch are
  deliberately UNCHANGED. Plus L10 (docs) + L14 (structurally resolved).
- **Deferred:** the #3315 sketch #3607 over-throttle (needs its own fail-closed
  analysis); the `syn-cookie` ON aggregate cookie-lock (Junos-consistent; a
  hysteresis refinement is a follow-up).
- **PLAN-DEFER-operator** remains an explicit fallback if the user weights blast
  radius over the accuracy gain (fix only L10 + optionally L14).

Issue stays OPEN, label `plan-deferred-research`, awaiting manual `/engineer`.
