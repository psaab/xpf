# Claude SMR final attestation — round 4 (plan v9, c0ad0bd07)

My r3 SMR attested PLAN-READY on v6. The v7-v9 deltas are exclusively
reviewer-driven narrowings (attempt-boundary hygiene → completion-site
cleanup relocation), each verified by the reviewer who demanded it:

- v7 (Codex r4 F3 + AGY r4 H1-H3): call-path + mutation-locus + boundary
  hygiene. Audited: consistent with the read-only timer_pass contract.
- v8/v9 (Codex r5/r6): all success-side cleanup inline at the
  authenticated completion site, before same-iteration TUN egress;
  attempt.drive success only clears the attempt. Audited the one residual
  trace I could construct — completion with NO active attempt draining a
  pre-completion edge: obsoleted by the completion by definition;
  unconfirmed-responder egress re-arms within the 1/s rate limit (bounded
  ≤1s, identical to today's NoSession behavior). No regression.

Final cross-check of the §3 section of record against the v9 machinery:
every timer (T1-T9) has an enforcement locus, a pacing/arming rule, a
skip rule, a test, and a telemetry counter. The plan is implementable
without further design decisions beyond explicitly-deferred naming.

**Verdict: PLAN-READY** (Path A — combined timers + poll conversion).
