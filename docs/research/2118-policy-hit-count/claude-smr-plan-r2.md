# Claude SMR plan review — #2118 — r2 (HOSTILE) — CONVERGENCE PASS

Reviewer: Claude SMR (in-conversation, hostile-by-mandate).
Plan reviewed: plan.md r3 (post reviewer A + reviewer B + SMR-r1).

## Verdict: PLAN-READY.

My r1 raised three issues. r2/r3 resolved all three, and the two
independent hostile reviewers (A: PLAN-NOT-READY→folded; B: PLAN-READY)
added two more MAJORs that are now also folded. Re-checking each:

- **SMR-r1 MAJOR-1 (H1a asserted not evidenced):** RESOLVED. r3 traces
  poll_descriptor/mod.rs:1700-1796 showing the increment-bearing eval
  drives both permit (session create) and deny (PolicyDenied) for new
  flows, and explicitly down-ranks H1a. Reviewer A independently found
  the SECOND eval site (mod.rs:2342) the original draft missed — now in
  §2/§4/§7/§11/§8.
- **SMR-r1 MAJOR-2 (force the policy-stats-on re-test):** RESOLVED. The
  GATING FORK is now the first thing in §4 and Step-1 action #0.
- **SMR-r1 MINOR-3 (implicit-deny parity unsourced):** RESOLVED. r3 marks
  "count the default line" as an xpf decision to confirm against vSRX,
  with the synthetic-counter implementation note (reviewer B) so it isn't
  routed through the empty-RuleID-skipping keyed store.
- **Reviewer A MAJOR (second increment site):** FOLDED into §2 (chain map
  row), §4 (note), §7 (transient over-count caveat), §11 (risk), §8
  (two-site invariant test).
- **Reviewer A MAJOR + Reviewer B MAJOR (re-rank H2):** FOLDED. H2 is now
  PRIMARY for the deny rows (correct-behavior, not a bug — the cluster has
  no explicit deny rules), permit rows are the only anomaly, §12 rewritten
  to lead with this.
- **Reviewer B MINOR (Option-B file:line):** FOLDED — corrected to
  "positional ID shifts on reorder".
- **Reviewers A+B (missing smoke doc):** FOLDED — §1 caveat.
- **Reviewer A MINOR (0 may be 1):** FOLDED — H2b + Step-1 exact-value
  requirement.

## Residual nit (accepted, non-blocking)
The GATING-FORK paragraph (§4) still frames the knob-ON outcome as
"populates → H4; still 0 → chain broken (H1b/H3)" without inline
cross-reference to H2b ("still 0" might be "actually 1"). The ranked list
below it covers H2b explicitly and Step 1 mandates reading the exact
value, so the fork is not misleading in context. Accepted as-is.

## Convergence
Three reviewers agree PLAN-READY: SMR (this), reviewer A (after fold),
reviewer B. Recommend Option A. The companion infra (Codex/AGY) is
degraded per the research directive; the 3-way is satisfied by 2
independent hostile Claude plan-reviewers + this SMR, all hostile-verified
against source (not synthesizer-by-default).

## Why this is PLAN-READY and not PLAN-KILL
The work is real and bounded: a live diagnosis pass (no code) settles
whether the permit-row 0 is the knob (H0/H4), a single-flow artifact
(H2b), or an Arc-divergence (H1b); the fix is small; and the
policy-stats display-gate unification (H4) is a genuine bug regardless.
The wire surface is reused (no new fields), #1961-safe, and the hot path
is one relaxed atomic on the cold path. Killing it would leave a core
Junos-parity observability primitive reading 0/inconsistent.
