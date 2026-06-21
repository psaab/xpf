# Claude SMR plan review — #2118 — r1 (HOSTILE)

Reviewer: Claude SMR (in-conversation, hostile-by-mandate).
Plan reviewed: plan.md r1 (pre-convergence draft).

## Verdict: PLAN-NOT-READY (r1) — three substantive issues.

The plan is honest about the most important thing (the chain exists and
the bug is live-only), which is good and rare. But a hostile read finds
three issues that must be fixed before convergence.

### MAJOR-1 — the plan's own §2 contradicts the issue, and the plan doesn't resolve it
§2 proves the full chain is intact AND §4 says the Go read path is
unit-tested green. If both are true, the table should be nonzero. The
plan correctly calls this "live-only" but then §4 H1a is hand-wavy: it
asserts permitted flows "took a disposition branch that bypasses
`evaluate_policy_result_with_len`" WITHOUT showing that such a branch
exists for the *normal* permit case. If the only way to permit a new
flow is `ForwardCandidate` → policy eval, then H1a is false and the bug
is elsewhere. The plan must either (a) point at the specific
permit-without-policy-eval branch in poll_descriptor (the "Permit
without policy check or session install" comment at mod.rs:1078 is a
strong lead the plan half-cites but doesn't run down), or (b)
down-rank H1a. As written, the leading hypothesis is asserted, not
evidenced.

### MAJOR-2 — the policy-stats-off explanation makes the bug possibly NON-EXISTENT, and the plan doesn't force that question
§3 establishes the smoke likely ran with `policy-stats` OFF, and #2008
M4 says counts should be 0 when off. If the increment is currently
ungated (it is) and the display is currently ungated (it is), then with
the knob off the live counts WOULD still be nonzero and WOULD display —
unless the chain is broken. The plan needs to state plainly: **the very
first action in Step 1 is to re-run with `policy-stats enable` and
confirm whether the bug reproduces at all.** If it does NOT reproduce
with the knob on, then #2118 collapses to H4 only (display-gate
inconsistency) and the "live increment is broken" framing is wrong. The
plan must make this the gating fork, not bury it in H2/§6.

### MINOR-3 — Junos parity claim on the default-deny hit count is unsourced
§6 Step 2 and §8 assert "Junos shows a hit count on the implicit deny
too" and the plan proposes counting the default-action path. That is a
behavior change (today only explicit rule matches increment). Whether
Junos increments the implicit-deny hit count is a factual claim that
should be sourced or marked as a deliberate xpf decision, not stated as
parity fact. If it's wrong, adding it diverges FROM Junos.

## Smaller notes
- §9's "preserve across recompile (divergence from Junos)" is a good
  catch and correctly kept, but the issue explicitly asks "whether to
  reset counts on policy change (Junos resets on commit)". The plan
  decides NOT to reset and documents it — acceptable, but the issue
  comment must call this decision out so the user can veto it.
- §10 lists coordinator ArcSwap files "only if H1b" — fine, but the
  failover-test gate in §8 should be unconditional if ANY Rust
  forwarding-path file is touched, not just under H1b.

## What's right
- Reusing `policy_rule_counters` (no new wire surface) is correct and
  #1961-safe. Numeric + serde-default/omitempty confirmed.
- Hot-path cost analysis is sound (once-per-flow relaxed atomic).
- Rejecting Option B (positional key) on the recompile-misattribution
  argument is correct and well-reasoned.
