# Claude SMR — hostile plan review r2 — #2238

Reviewing plan r3 (which folded Codex-r1 + AGY-r1 + my r1). Verdict:
**PLAN-READY (Path B).**

## Convergence on the one real blocker

My r1 raised fail-open vs fail-closed as the most-arguable point (Q1) and
explicitly invited override. Both Codex-r1 and AGY-r1 returned PLAN NO with the
SAME finding: §6.2 fail-OPEN is a security bypass because an output-filter
`discard` is a security boundary. That is the correct framing and it overrides
my r1 lean. Plan r3 flips §6.2 to **fail-CLOSED (drop) + mandatory counter**. I
concur fully — this is the convergent, defensible position and it is now
consistent with the rest of the fail-closed project.

## Codex's second blocker (Path B not committed) — also correct

Codex-r1 flagged that r2 presented Path A/B/C as a menu, leaving Path A
re-openable. Path A has a real hazard (routing local replies into the transit
`PendingForwardRequest` loop + the dispatch mirror being input-direction, so its
"free mirror" is illusory and its re-injection risks wrong-direction handling).
Plan r3 makes Path B the COMMITTED decision with A/C rejected-with-reason. Good
— this is the engineering-style "narrow scope / don't re-litigate" discipline.

## Codex implementation notes — verified non-blocking

- ICMP-type keying: the plan never depended on icmp-type matching (only
  `protocol icmp` + addresses). r3 §8.1 makes that explicit so no reviewer
  misreads it as a requirement. ✅
- Counter wiring (two-tier BatchCounters + live/snapshot) and Time Exceeded
  multi-call-site: these are real wiring breadth, captured in r3 §8.1 as
  `/engineer` work, with the "one shared choke point" preference. They do not
  change the design. ✅

## Re-attack on the fail-closed flip (am I now wrong in the other direction?)

A fair counter-attack: does fail-closed now risk a silent control-plane outage
if the parser has a systemic bug (drops ALL Time Exceeded)? No — the dedicated
counter makes it loud, and the failure is gated on OUR-built bytes (a real
parser bug would be caught by the round-trip builder tests in §9, which feed
real built frames through the parser). The blast radius of "drop a control
reply on our own logic bug" is strictly smaller than "leak past a security
filter." Fail-closed wins. ✅

## Things still clean (unchanged from r1)

No double-count (single `resolve_cos_tx_selection_at` per reply); no HA/fabric
state leak; no hot-path allocation (cold paths only); budget gate ordering
preserved. ✅

## Residual open items (NON-blocking, named follow-ups)

- Embedded-ICMP NAT-reversal sibling (§10) — file it; I conceded r1 deferral.
- Output-direction port-mirror (§10) — file it; correct scope fence.
- icmp-type filter matching as a future filter-engine feature (§8.1) — file if
  an operator needs it; out of this bug's scope.

**SMR r2 verdict: PLAN-READY (Path B).** All three reviewers converge: Path B,
fail-closed §6.2, scope-fenced mirror + NAT sibling. No blocking defect remains.
