# Claude SMR hostile plan review — #6751 plan v10 (round 10, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v10 is my own fold of Codex r9's
alias-first blocker; this pass re-walks the wire-form-yield rule's merge
mechanics (the part AGY r10 and I had to specify mid-walk) and the
pub_token choke. Codex r10 was in flight when this was written.

## Wire-form-yield rule, independently re-walked

Both of AGY r10's scenario walks match the code and the v10 text:

- **Scenario (a) (legit alias-first)**: alias reserves and publishes;
  base arrives and conflicts; clause (i) fires (`forward_wire_key(H→S,
  nat) == E→S`, identical decision) and the base wins. Verified the
  lookup consequence: the base's publish populates the derived
  forward-wire index (shared_ops.rs:943-957), so fabric-return lookups
  resolve to the base and reverse synthesis reads the base's real client
  source (shared_ops.rs:678/738). The r9 worst case (alias survives,
  base dropped) is dead.
- **Scenario (b) (Codex r8's mis-attachment retry)**: B's base
  (`H_B→S`) vs A's base (`H_A→S`) — neither is the other's wire form
  (each wire form is the shared `E→S`), so clause (ii) drops B's base
  (the promised genuine-collision posture). B's alias IS the wire form of
  A's base with an identical decision, so clause (i) merges it — and that
  merge is benign because B's alias row is byte-identical to A's own
  alias row (same key, same decision; the only differing metadata is
  accounting-level). The r7/r8 mis-attachment concern collapses to a
  no-op for predicate-matching aliases precisely because predicate-
  matching aliases are byte-identical.

## Self-found precision nit (folded into v10.1)

### N18 — the merge must state the fate of the alias's already-published canonical row

In scenario (a) the alias import had ALREADY published its canonical row
(at key `E→S`) before the base arrived and won. v10 says the alias's
"markers and identity fold into the canonical-form import's record" but
does not say what happens to that published row. Two coherent answers:
sweep it (the derived forward-wire index covers the lookup — AGY r10's
reading), or RETAIN it (it is byte-identical to the alias row the base
itself would export — retaining avoids sweep+re-export churn). v10.1
specifies RETAIN: the alias's published canonical row stays, now serving
as the base's alias row (its holder units transferred to the base's
record in the merge); the peer's next re-export refreshes it
idempotently. This is the least-churn answer and matches the steady
state the export stream converges to anyway.

## pub_token choke, verified

`publish_shared_session` (shared_ops.rs:897) is the single choke every
publication path funnels through (session_import.rs:133/206, local
publish at poll_descriptor/mod.rs:2591, tunnel prewarm tunnel.rs:748/756,
activation prewarm shared_ops.rs:391 — AGY r10's enumeration matches my
own grep of publish_shared_session callers from round 1). Stamping
`entry.pub_token = next_pub_token()` inside the choke covers canonical +
derived rows of one publication; token-0 rows are pre-PR legacy only.
The §6 additive-internal-field note is accurate (no wire shape change).

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives. N18 (retain the
merged alias row) folds into v10.1 wording; AGY r10's carried nit
(V4+V6 alias test parity) is an implementation-time test item already
implied by §9. If Codex r10 converges, this is terminal.
