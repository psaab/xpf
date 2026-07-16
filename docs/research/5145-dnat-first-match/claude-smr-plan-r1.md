# Claude SMR — hostile plan review r1 — #5145 DNAT first-match

Reviewing `plan.md` @ 12c4a3fa156e. Posture: hostile. I verified every factual
claim in the plan against the code firsthand before writing this.

## Factual claims — verified

- **Cross-tier short-circuit is real.** `lookup_with_counter` (destination.rs
  ~636-690) chains exact → wildcard-port → PROTO_ANY → prefix-LPM via `.or_else`;
  first non-`None` tier wins. ✓
- **Within-prefix-tier longest-wins is real.** `best_in_tier` (destination.rs
  ~880-885) replaces on strictly-greater `prefix_len()`, config order only
  breaking equal-length ties. ✓ So the plan is right that the divergence is BOTH
  cross-tier AND within the prefix tier (D2).
- **Documented-intentional.** destination.rs:747-756 explicitly states
  "MOST-SPECIFIC-WINS … NOT strict Junos config order." ✓ Reversing it is the
  substance of the issue, not a bug fix.
- **Go emits in config order.** `buildDestinationNATSnapshotsWithFeeds`
  (nat_destination.go:97-101) iterates RuleSets then Rules in slice order; the
  `sort.SliceStable` in compiler_validate_strict_nat.go is error-reporting-only.
  ✓
- **Additive wire field is feasible.** `DestinationNATRuleSnapshot`
  (protocol.go:680) is a JSON struct with a documented additive-evolution
  convention (#1961). ✓
- **Per-session-miss cost claim is CORRECT.** The sole production caller of the
  rule table (`dnat_table.lookup_with_counter_scoped`) is
  poll_descriptor/mod.rs:1558, and the enclosing block is the session-miss
  handler — `telemetry.counters.session_misses += 1` at line 1387 precedes it. ✓
  This is the plan's single most important de-risking fact and it holds.

I found no factual error in the plan. That is necessary but not sufficient.

## Hostile findings

### H1 — The plan UNDER-sells a second behavior flip: interface-vs-zone is currently INVERTED, and Option A reverses it.

`match_entries` prefers `from_zone`-non-empty (zone-specific) over
`from_zone`-empty (destination.rs ~761-773). An **interface-scoped** DNAT
rule-set has `from_zone` EMPTY (it carries `from_interface`), so today it sits
in the "zone-wildcard" bucket and **LOSES** to a zone-scoped entry in the same
tier. That is backwards from Junos (interface > zone). Option A's context rank
(interface=0 < zone=1) **flips** this: interface would now win. This is
*correct* (a latent-bug fix), **but the plan lists it only as a "verify the
subsumption" aside in §5.4 point 4.** It is a genuine cross-rule-set behavior
change and belongs in §8's regression table explicitly. **Required plan edit:**
call out the interface-vs-zone flip as a distinct, intended behavior change, and
add a unit test asserting it (the plan's test #6 covers the direction but the
prose must own that this REVERSES current behavior, not merely "adds"
precedence).

### H2 — The single fused ordinal is fine, BUT the plan should mandate lexicographic (rank, seq), not a hand-fused integer.

§5.3 point 2 suggests `ordinal = ruleSeq` (a single counter over the
context-sorted walk). That works only because the walk is pre-sorted by rank.
This is fragile: any future change to the emission loop that reorders rule-sets
silently corrupts precedence. Q5 already asks this; my verdict is **the plan
should PREFER carrying `context_rank` and `config_seq` as two fields compared
lexicographically on the Rust side**, OR, if fusing, document the invariant
"emission MUST be rank-sorted before seq assignment" as a load-bearing comment
with a Go test that asserts a rank-2 rule never gets a lower ordinal than a
rank-0 rule. A bare `ruleSeq` with the invariant buried in a walk order is a
latent footgun. Not a PLAN-KILL, but a required hardening.

### H3 — The HA "no version gate" conclusion rests on an UNVERIFIED claim. This is the biggest open risk.

§7 asserts synced sessions replay the resolved DNAT (via `publish_dnat_table_entry`)
so the peer never re-runs the rule lookup — therefore no flag-day. **I did not
verify this end-to-end and the plan admits it hasn't either** ("Reviewers must
confirm"). If, in fact, a synced session on the peer re-derives the DNAT by
re-running `lookup_with_counter` against the peer's (possibly older) rule table,
then a rolling upgrade produces asymmetric translation for the SAME flow across
the cluster — a real HA correctness bug, not a transient. **This claim must be
proven (trace session_delta/ha.rs → dnat_table publish/consume) BEFORE PLAN-READY
is meaningful, or the plan must adopt a version gate as the safe default.** As
written this is the load-bearing assumption and it is only asserted. Downgrade
the plan from "no gate needed" to "gate unless proven otherwise."

### H4 — Q1 (Junos fall-through) is correctly flagged but the plan lets it ride too casually.

The plan calls the multi-rule-set fall-through an "exotic edge." It is exotic,
but the whole ordinal MODEL depends on the answer: lowest-ordinal-argmin
*implements fall-through by construction* (a lower-context rule-set's rule wins
only when the higher-context rule-set has no matching rule). If Junos does NOT
fall through, Option A is subtly wrong for that case and the fix would need
rule-set-scoped selection (materially more code). The plan is honest that a
citation is required, which is the right research posture — but it should state
plainly that **without the citation, Option A cannot be declared correct**, and
that the citation gate belongs at PLAN-READY, not deferred to /engineer. This is
the difference between "PLAN-READY to implement" and "PLAN-READY as a
decision-surface for the user."

### H5 — Recommendation A vs C is genuinely the user's call; the SMR will NOT rubber-stamp A.

The plan recommends A (full rewrite). My hostile read: given (a) the divergence
is documented-intentional, (b) the common exemption idiom already works, (c) the
fail-open bites only the unusual broad-off-before-specific-translate ordering,
(d) A carries MED–HIGH regression risk PLUS an unproven HA assumption (H3) PLUS
a citation dependency (H4) — **Option C (keep most-specific-wins, add a
commit-time lint that makes the shadowed-exemption operator-visible) delivers the
security value at a fraction of the risk and zero HA/wire churn.** I am not
saying C wins; I am saying the plan currently tilts toward A and should present
A and C as a genuine *coin-flip for the user*, weighted by whether the project
prioritizes strict-parity (→A) or risk-minimization (→C). This is exactly the
kind of decision `/research` exists to surface, so this is a PLAN-READY-shaped
outcome, not a defect — provided the plan's recommendation section is rebalanced
to not pre-empt the user's judgment.

## Verdict

**ITERATE → r2.** The plan is factually sound, the cost model is verified, and
the design is coherent. But three things must change before it is a trustworthy
decision surface:
1. (H3) Reclassify the HA mitigation from "no gate needed" to "version gate is
   the default UNLESS session-sync-replays-resolved-decision is proven" — and
   make proving it a PLAN-READY gate item.
2. (H4) State that the Junos fall-through citation is a PLAN-READY gate, not a
   /engineer deferral — Option A's correctness depends on it.
3. (H1) Promote the interface-vs-zone inversion flip into the regression table
   as an intended behavior change; (H2) mandate the rank/seq lexicographic key
   (or a Go-tested emission-order invariant).

With those, I expect **PLAN-READY recommending "user chooses A (parity) vs C
(risk-min); B rejected"**, with A gated on H3+H4 resolving favorably. No
PLAN-KILL — the issue is real and both A and C are legitimate ships.
