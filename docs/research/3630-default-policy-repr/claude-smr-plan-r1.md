# Claude SMR — hostile plan review r1 — #3630

Reviewer: Claude SMR (in-conversation, hostile-by-default).
Plan under review: `docs/research/3630-default-policy-repr/plan.md` @ 1ea5ed9f6.

## Verdict: PLAN-NEEDS-MINOR

The design is sound, additive, and low-risk, and it correctly mirrors the
shipped #3375 typed pattern. It is NOT PLAN-KILL — a genuine (if minor)
schema-only-client clarity gap plus the empty-array misread survive. But the
plan **overstates the ambiguity it fixes** and **under-designs the
exactly-one-default invariant**. Three MINOR fixes required before READY; with
them folded the correct terminal is PLAN-DEFERRED (low value), which the plan
already recommends.

## Findings

### F1 (MINOR, honesty) — the plan understates the EXISTING discriminators; there are TWO, not "only the magic policy_id"

The plan's §3 says the only machine-unambiguous discriminator today is
`policy_id == 0xFFFFFFFF`. That is incomplete and it weakens the plan's own
honesty. There is a **second** already-present, already-unambiguous
discriminator:

- Real rules set `rule_id = StablePolicyRuleID(from,to,name)` which is
  `"<from>-><to>/<name>"` — ALWAYS contains `"->"`
  (`pkg/dataplane/userspace/policies.go:1197-1199`).
- The synthetic default row sets `rule_id = DefaultPolicyName = "default-policy"`
  — bare, no `"->"` (`pkg/api/security.go:322`,
  `pkg/grpcapi/server_show_zones.go:292`).

So `rule_id == "default-policy"` (exact) uniquely identifies the default row
**today**, and it is robust even against a real policy literally named
`default-policy` (that rule's rule_id would be `trust->untrust/default-policy`,
not bare). The plan's §7 correctly notes the *name* string is unreliable but
misses that the *rule_id* is already reliable. This MATTERS because it makes
the "current representation is unambiguous-enough" (PLAN-KILL) argument
stronger than the plan admits: a schema-aware client has TWO documented ways to
be unambiguous today. The plan must state this honestly — the win is narrowed
to "self-describing bool vs one documented convention," i.e. pure ergonomics.
Required: add F1 to §3 and re-affirm PLAN-DEFERRED on that stronger basis (do
NOT drive-now).

### F2 (MINOR, design) — set the flag via a SHARED builder, not duplicated at two sites

The synthetic default row is currently constructed **twice**, field-for-field,
with the empty arrays + sentinel + name duplicated (`pkg/api/security.go:315-323`
and `pkg/grpcapi/server_show_zones.go:284-293`). That duplication IS the #3630
smell — two encodings drift because they are two literals. Adding `is_default`
at both sites (plan §5.2) perpetuates the duplication and directly threatens the
"exactly one is_default row" invariant the plan itself flags in open-question 6.

Required: the plan must adopt its own open-question-6 answer — extract a single
SSOT that both surfaces consume. Concretely, a shared helper that returns the
canonical default-policy tuple (action + sentinel id + rule_id +
`is_default=true`), or at minimum a shared `defaultPolicyRow()` in a common
package (the sentinel + name already live in `pkg/dataplane/types.go`; a
`dataplane.DefaultPolicyRuleFields(action)` returning the field set is natural).
REST and gRPC each map that one tuple into their own struct. This guarantees the
flag, sentinel, name, and action can never diverge across transports and makes
"exactly one is_default row" a structural property, not a convention repeated at
N call sites. Without this the plan fixes the client-visible symptom while
leaving the server-side dual-encoding root cause in place.

### F3 (MINOR, test) — require a cross-TRANSPORT parity assertion, not just cross-surface

Plan §9 has a REST test, a gRPC test, and a cross-surface (inventory vs
match-policies) action test. It is missing the parity the #3363 philosophy
demands: assert REST `GetPolicies` and gRPC `GetPolicies` emit the **same**
`is_default` semantics on the same config (both mark exactly the one synthetic
row, both false everywhere else). If F2 is adopted (shared builder) this test
is nearly free and locks the SSOT. Required: add it.

## Non-blocking (evaluated, not required)

- **N1 — enum vs bool (plan open-q 2):** `bool is_default` is correct for a LOW
  issue. A `scope` enum (default/zone_pair/global) would have to also reconcile
  the existing `*`/`*` global-tier convention and the scoped-global
  MatchFromZone/MatchToZone fields (#3286) — real over-scope. Reject the enum.
  Agree with the plan.
- **N2 — empty arrays (plan open-q 3):** documenting "empty ⇒ match-ANY under
  is_default" is the right call; emitting `["any"]` is a breaking change and
  collides with a real address book named `any`. Agree with the plan; the flag
  is the disambiguator.
- **N3 — keep is_default ≠ default_used (plan open-q 4):** correct. They are
  distinct concepts (a row that IS the default vs a query that FELL THROUGH to
  it) and renaming the shipped #3375 field is a wire break. Agree.
- **N4 — text/Prometheus unchanged (plan open-q 5):** defensible; `-`/`-` is a
  human convention and a Prometheus label cannot carry a bool without churning
  every series. Agree.
- **N5 — factual check:** verified `message PolicyRule` fields run 1..20
  (`scheduler_name=19`, `inactive=20`), so field 21 is genuinely free. The
  file:line map in §5.1 matches source at 84b6533e7. No factual errors found.

## Bottom line

Fold F1 (honesty about the second existing discriminator), F2 (shared
default-row SSOT builder — this is the part that actually earns the change), F3
(cross-transport parity test). Then PLAN-READY, terminal state PLAN-DEFERRED.
If the user would rather not spend a proto field on pure ergonomics given TWO
existing unambiguous discriminators, PLAN-KILL (works-as-intended, document
"key on rule_id=='default-policy' or policy_id==0xFFFFFFFF") is a legitimate
alternative and I would not argue against it.
