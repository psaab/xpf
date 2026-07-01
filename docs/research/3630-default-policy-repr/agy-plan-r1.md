# AGY — adversarial plan review r1 — #3630

Reviewer: Antigravity (agy:agy-rescue), commit 1ea5ed9f6.

## Verdict: PLAN-KILL

Works-as-intended reason: the synthetic default row already carries
`policy_id == 0xFFFFFFFF` (`DefaultPolicySentinelID`), which since #3623 has
explicit proto3 presence and is always emitted, PLUS four other stable
discriminators (`rule_id`/`name` == "default-policy", `from_zone`/`to_zone` ==
"-"). The developer-clarity gap is a DOCUMENTATION problem, not a schema
problem; a proto/JSON doc-comment naming the sentinel resolves it without new
wire fields.

## Findings (verbatim summary)

1. PLAN-KILL confirmed. `policy_id` is an always-present machine discriminator
   (`proto/xpf/v1/xpf.proto:319`; `pkg/dataplane/types.go:438`). A new
   `is_default` bool is redundant schema churn for a LOW issue — fix with
   proto/JSON doc comments.
2. Neither bool nor enum: a scope enum over-scopes; the bool is redundant with
   the existing sentinel.
3. Design smell either way: "empty ⇒ match-ANY only when is_default" forces
   sibling-dependent client parsing; `"any"` token breaks compat + collides
   with an address book named "any".
4. Keeping `is_default` distinct from `default_used` is permanent naming
   divergence defeating the normalization goal; renaming breaks #3375. Bad
   either way for LOW severity.
5. Leaving text/Prometheus unchanged contradicts the plan's "consistent across
   all surfaces" claim — only the schema client benefits; net benefit
   negligible.
6. No factual errors; field 21 genuinely free; file:line accurate at 1ea5ed9f6.
7. No missed producer today, but `is_default` creates a manual two-site
   invariant with no central builder — a future third producer silently breaks
   exactly-one-is_default.

## Note

AGY independently corroborates Claude SMR F1 (multiple existing discriminators)
and F2/F7 (no central builder → two-site invariant fragility). AGY weights the
existing discriminators as sufficient → KILL; Claude SMR weights the
schema-only-client gap as a genuine-but-minor residual → NEEDS-MINOR/DEFER.
