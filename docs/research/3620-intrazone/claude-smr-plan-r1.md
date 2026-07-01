# Claude SMR — hostile plan review r1 — #3620 intrazone default

Reviewing `docs/research/3620-intrazone/plan.md` @ r1. Posture: HOSTILE. This is a
security decision; a wrong verdict ships a regression. I tried to BREAK the
premise and the KILL. Below is what survived.

## Attack 1 — is the premise resolution actually correct? (the crux)

Claim under attack: "mainline Junos SRX/vSRX does NOT implicitly permit intrazone
traffic; it is policy-governed + default-deny."

I attempted to find a runtime implicit intrazone permit on SRX:

- **default-policy default = deny-all.** Juniper config-statement reference is
  explicit: "Deny all traffic. Packets are dropped. This is the default," scoped
  to "a packet that does not match any user-defined policy." No same-zone
  carve-out. HOLDS.
- **Intrazone is policy-evaluated.** Security Policies Overview: policy lookup
  happens "between two interfaces bound to the same zone." So intrazone hits the
  same lookup → same deny-all default when unmatched. HOLDS.
- **Community accepted answer** ("in srx intra-zone traffic is not allowed by
  default"). Third-party, but consistent with the two primary Juniper sources.
- **ScreenOS is the confounder.** ScreenOS had implicit intrazone permit via
  `intrazone-block` (default unblocked). SRX has no such construct. The plan
  correctly identifies this as the source of the "permitted by default" folklore
  and of the second web-search hit. HOLDS.

Corner cases I probed and could NOT turn into an implicit permit:
- **Same-interface hairpin / u-turn:** SRX still runs a policy lookup (from-zone
  == to-zone). No bypass. Not a counterexample.
- **`Pre ID default policy: permit-all`** (junos-cli-reference.md:215): this is
  the pre-application-identification default (first packets flow until AppSecure
  resolves the app), applied equally to inter- and intrazone; it is NOT a
  zone-based transit permit and does not create an implicit intrazone-permit for
  the session's policy decision. Not a counterexample.
- **Branch-SRX factory default:** permits trust intrazone — but via a CONFIGURED
  policy in the shipped config (the "default-permit" Index-4 the review cited),
  not a runtime default. Zeroize → deny-all. This is the plan's central point and
  it is correct.
- **vSRX vs SRX / older Junos (12.1x47):** same flow-based security-policy engine;
  deny-all default throughout. No divergence found.

Verdict on Attack 1: **premise resolution HOLDS.** I could not produce an
authoritative citation of a runtime implicit intrazone permit on SRX. The review
misread a configured policy name.

## Attack 2 — are the code claims right?

- policy.rs `evaluate_policy_result_l3_aware` — confirmed: tiers exact →
  single-wildcard → both-any → junos-global → single `default_action`; no
  `from_id == to_id` branch; `PolicyState.default_action` single field, Default =
  Deny; one default counter/sentinel. Same-zone runs the identical pipeline.
- policymatch.go Tier 5 returns the single default for any miss incl. same-zone.
- No pre-existing intrazone special-casing anywhere. HOLDS.

Consequence: xpf denies unmatched same-zone traffic via default_action — which is
SRX-correct. And a configured trust→trust permit is honored by the exact tier —
also SRX-correct. Both directions match.

## Attack 3 — is PLAN-KILL the right disposition?

- Option B (build the tier) would make xpf PERMIT unmatched same-zone traffic —
  the opposite of SRX and of the operator's default-deny intent. The plan's
  "security regression / anti-parity" framing is fair and, if anything,
  understated: it is the single most important reason NOT to build.
- Option C (opt-in ScreenOS-style knob) is correctly deferred as a non-parity,
  demand-gated, separate feature — not this issue.
- KILL is conclusive (architectural premise broken), so per the project label
  convention `plan-kill` = close. Correct.

One residual tension (not a blocker): Option A' (docs clarification) is marked
optional. To stop a future reviewer re-filing the same misread, I recommend the
kill comment itself carry the one-paragraph clarification (or a tiny standalone
doc PR), but this does NOT gate closing — the verdict stands on the premise
resolution alone.

## Attack 4 — gaps / dedup

- Dedup vs #3042 / #3065 / #3363 / #3057 / #3534 / #3611 is accurate; this issue's
  unique question (does an intrazone default even exist on SRX?) is answered NO.
- No missing SRX knob (SRX has no intrazone-block). Confirmed.

## SMR verdict

**PLAN-KILL-CONFIRMED (works-as-intended).** The premise ("SRX implicitly
permits intrazone") is false; xpf already matches SRX (same-zone → policy →
default deny); building the reviewed tier would be a security regression. Close
#3620 `plan-kill`. Recommend folding the optional one-paragraph docs
clarification (Option A') to prevent re-filing, but it does not gate the close.
