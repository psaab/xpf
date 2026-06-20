# Claude SMR — hostile self-review, #2008 Tier-3 (H7 + H12)

Round 1. Adversarial pass over `plan.md`. Goal: break the dispositions, not
confirm them. Verdict at the end.

## Confidence summary

- **H7 disposition (feasible-increment small): HIGH.** The "stream machinery
  already exists end-to-end" claim is source-verified at every layer (schema →
  type → compiler → daemon client build → ringbuf per-client filtered
  broadcast). The audit row's "whole stanza absent" is demonstrably wrong, and
  I down-graded accordingly. The one place I could be wrong is the exact Junos
  semantics of `default-profile` (see C1).
- **H12 disposition (defer-large, demand-gated): HIGH.** Net-new daemon,
  confirmed no listener exists, existing design doc + closed tracking issue
  corroborate scope. The only judgment call is "defer vs ship config-only
  opener" (see C3).

## Hostile findings

### C1 — Am I sure xpf's per-stream routing is a Junos *superset*, not a *divergence*? (H7, the load-bearing claim)

The whole H7 down-grade rests on: "xpf already routes different event classes to
different streams via per-stream category/severity filters, so `default-profile`
is mostly a validated alias." I verified the mechanism: `daemon_system.go:96-137`
builds one client per stream with independent `Categories`/`MinSeverity`;
`ringbuf.go:520-547` broadcasts each record to every client gated by
`ShouldSendEvent`. That is real and correct.

**Where this could be wrong:** Junos `default-profile` may carry semantics beyond
"catch-all stream" — e.g. it may select the *formatting/structured-data profile*
applied to ALL streams (the `profile` in `security log profile` could be a
formatting template object, not a routing target). The audit row text
"`security log profile` (stream-name/category/default-profile)" is ambiguous
between (a) a routing default and (b) a named formatting profile. I asserted (a)
without a Junos doc citation. **Mitigation already in the plan:** Option A is
defined as a *validated alias leaf* with **no runtime change**, which is correct
under BOTH interpretations — if `default-profile` is a formatting selector, xpf
already has per-stream `format` overriding global `format`, so the alias still
just needs to validate and (at most) set the global default format. The plan's
Increment-1 should therefore explicitly say: "implement `default-profile` as a
validated leaf; if its Junos meaning is a default *format/profile* rather than a
routing target, resolve it to the global `format`/source inheritance — confirm
the exact Junos semantics from a real imported config before choosing." I am
flagging this as the single most likely thing to be wrong, but it does **not**
change the disposition (still small, still no dataplane risk). **Severity:
MEDIUM — semantics caveat, not a disposition error.** Recommend the plan add an
explicit "confirm Junos semantics before fixing the meaning" note to Increment-1
step 3. (The plan already hedges this in the Option A text and the optional
follow-up, but it should be sharpened.)

### C2 — Is the H7 silent-drop claim actually true, or does commit reject `default-profile`? (H7)

I claimed `set security log default-profile <name>` "does not parse-error … but
is silently discarded." Verified: `schema_walk.go:241-244` — an unknown keyword
under a known parent `return nil` ("the gate is opt-in; leave reporting to the
compiler"), and `compileLog` (`compiler_security.go:494-573`) has no
`default-profile` case, so it is dropped. So the silent-drop framing is
**correct**. No change. (This strengthens C-side: the fix genuinely closes a
silent-drop.)

### C3 — Is "DEFER H12 entirely" the right call, or am I under-shipping? (H12)

The plan recommends keeping the warning and shipping nothing by default. Counter-
argument: the config-only opener is **S** and converts a silent sub-tree
discard (forwarders/default-domain are parsed by the parser but dropped by the
compiler) into parsed-and-validated. That is the same class of fix I'm shipping
for H7 — why ship H7's but defer H12's?

**Resolution (stands):** the asymmetry is justified and the plan states it.
(1) For H7, the *runtime is already complete* — the alias is the only missing
piece, so the increment delivers full parity. For H12, the config-only opener
delivers **no DNS behavior**; it leaves a parsed-but-still-warned config, which
is only marginally better than today's bool+warning. (2) There is **no
exercising config**: the H12 example is from `parser_system_test.go`, not a real
imported `vsrx.conf` — verified `dns-proxy` does not appear in the repo's
`vsrx.conf`/`vsrx-ha.conf`. Shipping a config model for a knob no imported
config uses, with no runtime, is low-value churn. (3) The existing commit
warning is the correct truth-in-commit backstop. **The plan correctly makes the
config-only opener *conditional on the daemon being greenlit* rather than a
standalone ship.** Disposition holds: DEFER. **Severity: LOW — judgment call,
adequately argued.**

### C4 — Did I overstate how cheap H7's cross-reference validation is? (H7, effort)

I graded H7 **S** and claimed the validator can resolve `default-profile`
against sibling stream names. Reality check: `schema_walk.go` validators are
per-leaf and do **not** trivially see sibling nodes for a cross-reference
(`ValueHintStreamName` is a *completion* hint, not a commit-time existence
check — grep shows it is only used for the `stream` keyword's own completion at
`schema_complete.go:16`, with no existence validator). So the "stream exists"
check most likely must live in the **compiler** (`compileLog`), not the schema
validator. The plan already says this ("a compiler-side check if the validator
can't see siblings — see the cross-ref precedent"), and `compileLog` already has
the full stream map in scope when it would read `default-profile`, so the check
is one map-membership test. **Effort remains S.** No disposition change, but the
plan should lead with "validate in the compiler" rather than implying a schema
validator does the cross-ref. **Severity: LOW — accuracy nit, plan already
hedges.**

### C5 — H12 effort grade: is "L / 4-6 PR" defensible or hand-wavy? (H12)

I leaned on the agent's 3000-4000 LOC / 4-6 week estimate and the design doc's 6
phases. That is a reasonable upper bound but I did not independently size each
phase. **However** the disposition (DEFER) does not depend on the precise grade —
it depends only on "L, net-new daemon, no exercising config, warning already
exists," all of which are solid. Even if the true effort were M (e.g. a thin
`dnsmasq` delegate instead of `unbound`), the demand-gating argument (no real
config uses it) would still justify deferral. **Severity: LOW — grade is an
upper-bound estimate; disposition is robust to it.** The plan should avoid
over-precise week counts; the relative grade (L, multi-PR) is what matters.

### C6 — Did I miss that H12 might already be partially shipped (like some H-items were in Inc-1/Inc-2)? (both)

The prompt warned some H-items shipped in earlier increments. I verified on
`ec46efbc7`: H12's warning is still live at `compiler.go:1341`, the field is
still a bare bool at `types_system.go:194`, and `git log -- docs/next-features/
dns-proxy.md` shows only doc commits (no runtime). H7's `default-profile` is
absent from schema/compiler/types. **Neither shipped.** No change.

### C7 — Scope creep risk in H7 Option A (H7)

Could H7 "Option A" balloon if a reviewer demands full Junos `profile`-object
parity (the Option B path)? The plan explicitly recommends *against* Option B
(behavior change to a working broadcast model, regression risk, near-zero real
demand) and against reworking `ringbuf.go` dispatch. As long as Increment-1
stays at "validated alias leaf, no dispatch change," scope is contained. The
plan is clear on this. **Severity: LOW — bounded by the plan's explicit Option-B
rejection.**

## What I could NOT fully verify (honest gaps)

1. **Exact Junos `default-profile`/`profile` semantics** (C1) — asserted from
   general Junos knowledge, not a cited Junos doc or a real imported config. The
   plan's "no runtime change" framing is robust to either interpretation, but
   the *meaning* assigned to the leaf must be confirmed before implementation.
   This is the one item that should gate the H7 PR's design step.
2. **Whether any operator actually wants client-facing DNS proxy** (H12 value) —
   I established no in-repo config uses it; I cannot establish external demand.
   The DEFER recommendation is explicitly demand-gated, which is the correct
   posture under that uncertainty.
3. **H12 phase-by-phase LOC** (C5) — upper-bound estimate, not independently
   sized per phase. Disposition does not depend on precision.

## Verdict

**Plan is sound. Dispositions hold.**

- **H7 — FEASIBLE-INCREMENT (small):** confirmed. The audit row overstated the
  gap; the stream subsystem is complete and the residual is a validated alias
  leaf. One sharpening required before implementation: **confirm the Junos
  meaning of `default-profile` (routing-target vs format-profile)** and lead the
  validation with a **compiler-side** stream-existence check (C1, C4). Neither
  changes the small grade or the no-dataplane-risk property.
- **H12 — PLAN-DEFER (large), demand-gated:** confirmed. Net-new daemon, no
  exercising config, existing commit warning is the correct backstop, and a
  full design already exists (`docs/next-features/dns-proxy.md`, #660) to
  resurrect on demand. The optional config-only opener is correctly gated on the
  daemon being greenlit rather than recommended standalone.

No MAJOR findings. Two MEDIUM/LOW sharpenings folded as notes (C1 semantics
confirmation, C4 compiler-side validation). Recommend shipping **H7 Option A**
as the next small Tier-3 increment; **defer H12**.
