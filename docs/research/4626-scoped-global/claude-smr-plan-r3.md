# Claude SMR — hostile plan review, #4626 r3

Reviewer: Claude (self-model review, HOSTILE). Base `origin/master` 4eb28ae25.
Target: `docs/research/4626-scoped-global/plan.md` r3 (post Codex-r2).

## Verdict

- **M03 → PLAN-READY.** r3 closes the last two Codex-r2 items (mixed-`any` reject + complete
  consumer list). I re-attacked the mixed-`any` reject and the SSOT-choke-point claim; both hold.
- **L01 → PLAN-DEFER** (PLAN-KILL-as-WONT-FIX honest primary). Unchanged.

## Re-attacked r3

1. **Does rejecting mixed `any` (A3b) lose any real Junos config?** No. `[any trust]` is
   redundant (`any ⊇ trust`); a real operator writes either `any` or an explicit list. And the
   pre-#4626 world rejected ALL multi-element scope lists, so no committed config contains
   `[any trust]` to regress. The tolerant-path collapse backstop still protects a bad HA
   peer/hand-built snapshot. CLEAN and symmetric with the junos-host no-mix rule.

2. **SSOT choke points — is "convert the 3 helpers and call sites follow mechanically" actually
   true?** `GlobalPolicyAppliesToZone` (audit), `GlobalPolicyAppliesToZonePair` (filtered view),
   and `ZoneScopeLabel` (display join) are indeed where the CLI/gRPC/zone-detail sites funnel
   (verified: `cli_show_security.go`, `cli_show_security_dispatch.go`, `zone_detail_summary.go`,
   `server_show_policies_text.go`, `cmd/cli/show_security.go` all call one of the three). The
   residual direct reads are the `hcFrom`/`globalFromZone` display locals (`!= ""` → assign),
   which r3 routes through `ZoneScopeSetLabel`. The re-grep gate on the /engineer PR catches any
   site the enumeration still missed. This is the right structural containment — no surface
   open-codes join/wildcard/match. CLEAN.

3. **Did the r3 edits break internal consistency?** Checked: A3b (reject mixed-any) is referenced
   from A4 (strict gate), invariant #6, Q5, and the test plan — all cross-consistent. The
   `IsWildcardZoneSet` contains-`any` semantics is now explicitly demoted to "tolerant backstop
   only," which is consistent with the strict gate never emitting a mixed set. No contradiction
   with A2 (the helper still exists and is still the wildcard SSOT for the empty/`[any]` cases).

4. **Any NEW hole from the reject-mixed rules?** A `from-zone any` single-token scope must STILL
   be allowed (it is the idiomatic all-zones global). r3 A4 test plan explicitly keeps "single
   `from-zone any` still ALLOWED" — good, the reject is specifically for `any` MIXED with another
   token, not `any` alone. CLEAN.

## Residual nits (unchanged from r2, /engineer-time)

- N1 (permit-vs-deny asymmetry of the old-helper first-zone degradation — recommend singular =
  first-element), N2 (confirm the Rust reported-zone path), N3 (wire plural order = sorted order
  for HA-symmetric `expand_side`). All /engineer details, not plan blockers.

## Bottom line

r3 is PLAN-READY for M03 and PLAN-DEFER for L01. Every Required item from Codex r1+r2 and SMR
r1+r2 is now addressed with a file:line-anchored design and a matching test. Converged.
