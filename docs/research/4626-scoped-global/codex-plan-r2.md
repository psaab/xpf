# Codex hostile plan re-review — #4626 r2

Task ID: `task-mrdrwdom-jh3ple` (Codex session `019f47e5-8e39-7b93-a024-6afe78c71db8`).
Verbatim verdict below.

---

Verdict: **M03 PLAN-KILL**, **L01 PLAN-DEFER**. Not converged. r2 fixes the big wire and
host-inbound design defects, but it still fails the r1 "every Required item" bar.

1. **WIRE: M03 PLAN-READY.** Additive plural fields are rolling-upgrade safe across all four
   Go/Rust pairings. Old Rust keeps decoding the retained singular strings; new Rust can default
   missing plural fields and fall back. I found no `deny_unknown_fields`, and decode still happens
   before gating at `handlers/mod.rs:88`, so avoiding a singular type-change is mandatory.

2. **HOST-INBOUND: M03 PLAN-READY.** r2's reject-mixed-`junos-host` rule plus `is_host_scope()`
   exact-host semantics resolves the r1 hole. `to-zone [junos-host untrust]` is no longer "missed";
   it is invalid. `to-zone any` cannot leak onto host-inbound because `Any` is explicitly not host
   scope.

3. **multi:true FALLOUT: M03 PLAN-KILL.** The `multi:true` fallout tests now cover repeated set,
   member delete, apply-groups union, and order/dedup, but r1 also required **mixed `any`**. r2
   defines contains-`any` wildcard semantics at plan.md:114, yet the test plan at plan.md:285 does
   not require `[any trust]` / `[any untrust]` coverage. Required change: add explicit compiler,
   matcher, display-label, and Rust scope tests for the chosen mixed-`any` behavior, or change the
   design to reject mixed `any`.

4. **CONSUMERS: M03 PLAN-KILL.** r2's "complete" list at plan.md:136 is not complete. Missing
   active non-test consumers include:
   - `pkg/cli/cli_show_security.go:116/139/300/326`
   - `pkg/cli/cli_show_security_dispatch.go:298/416/443`
   - `pkg/policymatch/zone_detail_summary.go:141/149`
   - extra line sites in named files: `cmd/cli/show_security.go:361/643`,
     `pkg/grpcapi/server_show_policies_text.go:413`

   Required change: update A5 to include these and require every one to use the shared set
   matcher/formatter, with local CLI and zone-detail tests.

5. **STRICT: M03 PLAN-READY.** r2's per-element loop, `from-zone junos-host` reject,
   undefined-zone reject, and exact `to-zone junos-host` allowance/no-mix rule resolve r1 #5.

6. **L01: PLAN-DEFER.** Correct. No standalone renumber without a session schema/version
   migration.

---

## Disposition of Codex r2 findings in plan r3

- **#1 WIRE / #2 HOST-INBOUND / #5 STRICT / #6 L01:** Codex confirms PLAN-READY / correct. No
  change needed.
- **#3 mixed-`any` (was the ONLY remaining semantic ambiguity):** ACCEPTED — r3 §5A-A3b takes the
  "change the design to reject mixed `any`" option (symmetric with the junos-host no-mix rule),
  keeping the contains-`any` collapse only as the tolerant-snapshot backstop. r3 test plan adds
  `[any trust]`/`[any untrust]` REJECT tests + the tolerant-path collapse test.
- **#4 consumers:** ACCEPTED — r3 §5A-A5 adds every cited site (`cli_show_security.go`,
  `cli_show_security_dispatch.go`, `zone_detail_summary.go:141`, `cmd/cli/show_security.go:361/643`,
  `server_show_policies_text.go:413`) and names the THREE SSOT choke points
  (`GlobalPolicyAppliesToZone`, `GlobalPolicyAppliesToZonePair`, `ZoneScopeLabel`→`ZoneScopeSetLabel`)
  every site routes through, plus a re-grep gate on the /engineer PR.

Both remaining items were bounded test/enumeration additions, folded into r3. Re-review requested
to confirm M03 → PLAN-READY.
