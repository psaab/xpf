# #17864 — routing reconcile flush detection

Status: IMPLEMENTED — v4 plan followed after parent-directed process fold-ins

## Issue framing

The no-debt recovery tick currently restores the pref-2000 VRF miss terminator before reading it as a canary. The readback then sees the successful repair and skips policy-rule, route-leak, and management-DNS recovery. The existing flush test returns a constant missing-rule table, so it cannot observe the preceding write. A probe error has the same evidence-loss consequence: the tick logs the error, treats it as not flushed, then repairs pref-2000 and ends without recovering the other bands.

## Honest scope and value

This is recovery correctness, not a performance change: without a commit, a kernel rule-table flush can leave the daemon's policy, route-leak, and management-DNS state absent indefinitely. The bounded change makes the read-only observation precede the repair and treats an unreadable eligible canary as requiring conservative full recovery. Healthy ticks with a readable, present canary remain quiet. The cost of persistent RuleList failures is repeated full reconciliation at the existing 30-second cadence.

## Already shipped / partial state

- #9693 owns generic routing retry debt and retries policy and route-leak reconciles.
- #10421/#10458 reassert the pref-2000 terminator on eligible ticks.
- #16804 added the flush probe and escalation, but orders its read after the terminator write and used a test fake that did not reflect writes.
- The existing ordering invariant remains: the terminator reconcile write must precede management-DNS steering writes at 2500-2503. The new pre-repair probe is read-only and does not change write order.
- Management-VRF DHCP-route debt remains a separate domain.

## Concrete design

Within `Daemon.reassertRoutingReconcileOnce`, after `applySem` acquisition and active-config read, retain both existing `!d.inBootstrap()` gates. On eligible ticks, call `terminatorFlushed16804` before `vrfMissTerminatorReconcileFn`, retaining its result. If the probe returns an error, log it and classify the tick as recovery-required; still call the terminator reconcile exactly once and reuse its captured `vrfErr` in the full recovery set. Run policy, route-leak, terminator-result accounting, and management-DNS recovery when generic debt was already owed, the canary was missing, or the eligible probe errored. Feed reconcile errors through existing `noteRoutingReconcileResult`. A successful full recovery need not retain the probe error as debt; each persistent probe error causes full recovery on every eligible 30-second tick.

The RuleList fake will read the same state mutated by the real `routing.Manager` terminator callback. Use the existing stateful terminator fake (`day2StatefulTerm10458`); clear its installed-family set to simulate a flush, and assert both families are present inside the management-DNS callback. Include healthy-present and each single-family partial-flush controls, probe-error recovery across two consecutive failing reads (full recovery runs twice, terminator repair runs once per tick, no probe-only debt when repairs succeed), and recovery-failure-then-healthy-probe retry through generic debt. The debt-free bootstrap negative control must assert that probe, terminator, and all recovery callbacks are skipped; a debt-positive bootstrap tick must preserve existing generic and management-route retries while suppressing the probe and terminator callback. Do not add a blanket bootstrap early return. Add an active no-desired-VRF tick with pending terminator removal; require deletion without reinstall, successful debt discharge, and a following quiet tick. Exercise generic routing and management-route debt independently when both are owed: successful generic recovery cannot discharge management-route debt, and successful management-route recovery cannot discharge failed generic debt. Update the #10458 async-delete expectation because a truthful missing-canary read now escalates to the full recovery set.

No routing API change is planned: the observation/repair race with an external kernel writer remains possible, but the deterministic in-function ordering defect is addressed without changing all routing-manager callers.

## Public API preservation

No public function signatures or wire/protocol APIs change. The callback seams remain package-private and unchanged.

## Hidden invariants

- `applySem` acquisition and the config read stay before the probe; do not move observation outside the critical section.
- Bootstrap suppresses both canary-driven escalation and terminator takeover; keep both gates.
- The probe is read-only. Terminator repair still precedes every policy/leak/DNS write, preserving pref-2000-before-2500..2503 ordering.
- `termRemovePending` is also included in `shouldReassertVRFMissTerminator`. A pending removal with no rule may cause one conservative full reconciliation; the real tick test must prove it does not reinstall the terminator and that successful removal clears debt before the next quiet tick.
- v4 or v6 missing independently triggers recovery. `mgmtRoutesOwed` remains independent and is not folded into generic routing debt; add a combined-state test for independent discharge in both directions.
- An external writer can flush between the probe and repair; the repair can hide that later flush. This is outside the deterministic ordering fix.
- The priority-only probe can miss selective loss of other bands or a foreign rule occupying priority 2000. A true no-VRF/no-management-stanza config with other policy rules also has no pref-2000 canary; this distinct residual is not solved here and must not be claimed solved.
- Lane B's management-DNS-only premise is refuted for configured management interfaces, which contribute to desired management-VRF state. Transfer the distinct no-VRF/no-management policy-band blind spot to actionable follow-up #18005 and link it in the implementation PR. Only then may the PR close #17864; otherwise use `Refs #17864`. Do not add a second DNS-specific canary or duplicate the existing post-FRR reconcile.
- Update `pkg/routing/README.md` and the affected recovery source comments to document probe-before-repair ordering, conservative recovery on eligible probe errors, and the boundary that only configs desiring the VRF terminator receive this canary; link #18005 as the separate no-VRF/no-management policy-band residual.

## Risk assessment

| Risk | Level | Mitigation |
|---|---|---|
| Behavioral regression | LOW | Stateful RED test; healthy, partial-flush, failure, bootstrap, and #10458 controls |
| Lifetime / borrow-checker | N/A | Go callback orchestration only; no ownership/lifetime change |
| Performance regression | LOW | One additional ordering change, no extra probe count; persistent probe errors intentionally cause full recovery every 30 s |
| Architectural mismatch | LOW | No new abstraction or cross-package API; existing debt owner remains the recovery path |

## Test plan

- Demonstrate the new stateful regression fails before production change and passes afterward; assert real-manager recovery state from inside the DNS callback.
- Demonstrate RED-on-revert using the production file only.
- Test both one-family missing cases, healthy-present quiet behavior, and two consecutive persistent probe errors; each error tick must run all recovery callbacks, restore terminator once, and latch no probe-only debt when recovery succeeds.
- Test that a failure in the first full recovery leaves generic debt and that a later healthy-canary tick retries and discharges it; test pending removal and both directions of generic-vs-management route debt independence.
- The bootstrap negative control must be debt-free and prove the probe, terminator, and full-recovery callbacks are not invoked. Debt-gated retries remain unchanged during bootstrap; no new blanket early return is allowed. Review all direct `reassertRoutingReconcileOnce` tests for assumptions about an absent live pref-2000 canary and update their fixtures/contracts intentionally.
- Run daemon tests focused on `16804`, `10421`, `10458`, `9693`, and `11450`, plus `go build ./pkg/daemon/...`, with campaign Go cache paths.
- No performance improvement is claimed; the implementation changes shipped daemon recovery behavior and remains subject to the parent-run, final-head campaign forwarding/throughput gate. The defect-specific unit tests do not replace that gate.

## Out of scope

- A separate management-DNS-only canary; configured management interfaces desire the managed VRF, while any dynamic DNS rule check must remain lease-aware.
- A generic all-band flush detector or replacement canary.
- Changing routing.Manager's `ReassertVRFMissTerminator` result contract.
- Reworking the #16804 post-FRR DNS reconcile.

## Plan review outcomes

1. The RuleList fake reads the same `day2StatefulTerm10458` state mutated by the real routing manager; the flush regression also observes both families inside the DNS callback.
2. The test set pins debt-free and debt-positive bootstrap, pending removal without reinstall, both partial-family flushes, persistent probe errors, and independent generic/management-route debt transitions.
3. Configured management interfaces do desire the management VRF. The separate no-VRF/no-management policy-band gap is tracked in #18005; #17864's PR must link that issue before closing #17864.
4. Eligible probe errors trigger conservative full recovery. Successful recovery does not retain probe-only debt; persistent errors deliberately cause repeated idempotent full recovery at the 30-second cadence.
