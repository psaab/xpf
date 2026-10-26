# #17864 — routing reconcile flush detection

Status: DRAFT v2 — pending adversarial plan review

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

Within `Daemon.reassertRoutingReconcileOnce`, after `applySem` acquisition and active-config read, retain both existing `!d.inBootstrap()` gates. On eligible ticks, call `terminatorFlushed16804` before `vrfMissTerminatorReconcileFn`, retaining its result. If the probe returns an error, log it and classify the tick as recovery-required; still attempt the terminator repair. Then run the existing policy, route-leak, terminator, and management-DNS reconcile set when generic debt was already owed, the canary was missing, or the eligible probe errored. Feed reconcile errors through the existing `noteRoutingReconcileResult` debt path. A successful full recovery need not retain the probe error as debt; a persistent probe error causes conservative full recovery on subsequent ticks.

The test's RuleList fake will read the same state mutated by the real `routing.Manager` terminator callback. Prefer the existing stateful terminator fake (`day2StatefulTerm10458`); explicitly clear its installed-family set to simulate a flush, and assert both family rules are already present when the management-DNS callback runs. Keep healthy-present, partial-family-flush, probe-error, bootstrap, and recovery-failure controls. Update the #10458 async-delete expectation because a truthful missing-canary read now escalates to the full recovery set.

No routing API change is planned: the observation/repair race with an external kernel writer remains possible, but the deterministic in-function ordering defect is addressed without changing all routing-manager callers.

## Public API preservation

No public function signatures or wire/protocol APIs change. The callback seams remain package-private and unchanged.

## Hidden invariants

- `applySem` acquisition and the config read stay before the probe; do not move observation outside the critical section.
- Bootstrap suppresses both canary-driven escalation and terminator takeover; keep both gates.
- The probe is read-only. Terminator repair still precedes every policy/leak/DNS write, preserving pref-2000-before-2500..2503 ordering.
- `termRemovePending` is also included in `shouldReassertVRFMissTerminator`. A pending removal with no rule may cause one conservative full reconciliation; it must not re-install a terminator or leave debt after successful cleanup.
- v4 or v6 missing independently triggers recovery. `mgmtRoutesOwed` remains independent and is not folded into generic routing debt.
- An external writer can flush between the probe and repair; the repair can hide that later flush. This is outside the deterministic ordering fix.
- The priority-only probe can miss selective loss of other bands or a foreign rule occupying priority 2000. A true no-VRF/no-management-stanza config with other policy rules also has no pref-2000 canary; this distinct residual is not solved here and must not be claimed solved.
- Lane B's original management-DNS-only premise must be corrected: configured management interfaces contribute to desired management VRF state. This PR is scoped to the explicit pref-2000 write-before-read issue; do not add a second DNS-specific canary or duplicate the existing post-FRR reconcile.

## Risk assessment

| Risk | Level | Mitigation |
|---|---|---|
| Behavioral regression | LOW | Stateful RED test; healthy, partial-flush, failure, bootstrap, and #10458 controls |
| Lifetime / borrow-checker | N/A | Go callback orchestration only; no ownership/lifetime change |
| Performance regression | LOW | One additional ordering change, no extra probe count; persistent probe errors intentionally cause full recovery every 30 s |
| Architectural mismatch | LOW | No new abstraction or cross-package API; existing debt owner remains the recovery path |

## Test plan

- Demonstrate the new stateful regression fails before production change and passes afterward.
- Demonstrate RED-on-revert using the production file only.
- Run the whole daemon package focused set for `16804`, `10421`, `10458`, `9693`, and `11450`, plus `go build ./pkg/daemon/...`, with campaign Go cache paths.
- Review all direct `reassertRoutingReconcileOnce` tests for assumptions about an absent live pref-2000 canary and update their fixtures/contracts intentionally.
- No userspace dataplane behavior or throughput changes are expected; cluster throughput gating is not applicable to this daemon-only recovery correction.

## Out of scope

- A lease-aware management-DNS-only canary for configs with no managed VRF.
- A generic all-band flush detector or replacement canary.
- Changing routing.Manager's `ReassertVRFMissTerminator` result contract.
- Reworking the #16804 post-FRR DNS reconcile.

## Open questions for adversarial review

1. Is classifying a probe error as recovery-required the correct fail-safe behavior when full recovery succeeds, despite repeated 30-second write cost under a persistent RuleList failure?
2. Does the stateful terminator fake actually share every RuleList-visible state mutation with the real manager callback, including deletes and partial-family state?
3. Are bootstrap and management-route-only controls sufficient to prove no scope expansion or debt coupling?
4. Is one conservative full reconciliation during a pending terminator removal acceptable, without reinstall or sticky debt?
5. Is the documented residual for no-VRF/no-management policy rules sufficiently explicit, with a separate issue required before merge?
