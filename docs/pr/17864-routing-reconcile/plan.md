# #17864 — routing reconcile flush detection

Status: IMPLEMENTED — #18005 folded into the active recovery change

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

Within `Daemon.reassertRoutingReconcileOnce`, after `applySem` acquisition and active-config read, retain both existing `!d.inBootstrap()` gates. On eligible ticks, derive the desired family/priority inventory for next-table, rib-group (including returns), PBR, and filtered lease-derived management-DNS pairs, then read only families that contain desired policy state or an owned VRF canary. Compare desired and live counts before `vrfMissTerminatorReconcileFn`; any missing count, missing owned canary, or eligible inventory/RuleList error classifies the tick as recovery-required. Run policy, route-leak, terminator-result accounting, and management-DNS recovery when generic debt was already owed or the readback requires recovery. Feed reconcile errors through existing `noteRoutingReconcileResult`. A successful full recovery need not retain a probe error as debt; persistent probe errors cause full recovery on every eligible 30-second tick.

The original canary tests retain their stateful terminator fake. The #18005 regression uses a shared RuleList fake mutated by the routing policy writers and terminator writer, and covers a no-VRF PBR-only flush, selective PBR loss with the canary still present, healthy state, and an empty policy inventory. These cells prove the PBR-only case recovers without installing pref-2000; existing tests continue to pin canary ordering, bootstrap suppression, pending removal, debt ownership, and DNS write order.

The routing package exposes a sorted family/priority multiplicity inventory derived from the same next-table, rib-group, and PBR builders/admission logic used by its writers. The observation/repair race with an external kernel writer remains possible, and RuleList cannot expose all rule selectors (notably DSCP).

## API surface

The new routing inventory helper is an exported Go API; no wire or protocol APIs change. Existing callback seams remain package-private.

## Hidden invariants

- `applySem` acquisition and the config read stay before the probe; do not move observation outside the critical section.
- Bootstrap suppresses both canary-driven escalation and terminator takeover; keep both gates.
- The probe is read-only. Terminator repair still precedes every policy/leak/DNS write, preserving pref-2000-before-2500..2503 ordering.
- `termRemovePending` is also included in `shouldReassertVRFMissTerminator`. A pending removal with no rule may cause one conservative full reconciliation; the real tick test must prove it does not reinstall the terminator and that successful removal clears debt before the next quiet tick.
- v4 or v6 missing independently triggers recovery. `mgmtRoutesOwed` remains independent and is not folded into generic routing debt; add a combined-state test for independent discharge in both directions.
- An external writer can flush between the probe and repair; the repair can hide that later flush. This is outside the deterministic ordering fix.
- The detector compares family/priority multiplicities rather than full selectors, so it cannot validate actions or DSCP and a foreign rule at a matching slot can mask a missing xpf rule.
- Management-DNS eligibility is lease-derived and passes through the same filtered desired-pair builder as reconciliation; it does not infer DNS rules from config shape.
- #18005's no-VRF/no-management policy-band gap is addressed in this change without widening `shouldReassertVRFMissTerminator`; the global pref-2000 rule remains absent unless a VRF terminator is desired or retained. Do not add a second DNS-specific canary or duplicate the existing post-FRR reconcile.

## Risk assessment

| Risk | Level | Mitigation |
|---|---|---|
| Behavioral regression | LOW | Stateful RED test; healthy, partial-flush, failure, bootstrap, and #10458 controls |
| Lifetime / borrow-checker | N/A | Go callback orchestration only; no ownership/lifetime change |
| Performance regression | LOW | One additional ordering change, no extra probe count; persistent probe errors intentionally cause full recovery every 30 s |
| Architectural mismatch | LOW | No new abstraction or cross-package API; existing debt owner remains the recovery path |

## Test plan

- The #18005 fail-on-revert test uses one stateful RuleList table shared by inventory and the real recovery writers; prove the no-debt PBR-only flush restores without a commit and without a canary, selective loss recovers while the canary remains, healthy rules do not rewrite, and an empty policy config neither probes nor creates a canary.
- Demonstrate RED-on-revert using the production inventory probe and its tick call site.
- Retain the existing tests for both one-family canary misses, healthy-present quiet behavior, consecutive probe errors, recovery failures/debt, pending removal, management-route debt independence, and bootstrap suppression.
- Run daemon tests focused on `18005`, `16804`, `10421`, `10458`, `9693`, and `11450`, plus `go build ./pkg/daemon/...` and the routing package tests, with campaign Go cache paths.
- No performance improvement is claimed; the implementation changes shipped daemon recovery behavior and remains subject to the parent-run, final-head campaign forwarding/throughput gate. The defect-specific unit tests do not replace that gate.

## Out of scope

- A separate management-DNS-only canary; configured management interfaces desire the managed VRF, while any dynamic DNS rule check must remain lease-aware.
- Full selector/action validation and non-policy priority bands outside the explicitly inventoried recovery domains; same-slot foreign rules can mask missing xpf rules.
- Changing routing.Manager's `ReassertVRFMissTerminator` result contract.
- Reworking the #16804 post-FRR DNS reconcile.

## Plan review outcomes

1. The RuleList fake reads the same `day2StatefulTerm10458` state mutated by the real routing manager; the flush regression also observes both families inside the DNS callback.
2. The test set pins debt-free and debt-positive bootstrap, pending removal without reinstall, both partial-family flushes, persistent probe errors, and independent generic/management-route debt transitions.
3. Configured management interfaces desire the management VRF. The separate no-VRF/no-management policy-band gap from #18005 is folded into this implementation and covered by the shared-state PBR regression.
4. Eligible probe errors trigger conservative full recovery. Successful recovery does not retain probe-only debt; persistent errors deliberately cause repeated idempotent full recovery at the 30-second cadence.
