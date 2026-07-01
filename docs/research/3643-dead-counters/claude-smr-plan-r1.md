# Claude SMR hostile plan review — #3643 r1

Reviewer: Claude SMR (hostile). Plan: `plan.md` @ `87749ce81`.

I tried to soft-pass this as "clean POPULATE plan" and stopped myself — the
plan's whole severity argument rests on one unverified kernel claim, and the
recommendation buries a real "is this worth doing at all" question. Hostile pass
below.

## F1 (HIGH → must resolve before PLAN-READY): the OOB-error linchpin is asserted, not proven

The plan's escalation from "misleading 0" to "REST 500 / Prometheus false alert /
CLI error rows" depends entirely on: *a BPF dense per-CPU array `Lookup(key ≥
max_entries)` returns `ENOENT` → `ErrKeyNotExist`, and the read surfaces
propagate that error.* I could not run the empirical probe (no CAP_BPF /
memlock in the research sandbox — the probe test skipped). So this is
**corroborated, not proven**:

- `pkg/dataplane/maps_nat.go:366` comment (maintainer, #2255): *"a hash id ≥
  MaxNATRuleCounters would fail that bounded Lookup"* — a direct statement that
  the dense-array lookup fails for an OOB stable-hash id. This is the strongest
  corroboration: the *same class* of counter already hit this and was fixed for
  exactly this reason.
- `pkg/dataplane/constants_test.go:85`: *"ifindex == MaxInterfaces is out of
  range for a dense array"* — repo treats OOB dense-array index as a hard fail.
- `ReadZoneCounters` (maps_counters.go:95) and `ReadFloodCounters`
  (maps_screen.go:79) return the raw `Lookup` error and do **not** convert
  `ErrKeyNotExist`→zero (unlike `ReadInterfaceCounters`, maps_counters.go:81,
  which does convert — because it's a HASH map where a miss is legitimate).

**Verdict on F1:** high-confidence but the plan MUST label this an assumption
and Phase 1 MUST NOT be called a "bug fix" until it is smoke-verified on the
loss cluster (`curl` the REST endpoint, scrape `xpf_counter_read_errors_total`,
run the CLI). The plan already says this in §11 Q2 — good — but §2/§3 state the
500/false-alert as fact. Downgrade the prose to "expected (pending
cluster-verify)" or verify first. If the reads actually clean-zero, the whole
severity story collapses to the issue's original mild "misleading 0" and Phase 1
shrinks to a cosmetic honesty fix. **This is the single highest-leverage thing
to confirm.**

## F2 (MED): the recommendation waffles between POPULATE and HIDE

The plan recommends POPULATE (§5A) but its own §3 concedes per-zone is a
"nice-to-have already largely covered." A hostile reader asks: if global +
per-interface (`Bindings[].RXPackets/TXPackets/RXBytes/TXBytes`) + per-policy
(#2118) + per-screen-reason (#3343) already exist, **what does per-zone add that
an operator can't already get by summing the zone's interfaces client-side?**
The honest answer: (a) server-side zone rollup convenience, (b) VLAN-unit-level
attribution that per-interface can't express. (b) is the only *unique* value —
and it's exactly what DERIVE (§5C) can't do and POPULATE can. So the real
decision is narrower than "POPULATE vs HIDE": it is **"do operators need
VLAN-unit-granular per-zone volume?"** If yes → §5A. If no → per-interface
already covers whole-interface zones and the marginal value of §5A is low → HIDE.
The plan should say this crisply and let the user answer the narrow question,
rather than defaulting to POPULATE.

## F3 (MED): Phase 1 alone re-creates the "misleading 0" the issue filed against

Phase 1 converts error→clean-zero. That *is* the state the issue complains about
("indistinguishable from no traffic"). So Phase 1 without §5A/§5B is a
**regression back to the exact complaint**, dressed up as a fix. The plan says
this (§5 "necessary but not sufficient") but it must be loud: Phase 1 MUST land
paired with either §5A (real data) or §5B (explicit "not available" — NOT a
zero). Shipping Phase 1 solo would technically close the 500 while re-opening
#3643's literal grievance. Good that the plan forbids a bare zero in §5B; make
that non-negotiable.

## F4 (LOW-MED): §5A wire cost + the "sum across workers" question is under-specified

§11 Q4 flags per-binding vs worker-summed sparse block but the plan doesn't pick.
Cold-path (the cited precedent) reports per-worker and the Go side sums. For
zone counters the same choice applies. Recommend: pre-sum across workers in the
helper into ONE `ProcessStatus`-level sparse per-zone block, so the wire cost is
O(active zones) once, not O(active zones × bindings). This also matches how
`sumBindingCounters` already collapses per-binding scalars — but per-zone is a
map, so summing on the Go side means iterating every binding's map every poll.
Helper-side pre-sum is cleaner. The plan should commit to this in §5A, not leave
it open, since it changes the wire shape.

## F5 (LOW): flood — is per-zone even wanted, or is #3343 aggregate enough?

§11 Q6 asks this but the plan keeps per-zone flood in §5A. Given #3343 already
surfaces syn/icmp/udp-flood drops aggregated globally, and the per-zone flood
surface (`show security screen ids-option statistics <zone>`) is a niche IDS
view, a defensible narrowing is: **POPULATE per-zone packets/bytes (§5A) but mark
per-zone flood "not available" and lean on the #3343 aggregate.** That halves
the wire/Rust work for the lower-value half. The plan should offer this as an
explicit sub-option, not bundle flood into §5A by default.

## F6 (LOW): confirm zone-counter slots are node-local (no cross-node slot read)

§7 asserts HA symmetry via deterministic slot assignment. But the *safe* design
is the cold-path one: slots are **node-local and never ride the sync wire** —
only the zone-id-keyed rollup is read cross-surface. Confirm no HA session-sync
or config-sync path serializes a *slot index* (it must serialize zone *ids*).
If slots stay node-local like cold-path, HA determinism is a non-issue and the
"sort before assign" requirement is only for single-node reproducibility, not
correctness. The plan overstates the HA risk; verify and downgrade.

## What's genuinely strong

- The #2255 read-side clone is exactly right and low-risk; citing the maintainer
  comment that predicts the OOB failure is the best evidence in the plan.
- Catching that the issue's "dense 1..N zone ids / silent 0" premise is stale
  (#3075) is the real research contribution — it reframes the whole issue.
- Rejecting DERIVE on VLAN-unit infidelity (with the project's own reth0.50/.80
  WAN topology as the counterexample) is correct and well-argued.
- The ColdPathSlotMap precedent is a real, load-bearing blueprint, not a
  hand-wave.

## SMR verdict

**PLAN-NEEDS-MINOR → conditionally PLAN-READY.** The architecture is sound and
well-grounded in shipped precedent (#2255 + ColdPathSlotMap). Conditions:
1. Relabel the 500/false-alert as *expected, pending cluster-verify* (F1); make
   the smoke-verify a Phase-1 gate.
2. Make explicit that Phase 1 must ship paired with real data (§5A) or explicit
   "not available" (§5B) — never a bare zero (F3).
3. Reframe the recommendation around the narrow question "is VLAN-unit-granular
   per-zone volume wanted?" (F2), and offer the "per-zone packets/bytes but
   aggregate-only flood" sub-option (F5).
4. Commit to helper-side worker-pre-sum for the wire (F4) and confirm node-local
   slots (F6).

Net recommendation to the user: **PLAN-READY for a two-phase POPULATE** — Phase 1
(read-side #2255 clone) unconditional after cluster-verify; Phase 2 (§5A) the
recommended source **if** per-zone/VLAN-unit volume is wanted, else HIDE (§5B) as
a legitimate PLAN-KILL of the feature. This is a real fork the user should
decide, not one the plan should force.
