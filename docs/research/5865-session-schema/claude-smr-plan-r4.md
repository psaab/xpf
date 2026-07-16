# Claude SMR — plan review r4 (#5865)

Reviewing `plan.md` v6 @ `d74f86994faa`. Convergence check after Codex r3's
narrow REVISE (which accepted the phased outcome). Hostile pass on whether Phase 1
is now internally self-consistent.

## Verdict: PLAN-READY (Phase 1 + Phase-2-contract-as-follow-up)

v6 resolves the r3 Phase-1 scoping inconsistencies. Phase 1 no longer claims more
than it delivers, the export-overflow behavior is decided and epoch-scoped, and
the Phase-2 contract is a complete requirements spec. This is the correct research
outcome for a problem that adversarial review established is a resync-protocol
redesign, not a bounded bug.

## Codex r3 items — verified addressed in v6

1. **Gate narrowed to local.** Section 1/5/6.5/8 now state Phase 1 ships only the
   **local** helper→daemon admission latch and explicitly do **not** claim to
   close the cross-node mixed-version hole (a primary latching unready can't stop
   a ready standby taking over — Phase 2's source→target propagation +
   node-to-node semantic capability close it). Internally consistent. ✓
2. **Permanent latch, no ACK-recovery in Phase 1.** §6.5/§8: released only by a
   capable local helper on restart/reconnect/upgrade; ACK-gated recovery is
   Phase 2. ✓
3. **Export overflow decided + epoch-scoped.** §6.4: `ok=false` + discard partial
   + durable unready + exact recovery; **export-epoch-scoped** accounting so
   pre-existing P2 entries can't substitute for dropped export rows; no P0
   escalation (P0 OPEN-only + same-stream hazard). ✓
4. **Acceptance narrowed.** §11: Phase-1 acceptance = P2/P3 parity + JSON-CLOSE +
   unchanged-binary-CLOSE + fail-closed export + local latch; no-re-degradation
   and mixed-peer/ACK moved to Phase 2. ✓
5. **Contract additions** §7.6 (repair incl. flags), §7.7 (incarnation coverage,
   stale CLOSE/UPDATE after OPEN(B)), §7.8 (epoch/retry fencing), §7.9 (bilateral
   activation). ✓
6. **Producer nits** (P1 OPEN/CLOSE only; P3 JSON only when live binding; 4096
   bounds P2). ✓

## Stress-tested

- **Phase-1 self-containment now holds.** With the gate scoped to local admission
  + permanent latch and acceptance limited to matched-pair parity + fail-closed
  export, Phase 1 makes no claim it cannot satisfy without Phase 2. The capability
  field + gate ship in the same .deb, so a matched pair passes; the latch only
  bites on genuine local skew. No regression to the normal single-node upgrade.
- **Phase-2 contract completeness.** §7.1–7.9 now cover backfill-before-suppress,
  full-set repair+deletion, incarnation semantics, epoch fencing, and bilateral
  activation — a genuine requirements spec, not hand-waving, so splitting it to a
  follow-up is a real scoping decision.

## No remaining blockers

PLAN-READY. Recommendation: land Phase 1 (bounded), file the Phase-2 follow-up
seeded by Section 7, keep #5865 open until Phase 2 lands. Pending Codex r4
concurrence.
