# Claude SMR — hostile plan review, #4626 r2

Reviewer: Claude (self-model review, HOSTILE). Base `origin/master` 4eb28ae25.
Target: `docs/research/4626-scoped-global/plan.md` r2 (post Codex-r1 + SMR-r1).

## Verdict

- **M03 → PLAN-READY.** r2 closes every r1 gap. My R1 (address-book) and R2 (warn validator) are
  in §5A-A5/A7; Codex's wire correction (additive fields), host-inbound set semantics, and
  multi:true fallout are all folded. The design is now doctrine-correct and consumer-complete.
- **L01 → PLAN-DEFER** (with PLAN-KILL-as-WONT-FIX as the honest primary). Unchanged, agreed.

## Re-attacked r2 — did the fixes introduce new holes?

1. **Additive wire (A8): does new Rust's "prefer plural, else singular" ever double-count or
   disagree with new Go?** New Go emits singular=first-element AND plural=full-list. New Rust
   reads plural when non-empty → ignores singular. Consistent. Old Rust reads singular only →
   sees first element (documented degradation). Old Go emits singular only → new Rust plural is
   empty → falls back to singular. All four cross-version pairings resolve to a well-defined
   scope. No double-count (they are alternatives, not additive semantics). CLEAN.

2. **A8 old-helper degradation direction: is first-zone-only SAFE, or can it fail OPEN?** For a
   PERMIT global `from-zone [trust dmz]`, an old helper honoring only `trust` is STRICTER (dmz
   traffic falls through to the next tier / default) — fail-closed-ish, not a widening. For a
   DENY global, honoring only `trust` under-denies dmz for the brief window — a transient
   under-block, but the operator just committed this and the window closes when the peer
   upgrades. Acceptable + documented. No hard fail-open. OK — but the plan should STATE the
   permit-vs-deny asymmetry explicitly (minor; see nit N1).

3. **A6 junos-host no-mix: does rejecting `[junos-host untrust]` break any existing valid
   config?** Today the multi-element list is REJECTED wholesale (scalar:true), so no committed
   config contains it — the no-mix rule cannot regress anything. A lone `to-zone junos-host`
   stays valid. CLEAN.

4. **A7 address-book single-zone carve-out: does it silently change a currently-working
   single-zone scoped global?** No — `len==1` keeps the exact `rewrite(zone,...)` call. Only the
   newly-allowed multi-zone case takes the global-book path. CLEAN.

5. **A2 shared SSOT vs the existing `IsWildcardZone`/`globalScopeMatches`:** the plan ADDS set
   variants rather than replacing — confirm the scalar helpers still have callers (they do:
   junos-host single-zone paths, NAT from-context). No orphaning. CLEAN.

6. **Did r2 keep the OR-audit vs AND-match distinction (r1 invariant #4)?** Yes, §7 #4 retains
   it. `GlobalPolicyAppliesToZone` stays OR-of-sides; the matcher stays AND. Good — a common
   refactor error (unifying them) is explicitly guarded.

## Residual nits (non-blocking)

- **N1.** State the permit-vs-deny asymmetry of the A8 old-helper first-zone degradation (point 2
  above) in §6 so the /engineer author picks singular=first-element deliberately (vs singular=""
  → all-zones, which would fail-OPEN a permit). Recommend singular=first-element (as written).
- **N2.** A10 (`matchedResult` reports concrete flow zone): add a one-line assertion to the Rust
  reported-zone path check — the Go side is pinned but the Rust `PolicyEvaluationResult` reported
  zone should be independently confirmed at /engineer.
- **N3.** Q6 (compile-time sort+dedup): if adopted, ensure the WIRE plural order is the sorted
  order on BOTH nodes so the cold-path `expand_side` slot assignment stays HA-symmetric (the plan
  implies this in A3; make it explicit at /engineer).

## Bottom line

r2 is PLAN-READY for M03 and PLAN-DEFER for L01. Every r1 Required item from both reviewers is
addressed with a concrete file:line-anchored design. The three nits are /engineer-time details,
not plan blockers. Converged.
