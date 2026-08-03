# Claude SMR hostile plan review — #6751 plan v11 (round 11, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v11 is my own retreat from the
alias-in-ownership-design direction I drove for five rounds; this pass
tries to break the retreat itself, because a plan that gets simpler by
dropping a feature usually dropped the feature's purpose with it.
Codex r11 was in flight when this was written; its verdict lands in the
ledger and folds if it adds anything.

## Attacking the retreat: what did the explicit alias row actually DO?

The v11 claim is "the explicit alias row is redundant with the base's
derived forward-wire index row". I re-derived the lookup chain
(shared_ops.rs:585-635): local primary → local forward-wire → shared
canonical → shared forward-wire. A fabric-return packet presents the
WIRE key (E:p→S:q). With the alias dropped:

- shared canonical lookup BY WIRE KEY: the alias row would have answered
  (it is stored under the wire key as a canonical row). Absent → miss.
- shared forward-wire lookup: the base's publish inserted
  `shared_forward_wire_sessions[(E:p→S:q)] = base entry` (wire key ≠
  canonical key, shared_ops.rs:943-957) → HIT → the BASE entry, whose
  resolution is the same fabric-redirect-to-owner disposition the alias
  entry carried.

Same disposition, same punt target. The only content difference between
the alias entry and the base entry for this lookup is metadata
(session ids, counters) — accounting, not routing. Redundancy confirmed.

The pre-existing broken-companion point is real and I verified it
independently: `synthesized_synced_reverse_entry` (shared_ops.rs:750)
builds a companion for EVERY forward import, and for an alias entry
`nat.reverse(src_ip = E)` produces `rewrite_dst = E` — a companion that
un-NATs replies to the firewall's own address, keyed at the SAME reverse
key K as the base's correct companion, published SECOND (canonical-then-
alias export order), displacing the correct one in the single-value
shared reverse map every sweep. That is a shipped hazard the codebase
only ever documented (the `record_shared_nat_displacement` exclusion
calls it "same-logical-session republish"). Dropping the alias at import
removes the poison AND the churn — v11 is not merely a retreat, it is a
side-fix of a live HA fabric bug.

## Remaining attacks on v11

1. **Promote paths**: does `maybe_promote_synced_session` or the
   activation prewarm consume the explicit alias row specifically?
   Prewarm replays shared rows (shared_ops.rs:391 publish loop) — it
   re-publishes whatever rows exist; the derived index rows exist
   regardless. A promote operates on synced rows by owner-RG indexes —
   the alias row would have been one such row; its absence means one
   fewer duplicate to promote, not a missing one. The derived
   forward-wire row carries the lookup. No break found.
2. **`is_fabric_wire_placeholder`** (shared_ops.rs:585-635): inspects the
   RETURNED entry's metadata (fabric_ingress + is_reverse + decision) —
   the base entry's metadata, present either way. No break found.
3. **Old-peer window semantics**: an unflagged legacy alias imports as
   canonical with today's behavior — including the broken companion.
   The window is the status quo (not worse); the §5.4 note says so.
   One residual worth naming: a NEW helper + OLD Go peer keeps the
   broken companion; the churn counter stays live for those sessions —
   correct and honest.
4. **Exporter side**: the two queue sites (daemon_ha_userspace_stream.go:370
   for V4, :379 for V6) are exactly where the alias is derived, so the
   flag is set at the one place alias-ness is certain. `omitempty`
   makes it additive; an old helper ignoring it treats the row as
   canonical (today's behavior). No Go-side ambiguity found.
5. **The derived forward-wire row's own lifecycle**: it is inserted at
   the base's publish and removed at `remove_shared_session` (the same
   conditional removal the sweep mirrors). If the base's canonical row
   is removed but the derived row lingers (missed removal), the lookup
   could resolve to a dead base — but that is the pre-existing derived-
   row lifecycle, unchanged by v11, and the sweep/compare-and-remove
   work (Codex r7-r9 folds) covers its ownership validation.

## Verdict

**PLAN-READY-WITH-NITS.** The retreat survives hostility: the alias's
only routing function is byte-redundant with the derived index row, and
removing it deletes a live pre-existing hazard rather than a feature.
No BLOCKER or MAJOR survives. Residual nits (folded in v11): none new
beyond the carried AGY r10 V4+V6 parity test item. If Codex r11
converges, this is terminal.
