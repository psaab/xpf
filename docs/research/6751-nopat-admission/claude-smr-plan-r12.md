# Claude SMR hostile plan review — #6751 plan v12 (round 12, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v12 is my own second iteration
of the alias retreat (v11 moved the drop receiver-side with a real
carrier); this pass tries to break the carrier, the gate, and the
receiver-side drop point. Codex r12 was in flight when this was written.

## Carrier and drop point, independently verified

- The `SessionValue.Flags uint16` field (pkg/dataplane/types.go:22)
  already carries one late-added bit (`SessFlagNPTV6` = bit 8, #5460),
  and the ABI is size-asserted at 136 bytes — a new high bit within the
  existing u16 changes no layout, so the cluster upsert payload, the BPF
  conntrack mirror, and the peer's helper request construction all carry
  it without a format change. The one residual Codex could still raise —
  a decoder that rejects unknown bits — is exactly what v12 pins as an
  implementation verification (truncate-style decoding everywhere, with
  the strict-decode fallback noted). Reasonable.
- The receiver-side drop point (Go daemon at the cluster receive
  boundary) precedes every consumer I can enumerate: the helper forward
  (`SessionSyncRequest` construction, manager_ha.go:1584/1668), the BPF
  mirror, the local session store, and bulk replay. No alias row reaches
  the helper's ownership machinery in any matrix cell — Codex r11 B2's
  regression channel is structurally dead, not patched.
- The per-peer sticky capability gate is implementable with receiver
  state alone (a per-peer bool flipped on the first flagged row); its
  collateral story is honest: legacy genuine self-NAT rows (a client
  owning the WAN address, the #2387 corner) drop under the signature
  rule, documented + counted, and flag-capable peers never hit the
  signature at all.

## Attacks attempted and failed

1. **Delete path**: wire-key deletes on the new path no-op (no row
   present; `remove_shared_session` removes only what it finds); the
   base's derived forward-wire index row lives under the base's key and
   is removed only by the base's delete. The genuine self-NAT occupant
   corner is pre-clobbered today by the alias publish itself — v12's
   "no delete flag needed" holds.
2. **Old-sender cell**: the signature heuristic (`forward &&
   sync-derived && src == rewrite_src`) fires for exactly the rows the
   old exporter derives as aliases; the base row never matches (its src
   is the internal host, not the translation). Only the #2387 genuine
   self-NAT corner collides, documented. The legacy window comes out
   BETTER than today (no broken companion), not worse.
3. **pub_token chain**: restored into the staged-replacement sweep
   bullet with the full hierarchy and the per-map atomicity note;
   cross-checked against the r10 text — faithful.
4. **Stale artifacts**: HolderSet justification now cites legacy-window
   duplicates (still load-bearing — the legacy window is where same-scope
   duplicates exist); §6 inventory no longer lists the removed predicate
   helper; counters say five everywhere except one §9 typo AGY r12
   caught (folded: "the four" → "the five").

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives. The carrier is
real (existing field, ABI-unchanged), the regression channel is
structurally closed, and the retreat's two foundations (alias-row
redundancy, delete no-op) survived three independent walks each. The
only folds this round are AGY r12's §9 counter typo (folded) and the
carried implementation-time items. If Codex r12 converges, this is
terminal.
