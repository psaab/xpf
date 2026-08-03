# Claude SMR hostile plan review — #6751 plan v15 (round 15, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15 is my own fifth alias
iteration; Codex r14's two blockers were both about ORDERING (the
quarantine assumed base-arrives-after when the sender queues base-first,
and cleared suppression at the base's delete when the alias delete
follows it). This pass re-verifies the ordering logic end to end and
attacks what the ordering corrections might have reopened. Codex r15 was
in flight when this was written.

## Ordering, re-derived from the exporter's queue discipline

- OPEN: canonical base queued first, alias second for both families
  (daemon_ha_userspace_stream.go:370/375/384). The v15 confirmation is
  order-agnostic: at quarantine INSERTION, check the CURRENT store for a
  sibling base (the normal case — base already imported). Only the
  lossy-reorder case (base enqueue lost, alias succeeded after queue
  drainage, sync_conn_write.go:36 nonblocking/lossy) waits for arrival.
  The r14 blocker 2's "every alias times out and is admitted, recreating
  the poisoned companion" is dead: the normal path confirms at insertion
  and drops.
- CLOSE: base delete queued before alias delete
  (daemon_ha_userspace_stream.go:398/403). v15's suppression clears when
  the FIRST delete for the key AFTER the base's delete is consumed (the
  alias's own delete — which the suppression swallows), or on a short
  bound if that delete was lost. The r14 blocker 2's "clearing at the
  base delete lets the alias delete through" is dead: the alias delete
  is exactly the event that ends suppression, and it is itself
  suppressed.
- The direct-D residual: D (direct no-NAT, signature-clean — no
  rewrite_src, so never quarantined) installs at K; D's delete arrives
  while suppression is active → suppressed → D strands until its OWN
  session timeout. Bounded (entries expire on their own timeouts), and
  strictly safer than today (the alias upsert clobbers D at publish
  with certainty). Only in the #2387 overlap corner at all.

## Fabric-gate removal, priced

The disposition field genuinely does not survive the legacy wire
(userspaceSessionFromDeltaV4/V6 copies only SNAT/DNAT/FabricIngress —
daemon_ha_userspace_convert.go:357/462; the codec has no disposition
field, sync_protocol.go:114/229). Removing the gate widens the
quarantine to non-fabric identity-NPTv6 canonical rows — a 5s
timeout-admit delay for a corner-of-corner (identity prefix
translation, no alias ever derived for it,
daemon_ha_userspace_convert.go:511). No drop, no poison, bounded. The
alternative (a discriminator from old senders) does not exist; the
price is honest.

## Capability channel, re-checked

The pre-data `syncMsgCapability` frame with fail-safe
unknown→keep-deriving lifecycle closes the r14 major 3's race (alias
emission held until capability known; a lost frame degrades to legacy
behavior, never to dropped sync; reconnect resets to UNKNOWN first).
Unauthenticated clusters get the same frame (no auth-handshake
dependency, sync_auth.go:321 bypass).

## Attacks that failed

- Timeout admission now names the complete pipeline (generation checks,
  timestamp rebasing, bulk bookkeeping, coordinator reserve, helper
  dispatch, sync_conn_read.go:110 → sync_conn_gen.go:435) — an admitted
  genuine row is indistinguishable from a never-quarantined one.
- The sibling-base predicate's equal-NON-ZERO-RT-flow-id clause: a
  distinct colliding flow carries a different id, so confirming a
  stranger's quarantined entry as alias is infeasible; a same-id pair is
  the actual base by construction (the alias carries the base's id).
- The five-ordering matrix (base-first confirm-at-insert; alias-first
  wait-and-confirm-or-admit; genuine-row timeout-admit; close
  base-delete-then-alias-delete suppression lifecycle; lost-delete
  bound) — no free-while-reachable and no admitted-alias window found.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives. The alias
discipline is now: exact omission on the happy path (zero traffic, zero
collateral), order-correct quarantine with safe timeout admission on
the legacy window, and a delete lifecycle matched to the exporter's
real queue order. Residual nits: none new. If Codex r15 converges,
this is terminal.
