# Claude SMR hostile plan review — #6751 plan v8 (round 8, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v8 is my own fold of Codex r7's
alias-internals blockers; this pass re-derives the four-part predicate's
soundness and the counting HolderSet's order-safety, then attacks the
id-0 fallback that AGY r8 accepted. Codex r8 was in flight when this was
written; its verdict lands in the ledger and folds if it adds anything.

## Four-part predicate, independently re-derived

- The alias export carries the base's FULL value unchanged
  (`userspaceForwardWireAliasV4` returns `(wireKey, val, true)`,
  daemon_ha_userspace_convert.go:399-405). The value embeds BOTH ids:
  the node-local `SessionID` (per converted session, #6198) and the
  cross-node `RTFlowSessionID` (#5212, protocol_ha.go:190). Verified in
  pkg/dataplane/types.go:16-46 + protocol_ha.go:185-190.
- Clause (4) on equal non-zero `RTFlowSessionID` kills Codex r7's
  counterexample: colliding flow B's alias carries B's RT-flow id, which
  differs from A's, so the predicate fails, the alias imports first-class,
  hits `IdentityConflict`, and drops. Correct.
- The id-0 fallback is where I probed hardest: is there an id-0 pair of
  colliding flows whose values are nonetheless identical? The value's
  node-local `SessionID` is minted PER CONVERTED SESSION
  (`nextUserspaceSyncedSessionID`, #6198 — pkg/dataplane/types.go:31-36
  documents the two nodes disagree on it, which is irrelevant here: the
  comparison is same-row, same node). So A's base row value and B's alias
  value differ in `SessionID` even at RT-flow-id 0, and the fallback's
  identical-`SessionValue` requirement discriminates. The fallback is
  adequate. v8.1 names `RTFlowSessionID` explicitly (the earlier
  "#5212 stable session id" phrasing was ambiguous between the two id
  fields; the node-local one must NOT be the cross-node comparison key).

## Counting HolderSet order-safety

Walked the five orders myself (base-first, alias-first via
adopt/merge, delete-alias-first, delete-base-first, duplicate replay):
each holder-bearing ROW contributes one unit per scope
(`per_worker[w]` / `shared_rows`); reverse companions and derived index
rows are holder-neutral; the identity frees only when both scopes count
zero. The lossy-enqueue note (sync_conn_write.go:36) is real but cuts
the safe way: a LOST acquire means the row never installs (nothing held,
nothing reachable — the peer re-exports), and a lost delete replicates
on the next sweep or the entry reaps. No order frees-while-reachable.

## Residual nits (folded into v8.1/v9 wording, no re-review needed)

1. The four-part predicate's clause (4) now names `RTFlowSessionID`
   explicitly and the full-`SessionValue` fallback (folded, this round).
2. AGY r8's two nits (test both clause-4 branches — id>0 match/mismatch
   AND id-0 fallback; doc comment that the fallback looks up the base
   canonical row in `shared_sessions`) are implementation-level and
   already implied by §5.6/§9 — carried, not re-folded as design text.
3. One wording precision for v9: the fallback's lookup target is the
   shared canonical row at the PRESENTED key's base form — which is only
   computable when the presented key's base form is known (the alias
   import path has the alias's own presented key; the base form is
   derived by the predicate's wire-form relation against the CANDIDATE
   record being tested, so the fallback runs against that candidate's
   row, not a derived key). State it that way so an implementer doesn't
   try to reverse-derive a base key from the alias alone.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives. The four-part
predicate with the RT-flow-id clause is sound, the fallback discriminates
via the per-session node-local id, and the counting HolderSet is
order-safe. If Codex r8 converges (or adds only nits), this is terminal.
