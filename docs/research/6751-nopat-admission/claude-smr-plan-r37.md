# Claude SMR hostile plan review — #6751 plan v15.25 (round 36 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.25 folds AGY r36's two
nits and Codex r36's blocker/major/minors. The transport-level
refusal is the third refinement of the re-prime fence; the
two-stage lineage closes the missed r35 second-MAJOR. Codex r37
and AGY r37 have not been dispatched yet.

## B1 fold (transport-level refusal), attacked

The v15.24 fold refused at installConn — post-setup, so both
endpoints installed locally first and the both-empty proof failed.
v15.25 refuses at the TRANSPORT (listener closed / SYN refused):
no setup completes, nothing installs on either side, the old peer
needs no protocol change (its connect(2) simply fails with
immediate feedback for its 1s retry).
Attack 1 — the drain clock: with transport refusal, no attempt
during the interval installs anything, so the drain requirement
simplifies to "interval ≥ the peer's disconnect-detection bound,
measured from fence engagement" — any connection installed BEFORE
the fence drains within the bound regardless of retry timing. The
"last transport-refused attempt" phrasing is belt-and-braces; the
mechanism needs only the engagement timestamp. Sound.
Attack 2 — re-fence liveness: each cycle is ~2.5 × keepalive
bound; a peer that never completes a bulk keeps getting fenced
until the readiness timeout releases the hold degraded (the
existing bounded terminal). No new liveness debt.
Attack 3 — the old peer's write-completion clearing (BulkEnd
written = success, sticky outboundBulkAcked): the receiver-side
protections (no reconcile without complete bulk, the
reconciliation hold, re-fence on missed deadline) cover our side;
the old peer's legacy clearing is its own behavior, correctly
scoped as out of the fence's control.

## M2 fold (two-stage lineage), attacked

The missed second r35 MAJOR was real: marking only confirmed
aliases let a timeout-admitted suspect promote and export
(SharedPromote is exportable, export.rs:114; the legacy alias
copies the base value exactly, daemon_ha_userspace_convert.go:399).
Attack 4 — conservative suppression cost: a permanently-unresolved
suspect suppresses its own export indefinitely — but the suspect
is local-live (self-NAT/NPTv6) and the suppression holds only
while UNRESOLVED; the definitive resolution pass runs at every
completed BulkEnd (and the 5s window for incremental), so the
suppression persists only when no bulk completes — a state in
which there is no connected peer to export to anyway. The genuine
row's recovery is the next completed bulk's verdict, not a new
mechanism. Sound and priced.
Attack 5 — the verdict→stage transition's atomicity: the
resolution pass is the same serialized pass that ACKs (the
never-ACK-unresolved rule), so a suspect cannot be exported
between verdict and mark update — the mark is updated in the
resolution's own critical section. Consistent with the
two-ledger transaction.

## Minors/nits, verified

- The §5.6 "not fed back" paragraph is REPLACED (not just
  annotated) with the explicit supersession — the contradiction
  class Codex r35/r36 kept finding (text in one section
  contradicting the newer rule) is resolved textually.
- §9 now pins worker-refusal fencing, purge failure → Failed,
  timeout/unknown → Pending with teardown, the restarted
  (E2,1)-after-(E1,100) incarnation case, and the stale-replica
  last_seen regression.
- Rule 6's incarnation is normatively daemon-issued and bound at
  the barriered handoff; the refresh iterator's origin projection
  is named as an internal signature change.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.25 that
I can construct. The remaining items are implementation-level
(refusal wire shape, the concrete quiet-interval multiple already
parameterized, the outcome-channel struct). Both forks remain
settled; the option-(a) core is untouched. If Codex r37 and AGY
r37 converge, this is terminal.
