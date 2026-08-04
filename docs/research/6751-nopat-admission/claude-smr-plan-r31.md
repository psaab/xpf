# Claude SMR hostile plan review — #6751 plan v15.18 (round 30 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.18 folds AGY r30's eight
findings and Codex r30's six blockers + nit into one revision. The
highest-risk folds are the compare-and-delete incarnation rule, the
standby import-driven allocator creation, and the owner-key type
split. Codex r31 and AGY r31 have not been dispatched yet.

## Compare-and-delete incarnation rule (AGY 1-3 / Codex 1), attacked

Attack 1 — token presence: the fold relies on the #5213 stable
session_id being stamped into the conntrack value at publish
(bpf_map/mod.rs:260-265 confirms the field exists and is stamped).
A row published BEFORE #5213 (legacy after a helper upgrade) has a
zero/legacy id — the compare-and-delete must define the legacy case:
a stored id of 0 never matches a real closing id, so a legacy row
survives a close. That is the SAFE direction (the tombstone still
conveys the close to the peer; the stale mirror row is omitted from
bulks via the sender tombstone). Verified the fold's sender-tombstone
leg covers it; §9 should pin the legacy-id case explicitly (noted
below).
Attack 2 — purge/GC generation: delete_synced_session_gen(key, 0)
applies unconditionally at the import guard; the fold draws a tracked
tombstone generation for tracked keys. A purge of a key the sender
never tracked stays gen-0 — the documented unordered class, bounded
by the next bulk. Consistent with the r23 disposition.

## Standby import-driven creation (Codex 4), attacked

Attack 3 — creation vs the 256 cap on the standby: reserve_synced now
creates allocators import-driven via the same fallible path — a
standby whose peer owns >256 egress addresses fails the import
closed (IdentityConflict-class drop with the registry-cap counter)
rather than silently exceeding the cap or silently not reserving.
That is the honest failure and matches the admission arm. The
asymmetry (active admits, standby cannot mirror) trips the sync
identity-conflict counter and surfaces via the debt/quarantine
machinery. Acceptable; noted as an operational ceiling identical to
the admission one.
Attack 4 — import-driven creation vs drain: the rule keeps
NotThisDomain for drain cases, so a draining address's imports still
route to the draining allocator via the drain-vec scan (AGY r4's
rule), not the fresh one. Consistent.

## Owner-key type split (Codex 3), attacked

Attack 5 — InterfaceOwnerKey vs pool SourceNatFlowKey collision in
shared helpers: release_source_nat_allocation is the EXISTING
teardown for pool flows; interface records release via their own
registry path. The split means a release must know which domain the
flow lived in — the plan's flow-keyed discrimination (AGY r4) already
carries domain provenance in the record. No new ambiguity.
Attack 6 — occupancy as explicit input at the port-less branch:
reserve_address_only(owner, occupancy, w) — the occupancy for a
port-less protocol carries flow.src_port==0 and the effective dst;
the AddressOnlyReverseKey derivation (allocator.rs:1735-1740) moves
to the explicit occupancy. GRE/ESP token idempotence preserved
(owner unchanged). Sound.

## Carried-alias provisional purge (Codex 2), attacked

Attack 7 — purge-at-BulkEnd vs a base that arrives LATER than the
alias's evaluation: the BulkEnd snapshot is definitive (complete), so
"alias signature matches AND sibling base in the definitive set" is
decidable at that instant; a base arriving after BulkEnd is the
lost-base class whose admission was already the designed fallback.
No new window.

## Remaining folds, verified

- Carry-forward clear-on-completion + capped-overflow forceResync:
  the D1-across-aborted-bulks trace converges; the cap is the
  generation-map order, and overflow re-anchors authoritatively.
- Static provenance + test-direction fix: the §9 directions now match
  the §5.7 norm (static-first → interface PATs; interface-first →
  static fails closed); provenance covers config removal, drain, and
  pool/NAT64 enablement via the validator owner set.
- Id preservation across re-bulk: the sync-side record echoes the
  received id; the BPF zero-lift is bypassed at encode time.
- Exact-publication purge (P2): genuine replacement rows survive;
  the documented shared_ops.rs:907 residual is unchanged.
- Pre-dispatch no-pair assertion: present in §9.

## Self-found nit (folded into §9)

The legacy-zero session_id row (pre-#5213 publish) never matches a
closing id — the safe direction, but it should be pinned alongside
the incarnation test so a future refactor doesn't "fix" it into
matching. Added to the §9 incarnation entry.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.18 that I
can construct. Implementation notes (not plan defects): the
legacy-id pin; the standby's 256-cap import failure surfaces as a
sync identity-conflict, not a silent skip. If Codex r31 and AGY r31
converge, this is terminal.
