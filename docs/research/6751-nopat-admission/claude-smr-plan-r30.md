# Claude SMR hostile plan review — #6751 plan v15.17 (round 29 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.17 folds Codex r29's
eleven findings. The biggest new surface is the owner/occupancy tuple
split and the incarnation-conditional delete; the pass attacks those
first. Codex r30 and AGY r30 have not been dispatched yet.

## Finding-1 fold (incarnation-safe, producer-complete), attacked

Attack 1 — the table check's consistency substrate: the
incarnation-conditional delete compares against the authoritative
SessionTable in the producer domain. A same-key replacement lands on
the SAME worker (hash-consistent steering), so the check is
worker-local and race-free; there is no cross-worker same-five-tuple
install path. Sound; implementation note: the check must read the
worker's own shard, not a cross-worker view.
Attack 2 — delete-error accounting: ENOENT-tolerant retry, then
publish-with-count + out-of-sync latch + #2442 re-export. The
tombstone remains the peer's correctness channel even when the mirror
is unwritable — the failure mode degrades to "mirror unreliable,
latch trips, full re-export", which is the existing catastrophic-
mirror posture, not a new failure class. Sound.
Attack 3 — funnel completeness: expiry (session_delta), terminal
teardown (session_glue:546), policy invalidation
(daemon_policy_invalidate.go:357) all named with the same
delete-before-publish discipline. The r29 "mirror presence does not
imply no close published" counterexample (invalidation publishing
after a FAILED delete) is now covered by the error-accounted rule:
the delete is retried; persistence latches. Residual: the window
between retry-exhaustion publish and the re-export is bounded by the
re-export itself. Acceptable.

## Finding-2 fold (carry-forward), attacked

Attack 4 — carried key closed before BulkStart: tombstone deletes the
row via the normal path; reconcile acts only on present rows, so the
carried set entry is inert. No resurrection — verified the plan now
says exactly this.
Attack 5 — carried key vs quarantine: a quarantined-then-admitted key
installs via the timeout path and is carried like any delta install.
Consistent with bookkeeping-not-gated (AGY r15).

## Finding-3 fold (owner/occupancy split), attacked

Attack 6 — shipped hybrid regression: :807/:880 stop canonicalizing
dst_ip into the flow key. A consumer relying on the hybrid for
release matching of PRE-CHANGE flows would miss — but the helper is
not upgraded in place; restart rehydrates via the HA re-sync
pre-reserve (already in §9), and the staged/drain machinery covers
allocator generation changes. Acceptable; flagged as an
implementation note for the release path to tolerate both shapes
during the rehydration window.
Attack 7 — the split vs NAT64: nat64.rs sites have
rewrite_dst_port: None, so occupancy == original for the port —
behavior unchanged, matching Codex's own verification.

## Finding-4 fold (static occupancy), attacked

Attack 8 — the registry write site: static returns BEFORE the
interface branch (nat_exception.rs:57), so the occupancy record must
be written at the STATIC decision point (static_nat.rs), a new call
site into the same registry. Plan-level acceptable; the fail-closed
on conflict matches the fixed-address posture. The asymmetric rule
(static held → interface PATs; interface held → static fails closed)
is the only PAT-consistent assignment. Sound.

## Finding-5 fold (index cardinality + confirm-purge), attacked

Attack 9 — bulk-epoch index memory: bounded by the received set —
same order as the existing bulkRecv maps; no new worst case. The
incremental cap (4096) degrades to timeout-admission, the designed
fallback — convergence restored.
Attack 10 — confirm-purge vs a genuine row at the alias key: the
documented residual (shared_ops.rs:907) flips from "strands until
timeout" to "purged at confirm" — strictly more consistent with the
base's companion discipline. Sound.

## Findings 6-11 folds, verified

- (bulk epoch → debtGen) pair + non-current-ACK-ignore + terminal
  disable-clear: the attribution is implementable from named state.
- Worker-id threading and the fallible allocator_for with the cap
  counter: both mechanical, both with §9 pins.
- Sweep-wake: the arm resetting the timer makes the bound the sweep
  cycle; the 10s backoff claim is corrected.
- Producer enumeration: sweep first-offers in, journal re-envelope
  explicitly out of re-drawing (epoch-only), matching layer (a1).
- Projection as exclude-list: matches the manager_ha.go:1595 import
  surface.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.17 that I
can construct. Implementation-level notes (not plan defects): the
incarnation check is worker-shard-local; the release path tolerates
both owner-key shapes across the rehydration window; the static
registry write lands at the static decision point. If Codex r30 and
AGY r30 converge, this is terminal.
