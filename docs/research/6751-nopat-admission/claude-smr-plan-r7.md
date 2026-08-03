# Claude SMR hostile plan review — #6751 plan v7 (round 7, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v7 is my own fold of Codex r6's
fabric-alias blocker, the deepest mechanism yet; this pass re-derives the
alias lifecycle and attacks the two edges AGY r7 and I could construct.
Codex r7 was in flight when this was written; its verdict lands in the
ledger and folds if it adds anything.

## Fabric-alias fold, independently re-derived

- Export order is canonical-then-alias on ONE stream
  (`ss.QueueSessionV4(key, val)` then `ss.QueueSessionV4(wireKey, wireVal)`,
  daemon_ha_userspace_stream.go:368-376), so per-session in-order arrival
  holds on a healthy stream.
- The predicate as shipped (shared_ops.rs:73-100) is three-part: one key
  is the other's forward-wire form (`forward_wire_key` idempotent) AND
  identical NatDecision AND at least one side sync-derived. The third
  clause is what makes it safe to elevate: LOCAL mints are never
  sync-derived, so an active-node genuine collision (which gets distinct
  PAT decisions anyway) can never satisfy the predicate. AGY r7's analysis
  matches mine.
- The under-count inheritance is bounded by an already-ambiguous case: a
  genuine session whose canonical key equals a fabric alias's key AND
  whose NatDecision is identical requires overlapping address space (a
  host owning the firewall's WAN address E in another VRF) — the #2387
  cross-VRF same-tuple case, already indistinguishable at the reverse
  index pre-change and explicitly out of scope in §5.1. Accepted.

## Self-found edge (folded into v7.1 as a design sentence, not a redesign)

### E1 (MINOR) — Out-of-order alias arrival across replay/reconnect

On a single healthy stream the alias follows the canonical. Across a
reconnect, BULK sync and incremental deltas can interleave (a bulk export
of an older epoch racing a newer delta), so an alias CAN arrive before
its base. v7 as written runs the predicate one direction
(presented-is-wire-form-of-existing → attach to base); an alias arriving
first finds no base and would mint a first-class record for the alias's
presented key — and the base's later import would `IdentityConflict` and
drop (worse than v6 for exactly the session the alias exists to protect).
v7.1 states the merge rule: the predicate runs BOTH directions at import
— presented-is-wire-form-of-existing (alias attaches to base) AND
existing-is-wire-form-of-presented (base finds an earlier alias record
and ADOPTS it: the alias record's markers and identity fold into the
base's record; the spare record drops). Both orders converge to one
record with the union of markers. AGY r7 nit 1's out-of-order test pins
exactly this.

## AGY r7 nits adjudication

- NIT 1 (out-of-order test assertion): adopted and upgraded to the E1
  design sentence above.
- NIT 2 (doc comment on the predicate helper's `sync_derived` scope):
  correct and cheap; named in §5.6 for the implementer.

## Everything else in v7 (verified, not re-litigated)

The secondary flow index + selection rule (Codex r6 M2) is coherent —
local mints are single-decision episodes, the two-record transient lives
only across the re-sync boundary on the standby where no local mint of
that flow runs. The fixed-address fail-closed modes, MaterializeConflict
wording, queue/relay-or-expiry bound, and holder-bearing-forward-replica
qualification all read correctly against their citations.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives. The one
self-found edge (E1) is a design-sentence fold (both-direction predicate +
merge rule) with AGY's out-of-order test pinning it — folded into v7.1
without changing the architecture. If Codex r7 adds nothing new, this is
the convergence candidate.
