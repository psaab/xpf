# Claude SMR hostile plan review — #6751 plan v15.4 (round 17 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.4 folds Codex r17's
recovery-contract blocker, which is the class of finding that makes or
breaks the alias discipline's operability: an abort with no recovery
mechanism is a wedge, not a fail-safe. This pass verifies the teardown
contract against the actual sync state machinery and attacks the
remaining gaps. Codex r18 has not been dispatched yet.

## The recovery contract, verified against the machinery

Codex r17's three mechanism facts all check out: `BulkSync()` is
write-only (records the pending ACK, writes BulkEnd, returns without
waiting — sync_bulk.go:169/183/195); connection setup clears
needColdPrime before any ACK (sync_conn.go:194); and the survivor
re-drive's `outboundBulkAcked` is sticky after the first acknowledged
bulk (sync.go:479). My v15.3's "let the sender's bulk machinery retry"
was indeed false — there was no retry trigger at all. The v15.4
contract (receiver closes BOTH connections on abort) converts every
abort shape to the full-disconnect path that already exists and works:
all fabrics down → state reset → reconnect → cold re-prime → fresh
bulk with a fresh epoch. The trailing-frames problem (session handlers
use `bulkInProgress` only for bookkeeping and install trailing frames
normally, sync_conn_read.go:109) dies with the TCP teardown itself —
discard-until-end on a live stream would have been a new, raceable
machinery; teardown reuses the proven one.

## Attacks attempted on the contract

- **Reconnect backoff vs liveness**: the reconnect after an abort is
  rate-limited by the reconnect backoff; a persistent overflow livelock
  (reconnect → bulk → overflow → teardown) is bounded by the backoff
  and surfaced by the overflow counter + tunable cap. An operator sees
  saturation, not silence. Acceptable.
- **Abort while the peer is healthy**: teardown of both connections
  when only the RECEIVER's quarantine overflowed is heavy-handed (the
  peer did nothing wrong) — but the peer's cold re-prime is exactly
  the recovery the design needs (full snapshot re-drive), and the
  cluster reconnect machinery handles healthy-peer reconnects as a
  routine path. The cost is one cold re-prime per genuine overflow —
  rare by construction (>4096 fabric SNAT sessions in one bulk).
  Acceptable.
- **Superseding BulkStart vs teardown**: the two terminal rules
  coexist correctly — a superseding BulkStart arriving WITHOUT an
  abort (the E1→E2 fabric-failover path) drops the prior epoch's
  pinned entries fail-closed before the maps are overwritten; an abort
  (overflow/deadline) tears the connection down so no BulkStart on the
  aborted epoch can arrive at all. No contradiction.
- **The fourth death shape** (single active-fabric reset after a prior
  successful bulk, other fabric survives): the abort itself tears down
  both connections, so the shape no longer exists as a separate case —
  it becomes the full-disconnect case.

## Residual nits (implementation-time)

1. The reconnect backoff's parameters (base/cap) are implementation
   tuning; the plan should name that the backoff lives per-peer and
   does NOT delay the first reconnect after an UNRELATED disconnect
   (only abort-triggered reconnects are backed off). One line for §5.6.
2. The capability ticker's period choice (e.g., matching the
   clock-sync cadence) is implementation-time; the contract (periodic,
   additive, old-peer-ignorable, reset-on-reconnect) is closed.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.4. The
alias discipline now has a complete lifecycle: exact omission on the
happy path, epoch-definitive resolution at BulkEnd, fail-closed
terminal rules at every epoch-death shape, and a recovery contract
that reuses the proven full-disconnect re-prime instead of inventing a
retry. If Codex r18 converges, this is terminal.
