# Claude SMR hostile plan review — #6751 plan v15.5 (round 18 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.5 folds Codex r18's
atomic-abort blocker, which is the hardest systems finding of the alias
saga: my own v15.4 teardown contract had a race I did not see (a
reconnect installed between the two old disconnect callbacks sees a
nonempty registry, so cleanup never runs). This pass verifies the
generation-fenced transition against the actual registry/disconnect
machinery and attacks its edges. Codex r19 has not been dispatched yet.

## The fenced transition, verified against the machinery

Codex r18's mechanism facts all check out independently: receive loops
remove connections independently via deferred callbacks
(sync_conn_read.go:14); `handleDisconnect` runs the full cleanup only
when both slots are nil at that instant (sync_conn.go:483/496);
`installConn` on a nonempty registry neither records a full-disconnect
edge nor arms `needColdPrime` (sync_conn.go:244/278); and
`outboundBulkAcked` is sticky (sync.go:479). My v15.4 "close both
connections" contract was genuinely insufficient — two closes are two
independent events with an install window between them.

The v15.5 transition closes that window structurally:

1. **Fence first**: the abort increments a generation counter and marks
   the registry FENCED. `installConn` checks the fence BEFORE checking
   slot occupancy, so a reconnect arriving between the two old
   disconnect callbacks is REFUSED — it can no longer observe a
   nonempty registry and claim the connected state. The pinned test
   (install a reconnect between the two old disconnect callbacks)
   directly exercises the r18 race.
2. **Fence-as-invalidation**: stale receive handlers are invalidated
   by the fence, not by `Close` — a failing/erroring close cannot
   strand a live handler (the handler's frames are discarded on the
   fence check, not on socket state).
3. **Exactly-once reset**: bulk/quarantine/capability state resets
   inside the fenced transition when both slots confirm detached (or
   the fence times out) — never per-callback, so no double-reset and
   no missed reset.
4. **Peer convergence**: the peer's reconnect attempts during the
   fence are refused; it retries and lands AFTER cleanup on the
   genuine empty→connected cold-prime edge (sync_conn.go:139,
   sync_conn.go:551, sync_bulk.go:65), which allocates a fresh bulk
   epoch. The recovery is driven by the fence lifecycle, not by either
   side's timing.

## Attacks attempted

- **Fence timeout**: if a slot never confirms detached (wedged
  handler), the fence times out and resets anyway — a wedged handler's
  frames are fence-discarded, so the reset is safe. The timeout must be
  named (implementation parameter, e.g. a small multiple of the
  disconnect callback's normal latency); one-line note folded into §9.
- **Peer older than the fence**: old peers know nothing about the
  fence — but the fence is receiver-local, and the receiver's own
  installConn enforces it; an old peer's reconnect is refused by the
  receiver's fence regardless of the peer's version. Compatible.
- **Abort during an active fence**: the generation counter
  disambiguates; a second abort inside a fence is a no-op (already
  fenced at a higher generation) or re-arms at the higher generation
  with the same reset-once semantics. Named in the transition
  contract.
- **Cold-prime cost cascade**: the r18 minor-3 pricing (lifecycle
  callbacks fire config reconcile + DHCP + IPsec re-advertisement per
  cycle, daemon_ha_sync.go:934) is folded: the cap is sized at
  provisioning so genuine deployments never saturate in steady state;
  the overflow counter + backoff are the escape hatch, not the plan.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.5. The
alias discipline's abort path is now an atomic, generation-fenced
transition with a proven recovery edge, a peer-convergence rule that
needs no cooperation from the peer, and an honest cost model. The
remaining nits (fence-timeout parameter name, second-abort semantics
clarification) are folded into §9. If Codex r19 converges, this is
terminal.
