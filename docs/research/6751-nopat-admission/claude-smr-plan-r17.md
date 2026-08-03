# Claude SMR hostile plan review — #6751 plan v15.3 (round 16 fold-check, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v15.3 folds Codex r16's two
lifecycle blockers (eviction payload loss; missing bulk teardown +
E1→E2 supersession) that my own r16 review's implementation notes got
WRONG (I wrote "eviction resolves as admit-after-confirm-check" and
"stalled bulk resolves in the existing bulk-liveness teardown" — Codex
showed the payload for the first doesn't exist and the machinery for
the second doesn't either). This pass verifies the terminal rules that
replaced them and attacks their edges. Codex r17 has not been
dispatched yet.

## Terminal rules, re-derived

- **Overflow → abort, never evict.** The payload argument is decisive:
  bulk bookkeeping retains only keys (sync_conn_read.go:200), so an
  evicted frame's value is gone — any "admit evicted entries later"
  rule is unimplementable, and any "drop evicted entries" rule loses
  genuine self-NAT rows. Aborting the incomplete bulk WITHOUT ACK (no
  reconcile, no sync-hold release) with a per-peer re-prime backoff is
  the only bounded honest terminal action: the peer's bulk retry
  re-drives every row, so nothing is lost permanently, and a
  persistently overflowing deployment (>4096 fabric SNAT sessions in
  one bulk) sees a saturation counter telling it to raise the cap.
  Livelock check: the retry overflows again only if the deployment
  genuinely exceeds the cap — the counter + tunable cap is the
  documented escape, and fail-closed beats silent misdelivery. Sound.
- **Epoch death is EARLIEST-OF-three.** (i) Own BulkEnd: definitive
  confirm-or-admit against the complete snapshot (unchanged, verified
  last round). (ii) Superseding BulkStart: I verified the reset
  condition — receiver bulk state resets only when ALL fabrics are down
  (sync_conn.go:496/554), so a single-fabric drop mid-E1 with a
  survivor re-drive makes E2's BulkStart unconditionally overwrite E1's
  epoch and received maps (sync_conn_read.go:183/198). Dropping E1's
  pinned entries fail-closed BEFORE the overwrite is the only rule that
  cannot leak a stale frame into E2, and the superseding bulk re-sends
  everything, so genuine rows lose nothing but a bounded delay.
  (iii) Bulk deadline: Codex is right that none exists today (read
  timeouts only heartbeat, sync_conn_read.go:27; the 30s VRRP timeout
  degrades without teardown, manager.go:372), so the per-bulk receive
  deadline is required NEW behavior, and it aborts per the overflow
  rule. The three terminal points cover every epoch lifecycle:
  complete, superseded, stalled. My r16 "existing bulk-liveness
  teardown" note is replaced by real machinery; the supersession case
  I did not see is covered.
- **Capability lifecycle**: gate on ALL FOUR alias branches
  (V4/V6 open AND close — the omission must also stop alias deletes,
  else a closed legacy-alias row from the pre-capability window gets
  its delete while later aliases never arrive, an asymmetry Codex
  caught); re-advertisement needs a NAMED periodic transport
  (sendClockSync is setup-only, sync_conn.go:137) — new ticker or
  piggyback on an existing periodic stream message — and capability
  state resets to UNKNOWN on every (re)connection. All three are
  implementation-closing, not design-changing.

## Edge attacks attempted

- Abort-during-active-bulk while the peer keeps streaming: the
  receiver stops ACKing, the peer's own bulk timeout re-drives; the
  backoff prevents tight retry storms. Acceptable.
- Superseding BulkStart arriving while the prior epoch's resolution
  pass is mid-flight on the serialized loop: both are events on the
  same serialized loop, so the resolution pass for E1 (fail-closed
  drop) and E2's BulkStart (which drops E1's pinned entries) are
  ordered by construction; the maps are overwritten only inside the
  loop. No interleave.
- The epoch-death fail-closed drop and the genuine self-NAT collateral:
  a genuine row whose bulk dies unresolved is dropped and re-sent on
  the retry — a delay, not a loss (the peer re-drives everything).
  Priced correctly.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.3. The
alias discipline is now lifecycle-complete: exact omission on the
happy path, epoch-definitive resolution at BulkEnd, fail-closed
terminal rules at every epoch-death shape (overflow, supersession,
stalled deadline), bookkeeping that never lies to reconcile, and a
delete lifecycle matched to the exporter's real queue order. Residual
nits: the named-capability-transport choice and the counter-name
inventory are implementation-time. If Codex r17 converges, this is
terminal.
