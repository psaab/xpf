# Claude SMR hostile plan review — #6751 plan v15.16 (round 28 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.16 folds Codex r28's four
blockers, two majors, and minor, plus AGY r28's nit. Two of the folds
(producer-ordering invariant; daemon-lifetime debt) are new design
surface written for this fold. This pass attacks them first. Codex
r29 and AGY r29 have not been dispatched yet.

## Blocker-1 fold (producer-ordering invariant), attacked

The fold's root claim: reordering the Rust Close path to
delete-mirror-row-before-publish makes "mirror has K at a Go read"
imply "no close for K consumed by Go", so the V1 re-read is a
consistent cut against Go's generation map.

Attack 1 — funnel completeness: are ALL outbound close publications
routed through session_delta.rs after their mirror deletions? The
per-session Close path is the :420/:426/:444/:445 block (after the
:282 publish — the reversed order). The other mirror-removal sites
(session_glue/mod.rs:437 worker-synced redirect, :577 import-path
removal, :926-933 kernel-local transitions) never outbound-publish a
delete for a locally-owned key: a sync-imported session's delete is
SENT by the peer through its own ordered funnel and consumed via the
receiver import path. The fold now scopes the invariant to
outbound-published closes of locally-originated sessions and cites
the bulk's owned-zone filter (ShouldSyncZone + IsReverse,
sync_bulk.go:94-96). Verified against the call sites.
Attack 2 — Go-consumption direction: close CONSUMED ⇒ close
PUBLISHED (trivially) ⇒ mirror row already deleted (producer order).
Go-side lag is irrelevant to the direction needed. Sound.
Attack 3 — V2 mint vs in-flight close: mirror present ⇒ close not
consumed ⇒ gen map holds install record or none; a fresh mint G_m is
strictly below the close's later G_d (global monotone counter), so
the tombstone wins in both wire orders. Sound.
Attack 4 — known-stale omission vs received-set (my own residual
find): a replacement delta dropped on a full queue + BulkEnd before
the 1s sweep → receiver deletes K at reconcile, re-installs at the
sweep — a sub-second standby gap for a mid-bulk-changed session.
This is now stated explicitly in the plan as a documented residual,
identical in shape to today's in-flight-change-during-bulk behavior.
Not a regression; hidden cost now visible.
Attack 5 — wholesale config-clear: config-apply session clears emit
their own ordering through the #3931/#5274 config-epoch machinery
(the receiver refuses stale-epoch installs), independent of this
invariant. No interference.

## Blocker-2 fold (daemon-lifetime debt), attacked

Attack 6 — inheritance correctness: the debt arms with debtGen++
under the daemon lifecycle lock; the replacement SessionSync reads
owed=true at first connect and primes regardless of the
wasDisconnected shape. A second abort during recovery re-arms with
debtGen+1; the older prime's ACK maps to the older generation and
fails the exact-generation compare — the admitted sync.go:513 race
dies by construction. Sound.
Attack 7 — ACK-vs-write: discharge keys on the ACK (receiver
confirmed + reconciled), not BulkEnd-written — matches Codex's
sync_bulk.go:183 / sync_conn_read.go:249 evidence. A written-but-
unacked bulk leaves the debt armed → the retry/reconnect machinery
re-drives. Sound.
Attack 8 — nil-runtime defer: cold-prime attempted with sessions==nil
now DEFERS and re-arms instead of erroring (the accept-at-:1138 vs
SetRuntime-at-:1165 window Codex named). The debt cannot be
accidentally discharged by a failed prime. Sound; implementation must
thread the defer into doBulkSync's error path.

## Blocker-3 fold (effective-destination port), attacked

Attack 9 — canonicalization vs rule MATCHING: the fold touches ONLY
SourceNatFlowKey construction (occupancy identity), never the
rule-match tuple (nat.rs:104's flow.dst_ip/dst_port feeds
match_source_nat_result_for_tuple — Junos rule semantics, settled
behavior). The distinction is stated in the fold. Verified the
occupied-identity sites: :807 and :880 both build with raw
key.dst_port today (the bug), and forward_wire_key/reverse_wire_key
use rewrite_dst_port (the target shape). Sound.
Attack 10 — NAT64/static interplay: rewrite_dst_port absent →
unwrap_or(key.dst_port) — identity unchanged for port-preserving
decisions. No blast radius beyond DNAT-with-port cases.

## Blocker-4 fold (base-identity index), attacked

Attack 11 — index lifetime alignment: incremental-path index entries
must live EXACTLY as long as the quarantine fallback window (5s) — a
base entry expiring before the alias's own fallback would force a
genuine pair into timeout-admission (the designed fallback for
non-fabric rows, so fail-safe not fail-closed, but it would defeat
the optimization). The fold ties the expiry to the fallback window;
noted as an implementation invariant.
Attack 12 — decode-time population vs the alias-first case: the alias
arrives before the base; at its BulkEnd resolution the index holds
the base's (key→id) from decode — definitive. Incremental alias-first
waits on the 5s timer with the index being populated as the base
arrives. Both shapes resolve.

## Majors/minor folds, verified

- Universal producer rule: draw+epoch+record in one critical section
  per producer (the sync_conn_gen.go:119 draw-before-lock +
  putGenBounded unconditional-overwrite pair is the exact regression
  the §9 test pins RED).
- Equality projection: LastSeen/policy_id/counter-only refresh does
  not force a mint (bpf_map/mod.rs:364/438 excluded fields named).
- Barrier request path (writeBarrierMessage, sync_bulk.go:305) joins
  the envelope discipline — Codex's closing-note gap covered.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.16 that I
can construct. Two self-found issues (invariant scope across
non-funnel removal paths; known-stale received-set residual) were
folded into the plan text during this pass. Implementation-level
notes, not plan defects: the doBulkSync defer-on-nil-runtime path and
the index-expiry=fallback-window alignment must land as written. If
Codex r29 and AGY r29 converge, this is terminal.
