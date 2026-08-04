# Claude SMR hostile plan review — #6751 plan v15.19 (round 31 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.19 folds Codex r31's
seven blockers + two majors + minor. The crux fold (incarnation-gated
close suppression) actually SIMPLIFIES the design; this pass attacks
whether it is stated tightly enough to implement, and whether the
suppression has its own leak. Codex r32 and AGY r32 have not been
dispatched yet.

## B1 fold (incarnation-gated close end-to-end), attacked

Attack 1 — stripe coverage completeness: the rule names "BOTH the
mirror publish path and the compare-and-delete". The mirror has more
than one publish site: conntrack publish (publish_conntrack.rs),
session-map publish/delete (bpf_map/mod.rs:600-720), redirect
entries, and the last_seen/policy_id refresh writers
(bpf_map/mod.rs:364/438). If any same-key writer skips the stripe,
the TOCTOU Codex named reopens. The plan text says "the mirror
publish path" — implementation must enumerate every same-key writer
into the stripe (noted; §9's serialization test must construct the
migrate-during-compare race, which fails RED without full coverage).
Attack 2 — the suppression's own residual: with the forward close
suppressed, the peer's state for the OLD incarnation is superseded
by the replacement Open at a strictly greater generation (per-key
guard) — correct. If that Open is dropped (queue full), the peer
keeps the dead S_old row until the backfill sweep re-sends S_new —
bounded, and strictly better than the alternative (publishing the
close tombstones the LIVE S_new). The reverse-companion sub-case:
S_old's reverse row carries S_old's id (matches → deleted locally),
but the suppressed forward close never tells the peer to delete
S_old's differently-keyed reverse companion — it ages out at the
session timeout. That is a bounded dead-session companion residual,
identical in shape to any uncompanioned dead session; not worth a
fourth mechanism. Documented here so it is a decision, not an
oversight.
Attack 3 — expected-id sourcing: tunnel_purge.rs:69 hardcodes
session_id: 0 today with a comment asserting the entry "carries no
session id" — the fold makes the purge read the id from the
shared_sessions entry it is purging. That entry IS the authoritative
record for the purge, so the id is available by construction;
whether the current SyncedSessionEntry struct literally stores it is
an implementation check (the #5212/#4915 id is assigned at install
and the import path retains it — the fold's id-preservation rule
already requires the sync-side record to carry it).

## B2/B3/M8 folds (omission index + fenced inbound re-prime), attacked

Attack 4 — the fenced reconnect really cold-primes inbound: our
forced disconnect tears both fabrics; the peer observes both slots
empty; its next accept arms needColdPrime (#4962 latch); the inbound
authoritative bulk follows. Mechanism verified against the existing
latch — no new protocol message needed.
Attack 5 — the reconciliation hold's scope: the hold covers carried
keys of the overflowed episode only — a narrower hold than "stop
reconciling". The plan says "does not reconcile-delete any carried
key" — the hold is keyed on the carried set, not global. Sound; a
global hold would starve legitimate reconcile for the re-prime
window.

## B4/B5/B6/B7 folds, verified

- The §5.3 contradiction is removed; the signature inventory now
  budgets registry + worker + effective destination per call class,
  and the probe path correctly takes registry-only.
- Static: the emitted-port rule (8080→80 reserves E:8080) is pinned;
  the inbound acquisition point is named with its cites; the
  drain-on-removal composes with the existing drain-vec discipline.
- The purge's serialized-event-loop atomicity is the same mechanism
  the quarantine already uses (sync_conn_gen.go:381) — no new lock,
  and the store-mutex-before-BPF-delete order fix is named as part
  of the work, not assumed.
- The mixed-version cell is now honest (old-sender aliases bounded
  by session lifetime) — a weaker but TRUE promise, which is what a
  matrix needs.
- The producer scoping (kernel GC disabled in userspace mode,
  daemon_run.go:230) converts the "FOUR producers" claim from false
  to scoped-true.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.19 that I
can construct. Implementation-level notes (not plan defects): stripe
coverage must enumerate every same-key mirror writer; the
suppressed-close reverse-companion ages out at session timeout (a
documented residual, adopted); the purge's expected id must be
readable from the shared_sessions entry (struct check at
implementation). If Codex r32 and AGY r32 converge, this is
terminal.
