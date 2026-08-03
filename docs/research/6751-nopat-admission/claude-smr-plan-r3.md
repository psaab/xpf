# Claude SMR hostile plan review — #6751 plan v3 (round 3)

Reviewer: Claude SMR. Posture: hostile. v3 is my own fold of two hostile
rounds; this pass tries to break the v3 holder/foreclosure/transaction
machinery on its own terms and adjudicates AGY r3 (Codex r3 was still in
flight when this was written; its verdict lands in the ledger and any new
findings fold into the same v4).

## AGY r3 adjudication (verified against the worktree at 08709a438)

**AGY r3 major 1 (displacement leaks {Shared}) — REAL CLASS, WRONG MAP;
refined.** v3 says "+{Shared} at `publish_shared_session`, −{Shared} at
`remove_shared_session`" without pinning WHICH map's lifetime brackets the
holder. `publish_shared_session` writes THREE maps: the canonical
`shared_sessions` (keyed by session key, shared_ops.rs:905-909) and the two
reverse indexes (`shared_nat_sessions` at :921/:932, `shared_forward_wire_sessions`).
AGY reads the holder as riding the reverse index, where a colliding insert
drops the displaced entry without `remove_shared_session`. The correct pin is
the CANONICAL map: its insert displaces only the SAME key — the same logical
session re-publishing (refresh / promote / RG migration) — which the
holder SET absorbs idempotently (same flow record, `{Shared}` already
present, no double count). A reverse-index displacement drops only an index
row pointing at an entry whose canonical row (and holder) is untouched, so
it is NOT a holder event. With the holder pinned to the canonical map, AGY's
displacement leak does not exist — BUT v3 is under-specified and an
implementer could ride the wrong map, so v4 must pin it explicitly. Where
AGY is RIGHT: the reverse-index displacement counter
(`NAT_REVERSE_KEY_SHARED_DISPLACEMENTS`) still fires for cross-mechanism
collisions, and the displaced flow's reverse lookup silently degrades to the
shared-canonical... no — out of scope; the holder pin is the finding.

**AGY r3 major 2 (wholesale clear leaks every {Shared}) — CONFIRMED REAL.**
`clear_synced_state` (coordinator/mod.rs:756-766) `.clear()`s all three
shared maps wholesale — every synced entry's canonical row vanishes with no
`remove_shared_session`, so every synced interface-mode identity's `{Shared}`
holder leaks until process restart. This is the same class as the materialize
bypass (round 2): an unwrapped shared-map mutation. v4 must make the clear
path iterate-and-release (`−{Shared}` per forward interface-mode entry)
BEFORE clearing — or run a registry-side epoch reset scoped to synced-origin
identities; the iterate-and-release is simpler and matches the
`remove_shared_session` discipline.

**AGY r3 nit 3 (churn cap) — accepted as policy with one hardening.**
`reclaim_absent` runs only at snapshot-apply. Add: a release that empties an
absent-address allocator reclaims it opportunistically (same predicate),
which bounds accumulation between applies; the 256 cap stays as the
config-abuse bound, documented.

## My own round-3 findings

### M13 (MAJOR) — The {Shared} bracket must enumerate the Close-delta relay, not just the seven direct callers

The locally-owned session lifecycle's shared removal does NOT happen at reap:
`reap_expired_sessions` (worker/loop_body/mod.rs:1616-1650) removes the
worker-table entry and emits a Close delta (expire.rs:342 gate allows it for
non-peer-synced origins), and the DELTA CONSUMER runs
`remove_shared_session` (session_delta.rs:436/446). So the {Shared} bracket
for a locally-admitted session is: + at publish (install), − at Close-delta
consumption — with delta-processing delay and ordering between. v3's
"+ at publish / − at remove_shared_session" is right but incomplete as a
spec: the implementer must know the reap path reaches removal only VIA the
delta relay. If any locally-owned removal path bypasses the delta relay
(e.g. `sessions.delete` + `remove_shared_session` direct at
session_glue/mod.rs:587 — that one calls remove_shared_session directly, fine;
`delete_synced.rs` handles peer deletes), the holder still balances because
every bypass calls remove_shared_session directly. Enumerated: the seven
`remove_shared_session` callers (session_delta.rs:436/446, promote.rs:181,
session_glue/mod.rs:587/938/945, session_import.rs:314/329,
local_delivery.rs:91), the canonical same-key displacement (set-idempotent,
non-event), the reverse-index displacement (non-event), the wholesale clear
(AGY-2, fixed in v4). The bracket is complete — v4 states it as a closed
inventory with the delta-relay note.

### M14 (MINOR) — Coordinator pre-reserve identity for bulk-sync replay must be spelled out

Bulk re-sync re-imports entries that are already published (coordinator
re-runs session_import for the same entries on reconnect). The pre-reserve
runs `reserve` per import; for an entry whose identity it already holds
({Shared} present), the idempotent re-entry (`live_by_flow[flow]` hit)
returns existing — {Shared} stays single. But a re-import whose decision
carries a DIFFERENT tuple (active re-admitted with a new PAT port) hits the
stale-tuple-drop (§5.3): the drop decrements... WHICH holders? The stale
record's holders are {Shared} ∪ {Worker(Wn)} across the standby's workers;
the stale-tuple-drop at the coordinator can only decrement {Shared} — the
stale {Worker(Wn)} holders orphan until each worker's own re-reserve (the
upsert fanout follows the publish) drops ITS stale tuple and re-adds. v4
must state the per-holder-owner discipline: each holder is decremented only
by its owner's path (coordinator ↔ {Shared}, worker ↔ {Worker(W)}), and the
stale-tuple-drop at each site decrements only its own marker; orphan windows
are bounded by the fanout. Safe direction (leak-then-clean, never
free-early), but must be written down.

### M15 (NIT) — §5.6 "counted + Debug log" for dropped imports needs a counter name

The drop-on-conflict at import is a security-relevant event (a standby
refusing a synced session). One line: it bumps
`interface_snat_identity_exhaustion_total`? No — it is a CONFLICT, not
exhaustion. Give it its own additive counter
(`xpf_userspace_interface_snat_sync_conflict_dropped_total`) or fold it into
an existing HA sync anomaly counter. v4 names it.

## What v3 got right (verified, not rubber-stamped)

- The full-cycle chunked probe's exhaustion is exact per destination and
  linearizability-safe under concurrent mints/frees (AGY r3's math checks
  out: 1008 chunk-acquisitions ≈ 0.64 µs each, no starvation of the
  preserve fast path).
- The two-layer §5.7 foreclosure's snapshot-builder layer uses a real,
  shipped fail-closed channel (`pool_failure`/`PoolUnusable`,
  nat_source.go:118-122) and the builder does see runtime addresses
  (interfaces.go:455).
- The {Worker(u32)|Shared} model with the single install+reserve wrapper
  covers all three sync-family install sites (AGY r3 verified the caller
  inventory complete: upsert_synced.rs:65, session_glue/mod.rs:808/1130).

## Verdict

**PLAN-NEEDS-REVISION** — one major refinement class remains: the {Shared}
holder's exact bracket (canonical-map pin + the AGY-2 wholesale-clear
iterate-and-release + the M13 delta-relay inventory + the M14
per-holder-owner decrement discipline), plus the M15 counter name and the
AGY nit-3 opportunistic reclaim. All are specification-level folds; the
architecture holds. If Codex r3 adds nothing new, v4 should be the
convergence candidate.
