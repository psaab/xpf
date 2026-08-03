# Claude SMR hostile plan review — #6751 plan v6 (round 6, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v6 is my own fold; this pass
independently verifies the three v6 mechanism changes (tuple-versioned
records, alias-sweep parity, uniform quarantine placement) and attacks what
they might have introduced. Codex r6 was in flight when this was written;
its verdict lands in the ledger and folds if it adds anything.

## Independent verification of the v6 folds

**Tuple-versioned records (Codex r5 B1) — fold is coherent.** Confined to
the interface registry's allocator instances: records keyed
`(flow, translated)`, each with its own holder set; idempotent re-entry on
the exact pair; stale-drop removes only when empty; caps count records
(bounded transient of 2 during staged replacement — same-index drain count
transiently +1 and decrements on T_old release, no underflow/false-drain
path — I re-derived AGY r6's arithmetic and agree). Pool allocators keep
the flow-keyed shape and free-on-release semantics, so #6522's open holder
question is neither fixed nor worsened — the two-shape split is the right
containment.

**Alias sweep parity (Codex r5 B2) — verified against
`remove_shared_session`.** The removal side (shared_ops.rs, the function
following `publish_shared_session`) removes reverse_wire, reverse_canonical
only when `!= reverse_wire`, and forward_wire only when `!= key`, with
owner-RG index maintenance — the sweep in the displacement path must mirror
those exact conditionals, and v6 §5.6/§6 says so. Side effect worth noting:
the sweep TIGHTENS the SMR-r5 N16 window for local re-admission — a stale
canonical row displaced by a new admission's publish has its old reverse
aliases swept, shrinking the lingering-alias misdelivery window rather than
widening anything.

**Uniform quarantine placement (Codex r5 B3) — coherent, one
clarification nit.** The pool address loop already iterates candidate
addresses (`allocate_translation`'s round-robin loop and
`reserve_address_only_roundrobin`); the quarantine predicate slots in as a
per-address `continue`. For address-persistent (sticky) pools the loop is
single-attempt by contract, so a quarantined sticky address yields
`AllocatorExhausted` (fail closed) rather than rotation — the correct
preservation of the sticky contract, and v6 §5.7's "skip" language covers
it implicitly. NIT: state the sticky-exhaust consequence explicitly in
§5.7 so an implementer doesn't "fix" it into rotation.

**MaterializeConflict (Codex r5 M4) — sufficient at plan level.** A
distinct outcome propagated to an explicit recycle/drop branch; the
cold-miss path (poll_descriptor/mod.rs:432/903) is never re-entered; the
unconditional shared decision (session_glue/mod.rs:1128/1146) is never
returned on conflict.

## Attack pass — what v6 might have introduced

- The alias sweep runs inside `publish_shared_session`'s displacement
  handling, which is called from MANY paths (local publish, import,
  prewarm, tunnel, tests). Sweep cost is one index removal per displaced
  alias — only on displacement (rare: refresh/re-publish). Cold path. OK.
- The sweep removes the displaced entry's aliases even when the
  displacement is a same-tuple refresh (T_old == T_new): the aliases are
  identical to the ones just inserted — order matters (sweep BEFORE
  inserting the new aliases, or the sweep must skip aliases equal to the
  new entry's). v6 §5.6's coordinator order is "canonical insert → alias
  sweep → −{Shared}" — for same-tuple refresh the sweep would remove the
  aliases the entry still needs! The implementation must either sweep
  only aliases that differ from the new entry's, or sweep-then-reinsert.
  NIT: v6 states the order but not the same-tuple guard — fold one
  sentence (sweep is computed from the displaced entry and filtered
  against the new entry's aliases; same-tuple refresh sweeps nothing).
- Tuple-versioned caps: `max_tracked_flows` counting records means the
  two-record transient consumes 2 slots — an attacker forcing repeated
  tuple changes could inflate record counts? Tuple changes require
  close+re-admit (session lifecycle), so churn is bounded by session
  churn, which the session-rate limits already bound. OK.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives; the v6 mechanisms
verify under independent re-derivation. Nits (fold into v7 wording, no
re-review needed if Codex r6 converges): (1) same-tuple-refresh guard for
the alias sweep (filter against the new entry's aliases / sweep-then-
reinsert); (2) sticky-pool quarantine yields exhaustion, not rotation —
state explicitly in §5.7; (3) AGY r5/r6's two carried nits (optional
reason label; `translated_tuple_of` accessor) remain implementation-time
items already named in §5.8/§6.
