# Claude SMR hostile plan review — #6751 plan v5 (round 5, convergence adjudication)

Reviewer: Claude SMR. Posture: hostile — v5 is my own fold of four rounds;
per `feedback_triple_review_includes_claude_smr` a first-pass soft-pass is a
yellow flag, so this pass tries to falsify the lifecycle-complete claim one
more time before agreeing convergence.

## Method

Re-walked the four lifecycle families v5 claims closed (publication,
tuple-changing re-sync, drain transition, teardown), then attacked three
things nobody has put on the table yet: (1) the reverse-companion lag vs
identity free; (2) the preserve-mint's immediate reclaim of a just-freed
identity; (3) the coordinator/worker staged-replacement implementability
against the current `upsert_synced_with_origin` bool return.

## Verified folds (independently re-derived, not trusted)

- **Tri-state reserve** kills the r4-B1 counterexample: the draining pool
  answers `IdentityConflict` for T and the scan aborts — no fall-through to
  the interface registry. The nat64 bypass is coherent (post-#5144 a NAT64
  pool is never a source pool; defense-in-depth).
- **Publish-acquires-{Shared}** closes the early-free: AGY r5's lifecycle
  walkthrough matches the code (mint {Worker} → publish +{Shared} at
  poll_descriptor/mod.rs:2591 → reap −{Worker} at loop_body/mod.rs:1625 →
  Close-delta relay −{Shared} at session_delta.rs:436). No free-while-
  reachable window on the local path.
- **Worker-teardown matrix**: verified the stop_inner callers (link-cycle
  coordinator/mod.rs:459-460, exit :471-473, reconcile teardown.rs:80,
  rollback bringup.rs:213) and that full reconcile snapshots canonical
  entries (teardown.rs:56) and replays them (coordinator/mod.rs:810).
  `release_all_worker_markers` + the {Shared} iterate-release on
  clear_synced_state covers every combination.
- **Drain**: marker-before-RuntimeView (snapshot_refresh.rs:458/472) plus
  the atomic lift closes the v4 window rather than documenting it; the
  drain-vec participation in both release and reserve scans closes the
  mid-drain pool-edit trap (AGY r4 major 2); the authoritative addr_index
  fix is required and correct (allocator.rs:1770/1874 currently write 0).

## Self-found residual (NIT-level, documentation — does NOT block)

### N16 — Reverse-companion lag vs identity free (inherited window, now documented)

Forward and reverse companions of one flow can live in DIFFERENT workers'
tables (internal tuple and external tuple hash differently; the shared maps
exist for exactly this). The identity frees when the holder set empties
(forward reap −{Worker} + canonical removal −{Shared}), while a reverse
companion entry in another worker's table is holder-neutral and may linger
until its own reap (closing window: 2s RST / 30s FIN per #4109 companion
propagation) or until the delete-replication relay
(`replicate_session_delete`, session_glue/mod.rs:587-590 region; the
session_delta.rs:436-446 removal covers both keys) reaches it. A NEW flow
re-minting the same preserved identity inside that window — H1's OS reusing
the same source port, or a deliberate H2 — can have a reply land on the
lingering reverse entry (primary key == the recycled tuple) and be un-NAT'd
to the OLD internal host. Two mitigations make this a bounded, inherited
window rather than a new exposure: (i) the delete-replication relay removes
sibling reverse entries at ms-scale; (ii) the same window exists TODAY for
pool mode (pool port freed at forward reap while the reverse companion
lingers; the #3011 recycle FIFO is only a reuse-delay, also churnable).
v6 must document it explicitly so the invariant statement is not
over-claimed: "held continuously until not reachable" has a relay-bounded
lag on the reverse-companion edge, identical in shape to the shipped pool
discipline. Not a blocker: the change does not widen it, and closing it
belongs to the session-teardown domain (affects pool mode identically),
not to this NAT-admission fix.

## AGY r5 nits adjudication

- **N1 (Prometheus reason label on registry_cap_exhaustion)**: legitimate
  refinement, optional. The two-cap aggregation is intentional (both are
  "cannot create more registry state"); a `reason` label
  (`flow_cap` vs `allocator_cap`) is an implementation-time nicety that
  does not change the plan. Accept as v6 note.
- **N2 (staged pre-read helper signature)**: the wrapper can pre-read via
  `entry_by_key` before calling `upsert_synced_with_origin` (no signature
  change required), or the implementer may return `Option<NatDecision>`
  (the previous decision) from the install — v6 names both, implementer
  picks. Accept as v6 note.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR finding survives. The four
lifecycle families are closed with code-cited mechanisms; the one residual I
could construct (N16) is an inherited, relay-bounded window identical in
shape to shipped pool-mode discipline — documentation, not redesign. Nits
folded into v6: N16 documentation paragraph (§5.6), the reason-label
refinement note (§5.8), the staged pre-read helper note (§5.6/§6).
