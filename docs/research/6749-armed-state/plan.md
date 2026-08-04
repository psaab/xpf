# #6749 — binding-plan expansion registers new slots unarmed, dataplane disabled indefinitely

**Status: DRAFT v8.13 — pending adversarial plan review (round 18)**

- Issue: #6749 (opus-review-001 root R06, severity High)
- Research base: `ad9591177` (origin/master at worktree creation)
- Research branch: `research/6749-armed-state` (plan docs only — no
  production code in this branch)
- v1 @ `8c76670d6` (r1: all DEMAND-REVISION); v3 @ `bce10126c` (r2:
  all DEMAND-REVISION); v4 @ `f679a791a` (r3: all DEMAND-REVISION);
  v5 @ `0c0b9b677` (r4: Codex DEMAND-REVISION; AGY + SMR
  PLAN-READY-WITH-NITS); v6 @ `6969b6167` (r5: Codex DEMAND-REVISION;
  AGY + SMR PLAN-READY-WITH-NITS); v7 @ `3e388fde8` (r6: all
  DEMAND-REVISION); v7.1 @ `d61e76ec3` (AGY r6 + SMR r6 folds); v8 @
  `ee2f548d8` (r7: Codex DEMAND-REVISION; AGY + SMR
  PLAN-READY-WITH-NITS); v8.1 (AGY r7 f1/f3 + SMR r7 N1-N3 folds);
  v8.2 (Codex r7 folds) @ `f84e0827a` (r8: Codex DEMAND-REVISION;
  AGY PLAN-READY; SMR PLAN-READY-WITH-NITS); v8.2.1 @ `c15a99796`
  (AGY r7 leftovers + SMR r8 nits); v8.3 folds Codex r8 (two-phase
  precheck, epoch-open MAC debt with applySem, Go fabric
  pre-disable, acceptance-time rollover, reset clock,
  identity-keyed error attribution, r8 test matrix) @ `e7b835f73`
  (r9: all DEMAND-REVISION); v8.4 folds AGY r9 + SMR r9
  (three-bucket precheck, in-flow settlement, settlement-driven
  dispatch, pre-disable-no-liveness-reset, operator-arm clock
  reset, CLI scope, doc notes) @ `bfdf6daf8`; v8.5 folds Codex r9:
  VERIFIED pre-disable (readback-proved ctrl=0 before the RPC is
  sent, else don't send), helper-authoritative fabric cache
  adoption on every status application (the lost-response cache
  divergence class dies), the tagged retry's stored-generation
  guard (a stale epoch's retry never consumes a landed-but-
  unacknowledged successor's latch), nil-config teardown
  cancellation, HA role-based sync authority (applied → advance +
  supersede; identical shortcut → no advance), reset-clock
  exponent preservation (events never touch the exponent; only
  immutable membership transitions pull the deadline earlier),
  §7.3 planned-identity alignment + identity-keyed error
  attribution + the dropped-identity pin, and the r9 test matrix
  (reconcile-entry hook, lost-ACK shapes, advance-point matrix
  with UNKNOWN/nil-config/reverse-vs-identical, pre-disable fault
  injection, guard-hit/UNKNOWN release budgets, event storm,
  bucket edges, stale-attempt race, real validation handoff) @
  `fe899556f` (r10: Codex DEMAND-REVISION; AGY
  PLAN-READY-WITH-NITS; SMR PLAN-READY-WITH-NITS); v8.6 folds
  Codex r10 + AGY r10: the MAC completion validation set is
  bucket-i ONLY (bucket-ii members recover independently and never
  gate — the mixed-bucket outage is dead; configured-disabled
  members are excluded from validation AND recovery — the debt
  never fights `disable: true`; missing members excluded until
  the next precheck), settle-time link-state REREAD (the
  precheck→validation flap), `m.configEpoch` (a config-only epoch
  counter — FIB overlays never move it — replacing the
  contaminated scalar generation for debt scoping), the tagged
  completion rebind carries `expected_snapshot_generation` (the
  helper refuses stale completions — the v8.5 stored-generation
  guard and its overlay false-positives are gone), EVERY
  authorized defer exit clears ALL THREE latch authorities
  (manager flag, helper stored latch, and the Go cache
  `m.lastSnapshot.DeferWorkers` — no ownerless re-latch),
  PAIR-GATED fabric adoption (adopt only when the status's
  (generation, fib) pair matches the committed snapshot — no
  B-config/A-fabric hybrid in either direction), the edge-triggered
  VERIFIED pre-disable (once per new projection value; readback
  proof of 0; block the send on an unobtainable readback and
  surface the error), the LinkController handoff (one new
  operation for the bucket/validation handoff), the honest ≈19s
  accepted-change budget (and the repeated-guard-hit pulses
  eliminated), plus the full test re-specification (reconcile-entry
  counter, lost-ACK expected-generation refusal, three-authority
  clear, pair-gated quadrants, nil-config, HA pairs, fault
  injection, release budgets, event storm, bucket edges, the
  capacity-one-safe stale-attempt race, and the stale v8.3 restart
  test corrected to bucket semantics) @ `dc0e618f8` (r11: Codex
  DEMAND-REVISION (9 BLOCKER + 3 MAJOR); AGY PLAN-READY (clean);
  SMR PLAN-READY-WITH-NITS (1 MINOR + 2 NIT)); v8.7 folds Codex
  r11 + SMR r11: the fabric-adoption gate is re-keyed from the
  (generation, fib) pair to CONFIG LINEAGE on
  `appliedSnapshot.Generation` (the documented helper-acknowledged
  full-snapshot authority, applied_nat_view.go:5-21 — the pair
  gate wedged on every successful FIB bump / neighbor regen /
  fabric persist because those paths advance Go's scalar but not
  the helper's `last_snapshot_generation`), PLUS the request-side
  fence (`update_fabrics` carries `expected_snapshot_generation`
  from the NEW compile-stamped `ConfigGeneration` field — overlay
  paths never touch it — with helper-side refusal, plus Go-side
  divergence send suppression); the completion tag carries the
  same FIB-clean `ConfigGeneration` (the v8.6
  `m.publishedSnapshot.Generation` token false-refused legitimate
  same-epoch completions after ANY partial operation — and
  `m.publishedSnapshot` is a uint64, not an object), with the
  refusal ordered FIRST in the rebind handler (before
  rebind.rs:42-50's field clearing); UNKNOWN-outcome ownership
  (the timeout-but-landed deferred successor is owned by the
  status-poll re-sync — helper-ahead → #4036 exact-equal → adopt
  → configEpoch advances → B-keyed debt instantiated — not "the
  next apply"), and the FULL six-exit enumeration with per-exit
  clean AND UNKNOWN all-three-authority clears (incl. nil-config
  `stopLocked` clearing `m.deferWorkers` +
  `m.lastSnapshot.DeferWorkers` — process.go:197-267 retains them
  today — and the NEW `stored_defer_workers` status echo);
  `m.configEpoch`'s advance contract sharpened to
  observed-accepted publish of a COMPILED config ONLY (never at
  staging, never on the #5134 direct retry — which would cancel
  same-config link-recovery entries — never on overlays); the
  debt becomes TWO TYPED COLLECTIONS (`macEpochDebt` gating,
  `linkRecoveryDebt` never gating — `hasActiveMACDebt` counts
  only the former) with the settle reread at EVERY validation
  attempt (a permanently-down bucket-i member downgrades at the
  first retry ≤5s — the v8.6 Q7 keep-epoch-open claim DELETED);
  the LinkController handoff fully specified
  (`AttemptMACDebt(ctx, epoch, members)` — daemon-side execution
  under applySem, per-member epoch revalidation, idempotent, no
  rollback); the value edge-trigger is replaced by ENV-GATED
  resend suppression (helper `guard_env_generation` + Go
  (projection, envGen) cache) with EVERY non-suppressed send
  pre-disabled (the reject→accept bypass and the A→B→A pulse
  both die) and the pre-disable error propagated end-to-end
  (SyncFabricState gains an error return through
  controllers.go:47/:128-143 to daemon_ha_fabric.go:752-759);
  the honest budgets (≈19s healthy baseline; ≈60s-floor + ≈70s
  warm-clock worst case); and the full test re-specification
  (request-side fence refusal, authority-split proofs,
  false-refusal negative, ownerless-B re-sync, UNKNOWN-exit
  matrix, mixed cohort predicate, every-attempt reread,
  env-gated suppression, reject→accept proof, error-propagation
  chain, warm-clock budget; trailing-coalesce test DELETED —
  its mechanism was removed in v8.2; the common S4' caller list
  corrected — update_fabrics is not a reconcile caller; "every
  member up" rule corrected to still-in-macEpochDebt) @ pending
; v8.8 folds Codex r12 (11 BLOCKER + 3 MAJOR) + AGY r12 (3
  BLOCKER + 3 MAJOR) + SMR r12 (1 BLOCKER + 1 MAJOR + 2 MINOR +
  1 NIT): the lineage authority becomes `config_epoch` ON THE
  WIRE (an additive `ConfigSnapshot.config_epoch` stamped on
  every full apply — compiles carry the NEW
  `m.pendingConfigEpoch`, clone-republishes and overlays carry
  `m.acceptedConfigEpoch` — stored by the helper and echoed in
  status) because EVERY predecessor token failed: the
  (generation, fib) pair wedged on ordinary fib bumps, the
  `appliedSnapshot.Generation` gate misdetected every clean
  deferred B (markAppliedSnapshotLocked deliberately skips
  capture while deferred, applied_nat_view.go:64-98) AND
  recorded the mutated Go scalar post-rebind
  (process_linkcycle.go:219-233), the staged-ahead
  scalar/pointer disjuncts false-blocked fib-bump and
  content-dedup states (manager_generation.go:71 vs
  manager_neighbor.go:138; builder.go:156-178 vs
  process_status.go:72-80), and the Go-internal
  `ConfigGeneration` fence/tag false-refused after every
  full-apply producer (route overlays manager_overlay.go:188-250,
  scheduler republishes manager_compile.go:575-621, #5134
  clone-republishes manager_worker_arm_5134.go:57-92 — the
  helper stores each generation, snapshot.rs:150-155). The
  adoption gate, the latch echo, the request fence, and the
  completion tag all key on the wire epoch (fib-clean AND
  overlay-clean); the content-dedup skip collapses
  accepted=pending (truthful by the builder hash); the
  UNKNOWN-outcome re-sync owner is the ACTIVE-CONFIG RE-APPLY
  (Go discards the staged snap on publish timeout and
  bumpGeneration burns the number — an exact-equal republish
  of B is impossible, but the control-plane commit already
  landed, so the re-apply is fresh-generation/identical-content/
  fresh-precheck); the defer intent is a Compile ARGUMENT set
  under m.mu (the poll-vs-Compile race dies); exit (d) gains
  OPERATOR provenance (automatic disarms are epoch-preserving)
  and transition (g) models helper restart; the MAC debt
  becomes THREE TYPED OBLIGATIONS (`macEpochDebt` gating;
  `macAndLinkRecovery` + `linkOnlyRecovery` never gating —
  a down bucket-i member transfers with its FULL obligation
  preserved: program-MAC + setUp + post-cycle repairs + XSK
  rebind on link return, since NO production link-UP→rebind
  machinery exists) with the pass-1 reread covering ALL
  desired members (bucket-iii flaps get linkOnlyRecovery
  entries); debt execution is daemon-side with a ONE-WAY
  applySem > m.mu hierarchy, bounded BLOCKING acquire (the
  TRY-acquire starvation against the 30s proxy-ARP reconcile
  dies), and two daemon→manager methods
  (`ValidateMACDebtEpoch`, `ReportMACDebtAttempt` with sticky
  `linkCycled`); the guard env token becomes CAUSAL (one
  sample per verdict, UNION watch over accepted + last-rejected
  candidates, incarnation-scoped Go cache, poll-dispatched
  retry — the 30s ticker wait dies); and the fabric sync error
  becomes a TYPED outcome (map commit stands, sync debt owns
  the retry, readiness reads (map, debt) — all four call
  sites) @ pending
; v8.9 folds Codex r13 (12 BLOCKER + 3 MAJOR) + AGY r13 (4
  BLOCKER + 2 MAJOR) + SMR r13 (1 BLOCKER + 3 MINOR/NIT):
  `config_epoch` becomes the configstore's GLOBALLY-MONOTONIC
  COMMIT SEQUENCE (`archiveSeq`, store.go:233-245/
  store_commit.go:304) of the committed config each snapshot
  CONTAINS — no allocator, never reused, identical across
  same-config Compile invocations (the v8.8 mint/carry
  contract dies: it could not represent ambiguous post-write
  failures, published staged B under A's lineage, and could
  not transfer dedup lineage); the FIVE full-publish producers
  (normal Compile, pending-XSK deferred publish, route
  overlay, scheduler republish, #5134) each carry their
  CONTAINED config's seq, and the helper REFUSES a
  strictly-older-seq `apply_snapshot` (epoch-rollback refusal,
  #3767 H5's shape) so a stale A-clone can never overwrite
  timeout-landed B and erase the re-sync signal; the
  content-dedup case transfers lineage via the NEW
  `note_config_epoch` verb (the v8.8 local-collapse wedge is
  dead); ALL lineage-sensitive operations FAIL CLOSED on an
  old helper's epoch 0 (mixed-version); divergence
  suppression covers ALL older-lineage producers (not just
  SyncFabricState); the UNKNOWN-outcome owner is a
  DAEMON-DRIVEN single-flight RE-SYNC DEBT (enqueue-after-unlock
  — the poll records under m.mu, the daemon drains, acquires
  applySem, re-reads the ACTIVE config, drives the normal
  commit path); the defer intent is a
  `StartDeferredCompile()` reservation (intent+compileInFlight
  in ONE m.mu section at the precheck point — the v8.8
  argument-only text had no API path and reopened the
  mid-compile arm-sync window); `set_forwarding_state` gains
  a `provenance` wire field (automatic disarms
  epoch-preserving; durable operator-verb retry debt); the
  MAC debt recovery becomes a SAFE XSK TRANSACTION
  (Prepare/Notify quiesce-all+rebind-all, budgeted as a rare
  operator-visible event; `linkCycled` recorded at
  DOWN-success; proxy-ARP/NDP in the repair list; debt clears
  on OBSERVED bound+ready, not a void return); the debt
  interface becomes work-PULL (`ClaimMACDebtWork` with a
  monotonic `claimToken` linearization fence +
  `ReportMACDebtAttempt` discarding stale-token results;
  `ApplyResult` gains the epoch; #5134 `pendingWorkerArm`
  epoch-qualified + cleared on supersession); the lock rule
  restates as "no SYNCHRONOUS manager→daemon call while
  holding m.mu" (async enqueue is the OnXSKBound shape) with
  a FIFO+bounded-hold fairness proof (30s acquire bound,
  try-lock-or-skip manager calls); the env token becomes
  loss-safe (≤4 ack-set of rejected-projection identities +
  debounced dispatch, ≤1/5s per identity — the 1 Hz ctrl
  oscillation dies); and the fabric sync debt becomes an
  executable state machine keyed `(config_epoch,
  projection-hash)` (clean-matching-sync clear; readiness
  ANDs fabricPopulated with no-outstanding-debt) @ pending

; v8.10 folds Codex r14 (12 BLOCKER + 3 MAJOR) + AGY r14 (4
  BLOCKER + 2 MAJOR + 1 MINOR) + SMR r14 (2 BLOCKER + 4
  MINOR/NIT): the lineage foundation is REBUILT as TWO
  revisions because v8.9's `archiveSeq` was never a commit
  sequence (a per-process archive-filename/retention counter
  that CommitConfirmed/SyncApply/PromoteRollback don't bump,
  that manual ArchiveConfig bumps without a commit, that
  crash-reseeds can reuse, and that no config object
  carries): **(R1) `commit_revision`** — a REAL durable
  promotion revision assigned by the configstore AT PROMOTION
  TIME on EVERY accepted-config path (plain Commit,
  CommitConfirmed confirm, SyncApply, PromoteRollback, the
  boot-recovery promote), persisted atomically with the
  active config, read via the new `ActiveConfigRevision()`
  API — it carries CONFIG IDENTITY (debts, completions,
  fences, gates); **(R2) `publication_rev`** — a
  manager-minted monotonic per-send revision (burned on every
  send, seeded at startup from the helper's echo) — it
  carries SEND ORDER (the helper refuses a not-strictly-
  greater apply_snapshot; same-commit feed reshapes get
  distinct revs; Go's helper-ahead detection compares it).
  The dedup lineage transfer becomes a COMPARE-AND-SET verb
  (`note_commit_revision {new_rev, expected_rev}` —
  strict-older refusal, equality-idempotent, CAS refusal
  abandoned as superseded, FAILED/UNKNOWN retried via a
  supersedable note debt cleared only on an exact echo);
  the latch echo becomes ASYMMETRIC clear-only (a lingering
  helper latch can never re-latch a non-deferred compile);
  the re-sync debt FIRES on observed divergence (never gated
  on its own key — v8.9's rule prohibited it) with
  latest-wins drain-time re-reads and explicit transitions
  (nil ActiveConfig, channel saturation, acquire timeout,
  re-apply failure); EVERY Compile begins with
  `StartCompile(deferIntent bool)` (one m.mu section setting
  deferWorkers + compileInFlight; non-deferred compiles
  explicitly reset a stale flag) with every exit + the apply
  flow's aborts routing through ClearCompileReservation;
  auxiliary full-publish producers are ALL suppressed while
  any config is staged (the #5134 DeferWorkers=false clone
  can never arm staged B); the claimToken is re-validated
  before EVERY netlink mutation (operator verbs take m.mu
  but not applySem — the fence lives in the work loop);
  `Deadline`'s consumer is the scheduler's wake computation;
  `PrepareLinkCycle` gains an `error` return (quiescence
  failure ABORTS the recovery — no DOWN/UP on live UMEM)
  with multi-member BATCHING and phase-only retries and a
  registered-only observed-clear predicate; the fairness
  bound is honest (150s — the worst legal owner hold is a
  120s control round trip inside the whole-pipeline apply
  hold); Go's env suppression DROPS entries absent from the
  echoed reject-set (eviction ownership) with an AGGREGATE
  ≤4/5s dispatch cap; the fabric sync debt keys on the FULL
  sent FabricSnapshot payload (telemetry can no longer
  alias), records clean guard rejections as
  readiness-relevant debts, and reaches takeover readiness
  via the NEW `FabricSyncDebtOutstanding` query (the
  interface change accepted); a bootstrap epoch rebase
  covers the unclean-reset class (first apply with
  `acceptedCommitRevision == 0` carries
  `allow_epoch_rebase: true`) @ pending
; v8.11 folds Codex r15 (12 BLOCKER + 2 MAJOR + 1 MINOR) +
; v8.12 folds Codex r16 (14 BLOCKER + 2 MAJOR + 1 MINOR) +
  AGY r16 (4 BLOCKER + 3 MAJOR + 1 MINOR + 1 NIT) + SMR
  r16 (1 MAJOR + 5 MINOR/NIT): Option-B becomes an EXPOSURE
  GATE — a promotion whose pair write has not durably
  landed is NOT EXPOSED to the dataplane (accepted
  control-plane, recorded pending-durable with the store's
  retry; the dataplane keeps the LAST DURABLE config until
  `writeTreeMarked` (db.go:431-461) lands it) — the (B,A)
  aliasing dies at the root and no allocation journal is
  needed; the revision high-water is a DEDICATED counter
  (seeded from `max(active.json revision, 0)`, bumped only
  inside the five promotion paths, never from archive
  filenames); the migration allocator is
  `max(active revision, durable high-water) + 1` seeded
  BEFORE Load's expired-confirm recovery; the envelope's
  supported-reader capability rises to 2 (old writers
  refuse rather than erase); the migration write failure
  retries with the dataplane in the legacy-zero gate; the
  `(config, revision)` pair travels as an EXPLICIT
  ARGUMENT (`ConfigSink.ApplyConfig(ctx, cfg,
  commitRevision)` — never an optional assertion) sourced
  from ONE `ActivePair()` store getter (one s.mu-atomic
  read), with feed/DHCP queued reapplies REPLACING the
  captured config entirely under applySem, and the direct
  CLI path passing revision 0 explicitly; the synchronous
  ping moves to the TOP of every Compile (BEFORE the
  snapshot build stamps Generation/FIB — the surviving
  helper's first snapshot no longer arrives pre-stamped
  with reset legacy values), with not-seeded-yet errors
  routing to the standard publish-retry machinery and the
  LEGACY (generation, fib) high-waters seeded from the
  same echo; the downward rebase is DELETED (socket
  ownership is not a proof — connection-per-request,
  unlimited sequence, no session/nonce/lease — and a
  downward rebase opens a rollback window) in favor of a
  HELPER RESPAWN on downward startup divergence; the
  common send primitive gains a `snapshot_token` freshness
  check (monotonic, minted at BUILD time inside m.mu) AND
  a build-current validation at send time (T1's stale
  same-commit snapshot is abandoned Go-side; the helper
  refuses strictly-older tokens — the same-commit stale
  content window closes); `ControlResponse` gains an
  additive `error_code: string` (the note CAS refusal and
  the machinery's typed errors classify; existing errors
  keep "" and their handling); the note CAS's refusal with
  current<expected is OWNED BY THE RE-SYNC (not abandoned);
  the note echo advances accepted BEFORE divergence
  classification in ONE common lineage-observation routine;
  the compile reservation becomes a PREDECESSOR-CHAINED
  token (Finish applies only at the head; a restore
  applies the head's OWN prior — the ABA resurrection
  dies) with the PENDING-XSK STAGED and PRE-SEND outcomes
  added, a stale-token send dying on the freshness token,
  and the direct CLI path getting an explicit default
  reservation; validation and quiescence merge into
  `PrepareLinkCycleChecked(claimToken)` (the token
  validated under the SAME m.mu acquisition that begins
  the quiescence) with a TRI-STATE verdict (Valid /
  RetryLater (contended — release, keep the batch, retry,
  NO unwind) / Stale (abandon WITH the balanced unwind));
  the restore becomes TYPED (`NotifyLinkCycle` gains a
  typed result; a failed restore records a RESTORE DEBT
  with per-failure-mode policies (missing process →
  respawn; ctrl error → retry; rebind error → #5134;
  status error → poll reconciles); the abandoned batch's
  finalizer runs it UNCONDITIONALLY after every
  possibly-landed quiesce before releasing applySem); the
  recovery flow becomes REPAIR-BEFORE-REBIND with a
  renewed settle (Prepare → validate-and-program ALL due
  members including arrivals absorbed at the re-Claim →
  settle → rebind — no second cycle, no wrong-MAC rebind;
  the selective-rebind-hold alternative rejected;
  `programRethMAC` is never a "revalidation" inside a
  rebind; any MAC work after the settle requires a renewed
  settle); the fairness contract becomes a NO-TIMEOUT
  FIFO queue (position preserved; eventual progress by
  FIFO + proven-terminating owners) with a 60s
  queued-state Warn that stops/resets on acquisition, and
  the acquire-BEFORE-Claim ordering normative (no logical
  claim while queued); the fabric readiness answer becomes
  a CAUSAL protocol (`map_generation` minted atomically
  with each BPF mutation, echoed by the helper as
  `accepted_fabric_map_generation`; `FabricSyncStateOK()`
  is true only when the accepted generation matches the
  current AND no debt is outstanding AND a coherence proof
  exists since startup (fresh-boot-no-proof answers FALSE,
  as does old-helper zero); the fabric-send order spans
  full snapshots and `update_fabrics` via the generation;
  the projection identity corrects to (name, parent Linux
  name, parent ifindex, effective queue count)
  (planning.rs:160-171 — FabricSnapshot has no VLAN
  field)); the re-sync's drain provably invokes the
  revised `applyConfigLocked` (the test asserts the
  three-bucket precheck runs and B's MAC debt is
  recreated, forbidding a bare `d.dp.ApplyConfig`); and
  the test corpus gains the chain tests (migration
  failure/retry + allocator ordering + capability-2
  envelope refusal, Option-B exposure gate, paired
  transport on every apply path, ping-first Compile
  ordering, respawn-on-divergence, freshness-token stale
  send, typed error_code classification, token ABA +
  outcomes + CLI default, PrepareLinkCycleChecked
  tri-state + stop_workers timeout-but-landed, typed
  restore + restore debt, repair-before-rebind +
  post-settle program rule, no-timeout queue + Warn
  lifecycle, causal map-generation readiness) @ pending
; v8.13 folds Codex r17 (13 BLOCKER + 1 MAJOR + 1 MINOR) +
  AGY r17 (4 BLOCKER + 3 MAJOR + 1 MINOR + 1 NIT) + SMR
  r17 (3 BLOCKER + 3 MAJOR + 5 MINOR): the exposure gate
  gains its missing other half — the ACCEPTED/EXPOSED
  pair split and the DURABILITY-EXPOSURE DEBT (Codex f2 =
  AGY f1 = SMR17-1): the store's promotion return (or a
  `PersistDegraded()` getter consulted by the daemon's
  apply flow) marks a promotion whose pair write failed;
  the dataplane apply is SKIPPED (the gate's locus, named
  for the first time: the daemon's applyConfigLocked
  consults the indicator BEFORE compiling); the commit
  reports success WITH a "dataplane exposure
  pending-durable" warning (posture sentence + edge Warn
  + show visibility); and the store's persist-retry
  success leg WAKES the debt (a daemon-polled getter on
  the apply scheduler's cadence — no new store→daemon
  call direction), whose drain acquires applySem,
  re-reads `ActivePair()` (latest-wins), and drives the
  REVISED applyConfigLocked (full three-bucket precheck +
  MAC-debt creation) — the re-exposure apply; HA applied
  markers (the `syncAndApply` digest stamp,
  daemon_apply_commit.go:426/:464) key to the EXPOSED
  pair — a gated apply stamps NOTHING, so the peer's
  equal-text suppression (daemon_ha_sync.go:474/:549)
  can never strand B; the legacy-migration retry rides
  the same debt (revision 1's exposure). The freshness
  token becomes a BUILD SEQUENCE (Codex f5 = AGY f2 =
  SMR17-2): a cheap input-capture section under m.mu
  snapshots the build's inputs (the config pair AND the
  feed/overlay state refs) and mints `buildSeq` (==
  `snapshot_token`, one counter); the send primitive
  gains explicit LOCKED and UNLOCKED entries (auxiliary
  publishers already under m.mu use the former;
  Compile's publish leg the latter — the self-deadlock
  dies) and validates at send: `buildSeq ==
  m.latestBuildSeq` AND the pair still current — a stale
  same-commit reshape dies Go-side regardless of lock
  ordering (the pair-only check could not see it); the
  helper refuses strictly-older tokens per incarnation
  (backstop); the semantic hash EXCLUDES
  `snapshot_token` (builder.go:156-178's zero set grows —
  dedup and note-CAS survive). The paired transport is
  swept (Codex f3 = AGY f4 = SMR17-3): the re-sync text's
  stale `SetActiveRevision` reference becomes
  `ActivePair()`; `m.pendingCommitRevision` and
  `ApplyResult` source from the same `ActivePair()` read;
  `applyConfigLocked(ctx, cfg, commitRevision)` is the
  defined signature; the boot path reads the pair UNDER
  the wrapper's applySem hold (moved inside
  daemon_apply.go:49); and the mandatory live-MAC second
  leg REUSES THE OUTER TRANSACTION'S ORIGINAL PAIR
  (captured at the flow entry under the same applySem
  hold — coherent by construction) — an interposed
  promotion (operator commit OR the persistence
  transition, which needs only s.mu) is NEVER re-read
  mid-flow; B's durability notification queues behind the
  outer transaction as a separate full B apply (the
  exposure debt). The zero-event boot retry gains an
  owner (Codex f4): the not-seeded abort records a
  daemon-side BOOT-APPLY DEBT (single-flight, short
  cadence, owned by the daemon's apply scheduler — the
  status republisher cannot own a pre-build abort: no
  staged snapshot, no loop yet); the seeded state is
  incarnation-scoped; the ping's deadline class pinned
  (3s `controlBaseDeadline` (process_control.go:34-41) —
  SMR17-10's correction of AGY f6). `error_code` gains
  its complete census (Codex f6): §6 carries
  `ControlResponse.error_code` + the canary; the
  producers are pinned per code (stale_completion:
  rebind; diverged_fabric: update_fabrics; epoch_rollback
  + publication_rollback: apply_snapshot;
  note_cas_refusal: the note handler (a named dispatcher
  entry); `stale_snapshot_token`: the token refusal;
  `not_seeded` is MANAGER-LOCAL — synthesized Go-side
  before the send, never on the wire); the consumer
  contract: a typed response (error_code != "") survives
  the OK=false discard, invokes the common lineage
  observer, and selects the reservation/debt outcome —
  UNTYPED failures keep today's handling (status NOT
  copied; Rust attaches status to ordinary failures too
  (handlers/mod.rs:260-267)). The predecessor chain
  records outcomes (Codex f7): a non-head Finish records
  its outcome on its node; the head's Finish applies its
  own outcome AND replays completed predecessors'
  recorded outcomes in order (T1's ACCEPTED lands even
  though it finished while T2 was head — the ABA dies for
  real); §6's `StartCompile` returns the token; the
  manager state lists the chain (head + node registry +
  ID counter); panic outcomes classify by phase
  (pre-wire PRE-SEND / possibly-landed UNKNOWN /
  post-acceptance tail) via the Compile-internal defer;
  PENDING-XSK STAGED stores its token for the deferred
  leg, a newer StartCompile FINALIZES an orphaned open
  predecessor as OVERLAP (SMR17-5 = AGY f5), and helper
  death before the leg finalizes it UNKNOWN. The checked
  quiescence's API and hold span are pinned (Codex f8 =
  SMR17-9): §6 replaces the split
  ValidateClaimToken+PrepareLinkCycle with the merged
  `PrepareLinkCycleChecked(claimToken)`; the method
  try-acquires m.mu, validates, issues ctrl-disable +
  stop_workers under the hold (3s base deadline each),
  and RELEASES before the MAC phase (the per-mutation
  try-lock re-reads resume after release — no
  self-deadlock); RetryLater exists only BEFORE any
  ctrl/worker mutation (a post-quiescence try-lock skip
  routes through the restore finalizer). The restore debt
  becomes executable (Codex f9): a rebind error records
  the RESTORE DEBT itself (NOT the #5134 debt — that
  self-clears on non-deferred snapshots,
  manager_worker_arm_5134.go:50-54); missing-process →
  respawn FOLLOWED BY a daemon-owned revised full apply
  (paired replay from `ActivePair()` — rebinding an
  empty helper is prohibited); ctrl error → restore-debt
  retry (5/10/30/60s + edge Warn, no terminal cap, the
  pending-activation posture); status error → the poll
  reconciles; §6 gains the restore-debt state and
  `NotifyLinkCycle`'s typed result. The late-arrival
  event-fired attempt is DELETED (Codex f10 = AGY f7 =
  SMR17-7): no passive link-event machinery exists
  (daemon_flow.go:725-749 — SNMP traps only), so the
  late member is handled by absorption at the re-Claim
  (unchanged) or the debt's normal backoff retry; the
  batch's global rebind binding the late member with its
  factory MAC is ACCEPTED and stated honestly (a
  partial-path blackhole for flows hashed to it, bounded
  below by the retry cadence + FIFO queueing — the
  no-priority posture (AGY r16 f8) already owns this
  latency class; the ≤ ~1s claim is deleted). The FIFO
  contract is restated honestly (Codex f11): progress is
  guaranteed for all userspace-bounded owners; the
  kernel-unreapable/D-state class (`stopLocked`'s
  unconditional `<-done` after Kill(),
  process.go:231-244) is unbounded by ANY userspace
  design — the 60s Warn plus the systemd outer bound
  (TimeoutStopSec + Restart) is the documented escape,
  not a mechanism change. `map_generation` becomes a
  single transaction with a seed and a capability
  (Codex f12 = AGY f3 = SMR17-4): the manager owns the
  whole fabric sync — ONE m.mu section samples the map
  view, mints `map_generation`, and builds the helper
  payload FROM THE SAME SAMPLE (the peer-MAC-X/map vs
  Y/payload divergence dies); the four call sites
  (daemon_ha_fabric.go:738-756/:771-778/:944-957/:969-976)
  route through it; the direct key writes
  (maps_fabric.go:16-33) move inside the manager's
  wrapper; the legacy-adapter bypass
  (legacy_dataplane.go:346) is enumerated as a
  pre-upgrade/test-only path (production never calls
  it); `map_generation` SEEDS from the startup ping echo
  (accepted → minted high-water — the re-init desync
  dies, mirroring the publication_rev seed); the
  new-helper-zero vs old-helper-zero ambiguity resolves
  via a protocol CAPABILITY bit in the ping exchange
  (old helper → fail-closed REQUIRED restart; a new
  helper's genuine zero is valid pre-proof state); a
  full snapshot advances the accepted generation even
  when fabric content is equal (idempotent advance,
  ordering pinned); the fresh-boot first-proof producer
  is pinned (`startClusterComms`'s fab0/fab1 population
  goroutines, daemon_ha_sync.go:1223-1242 — Codex f12's
  answer to AGY f3); §6 + the canaries gain both fields;
  the fabric sync debt's clear rule moves from
  payload-hash to generation. The 60s Warn keys on the
  work item's FIRST-QUEUE timestamp with PERIODIC
  reporting (Codex f15 = AGY f8 = SMR17-8 — a RetryLater
  re-queue continues the episode; one-shot edge deleted).
  §9 gains the missing chain tests with the false-green
  shapes answered (Codex f13 = SMR17-6): exposure
  (retry-alone exposes, no config event; HA markers key
  to the exposed pair; migration retry rides the debt);
  paired transport (revision flow through the revised
  applyConfigLocked; boot under the hold; persistence
  landing BETWEEN the live-MAC legs — the second leg
  uses the outer pair); ping/boot (the zero-event boot
  retry FIRES; post-respawn paired replay); freshness
  (buildSeq invalidation; hash exclusion; wire presence;
  all-five-producer routing); error_code (per-producer;
  typed-only preservation; untyped unchanged); the
  reservation chain (recorded-outcome replay; panic
  phases; deferred-leg token; helper death); the checked
  quiescence (merged API; operator bump at the boundary;
  post-quiescence skip → finalizer); the restore debt
  (ordinary rebind failure owned; fresh-helper paired
  replay; ctrl retry cadence); causal fabric (concurrent
  writers; projection TOCTOU; adapter-bypass
  enumeration; old-helper capability; idempotent
  advance; first-startup proof); and the canary list
  gains snapshot_token, error_code, map_generation,
  accepted_fabric_map_generation. Edit hygiene
  (SMR17-11 + Codex f1's count note): the duplicated
  v8.11 outcomes paragraph, the note-CAS splice, the
  triple "Control verbs" header, the orphan fragment,
  and the remaining duplicated lines are fixed; the
  Codex r16 count corrects to 14 tagged blockers @
  pending
  AGY r15 (4 BLOCKER + 3 MAJOR + 1 MINOR) + SMR r15 (2
  BLOCKER + 3 MAJOR + 3 MINOR/NIT): R1 becomes a REAL
  rollout+transport contract — a legacy `active.json`
  migration at `Load` (revision 1 + a min-reader downgrade
  policy, so an upgraded node is not stuck at zero and an
  old daemon refuses rather than erases), the `(config,
  revision)` pair transported as an INPUT via
  `SetActiveRevision(rev)` under the same `applySem` hold
  (feed/DHCP queued reapplies re-read the pair under the
  semaphore — stale A can never be labelled with B's
  revision), and Option-B durability reclassified (a
  failed pair write leaves the revision UNCONFIRMED —
  `ActiveConfigRevision()` answers only confirmed values,
  riding the store's non-reusable high-water, so
  crash-before-retry can never reuse); R2 splits into TWO
  high-waters (`m.mintedPublicationRev` burned per send
  with a common one-mint-per-wire-attempt primitive;
  `m.observedPublicationRev` moving only on
  acceptance-proving responses — a same-commit lost
  completion is visible again) with the seed acquired in
  the SYNCHRONOUS startup ping (no mint/send before it,
  typed not-seeded-yet retries, the LEGACY
  (generation, fib) high-waters seeded from the same echo,
  spawn-on-unavailable); the helper's refusal becomes
  DUAL (publication not-strictly-greater OR commit_revision
  strictly-older — publication order orders sends, never
  config freshness; a legitimate rollback promote carries
  a fresh commit_revision and passes); a LEGACY-ZERO mode
  (all-zero requests accepted until the first
  epoch-carrying apply lands, then refused); the rebase
  requires the startup-ping handshake proof (socket
  ownership + acceptedCommitRevision == 0), never a bare
  Boolean; the note CAS gets its three-way order
  (stored==new_rev idempotent success → stored==expected_rev
  mutate → typed refusal carrying current state in the
  response's Status, with Go reading refusal state on
  OK=false; current>expected abandoned, current<expected
  owned by the re-sync; the note echo advances accepted
  BEFORE divergence classification; the semantic hash
  excludes BOTH lineage fields); the re-sync debt fires in
  BOTH directions (helper-ahead OR nonzero helper-behind)
  and executes through a REVISED `applyConfigLocked` (the
  daemon's own no-promotion, semaphore-held path INCLUDING
  the three-bucket precheck and MAC-debt creation — never
  a precheck-bypassing `d.dp.ApplyConfig`); the compile
  reservation is TOKENED (reservationToken captures prior
  values; `FinishCompileReservation(token, outcome)` with
  ACCEPTED / PRE-PUBLISH-FAILURE / UNKNOWN /
  POST-ACCEPTANCE-TAIL / OVERLAP outcomes — no ownerless
  double-clear); the work-pull gains
  `ValidateClaimToken(token) (ok bool)` (try-lock;
  contention/mismatch abandons the batch WITH a balanced
  unwind (restore-rebind first, workers never left
  stopped), release, re-Claim) and an explicit `nextWake`
  on every Claim (empty included); the fairness contract
  drops the timeout entirely (a no-timeout FIFO queue —
  position preserved, progress guaranteed by FIFO +
  bounded owner holds — plus a 60s queued-state Warn);
  every quiesced recovery attempt ends with a
  restore-rebind on EVERY outcome (the dataplane returns
  to RUNNING before the backoff); the batch's global
  rebind REVALIDATES every macAndLinkRecovery member's MAC
  before enabling its slots (link-return attempts fire on
  the link event with the MAC program first — the exposure
  is the ms-scale event latency, not the 5s floor); the
  fabric readiness answer becomes `FabricSyncStateOK()
  bool` (a no-argument manager-owned consistency answer —
  the map-view and sent-payload projections differ, so no
  daemon-side hash can name the payload); the env token
  (the r14 round's ONE clean closure) is unchanged; and
  the §9 identifiers are swept (no v8.9 names survive)
  with the new chain tests (migration, Option-B confirm,
  transport race, dual refusal, legacy-zero, ping-seeded
  startup, note three-way, both-direction re-sync via
  applyConfigLocked, token outcomes, ValidateClaimToken
  unwind, no-timeout queue Warn, restore-on-abandon,
  batch MAC revalidation, no-arg readiness) @ pending
---

## 1. Status

DRAFT v8.13 — pending adversarial plan review round 18 (Codex + AGY +
Claude SMR). Convergence target: PLAN-READY (recommended path shipped
to `/engineer`) or PLAN-KILL. No production code is written under
`/research`.

### Round verdict log

- **Round 1** (v1): all three DEMAND-REVISION. Deferred-activation is
  not a disarm; identity is not physical; E2; volatile-vs-control
  carry; queue-override lifetime; B dismissal overstated; unsafe-green
  tests; trigger/outage overstatement.
- **Round 2** (v3): all three DEMAND-REVISION, converging on durable
  provenance. The rebind completion path; full-leg defer completion;
  deferred CONTRACTION leaves all armed; arm-before-reconcile lie;
  full fan-out reverses operator disarms — scoped provenance REQUIRED;
  E2 flap; unsafe-green tests.
- **Round 3** (v4): all three DEMAND-REVISION. Hybrid-plan activation
  via unversioned marker; S3/S2 mark operator-owned slots (was-armed
  gates); one-bool provenance conflation (C3 scoped to registered);
  S4's scope (S4' global failure mark); toggle mid-defer (defer
  gate); arm fan-out reordered after Ok; planner never arms (AGY f1).
- **Round 4** (v5): Codex DEMAND-REVISION (6 BLOCKER + 3 MAJOR); AGY +
  SMR PLAN-READY-WITH-NITS. Name-only plan gate authorizes
  wrong-physical and incomplete retained plans; bool conflates
  global-disarm with operator ownership; S4' full-apply-only +
  retained-records retry deficit; arm-then-fail strands with no
  production retry; compile-time arm-sync bypasses the defer gate
  (verified); rebind verb-identity is not completion provenance;
  sysfs-race authorization.
- **Round 5** (v6): Codex DEMAND-REVISION (8 BLOCKER + 2 MAJOR); AGY +
  SMR PLAN-READY-WITH-NITS (both nits on the Warn-rate + a docs
  clarification, triple-converged with Codex M10). Codex's round:
  tri-state cannot distinguish disarmed-then-force-cleared from
  unregistered; failure-path replan destroys accepted-A operator
  claims AND reintroduces the live-sysfs race (permanent empty
  vector); `update_fabrics` falsifies the coherent-vector invariant;
  daemon clears `m.deferWorkers` before MAC programming (pre-MAC arm
  race moved); S4' creates unscheduled pending sinks; completion and
  #5134 provenance neither durable nor generation-safe, and
  live-change completion fires on FAILED MAC programs; #6165 refusal
  floods Warn.
- **Round 6** (v7): all three DEMAND-REVISION. AGY (1 BLOCKER + 2
  MAJOR + 1 MINOR): convergence signature/latch atomicity;
  transient-MAC stranding; fixed-5s retry thrash; clear-to-dispatch
  race. SMR: PLAN-READY-WITH-NITS (same three items as nits). Codex
  (6 BLOCKER + 2 MAJOR + 1 NIT): C2's register-vs-disarm distinction
  is unimplementable as stated (both serialize
  `(registered=true, armed=false)` — but the RESULT is the same claim
  either way; AND candidate deletion (invalid fabric parent, zero
  queue count) silently destroys operator claims, with S5 re-creation
  auto-arming them); plain restoration's volatile claim is false —
  surviving partial-B workers alias by slot onto restored-A
  identities (identity-check the volatile copy: the live record
  carries `socket_ifindex`/`socket_queue_id`,
  refresh_bindings.rs:61-62); **replan-only `update_fabrics` publishes
  a same-name/new-ifindex binding as registered+armed+none with NO
  reconcile — Go programs the new ifindex to an XSK bound to the OLD
  device while `enabled` reports true** (a new v7-introduced hazard
  in the issue's own class); the live-sysfs race is RELOCATED into
  `update_fabrics` (full-FabricSnapshot comparison replans on
  telemetry churn, and fabric refresh is also netlink-event-driven,
  faster than 30s); the v7.1 flag-clear opens a completion/quiescence
  race (`NotifyLinkCycle` deliberately sleeps 1s before rebind,
  process_linkcycle.go:184 — the arm-sync or retry can recreate
  workers mid-quiescence → the EBUSY the sleep exists to prevent);
  the pending retry is incomplete (untagged rebind can't consume the
  latch after a failed tagged completion; UNREGISTERED pendings
  (S1/S2) never re-register via a non-replanning rebind; the
  predicate checks desired not ACTUAL armed; full-set teardown churn;
  first-Compile error exits before :350/:369 still orphan the loop);
  **Go re-latches Rust after a successful completion**
  (`m.lastSnapshot.DeferWorkers` stays true and route/scheduler
  republishes clone it wholesale, manager_overlay.go:188); the #5134
  debt generation scope is wrong (FIB-only bumps would discard valid
  debt — needs a plan/config epoch); `programRethMAC` can set the MAC
  then fail `setUp` returning (true, error) and the next attempt
  no-ops on the installed MAC — the MAC debt needs phase
  revalidation; the 3s control deadline vs 10s worker readiness
  demands idempotent completion.
- **Round-6 disposition table (v7.1 folds AGY r6 + SMR r6 first,
  then v8 folds Codex r6):**

  | r6 finding | disposition |
  |---|---|
  | AGY f1 signature + latch atomicity | CLOSED v7.1 — explicit `defer_completion_authorized`; consume-on-Ok-inside, never on Err (§5-C) |
  | AGY f2 transient MAC stranding | CLOSED v8 — MAC debt WITH phase revalidation (MAC installed AND link up) + autonomous backoff (§5-C; Codex r6 f8 deepened it) |
  | AGY f3 retry thrash | CLOSED v8 — backoff with jitter + attempt cap + reset-on-change + actionable predicate (§5-C; Codex r6 f7 shaped it) |
  | AGY f4 clear→dispatch race | CLOSED v8 — the defer flag now spans sleep+dispatch (link-cycle flow); clears on tagged-rebind success (§5-C; Codex r6 f6 made it load-bearing) |
  | Codex f2 C2 + claim deletion | CLOSED v8 — C2 restated result-based (no discriminator); deletion boundary documented (§5-C, §10) |
  | Codex f3 partial-B/restored-A alias | CLOSED v8 — identity-checked volatile refresh (§5-C) |
  | Codex f4 update_fabrics wrong-physical | CLOSED v8 — projection-scoped change detection; physical changes mark pending + reconcile (§5-C) |
  | Codex f5 sysfs race in update_fabrics | CLOSED v8 — telemetry vs projection split + empty-replan guard + rate cap (§5-C) |
  | Codex f6 quiescence race | CLOSED v8 — completion epoch spans sleep+dispatch; arm-sync gated on it (§5-C) |
  | Codex f7 retry completeness | CLOSED v8 — tagged completion retry (epoch-scoped) for latch states; unregistered pendings converge only at replan-producing applies (documented); actual-armed predicate; backoff-with-reset; loop after `ensureProcessLocked` (§5-C) |
  | Codex f8 latch authority / debt epoch / MAC phases | CLOSED v8 — `m.lastSnapshot.DeferWorkers` cleared on success; debt scoped to config generation; MAC debt revalidates both phases (§5-C) |
  | Codex M9 tests | CLOSED v8 — §9 rewritten with the new shapes |
  | Codex NIT M10/retry observability | CLOSED v8 — retry carries attempt counter, fingerprint, edge Warns (§5-C) |
  | SMR r6 N1/N2/N3 | = AGY f3/f2/f1 (v7.1) |

- **Round 7** (v8): Codex DEMAND-REVISION (6 BLOCKER + 3 MAJOR);
  AGY PLAN-READY-WITH-NITS (3 nits, folded in v8.1); SMR
  PLAN-READY-WITH-NITS (3 nits, folded in v8.1). Codex's round:
  `update_fabrics` is not a fail-closed Go→Rust replan transaction
  (Go's SyncFabricState ignores the returned status and writes back
  its input; the in-handler reconcile's teardown window leaves
  ctrl=1 with dying XSKs; and a `pending`-only mark does NOT close
  the `enabled` gate, which reads only `registered && armed` — the
  physical-change mark must be explicitly `armed=false`); the
  empty-replan guard has split Rust/Go authority (Go stores the
  incoming fabric slice unconditionally, so a guard-rejected
  projection re-enters through the next wholesale clone; and the
  handler publishes the incoming projection to workers BEFORE
  evaluating it — a rejected projection must be staged); the defer
  "epoch" is a leaking boolean (a failed tagged completion + an
  unrelated no-MAC-work commit stamps DeferWorkers=true into every
  later compile with no completion owner — needs explicit rollover
  on every commit); the ~12-attempt terminal cap deliberately
  recreates the issue's permanent sink (WorkerSpawn includes
  TRANSIENT pthread_create EAGAIN/ENOMEM whose recovery needs no
  state change — cap the FREQUENCY at 60s, never the recovery);
  "CONFIG generation" is not an implementable contract (the
  composite counter moves on FIB/fabric bumps and failed-compile
  allocations — needs a config-only epoch counter advanced
  only on accepted commits) and the MAC debt has no accepted-config
  identity/desired-set/supersession rule; the socket-tuple identity
  check can tear on relaxed stores (compare the PLANNED identity in
  workers.identities instead, and preserve last_error when zeroing
  on mismatch); the claim boundary contradicts itself on renames
  and queue-count contraction (the honest boundary is ANY
  planned-identity deletion); Q2 is sound (plan-scoped convergence;
  add the prior-S4 + current-S3 overlap test); tests remain
  false-green-capable; and do NOT split the MAC debt or pending
  retry into follow-ups — they are load-bearing (option D is the
  only safe split candidate).
- **Round-7 disposition table:**

  | r7 finding | v8.2 disposition |
  |---|---|
  | Codex f2 update_fabrics transaction | CLOSED — NO in-handler reconcile; projection change marks ALL non-operator slots `armed=false, pending` (enabled-gate-exact); Go applies the returned status IMMEDIATELY so ctrl drops in the same tick; the retry/next-apply drives the binding reconcile with the normal fail-closed posture (§5-C) |
  | Codex f3 guard authority | CLOSED — incoming projection is STAGED (refresh_fabric_links gets only the ACCEPTED set); Go writes back the helper's accepted fabrics, not its request input; the per-candidate skip cause is exact; legit full removal goes through apply_snapshot (never triggers the guard; the explicitly-empty fabrics slice is unencodable today — Rust-test-only) (§5-C) |
  | Codex f4 leaking epoch | CLOSED — epoch rollover on every commit: no-MAC-work clears the manager flag at compile start + cancels stale debts + the non-deferred stamp clears the helper latch; MAC work opens/replaces the epoch; an explicit operator arm clears the flag too (§5-C) |
  | Codex f5 terminal cap | CLOSED — retry is rate-capped-forever (60s floor) with one edge Warn at ~12 and reset-on-change; NO terminal cap anywhere; the tagged completion retry is explicitly exempt (§5-C) |
  | Codex f6 debt contracts | CLOSED — `m.configEpoch` (a config-only counter advanced only at compile acceptance, FIB-bump-clean per AGY r10 f1) keys both debts; supersession, member-removal cancellation, completion-mode history (§5-C; the v8.2 `lastAcceptedConfigGeneration` name superseded by v8.6's explicit counter) |
  | Codex f7 torn identity check | CLOSED — compare the PLANNED identity (workers.identities, written once at plan time) not the relaxed socket tuple; mismatch zeroing preserves last_error (§5-C) |
  | Codex f8 claim boundary | CLOSED — boundary restated: claims survive slot reshuffles and flaps; die at global fan-out or ANY planned-identity deletion (rename, candidate dropout, queue-count contraction) (§5-C C2, §10) |
  | Codex M9 tests | CLOSED — §9 rewritten with the r7 matrix incl. the Q2 overlap test |
  | AGY r7 f1/f2/f3 | CLOSED v8.1 — tag issued as `deferWorkers && !hasActiveMACDebt`; the Go test pins it; the arm-sync gate is the arm-direction skip `if desired && m.deferWorkers { return nil }` |
  | SMR r7 N1/N2/N3 | CLOSED v8.1 — exact empty-guard discriminator (superseded by Codex r7 f3's exact form); MAC debt member-removal cancellation; plan-scoped convergence note (Codex r7 confirms Q2 sound + overlap test) |

- **Round 8** (v8.2): Codex DEMAND-REVISION (3 BLOCKER + 3 MAJOR);
  AGY PLAN-READY (clean pass, zero findings); SMR
  PLAN-READY-WITH-NITS (3 nits). Codex's round: the MAC-completion
  contract is not restart-safe (boot with correct MAC + DOWN member
  opens no epoch — the precheck must check MAC mismatch OR link
  down per member) nor positively provenance-gated (the tag must
  mean epoch-open-AND-debt-settled, and the debt's mutations must
  participate in applySem); `update_fabrics` lacks unknown-outcome
  handling (a timeout/EOF after the helper commits leaves
  ctrl=1 with dying XSKs — pre-disable on projection change and
  stay fail-closed on unknown outcomes; and the honest convergence
  budget is ~15s worst-case, not ≤5s — mark-and-retry still wins);
  Q1 has a literal mixed-version producer (new Go + old helper
  creates registered+armed=false+state=none slots — the helper
  restart upgrade note is load-bearing); the last_error rule must
  be identity-keyed (match → copy even with zeroed tuple; mismatch
  → no error copy); the retry reset clock is underspecified
  (fingerprint = immutable pending identity membership; reset pulls
  earlier only, never postpones); the rollover actions belong at
  compile ACCEPTANCE not compile start (a failed successor must
  roll the flag back and leave stale debts alive); an explicit
  operator arm must clear the HELPER latch too; tests still
  false-green-capable (pending-ownership proof, boundary cases,
  torn/poisoned socket fields, the full advance-point matrix,
  response-loss, fresh-daemon restart, positive provenance pin);
  and D is a release gate (ships in this PR or as a stacked
  prerequisite — never dropped).
- **Round-8 disposition table:**

  | r8 finding | v8.3 disposition |
  |---|---|
  | Codex f4 MAC contract restart/provenance/serialization | CLOSED — precheck is MAC-mismatch OR link-down per member (boot reconstructs the debt from active config); debt opens at epoch opening (tag = epoch-open AND debt-settled, positive form); every mutation acquires applySem + epoch-revalidates immediately before acting (§5-C) |
  | Codex f5 fabric unknown-outcome + budget | CLOSED — Go pre-disables ctrl whenever the requested projection differs from the cached accepted projection, stays fail-closed on timeout/EOF until the next successful poll, and the plan states the honest ~15s worst-case window (§5-C) |
  | Codex f6 mixed-version producer | CLOSED — release note upgraded from advisory to REQUIRED helper restart; D is the tripwire for exactly that window (§9 docs) |
  | Codex f7 reset clock | CLOSED — fingerprint = immutable pending identity membership (no last_change/last_error); reset pulls the deadline earlier only (§5-C) |
  | Codex f8 (Q5 identity) | CONFIRMED SOUND — planned-identity comparison is exact for fabric/orphan parent re-keys; last_error attribution is now identity-keyed: match → copy even with zeroed tuple, mismatch → no error copy (§5-C, §9 item 16) |
  | Codex f9 rollover timing + operator arm latch | CLOSED — rollover actions happen at compile ACCEPTANCE; a failed successor rolls the flag back and leaves stale debts alive; the operator arm clears the helper's stored latch in the same handler write (§5-C) |
  | Codex M8 tests | CLOSED — §9 items 12/13/14/16/17/19 + Go retry reset-clock cases + MAC fresh-daemon restart and positive-provenance pins |
  | AGY r8 PLAN-READY | (clean pass) |
  | SMR r8 N1/N2/N3 | CLOSED v8.2.1 — rollover ordering sentence, mixed-update whole-defer rule, claimed-slot rebind assurance |

- **Round 9** (v8.3): AGY DEMAND-REVISION (2 BLOCKER + 1 MAJOR + 1
  MINOR + 1 NIT); SMR PLAN-READY-WITH-NITS (5 doc nits); Codex in
  flight at v8.4 fold time. AGY's round: the two-phase precheck
  (`mac != desired || !linkUp`) opens a defer epoch on EVERY commit
  while any member link is down — an unplugged cable then gates the
  arm-sync AND the pending retry forever, taking the whole
  dataplane down over one dead member (this issue's outage mode,
  reproduced by the v8.3 precheck); the epoch-open debt deadlocks
  the FIRST tagged rebind (the background debt task can't settle
  while applySem is held in the apply flow, so
  `deferWorkers && !hasActiveMACDebt` evaluates false at the
  dispatch and the untagged rebind never consumes the latch —
  needs in-flow synchronous settlement of the initial
  programRethMAC's validated phases, and the debt's full-settlement
  EVENT must dispatch the tagged completion itself); the fabric
  pre-disable must not reset `neighborsPrewarmed` on a guard-hit
  (nothing changed helper-side — the next poll's normal readiness
  gate re-enables in ~1 tick; reset only on accepted projection
  changes); operator arm must reset the pending-retry clock
  (attempts + nextAt); and `activation_state` display must be
  pinned to JSON + verbose only (non-verbose CLI layout unchanged).
- **Round-9 disposition table:**

  | r9 finding | v8.4 disposition |
  |---|---|
  | AGY f1 two-phase precheck outage | CLOSED — precheck reverts to MAC-mismatch-only for epoch opening; three-bucket classification: MAC mismatch → epoch, correct-MAC-link-down → link-recovery debt entry with NO epoch/latch/pending marks (healthy dataplane keeps forwarding; the Codex r8 f4 restart case is restart-safe via the recovery entry, not an epoch) (§5-C) |
  | AGY f2 epoch-open deadlock | CLOSED — the initial programRethMAC IS validation pass 1 and settles validated phases in the debt SYNCHRONOUSLY in-flow before the dispatch is evaluated; a fully-successful first attempt fires the tag in the same flow; and the debt's full-settlement EVENT dispatches the tagged rebind itself (the retry path's completion) (§5-C) |
  | AGY f3 pre-disable prewarm reset | CLOSED — the fabric pre-disable is a plain ctrl.Enabled=0 write; liveness/prewarm resets happen only on ACCEPTED projection changes (§5-C, §7; = SMR r9 N3) |
  | AGY f4 retry clock on operator arm | CLOSED — any operator arm (global or per-binding) resets pendingRetryAttempts and pendingRetryNextAt to zero (§5-C) |
  | AGY f5 CLI scope | CLOSED — `activation_state` pinned to JSON + verbose only; non-verbose CLI layout byte-identical (§6) |
  | SMR r9 N1-N5 | CLOSED — N1 out-of-band admin-down = config-authoritative drift (folded into the three-bucket text); N2 first-validation-is-synchronous (folded into the settlement text); N3 = AGY f3; N4 timeout-landed convergence via #4036 exact-equal retry + completion machinery (no mirror rollback needed); N5 dropped-queue errors die with the identity, reverse-sync arrives only as rollback (both covered by existing contracts) |
  | Codex r9 | see the r9-codex table below (v8.5) |

- **Round 9, Codex verdict (v8.3):** DEMAND-REVISION (2 BLOCKER +
  4 MAJOR). Codex's round: the pre-disable is insufficient without
  failure semantics (ctrl lookup/update/readback can fail — the
  projection RPC must not be sent unless ctrl=0 is VERIFIED, else
  don't send); UNKNOWN recovery leaves Go's accepted-fabric cache
  stale (helper accepts B, response lost, Go keeps A, a
  route/scheduler clone republishes A and reverts B — the status
  application must adopt `status.Fabrics` helper-authoritatively
  on every poll); §7.3 still mandated the torn socket-tuple check
  (reviving the relaxed-store tear — must be the planned
  identity); item 16's error rule was self-contradictory (now
  identity-keyed: match copies even with a zeroed tuple, mismatch
  copies nothing, dropped-identity errors die with the identity);
  the reset clock lets an event storm pin worker-set teardowns at
  a 5s cadence (events must never touch the attempt exponent —
  only immutable membership transitions pull the deadline
  earlier); the tagged retry can consume a landed-but-
  unacknowledged successor's latch (needs a stored-generation
  guard); nil-config bootstrap teardown leaves ownerless
  epoch/debt state (needs explicit cancellation); HA reverse-sync
  authority is role-based (applied older peer config IS
  authoritative → advance + supersede; the applied-identical
  shortcut must NOT advance); and the tests still green-capable
  (reconcile-entry hook, lost-ACK shapes, advance matrix
  additions, pre-disable fault injection, release budgets, event
  storm, bucket edges, stale-attempt race, real handoff).
- **Round-9-codex disposition table:**

  | r9 finding | v8.5 disposition |
  |---|---|
  | Codex f5 pre-disable verification + cache adoption | CLOSED — ctrl=0 is readback-VERIFIED before the projection RPC is sent (disable failure blocks the send); applyHelperStatusLocked adopts status.Fabrics into m.lastSnapshot.fabrics on EVERY poll (helper-authoritative — the lost-response A/B divergence dies; partial publishers always carry the accepted set) (§5-C) |
  | Codex f6 invariant/error-rule contradictions | CLOSED — §7.3 now mandates the PLANNED-identity comparison (tear-free); item 16's error rule is identity-keyed with the explicit no-dropped-row/no-B→A-attribution/operation-stage-retained pin (§5-C, §7, §9) |
  | Codex f7 reset exponent | CLOSED — events never touch the attempt exponent; only immutable pending-membership transitions pull nextAt EARLIER with the exponent preserved (event-storm test at the floor) (§5-C, §9) |
  | Codex f8 test holes | CLOSED — §9 items 12/13/16/17/19 + retry storm + MAC bucket edges/stale-attempt/real-handoff rewritten |
  | Codex f9 HA authority | CLOSED — role-based note: applied peer config (any origin) advances + supersedes; the applied-identical shortcut advances nothing (§5-C, §9 item 17) |
  | Codex f10 lost-ACK latch + nil-config teardown | CLOSED — tagged retry suppressed while the helper's stored generation exceeds the debt's epoch; shutdown with no accepted config cancels open epoch/debts explicitly (§5-C) |

- **Round 10** (v8.5): Codex DEMAND-REVISION (3 BLOCKER + 4
  MAJOR); AGY PLAN-READY-WITH-NITS (1 MINOR + 2 NIT); SMR
  PLAN-READY-WITH-NITS (3 doc nits). Codex's round: the
  three-bucket MAC design still reproduces the entire-dataplane
  outage in the MIXED case (a MAC-mismatch epoch's "every member
  validated" rule lets one unplugged bucket-ii member block the
  whole dataplane — the validation set must be bucket-i only, and
  configured-disabled (`disable: true` is authoritative config,
  types_interfaces.go:22) must be excluded from validation AND
  recovery, missing members until the next precheck, and the
  settle must REREAD link state because programRethMAC returns
  success on MAC equality without inspecting it); unconditional
  helper-authoritative fabric adoption creates B-config/A-fabric
  hybrids in two directions (staged-newer-config unpublished and
  landed-but-unacknowledged apply) — adoption must be PAIR-GATED
  on the (generation, fib) lineage pair; the stored-generation
  guard is contaminated (FIB overlay republishes advance the
  scalar on both sides, manager_overlay.go:188/:239 —
  manager-side `m.configEpoch` plus a rebind-carried
  `expected_snapshot_generation` the helper can refuse is the
  clean form, and every authorized exit must clear ALL THREE
  latch authorities including the Go cache); the MAC
  daemon/manager handoff is unspecified (the current
  LinkController has three operations, apply.go:130); and the
  usual doc-contradiction sweep (§7.3 socket tuple vs planned
  identity, item 16's dual error rules, the pseudocode/invariant
  reset semantics, the stale v8.3 restart test) — several of my
  v8.5 fold texts had silently failed to land while the
  disposition table claimed them (an expensive lesson in
  per-edit verification, which this revision applies to every
  edit). AGY's round: the stored-generation guard must compare a
  config-only generation, not the fib-contaminated scalar
  (manager_generation.go:69 increments it on FIB-only updates) —
  answered by the configEpoch contract; and the rebind handler
  plumbing needs to forward request.complete_deferred explicitly.
- **Round-10 disposition table:**

  | r10 finding | v8.6 disposition |
  |---|---|
  | Codex f2 mixed-bucket outage + bucket semantics + handoff | CLOSED v8.6, REOPENED r11 (bucket-ii "in the MAC debt" vs `!hasActiveMACDebt` gating contradiction; handoff unspecified), RE-CLOSED v8.7 — TWO TYPED COLLECTIONS (`macEpochDebt` gates, `linkRecoveryDebt` never; `hasActiveMACDebt` counts only the former); reread at EVERY validation attempt; `AttemptMACDebt` fully specified (§5-C, §6) |
  | Codex f3 adoption hybrids | CLOSED v8.6 (pair gate), REOPENED r11 (the pair is not a helper lineage pair — FIB/neighbor/fabric-persist split it; request side unfenced), RE-CLOSED v8.7 — lineage gate on `appliedSnapshot.Generation` + staged-ahead check (response) and `expected_snapshot_generation` fence + divergence suppression (request) (§5-C (iii)/(iv)) |
  | Codex f4 guard contamination + three-authority latch | CLOSED v8.6, REOPENED r11 (the `publishedSnapshot` token false-refuses legitimate completions after partial ops; exit enumeration incomplete; nil-config retains the flag), RE-CLOSED v8.7 — `ConfigGeneration` token (fib-clean both sides), refusal ordered FIRST, six-exit enumeration with clean+UNKNOWN clears, `stopLocked` clears all three, `stored_defer_workers` echo (§5-C, §5 Ownership (a)-(f), §6) |
  | Codex f5/f6 contradictions + test folds absent | CLOSED v8.6, PARTIALLY REOPENED r11 (new contradictions found: "every member up" tests, S4' caller list, trailing-coalesce, additive-field count, coordinator claim), RE-CLOSED v8.7 — all five corrected in §6/§9 and verified per-edit |
  | Codex f7 Q2 proof + budget | CLOSED v8.6, REOPENED r11 (value edge unsafe: reject→accept bypass + A→B→A pulse; ≈19s is baseline not worst-case; error swallowed), RE-CLOSED v8.7 — env-gated suppression + always-disable-on-send, end-to-end error propagation, honest warm-clock budget (§5-C (i), §11 Q7) |
  | AGY r10 f1 (MINOR) | CLOSED — the debt epoch is `m.configEpoch`, explicitly NOT the fib-contaminated scalar (manager_generation.go:69-72's direct `m.generation++` never touches it) |
  | AGY r10 f2/f3 (NITs) | CLOSED — the rebind handler takes the request (or `complete_deferred: bool`) and forwards it to `reconcile_status_bindings(state, request.complete_deferred)`; the evidence wish is informational (no fold needed) |
  | SMR r10 N1-N3 | CLOSED/SUPERSEDED — N1 (fib-invariance sentence) superseded by the configEpoch contract itself (fib-clean by construction); N2 (flap classes) folded into the bucket text + the settle reread; N3 (posture sentence) folded into the verified pre-disable bullet |
- **Round 11** (v8.6): Codex DEMAND-REVISION (9 BLOCKER + 3
  MAJOR); AGY PLAN-READY (clean pass, zero findings); SMR
  PLAN-READY-WITH-NITS (1 MINOR + 2 NIT). Codex's round: the
  (generation, fib) pair gate compares values that are not a
  helper snapshot-lineage pair (FIB bumps/neighbor
  regens/fabric persists split them — adoption wedges and a
  later wholesale clone republishes stale Go fabrics, the #5306
  class); response-side gating cannot fence REQUEST-side fabric
  hybrids (`update_fabrics` mutates whichever snapshot the
  helper stores, no lineage token); the
  `m.publishedSnapshot.Generation` completion token
  false-refuses legitimate same-epoch completions after any
  partial operation (and `m.publishedSnapshot` is a uint64, not
  an object; refusal ordering unspecified against rebind.rs's
  clear-first behavior); timeout-but-landed successors and
  defer exits lack a complete ownership protocol (the two v8.6
  statements cannot both be established; nil-config
  `stopLocked` retains `m.deferWorkers`; the "exactly two
  exits" claim is false); `configEpoch`'s advance contract is
  inconsistent (the #5134 direct retry must not advance —
  no precheck, so advancing cancels same-config link-recovery
  entries; the pending-XSK staging advance point unspecified);
  the bucket-i completion cohort is semantically contradictory
  (bucket-ii entries "in the MAC debt" vs `!hasActiveMACDebt`
  gating; "every member up" tests vs the settle reread vs Q7's
  keep-epoch-open); the LinkController handoff is not an
  architecture contract (no signature/types/epoch token/locking
  — the daemon owns applySem); the value edge-trigger is unsafe
  (environmental guard → reject→accept bypass and A→B→A pulse;
  one scalar cannot carry both properties; the pre-disable
  error is swallowed by controllers.go and daemon_ha_fabric.go);
  the test plan can green with the blockers intact (ten
  sub-items); the ≈19s figure is a clean-baseline estimate, not
  a worst case (warm retry clock → ≈60s floor). Q1 (unowned
  producer hunt) remains CLOSED — Codex found no additional
  same-version producer. AGY's clean pass and SMR's SMR11-1
  (the pair gate wedges on a fib-bump failure → config-lineage
  refinement) CONVERGE with Codex f2 on the same defect from
  three angles.
- **Round-11 disposition table:**

  | r11 finding | v8.7 disposition |
  |---|---|
  | Codex f1 disposition overclaim | CLOSED — this table + the r10 rows re-audited; every v8.7 fold verified per-edit against the file |
  | Codex f2 pair authority | CLOSED v8.7, REOPENED r12 (appliedSnapshot capture is deliberately delayed while deferred + records the mutated scalar post-rebind; ConfigGeneration is Go-internal vs the helper's ever-advancing stored generation), RE-CLOSED v8.8 — `config_epoch` ON THE WIRE for the adoption gate, fence, and tag (§5-C, §6) |
  | Codex f3 request-side hybrids | CLOSED v8.7, REOPENED r12 (the Go-internal token false-refuses after every full-apply producer; old-helper suppression has an unobserved helper-ahead window), RE-CLOSED v8.8 — `expected_config_epoch` fence + divergence suppression (§5-C (iv)) |
  | Codex f4 completion token false-refusal + ordering | CLOSED v8.7, REOPENED r12 (route/scheduler/#5134 full republishes deterministically false-refuse), RE-CLOSED v8.8 — the tag carries the debt's `config_epoch` (clone-republishes and overlays carry the SAME epoch); refusal still ordered FIRST (§5-C) |
  | Codex f5 ownership protocol + exits | CLOSED v8.7, REOPENED r12 (B discarded — no exact-equal republish exists; the echo erases staged intent; verbs lack provenance), RE-CLOSED v8.8 — ACTIVE-CONFIG RE-APPLY owns the re-sync; (v) gated echo; operator-provenance exit (d); transition (g) helper restart; seven exits/transitions (§5-C, Ownership (a)-(g)) |
  | Codex f6 configEpoch advance | CLOSED v8.7, REOPENED r12 (:618 citation is the scheduler overlay; pending-XSK has no debt handoff), RE-CLOSED v8.8 — pending/accepted split; advance at compile publish legs (:361/:365) ONLY + re-sync + dedup collapse; staged compile RETAINS cohort+results keyed on the pending epoch (§5-C epoch contract) |
  | Codex f7 bucket cohort | CLOSED v8.7, REOPENED r12 (the transfer DISCARDS the unprogrammed MAC obligation; bucket-iii has no owner), RE-CLOSED v8.8 — THREE TYPED OBLIGATIONS with obligation-preserving transfer; pass-1 reread covers ALL desired members (§5-C debt) |
  | Codex f8 LinkController contract | CLOSED v8.7, REOPENED r12 (direction contradicts the daemon→manager interface; linkCycled + repairs missing; d.configEpoch invented), RE-CLOSED v8.8 — daemon-side scheduler, ONE-WAY applySem > m.mu, `ValidateMACDebtEpoch` + `ReportMACDebtAttempt` (§5-C, §6) |
  | Codex f9 edge-trigger + error swallow | CLOSED v8.7, REOPENED r12 (env token lacks causal sampling/union watch/incarnation/dispatch; bare error corrupts map-commit bookkeeping), RE-CLOSED v8.8 — causal one-sample token + union watch + incarnation reset + poll dispatch; typed outcome at all four call sites (§5-C (i)) |
  | Codex f10 test greens | CLOSED v8.7, REOPENED r12 (tests can green with the r12 blockers intact), RE-CLOSED v8.8 — §9 re-specified per r12 f13 (full-producer negatives, active-config handoff, UNKNOWN matrix additions, three-obligation cohort, causal env, four-site typed error, canaries) |
  | Codex f11 budget | CLOSED v8.7 (relabeling accepted), REOPENED r12 for the omitted unbounded cases (suppression-without-watch, TRY starvation, ownerless B, +30s dispatch), RE-CLOSED v8.8 via the f5/f9/f10 folds + the updated budget text (§5-C budget, §11 Q7) |
  | AGY r11 (clean) | no fold needed |
  | SMR r11 SMR11-1 | CLOSED/SUBSUMED by Codex f2's fold — the `appliedSnapshot.Generation` authority IS the config-lineage refinement (and survives the content-dedup advance that SMR's `publishedSnapshot` leg would not, process_status.go:72-80) |
  | SMR r11 N2/N3 | CLOSED — N2 (bucket-i flap bound+armed normally, link recovery rides link events) folded into the every-attempt-reread text; N3 (configured-disabled posture) folded into §11 Q5 |

- **Round 12** (v8.7): ALL THREE DEMAND-REVISION — Codex (11
  BLOCKER + 3 MAJOR), AGY (3 BLOCKER + 3 MAJOR), SMR (1 BLOCKER
  + 1 MAJOR + 2 MINOR + 1 NIT, self-found in its own v8.7 fold).
  The three reviewers converged on five defect families: (i) the
  lineage TOKENS all fail — v8.7's `ConfigGeneration` is
  Go-internal while the helper's stored generation advances on
  EVERY full-apply producer (route overlays, scheduler
  republishes, #5134 clone-republishes), false-refusing every
  legitimate completion and fabric update after ordinary churn
  (Codex f2/f4 = AGY f2 = SMR12-1); the `appliedSnapshot`
  adoption gate misdetects every clean deferred B (the
  deliberately-delayed capture, applied_nat_view.go:64-98) and
  records the mutated Go scalar post-rebind (Codex f3); the
  staged-ahead scalar/pointer disjuncts false-block fib-bump
  and content-dedup states (Codex f4 = AGY f3 = SMR12-3); (ii)
  the UNKNOWN re-sync is unimplementable — Go discards the
  staged snap on publish timeout and `bumpGeneration` burns
  the number, so no exact-equal republish of B exists (Codex
  f5 = AGY f1); (iii) the v8.7 additions introduce their own
  races — the unconditional `stored_defer_workers` echo erases
  freshly-staged defer intent mid-Compile (Codex f6), the
  bucket-i→linkRecovery transfer discards the unprogrammed
  MAC obligation (Codex f7), the TRY-acquire phase-locks
  against the 30s proxy-ARP reconcile (Codex f9), the env
  token lacks causal sampling / rejected-candidate watch /
  incarnation scoping / dispatch (Codex f10 = AGY f6), and the
  bare error return corrupts post-map-commit bookkeeping
  (Codex f11); (iv) `AttemptMACDebt` is directionally
  incoherent (the LinkController is daemon→manager; both
  directions are needed; sticky `linkCycled` and post-cycle
  repairs are missing) (Codex f8 = AGY f4 = SMR12-2); (v) the
  test suite can green with every blocker intact (Codex f13,
  ten holes), and the v8.7 hazard budget omits the new
  unbounded cases (Codex f14). Q1 (slot-writer hunt) remains
  CLOSED for the eleventh enumeration. AGY f5 (bucket-iii
  flap unmonitored) and SMR12-4/SMR12-5 converge with Codex
  f7/f10.
- **Round-12 disposition table:**

  | r12 finding | v8.8 disposition |
  |---|---|
  | Codex f1 disposition overclaim | CLOSED — this table + the r11 rows re-audited; every v8.8 fold verified per-edit |
  | Codex f2 ConfigGeneration vs wrong authority (= AGY f2 = SMR12-1) | CLOSED — `config_epoch` ON THE WIRE: stamped on every full apply (compiles pending, clones/overlays accepted), helper-stored, status-echoed; fence + tag carry `expected_config_epoch`; Go-internal `ConfigGeneration` DELETED (§5-C, §6) |
  | Codex f3 appliedSnapshot asymmetric capture | CLOSED — the adoption gate keys on the wire epoch, not `appliedSnapshot` (which stays with its #2079 consumer); the delayed-capture misdetection and mutated-scalar capture classes die with the gate change (§5-C (iii)) |
  | Codex f4 staged-ahead disjuncts false-block (= AGY f3 = SMR12-3) | CLOSED — scalar/pointer disjuncts deleted; staged-ahead ⟺ `m.pendingConfigEpoch > m.acceptedConfigEpoch`; the content-dedup skip collapses accepted=pending (builder-hash-proven truthful) (§5-C (iii)) |
  | Codex f5 B unrecoverable (= AGY f1) | CLOSED — the re-sync owner is the ACTIVE-CONFIG RE-APPLY (control-plane commit already landed; fresh generation mint satisfies #3767; identical content; fresh precheck re-instantiates debts; both MAC shapes take it) (§5-C completion machinery) |
  | Codex f6 echo erases staged intent + verb provenance + restart | CLOSED — the latch echo is (v) lineage-gated (epoch match, no staged config, no compile in flight); the defer intent is a Compile ARGUMENT set under m.mu (the daemon's pre-Compile SetDeferWorkers call deleted); exit (d) is OPERATOR-provenance-only (automatic disarms epoch-preserving; UNKNOWN-disarm owner = desired-state sync); transition (g) helper restart modeled (§5-C (v), Ownership (a)-(g)) |
  | Codex f7 reclassification discards MAC obligation (+ bucket-iii hole = AGY f5 = SMR12-5) | CLOSED — THREE TYPED OBLIGATIONS: a down bucket-i member transfers to `macAndLinkRecovery` with the FULL obligation (program-MAC + setUp + post-cycle repairs + XSK rebind on link return); the pass-1 reread covers ALL desired members (bucket-iii flap → `linkOnlyRecovery`); cancellation names all three collections (§5-C debt) |
  | Codex f8 AttemptMACDebt incoherent (= AGY f4 = SMR12-2) | CLOSED — debt scheduler + netlink daemon-side; ONE-WAY applySem > m.mu hierarchy (manager never calls daemon); two daemon→manager methods (`ValidateMACDebtEpoch`, `ReportMACDebtAttempt` with sticky `linkCycled`); recovery execution reuses the apply flow's repair primitives (§5-C, §6) |
  | Codex f9 TRY-acquire starvation | CLOSED — bounded BLOCKING acquire (10s ctx) + post-acquisition epoch revalidation (owners hold ms-scale; queued-supersede harmless) (§5-C, §9 race test) |
  | Codex f10 env token causal/watch/incarnation/dispatch (= AGY f6 = SMR12-4) | CLOSED — ONE sample per verdict; UNION watch (accepted + last-rejected candidates); incarnation-scoped Go cache (reset on respawn); poll-dispatched retry (no 30s ticker wait) (§5-C (i), §9 item 19) |
  | Codex f11 error corrupts map-commit | CLOSED — typed outcome: map commit stands, helper-sync failure = fabric SYNC DEBT (retry + edge Warn), readiness reads (map state, debt state); all four call sites (§5-C (i), §6) |
  | Codex f12 :618 citation + pending-XSK handoff | CLOSED — advance points are the compile publish legs (:361/:365) only; the pending-XSK staged compile RETAINS its cohort + pass-1 results in the debt keyed on the pending epoch (§5-C epoch contract) |
  | Codex f13 test greens | CLOSED — §9 re-specified per finding: full-producer false-refusal negatives, active-config re-apply handoff, UNKNOWN matrix additions (lost disarm, missing echo, fresh helper, mid-defer restart, poll-vs-Compile), three-obligation cohort + linkCycled + blocking acquire + repairs, causal env (one-sample/union/incarnation/dispatch), four-site typed error, budget +dispatch +starvation, protocol canaries for all new fields with missing-field semantics |
  | Codex f14 budget | CLOSED — the v8.8 budget adds the poll-dispatch path (no +30s) and the no-starvation guarantee; the new unbounded classes (suppression-without-watch, TRY starvation, ownerless B) are closed by f5/f9/f10 (§5-C budget, §11 Q7) |
  | AGY r12 f1-f6 | CLOSED — folded with the matching Codex rows above (f1→f5, f2→f2, f3→f4, f4→f8, f5→f7, f6→f10) |
  | SMR r12 SMR12-1..5 | CLOSED — SMR12-1→Codex f2 row (the `config_epoch`-on-wire fix is SMR12-1's required fix); SMR12-2→f8 row; SMR12-3→f4 row; SMR12-4→f10 row; SMR12-5→f7 row |
  | Codex f1's SMR-N2 row (no link-UP→rebind) | CLOSED — the recovery entries own the post-return rebind themselves; the v8.7/N2 sentence claiming existing machinery is DELETED (§5-C debt, §11 Q2) |

- **Round 13** (v8.8): ALL THREE DEMAND-REVISION — Codex (12
  BLOCKER + 3 MAJOR), AGY (4 BLOCKER + 2 MAJOR), SMR (1 BLOCKER
  + 3 MINOR/NIT, self-found in its own v8.8 fold). Convergence:
  the v8.8 dedup collapse wedges the gate AND the fence against
  the helper's un-updated stored epoch (Codex f4 = AGY f1 =
  SMR13-1); the mint/carry contract cannot represent ambiguous
  post-write failures and publishes staged B under A's lineage
  via overlay clones (Codex f2/f3); the UNKNOWN re-sync has no
  production owner and a stale #5134 clone can overwrite
  timeout-landed B and erase the signal (Codex f5 = AGY f1's
  premise); the defer intent has no API path and its v8.8
  deletion reopened the mid-compile arm-sync window (Codex f7
  = AGY f3); operator provenance cannot reach Rust (Codex f7);
  the MAC recovery is not a safe XSK transaction (Codex f8 =
  AGY f6); the debt interface cannot supply work and the
  claim is not a linearization fence (Codex f9); the lock
  rule is both too broad (OnXSKBound exists) and unproven for
  the new paths, and the 10s acquire bound is not a fairness
  guarantee (Codex f10 = AGY f4's premise); the env token is
  loss/oscillation-unsafe (Codex f11 = AGY f5 = SMR13-4); the
  fabric sync debt is not an executable state machine (Codex
  f12); mixed-version epoch-0 is not a barrier (Codex f6);
  tests green with the defects (Codex f13). AGY f2's
  mint-vs-stamp contradiction is answered by the commit-seq
  model (no allocator); AGY f4's inversion is answered by the
  precise lock rule (applySem is daemon-private).
- **Round-13 disposition table:**

  | r13 finding | v8.9 disposition |
  |---|---|
  | Codex f1 disposition overclaim | CLOSED — this table + the r12 rows re-audited; every v8.9 fold verified per-edit |
  | Codex f2 epoch allocator/ambiguous failure | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — `config_epoch` = the configstore's globally-monotonic commit seq (`archiveSeq`): no allocator, never reused, identical across same-config Compile invocations (§5-C epoch contract) |
  | Codex f3 overlay publishes B under A's lineage + census | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — every producer carries its CONTAINED config's seq (the B-clone carries B's); the five-producer census + the two deferred-acceptance legs (process_status.go:18-37/:120-139) are now in the advance list (§5-C (iv), epoch contract) |
  | Codex f4 dedup lineage (= AGY f1 = SMR13-1) | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — `note_config_epoch` lineage-transfer verb on the dedup skip; the local collapse is deleted; FAILED transfer = fail-closed suppression (§5-C (iii), §6) |
  | Codex f5 re-sync owner + A-clone overwrite | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — daemon-driven single-flight re-sync debt (enqueue-after-unlock); suppression of ALL older-lineage producers + the helper's epoch-rollback refusal backstop (§5-C completion machinery, (iv)) |
  | Codex f6 mixed-version epoch-0 | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — all lineage-sensitive operations fail closed on epoch 0 until the REQUIRED helper restart (§5-C epoch contract) |
  | Codex f7 defer-intent API + provenance wire | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — `StartDeferredCompile()` (intent+compileInFlight in one m.mu section at the precheck point, cleared on every Compile exit); `set_forwarding_state.provenance` wire field (default operator; automatic epoch-preserving); durable operator-verb retry debt (§5-C, §6) |
  | Codex f8 recovery XSK transaction (= AGY f6) | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — Prepare/Notify quiesce-all+rebind-all (budgeted, per-member quiescence a follow-up); linkCycled at DOWN-success; proxy-ARP/NDP in repairs; debt clears on observed bound+ready (§5-C debt) |
  | Codex f9 work-pull + linearization + pendingWorkerArm | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — `ClaimMACDebtWork` (due items + claimToken) + `ReportMACDebtAttempt` (stale-token discard); ApplyResult gains the epoch; #5134 pendingWorkerArm epoch-qualified + cleared on supersession (§5-C, §6) |
  | Codex f10 lock rule + fairness (= AGY f4 premise) | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — "no SYNCHRONOUS manager→daemon call while holding m.mu" (async enqueue = OnXSKBound shape); FIFO+bounded-hold proof with a 30s acquire bound; try-lock-or-skip manager calls (§5-C debt execution) |
  | Codex f11 env loss/oscillation (= AGY f5 = SMR13-4) | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — ≤4 ack-set of rejected identities (lost response re-sends + re-acks); debounced dispatch ≤1/5s per identity; the clamp source-model correction (§5-C (i), §9 item 19) |
  | Codex f12 fabric debt state machine | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — keyed `(config_epoch, projection-hash)`; {pending, retrying, failed-warned}; clean-matching-sync clear; readiness ANDs fabricPopulated with no-outstanding-debt; all four call sites (§5-C (i), §6) |
  | Codex f13 test greens | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — §9 re-specified per finding (re-sync debt shape, epoch reservation cases, staged-B producer census, deferred-acceptance legs, epoch-0, StartDeferredCompile + provenance wire, recovery transaction shapes, fairness + claimToken + contention, ack-set + flap, keyed debt clear) |
  | Codex f14 pass-1 cost | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — budgeted at µs-scale netlink reads (≤ ~1ms for a 12-member RETH) (§5-C budget) |
  | Codex f15 budget | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — the residual unbounded classes (epoch reuse, A-clone overwrite, ownerless owners, semaphore starvation, env oscillation, stale-5134 suppression, unobserved recovery) are closed by f2/f5/f9/f10/f11/f8; the budget text carries the fairness + pass-1 notes (§5-C budget, §11 Q7) |
  | AGY r13 f1-f6 | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — folded with the matching rows (f1→Codex f4, f2→f2 (commit-seq answers the contradiction), f3→f7 (StartDeferredCompile), f4→f10 (lock-rule proof), f5→f11, f6→f8) |
  | SMR r13 SMR13-1..4 | CLOSED v8.9, REOPENED r14 (codex-plan-r14.md f1 audit), RE-CLOSED v8.10 (r14 table below) — SMR13-1→Codex f4 row; SMR13-2/3 (re-sync debt identity, debt keying) → the epoch contract's uniform debt rule + the re-sync debt's explicit identity; SMR13-4 → f11 row + the recovery transaction's drop-window note |

- **Round 14** (v8.9): ALL THREE DEMAND-REVISION — Codex (12
  BLOCKER + 3 MAJOR), AGY (4 BLOCKER + 2 MAJOR + 1 MINOR), SMR
  (2 BLOCKER + 4 MINOR/NIT). The headline: v8.9's `archiveSeq`
  foundation is not a commit sequence (Codex f2 — a
  per-process archive-retention counter that
  CommitConfirmed/SyncApply/PromoteRollback don't bump, manual
  ArchiveConfig bumps without a commit, crash-reseeds reuse,
  and `config.Config`/`ActiveConfig` carry no revision at
  all); the rollback refusal rejects legitimate auto-revert
  and same-commit divergence is undetectable without a
  separate publication revision (Codex f3); auxiliary
  first-publishers publish staged B with no acceptance
  handoff and the #5134 clone can ARM it (Codex f4);
  `note_config_epoch` is an unguarded monotonicity backdoor
  with no failed-transfer owner (Codex f5 = AGY f5 =
  SMR14-1); the latch echo must be ASYMMETRIC clear-only
  (AGY f2 = SMR14-2, verified); the re-sync debt is
  prohibited by its own firing rule and not latest-wins
  (Codex f6); StartDeferredCompile reserves only deferred
  compiles and a stale flag leaks into no-MAC successors
  (Codex f7); the claimToken fences bookkeeping, not
  physical side effects (Codex f8); the recovery cannot
  prove quiescence (PrepareLinkCycle is void and ignores
  failures) (Codex f9); the fairness proof is source-false
  (a full apply holds applySem through a legally-120s
  control round trip) (Codex f10); the env ack-set lacks
  eviction ownership and an aggregate bound (Codex f11 =
  AGY f4 = SMR14-5); the fabric debt hash aliases telemetry
  and the readiness conduit doesn't exist (Codex f12 = AGY
  f6); the recovery clear predicate wedges on
  operator-UNREGISTERED slots (Codex f9 refines AGY f3 =
  SMR14-4); factory reset needs an epoch rebase (AGY f1,
  narrowed by Codex f3); tests green with the defects
  (Codex f13); the pass-1 figure is an unsupported estimate
  (Codex f14); the budget remains unbounded (Codex f15).
- **Round-14 disposition table:**

  | r14 finding | v8.10 disposition |
  |---|---|
  | Codex f1 disposition overclaim | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — this table + the r13 rows re-audited; every v8.10 fold verified per-edit |
  | Codex f2 archiveSeq not a commit sequence | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — `commit_revision` is a REAL durable promotion revision: store-assigned at promotion time on EVERY accepted-config path (plain Commit, CommitConfirmed, SyncApply, PromoteRollback, boot-recovery promote), persisted atomically with the active config, read via the new `ActiveConfigRevision()` API; archiveSeq deleted from the design (§5-C epoch contract) |
  | Codex f3 rollback refusal + same-commit divergence | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — `publication_rev` (manager-minted, burned per send, startup-seeded from the helper's echo) carries send order: the helper refuses a not-strictly-greater apply_snapshot; same-commit reshapes get distinct revs; the auto-revert promote assigns a fresh commit_revision at promotion time like every other path (§5-C epoch contract) |
  | Codex f4 auxiliary first-publishers | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — ALL auxiliary full-publish producers suppressed while any config is staged-unpublished; the ONLY first-publish of B is its own compile leg; the #5134 DeferWorkers=false clone can never arm staged B (§5-C (iv)) |
  | Codex f5 note backdoor + no owner (= AGY f5 = SMR14-1) | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — `note_commit_revision` CAS {new_rev, expected_rev}: strict-older refusal, equality-idempotent, CAS refusal abandoned as superseded, FAILED/UNKNOWN retried via a supersedable note debt cleared only on an exact echo of the captured sent revision (§5-C (iv), §6) |
  | Codex f6 re-sync prohibited + not latest-wins | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — the re-sync debt FIRES on observed divergence (status.commit_revision > accepted OR publication_rev ahead), never on its own key; latest-wins drain-time re-reads; explicit transitions (nil ActiveConfig, channel saturation, acquire timeout, re-apply failure) (§5-C UNKNOWN-outcome ownership) |
  | Codex f7 StartDeferredCompile one-sided + stale flag | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — universal `StartCompile(deferIntent bool)` for EVERY Compile (non-deferred explicitly resets a stale flag); every exit + apply-flow abort routes through ClearCompileReservation; the leftover "Compile argument" text deleted (§5-C) |
  | Codex f8 claimToken fences bookkeeping only | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — the daemon's work loop re-reads claimToken before EVERY netlink mutation (operator verbs take m.mu but not applySem); Deadline's consumer is the scheduler's wake computation; the impossible stale-Claim test deleted for the realizable pre-mutation form (§5-C debt execution, §9) |
  | Codex f9 recovery can't prove quiescence | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — `PrepareLinkCycle() error`: quiescence failure ABORTS the attempt (no DOWN/UP on live UMEM); multi-member BATCHING; phase-only retries; registered-only observed-clear predicate (raw Ready ignores armed; operator-unregister cancels via member-removal) (§5-C debt, §6, §9) |
  | Codex f10 fairness proof source-false | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — the honest 150s bound (the worst legal owner hold is a 120s control round trip inside the whole-pipeline apply hold); FIFO + cataloged worst hold; try-lock-or-skip manager calls with FIFO-ordered commit priority (§5-C debt execution, §9) |
  | Codex f11 env eviction + aggregate (= AGY f4 = SMR14-5) | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — Go DISCARDS suppression entries absent from the echoed reject-set (evicted → cache-drop → re-send → re-ack → re-inserted); aggregate ≤4 dispatches/5s via a dispatch-queue rate limiter (§5-C (i), §9 item 19) |
  | Codex f12 fabric debt aliasing + no conduit (= AGY f6) | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — the key covers the FULL sent FabricSnapshot payload (telemetry can't alias); clean guard rejections record readiness-relevant debts; `FabricSyncDebtOutstanding(projectionHash)` added to the HA controller (the interface change accepted) (§5-C (i), §6) |
  | Codex f13 test greens | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — §9 re-specified per finding (revision-assignment matrix replaces "mints", divergence-fired re-sync + transitions, universal reservation matrix, note CAS matrix, staged-B census, claimToken pre-mutation form, 150s fairness, recovery transaction proofs, eviction-drop + aggregate cap, full-payload debt + readiness query) |
  | Codex f14 pass-1 estimate | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — the budget is now a fake-netlink-call ceiling pinned by the daemon test (asserted call count + CI wall-clock), not an estimate (§5-C budget) |
  | Codex f15 budget unbounded | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — the residual unbounded classes (epoch zero fail-closed is bounded by the REQUIRED restart; equal-epoch stale snapshots die with publication_rev; failed note now has the note debt; the re-sync fires; the stale-defer stamp dies with universal StartCompile; the semaphore bound is honest; recovery quiesces are proven+batched) (§5-C budget, §11 Q7) |
  | AGY r14 f1 factory reset | CLOSED (narrowed by Codex f3: a clean zeroize stops xpfd and the helper never restores state.json) — the bootstrap epoch rebase covers the unclean-reset class: first apply with `acceptedCommitRevision == 0` carries `allow_epoch_rebase: true` (§5-C epoch contract) |
  | AGY r14 f2 echo corruption (= SMR14-2) | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — the latch echo is ASYMMETRIC clear-only; helper-true/Go-false is a drift Warn owned by the next full apply (§5-C (v)) |
  | AGY r14 f3 operator-disarmed recovery | CLOSED with Codex f9's refinement — the observed-clear predicate counts REGISTERED slots' bound+ready (raw Ready ignores armed); operator-UNREGISTERED slots cancel via the member-removal rule (§5-C debt, §9) |
  | AGY r14 f4-f7 | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — f4→Codex f11 row; f5→f5 row; f6→f12 row; f7 (Deadline consumer) → f8 row |
  | SMR r14 SMR14-1..6 | CLOSED v8.10, REOPENED r15 (codex-plan-r15.md f1 audit), RE-CLOSED v8.11 (r15 table below) — SMR14-1→f5 row; SMR14-2→AGY f2 row; SMR14-3 (drain-time re-read) → f6 row; SMR14-4→AGY f3 row; SMR14-5→f11 row; SMR14-6 (readiness RPC, Deadline, exit pairing) → f8/f12 rows + the ClearCompileReservation pairing (§5-C, §6) |

- **Round 15** (v8.10): ALL THREE DEMAND-REVISION — Codex (12
  BLOCKER + 2 MAJOR + 1 MINOR; f11 environment token is the
  ONE clean closure), AGY (4 BLOCKER + 3 MAJOR + 1 MINOR),
  SMR (2 BLOCKER + 3 MAJOR + 3 MINOR/NIT). Convergence:
  StartCompile's two-site reservation clobbers itself in one
  apply (Codex f8 = AGY f1 = SMR15-1); the publication_rev
  seed/startup path is unsafe (Codex f4 = AGY f4 = SMR15-2);
  the 150s bound is not the honest guarantee (Codex f11 =
  AGY f5 = SMR15-3); the per-mutation re-read blocks under
  applySem (Codex f9 = AGY f6 = SMR15-4); the re-sync misses
  NONZERO helper-behind (Codex f7 = AGY f2 = SMR15-5);
  quiesced attempts can leave workers stopped (Codex f10 =
  AGY f3 = SMR15-6); the fabric readiness hash is
  incoherent (Codex f12 = AGY f7 = SMR15-7); the note clear
  wedges against supersession (AGY f8 = SMR15-8). Codex's
  new depth: R1 has no rollout migration and no atomic
  transport (legacy active.json stays zero forever;
  feed/DHCP capture-before-lock can label stale A with B's
  revision) and Option-B paths can accept without a durable
  pair write (crash-before-retry reuse); R2 conflates the
  minted and observed high-waters (a same-commit lost
  completion is invisible), publication order is not config
  freshness (a stale send minted at send time passes), the
  legacy-zero texts contradict, and the rebase is an
  unverified Boolean any stale manager can assert; the note
  CAS's equality-repeat contradicts itself and Go discards
  refusal state on OK=false; the re-sync's execution
  bypasses the three-bucket precheck (a recovered deferred
  B without its MAC obligation — the terminal class); the
  compile reservation's ownerless Clear can't distinguish
  five outcomes; Claim can't deliver nextWake and has no
  validator method; a token-abandoned batch can leave all
  workers stopped; a mid-sleep macAndLinkRecovery member
  can be rebound wrong-MAC; and the fairness forms all lose
  FIFO position on retry (no finite guarantee under
  sustained legal arrivals).
- **Round-15 disposition table:**

  | r15 finding | v8.11 disposition |
  |---|---|
  | Codex f1 disposition accuracy | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — this table + the r14 rows re-audited; every v8.11 fold verified per-edit |
  | Codex f2 R1 durability (Option-B reuse) | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — a failed pair write leaves the revision UNCONFIRMED: `ActiveConfigRevision()` answers only confirmed values, riding the store's non-reusable high-water — crash-before-retry can never reuse (§5-C epoch contract) |
  | Codex f3 R1 rollout + transport | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — legacy `active.json` migration at `Load` (rev 1) + min-reader downgrade policy; `SetActiveRevision(rev)` under the same applySem hold transports the pair atomically; feed/DHCP queued reapplies re-read the pair under the semaphore (§5-C epoch contract) |
  | Codex f4 publication high-waters + seed | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — `m.mintedPublicationRev` (burned per send, one-mint-per-wire primitive) vs `m.observedPublicationRev` (moves only on acceptance-proving responses); the seed rides the SYNCHRONOUS startup ping (no mint/send before it; typed not-seeded-yet retries; LEGACY (generation, fib) seeded from the same echo; spawn-on-unavailable) (§5-C epoch contract) |
  | Codex f5 R2 fence + legacy-zero + rebase | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — the refusal is DUAL (publication not-strictly-greater OR commit_revision strictly-older; rollback promotes carry fresh revisions and pass); legacy-zero mode (all-zero accepted until the first epoch-carrying apply, then refused); the rebase requires the startup-ping handshake proof (§5-C epoch contract) |
  | Codex f6 note CAS coherence | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — three-way order (stored==new_rev idempotent → stored==expected_rev mutate → typed refusal carrying current state in the response Status, Go reading it on OK=false); current>expected abandoned, current<expected owned by the re-sync; the note echo advances accepted BEFORE divergence classification; the semantic hash excludes BOTH lineage fields (§5-C (iv)) |
  | Codex f7 re-sync owner + execution | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — fires in BOTH directions (helper-ahead OR nonzero helper-behind); executes via a REVISED `applyConfigLocked` (no-promotion, semaphore-held, INCLUDING the three-bucket precheck and MAC-debt creation) (§5-C UNKNOWN-outcome ownership) |
  | Codex f8 StartCompile clobber + outcomes (= AGY f1 = SMR15-1) | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — ONE reservation per apply (daemon sets `StartCompile(rethMACPending)` at the apply-flow entry; Compile never calls it); the reservation is TOKENED with `FinishCompileReservation(token, outcome)` (ACCEPTED / PRE-PUBLISH-FAILURE / UNKNOWN / POST-ACCEPTANCE-TAIL / OVERLAP — no ownerless double-clear); the leftover v8.8 defer-intent paragraph deleted (§5-C, §6) |
  | Codex f9 claim fence + nextWake (= AGY f6 = SMR15-4) | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — `ValidateClaimToken(token) (ok bool)` named try-lock method; contention/mismatch abandons WITH a balanced unwind (restore-rebind first, workers never left stopped), release, re-Claim; every Claim carries an explicit `nextWake` (empty included) (§5-C debt execution, §6) |
  | Codex f10 recovery abandon + wrong-MAC rebind (= AGY f3 = SMR15-6/9) | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — every quiesced attempt ends with a restore-rebind on EVERY outcome (RUNNING before the backoff); the batch's global rebind REVALIDATES every macAndLinkRecovery member's MAC before enabling its slots; link-return attempts fire on the link EVENT with the MAC program first (ms-scale exposure, not the 5s floor) (§5-C debt, §9) |
  | Codex f11 fairness FIFO loss (= AGY f5 = SMR15-3) | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — the timeout is DELETED: a no-timeout FIFO queue (position preserved; progress guaranteed by FIFO + bounded owner holds) + a 60s queued-state Warn (§5-C debt execution, §9) |
  | Codex f12 readiness incoherent (= AGY f7 = SMR15-7) | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — `FabricSyncStateOK() bool`: a no-argument manager-owned consistency answer (the manager owns both the map-commit and the helper-accept sides; no daemon-side hash can name the sent payload without a TOCTOU sample) (§5-C (i), §6) |
  | Codex f13 tests green | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — §9 identifiers swept (expected_commit_revision, note_commit_revision, status.commit_revision, pending/acceptedCommitRevision throughout) + the new chain tests (migration, Option-B confirm, transport race, dual refusal, legacy-zero, ping-seeded startup, note three-way, both-direction re-sync via applyConfigLocked, token outcomes, ValidateClaimToken unwind, no-timeout queue Warn, restore-on-abandon, batch MAC revalidation, no-arg readiness) |
  | Codex f14 pass-1 ceiling | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — exact assertions: ≤ 24 fake-netlink calls (12 link + 12 attr) with no per-retry amplification + ≤ 50 ms CI wall-clock (call-count and ordering pinned, not loaded-latency priced) (§5-C budget) |
  | Codex f15 budget unbounded | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — the residuals die with the rows above (migration covers revision-zero; Option-B confirmation covers reuse; the pair transport covers stale-labelling; the split high-waters cover same-commit loss; the ping-seed + spawn covers the surviving-helper guard; the proof-rebase covers the stale manager; the token covers reservation clobber; the no-timeout queue covers FIFO loss; the restore covers stopped workers; the revalidation covers wrong-MAC rebinds; the no-arg query covers readiness) (§5-C budget, §11 Q7) |
  | AGY r15 f1-f8 | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — folded with the matching rows (f1→f8, f2→f7, f3→f10, f4→f4, f5→f11, f6→f9, f7→f12, f8→the note's echo≥sent clear (§5-C (iv), §6)) |
  | SMR r15 SMR15-1..9 | CLOSED v8.11, REOPENED r16 (codex-plan-r16.md f1 audit), RE-CLOSED v8.12 (r16 table below) — SMR15-1→f8, SMR15-2→f4, SMR15-3→f11, SMR15-4→f9, SMR15-5→f7, SMR15-6→f10, SMR15-7→f12, SMR15-8→note clear, SMR15-9 (batch arrival + fsatomic checklist) → f10 row + the §9 implementation-checklist note |

- **Round 16** (v8.11): ALL THREE DEMAND-REVISION — Codex (13
  BLOCKER + 2 MAJOR + 1 MINOR), AGY (4 BLOCKER + 3 MAJOR +
  1 MINOR + 1 NIT), SMR (1 MAJOR + 5 MINOR/NIT). Convergence:
  the Option-B fallback aliases distinct configs onto one
  revision (Codex f2 = AGY f1 — B installs in-memory while
  ActiveConfigRevision() answers last-confirmed A; the helper
  accepts B labelled A and NO divergence ever fires); the
  downward rebase is either unsafe or deadlocked (Codex f6 =
  AGY f2 — socket ownership is no proof (connection-per-
  request), and a downward rebase opens a rollback window);
  the Compile canary panics on direct HA-sync/test paths
  (Codex f8/f10 = AGY f3); the batch-arrival wrong-MAC
  rebind (Codex f12 = AGY f4 = SMR16-1); the not-seeded-yet
  abort drops the boot apply with no guaranteed re-trigger
  (Codex f5 = AGY f5); the fairness forms contradict each
  other and lose FIFO position (Codex f13 = AGY f8); the
  fabric readiness answer has no causal protocol (Codex f14
  = AGY f7). Codex-only depth: the migration has no failure
  policy and no allocator ordering (legacy migration +
  expired-confirm recovery can both assign revision 1); the
  transport is an unbound scalar (Compile builds outside
  m.mu, overlapping Compiles are reachable, direct CLI
  Compile is public); the R2 seed happens AFTER the
  snapshot build stamps Generation/FIB (the surviving
  helper's first snapshot arrives pre-stamped with reset
  legacy values the rollback guard refuses); freshly minted
  stale same-commit content escapes both fences (T1 builds
  outside m.mu, T2 publishes, T1 sends with a fresh mint —
  commit equality and fresh publication both pass); the
  note CAS has no typed wire error and §6 contradicts the
  main text on abandonment; the reservation token has an
  ABA resurrection and no PENDING-XSK outcome; validation
  and quiescence are not atomic (an operator can bump
  between them), stop_workers timeout is
  quiesced-or-not UNKNOWN, and a failed restore leaves
  every worker stopped with no owner; the §6 inventory and
  the tests still carry the stale forms (nextWake-less
  Claim, no validator, 150s fairness, first-apply rebase,
  wrong-MAC binding, precheck-bypassing re-sync).
- **Round-16 disposition table:**

  | r16 finding | v8.12 disposition |
  |---|---|
  | Codex f1 disposition accuracy | CLOSED — this table + the r15 rows re-audited; every v8.12 fold verified per-edit |
  | Codex f2 Option-B aliasing (= AGY f1) | CLOSED — the EXPOSURE GATE: a promotion whose pair write has not durably landed is NOT EXPOSED (accepted control-plane, pending-durable with retry; the dataplane keeps the LAST DURABLE config until writeTreeMarked lands) — B is never transported under A's revision, no observer needed (§5-C epoch contract) |
  | Codex f3 migration policy + allocator | CLOSED — the migration write retries with the dataplane in the legacy-zero gate; the allocator is `max(active revision, durable high-water) + 1` seeded BEFORE Load's expired-confirm recovery; the envelope capability rises to 2 (old writers refuse rather than erase) (§5-C epoch contract) |
  | Codex f4 transport not atomic | CLOSED — the pair travels as an EXPLICIT ARGUMENT (`ConfigSink.ApplyConfig(ctx, cfg, commitRevision)`) sourced from ONE `ActivePair()` getter (s.mu-atomic); feed/DHCP queued reapplies REPLACE the captured config entirely under applySem; direct CLI passes revision 0 explicitly (§5-C epoch contract, §6) |
  | Codex f5 seed after build (= AGY f5 area) | CLOSED — the synchronous ping runs at the TOP of every Compile BEFORE the snapshot build stamps Generation/FIB; not-seeded-yet errors route to the standard publish-retry machinery (AGY f5's re-trigger) (§5-C epoch contract) |
  | Codex f6 rebase proof + rollback window (= AGY f2) | CLOSED — the downward rebase is DELETED: the manager RESPAWNS the helper on downward startup divergence (stored.commit_revision > ActiveConfigRevision() at startup) — the zeroed stored pair needs no proof (§5-C epoch contract) |
  | Codex f7 stale same-commit content | CLOSED — the common send primitive's `snapshot_token` (monotonic, minted at BUILD inside m.mu) + the build-current validation at send time (T1's stale snapshot abandoned Go-side; strictly-older tokens refused helper-side) (§5-C epoch contract) |
  | Codex f8 note typed wire + abandonment contradiction | CLOSED — `ControlResponse.error_code: string` (additive; the note CAS refusal and the machinery's typed errors classify; existing errors keep ""); current<expected is OWNED BY THE RE-SYNC (§6 harmonized with §5-C); the note echo advances accepted BEFORE divergence classification in ONE common lineage-observation routine (§5-C (iv), §6) |
  | Codex f9 re-sync test permits bypass | CLOSED — the test asserts the drain invokes the revised `applyConfigLocked` (precheck + MAC-debt creation asserted; a bare d.dp.ApplyConfig forbidden) (§9 item 13) |
  | Codex f10 token ABA + outcomes + CLI (= AGY f3) | CLOSED — the PREDECESSOR-CHAINED reservation (Finish only at the head; restores apply the head's OWN prior); PENDING-XSK STAGED + PRE-SEND outcomes; the Compile canary becomes assert-or-default (direct HA-sync/test/CLI paths default to false, never panic) (§5-C, §6) |
  | Codex f11 quiescence not atomic + restore owner (= AGY f6 area) | CLOSED — `PrepareLinkCycleChecked(claimToken)` (validation under the SAME m.mu acquisition as the quiescence start); TRI-STATE verdict (Valid/RetryLater (contended — keep, no unwind)/Stale (abandon WITH unwind)); the restore is TYPED with a RESTORE DEBT + per-mode policies; the finalizer restores UNCONDITIONALLY after every possibly-landed quiesce (stop_workers timeout-but-landed included) (§5-C debt execution, §6) |
  | Codex f12 batch wrong-MAC rebind (= AGY f4 = SMR16-1) | CLOSED — REPAIR-BEFORE-REBIND with a renewed settle (Prepare → validate-and-program ALL due members including arrivals absorbed at the re-Claim → settle → rebind); the selective-hold alternative rejected; `programRethMAC` never inside a rebind (double-cycle); any MAC work after the settle requires a renewed settle; the old wrong-MAC binding test corrected (§5-C debt, §9) |
  | Codex f13 fairness contradiction (= AGY f8) | CLOSED — the NO-TIMEOUT FIFO queue (position preserved; eventual progress by FIFO + proven-terminating owners) with the 60s queued Warn stopping/resetting on acquisition and the acquire-BEFORE-Claim ordering normative; the 10/30s/150s texts and tests harmonized (§5-C debt execution, §5-C budget, §9) |
  | Codex f14 readiness not causal (= AGY f7) | CLOSED — the `map_generation` causal protocol (minted atomically with each BPF mutation; echoed as `accepted_fabric_map_generation`; FabricSyncStateOK() true only when accepted == current AND no debt AND a coherence proof exists since startup (fresh-boot-no-proof and old-helper-zero both FALSE); the fabric-send order spans full snapshots and update_fabrics via the generation; the projection identity corrected to (name, parent Linux name, parent ifindex, effective queue count)) (§5-C (i), §6) |
  | Codex f15 tests green | CLOSED — §9 gains the chain tests (migration failure/retry + allocator ordering + capability-2 refusal, Option-B exposure gate, paired transport per path, ping-first Compile, respawn-on-divergence, freshness-token stale send, typed error_code, token ABA + outcomes + CLI default, PrepareLinkCycleChecked tri-state + stop_workers timeout, typed restore + restore debt, repair-before-rebind + post-settle rule, no-timeout queue + Warn lifecycle, causal readiness) + the stale forms swept |
  | Codex f16 pass-1 + budget labels | CLOSED — the fixture is explicitly fixture-scoped (≤24 calls, ≤50ms CI — call count and ordering, linear in RETH size); the env-recovery budget now reads "≤1 poll + RPC + manager-lock delay (≤~67s worst legal hold)"; the ≈19s/≈70s are labeled baselines, not upper bounds (§5-C budget) |
  | Codex f17 severity-High residuals | CLOSED — the residuals die with the rows above (the exposure gate kills the aliasing; the dedicated high-water kills reuse; the respawn kills the unauthenticated rebase; the freshness token kills stale same-commit publishes; the predecessor chain kills the ABA; the unconditional typed restore kills the stopped-workers ownerless case; repair-before-rebind kills the wrong-MAC rebind; the causal map-generation kills the false readiness) (§5-C budget, §11 Q7) |
  | AGY r16 f1-f9 | CLOSED — folded with the matching rows (f1→f2, f2→f6, f3→f10, f4→f12, f5→f5, f6→f11, f7→f14, f8→f13, f9 (evidence wishes) informational) |
  | SMR r16 SMR16-1..6 | CLOSED — SMR16-1→f12 row (the absorption/repair-before-rebind form is SMR16-1's own correction); SMR16-2 (dedicated high-water) → f2/f3 rows; SMR16-3 (migration-failure posture, note-echo ordering, UNKNOWN/PRE-PUBLISH classification) → f3/f8/f10 rows; SMR16-4 (unwind → #5134) → f11 row; SMR16-5 (release-on-skip, Warn edge reset) → f11/f13 rows; SMR16-6 (OK polarity) → f14 row |

- **Round 17** (v8.12): ALL THREE DEMAND-REVISION — Codex (13
  BLOCKER + 1 MAJOR + 1 MINOR), AGY (4 BLOCKER + 3 MAJOR +
  1 MINOR + 1 NIT), SMR (3 BLOCKER + 3 MAJOR + 5 MINOR).
  Heavy three-way convergence on the v8.12 mechanics: the
  exposure gate has no re-exposure owner (Codex f2 = AGY f1
  = SMR17-1 — persistRetryLoop is observer-free; a transient
  pair-write failure silently defers a committed config's
  dataplane exposure indefinitely, and the HA standby's
  applied digest stamps B while its dataplane runs A); the
  freshness token validates only the (config, revision)
  pair (Codex f5 = AGY f2 = SMR17-2 — same-commit reshapes
  share the pair; stale content with a newer token lands);
  the live-MAC re-apply's ActivePair() re-read admits an
  interposed promotion published without its precheck
  (Codex f3 = AGY f4 = SMR17-3 — and the persistence
  transition itself interposes, not just an operator
  commit); map_generation orders without coherence (Codex
  f12 = AGY f3 = SMR17-4 — no seed, no single
  sample/mint/payload transaction, zero-ambiguity); the
  predecessor chain still reproduces the ABA (Codex f7 —
  non-head outcomes discarded) + the PENDING-XSK leak
  (AGY f5 = SMR17-5); the zero-event boot retry has no
  owner (Codex f4); the restore debt is not executable
  (Codex f9 — #5134 self-clears; respawn needs a paired
  replay); the late-arrival attempt has no event source
  (Codex f10 = AGY f7 = SMR17-7); the FIFO proof is false
  (Codex f11 — stopLocked's unbounded `<-done`); the
  checked-quiescence API is split-brained (Codex f8 =
  SMR17-9); the tests/disposition overclaim (Codex f1/f13
  = SMR17-6); the Warn lifecycle is inconsistent (Codex
  f15 = AGY f8 = SMR17-8). Codex f12 answered AGY f3's
  fresh-boot trigger (startClusterComms' population
  goroutines, daemon_ha_sync.go:1223-1242).
- **Round-17 disposition table:**

  | r17 finding | v8.13 disposition |
  |---|---|
  | Codex f1 disposition accuracy | CLOSED — this table + the r16 rows re-audited; every v8.13 fold verified per-edit; the r16 count corrected to 14 tagged blockers |
  | Codex f2 exposure gate no state/owner (= AGY f1 = SMR17-1) | CLOSED — the ACCEPTED/EXPOSED pair split + the DURABILITY-EXPOSURE DEBT: the gate's locus is the daemon's applyConfigLocked consulting the store's pending-durable indicator (skip the apply); the store's persist-retry success wakes the debt (daemon-polled getter, no new call direction); the drain re-reads `ActivePair()` (latest-wins) and drives the REVISED applyConfigLocked (full precheck); HA applied markers key to the EXPOSED pair (a gated apply stamps nothing); the migration retry rides the same debt; the commit reports success WITH the pending-durable warning (§5-C epoch contract, §6, §9) |
  | Codex f3 transport authorities + live-MAC leg (= AGY f4 = SMR17-3) | CLOSED — the stale `SetActiveRevision` reference becomes `ActivePair()`; `m.pendingCommitRevision`/`ApplyResult` source from the same read; `applyConfigLocked(ctx, cfg, commitRevision)` defined; boot reads the pair UNDER the wrapper's hold; the live-MAC second leg REUSES THE OUTER TRANSACTION'S ORIGINAL PAIR (an interposed promotion is never re-read mid-flow; B's durability notification queues behind the outer transaction) (§5-C epoch contract, §6, §9) |
  | Codex f4 zero-event boot retry owner | CLOSED — the not-seeded abort records a daemon-side BOOT-APPLY DEBT (single-flight, short cadence, daemon apply-scheduler-owned); the seeded state is incarnation-scoped; the ping's deadline class pinned (3s base) (§5-C epoch contract, §6, §9) |
  | Codex f5 freshness linearization (= AGY f2 = SMR17-2) | CLOSED — the BUILD SEQUENCE: a cheap input-capture section under m.mu snapshots the build inputs (config pair + feed/overlay refs) and mints `buildSeq` (== `snapshot_token`); the send primitive gains LOCKED/UNLOCKED entries (auxiliary publishers already under m.mu never self-deadlock) and validates `buildSeq == m.latestBuildSeq` AND pair-current at send; the helper refuses strictly-older tokens; the semantic hash EXCLUDES the token (§5-C epoch contract, §6, §9) |
  | Codex f6 error_code census | CLOSED — §6 carries `ControlResponse.error_code` + the canary; the producers pinned per code (stale_completion/diverged_fabric/epoch_rollback/publication_rollback/note_cas_refusal (named dispatcher entry)/stale_snapshot_token; `not_seeded` is MANAGER-LOCAL, never on the wire); the consumer contract: typed responses survive the OK=false discard, invoke the common lineage observer, select the outcome; UNTYPED failures keep today's handling (status NOT copied) (§5-C (iv), §6, §9) |
  | Codex f7 chain ABA lives + API + PENDING-XSK (= AGY f5 = SMR17-5) | CLOSED — non-head Finish outcomes are RECORDED on their nodes; the head's Finish applies its own outcome AND replays completed predecessors' recorded outcomes in order; §6's `StartCompile` returns the token; the manager state lists the chain; panic outcomes classify by phase; PENDING-XSK STAGED stores its token, a newer StartCompile FINALIZES an orphaned open predecessor as OVERLAP, helper death finalizes UNKNOWN (§5-C, §6, §9) |
  | Codex f8 checked-quiescence split API (= SMR17-9) | CLOSED — §6 replaces the split API with the merged `PrepareLinkCycleChecked(claimToken)`; the hold span pinned (try-acquire → validate → quiescence RPCs under the hold → RELEASE before the MAC phase → per-mutation try-lock re-reads resume); RetryLater exists only pre-mutation (post-quiescence skips route through the restore finalizer) (§5-C debt execution, §6, §9) |
  | Codex f9 restore debt not executable | CLOSED — a rebind error records the RESTORE DEBT itself (NOT #5134 — it self-clears on non-deferred snapshots); missing-process → respawn FOLLOWED BY a daemon-owned revised full apply (paired replay from `ActivePair()`); ctrl error → restore-debt retry (5/10/30/60s + edge Warn, no terminal cap); status error → the poll reconciles; §6 gains the restore-debt state + `NotifyLinkCycle`'s typed result (§5-C debt execution, §6, §9) |
  | Codex f10 late arrival no event source (= AGY f7 = SMR17-7) | CLOSED — the event-fired attempt is DELETED (no passive link-event machinery exists); the late member rides absorption at the re-Claim or the debt's normal backoff retry; the batch's rebind binding it with the factory MAC is ACCEPTED and stated honestly (partial-path blackhole, bounded below by retry cadence + FIFO queueing; the ≤ ~1s claim deleted) (§5-C debt, §9) |
  | Codex f11 FIFO proof false (stopLocked) | CLOSED — the contract restated: progress guaranteed for all userspace-bounded owners; the kernel-unreapable/D-state class is unbounded by ANY userspace design — the 60s Warn + the systemd outer bound (TimeoutStopSec + Restart) is the documented escape (§5-C debt execution, §11 Q7) |
  | Codex f12 map_generation coherence (= AGY f3 = SMR17-4) | CLOSED — ONE m.mu section samples the map view, mints, and builds the payload FROM THE SAME SAMPLE; the four call sites + direct key writes route through the manager's wrapper; the legacy-adapter bypass enumerated (pre-upgrade/test-only); `map_generation` SEEDS from the startup ping echo; a protocol CAPABILITY bit resolves new-helper-zero vs old-helper-zero; full snapshots advance accepted even when content is equal (ordering pinned); the first-proof producer pinned (startClusterComms' population goroutines); §6 + canaries gain both fields; the debt's clear rule moves from payload-hash to generation (§5-C (i), §6, §9) |
  | Codex f13 tests green (= SMR17-6) | CLOSED — §9 gains the missing chain tests with the false-green shapes answered per test (see the §9 additions); the canary list gains snapshot_token, error_code, map_generation, accepted_fabric_map_generation |
  | Codex f14 residuals unbounded | CLOSED — the residuals die with the rows above (the exposure debt owns durable-B exposure + HA markers; the boot-apply debt owns not_seeded; the outer-pair rule owns the live-MAC leg; the recorded-outcome chain owns inFlight; the executable restore debt owns rebind/respawn/ctrl failures; the honest FIFO + late-arrival texts own the unbounded classes as documented postures; the single-transaction generation owns readiness) (§5-C budget, §11 Q7) |
  | Codex f15 Warn lifecycle (= AGY f8 = SMR17-8) | CLOSED — the Warn keys on the work item's FIRST-QUEUE timestamp with PERIODIC 60s reporting while queued; a RetryLater re-queue continues the episode (§5-C debt execution, §9) |
  | AGY r17 f1-f9 | CLOSED — folded with the matching rows (f1→Codex f2, f2→f5, f3→f12, f4→f3, f5→f7, f6→SMR17-10's pin (3s base deadline, in the budget text), f7→f10, f8→f15, f9 (evidence wishes) informational — f1/f4 were independently source-verified by SMR) |
  | SMR r17 SMR17-1..11 | CLOSED — SMR17-1→Codex f2 row; SMR17-2→f5 row; SMR17-3→f3 row; SMR17-4→f12 row; SMR17-5→f7 row; SMR17-6→f13 row; SMR17-7→f10 row; SMR17-8→f15 row; SMR17-9→f8 row; SMR17-10→f4 row (the ping deadline pin); SMR17-11 (edit hygiene) → the splice/duplication fixes folded throughout |

### Round-1 detail log (kept for the record)

- Claude SMR r1: DEMAND-REVISION — SMR-1 B-rejection overstated, SMR-2
  missing observability-only Go leg, SMR-3 close Q2/Q5 from source,
  SMR-4 document identity semantics. Folded (v2).
- AGY r1: DEMAND-REVISION — finding 1 (MAJOR): `had_existing` /
  `last_change` interaction strands an interface transitioning
  `ifindex<=0 → >0`. Folded as edge case E2. Finding 2 (MINOR, zero
  volatile on carry): adopted in v3's R3 (control-only carry).
  Finding 3 (NIT, Go-side gate test): folded into §9.
- Codex r1: DEMAND-REVISION — BLOCKER 1 (the real deferred-activation
  path enters a plan-changing apply with `forwarding_armed=true`
  WITHOUT disarming; arming new slots there combines with the
  slot-keyed `refresh_bindings` stale-Ready alias to open ctrl with
  stale-identity rows). BLOCKER 2 (`(interface, queue_id)` is unique
  per plan but is not physical identity — real XSK identity is
  (ifindex, queue)). MAJOR 3 (E2 concurrence), MAJOR 4 (whole-record
  carry conflates control with slot-owned telemetry), MAJOR 5
  (queue-scoped override lifetime), MAJOR 6 (B rejection overstated —
  the deferred design forces an explicit activation step), MAJOR 7
  (unsafe-green tests), MINOR 8 (trigger/outage overstated; release
  note must require helper restart).

## 2. Issue framing

A full `apply_snapshot` that changes the AF_XDP binding plan while the
helper is armed leaves every newly-created binding slot `registered=true`
but `armed=false`. The helper then reports `enabled=false` (the enabled
gate requires EVERY binding registered+armed), the Go manager's
shim-control gate keeps `userspace_ctrl.Enabled=0`, and transit traffic
stays fail-closed — for the WHOLE dataplane, not just the new slots.
Go's desired-state reconciliation compares only the GLOBAL
`forwarding_armed` bit, sees it equal to the desired value, and returns
without acting, so nothing ever arms the new slots. The dataplane stays
down until an operator manually toggles forwarding state or restarts the
helper. Config-synced HA peers take the same code path and land in the
same state, so failover does not recover.

The issue asks us to decide (i) who owns the per-binding `armed` state —
global fan-out vs per-binding vs planner — and (ii) the correct
convergence model — slot-stable identity vs numeric slot;
initialize-from-global vs explicit per-binding reconcile — and to ship a
fix with an expansion-while-armed regression test.

## 3. Honest scope/value framing

This is an availability bug with a total-transit-outage blast radius,
not a performance issue. The win at absolute scale (corrected per Codex
r1 MINOR 8 — v1 overstated both the trigger frequency and the "zero
outage" claim):

- **Outage avoided per trigger:** indefinite (until human intervention)
  → the bounded interruption of a normal plan-changing apply. The fix
  does NOT make the outage zero: a plan-changing Compile already
  programs bootstrap ctrl disabled and clears binding rows
  (manager_compile.go:319, maps_sync.go:121) and the full reconcile
  tears down + recreates workers (reconcile/mod.rs:330) — that bounded
  replan interruption exists today and stays. What dies is the
  INDEFINITE tail that required an operator to notice and act.
- **Trigger frequency in production (precise):** commits whose new plan
  has MORE numeric slots than the old one — slot count is
  `min(rx_i) × candidate_count` (planning.rs:495), so: adding a
  candidate without lowering the min queue count; raising the min
  (removing the lowest-queue candidate, or `ethtool -L` raising the
  smallest channel count when the snapshot carries `rx_queues == 0` —
  the sysfs-resolved count is hashed per #3007, so the replan fires on
  an unrelated later commit and the outage correlates with the WRONG
  commit in post-incident analysis). Contractions, pure reorders, and
  replacements change the plan key WITHOUT new numeric slots and do not
  trigger it. Plan-key inputs (`update_snapshot_binding_plan_key`):
  candidate set, `vlan_id`/`parent_linux_name`/`parent_ifindex`,
  effective rx_queues, fabric parents, workers/ring/shared_umem.
  - **deferred-activation amplifier (v3, Codex r1 BLOCKER 1):** a
    commit that both changes the plan AND pends a RETH MAC
    (reth membership change on a healthy armed node) strands the new
    slots through the deferred bring-up too — same indefinite tail via
    a second door (the v4 marker lifecycle closes all three completion
    shapes of it: same-plan re-apply, full-leg re-apply, rebind).
  - **amplifier on the roadmap:** #6702/#6681 change the layout from
    `min(rx_i) × N` to `Σ min(rx_i, 16)`, which makes plan-shape changes
    (and therefore new-slot creation) far more common. Both issues were
    read in full; their scope is capacity/UMEM/heartbeat/worker
    consequences of the count change — neither touches arm
    initialization. No collision; this issue must land its own fix and
    not wait for them.
- **HA multiplier:** config sync replays the same commit on both nodes;
  both helpers strand the same new slots; an RG failover moves the
  outage rather than clearing it.
- **Recovery cost today:** operator must know to run a forwarding
  arm/disarm toggle (or restart the helper). Nothing in `show` output
  says "slot N is registered but unarmed because of a plan expansion" —
  the failure presents as a total transit blackout after a routine
  commit.

If reviewers conclude the fix's churn exceeds the value — e.g. that the
trigger set is too rare to justify touching the planner — PLAN-KILL is
an acceptable verdict. Our assessment going in: the trigger set is
"any interface-geometry commit on a live box", the failure mode is a
silent total outage with no self-heal, and the primary fix is ~one
function plus tests, so the value/churn ratio strongly favors fixing.

## 4. What's already shipped / partially batched

Verified mechanism chain (every link read at base `ad9591177`):

1. **Full-apply replan** — `userspace-dp/src/server/handlers/snapshot.rs:344-350`:
   the non-same-plan leg replaces `guard.snapshot`, calls
   `replan_queues(guard.snapshot.as_ref(), guard.status.workers, &existing_bindings)`,
   and assigns the result to `guard.status.bindings`. The apply path
   never touches `guard.status.forwarding_armed`.
2. **Numeric-slot state carry + default-false armed** —
   `userspace-dp/src/server/helpers/planning.rs:482-531`
   (`replan_bindings_from_candidates`): prior state is carried by
   NUMERIC slot (`existing_by_slot.remove(&slot)`). A slot with no
   predecessor (`had_existing == false`) and a valid ifindex gets
   `registered = true`; `armed` stays at the `BindingStatus::default()`
   value `false`. Slots WITH a predecessor keep their full prior record
   — including `armed=true` — even when the plan reshuffle means the
   slot now addresses a DIFFERENT (interface, queue) pair (slot index =
   `queue_id * n_interfaces + iface_idx`; inserting/removing a candidate
   shifts every later slot).
3. **Enabled gate** — `userspace-dp/src/server/helpers/status.rs:274-281`:
   `enabled = forwarding_armed && forwarding_supported &&
   !bindings.is_empty() && all(registered && armed)`. One unarmed slot
   forces `enabled=false` for the whole process.
4. **Go ctrl gate** — `pkg/dataplane/userspace/maps_sync.go:391-487`:
   `status.Enabled == false` skips the entire enable block, leaving
   `ctrl.Enabled = 0`; the shim then holds transit fail-closed. Two
   inner gates agree with the same predicate even if `enabled` were
   true: `probeBindingsReady` (maps_sync.go:438-450) requires every
   registered binding armed, and the per-row shim admission
   `bindingForwardingLive` (maps_sync.go:97-99, consumed at :695/:751)
   requires `Registered && Armed && Ready && !workerDead` before the
   (ifindex, queue) row is marked READY in `userspace_bindings`.
5. **No convergence** — `syncDesiredForwardingStateLocked`
   (`pkg/dataplane/userspace/manager_ha.go:601-607`) compares only
   `m.lastStatus.ForwardingArmed == desired` and returns nil. Its three
   call sites (post-compile `manager_compile.go:408`, HA path
   `manager_ha.go:66`, ~1s status poll `process_status.go:240`) all
   inherit the blind spot. Per-slot verbs exist
   (`SetBindingState`/`SetQueueState`, `manager_status.go:132-180`) but
   are operator-only (gRPC diag + CLI `request chassis …`).
6. **The coordinator does NOT consume `armed`** — worker bring-up
   filters on `registered && ifindex > 0`
   (`afxdp/coordinator/reconcile/bringup.rs:274`); `bound`,
   `xsk_registered`, `ready` are re-derived from live worker state by
   `refresh_bindings` during reconcile (#2794 tail). So after the
   expansion apply's own reconcile, the new slots' XSKs really are
   bound and forwarding-capable — ONLY the stale `armed=false` bit (and
   its three downstream gates) keeps traffic off them, and the
   all-or-nothing `enabled` gate extends that to the whole dataplane.
7. **The deferred-activation door (v3, Codex r1 BLOCKER 1 —
   verified):** the daemon pends `DeferWorkers` for RETH MAC
   programming WITHOUT disarming (daemon_apply_dataplane.go:45-71 →
   manager_compile.go:330-331; the pre-publish disarm at
   manager_ha.go:568-599 fires only for unsupported configs). A healthy
   armed helper can therefore take a plan-changing DEFERRED apply:
   replan runs (new slots registered, unarmed), reconcile is SKIPPED
   (snapshot.rs:351-354), and `refresh_status` →
   `afxdp.refresh_bindings` (status.rs:23) maps still-live OLD workers
   into the NEW binding vector by NUMERIC SLOT
   (refresh_bindings.rs:25-32). Two consequences: (i) master strands
   the deferred new slots the same way (armed=false, later bound by the
   bring-up's reconcile, never converged — same indefinite tail); (ii)
   any fix that arms new slots on a no-reconcile apply would combine
   with the slot-keyed refresh to report stale-identity `ready`, open
   ctrl, and steer the new (ifindex, queue) onto an XSK bound to a
   DIFFERENT physical binding — worse than the outage. **The deferred
   CONTRACTION shape (Codex r2 BLOCKER 5) is already live on master
   through door (ii):** `[a,b,c] → [b,c]` deferred introduces no new
   slot, so every survivor stays armed, `enabled=true`, ctrl stays
   open, and the slot-keyed refresh attaches shifted stale `ready`
   state to the new identities — today's only mitigation is that
   deferring commits are rare. Any credible fix must gate the WHOLE
   vector, not just new slots (§5-C S3).
8. **The completion path is `rebind`, not `apply_snapshot` (v4, Codex
   r2 BLOCKER 3 — verified):** after MAC programming cycles the link,
   `NotifyLinkCycle` fires and Go sends `ControlRequest{Type:
   "rebind"}` (process_linkcycle.go:219; the daemon clears
   `m.deferWorkers` before it). The rebind handler reconciles and
   refreshes but never touches `armed` (rebind.rs:42-76). Any
   activation model scoped to `apply_snapshot` legs (v3's R2) misses
   the normal completion path entirely — the convergence must live
   inside `reconcile_status_bindings`, which rebind shares
   (rebind.rs:64).
9. **Partial survival on failed bring-up (v4, Codex r2 BLOCKER 2 —
   verified):** a post-teardown `WorkerSpawn` failure returns WITHOUT
   `stop_inner` — already-launched workers KEEP their records
   (bringup.rs:172-183) — and the reconcile refreshes actual partial
   state before returning `Err` (reconcile/mod.rs:391). An
  arm-at-replan model therefore reports `enabled=true` against a
   partially-dead worker set (the #869 gate ignores `ready`/`bound`),
   and Go can publish READY rows for the surviving subset. Activation
   must follow reconcile SUCCESS (or be reverted on failure) — §5-C S4.
10. **Volatile state ownership (v3, Codex r1 MAJOR 4 — verified):**
    every successful reconcile clears per-binding volatile fields
    (`reset_binding_counters`, reconcile/reset.rs:9-15) and
    `refresh_bindings` repopulates them from live workers by slot. So
    counters/`last_error`/`ready` carried across a replan are dead
    weight on the normal path and alias-prone in the defer window — the
    carry must move CONTROL fields only (§5-C R3).

Adjacent shipped work the plan must compose with:

- **#1666 ready-gate** (`bindingForwardingLive`): per-row shim steering
  already requires `Ready` in addition to `Registered && Armed`, so
  arming a slot whose XSK is still bootstrapping cannot get traffic
  steered to a dead queue. This is what makes "initialize new slots
  armed from the global state" as safe as the boot-time arm fan-out
  (which also arms not-yet-ready bindings).
- **#869 enabled-gate design note** (status.rs:267-273): `enabled`
  deliberately does NOT require `ready` — that deadlock-avoidance is
  preserved by every option below.
- **#5171/#5134 deferred-worker bring-up**: a `defer_workers=true`
  apply replans with `forwarding_armed == false`, so new slots
  initializing armed from the global state get `false` — matching the
  defer contract; the later bring-up arms everything via the
  `set_forwarding_state` fan-out. The bug only bites when the plan
  changes while the global bit is ALREADY true.
- **#6163/#6165/#5648 required-protocol arm gate**: any arm-direction
  convergence from Go must keep honoring
  `ensureRequiredSnapshotProtocolLocked`. (Only relevant to option B.)
- **#6702 / #6681 (open, unstarted)**: per-interface queue planner.
  Collision check done — they own binding-COUNT consequences
  (UMEM/heartbeat/workers/4096-cap), NOT arm initialization. Our
  identity key (§5, option C) must remain meaningful under their
  per-interface queue extents; `(interface, queue_id)` is
  layout-shape-independent, so it does.
- **State file is write-only** (`helpers/persistence.rs`): the helper
  never restores bindings at startup (lifecycle builds an empty
  `ProcessStatus`), so no persisted-state migration is needed.

## 5. Concrete design — with Multiple Path Options

The design space forks on the two questions the issue poses. Three
viable paths:

### Option A — planner initializes new slots from the live global armed state (minimal, Rust-only)

Thread the helper's current `forwarding_armed` into the planner and use
it as the default for genuinely new slots:

```rust
// planning.rs — signature change (one production caller, snapshot.rs:345)
pub(crate) fn replan_queues(
    snapshot: Option<&ConfigSnapshot>,
    workers: usize,
    existing: &[BindingStatus],
    forwarding_armed: bool,          // NEW: guard.status.forwarding_armed
) -> Vec<BindingStatus>

// replan_bindings_from_candidates — the !had_existing leg becomes:
} else if !had_existing {
    binding.registered = true;
    binding.armed = forwarding_armed; // NEW: was struct-default false
}
```

- **Ownership model:** the global bit (pushed by Go via
  `set_forwarding_state`) remains the single owner of the arm DEFAULT;
  the planner stops inventing a contradictory default.
- **Why the APPLIED global, not Go's desired:** at replan time the
  helper's `forwarding_armed` is exactly what a later
  `set_bindings_forwarding_armed` fan-out would write. Go's
  `disarmBeforeUnsupportedPublishLocked` already ran before the publish,
  so the applied value is never ahead of Go's intent.
- **What it fixes:** the indefinite whole-dataplane disable. After the
  apply's own `reconcile_status_bindings` binds the new XSKs, the next
  `refresh_status` recomputes `enabled=true` and the ctrl gate opens on
  the normal poll — no operator action.
- **Verdict (v4):** RECORDED FOR HISTORY, not a live retreat. A arms
  new slots at replan time, which round 2 showed is the core defect:
  on the deferred path the slots' XSKs never bind (Codex r1 BLOCKER 1),
  and on a failed non-deferred reconcile A reports `enabled=true`
  against a partially-dead worker set (Codex r2 BLOCKER 2). Patching A
  with defer-awareness + activation convergence + the E2 widening +
  the marker lifecycle converges it INTO option C except for keeping
  numeric-slot carry — at which point the only remaining difference is
  the wrong-identity inheritance below, which C also fixes.
- **What it does NOT fix:** numeric-slot carry. A plan reshuffle still
  inherits a predecessor's control record (armed/registered) onto a
  different (interface, queue) identity. The armed-bit consequence is
  mostly masked (when globally armed every carried slot reads
  `armed=true`, which is also what the S5 init would write), but an
  operator per-slot diagnostic disarm (`set_binding_state armed=false`)
  migrates to the WRONG interface across a reshuffle. Pre-existing
  defect, same locus.
- **Size:** ~10 lines + tests (but converges into C once made safe).

### Option B — Go desired-state reconciliation gains per-binding armed convergence (Go-only)

Extend `syncDesiredForwardingStateLocked` so that when the global bit
already equals desired, it additionally scans `m.lastStatus.Bindings`
for `Registered && Ifindex > 0 && !Armed` and converges the drifted
slots (per-slot `set_binding_state(registered=true, armed=true)` — NOT
`set_forwarding_state`, whose helper handler unconditionally runs a full
worker teardown+rebind even for a no-op re-assert, `forwarding.rs:43-58`).

- **Ownership model:** Go becomes the convergence owner for per-binding
  armed, treating the helper's bits as eventually-consistent state to be
  driven to the global value.
- **What is technically possible (corrected in v2 — SMR r1 SMR-1):** the
  manager is the ONLY client of the helper control socket — every
  per-slot request transits `Manager.SetBindingState`/`SetQueueState`
  (`manager_status.go:132-180`, reached via `LegacyDataPlaneAdapter` →
  `server_diag_system_action.go:430-455` / `cli_request_chassis.go:167-176`)
  — so a manager-side override registry (converge only slots the manager
  itself did NOT disarm; clear on global re-arm, plan change, daemon
  restart) IS implementable without a wire-protocol change. v1's "cannot
  distinguish" claim was wrong; the honest rejection is the three points
  below.
- **Why it still loses as PRIMARY:**
  1. **B alone leaves a ~1 status-poll-tick total transit outage per
     expansion commit** (apply lands → new slots unarmed → next poll
     tick converges). A/C close the window to zero at the source. For a
     bug whose entire cost is availability, the fix that shrinks the
     outage to zero beats the fix that bounds it at ~1s.
  2. **B alone keeps the wrong-identity carry defect** (numeric-slot
     state inheritance across reshuffles) — it converges the armed bit
     but leaves `registered`/`last_error`/counter provenance wrong.
  3. The override registry is new manager state with its own lifecycle
     hazards (staleness across daemon restart; slot renumbering between
     the status poll the operator read and the operator's request).
- **Exhaustive drift-producer enumeration (v2, SMR r1 SMR-3 / AGY r1
  Q2):** every writer of `binding.armed` in the tree — planner default
  (planning.rs:518-522), the `set_bindings_forwarding_armed` fan-out
  (status.rs:418-423), `set_binding_state` (binding.rs:29),
  `set_queue_state` (queue.rs:33), lifecycle init (all-false). The state
  file is write-only (`helpers/persistence.rs` — no restore path exists;
  lifecycle builds an empty `ProcessStatus`). Helper restart ⇒ Go
  reconnect ⇒ full apply (fresh plan, global false) ⇒
  `syncDesiredForwardingStateLocked` sees global false ≠ desired true ⇒
  `set_forwarding_state(true)` fan-out arms all. `update_ha_state` never
  touches bindings. Same-plan legs never replan. **With C in place, no
  non-operator producer of armed-bit drift remains** — the planner was
  the only one.
- **Verdict (v4):** REJECT B-as-Go-converger. Round 2 proved a
  converger IS required — but the helper-side `activation_pending`
  lifecycle (§5-C) provides it at the reconcile locus with exact
  provenance, where a Go-side converger would need a manager registry
  AND would still miss the rebind-completion timing semantics (the
  helper converges in the same lock-hold that binds the workers; Go
  would converge a poll-tick later). The issue's third fix-direction
  leg ("make Go's convergence check include each registered binding")
  is answered in detection form by option D below — whose predicate the
  marker now makes exact (`!Armed && !ActivationPending` = genuine
  drift, not pending activation).

### Option D — Go observability-only drift detection (companion to C; v2, SMR r1 SMR-2)

In `syncDesiredForwardingStateLocked`, **only when `desired == true`
and the global bit already equals it** (Codex r3 MINOR 10), when any
binding presents `Registered && Ifindex > 0 && !Armed &&
activation_state == none` (v6 tri-state: `pending` slots are
converging; `operator` slots are claimed — neither is drift), emit an
EDGE-TRIGGERED `slog.Warn` including the state for context (fires on
the drift predicate transitioning false→true, and again when it
clears; never per-tick — the project logging rules forbid >1/s
control-plane Info). No request is issued; nothing auto-reverts. The
predicate is EXACT by construction: what remains is genuinely
unexplained non-forwarding — the tripwire for any FUTURE unmarked
producer. ~15 lines in `manager_ha.go` + a manager test. On an OLD
helper (no state field), every unarmed registered slot reads as
`none` — exactly the old-bug stranding, so the warn doubles as the
mixed-version detector.

- **Value:** satisfies the issue's third leg as a detection surface; if
  a FUTURE drift producer ever appears (a new planner path, a
  mixed-version window nobody enumerated), on-call gets a log line
  naming the exact stranded slot instead of a silent blackout.
- **Cost/risk:** near zero; no semantics change. Bundled into the
  recommended ship.

### Option C — the `activation_state` lifecycle, v7: tri-state provenance + coherent vector + owned retry (Rust helper + Go manager + daemon ordering; superset of A)

v7 rewrite (Codex r5 BLOCKERs 2–8 + MAJOR 9–10; AGY r5 + SMR r5 nits).
Round 5 verified the tri-state's remaining encoding gaps and the
retry-ownership hole, and falsified two v6 mechanics (the
failure-path replan and the transient defer flag). v6's model stands;
v7 corrects its failure-recovery and completion machinery:

**The tri-state (unchanged from v6).**
`BindingStatus.activation_state ∈ {none, pending, operator}`:
`pending` = planner-owned (converge at the next successful,
defer-authorized armed reconcile); `operator` = operator-verb-owned
(never auto-converged, dies only at a global fan-out); `none` =
everything else (armed slots; global-fan-out-disarmed slots — global
ownership). Planner mark rules (never arms): S1 (unregistrable
creation → pending), S2 (force-clear on `ifindex <= 0` → pending
UNLESS the record is `operator`), S3 (deferred plan-CHANGING apply →
all registered slots `armed=false`, `pending` unless `operator`), S5
(new identity → `registered=true, armed=false, pending` always), S4'
(post-teardown bring-up failure → all non-operator registered slots
`armed=false, pending`). C1 (reaching `registered && armed` →
`none`), C3 (global fan-out sets `none` on REGISTERED slots;
unregistered keep state).

**C2, restated result-based (Codex r6 f2 — no discriminator
needed; boundary restated per Codex r7 f8).** r5's formulation
("register → `none`, disarm → `operator`") was attacked as
unimplementable because `(registered=true, armed=false)` serializes
identically for both names. The correct rule needs no operation
discriminator because it keys on the verb's RESULT, not its name:
**a verb that LEAVES the slot non-forwarding (`!armed`, or
`!registered`) sets `activation_state=operator` — the operator owns
that non-forwarding state, whatever they called the request; a verb
that leaves the slot forwarding (`registered && armed`) sets `none`
(C1 subsumes it).** There is no wire case that means "register into
the global default": the control API takes explicit booleans
(control.go:104 → protocol_binding.go:11 → control.rs:959), and
every caller is an explicit operator diagnostic
(cli_request_chassis.go:167-176, server_diag_system_action.go:430-455),
so a non-forwarding result IS the operator's intent. The state is
written in the same field mutation that applies the verb's values,
BEFORE any registration-changed reconcile (SMR r4 N2 code-order
pin). **Claim-deletion boundary (Codex r6 f2, restated exactly per
Codex r7 f8):** claims survive SLOT RESHUFFLES and interface FLAPS
(the planned `(linux-interface, queue_id)` identity persists), and
they die at a global fan-out (C3, registered slots) OR at ANY
deletion of that planned identity — a candidate dropout (invalid
fabric parent, planning.rs:464-467; unreadable queue count,
planning.rs:452-460), a rename (the linux name itself changes → new
identity, planning.rs:398), OR a queue-count contraction (the
global-min layout, planning.rs:495, deletes high-queue identities
on otherwise healthy interfaces). The later namesake is a new
binding (S5 pending) with no claim; §10 records the boundary; §9
item 15 pins all three deletion shapes.

**E2 narrowed to `pending` only (Codex r5 BLOCKER 2).** The
tri-state cannot distinguish "operator-disarmed then planner-force-
cleared" from "operator-unregistered" — both are
`!registered && operator` — so v6's "exact claim restoration" was
unimplementable: E2 would have re-registered explicit unregistrations
on ANY replan, no flap required. v7's rule: at replan,
`!registered && pending && new ifindex > 0` → `registered=true`
(still `!armed, pending`); **`operator` records are NEVER
re-registered or armed by the planner.** The retained claim
(`registered=false, operator`) is the honest degradation, restored
to §10: an operator-claimed slot whose interface flaps recovers
unregistered-with-intent (never armed, never auto-converged); the
operator re-registers by hand when the environment is understood.
Registration and arming of claimed slots belong to operators and
global fan-outs, not to recovery machinery.

**Failure recovery: plain restoration, no replan (Codex r5 BLOCKERs
3 + 5; subsumes r4 B2 + M9).** v6's failure-path replan-from-restored
reintroduced the live-sysfs race (an unreadable queue dir → empty
candidate set → a PERMANENT empty vector: rebind never replans, the
same-plan deficit exits for zero runnable bindings, `enabled=false`
with no slot for D to warn on) and destroyed accepted-A operator
claims absent from rejected B's vector. v7 replaces it with the
simplest coherent form — **the post-teardown apply-failure path
restores `guard.snapshot` AND `existing_bindings` wholesale (the
pre-apply vector captured at snapshot.rs:158, which IS the coherent
last-good vector: A's identities, A's ifindexes, A's operator claims),
then re-marks every non-operator registered slot `armed=false,
pending`** (the common S4' predicate, idempotent — the marks the
in-reconcile S4' put on the discarded B vector die with it). Then
`refresh_status` / `refresh_bindings` reports the REAL volatile state
of any surviving partial workers against that vector (the #4952
rationale — real post-teardown state, no pre-teardown ghosts —
preserved; the retained-B pin changes form, §6). No replan, no
sysfs, no race, no empty vector, no lost claims. The common S4'
itself stays in `reconcile_status_bindings` for the non-restoring
callers (rebind, toggles, forwarding arm, same-plan leg): on
`WorkerSpawn | WorkerBindIncomplete` it marks the CURRENT vector
before the Err propagates (Codex r4 B4's common-locus requirement,
kept).

**Convergence — one locus, two gates, one explicit signature (v7.1,
AGY r6 f1).** `reconcile_status_bindings(state,
defer_completion_authorized: bool) -> Result<(), ReconcileError>` —
the `rebind` handler passes `request.complete_deferred`; every other
caller (apply legs, forwarding, queue/binding toggles) passes
`false`. In the ARMED leg (`should_run_afxdp` true), after
`afxdp.reconcile` returns `Ok` and BEFORE the bindings are written
back / `refresh_status` / the single persist: (1) if
`defer_completion_authorized && guard.snapshot.defer_workers` —
CONSUME the latch: set the stored snapshot's `defer_workers=false`
(one mutation, inside the same critical section, sharing the
handler's one persist — never a separate write, never a window where
the state file says defer=true while in-memory says false, SMR r6
N3); (2) for every `state==pending && registered` slot, set
`armed=true, state=none, last_change=now`. The two gates are therefore
`should_run_afxdp` AND `(!stored_defer || defer_completion_authorized)`
— evaluated against the stored value AT ENTRY (before the consume),
so the tagged rebind converges in the same call that consumes the
latch, and an UNTAGGED caller during a stored-defer window is blocked
exactly as before. On `Err` the latch is NEVER consumed (a failed
tagged rebind leaves the defer state intact for the retry — AGY r6
f1's clear-before hazard is structurally excluded) and S4' marks as
usual. The convergence still cannot fire on a partial bind
(`bound == planned` is required for the Ok, bringup.rs:188).

**Identity-checked volatile refresh (Codex r6 f3; v8.2 per Codex r7
f7 — planned identity, not the relaxed socket tuple).**
`refresh_bindings` maps live workers into the status vector by
NUMERIC SLOT (refresh_bindings.rs:25). Surviving partial-B workers
after a failed bring-up (bringup.rs:172, pinned) therefore alias
their socket/heartbeat/`ready` state onto possibly-unrelated
restored-A identities — wrong in the failure window, and the same
mechanism as the deferred-window cosmetic alias from round 1. The
identity check compares the binding's `(interface, ifindex,
queue_id)` against the live record's PLANNED identity
(`workers.identities[slot]`, written ONCE at plan time,
bringup.rs:280 — tear-free), NOT the live socket tuple: v8's
socket-fields check was itself racy (separate relaxed stores of
ifindex and queue, binding_state/mod.rs:873, can tear a
(new-ifindex, queue-0) read into a false accept, Codex r7 f7). The error-attribution rule
is identity-keyed (Codex r8 f6): on an identity MATCH the copy
includes `last_error` — even when the socket tuple is zeroed (a
failed bind leaves no tuple but owns its error, worker/mod.rs:921);
on a MISMATCH the slot zeroes volatile/socket fields AND takes no
error — the live record's error belongs to a DIFFERENT physical
binding and must never be copied onto the restored identity (the
restored record keeps only its own pre-restoration diagnostic). Volatile state is then reported
only for the physical binding it belongs to, in every window
(deferred, failure, reshuffle). This is the ONLY coordinator-side
change in the PR. Two boundary notes (SMR r9 N5): a bind error
for a queue the restored plan DELETED dies with the identity (the
mismatch case already refuses the copy; the queue no longer
exists in the accepted config and the failure was surfaced at
apply time) — consistent with the claim-deletion boundary; and
the cluster's HA sync is ROLE-based (Codex r9 f9's
sharpening): only the RG0 primary pushes
(daemon_ha_sync.go:318), the secondary accepts whatever the peer
applies (daemon_ha_sync.go:534), and the generation hash is
content-deduplication, not an ordinal (daemon_ha_sync.go:381) —
so a peer config that APPLIES (older or newer by origin) is the
accepted authoritative configuration: the node-local acceptance
epoch advances and newer-local debts supersede, with NO numeric
generation floor imported. The applied-identical shortcut
(daemon_ha_sync.go:563) performs NO adoption and must NOT advance
the epoch.

**INVARIANT 2 (coherent vector), completed — `update_fabrics`
replans (Codex r5 BLOCKER 4, projection-scoped in v8 per Codex r6
f4/f5, transaction-shaped per Codex r7 f2/f3).** `update_fabrics`
(handlers/mod.rs:141-168) replaces `guard.snapshot.fabrics` — a
plan-key input that also ADDS binding candidates
(planning.rs:160-173, 462-477). v8 splits the fabric update into a
TELEMETRY half and a PROJECTION half: the projection is exactly the
fields the planner reads (`name`, `parent_linux_name`,
`parent_ifindex`, `rx_queues` — the plan-key inputs); telemetry is
everything else (resolved MACs, `up`, peer data — snapshot.rs:445).
Telemetry-only changes persist WITHOUT replanning (the 30s periodic
and the netlink-event-driven refresh, daemon_ha_fabric.go:243/:1039,
pay nothing). On a PROJECTION change, the handler:

1. **Evaluates the guard FIRST (Codex r7 f3; mixed-update rule per
   SMR r8 N2):** the incoming projection is STAGED, never published
   before acceptance — `refresh_fabric_links` (which pushes fabric
   state to workers, snapshot_refresh.rs:83) receives only the
   ACCEPTED projection (the prior one on a guard hit). The guard
   fires exactly when an eligible candidate (present in the
   accepted projection with raw `rx_queues==0`) fails queue-count
   resolution IN THE SAME PASS (`rx_queue_count`'s read_dir failed,
   planning.rs:605-621 — the only path to 0; the planner returns an
   exact per-candidate skip cause so the guard does not infer it).
   A guard hit defers the WHOLE update — prior projection AND prior
   vector, never a partial subset, because partial acceptance would
   diverge the vector from the accepted projection (SMR r8 N2); the
   deferred update re-applies on the next pass when sysfs recovers
   (projection and pending marks then apply together). A legitimate
   full removal goes through `apply_snapshot` — never
   `update_fabrics`, which production cannot even encode today (an
   explicitly-empty fabrics slice is dropped by
   `json:"fabrics,omitempty"`, protocol.go:83, and Go early-returns
   on empty, manager_ha.go:166 — so the removal case is
   Rust-test-only and never triggers the guard).
2. **Marks the whole non-operator vector unarmed+pending (Codex r6
   f4's option (b), made gate-exact by Codex r7 f2):** on an
   accepted projection change, EVERY non-operator registered slot
   is set `armed=false, state=pending` — explicitly `armed=false`,
   because the `enabled` gate reads only `registered && armed`
   (status.rs:274-281) and ignores the state field, so a
   `pending`-only mark would leave `enabled=true` against stale
   physical bindings. New candidates then initialize per S5
   (already `registered=true, armed=false, pending`); REMOVED
   candidates drop out (their claims die at the deletion boundary);
   same-name/new-ifindex identities are both carried AND marked
   (physically unbound until the next reconcile).
3. **Does NOT reconcile in-handler (v8.2, replacing v8's
   rate-capped in-handler reconcile):** the binding reconcile is
   driven by the existing machinery with the normal fail-closed
   posture — the pending marks force `enabled=false`, and the Go
   pending-activation retry (or the next apply, or the
   busy-watchdog) drives the plain rebind that tears down orphaned
   workers, binds the new/physically-changed slots, and converges
   the marks. This avoids embedding a 10-second worker-readiness
   reconcile inside an RPC with a 3-second deadline
   (process_control.go:33 vs bringup.rs:30) — the v8 in-handler
   reconcile's timeout-but-landed class disappears by
   construction — and it cannot leave Go holding `ctrl.Enabled=1`
   with stale READY rows across a teardown window, because of the
   next rule:
4. **The Go fabric transaction, v8.8 form (Codex r7 f2/f3, r8
   f5, r9 f5, r10 f3/f7, r11 f2/f3/f9, r12 f2/f4/f6/f10/f11):**
   the manager's `SyncFabricState` today ignores the returned status and
   writes back its own input (manager_ha.go:153/:175), so a
   projection the helper guard-rejected would live on in
   `m.lastSnapshot.fabrics` and re-enter through the next
   wholesale clone (route/scheduler republish,
   manager_overlay.go:188) — recreating the sink through the
   back door. The v8.8 transaction (the lineage authority for
   every gate below is the TWO-REVISION lineage — §6; the
   v8.7 `ConfigGeneration`/scalar/pointer tokens are all
   deleted):
   (i) **VERIFIED, CAUSALLY-ENV-GATED pre-disable (v8.9,
   Codex r13 f11; v8.8 causal form per Codex r12 f10; v8.7
   replaced v8.6's value edge-trigger per Codex r11 f9):**
   the guard is
   ENVIRONMENTAL — `rx_queue_count` returns 0 on an unreadable
   sysfs (planning.rs:605-621; note the source model: readable
   sysfs always yields ≥1, and the fabric-parent guard CLAMPS
   queue counts to ≥1 (planning.rs:452-476) — so the
   projection-rejection inputs are parent-ifindex VALIDITY and
   queue-count CHANGES, not a zero-count state current source
   cannot produce, Codex r13 f11's correction) and later
   recovers without the projection changing, so a value-keyed
   edge both bypasses and pulses. The v8.9 rules:
   (a) ONE SAMPLE PER VERDICT — each guard evaluation captures
   the candidate environment ONCE, and the verdict AND the
   returned `guard_env_generation` derive from THAT sample;
   (b) ACKNOWLEDGED BOUNDED REJECT-SET with EXPLICIT eviction
   ownership (v8.10, Codex r14 f11) — the helper retains a
   bounded set (≤4) of recently-REJECTED projections as
   (identity, sample) pairs (identity = the projection hash;
   replace-oldest on overflow; a rejection RESPONSE carries
   the (identity, generation) ack) and ECHOES the retained
   identity set in every full status; the env watch covers
   the UNION of the accepted snapshot's candidates AND the
   retained set's candidates — a lost rejection response
   leaves Go unsuppressed (it re-sends; the helper's
   idempotent re-rejection re-acks until a response lands),
   so helper watch ownership and Go's cache can never
   diverge on a lost response (Codex r13 f11's keep-first /
   replace-on-reject dilemma dies: the set holds BOTH B and
   B′); and Go DISCARDS any cached suppression entry whose
   identity is ABSENT from the echoed retained set (v8.10
   eviction ownership: an evicted identity is re-sent on
   the next relevant event — the helper re-rejects on a
   fresh sample and re-acks, re-inserting it — so an
   evicted identity can never stay suppressed forever,
   Codex r14 f11 = AGY r14 f4 = SMR r14 SMR14-5);
   (c) Go caches `(rejectedIdentity, rejectedGen)` and
   SUPPRESSES the resend of that IDENTITY only while both
   match, keyed to the HELPER INCARNATION (cache resets on
   every manager-driven (re)spawn); (d) the status poll that
   observes a `guard_env_generation` bump with a suppressed
   identity DISPATCHES the fabric sync — DEBOUNCED with an
   AGGREGATE cap: at most one dispatch per identity per 5s
   AND at most 4 dispatches per 5s GLOBALLY (a dispatch-queue
   rate limiter — up to four retained identities can
   otherwise dispatch independently, and a stream of novel
   projection hashes can churn the reject-set evictions,
   Codex r14 f11; a 1 Hz sysfs flap coalesces to ≤0.2
   dispatches/s/identity and ≤0.8/s aggregate, each
   guard-REJECTED cycle re-enabling ctrl in the same RPC
   tick — an RPC-length pulse — so the duty-cycle bound is
   ≈milliseconds per 5s, never an unbounded 1 Hz ctrl
   oscillation; an
   accept/reject oscillation (queue count flapping across the
   guard threshold) converges fail-closed on each accept and
   releases on each reject — the correct posture while the
   projection is unstable).
   EVERY non-suppressed send whose requested projection
   differs from the cached ACCEPTED projection is preceded by
   the verified pre-disable — first sends and post-recovery
   retries alike. The disable's PROOF is the post-write
   readback of 0 (Codex r10 f7): a lookup failure followed by
   a successful write+readback still proves zero;
   if NO readback can be obtained, the projection RPC is NOT
   sent. The pre-disable/sync failure surfaces through the
   FABRIC SYNC DEBT state machine (v8.11 identity-keyed form,
   Codex r14 f12 + AGY r15 f7 = SMR r15 SMR15-7, replacing
   v8.10's full-payload key):
   `SetFabricForwarding` commits the BPF map FIRST and only
   then syncs the helper (controllers.go:112-132 — "the map
   update is committed at this point"), so the map commit
   STANDS (never rolled back); a helper-sync/pre-disable
   failure records a debt entry keyed `(commit_revision,
   projection-identity)` — the identity being the planner
   fields (name, parent Linux name, parent ifindex,
   effective queue count) so a TELEMETRY
   update (peer-MAC resolve, link up/down) is the SAME
   identity and the debt is always findable (v8.10's
   full-payload key let a telemetry change move the payload
   off the debt's key — the readiness query missed it,
   AGY r15 f7) — and records the LAST-SENT
   `map_generation` per
   entry for the clear rule (v8.13, Codex r17 f12 — the
   payload-hash rule is replaced: the generation IS the
   send order). States
   {pending → retrying (5/10/30/60s backoff, driven by the
   existing 30s fabric ticker + event wakeups + the (d)
   poll-dispatch) → failed-warned (edge Warn, retrying
   continues at the 60s floor)}; a CLEAN sync CLEARS the
   entry ONLY when its `map_generation` is the debt's OR
   NEWER (a stale
   clean retry carrying an older generation can never clear a
   newer unsynced payload, Codex r14 f12's aliasing class);
   an unrelated clean status does NOT clear;
   a newer projection SUPERSEDES the old entry; and a CLEAN
   GUARD REJECTION records a readiness-relevant debt too
   (map-new/helper-old).
   `fabricPopulated` remains truthful MAP state,
   and takeover readiness (daemon_ha.go:774-783) ANDs it
   with "no outstanding sync debt for the CURRENT
   projection" — read through the NEW
   `FabricSyncStateOK() bool` — a NO-ARGUMENT manager-owned
   consistency answer with a CAUSAL protocol (v8.12, Codex
   r16 f14, replacing v8.11's name-only query; the
   single-transaction completion is v8.13, Codex r17 f12 =
   AGY r17 f3 = SMR r17 SMR17-4): the
   manager maintains a `map_generation` and owns the WHOLE
   fabric sync as ONE transaction — a single `m.mu`
   section that (a) SAMPLES the map view
   (`FabricFwdInfo`, types.go:797-804), (b) performs or
   confirms the BPF map mutation AND mints
   `map_generation` ATOMICALLY with it, and (c) builds the
   helper payload FROM THE SAME SAMPLE — the v8.12 form
   minted a bare counter, which ordered sends without
   proving correspondence (Codex r17 f12's divergence:
   the map is written with peer MAC X at generation g;
   neighbor resolution moves to Y before an independent
   payload build samples; the helper accepts payload Y
   tagged g and `accepted == current` reads true while
   map-X and helper-Y diverge — impossible when the
   payload is built from the sampled mutation itself).
   The controllers.go:68/:112 shape (write the BPF shim
   OUTSIDE `m.mu`, then ask the manager to build/send) is
   restructured so the sample/mint/build/send sequence
   serializes under `m.mu`; the direct key writes
   (maps_fabric.go:16-33) move inside the manager's
   wrapper; and the public legacy-adapter fabric methods
   (legacy_dataplane.go:346) are enumerated as
   pre-upgrade/test-only paths (production fabric writes
   route ONLY through the manager's wrapper). Every
   fabric send (`update_fabrics` AND full
   snapshots) carries the current `map_generation`
   (additive fields), and the helper echoes
   `accepted_fabric_map_generation` (the generation of the
   last fabric send it ACCEPTED) in every status —
   advancing on EVERY accepted full snapshot that carries
   the field, EVEN WHEN the fabric content is equal
   (idempotent advance, v8.13: the accepted value tracks
   the newest accepted send, not the newest content
   change; the helper's assignment is unconditional on
   accept, ordered with the snapshot's own storage). A clean
   fabric send whose echoed generation matches the current
   `map_generation` is the coherence proof.
   `map_generation` SEEDS from the startup ping echo
   (v8.13, SMR r17 SMR17-4: accepted → the minted
   high-water, mirroring the `publication_rev` seed — a
   manager re-init over a surviving helper no longer
   desyncs (v8.12's minted-from-0 vs the helper's
   retained accepted would have wedged readiness false
   forever)); and the new-helper-zero vs old-helper-zero
   ambiguity resolves via a protocol CAPABILITY bit in
   the ping exchange (v8.13, Codex r17 f12: an old
   helper lacks the capability → every lineage-sensitive
   operation fails closed until the REQUIRED helper
   restart; a NEW helper's genuine zero is a valid
   pre-proof state, distinguished by the bit). The
   first-proof producer on a fresh boot is pinned
   (v8.13, Codex r17 f12's answer to AGY r17 f3):
   `startClusterComms` starts the fab0/fab1 population
   goroutines (daemon_ha_sync.go:1223-1242), whose sync
   rides the same transaction — so a configured-fabric
   boot produces the proof at bringup and HA takeover
   readiness is correctly blocked until it lands.
   `FabricSyncStateOK()` returns TRUE only when
   `accepted_fabric_map_generation == map_generation` AND
   no sync debt is outstanding AND a coherence proof exists
   since this manager's startup (a fresh boot with an
   empty debt map but no proof answers FALSE (AGY r16 f7 —
   "no debt" alone would admit an arbitrarily diverged
   helper); an old helper (no capability bit) answers FALSE until
   the REQUIRED restart (correct fail-closed)). The
   fabric-send ORDER spans full snapshots and
   `update_fabrics` via the generation (v8.11's
   "publication-rev-ordered" clear was wrong —
   `update_fabrics` carries no publication revision
   (protocol.go:55-84)); the projection IDENTITY is
   (name, parent Linux name, parent ifindex, effective
   queue count) (planning.rs:160-171 — the v8.11 text's
   (name, parent, vlans, queues) was source-wrong:
   `FabricSnapshot` has no VLAN field
   (protocol.go:315-333)). The map's view
   (`FabricFwdInfo`: two ifindexes and two MACs,
   types.go:797-804) and the sent payload
   (`FabricSnapshot`: names, parent/overlay, queue count,
   peer address, Up, protocol.go:315-333) are DIFFERENT
   projections, with peer-MAC resolution independent
   (daemon_ha_fabric.go:484-490) — which is exactly why
   the payload must be built from the sampled map view in
   the same locked section (no daemon-side hash can name
   the sent payload without another TOCTOU sample, and a
   bare counter cannot prove correspondence).
   The debt itself keys on `(commit_revision,
   projection-identity)` as before (a telemetry update is
   the same identity — the debt is always found, AGY r15
   f7); a clean sync clears the entry ONLY when its
   `map_generation` is the debt's or newer (v8.13 — the
   clear rule moves from payload-hash to generation; a
   stale clean retry never clears a newer unsynced
   payload); a CLEAN
   GUARD REJECTION also records a readiness-relevant debt
   (map-new/helper-old);
   so a
   permanently-failing sync keeps readiness FALSE even with
   the map committed. All four call sites (fab0 explicit,
   fab1, both clear legs — daemon_ha_fabric.go:738-756/
   :944-957/:771-778/:969-976) route through the same
   machine.
   The disable itself is a plain `ctrl.Enabled=0` write that
   touches NO liveness state (v8.4, AGY r9 f3 = SMR r9 N3:
   `neighborsPrewarmed`/`ctrlEnableAt`/`xskLivenessProven`
   are reset ONLY when the helper ACCEPTED a projection
   change that marked bindings pending — i.e. a real rebind
   is coming).
   (ii) **Response-classified release:** on a CLEAN guard-hit
   response (helper kept prior projection+vector, no pending
   marks, enabled=true) ctrl re-enables IMMEDIATELY in the
   same tick (the pulse is RPC-length, not poll-length); on an
   ACCEPTED change the pending marks keep ctrl disabled until
   convergence; on an UNKNOWN outcome (timeout/EOF, helper
   possibly committed) ctrl stays 0 until the next successful
   poll shows the converged state (the pending-activation
   retry drives the binding reconcile meanwhile; the busy
   watchdog is NOT a fallback here — it requires ≥1
   `Registered && Armed` binding, maps_sync.go:1435, and the
   mark-all explicitly unarms everything).
   (iii) **EPOCH-GATED fabric adoption (v8.10 two-revision
   form, Codex r14 f3/f4):** adopt `status.Fabrics` into
   `m.lastSnapshot.fabrics` ONLY when
   `status.commit_revision == m.acceptedCommitRevision` AND
   `m.pendingCommitRevision == m.acceptedCommitRevision` (no
   newer config staged) AND the observed revision pair is
   NONZERO (fail-closed on an old helper's 0). Every
   other case keeps Go's snapshot whole: staged-ahead (never
   an A-fabric splice onto B's config); helper-ahead
   (`status.commit_revision > m.acceptedCommitRevision` OR
   `status.publication_rev` ahead of the last observed
   value) routes to the re-sync (§5-C UNKNOWN-outcome
   ownership); helper-behind (a restarted helper echoes 0)
   routes to the startup re-apply, never by adopting an
   empty set. The content-dedup case is covered by the
   `note_commit_revision` CAS transfer (§5-C epoch contract
   and (iv) below): after the observed transfer the helper
   echoes the staged revision and the gate holds — no
   publish, no wedge, no regression. `appliedSnapshot` stays
   untouched for its original #2079 consumer (the NAT pool
   alarm) and plays NO role here.
   (iv) **REQUEST-SIDE lineage fence + FULL-PRODUCER
   divergence suppression (v8.10, Codex r14 f4/f5):**
   response-side gating cannot undo a
   request-side hybrid — `update_fabrics` mutates whichever
   snapshot the helper stores (handlers/mod.rs:144-174). The
   `update_fabrics` request carries
   `expected_commit_revision` = the commit revision of the
   config the fabrics were derived from (`m.lastSnapshot`'s
   staged revision when staged, else the accepted revision),
   and the helper REFUSES on mismatch with its stored
   `commit_revision` — fail-closed, no mutation, no persist,
   the check ordered FIRST (before the guard evaluation,
   `refresh_fabric_links`, the fabric mutation, and
   persistence). Divergence suppression covers ALL auxiliary
   full-publish producers while ANY config is
   staged-unpublished (Codex r14 f4: a route overlay,
   scheduler republish, or #5134 retry cloning staged-B's
   `m.lastSnapshot` would otherwise publish B while Go is
   still accepted=A — a false helper-ahead with B's debt
   handoff skipped; and the A-owned #5134 clone forcibly
   sets `DeferWorkers=false` (manager_worker_arm_5134.go:50-64)
   and can ARM staged B before its MAC obligation settles):
   while `m.pendingCommitRevision >
   m.acceptedCommitRevision` OR an observed helper-ahead
   divergence is unresolved, the #5134 retry, route
   overlays, scheduler republishes, AND `SyncFabricState`
   are ALL suppressed — the ONLY allowed first-publish of a
   staged config is its own compile leg (or its
   pending-XSK deferred-publish leg); and the helper's OWN
   strictly-greater `publication_rev` refusal (§5-C epoch
   contract) is the second layer for any stale send that
   races through. The
   content-dedup lineage transfer is a COMPARE-AND-SET verb
   (v8.10, refined to a three-way order per Codex r15 f6):
   `note_commit_revision { new_rev, expected_rev }` —
   evaluated in this EXACT order: (i) `stored == new_rev` →
   idempotent SUCCESS (an equality repeat after a landed
   transfer — the v8.10 text's "equality idempotent"
   contradicted its own CAS, which would have refused a
   repeat as `stored != expected_rev`); (ii) else
   `stored == expected_rev` → MUTATE (the transfer);
   (iii) else a TYPED refusal carrying the CURRENT stored
   revision in the response's `Status` AND an
   `error_code: "note_cas_refusal"` (v8.12 wire form, Codex
   r16 f8: `ControlResponse` today carries only `OK`, a
   free-form error string, and `Status`
   (protocol.go:86-90, control.rs:932-945) — and EVERY
   ordinary handler response already carries `Status`
   (handlers/mod.rs:260-267), so "OK=false plus Status"
   cannot identify a CAS refusal. v8.12 adds an additive
   `error_code: string` (serde default `""`) to the
   response: the new typed codes (`stale_completion`,
   `diverged_fabric`, `note_cas_refusal`, `epoch_rollback`,
   `publication_rollback`, and v8.13's
   `stale_snapshot_token` (Codex r17 f6 — the token
   refusal needed its own code; `not_seeded` is
   MANAGER-LOCAL, synthesized Go-side before the send and
   NEVER on the wire)) classify the new
   machinery's refusals, EXISTING errors keep `""` (their
   current handling is untouched), and Go classifies by
   `error_code` with the error string as the untyped
   fallback. Go reads refusal state from the response even
   on `OK=false` — but ONLY for typed responses (v8.13,
   Codex r17 f6's consumer contract: the
   whole-response discard (process_control.go:163-169) is
   amended ONLY when `error_code != ""`;
   `requestLocked`'s status copy (:219-230) extends to
   typed-error cases ONLY — UNTYPED failures keep today's
   handling byte-identical, because Rust attaches `Status`
   to ordinary failed responses too
   (handlers/mod.rs:260-267) and copying it would change
   existing behavior; every typed response invokes the ONE
   common lineage-observation routine below and selects
   the reservation/debt outcome).
   And the v8.10/§6 contradiction — "response shapes
   unchanged" — is corrected: the shape is additively
   extended). A refusal with `current >
   expected` proves supersession — Go ABANDONS the note (no
   retry); a refusal with `current < expected` is
   helper-behind/reset — the RE-SYNC owns it (the v8.11
   nonzero-helper-behind firing covers it). The note echo
   (`status.commit_revision`) advances the accepted state
   and clears the note debt BEFORE generic divergence
   classification (v8.11 ordering, Codex r15 f6: otherwise
   the same echo simultaneously clears the note AND fires
   the re-sync as helper-ahead) — in ONE common
   lineage-observation routine shared by the response
   path and the status poll (v8.12 ordering pin, Codex r16
   f8). And the semantic hash
   EXCLUDES BOTH lineage fields (builder.go:156-178's zero
   set (Generation, FIBGeneration, GeneratedAt) grows to
   include `commit_revision` and `publication_rev` — if
   `commit_revision` participated, forwarding-identical A/B
   would never dedup and the note path would never run).
   A refusal with `current > expected`
   is INFORMATIVE (a racing publish already advanced
   lineage past the note): Go ABANDONS the note (no retry)
   and the gates re-evaluate against the newer stored
   revision. A FAILED/UNKNOWN transfer (timeout, or a
   `requestLocked` no-status success,
   process_control.go:219-230) records a SUPERSEDABLE note
   debt retried on the fabric ticker, cleared ONLY on an
   exact echo of the captured sent revision OR ANY NEWER
   revision (v8.11, AGY r15 f8 = SMR r15 SMR15-8: a newer
   accepted commit advancing the stored revision past the
   note's has FULFILLED the note's purpose) — never on an
   ACK, an unrelated poll, or the then-current pending
   revision. Mixed-version: old
   helper ignores the fields and echoes 0, so all
   lineage-sensitive sends fail closed until the REQUIRED
   helper restart (Codex r13 f6); an old Go driving
   a new helper degrades to epoch 0 == 0 (accept), the
   documented pre-upgrade semantics.
   (v) **LINEAGE-GATED, ASYMMETRIC latch echo (v8.10, AGY
   r14 f2 = SMR r14 SMR14-2, replacing v8.9's bidirectional
   echo):** the
   `stored_defer_workers` status echo reconciles the manager
   flag and the Go cache CLEAR-ONLY: it may set Go's flag
   FALSE when the helper's stored latch is false (the
   lost-completion case: Go true, helper false), and it may
   NEVER set Go's flag TRUE — defer intent only ever
   originates Go-side (the `StartCompile` reservation), so a
   helper-true/Go-false mismatch is NOT a state to adopt
   but a DRIFT to surface (edge-triggered Warn) whose owner
   is the next full apply (which stamps `defer_workers`
   from Go's own flag, re-asserting the truth) or the
   re-sync when the revisions also diverge. The
   reconciliation runs ONLY under the same lineage gate as
   (iii) — `status.commit_revision ==
   m.acceptedCommitRevision` AND `m.pendingCommitRevision ==
   m.acceptedCommitRevision` — and ONLY while
   `m.compileInFlight` is FALSE (the `StartCompile`
   reservation, §5-C defer-intent atomicity). The v8.9
   bidirectional echo let a lingering helper latch
   (reachable via a lost operator-arm response) re-latch a
   NON-deferred compile mid-build
   (manager_compile.go:177-228 builds outside `m.mu`; the
   :330-332 stamp reads the flag) and publish a clean
   config DEFERRED — dead by construction under clear-only;
   an old helper's missing echo (revision 0) never
   reconciles because its revisions never match.

   **Honest convergence budget (Codex r10 f7's wall-clock
   correction; v8.7 warm-clock correction, Codex r11 f11; v8.8
   dispatch + starvation corrections, Codex r12 f9/f10/f14):** an
   ACCEPTED fabric projection change converges
   in ≈19s from the pre-disable on a HEALTHY unsuppressed
   baseline (control RPC + ~5s
   retry-scheduling delay + ~10s worker readiness + status tick +
   backoff jitter); the WORST case is a warm retry clock — a
   same-name/new-parent-ifindex projection marks the same
   identities pending while their retry already sits at the 60s
   floor (the exponent-preserving reset never pulls it earlier
   for unchanged membership), giving ≈60s + readiness + poll +
   RPC + jitter (≈70s), with defer/debt suppressions able to
   extend it further; a clean guard-hit pulse is RPC-length with
   immediate re-enable; a guard-rejected projection resends ONLY
   on an observed `guard_env_generation` bump, and the observing
   POLL DISPATCHES the retry (it does not wait for the 30s fabric
   ticker, daemon_ha_fabric.go:243-256/:833-849 — the v8.7
   unbudgeted +30s dies), so env recovery adds ≤1 poll + RPC;
   an isolated UNKNOWN-no-commit releases at
   ~failed-RPC + 1s poll + RTT (≈7s); persistent control failure
   stays fail-closed indefinitely (correct posture while retries
   and diagnostics stay alive); the MAC debt's NO-TIMEOUT
   FIFO acquire (v8.12) guarantees eventual progress
   (position preserved; FIFO wake + bounded owner holds —
   a commit's whole-pipeline hold is several minutes of
   sequential ~67s-capped control requests
   (process_control.go:31-56/:85-103), never infinite — and
   the "guarantee" holds only because every owner,
   including the recovery restore, is proven terminating,
   Codex r16 f13's condition); and the honest
   manager-lock delay: any poll/ticker path can wait
   behind the status loop's `m.mu`-held work
   (process_status.go:162-257), whose legal control RPCs
   reach ~67s — so "env recovery ≤1 poll + RPC" reads as
   ≤1 poll + RPC + manager-lock delay (≤~67s worst legal
   hold), not as a strict sub-second bound (Codex r16 f16);
   the 30s proxy-ARP reconcile (daemon_proxyarp.go:16-24)
   and similar periodic owners are ms-to-seconds scale and
   irrelevant under FIFO. The all-member pass-1 reread is
   fixture-scoped (Codex r16 f16's labeling):
   the 12-member fixture pins AT MOST 24 fake-netlink calls
   (12 link + 12 attr, no per-retry re-read amplification)
   and ≤ 50 ms CI wall-clock (call COUNT and ordering —
   the load-independent properties — not a system-wide
   production-latency ceiling; `RethToPhysical()` iterates
   the configured map (types.go:62-95) and RG IDs extend
   through 155 (compiler_validate_strict_reth_vrrp.go:17-22),
   so larger RETHs scale the call count linearly).
   budgeted with EXACT assertions (Codex r14 f14): the
   daemon test fakes netlink and asserts the all-member
   pass-1 reread of a 12-member RETH issues AT MOST 12 link
   reads + 12 attr reads (≤ 24 total calls, no per-retry
   re-read amplification) and completes in ≤ 50 ms
   wall-clock on CI hardware (a generous bound over the
   measured µs-scale per call; the CI bound does not claim
   to price loaded production netlink latency — it pins
   call COUNT and ordering, the load-independent
   properties).


**Completion machinery, durable and provenance-exact (Codex r5
BLOCKERs 6 + 8; v8 epoch form per Codex r6 f6/f8):**

- **The defer EPOCH spans apply → MAC → sleep → dispatch →
  completion return — and ROLLS OVER on every commit (v8.2, Codex
  r7 f4's leaking-boolean fix).** Today `clearDeferWorkers()` runs
  immediately after `ApplyConfig` (daemon_apply_dataplane.go:170) —
  before `programRethMAC` (:247), before the completion dispatch
  (:393/:401), and before `NotifyLinkCycle`'s deliberate 1s
  quiescence sleep (process_linkcycle.go:184, the mlx5 queue-reuse
  quiescence). v8 splits the two completion flows:
  - **Live-change flow (no link cycle):** the mandatory re-apply is
    SYNCHRONOUS (`reapplyAfterDeferredMAC` → `d.dp.ApplyConfig`,
    :466-481), so the flag clears immediately before that call —
    the re-apply stamps `DeferWorkers=false` and converges in its
    own publish leg. No window.
  - **Link-cycle flow:** the flag stays SET through MAC programming,
    the 1s quiescence sleep, AND the tagged rebind's round trip;
    it clears only when the tagged rebind returns `Ok` (or the flow
    fails — then it stays set and the completion debt below owns
    the retry). The desired-state arm-sync stays gated the whole
    time, so no arm and no retry can recreate workers
    mid-quiescence (Codex r6 f6's EBUSY race). The gate's exact
    form (AGY r7 f3): an ARM-DIRECTION skip in
    `syncDesiredForwardingStateLocked` —
    `if desired && m.deferWorkers { return nil }` — NOT a blanket
    early return, so the disarm direction is never blocked.
  - **Epoch rollover (v8.2, Codex r7 f4's counterexample
    killed):** a stale epoch must never leak into an unrelated
    config. The ordering is ROLLOVER-THEN-OPEN, driven by ONE
    precheck (SMR r8 N1): on EVERY commit, before the snapshot is
    stamped, the commit's own `rethMACPending` precheck runs first.
    If it finds NO MAC work, the stamp is non-deferred, and every
    rollover ACTION happens at compile ACCEPTANCE (Codex r8 f9's
    eager-rollover fix): ON SUCCESS the manager clears
    `m.deferWorkers` and cancels any stale tagged-completion and
    MAC debts (they are config-generation-scoped and would abandon
    anyway — this makes the abandonment explicit), and the commit's
    own non-deferred stamp has already cleared the helper's stored
    latch via the `apply_snapshot` swap. If it finds MAC work, the
    commit opens (or replaces) the epoch — the same cancellation
    runs AT ACCEPTANCE, keyed on generation MISMATCH (stale debts),
    never on the epoch being opened — so the new epoch can never
    cancel itself: the flag-clear happens only in the
    no-MAC-work branch, the flag-set only in the MAC-work branch,
    and the precheck's answer selects exactly one branch. And the
    failed-successor rule (Codex r8 f9): a compile that FAILS
    pre-acceptance rolls the flag back to its prior value and
    leaves the stale debts ALIVE (still generation-matched to the
    last accepted config) — the old epoch and its retry owners
    survive a failed successor instead of being cancelled by it. The helper side needs NO mirror rollback (SMR r9 N4): the
    stamp only exists inside the publish path
    (manager_compile.go:330), so a pre-acceptance failure either
    never reached the helper, was rejected with the helper keeping
    prior state (#3766/#3789 capture-restore), or LANDED as
    timeout-but-landed — and the last case converges through the
    existing #4036 exact-equal idempotent-retry semantics (a retry
    re-sending the same (generation, fib) pair is accepted
    exact-equal) plus the completion machinery that owns the
    latch.
    An explicit OPERATOR global arm during a window also clears the
    manager flag (the operator completed the window explicitly —
    documented). Without rollover, a deferred A whose tagged
    completion failed would leak `DeferWorkers=true` into every
    later unrelated compile's stamp — B workerless forever with no
    MAC completion owner (Codex r7 f4's trace). Supersession is
    BY DESIGN total: every accepting path — normal commits, HA-peer
    config sync, rollback-to-older-config, `commit confirmed`
    auto-revert, and background full recompiles — advances
    `m.pendingCommitRevision` (assigned at promotion), and every
    OBSERVED-ACCEPTED publish advances `m.acceptedCommitRevision` — superseding any
    debt keyed on an older generation, because the debt's config is
    by definition no longer the accepted one; the new accepted
    config's own precheck owns whatever defer it needs. And the
    nil-config teardown rule (Codex r9 f10): a daemon shutdown or
    bootstrap teardown with NO accepted config cancels any open
    epoch/debt explicitly — they have no accepted owner and must
    not outlive the process that created them (their state dies
    with the daemon; nothing leaks into the next boot, where the
    three-bucket precheck re-derives everything from the active
    config anyway).
- **Completion requires a SUCCESSFUL prerequisite — and the
  prerequisite has a PHASE-COMPLETE precheck, an epoch-open debt,
  and applySem serialization (v8.3, Codex r8 f4).** `programRethMAC`
  can fail BEFORE setting the MAC, AFTER setting it but failing
  `setUp` (returns `(true, error)`, daemon_reth.go:257 — and a
  later attempt no-ops on the already-installed MAC, :244, never
  retrying the link-up), or not at all. v8.3's contract:
  - **The precheck opens an epoch only on MAC MISMATCH; a DOWN
    member with a CORRECT MAC is link-recovery, never an epoch
    (v8.4, Codex r8 f4 reconciled with AGY r9 f1).** The
    `rethMACPending` computation (daemon_apply_dataplane.go:45-70)
    stays `mac != desired` per desired member for the epoch
    decision: the defer epoch exists to avoid the mlx5 zero-copy
    EBUSY of MAC PROGRAMMING's link cycle, which only exists when
    the MAC actually needs changing. A member that is
    administratively/carrier down with the MAC already correct
    (unplugged cable, standby member, or the
    restart-after-"MAC installed, setUp failed" case Codex r8 f4
    raised) requires NO MAC programming and therefore NO epoch —
    opening one there would set `deferWorkers=true` on every
    commit while the cable stays out, gating the arm-sync AND the
    pending-retry forever and taking the WHOLE dataplane down over
    one dead member (AGY r9 f1's reproduction of this issue's
    outage mode through the v8.3 precheck). Instead the boot/apply
    precheck classifies each desired member into exactly one of
    three buckets: (i) MAC MISMATCH → epoch opens (both phases);
    (ii) MAC CORRECT but LINK DOWN → a link-recovery entry in the
    MAC debt (link-up phase only, NO epoch, NO latch, NO pending
    marks — the healthy dataplane forwards normally on every other
    interface while the debt re-drives the member's `setUp`; the
    restart case is thus restart-safe by construction WITHOUT an
    epoch); (iii) MAC CORRECT and LINK UP → nothing. An
    out-of-band admin-down of a CONFIGURED RETH member is
    config-authoritative drift (SMR r9 N1): nothing happens until
    the next commit, whose bucket-(ii) recovery entry brings the
    member back up — and the commit never waits for it.
  - **The MAC debt lifecycle starts at epoch OPENING, with
    SYNCHRONOUS in-flow settlement and settlement-driven dispatch
    (v8.4, Codex r8 f4's gate fix + AGY r9 f2's deadlock fix),
    and the debt is THREE TYPED OBLIGATIONS (v8.8, Codex r12
    f7's obligation-preservation fix; v8.7's two collections per
    Codex r11 f7):** `macEpochDebt` holds ONLY bucket-i (MAC
    mismatch → programmed-this-epoch) entries and is the ONLY
    collection that gates completion; the two recovery
    collections NEVER gate (`hasActiveMACDebt` counts
    `macEpochDebt` ONLY, by definition, so a literal
    implementation cannot let an unplugged sibling gate a
    bucket-i epoch — the r10 mixed-case stays dead):
    `macAndLinkRecovery` holds a bucket-i member found DOWN at
    any validation attempt and carries its FULL obligation —
    on link return it re-drives the recovery as a SAFE XSK
    transaction (v8.9, Codex r13 f8; v8.11 restore rule, AGY
    r15 f3 = SMR r15 SMR15-6): the SAME
    `PrepareLinkCycle`/`NotifyLinkCycle` quiescence pair the
    commit path uses (disable ctrl, join all workers, then
    DOWN→MAC→UP) — and EVERY attempt that enters the
    quiesce ENDS with a restore (the `NotifyLinkCycle`
    rebind + ctrl re-enable) on EVERY outcome — success,
    phase failure, or abort — so the dataplane returns to
    the pre-attempt RUNNING state before the backoff (the
    v8.10 abort could leave the box stopped for the whole
    backoff, indefinitely on a persistent failure; the
    restore is idempotent — the plan-binded sockets
    re-create). The debt then retries the failed phase from
    RUNNING, not STOPPED. A member whose link returns
    DURING an in-flight batch's quiescence DEFERS to the
    next attempt — and the batch's flow is
    REPAIR-BEFORE-REBIND with a renewed settle (v8.12,
    Codex r16 f12's executable choice, replacing v8.11's
    absorption/revalidation sketch, which either no-oped
    (the convergence arms per the coherent vector
    regardless) or downed the whole dataplane via the
    enabled gate (SMR r16 SMR16-1's two bad readings)):
    Prepare (quiesce) → validate-and-program MACs for ALL
    due members (including arrivals absorbed at the
    re-Claim — absorbed members' MAC programs happen
    INSIDE the batch's program phase, BEFORE the settle,
    so no second link cycle and no wrong-MAC rebind) →
    the 1s settle → the global rebind. The
    selective-rebind-hold alternative (excluding a member's
    slots from the global rebind (rebind.rs:41-71
    reconciles every registered binding globally, with no
    member hold set)) is REJECTED — a new primitive not
    needed when the program happens pre-settle. A member
    whose link returns AFTER the batch's program phase but
    before its rebind is handled by the DEBT'S NORMAL
    BACKOFF RETRY (v8.13, Codex r17 f10 = AGY r17 f7 =
    SMR r17 SMR17-7: the v8.12 "event-fired first-fire
    attempt with NO backoff" is DELETED — NO passive
    link-event machinery exists in production (the sole
    `NotifyLinkCycle` call is the apply flow's; the
    general link monitor emits SNMP traps only,
    daemon_flow.go:725-749), so there is no event source
    to fire it from, and even with one the attempt would
    queue FIFO behind the batch's own applySem hold and
    every earlier owner, adding queue delay + RPCs +
    programming + settle + a SECOND whole-dataplane
    quiesce the v8.12 text neither admitted nor
    budgeted). The batch's global rebind DOES bind the
    late member's slots — with its FACTORY MAC (the
    rebind reconciles every registered binding globally,
    rebind.rs:41-71, and the member's MAC obligation is
    the debt's, not the batch's) — and that is ACCEPTED
    and stated honestly: the member forwards with a
    factory MAC (a partial-path blackhole for flows
    hashed to it — peer frames to the virtual MAC drop
    at that member) from the batch's rebind until the
    debt's next attempt (5s initial backoff) programs
    its MAC and rebinds — an exposure of backoff +
    FIFO queueing + the transaction, NOT "~1s" (the
    no-priority posture (AGY r16 f8, below) already owns
    this latency class for the recovery itself). A `programRethMAC`
    call is NEVER a "revalidation": on mismatch it
    executes a DOWN→MAC→UP cycle (daemon_reth.go:238-270) —
    programs happen only in the batch's program phase or
    an attempt's own flow, never inside a rebind (a
    program there double-cycles: the rebind just bound
    fresh sockets and the program's DOWN→UP kills them —
    and any MAC work after the settle sleep requires a
    RENEWED settle before rebind, or the NIC/XSK race
    returns). The only read-only use is a MAC-match
    ROUTING check (which phase a member needs) — and it DEFERS to the
    next attempt only when it cannot be absorbed, v8.11
    SMR r15 SMR15-9) — a GLOBAL quiesce-all + rebind-all
    outage per recovery completion (batched per due set),
    explicitly accepted and budgeted
    (a RETH member recovery is a rare, operator-visible event;
    the outage is the same class as the existing linkcycle
    recovery the box already accepts on commits; a targeted
    per-member quiescence is a named follow-up, NOT this PR —
    the alternative (bare `programRethMAC`'s internal
    DOWN→MAC→UP without quiescence) risks live-XSK/UMEM
    corruption and is rejected) — followed by the complete
    post-cycle repair sequence (DAD/link-local,
    RX-VLAN, VLAN child MACs, VIP/VRRP, announcements, RA,
    AND proxy-ARP/NDP (daemon_apply_dataplane.go:408-411 —
    the v8.8 list stopped short; a non-commit cycle
    otherwise waits up to 30s for the reassert,
    daemon_proxyarp.go:220-226)) AND the XSK rebind (Codex
    r12 f7/f8:
    v8.7 transferred a down bucket-i member to a MAC-CORRECT
    recovery class, silently discarding the unprogrammed MAC
    obligation and arming the dataplane with the wrong member
    MAC; and NO production link-UP→rebind machinery exists —
    the sole `NotifyLinkCycle` call is the apply flow's, the
    general link monitor emits SNMP traps only,
    daemon_flow.go:725-749 — so the recovery entry owns the
    rebind itself; the v8.7/SMR-r11-N2 sentence claiming
    otherwise is DELETED). `linkCycled` is recorded when the
    DOWN phase SUCCEEDS (the cycle has begun — a subsequent
    MAC-write failure returning `(false, error)`
    (daemon_reth.go:260-265) cannot erase it, Codex r13 f8).
    The recovery debt CLEARS only on OBSERVED success — the
    post-rebind status showing the member's slots
    bound+ready (NotifyLinkCycle is void today
    (apply.go:130-134); the observed-status rule needs no
    signature change) — a failed recovery attempt retries on
    the debt's backoff. The post-recovery slots need NO
    separate arm path: `stop_workers` preserves
    `registered`/`armed` while clearing socket state
    (stop_workers.rs:14-25) and the rebind recreates them,
    so the enabled gate does not flap (Codex r13 f8 = AGY
    r13 f6's reconciliation question, answered with the
    transaction spelled out); `linkOnlyRecovery` holds
    members whose MAC is CONFIRMED correct and whose link is
    down — bucket-ii at precheck AND bucket-iii members found
    down at the pass-1 reread (v8.8, AGY r12 f5 + SMR r12
    SMR12-5: the pass-1 reread covers ALL desired members,
    not just bucket-i, so a correct/up member that flaps
    after the precheck gets a non-gating `linkOnlyRecovery`
    entry instead of going unmonitored) — re-driving setUp +
    the post-cycle rebind on link return.
    When the epoch opens (defer flag set), the
    `macEpochDebt` opens in
    phase-validation-pending state with every BUCKET-I member
    unvalidated, and settles only when every entry has either
    VALIDATED (MAC installed AND link re-up post-cycle) or
    TRANSFERRED to `macAndLinkRecovery` with its obligation
    intact; a bucket-ii member
    (correct MAC, down — unplugged, standby, or
    restart-after-"MAC installed, setUp failed") recovers
    independently via its `linkOnlyRecovery` entry and NEVER gates the
    epoch's completion (an unplugged member cannot hold the whole
    dataplane down — AGY r9 f1 stays dead in the mixed case too);
    a CONFIGURED-DISABLED member (`disable: true` is authoritative
    config — types_interfaces.go:22; compiler and networkd
    deliberately keep it down, compiler_iface.go:628,
    networkd.go:595) is EXCLUDED from validation AND from link
    recovery (the debt must never fight accepted configuration by
    calling `setUp` on a deliberately-down member); and a MISSING
    member (no netdev) is excluded entirely — its
    correct-MAC-or-not classification can't be made until it
    returns, at which point the NEXT precheck classifies it
    normally (factory MAC → bucket i → that epoch's normal flow;
    no link-up-debt-to-MAC-epoch transition exists or is needed).
    And the settle validation REREADS current link state at EVERY
    validation attempt — the initial in-flow pass (ALL desired
    members) AND every autonomous retry (that attempt's
    outstanding members), immediately before that attempt's netlink
    mutations (v8.7, Codex r11 f7's cohort contradiction fix;
    v8.6 reread at settle time only, Codex r10 f2's
    precheck→validation flap fix:
    `programRethMAC` returns success on MAC equality WITHOUT
    inspecting link state, daemon_reth.go:240, and returns
    `(true, error)` on a final link-up failure,
    daemon_reth.go:238-270, so a member that
    flapped down after a bucket-iii precheck, or a bucket-i member
    whose link cycled down DURING its own MAC cycle, is
    reclassified at the NEXT validation attempt — down now →
    transferred to the matching recovery collection with its
    obligation preserved, NOT a completion gate). A
    permanently-down bucket-i member
    therefore transfers out of the gating set at the FIRST
    autonomous retry (≤5s) and can NEVER keep the epoch open —
    and its MAC obligation is NOT discarded: it sits in
    `macAndLinkRecovery` until the link returns, where the full
    program+setUp+repairs+rebind sequence runs before the
    member can carry traffic. A bucket-i
    member whose link flaps down during its own cycle is bound
    and armed normally by the completion once transferred (the
    XSK binds on the netdev's queues, which exist while the
    netdev is admin-up; the slot passes no traffic while the
    carrier is down — the same posture as any down interface,
    with NO dataplane-wide gate), and the link's return is
    driven by the recovery entry (setUp + repairs + rebind),
    not by any passive link-event machinery (none exists).
    The INITIAL
    `programRethMAC` in the apply flow IS validation pass 1 —
    synchronous, applySem-held — and its per-member results settle
    the validated phases IN THE DEBT, in-flow, before the
    completion dispatch is evaluated (AGY r9 f2's deadlock: without
    in-flow settlement, the tag would evaluate
    `deferWorkers && !hasActiveMACDebt` against a debt the
    background task could not yet settle — applySem was held — and
    send an UNTAGGED rebind that never consumes the latch,
    stranding the epoch forever). So
    `complete_deferred = m.deferWorkers && !m.hasActiveMACDebt`
    means "epoch open AND all `macEpochDebt` prerequisites
    VALIDATED or obligation-preservingly TRANSFERRED" (recovery
    entries irrelevant), and on a
    fully-successful first attempt it fires in the SAME flow. On a
    partial or failed first attempt the unvalidated phases stay
    pending (debt active), completion is suppressed, and the
    autonomous retry drives them after applySem releases — and
    CRITICALLY, the debt's FULL-SETTLEMENT EVENT dispatches the
    tagged completion ITSELF (the retry path's completion: when the
    last pending phase validates or transfers, the debt issues the
    tagged rebind
    rather than waiting for an unrelated event). The debt re-drives
    only the missing phase per attempt, with autonomous backoff
    (5s→10s→30s→60s cap) and an edge Warn per phase transition.
  - **Debt execution ownership + serialization, v8.10
    side-effect-fenced form (Codex r14 f8/f9/f10, replacing
    v8.9's work-pull sketch):** the debt SCHEDULER and ALL
    netlink execution live DAEMON-side (the daemon owns the
    capacity-one `applySem`, daemon.go:485-496, and every
    repair primitive); the debt STATE lives manager-side
    under `m.mu`. The interface remains the PULL pair, now
    with the side-effect fence:
    `ClaimMACDebtWork() (epoch uint64, due []MACDebtWorkItem,
    claimToken uint64, nextWake time.Time)` — the manager (under `m.mu`) returns
    the currently-due work items
    (`MACDebtWorkItem{Interface string; WantMAC [6]byte;
    Phase uint8; Collection uint8; Deadline time.Time}`), a
    monotonic `claimToken` bumped on EVERY debt membership or
    epoch change, AND the scheduler's next wake explicitly
    (an EMPTY Claim carries `nextWake = min(earliest
    Deadline, next backoff tick)` — the v8.10 text's "an
    empty Claim tells the daemon when to wake" was
    impossible (an empty slice carries no deadline, Codex
    r15 f9)); and
    `ReportMACDebtAttempt(claimToken uint64, results
    []MACDebtMemberResult) (settled bool)` — accepted ONLY
    when `claimToken` is current (stale-token results
    discarded wholesale). **The claimToken is re-validated
    before EVERY netlink mutation, not just at Claim/Report
    (Codex r14 f8):** an operator can cancel a member between
    Claim and the work loop's syscall (operator binding verbs
    take `m.mu` but NOT `applySem`,
    manager_status.go:132-179), so the daemon's work loop
    performs a cheap `claimToken` re-read (an `m.mu` read,
    µs-scale) — and the validation is ATOMIC with the
    quiescence (v8.12, Codex r16 f11; hold span pinned v8.13,
    Codex r17 f8 = SMR r17 SMR17-9): the work loop calls
    `PrepareLinkCycleChecked(claimToken) (outcome, error)` —
    ONE manager method that (i) TRY-acquires `m.mu`
    (contention → `RetryLater`), (ii) validates the token
    (bumped → `Stale`), and (iii) on `Valid` ISSUES the
    quiescence — ctrl-disable + `stop_workers` — UNDER THE
    SAME HOLD (each a small request at the 3s
    `controlBaseDeadline` (process_control.go:34-41), so the
    hold is bounded at ~6s, not the 67s class — the operator
    bump between validation and the first irreversible
    action is structurally excluded), then RELEASES `m.mu`
    before the MAC phase begins (Go's `sync.Mutex` is
    non-reentrant: the per-mutation try-lock re-reads resume
    AFTER the release, and the window between release and
    the first MAC mutation is covered by exactly those
    re-reads). The verdicts:
    `Valid` (proceed), `RetryLater` (contended BEFORE any
    ctrl/worker mutation — the loop RELEASES `applySem`,
    keeps the batch AND its claimToken, retries next tick,
    NO unwind — harmonized with the validator's
    tri-state, Codex r16 f11's contradiction catch; a
    try-lock skip AFTER the quiescence has begun is NOT
    RetryLater — it routes through the restore finalizer
    below, because workers may already be stopped), and
    `Stale` (abandon WITH the balanced unwind below). A
    `stop_workers` timeout is UNKNOWN (the helper stops
    every worker and clears socket readiness BEFORE
    replying (stop_workers.rs:7-30), so
    `PrepareLinkCycleChecked` cannot tell "not quiesced"
    from "quiesced, response lost" — the restore therefore
    runs UNCONDITIONALLY after every possibly-landed
    quiesce before `applySem` releases (the idempotent
    rebind covers both). The RESTORE ITSELF is typed
    (v8.12, Codex r16 f11) and its debt is EXECUTABLE
    (v8.13, Codex r17 f9): `NotifyLinkCycle` gains a typed
    result (it is void today and swallows missing-process,
    ctrl, rebind, and status-application failures
    (process_linkcycle.go:184-224; even ctrl re-enable
    ignores errors (:102-116))) — a failed restore records
    a RESTORE DEBT (daemon-side, its own retry at
    5/10/30/60s with an edge Warn and NO terminal cap —
    the pending-activation retry's posture, since a
    stopped-worker recovery needs no state change), with
    explicit policies per failure mode: missing process →
    the respawn path FOLLOWED BY a daemon-owned REVISED
    FULL APPLY (the re-sync's applyConfigLocked shape,
    re-reading `ActivePair()` — a respawned helper holds
    ZERO stored state, so rebinding an empty helper can
    never restore forwarding; the paired replay is the
    only correct restore); ctrl error → the restore
    debt's own retry; rebind error → the RESTORE DEBT
    itself (NOT the #5134 worker-arm debt, v8.13's
    correction — the #5134 debt self-clears when the last
    snapshot is already non-deferred
    (manager_worker_arm_5134.go:50-54), so routing an
    ordinary recovery's rebind failure there would clear
    the debt while every worker stays stopped); status
    error → the poll reconciles (the status loop is
    ensured right after `ensureProcessLocked`, §5-C retry
    ownership). The
    abandoned batch's daemon-side finalizer — NOT generic
    later recovery — runs that restore before releasing
    `applySem`, so a failed unwind can never leave every
    worker stopped with no owner.
    The test is
    realizable by construction (Claim → operator cancellation
    bumps the token → the loop's next pre-mutation
    revalidation stops it — zero FURTHER mutations; the
    v8.9 test's "Claim returns a stale token" shape was
    impossible and is deleted). `Deadline` gains its
    consumer: the scheduler's next wake = `min(earliest due
    item's Deadline, next backoff tick)` (an empty Claim
    tells the daemon when to wake, Codex r14 f8).
    **Recovery quiescence is PROVEN, not assumed (Codex r14
    f9):** `PrepareLinkCycle` gains an `error` return
    (§6 — it is void today and its implementation ignores
    ctrl-disable failure and merely logs-and-returns on
    `stop_workers` failure, process_linkcycle.go:145-162);
    a quiescence FAILURE (ctrl-disable or stop_workers
    error) ABORTS the recovery attempt outright — NO
    DOWN→MAC→UP on live UMEM — and the debt retries at its
    backoff. Multiple currently-due members BATCH: ONE
    quiesce covers the whole due set in a single
    transaction (no back-to-back whole-dataplane quiesces
    per member). A post-quiescence phase failure retries
    ONLY the missing phase (never the whole recovery — the
    physical repair already succeeded). The observed-clear
    predicate counts only REGISTERED slots' bound+ready
    (raw `Ready` = `registered && bound && xsk_registered
    && heartbeat_fresh` and ignores `armed`
    (refresh_bindings.rs:253-261), so a registered
    operator-DISARMED slot clears correctly; an
    operator-UNREGISTERED slot can never become ready and
    its cancellation already removes its entries via the
    member-removal rule — the wedge AGY r14 f3 feared is
    closed on both ends, Codex r14 f9's refinement).
    **Lock hierarchy + HONEST fairness (Codex r14 f10):**
    `applySem > m.mu`, ONE direction — "no SYNCHRONOUS
    manager→daemon call while holding `m.mu`" (async
    enqueue is the `OnXSKBound` shape); `applySem` is
    daemon-private (the m.mu → applySem half is
    unconstructible, AGY r13 f4 answered). Attempts
    BLOCKING-acquire `applySem` with NO timeout — FIFO
    position is preserved, so progress is GUARANTEED by
    FIFO wake plus bounded owner holds FOR ALL
    USERSPACE-BOUNDED OWNERS (a commit's whole-pipeline
    hold is several minutes of sequential ~67s-capped
    control requests (process_control.go:31-56/:85-103),
    never infinite) — with the honest exception restated
    (v8.13, Codex r17 f11): helper teardown is NOT
    userspace-bounded — Rust worker stop performs
    blocking thread joins (worker_manager.rs:141) and
    `stopLocked` performs an unconditional `<-done` after
    `Kill()` (process.go:231-244), so a D-state or
    unreapable helper process has NO deadline while an
    apply owner holds `applySem` inside `stopLocked`. No
    userspace design can bound that class (abandoning the
    reap wait would let a respawn race the corpse's
    AF_XDP sockets — strictly worse); the escape is the
    60s Warn (visibility — it names the wedged owner)
    plus the systemd outer bound (`TimeoutStopSec` +
    `Restart`, the supervisor's SIGKILL-and-restart that
    clears even a D-state corpse eventually). The
    guarantee is therefore: progress for every owner
    whose hold is userspace-bounded, and surfaced-not-
    silent for the one kernel class that is not — plus a queued-state Warn REPORTED
    EVERY 60s while waiting (visibility; the v8.10 retry-with-timeout
    forms all lost FIFO position on every retry, so
    SUSTAINED legal arrivals could starve the attempt
    forever, Codex r15 f11 — a no-timeout queue cannot be
    starved by legal owners, and a wedged owner is a bug
    the Warn surfaces, not a legal state the design must
    price). The recovery's FIFO position carries NO
    priority (v8.12, AGY r16 f8): under high control churn
    an urgent recovery can queue behind minutes of legal
    holds — ACCEPTED, because the dataplane runs the
    accepted config meanwhile (fail-closed is safe; the
    recovery is not latency-critical) and the queued-state
    Warn (v8.13 lifecycle, Codex r17 f15 = AGY r17 f8 =
    SMR r17 SMR17-8: keyed on the work item's FIRST-QUEUE
    timestamp with PERIODIC 60s reporting while queued —
    a `RetryLater` release-and-requeue CONTINUES the same
    episode (the first-queue timestamp is unchanged), so
    sustained `m.mu` contention can never keep the Warn
    dark, and the one-shot edge form is deleted)
    surfaces the wait; a skipped attempt retries
    at its own backoff. `ClaimMACDebtWork`,
    `ReportMACDebtAttempt`, AND the work loop's per-mutation
    `claimToken` re-read are ALL TRY-LOCK-OR-SKIP on `m.mu`
    (v8.11, AGY r15 f6 = SMR r15 SMR15-4: v8.10 left the
    per-mutation re-read blocking, so the status loop's
    120s control request monopolized `applySem` behind it —
    a contended re-read now skips the mutation to the next
    backoff tick with the work item still claimed; no stall,
    no monopoly);
    fixed-cadence retries cannot
    starve a commit because the commit's own acquire is
    FIFO-ordered ahead of the next retry). The #5134
    `pendingWorkerArm` Boolean is epoch-qualified (records
    the commit revision) and CLEARED on supersession
    (Codex r13 f9's stale-suppression class).
  - Contract rules kept from v8.2, collections named (v8.8):
    a NEWER accepted config
    supersedes (cancels) ALL THREE collections BEFORE any stale MAC work runs —
    its own precheck owns the new epoch; a member REMOVED from
    config cancels only its own entries IN EVERY collection
    (SMR r7 N2, v8.8 collection-explicit); the debt
    records its completion-mode history (live vs cycle,
    including the sticky `linkCycled`) so the
    eventual dispatch picks the right path; a permanently broken
    member leaves the box fail-closed, Warn-visible,
    pending-visible — the operator's to fix. The `complete_deferred`
    rebind flag is set only when the cycle followed a successful
    (both-phase) MAC program.
- **The completion CONSUMES the latch — on BOTH sides of the
  process boundary (v8, Codex r6 f8's Go-shadow-latch).** Helper
  side: a successful `complete_deferred=true` rebind sets the
  stored snapshot's `defer_workers=false` inside the armed leg on
  `Ok`, before write-back/refresh/persist (v7.1, one mutation one
  write; never on `Err`). **Go side:** the same successful
  completion clears `m.lastSnapshot.DeferWorkers` (and the
  `publishedSnapshot` copy if distinct) — otherwise the NEXT
  route-overlay or scheduler republish, which clones the cached
  snapshot wholesale (manager_overlay.go:188,
  manager_compile.go:575), RE-LATCHES the helper into
  `defer_workers=true` after it was consumed (Codex r6 f8's
  verified re-latch). **Idempotency (Codex r6 f8's 3s-vs-10s
  point):** a tagged completion that times out on the 3s control
  deadline (process_control.go:33) but lands (10s worker readiness,
  bringup.rs:30) is safe to retry — a second tagged rebind against
  an already-consumed latch is a no-op convergence over an
  already-bound plan. And EVERY authorized defer
  exit clears ALL THREE latch authorities in the same operation
  (Codex r10 f4's ownerless re-latch fix; the FULL exit
  enumeration with per-exit clean AND UNKNOWN-outcome handling
  is the §5 "Ownership model" list (a)-(f), v8.7 Codex r11 f5):
  (a) the manager `deferWorkers` flag, (b)
  the helper's stored `defer_workers` latch (where applicable —
  the operator arm clears it in the same handler write, Codex r8
  f9's dual-cache afterlife: without it the stored
  `defer_workers=true` would block convergence of FUTURE pendings
  until the next apply), AND (c) the Go cache
  `m.lastSnapshot.DeferWorkers` (and `publishedSnapshot` copy if
  distinct) — otherwise the NEXT route-overlay or scheduler
  republish, which clones the cached snapshot wholesale
  (manager_overlay.go:188, manager_compile.go:575), RE-LATCHES the
  helper after the exit with no remaining completion owner
  (Codex r6 f8's verified re-latch, generalized). And ANY operator arm (global or
  per-binding) resets the pending-retry clock (v8.4, AGY r9 f4):
  `m.pendingRetryAttempts = 0` and `m.pendingRetryNextAt` zeroed —
  an operator who armed the system after a deep backoff expects the
  next pending state to retry at the 5s initial interval, not at
  the inherited 60s floor.
- **The tagged completion RETRY (Codex r6 f7a) — and the tag's
  provenance gate (AGY r7 f1).** A failed tagged
  rebind leaves the latch set and the slots pending; the generic
  untagged retry cannot consume the latch. The completion retry
  therefore re-sends the TAGGED rebind (backoff-shaped, same
  schedule as the generic retry) while the SAME defer epoch is open
  (flag still set, same config generation) — epoch expiry (a newer
  commit pends its own defer, or a global disarm) abandons it. The
  tag itself is issued as `CompleteDeferred:
  m.deferWorkers && !m.hasActiveMACDebt` (AGY r7 f1): an open
  defer epoch AND a clean MAC state — so a spurious or flap-driven
  `NotifyLinkCycle` (or one fired while the MAC-retry debt is
  active) sends an UNTAGGED rebind instead and can never consume
  the latch or arm slots against a wrong MAC. And the tagged completion
  itself carries `expected_config_epoch` (v8.8 token, Codex r12
  f2/f4; the v8.7 `ConfigGeneration` token and v8.6's
  `m.publishedSnapshot.Generation` token are both dead — v8.6's
  was overlay-contaminated, and v8.7's was Go-internal while the
  helper's stored generation advances on EVERY full-apply
  producer: route overlays (manager_overlay.go:188-250),
  scheduler republishes (manager_compile.go:575-621), and the
  #5134 clone-republish (manager_worker_arm_5134.go:57-92), with
  the helper storing each (snapshot.rs:150-155) — so both
  predecessors false-refused legitimate completions after
  ordinary churn; SMR r12 SMR12-1 + AGY r12 f2 found the same
  hole independently): the rebind request includes the debt's
  `commit_revision`, and the helper's rebind handler REFUSES a
  completion whose expected epoch differs from its stored
  snapshot's `commit_revision` (stale-completion
  error, retryable, NO mutation), the check ordered FIRST
  in the handler — before any binding-field clearing
  (rebind.rs:42-50 clears live fields before reconciling today),
  teardown, reconcile-entry increment, latch change, or
  persistence (Codex r11 f4's ordering fix). Because the epoch
  travels ON THE WIRE inside every full apply (§6) and moves
  ONLY when a NEW compiled config is accepted — clone-republishes
  and overlays carry the SAME epoch — no ordinary churn can
  false-refuse a legitimate completion, and a stale epoch's
  tagged rebind can never consume a landed-but-unacknowledged
  successor's latch (the helper's stored epoch is the
  successor's).
  **UNKNOWN-outcome ownership, v8.10 divergence-fired re-sync
  (Codex r14 f6, replacing v8.9's self-prohibited debt):**
  Go treats a timeout/EOF apply as NOT accepted
  (the flag rolls back, A's debts stay alive, NO revision
  moves — Compile commits its bookkeeping only after a
  clean response, manager_compile.go:350-365, while the write
  can land before response decoding fails,
  process_control.go:145-161; the staged snap is DISCARDED, and
  the next send's `publication_rev` is strictly newer
  regardless). The v8.10 owner is the RE-SYNC DEBT, a
  distinct debt type with its own lifecycle — NOT keyed on
  the accepted revision (v8.9 keyed it on
  `m.pendingCommitRevision` and then gated its firing on
  `accepted == key`, which prohibited it from ever firing
  during the only useful interval): it FIRES whenever the
  status poll observes divergence IN EITHER DIRECTION (v8.11,
  AGY r15 f2 = SMR r15 SMR15-5) —
  `status.commit_revision > m.acceptedCommitRevision` OR
  `status.publication_rev` ahead of the last observed value
  (helper-AHEAD), OR `0 < status.commit_revision <
  m.acceptedCommitRevision` OR `status.publication_rev`
  behind with a nonzero stored value (NONZERO helper-BEHIND:
  an incomplete persist or an older-but-real helper state —
  the v8.10 helper-behind clause covered only the
  echoes-0 case (→ startup re-apply), so a nonzero-behind
  helper matched NEITHER owner and diverged permanently);
  the echo-0 helper-behind case keeps the startup re-apply
  owner. Both directions drive the same ACTIVE-CONFIG
  re-apply (the strictly-greater publication rule accepts
  the newer send; the carried `commit_revision` is the
  active config's identity).
  It CLEARS only on the observed acceptance of the
  re-apply's `publication_rev` AND the active config's
  `commit_revision` in a successful status), never on an
  unrelated clean status. Execution: the poll RECORDS the
  debt under `m.mu` (enqueue-after-unlock — no synchronous
  manager→daemon call while holding `m.mu`; the dispatch
  rides a bounded channel the daemon drains, the
  `OnXSKBound` shape, maps_sync.go:451-456); the daemon's
  scheduler drains it, acquires `applySem`, re-reads the
  ACTIVE config FROM THE CONFIGSTORE AT DRAIN TIME (and on
  EVERY backoff retry — latest-wins: a chain of
  timeout-but-landed B then C converges on the newest
  commit, and a drain that finds a NEWER observed
  divergence re-keys and proceeds with the newest, SMR r14
  SMR14-3), and drives the dataplane RE-APPLY of that
  active config through a REVISED `applyConfigLocked` —
  the daemon's own no-promotion, semaphore-already-held
  apply path INCLUDING the three-bucket RETH precheck and
  MAC-debt creation (v8.11, Codex r15 f7: a literal
  `d.dp.ApplyConfig` BYPASSES the precheck
  (daemon_apply_dataplane.go:45-72) and would "recover" a
  timeout-landed DEFERRED B by publishing it without
  recreating B's MAC obligation — arming workers before
  B's RETH MAC is safe (the issue's terminal class); and
  `d.applyConfig` would re-acquire the `applySem` the
  drain already holds) — NOT a new configstore commit, so
  the carried `(config, commit_revision)` pair is the
  active config's OWN (matching the landed helper state
  and transported as the explicit
  `applyConfigLocked(ctx, cfg, commitRevision)` argument
  sourced from the SAME `ActivePair()` read (v8.13, Codex
  r17 f3's stale-reference fix — the v8.11
  `SetActiveRevision`-under-applySem mechanism is
  deleted), and the send mints a strictly-greater
  `publication_rev` the
  helper's refusal accepts). Explicit transitions (Codex
  r14 f6): nil `ActiveConfig` → skip + backoff (nothing
  committed yet); channel saturation → record-and-backoff
  (the debt persists, the next drain retries); `applySem`
  acquire timeout → retry at the debt's backoff; re-apply
  failure (publish error or another UNKNOWN) → retry at
  backoff + edge Warn; the debt NEVER cancels A's surviving
  debts and never itself mints a commit revision.
  **Universal compile reservation, v8.11 single-call-site form
  (AGY r15 f1 = SMR r15 SMR15-1, replacing v8.10's
  self-clobbering two-site form):** the reservation is set
  EXACTLY ONCE per apply, by the DAEMON at the apply-flow
  entry: `StartCompile(rethMACPending)` — ONE `m.mu` section
  setting `m.deferWorkers = rethMACPending` AND
  `m.compileInFlight = true` — called immediately before
  `ApplyConfig` at the precheck's decision point
  (daemon_apply_dataplane.go:69-72's context, for BOTH the
  deferred and non-deferred cases; the false case explicitly
  resets any stale flag — a deferred A whose completion
  failed left `m.deferWorkers=true`, and a no-MAC B or the
  mandatory live-MAC re-apply
  (daemon_apply_dataplane.go:466-489) must never publish
  from it). `Compile` NEVER calls `StartCompile` — it
  REQUIRES a reservation from the CURRENT applySem-held
  apply and CANARY-ASSERTS one exists OR creates a DEFAULT
  (`rethMACPending=false`) one when none does (v8.12, AGY
  r16 f3: manager-internal and direct `Compile`
  invocations — HA peer-config sync's apply path,
  background recompiles, unit tests, and the direct CLI
  path (pkg/cli/apply.go:196-200,
  legacy_dataplane.go:190-195) — reach `Compile` without
  the daemon's apply-flow entry having run, and a bare
  assertion would panic on legitimate paths; the
  default-false rule preserves them, and the daemon's
  apply flow always SETS its own reservation BEFORE
  `ApplyConfig`, so an existing one is only ever asserted,
  never overwritten — v8.10's two-site form let
  Compile-entry's `StartCompile(false)` clobber the
  precheck's `StartCompile(true)` in the same apply,
  publishing a deferred config non-deferred and arming
  workers on unprogrammed RETH MACs;
  `ApplyConfig(ctx, cfg)` has no options argument
  (apply.go:37-40), so the intent must live in the
  reservation, not the call signature — v8.12's
  `ApplyConfig(ctx, cfg, commitRevision)` extends the
  signature with the revision explicitly). EVERY Compile exit
  clears `m.compileInFlight` — success, build failure,
  publish failure, panic/recover (a Compile-internal
  `defer`), AND the apply flow's own abort paths
  (pre-Compile exits at daemon_apply_dataplane.go:126-135,
  manager.go:348-355's early returns) — all routed through
  — and the reservation itself is a PREDECESSOR-CHAINED
  TOKEN WITH RECORDED OUTCOMES (v8.12, Codex r16 f10,
  replacing v8.11's boolean capture; the recorded-outcomes
  completion is v8.13, Codex r17 f7 — the v8.12 form
  discarded non-head Finishes, which REPRODUCED the ABA:
  T2's captured prior IS T1's `{defer=true, inFlight=true}`,
  T1's Finish while T2 was head was a no-op, and T2's
  pre-publish failure then restored `{true,true}` —
  resurrecting T1's inFlight after T1 had returned):
  `StartCompile(rethMACPending) reservationToken` (§6 — it
  RETURNS the token; the manager state lists the chain:
  a head pointer, a node registry, and a monotonic ID
  counter) — each node carries the PRIOR pair AND its
  PREDECESSOR node's ID; `FinishCompileReservation(token,
  outcome)` on a NON-HEAD token RECORDS the outcome on
  its node (never discarded); a Finish on the HEAD
  applies its own outcome AND REPLAYS the recorded
  outcomes of any completed predecessors in chain order
  (so T1's ACCEPTED lands even though T1 finished while
  T2 was head — the terminal state is the fold of every
  recorded outcome, and T1's `{true,true}` is never the
  final word once T1's own Finish recorded otherwise).
  The outcomes: ACCEPTED (the new intent
  authoritative), PRE-PUBLISH FAILURE (restore the head's
  captured prior — a received error RESPONSE (the helper's
  rollback guards (snapshot.rs:33-105) mean nothing
  landed)), UNKNOWN (a timeout/EOF/partial-write — the
  epoch's debts stay alive; the re-sync owns), PRE-SEND
  (a dial/marshal failure — a no-op, no state change),
  PENDING-XSK STAGED (v8.12's new outcome, Codex r16 f10:
  the pending-XSK return (manager_compile.go:272-313)
  stages the snapshot WITHOUT publishing — the reservation
  STAYS OPEN (inFlight=true) WITH ITS TOKEN STORED for
  the deferred-publish leg (v8.13, Codex r17 f7's
  ownerless-leg fix), and that leg finishes it; a NEWER
  `StartCompile` FINALIZES an orphaned open predecessor
  as OVERLAP (SMR r17 SMR17-5 = AGY r17 f5 — the chain
  head moves and the staged leg's later Finish is a
  no-op by token, so `m.compileInFlight` can never wedge
  true and freeze the (v) latch echo); a helper DEATH
  before the leg finalizes it UNKNOWN (the respawn path
  owns the outcome)), POST-ACCEPTANCE TAIL FAILURE (the publish
  landed clean; the new intent stands and the tail's own
  retry owns the rest (manager_compile.go:353-410's
  status/HA/forwarding failures)), and OVERLAP (a newer
  reservation supersedes — the older token's Finish is a
  no-op, and a send from a STALE token is refused by the
  common primitive's freshness token (§5-C epoch contract)
  so a same-revision reshape from T1 can never publish
  after accepted T2). PANIC outcomes classify by phase
  via the Compile-internal `defer` (v8.13, Codex r17 f7):
  pre-wire (before any send byte) → PRE-SEND; after a
  possibly-landed write (send returned without a decoded
  response) → UNKNOWN; after observed acceptance →
  POST-ACCEPTANCE TAIL. A send's token validity is checked
  at SEND time (not just at Finish): T1's publish after
  T2's acceptance dies on the freshness token AND the
  commit-level supersession (T2's acceptance advances
  `acceptedCommitRevision`, superseding T1's debts — a
  same-revision T2 has no commit-level supersession and
  needs none: the freshness token covers it). And the
  direct CLI Compile path (pkg/cli/apply.go:196-200,
  legacy_dataplane.go:190-195) gets an EXPLICIT default
  reservation (revision 0, deferIntent false, a distinct
  CLI-scoped token) — never a missing reservation.
  `FinishCompileReservation` is the ONLY clear path; the
  `ClearCompileReservation()` of earlier text is DELETED
  as a separate method (the token mismatch made it
  ownerless). The arm-sync gate reads
  `m.deferWorkers` from the
  reservation point (the mid-compile window is covered for
  BOTH compile kinds), the (v) latch echo skips while
  `m.compileInFlight`, and `snap.DeferWorkers` stamps from
  `m.deferWorkers` in the publish leg's critical section
  (manager_compile.go:330-332, unchanged). The v8.8 "intent
  as a Compile argument" text remains DELETED.
- **The epoch contract, v8.10 two-revision form (Codex r14
  f2/f3/f4/f5/f6; supersedes the v8.9 commit-seq contract,
  whose foundation was false).** `archiveSeq` was the wrong
  authority — a per-process archive-filename/retention counter
  (store.go:233-245) that CommitConfirmed (:395-527),
  HA `SyncApply` (store.go:634-769), and `PromoteRollback`
  (store_commit.go:856-912) do NOT bump, that manual
  `ArchiveConfig` bumps WITHOUT a commit
  (store_persist.go:714-798/:786), that a crash between
  `Add(1)` and the async archive write lets a restart reseed
  and REUSE, and that no commit's config object carries
  (config.Config has no revision field, types.go:270-289;
  `ActiveConfig` returns only the pointer,
  store_format.go:55-60; `ConfigSink.ApplyConfig` accepts only
  that pointer, apply.go:37-40). v8.10 carries TWO revisions,
  each correct for its own job:
  **(R1) `commit_revision`** — a REAL durable promotion
  revision: a NEW configstore field assigned AT PROMOTION
  TIME on EVERY accepted-config path — plain `Commit`,
  `CommitConfirmed` confirm, `SyncApply` (HA peer sync),
  `PromoteRollback` (commit-confirmed auto-revert), and the
  boot-recovery promote of an expired confirmed window
  (store_persist.go:171-194) — each of which precedes the
  dataplane apply (daemon_apply_commit.go:194-222/:354-357/
  :489/:645-697), persisted ATOMICALLY with the active config
  it names (the revision and the config land in the same
  store write, so a crash can never leave a revision the
  config doesn't have, and a restart reads the ACTIVE
  config's revision — never an archive filename's), and
  exposed via a new `ActiveConfigRevision() uint64` store
  API. **Rollout and transport (v8.11, Codex r15 f3):**
  (a) MIGRATION — existing `active.json` files carry no
  revision; `Load` assigns a migration revision of 1 to a
  legacy active config AT LOAD (a legacy config and a
  just-upgraded helper (stored 0) meet at the legacy-zero
  mode below — the upgraded node is NOT stuck at zero: the
  first post-upgrade promotion assigns the next durable
  value from the store's high-water, which a rewritten
  legacy `active.json` carries forward); a DOWNGRADE policy
  is pinned (envelope readers ignore unknown fields but old
  writers must NOT silently erase the revision — a
  min-reader version on the envelope
  (envelope.go:258-312/:170-189), so an old daemon REFUSES
  a revisioned file instead of erasing it);
  (b) TRANSPORT, v8.12 paired-argument form (Codex r16 f4,
  replacing v8.11's unbound scalar setter): the
  `(config, revision)` pair travels AS AN ARGUMENT —
  `ConfigSink.ApplyConfig(ctx, cfg, commitRevision)` (the
  interface signature grows the explicit revision parameter
  (apply.go:37-40 — a REQUIRED field, never an optional
  type assertion (which would silently restore
  revision-zero on a forgotten call)), and
  `Manager.Compile(cfg, commitRevision)` receives it the
  same way — no manager-global scalar can be interposed by
  a second Compile (overlapping Compiles are documented
  reachable, maps_sync.go:1266-1270). Every daemon→manager
  apply path sources the pair from ONE store getter,
  `ActivePair() (*config.Config, uint64)` — a single
  `s.mu`-held read returning the active config AND its
  revision atomically (the background persistence retry
  takes `s.mu` without `applySem`, so two separate getters
  could interleave; one is required): the central apply
  path (daemon_apply_commit.go:172-246/:527-575), the HA
  peer path (:331-357/:489), the auto-revert path
  (:629-697 — `prevCfg=nil` correctly makes no dataplane
  call (:651-683)), the boot path
  (daemon_run_bringup.go:516-520 reads the pair UNDER the
  wrapper's applySem hold (v8.13, Codex r17 f3: the read
  moves inside `daemon_apply.go:49-56`'s acquisition — a
  read-before-acquire could pair a migrated revision with
  a pre-migration config)), and the mandatory live-MAC re-apply
  (daemon_apply_dataplane.go:466-489 — v8.13, Codex r17
  f3 = AGY r17 f4 = SMR r17 SMR17-3: the second leg
  REUSES THE OUTER TRANSACTION'S ORIGINAL PAIR, captured
  at the apply-flow entry under the same applySem hold
  the whole flow still holds — coherent by construction;
  the v8.12 text's "calls `ActivePair()` itself for its
  second apply" is DELETED: an interposed promotion CAN
  land mid-flow (an operator commit's store promotion
  needs no applySem, AND the persistence transition's
  `s.mu`-only retry (store_persist.go:402) can make a
  gated B durable mid-MAC-program), and a re-read would
  compile and publish the interposed B WITHOUT B's
  three-bucket precheck — arming workers on B's plan with
  A's MACs. B's own queued apply flow (or the exposure
  debt's drain) runs B's precheck as a separate full
  apply; the second leg never re-reads). The feed and
  DHCP queued reapplies REPLACE their captured config
  ENTIRELY with the `ActivePair()` result under `applySem`
  at apply time (daemon_feeds.go:26-41,
  daemon_dhcp.go:85-90 capture BEFORE acquiring
  (daemon_apply.go:49-56/:83-86 acquires inside) — the
  re-read substitutes the CURRENT config, not just the
  current revision, so stale A is never compiled at all
  (fetching revision B while compiling captured A was
  v8.11's remaining tear, Codex r16 f4's DHCP/feed row).
  The direct CLI Compile path (pkg/cli/apply.go:196-200,
  legacy_dataplane.go:190-195) passes revision 0
  explicitly (the legacy-zero mode below).
  (prevCfg=nil → bootstrap, daemon_apply_commit.go:645-697)
  does NOT call the dataplane and needs no revision there —
  the bootstrap's own first apply assigns through the
  normal path.
  `writeTreeMarked` (db.go:431-461) is the single durable
  temp/fsync/rename write that carries the pair atomically
  on every promotion path. **Option-B durability, v8.12
  exposure-gate form (Codex r16 f2, replacing v8.11's
  reservation model AND the aliasing fallback):**
  SyncApply (store.go:681-769), PromoteRollback
  (store_commit.go:867-946), and expired-window boot
  recovery (store_persist.go:171-228) can currently be
  ACCEPTED while the disk still holds the old pair
  (degrade-not-fail persistence), and v8.11's
  reservation/fallback answers both aliased (B installed
  in-memory and returned (store.go:681-689/:722-769) while
  `ActiveConfigRevision()` answered last-confirmed A — the
  transported pair was (B, A): the helper accepted B
  labelled A, A's debts matched B, B never superseded
  them, and the later persistence confirmation only
  rewrote store state with NO observer, leaving helper and
  manager at A forever with NO divergence signal, Codex
  r16 f2's full trace). v8.12's rule: a promotion whose
  pair write has NOT durably landed is NOT EXPOSED to the
  dataplane at all — the promotion is accepted
  control-plane (the operator's commit stands, recorded
  pending-durable with the store's existing background
  retry), but the dataplane keeps running the LAST DURABLE
  config until `writeTreeMarked` (db.go:431-461) lands the
  new pair — so a config is NEVER transported under
  another config's revision, the aliasing class dies at
  the root, and no allocation journal is needed (the
  exposure gate IS the invariant). **The gate's
  mechanics, v8.13 (Codex r17 f2 = AGY r17 f1 = SMR r17
  SMR17-1 — the v8.12 text asserted the invariant with no
  locus and no re-exposure owner: `persistRetryLoop`
  (store_persist.go:389-465) is an observer-free
  goroutine, so nothing would ever re-expose the
  config).** (i) LOCUS: the daemon's apply flow consults
  the store's pending-durable indicator (the promotion's
  return gains a degraded flag, or
  `Store.PersistDegraded()` consulted inside
  `applyConfigLocked` BEFORE compiling) — a promotion
  with a failed pair write SKIPS its dataplane apply;
  the commit reports SUCCESS WITH a "dataplane exposure
  pending-durable" warning (a commit-result warning plus
  an edge Warn plus `show` visibility — never the silent
  divergence the v8.12 form would have introduced).
  (ii) RE-EXPOSURE OWNER: the DURABILITY-EXPOSURE DEBT —
  a daemon-side, single-flight, latest-wins debt recorded
  when the gate skips an apply; the store's persist-retry
  success leg is observed by the daemon's apply
  scheduler POLLING `PersistDegraded()` on its wake
  cadence (no new store→daemon call direction — the
  scheduler already owns the re-sync/MAC-debt drains);
  the drain acquires applySem, re-reads `ActivePair()`
  (latest-wins — a chain of gated B then C converges on
  C), and drives the REVISED `applyConfigLocked(ctx,
  cfg, commitRevision)` INCLUDING the three-bucket
  precheck and MAC-debt creation — the re-exposure apply
  is a full apply, never a precheck bypass. (iii) the
  ACCEPTED/EXPOSED pair split: HA applied markers key to
  the EXPOSED pair — the `syncAndApply` applied-digest
  stamp (daemon_apply_commit.go:426/:464) happens ONLY
  when the dataplane apply RAN; a gated apply stamps
  NOTHING, so the peer's equal-text suppression
  (daemon_ha_sync.go:474/:549) can never strand B (the
  receiver's re-exposure debt converges locally
  regardless), and the current tails' session/peer
  bookkeeping keys to the exposed config. (iv) the
  legacy-migration retry rides the SAME debt (a failed
  migration write leaves the dataplane in the
  legacy-zero gate AND records the exposure debt; the
  retry landing revision 1 wakes the drain). (v) the
  staged-ahead divergence suppression engages for the
  gate window by design (`m.pendingCommitRevision >
  m.acceptedCommitRevision` while B waits) and LIFTS on
  the re-exposure apply's observed acceptance — bounded
  by the debt's drain, never indefinite. The high-water rule
  stays: a DEDICATED revision counter seeded from
  `max(active.json revision, 0)` at startup, bumped ONLY
  inside the five promotion paths — NEVER from archive
  filenames (SMR r16 SMR16-2 + Codex r16 f2: `archiveSeq`
  is a per-process archive-retention counter reseeded from
  archive names (store.go:233-245, store_persist.go:516-579),
  bumped by manual `ArchiveConfig` WITHOUT a promotion
  (store_persist.go:761-798), and unable to recover a
  revision whose active-pair write never landed — it can
  never serve as the revision high-water). The migration
  allocator is `next = max(active revision, durable
  high-water) + 1`, seeded BEFORE Load's expired-confirm
  recovery runs (Codex r16 f3: Load migrates the legacy
  active to revision 1 AND then runs the expired-window
  recovery promotion in the same Load
  (store_persist.go:110-114/:171-228) — without the
  ordering both would receive 1); the migration write's
  failure policy is bounded retries + Warn with the
  dataplane in the legacy-zero gate until it lands (never
  a silent revision-0, never a hard Load failure) AND the
  exposure debt recorded (iv above);
  and the envelope's supported-reader capability rises to
  2 (the central `stripEnvelope` min-reader check already
  exists (envelope.go:217-255) but today's capability is 1
  (envelope.go:111-127) — raising it makes an old writer
  REFUSE a revisioned file instead of silently erasing
  the revision, the actual downgrade rule). Manual
  `ArchiveConfig` is NOT a
  promotion and never moves it. DHCP/feed/boot re-applies
  do not promote (they
  reapply the active config) and therefore carry the CURRENT
  revision unchanged. Node-local per node (each node promotes
  locally). R1 carries CONFIG IDENTITY: debts key on it,
  completions and fabric fences expect it, the adoption and
  latch gates compare it, and it never pretends to order
  publications.
  **(R2) `publication_rev`** — a manager-minted monotonic
  revision PER FULL-PUBLISH SEND (any of the five producers),
  distinguishing different full snapshots produced from the
  SAME commit (feed-driven reshapes,
  feed_enforcement_test.go:216-252's class), carried as TWO
  distinct high-waters (v8.11, Codex r15 f4):
  `m.mintedPublicationRev` (the send counter: minted at send
  time, BURNED on every send (never rolled back, never
  reused — an ambiguous timeout-but-landed send's rev is
  dead; every wire retry of the same logical send RE-MINTS
  (a retry can never pass the strict-greater rule with a
  reused value), and a COMMON five-producer send primitive
  pins exactly-one-mint-per-wire-attempt)) and
  `m.observedPublicationRev` (the acceptance high-water:
  moves ONLY on a response or poll that PROVES helper
  acceptance — a same-commit send N that lands but times out
  leaves observed < N, so the next
  `status.publication_rev == N` IS ahead and the re-sync
  fires — v8.10's single counter made that divergence
  invisible). The helper REFUSES an `apply_snapshot` whose
  `publication_rev` is not STRICTLY GREATER than its stored
  one AND — the second layer, v8.11 Codex r15 f5 — whose
  `commit_revision` is STRICTLY LESS than its stored
  `commit_revision` (both fail-closed, no mutation, no
  persist: publication order orders SENDS, never config
  freshness, so the config-identity leg is required; a
  legitimate rollback/older-content promote carries a
  FRESHLY assigned commit_revision (every promotion assigns
  one), so it passes the identity leg while its content is
  older). Go's helper-ahead detection compares
  `status.publication_rev` against
  `m.observedPublicationRev`.
  **The COMMON send primitive's freshness token, v8.13
  BUILD-SEQUENCE form (Codex r17 f5 = AGY r17 f2 = SMR r17
  SMR17-2, replacing v8.12's pair-only validation, which
  could not see the same-commit class it existed to close;
  and replacing v8.12's impossible "stamped at BUILD time
  inside `m.mu`" — the build itself runs OUTSIDE `m.mu`
  (manager_compile.go:177-228) and cannot move inside it
  (build helpers self-acquire — bumpGeneration,
  manager_generation.go:33 — and expensive BPF work does
  not belong under the status/control lock)):** the dual
  refusal rejects older commit
  IDENTITY but cannot reject stale CONTENT carrying the
  current revision (T1 builds an older same-commit/feed
  snapshot outside `m.mu`; T2 publishes newer content; T1
  later locks and sends — commit equality and a fresh
  publication mint BOTH pass, and a pair-only send-time
  check passes too because same-commit reshapes SHARE the
  pair). Every full-publish send
  therefore funnels through ONE send primitive (all five
  producers) with TWO entry points (v8.13, Codex r17 f5's
  deadlock fix): a LOCKED entry for callers already
  holding `m.mu` (the auxiliary publishers — route
  overlay, scheduler republish, #5134 — send under `m.mu`
  today) and an UNLOCKED entry that acquires it
  (Compile's publish leg) — never a recursive acquire.
  The primitive's two halves: (i) a CHEAP INPUT-CAPTURE
  section under `m.mu` at build START — it snapshots the
  build's inputs (the `(config, revision)` pair AND the
  feed/overlay state refs the build will read) and mints
  `buildSeq` (ONE monotonic manager counter, ==
  `snapshot_token` on the wire — build order is now
  defined by the capture order, not the lock order at
  send); and (ii) a SEND-TIME validation under `m.mu`:
  the send proceeds only when `buildSeq ==
  m.latestBuildSeq` (no LATER build has captured inputs
  since) AND the captured pair still equals the manager's
  current pair — T1's stale same-commit reshape fails
  (i) the moment T2's capture lands (T2's buildSeq is
  newer), regardless of which lock acquisition happens
  first, and is ABANDONED Go-side; the helper
  additionally REFUSES a `snapshot_token` strictly older
  than the newest it has seen (per helper incarnation;
  `error_code: "stale_snapshot_token"`) as the backstop
  for any race the Go check cannot see (two managers are
  impossible — the control socket is single-client per
  connection but a stale same-host process could exist;
  the refusal is per-incarnation so a respawned helper
  resets). The auxiliary producers (route overlay, scheduler
  republish, #5134, deferred-XSK) all ride the same
  primitive, so no stale same-commit clone can pass either
  layer; and the semantic hash EXCLUDES `snapshot_token`
  (v8.13, Codex r17 f5's dedup fix: builder.go:156-178's
  zero set (Generation, FIBGeneration, GeneratedAt,
  commit_revision, publication_rev) grows to include it —
  a hashed token would make identical builds never dedup
  and the note-CAS path never run).
  **The seed has an acquisition ORDER (v8.11, AGY r15 f4 =
  SMR r15 SMR15-2; tightened per Codex r16 f5; the boot
  retry owner is v8.13, Codex r17 f4):**
  `ensureProcessLocked`'s synchronous PING (process.go:18-29/
  :116-125) runs at the TOP of EVERY `Compile` — BEFORE the
  snapshot build stamps Generation/FIB
  (manager_compile.go:200-217 currently stamps first and
  pings only at :324-325, so a surviving helper's first
  snapshot arrives already stamped with reset legacy values
  and the rollback guard refuses it (snapshot.rs:33-105) —
  the build moves after the ping). The ping is a SMALL
  request at the 3s `controlBaseDeadline`
  (process_control.go:34-41 — SMR r17 SMR17-10's pin:
  not the 67-120s class; on daemon paths it runs under
  applySem + `m.mu`, on direct Compile paths under `m.mu`
  alone, and the spawn path is the pre-existing
  ensureProcess behavior — the manager-lock-delay budget
  already prices this class). NO full-publish producer
  may mint or send before the ping completes (a send
  attempted earlier returns a typed not-seeded-yet error
  — `not_seeded` is MANAGER-LOCAL (v8.13, Codex r17 f6:
  synthesized Go-side before the send, NEVER a wire
  `error_code`)). The retry owner for that abort is the
  daemon-side BOOT-APPLY DEBT (v8.13, Codex r17 f4,
  replacing v8.12's "routes to the standard publish-retry
  machinery," which does not exist for a pre-build abort:
  the production boot calls `d.applyConfig` ONCE
  (daemon_run_bringup.go:516) and the wrapper only logs
  and returns on failure (daemon_apply.go:49-58); the
  status republisher requires a staged `lastSnapshot`
  (process_status.go:10-17) and the status loop starts
  only after the successful Compile tail
  (manager_compile.go:400-414) — neither can own it):
  a single-flight debt recorded by the daemon's apply
  flow on the not-seeded abort, retried on a short
  cadence by the daemon's apply scheduler (the same
  drain that owns the exposure and re-sync debts) until
  the first successful apply; the seeded state is
  INCARNATION-SCOPED (`m.seededPublicationRev` resets on
  every manager-driven (re)spawn, so a post-respawn
  Compile re-pings before re-minting). A manager
  re-init over a SURVIVING helper seeds the LEGACY
  `(generation, fib_generation)` high-waters from the same
  ping echo (the manager's generation restarts at 0
  (manager.go:85-105/:336-345, manager_generation.go:33-38)
  while the surviving helper refuses their rollback before
  side effects — and the FIB high-water is reconciled from
  the echo, not just a Go field (the snapshot's FIB is read
  from the BPF map at build time (manager_generation.go:10-22),
  so a Go-only seed is insufficient; the build after the
  ping carries the echoed values). If any seed is
  unavailable the manager respawns the helper (the existing
  spawn path) —
  the whole-daemon restart case (xpfd restarts the helper
  too) needs no seed (all zeros).
  **The gates consume the two revisions by role:** the
  adoption gate and the (v) latch echo compare
  `status.commit_revision == m.acceptedCommitRevision` AND
  `m.pendingCommitRevision == m.acceptedCommitRevision` AND
  nonzero; the `update_fabrics` fence and the tagged
  completion carry `expected_commit_revision` (config
  identity — clone-republishes and overlays carry the SAME
  commit revision as the config they contain, so no ordinary
  churn false-refuses); divergence suppression watches BOTH
  (`m.pendingCommitRevision > m.acceptedCommitRevision` OR
  `status.publication_rev` ahead of
  `m.observedPublicationRev`).
  **Legacy-zero mode (v8.11, Codex r15 f5):** an old Go
  omits both fields (0,0) and a new helper treats an
  all-zero request as LEGACY-ACCEPT (the pre-epoch
  semantics, documented degrade) UNTIL the first
  epoch-carrying apply lands — which sets stored > 0 and
  EXITS the legacy mode permanently (a later all-zero
  request is refused); a new Go + old helper sees echoed 0
  and fails closed (documented). The v8.10 texts
  contradicting this (strict-greater rejects 0>0 while
  another passage accepted 0==0) are harmonized.
  **Rebase with proof (v8.11, Codex r15 f5):**
  the helper is RESPAWNED on a downward startup divergence
  (v8.12, Codex r16 f6, DELETING the rebase entirely):
  socket ownership is NOT a proof — every request opens
  and closes a NEW Unix connection
  (process_control.go:129-169) and the helper accepts an
  unlimited sequence of independent connections
  (lifecycle.rs:169-179/:384-400), so there is no
  persistent session, nonce, lease, or exclusion of a
  stale same-UID manager; any client can assert any
  Boolean; and a DOWNWARD rebase would open a rollback
  window (an already-queued old request with a value
  between the rebased and former high-waters would become
  admissible). When the startup ping shows
  `stored.commit_revision > ActiveConfigRevision()`
  (helper-higher — the helper holds a newer-but-never-
  store-committed artifact), the manager RESPAWNS the
  helper (the existing spawn path): the fresh helper's
  stored pair is zero (the legacy-zero mode below covers
  the window), and the startup re-apply carries the
  configstore's current pair. The `allow_epoch_rebase`
  concept, its ping-handshake "proof", and the
  first-apply Boolean form are all DELETED — a respawn is
  the only downward authority reset that needs no proof.
  **The gates consume the two revisions by role:** the
  adoption gate and the (v) latch echo compare
  `status.commit_revision == m.acceptedCommitRevision` AND
  `m.pendingCommitRevision == m.acceptedCommitRevision` AND
  nonzero; the `update_fabrics` fence and the tagged
  completion carry `expected_commit_revision` (config
  identity — clone-republishes and overlays carry the SAME
  commit revision as the config they contain, so no ordinary
  churn false-refuses); divergence suppression watches BOTH
  (`m.pendingCommitRevision > m.acceptedCommitRevision` OR
  `status.publication_rev` ahead). **Mixed-version:** all
  lineage-sensitive operations FAIL CLOSED on an observed
  zero revision pair (old helper) until the REQUIRED helper
  restart; an old Go omits both fields (0 == 0 degrade). A
  bootstrap epoch rebase covers the UNCLEAN-reset class
  (AGY r14 f1, narrowed by Codex r14 f3: a clean zeroize
  stops xpfd (server_diag_system_action.go:198-205) and the
  helper never restores state.json (lifecycle.rs:182-204) —
  but an unclean reset can leave the helper process holding
  a stored revision while the store reseeds): the manager's
  FIRST apply after startup, valid only while
  `m.acceptedCommitRevision == 0` (no accepted config),
  the manager RESPAWNS the helper (v8.12, Codex r16 f6 —
  no downward rebase exists: socket ownership is not a
  proof (connection-per-request, unlimited sequence), and
  a downward rebase would open a rollback window for
  queued old requests; the respawn's zeroed stored pair
  needs no proof), and the legacy-zero mode covers the
  fresh-helper window.
  Debts key on the commit revision of the config whose
  precheck created them and fire only while that revision
  IS `m.acceptedCommitRevision` — EXCEPT the re-sync debt,
  which is a distinct type fired by OBSERVED divergence
  (§5-C UNKNOWN-outcome ownership, below), never by its own
  key.
  **Verb provenance, v8.9 wire form (Codex r13 f7):** the
  SAME `set_forwarding_state(armed=...)` verb arrives from
  the public operator API, the automatic
  unsupported-config disarm, and HA desired-state
  reconciliation, and today the helper receives only the
  bool (forwarding.rs:12-33, control.rs:947-951). v8.9 adds
  an additive `provenance: string` field on the verb (§6;
  serde default `"operator"` so an old Go's disarm keeps
  the historical latch-clearing semantics the operator
  expects; a NEW Go tags every automatic disarm
  `"automatic"`). The helper clears the defer latch on a
  FALSE verb ONLY when `provenance == "operator"`; an
  `"automatic"` FALSE disarms the dataplane (fail-closed)
  but leaves the epoch and debts alive (self-healing when
  the cause clears). The UNKNOWN-disarm retry owner for an
  OPERATOR verb is a NEW durable operator-verb retry debt
  (manager-side, keyed on the verb+target, retried on the
  status loop's cadence until observed — the desired-state
  sync cannot own it: standalone desired state is always
  armed, manager_ha.go:363-388); an AUTOMATIC verb's retry
  owner stays the desired-state sync.

**Retry ownership — the Go pending-activation retry, actionable
form (Codex r5 BLOCKER 7; v8 per Codex r6 f7).** v6 marked pending
states but scheduled no production reconcile to converge them:
first-Compile failures returned before `ensureStatusLoopLocked`; a
rollback to a previously-true global no-ops the desired-sync on
equality; a failed tagged rebind only warned; the busy watchdog
requires `Registered && Armed` (zero after S4'). The v8 retry, free
of discrimination because the tri-state makes `pending`
UNAMBIGUOUSLY planner-created:

```
// in the periodic status loop, after syncDesiredForwardingStateLocked:
if m.lastStatus.ForwardingArmed &&          // ACTUAL, not desired
   !m.deferWorkers && !m.pendingWorkerArm && !m.completionInFlight &&
   anyBinding(b => b.Registered && b.Ifindex > 0 &&
              b.ActivationState == "pending") &&
   now >= m.pendingRetryNextAt {
    send plain rebind   // reconciles the CURRENT coherent plan;
                        // convergence arms the pending slots inside
    m.pendingRetryAttempts++
    m.pendingRetryNextAt = now + backoffJitter(attempts) // 5,10,20,60s cap
    if m.pendingRetryAttempts == 12 {
        edge-warn once ("bindings stuck pending activation",
                        fingerprint of the failing slots)
        // keep probing at the 60s floor — recovery is never capped
    }
    // config/link events NEVER touch the attempt exponent (Codex r9 f7
    // + r10 f5): an event storm must not pin worker-set teardowns at a
    // 5s cadence; only an immutable pending-MEMBERSHIP transition (a
    // genuinely new pending identity appears, or one converges) pulls
    // nextAt EARLIER with the exponent preserved
}
```

Predicate details that make it actionable (Codex r6 f7's five
holes): (i) **ACTUAL armed** — the #6165 gate can pin desired=true
while the helper runs disarmed; an untagged rebind there only stops
workers, never converges, so the retry requires
`m.lastStatus.ForwardingArmed == true`. (ii) **REGISTERED pendings
only** — S1/S2's `registered=false, pending` slots cannot be healed
by a non-replanning rebind (E2 re-registration happens at REPLAN;
worker planning skips unregistered bindings, bringup.rs:274), so
they are EXCLUDED from the predicate and converge only at the next
replan-producing apply (any commit; the #5134 debt republish for
its generation) — documented, and visible in `show`. (iii) the two
suppressions (debt ownership, completion-in-flight) from v7.1, with
`completionInFlight` now backed by the defer epoch itself for the
link-cycle flow (flag set) and an explicit in-flight marker for
the live-change dispatch. (iv) **backoff with jitter, rate-capped
forever, NEVER attempt-capped (v8.2, Codex r7 f5):** permanent
failures back off to a 60s floor instead of tearing down the full
worker set every 5s (each cycle: full teardown,
reconcile/mod.rs:330, the 500ms mlx5 quiescence when workers
existed, teardown.rs:54, up to 10s readiness wait, bringup.rs:30 —
all under `m.mu`, process_status.go:162); at attempt ~12 ONE edge
Warn with the failure fingerprint fires — but the retry CONTINUES
at the 60s floor indefinitely, because `WorkerSpawn` failures
include TRANSIENT `pthread_create` EAGAIN/ENOMEM (bringup.rs:49)
whose recovery needs no state/config/link change, and a terminal
cap would recreate this issue's permanent sink through the back
door; the backoff RESETS under an exact clock rule (Codex
r8 f7): the change fingerprint is IMMUTABLE pending identity
MEMBERSHIP only — the set of `(interface, queue_id)` pendings, with
`last_change`/`last_error`/diagnostics EXCLUDED (a failed retry
pass mutates those and would self-reset into a 5s churn loop) —
and a reset only PULLS THE DEADLINE EARLIER (`nextAt =
min(nextAt, now + 5s)`), never postpones an already-due retry (so
frequent config/link events cannot starve recovery into perpetual
deferral); the tagged completion retry (§5-C) is explicitly
EXEMPT from any terminal cap for the same reason. (v) **the status loop is ensured right after
`ensureProcessLocked`** (before the publish at
manager_compile.go:350 and every later error exit, :369/:408) — no
compile failure path can orphan the retry (Codex r6 f7e; the #5873
orphaned-debt pattern generalized). The retry carries its own
attempt counter, backoff state, failure fingerprint, and
edge/rate-limited diagnostics (Codex r6 NIT). This is NOT option B
resurrected: B auto-converged blindly and fought operator disarms;
the v8 retry only schedules the helper's OWN requested activations
and changes no armed bit itself.

**Logging (Codex r5 MAJOR 10 = SMR r5 N1 = AGY r5 minor-1, triple
convergence).** The arm-verb rollback makes the Go desired-loop
retry a failed arm each tick; when the #6165 required-protocol gate
refuses the retry, `process_status.go:241` logs Warn at 1/s
(~86K/day for a permanent mismatch). The sync-failure log becomes
edge-triggered (fire on the false→true transition of the error
state, once on recovery) with a repeated-tick test.

**R3 (kept):** carry {`armed`, `registered`, `activation_state`,
`last_change`} keyed on configured-name `(interface, queue_id)`;
volatile rebuilt downstream; `had_existing` dead; queue-scoped
overrides membership-at-invocation.

**Ownership model (final form):** a slot's non-forwarding state has
exactly three owners, on the record: PLANNER (`pending` — converges
when a successful defer-authorized armed reconcile binds the current
plan; the Go pending-activation retry schedules that reconcile when
nothing else does), OPERATOR (`operator` — never converged, dies
only at a global fan-out), GLOBAL default (`none` — Go-pushed,
fanned out post-reconcile on explicit arms). The defer window's
authorized exits — each with its ALL-THREE latch-authority clear
specified for BOTH clean and UNKNOWN outcomes (v8.8 form, Codex
r11 f5 + r12 f5/f6; the v8.6 "exactly two exits" sentence was
false) — are:
(a) a successful-MAC completion with provenance (tagged rebind or
the mandatory non-deferred re-apply) — clean: all three clear
in-flow; lost response: the helper cleared its stored latch at
apply, and the next successful poll reconciles the manager flag
and the Go cache from the status's echoed
`stored_defer_workers` UNDER THE (v) LINEAGE GATE (§5-C fabric
transaction — epoch match, no staged config, no compile in
flight; an old helper's missing echo (epoch 0) never
reconciles, and a poll racing a staged compile can never
erase freshly-staged defer intent — Codex r12 f6);
(b) epoch rollover / acceptance cancellation at a newer commit —
clean: the accepting full apply stamps `defer_workers` from the
new config, clearing all three; timeout-but-landed: the
ACTIVE-CONFIG RE-APPLY owns it (the v8.8 UNKNOWN-outcome
re-sync: poll observes helper-ahead → re-apply the active
config → observed acceptance → all three settle to the
landed config's values);
(c) an explicit OPERATOR global arm — clean: all three in the
same handler write; lost response: the verb is idempotent — Go
retries it, and the retried verb's success clears all three
(the poll reconciles any interim state);
(d) an explicit OPERATOR-PROVENANCE GLOBAL DISARM (v8.8, Codex
r12 f6's verb-provenance fix): the epoch expires ONLY when the
disarm is operator-provenanced (the manager tags the call
site) — the disarm
verb's handler clears the manager flag AND writes the helper's
stored latch clear in the same control write, the Go cache
updates on observed success; lost response: verb retry + poll
reconcile (as (c)). An AUTOMATIC disarm (unsupported-config
refusal, HA desired-state reconciliation) is epoch-PRESERVING:
the dataplane is disarmed fail-closed but the epoch and debts
survive, so recovery self-heals when the cause clears; the
UNKNOWN-disarm retry owner is the desired-state sync
(independently derived intent, already retried);
(e) NIL-CONFIG teardown (daemon shutdown / bootstrap teardown
with no accepted config): cancels the open epoch and ALL THREE
debt collections explicitly AND clears the manager `deferWorkers`
flag AND `m.lastSnapshot.DeferWorkers` — `stopLocked`
(process.go:197-267) currently RETAINS both, so this is an
additive manager change, not just prose (Codex r11 f5);
(f) HA supersede — an applied peer config mints the node-local
`pendingCommitRevision` and supersedes node-local debts; the latch
authorities converge through the applied config's own publish
(a full apply stamps `defer_workers` from the peer config;
clean → all three on observed acceptance; unknown → the (b)
re-sync owns it);
(g) HELPER RESTART (v8.8, Codex r12 f6 — an authority
transition, not an exit): an unhealthy or config-driven helper
restart (process.go:18-33) resets the helper's stored state
to epoch 0; the next poll observes helper-behind (epoch 0 ≠
`m.acceptedCommitRevision`), the startup re-apply republishes
the current config (its precheck re-instantiates any needed
debts), and all three latch authorities converge on the
observed acceptance.

**What it fixes (delta over v6):** the unregister/disarm collapse
(E2 narrowed); failure-recovery claim destruction + live-sysfs race
+ permanent-empty-vector (plain restoration); the update_fabrics
invariant violation (replan on change); the pre-MAC arm race
(durable defer flag); completion-without-success (MAC-success
gating); the unconsumed defer latch; generationless #5134 debt; the
unscheduled pending sinks (Go pending-activation retry + status-loop
ordering); the sync-failure Warn flood (edge-trigger). **Delta v7 →
v7.1 (round 6):** the convergence gate's caller authorization is now
an explicit `defer_completion_authorized` parameter with the latch
consumed inside the armed leg on Ok — never on Err (AGY r6 f1);
transient MAC failures self-heal via a daemon-side MAC-retry debt
instead of stranding until the next commit (AGY r6 f2); the
pending-activation retry is backoff-shaped with an attempt cap and
suppressed while the #5134 debt or a provenance completion owns the
retry (AGY r6 f3/f4 = SMR r6 N1/N3).

**Size:** failure-path restoration + re-mark (~12), common S4' (~8),
E2 narrowing (~4), update_fabrics replan (~12), daemon clear reorder
+ MAC-success gating + MAC-retry debt (~45), convergence signature +
latch consume (~8), #5134 generation scoping (~12), Go
pending-activation retry + backoff/cap/suppressions + loop-order
(~45), edge-triggered warn (~15), C2/C3 rule sites (~8), Go
`BindingStatus`/`ControlRequest` fields + D predicate (~20),
protocol canary + #4952-pin test updates, docs — PLUS the v8.7/v8.8
additions: the two-revision lineage (`commit_revision`
durable promotion revision (configstore API + assignment on
every promotion path) + `publication_rev` manager-minted
per-send counter + the strictly-greater apply refusal) (~40),
the note CAS verb + supersedable note debt (~15), the
asymmetric latch echo (~4), the causal env token (one-sample,
≤4 ack-set with eviction ownership, incarnation reset,
debounced+aggregate-capped dispatch) (~25), the fabric sync
debt state machine (full-payload key, guard-rejection debts,
readiness query) (~30), the three-obligation debt + all-member
pass-1 reread + the proven-quiescence recovery transaction
(PrepareLinkCycle error, batching, phase-only retry) (~40),
the work-pull Claim/Report + claimToken with per-mutation
revalidation + StartCompile/ClearCompileReservation +
ApplyResult revision (~35), the re-sync debt
(divergence-fired, latest-wins) + full-producer staged
suppression (~20), the operator provenance wire field +
operator-verb retry debt (~15), the bootstrap epoch rebase
(~8), the nil-config `stopLocked` clears (~6), the
rebind/fabric refusal ordering (~8), and the
`stored_defer_workers` echo + gated clear-only reconciliation
(~8) — PLUS the v8.13 additions: the durability-exposure
debt + the store's `PersistDegraded()`/`ActivePair()`
surface and the accepted/exposed marker split (~25), the
build-sequence freshness token (input capture + the two
send-primitive entries + hash exclusion) (~20), the
boot-apply debt (~8), the error_code census (per-producer
+ typed consumer) (~15), the recorded-outcomes
reservation chain (~12), the merged checked quiescence
(~8), the executable restore debt + paired respawn replay
(~20), the single-transaction map_generation (manager
wrapper + seed + capability bit) (~25), and the §9 chain
tests. No
gate-semantics or shim changes; the coordinator identity-copy
change (R3 volatile rebuild, refresh_bindings.rs) IS a
coordinator change and is now acknowledged as one (Codex r10
f6's contradiction fix).
### Recommendation

**Ship option C + option D** — the v7 model: the tri-state
`activation_state` lifecycle (planner-owned `pending`, operator-owned
`operator`, global-owned `none`; the planner NEVER arms and never
restores operator claims), the coherent-vector invariant completed
(plain restoration on the failure path; `update_fabrics` replans on
change), the common-locus S4' failure marking, the two-gated
convergence (armed × defer-provenance), the durable defer window with
MAC-success-gated completion and latch consumption, generation-scoped
#5134 debt, the discrimination-free Go pending-activation retry,
arm-verb rollback feeding the desired loop, the Go arm-sync defer
gate, R3 control-only identity carry, E2 narrowed to `pending` —
plus the state-aware, desired-gated, edge-triggered Go drift
detector. Retreat: none lighter survives review — every simpler
shape died to a named counterexample in rounds 1-5 (arm-at-replan;
leg-scoped activation; ungated marker; bool provenance;
replan-at-convergence gating; replan-on-restore recovery; transient
defer flag; verb-identity completion). **Reject B as Go-converger**
(§5-B) — and note the v7 pending-activation retry is NOT B: it
schedules no arming, only a reconcile of the current coherent plan,
and the tri-state makes its target unambiguous (planner-requested
activations only, never operator claims).

Rationale in one line: non-forwarding state has exactly three owners
— planner, operator, global default — so put the ownership ON the
record, keep the record coherent with the accepted plan by
restoration rather than re-derivation, let activation complete only
where binding actually happened, and give the helper's own
activations a scheduled retry.

## 6. Public API preservation

- **Wire protocol:** additive fields, all with serde defaults,
  no `CONFIG_SNAPSHOT_PROTOCOL_VERSION` bump (the #3091
  additive-with-default precedent):
  1. `BindingStatus.activation_state: string ∈ {"none","pending",
     "operator"}` (serde default `"none"`; old Go ignores it; new Go
     treats missing as `"none"` — old-helper stranding reads as
     drift, the correct mixed-version signal). Go's `BindingStatus`
     gains it as optional.
  2. `ControlRequest.complete_deferred: bool` (serde default `false`;
     old helpers ignore it — safe fail-closed; new Go + old helper:
     the old helper's semantics, safe). Sent only by the
     `NotifyLinkCycle` path after a SUCCESSFUL MAC program.
  3. `ConfigSnapshot.commit_revision: u64` AND
     `ConfigSnapshot.publication_rev: u64` (serde defaults 0;
     v8.10 two-revision form, Codex r14 f2/f3 — REPLACES
     v8.9's `config_epoch`, whose `archiveSeq` foundation was
     not a commit sequence): `commit_revision` is the
     configstore's durable promotion revision (assigned at
     promotion time on every accepted-config path, persisted
     atomically with the active config, read via
     `ActiveConfigRevision()`); `publication_rev` is the
     manager-minted monotonic per-send revision (burned on
     every send, seeded at startup from the helper's echo).
     The helper stores both from each accepted apply and
     REFUSES an `apply_snapshot` whose `publication_rev` is
     not STRICTLY GREATER than its stored one. Old Go omits
     them (0); old helpers ignore them.
  4. `StatusSnapshot.commit_revision: u64` AND
     `StatusSnapshot.publication_rev: u64` (serde defaults 0;
     v8.10): the stored pair echoed into every full status —
     the lineage values for the adoption gate (iii), the latch
     echo gate (v), divergence suppression, the helper-ahead
     detection (publication_rev), and the fence/tag
     (commit_revision).
  5. `ControlRequest.expected_commit_revision: u64` (serde
     default 0 = "no expectation"; old helpers ignore it;
     v8.10, REPLACING `expected_config_epoch` before it ever
     ships). Sent on
     the tagged completion rebind (the debt's commit revision)
     AND on
     `update_fabrics` (the derivation config's commit revision);
     the
     helper REFUSES a nonzero expectation that differs from its
     stored `commit_revision` — the check ordered FIRST in each
     handler, before any field clearing/guard evaluation/
     mutation/persist (stale-completion / diverged-fabric,
     retryable, NO mutation).
  6. `ControlRequest.note_commit_revision: {new_rev u64,
     expected_rev u64}` (serde defaults 0 = absent; v8.10 CAS
     form, Codex r14 f5 = AGY r14 f5 = SMR r14 SMR14-1,
     REPLACING v8.9's unguarded `note_commit_revision`):
     the dedup lineage-transfer verb — the helper applies it
     evaluated in the EXACT three-way order: (i) `stored ==
     new_rev` → idempotent SUCCESS; (ii) else `stored ==
     expected_rev` → MUTATE; (iii) else a typed refusal
     (`error_code: "note_cas_refusal"`) carrying the CURRENT
     stored revision in the response's `Status`; Go marks
     `m.acceptedCommitRevision =
     `m.pendingCommitRevision` ONLY on the observed CAS success
     (a `requestLocked` no-status success does NOT count,
     process_control.go:219-230); a refusal with `current >
     expected` is abandoned
     (a racing publish superseded the note); a refusal with
     `current < expected` is OWNED BY THE RE-SYNC
     (helper-behind — the note's purpose is now the
     re-sync's); a FAILED/UNKNOWN
     transfer records a supersedable note debt retried on the
     fabric ticker, cleared ONLY on an echo of the captured
     sent revision OR ANY NEWER revision (v8.11 —
     supersession by a newer accepted commit completes the
     note's purpose, AGY r15 f8 = SMR r15 SMR15-8). And the
     note echo advances accepted state and clears the note
     debt BEFORE generic divergence classification, in ONE
     common lineage-observation routine shared by the
     response path and the status poll (v8.12, Codex r16
     f8's ordering pin).
  7. `ControlRequest.provenance: string ∈ {"operator",
     "automatic"}` on `set_forwarding_state` (serde default
     `"operator"`; v8.9, Codex r13 f7): the helper clears the
     defer latch on a FALSE verb ONLY for `"operator"`; an
     `"automatic"` FALSE disarms the dataplane but preserves
     the epoch and debts. Old Go omits it → `"operator"` (the
     historical latch-clearing semantics the operator expects);
     new Go tags every automatic disarm explicitly.
  8. `StatusSnapshot.stored_defer_workers: bool` (serde default
     `false`; v8.7, Codex r11 f5; v8.10 reconciliation is (v)
     lineage-gated AND ASYMMETRIC clear-only per AGY r14 f2 =
     SMR r14 SMR14-2): the stored snapshot's
     `defer_workers` echoed into every full status so Go's
     lost-response exit paths reconcile the manager flag and the
     Go cache from the helper's truth — clear-only, only under
     the revision gate with no compile in flight.
  9. `StatusSnapshot.guard_env_generation: u64` + 
     `StatusSnapshot.rejected_projections: []string` (serde
     defaults; v8.9/v8.10): the helper's monotonic
     guard-environment counter — ONE captured
     sample per guard evaluation (verdict and token derive from
     the same sample) — plus the identity hashes of the bounded
     (≤4) retained rejected-projection set the watch covers;
     echoed on
     full statuses and `update_fabrics` guard-rejection
     responses; Go's suppression cache resets on helper
     (re)spawn (incarnation-scoped) AND drops any entry whose
     identity is absent from the echoed set (v8.10 eviction
     ownership, Codex r14 f11).
  10. `ConfigSnapshot.snapshot_token: u64` AND
     `ControlRequest.snapshot_token: u64` where the request
     carries a full snapshot (serde defaults 0; v8.13, Codex
     r17 f5): the build sequence (== `buildSeq`, minted at
     input capture under `m.mu`); the helper REFUSES a
     strictly-older token per incarnation
     (`error_code: "stale_snapshot_token"`, retryable only
     by rebuilding current — the Go-side buildSeq validation
     abandons first in every reachable case). Old Go omits
     it (0 — legacy-accept, same posture as the revision
     fields); old helpers ignore it. The semantic hash
     EXCLUDES it (builder.go:156-178's zero set grows).
  11. `ConfigSnapshot.fabric_map_generation: u64` AND
     `ControlRequest.fabric_map_generation: u64` on
     `update_fabrics` AND `StatusSnapshot.accepted_fabric_map_generation:
     u64` (serde defaults 0; v8.13, Codex r17 f12): the
     causal fabric-map generation — minted in the same
     `m.mu` section that samples the map view and builds the
     payload; the helper echoes the generation of the last
     fabric send it ACCEPTED, advancing on EVERY accepted
     carrier (full snapshot or `update_fabrics`) even when
     the fabric content is equal (idempotent advance,
     ordered with the accept itself).
  12. `ControlResponse.error_code: string` (serde default
     `""`; v8.12 form, completed v8.13 per Codex r17 f6):
     the typed refusal classifier. Producer census:
     `stale_completion` (rebind `expected_commit_revision`
     mismatch, ordered FIRST in the handler before
     rebind.rs:42-50's field clearing); `diverged_fabric`
     (`update_fabrics` fence mismatch, ordered first);
     `epoch_rollback` + `publication_rollback`
     (`apply_snapshot` DUAL refusal, before any mutation);
     `note_cas_refusal` (the note handler — a NAMED
     dispatcher entry in handlers/mod.rs, not an
     afterthought); `stale_snapshot_token` (the token
     refusal). `not_seeded` is MANAGER-LOCAL — synthesized
     Go-side before the send, NEVER on the wire. Consumer
     contract: a response with `error_code != ""` SURVIVES
     the OK=false whole-response discard
     (process_control.go:163-169 amended for typed
     responses), invokes the ONE common lineage-observation
     routine (note echo → accepted advancement → divergence
     classification, shared by the response path and the
     poll), and selects the reservation/debt outcome;
     UNTYPED failures (`error_code == ""`) keep TODAY's
     handling exactly (status NOT copied on failure — Rust
     attaches `Status` to ordinary failed responses too
     (handlers/mod.rs:260-267), and copying it would change
     existing behavior).
  13. The ping exchange gains a protocol CAPABILITY bit
     (additive; v8.13, Codex r17 f12): present ⇒ the helper
     speaks the revision/token/generation fields; absent ⇒
     old helper — every lineage-sensitive operation fails
     closed until the REQUIRED restart. Resolves the
     new-helper-zero vs old-helper-zero ambiguity for
     `map_generation` (and documents the same for the
     revision pair).
- **Configstore API (v8.10/v8.13):** `ActiveConfigRevision()
  uint64` (v8.10 — confirmed values only); `ActivePair()
  (*config.Config, uint64)` (v8.12 — ONE `s.mu`-atomic read
  of the active config AND its revision; the ONLY transport
  source for every apply path); `PersistDegraded() bool`
  (v8.13, Codex r17 f2 — the exposure gate's indicator:
  true while a promotion's pair write is outstanding, i.e.
  `persistRetryLoop` has work); the promotion paths' return
  surface (or the getter) feeds the daemon's apply-skip
  decision; and the daemon's apply scheduler POLLS the
  getter on its wake cadence to wake the
  durability-exposure debt (no new store→daemon call
  direction). The revision assignment itself (the five
  promotion paths + the dedicated high-water + the
  migration allocator + the capability-2 envelope) is
  store-internal per §5-C's epoch contract.
- **Go manager state:** `m.pendingCommitRevision` (the durable
  revision of the newest STAGED config — set at staging from the
  SAME `ActivePair()` read that supplies the config (v8.13, Codex
  r17 f3 — never a separate `ActiveConfigRevision()` getter, which
  could interleave with the background persistence retry's
  `s.mu`-only write); a failed build stages nothing),
  `m.acceptedCommitRevision` (the durable revision of the
  newest OBSERVED-ACCEPTED published config),
  `m.mintedPublicationRev` (burned per send via the common
  one-mint-per-wire-attempt primitive) and
  `m.observedPublicationRev` (moves only on
  acceptance-proving responses), both seeded from the
  synchronous ping at the TOP of every Compile (no stamp
  before the seed, Codex r16 f5) with the seeded state
  INCARNATION-SCOPED (`m.seededPublicationRev` resets on every
  manager-driven (re)spawn, v8.13 Codex r17 f4),
  `m.latestBuildSeq` (the build-sequence high-water; each
  build's input-capture mints from it, v8.13 Codex r17 f5),
  `m.mapGeneration` (the fabric map high-water, seeded from
  the startup ping echo, v8.13 Codex r17 f12 = SMR r17
  SMR17-4) and the fabric coherence-proof flag (set on the
  first observed matching echo since startup),
  `m.compileInFlight` (the StartCompile reservation's
  in-flight flag, cleared on every Compile exit), the
  reservation CHAIN (head pointer + node registry +
  monotonic ID counter; non-head Finish outcomes recorded
  on their nodes, v8.13 Codex r17 f7), the fabric
  sync debt (keyed `(commit_revision, projection-identity)`
  with the last-sent generation per entry for the clear rule),
  the re-sync debt (divergence-fired, latest-wins), the note
  debt (supersedable CAS retries), the operator-verb
  retry debt, the DURABILITY-EXPOSURE debt (single-flight,
  latest-wins, woken by the persist-retry's success observed
  via the polled getter, v8.13 Codex r17 f2), the BOOT-APPLY
  debt (single-flight, short-cadence, owns the not-seeded
  abort, v8.13 Codex r17 f4), and the RESTORE debt
  (daemon-side, 5/10/30/60s + edge Warn, no terminal cap,
  v8.13 Codex r17 f9). The v8.7 `ConfigGeneration` snapshot field, the
  v8.8 mint/carry contract, and the v8.9 `archiveSeq`-based
  `commit_revision` are all DELETED.
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
  `set_queue_state`, `apply_snapshot`, `rebind`, `update_fabrics` —
  signatures unchanged; response shapes ADDITIVELY EXTENDED
  (v8.13, Codex r17 f6's correction of the v8.12
  "shapes unchanged" text): `ControlResponse` gains
  `error_code: string` (serde default `""`; the typed codes
  classify the new machinery's refusals; existing errors keep
  `""` and their handling). `set_binding_state` slot
  addressing is unchanged (slots remain positional).
- **Go manager API:** the manager gains the epoch/debt state
  (`m.deferWorkers`, `m.pendingCommitRevision` +
  `m.acceptedCommitRevision`, `m.mintedPublicationRev` +
  `m.observedPublicationRev`,
  `m.compileInFlight`, the
  three-obligation MAC debt
  (`macEpochDebt` + `macAndLinkRecovery` + `linkOnlyRecovery`),
  the fabric sync debt, the re-sync debt, the note debt, the
  operator-verb retry debt, and the pending-retry state) and the
  tagged/untagged rebind issuance
  rules — all manager-internal; D and the arm-sync defer gate are
  likewise manager-internal. The **LinkController interface
  (daemon.go:485 / apply.go:130) gains these daemon→manager
  operations** (v8.10; the interface's
  actual direction is daemon→manager: `userspaceLinkController`
  wraps `*Manager` (controllers.go:36-40, manager.go:379-381)
  and the daemon calls INTO the manager):
  `StartCompile(rethMACPending bool) reservationToken` —
  one `m.mu` section
  setting
  `m.deferWorkers = rethMACPending` AND `m.compileInFlight =
  true`, called EXACTLY ONCE per apply by the DAEMON at the
  apply-flow entry (deferred and non-deferred alike — the
  false case explicitly resets a stale flag), and NEVER
  again by `Compile` itself (which REQUIRES a reservation
  from the current applySem-held apply OR creates a
  DEFAULT (deferIntent=false) one when none exists —
  manager-internal and direct invocations (HA sync's apply
  path, background recompiles, unit tests, the direct CLI
  path (pkg/cli/apply.go:196-200,
  legacy_dataplane.go:190-195) — never a panic on a
  legitimate path, AGY r16 f3); it RETURNS the reservation
  token (v8.13, Codex r17 f7 — the chain node carrying the
  prior pair + the predecessor node's ID; the manager
  state lists the chain head, the node registry, and the
  ID counter) and FINALIZES any orphaned OPEN predecessor
  as OVERLAP (SMR r17 SMR17-5 — the (v) latch echo can
  never wedge behind an abandoned staged reservation);
  `FinishCompileReservation(token, outcome)` — the ONLY
  clear path, tokened by the predecessor-chained
  reservation WITH RECORDED OUTCOMES (§5-C, v8.13 Codex
  r17 f7): a non-head Finish RECORDS its outcome on its
  node; the head's Finish applies its own outcome AND
  replays completed predecessors' recorded outcomes in
  chain order: ACCEPTED / PRE-PUBLISH FAILURE /
  UNKNOWN / PRE-SEND / PENDING-XSK STAGED (its token is
  stored for the deferred-publish leg; helper death before
  the leg finalizes it UNKNOWN) /
  POST-ACCEPTANCE TAIL FAILURE / OVERLAP (the stale
  un-tokened `ClearCompileReservation()` is DELETED,
  Codex r16 f10); panic outcomes classify by phase via
  the Compile-internal `defer` (pre-wire → PRE-SEND;
  possibly-landed → UNKNOWN; post-acceptance → tail);
  `ClaimMACDebtWork() (epoch uint64, due []MACDebtWorkItem,
  claimToken uint64, nextWake time.Time)` — the pull
  model's work handout (due
  members/phases/desired MACs/deadline + the linearization
  token + an explicit next wake on EVERY Claim (empty
  included: `nextWake = min(earliest Deadline, next
  backoff tick)`, Codex r16 f11's hygiene catch));
  `PrepareLinkCycleChecked(claimToken uint64)
  (outcome LinkCycleOutcome, err error)` — the MERGED
  validator+quiescence (v8.13, Codex r17 f8 = SMR r17
  SMR17-9, REPLACING the split `ValidateClaimToken` +
  `PrepareLinkCycle() error` of earlier text): ONE method
  that try-acquires `m.mu` (contention → `RetryLater`),
  validates the token (bumped → `Stale`), and on `Valid`
  issues ctrl-disable + `stop_workers` UNDER THE SAME
  HOLD (3s `controlBaseDeadline` each,
  process_control.go:34-41), releasing `m.mu` before the
  MAC phase (the per-mutation try-lock re-reads resume
  after release); `RetryLater` exists only BEFORE any
  ctrl/worker mutation — a post-quiescence try-lock skip
  routes through the restore finalizer; and
  `ReportMACDebtAttempt(claimToken uint64, results
  []MACDebtMemberResult) (settled bool)` — accepted only
  while `claimToken` is current (stale-token results
  discarded wholesale), updating the collections under
  `m.mu`, with `settled=true` authorizing the daemon to
  dispatch the tagged completion via the EXISTING
  `NotifyLinkCycle` path.
  **`ApplyResult` gains the commit revision** (apply.go:97-117
  currently carries only the ordinary generation, Codex r13
  f9) — sourced from the SAME `ActivePair()` read that
  supplied the config (v8.13, Codex r17 f3: never a
  separate `ActiveConfigRevision()` getter).
  **`NotifyLinkCycle` gains a typed result** (v8.13, Codex
  r17 f9 — void today, swallowing missing-process, ctrl,
  rebind, and status-application failures
  (process_linkcycle.go:184-224)): each failure mode maps
  to an explicit owner — missing process → respawn
  FOLLOWED BY a daemon-owned revised full apply
  (`applyConfigLocked(ctx, cfg, commitRevision)` from
  `ActivePair()`); ctrl error → the RESTORE DEBT's retry
  (5/10/30/60s + edge Warn, no terminal cap); rebind
  error → the RESTORE DEBT itself (NOT the #5134 debt,
  which self-clears on non-deferred snapshots,
  manager_worker_arm_5134.go:50-54); status error → the
  poll reconciles. The restore-debt state is
  manager-side; the debt is daemon-driven like the MAC
  debt.
  **`FabricSyncStateOK() bool`** — a no-argument
  manager-owned consistency answer (v8.11, Codex r15 f12;
  causal single-transaction form v8.13, Codex r17 f12 —
  supersedes the parameterized query: the map-view and
  sent-payload projections differ (types.go:797-804 vs
  protocol.go:315-333), so no daemon-computed hash can name
  the sent payload without a TOCTOU sample; the manager
  owns both sides and answers (map-committed ↔
  helper-accepted) coherence directly);
  takeover readiness (daemon_ha.go:774-783) ANDs
  `fabricPopulated` with it (v8.10 accepted the
  interface addition, Codex r14 f12 — `HAController` has
  four mutating methods and no query today,
  apply.go:138-143).
  Daemon-internal ordering changes (defer-flag lifetime,
  MAC-success gating, rollover-at-acceptance) do not alter any
  OTHER interface.
- **CLI / `show` output:** unchanged shape; `activation_state`
  surfaces ONLY in JSON and verbose binding output (v8.4, AGY r9
  f5) — the non-verbose CLI text layout is byte-identical, so
  existing parsing scripts keep working.
- **Pinned behavior changes (each reviewer-sanctioned through
  rounds 3-5):**
  1. The #4952/#5143 post-teardown failure path now restores the
     PRE-APPLY binding vector (all non-operator slots unarmed+pending)
     instead of retaining the rejected plan's vector — the pins'
     intent (real post-teardown state, fail-closed truth) is
     preserved by `refresh_bindings` against surviving workers plus
     the restored coherent control state (§5-C).
  2. `update_fabrics` now replans bindings when the fabric set
     changes (new fabric-parent candidates appear as pending until
     the next armed reconcile) — previously the binding plan silently
     lagged the persisted fabric set.
  3. The daemon's defer flag now spans apply → MAC programming →
     completion (previously cleared right after ApplyConfig), and the
     live-MAC-change completion dispatch is skipped when MAC
     programming failed (previously fired on warn-only failures).
## 7. Hidden invariants the change must preserve

1. **Defer contract — the REAL one (v3–v8):** a `defer_workers=true`
   PLAN-CHANGING apply must leave the whole vector unarmed (S3;
   non-operator slots `pending`), because its reconcile is SKIPPED.
   The defer EPOCH is now durable end-to-end: the Go flag spans
   apply → MAC programming → quiescence sleep → dispatch →
   completion return (link-cycle flow), so no poll-tick arm and no
   retry can recreate workers mid-quiescence; completion fires only
   on a SUCCESSFUL (both-phase) MAC program; the tagged rebind
   consumes the latch on BOTH sides (helper's stored snapshot on
   `Ok`; Go's `m.lastSnapshot.DeferWorkers` on success, so wholesale
   snapshot clones can never re-latch); and a failed completion is
   retried TAGGED while the same epoch is open. An explicit operator
   arm remains an explicit authorization (documented). A deferred
   apply with an UNCHANGED plan marks nothing.
2. **#869 no-ready-in-enabled:** `enabled` must keep NOT requiring
   `ready`. Untouched.
3. **#1666 ready-gate:** per-row shim steering must keep requiring
   `Ready`. Untouched. In the defer window S3 keeps everything
   unarmed; and the identity-checked volatile refresh (§5-C) now
   guarantees no stale `Ready` can attach to a physically-different
   binding in ANY window — `copy_live_snapshot` requires the live
   worker's PLANNED identity (`workers.identities[slot]`: interface
   name + ifindex + queue_id, written once at plan time,
   bringup.rs:280 — tear-free) to equal the binding's
   `(interface, ifindex, queue_id)`, else the slot zeroes (error
   attribution follows the same key: match copies `last_error`
   even with a zeroed socket tuple, mismatch copies nothing).
4. **Disarm direction never blocked:** the `ifindex <= 0` leg still
   force-clears (marking `pending` unless the record is
   operator-claimed, S2); `set_forwarding_state(false)` still fans
   out `armed=false` and sets `none` on registered slots — a
   deliberate global disarm leaves nothing armed to auto-activate,
   while unregistered (S1/S2-marked) slots keep their state for E2.
5. **Same-plan skip (#2915/#2916/#3007/#3175):** the plan key and
   the candidate set are untouched; identity-carry only runs on the
   full-apply leg that ALREADY decided the plan changed (plus the
   failure-path RESTORATION and the projection-scoped
   `update_fabrics` replan — neither alters the key).
6. **One-XSK-per-(netdev,queue) (#1921):** the `seen_linux` dedup
   and candidate iteration order are unchanged; identity uniqueness
   per plan follows from it.
7. **Coordinator filter (`registered && ifindex > 0`):** unchanged;
   worker bring-up must not start reading `armed` OR the state
   field. (The one coordinator-side change is the volatile-copy
   identity check — a reporting predicate, not a planning input.)
8. **Operator override ownership (v8):** operator verbs claim slots
   with `activation_state=operator` keyed on the verb's RESULT (any
   non-forwarding result = claim; no wire discriminator needed,
   §5-C C2), in the same mutation as the verb's values, before any
   registration-changed reconcile. A claim is never marked pending,
   never converged, and never planner-restored (E2 is
   `pending`-only). Claim lifetime (Codex r7 f8's exact form):
   claims survive SLOT RESHUFFLES and interface FLAPS (the planned
   `(linux-interface, queue_id)` identity persists); they die at an
   explicit global fan-out (C3, registered slots) or at ANY
   deletion of that planned identity — a candidate dropout
   (invalid fabric parent / unreadable queue count), a RENAME (the
   linux name changes → new identity), or a queue-count contraction
   (the global-min layout drops high-queue identities on healthy
   interfaces). A globally-DISARMED slot (`none`) is NOT
   operator-owned: S2 re-marks it pending on flap and E2
   re-registers it. `set_queue_state` remains
   membership-at-invocation shorthand. And the claimed-slot rebind
   assurance (SMR r8 N3): any reconcile — including the
   pending-activation retry's plain rebind — tears down and
   re-binds a CLAIMED slot's XSK physically (worker planning
   filters `registered && ifindex > 0`, never `armed`), but the
   claim keeps `armed=false`, so its shim rows stay non-READY
   (`bindingForwardingLive` requires Armed) and no traffic is ever
   steered to it: the operator's no-forward intent survives
   physical rebinds exactly.
9. **Volatile state rebuilt, not carried (kept):** R3 carries
   {`armed`, `registered`, `activation_state`, `last_change`} only;
   everything else resets at replan and is re-derived — now by an
   identity-checked `refresh_bindings` (invariant 3).
10. **Coherent-vector invariant (v8, completed):** after every
    handler, the binding vector equals the stored snapshot's
    BINDING PROJECTION. Full-apply replan (replaces); same-plan
    legs (equal key ⇒ equal identities); #3789 pre-teardown restore
    (restores both together); post-teardown failure (restores
    snapshot AND the pre-apply vector — v7); `update_fabrics`
    (telemetry persists without vector change; projection changes
    replan with physical-change pending marks, the reconcile
    driven by the pending-activation machinery, never in-handler
    — v8.2); rebind /
    toggles / forwarding (no plan mutation). The server tests
    assert the invariant directly (§9 item 16).
11. **Failure truthfulness + retry ownership (v8):** the planner
    never arms (S5); ANY post-teardown bring-up failure marks all
    non-operator registered slots pending in COMMON typed handling
    (S4'); the arm verb rolls its global bit back on Err (the Go
    desired-loop retries, #6165-gated); and the status loop's
    pending-activation retry — ACTUAL-armed, registered+ifindex
    pending only, flag clear, no debt/in-flight, backoff-with-jitter
    + NO terminal cap (rate-capped-forever at the 60s floor) +
    reset-on-membership-change (pull-earlier only, exponent
    preserved) — schedules a convergence
    reconcile whenever nothing else does, with the loop ensured
    right after `ensureProcessLocked` so no compile error path
    orphans it. Unregistered pendings (S1/S2) converge only at
    replan-producing applies (documented; retry-excluded).
12. **HA portability:** no cluster-protocol or session-sync
    interaction; per-node helper-internal change with additive wire
    fields. Standby nodes run the same armed semantics. Mixed-version
    window: old helper + new Go strands as before (D warns);
    `complete_deferred` absent from old Go → no defer-window
    convergence → fail-closed (safe).
13. **Bootstrap fail-closed floor (Go side):** a plan-changing
    Compile already programs bootstrap ctrl disabled and clears
    binding rows before publish (manager_compile.go:315,
    maps_sync.go:163/178) — the bounded interruption exists on
    master and stays; the fix removes the INDEFINITE tail (§3).
## 8. Risk assessment

| Risk class | Level | Assessment |
|---|---|---|
| Behavioral regression | LOW-MED | Observable changes beyond v7.1: (i) `update_fabrics` projection changes now reconcile (teardown+bind on physical change/removal) instead of silently publishing a wrong-physical enabled state — a NEW v7 hazard (Codex r6 f4) closed before it ever shipped; telemetry-only fabric updates now skip the replan entirely (less work than v7); (ii) the volatile refresh copies only identity-matched live state — `show` output in failure/defer windows becomes physically truthful (was cosmetically aliased on master too); (iii) the link-cycle defer flag now spans the 1s quiescence sleep — the arm-sync stays gated through it (master's early clear raced the quiescence); (iv) successful completion also clears the Go-side cached `DeferWorkers` — route/scheduler republishes can no longer re-latch the helper (a real cross-process bug Codex r6 f8 found in the v7 design); (v) `programRethMAC` "MAC set, link-up failed" now retries the missing phase (master's next attempt no-ops); (vi) the retry is backoff/jitter/cap-shaped and ACTUAL-armed/registered-only — its worst case is a 60s-cycle worker-set bounce on a permanently-broken queue with an edge Warn, vs v7.1's 5s churn. All prior rounds' postures (S3, S4', C3 rollback, operator claims, plain restoration) are unchanged. |
| Lifetime / borrow-checker | LOW | Cold path; owned clones; plain enum; one-predicate coordinator change. No new lifetimes, no hot-path allocation. |
| Performance regression | LOW | The retry adds at most one rebind per backoff interval (5-60s) in failure windows only; fabric projection resends are env-gated (no resend while the guard environment is unchanged); the volatile identity check is O(1) per slot per refresh (same loop); the guard-env evaluation rides the existing telemetry candidate scan. No per-packet/session work; the 1s poll gains only O(n) scans. |
| Architectural mismatch | LOW-MED | The surface is now wide (helper planner + status/convergence + one coordinator predicate; two additive wire fields; Go manager D/gate/retry/debts/warn; daemon apply ordering + MAC debt) — §11 Q6 explicitly asks reviewers whether the daemon-side pieces (MAC debt) or the retry should split into follow-up PRs. The core (tri-state + coherent vector + provenance completion) is indivisible; the split candidates are additive layers. #6702/#6681 non-collision unchanged. |

## 9. Test plan

**Rust unit/integration (the fix lives here):**

- `replan_bindings_from_candidates` unit tests (`main_tests.rs`):
  1. **expansion while armed, non-deferred (S5 never-arm)** — new
     slots `registered=true, armed=false, state=pending`; carried
     slots unchanged.
  2. **expansion while disarmed** — same shape (S5 is uniform).
  3. **deferred plan-changing apply (S3 gate)** — every registered
     slot `armed=false`; `pending` on exactly the non-operator
     slots; an operator-claimed slot stays `armed=false, operator`;
     an unchanged-plan deferred apply marks nothing.
  4. **deferred CONTRACTION** — `[a,b,c] → [b,c]` with defer:
     survivors unarmed+pending despite no new identity.
  5. **contraction (non-deferred)** — vanished identities' state
     does not leak onto survivors.
  6. **reshuffle identity carry** — each surviving identity keeps
     its own `armed`/`activation_state` at its NEW slot; an
     operator-claimed identity stays claimed at its new slot.
  7. **E2 + flap matrix (v7 form, kept):** (a) `ifindex == 0` →
     `registered=false, pending` (S1); later valid → re-registered
     pending; converges at the next armed reconcile; (b)
     operator-UNREGISTERED (valid, `operator`) → flap → valid →
     STAYS `registered=false, operator` (E2 never restores claims);
     (c-i) ARMED slot flaps (S2 marks pending) → recovers →
     re-registered + converged; (c-ii) operator-DISARMED slot
     (`registered, armed=false, operator`) flaps → force-cleared
     WITHOUT pending (claim retained) → recovers as
     `registered=false, operator`; (d) invalid → GLOBAL ARM fan-out
     → valid: the S1 mark SURVIVES the fan-out (C3 clears state
     only on registered slots) → re-registers; (e) GLOBAL DISARM →
     flap → valid: the disarmed (`none`) slot is NOT operator-owned
     → S2 re-marks pending → E2 re-registers → converges on re-arm.
  8. **identity transition matrix:** same-name/new-ifindex carries
     state; rename/same-ifindex re-initializes; orphan-fallback →
     explicit-parent carries across the ifindex swap.
  9. **C2 result-based semantics + queue overrides (Codex r6 f2):**
     a verb leaving the slot non-forwarding sets `operator`
     (disarm AND disarmed-register, which are the same result); a
     verb leaving it forwarding sets `none` (C1); queue disarm →
     expansion adds a new member → initializes per S5 (pending, NOT
     claimed); contraction removing all claimed members leaves no
     residual; queue unregister survives a reshuffle as CLAIMED and
     un-registered (never planner-restored); the state write lands
     in the same mutation as the verb's values, BEFORE any
     registration-changed reconcile.
  10. **volatile non-carry (R3):** a carried identity's
      `ready`/`bound`/`xsk_registered`/counters/`last_error` reset
      at replan; only the control quad carries.
  11. **`had_existing` death:** inheritance depends ONLY on
      identity-map membership.
- **Identity-checked volatile refresh unit tests (Codex r6 f3):**
  live worker at slot S with `(ifindex=10, queue=0)`; binding at S
  with `(ifindex=11, queue=0)` → NO copy (zero_unbound_slot);
  matching pair → copy. Covers the partial-B/restored-A alias and
  the deferred-window alias.
- **Convergence unit tests** (`reconcile_status_bindings` armed
  leg): pending+registered slots arm+clear on Ok; marks NOT
  consumed on Err; operator-claimed slots never armed; convergence
  BLOCKED when stored defer=true and caller is not
  defer-authorized; ALLOWED for the authorized caller; allowed for
  every caller when stored non-deferred; the successful authorized
  rebind CONSUMES the latch (stored defer→false) in the same
  critical section.
- **Common S4' unit tests:** `WorkerSpawn` and
  `WorkerBindIncomplete` from EACH reconcile caller (full apply,
  same-plan apply, rebind, binding toggle, queue toggle, forwarding
  arm) → all non-operator
  registered slots unarmed+pending; operator-claimed slots
  untouched. NOTE (Codex r11 f10): `update_fabrics` is NOT a
  reconcile caller (rule 3, v8.2) — its projection-change path
  marks pending and the pending-activation retry drives the
  reconcile, so its S4' failure shape is exercised through the
  retry-driven rebind above (item 14(vii) covers the mark side).
- **Server-level regressions** (`userspace-dp/src/server/tests.rs`;
  valid map pins, `force_worker_healthy_stub`, assertions on
  ARMED/STATE + reconcile Ok/Err + reconcile stage + IMMEDIATE
  post-failure assertions per Codex r3-r6):
  12. **expansion-while-armed** (the issue's demanded test): apply
      A, `set_forwarding_state(true)`, apply B with an additional
      zoned interface; BOTH responses ok, plan keys differ, binding
      count increased, added identity exists, EVERY binding
      `registered && armed && state==none`, `enabled == true`,
      reconcile stage advanced. Red on master, green after. And the
      server test hooks the reconcile entry with a TEST-ONLY
      counter on the convergence locus (Codex r9 f8's delivery
      proof): `reconcile_status_bindings` gains a
      `#[cfg(test)] CONVERGENCE_CALLS: AtomicUsize` incremented at
      the armed-leg entry, and the test asserts the counter moved
      AND that the new identity arrived `pending=true` at that
      entry and became armed only after the locus ran — proving
      the HANDLER (not just the planner/convergence units)
      delivered the identity as pending and only the locus armed
      it. The
      convergence unit tests (below) must prove the new slot
      TRANSITED `pending → armed` via the convergence locus — an
      implementation that directly initializes `armed=true` at
      replan (the v5 defect) fails those, so item 12 cannot green
      an armed-at-replan shortcut (Codex r8 M8).
  13. **deferred expansion, three completion shapes + negatives
      (v8 form):** apply A, arm, apply B `defer_workers=true` +
      inserted earlier-sorting candidate: all non-operator slots
      `!armed && pending`, `enabled == false`, IMMEDIATE assertion
      on an untouched pending slot + reconcile-call delta.
      Complete via: (a) same-plan re-apply `defer_workers=false`;
      (b) full-leg re-apply with a changed plan key; (c) `rebind`
      with `complete_deferred=true` — after each, non-operator
      slots `registered && armed && state==none`, `enabled == true`,
      and (c) leaves the latch CONSUMED (persisted snapshot shows
      `defer_workers=false`). NEGATIVES: (i) a registration toggle
      DURING the window does NOT converge; (ii) a plain rebind
      DURING the window does NOT converge; (iii) a FAILED tagged
      completion leaves the latch set + slots pending, and the
      TAGGED completion retry (epoch-scoped, production-scheduled —
      NOT a manually issued second request) drives recovery —
      assert no untagged retry fires while the epoch is open; (iv)
      during the quiescence sleep the desired arm-sync does NOT
      fire (Go-side test below); (v) a completion dispatched after
      a FAILED MAC program does not fire (daemon-side, below); (vi)
      a route-overlay republish after successful completion does
      NOT re-latch (Go-side, below); (vii) the Q2 OVERLAP test
      (Codex r7): a prior S4' pending (failed bring-up) AND a
      current S3 defer pending coexist — a tagged SUCCESS converges
      BOTH (plan-scoped), a tagged FAILURE converges NEITHER; (viii)
      the EPOCH ROLLOVER test (Codex r7 f4, v8.3 acceptance form):
      deferred A with a failed tagged completion, then an UNRELATED
      commit B with no MAC work — B's SUCCESS clears the manager
      flag at ACCEPTANCE (assert), cancels A's stale tagged/MAC
      debts, publishes B non-deferred (helper latch cleared via the
      swap), and B's workers bind — no workerless-B sink; AND the
      boundary cases (Codex r8 M8): a pre-acceptance B FAILURE
      (publish error) rolls the flag back and leaves A's stale
      debts ALIVE; a post-ACK B error (apply error after the stamp)
      still converges via the retry owner; a status tick landing
      exactly on the rollover/open boundary sees no arm; a stale
      in-flight A completion arriving after B's acceptance is a
      no-op (epoch superseded); AND the
      lost-ACK successors (Codex r9 f10 + r10 f4 + r11 f4/f5 +
      r12 f2/f4/f5): a LOST-ACK B
      (timeout-but-landed deferred snapshot) WITH MAC work — A's
      tagged retry carries `expected_commit_revision = E_a`
      and the helper REFUSES (stored epoch is E_b ≠ E_a) —
      A's completion can never fire on B's latch; the REFUSAL
      performs NO mutation (assert zero binding-field clearing,
      zero reconcile-entry increment, zero latch change, zero
      persist — the check is ordered FIRST); AND the
      FALSE-REFUSAL negatives across EVERY full-apply producer
      (Codex r12 f2/f4 — v8.7's test covered only FIB/neighbor
      partials while claiming "arbitrary overlay churn"): an
      ordinary FIB bump, a neighbor regen, a ROUTE OVERLAY
      (manager_overlay.go:188-250), a SCHEDULER republish
      (manager_compile.go:575-621), and a #5134 clone-republish
      (manager_worker_arm_5134.go:57-92) each advance the
      helper's stored `generation` but carry the SAME
      `commit_revision` — the completion carrying `E_a` is
      ACCEPTED after each (assert: no false refusal after any
      churn class);
      AND the ownerless-B re-sync (Codex r12 f5 + AGY r12 f1 +
      r13 f5/f10 + r14 f6): after the lost-ACK B, Go has DISCARDED the
      staged snap
      (manager_compile.go:350-365) and the next send's
      `publication_rev` is strictly newer — the
      recovery is the DIVERGENCE-FIRED RE-SYNC DEBT: a status
      poll observes helper-ahead (`status.commit_revision >
      m.acceptedCommitRevision` OR `status.publication_rev`
      ahead) and the debt FIRES (assert it is NOT gated on its
      own key — the v8.9 rule prohibited firing during the
      own key, Codex r14 f6); AND the NONZERO helper-behind case
      (v8.11, AGY r15 f2 = SMR r15 SMR15-5: an incomplete persist
      leaves 0 < status.commit_revision < accepted — assert the
      debt FIRES here too (the v8.10 rule covered only echoes-0),
      driving the same active-config re-apply); the poll RECORDS it
      under m.mu (enqueue-after-unlock — NO
      inline manager→daemon call, assert none); the daemon's
      scheduler drains it, acquires `applySem`, re-reads the
      ACTIVE pair (config + revision via `ActivePair()`) AT
      DRAIN TIME, and drives the dataplane RE-APPLY through the
      REVISED `applyConfigLocked` (v8.12, Codex r16 f9: the
      daemon's own no-promotion, semaphore-already-held path
      INCLUDING the three-bucket precheck and MAC-debt
      creation (assert the precheck runs and B's MAC debt is
      recreated — a direct `d.dp.ApplyConfig` would bypass it
      and is FORBIDDEN here),
      NOT a new configstore commit — the carried
      overwritten and the
      helper-ahead signal never erased, Codex r13 f5);
      the observed-accepted publish (BOTH revisions observed)
      advances
      `m.acceptedCommitRevision`,
      supersedes A's debts, and B's completion is driven by the
      freshly instantiated debt carrying B's revision
      (accepted) — assert the full handoff with no operator
      action; the LATEST-WINS chain: timeout-but-landed B then
      C — the single-flight debt re-reads ACTIVE config at
      drain (C) and converges on C (assert the stale-B drain
      re-keys, Codex r14 f6); the explicit transitions: nil
      `ActiveConfig` (skip+backoff), channel saturation
      (record-and-backoff), `applySem` acquire timeout
      (retry at backoff), re-apply failure (retry at backoff +
      edge Warn); the SAME lost-ACK shape WITHOUT MAC work takes the
      SAME owner (the v8.7 test's "the next apply" fallback is
      deleted — it was never an owner, Codex r12 f5). And an
      explicit operator global arm clears ALL THREE latch
      authorities (manager `deferWorkers` flag, the helper's
      stored latch in the same handler write, AND the Go cache
      `m.lastSnapshot.DeferWorkers` — so a later route/scheduler
      wholesale clone cannot re-latch the helper, Codex r10 f4),
      AND the UNKNOWN-outcome shapes for every exit (Codex r11
      f5 + r12 f6/f13): lost tagged-completion response (poll
      reconciles the manager flag + Go cache from
      `stored_defer_workers` UNDER the (v) lineage gate), lost
      rollover apply (the active-config re-apply owns), lost
      operator-arm response (verb retry + poll reconcile),
      nil-config teardown
      (assert `stopLocked` clears `m.deferWorkers` AND
      `m.lastSnapshot.DeferWorkers`, not just the epoch/debt),
      HA supersede with a lost response (the re-sync owns),
      PLUS the v8.10 additions: a lost GLOBAL DISARM (operator
      provenance — latch clears on retry via the durable
      operator-verb retry debt; automatic provenance — epoch
      PRESERVED, recovery self-heals; and the WIRE tag: an
      old Go's untagged disarm defaults to operator), an old
      helper's MISSING `stored_defer_workers` echo (revision 0 —
      never reconciles), a FRESH helper post-restart (revision 0 →
      helper-behind → startup re-apply), a mid-defer helper
      restart (transition (g)), the mixed-version
      timeout-but-landed B with an OLD helper (revision 0 — ALL
      lineage-sensitive operations fail closed, no A-fabrics
      into B, Codex r13 f6), the ASYMMETRIC echo pair (AGY r14
      f2 = SMR r14 SMR14-2: a lingering helper latch
      (lost operator-arm response) with matching revisions —
      the echo may NOT set Go's flag true (clear-only;
      assert a non-deferred compile is NEVER stamped deferred
      by a poll) and the helper-true/Go-false mismatch raises
      an edge Warn owned by the next full apply),
      the universal reservation matrix (Codex r14 f7 + AGY r15
      f1/f4 = SMR r15 SMR15-1/2: the reservation is set
      EXACTLY ONCE per apply by the DAEMON at the apply-flow
      entry (`StartCompile(rethMACPending)`) and NEVER by
      Compile itself (assert: a deferred precheck followed by
      Compile-entry does NOT clobber the reservation — the
      v8.10 two-site form published a deferred config
      non-deferred; every exit routes through
      `FinishCompileReservation(token, outcome)` (v8.12,
      Codex r16 f10: the predecessor-chained token — assert
      T2's restore applies T2's OWN prior, never T1's), the
      PENDING-XSK STAGED outcome keeps the reservation OPEN
      for the deferred-publish leg, the PRE-SEND outcome is
      a no-op, the UNKNOWN outcome leaves the debts alive
      for the re-sync, and a STALE-token send dies on the
      freshness token (T1 after accepted T2)); every exit clears `m.compileInFlight`
      (success,
      build failure, publish failure, panic, pre-Compile abort
      via the finish path — assert no leak wedges the
      (v) echo or the suppression); AND
      the publication_rev SEED gate: the synchronous ping runs
      at the TOP of every Compile BEFORE the snapshot build
      (v8.12, Codex r16 f5: no stamp before the seed — a
      send attempted before the ping lands returns a typed
      not-seeded-yet error that ROUTES TO THE STANDARD
      publish-retry machinery (assert the boot apply re-fires
      after the ping, AGY r16 f5); and a manager re-init over
      a surviving helper seeds the LEGACY (generation, fib)
      high-waters from the same echo (assert the build after
      the ping carries the echoed values, never the reset
      legacy values that the rollback guard would refuse,
      Codex r16 f5 = AGY r16 f4));
      the epoch-RESERVATION cases
      (Codex r14 f2: a pre-wire build failure stages nothing
      and burns nothing — the NEXT send still mints a
      strictly-greater `publication_rev`; an ambiguous
      post-write failure can never alias because the rev
      never rolls back), the staged-B producer census (Codex
      r14 f4: with pending-XSK B staged, EVERY auxiliary
      producer (route overlay, scheduler republish, #5134
      retry) is SUPPRESSED — the ONLY first-publish of B is
      its own compile leg; and the #5134 DeferWorkers=false
      clone can never ARM staged B before its MAC obligation
      settles), the note CAS matrix (Codex r14 f5: the
      transfer applies ONLY on `stored == expected_rev`
      (strict-older refusal, equality-repeat idempotent); a
      racing newer publish makes the note stale — the CAS
      refusal carries the current stored rev and the note is
      ABANDONED (assert NO retry and NO suppression debt); a
      FAILED/UNKNOWN transfer (timeout, or a
      `requestLocked` no-status success) records the
      supersedable note debt, retried on the ticker, cleared
      ONLY on an echo of the captured sent revision OR ANY
      NEWER revision (supersession completes the note's purpose —
      an exact-echo rule would wedge against newer commits,
      AGY r15 f8 = SMR r15 SMR15-8);
      the two
      deferred-acceptance legs (Codex r13 f3: the pending-XSK
      deferred publish's clean leg AND the status-catch-up leg
      (process_status.go:18-37/:120-139) each advance
      `m.acceptedCommitRevision`), and the startup divergence
      policy (v8.12, Codex r16 f6: an unclean reset leaves
      the helper holding stored revisions while the manager
      starts fresh — the manager RESPAWNS the helper (no
      downward rebase exists — socket ownership is not a
      proof and a downward rebase opens a rollback window);
      assert the respawn is invoked, never a rebase);
      (ix) a successor
      commit WITH MAC work opens a new epoch and cancels the old
      commit WITH MAC work opens a new epoch and cancels the old
      one first (at acceptance); (x) an explicit operator global
      arm during the window also clears the manager flag.
  14. **failed bring-up, all shapes + retry (Codex r4-r6):** force
      `WorkerSpawn` and `WorkerBindIncomplete` on (i) expansion
      apply, (ii) E2-only apply, (iii) CONTRACTION apply, (iv)
      global-arm after a deferred boot apply (rollback from
      prev=false, no pre-reconcile fan-out), (iv-bis) idempotent
      re-arm on an already-true global (rollback to true + marks
      survive + pending-aware deficit fires recovery), (v) rebind,
      (vi) a registration toggle, (vii) update_fabrics with a
      projection change. IMMEDIATELY after each Err: every
      non-operator registered slot `!armed && pending`,
      `enabled == false`, marks SURVIVE; then the
      PRODUCTION-scheduled retry (the pending-activation retry
      firing on its own schedule, never a manually issued test
      request — Codex r8 M8) converges each.
  15. **operator-override survival + the deletion boundary (Codex
      r6 f2, r7 f8):** operator-disarm a slot; commit a plan-changing
      deferred apply + completion — the claimed slot stays
      `armed=false, operator` while the deferred slots converge;
      repeat across the failure path of 14(i) and the flap path of
      7(c-ii); a global arm fan-out afterwards clears the claim
      (C3). PLUS: accepted A with operator-claimed `a`, rejected
      B=[b,c] failing post-teardown — the restored vector CONTAINS
      `a` still claimed (plain restoration). PLUS the three
      deletion shapes, each killing the claim and re-creating the
      namesake as S5-pending (which converges): (i) candidate
      dropout (fabric parent invalid / queue count unreadable) →
      candidate returns; (ii) RENAME (the linux name changes → the
      old identity vanishes); (iii) queue-count CONTRACTION (the
      global-min layout drops the high-queue claimed identity on a
      healthy interface); and (iv) the boundary is exercised WITH
      sysfs unreadable during the replan (the guard holds the prior
      vector, no phantom re-creation).
  16. **coherent-vector invariant + plain restoration + volatile
      identity (Codex r4 B2, r5 B3/B5, r6 f3, r7 f7):** apply A,
      apply B (expansion), force B's bring-up to fail post-teardown
      with a MULTI-WORKER partial spawn where ONE worker owns
      MULTIPLE slots with distinctive socket/error/counter values
      (not the coordinator/tests.rs:4135 one-slot-per-worker
      fixture — Codex r7 f7): IMMEDIATELY assert the reported
      vector EQUALS the pre-apply vector (identities + ifindex +
      claims), all non-operator slots unarmed+pending, AND no
      restored-A slot reports volatile state from a
      physically-different surviving B worker — the identity check
      compares the PLANNED identity (`workers.identities`,
      tear-free), so a surviving B worker at slot 2 `(c,q2,if30)`
      cannot publish into restored-A's slot 2 `(c,q0,if30)` even
      with relaxed socket stores; and a slot whose live record
      carries a REAL bind-failure `last_error` copies it ONLY on an
      identity MATCH (even with a zeroed socket tuple — a failed
      bind owns its error); a MISMATCH copies NO error (restored A
      keeps only its own pre-restoration diagnostic), and a bind
      error for a plan-DELETED identity (`(c,q2)`) dies with the
      identity — NO dropped-identity row is fabricated, NO B→A
      attribution occurs, and the operation-level reconcile
      error/stage remains at snapshot.rs:379 for the failing pass
      (Codex r10 f6's three pins). Then: (i) a plain rebind binds
      A's plan and converges (self-heal to last-good); (ii) the
      failed-CONTRACTION shape: `a` is present, pending, and the
      rebind binds it — no enabled=true without an `a` worker;
      (iii) the same-name/new-ifindex shape: the restored vector
      carries A's ifindex; (iv) a killed sysfs-queues dir during
      the failure changes NOTHING (no replan on the failure path);
      (v) `guard.snapshot` equality with the pre-apply snapshot is
      asserted (not just the vector); (vi) deliberately TORN socket
      fields (ifindex advanced, queue still 0 — the relaxed-store
      tear Codex r7 f7 found) do NOT fool the planned-identity
      check (it compares workers.identities, not the tuple); (vii)
      an interface-NAME-only mismatch (same ifindex, different
      name) zeroes; (viii) a POSITIVE parent-rekey equality case
      (orphan VLAN child → parent netdev identity) copies;
      (ix) error attribution: same planned identity with bind
      failure copies that worker's `last_error` even with a zeroed
      socket tuple; planned-identity MISMATCH copies NO error —
      restored A keeps only its own pre-restoration diagnostic
      (Codex r8 f6).
      The updated #4952/#5143/#6140 pins live here — with the
      #6140 full-apply-leg proof re-anchored to an observable that
      survives the restoration (Codex r6 f3's requirement: the leg
      proof must not depend on the retained-B vector itself).
  17. **#5134 accepted-config-epoch contract (Go + Rust, Codex r7
      f6; v8.8 pending/accepted split):** deferred apply → failed
      mandatory re-apply → debt
      recorded WITH `m.pendingCommitRevision`; (i) a
      plan-changing SUCCESSFUL commit (`m.acceptedCommitRevision`
      advances on the observed publish) → the stale debt does NOT
      fire; (ii) a FAILED
      newer compile (NEITHER counter moves) → the debt STILL
      fires (a failed compile cancels nothing); (iii) a FIB-only
      bump / resolved-fabric persist / route-overlay / scheduler
      publish (the overlay/scheduler republishes carry the CURRENT
      accepted epoch — NEITHER counter moves) → the debt STILL
      fires (Codex r6 f8's scope fix, contract form); (iv) the retry's
      republish (same-plan, generation-bumped, epoch-carried)
      converges without
      the rebind flag, and its success settles the debt exactly
      once WITHOUT minting or advancing EITHER epoch counter
      (Codex r11 f6: the
      direct retry runs no precheck, so an advance would cancel
      same-config recovery entries through
      their epoch guard with nothing recreating them — assert a
      pre-existing recovery entry SURVIVES the retry's success);
      (v) a newer
      successful commit with the SAME binding plan (different other
      content) still supersedes (pending mints at compile,
      accepted advances at the observed publish) —
      the debt does not fire across it; (vi) the full
      revision-assignment matrix (v8.10, Codex r14 f2/f3/f13 —
      the v8.9 text's "each config mints" language was wrong:
      NOTHING in the dataplane mints config identity): boot-time
      first config, a
      DHCP/feed
      driven apply, an HA-peer config sync, a rollback to an OLDER
      config, a `commit confirmed` auto-revert, and a background
      full recompile — the CONFIGSTORE assigns a fresh durable
      `commit_revision` on EVERY promotion path (plain Commit,
      CommitConfirmed confirm, SyncApply, PromoteRollback, the
      boot-recovery promote), each accepted-config apply then
      stages with `m.pendingCommitRevision =
      ActiveConfigRevision()`, and each
      OBSERVED-ACCEPTED publish advances
      `m.acceptedCommitRevision`
      to the carried value; DHCP/feed/boot re-applies do NOT
      promote and therefore carry the CURRENT revision
      unchanged (assert they do NOT mint); the advance points
      are the compile publish legs
      (manager_compile.go:361/:365), the pending-XSK deferred
      publish's clean leg, AND the status-catch-up leg
      (process_status.go:18-37/:120-139); and every send mints a
      strictly-greater `publication_rev` (assert same-commit
      feed reshapes get DISTINCT publication revs and a stale
      same-commit clone is refused, Codex r14 f3);
      AND (Codex r11 f6 + r12 f12) a pending-XSK staged compile
      stages with B's revision and RETAINS its
      precheck cohort + pass-1 results in the debt keyed on that
      revision — the deferred publish carries B's revision,
      the observed acceptance advances the accepted revision, and
      the completion evaluates against the RETAINED results (no
      precheck re-run); and the pre-adoption-failure vs post-ACK-error
      distinction is pinned (pre-acceptance failure: flag rolls
      back, debts survive; post-ACK error: epoch opened, retry
      owner active); (vii) deferred-XSK adoption: a successful
      mandatory re-apply's own advance settles the debt exactly
      once. And the v8.8 epoch pairs
      (Codex r9 f5/f8/f9/f10, r10 f3/f4, r11 f2/f3, r12 f2/f3/f4/f5):
      (viii) the
      UNKNOWN-response adoption — a lost `update_fabrics` response
      followed by the next status poll adopts `status.Fabrics`
      into `m.lastSnapshot.fabrics` ONLY when
      `status.commit_revision == m.acceptedCommitRevision` AND
      `m.pendingCommitRevision == m.acceptedCommitRevision`
      (epoch-gated, Codex r12 f2/f3/f4), and a later
      route/scheduler partial clone carries the coherent accepted
      set (never an A-republish reverting B); plus the two
      divergence quadrants — Go-ahead-of-helper (staged newer
      config unpublished) keeps the newer snapshot whole (no
      A-fabric splice onto B's config), and helper-ahead-of-Go
      (landed-but-unacknowledged apply) routes to the
      active-config re-apply re-sync (no single-field adoption);
      PLUS the CHURN-IMMUNITY proofs (Codex r12 f2/f4): a clean
      FIB bump, a neighbor regen, a route overlay, a scheduler
      republish, a #5134 clone-republish, and a resolved-fabric
      persist each leave adoption UNBLOCKED (the epoch is
      fib-clean AND overlay-clean) — the v8.6 pair gate AND the
      v8.7 ConfigGeneration token would each have wedged or
      false-refused; PLUS the content-dedup case (Codex r13 f4
      — the v8.8 test asserted an impossible LOCAL collapse):
      a staged B whose forwarding content equals A's dedup-skips
      its publish; the manager then issues `note_commit_revision`
      (B's commit seq) — assert the helper sets its stored
      `commit_revision` to B's seq WITHOUT any snapshot mutation
      (persisted + echoed), Go marks
      `m.acceptedCommitRevision = m.pendingCommitRevision` ONLY on
      the observed success, adoption proceeds under the gate,
      and a FAILED/UNKNOWN transfer keeps suppression engaged
      (fail-closed, assert no adoption and no fenced send); AND the REQUEST-SIDE
      fence (Codex r11 f3 + r12 f2): a diverged `update_fabrics`
      fence (Codex r11 f3 + r12 f2): a diverged `update_fabrics`
      send is
      SUPPRESSED Go-side (staged-ahead or helper-ahead), and a
      forced send carrying a mismatched
      `expected_commit_revision` is REFUSED by the helper
      with NO fabric mutation and NO persist (assert the stored
      snapshot's fabrics byte-identical); (ix) the
      nil-config bootstrap teardown — a shutdown with no accepted
      config cancels any open epoch/debt explicitly AND clears
      `m.deferWorkers` AND `m.lastSnapshot.DeferWorkers` (all
      three authorities, Codex r11 f5); (x) the HA reverse-sync pair — an
      actually-accepted reverse/older peer config
      (daemon_ha_sync.go:534) mints `m.pendingCommitRevision` and
      supersedes newer-local debts on its observed publish,
      while the applied-identical
      shortcut (daemon_ha_sync.go:563) performs no adoption and
      mints/advances NOTHING; and the pre-adoption-failure counterpart
      (a reverse sync that fails before applying) leaves the
      epoch/debt state untouched.
  18. **same-plan retry deficit (Codex r4 B4 second half):** force
      a spawn failure (retained records with `last_error`), then a
      same-plan apply: the pending-aware deficit predicate MUST
      fire the reconcile, and the reconcile converges the marks.
  19. **update_fabrics matrix (Codex r5 B4, r6 f4/f5, r7 f2/f3):**
      (i) `[] → fab0`: fabric-parent bindings appear as
      `registered=true, armed=false, pending` and the
      pending-retry/next-apply's rebind binds and converges them;
      (ii) telemetry-only change (resolved MAC, `up`, peer data):
      NO replan, NO pending marks, vector untouched, persist
      happens; (iii) fab0 same name NEW parent_ifindex: EVERY
      non-operator registered slot is explicitly `armed=false,
      pending` (the enabled gate closes — the Codex r7 f2 exact
      form), and the rebind re-binds the identity on the new
      ifindex before `enabled=true`; (iv) removal-only change
      (fab0 → []): Rust-test-only today (production cannot encode
      an explicitly-empty fabrics slice — `omitempty` + Go
      early-return, protocol.go:83/manager_ha.go:166); in-test: the
      vector shrinks and orphaned workers are torn down by the
      next reconcile — no stale worker left forwarding; production
      removal goes through apply_snapshot and NEVER triggers the
      guard; (v) operator claim on a fabric candidate whose parent
      becomes invalid: claim dies at the deletion boundary (item
      15); (vi) killed sysfs-queues dir for an `rx_queues==0`
      interface during a fabric update: the guard fires (exact
      per-candidate skip cause), keeps the prior vector AND the
      prior projection, `refresh_fabric_links` publishes only the
      ACCEPTED (prior) projection, telemetry persists — and Go
      writes back the HELPER's accepted fabrics (NOT its request
      input), so a later route/scheduler wholesale clone carries
      the accepted set (the Codex r7 f3 authority fix); (vii)
      ENV-GATED resend suppression (v8.10 CAUSAL+ACKSET form,
      Codex r14 f11 — with explicit eviction ownership and an
      aggregate cap): (a) ONE SAMPLE PER VERDICT — the guard's
      verdict
      and the returned `guard_env_generation` derive from the
      SAME captured candidate-environment sample; (b) ACKSET —
      the helper retains a bounded (≤4) rejected-projection
      (identity, sample) set; the rejection response carries
      the (identity, generation) ack; a LOST rejection
      response leaves Go unsuppressed (it re-sends; the helper
      re-rejects idempotently and re-acks until a response
      lands — assert helper watch and Go cache can never
      diverge on the loss); a B-then-B′ rejection pair holds
      BOTH identities in the watch (assert a B′-only parent's
      recovery re-arms B′ and a B-only parent's recovery
      re-arms B — replace-oldest on a fifth); the FIFTH
      rejection evicts the oldest — and Go DISCARDS its
      cached suppression entry for the evicted identity on
      the next status echo (assert: evicted → cache-drop →
      re-send → fresh re-reject + re-ack → re-inserted — the
      evicted identity never stays suppressed forever,
      Codex r14 f11 = AGY r14 f4); (c) INCARNATION
      SCOPING — Go's suppression cache resets on every
      manager-driven helper (re)spawn; (d) DEBOUNCED DISPATCH
      with an AGGREGATE cap — the status poll that observes a
      bump with a suppressed identity dispatches at most once
      per identity per 5s AND at most 4 dispatches per 5s
      GLOBALLY (assert a SUSTAINED 1 Hz sysfs flap coalesces
      to ≤0.2 dispatches/s/identity, four concurrently
      flapping retained identities stay ≤4/5s, and a stream of
      NOVEL projection hashes churning evictions cannot exceed
      the aggregate cap — no unbounded 1 Hz ctrl oscillation,
      Codex r14 f11); (e) a
      guard-rejected identity with an UNCHANGED
      `guard_env_generation` is never resent (no pulse); and
      the helper bumps the generation ONLY on
      input change (two consecutive evaluations with identical
      inputs keep the value); (viii) response-loss: a timeout/EOF AFTER the
      inputs keep the value); (viii) response-loss: a timeout/EOF AFTER the
      helper committed the projection leaves ctrl=0 (the
      pre-disable fired on the different-projection request) until
      the next successful poll shows convergence (Codex r8 f5);
      (ix) separate projection changes for `name`,
      `parent_linux_name`, and `rx_queues` each trigger the
      mark-all gate individually; (x) the integrated Go path:
      pre-disable → RPC → immediate returned-status application →
      convergence — asserted end-to-end. (xi) pre-disable/sync FAULT
      INJECTION + the fabric sync debt state machine (Codex r10
      f7 + r11 f9 + r12 f11 + r13 f12): a lookup failure followed by a
      successful write+readback still proves zero and the RPC is
      sent; a failed or unobtainable READBACK blocks the send;
      the failure records a debt keyed `(commit_revision,
      projection-identity)` — the identity being the planner
      fields so a TELEMETRY update (peer-MAC resolve, link
      up/down) is the SAME identity and the debt is always
      findable (assert: a peer-MAC resolution mid-debt does
      NOT make the readiness query miss it, AGY r15 f7 = SMR
      r15 SMR15-7) — and records the last-sent
      `map_generation`
      per entry for the clear rule (v8.13, Codex r17 f12 —
      the payload-hash rule is replaced); the map commit STANDS (assert:
      the BPF map mutation is NOT rolled back); the debt
      retries on the ticker/wakeup/dispatch cadence; a CLEAN
      sync clears it ONLY when its `map_generation` is the
      debt's OR NEWER (assert a stale clean
      retry carrying an older generation can NOT clear the newer
      payload's debt, and an unrelated clean status does NOT
      clear at all — keyed supersession); a CLEAN GUARD
      REJECTION also records a readiness-relevant debt
      (map-new/helper-old — assert it is not silent);
      takeover readiness ANDs `fabricPopulated` with
      `FabricSyncStateOK()` via the NEW no-argument
      manager-owned consistency query (assert a
      permanently-failing sync keeps readiness FALSE with the
      map committed) at ALL FOUR call
      sites (fab0 explicit, fab1, and BOTH clear legs —
      daemon_ha_fabric.go:738-756/:944-957/:771-778/:969-976,
      not just :752-759);
      (xii) the clean guard-hit release: a
      transient-sysfs guard-hit leaves the readiness state
      untouched and ctrl re-enables IMMEDIATELY on the clean
      response in the same tick (RPC-length pulse), and the
      REJECT→ACCEPT bypass proof (Codex r11 f9): B rejected
      (sysfs killed), ctrl re-enabled, sysfs RECOVERS
      (`guard_env_generation` bumps), the SAME B is retried —
      the send is preceded by a FRESH verified pre-disable (no
      value-edge suppression), and a lost response to that
      accepted B leaves ctrl=0 until the poll converges;
      (xiii) the
      UNKNOWN-with-no-helper-commit release: a response lost with
      the helper un-committed releases at ~failed-RPC + 1s poll +
      RTT (≈7s budget); (xiv) the response-loss →
      lineage-gated
      adoption → partial-clone preservation chain (item 17(viii)'s
      integrated form); (xv) the budget assertions (Codex r11
      f11): the ≈19s figure is asserted as the HEALTHY
      unsuppressed baseline for an ACCEPTED projection change
      (pre-disable + RPC + ~5s scheduling + ~10s readiness +
      status tick + jitter), AND the warm-clock worst case is
      asserted honestly — a same-name/new-parent-ifindex
      projection with the retry clock already at the 60s floor
      converges in ≈60s + readiness + poll + RPC + jitter (the
      exponent-preserving reset does not pull it earlier), with
      the event-storm test asserting that honest delay rather
      than hiding it (the storm preserves the exponent — a
      same-membership mark during the storm lands on the floor).
  20. **v8.13 chain tests (Codex r17 f13 = SMR r17 SMR17-6 —
      the v8.12 fold NAMED these without writing them; each is
      specified with the false-green shape it must refuse):**
      (a) MIGRATION + EXPOSURE GATE: a legacy `active.json`
      migrates to revision 1 (allocator ordering: the same
      `Load`'s expired-confirm recovery gets 2, never
      double-1); a capability-1 (old) writer REFUSES the
      revisioned file rather than erasing it; a FAILED
      migration write leaves the dataplane in the
      legacy-zero gate AND records the exposure debt; and
      CRITICALLY: a pair write failed at promotion → the
      commit reports success WITH the pending-durable
      warning and NO dataplane apply runs (assert the
      helper never sees B) → the persist retry lands the
      write with NO config event → the
      `PersistDegraded()`-polled drain FIRES and drives
      the full revised `applyConfigLocked` (assert the
      three-bucket precheck runs, B's MAC debt is
      recreated, and the helper is observed at B's
      revisions) — the retry ALONE exposes B (the v8.12
      hole had no owner); a chain of gated B then C
      converges on C (latest-wins drain); the HA leg:
      `syncAndApply` stamps NO applied digest for a gated
      apply (assert the peer's equal-text suppression can
      never skip the later push, and the receiver's own
      exposure debt converges it); the false-green refused:
      inspecting revision allocation + disk retry without
      asserting the dataplane exposure.
      (b) PAIRED TRANSPORT: every `ConfigSink.ApplyConfig`
      caller passes the revision argument (compile-break
      proves the census); the re-sync drain's revision
      flows EXPLICITLY through the revised
      `applyConfigLocked(ctx, cfg, commitRevision)`
      (assert the carried pair is the drain-time
      `ActivePair()` read); boot reads the pair UNDER the
      wrapper's hold (assert a migration-retry interpose
      test); the live-MAC second leg REUSES the outer
      pair (assert: a promotion interposed BETWEEN the
      legs — operator commit AND the persistence
      transition's `s.mu`-only retry — is NEVER compiled
      by the second leg; B's own queued flow runs B's
      precheck); the false-green refused: asserting
      precheck execution while letting the second leg
      re-read.
      (c) PING/BOOT: a send before the ping returns the
      manager-local `not_seeded` error AND records the
      boot-apply debt; the debt FIRES with ZERO config
      events (assert the drain — not a manually invoked
      second apply); the ping runs before the build
      stamps Generation/FIB (order asserted); the seeded
      state resets on respawn (a post-respawn Compile
      re-pings before minting); post-respawn the paired
      replay carries `ActivePair()`'s current pair; the
      false-green refused: asserting ping-precedes-build
      while the boot retry has no owner.
      (d) FRESHNESS: T1 captures inputs, T2 captures
      inputs and publishes, T1's send is ABANDONED
      (buildSeq mismatch) — assert T1's content never
      reaches the helper even when T1 acquires `m.mu`
      first at send; the helper refuses a forced
      strictly-older token (`stale_snapshot_token`); the
      semantic hash produces EQUAL hashes for two
      identical builds (token excluded — dedup survives);
      ALL FIVE producers route through the primitive
      (locked entry for the already-locked auxiliary
      publishers — no self-deadlock; unlocked for
      Compile's publish leg); the false-green refused:
      manually assigning token values instead of driving
      the capture/send ordering.
      (e) ERROR_CODE: each producer emits its code
      (stale_completion on the rebind handler ordered
      BEFORE any field clearing; diverged_fabric;
      epoch_rollback + publication_rollback;
      note_cas_refusal via the named dispatcher entry;
      stale_snapshot_token); a typed response survives
      the OK=false discard and drives the common
      lineage-observation routine (note echo → accepted →
      divergence, in order); an UNTYPED failure copies NO
      status (today's handling byte-identical);
      `not_seeded` never appears on the wire; the
      false-green refused: parsing one code while the
      other producers/consumers are unexercised.
      (f) RESERVATION CHAIN: T2 starts (captures T1's
      `{true,true}`), T1 finishes ACCEPTED (recorded,
      non-head), T2 fails pre-publish — the head's Finish
      applies T2's restore AND replays T1's ACCEPTED
      (assert the terminal state is NOT the resurrected
      `{true,true}` — the v8.12 ABA dies); panic phase
      classification (pre-wire → PRE-SEND;
      possibly-landed → UNKNOWN; post-acceptance →
      tail); PENDING-XSK STAGED stores its token and the
      deferred leg finishes it; a newer StartCompile
      finalizes an orphaned open predecessor as OVERLAP
      (assert `m.compileInFlight` clears and the (v)
      echo resumes); helper death before the leg
      finalizes UNKNOWN; the CLI default reservation
      never panics; the false-green refused: asserting
      "T2 restores its own prior" without checking the
      prior contains finished T1's `inFlight=true`.
      (g) CHECKED QUIESCENCE: the merged
      `PrepareLinkCycleChecked` (no split API remains —
      compile-break); an operator bump between Claim and
      the method is `Stale` (abandon WITH unwind); `m.mu`
      contention before any mutation is `RetryLater`
      (applySem released, batch + token kept, NO unwind);
      a try-lock skip AFTER the quiescence began routes
      through the restore finalizer (assert workers are
      never left stopped); `stop_workers`
      timeout-but-landed → the unconditional restore runs
      (rebind re-spawns the plan's workers); the hold
      span is asserted (m.mu released before the MAC
      phase — no self-deadlock); the false-green refused:
      mocking an atomic method without the phase
      boundary.
      (h) RESTORE DEBT: an ORDINARY recovery rebind
      failure records the restore debt (assert the #5134
      debt is NOT consulted — it self-clears on
      non-deferred snapshots); missing-process → respawn
      → the daemon-owned revised full apply replays
      `ActivePair()` (assert NO bare rebind against the
      empty helper); ctrl error → the debt retries at
      5/10/30/60s with the edge Warn and no terminal cap;
      status error → the poll reconciles; the false-green
      refused: a debt record without the paired replay.
      (i) CAUSAL FABRIC: concurrent map writers serialize
      through the manager's wrapper (the direct key
      writes route inside it; the legacy-adapter bypass
      is enumerated and production-unreachable); the
      payload is built from the SAME sample as the
      mutation (a peer-MAC change between mutation and
      payload is impossible — assert the TOCTOU shape
      cannot construct); `map_generation` seeds from the
      ping echo on re-init (readiness recovers); the
      capability bit distinguishes new-helper-zero from
      old-helper-zero (old → fail-closed); a full
      snapshot advances accepted even with equal fabric
      content (idempotent advance); the first-startup
      proof arrives via `startClusterComms`'s population
      goroutines (readiness true after bringup with
      fabrics configured); the false-green refused:
      manually manipulating counters.
      (j) FAIRNESS/WARN: the Warn fires PERIODICALLY
      every 60s keyed on the first-queue timestamp; a
      `RetryLater` re-queue CONTINUES the episode (assert
      the Warn still fires under sustained `m.mu`
      contention); acquisition stops the episode; the
      honest FIFO text is asserted in docs only (the
      kernel-unreapable class needs no test).
- The fail-fast invariant (Q6, resolved r1): assertions live ONLY
  in tests and only over well-defined planner/activation
  transitions.
- Protocol canaries: `userspace-dp/src/protocol/tests.rs`
  exact-schema snapshots updated to pin `activation_state`,
  `complete_deferred`, `commit_revision` + `publication_rev`
  (snapshot + status), `expected_commit_revision`,
  `note_commit_revision`, `provenance`, `stored_defer_workers`,
  `guard_env_generation`, `rejected_projections`, AND the
  v8.13 additions `snapshot_token`, `fabric_map_generation`,
  `accepted_fabric_map_generation`, and
  `ControlResponse.error_code`
  deliberately — INCLUDING each field's missing-field
  semantics (old Go omits → serde defaults; old helper
  ignores → the documented degrade; a missing
  `stored_defer_workers` (revision 0) never reconciles; a
  missing `provenance` defaults to operator; a missing
  capability bit in the ping exchange means an OLD helper —
  fail closed).
- `make test-rust` (full cargo suite) clean; `cargo build`
  warning-free. Fleet cap honored:
  `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6749`.

**Go (option D + gates + retry + daemon ordering):**

- Manager unit test for the D warn, desired- and state-gated:
  (i) desired==true + `Registered && !Armed && state=="none"` →
  exactly one warn on the false→true edge, none on subsequent
  ticks, clears after re-arm; (ii) `state=="pending"` or
  `"operator"` → NO warn; (iii) desired==FALSE → NO warn; (iv)
  missing field (old helper) → reads as `"none"` (warn when
  desired).
- Manager unit test for the arm-sync defer gate (v8 epoch): with
  `m.deferWorkers == true` and desired==true, the sync issues NO
  arm — INCLUDING during the link-cycle quiescence sleep (the flag
  now spans it); disarm still passes; the flag clears only on
  tagged-rebind success (link-cycle flow) or just before the
  synchronous live-change re-apply.
- Manager unit test for the pending-activation retry (v8
  actionable form + Codex r7 f5): (i) ACTUAL armed +
  registered+ifindex pending + flag clear + no debt/in-flight →
  exactly one plain rebind, then backoff 5s→10s→20s→60s (with
  jitter) on repeated failure; (ii) desired==true but
  `lastStatus.ForwardingArmed == false` (protocol-gated) → NO
  rebind; (iii) `registered=false` pending (S1/S2) → NO rebind
  (replan-only convergence); (iv) at attempt ~12 ONE edge Warn
  with fingerprint fires and the retry CONTINUES at the 60s floor
  (NO terminal cap) — and a recovery at attempt >12 with NO
  intervening state/config/link event succeeds (the transient
  EAGAIN/ENOMEM class, Codex r7 f5); (v) reset on pending-set
  change does NOT touch the exponent (Codex r10 f5); an immutable
  pending-membership transition pulls the deadline EARLIER with the
  exponent preserved; (vi)
  `pendingWorkerArm` set → NO rebind; (vii) completion in-flight →
  NO rebind; (viii) a failed tagged completion triggers the TAGGED
  completion retry (epoch-scoped, explicitly exempt from any
  terminal cap), not the untagged one; (ix) a first-Compile
  failure (publish error at :350) followed by a production status
  tick still drives the retry (loop ensured after
  `ensureProcessLocked`).
      (x) reset-clock cases (Codex r8
      f7 + r9 f7 + r10 f5): frequent config/link events never
      POSTPONE an already-due retry (pull-earlier only — no
      starvation), a failed retry pass mutating
      `last_change`/`last_error` does NOT reset the backoff (the
      fingerprint is immutable identity membership only — no
      self-reset churn), and an EVENT STORM injected past attempt
      12 proves the exponent keeps climbing to the 60s floor
      regardless of event rate (events never touch the exponent;
      only immutable membership transitions pull the deadline
      earlier, exponent preserved).
- Manager unit test for `complete_deferred` provenance (v8 + AGY
  r7 f1/f2): the NotifyLinkCycle path sets
  `CompleteDeferred: m.deferWorkers && !m.hasActiveMACDebt` — true
  ONLY with an open defer epoch AND no active `macEpochDebt`
  entries (a `macAndLinkRecovery`/`linkOnlyRecovery` entry NEVER flips
  it false — pinned, Codex r11 f7); a spurious
  / flap-driven NotifyLinkCycle with the flag clear sends false;
  a NotifyLinkCycle fired while MAC debt is ACTIVE sends false
  (the latch survives); the busy-watchdog path
  (maps_sync.go:1484) never sets it; a timeout-but-landed tagged
  rebind is idempotent on retry.
- Manager unit test for the Go latch authority (Codex r6 f8):
  after a successful completion, a route-overlay or scheduler
  republish carries `DeferWorkers=false` (no re-latch).
- Manager unit test for the edge-triggered sync-failure warn
  (Codex r5 M10 = SMR r5 N1 = AGY r5 minor-1): a persistent
  refusal logs ONCE on the false→true transition, not per tick,
  and once on recovery; a repeated-tick test pins the count.
- Daemon unit test for the defer-flag epoch + MAC-success gating +
  MAC debt contract (Codex r5 B6/B8, r6 f6/f8, r7 f4/f6, AGY r6
  f2/f4): the flag is SET through apply → MAC programming →
  quiescence → dispatch; clears only on completion success OR on
  epoch rollover (a no-MAC-work commit at compile start); a failed
  `programRethMAC` suppresses the dispatch, leaves the flag set
  (assert `m.deferWorkers == true` immediately after), and records
  the phase-revalidating debt keyed on (accepted config
  generation, desired member→MAC set); the "MAC installed, setUp
  failed" (true, error) shape retries the link-up phase (not the
  MAC phase), INCLUDING after a process restart (the debt's
  desired set is revalidated, not assumed); TWO OR MORE members
  with order permutations complete only when EVERY member STILL
  IN `macEpochDebt` has the desired MAC AND is up (v8.7, Codex
  r11 f7 — the v8.6 "every member up" rule contradicted the
  buckets); the MIXED cohort predicate (Codex r11 f7): one
  member bucket-i (MAC mismatch) + one member bucket-ii
  (correct MAC, down) — the epoch completes when the bucket-i
  member validates ALONE, the bucket-ii member's
  `linkOnlyRecovery` entry never gates (assert
  `hasActiveMACDebt` counts ONLY `macEpochDebt`), and the
  healthy dataplane forwards throughout; the EVERY-ATTEMPT
  reread with OBLIGATION PRESERVATION (v8.8, Codex r12 f7 —
  v8.7 transferred a down bucket-i member to a MAC-CORRECT
  class and silently dropped the unprogrammed MAC): a bucket-i
  member whose link flaps
  down during its own MAC cycle TRANSFERS to
  `macAndLinkRecovery` at the NEXT
  validation attempt (non-gating) with its FULL obligation
  recorded — and the recovery executes as the SAFE XSK
  TRANSACTION (v8.9, Codex r13 f8): assert
  `PrepareLinkCycle` (ctrl disable + worker join) runs BEFORE
  any DOWN→MAC→UP (never a bare `programRethMAC` cycle on a
  live XSK), the FULL repair list runs after (DAD/link-local,
  RX-VLAN, VLAN child MACs, VIP/VRRP, announcements, RA, AND
  proxy-ARP/NDP — assert the reassert is dispatched, not
  left to the 30s ticker), the quiesce-all+rebind-all outage
  is asserted as the budgeted class (a rare operator-visible
  event, per-member quiescence explicitly a follow-up), and
  the member carries traffic only AFTER the rebind's OBSERVED
  success (the post-rebind status shows the member's slots
  bound+ready — the debt does NOT clear on a void
  `NotifyLinkCycle` return); the failure shapes: a MAC-write
  failure AFTER a successful DOWN (`(false, error)`,
  daemon_reth.go:260-265) keeps `linkCycled` SET (the cycle
  began — assert the history survives the return value), a
  rebind failure retries the whole recovery on the debt's
  backoff, and
  the member carries traffic only AFTER the full sequence —
  a permanently-down bucket-i member transfers at the FIRST
  autonomous retry (≤5s, epoch completes) with the obligation
  visibly outstanding (edge Warn); the BUCKET-III pass-1
  reread (AGY r12 f5): a correct/up member flapped down after
  the precheck gets a `linkOnlyRecovery` entry at pass 1
  (non-gating — assert it is NOT left unmonitored); the STICKY
  (non-gating — assert it is NOT left unmonitored); the STICKY
  `linkCycled` (Codex r12 f8): a member whose MAC install
  cycled the NIC records it, and a later equality no-op does
  NOT erase the history (the post-cycle repairs + rebind
  still run);
  a newer accepted config supersedes ALL THREE
  collections BEFORE any stale MAC work runs; a member removed from
  config cancels only its own entries in EVERY collection;
  live-change vs link-cycle
  completion modes dispatch on the recorded history; a
  permanently-failing member leaves the box deferred with an edge
  Warn; and (v8.6, replacing the stale v8.3 restart test that
  contradicted the buckets, Codex r10 f6): the restart test
  instantiates a FRESH daemon with an active config, a CORRECT
  installed MAC, and an administratively-DOWN link — the boot
  precheck classifies bucket ii (correct MAC, down) and creates a
  LINK-RECOVERY debt entry with NO epoch, NO latch, NO pending
  marks (the healthy dataplane forwards normally), and the entry
  re-drives `setUp` until the member returns; a sibling restart
  case with a MISMATCHED MAC classifies bucket i and opens the
  epoch normally; and the provenance test pins the POSITIVE
  current-epoch form: the tag fires only when the epoch is open
  AND the debt has settled (all phases validated for the current
  desired set — exercised through the REAL daemon-to-manager
      validation handoff, never by manually constructing "epoch
      open, no active debt" (Codex r9 f8); plus the bucket edges
      (v8.6 form): a CONFIGURED-DISABLED member (`disable: true`)
      is EXCLUDED from validation AND from link recovery (the debt
      never calls `setUp` on it — config is authoritative,
      types_interfaces.go:22, networkd.go:595); a MISSING member
      (netlink LinkByName error) is excluded entirely and its
      return is classified by the NEXT precheck (factory MAC →
      bucket i → normal epoch flow; no link-up-debt-to-MAC-epoch
      transition); and an administratively-down (but not
      configured-disabled) member classifies bucket ii WITHOUT
      opening an epoch; the inline first validation
      settles in-flow WITHOUT reacquiring the semaphore (no
      re-entrant applySem); and the stale-attempt race +
      fairness proof in its v8.10 form (Codex r14 f8/f9/f10,
      superseding all prior forms): (a) the autonomous attempt
      BLOCKING-acquires applySem with NO timeout (v8.12,
      Codex r16 f13, superseding every timeout form): a
      synthetic owner holding for a short window does NOT
      delay it past any bound (there is none), and a
      SEQUENCE of legal owners (a commit, then the 30s
      proxy-ARP reconcile, then a ~20s IPsec rebind hold,
      then a FULL APPLY whose whole-pipeline hold runs
      several ~67s-capped control requests
      (process_control.go:31-56/:85-103)) still lands the
      attempt (FIFO waiter wake + bounded owner holds —
      assert EVENTUAL progress with the FIFO position
      PRESERVED (no position-losing retries); assert the
      60s queued-state Warn fires while queued and STOPS/
      resets on acquisition (the Warn surfaces a wedged
      owner; it does not provide progress — progress comes
      from FIFO + terminating owners, Codex r16 f13)); (b) a SEPARATE flow acquires the
      semaphore, completes the superseding accepted commit
      (advancing `m.acceptedCommitRevision`), and releases it;
      the attempt Claims, an operator CANCELS
      a member mid-work (the binding verb takes `m.mu` but not
      `applySem`, manager_status.go:132-179 — the claimToken
      bumps), and the work loop's PRE-MUTATION revalidation
      ABANDONS the remaining work (assert: the mutation after
      the cancellation never happens; earlier idempotent
      mutations stand and re-Claim later; the v8.9 "stale
      Claim" shape is deleted — Claim always returns the
      CURRENT token, so the fence lives in the work loop,
      Codex r14 f8);
      (c) the post-acquisition m.mu contention case: the
      status loop holds `m.mu` through a long control request
      (up to 120s) — the attempt's TRY-LOCK-OR-SKIP Claim
      skips to its next backoff tick (assert it does NOT
      monopolize `applySem` while blocked on `m.mu`); and the
      epoch-qualified `pendingWorkerArm` (Codex r13 f9): a
      superseded #5134 debt is CLEARED (assert the generic
      activation retry is not suppressed by a stale Boolean).
      And the recovery-transaction proofs (Codex r14 f9 + AGY
      r15 f3/f6 = SMR r15 SMR15-4/6/9): a
      `PrepareLinkCycle` FAILURE (ctrl-disable or stop_workers
      error) ABORTS the attempt outright (assert NO
      DOWN→MAC→UP executes on live UMEM — the void Prepare of
      today (process_linkcycle.go:145-162) gains an error
      return); and EVERY quiesced attempt ENDS with a restore
      (rebind + ctrl re-enable) on EVERY outcome — success,
      phase failure, or abort — assert the dataplane returns
      to RUNNING before the backoff (never left stopped);
      TWO concurrently-due members BATCH into ONE
      quiesce (assert a single Prepare/Notify pair covers
      both — no back-to-back whole-dataplane quiesces), and a
      member whose link returns DURING the batch's quiescence
      is ABSORBED at the batch's re-Claim (its MAC program
      runs INSIDE the batch's program phase BEFORE the
      settle — assert NO wrong-MAC member is rebound, v8.12
      Codex r16 f12), and a member returning AFTER the
      program phase rides the DEBT'S NORMAL BACKOFF RETRY
      (v8.13, Codex r17 f10 — the event-fired attempt is
      deleted (no link-event machinery exists); assert the
      batch's rebind DID bind the member's slots with its
      factory MAC (accepted, stated honestly) and the
      debt's next attempt programs the MAC and rebinds —
      the exposure is backoff + FIFO queueing + the
      transaction, asserted honestly, never "~1s");
      a `programRethMAC` is NEVER called as a "revalidation"
      inside a rebind (assert no double-cycle — programs
      happen only in the batch's program phase or an
      attempt's own flow; a MAC work after the settle sleep
      requires a RENEWED settle before rebind); the
      wrong-MAC binding test's "physically binds its slots"
      expectation is CORRECTED: the absorbed member's slots
      rebind only POST-PROGRAM (v8.12, Codex r16 f12's
      contradiction with the old test); a
      post-quiescence phase failure retries ONLY the missing
      phase (assert the completed phases are NOT redone —
      physical repair is not re-run after it succeeded); the
      observed-clear predicate: a REGISTERED
      operator-disarmed member clears correctly (raw Ready
      ignores armed, refresh_bindings.rs:253-261) while an
      operator-UNREGISTERED member's entries are cancelled by
      the member-removal rule (assert no wedge on either
      side, Codex r14 f9 = AGY r14 f3's refinement); and the
      work loop's per-mutation `claimToken` re-read is
      TRY-LOCK-OR-SKIP (assert a contended read skips the
      mutation to the next tick with the item still claimed —
      no `applySem` monopoly behind a 120s status-loop
      request, AGY r15 f6 = SMR r15 SMR15-4).
 And the v8.4 mechanics
      (AGY r9 f1/f2/f3/f4): the THREE-BUCKET precheck — (i) MAC
      mismatch → epoch opens; (ii) MAC correct + link down →
      link-recovery entry ONLY (assert NO epoch, NO latch, NO
      pending marks, and the healthy dataplane forwards: the AGY
      r9 f1 case — an unplugged cable on one member must NOT
      disable the dataplane); (iii) MAC correct + link up →
      nothing; the in-flow settlement — a fully-successful first
      programRethMAC settles the debt synchronously and the tag
      fires IN THE SAME FLOW (assert CompleteDeferred=true reaches
      the helper — the AGY r9 f2 deadlock shape); a
      partially-failed first attempt suppresses completion until
      the debt's full-settlement EVENT dispatches the tagged
      rebind itself (not an unrelated event); the fabric
      pre-disable does NOT reset neighborsPrewarmed on a guard-hit
      (ctrl re-enables on the next poll's normal readiness gate)
      but DOES reset it on an accepted projection change; and any
      operator arm (global or per-binding) resets
      pendingRetryAttempts/pendingRetryNextAt to zero.
- `maps_sync` gate test (AGY r1 f3): synthesized post-expansion
  status (new slots converged) through `probeBindingsReady`/
  `bindingForwardingLive` — ctrl admits, shim rows go READY.
- `make test-go` clean.

**Smoke (loss userspace cluster, lock-cell wrapped):** deploy;
verify iperf3 baseline to 172.16.80.200; commit an ADDITIONAL zoned
VLAN unit (e.g. a new `reth0.90` in the wan zone) while armed;
assert transit continues with no manual arm toggle and
`show ... bindings` reports the new slots armed with
`activation-state=none`. ALSO exercise the deferred path: a
reth-membership-touching commit (the RETH MAC flow) completes with
workers bound and no manual action. Re-apply CoS after the deploy
per the cluster protocol (`apply-cos-config.sh`).

**Docs (module contract, same work item):**
`userspace-dp/src/server/README.md` — the arm-model narrative gains
the tri-state lifecycle, the coherent-vector invariant, the
completion-epoch contract (explicitly: clearing the Go-side defer
flag does NOT activate anything — only a provenance completion or
a non-deferred apply does, AGY r5 nit-2 / SMR r5 N2), the
operator-claim rule and its deletion boundary, the
failure-restoration semantics, the identity-checked volatile
refresh, and the pending-activation retry (incl. the rebind
completion log gaining the pending count, AGY r4 n2, and the
retry's own attempt/fingerprint diagnostics, Codex r6 NIT).
**Release note / upgrade note (AGY r1 Q7 + Codex r1 m8 + AGY r3
f4):** required and PROMINENT on: (1) the fix takes effect only
after the HELPER restarts into the new binary (process.go:18
reuses a pingable same-config helper) — `systemctl restart
xpf-userspace-dp` on upgrade; (2) the posture change — deferred
(RETH-MAC-pending) plan-changing commits now fail-close transit
until the provenance completion, and a failed MAC program no
longer binds workers onto a stale MAC. The helper restart is
REQUIRED, not advisory (Codex r8 f6's literal mixed-version
producer: a new Go + old helper leaves new slots
`registered=true, armed=false, state=none` — D's warn is the
tripwire for exactly that window, and only the helper restart
closes it); and option D itself is a RELEASE GATE (Codex r8 f7):
it ships in this PR (recommended — it is the issue's detection
leg) or as an immediate stacked prerequisite, but the issue is
not complete and no release ships without it.
## 10. Out of scope (explicitly)

- **Go per-binding armed AUTO-convergence (option B)** — rejected
  (§5-B). The v8 pending-activation retry is NOT B: it schedules a
  reconcile of the current coherent plan and changes no armed bit
  itself; the tri-state makes its target unambiguous
  (planner-requested activations only, never operator claims).
- **#6702/#6681 planner queue-geometry rework** — they own
  binding-count consequences; this fix is compatible but does not
  implement any of their layout change.
- **`bindingForwardingLive` / `enabled` / `probeBindingsReady` gate
  semantics** — the gates are correct; the bug is the DEFAULT they
  were fed. No gate changes.
- **The pre-existing mid-defer-window early-BIND hazard** (Codex r3
  B6's other half): a registration toggle during the defer window
  runs an armed reconcile that BINDS workers before the RETH MAC
  cycle — present on master (the toggle's reconcile is defer-blind).
  v8 closes the early-CONVERGE side (the defer gate), the early-ARM
  side (the Go arm-sync gate + durable epoch), and schedules the
  correct completion (tagged completion retry); the toggle's
  early-BIND itself is a separate pre-existing issue filed as a
  follow-up.
- **Operator-claim lifetime at planned-identity deletion (Codex r6
  f2 + r7 f8's boundary, documented):** an operator-claimed slot
  whose planned `(linux-interface, queue_id)` identity is DELETED —
  by candidate dropout (invalid fabric parent, unreadable queue
  count), by rename (the linux name changes), or by queue-count
  contraction (the global-min layout dropping high-queue identities)
  — loses the claim WITH the binding; the later namesake is a new
  binding (S5 pending) with no claim. Durable cross-deletion claims
  would need a manager-side claim registry (rejected as machinery
  disproportionate to an ephemeral diagnostic state that already
  dies at global fan-outs); documented in the server README.
- **Operator-claim registration degradation across a flap** (kept
  from v7): an operator-claimed slot whose interface flaps recovers
  as `registered=false, operator` — no-forward intent survives
  exactly; registration is not planner-restored (the tri-state
  cannot distinguish disarmed-then-force-cleared from
  unregistered). Documented.
- **Re-keying the coordinator's live-worker lookup beyond the
  identity check** — the identity-checked volatile copy (§5-C) is
  in scope (one predicate); deeper re-keying of the worker table
  belongs with #6702's coordinator-adjacent planner rework.
- **Persisted-state migration** — none needed (state file
  write-only; the fields are additive with serde defaults).
- **Operator-override persistence across global arm toggles** — the
  fan-out still clears claims (C3, registered slots); making
  diagnostic disarms durable is a separate product decision.
- **The retired v3/v4/v5/v6/v7 machinery** — leg-scoped R1/R2; the
  full fan-out defer-completion; v4's identity-scoped S4 revert;
  v4's arm-at-replan S5; v5's bool marker; v5's
  replan-at-convergence plan gate; v6's failure-path
  replan-from-restored; v6's transient defer flag; v6's
  verb-identity completion; v7's full-FabricSnapshot fabric
  comparison; v7.1's fixed-5s retry. Recorded at bce10126c /
  f679a791a / 0c0b9b677 / 6969b6167 / 3e388fde8 / d61e76ec3.

## 11. Open questions for adversarial review

Resolved across rounds 1-10 (for the record): Q2, Q5, Q6, Q7,
applied-vs-requested init, full fan-out vs scoped, Q3 (uniform S3),
Q5-toggle, Q7-boot, the plan gate (deleted), the failure-path replan
(deleted), E2's operator arm (deleted), C2's discriminator (result-
based), the latch signature/atomicity, the retry's fixed-5s shaping,
the transient-MAC stranding, the update_fabrics wrong-physical
hazard, the Go shadow-latch, the quiescence race, the debt
generation scope (now the v8.8 pending/accepted epoch split), the
in-handler fabric reconcile, the guard authority split (now
EPOCH-GATED adoption + fence on `commit_revision` ON THE WIRE, v8.8 —
the pair gate, the appliedSnapshot gate, and the ConfigGeneration
token all died to named counterexamples), the leaking epoch (rollover-at-acceptance),
the terminal retry cap (rate-capped forever, exponent preserved),
the torn identity check (planned identity), the claim boundary (any
planned-identity deletion), Q2 convergence scope (plan-scoped), the
two-phase precheck (reverted + three-bucket), the epoch-open
deadlock (in-flow settlement + settlement-driven dispatch), the
prewarm reset on guard-hits (plain ctrl write), the mixed-bucket
outage (bucket-i-only validation in a THREE-OBLIGATION debt with
obligation-preserving transfer, v8.8,
configured-disabled and missing
excluded), the precheck→validation flap (reread at EVERY validation
attempt over ALL desired members, v8.8), the contaminated
stored-generation guard and BOTH successor token designs (replaced by
the `commit_revision`-carried
`expected_commit_revision` refusal, v8.8), the ownerless re-latch
(all three authorities clear together, seven exits/transitions
enumerated incl.
UNKNOWN outcomes + helper restart, v8.8), the fabric adoption hybrids
(epoch-gated + request-side fence + divergence suppression, v8.8), the
reject→accept pre-disable bypass (causal env-gated suppression +
always-disable-on-send + typed error outcome, v8.8), the
TRY-acquire starvation (bounded blocking acquire, v8.8), the
poll-vs-Compile defer-intent race (intent is a Compile argument
set under m.mu, v8.8),
and Q1's unowned-producer hunt (no producer beyond
the three owners through nine enumerations; the mixed-version
producer is the documented exception with the required helper
restart).

Remaining questions for round 18, each invitable to PLAN-KILL with
a concrete counterexample:

1. **Completeness, final form.** Exhibit a path to
   `Registered && !Armed` with `activation_state == none` that is
   NOT global-fan-out-created, NOT operator-created, NOT a
   documented deletion-boundary re-creation, NOT an
   enabled-gate-explicit armed=false pending mark, and NOT the
   documented mixed-version case.
2. **CLOSED (v8.8, SMR r11 N2 + Codex r11 f7 + r12 f7/f8).** A
   bucket-i member whose link flaps down DURING its own MAC cycle
   transfers to `macAndLinkRecovery` (obligation preserved) and
   its slots are bound and armed normally by the completion (the
   XSK binds on the netdev's queues, which exist while the
   netdev is admin-up; the slot passes no traffic while the
   carrier is down — the same posture as any down interface,
   with NO dataplane-wide gate); the link's return is driven by
   the recovery entry (program-MAC + setUp + the post-cycle
   repair sequence + XSK rebind) — NO passive link-UP→rebind
   machinery exists in production (the sole `NotifyLinkCycle`
   call is the apply flow's; the general link monitor emits
   SNMP traps only, daemon_flow.go:725-749 — the v8.7 sentence
   claiming otherwise was wrong, Codex r12 f1's N2 row).
   Holding bucket-i slots pending until the link returns
   is AGY r9 f1's one-dead-member-holds-the-dataplane class,
   correctly rejected.
3. **CLOSED (v8.7, Codex r11 f4).** The question's premise was
   wrong: `m.publishedSnapshot` does NOT track the helper on
   every successful path (content-dedup, neighbor regens, and
   FIB bumps advance it without a full publish —
   process_status.go:72-80, manager_neighbor.go:129-140 — while
   `bump_fib` leaves the helper's stored generation untouched,
   snapshot.rs:470-473), so the v8.6 token false-refused
   legitimate same-epoch completions. The v8.7 token is the
   epoch config's `ConfigGeneration` (compile-stamped, never
   overlay-bumped) against the helper's stored full-snapshot
   generation (advanced only on full applies, snapshot.rs:153)
   — both sides FIB-clean, no false refusal, no bypass; and the
   refusal check is ordered FIRST in the rebind handler.
4. **CLOSED (v8.8, Codex r11 f2 + r12 f2/f3/f4; subsumes SMR r11 SMR11-1).**
   The wedge was real but the desyncing leg is the GENERATION,
   not the fib: `BumpFIBGeneration` advances Go's
   `m.lastSnapshot.Generation` (manager_generation.go:71) while
   the helper's `last_snapshot_generation` moves only on full
   applies — ANY successful bump (and neighbor regens, and
   fabric-persist) split the v8.6 pair. The v8.7 gate keys on
   `commit_revision` ON THE WIRE (v8.8 — the appliedSnapshot gate
   ALSO died: its capture is deliberately delayed while
   deferred and records the mutated scalar post-rebind); the
   request side is fenced by `expected_commit_revision` on
   `update_fabrics` plus divergence send suppression.
5. **CLOSED (v8.7, SMR r11 N3).** A configured-disabled
   (`disable: true`) member that is also a zoned binding
   candidate binds and arms as an ORDINARY (physically inert)
   binding: networkd keeps the link down, the XSK binds on its
   queues (they exist while admin-up), no traffic flows, and the
   all-or-nothing `enabled` gate counts it as a normal binding.
   That is the intended posture for THIS PR — the binding plan
   reflects config presence (zoned), not runtime link state; a
   `disable`-driven planner exclusion is #6702's
   candidate-filter territory
   (`include_userspace_binding_interface`), explicitly out of
   scope here.
6. **Round-17 disposition table audit.** §1's r17 table maps
   every r17 finding (Codex 13 BLOCKER + 1 MAJOR + 1 MINOR;
   AGY 4 BLOCKER + 3 MAJOR + 1 MINOR + 1 NIT; SMR 3 BLOCKER +
   3 MAJOR + 5 MINOR) to its v8.13 fold, and every fold this
   revision was verified per-edit against the file. Which
   row is claimed-but-wrong this time?
7. **Cumulative hazard budget, final sign-off (v8.8 honest
   numbers, Codex r11 f11 + r12 f14).** Healthy unsuppressed
   baseline for
   an ACCEPTED fabric projection change ≈19s (pre-disable + RPC
   + ~5s scheduling + ~10s readiness + poll + jitter); the
   WORST case is NOT 19s — a same-name/new-parent-ifindex
   projection can mark the same identities pending while their
   retry clock already sits at the 60s floor (the
   exponent-preserving reset never pulls it earlier for
   unchanged membership), so warm-clock convergence is ≈60s +
   readiness + poll + RPC + jitter (≈70s), and defer/debt
   suppressions can extend it further. Clean guard-hit =
   RPC-length pulse; a guard-rejected projection resends ONLY
   on an observed `guard_env_generation` bump, and the
   observing poll DISPATCHES the retry (no +30s fabric-ticker
   wait — v8.7's unbudgeted delay died); isolated
   UNKNOWN-no-commit ≈7s; permanent bind
   failure 60s-floor probes forever with edge Warns; unplugged
   RETH member = link-recovery retry with NO dataplane impact
   (mixed-bucket included); a MAC-mismatch epoch whose bucket-i
   member goes permanently down TRANSFERS at the first
   autonomous retry (≤5s) with its MAC obligation preserved in
   `macAndLinkRecovery` (v8.8 — the v8.7 transfer DISCARDED
   it); persistent control failure = indefinite fail-closed
   (correct posture while retries and diagnostics stay alive);
   the MAC debt's bounded blocking acquire has no starvation
   mode. Which of these, if any, is
   unacceptable for the severity-High class, and why?
