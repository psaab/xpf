# #6749 — binding-plan expansion registers new slots unarmed, dataplane disabled indefinitely

**Status: DRAFT v8.30 — pending adversarial plan review (round 35)**

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
; v8.14 folds Codex r18 (11 BLOCKER + 3 MAJOR) + AGY
  r18 (4 BLOCKER + 4 MAJOR + 1 MINOR + 1 NIT) + SMR
  r18 (2 BLOCKER + 3 MAJOR + 5 MINOR): the exposure
  gate becomes PAIR-SPECIFIC (Codex f4 — `durableRevision`:
  a pair is exposable iff `R <= durableRevision`, so
  durable A's mandatory second leg is never gated by
  nondurable B's interposed pendency — the global
  boolean's fatal counterexample dies; the check runs
  at `applyConfigLocked`'s ENTRY before any
  SNMP/web-management/bootstrap/kernel/VRF mutation)
  with a TYPED `ApplyOutcome{Ran, Exposed,
  ExposurePending}` (Codex f3 — every wrapper's success
  tails (MarkActiveApplied, session clear, peer push,
  applied stamp, armedActive, CF clear,
  lastAppliedConfigGen) gate on `Exposed`, so a standby
  enforcing A never reports B applied or
  transfer-ready; the exposure debt record carries the
  HA `item.gen` and runs the DEFERRED tails after
  observed acceptance); the exposed marker becomes
  REVISION-KEYED (Codex f2 — `appliedRevision` alongside
  `appliedDigest`, so a same-text/new-revision gated
  promotion never inherits applied==true and the
  equal-text shortcut cannot fire); the exposure debt
  carries an ALWAYS-LIVE timer (explicit `nextWake`,
  the MAC debt's Claim shape); the commit's
  pending-durable note rides `compiled.Warnings`
  synchronously (plumbed through REST/gRPC/CLI today);
  and the AUXILIARY-PRODUCER suppression
  (`m.exposureGateActive`, SMR18-1) closes the
  A-config/B-FIB overlay hybrid (the v8.13 "staged-ahead
  engages" text was wrong on its own terms — nothing is
  staged, so nothing suppressed the overlay). The
  freshness validation moves to the publish leg's ENTRY
  (Codex f5 — BEFORE any XDP/pin/shim/bootstrap-map
  side effect) with invalidation DELAYED until a
  successor's OBSERVED ACCEPTANCE (a newer capture
  never invalidates; T2's pre-publish failure leaves
  T1 viable; the SUPERSEDED report fires only on a
  real accepted successor), the validation compares the
  CONTENT HASH (SMR18-2 = AGY f4 — the input-ref
  capture was unimplementable) against
  `m.latestBuiltHash` plus the new `m.currentPair`
  field, and `buildSeq` SEEDS from the ping echo
  (Codex f6 — the surviving-helper token wedge dies).
  The reservation chain's fold order is PINNED (Codex
  f8 = AGY f5 = SMR18-3 — recorded outcomes apply
  oldest-first, the head's own LAST, with the 7×7
  matrix in §6 (PENDING-XSK STAGED is a state, not a
  Finish) and three-node coverage). The checked
  quiescence gains the MUTATION LEASE (Codex f9 — the
  claimToken re-read AND the netlink syscall under ONE
  `m.mu` acquisition, so an operator cancellation
  serializes atomically before or after each mutation,
  never inside it) and the acquisition rule is
  reconciled (while holding `applySem`, ALL `m.mu`
  acquisitions are BLOCKING — bounded by one legal
  owner hold, and the applySem transaction already
  prices RPC-length holds; the v8.13 `RetryLater`
  release-and-requeue lost FIFO position and could
  starve indefinitely; try-lock-or-skip survives only
  for non-applySem probes, AGY r15 f6's original
  motivation). The restore debt becomes DAEMON-SIDE
  with a real pull API (Codex f10 —
  `RecordRestoreDebt`/`ClaimRestoreWork`/
  `ReportRestoreAttempt` mirroring the MAC debt; the
  ctrl retry is the FULL `NotifyLinkCycle` sequence
  (rebind + status reconcile + the reconciled enable —
  never a bare ctrl write); the ctrl=0-while-bound
  window is fail-closed + Warn-visible + retry-forever).
  `map_generation` becomes the CANONICAL
  `(payload, generation)` pair (Codex f11 — built once
  per mutation from the rich locked sample (map view +
  names/overlay/queues/Up + the neighbor-CACHE
  resolution (SMR18-5 = AGY f3, never a netlink dump
  under the lock)); EVERY carrier uses its own
  payload's generation — full snapshots read the
  canonical pair at the publish leg, so a failed
  `update_fabrics` followed by a stale clone advances
  the helper's accepted only to the CLONE's (P0, g0),
  never to current g (the v8.13 idempotent-advance
  false proof dies); the debt's retry re-sends the
  recorded pair). The late-arrival cutoff is pinned
  (Codex f12 — absorption covers only members DUE AT
  THE CLAIM; a return between Claim and rebind rides
  the debt's own current backoff — up to the 60s
  floor, SMR18-8 = AGY f7). The FIFO contract drops
  the false systemd claim (Codex f14 — SIGKILL cannot
  reap D-state; the kernel-unreapable class is
  unbounded PERIOD; the 60s Warn + out-of-band operator
  action is the only mitigation). The note verb is
  enumerated end-to-end (Codex f7 — the request arm,
  the dispatcher match arm, and the decoded-response
  typed-return Go API, SMR18-7 = AGY f2/f9). §9's
  chain tests gain the false-green refusals per Codex
  f13's table (the always-live timer, the
  pair-specific gate, the deferred tails, the
  revision-keyed marker, delayed invalidation, the
  pre-side-effect validation, the token seed, the
  inverse + 7×7 + three-node folds, the lease, the
  blocking acquisition, the real restore drain, the
  failed-send/stale-carrier race, the honest warm
  blackhole) @ pending
; v8.15 folds Codex r19 (11 BLOCKER + 4 MAJOR) + AGY
  r19 (3 BLOCKER + 4 MAJOR + 1 MINOR + 1 NIT, f3
  NOT-VERIFIED on re-derivation) + SMR r19 (2 MAJOR +
  5 MINOR): the gate becomes FULL (Codex f2 — FRR is
  INSIDE `applyConfigLocked`, so the ENTRY gate defers
  the whole tail (dataplane leg, FRR, routing, fabric)
  and the drain re-runs it; the v8.14
  `m.exposureGateActive` suppression flag is DELETED —
  with the RIB never moving during the window, the
  A-config/B-FIB hybrid (SMR r18 SMR18-1), the
  stuck-flag case (AGY r19 f2), AND the suppressed-
  scheduler-close fail-open (Codex f3) all die at the
  root); `durableRevision` gains its implementation
  pins (Codex f2 — active-pair writes only, advance
  after `WriteFileDurable` returns, re-derived from the
  envelope at Load); the deferred set gains the
  AUTO-ROLLBACK census (Codex f5), the debt retains
  the LAST EXPOSED configuration (Codex f5's A→B→C
  fix — the drain's session invalidation composes
  last-exposed → current, never only the newest
  delta), the tails become PHASED with a TAIL DEBT
  (Codex f5 — a phase failure retries only the failed
  phase, never a re-apply), the HA settlement rides an
  INTERNAL ordered-loop item (Codex f4 —
  `recordAppliedConfigGen` advances in order, no CAS
  race), and the commit note rides a RESPONSE COPY
  (Codex f5's aliasing fix — never `compiled.Warnings`
  itself); the applied-marker verbs PARAMETERIZE
  (Codex f6 = AGY r19 f4 VERIFIED — the parameterless
  `MarkActiveApplied()` reads the CURRENT active at
  mark time, so an interposed promotion would be
  falsely stamped; all four call sites pass the
  captured pair) with the identity scopes SEPARATED
  (SMR r19 SMR19-2 — revisions are node-local: the
  pair comparison is node-local; the inter-node layer
  keys to the digest + the deferred gen settlement);
  the freshness validation loses the hash leg (SMR
  r19 SMR19-1 = AGY r19 f1/f5 = Codex f7 — the hash
  was both incoherent with the canonical fabrics
  replacement and a both-abandoned deadlock; the TWO
  legs (PAIR-CURRENT with the revision-0 CLI
  exemption (SMR r19 SMR19-4) + NO-ACCEPTED-NEWER-BUILD)
  plus the token backstop cover every case) and gains
  the NAMED phase split (Codex f8 — ping →
  side-effect-free shim COMPILE + build → VALIDATE →
  MUTATION phase); the re-sync gains the GO-LOCAL
  firing rule (Codex f7's ownerless path —
  `ActivePair().revision > m.acceptedCommitRevision`
  with no apply in flight FIRES the debt: the
  autonomous owner for every abandoned/failed build);
  the reservation fold's reduction is corrected
  (Codex f9 — PRE-PUBLISH FAILURE restores the NEWEST
  ACCEPTED PREDECESSOR's intent (or the chain-root
  value), NEVER the node's captured prior (the
  both-fail resurrection dies); the HEAD-POP rule
  guarantees the final fold fires; the SIX-outcome
  table (PENDING-XSK as the open state) is in §6);
  the mutation lease is REPLACED by the MEMBER-BOUNDARY
  model (Codex f10 — the lease was cross-layer
  impossible (manager `m.mu` vs daemon `programRethMAC`)
  and per-syscall insufficient (a mid-DOWN→MAC→UP
  cancellation would leave a member down); the token
  check runs at member boundaries (blocking, cheap);
  an in-flight member's program ALWAYS COMPLETES (no
  half-cycled state); a cancellation takes effect at
  the next boundary (wasted-not-harmful — no operator
  MAC verb exists); the §6 try-lock text is corrected
  to blocking); the restore drain ACQUIRES `applySem`
  and calls the LOCKED apply directly (Codex f11),
  with `StartCompile(rethMACPending)` carrying THE
  PRECHECK'S OWN RESULT (never `StartCompile(false)`
  arming workers on stale MACs); the canonical fabric
  pair becomes UNIFORM (Codex f12 — every carrier uses
  the CURRENT `(payload, generation)` (the (P0, g0)
  stale-carrier invention dies), the payload's MACs
  come from the MAP's OWN fields (never a cache
  re-resolution), the debt clears on an observed
  accepted ≥ recorded (the full snapshot's acceptance
  is the self-healing leg), and the dedup hash covers
  the FINAL wire content); the typed error becomes
  `*ControlError{Code, Resp}` with `errors.As`
  (AGY r19 f7 — the caller-discipline trap dies) and
  the old-helper note behavior is pinned (Codex f13 —
  untyped legacy failure, never a CAS-refusal
  classification); §9's chain tests gain the
  false-green refusals per Codex f14's table; and the
  hazard budget gains the authorization-affecting
  classes (Codex f15) @ pending
; v8.16 folds Codex r20 (10 BLOCKER + 3 MAJOR) + AGY
  r20 (2 BLOCKER + 1 MAJOR + 1 MINOR, f1 NOT-VERIFIED)
  + SMR r20 (2 MAJOR + 6 MINOR): the gate's FOLLOW set
  gains the SECURITY-CLOSEOUT class (Codex f2 — the
  management-auth mutations (SNMP communities, web
  credentials, host authorization) are
  monotonic-revocation obligations that follow the
  commit even under the gate (they forward no
  packets); the deferred set is exactly {dataplane
  leg, FRR, routing, fabric}); the flow-level
  pair-current rule (Codex f3 — EVERY leg re-reads
  `ActivePair()` and re-checks at ITS start (the
  dataplane leg aborts BEFORE any Compile mutation;
  the mandatory second leg ABORTS on interposition
  (reconciling tests (b)/(d)), returning
  SUPERSEDED-BY-NEWER-COMMIT with the coverage
  argument (SMR20-1)); the HA session fence rises AT
  EXPOSURE (Codex f4 — before any session
  invalidation, held until the settlement's high-water
  advance; the loop's item protocol gains the
  `settleExposure` internal kind (an ingress that
  answers neither nil nor error); the enqueue is
  non-blocking with a repost-into-tail-debt rule);
  `m.lastExposedPair` becomes a real state machine
  (Codex f5 = SMR20-2 — it advances at EXACTLY the
  `m.acceptedCommitRevision` advancement points) and
  the session invalidation's base is ALWAYS
  last-exposed (Codex f5 — every commit/drain/
  re-sync/restore composes last-exposed → new-pair,
  killing the direct-durable-C case); the phased
  completion ledger rides EVERY FIRST-EXPOSURE (Codex
  f6 — commit, drain, GO-local re-sync, restore's
  first-exposure; a replay of an already-exposed pair
  needs none); the wire defer stamp is NODE-LOCAL
  (Codex f7 — `snap.DeferWorkers` stamps from the
  compile's OWN reservation node's deferIntent, never
  the shared mutable global); the phase-split fiction
  dies (Codex f8 — `CompileUserspaceShim` mutates
  host networking, so the stale-build-mutates-host
  class is killed at the DAEMON's leg-entry
  pair-current check instead (auxiliary producers
  clone — no Compile at all); `m.acceptedBuildSeq`
  named; the helper tracks newest-SEEN token; the
  mid-flow respawn is benign (SMR20-8)); the operator
  binding/queue verbs REFUSE busy while a quiescence
  is active (Codex f9 — `m.linkCycleActive`, closing
  the re-spawn-during-quiescence class the
  member-boundary model only claimed dead) and the
  failed-UP ownership is pinned (Codex f9 — a
  member's `linkOnlyRecovery` entry survives the MAC
  debt's cancellation); the stale lease/try-lock
  texts are swept (Codex f9); the push marker gains
  ONE store-atomic `(text, digest, revision,
  exposed)` capture and the auto-rollback joins the
  marker census (Codex f10); the restore debt is
  DAEMON-SIDE with daemon-local helpers (Codex f10);
  the fabric REMOVAL TOMBSTONE (Codex f11 —
  `removed: true`, the helper DROPS the fabric state
  on a deliberate clear instead of preserving the
  stale working set); the drain-failure policy (SMR
  r20 SMR20-3 = AGY f3 — keep the debt with the
  standing backoff, never a 1s thrash, never a
  clear-on-error); the GO-LOCAL qualifier deleted
  (SMR r20 SMR20-7 = AGY f2 — the rule fires on
  `active > accepted` PERIOD (the drain's applySem
  already serializes; the leak's OVERLAP finalization
  rides the drain's own StartCompile) + the
  unconditional Finish defer); the identity-vs-
  telemetry separation restated (SMR r20 SMR20-6 =
  AGY f1's resolution — the projection identity
  excludes MACs, so a MAC resolution is a telemetry
  generation-mint, never a replan); the settlement
  context + FIFO pins (SMR r20 SMR20-5); the
  first-member boundary check + the idempotency/
  serialization answer (SMR r20 SMR20-4 = AGY f4);
  §9's chain tests re-specified per Codex f12's
  table; and the hazard budget gains the v8.15/16
  classes (Codex f13) @ pending
; v8.17 folds Codex r21 (12 BLOCKER + 2 MAJOR) + AGY
  r21 (2 BLOCKER + 2 MAJOR) + SMR r21 (1 BLOCKER + 2
  MAJOR + 4 MINOR): the PROMOTION-SERIALIZATION
  INVARIANT is stated (Codex f3, VERIFIED —
  `commitAndApply` holds `applySem` across
  `configstore.Commit` AND the apply
  (daemon_apply_commit.go:129-175; HA sync
  (:326-355), commit-confirmed (:525-531),
  auto-rollback (:629-645) the same; the persistence
  retry advances only durability; the boot-recovery
  promote precedes all flows) — NO promotion can
  interpose mid-flow, so the v8.16 flow-level
  re-reads and the second-leg abort rule are REVERTED
  (the abort itself recreated the workerless strand
  (Codex f4 = AGY f1); the residual pair-current
  concerns are the manager-internal classes the
  staged-ahead suppression and the legacy-zero mode
  already own); the closeout set is re-scoped to
  PROVEN MONOTONIC TIGHTENING ONLY (Codex f2 — B's
  REMOVALS only, computed against the union of
  A-live and B-desired reachability; additions,
  listener expansions, and relaxations DEFER; the
  closeout gets its own persistent retry debt; and
  it never consults deferred state (no
  `ApplyResult.ManagedInterfaces`, no B-derived
  host-inbound view over A's live interfaces)) with
  the flow re-ordered (closeout first, then the gate
  check, then the forwarding mutations (AGY f4));
  `beginFirstExposure(B) -> {priorPair,
  firstExposure, ledgerID}` is the atomic transition
  (Codex f6 — the wrapper carries the IMMUTABLE
  prior through completion (acceptance no longer
  tears the invalidation base), and the boot
  unknown-base policy (persisted exposed sidecar or
  a conservative clear-all when the base is
  unprovable)); the completion cursor `{pair,
  phaseCursor, completionState}` is installed
  ATOMICALLY at acceptance (Codex f7 — the re-sync
  clears only after the record installs; a completed
  replay skips tails; an incomplete replay resumes;
  a crash re-runs idempotent tails conservatively);
  the reservation token becomes an explicit Compile
  argument (Codex f8 — `Compile(cfg,
  commitRevision, reservationToken)`; the staged
  object carries the token + its baked-in
  `DeferWorkers`; clones preserve the cached value;
  #5134 forces `false` only for the generation it
  owns completion for); the helper's token fence is
  newest-ACCEPTED, not seen (Codex f10 — a rejected
  snapshot never advances the fence, and the seed
  reads newest accepted (the seen=100/accepted=5
  catch-up wedge dies); the token is per-build
  immutable (a wire retry carries the same token;
  `publication_rev` keeps the attempt order)); the
  GO-LOCAL rule gains the live-registration
  discriminator (SMR r21 SMR21-1 = AGY f2 = Codex
  f9 — `active > accepted` AND **no live
  deferred-publish registration for the active
  pair** (the pending-XSK staged window is owned by
  its `OnXSKBound` registration; a leaked
  registration lets the rule fire and OVERLAP-
  finalize the orphan (the AGY r20 f2 closure
  survives))); the settlement carries `(peer
  incarnation, gen, pair, settlementID)` with
  loop-side dedup/ack (Codex f5 — an
  old-incarnation settlement can never advance a
  new incarnation; exactly-once via the ack), and
  the drain's fence raise is MAX-CAS with an
  ownership token (never lowers; only its owner
  releases); the verb gate covers each physical
  quiescent transaction and clears at restore
  completion or debt transfer (SMR r21 SMR21-2 =
  AGY f3 = Codex f11 — the restore debt's backoff
  intervals do not hold it; each retry re-sets it
  for its window), and the link-down observation is
  recorded through a CANCELLATION-INSENSITIVE path
  before token disposition (Codex f11 — a stale
  Report can never un-record it); the tombstone is
  specified across all three paths with the
  configured fabric NAME as its stable key (Codex
  f12 — incremental, full build (omitted; the
  config re-adds at the next apply — runtime-scoped),
  and the runtime refresh (dropped from the preserved
  merge)); the outbound marker revalidates against
  `ActivePair()` inside the send-time write lock
  (Codex f13 — a stale capture is re-derived, never
  sent); §9's chain tests re-specified; and the
  hazard budget gains the v8.16/17 classes @ pending
; v8.18 folds Codex r22 (13 BLOCKER + 1 MAJOR) + AGY
  r22 (3 BLOCKER + 2 MAJOR + 1 MINOR) + SMR r22 (2
  MAJOR + 4 MINOR): the promotion-serialization
  invariant gains its EDGES (Codex f2 — SyncApply's
  topology/identity guard (:381-402) and
  PromoteRollback's nil-target bootstrap teardown are
  serialized DECISIONS, not violations, and the
  GO-LOCAL drain's revised `applyConfigLocked` carries
  the SAME guard (a restart-only config is never
  live-applied by the re-sync); the startup
  promotions (Load's boot-recovery promote, the
  legacy migration, bootstrapFromFile) complete
  BEFORE the apply scheduler starts, and the
  rollback executor's timer is armed only AFTER the
  boot apply (a near-expiry timer could otherwise
  fire mid-startup — B-derived naming with A-derived
  dataplane)); the stale interposition texts are
  swept (Codex f3 — the v8.12-v8.16 "operator
  promotion needs no applySem" claims were FALSE
  under the invariant); the closeout's A-live model
  is last-EXPOSED with a targeted removal projection
  (Codex f4 — beginFirstExposure's prior, never
  store-active `oldActive`; the owners take whole
  desired configs, so the closeout synthesizes a
  REMOVAL-ONLY desired projection and applies it
  through class-targeted removals (web binds read
  CURRENT kernel addresses; MIXED changes defer
  wholesale); the debt keys on the pair and
  RECOMPUTES from live authorization to the latest
  desired state on each retry (a stale B debt never
  removes something C keeps); the failure TRANSITION
  (a closeout failure does NOT prevent B's exposure
  — the alternative adds an unbounded gate); the
  operator-session strand is the intended
  monotonic-revocation consequence with the
  out-of-band recovery channel documented; and
  networkd/services are DEFERRED everywhere (they
  consume `ApplyResult.ManagedInterfaces`)); the
  beginFirstExposure lifecycle is cross-layer (Codex
  f5 = AGY f3 = SMR22-2 — manager-side at acceptance
  (the same `m.mu` section that advances
  `m.acceptedCommitRevision`), the `{priorPair,
  ledgerID, firstExposure}` triple rides the
  `ApplyResult`, `oldActive` is RETIRED from the
  invalidation path, the cursor installs atomically,
  the prior config is durable via the store's
  rollback/archive trees, and an unrecoverable base
  (sidecar-present included) triggers the
  conservative clear-all); the OVERLAP finalization
  CANCELS the staged leg's registration (SMR22-1 =
  AGY f2 = Codex f6 — and the send primitive checks
  the reservation node is still OPEN for staged
  sends; the registration's lifetime is bounded by
  {OnXSKBound firing with the liveness check, OVERLAP
  finalization, helper death, an explicit stage
  timeout → the GO-LOCAL re-drive}); the deferred-
  publish discriminator becomes a REAL REGISTRY
  (Codex f7 — `{pair, token, state, registeredAt}`
  with the transitions (staged → live; the
  syncSnapshotLocked catch-up publishes → completes
  (the ACTUAL publisher, process_status.go:10-140);
  OVERLAP → cancelled; helper death → died; stage
  timeout → the GO-LOCAL re-drive)); the helper
  fences on newest-ACCEPTED with the
  `accepted_snapshot_token` echo field (Codex f8 =
  AGY f1 — and the leftover newest-SEEN text is
  swept); the fence becomes an OWNER-TOKEN REGISTRY
  (Codex f9 — every fence writer takes a slot; the
  effective fence is the max over live slots; a
  writer clears only its own slot; slots die with
  their owner's terminal path) and the settlement
  lifecycle completes (allocation, dedup
  retention/GC, duplicate re-ack, stale-discard ack,
  release on every terminal path; the crash case
  rides the cursor's durability); the restore debt's
  retry uses a RESTORE-AUTHORIZED quiesce (Codex
  f10 — each retry becomes a NEW transaction:
  reassert the gate, stop operator-spawned workers,
  restore, rebind the CURRENT plan) and the
  link-state observation becomes the UNCONDITIONAL
  `RecordLinkObservation` (Codex f10 = AGY f5 — a
  stale Report can never un-record it, and it SKIPS
  already-removed members); the tombstone PERSISTS
  until a successful nonzero map transaction (Codex
  f11 — the config-authoritative form could
  resurrect a down fabric into a blackhole (every
  installed fabric down → the redirect falls back
  to one (fabric.rs:446-464)); the full build reads
  the canonical pair verbatim); the outbound marker
  becomes a STRUCTURED SEND TRANSACTION (Codex f12
  — `{queued, sentPair, sentDigest}`; the marker
  records the SENT pair; the exposure check holds
  gated pairs (AGY f4)); §9 re-specified; and the
  hazard budget gains the v8.17/18 classes @
  `0e4604ac4` (r23: SMR DEMAND-REVISION (2 BLOCKER +
  2 MAJOR + 3 MINOR + 1 NIT); AGY DEMAND-REVISION (3
  BLOCKER + 2 MAJOR + 1 MINOR); Codex infra-blocked
  (usage limit, reset Aug 10 — two documented
  attempts; 2-of-3 per the infra-blocked exception))
; v8.19 folds SMR r23 (2 BLOCKER + 2 MAJOR + 3 MINOR
  + 1 NIT) + AGY r23 (3 BLOCKER + 2 MAJOR + 1 MINOR):
  the restart-only guard × GO-LOCAL loop dies to a
  revision-keyed RESTART-SUPPRESSION marker (SMR23-1
  = AGY r23 f1 — a guard-refused promotion never
  advances `m.acceptedCommitRevision`, so the
  GO-LOCAL rule re-fired forever: the drain's
  guard-refusal now records the terminal marker
  (Warn-once with the reason), the rule's firing
  condition gains `ActivePair().revision ∉
  restartSuppressed`, the re-sync debt CLEARS into
  the marker (terminal, not into acceptance), a
  newer promotion R′ > R re-arms the rule for R′
  only, and the boot path owns the post-restart
  apply); the timer edge gains its MECHANISM
  (SMR23-2 = AGY r23 f2 — `Load` RECORDS the
  recovered confirm window WITHOUT arming the timer
  (the `time.AfterFunc` moves out of
  store_persist.go:231-253), and the daemon arms it
  via a store call (`ArmRecoveredConfirmTimer()`)
  AFTER the boot apply completes — an already-
  expired deadline fires immediately on that arm,
  ordered after the boot apply by construction and
  serialized by `applySem`; the executor
  registration stays at daemon init
  (daemon_run.go:130-136)); the status-loop
  catch-up acceptance gains its completion-tail
  owner (SMR23-3 = AGY r23 f3 — the catch-up's
  `beginFirstExposure` installs the cursor AND posts
  a completion notice on the bounded daemon channel
  (enqueue-after-unlock, the OnXSKBound shape
  (maps_sync.go:451-456)); the daemon drains it and
  runs the phased tails exactly-once per cursor
  entry (the cursor's `completionState` is the
  single authority — the Compile-leg wrapper and
  the listener never double-run); the
  helper-restart shape's no-op tails are named
  (invalidation no-op on the empty base; the peer
  push + applied stamp still run for HA)); the
  OVERLAP finalization ALSO clears the staged
  snapshot reference atomically (SMR23-4 = AGY r23
  f4 — `m.lastSnapshot` never references a cancelled
  staged object (same `m.mu` section), AND
  `syncSnapshotLocked`'s publish path gains the
  defense-in-depth token-liveness branch (a dead
  token → skip the publish + drop the staged
  reference → the GO-LOCAL re-drive owns)); the
  stage timeout is pinned (SMR23-5 — five minutes,
  a scheduler entry recorded at staging and
  cancelled with the registration, converting to
  the GO-LOCAL re-drive; the never-recoverable-XSK
  posture stated: the dataplane stays down by
  CONFIG INTENT (the config committed an
  unbindable plan), Warn-visible at the
  transitions); the fence registry gains its read
  discipline + crash window (SMR23-6 — the
  admission check reads the effective fence and the
  high-water as ONE consistent snapshot; the
  process-exit window (slots + in-memory
  high-water lost) stated in the budget); the
  structured send gains its wiring (SMR23-7 = AGY
  r23 f5 — constructor-injected `activePair`/
  `isExposed` closures (no `pkg/cluster`→
  configstore import), the marker records from the
  RESULT (the claim moves after the send; the
  reconciler reads `sentPair` from the result),
  and the exposure drain's completion wakes the
  sync reconciler); §9 (b)/(d)/(f) gain the
  assertions (AGY r23 f6); §8's budget gains the
  new classes; the cursor-crash phrasing corrected
  (SMR23-8) @ `8d1911b5f` (r24: SMR DEMAND-REVISION
  (1 BLOCKER + 1 MAJOR + 4 MINOR + 3 NIT); AGY
  DEMAND-REVISION (1 BLOCKER + 2 MAJOR + 1 MINOR +
  1 NIT); Codex infra-blocked (third documented
  attempt; 2-of-3))
; v8.20 folds SMR r24 (1 BLOCKER + 1 MAJOR + 4 MINOR
  + 3 NIT) + AGY r24 (1 BLOCKER + 2 MAJOR + 1 MINOR
  + 1 NIT): the completion notice's tails gain their
  pair-currency gate (SMR24-1 = AGY r24 f1 — a stale
  notice for B drained after C's apply ran A→B
  invalidation over C-permitted sessions and
  overwrote C's stamp; and the abort-only fix LEAKS
  (C's B→C delta never covers
  A-permitted/B-revoked/C-revoked sessions): the
  drain acquires `applySem`, re-reads the CURRENT
  pair at drain time, composes prior → CURRENT (the
  uniform base — complete with no over-deletion),
  currency-gates the applied stamp + peer push, and
  marks a superseded notice's cursor entry
  SUPERSEDED (terminal)); the cursor's
  check-and-advance is pinned (SMR24-2 = AGY r24 f2 —
  one manager method under `m.mu` for every
  `{phaseCursor, completionState}` read-modify-write;
  the transports are per-acceptance unique, so the
  residual race is phase-level); the post-clear
  `m.lastSnapshot` value is pinned NIL (SMR24-3 =
  AGY r24 f3, downgraded on the verified nil-guard
  census — overlay/neighbor/HA/status/applied-view
  all nil-guard under `m.mu`; the census becomes a
  build-time canary; the transient overlay/scheduler
  publish gap until the re-drive rebuilds is
  stated); the notice channel's overflow gains a
  periodic pending-cursor sweep (SMR24-4 = AGY r24
  f4 — the notice is an optimization over the sweep;
  the enqueue failure Warns); the suppression
  marker's recording moves to the SHARED
  guard-refusal path (SMR24-5 — the sync-receive
  guard records too, so the drain never fires even
  once for R); §9 (a) gains the listener assertions
  (SMR24-6 = AGY r24 f5 — the stale-notice
  composition, the currency-gated stamp, SUPERSEDED,
  the sweep); the stage-timeout/bind race
  serialization (SMR24-7), the `isExposed` closure's
  lock-order rule (SMR24-8 — writeMu → `s.mu` only),
  and the held-push-forever budget note (SMR24-9)
  fold @ `783c9581d` (r25: SMR DEMAND-REVISION (0
  BLOCKER + 0 MAJOR + 2 MINOR + 2 NIT); AGY
  PLAN-READY-WITH-NITS (2 MINOR + 2 NIT); Codex
  infra-blocked (fourth documented attempt; 2-of-3))
; v8.21 folds SMR r25 (2 MINOR + 2 NIT) + AGY r25 (2
  MINOR + 2 NIT): the SUPERSEDED parenthetical is
  reworded (SMR25-1 = AGY r25 f2 — "the composition
  is covered by the newer pair's chain" was FALSE on
  its face (it is exactly the abort-only leak
  SMR24-1 traced) and contradicted the fold's own
  (i): SUPERSEDED now marks ONLY the pair-specific
  tails (stamp/push) as skipped-by-design while the
  invalidation (i) composes prior → CURRENT and RUNS
  for stale notices exactly as for current ones —
  reworded in the normative text AND the r24 table
  row, and §9 (a) pins the reading (a skip-everything
  implementation fails the test)); the sweep's
  semaphore + cadence are pinned (SMR25-2 = AGY r25
  f3 — the sweep rides the 1s status-application
  pass (a dropped notice delays the tails ≤ 1s +
  drain scheduling) and its per-entry execution is
  the SAME `applySem`-acquiring drain path as the
  notice's (one routine, two triggers)); AGY r25 f1
  (a claimed §9 (a) `C-permitted`→`C-revoked` typo)
  is NOT-VERIFIED (spurious — both the dispatched
  prompt and plan.md read `C-revoked`; an AGY
  misread of the wrapped clause pair); the applySem
  → `m.mu`
  lock-order census (SMR25-3) and the OVERLAP-clear
  → re-drive chain-state note (SMR25-4) fold @
  `b7b9ff1ae` (r26: SMR DEMAND-REVISION (0 BLOCKER +
  1 MAJOR + 3 MINOR); AGY DEMAND-REVISION (1 MAJOR +
  2 MINOR + 1 NIT); Codex infra-blocked (fifth
  documented attempt; 2-of-3); + the AGY r25 f1
  record correction @ `e728b2e7d`)
; v8.22 folds SMR r26 (1 MAJOR + 3 MINOR) + AGY r26
  (1 MAJOR + 2 MINOR + 1 NIT): the sweep never blocks
  the status thread (SMR26-1 = AGY r26 f1 — the
  v8.21 "ONE routine, two triggers" wording let the
  1s status pass execute a blocking `applySem`
  acquire (freezable for minutes behind a long
  control apply): the 1s pass now only SCANS and
  MARKS pending cursors (under `m.mu`, non-blocking)
  and DISPATCHES the per-entry drain execution to
  the daemon's apply scheduler — the same scheduler
  thread the notice drain rides, where the blocking
  acquire is safe; the status thread never takes
  `applySem`); the drain-time composition target is
  the drain-time EXPOSED pair (SMR26-2 = AGY r26 f2
  + f4 — a promoted-but-GATED successor C leaves the
  dataplane enforcing B, so composing A→C would
  delete B-authorized sessions: the invalidation
  composes prior → `m.lastExposedPair` at drain time
  (A→C when C is exposed, A→B when C is gated — one
  rule, both shapes), the stamp/push gate keys on
  STORE currency (the two "currents" named
  explicitly), and §9 (a) gains the gated-successor
  assertion); the r25 f1 row's mis-attribution is
  recorded (SMR26-3 — corrected at `e728b2e7d`);
  and the cursor registry's terminal-entry GC is
  pinned (SMR26-4, self-found — a terminal entry
  (completed or SUPERSEDED) is GC'd on the sweep
  pass that first observes it terminal, so the
  registry's live set is bounded by concurrently-
  incomplete exposures and the 1s scan is O(handful);
  the crash rule never reads a GC'd entry — it
  re-derives from the sidecar + store) @ `a5ddf88ed`
  (r27: SMR DEMAND-REVISION (0 BLOCKER + 0 MAJOR +
  1 MINOR + 1 NIT); AGY DEMAND-REVISION (2 MAJOR +
  1 MINOR + 1 NIT); Codex infra-blocked (sixth
  documented attempt; 2-of-3))
; v8.23 folds SMR r27 (1 MINOR + 1 NIT) + AGY r27 (2
  MAJOR + 1 MINOR + 1 NIT): the sweep's "dispatch"
  mechanism is named — and simplified away (SMR27-1
  = AGY r27 f2/f3 — the v8.22 wording left the
  scheduler queue's capacity/drop-policy/mark
  semantics unspecified (AGY's two horns: a bounded
  queue that drops leaves a marked-dispatched entry
  stuck forever — never pending again, never
  terminal; an unbounded queue is an OOM vector):
  there is NO dispatch channel at all — the
  scheduler's per-tick pass ITERATES THE PENDING
  CURSOR SET directly (the notice remains the
  fast-path optimization; the pending set IS the
  correctness path — no dispatched-flag, no queue,
  no drop policy, no stuck state: an entry is
  pending until terminal, and the scheduler drains
  the pending set through the ONE drain routine
  every tick); and the drain's cursor lookup gains
  its missing-entry contract (SMR27-2 = AGY r27
  f1/f4 — a drain dequeued for an entry a
  concurrent sweep already observed terminal and
  GC'd finds the key GONE: the lookup treats a
  MISSING entry as already-terminal (a safe no-op
  — the entry's work completed or was covered; the
  crash rule never depends on a GC'd entry), never
  a nil dereference or an unhandled error); the r26
  SMR26-1 row's dispatch phrasing is amended
  (AGY r27 f3); §9 (a) gains the GC'd-dequeue
  no-op assertion and the no-queue convergence
  assertion @ `6c6d00b09` (r28: SMR DEMAND-REVISION
  (0 BLOCKER + 0 MAJOR + 2 MINOR); AGY
  DEMAND-REVISION (1 MAJOR + 1 MINOR + 1 NIT);
  Codex infra-blocked (seventh documented attempt;
  2-of-3))
; v8.24 folds SMR r28 (2 MINOR) + AGY r28 (1 MAJOR
  + 1 MINOR + 1 NIT): the cursor's phase machine is
  the claim-or-skip TRI-STATE (SMR28-1 — the v8.20
  "check-and-advance" was ambiguous between
  claim-or-skip and check-then-execute-then-advance,
  and only the first is exactly-once: per phase,
  pending → claimed → complete, with the claim
  atomic under `m.mu` and a duplicate claimant
  skipping (a claimed-but-slow drain's phase
  completes on the first executor; a
  claimed-but-crashed drain is the in-memory-loss
  case the crash rule re-derives)); the failing-tail
  retry gains its cadence (SMR28-2 = AGY r28 f1 —
  the iterate-pending-set model re-invoked the
  drain on a failing entry every 1s tick: the entry
  stays pending (correct) but the retry rides a
  per-entry `nextAttempt` on the standing
  5/10/20/60s exponent-preserving ladder (the
  per-tick pass skips not-yet-due entries) and the
  failure Warns on the standing edge-detect); and
  the missing-entry contract goes UNIFORM (AGY r28
  f2/f3 — the scheduler's iterate drain picks up a
  Compile-leg entry CONCURRENTLY with its
  synchronous `ApplyResult` wrapper (the claim
  serializes the phases), so the wrapper's accessor
  can hit a GC'd key too: the missing-entry →
  already-terminal contract applies to EVERY
  registry accessor (drain AND synchronous
  wrapper)); §9 (a) gains the claim-collision,
  backoff, and wrapper-vs-GC assertions @
  `50f0ef069` (r29: SMR DEMAND-REVISION (0 BLOCKER
  + 0 MAJOR + 2 MINOR + 1 NIT); AGY DEMAND-REVISION
  (1 MAJOR + 1 MINOR + 2 NIT); Codex infra-blocked
  (eighth documented attempt; 2-of-3))
; v8.25 folds SMR r29 (2 MINOR + 1 NIT) + AGY r29
  (1 MAJOR + 1 MINOR + 2 NIT): the claim gains its
  panic-safe release and its lease (AGY r29 f1 —
  the v8.24 "claimed-but-crashed drain is the
  in-memory-loss case the crash rule re-derives"
  covered only PROCESS crashes: a goroutine PANIC
  (the process lives) pinned the phase `claimed`
  forever — skipped by every claimant, never
  terminal, never GC'd, no boot recovery (the
  "un-leased claimed trap")): (i) a `defer` wrapper
  around EVERY phase execution catches panics and
  atomically reverts claimed → pending WITH
  `nextAttempt` under `m.mu`, and (ii) the claim
  records `claimedAt` + a claim GENERATION and is
  STEALABLE after the named bound (the tail
  operations' own timeout sum) — the stealer runs
  with a bumped generation and the stale claimant's
  late advance is REFUSED (the generation check
  under `m.mu`); the release-on-failure composes
  with the backoff (SMR29-1 = AGY r29 f2: the
  claimed → pending release and the `nextAttempt`
  set are ONE `m.mu` operation, and the claim
  itself refuses entries whose `nextAttempt` is in
  the future (the due-check lives in the claim —
  the notice-triggered drain respects it too, never
  accelerating a backed-off entry)); the ladder's
  reset adopts AGY's form (AGY r29 f3, SUPERSEDING
  SMR29-3's terminal-only form: a SUCCESSFUL phase
  resets the entry's ladder to the base step for
  the remaining phases — each phase's failure is
  operation-specific, matching the standing debt
  behavior); and §9 (a) gains the panic-injection
  assertion (AGY r29 f4) @ `c9c70de90` (r30: SMR
  DEMAND-REVISION (0 BLOCKER + 0 MAJOR + 1 MINOR +
  2 NIT); AGY DEMAND-REVISION (2 BLOCKER + 1 MINOR
  + 1 NIT); Codex infra-blocked (ninth documented
  attempt; 2-of-3))
; v8.26 folds SMR r30 (1 MINOR + 2 NIT) + AGY r30
  (2 BLOCKER + 1 MINOR + 1 NIT): the lease's steal
  is FENCED (AGY r30 f1 — the v8.25 generation
  guard refused only the stale claimant's
  completion RECORD while its tail EXECUTION
  mutated the world un-fenced: a late
  `MarkActiveApplied(B)` regresses `appliedRevision`
  after C stamped C (a store stamp corruption that
  reports C unapplied permanently), and a late
  invalidation(A,B) deletes sessions C re-permitted
  — SMR r30 SMR30-1's "idempotency proofs" were
  WRONG for the multi-commit case (the stamp is a
  regression, not an idempotent set; the late
  invalidation is the SMR24-1 class reopened) and
  are RETRACTED): (i) the drain's claim checks
  LIVENESS AT ENTRY (a stolen/dead claim aborts
  the drain BEFORE any side effect — the
  missing/stolen-entry contract, same `m.mu`
  operation as the claim), (ii) the applied stamp
  uses the CAS form (expected store-current
  revision — `setAppliedDigest` (store.go:848) —
  refusing when the store has moved past), and
  (iii) the drain's `applySem` hold + the
  drain-time-EXPOSED composition order every
  mid-drain case (no exposure can move while the
  drain holds the semaphore; a live-claimed drain
  composes correctly at entry); and the steal is
  BOUNDED (AGY r30 f2 — the v8.25 fixed-interval
  steal spawned a goroutine every namedBound on a
  hanging phase, an unbounded leak): the steal (i)
  CANCELS the stale claimant's context (every tail
  operation takes the claim's ctx and aborts on
  cancellation; a kernel-wedged residue is the
  budgeted D-state class, out-of-band), (ii)
  ADVANCES the entry's ladder (a steal is a failure
  by construction — the cadence decays to the 60s
  floor, never a fixed spin), and (iii) is a
  REPLACEMENT (exactly one live claim generation
  per entry — a second steal is refused while a
  live one stands); the defer-revert's
  missing-entry no-op is explicit (SMR30-2 = AGY
  r30 f4 — the revert rides the uniform
  missing-entry → already-terminal contract); and
  §9 (a) gains the steal-side-effect fence, the
  steal-cancellation + cadence-decay, and the
  revert-missing-entry assertions (AGY r30 f3) @
  `c09cceed3` (r31: SMR DEMAND-REVISION (0 BLOCKER
  + 0 MAJOR + 1 MINOR + 2 NIT); AGY DEMAND-REVISION
  (1 MAJOR + 1 MINOR + 1 NIT — architectural audit
  clean); Codex infra-blocked (tenth documented
  attempt; 2-of-3))
; v8.27 folds SMR r31 (1 MINOR + 2 NIT) + AGY r31
  (1 MAJOR + 1 MINOR + 1 NIT): the mid-drain steal's
  full walk is spelled out (SMR31-1 = AGY r31
  f1/f3 — the steal can fire while the stale drain
  executes under `applySem` (the steal needs only
  `m.mu`): (i) the invalidation was composed AT
  ENTRY against the drain-time EXPOSED pair and no
  exposure can move under `applySem` — the
  composition stays correct after the claim dies;
  (ii) the stamp's CAS passes (the store cannot
  move either) — the stale stamp LANDS and is
  CORRECT (the pair is store-active), while the
  phase's completion RECORD is refused by the
  generation guard, so the stealer RE-EXECUTES the
  phase and the re-execution's side effects are the
  idempotent ones (a second identical stamp CAS on
  the same value; a second identical push — the
  receiver's `SyncApply` no-ops on identical
  content (daemon_apply_commit.go:356-360); the
  invalidation's deletes idempotent); §9 (a) gains
  the mid-drain interleaving assertion (AGY r31
  f1's false-green fix — an implementation that
  omits the generation check on the completion
  record FAILS the test)); the cancellation's
  scope is clarified (SMR31-2 = AGY r31 f2 — ctx
  cancellation bounds the I/O tails (the conn
  write's TCP timeout + `handleDisconnect`; socket
  operations), while in-memory store mutations
  (`setAppliedDigest` takes no ctx) rely on the
  CAS revision verification — either order safe);
  and the steal-spawned goroutine population's
  bound is stated (SMR31-3 — cancellation reaps
  each goroutine within one operation of its
  cancellation; the residue is the kernel-wedged
  budgeted D-state class only) @ `a5f2918c7` (r32:
  SMR DEMAND-REVISION (0 BLOCKER + 0 MAJOR + 1
  MINOR + 1 NIT); AGY PLAN-READY-WITH-NITS (1
  MINOR + 1 NIT — the mid-drain trace assessed
  "mathematically sound"); Codex infra-blocked
  (eleventh documented attempt; 2-of-3))
; v8.28 folds SMR r32 (1 MINOR + 1 NIT) + AGY r32
  (1 MINOR + 1 NIT): the C2-gap composition note
  (SMR32-1 = AGY r32 f1 — the stealer acquires
  `applySem` AFTER the stale drain releases it, and
  an intervening exposure C2 can land in the gap:
  the stealer does NOT re-run the stale drain's
  composition, it runs its OWN against the exposed
  pair at ITS OWN entry — the union is exactly
  right (the stale drain's A→C deletes (composed
  at ITS entry), C2's own wrapper's C→C2 (its own
  tails), and the stealer's A→C2 delete exactly
  (A∪C)\C2 with every C2-permitted session
  surviving all three — the drain-time-EXPOSED-at-
  each-entry rule is what makes the union correct —
  and the two cursor entries are independent (each
  composes against the shared `m.lastExposedPair`
  at its own entry; the claim-or-skip serializes
  only within an entry)); §9 (a) gains the
  C2-interpose assertion (the stealer detects C1
  as non-store-active, skips its stamp/push,
  composes A→C2 idempotently, and marks C1
  SUPERSEDED); the stamp prose gains the
  store-currency-skip form (AGY r32 f2 — "a second
  identical stamp CAS on the same value (or skipped
  via store-currency gating when the pair is no
  longer store-active)"); and the
  record-before-timer case is stated (SMR32-2 —
  a drain finishing before the namedBound records
  complete normally and the steal-timer is
  cancelled by the completion, same `m.mu` op) @
  `676b176d5` (r33: SMR PLAN-READY-WITH-NITS (2
  NIT — the first SMR non-DEMAND verdict); AGY
  DEMAND-REVISION (1 BLOCKER + 1 MINOR + 1 NIT);
  Codex infra-blocked (twelfth documented attempt;
  2-of-3))
; v8.29 folds SMR r33 (2 NIT) + AGY r33 (1 BLOCKER
  + 1 MINOR + 1 NIT): the stamp/push gate re-keys
  from STORE currency to EXPOSED currency (AGY r33
  f1, a real design hole the SMR r33 sweep missed
  (recorded honestly): C1 exposed (notice queued),
  C2 promoted but GATED (store-active, unexposed —
  its own push HELD by the exposure check) — the
  v8.20 STORE-currency gate skipped C1's stamp and
  push (C1 no longer store-active), so the peer
  stayed on A and `appliedRevision` stayed at A
  while the primary ran C1 — an indefinite silent
  divergence for the whole gated window: the gate
  now keys on EXPOSED currency (the notice's pair
  == `m.lastExposedPair`) — the SMR24-1 over-stamp
  case (the newer pair EXPOSED → skip) stays
  killed, and the gated-successor case (successor
  store-active but UNEXPOSED → C1 is STILL the
  exposed pair → stamp/push C1 normally, and C1's
  entry completes normally (not SUPERSEDED)) now
  converges (the peer receives the exposed config
  exactly); and the C2-gap union formula is
  corrected (AGY r33 f2 — the v8.28 "every
  C2-permitted session survives all three" was
  FALSE: a session A-permitted, C-revoked,
  C2-re-permitted was deleted at C's exposure
  (correctly, at that time) and never recreated —
  intermediate revocations are PERMANENT (the
  intended semantics — the final config re-permits
  via re-handshake, never resurrection): the
  deleted set is (A∪C)\(C∩C2) (survivors
  (A∪C)∩C∩C2); the safety-critical direction
  stands (SMR33-1 (ii)'s subsumption: the
  stealer's A\C2 ⊆ (A\C) ∪ (C\C2) — the stealer
  provably cannot over-delete)); and the multi-gap
  generalization is stated (SMR33-1 (i) = AGY r33
  f3 — N successive gaps leave the stealer
  composing A→C_k and the union exactly
  (A∪C_1∪…∪C_{k-1})\(C_1∩…∩C_k)) @ `f67996d5f`
  (r34: SMR DEMAND-REVISION (1 BLOCKER + 1 MINOR);
  AGY DEMAND-REVISION (1 BLOCKER + 1 MINOR); Codex
  infra-blocked (thirteenth documented attempt;
  2-of-3))
; v8.30 folds SMR r34 (1 BLOCKER + 1 MINOR) + AGY
  r34 (1 BLOCKER + 1 MINOR): the stamp's form is
  corrected against the ACTUAL machinery (SMR34-1
  = AGY r34 f1 — verified store.go:787-853: the
  stamp is DIGEST-based with NO revision CAS
  (`MarkActiveApplied()` stamps
  `configTextDigest(s.active)` — the CURRENT active
  tree, which in the gated-successor window is the
  NEVER-APPLIED successor (the r30 f1 / #6296
  class); `MarkAppliedDigest(digest)` stamps a
  captured digest UNCONDITIONALLY; `ActiveApplied()`
  is the read-side digest comparison); the v8.26
  "CAS form (expected store-current revision)" was
  plan-invented and fails BOTH ways (an
  active-keyed CAS REFUSES the very stamp the
  v8.29 exposed-currency gate admits (C1 exposed,
  C2 store-active-but-gated); a CAS-free overwrite
  lets a late stale stamp regress the marker) and
  is RETRACTED): the stamp is the CAPTURED-DIGEST
  stamp (`MarkAppliedDigest(pair.capturedDigest)` —
  the pair's OWN digest, captured at
  acceptance/apply time under the apply
  serialization — never `MarkActiveApplied()`),
  and the anti-stale protection is the v8.29
  EXPOSED-currency ADMISSION gate (a stale
  notice's stamp is SKIPPED before any stamp call;
  the read-side `ActiveApplied()` digest
  comparison is the only "CAS" the machinery
  needs — the rollback case is the payoff: C2
  rolled back to C1 after C1's stamp landed ⇒
  `ActiveApplied()` reports C1 applied (true — C1
  is enforced)); and §9 (a) asserts the stamp
  LANDS (SMR34-2 = AGY r34 f2 —
  `appliedDigest == configTextDigest(C1's text)`
  after C1's drain with C2 gated, and
  `== digest(C2)` after C2's apply — a
  stamp-call-that-doesn't-land FAILS the test) @
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

DRAFT v8.30 — pending adversarial plan review round 35 (Codex + AGY +
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

- **Round 18** (v8.13): ALL THREE DEMAND-REVISION — Codex (11
  BLOCKER + 3 MAJOR), AGY (4 BLOCKER + 4 MAJOR + 1 MINOR +
  1 NIT), SMR (2 BLOCKER + 3 MAJOR + 5 MINOR). Convergence:
  the input-ref capture is unimplementable (Codex f6 = AGY
  f4 = SMR18-2 — the validation must be content-based);
  the outcome fold order is unspecified (Codex f8 = AGY f5
  = SMR18-3); the post-quiescence try-lock skip
  contradicts the standing text (AGY f1 = SMR18-4); the
  m.mu-resident netlink resolution (AGY f3 = SMR18-5);
  the 60s-floor blackhole bound (Codex f12 = AGY f7 =
  SMR18-8); the error_code Go consumer contract (Codex f7
  = AGY f2/f9 = SMR18-7); the commit-warning surface
  (Codex f3 = AGY f6); the polling-cannot-accelerate note
  (Codex f4 = AGY f8 = SMR18-6). SMR-only: the
  auxiliary-producer gate-window hybrid (SMR18-1). Codex-only
  depth: the exposed marker inherits same-text applied
  state (f2 — revision-keyed required); no typed
  accepted-vs-exposed outcome (f3 — every wrapper treats
  nil as ran; the HA generation/failover readiness tails
  leak); the global gate suppresses durable A's mandatory
  second leg (f4 — pair-specific durableRevision
  required); buildSeq invalidates predecessors before a
  viable successor + pre-send side effects (f5); the
  token lacks an incarnation seed (f6); the
  read-to-syscall cancellation race + RetryLater FIFO
  starvation (f9); the restore debt's placement/API/ctrl-
  retry composition (f10); the idempotent advance
  certifies map-P/helper-P0 (f11 — canonical
  (payload, generation) required); the systemd claim is
  not a bound (f14). Codex f15 (the v8.13 Warn
  lifecycle) was the round's one clean closure.
- **Round-18 disposition table:**

  | r18 finding | v8.14 disposition |
  |---|---|
  | Codex f1 disposition accuracy | CLOSED — this table + the r17 rows re-audited; every v8.14 fold verified per-edit |
  | Codex f2 exposed marker inherits same-text | CLOSED — `appliedRevision` alongside `appliedDigest`; `ActiveApplied()` compares the PAIR; HA markers key to the typed outcome's `Exposed`; the primary's marker claim defers until exposure; the lag is visible in `show chassis cluster` (§5-C epoch contract (iv), §6, §9 (a)) |
  | Codex f3 no typed accepted/exposed outcome | CLOSED — `ApplyOutcome{Ran, Exposed, ExposurePending}`; every wrapper tail gates on `Exposed`; the debt record carries the HA `item.gen` + commit context and runs the DEFERRED tails after observed acceptance; the commit note rides `compiled.Warnings` synchronously (§5-C (ii), §6, §9 (a)) |
  | Codex f4 global gate + no bounded wake | CLOSED — PAIR-SPECIFIC `durableRevision` gating at `applyConfigLocked`'s ENTRY (A's second leg never gated by B); the debt's ALWAYS-LIVE timer (explicit `nextWake`); the honest storage-failure-unbounded budget (§5-C (i)/(iii), §6, §9 (a)/(b)) |
  | Codex f5 premature invalidation + side effects | CLOSED — invalidation DELAYED until a successor's observed acceptance; the validation runs at the publish leg's ENTRY (before any XDP/pin/shim/bootstrap-map mutation); `m.currentPair` added; the SUPERSEDED report only on a real accepted successor (§5-C epoch contract, §9 (d)) |
  | Codex f6 capture-order + token incarnation (= AGY f4 = SMR18-2) | CLOSED — the validation compares the CONTENT HASH (no input enumeration); `buildSeq` SEEDS from the ping echo (`m.latestBuildSeq = max(echo, 0)`) (§5-C epoch contract, §9 (d)) |
  | Codex f7 note verb contradictory (= AGY f2/f9 = SMR18-7) | CLOSED — §6 enumerates the `note_commit_revision` request arm + the dispatcher match arm + the decoded-response typed-return Go API (callers branch on `error_code` BEFORE the `err != nil` return) (§6, §9 (e)) |
  | Codex f8 fold algebra (= AGY f5 = SMR18-3) | CLOSED — recorded outcomes apply OLDEST-FIRST, the head's own LAST; the 7×7 matrix in §6 (PENDING-XSK STAGED is a state, not a Finish); three-node coverage; `m.compileInFlight` clears exactly when every node is terminal (§5-C, §6, §9 (f)) |
  | Codex f9 read-to-syscall race + RetryLater starvation | CLOSED — the MUTATION LEASE (re-read + syscall under ONE `m.mu` acquisition); while holding `applySem` ALL `m.mu` acquisitions are BLOCKING (bounded by one legal owner hold; the applySem transaction already prices RPC-length holds); try-lock-or-skip survives only for non-applySem probes (§5-C debt execution, §9 (g)) |
  | Codex f10 restore debt not executable | CLOSED — DAEMON-SIDE entirely with `RecordRestoreDebt`/`ClaimRestoreWork`/`ReportRestoreAttempt` (the MAC debt's pull shape); the ctrl retry is the FULL `NotifyLinkCycle` sequence (rebind + status reconcile + reconciled enable, never a bare write); the ctrl=0 window fail-closed + Warn-visible + retry-forever (§5-C debt execution, §6, §9 (h)) |
  | Codex f11 map_generation false coherence | CLOSED — the CANONICAL `(payload, generation)` pair per projection (rich locked sample + neighbor-cache resolution); EVERY carrier uses its own payload's generation (full snapshots read the pair at the publish leg); the failed-send/stale-carrier race advances accepted only to (P0, g0); the debt's retry re-sends the recorded pair (§5-C (i), §6, §9 (i)) |
  | Codex f12 late-arrival cutoff + backoff (= AGY f7 = SMR18-8) | CLOSED — absorption covers ONLY members DUE AT THE CLAIM; a return between Claim and rebind rides the debt's own current backoff (up to the 60s floor); the ≤ ~1s text deleted in v8.13 (§5-C debt, §9) |
  | Codex f13 tests green | CLOSED — §9's chain tests gain the false-green refusals per the finding's table (§9 (a)-(j)) |
  | Codex f14 hazard budget + systemd claim | CLOSED — the budget gains the new classes (gate exposure, typed-outcome tails, premature invalidation, lease race, restore ctrl=0, warm blackhole, false fabric proof — all closed by the rows above); the systemd claim deleted: the kernel-unreapable class is unbounded PERIOD (the 60s Warn + out-of-band operator action is the only mitigation) (§5-C budget, §11 Q7) |
  | AGY r18 f1-f9 | CLOSED — f1 (post-quiescence contradiction) → the lease + blocking reconciliation (Codex f9 row); f2/f9 (error_code contract) → f7 row; f3 (m.mu-resident resolution) → the neighbor-cache pin (f11 row); f4 (input refs) → f6 row; f5 (fold matrix) → f8 row; f6 (warning surface) → f3 row; f7 (60s floor) → f12 row; f8 (polling) → f4 row (the honest unbounded-storage budget) |
  | SMR r18 SMR18-1..10 | CLOSED — SMR18-1 (auxiliary hybrid) → the `m.exposureGateActive` suppression (f2 row, §5-C (vi), §9 (a)); SMR18-2 → f6 row; SMR18-3 → f8 row; SMR18-4 → f9 row (subsumed by the lease); SMR18-5 → f11 row; SMR18-6 → f4 row; SMR18-7 → f7/f3 rows; SMR18-8 → f12 row; SMR18-9 → f10/f11 rows; SMR18-10 → f2/f4 rows |

- **Round 19** (v8.14): ALL THREE DEMAND-REVISION — Codex (11
  BLOCKER + 4 MAJOR), AGY (3 BLOCKER + 4 MAJOR + 1 MINOR +
  1 NIT, f3 NOT-VERIFIED on re-derivation), SMR (2 MAJOR +
  5 MINOR). Convergence: the hash leg dies (Codex f7 = AGY
  f1/f5 = SMR19-1 — incoherent with the canonical fabrics
  replacement AND a both-abandoned deadlock); the flag
  lifetime (AGY f2 = SMR19-3(iii)) and the scheduler-close
  fail-open (Codex f3) both die WITH the flag under full
  gating (Codex f2); the marker parameterization (Codex f6
  = AGY f4, VERIFIED — the parameterless
  `MarkActiveApplied()` reads the current active at mark
  time); the lease latency (Codex f10 = AGY f6) resolves
  by deleting the lease for the member-boundary model.
  SMR-only: SMR19-1 (the hash leg, shared), SMR19-2 (the
  node-local/inter-node revision scope split). Codex-only
  depth: the FRR-inside-the-gate contradiction (f2 — full
  gating subsumes the suppression flag); the HA settlement
  transport must ride the ordered loop (f4); the deferred
  tails lose A→B invalidation history + omit auto-rollback
  + need phased ownership + the warning aliases store
  state (f5); the validation needs a named phase split
  (f8); the fold replays speculative priors (f9 — the
  both-fail resurrection, distinct from AGY f3's misread
  trace); the lease is cross-layer impossible AND
  per-syscall insufficient (f10); the restore needs
  precheck-derived intent + applySem (f11); the canonical
  pair is uniform (P,g) with map-authoritative MACs
  (f12 — the (P0,g0) invention dies); the old-helper
  note behavior (f13). Codex f7's ownerless path gains
  the GO-LOCAL re-sync firing rule. AGY f3 NOT-VERIFIED
  (its trace misreads the capture semantics: T2's
  captured prior IS T1's in-flight state, so the fold
  yields the coherent state — while Codex f9's
  both-fail trace is the REAL algebra bug, folded).
- **Round-19 disposition table:**

  | r19 finding | v8.15 disposition |
  |---|---|
  | Codex f1 disposition accuracy | CLOSED — this table + the r18 rows re-audited; every v8.15 fold verified per-edit |
  | Codex f2 gate/FRR contradiction | CLOSED — FULL GATING: the ENTRY check defers the whole tail (dataplane leg, FRR, routing, fabric); the drain re-runs the full `applyConfigLocked`; the suppression flag DELETED (the RIB never moves, so no hybrid, no stuck flag, no suppressed scheduler close); `durableRevision`'s pins (active-pair writes only, advance after WriteFileDurable, Load re-derives) (§5-C (i), §6, §9 (a)/(b)) |
  | Codex f3 suppression fail-open | CLOSED with f2 — the flag's deletion kills the class (the scheduler's A-derived closes publish normally through the whole window) (§5-C (i), §9 (a)) |
  | Codex f4 HA settlement transport | CLOSED — the settlement rides an INTERNAL ordered-loop item (`(gen, digest, deferred-tail context)` — an in-process item kind, not a wire change); `recordAppliedConfigGen` advances IN ORDER; `applyingConfigGen` stays at the last-exposed gen during ExposurePending (visible); local commits' markers run directly in the drain (§5-C (ii), §9 (a)) |
  | Codex f5 tails lose history/rollback/ownership + warning aliasing | CLOSED — the debt retains the LAST EXPOSED configuration (invalidation composes last-exposed → current); the auto-rollback wrapper joins the census; the tails are PHASED with a TAIL DEBT (failed phase retries only itself); the note rides a RESPONSE COPY (never `compiled.Warnings`) (§5-C (i)/(ii), §6, §9 (a)) |
  | Codex f6 marker pair-safety (= AGY f4) | CLOSED — `MarkActiveApplied(digest, revision)` + `MarkAppliedDigest(digest, revision)` parameterized; all four call sites pass the captured pair; the primary's push marker gains the current-pair-exposed check; the identity scopes separated (SMR19-2: node-local pair vs inter-node digest + deferred gen) (§5-C (iv), §6, §9 (a)) |
  | Codex f7 hash contradicts invalidation + ownerless pair-current (= AGY f1/f5 = SMR19-1) | CLOSED — the hash leg DELETED (the two legs (PAIR-CURRENT with the revision-0 CLI exemption + NO-ACCEPTED-NEWER-BUILD) + the token backstop); the re-sync gains the GO-LOCAL firing rule (`ActivePair().revision > m.acceptedCommitRevision` with no apply in flight — the autonomous owner for abandoned/failed builds) (§5-C epoch contract, §9 (d)) |
  | Codex f8 no implementable build graph | CLOSED — the NAMED phase split: (1) ping; (2) side-effect-free shim COMPILE (.o + NAT IDs; no kernel mutation) + build; (3) VALIDATE under m.mu; (4) MUTATION phase (pin clean, attach, bootstrap maps, send) (§5-C epoch contract, §9 (d)) |
  | Codex f9 fold algebra (both-fail resurrection) | CLOSED — the reduction: PRE-PUBLISH FAILURE ⇒ the NEWEST ACCEPTED PREDECESSOR's deferIntent (or the chain-root value), NEVER the captured prior; the HEAD-POP rule guarantees the final fold; the SIX-outcome table in §6 (PENDING-XSK as the open state) (§5-C, §6, §9 (f)) |
  | Codex f10 lease impossible + insufficient (= AGY f6) | CLOSED — the lease is DELETED for the MEMBER-BOUNDARY model: token checks at member boundaries (blocking, cheap); an in-flight member's DOWN→MAC→UP ALWAYS COMPLETES (no half-cycled state); cancellation at the next boundary (wasted-not-harmful); no `m.mu` across any syscall; the honest per-member latency budget (§5-C debt execution, §6, §9 (g)) |
  | Codex f11 restore intent + serialization | CLOSED — the drain ACQUIRES `applySem` and calls the LOCKED apply directly; `StartCompile(rethMACPending)` carries THE PRECHECK'S OWN RESULT (never `StartCompile(false)`); the restore debt is daemon-side entirely (§5-C debt execution, §6, §9 (h)) |
  | Codex f12 canonical pair contradictory + hash domain + MAC authority | CLOSED — the UNIFORM rule (every carrier uses the CURRENT `(payload, generation)`; (P0, g0) deleted); the payload's MACs from the MAP's OWN fields (never a cache re-resolution); the debt clears on observed accepted ≥ recorded; the dedup hash covers the FINAL wire content (§5-C (i), §6, §9 (i)) |
  | Codex f13 old-helper note narrative | CLOSED — pinned: a compliant manager never sends (the capability bit fails closed); a forced send takes the byte-identical LEGACY failure (untyped, never a CAS-refusal classification) (§6 item 12, §9 (e)) |
  | Codex f14 tests green | CLOSED — §9's chain tests gain the false-green refusals per the finding's table (§9 (a)-(j)) |
  | Codex f15 hazard budget + risk table | CLOSED — the budget gains the authorization-affecting classes (scheduler-close fail-open (dead with the flag), A→B invalidation loss (dead with the last-exposed retention), tail-failure ownerless (dead with the TAIL DEBT), build abandonment (dead with the GO-LOCAL rule), cancelled-member-down (dead with the member-boundary model)); the honest unbounded classes restated (warm blackhole, retry-forever ctrl=0, kernel-unreapable) (§5-C budget, §8, §11 Q7) |
  | AGY r19 f1-f7 | CLOSED — f1/f5 → f7 row (hash deleted); f2 → f2 row (flag deleted); f3 NOT-VERIFIED (trace misreads the capture; the REAL algebra bug is Codex f9's, folded at the f9 row); f4 → f6 row; f6 → f10 row; f7 → the `*ControlError`/`errors.As` form (§6 item 12) |
  | SMR r19 SMR19-1..7 | CLOSED — SMR19-1 → f7 row; SMR19-2 (identity scopes) → f6 row; SMR19-3 (flag lifetime/fail-stale) → f2 row (flag deleted); SMR19-4 (CLI exemption) → f7 row; SMR19-5 (deferred set) → f5 row; SMR19-6 (lease latency/restore semaphore) → f10/f11 rows; SMR19-7 (durableRevision derivation) → f2 row |

- **Round 20** (v8.15): ALL THREE DEMAND-REVISION — Codex (10
  BLOCKER + 3 MAJOR), AGY (2 BLOCKER + 1 MAJOR + 1 MINOR,
  f1 NOT-VERIFIED), SMR (2 MAJOR + 6 MINOR). Convergence:
  the GO-LOCAL qualifier's circular deadlock (AGY f2 =
  SMR20-7 — the qualifier is unnecessary (the drain's
  applySem already serializes) AND deadlocking for the
  leak case; the rule fires on `active > accepted`
  PERIOD); the drain-failure policy (AGY f3 = SMR20-3);
  the restore rebind idempotency answer (AGY f4 =
  SMR20-4); AGY f1 (MAC-in-hash vs 19(ii)) NOT-VERIFIED
  (the projection identity excludes MACs — telemetry
  mints generations without firing mark-all). SMR-only:
  SMR20-1 (the pair-not-current abandon has no named
  report), SMR20-2 (the last-exposed record's update
  points). Codex-only depth: full gating defers
  security-critical revocation (f2 — the management-auth
  closeout set FOLLOWS); the entry gate does not
  linearize the pair (f3 — the flow-level pair-current
  rule; the second leg aborts on interposition); the
  settlement has no ingress and no session fence (f4 —
  the fence rises AT exposure); last-exposed is
  narration not a state machine (f5 — uniform
  invalidation base kills the direct-C case); the
  re-sync loses all wrapper tails (f6 — the completion
  ledger rides every first-exposure); the fold
  publishes the wrong reservation's defer intent (f7 —
  the wire stamp is node-local); the side-effect-free
  phase is source-false (f8 — the stale-mutation class
  dies at the daemon's leg-entry check); member
  boundaries don't preserve physical quiescence or
  failed-link ownership (f9 — the verb quiescence gate
  + the link-recovery cancellation survival); the
  fabric clear preserves stale helper state (f11 — the
  tombstone). Codex f3 (flag deletion) + f13
  (old-helper note) + AGY f7 + SMR19-3/4/7 were the
  round's clean closures.
- **Round-20 disposition table:**

  | r20 finding | v8.16 disposition |
  |---|---|
  | Codex f1 disposition accuracy | CLOSED — this table + the r19 rows re-audited; every v8.16 fold verified per-edit |
  | Codex f2 revocation deferral | CLOSED — the FOLLOW set gains the management-auth closeout class (SNMP communities, web credentials, host authorization — monotonic-revocation obligations that forward no packets); the deferred set is exactly {dataplane leg, FRR, routing, fabric} (§5-C (i), §9 (b)) |
  | Codex f3 pair not linearized | CLOSED — the flow-level pair-current rule: EVERY leg re-reads `ActivePair()` and re-checks at ITS start (the dataplane leg aborts BEFORE any Compile mutation; the mandatory second leg ABORTS on interposition (tests (b)/(d) reconciled); SUPERSEDED-BY-NEWER-COMMIT with the coverage argument (SMR20-1)) (§5-C epoch contract, §9 (b)/(d)) |
  | Codex f4 settlement ingress + session fence | CLOSED — the `settleExposure` internal item kind (the loop's own protocol — answers neither nil nor error); the gen fence rises AT EXPOSURE (before any invalidation, held until the settlement's high-water advance); the enqueue is non-blocking with the repost-into-tail-debt rule (stale settlements discarded) (§5-C (ii), §9 (a)) |
  | Codex f5 last-exposed not a state machine | CLOSED — `m.lastExposedPair` advances at EXACTLY the `m.acceptedCommitRevision` advancement points (SMR20-2); the session invalidation's base is ALWAYS last-exposed (uniform — kills the direct-durable-C case); the peer-push phase's ownership pinned (the sync layer's reconnect/redelivery + the tail debt's pending record) (§5-C (ii), §9 (a)) |
  | Codex f6 re-sync loses wrapper tails | CLOSED — the phased completion ledger rides EVERY FIRST-EXPOSURE (commit, drain, GO-local re-sync, restore's first-exposure); a replay of an already-exposed pair needs no tails (§5-C (ii), §9 (a)/(d)) |
  | Codex f7 wrong defer intent on the wire | CLOSED — `snap.DeferWorkers` stamps from the compile's OWN reservation node's deferIntent (NODE-LOCAL — never the shared mutable global) (§5-C, §9 (f)) |
  | Codex f8 side-effect-free phase source-false | CLOSED — the stale-build-mutates-host class dies at the DAEMON's leg-entry pair-current check (BEFORE any Compile/host mutation; auxiliary producers clone — no Compile at all); `m.acceptedBuildSeq` named; the helper tracks newest-SEEN; the mid-flow respawn benign (SMR20-8) (§5-C epoch contract, §9 (d)) |
  | Codex f9 quiescence + failed-link ownership | CLOSED — the operator binding/queue verbs REFUSE busy while `m.linkCycleActive` (the re-spawn-during-quiescence class closed); a member's `linkOnlyRecovery` entry SURVIVES the MAC debt's cancellation (the failed-UP case always has an owner); the stale lease/try-lock texts swept (§5-C debt execution, §6, §9 (g)) |
  | Codex f10 marker/restore partial | CLOSED — the push marker gains ONE store-atomic `(text, digest, revision, exposed)` capture; the auto-rollback joins the marker census; the restore debt is DAEMON-SIDE with daemon-local helpers (§6, §9 (a)/(h)) |
  | Codex f11 zero-entry false coherence | CLOSED — the REMOVAL TOMBSTONE (`removed: true`; the helper DROPS the fabric state on a deliberate clear — never preserves the stale working set; distinct from the guard's unresolved-candidate rejection) (§5-C (i), §9 (i)) |
  | Codex f12 tests green | CLOSED — §9's chain tests re-specified per the finding's table (§9 (a)-(j)) |
  | Codex f13 hazard budget stale | CLOSED — the budget gains the v8.15/16 classes (management-auth deferral (dead — closeout follows), mid-flow pair hybrids (dead — leg-entry check), the settlement window/FIFO (dead — fence-at-exposure + repost), direct-C invalidation loss (dead — uniform base), first-exposure completion (dead — the ledger), wrong wire intent (dead — node-local stamp), quiescence re-spawn + UP-failure (dead — the gate + survival), the drain's own failure (SMR20-3's policy)) (§5-C budget, §8, §11 Q7) |
  | AGY r20 f1-f4 | CLOSED — f1 NOT-VERIFIED (the projection identity excludes MACs — the SMR20-6 separation sentence resolves the ambiguity); f2 → SMR20-7's qualifier deletion; f3 → SMR20-3's drain-failure policy; f4 → SMR20-4's idempotency/serialization answer |
  | SMR r20 SMR20-1..8 | CLOSED — SMR20-1 (named report + coverage) → f3 row; SMR20-2 (update points) → f5 row; SMR20-3 (drain policy) → f13 row; SMR20-4 (first-member check + idempotency) → f9 row; SMR20-5 (settlement context/FIFO) → f4 row; SMR20-6 (identity vs telemetry) → f11 row; SMR20-7 (qualifier deletion + Finish defer) → the GO-LOCAL rule (§5-C, §9 (d)); SMR20-8 (benign respawn) → f8 row |

- **Round 21** (v8.16): ALL THREE DEMAND-REVISION — Codex (12
  BLOCKER + 2 MAJOR), AGY (2 BLOCKER + 2 MAJOR), SMR (1
  BLOCKER + 2 MAJOR + 4 MINOR). Convergence: the
  unqualified GO-LOCAL rule publishes the pending-XSK
  staged config early (SMR21-1 = AGY f2 = Codex f9 —
  the live-registration discriminator is the shared
  fix); the second-leg abort strands DeferWorkers=true
  for a gated successor (AGY f1 = Codex f4 — both
  reverted by Codex f3's invariant); the verb gate
  must clear at restore completion/debt transfer
  (SMR21-2 = AGY f3 = Codex f11's first half); the
  gate's entry placement conflicts with the closeout
  set and the bootstrap-exit line (AGY f4 — the flow
  re-orders). Codex-only depth, several of it
  simplifying: f3 — EVERY promotion is serialized
  WITH its apply under `applySem` (VERIFIED:
  `commitAndApply` holds it across `configstore.Commit`
  AND the apply (daemon_apply_commit.go:129-175)), so
  NO promotion can interpose mid-flow and the v8.16
  flow-level pair machinery addressed a state the
  locking already prevents (the residual concerns are
  the manager-internal classes the staged-ahead
  suppression and the legacy-zero mode own); f2 — the
  FOLLOW set was neither directionally safe nor a
  coherent partition (SNMP adds users/listeners; web
  does bind/TLS replacement; the RELAXING direction
  grants B access while A is exposed) — re-scoped to
  proven-monotonic-tightening-only with a persistent
  closeout debt; f5 — the drain cannot raise the HA
  fence out-of-loop safely (needs a MAX-CAS raise
  with an ownership token, and the settlement needs
  (peer incarnation, gen, pair, settlementID) with
  loop dedup/ack); f6 — lastExposedPair advances too
  early (beginFirstExposure returns the immutable
  prior; boot unknown-base policy); f7 — the
  completion ledger needs {pair, phaseCursor,
  completionState} installed at acceptance; f8 — the
  reservation token must be an explicit Compile
  argument; f10 — newest-seen makes rejected
  snapshots an ordering authority (fence on ACCEPTED;
  per-build immutability); f11 — the failed-UP record
  is lost on stale-token discard (cancellation-
  insensitive link recording); f12 — the tombstone
  spans three refresh/build paths and needs the
  configured-name key; f13 — atomic capture does not
  order the outbound generation (revalidate inside the
  send-time write lock). Codex's narrow prior closures
  remain valid (flag deletion, old-helper note,
  identity/telemetry separation, the drain backoff);
  Q1 remains complete.
- **Round-21 disposition table:**

  | r21 finding | v8.17 disposition |
  |---|---|
  | Codex f1 disposition accuracy | CLOSED — this table + the r20 rows re-audited; every v8.17 fold verified per-edit |
  | Codex f2 FOLLOW set unsafe/incoherent | CLOSED — the closeout is re-scoped to PROVEN MONOTONIC TIGHTENING ONLY (B's REMOVALS, computed against the union of A-live and B-desired reachability); additions/listener expansions/relaxations DEFER; a PERSISTENT CLOSEOUT DEBT owns the closeout's failure; the closeout never consults deferred state (no `ApplyResult.ManagedInterfaces`, no B-derived host-inbound view over A's live interfaces); the flow re-orders (closeout first, then the gate check, then forwarding mutations (AGY f4)) (§5-C (i), §9 (b)) |
  | Codex f3 pair check unreachable-or-racy | CLOSED — the PROMOTION-SERIALIZATION INVARIANT is stated (VERIFIED: `commitAndApply` holds `applySem` across `configstore.Commit` AND the apply (daemon_apply_commit.go:129-175); HA sync/commit-confirmed/auto-rollback the same; the persistence retry advances only durability; the boot-recovery promote precedes all flows) — NO promotion can interpose mid-flow; the v8.16 flow-level re-reads and the second-leg abort rule are REVERTED; the residual classes are manager-internal (the staged-ahead suppression owns the clones; the legacy-zero mode refuses the CLI on epoch-established boxes) (§5-C epoch contract, §9 (b)/(d)) |
  | Codex f4 abort recreates the outage (= AGY f1) | CLOSED with f3 — the abort is deleted (no interposition is reachable; the second leg always reuses the outer pair and completes) (§5-C epoch contract, §9 (b)) |
  | Codex f5 fence raise + settlement identity | CLOSED — the drain's fence raise is MAX-CAS with an OWNERSHIP TOKEN (never lowers; only its owner releases); the settlement carries `(peer incarnation, gen, pair, settlementID)` with loop-side dedup/ack (exactly-once via the ack; an old-incarnation settlement can never advance a new incarnation) (§5-C (ii), §9 (a)) |
  | Codex f6 lastExposedPair advances too early | CLOSED — `beginFirstExposure(B) -> {priorPair, firstExposure, ledgerID}` is the atomic transition at acceptance; the wrapper carries the IMMUTABLE prior through completion (no read-after-advance tear); the boot unknown-base policy (persisted exposed sidecar, or a conservative clear-all when the base is unprovable) (§5-C (ii), §6, §9 (a)) |
  | Codex f7 ledger has no state | CLOSED — the completion cursor `{pair, phaseCursor, completionState}` is installed ATOMICALLY at acceptance; the re-sync clears only after the record installs; a completed replay skips tails; an incomplete replay resumes its phase; a crash re-runs idempotent tails conservatively (§5-C (ii), §9 (a)) |
  | Codex f8 token not transported | CLOSED — `Compile(cfg, commitRevision, reservationToken)` (+ `ApplyConfig(ctx, cfg, commitRevision, reservationToken)`); the daemon passes the `StartCompile` token; the assert-or-default paths pass the default token they created; the staged object carries the token + its baked-in `DeferWorkers`; clones preserve the cached value; #5134 forces `false` only for the generation it owns completion for (§5-C, §6, §9 (f)) |
  | Codex f9 GO-LOCAL attacks the staged owner (= AGY f2 = SMR21-1) | CLOSED — the discriminator: `active > accepted` AND **no live deferred-publish registration for the active pair** (the pending-XSK staged window is owned by its `OnXSKBound` registration; a leaked registration lets the rule fire and OVERLAP-finalize the orphan) (§5-C re-sync, §9 (d)) |
  | Codex f10 newest-seen poisons | CLOSED — the helper's token fence is newest-ACCEPTED (a rejected token never advances it); the seed reads newest accepted; the token is per-build immutable (a wire retry carries the same token; `publication_rev` keeps the attempt order) (§5-C epoch contract, §9 (d)) |
  | Codex f11 gate lockout + failed-UP discard (= AGY f3 = SMR21-2) | CLOSED — the gate covers each physical quiescent transaction and clears at restore completion or debt transfer (the restore debt's backoff intervals do not hold it; each retry re-sets it for its window); the link-down observation is recorded through a CANCELLATION-INSENSITIVE path before token disposition (§5-C debt execution, §9 (g)) |
  | Codex f12 tombstone paths/key/lifetime | CLOSED — specified across all three paths (incremental (drop in refresh_fabric_links), full build (omitted — the config re-adds at the next apply, runtime-scoped), the runtime refresh (dropped from the preserved merge)); the configured fabric NAME is the stable key (the runtime FabricLink lacks it); the deliberate clear is distinguished from the guard's unresolved-candidate rejection (§5-C (i), §9 (i)) |
  | Codex f13 capture doesn't order outbound | CLOSED — the captured revision is revalidated against `ActivePair()` INSIDE the send-time write lock (a stale capture is re-derived from the current active pair before the generation is allocated, never sent) (§6, §9 (a)) |
  | Codex f14 tests/budget | CLOSED — §9 re-specified per the finding's walk; the budget gains the v8.16/17 classes (§8, §11 Q7) |
  | AGY r21 f1-f4 | CLOSED — f1 → f3/f4 rows (the invariant reverts the abort); f2 → f9 row; f3 → f11 row; f4 → f2 row (the flow re-order) |
  | SMR r21 SMR21-1..7 | CLOSED — SMR21-1 → f9 row; SMR21-2 → f11 row; SMR21-3 (boot/replay base semantics) → f6 row; SMR21-4 (deferred-leg stamp + #5134) → f8 row; SMR21-5 (fence discipline) → f5 row; SMR21-6 (tombstone posture) → f12 row; SMR21-7 (closeout failure = the commit's error) → superseded by f2's persistent closeout debt |

- **Round 22** (v8.17): ALL THREE DEMAND-REVISION — Codex (13
  BLOCKER + 1 MAJOR), AGY (3 BLOCKER + 2 MAJOR + 1
  MINOR), SMR (2 MAJOR + 4 MINOR). Convergence: the
  OVERLAP-finalized staged leg can publish late over
  the newer accepted config (SMR22-1 = AGY f2 = Codex
  f6 — the OVERLAP finalization must CANCEL the staged
  leg's registration, and the send primitive checks
  the node is still OPEN); the ApplyResult must
  transport the beginFirstExposure triple (AGY f3 =
  SMR22-2); AGY-only: f1 (accepted_snapshot_token
  missing from StatusSnapshot — the seed has no wire
  field), f4 (the QueueConfig re-derivation lacks the
  exposure check — a gated pair must never be
  pushed), f5 (the link recording strands deleted
  members), f6 (the tombstone's full-build phrasing
  contradicts itself). SMR-only: SMR22-2's
  locus/single-source half + SMR22-3..6 pins.
  Codex-only depth: the invariant is FALSE at startup
  and does not cover every promoted outcome (f2 —
  SyncApply promotes but deliberately SKIPS the apply
  for topology/identity changes (:381-402), so
  GO-LOCAL's revised applyConfigLocked would
  live-apply a restart-only config and bypass the
  guards; PromoteRollback's nil target takes
  bootstrap teardown; the boot-recovery promote and
  bootstrapFromFile run outside applySem; and the
  rollback executor can fire mid-startup (B-derived
  naming with A-derived dataplane)); the stale
  interposition texts were not actually swept (f3);
  the tightening-only closeout has no implementable
  A-live model (f4 — A-live must mean last-EXPOSED;
  the owners take whole desired configs; web binds
  are NOT interface-independent; the debt needs a
  pair key + recomputation rule + the failure
  transition); beginFirstExposure and the cursor
  have no cross-layer lifecycle (f5 — the
  prior/ledger/cursor must transport; the crash case
  needs the durable prior config or a conservative
  clear-all, sidecar-present included); the
  discriminator's registration is undefined and
  lifecycle-unbounded (f7 — the ACTUAL pending
  publisher is syncSnapshotLocked
  (process_status.go:10-140), not OnXSKBound); the
  accepted-token fence is contradicted by leftover
  newest-seen text and lacks its seed field (f8);
  fence ownership and settlement exactly-once need a
  token registry, not one MAX-CAS writer (f9); the
  gate's clear-on-transfer lacks the
  restore-authorized quiesce (f10); the
  runtime-scoped tombstone expiry can resurrect a
  down fabric into a blackhole (f11 — the tombstone
  persists until a successful nonzero map
  transaction); the outbound marker needs a
  structured {queued, sentPair, sentDigest}
  transaction (f12). Codex's prior closures remain
  valid; Q1 remains complete.
- **Round-22 disposition table:**

  | r22 finding | v8.18 disposition |
  |---|---|
  | Codex f1 disposition accuracy | CLOSED — this table + the r21 rows re-audited; every v8.18 fold verified per-edit |
  | Codex f2 invariant false at startup / doesn't cover all outcomes | CLOSED — the invariant gains its EDGES: SyncApply's topology/identity guard (:381-402) and PromoteRollback's nil-target teardown are serialized DECISIONS, not violations; the GO-LOCAL drain carries the SAME guard (a restart-only config is never live-applied by the re-sync); the startup promotions complete BEFORE the apply scheduler starts; the rollback executor's timer is armed only AFTER the boot apply (§5-C epoch contract, §9 (b)) |
  | Codex f3 stale interposition texts | CLOSED — the v8.12-v8.16 "operator promotion needs no applySem" claims are swept (FALSE under the invariant; the persistence transition changes only durability) (§5-C epoch contract, §9 (b)) |
  | Codex f4 closeout A-live/debt/failure semantics | CLOSED — A-live := last-EXPOSED (beginFirstExposure's prior); the closeout synthesizes a REMOVAL-ONLY desired projection (the union of A-live and B-desired reachability MINUS B's removals) and applies it through class-targeted removals (web binds read CURRENT kernel addresses; MIXED changes defer wholesale); the debt keys on the pair and RECOMPUTES from live authorization to the latest desired state on each retry; a closeout failure does NOT prevent B's exposure (the alternative adds an unbounded gate — rejected); the operator-session strand is the intended monotonic-revocation consequence with the out-of-band recovery channel documented; networkd/services DEFERRED everywhere (§5-C (i), §9 (b)) |
  | Codex f5 cursor cross-layer lifecycle (= AGY f3 = SMR22-2) | CLOSED — `beginFirstExposure` runs manager-side at acceptance (the same `m.mu` section that advances `m.acceptedCommitRevision`); the `{priorPair, ledgerID, firstExposure}` triple rides the `ApplyResult`; `oldActive` is RETIRED from the invalidation path; the cursor installs atomically; the prior config is durable via the store's rollback/archive trees; an unrecoverable base (sidecar-present included) triggers the conservative clear-all (§5-C (ii), §6, §9 (a)) |
  | Codex f6 staged leg publishes late (= AGY f2 = SMR22-1) | CLOSED — the OVERLAP finalization CANCELS the staged leg's registration; the send primitive checks the reservation node is still OPEN for staged sends; the registration's lifetime is bounded by {OnXSKBound firing with the liveness check, OVERLAP finalization, helper death, an explicit stage timeout → the GO-LOCAL re-drive} (§5-C, §6, §9 (f)) |
  | Codex f7 discriminator registration undefined | CLOSED — the deferred-publish discriminator becomes a REAL REGISTRY `{pair, token, state, registeredAt}` with the transitions (staged → live; the syncSnapshotLocked catch-up publishes → completes (the ACTUAL publisher, process_status.go:10-140); OVERLAP → cancelled; helper death → died; stage timeout → the GO-LOCAL re-drive) (§5-C re-sync, §6, §9 (d)) |
  | Codex f8 fence contradictory + no seed field (= AGY f1) | CLOSED — the helper fences on newest-ACCEPTED (a rejected token never advances it); `StatusSnapshot.accepted_snapshot_token: u64` added (+ the canary); the leftover newest-SEEN text swept; the token is per-build immutable (§5-C epoch contract, §6, §9 (c)/(d)) |
  | Codex f9 fence ownership + settlement exactly-once | CLOSED — the fence becomes an OWNER-TOKEN REGISTRY (every writer takes a slot; the effective fence is the max over live slots; a writer clears only its own slot; slots die with their owner's terminal path); the settlement lifecycle completes (allocation, dedup retention/GC, duplicate re-ack, stale-discard ack, release on every terminal path; the crash case rides the cursor's durability) (§5-C (ii), §9 (a)) |
  | Codex f10 restore-authorized quiesce + link observation | CLOSED — the restore debt's retry uses a RESTORE-AUTHORIZED quiesce (the same method with the restore debt's own claim token — each retry becomes a NEW transaction: reassert the gate, stop operator-spawned workers, restore, rebind the CURRENT plan); the UNCONDITIONAL `RecordLinkObservation` (a stale Report can never un-record it; it SKIPS already-removed members (AGY f5)) (§5-C debt execution, §6, §9 (g)) |
  | Codex f11 tombstone expiry blackhole | CLOSED — the tombstone PERSISTS until a successful nonzero map transaction; the full build reads the canonical pair verbatim (a fabric REMOVED from the config is absent by construction); the all-down-fabric fallback (fabric.rs:446-464) is pre-existing, not the tombstone's doing (§5-C (i), §9 (i)) |
  | Codex f12 outbound transaction incomplete | CLOSED — the STRUCTURED SEND TRANSACTION `{queued, sentPair, sentDigest}`; the marker records the SENT pair; the exposure check holds gated pairs (AGY f4) (§6, §9 (a)) |
  | Codex f13 tests green | CLOSED — §9 re-specified per the finding's walk (§9 (a)-(j)) |
  | Codex f14 hazard budget omits v8.17 hazards | CLOSED — the budget gains the v8.17/18 classes (the startup edge (dead — the timer arms post-boot-apply), the restart-only bypass (dead — the drain carries the guard), the closeout failure/strand (dead — the debt + the documented recovery channel), the cursor/crash (dead — the durable prior + the conservative clear-all), the dead-registration suppression (dead — the registry's bounded lifetime), the post-OVERLAP publication (dead — the cancellation + the OPEN check), the settlement/fence crash (dead — the registry + the cursor's durability), the operator-vs-restore collision (dead — the restore-authorized quiesce re-binds the current plan), the tombstone resurrection (dead — persists until a nonzero write), the stale outbound (dead — the structured transaction)) (§8, §11 Q7) |
  | AGY r22 f1-f6 | CLOSED — f1 → f8 row; f2 → f6 row; f3 → f5 row; f4 → f12 row; f5 → f10 row; f6 (phrasing) → f11 row |
  | SMR r22 SMR22-1..6 | CLOSED — SMR22-1 → f6 row; SMR22-2 → f5 row; SMR22-3 (boot-recovery edge) → f2 row; SMR22-4 (closeout strand) → f4 row; SMR22-5 (tombstone posture) → f11 row; SMR22-6 (settlement crash) → f9 row |

- **Round 23** (v8.18): SMR DEMAND-REVISION (2 BLOCKER + 2 MAJOR +
  3 MINOR + 1 NIT); AGY DEMAND-REVISION (3 BLOCKER + 2 MAJOR + 1
  MINOR); Codex INFRA-BLOCKED (usage limit, reset Aug 10 — two
  documented dispatch attempts; 2-of-3 per the infra-blocked
  exception, retries continue). Convergence (every BLOCKER/MAJOR
  found by BOTH reviewers independently, all verified against
  source): the restart-only guard × GO-LOCAL rule is an unbounded
  compile-and-refuse loop (SMR23-1 = AGY f1 — a guard-refused
  promotion never advances `m.acceptedCommitRevision`, so
  `ActivePair().revision > m.acceptedCommitRevision` stays true
  forever and the drain re-fires at the 60s backoff floor until
  the operator restarts — the plan's "defers to the operator
  restart exactly as the SyncApply path does" was false: the
  SyncApply path refuses ONCE per sync-receive; the drain has a
  retry loop); the timer-arms-post-boot-apply edge names no
  mechanism (SMR23-2 = AGY f2 — the registration is pre-`Load`
  (daemon_run.go:130-136) and `Load` re-arms unconditionally
  (store_persist.go:231-253), so a recovered near-expiry timer
  can fire mid-startup against nil/partial managers; the §9 (b)
  citation for the edge had no assertion); the status-loop
  catch-up acceptance has no completion-tail owner (SMR23-3 =
  AGY f3 — the ACTUAL publisher's acceptance leg has no
  `ApplyResult` to ride; Codex r22 f5's required
  queryable-cursor/listener never landed); the ACTUAL publisher
  never checks the token liveness the plan pins on the
  `OnXSKBound` leg (SMR23-4 = AGY f4 —
  `syncSnapshotLocked`'s publish conditions never consult the
  registry: a cancelled staged object still referenced by
  `m.lastSnapshot` publishes). SMR-only: SMR23-5 (stage-timeout
  mechanics unpinned), SMR23-6 (fence-registry admission read
  discipline + crash window), SMR23-7 (the `QueueConfig` closure
  wiring — `pkg/cluster` imports no configstore), SMR23-8
  (circular cursor-crash phrasing). AGY-only: f5 (= SMR23-7),
  f6 (§9 gaps for f1/f2).
- **Round-23 disposition table:**

  | r23 finding | v8.19 disposition |
  |---|---|
  | SMR23-1 / AGY f1 restart-only GO-LOCAL loop | CLOSED — the drain's guard-refusal records a revision-keyed RESTART-SUPPRESSION marker (terminal, Warn-once with the reason); the GO-LOCAL firing condition gains `ActivePair().revision ∉ restartSuppressed`; the re-sync debt CLEARS into the marker (terminal "restart-required", not into acceptance); a newer promotion R′ > R re-arms the rule for R′ only; the boot path owns the post-restart apply (§5-C epoch contract + re-sync, §9 (d), §8) |
  | SMR23-2 / AGY f2 timer mechanism + §9 (b) citation | CLOSED — `Load` RECORDS the recovered confirm window WITHOUT arming (the `time.AfterFunc` moves out of store_persist.go:231-253); the daemon arms it via `ArmRecoveredConfirmTimer()` AFTER the boot apply completes (an already-expired deadline fires immediately on that arm — ordered after the boot apply by construction, serialized by `applySem`; the executor registration stays at daemon init); §9 (b) asserts the mechanism (a mid-startup-expiry timer does NOT fire before the boot apply; a queued expiry fires after, in order) (§5-C epoch contract, §9 (b)) |
  | SMR23-3 / AGY f3 catch-up completion-tail owner | CLOSED — the catch-up's `beginFirstExposure` installs the cursor AND posts a completion notice on the bounded daemon channel (enqueue-after-unlock, the OnXSKBound shape); the daemon drains it and runs the phased tails exactly-once per cursor entry (the cursor's `completionState` is the single authority — the Compile-leg wrapper and the listener never double-run); the helper-restart shape's no-op tails named (invalidation no-op on the empty base; the peer push + applied stamp still run) (§5-C (ii), §6, §9 (a)/(d)) |
  | SMR23-4 / AGY f4 publisher liveness | CLOSED — the OVERLAP finalization CANCELS the registration AND CLEARS the staged snapshot reference atomically under the same `m.mu` section (`m.lastSnapshot` never references a cancelled staged object); AND `syncSnapshotLocked`'s publish path gains the defense-in-depth token-liveness branch (a dead token → skip + drop the staged reference → the GO-LOCAL re-drive owns); §9 (f) asserts the publisher leg (T1 staged → OVERLAP → T2 fails pre-staging → XSK bindable → NO publish of T1) (§5-C, §9 (f)) |
  | SMR23-5 stage-timeout mechanics | CLOSED — five minutes; a scheduler entry recorded at staging, cancelled with the registration; converts to the GO-LOCAL re-drive (not an indefinite stage); the never-recoverable-XSK posture stated (dataplane down by CONFIG INTENT, Warn-visible at the transitions; §8 carries the class) (§5-C, §8, §9 (f)) |
  | SMR23-6 fence read discipline + crash window | CLOSED — the session-admission check reads the effective fence (max over live slots) and the high-water as ONE consistent snapshot (a fence raise can never be torn away from the high-water it covers); the process-exit window (slots + in-memory high-water lost; admission runs against the lost high-water until the boot's first re-raise) stated as the pre-existing posture in §8 (§5-C (ii), §8) |
  | SMR23-7 / AGY f5 QueueConfig wiring | CLOSED — constructor-injected `activePair func() (*config.Config, uint64)` + `isExposed func(rev uint64) bool` closures (the daemon wires the configstore reads; no `pkg/cluster`→configstore import); the marker records from the structured RESULT (the claim moves after the send; the reconciler at daemon_ha_sync.go:474-497 reads `sentPair` from the result); the held push re-wakes on the exposure drain's completion (a trigger edge into the level-triggered reconciler) (§5-C (ii), §6) |
  | SMR23-8 cursor-crash phrasing | CLOSED — reworded: the crash LOSES the cursor; recovery derives the incomplete set from the `appliedRevision` sidecar + the store's rollback/archive trees (exposed vs active revision) (§5-C (ii)) |
  | AGY r23 f6 §9 gaps | CLOSED — §9 (b) gains the timer-mechanism assertion; §9 (d) gains the restart-only suppression assertion (a guard-refused promotion neither re-fires the rule nor holds the debt) |

- **Round 24** (v8.19): SMR DEMAND-REVISION (1 BLOCKER + 1 MAJOR
  + 4 MINOR + 3 NIT); AGY DEMAND-REVISION (1 BLOCKER + 2 MAJOR +
  1 MINOR + 1 NIT); Codex INFRA-BLOCKED (third documented
  attempt; 2-of-3). Convergence (the BLOCKER found by BOTH
  independently): the v8.19 completion notice's tails have no
  pair-currency gate (SMR24-1 = AGY f1 — a stale notice for B
  drained after C's apply runs A→B invalidation over C-permitted
  sessions and overwrites C's applied stamp; SMR's trace showed
  the abort-only fix LEAKS (C's B→C delta never covers
  A-permitted/B-revoked/C-revoked sessions), so the fold is the
  plan's own uniform-base rule: `applySem` + prior→CURRENT
  composition + SUPERSEDED terminal). The remainder: the
  cursor's check-and-advance atomic (SMR24-2 = AGY f2); the
  post-clear `m.lastSnapshot` value (SMR24-3 = AGY f3,
  downgraded on the verified nil-guard census); the notice
  overflow sweep (SMR24-4 = AGY f4); the suppression marker's
  recording locus (SMR24-5, SMR-only); the r23 table's SMR23-3
  §9 citation gap (SMR24-6 = AGY f5's §9 demand); three NITs
  (SMR24-7..9).
- **Round-24 disposition table:**

  | r24 finding | v8.20 disposition |
  |---|---|
  | SMR24-1 / AGY f1 notice currency gate | CLOSED — the completion-notice drain acquires `applySem`, re-reads the CURRENT pair at drain time, composes prior → CURRENT for the invalidation (the uniform base — complete with no over-deletion; the invalidation RUNS for stale notices exactly as for current ones), currency-gates the applied stamp + peer push (skipped when the notice's pair is no longer current), and marks a superseded notice's cursor entry SUPERSEDED (terminal — SUPERSEDED marks ONLY the pair-specific tails (stamp/push) as skipped-by-design; the v8.20 "the newer pair's chain covers the composition" phrasing was reworded v8.21 per SMR r25 SMR25-1 = AGY r25 f2 — C's B→C chain never covers A-permitted/B-revoked/C-revoked sessions; the drain's own prior → CURRENT composition does) (§5-C (ii), §6, §9 (a)) |
  | SMR24-2 / AGY f2 cursor atomic | CLOSED — the cursor record lives manager-side; EVERY `{phaseCursor, completionState}` read-modify-write goes through ONE manager method under `m.mu` (the daemon wrapper's phase completions call it across the package boundary; the listener likewise); the transports are per-acceptance unique, so the residual race is phase-level and the `m.mu` advancement covers it (§5-C (ii), §9 (a)) |
  | SMR24-3 / AGY f3 post-clear value | CLOSED — the post-clear `m.lastSnapshot` value is NIL (the staged object is the only reference; revert-to-published is impossible without new retained state — rejected); the nil-guard census (syncSnapshotLocked, overlay, neighbor, HA, status, applied-view — all nil-guard under `m.mu`) becomes a build-time canary; the transient overlay/scheduler publish gap until the GO-LOCAL re-drive rebuilds is stated (§5-C, §6) |
  | SMR24-4 / AGY f4 notice overflow | CLOSED — the notice is an OPTIMIZATION over a periodic pending-cursor sweep on the daemon scheduler (the cursor registry is queryable daemon-side; the sweep runs at the standing debt cadence); the enqueue failure records a Warn edge (§5-C (ii), §9 (a)) |
  | SMR24-5 marker recording locus | CLOSED — the recording lives in the SHARED guard-refusal path (one routine called by both the sync-receive guard (daemon_apply_commit.go:381-402) and the drain's guard), so the marker lands on the FIRST refusal and the drain never fires even once for R (§5-C epoch contract + re-sync) |
  | SMR24-6 / AGY f5 §9 listener assertions | CLOSED — §9 (a) gains the stale-notice composition assertion (prior → CURRENT at drain time, never A→B over C), the currency-gated stamp/push, the SUPERSEDED terminal marking, and the sweep fallback |
  | SMR24-7 timeout/bind race | CLOSED — the scheduler entry's fire and the registration's completion serialize under `m.mu`; the fire re-checks the registration's liveness under the same lock (a completed registration cancels the entry atomically) (§5-C) |
  | SMR24-8 isExposed lock order | CLOSED — the closure's `DurableRevision()` read under `writeMu` follows the order writeMu → `s.mu` ONLY (the reconciler reads `ActivePair()` under `s.mu` and RELEASES before `QueueConfig`; no `s.mu` holder calls into the send path) (§5-C (ii), §6) |
  | SMR24-9 held-push budget | CLOSED — §11 Q7 carries the class (a never-completing drain leaves the gated push held — a consequence of the budgeted persistent-storage-failure class; the peer's state never leads the primary's exposed state) |

- **Round 25** (v8.20): SMR DEMAND-REVISION (0 BLOCKER + 0
  MAJOR + 2 MINOR + 2 NIT); AGY PLAN-READY-WITH-NITS (2 MINOR
  + 2 NIT); Codex INFRA-BLOCKED (fourth documented attempt;
  2-of-3). Convergence: the SUPERSEDED parenthetical
  mis-described the fix it shipped (SMR25-1 = AGY f2 — "the
  composition is covered by the newer pair's chain" is the
  abort-only leak SMR24-1 traced; the fold's (i) is what
  actually covers the A-era deletions, and it RUNS for stale
  notices), and the sweep's semaphore/cadence were unpinned
  (SMR25-2 = AGY f3). AGY-only: f1 (a claimed
  `C-permitted`→`C-revoked` typo — NOT-VERIFIED
  (spurious): both the dispatched prompt and plan.md
  read `C-revoked`; an AGY misread of the wrapped
  SURVIVES/deleted clause pair). SMR-only: SMR25-3
  (the applySem → `m.mu` census),
  SMR25-4 (the OVERLAP-clear → re-drive chain-state note).
- **Round-25 disposition table:**

  | r25 finding | v8.21 disposition |
  |---|---|
  | SMR25-1 / AGY f2 SUPERSEDED wording | CLOSED — reworded in the normative text AND the r24 table row: SUPERSEDED marks ONLY the pair-specific tails (stamp/push) as skipped-by-design; the invalidation (i) composes prior → CURRENT and RUNS for stale notices exactly as for current ones; §9 (a) pins the reading (a skip-everything implementation FAILS) (§5-C (ii), §1 r24 row, §9 (a)) |
  | SMR25-2 / AGY f3 sweep semaphore + cadence | CLOSED — the sweep rides the 1s status-application pass (a dropped notice delays the tails ≤ 1s + drain scheduling) and its per-entry execution is the SAME `applySem`-acquiring drain path as the notice's (one routine, two triggers) (§5-C (ii)) |
  | AGY f1 §9 (a) typo claim | NOT-VERIFIED (spurious) — AGY quoted the review prompt's §9 (a) as reading "C-permitted session is deleted", but BOTH the dispatched prompt (`/tmp/agy-6749-r25-prompt.txt`, md5 3fd8b4c0) AND plan.md's §9 (a) read `C-revoked` (zero occurrences of the claimed form in either); an AGY misread of the wrapped SURVIVES/deleted clause pair |
  | SMR25-3 applySem → m.mu census | CLOSED — stated next to SMR24-8's writeMu → `s.mu` rule (Compile runs under `applySem` and takes `m.mu`; the GO-LOCAL debt recording is enqueue-after-unlock; the manager never acquires `applySem`) (§5-C (ii)) |
  | SMR25-4 chain-state note | CLOSED — stated: T1's node is OVERLAP-terminal, T2's Finish folded the recorded outcomes and cleared `compileInFlight`, and the re-drive's StartCompile begins a FRESH chain (§5-C) |

- **Round 26** (v8.21): SMR DEMAND-REVISION (0 BLOCKER + 1 MAJOR
  + 3 MINOR); AGY DEMAND-REVISION (1 MAJOR + 2 MINOR + 1 NIT);
  Codex INFRA-BLOCKED (fifth documented attempt; 2-of-3).
  Convergence (both substantive pins found independently): the
  v8.21 sweep pin let the 1s status pass execute a blocking
  `applySem` acquire (SMR26-1 = AGY f1 — freezable for minutes
  behind a long control apply, stalling status ingestion and
  heartbeat), and the notice drain's composition target could
  be an unexposed gated successor (SMR26-2 = AGY f2 — composing
  A→C while C is gated deletes B-authorized sessions). AGY-only:
  f3 (the r25 f1 row's mis-attribution — already corrected at
  `e728b2e7d`), f4 (the §9 (a) gated-successor assertion, folds
  with SMR26-2). SMR-only: SMR26-4 (the cursor registry's
  terminal-entry GC, self-found).
- **Round-26 disposition table:**

  | r26 finding | v8.22 disposition |
  |---|---|
  | SMR26-1 / AGY f1 sweep blocks the status thread | CLOSED — the 1s status pass only SCANS and MARKS pending cursors (under `m.mu`, non-blocking) and DISPATCHES the per-entry drain execution to the daemon's apply scheduler (the scheduler thread the notice drain rides — the blocking acquire is safe there); the "ONE routine, two triggers" lives on the scheduler thread, never the status thread; §9 (a) asserts the pass completes under `applySem` contention (§5-C (ii), §9 (a)) — amended v8.23 (AGY r27 f3): the "dispatch" is NOT a channel — the scheduler's per-tick pass ITERATES THE PENDING CURSOR SET (the notice is the fast path; the pending set is the correctness path; no dispatched-flag, no queue, no drop policy, no stuck state), and the drain's cursor lookup treats a MISSING entry as already-terminal |
  | SMR26-2 / AGY f2+f4 composition target | CLOSED — the invalidation composes prior → the drain-time EXPOSED pair (`m.lastExposedPair` under `m.mu`) — A→C when C is exposed, A→B when C is gated (one rule, both shapes; a gated successor never invalidates B-authorized sessions); the stamp/push gate keys on STORE currency (the two "currents" named explicitly); §9 (a) gains the gated-successor assertion (§5-C (ii), §9 (a)) |
  | SMR26-3 / AGY f3 r25 f1 row | CLOSED-ALREADY at `e728b2e7d` — the row now records NOT-VERIFIED (spurious — both artifacts read `C-revoked`; an AGY misread) |
  | SMR26-4 cursor terminal-entry GC | CLOSED — a terminal entry (completed or SUPERSEDED) is GC'd on the sweep pass that first observes it terminal; the registry's live set is bounded by concurrently-incomplete exposures; the crash rule re-derives from the sidecar + store, never from a GC'd entry (§5-C (ii)) |

- **Round 27** (v8.22): SMR DEMAND-REVISION (0 BLOCKER + 0
  MAJOR + 1 MINOR + 1 NIT); AGY DEMAND-REVISION (2 MAJOR + 1
  MINOR + 1 NIT); Codex INFRA-BLOCKED (sixth documented
  attempt; 2-of-3). Convergence (same underlying gap at
  different severities): the v8.22 "dispatch" mechanism was
  unspecified (SMR27-1 = AGY f2/f3 — a bounded queue that
  drops strands a marked-dispatched entry forever; an
  unbounded queue is an OOM vector; the fold removes the
  channel entirely — the scheduler iterates the PENDING cursor
  set), and the drain's cursor lookup had no missing-entry
  contract (SMR27-2 = AGY f1/f4 — a drain dequeued for a
  GC'd entry must treat the missing key as already-terminal,
  not dereference nil). AGY-only: f3 (the r26 SMR26-1 row's
  dispatch phrasing). SMR-only: none beyond the shared spine.
- **Round-27 disposition table:**

  | r27 finding | v8.23 disposition |
  |---|---|
  | SMR27-1 / AGY f2+f3 dispatch mechanism | CLOSED — there is NO dispatch channel: the scheduler's per-tick pass ITERATES THE PENDING CURSOR SET directly (the notice remains the fast-path optimization; the pending set IS the correctness path — no dispatched-flag, no queue, no drop policy, no stuck state: an entry is pending until terminal, and the scheduler drains the pending set through the ONE drain routine every tick); the r26 SMR26-1 row's phrasing amended (§5-C (ii), §1 r26 row, §9 (a)) |
  | SMR27-2 / AGY f1+f4 missing-entry contract | CLOSED — the drain's cursor lookup treats a MISSING entry as already-terminal (a safe no-op — the entry's work completed or was covered by the newer pair's chain; the crash rule never depends on a GC'd entry), never a nil dereference or an unhandled error; §9 (a) asserts the GC'd-dequeue no-op (§5-C (ii), §9 (a)) |

- **Round 28** (v8.23): SMR DEMAND-REVISION (0 BLOCKER + 0
  MAJOR + 2 MINOR); AGY DEMAND-REVISION (1 MAJOR + 1 MINOR +
  1 NIT); Codex INFRA-BLOCKED (seventh documented attempt;
  2-of-3). Convergence: the failing-tail retry cadence was
  unpinned (SMR28-2 = AGY f1 — the iterate-pending-set model
  re-invoked the drain every 1s tick on a failing entry,
  bypassing the standing backoff); the cursor's phase machine
  needed the claim-or-skip tri-state (SMR28-1, SMR-only — the
  v8.20 "check-and-advance" was ambiguous between claim-or-skip
  and check-then-execute-then-advance, and only the first is
  exactly-once); and the missing-entry contract's scope needed
  to go uniform (AGY f2/f3 — the scheduler's iterate drain
  picks up a Compile-leg entry concurrently with its
  synchronous wrapper, so the wrapper's accessor can hit a
  GC'd key too).
- **Round-28 disposition table:**

  | r28 finding | v8.24 disposition |
  |---|---|
  | SMR28-1 claim-or-skip tri-state | CLOSED — per phase, pending → claimed → complete; the claim is atomic under `m.mu`; a duplicate claimant skips (the first executor covers the phase; a claimed-but-crashed drain is the in-memory-loss case the crash rule re-derives); §9 (a) asserts the claim-collision (two concurrent drains, one phase, exactly one execution) (§5-C (ii), §9 (a)) |
  | SMR28-2 / AGY f1 failing-tail cadence | CLOSED — the entry stays pending and the retry rides a per-entry `nextAttempt` on the standing 5/10/20/60s exponent-preserving ladder (the per-tick pass skips not-yet-due entries); the failure Warns on the standing edge-detect; §9 (a) asserts two consecutive failures do not produce back-to-back full drains (§5-C (ii), §9 (a)) |
  | AGY f2+f3 uniform missing-entry contract | CLOSED — the missing-entry → already-terminal contract applies to EVERY registry accessor (the scheduler/notice drains AND the synchronous `ApplyResult` wrapper — the iterate drain picks up a Compile-leg entry concurrently with its wrapper, so the wrapper's accessor can hit a GC'd key); §9 (a) asserts the wrapper-vs-GC race no-ops cleanly (§5-C (ii), §6, §9 (a)) |

- **Round 29** (v8.24): SMR DEMAND-REVISION (0 BLOCKER + 0
  MAJOR + 2 MINOR + 1 NIT); AGY DEMAND-REVISION (1 MAJOR + 1
  MINOR + 2 NIT); Codex INFRA-BLOCKED (eighth documented
  attempt; 2-of-3). Convergence: the claim's release-on-failure
  had to be atomic with the backoff set (SMR29-1 = AGY f2), and
  the claim's lifetime needed more than the process-crash story
  (AGY f1's MAJOR — a goroutine PANIC pins the phase claimed
  forever with no recovery path; SMR29-2's named-bounds/D-state
  fold was superseded by the defer-revert + lease). AGY-only:
  f3 (the ladder reset — AGY's per-phase-success form adopted,
  superseding SMR29-3), f4 (the §9 (a) panic-injection
  assertion).
- **Round-29 disposition table:**

  | r29 finding | v8.25 disposition |
  |---|---|
  | AGY f1 un-leased claimed trap (panic vs process crash) | CLOSED — (i) a `defer` wrapper around EVERY phase execution catches panics and atomically reverts claimed → pending WITH `nextAttempt` under `m.mu`; (ii) the claim records `claimedAt` + a claim GENERATION and is STEALABLE after the named bound (the tail operations' own timeout sum) — the stealer runs with a bumped generation and the stale claimant's late advance is REFUSED (§5-C (ii), §9 (a)) |
  | SMR29-1 / AGY f2 atomic release + due-check | CLOSED — the claimed → pending release and the `nextAttempt` set are ONE `m.mu` operation; the claim itself refuses entries whose `nextAttempt` is in the future (the due-check lives in the claim — the notice-triggered drain respects it too) (§5-C (ii), §9 (a)) |
  | SMR29-2 stuck-claim bound | CLOSED — superseded by AGY f1's lease (the named bound IS the tail operations' timeout sum; the steal replaces the D-state-only posture for claims) |
  | SMR29-3 ladder scope/reset | CLOSED — per-ENTRY ladder; AGY f3's reset form adopted (a SUCCESSFUL phase resets the ladder to the base step for the remaining phases; a FAILED phase advances it), superseding the terminal-only form (§5-C (ii)) |
  | AGY f4 §9 (a) panic injection | CLOSED — §9 (a) asserts a panicking phase execution reverts claimed → pending with backoff applied |

- **Round 30** (v8.25): SMR DEMAND-REVISION (0 BLOCKER + 0
  MAJOR + 1 MINOR + 2 NIT); AGY DEMAND-REVISION (2 BLOCKER +
  1 MINOR + 1 NIT); Codex INFRA-BLOCKED (ninth documented
  attempt; 2-of-3). The round's substance: the v8.25 lease
  steal was under-fenced on BOTH sides (AGY f1 — the
  generation guard refused only the stale claimant's
  completion RECORD while its tail EXECUTION mutated the store
  and sessions un-fenced (a late stamp regresses
  `appliedRevision`; a late invalidation deletes C-authorized
  sessions); and AGY f2 — the fixed-interval steal spawned an
  unbounded goroutine per namedBound on a hanging phase). SMR
  r30's own idempotency "proofs" (SMR30-1) were WRONG for the
  multi-commit case and are RETRACTED in v8.26 (the stamp is
  a regression, not an idempotent set; the late invalidation
  is the SMR24-1 class reopened). SMR-only: SMR30-2/SMR30-3
  (the revert's missing-entry no-op; the advisory-mark note).
- **Round-30 disposition table:**

  | r30 finding | v8.26 disposition |
  |---|---|
  | AGY f1 un-fenced stale side effects | CLOSED — (i) the drain's claim checks LIVENESS AT ENTRY (a stolen/dead claim aborts the drain BEFORE any side effect — the missing/stolen-entry contract, same `m.mu` operation); (ii) the applied stamp uses the CAS form (`setAppliedDigest` (store.go:848), expected store-current revision — refuses when the store moved past); (iii) the drain's `applySem` hold + the drain-time-EXPOSED composition order every mid-drain case (no exposure moves under the semaphore; a live-claimed drain composes correctly); SMR30-1's multi-commit idempotency claims RETRACTED (§5-C (ii), §9 (a)) |
  | AGY f2 steal goroutine leak | CLOSED — the steal (i) CANCELS the stale claimant's context (every tail operation takes the claim's ctx and aborts on cancellation; a kernel-wedged residue is the budgeted D-state class), (ii) ADVANCES the entry's ladder (a steal is a failure by construction — the cadence decays to the 60s floor), (iii) is a REPLACEMENT (exactly one live claim generation per entry — a second steal is refused while a live one stands) (§5-C (ii), §9 (a)) |
  | SMR30-1 overlap idempotency | CLOSED-PARTIALLY-RETRACTED — the single-pair idempotency claims stand (idempotent deletes; the receiver's SyncApply no-ops identical content; the marker records the same sentPair) but the multi-commit forms were wrong (a late stamp on the OLD revision is a regression; a late invalidation over a NEWER exposure is the SMR24-1 class) — the fences in the AGY f1 row replace the multi-commit reliance |
  | SMR30-2 / AGY f4 revert missing-entry | CLOSED — the defer-revert rides the uniform missing-entry → already-terminal contract (a no-op on a GC'd entry), stated explicitly (§5-C (ii)) |
  | SMR30-3 advisory mark × due-check | CLOSED — stated (the claim refuses not-yet-due entries; the mark re-fires next pass; no mark-clearing machinery) (§5-C (ii)) |
  | AGY f3 §9 (a) gaps | CLOSED — §9 (a) asserts the late-stamp CAS refusal, the late-invalidation entry-fence abort, the steal's context cancellation + cadence decay + replacement-only, and the revert's missing-entry no-op |

- **Round 31** (v8.26): SMR DEMAND-REVISION (0 BLOCKER + 0
  MAJOR + 1 MINOR + 2 NIT); AGY DEMAND-REVISION (1 MAJOR + 1
  MINOR + 1 NIT — architectural audit CLEAN: "no new
  architectural race conditions or deadlocks were introduced by
  v8.26"); Codex INFRA-BLOCKED (tenth documented attempt;
  2-of-3). Convergence: the mid-drain steal's full trace needed
  spelling out (SMR31-1 = AGY f1/f3 — the entry fence covers
  dead-at-entry, but the steal can fire mid-execution under
  `applySem`, and the landed-but-unrecorded side effects plus
  the stealer's idempotent re-execution had to be stated and
  tested); the cancellation claim was imprecise for in-memory
  store operations (SMR31-2 = AGY f2); the goroutine
  population bound needed stating (SMR31-3).
- **Round-31 disposition table:**

  | r31 finding | v8.27 disposition |
  |---|---|
  | SMR31-1 / AGY f1+f3 mid-drain steal walk + test | CLOSED — the full trace stated in §5-C (ii) (the steal fires under `m.mu` while the stale drain executes under `applySem`: the invalidation composed at entry stays correct (no exposure moves under the semaphore); the stale stamp's CAS lands correctly (store-active pair); the completion record is generation-refused; the stealer re-executes and the side effects are the idempotent forms — identical stamp CAS on the same value, identical push (receiver `SyncApply` no-ops on identical content (daemon_apply_commit.go:356-360)), idempotent deletes); §9 (a) gains the mid-drain interleaving assertion (a no-generation-check implementation FAILS) (§5-C (ii), §9 (a)) |
  | SMR31-2 / AGY f2 cancellation scope | CLOSED — clarified: ctx cancellation bounds the I/O tails (the conn write's TCP timeout + `handleDisconnect`; socket operations); in-memory store mutations (`setAppliedDigest` takes no ctx) rely on the CAS revision verification — either order safe (§5-C (ii)) |
  | SMR31-3 goroutine population bound | CLOSED — stated: cancellation reaps each steal-spawned goroutine within one operation of its cancellation; the residual population is the kernel-wedged budgeted D-state class only (§5-C (ii)) |

- **Round 32** (v8.27): SMR DEMAND-REVISION (0 BLOCKER + 0
  MAJOR + 1 MINOR + 1 NIT); AGY PLAN-READY-WITH-NITS (1 MINOR
  + 1 NIT — the mid-drain trace assessed "mathematically
  sound" and the cancellation partition accepted); Codex
  INFRA-BLOCKED (eleventh documented attempt; 2-of-3).
  Convergence: the C2-interpose gap (an exposure landing
  between the stale drain's `applySem` release and the
  stealer's acquire) needed its composition proof and test
  (SMR32-1 = AGY f1). AGY-only: f2 (the stamp prose's
  store-currency-skip form). SMR-only: SMR32-2 (the
  record-before-timer note).
- **Round-32 disposition table:**

  | r32 finding | v8.28 disposition |
  |---|---|
  | SMR32-1 / AGY f1 C2-gap composition + test | CLOSED — the stealer runs its OWN composition against the exposed pair at ITS OWN entry (never re-runs the stale drain's): the union (stale A→C + C2's wrapper's C→C2 + stealer A→C2) deletes exactly (A∪C)\(C∩C2) with survivors exactly (A∪C)∩C∩C2 (the v8.28 "(A∪C)\C2 with every C2-permitted session surviving" was corrected v8.29 per AGY r33 f2 — a session A-permitted, C-revoked, C2-re-permitted was deleted at C's exposure and never recreated; intermediate revocations are permanent); the two cursor entries are independent; §9 (a) gains the C2-interpose assertion (the stealer detects C1 as non-store-active, skips its stamp/push, composes A→C2 idempotently, marks C1 SUPERSEDED) (§5-C (ii), §9 (a)) |
  | AGY f2 stamp prose | CLOSED — "a second identical stamp CAS on the same value (or skipped via store-currency gating when the pair is no longer store-active)" (§5-C (ii)) |
  | SMR32-2 record-before-timer | CLOSED — stated: a drain finishing before the namedBound records complete normally and the steal-timer is cancelled by the completion (same `m.mu` op as the record) (§5-C (ii)) |

- **Round 33** (v8.28): SMR PLAN-READY-WITH-NITS (2 NIT — the
  first SMR non-DEMAND verdict of the campaign); AGY
  DEMAND-REVISION (1 BLOCKER + 1 MINOR + 1 NIT); Codex
  INFRA-BLOCKED (twelfth documented attempt; 2-of-3). The
  round's substance: AGY's BLOCKER found a real design hole
  the SMR sweep missed — the STORE-currency stamp/push gate
  starves the LIVE exposed pair whenever the successor is
  GATED (C1 exposed, C2 store-active-but-unexposed: C1's
  stamp/push skipped, C2's push held — the peer and
  `appliedRevision` stay at A while the primary runs C1);
  the gate re-keys to EXPOSED currency in v8.29. And the
  v8.28 union formula was wrong for re-permitted sessions
  (AGY f2 — a session A-permitted, C-revoked, C2-re-permitted
  was deleted at C's exposure and never recreated; the
  deleted set is (A∪C)\(C∩C2)). SMR's own r33 nits: the
  multi-gap generalization (SMR33-1 (i) = AGY f3) and the
  push-coverage note (SMR33-2, subsumed by f1's fix).
- **Round-33 disposition table:**

  | r33 finding | v8.29 disposition |
  |---|---|
  | AGY f1 gated-successor starves the exposed pair | CLOSED — the stamp/push gate re-keys from STORE currency to EXPOSED currency (the notice's pair == `m.lastExposedPair`): the SMR24-1 over-stamp case (newer pair EXPOSED → skip) stays killed; the gated-successor case (successor store-active but UNEXPOSED → C1 is still the exposed pair → stamp/push C1 normally, entry completes normally); the SUPERSEDED marking keys on the same exposed currency (§5-C (ii), §6, §9 (a)) |
  | AGY f2 union formula wrong for re-permitted sessions | CLOSED — corrected: the deleted set is (A∪C)\(C∩C2) (survivors (A∪C)∩C∩C2); intermediate revocations are PERMANENT (the intended semantics — re-permit is re-handshake, never resurrection); the v8.28 "every C2-permitted session survives all three" is struck in §5-C (ii), the r32 row, and §9 (a); the stealer's delete-set subsumption (A\C2 ⊆ (A\C) ∪ (C\C2) — provably no over-deletion) stands (§5-C (ii), §1 r32 row, §9 (a)) |
  | SMR33-1 (i) / AGY f3 multi-gap generalization | CLOSED — stated: N successive gaps leave the stealer composing A→C_k and the union exactly (A∪C_1∪…∪C_{k-1})\(C_1∩…∩C_k) (the drain-time-EXPOSED-at-each-entry rule, not a new case) (§5-C (ii)) |
  | SMR33-2 push coverage | CLOSED — subsumed by the f1 fix: in the gated-successor case C1's push FIRES (C1 is the exposed pair); in the exposed-successor case C2's own push carries the newer config, with the periodic reconciler as the backstop (§5-C (ii)) |

- **Round 34** (v8.29): SMR DEMAND-REVISION (1 BLOCKER + 1
  MINOR); AGY DEMAND-REVISION (1 BLOCKER + 1 MINOR); Codex
  INFRA-BLOCKED (thirteenth documented attempt; 2-of-3). Full
  convergence on ONE defect, found from both sides: the v8.26
  "stamp CAS (expected store-current revision)" phrasing is
  the wrong model against the actual digest-based machinery
  (SMR34-1 = AGY f1 — an active-keyed CAS refuses the very
  stamp the v8.29 gate admits; a CAS-free overwrite lets a
  late stamp regress; verified store.go:787-853: digest-based,
  no revision CAS — the correct form is the captured-digest
  stamp + the exposed-currency admission gate). And the §9 (a)
  stamp-LANDS assertion (SMR34-2 = AGY f2).
- **Round-34 disposition table:**

  | r34 finding | v8.30 disposition |
  |---|---|
  | SMR34-1 / AGY f1 stamp CAS basis wrong | CLOSED — the v8.26 revision-CAS phrasing is RETRACTED (plan-invented; fails both ways against the actual machinery: an active-keyed CAS refuses the gate-admitted stamp; a CAS-free overwrite lets a late stamp regress). The stamp is the CAPTURED-DIGEST stamp (`MarkAppliedDigest(pair.capturedDigest)` — the pair's OWN digest captured at acceptance/apply time under the apply serialization (the #6296 form, store.go:824-853) — NEVER `MarkActiveApplied()` (which re-reads `s.active` and would stamp the never-applied successor)); the anti-stale protection is the v8.29 EXPOSED-currency ADMISSION gate (a stale notice's stamp is skipped before any stamp call); the read-side `ActiveApplied()` digest comparison is the only "CAS" the machinery needs (§5-C (ii), §9 (a)) |
  | SMR34-2 / AGY f2 stamp-LANDS assertion | CLOSED — §9 (a) asserts `appliedDigest == configTextDigest(C1's text)` after C1's drain with C2 gated, and `== digest(C2)` after C2's apply (a stamp-call-that-doesn't-land FAILS) |

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
   AGY r17 f3 = SMR r17 SMR17-4; the CANONICAL-PAIR
   completion is v8.14, Codex r18 f11): the
   manager maintains, per fabric projection, a CANONICAL
   `(payload, generation)` pair — built ONCE per accepted
   mutation in ONE `m.mu`
   section that (a) SAMPLES the rich observation (the map
   view (`FabricFwdInfo`, types.go:797-804) — the
   AUTHORITATIVE MAC source (the map's own `PeerMAC`/
   `LocalMAC` fields, populated by the daemon before the
   map mutation (daemon_ha_fabric.go:717-731) — the
   payload's MACs come from the MAP, never from an
   independently refreshed manager cache (v8.15, Codex
   r19 f12's causal-split fix: a cache re-resolution can
   bind generation g to a payload different from the
   map; the neighbor cache is consulted ONLY when the
   map's fields are unresolved (the zero case → the
   existing unresolved-posture marker))) — with the
   IDENTITY-VS-TELEMETRY separation restated (v8.16, SMR
   r20 SMR20-6 = the resolution of AGY r20 f1's apparent
   contradiction: the projection IDENTITY (what the
   mark-all/replan rule and the guard key on) is (name,
   parent Linux name, parent ifindex, effective queue
   count) and EXCLUDES the MACs, so a peer-MAC resolution
   (zero → learned) is a TELEMETRY update — it IS a BPF
   map mutation (so it mints a new generation and updates
   the canonical payload's telemetry fields, flowing to
   the helper, whose fabric forwarding starts using the
   learned MAC), and it NEVER fires the mark-all rule
   (the identity is unchanged — §9 item 19(ii)'s
   "resolved MAC → NO replan, NO pending marks" is
   consistent with map-authoritative MACs BECAUSE the two
   live in different fields; the "dedup hash" below is
   the note-CAS content hash, NOT the projection-change
   detector) — PLUS the names,
   overlay identity, queue counts, and `Up` states the
   `FabricSnapshot` payload needs (protocol.go:315-333 —
   the v8.13 "build the payload from the map view" was
   incomplete: the map view is two ifindexes and two MACs;
   the payload needs independent link reads, which this
   section performs — bounded netlink reads (µs-ms
   each, the latency stated), not an atomic kernel
   sample but sufficient: the map fields are the
   authoritative half and the link metadata changes only
   with the projection identity itself), (b) performs or
   confirms the BPF map mutation AND mints
   `map_generation` ATOMICALLY with it, and (c) builds and
   RETAINS the helper payload FROM THE SAME SAMPLE, bound
   to the minted generation.
   EVERY carrier then uses the CURRENT canonical pair
   VERBATIM, read AT THE PUBLISH LEG (v8.15, Codex r19
   f12's uniform-rule correction — the v8.14 text's
   "(P0, g0) stale clone" example was self-contradictory:
   after a failed `update_fabrics(P, g)` the RETAINED
   pair IS (P, g) (the mutation was accepted), so every
   later carrier — a route/scheduler/#5134 clone OR a
   full snapshot — reads (P, g) at the publish leg and
   the helper's acceptance advances `accepted` to g,
   coherent with the map (P); the v8.14 (P0, g0) case
   does not exist) — with the REMOVAL TOMBSTONE
   pinned (v8.16, Codex r20 f11's zero-entry fix: when
   the daemon CLEARS a map entry (`Ifindex=0`), an
   all-unresolved payload makes the helper PRESERVE its
   previous resolved working set (fabric.rs:373-397/
   :406-437, snapshot_refresh.rs:83-112) — the helper
   could acknowledge g, the debt could clear, and HA
   readiness could pass while the BPF map is disabled
   but Rust still retains the old fabric; the canonical
   payload therefore carries an explicit `removed: true`
   tombstone for a deliberately cleared entry
   (additive), and the helper's refresh DROPS the
   fabric state on it (never preserve); the guard's
   rejection of missing parent/MAC values
   (planning.rs:452-476) covers the UNRESOLVED case
   (a candidate that was never resolvable), distinct
   from the deliberate clear): an
   `update_fabrics` send carries the canonical
   `(payload, generation)`; a FULL SNAPSHOT's fabrics
   section is READ FROM THE RETAINED PAIR AT THE PUBLISH
   LEG (never the pre-m.mu build (builder.go:78,
   manager_compile.go:214/:228)), and the snapshot's
   CONTENT HASH for the note-CAS dedup is computed over
   the FINAL wire content (post-canonical-fabrics —
   v8.15, Codex r19 f12's hash-domain fix: hashing the
   pre-replacement section would let the dedup decide
   about bytes that are never sent). The
   helper echoes
   `accepted_fabric_map_generation` — the generation OF
   THE LAST PAYLOAD IT ACCEPTED — advancing on EVERY
   accepted carrier (full snapshot or `update_fabrics`,
   tombstones included)
   to THAT PAYLOAD's generation. A clean
   fabric send whose echoed generation matches the current
   `map_generation` is the coherence proof; and the fabric
   sync DEBT clears on an observed accepted generation ≥
   its recorded one (v8.15 — the full snapshot's
   acceptance of (P, g) clears a debt recorded for the
   failed `update_fabrics(P, g)` — the self-healing leg
   the v8.14 text missed). The REMOVAL TOMBSTONE
   (v8.16, Codex r20 f11; specified across all three
   paths per Codex r21 f12): the canonical payload
   carries `removed: true` PLUS the configured fabric
   NAME (the `FabricSnapshot` names exist
   (protocol.go:315-333) — the RUNTIME `FabricLink`
   lacks the name (forwarding.rs:848-860), so the
   payload's name is the tombstone's stable key, and
   the helper resolves it against the OLD snapshot's
   fabrics for the physical identity). ALL THREE
   paths honor it: (i) the incremental `update_fabrics`
   handler (handlers/mod.rs:144-174 — the tombstone's
   entry drops the fabric state in `refresh_fabric_links`
   and stores the tombstoned projection); (ii) the full
   snapshot build (`populate_fabrics`,
   forwarding_build/fib.rs:233-264) reads the CANONICAL
   PAIR VERBATIM, and the tombstone PERSISTS until a
   successful nonzero map transaction (v8.18, Codex
   r22 f11's resurrection fix — the v8.17
   config-authoritative form let an unrelated full
   apply re-add the Rust `FabricLink` while the BPF
   map stays deliberately zero (the clear sets
   `fabricPopulated=false` and further clears no-op
   (daemon_ha_fabric.go:762-778)), and when EVERY
   installed fabric reports down the redirect
   deliberately falls back to one (fabric.rs:446-464) —
   a blackhole; so the tombstone dies ONLY when the
   population machinery next lands a successful
   nonzero map write (the operational state
   re-converging on its own machinery), and a fabric
   REMOVED from the config is absent from the build by
   construction);
   (iii)
   the same-plan/full runtime refresh
   (snapshot_refresh.rs:247-269/:380-396 — which
   today PRESERVES and merges old resolved fabrics:
   a tombstoned name is dropped from the preserved
   merge instead). The deliberate CLEAR (the daemon
   zeroes a map entry, `Ifindex=0`) is distinguished
   from the guard's unresolved-candidate rejection
   (planning.rs:452-476 — a candidate that was NEVER
   resolvable), and the generation/echo protocol
   covers the tombstone identically (its acceptance
   advances accepted — readiness compares).
   `map_generation` SEEDS from the startup ping echo
   (v8.13, SMR r17 SMR17-4: accepted → the minted
   high-water, mirroring the `publication_rev` seed — a
   manager re-init over a surviving helper no longer
   desyncs); and the new-helper-zero vs old-helper-zero
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
   (protocol.go:315-333)). The controllers.go:68/:112 shape
   (write the BPF shim OUTSIDE `m.mu`, then ask the
   manager to build/send) is restructured so the
   sample/mint/build/send sequence serializes under
   `m.mu`; the direct key writes (maps_fabric.go:16-33)
   move inside the manager's wrapper; and the public
   legacy-adapter fabric methods (legacy_dataplane.go:346)
   are enumerated as pre-upgrade/test-only paths
   (production fabric writes route ONLY through the
   manager's wrapper).
   The debt itself keys on `(commit_revision,
   projection-identity)` as before (a telemetry update is
   the same identity — the debt is always found, AGY r15
   f7); the debt's RETRY re-sends the RECORDED
   `(map_generation, payload)` pair (v8.14, SMR r18
   SMR18-9 — a fresh sample mints a NEW generation and
   SUPERSEDES the debt, never a re-mint moving the
   target the helper never saw); a clean sync clears the entry ONLY when its
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
    re-Claim — and the absorption CUTOFF is pinned
    (v8.14, Codex r18 f12): absorption covers ONLY
    members DUE AT THE CLAIM (the Claim returns
    currently-due items only — a member whose link
    returns BETWEEN the Claim and the rebind is NOT
    absorbed (it was never claimed) and rides the debt's
    normal retry at its own current backoff);
    absorbed members' MAC programs happen
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
    debt's next attempt programs
    its MAC and rebinds — an exposure of THE MEMBER'S OWN
    CURRENT BACKOFF (v8.14, SMR r18 SMR18-8 = AGY r18 f7:
    a member with prior failures sits at the 60s floor —
    the v8.13 text's "(5s initial backoff)" was the best
    case, not the bound) +
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
    Codex r17 f8 = SMR r17 SMR17-9; the acquisition rule
    reconciled v8.14, Codex r18 f9): the work loop calls
    `PrepareLinkCycleChecked(claimToken) (outcome, error)` —
    ONE manager method that (i) acquires `m.mu` — BLOCKING
    while the batch holds `applySem` (v8.14's reconciliation:
    a blocking acquire is bounded by ONE legal `m.mu` owner
    hold (≤ ~67s worst — the 3s-typical status RPC or a
    large-snapshot tick), and the applySem transaction
    ALREADY prices RPC-length holds, so blocking never
    loses FIFO position (the v8.13 `RetryLater` release-
    and-requeue DID — repeated finite status-loop holds
    could fail every try-lock indefinitely, Codex r18 f9's
    starvation); the try-lock-or-skip rule survives ONLY
    for paths NOT holding `applySem` (ambient scheduler
    probes)); (ii) validates the token
    (bumped → `Stale`), and (iii) on `Valid` ISSUES the
    quiescence — ctrl-disable + `stop_workers` — UNDER THE
    SAME HOLD (each a small request at the 3s
    `controlBaseDeadline` (process_control.go:34-41), so the
    hold is bounded at ~6s, not the 67s class — the operator
    bump between validation and the first irreversible
    action is structurally excluded), then RELEASES `m.mu`
    before the MAC phase begins (Go's `sync.Mutex` is
    non-reentrant: the member-boundary checks take it again
    at each boundary). The verdicts:
    `Valid` (proceed), `RetryLater` (contended BEFORE
    `applySem` is held — the loop releases nothing, keeps
    the batch, retries next tick, NO unwind; after
    `applySem` the acquisitions are blocking, so this
    verdict cannot occur mid-transaction), and
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
    (v8.13, Codex r17 f9; placed v8.14, Codex r18 f10):
    `NotifyLinkCycle` gains a typed
    result (it is void today and swallows missing-process,
    ctrl, rebind, and status-application failures
    (process_linkcycle.go:184-224; even ctrl re-enable
    ignores errors (:102-116))) — a failed restore records
    a RESTORE DEBT — DAEMON-SIDE entirely (v8.14, Codex
    r18 f10's placement fix: state + scheduler + drain,
    the MAC debt's daemon-ownership shape; the v8.13 text's
    "manager-side, daemon-driven" was contradictory), with
    a pull-model API mirroring the MAC debt's
    (`RecordRestoreDebt(failure, context)` +
    `ClaimRestoreWork() (items, claimToken, nextWake)` +
    `ReportRestoreAttempt(claimToken, results)`, stale-
    token discarded), its own retry at
    5/10/30/60s with an edge Warn and NO terminal cap —
    the pending-activation retry's posture, since a
    stopped-worker recovery needs no state change), with
    explicit policies per failure mode: missing process →
    the respawn path FOLLOWED BY a daemon-owned REVISED
    FULL APPLY (the re-sync's applyConfigLocked shape,
    re-reading `ActivePair()` — and running the FULL
    machinery: a fresh `StartCompile(rethMACPending)`
    reservation carrying THE PRECHECK'S OWN RESULT
    (v8.15, Codex r19 f11's intent fix — the v8.14
    text's `StartCompile(false)` contradicted the
    universal rule (the reservation carries the
    precheck's `rethMACPending`): a replayed config
    whose RETH members need MAC work must open the defer
    epoch like any other apply, or the replay arms
    workers on stale MACs — and never the CLI's
    default-reservation path either); the drain
    ACQUIRES `applySem` (v8.15, Codex r19 f11's
    serialization fix — a legal userspace-bounded FIFO
    owner (minutes of sequential RPCs, terminating),
    and it calls the LOCKED apply directly
    (`applyConfigLocked`), NEVER the wrapper
    (`daemon_apply.go:49-86` re-acquires) — so the
    restore can never overlap a MAC batch or a commit;
    a respawned helper holds
    ZERO stored state, so rebinding an empty helper can
    never restore forwarding; the paired replay is the
    only correct restore); ctrl error → the restore
    debt's retry of the FULL `NotifyLinkCycle` SEQUENCE
    (v8.14, Codex r18 f10 — NEVER a bare ctrl map write:
    a safe enable occurs only after binding/map
    reconciliation in `applyHelperStatusLocked`
    (maps_sync.go:689/:809), so the retry re-runs
    rebind + status reconcile + ctrl enable; the ctrl=0
    window while it retries is a TOTAL fail-closed
    outage, Warn-visible and retry-forever — stated
    honestly, v8.14); rebind error → the RESTORE DEBT
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
    (v8.13, Codex r17 f11; corrected v8.14, Codex r18
    f14): helper teardown is NOT
    userspace-bounded — Rust worker stop performs
    blocking thread joins (worker_manager.rs:141) and
    `stopLocked` performs an unconditional `<-done` after
    `Kill()` (process.go:231-244), so a D-state or
    unreapable helper process has NO deadline while an
    apply owner holds `applySem` inside `stopLocked`. NO
    design bounds that class: abandoning the reap wait
    would let a respawn race the corpse's AF_XDP sockets
    (strictly worse), and the v8.13 "systemd outer bound"
    claim is WRONG (Codex r18 f14) — `TimeoutStopSec` +
    `Restart` cannot terminate an uninterruptible
    D-state task (SIGKILL does not reap it; the kernel
    wait itself blocks). The ONLY mitigation is the 60s
    Warn (visibility — it names the wedged owner so an
    operator can act on the host, up to and including a
    reboot — the one true bound, out-of-band).
    The guarantee is therefore: progress for every owner
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
    `claimToken` re-read are governed by the v8.14
    acquisition reconciliation (Codex r18 f9), with the
    cancellation model corrected to MEMBER-BOUNDARY
    granularity (v8.15, Codex r19 f10 — the v8.14
    MUTATION LEASE (re-read + syscall under one `m.mu`
    hold) is DELETED as cross-layer unimplementable
    (the manager owns `m.mu`; the daemon owns
    `programRethMAC` — no LinkController method can hold
    the former across the latter, and a callback under
    `m.mu` violates the no-synchronous-manager→daemon
    rule) AND per-syscall insufficient (a cancellation
    after DOWN but before MAC/UP would leave the member
    administratively down with its debt cancelled)):
    the token check runs at MEMBER BOUNDARIES ONLY
    (a cheap BLOCKING `m.mu` read between members —
    never across a syscall — INCLUDING before the FIRST
    member's program (v8.16, SMR r20 SMR20-4: the check
    runs right after the quiescence, so a cancellation
    landing between `Valid` and the first program is
    caught before any physical work), and an IN-FLIGHT member's
    DOWN→MAC→UP program ALWAYS COMPLETES once begun
    (the member transaction is the atomic unit — no
    half-cycled state can ever exist); an operator
    cancellation (the binding verb bumps the token,
    manager_status.go:157) takes effect at the NEXT
    member boundary (the cancelled member's debt
    entries are already gone — its just-completed
    program is WASTED, never contradictory: no operator
    MAC verb exists, and the standing claimed-slot
    rebind assurance (§7 invariant 8) owns the
    member's dataplane end state) — and the PHYSICAL
    quiescence is preserved against the operator's own
    reconcile (v8.16, Codex r20 f9's closure of the
    re-spawn-during-quiescence class: the operator's
    registration toggle drives a helper-side
    `reconcile_status_bindings` (binding.rs:29-47),
    which re-spawns workers WHILE the batch holds its
    quiescence — Go could then run the unlocked
    DOWN→MAC→UP on that member with live XSK/UMEM, the
    exact condition `PrepareLinkCycle` exists to
    prevent; the v8.15 member-boundary model claimed
    the class dead without closing it, so the manager's
    binding/queue verbs now REFUSE with a busy error
    while a quiescence is active (`m.linkCycleActive`,
    set by `PrepareLinkCycleChecked` on `Valid`) — with
    the gate's CLEAR points pinned (v8.17, AGY r21 f3 =
    SMR r21 SMR21-2: the gate HOLDS from the
    quiescence through the batch's program phase (or
    the batch's abandonment) and CLEARS at the
    transaction's restore completion (success OR
    failure — the restore is unconditional, and once
    it has run the current batch's transaction is
    over; the RESTORE DEBT's retries are POST-window
    and do NOT hold the gate (the v8.16 form locked
    the operator out for the whole retry-forever
    window during a persistent control-socket outage —
    a restore-debt retry re-quiesces when it runs,
    re-setting the gate for THAT attempt's window);
    the pre-existing mid-defer-window early-BIND hazard
    (§10's follow-up) shrinks to this same gate's
    coverage). And the failed-UP ownership is pinned
    (v8.16, Codex r20 f9's second half; hardened v8.17,
    Codex r21 f11's stale-discard fix:
    `programRethMAC` can fail its final UP, or return
    its best-effort UP failure after a MAC-set error
    (daemon_reth.go:257-270), and a cancellation racing
    that failure lets `ReportMACDebtAttempt` discard
    the stale-token results WHOLESALE — including the
    only observation that the member is down: the
    LINK-DOWN observation is therefore recorded through
    a CANCELLATION-INSENSITIVE path BEFORE token
    disposition (the work loop records each member's
    observed link state into `linkOnlyRecovery` as it
    goes — a stale Report can never un-record it —
    AND the recording SKIPS a member already removed
    from the desired set (v8.18, AGY r22 f5's
    deleted-member fix: the recording checks the
    desired membership at record time, so a
    cancellation-then-failure sequence can never leave
    a deleted member in `linkOnlyRecovery` attempting
    to bring UP an interface that no longer exists in
    the desired config; and the standing member-removal
    rule sweeps a removed member's entries in EVERY
    collection (macEpochDebt, macAndLinkRecovery,
    linkOnlyRecovery) as before) —
    and the MAC-debt disposition (validate/transfer)
    remains token-gated as before): an operator
    cancellation removes the MAC obligation but NEVER
    the member's LINK obligation: a member found DOWN
    at any validation (including the phase-failure
    path) records/keeps a `linkOnlyRecovery` entry
    INDEPENDENT of the MAC debt's cancellation, so the
    member's admin-UP recovery always has an owner
    (the standing bucket-iii rule, now explicitly
    cancellation-surviving). The batch's latency
    is honest: each member transaction is bounded
    driver time (link cycles can take 50-500ms on
    mlx5/i40e-class drivers, AGY r19 f6), the batch is
    bounded by membership, and NO `m.mu` is held across
    any syscall (the status loop and operator verbs
    wait only for the cheap boundary reads);
    while the batch HOLDS `applySem`, every `m.mu`
    acquisition is BLOCKING (bounded by one legal
    `m.mu` owner hold —
    the applySem transaction already prices RPC-length
    holds, and blocking never loses FIFO position the way
    the v8.13 try-lock `RetryLater` release did); the
    try-lock-or-skip rule survives ONLY for paths NOT
    holding `applySem` (ambient scheduler probes —
    v8.11, AGY r15 f6 = SMR r15 SMR15-4's original
    motivation, the 120s status-loop monopoly, which
    only ever applied to those paths);
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
  owner — AND it FIRES on the GO-LOCAL rule (v8.15, Codex
  r19 f7's ownerless-path fix; the qualifier corrected
  v8.16, SMR r20 SMR20-7 = AGY r20 f2's circular-deadlock
  catch; the discriminator added v8.17, SMR r21 SMR21-1 =
  AGY r21 f2's staged-window catch): the ACTIVE pair's revision
  exceeding the newest OBSERVED-ACCEPTED revision
  (`ActivePair().revision > m.acceptedCommitRevision`)
  AND **no live deferred-publish registration exists for
  the active pair** AND **the active revision is not
  RESTART-SUPPRESSED** (v8.19, SMR r23 SMR23-1 = AGY r23
  f1's loop fix: a guard-refused promotion never advances
  `m.acceptedCommitRevision` (the guard refuses BEFORE
  any Compile, so no acceptance is ever observed for R),
  so the unmodified rule re-fires the drain forever at
  the 60s backoff floor — an unbounded compile-and-refuse
  loop against a config that can never apply without a
  restart, for what is a NORMAL, expected state (every
  #5840/#6192 topology/identity peer sync puts the
  standby here BY DESIGN): the SHARED guard-refusal
  path records R into the revision-keyed
  `restartSuppressed` set (v8.20, SMR r24 SMR24-5's
  locus pin — ONE routine called by both the
  sync-receive guard (daemon_apply_commit.go:381-402)
  and the drain's guard, so the marker lands on the
  FIRST refusal and the drain never fires even once
  for R — the v8.19 drain-only recording wasted one
  compile-and-refuse drain cycle per restart-only
  sync) — a terminal "restart-required"
  marker, Warn-once with the guard's reason — and the
  re-sync debt CLEARS into that marker (terminal, NOT
  into acceptance — the v8.18 text's "defers to the
  operator restart exactly as the SyncApply path does"
  was false: the SyncApply path refuses ONCE per
  sync-receive; the drain has a retry loop, and only the
  marker stops it)); the rule never fires for a
  suppressed revision; a newer promotion R′ > R
  evaluates on its own merits (R′ ∉ the set until its
  own guard-refusal records it); the set is
  process-scoped (the boot path owns the post-restart
  apply — a restart clears it by construction) and
  bounded (one entry per guard-refused revision, GC'd
  when the active revision moves past)) — the v8.15 "with no apply in flight"
  qualifier was deleted as unnecessary AND deadlocking (a live
  compile holds `applySem`, and the drain acquires
  `applySem`, so the FIFO already serializes them; and
  the qualifier deadlocked the leak case: inFlight stuck
  true → the rule never fires → no newer StartCompile →
  the orphaned node is never OVERLAP-finalized →
  inFlight wedges forever, freezing the (v) latch echo),
  but the unqualified form fired DURING the pending-XSK
  STAGED window (B promoted and staged with
  `DeferWorkers=true` because the XSK cannot bind yet —
  `active(B) > accepted(A)` — and the drain's apply would
  publish B EARLY (AGY r21 f2's trace: the drain's apply
  calls `StartCompile(false)`, overwrites
  `m.deferWorkers=false`, and publishes B before the
  bind — EBUSY / socket bind errors and a polling retry
  loop with side-effect churn, defeating the defer); the
  staged window has a LIVE owner — the `OnXSKBound`
  registration for the pending pair (maps_sync.go:451-456's
  shape) — so the rule's discriminator is exactly that
  registration: while it lives, the staged leg owns the
  publish; a LEAKED registration (the staged leg died)
  has no live registration, so the rule fires and the
  drain's own StartCompile OVERLAP-finalizes any
  orphan it finds (the AGY r20 f2 closure survives
  intact), and the Compile's Finish `defer` is
  UNCONDITIONAL (a plain `defer` at Compile's top
  covering EVERY return path, with the exit-census
  canary test pinning it)) — the autonomous owner for EVERY
  abandoned or failed build (a commit whose dataplane leg
  was abandoned as pair-not-current, or whose Compile
  failed pre-publish: today's posture only promises an
  identical recommit/feed retry
  (daemon_apply_dataplane.go:146-158), so without this
  rule an abandoned build could wait forever for an
  unrelated event; the rule needs no helper input and
  fires on the next poll tick; a deterministic failure
  retries forever at the 60s floor with the fingerprint
  Warn while the commit's error is also surfaced — the
  standing persistent-failure posture). Both directions drive the same ACTIVE-CONFIG
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
  PREDECESSOR node's ID (note the capture semantics,
  which AGY r19 f3's trace misread: the newer node's
  captured prior IS the older node's CURRENT state at
  capture, INCLUDING its speculative intent — so the
  prior can never be replayed as an absolute value,
  Codex r19 f9's both-fail resurrection: base false,
  T1 intent true captures false, T2 intent false
  captures T1's speculative true, BOTH fail
  pre-publish, and replaying T2's captured true would
  resurrect a deferred epoch that never published);
  `FinishCompileReservation(token,
  outcome)` on a NON-HEAD token RECORDS the outcome on
  its node (never discarded); a Finish on the HEAD
  applies the recorded outcomes of ALL completed nodes
  IN CHAIN ORDER (oldest first), its own outcome LAST
  — with the outcome REDUCTION pinned (v8.15, Codex
  r19 f9): ACCEPTED /
  POST-ACCEPTANCE TAIL: `deferWorkers` := the node's own
  deferIntent; PRE-PUBLISH FAILURE: `deferWorkers` :=
  the NEWEST ACCEPTED PREDECESSOR's deferIntent in the
  chain (or, when no node was accepted, the value
  before the chain began — the chain root's capture) —
  NEVER the node's own captured prior (which may be a
  sibling's speculative state);
  PRE-SEND / UNKNOWN / OVERLAP:
  no flag change); and because the head is applied LAST,
  the newest outcome is always the terminal word —
  T1-ACCEPTED + T2-head-PRE-PUBLISH-FAILURE yields
  `deferWorkers` = T1's intent (the helper runs T1's
  deferred epoch — coherent); T1-PRE-PUBLISH-FAILURE +
  T2-head-ACCEPTED yields T2's intent;
  both-fail yields the chain-root value (nothing
  published, no epoch — the resurrection dies); and
  `m.compileInFlight` clears exactly when EVERY node in
  the chain has a terminal outcome — with the HEAD-POP
  rule making that reachable (v8.15, Codex r19 f9: a
  Finishing head POPS to the oldest unfinished node,
  so the last unfinished node's eventual Finish is
  ALWAYS a head Finish that fires the fold and clears
  the flag — the v8.14 form had no operation
  guaranteed to trigger the final fold; PENDING-XSK
  STAGED is an OPEN STATE, not a Finish outcome — the
  matrix covers the SIX Finish outcomes {ACCEPTED,
  PRE-PUBLISH FAILURE, UNKNOWN, PRE-SEND,
  POST-ACCEPTANCE TAIL, OVERLAP}, and §6 carries the
  full table).
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
  THE COMPILE'S OWN RESERVATION NODE'S deferIntent
  (v8.16, Codex r20 f7's wrong-intent-on-the-wire fix —
  the v8.14/v8.15 form stamped from the SHARED mutable
  `m.deferWorkers`, which an overlapping T2's
  StartCompile(false) can overwrite before T1's publish
  leg: the helper would then accept T1's config with
  `defer_workers=false` and start workers before T1's
  MAC work, and no later Go-side fold can undo that
  unsafe wire publication) — with the token TRANSPORTED
  as an explicit Compile argument (v8.17, Codex r21
  f8's association fix: the token returned from
  `StartCompile` could never reach Compile through a
  mutable head or a process-global value under the
  documented overlapping-Compile model — the
  reservation token becomes an explicit argument:
  `Manager.Compile(cfg, commitRevision,
  reservationToken)` (and
  `ConfigSink.ApplyConfig(ctx, cfg, commitRevision,
  reservationToken)`); the daemon passes the token its
  `StartCompile` returned; the assert-or-default paths
  (HA sync's apply path, background recompiles, tests,
  the direct CLI path) pass the DEFAULT token they
  created; and the wire stamp reads THE TOKEN'S NODE,
  never the shared global. The PENDING-XSK staged
  object carries BOTH the immutable token AND its
  already-resolved `DeferWorkers` value (baked in at
  staging from T1's node), and the OVERLAP finalization
  CANCELS the staged leg's registration (v8.18, SMR
  r22 SMR22-1 = AGY r22 f2's stale-staged-leg fix: a
  newer `StartCompile` finalizing an open staged
  predecessor as OVERLAP must also CANCEL the staged
  leg's `OnXSKBound` registration — the v8.13/v8.17
  form marked the reservation but left the registration
  live, so the leg could later fire with the staged
  object and overwrite the newer accepted config (the
  DUAL refusal saves only the strictly-older-revision
  case; a same-commit staged reshape would land);
  the deferred leg ALSO checks its token's liveness
  BEFORE publishing (an OVERLAP-finalized token is
  dead — the leg discards the staged object and
  skips) — AND the OVERLAP finalization CLEARS the
  staged snapshot reference ATOMICALLY with the
  cancellation (v8.19, SMR r23 SMR23-4 = AGY r23 f4's
  publisher-blindness fix: the ACTUAL publisher is
  `syncSnapshotLocked` (process_status.go:10-140) and
  its publish conditions (the nil guards, the
  already-published skip, the helper-ahead catch-up,
  the XSK-liveness defer + same-plan exception, the
  plan-change restart, the content-hash dedup) never
  consulted the registry — so a cancelled staged
  object still referenced by `m.lastSnapshot` (T2
  OVERLAP-finalized T1 and then failed BEFORE staging
  its own object) published anyway via the main
  path): under the same `m.mu` section the
  finalization marks the reservation OVERLAP, cancels
  the registration, AND drops `m.lastSnapshot`'s
  staged reference (the accepted config is durable in
  the store — the staged snapshot is only the
  manager's compiled cache; losing it costs a
  rebuild, never correctness — and the GO-LOCAL
  re-drive's full-apply retry rebuilds from the
  store) — and the re-drive's chain state is CLEAN
  (v8.21, SMR r25 SMR25-4: T1's node is
  OVERLAP-terminal and T2's Finish already folded the
  recorded outcomes oldest-first and cleared
  `compileInFlight`, so the re-drive's StartCompile
  begins a FRESH chain — no stale chain state
  carries, and the cleared staged reference means
  the rebuild mints from the store) —
  `m.lastSnapshot` NEVER references a
  cancelled staged object by construction (and the
  post-clear value is pinned (v8.20, SMR r24 SMR24-3
  = AGY r24 f3: the value is NIL — the staged object
  is the only reference; revert-to-published is
  impossible (staging OVERWRITES `m.lastSnapshot` and
  the manager retains no second reference — adding
  one is new state, rejected); EVERY auxiliary
  producer nil-guards under the same `m.mu`
  (syncSnapshotLocked process_status.go:11; overlay
  manager_overlay.go:129/:134; neighbor
  manager_neighbor.go:52/:84/:202/:259; HA
  manager_ha.go:159/:209/:524/:630; status
  manager_status.go:111; applied_nat_view.go:85) —
  the census is a build-time canary (a new producer
  without a nil-guard fails it); the cost is a
  TRANSIENT publish gap — the route overlay /
  scheduler / neighbor legs skip until the GO-LOCAL
  re-drive rebuilds (≤ the 60s backoff floor),
  stated); AND
  `syncSnapshotLocked`'s publish path gains the
  defense-in-depth token-liveness branch (belt-and-
  suspenders: a dead token → skip the publish, drop
  the staged reference, and let the GO-LOCAL
  re-drive own the re-apply) — and the
  registration's lifetime is bounded
  by exactly: `OnXSKBound` firing (with the liveness
  check), OVERLAP finalization (which cancels AND
  clears), helper
  death (the registration dies with the process), and
  an explicit STAGE TIMEOUT (v8.19, SMR r23 SMR23-5's
  mechanics pin: FIVE MINUTES — an XSK that has not
  bound in five minutes is not the transient
  channel-set change (which recovers in
  seconds-to-minutes); the owner is a scheduler entry
  recorded at staging and cancelled with the
  registration (every other lifetime path cancels
  it; the entry's fire and the registration's
  completion serialize under `m.mu` — the fire
  re-checks the registration's liveness under the
  same lock, so a bind completing at the boundary
  cancels the entry atomically (v8.20, SMR r24
  SMR24-7)); on expiry the registration dies and the
  GO-LOCAL re-drive's full-apply retry at backoff
  owns the re-attempt — not an indefinite stage; the
  POSTURE stated: for the whole stage AND the
  re-drive's retries the staged config's
  `DeferWorkers=true` keeps the dataplane DOWN, and
  for a never-recoverable XSK (the VF destroyed) that
  is indefinite BY CONFIG INTENT — the config
  committed a binding plan whose interfaces cannot
  bind; the dataplane stays down until the operator
  fixes the XSK or the config, Warn-visible at the
  stage/timeout/retry transitions (§8 carries the
  class)). The
  auxiliary clones: route/scheduler clones PRESERVE the
  cached snapshot's defer value (they are republishes
  of the cached content, not new intents); and the
  #5134 clone's forcible `DeferWorkers=false`
  (manager_worker_arm_5134.go:50-64) fires only when
  the debt OWNS completion for that exact staged
  generation (the debt's settlement proves it — the
  v8.13 "no reservation means default false" is
  unsafe for a clone of a deferred snapshot and is
  replaced by the cached-value rule).
  The v8.8 "intent
  as a Compile argument" text remains DELETED — as a
  DIFFERENT form (an untokened intent argument); the
  v8.17 token argument is the association that form
  lacked.
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
  second apply" is DELETED (the v8.12-v8.16
  interposition texts claimed an operator promotion
  could land mid-flow because it "needs no applySem" —
  FALSE under the v8.17 invariant (every promotion
  holds `applySem` across promote+apply), and the
  persistence transition's `s.mu`-only retry changes
  only durability, never the active pair — so no
  interposition of any kind exists to re-read for;
  a re-read would only ever find the SAME pair); the
  second leg never re-reads) — and the
  PROMOTION-SERIALIZATION INVARIANT is stated explicitly
  (v8.17, Codex r21 f3, VERIFIED; the edges completed
  v8.18, Codex r22 f2): EVERY pair-changing promotion is
  serialized WITH its apply DECISION under `applySem`
  — `commitAndApply` holds `applySem` across
  `configstore.Commit` AND the apply
  (daemon_apply_commit.go:129-175), and the HA sync
  (:326-355), commit-confirmed (:525-531), and
  auto-rollback (:629-697) paths are the same shape —
  WHERE the apply DECISION includes the deliberate
  skips: SyncApply's topology/identity guard
  (:381-402 — a restart-only config is promoted but
  deliberately NOT live-applied) and PromoteRollback's
  nil-target bootstrap teardown (:651-683) are
  serialized DECISIONS, not violations — and the
  GO-LOCAL drain's revised `applyConfigLocked` carries
  the SAME topology/identity guard (v8.18, Codex r22
  f2's bypass fix: a restart-only config is never
  live-applied by the re-sync) — and the SHARED
  guard-refusal path records the revision-keyed
  `restartSuppressed` marker (v8.19/v8.20, SMR r23
  SMR23-1 = AGY r23 f1 + SMR r24 SMR24-5's locus pin:
  ONE routine called by both the sync-receive guard
  and the drain's guard — the marker lands on the
  FIRST refusal); the v8.18 "defers to the operator
  restart exactly as the SyncApply path does" was
  FALSE — the SyncApply path refuses ONCE per
  sync-receive, but the drain is a retrying debt and
  a guard-refused promotion never advances
  `m.acceptedCommitRevision`, so the unmarked drain
  re-fires forever at the 60s floor; the marker makes
  the refusal terminal (Warn-once), clears the debt,
  and suppresses the GO-LOCAL rule for that revision
  (§5-C re-sync));
  the persistence retry advances only DURABILITY under
  `s.mu` (never a new active pair; the write is
  atomic (`writeTreeMarked`), so a drain's
  `ActivePair()` read observes before-or-after
  durability, never a torn pair); and the startup
  promotions (the boot-recovery promote inside `Load`
  (store_persist.go:171-228), the legacy migration,
  `bootstrapFromFile` (daemon_apply_commit.go:14-63))
  complete BEFORE the apply scheduler starts (startup
  serialization, v8.18's edge pin — INCLUDING the
  rollback executor's timer: it is armed only AFTER
  the boot apply completes, BY MECHANISM (v8.19, SMR
  r23 SMR23-2 = AGY r23 f2's mechanism pin — the v8.18
  text stated the arming as fact but named no
  mechanism, and the registration reality contradicts
  the unmodified code: the executor is registered
  before `Load` (daemon_run.go:130-136) and `Load`
  re-arms the recovered confirm window's timer
  UNCONDITIONALLY (`s.confirmTimer =
  time.AfterFunc(remaining, ...)`,
  store_persist.go:231-253), while the executor's
  `applySem` is FREE during the startup phases — so a
  recovered near-expiry timer could fire mid-startup
  between naming (daemon_run_naming.go:42-90) and
  manager construction/dataplane apply
  (daemon_run_bringup.go:161-208/:418-520),
  producing B-derived naming with A-derived
  managers/dataplane or a nil-manager panic): the
  chosen mechanism is the DEFERRED ARM — `Load`
  RECORDS the recovered window (the deadline, the
  rollback target trees, the confirm generation —
  everything store_persist.go:231-253 already
  restores) WITHOUT calling `time.AfterFunc`, and the
  daemon arms it via a new store method
  `ArmRecoveredConfirmTimer()` invoked AFTER the boot
  apply completes (phase 4,
  `setupDataplaneAndInitialConfig`, returns): an
  already-expired deadline fires IMMEDIATELY on that
  arm (`time.Until` ≤ 0 → `AfterFunc` runs at once),
  so the expiry is never dropped — it is ORDERED
  after the boot apply by construction and serialized
  by `applySem` like every other promotion+apply (the
  executor then promotes the rollback target and
  re-applies as an ordinary serialized DECISION); the
  executor registration stays at daemon init
  (daemon_run.go:130-136 — it covers every
  commit-confirmed path from the first commit, and no
  commit can exist before phase 1 completes, so the
  registration point is not the hazard — the ARM
  point was); the alternatives rejected: moving the
  registration post-phase-4 leaves `Load`'s re-arm
  executorless (a silent no-op expiry — the worst
  shape), and a boot-complete gate inside the
  executor defers the fire into daemon state the
  store cannot see (the store's confirm state would
  sit un-fired past its deadline with no record —
  the deferred arm keeps the pending expiry INSIDE
  the store, visible and exactly-once); and
  `PromoteRollback`'s own apply takes
  `applySem` like every other path)).
  Therefore NO promotion
  can interpose mid-flow: the pair read at a flow's
  start stays current for the whole flow; the v8.16
  flow-level re-reads and the second-leg abort rule
  addressed a state the locking already prevents (and
  the abort itself recreated the indefinite workerless
  outage for a gated successor (Codex r21 f4 = AGY
  r21 f1) — both are REVERTED: the second leg simply
  REUSES THE OUTER TRANSACTION'S ORIGINAL PAIR,
  always), and the residual pair-current concerns live
  ONLY in the manager-internal paths: the auxiliary
  producers CLONE the cached snapshot (their stamped
  revision is the cached snapshot's own — the
  staged-ahead divergence suppression (§5-C (iv))
  owns that class), and the direct CLI Compile is
  refused on any epoch-established box by the
  legacy-zero mode (it works only pre-epoch, where
  nothing exists to race). The manager-side
  pair-current leg at the send primitive remains as the
  belt-and-suspenders backstop for those manager-internal
  paths (below). The feed and
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
  config); completed v8.14 (Codex r18 f2/f3/f4 + SMR r18
  SMR18-1/6/7/10 + AGY r18 f6/f8).** (i) LOCUS,
  PAIR-SPECIFIC (v8.14, Codex r18 f4 — the v8.13/v8.14
  global-boolean form had a fatal counterexample: durable
  A's MAC-deferred apply spans two legs; nondurable B is
  promoted BETWEEN the legs (expressly allowed); A's
  mandatory second leg reuses pair A — but a global
  `PersistDegraded()` boolean sees B's degradation and
  skips A's second leg anyway, leaving the whole
  dataplane workerless until B lands (indefinitely on
  persistent storage failure)): the store tracks
  `durableRevision` (the last `writeTreeMarked`-landed
  revision, advanced only inside that write); a pair
  `(cfg, R)` is EXPOSABLE iff `R <= durableRevision` —
  A's second leg (R_a durable) is NEVER gated by B's
  pendency, and B's own apply (R_b > durableRevision)
  skips; the value advances in-memory only after
  `WriteFileDurable` returns success, ONLY active-pair
  writes advance it (never candidate/rollback trees),
  and `Load` re-derives it from the on-disk envelope
  (v8.15, Codex r19 f2's pins + SMR r19 SMR19-7 — a
  crash after the file lands but before the RAM
  assignment is conservative: exposure stays gated
  until restart reads the file, never an unsafe
  window). The check runs at `applyConfigLocked`'s ENTRY
  (v8.14, Codex r18 f4 — before that function's SNMP,
  web-management, bootstrap, naming, and kernel/VRF
  mutations (daemon_apply.go:127/:167/:200/:246), the
  RETH precheck/defer setter, the scheduler seed, the
  route-overlay cache, the feed reconciliation
  (daemon_apply_dataplane.go:44-141), the dataplane
  call (:137), AND FRR (`applyRoutingRules`,
  daemon_apply.go:314-335) — v8.15, Codex r19 f2: the
  v8.14 "FRR follows the commit" text was
  self-contradictory, because FRR is INSIDE the gated
  function, so an ENTRY gate necessarily defers it; the
  choice is FULL GATING of the FORWARDING plane — the
  dataplane leg, FRR, routing, and fabric defer to the
  drain, which re-runs the full `applyConfigLocked`
  when the pair lands) — with the SECURITY-CLOSEOUT
  exception (v8.16, Codex r20 f2: full gating as v8.15
  wrote it ALSO defers the management-authorization
  mutations (SNMP communities, web credentials, host
  authorization — daemon_apply.go:167-213/:293-307),
  which are MONOTONIC-REVOCATION obligations: during a
  permanent storage failure a committed tightening
  would leave old communities/credentials live FOREVER
  (source performs these revocations early precisely
  because leaving permissive host authorization after
  promotion is a revocation violation): the
  management-auth closeout FOLLOWS the commit even
  under the gate — re-scoped to PROVEN MONOTONIC
  TIGHTENING ONLY (v8.17, Codex r21 f2's partition
  fix, completed v8.18 per Codex r22 f4:
  the v8.16 closeout set was neither directionally
  safe nor a coherent partition — SNMP is not merely
  revocation (starts/stops UDP/161, adds
  users/communities/trap targets (daemon_apply.go:167-198)),
  web-management does listener bind/TLS/auth
  replacement (:200-213), and the RELAXING direction
  (adding an RW community/API credential/root key,
  expanding an HTTP listener, adding a host-inbound
  permit) would grant B's access while A remains the
  exposed state — "merely early" is not an acceptable
  security invariant. The closeout therefore applies
  ONLY B's REMOVALS — access present in A's
  LAST-EXPOSED config and absent in B's desired config
  (v8.18, Codex r22 f4's A-live fix: "A-live" is the
  last EXPOSED configuration (beginFirstExposure's
  prior), never the store-active predecessor (which
  can be gated-and-unexposed)) — computed as a
  TARGETED removal projection per class (v8.18, Codex
  r22 f4's whole-config fix: the existing owners
  accept WHOLE desired configs (SNMP replaces all
  authorization (daemon_snmp_reconcile.go:375-423),
  web reconciliation consumes a complete desired API
  config (management.go:189-249), host-auth passes
  one whole config (daemon_apply_hostauth.go:53-79)),
  so a set-difference narration cannot drive them —
  the closeout synthesizes a REMOVAL-ONLY desired
  projection (the union of A-live and B-desired
  reachability MINUS B's removals, so a removal can
  never exceed what B actually removes and never
  touch what B keeps) and applies it through
  class-targeted removal operations (SNMP
  community/user/trap-target removal, web endpoint
  auth removal for the REMOVED endpoint (and web
  binds resolve CURRENT kernel addresses
  (daemon_run_servers.go:507-539) — the closeout's
  web leg reads A's live interface set, never B's
  deferred one), host-inbound rule removal against
  A's LIVE interface set only (daemon_nft.go:419-462 —
  a B-derived closeout could delete A's protection
  for an interface B removes or moves); MIXED changes
  (remove A's listener AND add B's listener, or
  retain a credential on only one endpoint) DEFER
  wholesale to the exposure — the tightening-only
  form applies only to pure-removal deltas) —
  while ADDITIONS, listener expansions, and
  relaxations DEFER with the dataplane leg (they
  authorize access, and authorizing B's access before
  B is exposed is the violation); and the closeout's
  own failure records a PERSISTENT CLOSEOUT DEBT
  (v8.17/v8.18, Codex r21 f2 + r22 f4's owner fix — SNMP/web
  currently retry only on a later commit
  (daemon_snmp_reconcile.go:394-410,
  daemon_apply.go:210-213), and the host-auth closeout
  may time out and abandon an owner
  (daemon_apply_hostauth.go:34-79/:158-186): the debt
  keys on the closeout PAIR with a captured removal
  projection, rides the daemon's apply scheduler with
  the standing
  backoff + edge Warn, and RECOMPUTES from actual
  live authorization to the LATEST desired state on
  each retry (v8.18, Codex r22 f4's supersession fix —
  a stale B debt can never remove something C keeps
  (the recomputation supersedes it), and discarding B
  blindly can never lose a still-required revocation
  (the recomputation re-derives it)); the failure
  TRANSITION (v8.18, Codex r22 f4): a closeout
  failure does NOT prevent B's exposure (B's
  dataplane exposure is independent — the alternative
  (gating exposure on the closeout) would add another
  unbounded whole-forwarding-plane gate, rejected);
  B runs with the closeout PENDING (Warn-visible, the
  debt retrying) — and the operator-session strand is
  the intended monotonic-revocation consequence (B
  may revoke the channel used to submit it: the
  commit already landed control-plane, the synchronous
  note may not reach the operator on that channel
  (acceptable), and the out-of-band recovery channel
  (console / another credential) is the operator's
  documented escape);
  the closeout never consults deferred state (no
  `ApplyResult.ManagedInterfaces` (exists only after
  the dataplane leg))) — with the flow
  ORDER pinned (v8.17, AGY r21 f4: the closeout set
  (SNMP (daemon_apply.go:167), web-management (:200),
  host-auth) runs FIRST, THEN the gate check, THEN the
  forwarding-plane mutations — because line 192's
  bootstrap exit (interface renaming, IP forwarding
  enablement, dataplane arming) is FORWARDING-plane
  and sits BETWEEN the management-auth mutations in
  the current order, so a gate at the very entry would
  skip the closeout (violating it) and a gate after
  :200 would run the bootstrap exit (violating the
  gate); the web-management reconciliation moves AHEAD
  of the bootstrap exit (it is management-plane and
  independent of interface state) so the closeout set
  is contiguous before the gate); the deferred set is
  exactly {the dataplane leg, FRR, routing, fabric,
  the bootstrap-exit/host/VRF mutations, networkd,
  services, AND the closeout's additions/relaxations}
  (v8.18 — networkd and services are DEFERRED here,
  reconciling the v8.17 text's other passage that
  classified them as FOLLOW (Codex r22 f4's
  contradiction catch: they consume
  `ApplyResult.ManagedInterfaces` (exists only after
  the dataplane leg, daemon_apply_dataplane.go:137-165/
  :218-245), so they cannot run under the gate);
  and with FRR gated, the RIB never moves during the
  window, the overlay publishes A's routes in A's
  clone, and the v8.14 `m.exposureGateActive`
  suppression flag and its A-config/B-FIB hybrid (SMR
  r18 SMR18-1), its flag-lifetime problem (AGY r19 f2 =
  SMR r19 SMR19-3(iii)), AND its stale-authorization
  fail-open for scheduler closes (Codex r19 f3 — a
  suppressed close leaves the old permit live,
  manager_compile.go:575-610) ALL DIE AT THE ROOT:
  there is nothing to suppress because the RIB never
  diverges, and the scheduler's A-derived publishes
  flow normally throughout the window);
  the commit reports SUCCESS WITH a "dataplane exposure
  pending-durable" note delivered SYNCHRONOUSLY on the
  commit's own result surface via a RESPONSE COPY
  (v8.15, Codex r19 f5's aliasing fix — the note is
  appended to a COPY of the warnings for the commit
  RESULT, NEVER to `compiled.Warnings` itself: the
  store retains the same pointer (`s.compiled =
  compiled`, store_commit.go:224-324), so appending
  there would mutate the active in-memory state and
  let later applies re-log the supposedly
  nonpersistent note after recovery), 
  plus an edge Warn plus the exposure debt's presence in
  `show` — never the silent
  divergence the v8.12 form would have introduced.
  (ii) TYPED OUTCOME (v8.14, Codex r18 f3; the deferred
  set completed v8.15 per Codex r19 f5): the gated
  apply returns `ApplyOutcome{Ran, Exposed,
  ExposurePending}` (NOT nil-success, NOT error) — and
  every wrapper's success tails gate on `Exposed`, with
  the deferred set NAMED (v8.15, SMR r19 SMR19-5):
  DEFER = {the dataplane-adjacent success markers
  (`MarkActiveApplied` (daemon_apply.go:49), the
  session clear and the peer push and the applied stamp
  (daemon_apply_commit.go:245), `armedActive=true` and
  the peer sync's success tail (:479), the CF-health
  clear and the `lastAppliedConfigGen` advance
  (sync_conn_config.go:350/:385 — which control manual
  failover readiness (sync.go:231, sync_bulk.go:235) and
  stale-session refusal (sync_conn_gen.go:398), so a
  standby still enforcing A can NEVER report B applied,
  transfer-ready, or healthy)} — and the
  commit-confirmed AUTO-ROLLBACK wrapper joins the same
  census (v8.15, Codex r19 f5: it calls
  `applyConfigLocked` and then unconditionally
  invalidates sessions and pushes the rollback
  (daemon_apply_commit.go:629-723) — those actions gate
  on `Exposed` identically); networkd and services are
  DEFERRED with the dataplane leg (v8.18, Codex r22
  f4's contradiction fix — they consume
  `ApplyResult.ManagedInterfaces` (exists only after
  the dataplane leg), so they cannot run under the
  gate (the v8.15/v8.17 "FOLLOW" classification is
  corrected); FRR is NOT in this
  set — it lives INSIDE the gated
  `applyConfigLocked` (the (i) full-gating choice),
  so it defers with the dataplane leg). The deferred session
  clear means sessions valid under A KEEP FLOWING while
  B waits (correct — A is still enforced), and B's
  session-relevant changes take effect at exposure —
  and the debt retains the LAST EXPOSED configuration
  (v8.15, Codex r19 f5's A→B→C fix: a latest-wins debt
  keyed only on the newest gated pair would lose A→B
  invalidation (A exposed → gated B tightens → gated C
  promoted → C's exposure invalidates B→C only,
  leaving an A-authorized session alive;
  daemon_apply_commit.go:256-269 classifies partial
  local invalidation as a stale-authorization gap and
  :405-416 omitted peer invalidation as a permanent
  security fail-open): the debt records the
  last-exposed pair at recording time, and the drain's
  session invalidation composes LAST-EXPOSED →
  CURRENT (A→C, covering A→B→C), never only the
  newest delta; the record itself,
  `m.lastExposedPair`, is replaced by the ATOMIC
  `beginFirstExposure(B) -> {priorPair, firstExposure,
  ledgerID}` transition (v8.17, Codex r21 f6's
  too-early-advance fix: advancing last-exposed at the
  observed-acceptance points (inside Compile, before
  the wrapper's invalidation runs
  (manager_compile.go:350-365 vs
  daemon_apply_commit.go:245-270)) would change A→B
  into B→B even in the no-gate common case — the
  invalidation would compose against the NEW pair and
  delete nothing): `beginFirstExposure(B)` runs
  MANAGER-SIDE at acceptance, in the SAME `m.mu`
  section that advances `m.acceptedCommitRevision`
  (v8.18, SMR r22 SMR22-2's locus pin — the prior is
  always the pre-advance value), and returns the
  IMMUTABLE PRIOR
  pair (A) plus a ledger ID — TRANSPORTED on the
  `ApplyResult` (v8.18, SMR r22 SMR22-2 = AGY r22
  f3's transport fix: `ApplyResult` gains
  `{priorPair, ledgerID, firstExposure}` — the
  daemon wrapper receives the captured values from
  Compile's atomic acceptance across the package
  boundary, never a post-hoc read after `m.mu` is
  released); the wrapper carries THAT
  prior through the whole completion (the session
  invalidation composes prior → B, always — the
  uniform base (every commit/drain/re-sync/restore)
  with no read-after-advance tear) — and the wrapper's
  `oldActive` parameter is REPLACED by the prior ON
  THE INVALIDATION PATH (v8.18, SMR r22 SMR22-2's
  single-source pin: under the promotion-serialization
  invariant they agree in the no-gate case
  (`oldActive == last-exposed`), and they differ
  EXACTLY post-gate (B promoted and gated, C committed
  direct-durable: `oldActive` is B (store-active), the
  prior is A (last-exposed) — the prior is the correct
  base, and the wrapper's `oldActive` would reopen
  Codex r20 f5's direct-C case if it ever won); the
  STATUS-LOOP CATCH-UP acceptance leg gains its own
  completion-tail owner (v8.19, SMR r23 SMR23-3 = AGY
  r23 f3's transport fix for the second acceptance
  leg: the `syncSnapshotLocked` catch-up (the ACTUAL
  publisher, process_status.go:10-140) accepts
  asynchronously inside the manager's background
  status loop — no `ApplyConfig` frame, no
  `ApplyResult`, no daemon wrapper — so the
  `ApplyResult` transport can never serve it): the
  catch-up's `beginFirstExposure` runs in the same
  manager-side `m.mu` acceptance section, installs
  the cursor atomically exactly as the Compile leg
  does, AND posts a COMPLETION NOTICE on the bounded
  daemon channel (enqueue-after-unlock — no
  synchronous manager→daemon call under `m.mu`; the
  `OnXSKBound` shape, maps_sync.go:451-456); the
  daemon's scheduler drains the notice and runs the
  phased tails (the session invalidation composing
  prior → B, the peer push, the applied stamp) with
  the cursor's `completionState` as the SINGLE
  exactly-once authority — a tail runs once
  regardless of whether the Compile-leg wrapper or
  the listener observes it first (the wrapper's
  ApplyResult path and the notice path both consult
  and advance the same cursor record; a completed
  entry's tails are skipped) — AND with the
  PAIR-CURRENCY gate (v8.20, SMR r24 SMR24-1 = AGY
  r24 f1's stale-notice fix: a newer commit C can
  promote and apply while B's notice sits queued —
  an un-gated drain would compose A→B over C-permitted
  sessions and overwrite C's stamp; and the
  abort-only fix LEAKS (C's own tails compose B→C,
  which never covers A-permitted/B-revoked/C-revoked
  sessions)): the notice drain ACQUIRES `applySem`
  (serializing against every promotion+apply),
  re-reads the CURRENT pair at drain time, and (i)
  the session invalidation composes prior → the
  drain-time EXPOSED pair (`m.lastExposedPair` under
  `m.mu` — v8.22, SMR r26 SMR26-2 = AGY r26 f2's
  gated-successor fix: "CURRENT" for the
  invalidation is the EXPOSED pair at drain time,
  NOT the store-active pair — a promoted-but-GATED
  successor C (`R_c > durableRevision`) leaves the
  dataplane enforcing B, and composing A→C would
  delete B-authorized sessions while C is
  unenforced (the exposure gate's invariant: an
  unexposed config never alters session posture);
  the rule covers both shapes — C exposed ⇒ A→C
  (A→C covers A\B\C-revoked
  exactly, keeps A\B∩C-permitted, and C's own B→C
  covers B\C: the union is complete with no
  over-deletion), C gated ⇒ A→B (exactly the
  sessions the ENFORCED config revokes; C's own
  exposure tails compose B→C later)), (ii)
  the applied stamp and the peer
  push are CURRENCY-GATED on EXPOSED currency
  (v8.29, AGY r33 f1's gated-successor fix, RE-KEYED
  from the v8.20/v8.22 STORE currency: the gate is
  `notice.pair == m.lastExposedPair` — the SMR24-1
  over-stamp case (a newer pair EXPOSED ⇒ the
  notice's pair is no longer the exposed pair ⇒
  skip) stays killed, and the GATED-successor case
  (C2 store-active but UNEXPOSED — its own push
  HELD by the exposure check) leaves C1 STILL the
  exposed pair ⇒ C1's stamp and push FIRE normally
  and C1's entry completes normally (the v8.20
  store-currency form starved the LIVE exposed
  pair for the whole gated window — the peer and
  `appliedRevision` stuck at A while the primary
  ran C1, an indefinite silent divergence); the
  SUPERSEDED marking keys on the same EXPOSED
  currency), and (iii) a superseded notice's
  cursor entry is marked SUPERSEDED (terminal,
  never left pending) — where SUPERSEDED marks ONLY
  the pair-specific tails (the stamp and the push)
  as skipped-by-design, and the invalidation (i)
  composes prior → the drain-time EXPOSED pair and
  RUNS for stale
  notices exactly as for current ones (v8.21, SMR
  r25 SMR25-1 = AGY r25 f2's wording fix — the
  v8.20 parenthetical "the composition is covered
  by the newer pair's chain" was FALSE on its face
  (it is exactly the abort-only leak SMR24-1
  traced: C's B→C chain never covers
  A-permitted/B-revoked/C-revoked sessions) and
  contradicted (i); a skip-everything reading
  reintroduces the leak); the cursor's check-and-advance
  is atomic by construction (v8.20, SMR r24 SMR24-2 =
  AGY r24 f2: the cursor record lives manager-side
  and EVERY `{phaseCursor, completionState}`
  read-modify-write goes through ONE manager method
  under `m.mu` — the daemon wrapper's phase
  completions call it across the package boundary,
  the listener likewise; the transports are
  per-acceptance unique (a Compile-leg acceptance
  yields an `ApplyResult`, a catch-up acceptance
  yields a notice — never both for one acceptance),
  so the residual race is phase-level and the `m.mu`
  advancement covers it) — as the claim-or-skip
  TRI-STATE (v8.24, SMR r28 SMR28-1: per phase,
  pending → claimed → complete, with the CLAIM
  atomic under `m.mu` and a duplicate claimant
  skipping (the v8.20 "check-and-advance" was
  ambiguous between claim-or-skip and
  check-then-execute-then-advance — and only the
  first is exactly-once: two concurrent drains (the
  notice-triggered AND the scheduler-iterated, which
  also picks up a Compile-leg entry concurrently
  with its synchronous wrapper) would otherwise
  both observe a phase pending and both execute it;
  with the claim, the first claimant executes and
  the duplicate skips; a claimed-but-crashed drain
  is the in-memory-loss case the crash rule
  re-derives) — with the claim's own lifetime
  bounded (v8.25, AGY r29 f1's un-leased-claimed
  fix: the "crashed drain" phrase covered only
  PROCESS crashes — a goroutine PANIC (the process
  lives) would pin the phase `claimed` forever
  (skipped by every claimant, never terminal, never
  GC'd, no boot recovery): (i) a `defer` wrapper
  around EVERY phase execution catches panics and
  atomically reverts claimed → pending WITH
  `nextAttempt` under `m.mu` (the revert rides the
  SAME uniform missing-entry → already-terminal
  contract — a no-op on an entry a concurrent pass
  GC'd (v8.26, SMR r30 SMR30-2 = AGY r30 f4 —
  the panic-safe path never dereferences a missing
  key either)), and (ii) the claim
  records `claimedAt` + a claim GENERATION and is
  STEALABLE after the named bound (the tail
  operations' own timeout sum — the peer push's
  connection write path (handleDisconnect on
  error), the stamp's synchronous store return, the
  invalidation's local kernel calls) — the stealer
  runs with a bumped generation and the stale
  claimant's late advance is REFUSED (the
  generation check under `m.mu`) — AND the steal
  is FENCED and BOUNDED (v8.26, AGY r30 f1/f2: the
  v8.25 guard refused only the stale claimant's
  completion RECORD while its tail EXECUTION
  mutated the world un-fenced (a late
  `MarkActiveApplied(B)` regressing
  `appliedRevision` after C stamped C; a late
  invalidation deleting C-authorized sessions),
  and the fixed-interval steal spawned an
  unbounded goroutine per namedBound on a hanging
  phase): (a) the drain's claim checks LIVENESS AT
  ENTRY (a stolen/dead claim aborts the drain
  BEFORE any side effect — the missing/stolen-
  entry contract, in the same `m.mu` operation as
  the claim); (b) the applied stamp is the
  CAPTURED-DIGEST stamp (v8.30, SMR r34 SMR34-1 =
  AGY r34 f1's form fix, RETRACTING the v8.26
  "CAS form (expected store-current revision)" —
  verified against the actual machinery
  (store.go:787-853: digest-based, NO revision
  CAS — `MarkActiveApplied()` stamps
  `configTextDigest(s.active)` (the CURRENT active
  tree — in the gated-successor window the
  NEVER-APPLIED successor, the r30 f1 / #6296
  class) and `MarkAppliedDigest(digest)` stamps a
  captured digest UNCONDITIONALLY; an
  active-keyed CAS would REFUSE the very stamp
  the v8.29 exposed-currency gate admits, and a
  CAS-free overwrite would let a late stale stamp
  regress the marker): the stamp is
  `MarkAppliedDigest(pair.capturedDigest)` — the
  pair's OWN digest, captured at acceptance/apply
  time under the apply serialization (the #6296
  TOCTOU-safe form) — NEVER `MarkActiveApplied()`;
  and the anti-stale protection is the v8.29
  EXPOSED-currency ADMISSION gate (a stale
  notice's stamp is SKIPPED before any stamp
  call — the read-side `ActiveApplied()` digest
  comparison is the only "CAS" the machinery
  needs); (c) the drain's `applySem` hold
  + the drain-time-EXPOSED composition order every
  mid-drain case (no exposure can move while the
  drain holds the semaphore; a live-claimed drain
  composes correctly at entry); and the steal
  itself (d) CANCELS the stale claimant's context
  (every tail operation takes the claim's ctx and
  aborts on cancellation — a kernel-wedged residue
  is the budgeted D-state class, out-of-band — and
  the ctx scope is precise (v8.27, SMR r31 SMR31-2
  = AGY r31 f2: cancellation bounds the I/O tails
  (the conn write's TCP timeout +
  `handleDisconnect`; socket operations); the
  in-memory store mutations (`setAppliedDigest`
  takes no ctx) rely on the CAS revision
  verification — either order safe, and the
  cancellation bounds the goroutine's remaining
  life to one operation, not to the next tick)),
  (e) ADVANCES the entry's ladder (a steal is a
  failure by construction — the steal cadence
  decays to the 60s floor, never a fixed spin),
  and (f) is a REPLACEMENT (exactly one live claim
  generation per entry — a second steal is refused
  while a live one stands) — and the MID-DRAIN
  steal's full trace is stated (v8.27, SMR r31
  SMR31-1 = AGY r31 f1/f3: the steal needs only
  `m.mu` to fire, so it can land while the stale
  drain executes its tails under `applySem` (no
  `m.mu` held mid-tails): (i) the invalidation was
  composed AT ENTRY against the drain-time EXPOSED
  pair, and no exposure can move while the drain
  holds `applySem` — the composition stays correct
  after the claim dies; (ii) the stamp's CAS
  passes (the store cannot move under `applySem`
  either) — the stale stamp LANDS and is CORRECT
  (the pair is store-active; the stamp marks it
  applied), while the phase's completion RECORD
  is refused by the generation guard — so the
  stealer RE-EXECUTES the phase, and the
  re-execution's side effects are the idempotent
  forms (a second identical stamp CAS on the same
  value (or skipped via store-currency gating when
  the pair is no longer store-active (v8.28, AGY
  r32 f2)); a second identical push — the receiver's
  `SyncApply` no-ops on identical content
  (daemon_apply_commit.go:356-360); the
  invalidation's deletes idempotent) — and the
  stealer's composition is its OWN (v8.28, SMR
  r32 SMR32-1 = AGY r32 f1's C2-gap note: the
  stealer acquires `applySem` AFTER the stale
  drain releases it, and an intervening exposure
  C2 can land in the gap — the stealer does NOT
  re-run the stale drain's composition; it runs
  its OWN against the exposed pair at ITS OWN
  entry, and the union is exactly right: the
  stale drain's A→C deletes (composed at ITS
  entry), C2's own wrapper's C→C2 (its own
  tails), and the stealer's A→C2 delete exactly
  (A∪C)\(C∩C2) with survivors exactly (A∪C)∩C∩C2
  (v8.29, AGY r33 f2's formula fix: the v8.28
  "(A∪C)\C2 with every C2-permitted session
  surviving" was FALSE for re-permitted sessions —
  a session A-permitted, C-revoked,
  C2-re-permitted was deleted at C's exposure
  (correctly, at that time) and never recreated:
  intermediate revocations are PERMANENT (the
  intended semantics — the final config re-permits
  via re-handshake, never resurrection); and the
  safety-critical direction STANDS (SMR33-1 (ii)'s
  subsumption: the stealer's own delete set A\C2 ⊆
  (A\C) ∪ (C\C2), so the stealer provably cannot
  over-delete beyond the already-correct union);
  and the rule generalizes (SMR33-1 (i) = AGY r33
  f3: N successive gaps leave the stealer
  composing A→C_k and the union exactly
  (A∪C_1∪…∪C_{k-1})\(C_1∩…∩C_k) — the
  drain-time-EXPOSED-at-each-entry rule, not a new
  case); and the two cursor entries are
  independent (each composes against the shared
  `m.lastExposedPair` at its own entry; the
  claim-or-skip serializes only within an entry);
  and a drain that finishes BEFORE the namedBound
  records complete normally — the steal-timer is
  cancelled by the completion, same `m.mu` op
  (SMR32-2)); and (iii)
  the steal-spawned goroutine population is
  bounded (SMR31-3: cancellation reaps each
  goroutine within one operation of its
  cancellation; the residue is the kernel-wedged
  budgeted D-state class only))); and the notice is an
  OPTIMIZATION over a sweep (v8.20, SMR r24 SMR24-4 =
  AGY r24 f4: the enqueue-after-unlock is
  non-blocking — a full buffer drops the notice, so
  the daemon's apply scheduler runs a periodic
  pending-cursor sweep (the cursor registry is
  queryable daemon-side) and
  the enqueue failure records a Warn edge — a dropped
  notice delays the tails to the sweep interval,
  never loses them; the sweep's pins (v8.21, SMR r25
  SMR25-2 = AGY r25 f3: the sweep rides the 1s
  status-application pass — after each helper-status
  application the daemon scans the pending-cursor set
  (no new timer; a dropped notice delays the tails
  ≤ 1s + drain scheduling) — and the pass NEVER
  blocks on `applySem` (v8.22, SMR r26 SMR26-1 = AGY
  r26 f1's freeze fix: the 1s pass only SCANS and
  MARKS pending entries (under `m.mu`, non-blocking)
  and DISPATCHES the per-entry drain execution to
  the daemon's apply scheduler — the same scheduler
  thread the notice drain rides, where the blocking
  `applySem` acquire is safe; the v8.21 "ONE
  routine, two triggers" wording let the status
  thread itself execute the blocking acquire,
  freezable for minutes behind a long control apply
  (stalling status ingestion, fabric tracking, and
  heartbeat) — the "one routine" now lives ONLY on
  the scheduler thread, with the notice and the
  sweep-dispatch as its two triggers, and the status
  thread never takes `applySem`) — and the
  "dispatch" is NOT a channel (v8.23, SMR r27
  SMR27-1 = AGY r27 f2/f3's mechanism pin: the
  scheduler's per-tick pass ITERATES THE PENDING
  CURSOR SET directly — the notice remains the
  fast-path optimization and the pending set IS the
  correctness path: no dispatched-flag, no queue,
  no drop policy, and no stuck state (a bounded
  queue that drops would strand a marked-dispatched
  entry forever — never pending again, never
  terminal; an unbounded queue is an OOM vector);
  an entry is pending until terminal, and the
  scheduler drains the pending set through the ONE
  drain routine every tick — the sweep's mark is
  advisory-only and the cursor's `m.mu`
  check-and-advance is the only exactly-once
  authority; a drain that FAILS mid-tails leaves
  the entry pending and the retry rides a per-entry
  `nextAttempt` on the standing 5/10/20/60s
  exponent-preserving ladder (v8.24, SMR r28
  SMR28-2 = AGY r28 f1: the per-tick pass SKIPS
  not-yet-due entries — the iterate model
  re-invoking the drain every 1s on a failing entry
  was a tight 1Hz retry loop against the plan's own
  standing posture — and the failure Warns on the
  standing edge-detect) — with the release
  composed atomically (v8.25, SMR r29 SMR29-1 =
  AGY r29 f2: the claimed → pending release-on-
  failure and the `nextAttempt` set are ONE `m.mu`
  operation (a split release lets a racing iterate
  tick re-claim immediately and the 1Hz loop
  returns via the claim path), and the claim itself
  refuses entries whose `nextAttempt` is in the
  future (the due-check lives in the claim — the
  notice-triggered drain respects it too, never
  accelerating a backed-off entry)) and the ladder
  per-ENTRY with AGY's reset form (v8.25, AGY r29
  f3, superseding SMR29-3's terminal-only form: a
  SUCCESSFUL phase resets the entry's ladder to the
  base step for the remaining phases — each phase's
  failure is operation-specific, matching the
  standing debt behavior; a FAILED phase advances
  the ladder); and the drain's cursor
  lookup treats a
  MISSING entry as already-terminal (v8.23, SMR r27
  SMR27-2 = AGY r27 f1/f4; scope made uniform
  v8.24, AGY r28 f2/f3: the contract applies to
  EVERY registry accessor — the scheduler/notice
  drains AND the synchronous `ApplyResult` wrapper
  (the iterate drain picks up a Compile-leg entry
  concurrently with its wrapper, so the wrapper's
  accessor can hit a GC'd key too)): a drain dequeued for an
  entry a concurrent sweep already observed terminal
  and GC'd finds the key GONE — a safe no-op (the
  entry's work completed or was covered by the newer
  pair's chain; the crash rule never depends on a
  GC'd entry), never a nil dereference or an
  unhandled error)); and a terminal
  cursor entry (completed or SUPERSEDED) is GC'd on
  the sweep pass that first observes it terminal
  (v8.22, SMR r26 SMR26-4: the registry's live set
  is bounded by concurrently-incomplete exposures —
  a handful — so the 1s scan is O(handful) for the
  daemon's lifetime; the crash rule never reads a
  GC'd entry — it re-derives from the sidecar +
  store))); the helper-restart
  shape's no-op tails are NAMED (a fresh helper holds
  no sessions — the invalidation is a no-op on the
  empty base — but the peer push and the applied
  stamp are NOT no-ops: HA still needs both, and the
  listener runs them); the boot
  unknown-base policy (Codex r21 f6's second half):
  a genuinely cold helper has no sessions (empty base,
  no-op — safe), but a manager/daemon RESTART over a
  surviving A helper with disk-active B leaves the
  base UNKNOWN (the invalidators no-op on a nil old
  config (daemon_policy_invalidate.go:60-65/:193-195),
  so EMPTY→B would leave A-authorized sessions alive):
  the exposed base is PERSISTED with the store's
  active pair (the `appliedRevision` sidecar records
  the exposed revision), and when the base cannot be
  proven (no sidecar), the first apply after startup
  CONSERVATIVELY CLEARS all sessions (fail-closed
  visibility over a silent stale-authorization gap);
  the session invalidation's
  base is ALWAYS that immutable prior, on EVERY commit
  (v8.16, Codex r20 f5's uniform fix: the invalidation
  today composes from the wrapper's captured
  `oldActive` (the STORE's previous active), so a
  direct-durable C after a gated B invalidates B→C
  (B was store-active) and leaves an A-authorized
  session alive; composing from last-EXPOSED instead
  (A→C) covers it uniformly — every commit, drain,
  re-sync, and restore composes
  prior → new-pair); the peer-push phase's
  observability is pinned (Codex r20 f5: `QueueConfig`
  returns void and silently no-ops without a
  connection (sync_conn_config.go:230-252) — the
  phase's "failure" is ownership, not result-checking:
  the sync layer's reconnect/redelivery owns the
  redelivery (daemon_ha_sync.go:355-378), and the
  tail debt records the phase as PENDING until the
  peer's next reported applied digest covers it); and
  the phased tails ride EVERY FIRST-EXPOSURE (v8.16,
  Codex r20 f6's completion-ledger fix — the GO-local
  re-sync's accepted apply was clearing its debt
  WITHOUT any tails, forwarding B while A-authorized
  sessions and stale peer/marker state remained):
  an exposure is COMPLETE only after the dataplane
  acceptance AND the phased tails, with the
  completion-cursor state (v8.17, Codex r21 f7):
  `{pair, phaseCursor, completionState}` — DISTINCT
  from the prior/exposed pair — installed ATOMICALLY
  at acceptance (the re-sync debt clears ONLY after
  the record is installed, never on acceptance alone);
  a tail success advances the cursor; a PURE
  divergence replay of a completed pair skips the
  tails (the cursor says complete); an incomplete
  replay RESUMES its phase; a crash between phases is
  covered by re-running the idempotent tails
  conservatively at startup (v8.17 — the daemon-local
  in-memory cursor does not survive a crash, and the
  idempotent phases are safe to re-run). The deferred tails are PHASED with
  their own sub-debt (v8.15, Codex r19 f5's
  tail-failure fix: after the re-exposure apply's
  observed acceptance, the tails run as phases
  (session clear → peer push → markers → HA
  settlement); a phase failure records a TAIL DEBT
  that retries ONLY the failed phase (never a
  re-apply — a monolithic debt would repeatedly
  reapply and duplicate completed tails), and a crash
  between phases leaves the tail debt as the explicit
  owner). The HA
  settlement itself is marshalled through the ORDERED
  `configApplyLoop` consumer (v8.15, Codex r19 f4:
  `recordAppliedConfigGen` is deliberately non-CAS
  because the ordered loop is its sole caller
  (sync_conn_config.go:265-307) — an async direct
  store races it; and `item.gen` exists only inside
  that loop (:325-395), while `OnConfigReceived`
  carries only text (sync.go:339-347,
  daemon_ha_sync.go:909-913)): the loop's item protocol
  gains an INTERNAL item kind (`settleExposure{gen,
  digest, context}` — defined in the loop's OWN
  protocol (not a wire change), so the daemon's drain
  has an ingress that represents the pending exposure
  WITHOUT answering nil (which advances the generation
  immediately) or error (which invokes ordinary
  apply-failure/CF behavior) — v8.16, Codex r20 f4's
  ingress fix; and the drain, after the re-exposure apply's observed
  acceptance, posts it — BUT the session fence rises
  AT EXPOSURE, not at settlement (v8.16, Codex r20
  f4's session-fence fix: v8.15 cleared A-era sessions
  while leaving `applyingConfigGen` at A until the
  queued settlement ran, so an A-stamped session
  arriving after the clear but before settlement was
  admitted and survived C; existing code raises the
  new-generation fence BEFORE the clear and retains it
  until the high-water advances (sync_conn_gen.go:398-432)
  — the drain therefore (1) raises the gen fence at
  observed acceptance (before ANY session
  invalidation) — through the OWNER-TOKEN REGISTRY
  (v8.18, Codex r22 f9's fence fix, replacing v8.17's
  single-writer MAX-CAS (which left the loop's
  begin/end pair untouched: the current loop operations
  are unconditional `Store(gen)` and `Store(0)`
  (sync_conn_config.go:289-309), so a loop begin can
  lower a drain-owned fence and any loop end can erase
  it): EVERY fence writer (the drain AND the loop's
  begin/end pair) takes a registry SLOT with an
  ownership token; the EFFECTIVE fence is the maximum
  over live slots; a writer raises or clears ONLY its
  own slot (a slot clear is owner-scoped — no writer
  can erase another's); and a slot dies with its
  owner's terminal path (the drain's settlement, the
  loop's end, a process exit) — and the
  session-admission READER discipline is pinned
  (v8.19, SMR r23 SMR23-6: the admission check
  (sync_conn_gen.go:398-432's `max(fence, high-water)`)
  reads the effective fence (the max over live slots)
  AND the high-water as ONE consistent snapshot (one
  short registry lock covering both reads — a fence
  raise can never be torn away from the high-water it
  covers: reading the pair separately admits a session
  under a just-raised fence, fail-open); the
  process-exit window is the pre-existing posture,
  stated: a crash loses all slots AND the in-memory
  high-water, so admission between crash and the
  boot's first re-raise runs against the lost (zero)
  fence/high-water — the boot's first apply re-raises
  both and the window closes (§8 carries the class)), (2) runs the phased tails (the clear
  included), and (3) the settlement item advances the
  high-water LAST — the fence covers the whole
  window); the settlement item carries
  `(peerIncarnation, gen, pair, settlementID, the
  deferred-tail context)` (v8.17, Codex r21 f5's
  settlement-identity fix; the lifecycle completed
  v8.18, Codex r22 f9: the settlementID allocates from
  the drain's monotonic counter; the loop's dedup
  retains processed IDs (bounded, GC'd on
  peer-incarnation change); a duplicate delivery is
  re-acked without re-processing; a stale
  (older-incarnation or newer-gen-landed) settlement
  is discarded WITH an ack (so the tail debt can
  clear); and EVERY terminal path (processed,
  duplicate, stale, superseded) releases the tail
  debt exactly once: bulk/reconnect resets both
  high-water and fence to zero (sync_conn_gen.go:324-367),
  so a delayed OLD-INCARNATION settlement could
  advance the new incarnation past its legitimate
  generations — the item keys on the peer incarnation
  and the loop dedups/acks by settlementID (exactly-once:
  the tail debt retains until the loop's PROCESSING
  ack (not just the post); a same-process
  landed-but-unprocessed item is re-posted by the
  debt's backoff; a process crash losing the channel,
  cursor, AND debt together is covered by the
  completion cursor's crash rule (v8.19, SMR r23
  SMR23-8's phrasing fix: the crash LOSES the cursor —
  recovery derives the incomplete set from the
  `appliedRevision` sidecar (the exposed revision) and
  the store's rollback/archive trees (the durable
  active revision): exposed < active ⇒ the tails for
  exposed→active re-run idempotently at startup)) — an
  in-process item, not a wire change — the context
  being the last-exposed config by GC-RETAINED POINTER
  (v8.16, SMR r20 SMR20-5: the store's active object;
  a superseding commit replaces the store's pointer but
  the debt's reference keeps the object alive, and the
  settlement phase re-reads NOTHING from the store (no
  TOCTOU)); the item's FIFO position behind a large
  config push is bounded (the loop is sequential and
  each item is bounded), and the enqueue is
  NON-BLOCKING with a REPOST rule (v8.16, Codex r20
  f4's FIFO fix: the channel is finite (64,
  sync.go:847-857) — a full channel drops the
  settlement INTO THE TAIL DEBT (which re-posts at
  its backoff; the loop's ack (or the stale check)
  clears it — never a
  deadlock from blocking the drain on the channel,
  never a silent loss),
  which advances
  `recordAppliedConfigGen` IN ORDER (no CAS race) and
  runs the HA tails; `applyingConfigGen` during
  `ExposurePending` stays at the last-exposed gen
  (visible in `show`). For LOCAL commits (no sync
  item) the deferred markers run directly in the
  drain.
  (iii) RE-EXPOSURE OWNER: the DURABILITY-EXPOSURE DEBT —
  a daemon-side, single-flight, latest-wins debt recorded
  on EVERY gate skip (idempotently — the re-sync and
  restore paths through `applyConfigLocked` inherit it);
  the debt carries its OWN ALWAYS-LIVE timer (v8.14,
  Codex r18 f4 + SMR r18 SMR18-6: recording schedules a
  1s wake via the scheduler's timer with an explicit
  `nextWake` on every scheduler query (the MAC debt's
  Claim shape) — a gated commit with no other debts
  never waits on ambient wakes) and polls
  `durableRevision` at each wake (no new store→daemon
  call direction; polling observes the store's own retry
  and cannot accelerate it (AGY r18 f8) — the bound is
  the store's backoff (1s initial, doubling to a 60s
  ceiling, `ensurePersistRetryLoopLocked`
  (store_commit.go:615-628)) plus, honestly, UNBOUNDED
  time while storage itself is failed — the
  commit→exposure latency is storage-recovery
  (unbounded in the worst case, Warn-visible via the
  store's own retry Warns) + the debt's 1s wake +
  FIFO/apply, stated honestly);
  the drain acquires applySem, re-reads `ActivePair()`
  (latest-wins — a chain of gated B then C converges on
  C), and drives the REVISED `applyConfigLocked(ctx,
  cfg, commitRevision)` INCLUDING the three-bucket
  precheck and MAC-debt creation — the re-exposure apply
  is a full apply, never a precheck bypass; the drain's
  OWN apply failure KEEPS the debt with the standing
  backoff shape (v8.16, SMR r20 SMR20-3 = AGY r20 f3:
  5/10/30/60s + jitter + edge Warn — never a 1s hot
  loop (which would thrash `applySem`), never a
  clear-on-error (which would drop the exposure tail
  forever); the next drain re-reads `ActivePair()`
  (latest-wins); a publish UNKNOWN routes to the
  re-sync debt (the standing UNKNOWN ownership); a
  deterministic failure retries forever at the 60s
  floor with the fingerprint Warn — the standing
  persistent-failure posture). (iv) the
  ACCEPTED/EXPOSED pair split, with the IDENTITY SCOPES
  SEPARATED (v8.15, SMR r19 SMR19-2 — the v8.14
  revision-keyed marker conflated two scopes: revisions
  are NODE-LOCAL ("each node promotes locally"), so the
  same config text carries DIFFERENT revisions on
  different nodes and an inter-node revision comparison
  is meaningless): (a) NODE-LOCAL — the store gains
  `appliedRevision uint64` alongside `appliedDigest`,
  and `ActiveApplied()` compares the PAIR (text AND the
  LOCAL revision), so a same-text/new-revision gated
  promotion never inherits its predecessor's applied
  state (the v8.13 "stamp nothing" form was
  insufficient: `appliedDigest` compares config TEXT
  (store.go:278/:781/:803), so a same-text promotion
  with a NEW `commit_revision` inherits
  `ActiveApplied()==true` even when the new pair was
  gated); and `MarkActiveApplied(digest, revision)`
  gains EXPLICIT PARAMETERS (v8.15, AGY r19 f4,
  VERIFIED — the parameterless form
  (store.go:787-794) reads the CURRENT active at mark
  time, so a concurrent `store.Commit(R3)` landing
  during R2's apply would stamp R3's digest applied
  though only R2 was exposed; the mark carries the pair
  ACTUALLY exposed (the parameterized
  `setAppliedDigest` form (store.go:848) already
  exists)); (b) INTER-NODE — the sync layer's applied
  tracking keys to the config DIGEST (as today,
  daemon_ha_sync.go:474/:549) plus the typed outcome's
  DEFERRED gen settlement (the peer's
  `lastAppliedConfigGen` and CF/readiness tails advance
  only on EXPOSURE, so the primary's view of the peer
  lags VISIBLY until the peer's own exposure debt
  converges it); the equal-text shortcut
  (daemon_ha_sync.go:549) compares digests — a peer
  that already has the text skips the push, and its
  LOCAL exposure debt converges it regardless, so the
  shortcut can never strand B;
  HA applied markers (the `syncAndApply`
  digest stamp (daemon_apply_commit.go:426/:464)) happen
  ONLY when the dataplane apply RAN (the typed
  outcome's `Exposed`), and the current tails' session/peer
  bookkeeping keys to the exposed config; the primary's
  marker claim (daemon_ha_sync.go:474) is likewise
  deferred until exposure, and the peer's reported
  applied state during the window keys to the exposed
  config with the primary-side lag VISIBLE in `show
  chassis cluster` output (never silent). (v) the
  legacy-migration retry rides the SAME debt (a failed
  migration write leaves the dataplane in the
  legacy-zero gate AND records the exposure debt; the
  retry landing revision 1 wakes the drain). (vi) the
  AUXILIARY-PRODUCER question DISSOLVES under full
  gating (v8.15, Codex r19 f2/f3: the v8.14
  `m.exposureGateActive` suppression flag is DELETED —
  with FRR inside the gate, the RIB never moves during
  the window, so the overlay's A-clone carries A's
  routes (coherent), the scheduler's A-derived
  publishes flow normally (no suppressed close
  preserving an expired permit), and there is no flag
  whose lifetime needs an owner (AGY r19 f2's
  stuck-flag case dies with the flag). The
  A-config/B-FIB hybrid class (SMR r18 SMR18-1) is
  closed by construction: nothing moves the RIB until
  the drain's full apply. The high-water rule
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
  The primitive's two halves, v8.14 content-hash form
  (SMR r18 SMR18-2 = AGY r18 f4, replacing v8.13's
  input-capture-of-refs — storing a REFERENCE freezes
  nothing: the build dereferences feed/overlay state
  lazily OUTSIDE `m.mu`, so a concurrent mutation
  between capture and dereference silently changes the
  content the sequence supposedly orders (and is a data
  race outright); the enumeration of "which refs" is
  also unanswerable in principle (Compile reads
  scheduler state, route/feed overlays, FIB generation,
  NAT IDs, and the cold-path mask at separate times
  (manager_compile.go:192-225) and the builder later
  samples routes, fabrics, interfaces, and neighbors
  (builder.go:41-105) including live netlink fabric
  state (fabric.go:34/:102)), so the input-capture
  form is unimplementable as written): (i) a CHEAP
  section under `m.mu` at build START mints `buildSeq`
  (ONE monotonic manager counter, ==
  `snapshot_token` on the wire — the WIRE ORDERING and
  the helper-side backstop) and records NOTHING else;
  and (ii) a PUBLISH-LEG-ENTRY validation
  (v8.14, Codex r18 f5 — NOT "at send time": Compile
  performs side effects BEFORE the send (XDP/pin work
  and shim compilation at manager_compile.go:177-226,
  classifier/bootstrap map mutations at :279-350, and
  the deferred path confirms those maps are already
  ahead before its later send (process_status.go:103)),
  so the validation runs at the publish leg's ENTRY,
  before ANY of those mutations) — with the ordering
  rule re-specified (v8.16, Codex r20 f8, REPLACING
  v8.15's source-false "side-effect-free preparation
  phase": the userspace shim .o is build-time embedded
  (loader_userspace_shim.go:1-12) — no .o compile
  happens per-Compile — and `CompileUserspaceShim`
  calls `CompileConfig`, which directly creates VLANs,
  reconciles addresses, changes MTUs, toggles
  RX-VLAN/ethtool/rings, changes links UP/DOWN, and
  bumps the FIB-generation map (compiler_iface.go:446-510/
  :586-650/:679-717, compiler.go:298-304,
  maps_fabric.go:78-95) — there IS no side-effect-free
  Compile sub-phase to validate before, and the
  snapshot build consumes the compile's NAT IDs, so
  the build cannot even complete before the mutating
  compile): the STALE-BUILD-MUTATES-HOST class is
  killed at the DAEMON's dataplane-leg ENTRY instead —
  the flow re-reads `ActivePair()` and runs the
  pair-current check BEFORE `d.dp.ApplyConfig` (the
  (f3) flow-level rule: a stale flow aborts BEFORE
  any Compile (and its host mutations) begins; the
  auxiliary producers (route overlay, scheduler
  republish, #5134) CLONE the cached snapshot
  (manager_overlay.go:188 — no Compile, no host
  mutations at all), so their only validation locus is
  the send primitive); the manager-side validation at
  the send primitive keeps the TWO legs below (the
  residual race the daemon's entry check cannot see
  (manager-internal paths)), and the state names are
  pinned (v8.16, Codex r20 f8's inventory fix):
  `m.latestBuildSeq` mints per build (== the wire
  `snapshot_token`, seeded from the ping echo);
  `m.acceptedBuildSeq` advances ONLY on an observed
  acceptance (the (b) leg's authority); the helper
  fences on the NEWEST ACCEPTED token (per incarnation
  — v8.17, Codex r21 f10: a sent-but-REJECTED token
  NEVER advances the fence (a rejected snapshot is not
  an ordering authority), and a wire retry of the same
  build carries the SAME token (per-build immutable —
  the exact-equal retry (#4036) passes); the
  `publication_rev` (burned per ATTEMPT) keeps the
  wire-attempt order, so the two identities never
  contradict); and a mid-flow helper
  respawn is benign (SMR r20 SMR20-8 — zero-stored
  accepts everything; the bring-up is the bounded
  class) as TWO legs plus the
  wire backstop (v8.15, SMR r19 SMR19-1 = AGY r19 f1/f5,
  DELETING the v8.14 semantic-hash leg — the hash was
  computed at build end over the BUILT fabrics while the
  publish leg replaces that section from the canonical
  pair, so the wire content was never the hashed content
  (AGY r19 f5); and the hash leg deadlocked outright:
  T2's failed pre-publish build had already overwritten
  `m.latestBuiltHash`, so T1's check failed with NO
  accepted successor and every build abandoned (AGY r19
  f1). The two surviving legs cover every case without
  it): under `m.mu` at the publish leg's entry,
  (a) PAIR-CURRENT — the built `(config, revision)`
  pair must equal `m.currentPair` (the manager's
  current-pair record, set from every `ActivePair()`
  read — a newer commit's promotion invalidates the
  build), with the explicit revision-0 CLI Compile path
  EXEMPT (v8.15, SMR r19 SMR19-4: the diagnostic path
  (pkg/cli/apply.go:196-200, legacy_dataplane.go:190-195)
  promotes nothing, so its pair is never current — the
  legacy-zero mode governs it helper-side and the
  remaining legs still apply); the pair-not-current
  abandon reports SUPERSEDED-BY-NEWER-COMMIT (v8.16,
  SMR r20 SMR20-1 — success-equivalent for the apply
  flow, with the coverage argument that makes it sound:
  EVERY promotion path has an apply owner — the commit's
  own flow (plain, commit-confirmed, rollback), the HA
  peer flow, the auto-revert flow, the boot flow, the
  exposure debt's drain (the persistence transition),
  or the GO-LOCAL re-sync (anything else) — so the
  older commit's dataplane leg is always fulfilled by
  the newer config's own apply); and
  (b) NO ACCEPTED NEWER BUILD — a strictly-newer build
  OBSERVED-ACCEPTED (its send landed) invalidates (the
  same-commit reshape: T2's fresher content accepted ⇒
  T1 abandoned; T2 not yet accepted ⇒ T1 publishes and
  T2 converges milliseconds later — the natural
  direction, never stale-over-fresh; T2 failed
  pre-publish ⇒ T1 is the newest VIABLE build and
  publishes). Invalidation is DELAYED until the
  successor's OBSERVED ACCEPTANCE (v8.14, Codex r18 f5 —
  a newer CAPTURE never invalidates), and T1's
  abandon on a real accepted successor returns the typed
  SUPERSEDED-BY-NEWER-BUILD result, SUCCESS-equivalent
  for the apply flow (the accepted successor fulfills
  the commit's dataplane leg); if the ACCEPTED
  successor's own bookkeeping later unravels, the
  re-sync debt owns the outcome (never a silent loss).
  The helper
  additionally REFUSES a `snapshot_token` strictly older
  than the newest it has ACCEPTED (per helper
  incarnation; `error_code: "stale_snapshot_token"`) as
  the backstop — FENCING ON ACCEPTED, NOT SEEN (v8.17,
  Codex r21 f10's poisoning fix: the v8.16 "newest
  seen" rule made a REJECTED snapshot an ordering
  authority — a higher T2 that reached the helper but
  failed validation would poison a lower viable T1
  with no accepted successor, and after a manager
  restart (helper `seen=100, accepted=5`) Go would
  seed from 5 and mint refused tokens 6…100 (an
  unbounded retry-count catch-up, not benign
  behavior); fencing on ACCEPTED removes both (a
  rejected token never advances the fence, and the
  seed reads the newest accepted)) — and the token's
  identity is PER-BUILD IMMUTABLE (v8.17, Codex r21
  f10's scalar fix: `snapshot_token == buildSeq` is
  minted ONCE per build; a wire RETRY of the same
  logical send carries the SAME token (idempotent —
  the exact-equal retry (#4036) passes, and a
  strictly-older refusal applies only against a newer
  ACCEPTED build; the `publication_rev` (burned per
  ATTEMPT) remains the wire-attempt order, so the two
  identities no longer contradict);
  the refusal
  catches the residual race the Go legs cannot see (T1
  validated before T2's acceptance LANDED — the refusal
  catches it and the typed code classifies it as
  superseded, success-equivalent; two managers are
  impossible — the control socket is single-client per
  connection but a stale same-host process could exist;
  the refusal is per-incarnation so a respawned helper
  resets); and `buildSeq` SEEDS from the startup ping
  echo of the newest ACCEPTED token
  (v8.14, Codex r18 f6: the ping/status exchange
  gains the helper's newest accepted `snapshot_token`
  (additive), and the manager seeds
  `m.latestBuildSeq = max(echo, 0)` — a manager re-init
  over a surviving helper no longer mints from zero into
  indefinite refusal, mirroring the publication_rev and
  map_generation seeds; a helper RESPAWN between the
  ping and the validation is BENIGN for the fences
  (v8.16, SMR r20 SMR20-8: the fresh helper's stored
  token/revisions/generation are all zero, so the
  build's token and legacy high-waters PASS (no
  rollback possible against zero; the legacy-zero mode
  covers the revision pair), and the landing send
  triggers a full bring-up — the standing bounded
  replan interruption of §3, not a wedge). The auxiliary producers (route overlay, scheduler
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
     strictly-older-than-newest-ACCEPTED token per
     incarnation (`error_code: "stale_snapshot_token"`, and
     `StatusSnapshot.accepted_snapshot_token: u64` (serde
     default 0; v8.17, AGY r22 f1's missing-wire-field fix
     — the seed's ONLY source: the ping/status exchange
     echoes the newest ACCEPTED token, and a rejected token
     never advances it); a wire retry of the same build
     carries the SAME token (per-build immutable; the
     exact-equal retry (#4036) passes). Old Go omits
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
     contract, v8.15 `errors.As` form (SMR r18 SMR18-7 +
     AGY r19 f7's idiom fix — the v8.13/v8.14
     (response, error) pair required callers to check
     `resp.error_code` BEFORE the `err != nil`
     early-return, a caller-discipline trap any future
     standard-idiom caller would fall into): the typed
     refusal surfaces as a CUSTOM ERROR TYPE
     (`*ControlError{Code string; Resp ControlResponse}`)
     — the decoded response rides INSIDE the error value,
     callers use `errors.As` (the standard idiom, no
     ordering trap), and every typed response invokes the
     ONE common lineage-observation routine (note echo →
     accepted advancement → divergence classification,
     shared by the response path and the poll) and selects
     the reservation/debt outcome;
     UNTYPED failures (`error_code == ""` — including an
     old helper's unknown-TYPE rejection of the note verb
     (v8.15, Codex r19 f13: old Rust ignores additive
     unknown fields (no `deny_unknown_fields`,
     control.rs:107-139) then rejects the unknown request
     type with an untyped response (handlers/mod.rs:124-267);
     a compliant manager never sends the verb (the
     capability bit already fails lineage-sensitive
     operations closed), but a forced send takes the
     byte-identical LEGACY failure handling, never a
     CAS-refusal classification)) keep TODAY's
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
- **Configstore API (v8.10/v8.13/v8.14/v8.15):** `ActiveConfigRevision()
  uint64` (v8.10 — confirmed values only); `ActivePair()
  (*config.Config, uint64)` (v8.12 — ONE `s.mu`-atomic read
  of the active config AND its revision; the ONLY transport
  source for every apply path); `DurableRevision() uint64`
  (v8.14/v8.15, Codex r18 f4 + r19 f2 — the last
  active-pair `writeTreeMarked`-landed revision; advanced
  in-memory only after `WriteFileDurable` returns success,
  ONLY by active-pair writes (never candidate/rollback
  trees), re-derived from the on-disk envelope at `Load`;
  the exposure gate's PAIR-SPECIFIC comparison
  (`R <= DurableRevision()` ⇒ exposable), consulted at
  `applyConfigLocked`'s ENTRY and polled by the
  durability-exposure debt); `appliedRevision uint64`
  alongside `appliedDigest` (v8.14, Codex r18 f2 —
  `ActiveApplied()` compares the PAIR (text AND the LOCAL
  revision), so a same-text/new-revision gated promotion never
  inherits its predecessor's applied state); and the
  applied-marker verbs PARAMETERIZED (v8.15, Codex r19
  f6 = AGY r19 f4, VERIFIED — the parameterless
  `MarkActiveApplied()` (store.go:787-794) reads the
  CURRENT active at mark time, so a promotion interposed
  without `applySem` during an apply would stamp the
  newer config applied though only the older was
  exposed): `MarkActiveApplied(digest, revision)` and
  `MarkAppliedDigest(digest, revision)`/`ActiveDigest()`
  carry the pair ACTUALLY exposed (the parameterized
  `setAppliedDigest` form (store.go:848) already exists);
  all four production call sites pass the captured pair
  (daemon_apply.go:70, daemon_apply_commit.go:285/:438/:475),
  PLUS the auto-rollback path (v8.16, Codex r20 f10's
  census fix: the rollback's fresh local revision is
  directly applied/cleared/pushed
  (daemon_apply_commit.go:697-723) but was never
  STAMPED — it joins the census (the rollback pair is
  marked applied on its exposure)); and the primary's
  periodic push marker
  (daemon_ha_sync.go:474-497) gains ONE store-atomic
  captured `(text, digest, revision, exposed)` value
  read under `s.mu` at enqueue — REVALIDATED against
  `ActivePair()` immediately BEFORE the generation
  allocation/write (v8.17, Codex r21 f13's
  outbound-ordering fix: the atomic capture prevents
  a torn tuple but not the send-order race (periodic
  captures A; B promotes and sends first; delayed
  periodic A acquires `QueueConfig` afterward and
  receives the higher wire generation; the peer
  applies stale A after B; the marker stays at B, so
  the reconciler believes B was pushed): `QueueConfig`
  assigns its generation at send time under a separate
  write lock (sync_conn_config.go:230-252), as ONE
  STRUCTURED SEND TRANSACTION (v8.18, Codex r22 f12:
  `{queued, sentPair, sentDigest}` — the captured
  revision is re-read and revalidated against
  `ActivePair()` inside the write-lock hold (a stale
  capture is re-derived from the CURRENT active pair
  before the generation is allocated, never sent),
  and the marker records the SENT pair (B, not the
  originally captured A) — AND the
  revalidation includes the EXPOSURE check (v8.18,
  AGY r22 f4: the re-derived pair may itself be GATED
  (R > `DurableRevision()`) — an unexposed config must
  NEVER be pushed: the push HOLDS for a gated pair
  (the peer's state never leads the primary's exposed
  state, and the peer's own exposure machinery
  converges its local config independently once the
  push lands post-exposure)) — with the WIRING pinned
  (v8.19, SMR r23 SMR23-7 = AGY r23 f5: (i) the
  revalidation reaches the configstore through
  CONSTRUCTOR-INJECTED closures — `SessionSync`
  gains `activePair func() (*config.Config, uint64)`
  and `isExposed func(rev uint64) bool`, wired by the
  daemon at construction (pkg/cluster imports NO
  configstore (sync_conn_config.go:1-8) and keeps it
  that way — no package cycle); the closures'
  lock-order rule (v8.20, SMR r24 SMR24-8): the
  `isExposed`/`activePair` reads take `s.mu` UNDER
  `QueueConfig`'s `writeMu`, so the ONLY direction is
  writeMu → `s.mu` — the reconciler reads
  `ActivePair()` under `s.mu` and RELEASES before
  `QueueConfig`, and no `s.mu` holder may call into
  the sync layer's send path (the census: the
  reconciler at daemon_ha_sync.go:474-497 and the
  loop's begin/end, which take no `s.mu`); and the
  COMPANION order (v8.21, SMR r25 SMR25-3): the
  notice drain holds `applySem` while calling the
  cursor's `m.mu` method — applySem → `m.mu` is the
  ONLY direction there too (Compile runs under
  `applySem` and takes `m.mu`; the GO-LOCAL debt
  recording is enqueue-after-unlock (no `m.mu` →
  `applySem` path); the manager NEVER acquires
  `applySem` (it is a daemon semaphore)); (ii) the marker-claim
  ORDER: today the daemon claims its marker BEFORE
  calling `QueueConfig` (daemon_ha_sync.go:474-497) —
  the claim moves AFTER the send: the reconciler
  records the marker FROM the structured result's
  `sentPair` (a re-derived B is marked B, never the
  originally captured A); and (iii) the held push's
  RE-WAKE owner: a gated pair HOLDS the push
  (`{queued: false, holdReason: "unexposed"}` — no
  send, no generation burned), and the exposure
  drain's completion posts a trigger edge into the
  level-triggered `reconcileConfigSyncToPeer` (the
  same reconciler, daemon_ha_sync.go:355-378), which
  re-attempts the push on that edge — the peer never
  waits for the slow periodic tick); the revision
  assignment itself (the five
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
  build's input-capture mints from it, v8.13 Codex r17 f5;
  SEEDED from the startup ping echo (v8.14, Codex r18 f6))
  and `m.currentPair` (the
  manager's current `(config, revision)` record, set from
  every `ActivePair()` read, v8.14 Codex r18 f5;
  the v8.14 `m.latestBuiltHash` is DELETED (v8.15, SMR
  r19 SMR19-1 = AGY r19 f1/f5 — the two-leg validation
  needs no hash)),
  `m.mapGeneration` (the fabric map high-water, seeded from
  the startup ping echo, v8.13 Codex r17 f12 = SMR r17
  SMR17-4), the canonical `fabricProjection{payload,
  generation}` retained per projection (v8.14, Codex r18
  f11), and the fabric coherence-proof flag (set on the
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
  abort, v8.13 Codex r17 f4). The RESTORE debt is
  DAEMON-SIDE ENTIRELY (v8.16, Codex r20 f10's
  ownership fix — state + scheduler + drain, the MAC
  debt's daemon-ownership shape; NOT manager state —
  the manager's only role is the typed
  `NotifyLinkCycle` result and the reconcile
  primitives; the `RecordRestoreDebt` /
  `ClaimRestoreWork` / `ReportRestoreAttempt` helpers
  are DAEMON-local (not LinkController methods);
  retry 5/10/30/60s + edge Warn, no terminal cap).
  The v8.7 `ConfigGeneration` snapshot field, the
  v8.8 mint/carry contract, and the v8.9 `archiveSeq`-based
  `commit_revision` are all DELETED.
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
  `set_queue_state`, `apply_snapshot`, `rebind`, `update_fabrics` —
  signatures unchanged; PLUS the NEW `note_commit_revision`
  verb (v8.14, Codex r18 f7's enumeration fix — the v8.12
  text demanded a named dispatcher entry while this list
  claimed "signatures unchanged" and omitted the verb; today
  both request structs lack the field (protocol.go:55,
  control.rs:108) and Rust falls through to the unknown-type
  arm (handlers/mod.rs:124/:255)): the request type gains a
  `note_commit_revision {new_rev, expected_rev}` arm
  (additive, serde defaults — old Go never sends it; old
  helpers reject it as unknown, which the note debt
  classifies as the mixed-version fail-closed case), the
  dispatcher gains its named match arm, and the handler
  implements the three-way CAS (§5-C (iv)); response shapes
  ADDITIVELY EXTENDED
  (v8.13, Codex r17 f6's correction of the v8.12
  "shapes unchanged" text): `ControlResponse` gains
  `error_code: string` (serde default `""`; the typed codes
  classify the new machinery's refusals; existing errors keep
  `""` and their handling). `set_binding_state` slot
  addressing is unchanged (slots remain positional).
- **Daemon apply outcome (v8.14, Codex r18 f3):**
  `ApplyOutcome` ∈ {`Ran`, `Exposed`,
  `ExposurePending`} — the gated apply returns
  `ExposurePending` (NOT nil-success, NOT error); every
  wrapper's success tails gate on `Exposed` (boot skips
  `MarkActiveApplied`; the commit skips the session clear
  / peer push / applied stamp; the peer sync skips
  `armedActive=true` + its success tail; `configApplyLoop`
  skips the CF clear + `lastAppliedConfigGen` advance);
  the exposure debt record carries the HA `item.gen` +
  commit context so the drain runs the deferred tails
  after observed acceptance.
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
  node; the head's Finish applies the recorded outcomes
  of ALL completed nodes IN CHAIN ORDER (oldest first),
  its own outcome LAST, with the REDUCTION (v8.15,
  Codex r19 f9):
  | outcome | `deferWorkers` after |
  |---|---|
  | ACCEPTED | the node's own deferIntent |
  | POST-ACCEPTANCE TAIL | the node's own deferIntent |
  | PRE-PUBLISH FAILURE | the NEWEST ACCEPTED predecessor's deferIntent (or the chain-root value when no node was accepted) — NEVER the node's captured prior (a sibling's speculative state) |
  | PRE-SEND | unchanged |
  | UNKNOWN | unchanged (the debts own) |
  | OVERLAP | unchanged (superseded) |
  and the HEAD-POP rule (a Finishing head pops to the
  oldest unfinished node, so the last node's eventual
  Finish is always a head Finish that fires the fold
  and clears `m.compileInFlight`); PENDING-XSK STAGED
  is an OPEN STATE, not a Finish outcome (its token is
  stored for the deferred-publish leg; helper death
  before the leg finalizes it UNKNOWN);
  panic outcomes classify by phase via
  the Compile-internal `defer` (pre-wire → PRE-SEND;
  possibly-landed → UNKNOWN; post-acceptance → tail);
  the stale
  un-tokened `ClearCompileReservation()` is DELETED,
  Codex r16 f10);
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
  that acquires `m.mu` — BLOCKING while the batch holds
  `applySem` (v8.15, Codex r19 f10's consistency fix:
  the v8.13/v8.14 try-lock text contradicted the
  blocking reconciliation; try-lock-or-skip survives
  ONLY for paths NOT holding `applySem`) —
  validates the token (bumped → `Stale`), and on `Valid`
  issues ctrl-disable + `stop_workers` UNDER THE SAME
  HOLD (3s `controlBaseDeadline` each,
  process_control.go:34-41), releasing `m.mu` before the
  MAC phase; the per-member token checks then run at
  MEMBER BOUNDARIES (cheap BLOCKING reads — the v8.14
  mutation lease is DELETED (Codex r19 f10): an
  in-flight member's DOWN→MAC→UP program ALWAYS
  COMPLETES (the member transaction is the atomic
  unit), and a cancellation takes effect at the next
  boundary (wasted-not-harmful; no half-cycled member
  can exist)); `RetryLater` exists only for
  pre-`applySem` probes — and the RESTORE DEBT's retry
  uses a RESTORE-AUTHORIZED variant (v8.18, Codex r22
  f10's API fix: the restore debt has a DIFFERENT
  token than the MAC debt's claim — the restore's
  retry calls the restore-authorized quiesce (the same
  method with the restore debt's own claim token), so
  each retry becomes a NEW transaction: reassert the
  gate, stop any workers an intervening operator verb
  spawned, perform the restore, and rebind the CURRENT
  plan (including the operator's change) — the v8.17
  form named no restore-authorized quiesce operation);
  and
  `ReportMACDebtAttempt(claimToken uint64, results
  []MACDebtMemberResult) (settled bool)` — accepted only
  while `claimToken` is current (stale-token results
  discarded wholesale), updating the collections under
  `m.mu`, with `settled=true` authorizing the daemon to
  dispatch the tagged completion via the EXISTING
  `NotifyLinkCycle` path — PLUS the UNCONDITIONAL
  `RecordLinkObservation(member string, linkUp bool)`
  (v8.18, Codex r22 f10's second half: a separate
  unconditional, cancellation-insensitive transition
  for the link-state observation (the work loop calls
  it as it goes, BEFORE any token disposition) — a
  stale `ReportMACDebtAttempt` can never un-record it
  (§5-C's failed-UP ownership rule rides it), and it
  SKIPS a member already removed from the desired set
  (AGY r22 f5's deleted-member fix — the recording
  checks the desired membership at record time, so a
  deleted member can never linger in
  `linkOnlyRecovery`).
  **`ApplyResult` gains the commit revision** (apply.go:97-117
  currently carries only the ordinary generation, Codex r13
  f9) — sourced from the SAME `ActivePair()` read that
  supplied the config (v8.13, Codex r17 f3: never a
  separate `ActiveConfigRevision()` getter) — AND the
  exposure-transition triple `{priorPair, ledgerID,
  firstExposure}` (v8.18, Codex r22 f5 = AGY r22 f3:
  `beginFirstExposure(B)` runs manager-side at
  acceptance (the same `m.mu` section that advances
  `m.acceptedCommitRevision`) and returns the immutable
  prior (the pre-advance last-exposed pair), the ledger
  ID, and whether this acceptance IS a first exposure;
  the daemon wrapper receives them on the `ApplyResult`
  across the package boundary (never a post-hoc read
  after `m.mu` is released); the wrapper's `oldActive`
  parameter is RETIRED from the invalidation path (the
  prior is the one source of truth — they differ
  exactly post-gate (B promoted and gated, then C
  committed direct-durable: `oldActive` is B
  (store-active), the prior is A (last-exposed))); and
  the completion cursor `{pair, phaseCursor,
  completionState}` is installed ATOMICALLY in the same
  section (the re-sync debt clears ONLY after the
  record installs; a completed replay skips the tails;
  an incomplete replay resumes its phase) — and the
  STATUS-LOOP CATCH-UP acceptance leg (the
  `syncSnapshotLocked` publisher, which has no
  `ApplyResult` to ride) posts a COMPLETION NOTICE on
  the bounded daemon channel (enqueue-after-unlock,
  the OnXSKBound shape); the daemon drains it and runs
  the phased tails with the cursor's `completionState`
  as the single exactly-once authority across BOTH
  legs (v8.19, SMR r23 SMR23-3 = AGY r23 f3) — UNDER
  the pair-currency gate (v8.20, SMR r24 SMR24-1 =
  AGY r24 f1: the drain acquires `applySem`, re-reads
  the CURRENT pair, composes prior → CURRENT,
  currency-gates the stamp/push, and marks a
  superseded entry SUPERSEDED) — the stamp/push
  gate keying on EXPOSED currency (v8.29, AGY r33
  f1 — the notice's pair == `m.lastExposedPair`,
  never the store-active pair: a gated successor
  leaves the exposed pair's stamp/push firing)
  with every cursor
  read-modify-write through ONE `m.mu` method
  (SMR24-2 — the claim-or-skip tri-state, v8.24 SMR
  r28 SMR28-1) and the scheduler's per-tick pass
  iterating the pending-cursor set (v8.23 — the
  pending set IS the correctness path, the notice
  the fast path) with the per-entry `nextAttempt`
  backoff (v8.24 SMR28-2) and the UNIFORM
  missing-entry → already-terminal contract across
  every accessor including this wrapper's (v8.24,
  AGY r28 f2). The prior
  config is durable by construction (the store's
  rollback/archive trees retain it by revision), so a
  crash mid-completion re-derives the cursor from the
  store and re-runs the idempotent tails conservatively
  at startup — and when the cursor AND the prior are
  BOTH unrecoverable, the first apply after startup
  CONSERVATIVELY CLEARS all sessions (INCLUDING
  sidecar-present cases: the `appliedRevision` sidecar
  records the exposed revision, not the prior config,
  so its presence alone cannot prove the base
  (Codex r22 f5's sidecar fix; the invalidators no-op
  on a nil old config (daemon_policy_invalidate.go:60-65/
  :193-195), so an unprovable base must never silently
  pass)).
  **`NotifyLinkCycle` gains a typed result** (v8.13, Codex
  r17 f9 — void today, swallowing missing-process, ctrl,
  rebind, and status-application failures
  (process_linkcycle.go:184-224)): each failure mode maps
  to an explicit owner — missing process → respawn
  FOLLOWED BY a daemon-owned revised full apply
  (`applyConfigLocked(ctx, cfg, commitRevision)` from
  `ActivePair()`, full reservation + precheck); ctrl
  error → the RESTORE DEBT's retry of the FULL
  `NotifyLinkCycle` sequence (rebind + status reconcile +
  ctrl enable via `applyHelperStatusLocked`'s reconciled
  path (maps_sync.go:689/:809) — never a bare ctrl write);
  rebind error → the RESTORE DEBT itself (NOT the #5134
  debt, which self-clears on non-deferred snapshots,
  manager_worker_arm_5134.go:50-54); status error → the
  poll reconciles. **The restore debt is DAEMON-SIDE
  entirely** (v8.14, Codex r18 f10 — state + scheduler +
  drain, the MAC debt's daemon-ownership shape; the
  manager's only role is the typed result + the reconcile
  primitives), with a pull-model API mirroring the MAC
  debt's: `RecordRestoreDebt(failure, context)` +
  `ClaimRestoreWork() (items, claimToken, nextWake)` +
  `ReportRestoreAttempt(claimToken, results)` (stale-token
  discarded); retry 5/10/30/60s + edge Warn, NO terminal
  cap; the ctrl=0-while-bound window is a TOTAL
  fail-closed outage, Warn-visible, retry-forever.
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
| Architectural mismatch | MED | The surface is now wide (helper planner + status/convergence + one coordinator predicate; two additive wire fields; Go manager D/gate/retry/debts/warn; daemon apply ordering + MAC debt; PLUS the v8.13-v8.16 control-plane superstructure: the two-revision lineage, the exposure gate + debt, the typed ApplyOutcome + phased completion ledger, the ordered-loop settlement, the reservation chain, the checked quiescence + member boundaries, the restore debt, the canonical fabric pair) — §11 Q6 explicitly asks reviewers whether the daemon-side pieces (MAC debt) or the retry should split into follow-up PRs. The core (tri-state + coherent vector + provenance completion) is indivisible; the superstructure exists because each lighter shape died to a named counterexample in rounds 8-20 (UNKNOWN-outcome ownership, the Option-B alias, the fold ABA, the wrong-intent stamp, the false fabric coherence); the split candidates are additive layers. #6702/#6681 non-collision unchanged. |
| Safety/authorization posture | MED | The v8.15/16 machinery's honest postures (each reviewer-sanctioned): persistent storage failure leaves a committed config's FORWARDING plane unexposed (the dataplane keeps the last durable config; the security closeout (management auth) still applies; Warn-visible + the always-live debt) — bounded by storage recovery, unbounded in the worst case, stated; a persistently failing compile retries forever at the 60s floor (the commit's error is also surfaced; rolling back a committed config is a bigger contract change, explicitly out of scope); the late-member warm blackhole (up to 60s backoff + FIFO + transaction, partial-path); the ctrl=0 restore window (fail-closed, Warn-visible, retry-forever); the kernel-unreapable/D-state class (unbounded PERIOD — SIGKILL cannot reap D-state; the 60s Warn + out-of-band operator action is the only mitigation). |

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
      note ON THE COMMIT'S OWN RESULT SURFACE
      (a RESPONSE COPY of the warnings — assert the store's
      `compiled.Warnings` is NOT mutated (the aliasing
      class, Codex r19 f5))
      and NO dataplane apply runs (assert the
      helper never sees B) AND NO FRR reload runs (v8.15,
      Codex r19 f2 — FRR is inside the gate; assert the
      RIB never moves during the window, and the
      AUXILIARY coherence: the overlay publishes A's
      routes in A's clone (assert NO A-config/B-FIB
      hybrid — with FRR gated there is no flag and no
      suppression to get wrong), and the scheduler's
      A-derived closes PUBLISH normally (assert no
      stale-permit fail-open, Codex r19 f3)) →
      the persist retry lands the
      write with NO config event → the debt's OWN
      always-live timer (assert the 1s `nextWake` fires —
      an ambient-wait implementation fails) polls
      `DurableRevision()` and
      the drain FIRES and drives
      the full revised `applyConfigLocked` (assert the
      three-bucket precheck runs, B's MAC debt is
      recreated, the FRR reload runs at the drain, and
      the helper is observed at B's
      revisions) — the retry ALONE exposes B (the v8.12
      hole had no owner); the TYPED OUTCOME (v8.14, Codex
      r18 f3): the gated apply returns `ExposurePending`
      and EVERY wrapper tail is SKIPPED (assert no
      `MarkActiveApplied`, no session clear, no peer
      push, no applied stamp, no `armedActive`, no CF
      clear, no `lastAppliedConfigGen` advance — the
      standby never reports B applied or transfer-ready),
      INCLUDING the commit-confirmed auto-rollback
      wrapper (v8.15, Codex r19 f5 — assert its session
      invalidation and push also gate on `Exposed`);
      the COMPLETION-LISTENER legs (v8.20, SMR r24
      SMR24-1/2/4/6 = AGY r24 f1/f2/f4/f5): B accepted
      via the status-loop catch-up posts its notice;
      C promotes and applies BEFORE the notice drains
      — assert the drain acquires `applySem`, composes
      prior → the drain-time EXPOSED pair (v8.22, SMR
      r26 SMR26-2 = AGY r26 f2/f4: C EXPOSED ⇒ A→C (an
      A-permitted,
      B-revoked, C-permitted session SURVIVES; an
      A-permitted, B-revoked, C-revoked session is
      deleted) — never the A→B composition over C; and
      C promoted-GATED (unexposed) ⇒ A→B (a
      B-permitted, C-revoked session SURVIVES the
      gated window — an unexposed config never alters
      session posture; C's own exposure tails compose
      B→C later); and
      the composition RUNS for the stale notice —
      a skip-everything-on-SUPERSEDED implementation
      FAILS this test (v8.21, SMR r25 SMR25-1 = AGY
      r25 f2)),
      skips the applied stamp + peer push for the
      superseded pair, and marks the cursor entry
      SUPERSEDED (terminal); the cursor's
      check-and-advance runs under `m.mu` (assert a
      concurrent wrapper/listener phase completion
      cannot double-run a tail); a full notice
      channel drops the enqueue with a Warn AND the
      periodic pending-cursor sweep runs the tails
      anyway (assert the sweep, not just the notice)
      — and the sweep NEVER blocks the status thread
      (v8.22, SMR r26 SMR26-1 = AGY r26 f1: assert
      the 1s pass completes with `applySem` HELD by a
      long control apply — the pass scans and marks
      under `m.mu` only, the drain execution is
      dispatched to the apply scheduler, and a
      terminal entry is GC'd on the observing pass
      (SMR26-4)); the scheduler's per-tick pass
      ITERATES the pending cursor set (v8.23, SMR r27
      SMR27-1 = AGY r27 f2: assert NO channel exists
      — N pending entries converge with no queue and
      no drop policy, and an entry stays pending
      until terminal); a drain dequeued for a
      GC'd entry is a safe NO-OP (v8.23, SMR r27
      SMR27-2 = AGY r27 f1/f4: assert the missing
      entry lookup returns already-terminal, never a
      nil dereference or an unhandled error) — FOR
      EVERY accessor (v8.24, AGY r28 f2/f3: the
      synchronous `ApplyResult` wrapper's accessor
      hits a GC'd key and no-ops cleanly too (the
      iterate drain can claim and complete a
      Compile-leg entry's phases concurrently with
      its wrapper)); the phase machine is the
      claim-or-skip tri-state (v8.24, SMR r28
      SMR28-1: assert two concurrent drains on one
      phase produce exactly ONE execution — the
      duplicate claimant skips); a failing tail
      retries on the per-entry `nextAttempt` ladder
      (v8.24, SMR r28 SMR28-2 = AGY r28 f1: assert
      two consecutive failures do NOT produce two
      back-to-back full drains, and the Warn fires
      on the standing edge-detect); a PANICKING
      phase execution reverts claimed → pending
      with backoff applied (v8.25, AGY r29 f1/f4:
      inject a panic mid-phase — assert the `defer`
      wrapper's atomic revert and that the next
      claimant picks the phase up at the ladder-due
      time, never immediately); a stuck claim is
      STOLEN after the named bound (v8.25, AGY r29
      f1: assert the stealer's bumped generation
      executes and the stale claimant's late advance
      is refused) — FENCED (v8.26, AGY r30 f1/f2:
      the stale claimant's drain ABORTS AT ENTRY
      (assert NO side effect lands — no session
      delete, no stamp, no push — when the claim is
      dead at entry); a late stamp on the OLD
      revision is CAS-refused (assert
      `appliedRevision` never regresses after a
      newer stamp); the steal CANCELS the stale
      claimant's context (assert the wedged
      goroutine exits on cancellation), ADVANCES the
      entry's ladder (assert two steals are never
      back-to-back at the base interval — the
      cadence decays to the 60s floor), and is
      REFUSED while a live claim stands (assert
      max-one-live-claim); the panic-revert on a
      GC'd entry is a no-op (AGY r30 f4)) — AND the
      MID-DRAIN interleaving (v8.27, SMR r31
      SMR31-1 = AGY r31 f1: a claim valid at entry,
      stolen MID-execution — assert the side
      effects land under `applySem` (the composed
      invalidation, the CAS stamp, the push), the
      completion record is generation-refused, and
      the stealer's re-execution completes
      idempotently (a no-generation-check
      implementation FAILS this test)) — AND the
      C2-INTERPOSE gap (v8.28, SMR r32 SMR32-1 =
      AGY r32 f1; formula corrected v8.29, AGY r33
      f2): C2 exposes BETWEEN the stale
      drain's `applySem` release and the stealer's
      acquire — assert the stealer composes A→C2
      (never A→C), detects C1 as non-store-active
      (its stamp/push skipped), and marks C1
      SUPERSEDED — the union of the three delete
      sets is exactly (A∪C)\(C∩C2) with survivors
      exactly (A∪C)∩C∩C2 (an A-permitted,
      C-revoked, C2-re-permitted session was
      deleted at C's exposure and never recreated
      — intermediate revocations are permanent);
      and the GATED-successor case (v8.29, AGY r33
      f1): C1 exposed, C2 store-active but GATED
      (unexposed) — assert C1's stamp and push
      FIRE (C1 is still the exposed pair — the
      gate keys on EXPOSED currency), C2's push is
      HELD, and the peer converges on C1 exactly —
      and the stamp LANDS in captured-digest form
      (v8.30, SMR r34 SMR34-1/2 = AGY r34 f1/f2:
      assert `appliedDigest ==
      configTextDigest(C1's text)` after C1's
      drain (the stamp is `MarkAppliedDigest` of
      C1's captured digest, NEVER
      `MarkActiveApplied()` of the gated successor)
      and `== digest(C2)` after C2's own apply —
      a stamp-call-that-doesn't-land FAILS);
      the A→B→C COMPOSITION (v8.15, Codex r19 f5): A
      exposed → gated B tightens → gated C promoted →
      C's exposure invalidates sessions against
      LAST-EXPOSED → CURRENT (A→C — assert no
      A-authorized session survives, never only B→C);
      the PHASED tails (v8.15, Codex r19 f5): a tail
      phase failure (the peer push fails after
      acceptance) records the TAIL DEBT and retries ONLY
      that phase (assert NO re-apply and no duplicated
      completed phases); the HA SETTLEMENT transport
      (v8.15, Codex r19 f4): the drain's settlement
      rides an INTERNAL ordered-loop item (assert
      `recordAppliedConfigGen` advances IN ORDER — a
      racing direct store is impossible); the
      REVISION-KEYED marker (v8.14, Codex r18 f2 +
      r19 f6): a
      same-text/new-revision gated promotion does NOT
      inherit `ActiveApplied()==true` (assert the
      equal-text shortcut cannot fire), and
      `MarkActiveApplied` carries the EXPOSED pair
      (assert a promotion interposed mid-apply is never
      stamped);
      a chain of gated B then C
      converges on C (latest-wins drain); the HA leg:
      `syncAndApply` stamps NO applied digest for a gated
      apply (assert the peer's equal-text suppression can
      never skip the later push, the receiver's own
      exposure debt converges it, and the primary-side
      lag is VISIBLE in `show chassis cluster`);
      the false-green refused:
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
      pair AND ABORTS on interposition (v8.16, Codex r20
      f3 — the interposition tests of v8.12-v8.16 are
      UNREACHABLE under the invariant (every promotion
      path holds `applySem` across promote+apply — no
      operator commit, HA sync, commit-confirmed, or
      auto-rollback can interpose mid-flow, and the
      persistence transition changes only durability);
      the PROMOTION-SERIALIZATION
      INVARIANT (v8.17, Codex r21 f3): EVERY promotion is
      serialized with its apply under `applySem`
      (VERIFIED: `commitAndApply` holds `applySem`
      across `configstore.Commit` AND the apply
      (daemon_apply_commit.go:129-175)) — assert NO
      interposition is reachable from any promotion
      path (local commit, HA sync, commit-confirmed,
      auto-rollback all hold the semaphore), so the
      pair read at flow start stays current for the
      whole flow and the second leg ALWAYS completes
      with the outer pair; AND the PAIR-SPECIFIC gate (v8.14, Codex
      r18 f4): durable A's MAC-deferred apply with
      nondurable B promoted BETWEEN the legs — A's
      mandatory second leg (R_a ≤ durableRevision) RUNS
      (assert the gate NEVER skips it), while B's apply
      (R_b > durableRevision) skips; the gate check runs
      at `applyConfigLocked`'s ENTRY (assert no
      SNMP/web-management/bootstrap/kernel/VRF mutation
      precedes it); and the SECURITY CLOSEOUT (v8.16,
      Codex r20 f2): a gated commit's SNMP/web/host-auth
      tightening FOLLOWS (assert old communities/
      credentials close even while the dataplane leg
      waits); the DEFERRED-ARM rollback timer (v8.19,
      SMR r23 SMR23-2 = AGY r23 f2): a recovered
      confirm window whose deadline falls MID-STARTUP
      does NOT fire before the boot apply completes
      (assert `Load` records the window without arming
      — no `time.AfterFunc` in the load path — and the
      executor never runs between phases); an
      already-expired deadline fires IMMEDIATELY on the
      post-boot-apply `ArmRecoveredConfirmTimer()` call
      (assert the expiry is queued, never dropped, and
      its promote+apply serializes under `applySem`
      AFTER the boot apply — never B-derived naming
      with A-derived dataplane);
      the false-green refused: asserting
      precheck execution while letting the second leg
      re-read or the boolean gate suppress A.
      (c) PING/BOOT: a send before the ping returns the
      manager-local `not_seeded` error AND records the
      boot-apply debt; the debt FIRES with ZERO config
      events (assert the drain — not a manually invoked
      second apply); the ping runs before the build
      stamps Generation/FIB (order asserted); the seeded
      state resets on respawn (a post-respawn Compile
      re-pings before minting); the ACCEPTED-ECHO seed
      (v8.18, Codex r22 f8): a manager re-init over a
      surviving helper seeds `m.latestBuildSeq` from the
      ping's `accepted_snapshot_token` echo (assert the
      wire field exists, a REJECTED token never advances
      the fence (a rejected-high T2 followed by a
      lower-viable T1 is ADMITTED), and an exact-equal
      retry of the same build passes (#4036)); a helper RESPAWN BETWEEN
      the ping and the validation is benign (v8.16, SMR
      r20 SMR20-8 — assert the send lands on the fresh
      helper (zero-stored accepts) and a full bring-up
      follows, never a refusal or wedge); post-respawn the paired
      replay carries `ActivePair()`'s current pair; the
      false-green refused: asserting ping-precedes-build
      while the boot retry has no owner.
      (d) FRESHNESS: the promotion-serialization
      invariant (v8.17, Codex r21 f3 — no promotion can
      interpose mid-flow, so no stale-pair mutation can
      occur on any daemon flow); the auxiliary
      producers (overlay/scheduler/#5134) CLONE the
      cached snapshot (assert no Compile runs for them
      at all, and the staged-ahead divergence
      suppression holds them while `pending > accepted`);
      T1 builds, T2 builds and publishes, T1's
      publish leg is REFUSED AT ENTRY (T2 was
      observed-accepted) — assert NO XDP/pin/shim/
      bootstrap-map side effect of T1's runs and
      T1's content never reaches the helper; the DELAYED
      invalidation (v8.14, Codex r18 f5): T2 fails in
      shim compilation BEFORE sending — T1 remains VIABLE
      and its send lands (assert T1 is NOT abandoned on a
      mere newer capture, and with the hash machinery
      DELETED (v8.15) there is no `latestBuiltHash` to
      strand it on); the pair-current leg (v8.15):
      T1's pair superseded by a newer promotion abandons
      T1 — and the GO-LOCAL re-sync rule FIRES
      (`ActivePair().revision > m.acceptedCommitRevision`,
      no helper input — assert the autonomous re-drive,
      Codex r19 f7's ownerless path) — AND the
      RESTART-SUPPRESSION marker (v8.19, SMR r23
      SMR23-1 = AGY r23 f1): a peer-synced
      topology/identity-changing config promotes R but
      is guard-refused — assert the drain's guard-refusal
      records R into `restartSuppressed` (Warn-once),
      the re-sync debt CLEARS into the terminal marker
      (no acceptance, no retry — assert NO second drain
      fires for R on any later poll), the rule never
      re-fires for R, and a newer promotion R′ > R
      re-arms the rule for R′ only (the set is
      process-scoped — a restart clears it); the explicit
      revision-0 CLI Compile is EXEMPT from the
      pair-current leg (SMR r19 SMR19-4);
      the token seed (v8.14, Codex r18 f6): a manager re-init
      over a surviving helper seeds `m.latestBuildSeq`
      from the ping echo (assert no indefinite refusal);
      the helper refuses a forced
      strictly-older token (`stale_snapshot_token`); the
      semantic hash produces EQUAL hashes for two
      identical builds (token excluded — dedup survives);
      ALL FIVE producers route through the primitive
      (locked entry for the already-locked auxiliary
      publishers — no self-deadlock; unlocked for
      Compile's publish leg); the false-green refused:
      manually assigning token values, asserting
      capture-order instead of the two legs, or abandoning on
      capture instead of acceptance.
      (e) ERROR_CODE: each producer emits its code
      (stale_completion on the rebind handler ordered
      BEFORE any field clearing; diverged_fabric;
      epoch_rollback + publication_rollback;
      note_cas_refusal via the named dispatcher entry
      (assert the `note_commit_revision` REQUEST arm exists
      in both request structs AND the dispatcher's match
      table — an unknown-type fall-through fails the test,
      v8.14 Codex r18 f7);
      stale_snapshot_token); a typed refusal surfaces as
      `*ControlError{Code, Resp}` (assert callers use
      `errors.As` — the standard idiom, v8.15 AGY r19 f7)
      and drives the common
      lineage-observation routine (note echo → accepted →
      divergence, in order); an UNTYPED failure copies NO
      status (today's handling byte-identical);
      the OLD-HELPER behavior (v8.15, Codex r19 f13): a
      forced note send to an old helper takes the
      byte-identical LEGACY failure (never a CAS-refusal
      classification), and a compliant manager never sends
      (the capability bit fails closed first);
      `not_seeded` never appears on the wire; the
      false-green refused: parsing one code while the
      other producers/consumers are unexercised.
      (f) RESERVATION CHAIN: the token is an explicit
      Compile argument (v8.17, Codex r21 f8 — assert
      `Compile(cfg, commitRevision, reservationToken)`
      receives the daemon's `StartCompile` token and the
      wire stamp reads THE TOKEN'S NODE (T1's immutable
      intent), never the shared global; the pending-XSK
      staged object carries both the token and its
      baked-in `DeferWorkers`; route/scheduler clones
      PRESERVE the cached defer value; the #5134 clone
      forces `false` only for the generation it owns
      completion for);
      the POST-OVERLAP staged send (v8.18, Codex r22 f6
      = AGY r22 f2 = SMR r22 SMR22-1; the publisher leg
      added v8.19, SMR r23 SMR23-4 = AGY r23 f4): T1 stages
      (pending-XSK), same-pair T2 starts and finalizes
      T1 as OVERLAP, T2 FAILS before acceptance — T1's
      deferred leg fires — assert the leg's registration
      was CANCELLED by the finalization AND the send
      primitive checks the node is still OPEN (T1's
      staged content NEVER publishes late over T2's
      state, and the leg discards the staged object) —
      AND the publisher leg: T2 fails BEFORE staging its
      own object, so `m.lastSnapshot` still references
      T1's staged object; the XSK becomes bindable;
      assert the OVERLAP finalization ALSO CLEARED the
      staged reference atomically (the publisher has
      nothing stale to send), `syncSnapshotLocked`'s
      defense-in-depth token-liveness branch skips any
      residual dead-token publish (and drops the staged
      reference), and the GO-LOCAL re-drive owns the
      re-apply (T1's cancelled content NEVER reaches
      the helper on EITHER leg);
      the registration's lifetime (staged → live →
      completed on the catch-up's publish; OVERLAP →
      cancelled + cleared; helper death → died; stage
      timeout →
      the GO-LOCAL re-drive (assert the timeout fires
      the re-sync at the five-minute mark, not an
      indefinite stage, and the scheduler entry is
      cancelled on every other lifetime path));
      T2 starts (captures T1's
      `{true,true}`), T1 finishes ACCEPTED (recorded,
      non-head), T2 fails pre-publish — the head's Finish
      applies the recorded outcomes oldest-first, its own
      LAST (assert the terminal `deferWorkers` is T1's
      intent — the restore reads the NEWEST ACCEPTED
      predecessor's intent, never T2's captured prior);
      the BOTH-FAIL case (v8.15, Codex r19 f9's
      resurrection): base false, T1 intent true captures
      false, T2 intent false captures T1's speculative
      true, BOTH fail pre-publish — assert the terminal
      `deferWorkers` is the CHAIN-ROOT value (false —
      NOTHING published, no epoch; the v8.14 captured-prior
      replay would have resurrected it); the
      INVERSE ordering: T1 fails pre-publish (recorded),
      T2 ACCEPTED — T1's restore applies first (chain-root
      value — no accepted predecessor), T2's intent is
      terminal; the HEAD-POP rule (v8.15, Codex r19 f9):
      the head Finishes while a predecessor remains OPEN —
      the head pops, the predecessor's eventual Finish is
      a HEAD Finish (assert the fold fires and
      `m.compileInFlight` clears — the v8.14 form had no
      guaranteed trigger); the full SIX-outcome table
      {ACCEPTED, PRE-PUBLISH FAILURE, UNKNOWN, PRE-SEND,
      POST-ACCEPTANCE TAIL, OVERLAP} for two-node AND
      three-node chains (PENDING-XSK STAGED is an OPEN
      STATE, not a Finish outcome — pinned, and its token
      is stored for the deferred leg, which finishes it);
      panic phase
      classification (pre-wire → PRE-SEND;
      possibly-landed → UNKNOWN; post-acceptance →
      tail); a newer StartCompile
      finalizes an orphaned open predecessor as OVERLAP
      (assert `m.compileInFlight` clears and the (v)
      echo resumes); helper death before the leg
      finalizes UNKNOWN; the CLI default reservation
      never panics; the false-green refused: asserting
      only the favorable ordering.
      (g) CHECKED QUIESCENCE + MEMBER BOUNDARIES: the merged
      `PrepareLinkCycleChecked` (no split API remains —
      compile-break); an operator bump between Claim and
      the method is `Stale` (abandon WITH unwind); the
      m.mu acquisition while holding applySem is BLOCKING
      (assert NO `RetryLater` position loss — a repeated
      finite status-loop hold cannot starve the batch,
      v8.14 Codex r18 f9); the MEMBER-BOUNDARY model
      (v8.15, Codex r19 f10 — the mutation lease is
      DELETED): an operator cancellation landing DURING a
      member's DOWN→MAC→UP program does NOT interrupt it
      (assert the member's program COMPLETES — no
      half-cycled member can exist, and `m.mu` is never
      held across a syscall), the cancellation takes
      effect at the NEXT member boundary (the cancelled
      member's entries are gone; its completed program is
      wasted-not-harmful); the OPERATOR-VERB QUIESCENCE
      GATE (v8.16, Codex r20 f9; clear points v8.17, AGY
      r21 f3 = SMR r21 SMR21-2 = Codex r21 f11): a
      registration toggle
      while `m.linkCycleActive` is REFUSED busy (assert
      NO helper-side reconcile re-spawns workers mid-
      quiescence — the live-XSK-during-MAC-cycle class
      is closed, not just bounded), AND the gate CLEARS
      at the transaction's restore completion (success
      OR transfer to the restore debt — assert the
      restore debt's backoff intervals do NOT hold it
      (the operator's verbs work between attempts) and a
      retry re-sets it for THAT attempt's window); the FAILED-UP
      ownership (v8.16, Codex r20 f9; hardened v8.17,
      Codex r21 f11): a member whose
      MAC-set succeeded but whose final UP failed keeps
      its `linkOnlyRecovery` entry EVEN WHEN the MAC
      debt is concurrently cancelled (assert the
      link-recovery owner survives — the link-down
      observation is recorded through the
      cancellation-insensitive path BEFORE token
      disposition — the member is never
      left down ownerless), and the batch's latency is
      asserted (bounded driver time per member
      transaction (50-500ms link cycles), bounded
      membership); `stop_workers`
      timeout-but-landed → the unconditional restore runs
      (rebind re-spawns the plan's workers); the hold
      span is asserted (m.mu released before the MAC
      phase — no self-deadlock); the false-green refused:
      mocking an atomic method or a per-syscall lock.
      (h) RESTORE DEBT: an ORDINARY recovery rebind
      failure records the restore debt (assert the #5134
      debt is NOT consulted — it self-clears on
      non-deferred snapshots); the REAL cross-owner drain
      (assert `ClaimRestoreWork` hands the item to the
      daemon's scheduler, not a mock replay, v8.14 Codex
      r18 f10) — and the drain ACQUIRES `applySem`
      (assert it — v8.15 Codex r19 f11) and calls the
      LOCKED apply directly (never the re-acquiring
      wrapper); missing-process → respawn
      → the daemon-owned revised full apply replays
      `ActivePair()` with `StartCompile(rethMACPending)`
      carrying THE PRECHECK'S OWN RESULT (assert it —
      v8.15 Codex r19 f11: a replayed config needing MAC
      work opens the defer epoch, never
      `StartCompile(false)` arming workers on stale MACs);
      ctrl error → the debt retries the
      FULL `NotifyLinkCycle` sequence (rebind + status
      reconcile + the reconciled ctrl enable — assert NO
      bare ctrl map write), and the ctrl=0-while-bound
      window is asserted fail-closed + Warn-visible +
      retry-forever;
      status error → the poll reconciles; the false-green
      refused: a debt record without the real drain, the
      semaphore, or the precheck-derived intent.
      (i) CAUSAL FABRIC: concurrent map writers serialize
      through the manager's wrapper (the direct key
      writes route inside it; the legacy-adapter bypass
      is enumerated and production-unreachable); the
      canonical `(payload, generation)` pair is built
      from the SAME locked sample as the mutation, with
      the payload's MACs from the MAP's OWN
      `PeerMAC`/`LocalMAC` fields (assert the map is the
      authority — a cache re-resolution can NEVER bind
      the generation to a different value, Codex r19
      f12; the neighbor cache is consulted ONLY for the
      unresolved (zero) case);
      the UNIFORM carrier rule (v8.15, Codex r19 f12):
      a mutation P mints g, the `update_fabrics(P, g)`
      send FAILS (the debt records), then a
      route-overlay clone publishes — assert it carries
      the CURRENT canonical `(P, g)` (NOT a (P0, g0)
      stale pair — that case does not exist), the
      helper's acceptance advances `accepted` to g
      (coherent with the map), AND the debt CLEARS on
      the observed accepted ≥ recorded (the full
      snapshot's acceptance is the self-healing leg);
      the REMOVAL TOMBSTONE (v8.16, Codex r20 f11;
      persistence v8.18, Codex r22 f11): the
      daemon clears a map entry (`Ifindex=0`) — the
      payload carries `removed: true` and the helper
      DROPS its retained fabric state (assert NO stale
      working set survives (a preserve-on-unresolved
      read would fail this), the debt's clear is
      truthful, and HA readiness stays FALSE until the
      tombstone is accepted); the tombstone PERSISTS
      until a successful nonzero map transaction
      (assert an unrelated full apply does NOT
      re-introduce the `FabricLink` while the map
      stays zero (the full build reads the canonical
      pair verbatim — no blackhole via the all-down
      fallback), and the population machinery's next
      successful nonzero write lifts it); a fabric
      REMOVED from the config is absent from the
      build by construction; the unresolved-candidate
      guard still rejects missing parent/MAC values
      (distinct from the deliberate clear);
      the content hash for the dedup covers the FINAL
      wire content (post-canonical-fabrics — assert the
      hashed bytes are the sent bytes);
      `map_generation` seeds from the
      ping echo on re-init (readiness recovers); the
      capability bit distinguishes new-helper-zero from
      old-helper-zero (old → fail-closed);
      the first-startup
      proof arrives via `startClusterComms`'s population
      goroutines (readiness true after bringup with
      fabrics configured); the false-green refused:
      manually manipulating counters, a stale-carrier
      rule, or asserting accepted==current without the
      payload binding.
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
      (up to 120s) — the attempt's Claim BLOCKS on `m.mu`
      while holding `applySem` (v8.14's reconciliation:
      bounded by one legal owner hold; assert it waits, never
      skips, so no FIFO position is lost); and the
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
      work loop's member-boundary `claimToken` checks are
      BLOCKING reads at member boundaries (v8.14's
      reconciliation + v8.15's member-boundary model —
      assert a contended read WAITS (bounded by one legal
      owner hold), never skips a mutation, and `m.mu` is
      never held across a syscall).
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

Remaining questions for round 35, each invitable to PLAN-KILL with
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
6. **Round-34 disposition table audit.** §1's r34 table maps
   every r34 finding (SMR 1 BLOCKER + 1 MINOR; AGY 1 BLOCKER
   + 1 MINOR; Codex infra-blocked) to its v8.30 fold, and
   every fold this revision was verified per-edit against the
   file. Which row is claimed-but-wrong this time?
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
   mode — PLUS the v8.13-v8.16 classes, each with its owner
   named (Codex r20 f13's completeness demand): persistent
   STORAGE failure = the committed config's forwarding
   plane unexposed (the dataplane keeps the last durable
   config; the security closeout still applies; the
   always-live exposure debt + the store's own retry Warns
   make it visible; bounded by storage recovery, unbounded
   in the worst case, stated); a persistently FAILING
   compile (deterministic build error) = the GO-local
   re-sync retries forever at the 60s floor with the
   fingerprint Warn while the commit's error is also
   surfaced (the config is committed; rolling it back is
   a bigger contract change, explicitly out of scope);
   the exposure drain's OWN apply failure = the standing
   backoff (5/10/30/60s + jitter + edge Warn, latest-wins
   re-read, publish-UNKNOWN → the re-sync); the settlement
   FIFO = bounded by the ordered loop's sequential bounded
   items + the repost-into-tail-debt rule; the
   late-member warm blackhole = the member's own current
   backoff (up to the 60s floor) + FIFO queueing + the
   transaction (partial-path, no dataplane-wide gate);
   the ctrl=0 restore window = fail-closed + Warn-visible
   + retry-forever (the full NotifyLinkCycle sequence);
   the kernel-unreapable/D-state class = unbounded PERIOD
   (SIGKILL cannot reap D-state; the 60s Warn +
   out-of-band operator action up to a reboot is the only
   mitigation) — PLUS the v8.17-v8.19 classes (Codex r22
   f14's demand, completed): the restart-only active
   config (a peer-synced topology/identity promotion the
   guard refuses live) = the terminal `restartSuppressed`
   marker (Warn-once, no retry loop — the boot path owns
   the post-restart apply; DEAD as a loop, the marker is
   the posture); the never-recoverable-XSK stage (the
   staged config's `DeferWorkers=true` keeps the
   dataplane DOWN for the stage + the re-drive's
   retries, INDEFINITE for a destroyed VF) = BY CONFIG
   INTENT (the config committed an unbindable binding
   plan; the dataplane stays down until the operator
   fixes the XSK or the config), Warn-visible at the
   stage/timeout/retry transitions; the fence-registry
   crash window (a process exit loses all slots AND the
   in-memory high-water; admission between crash and the
   boot's first re-raise runs against the lost zero
   fence/high-water) = pre-existing posture, the boot's
   first apply re-raises both; the deferred-arm
   rollback timer (a recovered confirm window whose
   deadline falls mid-startup) = QUEUED, never dropped
   (the arm fires it immediately after the boot apply,
   serialized by `applySem`); the held-push-forever
   class (v8.20, SMR r24 SMR24-9: a never-completing
   exposure drain leaves the gated config's peer push
   HELD indefinitely) = a CONSEQUENCE of the budgeted
   persistent-storage-failure class above (the peer's
   state never leads the primary's exposed state —
   correct by invariant; the peer converges when the
   push lands post-exposure; the periodic reconciler
   re-attempts on every trigger edge). Which of these, if any, is
   unacceptable for the severity-High class, and why?
