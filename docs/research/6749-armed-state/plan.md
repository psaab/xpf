# #6749 — binding-plan expansion registers new slots unarmed, dataplane disabled indefinitely

**Status: DRAFT v8.9 — pending adversarial plan review (round 14)**

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

---

## 1. Status

DRAFT v8.9 — pending adversarial plan review round 14 (Codex + AGY +
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
  | Codex f2 epoch allocator/ambiguous failure | CLOSED — `config_epoch` = the configstore's globally-monotonic commit seq (`archiveSeq`): no allocator, never reused, identical across same-config Compile invocations (§5-C epoch contract) |
  | Codex f3 overlay publishes B under A's lineage + census | CLOSED — every producer carries its CONTAINED config's seq (the B-clone carries B's); the five-producer census + the two deferred-acceptance legs (process_status.go:18-37/:120-139) are now in the advance list (§5-C (iv), epoch contract) |
  | Codex f4 dedup lineage (= AGY f1 = SMR13-1) | CLOSED — `note_config_epoch` lineage-transfer verb on the dedup skip; the local collapse is deleted; FAILED transfer = fail-closed suppression (§5-C (iii), §6) |
  | Codex f5 re-sync owner + A-clone overwrite | CLOSED — daemon-driven single-flight re-sync debt (enqueue-after-unlock); suppression of ALL older-lineage producers + the helper's epoch-rollback refusal backstop (§5-C completion machinery, (iv)) |
  | Codex f6 mixed-version epoch-0 | CLOSED — all lineage-sensitive operations fail closed on epoch 0 until the REQUIRED helper restart (§5-C epoch contract) |
  | Codex f7 defer-intent API + provenance wire | CLOSED — `StartDeferredCompile()` (intent+compileInFlight in one m.mu section at the precheck point, cleared on every Compile exit); `set_forwarding_state.provenance` wire field (default operator; automatic epoch-preserving); durable operator-verb retry debt (§5-C, §6) |
  | Codex f8 recovery XSK transaction (= AGY f6) | CLOSED — Prepare/Notify quiesce-all+rebind-all (budgeted, per-member quiescence a follow-up); linkCycled at DOWN-success; proxy-ARP/NDP in repairs; debt clears on observed bound+ready (§5-C debt) |
  | Codex f9 work-pull + linearization + pendingWorkerArm | CLOSED — `ClaimMACDebtWork` (due items + claimToken) + `ReportMACDebtAttempt` (stale-token discard); ApplyResult gains the epoch; #5134 pendingWorkerArm epoch-qualified + cleared on supersession (§5-C, §6) |
  | Codex f10 lock rule + fairness (= AGY f4 premise) | CLOSED — "no SYNCHRONOUS manager→daemon call while holding m.mu" (async enqueue = OnXSKBound shape); FIFO+bounded-hold proof with a 30s acquire bound; try-lock-or-skip manager calls (§5-C debt execution) |
  | Codex f11 env loss/oscillation (= AGY f5 = SMR13-4) | CLOSED — ≤4 ack-set of rejected identities (lost response re-sends + re-acks); debounced dispatch ≤1/5s per identity; the clamp source-model correction (§5-C (i), §9 item 19) |
  | Codex f12 fabric debt state machine | CLOSED — keyed `(config_epoch, projection-hash)`; {pending, retrying, failed-warned}; clean-matching-sync clear; readiness ANDs fabricPopulated with no-outstanding-debt; all four call sites (§5-C (i), §6) |
  | Codex f13 test greens | CLOSED — §9 re-specified per finding (re-sync debt shape, epoch reservation cases, staged-B producer census, deferred-acceptance legs, epoch-0, StartDeferredCompile + provenance wire, recovery transaction shapes, fairness + claimToken + contention, ack-set + flap, keyed debt clear) |
  | Codex f14 pass-1 cost | CLOSED — budgeted at µs-scale netlink reads (≤ ~1ms for a 12-member RETH) (§5-C budget) |
  | Codex f15 budget | CLOSED — the residual unbounded classes (epoch reuse, A-clone overwrite, ownerless owners, semaphore starvation, env oscillation, stale-5134 suppression, unobserved recovery) are closed by f2/f5/f9/f10/f11/f8; the budget text carries the fairness + pass-1 notes (§5-C budget, §11 Q7) |
  | AGY r13 f1-f6 | CLOSED — folded with the matching rows (f1→Codex f4, f2→f2 (commit-seq answers the contradiction), f3→f7 (StartDeferredCompile), f4→f10 (lock-rule proof), f5→f11, f6→f8) |
  | SMR r13 SMR13-1..4 | CLOSED — SMR13-1→Codex f4 row; SMR13-2/3 (re-sync debt identity, debt keying) → the epoch contract's uniform debt rule + the re-sync debt's explicit identity; SMR13-4 → f11 row + the recovery transaction's drop-window note |

### Round-1 detail log (kept for the record)

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
   every gate below is `config_epoch` ON THE WIRE — §6; the
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
   (b) ACKNOWLEDGED BOUNDED REJECT-SET — the helper retains a
   bounded set (≤4) of recently-REJECTED projections as
   (identity, sample) pairs (identity = the projection hash;
   replace-oldest on overflow; a rejection RESPONSE carries
   the (identity, generation) ack), and the env watch covers
   the UNION of the accepted snapshot's candidates AND the
   retained set's candidates — a lost rejection response
   leaves Go unsuppressed (it re-sends; the helper's
   idempotent re-rejection re-acks until a response lands),
   so helper watch ownership and Go's cache can never
   diverge on a lost response (Codex r13 f11's keep-first /
   replace-on-reject dilemma dies: the set holds BOTH B and
   B′); (c) Go caches `(rejectedIdentity, rejectedGen)` and
   SUPPRESSES the resend of that IDENTITY only while both
   match, keyed to the HELPER INCARNATION (cache resets on
   every manager-driven (re)spawn); (d) the status poll that
   observes a `guard_env_generation` bump with a suppressed
   identity DISPATCHES the fabric sync — DEBOUNCED: at most
   one dispatch per identity per 5s interval (a 1 Hz sysfs
   flap coalesces to ≤0.2 dispatches/s, and each
   guard-REJECTED cycle re-enables ctrl in the same RPC tick
   — an RPC-length pulse — so the duty-cycle bound is
   ≈milliseconds per 5s, never an unbounded 1 Hz ctrl
   oscillation, Codex r13 f11's flap class; an
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
   FABRIC SYNC DEBT state machine (v8.9 executable form,
   Codex r13 f12, replacing v8.8's typed-outcome sketch):
   `SetFabricForwarding` commits the BPF map FIRST and only
   then syncs the helper (controllers.go:112-132 — "the map
   update is committed at this point"), so the map commit
   STANDS (never rolled back); a helper-sync/pre-disable
   failure records a debt entry keyed `(config_epoch,
   projection-hash)` with states
   {pending → retrying (5/10/30/60s backoff, driven by the
   existing 30s fabric ticker + event wakeups + the (d)
   poll-dispatch) → failed-warned (edge Warn, retrying
   continues at the 60s floor)}; a CLEAN MATCHING sync (same
   key) CLEARS the debt — an unrelated clean status does NOT
   (a stale fab0/fab1/clear retry can never clear a newer
   projection's failure); a newer projection SUPERSEDES the
   old entry. `fabricPopulated` remains truthful MAP state,
   and takeover readiness (daemon_ha.go:774-783) ANDs it
   with "no outstanding sync debt for the CURRENT
   projection" — the daemon reads the debt state through the
   existing HA controller path (daemon→manager), so a
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
   (iii) **EPOCH-GATED fabric adoption (v8.9, Codex r13
   f3/f4/f6; the gate predicate is unchanged from v8.8, the
   epoch MEANING is new — commit-seq per the epoch
   contract):** adopt `status.Fabrics` into
   `m.lastSnapshot.fabrics` ONLY when
   `status.config_epoch == m.acceptedConfigEpoch` AND
   `m.pendingConfigEpoch == m.acceptedConfigEpoch` (no newer
   config staged) AND the observed epoch is NONZERO
   (fail-closed on an old helper's 0, Codex r13 f6). Every
   other case keeps Go's snapshot whole: staged-ahead (never
   an A-fabric splice onto B's config); helper-ahead
   (`status.config_epoch > m.acceptedConfigEpoch`) routes to
   the re-sync (§5-C completion machinery); helper-behind
   (a restarted helper echoes 0) routes to the startup
   re-apply, never by adopting an empty set. The
   content-dedup case is covered by the `note_config_epoch`
   lineage transfer (§5-C epoch contract): after the
   observed transfer the helper echoes the staged seq and
   the gate holds — no publish, no wedge (the v8.8 local
   collapse is deleted). `appliedSnapshot` stays untouched
   for its original #2079 consumer (the NAT pool alarm) and
   plays NO role here.
   (iv) **REQUEST-SIDE lineage fence + FULL-PRODUCER
   divergence suppression (v8.9, Codex r13 f3/f5/f6):**
   response-side gating cannot undo a
   request-side hybrid — `update_fabrics` mutates whichever
   snapshot the helper stores (handlers/mod.rs:144-174). The
   `update_fabrics` request carries
   `expected_config_epoch` = the commit seq of the config the
   fabrics were derived from (`m.lastSnapshot`'s staged seq
   when staged, else the accepted seq), and the helper
   REFUSES on mismatch with its stored `config_epoch` —
   fail-closed, no mutation, no persist, the check ordered
   FIRST (before the guard evaluation,
   `refresh_fabric_links`, the fabric mutation, and
   persistence). Divergence suppression now covers ALL FIVE
   full-publish producers (Codex r13 f5 — suppressing only
   `SyncFabricState` let a stale #5134 retry clone A with a
   newer ordinary generation and overwrite timeout-landed B,
   erasing the helper-ahead signal): while
   `m.pendingConfigEpoch > m.acceptedConfigEpoch` OR the last
   status showed `config_epoch > m.acceptedConfigEpoch`,
   the #5134 retry, route overlays, scheduler republishes,
   and `SyncFabricState` are ALL suppressed (any producer
   whose payload would carry an OLDER commit seq than the
   helper's stored seq), and the helper's OWN epoch-rollback
   refusal (§5-C epoch contract) is the second layer that
   refuses any such stale full apply that races through
   (fail-closed, no mutation). A producer carrying the
   NEWEST staged seq (a clone of staged B) is NOT suppressed
   — it carries B's own lineage and is the legitimate
   publish of B. Mixed-version: old
   helper ignores the field and echoes 0, so all
   lineage-sensitive sends fail closed until the REQUIRED
   helper restart (Codex r13 f6); an old Go driving
   a new helper degrades to epoch 0 == 0 (accept), the
   documented pre-upgrade semantics.
   (v) **LINEAGE-GATED latch echo (v8.9, Codex r12 f6 +
   r13 f7):** the
   `stored_defer_workers` status echo reconciles the manager
   flag and the Go cache ONLY under the same lineage gate as
   (iii) — `status.config_epoch == m.acceptedConfigEpoch`
   AND `m.pendingConfigEpoch == m.acceptedConfigEpoch` —
   and ONLY while `m.compileInFlight` is FALSE (the
   StartDeferredCompile reservation, §5-C defer-intent
   atomicity: the intent and the in-flight flag are set in
   ONE m.mu section at the daemon's precheck decision, so a
   1 Hz poll can never observe intent-staged-but-unreserved
   and can never erase it mid-compile — the v8.7
   unconditional echo's pre-MAC race and the v8.8
   argument-only text's mid-compile arm-sync window (AGY
   r13 f3) are both dead; an old helper's missing echo
   (epoch 0) never reconciles because its epoch never
   matches).

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
   and diagnostics stay alive); the MAC debt's bounded blocking
   acquire (v8.8) has no starvation mode (periodic applySem
   owners hold ms-scale — a 10s bound always lands; the v8.7
   TRY-acquire phase-lock against the 30s proxy-ARP reconcile,
   daemon_proxyarp.go:16-24, dies — v8.9 fairness: FIFO
   waiter wake + bounded owner holds (worst legal hold ~20s,
   daemon_ipsec_rebind.go:91-100/:220-249) with a 30s acquire
   bound and try-lock-or-skip manager calls — starvation is
   unconstructible); the all-member pass-1 reread is
   budgeted at µs-scale netlink link-reads (≤ ~1ms for a
   12-member RETH — the precheck already performs
   per-member reads in the same critical path, Codex r13 f14).


**Completion machinery, durable and provenance-exact (Codex r5
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
    `m.pendingConfigEpoch` (mints), and every OBSERVED-ACCEPTED publish
    advances `m.acceptedConfigEpoch` — superseding any
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
    TRANSACTION (v8.9, Codex r13 f8): the SAME
    `PrepareLinkCycle`/`NotifyLinkCycle` quiescence pair the
    commit path uses (disable ctrl, join all workers, then
    DOWN→MAC→UP) — a GLOBAL quiesce-all + rebind-all outage
    per recovery completion, explicitly accepted and budgeted
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
  - **Debt execution ownership + serialization, v8.9 work-pull
    form (Codex r13 f9/f10, replacing v8.8's two-method
    sketch):** the debt SCHEDULER and ALL netlink
    execution live DAEMON-side (the daemon owns the capacity-one
    `applySem`, daemon.go:485-496, and every repair primitive);
    the debt STATE (the three collections, the epoch key, the
    backoff clock, the settlement bookkeeping) lives
    manager-side under `m.mu`. The interface is a PULL pair
    (the v8.8 methods could not supply work — the daemon had
    no way to learn due members/phases/deadlines/desired MACs,
    and `ApplyResult` (apply.go:97-117) carries only the
    ordinary generation — so `ApplyResult` ALSO gains the
    commit-seq epoch field, §6):
    `ClaimMACDebtWork() (epoch uint64, due []MACDebtWorkItem,
    claimToken uint64)` — the manager (under `m.mu`) returns
    the currently-due work items
    (`MACDebtWorkItem{Interface string; WantMAC [6]byte;
    Phase uint8; Collection uint8; Deadline time.Time}`) and a
    monotonic `claimToken` bumped on EVERY debt membership or
    epoch change (a same-epoch operator cancellation bumps it
    — the token, not the epoch check alone, is the
    linearization fence); and
    `ReportMACDebtAttempt(claimToken uint64, results
    []MACDebtMemberResult) (settled bool)` — the manager
    accepts results ONLY when `claimToken` is current (a
    stale token's results are discarded wholesale: a
    cancellation between Claim and Report can never be
    resurrected by in-flight work) and updates the
    collections under `m.mu`, with `settled=true` authorizing
    the daemon to dispatch the tagged completion through the
    EXISTING `NotifyLinkCycle` path.
    The daemon's apply flow reports validation pass 1 through
    `ReportMACDebtAttempt` in-flow (applySem already held).
    **Lock hierarchy, v8.9 precise form (Codex r13 f10):**
    `applySem > m.mu`, ONE direction — and the rule is NOT
    "the manager never calls the daemon" (already false:
    the async `OnXSKBound` dispatch is manager-side,
    maps_sync.go:451-456) but "no SYNCHRONOUS manager→daemon
    call while holding `m.mu`" — poll-detected needs (the
    re-sync debt, the env-dispatch) are RECORDED under `m.mu`
    and EXECUTED after release via the daemon-drained bounded
    channel (enqueue-after-unlock). `applySem` is
    daemon-private (no manager code references it — the
    m.mu → applySem half is unconstructible, AGY r13 f4
    answered). **Fairness (Codex r13 f10):** attempts
    BLOCKING-acquire `applySem` with a 30s context —
    x/sync/semaphore wakes waiters FIFO and the worst legal
    owner hold is bounded (the IPsec rebind's ~20s,
    daemon_ipsec_rebind.go:91-100/:220-249, is the maximum;
    the 30s proxy-ARP reconcile and commits are ms-to-seconds
    scale) — so every acquire lands within
    queue-depth × max-hold (the v8.8 10s bound could
    time out behind a single IPsec hold; the 30s bound plus
    FIFO makes starvation unconstructible, and a timed-out
    attempt simply retries at its own backoff tick).
    `ClaimMACDebtWork` and `ReportMACDebtAttempt` are
    TRY-LOCK-OR-SKIP on `m.mu` (an attempt that finds the
    manager contended — e.g. the status loop mid-control-
    request, whose deadlines reach 120s
    (process_status.go:185-200, process_control.go:52-56) —
    skips to its next backoff tick rather than monopolizing
    `applySem` while blocked on `m.mu`). The #5134
    `pendingWorkerArm` Boolean is epoch-qualified (records
    the commit seq) and CLEARED on supersession (Codex r13
    f9: a superseded one previously kept suppressing the
    generic activation retry forever).
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
  `config_epoch`, and the helper's rebind handler REFUSES a
  completion whose expected epoch differs from its stored
  snapshot's `config_epoch` (stale-completion
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
  **Defer-intent atomicity (v8.8, Codex r12 f6's poll-vs-Compile
  race):** the daemon's pre-Compile `SetDeferWorkers(true)` call
  is DELETED — the defer intent travels as a Compile ARGUMENT
  (the daemon precheck's decision) and is set under `m.mu`
  INSIDE Compile before any publish, with `snap.DeferWorkers`
  stamped in the same critical section (manager_compile.go:330-332's
  read becomes the same-lock write). A 1 Hz status poll can no
  longer observe intent-staged-but-snapshot-unstamped, and the
  (v) latch echo (§5-C fabric transaction) reconciles only when
  no compile is in flight — so B can never be published
  non-deferred by a racing poll (the pre-MAC activation race
  stays dead).
  **UNKNOWN-outcome ownership, v8.9 daemon-owned single-flight
  form (Codex r13 f5, replacing v8.8's ownerless poll
  re-apply):** Go treats a timeout/EOF apply as NOT accepted
  (the flag rolls back, A's debts stay alive, NO epoch
  move — Compile commits its bookkeeping only after a
  clean response, manager_compile.go:350-365, while the write
  can land before response decoding fails,
  process_control.go:145-161; the staged snap is DISCARDED, and
  the next commit gets a strictly newer commit seq, never B's —
  the v8.8 "re-apply the active config" sketch had no production
  owner: the status loop is manager-local, holds `m.mu`, and has
  no daemon/configstore hook, and "the manager never calls the
  daemon" forbade the inline path). The v8.9 owner is the
  RE-SYNC DEBT, a daemon-driven single-flight work item: the
  status poll DETECTS helper-ahead (`status.config_epoch >
  m.acceptedConfigEpoch`) and RECORDS the debt under `m.mu`
  (enqueue-after-unlock, Codex r13 f10 — no manager→daemon
  call while holding `m.mu`; the dispatch rides a bounded
  channel the daemon drains, the same async shape as the
  existing manager-side `OnXSKBound` dispatch,
  maps_sync.go:451-456); the daemon's scheduler drains it,
  acquires `applySem`, re-reads the ACTIVE config from the
  configstore (the control-plane commit already landed), and
  drives the dataplane RE-APPLY of that active config
  (`ApplyConfig` — NOT a new configstore commit, so the carried
  seq is B's OWN seq, matching the landed helper state) —
  a fresh compile whose content is identical (idempotent),
  whose three-bucket precheck re-instantiates the debts, and
  whose observed-accepted publish advances
  `m.acceptedConfigEpoch` to it. During the divergence EVERY
  older-lineage producer is suppressed AND the helper's
  epoch-rollback refusal is the backstop (§5-C (iv)), so a
  stale #5134 retry can never overwrite the landed B and
  erase the signal (the v8.8 overwrite class is dead). A
  FAILED re-apply (UNKNOWN again) retries on the re-sync
  debt's own backoff (5/10/30/60s + edge Warn) and never
  cancels anything; the debt CLEARS only on the observed
  matching acceptance (not an unrelated clean status). Both
  the B-with-MAC and B-without-MAC shapes take this path.

  **Defer-intent reservation, v8.9 StartDeferredCompile form
  (Codex r13 f7 + AGY r13 f3, reconciling Codex r12 f6's
  poll-race with the mid-compile arm-sync coverage):** the
  daemon's precheck decision point
  (daemon_apply_dataplane.go:69-72) calls a NEW manager
  method `StartDeferredCompile()` — ONE `m.mu` section that
  sets `m.deferWorkers = true` AND `m.compileInFlight =
  true` — replacing the bare `SetDeferWorkers(true)` (the
  v8.8 "intent as a Compile argument" text is deleted:
  `ApplyConfig(ctx, cfg)` has no options argument
  (apply.go:37-40's ConfigSink), so an argument could never
  have reached Compile, and an intent set only at the
  pre-publish stamp would reopen the mid-compile arm-sync
  window (Compile builds outside `m.mu`,
  manager_compile.go:177-228, while the status loop's
  desired-arm reconciliation could fire)). Every Compile
  exit — success, failure, or the apply flow's deferred
  clear — clears `m.compileInFlight` under `m.mu`
  (rollback on every exit path). The arm-sync gate reads
  the intent from the reservation point (the mid-compile
  window is covered), the (v) latch echo skips while
  `m.compileInFlight` (the poll-race is dead), and
  `snap.DeferWorkers` stamps from `m.deferWorkers` in the
  publish leg's critical section (manager_compile.go:330-332,
  unchanged).

- **The epoch contract, v8.9 commit-lineage form (Codex r13
  f2/f3/f4/f5; supersedes the v8.8 mint/carry contract, which
  could not represent ambiguous post-write failures, could not
  clone staged configs safely, and could not transfer dedup
  lineage).** `config_epoch` IS the configstore's globally
  monotonic archive sequence of the committed config being
  published (`archiveSeq`, store.go:233-245, bumped per commit
  at store_commit.go:304, GLOBALLY monotonic across daemon
  restarts per store_persist.go:472-579) — node-local (each
  node commits the peer's synced config locally, so HA epochs
  are per-node, consistent with the v8.5 role-based
  authority), never reused (a rollback/auto-revert is a NEW
  commit with a NEWER seq), and requiring NO allocator of any
  kind (the commit's seq exists before the dataplane is
  involved, so an ambiguous post-write failure cannot alias:
  the next config commit gets a strictly newer seq — Codex r13
  f2's reuse class dies by construction; same-config Compile
  invocations — the initial compile, the mandatory live-MAC
  re-apply, the active-config re-apply — all carry the SAME
  commit seq, Codex r13 f2's "several epochs per config"
  objection dies likewise). The manager tracks
  `m.pendingConfigEpoch` (the commit seq of the newest STAGED
  config — set at staging; a failed BUILD stages nothing and
  changes nothing) and `m.acceptedConfigEpoch` (the commit seq
  of the newest OBSERVED-ACCEPTED published config — advanced
  on (a) the clean compile publish legs
  (manager_compile.go:361/:365), (b) the pending-XSK deferred
  publish's clean leg AND the status-catch-up leg
  (process_status.go:18-37/:120-139 — the two legs the v8.8
  "ONLY" list omitted, Codex r13 f3), and (c) the re-sync's
  observed active-config re-apply). EVERY full-publish
  producer — the complete census is FIVE (Codex r13 f3):
  normal Compile publish, pending-XSK deferred publish, route
  overlay (manager_overlay.go:188-239), scheduler republish
  (manager_compile.go:575-621), and the #5134 clone-republish
  (manager_worker_arm_5134.go:57-92) — carries the commit seq
  OF THE CONFIG IT CONTAINS (a clone of staged B carries B's
  seq — the v8.8 "clones carry acceptedConfigEpoch" rule,
  which would have published B's content under A's lineage, is
  DELETED); `update_neighbors` (manager_neighbor.go:97-112;
  Rust mutates only the neighbor table, neighbors.rs:42-57)
  and `bump_fib` (snapshot.rs:470-473) are NOT full applies
  and never touch the epoch. **Epoch-rollback refusal
  (v8.9, Codex r13 f5):** the helper REFUSES an
  `apply_snapshot` whose `config_epoch` is STRICTLY LESS than
  its stored epoch (fail-closed, no mutation, no persist —
  mirroring #3767 H5's fib-rollback guard): a stale A-lineage
  clone (a #5134 retry carrying A's seq while the helper has
  landed B's) can never overwrite the newer config, so the
  helper-ahead signal survives for the re-sync. **Dedup
  lineage transfer (v8.9, Codex r13 f4 = AGY r13 f1 =
  SMR r13 SMR13-1):** the builder hash
  (builder.go:156-178) excludes generation/fib/time/pointer
  AND `config_epoch` (a lineage field, not content). A staged
  config whose forwarding content equals the incumbent's
  dedup-skips its publish (process_status.go:72-80); the
  manager then issues a `note_config_epoch` control message
  (§6 — a NEW additive verb carrying ONLY the staged commit
  seq; the helper sets its stored `config_epoch` to it, no
  snapshot mutation, persisted, echoed) and, on the observed
  success, sets `m.acceptedConfigEpoch =
  m.pendingConfigEpoch`. A FAILED/UNKNOWN transfer leaves the
  suppression engaged (fail-closed) until the next successful
  poll — the v8.8 local-collapse rule, which wedged the
  adoption gate AND the fence against the helper's un-updated
  stored epoch, is DELETED.
  **Mixed-version (v8.9, Codex r13 f6):** an old helper
  echoes epoch 0 forever and ignores the fences, so ALL
  lineage-sensitive operations (the adoption gate, the (v)
  latch echo, the fabric fence, the tagged completion) FAIL
  CLOSED while the observed epoch is 0 — never sending or
  adopting on an unnegotiated lineage — until the REQUIRED
  helper restart on upgrade brings a new helper up (the
  startup re-apply then carries the epoch). The D gate +
  restart requirement bound the window operationally; the
  fail-closed-on-zero rule closes it technically.
  Debts key on the commit seq of the config whose precheck
  created them and fire only while that seq IS
  `m.acceptedConfigEpoch` (v8.9 uniform form, SMR r13
  SMR13-3): the #5134 debt (created post-publish, key = the
  just-accepted seq), the MAC debt (created at epoch opening,
  key = the deferred config's seq), and the re-sync debt
  (created pre-publish, key = the re-applied config's
  `m.pendingConfigEpoch`; fires the re-apply on its own
  backoff; settles when `m.acceptedConfigEpoch` reaches the
  key). The
  #5134 direct retry carries the accepted seq and never
  changes any epoch state; its success
  settles its own debt exactly once (its purpose) with any
  still-needed recovery entries re-derived by the mandatory
  same-config re-apply's precheck when one runs. A pending-XSK
  staged compile stages B with B's commit seq and
  RETAINS its precheck cohort + pass-1 results in the debt
  keyed on that seq (Codex r12 f12's handoff): the deferred
  publish carries B's seq, the observed acceptance
  advances `m.acceptedConfigEpoch` to it, and the completion
  evaluates against the RETAINED results — no precheck re-run,
  no atomic A→B debt transfer problem.
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
`pendingConfigEpoch` and supersedes node-local debts; the latch
authorities converge through the applied config's own publish
(a full apply stamps `defer_workers` from the peer config;
clean → all three on observed acceptance; unknown → the (b)
re-sync owns it);
(g) HELPER RESTART (v8.8, Codex r12 f6 — an authority
transition, not an exit): an unhealthy or config-driven helper
restart (process.go:18-33) resets the helper's stored state
to epoch 0; the next poll observes helper-behind (epoch 0 ≠
`m.acceptedConfigEpoch`), the startup re-apply republishes
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
additions: the `config_epoch` commit-lineage wire field +
epoch-gated adoption + `expected_config_epoch` fence/tag +
`note_config_epoch` + the epoch-rollback apply refusal (~35),
the causal env token (one-sample, ≤4 ack-set, incarnation
reset, debounced dispatch) (~20), the fabric sync debt state
machine + readiness AND (~25), the three-obligation debt +
all-member pass-1 reread + the Prepare/Notify recovery
transaction (~40), the work-pull Claim/Report + claimToken +
StartDeferredCompile + ApplyResult epoch (~30), the
re-sync debt (daemon-driven, single-flight) + suppression of
all old-lineage producers (~20), the operator provenance wire
field + operator-verb retry debt (~15), the nil-config
`stopLocked` clears (~6), the rebind/fabric refusal ordering
(~8), and the `stored_defer_workers` echo + gated
reconciliation (~8). No
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
  3. `ConfigSnapshot.config_epoch: u64` (serde default 0; v8.9
     commit-lineage semantics, Codex r13 f2/f3/f4/f5): the
     configstore's globally-monotonic archive sequence
     (`archiveSeq`, store.go:233-245/store_commit.go:304) of the
     committed config the snapshot CONTAINS — every full apply
     carries its own config's commit seq (compiles the staged
     seq, clones/overlays the contained config's seq); the
     helper stores it from each accepted apply alongside
     `generation` (snapshot.rs:153's sibling) and REFUSES an
     `apply_snapshot` carrying a STRICTLY-OLDER seq
     (epoch-rollback refusal, mirroring #3767 H5). Old Go
     omits it (0); old helpers ignore it.
  4. `StatusSnapshot.config_epoch: u64` (serde default 0; v8.8):
     the stored snapshot's epoch echoed into every full status —
     the lineage value for the adoption gate (iii), the latch
     echo gate (v), divergence suppression, and the re-sync's
     helper-ahead detection.
  5. `ControlRequest.expected_config_epoch: u64` (serde default 0
     = "no expectation"; old helpers ignore it). Sent on
     the tagged completion rebind (the debt's commit seq) AND on
     `update_fabrics` (the derivation config's commit seq); the
     helper REFUSES a nonzero expectation that differs from its
     stored `config_epoch` — the check ordered FIRST in each
     handler, before any field clearing/guard evaluation/
     mutation/persist (stale-completion / diverged-fabric,
     retryable, NO mutation).
  6. `ControlRequest.note_config_epoch: u64` (serde default 0 =
     absent; v8.9, Codex r13 f4 = AGY r13 f1 = SMR r13 SMR13-1):
     the dedup lineage-transfer verb — on a content-dedup skip
     the manager sends the staged config's commit seq; the
     helper sets its stored `config_epoch` to it (NO snapshot
     mutation), persists, and echoes it; Go marks
     `m.acceptedConfigEpoch = m.pendingConfigEpoch` on the
     observed success; a failed/UNKNOWN transfer leaves
     suppression engaged (fail-closed).
  7. `ControlRequest.provenance: string ∈ {"operator",
     "automatic"}` on `set_forwarding_state` (serde default
     `"operator"`; v8.9, Codex r13 f7): the helper clears the
     defer latch on a FALSE verb ONLY for `"operator"`; an
     `"automatic"` FALSE disarms the dataplane but preserves
     the epoch and debts. Old Go omits it → `"operator"` (the
     historical latch-clearing semantics the operator expects);
     new Go tags every automatic disarm explicitly.
  8. `StatusSnapshot.stored_defer_workers: bool` (serde default
     `false`; v8.7, Codex r11 f5; v8.9 reconciliation is (v)
     lineage+`compileInFlight`-gated per Codex r12 f6 + r13 f7):
     the stored snapshot's
     `defer_workers` echoed into every full status so Go's
     lost-response exit paths reconcile the manager flag and the
     Go cache from the helper's truth — only under the epoch
     gate with no compile in flight.
  9. `StatusSnapshot.guard_env_generation: u64` + 
     `StatusSnapshot.rejected_projections: []string` (serde
     defaults; v8.9, Codex r13 f11): the helper's monotonic
     guard-environment counter — ONE captured
     sample per guard evaluation (verdict and token derive from
     the same sample) — plus the identity hashes of the bounded
     (≤4) retained rejected-projection set the watch covers
     (the ack Go's suppression cache keys on; a lost rejection
     response just re-sends and re-acks); echoed on
     full statuses and `update_fabrics` guard-rejection
     responses; Go's suppression cache resets on helper
     (re)spawn (incarnation-scoped).
- **Go manager state:** `m.pendingConfigEpoch` (the commit seq
  of the newest STAGED config — set at staging; a failed build
  stages nothing) and `m.acceptedConfigEpoch` (the commit seq of
  the newest OBSERVED-ACCEPTED published config); plus
  `m.compileInFlight` (the StartDeferredCompile reservation's
  in-flight flag, cleared on every Compile exit), the fabric
  sync debt (keyed `(config_epoch, projection-hash)`, states
  {pending, retrying, failed-warned}), the re-sync debt
  (single-flight, daemon-driven), and the operator-verb retry
  debt. The v8.7 `ConfigGeneration` snapshot field and the
  v8.8 mint/carry contract are DELETED.
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
  `set_queue_state`, `apply_snapshot`, `rebind`, `update_fabrics` —
  signatures and response shapes unchanged. `set_binding_state` slot
  addressing is unchanged (slots remain positional).
- **Go manager API:** the manager gains the epoch/debt state
  (`m.deferWorkers`, `m.pendingConfigEpoch` +
  `m.acceptedConfigEpoch`, `m.compileInFlight`, the
  three-obligation MAC debt
  (`macEpochDebt` + `macAndLinkRecovery` + `linkOnlyRecovery`),
  the fabric sync debt, the re-sync debt, the operator-verb
  retry debt, and the pending-retry state) and the
  tagged/untagged rebind issuance
  rules — all manager-internal; D and the arm-sync defer gate are
  likewise manager-internal. The **LinkController interface
  (daemon.go:485 / apply.go:130) gains THREE daemon→manager
  operations** (v8.9 work-pull contract, Codex r13 f9/f10 —
  the interface's
  actual direction is daemon→manager: `userspaceLinkController`
  wraps `*Manager` (controllers.go:36-40, manager.go:379-381)
  and the daemon calls INTO the manager):
  `StartDeferredCompile()` — one `m.mu` section setting
  `m.deferWorkers = true` AND `m.compileInFlight = true` at
  the daemon's precheck decision point (replacing the bare
  `SetDeferWorkers(true)` at daemon_apply_dataplane.go:70);
  `ClaimMACDebtWork() (epoch uint64, due []MACDebtWorkItem,
  claimToken uint64)` — the pull model's work handout (due
  members/phases/desired MACs/deadline + the linearization
  token); and
  `ReportMACDebtAttempt(claimToken uint64, results
  []MACDebtMemberResult) (settled bool)` — accepted only
  while `claimToken` is current (stale-token results
  discarded wholesale), updating the collections under
  `m.mu`, with `settled=true` authorizing the daemon to
  dispatch the tagged completion via the EXISTING
  `NotifyLinkCycle` path.
  **`ApplyResult` gains the commit-seq epoch** (apply.go:97-117
  currently carries only the ordinary generation, Codex r13
  f9) so daemon-side schedulers learn the applied config's
  epoch without a second lookup.
  **Fabric sync debt (v8.9, Codex r13 f12):** keyed
  `(config_epoch, projection-hash)`, states
  {pending → retrying (5/10/30/60s, driven by the fabric
  ticker + event wakeups + the env-dispatch) → failed-warned
  (edge Warn, retrying at the 60s floor)}; cleared ONLY by a
  clean MATCHING sync; superseded by a newer projection;
  exposed to the daemon's takeover-readiness path through the
  existing HA controller (readiness ANDs `fabricPopulated`
  with "no outstanding debt for the current projection").
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
      tagged retry carries `expected_config_epoch = E_a`
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
      `config_epoch` — the completion carrying `E_a` is
      ACCEPTED after each (assert: no false refusal after any
      churn class);
      AND the ownerless-B re-sync (Codex r12 f5 + AGY r12 f1 +
      r13 f5/f10): after the lost-ACK B, Go has DISCARDED the
      staged snap
      (manager_compile.go:350-365) and the next commit gets a
      strictly-newer commit seq — the
      recovery is the DAEMON-DRIVEN RE-SYNC DEBT: the next
      status poll observes helper-ahead
      (`status.config_epoch > m.acceptedConfigEpoch`) and
      RECORDS the debt under m.mu (enqueue-after-unlock — NO
      inline manager→daemon call, assert none); the daemon's
      scheduler drains it, acquires `applySem`, re-reads the
      ACTIVE config, and drives the dataplane RE-APPLY (`ApplyConfig`,
      NOT a new configstore commit — the carried seq is B's own,
      generation, the ACTIVE config's own commit seq —
      assert the helper's epoch-rollback refusal PASSES
      because stored B's seq equals the re-applied seq);
      DURING the divergence a stale A #5134 retry is
      SUPPRESSED and, forced anyway, REFUSED by the helper
      (epoch-rollback — assert B is never overwritten and the
      helper-ahead signal never erased, Codex r13 f5); the
      observed-accepted publish advances
      `m.acceptedConfigEpoch`,
      supersedes A's debts, and B's completion is driven by the
      freshly instantiated debt carrying the new epoch
      (accepted) — assert the full handoff with no operator
      action; the SAME lost-ACK shape WITHOUT MAC work takes the
      SAME owner (the v8.7 test's "the next apply" fallback is
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
      PLUS the v8.9 additions: a lost GLOBAL DISARM (operator
      provenance — latch clears on retry via the durable
      operator-verb retry debt; automatic provenance — epoch
      PRESERVED, recovery self-heals; and the WIRE tag: an
      old Go's untagged disarm defaults to operator), an old
      helper's MISSING `stored_defer_workers` echo (epoch 0 —
      never reconciles), a FRESH helper post-restart (epoch 0 →
      helper-behind → startup re-apply), a mid-defer helper
      restart (transition (g)), the mixed-version
      timeout-but-landed B with an OLD helper (epoch 0 — ALL
      lineage-sensitive operations fail closed, no A-fabrics
      into B, Codex r13 f6), the poll-vs-Compile race
      (StartDeferredCompile sets intent+inFlight in ONE m.mu
      section at the precheck point — a poll during the
      window can NOT erase the intent (the (v) echo skips on
      `m.compileInFlight`), the mid-compile arm-sync reads
      the intent from the reservation point (AGY r13 f3's
      window covered), and B is never published non-deferred,
      Codex r12 f6 + r13 f7), the epoch-RESERVATION cases
      (Codex r13 f2: a pre-wire build failure stages nothing
      and burns nothing — the NEXT config commit carries a
      strictly-newer seq; an ambiguous post-write failure can
      never alias because commit seqs never recycle), the
      staged-B producer census (Codex r13 f3: with pending-XSK
      B staged, a route overlay, a scheduler republish, and a
      #5134 retry each carry the CONTAINED config's seq — the
      B-clone publishes B under B's own lineage, and an A-clone
      is suppressed AND epoch-rollback-refused), and the two
      deferred-acceptance legs (Codex r13 f3: the pending-XSK
      deferred publish's clean leg AND the status-catch-up leg
      (process_status.go:18-37/:120-139) each advance
      `m.acceptedConfigEpoch`);
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
      recorded WITH `m.pendingConfigEpoch`; (i) a
      plan-changing SUCCESSFUL commit (`m.acceptedConfigEpoch`
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
      the debt does not fire across it; (vi) the full mint/advance
      matrix (Codex r8 M8 + r12 f12): boot-time first config, a
      DHCP/feed
      driven apply, an HA-peer config sync, a rollback to an OLDER
      config, a `commit confirmed` auto-revert, and a background
      full recompile — each COMPILED config mints
      `m.pendingConfigEpoch` at compile acceptance, and each
      OBSERVED-ACCEPTED publish advances `m.acceptedConfigEpoch`
      to the carried value
      by design; the advance points are the compile publish legs
      (manager_compile.go:361/:365) ONLY — NOT :575-621 (the
      policy-scheduler overlay republish, an overlay carrying
      the accepted epoch — the v8.7 citation of :618 was wrong,
      Codex r12 f12);
      AND (Codex r11 f6 + r12 f12) a pending-XSK staged compile
      mints `m.pendingConfigEpoch` at staging and RETAINS its
      precheck cohort + pass-1 results in the debt keyed on that
      epoch — the deferred publish carries the pending epoch,
      the observed acceptance advances the accepted epoch, and
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
      `status.config_epoch == m.acceptedConfigEpoch` AND
      `m.pendingConfigEpoch == m.acceptedConfigEpoch`
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
      its publish; the manager then issues `note_config_epoch`
      (B's commit seq) — assert the helper sets its stored
      `config_epoch` to B's seq WITHOUT any snapshot mutation
      (persisted + echoed), Go marks
      `m.acceptedConfigEpoch = m.pendingConfigEpoch` ONLY on
      the observed success, adoption proceeds under the gate,
      and a FAILED/UNKNOWN transfer keeps suppression engaged
      (fail-closed, assert no adoption and no fenced send); AND the REQUEST-SIDE
      fence (Codex r11 f3 + r12 f2): a diverged `update_fabrics`
      fence (Codex r11 f3 + r12 f2): a diverged `update_fabrics`
      send is
      SUPPRESSED Go-side (staged-ahead or helper-ahead), and a
      forced send carrying a mismatched
      `expected_config_epoch` is REFUSED by the helper
      with NO fabric mutation and NO persist (assert the stored
      snapshot's fabrics byte-identical); (ix) the
      nil-config bootstrap teardown — a shutdown with no accepted
      config cancels any open epoch/debt explicitly AND clears
      `m.deferWorkers` AND `m.lastSnapshot.DeferWorkers` (all
      three authorities, Codex r11 f5); (x) the HA reverse-sync pair — an
      actually-accepted reverse/older peer config
      (daemon_ha_sync.go:534) mints `m.pendingConfigEpoch` and
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
      ENV-GATED resend suppression (v8.9 CAUSAL+ACKSET form,
      Codex r13 f11 — the v8.8 form lacked loss-safety and a
      flap bound): (a) ONE SAMPLE PER VERDICT — the guard's
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
      re-arms B — replace-oldest on a fifth); (c) INCARNATION
      SCOPING — Go's suppression cache resets on every
      manager-driven helper (re)spawn; (d) DEBOUNCED DISPATCH
      — the status poll that observes a bump with a suppressed
      identity dispatches at most once per identity per 5s
      (assert a SUSTAINED 1 Hz sysfs flap coalesces to ≤0.2
      dispatches/s, each guard-rejected cycle re-enabling
      ctrl in the same RPC tick — no unbounded 1 Hz ctrl
      oscillation, Codex r13 f11); (e) a
      guard-rejected identity with an UNCHANGED
      `guard_env_generation` is never resent (no pulse); and
      the helper bumps the generation ONLY on
      input change (two consecutive evaluations with identical
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
      the failure records a debt keyed `(config_epoch,
      projection-hash)` with the map commit STANDING (assert:
      the BPF map mutation is NOT rolled back); the debt
      retries on the ticker/wakeup/dispatch cadence; a CLEAN
      MATCHING sync clears it (assert an unrelated clean status
      does NOT, and a stale fab0/fab1/clear retry cannot clear
      a NEWER projection's failure — keyed supersession);
      takeover readiness ANDs `fabricPopulated` with
      no-outstanding-debt-for-the-current-projection (assert a
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
- The fail-fast invariant (Q6, resolved r1): assertions live ONLY
  in tests and only over well-defined planner/activation
  transitions.
- Protocol canaries: `userspace-dp/src/protocol/tests.rs`
  exact-schema snapshots updated to pin `activation_state`,
  `complete_deferred`, `config_epoch` (snapshot + status),
  `expected_config_epoch`, `note_config_epoch`, `provenance`,
  `stored_defer_workers`, `guard_env_generation`, and
  `rejected_projections` deliberately — INCLUDING each field's
  missing-field semantics (old Go omits → serde defaults; old
  helper ignores → the documented degrade; a missing
  `stored_defer_workers` (epoch 0) never reconciles; a missing
  `provenance` defaults to operator).
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
      fairness proof in its v8.9 form (Codex r13 f10,
      superseding all prior forms): (a) the autonomous attempt
      BLOCKING-acquires applySem with a 30s context — a
      synthetic owner holding for a short window does NOT
      delay it past the bound, and a SEQUENCE of legal owners
      (a commit, then the 30s proxy-ARP reconcile, then a ~20s
      IPsec rebind hold) still lands the attempt
      (FIFO waiter wake + bounded holds — assert the acquire
      completes within queue-depth × max-hold, never the v8.7
      TRY-acquire phase-lock and never a 10s timeout behind a
      single IPsec hold); (b) a SEPARATE flow acquires the
      semaphore, completes the superseding accepted commit
      (advancing `m.acceptedConfigEpoch`), and releases it;
      the attempt then acquires, Claims with a STALE
      `claimToken` (the commit bumped it), its Report is
      DISCARDED wholesale (assert zero netlink calls — the
      claimToken, not the epoch check alone, is the fence);
      (c) the post-acquisition m.mu contention case: the
      status loop holds `m.mu` through a long control request
      (up to 120s) — the attempt's TRY-LOCK-OR-SKIP Claim
      skips to its next backoff tick (assert it does NOT
      monopolize `applySem` while blocked on `m.mu`); and the
      epoch-qualified `pendingWorkerArm` (Codex r13 f9): a
      superseded #5134 debt is CLEARED (assert the generic
      activation retry is not suppressed by a stale Boolean).
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
EPOCH-GATED adoption + fence on `config_epoch` ON THE WIRE, v8.8 —
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
the `config_epoch`-carried
`expected_config_epoch` refusal, v8.8), the ownerless re-latch
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

Remaining questions for round 14, each invitable to PLAN-KILL with
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
   `config_epoch` ON THE WIRE (v8.8 — the appliedSnapshot gate
   ALSO died: its capture is deliberately delayed while
   deferred and records the mutated scalar post-rebind); the
   request side is fenced by `expected_config_epoch` on
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
6. **Round-13 disposition table audit.** §1's r13 table maps
   every r13 finding (Codex 12 BLOCKER + 3 MAJOR; AGY 4 BLOCKER
   + 2 MAJOR; SMR 1 BLOCKER + 3 MINOR/NIT) to its v8.9 fold, and
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
   mode. Which of these, if any, is
   unacceptable for the severity-High class, and why?
