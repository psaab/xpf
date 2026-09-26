# pkg/eventengine

Event-driven automation engine implementing Junos-style `event-options`
policies. Matches RPM probe events against policy clauses (with optional
temporal `within` windows) and triggers commit-and-apply actions.

## Entry points

- `Engine` — `engine.go`.
- `New(store, commitFn)` — `engine.go`.
- `Apply(policies []*config.EventPolicy)` — `engine.go`. Loads policies,
  RECONCILING per-policy runtime state (see cooldown survives reload, below).
- `HandleEvent(evt)` — `engine.go`. Called by the RPM event callback. Evaluates
  under lock, pre-classifies the action, and enqueues it onto the single worker.
- `Close()` — `engine.go`. Stops the action worker; called from daemon shutdown.
- `Stats()` — `engine.go`. Counter snapshot for the `xpf_event_actions_*`
  metrics.
- `CommitFn` — `engine.go`. The atomic commit-and-apply hook.

## File layout (#7636)

`engine.go` crossed the 1500-LOC `[WATCH]` floor in #6810 and was split into
three cohesive units by a **verbatim move** — no behaviour change, so the diff
reads as a move:

- **`engine.go`** (943) — construction, `Apply`, `HandleEvent`, the action
  worker, `runAction`/`applyOnce`, cooldown arming, and the public accessors.
- **`queue.go`** (215) — action-queue *admission*: `enqueue`, `supersede`,
  `releaseEdgeLatch`, `actionQueueDepth`. A bounded-channel admission policy
  with its own concurrency contract (#5062, #5853, #2869, #6810).
- **`evaluate.go`** (427) — *evaluation*: `evaluateEvent`, `withinMatches`,
  `pruneWindow`, `attributesMatch`, `classifyPlan` and their helpers. The
  `within`-clause semantics (#3751, #3756, #7223, #4423) read as one subject
  and were previously separated from themselves by the worker code.

**The lock-order invariant is the thing the split makes easier to break**, and
it is therefore stated in all three places rather than once: `e.mu` (evaluation
and runtime state) and `enqueueMu` (admission) are **never nested in either
order**. `enqueue` runs after `evaluateEvent` has released `e.mu`, which is what
lets `releaseEdgeLatch` take `e.mu` at all — #6810's latch rollback would
deadlock against a held `enqueueMu`. Before the split the two locks were visible
on one screen; now they are not.

## Callers

`pkg/daemon` (event loop, RPM results). `pkg/api` reads `Stats()` for metrics.

## Dependencies

`pkg/config`, `pkg/configstore`, `pkg/rpm`.

## Daemon lifecycle (#3752 / #3755)

The daemon constructs the engine UNCONDITIONALLY at boot (`initEventEngine`,
`pkg/daemon`), mirroring the LLDP manager and DHCP relay: the `d.eventEngine`
pointer is written once and read-only thereafter (race-free `Stats()` reads),
and `reconcileEventOptions` applies the committed policy set at boot and on
every day-2 commit. Because the engine always exists, enabling the FIRST
event-options policy on a running daemon takes effect immediately instead of
being inert until a restart (#3752 — the old code constructed the engine only
when the boot config already had a policy).

`initEventEngine` also registers the RPM event callback BEFORE `reconcileRPM`
starts the probe goroutines. RPM runs each probe's first cycle immediately, so
a `ping_probe_failed`/`ping_test_failed`/`ping_test_completed` from that first
cycle would otherwise fire into a nil callback and be lost (#3755); registering
first closes the gap, and `pkg/rpm` additionally buffers-and-replays any event
fired before a callback exists as a belt against a future reorder.

## Cross-policy global action budget (#10871)

Per-policy cooldowns do not constrain a storm across many distinct policies.
The worker therefore admits at most **four commit attempts in any rolling
60-second window**, shared by every event-options policy. Four simultaneous
actions can still run as a burst; once exhausted, queued actions are dropped
before taking the config lock and counted by
`xpf_event_actions_dropped_total{reason="global_budget"}`. A denied `trigger on`
edge has its latch released, so a later edge can retry after budget capacity
returns.

Admission order rotates from the policy after the last budgeted commit. This
prevents the first four policies in config order from consuming every refill
while later planted policies starve.

**Throughput bound:** for 64 policies matching the same `ping_test_failed`
event, with no `within` threshold and failure edges every 3 seconds, the old
30-second per-policy cooldown could allow 64 serialized commits per edge and
up to 128 commits/minute. The global budget caps this at four commit attempts
per rolling minute (a 32× reduction); further actions are shed until an older
attempt ages out. `TestFlappingTargetGlobalBudgetAndOperatorLatency10871`
exercises this profile, verifies the 59-second boundary and next refill, and
holds an operator commit to a 500 ms SLO while the flapping actions are being
dropped. The test models a 25 ms per-action apply interval; it does not claim a
universal latency bound for a real apply that itself exceeds the SLO.

## Transactional batch (#2139)

A `change-configuration` action's `then` commands are applied as an
all-or-nothing transaction:

1. **Pre-classify** the `then` commands into a typed plan BEFORE touching the
   candidate. An unparseable `set`/`delete` or an unknown command type rejects
   the WHOLE batch immediately (no lock taken, no queue slot) and bumps
   `xpf_event_actions_rejected_total`.
2. **Apply to the candidate** (`EnterConfigure` clones the active config — the
   candidate IS the rollback). Any op error discards the candidate
   (`ExitConfigure`) and rejects the batch. **No partial apply ever commits.**
3. **Validate the whole candidate** with `CommitCheck()` before committing; a
   failure discards cleanly.
4. **Commit** through the daemon's atomic commit+apply (`CommitFn`, #846) so it
   serializes with operator commits.

A `delete` of a missing path is a **tolerated exception** (logged at Debug):
Junos `change-configuration` semantics, and a missing delete target is not a
half-applied batch.

**Audit description (#3754/#10874):** the remediation commit carries a
deterministic description — `event-options policy <name>:
<event>/<owner>/<test> (<n> commands) [local-only; not peer-synced]` — built by
`remediationDescription` from the triggering-event context captured on the
`plannedAction` at evaluate time. It is threaded into both the `CommitFn` (daemon
`commitAndApply` → `CommitWithDescription`) and the standalone
`store.CommitWithDescription` branch, so an autonomous config mutation lands in
commit/rollback history attributed to the policy and event that made it and
explicitly notes its deliberate node-local scope. Event-options changes are
intentionally not synchronized to the HA peer (#5962).
Regression-locked by
`TestRemediation_CommitCarriesAuditDescription` (fail-on-revert: reverting to
`commitFn(ctx, "")` leaves the comment empty and the test goes RED).

## Cooldown / window state survives a config reload (#2140)

Per-policy temporal state (sliding `within` windows + last-trigger time) is
held in a `policyRuntime` record separate from the immutable policy config.
`Apply` RECONCILES this state rather than recreating it (the proven
`pkg/ipmon` pattern): for each policy it carries the previous runtime forward
when `(policy name, semantic revision)` is unchanged, and resets it when the
policy is new, removed, or semantically changed. The semantic revision is a
hash of the match/action fields (sorted `Events`, sorted `AttributesMatch`,
`WithinClauses`, ordered `ThenCommands`); the policy name is the stable
identity. `Events` and `AttributesMatch` are sorted because they are SETS (a
bare reorder is not a redefine, #4423 L4); `ThenCommands` stay ordered because
command order is semantic.

This fixes the self-wipe: the daemon calls `Apply` on every commit, including
the engine's own remediation commit. With the old recreate-on-Apply, a policy
erased its own cooldown the instant it remediated, so the same event re-fired
with the cooldown defeated. Now the self-triggered commit re-applies the SAME
policy set (same revision) → state survives → the cooldown holds.

Note: if a remediation's `change-configuration` edits the event-options stanza
of the *triggering* policy itself, that policy's revision changes and its state
legitimately resets — a redefined policy re-arms.

The cooldown is **armed on a SUCCESSFUL commit, not at evaluate time** (#2157
SMR finding 3). `evaluateEvent` still *checks* the cooldown to avoid flooding
the queue, but the timestamp is written by the worker after a successful
commit, so a dropped/rejected action does NOT consume the cooldown — the next
legitimate trigger can retry.

### Revision-aware cooldown arm (#5311)

The arm-on-commit stamp is **conditional on the live runtime still being the
same generation that authorized the action**. `armCooldown(name, authRev)`
stamps `lastTrigger` only when `e.semRev[name] == authRev`, where `authRev` is
the action's `plannedAction.semRev`. The identity check and the stamp run
together under `e.mu`, so a concurrent `Apply` cannot swap the runtime between
them (no TOCTOU).

This closes a **name-based ABA** that violated the "a redefined policy re-arms"
contract above. A remediation whose own `change-configuration` redefines its
triggering policy (R1 → R2) commits synchronously; the daemon's commit callback
then reconciles the new config and calls `Apply`, which — because the semantic
revision changed — installs a **fresh re-armed runtime** (zero `lastTrigger`)
for the successor R2. The old revision-blind `armCooldown(name)` stamped
whatever runtime was under `name` at that instant, so it wrote **R1's completion
time onto the freshly re-armed R2**, suppressing R2 for the whole 30 s cooldown —
exactly the re-arm the reconcile just performed. Passing the authorizing
revision lets `armCooldown` detect the successor (`e.semRev[name]` now carries
R2's revision, `authRev` still carries R1's) and skip the stamp; R2 keeps its
zero `lastTrigger` and an immediately following event fires it. When the policy
was instead removed during the action, `e.semRev` has no entry and the mismatch
skips the (now absent) stamp too. The common case — a policy that does not
redefine itself — is unchanged: `authRev` still matches the carried-forward
runtime and the cooldown stamps as before. Regression-locked (fail-on-revert) by
`Test*_5311` in `engine_cooldown_rev_5311_test.go` — reverting to the name-only
stamp re-throttles the successor and the ABA tests go RED.

## Revalidate a queued action before commit (#3750)

A pre-classified `plannedAction` sits in the worker queue (and may retry for up
to 60 s on a held config lock) before it commits. Between enqueue and commit the
policy set can change under an operator commit, and the cooldown can be armed by
a sibling commit — so the action must be **revalidated against live engine state
immediately before it commits**, not applied blind.

Each action is stamped with the policy's **semantic revision as of the evaluate
that produced it** (`plannedAction.semRev`, captured under `e.mu` in
`evaluateEvent`). The worker's `applyOnce` calls `staleReason(a)` right after
`EnterConfigure` succeeds — while it holds the config lock, so **no operator
commit (hence no `Apply` that could remove or redefine the policy) can
interleave** until `ExitConfigure`. If the action is stale it is dropped (the
candidate is never touched), `applyOnce` returns the `errStaleAction` sentinel,
and `runAction` counts it on `xpf_event_actions_dropped_total{reason="stale"}`
and does **not** retry (staleness is terminal). Three fail-opens fold into this
one gate:

- **Policy removed (H1):** `e.semRev` has no entry for the policy. An operator
  committed a config that dropped this event-options policy while its remediation
  was queued/retrying; committing the stale batch would mutate config no active
  policy authorizes. Dropped.
- **Policy redefined (H2):** the live semantic revision differs from the action's
  stamped `semRev`. A same-name redefinition changed the policy's meaning; the
  OLD command set must not commit under the new definition. Dropped.
- **Cooldown active (H3):** a successful commit of the SAME policy is within the
  30 s cooldown window. The enqueue-time cooldown check in `evaluateEvent` races
  the arm-on-commit timing (the cooldown is armed only after a commit), so a
  duplicate can slip into the queue while the worker is blocked: the first event
  is already IN-FLIGHT in the worker (dequeued, retrying under the held lock), so
  the enqueue-time dedup finds no same-policy entry still QUEUED to supersede and
  the duplicate is enqueued. Re-enforcing the cooldown here at commit time
  suppresses the within-window duplicate instead of double-committing — restoring
  the documented "not more than once in any 30 s window" invariant even under lock
  contention.

Legitimate remediations are unaffected: distinct policies and a re-fire AFTER the
cooldown elapses pass the gate and commit. Regression-locked (fail-on-revert) by
`TestStale_*_3750` in `engine_stale_revalidate_3750_test.go` — removing the
`staleReason` gate makes the removed/redefined/duplicate batches commit and the
H1/H2/H3 tests go RED.

## attributes-match (regex, #2008 M7) — fail-closed at runtime (#2141)

`attributes-match "<event>.<attribute> matches <pattern>"` filters policy
triggering on a **regex** match of `<pattern>` against the event attribute
(Junos `matches` semantics). `<pattern>` is an RE2 regular expression.

- Unanchored patterns are substring matches (`Com` matches `Comcast`); anchor
  with `^...$` for an exact match.
- Supported attributes are `test-owner`, `test-name`, and (since #3756 H14) the
  static per-test config strings `target`, `routing-instance`, and
  `destination-interface`. They are defined once in
  `config.EventAttributesKnownFields` (the single source of truth consumed by
  both the commit-time validator and the runtime matcher — a drift-guard test,
  `TestEventAttributesKnownFields_MatchesRuntimeSwitch`, keeps them identical)
  and resolved from the `rpm.Event` populated at every `fireEvent` call site.
  This lets a policy key on "all probes to target X" or "all probes in
  routing-instance Y". Numeric attributes (`rtt`, `jitter`, loss threshold) and
  a `failure-reason` taxonomy remain deferred — see `docs/feature-gaps.md` M7.
- **Event-name scoping (#3753):** the `<event>.` prefix scopes the constraint
  to a single event of a multi-event policy. The runtime matcher applies a
  constraint ONLY when the current event equals its prefix, so
  `attributes-match "event_a.test-owner matches ^X$"` on a policy with
  `events [ event_a event_b ]` gates event_a alone and leaves event_b
  unconstrained (and vice-versa). Before this the prefix was dropped and the
  constraint gated EVERY event. The strict commit validator additionally
  rejects a prefix that is not one of the policy's declared events (it could
  never apply). Regression-locked by
  `TestAttributesMatch_EventNamePrefixScopesConstraint` /
  `TestAttributesMatch_PerEventScopingBothDirections` (eventengine) and
  `TestValidateEventAttributesMatchStrict_EventNameScope` (config).
- **Strict at commit (#2141):** `config.ValidateEventAttributesMatchStrict`
  rejects at commit not only an uncompilable regex (#2008 M7) but also a
  malformed line (no ` matches ` / no `.`) and an unknown `<field>` name. These
  were previously fail-OPEN: the runtime matcher silently DROPPED the
  constraint, turning targeted remediation into broad config mutation while
  commit succeeded.
- **Lenient on LOAD:** the tolerant load/peer-sync path downgrades the same
  error to a warning so an upgrading node boots through a config persisted by an
  older binary (mirrors every sibling validator).
- **Fail-CLOSED at runtime (#2124 doctrine):** a malformed/unknown line that
  slipped through a lenient load makes the policy NOT fire (rather than dropping
  the constraint and over-firing). This is surfaced by the boot-time
  lenient-compile warning plus `xpf_event_attributes_match_invalid_total`.
  **Behavior change:** a legacy config that booted with a typo'd constraint now
  *stops* firing that policy instead of over-firing — the safe direction.
- Compiled regexes are cached at `Apply()` time keyed by pattern string, so the
  event hot path never recompiles.

## Fail-safe action queue (#2157)

Remediation actions run on a **single serialized worker goroutine**, not on the
RPM probe goroutine that fired the event. Because `fireEvent` runs on per-probe
goroutines, two probes failing at once previously both raced into
`EnterConfigure` and one action was silently dropped. With the single worker,
only the worker ever enters configure mode on the engine's behalf, so that race
cannot occur.

- **Held config lock:** if `EnterConfigure` fails with
  `configstore.ErrConfigLocked` (an operator or REST/gRPC session holds the
  candidate), the worker RETRIES with bounded exponential backoff
  (200 ms → 5 s) up to a 60 s deadline, bumping
  `xpf_event_actions_retried_total`, instead of dropping. After the deadline it
  bumps `xpf_event_actions_dropped_total{reason="lock_held"}`. The sentinel is
  matched with `errors.Is`, not a fragile string match. The backoff sleep uses
  an explicit `time.NewTimer` + `Stop()` (via `newRetryTimer`), NOT
  `time.After`: when `stopCh` fires before the backoff elapses (daemon shutdown
  or `Apply` churn), the retry stops the timer immediately and releases the
  runtime timer instead of leaking an armed timer until it fires (#2890). With
  a doubling backoff toward the 5 s ceiling, orphaned `time.After` timers would
  otherwise accumulate across restart churn. Regression-locked by
  `TestRetry_TimerStoppedOnEngineStop` (fail-on-revert: it injects `newTimerFn`,
  parks the worker in the retry select under a held lock, closes the engine, and
  asserts the stop func was invoked — reverting to `time.After` never consults
  the seam and the test goes RED).
- **Bounded queue, dedup-by-policy (early — #5853):** the queue holds at most one
  pending action per policy — a newer trigger supersedes an older queued one (no
  value in applying a stale remediation twice). The dedup runs on **every**
  enqueue via `supersede()`, not only once the channel is full. The pre-#5853
  `enqueue` did an unconditional fast-path send and deduped only in the full
  branch, so while the worker was blocked behind the config lock a burst from ONE
  policy filled all 64 slots with redundant duplicates (later discarded by
  cooldown/staleness) and the NEXT remediation for an UNRELATED policy was dropped
  queue-full — one flapping policy could starve every other policy's remediation.
  Early dedup keeps a same-policy burst to a single slot, leaving the rest free.
  A same-policy replacement is a **benign** dedup (the newer equivalent action
  still runs — nothing is lost) and is counted as
  `xpf_event_actions_superseded_total`, **not** as a drop. A genuine capacity loss
  — the queue full of unrelated policies with no same-policy entry to evict, so
  the genuinely-unfittable new arrival cannot fit — bumps
  `xpf_event_actions_dropped_total{reason="queue_full"}` **exactly once per
  dropped action** (counted by `enqueue`; `supersede()` does NOT also count that
  overflow in its refill loop — it only counts a SURVIVOR it could not re-place).
  Loss is always counted, never silent, and never double-counted (#2869), and the
  benign dedup no longer inflates the alert-worthy `queue_full` metric.
- **FIFO ordering across policies (#2869):** the queue is FIFO. Each enqueue's
  `supersede()` drains/refills the queue to drop any stale same-policy entry, then
  re-enqueues the surviving OTHER-policy actions in their original order and
  places the new (superseding) action at the **TAIL** — never the head.
  Prepending the new action would let the newest event jump ahead of every older
  queued remediation (LIFO), starving older policies under sustained event
  frequency and reordering remediation against the order events were observed.
  Supersede therefore only ever drops/replaces the stale same-policy entry; it
  does not reorder unrelated policies. Locked by
  `TestSupersede_PreservesFIFOPlacesNewAtTail` (fail-on-revert: a prepend lands
  the new action at index 0 and the test goes RED).
- **Producer serialization — no capacity theft (#5062):** `HandleEvent`
  evaluates under `e.mu` but RELEASES it before `enqueue`, so many RPM-probe
  goroutines run `enqueue` concurrently. `supersede()` DRAINS the accepted
  actions into a private slice (opening slots) and then re-enqueues the
  survivors; without a producer lock a SECOND concurrent producer — via
  `enqueue`'s fast-path send OR its own `supersede` — could take a drain-freed
  slot between the drain and the re-enqueue, forcing `supersede`'s refill
  `default` branch to DROP a survivor (an already-accepted action for a DIFFERENT
  policy), losing it and its FIFO position (miscounted `queue_full`). ALL
  producer-side queue mutation now runs under a dedicated `enqueueMu` held across
  the WHOLE `enqueue` (fast-path send AND the `supersede` drain+refill), so the
  drain→re-enqueue is atomic w.r.t. other producers: the only concurrent actor
  left is the consumer (`actionWorker`), which only REMOVES items, so a
  drain-freed slot is never re-filled by anyone but `supersede` itself and every
  survivor is preserved exactly once, in FIFO order. `enqueueMu` is a
  producer-only leaf lock — never held while `e.mu` is held (`enqueue` runs after
  `evaluateEvent` released `e.mu`), and the consumer path (`staleReason` /
  `armCooldown`, which take `e.mu`) never takes `enqueueMu` — so there is no
  lock-ordering cycle and no deadlock (every channel op under `enqueueMu` is a
  non-blocking select-with-default). This is DISTINCT from #2869, which fixed
  same-policy ordering, not concurrent capacity theft. Locked by
  `TestSupersede_ConcurrentProducersConserveSurvivors` (concurrent barrier) and
  `TestSupersede_DrainStealWindowIsClosed` (deterministic drain→steal→drop
  window via the `afterDrainFn` seam) — both fail-on-revert if `enqueueMu` is
  removed (a survivor is dropped).
- A non-lock error (bad apply / CommitCheck reject) is a permanent failure: no
  retry, bumps `xpf_event_actions_rejected_total`.

## HA event-remediation publication (#10874)

The event engine's publication gate follows RG0 config writability. The daemon
closes it on RG0 demotion and opens it after the config store becomes writable
on promotion. An action already accepted by the worker stays pending while the
gate is closed; `ErrClusterReadOnly` is deferred rather than counted as a
permanent rejection. Closing the gate before demotion also avoids repeatedly
entering configure mode on the standby. Shutdown still abandons and counts an
in-flight deferred action.

Preserving the action matters because RPM emits `ping_test_failed` on a
pass-to-fail edge, not on every failed cycle. A failure edge consumed on the
standby does not recur merely because that node becomes primary. Relying on a
new probe failure instead would cost approximately `successive-loss threshold ×
test-interval`: with the current defaults (3 successive losses and a 60 s test
interval), that is about 180 s, a material delay for then-commands intended to
remediate a failure. The deferred action resumes as soon as promotion opens the
gate, without waiting for another probe threshold.

Event-options changes remain deliberately node-local and use `peerSyncNever`
(#5962); this fix does not push them to the peer. Commit history now marks each
such remediation `[local-only; not peer-synced]` so the expected divergence is
visible rather than mistaken for a replicated commit. The marker documents the
sync policy; it does not change it.

## Cancellable remediation commit (#2868)

A remediation commit (`CommitFn`) drives netlink updates, an FRR reload, and
Rust dataplane sync — seconds of work. The engine threads an **engine-lifetime
context** into `commitFn` (built in `New`, returned by `commitContext`, and
passed through `applyOnce`). `Close()` closes `stopCh` AND cancels that context
(`lifeCancel`), so a remediation commit in flight at daemon shutdown is
cancelled cleanly instead of running under an uncancellable `context.Background`
that would block termination past the systemd `TimeoutStopSec` SIGKILL. The
standalone (no-`commitFn`) `store.Commit()` branch is unaffected (it does not
take a context). Regression-locked by `TestCommit_CancelledOnEngineStop`, which
blocks a `commitFn` on `ctx.Done()` and asserts `Close()` aborts it with
`context.Canceled` (fails on the timeout if reverted to `context.Background`).

## Metrics (`pkg/api`)

`Engine.Stats()` backs:

- `xpf_event_actions_committed_total` (INCLUDES the committed-with-apply-debt
  subset, #5063)
- `xpf_event_actions_committed_with_debt_total` (#5063 — see below)
- `xpf_event_actions_rejected_total`
- `xpf_event_actions_retried_total`
- `xpf_event_actions_dropped_total{reason="lock_held"|"queue_full"|"stale"|"global_budget"}`
  (`stale` = revalidate-before-commit dropped a removed/redefined-policy or
  within-cooldown action, #3750; `global_budget` = the shared #10871 rolling
  commit-attempt budget was exhausted)
- `xpf_event_attributes_match_invalid_total`
- `xpf_event_action_queue_depth` (gauge)

## Commit-status classification (`CommitFn` is tri-state, #5063)

The daemon's `CommitFn` (`commitAndApply` → `applyAndSyncCommitted`,
`pkg/daemon/daemon_apply.go`) returns `(*config.Config, error)` and **the
returned config, not the error, is the authority on whether the generation was
promoted**:

- `(compiled != nil, nil)` — committed, active, dataplane armed. **Committed.**
- `(compiled != nil, err)` — committed, active, dataplane armed, but a
  **best-effort** subsystem (networkd write / Kea restart / host-inbound nft)
  is in **debt**. The generation is LIVE — **NOT a rejection.** `applyOnce`
  signals this as a `commitDebtError`; `runAction` counts it
  `committed` + `committedWithDebt`, arms the SAME-generation cooldown, logs a
  WARN, and does **not** retry.
- `(nil, err)` — the commit did NOT promote (bootstrap gate, compile/commit
  failure, or a required-protocol gate that DISARMED the dataplane). This is the
  **only genuine rejection** (`xpf_event_actions_rejected_total`).

Invariant: once a generation is promoted and armed, the engine's commit
counters, cooldown, and audit MUST record it as committed even if a best-effort
subsystem remains in debt. Before #5063, `applyOnce` discarded `compiled` and
returned `errBatch` on ANY error, so a live autonomous change was miscounted
rejected, no cooldown armed, and the same event could immediately re-commit —
false telemetry plus control-plane churn during an incident. Regression-locked
by `engine_armed_debt_5063_test.go` (fail-on-revert: the debt case goes RED if
`applyOnce` re-discards `compiled`).

## Temporal `within` trigger semantics (#3756)

`within <seconds> { trigger on N }` / `{ trigger until N }` are pinned to the
Junos reading in `withinMatches` (`evaluate.go`):

- **The window is range-checked at evaluate time, not trusted (#8597).**
  `within` is bounded to `[config.MinEventWithinSeconds,
  config.MaxEventWithinSeconds]` (1..86400) by
  `validateEventOptionsWithinAST`, and that file notes the 24h ceiling is
  also what keeps `Seconds * time.Second` inside int64 nanoseconds. The
  gate is STRICT-only: the tolerant Load / peer-sync ingress downgrades a
  violation to a warning and the compiler stores the raw `strconv.Atoi`
  int — the same ingress the #3751 belt exists for. A large enough value
  overflows the multiply and the residue can be small and POSITIVE, which
  the #3751 `Seconds <= 0` check cannot see.
  `withinWindow` re-checks the range against the config constants (never
  a copied `86400`: two layers that disagree about the ceiling would be
  the defect, not the fix) and fails CLOSED, which matters because the
  consequence SPLITS by clause shape — an overflowing **`trigger until`**
  clause counts 0, satisfies `0 > N` as false, and fires on EVERY event.
  On the self-mutating surface that is an unauthorized remediation loop
  throttled only by the 30s cooldown; the `trigger on` shape merely goes
  dead. `pruneWindow` needs the check independently: it is not gated by
  the PASS-1 belt, and a wrapped `maxWindow` would discard the history of
  every event the policy watches, including its well-formed clauses'.

- **`trigger on N` is EDGE-triggered** — the policy fires on the threshold
  CROSSING (the in-window count first reaching N), NOT on every event while the
  count stays at or above N. A per-`(policy, event)` latch (`policyRuntime.
  onLatched`) records that a crossing already fired; it is set in
  `evaluateEvent` only AFTER the cooldown check passes (a cooldown-suppressed
  crossing is not consumed) and re-armed (cleared) by `withinMatches` the moment
  the count drops back below N. Rationale: the 30 s cooldown alone only
  THROTTLES a sustained failing level — it would re-remediate an unchanged
  condition every cooldown, which is harmful for a non-idempotent then-batch and
  spams commit/rollback history. Regression-locked by
  `TestEdgeTriggerOn_*_3756`. Only a policy carrying a `trigger on` clause
  latches (`policyHasTriggerOn`); a no-within or `trigger until` policy is
  unaffected.
- **The latch is rolled back when the action it authorized is never admitted
  (#6810).** `evaluateEvent` arms the latch under `e.mu` and returns;
  `HandleEvent` classifies and enqueues afterwards, OUTSIDE that lock. `enqueue`
  used to return nothing, so a dropped action was indistinguishable from an
  admitted one at the call site — and the consequence was not a delayed
  remediation but a LOST one: `withinMatches` suppresses every later
  at/above-threshold event while the latch is armed and re-arms only when a
  clause's count drops BELOW its threshold, which for the sustained fault a
  policy exists to remediate never happens. A transient saturation of the 64-slot
  queue by 64 DISTINCT other policies therefore permanently consumed the
  crossing.

  `enqueue` now returns an admission verdict and `HandleEvent` calls
  `releaseEdgeLatch` when it is false, restoring the invariant the latch
  expresses — *this crossing already fired* — for a crossing that did not. A
  **superseded** placement counts as admitted: the newer equivalent action is
  queued, which is what the latch asserts. The rollback carries the same
  semantic-revision ABA guard `armCooldown` uses (#5311): if a successor
  generation was installed (or the policy removed) while the action was being
  classified and rejected, its latch belongs to the successor and a
  predecessor's failure must not clear it. A concurrent event landing between
  the drop and the rollback is still suppressed, so the cost is a delay to the
  next event rather than a consumed crossing.

  **Two sibling paths deliberately do NOT roll back**, and the distinction is
  transient-vs-deterministic. A `classifyPlan` rejection (malformed/unknown
  command) fails identically every time, so re-arming would re-evaluate and
  re-reject on every subsequent event — unbounded churn for a remediation that
  can never run; it is counted (`rejected`) and logged once instead. An empty op
  list had no remediation to lose. Only the queue-full drop is transient, i.e.
  the only one where retrying succeeds. Pinned as an executable decision by
  `TestClassifyRejectAndEmptyPlanKeepTheLatch6810` so the scope is not mistaken
  for an oversight later. Regression-locked by
  `engine_latch_before_admission_6810_test.go`, which drives the real
  `HandleEvent` — every pre-existing edge-latch test calls `evaluateEvent`
  directly and is structurally blind to this seam.
- **`trigger until N` fires through the INCLUSIVE N-th event**, then stops
  (Junos "trigger UNTIL the event has been received N times" — the N-th
  occurrence is the last that fires). The current event is appended to the
  window BEFORE the check, so the N-th matching event makes `count == N`; the
  boundary is `count > N` (not `>=`). This fixed a dead-config bug: with `>=`,
  `until 1` made the first event `count == 1 >= 1` and NEVER fired, and
  `until N` fired only on events 1..N-1. Regression-locked by
  `TestInclusiveUntil_*_3756`.
- **Multiple `within` clauses are combined with AND (#4423 M3).** A policy with
  two `within` clauses fires only when EVERY clause passes for the current
  event. There is no OR; express an OR-of-conditions as separate policies.
  Regression-locked by `TestWithinMultipleClausesAreANDed`.
- **The verdict does not depend on clause ORDER (#7223).**
  `withinMatches` is three passes over the clause list — structural validity,
  then the `trigger on` re-arm/latch, then `trigger until` — rather than one
  fused loop that returned from the middle of the walk. With the fused loop and
  two `trigger on` clauses, whichever clause was reached first decided whether
  the latch was checked or re-armed and the other was never evaluated: a
  latched policy whose LONG window was still above threshold returned at that
  clause, so the SHORT clause that had decayed below its own threshold never
  re-armed the latch. The ANDed condition went false and true again — a real
  crossing — and the policy stayed silent until the long window decayed. The
  latch now clears exactly when the ANDed condition is false, i.e. when ANY
  `trigger on` clause is below its threshold, decided across all of them first.
  Regression-locked by `TestWithinTriggerOnRearmIsIndependentOfClauseOrder`,
  which runs the same timeline against both clause orderings and requires them
  to agree. One deliberate delta: a policy carrying BOTH a structurally invalid
  clause and a below-threshold `trigger on` clause no longer clears the latch
  (pass 1 fails closed first). Such a policy fires on no event at all while the
  invalid clause exists, so the latch value is unobservable until the config is
  corrected.

## Audit hardening (#4423)

A backlog re-audit of the event-options engine produced these fixes and
dispositions (`gh issue view 4423`):

- **Event-name index (M6, part of M5).** `Apply` builds `eventIndex`
  (`event name → policies listing it`, deduped per policy) so `evaluateEvent`
  scans only the policies relevant to the fired event instead of every policy
  on every event. The remaining per-matching-policy attributes/`within` work is
  inherent and bounded by the pruned window. Locked by
  `TestEventIndexRoutingAndDedup`.
- **Typed missing-delete tolerance (M9).** `config.DeletePath` now wraps the
  `config.ErrPathNotFound` sentinel (message text unchanged), and the
  tolerated-missing-delete carve-out matches it with `errors.Is` instead of a
  substring match — a future error reword can no longer silently turn a
  tolerated missing-delete into a batch-aborting reject. ALL FOUR of
  `deletePath`'s not-found returns wrap the sentinel — the top-of-recursion
  miss, the **intermediate-container miss** (`delete <subtree>` when the parent
  container is not configured — the most common defensive-remediation shape),
  the leaf-miss (`removeMatchingNode`), and the member-miss
  (`removeMultiLeafMembers`) — so every shape the old `strings.Contains("path
  not found")` tolerated stays tolerated. Locked by
  `TestDeletePathWrapsErrPathNotFound`, `...ContainerMiss...`,
  `...MissingMember...`, and the engine-level
  `TestBatchContainerMissDeleteIsTolerated`.
- **Regex cache back-fill (M10).** A pattern that reaches `attributesMatch`
  without an `Apply`-time cache entry (legacy lenient-load path) is compiled
  once and cached, not recompiled per event. Locked by
  `TestAttributesMatchCacheBackfillOnMiss`.
- **Per-policy invalid-attributes throttle (M11).** The fail-closed warning
  throttle is keyed by policy name, so a flapping bad line on one policy no
  longer swallows the first warning about a distinct bad line on another. Locked
  by `TestFlagAttributesInvalidPerPolicyThrottle`.
- **Duplicate policy-name merge (L1).** Two hierarchical `policy foo { ... }`
  blocks MERGE into one policy in `compileEventOptions` (matching flat-set and
  Junos merge semantics) instead of producing two same-named `EventPolicy`
  structs that clobber each other's runtime/cooldown/`semRev` state. Locked by
  `TestCompileEventOptionsMergesDuplicatePolicyBlocks`.
- **Event-list reorder is not a redefine (L4).** `policySemanticRevision` sorts
  the event names before hashing (the event list is a set), so a bare reorder no
  longer re-arms and wipes the carried-forward cooldown. Locked by
  `TestPolicySemanticRevisionEventOrderStable`.
- **Nil-store guard (L7).** A matcher-only `New(nil, nil)` engine whose policy
  actually triggers now fails the batch permanently (counted rejected) instead
  of nil-panicking in the worker goroutine. Locked by
  `TestApplyOnceNilStoreDoesNotPanic`.

Dispositions with no code change (verified against master):

- **M7 (double compile on commit) — deliberate.** `applyOnce` runs
  `CommitCheck()` to reject a semantically-invalid batch BEFORE it acquires the
  daemon apply semaphore in `CommitFn`; the subsequent compile inside
  `commitAndApply` (`CompileCandidate` device-map preflight + `Commit`) is the
  daemon's own path, not the engine's. Keeping the early check avoids taking
  `applySem` for a doomed batch; the extra compile is cheap and rare
  (remediations are infrequent).
- **M8 (config lock held across the apply-semaphore wait) — not a deadlock.**
  The config lock (`configDir`) is a non-blocking try-lock:
  `store.EnterConfigure` returns `ErrConfigLocked` immediately when held
  (`configstore/store_lock.go`), and the worker retries with backoff — nothing
  ever blocks *waiting* for it, so no wait-for cycle exists. The engine holds it
  across `CommitFn` because `Commit` reads the candidate the engine staged under
  that lock (releasing it first would discard the batch). This mirrors the
  ordinary operator commit path (frontend `EnterConfigure` → commit →
  `commitAndApply` → `applySem.Acquire`).
- **M12 (metrics are global, not per-policy) — deferred.** Per-policy labels on
  `xpf_event_actions_*` need a metric-schema decision (additive per-policy series
  vs relabeling the existing global counters, plus cardinality bounds). Tracked
  for a follow-up rather than folded in here.

## Gotchas

- 30 s policy cooldown (`policyCooldown`, `engine.go`). The same policy will not
  trigger more than once in any 30 s window. Armed on successful commit, CHECKED
  both at evaluate (`evaluateEvent`) AND re-checked at commit (`staleReason`,
  #3750) — the commit-time re-check is what holds the invariant when a duplicate
  slips into the queue during lock contention (the evaluate-time check races the
  arm-on-commit timing).
- Temporal `within` clauses keep a sliding window of timestamps per
  (policy, event) pair, **pruned on every append** so a cooldown-suppressed
  event can never grow the window unbounded. This holds for the cases #2216
  flagged: a no-within policy (bounded to the 60s default horizon) and a
  `within N { trigger on M }` policy whose threshold is never met (bounded to
  the clause horizon). Pruning is NOT gated behind the trigger-success path.
  Regression-locked by `TestWindow_*_2216A`. The prune also **releases the
  burst high-water capacity** (#4423 M4): the in-place compaction reuses the
  same backing array, so `pruneWindow` copies into a right-sized slice once the
  retained capacity dwarfs the live length — a one-off event storm no longer
  pins that memory forever. Regression-locked by
  `TestPruneWindowReleasesBurstCapacity`.
- A single event that matches several policies fires EVERY matching policy's
  action — `HandleEvent` enqueues each triggered policy onto the single worker,
  which applies them serially, so none is dropped racing the config lock (the
  #2216-B all-but-one drop the pre-#2157 per-probe `executeCommands` path had).
  The cross-goroutine drop race is regression-locked by the pre-existing
  `TestQueue_ConcurrentProbesSerialize` (8 concurrent `HandleEvent` callers);
  `TestConcurrent_OneEventMatchesManyPolicies_2216B` adds the complementary
  single-event fan-out invariant (one event → all N matching policies commit).
- `CommitFn` holds the apply semaphore across both commit and apply (#846) so
  event-triggered commits serialize with operator commits.
- The engine holds no engine-level lock (`e.mu`) while in configure/commit
  (preserves the #846 deadlock-avoidance contract); the worker reads the
  pre-classified plan, not live engine state.
