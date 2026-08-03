# #6749 — binding-plan expansion registers new slots unarmed, dataplane disabled indefinitely

**Status: DRAFT v8.3 — pending adversarial plan review (round 9)**

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
  (AGY r7 leftovers + SMR r8 nits); v8.3 folds Codex r8: two-phase
  defer precheck (MAC mismatch OR link down — restart-safe by
  construction), MAC debt lifecycle from epoch opening with applySem
  serialization (Codex r8 f4), Go fabric pre-disable +
  unknown-outcome fail-closed + honest ~15s budget (Codex r8 f5),
  identity-keyed last_error attribution (Codex r8 f6), immutable
  reset fingerprint with pull-earlier-only clock (Codex r8 f7),
  rollover actions at compile ACCEPTANCE with failed-successor
  debt survival (Codex r8 f9), operator arm clears the helper
  latch too, and the r8 test matrix (Codex r8 M8).

---

## 1. Status

DRAFT v8.3 — pending adversarial plan review round 9 (Codex + AGY +
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
  allocations — needs `m.lastAcceptedConfigGeneration` advanced
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
  | Codex f6 debt contracts | CLOSED — `m.lastAcceptedConfigGeneration` (advances only on accepted config commits) keys the #5134 debt; the MAC debt keys on (accepted generation, desired member→MAC set) with supersession, member-removal cancellation, and completion-mode history (§5-C) |
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
change in the PR.

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
4. **Go pre-disables on projection change, applies the returned
   status IMMEDIATELY, stays fail-closed on an UNKNOWN outcome, and
   adopts the helper's ACCEPTED set (Codex r7 f2/f3 + r8 f5):** the
   manager's `SyncFabricState` today ignores the returned status
   and writes back its own input (manager_ha.go:153/:175), so a
   projection the helper guard-rejected would live on in
   `m.lastSnapshot.fabrics` and re-enter through the next wholesale
   clone (route/scheduler republish, manager_overlay.go:188) —
   recreating the sink through the back door. v8.3's Go
   transaction: (i) whenever the REQUESTED projection differs from
   the cached accepted projection, Go disables ctrl BEFORE sending
   the RPC (the #4959 fail-closed pattern — a response
   timeout/EOF after the helper committed the projection and
   marked the vector, process_control.go:129 permitting
   response-read failure after send, can otherwise leave
   `ctrl.Enabled=1` with stale READY rows against dying XSKs for a
   full poll interval, or indefinitely under persistent control
   failure); (ii) on a clean response Go writes back the HELPER's
   accepted fabric set (from the returned status, not its request
   input) and applies that status immediately, so the pending
   marks keep ctrl disabled in the same tick; (iii) on an UNKNOWN
   outcome (timeout, EOF, transport error) Go stays fail-closed —
   ctrl remains 0 until a subsequent successful status poll shows
   the converged state (the pending-activation retry drives the
   binding reconcile meanwhile; the busy watchdog is NOT a
   fallback here — it requires ≥1 `Registered && Armed` binding,
   maps_sync.go:1435, and the mark-all explicitly unarms
   everything). **Honest convergence budget (Codex r8 f5's
   correction):** the mark-all gate's worst-case window is the
   retry's first rebind (~5s initial backoff) + worker readiness
   (up to ~10s, bringup.rs:30) + the next status application —
   ~15s worst-case per accepted fabric projection change
   (rate-capped), NOT the "≤5s" v8.2 implied; still shorter and
   simpler than the in-handler alternative (a 10s reconcile inside
   a 3s-deadline RPC plus a Go fail-closed transaction wrapper
   with its own timeout-but-landed state), which is why the
   mark-and-retry shape wins even with the budget stated
   honestly (Codex r8 f5 concurs: mark-and-retry, given the
   pre-disable).

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
    survive a failed successor instead of being cancelled by it.
    An explicit OPERATOR global arm during a window also clears the
    manager flag (the operator completed the window explicitly —
    documented). Without rollover, a deferred A whose tagged
    completion failed would leak `DeferWorkers=true` into every
    later unrelated compile's stamp — B workerless forever with no
    MAC completion owner (Codex r7 f4's trace). Supersession is
    BY DESIGN total: every accepting path — normal commits, HA-peer
    config sync, rollback-to-older-config, `commit confirmed`
    auto-revert, and background full recompiles — advances
    `m.lastAcceptedConfigGeneration` and thereby supersedes any
    debt keyed on an older generation, because the debt's config is
    by definition no longer the accepted one; the new accepted
    config's own precheck owns whatever defer it needs.
- **Completion requires a SUCCESSFUL prerequisite — and the
  prerequisite has a PHASE-COMPLETE precheck, an epoch-open debt,
  and applySem serialization (v8.3, Codex r8 f4).** `programRethMAC`
  can fail BEFORE setting the MAC, AFTER setting it but failing
  `setUp` (returns `(true, error)`, daemon_reth.go:257 — and a
  later attempt no-ops on the already-installed MAC, :244, never
  retrying the link-up), or not at all. v8.3's contract:
  - **The precheck checks BOTH phases per member (Codex r8 f4's
    restart case):** the `rethMACPending` computation
    (daemon_apply_dataplane.go:45-70) becomes
    `mac != desired || !linkUp` per desired member — so a daemon
    restart after "MAC installed, setUp failed" (boot sees the
    CORRECT MAC but a DOWN member) reopens the epoch and
    reconstructs the debt from the ACTIVE config, with no separate
    reconstruction rule needed (the boot precheck is the same code
    path). The debt is therefore restart-safe by construction, not
    by a promise.
  - **The MAC debt lifecycle starts at epoch OPENING (positive
    provenance, Codex r8 f4's gate fix):** when the epoch opens
    (defer flag set), the debt opens in phase-validation-pending
    state and settles only when EVERY member of the desired set
    has its MAC installed AND is administratively up — so
    `complete_deferred = m.deferWorkers && !m.hasActiveMACDebt`
    means "epoch open AND all prerequisites VALIDATED", never
    merely "no failure recorded yet" (the v8.1 negative formula
    would let a tag fire in the gap between epoch opening and the
    first validation attempt). The debt re-drives only the missing
    phase per attempt, with autonomous backoff (5s→10s→30s→60s
    cap) and an edge Warn per phase transition.
  - **The debt participates in the daemon's apply serialization
    (Codex r8 f4's mutation race):** each autonomous attempt
    acquires `applySem` (daemon.go:485 — the same semaphore as
    every config entry point) and re-validates its epoch
    (generation match against `m.lastAcceptedConfigGeneration`)
    immediately before each netlink mutation; on contention or
    mismatch it skips the attempt. No debt-driven MAC/link mutation
    ever races a live commit.
  - Contract rules kept from v8.2: a NEWER accepted config
    supersedes (cancels) the debt BEFORE any stale MAC work runs —
    its own precheck owns the new epoch; a member REMOVED from
    config cancels only its own entry (SMR r7 N2); the debt
    records its completion-mode history (live vs cycle) so the
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
  already-bound plan. And an explicit
  OPERATOR global arm, as an authorized defer exit, also clears the
  helper's stored latch in the same handler write (Codex r8 f9's
  dual-cache afterlife: without it the stored `defer_workers=true`
  would block convergence of FUTURE pendings until the next apply —
  the operator completed the window explicitly, so the window
  closes on both sides at once).
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
  the latch or arm slots against a wrong MAC.
- **#5134 debt is scoped to the ACCEPTED config generation (v8.2
  contract, Codex r6 f8 + r7 f6).** The manager gains
  `m.lastAcceptedConfigGeneration`, advanced ONLY when a config
  apply SUCCEEDS (`bumpGeneration` at compile success — the
  composite `lastSnapshot.Generation` is wrong for this purpose:
  it moves on FIB-only bumps (manager_generation.go:69) and
  resolved-fabric persistence (manager_ha.go:208), and a FAILED
  compile's pre-build allocation (manager_compile.go:214) must not
  move the epoch either). `RecordDeferredWorkerArmDebt` records the
  debt with `m.lastAcceptedConfigGeneration` at creation;
  `retryDeferredWorkerArmLocked` fires only while the CURRENT
  `m.lastAcceptedConfigGeneration` equals the debt's — so a stale A
  debt can never authorize a newer deferred B before B's MAC work
  (Codex r5 B8), a FAILED newer compile cancels nothing (it never
  advanced the accepted epoch), FIB/overlay/fabric-telemetry bumps
  discard nothing (they never touch it), and the mandatory
  same-config re-apply's own success advances it — settling the
  debt exactly once (Codex r7 f6's contract).

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
    // a pending-set change / config event / link event resets attempts
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
fanned out post-reconcile on explicit arms). The defer window has
exactly two authorized exits: a successful-MAC completion with
provenance (tagged rebind or the mandatory non-deferred re-apply),
or an explicit operator/global verb.

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
protocol canary + #4952-pin test updates, docs. No coordinator,
gate-semantics, or shim changes.
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

- **Wire protocol:** TWO additive fields, both with serde defaults,
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
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
  `set_queue_state`, `apply_snapshot`, `rebind`, `update_fabrics` —
  signatures and response shapes unchanged. `set_binding_state` slot
  addressing is unchanged (slots remain positional).
- **Go manager API:** unchanged (D, the arm-sync defer gate, the
  pending-activation retry, and the #5134 generation scoping are
  manager-internal). Daemon-internal ordering changes (defer-flag
  lifetime, MAC-success gating) do not alter any interface.
- **CLI / `show` output:** unchanged shape; `activation-state` may
  surface in verbose binding output as an additive display field.
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
   worker's `(socket_ifindex, socket_queue_id)` to equal the
   binding's `(ifindex, queue_id)`, else the slot zeroes.
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
    replan with physical-change pending + reconcile — v8); rebind /
    toggles / forwarding (no plan mutation). The server tests
    assert the invariant directly (§9 item 16).
11. **Failure truthfulness + retry ownership (v8):** the planner
    never arms (S5); ANY post-teardown bring-up failure marks all
    non-operator registered slots pending in COMMON typed handling
    (S4'); the arm verb rolls its global bit back on Err (the Go
    desired-loop retries, #6165-gated); and the status loop's
    pending-activation retry — ACTUAL-armed, registered+ifindex
    pending only, flag clear, no debt/in-flight, backoff-with-jitter
    + attempt cap + reset-on-change — schedules a convergence
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
| Performance regression | LOW | The retry adds at most one rebind per backoff interval (5-60s) in failure windows only; fabric-driven reconciles are rate-capped ≥2s + trailing coalesce; the volatile identity check is O(1) per slot per refresh (same loop). No per-packet/session work; the 1s poll gains only O(n) scans. |
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
  arm, update_fabrics-with-projection-change) → all non-operator
  registered slots unarmed+pending; operator-claimed slots
  untouched.
- **Server-level regressions** (`userspace-dp/src/server/tests.rs`;
  valid map pins, `force_worker_healthy_stub`, assertions on
  ARMED/STATE + reconcile Ok/Err + reconcile stage + IMMEDIATE
  post-failure assertions per Codex r3-r6):
  12. **expansion-while-armed** (the issue's demanded test): apply
      A, `set_forwarding_state(true)`, apply B with an additional
      zoned interface; BOTH responses ok, plan keys differ, binding
      count increased, added identity exists, EVERY binding
      `registered && armed && state==none`, `enabled == true`,
      reconcile stage advanced. Red on master, green after. The
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
      no-op (epoch superseded); and an explicit operator global arm
      clears ALL latch authorities (manager flag AND the helper's
      stored latch in the same handler write); (ix) a successor
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
      carries a REAL bind-failure `last_error` KEEPS it (mismatch
      zeroing preserves the error). Then: (i) a plain rebind binds
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
      f6):** deferred apply → failed mandatory re-apply → debt
      recorded WITH `m.lastAcceptedConfigGeneration`; (i) a
      plan-changing SUCCESSFUL commit (accepted generation
      advances) → the stale debt does NOT fire; (ii) a FAILED
      newer compile (accepted generation UNMOVED) → the debt STILL
      fires (a failed compile cancels nothing); (iii) a FIB-only
      bump / resolved-fabric persist / route-overlay / scheduler
      publish (accepted generation UNMOVED) → the debt STILL fires
      (Codex r6 f8's scope fix, contract form); (iv) the retry's
      republish (same-plan, generation-bumped) converges without
      the rebind flag, and its success advances the accepted
      generation — settling the debt exactly once; (v) a newer
      successful commit with the SAME binding plan (different other
      content) still supersedes (accepted generation advanced) —
      the debt does not fire across it; (vi) the full advance-point
      matrix (Codex r8 M8): boot-time first config, a DHCP/feed
      driven apply, an HA-peer config sync, a rollback to an OLDER
      config, a `commit confirmed` auto-revert, and a background
      full recompile — each ACCEPTING path advances
      `m.lastAcceptedConfigGeneration` and supersedes older debts
      by design; and the pre-adoption-failure vs post-ACK-error
      distinction is pinned (pre-acceptance failure: flag rolls
      back, debts survive; post-ACK error: epoch opened, retry
      owner active); (vii) deferred-XSK adoption: a successful
      mandatory re-apply's own advance settles the debt exactly
      once.
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
      trailing coalesce: two projection changes inside the rate
      window reconcile the FINAL projection once (not the first,
      not twice); (viii) response-loss: a timeout/EOF AFTER the
      helper committed the projection leaves ctrl=0 (the
      pre-disable fired on the different-projection request) until
      the next successful poll shows convergence (Codex r8 f5);
      (ix) separate projection changes for `name`,
      `parent_linux_name`, and `rx_queues` each trigger the
      mark-all gate individually; (x) the integrated Go path:
      pre-disable → RPC → immediate returned-status application →
      convergence — asserted end-to-end.
- The fail-fast invariant (Q6, resolved r1): assertions live ONLY
  in tests and only over well-defined planner/activation
  transitions.
- Protocol canaries: `userspace-dp/src/protocol/tests.rs`
  exact-schema snapshots updated to pin `activation_state` and
  `complete_deferred` deliberately.
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
  change / config event / link event shortens the backoff; (vi)
  `pendingWorkerArm` set → NO rebind; (vii) completion in-flight →
  NO rebind; (viii) a failed tagged completion triggers the TAGGED
  completion retry (epoch-scoped, explicitly exempt from any
  terminal cap), not the untagged one; (ix) a first-Compile
  failure (publish error at :350) followed by a production status
  tick still drives the retry (loop ensured after
  `ensureProcessLocked`).
      (x) reset-clock cases (Codex r8
      f7): frequent config/link events never POSTPONE an
      already-due retry (pull-earlier only — no starvation), and a
      failed retry pass mutating `last_change`/`last_error` does
      NOT reset the backoff (the fingerprint is immutable identity
      membership only — no self-reset churn).
- Manager unit test for `complete_deferred` provenance (v8 + AGY
  r7 f1/f2): the NotifyLinkCycle path sets
  `CompleteDeferred: m.deferWorkers && !m.hasActiveMACDebt` — true
  ONLY with an open defer epoch AND no active MAC debt; a spurious
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
  with order permutations complete only when EVERY member has the
  desired MAC AND is up; a newer accepted config supersedes the
  debt BEFORE any stale MAC work runs; a member removed from
  config cancels only its own entry; live-change vs link-cycle
  completion modes dispatch on the recorded history; a
  permanently-failing member leaves the box deferred with an edge
  Warn; and (Codex r8 M8) the restart test instantiates a FRESH
  daemon with an active config, a CORRECT installed MAC, and an
  administratively-DOWN link — the boot precheck (MAC OR down)
  reopens the epoch and reconstructs the debt with no manual
  intervention; and the provenance test pins the POSITIVE
  current-epoch form: the tag fires only when the epoch is open
  AND the debt has settled (all phases validated for the current
  desired set), never merely in the absence of a recorded failure.
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

Resolved across rounds 1-7 (for the record): Q2, Q5, Q6, Q7,
applied-vs-requested init, full fan-out vs scoped, Q3 (uniform S3),
Q5-toggle, Q7-boot, the plan gate (deleted), the failure-path replan
(deleted), E2's operator arm (deleted), C2's discriminator (result-
based), the latch signature/atomicity, the retry's fixed-5s shaping,
the transient-MAC stranding, the update_fabrics wrong-physical
hazard, the Go shadow-latch, the quiescence race, the debt
generation scope, the in-handler fabric reconcile (replaced by
mark-all-pending + retry-driven bind), the guard authority split,
the leaking epoch (rollover), the terminal retry cap (rate-capped
forever), the torn identity check (planned identity), the claim
boundary (any planned-identity deletion), Q2 convergence scope
(plan-scoped, confirmed sound).

Remaining questions for round 8, each invitable to PLAN-KILL with a
concrete counterexample:

1. **Completeness, final form.** Exhibit a path to
   `Registered && !Armed` with `activation_state == none` that is
   NOT global-fan-out-created, NOT operator-created, NOT a
   documented deletion-boundary re-creation, and NOT an
   enabled-gate-explicit `armed=false` pending mark — an unowned
   producer that strands D-silent.
2. **The mark-all-pending fabric gate's outage shape.** An
   accepted fabric projection change now takes the WHOLE dataplane
   fail-closed (all non-operator slots unarmed) until the
   pending-retry's first rebind (≤5s initial backoff) — a total
   outage per fabric projection change, on a path that also fires
   during HA fabric churn (rate-capped). Is the alternative
   (in-handler reconcile with a Go fail-closed transaction
   wrapper, ~10s ctrl=0 but converged atomically) actually worse,
   and on which metric (window length, complexity, deadlock
   surface)? Pick one and defend the pick.
3. **The lastAcceptedConfigGeneration advance points.** The
   contract advances the epoch ONLY on accepted config commits.
   Name every production path that can move it and confirm the
   debts behave: compile success, mandatory re-apply success,
   config sync from the HA peer, rollback (commit revert to an
   OLDER config — does the epoch roll back too, and do debts from
   the newer generation strand?), `commit confirmed` auto-revert.
4. **The epoch rollover vs a mid-commit defer.** A commit whose
   OWN apply defers (MAC work) opens the epoch at compile start —
   but the rollover bullet also runs at compile start. Order them
   exactly: rollover (cancel stale) THEN open (set flag for this
   commit). Any interleaving where the new epoch is cancelled by
   its own rollover?
5. **The volatile identity check vs fabric parent re-keying.** A
   VLAN-orphan child's bindings key on the PARENT netdev; the
   planned identity in `workers.identities` is the candidate's
   (parent name, parent ifindex, queue). The binding record carries
   the same. Any case where the planned identity and the binding's
   `(interface, ifindex, queue_id)` legitimately differ (making the
   check zero out a HEALTHY slot)?
6. **Round-7 disposition table audit.** §1's table maps every r7
   finding to its v8.1/v8.2 fold. Which row is claimed-but-wrong
   this time?
7. **Split-line confirmation (Codex r7's own answer).** Codex r7
   said: do NOT split the MAC debt or pending retry (load-bearing);
   option D is the only safe split. Confirm or deny with a
   dependency argument: is D truly independent (the warn predicate
   + manager test ride no other v8.2 mechanism beyond the wire
   field), or does splitting it leave the issue's third leg
   (detection) unaddressed in the PR that owns the model?



