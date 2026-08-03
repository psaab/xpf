# #6749 — binding-plan expansion registers new slots unarmed, dataplane disabled indefinitely

**Status: DRAFT v1 — pending adversarial plan review**

- Issue: #6749 (opus-review-001 root R06, severity High)
- Research base: `ad9591177` (origin/master at worktree creation)
- Research branch: `research/6749-armed-state` (plan docs only — no
  production code in this branch)

---

## 1. Status

DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR).
Convergence target: PLAN-READY (recommended path shipped to `/engineer`)
or PLAN-KILL. No production code is written under `/research`.

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
not a performance issue. The win at absolute scale:

- **Outage avoided per trigger:** indefinite (until human intervention)
  → zero (planner-side fix) or ~1 status-poll tick (Go-convergence fix).
- **Trigger frequency in production:** every config commit that changes
  the binding-candidate set or its queue geometry on a live, armed
  firewall. Concretely (verified against the plan-key inputs in
  `planning.rs:update_snapshot_binding_plan_key` and the candidate
  filter `include_userspace_binding_interface`):
  - adding a zoned, non-tunnel interface or VLAN unit (new candidate);
  - re-parenting a VLAN unit / changing RETH membership
    (`vlan_id`/`parent_linux_name`/`parent_ifindex` are plan-key inputs);
  - adding or removing a fabric parent;
  - changing a committed per-interface `rx_queues` value;
  - the first commit after an out-of-band `ethtool -L <if> combined N`
    when the snapshot carries `rx_queues == 0` (the sysfs-resolved count
    is hashed into the plan key per #3007, so the replan fires on an
    unrelated later commit — the outage then correlates with the WRONG
    commit in post-incident analysis);
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
- **What it does NOT fix:** numeric-slot carry. A plan reshuffle still
  inherits a predecessor's full record (armed/registered/last_error/
  counter gauges) onto a different (interface, queue) identity. The
  armed-bit consequence is mostly masked (when globally armed every
  carried slot reads `armed=true`, which is also what option A would
  initialize it to), but an operator per-slot diagnostic disarm
  (`set_binding_state armed=false`) migrates to the WRONG interface
  across a reshuffle, and `last_error`/counters attach to the wrong
  interface. Pre-existing defect, same locus.
- **Size:** ~10 lines + tests.

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
- **Fatal tension (why this cannot be the primary fix):** the drift
  predicate cannot distinguish "planner-default unarmed slot" (must
  converge) from "operator-diagnostic disarmed slot" (must NOT
  auto-revert). Both present as `Registered && Bound && !Armed`. A naive
  converger reverts the `set_binding_state`/`set_queue_state` diagnostic
  verbs within ~1s, silently killing a troubleshooting surface
  (`cli_request_chassis.go`, `server_diag_system_action.go`). A
  discriminating converger needs a provenance bit (planner-default vs
  operator-override) threaded through the wire protocol — real protocol
  churn for a belt-and-braces layer.
- **Residual gap even if shipped:** ~1 poll tick of total transit
  outage per expansion commit (the window between the apply and the
  next convergence fire), vs zero with A/C.
- **Verdict candidate:** REJECT as primary; defer any narrow form to a
  follow-up only if reviewers can name a drift producer that A/C miss
  (see open question Q2).

### Option C — stable-identity state carry + global-init for genuinely new identities (Rust planner; superset of A)

Change the carry key from numeric slot to binding identity, and
initialize genuinely-new identities from the global armed state:

```rust
// identity = (interface, queue_id) — both already stored on BindingStatus;
// `interface` is the candidate linux netdev name (VLAN-orphan parent and
// fabric parent included), unique per plan via the seen_linux dedup.
let mut existing_by_identity: BTreeMap<(String, u32), BindingStatus> = ...;
for binding in existing {
    existing_by_identity.insert((binding.interface.clone(), binding.queue_id), binding.clone());
}
// in the layout loop:
let mut binding = existing_by_identity
    .remove(&(iface.clone(), queue_id as u32))
    .unwrap_or_default();
// slot/worker/interface/ifindex are then assigned positionally exactly as
// today; had_existing/new-slot logic unchanged except the init:
if binding.ifindex <= 0 { registered/armed/ready = false }
else if !had_existing { registered = true; armed = forwarding_armed; }
```

- **Ownership model:** same as A for the DEFAULT (global armed state);
  per-slot operator overrides become identity-scoped ephemeral state
  that follows the interface across reshuffles — the least-surprising
  semantics for the diagnostic verbs, and strictly more correct than
  today's slot-scoped carry.
- **What it fixes:** everything A fixes, PLUS the wrong-identity carry
  of `armed`/`registered`/`last_error`/counter gauges. Counters and
  errors now stay attached to the interface that produced them.
- **Slot numbers stay positional** (assigned in layout order), so
  `set_binding_state(slot=…)` addressing, `show` output shape, and the
  shim's `userspace_bindings` row computation (which keys on
  `(ifindex, queue_id)`, never on slot) are all unaffected. Only state
  PROVENANCE changes.
- **What it does NOT fix:** nothing known in the arm domain; see Q2.
- **Size:** one function rework (~40 lines incl. comments) +
  `forwarding_armed` threading + tests.

### Recommendation

**Ship option C** (A's init rule + identity carry), with A as the
documented retreat if implementation uncovers a hidden coupling in
identity keying (none found in research: the coordinator's bring-up and
Go's shim-map writer both key on `(ifindex, queue_id)`/`interface`
already). **Reject B as primary** on the operator-override
discrimination conflict; record the deferred narrow-B question as Q2
for the reviewers.

Rationale in one line: the planner is where the contradictory default
is born, so the planner is where the fix belongs — and while there,
carrying state by WHO THE BINDING IS rather than WHERE IT LANDED is the
same class of correctness fix as #3007/#3175 (hash what the layout
uses), at one-function cost.

## 6. Public API preservation

- **Wire protocol:** unchanged. `BindingStatus`, `ControlRequest`/
  `ControlResponse`, snapshot schema, and the state-file payload keep
  identical fields; only the planner's internal carry key and new-slot
  default change. `CONFIG_SNAPSHOT_PROTOCOL_VERSION` is NOT bumped —
  mixed-version interop is unaffected (old Go + new helper: fix works,
  self-contained; new Go + old helper: bug persists until the helper
  restarts into the new binary — same-.deb transient window, same as
  any helper-side fix).
- **Control verbs:** `set_forwarding_state`, `set_binding_state`,
  `set_queue_state`, `apply_snapshot`, `rebind` — signatures and
  response shapes unchanged. `set_binding_state` slot addressing is
  unchanged (slots remain positional).
- **Go manager API:** unchanged under A/C. (B would have touched
  `syncDesiredForwardingStateLocked` only — also no API change, but see
  §5-B.)
- **CLI / `show` output:** unchanged shape; counter/error provenance
  becomes correct-by-identity (a behavioral improvement, not a schema
  change).

## 7. Hidden invariants the change must preserve

1. **Defer contract (#5171/#5134):** a `defer_workers=true` apply must
   keep new slots unarmed. Holds because the init value is the LIVE
   `guard.status.forwarding_armed`, which is false on that path.
2. **#869 no-ready-in-enabled:** `enabled` must keep NOT requiring
   `ready`. Untouched — only the armed default changes.
3. **#1666 ready-gate:** per-row shim steering must keep requiring
   `Ready`. Untouched — and it is precisely what makes armed-from-global
   safe for a not-yet-bound slot.
4. **Disarm direction never blocked:** the `ifindex <= 0` leg still
   force-clears `registered/armed/ready`; `set_forwarding_state(false)`
   still fans out `armed=false` to every binding regardless of identity
   carry. A binding whose identity vanished from the plan simply drops
   out of the vector (as today).
5. **Same-plan skip (#2915/#2916/#3007/#3175):** the plan key and the
   candidate set are untouched — `snapshot_binding_plan_key` inputs are
   identical, so the same-plan leg never starts disagreeing with the
   layout. Identity-carry only runs on the full-apply leg that ALREADY
   decided the plan changed.
6. **One-XSK-per-(netdev,queue) (#1921):** the `seen_linux` dedup and
   the candidate iteration order are unchanged; identity uniqueness per
   plan follows from it (a name appears at most once, queue_ids are
   distinct per name).
7. **Coordinator filter (`registered && ifindex > 0`):** unchanged;
   worker bring-up must not start reading `armed`.
8. **Operator override lifetime:** `set_binding_state` overrides
   survive same-plan applies (no replan) and die on the next global
   `set_forwarding_state` fan-out — both unchanged. Under C they
   additionally survive plan RESHUFFLES attached to the same identity
   (the semantic improvement); under A they silently migrate (the
   pre-existing defect).
9. **Counter/heartbeat ownership:** `refresh_bindings` continues to
   re-derive `bound`/`xsk_registered`/`ready`/socket fields from live
   worker state after every reconcile — identity-carried records get
   their volatile fields refreshed exactly as slot-carried ones do
   today.
10. **HA portability:** no cluster-protocol or session-sync
    interaction; per-node helper-internal change. Standby nodes run the
    same armed semantics (`desiredForwardingArmedLocked` returns true on
    standby with data RGs), so the fix behaves identically on both
    cluster roles.

## 8. Risk assessment

| Risk class | Level | Assessment |
|---|---|---|
| Behavioral regression | LOW-MED | The observable change: after an expansion-while-armed, `enabled` recomputes true and ctrl opens WITHOUT operator action (today: never). This is the boot-arm semantics extended to plan expansion, backstopped by the #1666 ready-gate per row. Residual: a not-yet-bound new slot is reported `armed=true` for one refresh window — same reporting posture as the boot arm, and the shim never steers to it until `Ready`. |
| Lifetime / borrow-checker | LOW | Cold path, owned `BindingStatus` clones already in use; the identity map is a local `BTreeMap<(String, u32), BindingStatus>` — no new lifetimes, no hot-path allocation (one map build per REPLAN, which already clones every binding today). |
| Performance regression | LOW | Planner runs once per full apply (control path); O(n) map build replaces O(n) map build. No per-packet, per-session, or per-poll work. |
| Architectural mismatch | LOW-MED | Must not entangle with #6702/#6681's planner rework. The identity key `(interface, queue_id)` is layout-shape-independent and survives their per-interface queue extents; both issues confirmed non-overlapping in scope. The one coordination note: whichever lands second rebases the replan function. |

## 9. Test plan

**Rust unit/integration (the fix lives here):**

- `replan_bindings_from_candidates` unit tests (extend the existing
  replan test module — `userspace-dp/src/main_tests.rs` hosts
  `replan_queues_binds_vlan_unit_on_parent_netdev`):
  1. **expansion while armed** — existing plan all-armed, add a
     candidate: new slots `registered=true, armed=true`; carried slots
     unchanged.
  2. **expansion while disarmed** — same but global false: new slots
     `armed=false`.
  3. **contraction** — remove a candidate: vanished identities' state
     does not leak onto survivors.
  4. **reshuffle identity carry** — insert a candidate that sorts
     earlier (or change queue_count): each surviving identity keeps its
     own `armed`/`last_error` at its NEW slot; an operator-disarmed
     identity stays disarmed at its new slot.
  5. **orphan-VLAN + fabric identities** — parent-rekeyed and
     fabric-parent candidates carry/arm correctly.
  6. **same-identity same-slot no-reshuffle** — byte-identical outcome
     to today (regression pin for the common case).
- **Server-level expansion-while-armed regression** (the issue's
  demanded test — `userspace-dp/src/server/tests.rs`, alongside the
  existing full-apply tests at :1314/:1475): apply snapshot A, arm via
  `set_forwarding_state(true)`, apply snapshot B with an additional
  zoned interface (plan key differs → full-apply leg), assert EVERY
  binding `registered && armed` and `status.enabled == true` after the
  apply. Red on master, green after.
- `make test-rust` (full cargo suite) clean; `cargo build` warning-free.
  Fleet cap honored: `CARGO_TARGET_DIR=/home/ps/cargo-target/research-6749`.

**Go:** no production change under A/C — the existing `make test-go`
suite must pass unchanged (pins that no Go gate depended on the buggy
default).

**Smoke (loss userspace cluster, lock-cell wrapped):** deploy; verify
iperf3 baseline to 172.16.80.200; commit an ADDITIONAL zoned VLAN unit
(e.g. a new `reth0.90` in the wan zone) while armed; assert transit
continues with no manual arm toggle and
`show ... bindings` reports the new slots armed. Re-apply CoS after the
deploy per the cluster protocol (`apply-cos-config.sh`).

**Docs (module contract, same work item):**
`userspace-dp/src/server/README.md` — the arm-model narrative (the
`set_bindings_forwarding_armed`/defer sections around :71/:294-324)
gains the planner-default rule and the identity-carry invariant.

## 10. Out of scope (explicitly)

- **Go per-binding armed convergence (option B)** — rejected as
  primary (operator-override discrimination conflict, §5-B); a narrow
  provenance-tagged converger is deferred unless reviewers identify a
  drift producer A/C misses (Q2).
- **#6702/#6681 planner queue-geometry rework** — they own binding-count
  consequences; this fix is compatible but does not implement any of
  their layout change.
- **`bindingForwardingLive` / `enabled` / `probeBindingsReady` gate
  semantics** — the gates are correct; the bug is the DEFAULT they were
  fed. No gate changes.
- **Persisted-state migration** — none needed (state file write-only).
- **Operator-override persistence across global arm toggles** — the
  fan-out still clears them; making diagnostic disarms durable is a
  separate product decision.

## 11. Open questions for adversarial review

Each is invitable to PLAN-KILL with a concrete counterexample.

1. **Applied vs requested init value.** The plan initializes new slots
   from the helper's APPLIED `forwarding_armed` at replan time. Is there
   ANY path where the applied bit at replan time disagrees with Go's
   intent in a way that strands state — e.g. an apply racing a
   disarm-in-flight on the same control connection? (The control socket
   serializes requests under the `ServerState` lock, and
   `disarmBeforeUnsupportedPublishLocked` precedes the publish, but a
   hostile review should try to break this ordering.)
2. **Is the planner truly the only non-operator producer of armed-bit
   drift?** If a reviewer can name a code path that leaves
   `Registered && Bound && !Armed` without an operator verb and without
   a replan (helper restart? mixed-version window? `update_ha_state`?),
   then rejecting option B is wrong and the plan needs the
   provenance-tagged converger instead.
3. **Identity-carry vs pinned behavior.** Do any EXISTING tests or
   operator procedures depend on slot-positional state inheritance
   (e.g. `show` consumers expecting counters to reset when the plan
   reshuffles, or the full-apply tests at server/tests.rs:1314/:1475
   asserting carry-by-slot)? If identity-carry breaks a pinned
   behavior, option A is the retreat — reviewers should verify the pin
   set.
4. **`last_error` provenance.** Under C, `last_error` carries by
   identity. Is carrying a stale EBUSY across a reconcile that later
   SUCCEEDED acceptable (it is today, by slot), or must the carry
   exclude `last_error`/volatile fields? Is there a consumer that reads
   `last_error` as "current" rather than "last"?
5. **VLAN-alias consumer.** Go's `buildUserspaceIngressBindingAliases`
   (maps_sync.go:745) maps child ifindex → parent binding rows. Confirm
   identity-carry cannot alter the (ifindex, queue_id) rows the alias
   consumes — the alias keys on `binding.Ifindex`/`QueueID`, which the
   layout assigns independent of state provenance.
6. **Fail-fast invariant.** Should the apply path `debug_assert` (or a
   server test pin) that after replan+reconcile with global armed, every
   registered binding is armed — turning any FUTURE drift producer into
   a test failure instead of a silent outage? Or is that asserting an
   implementation detail that legitimate future states (operator
   override mid-apply?) could violate?
7. **Severity cross-check.** The review labels this High. With the
   trigger set quantified in §3 (any interface-geometry commit + the
   #3007 out-of-band `ethtool -L` landmine), should the issue also
   request a release-note / upgrade-note entry, or is the fix small
   enough to ride silently?
