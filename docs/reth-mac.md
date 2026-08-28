# Consistent RETH MAC Addresses

## Problem

In the HA cluster, RETH interfaces use VRRP on physical member interfaces (no bond devices). Each node has a different physical MAC on its RETH member interface, causing problems during failover:

1. **IPv6 link-local addresses differ** -- EUI-64 link-local (`fe80::...`) is derived from MAC. After failover, the new primary has a different link-local address, breaking neighbor caches on LAN hosts.
2. **Neighbor cache invalidation** -- Clients must update both VIP->MAC and gateway link-local->MAC mappings. Unsolicited NA only covers the VIP.
3. **`bpf_fib_lookup` smac** -- XDP forwarding uses `fib.smac` from the kernel. Different MACs mean forwarded packets have different source MACs after failover.

## Solution

Program a deterministic virtual MAC on RETH physical member interfaces at daemon startup. Both nodes present the same MAC for each RETH, making IPv6 link-local addresses identical and eliminating neighbor cache issues.

## MAC Format

```
02:bf:72:CC:RR:00
```

| Byte | Value | Meaning |
|------|-------|---------|
| 0 | `02` | Locally-administered unicast (U/L bit set) |
| 1 | `bf` | xpf identifier |
| 2 | `72` | ASCII 'r' (bpf**r**x) |
| 3 | `CC` | cluster_id (from config) |
| 4 | `RR` | redundancy_group_id |
| 5 | `00` | Reserved |

Example for cluster_id=1:
- reth0 (RG1): `02:bf:72:01:01:00` -> link-local `fe80::bf:72ff:fe01:100`
- reth1 (RG2): `02:bf:72:01:02:00` -> link-local `fe80::bf:72ff:fe01:200`

## Ordering

1. **`.link` files** (udev/networkd) -- match physical MAC for interface rename (e.g. enp6s0 -> ge-0-0-0)
2. **`networkctl reload`** -- applies the rename
3. **Virtual MAC** -- `netlink.LinkSetHardwareAddr()` programs the deterministic MAC
4. **VRRP `UpdateInstances()`** -- picks up new MAC via `net.InterfaceByName()`
5. **GARP/NA** -- automatically use the kernel MAC (called at send time)
6. **`bpf_fib_lookup`** -- automatically returns new MAC as `fib.smac`

## Rename Owns the Link UP (#3920)

A RETH member must be administratively DOWN to be renamed (kernel
requirement). `renameRethMember` therefore downs the link, renames it,
and then brings it back UP — the function that downs a link owns
bringing it back up.

It must NOT delegate the UP to the subsequent `programRethMAC`.
`programRethMAC` early-returns (no UP) when the virtual MAC already
matches, and that is precisely the situation after a rename:
`renameRethMember` locates the interface by matching that same virtual
MAC, so on a just-renamed member the MAC always already matches and
`programRethMAC` always no-ops. (A second facet: even in the MAC-change
path, `programRethMAC`'s fast path sets the MAC while the link is still
DOWN, which succeeds without a cycle and returns without an UP.) If the
UP were skipped, the RETH data link would be left DOWN → the interface
track detects link-down → the redundancy group demotes → traffic
blackhole.

There is no flap: whenever a rename happens the MAC already matches so
`programRethMAC` no-ops, leaving `renameRethMember`'s UP as the final
state; and even in the defensive case where `programRethMAC` does cycle,
the member still ends UP. Bringing the member UP before `programRethMAC`
also restores that function's live-address-change attempt, which needs an
UP link to have any chance of succeeding — a DOWN link takes the fast
path that sets the MAC without a cycle, so the fallback is never
exercised and the member never gets its post-cycle recovery.

## The AF_XDP Worker Join Precedes the Link Cycle (#5103)

`PrepareLinkCycle`'s contract is that **no thread touches UMEM once it returns
successfully** — it disables `ctrl` so the XDP shim stops redirecting to XSK,
then sends `stop_workers` so the Rust helper joins every worker thread. That
barrier therefore has to land **before** the NIC tears down its queues, not
after: a worker still reading UMEM while the driver unmaps those pages is a
use-after-unmap.

The success qualifier is the whole reason the function returns an `error`
(#6871 round 13; earlier revisions stated the contract unconditionally). If
`stop_workers` fails, `PrepareLinkCycle` returns with the workers **possibly
still running**, and the caller must not cycle the link — which is exactly what
`programRethMACWithWorkerJoin` does with it.

It cannot simply be hoisted above `programRethMAC`. Whether a cycle happens at
all is only knowable by **attempting** the live MAC set: if the kernel accepts
it, no cycle occurs. Joining unconditionally would impose a forwarding outage on
every RETH MAC apply on mlx5 and virtio (the cluster's own NICs), to protect a
path they take only rarely.

**Neither outcome of that attempt is a statement about `IFF_LIVE_ADDR_CHANGE`,
and an earlier revision of this document said it was** (#6871). Linux's
`dev_set_mac_address` does not consult that flag on the failure path at all — it
refuses a live set for a missing `ndo_set_mac_address`, a wrong `sa_family`, an
absent device, a *busy* device, or a driver/notifier rejection, all the same way.
So a transient refusal on the cluster's own mlx5 VFs takes the cycle fallback
even though those VFs do have the capability, and the journal line
`RETH MAC live set refused; falling back to a link cycle` carries the actual
error rather than a guess at its cause. Read the fallback as "the live set was
refused, for whatever reason, and a cycle is the remaining option" — treating it
as a driver-capability verdict produces the wrong diagnosis on exactly the
hardware this cluster runs.

So the join is a hook. `programRethMAC` takes a `beforeCycle func() error` and
invokes it **at most once, on the fallback path only** — after the live set has
been rejected, before `setDown`:

```
set-mac-live (rejected) → beforeCycle (stop_workers) → link-down → set-mac → link-up → rebind
```

`PrepareLinkCycle` returns an `error` across `LinkController` and every
implementation. A void return made a failed join indistinguishable from a
successful one, so the link cycled with workers still live.

**Abort semantics.** A rejected live set does not change link state — the kernel
refuses the address change outright — so when `beforeCycle` returns an error the
link is exactly as it was found. `programRethMAC` returns `(false, err)` **without
touching the link**: the member keeps its previous MAC, which the next apply
retries; cycling out from under live workers is not recoverable.

**The abort is not side-effect-free, and owns its own rollback.** By the time the
hook fails, `PrepareLinkCycle` has already disabled `ctrl` (and cleared every
binding row if that disable could not be verified), and the helper may or may not
have joined its workers. Nothing downstream re-arms that: the post-cycle rebind is
gated on `linkCycled`, false here because the cycle was aborted *before*
`setDown` — a failed hook never reaches it (#6915: a failure AFTER a successful
`setDown` does report true, and is re-armed by step 2.6b2), and
`reapplyAfterDeferredMAC` is gated on `rethMACPending`, which is computed *before*
`networkd.Apply` — so it is false for an apply whose only member needing a MAC was
renamed into its config name by that same `networkd.Apply`. (`rethMACPending` is
one bool for the whole apply, not per member: a multi-RETH apply where a
*different* member was already present with the wrong MAC does set it, and that
apply does re-apply.) `programRethMACWithWorkerJoin` therefore sends the documented
inverse of `stop_workers` — `rebind`, via `NotifyLinkCycle()` — and returns a
`errRethPrepareLinkCycle`-classified error. Its caller, `programRethMemberMAC`,
`errors.Join`s that into the accumulated commit error (the same `networkdErr`
channel the device-map teardown (#5309) and the management-VRF rebind (#5700)
use), so the commit reports FAILURE instead of success over a half-torn-down
dataplane. Ordinary netlink MAC-set failures stay warn-only, as they always have.

`programRethMemberMAC` exists as a function, rather than as three statements
inline in step 2.6's loop, so that fold is unit-testable: inline it was reachable
only through `applyDataplaneAndHACore`, which needs a live cluster manager, a
wired dataplane, a networkd writer and real netlink members, and the only
available guard was an AST canary over the call site — which is satisfied by an
assignment that is unreachable, shadowed, or jumped over.
`reth_commit_fold_5103_test.go` drives it against the same fake link seam and
fake dataplane the wrapper's own tests use. It folds BOTH per-member
accumulators: the commit error (joined, so an earlier step's error survives) and
`needLinkCycleRecovery` (ORed, so a member needing no cycle cannot clear a gate
an earlier member armed).

**The gate is "the hook RAN", not "the hook FAILED".** `PrepareLinkCycle` drives
`ctrl` to 0 *before* it can fail on `stop_workers`, so by the time it returns —
either way — the member is no longer forwarding. On success the workers are
additionally joined; on failure their state is simply **unknown**, which is why
the link must not be cycled (#6871: an earlier revision of this sentence said it
"stops the workers whether it then succeeds or fails", which overstates the
failure path — a `stop_workers` that never reaches the helper joins nothing). A
*successful* join therefore leaves the member just as un-forwarding as a failed
one — and
`setDown` and the cycled `setHardwareAddr` are both still fallible after it
returns. Keying the rollback on the hook's own error let both escape with a nil
commit error and no rebind — `ctrl` off, transit dropped, commit green.

Of those two, only a failed `setDown` still yields `linkCycled=false` and the
state above (prepare applied, cycle not completed, neither `linkCycled` nor
`rethMACPending` able to re-arm it). Since #6915 a failed *cycled* MAC write
reports `linkCycled=true`, because by then `setDown` has succeeded and the link
really has cycled; it is re-armed by step 2.6b2 rather than by the rollback here.
Both still fail the commit, which is what this section is about — the rollback
gate is "the hook RAN", and that is unchanged. So `programRethMACWithWorkerJoin` records that the hook
ran (after its `d.dp == nil` guard, which keeps the rollback unreachable with no
dataplane attached) and rolls back on any subsequent failure:

| outcome | `linkCycled` | rollback here | commit |
|---------|--------------|---------------|--------|
| live set accepted — no cycle | false | no (hook never ran) | OK |
| member lookup failed | false | no (hook never ran) | OK — warn-only |
| join failed | false | `NotifyLinkCycle()` | FAIL |
| join OK, `setDown` failed | false | `NotifyLinkCycle()` | FAIL |
| join OK, cycled MAC write failed | **true** (#6915) | no — step 2.6b2 owns it | FAIL |
| join OK, cycle ran, `link-up` failed | **true** | no — step 2.6b2 owns it | FAIL |
| join OK, cycle completed | true | no — step 2.6b2 owns it | OK |

The last **three** rows are the failures in the class that do *not* roll back
here: the link cycled, so step 2.6b2 already rebinds off `linkCycled`, and firing
`NotifyLinkCycle()` too would be the double rebind that gets `EBUSY` on mlx5
zero-copy queues. They still fail the commit.

`linkCycled` reports whether the link **went DOWN and back UP**, not whether the
MAC write succeeded (#6915). Those differ in exactly one row — "join OK, cycled
MAC write failed" — which returned `false` until #6915 even though `setDown` had
returned nil. A DOWN flushes every kernel address on the member, so that row lost
the VRRP VIPs and the stable RETH link-local, and step 2.6b's reconcile is gated
on this same value through `needLinkCycleRecovery`: it was **skipped for a cycle
that genuinely happened**, and the member came back holding the VRRP role while
answering for none of its addresses.

Nothing else re-added them, which is why the gate was the whole fix:
`ReconcileVIPs` has exactly **one** production caller (step 2.6b's), the 2s
`reconcileRGState` tick re-adds only the *stable link-local* in VRRP mode, and
`sendAdvert` swallows its send error at `Debug` so VRRP never observes the flap
and stays MASTER. **Direct (no-VRRP) mode was never exposed**: the same tick calls
`reconcileDirectVIPOwnership` → `addDirectVIPs` unconditionally, which is
idempotent and re-adds what the DOWN removed, announcing on `added > 0`. So the
defect was VRRP-mode only and unbounded there — the addresses returned on the
next apply that cycled the member, not on any timer.

The two rows that remain `false` are the ones where **no cycle happened at all**:
a failed join, and a failed `setDown`. Those flushed nothing, so there is nothing
for step 2.6b to reconcile and no torn-down sockets for step 2.6b2 to rebind —
which is why the rollback below stays their only owner.

Note the remaining `link-up failed` and `cycled MAC write failed` rows differ in
recoverability even though both now report `true`: the first wrote the MAC, so
every later apply early-returns on `bytes.Equal(current, mac)` and never retries
`setUp` — the member stays administratively DOWN until a restart. The second did
not, so the next apply retries the whole sequence.

Suppression is per-MEMBER, while step 2.6b2's gate is a per-APPLY accumulator, so
an apply that mixes an aborted member with a cycled one pays two rebinds. Which
of the two arms the 500ms zero-copy quiesce depends on the order step 2.6 visits
the members in, and that order is a Go map range — so both orders hold. Every
`stop_workers` **that reaches its handler** empties `coord.workers.records`
(`WorkerManager::stop_and_clear` joins each worker thread, then `clear()`s), and
`tear_down` samples `had_live_workers` from exactly that. The qualifier is
load-bearing and #6871 added it: a prepare can fail on the *dial* or the *write*,
before the helper ever runs the handler — precisely the failure class the
rollback exists for — and then records are NOT cleared, so the sample is `true`
and the quiesce is PAID rather than skipped. That costs an extra 500ms and
nothing else; the two orders below describe the handler-ran case. If the ABORTED member
is visited first, its rollback rebind recreates the workers but the cycled
member's own `stop_workers` clears them again, so step 2.6b2's rebind sees
`had_live_workers == false` and SKIPS the quiesce; if the CYCLED member is
visited first, nothing recreates workers before the aborted member's rollback
rebind does, so step 2.6b2's rebind sees `true` and arms it. Both are safe, and
not because of the quiesce: it covers a rebind that rebuilds the same queue set
immediately after a teardown it did not itself wait on, and here every rebind
follows a `stop_workers` that joined the worker threads synchronously plus
`NotifyLinkCycle`'s own unconditional 1s NIC settle — twice the 500ms it may
skip.

The rollback's `NotifyLinkCycle()` sits inside the per-member RETH loop and opens
with a 1s NIC-settle sleep, where step 2.6b2 pays that second at most once
outside the loop — worst case *N* extra seconds of `applySem` hold when every
member aborts (*N* = RETH count; 2 on the loss cluster). Bounded, and only on a
path where this node's forwarding is already down.

| File | Function |
|------|----------|
| `pkg/daemon/daemon_reth.go` | `programRethMAC(ifName, mac, beforeCycle)` — invokes the hook on the cycle path only, aborts without touching the link |
| `pkg/daemon/daemon_apply_dataplane.go` | `programRethMACWithWorkerJoin()` — builds the hook, rolls back a prepare whose cycle then failed, classifies the commit error |
| `pkg/daemon/daemon_apply_dataplane.go` | `programRethMemberMAC()` — step 2.6's per-member fold: joins the classified error into the commit error, ORs `linkCycled` into step 2.6b2's rebind gate |
| `pkg/dataplane/userspace/process_linkcycle.go` | `Manager.PrepareLinkCycle()` — ctrl disable + `stop_workers`, returns the join error |
| `pkg/dataplane/userspace/controllers.go` | `userspaceLinkController.PrepareLinkCycle()` — the live production adapter from the daemon hook to the manager |
| `userspace-dp/src/server/handlers/stop_workers.rs` | helper side of the join; `rebind.rs` is its inverse |

### The rename site cycles the link too (#6911)

`programRethMAC` is not the only place that cycles a RETH member.
`renameRethMember` performs its own `setDown` -> `setName` -> `setUp`
(the rename requires the link DOWN, and #3920 makes it own the UP), and
until #6911 it did so with **no worker join** — the identical hazard,
one function up.

It now takes the same `beforeCycle func() error`, invoked once a rename
candidate is confirmed and strictly before `setDown`, and returns `""`
**without touching the link** if the join fails. A nil hook means "no
join needed", matching `programRethMAC`'s contract. The daemon wires a
real hook at the apply site; the lease `PrepareLinkCycle` takes is
released by the `abandonLinkCycleLease` already deferred over the whole
apply, so this adds a join rather than a new lifecycle.

**The hazard is latent, not live, and the hook is there because the
argument for that is unasserted.** `renameRethMember` runs only when
`LinkByName(targetName)` has already failed; it matches candidates by
the *virtual* MAC; and the dataplane cannot have resolved a binding to a
name that did not exist. So no live binding can be torn down today. That
chain is correct, but it rests on three separate properties of unrelated
code and none of them is checked anywhere — a future change to any one
would reopen #5103 silently. Making the two cycle sites symmetric turns
that into a loud failure for the price of one hook.


## The Link-Cycle Lease Holds the Join Across the Cycle (#6871)

The join above is a **moment, not a barrier**. `PrepareLinkCycle` takes `m.mu`,
joins the workers, and releases it on return — and the daemon does not reach
`setDown` until several netlink calls later. Every other holder of `m.mu` runs in
that window, so "no thread touches UMEM once it returns successfully" was true
only for the instant it returned. (On a failed join it was not true even then —
see the qualifier above; this section is about the window that follows a join
that did succeed.)

The busiest producer in that window is the 1 Hz status tick, which undoes the
join five different ways:

| producer | file | what it does mid-cycle |
|---|---|---|
| plan-key restart | `process_status.go` (`syncSnapshotLocked`) | `stopLocked()` + `ensureProcessLocked()` — respawns the **helper process** |
| #5134 worker arm | `manager_worker_arm_5134.go` | republishes the snapshot with `DeferWorkers=false` — starts the workers |
| busy-binding auto-rebind | `maps_sync.go` (`maybeAutoRebindBusyBindingsLocked`) | sends `rebind` — the exact inverse of the `stop_workers` just issued |
| bindings watchdog | `maps_sync.go` (`verifyBindingsMapLocked`) | repopulates binding rows a fail-closed ctrl disable had just cleared |
| ctrl gate | `helper_status_apply.go` (`resolveCtrlEnableLocked`, reached from `maps_sync.go`'s `applyHelperStatusLocked`) | re-enables `ctrl`, steering transit into XSK sockets whose queues are being destroyed |

`stop_workers` preserves registered bindings and `forwarding_armed`, so the Rust
same-plan predicate sees runnable-but-not-live bindings and reconciles by
restarting workers — which is why the first three are not hypothetical.

**The lease.** `Manager.linkCycleLeaseUntil` is an `atomic.Int64` deadline, taken
by `PrepareLinkCycle` and released by `NotifyLinkCycle`. It is atomic for the
same reason `rgTransitionInFlight` is: the guard has to survive `m.mu` being
released. Its unit is **monotonic nanoseconds** since a package-level
`linkCycleLeaseEpoch`, not `UnixNano` (#6871): a wall-clock deadline lets an NTP
step larger than the TTL expire a live lease — re-opening the very race the lease
closes — and a backward step strand a dead one. This appliance runs chrony, and a
first sync after boot can move the wall clock by minutes.

It is consulted in exactly four places:

- **at the top of the status tick's critical section**, which skips its *whole
  body*. Nothing is lost — every action in that body is level-triggered on
  persistent manager state (`publishedSnapshot` vs `lastSnapshot.Generation`,
  `pendingWorkerArm`, `pendingHAStateClear`, `lastStatus.ForwardingArmed` vs
  desired), so the next tick after the lease ends services whatever is still
  outstanding.
- **at the ctrl write in `resolveCtrlEnableLocked`** (the step
  `applyHelperStatusLocked` drives for the ctrl decision, split out of it in
  #6429), alongside the existing `rgTransitionInFlight` check. This is not
  redundant with the tick guard:
  `UpdateRGActive` also ends in `applyHelperStatusLocked`, and it runs off VRRP
  events and `reconcileRGStateLoop`'s 2s pass (`daemon_ha.go`, which also wakes
  early on dropped-event notifications) — **neither serialized on the daemon's
  `applySem`** — so it lands mid-cycle on its own schedule. Its own
  `rgTransitionInFlight` guard does not help: a demotion never sets the flag, and
  an activation clears it before the status apply.
- **at the three operator worker-affecting verbs** in `manager_status.go`
  (`SetForwardingArmed`, `SetQueueState`, `SetBindingState`), which return
  `errLinkCycleInFlight`. This is the sixth producer, and the only one reachable
  from *outside* the daemon: `request chassis cluster data-plane userspace
  forwarding|queue|binding ...` in the CLI (`cli_request_chassis.go`) and gRPC
  `SystemAction` (`server_diag_system_action.go`). Neither call site is
  serialized on `applySem` — there is no `applySem` use anywhere in `pkg/cli` or
  `pkg/grpcapi` — so an operator or an automation can fire one into the middle
  of a cycle. Each lands in a helper handler that reaches `afxdp.reconcile` and
  **spawns worker threads** (`handlers/forwarding.rs` calls
  `reconcile_status_bindings` unconditionally; `handlers/binding.rs` and
  `handlers/queue.rs` on `registration_changed`). The ctrl gate above cannot
  cover it: the spawn happens *inside the helper*, before the status this
  manager applies, so the gate has nothing left to un-spawn.

  Gated at the verbs rather than centrally in `requestLocked` because
  `requestLocked` also carries the cycle's own `stop_workers`, sent *after* the
  lease is taken — a central gate would need an exemption list for exactly the
  requests that take and release the lease. Both directions are refused, not
  only arming: a disarm does not spawn, but it still drives `afxdp.reconcile`'s
  teardown arm over sockets the cycle has quiesced, and nothing inside the
  daemon calls these three, so the broader scope blocks no internal path.

- **at `syncDesiredForwardingStateLocked`** in `manager_ha.go`, which DEFERS its
  `set_forwarding_state` publish rather than sending it. This is the **seventh**
  producer, and it is the one that shows why enumerating callers does not close
  the class: the daemon's own HA watchdog heartbeat reaches it. `SetHAWatchdog`
  runs on a 500ms goroutine in `daemon_ha_sync.go` with **no `applySem`**, and on
  the first tick for an RG, on any Active-state change, or on the 3s backstop it
  publishes the full HA state (`syncHAStateLocked`) — whose tail is this
  function. `set_forwarding_state` lands in `handlers/forwarding.rs`, which calls
  `reconcile_status_bindings` unconditionally and spawns worker threads.

  The gate sits at the **emitter**, not at `UpdateHAWatchdog`. Three callers
  reach it and only one was covered: the status tick is already inside its own
  lease skip, and the compile path runs under `applySem` (which the RETH MAC loop
  also holds). Gating the emitter covers all three, and any future caller that
  publishes forwarding state *through `syncDesiredForwardingStateLocked`*.

  It is **not** a chokepoint for the request type, and round 6 of this document
  said it was. Three other sites build a raw `set_forwarding_state`:
  `SetForwardingArmed` (`manager_status.go`), gated at its own entry point via
  `errLinkCycleInFlight`; `disarmBeforeUnsupportedPublishLocked`
  (`manager_ha.go`) and `disarmSnapshotProtocolFailureLocked`
  (`manager_compile.go`), both **ungated**. Neither ungated site has a runtime
  escape today — each is reachable only from the compile / policy-scheduler /
  route-overlay publish paths, which serialize on `applySem`, which the RETH MAC
  loop holds — but the reason is `applySem`, not this gate. A future publisher
  that runs off `applySem`, as the watchdog heartbeat does, needs its own answer.

  It **defers** rather than failing: the decision is level-triggered on
  `desiredForwardingArmedLocked()` vs `lastStatus.ForwardingArmed`, so the first
  pass after the lease ends publishes the same delta, and the 1 Hz tick
  guarantees that within a second of `NotifyLinkCycle`. Returning `nil` is what
  keeps it a deferral — callers log or propagate an error, and nothing failed.

  **The watchdog's other half is deliberately NOT gated.** `update_ha_state` is
  the only refresh of the helper's per-RG forwarding lease
  (`Coordinator::update_ha_state` → `HAGroupRuntime::active_lease_until` →
  `ActiveUntil(watchdog + HA_WATCHDOG_STALE_AFTER_SECS)`, **10s**, in
  `userspace-dp/src/afxdp/mod.rs`), and `is_forwarding_active` consults it per
  packet. Suppressing it for the length of a 60s link-cycle lease would expire
  that lease and stop forwarding for the RG — an **outage**, strictly worse than
  the respawn race being closed. Its handler (`server/handlers/ha.rs`) does call
  `refresh_status`, which can repair the WG and GRE auxiliary threads — round 6
  of this document said it "reaches no worker spawn", which is too absolute —
  but it does **not** reach `reconcile_status_bindings` or any other spawn of the
  AF_XDP **packet** workers, the only threads whose UMEM the cycle's unmap can
  race, and after a successful `stop_workers` the helper has cleared its
  worker/WG/GRE records anyway. So there is nothing to gain by suppressing it
  either. The kernel-visible shim watchdog map write is likewise never gated.

**Acquire point:** before the ctrl disable, not after a successful join. The
window that needs covering opens at the first mutation of dataplane state, and a
`stop_workers` can fail *after* the ctrl disable has already cleared binding rows.

**Release point:** the top of `NotifyLinkCycle`'s critical section — the earliest
correct point (from there we hold `m.mu` for the rest of the function, so no
producer can interleave anyway) and the latest (it precedes every `return`,
including the rebind failure, so a lease cannot be stranded on exactly the paths
where forwarding is already down). Releasing there also keeps the ctrl gate out
of the way of `NotifyLinkCycle`'s own post-rebind status apply, so a completed
cycle re-enables `ctrl` on that call instead of costing an extra reconcile tick.

**Renewal, and what the TTL actually bounds.** `linkCycleLeaseTTL` (60s) bounds
the gap between two consecutive **touches** of a lease — the acquire, each
`RenewLinkCycle`, and (since round 8) each beat of the lease's own heartbeat —
not the whole cycle.

That distinction was a defect before #6871's round 6. Only a member that actually
cycles re-arms the lease, so the exposure was the tail of members visited *after*
the last cycling one. `reth-count` is operator-settable to 128
(`pkg/config/schema_chassis.go`), step 2.6 walks the members serially, and the
dominant per-member cost — `ethtool -K <if> rxvlan off` — has a **20s** hard
ceiling, not 15: `externalCommandTimeout` is 15s and `runCommandStdinTimeout` adds
a 5s `WaitDelay` on top (`pkg/daemon/exec_timeout.go`). Four wedging members in
that tail already exceed 60s. Worse, `rethToPhys` is a Go **map**, so which
members land in the tail differs between runs — the same config would pass or
fail at random. A larger constant would have been the same defect with a bigger
number.

So the daemon renews instead. `LinkController.RenewLinkCycle()` extends a lease
that is **already held** and can never create one from the `0` sentinel
(`RenewLinkCycle` refuses unless `linkCycleInFlight()`, and its load/CAS pair
loses to a concurrent release). It is on the `LinkController` interface rather
than reached by an optional type assertion so a new implementation has to answer
for it at compile time instead of silently no-opping the renewal.

Round 6 renewed at **one** point — `programRethMemberMAC`, on every member's turn
including the ones that need no cycle — and claimed that made the TTL bound "one
member interval". That was wrong, and round 7 fixes it. The call lands at the end
of the **MAC set**, before everything expensive in a member's turn, so the real
interval between two renewals was member N's whole tail plus member N+1's MAC
set, and the final tail ran to the release with no renewal in it at all. There
are now three renewal points, all through `Daemon.renewLinkCycleLease`:

| renewal point | what the preceding interval contains |
|---|---|
| `programRethMemberMAC` | 3 netlink calls (down / set / up) |
| `finishRethMemberLinkTail` | **one** `ethtool -K rxvlan off` + one netlink round trip per VLAN child |
| `reconcileAfterRethLinkCycle` | netlink, one pass per redundancy group |
| *(release: `NotifyLinkCycle`)* | its 1s NIC settle + one control round trip |

The last two renewals are *unconditional* on whether the member cycled, and that
is safe because the renewal cannot create a lease.

**It buys nothing on the abort path, and this table used to say it did (#6871
round 15).** The claim was that gating on `needLinkCycleRecovery` "would skip
exactly the abort path, where `programRethMACWithWorkerJoin` took a lease and
then returned `linkCycled=false`". By the time these renewals run there is no
lease on that path: the rollback calls `NotifyLinkCycle`, whose first act is
`releaseLinkCycleLease`, and it does so *inside* the per-member loop — so the
word is already `0` and `RenewLinkCycle` refuses to renew from the `0` sentinel.
Whenever a lease is still held at those lines, `needLinkCycleRecovery` is true,
so the gate would have been equivalent. Ungated is still the better shape: it
does not depend on an accumulator staying in step with the lease. But the reason
is "no gate is needed", not "the gate would lose a case".

### The lease ends at the LAST repair of the apply (#6871 round 15, fixed in #7007)

**Until #7007 it ended at the FIRST.** `NotifyLinkCycle` released
unconditionally, and in a **mixed** multi-member apply — one member cycles, a
later one aborts — the aborted member's in-loop rollback was the first
`NotifyLinkCycle`, so it ended the lease while the cycled member's apply was
still running. Everything after it (the remaining members' tails, both renewals
above, and step 2.6b2's own `NotifyLinkCycle`) ran with the word at `0`, which
made those renewals no-ops. The measured trace, from the #7007 binder at the
pre-fix revision:

```
acquire  renew  renew  prepare-failed  notify(release)
         renew(NO-OP: lease already released) x3  notify(release)  abandon
```

**It is still NOT fixed by refcounting**, and that is worth keeping stated
because it is the obvious reading and it was the first suggestion made.
Acquisitions and releases do not pair: an acquisition is per **member** (each
member's `PrepareLinkCycle`), while a release is one per **repair** — one per
aborted member's rollback, plus at most one for the whole apply at step 2.6b2,
which sits *outside* the per-member loop and is gated on
`needLinkCycleRecovery`. A two-member apply where **both** members cycle
therefore takes two leases and issues exactly one release, so a refcount would
leave the count at 1 on the most ordinary multi-member path, strand the lease
until the deferred `abandonLinkCycleLease`, and make that backstop log its "apply
is leaving with a lease still held" error on every such commit. That is worse
than the gap it would close.

**What #7007 does instead is separate REPAIR from RELEASE.** The two acts were
fused in `NotifyLinkCycle`, and the fusion is the bug: an aborted member genuinely
must rebind — its own workers are joined and its ctrl is off, and nothing else
will undo that — but it has no business ending the *apply's* lease to do it. So
the in-loop rollback now calls `NotifyLinkCycleKeepingLease`, which performs the
identical rebind and renews the lease rather than releasing it, and the release
moves to the apply-wide site outside the loop.

Two arms make the release unconditional in effect:

- step 2.6b2's `NotifyLinkCycle`, when some member actually cycled
  (`needLinkCycleRecovery`); and
- an explicit end-of-apply `AbandonLinkCycle`, gated on
  `rethRollbackKeptLease`, for the apply where **every** member aborts. Without
  it that apply reaches no `NotifyLinkCycle` at all and would strand the lease to
  the deferred abandon — arriving at the refcount's failure mode by another
  route. `AbandonLinkCycle` rather than a second `NotifyLinkCycle`, because the
  rollbacks already rebound: what is owed there is the release, not another
  NIC-settle second and another worker recreate on a path where the commit is
  failing anyway.

The gate stays scoped to `rethRollbackKeptLease` rather than "release whatever is
held", so the deferred abandon keeps its teeth for the case it was written for —
the rename-join hook, which takes a lease with no release partner at all and
should still be reported.

**The failed-rollback-rebind residual, re-decided.** The old ordering made it
moot by accident: the lease was already gone before the rebind could fail. Under
a last-repair release it is a real question, and the answer is that the lease is
still released, by the end-of-apply arm above. That is deliberate and it is the
same trade this document already argues for the single-member case: on a path
where this node's forwarding is down, a stranded lease would add a frozen
reconcile loop to an outage in progress. The commit fails regardless; what the
release buys is that the 1 Hz reconcile resumes and can attempt recovery. The
difference from before is that the protection now covers the whole apply
*including* the failed-rebind window, instead of ending before it.

**Bound by a multi-member fixture that had to be built.** Three existing pieces
each blocked reusing one: `rethCallsiteConfig` is deliberately one member;
`newRecordingRethOps` returns a single shared fake link that ignores the
interface name, with one global `liveFail`; and `abortRecoveryLinkController`
models the lease as a bool only `AbandonLinkCycle` clears, so it cannot observe
"still held". `reth_multimember_lease_7007_test.go` supplies all three.

Its assertions are **counts and invariants, never sequences**, because the apply
iterates `rethToPhys` — a Go map — so member order is randomised per run. The
error is injected by CALL order rather than by member identity, which is what
makes the binder deterministic in either traversal instead of a 50/50 flake.

**Round 7's answer was still an estimate, and round 8 stopped estimating.** The
round-7 claim — "exactly one interval contains the only term with a hard ceiling,
the 20s `ethtool`, so 60s is 3x the only bounded term" — was honest and
insufficient, because the *other* terms in that same interval scale with things
an operator sets:

| term | what bounds it |
|---|---|
| the VLAN-child loop in `finishRethMemberLinkTail` | one pass per child netdev — a member can carry one VLAN sub-interface per VLAN id, each pass a sysctl write plus up to three netlink round trips |
| the per-RG loop in `reconcileAfterRethLinkCycle` | the redundancy-group count |
| the enclosing member loop | `reth-count`, schema ceiling 128 |
| any single netlink syscall | **nothing** — it can block indefinitely |

The last row is the one no amount of call-site renewal can reach: a blocking
syscall sits *between* two renewals by construction. A single member with a few
thousand VLAN children exceeds 60s in one interval before the second member is
visited, and no constant fixes that — a bigger one is the same defect with a
bigger number.

So the lease now **renews itself**. `acquireLinkCycleLease` starts a goroutine
that calls `RenewLinkCycle` every `linkCycleLeaseHeartbeat`
(`linkCycleLeaseTTL / 4`, i.e. 15s); `releaseLinkCycleLease` stops it and
**joins** it, so a released lease can never be extended by a beat still in
flight. The interval the TTL must cover is therefore a constant, independent of
member count, VLAN-child count, redundancy-group count and netlink latency, and
the TTL is 4x it — three missed beats of headroom for a saturated box, a GC
pause or a descheduled goroutine. The three daemon call sites stay: they are no
longer load-bearing, but they are free (a renewal cannot create a lease) and they
keep a heartbeat that failed to start degrading to round 7 rather than to no
renewal at all.
That goroutine has **exactly one exit**, and it is load-bearing (#6871 round 9).
Round 8 gave it a second — a self-reap when the lease word read `0` — which
returned *without* clearing `linkCycleHB.stop/done`, while
`startLinkCycleHeartbeat`'s idempotence guard tests that **field** rather than
goroutine liveness. One reap therefore left the field non-nil with nothing
running, and every later `acquireLinkCycleLease` **in the same apply** silently
started no heartbeat at all: every RETH member cycled after that point ran on
round-7 protection. The trigger was the case this design is built around — the
TTL backstop retiring a lease after four missed beats, i.e. exactly the
starvation the 4x margin exists to absorb. Clearing the fields inside the reap
was rejected as the fix: a release plus a fresh acquire can install a new
`stop`/`done` between the reap's decision and its lock, so the dying goroutine
would clear its successor's state. One exit needs no identity check.

**A self-renewing lease needs a guaranteed release, and that is the other half.**
A heartbeat keeps a live lease alive indefinitely — correct while the cycle runs,
and catastrophic once its owner is gone, because a leaked lease would suppress
the 1 Hz reconcile *permanently* instead of for one TTL. So
`applyDataplaneAndHACore` defers `Daemon.abandonLinkCycleLease`, which calls
`LinkController.AbandonLinkCycle()`: it drops a still-held lease, reports whether
there was one (a `true` is a bug report, logged at `Error`), and does **not**
rebind — the rebind already has two owners (step 2.6b2 and the abort rollback)
and a third would be the double rebind that gets `EBUSY` on mlx5 zero-copy
queues. Dropping the lease alone *is* the recovery: it hands the helper back to
the 1 Hz reconcile, which re-arms bindings and workers on its own.

The defer is on the extent that contains both ends of the cycle, so it runs on
every exit including a panic and any early return a later change introduces.

Neither half is correct alone: without the heartbeat the TTL is a guess, and
without the guaranteed release the heartbeat turns a leak into a permanent
outage. What remains is a caller **blocked forever** inside the cycle — and there
holding is the right answer, because the workers really are joined.

**How fast the abandon recovers, stated as what it is.** What resumes within a
tick is the *reconcile* — the status loop stops skipping its body, so the ctrl
re-enable is available on the next pass, ~1s. Restoring *forwarding* is slower:
the busy-binding auto-rebind that recreates workers is gated by
`shouldAutoRebindBusyBindingsLocked` on a wedge observed for >= 5s, a 15s
rate limit, and `lastStatus.ForwardingArmed`. So the honest figure is **seconds**,
not one tick. An earlier revision implied the latter (#6871 round 9).

**The TTL does not back an out-of-extent acquisition up at all**, and an earlier
revision of this paragraph claimed the opposite — that the TTL "is now a backstop
for exactly one residual: a lease acquired outside that deferred extent" (#6871
round 13). `acquireLinkCycleLease` starts the heartbeat wherever it is called
from, and the heartbeat re-arms the deadline every 15s for as long as the word is
non-zero. A lease taken outside the daemon's deferred `AbandonLinkCycle` is
therefore precisely the lease the TTL can never reach: it renews itself until the
process exits.

What the TTL *does* back up is a heartbeat that is alive but **starved** — four
missed beats, which is what the 4x margin is chosen for. That case stays bounded
and loud rather than silent: `linkCycleInFlight` logs a `Warn` under the CAS when
it retires an expired lease, and the behaviour it degrades to is master's, where
the tick was never suppressed at all.

Which makes the guards the *only* thing covering a second acquisition site, not a
supplement to a timer. Since #6871 round 9 the property is **enforced** rather
than merely stated: `link_cycle_acquisition_site_6871_test.go` walks the whole
module for `PrepareLinkCycle` calls against an allowlist, and separately pins that
the unexported `acquireLinkCycleLease` is reached only from
`Manager.PrepareLinkCycle` (an in-package caller would bypass the chokepoint
entirely). Round 8's comment named the first of those as existing enforcement
when no such test existed.

Both guards classify by **position**, not by name (#6871 round 13). A selector
that is a call's callee is a call site and is checked against the allowlist;
every other reference form — a method value above all — is rejected outright,
because a value can be stored and invoked anywhere later, so the declaration it
was written in bounds nothing. The escape that forced this was compiled, not
imagined: taking `m.acquireLinkCycleLease` as a method value *inside* the
allowlisted `PrepareLinkCycle`, leaking it through a package-level variable, and
calling it after the apply returned left the only matching selector in the
allowlisted declaration and both guards green.

**Callee position is not temporal containment, and the allowlist now says which
it has (#6871 round 14).** Round 13's key named the declaration a call is written
in, on the reading that reaching the call requires being there. True — and it
says nothing about *when* the call runs relative to that declaration. Two forms
were green against it, both compiled: an acquisition inside a func literal that
escapes to a package-level variable and is invoked after the apply returns, and
`go m.acquireLinkCycleLease()`, whose goroutine can outlive the whole apply. So a
call's key now carries the form — `[in a func literal]`, `[started by a go
statement]` — for every way of writing it that the AST cannot prove runs inside
the enclosing declaration's extent. Ordinary flow, `defer`, and an immediately
invoked literal are contained and carry no marker; anything else cannot come to
rest on a key that reads as a proof.

**Markers are a list, not a set (#6871 round 16).** They describe the chain of
boundaries between the call and its declaration, so collapsing equal entries
destroys the nesting depth — the same multiplicity mistake as the call map,
in a different container. With duplicates removed, an inner literal that
*shadows the outer one's name* renders the same marker at both levels, the two
merge, and the key becomes byte-identical to the allowlisted single-level one
while the acquisition is launched on a goroutine that outlives the apply.
Measured green before the fix. A third marker, `[under a constant-false if]`,
covers a decoy written to keep an allowlist entry satisfied after the real
acquisition is deleted; general reachability is undecidable syntactically, and
what bounds *that* residual is the daemon's own suite, because an acquisition
that stops happening changes observable behaviour.

The named behavioural proof is checked for three things — that it exists, that
its file is **in the build** (a `//go:build never` dummy is in no test binary at
all), and that it has a `func TestXxx(*testing.T)` signature `go test` will
actually run. What is left is one honest sentence: nothing verifies the named
test *proves* what the entry says it proves. That needs a reader.

That distinction is not academic here, because **the daemon's one production
acquisition is itself a marked site**: it is written in the `beforeCycle`
callback, and what keeps it inside `applyDataplaneAndHACore`'s deferred abandon
is that `programRethMAC` invokes that callback synchronously — a fact about
another package that no local AST inspection reaches. Establishing containment in
general needs whole-program call-graph and escape analysis, which these guards do
not do and do not claim. What they do instead is make the gap explicit and
force it to be paid for elsewhere: every marked site must name a behavioural test
in `linkCycleUnprovenFormBindings`, that test must exist (checked by scanning the
tree, so renaming it away fails the guard), and for this site it is
`TestRethMACHookRunsOnTheCallersGoroutine_6871`, which asserts the hook runs on
the caller's goroutine. A callback dispatched to another goroutine and joined
before returning would also be contained, and fails that test deliberately: it is
a different containment argument and should have to be made again.

Call identity is also the selector's **full source text**, not the method name
(#6871 round 14). Under a name-only key, any same-named call written in the
allowlisted declaration held its entry up after the real acquisition was deleted
— measured, with `hooks.acquireLinkCycleLease[0]()` substituted for
`m.acquireLinkCycleLease()` and both guards still green while the manager took no
lease at all. What that does *not* reach is a decoy with identical source text
resolving to a different type; distinguishing those needs `go/types` over the
whole module, which these guards deliberately do not run.

**`linkCycleInFlight` re-reads on a lost CAS (#6871 round 8).** Four writers
touch the lease word: the expiry CAS in `linkCycleInFlight`, `RenewLinkCycle`'s
CAS, `acquireLinkCycleLease`'s `Store`, and `releaseLinkCycleLease`'s `Store(0)`
— which an earlier revision left out of the count while listing its outcome in
the table below (#6871 round 13). Any of the other three can land between the
reader's `Load` and its CAS, and the reader's CAS then **fails**. The
previous code returned `false` regardless, discarding the CAS result — but the
value the word moved *to* is what decides the answer:

| the word moved to | what happened | correct answer |
|---|---|---|
| `0` | a concurrent release retired it | no cycle |
| a later deadline | a renewal extended a **live** cycle | **in flight** |
| a fresh deadline | a new `PrepareLinkCycle` | **in flight** |

Two of the three read the opposite way from the discarded expiry, so the old form
unlatched the guard for the remainder of a cycle that was still running — and the
renewal case is the sharp one, because a renewal landing on the expiry instant is
precisely what renewal is *for*. The mechanism added to strengthen the lease was
the one most likely to defeat it. The fix loops: report "expired" only if this
goroutine's CAS is the one that retired it, otherwise re-read and judge the new
value.

One further precision on the renewal, since round 6 overstated this too: "it
never renews an expired lease" is stronger than the code. A renewal can pass the
`linkCycleInFlight()` check while the lease is live, be descheduled past the
deadline, and then CAS a still-nonzero — by then expired — deadline forward,
because no reader happened to observe the expiry and retire it to `0` in the
interim. What is true is narrower and still sufficient: the call **began** while a
cycle genuinely owned the dataplane, so it extends a real cycle rather than
conjuring one, and the overshoot is bounded by the deschedule window.

**The rollback now reports.** `NotifyLinkCycle` returns an `error`. Its rebind is
the documented inverse of `stop_workers`, and a failure used to be a `slog.Warn`
and a bare return on a void function — so a clean cycle whose rebind failed left
every worker stopped **while the commit reported success**, a silent total
dataplane outage. Both call sites now fold it into the commit under the same
`errRethPrepareLinkCycle` class as a failed join: the per-member rollback joins it
onto the abort cause (which stays, being the more actionable of the two), and step
2.6b2 joins it into the apply's commit error. The error's scope is deliberately
narrow, mirroring `PrepareLinkCycle`'s: it reports whether the **rebind** landed,
not whether the subsequent status apply did — `applyHelperStatusLocked` fails with
"userspace_ctrl map not loaded" whenever no shim is attached, and failing a commit
on that would be an over-rejection.

| file | role |
|------|------|
| `pkg/dataplane/userspace/manager.go` | `linkCycleLeaseUntil` — the atomic deadline; `linkCycleHB` — the heartbeat's own state |
| `pkg/dataplane/userspace/process_linkcycle.go` | `acquireLinkCycleLease` / `releaseLinkCycleLease` / `RenewLinkCycle` / `AbandonLinkCycle` / `linkCycleInFlight` + the monotonic epoch, the TTL, and `linkCycleLeaseHeartbeat` with `start`/`stopLinkCycleHeartbeat` |
| `pkg/dataplane/userspace/manager_ha.go` | the `set_forwarding_state` deferral (covers the HA watchdog heartbeat) |
| `pkg/daemon/daemon_apply_dataplane.go` | `renewLinkCycleLease` + its three call sites — `programRethMemberMAC`, `finishRethMemberLinkTail`, `reconcileAfterRethLinkCycle` — and `abandonLinkCycleLease`, deferred over the whole of `applyDataplaneAndHACore` |
| `pkg/dataplane/userspace/process_status.go` | the tick-wide skip |
| `pkg/dataplane/userspace/maps_sync.go` | `ctrlMustStayDisabledLocked` — the ctrl-write gate predicate (covers `UpdateRGActive`) |
| `pkg/dataplane/userspace/helper_status_apply.go` | `resolveCtrlEnableLocked` — where that predicate is consulted (#6429) |
| `pkg/dataplane/userspace/manager_status.go` | `errLinkCycleInFlight` + the three operator-verb gates |
| `pkg/dataplane/apply.go` | `LinkController.NotifyLinkCycle() error` + `LinkController.RenewLinkCycle()` + `LinkController.AbandonLinkCycle() bool` |
| `pkg/dataplane/userspace/controllers.go` | `userspaceLinkController.NotifyLinkCycle()` — the live adapter carrying the rebind error to the daemon |

### The production adapters are load-bearing, and are tested as such

The daemon never touches `*userspace.Manager`. It holds a
`dataplane.RuntimeDataPlane` and reaches the dataplane through two thin seams:

```
Daemon -> dp.Link() -> userspaceLinkController -> Manager.<method>
Daemon -> dp.HA()   -> userspaceHAController -> managerHAOps -> Manager.<method>
```

Every hop is a two-line forwarder, which is exactly why tests skip them: calling
`m.UpdateHAWatchdog(1, ts)` is easier than building `dp.HA()` and calling
`SetHAWatchdog(ctx, 1, ts)`, and the assertion reads the same. It is not the
same. Before round 7, replacing any of these bodies with `return nil` left
`pkg/dataplane/userspace` **and** `pkg/daemon` fully green while removing the
behaviour from production entirely — measured, for seven distinct forwarders.

The worst two are the watchdog hops: severing either stops the daemon's 500ms
heartbeat from refreshing the helper's 10s per-RG forwarding lease, so the lease
expires and the redundancy group **stops forwarding**. Severing
`userspaceLinkController.RenewLinkCycle` removes every production renewal of the
link-cycle lease while leaving all of its tests green.

`pkg/dataplane/userspace/runtime_adapter_binding_6871_test.go` drives **every**
method of both adapters through `m.Link()` / `m.HA()` — the same constructors the
daemon uses, so severing a constructor is caught too — against an observable only
the real inner `Manager` can produce (a control-socket request, a manager field,
the lease deadline, or the specific error a missing BPF map raises).

**Round 8 made that structural, because counting by hand kept under-counting.**
Codex found two unbound forwarders; the round-7 sweep answering it found six;
Codex then found a **seventh**, `userspaceLinkController.RecordDeferredWorkerArmDebt`.
Every one of those numbers was a lower bound, because every one was somebody
enumerating by hand and stopping at what they could see — so an eighth
hand-written cell would have had the same property.

`controllers_binding_table_6871_test.go` therefore **derives** the surface
instead of listing it. It parses this package's non-test sources for every method
declared on `userspaceLinkController`, `managerHAOps`, `userspaceHAController` or
`userspaceSessionStore`, and fails if any of them lacks a row in
`adapterBindingTable` — so adding an adapter method without answering for it is a
named test failure rather than a silent gap. Each row then drives the method
through the production constructor. A row may instead carry a `cannotDrive`
reason, which makes a gap **visible in the table** rather than absent from it.

Two things that enumeration alone got wrong, both now covered:

- `userspaceHAController.SetFabricForwarding` calls `managerHAOps.SyncFabricState`
  **directly**, bypassing `userspaceHAController.SyncFabricState`'s body. The
  map-free fixture never reaches that tail (the fabric update fails first), so a
  fake `userspaceHAOps` whose updates succeed drives it — `userspaceHAOps` being
  an interface is what makes that possible. Without it, deleting the
  "always push helper fabric state after a successful update" line was invisible.
- `RecordDeferredWorkerArmDebt` is reached by an optional type assertion, not
  through `LinkController`, so its cell asserts the same way
  `Daemon.recordDataplaneWorkerArmDebt` does — a failed assertion *is* the
  severance. Its live reachability is narrower than first reported: production
  `d.dp` is `*LegacyDataPlaneAdapter`, which satisfies that assertion itself, so
  the `d.dp.Link()` fallback is a latent path rather than the live one today.

The two files overlap on purpose. The older one's cells were each measured
against a real severance, and a table that subsumed them would be a table that
could retire one by accident.

Known boundaries of the derivation, stated rather than left to be found: it does
not cover methods **promoted** from `userspaceSessionStore`'s embedded
`dataplane.SessionStore` (those are the implementation, not a forwarder), and the
one hand-maintained list left is the set of controller *types* — a new type is a
new production seam that gets reviewed, unlike a two-line method added to an
existing one.

## Deferred AF_XDP Worker Arming After a Live MAC Change (#5134)

Programming the virtual MAC can happen two ways:

- **Link cycle** (`programRethMAC` had to bring the member DOWN/UP): the old
  AF_XDP sockets die with the cycle. The daemon calls `NotifyLinkCycle()`,
  which sends `rebind` to the helper and recreates the workers with fresh
  sockets. This path arms the workers via the rebind, independent of the
  published snapshot's `DeferWorkers` flag.
- **Live MAC set** (the kernel accepted the address change on an UP link, or the
  fast path set it while the link was still DOWN — either way, no cycle): the
  initial dataplane
  apply of the commit ran with `SetDeferWorkers(true)` so worker startup was
  skipped (avoids the mlx5 zero-copy double-bind EBUSY). The published
  snapshot therefore carries `DeferWorkers=true` and is **workerless /
  non-forwarding**. The daemon then issues a MANDATORY second `ApplyConfig`
  (`reapplyAfterDeferredMAC`) with the correct MAC and `DeferWorkers` cleared —
  that re-apply is what actually starts the workers.

The re-apply is failure-critical. The userspace manager only advances its
snapshot bookkeeping (`lastSnapshot` / `publishedSnapshot` / `lastSnapshotHash`)
on a **successful** `apply_snapshot` publish. If the re-apply's publish fails
(helper rejects it, control-socket error, resource pressure) and the daemon
swallows the error, the manager keeps the workerless `DeferWorkers=true`
snapshot as the published/last state, status reconciliation replays it, the
workers never bind, and the commit still reports success — a silent forwarding
outage on that node.

**Contract:** `reapplyAfterDeferredMAC` never swallows the re-apply error. On
failure it records **generation debt** via `RecordDeferredWorkerArmDebt()`
(`Manager.pendingWorkerArm`). The 1 Hz status reconcile loop calls
`retryDeferredWorkerArmLocked()`, which republishes the retained snapshot with
`DeferWorkers=false` and a bumped generation until the workers bind, then clears
the debt. A transient helper error self-heals without failing the commit; the
node never terminally publishes a workerless snapshot while reporting success.

| File | Function |
|------|----------|
| `pkg/daemon/daemon_apply_dataplane.go` | `reapplyAfterDeferredMAC()` — mandatory re-apply; records debt on failure (moved from `daemon_apply.go` in #4407) |
| `pkg/daemon/daemon_apply_dataplane.go` | `recordDataplaneWorkerArmDebt()` — routes the debt to the dataplane |
| `pkg/dataplane/userspace/manager_worker_arm_5134.go` | `RecordDeferredWorkerArmDebt()` / `retryDeferredWorkerArmLocked()` |
| `pkg/dataplane/userspace/process_status.go` | status loop drives the retry each tick |

## Reboot Safety

- Bootstrap `.link` files (from `setup.sh`) use the physical MAC for udev rename
- After daemon programs the virtual MAC, the kernel MAC changes
- On next `applyConfig()`, if the kernel MAC is a virtual RETH MAC (`02:bf:72:...`), the compiler skips writing a `.link` file for that interface
- This preserves the bootstrap `.link` file with the physical MAC
- On reboot, udev matches the physical MAC (NIC resets to factory MAC) and renames correctly
- Daemon starts and re-programs the virtual MAC

## Implementation

| File | Function |
|------|----------|
| `pkg/cluster/reth.go` | `RethMAC(clusterID, rgID)` -- returns deterministic MAC |
| `pkg/cluster/reth.go` | `IsVirtualRethMAC(mac)` -- detects virtual RETH pattern |
| `pkg/daemon/daemon_reth.go` | `renameRethMember()` -- renames a member found by virtual MAC (down → rename → **up**, #3920); takes the same `beforeCycle` AF_XDP worker-join hook as `programRethMAC` (#6911) |
| `pkg/daemon/daemon_reth.go` | `programRethMAC()` -- sets MAC via netlink (step 2.6 in applyConfig); takes the mandatory `beforeCycle` AF_XDP worker-join hook (#5103) |
| `pkg/dataplane/compiler.go` | Skips `.link` file when RETH member has virtual MAC |

## Impact

- **XDP forwarding**: `bpf_fib_lookup` automatically returns the virtual MAC as `fib.smac` -- no BPF changes needed
- **GARP/NA**: `net.InterfaceByName()` returns the virtual MAC -- no code changes needed
- **VRRP**: advertisements use the virtual MAC -- neighbor caches stay valid across failover
- **IPv6 link-local**: both nodes derive the same `fe80::bf:72ff:fe01:RR00` -- seamless failover
