# pkg/ipmon

`services ip-monitoring` engine (#1827 PR-1b): Junos-parity
probe-driven preferred-route failover. A policy matches one RPM probe;
while ANY test of that probe is FAILED, the policy's preferred routes
are injected (at route preference 1 — Static/1, beating static AD 5 and
DHCP AD 200); on recovery they are withdrawn (after the optional
`hold-down`, an extension beyond Junos that damps recovery flaps).

## The single decision point

`ActiveOverlay()` is the engine's **effective-route overlay**: the set
of currently-injected routes after winner resolution — per
(routing-instance, prefix) the lowest `preferred-metric` wins,
tie-break lexicographic policy name. Both consumers read the SAME
overlay, so kernel and dataplane agree by construction:

1. **FRR** — `frr.FullConfig.PreferredRoutes`, rendered as distance-1
   statics in the managed section (emission step 7), assembled by the
   daemon's `assembleFRRConfig` for BOTH the full apply path and the
   routes-only actuator.
2. **Dataplane snapshot** — `buildRouteSnapshots` overlay parameter;
   an overlay winner replaces the ENTIRE (table, family, prefix) entry
   set (never merges next-hops — no ECMP half-override), published via
   `userspace.Manager.PublishRouteOverlaySnapshot`.

## Actuation

Coalesced: dirty bit + bounded debounce (1 s) + minimum
inter-actuation throttle (3 s); at most one actuation in flight (the
single run-loop goroutine); the actuator snapshots the overlay at run
time (last-writer-wins). `Apply` marks dirty only when the effective
overlay actually changed (Codex PR #1843 MED) — overlay-neutral
commits never schedule a routes-only FRR reload, and the actuator
bumps the FIB generation only when `PublishRouteOverlaySnapshot`
reports a REAL publish (duplicate-skips do not churn established-flow
route caches). A sustained per-cycle flapper with hold-down 0
produces at most one frr-reload + one snapshot push per throttle window
— bounded and observable via `xpf_ipmon_policy_transitions_total`.

### Three separate properties, and what can observe each (#8027)

"Coalesced" above bundles three mechanisms that fail independently, and a
test that observes one is easy to mistake for a test that observes all
three. The distinction cost a green test that covered nothing:

| mechanism | what it does | falsified by |
|---|---|---|
| **dirty bit** | one actuation covers every pending change | a count of actuations under a storm |
| **debounce** | DELAYS actuation until the window elapses | a latency LOWER bound after a change |
| **throttle** | paces consecutive actuations | a latency lower bound after an actuation |

**A count cannot see the debounce.** Because the dirty bit makes one
actuation cover every pending transition, a flap storm coalesces *by
design* — the count stays low whatever the window does. `TestDebounceCoalescing`
asserted `<= 2` actuations under a ten-flap storm, and stayed GREEN with the
debounce disabled outright (`now.Sub(e.dirtySince) >= e.debounce` changed to
`>= 0`). Its bound was satisfied by the shape of the code, not by the
behaviour it was named for, so it could not distinguish *coalescing works*
from *multiple actuations are unreachable in this fixture* — which is true
regardless. It is now `TestActuationCountStaysBoundedUnderFlapStorm`, which
is what it does cover.

The debounce's and throttle's own properties are latency lower bounds, in
`debounce_falsifiable_8027_test.go`. Two things make those assertions stable
rather than a new timing flake:

- they run on the package's **fake clock**, so the window is crossed by
  `clock.Advance` and not by elapsed wall time;
- the load-bearing assertion is an **absence** — nothing actuated before the
  window — and contention can only make an actuation LATER, never earlier. A
  loaded machine cannot produce a false RED. It could produce a false GREEN
  (a wedged loop that never actuates at all), which is why each cell is
  bracketed by liveness waits proving the engine actuates both before and
  after the quiet period.

**Each is set small while the other is under test, deliberately.** With the
production proportions the throttle is the binding constraint, and an
actuation held back by the throttle is indistinguishable from one held back
by the debounce — a test written that way passes with the debounce disabled,
which is the defect being fixed.

### Probe verdicts survive a probe restart (#6561)

`evaluateLocked` computes `anyFailed` from `e.failedTests`, which
`seedResultsLocked` fills with `r.LastStatus == "fail"` — so `"unknown"`
buckets with `"pass"`. Combined with the DEFAULT `hold-down` of 0 (Junos
parity: withdraw immediately on recovery), a results snapshot in which
every test reads `"unknown"` recovers the policy and withdraws an ACTIVE
failover route **in the same call**.

That used to happen on an ordinary commit. `reconcileRPM` is hash-gated,
but the hash covers `cfg.RethToPhysical()` as well as the RPM stanza, so
adding, removing or renaming any RETH member — an interface-stanza edit
that never mentions `services rpm` or `services ip-monitoring` — reopened
the gate, and `rpm.Manager.Apply` then rebuilt its whole results table
from config with every key seeded `"unknown"`. `Apply` here goes to real
trouble to preserve its own runtime half (`st.failed = prev.failed`), and
the reseed immediately overwrote it from the wiped snapshot. The
commit's own FRR render is snapshotted **before** step 17c, so the
withdrawal never appeared in the commit output — it landed on the
delayed actuation about a second later.

The fix is in `pkg/rpm`, not here: `Manager.Apply` snapshots the prior
results before `StopAll` reallocates the table and carries a test's
runtime verdict forward when its RESOLVED measurement identity — probe
type, target, source, routing-instance, next-hop, and the destination
interface **after** RETH translation — is unchanged. The reconcile is
not skipped; probes genuinely must restart when their marks are
reprogrammed. What is preserved is the half the config does not carry.

Two boundaries that must not drift:

- **ABSENT is not UNKNOWN.** A key the config dropped stays absent, and
  an absent key still clears a stale FAIL (#4423 M8) — no probe, no
  protection. The carry-forward only ever fills a key present in both
  tables.
- **The identity is a resolved PATH, not the fwmark.** An earlier
  revision compared marks; `BuildProbePins` assigns
  `ProbeFwmarkBase + idx` over sorted probe/test names, so a mark is a
  POSITION in the pin band. It does not move when a RETH remap changes
  the resolved interface, and it does move when an unrelated test sorts
  earlier. Both directions are wrong.

The daemon actuator (`pkg/daemon/daemon_ipmon.go`) runs under the SAME
apply semaphore as operator commits and bumps the FIB generation ONLY
after a successful snapshot publish (ordering is load-bearing — see
`actuateRouteOverlayLocked`).

### Consistency + autonomous self-heal (#3757)

The actuator returns a `bool`; the engine clears its dirty bit **only
after** the actuator reports a fully consistent, converged actuation.
Any consumer failure keeps the state dirty and the run loop retries
autonomously on the next sweep, throttle-paced (at most one
frr-reload + snapshot per throttle window), until it converges — no
future config change is required to recover.

- **Hard FRR reload error (H1):** the FRR manager contract guarantees
  *nothing converged* — the kernel FIB still holds the previous routes
  — so the actuator **aborts before publishing** the userspace
  snapshot. Publishing on top would split the FIB (kernel on the old
  route, dataplane on the failover route). Both FIBs stay on the last
  consistent state and the retry re-applies once FRR recovers. A
  **degraded** reload (#1880, additive `vtysh -f` applied) is *not* a
  hard error: the new routes are live in the kernel, so the matching
  snapshot publish keeps the two FIBs in agreement while the FRR
  manager's own retry converges stale-config removal.
- **Snapshot publish error (H2):** no FIB-generation bump, state stays
  dirty, retried on the next sweep.
- **Unconfirmed FIB-generation bump (H3):** `pendingFIBBump` is armed
  *and* the actuation reports failure, so the bump retries on the next
  autonomous sweep (not only on a future unrelated actuation).
- **Dirty cleared only on success (M1):** the run loop snapshots a
  `dirtyGen` before actuating and clears `dirtySince` only when the
  actuation converged AND no newer change landed meanwhile
  (last-writer-wins preserved).
- **Bounded per-actuation timeout (#4423 L):** each `actuate()` call
  runs under a `DefaultActuateTimeout` (30 s) child of the shutdown
  context, so a wedged consumer — an apply semaphore never released by a
  stuck operator commit — cannot hold the run loop off its next retry
  indefinitely while the daemon is up. It bounds only the ctx-checked
  wait (the semaphore acquire, #3758); a live FRR reload past that point
  is never interrupted mid-apply. A timed-out actuation returns `false`,
  so it folds into the same self-heal retry. `Stop` still cancels the
  parent context, so shutdown abort is unaffected.
- **Actuation-failure counter (#4423 L):** every non-converged actuation
  (any of H1/H2/H3 above, or a timeout/shutdown abort) increments a
  monotonic counter exported as `xpf_ipmon_actuation_failures_total`
  (`ActuationFailures()`), making the otherwise-silent retry loop
  observable — a steadily-climbing value means the overlay cannot commit
  and failover protection is degraded. Pair it with a sustained
  `xpf_ipmon_routes_desired > xpf_ipmon_routes_applied` gap.

## HA

Overlay is runtime state, never config: it does not sync to the peer
and re-derives from fresh probe results within seconds of a takeover.
`SetPublishEnabled(false)` (standby) makes `ActiveOverlay` return nil —
the config baseline — while the state machine keeps tracking
underneath. Primary-only probing/publication scope is computed in
`pkg/daemon` (`filterRPMForHAGating`, `ipmonPublishAllowed`).

While gated off, `NotifyNextHopChange` is a no-op (#4423 M4): the
published overlay is the baseline regardless of any DHCP-learned
gateway, so a lease change on the standby cannot alter what this node
publishes — scheduling an actuation would only churn a no-op
frr-reload + snapshot. `SetPublishEnabled(true)` on takeover re-actuates
and the overlay then follows the fresh lease.

## DHCP-tracked next-hops (#1844)

An interface-typed preferred route (`next-hop ge-0/0/3.0`, compiled to
`PreferredRoute.NextHopInterface` — the Linux DHCP lease key) is
resolved to the unit's DHCP-learned gateway **inside the engine,
before winner selection**, via the injected `NextHopResolver`: an
unresolvable winner (no lease) is skipped so a resolvable losing
candidate can win the prefix — resolving after selection would get
this wrong by construction. Resolved entries carry the gateway in
`RouteOverlayEntry.NextHop` (plus the lease key in
`NextHopInterface`), so FRR render and the snapshot builder are
unchanged. Skipped candidates surface as
`PolicyStatus.UnresolvedRoutes` (a typed `UnresolvedRoute` with the
routing-instance, tracked unit, metric, and reason — shown by
`FormatStatus` and exported as `xpf_ipmon_unresolved_next_hops`).

## Status truth model (#3761)

`Status`/`FormatStatus`/metrics distinguish converged truth from intent:

- **UNKNOWN vs PASS (H7).** `PolicyStatus.Known` is false until the
  policy's probe has produced at least one result. `FormatStatus`
  renders `Status: UNKNOWN` in that window — never `PASS`. An operator
  reading `PASS` would assume failover protection is active when no
  probe has run.
- **Applied vs desired (H8).** `PolicyStatus.Routes` is the DESIRED
  winner-resolved overlay (what the engine wants injected).
  `PolicyStatus.AppliedRoutes` is the subset of the last CONVERGED
  actuation's overlay owned by the policy — what is actually live in the
  kernel + userspace FIBs. The engine records `appliedOverlay` only when
  the run loop confirms a consistent actuation (`actuate()==true` and no
  newer change landed), so it holds the last good state across a
  failing/pending actuation (#3757). `RoutesApplied()` and
  `xpf_ipmon_routes_applied` report applied; `xpf_ipmon_routes_desired`
  reports desired. A sustained `desired > applied` gap means the
  actuator has not converged the failover routes.
- **Suppressed vs unresolved (M9/M10).** A FAILED policy's resolvable
  candidate that lost winner resolution to another policy is reported in
  `PolicyStatus.SuppressedRoutes` (`suppressed by policy <name>`),
  distinct from an interface-typed candidate skipped for a missing
  next-hop (`UnresolvedRoutes`). Neither reads as a bare "(none
  applied)".

`NotifyNextHopChange` is the DHCP gateway-change trigger (wired to
`dhcp.New`'s `onGatewayChange` hook): it marks the overlay dirty only
when a currently FAILED policy has an interface-typed route, and
enters the SAME dirty→debounce→throttle queue as probe transitions —
no second actuation path, no full apply.

**Lock order (one-way, load-bearing):** `Engine.mu → dhcp.Manager.mu`.
The resolver (called under `Engine.mu`) takes `dhcp.mu` via
`LeaseFor`; `pkg/dhcp` fires the hook strictly OUTSIDE `dhcp.mu`, so
the hook's bounded blocking on `Engine.mu` can never deadlock. The
resolver must never call back into the engine.

Withdrawal: a removed lease record (client stopped, unit
deconfigured) fires the hook → resolver returns `!ok` → next actuation
withdraws the route. A failed re-acquisition keeps the last-known
gateway (record persists until replaced) — deliberate parity with the
FRR DHCP default route; see the RFC 2131 coupling rule in
`pkg/dhcp/README.md`.

## Entry points

- `Engine`, `New(actuate func() bool)`, `Start/Stop` — `ipmon.go`.
  The actuator returns `true` on a consistent, converged actuation and
  `false` to keep the state dirty for an autonomous retry (#3757).
- `Apply(cfg, results)` — install committed policies, preserving FAIL
  state for surviving (name, probe) pairs. A non-nil `results` slice is a
  full authoritative snapshot, including a non-nil empty slice that clears
  known test state. A nil slice means no snapshot is available and preserves
  the last known state; it must not be used to represent authoritative-empty.
- `HandleTransition(rpm.Transition)` — the sensor input (wired to
  `rpm.Manager.SetTransitionCallback`). RPM supplies an authoritative,
  non-nil results snapshot; the transition itself is still applied if a
  caller omits that snapshot.
- `SetNextHopResolver(NextHopResolver)` (before `Start`; mu-guarded so a
  late call cannot race the run loop's resolver read, #4423 L) and
  `NotifyNextHopChange()` — the #1844 DHCP next-hop seam (above).
- `ActiveOverlay() []config.RouteOverlayEntry`.
- `Status() []PolicyStatus`, `FormatStatus` (`display.go`) — shared by
  the local CLI and gRPC `show services ip-monitoring status`.

## Callers

`pkg/daemon` (engine lifecycle + actuator + next-hop resolver),
`pkg/cli`, `pkg/grpcapi`, `pkg/api` (metrics).

## Dependencies

`pkg/config`, `pkg/rpm`.
