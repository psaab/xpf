# #1519 daemon legacyDP() shrink + delete — plan v1 (DRAFT)

**Status:** DRAFT v1 — pending Codex + Antigravity plan-review.

Issue: https://github.com/psaab/xpf/issues/1519
Parent: #1451 (eBPF retirement migration scope).
Sibling/blocker context: #1516 (grpcapi), #1517 (cli), #1518 (cluster
session-sync). All three explicitly listed as `Depends on` in the #1519
issue body; all three are currently OPEN with no PR.

## 1. Issue framing

`pkg/daemon/daemon.go` defines `(*Daemon).legacyDP() dataplane.DataPlane`
as an escape hatch for daemon call sites that still want the legacy
BPF-shaped interface. `d.dp` is typed `dataplane.RuntimeDataPlane`
(the post-#1381 narrow surface); `legacyDP()` is a type assertion that
re-widens to the BPF-shaped `dataplane.DataPlane` when the concrete
backend supports it (it does: the userspace `LegacyDataPlaneAdapter`
satisfies both, and the eBPF Manager satisfies both natively).

#1519 wants every `legacyDP()` consumer to either:

- migrate to a narrower typed accessor (`d.userspaceManager()`,
  `d.eventExporter()`, `d.forwardingStatus()`, telemetry-domain calls,
  etc.), or
- be paired with a dedicated provider probe behind a typed interface
  declared in the consumer package.

And then delete `legacyDP()` itself, OR explicitly document the
remaining dependency and file a follow-up.

## 2. Honest scope/value framing

The win when this lands is purely architectural: legacy BPF-shaped
surface removed from the daemon's public API, the eBPF retirement
(#1373) blocker set advances one step toward source removal. There is
no runtime / hot-path / memory / perf win. Worst-case behavioral
delta from a correctness regression here is a control-path bug in
session sync, GC, or HA event streaming.

If reviewers conclude the work cannot complete deletion of
`legacyDP()` in this PR and the partial shrink is too small to
justify the churn, **PLAN-KILL is an acceptable verdict**. This plan
section spells out exactly which call sites are blocked by which
sibling issues, so reviewers can rule on whether the unblocked subset
is worth a standalone PR.

## 3. Call-site audit (master @ fcd53beb)

`legacyDP()` is the type assertion `d.dp.(dataplane.DataPlane)`. It
returns nil when `d.dp` is nil or doesn't satisfy DataPlane. Every
call site stratified by what unblocking it requires:

### 3.1 Unblocked (can shrink in this PR)

These do not depend on any sibling sub-issue surface:

1. `daemon_gc.go:16` — `if lp := d.legacyDP(); lp != nil { ... }` in
   `newConntrackGC()`. The legacy `lp` is passed twice as
   `sessionCount` and `persistent`. Already covered by
   `conntrack.NewGC(provider RuntimeDomainProvider)` (added in
   #1507) — that constructor extracts `sessionCountPublisher` and
   `persistentNATProvider` via type assertions on the provider.
   **Migration:** replace `newConntrackGC` body with
   `conntrack.NewGC(d.dp, interval)`.

2. `daemon_scheduler.go:159` — the `legacyDP()` fallback for
   `UpdatePolicyScheduleState`. Both the eBPF Manager
   (`pkg/dataplane/maps.go:1497`) and the userspace adapter
   (`pkg/dataplane/userspace/legacy_dataplane.go:161`) implement
   `policyScheduleStateUpdater` (the local typed probe at
   `daemon_scheduler.go:14`). The `d.dp.(policyScheduleStateUpdater)`
   assertion at line 155 succeeds for every in-tree backend, so the
   legacyDP fallback path at lines 159-161 is **dead code**.
   **Migration:** delete lines 159-161.

3. `daemon_ha_sync.go:271,281` — `d.legacyDP().(userspaceEventStreamExporter)`
   and the `%T` log. `userspaceEventStreamExporter` is a local typed
   interface (`pkg/daemon/daemon_ha_userspace.go:49`). Type assertions
   on `d.dp` work just as well as on `legacyDP()` here — the
   adapter/manager satisfies the local interface directly, no need to
   round-trip through the wider `dataplane.DataPlane` shape.
   **Migration:** replace `d.legacyDP().(userspaceEventStreamExporter)`
   with `d.dp.(userspaceEventStreamExporter)`; replace `%T` formatter
   target similarly.

4. `daemon_ha_sync.go:700` — same shape as #3 for
   `userspaceEventStreamProvider`.
   **Migration:** `d.dp.(userspaceEventStreamProvider)`.

5. `daemon_forwarding_status.go:20,28,56,70` — accessor methods.
   - `IsLoaded()` (line 20-22): `dataplane.RuntimeDataPlane` does NOT
     expose `IsLoaded()`. **Need a narrow typed probe** declared in
     `pkg/daemon` — `type dataplaneReadyProbe interface { IsLoaded()
     bool }`. The userspace adapter and eBPF Manager both implement
     it via the legacy DataPlane interface.
   - `GetMapStats()` (line 28-32): available via
     `d.dp.Telemetry().MapStats()` — the `Telemetry` domain interface
     covers this. **Migration:** swap to telemetry call.
   - `Status()` (line 56-63): already typed against the userspace
     `interface { Status() (...) }` probe; the `legacyDP()` cast is
     pure round-trip. **Migration:** assert on `d.dp` directly.
   - `forwardingStatusDataplane()` (line 66-81): builds an accessor
     wrapper. Replace internal `dp := d.legacyDP()` with the new
     `dataplaneReadyProbe` typed probe.

6. `daemon_run.go:277-283` — `SeedNATPortCounters()` and
   `SeedSessionIDCounter(nodeID)` after dataplane start. These are
   legacy-only NAT counter / session-ID seeds. The userspace adapter
   delegates them to the bpfShim; the userspace fast-path doesn't
   need them but they are not harmful (best-effort seed of a map the
   userspace path doesn't read). **Migration:** introduce a local
   typed probe `type natSeeder interface { SeedNATPortCounters();
   SeedSessionIDCounter(int) }`; assert on `d.dp` directly.

7. `daemon_run.go:332-334` — `lp.StartFIBSync(ctx)`. The existing
   comment notes this is a no-op on every in-tree backend. Both eBPF
   and userspace adapter implement it as a stub. **Migration:**
   introduce a local typed probe
   `type fibSyncStarter interface { StartFIBSync(context.Context) }`;
   assert on `d.dp`. (Alternative: delete the call entirely since
   the comment says no-op everywhere. We keep it under the probe
   for now because DPDK had a real implementation and the user might
   plug another backend later.)

8. `daemon_run.go:1043-1045` — `logFinalStats(lp)` at shutdown.
   `logFinalStats(dp dataplane.DataPlane)` only uses
   `dp.IsLoaded()` + `dp.ReadGlobalCounter(uint32)`. Both are
   reachable via `dataplaneReadyProbe` + `telemetry.GlobalCounter()`.
   **Migration:** change signature to
   `logFinalStats(ready dataplaneReadyProbe, telemetry dataplane.Telemetry)`
   and call as `logFinalStats(d.dp, d.dp.Telemetry())`. The function
   moves to depend on the runtime telemetry domain rather than the
   legacy interface.

### 3.2 Blocked by sibling issues (cannot shrink in this PR)

These three call sites pass `legacyDP()` into a downstream API that
literally declares the parameter as `dataplane.DataPlane`. Until the
downstream package narrows its parameter type (the sibling issue's
job), the daemon must keep producing a `dataplane.DataPlane`.

9. `daemon_run.go:677` — `api.Config{DP: d.legacyDP()}`. The api
   package's `Server.dp` is already typed `apiRuntimeDataPlane`
   (`pkg/api/handlers.go:28`), a structural subset of DataPlane.
   `dataplane.RuntimeDataPlane` does NOT cover `IsLoaded`,
   `IterateSessions`, `IterateSessionsV6`, `ClearAllSessions`,
   `ReadFilterConfig`, `ClearAllCounters`. Until #1516 migrates
   those to runtime-domain surfaces, the daemon must pass a
   DataPlane-shaped value. **Blocked by #1516.**

10. `daemon_run.go:763` — `grpcapi.Config{DP: d.legacyDP()}`. The
    grpcapi field is literally `DP dataplane.DataPlane`
    (`pkg/grpcapi/server.go:40`). **Blocked by #1516.**

11. `daemon_run.go:849` — `cli.New(..., d.legacyDP(), ...)`. The
    cli constructor parameter is literally `dp dataplane.DataPlane`
    (`pkg/cli/cli.go:108`). **Blocked by #1517.**

12. `daemon_ha_sync.go:736` — `d.sessionSync.SetDataPlane(d.legacyDP())`.
    `cluster.SessionSync.SetDataPlane` takes `dataplane.DataPlane`
    (`pkg/cluster/sync.go:393`). **Blocked by #1518.**

### 3.3 Summary

- 12 unblocked call sites (across 5 files) can shrink in this PR.
- 4 blocked call sites (3 in daemon_run.go, 1 in daemon_ha_sync.go)
  remain. `legacyDP()` cannot be deleted yet.

## 4. Proposed PR shape

**Option A — partial shrink + retain legacyDP():** address all 12
unblocked sites, leave the 4 blocked sites pointing at `legacyDP()`,
keep the accessor in tree with a docstring naming the remaining
dependencies (#1516 → api+grpcapi, #1517 → cli, #1518 → session
sync). File a follow-up "delete legacyDP() once siblings land"
note (or just rely on the existing #1519 issue staying open until
those PRs ship). The issue's acceptance criteria explicitly allow
this shape.

**Option B — PLAN-KILL, wait for siblings:** none of the unblocked
shrinks unlock anything downstream. The deletion is the actual
architectural milestone; partial shrink is mechanical churn that
makes #1516/#1517/#1518 trivially harder to rebase. Wait for
siblings to land, then come back and finish #1519 as a single
delete-and-narrow PR.

This plan documents both options and asks the reviewers to choose.

### Risk / value comparison

| Aspect | Option A (partial shrink) | Option B (PLAN-KILL) |
|---|---|---|
| Delivered architectural value now | low (no api shrink, no delete) | none |
| Merge churn risk | medium (rebases under #1516/17/18 plan-review) | none |
| Behavioral regression risk | low-to-medium (HA sync, GC, scheduler touched) | none |
| Reviewer time cost | ~30 cells smoke + Copilot + 2 reviewer rounds | one round, then close |
| Net codebase shape after | `legacyDP()` still in tree | `legacyDP()` still in tree |

The honest comparison shows Option B saves work without losing any
architectural ground.

## 5. Recommendation

**This plan recommends Option B — PLAN-KILL with explicit rationale**,
and asks the reviewers to either ratify or argue for Option A.

Rationale:

- Of the 17 `legacyDP()` call sites, the 4 that matter
  architecturally (api, grpcapi, cli, sessionSync) are all blocked
  by sibling issues that have no PR yet.
- The 12 unblocked sites are mechanical refactors: rename a type
  assertion, swap to telemetry, delete one dead branch, introduce
  three local typed probes. None of these unlocks any downstream
  consumer; they are pure code-shape changes.
- The eBPF-retirement acceptance criterion (#1451) is "the legacy
  interface stops being exposed at the daemon boundary." Shrinking
  internal call sites without deleting the accessor doesn't
  advance that criterion. The accessor disappears in one shot once
  #1516/#1517/#1518 land.
- Re-opening this issue after the siblings ship lets us land a
  single tight "delete legacyDP() + narrow N call sites" PR with
  one round of plan-review, one Copilot pass, one smoke run — net
  cheaper than partial-shrink + capstone-delete.
- The repo's #946 Phase 2 and #1211 precedents show PLAN-KILL is
  the right verdict when the proposed work cannot deliver its
  stated architectural milestone in this PR.

If reviewers prefer Option A, this plan can be revised v2 to spell
out the concrete edits for the 12 unblocked sites, the three new
typed probes, and the smoke matrix.

## 6. Hidden invariants to preserve (if Option A goes ahead)

- **Type-assertion semantics:** `legacyDP()` returns nil when `d.dp`
  is nil OR when the concrete type does not satisfy DataPlane.
  Direct type assertion on `d.dp` must preserve the nil-check shape
  (`if probe, ok := d.dp.(X); ok && probe != nil { ... }`).
- **`logFinalStats` ordering:** runs after `d.cluster.Stop()` and
  `d.sessionSync.Stop()`, before `d.dp.Close()`/`d.dp.Teardown()`.
  Telemetry must still be valid at that point. Verify that the
  userspace `Telemetry()` provider doesn't go nil after Stop.
- **`SeedNATPortCounters` / `SeedSessionIDCounter`:** seed values
  derived from `nodeID` at config-active time. The new typed probe
  must succeed on both eBPF and userspace adapter — verify with a
  unit test against the concrete types.
- **`StartFIBSync`:** documented no-op on all in-tree backends. The
  typed probe must keep the call site behavior identical (call if
  probe satisfies, else skip).
- **`UpdatePolicyScheduleState` fallback:** before deleting, verify
  that BOTH userspace and eBPF backends implement
  `policyScheduleStateUpdater` (line 155). If either does not, the
  fallback at line 159 is live, not dead.
- **`session_sync.SetDataPlane`:** stays on legacyDP() — blocked by
  #1518. Verify the call site comment cites #1518 explicitly so a
  future cleanup pass doesn't miss it.

## 7. Test plan (only meaningful for Option A)

- `make test` — full Go suite, focus `./pkg/daemon/...`,
  `./pkg/conntrack/...`, `./pkg/cluster/...`, `./pkg/api/...`,
  `./pkg/grpcapi/...`.
- `make test-failover` — required by issue body if HA-adjacent
  accessor (forwarding status, HA sync, event exporter) changes
  shape. This plan WOULD change forwarding-status accessor shape
  (Option A), so this gate is mandatory.
- Loss userspace cluster smoke (per CLAUDE.md):
  - Pass A: CoS-off, v4 + v6 × push + reverse + 12-stream reverse.
  - Pass B: CoS-on, per-class (5201-5206) × v4 + v6 × push + reverse.
  - Total 30 measurements.
- Optional: a unit test that asserts the new typed probes are
  satisfied by both `*dataplane.Manager` (eBPF) and
  `*userspace.LegacyDataPlaneAdapter`.

## 8. Out of scope (explicit)

- Deleting `legacyDP()` itself — blocked until #1516/#1517/#1518 ship.
- Migrating `api.Config.DP`, `grpcapi.Config.DP`, `cli.New(dp)`,
  `cluster.SessionSync.SetDataPlane` parameter types — owned by the
  sibling issues.
- Deleting `LegacyDataPlaneAdapter` — owned by a later #1451 phase.
- Any change to `dataplane.RuntimeDataPlane` shape — owned by
  #1381 follow-up if needed (e.g. adding `IsLoaded()` to the runtime
  surface).

## 9. Open questions for adversarial review

1. **Architectural premise — is Option B (PLAN-KILL) correct?**
   The acceptance criteria explicitly allow Option A (partial shrink +
   documented remaining deps). Does the reviewer agree that without
   accessor deletion this PR has near-zero architectural value, or is
   there a downstream benefit I'm missing (e.g. unlocking #1520/#1521
   that I haven't seen)?

2. **`policyScheduleStateUpdater` fallback dead-code claim.** I claim
   the legacyDP fallback at `daemon_scheduler.go:159` is dead because
   both backends satisfy the local typed probe at line 14. Verify by
   walking `*dataplane.Manager.UpdatePolicyScheduleState` and
   `*LegacyDataPlaneAdapter.UpdatePolicyScheduleState` to confirm both
   are method-set-visible on the concrete types stored in `d.dp`.

3. **`StartFIBSync` no-op claim.** The comment says no-op on all
   in-tree backends. Is the comment accurate? If a future backend
   needs a real FIB sync, does the proposed typed probe degrade
   gracefully (call if probe satisfies, else skip) or does it
   silently lose work?

4. **`logFinalStats` telemetry-after-Stop hazard.** After
   `d.sessionSync.Stop()` and `d.cluster.Stop()` (but before
   `d.dp.Close()`), is `d.dp.Telemetry()` still safe to call?
   Specifically, does the userspace adapter's Telemetry path go
   through a sub-process socket that may already be torn down?

5. **Partial-shrink rebase risk under siblings.** If Option A ships
   first and then #1516/#1517/#1518 land later, do the sibling PRs
   have an easier or harder merge? The siblings change the downstream
   parameter types; this PR changes how the daemon constructs the
   argument. Same files (daemon_run.go, daemon_ha_sync.go) touched by
   both. Real conflict risk?

6. **Are #1520/#1521 (siblings) latent blockers I missed?** The issue
   body lists #1516/#1517/#1518 as `Depends on` but not #1520/#1521.
   Does any current `legacyDP()` call site secretly depend on the
   userspace boot path (#1520) or maps_sync (#1521)?

7. **AGY hallucination check.** The user warning specifies "AGY
   hallucinations: verify before propagating." If Antigravity claims a
   typed probe shape or fallback path that contradicts the code at
   the cited file:line, treat that as a hallucination and require
   verbatim quoting before propagating.
