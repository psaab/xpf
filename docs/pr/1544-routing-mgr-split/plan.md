# #1544 — Split routing manager by domain (pure file-motion refactor)

## Status

DRAFT v1 — pending adversarial plan review by Codex + Gemini.

## Issue framing

`pkg/routing/routing.go` is 2085 LOC and mixes nine unrelated control-plane
concerns behind a single `routing.Manager`:

- VRF lifecycle + reconcile + interface binding
- static-route reads + Junos-style route formatters
- GRE tunnel apply/clear and tunnel status
- tunnel keepalive goroutines
- XFRM/IPsec interface lifecycle
- next-table and rib-group ip-rule programming
- policy-based routing rules (PBR)
- bond lifecycle
- RETH lifecycle + interface monitors

Issue #1544 asks to split this manager into per-domain modules so that each
concern has its own file, its own tests, and a narrow netlink-facing
interface. The standing project rule (`docs/engineering-style.md` plus the
caller's instructions for this refactor) is **sibling .go files inside
`pkg/routing/`, not a `routing_vrf.go` prefix anti-pattern and not
sub-packages**. We keep the package name `routing` so the existing public
import surface (12 importers across `pkg/daemon`, `pkg/grpcapi`, `pkg/api`,
`pkg/cli`) is untouched.

## Honest scope/value framing

This is a **pure code-motion refactor**: zero behavior change, zero new
public API, zero new exported symbol. The wins are entirely structural:

- 9 concerns physically separated → reviewers can grep one domain in
  isolation when chasing a bug.
- Each domain test file (`vrf_test.go`, `tunnel_test.go`, …) holds its
  own fixtures, so adding a VRF test no longer scrolls past 600 LOC of
  PBR test setup.
- Mechanical churn → near-zero risk of a behavioral regression so long
  as we move declarations verbatim and let `gofmt` resolve imports.

If reviewers conclude this churn is too risky relative to the structural
benefit (e.g., merge-conflict cost against in-flight branches, audit-trail
loss in `git log -- pkg/routing/routing.go`), **PLAN-KILL is an acceptable
verdict**. Two concrete arguments that could push there:

1. Cluster code in `pkg/cluster` is currently being heavily refactored
   under #1373/#1525 and lands routing manager hooks on every merge; a
   2085-LOC churn may invalidate every open branch that touches RETH.
2. The split is presentation-only — no method moves off `*Manager`,
   no lock is split, no interface is narrowed — so the win is "files
   are smaller" rather than "manager is decomposed".

If the reviewers want a true decomposition (per-domain structs holding
the netlink handle by injection, façade `*Manager`), that is a much
larger Step 2; this PR is Step 1 (file-motion only).

## What's already shipped / partially batched

- #844 (VRF idempotent reconcile) already isolated VRF logic behind a
  `vrfOps` interface and tracks managed VRFs under `vrfsMu`. That makes
  VRF the cleanest domain to split first.
- #848 hardened `ifaceMu` to serialize the tunnels/xfrmis/bonds slices.
  The lock stays on `*Manager` after the split — splitting the lock is
  explicitly out of scope (Step 2 candidate, not this PR).
- The interface-monitor map (`monitorStatus`, `mu`) and `keepalives`
  map both live on `*Manager` today. They stay there.

The legacy eBPF dataplane retirement (#1373/#1476/#1525) does **not**
touch `pkg/routing/`; this refactor is independent of the dataplane
retirement chain.

## Concrete design — 8-file split

Current layout:

```
pkg/routing/
  README.md
  routing.go            2085 LOC (everything)
  routing_test.go       1225 LOC (everything)
```

Target layout (sibling files, no prefix, all in package `routing`):

```
pkg/routing/
  README.md
  manager.go            — Manager struct, New, Close, helper types
                          KeepaliveState, InterfaceMonitorStatus,
                          keepaliveRunner, errLinkNotFound,
                          isLinkNotFound. ~120 LOC.
  vrf.go                — CreateVRF, createVRFLocked, vrfOps interface,
                          IsManagedVRF, ReconcileVRFs, reconcileVRFs,
                          createLinkedVRF, vrfTable, BindInterfaceToVRF,
                          VRFSpec. ~330 LOC.
  routes.go             — GetRoutesForTable, routeToEntry, RouteEntry,
                          GetRoutes, protoTag, FormatRouteTerse,
                          GetVRFRoutes, GetTableRoutes, TableRoutes,
                          GetAllTableRoutes, appendSplitAF,
                          FormatRouteDestination, FormatRouteSummary,
                          formatSummaryProtos, FormatAllRoutes,
                          formatTableJunos, junosProtoName, rtProtoName.
                          ~595 LOC. (Route reads + formatters.)
  tunnel.go             — ApplyTunnels, closeTuntapFiles, ClearTunnels,
                          clearTunnelsLocked, TunnelStatus,
                          GetTunnelStatus. ~360 LOC.
  keepalive.go          — stopAllKeepalives, startKeepalive,
                          keepaliveLoop, probeICMP, GetKeepaliveState.
                          ~135 LOC.
  xfrm.go               — ApplyXfrmi, ClearXfrmi, clearXfrmiLocked.
                          ~95 LOC.
  pbr.go                — nextTableRulePriority, ribGroupRulePriority,
                          ApplyNextTableRules, clearNextTableRules,
                          ApplyRibGroupRules, clearRibGroupRules,
                          pbrRulePriority, PBRRule, ApplyPBRRules,
                          clearPBRRules, BuildPBRRules, buildPBRFromFilter,
                          dscpToTOS, resolveRibTable. ~395 LOC.
                          (All ip-rule programming — next-table, rib-group,
                          and PBR all program FIB rules so they live
                          together; splitting further would scatter the
                          shared priority constants and helpers.)
  bond.go               — ApplyBonds, ClearBonds, clearBondsLocked.
                          ~90 LOC.
  reth.go               — ApplyRethInterfaces, ClearRethInterfaces,
                          RethNames, ApplyInterfaceMonitors,
                          InterfaceMonitorStatuses. ~80 LOC.
```

Total: ~2085 LOC redistributed across 9 files. No declaration is dropped,
no declaration is renamed, no declaration changes signature.

### Why these groupings?

| Domain      | Cohesion rationale |
|-------------|--------------------|
| `manager.go`| Shared owner of state used by every other file. Holds the netlink handle, lock fields, type aliases. |
| `vrf.go`    | VRF reconcile logic was already factored behind `vrfOps`; lives with `vrfsMu`-guarded operations. |
| `routes.go` | Read-path + display formatters. No mutation, only ip-route reads + Junos-style formatting. Issue body lumps "static route reads" with VRF but the formatters are >400 LOC of presentation logic that doesn't belong with VRF reconciliation. |
| `tunnel.go` | GRE tunnel lifecycle. Uses `ifaceMu` + `tunnels[]`. Status read in same file. |
| `keepalive.go` | Goroutine lifecycle for tunnel keepalives. Mentioned separately in the issue ("Keep keepalive goroutine lifecycle separate from apply/clear logic"). |
| `xfrm.go`   | XFRM/IPsec interface lifecycle. Uses `ifaceMu` + `xfrmis[]`. |
| `pbr.go`    | All FIB rule programming (next-table + rib-group + PBR). The three share a priority scheme (100 / 33000 / 31000) and helper functions. Issue body lists them separately but splitting forces three files to share `dscpToTOS`/`resolveRibTable` and the FIB-rule clear/apply pattern, which is more friction than cohesion. |
| `bond.go`   | Bond lifecycle. Uses `ifaceMu` + `bonds[]`. |
| `reth.go`   | RETH interfaces + interface monitors. Uses `mu` + `monitorStatus`. |

### Issue body vs. target layout

The issue suggests 8 buckets: `vrf, tunnel, keepalive, xfrm, pbr, bond, reth,
status`. Our 9-file split differs in two places:

- `routes.go` instead of `status` — the file holds route reads + Junos
  formatters, not just "status". The name "status" is also misleading
  because tunnel status lives in `tunnel.go` and monitor status lives
  in `reth.go`.
- All three ip-rule mechanisms (next-table, rib-group, PBR) consolidate
  into `pbr.go` to keep the FIB-rule programming code coresident.

If reviewers want strict 1:1 alignment with the issue body's 8 buckets,
say so in plan review and we'll re-split. The current shape is what
reads best after walking the file.

### Test file split

Mirror the source split with sibling `_test.go` files in the same package
(`package routing`, not `routing_test`). Tests stay in-package because
some hit unexported helpers (`reconcileVRFs`, `resolveRibTable`,
`dscpToTOS`, `buildPBRFromFilter`, `countAlreadyDeleted`).

```
vrf_test.go        — TestReconcileVRFs* (all 9 variants), fakeVRFOps,
                     injectableFakeOps, transientLookupOps,
                     stringSlicesEqual, countAlreadyDeleted. ~880 LOC.
pbr_test.go        — TestResolveRibTable, TestRibGroupNeedsLeak,
                     TestDscpToTOS, TestBuildPBRRules,
                     TestMultiVRFRibGroupLeaking,
                     TestIPv6OnlyRibGroupLeaking. ~310 LOC.
keepalive_test.go  — TestProbeICMP, TestKeepaliveState,
                     TestKeepaliveDefaults. ~55 LOC.
reth_test.go       — TestInterfaceMonitorStatuses,
                     TestRethMemberCollection. ~80 LOC.
```

Per-domain test coverage preservation: `go test ./pkg/routing/...` runs
exactly the same set of test functions in exactly the same order
(Go runs `Test*` alphabetically across files, so behavior is identical).

## Public API preservation

Every exported symbol on `*Manager` stays exported with the identical
signature. No method moves off the receiver. The list (16 methods +
12 free functions + 8 types):

Methods on `*Manager`:
`Close, CreateVRF, IsManagedVRF, ReconcileVRFs, BindInterfaceToVRF,
GetRoutesForTable, ApplyTunnels, GetKeepaliveState, ClearTunnels,
ApplyXfrmi, ClearXfrmi, GetTunnelStatus, GetRoutes, GetVRFRoutes,
GetTableRoutes, GetAllTableRoutes, ApplyNextTableRules,
ApplyRibGroupRules, ApplyPBRRules, ApplyBonds, ClearBonds,
ApplyRethInterfaces, ClearRethInterfaces, RethNames,
ApplyInterfaceMonitors, InterfaceMonitorStatuses`.

Free functions: `New, FormatRouteTerse, FormatRouteDestination,
FormatRouteSummary, FormatAllRoutes, BuildPBRRules`.

Types: `Manager, KeepaliveState, InterfaceMonitorStatus, VRFSpec,
TunnelStatus, RouteEntry, TableRoutes, PBRRule`.

Importer call sites (12 .go files in 4 packages) need **zero changes**.

## Hidden invariants the change must preserve

1. **Locking discipline.** `ifaceMu` serializes `tunnels[]`, `xfrmis[]`,
   `bonds[]`. `vrfsMu` serializes `vrfs[]`. `mu` serializes
   `monitorStatus`. The locks **stay on `*Manager`** so any caller that
   acquires one before calling into multiple files still works. We do
   not introduce per-file mutexes.

2. **Apply/Clear ordering on shutdown.** `Close()` (in `manager.go`)
   calls `stopAllKeepalives()` (now in `keepalive.go`) before draining
   `nlHandle`. The cross-file call must compile and the call order in
   `Close()` is unchanged.

3. **`keepaliveRunner.done` channel discipline.** Closed by
   `keepaliveLoop()` just before return; `Close`/`stopAllKeepalives`
   wait on it to avoid use-after-close of `m.nlHandle`. The split keeps
   `keepaliveLoop` and `stopAllKeepalives` in the same file
   (`keepalive.go`), so the contract is intact.

4. **`#848` invariant: GetTunnelStatus snapshot under lock.** The
   method snapshots `tunnels[]` under `ifaceMu`, then iterates lock-free.
   Stays in `tunnel.go`; `ifaceMu` is still a `Manager` field.

5. **VRF ownership-set persistence.** `vrfs[]` is only mutated under
   `vrfsMu`. `reconcileVRFs()` returns the new tracked list and the
   exported wrapper assigns it under the lock. Stays in `vrf.go`.

6. **Junos-style route formatter ordering.** `FormatRouteSummary`
   depends on `protoTag` + `junosProtoName` + `formatSummaryProtos`.
   All four stay in `routes.go`.

7. **Constant placement.** `nextTableRulePriority = 100`,
   `ribGroupRulePriority = 33000`, `pbrRulePriority = 31000` all live
   in `pbr.go` next to the functions that reference them. They are
   package-level constants today; they remain package-level so no
   importer sees a difference.

8. **No test imports `routing` as `_test` package** — both test files
   stay in `package routing` so they can keep accessing unexported
   helpers.

## Risk assessment

| Risk class | Level | Why |
|-----------|-------|-----|
| Behavioral regression | **LOW** | Pure declaration move. `git diff -M` should report >95% rename score on every file. No expression changes. No control-flow changes. |
| Lifetime / borrow-checker shape (Go: type/method coherence) | **LOW** | All methods stay on `*Manager`, same package. Go method sets across files in a package are identical to a single file. |
| Performance regression | **LOW** | Control plane only. Routing manager operations happen at commit, deploy, and HA failover — not in the packet path. Splitting files has zero perf impact. |
| Architectural mismatch (#961 / #946 Phase 2 dead-end) | **MED** | Issue body floats sub-packages and per-domain managers (`pkg/routing/vrf/`, etc.); this PR consciously does file-motion only. If the project intent is a true decomposition with narrowed interfaces, this PR is Step 1 of N and we should say so. Otherwise a true decomp will be a separate Step 2 PR. |
| HA-sensitive blast radius | **MED** | RETH + interface-monitor code lives in `reth.go`. Cluster code (`pkg/cluster`) calls `ApplyRethInterfaces`, `ClearRethInterfaces`, `RethNames`, `ApplyInterfaceMonitors`, `InterfaceMonitorStatuses`. Move-only churn should be safe but **smoke matrix MUST include `make test-failover`-style HA cycle** because RETH virtual MAC + VIP reconciliation depend on this path. |
| Merge conflict against open branches | **MED** | 2085-LOC file split will collide with any open PR touching `routing.go`. We accept the conflict cost; the alternative is "never refactor". |

## HA-sensitivity determination

**This refactor IS HA-sensitive.** `reth.go` will hold
`ApplyRethInterfaces`, `ClearRethInterfaces`, `RethNames`, and
`ApplyInterfaceMonitors` — all of which run on every commit and every HA
state transition. Plan calls for **smoke + `make test-failover`** per
[[feedback_smoke_serialized_single_agent]] §4. PR comment will use:

```
<!-- AWAITING-SMOKE -->
scope: smoke-plus-test-failover
```

If the smoke runner only has bandwidth for one of the two: prefer
`test-failover` over the 30-cell smoke matrix, because the RETH path
is what this refactor touches; CoS classifier path is far away from
this PR.

## Test plan

Gates in order:

1. **`go build ./...`** clean — no missing imports, no duplicate symbols.
2. **`gofmt -d pkg/routing/`** zero diff after the split.
3. **`go vet ./pkg/routing/...`** clean.
4. **`go test ./pkg/routing/...`** — same set of tests as master, all
   pass. Specifically the 19 `Test*` functions enumerated above.
5. **`go test ./...`** — full Go suite (30 packages, 640+ tests).
6. **`make build`** clean.
7. **`make cluster-deploy`** to `loss:xpf-userspace-fw0/fw1`.
8. **Pass A smoke** (CoS disabled, v4 + v6 × push + reverse + `-P 12 -R`
   reproducer). Per-class CoS smoke is OPTIONAL for this refactor since
   none of the code paths touch the classifier/policer; if smoke
   bandwidth is constrained, skip Pass B.
9. **`make test-failover`** — single iteration, primary reboot during
   iperf3, zero-drop failover. **Required gate** because this PR
   restructures RETH and interface-monitor code.

If `test-failover` fails on this PR but not on master, this is a real
regression and the PR is blocked — no "sandbox flake" handwave.

## Out of scope (explicitly)

- **Sub-package split** (`pkg/routing/vrf/` etc.). Standing rule rejects
  the prefix anti-pattern AND the sub-package shape; sibling files in
  `pkg/routing/` is the chosen layout.
- **Method moves off `*Manager`.** No method gains a new receiver type.
  No domain struct is introduced. That's a Step 2.
- **Lock decomposition.** `ifaceMu` keeps protecting tunnels + xfrmis +
  bonds even though those will live in three different files. Splitting
  the lock is a Step 3 candidate, not this PR.
- **Narrowing the `vrfOps` pattern to other domains.** VRF has it for
  test injection; tunnel/xfrm/bond/RETH don't. Out of scope to add.
- **`routing.go` deletion.** After the split, `routing.go` will be empty
  except for the package clause — actually no, the file will be
  **removed entirely** and `manager.go` becomes the new "header" file.
  The package-doc comment moves to `doc.go` if needed, but most likely
  it stays on the `Manager` declaration in `manager.go`.

## Open questions for adversarial review

Each question is invitable to PLAN-KILL or PLAN-NEEDS-MAJOR.

1. **Is "file-motion only" the right Step 1?** The issue body explicitly
   says "domain modules with narrow netlink-facing interfaces" and "PBR
   rule operations testable without tunnel state". Pure file-motion does
   NOT achieve the testability win — `pkg/routing/pbr_test.go` can already
   test PBR without tunnel state today, because `BuildPBRRules` is a free
   function and the apply path mocks netlink. Should this PR instead
   land a domain-struct decomposition (`type vrfManager`, `type pbrManager`,
   …) with `*Manager` as façade? If yes, **PLAN-NEEDS-MAJOR** and we
   redraft.

2. **Should `routes.go` actually be `status.go` and stay close to the
   issue body's vocabulary?** The issue lists `status` as the 8th bucket
   but the contents are route reads + formatters, not status. Naming
   matters for grep discoverability.

3. **Should the three FIB-rule mechanisms (next-table, rib-group, PBR)
   really share `pbr.go` or split into `nexttable.go`, `ribgroup.go`,
   `pbr.go`?** Splitting forces `dscpToTOS`/`resolveRibTable` to either
   duplicate or live in a shared helper file. The issue body lists PBR
   as one bucket and "next-table/rib-group" is not separately enumerated,
   so consolidating into `pbr.go` is defensible — but a reviewer who
   has chased a rib-group bug recently may want them split.

4. **Is `make test-failover` the right HA gate, or should we run the
   full HA crash matrix?** Per-PR `test-ha-crash` adds ~5 minutes and
   exercises more transitions. Standing rule says any RETH/VRRP/session
   sync change MUST pass `test-failover`; the crash matrix is optional.
   Reviewers may want both for a 2085-LOC churn.

5. **Merge-conflict cost vs. structural win.** Are there open PRs
   touching `pkg/routing/routing.go` that this would invalidate? If
   yes and they're close to merge, queue this refactor behind them.
   If no, the conflict cost is zero.

6. **Should `keepaliveLoop` and `startKeepalive` move to a sub-struct
   even in this PR?** Right now both methods on `*Manager` hold
   `m.keepalives` directly. A trivial helper `type keepaliveSet struct
   { runners map[string]*keepaliveRunner }` would let `keepalive.go` own
   its state. That's a small step toward true decomposition. Worth
   adding as a deviation from "file-motion only"?

7. **Does removing the line-history hint in `git log -- routing.go`
   hurt incident response?** `git log --follow` works across renames
   so blame survives, but the single-file `git log` view dies. For
   a 2085-LOC file with 6+ months of bug fixes, that may matter.

8. **HA test environment availability.** The loss userspace cluster
   is shared smoke-runner real estate. If `test-failover` is required
   and the smoke runner can't serve it, this PR will block. Acceptable?

---

This plan is intentionally hostile to itself: PLAN-KILL is a real outcome
if reviewers conclude the structural win doesn't justify the churn or if
the project actually wants a true decomposition Step 1.
