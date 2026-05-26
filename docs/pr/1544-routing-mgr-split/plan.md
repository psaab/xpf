# #1544 — Split routing manager by domain (pure file-motion refactor)

## Status

**KILLED v1 — 2026-05-26 20:24 UTC.** Both Codex (task-mpn2w0bb-rmexxr) and
Gemini Pro 3 (task-mpn2wo93-pzup4g) returned **PLAN-KILL independently** in
round 1. The plan did not survive adversarial review. No code was moved.
No PR was opened.

See "Round 1 plan-kill verdicts (preserved verbatim)" at the bottom of this
file for both findings. The kill is grounded in three independent fatal
findings I locally verified:

1. **File-motion-only side-steps the issue's actual ask.** Issue #1544
   explicitly calls for "domain modules with narrow netlink-facing
   interfaces" and per-domain testability. The proposed PR keeps every
   method on `*Manager`, splits no lock, narrows no interface — it is a
   cosmetic change that delivers structural-decomposition appearance
   without structural-decomposition substance. (Both Codex finding 1 and
   Gemini finding 1; Codex evidence: `routing.go:42` single `*netlink.Handle`
   field, only VRF has a `vrfOps` fakeable surface at `routing.go:141`;
   the rib-group test explicitly says it can't test ip-rule creation
   without netlink at `routing_test.go:549`.)

2. **HA-sensitivity claim was hallucinated.** Local re-verification
   confirms Gemini finding 5: `ApplyRethInterfaces` and `RethNames` are
   no-op stubs (`routing.go:1996`, `routing.go:2028`); `ClearRethInterfaces`
   is called only on shutdown; only `ApplyInterfaceMonitors` (4 callers in
   `pkg/daemon/daemon_apply.go:948`, `pkg/grpcapi/server_cluster.go:65`,
   `pkg/cli/cli_helpers.go:110`) and `InterfaceMonitorStatuses` are live,
   and the live paths feed cluster weight on apply, not VRRP/RETH MAC
   reconciliation. The actual RETH MAC + VIP reconciliation lives in
   `pkg/cluster/reth.go` (`RethMAC` at `pkg/cluster/reth.go:106`), which
   this refactor does NOT touch. The plan's "must pass `test-failover`"
   gate is therefore overstated; that gate exists for cluster/VRRP/session
   sync changes, not for inert routing manager file-motion. The plan
   should have grepped before claiming HA-sensitivity.

3. **`pbr.go` boundary is wrong.** Both reviewers independently flagged
   that next-table, rib-group, and PBR are listed as three separate
   concerns in the issue (and in this plan's own framing at section
   "Issue framing") and that the shared-helpers argument is weak —
   `resolveRibTable` is rib-group-specific (called at `routing.go:1591`,
   defined at `routing.go:1871`); `dscpToTOS` is PBR-specific (called at
   `routing.go:1807`). The right shape is `nexttable.go` + `ribgroup.go` +
   `pbr.go`, OR a neutral `rules.go` if consolidation is intentional —
   not "all dumped into pbr.go".

Additional findings the reviewers caught:

- Plan said "8-file split" in one heading and "9 files" in another
  (Codex finding 3; plan.md:75 vs plan.md:132).
- Plan claimed "16 methods + 12 free functions" — the actual count is
  26 methods + 6 free functions (Codex finding 8; plan.md:192).
- `pkg/routing/README.md:14` still says every entry point lives in
  `routing.go`; README update was missing from scope (Codex finding 9).
- `KeepaliveState` + `keepaliveRunner` types were placed in `manager.go`
  but belong in `keepalive.go` next to the methods that use them
  (Codex finding 4).

### Why this kill is appropriate

The plan invited PLAN-KILL on three concrete arguments at draft time
(see "Honest scope/value framing" → bullets 1-2 and Open Question 1).
Both reviewers picked up that invitation and converged on the same
verdict. Pushing file-motion-only would have shipped a 2085-LOC churn
that satisfies the layout rule but not the issue, and would have
landed a #946-Phase-2 / #961-style architectural mismatch.

### What a future plan must change to escape KILL

A successor plan for #1544 must:

1. **Introduce per-domain ops interfaces (at minimum) or unexported
   domain structs (preferred), with `*Manager` as façade.** This is
   the "narrow netlink-facing interface" the issue actually asks for.
   The shape that would have passed: each domain file owns an
   unexported `vrfManager`/`tunnelManager`/`pbrManager`/etc. struct
   holding a reference to the shared `*netlink.Handle` and its own
   sub-state; `*Manager` becomes a coordinator that owns the netlink
   handle plus one of each domain struct, with the existing public
   methods delegating to the domain. This is achievable as code-motion
   plus mechanical method-receiver rewrite, but it IS more than
   file-motion.

2. **Drop the `test-failover` claim** unless the plan actually touches
   live HA code paths. Re-grep `pkg/cluster/`, `pkg/daemon/`, and
   `pkg/vrrp/` for routing.Manager callsites and only assert
   HA-sensitivity if a non-stub method is on a hot path.

3. **Split `pbr.go` into `nexttable.go` + `ribgroup.go` + `pbr.go`**,
   or rename to a neutral `rules.go`. Do NOT collapse three concerns
   the issue lists separately into one file just because they share
   one helper.

4. **Fix the API accounting** (26 methods + 6 free functions, not
   16+12). Mechanical, but a plan with wrong arithmetic doesn't
   inspire confidence in the file-by-file move list.

5. **Update `pkg/routing/README.md`** as part of the same PR; the
   file-by-file layout description there will be stale immediately.

6. **Consider a smaller Step 0** — Gemini suggested extracting just
   `routes.go` (~595 LOC of Junos formatters and route reads) as a
   safer first commit. This isolates the highest-cohesion bundle with
   minimum merge-conflict risk and leaves the rest of the manager for
   a true domain-struct Step 1.

### What happens now

- This plan stays on `refactor/1544-routing-mgr-split` at commit
  `d01fc75963ae219453e77e07a6f94218e4a385db` plus this killed-status
  update so the audit trail is preserved.
- No PR is opened. The branch can be deleted after the issue comment
  lands, or kept for future plan re-drafts.
- A comment on issue #1544 will record the kill, both verdicts, and
  the "what a future plan must change" list above so the next attempt
  doesn't repeat the same mistakes.

---

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

## Round 1 plan-kill verdicts (preserved verbatim)

### Codex (task-mpn2w0bb-rmexxr) — PLAN-KILL

**Verdict: PLAN-KILL**

The sibling-file layout rule is satisfied, but the plan fails the issue target. A pure file-motion commit can be the first commit in a real refactor PR; it is not enough as the whole #1544 PR.

**Findings**

1. **High: file-motion-only side-steps #1544.** The plan says the issue asks for "narrow netlink-facing interface" per concern in plan.md:22, then scopes the PR to "pure code-motion" in plan.md:33, and explicitly excludes method moves and narrowed ops in plan.md:311. Current code has one `*netlink.Handle` on `Manager` in routing.go:42; only VRF has a narrow fakeable surface, `vrfOps`, in routing.go:141. The tests prove the gap: rib-group testing says it "can't test actual ip rule creation without netlink" in routing_test.go:549. For #1544, this PR should introduce unexported domain structs or at least per-domain ops interfaces with `*Manager` as façade.

2. **High: `pbr.go` is the wrong boundary.** The plan itself lists next-table/rib-group and PBR as separate concerns in plan.md:17, but collapses all ip-rule mechanisms into `pbr.go` in plan.md:115. The "shared helpers" argument is weak: `resolveRibTable` is rib-group-specific, used from routing.go:1591 and defined at routing.go:1871; `dscpToTOS` is PBR-specific, used at routing.go:1807. Split this into `nexttable.go`, `ribgroup.go`, and `pbr.go`, or use a neutral `rules.go` if consolidation is intentional.

3. **Medium: the 8-vs-9 story is internally inconsistent.** The section title says "8-file split" in plan.md:75, the target lists `manager.go` plus eight domain files in plan.md:91, then says "9 files" in plan.md:132. The plan quotes the issue's 8 buckets at plan.md:151. `routes.go` is a defensible name, but route reads and Junos formatting are different responsibilities; consider `routes.go` plus `format.go` if this is meant to be a real domain split.

4. **Medium: `keepalive.go` can be separate, but the state placement is wrong.** The split is defensible because keepalive lifecycle is distinct and issue-aligned, but plan puts `KeepaliveState` and `keepaliveRunner` in `manager.go` at plan.md:91. Current tunnel code calls `startKeepalive` from routing.go:672, clears via `stopAllKeepalives` at routing.go:843, and status reads through `GetKeepaliveState` at routing.go:1012. Keep the keepalive types in `keepalive.go` and document the `ifaceMu` invariant there.

5. **Locking: no order violation found for move-only split.** I found no call site that holds more than one of `ifaceMu`, `vrfsMu`, and `mu`. VRF paths take only `vrfsMu` at routing.go:190; tunnel/xfrm/bond/keepalive paths take only `ifaceMu`, e.g. routing.go:494; monitor paths take only `mu` at routing.go:2034. Preserve the important pattern where `GetTunnelStatus` snapshots and unlocks before later keepalive status reads, starting at routing.go:970.

6. **Cross-file references will compile if package stays `routing`.** Later-defined calls are: Close→stopAllKeepalives; CreateVRF→createVRFLocked; createVRFLocked→createLinkedVRF; ReconcileVRFs→reconcileVRFs; reconcileVRFs→createLinkedVRF/vrfTable; GetRoutesForTable→routeToEntry; routeToEntry→rtProtoName; ApplyTunnels→closeTuntapFiles/startKeepalive/clearTunnelsLocked; startKeepalive→keepaliveLoop; keepaliveLoop→probeICMP; ClearTunnels→clearTunnelsLocked; ApplyXfrmi/ClearXfrmi→clearXfrmiLocked; GetAllTableRoutes→appendSplitAF; formatters to formatTableJunos, formatSummaryProtos, junosProtoName; rule appliers to clear helpers; BuildPBRRules→buildPBRFromFilter; buildPBRFromFilter→dscpToTOS; bond appliers to clearBondsLocked. Same-package unexported cross-file calls are fine, and tests already use `package routing` in routing_test.go:1.

7. **HA sensitivity is real, but the plan overstates the callers and understates validation.** Grep found current callers for `ClearRethInterfaces`, `ApplyInterfaceMonitors`, and `InterfaceMonitorStatuses`, not `ApplyRethInterfaces` or `RethNames`. The daemon clears RETH at daemon_apply.go:292, applies monitors at daemon_apply.go:945, and feeds statuses into cluster weights at daemon_apply.go:955. Cluster weight changes re-run election at election.go:367. So `make test-failover` is required, and by repo style HA/VRRP changes should also require `make test-ha-crash` per engineering-style.md:102, not optional.

8. **Importer surface is preserved under move-only, but the plan's API accounting is wrong.** The routing importers are still the 12 files in `pkg/daemon`, `pkg/grpcapi`, `pkg/api`, and `pkg/cli`; no call site changes are needed if signatures stay fixed. But plan.md:192 says "16 methods + 12 free functions"; the listed method set is 26 methods, and the free functions are 6. Fix that before implementation.

9. **Docs would drift.** `pkg/routing/README.md` still says every entry point lives in `routing.go`, e.g. README.md:14, while the plan deletes `routing.go` in plan.md:318. README update must be in-scope.

I could not verify open GitHub PRs: `gh pr list --state open --search "routing"` failed with `socket: operation not permitted`. A local branch scan did not find local `refs/heads` diffs touching `pkg/routing/routing.go` or `pkg/routing/routing_test.go`, but that is not a substitute for the live PR check.

### Gemini Pro 3 (task-mpn2wo93-pzup4g) — PLAN-KILL

**Adversarial PLAN Review**

1. **File-motion only vs. Issue #1544:**
The plan explicitly sidesteps the core architectural ask. It quotes #1544 as asking for "domain modules with narrow netlink-facing interfaces". Yet, it proposes a "pure code-motion refactor: zero behavior change... no interface is narrowed". The plan itself admits in its Open Question 1: "Pure file-motion does NOT achieve the testability win". Moving 2085 LOC across files while keeping every method on `*Manager` is a cosmetic change that entirely dodges the structural decomposition requested by the issue.

2. **Is the 9-file boundary correct?**
   - **a. routes.go (~595 LOC):** Grouping route reads and Junos formatters here is justifiable. As the plan notes, presentation logic does not belong with VRF reconciliation.
   - **b. pbr.go:** Consolidating next-table, rib-group, and PBR is architecturally sound. They share FIB-rule programming logic, priority constants (e.g., `pkg/routing/routing.go:1688` `ApplyPBRRules` and earlier `ApplyRibGroupRules`), and helpers like `dscpToTOS`.
   - **c. keepalive.go vs tunnel.go:** The separation is clean. `keepaliveLoop` touches `m.nlHandle.LinkByName` (e.g., `pkg/routing/routing.go:765`), but because everything remains a method on `*Manager` in `package routing`, cross-file method calls like `m.stopAllKeepalives()` (`pkg/routing/routing.go:690`) work without forcing any public API helper exports.
   - **d. 9 files vs 8 buckets:** The deviation (using `routes.go` instead of `status.go` and consolidating the FIB rules) is well-justified by file cohesion.

3. **Locking:**
Go method-set semantics allow methods defined in sibling `.go` files to safely acquire unexported locks like `m.ifaceMu` and `m.vrfsMu`. However, because all locks and methods remain on the single `*Manager` struct, the domains are not actually isolated from each other.

4. **Test file split:**
Using in-package tests (`package routing` rather than `routing_test`) successfully preserves access to unexported helpers. Tests will still be able to hit `reconcileVRFs` (e.g., `pkg/routing/routing.go:190`) and `dscpToTOS` without introducing hidden public API coupling.

5. **HA-sensitivity (FATAL FLAW):**
The plan claims this PR needs `make test-failover` because `reth.go` will hold `ApplyRethInterfaces`, `ClearRethInterfaces`, `RethNames`, and `ApplyInterfaceMonitors`, claiming that `pkg/cluster` calls these on "every commit and every HA state transition" and that "RETH virtual MAC + VIP reconciliation depend on this path." **This is hallucinated.**
   - `pkg/routing/routing.go:1994-1997` explicitly states: `// ApplyRethInterfaces is a no-op. RETH bonds are no longer created... func (m *Manager) ApplyRethInterfaces(...) error { return nil }`.
   - `pkg/routing/routing.go:2028-2029` states: `func (m *Manager) RethNames() []string { return nil }`.
   - A global `grep` reveals **zero** call sites for `ApplyRethInterfaces` or `ApplyInterfaceMonitors` across `pkg/cluster` or `pkg/daemon`. The real HA/MAC reconciliation logic lives entirely inside `RethController` in `pkg/cluster/reth.go` (e.g., `pkg/cluster/reth.go:106` `func RethMAC(...)`). The blast-radius assessment is entirely false because it relies on dead/stubbed code paths.

6. **Architectural mismatch (#946-Phase-2 / #961):**
As the plan openly acknowledges, pure file-motion provides no architectural isolation. `pbr_test.go` already tests PBR independently because it uses free functions and mocks netlink. The testability win is purely cosmetic.

7. **Merge-conflict cost vs. structural win:**
A 2085-LOC file-motion churn introduces massive merge-conflict risk against open branches but delivers zero actual encapsulation. Reviewers grepping for `ApplyPBRRules` will still find it operating against the exact same bloated `*Manager` struct. The structural win is nil.

8. **Safer increments:**
A much safer Step 0 would be extracting *only* `routes.go` (~595 LOC of Junos formatting and static route reads). This strips the heaviest presentation logic out of the manager with isolated conflict risk, preserving the rest of the file for a genuine domain-struct decomposition (Step 1).

**Verdict: PLAN-KILL**
The plan fails because it actively circumvents the architectural intent of #1544, introduces massive unrewarded churn, and hallucinates an HA-sensitivity blast radius based on dead code. A true domain-struct decomposition is required.

### Note on disagreement

The two reviewers disagree on whether `pbr.go` consolidation is right
(Codex says split it three ways; Gemini says it's "architecturally
sound"). Either way the consolidation is not the load-bearing kill —
Codex's #1 finding and Gemini's #1+#5 findings are the load-bearing
kills, and both converge on the same fundamental problem: the plan
solves a different problem than #1544 asked for.

### Note on HA-sensitivity arithmetic

Codex finding 7 says `make test-failover` IS required because monitor
status feeds election; Gemini finding 5 says the HA-sensitivity claim
is hallucinated because the RETH stubs are dead. Both can be true: the
monitor-status path IS a live HA signal but the RETH bond path is
dead. A successor plan should grep both paths separately and only assert
the gates the live code paths require.
