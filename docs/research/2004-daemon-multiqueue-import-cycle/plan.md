# Research plan: consolidate `pkg/daemon` device_map + rss_indirection into `pkg/daemon/multiqueue/`

- **Status**: DRAFT v1 (draft-fanout; not yet reviewed by Codex / AGY / Copilot)
- **Issue**: #2004 — "Refactor (backlog): consolidate pkg/daemon device_map +
  rss_indirection into pkg/daemon/multiqueue/"
- **Disposition (author, pre-review)**: **LIKELY-DEFER-MULTI-INCREMENT** — the
  literal "move both files into a sub-package" framing is blocked by a
  bidirectional import edge that is wider than the issue states; the realistic,
  reviewable first increment is much smaller than the proposed three-file
  package. See §10.
- **Branch**: `research/2004-daemon-multiqueue-import-cycle`
- **Base**: `origin/master` @ `c4e7c77cd` (worktree fetch)
- **Scope**: behavior-preserving code motion only. No runtime behavior change.

---

## 1. Issue framing (what was asked)

agy-review-013 Part II.3 (a modularity-target backlog item, peer to
#1986-#1990) asks to consolidate the two flat multiqueue/RSS device-mapping
files in `pkg/daemon/` into a `pkg/daemon/multiqueue/` sub-package:

- `pkg/daemon/device_map.go` (666 LOC) — #1956 bare-metal device-map resolver
  glue (rename / teardown / commit pre-flight).
- `pkg/daemon/rss_indirection.go` (493 LOC) — #785/#805 mlx5 RSS indirection
  table reshaping.

Suggested layout in the issue:

```
pkg/daemon/multiqueue/
  device.go    # PCI slot-to-core device-map bindings
  rss.go       # RSS indirection + symmetric-hash key settings
  manager.go   # reconcile multi-queue bounds on NIC link events
```

The issue itself flags the constraint: "Behavior-preserving code motion only.
`device_map.go` is the #1956 bare-metal device-map; preserve the leave-alone
default + no-auto-fxp0 lifeline semantics."

The task prompt sharpens the real problem: **moving these files into a new Go
package forces a bidirectional import edge.** A new directory in Go is a new
package with a hard import boundary; the two files both *consume* daemon-package
helpers and *are consumed by* daemon-package call sites. The design question is
how to break that edge.

---

## 2. Honest scope / value

This is pure internal tidiness. There is **zero runtime, perf, HA, or
operator-visible value** — no hot-path change, no allocation change, no behavior
change. The only benefit is module legibility: a reader looking for
"how does xpf name NICs / shape RSS" gets a named package instead of two flat
files in a 70-file directory.

`pkg/daemon` is ~70 `.go` files and the two target files are 1,159 LOC of a very
large package. Extracting them does not meaningfully shrink `pkg/daemon` (it is
1.6% of the non-test source), and — critically — it does NOT cleanly extract,
because the symbols are woven into the daemon's startup naming path, apply path,
and the shared `host_tunables` / `coalescence` ethtool substrate (see §5).

If reviewers conclude the perf gain / scope is too small to justify the churn,
**PLAN-KILL is acceptable.** This plan deliberately surfaces the import-edge
cost so that decision can be made with eyes open rather than discovered mid-PR.

---

## 3. What is already shipped (do not re-litigate)

- **#1956 bare-metal device-map** (`device_map.go` + `pkg/devicemap/`): opt-in
  `set chassis device-map`, stable-identity rename, `unmapped-interface-policy`
  leave-alone default, no-auto-fxp0 / console-lifeline (§9.6), commit pre-flight
  that rejects a management-stranding map (and validates the rollback target for
  `commit confirmed`), managed→unmapped teardown before `networkd.Apply`. The
  **pure resolver core already lives in the leaf package `pkg/devicemap`**;
  `device_map.go` is only the daemon-side rename/teardown/pre-flight glue.
- **#785/#805 RSS indirection** (`rss_indirection.go`): mlx5 weight-vector
  reshaping to queues `0..workers-1`, the `workers>=queues` stale-table restore
  (#805), idempotent ethtool probe, kill-switch restore.
- **#801 coalescence** (`coalescence.go`): reuses `rss_indirection.go`'s
  `rssExecutor` interface, `realRSSExecutor`, `mlx5Driver`, `isExecNotFound`.
- **#1715 precedent — `pkg/daemon/system/`**: a *leaf* sub-package of pure
  renderers (DNS drop-in / resolv.conf) with NO daemon-internal imports; the
  daemon wraps them. This is the established Go pattern for breaking the edge.
- **#2005 precedent — session decompose (PR #2028)**: split a 1,604-LOC Rust
  file into *same-crate submodules*. Note: this did NOT cross a package
  boundary; Rust submodules share the crate, so the Go import-cycle problem did
  not apply. It is a precedent for "behavior-preserving byte-identical motion +
  quad review," NOT for crossing a package line.

---

## 4. Blast radius (measured on this worktree)

### 4.1 Symbols defined in the two target files

`device_map.go` defines 18 symbols (functions, vars, the `presentNIC` alias).
`rss_indirection.go` defines the `rssExecutor` interface, `realRSSExecutor`,
9 functions, and the `mlx5Driver` const.

### 4.2 Outbound deps (target files → rest of `pkg/daemon`) — the "in" edge

`device_map.go` calls these daemon-package symbols defined elsewhere:

| Symbol | Defined in | Subsystem |
|---|---|---|
| `recoverOriginalName`, `renameInterface`, `writeLinkFile`, `networkctlReload`, `writeBootstrapFxp0Network`, `linkDir`, `linkPrefix`, `execCommand` | `linksetup.go` | NIC naming / .link files |
| `deriveKernelName` | `daemon_reth.go` | RETH PCI→kernel-name |
| `resolveLifelineCurrentName`, `protectedInterfaces` | `bootstrap.go` | #1922 mgmt lifeline |
| `runCommandTimeout` | `exec_timeout.go` | command exec |

`rss_indirection.go` is self-contained except `runCommandTimeout`
(`exec_timeout.go`).

### 4.3 Inbound deps (rest of `pkg/daemon` → target symbols) — the "out" edge

Device-map symbols are called from:

| Symbol | Call site | Path class |
|---|---|---|
| `applyStartupNamingPolicy` | `daemon_run.go:387`, `daemon_run.go:1611` | **boot / bootstrap-exit** (slow) |
| `enumeratePresentNICs` | `daemon_apply.go:214` | HA config-sync admission (slow) |
| `deviceMapStrandsManagement` | `daemon_apply.go:225` | HA admission alarm (slow) |
| `deviceMapCommitPreflight` | `daemon_apply.go:147,250` | **commit / commit-confirmed** (slow) |
| `protectedForConfig` | `daemon_apply.go:225,729` | commit + teardown (slow) |
| `teardownUnmappedManaged` | `daemon_apply.go:729` | commit apply (slow) |

RSS symbols are called from:

| Symbol | Call site | Path class |
|---|---|---|
| `applyRSSIndirection`, `realRSSExecutor{}` | `linksetup.go:114` (boot), `linksetup.go:126/133` (reapply) | boot + commit reconcile (slow) |
| `rssExecutor` (interface), `realRSSExecutor`, `mlx5Driver`, `isExecNotFound` | `host_tunables.go`, `host_tunables_daemon.go`, `coalescence.go` | **shared ethtool substrate** |

**All call sites are slow-path** (boot, commit, HA sync). None is per-packet /
per-session / per-poll-tick. There is no hot-path or allocation concern.

### 4.4 The cycle, concretely

If `device_map.go` + `rss_indirection.go` move verbatim into package
`multiqueue`:

- `multiqueue` must import `daemon` for `linksetup`/`bootstrap`/`daemon_reth`/
  `exec_timeout` helpers (§4.2). **Edge A: multiqueue → daemon.**
- `daemon` must import `multiqueue` for the six device-map call sites + the RSS
  call site (§4.3). **Edge B: daemon → multiqueue.**
- Edge A + Edge B = **import cycle. Does not compile.**

And it is worse than the issue states: `rssExecutor` / `realRSSExecutor` /
`mlx5Driver` / `isExecNotFound` are shared by `host_tunables.go`,
`host_tunables_daemon.go`, and `coalescence.go` — none of which the issue
proposes to move. Moving the `rssExecutor` type into `multiqueue` forces THOSE
three files to import `multiqueue` for the type, widening Edge B well beyond the
device-map/RSS call sites.

### 4.5 Tests

`device_map_test.go` (394), `device_map_startup_test.go` (180),
`rss_indirection_test.go` (891) — 1,465 LOC of `package daemon` tests that
reference the internal symbols directly (unexported), plus `coalescence_test.go`
and `host_tunables*_test.go` which exercise the shared `rssExecutor`. Any
package move requires the tests to either move with it (and use exported names)
or stay in `package daemon` (and the moved symbols become exported). This is a
non-trivial slice of the churn.

---

## 5. Concrete design (code-level)

Three viable paths. The issue's literal three-file `multiqueue/` package is
**Path C** and is the most expensive; Paths A and B are smaller.

### Path A — leaf primitives package both import (RECOMMENDED first increment)

Mirror the `pkg/daemon/system/` precedent: extract ONLY the **pure, side-effect-
free, daemon-state-free** logic into a leaf package both `daemon` and any future
`multiqueue` can import, and leave the side-effecting glue (rename, ethtool exec,
networkctl reload, the `*Daemon` method, the call sites) in `package daemon`.

Candidate leaf package `pkg/daemon/multiqueue` (pure, NO daemon import):

- From `rss_indirection.go` — the pure decision/parse functions, which take
  plain values and return plain values:
  - `computeWeightVector(workers, queues int) ([]int, string)`
  - `indirectionTableMatches(output []byte, weights []int) bool`
  - `indirectionTableIsDefault(output []byte, queueCount int) bool`
  - `const mlx5Driver` (becomes `multiqueue.Mlx5Driver`)
  - These have ZERO daemon deps and are the most-tested logic.
- From `device_map.go` — `deviceMapOriginalNameFor` is *almost* pure but calls
  `recoverOriginalName` (linksetup) + `deriveKernelNameFn` (daemon_reth), so it
  is NOT a clean leaf candidate without also moving its callees. Leave it.

What stays in `package daemon`: all ethtool-invoking functions
(`applyRSSIndirection*`, `restoreDefaultRSSIndirection`, `maybeRestoreDefault`,
`realRSSExecutor`, the `rssExecutor` interface — because `host_tunables` /
`coalescence` share it), and ALL of `device_map.go`'s rename/teardown/pre-flight
glue (it depends on linksetup + bootstrap + daemon_reth).

Result: the daemon files call `multiqueue.ComputeWeightVector(...)` etc. No
cycle: `multiqueue` imports nothing from `daemon`; `daemon` imports `multiqueue`
one-way. ~150-200 LOC moved, tests for the pure functions move with them.

**Tradeoff**: this does NOT satisfy the issue's stated layout (the side-effecting
device-map and RSS glue stays flat in `pkg/daemon`). It captures the cleanly
extractable ~15% and explicitly documents why the rest cannot move without
dragging linksetup + bootstrap + the shared ethtool substrate along. Honest, but
a partial win the reviewer may judge not worth the churn.

### Path B — break the "in" edge by parameter injection, then move the glue

Make the moved files NOT depend on `package daemon` by injecting their daemon
callees as function parameters / a small interface, so `multiqueue` becomes a
true sub-package that the daemon drives (the `system/` ownership inversion, but
for side-effecting code).

Sketch — a `multiqueue.NamingDeps` struct the daemon constructs:

```go
// package multiqueue
type NamingDeps struct {
    RecoverOriginalName    func(cur string) string
    RenameInterface        func(old, new string) error
    WriteLinkFile          func(target, orig string) bool
    NetworkctlReload       func() error
    WriteBootstrapFxp0     func() bool
    DeriveKernelName       func(ifName string) string
    ResolveLifelineCurrent func() (string, bool)
    ProtectedInterfaces    func(mgmtLeaf string) map[string]bool
    RunCommandTimeout      func(name string, args ...string) ([]byte, error)
    LinkDir, LinkPrefix    string
}
```

`deviceMapCommitPreflight` is already a `*Daemon` method that touches **zero
`Daemon` fields** (verified: 0 `d.` references in its body) — it becomes a free
function `multiqueue.CommitPreflight(candidate, rollbackTarget, deps)` trivially.

Then `multiqueue` exports `EnumerateAndRenameMapped`, `CommitPreflight`,
`StrandsManagement`, `TeardownUnmappedManaged`, `ApplyRSSIndirection`,
`ApplyStartupNamingPolicy`, etc., and `daemon` calls them with a `deps` built
once. No cycle: `multiqueue → daemon` is gone (deps are funcs/values).

**Tradeoff**: a function-pointer `deps` struct is a real abstraction cost for a
tidiness refactor — it makes the call sites less greppable and adds indirection
the project tends to avoid for no behavior gain. It also has to thread the
shared `rssExecutor` type decision (does it stay in daemon and get passed, or
move to multiqueue and force host_tunables/coalescence to import multiqueue?).
This is the only path that produces the issue's literal package, but it is the
highest abstraction-debt option.

### Path C — move the glue AND the substrate it needs (full move)

Move `device_map.go`, `rss_indirection.go`, AND the substrate they depend on
(`linksetup.go`, the relevant `bootstrap.go` lifeline helpers, `daemon_reth.go`'s
`deriveKernelName`, `exec_timeout.go`, plus the shared `rssExecutor` from
`coalescence`/`host_tunables`) into `multiqueue`.

**This is the wrong direction.** `protectedInterfaces` / `resolveLifelineCurrentName`
pull in `readLifelineRecord`, `pciAddrForInterface`, `defaultMgmtInterface`,
`setupBootstrapLifeline` — the entire #1922 bootstrap lifeline machinery. RSS's
shared `rssExecutor` pulls in `host_tunables` + `coalescence`. The transitive
closure is most of the daemon's interface-management and bootstrap subsystems.
Path C would relocate ~5,000+ LOC and several subsystems to "consolidate" 1,159
LOC. **Rejected; documented here so a reviewer does not propose it.**

### Recommendation

**Path A as a first increment, with Path B explicitly deferred** to a follow-up
only if the reviewer decides the issue's literal package layout is worth the
function-pointer abstraction cost. Path C is rejected.

---

## 6. Public API preservation

`pkg/daemon` exports nothing from these files today (all symbols are unexported;
the daemon is consumed only via `Daemon` methods + a few exported entry points).
Path A introduces a NEW exported leaf-package API (`multiqueue.ComputeWeightVector`
etc.) but changes no existing exported surface. Path B exports more
(`multiqueue.ApplyStartupNamingPolicy`, the `NamingDeps` struct). No protobuf,
gRPC, CLI command-tree, REST, or config-schema surface is touched by any path —
this is internal Go package structure only. `pkg/devicemap`'s public API
(`Resolve`, `EnumeratePresentNICs`, `Binding`, `PresentNIC`, ...) is unchanged.

---

## 7. Hidden invariants that MUST be preserved (the dangerous part)

Code motion is "safe" only if these survive byte-for-byte. Each is a place a
careless move breaks production:

1. **#1956 device-map semantics** — leave-alone default
   (`EffectiveUnmappedPolicy`), no-auto-fxp0 (`if desiredNames["fxp0"]` guard),
   console-lifeline (§9.6). The `deviceMapNamingActive` predicate and
   `applyStartupNamingPolicy` branch select mapped-vs-positional; **inverting or
   dropping the branch silently changes boot naming.** A regression here is
   exactly what `TestDeviceMapNamingActiveStartupDecision` guards — the tests
   MUST move/pass with the code.
2. **HA / boot ordering** — `applyStartupNamingPolicy` runs at TWO sites
   (normal boot `daemon_run.go:387`, bootstrap-exit `daemon_run.go:1611`); BOTH
   must keep branching. RSS reshaping MUST run **before any AF_XDP socket binds**
   (the ordering is structural: `applyRSSIndirection` is called from
   `enumerateAndRenameInterfaces` which runs before the dataplane loads in
   `Run()`). Moving RSS out of `linksetup.go` must not reorder it after the XSK
   bind. The #805 `workers>=queues` stale-table restore must stay on the skip
   path.
3. **#1922 management lifeline / commit pre-flight** — `deviceMapCommitPreflight`
   rejects a management-stranding map at COMMIT time (and validates the rollback
   target for `commit confirmed`). `deviceMapStrandsManagement`'s two invariants
   (mgmt-reachable; no protected-name collision) and the protected-set
   resolution via the **candidate's own** management-interface leaf
   (`protectedForConfig`, AGY HIGH-2) must be preserved exactly. A subtle move
   bug here is a silent management lockout on reboot.
4. **`teardownUnmappedManaged` ordering** — runs BEFORE `networkd.Apply`
   (`daemon_apply.go:729`); the protected-interface skip (AGY r2 CRITICAL) and
   the 10-xpf-*.link glob as source-of-truth must survive. Reordering it after
   Apply re-introduces the half-clean un-rename bug.
5. **Byte-order** — N/A: neither file does any `__be32` / native-endian map
   serialization. (Stated for completeness per the review checklist.)
6. **Dual-AST** — N/A in these files; the device-map AST (`config.DeviceMapConfig`,
   `DeviceMapEntry`) is parsed in `pkg/config` and consumed here only as typed
   structs. No parser shape handling moves.
7. **Hot-path allocation** — N/A: all paths are slow (boot/commit/HA). No
   per-packet allocation to preserve.
8. **Shared `rssExecutor` substrate** — `host_tunables` + `coalescence` depend
   on the SAME interface/type/const. Whatever path is chosen must NOT split that
   type across a package boundary in a way that forces those files to import the
   new package (or it widens the edge — §4.4).
9. **Test-injection seams** — `enumerateAndRenameMappedFn`,
   `enumerateAndRenameInterfacesFn`, `predictableNameLookup`, `deriveKernelNameFn`
   are package-level `var` indirections the tests swap. Moving the functions
   without preserving the seam (or its test access) breaks the existing
   non-VM-testable coverage that #1956 deliberately added.

---

## 8. Risk table (4 classes)

| Class | Risk | Likelihood | Mitigation |
|---|---|---|---|
| **Correctness** | Import cycle → does not compile (Path C, or naive Path B) | High if attempted naively | `go build ./...` gate; choose Path A/B that breaks the edge by construction |
| **Correctness** | Branch inversion in `applyStartupNamingPolicy` during move silently changes boot naming | Medium | Byte-identical motion; `TestDeviceMapNamingActiveStartupDecision` + startup-decision tests move and pass |
| **Correctness** | RSS reshaping reordered after XSK bind | Low-Medium | Keep call site in `linksetup.go`'s `enumerateAndRenameInterfaces` (Path A) or assert order in test; do NOT move the *call site*, only the callee |
| **Correctness** | Mgmt lifeline / commit pre-flight subtly altered → reboot lockout | Low (if byte-identical) | Diff every moved body byte-for-byte; `device_map_test.go` strand/preflight cases move + pass |
| **HA / failover** | Move perturbs HA config-sync admission (`deviceMapPassiveAdmissionAlarm`) or commit-confirmed rollback-target validation | Low | These call sites stay in `daemon_apply.go`; only callees move; `make test-failover` if any HA-path file is touched |
| **Perf** | None — no hot-path code moves | N/A | No perf test needed beyond a smoke sanity run |
| **Operational / churn** | Large diff (1,159 LOC + 1,465 test LOC + exported-name renames) for zero behavior gain; review fatigue; merge-conflict surface vs. in-flight #1956 follow-ups | Medium | Prefer the smallest path (A); split into increments; coordinate with any open device-map work |

---

## 9. Test plan

This is behavior-preserving code motion, so the bar is "prove nothing changed."

- **Unit (must)**: `go test ./pkg/daemon/...` green, including the moved
  `device_map_test.go`, `device_map_startup_test.go`, `rss_indirection_test.go`,
  and the unmoved `coalescence_test.go` / `host_tunables*_test.go` that share the
  `rssExecutor`. For Path A, the pure-function tests move to
  `pkg/daemon/multiqueue` and run there.
- **Build (must)**: `go build ./...` and `go vet ./...` to prove no cycle and no
  dangling reference.
- **Byte-identity (must, review aid)**: every moved function body diffed against
  its origin to prove identical logic (the #2005 quad-review discipline). The
  only legitimate deltas are: package clause, import list, and exported-name
  capitalization at the package boundary.
- **Loss-cluster lab — NOT required for Path A.** Path A moves only pure
  decision functions; no boot/HA/dataplane behavior changes, so a unit-green +
  build-green + byte-identity proof is sufficient. A single `make cluster-deploy`
  + sanity iperf3 is a nice-to-have confidence check, not a gate.
- **`make test-failover` — required ONLY if a file on the HA/cluster path is
  touched.** Path A does not touch `daemon_apply.go` / `daemon_ha*` / VRRP /
  session-sync, so per the CLAUDE.md rule it is not triggered. Path B touches the
  call sites in `daemon_apply.go` (commit/HA admission) → `make test-failover`
  becomes mandatory.
- **Multi-increment?** Yes for the issue's full layout: Path A is increment 1
  (pure-function leaf package); Path B (the literal `multiqueue/` package with
  injected deps) is a deferred increment 2, gated on a reviewer decision that the
  abstraction cost is justified. Path C is rejected outright.

---

## 10. Out of scope

- Any runtime behavior change to device-map, RSS, or coalescence.
- The `manager.go` "reconcile multi-queue bounds on NIC link events" file the
  issue sketches — **there is no such code today.** xpf does not reconcile RSS on
  link events; RSS is applied at boot + commit only. Inventing `manager.go` would
  be a NEW FEATURE, not code motion, and is explicitly out of scope.
- Symmetric-hash key settings (`rss.go` in the issue sketch) — not implemented
  today; xpf only reshapes the indirection *table*, not the hash key. Out of
  scope.
- Moving `coalescence.go` / `host_tunables.go` (they share the `rssExecutor` but
  are a separate subsystem; the issue does not ask for them and moving them
  widens the edge).
- Moving `pkg/devicemap` (already a clean leaf package).

---

## 11. Open questions for adversarial review (>=5)

1. **Is ANY version of this worth it?** Given zero behavior value and a
   bidirectional edge wider than the issue states, is the right call PLAN-KILL
   rather than even Path A? What is the bar for "modularity churn worth doing"
   in this codebase (peer issues #1986-#1990 — were any of those killed)?
2. **Path A vs B vs PLAN-KILL.** Path A is a partial win that does NOT produce
   the issue's `multiqueue/` package (the side-effecting glue stays flat). Is a
   partial extraction better than nothing, or does it leave a confusing
   half-moved subsystem that is worse than the status quo?
3. **The `rssExecutor` shared-type problem.** `host_tunables` + `coalescence`
   share `rssExecutor` / `realRSSExecutor` / `mlx5Driver` / `isExecNotFound`.
   Should these move to a shared leaf package too (a third subsystem in the
   refactor), stay in `daemon`, or is this the reason RSS simply should not be
   extracted at all? Does extracting RSS without coalescence create an arbitrary
   split of the "mlx5 ethtool tuning" concern?
4. **Function-pointer deps (Path B) acceptability.** The project generally
   avoids indirection for its own sake. Is a `NamingDeps` func-pointer struct an
   acceptable cost for a tidiness refactor, or does it make the boot/commit call
   chain less greppable in exchange for a directory rename?
5. **Ordering-invariant fragility.** RSS reshaping must run before XSK bind; if
   Path A leaves the *call* in `linksetup.go` but moves the *logic* to
   `multiqueue`, is there any reordering risk, and is there an existing test that
   would actually catch a reorder (or only the structural guarantee)?
6. **Test-seam preservation.** Path A/B both have to keep the `*Fn` injection
   vars working. If the functions move but the tests stay in `package daemon`,
   the seam vars must stay in `daemon` too — does that strand half the logic and
   half the seam on opposite sides of the boundary?
7. **Coordination risk.** Are there in-flight #1956 device-map follow-ups or
   `host_tunables` changes that a 1,159-LOC move would conflict with? Should this
   wait until that area is quiescent?

---

## 12. Claude self-SMR (hostile)

**Strongest objection to my own plan:** the issue, as literally written, cannot
be satisfied cheaply, and the version that CAN be done cheaply (Path A) does not
satisfy the issue. The issue asks for a `multiqueue/` package containing
`device.go` + `rss.go` + a `manager.go` that does not exist. To produce that
package you need Path B (function-pointer injection), which adds real
abstraction debt — a `NamingDeps` struct of nine function pointers threaded
through the boot and commit paths — purely to relocate code, with no behavior,
perf, or HA benefit whatsoever. That is exactly the kind of "indirection for its
own sake" the engineering-style doc warns against. Meanwhile Path A, the clean
option, extracts only ~15% (three pure RSS functions + a couple of parse helpers)
and leaves the device-map glue and the RSS ethtool machinery flat in
`pkg/daemon`, producing a *half-moved* subsystem that arguably reads WORSE than
the current two clearly-named flat files.

A second, independent objection: the `rssExecutor` type is shared with
`host_tunables` + `coalescence`. Any RSS extraction either splits that type
across a package boundary (forcing two more files to import the new package,
widening the very edge we are trying to break) or leaves RSS half-extracted. The
"mlx5 ethtool tuning" concern (RSS + coalescence + host-tunables) is genuinely
one subsystem; carving out only RSS is an arbitrary cut.

**Counter-argument (why not an outright kill):** the `pkg/daemon/system/`
precedent shows the project DOES value pure-logic leaf packages, and the
pure-function tests (`computeWeightVector` + the two table-parsers) are the
best-tested, cleanest-to-extract code in either file. A minimal Path A increment
that moves ONLY those, with byte-identical bodies and their tests, is low-risk
and a genuine (if small) legibility gain — and it is honest about why the rest
cannot follow.

**Disposition: LIKELY-DEFER-MULTI-INCREMENT.**

- The literal issue (a full `multiqueue/` package) is too large and too
  abstraction-costly for one behavior-preserving PR, and its `manager.go` /
  `rss.go` symmetric-hash pieces describe code that does not exist (feature work,
  not motion).
- **Named shippable first increment**: Path A — a `pkg/daemon/multiqueue` leaf
  package containing only the pure RSS decision/parse functions
  (`ComputeWeightVector`, `IndirectionTableMatches`, `IndirectionTableIsDefault`,
  `Mlx5Driver`) and their unit tests, with the daemon calling them one-way. No
  cycle, no HA-path touch, unit + build + byte-identity gated, no lab required.
- **Deferred increment 2 (reviewer-gated)**: Path B, only if a reviewer judges
  the func-pointer abstraction worth the issue's literal layout. Requires
  `make test-failover` (touches the commit/HA call sites).
- **Reject**: Path C (full substrate move) and the invented `manager.go`/`rss.go`
  symmetric-hash files.
- **PLAN-KILL remains a legitimate outcome** if the reviewer decides even Path A's
  partial, half-the-subsystem extraction is not worth the churn for zero behavior
  value — the two flat files are already clearly named and documented.
