# #2004 — consolidate `pkg/daemon` device_map + rss_indirection into `pkg/daemon/multiqueue/`

**Status:** PLAN-KILLED (converged 2026-06-19 — AGY PLAN-KILL-CONFIRMED +
Claude SMR confirmed against reproduced edge/grep evidence; Codex review
ran but its result infra-dropped). No code written, no production source
touched, no PR opened.

**Recommendation: PLAN-KILL** (close as won't-fix / tracked-decision),
with a clearly-scoped *Path-A increment* available if the campaign owner
wants a small, honest partial win. Rationale in §1 and §10.

**Branch:** `research/2002-2004-import-cycles`. Supersedes/consolidates the
earlier `research/2004-daemon-multiqueue-import-cycle` plan (same
conclusion; this revision adds reproduced edge evidence + verifies the
issue's `manager.go`/`rss.go` describe nonexistent code).

---

## 1. TL;DR / verdict

- **Is the cycle real?** The codebase **compiles cleanly today** (`go build
  ./pkg/daemon/` → OK). No cycle in the current flat layout. The cycle is
  *created by* the move the issue asks for.
- **Does the literal move create a cycle?** **Yes — a bidirectional edge,
  wider than the issue states.** Verified on this branch (§4):
  - **Edge A (multiqueue → daemon):** the two moved files call **~12**
    daemon-internal symbols defined elsewhere — `linksetup.go`
    (`recoverOriginalName`, `renameInterface`, `writeLinkFile`,
    `networkctlReload`, `writeBootstrapFxp0Network`, `linkDir`, `linkPrefix`,
    `execCommand`), `daemon_reth.go` (`deriveKernelName`), `bootstrap.go`
    (`resolveLifelineCurrentName`, `protectedInterfaces`), `exec_timeout.go`
    (`runCommandTimeout`).
  - **Edge B (daemon → multiqueue):** 6 device-map symbols are consumed by
    `daemon_run.go` + `daemon_apply.go` (`applyStartupNamingPolicy`,
    `enumeratePresentNICs`, `deviceMapStrandsManagement`,
    `deviceMapCommitPreflight`, `protectedForConfig`,
    `teardownUnmappedManaged`); and the RSS substrate (`rssExecutor`,
    `realRSSExecutor`, `mlx5Driver`, `isExecNotFound`, `applyRSSIndirection`)
    is consumed by `coalescence.go`, `host_tunables.go`,
    `host_tunables_daemon.go`, `linksetup.go`.
  - A + B = **import cycle. Does not compile.** Re-export shims don't help:
    a shim still needs `daemon` to import `multiqueue` (B) while
    `multiqueue` imports `daemon` (A).
- **Worse than stated.** The `rssExecutor`/`realRSSExecutor`/`mlx5Driver`/
  `isExecNotFound` type family is shared with **four** files the issue does
  NOT propose to move (`coalescence`, `host_tunables`,
  `host_tunables_daemon`, `linksetup`). Moving the type into `multiqueue`
  forces all four to import `multiqueue`, widening Edge B well beyond the
  device-map/RSS call sites. "mlx5 ethtool tuning" (RSS + coalescence +
  host-tunables) is genuinely one subsystem; carving out only RSS is an
  arbitrary cut.
- **The issue describes code that doesn't exist.** Its proposed
  `manager.go` ("reconcile multi-queue bounds on NIC link events") and the
  symmetric-hash-key part of `rss.go` have **no corresponding code today**
  (verified: zero hits for link-event reconcile or `symmetric-hash`/`rx-flow-
  hash`/hash-key). xpf applies RSS at boot + commit only and reshapes the
  *indirection table*, not the hash key. Building those would be **new
  feature work, not code motion** — out of scope for the issue's own
  "behavior-preserving" charter.
- **Churn vs benefit.** ~1,159 LOC of source + ~1,465 LOC of `package
  daemon` tests, exported-name renames, and either a function-pointer `deps`
  abstraction (Path B) or a ~5,000-LOC substrate drag (Path C) — for **zero**
  runtime/perf/HA/operator value. `pkg/daemon` is ~70 files; the two targets
  are 1.6% of non-test source, so extraction barely shrinks the package.

---

## 2. Issue framing

agy-review-013 Part II.3 (modularity backlog, peer to #1986–#1990) asks to
consolidate two flat multiqueue/RSS files into `pkg/daemon/multiqueue/`:

- `device_map.go` (666 LOC) — #1956 bare-metal device-map glue (rename /
  teardown / commit pre-flight).
- `rss_indirection.go` (493 LOC) — #785/#805 mlx5 RSS indirection-table
  reshaping.

Suggested layout: `multiqueue/{device.go, rss.go, manager.go}`. The issue
flags: *"Behavior-preserving code motion only. preserve the leave-alone
default + no-auto-fxp0 lifeline semantics."* The catch: a new directory is a
new Go package with a hard import boundary, and both files sit on a
**bidirectional** edge.

## 3. Honest scope / value

Pure internal tidiness. **Zero runtime/perf/HA/operator-visible value** — no
hot-path change, no allocation change, no behavior change. The only benefit
is legibility: a named package instead of two flat files. But the extraction
is not clean — the symbols are woven into the daemon's startup-naming path,
apply path, and the shared `host_tunables`/`coalescence` ethtool substrate.

**If reviewers conclude the scope is too small to justify the churn,
PLAN-KILL is the intended outcome.** This plan surfaces the import-edge cost
so the decision is made with eyes open.

## 4. The cycle — verified with edge evidence

### 4.1 Baseline (no cycle today)

```
$ go build ./pkg/daemon/      # on this branch, go1.24.9
DAEMON_BUILD_OK
```

### 4.2 Edge A (multiqueue → daemon), measured

`device_map.go` calls (defined elsewhere in `pkg/daemon`):

| Symbol | Defined in | Uses in device_map.go |
|---|---|---|
| `recoverOriginalName` | linksetup.go | 3 |
| `renameInterface` | linksetup.go | 4 |
| `writeLinkFile` | linksetup.go | 2 |
| `networkctlReload` | linksetup.go | 2 |
| `writeBootstrapFxp0Network` | linksetup.go | 1 |
| `linkDir` | linksetup.go | 5 |
| `linkPrefix` | linksetup.go | 5 |
| `execCommand` | linksetup.go | 1 |
| `deriveKernelName` | daemon_reth.go | 2 |
| `resolveLifelineCurrentName` | bootstrap.go | 1 |
| `protectedInterfaces` | bootstrap.go | 1 |

`rss_indirection.go` calls `runCommandTimeout` (exec_timeout.go) ×1.

### 4.3 Edge B (daemon → multiqueue), measured

Device-map symbols consumed by other daemon files:

| Symbol | Consumed by |
|---|---|
| `applyStartupNamingPolicy` | daemon_run.go |
| `enumeratePresentNICs` | daemon_apply.go |
| `deviceMapStrandsManagement` | daemon_apply.go |
| `deviceMapCommitPreflight` | daemon_apply.go |
| `protectedForConfig` | daemon_apply.go |
| `teardownUnmappedManaged` | daemon_apply.go |

RSS symbols consumed by other daemon files:

| Symbol | Consumed by |
|---|---|
| `applyRSSIndirection` | daemon_run.go, host_tunables.go, linksetup.go, coalescence.go |
| `rssExecutor` | coalescence.go, host_tunables_daemon.go, linksetup.go, host_tunables.go |
| `realRSSExecutor` | host_tunables_daemon.go, linksetup.go |
| `mlx5Driver` | coalescence.go |
| `isExecNotFound` | coalescence.go, host_tunables.go |

Edge A + Edge B both exist → moving both files verbatim is a guaranteed
cycle. **All call sites are slow-path** (boot, commit, HA sync) — none is
per-packet/per-session/per-poll-tick; no hot-path concern.

### 4.4 The `rssExecutor` widening, confirmed

`rssExecutor`/`realRSSExecutor`/`mlx5Driver`/`isExecNotFound` are shared by
`coalescence.go` + `host_tunables.go` + `host_tunables_daemon.go` +
`linksetup.go` — none of which the issue moves. Relocating the type to
`multiqueue` forces those four to import `multiqueue`, widening Edge B.

### 4.5 The issue's nonexistent code, confirmed

- `manager.go` ("reconcile multi-queue bounds on NIC link events"): **no
  such code** — zero hits for link-event RSS reconcile in either target file.
  RSS is applied at boot + commit only.
- `rss.go` "symmetric-hash key settings": **no such code** — zero hits for
  `symmetric-hash`/`hash-key`/`rx-flow-hash`/`--config-nfc`. xpf reshapes the
  indirection *table*, not the hash key.

Inventing either is a new feature, not motion — explicitly out of scope.

### 4.6 `deviceMapCommitPreflight` is `*Daemon`-method-but-stateless

```
pkg/daemon/device_map.go:450: func (d *Daemon) deviceMapCommitPreflight(...)
```

Verified: **0 `d.field` references** in its body — trivially convertible to a
free function `multiqueue.CommitPreflight(candidate, rollbackTarget, deps)`.
This is the one fact that makes Path B's `deps`-injection mechanically
feasible (but see §5/§10 for why it's still not worth it).

## 5. Design options (if pursued despite the kill recommendation)

### Path A — leaf primitives package both import (smallest, RECOMMENDED-if-pursued)

Mirror the `pkg/daemon/system/` precedent (a leaf package of pure renderers
the daemon wraps). Extract ONLY the pure, side-effect-free, daemon-state-free
logic into a leaf `pkg/daemon/multiqueue` both `daemon` and any future code
import one-way:

- From `rss_indirection.go`: `computeWeightVector(workers, queues)`,
  `indirectionTableMatches(output, weights)`,
  `indirectionTableIsDefault(output, queueCount)`, `const mlx5Driver`. Zero
  daemon deps; best-tested logic.
- Keep in `package daemon`: all ethtool-invoking functions
  (`applyRSSIndirection*`, `restoreDefaultRSSIndirection`, the `rssExecutor`
  interface + `realRSSExecutor` — shared by host_tunables/coalescence) and
  ALL of `device_map.go` (depends on linksetup + bootstrap + daemon_reth).

Result: ~150–200 LOC moved, pure-function tests move with them. No cycle:
`multiqueue` imports nothing from `daemon`.
**Tradeoff:** does NOT satisfy the issue's stated layout (the side-effecting
glue stays flat). Captures the cleanly-extractable ~15% and is honest about
why the rest can't move — but a half-moved subsystem may read worse than two
clearly-named flat files.

### Path B — break Edge A by parameter injection, then move the glue

Make the moved files NOT import `daemon` by injecting their daemon callees as
a `multiqueue.NamingDeps` struct of ~9 function pointers + a few values
(`RecoverOriginalName`, `RenameInterface`, … `RunCommandTimeout`, `LinkDir`,
`LinkPrefix`). `deviceMapCommitPreflight` becomes a free function (§4.6).
This is the only path producing the issue's literal package.
**Tradeoff:** a 9-func-pointer `deps` struct threaded through boot + commit
is exactly the "indirection for its own sake" the engineering-style doc warns
against — for zero behavior gain. It also makes the call chain less greppable
and still must resolve the shared `rssExecutor` type decision.

### Path C — move the glue AND its substrate (REJECTED)

Moving `device_map.go`'s lifeline deps pulls in `readLifelineRecord`,
`pciAddrForInterface`, `defaultMgmtInterface`, `setupBootstrapLifeline` (the
entire #1922 bootstrap machinery); RSS's shared `rssExecutor` pulls in
host_tunables + coalescence. Transitive closure ≈ 5,000+ LOC across several
subsystems to "consolidate" 1,159 LOC. **Wrong direction — documented so no
reviewer proposes it.**

### Recommendation

Path A as the only defensible partial; Path B deferred and contentious; Path
C rejected. Overall: **PLAN-KILL** (§10).

## 6. Public API preservation

`pkg/daemon` exports nothing from these files today (all unexported; consumed
only via `Daemon` methods + a few entry points). Path A adds a NEW exported
leaf API (`multiqueue.ComputeWeightVector`, …) but changes no existing
exported surface. Path B exports more (`NamingDeps`, `ApplyStartupNaming…`).
No protobuf/gRPC/CLI-tree/REST/config-schema surface is touched by any path.
`pkg/devicemap`'s public API is unchanged.

## 7. Hidden invariants that MUST survive

1. **#1956 device-map semantics** — leave-alone default
   (`EffectiveUnmappedPolicy`), no-auto-fxp0 (`if desiredNames["fxp0"]`
   guard), console-lifeline (§9.6). `applyStartupNamingPolicy`'s
   mapped-vs-positional branch selects boot naming; inverting/dropping it
   silently changes boot. `TestDeviceMapNamingActiveStartupDecision` guards
   it — tests MUST move/pass with the code.
2. **HA / boot ordering** — `applyStartupNamingPolicy` runs at TWO sites
   (normal boot daemon_run.go, bootstrap-exit daemon_run.go); BOTH must keep
   branching. RSS reshaping MUST run **before any AF_XDP socket binds**
   (structural: `applyRSSIndirection` is called from
   `enumerateAndRenameInterfaces`, before the dataplane loads). Moving RSS
   logic must not reorder it after the XSK bind; keep the *call site* in
   linksetup.go (Path A). The #805 `workers>=queues` stale-table restore must
   stay on the skip path.
3. **#1922 mgmt lifeline / commit pre-flight** — `deviceMapCommitPreflight`
   rejects a management-stranding map at commit (and validates the rollback
   target for `commit confirmed`); `deviceMapStrandsManagement`'s two
   invariants + the protected-set via the candidate's own mgmt leaf
   (`protectedForConfig`, AGY HIGH-2) must be exact. A move bug here is a
   silent reboot lockout.
4. **`teardownUnmappedManaged` ordering** — runs BEFORE `networkd.Apply`; the
   protected-interface skip + the `10-xpf-*.link` glob as source-of-truth
   must survive. Reordering re-introduces the half-clean un-rename bug.
5. **Shared `rssExecutor` substrate** — host_tunables + coalescence depend on
   the SAME interface/type/const. No path may split that type across a
   boundary in a way that forces those files to import the new package (§4.4).
6. **Test-injection seams** — `enumerateAndRenameMappedFn`,
   `enumerateAndRenameInterfacesFn`, `predictableNameLookup`,
   `deriveKernelNameFn` are package-level `var` indirections tests swap.
   Moving functions without preserving the seam breaks #1956's
   non-VM-testable coverage.
7. **N/A (stated for the checklist):** byte-order (no `__be32`/native-endian
   here), dual-AST (device-map AST is parsed in `pkg/config`, consumed here
   as typed structs only), hot-path allocation (all paths slow).

## 8. Risk table

| Class | Risk | Likelihood | Mitigation |
|---|---|---|---|
| Correctness | Import cycle → won't compile (Path C / naive B) | High if naive | `go build ./...` gate; choose a path that breaks the edge by construction |
| Correctness | Branch inversion in `applyStartupNamingPolicy` silently changes boot naming | Medium | Byte-identical motion; startup-decision tests move + pass |
| Correctness | RSS reshaping reordered after XSK bind | Low-Medium | Keep the *call site* in linksetup.go; move only the callee (Path A) |
| Correctness | Mgmt lifeline / commit pre-flight subtly altered → reboot lockout | Low (if byte-identical) | Diff every moved body; strand/preflight tests move + pass |
| HA/failover | Move perturbs HA config-sync admission or commit-confirmed rollback-target validation | Low | Keep call sites in daemon_apply.go; only callees move; `make test-failover` if any HA-path file is touched (Path B touches daemon_apply.go → mandatory) |
| Perf | None — no hot-path code moves | N/A | No perf test needed beyond smoke |
| Operational/churn | ~1,159 LOC + ~1,465 test LOC + exported renames for zero behavior gain; merge-conflict surface vs in-flight #1956 work | Medium | Prefer Path A; split increments; coordinate with open device-map work |

## 9. Test plan

Behavior-preserving motion → bar is "prove nothing changed."

- **Unit (must):** `go test ./pkg/daemon/...` green incl. the moved
  `device_map_test.go` / `device_map_startup_test.go` /
  `rss_indirection_test.go` and the UNMOVED `coalescence_test.go` /
  `host_tunables*_test.go` that share `rssExecutor`. Path A: pure-function
  tests move to `multiqueue` and run there.
- **Build (must):** `go build ./...` + `go vet ./...` to prove no cycle and
  no dangling reference.
- **Byte-identity (must, review aid):** every moved body diffed against
  origin; only legitimate deltas are package clause, import list,
  exported-name capitalization at the boundary.
- **Loss-cluster lab — NOT required for Path A.** Pure decision functions
  only; no boot/HA/dataplane behavior change. Optional single
  `cluster-deploy` + sanity iperf3 is nice-to-have, not a gate.
- **`make test-failover` — required ONLY if an HA/cluster-path file is
  touched.** Path A doesn't touch daemon_apply.go / daemon_ha* / VRRP /
  session-sync → not triggered. **Path B touches daemon_apply.go call sites →
  mandatory.**

## 10. Disposition: PLAN-KILL (with Path-A as the only defensible partial)

**Recommended: PLAN-KILL.** Close #2004 as won't-fix / tracked-decision.
Evidence:

1. **The literal issue can't be done cheaply** — moving both files is a
   guaranteed bidirectional cycle (§4), wider than stated (the `rssExecutor`
   widening, §4.4).
2. **The version that CAN be done cheaply (Path A) doesn't satisfy the
   issue** — it extracts only ~15% (3 pure RSS functions) and leaves the
   device-map glue + RSS ethtool machinery flat, producing a half-moved
   subsystem arguably worse than two clearly-named flat files.
3. **The version that DOES satisfy the issue (Path B) adds real abstraction
   debt** — a 9-func-pointer `NamingDeps` struct threaded through boot +
   commit, "indirection for its own sake," for zero behavior/perf/HA gain.
4. **Two of the three proposed files describe nonexistent code** —
   `manager.go` (link-event reconcile) and `rss.go`'s symmetric-hash key are
   features that don't exist; building them is not motion.
5. **Zero payoff** — no runtime/perf/HA/operator value; 1.6% of `pkg/daemon`
   non-test source; the two files are already clearly named and documented.

**Acceptable fallback IF the campaign owner still wants a partial win:** Path
A only — a `pkg/daemon/multiqueue` leaf package containing just the pure RSS
decision/parse functions (`ComputeWeightVector`, `IndirectionTableMatches`,
`IndirectionTableIsDefault`, `Mlx5Driver`) + their unit tests, daemon calling
them one-way. No cycle, no HA-path touch, unit + build + byte-identity gated,
no lab required. **Reject** Path C and the invented `manager.go`/`rss.go`.

## 11. Out of scope

- Any runtime behavior change to device-map / RSS / coalescence.
- `manager.go` link-event reconcile (does not exist — new feature).
- Symmetric-hash key (`rss.go`) (does not exist — new feature).
- Moving `coalescence.go` / `host_tunables.go` (separate subsystem; the issue
  doesn't ask, and moving them widens the edge).
- Moving `pkg/devicemap` (already a clean leaf package).

## 12. Open questions for plan-review (≥5)

1. **Is ANY version worth it?** Zero behavior value + a bidirectional edge
   wider than the issue states → is PLAN-KILL right rather than even Path A?
   What's the bar for "modularity churn worth doing" here? (Peers #1988/#1989/
   #1990 shipped — but those crossed package lines *without* a back-edge.
   #1986/#1987/#2005 remain open.)
2. **Path A vs PLAN-KILL.** Is a partial extraction (side-effecting glue stays
   flat) better than nothing, or a confusing half-moved subsystem worse than
   the status quo?
3. **The `rssExecutor` shared-type problem.** Should it move to a shared leaf
   too (a third subsystem in the refactor), stay in daemon, or is this the
   reason RSS simply should not be extracted? Is extracting RSS without
   coalescence an arbitrary split of "mlx5 ethtool tuning"?
4. **Func-pointer deps (Path B) acceptability.** Is a 9-func-pointer
   `NamingDeps` an acceptable cost for tidiness, or does it harm
   greppability of the boot/commit chain for a directory rename?
5. **Ordering-invariant fragility.** RSS must run before XSK bind. If Path A
   leaves the call in linksetup.go but moves the logic, is there any reorder
   risk, and does any existing test actually catch a reorder (or only the
   structural guarantee)?
6. **Test-seam preservation.** Path A/B both must keep the `*Fn` injection
   vars working. If functions move but tests stay in `package daemon`, the
   seam vars must stay in daemon too — does that strand half the logic and
   half the seam on opposite sides of the boundary?
7. **Coordination risk.** Any in-flight #1956 device-map follow-ups or
   `host_tunables` changes a 1,159-LOC move would conflict with?

---

## Claude self-SMR (hostile)

**Strongest objection to my own plan:** the issue cannot be satisfied
cheaply, and the version that CAN be done cheaply (Path A) does not satisfy
the issue. The issue asks for a `multiqueue/` package containing `device.go`
+ `rss.go` + a `manager.go` that does not exist. To produce that package you
need Path B (function-pointer injection), which adds a 9-func-pointer
`NamingDeps` struct threaded through boot + commit — "indirection for its own
sake" — purely to relocate code, with no behavior/perf/HA benefit. Meanwhile
Path A extracts only ~15% and leaves the device-map glue + RSS ethtool
machinery flat, producing a half-moved subsystem that arguably reads WORSE
than the current two clearly-named flat files. Independently, the
`rssExecutor` type is shared with host_tunables + coalescence — any RSS
extraction either splits that type across a boundary (widening the very edge
we're breaking) or leaves RSS half-extracted; "mlx5 ethtool tuning" is
genuinely one subsystem and carving out only RSS is arbitrary.

**Counter-argument (why not blind-kill):** the `pkg/daemon/system/`
precedent shows the project DOES value pure-logic leaf packages, and the
pure RSS functions are the best-tested, cleanest-to-extract code in either
file. A minimal Path-A increment moving only those, byte-identical, with
their tests, is low-risk and a genuine (if small) legibility gain — and
honest about why the rest can't follow.

**Disposition: PLAN-KILL**, with Path A as the only defensible partial if
the owner wants motion. The issue should be amended on GitHub to record that
(a) the literal move is a guaranteed bidirectional import cycle, and (b) its
`manager.go`/`rss.go` describe code that does not exist.
