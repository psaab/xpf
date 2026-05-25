# #1451 migration scope — per-subsystem decomposition

This document maps the remaining direct dependencies on the legacy
`dataplane.DataPlane` interface (and the userspace package's
`LegacyDataPlaneAdapter` bridge) so the migration can be split into
small, individually reviewable PRs. #1451 by itself is unreviewable as
one PR; this scope doc divides it into per-subsystem sub-issues that
each fit in a single review cycle.

The migration target is the same in every case: replace
`dataplane.DataPlane` parameters/fields with a narrow, domain-specific
interface declared in the consumer package (the pattern already shipped
by `pkg/api`, `pkg/fwdstatus`, `pkg/monitoriface`, and the
`RuntimeDomainProvider` adopted by `pkg/conntrack`).

## Survey methodology

```
grep -rln 'dataplane\.DataPlane' --include='*.go' pkg/ cmd/
```

Run against `origin/master` at commit `da103d81`. Test files are listed
but not counted as new coupling — they exercise existing seams and move
with their production targets.

## Direct-import inventory (master @ da103d81)

| File | Refs | Role |
|---|---|---|
| `pkg/dataplane/userspace/manager_coupling_test.go` | 7 | Canary AST test — must remain |
| `pkg/dataplane/userspace/legacy_dataplane.go` | 4 | Compatibility adapter — intentionally retained |
| `pkg/daemon/daemon.go` | 3 | `legacyDP()` accessor + type assertion |
| `pkg/cluster/sync.go` | 3 | Session-sync constructor + setter |
| `pkg/grpcapi/server.go` | 2 | `Config.DP` + `Server.dp` fields |
| `pkg/dataplane/retirement_boundary_canary_test.go` | 2 | Canary — must remain |
| `pkg/dataplane/dpdk/manager.go` | 2 | DPDK backend register (kept per #1475) |
| `pkg/cli/cli.go` | 2 | `cli.dp` field + `New()` signature |
| `pkg/monitoriface/monitor.go` | 1 | Doc comment only |
| `pkg/api/handlers.go` | 1 | Doc comment only |
| `pkg/daemon/daemon_flow.go` | 1 | `logFinalStats(dp dataplane.DataPlane)` |
| Test files (`*_test.go`) | 1 each | Move with their package |

## Already-migrated surfaces (no work needed)

These have already been split off and now consume domain-specific
interfaces. Confirmed by reading file headers:

- **`pkg/api`** — uses `apiRuntimeDataPlane` (`pkg/api/handlers.go:28`).
  Doc comment retains a reference to `dataplane.DataPlane` for
  historical context only.
- **`pkg/fwdstatus`** — uses `DataPlaneAccessor` (`builder.go:35`).
- **`pkg/monitoriface`** — uses `RuntimeDataPlane` (`monitor.go:30`).
- **`pkg/conntrack`** — `NewGC` and `NewGCWithDomains` take
  `RuntimeDomainProvider`, `SessionStore`, `Telemetry`, etc.; no
  `DataPlane` parameter on either constructor.

## Remaining coupling, by subsystem

For each remaining subsystem, this section lists files touched, the
methods called through the legacy interface, the public symbols that
need a domain-specific replacement, current callers, and an estimated
PR size and risk.

### S1 — `pkg/grpcapi` gRPC server

Files: `pkg/grpcapi/server.go`, `pkg/grpcapi/server_show_flow.go`,
`pkg/grpcapi/server_show_status.go`, `pkg/grpcapi/server_show_policies_text.go`,
`pkg/grpcapi/server_show_cluster_text.go`, `pkg/grpcapi/server_show_forwarding.go`,
`pkg/grpcapi/server_show_interfaces*.go`, `pkg/grpcapi/server_show_firewall.go`,
`pkg/grpcapi/server_diag.go`, `pkg/grpcapi/server_sessions.go`,
`pkg/grpcapi/server_show.go`.

Public coupling: `Config.DP dataplane.DataPlane` and `Server.dp
dataplane.DataPlane`.

Methods consumed via `s.dp`:
`IsLoaded`, `ReadGlobalCounter`, `IterateSessions`, `IterateSessionsV6`,
`ReadPolicyCounters`, `ReadInterfaceCounters`, `ReadFilterConfig`,
`ReadFilterCounters`, `ReadFloodCounters`, `ReadZoneCounters`,
`ReadNATPortCounter`, `ReadNATRuleCounter`, `ClearPolicyCounters`,
`ClearFilterCounters`, `ClearNATRuleCounters`, `ClearAllCounters`,
`ClearAllSessions`, `DeleteSession`, `DeleteSessionV6`,
`DeleteDNATEntry`, `DeleteDNATEntryV6`, `GetPersistentNAT`,
`GetMapStats`, `SessionCount`, `GetSessionV4`, `GetSessionV6`,
`Compile`. Plus four `s.dp.(interface{...})` provider probes for
userspace-specific extensions.

Target: declare a `grpcRuntime` interface in
`pkg/grpcapi/runtime.go` that lists exactly these methods, accept it as
`Config.DP`, fold the existing `s.dp.(interface{...})` provider probes
behind small named provider interfaces. Daemon passes the same
adapter.

Estimated size: large (>500 LOC touched but mostly mechanical) — split
further if needed by carving counter-reader, session-store-clear, and
diag clear methods into named sub-interfaces.

Risk: medium. Many call sites; mostly read-only. Risk concentrated in
the diag/clear paths and the four provider-probe type assertions.

### S2 — `pkg/cli` interactive CLI

Files: `pkg/cli/cli.go`, `pkg/cli/cli_show_chassis.go`,
`pkg/cli/cli_show_system.go`, `pkg/cli/cli_show_interfaces.go`,
`pkg/cli/cli_clear.go`, `pkg/cli/cli_helpers.go`.

Public coupling: `cli.dp dataplane.DataPlane` field; `New()` parameter.

Methods consumed via `c.dp`:
`IsLoaded`, `ReadGlobalCounter`, `ReadInterfaceCounters`, `ReadFilterConfig`,
`ReadFilterCounters`, `ReadFloodCounters`, `ReadZoneCounters`,
`ReadNATPortCounter`, `ReadNATRuleCounter`, `ReadPolicyCounters`,
`ClearAllCounters`, `ClearAllSessions`, `ClearFilterCounters`,
`ClearNATRuleCounters`, `ClearPolicyCounters`, `DeleteSession`,
`DeleteSessionV6`, `DeleteDNATEntry`, `DeleteDNATEntryV6`, `Compile`,
`GetMapStats`, `GetPersistentNAT`, `IterateSessions`, `IterateSessionsV6`,
`SessionCount`. Plus five `c.dp.(interface{...})` provider probes.

Target: declare a `cliRuntime` interface in `pkg/cli/runtime.go`.
Method set heavily overlaps S1; if both are migrated in close
succession, extract a shared `pkg/dataplane/runtime` package or place
the common subset in a new `pkg/dpiface` package and have S1 and S2
import only what each needs.

Estimated size: large but mechanical. Roughly parallel to S1.

Risk: medium. Same risk profile as S1; clear-counter and session-clear
paths need a smoke check.

### S3 — `pkg/cluster` session sync

Files: `pkg/cluster/sync.go`.

Public coupling: `NewSessionSync(local, peer, dp dataplane.DataPlane)`,
`NewDualSessionSync(local, peer, local1, peer1, dp dataplane.DataPlane)`,
`(*SessionSync).SetDataPlane(dp dataplane.DataPlane)`.

Methods consumed via the stored `dp`: confined to session-store and
session-sync hooks. Concretely: `SetSessionV4`/`SetSessionV6`,
`DeleteSession*`, `IterateSessions*`, plus the `SetSyncDeleteCallback`
hooks driven from `pkg/conntrack/gc.go`.

Target: declare a `clusterRuntime` interface in
`pkg/cluster/runtime.go` (subset of `dataplane.SessionStore` plus the
sync-delete callbacks). `SetDataPlane` becomes `SetRuntime`.

Estimated size: medium. About 300 LOC touched across `sync.go`,
plus a fan-out update to `pkg/daemon/daemon_ha_sync.go` and
`pkg/daemon/daemon_run.go`.

Risk: medium-high. Session sync is on the HA hot path; smoke must
include `make test-failover` per `CLAUDE.md` ("Any change touching
cluster, VRRP, session sync, or failover code MUST pass
`make test-failover` before commit"). On the loss userspace cluster.

### S4 — `pkg/daemon` legacyDP accessor

Files: `pkg/daemon/daemon.go` (`legacyDP()`),
`pkg/daemon/daemon_flow.go` (`logFinalStats`),
`pkg/daemon/daemon_forwarding_status.go`,
`pkg/daemon/daemon_gc.go`, `pkg/daemon/daemon_run.go`,
`pkg/daemon/daemon_scheduler.go`, `pkg/daemon/daemon_ha_sync.go`.

Public coupling: `Daemon.legacyDP() dataplane.DataPlane` returns the
adapter for the dozen call sites listed above. Every consumer that
needs a narrower interface should grow a typed accessor and stop
calling `legacyDP()`.

Target: keep `legacyDP()` only as long as S1 + S2 + S3 still call it;
delete once they no longer need the full interface. Most call sites
already type-assert (`d.legacyDP().(userspaceEventStreamExporter)`) and
can use the underlying `userspace.Manager` directly through a typed
accessor pair (`d.userspaceManager()` already exists; expose narrow
helpers like `d.eventExporter()`).

Estimated size: small individually (~150 LOC) but blocked by S1–S3
finishing. Land last.

Risk: low once the consumers have migrated; this is mostly deletion.

### S5 — userspace boot path (`pkg/dataplane/userspace/manager.go`)

Files: `pkg/dataplane/userspace/manager.go`.

Public coupling: still constructs the userspace backend through
`dataplane.New()` (registered via `RegisterBackend(TypeUserspace, …)`)
and still references `xdp_main_prog` / `xdp_userspace_prog` for the
runtime swap during userspace bring-up. The userspace path proper does
not embed `dataplane.DataPlane` — the canary test in
`manager_coupling_test.go` enforces that. The coupling that remains is
the **boot path** that goes through legacy program loading before
swapping to the userspace XDP shim.

Target: factor the bring-up into a `userspace.Boot()` that does not
require the legacy XDP main program. Coordinate with #1473 — that
issue covers the dedicated userspace-XDP shim decoupling.

Estimated size: medium-large. Smoke-bound; must keep cluster bring-up
working.

Risk: high. Touches the only thing between "dataplane comes up" and
"dataplane does not come up". Defer until S1–S4 are merged so that
review focus is undiluted.

### S6 — userspace maps sync (`pkg/dataplane/userspace/maps_sync.go`)

Files: `pkg/dataplane/userspace/maps_sync.go`.

Public coupling: hard-coded references to BPF map names:
`userspace_ctrl`, `userspace_bindings`, `userspace_fallback_progs`,
`userspace_xsk_map`, plus session and fallback maps. While these are
maps owned by the AF_XDP shim (not the legacy dataplane), they live
under the legacy `pkg/dataplane` map-management layer.

Target: introduce a thin map-name registry under
`pkg/dataplane/userspace/maps.go` and have `maps_sync.go` consume the
registry rather than string-literal names. Coordinate with #1473 (XDP
shim split) so the shim owns its own map names.

Estimated size: medium.

Risk: medium. Map-name drift would silently break bringup.

### S7 — core runtime (`pkg/dataplane/dataplane.go`, `loader.go`, `loader_ebpf.go`)

Files: `pkg/dataplane/dataplane.go` (362 LOC, ~130 interface
methods), `pkg/dataplane/loader.go` (1187 LOC, bpf2go go:generate
directives), `pkg/dataplane/loader_ebpf.go` (957 LOC).

This is the final removal step. It cannot land until S1–S6 are merged
and #1473, #1474, #1475 are closed. It is the mechanical-deletion
phase tracked under #1476, with the canaries in
`pkg/dataplane/retirement_boundary_canary_test.go` and
`pkg/dataplane/userspace/manager_coupling_test.go` continuing to fence
the boundary.

Estimated size: large (deletion-heavy).

Risk: low if the prior steps land cleanly — the canaries catch
re-introductions; the smoke catches semantic breaks.

### S8 — conntrack GC legacy bridge (smallest, lowest risk)

Files: `pkg/conntrack/gc.go`, `pkg/conntrack/gc_test.go`,
`pkg/conntrack/README.md`.

Public coupling: `NewGC(provider RuntimeDomainProvider, …)` already
takes the domain provider on master. The only remaining legacy-shape
artifact is the bridge in `pkg/conntrack/gc.go` that, on receiving a
nil provider, falls through `dataplane.SessionStoreOf(nil)` /
`dataplane.TelemetryOf(nil)` to produce a no-op GC. The test file uses
a mock that nominally implements `dataplane.DataPlane` to satisfy the
old constructor shape.

This is already mostly migrated. The remaining task: tighten the
canary so a future regression cannot re-introduce
`func NewGC(dp dataplane.DataPlane, …)`, and confirm the README +
package doc accurately describe the new constructor surface.

Estimated size: tiny (<100 LOC, mostly doc + test guard).

Risk: trivial.

## Sub-issue boundaries and ordering

Sub-issue order (smallest first, hot-path last):

| Order | Sub-issue | Subsystem |
|---|---|---|
| 1 | smallest | S8 conntrack GC legacy-bridge tightening |
| 2 |  | S1 grpcapi runtime interface |
| 3 |  | S2 cli runtime interface |
| 4 |  | S3 cluster session-sync runtime interface |
| 5 |  | S4 daemon legacyDP shrinkage / deletion |
| 6 |  | S5 userspace boot path (coord with #1473) |
| 7 |  | S6 userspace map-name decoupling (coord with #1473) |
| 8 | last | S7 — covered by #1476 (final source removal) |

## Cross-cutting concerns surfaced during the survey

These don't fit neatly into a single subsystem but the migration cannot
land cleanly without them. They're filed as separate blocker issues
(see PR description for issue numbers).

- **Doc drift.** README files in `pkg/dataplane/`, `pkg/cluster/`,
  `pkg/conntrack/`, and `pkg/grpcapi/` still describe the legacy
  pipeline as the primary path. Each migration sub-PR must update its
  package README so docs and code agree.
- **Tests that assert legacy pipeline behaviour.** Searches for
  hardcoded `xdp_main_prog`/`xdp_userspace_prog` strings outside the
  canaries are needed before S5/S6 lands.
- **`bpf/xdp/` and `bpf/tc/` build hooks.** Final deletion is #1476's
  job, but each migration step should not introduce new go:generate
  hooks against those directories.

## Smoke evidence required per sub-PR

From the project's standing rule (`CLAUDE.md`,
`docs/engineering-style.md`): smoke runs on the **loss userspace
cluster only** (`loss:xpf-userspace-fw0/fw1`), v4 + v6, push + reverse,
CoS-off + CoS-on. Any change touching cluster/session-sync/HA also
requires `make test-failover`.

Refs: #1451, #1373, #1473, #1474, #1475, #1476, #1477.
