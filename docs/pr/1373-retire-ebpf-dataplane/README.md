# #1373 Retire eBPF Dataplane Blocker Plans

> [!IMPORTANT]
> DPDK dataplane retired in #1525. The `## #1475 DPDK Backend Policy`
> and `## #1504 Userspace Shim Boundary Escape Assumptions` sections
> below are preserved verbatim only because the retirement-boundary
> canaries (`TestRetirementBoundaryDocsMentionDPDKPolicy` and
> `TestRetirementBoundaryDocsMentionShimEscapeAssumptions` in
> `pkg/dataplane/retirement_boundary_canary_test.go`) pin their
> text strings. The full rewrite of those sections lands together
> with the canary update in #1527/#1528.

Status: closeout and removal-plan bundle for #1373. The original #1374-#1381
feature-gap plans are kept here as design history and documented runtime
contracts, but those feature-gap blockers are closed. Current removal work is
tracked by #1451 and the removal-phase child issues below.

## Feature Gap Closeout Index

| Issue | Plan | Retirement state | Notes |
|---|---|---|---|
| #1374 SYN cookie flood protection | [plan-1374-syn-cookies.md](plan-1374-syn-cookies.md) | Closed | Runtime challenge/ACK/cache/counters, root-auth-derived snapshot key, bounded SYN-ACK/RST TX, status counters, and gate removal landed; final source-removal evidence rolls into #1477 if required. |
| #1375 three-color policers | [plan-1375-three-color-policers.md](plan-1375-three-color-policers.md) | Closed | Color-blind `then discard` runtime plus compatible snapshot continuity landed; future hardening is production follow-up work, not an active feature-gap blocker. |
| #1376 port mirroring | [plan-1376-port-mirroring.md](plan-1376-port-mirroring.md) | Closed | Snapshot/wire plus bounded runtime admission landed; final mirror-fidelity evidence rolls into #1477 if required. |
| #1377 persistent SNAT pool address selection | [plan-1377-snat-pools.md](plan-1377-snat-pools.md) | Closed | Userspace-v1 selector, unusable-pool fail-closed runtime, helper-local persistent-NAT lease reuse, per-pool allocator sharing, and allocator counters landed. #1448, #1449, and #1450 are closed documented contracts for helper restart reset, HA admission gating, and backend-specific selector behavior. |
| #1378 policy schedulers | [plan-1378-policy-schedulers.md](plan-1378-policy-schedulers.md) | Closed | Closed by live HA artifact capture accepted by `policy_scheduler_validate.py`; no known #1378 runtime or evidence gap remains. |
| #1379 dataplane events | [plan-1379-dataplane-events.md](plan-1379-dataplane-events.md) | Closed | Policy-deny, screen-drop, PBR filter logs, non-PBR input/output/lo0 filter logs, cached input-log replay without filter rescans, source-disambiguated FILTER_LOG syslog, and deterministic fanout coverage landed. |
| #1380 userspace buffer/status parity | [plan-1380-userspace-buffers.md](plan-1380-userspace-buffers.md) | Closed | Helper-status rendering is active; Rust-owned session-table and flow-cache denominators are helper-published, while neighbor entries remain counters until Rust owns a bounded neighbor-cache capacity. |
| #1381 DataPlane split | [plan.md](plan.md) | Closed | The blocking userspace-apply/interface split closed; the broader source-removal migration continues under #1451. |

## Current Removal Work

| Issue | Scope |
|---|---|
| #1451 | Migrate remaining legacy eBPF-shaped runtime and operator surfaces before source/generated artifact deletion. |
| #1473 | Split the retained userspace XDP shim from legacy `xdp_main_prog` fallback. Closeout pending: implementation, link-cycle regressions, counter rename, and source/object/manager canaries already landed via #1493, #1498, #1512, #1513, #1514. See [plan-1473](../1473-xdp-shim-decouple/plan.md) for the per-AC evidence trail. |
| #1493 | Split userspace shim loader/bootstrap from the legacy `loadAllObjects()` path. |
| #1494 | Pin the retained userspace shim boundary with source/object/manager canaries before source deletion. |
| #1476 | Remove legacy BPF source, generated artifacts, and build hooks after the blockers close. |
| #1477 | Publish final userspace-only validation artifacts for the exact source-removal candidate. |

#1474 is closed: omitted `system dataplane-type` selects userspace, while
explicit `system dataplane-type ebpf` remains temporary warned compatibility
until legacy source removal.

## Removal-Phase Dependency

The source-removal order is now explicit:

1. #1494 canary: merge the retained userspace XDP shim boundary canaries.
2. #1493 loader split: remove userspace startup's dependency on the legacy
   `loadAllObjects()` graph.
3. #1451 surface shrink: finish moving runtime/operator callers off the legacy
   eBPF-shaped `dataplane.DataPlane` bridge.
4. #1476 deletion: remove legacy source, generated artifacts, and stale build
   hooks using [source-removal-manifest-1476.md](source-removal-manifest-1476.md).
5. #1477 final evidence: publish validation artifacts for the exact deletion
   candidate.

#1451 remains the common migration umbrella. The userspace manager no longer
embeds the old `DataPlane` interface directly, and a userspace legacy adapter
owns the compatibility boundary while unmigrated callers move to domain
interfaces. #1380 is a Phase 5 CLI/observability cleanup item, now closed for
the current helper schema; it does not block the source-removal gate by itself.

## #1451 Runtime Boundary Canaries

`pkg/dataplane/retirement_boundary_canary_test.go` pins the current retirement
boundary for #1451. It discovers every top-level `cmd/*` and `pkg/*`
production Go package except `pkg/dataplane` itself, then fails if a new direct
`github.com/psaab/xpf/pkg/dataplane` import appears outside the allowlist below,
or if a listed bridge disappears without shrinking this documentation.

The same canary also keeps operator packages away from direct BPF artifacts:
they may not import `github.com/cilium/ebpf`. The DPDK backend import was
historically allowed only at `cmd/xpfd/main.go` for backend registration; that
backend is retired in #1525 and #1527 removes the registration import. Daemon
startup must keep
owning `dataplane.RuntimeDataPlane` and must call
`dataplane.NewRuntimeDataPlane`, not `dataplane.NewDataPlane`. This is a
production-code canary; `_test.go` files may still import lower-level helpers
when they need backend fixtures for regression coverage.

## #1475 DPDK Backend Retired (#1525)

The DPDK backend was retired in umbrella #1525. The retirement
shipped in four phases:

- Phase 1 (#1526, merged): commit-time reject for `set system
  dataplane-type dpdk`.
- Phase 2 (#1527, merged): boot-path decouple — removed the blank
  registration import from `cmd/xpfd/main.go` and the backend
  registration in `pkg/dataplane/dpdk/manager.go`.
- Phase 4 (#1529, merged): documentation sweep across the doc tree
  (landed before Phase 3 because the canary-pinned text strings
  that pre-#1528 forbade direct rewrite are addressed here in
  Phase 3 by deleting the canaries themselves).
- Phase 3 (#1528, this PR): mechanical deletion of `dpdk_worker/`
  C tree, `pkg/dataplane/dpdk/` Go package, Makefile DPDK
  targets, `DPDKConfig`/`DPDKAdaptiveConfig`/`DPDKPort` schema
  types, the `SystemConfig.DPDKDataplane` field, and the
  retirement-boundary canary entries that policed the now-deleted
  package.

After #1528, the only DPDK-related code that remains is:

- The Phase 1 commit-time reject in `pkg/config/compiler.go`
  (`dataplaneTypeDPDK`, `ErrDPDKDataplaneRetired`,
  `validateDataplaneTypeStrict`) — kept for one release cycle so
  `commit` produces the operator-friendly migration message rather
  than a generic "unknown dataplane-type".
- The runtime sentinel in `pkg/dataplane/dataplane.go` (`TypeDPDK`,
  `ErrDPDKBackendRetired`, registry panic guards) — kept for the
  same window.
- The `rewriteRetiredDataplaneType` bridge in
  `pkg/configstore/dataplane_retire.go`, invoked from both
  `Store.Load` and `Store.SyncApply` before compile, which strips
  the `system dataplane-type dpdk` leaf so a node booting with a
  pre-#1526 persisted DPDK config loads cleanly and runs as the
  default `userspace` dataplane. (This replaces the pre-rebase
  plan-v3 `compileTreeForLoad` load-mode bypass.)
- A defense-in-depth forbidden-import entry in
  `pkg/dataplane/runtime/import_canary_test.go:47` that blocks
  re-introduction of `github.com/psaab/xpf/pkg/dataplane/dpdk` as
  an import from the runtime package.

A future cleanup PR after the release-cycle window may delete the
remaining Phase 1 reject machinery once the rolling-upgrade
window is closed.

## #1473 Userspace XDP Shim Build Split

The retained Rust userspace XDP shim is still required for the AF_XDP userspace
runtime. Its runtime fallback behavior and generation path are now explicit and
separate from the legacy XDP/TC dataplane:

- `make generate-userspace-xdp` rebuilds only
  `pkg/dataplane/userspace_xdp_bpfel.o` through the
  `pkg/dataplane/build-userspace-xdp.sh` go:generate directive.
- `make build-userspace-xdp` is an alias for the shim-only generation target.
- `make generate` remains the full compatibility target: legacy XDP/TC bpf2go
  artifacts plus the retained userspace shim.
- `make generate-legacy-bpf` regenerates legacy XDP/TC bpf2go artifacts while
  skipping the retained shim.

The userspace shim target must not depend on legacy `xdp_main` or TC program
generation. `pkg/dataplane/retirement_boundary_canary_test.go` reads the
Makefile and fails if `generate-userspace-xdp` gains legacy bpf2go tokens,
recursive Make dependencies, or the broad `./pkg/dataplane/...` generate path.
The same canary allowlists the retained Rust shim's source-level and built-object
maps/programs, rejects tail-call plumbing in that shim, and requires the retained
Go shim manager to keep its entry-program state unexported so JSON/reflection
cannot select the legacy XDP entry point. Production userspace code may only use
the narrow userspace-shim selection/swap methods. This keeps the retained shim
visible without implying that degraded userspace mode can bypass back into the
legacy pipeline.

#1509 renames the retained-shim degraded action counters on the Go/status and
operator documentation surface to `degraded_path_counters`. The pinned BPF map
name `userspace_fallback_stats` remains an internal mixed-version compatibility
exception until the final retained-shim ABI boundary is removed. New daemons
also emit `fallback_counters` as a legacy JSON alias for one compatibility
window so old status readers do not silently zero these counters during rolling
upgrades; new code should read `degraded_path_counters`. The dual-emit window
is intentionally short and the legacy alias should be removed with the next
userspace helper status protocol bump after the retained-shim ABI boundary is
retired.

The #1493 loader/bootstrap split keeps normal userspace startup on the
userspace-only shim loader below. Source removal still waits for #1451's
remaining operator/runtime surface migration and #1476's deletion candidate.

## #1504 Userspace Shim Boundary Escape Assumptions

The retained userspace shim boundary canary scans direct production files in
`pkg/dataplane` and `pkg/dataplane/userspace`. It deliberately does not recurse
into `pkg/dataplane/dpdk`; DPDK remains governed by the #1475 backend policy,
including its `-tags dpdk` CGo files, and is not part of the userspace-only shim
escape scan.

Package-local `dataplane.Manager` construction must not use positional
composite literals. The entry-program state lives in the unexported
`xdpEntryProg` field, so positional `dataplane.Manager` literals can silently
populate that field if the struct order changes or a local caller supplies all
fields. Production code must use `dataplane.New()` plus the narrow
userspace-shim selection/swap methods. Package-local tests may keep keyed
literals when they intentionally need direct field setup.

The same direct boundary packages must not add production `import "C"`,
`//go:linkname`, `//go:cgo_*` compiler directives, `.s` / `.S` assembly files,
or `.syso` precompiled object files. Those mechanisms can mutate Go state or
hide alternate entry paths outside the AST selectors pinned by the entry-program
canary. Production build constraints are also rejected unless they are
explicitly allowlisted and documented here. After #1476 mechanical source
removal the build-tag allowlist is empty: the legacy bpf2go-generated
`xpf{Xdp,Tc}*_x86_bpfel.go` wrappers and the `//go:build ignore`
`pkg/dataplane/loader_stub.go` placeholder are deleted along with the source
they wrapped. Any new boundary build tag, assembly or object file, CGo
import, or Go compiler directive requires a matching canary allowlist
rationale before it can land.

The historical generated legacy bpf2go build-tag allowlist (deleted by
#1476) is preserved in git history at the manifest's `## Delete Manifest`
section in `docs/pr/1373-retire-ebpf-dataplane/source-removal-manifest-1476.md`.

## #1493 Userspace Shim Loader Split

Normal AF_XDP userspace startup now enters `LoadUserspaceShim()` and
`CompileUserspaceShim()` instead of the legacy `Manager.Load()` /
`loadAllObjects()` path. The shim loader loads only the retained Rust
`xdp_userspace_prog` object plus explicit pinned compatibility maps used by the
userspace runtime and old operational bridges: `userspace_*`, `dnat_table`,
`dnat_table_v6`, `sessions`, `sessions_v6`, FIB/HA/fabric maps,
`session_id_gen`, and telemetry counter maps. It does not load
`xdp_main_prog`, legacy XDP tail-call programs, TC programs, `xdp_progs`, or
`tc_progs`.

The shim keeps `dnat_table` and `dnat_table_v6` at the legacy 10M-entry,
`BPF_F_NO_PREALLOC` contract so a legacy-to-shim restart can reuse existing
pins instead of silently wiping active SNAT-return state. If any required
compatibility map is incompatible, the shim loader fails closed with the
offending pin path and does not mutate pinned state; the operator must run an
explicit teardown or migration outside normal startup. The operator runbook is
[`docs/operations/userspace-shim-pin-recovery.md`](../../operations/userspace-shim-pin-recovery.md):
drain traffic, stop `xpfd`, inspect the pinned map, remove only the
incompatible pin path named in the error, restart `xpfd`, and verify the map was
recreated. Removing a stateful compatibility pin resets that map's dataplane
state, so the loader never retries by deleting a map pin or the whole BPF pin
tree. During userspace shim compile, any pinned legacy `tc_*` links are detached
and unpinned before the retained XDP shim is attached; TC programs are not part
of the userspace runtime and must not survive as stale egress hooks from a
previous legacy boot. Legacy-only map pins (`xdp_progs`, `tc_progs`, and
`policer_states`) are removed during userspace shim startup, while compatibility
stateful maps such as `sessions`, `sessions_v6`, `dnat_table`, and
`dnat_table_v6` are preserved.

The remaining compatibility bridge is config compilation metadata and Linux
interface setup: userspace still runs the shared config compiler, but through a
shim compile adapter that no-ops legacy dataplane map writes and attaches only
the userspace XDP shim. Legacy direct callers outside the runtime adapter remain
tracked under #1451.

### Allowlisted Legacy Bridges

These files are the current production direct-import allowlist for root
`pkg/dataplane`. New migration PRs should remove entries from this table as
surfaces move to domain interfaces such as `RuntimeDataPlane`, `SessionStore`,
`Telemetry`, or package-local accessor interfaces. Adding a new entry means
#1451 is moving backward and requires an explicit design reason.

| File | Current blocker |
|---|---|
| `cmd/shimverify/main.go` | #1864 build-time verifier gate: thin wrapper over `dataplane.VerifyUserspaceShimObject` (verify-only kernel-verifier load; no production load path). Deliberate, not retirement debt. |
| `cmd/shim-manifest/main.go` | #4977 build-time freshness gate: thin wrapper over `dataplane.WriteUserspaceXDPManifest` (regenerates the source→object manifest during `make generate`; no production load path). Deliberate, not retirement debt. |
| `cmd/xpfd/main.go` | Backend selection, cleanup, and backend registration still cross the root package. |
| `pkg/api/api.go` | Shared REST helpers still reference legacy dataplane counters and types (#1540 split entry: `apiRuntimeDataPlane` interface, `applyResult` adapter). |
| `pkg/api/metrics.go` | Prometheus telemetry still reads legacy counters and metadata. |
| `pkg/api/metrics_counters.go` | Prometheus map-counter collectors still call legacy dataplane reads (#1540 metrics split). |
| `pkg/api/metrics_nat.go` | Prometheus NAT pool collector still reads legacy dataplane (#1540 metrics split). |
| `pkg/api/metrics_userspace.go` | #2114 r6-F1 — the userspace `Status()` probe resolves through `dataplane.Unwrap` so the daemon's live indirection (whose method set is only the mandatory surface) does not erase the capability and blank every userspace metric family. Probe-routing only, no legacy enforcement path. |
| `pkg/api/metrics_sessions.go` | Prometheus session gauge collector still iterates legacy session tables (#1540 metrics split). |
| `pkg/api/nat.go` | REST NAT handlers still read legacy NAT counters and metadata (#1540 handlers split). |
| `pkg/api/security.go` | REST security handlers still reference legacy policy/screen counter types (#1540 handlers split). |
| `pkg/api/sessions.go` | REST session reads still use legacy session types (#1540 rename of `handlers_sessions.go`). |
| `pkg/api/stats.go` | REST statistics handlers still read legacy global/interface/zone counters (#1540 handlers split). |
| `pkg/cli/cli.go` | Embedded CLI construction still stores the legacy bridge. |
| `pkg/cli/cli_clear.go` | Clear commands still delete legacy session entries. |
| `pkg/cli/cli_config.go` | #9841 — `commitApply` syncs the just-published unconverged-MTU records onto the committed config via `dataplane.LastApplyGenerationOf`/`LastApplyResultOf`/`SyncMTUUnconvergedWarnings` (peer of the daemon wrapper). Commit-warning projection only; no legacy enforcement path. |
| `pkg/cli/cli_show_chassis.go` | #2114 r2-B7 — `show chassis forwarding` binds `backend := dataplane.Unwrap(dp)` to a local so an empty cell yields a nil `fwdstatus` accessor. The old `dp == nil` gate is permanently false under the live indirection, so an emptied cell fell through to the non-userspace wrapper and `fwdstatus.Build` reported `BufferKnown=true` with `BufferPercent=0` — a zero every downstream consumer is told to trust — where the nil-dp control says "unknown (see #878)". Peer of `pkg/grpcapi/server_show_forwarding.go`. Render-only, no legacy enforcement path. |
| `pkg/cli/cli_show_cluster.go` | #1444 — `fabricRedirectCounters` type and `readFabricRedirectCounters` relocated from `cli.go`; still reads legacy `GlobalCtrFabric*` counter indices via `dataplane.Telemetry`. |
| `pkg/cli/top_talkers_bound_8597.go` | #8597 K05 — the top-talkers collection **split out of** `pkg/cli/cli_show_flow.go` (`d93263fe5`: −89 lines there, +236 here). It uses the same `dataplane.SessionKey`/`SessionValue` (and v6 twins) as its parent entry — *"flow display still uses legacy session keys and values"* — and adds no new dataplane surface. This is a **relocation, not a new capability**: the allowlist is keyed by filename, so extracting code out of an allowlisted file trips the canary while the boundary posture is completely unchanged. Allowlisting a relocation keeps the guard accurate; allowlisting a new capability would weaken it. Render-only, no legacy enforcement path. |
| `pkg/cli/cli_show_system.go` | #2114 r6-F3 — `show system buffers` binds `backend := dataplane.Unwrap(dp)` to a local instead of asking `dp != nil`: the live indirection is permanently non-nil, so the old check printed "No BPF maps available" (a claim about a loaded backend) for a daemon with no dataplane at all. Since r7 that ONE resolution feeds both the publication check and the capability probe. Render-only, no legacy enforcement path. |
| `pkg/cli/cli_show_flow.go` | Flow display still uses legacy session keys and values. |
| `pkg/cli/cli_show_interfaces.go` | #9841 — `show interfaces` annotates unconverged MTUs via `dataplane.LastApplyResultOf` plus the shared Annotate/Render helpers (peer of `pkg/grpcapi/server_show_interfaces.go`). Render-only; no legacy enforcement path. |
| `pkg/cli/cli_show_nat.go` | NAT display still uses legacy NAT/session metadata. |
| `pkg/cli/cli_show_security.go` | Security display still uses legacy counters and filter types. |
| `pkg/cli/cli_show_security_dispatch.go` | #1444 — `handleShowSecurity` dispatcher and security helpers relocated from `cli.go`; still uses legacy `MaxRulesPerPolicy` and policy-counter accessors. |
| `pkg/cli/cli_show_security_log.go` | #2158 — split from `cli_show_security.go`; still reads legacy screen `GlobalCtr*` counter constants. |
| `pkg/cli/cli_show_security_screen.go` | #2158 — split from `cli_show_security.go`; still reads legacy screen `GlobalCtr*` counter constants. |
| `pkg/cli/cli_show_security_filters.go` | #7422 — `show firewall` / `show firewall filter <name>` resolve a `then dscp` / `then traffic-class` rewrite through `dataplane.ResolveFilterDSCP`, the SAME resolver `buildFilterTermSnapshots` uses, so the renderer cannot report a CoS marking the snapshot builder dropped. Mirrors `daemon_nft.go`'s #3436 and `netlink_lo0.go`'s #6387 use of the `dataplane.DSCPValues` SSOT. Render-only, no legacy enforcement path. |
| `pkg/cli/cli_show_security_wireguard.go` | #2114 r2-B4 — the WireGuard status and public-key renders bind `backend := dataplane.Unwrap(dp)` to a local, so an emptied cell answers "Dataplane not loaded" instead of naming a backend KIND ("requires the userspace dataplane") for a daemon that has no backend at all. Peer of `pkg/grpcapi/server_show_security_text.go`. Render-only, no legacy enforcement path. |
| `pkg/cli/cli_show_security_zones.go` | #3643 — `show security zones` distinguishes `dataplane.ErrCounterNotPopulated` (per-zone traffic counters HIDE) from a genuine counter-read error; still names root `pkg/dataplane` counter types. |
| `pkg/cli/proto.go` | #1444 — shared session/proto helpers (`sessionStateName`, `ntohs`, `protoNameFromNum`, etc.) relocated from `cli.go`; still names `dataplane.SessState*` enum and `ProtoICMPv6` sentinel. |
| `pkg/cli/session_filter.go` | #1444 — `sessionFilter` type, matcher methods, and peer-RPC fetchers relocated from `cli.go`; still uses legacy session key/value types and `SessFlag*`. |
| `pkg/cli/runtime.go` | #1517 — `cliRuntime` interface declares the narrow CLI dataplane surface; still depends on root `pkg/dataplane` type names (`SessionKey`, `CounterValue`, etc.) until those types move to a domain package. |
| `pkg/cluster/runtime.go` | `clusterRuntime` interface still names `dataplane.SessionStore`/`Telemetry` domain types from `pkg/dataplane`; no longer references `dataplane.DataPlane` after #1518. |
| `pkg/cluster/sync.go` | Session sync still installs sessions through the legacy bridge (deprecated `SetDataPlane` alias retained one cycle per #1518; constructors now take the narrow `clusterRuntime` instead of `dataplane.DataPlane`). |
| `pkg/cluster/sync_bulk.go` | Bulk sync still serializes legacy session entries. |
| `pkg/cluster/sync_conn_gen.go` | #5661 pure-motion split of `sync_conn.go` — session-gen guards still reference legacy session types. |
| `pkg/cluster/sync_conn_read.go` | #5661 pure-motion split of `sync_conn.go` — receive/dispatch path still references legacy session types. |
| `pkg/cluster/sync_conn_sweep.go` | #5661 pure-motion split of `sync_conn.go` — incremental sync sweep still references legacy session types. |
| `pkg/cluster/sync_conn_write.go` | #5661 pure-motion split of `sync_conn.go` — send/queue/journal path still references legacy session types. |
| `pkg/cluster/sync_install_table_9752.go` | #9752 round 5 — install-table send/recv memos name legacy session key/value types for the cluster sync path (same types as the `sync_conn_gen.go` guards); membership helpers only, no legacy enforcement path. |
| `pkg/cluster/sync_protocol.go` | Wire protocol still carries legacy session records. |
| `pkg/cluster/test_seams.go` | #9631 — test-only seam file that must live in the production package so external HA cells can drive it without internal-export tricks (peer of `pkg/dhcp/test_seams.go`); the generation/journal observers (`SentInstallGenerationV4ForTesting`, `DeleteJournalGenerationV4ForTesting`) name the same legacy `dataplane.SessionKey` the `sync_conn_gen.go` guards already name. No new dataplane surface. |
| `pkg/conntrack/gc.go` | GC still uses root package session-domain types until those move out of `pkg/dataplane`; constructors no longer accept `DataPlane`. |
| `pkg/daemon/daemon.go` | Daemon owns `dataplane.RuntimeDataPlane`; `legacyDP()` accessor was deleted in #1519 (sub-#1451 S4). Only the `RuntimeDataPlane` field and `LastApplyResultOf` adapter remain. |
| `pkg/daemon/daemon_apply_dataplane.go` | #5661 pure-motion split of `daemon_apply.go` — dataplane+HA core apply still adapts legacy compile/apply metadata. |
| `pkg/daemon/daemon_apply_tail.go` | #5661 pure-motion split of `daemon_apply.go` — tail reconcile still names legacy dataplane types. |
| `pkg/daemon/daemon_apply_mtu_warnings_9841.go` | #9841 — the commit wrapper syncs the just-published unconverged-MTU records onto the committed config via `dataplane.LastApplyGenerationOf`/`SyncMTUUnconvergedWarnings`. Commit-warning projection only; no legacy enforcement path. |
| `pkg/daemon/daemon_policy_invalidate.go` | #4234 commit-time deletion-clear names root dataplane session types (`SessionEntryV4/V6`, `DeleteReasonPolicyDeleted`) to invalidate a deleted policy's live sessions via `SessionStore.DeleteBatchKnown*`; control-plane session lifecycle, no legacy enforcement path. |
| `pkg/daemon/daemon_policy_invalidate_capture.go` | #6948 pre-publication invalidation capture names root dataplane session types (`SessionEntryV4/V6`, `SessionKey`/`SessionValue`, `DefaultPolicySentinelID`) to snapshot the candidate sessions through `SessionStore.ForEach*` before the new policy snapshot is published; control-plane session lifecycle, no legacy enforcement path. |
| `pkg/daemon/daemon_persistent_nat_show_8607.go` | #8607: the persistent-NAT SHOW refresh names `dataplane.PersistentNATTable` / `PersistentNATBinding` and resolves the published backend through `dataplane.Unwrap`, to FILL the table `show security nat source persistent-nat-table` reads. It exists **because** the legacy writer is unreachable on this path: `daemon_run.go` sets `gc.SkipSweep` on the userspace backend, so the preserve hook on `SessionStore.DeleteBatchKnown*` — the table's only binding writer — and `pnat.GC()` are both behind the skipped sweep, and the operator table was empty for the life of the box. Display-only; no legacy enforcement path. |
| `pkg/daemon/daemon_proxyarp.go` | #2197: extracted proxy-ARP/NDP reconcile + periodic re-assert call `dataplane.ReconcileProxyARP` (control-plane kernel responder reconcile relocated from `daemon_apply.go`). |
| `pkg/daemon/daemon_flow.go` | Flow logging still names legacy `dataplane.GlobalCtr*` counter indices read via `dataplane.Telemetry`. |
| `pkg/daemon/daemon_nft.go` | #3436: lo0/host-inbound nft generation resolves DSCP names through the `dataplane.DSCPValues` SSOT to emit numeric nft (avoids unloadable Junos DSCP tokens); generation-only, no legacy enforcement path. |
| `pkg/daemon/rss_indirection.go` | #7497: RSS indirection reshaping bounds its fed queue set by the `dataplane.BindingQueuesPerIface` stride SSOT, so RSS never steers to a queue index the planner cannot bind. Exemption is for a **constant-only** import — one compile-time constant, no `dataplane` call, no legacy type. **That limit is unenforced**: the canary is file-scoped and sees only *that* the package is imported, never *what*, so widening this file to a call or a type keeps the entry green while making this justification false. Not precedent for a wider import. Importing rather than re-spelling is deliberate — the stride already has three mutually-pinned spellings (shim source, `userspace-dp`, `pkg/dataplane`) and a fourth literal in `pkg/daemon` would inherit none of that pin. |
| `pkg/daemon/daemon_ha.go` | HA state updates still call legacy bridge methods. |
| `pkg/daemon/daemon_ha_fabric.go` | Fabric HA updates still call legacy bridge methods. |
| `pkg/daemon/daemon_ha_sync.go` | #9915 F-044 — sync-guard capacity sizing (`genGuardCapacityForRuntime`) names only the `dataplane.RuntimeDataPlane` interface the daemon already owns (`daemon.go`), reading provisioned session capacity through the daemon-local `CachedStatus` probe with a `conntrack.MaxSessions` fallback. Capacity-routing only; no legacy enforcement path. |
| `pkg/daemon/daemon_ha_userspace_convert.go` | #4659 split of `daemon_ha_userspace.go` by concern — HA session (de)serialization names root dataplane session-domain types (`SessionKey`/`SessionKeyV6`/`SessionValue`/`SessionValueV6`) and `SessFlag*`/`LogFlag*` wire constants when crossing the legacy bridge. |
| `pkg/daemon/daemon_ha_userspace_readiness.go` | #4659 split of `daemon_ha_userspace.go` by concern — userspace HA readiness gate reads `dataplane.EffectiveType`/`TypeUserspace` to confirm the runtime forwarding path. |
| `pkg/daemon/daemon_ha_userspace_stream.go` | #4659 split of `daemon_ha_userspace.go` by concern — userspace HA session-delta streaming names `dataplane.AFInet`/`AFInet6` address-family constants when crossing the legacy bridge. |
| `pkg/daemon/daemon_run.go` | Runtime wiring still uses the legacy `dataplane.ErrDPDKBackendRetired` sentinel and constructs `api`/`grpcapi`/`cli` configs against the daemon-local probes in `runtime_probes.go` (#1519 capstone). |
| `pkg/daemon/daemon_run_bringup.go` | #5661 pure-motion split of `daemon_run.go` — manager/config bring-up names `dataplane.ErrDPDKBackendRetired`/`ErrEBPFBackendRetired`/`Manager`. |
| `pkg/daemon/daemon_run_naming.go` | #5661 pure-motion split of `daemon_run.go` — interface naming reads `dataplane.EffectiveType`/`TypeUserspace`. |
| `pkg/daemon/daemon_run_routehelpers.go` | #5661 pure-motion split of `daemon_run.go` — applied-tunnel/route helpers read `dataplane.EffectiveType`/`TypeUserspace`. |
| `pkg/daemon/runtime_probes.go` | #1519 daemon-local typed probes (`apiDataPlane`/`grpcDataPlane`/`cliDataPlane`/`dataplaneReadyProbe`/`natSeeder`/`fibSyncStarter`) mirror downstream package-private interfaces; still name root `pkg/dataplane` types (`SessionKey`, `CounterValue`, etc.) until those move to a domain package. |
| `pkg/grpcapi/server_diag_system_action.go` | #2114 r6-F2/F3 — `clear-persistent-nat` binds `dataplane.PersistentNATTable` to a LOCAL so the table is resolved once per operation (a check-then-use across two cell loads nil-dereferenced), and `dataplaneActionError` maps `dataplane.ErrNotPublished` to `codes.Unavailable`. Control-plane only, no legacy enforcement path. |
| `pkg/grpcapi/server_show_forwarding.go` | #2114 r2-B7 — `show chassis forwarding` binds `backend := dataplane.Unwrap(dp)` to a local so an empty cell yields a nil `fwdstatus` accessor, restoring `BufferKnown=false`. Falling past the old permanently-false `dp == nil` gate made `fwdstatus.Build` take its BPF-map arm and set `BufferKnown=true` with `BufferPercent=0`. Peer of `pkg/cli/cli_show_chassis.go`. Render-only, no legacy enforcement path. |
| `pkg/grpcapi/server_show_system.go` | #2114 r6-F3 — `show system buffers` binds `backend := dataplane.Unwrap(dp)` to a local instead of asking `dp != nil`, with ONE resolution feeding both decisions since r7 (peer of `pkg/cli/cli_show_system.go`). Render-only, no legacy enforcement path. |
| `pkg/daemon/daemon_dp_live.go` | #2114 r4 — the live management-surface indirection handed to gRPC/REST/CLI in place of a startup snapshot of the published backend. It forwards the UNION of the `runtime_probes.go` probes, so it names exactly the same root `pkg/dataplane` types those probes do and moves with them. No legacy enforcement path. |
| `pkg/logging/ringbuf.go` | #3057 — RT_FLOW policy-name resolution references the shared wire-contract constants `dataplane.DefaultPolicySentinelID` + `dataplane.DefaultPolicyName` (the implicit default-policy sentinel ID, kept in lockstep with `userspace-dp/src/policy.rs`). Display-only; no legacy enforcement path. |
| `pkg/nftables/netlink_lo0.go` | #6387 PR-2 — the additive netlink lo0-filter builder resolves DSCP names through the `dataplane.DSCPValues` SSOT to emit numeric nft-equivalent matches (mirrors `daemon_nft.go`'s #3436 resolution). Ruleset-generation-only; no legacy enforcement path. |
| `pkg/policymatch/zone_detail_summary.go` | #3684 — the shared `show security zones detail` policy-summary presenter renders the same wire-contract constants `dataplane.DefaultPolicyName` + `dataplane.DefaultPolicySentinelID` on the default-policy catch-all row (M13). Display-only; no legacy enforcement path (peer of `pkg/logging/ringbuf.go`). |
| `pkg/grpcapi/apply_result.go` | gRPC apply metadata still adapts legacy apply results. |
| `pkg/grpcapi/server_nat.go` | #2218 — `GetNATRuleStats` keys NAT translation-hit counters with `dataplane.NATCounterKey` (type-namespaced `ruleset/rule`) so same-named SNAT/DNAT/static rules do not collide; shares the compiler's single key formatter. |
| `pkg/grpcapi/runtime.go` | #1516 — `grpcRuntime` interface declares the narrow gRPC dataplane surface; still depends on root `pkg/dataplane` type names (`SessionKey`, `CounterValue`, etc.) until those types move to a domain package. |
| `pkg/grpcapi/server_helpers.go` | gRPC helpers still format legacy dataplane types and bridge runtime accessors. |
| `pkg/grpcapi/server_sessions.go` | gRPC session RPCs still use legacy session types. |
| `pkg/grpcapi/server_show_cluster_text.go` | Cluster text output still reads legacy dataplane state. |
| `pkg/grpcapi/server_show_flow.go` | Flow text output still uses legacy session keys and values. |
| `pkg/grpcapi/server_show_policies_text.go` | Policy text output still uses legacy counters. |
| `pkg/grpcapi/server_show_security_text.go` | Security text output still uses legacy counters and filter types. |
| `pkg/grpcapi/server_show_status.go` | Status output still reads legacy dataplane state. |
| `pkg/grpcapi/server_show_zones.go` | Zone output still uses legacy dataplane types. |
| `pkg/grpcapi/server_show_zones_text.go` | #3643 — zone text output distinguishes `dataplane.ErrCounterNotPopulated` (per-zone traffic counters HIDE) from a genuine counter-read error; still names root `pkg/dataplane` counter types. |
| `pkg/grpcapi/server_show_interfaces.go` | #9841 — the `ShowInterfacesDetail` text twin annotates unconverged MTUs via the shared Annotate/Render helpers (peer of `pkg/cli/cli_show_interfaces.go`). Render-only; no legacy enforcement path. |
| `pkg/natshow/natshow.go` | #1687 — shared NAT presenter `Reader` interface names root `pkg/dataplane` session/counter types (`SessionKey`, `CounterValue`, `PersistentNATTable`). Net-neutral consolidation: the import moved here from `server_show_nat.go` (which no longer imports root dataplane) and is still named by `cli_show_nat.go`. |
| `pkg/natshow/source.go` | #1687 — shared source-NAT rule-detail renderer iterates legacy `SessionKey`/`Value` via the `Reader`. |
| `pkg/natshow/dest.go` | #1687 — shared destination-NAT rule-detail renderer iterates legacy `SessionKey`/`Value` via the `Reader`. |
| `pkg/natshow/persistent.go` | #1687 — shared persistent-NAT renderers iterate legacy `SessionKey`/`Value` and read `PersistentNATTable` via the `Reader`. |
| `pkg/natshow/walk.go` | #7315 — the single cancellable session-walk authority (`walkSessionValues`) the three walking NAT renderers route through; names the same legacy `SessionKey`/`Value` the three per-renderer copies it replaced already named. Net-neutral: the iterations moved OUT of `persistent.go`/`source.go`/`dest.go` into this file rather than a new consumer appearing. |

### Safe-Delete Blockers

- `pkg/dataplane.DataPlane` is still load-bearing for API, gRPC, CLI, status,
  cluster session sync, daemon HA, daemon flow, and daemon apply bridges listed
  above. Conntrack GC now enters through `SessionStore` and `Telemetry`
  runtime-domain providers. `pkg/monitoriface` now uses a
  package-local `RuntimeDataPlane`/`CounterReader` shape; CLI and gRPC adapt
  their wider dataplane fields before entering the monitor-interface package.
- Omitted `system dataplane-type` now resolves to the userspace runtime path.
  Explicit `system dataplane-type ebpf` remains available only as a temporary
  compatibility setting until source removal, and config compile emits a
  deprecation warning when it is selected.
- `pkg/dataplane/userspace.LegacyDataPlaneAdapter` is still required because
  userspace runtime construction returns a legacy-compatible adapter while
  unmigrated operator services consume old session, telemetry, and control
  methods. The userspace `Manager` itself must not implement `DataPlane`.
- DPDK was retired in #1525. The pre-retirement contract — that DPDK
  implemented both `DataPlane` and `RuntimeDataPlane` and that the blank
  registration import lived at `cmd/xpfd/main.go` — is preserved in the
  canary-pinned `#1475 DPDK Backend Policy` section in this file as a
  historical anchor; #1527 removes the registration import and #1528
  deletes the backend package.
- Legacy BPF source and generated artifacts are not safe to delete in #1451
  canary work: `bpf/`, `pkg/dataplane/*_bpfel.go`,
  `pkg/dataplane/*_bpfel.o`, and the legacy side of the `Makefile generate`
  path remain tied to the explicit eBPF backend until #1476 removes that
  backend source. They are no longer required by normal userspace startup.
- Retained userspace XDP shim artifacts are tracked separately:
  `pkg/dataplane/userspace_xdp_bpfel.o` and
  `pkg/dataplane/build-userspace-xdp.sh` remain required for userspace runtime
  startup, but `make generate-userspace-xdp` rebuilds them without legacy
  `xdp_main` or TC dataplane program generation.

## Phase 1/2 Smoke Gates

Use [smoke-gates.md](smoke-gates.md) for the repeatable Phase 1/2 operator
checklist: CoS-off IPv4/IPv6 push and reverse, screen/flood baseline,
CoS-on 5200..5211 class sweeps, 6200..6211 TCP echo probes, the standard
`userspace-phase-cycle.sh` eight-cell HA smoke matrix, and the existing HA
Makefile gates. The HA matrix uses explicit iperf3 ports so CoS-on cells run
on the uncapped-root class instead of the default 5201 / 100 Mbps class. The
direct HA validator keeps a `--fast` IPv4/IPv6 push-only readiness mode, but
standard smoke evidence must use the full matrix.

## #1477 Final Artifact Contract

Use [final-validation/README.md](final-validation/README.md) for the final
source-removal candidate artifact layout. The structural checker at
`test/incus/retire_ebpf_artifact_schema.py` verifies that the evidence bundle is
complete, consistently named, and tied to the exact 40-character candidate SHA;
it does not replace live-result review.

## Shared Non-Goals

- Do not remove `bpf/` in these blocker implementation PRs; that remains #1373
  Phase 4.
- Do not rewrite unrelated dataplane behavior while adding parity for the
  missing features.
- Do not use the DPDK worker as a correctness reference when it conflicts with
  the reviewed userspace-dp contract.
