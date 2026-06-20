# Claude-SMR self-review — #2049 enforcement-join re-target (r2)

Scope: the #2049 enforcement-join portion of
`docs/research/2049-dynamic-address-enforcement/plan.md` only. The #2050
refresh-correctness + fail-safe sections were reviewed PLAN-READY in r1 and
are unchanged here.

## What changed and why

A hostile re-review found the r1 plan joined the dynamic-address feed overlay
into the **retired eBPF compiler** (`pkg/dataplane/compiler.go`:
`compileAddressBook` :431, `resolveAddrList` :641, `CompileResult.AddrIDs`).
That compiler is dead for forwarding. The join is re-targeted to the runtime
AF_XDP userspace snapshot path.

## Ground-truth verification (read in this worktree, branch
research/review-015-triage)

Confirmed the retired compiler is a dead end for address resolution:

- `CompileUserspaceShim` (`pkg/dataplane/loader.go:148-177`) calls
  `CompileConfig(compilerDP, cfg, ...)` (`loader.go:161`) and uses the returned
  `result` only for `attachUserspaceShimXDP(result)` (XDP attach),
  `result.genericXDPIfindexes`/`tunnelIfindexes` (VLAN sub-interface
  bookkeeping), `m.lastCompile = result`, and
  `recordApplyResult(ApplyResultFromCompileResult(result))`. `result.AddrIDs`
  is **never** serialized into the wire snapshot and never sent to the helper.
- The eBPF dataplane is retired per CLAUDE.md (#1373 complete, source deleted
  #1476).

Confirmed the runtime join points read ONLY `cfg.Security.AddressBook` today
(so a feed-backed name is invisible to the helper):

- `buildAddressBookTable(cfg)` (`pkg/dataplane/userspace/policies.go:155`):
  `if cfg == nil || cfg.Security.AddressBook == nil { return nil, nil }`;
  iterates `ab.Addresses` + `ab.AddressSets` only. Returns the
  `[]AddressBookSnapshot` rows + `nameToID map[string]uint32`.
- `expandBookNameToCIDRs(cfg, name)` (`policies.go:282`): reads
  `cfg.Security.AddressBook` only; resolves Address/AddressSet recursively to
  v4/v6 CIDRs.
- `classifyPolicyAddresses(cfg, nameToID, addrs)` (`policies.go:110`): a token
  in `nameToID` → `bookSet`; otherwise → free-form literal (`seen`/`literals`).
  A feed-backed `address-name` is in neither `nameToID` nor a parseable CIDR,
  so it is silently emitted as a no-match literal.
- `expandUserspacePolicyAddresses` (legacy back-compat field used at
  `policies.go:67,71`) likewise expands only AddressBook names.

Confirmed the snapshot wiring:

- `buildSnapshotWithSchedulerState` (`pkg/dataplane/userspace/builder.go:17`)
  fills `AddressBooks` from `buildAddressBookTable(cfg)` (`builder.go:61-64`)
  and `Policies` from `buildPolicySnapshotsWithSchedulerState(cfg, activeState)`
  (`builder.go:47`). It is invoked from the apply-side compile at
  `pkg/dataplane/userspace/manager.go:571` (alongside `routeOverlay` +
  `activeState`, the existing overlay-threading precedent).

Confirmed the duplicate-publish content-hash gate (the load-bearing reason the
join must be in the snapshot, not the compiler):

- `snapshotContentHash(snap)` (`builder.go:82-101`) zeroes `Generation`,
  `FIBGeneration`, `GeneratedAt`, `Config` (nil), and filters `Neighbors` —
  but does NOT zero `AddressBooks`. So the `[]AddressBookSnapshot` rows are
  part of the hash.
- The gate is consulted in `Manager.Apply` (`manager.go:691-692` sets
  `m.lastSnapshotHash` after a successful publish) and on the route-overlay
  path (`manager.go:887-893`, `:909`) and in `process.go:336`/`:365`.
  `m.lastSnapshotHash` declared at `manager.go:126`.
- A feed `onUpdate` re-runs `applyConfig` against the **same `*config.Config`**
  (`daemon_run.go:886-892`). If the overlay does NOT alter `AddressBooks`, the
  snapshot is byte-identical, the hash matches `lastSnapshotHash`, and the
  refresh is silently suppressed. This is precisely why the r1 compiler.go
  join would have been a double no-op (no snapshot change AND gate-suppressed).

## Edits made to plan.md

- Revision header bumped to r2 with the re-target rationale.
- §1 (#2049 framing): rewritten to describe the runtime snapshot path and
  explicitly mark `compiler.go`/`AddrIDs`/`resolveAddrList` as retired/dead for
  forwarding; the r1 join called out as a no-op.
- §2 (blast radius): PRIMARY join now `userspace/policies.go`
  `buildAddressBookTable` + `builder.go`/`manager.go` threading +
  `daemon_run.go` overlay setter; `compiler.go` explicitly NOT touched.
- §2a (new): the content-hash duplicate-publish gate, why the join must be in
  `AddressBooks`.
- §3 (#2049 enforcement join): code block re-targeted to
  `buildAddressBookTable(cfg, feedOverlay)`; legacy `nextAddrID`/`resolveAddrList`
  language dropped.
- §4 (invariants): content-derived bucket IDs (not sequential `nextAddrID`),
  the in-hash `AddressBooks` invariant, `Manager.mu` accessor.
- §5 (risk table): added the "refresh silently suppressed by the content-hash
  gate" High risk; corrected the ID-collision row to the bucket pipeline.
- §6 (#2049 test plan): rewritten to assert against `AddressBookSnapshot` rows
  and `SourceBookIDs`/`DestinationBookIDs` in the published snapshot, plus an
  explicit `snapshotContentHash` differs-on-same-config assertion. Legacy
  `result.AddrIDs` assertions removed.
- §9 (this self-review's source): documented the r1→r2 re-target and the
  verification above.

## Residual / open for re-review

- The exact threading signature (add an overlay arg to
  `buildSnapshotWithSchedulerState` + `buildAddressBookTable` +
  `buildPolicySnapshotsWithSchedulerState`, vs. a manager-held accessor read
  inside) is an implementation choice; the plan recommends the accessor mirror
  of `routeOverlaySnapshot()`.
- NAT address-name resolution: the plan flags that `build*NATSnapshots` must be
  checked — if NAT resolves feed-backed names via a separate path, the overlay
  must reach it too. Not yet pinned to a line; called out as a verify item.
- The re-targeted join warrants a fresh hostile pass (Codex/AGY were NOT run —
  companion-free research). Status: PLAN-READY-pending-re-review.
