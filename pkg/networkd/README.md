# pkg/networkd

systemd-networkd file generator. Writes `.link`, `.network`, and
`.netdev` files for every xpfd-managed interface, handles MAC-based
rename, VLAN parent flagging, DHCP avoidance, and atomic file
replacement (AtomicGeneratedConfig, #1894: `fsatomic.WriteFileAtomic` —
many small files per reconcile, deliberately no fsync; the procfs
`rp_filter` knob stays a direct write, rename being impossible there).
Triggers `networkctl reload` only when files actually changed.

## Entry points

- `Manager` — `networkd.go`.
- `InterfaceConfig` — `networkd.go`. MAC, addresses, bonding, VLAN
  parent, VRF binding, description.
- `New()` — `networkd.go`.
- `NewInDir(dir)` — `networkd.go`. Test/offline renderer constructor that
  writes xpf-managed files under a caller-provided directory instead of
  `/etc/systemd/network`.
- `Apply(...)` — `networkd.go`. Also the TEARDOWN entry point: `Apply(nil)`
  sweeps every managed file and reloads (#2988). There is no separate `Clear`;
  see the retirement note below (#6852).
- `FindExternallyManaged(dir string) map[string]bool` — `networkd.go`. Detects networkd files
  the daemon doesn't own.

## Callers

`pkg/daemon`, `pkg/dataplane`.

## Dependencies

Standard library only.

## Naming conventions (CLAUDE.md authoritative)

- File prefix `10-xpf-` distinguishes xpf-managed files from manual
  configs. Anything else is left alone.
- Non-RETH interfaces match by `MACAddress=` — MAC is stable.
- RETH member interfaces match by `OriginalName=` (PCI kernel name)
  because the MAC alternates between physical and virtual at boot. The
  daemon's `ensureRethLinkOriginalName()` auto-fixes stale `.link` files
  that still use `MACAddress=`.
- `KeepConfiguration=static` on RETH interfaces preserves VRRP VIPs
  across `networkctl reload`.

## Gotchas

- `Apply()` calls `networkctl reload` when files actually changed **or**
  a prior activation is still owed (see reload-debt below). This matters:
  a reload bounces interfaces, and an idempotent reapply must be cheap.
- Interfaces not in the typed config get `ActivationPolicy=always-down`
  in their `.network` file, so they stay down across reboots.
- **DHCP is gated per-family (#2986).** A static address is suppressed
  ONLY for the family whose DHCP client owns it: `DHCPv4` suppresses the
  static IPv4 address(es), `DHCPv6` suppresses the static IPv6
  address(es). The common WAN shape `DHCPv4 + static IPv6` (and the
  mirror) installs the non-DHCP family's static address; do NOT re-gate
  all addresses on whole-interface DHCP state. `generateNetwork`
  classifies family by `addressIsIPv6` (colon test on the CIDR string).
- **A VLAN parent ignores `Addresses`; only `VLANParentAddresses` addresses
  it (#9721).** `IsVLANParent` suppresses every `Address=` line built from
  `Addresses`, so a sub-interface's addresses cannot leak onto the parent
  (`TestGenerateNetwork_VLANParent`). `VLANParentAddresses` is the explicit
  exception, and it renders only on a VLAN parent. Its one producer is
  `pkg/dataplane`'s `buildInterfaceNetworkdModels`: a VRRP-backed RETH whose
  untagged unit (no `vlan-id`) binds its VRRP instance to the parent gets the
  `169.254.<rg>.<node+1>/32` advert source there, with `KeepAddresses`.
  Routing that address through `Addresses` instead would drop it silently.
- VRF and tunnel interfaces created elsewhere are excluded from the
  unmanaged-interface scan via the `daemonOwned` map.
- **The activation tail's `networkctl reconfigure` argv is asserted in
  full, and the fixture must VARY every axis it claims to cover
  (#6914).** The tail selects `!Unmanaged && !Disable && BondMaster == ""`
  and accumulates names in slice order. An argv assertion can only catch a
  regression along an axis the fixture varies: with a single eligible
  interface, `[reconfigure trust0]` is also what a hardcoded literal, a
  deleted `Unmanaged` predicate, a deleted `Disable` predicate and a
  reversed accumulation all produce — all four were measured green against
  the one-interface fixture. `activationTailIfaces()` therefore carries two
  INCLUDED interfaces on either side of the three excluded ones (bond
  member, unmanaged, disabled), so accumulation and order are both
  observable. Its expectation (`wantActivationTailArgv`) is spelled out
  rather than derived by filtering the fixture with the production
  predicate — deriving it would let the same predicate decide both the
  behaviour and the expectation, so deleting an arm would change them
  together and the test could never red.
- **The activation tail is owed whenever ANYONE reloads, not only when
  `Apply` does (#6912).** `pkg/daemon` runs `networkctl reload` from
  several sites of its own and reports the result through
  `BeginReload`/`NoteReloadResult`. A SUCCESSFUL external reload genuinely
  discharges the reload obligation — the kernel really did re-read the
  directory — but performs none of the tail, which is the per-interface
  `networkctl reconfigure` that applies bond/VLAN addresses plus
  `restoreSlowPathRPFilter`. Only `Apply` can run those. Before #6912 the
  next unchanged `Apply` saw `changed==false`, no reload debt (correctly
  cleared), no reconfigure debt and no `activationPending`, skipped the
  whole block and returned nil — leaving addresses unreconfigured and the
  slow-path TUN's `rp_filter` at networkd's default, which silently drops
  locally-originated traffic. This is distinct from #5718, which covers a
  FAILED `Apply` whose debt a later external success clears; here nothing
  fails at any point, so the debt mechanism has nothing to carry.
  `NoteReloadResult` therefore arms a separate process-scoped `tailPending`
  on success, and only a completed tail clears it.
- **`Apply` is fail-closed on write errors (#2987).** `writeIfChanged`
  returns `(changed, err)`; `Apply` aggregates per-file write failures
  (still attempting every generated file), reloads whatever did change,
  then returns a non-nil error. The caller (`pkg/daemon/daemon_apply.go`
  step 2.5) captures this error and returns it at the tail of
  `applyConfigLocked` (mirroring `dhcpServerErr`), so a networkd write
  failure FAILS THE COMMIT (fail-closed) without skipping the downstream
  reconcile steps (RETH MAC, VRRP VIPs, FRR, RA, IPsec). A swallowed
  write (read-only `/etc`, full disk, EACCES, blocked path) used to report
  a clean commit against stale kernel state — a fail-open hole.
- **A failed stale-file DELETE also fails the commit (#4900).** The
  `10-xpf-*` stale sweep used to treat `os.Remove` failures as warn-only:
  a removed interface/address/bond/bridge/rename whose generated unit
  could not be deleted (read-only `/etc`, immutable bit, EACCES) survived
  a "successful" commit, and if no other generated file changed, `Apply`
  returned nil with no reload — so the surviving `.network`/`.netdev`
  re-applied the removed config on the next reload or boot (route leak /
  management surprise). `Apply` aggregates stale-remove
  failures alongside the write errors (still best-effort every delete,
  still reloading whatever DID change) and return a joined error, so a
  stale unit that cannot be removed FAILS THE COMMIT. Distinct from #2987
  (write failure) and #2988 (empty-set skip), neither of which surfaced a
  delete failure.
- **A failed reload/reconfigure owes activation debt (#4954).** The
  generated files are written to disk BEFORE `networkctl reload` runs, so
  a reload that fails leaves the kernel running the pre-failure config
  while the files on disk already match the desired state. Without state,
  an identical re-commit sees `writeIfChanged → (false, nil)` for every
  file (`changed==false`), skips the reload, and returns nil — a FALSE
  success masking a route leak / stranded NIC / management lockout. The
  A failed reload records the debt and re-runs the idempotent reload on
  the next activation pass even with unchanged files, clearing the debt
  only on success (and still returning the error until then). The
  per-interface `networkctl reconfigure` follow-up is best-effort
  (warn-only, Apply still returns nil) but is likewise retried from the
  `Manager`'s `reconfigurePending` set until it succeeds. Distinct from
  #2987 (write-error-fails-commit) and the stale-file sweep.
  **The TEARDOWN owes the same debt (#5718 A7-b01-C001).** Removing the
  managed files deactivates nothing until the reload lands, so a failed
  reload on the teardown path records the debt too, and the no-change
  case is NOT an unconditional `return nil`: with debt outstanding the
  files are already gone but the kernel never re-read them, so the next
  call re-runs the idempotent reload and reports failure until it
  succeeds. Without this the SECOND teardown found nothing to remove and
  reported a success it had not achieved while the removed addresses /
  VRFs / bonds / renames stayed live. `Apply` carries this via its
  `debtOwed := reloadDebtOutstanding()` re-activation, so `Apply(nil)`
  inherits it (#6852).
- **The reload debt has ONE holder and EVERY reload owner records into
  it (#5718 fold F2).** The debt is process-scoped (`reloadDebt` in
  `networkd.go`), not a `Manager` field, because `networkctl reload` acts
  on the single host `systemd-networkd` and this package is not its only
  owner: `pkg/daemon`'s `networkctlReload` runs it directly from FIVE
  production sites — linksetup's post-rename reload (warn-only),
  device-map's rename and teardown reloads, and bootstrap's teardown and
  lifeline reloads — all touching the same `10-xpf-*` files. A `Manager`-scoped
  bool left those owners unable to record anything, and the disagreement
  resolved in the dangerous direction: their failed reload left the files
  on disk unactivated while the flag stayed false, so the next `Apply`
  with identical content took the `changed==false && !debt` branch and
  reported the #4954 false success. `pkg/daemon` now brackets its
  shell-out with the exported `BeginReload` / `NoteReloadResult` pair,
  and `ReloadDebtOutstanding` lets it assert the POSTCONDITION of that
  reporting rather than the debt epoch — an epoch is unchanged both when
  a success is reported correctly and when reporting it is omitted
  entirely, so the epoch could not see a dropped success report or a
  `BeginReload()` moved after the shell-out (#5718 fold r4b).
  The per-interface reconfigure debt stays `Manager` state — it names the
  interfaces this Manager generated files for, and no other owner issues
  a `networkctl reconfigure`.
- **Discharging the debt is EPOCH-GUARDED, never a blind clear (#5718
  fold F4).** The epoch advances every time debt is recorded, and a
  successful reload may only clear the debt state it observed before it
  started. Otherwise a concurrent owner's failure is lost: owner B's
  reload re-reads the directory and succeeds, owner A then writes new
  files and its reload fails and records the debt, and B — still between
  its syscall and its bookkeeping — blind-stores `pending=false`. B's
  reload provably predates A's files, so nothing activated them, yet A's
  identical retry now sees `changed==false && !debt`, skips the reload
  and returns nil. A debt cleared whose work never ran is a silent skip
  of a reload the system believes it performed.
- **The reload debt is global; Apply's TAIL is not (#5718 fold r4).**
  Process-scoping the reload debt was right for the reload itself, but it
  collapsed two obligations into one flag. "The kernel re-read the
  directory" is global — any owner's successful `networkctl reload`
  discharges it. Apply's activation pass also has a tail only Apply can
  run: the per-interface `networkctl reconfigure` that applies bond/VLAN
  addresses, and `restoreSlowPathRPFilter`. Both sit behind
  `needReload`. So when Apply's own reload FAILED (returning early,
  before the tail, and therefore recording no reconfigure debt) and
  `pkg/daemon` then ran a successful reload, the global debt cleared and
  the next unchanged Apply skipped the block entirely — addresses never
  reconfigured, `rp_filter` left at networkd's default, silently
  dropping locally-originated traffic via the slow-path TUN, and `nil`
  returned. `Manager.activationPending` is set when Apply enters the
  pass and cleared only after the tail completes, so no other owner can
  discharge it.
- **The write/remove-error path owes the tail too, and did not ARM it
  (#5718 fold r7).** This paragraph used to end "the write-error path is
  unaffected: it always returns a non-nil error, so it can never report a
  false success", and that reasoning is what produced the bug. The error
  return is truthful for THAT Apply. What it does not do is record the
  obligation for the NEXT one: `activationPending = true` had a single
  assignment, in the success path, which the error branch returns before
  reaching — the tail was never armed, not merely skipped. The branch does
  arm the GLOBAL debt, and any reload owner discharges that. So a
  device-map teardown that removes the offending stale marker and reloads
  successfully clears the global debt while performing neither tail
  operation, and the byte-identical Apply that follows sees no change, no
  global debt, no reconfigure debt and no activation debt — and returns
  `nil` having run neither the per-interface `reconfigure` nor
  `restoreSlowPathRPFilter`. The error branch now arms `activationPending`
  before its own reload attempt, and deliberately does NOT clear it when
  that reload succeeds: the reload is half the tail, and the reconfigure
  half still has not run.
- **The debt does not survive the PROCESS (#5718 fold r7, disclosed not
  fixed).** `reloadDebt` is a package variable, so a daemon restart
  between a failed reload and its retry drops the obligation with the
  generated files sitting on disk unactivated — the LOST direction. This
  is not a regression: the pre-PR `Manager.reloadPending` field had exactly
  the same process lifetime, and making it durable means persisting it
  outside the process, a larger change than this one. It is recorded here
  because a reader just told the debt has "ONE holder" and is
  "process-scoped" can reasonably read that as a durability claim, and it
  is not one.
- **`Manager.Clear()` was RETIRED (#6852).** It had been exported and
  uncalled since this package was introduced (`git log -S` found no
  caller in history); the daemon uses only `SetProtectedResolver` and
  `Apply`. #5718 left the choice open — wire it or retire it — and the
  answer is retire, for a reason stronger than "nothing calls it":

  `Apply(nil)` already carries every contract `Clear` owned. It runs the
  `10-xpf-*` stale sweep, aggregates remove failures and fails the
  commit (#4900), and re-activates whenever files changed OR prior
  reload debt is outstanding (#4954) — which subsumes `Clear`'s
  empty-glob debt-discharge branch. That is not asserted, it is
  measured: `Clear`'s own four-step fail-on-revert
  (`applynil_reload_debt_5718_test.go`) was MOVED onto `Apply(nil)` and
  passes unchanged. A retirement whose tests were deleted rather than
  moved would have proved only that nobody was looking.

  Wiring it would have been actively WORSE. `Clear` globbed and removed
  every `10-xpf-*` file including the `SetProtectedResolver` lifeline
  ones, which `Apply(nil)` deliberately preserves. Any teardown that
  called `Clear` would have taken the management lifeline down with the
  managed config.
- **An empty desired set is NOT a no-op (#2988).** `Apply(nil)` (last
  managed interface removed) still runs the `10-xpf-*` stale-file sweep
  and requests a reload so old addresses/bonds/bridges/renames don't
  resurrect — while preserving the `SetProtectedResolver` lifeline files.
  The daemon caller (`daemon_apply.go` step 2.5) invokes `Apply` whenever
  the dataplane returned a result, NOT only when the managed set is
  non-empty — the old `len(ManagedInterfaces) > 0` guard shadowed the
  sweep on the live reconcile path. The lifeline stays protected
  end-to-end: `resolveProtectedInterfaces` derives the mgmt set from
  `ActiveConfig`, independent of the managed-interface set.
