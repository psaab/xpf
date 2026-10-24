# pkg/factoryreset

The shared factory-reset (zeroize) wipe: the full owned-artifact erasure
both entry points run — gRPC `SystemAction{zeroize}` (via
`pkg/grpcapi`'s `runZeroize`, through the daemon apply/terminal-reset
gate) and the interactive console `request system zeroize` (via
`pkg/cli`, through the same daemon transaction when wired). Extracted
from `pkg/grpcapi` in #16138 so the CLI no longer reaches back into the
gRPC package; clean cutover, no aliases kept in `pkg/grpcapi`.

## Entry points

- `PerformZeroizeWipe` — direct wipe with no log inventory (legacy/test).
- `PerformZeroizeWipeWithLogInventory` — crash-aware wipe with the
  pre-wipe configured firewall-log inventory (`LogInventory`, derived by
  `ZeroizeLogInventoryFromConfig` from the active config BEFORE the wipe
  erases the files the names come from).
- `PerformZeroizeWipePending` — gated path: records a PENDING reset
  handoff; the daemon flips it clean only after post-verification.
- `PerformZeroizeWipeUngated` — no-daemon path: erases and verifies the
  helper state file itself and completes clean in-wipe.
- `PerformZeroizeWipePendingWithInventory` — the gated pending entry
  `pkg/grpcapi`'s closure dispatches to (statically bound).
  `Completion`/`PendingCompletion` let that caller construct the
  pending completion. There is no dispatch variable in this package
  (#16138 fold-2): every `Perform*` entry calls the plain
  `performWipeWithLogInventory` func directly, and tests intercept at
  their own call-site seams (e.g. grpcapi's `zeroizePendingWipe` var),
  never inside factoryreset.
- `RedirectWipePathsForTesting` — redirects every filesystem path and
  command seam the wipe touches into a throwaway root (test-only).

## Invariants (do not move blindly)

- Sequencing stays with the callers: log-first journaling, then the
  daemon apply/terminal-reset gate, then this wipe, then partial-wipe
  reporting and the daemon stop. This package only erases.
- Configured archive/root validation (`configstore.ResolveFactoryResetRoot`,
  `FactoryResetArchiveDir` ownership) and the gated-vs-ungated
  distinction are load-bearing; see `pkg/grpcapi/README.md` for the
  gRPC-side sequencing and `pkg/cli` for the console twin.
- The wipe is hermetic under test only via the path seams above; every
  leg's default target is a real host path.
- The #10769 image-seal legs (`wipeImageSealResidue`) erase host-owned
  state (root `.ssh`, `/var/log`, `/tmp`, machine-id, hostname, …) ONLY
  on an appliance host — the bake-written `/etc/xpf/appliance` marker
  (`wipeIsApplianceHost`, #16448). A foreign-host `.deb` install keeps
  host-owned files; only xpf-owned state (and xpf-owned
  `/etc/resolv.conf`) is erased there, and root revocation falls back to
  the marker-aware `wipeRootLoginAccount`. `RedirectWipePathsForTesting`
  plants the marker by default so hermetic fixtures assert the appliance
  contract; foreign-host cells remove it.

Performance: operator-triggered maintenance path, no hot-path impact.
