# Claude-SMR plan review r2 — #1715 (reviewing plan r3)

Reviewer: Claude (domain SMR). Posture: hostile-verify.

**Verdict: PLAN-READY.**

Round 1 (all three reviewers PLAN-NEEDS-MAJOR) converged on: drop the
hybrid for real, centralize on one locked reconciler, fix the DHCP
callback so mgmt-only interfaces still reconcile DNS, and stop
over-claiming boot-time DNS. Plan r3 addresses every round-1 finding.

## Round-1 findings → r3 disposition (verified)

- **F1 hidden third owner / contradictory hybrid (Codex caught the
  residual §6.4 + AC#6 hybrid language).** r3 §6.4 now deletes
  `applyDNSService`, makes `reconcileDNS` always disable+mask resolved
  regardless of `DNSEnabled`, and turns `system services dns` into a
  commit-check WARNING beside the existing `dns-proxy` warning. AC#6
  rewritten to "no resolved branch." CLOSED.
- **F2 async write race + lock contract (Codex).** r3 §5b.3 specifies
  the non-reentrant two-function contract: `reconcileDNSLocked(cfg)`
  (caller holds `applySem`, called from `applyConfigLocked`) vs
  `reconcileDNSFromDHCP()` (acquires once). Explicit "MUST NOT
  re-acquire / MUST NOT double-acquire." CLOSED.
- **F2/F4 DHCP-callback skips DNS on mgmt-only (Codex, the fw0 class).**
  r3 §5b.3 mandates calling `reconcileDNSFromDHCP()` on EVERY address
  change in BOTH callback branches, not just the recompile branch.
  CLOSED — this was the sharpest catch; fxp0 is precisely the
  management-only interface that the old `else` branch
  (`applyMgmtVRFRoutes`, daemon_dhcp.go:45-46) skips.
- **F3 dual-stack clobber.** Closed by the central merge from
  `Leases()`. r3 keeps the static>v4>v6 dedup invariant. The
  `Leases()` shallow-copy note (lease must stay immutable after store)
  is a valid implementation caveat — captured in r3 test plan
  (`-race`). CLOSED.
- **F4 false boot invariant (Codex).** r3 §5b.4 replaces "repairs
  before anything needs DNS" with an explicit empty-merge policy:
  repair only a dangling/stub symlink, never clobber a good file, never
  assert boot-time DNS for a DHCP-only box. CLOSED — false invariants
  are worse than missing ones; r3 no longer asserts it.
- **v4 overclaim (Codex).** r3 corrects: v4 DNS is already extracted
  into `lease.DNS` (`dhcp.go:657`); the only "gap" was that no v4 path
  called the file writer — which r3 removes entirely. CLOSED.
- **Stale r1 test (Codex).** r3 test plan replaces the `installDNS`
  symlink test with reconciler/empty-merge/lock-contract/DHCP-callback
  tests. CLOSED.
- **Exact systemd ops + same-dir temp (Codex).** r3 specifies
  `disable --now` + `mask`, warn-on-failure (no silent second owner),
  and temp file in `/etc` + Lstat + Remove + Rename. CLOSED.

## Residual nits (non-blocking, for /engineer)
- Decide the empty-merge file body: comment-only managed file vs a
  minimal `nameserver` fallback. Recommend comment-only ("# managed by
  xpfd; no nameservers configured") so it is a valid non-dangling file
  without injecting a wrong resolver. Pin at implementation.
- `mask` is sticky across reboots; ensure an operator who later wants
  resolved (separate future PR) has an `unmask` path. Document.
- Confirm `reconcileDNSFromDHCP` debounce: the existing callback is
  already debounced 2s (`dhcp.go:101`), so no new debounce needed.

## Bottom line
The diagnosis was verified by all three reviewers with quoted lines.
r3's pure-Option-A single-locked-reconciler design closes F1-F4 and the
implementation-readiness gaps. PLAN-READY. Coordinate with #1713:
sequence #1713 (renderer extraction + Domains= fix) first; #1715 builds
`RenderResolvConf` + `reconcileDNS` on that seam (absorbing #1713 if not
yet landed).
