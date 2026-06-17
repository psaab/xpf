# Claude SMR hostile plan-review — #1956 r3

Reviewing plan.md v3 (with §14 r2 disposition). I explicitly re-verified the
two findings I MISSED in r2 (the HA-sync and rollback-target gaps the
companions caught), and confirmed the v3 resolutions are code-grounded.

## Verdict: PLAN-READY

v3 closes every r2 blocker, and the resolutions are anchored to verified code
sites. I also concede my r2 PLAN-READY was premature — I did not trace the
`compileTreeLenient` SyncApply path nor the `executeConfirmedRollback`
auto-apply, both of which the companions correctly flagged.

## Re-verification of the r2 findings (the ones SMR r2 missed)

- **V-1 (HA peer-lockout):** CONFIRMED real. `SyncApply` uses
  `CompileConfigForNodeLenient` (compiler.go:159-166) which downgrades the
  strict gate to a warning (store.go:232, freetext.go:28). A node-0 commit
  cannot fail on node-1's hardware, and node-1's lenient ingest persists the
  hazard. v3's resolution — a NARROW passive-node SyncApply admission gate
  scoped to the management-lockout class only — is the right shape: it does
  NOT make SyncApply broadly strict (which would reintroduce the HA-sync-loop
  hazard lenient ingest exists to prevent), it carves out the one class that
  must never be silently swallowed, mirroring the #1922 config-independent
  lifeline precedent. Sound.
- **V-3 (rollback target unvalidated):** CONFIRMED real.
  `executeConfirmedRollback` (daemon_apply.go:222) applies `PromoteRollback`'s
  previous config under applySem WITHOUT a strict re-check; there is no
  `force` bit in the CLI (cli_config.go:176). v3 validating BOTH candidate and
  rollback target at commit-confirmed time, plus a teardown safety check in
  `executeConfirmedRollback` itself (matching the existing #1922
  first-commit-rollback conservative branch at daemon_apply.go:232), closes
  it. Sound.

## Check of the other v3 resolutions

- **V-2 (udev/EEXIST):** The collision-safe multi-pass temp-rename is the
  textbook fix for a rename cycle, and v3 is HONEST that it does not claim
  zero live-misrename — only deterministic convergence + no EEXIST deadlock,
  with #1922 shielding mgmt through the window. Acceptable; the residual
  one-boot window is inherent to udev-runs-before-daemon and cannot be fully
  eliminated without a udev-rule-generation approach (correctly deferred).
- **V-4 (teardown ordering):** Pinning the teardown BEFORE `networkd.Apply`
  with the `10-xpf-*.link` glob as the "previously managed" state source
  (not the absent config) is correct and removes the half-clean race.
- **V-5 (empty-PermHWAddr + key field):** PCI-only-unverified binding with a
  loud `show` marker + commit-reject of `key mac` when no perm-MAC exists is
  the right degradation. The added `KeyOrder` field closes the grammar gap.
- **V-6 (general FPC validation + udev name discovery):** Generalizing the
  FPC/node-id alignment check to ALL mapped names (not just RETH) is correct;
  discovering the predictable name via the udev database rather than guessing
  is the right call.

## Residual notes (non-blocking, for the implementation PR)

- **N1.** V-1's passive-node admission gate is the subtlest piece: it must
  reject ONLY the device-map delta's lockout class, not the whole sync, or it
  reintroduces an HA-sync stall. The implementation PR must unit-test the
  "peer syncs a self-lockout map → alarm + refuse, but the rest of the config
  applies" path explicitly.
- **N2.** V-3's commit-confirmed path now validates two configs; ensure the
  rollback-target validation uses the SAME node-local hardware resolution as
  the candidate (not a stale snapshot).
- **N3.** The feature is now large enough that the implementation should be
  staged into reviewable increments (grammar+compile+validation; rename
  engine + teardown; HA-sync gate + rollback validation; show/candidates),
  each independently smoke-tested — flag for /engineer to sequence.

## Why PLAN-READY now

Three rounds drove the plan from a glossy "quick MVP" to an honest,
code-grounded, multi-part feature whose every safety edge is tied to a
verified code site. The identity key is durable for the primary target with
loud handling of the cases it isn't; the #1922 lifeline composition is
preserved AND extended to the HA-sync and rollback paths the first two
versions missed. No architectural defect remains. Ready for manual approval.
