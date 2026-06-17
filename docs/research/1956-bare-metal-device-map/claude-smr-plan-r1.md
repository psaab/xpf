# Claude SMR hostile plan-review — #1956 r1

Reviewing `plan.md` @ this commit as domain SMR + systems-design adversary.
Goal: fail the plan if the architecture is wrong, the identity key is
fragile, or it breaks the #1922 lifeline.

## Verdict: PLAN-READY (with two MINOR must-fix before /engineer)

The architecture is sound, the identity key is right, and the plan composes
with — does not fight — #1922. The MVP scoping is honest. I have two minor
corrections and several non-blocking notes.

## What's right (verified against code)

- **PCI-primary + permanent-MAC-fallback is the correct key.** It is
  literally the discipline #1922 already settled on
  (`resolveLifelineCurrentName`, `bootstrap.go:382-392`, PCI-first then
  MAC). Reusing one resolution ladder is the right call and avoids a second,
  divergent identity story.
- **The F2 fix (`unmapped-interface-policy leave-alone`) is the real
  payload.** I confirm the danger is concentrated in
  `compiler_iface.go:1166-1187`: unconfigured non-protected NICs are
  unconditionally appended `Unmanaged`, addr-stripped, and `LinkSetDown`.
  Gating that loop on policy is the minimal, correct intervention.
- **Config-presence mode selection** is backward-compatible and matches the
  existing #1922 pattern of behavior keyed on on-disk/config state rather
  than a separate mode flag.
- **The issue-framing correction (§1.1)** is correct and important:
  `assignName` only emits `em0` under `clusterMode` (`linksetup.go:214`);
  the issue body's unconditional idx1→em0 is wrong. A plan that copied the
  issue verbatim would have mis-modeled standalone bare metal.

## MINOR-1 (must-fix): the bring-down loop runs on EMPTY/rolled-back configs

The plan says the compiler reconcile honors `unmapped-interface-policy
leave-alone`, but `compiler_iface.go` runs the bring-down loop driven by the
ACTIVE config. On a rolled-back / empty / bootstrap-exit transient, the
active config may carry NO device-map even though the operator intends
device-map mode. The plan must specify: when does `leave-alone` apply if the
device-map momentarily isn't in the active config? Recommend: the
`unmapped-interface-policy` resolution must be config-independent in the same
way the #1922 protected set is — OR explicitly state that losing the map
reverts to `manage-down` (claim-all) and that this is acceptable because the
protected lifeline still shields mgmt. Pick one and write it down; today the
plan is silent and that's the exact class of bug #1922 r1 caught (empty-tree
compiles to non-nil config → wrong takeover).

## MINOR-2 (must-fix): SR-IOV VF PCI-address stability is unstated

The loss cluster's dataplane NICs are mlx5 SR-IOV VFs (CLAUDE.md). VF PCI
addresses (`0000:08:00.X`) can reorder across `sriov_numvfs` rewrites or
host reboots depending on the PF's VF-enable order. The plan claims PCI is
"stable across reboot" — true for PFs, weaker for VFs. The plan should note
that for VF-backed deployments the MAC fallback (or a future topology-path
key) carries more weight, and that the bare-metal MVP's primary target is
PF/onboard NICs where PCI-addr is genuinely durable. Not a blocker for the
design, but the stability table (§3) overstates the VF case.

## Non-blocking notes

- **N1.** §7 "missing NIC → WARN not FATAL" is the right call for shared
  per-node configs, and it matches `compileTreeLenient` tolerance
  (`docs/config-schema.md`). Good.
- **N2.** `show chassis device-map candidates` (§9.2) should arguably be in
  the MVP, not deferred — without it the operator hand-copies PCI addresses
  from `lspci`/sysfs, which is error-prone and the #1 source of the "missing
  NIC" warning. Cheap to build (reuses `enumeratePCINICs`). Recommend
  promoting to MVP, but not a blocker.
- **N3.** The plan should state that `enumerateAndRenameMapped` must still
  write the bootstrap fxp0 `.network` when fxp0 is mapped (§6.4 mentions it;
  make it an explicit MVP item, not prose).
- **N4.** Interaction with `findExternallyManaged` (`networkd.go`): a
  `leave-alone` NIC that the operator ALSO has a non-`10-xpf-` `.network`
  for is doubly safe; confirm the two paths don't conflict (they shouldn't —
  both leave it alone). Worth a sentence.
- **N5.** Collision validation (§7) is cross-entry; confirm it runs on the
  strict commit path only (`SchemaValidate`) and downgrades to warn on
  lenient ingest, consistent with the rest of the schema.

## Why not PLAN-KILL

The full device-map is correctly de-scoped to the hybrid allowlist MVP; the
plan does not over-build a from-scratch naming engine. The identity key is
the one the codebase already trusts. The #1922 composition is explicit and
correct (union, never override). The two minor issues are specification
gaps, not architectural defects.
