# Codex hostile plan-review — #1956 r2

## VERDICT: PLAN-NEEDS-MAJOR

Re-review of v2 against r1 findings.

**R-1: PARTIALLY-RESOLVED.** v2 requires PCI + permanent-MAC match to bind
and refuses a PCI/MAC mismatch (plan.md:387). Closes silent slot-hijack only
when `PermHWAddr` is present; `getPermAddr` returns "" when netlink lacks
`PermHWAddr` (compiler.go:1623). v2 says that disables MAC fallback but does
NOT say what happens to the PCI-primary topology cross-check when perm-MAC is
empty. VF handling adds `key mac` (plan.md:394) but the grammar/struct preview
still lists only `pci`/`mac` and `LogicalName,PCIAddr,MAC` (plan.md:263,276).
BLOCKER: specify PCI-match + empty-perm-MAC behavior; add the key-order field
to the grammar/types.

**R-2: STILL-OPEN.** udev applies stale `.link` rules BEFORE xpfd starts; the
daemon-start scrub happens AFTER that window (startup rename at
daemon_run.go:336,345; `.link` matches `OriginalName=` at linksetup.go:270).
Scrub-then-rewrite fixes disk state for the NEXT boot but does not undo a wrong
LIVE rename already applied by udev, nor free an occupied logical name (EEXIST).
BLOCKER: add pre-udev cleanup or explicit live stale-rename correction
(multi-pass temp-rename) before mapped renames.

**R-3: RESOLVED.** Plan explicitly rejects reusing the lifeline resolver and
requires a new permanent-MAC resolver (plan.md:416); lifeline records/resolves
the RUNNING MAC (bootstrap.go:357,387), getPermAddr reads PermHWAddr
(compiler.go:1623). Absence is made commit-visible (plan.md:418).

**R-4: RESOLVED.** Both rename sites identified (daemon_run.go:345 normal,
:1557 bootstrap-exit); v2 requires both to branch to enumerateAndRenameMapped
(plan.md:423). Closes the day-0 first-commit positional takeover.

**R-5: PARTIALLY-RESOLVED.** networkd.Apply sweeps all unexpected `10-xpf-*`
files (networkd.go:133) and reloads (networkd.go:185). The one-shot teardown
can compose IF it runs under the apply lock BEFORE networkd.Apply, because the
compiler otherwise still appends unmanaged, strips addresses, and downs links
(compiler_iface.go:1165,1172). The plan does not pin that ordering or the state
source for "previously managed". BLOCKER: define the teardown hook order
relative to compile and d.networkd.Apply (daemon_apply.go:624).

**R-7: RESOLVED.** compileChassis returns when cluster absent
(compiler_system.go:879); v2 requires independent device-map compilation +
mode selection by len(Entries)>0 (plan.md:462). Schema machinery supports the
typed instance-key path via keyValueType/keyValidator (schema.go:76,
schema_walk.go:289).

**R-8: STILL-OPEN.** Commit-time reject is implementable (strict commit-check
runs before promotion, store.go:1034,1174). But rollback-into-claim-all is NOT
caught by validating only the proposed map: CommitConfirmed preserves the
previous config as rollback target (store.go:1197) and the daemon
auto-applies it (daemon_apply.go:226), while v2 defines absent map as
positional claim-all (plan.md:489). CLI has no `force` bit
(cli_config.go:176); the rollback target goes unvalidated. BLOCKER: preflight
must evaluate the commit-confirmed rollback target, not just the candidate map.

## Remaining blockers
- R-2: current-boot stale `.link`/udev misrename window (scrub fixes next boot only).
- R-8: does not catch automatic rollback into absent-map positional claim-all.
- R-1: empty-PermHWAddr under PCI-primary cross-check unspecified; key-order field absent from grammar/types.
- R-5: teardown ordering relative to networkd.Apply undefined.
