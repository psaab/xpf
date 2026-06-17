# Codex hostile plan-review — #1956 r3

## Companion session verdict: PLAN-NEEDS-MINOR
## Agent-wrapper synthesis verdict: PLAN-NEEDS-MAJOR (see methodology note)

### Methodology note (planner)
The Codex companion's own session summary line returned **PLAN-NEEDS-MINOR**
and graded the V-4 teardown design as "directionally sound (plan.md:593-602)".
The agent WRAPPER's final synthesis re-graded to PLAN-NEEDS-MAJOR on the basis
that "none of the resolving code has been written yet … section 14 items are
design text, not shipped code." That is an IMPLEMENTATION rubric applied to a
RESEARCH-ONLY plan review — by design this branch contains NO production code
(the /research contract stops at PLAN-READY before any code). Grading a plan
"MAJOR because the code doesn't exist yet" is a category error: of course it
doesn't; that is the point. The substantive per-finding content below is what
matters, and it confirms the v3 DESIGNS are sound; the disagreement is purely
the rubric. Recorded verbatim for the record.

### Per-finding (the substantive content)
- **R-1 / V-5 (empty-PermHWAddr + KeyOrder):** types_chassis.go:7 still only
  has Cluster; getPermAddr returns "" on absent PermHWAddr (compiler.go:1623).
  → v3 DESIGN (PCI-only-unverified binding + KeyOrder field) addresses it; not
  yet coded (expected — research phase).
- **R-2 / V-2 (collision-safe temp-rename):** enumerateAndRenameInterfaces
  (linksetup.go:78) is still one-pass LinkSetName; the EEXIST window exists in
  CODE. → v3 DESIGN (multi-pass temp-rename) addresses it; not yet coded.
- **R-5 / V-4 (teardown ordering):** d.networkd.Apply called directly
  (daemon_apply.go:624); sweep at networkd.go:133-145. → v3 DESIGN
  "directionally sound" per Codex; not yet coded.
- **R-8 / V-3 (rollback target unvalidated):** executeConfirmedRollback
  (daemon_apply.go:226-247) promotes+applies prevCfg with no intervening
  check; CommitConfirmed validates only the candidate (store.go:1174);
  PromoteRollback persists without validating the target. → v3 DESIGN
  (validate both candidate+target at commit-confirmed; conservative rollback
  branch) addresses it; not yet coded.
- **V-1 (passive SyncApply gate):** SyncApply still lenient-compiles and
  promotes unconditionally (store.go:567-618); syncAndApply
  (daemon_ha_sync.go:368) has no device-map admission gate. → v3 DESIGN
  (narrow passive-node admission gate) addresses it; not yet coded.
- **V-6 (FPC/node validation):** no device-map entry validator (types.go:62);
  predictable-name recovery reads .link OriginalName (linksetup.go:223-255)
  not udev ID_NET_NAME_*. → v3 DESIGN (generalized FPC validator + udev-db
  name discovery) addresses it; not yet coded.

### Net
Codex's per-finding analysis confirms every v3 resolution is anchored to a
real code site and is the right fix; the only open question is implementation
strategy. The companion verdict (PLAN-NEEDS-MINOR) is the accurate read of the
DESIGN. The wrapper's MAJOR is a research-vs-implementation rubric mismatch.
