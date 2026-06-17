# #1958 plan v2 — Claude SMR hostile review (round 2)

Reviewer: Claude (domain SMR). Plan @ 5037bfe35. Re-reviewing the two AGY r1
folds + the three SMR folds.

## Verdict: PLAN-READY

Both AGY folds are correct and adequate; the architecture is unchanged. The
remaining items are /engineer-time confirmations, not plan defects.

## Fold 1 (§6.2 detector VMBus/XenBus) — ADEQUATE

The fix is the right shape: positive container signals are the only
authoritative container tell, `vmHeuristic` runs before the demoted PCI-empty
hint, and PCI-empty can never override a VM classification. This closes the
Hyper-V/Xen-VM-running-Docker misclassification because such a VM trips
`vmHeuristic` (the `/proc/cpuinfo` hypervisor flag is set by KVM, QEMU,
VMware, **Hyper-V, and Xen HVM** guests — `host_tunables.go:148-162` already
keys on exactly that token). Residual (named in OQ-1): Xen *PV* guests
historically may not set the cpuinfo hypervisor flag, but they DO expose
`/sys/hypervisor/type=xen`, which `vmHeuristic` checks first
(`host_tunables.go:129-133`). So both PV and HVM Xen are covered. ADEQUATE;
the /engineer confirmation is to validate on the actual target kernels, which
the plan already calls out.

## Fold 2 (§7 lifeline fail-safe) — ADEQUATE and is the more important fix

This is the correct resolution and actually *simplifies* the safety story:
safety no longer depends on the operator declaring the contract correctly,
because the boot-recorded #1922 lifeline is the unconditional backstop. This
is exactly the #1922 invariant 3 (`protectedInterfaces` is
config-independent, `bootstrap.go:401-403`), so the fold is consistent with
the existing machinery rather than fighting it — the contract can only ADD
protected NICs, never remove the boot lifeline. The one genuinely-empty case
(no default route at boot) is the true console-attached box where there is no
remote lifeline to lose. Sound.

## New second-order issue check — none material

I looked for a fold-induced regression:
- Does "lifeline always protected" conflict with #1956 §9.6's "no auto-fxp0
  on bare metal"? No — §9.6 is about not *fabricating* an fxp0 / not grabbing
  a NIC for a mgmt plane the operator never asked for; the boot-recorded
  lifeline is a NIC that ALREADY carries the operator's default route (they
  are demonstrably reaching the box on it). Protecting it is not fabrication.
  The two are consistent.
- Does the detector-is-advisory invariant conflict with the fold-1 priority
  ordering? No — the priority ordering only picks a *default*; an explicit
  `platform-profile` always wins, including forcing `vm` on a box the hint
  would have called container.

## SMR folds (1-3) self-check — applied correctly

- Fold 1 (§5.3 audit list): the name-prefix sites are listed with the
  benign-absence rationale; Codex's exhaustive grep is cited. Good.
- Fold 2 (detector-advisory invariant): stated in §6.2. Good.
- Fold 3 (binding-delivery in §2.1): two-phase (injected file first-boot,
  configstore thereafter), justified by container `delegate` reachability
  removing the first-commit chicken-and-egg. Good.

## Conclusion

PLAN-READY. The umbrella model (binding/config split + three pluggable axes +
A→B→C slicing) is validated; both critical catches are closed without
disturbing the architecture.
