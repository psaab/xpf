# #1958 plan — AGY adversarial plan review (round 1)

Reviewer: AGY (antigravity-cli). Plan @ 33a1d9de4.
Job: adversarial-review-mqicx5fe-e670b0.

## Verdict: PLAN-NEEDS-MAJOR (two catches, both folded in v2)

- Attack 1 (binding/config split): **load-bearing, not hand-waving.** Confirmed.
- Attack 2 (alias de-risking): **true for sub-mode (a); sub-mode (b) is the
  trap and is correctly deferred.** Confirmed.
- Attack 3 (substrate detector false-positive): **CRITICAL.** The "PCI-empty
  + veths" container tell false-positives on Hyper-V/Azure (VMBus, hv_netvsc)
  and AWS-Xen (XenBus, xen-netfront) VMs — those VMs have no PCI NICs, so
  enumeratePCINICs returns empty there too. A Hyper-V VM running Docker would
  be misclassified container → rename:no + delegate → VM provisioning breaks.
  FOLDED v2 §6.2: positive container signals authoritative; vmHeuristic runs
  before the PCI-empty hint (it detects VMBus/XenBus VMs via the hypervisor
  flag); PCI-empty demoted to a non-authoritative hint.
- Attack 4 (A->B->C ordering): **sound, no hidden dependency.** Confirmed.
- Attack 5 (reachability contract breaks SAFE-BOOTSTRAP): **CRITICAL lockout.**
  v1's "empty protected set for console-only/delegate" lets a bad commit down
  + strip the lifeline NIC the operator reaches the box on; rollback writes no
  backup .network so the operator is permanently locked out. FOLDED v2 §7
  CRITICAL FAIL-SAFE: the #1922 boot-recorded default-route lifeline is
  UNCONDITIONALLY protected regardless of contract; empty protected set only
  on a box with no default route at boot (truly console-attached).

VERDICT: PLAN-NEEDS-MAJOR
