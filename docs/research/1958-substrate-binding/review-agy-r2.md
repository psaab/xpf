# #1958 plan v2 — AGY adversarial re-review (round 2)

Reviewer: AGY. Plan @ 5037bfe35 (v2). Job: adversarial-review-mqid5hjs-1csvds.

## Verdict: PLAN-NEEDS-MAJOR (three second-order catches, all folded in v3)

- Catch 1 — ARM64 / hidden-CPUID VM detection: vmHeuristic relies on the
  x86 CPUID hypervisor flag + /sys/hypervisor/type, both ABSENT on ARM64
  guests (Graviton, Azure-ARM, GCP-T2A, Apple-Silicon QEMU) and on plain
  KVM/Hyper-V/VMware. Such a VM returns "" → misclassified bare-metal or
  (via PCI-empty hint) container → console-only/delegate default → no
  bootstrap DHCP .network → total mgmt lockout on first boot.
  Mitigation: add systemd-detect-virt (bare, cross-arch DMI/SMBIOS) to the
  VM-detection ladder. FOLDED v3 §6.2.
- Catch 2 — lifeline record is PCI-dependent: setupBootstrapLifeline only
  persists the record when pciAddrForInterface returns ok (bootstrap.go:465);
  a veth or VMBus/XenBus NIC (no PCI) is never recorded, so
  resolveLifelineCurrentName returns ("",false) and the "unconditional"
  protection is NON-FUNCTIONAL on exactly the non-PCI substrates the umbrella
  targets. Mitigation: persist a MAC/kernel-name lifeline identity when no
  PCI exists; resolve via MAC/name. FOLDED v3 §7 (Codex r2 independently
  flagged the same).
- Catch 3 — no override for a stale boot lifeline: a box that booted with a
  temporary DHCP route on eth0 records eth0 as the unconditional lifeline;
  the operator can't repurpose eth0 as a dataplane port (no CLI to clear
  /etc/xpf/lifeline-interface). Mitigation: explicit force-release-lifeline
  override leaf. FOLDED v3 §7.

VERDICT: PLAN-NEEDS-MAJOR
