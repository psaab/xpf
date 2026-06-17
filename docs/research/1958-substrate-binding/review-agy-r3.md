# #1958 plan v3 — AGY adversarial re-review (round 3)

Reviewer: AGY. Plan @ b6a2c3b00 (v3). Job: adversarial-review-mqidac11-5zdair.

## Verdict: PLAN-READY (converged)

All three r2 second-order catches verified closed; no new first/second-order
defect.

- Fold 1 (§6.2 ARM64/cross-arch): the VM-detection ladder vmHeuristic ->
  systemd-detect-virt -> demoted PCI-empty hint closes the lockout.
  systemd-detect-virt queries DMI/SMBIOS (mandatory on SBBR/SBSA ARM64) +
  device-tree (/proc/device-tree/hypervisor/compatible) and reliably returns
  kvm/qemu/microsoft/amazon/xen with exit 0 on ARM64 guests. Container-first
  ordering keeps nested netns correctly classified.
- Fold 2 (§7 non-PCI lifeline): generalizing lifelineRecord to
  pci -> perm-mac -> kernel-name fully closes the gap. veth MACs are valid and
  netns-lifetime-stable; per-netns isolation removes collision risk;
  kernel-name is the reliable backstop when MAC is absent/unstable.
- Fold 3 (§7 force-release-lifeline): clean, auditable escape hatch; preserves
  safe-by-default while allowing deliberate repurposing of a bootstrap NIC.

Conclusion: architecture ready; three clean incrementally-shippable slices
(A bare-metal device-map, B container alias-mode, C substrate detector).

VERDICT: PLAN-READY
