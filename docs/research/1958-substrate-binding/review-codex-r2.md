# #1958 plan v2 — Codex hostile re-review (round 2)

Reviewer: Codex (gpt-5.4, read-only). Plan @ 5037bfe35 (v2).

## Verdict: PLAN-READY

- FOLD 1 (§6.2 VMBus/XenBus): **Yes, closed.** PCI-empty is no longer a
  classifier; a Hyper-V/Azure/AWS-Xen guest reaches vmHeuristic first via
  /sys/hypervisor/type or the CPU hypervisor flag, so the PCI-empty/veth hint
  cannot flip it to container. Explicit platform-profile makes detector error
  recoverable.
- FOLD 2 (§7 lifeline fail-safe): **Yes, if implemented exactly as written.**
  Protected set = boot-recorded lifeline UNION declared mgmt contract; the
  reconcile (compiler_iface.go:1124) skips it before unmanaged strip/down.
  Empty set valid only when detectLifelineInterface found no default route.
- New second-order (non-blocking): (a) the implementation must NOT preserve
  the old fxp0-narrowing exception against the lifeline contribution; (b)
  non-PCI lifelines need a MAC/kernel-name record path if the invariant is
  meant beyond PCI bare metal. [Both folded into v3 §7.]

VERDICT: PLAN-READY
