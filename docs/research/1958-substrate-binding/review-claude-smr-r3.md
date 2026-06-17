# #1958 plan v3 — Claude SMR hostile review (round 3)

Reviewer: Claude (domain SMR). Plan @ b6a2c3b00. Confirming the three AGY r2
folds + checking for a third-order regression.

## Verdict: PLAN-READY

The v3 folds are correct and the plan has converged. AGY's two-rounds-deep
catches were the genuinely subtle bits of an interface-bring-up change and are
now all closed; I find no new first/second-order defect.

## r2 fold A (§6.2 ARM64 / cross-arch VM detection) — ADEQUATE

`systemd-detect-virt` is the right cross-arch tool: it queries DMI/SMBIOS and
arch-specific signals and returns `kvm`/`qemu`/`microsoft`/`amazon`/`xen`
regardless of x86-vs-ARM64, so it closes the ARM64-VM-misclassified-as-
container/bare-metal lockout. The ladder ordering (vmHeuristic → detect-virt →
PCI-empty hint) is correct: the cheap in-process checks first, the subprocess
fallback second, the weak hint last. Residual (named OQ-1): validate the exact
`systemd-detect-virt` output strings on the target images at /engineer — but
the mechanism is sound.

## r2 fold B (§7 non-PCI lifeline record) — ADEQUATE and necessary

This was the most important r2 catch: the "unconditional lifeline" was
PCI-keyed and thus a no-op on the very substrates (veth, VMBus, XenBus) the
umbrella exists to serve. Generalizing `lifelineRecord` to a
`pci → perm-mac → kernel-name` chain is the correct fix and is consistent
with the device-map identity chain (§3 A1) — one resolution discipline across
the codebase, not a special case. I checked the two ambiguities a reviewer
would raise:
- **perm-MAC unavailable on veth:** a veth's MAC is assigned by the
  orchestrator and is stable for the netns lifetime; if perm-MAC read fails
  the chain falls through to `kernel-name`, which the plan already specifies.
  So the chain degrades gracefully.
- **kernel-name collision across netns:** within a single xpf netns there is
  exactly one `eth0`; the lifeline resolver only ever runs inside xpf's own
  netns, so there is no cross-netns collision surface. Safe.

## r2 fold C (§7 force-release-lifeline override) — ADEQUATE

Mirrors the existing #1922 OQ-D fxp0-narrowing escape valve exactly, so it is
a known pattern in the codebase rather than a new mechanism. Safe-default
preserved (unconditional protection unless the operator explicitly releases).

## Codex r2 impl note (fxp0-narrowing vs lifeline) — captured

The §7 implementation note correctly states the `narrowFxp0` exception
(`bootstrap.go:419-436`) must NOT apply against the lifeline contribution.
This is a real subtlety — the protected-set union must add the lifeline on its
own merit. Captured.

## Third-order regression scan — none found

- Does the cross-arch detect-virt fallback conflict with the
  detector-is-advisory invariant? No — it only sets a default; explicit
  platform-profile still wins.
- Does the kernel-name lifeline path conflict with #1956's RETH
  `OriginalName=` MAC-alternation discipline? No — RETH/HA is out of scope for
  the non-PCI (container) path, and bare-metal RETH still uses the PCI/perm-MAC
  legs of the chain, not kernel-name.
- Does force-release-lifeline create a new lockout (operator releases the only
  lifeline then commits badly)? It is an explicit deliberate action with the
  same blast radius as the #1922 fxp0-narrowing valve; the operator who
  releases the lifeline is asserting console/external access. Acceptable and
  symmetric with existing behavior.

## Conclusion

PLAN-READY. Three review rounds; the architecture (binding/config split,
three pluggable axes, A→B→C slicing) held unchanged through all of them while
the bring-up edge cases (cross-arch detection, non-PCI lifeline, stale-
lifeline release) were progressively closed. The honest scope note (r2 fold B
expands Slice B/C surface) is the right caveat to carry into /engineer.
