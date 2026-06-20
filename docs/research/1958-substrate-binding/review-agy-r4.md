# AGY — adversarial plan-review round 4 (verbatim)

Reviewing the v4 refresh block (PLAN-DEFER recommendation). Two catches; both
folded in v5.

---

VERDICT: PLAN-NEEDS-MAJOR

**1. Defer decision (timing) — defer is logically correct.** Package is amd64-only (`debian/control:11`); deploy/bake target only KVM/libvirt + incus VMs using VirtIO (standard PCI). No Hyper-V/VMBus, Xen/XenBus, AWS, or Azure provisioning exists in the repo. No live non-PCI substrate today, so the PCI-keyed lifeline (#1922 r2-fold-B finding) is not a live lockout bug — deferring Slices B/C has no current consumer to break.

**2. Zero-consumer claim — holds.** Full worktree grep for docker/k8s/kubernetes/container found zero container provisioning code or active profiles; only historic design docs and `systemd-detect-virt` logic reference "container." The "speculative" framing is accurate.

[NOTE: AGY's catch 2 here was reading the STALE-base worktree, which lacked the
rebased view; Codex r4 found the `make test-ct` / `xpf-container` substrate on
current master. The two reviewers' catches are complementary — see v5 fold A.]

**3. Re-base honesty — FAILS. This is the disqualifier.** The branch `research/1958-refresh` (HEAD `e0ba29488`) is NOT actually rebased onto current master (`4e6fc2f2e`). The new commit was written on top of the old v3 base (`df2235787`/`5d452736e`), so v4's "re-based to current master (+471 commits)" claim is false against the actual worktree state. Concretely verified false in the worktree:
- "#1956 leave-alone skip present in `compiler_iface.go`" — NOT present in `pkg/dataplane/compiler_iface.go`.
- "`pkg/devicemap/` exists" — directory does not exist in the worktree at all.
- Line-number claims wrong: `enumeratePCINICs` is at line 137 (not 154) and `extractPCIAddr` at line 192 (not 209) in `pkg/daemon/linksetup.go`. The plan's numbers match master `4e6fc2f2e` but not the unrebased worktree.

**4. Disposition.** The defer judgment itself is sound (not PLAN-KILL — architecture stays as design-of-record; not PLAN-READY — no consumer to build for). But the branch is in an invalid, unrebased state whose own code claims do not match its source. The branch must be genuinely rebased onto master `4e6fc2f2e`, the code claims re-verified against the rebased tree, and the plan's file/line references aligned before this can be accepted.

---

**Folded in v5:** the branch was rebased onto `4e6fc2f2e` (catch 3 resolved);
AGY re-verified `REBASED` + the code spot-checks at r5 (PLAN-READY). Catch 1/2
(defer logically sound) carried forward; catch 2's "zero consumer" was
superseded by Codex's container-substrate finding (the stale-base worktree hid
`make test-ct` from AGY's grep).
