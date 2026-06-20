# Claude SMR — plan-review round 4 (v4 refresh / PLAN-DEFER judgment)

Reviewing: `docs/research/1958-substrate-binding/plan.md` v4 block, on branch
`research/1958-refresh` rebased onto origin/master `4e6fc2f2e`. The v1-v3
architecture is unchanged and already 3-round-converged; r4 reviews ONLY the
re-base + the recommendation flip from PLAN-READY to PLAN-DEFER.

This is a HOSTILE pass, not a synthesis. I tried to break the defer judgment.

## What I checked independently (not on the doc's word)

1. **The "zero container consumer" claim — BROKEN.** Codex r4 is correct and I
   independently confirm it against `origin/master`:
   - `Makefile:177-178` ships `make test-ct` → `setup.sh create-ct`.
   - `test/incus/setup.sh:43` `CT_PROFILE="xpf-container"`; `:296-318` defines a
     privileged container with `eth0..eth4` veth NICs (kernel names kept,
     unlike the VM profile which renames `eth0`→`enp5s0` at `:269`).
   - `:511-521` `cmd_create_ct` launches it; `:555-640` `cmd_deploy` pushes
     `xpfd`/`cli`/`xpf-userspace-dp`, installs `xpfd.service`, starts it.
   - The container path is **maintained**, not stale: it was hardened in #1943
     (Codex r1 carved kernel-coupled provisioning to VM-only because "a
     container shares the HOST kernel") and #1992 (multi-firewall guard).
   So a container substrate is named, tooled, and maintained in-tree. My v4
   "no concrete consumer / purely speculative" framing is FALSE as written.

2. **Does xpfd actually work in `test-ct` today? NO — and that sharpens, not
   softens, the catch.** The deploy pushes `xpf-test.conf`, which references
   Junos names `fxp0` / `ge-0/0/0..4` (`xpf-test.conf:1-59`). The container's
   NICs are veth `eth0..eth4` with no PCI device symlink, so:
   - `enumerateAndRenameInterfaces` (`linksetup.go:66-73`) hits
     `len(nics)==0` → logs "no PCI network interfaces found" → returns,
     renaming nothing.
   - The config's `ge-0/0/0` etc. never resolve to a real device.
   This is exactly the Slice-B gap (non-PCI discovery + alias) AND it uses
   Junos names, which is the *deferred sub-mode (b)* (logical alias), the
   harder one. So `test-ct` is a **broken-by-design-today** xpf-in-container
   path. No issue tracks it as a bug, but it exists.

3. **Re-base honesty — the worktree was at the OLD base (AGY r4 catch).** The
   research branch was cut from `df2235787` (v3 base `5d452736e`), so the
   reviewers reading the checked-out tree saw `pkg/devicemap` absent and the
   line numbers off. I rebased the branch onto `4e6fc2f2e`; the source tree
   now matches the v4 claims (`pkg/devicemap/devicemap.go` present;
   `compiler_iface.go` leave-alone skip present; `linksetup.go` /
   `bootstrap.go` line numbers now align). This was a real process defect —
   v4 verified claims against `git show origin/master:...` but committed onto a
   stale worktree, so the artifact the reviewers read contradicted its own
   text. Fixed.

4. **Is the r2-fold-B "PCI-keyed lifeline" a LIVE bug today (the strongest
   case AGAINST deferring)?** I pushed on this hard.
   - `bootstrap.go:609-625` (`pciAddrForInterface`) builds the lifeline record
     from `busAddr` only; `:584` `detectLifelineInterface` and `:727-739`
     fall back to `fxp0` protection only when PCI is present. On a veth
     container or a non-PCI VM NIC the lifeline record is never written →
     the #1922 fail-safe is non-functional there. CONFIRMED still true.
   - BUT the only non-PCI substrate that actually reaches `xpfd` today is the
     `test-ct` container, whose reachability is `incus exec` (delegate) — there
     is no remote SSH lifeline to lose, so the PCI-keyed-lifeline gap is not a
     *lockout* there. AGY r4 independently verified no Hyper-V/VMBus,
     Xen/XenBus, AWS, or Azure provisioning exists in-tree (deploy/bake target
     KVM/libvirt + incus VMs on standard-PCI virtio; `debian/control:11`
     amd64-only). So the PCI-keyed-lifeline gap is real-but-not-a-live-lockout:
     no provisioned remote-reachable non-PCI substrate exists. This does NOT
     force "build now."

5. **Architecture — still sound.** `LinuxIfName` is still
   `strings.ReplaceAll(name,"/","-")` (`types.go:12-14`); the §5.3 de-risking
   stands; no new architectural defect from the re-base. Not PLAN-KILL.

## My disposition

The two reviewer catches are both real and **complementary**, and neither
overturns the architecture:
- AGY's worktree-state catch: FIXED (rebase).
- Codex's container-substrate catch: the v4 *rationale* is wrong ("zero
  consumer" / "purely speculative" / "no CI substrate to smoke it on" — all
  three are refuted by `make test-ct`). The *disposition* (defer the net-new
  B/C work) can still hold, but ONLY on an honest rationale: a container
  substrate is tooled but xpf-in-container interface bring-up is
  known-non-functional and **nobody has filed it as a bug or prioritized it**;
  the deferred slices are the fix for a latent, un-prioritized gap, not a
  fictional one. And `test-ct` is in fact a ready-made smoke substrate, which
  *strengthens* the case that Slice B is now tractable to build+verify when
  prioritized — it does NOT make deferral wrong, but it removes "untestable"
  as a defer reason.

The defer is still the right call (latent gap, no bug filed, no remote-
reachable non-PCI substrate, B/C is real surface area on the most fragile
bring-up code) — but the plan MUST be rewritten to:
1. Acknowledge `make test-ct` / `xpf-container` as the existing-but-unsupported
   container substrate (kill the "zero consumer / speculative" framing).
2. State that xpf-in-container interface bring-up is non-functional TODAY
   (`enumerate` returns 0; `xpf-test.conf` uses Junos names = deferred
   sub-mode (b)) and that this is latent/un-prioritized, not a fictional need.
3. Drop the "no CI substrate to smoke it on" defer argument — `test-ct` IS
   one. Keep the real defer arguments: no bug filed, B/C is large surface on
   fragile code, no remote-reachable non-PCI lockout exists today.
4. Add a concrete un-defer trigger that already half-exists: "if `make
   test-ct` is to be a SUPPORTED path (a filed bug: xpfd interface management
   must work in `xpf-container`), `/engineer 1958` Slice B from this doc."
5. Note that `test-ct` uses Junos names, so a supported container path needs
   either sub-mode (b) (the deferred harder path, 50-consumer indirection) OR
   `xpf-test.conf` must be authored with `eth0` kernel names for sub-mode (a).
   This is a real design fork the plan must surface, not bury.

Because the rationale (not just wording) was materially wrong, this round is:

**VERDICT: PLAN-NEEDS-MAJOR** (fold the container-substrate reality + re-base
fix; the defer disposition survives on a corrected rationale, the architecture
is unchanged).
