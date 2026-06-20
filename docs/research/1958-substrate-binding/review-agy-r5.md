# AGY — adversarial plan-review round 5 (verbatim)

Branch `research/1958-refresh` @ `1406f13f3`, rebased onto origin/master
`4e6fc2f2e`. Verifying the v5 fold of the r4 catches (container substrate +
stale base).

---

### 1. Rebase Verification & Code Spot-Checks
* **Ancestry Check**: The command `git merge-base --is-ancestor 4e6fc2f2e 1406f13f3` outputs **`REBASED`**, confirming that the research branch `research/1958-refresh` is fully rebased onto master (`4e6fc2f2e`).
* **Spot-Checks**:
  * **Verified**: The package `.../pkg/devicemap/devicemap.go` exists in the worktree.
  * **Verified**: The `LinuxIfName` body in `.../pkg/config/types.go` is exactly `strings.ReplaceAll(name, "/", "-")`.
  * **Verified**: The `enumeratePCINICs` function in `.../pkg/daemon/linksetup.go` is present.

### 2. Container-Substrate Reality
* In `.../test/incus/setup.sh`, the `xpf-container` profile configures `eth0..eth4` veth NICs.
* The test config in `.../test/incus/xpf-test.conf` configures Junos-style names (`fxp0`, `ge-0/0/0..4`).
* Under the current PCI-only discovery (`enumeratePCINICs` in `linksetup.go`), xpf fails to manage container veth interfaces, and the lifeline mapping fails in `bootstrap.go` because it expects a PCI bus address.
* The framing of the container path as "broken-by-design-today, latent, no bug filed" is **entirely accurate**.

### 3. Non-PCI Lockout Verification
* Grepping for `vmbus` or `xenbus` across the codebase reveals matches only inside documentation and plan files.
* `.../scripts/image/bake.py` builds standard VM/appliance targets with no special VMBus/XenBus VM target provisioned in-tree.
* Since the only non-PCI target tooled is the container (`make test-ct`), which relies on `incus exec` (no remote-reachable network lockout risk), deferring Slice B/C does not leave any live lockout.

### 4. Disposition Verdict & Counter-Argument
* **Strongest Counter-Argument to `PLAN-DEFER`**: Build it now because maintaining a broken `test-ct` target in master incurs technical debt and leaves the container smoke harness non-functional for standard xpf interface management.
* **Rebuttal**: While `test-ct` is broken-by-design for interface renaming, there is no active feature request demanding xpf-in-container support. Slice B/C involves a fragile surface area (non-PCI enumerator, non-PCI lifeline, and a 50-file interface-name audit). Building it speculatively now brings regression risk to critical bring-up paths for no current business value.

VERDICT: PLAN-READY
