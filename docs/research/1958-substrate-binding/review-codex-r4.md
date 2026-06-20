# Codex — hostile plan-review round 4 (verbatim)

Reviewing the v4 refresh block (PLAN-DEFER recommendation) on branch
`research/1958-refresh`. This is the catch that drove the v5 fold.

---

VERDICT: PLAN-NEEDS-MAJOR

The defer judgment is not sound as written. The v4 premise that Slices B/C have "NO concrete consumer" is false on current `origin/master`: there is a shipped standalone Incus container path for running `xpfd` itself.

Evidence:
- `origin/master:Makefile:166-178` defines `test-ct` and runs `./test/incus/setup.sh create-ct`.
- `origin/master:test/incus/setup.sh:276-318` defines `xpf-container` with `eth0` through `eth4` veth-style NICs.
- `origin/master:test/incus/setup.sh:511-521` launches that container and provisions it.
- `origin/master:test/incus/setup.sh:555-640` deploys `xpfd`, `cli`, `xpf-userspace-dp`, pushes `xpf-test.conf`, installs `xpfd.service`, and starts it.
- `origin/master:test/incus/xpfd.service:8` runs `/usr/local/sbin/xpfd`.

That makes the non-PCI/container gap live, not speculative. Current master cannot support that path correctly:
- `origin/master:pkg/daemon/linksetup.go:66-73` returns immediately when no PCI NICs are found.
- `origin/master:pkg/daemon/linksetup.go:152-170` requires `/sys/class/net/<name>/device` and a PCI bus address.
- `origin/master:pkg/devicemap/devicemap.go:259-290` skips non-PCI interfaces, so #1956 does not cover container veths.
- `origin/master:pkg/daemon/bootstrap.go:609-625` records lifeline identity only via PCI.
- `origin/master:pkg/daemon/bootstrap.go:727-739` falls back to `fxp0` protection only when the lifeline has no PCI address.
- `origin/master:pkg/dataplane/compiler_iface.go:1139-1148` only enables `leave-alone` in active device-map mode, and `:1191-1211` otherwise marks unmanaged NICs and brings them down.

The re-base spot checks are otherwise mostly honest: `LinuxIfName` is still `strings.ReplaceAll(name, "/", "-")` at `origin/master:pkg/config/types.go:12-14`, #1956 device-map exists on master, and the `compiler_iface.go` leave-alone skip exists. No `platform-profile` or substrate-detector implementation was found in `pkg`/`cmd`.

The narrower non-PCI-VM lifeline slice is a sound exit criterion for a real VMBus/XenBus target, but it does not rescue this defer: the repo already has an xpf-in-container test substrate. The plan needs to either declare `test-ct` unsupported/stale and remove or quarantine it, or treat at least explicit container alias-mode plus non-PCI lifeline/discovery as live work (not deferred). Full detector/platform-profile can still be deferred.

---

**Folded in v5:** the "zero consumer / speculative / untestable" framing was
removed; v5 acknowledges `test-ct` as the existing-but-unsupported container
substrate and rebuilds the defer rationale on (no bug filed) + (no
remote-reachable lockout) + (large fragile surface). Codex re-verified the fold
adequate at r5 (PLAN-READY).
