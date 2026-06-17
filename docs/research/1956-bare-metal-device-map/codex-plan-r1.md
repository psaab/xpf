# Codex hostile plan-review — #1956 r1

## VERDICT: PLAN-NEEDS-MAJOR

**Finding 1 — Critical | pkg/daemon/linksetup.go:270, pkg/networkd/networkd.go:372**
The plan assumes PCI BDF (`DDDD:BB:DD.F`) is a durable bare-metal identity
key, but the current `.link` file generation matches `OriginalName=` (the
kernel-assigned name at boot), not PCI BDF. Stale `.link` files from a prior
boot can misbind before xpfd resolves the device-map: systemd-udev processes
`.link` matches at uevent time, before any daemon runs. If firmware renumbers
and the old kernel name now belongs to a different NIC, systemd renames the
wrong device before the daemon's PCI/MAC resolver gets a turn. The plan must
require a BDF cross-check of any already-renamed logical name and scrub/rewrite
stale `.link` files on topology-change detection, or it reproduces the exact
hazard it claims to remove. PCI BDF is not stable on SR-IOV VFs: VF BDFs are
dynamically allocated when `sriov_numvfs` is written; device/function numbers
depend on creation order and can change across reboots, firmware updates, or PF
driver re-probe.

**Finding 2 — High | pkg/daemon/bootstrap.go:357,387, pkg/dataplane/compiler.go:1610**
"reuse the lifeline resolver" conflicts with the proposed permanent-MAC
fallback. The lifeline record stores `link.Attrs().HardwareAddr` — the RUNNING
MAC, not permanent MAC (bootstrap.go:357). Its fallback resolver also matches
the running MAC (bootstrap.go:387). The RETH virtual MAC (`02:bf:72:...`) is
the running MAC when the daemon is active; matching it as a permanent-MAC key
binds the wrong entry. Permanent MAC exists only in `getPermAddr`, and it
returns empty when netlink lacks `PermHWAddr` (compiler.go:1610). The
device-map resolver needs a NEW explicit permanent-MAC path with
missing/duplicate handling — a direct lift of the lifeline code is unsafe.

**Finding 3 — High | pkg/daemon/daemon_run.go:1555**
Bootstrap exit (`runBootstrapExitStartup`) is a missed takeover path. When the
operator commits the first real config (when a device-map stanza would first
appear), this path calls the full positional rename loop (daemon_run.go:1555).
If the device-map is introduced in that first commit, the positional rename
runs first and claims every PCI NIC by position before the mapped resolver
runs. Day-0 bare-metal still destroys the stable-identity guarantee. The plan
does not address bootstrap-exit branching.

**Finding 4 — High | pkg/dataplane/compiler_iface.go:1132,1165, pkg/networkd/networkd.go:115,133**
`leave-alone` is not just a compiler guard. The destructive path includes an
address strip and interface-down sequence (compiler_iface.go:1132,1165), but
`networkd.Apply` also removes stale `10-xpf-*` files outside its expected
managed set (networkd.go:115,133). An interface previously managed (had a
`.link` written) and later moved to `leave-alone` will have its `.link` deleted
by `networkd.Apply`, triggering a reload that removes the kernel rename. The
plan's "never renamed, never address-stripped" promise is only safe for
interfaces the daemon has NEVER previously touched. Managed→unmapped migration
needs explicit stale-file cleanup semantics; the plan does not specify this.

**Finding 5 — Medium | pkg/daemon/linksetup.go (RETH OriginalName block)**
RETH OriginalName matching uses `OriginalName=` precisely because the running
MAC alternates physical↔virtual across the daemon lifecycle. If a device-map
entry for a RETH member uses MAC as the fallback key, it matches the virtual
MAC when the daemon is up and the physical MAC when not — non-deterministic
binding. The plan must explicitly EXCLUDE RETH member interfaces from the
MAC-fallback path and keep `OriginalName=` matching for them, or it silently
breaks HA.

**Finding 6 — Medium | pkg/config/schema_chassis.go:8, types_chassis.go:7, compiler_system.go:879, docs/config-schema.md:116**
Schema/compiler integration is underspecified. `schema_chassis.go` only
registers `cluster`; `ChassisConfig` only has `Cluster`; `compileChassis`
returns immediately if there is no `cluster` node (compiler_system.go:879). A
sibling `chassis device-map` is silently ignored unless that compiler shape
changes. On rollback to a tree with no `device-map`, the daemon silently falls
back to positional mode with no warning. docs/config-schema.md:116 indicates
named-instance identity tokens need `keyValueType/keyValidator`, NOT ordinary
`valueType` leaves, which the plan does not mention.

**Finding 7 — Medium**
Failure modes underspecified: (a) two entries claiming the same PCI address —
no validator exists today; (b) a listed NIC absent at boot — plan says "log and
skip" but does not say whether the slot is left unbound or falls through to
positional; (c) a VF renumbered between reboots — treated as missing (F1); (d)
operator MAC fallback that matches the RETH virtual MAC (F5). The plan does not
commit to validator implementations.

**Finding 8 — Low (scope)**
The smallest viable version is NOT decoupleable from the policy knob (the map
without the knob adds complexity without reducing bring-down risk). But the VF
PCI instability, bootstrap-exit branch, RETH MAC-fallback exclusion, and
networkd stale-file migration semantics are all blockers. Smallest safe
version = PCI-map + topology-change detection + explicit VF exclusion +
OriginalName-preserved RETH exemption + bootstrap-exit branch + policy knob —
all five together.
