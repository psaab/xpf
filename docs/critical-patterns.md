# xpf critical patterns / gotchas

Project-specific traps that repeatedly bite when working on xpf. The
broader coding and review discipline (hot-path allocation rules, review
severity, PR discipline) lives in
[`engineering-style.md`](engineering-style.md) — read that first for
non-trivial code. This page is the quick-reference gotcha list.

## Byte order

- Use `binary.NativeEndian.Uint32(ip4)` for BPF `__be32` fields — **NOT**
  `BigEndian`.
- cilium/ebpf serializes map values in native endian; IP bytes are
  already in network order.

## C/Go struct alignment

- When mirroring C structs in Go for cilium/ebpf, always match `sizeof`
  in C.
- Add trailing `Pad [N]byte` fields to reach the C compiler's struct
  alignment.

## Parser dual AST shape & set-syntax testing

- Hierarchical `family inet { dhcp; }` → `Node{Keys:["family","inet"]}`
  with children. **Flat `set interfaces eth0 unit 0 family inet dhcp`
  produces the IDENTICAL tree** — `SetPath` descends a `compoundKey`
  container exactly as the parser does, so flat-vs-hierarchical is *not*
  where the shape varies (#8808).
- **The real variable is BRACING**, and there are three shapes:

  | spelling | tree |
  |---|---|
  | `family inet { dhcp; }` | `[family inet]` + child `[dhcp]` (COMPOUND) |
  | `family { inet { dhcp; } }` | `[family]` → `[inet]` → `[dhcp]` (SPLIT) |
  | `family inet dhcp;` | `[family inet dhcp]` (PACKED, the #2419 class) |

- The compiler must handle **all three**. The SPLIT form is where a bare
  `Node{Keys:["family"]}` with an `inet` child actually comes from — an
  operator bracing the family separately, never a `set` command.
- Pinned by `TestFlatSetAndHierarchicalProduceTheSameTree8808` and
  `TestBracingProducesThreeDistinctShapes8808`.
- **Testing flat set syntax:** ALWAYS use `ParseSetCommand()` +
  `tree.SetPath()` loop, NEVER `NewParser()` — the parser treats newlines
  as whitespace and will merge all set lines into one giant node.

## BPF verifier (retained AF_XDP shim)

- Branch merges lose packet range — re-read `ctx->data`/`ctx->data_end`
  after branches.
- Combined stack limit is 512 bytes across call frames — use
  `__noinline` and scratch maps.
- Variable-offset pkt pointer: the verifier refuses range tracking when
  `var_off` is wide (0xffff) — use a constant-offset from a validated
  pointer instead.
- **Narrowing meta offsets**: when using `meta->l3_offset` (u16) for
  packet pointer math, mask with `& 0x3F` to narrow `var_off` so the
  verifier can track range.
- `__u16` causes sign-extension (`smin=-32768`) — fails for pkt pointer
  math.
- `iter.Next(&key, nil)` crashes in cilium/ebpf v0.20 — always use
  `var val []byte`.
- The shim's verifier floor is kernel ≥ 6.18 (NAT64 complexity fails on
  6.12). The image bake asserts this (#1864).

## TTY detection

- Use `unix.IoctlGetTermios(fd, TCGETS)` — **not** `os.ModeCharDevice`
  (`/dev/null` is a CharDevice).

## Interface management (networkd)

- **xpfd manages ALL interfaces** on the firewall — no external networkd
  configs needed. Every interface must be defined in the config and
  assigned to a security zone; interfaces not in the config are brought
  down (`ActivationPolicy=always-down`).
- VRF devices and tunnel interfaces created by the daemon are excluded
  from unmanaged detection.
- **`.link` files** (prefix `10-xpf-`) rename kernel names
  (`enp7s0` → `ge-0-0-0`). Startup naming is
  `enumerateAndRenameInterfaces()` in `pkg/daemon/linksetup.go`.
  - Non-RETH interfaces match by `MACAddress=` (MAC is stable).
  - RETH member interfaces match by `OriginalName=` (PCI kernel name) —
    MAC alternates between physical (boot) and virtual (daemon), so
    `MACAddress=` is unreliable. `ensureRethLinkOriginalName()`
    auto-fixes stale files.
  - **The pre-rename name comes from the KERNEL, not from arithmetic
    (#6677).** `deriveKernelName()` asks for the interface's kernel
    ALTERNATIVE names first and only falls back to deriving one from the
    sysfs PCI address. Altnames are the candidate set udev itself computed
    and are stable across renames, so they stay correct after xpf has
    renamed the interface — which is exactly when the pre-rename name has
    to be recovered.
    Re-deriving from the address cannot match systemd, which has at least
    three inputs the address string does not carry (all measured on real
    hardware, systemd 261): **ARI** folds slot and function into one 8-bit
    function number; an **SR-IOV VF** is named from its *physical*
    function's address plus the VF index (`0000:b7:02.0`, physfn
    `0000:b7:00.0`, is `enp183s0f0v0` — the address-only derivation says
    `enp183s2f0`); and a multi-port NIC carries an **`npN` port suffix**
    (`enp183s0f0np0`). Altname selection follows systemd's default
    `NamePolicy` order — onboard (`eno`), slot (`ens`), path (`enp`) —
    because a device commonly carries several at once and the first the
    policy resolves is the one udev assigns. `eth` is accepted last only,
    and a MAC-based `enx` name never.
  - **The ARI arithmetic is deliberately NOT implemented in the fallback
    (#7415, recorded here rather than left open).** systemd's `net_id`
    reinterprets the PCI slot and function fields as one 8-bit function
    number when ARI is enabled, i.e. `func += slot * 8`. `pciAddrToEnp`
    does not do this, so on an ARI device at a non-zero slot the two would
    disagree.
    That divergence could not be REPRODUCED: it needs an ARI-enabled,
    **non-VF** network function at a **non-zero** PCI slot, and no such
    device was available. The discriminator, for anyone who has one:
    ```bash
    for d in /sys/bus/pci/devices/*/; do
      [ "$(cat $d/ari_enabled 2>/dev/null)" = 1 ] || continue
      [ -e "$d/physfn" ] && continue                   # skip VFs
      case "$(basename $d)" in *:00.*) continue;; esac # skip slot 0
      [ -d "$d/net" ] && echo "DISCRIMINATOR: $(basename $d)"
    done
    ```
    On such a device, compare `udevadm test-builtin net_id
    /sys/class/net/<if>` against `pciAddrToEnp`. Multi-function ARI
    endpoints that are not SR-IOV VFs — some multi-port NICs and
    accelerator cards — are the likely candidates.
    It was not implemented on argument rather than oversight. #6677 made
    udev authoritative (`deriveKernelName` reads `ID_NET_NAME_PATH` from
    `/run/udev/data/n<ifindex>`, which already accounts for ARI, the VF
    parent and the port suffix), so the fallback runs only when udev data
    is ABSENT — early boot before settle, or a container. The residual is
    therefore reachable only on a host that simultaneously has an ARI
    non-VF NIC at a non-zero slot AND no udev data for it. Adding
    arithmetic that cannot be demonstrated, to a nearly unreachable path,
    in a function that silently renames network interfaces, is risk
    without measurable benefit: **a naming fix that guesses is worse than
    none.**
    If someone confirms the divergence on real hardware, the change is
    `func += slot * 8` in `pciAddrToEnp` when
    `/sys/bus/pci/devices/<addr>/ari_enabled` is `1` — which requires the
    helper to take the device PATH rather than the address string, since
    ARI is a property of the device — plus a fixture built from that
    hardware's real `udevadm` output, keeping the udev-first path primary.
  - **Collision-safe positional rename (#4178).** The positional loop
    (`renamePositional`) is two-pass, like device-map mode: it captures
    every NIC's `OriginalName=` from the existing `.link` set BEFORE
    writing any file, then breaks target-name collisions with `xpf-tmp-N`
    names (shared helper `breakNameCollisions`), then writes each `.link`
    and renames to the final name. This keeps an enumeration shift (a NIC
    added/removed/reordered changes the positional index→name map) from
    corrupting the `OriginalName=` chain or EEXIST-stranding a rename —
    the old single-pass loop wrote a `.link` then re-read it in a later
    iteration, so a NIC added at a lower PCI bus scrambled the rename
    database and shifted port↔zone bindings for a boot.
- **HA config-arrival re-naming (#4179).** An HA node with
  `/etc/xpf/node-id` but no committed config boots NOT in bootstrap mode
  (HA-node guard) and names its NICs STANDALONE (`fxp0`, `ge-0-0-X`)
  because the nil active config carries no cluster stanza. The one-shot
  `emptyHANamingPending` flag makes the first non-empty config that
  arrives (a cluster SyncApply from the primary, or a local commit)
  re-run startup naming with the config's cluster identity —
  `em0` + `ge-<fpc>-0-X` (node 1 → FPC 7) — via
  `maybeReapplyConfigArrivalNaming` in `applyConfigLocked`, BEFORE the
  reconcile wires the config onto the interfaces. No daemon restart is
  needed; it mirrors bootstrap-exit re-naming but does NOT re-arm the
  dataplane (this node is not in bootstrap mode). A standalone config or
  any later commit is a no-op. The flag is consumed ONLY on a successful
  re-name — a transient enumeration/netlink error leaves it set so the
  next config apply retries (never strand the node on one blip).
- **`.network` files** configure addresses, DHCP avoidance, RA disable,
  VLAN parent flags. `KeepConfiguration=static` on RETH interfaces
  preserves VRRP VIPs across `networkctl reload`. A VLAN parent carries
  none of its units' addresses. The one exception is the
  `169.254.<rg>.<node+1>/32` VRRP advert source of a VRRP-backed RETH with an
  addressed unit that has no `vlan-id`: that unit's VRRP instance is bound to
  the parent, which is otherwise left with no IPv4 source
  (`VLANParentAddresses`, #9721).
  DHCP interfaces: the daemon's DHCP client manages the address; address
  reconciliation is skipped. DHCP-learned default routes get admin distance
  200 in FRR. A learned classless prefix is suppressed (with a visible warning)
  when a rendered/operator static or an installed same-VRF RIB route contains
  it, so DHCP cannot defeat an existing path by longest-prefix match. The FRR
  apply reads the live main/instance tables for non-static routes, including
  BGP/OSPF/IS-IS/RIP and tunnel next-hops, and also checks the preferred-route
  overlay. Static FIB rows are checked from renderable config instead: FRR
  stamps its own DHCP classless routes as staticd entries, so importing those
  would make a lease suppress itself on every later apply. A live dynamic
  default is not classless-prefix coverage; the separate configured-static
  default rule is unchanged. If the live-table read is incomplete, classless
  routes fail closed while DHCP defaults keep their independent contract;
  `XPF_DHCP_TRUST_CLASSLESS_OVERRIDE=1` is the explicit escape hatch.
  The management VRF treats only table-999 `RTPROT_STATIC` routes, plus the
  management statics xpf stamps with protocol 0x58
  (`config.ManagementVRFMultipathStaticProtocol`, #12539, #14972), as operator
  authority; xpf-owned `RTPROT_DHCP` and ordinary connected/kernel routes are
  not operator authority. BGP/OSPF/IS-IS/RIP routes in table 999 suppress
  classless prefixes they contain, except a dynamic `/0`, which does not
  protect specific option-121 destinations. A gatewayless `RTPROT_KERNEL`
  connected prefix in table 999 suppresses any DHCP classless route it contains
  by default (#11383); `XPF_DHCP_TRUST_CLASSLESS_OVERRIDE=1` may restore that
  general connected overlap with a loud security warning. As a separate
  non-overridable hard fence (#11362), a connected prefix on a configured
  cluster control/fabric interface suppresses any DHCP classless route it
  contains even with the trust override set. Unexpected other-protocol routes
  are warned and ignored. Competing eligible DHCP defaults in table 999 are
  resolved per family by selecting the lexically first interface (gateway
  address breaks interface ties) and warning with the candidates and winner
  (#11363); classless routes from other leases still apply. An option-121 `/0`
  follows the normal DHCP-default suppression contract. Unusually broad
  classless `/1` prefixes and non-forwardable martian ranges (`0/8`, `127/8`,
  `169.254/16`, `224/4`, `240/4`) are refused by default. The deliberate
  escape hatch `XPF_DHCP_TRUST_CLASSLESS_OVERRIDE=1` restores operator-covered,
  dynamic-RIB-covered, general connected-overlap, broad, and martian classless
  routes except the cluster control/fabric-prefix fence, and emits a loud
  security warning; it is unset by default.

## XDP on SR-IOV interfaces

The line-rate behavior is coupled to the NIC driver exposed to the VM.

- **iavf (Intel VF driver) has NO native XDP support** — only
  generic/SKB mode works (full `sk_buff` per packet, ~16% CPU overhead).
  Throughput drops from 25+ Gbps to ~6.8 Gbps.
- **i40e/ice/mlx5 (PF driver) have native XDP** — driver-mode XDP
  processes packets before SKB allocation.
- **`bpf_redirect_map` requires `ndo_xdp_xmit` on the target** — you
  cannot redirect from native XDP to an interface that lacks native XDP;
  the redirect silently fails. Mixing native+generic interfaces in a
  redirect set does not work.
- **XDP on a PF does NOT see VF traffic** — SR-IOV hardware switching
  delivers VF packets directly to VFs, bypassing the PF's XDP program.
- **mlx5 SR-IOV VFs DO support native XDP** and exact/masked ntuple
  steering — this is the loss-cluster reference shape (each VF exposes 6
  combined RX queues → 6 workers).
- **PF passthrough claims the whole NIC** — no VFs available to other
  VMs. For multi-VM setups, VF passthrough is the only option (mlx5 VFs
  keep native XDP; Intel VFs fall to generic).

See the deploy backing table in
[`deploy-quickstart.md`](deploy-quickstart.md) for which backing to pick.

## Chassis cluster (HA)

- **Unplanned peer loss — compiler-default private-RG election**: RETH VRRP is
  suppressed (`pkg/config/compiler_system.go:3132-3137`; see the ownership-mode
  table in `pkg/vrrp/README.md:950-964`). The heartbeat staleness threshold is
  interval × threshold: 100ms × 5 = 500ms at runtime defaults, or 200ms × 5 =
  1s in the deployed lab config. These are `set chassis cluster
  heartbeat-interval <ms>` and `heartbeat-threshold <n>`
  (`pkg/cluster/heartbeat.go:61-65,1916-1960`;
  `docs/ha-cluster-userspace.conf:71-72`). The threshold is not always the
  declaration time: while sync is connected and last peer traffic is ≤2s old,
  `shouldSuppressPeerHeartbeatTimeout` defers loss; continuous suppression is
  capped at 5s. A silent death/partition with ESTABLISHED sync can therefore
  take max(threshold, remaining sync-recency window) plus up to one heartbeat
  tick: 0.5–2.1s from peer death at defaults or 1.0–2.2s in the lab.
  Process exit that closes sync or sync idle >2s falls through at the heartbeat
  threshold, subject to startup/restart grace
  (`pkg/daemon/daemon_ha_sync.go:170-206`;
  `pkg/cluster/heartbeat_manager.go:790-832`).
- **Separate interface/IP monitor detection**: polls run each second; 3
  consecutive failed polls mark a monitor down, followed by a 5s hold-down
  before another state transition. IP sweeps use up to 16 concurrent probes
  with 800ms read deadlines, so >16 targets add 800ms probe waves
  (`pkg/cluster/monitor.go:28-32,44-57,260-276,386-397,585-600`).
- **Unplanned peer loss — legacy VRRP-backed RETH** (`no-private-rg-election`,
  unless `no-reth-vrrp` is also set): only this mode uses the 30ms default RETH
  advertisement; configure it with `set chassis cluster
  reth-advertise-interval <ms>`. The steady-state master-down timer is
  `3×advertised interval + priority skew`; at 30ms and priorities 1–255 it is
  >90ms and <120ms, a detection timer rather than an end-to-end restoration
  measurement (`pkg/vrrp/vrrp.go:153-166`;
  `pkg/vrrp/instance_timing.go:112-128`;
  `pkg/vrrp/README.md:950-964`).
- **Planned shutdown**: legacy VRRP-backed shutdown sends three priority-0
  advertisements; the BACKUP arms a 1ms timer, and a run-loop test requires
  MASTER advertisement within 50ms (test constraint, not an SLA)
  (`pkg/vrrp/instance.go:770-807`; `pkg/vrrp/instance_rx.go:155-173`;
  `pkg/vrrp/instance_prio0_run_test.go:143-149`). Private-RG operator failover
  is an explicit transfer/resignation path
  (`pkg/cluster/failover.go:447-450`;
  `pkg/cluster/election.go:1021-1042`). Private-RG planned shutdown without
  explicit transfer sends no resign frame; after `rg_active` clears, the peer
  promotes through heartbeat loss no earlier than the heartbeat staleness
  threshold, and the sync-recency guard can further defer it
  (`pkg/daemon/daemon_run_shutdown.go:418-428`;
  `pkg/cluster/manager.go:1026-1077`;
  `pkg/daemon/daemon_ha_sync.go:170-206`).
- **VRRP advertisement**: the 30ms default applies only to VRRP-backed RETH
  instances; `AdvertiseInterval` is milliseconds internally, centiseconds on
  wire per RFC 5798 (`pkg/vrrp/vrrp.go:153-166`).
- **Event debounce**: the 500ms cluster-event → VRRP-priority coalesce is used
  only in legacy VRRP-backed mode; direct/private-RG mode skips it
  (`pkg/daemon/daemon_ha.go:782-824`).
- **Deafness windows and the extended master-down timer (#7579)**: in legacy
  VRRP-backed mode a BACKUP promotes when its master-down timer expires; that
  arm is deliberately UNGATED by `preempt` — RFC 5798's preempt governs
  displacing a master it can HEAR, not filling an apparent vacancy. The normal
  30ms-advert master-down timer is >90ms and <120ms across priorities 1–255.
  When `preempt=false`, the implementation extends this deafness window to 3s
  in TWO places: **process start**, before the AF_PACKET receiver is capturing,
  and **sync-hold release**, when a rejoining node is installing synced
  sessions and about to do VIP work. Missing the second extension produced an
  observed ~12.9s dual-owner window. `handleBackupRx` resets to the normal
  master-down timer on the first advert, so a heard peer does not pay the 3s
  floor (`pkg/vrrp/instance.go:71-93`;
  `pkg/vrrp/instance_timing.go:11-41`;
  `pkg/vrrp/instance_rx.go:151-173`).
- **Async GARP**: `becomeMaster()` runs GARP in a goroutine; critical
  path is addVIPs → sendAdvert → emitEvent (sync), then
  `go sendGARP(false)`. `sendGARP(force)` has two gates — per-epoch dedup
  and a 500ms time dampener; `force=true` (used by `ReconcileVIPs` after a
  MAC change) bypasses ONLY the dampener so the post-MAC-change GARP is not
  swallowed by a routine burst from the prior 500ms (#2081).
- **Fail-closed VIP ownership (#5082)**: `becomeMaster()` gates the MASTER
  advert/event on SUCCESSFUL required-VIP actuation. `addVIPs` returns a
  structured result (which VIPs actuated, which failed) instead of void; a
  swallowed LinkByName/AddrAdd failure no longer lets the peer and dependent
  services trust an owner that cannot receive VIP traffic. On any required-VIP
  failure `becomeMaster` rolls back partial adds, reverts to `StateBackup`, and
  returns `false` WITHOUT advertising/emitting — the run-loop then re-arms the
  master-down timer (`rearmForRetry`) to retry the election.
  - **A failed rollback delete is surfaced (#9509)**, exactly as `becomeBackup`
    surfaces its removal. `surfaceStaleVIP` bumps `vipRemoveFailures`, sets
    `vipDiverged`, and schedules the generation-fenced reconcile. It is called
    after `setState(StateBackup)` and after releasing `vipMu`, and it is called
    unconditionally, so a clean rollback clears a stale flag.
  - Without it the stranded VIP was permanent: the master-down retry never fires
    while a healthy peer adverts.
  - `ReconcileVIPs`' own superseded rollback stays log-only. The only transition
    that can supersede it is `becomeBackup`, which always follows with a full,
    surfaced removal.

  The clean success path is unchanged (`vipMu` is uncontended). This fix makes
  no claim about cross-mode detection or traffic-restoration timing. A monotonic
  **ownership generation** (`ownerGen`, bumped by `setState` on every real
  transition) is captured before the netlink add and revalidated after:
  `ReconcileVIPs` re-adds VIPs and forces GARP only if the instance is STILL the
  current-generation MASTER after the add, closing the check-then-act TOCTOU
  where a superior advert demoting to BACKUP could interleave and re-add VIPs +
  force GARP while BACKUP (duplicate address, split routing). `vipMu` serializes
  the add/remove + revalidation across the run-loop and the manager's
  `ReconcileVIPs`.
- **Fabric forwarding**: the userspace dataplane redirects packets for
  peer-owned synced sessions over the fabric link
  (`resolve_fabric_redirect()` / `ingress_is_fabric()` in
  `userspace-dp/src/afxdp/forwarding/mod.rs`; see
  [`fabric-cross-chassis-fwd.md`](fabric-cross-chassis-fwd.md)).
- **RETH virtual MAC**: per-node, per-RETH `02:bf:72:CC:RR:(2*index+node)`; `programRethMAC()`
  does link DOWN → set MAC → link UP, then `ReconcileVIPs()` re-adds
  VRRP VIPs.
- **Address owner always preempts (#4116)**: an instance whose *configured*
  priority is 255 (the IP address owner) preempts a lower-priority master
  irrespective of the `no-preempt` flag or sync-hold suppression (RFC 5798
  §6.1). `getPreempt()` and `shouldPreemptObservedMaster()` OR-in
  `cfg.Priority == 255`, so an owner hearing a lower advert does NOT reset its
  master-down timer (`handleBackupRx`) — the timer expires and the owner
  reclaims MASTER. Keyed on configured priority, this composes with the
  owner-255 track-demotion exemption (`getPriority`, which never demotes 255).
  These are VRRP-instance election rules, not a timing claim for the default
  private-RG mode.
- **Sync hold**: VRRP starts with `preempt=false`; both VRRP and the
  no-RETH/private-RG startup paths use a 30s safety timeout (released early
  when bulk sync completes), not 10s. `preemptNowCh` triggers VRRP preemption
  when sync completes early (`pkg/daemon/daemon_run_bringup.go:260-273`;
  `pkg/daemon/daemon_ha_noreth_hold.go:42-53`;
  `pkg/vrrp/manager.go:355-379`).
- **Heartbeat**: 100ms × threshold 5 (500ms staleness threshold) at runtime
  defaults, 200ms × 5 (1s) in the deployed lab. The knob names are
  `set chassis cluster heartbeat-interval <ms>` and
  `set chassis cluster heartbeat-threshold <n>`; the sync-recency guard and
  startup/restart grace can defer peer-loss declaration
  (`pkg/cluster/heartbeat.go:61-98,1916-1960`;
  `pkg/daemon/daemon_ha_sync.go:170-206`;
  `docs/ha-cluster-userspace.conf:71-72`).

## Shutdown

- FRR reloads run `frr-reload.py` DIRECTLY (15s context per leg) — NEVER
  `systemctl reload frr`: FRR 10.6's ExecReload bounces watchfrr and ends
  with systemd SIGKILLing FRR (#1880).
- The systemd unit has `TimeoutStopSec=20` as a safety net,
  `RestartSec=1`.
