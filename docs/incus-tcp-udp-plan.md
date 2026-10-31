# Plan (PLAN ONLY — nothing created): twin userspace clusters `tcp` + `udp`

Status: **PARKED — NOT READY TO EXECUTE (user ruling 2026-10-20), preserved for iteration.** No build approval: steps S0–S7 require an explicit fresh go-ahead; do not create/configure the tcp/udp fw hosts for testing or smoke testing yet. Open items: Q1–Q13 (§7) unresolved. This document was written from
read-only inspection only (repo files below + `incus`/`ssh` queries that do not
mutate). No VM, container, network, profile, storage pool, file (other than
this plan), host sysctl, or cluster config was created or changed, and no
deploy was run. Every command in §5 is a *proposed* command for the approval
gate, not a record of execution.

Date basis: inspection on 2026-10-19 (workstation date shown to this agent).
Heads/versions observed: `loss` fw nodes report
`Software version: working-20838-g61c7d45603` (read via `cli` on fw0).

**Revision 2026-10-21 (this edit, for review — still PARKED, no execution):**
VF-first allocation added after a dedicated NIC inspection of both hosts
(read-only `ssh`/`incus` probes on 2026-10-21, §1.4.1). The hosts are not
"a 100G NIC plus a 25G NIC": each carries a dual-port 100G Mellanox
ConnectX-6 Dx **and** a dual-port 25G Intel E810 (§1.4.1). All dataplane,
generator, and target roles are now assigned to **SR-IOV VFs** (§2.8);
PFs stay host-owned and are never passed through. New/changed material:
§1.4.1–§1.4.3, §2.1, §2.3 item 8, §2.8, §3 VF columns, §5 S0–S3 VF
preparation steps, R10–R12, Q11–Q13, Appendix A. Open items are now
Q1–Q13. Nothing in this revision authorises S0–S7.

**Revision 2026-10-21b (fabric on E810 VFs, for review — still PARKED):**
the fabric leg moves from the `bpu-*-fab0` bridge to **SR-IOV VFs on the
E810 `ix0` PF** with a PF-private VF VLAN, after a follow-up probe
confirmed `hwmode VEB` + `local_forwarding: enabled` on both hosts
(§1.4.1). Fabric is now v1 scope (§2.8.2 row F, §2.8.3 item 1); the
bridge remains the documented fallback. This adds one machinery slice
to §4 (SR-IOV fabric support in `cluster-setup.sh`, default-off so
`loss` is untouched) and closes Q13's phasing question in favour of
fabric-in-v1 — Q13 itself stays open only for reviewer confirmation.
The full VF interface-map diagram is §2.8.6; §2.1 remains only the
cluster topology sketch.

---

## 0. What is being asked, restated

Stand up **two new, independent clusters** analogous to the existing isolated
`loss` userspace cluster, but hosted on two **separate Incus servers that
already exist as remotes** and are currently **empty**:

- remote `tcp`  → `https://172.16.100.102:8443` (host `tcp`, see §1.4)
- remote `udp`  → `https://172.16.100.103:8443` (host `udp`, see §1.4)

Each cluster mirrors the `loss` userspace shape:

- generator host: analogous to `cluster-userspace-host` (LAN-side source);
- HA firewall pair: analogous to `xpf-userspace-fw0` / `xpf-userspace-fw1`
  (`xpfd` + Rust userspace helper `xpf-userspace-dp`, AF_XDP, RG0/1/2);
- same fabric pattern as `loss` (mgmt bridge + heartbeat bridge + fabric
  bridge, SR-IOV WAN trunk, SR-IOV LAN access-VLAN) — with every
  forwarding/generator/target leg as an **SR-IOV VF** on the new hosts'
  100G/25G PFs (VF allocation normative in §2.8, added 2026-10-21).

The two clusters carry **separate TCP and UDP test stacks with different
addressing** (from the ticket):

| Stack | WAN-side address #1 | WAN-side address #2 | Delegated / LAN prefix |
|---|---|---|---|
| TCP | `2001:559:8585:50::a` | `2001:559:8585:80::a` | `2001:559:8585:aa00::/56` |
| UDP | `2001:559:8585:50::b` | `2001:559:8585:80::b` | `2001:559:8585:ba00::/56` |

### 0.1 Interpretation I am planning to (needs confirmation — Q1, Q2)

The ticket text is terse about *which node owns* `::a`/`::b` etc. I adopt —
and flag as the single biggest decision in this plan — this reading:

1. **`2001:559:8585:50::X` and `2001:559:8585:80::X` are the firewall's own
   WAN RETH addresses** (the analogue of today's `…50::8` / `…80::8` on
   `reth0.50` / `reth0.80` in `docs/ha-cluster-userspace.conf:120,125`).
   Reason: `50` and `80` are the two existing WAN VLAN subnets
   (`reth0` is `vlan-tagging` with `unit 50 { vlan-id 50 }` and
   `unit 80 { vlan-id 80 }`), and the only stack-specific addresses that can
   live on *both* of those subnets and differ per stack are the RETH VIPs
   themselves. Alternative reading (WAN *target* addresses, analogue of
   `…80::200`) is analysed in §2.6/Alt-B with its own table delta; it
   requires also choosing new RETH addresses, which the ticket does not give.
2. **The `/56` is the LAN (delegated) prefix for that stack**: carved to a
   `/64` on `reth1` (LAN gateway `…::1`), advertised by the firewall's
   embedded RA sender, and — for WAN reachability — announced upstream by a
   static route at whatever router owns `…50::1`/`…80::1` today (§2.4).
   Carve is `aa00::/64` (TCP) and `ba00::/64` (UDP) by default, i.e. the
   first `/64` of each `/56`; the remaining 255 `/64`s of each `/56` are held
   reserved for per-test subnets (§2.4.2).
3. **"Separate TCP and UDP test stacks" = two whole clusters** (one per
   remote), each *specialised* by workload (TCP cluster runs TCP load, UDP
   cluster runs UDP load), **not** one cluster with two LANs. The remotes are
   literally named `tcp` and `udp` and are empty; §2.7 analyses the
   single-cluster alternative and recommends against it for this ask.

If either reading is wrong, §2.6 and §7-Q1/Q2 are the pivot points; the rest
of the plan (inventory, build sequence, validation, risks) is written so only
§2/§3 tables change.

---

## 1. Inventory of the existing `loss` cluster (observed, read-only)

### 1.1 Defining files (exact paths — the "name exact commands/files" ask)

| Artifact | Path / command | Role |
|---|---|---|
| Canonical env (userspace) | `test/incus/loss-userspace-cluster.env` | Remote, instance names, profile, VF PCI hints, LAN/WAN params, iperf targets (§1.2). |
| Legacy env (loss, eBPF/xdp ref) | `test/incus/loss-cluster.env` | `bpfrx-fw0/1` + `cluster-lan-host`, VLAN 3666, cluster-id 2. |
| Cluster lifecycle script | `test/incus/cluster-setup.sh` (1135 lines) | `init/create/destroy/deploy/ssh/status/logs/start/stop/restart`; `require_cluster_cell` lock gate (§1.7). |
| Shared env resolver | `test/incus/cluster-env.sh` | Derives `FW0/FW1/CLUSTER_LAN_HOST` refs from `BPFRX_CLUSTER_ENV`. |
| Cluster lock protocol | `test/incus/cluster-lock.sh`, `test/incus/with-cluster.sh` | Default loss tuple is the workstation-local `flock` `/var/worktrees/.cache/tmpdir/xpf-cluster.lock` (with matching owner/epoch; see §6-R7). |
| Deploy helpers | `test/incus/deploy-lib.sh` (54 KB), `scripts/image/bake.py` | Verified deb cutover, sha-verified raw push, preflight shim-verify. |
| Unified FW config (userspace) | `docs/ha-cluster-userspace.conf` (397 lines, cluster-id **22**) | Single config for both nodes; node split via `groups { node0/node1 }` + `apply-groups "${node}"`; node id from `/etc/xpf/node-id`. |
| Unified FW config (legacy loss) | `docs/ha-cluster-loss.conf` (339 lines, cluster-id **2**) | Same shape, `dataplane-type` absent (legacy), LAN `10.0.89.1` / `2001:559:8585:df01::1`. |
| Makefile entry points | `Makefile:1460-1600` | `CLUSTER_ENV:=test/incus/loss-userspace-cluster.env` default; `CLUSTER_SETUP = BPFRX_CLUSTER_ENV=$(CLUSTER_ENV) ./test/incus/cluster-setup.sh`. `make cluster-{init,create,deploy,deploy-and-gate,destroy,status,ssh,logs,start,stop,restart}`; aliases `userspace-cluster-*` → same; `loss-cluster-*` uses `LOSS_CLUSTER_ENV`. |
| Validators to clone | `scripts/userspace-ha-validation.sh` (980 ln), `scripts/userspace-phase-cycle.sh`, `scripts/userspace-perf-compare.sh`, `scripts/userspace-native-gre-validation.sh`, `scripts/iperf-json-metrics.py` | Phase-cycle = push branch → deploy fw0/1 → validate. Validator defaults `PARALLEL=6`, `MIN_GBPS_V4/V6=18.0`. |
| Target-service contract | `test/incus/target-services.sh`, `test/incus/mouse-target-setup.sh` | WAN target grid: iperf3 `5200-5211`, echo `6200-6211` (+7) per class; §1.5. |
| Image bake (production appliance) | `scripts/image/bake.py`, `scripts/image/make_config_drive.py`, `scripts/image/validate.py` | **Not** what the lab VMs use — lab uses stock cloud image + apt provisioning (§1.6). Do not confuse the two. |
| systemd unit (lab) | `test/incus/xpfd.service` | `ExecStart=/usr/local/sbin/xpfd`. The raw deploy pushes it (and the two boot barriers) to `/etc/systemd/system`. The deb path uses the packaged units, and since #18544 it removes those raw-push `/etc` copies, which otherwise shadow the packaged units. |

### 1.2 The userspace env file, as-is (`loss-userspace-cluster.env`)

```
INCUS_REMOTE="loss"  VM0="xpf-userspace-fw0"  VM1="xpf-userspace-fw1"
LAN_HOST="cluster-userspace-host"  PROFILE="xpf-cluster-userspace"   # NOTE: live profile is named bpfrx-*, §1.3.1
VF_WAN_PCI=("0000:65:00.4" "0000:65:00.5")   # legacy hint; nictype=sriov now allocates, §1.6
VF_LAN_PCI=("0000:65:05.4" "0000:65:05.5")   # ditto
SRIOV_PARENT="mlx0"  SRIOV_LAN_PARENT="mlx1"  VF_LAN_VLAN=3667
NET_MGMT="incusbr0"  NET_HEARTBEAT="bpu-hb0"  NET_FABRIC="bpu-fab0"  NET_CLAN=""   # "" = SR-IOV LAN, no bridge
CLUSTER_CONF="docs/ha-cluster-userspace.conf"
LAN_ADDR="10.0.61.102/24"  LAN_GW/LAN_VIP4="10.0.61.1"  LAN_VIP6="2001:559:8585:ef00::1"
WAN_GW4="172.16.50.1"  WAN_VIP4="172.16.50.8"   # fixed #16468: was .6, stale vs conf (.8)
IPERF_TARGET4="172.16.80.200"  IPERF_TARGET6="2001:559:8585:80::200"
MOUSE_TARGET_V4="172.16.80.201"  MOUSE_TARGET_V6="2001:559:8585:80::201"
```

### 1.3 Live state on `loss:` (observed; commands shown for reproducibility)

Commands run (all read-only): `incus remote list`, `incus list loss:`,
`incus network list loss:`, `incus profile list/show loss:…`,
`incus config show loss:<inst> --expanded`, `incus info loss:`,
`ssh loss '<read-only probes>'`, `incus exec loss:<fw0> -- cli -c "…"`.

#### 1.3.1 Instances

| Instance | Type | State | Profile(s) | Notes |
|---|---|---|---|---|
| `xpf-userspace-fw0` | VM | RUNNING | `bpfrx-cluster-userspace` ⚠ | 6 CPU / 8 GiB / 8×1 GiB hugepages (instance-level, §1.3.3) |
| `xpf-userspace-fw1` | VM | RUNNING | `bpfrx-cluster-userspace` ⚠ | same |
| `cluster-userspace-host` | container | RUNNING | `default` | LAN generator; `eth0` = SR-IOV `mlx1` VF, VLAN 3667 |
| `xpf-mouse-target` | container | RUNNING | `default` | WAN target #2, SR-IOV `mlx0` VF VLAN 80, `172.16.80.201` + `…80::201` **and also holds `.200`/`::200`** (see §1.5) |
| `cluster-lan-host` | container | RUNNING | `default` | legacy cluster LAN host (`10.0.89.102`) |
| `bpfrx-fw0`, `bpfrx-fw1` | VM | STOPPED | `bpfrx-cluster-loss` | legacy eBPF cluster — still defined; **do not resurrect under new names** (§6-R3) |
| `xpf-zone-matrix-dmz`, `ts-cc`, `u2604-eno2` | container | RUNNING | `default` | unrelated tenants sharing `incusbr0`/host — proof the host is shared, not dedicated |

⚠ **Profile-name drift (observed):** the env file says
`PROFILE="xpf-cluster-userspace"`, but the live profile is
`bpfrx-cluster-userspace` and no `xpf-cluster-userspace` profile exists
(`incus profile show loss:xpf-cluster-userspace` → *Profile not found*).
`cluster-setup.sh:create_profile` would **delete-and-recreate** a profile
under the env name on next `init` (`cluster-setup.sh:293-298`). Any new env
file must either adopt the live name or expect `init` to create a second,
unused profile. New clusters have no legacy profile, so this drift does not
carry over — but the new env files must be internally consistent from day one.

#### 1.3.2 Networks (`incus network list loss:` — bridges only; dozens of
physical/VF entries elided)

| Network | Type | Managed | IPv4 / IPv6 | Used by |
|---|---|---|---|---|
| `incusbr0` | bridge | yes | `10.136.126.1/24` NAT, `fd42:49f1:b041:fd8d::1/64` NAT | 8 (mgmt `fxp0` for all VMs + `ts-cc`/`u2604`) |
| `bpu-hb0` | bridge | yes | none / none | 3 — heartbeat (`em0`, node↔node control) |
| `bpu-fab0` | bridge | yes | none / none (bridge.mtu=9000 set by `create_networks`) | 3 — fabric (`fab0/fab1`, session sync) |
| `bpfrx-fab-loss`, `em0br` | bridge | yes | none | 3 each — legacy cluster fabric/heartbeat (**DOWN**, no carrier: legacy pair stopped) |

There is **no LAN bridge and no WAN bridge**: both are SR-IOV VFs straight
into the VMs (`NET_CLAN=""`). This is the "same fabric pattern" the new
clusters started from: 3 bridges (mgmt shared, hb+fab dedicated) + 2 SR-IOV
attachments per fw + 1 SR-IOV attachment for the LAN host. The new design
keeps the pattern but moves the fabric leg off its bridge onto E810 VFs
(§2.8.2-F), so the new clusters have 2 bridges (mgmt + heartbeat) + 3
SR-IOV attachments per fw (WAN, LAN, fabric).

#### 1.3.3 Per-instance devices / limits (from `--expanded`)

fw0 (fw1 identical except VF ids / MACs):

```
limits.cpu: "6"   limits.memory: 8GiB     # instance-level overrides
limits.hugepages.1GB: "8"  limits.memory.hugepages: "true"
raw.qemu: -global virtio-net-pci.rx_queue_size=1024
root: 20GB, pool default (dir, /var/lib/incus/storage-pools/default)
eth0: nic network=incusbr0  name=enp5s0     → guest fxp0 (DHCP, 10.136.126.113 fw0 / .134 fw1 observed)
eth1: nic network=bpu-hb0   name=enp6s0     → guest em0  (10.99.12.1/30 fw0, .2 fw1)
eth2: nic network=bpu-fab0  name=enp7s0     → guest fab0/fab1 (10.99.13.1/30, .2)
wan-vf: nic nictype=sriov parent=mlx0 security.mac_filtering=false   → guest ge-0/0/2 (fw0) / ge-7/0/2 (fw1); trunk, guest tags VLAN 50/80
lan-vf: nic nictype=sriov parent=mlx1 vlan="3667"                     → guest ge-0/0/1 / ge-7/0/1; access VLAN
image: Debian trixie amd64 20260318_05:24 (disk-kvm.img)               # see §1.6 drift note
```

Profile `bpfrx-cluster-userspace` itself only carries
`limits.cpu: "4"`, `limits.memory: 4GB`, the 3 bridge NICs + root disk; the
6 CPU / 8 GiB / hugepages are **instance-level config set out-of-band**
(nothing in `cluster-setup.sh:create_profile` writes them — grep confirms;
they were applied manually or by an older script version). **A fresh
`cluster-create` today would produce 4 CPU / 4 GiB, no hugepages** — the
userspace helper's current perf envelope (6 workers, §1.4) is not reproducible
from the script alone. The new env/profile must encode these (§5-S2).

LAN host: container, `default` profile, `eth0: nictype=sriov parent=mlx1
vlan=3667`, root on `default` pool; static
`10.0.61.102/24`, gw `10.0.61.1`, `IPv6AcceptRA=true`
(`/etc/systemd/network/10-cluster-lan.network`, written by
`create_lan_host`, `cluster-setup.sh:554-565`). Live: v6 SLAAC address from
RA prefix `2001:559:8585:ef00::/64` + default via link-local of reth1.
Tools present: `iperf3` (3.20), `ping`, `mtr`, `tcpdump` — matches the skill
note that the generator "only needs ping, mtr, iperf3".

#### 1.3.4 Firewall runtime (observed on fw0)

- `show chassis cluster status`: cluster-id 22, RG0/1/2 all `node0 primary
  (200) / node1 secondary (100)`, failover counts RG1=1, RG2=4.
- `show chassis cluster data-plane statistics`: helper
  `rust-afxdp-bootstrap`, `Enabled: true`, `Forwarding armed/supported: true`,
  `Workers: 6`, `Ring entries: 16384`, `poll-mode interrupt` (from conf
  `system.dataplane`), session table `12/786432`, flow cache `73728`,
  6 AF_XDP queues bound (`xdp_userspace_p` on `ge-0-0-1/2`).
- Guest interfaces: `fxp0` (mgmt DHCP), `em0` `10.99.12.1/30`, `fab0@ge-0-0-0`
  `10.99.13.1/30`, `ge-0-0-1` = reth1 child (`10.0.61.1`,
  `2001:559:8585:ef00::1`), `ge-0-0-2.50` (`172.16.50.8`,
  `2001:559:8585:50::8`), `ge-0-0-2.80` (`172.16.80.8`,
  `2001:559:8585:80::8`), `gr-0-0-0` `10.255.192.42/30` (GRE to
  `2602:ffd3:0:2::7`). Static defaults: v4 via `172.16.50.1`, v6 via
  `2001:559:8585:50::1` (conf:336-342).

#### 1.3.5 WAN side / targets (the part a new cluster cannot inherit)

- Upstream gateway `172.16.50.1` / `2001:559:8585:50::1` and
  `2001:559:8585:80::1` are **external lab routers** (not Incus instances;
  `loss` host itself has no route to `172.16.50/80` except via the fw —
  `ip route` on `loss` shows neither subnet). From `tcp` host,
  `ping 172.16.50.1` and `ping6 2001:559:8585:50::1` both succeed today
  (observed), so the WAN VLANs are reachable from the new hosts' *host*
  network at least at L3 via their own upstream — whether traffic from a
  *new fw's SR-IOV VF* will reach the same gateway depends on switchport /
  VF-VLAN plumbing (§6-R1, Q3).
- `172.16.80.200`/`…80::200` (elephant target): **external lab hardware**, no
  SSH, no Incus handle (`target-services.sh:35-43`). On `loss` today that
  address is *also* aliased onto `xpf-mouse-target` (`ip -br a` shows
  `172.16.80.200/24` and `2001:559:8585:80::200/64` on its eth0 alongside
  `.201`/`::201`) — i.e. the "external" target may in practice be answered
  by that container right now; the two must not be conflated when planning
  new targets (§6-R5).
- `xpf-mouse-target` service grid (observed `ss -tlnp`): iperf3 on
  `5200-5211` (one process per port), python echo on `6200-6211` + `7`.
  `mouse-target-setup.sh` is the provisioning path; `target-services.sh
  up/check` is the gate.
- GRE/sfmix (`gr-0-0-0`, `10.255.192.40/30`, dest `2602:ffd3:0:2::7`,
  peer `10.255.192.41`) is a *third* traffic path in the same config. The new
  stacks do not need it; §2.5 makes dropping it an explicit decision
  (recommendation: drop from v1 configs, keep the `sfmix` zone/policy out).

### 1.4 The two target hosts (observed)

| | `loss` (existing) | `tcp` (172.16.100.102) | `udp` (172.16.100.103) |
|---|---|---|---|
| Incus | 7.0.0, `server_name: loss`, not clustered | 7.0.1, `server_name: tcp` | 7.0.1, `server_name: udp` |
| Instances | 10 (above) | **0** | **0** |
| Storage pools | `default` (dir) | **none** (`incus storage list tcp:` empty) | **none** |
| Profiles | 3 + default | only `default` (**empty**: no devices) | only `default` (**empty**) |
| Networks | §1.3.2 | only physical/VF devices + `docker0`; **no `incusbr0`, no bridges at all** | same (not even `docker0`) |
| Host CPU/RAM/disk | Xeon D-2146NT, 16 thr, 125 GiB (34 used), 833 G disk (701 free) | Core Ultra 9 285HX, 24 thr, 246 GiB (11 used), 3.6 T NVMe (3.4 T free) | identical class, 246 GiB, 3.6 T |
| NICs | `mlx0`/`mlx1` ConnectX-6 **Lx 25 Gb/s** each (`0000:65:00.0/.1`, 32/32 VFs); `ix0` X722 10 Gb/s | Dual-port ConnectX-6 **Dx 100 Gb/s** (`mlx0`/`mlx1`) + dual-port E810 **25 Gb/s** (`ix0`/`ix1`) + 10 Gb/s mgmt (`rx1`) — full PF/VF map in §1.4.1 | Identical to `tcp` (same PCI layout, MACs differ) |
| Hugepages | fw VMs use 8×1 GiB (host must reserve) | `vm.nr_hugepages=0`, `HugePages_Total: 0` — **must be raised before fw VMs start** (§5-S1) | (not probed; assume same) |
| Reachability | — | pings `loss`, `172.16.50.1`, `2001:559:8585:50::1` OK | pings `loss` OK |

Consequences: the `tcp`/`udp` hosts are **greener than `loss` was** — there
is no storage pool, no mgmt bridge, and the `default` profile has no root
disk/NIC, so `cluster-setup.sh init/create` cannot be pointed at them as-is:
`incus launch --vm --profile …` will fail until a pool exists, and
`create_networks` only creates hb/fab (+ optional clan), assuming `incusbr0`
already exists (it is the *default-profile* network on loss, created by
`incus admin init`, which has evidently not been run to completion on
tcp/udp — `udp` even prints the "first time running Incus" hint when the
local socket is used). §5-S1 covers the host-prep delta explicitly.

Also observed: `tcp` host's many `eno*` VF interfaces carry DHCP addresses in
`172.16.15.0/20` and v6 in `2001:559:8585:fff1::/64` — these hosts sit on a
busy shared L2. Picking LAN/WAN VLAN ids and the LAN access VLAN for the new
clusters must be coordinated against that (§6-R2, Q4).

#### 1.4.1 Physical PF / VF inventory (observed 2026-10-21, both hosts)

Probed read-only over `ssh` (`lspci`, `/sys/class/net/*/device/sriov_*`,
`ethtool`, `ip link`, `devlink port`). `tcp` and `udp` are identical in
layout; only MAC addresses differ. **Detect PFs by PCI address, never by
interface name** (existing rule, §7 revision notes, now applied to four PFs).

| PF (host name) | PCI | Device / driver | Link | PF queues | VFs (`numvfs`/`totalvfs`) | VF driver in guest | VF queues |
|---|---|---|---|---|---|---|---|
| `mlx0` | `0000:02:00.0` | Mellanox MT2892 ConnectX-6 Dx, `mlx5_core`, fw 22.50.1002 | 100 Gb/s fibre, UP | 24 combined | 32/64 | `mlx5_core` | 11 combined |
| `mlx1` | `0000:02:00.1` | ConnectX-6 Dx port 2 (same card/switchid as `mlx0`) | 100 Gb/s fibre, UP | 24 combined | 32/64 | `mlx5_core` | 11 combined |
| `ix0` | `0000:03:00.0` | Intel E810-XXV for SFP, `ice`, fw 4.70 | 25 Gb/s fibre (`25000baseSR`), UP | 12 combined (24 max) | 8/128 | `iavf` | 16 combined |
| `ix1` | `0000:03:00.1` | E810-XXV-2 port 2 | 25 Gb/s fibre, UP | 12 combined | 8/128 | `iavf` | 16 combined |
| `rx1` | `0000:ac:00.0` | Realtek RTL8127, `r8169` | 10 Gb/s, UP — host mgmt `172.16.100.102/.103` | 1 | — (no SR-IOV) | — | — |
| `rx0` | `0000:ad:00.0` | Intel I226-LM, `igc` | DOWN (no carrier) | — | — | — | — |

Additional observed facts:

- PCIe: Mellanox PFs at 16.0 GT/s ×16, Intel PFs at 16.0 GT/s ×4. Neither
  link is PCIe-bottlenecked at its wire rate.
- MTU is 1500 everywhere today; hardware max is 9978 (Mellanox) / 9702
  (Intel), so MTU 9000 is available on any VF whose path needs jumbo
  (fabric candidate, §2.8.3).
- Single NUMA node (24 CPUs, node 0) on both hosts. No NUMA-locality
  constraint on AF_XDP worker pinning (contrast R8).
- VF MAC/spoof state today: Mellanox VFs `spoof checking off, trust off`;
  Intel VFs `spoof checking on, trust off`. The Intel state would reject
  the RETH virtual MAC until cleared (§2.8.4, R11).
- Embedded-switch (eSwitch/VEB) state, probed 2026-10-21b: all four fast
  PFs report `hwmode VEB` (`bridge link show`), and the Intel PFs report
  devlink `local_forwarding: enabled`. VF-to-VF traffic on the same PF
  with the same VF VLAN is therefore switched inside the NIC and does
  not traverse the host bridge or the uplink. This is the evidence that
  makes the E810 fabric design (§2.8.2 row F) possible; it was not
  assumed, it was read off both hosts.
- `loss` comparison: its `mlx0`/`mlx1` are ConnectX-6 **Lx at 25 Gb/s**
  (PCIe 8.0 GT/s ×8). The new Mellanox pair is 4× the loss wire rate;
  the loss baseline of 22–23 Gb/s (§2.5) is a 25G-class number and must
  not be carried over as the 100G expectation (§5-V3 note).

#### 1.4.2 Current VF occupancy — the pool is free for Incus, busy on the host

- Mellanox: all 32 VFs per PF exist as host netdevs (`eno1v0–31` on
  `mlx0`, `eno2v0–31` on `mlx1`), UP, holding only SLAAC v6 in
  `2001:559:8585:fff1::/64`. Receive counters ~14 MB each (broadcast).
- Intel: all 8 VFs per PF exist as host netdevs (`eno3v*` on `ix0`,
  `eno4v*` on `ix1`), UP, each with a DHCP v4 lease in `172.16.15.0/20`
  plus `fff1` SLAAC. Counters ~0.
- Incus sees every one of these as an unused `physical` network
  (`USED BY 0`); there are no instances to conflict with.
- [INFERENCE] This is the Ubuntu installer netplan claiming every
  interface with DHCP. An Incus `nictype=sriov` device cannot be
  allocated cleanly while the host still owns the VF netdev with
  addresses/routes. §5-S1 therefore includes an explicit VF-release
  step **before** `cluster-create`. Because Incus allocates *any* free
  VF on the parent (the plan pins no VF indices, §2.8 principle 2),
  the release must cover **all 32 VFs on each Mellanox PF** — releasing
  only the 6 that will eventually be used is not implementable, since
  which 6 Incus picks is not known in advance. The observed cost is
  low for Mellanox: its VFs carry no host v4 addressing (SLAAC v6
  only). The `ix0` VFs do carry DHCP v4 leases, so their release is the
  part Q12 must explicitly confirm; `ix1` VFs are not allocated in v1
  and stay host-owned untouched.
- VF headroom is not a constraint: each cluster needs 3 VFs on `mlx0`,
  3 on `mlx1`, and 2 on `ix0` (§2.8.2), against 32/64 and 8/128
  available. `sriov_numvfs` does **not** need raising.

#### 1.4.3 What the 2026-10-21 inspection could NOT establish

- **Switchport / VLAN-trunk mapping per PF.** Which of `mlx0`, `mlx1`,
  `ix0`, `ix1` is cabled/trunked to the fabric carrying VLAN 50/80 is
  unknown. The host's successful pings to `172.16.50.1` /
  `2001:559:8585:50::1` leave via `rx1` or an Intel-VF default route
  (`ip route get` shows `via 172.16.0.1 dev eno3v*`), **not** via any
  fast PF, so they prove nothing about the fast ports. Passive capture
  was blocked (SSH user has no passwordless sudo and no `CAP_NET_RAW`;
  no LLDP tooling installed). This is now the gating unknown for the
  §2.8 role assignment — see R1 (revised) and Q11.
- Whether the four fast ports land on one switch / one broadcast domain
  (all PFs and VFs receive `fff1` RAs, suggesting a shared L2) or on
  separate fabrics. If they share one L2, "WAN PF" vs "LAN PF" is a
  queue/driver separation, not an L2 separation, and the LAN access
  VLAN (Q4) is what actually isolates LAN traffic.
- Host netplan contents (`/etc/netplan/00-installer-config.yaml` is
  root-only) and therefore the exact VF-release mechanism for §5-S1.

### 1.5 How the loss config is seeded / differs per node

- **One file, both nodes.** `docs/ha-cluster-userspace.conf` is pushed
  verbatim to `/etc/xpf/xpf.conf` on both VMs by the raw deploy path
  (`cluster-setup.sh:938-958`): push conf → `rm -rf /etc/xpf/.configdb` →
  delete numbered rollback slots `xpf.conf.<N>` → write
  `/etc/xpf/node-id` (0 or 1) → `systemctl enable --now xpfd`. The deb path
  deliberately does **none** of that (preserves operator config,
  `cluster-setup.sh:746-750`); config changes on the deb path are pushed
  explicitly/separately. Plan must pick one seeding story per new cluster
  (§5-S5 recommends raw/fast for first bring-up, deb thereafter).
- Per-node deltas come only from `groups { node0 {…} node1 {…} }` +
  `apply-groups "${node}"`: hostname, `node 0|1`, `peer-address` /
  `fabric-peer-address` (mirrored `10.99.12.1↔.2`, `10.99.13.1↔.2`),
  `em0`/`fab0|fab1` addresses, and physical names (`ge-0/0/*` on node0 vs
  `ge-7/0/*` on node1). Everything else — RETH addresses, zones, policies,
  NAT, RA, static routes, `dataplane-type userspace` + `workers 6` — is
  shared. New configs follow the same rule: **stack deltas live in the shared
  section only via the env-selected conf file; node deltas stay in groups.**
- HA parameters: `cluster-id 22`, shared PSK
  (`authentication-key "xpf-lab-ha-psk-cluster-22-CHANGE-ME"` — lab value,
  must differ per new cluster, §5-S4), `reth-count 2`, heartbeat
  200 ms × threshold 5 on `em0`, `configuration-synchronize`, RG0 (control,
  200/100), RG1 (WAN reth0, interface-monitor on `ge-*/0/2`), RG2 (LAN reth1,
  monitor on `ge-*/0/1`), `gratuitous-arp-count 8`.
- Policies: `default-policy deny-all`; `lan→wan allow-all` (log
  session-init/close); `lan→sfmix allow-all`. NAT: interface-mode SNAT
  catch-alls (v4+v6) + one pool-SNAT rule for `10.0.61.240/28` →
  `172.16.80.7/32` ports 30000-30999 with `proxy-arp` on `reth0.80`
  (conf:250-320). DHCPv4 server on reth1 (`10.0.61.100-199`), embedded RA on
  reth1 (`ef00::/64`, lifetime 180, DNS `2001:4860:4860::8888`).

### 1.6 Images / provisioning actually used by the lab

- Script default: `IMAGE_VM=images:ubuntu/26.04/cloud`,
  `IMAGE_CT=images:ubuntu/26.04` (`XPF_BASE_RELEASE=26.04`, kernel ≥ 6.18
  floor asserted in `provision_vm`, `cluster-setup.sh:470-472`), then
  apt-installs the toolchain, writes sysctls (`bpf_jit`, forwarding,
  `init_on_alloc=0` grub drop-in + reboot), enables FRR/chrony, writes
  node-id. **Live VMs instead run `Debian trixie amd64 (20260318_05:24)`** —
  the running fleet predates/diverges from the current script defaults.
  [INFERENCE] Re-running `create` today would rebuild on Ubuntu 26.04, not
  reproduce the live Debian guests. For the new clusters this is fine
  (greenfield) but must be stated: **new fw/host images = whatever
  `cluster-setup.sh` produces at execution time (Ubuntu 26.04 cloud), not a
  clone of the live loss guests.** If bit-parity with loss is wanted, that is
  a separate decision (Q6) requiring pinning `IMAGE_VM/IMAGE_CT` to the
  Debian fingerprint `b04211c8…` (fw) / `42dc8dda…` (host) — which are local
  cached images on `loss` only and do not exist on tcp/udp.
- Production `scripts/image/bake.py` appliance images are **not** used by any
  cluster VM; do not bake for this plan unless Q6 decides otherwise.

### 1.7 Locking / shared-state hazard in the existing machinery

`cluster-setup.sh` mutating verbs re-exec through `with-cluster.sh`, which
uses the `cluster-lock.sh` default loss tuple
(`/var/worktrees/.cache/tmpdir/xpf-cluster.lock`, matching owner and epoch)
on the workstation running the script, regardless of `INCUS_REMOTE`.
With no per-cluster overrides, tcp/loss commands therefore serialize. For
parallel tcp+udp bring-up, and for every ordinary tcp/udp command, export
all three canonical `XPF_CLUSTER_LOCK` / `XPF_CLUSTER_OWNER` /
`XPF_CLUSTER_EPOCH` values from CLAUDE.md or the campaign skill before
invoking any self-locking command. Changing only the lock path is unsafe:
owner and epoch must use the same cluster-specific tuple. Loss commands
continue to use the exact default tuple; gates and ordinary commands must
never use different tuples for the same physical cluster. Without those
tcp/udp overrides, keep cells strictly sequential rather than implying they
can overlap.

---

## 2. Target design

### 2.1 Topology per new cluster (×2: `tcp`, `udp`)

```
                        ┌──────────────────── host: tcp (172.16.100.102) ────────────────────┐
                        │                                                                      │
  mgmt (operator)       │  incusbr-tcp (NEW bridge, §2.3)   bpu-tcp-hb0      ix0 VEB (fabric) │
  ──────────────────────┤   │ fxp0 (DHCP)                     │ em0     fab0/fab1 via VF VLAN  │       │
                        │   ▼                                 ▼       fab-vf on ix0, §2.8.2-F  │       │
                        │  ┌──────────────┐   heartbeat/fabric  ┌──────────────┐               │
                        │  │ xpf-tcp-fw0  │◄═══════════════════►│ xpf-tcp-fw1  │               │
                        │  │ xpfd +       │   RG0 control       │  (mirror)    │               │
                        │  │ xpf-userspace│   RG1 reth0 (WAN)   │              │               │
                        │  │ -dp, AF_XDP  │   RG2 reth1 (LAN)   │              │               │
                        │  └──┬───────┬───┘                     └──┬───────┬───┘               │
                        │     │ge-*/0/2 = VF on mlx0 (100G, trunk) │       │ge-*/0/1 = VF on  │
                        │     │ge-*/0/1 = VF on mlx1 (100G, T-LAN) │       │ mlx1 (100G, T-LAN)│
                        └─────┼───────┼────────────────────────────┼───────┼───────────────────┘
                              │VLAN50│VLAN80                      │       │
                              ▼      ▼                             ▼       ▼
                    upstream lab router (…50::1 / …80::1, EXISTING — §2.4, Q3/Q11)
                              │      │                                     │
                    TCP target addresses on VLAN50/80 (§2.2)      LAN: ┌───────────────┐
                    (external or NEW containers, §2.5)            │cluster-tcp-host│ VF on mlx1
                ┌────────────────┐                                │ iperf3 client  │ VLAN T-LAN
                │ xpf-tcp-target │ VF on mlx0, VLAN 80            │ TCP stack      │ aa00::/64
                │ iperf3 server  │ (§2.8.2)                       └───────────────┘
                └────────────────┘
        Fabric: fab-vf VFs on ix0 (25G Intel, PF-private VLAN, VEB-local, §2.8.2-F).
        ix1 (25G) reserved: capture / second target / spare. rx1 (10G) = host mgmt only.
        All forwarding/generator/target/fabric attachments are SR-IOV VFs (§2.8);
        no PF is passed through and no dataplane or fabric leg uses a bridge.
        (Only mgmt fxp0 and heartbeat em0 remain bridges.)
```
The `udp` cluster is byte-for-byte the same drawing with `tcp→udp`,
`aa00→ba00`, `::a→::b`, different cluster-id/PSK, different LAN VLAN and
LAN v4 subnet (§3). PF/VF assignment, VLAN mode, and queue/trust settings
for every leg are normative in §2.8; this drawing only shows topology.
**The VF-level diagram is §2.8.6** (host PF → VF → Incus device → guest
device → xpf interface, per lane) — this §2.1 sketch predates the VF
design and is not a substitute for it.

### 2.2 Where each ticket address lives (primary interpretation)

| Ticket address | Lives on | xpf object | Analogue today |
|---|---|---|---|
| TCP `2001:559:8585:50::a` | **fw RETH (active RG1 node only)** | `reth0 unit 50 family inet6 address 2001:559:8585:50::a/64` | `…50::8` (userspace) |
| TCP `2001:559:8585:80::a` | **fw RETH (active RG1 node only)** | `reth0 unit 80 family inet6 address 2001:559:8585:80::a/64` | `…80::8` |
| UDP `2001:559:8585:50::b` | fw RETH (udp cluster) | `reth0.50` `…50::b/64` | same |
| UDP `2001:559:8585:80::b` | fw RETH (udp cluster) | `reth0.80` `…80::b/64` | same |
| TCP `2001:559:8585:aa00::/56` | delegated LAN block | `reth1` `aa00::1/64` + RA prefix `aa00::/64`; block routed to fw upstream (§2.4) | `ef00::/64` on-link only |
| UDP `2001:559:8585:ba00::/56` | delegated LAN block | `reth1` `ba00::1/64` + RA `ba00::/64` | same |

Collision check against everything observed in loss confs/envs/scripts
(grep over `docs/ha-cluster*.conf`, `test/incus/*.{env,sh}`,
`scripts/*.sh`): `::a` (TCP), `::b` (UDP) on `50`/`80`, and the `aa00`/`ba00`
blocks, are **unused** (in-use: `::1` gateway, `::6` legacy VIP, `::7` legacy
loss RETH, `::8` userspace RETH, `::200/::201` targets, `ef00/df01/cf01`
LANs). The full `2001:559:8585::/32`-ish lab space is shared and flat, so
this check is necessary but not sufficient — §6-R2/Q5 asks for confirmation
that nothing outside this repo (e.g. the `fff1` / `100` tenant networks seen
on tcp/udp hosts) uses `aa00`/`ba00`.

Why RETH and not target: the addresses differ *per stack on the same two
subnets*. If they were targets, both stacks would still need fw RETH
addresses (unnamed in the ticket) and target addressing would collide with
the standing `::200` convention for no benefit. As RETH addresses they are
exactly the stack identity: *the TCP firewall is `::a`, the UDP firewall is
`::b`*, on both WAN VLANs, and they move with RG1 on failover (GARP /
unsolicited NA from the new primary — validation gate V6).

### 2.3 Isolation model — how the two stacks stay apart

Chosen: **physical/logical separation at every layer except the shared lab
WAN subnets**, in decreasing order of strength:

1. **Separate Incus servers** (`tcp:` vs `udp:` remotes) → separate hosts,
   CPUs (24 thr each), RAM, disks, SR-IOV PFs. A runaway UDP flood cannot
   starve the TCP cluster's dataplane workers. This is the main isolation
   and it is free (hosts already exist).
2. **Separate Incus projects? No — separate *servers*** makes projects
   redundant. Use `default` project on each (it is the only one; creating
   projects buys nothing when the whole daemon is dedicated). [Recommendation]
3. **Separate bridges per cluster** for the two legs that remain
   bridged, uniquely named (`bpu-tcp-hb0`, mgmt `incusbr-tcp`;
   `bpu-udp-*` likewise). Fabric is **not** a bridge in this design
   (item 8, §2.8.2-F): it is a PF-private VF VLAN on `ix0`, so there is
   no `bpu-*-fab0` network to name or collide. Even though bridges on
   different hosts cannot collide, unique names keep `incus network
   list` output and any future cross-remote tooling unambiguous, and
   mirror the `bpu-` prefix convention from loss.
4. **Separate LAN access VLANs** on `mlx1` per cluster (values TBD — Q4;
   loss uses 3666 legacy / 3667 userspace; new clusters need two unused ids,
   e.g. candidates 3668/3669 *only if* confirmed free on the switching
   fabric — do not assume). LAN v4 subnets likewise distinct (§3):
   candidates `10.0.62.0/24` (tcp) / `10.0.63.0/24` (udp), both free in all
   repo configs (in-use: `10.0.60/61/89`, `10.99.12/13`, `10.136.126`,
   `10.255.192.40/30`). ⚠ These candidates appear in one selftest fixture
   (`cluster-cell-selftest.sh` uses synthetic values) — re-grep before use.
5. **Separate HA identities**: distinct `cluster-id` (recommend **23** tcp /
   **24** udp; in-use: 2 legacy, 22 userspace), distinct PSK per cluster
   (`openssl rand -base64 32` at build time, never the loss lab string),
   distinct control/fabric subnets (§3: `10.99.14/15` tcp, `10.99.16/17` udp
   /30s — free in repo; loss uses `10.99.12/13` userspace, `10.99.2/3`
   legacy).
6. **Shared, deliberately**: the WAN VLANs 50/80 and their `/64`s +
   `172.16.50/80.0/24`. Both clusters attach to the same upstream broadcast
   domains (as loss-fw and loss-userspace already do simultaneously:
   `.7`/`::7` vs `.8`/`::8`). Isolation *within* the shared WAN is by
   address (RETH `::a` vs `::b`, v4 §2.5) and by ND/ARP, exactly as
   today. **Consequence to accept explicitly**: the two new clusters and the
   two loss clusters are L2 neighbours on VLAN 50/80; a misconfigured RETH
   (duplicate address, wrong VLAN tag) in one can disturb another. The
   validation §5-V0 therefore starts with passive ND/ARP collision checks
   before any xpfd starts.
7. **Not** separate routing instances inside one firewall (that's Alt-A,
   §2.7): xpf *supports* `routing-instances … virtual-router` (used today
   only for `sfmix`), but a two-VRF single-pair design would couple the
   stacks' failover, worker pool, and session sync — the opposite of the
   ticket's "separate … stacks".
8. **VF-level separation within the shared PFs** (§2.8): WAN and LAN do
   not share a PF (WAN VFs on the 100G `mlx0`, LAN VFs on the 100G
   `mlx1`), so WAN and LAN queues, eSwitch ports, and AF_XDP bindings
   are disjoint even though both legs are host-local hairpins. Fabric
   shares neither PF nor card with them: both fabric VFs sit on the
   25G Intel `ix0` with a PF-private VF VLAN (§2.8.2-F), so session
   sync is isolated from dataplane queues *and* from the Mellanox
   card's fate (R12). The Intel PFs carry no v1 *forwarding* (transit)
   traffic, so a future `iavf` incident cannot take down the dataplane;
   fabric rides the kernel `iavf` path, not AF_XDP. Per-VF VLAN
   enforcement is done by Incus (`nictype=sriov vlan=` for access
   ports, trunk + `security.mac_filtering=false` for the WAN VF),
   which re-applies it on every VM start — the durable fix for the
   2026-07-01 LAN de-isolation outage class (§2.8.4).

### 2.4 Routing for the /56s

#### 2.4.1 Inside the cluster (fw ↔ generator)

- `reth1` (RG2) carries `aa00::1/64` (tcp) / `ba00::1/64` (udp); embedded RA
  advertises that `/64` (on-link, autonomous), default lifetime 180,
  interval 10–30 — copied from `ha-cluster-userspace.conf:322-335` with the
  prefix swapped. Generator gets SLAAC address + default via reth1
  link-local, exactly as `cluster-userspace-host` does today
  (`IPv6AcceptRA=true`; validator already force-checks this pattern,
  `userspace-ha-validation.sh` + skill §"cluster-userspace-host is forced to
  keep accepting IPv6 RAs").
- Generator static addresses: `aa00::102/64` (tcp host) / `ba00::102/64`
  (udp host) set alongside SLAAC for deterministic test addressing,
  mirroring `LAN_ADDR/LAN_HOST_IP=…102` v4 convention.

#### 2.4.2 Upstream (WAN router ↔ fw) — the part that is NOT ours to configure silently

For a WAN-side node to reach the LAN `/56` (return traffic for routed — see
NAT note below — flows, and any WAN-initiated test), the existing upstream
router(s) owning `…50::1`/`…80::1` need, per stack:

```
# on upstream router (OWNER ACTION — Q3; NOT executed by this plan's build)
ipv6 route 2001:559:8585:aa00::/56 2001:559:8585:50::a    # TCP, via VLAN50 RETH
ipv6 route 2001:559:8585:ba00::/56 2001:559:8585:50::b    # UDP, via VLAN50 RETH
# (optionally the same via …80::a / …80::b as backup path; pick ONE primary to avoid ECMP asymmetry)
```

- If NAT interface-mode SNAT (v6) is kept from the loss template, LAN→WAN
  flows egress as the RETH address and return traffic needs **no** `/56`
  route — the `/56` route is then only for WAN-initiated / routed-no-NAT
  tests. Whether the new stacks NAT v6 at all is a real choice (§2.5, Q7);
  the loss template SNATs `::/0 → interface` (conf:306-309), which would
  make the delegated prefix nearly decorative. **Recommendation: keep the
  `/56` routed, and scope SNAT to v4 only (+ the pool-SNAT exercise rule),
  so the delegated prefix is genuinely exercised** — but flag that this
  deviates from the loss template and changes what "allow-all lan→wan"
  means for v6 (publicly routable LAN). Alternative (keep template as-is)
  is listed in §2.7 Alt-C.
- Carve discipline: only `aa00::/64` (resp. `ba00::/64`) is on-link in v1.
  Remaining `/64`s (`aa01::/64` … `aaff::/64`) are reserved inside the `/56`
  for future per-test LANs/DMZ without new upstream routes (the `/56` route
  already covers them; adding one later is fw+host config only). Do **not**
  advertise the whole `/56` in RA.
- fw static defaults stay as today: `::/0 via 2001:559:8585:50::1`,
  `0.0.0.0/0 via 172.16.50.1` (conf:338-339). No GRE static in v1 (§2.5).

### 2.5 What each stack's traffic looks like

**TCP cluster** (generator = client/source, WAN = server/target):

- Servers listen on the WAN side. Two target shapes, pick per Q3/Q8:
  (a) *External* existing targets on VLAN80 (`…80::200` grid) — zero build,
  but shared with loss clusters and semantically "someone else's target";
  (b) *New dedicated target containers* on each host (analogue of
  `xpf-mouse-target`: SR-IOV `mlx0` VF, VLAN 80, running
  `target-services.sh` grid iperf3 5200-5211 + echo 6200-6211). 
  **Recommendation: (b)**, named `xpf-tcp-target` / `xpf-udp-target`, at
  fresh addresses (§3: `…80::210` tcp / `…80::211` udp + v4 `172.16.80.210/211`
  — free per grep; in-use `.200/.201`, `.7/.8` RETH, `.1` gw). This keeps the
  "separate stacks" promise end-to-end and removes contention with loss runs.
- Client runs from the generator: TCP `iperf3 -c <target> -P 6 -t … -J`
  (defaults cloned from `userspace-ha-validation.sh`: `PARALLEL=6`,
  3 runs × 5 s fast gate), plus reverse (`-R`) cells — the AF_XDP fast path's
  quoted 22–23 Gb/s figure is a *reverse* P=12 number on loss (env:38-40),
  so the baseline expectations in §5-V3 are stated per-direction, not as one
  number.

**UDP cluster**:

- `iperf3 -u` is the primary tool but is **not** a throughput oracle by
  itself (it reports sender-side rate + receiver loss/jitter only with the
  server report; at multi-Gb/s it becomes host-CPU-bound). Plan three UDP
  load shapes (all from `cluster-udp-host`):
  1. `iperf3 -u -b <rate> -l 1400 -P N` rate-stepped sweep
     (1/5/10/20 Gb/s targets), judged on receiver loss% + fw counters (§5-V4);
  2. small-packet flood via the repo's existing generators
     (`test/incus/wire_probe_burst.py`, `wire_raw_tcp_burst.py` analogues /
     `newflow-gen`) where pps, not bps, is the stress;
  3. the deterministic one-way UDP burst gate pattern from
     `userspace-native-gre-validation.sh --udp` (path assertion, not remote
     iperf dependency) for failover cells.
- UDP target: `iperf3 -s -p 5201` (UDP shares the TCP port number on the
  server) on `xpf-udp-target`. TCP cross-checks still run on the UDP cluster
  at smoke level (a stack that *only* ever forwards UDP would hide TCP
  regressions; §5-V2 requires one TCP pass per cluster and one UDP pass per
  cluster, with the *deep* sweeps specialised).

**Dropped from v1 configs** (explicit, reversible): GRE `gr-0/0/0` +
`sfmix` VRF/zone/policies + the `2602:ffd3:0:2::/64` static (they exist for
the SFMIX/GRE test line, would need fresh tunnel addressing per stack, and
nothing in this ticket asks for GRE). Dropping them shrinks the config diff
vs. loss to: addressing, cluster-id/PSK, RA prefix, NAT-scope choice,
hostnames. If GRE parity is later wanted, it is an additive config change.

**IPv4 counterparts**: the ticket gives only v6. The loss template is
dual-stack everywhere; going v6-only would orphan `iperf3` v4 gates, ARP
validation, and every existing validator default (`MIN_GBPS_V4`, TTL/mtr v4
cells). **Recommendation: full dual-stack mirror** with stack-distinct v4
RETH addresses continuing the `.7`(legacy)/`.8`(userspace) sequence:
TCP RETH `172.16.50.10`/`172.16.80.10`, UDP `172.16.50.11`/`172.16.80.11`
(both pairs free per grep; `.1` gw, `.6` stale VIP in env — §6-R4).
**Superseded on VLAN 50 (#18558):** a grep of this repo cannot see hosts that
have no config here. A live ARP probe showed `.10` and `.11` held by non-xpf
lab devices, so the v4 RETHs moved to `.42` / `.43`. The VLAN 80 pair is
unaffected. See §3.3. Generator
v4: `10.0.62.102`/`10.0.63.102`, gw `.1`. Targets v4 as above. v4 LAN is
**not** part of the `/56` delegation story (no v4 delegation given); if a v4
delegated block is wanted it is Q7's second half.

### 2.6 Alternative reading (Alt-B): ticket addresses are WAN *targets*

If `::a/::b` were intended as target (server) addresses instead of RETH:
RETH addresses must then be invented (natural continuation `…50::9/…80::9`
tcp, `…50::10/…80::10` udp — wait, `::10` hex vs decimal ambiguity is itself
a trap; use `::c`/`::d` style letter suffixes to stay in the ticket's
idiom), targets become containers at `::a` (VLAN50) **and** `::a` on VLAN80 —
note the same suffix on two subnets means *two* target interfaces or one
dual-homed target, which the mouse-target precedent (single VLAN80 VF) does
not cover. This plan's §3 table is written so Alt-B is a mechanical
transform: swap the "fw RETH" rows with new target rows. **I do not
recommend Alt-B** without ticket confirmation, because it leaves the fw's
own WAN identity unspecified.

### 2.7 Alternatives considered

| Alt | Shape | Verdict |
|---|---|---|
| **Chosen** | Two clusters, one per existing empty remote; specialised load; dual-stack; routed `/56`, v4-only SNAT | Matches remote names + ticket addressing 1:1; isolation strongest; build = 2× known recipe. |
| Alt-A | One cluster (on `tcp:`), two LANs/VRFs (`routing-instances tcp/udp`), two generators | Halves build, but couples HA/workers/session-sync; "separate stacks" only logical; UDP flood can starve TCP flows in one AF_XDP pool; RG failover moves both stacks together — fails the separation intent. Rejected. |
| Alt-B | Ticket addresses = targets (§2.6) | Needs invented RETH addressing; hold pending Q1. |
| Alt-C | Chosen topology but keep loss NAT verbatim (v6 SNAT interface-mode) | `/56` route then unnecessary for LAN→WAN; delegated prefix untested by main flows. Only choose if the goal is *address-shape parity* with loss rather than exercising delegation. Flagged in Q7. |
| Alt-D | Build both clusters *on `loss:`* alongside existing (new VLANs/VFs) | Contradicts the existence of purpose-named empty remotes; `loss` has 16 thr and two live clusters already; VF budget `mlx0/mlx1` 32 each is fine but CPU is not (2 more fw VMs × 6 CPU + 2 hosts on a 16-thread box already running the canonical cluster). Rejected unless Q9 says the tcp/udp hosts are off-limits for VMs. |
| Alt-E | Bridge-based LAN/WAN (no SR-IOV) on new hosts | `cluster-setup.sh` supports bridge LAN (`NET_CLAN`) but WAN is SR-IOV-only in this machinery; bridge WAN would be new code + a perf cliff for AF_XDP. Rejected. |
| Alt-F | LAN or WAN on the 25G Intel PF (`ix0`/`ix1`, `iavf` VF) | Puts a 25 Gb/s cap on the whole LAN→WAN path (see §2.8.1), spends the only unproven AF_XDP driver (`iavf`) in the forwarding path, and inherits `spoof checking on` (§1.4.1). The 25G pair is worth more as fabric (`ix0`, v1) / capture / spare (§2.8.3) than as a bottleneck. Rejected for v1 forwarding; revisit only with the §2.8.5 AF_XDP smoke passed and a stated reason to need a third dataplane PF. Fabric on `ix0` is **not** Alt-F: it uses `iavf` as a kernel NIC, never AF_XDP. |
| Alt-G | PF passthrough (`type=pci` on a whole PF) for a firewall | Wastes a 100G port on one VM, removes the host eSwitch hairpin for generator/target on the same PF, and loses Incus re-application of VF VLAN/trust state on VM start (the loss machinery deliberately moved from raw PCI to `nictype=sriov` for this, §2.8.4). VFs give the same guest driver and queues at 1/32 of the port. Rejected. |

### 2.8 VF allocation — every leg is an SR-IOV VF (normative)

This section is the normative PF/VF assignment. §2.1 shows topology;
§3 carries the same VF assignment per node. If §3 and this section ever
disagree, this section wins and §3 is the bug.

**Principles.**

1. **VFs only.** No PF is passed through, no dataplane leg is a bridge,
   and the host keeps ownership of all four PFs (`mlx0`, `mlx1`, `ix0`,
   `ix1`). A VF gives the guest the native driver (`mlx5_core` /
   `iavf`), hardware queues, and eSwitch forwarding; the PF stays
   available for the host, for other VFs, and for `ethtool`/counter
   observability during validation (§6-V7).
2. **Allocate by PCI, name by role.** Env files set
   `SRIOV_PARENT`/`SRIOV_LAN_PARENT` from the PCI-derived PF identity
   (§5-S0 verifies `0000:02:00.0 → mlx0` etc. before any create), never
   from assumed interface-name order. Incus then allocates a free VF on
   that parent; the plan does not pin VF indices or VF PCI addresses
   (the loss machinery dropped `VF_WAN_PCI` pinning for the VM path —
   `cluster-setup.sh` WAN/LAN device comments). VF PCI addresses are
   recorded in the run record after create (§5-S3), not pre-assigned.
3. **Speed-matched legs.** End-to-end test throughput is
   min(generator→fw, fw→target). Any 25G leg caps the cell at 25G, so
   every leg of the measured path is a 100G Mellanox VF (§2.8.1).
4. **One PF per direction.** WAN VFs and LAN VFs never share a PF, so
   ingress and egress AF_XDP bindings, queues, and eSwitch ports are
   disjoint and a queue/ring fault on one side cannot starve the other.

#### 2.8.1 Why WAN and LAN are both 100G Mellanox

- The measured path is generator → (LAN VF) → fw → (WAN VF) → target.
  `loss` delivers 22–23 Gb/s on 25G Mellanox; that number is the 25G
  wire/eSwitch class, not an xpf ceiling. Putting either new leg on the
  25G Intel PF would silently reproduce the loss ceiling on 100G
  hardware and make every §5-V3/V4 result ambiguous ("was that xpf or
  the 25G leg?").
- Mellanox VF → guest `mlx5_core` is the proven AF_XDP surface (the
  whole loss userspace fleet). Intel VF → guest `iavf` is not proven
  for `xpf-userspace-dp` (R11); v1 does not put an unproven driver
  under the pass/fail gates.
- Both Mellanox PFs are ports of one ConnectX-6 Dx (PCIe ×16). Host-local
  legs hairpin in the eSwitch/PCIe fabric and do not consume wire
  bandwidth; the only leg that can consume wire bandwidth is WAN
  traffic that actually leaves toward the upstream router (Q11 decides
  whether that path exists per PF).

#### 2.8.2 VF allocation per cluster (×2 — same layout on `tcp:` and `udp:`)

| # | Consumer | Incus device | PF (PCI) | VLAN mode | Guest device | Driver / queues | AF_XDP? |
|---|---|---|---|---|---|---|---|
| W0 | `xpf-<stack>-fw0` WAN | `wan-vf` | `mlx0` (`0000:02:00.0`) | trunk, guest tags 50/80; `security.mac_filtering=false` | `ge-0/0/2` → reth0.50/.80 | `mlx5_core` / 11 | yes — dataplane |
| W1 | `xpf-<stack>-fw1` WAN | `wan-vf` | `mlx0` | trunk, as above | `ge-7/0/2` → reth0.50/.80 | `mlx5_core` / 11 | yes |
| L0 | `xpf-<stack>-fw0` LAN | `lan-vf` | `mlx1` (`0000:02:00.1`) | access `vlan=T-LAN` (Q4), enforced by Incus | `ge-0/0/1` → reth1 | `mlx5_core` / 11 | yes — dataplane |
| L1 | `xpf-<stack>-fw1` LAN | `lan-vf` | `mlx1` | access `vlan=T-LAN` | `ge-7/0/1` → reth1 | `mlx5_core` / 11 | yes |
| G | `cluster-<stack>-host` (generator) | `eth0` | `mlx1` | access `vlan=T-LAN` (same as L0/L1) | `eth0` | `mlx5_core` / 11 | no — kernel iperf3 |
| T | `xpf-<stack>-target` | `eth0` | `mlx0` | access `vlan=80` | `eth0` | `mlx5_core` / 11 | no — kernel iperf3 |
| M | fw0/fw1 mgmt | `eth0` (bridge `incusbr-<stack>`) | — | — | `fxp0` | virtio | no |
| H | fw0/fw1 heartbeat/control | `eth1` (bridge `bpu-<stack>-hb0`) | — | — | `em0` | virtio | no |
| F0 | `xpf-<stack>-fw0` fabric | `fab-vf` (profile `eth2`, `name=enp7s0`) | `ix0` (`0000:03:00.0`) | access `vlan=FAB-VLAN` (PF-private, §2.8.4), MTU 9000 | `ge-0/0/0` → `fab0` | `iavf` / 16 | **no — must never bind** |
| F1 | `xpf-<stack>-fw1` fabric | `fab-vf` (profile `eth2`, `name=enp7s0`) | `ix0` (same PF) | access `vlan=FAB-VLAN`, MTU 9000 | `ge-7/0/0` → `fab1` | `iavf` / 16 | **no — must never bind** |

Counts per host: **3 VFs on `mlx0`** (W0, W1, T), **3 VFs on `mlx1`**
(L0, L1, G), **2 VFs on `ix0`** (F0, F1), **0 VFs on `ix1` in v1**.
Against 32 allocated VFs per Mellanox PF (§1.4.2) this leaves ≥29 spare
VFs per PF for future per-test subnets inside the `/56` (§2.4.2) without
touching `sriov_numvfs`; `ix0` has 6 of 8 VFs spare. Env mapping:
`SRIOV_PARENT=mlx0` (WAN + target parent), `SRIOV_LAN_PARENT=mlx1`
(LAN + generator parent), `SRIOV_FABRIC_PARENT=ix0` +
`VF_FABRIC_VLAN=<FAB-VLAN>` (fabric parent/VLAN, §4 machinery item 6);
the target container reuses `SRIOV_PARENT` with `vlan=80` (§5-S3).
Candidate FAB-VLANs: **3990 (tcp) / 3991 (udp)** — distinct per host as
defence in depth even though the VLAN is PF-local (§2.8.4); both need
the Q11 confirmation that they are *not* allowed on the `ix0` uplink
trunk. This matches the loss env shape for WAN/LAN
(`SRIOV_PARENT="mlx0"`, `SRIOV_LAN_PARENT="mlx1"`) — only the
underlying silicon speed changes, plus the new fabric parent.

Traffic-path note: G→L and W→T are eSwitch hairpins on a shared PF
(same-host VF-to-VF), and F0↔F1 is a VEB hairpin on `ix0`
(`hwmode VEB` + `local_forwarding: enabled`, §1.4.1). That is
deliberate: it keeps generator, target, and fabric off the wire and
off the upstream router for the baseline cells, so a throughput
collapse is attributable to the firewall, not the lab fabric. Cells
that must traverse the real wire/upstream are the §2.4.2 routed cells
and depend on Q11.

#### 2.8.3 What the 25G Intel PFs are for

The Intel pair carries **no v1 transit (forwarding) traffic** (Alt-F),
but it is not idle: `ix0` carries the fabric in v1, and `ix1` is the
reserve. Assigned in order of value:

1. **v1: fabric on `ix0`** (rows F0/F1). One VF per firewall on the
   *same* PF, same PF-private VF VLAN, MTU 9000, replacing the
   `bpu-<stack>-fab0` bridge (the bridge remains the fallback if the
   fabric smoke in §6-V0 fails). Session sync gets dedicated hardware
   queues isolated from bridge/veth contention and from the Mellanox
   card (R12). Why this is safe in v1 while Alt-F is not: fabric
   traffic rides the kernel `iavf` stack (gRPC/heartbeat/session
   sync), never AF_XDP, so the unproven `iavf` AF_XDP surface (R11)
   is not exercised. Preconditions, all checked at V0: the dataplane
   queue planner must never AF_XDP-bind the fabric VF (the codebase
   already refuses fabric/tunnel members in the planner; this needs
   the live `Bound bindings` check), and ARP + session-sync counters
   must move between the two VFs (the spoof-check probe, §2.8.4).
   Heartbeat does **not** move: `em0` stays on its bridge so fabric
   and control never share a PF or a failure mode — 200 ms × 5
   control traffic gains nothing from 25G.
2. **Any phase: capture / mirror / cross-check on `ix1`.** A VF on
   `ix1` as a passive or active second target (e.g. a second target
   container on VLAN 80 via `ix1`) lets a suspicious result be re-run
   on a different PF/driver to separate "firewall" from "Mellanox
   path" — the attribution trick the mouse-target split (§1.2,
   MOUSE_TARGET) already uses at the address level, applied at the
   PF level.
3. **Spare capacity.** Second generator, per-test `/64` subnets
   (§2.4.2), or a future GRE/sfmix leg (Q10) can take `ix1` (or spare
   `ix0`) VFs without renumbering the v1 allocation.

`rx1` (10G Realtek) is host management only, in all phases. It is a
single-queue consumer NIC and must never carry test, fabric, or
heartbeat traffic.

#### 2.8.4 VF configuration rules (apply at create; verified at V0)

- **Trunk vs access is per-VF and Incus-enforced.** WAN VFs (W0/W1):
  no `vlan=` (trunk), guest tags reth0.50/.80,
  `security.mac_filtering=false` so the guest can source the RETH
  virtual MAC. LAN/generator VFs (L0/L1/G): `vlan=T-LAN` access,
  enforced by Incus on every VM/container start. Target VF (T):
  `vlan=80` access. Fabric VFs (F0/F1): `vlan=FAB-VLAN` access on
  `ix0`. Never set VF VLAN/trust out-of-band with
  `ip link set … vf …` on the host PF: that host-PF state is cleared
  on host reboot/PF reset and caused the 2026-07-01 LAN de-isolation
  outage; `nictype=sriov` re-applies it durably (machinery comment in
  `cluster-setup.sh`, WAN/LAN device creation).
- **Fabric VLAN is PF-private — terminology and the real condition.**
  FAB-VLAN is a VF access VLAN local to the `ix0` VEB (`hwmode VEB`,
  `local_forwarding: enabled`, §1.4.1): F0↔F1 frames are switched
  inside the NIC and the guest sends them untagged, so no xpf config
  carries the VLAN at all. It is *not* an 802.1Q private-VLAN on the
  uplink switch. Both fabric VFs must be on the **same PF** (`ix0`);
  splitting them across `ix0`/`ix1` would force traffic onto the wire
  and void the design. The privacy condition is that FAB-VLAN is
  **not allowed on the `ix0` uplink trunk** (Q11): known-destination
  fabric unicast is VEB-local regardless, but broadcast (ARP) tagged
  with an uplink-allowed VLAN could leak to the switch and, if the
  peer host used the same VLAN, cross-couple the two clusters —
  hence distinct candidates per host (3990/3991) *and* the trunk
  check. If the owner cannot confirm the trunk exclusion, the fabric
  falls back to the `bpu-<stack>-fab0` bridge (§2.8.3).
- **Spoof/trust.** Mellanox VFs already show `spoof checking off`
  (§1.4.1); the RETH MAC requirement is met via
  `security.mac_filtering=false`. Fabric VFs: set
  `security.mac_filtering=false` on `fab-vf` as well. The fabric MAC
  is the Incus-assigned VF MAC and xpf does not rewrite it (on loss,
  `fab0` inherits the `eth2` MAC), so `spoof checking on` is expected
  to pass — but expectation is not evidence: V0 must show fabric ARP
  resolving and session-sync counters (`Session create` received,
  `Errors 0`) moving. If they do not, spoof/trust on the `ice` PF is
  the first suspect (R11). Any clearing must be re-applied by Incus,
  not by a host one-off. If a future Intel VF enters any other
  guest-MAC-flexible role, the same rule applies.
- **Queues.** Guest Mellanox VFs present 11 combined queues; the
  dataplane planner stride is 16, so no over-stride reshape is needed
  and the 6 workers bind a subset. Fabric VFs present 16 combined
  queues (`iavf`) and are excluded from binding (row F), so their
  queue count is a kernel-path detail, not a planner input. Record
  the guest-visible queue counts (`ethtool -l`) at V0; if a *dataplane*
  VF ever presents >16 queues, the over-stride warning path applies
  and the result must be read with the `ethtool -x` reshape check,
  not assumed safe.
- **MTU.** WAN/LAN/generator/target VFs stay 1500 in v1 (matches the
  loss template and the upstream). Only the fabric VFs use 9000, and
  that requires the whole leg raised together: host PF `ix0` MTU
  9000 first (a VF cannot exceed its PF; `ix0` is 1500 today,
  §1.4.1), then the Incus device `mtu=9000`, then the guest. Raising
  the PF MTU does not disturb its 1500 host traffic.
- **Release before allocate.** Every VF Incus could allocate on
  `mlx0`/`mlx1`/`ix0` must be free of host networking first — in
  practice all 32 VFs per Mellanox PF and all 8 VFs on `ix0`
  (§1.4.2, §5-S1), because allocation is not pinned to indices. The
  `ix0` release additionally drops the 8 DHCP v4 leases in
  `172.16.15.0/20` (§1.4.2) — observed counters were ~0 and the
  addresses are installer artefacts, but Q12 must confirm no tenant
  depends on them. After Incus allocation the VF netdev disappears
  from the host; that disappearance is the expected success signal,
  not an error.

#### 2.8.5 Two different `iavf` smokes — do not conflate them

- **Fabric smoke (v1 gate, §6-V0).** The fabric VFs use `iavf` only as
  a kernel NIC: ARP between F0/F1 resolves, fabric ping works at MTU
  9000, session-sync counters move with `Errors 0`, and `Bound
  bindings` shows *no* fabric device bound. This is cheap and is part
  of first bring-up.
- **AF_XDP smoke (not a v1 gate).** Required only before Alt-F is
  revisited or any Intel VF joins the *forwarding* path: bind
  `xpf-userspace-dp` to a single `iavf` VF in a scratch VM, confirm
  `Forwarding supported: true` with all queues bound, pass one TCP
  and one UDP iperf cell, and confirm spoof/trust state survives a VM
  restart. Until that smoke exists on record, statements about 25G
  forwarding performance are speculation.

#### 2.8.6 Diagram — full interface map (per host)

`tcp` shown; `udp` is the identical layout with §3.2 substitutions
(U-LAN, FAB-VLAN 3991, `10.99.16/17`, `ba00::`, `::b`). `VF⟨n⟩` = VF id
allocated by Incus at create (§2.8 principle 2); the host netdev name
(`eno1v⟨n⟩` etc., §1.4.1) exists only *before* allocation and disappears
when Incus claims the VF.

```
 HOST tcp                                                                 GUEST / xpf
 ═══════════════════════════════════════════════════════════════════════════════════════

 PF mlx0  0000:02:00.0  ConnectX-6 Dx 100G, mlx5_core, VEB
   ├─ VF⟨n⟩ W0 ── incus wan-vf (trunk, mac_filtering=false) ─► fw0 ge-0/0/2 ─┐
   ├─ VF⟨n⟩ W1 ── incus wan-vf (trunk, mac_filtering=false) ─► fw1 ge-7/0/2 ─┤► reth0 (RG1)
   └─ VF⟨n⟩ T  ── incus eth0  (access vlan 80) ──────────────► target eth0   │  ├─ reth0.50
        host pool: eno1v0..31 · PCI 02:00.2 .. 02:04.1                      │  └─ reth0.80
                                                                             (AF_XDP, 11q)
 PF mlx1  0000:02:00.1  ConnectX-6 Dx 100G, mlx5_core, VEB
   ├─ VF⟨n⟩ L0 ── incus lan-vf (access vlan T-LAN) ──────────► fw0 ge-0/0/1 ─┐
   ├─ VF⟨n⟩ L1 ── incus lan-vf (access vlan T-LAN) ──────────► fw1 ge-7/0/1 ─┤► reth1 (RG2)
   └─ VF⟨n⟩ G  ── incus eth0  (access vlan T-LAN) ───────────► generator eth0│  LAN gw/RA/DHCP
        host pool: eno2v0..31 · PCI 02:08.2 .. 02:0c.1                      (AF_XDP, 11q)

 PF ix0   0000:03:00.0  E810-XXV 25G, ice/iavf, VEB + local_forwarding, MTU 9000
   ├─ VF⟨n⟩ F0 ── incus fab-vf/eth2 (access vlan 3990, 9000) ─► fw0 ge-0/0/0 ─► fab0
   └─ VF⟨n⟩ F1 ── incus fab-vf/eth2 (access vlan 3990, 9000) ─► fw1 ge-7/0/0 ─► fab1
        host pool: eno3v0..7 · PCI 03:01.0 .. 03:01.7     F0◄─VEB-local─►F1 (never uplink,
        kernel iavf path, session sync, NEVER AF_XDP-bound          never host bridge)

 PF ix1   0000:03:00.1  E810 25G ── no VFs allocated in v1 (capture / 2nd target / spare)
 PF rx1   0000:ac:00.0  Realtek 10G ── host mgmt 172.16.100.102 only, no VFs, no guests

 Bridges (no VF behind them)
   incusbr-tcp ── incus eth0 (enp5s0) ─► fw0+fw1 fxp0        mgmt zone, DHCP
   bpu-tcp-hb0 ── incus eth1 (enp6s0) ─► fw0+fw1 em0         RG0 heartbeat 200ms×5
   (there is NO fabric bridge; if the V0 fabric smoke fails, fallback adds bpu-tcp-fab0)

 Traffic:  generator ──G/mlx1 hairpin──► fw reth1 ═ AF_XDP ═► fw reth0 ──W/mlx0 hairpin──► target
           fab0 ◄────── F0/F1 VEB-local (ix0) ──────► fab1        heartbeat: em0 via bridge only
```

Reading the diagram against §2.8.2: rows W0/W1/T are the three `mlx0`
lanes, L0/L1/G the three `mlx1` lanes, F0/F1 the two `ix0` lanes, and
M/H the two bridge lanes. A lane crossing cards (e.g. a fabric VF on
`ix1`, or a LAN VF on `ix0`) is a build error and aborts at §5-S3.

---

## 3. Addressing table (complete; `[NEW]` = to create, all else exists)

### 3.1 TCP cluster — remote `tcp:` (host 172.16.100.102)

VF IDs (W0/W1/L0/L1/G/T) are the §2.8.2 allocation IDs. Every SR-IOV row
below is a VF on the named PF; no row is a PF passthrough.

| Node | Interface (Incus → guest) [VF] | v4 | v6 | Role |
|---|---|---|---|---|
| xpf-tcp-fw0 `[NEW]` | eth0→fxp0 (mgmt br) | DHCP from `incusbr-tcp` (expect `10.136.127.x/24` if `/24` mirrored — §5-S1 picks subnet) | — (mgmt v6 NAT optional; loss has `fd42:…::1/64`) | operator/SSH, deb fetch |
| | eth1→em0 (`bpu-tcp-hb0`) | `10.99.14.1/30` | link-local only | HA control (heartbeat 200 ms×5) |
| | eth2 (`fab-vf`, `name=enp7s0`)→ge-0/0/0→fab0 (**F0**: VF on `ix0` `0000:03:00.0`, VLAN **FAB-VLAN tcp=3990**‡, MTU 9000) | `10.99.15.1/30` | link-local only | fabric: session/config sync (child `ge-0/0/0`) |
| | wan-vf→ge-0/0/2 (**W0**: VF on `mlx0` `0000:02:00.0`, trunk) | — (parent) | `fe80::bf72:16:1` (RETH LL, shared) | AF_XDP WAN parent |
| | ↳ reth0.50 (VLAN 50, RG1) | `172.16.50.42/24` (was `.10`; foreign-held, #18558, §3.3) | **`2001:559:8585:50::a/64`** | WAN primary |
| | ↳ reth0.80 (VLAN 80, RG1) | `172.16.80.10/24` `[NEW]` | **`2001:559:8585:80::a/64`** | WAN target VLAN |
| | lan-vf→ge-0/0/1 (**L0**: VF on `mlx1` `0000:02:00.1`, VLAN **T-LAN**=TBD Q4) ↳ reth1.0 (RG2) | `10.0.62.1/24` (VIP) | `2001:559:8585:aa00::1/64` (VIP) | LAN gw + RA + DHCPv4 srv |
| xpf-tcp-fw1 `[NEW]` | eth0→fxp0 | DHCP | — | mirror |
| | eth1→em0 | `10.99.14.2/30` | — | `peer-address 10.99.14.1` |
| | eth2 (`fab-vf`, `name=enp7s0`)→ge-7/0/0→fab1 (**F1**: VF on `ix0`, same PF + FAB-VLAN as F0, MTU 9000) | `10.99.15.2/30` | — | `fabric-peer-address 10.99.15.1` |
| | wan-vf→ge-7/0/2 (**W1**: VF on `mlx0`, trunk) ↳ reth0.50/.80 | same RETH VIPs (held by RG1 primary) | same | standby until failover |
| | lan-vf→ge-7/0/1 (**L1**: VF on `mlx1`, VLAN T-LAN) ↳ reth1.0 | same LAN VIPs (RG2 primary) | same | standby until failover |
| cluster-tcp-host `[NEW]` | eth0 (**G**: VF on `mlx1`, VLAN T-LAN) | `10.0.62.102/24`, gw `10.0.62.1` | `2001:559:8585:aa00::102/64` static + SLAAC, gw via RA | TCP generator (iperf3 client) |
| xpf-tcp-target `[NEW]` | eth0 (**T**: VF on `mlx0`, VLAN 80) | `172.16.80.210/24`, gw `172.16.80.1` † | `2001:559:8585:80::210/64`, gw `…80::1` † | TCP server grid 5200-5211/6200-6211 |
| (upstream, existing) | lab router | `172.16.50.1`, `172.16.80.1` | `2001:559:8585:50::1`, `…80::1` | needs `aa00::/56 via …50::a` route added (Q3) |

† Target gateway: mouse-target today sits *on-link* on VLAN80 with (observed)
both `.200/.201`; its default route was not inspected. If the target must be
reached *through* the fw from the LAN (the test path is LAN→fw→WAN target
on-link), the target needs **no** default via the fw — it replies on-link to
the RETH / SNAT address. Only target-initiated traffic needs `…80::1`. Keep
target addressing on-link minimal (address + no default, or default via
`…80::1` if the lab router accepts it) and state it in the env file.

‡ FAB-VLAN (3990 tcp / 3991 udp) is a PF-private VF VLAN on `ix0`
(§2.8.4): it appears in no xpf configuration (guests send fabric frames
untagged), needs no upstream route, and must not be allowed on the
`ix0` uplink trunk (Q11). There is no `bpu-tcp-fab0` bridge.

### 3.2 UDP cluster — remote `udp:` (host 172.16.100.103) — deltas only

Identical structure; substitute: cluster-id **24**, PSK₂, bridges
`incusbr-udp` / `bpu-udp-hb0` (no fabric bridge — fabric is VF, below),
control `10.99.16.1/.2/30`,
fabric `10.99.17.1/.2/30`, LAN VLAN **U-LAN** (TBD, ≠ T-LAN), LAN
`10.0.63.1/24` VIP, host `cluster-udp-host` `10.0.63.102` +
`2001:559:8585:ba00::102/64`, reth1 `2001:559:8585:ba00::1/64` (RA
`ba00::/64`), RETH v6 **`2001:559:8585:50::b`** / **`2001:559:8585:80::b`**,
RETH v4 `172.16.50.43` (was `.11`; foreign-held, #18558, §3.3) / `172.16.80.11`, target `xpf-udp-target`
`172.16.80.211` / `2001:559:8585:80::211`, upstream route
`ba00::/56 via …50::b`. **VF layout is identical** (§2.8.2): W0/W1/T on
`mlx0` (`0000:02:00.0`), L0/L1/G on `mlx1` (`0000:02:00.1`), F0/F1 on
`ix0` (`0000:03:00.0`) with **FAB-VLAN 3991** — only the LAN access
VLAN and the FAB-VLAN change (U-LAN / 3991 for T-LAN / 3990).

### 3.3 Shared / pre-existing addressing (collision reference)

| Block | Owner today | New clusters must |
|---|---|---|
| `2001:559:8585:50::/64`, `172.16.50.0/24` | loss legacy RETH `.7/::7`, userspace `.8/::8`, gw `.1/::1`, standalone VM `xpf-fw` (`test/incus/xpf-test.conf`, pushed by `test/incus/setup.sh`) iface `.5/::5` + NAT64 pool `.14` + SNAT pool `.15` (both proxy-ARPed, #16473), legacy local cluster (`docs/ha-cluster.conf`, `xpf-cluster-fw{0,1}.conf`) RETH `.6/::6` + its fw0 NAT64 pool `.9` + SNAT pool / proxy-ARP `.12` (both proxy-ARPed, #16473) | add `.42/::a` (tcp), `.43/::b` (udp). They were `.10/.11` until #18558: a live ARP probe showed both v4 addresses held by **non-xpf** lab devices (see the note below this table), so v4 moved while v6 kept `::a/::b`. **Every address on this segment has exactly one stack owner (#16473): `.14`/`.15` are the standalone's alone and `.9`/`.12` the legacy local cluster's alone — never allocate them (or `.5`/`.6`) to another stack, and never move a pool back onto another stack's RETH (`.6`/`.7`/`.8`/`.42`/`.43`), or onto a foreign-held address (note below)** |
| `2001:559:8585:80::/64`, `172.16.80.0/24` | RETH `.7/.8`, targets `.200/.201` (+`::200/::201`), pool-SNAT `172.16.80.7` (userspace proxy-arp; also legacy-loss RETH `.7` — the documented, accepted overlap: the loss pair's RETH and its own SNAT pool are the same stack, and no second stack claims `.7` on VLAN 80) | add `.210/::210`, `.211/::211`; ⚠ do **not** reuse `172.16.80.7` pool — if pool-SNAT exercise is copied, allocate per stack (candidates `.12` tcp / `.13` udp — Q7) |
| `2001:559:8585:ef00::/64` + `10.0.61.0/24` | loss userspace LAN | untouched |
| `2001:559:8585:df01::/64` + `10.0.89.0/24` | loss legacy LAN | untouched |
| `10.99.12/13.0/30`, cluster-id 22 | loss userspace HA | new: `10.99.14-17`, ids 23/24 |
| VLAN 3666/3667 on `mlx1` (loss LAN) | loss clusters | new LAN VLANs TBD (Q4); **FAB-VLANs 3990/3991 are PF-private to each host's `ix0`** (§2.8.4) — no switch allocation, but must be confirmed *not* trunk-allowed on `ix0` uplinks (Q11) |
| `10.136.126.0/24` (`incusbr0` on loss) | mgmt for all loss VMs | new mgmt bridges on tcp/udp need their own subnets (suggest `10.136.127.0/24` tcp, `10.136.128.0/24` udp — free on those hosts; they are host-local NAT bridges so reuse would also work, but distinct aids log reading) |
| `2001:559:8585:100::/64`, `…fff1::/64`, `172.16.15.0/20`, `172.16.100.0/22` | host mgmt / tenant nets on tcp/udp/loss hosts | do not place any test addressing here |

**This segment is not xpf-only (#18558).** VLAN 50 is a shared lab network
with dozens of non-xpf hosts, mostly Ubiquiti gear in `.2`-`.36` and across
the rest of the /24. None of them has a config in this repo, so neither the
table above nor the #16473 config census can see them. Before giving any
stack an address here, probe it with RFC 5227 ARP (sender 0.0.0.0) from a
node on the segment and require **no** reply. Ask the lab owner to reserve
it as well: the segment's DHCP/IPAM is not under this repo's control.

The 2026-10-31 sweep (tcp fw1, 3 rounds over each /24) found these foreign
holders of addresses the shipped configs used:

| address | used by | foreign holder |
|---|---|---|
| `172.16.50.10` | tcp WAN RETH (moved to `.42`) | `18:e8:29:2c:13:7a` |
| `172.16.50.11` | udp WAN RETH (moved to `.43`) | `d8:b3:70:8c:f8:44` |
| `172.16.50.9`, `.12` | legacy local NAT64 / SNAT pools (#18574) | `2a:dd:35:a2:96:97`, `ac:8b:a9:df:fd:f3` |
| `172.16.50.14`, `.15` | standalone NAT64 / SNAT pools (#18574) | `f4:e2:c6:ea:d7:80`, `9c:05:d6:e1:f2:0f` |
| `172.16.80.200` | loss iperf target (not a stack claim) | answered by **both** `loss:xpf-mouse-target` (`10:66:6a:8b:91:a4`) and the external v6 target box (`f6:f0:06:10:77:d5`) (#18576) |

The full measured list is `foreignClaimed18558` in
`pkg/configstore/shared_segment_foreign_claim_18558_test.go`. That test fails
on any shipped claim of an address in the list. A duplicate makes the
upstream gateway's ARP entry flip between the two holders, which shows up as
periodic IPv4-only loss on the stack (20-50% on tcp, up to 80% on udp), with IPv6 clean.

**Renumbering a stack on the shared segment (#18558).** Deb deploys preserve
the live config, so changing an address in the repo changes nothing on the
running cluster until these steps run. Run them inside one lock cell
(`test/incus/with-cluster.sh`, with that cluster's lock tuple):

1. **Pick the address.** It must be unanswered: send RFC 5227 probes (sender
   0.0.0.0) for it from a node on the segment, and require that only the
   gateway's control probe is answered. `ha_wan_claim_probe` in
   `test/incus/ha-assurance-lib.sh` shows the frame. Then land the repo
   change, and register the address in the table above.
2. **Commit.** On the RG0 primary (config authority):
   `delete interfaces reth0 unit 50 family inet address <old>/24`,
   `set interfaces reth0 unit 50 family inet address <new>/24`, `commit`.
   Check for `commit complete`.
3. **Remove the old address.** On the RG1 owner, run
   `ip addr del <old>/24 dev <member>.50`, where `<member>` is
   `ge-0-0-2` on node0 and `ge-7-0-2` on node1. This step is needed because
   the commit never removes the old VIP (#18573). If you skip it, the owner
   keeps answering ARP for an address it no longer owns.
4. **Refresh the helper snapshot.** Use any further commit, or an RG1
   failover and failback. The commit's snapshot captured the stale old
   address, and interface-mode SNAT keeps using it (#18573). Then confirm
   that `show security flow session destination-prefix 1.1.1.1/32` shows
   `--> <new>/...`.
5. **Verify.** In `make test-connectivity`, the cell "WAN IPv4 <new> answered
   for only by this cluster" must PASS.

**Coexistence window.** Between the repo change merging and step 4 on a
cluster, master's env names `<new>` while the cluster still holds `<old>`:
- `test-private-rg` FAILs with "WAN VIP <new> missing".
- `wire-zone-matrix` routes the DMZ prober via the unheld `<new>`.
- The claim check and test-connectivity's claim cell report that no node
  holds `<new>` (VOID). So an external IPv4 FAIL stands, and is judged by the
  3-smoke rule in `docs/regression-test-matrix.md`.

Branches cut from the old master have the opposite mismatch once the live
renumber is done. Renumber immediately after the merge, and read those cells
as unattributable in between.

### 3.4 HA sync / fabric summary (per cluster)

RG0 control (em0 heartbeat + config sync), RG1 = reth0 WAN (monitor
`ge-*/0/2`), RG2 = reth1 LAN (monitor `ge-*/0/1`); fabric `fab0/fab1` over
`ge-*/0/0` child on the **fabric VF** (F0/F1 on `ix0`, §2.8.2) carries
session sync (observed on loss over the bridge equivalent:
Session create/close/config/bulk counters, `Errors 0`). Priorities 200/100
node0-preferred, `gratuitous-arp-count 8`, preempt **no** (observed
`Preempt no` — a failover is sticky until manual failback; validation must
not assume automatic failback). VF view (§2.8.2): RG1 monitors the `mlx0`
VFs (W0/W1), RG2 monitors the `mlx1` VFs (L0/L1) — a PF-level link loss
therefore fails over exactly one RG per PF, and losing the Mellanox card
loses both RGs (single card, two ports; accepted, §2.8.1) **but not the
fabric**: F0/F1 sit on the Intel card, so session sync survives a
Mellanox-card failure and dies only with `ix0` or the host itself.

---

## 4. Repo changes the build will need (for approval; none made)

These are the *only* code/repo artifacts the build adds; everything else is
Incus/host state. Listed so the approver sees the footprint:

1. `test/incus/tcp-userspace-cluster.env`, `test/incus/udp-userspace-cluster.env`
   (clones of `loss-userspace-cluster.env` with §3 values; `INCUS_REMOTE=tcp|udp`,
   `VM0/VM1/LAN_HOST`, `PROFILE=xpf-cluster-tcp|udp` — fresh names, no legacy
   `bpfrx-` prefix; `VF_LAN_VLAN`, `NET_*`, `CLUSTER_CONF`, `LAN_*`, `IPERF_*`,
   plus new `TARGET_*` vars for the dedicated target containers and
   `XPF_CLUSTER_LOCK`, `XPF_CLUSTER_OWNER`, and `XPF_CLUSTER_EPOCH` per §1.7
   (`/var/worktrees/.cache/tmpdir/xpf-cluster-<stack>.lock`,
   `/var/worktrees/.cache/tmpdir/xpf-cluster-<stack>.owner`, and
   `/var/worktrees/.cache/tmpdir/xpf-cluster-state/epoch-<stack>`). **VF contract
   in each env (normative, §2.8.2): `SRIOV_PARENT=mlx0` (verified as PCI
   `0000:02:00.0` at S0), `SRIOV_LAN_PARENT=mlx1` (PCI `0000:02:00.1`);
   no `VF_WAN_PCI`/`VF_LAN_PCI` pinning (Incus allocates free VFs);
   the target container's parent is spelled out as `mlx0` + `vlan=80`
   in §5-S3 so it cannot silently inherit a future env change.**
2. `docs/ha-cluster-tcp.conf`, `docs/ha-cluster-udp.conf` (clones of
   `docs/ha-cluster-userspace.conf` with §3 deltas, GRE/sfmix removed, NAT per
   Q7, cluster-id/PSK, RA prefix). Config seed = these files; per-node
   difference remains only `groups node0/node1` + `/etc/xpf/node-id`.
3. (Optional, recommended) `scripts/tcp-udp-cluster-validation.sh` — thin
   parameterisation of `userspace-ha-validation.sh` by env (it already takes
   `--env`; a wrapper that runs TCP gate then UDP gate with per-stack targets
   avoids forking the 980-line validator). Do **not** copy-paste the validator.
4. Makefile: **no change required** — `make CLUSTER_ENV=test/incus/tcp-userspace-cluster.env cluster-deploy`
   already routes correctly (Makefile:1463-1478). Optionally add
   `tcp-cluster-*`/`udp-cluster-*` alias blocks mirroring `loss-cluster-*`
   (Makefile:1565-1599) for ergonomics.
5. `test/incus/target-services.sh` / `mouse-target-setup.sh`: reuse as-is
   against new target instances (they are env-driven via `TARGET_V4` /
   `MOUSE_TARGET_*`); no edits expected. [INFERENCE — verify `INCUS_REMOTE`
   handling in mouse-target-setup at build time; target-services defaults
   `INCUS_REMOTE=loss` (`target-services.sh:82`) so the env must override it.]
6. **`test/incus/cluster-setup.sh`: SR-IOV fabric support (the only
   machinery change).** Today the fabric is hardwired as a bridge:
   `NET_FABRIC` is always created by `create_networks`
   (`cluster-setup.sh:136-137,261-276`) and the profile's `eth2` is
   always `network: ${NET_FABRIC}` (`create_profile`,
   `cluster-setup.sh:319-322`). Add an opt-in, default-off path mirroring
   the SR-IOV LAN pattern (`SRIOV_LAN_PARENT`): when
   `SRIOV_FABRIC_PARENT` is set (new envs set it to `ix0`, verified by
   PCI at S0), (a) `create_networks` skips the fabric bridge, (b)
   `create_profile` emits `eth2` as
   `name: enp7s0, nictype: sriov, parent: ${SRIOV_FABRIC_PARENT},
   vlan: ${VF_FABRIC_VLAN}, mtu: 9000, security.mac_filtering: false`
   (keeping `name: enp7s0` so the guest PCI slot and the xpf rename to
   `ge-*/0/0` are unchanged), and (c) `NET_FABRIC` may be empty without
   tripping the `NETWORKS` loop. When `SRIOV_FABRIC_PARENT` is unset,
   generated networks/profile must be byte-identical to today, so
   `loss` is unaffected; that identity is the unit/regression test for
   the slice (existing cluster-setup selftests + a dry `cluster-init`
   profile diff on the loss env). New envs also set
   `VF_FABRIC_VLAN=3990` (tcp) / `3991` (udp). No change to the
   WAN/LAN VF paths, which already work this way.

---

## 5. Build sequence (ordered; exact commands; approval gate before S1)

Conventions: run from repo root on this workstation. `sg incus-admin -c '…'`
wrapping follows the repo scripts' own re-exec behaviour — invoke the scripts
and let them re-exec; raw `incus` below assumes the group already applies
(the scripts do this at `cluster-setup.sh:52-60`). Replace `<STACK>` ∈
`{tcp, udp}`, `<REMOTE>` likewise. **Each numbered step lists its abort
condition.** Steps S1–S3 are per-host; S4+ per cluster; the two clusters may
proceed in parallel *only* with distinct locks (§1.7) and only after S0.

### S0 — Pre-flight decisions & collision sweep (no state change)

```bash
# Close Q1-Q13 (§7) in writing on the ticket. Then, read-only:
incus list loss: && incus list tcp: && incus list udp:            # tcp/udp still empty
grep -rnE '2001:559:8585:(aa|ba)00|::a/64|::b/64|172\.16\.(50|80)\.(10|11)\b|10\.0\.6[23]\.|10\.99\.1[4-7]\.' \
  docs test scripts Makefile                                     # expect: no hits outside this plan
# PF identity by PCI (all four fast PFs, both hosts — §1.4.1; expect the exact map below):
for h in tcp udp; do ssh $h 'for d in 0000:02:00.0 0000:02:00.1 0000:03:00.0 0000:03:00.1; do
  echo "$d -> $(ls /sys/bus/pci/devices/$d/net/) speed=$(cat /sys/bus/pci/devices/$d/net/*/speed) numvfs=$(cat /sys/bus/pci/devices/$d/sriov_numvfs)/$(cat /sys/bus/pci/devices/$d/sriov_totalvfs)"; done'; done
#   expect: 02:00.0->mlx0 100000 32/64 · 02:00.1->mlx1 100000 32/64 · 03:00.0->ix0 25000 8/128 · 03:00.1->ix1 25000 8/128
# VF occupancy baseline (§1.4.2 — record which host netdevs the §2.8 VFs will replace):
ssh tcp 'ip -br link | grep -cE "^eno[12]v"; ip -br link | grep -cE "^eno[34]v"'
ssh udp 'ip -br link | grep -cE "^eno[12]v"; ip -br link | grep -cE "^eno[34]v"'   # expect 64 and 16 (all VFs host-bound today)
ssh tcp 'cat /sys/class/net/mlx0/device/sriov_numvfs; cat /sys/class/net/mlx1/device/sriov_numvfs; free -g; df -h /'
ssh udp 'cat /sys/class/net/mlx0/device/sriov_numvfs; cat /sys/class/net/mlx1/device/sriov_numvfs; free -g; df -h /'
# Switchport evidence (Q11 — pick whichever the fabric owner supports; host pings via rx1 do NOT count, §1.4.3):
#   switch-side: show interfaces trunk / mac-address-table for the four PF MACs (mlx0/mlx1/ix0/ix1, from `ip -br link`)
#   host-side (needs sudo): sudo tcpdump -i mlx0 -c5 -nn -e vlan ; sudo lldpctl (if lldpd is installed at S1)
#   fabric specifically: FAB-VLANs 3990/3991 must be ABSENT from the ix0 uplink allowed list (§2.8.4) — record the allowed list, not an assurance
# E810 fabric preconditions (re-confirm on the build day, both hosts; observed 2026-10-21b, §1.4.1):
for h in tcp udp; do ssh $h 'bridge link show ix0; devlink dev param show pci/0000:03:00.0 name local_forwarding'; done
#   expect: hwmode VEB ; local_forwarding value enabled — if either differs, fabric falls back to the bridge (§2.8.3) and §4 item 6 is not used
```
Abort if: any proposed address/VLAN/cluster-id is claimed, the PCI→PF map
differs from §1.4.1 on either host, or the upstream owner (Q3/Q11) has not
confirmed (a) VLAN 50/80 trunked to the `mlx0` switchport and (b) the `/56`
routes. **If VLAN 50/80 turn out to be trunked to an Intel port instead of
`mlx0`, stop: that swaps the §2.8 PF assignment and re-opens Alt-F — it is
a plan revision, not a field improvisation.**

### S1 — Host prep per new host (root on tcp, then udp) `[NEW STATE]`

Why: §1.4 — no pool, no mgmt bridge, empty default profile, no hugepages.

```bash
ssh tcp   # (repeat on udp)
sudo incus admin init --minimal        # REVIEW its preseed first: creates default pool + incusbr0
#   If --minimal's defaults are unwanted, do it manually instead:
#   sudo incus storage create default dir
#   sudo incus network create incusbr-tcp ipv4.address=10.136.127.1/24 ipv4.nat=true ipv6.address=none
#   (name it incusbr-tcp / incusbr-udp per §2.3; then set NET_MGMT accordingly in the env file —
#    cluster-setup.sh never creates NET_MGMT, it only references it.)
echo 8 | sudo tee /proc/sys/vm/nr_hugepages        # 8×1GiB for fw VMs (match loss fw limits); persist in /etc/sysctl.d/99-xpf-hugepages.conf
#   (verify: grep HugePages_Total /proc/meminfo  → 8; if the host uses 2MiB pages by default, use the equivalent count)
ls -l /sys/bus/pci/devices/0000:02:00.0/net/mlx0 /sys/bus/pci/devices/0000:02:00.1/net/mlx1
# confirm PCI 0000:02:00.0 -> WAN PF mlx0 and 0000:02:00.1 -> LAN PF mlx1; derive SRIOV_PARENT from PCI identity, not interface-name order.
# --- VF release (§1.4.2/§2.8.4): free ALL Mellanox VFs + all ix0 VFs from host networking (Incus allocates any free VF; indices are not pinned) ---
sudo cat /etc/netplan/00-installer-config.yaml     # READ FIRST (root-only today): confirm the DHCP-on-everything hypothesis (§1.4.2)
# Remove/ignore every eno1v*/eno2v* (mlx0/mlx1 VF) AND every eno3v* (ix0 VF) interface, so no host DHCP/SLAAC state fights whichever VFs Incus picks.
# Exact mechanism depends on the netplan found above (match the VF interfaces by their PCI parent, not by eno*v name order); invariants:
#   - all 64 Mellanox VFs end with no host addresses and no routes (they carry only SLAAC v6 today — no v4 tenant state to lose)
#   - all 8 ix0 VFs end with no host addresses (this DROPS their 172.16.15.0/20 DHCP leases — Q12 must confirm they are installer artefacts, §2.8.4)
#   - all four PFs and all 8 ix1 VFs keep their current host networking untouched (ix1 is not allocated in v1)
#   - the change survives a host reboot (edit netplan + `sudo netplan apply`; a bare `ip link set down` does not)
ip -br addr | grep -E '^eno[123]v'                 # re-check after apply: expect NO addresses on any eno1v*/eno2v*/eno3v* (was: fff1 SLAAC on 64, DHCP on 8)
# Do NOT raise sriov_numvfs (32/64 and 8/128 already ≥ needed per PF, §1.4.2).
# Do NOT set any VF vlan/trust/spoof by hand on the PF — Incus owns that from S3 onward (§2.8.4).
# --- Fabric PF MTU (§2.8.4): raise ix0 to 9000 so fabric VFs can carry MTU 9000 (PF is 1500 today) ---
sudo ip link set ix0 mtu 9000                      # persist alongside the netplan edit above (same reboot-survival requirement)
ip -d link show ix0 | grep -o 'mtu [0-9]*'         # expect mtu 9000; PF host traffic at 1500 is unaffected
```
Abort if: `incus admin init` proposes clustering or a non-`dir` pool driver
that doesn't match the plan (dir is what loss uses; btrfs/lvm would change
disk provisioning in `create_profile`). Abort the VF release if the netplan
does not match the §1.4.2 hypothesis (e.g. VFs are individually pinned by
MAC for a tenant workload) — re-scope which VFs are safe to release with
the host owner instead of guessing.

### S2 — Author the repo artifacts (§4 items 1-2, plus item 6 machinery)

Write the two env files and two conf files with exactly the §3 values.
The envs must carry the fabric contract as well as WAN/LAN:
`SRIOV_FABRIC_PARENT=ix0`, `VF_FABRIC_VLAN=3990` (tcp) / `3991` (udp),
and no fabric bridge name is consumed when the fabric parent is set.
Land §4 item 6 (`cluster-setup.sh` SR-IOV fabric, default-off) **before**
S3 and prove its loss-invariance: profile/network output for the loss
env is byte-identical with the change deployed (§4 item 6 test).
Profile-level resource fix (from §1.3.3 drift): after `init` (S3), set the
userspace envelope on the instances, since `create_profile` hardcodes
4 CPU/4 GiB and nothing sets hugepages:

```bash
# (in the build, after create; encode in a small per-cluster post-create step or do by hand)
incus config set tcp:xpf-tcp-fw0 limits.cpu=6 limits.memory=8GiB limits.hugepages.1GB=8 limits.memory.hugepages=true
incus config set tcp:xpf-tcp-fw1 limits.cpu=6 limits.memory=8GiB limits.hugepages.1GB=8 limits.memory.hugepages=true
incus config set tcp:xpf-tcp-fw0 raw.qemu='-global virtio-net-pci.rx_queue_size=1024'   # fw1 likewise
```
PSK generation (per cluster, at authoring time, kept identical on both nodes
because it lives in the shared section):
`openssl rand -base64 32` → `authentication-key` in the stack's conf;
record in the ticket (lab PSK, but not the loss one, and not in git history
beyond the conf itself — the loss conf commits its lab PSK in-tree at
`docs/ha-cluster-userspace.conf:69`, so in-tree is the established lab
practice; follow it or use the ticket, approver's call).

### S3 — Create networks + profile + instances (per cluster)

```bash
export XPF_CLUSTER_LOCK=/var/worktrees/.cache/tmpdir/xpf-cluster-tcp.lock
export XPF_CLUSTER_OWNER=/var/worktrees/.cache/tmpdir/xpf-cluster-tcp.owner
export XPF_CLUSTER_EPOCH=/var/worktrees/.cache/tmpdir/xpf-cluster-state/epoch-tcp
# UDP shell instead exports:
#   XPF_CLUSTER_LOCK=/var/worktrees/.cache/tmpdir/xpf-cluster-udp.lock
#   XPF_CLUSTER_OWNER=/var/worktrees/.cache/tmpdir/xpf-cluster-udp.owner
#   XPF_CLUSTER_EPOCH=/var/worktrees/.cache/tmpdir/xpf-cluster-state/epoch-udp
make CLUSTER_ENV=test/incus/tcp-userspace-cluster.env cluster-init     # bpu-tcp-hb0 bridge + SR-IOV fabric profile (§4 item 6; NO bpu-tcp-fab0), profile xpf-cluster-tcp
make CLUSTER_ENV=test/incus/tcp-userspace-cluster.env cluster-create   # fw0/fw1 VMs (SR-IOV wan+lan+fabric VFs) + cluster-tcp-host
incus list tcp:                                          # expect fw0, fw1, cluster-tcp-host
make CLUSTER_ENV=test/incus/tcp-userspace-cluster.env cluster-status
# VF allocation audit (§2.8.2/§2.8.4 — record in the run record; VF PCI addrs are allocated, not pinned):
incus config show tcp:xpf-tcp-fw0 --expanded | grep -A4 -E 'wan-vf|lan-vf|eth2'   # wan parent=mlx0 trunk / lan parent=mlx1 vlan=<T-LAN> / eth2 sriov parent=ix0 vlan=3990 mtu=9000 name=enp7s0
incus config show tcp:xpf-tcp-fw1 --expanded | grep -A4 -E 'wan-vf|lan-vf|eth2'   # fw1 likewise (fabric VF on the SAME ix0 PF + VLAN as fw0)
incus network list tcp: | grep -E 'bpu-tcp'              # expect bpu-tcp-hb0 ONLY — a bpu-tcp-fab0 bridge means §4 item 6 did not engage; abort
ssh tcp 'ip link show mlx0 | grep -E "vf [0-9]" | grep -v "00:00:00:00:00:00" ; ip link show mlx1 | grep -E "vf [0-9]" ; ip link show ix0 | grep -E "vf [0-9]"'
#   expect: exactly the allocated VFs detached from host networking (netdev gone host-side);
#   LAN VFs show the access VLAN on the PF, WAN VFs show no PF-side VLAN (guest-tagged trunk);
#   both fabric VFs show vlan 3990 on ix0 with spoof state as configured (§2.8.4).
incus exec tcp:xpf-tcp-fw0 -- bash -c 'ethtool -l ge-0-0-2; ethtool -l ge-0-0-1; ethtool -l ge-0-0-0; ip -d link show ge-0-0-0'   
#   dataplane queues expect 11 (§2.8.4); fabric expect iavf 16 queues, MTU 9000, and the device present as ge-0-0-0 (not shifted) — §2.8.3 V0 preconditions
```
`create` provisions: Ubuntu 26.04 cloud image, apt toolchain, sysctls,
≥6.18 kernel + mlx5 assert, `init_on_alloc=0` grub + reboot, node-id files
(`cluster-setup.sh:338-574`). Then apply the S2 instance limits (VMs must be
stopped or restarted to grow hugepages: `incus restart tcp:xpf-tcp-fw{0,1}`).
Abort S3 if any VF lands on the wrong parent (e.g. WAN VF on `ix0`, or the
two fabric VFs on *different* PFs), if a LAN/fabric VF comes up without
its access VLAN on the PF, if a `bpu-<stack>-fab0` bridge was created
anyway, or if the guest queue count differs from §2.8.4 without an
over-stride assessment — these are allocation bugs, and proceeding would
validate the wrong topology.

Dedicated WAN target (not part of `cluster-setup.sh`; analogue of
`mouse-target-setup.sh`):
```bash
incus launch images:ubuntu/26.04 tcp:xpf-tcp-target -s default       # container
incus config device add tcp:xpf-tcp-target eth0 nic nictype=sriov parent=mlx0 vlan=80   # VF T (§2.8.2): mlx0 access VLAN 80; parent spelled out, not inherited
incus exec tcp:xpf-tcp-target -- bash -c 'ip addr add 172.16.80.210/24 dev eth0; ip -6 addr add 2001:559:8585:80::210/64 dev eth0'
TARGET_V4=172.16.80.210 INCUS_REMOTE=tcp ./test/incus/target-services.sh up   # starts iperf3 5200-5211 + echo grid if instance-managed
./test/incus/target-services.sh check                                 # all 24 ports from the LAN host's vantage (script probes from LAN host)
```

### S4 — Config push & first deploy (per cluster)

First bring-up via the raw path (it pushes the conf + clears config DB +
verifies helper sha — the only path that seeds config, §1.5):

```bash
make CLUSTER_ENV=test/incus/tcp-userspace-cluster.env cluster-deploy XPF_DEPLOY_FAST=1
# = build + build-ctl + build-userspace-dp, then cluster-setup.sh deploy all:
#   secondary-first rolling raw deploy, config push to both, node-id assert,
#   xpfd.service + transit/input-closed units, live-binary sha verification.
make CLUSTER_ENV=test/incus/tcp-userspace-cluster.env cluster-status
incus exec tcp:xpf-tcp-fw0 -- cli -c 'show chassis cluster status'
incus exec tcp:xpf-tcp-fw0 -- cli -c 'show chassis cluster data-plane statistics'   # expect Forwarding supported: true, workers 6
```
Subsequent code updates use the default deb path
(`make … cluster-deploy`, no `XPF_DEPLOY_FAST`) and, when config itself
changes, an explicit conf push — because deb deploy preserves config by
design (`cluster-setup.sh:746-750`). State this in the cluster's runbook
line in the env file header.

### S5 — Upstream & WAN wiring confirmation (owner-assisted; Q3/Q11)

- Confirm the **`mlx0` switchport** (PCI `0000:02:00.0`, §1.4.1) on each of
  tcp/udp carries VLAN 50 + 80 trunked to the same upstream as loss (the fw
  WAN VF W0/W1 is a trunk; tagging is guest-side reth). If the trunk lands
  on a different PF than `mlx0`, stop and revise §2.8 (see S0 abort) —
  do not silently move the WAN VF.
- Upstream owner adds §2.4.2 `/56` routes (one primary next-hop each).
- From each fw (active node): `ping 172.16.50.1`, `ping6 2001:559:8585:50::1`,
  `ping6 2001:559:8585:80::1`, and ND table shows the gateway MAC; from
  upstream: `ping6 2001:559:8585:50::a` (tcp) etc. — this also proves no
  other tenant already answers those addresses (collision tripwire).

### S6 — Validation (§6) then handover

Run V0→V6 in order; do not run TCP and UDP deep sweeps simultaneously on
first validation (shared upstream VLANs; you want attributable baselines).
Record baselines via the harness ledger exactly as loss does
(`make CLUSTER_ENV=… test-connectivity` etc. are env-parameterised already).

---

## 6. Validation (smoke gates; expected results & counters)

> Threshold philosophy: the loss validator's `MIN_GBPS_V4/V6=18.0` is a
> *target for the loss tree state*, not a law of nature (skill:
> userspace-ha-validation). For greenfield clusters, V3 records **measured
> baselines** on first pass; the 18 Gb/s figure becomes the gate only from
> the second run onward, per stack, per direction. Zero-throughput intervals
> (not retransmit counts) are the failover failure signal (skill:
> userspace-native-gre-iperf).
>
> VF note (2026-10-21): 18 Gb/s is a **25G-class** number from the loss
> Mellanox (§1.4.1). On the 100G VF allocation (§2.8) it is a floor for
> "not obviously broken", not a performance expectation. Run-1 baselines
> must state the cell's limiting leg explicitly (all v1 cells are
> eSwitch-hairpin cells on 100G VFs, §2.8.2); a baseline near 22–23 Gb/s
> on this hardware is a finding to explain (queues? workers? generator
> CPU?), not a pass to file away.

| Gate | Command (per cluster; `ENV=test/incus/<stack>-userspace-cluster.env`) | Pass criteria |
|---|---|---|
| **V0 — idle/collision + VF audit + fabric smoke** | Before first `cluster-start`: passive `tcpdump -i mlx0 vlan 50/80` on host for ND NS/NA + ARP for `::a/::b`, `.10/.11`; `incus exec <fw0> -- cli -c 'show chassis cluster status'` after start; §5-S3 VF audit (parents, PF-side VLANs, guest `ethtool -l`); fabric: `ping` the fabric peer `/30`, ARP check, `show chassis cluster data-plane statistics` session-sync counters (§2.8.5 fabric smoke) | No foreign NA/ARP answers for new addresses; RG0/1/2 node0-primary; `Forwarding supported: true`, `Bound bindings` = all WAN+LAN VF queues **and no fabric device bound**; helper PID alive on **both** nodes; every VF on its §2.8.2 parent with its §2.8.4 VLAN mode; fabric ARP resolves both ways at MTU 9000, session-sync `Session create` received increments with `Errors 0` (if ARP/sync fails, suspect `ice` spoof state per §2.8.4 — do not proceed to V1) |
| **V1 — L2/L3 smoke** | From generator: `ping -c3 10.0.6x.1`, `ping6 -c3 <aa|ba>00::1`, `ping -c3 172.16.50.1`, `ping6 -c3 2001:559:8585:50::1`, `ping6 -c3 …80::1`, `rdisc6 -1 eth0` (if RA default missing), `mtr -1` to `1.1.1.1` + `2607:f8b0:4005:814::200e` (TTL-expired probes: exit 1 *with* time-exceeded is PASS) | All replies; v6 default via RA present (`ip -6 r`); first hop resolved in mtr; zero `policy_denied` increments for these flows in helper stats |
| **V2 — cross-protocol smoke** | TCP cluster: one UDP pass `iperf3 -u -c <target> -b 1G -t 10`; UDP cluster: one TCP pass `iperf3 -c <target> -t 10` | Both complete; proves neither stack is accidentally protocol-pinned (zones are `application any`) |
| **V3 — TCP deep (TCP cluster)** | `BPFRX_CLUSTER_ENV=$ENV ./scripts/userspace-ha-validation.sh` (3×5 s, P=6, v4 `172.16.80.210` + v6 `…80::210` overrides via `V4_TEST_TARGET/V6_TEST_TARGET`); plus `-R` reverse cells | No run collapses (`iperf-json-metrics.py`: no zero interval, tail-ratio ≥ 0.35); baseline recorded run-1, ≥18 Gb/s gate from run-2; sessions visible: `show security flow session` count rises/falls cleanly |
| **V4 — UDP deep (UDP cluster)** | Rate sweep `iperf3 -u -b {1,5,10,20}G -l 1400 -P {1,4}`; small-packet pps cell (repo burst gen); receiver report parsed from iperf JSON | Loss < 1% at/below the knee rate (record the knee); fw helper counters: `transit_drop`/`early_filter` deltas explained (policy/NAT), no unexplained loss; `show chassis cluster data-plane statistics` session entries track UDP flows and expire |
| **V5 — HA failover mid-flow** | Long `iperf3` (TCP cluster) / `iperf3 -u` (UDP cluster) running; `incus exec <fw-active> -- cli -c 'request chassis cluster failover redundancy-group 1 node <other>'` (RG1; repeat RG2 separately; RG0 control move last) | Flow continues on new primary (TCP: no zero-throughput interval in JSON stream; UDP: loss burst bounded to the failover window only); RETH addresses answer from the new node (unsolicited NA/GARP observed on host tcpdump); session-sync counters (`Session create` received) increment on the new primary, `Errors` stays 0; **no automatic failback** (preempt no) — reset primary manually and note it |
| **V6 — NA/ND & RA** | `ndisc6`/ping the RETH v6 from target + upstream; kill RA (stop xpfd on active) briefly and watch generator default expire (lifetime 180) and return; `ip -6 neigh` on fw for generator/target/gw | ND resolves for `::a/::b` and LAN `::1`s from all neighbours; RA re-advertises within interval after failover (RG2 move carries RA source); no duplicate-address detection events in `journalctl -u xpfd` |
| **V7 — counters snapshot** | Before/after each gate: `cli -c 'show chassis cluster data-plane statistics'`, `show security flow session summary`, host `ip -s link` + `ethtool -S` on the **PFs** (`mlx0`/`mlx1` — VFs are detached host-side) | Attach the snapshots to the run record, labelled by PF and VF allocation ID (§2.8.2); deltas reconcile with iperf bytes (± framing); `Degraded path counters` show no growth in `transit_drop` beyond explained drops; PF error/drop counters stay at zero |

Negative gate (cheap, do once per cluster): from the *other* stack's
generator, ping this stack's LAN prefix — must be unreachable (no route /
policy), proving stack separation is real and not just addressing cosmetics.
And from the WAN target, attempt `iperf3` to the LAN host's *other*-stack
address — same expectation.

---

## 7. Risks & open questions for the user

### Risks (with evidence)

- **R1 — WAN plumbing on the new hosts is unproven (revised 2026-10-21).**
  Loss's WAN is two SR-IOV PFs into a lab fabric where VLAN 50/80 + the
  `…50::1` gateway exist. Physical mapping: `mlx0` = PCI `0000:02:00.0`
  (WAN PF), `mlx1` = PCI `0000:02:00.1` (LAN PF), `ix0`/`ix1` = PCI
  `0000:03:00.0/.1` (25G Intel, reserved §2.8.3) — S0/S1/S5 MUST address
  PFs by PCI (`/sys/bus/pci/devices/0000:02:00.*/net/` etc.), never by
  assumed interface name (udev order is not contractual). The 2026-10-21
  probes (§1.4.3) showed the host's pings to `172.16.50.1`/`…50::1`
  leave via `rx1`/Intel-VF default routes, so **no fast PF is yet proven
  to reach the WAN VLANs at all**; switchport trunk state per PF is
  unknown (no sudo/`CAP_NET_RAW`/LLDP available to the probing user).
  A VF passed to a VM with guest VLAN tagging may land on the wrong
  VLANs (switchport mode, VF trust/`mac_filtering=false` semantics,
  spoof-check differ per fabric). First fw bring-up may forward nothing
  WAN-side until the fabric owner confirms trunk config. Mitigation:
  S0 switchport evidence + V0/V1 ordering; do S5 before S6; Q11 gates
  the §2.8 PF assignment.
- **R2 — Address/VLAN collisions outside the repo.** `2001:559:8585::/…` is a
  shared lab allocation (hosts themselves use `…100::`, `…fff1::`,
  `172.16.15.0/20`, `172.16.100.0/22`). `aa00/ba00`, `::a/::b`, LAN
  VLAN candidates, `10.0.62/63`, `10.99.14-17`, cluster-ids 23/24 are free
  *in every repo artifact I grepped* — but the authoritative allocator (if
  any) is out-of-repo. S0's grep + V0's passive listen are the tripwires;
  they do not replace asking the lab owner.
- **R3 — Shared WAN broadcast domains.** All four clusters (2 legacy/live on
  loss + 2 new) neighbour on VLAN 50/80. A typo'd RETH address in a new conf
  (e.g. `::8` instead of `::a`) would ARP/ND-fight the production-ish userspace
  cluster. The conf files are 400-line clones — diff them against
  `docs/ha-cluster-userspace.conf` and review the diff hunks only; the
  addressing lines are the whole delta (plus §2.5 removals).
- **R4 — Stale precedents in the source material.** `loss-userspace-cluster.env`
  `WAN_VIP4=172.16.50.6` vs conf `172.16.50.8` (fixed #16468: env now .8, hermetic
  cell `TestClusterEnvVIPsMatchClusterConf16468` guards every cluster env); profile name
  `xpf-cluster-userspace` (env) vs `bpfrx-cluster-userspace` (live);
  `IMAGE_VM` Ubuntu-26.04 (script) vs Debian-trixie (live guests);
  profile 4 CPU/4 GiB (script) vs 6 CPU/8 GiB+hugepages (live). Each is a
  place where "copy what loss does" is ambiguous. This plan resolves each
  explicitly (§1.3.1, §1.6, S2); the approver should confirm those
  resolutions rather than re-derive them at build time.
- **R5 — The `.200` target ambiguity.** `xpf-mouse-target` on loss holds v4
  `.200` (pinned by `mouse-addr.service`). It does not hold `::200`. That
  address is configured on the container but `dadfailed tentative`, checked
  read-only on 2026-10-31 (`ip -6 addr show dev eth0`); #16213 first found
  it. It belongs to the external box (`target-services.sh`).
  **Measured 2026-10-31 (#18576):** v4 `.200` is ALSO answered by that
  external box (`f6:f0:06:10:77:d5`). So the loss smoke's v4 target is
  dual-held, not just ambiguous by name. Its v6 target is a different host
  from its v4 target. If the new clusters' tests ever point at
  `.200` "because loss does", they may be measuring an SR-IOV container on
  loss, not the external box. The plan's dedicated `.210/.211` targets
  eliminate this for the new stacks; do not "reuse the existing target to
  save time" without deciding which `.200` you mean.
- **R6 — UDP load realism.** `iperf3 -u` at high rates is host-bound and its
  loss numbers conflate generator/target CPU with dataplane loss. The V4
  knee-finding + fw counter reconciliation is the guard; dedicated UDP
  tooling (e.g. a pktgen/`newflow-gen`-class sender) may still be needed if
  the question is "can the dataplane do X Mpps UDP" rather than "does UDP
  forward correctly under HA". Approver to state which question the UDP
  cluster exists to answer (affects Q8).
- **R7 — One workstation, one lock, two clusters.** §1.7: parallel `make`
  cells will serialise (or, with distinct `XPF_CLUSTER_LOCK`, proceed but
  share the workstation's build CPU for `make deb`). Also the whole plan is
  driven from this workstation's Incus remotes over TLS to
  `172.16.100.102/103` — if those hosts are themselves VMs/containers in
  someone else's system (the `ts-cc` tenant on loss hints at shared
  infrastructure), VM-in-VM SR-IOV may not be available at all. **This is
  the cheapest thing to check and the most expensive to discover late**
  (Q9).
- **R8 — Hugepages on new hosts (NUMA resolved 2026-10-21).** Both hosts
  show `HugePages_Total: 0`; fw VMs configured for 8×1 GiB hugepages will
  fail to start until S1 is done, and silently underperform if THP
  substitutes. NUMA is **not** a risk: the 2026-10-21 probe confirmed a
  single NUMA node (24 CPUs) with all PFs on it (§1.4.1), so AF_XDP worker
  pinning has no locality constraint.
- **R9 — Time sync.** Loss fw0 already warns: "cluster clock has no `system
  ntp server`; fabric RPC fails past 30s skew". New confs should carry an
  explicit `system ntp server` (chrony is enabled by provisioning) rather
  than inherit the warning.
- **R10 — Host-bound VFs fight the allocation (new 2026-10-21).** Every VF
  on all four fast PFs currently has a host netdev with DHCP/SLAAC state
  (§1.4.2). If `cluster-create` runs without the §5-S1 release, Incus may
  fail to allocate, allocate a different VF than the audit expects, or
  leave host routes that make pre-flight pings "succeed" through the host
  stack while the guest VF forwards nothing — a false-green bring-up.
  Mitigation: S1 release of all Mellanox + `ix0` VFs with a counted
  re-check (zero host addresses left on `eno1v*`/`eno2v*`/`eno3v*`),
  S3 VF audit before any deploy.
- **R11 — `iavf`: kernel path in v1 (fabric), AF_XDP still unproven
  (revised 2026-10-21b).** Intel VFs present as `iavf` in the guest with
  `spoof checking on, trust off` (§1.4.1). In v1 they carry only the
  fabric (§2.8.3), as a kernel NIC — the failure modes are therefore
  the small ones: spoof-check dropping fabric ARP (checked at V0 with
  sync counters as the oracle, §2.8.4/§2.8.5), and an `iavf` driver
  fault degrading session sync while heartbeat (`em0`, bridge) and
  the dataplane keep running. The big one — unproven AF_XDP on `iavf`
  plus the RETH-MAC spoof problem — is inherited only by a future
  Alt-F/second-target promotion. Mitigation: V0 fabric smoke +
  planner-never-binds proof are hard gates; the §2.8.5 AF_XDP smoke
  remains a hard precondition for any forwarding promotion.
- **R12 — Single Mellanox card is a shared fate (revised 2026-10-21b).**
  `mlx0` and `mlx1` are two ports of one ConnectX-6 Dx. A card/PCIe
  failure takes WAN and LAN together, so RG1 and RG2 fail over (or the
  cluster degrades) as a unit despite being on "different PFs". This is
  accepted for v1 (the alternative — a dataplane leg on the 25G card —
  costs more in throughput and driver risk than it buys, §2.8.1).
  Fabric on `ix0` (§2.8.3) removes session sync from that fate: a
  Mellanox-card failure degrades forwarding/HA but the peers can still
  sync state over the Intel card. The symmetric fate now exists on
  `ix0`: losing that one PF loses the fabric (both VFs are on it by
  design, §2.8.4) while heartbeat and fabric-peer reachability via
  `em0` survive. Reviewers should confirm both acceptances explicitly
  rather than discover them during a failover test.

### Open questions (need user/owner answers; defaults in *italics* are what §2-§5 assume)

- **Q1 (reading)** — Are `::a/::b` the firewalls' RETH WAN addresses (§2.2,
  *assumed*), or WAN target addresses (Alt-B, §2.6)?
- **Q2 (reading)** — Is "`/56` delegated/LAN prefix" = "LAN side of the fw"
  (*assumed*), or a block delegated *through* the fw to a downstream router/DHCPv6-PD
  client behind the generator host? (xpf has DHCPv6-PD machinery —
  `prefix-delegating` in `pkg/config/compiler_interfaces.go:797` — so true PD
  is implementable, but it is a different test design with a PD client I have
  not scoped.) If true PD is wanted, §2.4/§3/V-gates need a PD section.
- **Q3 (upstream)** — Who owns `…50::1/…80::1` routing + the tcp/udp
  switchports, and will they (a) trunk VLAN 50/80 to the new hosts' `mlx0`
  PF (`0000:02:00.0`, §2.8 — per-port detail is Q11),
  (b) add `aa00::/56 via …50::a` and `ba00::/56 via …50::b`? *Assumed yes
  with owner assist at S5; without (b), `/56` is LAN-local only and
  WAN-initiated tests are out of scope.*
- **Q4 (LAN VLANs)** — Which two access VLANs on `mlx1` for T-LAN/U-LAN?
  (*Candidates 3668/3669 only if the fabric owner confirms free; loss uses
  3666/3667.*) Also confirm mlx1 on tcp/udp reaches the same LAN fabric —
  the generator and both fw LAN VFs are all on the *same host* per cluster,
  so the VLAN only needs to be consistent host-locally… *unless* the target
  or upstream must also see it (they must not — LAN stays host-local by
  SR-IOV VF pinning; state this explicitly if agreed).*
- **Q5 (allocation)** — Confirm `aa00::/56`, `ba00::/56`, `…50/80::a/b/ab`,
  `172.16.50/80.10-13`, `172.16.80.210/211`, `10.0.62/63.0/24`,
  `10.99.14-17/30`, cluster-ids 23/24 against the lab's real allocator.
- **Q6 (images)** — Greenfield Ubuntu 26.04 from current `cluster-setup.sh`
  (*assumed*), or Debian-trixie parity with the live loss guests (requires
  copying image fingerprints to tcp/udp and pinning `IMAGE_VM/IMAGE_CT`)?
- **Q7 (NAT)** — Keep loss NAT verbatim incl. v6 interface SNAT (Alt-C), or
  routed v6 with v4-only SNAT so the `/56` is exercised (*recommended*)?
  And: v4 delegated block needed, or v4 stays NAT-only (*assumed NAT-only*)?
  If pool-SNAT exercise is wanted per stack, confirm `.12/.13` pool addresses.
- **Q8 (targets)** — Dedicated per-stack target containers `.210/.211`
  (*recommended*), or reuse external `.200` (and accept R5)? For UDP: is
  `iperf3 -u` sufficient evidence, or is a pps-class generator in scope (R6)?
- **Q9 (hosts)** — Are `tcp`/`udp` hosts bare-metal under our control (root,
  rebootable, SR-IOV VF passthrough to QEMU VMs permitted, hugepage sysctl
  changeable)? *Assumed yes from Incus/SSH evidence; R7 makes this the
  first confirmation to get.*
- **Q10 (scope)** — Is GRE/sfmix parity wanted in v1? (*Assumed no, §2.5.*)
  Is IPv6-only with v4 removed acceptable instead of dual-stack mirror?
  (*Assumed no — dual-stack, §2.5.*) Should the two clusters also run the
  loss cluster's full harness ledger (`test-failover`, `test-connectivity`,
  …) as regression tenants, or only §6's gates?
- **Q11 (switchports — gates §2.8)** — For each host, which switchport does
  each fast PF (`mlx0`, `mlx1`, `ix0`, `ix1` by PCI/MAC) land on, and which
  VLANs are trunked/allowed on each? *Assumed in §2.8: VLAN 50/80 trunked
  to `mlx0` (`0000:02:00.0`); the LAN VLANs (Q4) need only host-local
  eSwitch consistency on `mlx1`; and **FAB-VLANs 3990/3991 are NOT
  allowed on the `ix0` uplink** (§2.8.4 — the fabric-privacy condition).
  If 50/80 land on an Intel port instead, §2.8 and Alt-F must be
  re-decided before S1 (see S0 abort); if 3990/3991 *are* allowed on the
  `ix0` uplink, pick different FAB-VLANs or fall back to the fabric
  bridge.* Evidence accepted: switch `show trunk`/MAC-table output
  (allowed-list per port, recorded verbatim), or a sudo passive
  capture per PF at S0.
- **Q12 (VF release)** — May the build release **all 64 Mellanox VFs +
  all 8 `ix0` VFs** per host from host networking at S1, by editing the
  root-only netplan so the release survives reboot? (*Assumed yes.*)
  The all-of-PF scope is required because Incus allocates any free VF
  and the plan pins no indices (§1.4.2). Observed Mellanox VFs carry
  only SLAAC v6 (no v4 tenant state); `ix0` VFs carry DHCP leases in
  `172.16.15.0/20` with ~0 counters — confirm those leases are
  installer artefacts nobody depends on. All PFs and all `ix1` VFs
  keep host networking. If any released VF is in fact pinned to a
  tenant workload, say which — the fallback is to pin VF indices in
  the Incus devices instead, which is a §2.8 principle change, not a
  tweak.
- **Q13 (25G — fabric phasing, decided pending confirmation)** — The
  2026-10-21b revision puts fabric on `ix0` **in v1** (§2.8.3), with
  `ix1` as capture/second-target/spare and the Intel pair still out of
  the forwarding path. *Confirm this stands.* If reviewers instead
  want the bridge fabric for v1, the change is mechanical (do not set
  `SRIOV_FABRIC_PARENT`; §4 item 6 stays unused) — but say so before
  S2, because it decides whether the machinery slice is on the
  critical path at all.

---

## Appendix A — Command index (everything proposed, in order)

```
S0  incus list {loss,tcp,udp}: ; grep collision sweep ; ssh {tcp,udp} PCI->PF map (4 PFs) + VF occupancy + VEB/local_forwarding re-check + switchport evidence incl. ix0 FAB-VLAN exclusion (Q11)
S1  ssh <host>: incus admin init --minimal (or manual storage/network create) ; hugepages sysctl ; VF release (all 64 Mellanox + 8 ix0 VFs, netplan, §2.8.4) ; ix0 PF MTU 9000
S2  author test/incus/{tcp,udp}-userspace-cluster.env (SRIOV_PARENT=mlx0 / SRIOV_LAN_PARENT=mlx1 / SRIOV_FABRIC_PARENT=ix0 + VF_FABRIC_VLAN=3990|3991 by PCI), docs/ha-cluster-{tcp,udp}.conf ; land cluster-setup.sh SR-IOV fabric slice (§4.6, loss-invariance test) ; openssl rand -base64 32 ×2
S3  make CLUSTER_ENV=test/incus/<stack>-userspace-cluster.env cluster-init   # hb bridge only, no fab bridge
    make CLUSTER_ENV=test/incus/<stack>-userspace-cluster.env cluster-create
    VF audit: parents/PF-VLANs/guest queues vs §2.8.2+§2.8.4 incl. fabric pair same-PF+same-VLAN (abort on mismatch)
    incus config set <remote>:xpf-<stack>-fw{0,1} limits… hugepages… raw.qemu…
    incus launch … <remote>:xpf-<stack>-target ; VF T: sriov parent=mlx0 vlan=80 ; target-services.sh up/check
S4  make CLUSTER_ENV=… cluster-deploy XPF_DEPLOY_FAST=1     # first seed (raw, config-pushing)
    make CLUSTER_ENV=… cluster-deploy                      # thereafter (deb, config-preserving)
S5  upstream: ipv6 route <aa|ba>00::/56 via …50::<a|b> ; fw ping/ND checks
S6  userspace-ha-validation.sh (per env, target overrides) ; failover cli cmds ; counter snapshots
```

## Appendix B — Evidence index (where each inventory claim comes from)

- Repo: `test/incus/loss-userspace-cluster.env`, `loss-cluster.env`,
  `cluster-setup.sh:80-141,253-334,338-574,609-717,864-992`,
  `cluster-env.sh`, `cluster-lock.sh:44-53`, `docs/ha-cluster-userspace.conf`
  (cluster-id L64, RETH L114-137, NAT L250-320, RA L322-335, routes L336-342,
  dataplane L388-396), `docs/ha-cluster-loss.conf`, `Makefile:1460-1600`,
  `scripts/userspace-ha-validation.sh:7-42`, `test/incus/target-services.sh:25-43,50-82`,
  `test/incus/xpfd.service`.
- Live (read-only): `incus {remote,list,network,profile,config,info,storage}`
  against `loss:`/`tcp:`/`udp:`; `incus exec loss:…` (`ip`, `cli show …`,
  `ss`, service grid); `ssh loss/tcp/udp` (`ip`, `ethtool`, `/sys sriov`,
  `/proc/meminfo`, `free`, `df`, `lscpu`). Host-key prompts on first `ssh
  tcp/udp` were accepted with `StrictHostKeyChecking=no` for read-only
  probes in this session only — pin the real host keys before any build.
- Live 2026-10-21 (§1.4.1–§1.4.3): `ssh tcp/udp` — `lspci -D` (MT2892
  ConnectX-6 Dx, E810-XXV), `/sys/bus/pci/devices/{0000:02:00.0,0000:02:00.1,0000:03:00.0,0000:03:00.1}/net`
  + `sriov_{num,total}vfs`, `ethtool [-i|-l|-g]` per PF/VF, `ip -d link`
  (VF spoof/trust state), `devlink port`, PCIe `current_link_{speed,width}`,
  `ip route get {172.16.50.1,2001:559:8585:50::1}` (egress via `rx1`/`eno3v*`),
  `incus network list {tcp,udp}:` (all VFs `USED BY 0`); `ssh loss` PF/VF
  comparison (ConnectX-6 Lx 25 Gb/s, VF vlan/trust state). Blocked at this
  privilege level: host netplan (root-only), `tcpdump` (no `CAP_NET_RAW`),
  `sudo` (interactive auth) — the gaps behind §1.4.3/Q11.
- Live 2026-10-21b (§1.4.1, §2.8.2-F): `ssh tcp/udp` — `bridge link show`
  (all fast PFs `hwmode VEB`), `devlink dev param show pci/0000:03:00.0`
  (`local_forwarding: enabled` on both hosts), `ip link show ix0`
  (VF spoof/trust state). This is the evidence for VEB-local fabric
  switching; the same commands are re-run at S0 as a build-day check.
```

---

## Revision notes
- 2026-10-19 (user corrections): UDP second WAN address is `2001:559:8585:80::b` (not `::ab`); `mlx0` = PCI `0000:02:00.0` (WAN PF), `mlx1` = PCI `0000:02:00.1` (LAN PF). Both are now reflected in §§0-3, S0/S1, and R1 — detect PFs by PCI address before setting `SRIOV_PARENT`/`SRIOV_LAN_PARENT`, never by assumed interface name.
- 2026-10-21 (VF revision, for review): dedicated NIC inspection of `tcp`/`udp` (§1.4.1–§1.4.3, read-only). Findings: dual-port 100G ConnectX-6 Dx + dual-port 25G E810 per host (not one NIC of each); all 80 fast VFs currently host-bound via installer netplan; WAN reachability via any fast PF unproven (host pings egress via `rx1`). Design response: normative VF allocation §2.8 (WAN/target VFs on 100G `mlx0`, LAN/generator VFs on 100G `mlx1`, Intel 25G reserved for phase-2 fabric/capture/spare, `rx1` mgmt-only), threaded into §2.1/§2.3/§3/§4/§5 (S0 PCI map + switchport evidence, S1 VF release, S3 VF audit)/§6 (V0/V3/V7) with new risks R10–R12 and questions Q11–Q13 (Q3 narrowed to `mlx0`). PF-passthrough (Alt-G) and 25G-in-forwarding-path (Alt-F) considered and rejected with reasons. No execution has occurred.
- 2026-10-21b (fabric revision, for review): fabric moved from the `bpu-*-fab0` bridge to PF-private VFs on the E810 `ix0` (rows F0/F1, candidates FAB-VLAN 3990 tcp / 3991 udp), after confirming `hwmode VEB` + `local_forwarding: enabled` on both hosts. Threaded into §2.1/§2.3/§2.8.3–§2.8.5/§3 (device rows, ‡ note, §3.4 fate split)/§4 item 6 (default-off `cluster-setup.sh` SR-IOV-fabric slice with loss-invariance test — the only machinery change)/§5 (S0 VEB + FAB-trunk checks, S1 all-`ix0` VF release + PF MTU 9000, S2 machinery-before-create, S3 fabric audit + no-fab-bridge abort)/§6-V0 (fabric smoke as a hard gate), R11/R12 (rewritten: `iavf` kernel-path risk is small, AF_XDP risk unchanged; two-card fate split), Q11 (FAB-VLAN trunk exclusion), Q12 (release now includes the 8 `ix0` DHCP leases), Q13 (rewritten as confirmation of fabric-in-v1). Bridge fabric retained as the documented fallback. No execution has occurred.
- 2026-10-21c (EXECUTION, attempt 1 — authorised by user "go ahead and try to deploy"): PARKED status lifted by that ruling for attempt 1 only. Bridge-fabric fallback used (SR-IOV fabric machinery §4.6 not yet implemented). Results so far: (1) sudo granted on both hosts; 16×1GiB hugepages allocated; QEMU SPICE module installed (required `libx11-6` one-patch downgrade). (2) Incus allocates only VFs whose host netdev is **down** — Mellanox VF netdevs brought down on both hosts (runtime-only, not reboot-persistent). (3) Docker `FORWARD DROP` on `tcp` bypassed for mgmt subnet + NAT66 added to `incusbr-tcp`; `udp` has no Docker. (4) TCP `cluster-create` completed fw0/fw1 provisioning; LAN container `systemd-networkd` wedges (`activating`, netplan-configure failed) — static IP applied manually, reboot-persistence open. (5) VF audit clean: mlx0 VF1=fw0-WAN/VF3=fw1-WAN, mlx1 VF1=fw0-LAN/VF2=generator/VF3=fw1-LAN, VLAN 3668 on PF, guest VF queues = 6 combined (not 11 as host-side). (6) **Q11 partially answered by traffic: target container on mlx0 VF VLAN 80 pings `172.16.80.1` and `2001:559:8585:80::1`** — mlx0 carries VLAN 80 to the upstream. (7) Global cluster lock is contended by a concurrent `loss` acceptance run; deploys queue behind it. Deploy/validation results to follow in 2026-10-21d.
- 2026-10-21d (EXECUTION, attempt 1 results): **Both clusters are up.** TCP: cluster-id 23 formed, RG0/1/2 node0-primary, `Forwarding supported: true`, Bound 18/18 (12 zerocopy Mellanox + 6 fabric-child), IPv4 iperf3 -P4 ≈ **36.0 Gbit/s**, IPv6 ≈ **36.2 Gbit/s** (per-second SUM intervals; iperf end-exchange `pthread_cancel` quirk prevents the final SUM line — intervals are the evidence). UDP: cluster-id 24 formed identically, TCP v4 41.1 / v6 41.5 Gbit/s, UDP-mode 10 Gbit/s offered → 9.78 received (2.2% loss), 40 Gbit/s offered → 12.7 sender-capped single-flow (3.1% loss). Bugs/findings: (a) **packaging bug fixed in-tree** — prose `#DEBHELPER#` in a `debian/xpf.postinst` comment was spliced by debhelper, breaking fresh installs (`may: not found`, exit 127); one-line fix in working tree, uncommitted. (b) Raw first-seed deploy pushes `xpf-userspace-dp` uid-1000-owned and xpfd refuses it — chown root + restart required on all four nodes (deploy script's helper check then passes on re-check); deb path is immune (converts to versions/ symlinks). (c) Rolling deb deploy refuses a virgin pair ("peer is not alive") — first seed must be XPF_DEPLOY_FAST=1. (d) **RG1 manual failover under iperf: existing flows blackholed for the remaining ~30 s while new flows worked immediately** — zero-interval count far exceeds the `test-failover` floor; needs its own investigation (split-RG transit / neighbor resolution on the new owner). RG1 restored to node0. (e) LAN/target containers' systemd wedges (networkd `activating`, netplan-configure failed) — static IPs, DNS, and return routes are manual and NOT reboot-persistent; target-services grid (5200-5211) not yet installed (ad-hoc 5301/54xx servers used). (f) Host VF-down + hugepage state is runtime-only. Fabric is bridge (attempt-1 fallback); SR-IOV fabric (§4.6) still unimplemented. Upstream `/56` routes (Q3) still owed — v6 return path currently via a static route on the target containers only.
- 2026-10-21e (EXECUTION, reboot recovery + core-scaling experiment, authorised by user "try raising the core count and see what happens"): (1) Both hosts rebooted onto new GRUB params (`iommu=pt … hugepages=20`, backups `/etc/default/grub.bak-20261021`); clusters recovered: `xpf-vf-down.service` (down Mellanox VF netdevs pre-Incus) + `xpf-mgmt-fwd.service` (tcp Docker FORWARD exception) added, Incus autostart priorities set (firewall VMs 10, containers 0). UDP post-reboot VF collision (target + fw0 both on mlx0 VF0, merged PF MAC/VLAN) fixed by VM-first start order. Container static IPs/routes re-applied manually (systemd wedge from 2026-10-21d still open — addressing is NOT reboot-persistent). (2) Cross-cluster v6 fixed with interim static `/56` return routes on the target containers (upstream Q3 routes still owed). (3) iperf3 container `pthread_cancel Permission denied` root-caused to AppArmor (`signal`/`ptrace` to `**//&unconfined` peers denied); fixed with glob-form `raw.apparmor` rules; daemon-mode iperf verified clean. (4) **Core experiment on TCP cluster:** 12 vCPU alone → xpfd OOM crash-loop (8 GiB / 8 hugepages insufficient) — rolled back. Scaled coherently to 10 vCPU + 16 GiB + `limits.hugepages.1GB=16` per FW VM, host runtime pool 36 pages, `workers 6→10` (`docs/ha-cluster-tcp.conf`): guest VF channels 10, `Bound bindings 30/30`, `Armed queues 10/10`. **Result: `-P32` throughput did NOT scale** — own-cluster TCP target ≈34.5 Gbit/s (interrupt) / 37.5 (busy-poll) / 38.3 final vs ≈36 at 6 workers; cross-cluster to `::211` ≈44–50 Gbit/s with all 10 workers at 90–100%. Endpoint CPUs, queue counts (11), and RSS distribution all verified non-limiting. Verdict: workers were never the binding constraint above 6; the ~2 µs/packet userspace forwarding cost (flow lookup + SNAT + policy + AF_XDP) is. Jumbo frames would cut packet rate ~6× but are **blocked**: MTU 9000 in config does not propagate to guest netdevs and `ip link set mtu 9000` on XDP-attached `ge-*` returns `Invalid argument` — product gap, not a config knob. (5) Final TCP state at the end of this experiment (superseded — see below): 10 CPU / 16 GiB / workers 10 / `poll-mode busy-poll`; UDP cluster left at 6/8 GiB/workers 6 as control. TCP host GRUB raised to `hugepages=40` (file only, not yet rebooted) because the two 16-page VMs exceed the old 20-page boot pool. RG1 failover existing-flow blackhole (2026-10-21d-d) remains open.
- 2026-10-22 (poll-mode reconciliation): the 2026-10-21e note above records `poll-mode busy-poll` as the final TCP state of that experiment; the subsequent perf-diagnosis work (docs/xpf-dataplane-perf-diagnosis.md §5) left the cluster in `poll-mode interrupt` (interrupt matched busy-poll within noise and cut retransmits ~6x), which is what docs/ha-cluster-tcp.conf carries today. Read 2026-10-21e's busy-poll as experiment-end state, not current state.
- No execution has occurred beyond attempt 1 above. Next action remains user decision: answer Q1-Q13 (§7) or request refinements, then approve S0/S1 for any wider build.
