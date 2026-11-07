# xpf test network topology

This documents the interface maps for the two test environments. For how
*deployed* appliances map vNICs/SR-IOV to interface names, see the
positional naming contract in [`deploy-quickstart.md`](deploy-quickstart.md)
and [`../examples/deploy/README.md`](../examples/deploy/README.md). For
the SR-IOV/XDP driver caveats, see the "XDP on SR-IOV interfaces" section
of [`critical-patterns.md`](critical-patterns.md).

All interfaces are managed by xpfd — renamed via `.link` files,
configured via `.network` files. Startup naming by
`enumerateAndRenameInterfaces()` (`pkg/daemon/linksetup.go`) assigns
vSRX names based on PCI bus order.

> **Name form.** The interface maps below use the **Linux link / dash
> form** (`ge-0-0-0`) — what `ip link` and `enumerateAndRenameInterfaces()`
> produce. The **config and CLI use the slash form** (`ge-0/0/0`); the
> config layer translates between the two. Use the slash form in `cli`
> and in `xpf.conf`, the dash form in `ip`/`ethtool` on the box.

## Standalone VM (xpf-fw)

No `/etc/xpf/node-id`, no `em0`:

```
  Virtio (PCI bus 05-08):
    enp5s0  → fxp0       DHCP          — mgmt zone (SSH + ping)
    enp6s0  → ge-0-0-0   10.0.1.10     — trust zone
    enp7s0  → ge-0-0-1   10.0.2.10     — untrust zone
    enp8s0  → ge-0-0-2   10.0.30.10    — dmz zone
  i40e PCI passthrough (PCI bus 09+, always higher than virtio):
    enp9s0f0np0   → ge-0-0-3  172.16.50.5  — wan zone (VLAN 50, IPv6)
    enp101s0f1np1 → ge-0-0-4               — loss zone

  Test containers:
    trust-host    10.0.1.102  (2001:559:8585:bf01::102)  — xpf-trust bridge
    untrust-host  10.0.2.102  (2001:559:8585:bf02::102)  — xpf-untrust bridge
    dmz-host      10.0.30.101 (2001:559:8585:bf03::101)  — xpf-dmz bridge
```

> **DUT isolation (#1992).** The `10.0.1.10` / `10.0.2.10` gateway IPs above
> are static and identical on every standalone firewall, and the test hosts
> default-route through them. Only ONE firewall may be attached to the
> trust/untrust bridges at a time — a second firewall claims the same gateway
> IPs and the hosts' gateway ARP flips nondeterministically, producing false
> "stall" readings (this caused the #1961 misdiagnosis). `setup.sh`
> create-vm/create-ct/deploy refuse to run while another firewall holds these
> gateways (override: `XPF_FORCE_TEARDOWN_PEERS=1`). See the "DUT Isolation"
> section of [`testing.md`](testing.md).

## HA cluster (`loss:xpf-userspace-fw0/fw1`)

Different topology from the standalone VM above. Do NOT extrapolate the
standalone PCI map to the loss userspace cluster: the WAN interface there
is `ge-0-0-2` (node 0 name — node 1 uses FPC 7, i.e. `ge-7-0-2`), not
`ge-0-0-3`, and `ge-0-0-0` is the fabric IPVLAN parent (not WAN). The
per-cluster wiring is canonical in `docs/ha-cluster-userspace.conf` and
`test/incus/loss-userspace-cluster.env`.

```
loss:xpf-userspace-fw{0,1} — node-id 0 / 1, /etc/xpf/node-id present:
  NOTE: ge-* names below are node 0; node 1 substitutes FPC 7 for ALL
  ge-* interfaces — the fabric parent ge-0-0-0 becomes ge-7-0-0, and the
  dataplane VFs become ge-7-0-1 / ge-7-0-2 — per pkg/daemon/linksetup.go
  (fpc=7 for node 1) and docs/ha-cluster-userspace.conf.
  Virtio (PCI bus 05-07, lower bus → lower vSRX name):
    enp5s0  → fxp0       DHCP                          — mgmt zone (SSH + ping)
    enp6s0  → em0        10.99.{0..12}.{1,2}           — cluster control plane / heartbeat
    enp7s0  → ge-0-0-0   fab0 IPVLAN parent            — fabric (xdpgeneric — fabric path only)
  mlx5 SR-IOV VF (PCI bus 08-09 — native XDP):
    enp8s0  → ge-0-0-1   reth1.0 (LAN, 10.0.61.1/24)   — LAN-side, mlx5_core xdp native
    enp9s0  → ge-0-0-2   reth0 (WAN; VLAN 50 + 80)     — WAN-side, mlx5_core xdp native
                         reth0.50  172.16.50.8/24      —   transit
                         reth0.80  172.16.80.8/24      —   data path target VLAN
```

Smoke iperf3 target: `$IPERF_TARGET4` (loss `172.16.80.202`) /
`2001:559:8585:80::200` (on
reth0.80 WAN path, AF_XDP zero-copy fast path). Per-class iperf3 servers
live on ports 5200-5211 matching `test/incus/cos-iperf-config.set`. Do
NOT use `172.16.100.x` — that reaches a different `loss:` uplink path
capped at ~9-10 Gb/s.
