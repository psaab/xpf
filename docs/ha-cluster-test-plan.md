# HA Cluster Test Plan — Two-VM SR-IOV Setup

> #1373 note: this plan preserves the legacy eBPF/bpfrx-style HA test
> topology and BPF-specific fallback checks for regression use. The default
> target for new dataplane validation is the userspace AF_XDP cluster
> (`loss:xpf-userspace-fw0/fw1`) and the userspace HA validation runbooks.

## Overview

Two VMs running xpfd in chassis cluster (active/passive) mode with:
- **WAN**: SR-IOV VFs from `eno6np1` (i40e, one VF per VM via PCI passthrough, bonded into reth0)
- **LAN**: One bridged network (one interface per VM, bonded into reth1)
- **Heartbeat**: Dedicated bridge for cluster health monitoring (UDP:4784)
- **Fabric**: Dedicated link between VMs for session sync, config sync, IPsec SA sync (TCP)
- **Test host**: Container on LAN for end-to-end traffic validation

## Single-Config Model

Both nodes share **one configuration file** (`docs/ha-cluster.conf`) using the Junos
`groups` / `apply-groups` pattern. Node-specific settings (hostname, cluster node ID,
peer addresses, interface-to-RETH mappings) live inside `groups { node0 { ... } }` and
`groups { node1 { ... } }`. The shared sections (chassis cluster, RETH, security, NAT,
routing) appear at the top level.

At load time, the daemon reads `/etc/xpf/node-id` (a plain integer: 0 or 1) and
resolves `apply-groups "${node}"` by substituting `${node}` with `node0` or `node1`.
This merges the node-specific group into the active config, producing a complete
per-node configuration from a single source file.

Config sync "just works" — the primary sends the **unexpanded** config text (with groups
intact) to the secondary. Each node compiles it with its own `${node}` expansion.

### Interface Naming Convention

xpf uses vSRX-style interface names:

| vSRX Name | Linux Name | Role |
|-----------|-----------|------|
| `fxp0` | `fxp0` | Management (out-of-band) |
| `em0` | `em0` | Embedded management / cluster control (heartbeat) |
| `fab0` | `fab0` | Fabric sync link (member: ge-0/0/0 or ge-7/0/0) |
| `fab1` | `fab1` | Fabric sync link (member: ge-0/0/1 or ge-7/0/1) |
| `ge-0/0/0` | `ge-0-0-0` | Node 0: fab0 member (renamed to fab0 by daemon) |
| `ge-0/0/1` | `ge-0-0-1` | Node 0: fab1 member (renamed to fab1 by daemon) |
| `ge-0/0/2` | `ge-0-0-2` | Node 0 data interface (LAN, reth1 member) |
| `ge-0/0/3` | `ge-0-0-3` | Node 0 data interface (WAN, reth0 member) |
| `ge-7/0/0` | `ge-7-0-0` | Node 1: fab0 member (renamed to fab0 by daemon) |
| `ge-7/0/1` | `ge-7-0-1` | Node 1: fab1 member (renamed to fab1 by daemon) |
| `ge-7/0/2` | `ge-7-0-2` | Node 1 data interface (LAN, reth1 member) |
| `ge-7/0/3` | `ge-7-0-3` | Node 1 data interface (WAN, reth0 member) |
| `reth0` | `reth0` | Redundant Ethernet — WAN |
| `reth1` | `reth1` | Redundant Ethernet — LAN |

**Name translation**: Junos `ge-X/Y/Z` uses slashes, but Linux interface names cannot
contain slashes. The daemon translates slashes to hyphens: `ge-0/0/0` → `ge-0-0-0`.
Config files use the Junos form; `.link` files rename kernel interfaces to the Linux form.

## Physical Host

```
Host NIC: eno6np1 (i40e, Intel X710/X722)
  - 32 SR-IOV VFs available (sriov_numvfs=32)
  - VFs passed through as PCI devices (type=pci) to each VM
  - VF0 (0000:b7:06.0) → xpf-fw0
  - VF1 (0000:b7:06.1) → xpf-fw1
  - VFs use iavf driver inside VMs (generic XDP only)
```

## Network Topology

```
                         Internet / Upstream
                              |
                    +---------+---------+
                    |   eno6np1 (i40e)  |  Host PF
                    |   32 SR-IOV VFs   |
                    +----+--------+-----+
                         |        |
                   VF0 (PCI)  VF1 (PCI)
                         |        |
              +----------+--+  +--+----------+
              |  xpf-fw0  |  |  xpf-fw1  |
              |  (node 0)   |  |  (node 1)   |
              |  pri: 200   |  |  pri: 100   |
              +--+--+--+--+-+  +-+--+--+--+--+
                 |  |  |  |      |  |  |  |
  fxp0 ---------+  |  |  |      +--|--------  fxp0
  em0 ------------+  |  |      +--|---------  em0
  fab0 ----------------+  |      |  +--------  fab0
  ge-0/0/0 ---------------+      +-----------  ge-7/0/0
                 |                   |
                 +------+   +-------+
                        |   |
           incusbr0             (fxp0, DHCP)
           xpf-heartbeat      (em0, 10.99.0.0/30)
           xpf-fabric         (fab0, 10.99.1.0/30)
           xpf-clan           (reth1: 10.0.60.0/24)

              +------------------+
              |  cluster-lan-    |
              |  host            |
              |  eth0: clan      |  10.0.60.102/24
              +------------------+
```

Each VM has one LAN interface on the same bridge. reth1 floats the VIP to
whichever VM is primary, same as reth0 for WAN.

## Incus Resources

### Networks (all pure L2, no Incus IP management)

| Network | Purpose | Incus Config |
|---------|---------|-------------|
| `incusbr0` | Management (existing, DHCP) | default |
| `xpf-heartbeat` | Cluster heartbeat (UDP:4784) | ipv4.address=none, ipv6.address=none |
| `xpf-fabric` | Session/config/IPsec sync (TCP) | ipv4.address=none, ipv6.address=none |
| `xpf-clan` | LAN segment (reth1 member per VM) | ipv4.address=none, ipv6.address=none |

### Profile: `xpf-cluster`

```
CPU:    4 vCPU
Memory: 4 GB
Disk:   20 GB (pool: default)
```

| Device | VM Interface | Renamed To | Network | Purpose |
|--------|-------------|-----------|---------|---------|
| `eth0` | enp5s0 | fxp0 | incusbr0 | Management (DHCP) |
| `eth1` | enp6s0 | em0 | xpf-heartbeat | Heartbeat / control |
| `eth2` | enp7s0 | ge-X-0-0 → fab0 | xpf-fabric | Fabric fab0 member |
| `eth3` | enp8s0 | ge-X-0-1 → fab1 | xpf-fabric1 | Fabric fab1 member |
| `eth4` | enp9s0 | ge-X-0-2 | xpf-clan | LAN (reth1 member) |
| `eth5` | enp10s0 | ge-X-0-3 | incusbr0 | Spare |

SR-IOV WAN VF added per-VM as PCI passthrough (becomes `ge-X-0-4`):
```bash
incus config device add $vm wan-vf pci address=0000:b7:06.0  # VF0 for fw0
incus config device add $vm wan-vf pci address=0000:b7:06.1  # VF1 for fw1
```

Where X = 0 for node 0 and X = 7 for node 1. Fabric member interfaces (ge-X-0-0, ge-X-0-1)
are renamed to fab0/fab1 by the daemon via fabric-options member-interfaces.

### Instances

| Instance | Type | Role |
|----------|------|------|
| `xpf-fw0` | VM | Firewall node 0 (primary, priority 200) |
| `xpf-fw1` | VM | Firewall node 1 (secondary, priority 100) |
| `cluster-lan-host` | Container | Test traffic source/sink on LAN (eth0 only) |

## Interface Mapping

### Per-VM Interfaces

**Node 0 (xpf-fw0):**

| Kernel Name | Renamed To | Config Name | Driver | XDP Mode | Role |
|-------------|-----------|-------------|--------|----------|------|
| enp5s0 | fxp0 | fxp0 | virtio_net | native | Management (DHCP) |
| enp6s0 | em0 | em0 | virtio_net | native | Heartbeat / control |
| enp7s0 | ge-0-0-0 → fab0 | ge-0/0/0 | virtio_net | native | Fabric fab0 member |
| enp8s0 | ge-0-0-1 → fab1 | ge-0/0/1 | virtio_net | native | Fabric fab1 member |
| enp9s0 | ge-0-0-2 | ge-0/0/2 | virtio_net | native | LAN (reth1 member) |
| VF (PCI) | ge-0-0-3 | ge-0/0/3 | iavf | generic | WAN (reth0 member) |

**Node 1 (xpf-fw1):**

| Kernel Name | Renamed To | Config Name | Driver | XDP Mode | Role |
|-------------|-----------|-------------|--------|----------|------|
| enp5s0 | fxp0 | fxp0 | virtio_net | native | Management (DHCP) |
| enp6s0 | em0 | em0 | virtio_net | native | Heartbeat / control |
| enp7s0 | ge-7-0-0 → fab0 | ge-7/0/0 | virtio_net | native | Fabric fab0 member |
| enp8s0 | ge-7-0-1 → fab1 | ge-7/0/1 | virtio_net | native | Fabric fab1 member |
| enp9s0 | ge-7-0-2 | ge-7/0/2 | virtio_net | native | LAN (reth1 member) |
| VF (PCI) | ge-7-0-3 | ge-7/0/3 | iavf | generic | WAN (reth0 member) |

### RETH Bonds

| RETH | Node 0 Member | Node 1 Member | IPv4 VIP | IPv6 VIP | Zone | Purpose |
|------|--------------|--------------|----------|----------|------|---------|
| reth0 | ge-0/0/3 | ge-7/0/3 | 172.16.50.6/24 (VLAN 50) | 2001:559:8585:50::6/64 | wan | WAN uplink |
| reth1 | ge-0/0/2 | ge-7/0/2 | 10.0.60.1/24 | 2001:559:8585:cf01::1/64 | lan | LAN |

## IP Addressing

### Point-to-Point Links

| Link | fw0 | fw1 | Subnet |
|------|-----|-----|--------|
| Heartbeat (em0) | 10.99.0.1/30 | 10.99.0.2/30 | 10.99.0.0/30 |
| Fabric (fab0) | 10.99.1.1/30 | 10.99.1.2/30 | 10.99.1.0/30 |

### RETH VIPs (float to primary)

| RETH | IPv4 VIP | IPv6 VIP | Gateway for |
|------|----------|----------|-------------|
| reth0 | 172.16.50.6/24 | 2001:559:8585:50::6/64 | WAN uplink |
| reth1 | 10.0.60.1/24 | 2001:559:8585:cf01::1/64 | cluster-lan-host |

### Test Container

| Interface | Network | IPv4 Address | IPv6 | Gateway |
|-----------|---------|-------------|------|---------|
| eth0 | xpf-clan | 10.0.60.102/24 | SLAAC + DHCPv6 | 10.0.60.1 / fe80::... (RA) |

## Cluster Configuration

A single config file (`docs/ha-cluster.conf`) is loaded on both nodes. The
`apply-groups "${node}"` directive selects node-specific overrides at commit time.

Node ID is read from `/etc/xpf/node-id` (plain integer: 0 or 1). If this file
does not exist, the daemon runs in standalone (non-cluster) mode.

### Node-Specific Settings (via groups)

| Setting | node0 (fw0) | node1 (fw1) |
|---------|------------|------------|
| host-name | xpf-fw0 | xpf-fw1 |
| cluster node | 0 | 1 |
| peer-address | 10.99.0.2 | 10.99.0.1 |
| fabric-peer-address | 10.99.1.2 | 10.99.1.1 |
| em0 address | 10.99.0.1/30 | 10.99.0.2/30 |
| fab0 address | 10.99.1.1/30 | 10.99.1.2/30 |
| WAN RETH member | ge-0/0/3 | ge-7/0/3 |
| LAN RETH member | ge-0/0/2 | ge-7/0/2 |

### Shared Cluster Settings

```
chassis {
    cluster {
        cluster-id 1;
        reth-count 2;
        heartbeat-interval 1000;
        heartbeat-threshold 3;
        control-interface em0;
        fab0 {
            fabric-options {
                member-interfaces {
                    ge-0/0/0;
                    ge-7/0/0;
                }
            }
        }
        fab1 {
            fabric-options {
                member-interfaces {
                    ge-0/0/1;
                    ge-7/0/1;
                }
            }
        }
        configuration-synchronize;
        redundancy-group 0 {
            node 0 priority 200;
            node 1 priority 100;
            preempt;
        }
        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
            preempt;
            gratuitous-arp-count 8;
            interface-monitor {
                ge-0/0/1 weight 255;
                ge-7/0/1 weight 255;
            }
        }
        redundancy-group 2 {
            node 0 priority 200;
            node 1 priority 100;
            preempt;
            gratuitous-arp-count 8;
            interface-monitor {
                ge-0/0/0 weight 255;
                ge-7/0/0 weight 255;
            }
        }
    }
}
```

- **RG0**: Control plane (cluster management, no interface-monitor)
- **RG1**: reth0/WAN — monitors both nodes' WAN physical interfaces
- **RG2**: reth1/LAN — monitors both nodes' LAN physical interfaces

### Security Zones

| Zone | Interfaces | Allowed Services | Allowed Protocols |
|------|-----------|-----------------|------------------|
| mgmt | fxp0 | ssh, ping, dhcp | — |
| control | em0, fab0 | ping | — |
| wan | reth0 | ping | — |
| lan | reth1 | ssh, ping, dhcp, dhcpv6 | router-discovery |

### Policies

| From | To | Action | Notes |
|------|----|--------|-------|
| lan | wan | permit + SNAT | Internet access from LAN |
| wan | lan | deny | Default deny inbound |
| default | * | deny-all | Global default |

### NAT

```
security {
    nat {
        source {
            rule-set lan-to-wan {
                from zone lan;
                to zone wan;
                rule snat {
                    match { source-address 0.0.0.0/0; }
                    then { source-nat { interface; } }
                }
            }
        }
    }
}
```

### Routing

```
routing-options {
    static {
        route 0.0.0.0/0 { next-hop 172.16.50.1; }
        route ::/0 { next-hop 2001:559:8585:50::1; }
    }
}
```

### Router Advertisements (reth1)

```
protocols {
    router-advertisement {
        interface reth1 {
            managed-configuration;
            other-stateful-configuration;
            prefix 2001:559:8585:cf01::/64 { on-link; autonomous; }
            dns-server-address 2001:4860:4860::8888;
        }
    }
}
```

Flags: M (managed) tells clients to use DHCPv6 for address, O (other) for DNS/domain,
A (autonomous) allows SLAAC as well. radvd resolves RETH names to physical member
interfaces via `ResolveReth()` + `LinuxIfName()`.

### DHCP Server (on reth1)

```
system {
    services {
        dhcp-local-server {
            group lan-pool {
                interface reth1;
                pool lan-range {
                    subnet 10.0.60.0/24;
                    address-range low 10.0.60.100 high 10.0.60.199;
                    router 10.0.60.1;
                    dns-server 8.8.8.8;
                }
            }
        }
    }
}
```

### DHCPv6 Server (on reth1)

```
system {
    services {
        dhcpv6-local-server {
            group lan6-pool {
                interface reth1;
                pool lan6-range {
                    subnet 2001:559:8585:cf01::/64;
                    address-range low 2001:559:8585:cf01::100 high 2001:559:8585:cf01::1ff;
                    dns-server 2001:4860:4860::8888;
                }
            }
        }
    }
}
```

## Setup Procedure

All setup is automated via `test/incus/cluster-setup.sh`:

```bash
./test/incus/cluster-setup.sh init       # Create networks + profile
./test/incus/cluster-setup.sh create     # Launch both VMs + test container
./test/incus/cluster-setup.sh deploy all # Build xpfd, push to both VMs
```

Or via Makefile targets:
```bash
make cluster-init     # Create networks + profile
make cluster-create   # Launch both VMs + test container
make cluster-deploy   # Build + push to both VMs (NODE=0|1 for single)
make cluster-destroy  # Tear down
make cluster-status   # Show status
make cluster-ssh NODE=0|1  # Shell into VM
make cluster-logs NODE=0|1 # Show logs
make cluster-start/stop/restart  # Service lifecycle (NODE=0|1|all)
```

### What `create` does per VM

1. Launch Debian 13 VM with `xpf-cluster` profile (4 virtio NICs)
2. Add SR-IOV VF via PCI passthrough (stop VM → add device → restart)
3. Write `.link` files for vSRX-style interface renaming (MAC-based)
4. Install packages: FRR, strongSwan, tcpdump, iperf3, bpftool, ethtool, etc.
5. Upgrade kernel to 6.18+ from Debian unstable
6. Set GRUB: `init_on_alloc=0` for XDP performance
7. Configure sysctl: legacy BPF JIT, IP forwarding, RA disable
8. Write `/etc/xpf/node-id` (0 or 1)
9. Reboot for new kernel

### What `deploy` does per VM

1. Build `xpfd` and `cli` binaries
2. Stop running service, push binaries to `/usr/local/sbin/`
3. Push unified `docs/ha-cluster.conf` to `/etc/xpf/xpf.conf`
4. Ensure `/etc/xpf/node-id` exists
5. Install and enable systemd service

## Test Cases

### TC-1: Cluster Formation

**Objective:** Verify both nodes form a cluster and elect a primary.

```bash
# On fw0 (expected primary due to priority 200):
printf 'show chassis cluster status\nexit\n' | incus exec xpf-fw0 -- cli

# Expected:
#   Node 0: primary   (priority 200, weight 255)
#   Node 1: secondary (priority 100, weight 255)
```

**Pass criteria:**
- fw0 is primary for RG0
- fw1 is secondary for RG0
- Heartbeat state: "up"
- Both RETH interfaces active on fw0

### TC-2: LAN Connectivity Through Cluster (IPv4 + IPv6)

**Objective:** Verify traffic flows from LAN container through the primary firewall to WAN.

```bash
# IPv4 from cluster-lan-host:
incus exec cluster-lan-host -- ping -c 5 172.16.50.1   # WAN gateway (via reth0)
incus exec cluster-lan-host -- ping -c 5 8.8.8.8       # Internet (SNAT via reth0)
incus exec cluster-lan-host -- ping -c 5 10.0.60.1     # reth1 VIP

# IPv6 from cluster-lan-host:
incus exec cluster-lan-host -- ping -c 5 2001:559:8585:cf01::1  # reth1 IPv6 VIP
incus exec cluster-lan-host -- ping -c 5 2001:559:8585:50::6    # reth0 IPv6 VIP (WAN)

# Verify sessions on primary:
printf 'show security flow session\nexit\n' | incus exec xpf-fw0 -- cli
```

**Pass criteria:**
- All IPv4 pings succeed
- IPv6 gateway ping (reth1) succeeds
- Sessions visible on fw0 (primary)
- SNAT applied for WAN-bound traffic

### TC-3: Failover — Primary Failure

**Objective:** Verify secondary takes over when primary fails.

```bash
# 1. Start continuous ping from cluster-lan-host
incus exec cluster-lan-host -- ping 8.8.8.8 &

# 2. Stop primary
incus exec xpf-fw0 -- systemctl stop xpfd

# 3. Wait for failover (30ms VRRP → ~97ms masterDown; planned stop near-instant)
sleep 1

# 4. Check cluster status on fw1
printf 'show chassis cluster status\nexit\n' | incus exec xpf-fw1 -- cli

# 5. Verify ping continues (expect ~6 lost at 10ms interval = ~60ms)
```

**Pass criteria:**
- fw1 becomes primary within ~100ms (measured ~60ms)
- Async GARP burst sent for reth0, reth1 VIPs (first pair immediate, rest in background)
- cluster-lan-host traffic resumes after ~60ms interruption
- Sessions synced from fw0 survive on fw1

### TC-4: Failover — Recovery and Preemption

**Objective:** Verify original primary reclaims after recovery (preempt enabled).

```bash
# 1. Restart fw0
incus exec xpf-fw0 -- systemctl start xpfd

# 2. Wait for preemption (election + hold timer)
sleep 10

# 3. Verify fw0 is primary again
printf 'show chassis cluster status\nexit\n' | incus exec xpf-fw0 -- cli
```

**Pass criteria:**
- fw0 reclaims primary role
- Traffic continues without prolonged outage
- Session state synced back

### TC-5: Config Synchronization

**Objective:** Verify config changes on primary replicate to secondary.

```bash
# 1. On fw0 (primary), add a policy:
printf 'configure\nset security policies from-zone lan to-zone wan policy test-sync match source-address any destination-address any application any then permit\ncommit\nexit\nexit\n' | incus exec xpf-fw0 -- cli

# 2. On fw1, verify config arrived:
printf 'show configuration security policies from-zone lan to-zone wan | display set\nexit\n' | incus exec xpf-fw1 -- cli
```

**Pass criteria:**
- Policy `test-sync` appears on fw1 within seconds
- fw1 shows config as read-only (secondary cannot modify)

### TC-6: Session Synchronization

**Objective:** Verify active sessions are synced to secondary for hitless failover.

```bash
# 1. Create a long-lived session from cluster-lan-host
incus exec cluster-lan-host -- iperf3 -c <wan-target> -t 60 &

# 2. Verify session on fw0
printf 'show security flow session\nexit\n' | incus exec xpf-fw0 -- cli

# 3. Verify session is synced to fw1
printf 'show security flow session\nexit\n' | incus exec xpf-fw1 -- cli
```

**Pass criteria:**
- Session appears on both fw0 and fw1
- Session on fw1 matches fw0 (IPs, ports, NAT state)

### TC-6b: Manual Failover / Reset (`6d63020`)

**Objective:** Verify per-RG manual failover and reset, with connectivity maintained.

```bash
# 1. Baseline: verify node0 primary for all RGs
echo 'show chassis cluster' | incus exec xpf-fw0 -- cli

# 2. Manual failover RG1 to node1
echo 'request chassis cluster failover redundancy-group 1 node 1' | \
  incus exec xpf-fw0 -- cli
sleep 2

# 3. Verify RG1: node0=secondary(Manual=yes), node1=primary
echo 'show chassis cluster' | incus exec xpf-fw0 -- cli
echo 'show chassis cluster' | incus exec xpf-fw1 -- cli

# 4. LAN VIP connectivity during failover
incus exec cluster-lan-host -- ping -c 3 10.0.60.1
incus exec cluster-lan-host -- ping -6 -c 3 2001:559:8585:cf01::1

# 5. Reset failover — node0 preempts back
echo 'request chassis cluster failover reset redundancy-group 1' | \
  incus exec xpf-fw0 -- cli
sleep 2

# 6. Verify RG1: node0=primary, Manual=no, weight restored to 255
echo 'show chassis cluster' | incus exec xpf-fw0 -- cli

# 7. LAN VIP connectivity after reset
incus exec cluster-lan-host -- ping -c 3 10.0.60.1
incus exec cluster-lan-host -- ping -6 -c 3 2001:559:8585:cf01::1
```

**Pass criteria:**
- After failover: RG1 node1=primary, node0=secondary with Manual=yes
- After reset: RG1 node0=primary, Manual=no
- LAN VIP IPv4 + IPv6: 0% packet loss through both transitions
- Other RGs (0, 2) unaffected throughout

### TC-7: RETH Interface Monitor Failover

**Objective:** Verify failover when a monitored RETH member loses link.

```bash
# Simulate WAN VF failure by detaching the PCI device:
incus config device remove xpf-fw0 wan-vf

# Monitor cluster status (reth0 weight should drop to 0):
printf 'show chassis cluster status\nexit\n' | incus exec xpf-fw1 -- cli
```

**Pass criteria:**
- fw0 weight drops (reth0 monitor triggers)
- fw1 becomes primary if fw0 weight falls below fw1
- Traffic fails over to fw1's WAN VF

### TC-8: Throughput Under HA

**Objective:** Measure forwarding throughput through the HA cluster.

```bash
# Server on WAN side (or use external target)
# Client on cluster-lan-host:
incus exec cluster-lan-host -- iperf3 -c <target> -P 4 -t 30 -C bbr
```

**Pass criteria:**
- Throughput > 1 Gbps through SNAT (generic XDP on iavf VF is the bottleneck)
- No packet loss during steady state
- Compare with/without HA overhead

### TC-9: DHCP Server on reth1

**Objective:** Verify cluster-lan-host can obtain an address via DHCP from the primary.

```bash
incus exec cluster-lan-host -- dhclient eth0
incus exec cluster-lan-host -- ip addr show eth0
```

**Pass criteria:**
- Lease obtained from 10.0.60.100-199 range
- Gateway set to 10.0.60.1 (reth1 VIP)

### TC-10: Split-Brain Prevention

**Objective:** Verify cluster handles heartbeat network failure gracefully.

```bash
# Disconnect heartbeat by removing device from fw1
incus config device remove xpf-fw1 eth1

# Both nodes should detect heartbeat loss
# Node 1 (lower priority) should go secondary-hold
sleep 10
printf 'show chassis cluster status\nexit\n' | incus exec xpf-fw0 -- cli
printf 'show chassis cluster status\nexit\n' | incus exec xpf-fw1 -- cli
```

**Pass criteria:**
- No dual-primary condition
- Higher-priority node retains primary
- Lower-priority node enters secondary-hold or lost state

### TC-11: IPv6 Router Advertisements and DHCPv6

**Objective:** Verify LAN hosts receive IPv6 configuration via SLAAC and DHCPv6.

```bash
# Verify radvd is running on primary with correct interface name
incus exec xpf-fw0 -- systemctl status radvd
incus exec xpf-fw0 -- cat /etc/radvd.conf
# Expected: interface name is physical member (ge-0-0-0), NOT "reth1"

# Verify kea-dhcp6 is running on primary
incus exec xpf-fw0 -- systemctl status kea-dhcp6-server

# Verify cluster-lan-host got IPv6 via SLAAC/DHCPv6
incus exec cluster-lan-host -- ip -6 addr show eth0
# Expected: global address in 2001:559:8585:cf01::/64

# Verify RA from cluster-lan-host (needs ndisc6 package)
incus exec cluster-lan-host -- rdisc6 eth0
# Expected: Router Advertisement from fe80::... with prefix 2001:559:8585:cf01::/64

# Ping IPv6 gateway
incus exec cluster-lan-host -- ping -c 3 2001:559:8585:cf01::1
```

**Pass criteria:**
- radvd running with physical interface name (not reth1)
- kea-dhcp6-server running
- cluster-lan-host has global IPv6 address
- IPv6 gateway reachable

### TC-12: Hitless Forwarding Failover (IPv4 + IPv6)

**Objective:** Verify transit traffic survives primary restart and full failover
with minimal disruption, for both IPv4 (with SNAT) and IPv6.

This tests two legacy `META_FLAG_KERNEL_ROUTE` BPF fallback paths:
- **LOCAL/NOT_FWDED:** After daemon restart, existing sessions have stale FIB
  cache (`fib_gen` mismatch). `bpf_fib_lookup` returns LOCAL/NOT_FWDED because
  FRR routes haven't converged. The packet routes through conntrack for NAT
  reversal and XDP_PASSes for kernel routing.
- **NO_NEIGH:** After VRRP failover, the new MASTER has no ARP/NDP entry for
  the next hop or the LAN client. `bpf_fib_lookup` returns NO_NEIGH. Same
  path: conntrack for NAT reversal, then kernel resolves ARP/NDP inline.

#### Ping-based tests

```bash
# IPv4 forwarding test through SNAT:
incus exec cluster-lan-host -- ping -c 30 -i 0.5 172.16.100.200 &
sleep 5
incus exec xpf-fw0 -- systemctl restart xpfd
# Expected: 28-29/30 received (1-2 packets lost during restart)

# IPv6 forwarding test (no SNAT, routed):
incus exec cluster-lan-host -- ping -c 30 -i 0.5 2607:f8b0:400f:806::200e &
sleep 5
incus exec xpf-fw0 -- systemctl restart xpfd
# Expected: similar 1-2 packet loss

# Full failover test (stop primary, secondary takes over):
incus exec cluster-lan-host -- ping -i 0.01 -c 500 -W 1 10.0.60.1 &
sleep 1
incus exec xpf-fw0 -- systemctl stop xpfd
# Expected: ~6 packets lost at 10ms interval = ~60ms failover
# (3× priority-0 burst on shutdown → peer immediate takeover)
sleep 5
incus exec xpf-fw0 -- systemctl start xpfd
# Expected: ~13 packets lost = ~130ms failback (daemon startup + sync hold)
```

#### iperf3 failover tests (throughput under failover)

These verify that bulk TCP transfers survive VRRP failover without permanent
connection death. The TCP cwnd should recover after a brief dip, not collapse.

```bash
# Requires an iperf3 server reachable from WAN (e.g. casper at 172.16.100.200
# for IPv4 or 2001:559:8585:100::247 for IPv6).

# --- IPv4 iperf3 failover ---
# 1. Start iperf3 on LAN host (60s, BBR for fast recovery)
incus exec cluster-lan-host -- iperf3 -c 172.16.100.200 -t 60 -C bbr &

# 2. After 15s of steady state, stop primary (full VRRP failover)
sleep 15
incus exec xpf-fw0 -- systemctl stop xpfd

# 3. Wait for secondary to take over, verify throughput resumes
sleep 20

# 4. Bring primary back (VRRP preemption)
incus exec xpf-fw0 -- systemctl start xpfd

# 5. Wait for iperf3 to finish, check results
# Expected: throughput dips to ~0 for ~2s during each transition,
# then recovers to multi-Gbps. Connection survives both transitions.

# --- IPv6 iperf3 failover ---
# 1. Start IPv6 iperf3 (routed, no SNAT)
incus exec cluster-lan-host -- iperf3 -c 2001:559:8585:100::247 -t 60 -C bbr &

# 2. Same failover sequence
sleep 15
incus exec xpf-fw0 -- systemctl stop xpfd
sleep 20
incus exec xpf-fw0 -- systemctl start xpfd

# Expected: same behavior — brief throughput dip, full recovery,
# connection survives. No cwnd collapse to 0.
```

**Pass criteria:**
- Hitless restart (systemctl restart): <= 2 packets lost (ping)
- Full failover (stop primary): <= 5 packets lost (ping)
- iperf3 IPv4: TCP connection survives failover + preemption, throughput recovers
- iperf3 IPv6: TCP connection survives failover + preemption, throughput recovers
- No permanent traffic blackhole or cwnd collapse
- Traffic auto-recovers after all transitions

**Verified results (2026-02-23):**

| Test | Steady | Failover dip | Recovery | Preemption dip | Result |
|------|--------|-------------|----------|----------------|--------|
| IPv4 SNAT iperf3 | 4.75 Gbps | ~4.2 Gbps (~2s) | 4.65 Gbps | ~4.1 Gbps (~2s) | PASS |
| IPv6 routed iperf3 | 4.80 Gbps | 0 Gbps (~6s) | 4.80 Gbps | seamless | PASS |

- **IPv4 SNAT:** Connection survived both failover and preemption with no cwnd collapse.
  cwnd briefly dipped to ~5.6 KB during the exact transition moment then immediately
  recovered. Throughput never dropped below 3.6 Gbps. Session sync + dnat_table
  replication ensured hitless SNAT continuation on the new primary.
- **IPv6 routed:** Connection survived with ~6s disruption during failover (longer than
  IPv4 because IPv6 has no dnat_table pre-population — relies entirely on session sync +
  VRRP MASTER transition + neighbor discovery). Preemption back to fw0 was seamless.

**How it works:**
1. Legacy BPF programs pinned at `/sys/fs/bpf/xpf/` survive daemon restart
2. Existing sessions preserved in pinned conntrack maps
3. After restart, FIB cache in session entries is stale (`fib_gen` mismatch)
4. `bpf_fib_lookup` may return LOCAL/NOT_FWDED (routes not yet in kernel)
   or NO_NEIGH (ARP/NDP not yet resolved on new MASTER)
5. `xdp_zone` detects existing session + failed FIB → sets `META_FLAG_KERNEL_ROUTE`
6. `xdp_conntrack` processes session normally (NAT reversal via meta fields)
7. `xdp_forward` sees `META_FLAG_KERNEL_ROUTE` → `XDP_PASS` for kernel routing
8. Kernel forwards the NAT'd packet via its own routing table, resolving ARP/NDP inline
9. Once FRR converges (~1-2s) and ARP/NDP resolves, fresh FIB lookups succeed
   and XDP resumes direct forwarding

### TC-13: IPv6 DNAT Across Fabric Redirect

**Objective:** Verify IPv6 DNAT'd traffic survives failover via fabric cross-chassis
redirect. Exercises `apply_dnat_before_fabric_redirect_v6()` which rewrites the
IPv6 destination and L4 port in the packet header before fabric redirect.

**Background:** When the active RG moves to the peer, the local node's cached session
points to an inactive egress interface. `xdp_zone` detects this and redirects the
packet over the fabric link to the peer. For DNAT sessions, the packet header still
has the original VIP destination — `apply_dnat_before_fabric_redirect_v6()` must
rewrite it to the real server address (using parsed `meta->l3_offset`/`meta->l4_offset`
for VLAN support, and skipping port checksum updates when `meta->csum_partial` is set).

**Prerequisites:**
- IPv6 DNAT rule in cluster config (e.g., `[reth0-VIP]:5201` → `[server]:5201`)
- IPv6 iperf3 server reachable from WAN

**Config additions needed:**
```
security {
    nat {
        destination {
            pool ipv6-server {
                address 2001:559:8585:100::247/128;
                port 5201;
            }
            rule-set wan-dnat-v6 {
                from zone wan;
                rule dnat-iperf6 {
                    match {
                        destination-address 2001:559:8585:50::6/128;
                        destination-port 5201;
                        protocol tcp;
                    }
                    then {
                        destination-nat pool ipv6-server;
                    }
                }
            }
        }
    }
}
```

```bash
# 1. Start IPv6 iperf3 through DNAT (WAN VIP → real server)
incus exec cluster-lan-host -- iperf3 -6 -c 2001:559:8585:50::6 -t 60 -P 4 &

# 2. Verify sessions on fw0 (should show DNAT flag)
incus exec xpf-fw0 -- cli -c 'show security flow session destination-prefix 2001:559:8585:50::6'

# 3. Verify sessions synced to fw1
incus exec xpf-fw1 -- cli -c 'show security flow session destination-prefix 2001:559:8585:50::6'

# 4. Failover RG1 to fw1
incus exec xpf-fw0 -- cli -c 'request chassis cluster failover redundancy-group 1 node 1'
sleep 5

# 5. Verify traffic still flowing (fw1 now MASTER, fabric redirect active)
incus exec cluster-lan-host -- curl -6 --connect-timeout 5 http://[2001:559:8585:50::6]:5201

# 6. Check iperf3 streams alive
# Expected: all streams alive, throughput > 0

# 7. Failback to fw0
incus exec xpf-fw0 -- cli -c 'request chassis cluster failover reset redundancy-group 1'
sleep 5

# 8. Verify traffic still flowing
```

**Pass criteria:**
- IPv6 DNAT sessions visible on both nodes (with DNAT flag set)
- iperf3 connections survive failover (RG1 fw0→fw1)
- iperf3 connections survive failback (RG1 fw1→fw0)
- No permanent stream death
- dnat_table_v6 entries created on secondary (verify via sync receiver logging)

**Validates:**
- `apply_dnat_before_fabric_redirect_v6()` correctness (parsed offsets, csum_partial)
- IPv6 RG-inactive cached session fabric redirect (missing DNAT call before this fix)
- `SetSessionV6(reverse)` and `SetDNATEntryV6` in sync receiver (error logging)

---

### TC-14: Port-Only DNAT Across Fabric Redirect

**Objective:** Verify DNAT that changes only the destination port (same IP) works
correctly across fabric redirect. This tests the fix for the short-circuit bug where
`apply_dnat_before_fabric_redirect_v6()` returned early when the destination IP
matched, skipping the L4 port rewrite.

**Background:** The old code short-circuited on `ip_addr_eq_v6(meta->dst_ip, ip6h->daddr)`.
For port-only DNAT (e.g., redirect port 80 → 8080 on the same VIP), the IPs match but
the port differs. The fix uses a `need_addr` flag so L4 port rewrite runs even when
the address hasn't changed.

**Config additions needed:**
```
security {
    nat {
        destination {
            pool port-redirect {
                address 2001:559:8585:50::6/128;  # same VIP
                port 8080;                         # different port
            }
            rule-set wan-dnat-port {
                from zone wan;
                rule port-only-dnat {
                    match {
                        destination-address 2001:559:8585:50::6/128;
                        destination-port 80;
                        protocol tcp;
                    }
                    then {
                        destination-nat pool port-redirect;
                    }
                }
            }
        }
    }
}
```

```bash
# 1. Start HTTP server on port 8080 behind the firewall
# (or use an iperf3 server on port 8080)

# 2. Connect to VIP:80 (DNAT rewrites port to 8080, same IP)
incus exec cluster-lan-host -- curl -6 --connect-timeout 5 \
    http://[2001:559:8585:50::6]:80/

# 3. Verify session shows DNAT with port change
incus exec xpf-fw0 -- cli -c 'show security flow session'
# Expected: session shows dst port translated 80→8080

# 4. Failover RG1 to fw1 (triggers fabric redirect)
incus exec xpf-fw0 -- cli -c 'request chassis cluster failover redundancy-group 1 node 1'
sleep 3

# 5. New connection to VIP:80 should still work via fabric
incus exec cluster-lan-host -- curl -6 --connect-timeout 5 \
    http://[2001:559:8585:50::6]:80/

# 6. Verify the packet was rewritten (port 80→8080) before fabric redirect
# Check fw1 sessions — should show correct port translation

# 7. Reset
incus exec xpf-fw0 -- cli -c 'request chassis cluster failover reset redundancy-group 1'
```

**Pass criteria:**
- Port-only DNAT works in steady state (no failover)
- Port-only DNAT survives failover via fabric redirect
- Session on peer shows correct port translation (80→8080)
- No checksum errors (verify with tcpdump on peer if needed)

**Validates:**
- Fix for `ip_addr_eq_v6` short-circuit — port rewrite runs even when IPs match
- Both IPv4 and IPv6 variants (test both `apply_dnat_before_fabric_redirect` paths)

---

### TC-15: Multi-Cycle Failover Under IPv6 Load

**Objective:** Verify IPv6 TCP streams survive repeated rapid failover cycles,
analogous to the IPv4 stress test (`test-stress-failover.sh`).

**Background:** The IPv4 stress test validates that 8 parallel iperf3 streams survive
N failover/failback cycles with 0 dead streams. This test extends coverage to IPv6,
exercising the IPv6 fabric redirect path (including DNAT rewrite if IPv6 DNAT rules
are configured) and IPv6 session sync.

```bash
# 1. Start IPv6 iperf3 with parallel streams
incus exec cluster-lan-host -- iperf3 -6 \
    -c 2001:559:8585:100::247 -t 120 -P 8 --forceflush \
    > /tmp/iperf3-v6-stress.log 2>&1 &

# 2. Wait for streams to establish
sleep 8

# 3. Verify v6 sessions on fw0 and fw1
incus exec xpf-fw0 -- cli -c 'show security flow session protocol tcp family inet6' \
    | grep -c 'State: Established'
# Expected: >= 8

# 4. Run 5 failover/failback cycles (30s interval)
for cycle in $(seq 1 5); do
    echo "=== Cycle $cycle: failover fw0→fw1 ==="
    incus exec xpf-fw0 -- cli -c 'request chassis cluster failover redundancy-group 1'
    sleep 15

    # Check for dead streams
    incus exec cluster-lan-host -- tail -21 /tmp/iperf3-v6-stress.log \
        | grep -E '^\[  [0-9]|^\[ [0-9][0-9]' | tail -8 \
        | grep -c '0.00 bits/sec' || true

    echo "=== Cycle $cycle: failback fw1→fw0 ==="
    incus exec xpf-fw0 -- cli -c 'request chassis cluster failover reset redundancy-group 1'
    incus exec xpf-fw1 -- cli -c 'request chassis cluster failover reset redundancy-group 1'
    incus exec xpf-fw0 -- cli -c 'request chassis cluster failover redundancy-group 1 node 0'
    sleep 15

    # Check again
    incus exec cluster-lan-host -- tail -21 /tmp/iperf3-v6-stress.log \
        | grep -E '^\[  [0-9]|^\[ [0-9][0-9]' | tail -8 \
        | grep -c '0.00 bits/sec' || true
done

# 5. Final: count total zero-throughput intervals
incus exec cluster-lan-host -- grep -E '^\[  [0-9]|^\[ [0-9][0-9]' \
    /tmp/iperf3-v6-stress.log | grep -c '0.00 bits/sec' || true
# Expected: 0

# 6. Cleanup
incus exec cluster-lan-host -- pkill -9 iperf3
```

**Pass criteria:**
- All 8 IPv6 streams alive after each failover and failback
- 0 zero-throughput intervals across the entire run
- iperf3 process alive at end of test
- Throughput >= 1.0 Gbps during steady state

**Validates:**
- IPv6 session sync (forward + reverse sessions, dnat_table_v6 entries)
- IPv6 fabric redirect under load (all existing-session paths)
- `apply_dnat_before_fabric_redirect_v6()` under repeated failovers
- Sync receiver error handling (slog.Warn on SetSessionV6/SetDNATEntryV6 failures)

**Future:** Integrate into `test-stress-failover.sh` as an `IPERF_FAMILY=6` option.

---

## Performance Expectations

| Metric | Expected | Verified | Notes |
|--------|----------|----------|-------|
| WAN throughput (per VF) | ~6-8 Gbps | — | iavf generic XDP, single direction |
| LAN throughput (virtio) | ~12-15 Gbps | — | virtio_net native XDP |
| HA throughput (IPv4 SNAT) | ~4-5 Gbps | 4.75 Gbps | LAN→WAN through SNAT |
| HA throughput (IPv6 routed) | ~4-5 Gbps | 4.80 Gbps | LAN→WAN, no NAT |
| IPv4 failover disruption | < 5 seconds | ~2 seconds | cwnd dip, no collapse |
| IPv6 failover disruption | < 10 seconds | ~6 seconds | session sync + ND |
| Failover time | ~3.5 seconds | ~3-4 seconds | Master-down timer (3×advert + skew) |
| Session sync latency | < 2 seconds | < 1 second | Ring buffer real-time + 1s sweep |
| Config sync latency | < 1 second | — | TCP immediate push on commit |
| IPv4 VIP recovery | < 1 second | — | Dual GARP + gateway ARP probe |
| IPv6 VIP recovery | < 1 second | — | Unsolicited NA + NODAD flag |

## Known Issues & Fixes (Post-Implementation)

### ConfigDB Bootstrap Caveat

The daemon stores compiled config in `.configdb/active.json`. On startup it loads
from this DB, NOT from the text `.conf` file. The text config is only read when the
DB is empty (first boot or after deletion).

**If you change `ha-cluster.conf` and redeploy**, the daemon will ignore the new
text file because `active.json` already exists. To force re-bootstrap:

```bash
incus exec xpf-fw0 -- rm /etc/xpf/.configdb/active.json
incus exec xpf-fw1 -- rm /etc/xpf/.configdb/active.json
make cluster-deploy  # re-push config + restart
```

Alternatively, use `load override` via CLI to load the new config interactively.

### Legacy BPF FIB LOCAL/NOT_FWDED Fix (`b0e7e33`)

**Problem:** After daemon restart or VRRP failover, existing sessions had stale FIB
cache entries. `bpf_fib_lookup` returned LOCAL or NOT_FWDED because FRR routes hadn't
converged yet. These packets fell into the host-inbound path in `xdp_forward` and
were either dropped (by host-inbound policy) or delivered to the kernel stack without
NAT reversal, causing RSTs.

**Fix:** Three-part change:
1. `xpf_common.h`: Added `META_FLAG_KERNEL_ROUTE` (1 << 2)
2. `xdp_zone.c`: In the FIB failure else-branch, check if packet matches an existing
   session (sv4/sv6 != NULL). If so, set `META_FLAG_KERNEL_ROUTE` and tail-call to
   conntrack for normal session processing and NAT reversal.
3. `xdp_forward.c`: When `fwd_ifindex == 0` and `META_FLAG_KERNEL_ROUTE` is set,
   bypass host-inbound policy and `XDP_PASS` for kernel routing. This is transit
   traffic that needs kernel forwarding, not host-bound traffic.

**Result:** Hitless restart loses only 1-2 packets (ARP/NDP warmup delay) instead of
permanent traffic blackhole for all existing sessions.

### Legacy BPF FIB NO_NEIGH Fix (`d95a84e`)

**Problem:** After VRRP failover, the new MASTER had no ARP/NDP entries for LAN
clients or WAN next-hops. `bpf_fib_lookup` returned NO_NEIGH for synced sessions.
The original fix (`0080cbc`) used XDP_DROP for existing sessions, relying on
userspace ARP warmup (~50ms). This worked for IPv4 but failed for IPv6 GUA
addresses that warmup didn't cover — return traffic was permanently dropped.

**Fix:** Changed NO_NEIGH handling for existing sessions from XDP_DROP to
`META_FLAG_KERNEL_ROUTE` + conntrack tail-call (same pattern as LOCAL/NOT_FWDED
fix). Packets route through NAT reversal first, then the kernel forwards and
resolves ARP/NDP inline (queues packet, sends ARP/NS, forwards on reply).

**Result:** IPv6 iperf3 at ~4.5 Gbps survives full VRRP failover with only a
~2s throughput dip. No dependency on userspace ARP warmup timing.

### MASTER-Only radvd and Kea DHCP (`d95a84e`)

**Problem:** Both cluster nodes ran radvd and Kea DHCP server, causing:
- LAN hosts received Router Advertisements from both nodes, creating two IPv6
  default routes (ECMP). Traffic hitting the BACKUP's link-local was blackholed.
- Dual DHCP servers could cause lease conflicts.

**Fix:** In cluster mode, `applyConfig()` skips radvd/kea startup. Instead,
`watchVRRPEvents()` manages them based on VRRP state:
- MASTER transition → `applyRethServices()` starts radvd + Kea
- BACKUP transition → `clearRethServices()` stops radvd + Kea

**Goodbye RA (`2d9ba6a`):** On BACKUP transition, `clearRethServices()` calls
`radvd.Withdraw()` which rewrites radvd.conf with `AdvDefaultLifetime 0`, reloads
(triggers an immediate RA with lifetime=0), waits 500ms, then stops radvd. This
tells LAN hosts to immediately remove the departing router as a default gateway,
preventing stale RA routes from persisting for up to 1800s.

### VRRP Implementation History
1. **Deadlock (`58ad85b`):** Manager write lock held during `stop()` which waited for blocking `recvmsg`. Fix: `SyscallConn().Control()`, `SetReadDeadline(1s)`, close-before-wait
2. **VLAN split-brain (`e018918`):** XDP strips VLAN tags; VRRP bypass didn't restore. Fix: push tag back, use AF_PACKET for VLAN sub-interfaces
3. **Per-interface sockets (`70b107c`):** Shared socket missed VLAN multicast. Fix: per-instance `SO_BINDTODEVICE` + self-sent filtering
4. **AF_PACKET for all (`d951626`):** Raw IP unreliable with generic XDP. Fix: AF_PACKET receiver for ALL instances; skip RETH VIP reconciliation
5. **Upstream GARP (`7bcaee9`):** Some routers ignore gratuitous ARP Reply. Fix: dual ARP format + gateway probe
6. **IPv6 VIP (`d03b29e`):** DAD failure + missing FRR interface + RETH name. Fix: NODAD flag + inline key extraction + RethMap translation
7. **Config sync (`64bc9d5`):** `${node}` unquoted in Format + no reverse-sync. Fix: `QuotedKeyPath()` + `OnPeerConnected` with startup guard

## SR-IOV Notes

- `eno6np1` (i40e) has 32 VFs; this setup uses 2 (VF0+VF1), leaving 30 for other uses
- VFs are passed through as PCI devices (`type=pci`), not `nictype=sriov` (which has hotplug issues)
- VFs use `iavf` driver inside VMs — **no native XDP**, only generic/SKB mode
- `redirect_capable` map in the legacy BPF path marks VF interfaces as non-redirectable
- VF interfaces fall back to `XDP_PASS` (kernel forwarding) instead of `bpf_redirect_map`
- WAN throughput is lower than LAN (virtio native XDP) due to generic mode overhead
- Spoof checking is ON by default on VFs — may need to be disabled for RETH MAC changes:
  ```bash
  ip link set eno6np1 vf <N> spoofchk off
  ```
