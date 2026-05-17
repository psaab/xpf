# Test Environment Details

> #1373 note: this document primarily describes the standalone and legacy eBPF
> Incus environments. The default target for new dataplane validation is the
> userspace AF_XDP cluster (`loss:xpf-userspace-fw0/fw1`) and the runbooks under
> `docs/userspace-*.md` / `testing-docs/`. Keep the legacy procedures here for
> explicit regression coverage.

## Network Topology
```
                    +-----------+
                    | Host      |
                    | (Debian)  |
                    +-----+-----+
                          |
              +-----------+-----------+------ ...
              |           |           |
         incusbr0    xpf-trust  xpf-untrust  xpf-dmz
         10.0.100.1  10.0.1.1     10.0.2.1       10.0.30.1
              |           |           |              |
        +-----+-----+----+-----------+--------------+------+
        |  xpf-fw VM                                      |
        |  enp5s0 → fxp0     (mgmt)     DHCP       — incusbr0      |
        |  enp6s0 → em0      (unused)               — incusbr0      |
        |  enp7s0 → ge-0-0-0 (trust)    10.0.1.10   — xpf-trust   |
        |  enp8s0 → ge-0-0-1 (untrust)  10.0.2.10   — xpf-untrust |
        |  enp9s0 → ge-0-0-2 (dmz)      10.0.30.10  — xpf-dmz     |
        |  PCI    → ge-0-0-3 (wan)  i40e PCI pass — wan zone (VLAN 50)  |
        |  PCI    → ge-0-0-4 (loss) i40e PCI pass — loss zone          |
        +---------------------------------------------------------------+
```

## Test Containers (iperf endpoints)
```
trust-host    10.0.1.102    on xpf-trust bridge
untrust-host  10.0.2.102    on xpf-untrust bridge
dmz-host      10.0.30.101   on xpf-dmz bridge
```
- Traffic between containers traverses xpf-fw VM (firewall)
- trust→untrust: permitted by policy
- untrust→trust: blocked except DNAT HTTP (junos-http to 10.0.1.100:80 via DNAT from 10.0.2.10:8080)

## WAN / Internet Interface
- i40e PF via PCI passthrough (VFIO)
- Device appears as `enp10s0f0np0` in VM
- `vlan-tagging` enabled, unit 50 with `vlan-id 50`
- Static IPv4: 172.16.50.5/24, default gateway 172.16.50.1
- Static IPv6: 2001:559:8585:50::5/64, default route via fe80::50 on enp10s0f0np0.50
- Default routes configured via `routing-options { static { ... } }`

## Management Interface (fxp0)
- UseRoutes=false in systemd-networkd — suppresses DHCP default route
- FRR is the sole route manager — only FRR routes in kernel FIB
- Still reachable via 10.0.100.0/24 connected route (for incus access)

## IPv6 Addressing
```
ge-0/0/0  (trust)    2001:559:8585:bf01::1/64
ge-0/0/1  (untrust)  2001:559:8585:bf02::1/64
ge-0/0/2  (dmz)      2001:559:8585:bf03::1/64
ge-0/0/3.50          2001:559:8585:50::5/64
```
- Router advertisements enabled on trust, untrust, dmz (managed + other-stateful)
- DHCPv6 server pools on trust, untrust, dmz (::100 to ::1ff range)

## Zone Policy Matrix
| From \ To | trust | untrust | dmz | tunnel | wan | loss |
|-----------|-------|---------|-----|--------|-----|------|
| trust     | -     | permit  | permit | - | permit+SNAT | permit+SNAT |
| untrust   | DNAT web only | - | HTTP only | - | permit+SNAT | permit+SNAT |
| dmz       | -     | -       | -   | - | permit+SNAT | permit+SNAT |
| tunnel    | permit | -      | -   | - | - | - |
| default   | deny-all | deny-all | deny-all | deny-all | deny-all | deny-all |

## SNAT Rules
- trust->wan: interface SNAT
- untrust->wan: interface SNAT
- dmz->wan: interface SNAT
- trust->loss: interface SNAT (loss0)
- untrust->loss: interface SNAT (loss0)
- dmz->loss: interface SNAT (loss0)

## DNAT Rules
- untrust->trust: 10.0.2.10:8080 -> 10.0.1.100:80 (pool web-server)
- untrust->trust: [2001:559:8585:bf02::1]:8080 -> [2001:559:8585:bf01::100]:80 (pool web-server-v6)

## Firewall Filters
- `dscp-filter` (inet, on untrust ge-0/0/1 input): accepts DSCP EF, blocks SSH (tcp/22), accepts rest
- `block-ra` (inet6, on untrust ge-0/0/1 input): blocks ICMPv6 type 134 (router advertisements), accepts rest

## Screen / IDS
- `untrust-screen`: tcp land, syn-flood; icmp ping-death; ip source-route-option

## Flow Settings
- `tcp-mss { ipsec-vpn 1350; }` — MSS clamping for IPsec
- `allow-dns-reply` — permit DNS responses without sessions (legacy BPF conntrack wiring: `1a8b873`)
- `allow-embedded-icmp` — allow ICMP errors referencing existing sessions
- ALG disabled: dns, ftp

## Services
- DHCP server pools on trust, untrust, dmz (IPv4 + IPv6)
- RPM probe `isp-health`: ICMP ping to 10.0.2.1 every 5s, 3 successive-loss threshold
- Flow monitoring: NetFlow v9 to 192.168.99.104:4739 (1:1 sampling)
- SNMP: community "public", ifTable MIB for interface counters

## Testing Patterns
- **Remote CLI:** `incus exec xpf-fw -- cli`
- **Non-interactive:** `printf 'show ...\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null`
- **HTTP API:** `incus exec xpf-fw -- curl -s http://127.0.0.1:8080/health`
- **Legacy BPF/XDP verify:** `incus exec xpf-fw -- bpftool net show`
- **FRR routes:** `incus exec xpf-fw -- vtysh -c 'show ip route'`
- **Forwarding test:** create trust-host/untrust-host containers, set IPs + routes, ping across zones

## XDP Mode per Interface
| Interface | Driver | XDP Mode | Reason |
|-----------|--------|----------|--------|
| ge-0-0-0 (enp7s0) | virtio_net | native | supports ndo_xdp_xmit |
| ge-0-0-1 (enp8s0) | virtio_net | native | supports ndo_xdp_xmit |
| ge-0-0-2 (enp9s0) | virtio_net | native | supports ndo_xdp_xmit |
| ge-0-0-3 (PCI) | i40e | native | PF driver supports ndo_xdp_xmit |
| ge-0-0-4 (PCI) | i40e | native | PF driver supports ndo_xdp_xmit |

## Legacy BPF Pin Paths
```
/sys/fs/bpf/xpf/          # Stateful maps (sessions, DNAT, NAT64, NAT ports)
/sys/fs/bpf/xpf/links/    # XDP/TC link pins (xdp_N, tc_N per ifindex)
```

## Performance Testing
```bash
# iperf through firewall (trust→untrust):
sg incus-admin -c "incus exec untrust-host -- iperf3 -s -D"
sg incus-admin -c "incus exec trust-host -- iperf3 -c 10.0.2.102 -t 10 -P 4 -C bbr"
# Expected: ~12 Gbps with BBR, ~6 Gbps with CUBIC

# Perf profile on VM during iperf:
sg incus-admin -c "incus exec xpf-fw -- perf record -a -g -o /tmp/perf.data -- sleep 15"
sg incus-admin -c "incus exec xpf-fw -- perf report -i /tmp/perf.data --stdio --no-children -g none --percent-limit 1"
```

### Virtio-net performance notes
- Multi-queue: auto-enabled by Incus (combined=16 matching vCPUs), not a knob to tune
- `init_on_alloc=0` in GRUB: eliminates 20% CPU waste from `clear_page_erms` page zeroing
- BBR vs CUBIC: BBR nearly doubles throughput through virtio
- **After GRUB + tc bypass:** 15.6 Gbps reverse / 16.3 Gbps forward (8×BBR)
- **After GRUB only:** 14.7 Gbps reverse / 15.2 Gbps forward
- **Baseline (no tuning):** ~12.1 Gbps reverse / ~12.2 Gbps forward

### Required test procedures after deploy
- Ping: trust→untrust, trust→dmz, trust→wan, VM→wan
- MTR: trust→untrust (zone-to-zone), trust→wan (zone-to-wan) — verify hop 1 shows firewall IP
- iperf: trust→untrust forward + reverse
- Host bottleneck is vhost-net copy path (`handle_tx_copy`); SR-IOV bypasses entirely
- The high retransmit count with BBR is expected (BBR probes bandwidth by inducing loss)

## VRF / Routing Instance Testing

### What was implemented
Per-interface VRF routing via `iface_zone_map` on the legacy eBPF path. The BPF map value was extended from
bare `__u16 zone_id` to `struct iface_zone_value { zone_id, routing_table }`. When a
packet arrives on an interface belonging to a routing instance, `xdp_zone` sets
`meta->routing_table` from the map. All `bpf_fib_lookup` calls pass `BPF_FIB_LOOKUP_TBID`
when `routing_table != 0`. PBR from firewall filters takes priority over VRF routing.

### Current test config
`dmz-vr` routing instance: ge-0-0-2 in VRF, rib-group route leaking to main table.

### Infrastructure verification (DONE)
```bash
# 1. VRF device exists
sg incus-admin -c "incus exec xpf-fw -- ip vrf show"
# Expected: vrf-dmz-vr  100

# 2. Interface bound to VRF
sg incus-admin -c "incus exec xpf-fw -- ip link show ge-0-0-2"
# Expected: master vrf-dmz-vr, XDP still attached

# 3. VRF routing table populated
sg incus-admin -c "incus exec xpf-fw -- ip route show table 100"
# Expected: 10.0.30.0/24 connected

# 4. FRR has per-VRF route
sg incus-admin -c "incus exec xpf-fw -- cat /etc/frr/frr.conf" | grep -A 2 vrf
# Expected: vrf vrf-dmz-vr section

# 5. No regressions — existing zones still work
sg incus-admin -c "incus exec trust-host -- ping -c 3 10.0.2.102"     # trust→untrust
sg incus-admin -c "incus exec trust-host -- ping -c 3 8.8.8.8"         # trust→internet
sg incus-admin -c "incus exec trust-host -- ping -c 3 10.0.30.101"     # trust→dmz
sg incus-admin -c "incus exec trust-host -- ping -6 -c 3 2001:4860:4860::8888"  # IPv6
```

### Functional VRF routing tests (DONE — tunnel-host on xpf-tunnel bridge)
These tests verify the legacy BPF path actually uses the VRF table for FIB
lookups on VRF-bound interfaces.

**Setup:**
```bash
# Create tunnel-host container (one-time)
sg incus-admin -c "incus init images:debian/13 tunnel-host --storage default --network xpf-tunnel"
sg incus-admin -c "incus start tunnel-host"
# Gets DHCP 10.0.40.2 from bridge; add static IP + default via firewall:
sg incus-admin -c "incus exec tunnel-host -- ip addr add 10.0.40.102/24 dev eth0"
sg incus-admin -c "incus exec tunnel-host -- ip route replace default via 10.0.40.10"
```

**Test 1: Host-inbound via VRF-bound interface (PASS)**
```bash
sg incus-admin -c "incus exec tunnel-host -- ping -c 3 10.0.40.10"
# Success: host-inbound-traffic allows ping for tunnel zone
```

**Test 2: VRF isolation — no cross-VRF route (PASS — correctly drops)**
```bash
sg incus-admin -c "incus exec tunnel-host -- ping -c 3 -W 2 10.0.1.102"
# 100% loss: VRF table 100 has no route to 10.0.1.0/24
# FIB lookup fails → XDP_PASS → kernel also can't route in VRF → dropped
```

**Test 3: Cross-VRF forwarding with route leaking (PASS)**
Requires two route leaks:
1. **Forward:** `10.0.1.0/24 dev enp6s0` in VRF table 100 (so BPF FIB resolves egress)
2. **Return:** `10.0.40.0/24 dev enp9s0` in main table (so reply finds VRF interface)
Plus tunnel→trust security policy.
```bash
# Forward leak (cross-VRF route in table 100 pointing to non-VRF interface)
sg incus-admin -c "incus exec xpf-fw -- ip route replace 10.0.1.0/24 via 10.0.1.102 dev enp6s0 table 100"
# Return leak (main table needs route back to VRF subnet)
sg incus-admin -c "incus exec xpf-fw -- ip route add 10.0.40.0/24 dev enp9s0 table main"
# Test
sg incus-admin -c "incus exec tunnel-host -- ping -c 3 10.0.1.102"
# Success: 3/3 packets, ~0.3ms RTT
```
Flow: tunnel-host → enp9s0 (routing_table=100) → FIB in table 100 → egress enp6s0 (trust)
→ policy tunnel→trust permit → session created → bpf_redirect to enp6s0 → trust-host

**Key lesson: VRF route leaking is bidirectional.** Forward route leak alone gets the
session created (sessions counter increments), but return traffic routes via WAN default
unless the main table also has a route back to the VRF subnet.

**Test 4: Verify PBR overrides VRF routing (TODO)**
```bash
# Add firewall filter on tunnel interface with `then routing-instance <other>;`
# Verify meta->routing_table uses PBR table, not VRF table
```

### Multi-ISP VRF test (TODO — needs dual WAN or simulated topology)
The primary use case for VRF routing. Each WAN interface gets its own routing instance
with its own default route. Internal interfaces use PBR (firewall filter `then
routing-instance ISP-A;`) to select which WAN VRF to use.

```
routing-instances {
    ISP-A {
        instance-type virtual-router;
        interface enp10s0f0np0.50;
        routing-options {
            static { route 0.0.0.0/0 { next-hop 172.16.50.1; } }
        }
    }
}
```

**Key considerations for multi-ISP:**
- Moving WAN interface to VRF removes its connected route from main table
- Global `routing-options { static { route 0.0.0.0/0 ... } }` must move into the
  routing instance (or be removed) — otherwise main table has unreachable next-hop
- Internal interfaces (trust, untrust) stay in main table (routing_table=0)
- PBR via firewall filter selects routing instance: `then routing-instance ISP-A;`
- Without PBR, internal→WAN FIB lookup in main table would fail (no default route)
- Return traffic on WAN uses VRF table — needs route leaking for internal networks
  OR conntrack fast-path handles it (established sessions cache FIB data, skip xdp_zone)

### Edge cases to test
1. **Hitless restart with VRF**: VRF device and interface binding survive restart
   (non-destructive SIGTERM doesn't clean up VRFs)
2. **Config rollback**: Rolling back from VRF config to non-VRF should unbind interface
   and delete VRF device
3. **VLAN + VRF**: Interface like `enp10s0f0np0.50` in a routing instance — verify
   the ifaceRef lookup in `ifaceTableID` map uses the correct name format
4. **Multiple routing instances**: Two or more VRFs with different table IDs, verify
   correct table ID in the legacy BPF map per interface
5. **IPv6 in VRF**: FIB lookup for IPv6 destinations with TBID flag
6. **NAT64 in VRF**: NAT64 FIB lookups use meta->routing_table
7. **ICMP error in VRF**: Embedded ICMP error routing (xdp_conntrack) uses VRF table

### Host kernel tuning (in /etc/default/grub, requires reboot)
- `init_on_alloc=0` — eliminates 31% host CPU from `clear_page_erms`
- `hardened_usercopy=off` — eliminates 18% host CPU from `__check_object_size`
- `mitigations=off` — disables Spectre/Meltdown/MDS for perf testing
- Host kernel: 6.18.5+deb14-amd64, `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`, `CONFIG_HARDENED_USERCOPY_DEFAULT_ON=y`
- Full GRUB line: `intel_iommu=on transparent_hugepage=never default_hugepagesz=1G hugepages=20 iommu=pt console=tty1 console=ttyS1,115200 init_on_alloc=0 hardened_usercopy=off mitigations=off`

## Hitless Restart Testing
```bash
# Start iperf3, restart daemon 3x during, verify zero drops
iperf3 -c 10.0.30.101 -P 4 -R -t 40 &
for i in 1 2 3; do sleep 8; sg incus-admin -c 'incus exec xpf-fw -- systemctl restart xpfd'; done
# Expected: 25+ Gbps sustained, zero stuck streams
```

## Full Teardown
```bash
incus exec xpf-fw -- xpfd cleanup   # Remove all legacy BPF pins + FRR routes
```

## Chassis Cluster (Two-VM HA) Test Environment

### Single-Config Model
Both nodes share `docs/ha-cluster.conf` using `apply-groups "${node}"`. Node ID from `/etc/xpf/node-id`.

### Topology
```
               eno6np1 (i40e PF, X722 10G)
             VF0 (PCI)       VF1 (PCI)
              0000:b7:06.0    0000:b7:06.1
                   |            |
          +--------+---+  +----+-------+
          | xpf-fw0  |  | xpf-fw1  |
          | node 0     |  | node 1     |
          | pri 200    |  | pri 100    |
          +------------+  +------------+
          | fxp0  DHCP |  | fxp0  DHCP|  ← incusbr0
          | em0  .0.1  |←→| em0  .0.2 |  ← xpf-heartbeat
          | ge-0-0-0→fab0|←→|ge-7-0-0→fab0| ← xpf-fabric
          | ge-0-0-1→fab1|←→|ge-7-0-1→fab1| ← xpf-fabric1
          | ge-0-0-3   |  | ge-7-0-3  |  ← SR-IOV VF (PCI passthrough)
          |  └reth0────|──|──reth0┘   |  RETH: 172.16.50.6/24
          | ge-0-0-2   |  | ge-7-0-2  |  ← xpf-clan bridge
          |  └reth1────|──|──reth1┘   |  RETH: 10.0.60.1/24
          +------------+  +------------+
                               |
                    +----------+-----+
                    | cluster-lan-   |
                    | host           |
                    | eth0: 10.0.60.102 |
                    +----------------+
```

### IP Addressing
| Link | Subnet | fw0 | fw1 |
|------|--------|-----|-----|
| Heartbeat (em0) | 10.99.0.0/30 | 10.99.0.1 | 10.99.0.2 |
| Fabric (fab0) | 10.99.1.0/30 | 10.99.1.1 | 10.99.1.2 |
| WAN RETH (reth0) | 172.16.50.0/24 | VIP 172.16.50.6 | |
| LAN RETH (reth1) | 10.0.60.0/24 | VIP 10.0.60.1 | |

### Networks (L2 bridges, no Incus IP)
- `xpf-heartbeat` — heartbeat UDP:4784
- `xpf-fabric` — session sync TCP
- `xpf-clan` — LAN RETH + test container

### Profile: `xpf-cluster`
- 4 CPU, 4GB RAM, 20GB disk
- eth0→incusbr0 (fxp0), eth1→xpf-heartbeat (em0), eth2→xpf-fabric (ge-X-0-0→fab0), eth3→xpf-fabric1 (ge-X-0-1→fab1), eth4→xpf-clan (ge-X-0-2), eth5→incusbr0 (ge-X-0-3, spare)
- SR-IOV VF added per-VM as PCI passthrough device `wan-vf` (ge-X-0-4)

### Config
- Single unified config: `docs/ha-cluster.conf` (pushed to both VMs as `/etc/xpf/xpf.conf`)
- Node ID: `/etc/xpf/node-id` (plain integer: 0 or 1)

### Setup Script: `test/incus/cluster-setup.sh`
```
./cluster-setup.sh init       # Create networks + profile
./cluster-setup.sh create     # Launch VMs + container
./cluster-setup.sh deploy all # Build + push to both VMs
./cluster-setup.sh destroy    # Tear down
./cluster-setup.sh ssh 0|1    # Shell into VM
./cluster-setup.sh status     # Show all status
./cluster-setup.sh logs 0|1   # Show xpfd logs
./cluster-setup.sh start|stop|restart [0|1|all]
```

### Validation Steps
1. Heartbeat: fw0 pings fw1 on 10.99.0.x via em0
2. Fabric: fw0 pings fw1 on 10.99.1.x via fab0
3. Cluster status: `show chassis cluster status` — fw0=primary, fw1=secondary
4. RETH active: reth0/reth1 IPs on fw0 only
5. LAN connectivity: cluster-lan-host pings 10.0.60.1
6. Failover: stop xpfd on fw0 → fw1 becomes primary
7. Preempt: restart fw0 → fw0 reclaims primary
8. Config sync: commit on fw0 → fw1 receives config
9. Read-only: `configure` on fw1 secondary → "not writable" error

## Cluster HA Bug Testing Procedures

### VRRP Split-Brain Test (`e018918`, `70b107c`)
Verify VRRP instances on VLAN sub-interfaces don't go split-brain.
```bash
# Deploy to both VMs
sg incus-admin -c 'make cluster-deploy'

# Check VRRP state — fw0 should be MASTER for all groups
printf 'show security vrrp\nexit\n' | sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
printf 'show security vrrp\nexit\n' | sg incus-admin -c 'incus exec xpf-fw1 -- cli' 2>/dev/null
# Expected: fw0=MASTER for groups 101+102, fw1=BACKUP for both

# Verify no split-brain — only one node has VIPs
sg incus-admin -c 'incus exec xpf-fw0 -- ip addr show ge-0-0-1.50' | grep '172.16.50.6'
sg incus-admin -c 'incus exec xpf-fw1 -- ip addr show ge-7-0-1.50' | grep '172.16.50.6'
# Expected: VIP only on fw0
```

### VRRP Failover Test (`d951626`, `7bcaee9`, updated `ff7821c`, `ae1a717`)
Verify failover completes within ~100ms with 30ms VRRP intervals.
```bash
# Rapid ping from cluster-lan-host to LAN RETH VIP (10ms interval)
sg incus-admin -c 'incus exec cluster-lan-host -- ping -i 0.01 -c 500 -W 1 10.0.60.1' &

# Stop fw0 to trigger failover (sends 3× priority-0 burst)
sleep 1
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl stop xpfd'

# Expected: ~6 lost pings at 10ms interval = ~60ms failover
# (masterDown ~97ms with 30ms intervals; planned stop near-instant via priority-0)
# Check fw1 became MASTER:
sg incus-admin -c 'incus exec xpf-fw1 -- cli -c "show security vrrp"'

# Restart fw0 — preemption should reclaim primary within ~150ms
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl start xpfd'
sleep 3  # wait for daemon startup + legacy BPF load + sync hold
sg incus-admin -c 'incus exec xpf-fw0 -- cli -c "show security vrrp"'
```

### IPv6 VIP Reachability Test (`d03b29e`)
Verify IPv6 VRRP VIP is reachable and DAD doesn't interfere.
```bash
# From host, test both VIPs
ping -c 3 172.16.50.6        # IPv4 WAN VIP
ping -c 3 2001:559:8585:50::6  # IPv6 WAN VIP

# Verify no DAD issues on primary
sg incus-admin -c 'incus exec xpf-fw0 -- ip -6 addr show ge-0-0-1.50' | grep 2001:559:8585:50::6
# Expected: "nodad" flag present, NOT "dadfailed tentative"

# Verify FRR IPv6 route points to VLAN sub-interface (not parent)
sg incus-admin -c 'incus exec xpf-fw0 -- grep "ipv6 route" /etc/frr/frr.conf'
# Expected: "ipv6 route ::/0 fe80::50 ge-0-0-1.50 5"

sg incus-admin -c 'incus exec xpf-fw0 -- ip -6 route show default'
# Expected: "via fe80::50 dev ge-0-0-1.50" (NOT dev ge-0-0-1)
```

### Config Sync Test (`64bc9d5`)
Verify config sync works in both directions.
```bash
# Forward sync: commit on primary → secondary receives
printf 'configure\nset routing-options static route 10.77.77.0/24 discard\ncommit\nexit\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
sleep 3
printf 'show configuration routing-options | match 77\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw1 -- cli' 2>/dev/null
# Expected: "route 10.77.77.0/24 discard;"

# Reverse sync: stop+start fw0 → fw0 gets config from fw1
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl stop xpfd'
sleep 2
# Add route on fw1 (becomes primary during fw0 downtime)
printf 'configure\nset routing-options static route 10.88.88.0/24 discard\ncommit\nexit\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw1 -- cli' 2>/dev/null
# Restart fw0 — should receive fw1's config before preempting
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl start xpfd'
sleep 10
printf 'show configuration routing-options | match 88\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
# Expected: "route 10.88.88.0/24 discard;" (synced from fw1)

# Cleanup: remove test routes
printf 'configure\ndelete routing-options static route 10.77.77.0/24\ndelete routing-options static route 10.88.88.0/24\ncommit\nexit\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
```

### Manual Failover / Reset Test (`6d63020`)
Verify per-RG manual failover and reset work correctly with connectivity.
```bash
# Baseline: all RGs on node0
echo 'show chassis cluster' | sg incus-admin -c 'incus exec xpf-fw0 -- cli'
# Expected: all RGs node0=primary, node1=secondary

# Manual failover RG1 → node1
echo 'request chassis cluster failover redundancy-group 1 node 1' | \
  sg incus-admin -c 'incus exec xpf-fw0 -- cli'
sleep 2

# Verify: RG1 node0=secondary(Manual=yes), node1=primary
echo 'show chassis cluster' | sg incus-admin -c 'incus exec xpf-fw0 -- cli'
echo 'show chassis cluster' | sg incus-admin -c 'incus exec xpf-fw1 -- cli'

# LAN VIP connectivity must survive failover (0% loss)
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'
sg incus-admin -c 'incus exec cluster-lan-host -- ping -6 -c 3 2001:559:8585:cf01::1'

# Reset failover — node0 preempts back
echo 'request chassis cluster failover reset redundancy-group 1' | \
  sg incus-admin -c 'incus exec xpf-fw0 -- cli'
sleep 2

# Verify: RG1 node0=primary, node1=secondary, Manual=no
echo 'show chassis cluster' | sg incus-admin -c 'incus exec xpf-fw0 -- cli'

# LAN VIP connectivity after reset (0% loss)
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'
sg incus-admin -c 'incus exec cluster-lan-host -- ping -6 -c 3 2001:559:8585:cf01::1'
```

### LAN RETH Connectivity Test
```bash
# From cluster-lan-host, ping LAN RETH VIP
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'
# Expected: 3/3 success, <1ms RTT
```

### Full Cluster Validation Sequence
Run all cluster tests in order after any VRRP/cluster/config-sync changes:
```bash
# 1. Deploy
sg incus-admin -c 'make cluster-deploy'
sleep 10

# 2. Check cluster status
printf 'show chassis cluster status\nexit\n' | sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null

# 3. VIP reachability (IPv4 + IPv6)
ping -c 3 172.16.50.6 && ping -c 3 2001:559:8585:50::6

# 4. LAN connectivity
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'
sg incus-admin -c 'incus exec cluster-lan-host -- ping -6 -c 3 2001:559:8585:cf01::1'

# 5. Failover + recovery
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl stop xpfd'
sleep 1  # 30ms VRRP → ~97ms failover (planned stop near-instant via priority-0)
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'  # should reach fw1
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl start xpfd'
sleep 5  # daemon startup + legacy BPF load + sync hold
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'  # should reach fw0 again

# 6. Manual failover + reset
echo 'request chassis cluster failover redundancy-group 1 node 1' | \
  sg incus-admin -c 'incus exec xpf-fw0 -- cli'
sleep 2
echo 'show chassis cluster' | sg incus-admin -c 'incus exec xpf-fw0 -- cli'
# RG1: node0=secondary(Manual=yes), node1=primary
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'
sg incus-admin -c 'incus exec cluster-lan-host -- ping -6 -c 3 2001:559:8585:cf01::1'
echo 'request chassis cluster failover reset redundancy-group 1' | \
  sg incus-admin -c 'incus exec xpf-fw0 -- cli'
sleep 2
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'
sg incus-admin -c 'incus exec cluster-lan-host -- ping -6 -c 3 2001:559:8585:cf01::1'
```

### Cluster Reboot Tests (`f8353de`, `a4eb2b2`)
Verify interface naming and VIP stability survive VM reboots.
```bash
# Test 1: Single node reboot (secondary)
sg incus-admin -c 'incus restart xpf-fw1'
sleep 30  # wait for boot + daemon start
# Verify: all interfaces renamed, VRRP BACKUP, connectivity OK
sg incus-admin -c 'incus exec xpf-fw1 -- ip -br link'
printf 'show security vrrp\nexit\n' | sg incus-admin -c 'incus exec xpf-fw1 -- cli' 2>/dev/null

# Test 2: Single node reboot (primary) — should reclaim MASTER
sg incus-admin -c 'incus restart xpf-fw0'
sleep 30
# Verify: MASTER in ~6s, VIPs present, connectivity OK
printf 'show security vrrp\nexit\n' | sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'

# Test 3: Simultaneous reboot — both converge within ~10s
sg incus-admin -c 'incus restart xpf-fw0' &
sg incus-admin -c 'incus restart xpf-fw1' &
wait
sleep 35
# Verify: fw0=MASTER, fw1=BACKUP, all VIPs present (including IPv6)
printf 'show security vrrp\nexit\n' | sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
printf 'show security vrrp\nexit\n' | sg incus-admin -c 'incus exec xpf-fw1 -- cli' 2>/dev/null
sg incus-admin -c 'incus exec xpf-fw0 -- ip addr show ge-0-0-0' | grep 'cf01::1'
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'
sg incus-admin -c 'incus exec cluster-lan-host -- ping -6 -c 3 2001:559:8585:cf01::1'

# Verify .link files use OriginalName= for RETH members
sg incus-admin -c 'incus exec xpf-fw0 -- grep -l OriginalName /etc/systemd/network/10-xpf-ge-*.link'
# Expected: ge-0-0-0.link and ge-0-0-1.link use OriginalName=
```

## Makefile Targets
```
make test-env-init   # Install incus, create networks + profiles
make test-vm         # Create Debian 13 VM with FRR, strongSwan
make test-deploy     # Build -> push binary + config + unit -> systemctl enable --now
make test-ssh        # Shell into VM
make test-status     # Instance + service + network info
make test-logs       # journalctl -u xpfd -n 50
make test-journal    # journalctl -u xpfd -f (follow)
make test-start/stop/restart  # Service lifecycle
make test-destroy    # Tear down
```
