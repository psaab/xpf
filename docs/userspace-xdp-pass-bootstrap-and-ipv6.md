# Userspace Dataplane: XDP_PASS Bootstrap, IPv6 NDP, and Fast Restart

**Date:** 2026-03-21
**Commit:** `30383e6`
**Related issues:** Zero-copy fill ring starvation, IPv6 forwarding broken on VLAN interfaces, 40s restart gap

## Problem Statement

After daemon restart on the userspace HA cluster (`loss:xpf-userspace-fw0/fw1`), three problems existed:

1. **IPv4 forwarding dead for 40+ seconds** after restart, even though VRRP election should provide failover in ~1s
2. **IPv6 forwarding completely broken** on VLAN sub-interfaces (`ge-0-0-2.50`, `ge-0-0-2.80`) — `iperf3 -c 2001:559:8585:80::200` returned "No route to host"
3. **Kernel ARP/NDP tables empty** because the XDP shim captured all ARP replies and NDP NAs, preventing the kernel from learning neighbors

## Root Causes

### 1. Historical XDP Shim Tail-Call Silent Failure

At the time of this investigation, the Rust eBPF XDP shim
(`userspace-xdp/src/lib.rs`) used `USERSPACE_FALLBACK_PROGS.tail_call()` to
jump back to `xdp_main_prog` when the userspace dataplane could not handle a
packet. **This tail call always silently failed** in aya-ebpf, despite the prog
array being correctly populated (verified via `bpftool map dump`).

Issue #1473 removed this runtime dependency: the retained userspace shim now
passes only proven local/control traffic to the kernel when helper/XSK state is
degraded. Non-local transit drops in both compat and strict modes and is counted
as `transit_drop` in `degraded_path_counters`. The pinned BPF map still uses the
internal compatibility name `userspace_fallback_stats` during mixed-version
upgrades.

When the tail call failed, the function fell through to `return Ok(xdp_action::XDP_DROP)`, silently dropping all fallback packets. This affected three code paths:

| Path | Trigger | Old Behavior | New Behavior |
|------|---------|-------------|-------------|
| Historical tail-call fallback | Heartbeat missing/stale, early filter | `XDP_DROP` | Local/control pass; transit `XDP_DROP` |
| Binding not ready | VLAN sub-interface without XSK binding | `XDP_DROP` | Local/control pass; transit `XDP_DROP` |
| Heartbeat stale | Timeout exceeded | `XDP_DROP` | Local/control pass; transit `XDP_DROP` |

**Impact:** Every packet that should have fallen back to the eBPF pipeline was silently dropped. During startup bootstrap, this meant zero forwarding.

### 2. Generic XDP on VLAN Sub-Interfaces Breaks NDP

The compiler attaches XDP programs to VLAN sub-interfaces (`ge-0-0-2.50`, `ge-0-0-2.80`) in `xdpgeneric` mode. When the userspace shim was swapped in, these VLAN sub-interfaces also got the shim.

**The problem:** When the parent interface's native XDP returns `XDP_PASS` for a VLAN-tagged packet, the kernel demuxes the VLAN tag and delivers to the sub-interface. The sub-interface's generic XDP then runs. For NDP Neighbor Solicitation (solicited-node multicast), the shim's `should_fallback_early()` returns true (multicast) and does `XDP_PASS`. But **generic XDP + XDP_PASS on VLAN devices doesn't properly deliver NDP packets to the kernel's IPv6 NDP state machine**.

Evidence: `ping6` to the LAN interface (non-VLAN `ge-0-0-1`) worked perfectly. `ping6` to any VLAN interface was 100% loss. Removing generic XDP from the VLAN sub-interface immediately fixed NDP.

**Fix:** Skip XDP attachment on VLAN sub-interfaces when the userspace shim is active (`pkg/dataplane/compiler.go`). The parent's native XDP handles all VLAN-tagged traffic. New `VlanSubInterfaces` map in `loader.go` tracks which ifindexes to skip during userspace-shim swaps.

### 3. VIPs Missing from `userspace_local_v6` BPF Map

The XDP shim checks `USERSPACE_LOCAL_V6` to determine if a packet's destination is a local address (→ `cpumap_or_pass` to kernel) vs transit (→ redirect to XSK). The map was populated from the config snapshot, which only contains statically configured addresses.

**VRRP VIPs are added dynamically** after election — they were never in the map. This meant:
- ICMPv6 echo replies to the WAN VIP (`2001:559:8585:80::8`) were redirected to XSK as transit traffic
- NDP NAs for the VIP were not recognized as local
- Any IPv6 traffic destined to the firewall's own WAN VIPs was misclassified

**Fix:** `syncLocalAddressMapsLocked()` in `maps_sync.go` now enumerates ALL kernel addresses via `netlink.AddrList(nil, family)`, including dynamically added VIPs. This runs periodically in the status update loop.

**Hardening — no prune on incomplete enumeration (#3924):** the reconcile
adds the desired local keys and then prunes any map key not in the desired
set. Because the desired set is built partly from `netlink.AddrList`, a
transient netlink failure (or an interrupted / `ENOBUFS` partial dump)
produced an INCOMPLETE desired set that was still treated as authoritative —
so the prune removed the VRRP VIP keys (and any other kernel-owned local
address) from `userspace_local_v4`/`userspace_local_v6`, blackholing
VIP/SSH/BGP/IKE traffic destined to the firewall's own endpoints, and the
`AddrList` error was swallowed silently. `buildDesiredLocalAddressSets` now
reports whether the enumeration was COMPLETE (all `AddrList` family dumps
succeeded). On an incomplete enumeration the reconcile still performs the
adds (adding a key only ever widens the local set — always safe) but SKIPS
the stale-key prune for that cycle and logs a warning; the next reconcile
with a complete enumeration removes any genuinely stale keys. Pruning is
therefore only ever performed against a known-complete desired set. This is
the same fail-safe-reconcile posture used elsewhere: never act destructively
on incomplete input. `userspace_local_v4`/`v6` are the only maps affected —
the interface-NAT and config-derived local sets are snapshot-only and do not
enumerate the kernel.

### 4. Kernel Never Learns ARP/NDP from XSK-Captured Packets

When the XDP shim redirects packets to XSK, the kernel never sees them. The helper parses ARP replies and NDP NAs to update its internal `dynamic_neighbors` cache, but the kernel's own ARP/NDP tables stayed empty.

This caused two problems:
- **Kernel-originated traffic** (ping from fw0 itself) couldn't resolve neighbors
- **Local/control kernel delivery** during bootstrap sent host-owned packets to the kernel, which couldn't answer correctly because it had no ARP/NDP entries

**Fix:** After learning a neighbor from an ARP reply or NDP NA, the helper now calls `add_kernel_neighbor()` which sends a raw netlink `RTM_NEWNEIGH` message to add the entry to the kernel's neighbor table. For VLAN interfaces, `resolve_ingress_logical_ifindex()` resolves the correct sub-interface ifindex from the VLAN tag.

### 5. Zero-Copy Fill Ring Bootstrap (XSK RQ Starvation)

After fresh XSK binding in zero-copy mode (mlx5), the NIC's XSK Receive Queue (RQ) needs NAPI to post fill ring entries as hardware DMA WQEs. The helper's `sendto()`/`poll()` triggers `ndo_xsk_wakeup`, which only activates the ICOSQ NAPI — **not the regular RX NAPI that posts XSK fill ring entries**.

If heartbeat was written immediately, the XDP shim redirected to XSKMAP. On queues where the XSK RQ hadn't been bootstrapped, the redirect either failed silently or succeeded but the NIC couldn't deliver packets (no WQEs).

**Fix:** `xsk_rx_confirmed` flag in `BindingWorker`. Heartbeat is only written after the XSK RX ring has delivered at least one packet, proving the NIC's XSK RQ is active. Until then, the XDP shim sees no heartbeat: proven local/control traffic may reach the kernel, while non-local transit drops and retries rather than bypassing policy/NAT/conntrack. Background traffic (VRRP advertisements, ARP, heartbeats) naturally bootstraps each queue's NAPI over time.

### 6. Session Sync Readiness Timeout Too Long

The readiness gate blocked VRRP election until the peer's bulk session sync was received. The timeout was 30 seconds. In a restart scenario, the peer is clearly alive (heartbeat received within ~1s), but the reverse bulk sync from the peer can take 10-30+ seconds depending on TCP reconnection timing.

**Fix:** Reduced timeout from 30s to 5s. Also reduced ctrl enable delay from 10s to 3s and heartbeat grace period from 15s to 6s.

## Timeline Improvement

| Phase | Before | After |
|-------|--------|-------|
| systemctl stop + start | ~6s | ~6s |
| Session sync timeout | 30s | 5s |
| Ctrl enable delay | 10s | 3s |
| Hold timer | 3s | 3s |
| **Total gap (no fw1)** | **39.5s** | **~14s** |
| **fw1 takeover gap** | N/A (fw1 broken) | **2.25s** |

With both nodes running the new code, fw1 takes over in ~2.25s and forwards traffic while fw0 restarts. When fw0 comes back (after ~14s), it preempts fw1 and resumes as primary.

## Files Changed

| File | Changes |
|------|---------|
| `userspace-xdp/src/lib.rs` | Local/control kernel delivery and degraded transit drop paths |
| `userspace-dp/src/afxdp.rs` | `xsk_rx_confirmed`, `add_kernel_neighbor()` via netlink, ARP/NDP reinject, grace period tuning |
| `pkg/dataplane/compiler.go` | Skip XDP on VLAN sub-interfaces with userspace shim, `VlanSubInterfaces` tracking |
| `pkg/dataplane/loader.go` | `VlanSubInterfaces` field, skip during userspace-shim swaps |
| `pkg/dataplane/userspace/manager.go` | Kernel address enumeration for local map, ctrl delay 3s |
| `pkg/daemon/daemon.go` | Session sync timeout 5s |
| `pkg/dataplane/userspace_xdp_bpfel.o` | Rebuilt XDP shim object |

## Verification

```bash
# IPv4 transit (steady state)
source test/incus/cluster-env.sh   # IPERF_TARGET4: loss 172.16.80.202 (#18576)
incus exec loss:cluster-userspace-host -- ping -c 5 -W 1 "$IPERF_TARGET4"
# 5/5, 0% loss

# IPv6 transit (was completely broken)
incus exec loss:cluster-userspace-host -- ping6 -c 5 -W 1 2001:559:8585:80::200
# 5/5, 0% loss

# IPv6 iperf3 (was "No route to host")
incus exec loss:cluster-userspace-host -- iperf3 -c 2001:559:8585:80::200 -P 8 -t 10
# 21.4 Gbps aggregate

# Restart test: start ping, restart fw0, measure gap
# Pre-fix: 39.5s continuous gap
# Post-fix: 2.25s gap (fw1 takeover), 14s total recovery
```

## Remaining Known Issues

1. **Retired tail-call dependency:** #1473 removed
   `USERSPACE_FALLBACK_PROGS.tail_call()` from the userspace shim. Compat
   and strict degraded paths now pass only proven local/control traffic and
   fail closed for non-local transit.

2. **XSK RQ bootstrap timing:** Quiet queues (no background traffic) may never bootstrap until a hardware RX event reaches that queue. Under load (iperf3), all queues bootstrap within milliseconds. During the unproven window, transit is dropped instead of forwarded through the kernel.

3. **VLAN sub-interface XDP:** Skipping XDP on VLAN sub-interfaces means the eBPF pipeline doesn't run on demuxed VLAN traffic when the userspace shim is NOT active (e.g., during initial compile before shim swap). The parent's XDP handles the raw VLAN-tagged packet, which is sufficient for the userspace path.
