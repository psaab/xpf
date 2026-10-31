# Performance Optimizations

## Implemented

### 1. Disable bpf_printk (`e104112`)
- **Impact:** 55%+ CPU → negligible
- Debug tracing was the #1 CPU consumer

### 2. Reduce per-packet memset/memcpy (`299a536`)
- Only zero fields actually used, not entire scratch struct

### 3. FIB result caching in sessions (`144a3c2`)
- Cache `fwd_ifindex`, `fwd_dmac`, `fwd_smac` in session entries
- Skip `bpf_fib_lookup` on established flows
- Skip cache on TCP SYN (need fresh FIB for new connections)

### 4. Per-CPU NAT port partitioning (`7aa77f0`)
- Eliminate cross-CPU contention on NAT port counters

### 5. Per-interface native XDP (`f9edb92`)
- virtio-net: native XDP + `ndo_xdp_xmit` → `bpf_redirect_map`
- i40e (PCI passthrough PF): native XDP + `ndo_xdp_xmit` → `bpf_redirect_map`
- Historical: iavf (SR-IOV VF) forced generic XDP → `XDP_PASS` for kernel forwarding
- All-or-nothing mode: code tries native on ALL interfaces, falls back to generic if ANY fails
- `redirect_capable` BPF array map tells xdp_forward which mode each interface supports
- **Result:** ~6.8 Gbps → 25+ Gbps

### 6. Disable init_on_alloc (`a0aabfd`)
- **Impact:** Eliminates 20% CPU from `clear_page_erms` page zeroing
- Debian's `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` zeros every allocated page
- Boot param `init_on_alloc=0` in GRUB; set in `test/incus/setup.sh`
- Not runtime tunable — boot-time only

## Perf Profile (virtio-net, init_on_alloc=0, Feb 2026)

During iperf3 trust→untrust through firewall (~12 Gbps BBR, ~6 Gbps CUBIC):
```
 6.7%  xdp_forward_prog      (forwarding stage)
 5.9%  xdp_main_prog         (entry point)
 4.6%  receive_buf           (virtio-net RX)
 4.3%  htab_map_hash         (BPF hash map lookups)
 3.8%  xdp_zone_prog         (zone + conntrack fast-path)
 2.7%  lookup_nulls_elem_raw (hash element traversal)
 2.3%  virtnet_rq_unmap      (virtio RX buffer cleanup)
 2.1%  virtnet_xdp_xmit      (XDP redirect TX)
 1.9%  read_tsc              (conntrack ktime)
 1.8%  virtnet_rq_alloc      (virtio RX buffer alloc)
 1.7%  __htab_map_lookup_elem (hash map lookup wrapper)
```

## Previous Perf Profile (Native XDP, Physical NIC, Feb 2026)

BPF programs total ~10% CPU. Generic XDP infrastructure ~16% (only on iavf interface).
FIB lookup: 0% (cached in session entries).

```
 2.8%  htab_map_hash         (BPF hash map lookups)
 2.7%  xdp_main_prog         (entry point)
 2.5%  read_tsc              (conntrack ktime)
 2.1%  lookup_nulls_elem_raw (hash element traversal)
 2.0%  iavf_xmit_frame       (SR-IOV TX — generic XDP only)
 1.7%  xdp_forward_prog      (forwarding stage)
 1.6%  csum_partial          (TX checksum)
 1.5%  xdp_conntrack_prog    (session lookup)
 1.1%  xdp_zone_prog         (zone + conntrack fast-path)
 1.0%  xdp_nat_prog          (NAT translation)
```

### 7. Host GRUB: init_on_alloc=0 + hardened_usercopy=off + mitigations=off
- **Impact (measured):** 21-25% throughput increase (12.1→14.7 Gbps reverse, 12.2→15.2 Gbps forward, 8×BBR)

### 8. tc mirred bridge bypass (tested, not persisted)
- **Impact (measured):** +6-7% throughput (14.7→15.6 Gbps reverse, 15.2→16.3 Gbps forward, 8×BBR)
- `tc filter add dev <tap> ingress matchall action mirred egress redirect dev <veth>` (and reverse)
- Problem: blanket `matchall` breaks host-routed traffic (WAN, DHCP, ARP to bridge IP)
- Needs selective filter (e.g., match on dst MAC) to avoid redirecting non-peer traffic
- Not persisted — rules are ephemeral and lost on reboot
- Host was running with `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` (31% in `clear_page_erms`),
  `CONFIG_HARDENED_USERCOPY_DEFAULT_ON=y` (18% in `__check_object_size`),
  and full CPU mitigations enabled
- Added to `/etc/default/grub` + `update-grub`; requires reboot

### 9. IPv6 established-flow cache in `xdp_zone` (`perf-ipv6-flow-cache`)
- **Goal:** reduce `sessions_v6` lookup pressure for long-running IPv6 TCP flows
- Added a small per-CPU exact-flow cache for established IPv6 TCP traffic
- Cache is intentionally narrow:
  - IPv6 only
  - TCP ACK/data only
  - no `SYN/FIN/RST`
  - no `NAT64`, `ALG`, or predicted sessions
- Cache entries batch counter / `last_seen` writeback to the real session map
- Invalidates on FIB generation change or RG ownership loss
- Design notes: `docs/next-features/ipv6-session-fast-path.md`

### 10. IPv6 no-extension parse fast path + narrower NAT rewrite (`perf-ipv6-flow-cache`)
- Added a common-case fast return in `parse_ipv6hdr()` when the base IPv6 header directly names the upper-layer protocol
- The generic extension-header walker now runs only when extension headers are actually present
- Reworked `nat_rewrite_v6()` to specialize by protocol and actual NAT direction
- This avoids repeated protocol branches and avoids touching source/destination fields that are not changing for the packet

## Host-Side Perf Profile (from host during iperf through VM, Feb 2026)

Profile captured from the **host** (not VM). No BPF/XDP stacks visible — XDP pipeline
is essentially free from host perspective. Bottleneck is entirely virtualization:

```
67.38%  memcpy (vhost ring copy)     — rep_movs_alternative in handle_tx_copy/handle_rx
59.40%  KVM hypervisor               — vcpu_halt, apic, vmx_sync, lapic
49.61%  checksum (csum_partial)      — TCP/IP checksum (no HW offload on tun/tap)
31.36%  clear_page_erms              — init_on_alloc=1 (FIXED in GRUB)
24.30%  TCP stack                    — iperf3 endpoint processing on containers
23.87%  Linux bridge                 — br_handle_frame for every packet (tap↔veth)
20.30%  flow dissect + hash          — __skb_flow_dissect + siphash for multiqueue
18.09%  HARDENED_USERCOPY            — __check_object_size (FIXED in GRUB)
12.33%  netif backlog                — process_backlog / __netif_receive_skb
11.64%  slab alloc/free              — kmem_cache/slab for skb lifecycle
10.10%  vhost virtqueue ops          — vhost_get_vq_desc_n / vhost_net_buf_peek
 8.46%  skb free                     — consume_skb / skb_release_data
 5.84%  GSO segmentation             — tcp_gso_segment / skb_segment
```
(Percentages sum >100% due to perf report hierarchy duplication)

### Key insight
The Incus bridge networks (xpf-trust, xpf-untrust, etc.) each have only 2 ports
(VM tap + container veth), so the bridge adds ~24% CPU overhead with zero benefit.
Switching to macvtap, routed, or tc-redirect could eliminate this entirely.

## Future Possibilities

### Bridge + veth for iavf
- Bridge iavf with a veth pair; attach XDP to veth end (fully supports native)
- Would eliminate remaining generic XDP overhead on WAN interface
- Pro: no BPF changes. Con: extra bridge hop, network config complexity

### XDP-capable NIC replacement
- ice, i40e, mlx5, ixgbe, bnxt all support native XDP
- Would make all interfaces native, eliminate need for redirect_capable map

### BPF hash map optimization
- `htab_map_hash` is the top BPF-related CPU consumer
- Could explore bloom filter pre-check or session ID optimization
- Diminishing returns — 2.8% is already very low

### Incus bridge bypass for test containers
- Bridges (xpf-trust, etc.) consume ~24% host CPU just for 2-port L2 forwarding
- Options: macvtap NIC type, `tc redirect` hairpin, or routed mode
- Would eliminate `br_handle_frame` + `br_dev_queue_push_xmit` overhead

### Host flow dissect / hash reduction
- `__skb_flow_dissect` + `siphash` consume ~20% on host for multiqueue steering
- Could disable RPS/RFS on tap devices if single-queue is sufficient
- `ethtool -K tapXXX rx-flow-hash off` (if supported)

### Virtio-net checksum offload
- `csum_partial` is 50% of host CPU — host computing checksums for tun/tap path
- Verify guest csum offload is enabled end-to-end
- SR-IOV passthrough (already used for WAN) bypasses this entirely

## Cluster Failover Timing (mode-specific; historical measurements)

The `ae1a717` VRRP measurements below describe the legacy VRRP-backed RETH
path, not the compiler-default private-RG election mode. The latter uses
heartbeat detection. Runtime heartbeat defaults are 100ms × 5 = 500ms; the
deployed lab config is 200ms × 5 = 1s. The receiver checks staleness every
quarter heartbeat interval (interval / 4, floored at 10 ms; #18639), so a peer
is declared within that check period of its last admitted heartbeat turning
interval × threshold old. While session sync looks connected, a peer that has
acked a sync-level heartbeat on this incarnation (#18570) must answer a
liveness probe sent at its first missed heartbeat (once its last heartbeat is
1.5 intervals old); any sync frame handled after the probe counts as the
answer. A hard-crashed peer is then declared at the threshold, provided the
ack latch had armed and no frame the peer queued before it died is handled
after the probe: about 0.5–0.525 s after its last heartbeat (0.4–0.525 s after
the crash) at defaults and 1.0–1.05 s (0.8–1.05 s) in the lab. A frame is
stamped when it is handled, not when it arrived (`notePeerLiveness`), so a
pre-crash backlog handled after the probe answers it; on the half-open socket
a hard crash leaves, no FIN watchdog bounds that backlog, and the recency rule
below runs from the last such frame. If no probe could be pre-armed because
the late heartbeats fell inside the 5 s restart grace or the boot floor, the
crash is declared counting from the grace's end: at the first check after it
if sync is then disconnected or more than 2 s stale; otherwise an ack-capable
peer is probed then and gets (threshold − 1.5) intervals (350 ms at defaults,
700 ms in the lab) plus a check period, and a peer without ack support follows the rule below. A peer without ack support keeps the #17056 recency rule:
max(threshold, remaining 2 s sync window) plus a check period, with a 5 s cap
on continuous suppression. A process crash that sends FIN, or sync idle for
more than 2 s, falls back to the plain threshold when the receiving standby is
caught up, subject to startup/restart grace; a standby still draining a
backlog when the peer's FIN/RST arrives keeps sync installed while it drains,
and its frames refresh peer recency for up to one 1 s watchdog tick, so there
detection is up to max(threshold, ~3 s) plus a check period — about 3.0 s at
defaults and 3.05 s in the lab, under the 5 s cap (#18521; the probe does not
shorten it, because backlog frames handled after the probe answer it). `show
chassis cluster information` prints "Liveness probes sent: N (unanswered at
timeout: M, peer acks probes: yes|no)", which tells an operator which case
applies. These are detection times, not traffic restoration: activation adds
about 0.34–0.44 s from peer-lost to the first ping reply on the lab clusters
(#18561), so a lab crash outage lands near 1.4 s. (`compileChassis` in
`pkg/config/compiler_chassis.go`;
`DefaultHeartbeatInterval`/`DefaultHeartbeatThreshold` in
`pkg/cluster/heartbeat.go`; `timeoutCheckInterval` and
`heartbeatReceiver.checkTimeout` in `pkg/cluster/heartbeat.go`;
`prearmPeerLivenessProbe`, `peerAnsweredLivenessProbeLocked` and
`syncSuppressesPeerTimeoutLocked` in `pkg/cluster/heartbeat_suppress.go`;
`notePeerLiveness` in `pkg/cluster/sync_payload_caps_16041.go`;
`handlePeerTimeout` in `pkg/cluster/heartbeat_manager.go`;
`docs/ha-cluster-userspace.conf:71-72`).

### Legacy VRRP-backed RETH mode (`no-private-rg-election`)
- The 30ms advertisement default is configurable with
  `set chassis cluster reth-advertise-interval <ms>`; the master-down timer is
  `3 × advertised interval + priority skew` (>90ms and <120ms at 30ms for
  priorities 1–255). This is a detection timer, not an end-to-end restoration
  measurement (`pkg/config/compiler_system.go:3119-3122`;
  `pkg/vrrp/vrrp.go:153-166`; `pkg/vrrp/instance_timing.go:112-128`).
- The historical test note recorded ~60ms in the legacy VRRP path; it is not
  a current-default promise.
- Planned legacy shutdown sends three priority-0 adverts and arms a 1ms backup
  timer; the run-loop test requires takeover within 50ms (test constraint, not
  SLA) (`pkg/vrrp/instance.go:770-807`;
  `pkg/vrrp/instance_rx.go:155-173`;
  `pkg/vrrp/instance_prio0_run_test.go:143-149`).
- `becomeMaster()` sends the advertisement synchronously and GARP in a
  background goroutine (the prior blocking path cost about 200ms).
- `SendGratuitousARPBurst()` sends the first pair <1ms, then remaining at 50ms
  intervals in the background.
- `AdvertiseInterval` is milliseconds internally and centiseconds on wire;
  per-RG `GratuitousARPCount` is wired through to VRRP instances.
- A non-preempting legacy VRRP BACKUP has the 3s deafness window at process
  start and sync-hold release, reset by the first peer advert
  (`pkg/vrrp/instance.go:71-93`;
  `pkg/vrrp/instance_timing.go:17-41`;
  `pkg/vrrp/instance_rx.go:151-173`).
- Event debounce is 500ms before priority updates only in legacy VRRP-backed
  mode (was 2s; `pkg/daemon/daemon_ha.go:782-824`).

### Current mode and related timers
- Heartbeat staleness uses `set chassis cluster heartbeat-interval <ms>` and
  `set chassis cluster heartbeat-threshold <n>`; startup/restart grace also
  applies, with the cold-boot floor ending early once bring-up is proven
  over (#18549) (`pkg/cluster/heartbeat.go:61-98,1916-1960`).
- Interface/IP monitoring is separate: polls every 1s, requires three
  consecutive failed polls, and has a default 5s state-change hold-down. IP
  probes run 16 at a time with 800ms per-target deadlines and 500ms cycle
  slack; more than 16 targets add 800ms waves
  (`pkg/cluster/monitor.go:28-57,242-276,383-398,585-600`).
- Ordinary private-RG shutdown sends no resign frame; after `rg_active`
  clears, the peer promotes no sooner than the heartbeat threshold and may be
  deferred further by the sync-recency guard. Operator-initiated private-RG
  failover is a distinct explicit peer-transfer path
  (`pkg/daemon/daemon_run_shutdown.go:418-428`;
  `pkg/cluster/manager.go:1026-1077`;
  `pkg/cluster/heartbeat.go:61-65,1916-1960`;
  `pkg/daemon/daemon_ha_sync.go:170-206`;
  `pkg/cluster/failover.go:447-450`;
  `pkg/cluster/election.go:1021-1042`).
- Sync hold is 30s in both the VRRP and no-RETH startup paths (released early
  when bulk sync completes), not 10s
  (`pkg/daemon/daemon_run_bringup.go:260-273`;
  `pkg/daemon/daemon_ha_noreth_hold.go:42-53`;
  `pkg/vrrp/manager.go:355-379`).

### Other historical optimization notes
- Session-sync reconnect makes its first dial immediately and retries at a
  1s cadence; this is a reconnect interval, not a failback completion bound
  (`pkg/cluster/sync_conn.go:1379-1414`).
- `test/incus/xpfd.service` uses `RestartSec=1`
  (`test/incus/xpfd.service:9-11`).

### Historical measured failover/failback times (legacy test records)
| Scenario | Original | `ff7821c` | `ae1a717` |
|----------|----------|-----------|-----------|
| Failover (daemon dies → peer takes over) | ~3.2s | ~0.8s | ~60ms |
| Clean stop (priority-0 → peer skew) | ~219ms | ~55ms | Historical result not source-backed |
| Failback (daemon returns → preempts) | ~5-6s | ~2-3s | Not source-backed |
| Single node reboot → MASTER | N/A | ~6s | ~6s |
| Simultaneous reboot → converge | N/A | ~10s | ~10s |

The table is retained as historical test data only; its old clean-stop and
failback rows are not current-default end-to-end bounds.
