# Testing & Performance Guide

> Retirement notice (#1373, complete): the eBPF dataplane retirement is
> done — the Rust AF_XDP userspace dataplane is the only runtime forwarding
> path, the legacy XDP/TC source was deleted in #1476, and `system
> dataplane-type ebpf` is hard-rejected at commit and runtime. The eBPF
> standalone/HA procedures and performance notes below are HISTORICAL: they
> describe a backend that is no longer selectable and are preserved only as
> context. For current validation, use the userspace path.

For current userspace validation, use
[`userspace-ha-validation.md`](userspace-ha-validation.md) and the
`loss:xpf-userspace-fw0/fw1` cluster.

## Test Environment

### VM Setup (Incus)
```
Host: Debian, kernel 6.18.5+deb14-amd64
VM:   Ubuntu 26.04, stock kernel >= 6.18 (#1943; bake.py parity)
      8 vCPU, 4 GB RAM
```

### Network Topology
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
        +-----+-----+----+-----------+--------------+-----------+
        |  xpf-fw VM                                          |
        |  enp5s0 → fxp0    (mgmt)     DHCP    — incusbr0      |
        |  enp6s0 → em0     (unused in standalone)              |
        |  enp7s0 → ge-0-0-0 (trust)   10.0.1.10  — trust zone |
        |  enp8s0 → ge-0-0-1 (untrust) 10.0.2.10  — untrust    |
        |  enp9s0 → ge-0-0-2 (dmz)     10.0.30.10 — dmz zone   |
        |  PCI    → ge-0-0-3 (wan)     172.16.50.5 — wan zone   |
        |  PCI    → ge-0-0-4 (loss)    PCI passthrough          |
        +-------------------------------------------------------+
```

### Interface Details
| Interface | Renamed | Driver | XDP Mode | Zone | Address |
|-----------|---------|--------|----------|------|---------|
| enp5s0 | fxp0 | virtio_net | native | mgmt | DHCP |
| enp6s0 | em0 | virtio_net | native | — | unused (standalone) |
| enp7s0 | ge-0-0-0 | virtio_net | native | trust | 10.0.1.10/24 |
| enp8s0 | ge-0-0-1 | virtio_net | native | untrust | 10.0.2.10/24 |
| enp9s0 | ge-0-0-2 | virtio_net | native | dmz | 10.0.30.10/24 |
| enp10s0f0np0 | ge-0-0-3 | i40e (PF) | native | wan | VLAN 50, 172.16.50.5 + IPv6 |
| enp101s0f1np1 | ge-0-0-4 | i40e (PF) | native | loss | PCI passthrough |

All interfaces renamed at boot by `xpf-link-setup.service` (PCI bus order → vSRX names), configured via `.network` files by xpfd.

### DUT Isolation — Exactly One Firewall Per Gateway (#1992)

**Before any forwarding or stall measurement, isolate the DUT: exactly ONE
firewall may answer the dataplane gateway IPs at a time.**

The standalone firewall claims the SAME static gateway IPs on every run —
`10.0.1.10` on `ge-0-0-0` (trust bridge) and `10.0.2.10` on `ge-0-0-1`
(untrust bridge), per `test/incus/xpf-test.conf`. The `trust-host` and
`untrust-host` test containers default-route through those IPs. If a SECOND
firewall VM is attached to the same trust/untrust bridges, it claims the same
gateway IPs, and the test hosts' gateway ARP resolves **nondeterministically
to whichever firewall last answered or GARP'd**.

During a sustained flow the gateway MAC can flip mid-stream to a firewall that
is not forwarding to the other side, producing a classic "~4 Gbps → 0 for
several seconds → recover with a retransmit burst" pattern and making the
intended DUT's RX-queue irq counter read 0 (the traffic went elsewhere). This
was **misdiagnosed as a virtio_net per-queue NAPI-quiesce kernel bug** in
#1961 before an isolated run — stop the other firewalls, only the DUT
answering, kernel `ip_forward=0` — proved plain-virtio forwards rock-steady at
~4 Gbit/s, 0 stalls, both directions.

`test/incus/setup.sh` now enforces this: `create-vm`, `create-ct`, and
`deploy` call `assert_sole_dataplane_owner` first and **refuse to proceed**
when another instance is attached to BOTH the trust and untrust bridges
(single-sided test hosts like `trust-host`/`untrust-host` are not flagged —
they do not claim the gateway IP). Set `XPF_FORCE_TEARDOWN_PEERS=1` to stop and
delete the conflicting firewall(s) automatically:

```bash
# Refused with guidance if another firewall holds the gateways:
make test-deploy

# Or remove the colliding firewall(s) and proceed:
XPF_FORCE_TEARDOWN_PEERS=1 ./test/incus/setup.sh deploy

# Manual isolation:
incus stop <other-firewall> && incus delete --force <other-firewall>
```

When you cannot tear a peer down, pin static ARP for the gateway to the DUT's
MAC on the test host (or assert exactly one ARP answerer for the gateway)
before measuring — never trust a forwarding/stall number taken while two
firewalls share the gateway.

### WAN Interface (PF Passthrough)
- Intel X710 PF (enp10s0f0np0 on host) passed through via PCI/VFIO
- i40e driver has **native XDP** — no generic mode overhead
- Appears as `enp10s0f0np0` inside VM
- PCI passthrough via: `incus config device add VM internet pci address=<BDF>`
- VLAN 50 tagging configured in Junos config, handled by the active dataplane
- IPv6: 2001:559:8585:50::5/64

### Zone Policy Matrix
| From \ To | trust | untrust | dmz | wan | loss |
|-----------|-------|---------|-----|-----|------|
| trust | - | permit | permit | permit+SNAT | permit+SNAT |
| untrust | DNAT web only | - | HTTP only | permit+SNAT | permit+SNAT |
| dmz | - | - | - | permit+SNAT | permit+SNAT |
| default | deny-all | deny-all | deny-all | deny-all | deny-all |

---

## What a green run did NOT examine (#9052)

A gate that reports a clean board for a subject it never looked at is worse
than no gate, because it retires the question. Four of them did, and the fixes
are here rather than in a tracker because a procedure that lives only in an
issue is not read before the next gate is written.

### `make test` is not the whole board

`go test ./...` prints `ok` for a package whose cells all **skipped**: the
summary line for "everything passed" and "nothing ran" is byte-identical, and
no leg passes `-v`. So:

| Command | What it examines that nothing else does |
|---|---|
| `sudo make test-root` | the XDP shim's behavioural cells. They SKIP unprivileged, and the #1864 verifier gate does **not** substitute — two distinct WRONG fixes of the #7494 fragment bug both pass it. `make test` now prints a line saying it did not examine them. |
| `make go-skip-census` | every Go `t.Skip` in the tree, counted per bucket and ratcheted |
| `make ignored-cell-census` | every Rust `#[ignore]`, including the third crate outside both workspaces |
| `make test-cold-path-flooder` | 44 `#[test]`s in `test/incus/cold-path-flooder`, which was reached by nothing |
| `make harness-census` | every runnable shell harness under `test/incus/` |
| `make selftest` | the self-test layer: every hermetic self-test, plus the censuses (go-skip, harness, ignored-cell, go-buildtag, miri, interpreter, selftest) and the ledger legs |

### The go-skip census, and the thing it found

`make go-skip-census` counts skip call sites into four **named** buckets and
ratchets each against a floor in `scripts/go-skip-census.floors`. It reds in
both directions: a growth is a subject the suite stopped examining, and a
shrink is good news that must be banked, because a loose floor is exactly that
much room for the next regression to hide in.

The buckets are the point:

- **`priv-absent`** — shed when privilege is absent (40 at last census).
- **`priv-present`** — shed when privilege is **present** (10). This direction
  is why the split exists: **no single run examines all 50.** Running the suite
  as root does not close the gap, it swaps which subjects go unexamined — and
  folded into one "root-gated" total that is invisible, making the obvious
  remedy look like a fix when it is a trade.
- **`other`** — environment-, tool- and fixture-gated skips.
- **`unparsed`** — sites the census counted but could not classify:
  `t.SkipNow()` (no message by construction) and non-literal messages. It is a
  **reported** bucket with its own floor, deliberately, rather than a silent
  drop. A census that quietly shrinks its own population is blind exactly where
  somebody wrote something unusual, and "unusual" correlates with "worth
  looking at" — the #9088 lesson, applied ahead of time.

It does **not** judge whether a skip is justified. There is no marker
convention on Go skips, so such a verdict would be a guess off message prose,
and a census whose verdict is a guess trains people to argue with it.

### There is no CI

`.github/` contains only `instructions/`, and the Makefile says so twice. Every
gate above is developer-invoked and chained from no default target. The merge
criterion in `docs/engineering-style.md` used to read "squash merge once CI is
green", which was **vacuously satisfiable**; it now names the gates and when to
run each.

## Build & Deploy Workflow

```bash
# Legacy/full build (BPF codegen + Go binary)
make generate && make build

# Primary userspace dataplane helper
make build-userspace-dp

# Run unit tests — Go suite AND Rust userspace-dp cargo suite (#4006).
# A Rust dataplane regression fails `make test`. `make test-go` /
# `make test-rust` run one leg; the Rust leg needs cargo (~minutes).
make test

# Deploy to Incus VM
make test-deploy    # build -> push -> install -> restart

# Monitor
make test-logs      # journalctl -n 50
make test-journal   # journalctl -f (follow)
make test-status    # instance + service + network info
```

### Permission Issues
If `incus` commands fail: `sg incus-admin -c "make test-deploy"`

### Remote CLI Access
```bash
# Interactive
incus exec xpf-fw -- cli

# Non-interactive (pipe commands)
printf 'show security flow session\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null

# Via sg if needed
printf 'show ...\nexit\n' | sg incus-admin -c 'incus exec xpf-fw -- cli' 2>/dev/null
```

---

## Performance Testing

### Throughput Benchmarks

**iperf3 between host and VM (cross-zone):**
```bash
# Start server on host (listening on untrust network)
iperf3 -s -B 10.0.2.1

# Run from trust-host container or host trust interface
# 4 parallel streams, reverse mode, 30 seconds
iperf3 -c 10.0.2.1 -P 4 -R -t 30

# Or via DMZ network
iperf3 -c 10.0.30.100 -P 4 -R -t 30
```

**Results (Feb 2026):**
| Configuration | Throughput | Notes |
|--------------|-----------|-------|
| All generic XDP | ~6.8 Gbps | baseline, all interfaces SKB mode |
| bpf_printk enabled | ~3 Gbps | 55%+ CPU wasted on trace output |
| Per-interface native XDP | ~25 Gbps | virtio native, iavf generic |
| During hitless restart | ~25 Gbps | zero drop across 3 restarts |
| Virtio-net 8xBBR (baseline) | ~12.1 Gbps | CUBIC congestion, no GRUB tuning |
| Virtio-net 8xBBR (GRUB only) | ~14.7 Gbps | init_on_alloc=0 + hardened_usercopy=off |
| Virtio-net 8xBBR (GRUB+tc) | ~15.6 Gbps | + tc bridge bypass on host |

**Host GRUB tuning (applied to both host AND VM):**
- `init_on_alloc=0` — disables Debian's `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` (~20% CPU from `clear_page_erms`)
- `hardened_usercopy=off` — disables `CONFIG_HARDENED_USERCOPY_DEFAULT_ON` (~18% host CPU from `__check_object_size`)
- `mitigations=off` — disables Spectre/Meltdown mitigations (perf testing only)
- **BBR congestion control:** 12.1 Gbps vs 6.4 Gbps with CUBIC through virtio-net firewall

### CPU Profiling

**How to profile:**
```bash
# On VM: record 30 seconds of perf data during iperf3
incus exec xpf-fw -- perf record -a -g -F 99 -- sleep 30

# Copy perf.data to host
incus file pull xpf-fw/root/perf.data ./perf.data

# Analyze
perf report --no-children --sort=dso,symbol
```

**Perf profile (generic XDP, 4-stream iperf3):**
```
 8.1%  memcpy_orig          (SKB linearization for generic XDP)
 8.1%  memset_orig          (SKB head expansion for generic XDP)
 4.1%  pv_native_safe_halt  (CPU idle)
 3.8%  spin_unlock          (dev_map_generic_redirect)
 3.0%  clear_page_erms      (virtio RX page alloc)
 2.8%  htab_map_hash        (BPF hash map lookups)
 2.7%  xdp_main_prog        (entry point)
 2.5%  read_tsc             (conntrack ktime)
 2.1%  lookup_nulls_elem_raw (hash element traversal)
 2.0%  iavf_xmit_frame      (SR-IOV TX)
 1.7%  xdp_forward_prog     (forwarding stage)
 1.6%  csum_partial         (TX checksum)
 1.5%  xdp_conntrack_prog   (session lookup)
 1.1%  xdp_zone_prog        (zone + FIB lookup)
 1.0%  xdp_nat_prog         (NAT translation)
```

**Key insight:** BPF programs total ~10% CPU. Generic XDP infrastructure adds ~16%. FIB lookup is 0% (cached in session entries after first packet).

### Performance Optimizations Applied (in order)

1. **Disable bpf_printk** (`e104112`): 55%+ CPU → negligible. Always remove debug tracing for production.

2. **Reduce memset/memcpy** (`299a536`): Minimized per-packet metadata clearing. Only zero fields actually used, not entire scratch struct.

3. **FIB result caching** (`144a3c2`): Cache `fwd_ifindex`, `fwd_dmac`, `fwd_smac` in session entries. Skip `bpf_fib_lookup` on established flows. (Skip on TCP SYN to get fresh FIB for new connections.)

4. **Per-CPU NAT port partitioning** (`7aa77f0`): Eliminate cross-CPU contention on NAT port counters.

5. **Per-interface native XDP** (`f9edb92`): virtio-net interfaces use native XDP (driver mode), iavf uses generic. `redirect_capable` map tells xdp_forward which mode each interface supports.

---

## Legacy eBPF Hitless Restart Testing

### What It Tests
Daemon restart with zero session loss and zero packet loss via legacy BPF
map/link pinning.

### Prerequisites
- Stateful maps pinned to `/sys/fs/bpf/xpf/`
- XDP/TC links pinned to `/sys/fs/bpf/xpf/links/`
- Non-destructive SIGTERM shutdown (no route/DHCP/VRF cleanup)

### Test Procedure
```bash
# 1. Verify clean pinned state
sg incus-admin -c 'incus exec xpf-fw -- ls -la /sys/fs/bpf/xpf/'
sg incus-admin -c 'incus exec xpf-fw -- ls -la /sys/fs/bpf/xpf/links/'

# 2. Start long-running iperf3 (from host, cross-zone through firewall)
iperf3 -c 10.0.30.100 -P 4 -R -t 60 &

# 3. While iperf3 is running, restart daemon multiple times
sg incus-admin -c 'incus exec xpf-fw -- systemctl restart xpfd'
sleep 5
sg incus-admin -c 'incus exec xpf-fw -- systemctl restart xpfd'
sleep 5
sg incus-admin -c 'incus exec xpf-fw -- systemctl restart xpfd'

# 4. Verify iperf3 completes without errors
# Expected: consistent throughput, no retries, no stuck streams

# 5. Verify sessions survived
printf 'show security flow session\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw -- cli' 2>/dev/null
```

### Success Criteria
- iperf3 throughput stays consistent (no drops to zero)
- No "connection reset" or "broken pipe" errors
- Sessions visible in CLI after restart
- No "stuck" parallel streams (all 4 should report similar throughput)

### Verified Results (Feb 2026)
- 3 restarts during 40-second iperf3: 25.3 Gbps average, zero drops
- Sessions survived all restarts
- No stuck streams

### Failure Modes (Before Fixes)
1. **Streams stuck at 0 bps:** Routes removed during shutdown → FIB lookup fails → packets dropped
2. **DHCP addresses lost:** DHCP context cancellation removes IPs → interface has no address
3. **Brief deny-all window:** Programs replaced before policies loaded → default-deny drops everything for ~100ms

### How Pinning Works

**Map pinning:**
```
/sys/fs/bpf/xpf/
├── sessions          # IPv4 conntrack (survives restart)
├── sessions_v6       # IPv6 conntrack (survives restart)
├── dnat_table        # Reverse DNAT mappings (survives restart)
├── dnat_table_v6     # IPv6 reverse DNAT (survives restart)
├── nat64_state       # NAT64 session state (survives restart)
└── nat_port_counters # SNAT port tracking (survives restart)
```

**Link pinning:**
```
/sys/fs/bpf/xpf/links/
├── xdp_3             # XDP link for ifindex 3 (enp6s0)
├── xdp_4             # XDP link for ifindex 4 (enp7s0)
├── xdp_5             # XDP link for ifindex 5 (enp8s0)
├── xdp_6             # XDP link for ifindex 6 (enp9s0)
├── xdp_7             # XDP link for ifindex 7 (enp10s0f0)
├── tc_3              # TC link for ifindex 3
├── tc_4              # ...
├── tc_5
├── tc_6
└── tc_7
```

**Restart flow (legacy eBPF path, retired in #1476):**

The flow below describes the pre-#1476 daemon-restart behaviour for the
legacy XDP/TC dataplane. After the mechanical source removal, the
userspace dataplane (`userspace-dp`) handles restart via shim-only
loading (`loadUserspaceShimObjects`) and userspace-side session-state
preservation. Kept here as historical reference.

1. SIGTERM → close Go FD handles (pinned links/maps stay in kernel)
2. New daemon starts → `loadAllObjects()` reuses pinned maps (sessions preserved)
3. `AttachXDP()` loads pinned link → `link.Update(newProg)` atomically replaces program
4. Config recompiled → all maps repopulated → then program replacement happens
5. Existing sessions continue uninterrupted

**Full teardown:**
```bash
incus exec xpf-fw -- xpfd cleanup
# Removes /sys/fs/bpf/xpf/ recursively + clears FRR routes
```

---

## Debugging Techniques

### When an instrument answers "nothing", ask whether it means "I cannot see"

The failure below has now bitten five separate investigations in this repo, and
it is worth naming as a class before the individual instances.

**An instrument that cannot observe something usually reports a well-formed,
plausible negative** — zero rows, zero packets, zero failures — with no error and
no "unavailable" marker. That negative is indistinguishable from a real one. And
it is most dangerous on exactly the investigations where a negative is the
expected finding, because there it reads as confirmation.

The instances so far:

| instrument | reported | actually meant |
|---|---|---|
| `tcpdump` on `ge-*-0-1` / `ge-*-0-2` (#7770) | 4-14 frames of 15 sent | AF_XDP consumes packets before the `AF_PACKET` tap; it saw nothing |
| `show security policies hit-count` (#7776) | `0 packets / 0 bytes` on every row | the surface is not fed on this path; policies were matching |
| packet capture across an RG failover (#6934) | "zero unsolicited NAs reach the wire" | measured on a redundancy group that never transitioned |
| a mutation harness (#6937 v1) | marker checked, then probed anyway | the lever had not applied; the probe measured the unchanged config |
| the struct auditor's own Rust scanner (#6937) | no row for `ForwardingState` | an unhandled `pub(in path)` visibility prefix made it invisible |

The last one is the most instructive: it was the blind spot of a tool built to
find blind spots, and neither of its two defects was visible in its own output.
What exposed them was a field count someone else had measured independently.

**What actually helps, in order of strength:**

1. **A positive control from OUTSIDE the instrument.** Prove the instrument can
   see a thing you know is there before believing it when it sees nothing. The
   `ForwardingState` bugs were caught only by an externally-stated count; the
   #6934 capture was believed for two rounds because nothing external contradicted
   it.
2. **A marker check that GATES rather than annotates.** #6937's first harness
   verified that its config lever had applied and then ran the probe regardless.
   A check whose result does not stop the next step is decoration.
3. **Make "could not see" a distinct outcome from "saw nothing".** Prefer an
   instrument that errors, or that reports coverage alongside its result, over one
   that renders a clean zero. Where the instrument cannot be changed, write the
   blind spot down beside it — as the AF_XDP section below does.
4. **State a negative as "not measured", not "no evidence found."** They license
   different conclusions, and only the second is a finding.

> Whether this belongs in `docs/engineering-style.md` — which is an
> agent-behaviour contract rather than an operations guide — is a call for the
> repository owner. It is recorded here, next to the concrete instances, so it is
> usable either way.

### Packet capture is BLIND on the AF_XDP data interfaces (#7770)

**`tcpdump` on `ge-*-0-1` / `ge-*-0-2` of the loss userspace cluster does not see
forwarded traffic.** Those interfaces run native XDP with AF_XDP, so the Rust
dataplane consumes packets in userspace and the kernel's `AF_PACKET` tap — which
is what `tcpdump` binds — never sees them.

**This fails in the dangerous direction: the blindness is indistinguishable from
packet loss.** A capture returns a frame count far below what was sent, which on
an investigation that is *about* dropped packets reads as confirmation. Measured
during #7770: a four-hop capture across a manual failover returned 4-14 frames
against 15 echo requests, and every ICMP frame it did catch was the cluster's own
`id 0, seq 0` probe traffic rather than the packets under test.

The same shape sent #6934 down a wrong path for two rounds — its "zero unsolicited
NAs on the wire" was an absence produced by measuring the wrong thing, not by the
system. **Treat a low capture count on these interfaces as "the instrument did not
see it", never as "the packet was not sent".**

What DOES observe this traffic:

| instrument | sees AF_XDP traffic | notes |
|---|---|---|
| `show security flow statistics` | **yes** | dataplane's own counters: `Packets dropped`, `Policy deny`, `Screen drops`, `NAT allocation failures`, `Sessions created`. Diff it around a single probe, with a control run, to attribute a drop to a node and a category |
| `POLICY_DENY` journal lines on the node | **yes** | carries `src`/`dst`/`ingress_zone`/`egress_zone`/`policy_id`, which is what identifies *which direction* of a flow was dropped |
| `show security flow session` | **yes** | whether a session exists on that node at all |
| `tcpdump` on the LAN host / containers | yes | ordinary NICs, no XDP — capture at the *ends* rather than on the firewall's data interfaces |
| `tcpdump` on the firewall's `ge-*-0-1` / `ge-*-0-2` | **NO** | see above |
| `show security policies hit-count` | **no** (observed) | reported `0 packets / 0 bytes` on every row including permit policies carrying live traffic, before and after a probe (#7770). Do not use it to confirm a policy fired |

Capturing on the **fabric parent** (`ge-*-0-0`) and on the peer's interfaces has the
same limitation wherever those carry AF_XDP traffic. Capture at the traffic's
endpoints (LAN host, target container) when you need frames, and use the counter
surfaces for anything crossing the firewall.

### BPF Program Verification
```bash
# Check attached BPF programs
incus exec xpf-fw -- bpftool net show

# Check pinned maps
incus exec xpf-fw -- ls -la /sys/fs/bpf/xpf/

# Dump map contents (e.g., sessions)
incus exec xpf-fw -- bpftool map dump pinned /sys/fs/bpf/xpf/sessions
```

### Session Inspection
```bash
# Via CLI
printf 'show security flow session\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null

# Filter by source
printf 'show security flow session source-prefix 10.0.1.0/24\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
```

### Route Verification
```bash
# FRR routes
incus exec xpf-fw -- vtysh -c 'show ip route'
incus exec xpf-fw -- vtysh -c 'show ipv6 route'

# Kernel routes (should match FRR)
incus exec xpf-fw -- ip route show
incus exec xpf-fw -- ip -6 route show

# Via CLI: all routes, by VRF, by protocol, by prefix
printf 'show route\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
printf 'show route table vrf-dmz-vr\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
printf 'show route protocol static\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
printf 'show route 10.0.1.0/24\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
```

### XDP Mode Verification
```bash
# Check XDP attachment mode per interface
incus exec xpf-fw -- ip link show | grep -A1 xdp

# Or via bpftool
incus exec xpf-fw -- bpftool net show
```

### Counter Inspection
```bash
# Global counters via API
incus exec xpf-fw -- curl -s http://127.0.0.1:8080/api/stats | jq .

# Prometheus metrics
incus exec xpf-fw -- curl -s http://127.0.0.1:8080/metrics | grep xpf

# Flow statistics via CLI
printf 'show security flow statistics\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null

# Policy hit counts (with optional zone filter)
printf 'show security policies hit-count\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
printf 'show security policies hit-count from-zone trust to-zone untrust\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null

# Firewall filter hit counters
printf 'show firewall\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null

# NAT statistics
printf 'show security nat source summary\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
printf 'show security nat destination summary\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null

# Dataplane buffer utilization
printf 'show system buffers\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
```

### Session Management
```bash
# Clear all sessions
printf 'clear security flow session\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null

# Clear filtered sessions
printf 'clear security flow session source-prefix 10.0.1.0/24\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
printf 'clear security flow session protocol tcp\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
printf 'clear security flow session destination-prefix 10.0.2.102/32 protocol udp\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null

# Clear policy counters
printf 'clear security policies hit-count\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null

# Clear firewall filter counters
printf 'clear firewall all\nexit\n' | incus exec xpf-fw -- cli 2>/dev/null
```

### Common Issues

**"operation not supported" on XDP attach**
- Interface driver doesn't support native XDP
- Expected for iavf — falls back to generic automatically
- Check logs for `native XDP not supported, using generic mode`

**Session count drops to 0 after cleanup**
- Expected: `xpfd cleanup` removes all pinned state
- Restart daemon to recreate fresh state

---

## Network-Specific Notes

### Management Interface (enp5s0)
- `UseRoutes=false` in `/etc/systemd/network/enp5s0.network`
- Prevents DHCP default route from shadowing FRR-managed routes
- Still reachable via 10.0.100.0/24 connected route (for incus access)

### ARP Resolution with XDP
- `arping` uses PF_PACKET raw sockets — doesn't populate kernel ARP with XDP attached
- Use `ping` instead for proactive neighbor resolution
- Daemon runs periodic pings (every 15s) for DNAT pools, static NAT, gateways
- STALE ARP entries work fine with `bpf_fib_lookup` — only truly absent entries fail

### VLAN Handling
- WAN interface (wan0) uses VLAN 50 — tag pushed/popped by the active dataplane
- Configured via Junos `vlan-tagging` + `unit 50 { vlan-id 50; }`
- `vlan_iface_map` BPF map tracks VLAN ID per logical interface

### IPv6
- DHCPv6 on WAN gets global address (2001:559:8585:50::5/64)
- IPv6 default route via link-local gateway
- Router Advertisements managed via radvd on LAN interfaces
- NAT64 translation is native to the dataplane (no Tayga/Jool)

---

## cpumap (XDP Multi-CPU Distribution)

Implemented but disabled by default (`Manager.EnableCPUMap`). Cross-CPU cache miss overhead makes it slower than single-CPU processing on virtio-net:

| Configuration | Throughput | Notes |
|--------------|-----------|-------|
| No cpumap (default) | ~12.2 Gbps | Single CPU processes all 4 flows |
| cpumap enabled | ~3.8 Gbps | Cross-CPU cache misses dominate |

cpumap is only useful when a single CPU is genuinely saturated (40G/100G NICs).

**Key gotchas:**
- PROG_ARRAY owner incompatibility: separate array per attach type needed
- Must store map+prog references in Go to prevent GC from closing FDs

---

## Chassis Cluster HA Testing

### Prerequisites
```bash
# Cluster environment must be set up:
make cluster-init    # one-time: networks + profile
make cluster-create  # launch xpf-fw0, xpf-fw1, cluster-lan-host
make cluster-deploy  # build + push to both VMs
```

**Post-deploy node0-primary reassert (#4009, fail-closed in #6591).** Every
deploy path ends in `reassert_primary_node0`, which leaves node0 the primary
for EVERY redundancy group so downstream smoke (`apply-cos-config.sh`,
`test-failover`) starts from the documented steady state. It matters because
the loss userspace cluster runs `preempt=no`: if node1 holds a group when the
deploy finishes, nothing corrects it on its own, and node0 sits secondary at
priority 200 behind node1 at 100.

Per RG, on node0: **reset → transfer → reset**. `failover reset` alone clears
the manual-failover flag and never MOVES ownership — only
`request chassis cluster failover redundancy-group <rg> node 0` does. The
trailing reset clears the flag the transfer itself sets, which would otherwise
block the peer from electing during a later reboot leg.

**It is fail-closed and dies rather than warning.** It retries the status read
across the post-deploy settle window (the daemon is still coming up; a reassert
issued ~20s after a deploy was measured not to take while the identical command
later did), then VERIFIES that node0 reads `primary` for every group and aborts
the deploy loudly if not. Before #6591 an unreadable status made it iterate
zero groups, warn, and return SUCCESS — so `DEPLOY_RC=0` with the cluster left
inverted, and the failure surfaced minutes later inside an unrelated smoke
target's preflight (`FATAL: fw0 is not primary`), where the natural first
hypothesis is that the change under test broke HA. That misdiagnosis cost two
gate cycles.

If a deploy aborts here, the cluster is left in whatever state the transfer
produced: read `show chassis cluster status` on both nodes before re-running,
and do NOT read the next smoke's failure as an HA regression.

The logic lives in `deploy-lib.sh` (`deploy_reassert_primary_node0`,
`deploy_reassert_node0_primary_ok`) so `make test-deploy-lib` covers it against
a mocked incus — no cluster required.

**The failover smoke names WHICH failure it hit (#7368).**
`test-failover.sh` used one exit code (2) for three different outcomes, so
`FO_RC=2` was read as "failover broke" when it meant "the cluster was never in
a testable state". The three are now distinct:

| outcome | signal |
|---|---|
| precondition not met | `FATAL[PRECONDITION]`, exit 2 |
| ownership and forwarding disagree | `FATAL[DIVERGENCE]`, exit 3 |
| a real assertion failed | the usual `FAIL` tally, exit 1 |

Two changes make that possible. The preflight primacy check now uses
`deploy_reassert_node0_primary_ok` — the same per-RG predicate the deploy
reassert uses — instead of `grep -q "node0.*primary"` over the whole status
output. Measured: `secondary` contains no `primary` substring, so that grep
was not wrong in the way it looks; it was **unscoped**, so a cluster with
node0 SECONDARY for RG0 and primary for RG1 satisfied it.

The **post-reboot rejoin** assertions kept that unscoped form until later, and
there it was worse than admitting a partial state. The check is an if/elif that
tries `grep -q "node0.*secondary"` first and `grep -q "node0.*primary"` second,
so a cluster that auto-preempted for RG1 while staying secondary for RG0 matched
the FIRST branch and reported PASS — leaving the elif that names the auto-preempt
regression unreachable in exactly the mixed case it was written for. Both roles
now use `deploy_node_role_every_rg_ok <node> <role>`, the generalisation of the
primacy predicate (which is now `deploy_node_role_every_rg_ok node0 primary` and
keeps its name, since that is the vocabulary the deploy path uses). A mixed state
is rejected by BOTH roles, so the phase falls through to its failure branch and
reports the partial preempt instead of passing.

The failback loop further down was already scoped — it greps inside
`grep -A1 "Redundancy group: $rg"` — so `grep -q "node0.*primary"` still appears
there legitimately. The selftest's wiring guard therefore tests SCOPED-NESS, not
the substring: it fires only on a role grep with no `Redundancy group:` scoping
on the same line. An earlier revision banned the substring outright, and a
control cell caught it reddening on exactly that legitimate shape.

And the session assertion now cross-references the two independent checks the
script already performed. Primacy is read from a field the node reports about
ITSELF; the session count is a real measurement; they were never compared. In
#6656 that meant a genuine ownership divergence (node0 primary with 1 session,
node1 carrying 33) surfaced as a session-count shortfall and was attributed to
the change under test. The peer count is read on the shortfall path only, and
`failover_ownership_verdict` (pure, in `deploy-lib.sh`, selftested) decides
between `diverged` and `nostream`. "The peer has sessions" is deliberately NOT
the discriminator — session sync means the peer legitimately holds some, so the
peer must be above `MIN_SESSIONS` while the reported primary is below it.

### VRRP State Verification
```bash
# Both nodes should agree: fw0=MASTER, fw1=BACKUP for all groups
printf 'show security vrrp\nexit\n' | sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
printf 'show security vrrp\nexit\n' | sg incus-admin -c 'incus exec xpf-fw1 -- cli' 2>/dev/null

# Verify VIPs only on primary (fw0)
sg incus-admin -c 'incus exec xpf-fw0 -- ip addr show ge-0-0-1.50' | grep '172.16.50.6'
sg incus-admin -c 'incus exec xpf-fw1 -- ip addr show ge-7-0-1.50' | grep '172.16.50.6'
# Expected: VIP only on fw0
```

### IPv6 VIP Reachability (`d03b29e`)
```bash
# Both VIPs must be reachable from host
ping -c 3 172.16.50.6           # IPv4 WAN VIP
ping -c 3 2001:559:8585:50::6   # IPv6 WAN VIP

# Verify no DAD issues
sg incus-admin -c 'incus exec xpf-fw0 -- ip -6 addr show ge-0-0-1.50' | grep 2001:559:8585:50::6
# Expected: "nodad" flag, NOT "dadfailed tentative"

# Verify FRR IPv6 route on correct sub-interface
sg incus-admin -c 'incus exec xpf-fw0 -- grep "ipv6 route" /etc/frr/frr.conf'
# Expected: "ipv6 route ::/0 fe80::50 ge-0-0-1.50 5"
sg incus-admin -c 'incus exec xpf-fw0 -- ip -6 route show default'
# Expected: "via fe80::50 dev ge-0-0-1.50" (NOT dev ge-0-0-1)
```

### Failover + Preemption Test
```bash
# Start continuous ping to VIP
ping 172.16.50.6 &

# Stop fw0 → fw1 should become MASTER within ~3.5s
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl stop xpfd'
# Expected: 3-4 lost pings, then recovery

# Verify fw1 is MASTER
sleep 5
printf 'show security vrrp\nexit\n' | sg incus-admin -c 'incus exec xpf-fw1 -- cli' 2>/dev/null

# Restart fw0 → preemption reclaims primary
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl start xpfd'
sleep 5
printf 'show security vrrp\nexit\n' | sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
# Expected: fw0=MASTER again
```

### Config Sync Test (`64bc9d5`)
```bash
# Forward: commit on primary → secondary receives
printf 'configure\nset routing-options static route 10.77.77.0/24 discard\ncommit\nexit\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
sleep 3
printf 'show configuration routing-options | match 77\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw1 -- cli' 2>/dev/null
# Expected: "route 10.77.77.0/24 discard;"

# Reverse: returning primary gets config from current primary
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl stop xpfd'
sleep 2
printf 'configure\nset routing-options static route 10.88.88.0/24 discard\ncommit\nexit\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw1 -- cli' 2>/dev/null
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl start xpfd'
sleep 10
printf 'show configuration routing-options | match 88\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
# Expected: "route 10.88.88.0/24 discard;" (synced from fw1)

# Cleanup
printf 'configure\ndelete routing-options static route 10.77.77.0/24\ndelete routing-options static route 10.88.88.0/24\ncommit\nexit\nexit\n' | \
  sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null
```

### LAN RETH Connectivity (IPv4 + IPv6)
```bash
# IPv4
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'
# Expected: 3/3, <1ms RTT

# IPv6 (requires radvd + DHCPv6 running on primary)
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 2001:559:8585:cf01::1'
# Expected: 3/3, <1ms RTT

# Verify container got IPv6 via SLAAC/DHCPv6
sg incus-admin -c 'incus exec cluster-lan-host -- ip -6 addr show eth0'
# Expected: global address in 2001:559:8585:cf01::/64
```

### Hitless Forwarding Through Restart (IPv4 + IPv6)

Tests that transit traffic (SNAT'd through firewall) survives daemon restart with
minimal disruption on the legacy eBPF path. This validates the
`META_FLAG_KERNEL_ROUTE` BPF fallback path.

**Background:** After restart, FIB cache in session entries is stale. `bpf_fib_lookup`
returns LOCAL/NOT_FWDED until FRR reconverges. The BPF fix (`b0e7e33`) detects existing
sessions with failed FIB and routes them through conntrack → NAT → kernel forwarding
instead of dropping them or sending un-NAT'd packets to the kernel.

```bash
# IPv4: ping through SNAT from LAN to external host
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 30 -i 0.5 172.16.100.200' &

# After 5 seconds, restart primary
sleep 5
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl restart xpfd'

# Wait for completion — expect 28-29/30 received (1-2 lost, ~1s disruption)

# IPv6: ping gateway through restart
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 30 -i 0.5 2001:559:8585:cf01::1' &
sleep 5
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl restart xpfd'
# Same expectation: 1-2 packets lost during ARP/NDP warmup
```

**Why only 1-2 packets lost:**
1. BPF programs are pinned — they keep processing packets during restart
2. Existing sessions in pinned maps are preserved
3. META_FLAG_KERNEL_ROUTE lets stale-FIB packets use kernel routing
4. ARP/NDP warmup on VRRP MASTER transition resolves neighbors in ~50ms
5. FRR reconverges routes in ~1-2s, then XDP direct forwarding resumes

**Full failover test (stop primary, secondary takes over):**
```bash
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 60 -i 0.5 10.0.60.1' &
sleep 5
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl stop xpfd'
# Expected: 3-5 packets lost during VRRP Master-down timer (~3.5s)
sleep 15
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl start xpfd'
# Expected: 3-5 more packets lost during preemption back
```

### ConfigDB Bootstrap After Config Changes

The daemon loads from `.configdb/active.json`, NOT from the text `.conf` file.
If you modify `ha-cluster.conf` and redeploy, the daemon ignores the new text
because the DB already exists. Force re-bootstrap:

```bash
sg incus-admin -c 'incus exec xpf-fw0 -- rm /etc/xpf/.configdb/active.json'
sg incus-admin -c 'incus exec xpf-fw1 -- rm /etc/xpf/.configdb/active.json'
sg incus-admin -c 'make cluster-deploy'
```

### Full Cluster Validation Sequence
Run after any VRRP/cluster/config-sync changes:
```bash
sg incus-admin -c 'make cluster-deploy' && sleep 10
printf 'show chassis cluster status\nexit\n' | sg incus-admin -c 'incus exec xpf-fw0 -- cli' 2>/dev/null

# IPv4 VIPs
ping -c 3 172.16.50.6
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 10.0.60.1'

# IPv6 VIPs
ping -c 3 2001:559:8585:50::6
sg incus-admin -c 'incus exec cluster-lan-host -- ping -c 3 2001:559:8585:cf01::1'

# Failover + recovery
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl stop xpfd'
sleep 5 && ping -c 3 172.16.50.6 && ping -c 3 2001:559:8585:50::6
sg incus-admin -c 'incus exec xpf-fw0 -- systemctl start xpfd'
sleep 5 && ping -c 3 172.16.50.6 && ping -c 3 2001:559:8585:50::6
```

---

## Legacy eBPF Feature Caveats

These config fields are parsed and compiled to BPF maps but NOT checked in BPF programs:

| Field | BPF Struct | Status |
|-------|-----------|--------|
| `power_mode_disable` | `flow_config` | Placeholder — no BPF logic |
| `gre_accel` | `flow_config` | Placeholder — GRE acceleration not implemented |
| `pre-id-default-policy` | Not in BPF | Requires application identification (not implemented) |

These config features are parsed in Go but never used at runtime:

| Feature | Where Parsed | Status |
|---------|-------------|--------|
| `rib-groups` | compiler.go:1971-2011 | Parsed, not passed to FRR |
| `SamplingInput/Output` | compiler.go:1028-1074, exporter.go | Wired: per-zone sampling direction filters flow export |
| `LogConfig.Mode` | compiler.go:1591 | Parsed, stream mode always used |
| `WebMgmt interface binding` | compiler.go:3343-3360 | Parsed, servers always bind to localhost |
