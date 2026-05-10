# dpdk_worker/

Optional DPDK userspace dataplane backend. Single-pass packet processor
implemented in C with DPDK, sharing memory with the Go daemon for the
control plane (port stats, FIB sync, session counters). Selected via
`set system dataplane-type dpdk`.

This is a separate execution mode from the eBPF default and the AF_XDP
userspace-dp backend. It's checked in but not built by default.

## Entry

`main.c` — DPDK EAL init, port configuration, signal handling. Per-lcore
RX dispatch via a function table:

- `rx_loop_poll` — continuous polling.
- `rx_loop_interrupt` — NAPI interrupt-driven.
- `rx_loop_adaptive` — switches between the two based on offered load.

## Modules

| File | Purpose |
|------|---------|
| `parse.c` | L3+L4 parsing into `pkt_meta`. |
| `zone.c` | Zone classification. |
| `screen.c` | Screen / IDS checks. |
| `conntrack.c` | Session lookup + state update. |
| `policy.c` | First-match-wins policy evaluation. |
| `nat.c` | NAT44 (SNAT/DNAT/static). |
| `nat64.c` | RFC 6052 IPv6↔IPv4 translation. |
| `filter.c` / `policer.c` | Firewall filter + token-bucket policer. |
| `forward.c` | Output selection, MAC rewrite, TX. |
| `reject.c` | TCP RST / ICMP unreachable rejects. |
| `gc.c` | Session sweep (`gc_sweep`). |
| `power.c` | Power-efficiency tuning per lcore. |
| `events.h`, `counters.h`, `tables.h` | Event counters, per-lcore stats, hash table / LPM / session slab definitions. |

## Shared memory

`struct shared_memory` (defined in `tables.h`) lives in a DPDK memzone.
The Go side (`pkg/dataplane/dpdk`) opens the same memzone and reads /
writes the same structs:

- Conntrack hash table.
- NAT pool state.
- LPM4 / LPM6 routing tables.
- Session slab (entries indexed by 32-bit handles).

CGo bridge in `pkg/dataplane/dpdk` handles the memory layout
synchronization.

## Build

Requires DPDK headers + libraries on the build host. Not part of
`make build`. The Go side stubs out the backend behind a build tag when
DPDK isn't available.

## Gotchas

- All allocations go through `rte_malloc` (NUMA-aware). Don't use libc
  `malloc` from inside the worker loop.
- mbuf allocation comes from a per-lcore mempool; the pool size has to
  exceed the in-flight burst size by a comfortable margin or RX
  silently drops.
- Signal-driven shutdown sets `g_force_quit`; loops poll it on every
  tick.
