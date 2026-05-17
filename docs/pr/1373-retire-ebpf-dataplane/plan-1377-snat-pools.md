# #1377 Userspace SNAT Pool Contract

## Goal

Make source-NAT pool mode a first-class userspace feature so configs using
`then source-nat pool <name>` no longer depend on the legacy eBPF dataplane for
safe admission, address selection, port-range enforcement, durable
translations, and operator-visible allocation failures.

## Current Status

- #1385 landed the immediate fail-closed userspace snapshot fix: missing pools,
  empty pools, malformed pool addresses, wrong-family pool shadowing, and
  invalid `uint16` port ranges no longer silently create broad matching no-op
  rules.
- #1385 also plumbed `address_persistent`, resolved pool addresses, and
  `port_low` / `port_high` into the userspace snapshot and Rust
  `SourceNATRuleSnapshot`.
- The current Rust dataplane implements a userspace-v1 `address-persistent`
  pool selector. That closes the original silent round-robin regression for
  AF_XDP userspace forwarding.
- The remaining #1377 work is now contract work plus runtime work for per-pool
  `persistent-nat` and pool allocator observability.

## Userspace-v1 Address-Persistent Contract

For AF_XDP userspace pool-mode SNAT, global `source address-persistent` means:

- pool selection is computed only from the original source IP address, the
  packet address family, the pool family, and the configured order of addresses
  in that family;
- the hash input is the fixed domain tag
  `xpf-userspace-snat-address-persistent-v1`, followed by a one-byte family tag
  (`4` or `6`), followed by canonical source address bytes;
- the selector is the first 64 bits of SHA-256, interpreted big-endian, modulo
  the number of configured pool addresses in the packet family;
- IPv4 and IPv6 pool addresses are selected from separate family-specific
  address lists, preserving configured order within each family;
- one-address pools are valid and always select index 0; and
- changing pool size, pool order, or address family can remap sources.

The userspace-v1 key deliberately does not include zone, rule name, rule index,
destination address, protocol, or port. Adding any of those would be a new
algorithm version and would require explicit migration tests.

## Cross-Backend Compatibility Boundary

The retained backends do not share an address-persistent selector today:

- legacy eBPF IPv4 uses the packet-order `src_ip` word modulo the IPv4 pool
  size. On the current little-endian x86 deployment target this makes low bits
  come from the first IPv4 octet;
- legacy eBPF IPv6 XORs the four 32-bit source-address lanes and mods by the
  IPv6 pool size;
- current DPDK mirrors that C-word modulo / lane-XOR behavior for pool address
  selection, while using DPDK-local port counters; and
- current AF_XDP userspace uses the userspace-v1 SHA-256 selector above.

The #1377 follow-up therefore treats userspace-v1 as the AF_XDP contract and
does not promise new-flow pool-address parity across eBPF, DPDK, and userspace
rollback. Mixed-backend tests must separate:

- active session continuity, where the translated tuple is session state and
  should survive HA takeover when the session is synced; from
- new allocation after failover or rollback, where the same client may choose a
  different pool address after the backend changes.

Phase 4 eBPF source removal must not use a mixed-backend rollback test that
expects newly allocated userspace flows to match legacy eBPF/DPDK
address-persistent pool choices unless a later PR standardizes a shared
algorithm for all retained backends.

## Persistent NAT Boundary

Junos global `source address-persistent` is not the same feature as per-pool
`persistent-nat`:

- `address-persistent` chooses a stable pool address for a source IP while a
  flow is being allocated.
- `persistent-nat` keeps a source tuple bound to the same translated tuple
  across later flows until timeout, subject to pool persistence mode such as
  `permit-any-remote-host`.

Current AF_XDP userspace snapshots do not carry per-pool `persistent-nat`
configuration, and the Rust allocator does not consult the Go
`PersistentNATTable`. The existing Go table can record expired legacy sessions,
but that is not a userspace-v1 allocation contract. A production-ready
userspace persistent-NAT implementation needs:

- snapshot fields for pool persistence mode, inactivity timeout, and
  `permit-any-remote-host`;
- a bounded runtime mapping table keyed by the Junos-compatible persistence key;
- lookup-before-allocation, collision handling, timeout/LRU reclamation, and a
  no-alias invariant for live translated 5-tuples; and
- HA behavior that either syncs the persistent table or explicitly limits
  persistence to active synced sessions.

Until that lands, #1377 remains open for per-pool `persistent-nat`. Configs that
depend on persistent-NAT lease reuse must not be treated as fully owned by the
AF_XDP userspace dataplane.

## Port Allocation and Counters

Current userspace pool ports are allocated by per-pool-address atomic counters
that wrap inside the configured range. There is no live-port ownership table in
the Rust allocator, so it cannot currently prove exhaustion or report true pool
exhaustion. The counter contract still needed for #1377 is:

- allocation success by pool and address family;
- allocation failure separated into missing/invalid pool, wrong-family pool,
  exhausted live translated tuple space, and persistence-table eviction;
- port wrap/reuse visibility until live-port tracking exists; and
- persistence-table size, hit, miss, timeout, and eviction counters.

## Hot-Path Invariants

- No global allocator lock on the packet path.
- Port-range validation happens before any `u16` truncation.
- A pool-mode rule without a usable pool is fail-closed, not a matching no-op.
- Existing reverse-session NAT behavior remains the source of truth for return
  traffic on active sessions.
- Address-persistent pool choice is deterministic for the configured backend,
  source address, pool family, pool order, and pool size.
- Cross-backend selector divergence is an explicit compatibility boundary, not
  an accidental test failure.

## Exact Tests

Already covered by #1385 and this follow-up:

- Go: userspace snapshot carries pool addresses, port low/high, rule identity,
  and `address_persistent`.
- Go: snapshot builder skips missing pool, empty pool, invalid port range, and
  nil pool entries instead of emitting a matching no-op rule.
- Cargo: wrong-family pools do not shadow later compatible source-NAT rules.
- Cargo: userspace-v1 fixtures pin IPv4/IPv6 sticky hash outputs.
- Cargo: one source keeps one pool address across repeated allocations.
- Cargo: many sources spread across the pool and do not collapse to a single
  address.
- Cargo: userspace-v1 fixtures explicitly differ from legacy eBPF/DPDK
  address-persistent algorithms.

Still required to close the remaining #1377 runtime work:

- Go/Rust protocol tests for per-pool `persistent-nat` snapshot fields once they
  exist.
- Cargo: persistent key reuses the same translated tuple while live and
  reallocates after expiry.
- Cargo: allocator never assigns the same live translated 5-tuple to two live
  clients and reports exhaustion instead of silent wrap reuse.
- Integration: active userspace SNAT pool sessions preserve return traffic
  across failover, while new-flow mixed-backend rollback tests accept the
  documented selector boundary.
- Observability: pool allocation, exhaustion, persistence hit/miss, timeout,
  and eviction counters are visible under pressure.

## Non-Goals

- Do not redesign all NAT rule matching in #1377.
- Do not remove eBPF NAT source as part of #1377.
- Do not claim per-pool `persistent-nat` parity from the userspace-v1
  address-persistent selector alone.
