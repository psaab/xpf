# #1377 Userspace SNAT Pool Contract

## Goal

Make source-NAT pool mode a first-class userspace feature so configs using
`then source-nat pool <name>` no longer depend on the legacy eBPF dataplane for
safe admission, address selection, port-range enforcement, durable
translations, and operator-visible allocation failures.

## Current Status

- #1385 landed a defensive userspace snapshot fix: missing pools, empty pools,
  and invalid `uint16` port ranges are omitted from the snapshot instead of
  being emitted as broad matching no-op rules. That is not a forwarding
  fail-closed gate today; rules omitted for those inputs still leave the
  runtime free to forward without SNAT.
- #1385 also plumbed `address_persistent`, resolved pool addresses, and
  `port_low` / `port_high` into the userspace snapshot and Rust
  `SourceNATRuleSnapshot`.
- The current Rust dataplane implements a userspace-v1 `address-persistent`
  pool selector. That closes the original silent round-robin regression for
  AF_XDP userspace forwarding.
- The remaining #1377 work is now contract work plus runtime work for per-pool
  `persistent-nat`, pool allocator observability, and real fail-closed paths
  for missing-pool, empty-pool, invalid-port-range, and live allocation-failure
  source-NAT pool cases.

## Current Fail-Open Runtime Boundary

Current AF_XDP userspace SNAT pool handling is fail-open from the forwarding
path's point of view. `match_source_nat_for_flow` returns `None` for both "no
source-NAT rule applies" and "a configured pool-mode rule cannot produce a
usable translation". The packet path then converts that `None` into the default
empty `NatDecision`, creates/continues the forwarding decision, and sends the
packet without SNAT.

The current fail-open runtime call sites are the four
`match_source_nat_for_flow(...).unwrap_or_default()` paths in
`userspace-dp/src/afxdp/poll_descriptor.rs`:

- `poll_descriptor.rs:1060` - normal new-session path, no pre-routing DNAT:
  source NAT lookup falls through to `unwrap_or_default()` and forwards with no
  rewrite.
- `poll_descriptor.rs:1074` - normal new-session path after pre-routing DNAT:
  the source NAT side of the merged decision falls through to
  `unwrap_or_default()`.
- `poll_descriptor.rs:1953` - pending-neighbor/session-build retry path, no
  pre-routing DNAT: source NAT lookup falls through to `unwrap_or_default()`.
- `poll_descriptor.rs:1967` - pending-neighbor/session-build retry path after
  pre-routing DNAT: the source NAT side of the merged decision falls through to
  `unwrap_or_default()`.

Risk: traffic that matched an intended pool-mode source-NAT rule can leave the
userspace dataplane untranslated when the pool is omitted from the snapshot, all
pool addresses are malformed, no address exists for the packet family, egress
metadata is missing, or the allocator cannot produce a usable tuple. That can
leak original source addresses, create sessions with no reverse SNAT state, and
make return traffic fail in ways that look like routing or policy issues rather
than NAT admission failures.

Closing this boundary requires a code PR that separates "no source-NAT rule
matched" from "a source-NAT rule matched but translation failed", then plumbs
the failure through all four call sites above as a drop/exception before
session creation or forwarding. The closing PR also needs tests for the normal
and pending-neighbor paths, plus counters or exceptions that name the pool,
family, and reason: missing pool, empty pool, malformed address, wrong-family
pool with no compatible fallback, invalid range, live tuple exhaustion, and
persistent table failure. Until that lands, docs and capability gates must not
claim userspace pool-mode SNAT is fail-closed.

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
- Current behavior: a pool-mode rule without a usable pool is fail-open at the
  four runtime call sites listed above. Target behavior for the runtime follow-up
  is fail-closed drop/exception before session creation or forwarding.
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
- Go: snapshot builder omits missing pool, empty pool, invalid port range, and
  nil pool entries instead of emitting a matching no-op rule. This prevents one
  no-op shadowing bug but remains fail-open at runtime because forwarding can
  continue without SNAT.
- Cargo: wrong-family pools do not shadow later compatible source-NAT rules.
  If no compatible later rule exists, the current runtime still forwards without
  SNAT.
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
- Cargo/integration: source-NAT pool rules with missing pools, empty pools,
  invalid port ranges, wrong-family-only pools, or live allocation failures
  fail closed at all four `poll_descriptor.rs` source-NAT call sites instead
  of falling through `unwrap_or_default()` as an untranslated forward.
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
