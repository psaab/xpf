# #1377 Userspace SNAT Pool Contract

## Goal

Make source-NAT pool mode a first-class userspace feature so non-HA configs
using `then source-nat pool <name>` no longer depend on the legacy eBPF
dataplane for safe admission, address selection, port-range enforcement,
runtime lease reuse, and operator-visible allocation failures.

## Current Status

- The current snapshot preserves pool-mode source-NAT rule intent even when
  the referenced pool is missing, nil, empty, or has an invalid port range.
  Such rules carry `pool_unusable` / `pool_unusable_reason` so Rust can fail
  closed at runtime instead of treating the rule as absent.
- #1385 also plumbed `address_persistent`, resolved pool addresses, and
  `port_low` / `port_high` into the userspace snapshot and Rust
  `SourceNATRuleSnapshot`.
- The current Rust dataplane implements a userspace-v1 `address-persistent`
  pool selector. That closes the original silent round-robin regression for
  AF_XDP userspace forwarding.
- The current Rust dataplane separates "no source-NAT rule matched" from "a
  pool-mode source-NAT rule matched but cannot produce a translation". Missing
  pools, empty pools, invalid pool inputs, wrong-family-only pools, and
  allocator failures are fail-closed before session creation or forwarding.
- Per-pool `persistent-nat` now has explicit snapshot fields and Rust runtime
  lease reuse. The userspace protocol is bumped so helpers that do not know
  those fields reject the snapshot instead of silently claiming support.
- Rust now tracks live translated tuples and reports allocator exhaustion
  instead of wrapping into an already-owned port. Userspace status, CLI summary,
  and Prometheus expose live-flow, used-port, persistent-lease, allocation,
  reuse, and exhaustion counters.
- The supported persistent-NAT slice is helper-local and non-HA. Rules that
  reference the same concrete pool share one allocator and one lease table, so
  duplicate rules cannot overbook the same translated tuple. Compatible
  in-process snapshot refreshes preserve allocator state, but helper restart
  does not. HA configs that use a persistent source-NAT pool are gated because
  persistent leases are not synchronized.

## Current Fail-Closed Runtime Boundary

Current AF_XDP userspace SNAT pool handling is fail-closed for matched pool-mode
rules that cannot produce a usable translation. `match_source_nat_for_flow_result`
distinguishes "no source-NAT rule applies" from "a configured pool-mode rule
matched but is unavailable". The packet path converts unavailable pool results
into `record_source_nat_failure` exceptions and recycles the packet before
session creation or forwarding.

The current fail-closed runtime call sites are the four
`source_nat_decision_for_flow(...)` paths in
`userspace-dp/src/afxdp/poll_descriptor.rs`:

- `poll_descriptor.rs:1229` - normal new-session path, no pre-routing DNAT:
  source NAT lookup fails closed before the NAT decision is installed.
- `poll_descriptor.rs:1257` - normal new-session path after pre-routing DNAT:
  the source NAT side of the merged decision fails closed before merge/session
  creation.
- `poll_descriptor.rs:2160` - pending-neighbor/session-build retry path, no
  pre-routing DNAT: source NAT lookup fails closed before the missing-neighbor
  seed session is installed.
- `poll_descriptor.rs:2187` - pending-neighbor/session-build retry path after
  pre-routing DNAT: the source NAT side of the merged decision fails closed
  before the missing-neighbor seed session is installed.

Recent-exception reasons identify the runtime failure class:
`source_nat_pool_missing`, `source_nat_pool_empty`,
`source_nat_pool_invalid`, `source_nat_pool_invalid_port_range`,
`source_nat_pool_wrong_family`, and `source_nat_pool_exhausted`.
Source-NAT pool exceptions also carry the matched `rule_name` and `pool_name`
so operators can identify the unusable stanza without reverse-engineering the
packet tuple.

The wrong-family case is deliberately fail-closed, even though older userspace
behavior walked past a matched IPv4 rule whose pool only contained IPv6
addresses. Once a rule's zones and prefixes match, the configured rule owns the
packet; silently falling through to a later rule would mask the broken pool and
make rule ordering dependent on address-family mistakes. Operators should split
IPv4 and IPv6 pool rules explicitly when they want independent behavior.

Allocator exhaustion is now a real runtime condition. The allocator owns a
bounded per-pool live-flow table, a translated-tuple owner table, and a
persistent source-tuple lease table. When no translated port can be claimed for
the matched pool family, the packet fails closed with
`source_nat_pool_exhausted` before session creation or forwarding.

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

AF_XDP userspace snapshots now carry per-pool `persistent-nat` runtime fields:

- `persistent_nat`
- `persistent_nat_permit_any_remote_host`
- `persistent_nat_inactivity_timeout`

The protocol version is `3`. A daemon with these fields will only publish to a
helper that reports the same snapshot protocol version; older helpers reject the
snapshot as an unsupported version instead of ignoring the persistence fields.

The implemented runtime key is source tuple:

- L4 protocol
- original source IP
- original source port

That source tuple maps to one translated tuple:

- selected pool IP
- selected source port

The key intentionally does not include destination address or destination port,
because per-pool persistent NAT is source-tuple lease reuse. This is distinct
from global `source address-persistent`, which is only source-IP to pool-address
affinity during allocation.

The userspace runtime does not consult the Go `PersistentNATTable`. The current
contract is helper-local:

- live flows hold the translated tuple until their userspace session expires;
- persistent leases remain after the last live flow releases them and expire
  after the configured inactivity timeout;
- source-NAT allocations that fail before session install use a rollback path,
  not the inactivity-release path, so a rejected new persistent tuple does not
  pin a lease for the timeout window;
- compatible in-process snapshot refreshes preserve allocator state;
- helper restart loses the persistent lease table; and
- HA configs using persistent source-NAT pools are gated because leases are not
  synchronized to the peer.

`permit any-remote-host` is represented in the snapshot/status contract and is
accepted by this runtime slice. The allocator reuse key is already independent
of remote host. Sessionless inbound permission semantics beyond normal
reverse-session traffic are not claimed by this slice.

## Port Allocation and Counters

Tracked userspace flow allocations use per-address cursors plus recycled-port
stacks, and translated tuple ownership is recorded before a session is
installed. The remaining tupleless diagnostic lookup path still uses
per-address atomic counters because it does not create a tracked session.

The per-pool allocator state is bounded by the smaller of pool port capacity and
`262144` tracked live flows. This prevents attacker-controlled unbounded growth
in the packet path. Fresh port claims use a per-address cursor and a recycled
port stack, and persistent lease expiry uses a replace-in-place ordered expiry
index bounded by the number of retained leases. Near-full allocation and
timeout cleanup do not scan the whole port range or lease map on every new
flow. The allocator reports exhaustion when:

- the selected address-persistent pool address has no free port;
- a non-address-persistent family has no free port on any family-compatible
  pool address; or
- the bounded live-flow table is full.

Status and Prometheus expose:

- live tracked flows;
- owned translated ports;
- retained persistent leases;
- total new allocations;
- total live/persistent reuses; and
- total exhaustion events.

## Hot-Path Invariants

- No global allocator lock on the packet path. Each concrete source-NAT pool
  owns its own allocator lock and bounded maps. Multiple rules that reference
  the same pool share that allocator.
- Port-range validation happens before any `u16` truncation.
- A pool-mode rule without a usable pool is fail-closed at the four runtime
  call sites listed above. The packet is dropped and a recent exception is
  recorded before session creation or forwarding.
- Existing reverse-session NAT behavior remains the source of truth for return
  traffic on active sessions. Persistent leases affect new source-side
  allocation only.
- Address-persistent pool choice is deterministic for the configured backend,
  source address, pool family, pool order, and pool size.
- Cross-backend selector divergence is an explicit compatibility boundary, not
  an accidental test failure.

## Exact Tests

Covered by #1385 and this closeout:

- Go: userspace snapshot carries pool addresses, port low/high, rule identity,
  `address_persistent`, and per-pool `persistent-nat` fields.
- Go: protocol round-trip covers source-NAT persistent fields and source-NAT
  pool status rows.
- Go: userspace admission gates HA configs that use persistent source-NAT
  pools because leases are not synchronized.
- Go: snapshot builder preserves missing pool, empty pool, invalid port range,
  and nil pool entries as unusable pool-mode rules with
  `pool_unusable_reason`.
- Cargo: missing pools, empty pools, invalid port ranges, malformed pool
  addresses, wrong-family-only pools, and allocator exhaustion surfaces are
  distinct from no source-NAT match.
- Cargo: source-NAT pool rules with missing pools, empty pools, invalid port
  ranges, wrong-family-only pools, or allocation failures fail closed at all
  four `poll_descriptor.rs` source-NAT call sites instead of becoming an
  untranslated forward.
- Cargo: userspace-v1 fixtures pin IPv4/IPv6 sticky hash outputs.
- Cargo: one source keeps one pool address across repeated allocations.
- Cargo: many sources spread across the pool and do not collapse to a single
  address.
- Cargo: userspace-v1 fixtures explicitly differ from legacy eBPF/DPDK
  address-persistent algorithms.
- Cargo: persistent source tuple reuses the same translated tuple across remote
  hosts while the lease is live.
- Cargo: persistent source tuple is reassigned after release plus inactivity
  timeout.
- Cargo: live allocator exhaustion increments per-pool status counters.
- Cargo: duplicate source-NAT rules that reference the same concrete pool share
  one allocator, so a one-port pool cannot be double-booked across rules.
- Cargo: failed source-NAT session installation rolls back the live translated
  tuple, making the port immediately available for a later flow.
- Cargo: duplicate source-NAT rules that reference the same concrete pool but
  use different persistence settings still share tuple-space ownership.
- Cargo: DNAT+source-NAT release uses the post-DNAT destination key so normal
  expiry and rollback release the actual allocated tuple.
- Cargo: repeated persistent lease refresh/release churn keeps the expiry index
  bounded by retained leases rather than by allocation count.
- Cargo: protocol round-trip covers persistent source-NAT snapshot/status
  fields.

Still outside the current supported contract:

- Integration: active userspace SNAT pool sessions preserve return traffic
  across failover, while new-flow mixed-backend rollback tests accept the
  documented selector boundary.
- Helper-restart persistence for the persistent-NAT lease table.
- HA synchronization for persistent-NAT leases.
- A shared selector algorithm across eBPF, DPDK, and userspace for new-flow
  cross-backend parity.

## Non-Goals

- Do not redesign all NAT rule matching in #1377.
- Do not remove eBPF NAT source as part of #1377.
- Do not claim helper-restart or HA persistence for per-pool `persistent-nat`.
