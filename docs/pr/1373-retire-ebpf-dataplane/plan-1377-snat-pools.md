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
  duplicate rules cannot overbook the same translated tuple. In-process
  snapshot refreshes preserve allocator state only when the helper keeps the
  same binding-plan entries and the allocator key is unchanged. Helper restart,
  binding-plan changes that force helper replan, and pool-shape edits are
  explicit reset boundaries: live tuple ownership, persistent leases, and
  allocator counters are not replayed. #1449 closes the HA question by treating
  persistent source NAT in HA as an admission boundary: userspace forwarding is
  blocked with an explicit unsupported reason because persistent leases are not
  synchronized.

## Current Fail-Closed Runtime Boundary

Current AF_XDP userspace SNAT pool handling is fail-closed for matched pool-mode
rules that cannot produce a usable translation. `match_source_nat_for_flow_result`
distinguishes "no source-NAT rule applies" from "a configured pool-mode rule
matched but is unavailable". The packet path converts unavailable pool results
into `record_source_nat_failure` exceptions and recycles the packet before
session creation or forwarding.

These are the current fail-closed runtime decision sites; #17021 moved the
first two into one composer (#19132). `userspace-dp/tests/snat_contract_doc_guard.rs`
pins this layout with a crate-wide census:

- `session_glue/forward_commit.rs`: `compose_outbound_source_nat` makes the
  `source_nat_decision_for_flow(...)` decision for BOTH packet paths and returns
  a failed decision as `Err(NatFailure::SourceNat(failure))`. It never forwards
  untranslated. Its two callers are in `poll_descriptor/mod.rs`:
  - normal new-session path: the `NatFailure::SourceNat` arm calls
    `record_source_nat_failure` and recycles the frame before the NAT decision
    is installed. This is the single SNAT fallback the merge path uses whether
    or not a pre-routing DNAT is present.
  - pending-neighbor/session-build retry path (the missing-neighbor seed): the
    same arm records the failure and recycles the frame before the seed session
    is installed.
- `poll_descriptor/frag_assoc.rs`: the flowless-fragment NAT retry (#10957) makes
  its own `source_nat_decision_for_flow(...)` decision and DROPS the fragment on
  any failure, which is fail-closed. It does not call
  `record_source_nat_failure`. A pool failure there is counted only by the
  generic `nat_frag_untranslated_dropped` (shared with the retry's other drop
  reasons), with no `nat_alloc_fail` and no source-NAT exception. That is a
  visibility gap, not a fail-open (#19146).

> #3121 reduction (was four sites): NPTv6 outbound source translation now
> COMPOSES with destination NAT. Each path (the normal new-session Permit-NAT
> site and the missing-neighbor seed site) previously had a duplicated
> `source_nat_decision_for_flow(...)` call — one in a `rewrite_dst.is_none()`
> branch and one in the `else` (DNAT-present) branch. The #3121 fix attempts
> NPTv6 first (and `merge()`s its source rewrite into any pre-routing DNAT
> decision) and falls back to a SINGLE `source_nat_decision_for_flow(...)` SNAT
> call per path, regardless of whether a destination rewrite is present. The
> two former duplicate-pair sites therefore collapsed into one fail-closed SNAT
> call each (4 → 2). The #1377 fail-closed contract is unchanged: NPTv6
> short-circuits before the SNAT fallback and cannot fail in the pool sense
> (it is a stateless prefix rewrite with no pool allocation), and BOTH
> remaining `source_nat_decision_for_flow(...)` calls still converted an
> unavailable pool result into a `record_source_nat_failure` exception and
> recycle the packet before session creation or forwarding.

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

#1450 is closed by choosing a backend-specific selector contract, not by
standardizing the retained backends in this slice. Operators should treat
AF_XDP userspace `address-persistent` pool selection as deterministic only
while new allocations stay on the AF_XDP userspace backend and the pool shape
is unchanged.

The retained backends do not share an address-persistent selector today:

- legacy eBPF IPv4 uses the packet-order `src_ip` word modulo the IPv4 pool
  size. On the current little-endian x86 deployment target this makes low bits
  come from the first IPv4 octet;
- legacy eBPF IPv6 XORs the four 32-bit source-address lanes and mods by the
  IPv6 pool size;
- current DPDK mirrors that C-word modulo / lane-XOR behavior for pool address
  selection, while using DPDK-local port counters; and
- current AF_XDP userspace uses the userspace-v1 SHA-256 selector above.

> Historical note (2026-06-22, #2349): the AF_XDP userspace selector was later
> changed from SHA-256 to a seeded non-cryptographic FxHash (userspace-v2). This
> plan records the original #1377 design and is intentionally NOT rewritten; for
> the current selector contract see `docs/userspace-dataplane-gaps.md` (Source
> NAT pool mode).

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

Operationally, backend rollback is expected to preserve already-synced active
sessions by carrying their translated tuple in session state. It is allowed to
remap later new flows from the same client source IP to a different pool
address after the backend changes.

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
- compatible in-process snapshot refreshes preserve allocator state only when
  the helper keeps the same binding-plan entries and the concrete allocator key
  is unchanged;
- helper restart, helper cold start, and binding-plan changes that force helper
  replan reset allocator live state even when the pool key is unchanged;
- reset boundaries do not replay live tuple ownership, persistent leases, or
  allocator counters. New flows allocate from fresh helper-local state; they may
  happen to receive the same translated tuple, but that is a fresh allocation,
  not lease continuity;
- edits to pool name, IPv4/IPv6 address lists, address order, or port range
  replace allocator state and can reset persistent lease continuity;
- HA configs using persistent source-NAT pools are gated before userspace
  forwarding is admitted because leases are not synchronized to the peer.

## HA Failover Boundary (#1449)

Persistent-NAT leases are allocator runtime state, not HA session state. Full
HA lease synchronization would need a peer wire format, ownership rules,
conflict handling for live translated tuples, rollback semantics, and stale
entry cleanup. This slice deliberately does not add partial replay because a
standby importing stale helper-local leases could claim a tuple that is still
owned by a live synced session or by a different allocator shape.

The production contract is therefore an audited gate:

- if chassis cluster is configured and any source-NAT rule references a pool
  with `persistent-nat`, `deriveUserspaceCapabilities()` marks userspace
  forwarding unsupported;
- `TakeoverReady()` propagates the same unsupported reason, so planned
  userspace failover does not treat the helper as ready for that config;
- `show ... userspace` status renders `Forwarding blocked by:
  userspace persistent-nat source pool leases are not HA-synchronized`;
- non-HA persistent pools still expose live-flow, used-port,
  persistent-lease, allocation, reuse, and exhaustion counters, so allocator
  exhaustion remains distinguishable from the HA gate.

There is no "lease reset after failover" behavior in the admitted userspace HA
contract because the config is not admitted to userspace forwarding in the
first place. A future PR that removes this gate must implement full lease sync
or replay with tuple-conflict and stale-entry tests before claiming HA
persistent-NAT support.

Operators can audit the boundary through existing status and Prometheus
counters. `Source NAT pools` status rows and the
`xpf_userspace_source_nat_pool_*` metrics report helper-local `live_flows`,
`used_ports`, `persistent_leases`, `allocations_total`, `reuses_total`, and
`exhaustions_total`; after helper restart or replan these values start again
from the new helper runtime state.

The compatible-refresh boundary has two parts. First, the helper must keep the
same binding-plan entries; binding-plan changes cause helper replan and rebuild
forwarding state, so allocator live state is reset. Second, within a preserved
binding plan, the Rust `SourceNatPoolAllocatorKey` in
`userspace-dp/src/nat.rs` must be unchanged: pool name, configured IPv4 address
list, configured IPv6 address list, and low/high port range. Any change to
those fields is treated as a different allocator shape. The runtime
deliberately does not try to remap old persistent leases across shape edits
because doing so would require proving translated tuple ownership across
potentially different address and port spaces.

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
port stack.

Persistent leases are bounded by the same `max_tracked_flows` value:
`min(pool_port_capacity, 262144)`. Idle persistent leases appear once in the
global ordered expiry index and once in the selected address's ordered expiry
index. Active leases remain in the lease table but are absent from expiry
indexes until their last live flow releases. The per-address expiry index also
has one empty set header per configured pool address.

The latency contract is budgeted work, not strict constant time:

- every allocation runs at most `ALLOCATION_GC_BUDGET` (`8`) global expiry
  checks before attempting a claim;
- every `GC_PERIOD` (`10`) releases run at most `RELEASE_GC_BUDGET` (`64`)
  global expiry checks;
- if the global persistent lease table is at `max_tracked_flows`, each address
  attempt can run at most `PRESSURE_GC_BUDGET` (`64`) global expiry checks
  before trying that address claim;
- if the selected address has no fresh or recycled port, pressure handling
  runs at most `PRESSURE_GC_BUDGET` (`64`) expiry checks for that address
  before retrying the claim; and
- non-address-persistent allocation can repeat the selected-address pressure
  path for each family-compatible pool address.

Near-full allocation and timeout cleanup do not scan the whole lease map on
every new flow, but full-pool pressure can still do non-trivial work. In a
non-address-persistent pool, the still-full lease-table case can consume one
global pressure-GC budget per family-compatible address attempt before
continuing to the next address. If a global pressure pass frees capacity, later
attempts can enter the port-pressure path, where each selected address can
consume one per-address pressure-GC budget before retry. Operators should size
pool address counts, port ranges, and session creation rates with those
budgeted cases in mind. The allocator reports exhaustion when:

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
- A pool-mode rule without a usable pool is fail-closed at the two runtime
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
- Go: userspace admission and takeover readiness gate HA configs that use
  persistent source-NAT pools because leases are not synchronized.
- Go: userspace status summary renders the persistent source-NAT HA unsupported
  reason as a forwarding-blocked status line.
- Go: snapshot builder preserves missing pool, empty pool, invalid port range,
  and nil pool entries as unusable pool-mode rules with
  `pool_unusable_reason`.
- Cargo: missing pools, empty pools, invalid port ranges, malformed pool
  addresses, wrong-family-only pools, and allocator exhaustion surfaces are
  distinct from no source-NAT match.
- Cargo: source-NAT pool rules with missing pools, empty pools, invalid port
  ranges, wrong-family-only pools, or allocation failures fail closed at both
  `poll_descriptor` source-NAT call sites instead of becoming an
  untranslated forward.
- Cargo: userspace-v1 fixtures pin IPv4/IPv6 sticky hash outputs and selected
  pool addresses through the source-NAT rule path.
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
- Cargo: allocation-time persistent lease cleanup is budgeted when the pool is
  not under pressure, so one new flow cannot drain an arbitrary expired run under
  the allocator mutex.
- Cargo: address-persistent pressure cleanup reclaims expired leases for the
  selected pool address even when the global allocation cleanup budget was spent
  on older expirations from other addresses.
- Cargo: compatible in-process snapshot refresh preserves persistent leases,
  tuple ownership, and allocator counters for an unchanged source-NAT pool key.
- Cargo: helper cold start with the same snapshot resets persistent leases,
  tuple ownership, and allocator counters; the next same-source flow is counted
  as a new allocation rather than a lease reuse.
- Cargo: protocol round-trip covers persistent source-NAT snapshot/status
  fields.

Still outside the current supported contract:

- Integration: active userspace SNAT pool sessions preserve return traffic
  across failover, while new-flow mixed-backend rollback tests accept the
  documented selector boundary.
- Helper-restart lease replay beyond the documented reset boundary.
- HA synchronization for persistent-NAT leases. The current #1449 contract is
  the explicit HA capability gate above, not partial lease replay.
- A shared selector algorithm across eBPF, DPDK, and userspace for new-flow
  cross-backend parity.

## Non-Goals

- Do not redesign all NAT rule matching in #1377.
- Do not remove eBPF NAT source as part of #1377.
- Do not claim helper-restart or HA persistence for per-pool `persistent-nat`.
