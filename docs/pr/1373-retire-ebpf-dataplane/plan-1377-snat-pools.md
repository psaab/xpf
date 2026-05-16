# #1377 Userspace Persistent SNAT Pool Plan

## Goal

Make source-NAT pool mode a first-class userspace feature so configs using
`then source-nat pool <name>` no longer depend on the legacy eBPF dataplane for
address selection, port-range enforcement, and durable translations.

## Dependencies

- #1381 should land first so NAT config ownership and runtime status are
  backend-local rather than daemon-side BPF map writes.
- #1385 closes the immediate snapshot safety gap by failing closed when a
  pool-mode SNAT rule references a missing or unsafe pool. The full #1377
  implementation still needs persistent address/port selection semantics.

## Design

Userspace snapshots must carry the resolved pool address set, configured port
range, rule identity, and persistence mode. Rust NAT state then owns address and
port allocation on the forwarding path. Missing pools, empty pools, invalid
port ranges, or unsupported persistence modes must be rejected at commit/snapshot
admission; they must not produce a broad match with no translation.

Port allocation should be sharded per worker and per pool address to avoid a
single hot allocator. Persistent mappings need a bounded table keyed by the
Junos-compatible persistence key, with LRU/timeout reclamation and collision
handling that never aliases two live clients to the same translated 5-tuple.

## Hot-Path Invariants

- No global allocator lock on the packet path.
- Port-range validation happens before any `u16` truncation.
- A pool-mode rule without a usable pool is fail-closed, not a matching no-op.
- Existing reverse-session NAT behavior remains the source of truth for return
  traffic.

## State and HA Behavior

- Active translations are session state and must be included in session sync or
  reconstructed from synced session metadata on failover.
- Persistent mapping tables are runtime state; failover behavior must be
  documented if persistence survives only for active synced sessions.
- Counters expose allocation success, port exhaustion, missing-pool rejects,
  and persistence table evictions.

## Risks

- Silent broad matches: the worst failure mode is a pool rule that matches
  traffic but performs no NAT, shadowing later rules. Admission must fail closed.
- Port exhaustion: allocator contention and exhaustion can cause bursty drops;
  counters must separate exhaustion from policy/NAT no-match.
- Persistence leakage: stale mappings can pin scarce ports after lease/session
  expiry unless reclamation is tied to session lifetime.
- HA skew: allocating different translated ports on the peer after failover can
  break return traffic for live sessions.

## Exact Tests

- Go: snapshot builder rejects missing pool, empty pool, invalid port range,
  and unsupported persistence without emitting a matching no-op rule.
- Go: userspace snapshot round-trip carries pool addresses, port low/high, rule
  identity, and persistence mode.
- Cargo: allocator respects configured port range and never returns duplicate
  live translated 5-tuples.
- Cargo: persistent key reuses the same mapping while live and reallocates after
  expiry.
- Integration: multiple clients through a userspace SNAT pool preserve reverse
  traffic across failover and report pool-exhaustion counters under pressure.

## Non-Goals

- Do not redesign all NAT rule matching in this PR.
- Do not remove eBPF NAT source as part of #1377.
