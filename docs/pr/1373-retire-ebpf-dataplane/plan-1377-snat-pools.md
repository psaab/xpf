# #1377 Userspace Address-Persistent SNAT Pool Plan

## Goal

Make source-NAT pool mode a first-class userspace feature so configs using
`then source-nat pool <name>` no longer depend on the legacy eBPF dataplane for
address selection, address-persistent pool choice, port-range enforcement, and
durable translations.

## Dependencies

- #1381 should land first so NAT config ownership and runtime status are
  backend-local rather than daemon-side BPF map writes.
- #1385 closes the immediate snapshot safety gap by failing closed when a
  pool-mode SNAT rule references a missing or unsafe pool. The full #1377
  implementation still needs address-persistent pool selection semantics and a
  cross-backend compatibility decision.

## Design

Userspace snapshots must carry the resolved pool address set, configured port
range, rule identity, global `source address-persistent` state, and per-pool
`persistent-nat` mode. Rust NAT state then owns address and port allocation on
the forwarding path. Missing pools, empty pools, invalid port ranges, or
unsupported persistence modes must be rejected at commit/snapshot admission;
they must not produce a broad match with no translation.

Address-persistent pool selection is not currently cross-backend equivalent and
must be made explicit before #1373 Phase 4:

- legacy eBPF IPv4 uses `src_ip % num_ips`;
- legacy eBPF IPv6 XORs the four 32-bit source-address lanes and mods by the
  IPv6 pool size;
- current userspace uses a `xpf-userspace-snat-address-persistent-v1` domain
  tag plus address family and canonical source bytes through SHA-256; and
- DPDK consumes the shared pool config but has allocator-local implementation
  details.

#1377 must either standardize a single shared algorithm for all retained
backends or document a compatibility break and constrain mixed-backend
failover/rollback tests accordingly. Until then, "address-persistent" means
stable within one backend's pool order and size, not stable across eBPF,
userspace, and DPDK.

Port allocation should be sharded per worker and per pool address to avoid a
single hot allocator. Persistent mappings need a bounded table keyed by the
Junos-compatible `persistent-nat` key, with LRU/timeout reclamation and
collision handling that never aliases two live clients to the same translated
5-tuple.

## Hot-Path Invariants

- No global allocator lock on the packet path.
- Port-range validation happens before any `u16` truncation.
- A pool-mode rule without a usable pool is fail-closed, not a matching no-op.
- Existing reverse-session NAT behavior remains the source of truth for return
  traffic.
- Address-persistent pool choice must be deterministic for the configured
  backend, source address, pool family, and pool order; any cross-backend
  divergence must be captured in tests and docs.

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
- Algorithm divergence: a rollback from userspace to eBPF or DPDK can map the
  same source to a different pool address unless #1377 standardizes the
  algorithm or declares the compatibility boundary.

## Exact Tests

- Go: snapshot builder rejects missing pool, empty pool, invalid port range,
  and unsupported persistence without emitting a matching no-op rule.
- Go: userspace snapshot round-trip carries pool addresses, port low/high, rule
  identity, and persistence mode.
- Cargo: allocator respects configured port range and never returns duplicate
  live translated 5-tuples.
- Cargo/Go: address-persistent algorithm fixtures cover IPv4 and IPv6 source
  addresses, pool reordering, and the chosen cross-backend compatibility rule.
- Cargo: persistent key reuses the same mapping while live and reallocates after
  expiry.
- Integration: multiple clients through a userspace SNAT pool preserve reverse
  traffic across failover and report pool-exhaustion counters under pressure.

## Non-Goals

- Do not redesign all NAT rule matching in this PR.
- Do not remove eBPF NAT source as part of #1377.
