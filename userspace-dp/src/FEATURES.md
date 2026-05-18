# userspace-dp/src/ — feature modules

The single-file feature modules sit at the crate root and are
consumed by the per-worker hot path in `afxdp/`. They're intentionally
flat: each owns one feature's lookup tables and decision logic, with
no internal sub-modules. Test layout is mixed: most feature modules
have a sibling `<feature>_tests.rs` (`nat`, `nat64`, `nptv6`,
`policy`, `screen`, `prefix_set`, `flowexport`); some keep their tests
inline (`fairness`, `slowpath`, `protocol`, `prefix`); and a few have
neither (`state_writer`, `xsk_ffi`).

## Stages mirroring the BPF pipeline

These mirror the BPF-side stage modules in `bpf/xdp/` and `bpf/tc/`.
The table is a simplified map of feature areas — the actual order
the worker hot path runs them in is interleaved across the
session-hit and session-miss branches in
`afxdp/poll_descriptor.rs`. Read that file for the authoritative
ordering.

| File | Stage | What it does |
|------|-------|--------------|
| `screen.rs` | screen | Pre-session attack-protection checks (land, TCP SYN+FIN, no-flag, FIN-without-ACK, ICMP frag, plus rate-limits). Mirrors `bpf/xdp/xdp_screen.c`. Also contains the #1374 userspace SYN-cookie mint/validate core, fixed-size validated-client admission table, and session-miss ACK validation hook. The lower screen tests cover bounded 4-way validated-client cache replacement; validated-client cache expiration, secret-epoch rotation, and HA-safe secret/cache survivability are still deferred #1374 work. BindingStatus carries local challenge, secret-unavailable, ACK-valid, ACK-invalid, and bypass counters; only ACK-valid, ACK-invalid, and bypass are projected into daemon BPF-global counters today. Challenge, secret-unavailable, validated-client cache state, and the SYN-cookie secret remain local until bounded SYN-ACK TX replies and HA secret publication exist. The Go `syn-cookie` capability gate must stay closed until SYN-ACK TX replies, ACK RST emission, HA-secret publication, and integration validation are wired into the worker path. |
| `policy.rs` | policy | Zone-pair → permit/deny + forwarding-class + DSCP-rewrite + filter chaining. `ZonePairKey` is a `u32` (`from_id << 16 \| to_id`); `JUNOS_GLOBAL_ZONE_ID = u16::MAX` is the sentinel for the global zone. |
| `nat.rs` | NAT44 | Source / destination / static NAT decisions. `NatDecision` carries `rewrite_src` and `rewrite_dst` Options the TX path consumes. |
| `nat64.rs` | NAT64 | RFC 6052 IPv4↔IPv6 translation. `Nat64Prefix` is the 96-bit + IPv4-pool config; `Nat64ReverseInfo` carries the original IPv6 tuple for reverse translation. |
| `nptv6.rs` | NPTv6 | RFC 6296 stateless IPv6-to-IPv6 prefix translation. Each rule maps an internal /48 or /64 to an external prefix; a precomputed adjustment value keeps the L4 checksum neutral so no checksum update is needed after rewrite. |

## Cross-cutting helpers

| File | What it does |
|------|--------------|
| `slowpath.rs` | TUN device injection for firewall-local packets (TCP retransmits, ICMP errors). Built on `io_uring` for batched submit. Rate-limited with `DEFAULT_RATE_LIMIT_PACKETS_PER_SEC = 1_000_000` and `DEFAULT_RATE_LIMIT_BYTES_PER_SEC = 4 * 1024 * 1024 * 1024` (4 GiB). |
| `flowexport.rs` | NetFlow v9 flow export. Samples every Nth session creation, buffers records, periodically flushes as UDP packets to the configured collectors. Template fields enumerated at the top of the file. |
| `fairness.rs` | Pure functions for the fairness-regimes contract (`compute_cstruct`, `compute_observed_cov`, `starved_flow_count`). Consumed by the `fairness-eval` binary and by the contract's pinned worked-example tests. See `docs/fairness-regimes.md` and `docs/per-5-tuple/state.md`. |

## Lookup-structure helpers

| File | What it does |
|------|--------------|
| `prefix.rs` | `PrefixV4` / `PrefixV6` — the canonical IP-prefix value type. |
| `prefix_set.rs` | `PrefixSetV4` / `PrefixSetV6` — adaptive 3-variant enum (#923): `MatchAny`, linear scan, and trie variants. The compiler picks based on the input prefix list. |

## Wire / transport / state

| File | What it does |
|------|--------------|
| `protocol.rs` | Control request / response and snapshot schema types shared between the control socket server (`server/`) and the AF_XDP coordinator. The JSON tags ARE the wire contract — changing them without updating the Go side (`pkg/dataplane/userspace/protocol.go`) breaks the helper. |
| `state_writer.rs` | `io_uring`-backed atomic writer for the daemon's state snapshot file. |
| `xsk_ffi.rs` | Drop-in replacement for `xdpilone` using libxdp's XSK helpers via a C bridge. Provides the same type names (`Umem`, `UmemConfig`, `UmemChunk`, `IfInfo`, `Socket`, `DeviceQueue`, `RingRx`, `RingTx`, `ReadRx`, `WriteTx`, `WriteFill`, `ReadComplete`, `XdpDesc`) so the rest of the crate compiles unchanged. |
| `test_zone_ids.rs` | Test-only zone-id constants used across `_tests.rs` files. |
| `main.rs` / `main_tests.rs` | Crate `main()` — argv handling and dispatch into `server::lifecycle::run()`. Tests live next door. |

## Where these are called from

The worker poll loop drives the per-packet stages from
`afxdp/worker/lifecycle.rs::poll_binding` and the per-descriptor
dispatch in `afxdp/poll_descriptor.rs`. The stages above approximate
the "session-hit" fast path; the real session-miss order interleaves
DNAT, NPTv6 inbound, NAT64, FIB / forwarding resolution, policy, and
SNAT decisions across multiple branches in `poll_descriptor.rs`. Read
that file for the authoritative order — the tabular pipeline above is
intentionally simplified.

`flowexport` and `fairness` are auxiliary surfaces consumed by the
daemon control plane and the `fairness-eval` binary.
