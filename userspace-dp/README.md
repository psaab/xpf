# userspace-dp/

> #1373 status (complete): the eBPF dataplane retirement is done. This Rust
> AF_XDP dataplane is the only runtime forwarding path. The legacy BPF source
> (`bpf/xdp/*.c`, `bpf/tc/*.c`) was deleted in #1476; the eBPF backend is
> hard-rejected at commit by the config compiler (`ErrEBPFDataplaneRetired`,
> `pkg/config`) and at runtime by the dataplane factory
> (`ErrEBPFBackendRetired`, `pkg/dataplane`).

Standalone Rust AF_XDP dataplane that mirrors the BPF pipeline
(screen → zone → conntrack → policy → NAT → forward) but in userspace.
Runs as a separate `xpf-userspace-dp` binary the Go daemon spawns over a
Unix-socket control protocol.

This crate is the only runtime dataplane backend: an empty / omitted
`system dataplane-type` resolves to userspace in
`pkg/dataplane.EffectiveType`. Operators can still pin the selection
explicitly with `set system dataplane-type userspace`. The legacy eBPF
backend is retired (#1373/#1476) and hard-rejected (commit: `pkg/config`
compiler; runtime: `pkg/dataplane` factory);
the DPDK backend is retired under #1525.

## Crate entry

`src/main.rs` — argv parsing, then `server::lifecycle::run()`.

## Top-level layout

| Path | Purpose |
|------|---------|
| `src/afxdp/` | Core dataplane: workers, UMEM, RX/TX rings, frame parsing, session glue. |
| `src/server/` | Control-socket lifecycle and request dispatch. |
| `src/session/` | Session table (slab + Fx-hash indices) + timer wheel. |
| `src/filter/` | Junos-style firewall filter compiler + engine + policer. |
| `src/event_stream/` | Push-based binary session-delta stream to the daemon. |
| `src/bin/` | Helper binaries (`fairness-eval`). |
| `src/nat.rs`, `src/nat64.rs`, `src/nptv6.rs`, `src/policy.rs`, `src/screen.rs`, `src/slowpath.rs`, `src/fairness.rs` | Single-file feature modules consumed by the worker hot path. |

## Architecture

One worker thread per RSS queue. Each worker owns its AF_XDP socket,
UMEM (12K+ RX/TX frames, 256-byte headroom), RX/TX/fill/completion rings,
a per-worker reverse-NAT cache, and a per-worker session table view.

The hot path is the `worker_loop` (in `src/afxdp/worker/`), which polls
all bindings in batch (`RX_BATCH_SIZE=64`, up to `MAX_RX_BATCHES_PER_POLL=4`
per tick). Per descriptor: parse → screen → session lookup → NAT/policy
decision → forwarding build → enqueue TX or recycle.

## Queue planning (`replan_queues`)

`server::helpers::replan_queues` derives the AF_XDP binding plan from the
config snapshot. It builds a candidate list of binding-eligible Linux
netdevs, and emits one binding per `(netdev, queue_id)` for each of that
netdev's own `min(rx_queues, 16)` queues — so the plan is `Σ min(rx, 16)`
and `planned_workers` equals `min(workers, widest interface's queues)`.

Until #7497 this took `queue_count = min(rx_queues)` across ALL candidates
and applied that one number to every interface. On a symmetric box the two
rules agree; on an asymmetric one the old rule left every queue above the
global minimum **unbound**, and an unbound queue is not idle — the shim
takes `drop_degraded_transit` on `BINDING_MISSING`, so it drops every
transit packet RSS steers to it while the interface still reads up. The 16
is the binding array's per-interface stride (`BINDING_QUEUES_PER_IFACE`);
a queue id at or above it would alias the adjacent ifindex's row (#4894).

The candidate set is the shared
binding-exclusion contract (`include_userspace_binding_interface`, the
Rust mirror of the Go `UserspaceBoundLinuxInterfaces` allowlist): zoned,
non-tunnel, non-local-fabric netdevs, excluding `fxp*`/`em*`/`fab*`/`lo0`
and the mgmt/control zones.

Two dedup rules govern which netdev owns a queue. Before #7497 they also
kept the global `queue_count` minimum from COLLAPSING — a single 1-queue
candidate dragged every interface down to one queue. Per-interface counts
remove that amplification, but both rules are still required: the first
prevents a double bind on one `(netdev, queue)`, and the second attributes
a VLAN child's traffic to the hardware queues it actually arrives on.

- **#1921 (`seen_linux`)**: the snapshot lists both a physical interface
  (`ge-0/0/0`) and its non-VLAN unit (`ge-0/0/0.0`); both resolve to the
  same Linux netdev. The first wins; the duplicate is dropped (a second
  XSK bind on the same `(netdev, queue)` returns EBUSY).
- **#3091 (`vlan_child_parent_netdev`)**: a VLAN-child unit
  (`reth0.50`/`reth0.80` → Linux `ge-0-0-2.50`/`ge-0-0-2.80`) is a
  *software* VLAN device the kernel exposes with a **single** RX queue,
  but its tagged frames are delivered on the **physical parent's**
  hardware queues (`ge-0-0-2`, 6 queues). The child netdev name differs
  from the parent, so the #1921 guard misses it. A VLAN child
  (`vlan_id != 0` with a distinct non-empty `parent_linux_name`) is
  therefore deduped onto its parent: when the parent is itself a
  candidate it is skipped entirely; an orphan VLAN child (parent not a
  candidate) is re-keyed onto the parent netdev using the parent's
  hardware queue count, never the child's lone software queue. Before
  #7497 the cost of missing this was global: `min(6, 1, 1, 6) = 1` forced
  a single worker across the whole box (~6-7 Gbps; the #3091 regression).
  Under per-interface counts a missed re-key no longer collapses other
  interfaces — but it still binds the child's single software queue
  instead of the parent's six hardware ones, so the parent's traffic
  arrives on queues nothing is bound to and is dropped as
  `BINDING_MISSING`. The rule is no less load-bearing; only its blast
  radius changed.

Both `vlan_id` and `parent_linux_name` are hashed into the binding
plan key (`update_snapshot_binding_plan_key`) so a re-parenting or VLAN
change always triggers a replan — the #2915/#2916 "the plan key and the
planner agree on every layout input" invariant.

## External interfaces

- **Unix socket** (`/tmp/xpf-userspace-dp.sock`): newline-delimited text
  protocol — `BIND`, `CONFIG`, `SESSION_INJECT`, `STATUS`, `STOP`, etc.
- **AF_XDP rings** (kernel ↔ userspace): RX/TX/fill/completion.
- **BPF maps** (shared with the XDP shim): session table mirror,
  conntrack, NAT pools, heartbeat.
- **Sysctl tuning**: writes `/proc/sys/net/core/rmem_default` and
  `rmem_max` (see `userspace-dp/src/server/lifecycle.rs`); enables
  NAPI busy-poll in `BusyPoll` mode.

## Critical invariants

These invariants are enforced in code (`const_assert`s and runtime
checks). `docs/per-5-tuple/state.md` documents the AF_XDP UMEM ownership
ceiling; the batch and heartbeat constants are pinned in
`userspace-dp/src/afxdp/mod.rs`. They aren't mirrored into CLAUDE.md —
that file's authoritative content covers Go, BPF, and Rust-helper
logging rules, not these specific hot-path constants.

- AF_XDP UMEM ownership is per-queue. A flow that hashes to queue N is
  *physically tied* to worker N — there is no cross-worker descriptor
  sharing. This is why every "rebalance flows across workers" design
  has been plan-killed; see `docs/per-5-tuple/state.md` for the formal
  ceiling.
- `RX_BATCH_SIZE = 64` is paired with the L1d footprint (≤14 KB
  working set per batch) in `userspace-dp/src/afxdp/mod.rs`. A
  `const_assert` enforces it; don't bump it without re-validating.
- `TX_BATCH_SIZE = 64` is paired with the CoS guarantee quantum in
  `userspace-dp/src/afxdp/mod.rs`. Changing requires re-running the
  `guarantee_phase_*` tests.
- **(#9043, corrected)** This line used to read *"Generic-XDP fallback
  consumes UMEM frames permanently on mlx5"*. That is wrong twice over,
  and the tree itself settles it: a generic-XDP interface binds
  **`COPY_ONLY_BIND_FLAGS`** (`afxdp/bind.rs`, the `interface_uses_generic_xdp`
  branch — virtio_net is the one exception, taking AUTO), and
  `afxdp/umem/README.md` states that in copy mode `XDP_PASS` "operates on
  kernel DMA buffers, not UMEM frames". So the generic fallback cannot
  consume a UMEM frame at all. "On mlx5" is incoherent besides: mlx5
  supports native XDP and does not take the generic fallback.

  What is true and worth keeping: the XDP shim redirects `XDP_PASS` to a
  cpumap stage (`USERSPACE_CPUMAP`) that frees the XSK frame immediately.
  That mitigation is shipped and is unaffected by this correction — see
  `afxdp/umem/README.md` for what it is a mitigation *for*, and for why
  that premise is now marked unverified.
- Producer-ring writers (`WriteTx` / `WriteFill` in
  `userspace-dp/src/xsk_ffi.rs`) are **append-safe across multiple
  `insert()` calls on one reservation**: each `insert()` writes at
  `base_idx + written + n` and is bounded by the *remaining*
  reservation (`reserved - written`), so a second `insert()` appends
  after the first instead of overwriting it, and `commit()`/`Drop`
  submit the accumulated `written` count over distinct, initialized
  slots. libxdp masks the slot index against the ring size, so the
  unwrapped sum is correct. (Fixed in #2383 — the prior `base_idx + n`
  indexing was latent because every callsite did exactly one `insert()`
  per reservation; the early-out described below cuts the wasted tail of
  that retry loop (#2481); the #2374 fill-ring suffix retry re-`reserve`s a
  fresh `WriteFill` per NAPI iteration rather than re-inserting, so it
  never tripped the hazard.)
- The bringup fill-ring NAPI-trigger loop in `prime_fill_ring_offsets`
  (`userspace-dp/src/afxdp/bind.rs`) early-outs once the ring is fully
  primed (`remaining == total`) instead of always running the full
  `FILL_PRIME_MAX_ITERS` (20) cap (#2481). It still runs **at least one**
  iteration so the NAPI kick that posts the RX WQEs always fires, and a
  transiently-full ring keeps retrying the deferred suffix up to the cap;
  only the wasted tail (up to 19 × 1 ms poll per queue, ~320 ms of
  avoidable serial bringup latency across 16 queues) is cut. The
  iteration driver `drive_fill_prime_loop` is a pure seam so the early-out
  is unit-tested (fail-on-revert) without a bound `DeviceQueue`.
- **Slow-path control-queue rate limiter** (`src/slowpath.rs`,
  `RateLimiter`): the reinjector that punts firewall-local / control
  traffic to the kernel via the TUN device protects the control queue
  with a dual **token bucket** (packets/s and bytes/s). Tokens accrue
  continuously at the configured rate and the bucket caps at one second
  of tokens, so the admitted rate is smooth across time and the burst in
  ANY interval is bounded by the configured per-second rate. This
  replaced a fixed 1-second window (#2912) that zeroed its counters on
  the boundary and therefore permitted up to **2x** the rate in a short
  interval straddling a window edge (full budget at the end of window N
  plus a full budget at the start of window N+1). `allow_at(now, len)` is
  the clock-injectable core so the boundary behaviour is unit-tested
  fail-on-revert without sleeping; `allow(len)` is the production wrapper.
- **dnat_table reverse-NAT lifecycle (#2979)**: when an SNAT'd session
  installs, the worker poll path calls `publish_dnat_table_entry`
  (`src/afxdp/checksum.rs`) to write a DYNAMIC (flags=0) reverse-NAT
  record into `dnat_table` / `dnat_table_v6` so the embedded-ICMP handler
  can reverse-NAT inbound ICMP errors (PMTUD / traceroute) back to the
  original source. Those maps are `BPF_MAP_TYPE_HASH`,
  `max_entries = MAX_SESSIONS`, `BPF_F_NO_PREALLOC` — **NOT LRU**, so
  nothing self-evicts. The session Close/expiry handler
  (`flush_session_deltas` in `src/afxdp/session_delta.rs`) therefore MUST
  delete the matching entry via `delete_dnat_table_entry`, alongside the
  `session_map` / conntrack cleanup, or every closed SNAT session leaks
  one entry until the map fills and new reverse-NAT publishes fail (the
  #2244 capacity error). The delete key is derived from the SAME
  `dnat_v4_key_bytes` / `dnat_v6_key_bytes` helpers the publish path uses,
  so it byte-matches the insert key exactly (a mismatched key would leave
  the leak). The delete keys ONLY on the forward key + nat decision (the
  Close delta is gated on `!is_reverse`), is a no-op for non-SNAT flows
  (no `rewrite_src` → no key), and ENOENT on an absent key is benign.
  Compiler-managed STATIC DNAT-config entries (flags=1) are never
  published or deleted by this path. Fail-on-revert: the wiring test
  `close_delta_deletes_dnat_table_entry_for_snat_flow` plus the key-SSOT
  tests in `src/afxdp/tests.rs`.
- **Interface-mode SNAT fails closed with no egress address (#5688)**:
  interface source-NAT translates the source to the egress interface's
  OWN address of the PACKET's family (`match_source_nat_result_for_tuple`
  in `src/nat/source.rs`). When the egress interface has NO same-family
  address (a v4 packet on an egress with only v6 addresses, or vice
  versa) there is nothing to translate to. The pre-#5688 code returned
  `Matched` with a `None` rewrite, so the packet was forwarded with its
  private/internal source UNTRANSLATED onto the egress — an address leak.
  The fix fails CLOSED: it returns
  `SourceNatLookup::Unavailable(SourceNatFailureReason::InterfaceNoEgressAddress)`,
  which funnels through the SAME drop / `nat_alloc_fail`
  (`record_source_nat_failure`) disposition a pool-mode allocation
  failure takes, so the flow is dropped and counted instead of leaking.
  The families are resolved independently (a v4 packet checks the v4
  egress address, a v6 packet the v6 one), and the working case — egress
  HAS a same-family address — still translates. No NAT tuple / map-key /
  wire layout change; disposition-only. Fail-on-revert:
  `interface_source_nat_no_v4_egress_addr_fails_closed`,
  `interface_source_nat_no_v6_egress_addr_fails_closed`, and
  `interface_source_nat_translates_when_same_family_egress_addr_present`
  in `src/nat/tests_source.rs`.
- **Source-NAT pool subnet expansion (#3049)**: a source-NAT pool
  address entry may be a bare IP, a host CIDR (`/32`, `/128`), or a
  subnet CIDR (e.g. `203.0.113.0/28`). Junos uses the FULL prefix range
  for a source-NAT pool, so `parse_source_nat_rules_with_previous`
  (`src/nat/source.rs`) enumerates every address in the prefix
  (network..=broadcast inclusive) via `expand_pool_address`, populating
  `pool_addresses_v4` / `pool_addresses_v6` so the port allocator
  round-robins / hashes across the whole range. The pre-#3049 code
  stripped the mask and kept only the network host, silently collapsing
  a `/28` (16 addresses) to one — severe pool/port exhaustion with no
  signal. A single-host prefix still yields exactly one address. An
  over-broad prefix whose host count exceeds `MAX_POOL_PREFIX_HOSTS`
  (65536; covers up to a v4 `/16` or v6 `/112`) is rejected as an
  invalid pool (`SourceNatFailureReason::InvalidPool`) — fail-closed, so
  the operator gets a clear signal rather than a clamped or OOM pool.
  Fail-on-revert: `pool_snat_subnet_expands_full_cidr_range`,
  `pool_snat_host_cidr_yields_single_address`, and
  `pool_snat_overbroad_prefix_marks_invalid` in `src/nat/tests.rs`.
- **Source-NAT port allocation is lock-free (#2852 Phase 1)**: port
  ownership is a per-pool-address atomic occupancy bitmap
  (`AddressOccupancy` in `src/nat/allocator.rs`: `Vec<AtomicU64>` + an
  atomic fresh-port cursor). A `fetch_or` CAS on the bit IS the ownership
  token — a set bit cannot be re-claimed — so the port CLAIM (forward-
  probe cursor + recycle drain) runs WITHOUT the global mutex. The
  non-persistent new-flow hot path claims its port lock-free and takes the
  retained `Mutex<PortAllocatorLiveState>` only for a tiny
  reuse-check + exact-cap-check + `live_by_flow` insert. The global
  tracked-flow cap (F4) is `live_by_flow.len()` re-checked under that tiny
  mutex, so it is EXACT — no M-in-flight overshoot, and a tiny pool near
  capacity is never falsely exhausted. The pre-#2852 single mutex
  serialized every claim (`owner_by_translated` +
  `next_port_offset_by_addr` maps under one lock) and negative-scaled
  (microbench: 2.87M→0.62M allocs/sec, M=1→8); Phase 1 is 1.4–1.6× at
  M=6/8 (`docs/research/2852-portalloc/microbench-results.md`). Persistent
  NAT keeps its lease decision + claim atomic under the mutex (the cold
  path); Phase 2 (hash-sharding the maps) stays deferred. Fail-on-revert:
  `pool_snat_lockfree_concurrent_fill_is_exact_and_collision_free`,
  `pool_snat_lockfree_concurrent_churn_no_double_alloc_no_leak`,
  `pool_snat_release_frees_bit_and_port_is_reusable`,
  `pool_snat_fills_to_exact_capacity_then_exhausts` in `src/nat/tests_pool.rs`.
- **Source-NAT port recycling is FIFO (#3011)**: freed SNAT source
  ports go into a per-address `VecDeque` (`AddressOccupancy::recycle` in
  `src/nat/allocator.rs`, behind a per-ADDRESS mutex — NOT the global
  allocator mutex, #2852) — `push_back` on release, `pop_front` on
  allocation. FIFO recycles the OLDEST-freed port first, maximizing the
  wall-clock gap before any port is reassigned so reuse spreads across
  the upstream's 2MSL/TIME_WAIT window. The pre-#3011 `Vec` push/pop at
  the back was LIFO: the just-freed port was the FIRST reassigned — the
  worst case for colliding with lingering peer TIME_WAIT state. This
  composes with the #3047 (062-10) collision-retain logic: a popped port
  whose occupancy bit is already set is RETAINED (re-queued at the back),
  never discarded, so a transient collision cannot shrink the pool;
  re-queued collided ports go behind the genuinely-free ports so FIFO
  order among the free ports is preserved. Fail-on-revert:
  `pool_snat_recycle_order_is_fifo_not_lifo` in `src/nat/tests_pool.rs`
  (reverting to a back-popping LIFO queue flips the reuse order RED).
- **The recycle ring is bounded in LENGTH and in per-claim COST (#7174
  M13)**: an out-of-band `reserve()` (HA session sync, persistent NAT,
  deterministic NAT) sets a port's occupancy bit without removing the
  port's queued FIFO token, so after HA role churn the ring holds tokens
  that cannot be claimed. Two bounds, both in `AddressOccupancy`
  (`src/nat/allocator.rs`), neither of which changes WHICH port is handed
  out:
  - **Cost.** `claim`'s recycled phase returns `None` immediately when
    `occupied == range`. The retain-at-BACK policy already amortizes the
    churn case (one O(K) sweep, then the reserved tokens sit behind the
    free ones), but the EXHAUSTED address does not amortize: with no free
    tokens left, every claim popped the whole ring, retained the whole
    ring, allocated a K-element retain buffer and returned `None` — and
    `None` is the CORRECT answer there, so nothing self-corrected. The
    test is exact rather than a scan budget on purpose: a budget returns
    `None` on exhaustion, callers read that as "this address is full",
    and the result is a spuriously dropped translation on a pool that
    still has free ports. `occupied` is a live counter maintained by the
    only two sites that transition a bit (`claim_offset` / `free_offset`),
    and `free_recycle` clears the bit AND queues the token under the same
    per-address mutex `claim` holds, so the test is exact with respect to
    the ring the claimer is about to walk rather than a hint.
  - **Length.** `RecycleRing` pairs the `VecDeque` with a per-offset
    "already queued" bitset, so a port holds at most ONE token and the
    ring is bounded by the address's port `range`. Without it the retain
    policy mints duplicates: a retained token means the bit was set at pop
    time, and when that occupant later releases through `free_recycle` the
    `1 -> 0` transition queues a SECOND token for the same port. That grew
    per churn cycle, past `range`, forever.
  Fail-on-revert:
  `pool_snat_exhausted_address_does_not_walk_recycle_fifo_7174_m13`,
  `pool_snat_partially_occupied_address_still_scans_recycle_fifo_7174_m13`
  (the control — a NOT-full address must still scan, so a gate that fired
  one port early reds here),
  `pool_snat_recycle_ring_never_holds_a_duplicate_token_7174_m13` and
  `pool_snat_occupancy_counter_agrees_with_bitmap_7174_m13` in
  `src/nat/tests_pool.rs`. The cost assertion reads
  `debug_recycle_scan_pops`, not the return value: an exhausted address
  returns `None` with or without the short-circuit, so a test that
  asserted only the outcome would be satisfied by no fix at all.
- `HEARTBEAT_GRACE_PERIOD_NS = 6 s` is defined in
  `userspace-dp/src/afxdp/mod.rs` but currently `#[allow(dead_code)]`
  — reserved for future XDP-shim heartbeat gating logic. Workers
  write the heartbeat immediately on bind today
  (`userspace-dp/src/afxdp/worker/mod.rs`), so there is no live
  6-second grace window.

- **Wire struct literals carry `..Default::default()` (#7689).** An
  ADDITIVE snapshot field — one with `#[serde(default)]`, designed to be
  invisible to an older peer — is still a compile break at every
  EXHAUSTIVE struct literal in tests, because those literals enumerate
  every field. Most wire structs are already well defended by convention
  (`InterfaceSnapshot`: 1 exhaustive literal of 402;
  `FirewallTermSnapshot`: 12 of 330). `CoSSchedulerSnapshot` was the
  outlier at 72 of 74, which is why #6846's two new fields broke 71
  literals across five files. Those were converted, and
  `cos_scheduler_snapshot_literals_carry_an_update_tail_7689`
  (`src/protocol/cos_literal_guard_7689.rs`) keeps the count at zero.
  Deliberately NOT `#[non_exhaustive]`: that forces the tail at compile
  time but also blocks exhaustive construction outside the defining
  crate, changing a public contract to solve a test-hygiene problem.

  **Generalised.** A second cell,
  `additive_wire_exhaustive_literals_only_ever_decrease_7689`, ratchets
  the whole additive-wire population — a `Default` impl, at least one
  `#[serde(default)]` field, and >= 8 fields — at **124 exhaustive
  literals across 23 structs**, and no struct may gain one. The ceiling
  fails in BOTH directions: a count below its ceiling also reds, with an
  instruction to tighten it, so ground gained is held.

  The population is deliberately narrow, and the two exclusions are the
  load-bearing part. "Every struct with a `Default` impl" is **1497**
  literals, most harmless — `FirewallFilterSnapshot` is 276 of 276
  exhaustive and costs nothing, because it has three fields and does not
  grow. Exhaustiveness is only a tax on a struct that GAINS fields. And a
  NON-wire struct is excluded on purpose: an additive `#[serde(default)]`
  field is invisible to an older peer by design, so a literal breaking on
  one breaks for no reason, whereas adding a field to an internal struct
  is an ordinary breaking change and the compile error at each site is
  review pressure worth keeping.

- **Zone-policy re-derivation on the established-session hit path (#8356 /
  #8618 / #9381)** — `src/afxdp/poll_descriptor/policy_revalidation.rs`
  re-asks zone policy for a session that was admitted under an older
  config generation, at most once per session per generation, on the
  forward direction only. It is the zone-policy sibling of #7212's
  input-filter revalidation, and it exists because #5858/#7212 already
  tears down a live flow when a commit narrows an input FILTER — not
  doing the same when a commit narrows ZONE POLICY is the asymmetry, not
  a safe default.

  The module header owns the full contract. Two parts of it belong here
  because a reader outside that file can get them wrong:

  - **The revoke predicate is PERMIT-or-not, not "is it Deny".**
    `PolicyAction` is three-valued (`Permit` / `Deny` / `Reject`), and
    `Reject` is a TERMINAL NON-FORWARDING verdict everywhere else in the
    crate — admission requires `Permit` (`poll_descriptor/mod.rs`,
    `flowless_verdict.rs`, `host_inbound_policy.rs`,
    `forwarding/fabric.rs`), the first-packet path drops it
    (`poll_descriptor/reject_reply.rs`), and `policy.rs`'s own
    terminal-action test spells the pair `Deny | Reject`. Until #9381 this
    one arm spelled the same intent as `Deny` ALONE, so a commit narrowing
    a rule `permit` -> `reject` enforced the new verdict on NEW flows
    while every ESTABLISHED session admitted by that rule kept forwarding
    in both directions until idle timeout — and was stamped "revalidated",
    so no later packet of that generation re-asked. Test the POSITIVE
    `Permit` here: a fourth action added later then fails CLOSED instead
    of inheriting the permit arm.
  - **A revoked session is torn down SILENTLY, `Reject` included.** No
    ICMP unreachable, no TCP RST, no log record, no counter — the
    derivation is side-effect-free by contract. That loses nothing
    operator-visible: the teardown also evicts both directions'
    flow-cache slots, so the next packet of the 5-tuple is a session MISS
    and takes the full admission path, which emits the reject reply and
    the RT_FLOW deny record from the one site that owns them.

  - **The evaluated DESTINATION is the POST-translation one (#9382).**
    Admission judges the post-translation destination tuple (#2345/#2358);
    this derivation must ask the SAME question or a translated session is
    judged by two standards. The forward entry is keyed on the WIRE
    tuple, so reading the destination off `flow` gives the VIP — the
    address admission REFUSES to match a rule against. Until #9382 that
    made a permit naming the real server contribute nothing: the
    derivation matched no rule, fell to the default policy, and revoked a
    session whose policy had not changed at all. Fail-CLOSED, and it
    needed no crafted config: `PublishRouteOverlaySnapshot` bumps the
    generation for a ROUTE-ONLY publish, so ordinary BGP/OSPF churn tore
    down every live DNAT/NPTv6 service. The destination now comes from
    the entry's `decision.nat` (`rewrite_dst` / `rewrite_dst_port`),
    which is the same quantity admission folds into `policy_dst_ip` /
    `policy_dst_port` for DNAT, static-DNAT, NPTv6 and NAT64 alike. The
    SOURCE stays pre-translation in both places — Junos evaluates after
    destination NAT and before source NAT.

  - **BOTH zones are resolved LIVE, and fabric ingress is the one
    exemption (#9384).** `to_id` has always come from the egress
    interface read through the live ledger; the FROM-zone used to come
    from the session ENTRY, which the override makes win, so the module's
    claim that "a commit that moves an interface BETWEEN ZONES is caught"
    was true of the EGRESS half only. Moving an interface OUT of a
    permitted zone therefore cut off new flows and left every live
    session being judged under the zone it was admitted in, stamped fresh
    and forwarding. Go's commit-time invalidation cannot cover it either:
    it diffs policy text and referenced-object fingerprints, never zone
    MEMBERSHIP.

    The from-zone is now resolved from the interface THIS packet arrived
    on, through `resolve_ingress_logical_ifindex` (#9383 — keying the raw
    physical index here would turn a trunk mis-attribution into a
    revocation). Two guards keep it from being a revoke storm:

    * **Fabric ingress keeps the entry's zone**, and the discriminator is
      the PACKET's fabric ingress, not the session's
      `metadata.fabric_ingress` — the latter says the session was
      installed from a punt, which says nothing about where this packet
      arrived. This is load-bearing on the SHIPPED config, not
      hypothetical: `docs/ha-cluster-userspace.conf` puts `fab0` in the
      `control` zone and the ledger propagates that onto `ge-0-0-0`, so a
      live resolution there gives `control -> wan`, which nothing
      permits. Without the exemption every established cross-chassis
      session is revoked on the first packet after any commit — TCP death
      on VRRP failback, which the fabric redirect exists to prevent.
    * **An arrival that resolves to NO zone DECLINES**, via the
      pre-existing `from_id == 0` arm, because a zone lookup failure is
      not a verdict. That is a stated residual: an interface moved out of
      every zone is not torn down.

  - **Side-effect freedom here is a property of the CALL, not of the type
    signature (#9385).** This invariant used to be stated STRUCTURALLY —
    that `evaluate_policy_result_*` "takes `&PolicyState` and RETURNS a
    counter handle; it cannot count, log or meter by itself". True of the
    HANDLE, false of the EVALUATION: `try_match_rule` bumps
    `rule.hit_counter` on every match and the implicit-default path bumps
    `state.default_counter`, and `&PolicyState` does not prevent it
    because those counters are ATOMICS behind shared references. Passing
    `packet_len = 0` does not help either — the zero-length gate in
    `HitCounter::add` covers BYTES only and the packet increment is
    unconditional. So every re-derivation recorded a phantom hit, up to
    one packet per live session per config generation, arriving exactly
    when an operator is watching hit-count to confirm a narrowing took
    effect.

    The derivation now calls `evaluate_policy_result_without_counting`
    (`PolicyHitCount::Never`), mirroring the filter engine's
    `NonRoutingCountPolicy`. `HitCounter::add` was deliberately NOT
    changed to treat a zero length as "do not count": #6304's test
    accessor depends on zero-length-still-counts as a distinguisher, and
    `add` is on every counting path in the crate. The
    `to-zone junos-host` walker passes `Count` on purpose — #3706 makes it
    the counting site for a host-bound packet, and the established-hit
    path skips its own re-count for `LocalDelivery` because of that.

  - **A zone of 0 is EVALUATED; only an unresolved INTERFACE declines
    (#9513).** The decline arm used to be
    `if to_id == 0 || from_id == 0 { return None; }`, justified by a
    paragraph that was wrong in every clause after the first: it claimed
    `ifindex_unambiguous_zone_id` is filled by `populate_egress` "only for
    interfaces with a resolvable link-layer address". It is filled by
    `populate_interfaces`, it is not conditioned on a link-layer address
    at all, and #6722 is the change that made a correctly-zoned `xfrmi`
    resolve to its REAL zone — the comment restated the PRE-#6722 bug as
    current behaviour.

    A zero zone on a RESOLVED ifindex means the box does not consider that
    interface to be in any zone: an operator de-zone, a #7509 contested
    ifindex, or an uncorroborated Go claim. New flows there already fall
    to the default policy, so declining to re-judge established ones was
    exactly the asymmetry #8356 exists to remove.

    The fix is NOT "revoke on zero". Zero has a fourth cause that must
    keep declining — **no egress ifindex at all**, which is a flow with no
    route or a peer-synced import for an inactive RG (`upsert_synced`
    leaves `NoRoute`/0). Revoking there tears down the standby population
    at the moment of promotion. The split needs no new state:
    `egress_ifindex == 0` is the lookup failure, `arrival_logical == 0` is
    its ingress twin (fabric ingress keeps the entry's zone, so its twin
    is `metadata.ingress_zone == 0`), and everything else is EVALUATED.

    Evaluated, not special-cased: `evaluate_policy_result_*` (#3110)
    refuses to match any zone-pair or `junos-global` rule against the 0
    sentinel and falls to the default action — the same verdict a NEW flow
    on that interface gets. So it is automatically right under both
    postures: `default-policy deny` revokes, `permit-all` keeps.

  `security policies policy-rematch` is the COMMIT-time mitigation for
  the same class, and it is off by default
  (`pkg/config/types_security.go`), so on a stock box this module is the
  only mechanism — which is why the `Reject` gap was a real enforcement
  hole rather than a cosmetic one.

- **`ifindex_to_zone_id` is keyed by the LOGICAL (VLAN unit) ifindex, and
  the map deliberately lies about the parent (#921/#3618, #9383).** The
  build propagates a zoned child unit's zone onto its parent's ifindex so
  that untagged traffic on a trunk parent is attributed to its unit's
  zone. The consequence every reader must hold: on a trunk whose units
  sit in different zones, the RAW PHYSICAL key and the LOGICAL key return
  **different answers** for the same frame — not two spellings of one
  answer. Measured on a `build_forwarding_state` trunk with unit 42 in
  `lan`, unit 43 unzoned, both `parent_ifindex = 41`:
  `ifindex_to_zone_id[41] = Some(lan)` while
  `resolve_ingress_logical_ifindex(41, vlan 20) = Some(43)` and
  `ifindex_to_zone_id[43] = None`.

  So **resolve the logical unit before reading this map**:
  `resolve_ingress_logical_ifindex(fw, physical, vlan).unwrap_or(physical)`.
  The `unwrap_or` is the established spelling (`poll_descriptor/filter.rs`,
  `prerouting_scope.rs`, `poll_stages.rs`, `neighbor_dispatch.rs`,
  `forwarding/mss.rs`, `forwarding/local_delivery.rs`) and keeps an
  untagged port byte-identical, because `populate_egress` inserts a
  `(bind_ifindex, vlan_id)` row for every snapshot interface — including
  MAC-less ones, since the insert precedes the `src_mac` `continue`.

  Two sites read the PHYSICAL index on purpose and say so in place —
  `afxdp/icmp.rs` (the socket-bind port is the identity it needs) and
  `afxdp/tx/dispatch/mod.rs`. Anywhere else, physical is a defect. #9383
  fixed three: the #7169 reverse-session synthesis in
  `session_glue/mod.rs` (a wrong arrival zone MINTS a reverse session,
  and reverse entries are exempt from zone-policy re-derivation by
  design, so it then rides the established fast path unadjudicated), the
  fabric zone stamp in `poll_descriptor/mod.rs` (the id selects the PEER
  node's ingress zone for a redirected packet), and the filter-log
  source-zone attribution in `afxdp/forward_request.rs`.

  GRE/WireGuard decap is unaffected and that is by construction, not by
  luck: `afxdp/logical_ingress.rs` builds the inner meta with
  `ingress_ifindex = logical_ifindex` and `ingress_vlan_id = 0`, and a
  tunnel row has no parent so it keys itself — the resolution is the
  identity.

## Subdir READMEs

See `src/afxdp/README.md`, `src/server/README.md`, `src/session/README.md`,
`src/filter/README.md`, `src/event_stream/README.md`, `src/bin/README.md`.
