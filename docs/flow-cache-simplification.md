# Flow Cache Simplification

## Purpose

This document captures the current flow-cache simplification work in the
userspace dataplane, why it matters for HA failover, what has already been
simplified, and the next implementation phases.

The goal is not to remove the flow cache. The flow cache is still needed for
performance. The goal is to make it a disposable acceleration layer instead of
another piece of HA transition machinery.

## Why This Matters

The current HA/failover path is hard to reason about because several concerns
are mixed together in the hot packet path:

1. forwarding decision
2. rewrite data
3. cache validation state
4. RG ownership / HA freshness checks
5. transition-time invalidation rules

That makes failover fragile because the fast path is carrying both performance
state and transition state.

The simpler model is:

1. canonical forwarding/session state decides what should happen
2. flow cache stores a validated shortcut for that decision
3. cache entries self-invalidate cheaply when config/FIB/RG state changes
4. failover remains correct even if the cache is cold or empty

## Current Cache Model

The current cache is still:

- per-worker
- direct-mapped
- keyed by session 5-tuple plus ingress ifindex
- validated by:
  - config generation
  - FIB generation
  - owner RG epoch

Relevant code:

- [userspace-dp/src/afxdp/types.rs](../userspace-dp/src/afxdp/types.rs)
- [userspace-dp/src/afxdp.rs](../userspace-dp/src/afxdp.rs)
- [userspace-dp/src/afxdp/session_glue.rs](../userspace-dp/src/afxdp/session_glue.rs)

This is the right general direction. The problem was that validation and cache
construction logic were spread through the hot packet loop.

## Simplifications Already Implemented

### 1. Separate rewrite data from validation state

Committed in:

- `744a7ef5` `refactor: simplify flow cache validation state`

Changes:

- `RewriteDescriptor` now carries only rewrite/tx data
- cache validation moved into:
  - `FlowCacheStamp`
  - `FlowCacheLookup`
- `FlowCacheEntry` now carries a single `stamp`

Why this helps:

- rewrite state is no longer polluted with HA/config epoch bookkeeping
- lookup and insert semantics are explicit
- cache validation is easier to audit independently of packet rewrite logic

### 2. Extract cache eligibility and entry construction helpers

Committed in:

- `4f20542b` `refactor: extract flow cache eligibility helpers`

Changes:

- added `FlowCacheEntry::packet_eligible(...)`
- added `FlowCacheEntry::should_cache(...)`
- added `FlowCacheEntry::from_forward_decision(...)`
- packet loop now stops hand-building flow-cache entry fields inline

Why this helps:

- the hot path is less branch-heavy and easier to read
- all cacheability policy is centralized
- future cache policy changes will touch one helper instead of duplicated
  packet-loop logic

#### Cacheability contract: lookup and insertion are symmetric (#2363)

`FlowCacheEntry::packet_eligible(meta)` is the single source of truth for
which segments may use the flow cache:

- UDP — always eligible.
- established-TCP **pure ACK** (`tcp_flags::is_ack_only`, i.e.
  `flags & (FIN|SYN|RST|ACK) == ACK`; PSH and URG are ignored, so a
  **PSH+ACK data segment stays cacheable**).
- TCP control segments (SYN, SYN-ACK, FIN, RST) — **never eligible**.

Both directions of the cache must reference this predicate:

- **Lookup** is gated in `poll_descriptor/mod.rs` — the fast path is
  only entered when `FlowCacheEntry::packet_eligible(meta)` holds.
- **Insertion** is gated by `FlowCacheEntry::should_cache`, which calls
  `packet_eligible` first (#2363). Before #2363 only lookup was gated:
  a control segment that produced a `ForwardCandidate` decision would
  seed a cache entry, and a later pure-ACK on the same 5-tuple would
  take the fast path and skip the session lookup that observes and
  advances TCP closing state on FIN/RST. The cached decision is the
  legitimately-computed forward decision (so this was never a policy
  fail-open) — the harm is the skipped flag-sensitive session-state
  observation, plus the hazard of seeding any future per-packet
  flag-sensitive feature off the first control packet.

Keeping the eligibility rule in `packet_eligible` and calling it from
both sites means admission and lookup can never drift apart: a segment
that cannot look up the cache also cannot populate it.

## What Is Simpler Now

After the two refactors above:

1. cache lookup takes one context object
2. cache insertion takes one constructor path
3. descriptor fields are only packet rewrite fields
4. config/FIB/RG epoch validation is isolated from rewrite logic

This removes a large amount of inline cache plumbing from the packet path
without changing behavior.

## What Is Still Too Complex

The flow cache is improved, but the hot path still contains too much inline
execution logic after a cache hit.

The biggest remaining complexity is in cached-hit execution:

- target binding selection
- fabric queue selection
- in-place rewrite attempt
- fallback to `PendingForwardRequest`
- same-binding vs cross-binding behavior

That code still lives inline in the packet loop in
[userspace-dp/src/afxdp.rs](../userspace-dp/src/afxdp.rs).

This is still harder than it should be for HA work because the control flow of
"cache hit -> how do we transmit this?" is mixed into the control flow of
"packet classification -> should we do slow path or fast path?"

## Desired End State

The desired end state is:

1. packet loop determines whether the cache may be used
2. cache lookup returns a validated cached entry or a miss
3. one helper executes the cached hit
4. one helper constructs cache entries from authoritative forwarding decisions
5. cache invalidation remains epoch/generation based
6. failover does not require special flow-cache scans or transition-specific
   cache repair

Conceptually:

```text
packet
  -> flow cache allowed?
  -> cache lookup(validated)?
     -> yes: execute_cached_flow(...)
     -> no: resolve authoritative decision
           -> maybe cache result
           -> execute authoritative path
```

## Remaining Implementation Phases

### Phase 1: Extract cached-hit execution

Move the remaining cached fast-path execution block into one helper, for
example:

- `execute_cached_flow(...)`

That helper should own:

- target binding selection
- fabric target selection
- in-place rewrite attempt
- fallback request construction
- final recycle / continue decision

Expected benefit:

- removes most of the remaining flow-cache complexity from the packet loop
- makes fast-path correctness review substantially easier

### Phase 2: Shrink cached metadata

`FlowCacheEntry` still stores more than it likely needs.

Today it carries:

- `decision`
- `descriptor`
- `metadata`
- `stamp`

The next step is to determine whether the cached execution path really needs the
full `SessionMetadata`, or whether it only needs a smaller subset such as:

- ingress zone
- owner RG
- fabric ingress flag

Expected benefit:

- smaller entries
- clearer separation between authoritative session state and cached execution
  hints

### Phase 3: Make cache decision classes explicit

Today caching is still effectively tuned around `ForwardCandidate`.

If additional dispositions ever become cacheable, the code should not regress
back into ad hoc packet-loop branches.

Expected direction:

- define explicit cache decision classes / supported dispositions
- keep unsupported classes out of the cache constructor

Expected benefit:

- avoids future HA regressions caused by silently widening cache coverage

### Phase 4: Tighten tests around the helper boundary

Add focused tests for:

1. cache hit, same-binding transmit
2. cache hit, cross-binding transmit
3. stale HA validation forcing miss/fallthrough
4. stale RG epoch forcing miss
5. non-cacheable NAT64 decisions staying uncached (NPTv6 is now
   cacheable — see "NPTv6 fast-path caching (#2652)" below)

Expected benefit:

- protects the flow cache as a performance layer without forcing HA behavior to
  be debugged from the packet loop

## Non-Goals

This work does **not** attempt to solve the whole HA failover problem by
itself.

It does **not**:

- replace session sync design
- remove ownership or HA runtime state
- make failover MAC-move-only on its own
- remove the need for a simpler canonical HA state model

Those broader problems are covered in:

- [ha-simple-failover-design.md](./ha-simple-failover-design.md)
- [userspace-forwarding-and-failover-gap-audit.md](./userspace-forwarding-and-failover-gap-audit.md)

This document is narrower: make the flow cache easier to reason about so it
stops amplifying HA complexity.

## Validation

The current simplification work has been validated with:

- `cargo test --manifest-path userspace-dp/Cargo.toml --no-run`
- `cargo test --manifest-path userspace-dp/Cargo.toml epoch_based_flow_cache_invalidation_for_demoted_owner_rg -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml epoch_based_flow_cache_unrelated_rg_not_invalidated -- --nocapture`
- `cargo test --manifest-path userspace-dp/Cargo.toml apply_descriptor_nat64_falls_back -- --nocapture`

## RG epoch index fallback (#2466)

The per-RG epoch table is a fixed `MAX_RG_EPOCHS = 16` array (`rg_epochs:
[AtomicU32; 16]`). The config schema accepts redundancy-group IDs with no
upper bound, so an operator can configure an RG whose ID is `>= 16`.

Before #2466 the flow-cache stamp/consumer guard only consulted a per-RG
epoch slot when `owner_rg_id > 0 && owner_rg_id < MAX_RG_EPOCHS`; any other
owner (an out-of-range high RG ID, or `owner_rg_id <= 0` for fabric /
unresolved-owner reverse) was stamped with a literal epoch `0` and never
re-checked against any epoch slot on lookup. A cached forwarding decision
for an RG `>= 16` therefore survived that RG's activation/demotion until the
`owner_rg_lease_until` or node-level session-expiry backstop caught it —
delayed invalidation, not immediate.

The fix routes every owner through a single helper,
`flow_cache::rg_epoch_index(owner_rg_id)`:

- in-range (`1 ..= MAX_RG_EPOCHS-1`): use the owner's own slot (unchanged —
  RG 0/1/2 used by the loss cluster behave bit-identically);
- out-of-range high RG IDs and `owner_rg_id <= 0`: fall back to the
  node-level `rg_epochs[0]` activation edge.

Both `FlowCacheStamp::capture` and the lookup invalidation now use that
helper, so the stamp and the re-check always agree. This mirrors the worker
session-expiry gate (`epoch_of` in `worker/loop_body/mod.rs`), which already
maps out-of-range/`<= 0` owners to `rg_epochs[0]`; the two gates are now
consistent. A high-RG flow is now stamped with the node-level epoch and
invalidates on a node-level **activation** edge (`rg_epochs[0]` is bumped
when any RG activates, ha.rs) plus the unconditional `owner_rg_lease_until`
backstop, instead of never (it was previously stamped epoch 0). A high-RG
**demotion-without-activation** does not bump `rg_epochs[0]` (the per-RG
bump loops are themselves guarded by `idx < MAX_RG_EPOCHS`), so that case
is caught by the lease backstop rather than the epoch edge — the same
structural behavior the worker session-expiry gate already has. No schema
change and no operator-facing rejection. Tests: `out_of_range_owner_rg_stamps_node_level_epoch`,
`out_of_range_owner_rg_invalidates_on_node_level_bump`,
`in_range_owner_rg_unchanged_by_node_level_bump` (flow_cache_tests.rs).

## NPTv6 fast-path caching (#2652)

Before #2652 `FlowCacheEntry::should_cache` excluded BOTH `decision.nat.nat64`
and `decision.nat.nptv6`, so every NPTv6- and NAT64-translated packet missed
the flow cache and re-ran the full session-lookup + policy-eval slow path on
every packet. #2652 splits these two cases on the actual dataplane mechanics:

- **NPTv6 (RFC 6296) is now cacheable.** At the dataplane an NPTv6 decision is
  nothing more than a same-family IPv6 address byte-rewrite of one side
  (`rewrite_dst` for inbound, `rewrite_src` for outbound). The RFC 6296
  checksum-neutral adjustment word is computed entirely upstream in
  `src/nptv6.rs` (`translate_inbound`/`translate_outbound` via `adjust_word`),
  so the `Ipv6Addr` handed to the worker in `NatDecision` already preserves
  the L4 ones-complement sum. The slow path (`apply_nat_ipv6`) writes that
  address and SKIPS the L4 checksum adjust (`skip_l4_csum = nat.nptv6`); the
  descriptor fast path carries `l4_csum_delta == 0` (`compute_l4_csum_delta`
  short-circuits on `nat.nptv6`) so the IPv6 arm
  (`apply_rewrite_descriptor_ipv6`) ALSO leaves the L4 checksum untouched.
  The two paths are therefore byte-identical. The orchestrator
  (`frame/rewrite/mod.rs`) no longer early-returns for `rd.nptv6`; it keeps a
  defense-in-depth fall-back only when a `nptv6` descriptor carries a non-v6
  `ether_type` (NPTv6 is IPv6-only). `should_cache` drops the
  `!decision.nat.nptv6` clause and `from_forward_decision` propagates
  `nptv6: decision.nat.nptv6` into the descriptor.

- **NAT64 stays excluded (correct).** NAT64 is a version-changing translation:
  the IPv6 40-byte header is rebuilt as an IPv4 20-byte header (or vice versa),
  the frame length changes, and fragment-header handling differs. It is
  produced by `build_nat64_*_frame`, which ALLOCATES a fresh frame of a
  different size — there is no in-place rewrite the byte-write
  `RewriteDescriptor` could carry. The orchestrator still early-returns
  `None` for `rd.nat64`, and `should_cache` keeps `!decision.nat.nat64`.

Validation:

- `nptv6_is_cacheable`, `nat64_not_cacheable` (flow_cache_tests.rs) — the
  admission split; fail-on-revert if the `!nptv6` exclusion is reinstated.
- `pin_nptv6_descriptor_matches_generic_byte_for_byte`
  (frame/prop_tests/rewrite.rs) — proves the descriptor fast path output is
  byte-identical to the generic slow path for an NPTv6 dst rewrite, with the
  L4 checksum unchanged (checksum-neutral). Fail-on-revert: reinstating the
  `rd.nptv6` decline makes `apply_rewrite_descriptor` return `None` and the
  `.expect(...)` panics.
- `pin_descriptor_nat64_decline_frame_untouched` — NAT64 (and a `nptv6`
  descriptor with a v4 `ether_type`) still decline before any byte is written.
- `descriptor_generic_differential` (unmasked) — existing same-family parity
  unaffected.

## Neighbor MAC-change invalidation (#3048)

A cached `RewriteDescriptor` carries the resolved next-hop destination MAC
(`dst_mac`, set from `decision.resolution.neighbor_mac`). The stamp gates
(`config_generation`, `fib_generation`, the RG epoch/lease) did NOT cover a
bare kernel ARP/NDP MAC change with the route unchanged: when an upstream
gateway fails over (VRRP), a NIC is swapped, or a host's MAC otherwise
changes, the `dst_mac` in every cached forwarding decision for that next-hop
went stale and kept rewriting to the old MAC until the session expired or an
unrelated config/route event bumped `fib_generation` — blackholing
long-lived flows.

The fix adds monotonic MAC-change epochs to `ShardedNeighborMap`
(`sharded_neighbor.rs`). **Per #5147 these are PER-SHARD**
(`shard_mac_epochs: [AtomicU32; NUM_SHARDS]`), not a single global counter:
a write bumps ONLY the epoch of the shard that holds the changed neighbor
key. The epoch is bumped ONLY when a write REPLACES an existing neighbor's
hwaddr with a DIFFERENT MAC — never on a first insert of a new neighbor (no
cached flow can reference a MAC that did not previously exist) and never on a
same-MAC ARP/NDP refresh (the overwhelmingly common case; bumping there would
flush that shard's cached flows on every neighbor refresh and collapse the
fast-path hit rate). All FIVE neighbor write paths are covered, each bumping
the specific shard(s) it mutates:

- the netlink monitor (`insert_if_changed`, the primary RTM_NEWNEIGH path);
- the data-path ARP-reply / NDP-NA learn (`poll_stages.rs`), now routed
  through `insert_if_changed` so a MAC change observed directly on the wire
  bumps the epoch. A plain `insert` there would write the new MAC first and
  then SHADOW the kernel-monitor event that follows `add_kernel_neighbor`
  (the monitor would see `prior == new` and not bump), leaving the cache
  stale;
- the on-demand resolver (`insert_confirmed_if_unchanged`), which bumps when
  a confirmed GETNEIGH result replaces an existing MAC (its epoch-reject
  path writes nothing and so never bumps);
- the Go control-plane snapshot push (`apply_manager_neighbors` →
  `ShardedNeighborMap::bulk_replace_neighbors`), the authoritative #1197
  neighbor mechanism. This path is REACHABLE for the exact #3048 headline
  case: under a VRRP-failover RTM_NEWNEIGH multicast burst the in-process
  monitor's bounded rcvbuf can overflow and silently drop events, after
  which the Go neighbor listener (separate socket + resubscribe + 15s
  force-probe) pushes the new gateway MAC through this path. A shadowing
  race exists even without overflow: if the Go push lands first, the monitor
  then sees `prior == new` and does not bump. Either way the epoch must
  advance here or the cached `dst_mac` stays stale until session expiry —
  a blackhole. The bump CANNOT be a naive change-check inside the per-key
  `insert`: a snapshot push uses `NeighborReplace: true`, which does
  `remove(old)` BEFORE `insert(new)` under the bulk lock, so the prior MAC
  is already gone by insert time. `bulk_replace_neighbors` therefore
  SNAPSHOTS each incoming key's prior MAC UNDER the bulk lock BEFORE the
  removes, then (per #5147) bumps the shard of each key whose incoming MAC
  differs from its snapshotted prior — one bump per changed shard, deduped
  via a `[bool; NUM_SHARDS]` mask so two changed keys colliding in one shard
  bump it once (a pure same-MAC refresh and brand-new keys with no prior do
  NOT bump). HA peer-promoted session closes remain out of scope;
- the #1787 RX source-MAC data-path learn (`learn_dynamic_neighbor` in
  `neighbor_dispatch.rs`), now routed through
  `ShardedNeighborMap::learn_pair_if_changed` (#3169). This learn snoops the
  source MAC off every received frame and writes it under up to two keys (the
  physical ingress ifindex plus the resolved logical VLAN sub-ifindex) in the
  #949 pair-write. Its `pair_write_needed` gate fires on a genuine MAC change
  (`current != Some(src_mac)`), not just a first sighting, so it really does
  mutate an existing neighbor's MAC — and `lookup_neighbor_entry`
  (`forwarding/fib.rs`) falls back to `dynamic_neighbors` for a next-hop
  absent from the manager set, the common AF_XDP fast-path case where the
  kernel never ARP-resolves the next-hop because zero-copy bypasses the
  stack. Without a bump an RX-learned MAC change would leave the cached
  `dst_mac` stale until session expiry (the #3048 blackhole class), and it
  could also SHADOW the kernel monitor's `insert_if_changed` (the monitor
  then observes `prior == new` and does not bump). `learn_pair_if_changed`
  snapshots each key's prior MAC via `BulkShardGuard::get` under the same
  all-shard lock as the insert, then bumps the epoch exactly once for the
  pair if any key replaces an existing MAC with a different one — first
  sighting and same-MAC re-learn add a single Relaxed read per key and no
  bump, matching the per-key semantics.

`FlowCacheEntry` carries a `neighbor_mac_epoch` PLUS (per #5147) a
`neighbor_shard` — the index of the shard holding this flow's resolved
next-hop `(egress_ifindex, next_hop)`, precomputed once at cache-miss time
(`ShardedNeighborMap::shard_index`). The worker fast path
(`poll_descriptor/flow_cache_hit.rs`) re-reads only THAT shard's epoch on
every hit (`FlowCacheEntry::neighbor_mac_epoch_stale` → `shard_mac_epoch`, a
single indexed relaxed load + compare); a mismatch evicts the slot and falls
through to the slow path, which re-resolves the current MAC. A flow with no
resolved next-hop (`NEIGHBOR_SHARD_NONE`) has no dynamic-neighbor dependency
and is never MAC-stale. This is the same lazy epoch-compare pattern as
`rg_epochs` — chosen over an explicit cross-worker `FlushFlowCaches` so
invalidation is lock-free and self-healing on the next packet.

**Read-before-resolve (#3918 / #5147).** The stamped epoch is SNAPSHOTTED
BEFORE the next-hop MAC is resolved, not re-read at insert time. Because the
resolved shard is not known until after the resolve, `poll_descriptor/mod.rs`
snapshots the WHOLE per-shard epoch vector
(`dynamic_neighbors.snapshot_shard_epochs()` → `neighbor_epoch_snapshot`) at
the top of per-descriptor processing — before `resolve_flow_session_decision`
/ the session-miss `finalize_new_flow_ha_resolution` consult the neighbor
table. After the resolve it extracts the resolved shard's snapshotted value
(`neighbor_epoch_snapshot.epoch_for(&(egress_ifindex, next_hop))`) and threads
it into `FlowCacheEntry::from_forward_decision` (a `neighbor_mac_epoch` value
parameter; the constructor independently derives the matching `neighbor_shard`
from the same `decision.resolution`, and has no `dynamic_neighbors` handle so
it cannot re-read the live epoch). Re-reading the shard epoch AT insert time
(after the resolve) was a TOCTOU that re-opened the #3048 blackhole: a VRRP
gateway failover landing between the resolve (which read the OLD MAC) and the
stamp would capture the NEW shard epoch onto the cached OLD `dst_mac` — a
fresh-looking stale entry that survives every hit until it ages out.
Snapshotting first guarantees the stamped shard epoch is `<=` the shard epoch
observed at resolve time, so the MAC-change bump makes the entry stale on its
next hit and it re-resolves to the new MAC. Relaxed loads suffice: the
snapshot and the stamp run on the one worker thread (program order sequences
the snapshot before the resolve), and the neighbor shard `Mutex` — not these
counters — synchronizes the MAC bytes; the epochs are monotonic invalidation
signals needing only eventual cross-thread visibility. Mirrors the
#2170/#3912 record-before-use discipline. The snapshot is NUM_SHARDS relaxed
loads on the cold cache-miss/resolve path only (established flows hit the
cache and never reach it).

**Scope / tradeoff (per #5147, superseding the #3048 global epoch):** the
flow cache is keyed by the flow 5-tuple, not by next-hop, so it cannot key
invalidation on the exact neighbor. #3048's first cut used a SINGLE global
epoch, which meant ANY neighbor's MAC change lazily invalidated ALL cached
flows. That was an attacker-driven cache-thrash / DoS: an on-link sender
alternating one IP's MAC advanced the global epoch faster than entries could
warm, collapsing the whole flow cache to ~1 packet (#5147). The fix stamps
each cached flow with the epoch of the SPECIFIC shard its resolved next-hop
lives in and bumps only the changed neighbor's shard, so a MAC change on
neighbor A invalidates a cached flow using neighbor B only if A and B hash to
the SAME shard (probability 1/NUM_SHARDS = 1/64), never map-wide. This trades
exact per-neighbor precision for a fixed-size (64-slot) epoch vector that
keeps the hot-path check to one indexed load — a genuine per-neighbor index
would require a hashmap probe on every fast-path hit, defeating the flow
cache. Genuine MAC changes are rare (failover / NIC swap) and same-MAC
refreshes (which never bump) are the steady-state norm, so the residual
1/64 same-shard collision costs at most a single spurious re-resolve.

Validation: `mac_change_epoch_*` (sharded_neighbor_tests.rs) cover, now
PER-SHARD via `mac_change_epoch_for(&key)`: starts-at-zero,
no-bump-on-first-insert, no-bump-on-same-mac-refresh, bump-on-change
(fail-on-revert for `insert_if_changed`), `mac_change_epoch_isolated_per_
shard_across_neighbors` (a change on A bumps only A's shard, leaving an
unrelated neighbor B in a different shard at 0 — the #5147 isolation guard;
RED under the old global epoch), the three resolver cases (first-insert
no-bump, change bumps — fail-on-revert for the resolver —, epoch-reject
no-bump), the bulk-replace cases (`mac_change_epoch_bulk_replace_*`: change
bumps — fail-on-revert for `bulk_replace_neighbors` —, same-MAC refresh
no-bump, brand-new-keys no-bump, and `..._bumps_each_changed_shard_once`:
two distinct-shard keys each bump their own shard once), and the RX-learn
cases (`mac_change_epoch_rx_learn_*`: first-sighting no-bump, same-MAC
re-learn no-bump, change bumps — fail-on-revert for `learn_pair_if_changed`
—, and `..._pair_bumps_each_key_shard`: each key of the #949 pair-write
bumps its own shard). At the flow-cache layer:
`cached_descriptor_evicted_only_on_neighbor_mac_change` (flow_cache_tests.rs)
is the #3048-preserved over-eviction guard — a descriptor stamped against its
OWN neighbor's shard survives a same-MAC refresh and is evicted on a change
to that neighbor; `unrelated_neighbor_mac_change_does_not_evict_cached_flow`
is the #5147 targeted-invalidation guard — with two neighbors A/B in distinct
shards, changing A evicts F_a (uses A) but leaves F_b (uses B) a cache hit
(RED under the old global epoch, where both evict). Neutralizing
`bump_shard_epoch` (or making it bump all shards) turns these RED.
`flow_cache_stamps_pre_resolve_epoch_survives_interleaved_gateway_failover`
(flow_cache_tests.rs) is the #3918 read-before-resolve fail-on-revert: it
snapshots the per-shard epochs, interleaves a gateway-MAC failover (bumping
the neighbor's shard epoch), stamps a real `from_forward_decision` entry with
the PRE-resolve snapshot value, and asserts the entry is stale on its next
hit — and that a POST-resolve read (the pre-#3918 bug) would look fresh (the
blackhole).
Reverting the fix so the constructor ignores the caller's pre-resolve epoch
turns it RED. `flow_cache_normal_resolve_caches_and_serves_neighbor_mac` is
the companion no-interleave case: a normal resolve must not spuriously evict.

## FIB-generation bump gating (#3767)

The `fib_generation` half of the validation stamp is invalidated cheaply by a
lightweight `bump_fib_generation` control message (the Go
`Manager.BumpFIBGeneration` route-only overlay path — no full snapshot
rebuild). Because flow-cache validation is **equality** based
(`entry.stamp.fib_generation != lookup.fib_generation` in `flow_cache.rs`),
NOT monotone, the bump verb needs the same guards a full `apply_snapshot`
carries. Before #3767 it had none — it checked only snapshot presence. Three
gates were added (handler `server/handlers/snapshot.rs::bump_fib`, coordinator
`afxdp/coordinator/mod.rs::bump_fib_generation`):

- **Protocol-version gate (H4).** `bump_fib` now rejects
  `snapshot.version != CONFIG_SNAPSHOT_PROTOCOL_VERSION`, mirroring `apply`.
  A mixed-version / corrupt client (which serializes `version = 0`) can no
  longer mutate validation state. The Go `Manager.BumpFIBGeneration` now
  stamps the bump snapshot with `ProtocolVersion` so a legitimate route-only
  bump still passes.
- **Monotonicity gate (H5).** `Coordinator::bump_fib_generation` refuses a
  value strictly lower than the current in-memory `validation.fib_generation`
  and returns `false`; the handler then reports `ok = false` and mutates
  nothing. A route-only overlay bump is monotone by construction on the Go
  side (the shim counter only increments), so a lower value is a
  stale/duplicate/corrupt message or a reset shim counter. Reviving it would
  make cache entries a prior bump already invalidated MATCH validation again,
  reusing a forwarding decision after a route withdrawal / failover. A full
  snapshot generation transition assigns `self.validation` directly through
  `refresh_runtime_snapshot` / reconcile `apply_snapshot` and is intentionally
  NOT gated here, so a legitimate config-transition reset still lands.
- **Persist gate (M2).** An accepted bump now sets `persist_state`, so the
  on-disk `status.last_fib_generation` + `snapshot.fib_generation` advance
  with the bump. Previously they were mutated in RAM only, so a route-only
  bump to gen N left the persisted state at gen N-1 and a helper/host restart
  booted from a stale FIB generation the control plane already considered
  applied.

Validation (`server/tests.rs`): `bump_fib_generation_rejects_wrong_protocol_version`
(H4 — fail-on-revert), `bump_fib_generation_rejects_generation_rollback`
(H5 — fail-on-revert; status / stored snapshot / worker FIB gen all stay at
the last accepted value), and `bump_fib_generation_persists_bumped_generation`
(M2 — fail-on-revert; the persisted state a restart boots from carries the
bumped generation).

## apply_snapshot generation monotonicity (#5169)

The #3767 H5 gate covered only the lightweight `bump_fib` verb. The FULL
`apply_snapshot` handler (`server/handlers/snapshot.rs::apply`) published the
incoming `(generation, fib_generation)` pair VERBATIM into
`status.last_snapshot_generation` / `status.last_fib_generation` (and, on the
armed legs, into `ValidationState` via `refresh_runtime_snapshot` / reconcile)
with NO monotonicity gate. Because flow-cache validation is equality based on
the WHOLE pair (`entry.stamp.config_generation != lookup.config_generation ||
entry.stamp.fib_generation != lookup.fib_generation` in `flow_cache.rs`), a
REUSED / ROLLED-BACK pair equal to a prior published pair makes the cache
entries that a later generation logically invalidated MATCH validation again —
reviving a lazily-unevicted cached ALLOW after the config/route that authorized
it was withdrawn. That is a fail-OPEN, the exact defect #3767 H5 closed for
`bump_fib`, left open on the full path.

- **Pair-monotonicity gate (#5169).** The handler now refuses a full apply
  whose `(generation, fib_generation)` pair is STRICTLY LESS than (rolls back
  below) the currently-published `(last_snapshot_generation,
  last_fib_generation)` pair: admit iff `generation > cur_generation` OR
  (`generation == cur_generation` AND `fib_generation >= cur_fib_generation`).
  The Go control plane assigns `generation` from a monotone commit counter
  (`Manager.bumpGeneration`, only ever ++, never resets) and `fib_generation`
  from the monotone shim FIB counter (`readFIBGeneration`), so this admits every
  legitimate transition — a full apply advancing config (any fib; a strictly
  greater config value was, under this same guard, never published, so no
  stamped entry can equality-match it), a route-only overlay advancing fib with
  config reused, AND an EXACT-EQUAL re-apply — and refuses only a SUPERSEDED
  (strictly-less) pair: a config rollback (`generation < cur`) or a fib rollback
  under a reused config (`generation == cur && fib_generation < cur_fib`). Both
  are the revival fail-open. Exact-equal is admitted because it revives nothing
  (an equal pair equality-matches only the CURRENT published pair, whose cache
  entries are already valid), and refusing it would break the #4036
  "timeout-but-landed" IDEMPOTENT RETRY: the partial-republish Go paths
  (`UpdatePolicyScheduleState`, `PublishRouteOverlaySnapshot`,
  `retryDeferredWorkerArmLocked`; an earlier revision listed `Compile`, which
  bumps the generation inline and never reuses one, #9520)
  commit `m.generation` only on Go-observed success and do not consult
  `lastStatus.LastSnapshotGeneration`, so a timed-out-but-landed apply of gen G
  leaves `m.generation` at G-1 and the retry re-sends the IDENTICAL (G, fib)
  pair, which must be ACKed ok rather than fail-closed into a non-converging
  loop. This is the exact `<`-not-`<=` semantics `bump_fib` already uses
  (`Coordinator::bump_fib_generation` refuses a strictly-less fib, admits an
  equal one). The check compares against the last PUBLISHED pair in
  `guard.status` (not `ValidationState`: `config_generation` has no coordinator
  accessor and a disarmed apply advances `guard.status` but not
  `ValidationState`; `guard.status` is the authoritative published pair the
  armed flow-cache's `ValidationState` is derived from, so guard and cache
  agree). It is gated on a prior published snapshot (`guard.snapshot.is_some()`)
  so the first apply — no baseline, no cache entries to revive — always applies,
  matching `bump_fib` admitting the first bump against generation 0. Refusal is
  fail-CLOSED before any guard mutation, integrity preflight, or side effect:
  `ok = false`, nothing advances, nothing persists — the live prior forwarding /
  generation / flow-cache stay untouched (mirroring the #3766 / #3789
  capture-restore legs). The coordinator's `refresh_runtime_snapshot` /
  reconcile still assign `self.validation` directly and remain intentionally
  ungated at the coordinator layer; the monotonicity invariant for the full path
  is now enforced ONE layer up, at the handler.

Validation (`server/tests.rs`): `apply_snapshot_rejects_generation_rollback_5169`
(fail-on-revert; a strictly-less CONFIG rollback is refused — published pair,
stored snapshot, and persisted state all stay at the last accepted generation;
asserts the flow-cache revival is prevented because the published pair never
rolls back to the stale entry's stamp), `apply_snapshot_rejects_fib_rollback_5169`
(fail-on-revert; the second rollback axis — a strictly-less FIB under a reused
config is refused), `apply_snapshot_admits_generation_reuse_5169` (an exact-equal
re-apply is ADMITTED — the #4036 idempotent-retry path),
`apply_snapshot_monotonic_config_advance_applies_5169` (a config advance still
applies), and `apply_snapshot_fib_only_advance_admitted_5169` (a fib-only advance
with config reused is admitted, guarding against an over-strict gate that would
break route-only overlays).

## Content identity for a reused generation (#9520)

The #5169 gate admits an exact-equal pair because it "revives nothing". That
holds only when the CONTENT is equal too. The republish paths above rebuild
their content before a retry (routes, policy-scheduler bits), so a retry after a
timeout-but-landed apply can carry different content at the landed generation.
Flow-cache entries are stamped with the pair, and session policy stamps and the
#8356 re-derivation with the config generation alone, so admitting that retry
left every decision made for the landed content fresh.

- **Wire digest.** Every `apply_snapshot` carries `content_digest`
  (`ConfigSnapshot.ContentDigest`, snapshot protocol v15): hex SHA-256 from Go's
  `snapshotContentHash`, which excludes `generation`, `fib_generation`,
  `generated_at`, the raw `config` (the helper never reads it) and the digest
  itself. `requestApplySnapshotLocked` (`pkg/dataplane/userspace`) is the only
  send site, and it stamps the digest over the exact struct it sends.
- **Helper gate.** `server/handlers/snapshot.rs::apply` refuses, before any
  mutation, an apply whose generation equals the installed one when the digests
  differ or either is empty, at ANY fib. A `(G, F' > F)` apply passes #5169 as a
  fib advance, but the generation-only policy stamp makes different content
  there as unsafe as at `(G, F)`; the same content at an advanced fib is still
  admitted. The error starts with `SNAPSHOT_CONTENT_CONFLICT_PREFIX`
  (`protocol/control.rs`). `update_fabrics` and `update_neighbors` clear the
  installed digest when they change enforced content, so a same-generation
  replay of the older full apply is refused as well.
- **Go reaction.** Only that refusal proves the helper holds the generation, so
  `requestApplySnapshotLocked` consumes it (raises `m.generation` to it) and
  republishes once on the next generation, and every caller commits the
  generation actually sent. No other failure moves `m.generation` (#5134). The
  retry is skipped once `BeginControlShutdown` has latched.
- **Unknown outcomes.** A failure other than an in-band refusal may have landed,
  so it marks the helper's content unknown until an apply succeeds. While it is
  marked, the publish shortcuts that trust Go's bookkeeping stand down: the
  route-overlay content-hash dedup, and `syncSnapshotLocked`'s hash dedup and
  generation-only catch-up. Without that, content B landed by a lost response
  stays enforced when the desired content reverts to A, because A's hash still
  matches `m.lastSnapshotHash`.

The published generation then advances, so the flow cache misses and the #8356
re-derivation re-asks policy for every session stamped under the landed content.
An identical, non-empty digest at the same generation (the #4036 idempotent
retry) is still ACKed, and `>=` was not tightened.

Validation: the `_9520` cells in `server/tests.rs` and
`pkg/dataplane/userspace/apply_snapshot_identity_9520_test.go`.

## Recommended Next Step

Implement Phase 1 next:

- extract cached-hit execution into one helper

That is the next change most likely to reduce packet-loop complexity without
changing flow-cache behavior.
