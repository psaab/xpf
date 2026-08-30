# #6979 F6 — the residual half: two source-NAT pools, one address, two
# occupancy domains

## What the finding says, and what actually reproduces

F6 as filed has two halves. The **key-collapse** half landed in #7858
(`carry_renamed_pool_reservations`). This plan covers the other one:

> A **match-only** edit therefore strands a reservation in an allocator that can
> no longer match the flow, while the rule that now owns it is free to reissue
> the tuple.

Before designing anything, three probes were driven against `origin/master`
(`f5402ea38`). Pools are single-address (`203.0.113.1`) with a single-port range
(`20000-20000`) so a duplicate is unambiguous.

| probe | construction | result at master |
|---|---|---|
| **P1** | pools `a` and `b` both `[203.0.113.1]`; flow 1 matches r1 → `a`; **match-only edit** narrows r1's `source-address` so flow 2 matches r2 | flow 1 `203.0.113.1:20000`, flow 2 **`203.0.113.1:20000`** — the identical reverse identity, while flow 1's reservation is still live in `a` |
| **P2** | the same two pools, **no edit** — r1 matches `10.0.0.0/24`, r2 matches `10.1.0.0/24` | flow 1 `203.0.113.1:20000`, flow 2 **`203.0.113.1:20000`** — the same duplicate |
| **P3** | ONE pool, the same match-only edit | second flow → `Unavailable(AllocatorExhausted)`. The carried-over allocator still holds the tuple and refuses to reissue it |

**P3 is the correction that decides the design.** The key's ignorance of match
criteria and zone scope is, on its own, *harmless*: carryover is keyed on
`(pool_name, addresses, range)`, a match-only edit leaves all three untouched,
the allocator is reused by `Arc`, and its live reservation keeps protecting its
tuple. Adding match criteria to the key — F6's own suggestion — would have
broken exactly that (the stranding `drain_allocator_key`/#7717 exists to
prevent) and fixed nothing.

**P2 is the defect.** The edit is not load-bearing — the duplicate needs no edit
at all. What produces it is that **two distinct allocator keys can cover the
same pool address**, so one address has two independent occupancy bitmaps and
each is blind to the other's reservations. The match-only edit is only the
mechanism that moves a flow from one domain to the other.

The comment #7858 left on `carry_renamed_pool_reservations` names the hazard
exactly — "keeping them apart would give one address two independent occupancy
domains, which is the collision the key exists to prevent" — while two
*differently named* pools on one address are precisely that state, live on
master.

## Severity, stated honestly

- The config is **rejected at strict commit** by the Go #5144 gate
  (`validateNATPoolExternalTupleOverlapStrict`, on ADDRESS overlap alone — it
  does not consult port ranges). It reaches the dataplane only from a tolerated
  lenient load, a peer sync, an older control plane, or a handcrafted snapshot —
  the identical population #6812's aggregate-budget gate exists for.
- The consequence is a duplicate translated identity: two live flows sharing one
  `(pool address, port)` toward the same remote, whose replies the reverse index
  cannot disambiguate. Mis-delivery, not a leak.
- What F6's text calls "protection in the wrong place" is real but benign on a
  valid config: teardown sweeps every pool rule without running its matcher, so
  a stranded reservation is still released. P3 measures that directly. **This
  change does not claim to fix a stranded release, because there is not one.**

## Design — narrow MINTING, leave RETENTION alone

The key is **not touched at all**. `SourceNatPoolAllocatorKey`,
`allocator_key()` and `drain_allocator_key()` are byte-identical, so every
allocator in a running process carries over across the upgrade exactly as it
does today and the first reconcile after upgrade strands nothing. That is the
whole upgrade story, and it is this short *because* the key is untouched.

What narrows is minting:

1. **`wire_overlap_peers` (apply).** Each pool-mode rule records the peer pool
   allocators — a *different allocator instance* — whose pool covers one or more
   of its own addresses, with the index each shared address has in that peer.
   The address relation is static, so it is resolved once; the occupancy is not,
   so it is read at mint time. Empty for every rule of a config with no
   overlapping pools.
2. **`reject_peer_owned_identity` (mint).** At the three PAT allocation sites,
   an allocation that lands on an identity a peer already owns is rolled back
   and returned as `Unavailable(PoolPeerAddressOverlap)` instead of published.
3. The check runs **after** the allocation, deliberately. Check-then-mint has a
   window: two workers minting from two peer allocators can both see the tuple
   free and both take it. Mint-then-check closes it — the claiming `fetch_or`
   runs before either looks, so at least one sees the other and rolls back, and
   if they see each other simultaneously BOTH roll back. Worst case a refused
   flow, never a published duplicate, with no cross-allocator lock.
4. That argument needs a **`SeqCst` fence** between the claiming `fetch_or` and
   the peer read, on both sides. The two workers store to DIFFERENT bitmaps and
   then load the other's — the store-buffer litmus test — which the bitmap's
   existing `fetch_or(AcqRel)` / `load(Acquire)` pair does not forbid. Without
   it both could observe the peer free and both publish, which is the defect.
   The fence sits after the empty-peer early-out, so no config a strict commit
   accepts executes it, and the doc comment states plainly that no test can
   distinguish its presence from its absence.

Cost on the hot path for every config a strict commit accepts: one
`Vec::is_empty`.

### Rejected alternatives

- **Add match criteria / zone to the key.** The finding's own suggestion. P3
  shows it fixes nothing and it breaks carryover for every match-only edit.
- **Drop `pool_name` from the key.** Merges only *exactly* equal address sets,
  leaves partial overlap open, and decommissions #7858's fixtures.
- **Merge the two allocators.** Not available: `occupancy` is a `Vec` indexed by
  pool-address POSITION, so pools whose address lists differ cannot share one —
  the same reason #6765 re-seeds instead of loosening the key.
- **Quarantine the later pool** (fail it closed at apply, drain its allocator,
  the #7717 shape). Built and measured first; **rejected on evidence.** It reds
  16 merged tests, and the reason is not fixture noise: #6211's entire pass-1
  narrowing exists because "two rules with OVERLAPPING pool addresses in
  SEPARATE allocators" is a state the standby must resolve correctly
  (`overlapping_pool_rules_6211`), and #6876's release sweep frees from every
  allocator for the same reason. Failing such a pool closed inverts two merged
  designs to fix one duplicate. The mint-time check gets the same protection
  while every pool keeps translating.
- **Carry the peer's live flows into this allocator.** Would also work at apply
  time, but it is the exact cross-pollination
  `coexisting_pools_sharing_an_address_do_not_cross_pollinate_6979` (#7858)
  forbids, and it is stale the moment either pool mints again.

## What this does NOT cover — corrected after Codex round 1

The first draft called the address-only path "the residual". That understated
it. There are THREE separate ROUTES to the same duplicate that this change does
not close, and calling them a residual rather than uncovered routes is the kind
of hedge that reads as a limitation when it is a gap:

- **address-only** (`port no-translation`, port-less protocols) mints an
  `address_only_owners` reverse-identity token and claims NO occupancy bit, so
  it is invisible to this query in both directions — an A address-only flow
  preserving `X:P` does not stop a B PAT mint of `X:P`;
- **the HA synced reserve** (`source/synced.rs`) calls `reserve_flow` on one
  allocator directly and never reaches the check, so an imported flow can take a
  tuple a LOCAL flow already owns in a peer pool. Sequential, no race needed;
- **NAT64** prefixes are their own allocators (`nat64.rs`) and are not indexed.

All three are filed as #8115, with the design constraint each carries — folding
them in would have made a bounded, measured change open-ended.

Also uncovered, and pre-existing rather than introduced here: a pool whose own
configured members repeat one address self-collides, because expansion does not
deduplicate and each position has its own bitmap. The PEER half of that IS
fixed — every position is recorded.

Pinned rather than fixed: the deterministic-v4 refusal costs the colliding
subscriber its whole BLOCK, not one port, because `allocate_deterministic_v4`
restarts its scan at the block start and the rollback frees the bit without
recycling. The retry that would step past it is not expressible with the current
allocator API (allocation is idempotent per flow key, so a second call returns
the same tuple, and there is no public way to hold the rejected port claimed
across retries). The direction is the project's stated one — at master that
subscriber receives a duplicate identity instead — and
`a_deterministic_collision_refuses_the_subscriber_6979` pins it with a block
size of 4, so "the block was full" cannot be mistaken for the cause.

The round-robin refused flow is dropped and counted, not retried: the monotonic
cursor has already advanced past the colliding port, so the pool's next flow
translates normally
(`an_overlapping_pool_still_mints_an_identity_its_peer_does_not_own_6979`).

## Files

| file | change |
|---|---|
| `userspace-dp/src/nat/allocator.rs` | `holds_port` (production query, `debug_is_port_occupied` becomes its alias), `same_allocator` |
| `userspace-dp/src/nat/source/failure.rs` | `PoolPeerAddressOverlap` + exception string |
| `userspace-dp/src/nat/source/mod.rs` | the `overlap_owners` field and the `wire_overlap_peers` call at the end of `resolve_pool_allocators` |
| `userspace-dp/src/nat/source/overlap.rs` | NEW — `PoolAddressOwners`, `peer_holds_identity`, `wire_overlap_peers`. A sibling module rather than more `mod.rs`, because #6874's touched-file modularity gate reds a file this change would push past the 1500 LOC [WATCH] floor |
| `userspace-dp/src/nat/source/match_rules.rs` | `reject_peer_owned_identity` at the three PAT mint sites |
| `userspace-dp/src/nat/tests_pool_overlap_6979.rs` | new cells |
| `userspace-dp/src/FEATURES.md`, `docs/userspace-dataplane-architecture.md`, `docs/log/6979.md` | docs |

## Test strategy

| cell | binds | fires on |
|---|---|---|
| `overlapping_pools_do_not_both_mint_one_identity_6979` | P2 verbatim — the second pool must not publish the identity the first holds | deleting the mint check |
| `a_match_only_edit_keeps_the_reservation_and_mints_no_second_identity_6979` | P1, plus the carryover a wider key would break | deleting the check, OR widening the key |
| `an_overlapping_pool_still_mints_an_identity_its_peer_does_not_own_6979` | the pool is not failed closed; only the duplicate is refused | any quarantine-shaped fix |
| `two_rules_naming_one_pool_are_not_peers_6979` | peer identity is the ALLOCATOR, not the key or the address | comparing keys/addresses — every mint on a shared pool would then refuse |
| `overlapping_v6_pools_...` / `overlapping_deterministic_pools_...` | the v6 and deterministic-v4 arms are separate call sites | deleting either one's check — measured, each escapes the entire v4 suite |
| `a_peer_holding_the_identity_at_a_duplicate_position_is_still_seen_6979` | every position is indexed, not `.position()`'s first | recording only the first position. Its first draft was VACUOUS and the mutation escaped it |
| `a_deterministic_collision_refuses_the_subscriber_6979` | LIMITATION PIN — the refusal costs the whole block | a future fix that steps to a free sibling port, which must update the docs with it |
| `disjoint_pools_are_not_peers_6979` | control — the empty-`Vec` fast path | a peer relation not keyed on a shared address |
| `a_refused_mint_leaves_no_reservation_behind_6979` | the rollback | returning the failure without rolling back |
| `the_identity_is_mintable_again_once_the_peer_releases_it_6979` | the refusal is per-IDENTITY, not per-address or per-peer-liveness | a coarser predicate |
