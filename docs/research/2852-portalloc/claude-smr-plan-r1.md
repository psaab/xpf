# Claude SMR hostile plan review — #2852 r1

Verdict: **PLAN-NEEDS-MINOR** (architecture is sound; four refinements
required before PLAN-READY-pending-lab). Not a rubber stamp — the design
has one under-specified correctness invariant, one unresolved #3011
equivalence claim, and a churn/sequencing improvement the plan should
adopt.

## What the plan gets right (verified, not assumed)
- Bottleneck is real and correctly located: one `Mutex` per pool
  (allocator.rs:166), held for the whole `allocate_translation`
  (336–475), shared across all workers via
  `Arc<ArcSwap<ForwardingState>>` → `pool_allocator` →
  `Arc<PortAllocatorShared>`. Confirmed.
- Correctly downgrades the issue's framing: it's a per-NEW-FLOW lock, not
  per-packet (poll_descriptor:815 session-miss gate). The PLAN-KILL line
  and the mandatory lab gate are the honest disposition. Agreed.
- Address-persistence cannot break (sticky_pool_index is lock-free and
  untouched). Reverse-NAT is session-table-resolved, not allocator-
  resolved. Both correct.
- HA-reservation correction is right and important: synced tuples are not
  reserved today; keeping that out of scope is correct.

## Findings (must fold)

### F1 (MAJOR-leaning, correctness) — the bit-clear must be gated by the record removal, or ABA reopens
The plan says "free = atomic clear" and "clear the bitmap bit
(lock-free)". As written this is ambiguous and, if implemented as an
*unconditional* clear, is WRONG. The "bit IS the ownership token,
ABA-safe" claim only holds if the bit is cleared **iff** the owning
record removal succeeded under its shard lock:

- Non-persistent: `release_flow` must remove `live_by_flow[flow]` under
  the flow-shard lock and clear the bit ONLY when that removal returned
  the matching translated tuple. A duplicate/late `release_flow` for the
  same 5-tuple finds the entry already gone and MUST NOT clear the bit —
  otherwise it clears a port a *different* flow (C) has since CAS-claimed
  at the same offset → silent PAT double-allocation. (This is exactly the
  hazard `existing.translated != translated` guards against today at
  allocator.rs:623/664; the sharded design must keep that compare AND
  make the bit-clear conditional on the successful, matching removal.)
- Persistent: the bit is owned by the LEASE, shared by many flows. An
  individual persistent `release_flow` decrements `active_flows` and MUST
  NOT clear the bit. The bit clears ONLY at lease teardown
  (`release_expired_lease_locked` / rollback `remove_lease`) under the
  persist-shard lock with `active_flows == 0` — mirroring today's
  `release_translated_locked` call sites.

Action: state as a hard invariant — *"the occupancy bit is cleared
exactly once, by the code path that successfully removes the owning
`live_by_flow` entry (non-persistent) or tears down the lease
(persistent), under that record's shard lock; never unconditionally."*
Add a regression test: double-release and stale-tuple-release must NOT
free a port owned by an unrelated live flow.

### F2 (MINOR→MAJOR depending on lab, correctness) — #3011 cursor-wrap is NOT proven equivalent to the FIFO recycle queue
The plan proposes deleting `recycled_ports_by_addr` and relying on the
advancing cursor. But today's cursor is a **one-shot sweep 0..range**
(allocator.rs:502 `if next_offset >= range break`), after which all reuse
comes from the FIFO `recycled_ports_by_addr` (drained front-first, #3011)
— strict oldest-freed-first. A **wrapping** bitmap cursor does NOT
reproduce this: a port freed just *ahead* of the cursor is re-probed
almost immediately on the next allocate, while a port freed just *behind*
waits a full wrap. Reuse latency becomes position-dependent, not
oldest-first — a #3011 regression (a just-freed port can be handed back
inside the upstream's 2MSL/TIME_WAIT window). The plan's Q3 flags this
but the §5.2 body still asserts the cursor "replaces" the queue.

Action: do NOT delete the recycle mechanism on the strength of the
cursor. Either (a) keep a **lock-free recycle ring** (e.g. an MPMC ring
or a per-address `SegQueue`) drained before forward-probing, preserving
FIFO, OR (b) make F2 a lab-gated decision with a #3011-specific
regression test (free N ports, assert the just-freed port is the LAST
reused). Default to (a) unless the lab proves (b) safe. Downgrade the
§5.2 claim from "replaces" to "candidate, gated by F2".

### F3 (design/sequencing, reduces churn — the strongest improvement) — phase the work: lock-free bitmap FIRST, map sharding ONLY if measurement still shows contention
The plan bundles two independent changes. They are not equally
load-bearing. Decompose the critical section:
1. port claim (cursor + `owner_by_translated` insert + `addr_index`
   insert) — the bulk of the locked work and the genuinely-shared
   resource;
2. `live_by_flow` / persistent map insert — a couple of hash ops.

Making (1) lock-free (the bitmap) removes most of the contention on its
own. Sharding the maps (2) only removes the residual map-insert
contention. So the honest hierarchy is: **Tier 1 = lock-free bitmap
(essential), Tier 2 = map sharding (incremental)**. Conversely, sharding
the maps WITHOUT the lock-free claim (the rejected "Option C-minus")
buys almost nothing, because the port claim stays serialized — the plan
should say this explicitly (it currently dismisses C-minus without the
reason).

Recommended restructure: **Phase 1** = lock-free per-address bitmap claim
+ keep a SINGLE (now tiny) mutex around just the map inserts/removes;
measure on the lab. **Phase 2** = shard the maps, gated on Phase-1
measurement still showing the residual mutex as a bottleneck. This
roughly halves the Phase-1 churn (no shard-key correctness surface, no
two-lock ordered path) while capturing the dominant win, and it directly
de-risks the churn-vs-win PLAN-KILL axis. The two-lock persistent
ordering complexity only enters at Phase 2 if justified.

### F4 (MINOR, correctness) — global cap needs an explicit reserve/rollback discipline
With sharded (or even single-mutex-but-separate) `live_by_flow`, the
exact global cap via `AtomicUsize` needs a defined protocol:
`fetch_add` to reserve a slot, then on any subsequent failure (port
claim exhaustion, lease-table pressure) `fetch_sub` to release the
reservation; and the over-cap check must be a CAS/`fetch_add`-then-
compare-then-rollback, not a racy load-then-add. Otherwise the cap
either leaks slots (count drifts up, premature exhaustion) or admits
over-cap. Specify it.

## Minor / confirm
- Bitmap memory: full default range (1024–65535) ≈ 8 KiB/address; a /24
  pool ≈ 2 MiB. Bounded and acceptable; note it and the
  large-address-pool case explicitly (Q2).
- `snapshot.used_ports`: prefer a maintained `AtomicU64` over per-poll
  popcount of large bitmaps (Q6) — cheap and avoids scanning MiBs at
  1/s.
- Re-expressing ~185 white-box tests is the real cost; F3 phasing
  reduces the Phase-1 slice of it.

## Disposition
Fold F1–F4 → the plan is **PLAN-READY-pending-lab**: architecture firm,
but merge is gated on the loss-cluster new-flow-ceiling measurement (and
PLAN-KILL remains the correct outcome if that measurement shows no win).
