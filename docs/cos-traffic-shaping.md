# Class of Service — Hierarchical Egress Traffic Shaping

Userspace-only implementation in the Rust AF_XDP forwarding plane.

> Looking for the WAN smart-queueing (SQM) operator recipe — the
> one-knob `shaping-rate` setup that buys CAKE-class shaping + per-flow
> fairness on an uplink? See [`docs/cos-wan-sqm.md`](cos-wan-sqm.md)
> (#1828). This file is the engine design doc.

## Scope and Non-Goals

**This is:**
- userspace-only
- egress-only
- a hierarchical shaper with the service tree `root(interface) -> reservation -> container`
- protocol oblivious at the scheduling layer
- work-conserving across reservations
- timer-wheel-driven at the reservation wakeup level rather than per-packet pacing
- designed to support many cores without introducing a shaping bypass
- average-rate shaping with bounded bursts, not wire-level pacing

**This is not:**
- an ingress policer
- perfect packet pacing
- a full Junos CoS implementation
- per-flow fair queueing in the first pass
- a cure for a single hot reservation saturating the CPU of its owning scheduler

## Problem Statement

The current flat policer drops excess traffic on arrival. It does not provide:

- egress queueing
- work-conserving surplus sharing
- class-level isolation under overload
- robust behavior when traffic lands unevenly across workers

What we need instead is a real egress shaper that:

- buffers packets
- transmits under hierarchical budgets
- remains protocol oblivious
- shares unused bandwidth across configured classes through their reservations
- scales across many cores without multiplying guarantees by worker count

The motivating cases remain:

- one elephant versus one hundred mice
- one hundred elephants versus one mouse
- one hundred elephants versus one hundred mice
- all of the above with uneven hashing across workers

Important first-pass constraint:

- the first implementation should use a single FIFO queue per container
- weighted scheduling happens among reservations
- it does **not** attempt micro-flow fairness inside a container

That means the first pass protects configured classes from each other much
better than it protects individual flows that share the same container.

## Design Goals

1. **Hierarchical**: every transmitted byte is accounted against:
   - the interface root
   - one reservation node
   - one container node

2. **Work-conserving**: idle reservations do not waste interface bandwidth.

3. **Protocol-oblivious**: scheduling decisions depend on queue assignment,
   packet size, and queue state, not on TCP/UDP/ESP/GRE/ICMP semantics.

4. **No fast-path bypass**: every packet that egresses a shaped interface
   follows the same logical path:
   `classify -> enqueue -> admit -> schedule -> transmit`

5. **Adversarial resilience at class granularity**: elephants in one configured
   class should not destroy latency and throughput for other classes.

6. **Many-core support**: guarantees must remain correct across workers, and
   the behavior of a reservation must not silently multiply with worker count.

7. **Low CPU cost**: the hot path should remain O(1) expected per packet with
   bounded contention on shared state and without busy-rescanning sleeping
   reservations.

8. **Incremental complexity**: the baseline design should be implementable
   without per-flow fair queueing. Finer-grained fairness can be a later
   extension if class-level FIFO proves insufficient.

## Hierarchical Service Model

The service tree is:

```text
Interface root
  -> reservation
    -> container
```

### Root Node

The root node represents the shaped interface.

Responsibilities:

- enforce the interface shaping-rate and burst
- cap aggregate transmitted bytes
- track total queued bytes and frames
- enforce interface-level UMEM budget

### Reservation Node

A reservation node is the intermediate scheduling object.

Conceptually, this is where the service guarantee lives.

Responsibilities:

- own the class reservation (`transmit-rate`, optional ceiling, priority, weight)
- participate in the scheduler's guarantee and surplus phases
- own reservation-level buffer limits and admission policy
- define how much service the attached containers may consume

In a Junos-like model, this is closest to the scheduler attached to a
forwarding class on a shaped interface.

### Container Node

A container node is the leaf queue that actually holds packets.

First-pass responsibilities:

- hold queued packets
- preserve FIFO ordering
- enforce container byte/frame limits
- provide the packet dequeued when its reservation is selected

In the first pass, a container is intentionally simple:

- one FIFO queue
- no per-flow buckets
- no micro-flow DRR
- no flow-key-based fairness accounting

In the first pass, each reservation has exactly one container:

```text
containers_per_reservation = 1
```

So the `reservation -> container` split is structural and future-proofing, not
an immediate claim that one reservation already contains multiple independently
scheduled queues.

### Invariants

These invariants define the design:

1. Every packet on a shaped interface follows one logical path:
   `classify -> map to reservation/container -> enqueue -> admit -> schedule -> transmit`

2. `CIR` is not a fast path or a separate queue. It is only the guaranteed
   service budget of a reservation node inside the same scheduler.

3. A packet may transmit only if:
   - the root has budget
   - the selected reservation has budget for the active phase
   - the selected container has a dequeuable packet

4. A container belongs to exactly one scheduler owner at a time.

5. Session hits, generated traffic, and cross-binding forwards do not bypass
   shaping on a shaped interface.

6. In the first pass, fairness stops at the container boundary. Packets within
   one container are FIFO, not micro-flow scheduled.

## Service Semantics

### Guaranteed Service

- A backlogged reservation receives service up to its configured
  `transmit-rate` over windows larger than one scheduling cycle plus burst
  horizon.
- Reservation guarantees hold regardless of RSS placement because the
  reservation budget is shared and authoritative.

### Opportunistic Service

- Surplus bandwidth above active reservation guarantees is distributed by
  reservation priority and same-priority weighted DWRR.
- `transmit-rate exact` reservations never receive surplus by default.
  Add `surplus-sharing` (#915) on the scheduler to opt the queue into
  surplus-phase participation while keeping its per-queue rate as a
  guarantee floor.

#### `transmit-rate` / `shaping-rate` value forms (#4228 Gap 2)

`transmit-rate` accepts three mutually-exclusive Junos value forms, each
optionally followed by `exact`:

- an **absolute bandwidth** — `transmit-rate 3g` (enforced);
- **`percent <n>`** — `transmit-rate percent 30` (a share of the bound
  interface's rate); and
- **`remainder`** — `transmit-rate remainder` (a share of the leftover
  bandwidth, resolved in #6846 — see below).

`shaping-rate` (traffic-control-profiles) accepts an absolute bandwidth or
`shaping-rate percent <n>`. These forms are accepted so imported vSRX
configs commit unchanged (the percent form is the most common Junos
scheduler idiom).

**Percent resolution (#4228 Gap 2 — now ENFORCED).** Both percent forms
resolve to an absolute byte/sec rate, mirroring the `buffer-size percent`
resolution exactly (same `ceil` rounding, same clamp to `[1, MaxUint64]`):

- **`transmit-rate percent <n>`** resolves PER INTERFACE, in the Rust
  `forwarding_build::cos` builder, against the bound interface's root
  shaping-rate (`cos_shaping_rate_bytes_per_sec`). A named scheduler mapped
  onto interfaces of different shaping rates materializes a *different*
  absolute rate on each — which is why the percent is carried to the
  dataplane (not pre-resolved) on the shared scheduler snapshot. A resolved
  percent drives the queue guarantee, surplus weight, and token bucket just
  like an absolute `transmit-rate`. Residual inert cases: a scheduler not
  bound (via a scheduler-map) to an interface with a root shaping-rate, or an
  interface with a transparent root (no shaping-rate) — there is no base to
  resolve against, so the queue gets no explicit rate (a `ValidateConfig`
  advisory flags the unbound case).
- **`shaping-rate percent <n>`** (traffic-control-profiles) resolves in the
  Go compiler (`resolveCoSTrafficControlProfiles`) against the bound
  interface's configured line rate (`set interfaces <if> speed <rate>` or
  `bandwidth`) — Junos resolves shaping-rate percent against the interface
  speed. The resolved absolute rate is folded into the unit's root shaper
  exactly as an absolute `shaping-rate` would be. Resolution is per-binding:
  the same profile bound to interfaces of different speeds folds a different
  rate onto each. If the interface has no configured speed/bandwidth the
  percent cannot resolve and the unit is left unshaped; a per-binding
  `ValidateConfig` advisory names the interface and the fix.

**Remainder resolution (#6846 — now ENFORCED).** `transmit-rate remainder`
resolves in the same Rust builder, but it cannot use the per-scheduler path
above: it means *"whatever the interface's shaping rate has left after every
sibling queue on the scheduler-map has resolved"*, so it is a function of the
SIBLING SET rather than of the scheduler. `cos_remainder_rate_bytes` therefore
runs as a **pre-pass, once per interface, before any queue is materialized** —
computing it inside the materialization loop would give each remainder queue a
different *partial* sibling set depending on map iteration order.

Rules, each of which is load-bearing:

- the sibling sum counts **resolved** siblings only. A sibling that is itself
  `remainder` contributes **zero** (it claims the leftover, not a share of it);
  a sibling with no rate contributes zero (no guarantee to subtract). A
  scheduler carrying *both* an absolute rate and `remainder` — reachable only
  on the lenient load / peer-sync path, since the strict gate rejects it —
  resolves via the absolute rate and is **not** counted as a remainder queue,
  so the pre-pass and the main path agree about which queues those are.
- a **percent** sibling is counted at the value the dataplane gives it, which
  means **ceiled**, clamped to at least 1, and zero outside `(0,100]`. The
  control-plane advisory computes the same leftover independently — there is no
  shared representation between Go and Rust — so the rounding rule is part of
  the contract, not an implementation detail. Truncating on one side makes its
  leftover larger and suppresses the advisory on a shape the dataplane declines:
  `percent 33.3333333` + `percent 66.6666667` on a 1 Gbps shape is 124_999_999
  truncated against 125_000_001 ceiled, over a 125_000_000 base.
- the leftover **splits equally, flooring**, across remainder-marked queues.
  An indivisible leftover loses up to `count − 1` bytes/sec, which is noise
  against any shaping rate a remainder is meaningful on. A leftover *smaller*
  than the queue count floors to nothing, which is the zero case below rather
  than a rate. Ceiling would make
  the remainder queues jointly claim *more* than the leftover they were
  computed from; distributing the slack would make the result depend on which
  queues come first, reintroducing the map-order dependence the pre-pass
  exists to avoid.
- **a leftover of zero does NOT resolve.** Zero is the dataplane's sentinel
  for "unshaped/full bucket" (`types/cos.rs`), so resolving to it would set
  `guarantee_enabled` on a queue the token bucket then treats as uncapped —
  promoting it into guarantee service rather than starving it. It does not take
  over-subscription to get there: `percent 60` + `percent 40` + `remainder` is
  an ordinary shape and leaves exactly nothing, and so does any leftover that
  floors to nothing. So the form stays inert, the queue keeps the historical
  no-guarantee fallback, and `ValidateConfig` warns with wording that names
  WHICH of the two reasons applies — no shaping base, or siblings leaving no
  usable leftover — because the fix differs.

**Temporal resolution (#6846 — now ENFORCED).** `buffer-size temporal <us>`
sizes the queue by drain time, so it converts against the queue's **drain
rate** — strictly after the rate, including after `remainder` when both are set
on one queue. That combination is **legal**: temporal is well defined once
remainder resolves, and rejecting a combination the model supports would break
valid Junos. Rounding and clamping mirror `buffer-size percent` exactly.

The drain rate is not the same thing as a *resolved* transmit-rate, and the
difference matters for the advisory. A queue with no guarantee of its own keeps
the historical fallback — the interface shaping-rate — so it still drains, and
a microsecond target against it still has a byte value. `buffer-size temporal`
therefore goes inert only where that fallback is itself zero: no absolute rate
on the scheduler **and** no scheduler-map binding to an interface with a root
shaping-rate. An unresolved `percent` or an unresolved `remainder` does **not**
make temporal inert.

**Still inert, and only here:**

- `transmit-rate remainder` with no usable leftover — either no shaping base at
  all (not bound via a scheduler-map to an interface with a root shaping-rate)
  or siblings leaving nothing after the floor. There is no bandwidth to take a
  remainder *of*, and no port speed is available to substitute: `InterfaceSnapshot`
  carries no link-speed field, and a zero shaping rate is already treated as
  "no usable CoS state".
- `buffer-size temporal` on a queue whose effective rate is **zero** — no
  absolute rate and no shaped binding. There is no drain speed to convert a
  microsecond target against.

Both advisories narrowed to exactly these cases in #6846 — an advisory that
keeps firing for configurations that now work teaches the operator to ignore
it. The narrowing is measured, not asserted:
`build_cos_state_temporal_converts_against_the_fallback_drain_rate` pins the
runtime fact the temporal advisory depends on, and
`TestRemainderAdvisoryTracksTheLeftover6846` pins the remainder one against the
Rust resolver cells it mirrors.

The commit gate still rejects garbage (`transmit-rate percent 150`,
`transmit-rate asd`) and a both-forms-set config (an absolute rate AND a
percent).

### First-Pass Fairness Boundary

This design is intentionally honest about what it does and does not solve.

It does help with:

- one elephant in `best-effort` versus mice in `expedited-forwarding`
- multiple busy low-priority classes contending for surplus
- uneven worker placement that would otherwise multiply class behavior

It does **not** fully solve:

- one elephant versus one hundred mice if they all land in the **same**
  container
- one sender opening many micro-flows inside one FIFO container

That is accepted in the first pass. The design should say so explicitly rather
than pretending class FIFO somehow gives micro-flow fairness.

## Unified Packet Path

Every packet that egresses a shaped interface follows:

```text
RX
  -> parse / route / session / NAT
  -> classify to forwarding class
  -> map class to reservation and container
  -> enqueue on the reservation/container owner
  -> reservation/container admission control
  -> if eligible now: runnable reservation
  -> else: reservation parked on timer wheel until eligible
  -> reservation scheduling
  -> transmit from selected container
  -> TX ring submission
```

This applies to:

- forwarded packets on session hit
- forwarded packets on session miss
- locally generated packets on a shaped interface
- cross-binding forwards targeting a shaped interface

Caching may avoid repeated classification work, but it may not bypass queue
admission or scheduling.

## Scheduler

There is one scheduler with two service phases. Both operate on
**reservations**, not on micro-flows.

### Phase 1: Guarantee Service

Purpose:

- satisfy reservation guarantees
- ensure every backlogged reservation with available guarantee budget makes
  forward progress

Rules:

1. Walk active reservations in rotating round-robin order.
2. Give each reservation a bounded `cir_quantum` per visit.
3. Within the selected reservation, dequeue from its container FIFO.
4. Charge:
   - root aggregate budget
   - reservation CIR budget

Recommended per-visit quantum:

```text
cir_quantum_bytes = clamp(
    reservation_cir_bytes_per_us * 100,
    mtu_bytes,
    32 * 1024
)
```

This keeps:

- low-rate reservations from being permanently postponed
- high-rate reservations from consuming the entire cycle
- queue-order bias from dominating service

### Phase 2: Surplus Service

Purpose:

- distribute bandwidth above active guarantees

Rules:

1. Scan reservations by priority.
2. The first priority level with eligible surplus demand wins the cycle's
   surplus service.
3. Within that level, use weighted DWRR across reservations.
4. Within the selected reservation, dequeue from its container FIFO.
5. Charge:
   - root aggregate budget
   - reservation surplus budget / ceiling

Strict priority applies only to surplus service.

The ceiling should be modeled as a reservation-level token bucket distinct from
the guarantee bucket. In other words:

- the guarantee phase spends the reservation's CIR bucket
- the surplus phase spends a separate ceiling/PIR bucket

That keeps "exact" and ceiling semantics explicit instead of treating surplus as
an unbounded borrow from the root.

### Same-Priority Weighted DWRR Across Reservations

Each reservation at a priority level has a persistent `surplus_deficit`.

Per DWRR round:

```text
for each active reservation at this priority:
  reservation.surplus_deficit += reservation.weight * round_quantum
  while reservation.surplus_deficit >= next_pkt_len and budget remains:
    dequeue packet from reservation.container
    reservation.surplus_deficit -= pkt_len
    charge root + reservation surplus budget
```

This gives stable weighted sharing among reservations without implying any
micro-flow logic inside a container.

## Deferred Eligibility and Timer Wheel

The scheduler needs a way to handle backlogged reservations that are
temporarily ineligible because the root or reservation bucket does not yet have
enough credit for the next packet.

Without that mechanism, the implementation falls into one of two bad choices:

- repeatedly rescan sleeping reservations and waste CPU, or
- approximate shaping with ad hoc sleeps that are not tied to the hierarchy

The design should therefore include a **timer wheel**, but at the correct
level:

- not one timer per packet
- not wire-level pacing
- not a bypass around the hierarchy
- a wakeup structure for **backlogged reservations/containers that need to be
  retried later**

### What the Timer Wheel Owns

The timer wheel should track reservation runtime state, not individual packets.

Each scheduler owner keeps:

- runnable reservation lists for the guarantee and surplus phases
- a per-shard timer wheel for reservations that are backlogged but currently
  ineligible

Each reservation runtime record needs fields like:

```text
reservation_runtime {
  runnable_now
  queued_bytes
  queued_frames
  next_wakeup_tick
  wheel_level
  wheel_slot
  wake_reason
  cir_deficit
  surplus_deficit
}
```

The container remains a FIFO queue. The timer wheel only decides when the
reservation should re-enter the runnable set.

### Wake Reasons

The first pass only needs a few wake reasons:

- root budget should have refilled enough for at least one MTU
- reservation CIR budget should have refilled enough for one MTU
- reservation ceiling/surplus budget should have refilled enough for one MTU
- lease age / idle return deadline for shard-local budget cache

That is enough to keep the scheduler from spinning on reservations that cannot
possibly send yet.

With shared parent budgets, wakeup time is only an estimate. A shard can wake
because the root budget should have refilled enough for one MTU, then lose the
actual lease race to another shard. That is acceptable as long as the wake path
rechecks eligibility and re-arms cheaply.

### Timer Wheel Shape

This should be a **per-shard** structure, not a global wheel shared by all
cores.

A concrete starting point:

```text
level 0: 256 slots * 50 us    = 12.8 ms horizon
level 1: 256 slots * 12.8 ms  = 3.2768 s horizon
```

That covers the common shaping wakeups and short idle deadlines without
requiring a heap on the hot path. Longer deadlines such as HA/config drain
timeouts can stay on a separate coarse timer path if needed.

The wheel tick should match shaping granularity, not attempt packet pacing.

### Tick Advance

The wheel should advance at the start of each scheduler poll cycle using a
monotonic clock.

In practice, that means `drain_shaped_tx()` or the equivalent shard-local
scheduler loop advances the wheel before it services runnable reservations.
Tick resolution is therefore bounded by scheduler poll frequency, not by a
dedicated timer interrupt.

### Enqueue and Rearm Rules

On enqueue to an empty container:

1. classify packet to reservation/container
2. append to container FIFO
3. if the reservation is currently eligible, add it to the runnable set
4. otherwise compute the earliest eligible tick and park it on the timer wheel

On dequeue when backlog remains:

1. if root + reservation budget still allow service, keep the reservation
   runnable
2. if backlog remains but service budget is exhausted, compute the next wakeup
   and re-arm it on the wheel

On timer-wheel advance:

1. move due reservations from the current slot into the runnable set
2. recheck eligibility
3. if still not eligible because the shared parent budget has not been leased
   yet, recompute and re-arm

The important point is that the wheel schedules **reservation retries**, not
packet transmit timestamps.

Wheel advance is one 50 µs tick per loop iteration. After a long
per-worker idle period the first shaped drain would otherwise replay
the entire idle lag tick-by-tick — the #1782 cold-start stall (one
cold connect after ~111 s of idle was measured replaying 2,226,212
ticks in a single `advance_cos_timer_wheel` call). Since #1782 Step-2,
a catch-up lag that exceeds the full wheel horizon
(`COS_TIMER_WHEEL_L0_SLOTS * COS_TIMER_WHEEL_L1_SLOTS` = 65,536 ticks,
~3.28 s) snaps the wheel in O(slots): if no queue is parked, every
wheel entry is stale (entries are filtered lazily by the
`parked`/`wheel_level`/`wheel_slot` checks), so clearing all slot
vectors and setting `current_tick = now_tick` is exactly the per-tick
loop's end state. If any queue IS parked the snap is refused and the
per-tick loop runs unchanged. That fallback is NOT statically bounded:
park wake ticks come from an uncapped `deficit/rate` refill time, and
pathologically low configured rates (the schema accepts 1 B/s) can
park a queue tens of minutes out — a worker idling in that state
still pays the O(lag) loop on its next drain. This residual is
accepted deliberately: covering it needs absolute wake-tick re-arming
(plan option (b)), and the proven production cold-start mechanism — a
fully idle worker — has no backlog, hence no parked queue, and always
takes the O(slots) snap. In-horizon lag always takes the per-tick
loop unchanged. The `cos_wheel_ticks_advanced_total/_max` worker counters
(#1847) keep reporting the true lag on the snap path, so the
cold-start signal remains visible; only its O(lag) wall cost is gone.

Re-arm on dequeue must stay O(1). Each reservation runtime record stores its
current wheel location, and each wheel slot holds a linked list of parked
reservations. Re-arming a reservation is therefore an unlink from the old slot
plus a link into the new slot, not a heap operation or slot scan.

### Why This Fits the Hierarchy

The timer wheel does not replace the hierarchy. It serves it.

- root and reservation buckets still decide eligibility
- the container FIFO still decides which packet goes next
- the scheduler still decides guarantee versus surplus service
- the timer wheel only decides when a sleeping reservation should be looked at
  again

That keeps the model hierarchical and work-conserving while avoiding pointless
CPU burn.

## Container Scheduling

The first pass should stay simple:

- one FIFO queue per container
- one active dequeue head per container
- no fairness key derivation
- no per-flow DRR
- no host buckets

If a reservation later needs multiple containers, container selection inside
that reservation can still remain simple, for example:

- fixed-priority among containers, or
- round-robin among containers

But that is a later extension. The current baseline should not be written as
if per-flow fair queueing already exists.

## Admission Control

Admission control belongs inside the hierarchy.

### Root-Level Admission

The root enforces:

- interface-level byte limit
- interface-level frame limit
- interface-level UMEM budget

### Reservation-Level Admission

Each reservation enforces:

- byte limit
- frame limit
- optional reserved headroom

Reservation headroom prevents one reservation from consuming all of the shared
buffering and making the interface unusable for every other reservation.

### Container-Level Admission

Each container enforces:

- FIFO byte limit
- FIFO frame limit

First-pass overflow policy:

- tail-drop within the same container

This is intentionally simpler than reclaim lists or dominant-flow scavenging.
Those mechanisms are only worth introducing after the basic class-based shaper
works and we have evidence they are needed.

### Memory Accounting

Track queue occupancy in two dimensions:

- **payload bytes** for shaping and scheduling logic
- **UMEM frames** for actual memory safety

Both must be enforced even in FIFO-only mode.

## Many-Core Scaling

The previous draft used the word "sharding" too abstractly. The concrete model
should be:

- a **shard** is just a scheduler owner for some reservations/containers on
  one shaped interface
- a shard is **not** a second policy layer
- a shard is **not** a fast path
- a shard does **not** create independent rates

### Concrete Example

Phase 1 does not require multiple shards. The simplest valid implementation is
one scheduler owner per shaped interface, with every reservation on that one
owner.

The example below is intentionally a later many-core example for Phase 3, where
several scheduler shards exist for one interface.

Suppose interface `ge-0-0-1` has four scheduler shards:

- shard 0 owns `network-control`
- shard 1 owns `expedited-forwarding`
- shard 2 owns `assured-forwarding`
- shard 3 owns `best-effort`

Any worker that classifies a packet into `best-effort` does this:

1. map packet to the `best-effort` reservation/container
2. enqueue it to shard 3, because shard 3 owns that queue
3. shard 3 runs FIFO queueing for that container
4. when shard 3 dequeues, it spends:
   - root lease from the shared interface bucket
   - reservation lease from the shared `best-effort` bucket

So the queue is local to one shard, but the budget authority is still global.

### Ownership Rules

To keep semantics correct:

1. A container belongs to exactly one shard at a time.
2. All packets for that container enqueue to that shard.
3. The root and reservation budgets remain shared and authoritative.
4. A reservation must not silently exist as independent schedulers on several
   workers, because that would multiply its effective share.

### Why This Supports Many Cores

This model still uses many cores:

- parse, route, NAT, and classification can run on all workers
- different reservations can be owned by different scheduler shards
- shared budgets are touched through leases rather than on every packet
- semantics do not change when the number of arrival workers changes

### What It Does Not Solve

This first-pass many-core model is intentionally coarse-grained.

If one reservation is extremely hot:

- its owner shard can become CPU-bound
- throughput for that reservation can be bounded by that shard
- correctness is still preserved
- class behavior does not multiply across workers

That is acceptable for the first implementation. It is much easier to reason
about than splitting one reservation across many workers before the core
algorithm is stable.

### Recommended Rollout

The implementation plan should be explicit:

1. **Simplest valid version**: one scheduler owner per shaped interface
2. **Next step**: multiple scheduler shards with static reservation/container
   ownership
3. **Later only if needed**: more sophisticated ownership or sub-queue models

Do not start with per-flow shard placement.

## Shared Budget Leasing

Shared root and reservation budgets should not be touched directly on every
packet.

### Lease Hierarchy

Recommended implementation:

```text
shared root/reservation buckets
  -> optional socket-local lease cache
    -> shard-local lease
```

This gives:

- global correctness
- reduced cross-core cache-line contention
- better NUMA behavior

### Lease Size

Shard-local lease size should be dynamic:

```text
lease_bytes = clamp(
    rate_bytes_per_us * target_lease_us,
    mtu_bytes,
    min(burst_bytes / 8, max_lease_bytes)
)
```

Recommended defaults:

- `target_lease_us = 25`
- `min_lease_bytes = MTU`
- `max_lease_bytes = 64 KB` for root aggregate
- `max_lease_bytes = 16 KB` for reservation pools

At very low rates, direct charging against the shared bucket may be acceptable
because packet rate is already low.

### Lease Return

Unused leases must be returned when:

- the reservation/container goes idle
- the shard goes quiescent
- lease age exceeds a threshold
- config reload or HA transition occurs

### Total Lease Bound

Total leased-but-unspent credit per shared bucket must be bounded:

```text
max_total_leased = min(bucket_burst / 4, lease_per_shard * active_shards)
```

This prevents many shards from hoarding too much shared credit at once.

### Cache-Line Isolation

All shared buckets should be padded and isolated per cache line.

Without that, coherence traffic will dominate the hot path on many-core boxes.

Every per-worker, per-acquire-written array on the v8 shared lease is
therefore `#[repr(align(64))]`: `PackedEpochGrant` (worker grants,
starvation/demand events, equal-flow samples) and `PaddedAtomicU64`
(cumulative requested/granted bytes). `worker_active_flow_buckets` was
the one exception — a raw `Box<[AtomicU32]>` that packed 16 workers onto
a single cache line and false-shared on every per-flow-churn write.
#4270 (fable-166 R-9) wraps it in `PaddedAtomicU32` so it conforms to the
same isolation rule; compile-time `align_of`/`size_of` asserts pin the
padding. The interface timer wheel additionally reuses persistent
drain/rearm/wake scratch vectors (`CoSTimerWheelScratch`) so the per-tick
catch-up loop performs no allocator work.

## Failure Modes

### Queue Overflow

First-pass policy:

- container tail-drop on container overflow
- reservation admission failure if reservation-level caps are exceeded
- root/interface admission failure if interface-level UMEM or queue caps are
  exceeded

### TX Ring Backpressure

If TX ring submission is partial:

- return unsent packets to the front of the same shard/reservation/container
- preserve FIFO ordering

### Config Reload

On config reload:

1. drain queued packets for a bounded timeout
2. drop remaining packets if timeout expires
3. recycle UMEM
4. reset shard-local state and shared leases

### HA Transition

On demotion:

1. bounded drain
2. drop remaining packets after timeout
3. recycle UMEM

On activation:

- initialize empty shard state
- reset shared lease state

## Configuration Model

The configuration remains Junos-inspired:

- forwarding classes
- schedulers
- scheduler maps
- interface shaping-rate
- optional classifier bindings
- optional `equal-flow-enforcement` on positive `transmit-rate exact`
  schedulers
- optional `equal-flow-target-policy (slowest | mean | ideal-share)` on
  equal-flow-enforcing schedulers (#1746; unset == `slowest`, the
  byte-unchanged clip-to-slowest default)

Internal mapping:

- the interface shaping-rate becomes the **root**
- the scheduler attached to a forwarding class becomes the **reservation**
- the actual queue instance on that interface becomes the **container**

Future knobs for finer-grained fairness, such as something like
`host-fairness source-address`, are intentionally out of scope for Phase 1 and
should be treated as reserved future extensions rather than active baseline
behavior.

### Classifier and rewrite-rule `code-points` spellings (#6697)

Every spelling of a `code-points` / `code-point` leaf compiles to the same
thing. All of these author the same DSCP classifier entry:

```text
classifiers dscp c1 { forwarding-class voice { loss-priority low code-points [ ef af11 ]; } }
classifiers dscp c1 { forwarding-class voice { loss-priority low { code-points { ef; af11; } } } }
classifiers dscp c1 { forwarding-class voice { loss-priority low { code-points ef; code-points af11; } } }
set class-of-service classifiers dscp c1 forwarding-class voice loss-priority low code-points [ ef af11 ]
```

Before #6697 the hierarchical BLOCK form (`code-points { ef; af11; }`) was read
by none of the five readers, so it compiled to **nothing at all** — the whole
classifier was absent, not merely short a code point, while `show
class-of-service` rendered the authored config back intact and the interface
binding succeeded. It also let an invalid token commit clean, because each
reader's domain check runs on the tokens it reads.

The `classifiers` families (`dscp`, `ieee-802.1`, `inet-precedence`) take a
LIST. The `rewrite-rules` families write exactly ONE code point per
`(forwarding-class, loss-priority)` entry; there the Junos leaf is `code-point`
(singular), `code-points` is accepted as an alias, and if more than one value is
authored the first valid one is installed — but every value is still domain-
checked, so a typo anywhere in the list is rejected at commit.

### Example

```text
set class-of-service forwarding-classes queue 0 best-effort
set class-of-service forwarding-classes queue 1 expedited-forwarding
set class-of-service forwarding-classes queue 2 assured-forwarding
set class-of-service forwarding-classes queue 3 network-control

set class-of-service schedulers ef-sched transmit-rate 3g
set class-of-service schedulers ef-sched priority strict-high
set class-of-service schedulers ef-sched buffer-size 4m

set class-of-service schedulers be-sched transmit-rate 3g
set class-of-service schedulers be-sched priority low
set class-of-service schedulers be-sched buffer-size 16m

set class-of-service scheduler-maps my-map forwarding-class best-effort scheduler be-sched
set class-of-service scheduler-maps my-map forwarding-class expedited-forwarding scheduler ef-sched

set class-of-service interfaces ge-0-0-1 unit 0 shaping-rate 10g burst-size 125m
set class-of-service interfaces ge-0-0-1 unit 0 scheduler-map my-map
```

### Interface-level bindings (all units) (#4021)

A `scheduler-map`, `shaping-rate` (with `burst-size`), `classifiers`, or
`rewrite-rules` may be bound at the **physical interface level** — directly
under `class-of-service interfaces geX` with **no `unit`** — as a common
short form for a single-unit port:

```
set class-of-service interfaces ge-0-0-1 scheduler-map my-map
set class-of-service interfaces ge-0-0-1 shaping-rate 10g
```

Junos precedence: an interface-level binding applies to **every configured
logical unit** on the interface, and a **unit-level binding overrides it per
knob**. The compiler folds the interface-level binding into each of the
interface's logical units after the interface stanza is known
(`applyCoSInterfaceLevelBindings` in `pkg/config/compiler.go`), so the
dataplane snapshot and `show class-of-service interface` — which iterate the
per-unit bindings — apply it without any interface-level awareness of their
own. Mixing forms is honored: a `unit N` that sets its own `scheduler-map`
keeps that map while still inheriting the interface-level `shaping-rate`.
Before #4021 an interface-level binding compiled and committed cleanly but
was silently dropped (only `unit N` children were read), so the shaping /
classification / marking never applied.

`shaping-rate` and its `burst-size` are a coupled pair (`burst-size` is
grammatically a child of `shaping-rate`). A unit that **overrides**
`shaping-rate` therefore defines its own shaper and does **not** inherit
the interface-level `burst-size` (#hb166 G-10): pairing a level burst
sized for the level rate with a different unit rate would mismatch them
(e.g. a level `shaping-rate 100m burst-size 200000` with a unit override
`shaping-rate 1g` would otherwise carry a 200000-byte burst computed for
100m — 10x of intent). When such an override leaves `burst-size` unset it
stays 0 and the dataplane applies its rate-independent
`COS_MIN_BURST_BYTES` floor, exactly as for a fresh unit that sets
`shaping-rate` alone. A unit that inherits the rate (sets no
`shaping-rate`) still inherits both the level rate and the level burst as
a pair.

### Hierarchical traffic-control-profiles (#4315, fable-167 F-2)

The Junos hierarchical shaping binding is modeled and **wired** to the
per-unit shaper:

```
set class-of-service traffic-control-profiles wan-tcp shaping-rate 9g
set class-of-service traffic-control-profiles wan-tcp scheduler-map edge-map
set class-of-service interfaces ge-0-0-2 unit 80 output-traffic-control-profile wan-tcp
```

A `traffic-control-profiles <name>` profile carries `shaping-rate`,
`scheduler-map`, `guaranteed-rate`, and `delay-buffer-rate`. Binding it to a
logical unit's egress with `output-traffic-control-profile <name>` folds the
profile's **shaping-rate** and **scheduler-map** into that unit's existing
per-unit shaper (`resolveCoSTrafficControlProfiles` in
`pkg/config/compiler.go`, run after the interface-level fold), so the shaper
materializes exactly as if the operator had set `shaping-rate` /
`scheduler-map` directly on the unit. A **direct unit-level knob wins** over
the profile (Junos precedence), and an interface-level
`output-traffic-control-profile` applies to every configured logical unit.
A profile `shaping-rate percent <n>` resolves against the bound interface's
configured line rate before the fold (see the percent-resolution note under
"`transmit-rate` / `shaping-rate` value forms" above, #4228 Gap 2).

Before #4315 both `traffic-control-profiles` and
`output-traffic-control-profile` were unmodeled: the binding committed
cleanly and was **silently dropped** — the shaper never materialized (ZERO
shaping while the operator believed shaping was applied). `guaranteed-rate`
and `delay-buffer-rate` are typed (garbage rejected at commit) and captured
for `show configuration` fidelity, but are **accepted-but-inert** — the
userspace shaper has no per-unit absolute guaranteed-rate reservation or
delay-buffer sizing (the #1614 A1 `guarantee-rate` is a proportional
*fraction*, a distinct mechanism); a commit advisory surfaces the inertness.
A dangling `output-traffic-control-profile` reference (no such profile) also
warns (the unit is not shaped).

A `class-of-service interfaces <name>` binding whose interface — or a
bound `unit N` — is **not configured under `[interfaces]`** is a silent
no-op: the dataplane applier only visits CoS bindings that resolve
against `cfg.Interfaces`, so a typo'd interface name or an unconfigured
unit shapes nothing. The commit now emits a WARNING (not a reject — the
interface may be added later) so the operator knows the binding is
currently inert (#hb166 G-6).

**Commit-time validation of the interface-binding leaves (fable-review-166).**
The `shaping-rate`, `burst-size`, `oversubscription-policy` (its
`guarantee-rate` fraction), and `priority-low-min-share` leaves are typed
in `setSchema`, at BOTH the unit level and the interface level. A garbage
value now HARD-REJECTS at `commit` / `commit check` instead of silently
compiling to 0 and removing the shaper: before this, `shaping-rate 10gg`
parsed to 0 (`parseBandwidthLimit` silent-zero), the compiler read 0 as
"unset", and egress ran **unshaped** (#4217). `oversubscription-policy
guarantee-rate 1.7` is rejected rather than silently clamped to 1.0
(#4219). `priority-low-min-share` is typed + validated and completes, but
the dataplane does not yet enforce it (wire-surface only; a commit warning
surfaces the inertness — #4220). `bare-integer` burst-size is now rejected
as ambiguous — use an explicit `k`/`m`/`g` suffix (e.g. `125m`). Put the
rate and its `burst-size` on the SAME `set` line (`shaping-rate 10g
burst-size 125m`): a separate `set ... shaping-rate burst-size 125m`
line creates a second sibling `shaping-rate` node whose value is the
literal `burst-size` — which the commit gate now rejects (before this it
silently dropped the burst-size).

Scheduler `buffer-size` may be configured as an explicit byte size
(`4m`, `256k`, `1g`) or as a Junos percent value (`10%`). Percent values
are carried over the userspace protocol as `buffer_size_percent`, not as
`buffer_size_bytes = 0`. At runtime the scheduler's queue buffer is
resolved per interface as that percentage of the interface CoS burst
pool: the explicit `shaping-rate burst-size` when present, otherwise the
userspace default root burst (`max(shaping_rate_bytes / 100, 64 * MTU)`).
If both protocol fields are present, `buffer_size_bytes` keeps precedence
for compatibility with existing snapshots. For each interface unit, the
sum of percent buffers across the scheduler-map entries bound to that
unit must be at most 100% of the interface CoS burst pool. xpf
intentionally rejects `buffer-size 0%` even though Junos accepts it,
because zero is the legacy absent-field value on the userspace protocol
and runtime queues still retain a minimum burst floor.

`buffer-size` also accepts the Junos `temporal <microseconds>` form
(#4228 Gap 2 follow-up) — size the buffer by a target queue delay rather
than an absolute byte-size or percent. It is validated at commit (a
positive whole number of microseconds; `0` and garbage are rejected) and
stored as `BufferSizeTemporalUS`. Since #6846 it **RESOLVES** — see
"Temporal resolution" above: `cos_temporal_buffer_bytes` converts the
microsecond target against the queue's resolved transmit rate. The commit
advisory narrowed to the one case that still cannot resolve (a queue with no
resolvable rate at all) rather than being retracted. Modeled so imported vSRX
configs that use `temporal` buffer sizing commit clean instead of being
rejected.

### Current Userspace Test Recipe

This is the current lab recipe that matches what the userspace dataplane
actually honors today for a simple outbound `iperf3` check from the LAN side.

Important current behavior:

- shaping is enforced on the **egress** interface
- queue selection prefers the shaped interface **egress output filter** when it
  sets a forwarding-class — **output-overrides-when-set**, not
  presence-clears-ingress (#hb166 T-3). An output filter that assigns a
  forwarding-class (`then forwarding-class`) wins; an output filter that only
  counts/logs/terminates (`then count` / `then log` / `then discard`) and does
  NOT set a forwarding-class PRESERVES the class an ingress input filter
  assigned. Before the fix, attaching ANY output filter — even an audit-only
  `then count` — silently reclassified the traffic to the default best-effort
  queue
- the egress output filter matches the **post-NAT (on-wire) tuple** (#3642):
  Junos applies an interface `filter output` AFTER NAT, so a filter term
  matching source/destination address or port sees the TRANSLATED
  (SNAT/DNAT) values, and a NAT64 flow is matched by the EGRESS-family
  output filter. Forwarding-class selection, DSCP rewrite, counters,
  `then log`, and terminal accept/discard on the output filter are all
  driven by the on-wire tuple, not the pre-NAT ingress tuple
- when the output filter sets no forwarding-class, queue selection falls back to
  the forwarding-class the current **ingress interface input filter** assigned
  (whether or not a counter/log-only output filter is also attached)
- if neither filter assigns a forwarding class, queue selection falls back to
  the shaped interface's attached BA classifiers:
  - DSCP under
    `class-of-service interfaces <if> unit <u> classifiers dscp <name>`
  - IP precedence under
    `class-of-service interfaces <if> unit <u> classifiers inet-precedence <name>`
    (#6847)
  - 802.1p under
    `class-of-service interfaces <if> unit <u> classifiers ieee-802.1 <name>`

  consulted in that order: both L3 arms (which read the DS field) precede the
  L2 802.1p arm (which needs a VLAN tag)
- a BA classifier code-point that maps to a forwarding-class whose queue the
  interface does NOT materialize (the forwarding-class has no `scheduler-map`
  entry on that interface) falls back to the interface **default best-effort
  queue** — forward on best-effort, never blackhole (#hb166 T-4). Before the
  fix such a code-point resolved to a non-existent queue and every matching
  packet was silently dropped, while the config committed cleanly. The commit
  path now emits an operator warning naming the forwarding-class and queue that
  has no scheduler-map entry on the interface; it is a WARN (not a strict
  reject) because a classifier steering to a forwarding-class without a
  scheduler-map entry is a valid Junos config (queues exist by default there)
- non-`exact` scheduler `transmit-rate` values act as guarantees and may borrow
  surplus bandwidth up to the root shaper
- scheduler-map entries whose scheduler has no explicit positive
  `transmit-rate` are residual-only under the shaped root. They keep an
  effective rate for burst sizing and surplus weight, but do not receive
  non-`exact` guarantee service. The synthetic default best-effort queue used
  when an admitted CoS interface has no real scheduler-map queues remains the
  sole root-shaped guarantee queue; admission can come from shaping or from a
  classifier/rewrite rule that targets that default queue/class.
- a scheduler-map entry naming a scheduler that is NOT defined (a
  dangling reference) is hard-rejected at strict commit
  (`validateClassOfServiceSchedulerMapRefsStrict`), so an operator can
  never create one. If a config persisted by an older binary — or synced
  from a peer — still carries one, it is downgraded to a warning on load
  (`lenientSchedulerMapRef`, #1960) and the helper applies a SAFE
  best-effort default: the queue stays materialized under its real queue
  id / forwarding-class (so classified traffic still forwards) but is
  pinned to the MINIMAL surplus weight (1), not the whole-interface-rate
  MAXIMUM (16) the effective-rate derivation used before. This distinguishes
  a dangling reference (no scheduler; minimal share) from a defined
  scheduler that merely omits `transmit-rate` (residual-only above; full
  surplus weight). Before the fix a scheduler typo silently handed the
  class the LARGEST best-effort surplus share instead of its intended
  guarantee — a fail-open now closed.
- an INTERFACE-level reference naming an entity that is not defined — a
  `scheduler-map`, a `dscp` / `ieee-802.1` / `inet-precedence` classifier, or a
  `dscp` rewrite-rule — is likewise hard-rejected at strict commit
  (`validateClassOfServiceInterfaceRefsStrict`, #8107, which checks seven such
  links including `output-traffic-control-profile` and the inert `ieee-802.1`
  rewrite-rule). As with the scheduler case above, a config from an older
  binary or a peer sync can still carry one over the lenient load path, and the
  APPLIED behaviour is deliberately unchanged: either the interface contributes
  no other usable CoS state and is skipped entirely (the #1183 gate — admitting
  it would build a rate-0 best-effort queue and re-trigger the owner-worker
  redirect collapse), or it is admitted on some other input (a `shaping-rate`,
  say) and the dangling reference simply installs nothing. What changed in
  #7337 is that this is no longer SILENT: `dangling_cos_interface_refs` reports
  each unresolvable reference, naming the interface, the reference kind, and
  whether the interface was programmed at all. The second shape is the one that
  most misleads — the interface IS in `CoSState`, so the runtime shows CoS
  active on it while the configured classifier does nothing. The report does
  not reject the snapshot: on the lenient path that would turn one degraded
  interface into a node that will not take a config, which is exactly the brick
  #1960 exists to prevent.
- `transmit-rate exact` prevents that queue from borrowing surplus by default
- adding `surplus-sharing` on the scheduler (#915) opts an `exact` queue
  into surplus participation while keeping the per-queue rate as a
  guarantee floor
- adding `equal-flow-enforcement` on the scheduler is an explicit opt-in for
  shared flow-aware exact enforcement. The knob is accepted only with a
  positive `transmit-rate <rate> exact` and cannot be combined with
  `surplus-sharing`; commits fail closed when the rate is missing, zero,
  non-`exact`, or surplus-enabled. The Rust v8 queue lease then caps each
  active worker to the slowest sampled per-active-SFQ-bucket grant rate once
  every active worker is sampled, every active sampled worker is materially
  utilizing its prior fair share, and the target has survived the valid-streak
  guard. If multiple flows hash into one SFQ bucket they are counted as one
  bucket for this cap. The bucket key is the 5-tuple plus the routing domain
  and tunnel discriminator (#9645), so identical 5-tuples in two routing
  instances share a bucket only by chance. When the sample is incomplete, low-demand, or stale, the
  mode fails open to the normal work-conserving v8 behavior and reports the
  bounded fail-open reason in status/Prometheus.
- `per-unit-scheduler` is not implemented

For the `loss` userspace lab, the relevant path is:

- client ingress on `reth1.0`
- WAN egress on `reth0.80`

So the working test config is:

```text
set class-of-service forwarding-classes queue 0 best-effort
set class-of-service forwarding-classes queue 4 bandwidth-10mb
set class-of-service forwarding-classes queue 5 bandwidth-5mb

set class-of-service schedulers scheduler-be transmit-rate 15m
set class-of-service schedulers scheduler-10mb transmit-rate 10m
set class-of-service schedulers scheduler-5mb transmit-rate 5m

set class-of-service scheduler-maps bandwidth-limit forwarding-class best-effort scheduler scheduler-be
set class-of-service scheduler-maps bandwidth-limit forwarding-class bandwidth-10mb scheduler scheduler-10mb
set class-of-service scheduler-maps bandwidth-limit forwarding-class bandwidth-5mb scheduler scheduler-5mb

set class-of-service classifiers dscp bandwidth-dscp forwarding-class bandwidth-10mb loss-priority low code-points ef
set class-of-service classifiers dscp bandwidth-dscp forwarding-class bandwidth-5mb loss-priority low code-points default

set class-of-service interfaces reth0 unit 80 scheduler-map bandwidth-limit
set class-of-service interfaces reth0 unit 80 classifiers dscp bandwidth-dscp
set class-of-service interfaces reth0 unit 80 shaping-rate 15m

set firewall family inet filter bandwidth-output term 0 from destination-port 80
set firewall family inet filter bandwidth-output term 0 from destination-port 5201
set firewall family inet filter bandwidth-output term 0 then count output-10m
set firewall family inet filter bandwidth-output term 0 then forwarding-class bandwidth-10mb
set firewall family inet filter bandwidth-output term 0 then accept
set firewall family inet filter bandwidth-output term 1 then count output-5m
set firewall family inet filter bandwidth-output term 1 then forwarding-class bandwidth-5mb
set firewall family inet filter bandwidth-output term 1 then accept

set interfaces reth0 unit 80 family inet filter output bandwidth-output
```

Notes for this specific test:

- match `destination-port 5201` for client-to-server `iperf3` traffic; matching
  `source-port 5201` classifies the reverse direction instead
- shape and classify on `reth0.80`, not `reth0.0`, because the WAN test
  traffic in this lab leaves via `reth0.80`
- define an explicit `best-effort` queue so unmatched traffic does not depend
  on whatever queue happens to be first in the scheduler map
- DSCP BA classifiers are a fallback input to CoS queue selection today; an
  explicit firewall filter `then forwarding-class ...` decision still wins
- DSCP rewrite-rules can also be attached under
  `class-of-service interfaces ... unit ... rewrite-rules dscp <name>` on
  shaped userspace egress interfaces; they apply after queue selection and act
  as a fallback behind any explicit firewall-filter DSCP rewrite action. The
  rewrite is keyed on `(forwarding-class, loss-priority)` (#3995) — see the
  loss-priority note below
- `classifiers inet-precedence <name>` (#6847) is a fallback queue selector on
  the same footing as the DSCP classifier, reading the top 3 bits of the DS
  field (`(dscp >> 3) & 0x7` — IPv4 TOS and IPv6 traffic-class alike, matching
  the family-agnostic DSCP arm). The entry's `loss-priority` feeds the egress
  rewrite exactly as the dscp / 802.1p classifiers do. A unit may bind **at
  most one** of `classifiers dscp` and `classifiers inet-precedence`: both read
  the same DS field, so binding both is a contradiction rather than a
  composition, and it is hard-rejected at commit (the tolerant load /
  peer-sync path downgrades to a warning so a persisted config still boots, and
  DSCP wins on that boot). Before #6847 the classifier was definable at the top
  level but had NO unit binding site at all, so the bind line was rejected by
  the schema
- 802.1p BA classifiers are also available as a fallback queue selector on
  userspace interfaces; they use the ingress VLAN PCP preserved from tagged
  XDP traffic, including priority-tagged frames with VLAN ID 0
- `rewrite-rules ieee-802.1 <name>` (802.1p PCP egress rewrite, #4228 Gap 4)
  is now accepted, fully modeled, validated (loss-priority typo gate +
  code-point `0..7` range check + dangling-reference warns), and bindable under
  `class-of-service interfaces ... [unit ...] rewrite-rules ieee-802.1 <name>`
  — but it is **accepted-but-inert**: the userspace dataplane rewrites `dscp`
  on egress only and does not yet own the 802.1Q tag write, so a commit
  advisory surfaces that the PCP rewrite has no runtime effect. The classifier
  side is enforced; the egress-rewrite half awaits egress 802.1Q tag ownership
  in the AF_XDP TX path (a Rust follow-up)
- keep ingress `input` filter classification only as a compatibility fallback
  for existing configs that do not yet attach an egress CoS filter
- use `set class-of-service schedulers <name> transmit-rate <rate> exact` for
  queues that must stay capped at their guarantee instead of borrowing surplus
- use `set class-of-service schedulers <name> equal-flow-enforcement` only on
  positive exact-rate schedulers that do not use `surplus-sharing`; it is
  intentionally non-work-conserving and should be used only when lower
  absolute per-active-bucket spread is worth giving up aggregate throughput
  under RSS skew. In the worst case it may withhold every byte above
  `slowest_sampled_per_bucket_rate * active_buckets_on_worker`, so aggregate
  throughput can drop substantially when one active worker is much slower than
  its peers. The suppressor fails open when an active worker looks merely quiet
  rather than demand-saturated.
- `set class-of-service schedulers <name> equal-flow-target-policy
  (slowest | mean | ideal-share)` (#1746) selects the per-flow target the
  equal-flow publisher enforces. Unset is byte-identical to `slowest` (the
  pre-#1746 `min` reduction over the sampled per-worker achieved rates), so
  existing configs are unaffected. `mean` clips toward
  `sum(prev_grants) / sum(active_flows)` over the sampled set — it trims only
  the lucky fast outliers and keeps more aggregate than `slowest`.
  `ideal-share` is the nominal equal share: the rotation's true byte budget
  (rate x elapsed, lag-recovered) divided by the live total active-flow
  count. The static capacity-limited model predicts it clips nothing (every
  flow already runs below the nominal share); LIVE, the per-epoch sampled
  flow count and EWMA dynamics can make it intermittently bind, so treat it
  as "nominal-share semantics with occasional top-band trimming", not a
  strict no-op — the #1746 F1 measurement
  (`docs/pr/1746-equal-flow-target-policy/f1-measurement.md`) recorded
  cap-hit activity and OFF-to-ON CoV movement comparable to the clipping
  policies. Like all equal-flow enforcement it is bounded by the
  low-demand-worker fail-open governor.
  Modeled tradeoff on the observed loss-cluster banding (10 distinct flow
  rates `[0.87x4, 1.29x3, 1.63x2, 1.81x1]` Gb/s, baseline 12.42 G aggregate
  / 27.7 % per-flow CoV — #1746 plan section 4):

  | policy | target | aggregate | per-flow CoV | lifts the 0.87 G floor? |
  |---|---|---|---|---|
  | `ideal-share` | 2.0 G | 12.42 G (no-op) | 27.7 % (no-op) | NO |
  | `mean` | 1.242 G | 10.93 G (-12 %) | 16.7 % (-40 % relative) | NO |
  | `slowest` (default) | 0.87 G | 8.70 G (-30 %) | ~0 % | NO |

  Live A/B (#1746 F1 + supplementary matrix,
  `docs/pr/1746-equal-flow-target-policy/f1-measurement.md`): the effect
  of `mean` is **regime-dependent** — on high-CoV baseline draws (skewed
  RSS placement, per-flow CoV well above the structural floor) it
  delivered a 52 % relative CoV reduction at ~zero aggregate cost; on
  draws already near the fairness floor (~10 % CoV) it ADDED ~5 CoV
  points and cost 4-8 % aggregate, because there is nothing above the
  mean to trim and the enforcement duty cycle perturbs balanced flows.
  Enable `mean` only on classes that chronically exhibit high per-flow
  CoV; do not enable it on classes already near the floor.

  **No cap-based policy lifts the slowest band**: the cap is
  one-directional (`my_share.min(cap)`), and capacity freed by clipping a
  fast worker cannot reach a starved worker on a different queue/CPU.
  Lifting the floor is work-conserving cross-worker rebalance — tracked as
  #1748, not this knob. Selecting `slowest` or `mean` emits a
  non-work-conserving commit warning; the active policy is visible in
  `show class-of-service` (`policy=` on the Equal-flow line) and as the
  info metric
  `xpf_userspace_cos_equal_flow_target_policy{ifindex,queue_id,policy}`.
- **`equal-flow-enforcement` is supported at any worker count** (#1830 (e)).
  The former 32-worker cap (`MAX_WORKERS_SCRATCH` stack scratch in the v8
  lease rotation) is removed: `rotate_epoch_v8.rs` now captures per-worker
  swap state in a heap scratch sized at lease construction to cover the
  HIGHEST planned worker id (`last_planned_worker_slots` = max planned id
  + 1, not the worker count — ids can be sparse after partial binding
  unregister, per the Codex review on PR #1841; one cold allocation per
  lease build/rebuild; no allocation at rotation time), so an active
  worker beyond index 31 no longer forces an `unsampled_active_worker`
  fail-open every epoch. The matching #1733
  commit-time hard-reject of `workers > 32` + `equal-flow-enforcement`
  (and its lenient load/peer-sync warning downgrade) is retired with it.
  The `unsampled_active_worker` fail-open reason still exists for its
  original purpose — a real participant whose acquire-time sample was
  missed — and the measurement-only
  `xpf_fairness_equal_flow_unsampled_active_workers` estimator gauge
  (#1304) is unrelated to the removed cap.
- **Fairness throughput-window retention is bounded (#5100).** The
  collector's rolling per-queue throughput window (which feeds the
  `xpf_fairness_saturated` / `xpf_fairness_observed_cov` /
  `xpf_fairness_starved_flows` gauges and the equal-flow estimator, all
  keyed by `(ifindex, queue_id)`) now RETIRES a queue identity that has
  vanished from the current status AND holds no live telemetry — no
  accumulated flow bytes, worker bytes, or starvation records after the
  30 s window drains. Previously a `(ifindex, queue_id)` that disappeared
  (interface removal / ifindex churn / test namespaces) was retained for
  the process lifetime, so long-running systems accumulated telemetry
  state and paid an ever-growing per-scrape seed+sort of the full
  historical key slice under the collector mutex. Retention is now bounded
  by currently-observed identities plus one window of recently-active
  ones. Retirement is metric-invariant: a drained queue produces no gauge
  sample regardless (the scrape skips empty queues), a still-active queue
  is never retired, and a retired identity that reappears re-registers
  cleanly with a fresh baseline.
- `loss-priority` on CoS DSCP rewrite-rules is **enforced** (#3995): the
  userspace dataplane keys the egress DSCP rewrite on
  `(forwarding-class, loss-priority)`, so a rule that rewrites
  `<fc> low` and `<fc> high` to different code-points produces the
  LOW code-point for a low-loss-priority flow and the HIGH code-point
  for a high-loss-priority flow of that class. A rewrite entry with no
  explicit `loss-priority` is a wildcard that applies to every
  loss-priority (backward-compat). The loss-priority is taken from the
  egress interface's DSCP / 802.1p classifier assignment for the flow's
  ingress code-point (Junos default LOW when unclassified); it is
  resolved once per flow and cached, exactly like the firewall-filter
  DSCP rewrite. A single, loss-priority-uniform rewrite (or a wildcard)
  is additionally baked into the per-queue drain fallback; differentiated
  rules resolve per flow at classification time.
- `loss-priority` on CoS DSCP / 802.1p classifiers now drives the egress
  rewrite-rule selection above, but is still **not** enforced for
  drop-precedence / WRED buffer management (a commit warning names the
  remaining gap). Note the loss-priority is resolved per flow from the
  seed packet's ingress code-point; a flow that changes its marking
  mid-stream keeps the seed loss-priority for its cached rewrite.

Suggested verification commands:

```text
show configuration class-of-service | display set
show configuration firewall family inet filter bandwidth-output | display set
show class-of-service interface reth0.80
show firewall filter bandwidth-output
monitor interface traffic
```

## Observability

Observability should reflect the actual hierarchy.

### CLI

Required views:

- interface/root state
- reservation state
- container state
- shard state for many-core debugging

Currently implemented:

- `show class-of-service interface [IFACE[.UNIT]]`
- prints configured shaping rate, scheduler-map, attached CoS filters, attached
  DSCP classifier, and the live userspace queue/runtime state that is currently
  exported by the helper
- shaped egress interfaces now have a static userspace scheduler owner worker;
  non-owner workers hand shaped traffic to that owner before CoS queue
  admission so one interface does not silently get independent queue state on
  every worker
- ownership is now spread deterministically across eligible workers when
  multiple shaped egress interfaces share the same TX path
- `show firewall` / `show firewall filter <name>` now surfaces the three-color
  policer status inline under each `then policer <name>` term (#4372): the
  policer mode (single-rate / two-rate), color mode (color-aware / color-blind),
  and the per-color green (conform) / yellow (exceed) / red (violate) plus
  treatment-drop packet/byte counters the userspace dataplane publishes over its
  `three_color_policer_counters` status. Legacy single-rate `firewall policer`
  definitions are lowered into the same three-color runtime (#4514), so both
  policer namespaces render. The same counters are also printed as a
  "Three-color policers:" table in the dataplane status summary.

Still planned:

- reservation detail views
- container detail views
- shard detail views

Examples:

```text
show class-of-service interface ge-0-0-1
show class-of-service interface ge-0-0-1 reservation best-effort detail
show class-of-service interface ge-0-0-1 container best-effort
show class-of-service interface ge-0-0-1 shards
```

### Metrics

At minimum:

- root aggregate tokens
- reservation CIR/PIR served bytes
- reservation queue depth bytes/frames
- container queue depth bytes/frames
- container tail drops
- UMEM pressure drops
- timer-wheel sleeping reservations
- timer-wheel wakeups, rearms, and late wakes
- lease returns and lease expirations
- shard-local backlog and service

## Current Implementation Status

As of April 2026, xpf has landed a **userspace-only** CoS slice. The current
implementation is no longer just a design sketch; the following pieces are
implemented and exercised in the userspace dataplane:

- forwarding-class, scheduler, and scheduler-map parsing/compile support
- shaped egress interface binding through
  `class-of-service interfaces ... scheduler-map ... shaping-rate ...`
- queue selection from the shaped interface's egress output filter
- ingress input-filter fallback when no egress CoS filter is attached
- DSCP and 802.1p BA classifier attachment as fallback queue selectors
- DSCP rewrite-rule attachment on shaped egress interfaces
- firewall-filter DSCP rewrite precedence over queue-level rewrite-rules
- root shaping, bounded per-visit guarantee service, `transmit-rate exact`,
  strict-priority surplus selection, same-priority weighted DWRR, and
  non-`exact` surplus borrowing
- timer-wheel deferred eligibility for backlogged-but-ineligible queues
- static owner-worker handoff for shaped egress interfaces
- deterministic queue-owner spreading across eligible workers on a shared TX
  path
- shared-root budget leasing across owner workers on the same shaped interface
- base interface/runtime observability via
  `show class-of-service interface [IFACE[.UNIT]]`
- three-color policer per-color counters exported to Prometheus
  (`xpf_userspace_three_color_policer_packets_total` /
  `_bytes_total` labelled by `policer`+`color`, and
  `_drops_total` / `_drop_bytes_total` labelled by `policer`) AND surfaced in
  `show firewall` / `show firewall filter` per referencing term (#4372)

The following pieces are still not complete:

- non-userspace dataplane CoS parity
- WRED/drop profiles
- 802.1p rewrite-rules
- `loss-priority` enforcement for BA classifiers / rewrite-rules
- fuller Junos scheduler semantics beyond the current transmit-rate/priority/
  buffer-size slice
- detailed reservation/container/shard observability and metrics
- more advanced dynamic many-core ownership and leasing beyond the current
  static queue-owner model

## Implementation Plan

### Phase 1: Root + Reservation + Container FIFO

Status: implemented in the current userspace baseline.

- root aggregate shaping
- one reservation per class
- one FIFO container per reservation
- no bypass for generated packets on shaped interfaces
- valid baseline may start with one scheduler owner per interface before the
  later Phase 4 queue-ownership and leasing work
- runnable reservation lists only
- acceptable without a timer wheel because the reservation count per interface
  is still small enough to scan directly in the baseline implementation

### Phase 2: Timer Wheel and Deferred Eligibility

Status: implemented in the current userspace baseline.

- add a per-shard timer wheel for sleeping reservations
- park backlogged-but-ineligible reservations instead of rescanning them
- compute wakeups from root/reservation refill time to at least one MTU
- keep lease-age / idle-return wakeups on the same local mechanism if they are
  cheap enough

### Phase 3: Reservation Guarantees and Surplus

Status: implemented for the current userspace CoS slice. Bounded guarantee
service, strict-priority surplus selection, same-priority weighted DWRR, and
`transmit-rate exact` are landed. Explicit Junos-style ceiling/PIR expansion is
still broader future CoS work, not a gap in the current userspace slice.

- guarantee service phase
- surplus service phase
- strict priority between reservation levels
- weighted DWRR within the same priority
- shared root/reservation budgets
- timer-wheel wakeups feed reservations back into the runnable sets for both
  phases

### Phase 4: Many-Core Ownership and Leasing

Status: implemented for the current userspace slice. Queue ownership is spread
deterministically across eligible workers on the same TX path, packets are
handed to the owning worker before CoS enqueue, and shaped root budgets are
shared through worker-local leases.

- static reservation/container ownership by scheduler shard
- first userspace slice is implemented as queue ownership on shaped egress
  interfaces, with cross-worker handoff before CoS enqueue
- ownership is spread deterministically across eligible workers for queues on
  the same shaped egress TX path
- internal enqueue to the owning shard
- shared parent budgets plus shard-local leases
- cache-line isolation for shared pools
- one timer wheel per scheduler shard, not one global timer queue

### Phase 5: Observability and Tuning

Status: partially implemented. Interface/root-level live observability is
landed; deeper reservation/container/shard views and metrics are still future
work.

- root/reservation/container CLI
- shard metrics
- timer-wheel occupancy / wakeup metrics
- lease tuning
- latency and throughput tuning

### Future Extension, Not Phase 1

If class-level FIFO proves insufficient, later work can add:

- multiple containers per reservation
- more advanced admission/reclaim
- finer-grained fairness below the container level

But that should be justified by evidence, not assumed into the baseline design.

## Validation Plan

The design is only correct if all of these pass.

### Throughput and Accuracy

1. Single interface, single reservation, line-rate shaping
2. Low-rate shaping accuracy at `10/50/100 Mbps`
3. Multi-reservation contention on shared root budget

### Scheduling Correctness

4. Guarantee phase gives every backlogged reservation forward progress
5. Same-priority weighted DWRR surplus split matches configured weights
6. `transmit-rate exact` (without `surplus-sharing`) never exceeds its
   guarantee; with `surplus-sharing` (#915) it may borrow root surplus
   tokens above the guarantee while still holding the per-queue rate as
   a floor. `equal-flow-enforcement` is mutually exclusive with
   `surplus-sharing` because the surplus phase intentionally bypasses the
   per-queue lease cap that equal-flow suppression depends on.
7. In single-shard or uncontended cases, backlogged reservations wake from the
   timer wheel within one tick plus one scheduler cycle of becoming eligible

### Adversarial Class Behavior

8. One elephant in low priority does not destroy a small high-priority class
9. One hundred elephants across several low-priority reservations still allow
   high-priority reservations to meet guarantees
10. Uneven RSS placement does not multiply reservation guarantees

### Many-Core Behavior

11. Packets from many arrival workers still enqueue to the correct owning
    shard for their reservation/container
12. Shared-budget leasing remains stable under many-core contention
13. No long-lived stranded lease credit
14. Sleeping reservations on one shard do not require rescans on unrelated
    shards
15. Under contended shared-root leasing, wake-and-rearm retries remain bounded
    and do not devolve into busy rescans

### Infrastructure

16. No-bypass validation for session hits and generated packets
17. TX ring backpressure preserves FIFO ordering
18. Config reload and HA transition honor bounded drain behavior
19. UMEM accounting remains correct under mixed packet sizes

### Known First-Pass Limitation to Measure Explicitly

20. Elephant-versus-mice within the **same** container should be benchmarked
    and documented as FIFO behavior, not misrepresented as solved fairness

## Summary

The first-pass design should be framed as:

- a hierarchical shaper
- one unified packet path
- one service tree: `root(interface) -> reservation -> container`
- FIFO queueing inside containers
- weighted scheduling among reservations
- timer-wheel wakeups for sleeping reservations
- no CIR fast path
- many-core support through queue ownership and shared-budget leasing
- no claim of micro-flow fairness in phase 1

That keeps the document aligned with the actual intent:

- protocol oblivious
- class-oriented and work-conserving
- understandable on many-core systems
- implementable without jumping straight into expensive per-flow machinery
