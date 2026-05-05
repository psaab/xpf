# Class of Service — Hierarchical Egress Traffic Shaping

Userspace-only implementation in the Rust AF_XDP forwarding plane.

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

Internal mapping:

- the interface shaping-rate becomes the **root**
- the scheduler attached to a forwarding class becomes the **reservation**
- the actual queue instance on that interface becomes the **container**

Future knobs for finer-grained fairness, such as something like
`host-fairness source-address`, are intentionally out of scope for Phase 1 and
should be treated as reserved future extensions rather than active baseline
behavior.

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

set class-of-service interfaces ge-0-0-1 unit 0 shaping-rate 10g
set class-of-service interfaces ge-0-0-1 unit 0 shaping-rate burst-size 125m
set class-of-service interfaces ge-0-0-1 unit 0 scheduler-map my-map
```

### Current Userspace Test Recipe

This is the current lab recipe that matches what the userspace dataplane
actually honors today for a simple outbound `iperf3` check from the LAN side.

Important current behavior:

- shaping is enforced on the **egress** interface
- queue selection prefers the shaped interface **egress output filter**
- if no egress CoS filter is configured, queue selection falls back to the
  current **ingress interface input filter**
- if neither filter assigns a forwarding class, queue selection falls back to
  the shaped interface's attached BA classifiers:
  - DSCP under
    `class-of-service interfaces <if> unit <u> classifiers dscp <name>`
  - 802.1p under
    `class-of-service interfaces <if> unit <u> classifiers ieee-802.1 <name>`
- non-`exact` scheduler `transmit-rate` values act as guarantees and may borrow
  surplus bandwidth up to the root shaper
- `transmit-rate exact` prevents that queue from borrowing surplus by default
- adding `surplus-sharing` on the scheduler (#915) opts an `exact` queue
  into surplus participation while keeping the per-queue rate as a
  guarantee floor
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
  as a fallback behind any explicit firewall-filter DSCP rewrite action
- 802.1p BA classifiers are also available as a fallback queue selector on
  userspace interfaces; they use the ingress VLAN PCP preserved from tagged
  XDP traffic, including priority-tagged frames with VLAN ID 0
- keep ingress `input` filter classification only as a compatibility fallback
  for existing configs that do not yet attach an egress CoS filter
- use `set class-of-service schedulers <name> transmit-rate <rate> exact` for
  queues that must stay capped at their guarantee instead of borrowing surplus
- `loss-priority` on CoS DSCP / 802.1p classifiers is accepted for syntax
  compatibility but is not enforced yet
- `loss-priority` on CoS DSCP rewrite-rules is accepted for syntax
  compatibility but is not enforced yet

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
   a floor
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
