# Userspace Dataplane Cold-Start Fix Plan

## Purpose

This document explains the current userspace cold-start / `MissingNeighbor`
behavior, what we already changed to improve it, what is still missing, and
how I would finish the design so startup is deterministic instead of timing-
dependent.

This is intentionally separate from
[`userspace-cold-start-resolution.md`](./userspace-cold-start-resolution.md).
That document captures the fixes we landed and the behavior we observed at the
time. This document is the gap analysis and the forward plan.

## Short Version

We improved the symptom path, but we did not finish the control-plane model.

Today the system relies on a mix of:

- static neighbors baked into the initial snapshot
- periodic Go-side neighbor refresh
- a Rust-side netlink neighbor monitor
- opportunistic neighbor learning from RX traffic
- a `MissingNeighbor` buffer-and-retry path with raw ICMP probes
- a time-based global `ctrl.Enabled` delay

That combination can work, but it is not a clean startup contract.

The missing piece is not "one more probe." The missing piece is:

1. a single authoritative neighbor publisher
2. a generation-based neighbor update model
3. a readiness FSM for startup/enable
4. a clear split between infrastructure-neighbor prewarm and arbitrary first-hit host learning

Until we do that, cold start remains sensitive to timing and restart order.

## What We Already Changed

The following changes were directionally correct and should be kept:

1. Fill-ring bootstrap and heartbeat deadlock fixes
   - pre-bind fill-ring priming
   - removal of `xsk_rx_confirmed` heartbeat gating

2. `MissingNeighbor` fast recovery path in the helper
   - create a session immediately on `MissingNeighbor`
   - buffer the original packet in `pending_neigh`
   - trigger kernel ARP/NDP via raw ICMP/ICMPv6 sockets
   - retry buffered packets even on empty RX polls

3. ARP ownership moved back to the kernel
   - non-IP traffic is passed back so the kernel remains the ARP owner

4. Go-side proactive neighbor refresh
   - manager periodically reads the kernel neighbor table
   - manager pushes neighbor snapshots to the helper
   - **#5104 — the status-loop async prewarm scan is now bounded.** The status
     loop (`process_status.go`) kicks `proactiveNeighborResolveAsyncLocked`
     every 1s for the first 60s, then every 10s on HA standby. Each scan does
     route-indexed neighbor dumps and a probe sweep, which can outlast its tick
     under slow netlink or a large RIB. The prewarm is now:
     - **singleflight** — a lock-free `neighborPrewarmInFlight` CAS guard
       (`manager.go`) coalesces overlapping ticks onto the running scan; a
       second scan never starts while one is in flight. The guard clears when
       the scan goroutine returns (via `defer`, so a panic also clears it).
     - **deadline-bounded** — each scan runs under a
       `neighborPrewarmDeadline` (15s) context and checks it between netlink
       dumps, so a slow netlink layer cannot pin the guard indefinitely; the
       next tick spawns a fresh scan. (vishvananda/netlink calls are not
       context-cancelable mid-syscall, so the deadline bounds the between-dump
       loop, not a single wedged syscall.)
     - **bounded probe pool** — `runBoundedNeighborProbes` (`process_napi.go`)
       fans probes out through a fixed `neighborPrewarmProbeWorkers` (8) pool
       instead of one goroutine per target, so a large resolve set cannot
       multiply goroutines every tick.
     - **one neighbor dump per link per scan** — the scan caches
       `NeighList(FAMILY_ALL)` per link index, collapsing the old
       per-route re-dump.
     Regression: `neighbor_prewarm_singleflight_5104_test.go`.

5. Rust-side dynamic learning paths
   - netlink neighbor monitor
   - ARP/NA learn path on RX
   - source-neighbor learn path from normal IP packets

These changes reduced the worst behavior, but they do not solve the design gap
below.

## Current Design Gap

### 1. Neighbor ownership is split across too many paths

Current sources of truth:

- `state.neighbors` built from the initial snapshot in `build_forwarding_state()`
- Go-side periodic `update_neighbors`
- Rust netlink `neigh_monitor_thread()`
- opportunistic `learn_dynamic_neighbor_from_packet()`
- ARP/NA learn path from received control traffic

That is too many writers for startup-critical state.

The helper currently treats the manager refresh as a cache insert path, not as
an authoritative state publication.

Concrete example:

- `refreshNeighborSnapshotLocked()` in `pkg/dataplane/userspace/manager.go`
  sends `ControlRequest{Type: "update_neighbors"}`.
- `"update_neighbors"` in `userspace-dp/src/main.rs` only inserts into
  `dynamic_neighbors`.
- It does not rebuild forwarding state.
- It does not replace the helper's neighbor view.
- It does not remove stale/deleted entries.
- It has no generation or ack.

So neighbor publication is currently advisory, not authoritative.

### 2. Startup enable is time-based, not readiness-based

`applyHelperStatusLocked()` still uses a fixed delay:

- 3s in non-HA
- 15s in HA

Then it flips global `ctrl.Enabled`.

That is a heuristic, not a correctness condition.

It does not prove that:

- all required AF_XDP bindings are actually usable
- local VIP/source addresses are present
- required infrastructure neighbors are available
- the helper has installed the latest neighbor generation
- the `MissingNeighbor` safety path is live and ready

This is the core reason cold start still depends on races.

### 3. The manager still shells out to `ping`

`bootstrapNAPIQueuesLocked()`, `proactiveNeighborResolveLocked()`, and
`proactiveNeighborResolveAsyncLocked()` still use `exec.Command("ping"...)`
and `ping6`.

That creates three problems:

1. timing is nondeterministic
2. readiness cannot be acknowledged precisely
3. startup depends on external processes rather than an explicit state machine

Those shellouts may help warm the path, but they are not a sound startup model.

### 4. We do not distinguish infrastructure neighbors from arbitrary hosts

There are two different cold-start cases:

1. infrastructure prerequisites
   - default gateways
   - fabric peers
   - HA/control/sync peers
   - any mandatory next-hop required for normal forwarding

2. arbitrary first-hit destinations
   - e.g. a newly provisioned on-link server at its assigned address

These must not be solved the same way.

We can and should prewarm infrastructure neighbors before enabling redirect.
We cannot prewarm every possible host neighbor on a connected subnet.

Arbitrary first-hit destinations should be handled by the existing
`MissingNeighbor` buffer-and-retry path, but only after the startup system
itself is known-good.

### 5. The helper neighbor model is additive-only

Current issues:

- `update_neighbors` inserts only
- `neigh_monitor_thread()` inserts only
- opportunistic learning inserts only
- stale/failure/delete handling is not authoritative

That means the helper cache can drift away from the kernel neighbor table over
time. Even if that is not the initial cold-start bug, it makes startup and
post-restart behavior harder to reason about.

## What We Are Missing

The missing architecture is:

### A. One authoritative neighbor publisher

The Go manager should own the authoritative neighbor view that the helper uses
for forwarding decisions.

That means:

- maintain a live kernel-neighbor view in Go
- publish it with a monotonically increasing `neighbor_generation`
- send either:
  - full replacement at startup/resync, or
  - diff updates with add/update/delete semantics

The helper should stop treating manager neighbor updates as a best-effort side
cache.

### B. A clear helper data model

The helper should separate:

1. authoritative neighbors
   - published by the manager
   - generation-tagged
   - replaceable/removable

2. opportunistic learned neighbors
   - local helper observations from RX
   - short-lived
   - subordinate to the authoritative view

Forwarding lookups should consult:

1. authoritative neighbor table
2. opportunistic table

not a single undifferentiated `dynamic_neighbors` map with multiple writers.

### C. A startup readiness FSM

We need an explicit startup state machine, not a sleep.

Suggested phases:

1. `helper_started`
   - control socket ready
   - workers created

2. `bindings_ready`
   - all required bindings are registered/bound
   - per-binding queue bootstrap complete if needed

3. `local_addrs_ready`
   - HA VIP/local source addresses present

4. `infra_neighbors_ready`
   - required gateway/fabric/control peers known-good
   - based on manager-owned authoritative view

5. `ctrl_enabled`
   - only after phases 1-4 are satisfied

This should be evaluated per dataplane role, not only as one global timer.

### D. `MissingNeighbor` as safety net, not startup mechanism

The current helper `MissingNeighbor` path is good and should stay:

- trigger kernel ARP/NDP via raw ICMP
- buffer the packet
- create the session immediately
- retry on empty RX polls

But this should be the recovery path for arbitrary first-hit destinations,
not the primary mechanism we rely on to make startup work at all.

### E. In-process warmup, not shell-outs

Replace manager `ping`/`ping6` shell-outs with explicit in-process actions:

- netlink `RTM_NEWNEIGH` / `RTM_GETNEIGH` driven refresh
- raw ICMP/ICMPv6 probes where active resolution is needed
- any queue bootstrap trigger should be explicit and internally measurable

This gives us deterministic behavior and proper observability.

## Concrete Code Problems To Fix

### 1. `update_neighbors` needs generation and replacement semantics

Current:

- manager sends `Type: "update_neighbors"`
- helper inserts into `dynamic_neighbors`

Required:

- add `neighbor_generation`
- add "full replace" vs "delta" mode
- helper tracks installed generation
- helper reports installed generation in status
- manager waits for the expected generation before enabling redirect

### 2. Authoritative and opportunistic neighbors need separate storage

Current:

- `state.neighbors` from initial snapshot
- `dynamic_neighbors` for everything else

Required:

- `authoritative_neighbors`
- `learned_neighbors`
- deterministic merge order
- explicit aging/removal rules for learned entries

### 3. `ctrl.Enabled` needs readiness gates

Current:

- delay 3s/15s

Required:

- gate on:
  - bindings ready
  - local addresses ready
  - infrastructure neighbors ready
  - helper-installed neighbor generation

This likely belongs in `applyHelperStatusLocked()`.

### 4. Infrastructure next-hop set needs to be explicit

Manager should compute a startup-required neighbor set from config:

- route gateways
- fabric peer addresses
- native GRE outer next-hops
- control/sync peers if relevant

Do not attempt to prewarm every possible on-link destination.

### 5. Observability is insufficient

We need status fields for:

- current `neighbor_generation`
- last installed `neighbor_generation`
- authoritative neighbor count
- learned neighbor count
- required infrastructure neighbors ready / total
- pending-neighbor queue depth
- probe attempts / successes / timeouts
- first-hit buffered packet count

Without this, cold-start debugging stays anecdotal.

## Proposed Implementation Plan

### Phase 1: Make neighbor updates authoritative

1. Extend control protocol with:
   - `neighbor_generation`
   - `replace_neighbors`
   - `neighbor_deltas`

2. In the helper:
   - add `authoritative_neighbors`
   - move current manager-fed entries there
   - keep `learned_neighbors` separate

3. In status:
   - report installed generation and counts

### Phase 2: Replace time-based enable with readiness gating

1. Compute required startup neighbors in the manager
2. Wait for:
   - bindings ready
   - addresses ready
   - authoritative generation acknowledged
   - required neighbor set ready
3. Only then enable `ctrl`

Keep the current delay only as a hard timeout fallback during transition, not
the primary gate.

### Phase 3: Remove shell-out warmup

1. Delete `exec.Command("ping")` warmup paths
2. Replace with:
   - netlink-driven neighbor refresh
   - raw ICMP probes for missing required neighbors
3. Make every probe counted and visible

### Phase 4: Retain `MissingNeighbor` buffer-and-retry for arbitrary hosts

Keep the existing helper path for first-hit host destinations:

- session creation on miss
- raw ICMP probe
- packet buffer
- retry on empty RX poll

That path remains important even after startup is fixed.

### Phase 5: Tighten tests

We need explicit cold-start tests for:

1. daemon restart with empty/stale neighbor table
2. first IPv4 SYN to a new on-link destination
3. first IPv6 SYN to a new on-link destination
4. HA restart with VIP delay
5. cold startup with no preexisting kernel neighbors
6. cold startup where infra neighbors are ready but destination host is new

Acceptance should be:

- no indefinite timeout
- no dependence on a second TCP retransmit
- first connection succeeds within a bounded latency budget
- neighbor generation and readiness visible in status

## Recommended End State

The clean model is:

1. kernel remains authoritative for ARP/NDP resolution
2. manager is authoritative for publishing usable neighbors to the helper
3. helper owns a fast, generation-aware forwarding cache
4. startup redirect is enabled by readiness, not time
5. arbitrary first-hit destinations use `MissingNeighbor` buffer-and-retry as a safety net

That is the missing step between "we added enough tricks to make it usually
work" and "cold startup is deterministic."

## Bottom Line

The current code added several good recovery paths, but it did not complete the
control-plane contract.

What we are missing is not another ARP trick. We are missing:

- authoritative neighbor publication
- generation-aware helper state
- readiness-based enable
- a clean distinction between infrastructure warmup and arbitrary host cold miss

That is how I would solve the cold-start problem from here.
