# IPv6 HA Failover Parity With IPv4

## Goal

Make IPv6 HA failover converge as predictably as IPv4, especially for:

- LAN default-gateway failover
- WAN neighbor convergence after RG move
- hard failover where the old primary cannot withdraw state cleanly

Related issues:

- #191: IPv6 failover lacks an NDP probe equivalent to the IPv4 ARP probe
- #193: failed-neighbor cleanup actively reprobes IPv4 only
- #192: per-node RETH MAC and link-local identity make IPv6 failover weaker than IPv4

## Current Behavior

IPv4 and IPv6 do not fail over using equivalent signals.

IPv4:

- VRRP/direct takeover moves the VIP
- gratuitous ARP is sent immediately
- an explicit ARP probe is sent toward the likely gateway/upstream cache
- neighbor cleanup also actively reprobes IPv4 FAILED entries

IPv6:

- VRRP/direct takeover moves the VIP
- unsolicited NA is sent for the VIP
- no equivalent NDP probe is sent during takeover
- FAILED IPv6 neighbors are deleted but not actively reprobed
- default-router role moves separately through Router Advertisements sourced from the interface link-local address

This means IPv6 failover has two convergence problems while IPv4 mostly has one:

1. VIP neighbor convergence
2. router identity convergence

## Code Paths

### RETH identity

- `pkg/cluster/reth.go`: `RethMAC(clusterID, rgID, rethIndex, nodeID)`
- `pkg/daemon/daemon.go`: programs per-node/per-RETH MACs and re-adds link-local addresses

The RETH index and node ID share the final MAC octet, so siblings in one RG
have distinct MACs; each node's MAC also differs, so the derived EUI-64
link-local address differs across nodes.

### IPv4 takeover path

IPv4 has stronger cache refresh behavior:

- `pkg/vrrp/instance.go`: `sendGARP()` sends GARP and then `SendARPProbe()`
- `pkg/daemon/daemon.go`: `directSendGARPs()` sends GARP and then `SendARPProbe()`
- `pkg/daemon/daemon.go`: `cleanFailedNeighbors()` actively reprobes IPv4 after deleting FAILED entries

### IPv6 takeover path

IPv6 currently does less:

- `pkg/vrrp/instance.go`: `sendGARP()` sends only `SendGratuitousIPv6Burst()`
- `pkg/daemon/daemon.go`: `directSendGARPs()` sends only `SendGratuitousIPv6Burst()`
- `pkg/cluster/garp.go`: `SendNDSolicitation()` exists but is not wired into the failover path
- `pkg/daemon/daemon.go`: `cleanFailedNeighbors()` does not actively reprobe IPv6

### Router Advertisement path

The RA sender uses the interface link-local address:

- `pkg/ra/sender.go`: `ndp.Listen(..., ndp.LinkLocal)`
- `pkg/ra/sender.go`: sends initial RA immediately when sender starts
- `pkg/ra/ra.go`: goodbye RA is sent only on graceful withdraw paths

The daemon already documents the resulting behavior:

- `pkg/daemon/daemon.go`: inactive RG startup-goodbye comments explain that hosts see each node as a separate IPv6 router because each node has a distinct link-local identity

## Why IPv4 Looks Better Today

IPv4 failover mainly requires VIP-to-MAC convergence.

IPv6 failover requires:

- VIP-to-MAC convergence for the address itself
- convergence of the router identity that hosts learned from RA

The unsolicited NA helps the first part.
It does not fully solve the second part.

This becomes much worse on hard failover:

- the old primary cannot send goodbye RA
- the new primary starts advertising a different router identity later
- hosts may keep the stale dead router until reachability and RA logic converge

## Immediate Low-Risk Fixes

These should be implemented first because they improve parity without changing the architecture.

### 1. Add an IPv6 NDP probe on takeover

Wire `SendNDSolicitation()` into the same failover paths where IPv4 currently sends `SendARPProbe()`.

Targets:

- VRRP `sendGARP()` path
- direct RG `directSendGARPs()` path

The first version should probe only the obvious next-hop / on-link gateway case, matching the IPv4 behavior as closely as possible.

### 2. Actively reprobe FAILED IPv6 neighbors

Extend `cleanFailedNeighbors()` so IPv6 does not rely purely on passive later traffic to trigger NDP.

This should be symmetric with the IPv4 FAILED-neighbor recovery logic.

### 3. Add observability

Expose enough counters/logging to see whether IPv6 failover is actually converging:

- unsolicited NA sent
- NDP probe sent
- FAILED IPv6 neighbor deleted
- FAILED IPv6 neighbor reprobed
- RA sender started/stopped per RG

## Medium-Risk Improvement

### Put RA startup closer to the failover critical path

Today IPv6 router identity movement is later and more indirect than IPv4 cache movement.

A safer intermediate step is:

- keep the RA service model
- but make immediate RA start/send a first-class part of RG activation timing
- avoid relying only on later reconcile loops for the new router identity to become visible

This still does not fix hard-fail stale-router identity completely, but it narrows the gap.

## Architectural Limit

The biggest remaining problem is the current per-node RETH identity design.

As long as failover changes:

- the L2 source identity
- the IPv6 link-local router identity

IPv6 will remain less seamless than IPv4, especially for hard crash failover.

To truly close that gap, one of these must eventually happen:

### Option A: Stable active router identity

Use the same effective RETH identity on either node when active.

That implies solving the reason shared MAC was removed earlier:

- both nodes are visible on the same L2 today
- identical active identities flap CAM/FDB state unless the inactive side is hidden from L2

### Option B: Hide the inactive side from L2

Keep only the active RG interface presenting the router identity.

That would make shared MAC and shared link-local more realistic, but it is a larger control-plane and interface-ownership change.

### Option C: Accept per-node identity and optimize around it

If the project keeps per-node MACs, then IPv6 failover needs explicit compensating machinery:

- better RA timing
n- active NDP probing
- stronger host/upstream convergence nudges
- clear expectation that hard-failover will not be as clean as IPv4

## Recommended Sequence

1. Implement NDP probe parity with IPv4 ARP probe.
2. Implement active reprobe for FAILED IPv6 neighbors.
3. Measure failover behavior again on graceful and hard-fail tests.
4. If IPv6 still lags materially, treat router identity continuity as the next architectural decision rather than continuing small dataplane tweaks.

## Non-Goals For The First Slice

Do not combine the first fix with:

- shared-MAC reintroduction
- broad RETH ownership redesign
- RA protocol redesign
- session-sync redesign

Those are larger changes and should be evaluated after the parity slice is measured.
