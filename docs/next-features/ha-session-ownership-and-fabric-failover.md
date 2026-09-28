# HA Session Ownership And Fabric Failover

> [!IMPORTANT]
> DPDK retired in #1525. All DPDK-parity bullets/sections below are
> obsolete — implementations should target only the userspace
> AF_XDP backend and (transitionally) legacy eBPF.

## Summary

This note captures the current HA failover analysis around active/active
session ownership, fabric forwarding, and peer-owned RG failover behavior.

The highest-value problem is issue `#185`:

- session ownership is currently inferred from `IngressZone`
- active/active ownership is really per RG / per resolved egress path
- that mismatch affects near-real-time sync, bulk sync reconciliation, and GC

Related issues:

- `#185` HA session-sync: per-zone ownership mapping is not safe for active/active zones spanning multiple RGs
- `#186` HA failover gating: sync readiness is decoupled from fabric redirect readiness
- `#187` `xdp_zone`: `NO_NEIGH` active/active check drops VLAN context and can skip required fabric failover
- `#188` HA readiness: `RGInterfaceReady` treats missing local interfaces as peer-owned and can falsely unblock takeover
- `#189` HA readiness: `RGVRRPReady` reports ready when an RG has no local VRRP instance

## Main Findings

### 1. Session ownership is modeled by zone, not by actual owning RG

Current behavior:

- Session state stores `IngressZone` / `EgressZone`, but not owner RG.
- `SessionSync.ShouldSyncZone()` decides whether to sync a session from the
  session ingress zone.
- The daemon builds a `zone -> RG` map by picking the first RETH interface
  found in each zone.

Why this is wrong:

- a zone is a policy concept, not an ownership identity
- a single zone can span interfaces owned by different RGs
- a new session is actually owned by the RG of the resolved egress interface
  on the node that creates it

Impact:

- the wrong node can decide to sync or not sync a session
- bulk reconciliation can delete or retain the wrong sessions
- ownership correctness depends on zone layout, which is the wrong abstraction

Code paths:

- `pkg/cluster/sync.go`
- `pkg/daemon/daemon.go`
- `pkg/dataplane/types.go`
- `bpf/headers/xpf_conntrack.h`

### 2. `NO_NEIGH` failover handling drops VLAN context (historical diagnosis; not a current call path)

> **Historical diagnosis — not a current call path.** This section records an
> earlier BPF implementation/design claim. The cited `bpf/xdp/xdp_zone.c` file
> is not present in the current tree; `check_egress_rg_active` remains only as
> an unused header definition with no `.c` caller. Do not treat the following
> call/path list as current source documentation.

In the `BPF_FIB_LKUP_RET_NO_NEIGH` path, the active-active check calls
`check_egress_rg_active(fib.ifindex, 0)`.

That is wrong for VLAN-backed RETH traffic because interface zone lookups are
keyed by `{physical_ifindex, vlan_id}`. Dropping the VLAN ID can make the local
node believe the egress RG is active when it is not, which skips required
fabric redirect.

Impact:

- asymmetric failover behavior
- local kernel fallback instead of cross-chassis forwarding
- intermittent session stalls during RG movement

Code paths in the historical diagnosis:

- `bpf/xdp/xdp_zone.c`
- `bpf/headers/xpf_helpers.h`
- `pkg/dataplane/compiler.go`

### 3. Readiness gates are still too permissive

The current readiness model can declare takeover readiness before the local
dataplane and ownership path are actually usable.

Problems:

- missing interfaces can be treated as peer-owned instead of local failure
- VRRP readiness can be satisfied by unrelated RG instances
- sync readiness is independent of actual fabric redirect readiness

Impact:

- takeover can be allowed before the local forwarding path is ready
- failover timing depends on control-plane state that is not sufficient for
  data-plane correctness

Code paths:

- `pkg/cluster/monitor.go`
- `pkg/vrrp/manager.go`
- `pkg/daemon/daemon.go`

### 4. Fabric redirect still prefers `fab0` too aggressively

Fabric redirect always tries `fab0` first and uses neighbor reachability that
is not a strong enough signal for peer forwarding health.

Impact:

- traffic can keep getting sent to a stale `fab0` path
- a dead or wedged peer can still look usable if neighbor state survives

Code paths:

- `bpf/headers/xpf_helpers.h`
- `pkg/daemon/daemon.go`

## Concrete Implementation Plan For `#185`

### Goal

Move session ownership from a derived zone-based model to an explicit
per-session owner RG model.

### 1. Add authoritative owner identity to session state

Add `OwnerRGID` to the authoritative session value structs:

- `pkg/dataplane/types.go`
- `bpf/headers/xpf_conntrack.h`
- ~~`dpdk_worker/shared_mem.h`~~ (DPDK retired #1525)
- ~~`pkg/dataplane/dpdk/dpdk_cgo.go`~~ (DPDK retired #1525)

Guidelines:

- use `uint16`
- append it near the end of the session value structs to minimize hot-path
  layout disruption
- keep reverse entries on the same owner RG as the forward entry

### 2. Add owner RG to packet metadata and stamp it from the resolved egress path

The correct ownership signal already exists at FIB resolution time.

`xdp_zone` resolves the egress interface and has access to `iface_zone_value`,
which already carries `rg_id`. That value should be copied into `pkt_meta`
before policy/session creation.

Files:

- `bpf/headers/xpf_common.h`
- `bpf/xdp/xdp_zone.c`
- ~~DPDK equivalents in `dpdk_worker/zone.c` and metadata definitions~~ (DPDK retired #1525)

Rule:

- transit session owner = resolved egress RG
- standalone / non-RETH session owner = `0`
- reverse entry keeps the same owner RG as forward

### 3. Stamp `OwnerRGID` everywhere sessions are created

XDP:

- `bpf/xdp/xdp_policy.c`
- `bpf/tc/tc_conntrack.c`

~~DPDK:~~

- ~~`dpdk_worker/conntrack.c`~~ (DPDK retired #1525)

The owner must be assigned at creation time, not reconstructed later from
zones.

### 4. Replace zone-based sync decisions with owner-based decisions

Add `ShouldSyncOwnerRG(rgID uint16)` in `pkg/cluster/sync.go`.

Then switch these paths from `IngressZone` ownership to `OwnerRGID`:

- event-driven session-open sync
- periodic sync sweep
- bulk sync filtering
- stale reconciliation

Zone-based logic should remain only as backward-compatible fallback while mixed
versions can still exist.

### 5. Extend the sync wire format by appending `OwnerRGID`

Append the new field to the existing session payloads in:

- `pkg/cluster/sync.go` encode paths
- `pkg/cluster/sync.go` decode paths

The current decode logic is already length-tolerant, so appending the field is
the safest rolling-upgrade shape:

- old sender -> new receiver: missing `OwnerRGID`, fallback path
- new sender -> old receiver: trailing bytes ignored

### 6. Change bulk reconciliation to snapshot owner RG ownership, not zone ownership

Current bulk reconciliation snapshots zone ownership at `BulkStart`.

That needs to become owner-RG ownership:

- replace zone ownership snapshot state with owner-RG snapshot state
- reconcile peer-owned sessions using `OwnerRGID`
- stop deleting or preserving sessions based on `IngressZone`

### 7. Fix GC ownership at the same time

This is part of the same bug.

Today GC expiry is globally gated by `IsLocalPrimaryAny()`. That means a node
that is primary for one RG can still expire sessions belonging to other RGs.

Required change:

- add `IsLocalPrimaryForRG func(rgID uint16) bool` to GC
- expire only sessions whose `OwnerRGID` is locally primary
- only emit delete sync for sessions whose owner RG is locally primary

This keeps delete messages key-only; the sender should simply never emit
ownership-invalid deletes.

### 8. Preserve owner on sync receive

When a forward session is received from the peer, keep its `OwnerRGID`.

When the standby synthesizes the reverse entry, copy the same owner RG. Reverse
traffic swaps zones, but ownership does not.

### 9. Test plan

Add coverage for:

- same ingress zone, different `OwnerRGID`
- sync sweep only sends locally-owned owner RG sessions
- bulk sync only sends locally-owned owner RG sessions
- stale reconciliation only deletes peer-owned owner RG sessions
- GC only expires sessions for locally-owned owner RGs
- reverse entry creation preserves `OwnerRGID`

Keep the existing zone-based tests only as fallback compatibility coverage.

### 10. Suggested PR split

Recommended implementation order:

1. session structs + wire format + sync filtering + bulk reconciliation
2. dataplane owner stamping in XDP / TC (~~DPDK~~ retired #1525)
3. GC per-owner expiry and delete behavior

That keeps review scope narrow and makes rollback safer if HA regressions appear.

## New Connection Packet Walk For Peer-Owned RG

This is the path for a brand-new flow that arrives on node A while the active
forwarding RG is on node B.

### 1. Packet enters `xdp_main`

`xdp_main` parses the packet, resolves ingress zone from
`iface_zone_map`, and tail-calls either `xdp_screen` or `xdp_zone`.

Files:

- `bpf/xdp/xdp_main.c`
- `bpf/headers/xpf_helpers.h`

### 2. Screen stage runs, if needed

If screen checks are required, `xdp_screen` runs before `xdp_zone`.

Important constraint:

- at this point, screen decisions still use the local fabric interface zone
- a zone-encoded fabric packet has not been decoded yet

### 3. Original node does FIB in `xdp_zone`

For a new connection there is no existing session, so `xdp_zone` performs the
normal FIB-based forwarding decision.

If the resolved egress interface belongs to an RG that is not locally active,
the packet is treated as a new connection for a peer-owned RG.

### 4. Original node performs zone-encoded fabric redirect

`try_fabric_redirect_with_zone_cached()` rewrites the source MAC to encode the
original ingress zone and redirects to `fab0` or `fab1`.

Encoding:

- source MAC `02:bf:72:fe:00:ZZ`
- `ZZ` = original ingress zone ID

Files:

- `bpf/xdp/xdp_zone.c`
- `bpf/headers/xpf_helpers.h`

### 5. Peer receives the packet on fabric

On the peer, `xdp_zone` detects the fabric zone marker and restores the
original ingress zone from the source MAC.

It also forces routing table `254` because the fabric interface lives in
`vrf-mgmt` but the packet is transit traffic.

### 6. Zone-encoded packets stay on the full conntrack/policy path

These packets do not use the plain `FABRIC_FWD` bypass path.

That is correct because the peer has no existing session yet and must apply:

- pre-routing NAT
- conntrack miss handling
- policy lookup
- session creation

### 7. Peer creates the new session locally

`xdp_policy` creates the forward and reverse session entries using the decoded
original ingress zone and the peer’s resolved egress zone.

This is the point where the authoritative owner RG should be stamped.

### 8. Peer then syncs the session back to the other node

Today this re-enters the broken ownership model:

- near-real-time sync looks at the created session
- sync ownership is still decided by `ShouldSyncZone(val.IngressZone)`
- that can assign sync ownership to the wrong RG when zones span multiple RGs

This is why `#185` is the highest-value fix.

## Additional Gaps Surfaced By The Packet Walk

### 1. Zone decode happens too late for screen decisions

Zone-encoded fabric packets restore the original ingress zone in `xdp_zone`,
but screen behavior has already been chosen in `xdp_main` / `xdp_screen`.

That means new cross-chassis flows can apply the wrong screen profile or skip
the intended one.

This is a separate correctness gap from `#185`.

### 2. Plain fabric fallback for new flows is risky

In some unreachable / blackhole paths, a failed zone-encoded redirect can fall
back to plain fabric redirect.

Plain redirect loses the original ingress-zone provenance and can hand a truly
new flow to logic intended for already-validated fabric transit traffic.

This is also separate from `#185`.

## Recommended Priority

Priority order:

1. `#185` explicit per-session owner RG
2. `#187` preserve VLAN context in `NO_NEIGH` RG-active checks
3. `#186` couple readiness to actual fabric redirect readiness
4. tighten readiness correctness in `#188` and `#189`
5. address screen timing and unsafe plain-fabric fallback for new flows

## Practical Conclusion

The most important HA mismatch is that the dataplane already makes ownership
decisions per resolved egress path, but session sync and GC still reason in
terms of zones.

Until ownership becomes a first-class session attribute, active/active failover
will continue to have ambiguous behavior whenever zone layout does not match RG
layout exactly.
