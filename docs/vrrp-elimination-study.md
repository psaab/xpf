# Private RG Election: Replacing VRRP on Data-Plane Interfaces

## Problem Statement

VRRP on RETH interfaces floods every LAN segment with multicast traffic:

- **IPv4:** `224.0.0.18` (protocol 112) every 30ms per RETH member interface
- **IPv6:** `ff02::12` (protocol 112) every 30ms per RETH member interface
- 2 RGs × 2 interfaces (parent + VLAN) = **4 instances × 33 pkt/s = ~132 multicast pkt/s** on each LAN segment

Every host on the segment processes and discards this traffic. Every switch port floods it. The cluster already has a private control-plane interconnect (fxp1) carrying heartbeat traffic that includes per-RG state — we should be able to do election entirely over that private link.

## Why "Just Turn VRRP Off" Doesn't Work

We tried `no-reth-vrrp`. It caused **dual-active** — both nodes simultaneously acted as primary, both added VIPs, both sent GARPs. The boolean bug (`RethVRRP` defaulting to false) exposed the issue, but the underlying architectural problem is real: the heartbeat election has a **dual-active gap in non-preempt mode**.

## Root Cause: `electRG()` Non-Preempt Incumbent Bias

The election code in `pkg/cluster/election.go:157-163`:

```go
// Non-preempt: incumbent stays unless weight drops to 0.
if rg.State == StatePrimary {
    return electNoChange, "" // non-preempt: incumbent stays
}
```

When both nodes are primary (split-brain from transient heartbeat loss), **both** hit this line and **both** return `electNoChange`. Neither yields. The peer's primary state (line 165) is only checked when `rg.State != StatePrimary`.

In **preempt mode**, this self-resolves — the lower-priority node sees `localEff < peerEff` and demotes itself. But in **non-preempt mode**, incumbent bias means both stay primary forever.

**VRRP masks this gap.** When both VRRP instances advertise MASTER, RFC 5798 tie-breaking forces the loser to BACKUP within one advertisement interval. The VRRP state machine is the safety net that the cluster election lacks.

## What Actually Needs to Change

The heartbeat **already** carries per-RG state (GroupID, Priority, Weight, State) and **already** triggers `runElection()` on every received packet. We don't need a separate protocol — we need to fix the election and harden the direct-mode VIP management.

### What the heartbeat already provides

| Capability | Status |
|-----------|--------|
| Peer liveness detection | Done (configurable interval/threshold) |
| Per-RG state exchange (priority, weight, state) | Done (in every heartbeat packet) |
| Election on heartbeat reception | Done (`handlePeerHeartbeat` → `runElection`) |
| Election on peer loss | Done (`handlePeerTimeout` → single-node election) |
| Priority-based preemption | Done (higher effective priority wins) |
| Node ID tie-breaking | Done (lower node ID wins ties) |
| **Dual-active detection and resolution** | **Missing — this is the gap** |

### What VRRP provides that would go away

| VRRP Function | Replacement |
|--------------|-------------|
| VIP addition on MASTER | `directAddVIPs()` — already implemented |
| VIP removal on BACKUP | `directRemoveVIPs()` — already implemented |
| GARP bursts on MASTER | `directSendGARPs()` — already implemented |
| Dual-active resolution | **Fix `electRG()` — new** |
| Per-RG mastership reconciliation | **Harden reconcile loop — new** |

## Implementation Plan

### Phase 1: Fix Dual-Active in Election (Critical)

**`pkg/cluster/election.go` — `electRG()` non-preempt path:**

Add dual-active detection before the incumbent-stays shortcut:

```go
// Non-preempt: incumbent stays unless weight drops to 0.
// BUT: detect dual-active (both primary) and resolve immediately.
if rg.State == StatePrimary {
    if peerGroup.State == StatePrimary {
        // DUAL-ACTIVE: both nodes claim primary for this RG.
        // Resolve by effective priority, then node ID tie-break.
        // The lower-priority (or higher node ID) node must yield.
        if localEff < peerEff {
            return electLocalSecondary, "Dual-active: lower priority yields"
        }
        if localEff == peerEff && m.nodeID > m.peerNodeID {
            return electLocalSecondary, "Dual-active: higher node ID yields"
        }
        // We win — peer should yield on its next heartbeat.
        return electNoChange, ""
    }
    return electNoChange, "" // non-preempt: incumbent stays
}
```

**This is ~10 lines.** Both nodes receive each other's heartbeat, both see the dual-active, and the loser yields within one heartbeat interval. Same convergence guarantee as VRRP.

### Phase 2: Harden `no-reth-vrrp` Direct Mode

Gaps identified in the `control-link-only-reth-ownership` doc:

**2a. Reconcile removes stale VIPs (not just adds)**

Current code (`pkg/daemon/daemon.go:4747-4754`) only calls `directAddVIPs()` when active. Add removal:

```go
if noRethVRRP {
    if tr.Active {
        d.directAddVIPs(rgID)    // idempotent safety net
    } else {
        d.directRemoveVIPs(rgID) // remove stale VIPs on inactive RG
    }
}
```

**2b. Reconcile emits GARP on VIP correction**

If `directAddVIPs()` actually added any addresses (returns count > 0), emit a rate-limited GARP burst to update upstream MAC tables.

> **Dual-active reaffirm reconcile-fallback guarantee (#4867).** The
> "winner stays" resolution (`electRG` → `electNoChange`, reason
> `Dual-active: winner stays`) emits a `DualActiveWin` reaffirm event that
> the daemon turns into `scheduleDirectAnnounce` — the *only* signal that
> refreshes upstream ARP/NDP after a split-brain heals, because the winner
> never changed state (no `sendEvent` transition fires). That event is
> emitted through an inline non-blocking `select`; on a **full** `eventCh`
> it used to be silently dropped, bypassing the `onEventDrop` reconcile
> fallback that the normal `sendEvent` path uses, so the GARP/NA refresh was
> lost and peers held the losing node's MAC until cache aging.
>
> The drop now matches `sendEvent`'s reliable handling — it logs and fires
> `onEventDrop` (→ `triggerReconcile`) — **and** invokes a dedicated
> `onDualActiveWinDrop` callback that re-drives `scheduleDirectAnnounce`
> directly. The generic reconcile alone is not sufficient here: the
> direct-VIP ownership reconcile (2b) only re-announces on an *ownership
> change* (`announce = !prev || added > 0`), and a dual-active winner is
> already the steady owner (`prev = true`, `added = 0`), so
> `triggerReconcile` would not re-announce. The dedicated callback closes
> that gap so the post-split-brain refresh survives a saturated event
> channel.

**2c. Per-RG owner epoch in cluster manager**

Add `Epoch uint64` to `RedundancyGroupState`. Increment on every state transition. Include in heartbeat wire format (1 additional byte per RG, wrapping). Reject stale transitions when epoch mismatch detected.

This prevents a delayed/reordered heartbeat from causing a stale state flip after the real election has already resolved.

### Phase 3: Config Knob + VRRP Suppression

**`pkg/config/types.go`** — add `PrivateRGElection bool` to `ClusterConfig`.

**`pkg/config/ast.go`** — add `"private-rg-election"` schema node.

**`pkg/config/compiler.go`** — compile flag. Validation: warns if combined with `no-reth-vrrp` (redundant — `private-rg-election` implies it).

**`pkg/vrrp/vrrp.go`** — `CollectRethInstances()` returns nil when `PrivateRGElection` is true (same guard as `NoRethVRRP`).

**`pkg/daemon/daemon.go`** — `isNoRethVRRP()` returns true when either `NoRethVRRP` or `PrivateRGElection` is set.

Config:
```
chassis {
    cluster {
        cluster-id 1;
        private-rg-election;
    }
}
```

### Phase 4: Faster Heartbeat Option

The default heartbeat is 1000ms (3s detection). For environments wanting faster failover without VRRP:

```
chassis {
    cluster {
        heartbeat-interval 100;    /* 100ms */
        heartbeat-threshold 3;     /* 300ms detection */
        private-rg-election;
    }
}
```

No code changes — already configurable. Document the recommended tuning.

## Architecture Diagram

```
  ┌──────────┐                                    ┌──────────┐
  │   fw0    │                                    │   fw1    │
  │          │  Heartbeat + per-RG state           │          │
  │          │  (UDP 4784, fxp1, private)          │          │
  │          ├────────────────────────────────────→│          │
  │          │←────────────────────────────────────┤          │
  │          │                                    │          │
  │          │  Session sync (TCP, fab0/fab1)      │          │
  │          ├────────────────────────────────────→│          │
  │          │←────────────────────────────────────┤          │
  └──────────┘                                    └──────────┘

Heartbeat carries: per-RG (GroupID, Priority, Weight, State, Epoch)
Election runs on every heartbeat reception — detects + resolves dual-active.
No VRRP multicast on LAN interfaces.
No new protocol or socket needed.
```

## Why NOT a Separate Protocol

The earlier version of this doc proposed a separate UDP socket (port 4785) with its own advertisement format. After analyzing what exists:

**The heartbeat already IS the advertisement protocol.** It carries per-RG state, runs election on every packet, and uses the control link. Adding a second protocol would:

- Duplicate state that's already in the heartbeat
- Add socket management, timeout logic, and failure handling that already exists
- Create two sources of truth for per-RG election (heartbeat election vs. advertisement election)
- Require resolving conflicts between the two protocols

The only missing piece is **~10 lines in `electRG()`** to detect dual-active in non-preempt mode. A whole new protocol for that is overengineering.

**Timing:** If the heartbeat interval (100-200ms) isn't fast enough for detection, tune it. If you need VRRP-like 30ms detection, set `heartbeat-interval 30`. The heartbeat packet is small (~50 bytes) and runs on a private point-to-point link — there's no reason it can't run fast.

## Failure Scenarios

**Transient heartbeat loss → dual-active:**
- Both nodes elect themselves primary independently
- Next heartbeat from either side delivers peer state to the other
- `electRG()` detects both-primary, loser yields immediately
- Resolution time: one heartbeat interval (100-200ms typical)

**Sustained control link failure:**
- Heartbeat timeout → both nodes run single-node election → both claim primary
- No resolution possible without communication — same limitation as VRRP when all links fail
- Mitigation: peer fencing (`disable-rg`). Loss of all peer links cannot be
  resolved by a local helper lease while the daemon continues running.

**Daemon crash / SIGKILL:**
- The helper's receipt-anchored 10s forwarding lease expires after the last
  `update_ha_state` receipt; its per-packet check then treats the RG inactive.
- Peer heartbeat timeout → takes over all RGs
- Same as current VRRP behavior

**Stale heartbeat (delayed/reordered packet):**
- Epoch field (Phase 2c) rejects state transitions from stale packets
- Without epoch: benign — election re-evaluates on every packet, latest state wins

## Gaps in Current `no-reth-vrrp` to Fix

From `docs/next-features/control-link-only-reth-ownership.md`:

| Gap | Fix | Phase |
|-----|-----|-------|
| Reconcile only adds VIPs, never removes stale | Add `directRemoveVIPs()` for inactive RGs | 2a |
| No GARP on reconcile self-heal | Emit rate-limited GARP when VIPs corrected | 2b |
| No epoch/lease to reject stale transitions | Add epoch to RG state + heartbeat | 2c |
| No dedicated HA tests for direct mode | Event-drop simulation, crash loops, VIP ownership assertion | 2 |
| `strict-vip-ownership` incompatible | Validate in compiler (already done) | — |
| Failover timing depends on heartbeat tuning | Document recommended settings | 4 |

## Comparison: VRRP vs Private-RG-Election

| | VRRP (current) | Private RG Election (proposed) |
|--|------|-------------------|
| **LAN traffic** | ~132 multicast pkt/s per segment | Zero |
| **Election link** | LAN interfaces (multicast) | Control link fxp1 (unicast) |
| **Protocol** | RFC 5798 + cluster heartbeat | Cluster heartbeat only |
| **Sockets** | 4+ raw/AF_PACKET per RETH interface | 0 additional (reuse heartbeat) |
| **Dual-active resolution** | VRRP tie-break (~30ms) | Heartbeat tie-break (~100-200ms) |
| **Detection speed** | ~97ms (VRRP masterDown) | Configurable (heartbeat interval × threshold) |
| **Per-RG** | Separate VRID per RG | All RGs in heartbeat packet (already) |
| **New code** | 0 (exists) | ~10 lines election fix + ~100 lines hardening |
| **New protocol** | N/A | None needed |

## Migration Path

1. **Phase 1:** Fix dual-active in `electRG()` — safe to ship immediately, no behavioral change when VRRP is active (VRRP resolves it first anyway)
2. **Phase 2:** Harden `no-reth-vrrp` reconcile paths
3. **Phase 3:** Add `private-rg-election` config knob, suppress RETH VRRP
4. **Phase 4:** Document fast heartbeat tuning, run `test-failover` validation
5. **Future:** Consider making `private-rg-election` the default once battle-tested
