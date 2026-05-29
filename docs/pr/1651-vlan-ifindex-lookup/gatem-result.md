# #1651 Gate-M result — ifindex-mismatch hypothesis REFUTED

**Date**: 2026-05-29
**Cluster**: `loss:xpf-userspace-fw0/fw1` (fw0 active, RG owner of reth0.80)
**Target**: on-link `172.16.80.200` on `ge-0-0-2.80` (VLAN 80)
**Base**: origin/master @ `67258de88`

## Verdict

Gate-M **REFUTES** the lead hypothesis (Root cause A′, ifindex
key-mismatch). The proposed parent-ifindex fallback in
`lookup_neighbor_entry` would query an ifindex the kernel never
populates, so it would be a no-op. Per the /engineer kill-gate
instruction ("If Gate-M REFUTES the mismatch ... STOP and report — the
fix would be wrong"), the fix is NOT shipped. No PR.

## Topology confirmed

```
14: ge-0-0-2.80@ge-0-0-2  (logical VLAN sub-interface)   <- egress_ifindex used by lookup
 6: ge-0-0-2              (physical parent, XDP attached) <- bind_ifindex / resolve_tx_binding_ifindex(14)
```

`EgressInterface.bind_ifindex` for egress 14 = parent 6
(`forwarding_build/interfaces.rs:135`, `iface.parent_ifindex`).
`resolve_tx_binding_ifindex(forwarding, 14)` → 6. So the proposed
fallback, on a miss for `(14, target)`, would additionally look up
`(6, target)`.

## The decisive measurement (kernel-reported learn ifindex)

`ip -ts monitor neigh` on fw0 (the exact RTM_NEWNEIGH netlink stream
`parse_neighbor_msg` consumes) during a cold connect:

```
[..] 172.16.80.200 dev ge-0-0-2.80 lladdr ea:de:15:f5:66:70 REACHABLE
```

The kernel learns the on-link neighbor under **`ge-0-0-2.80` (logical
ifindex 14)** — the SAME ifindex the lookup keys on — NOT the physical
parent (6). Confirmed independently by:

- `ip -d neigh show to 172.16.80.200` → `dev ge-0-0-2.80`
- `cli -c 'show arp'` → `172.16.80.200 ge-0-0-2.80 reachable`
- in-binary throwaway instrumentation in `parse_neighbor_msg` logging
  the raw netlink `ifindex` field: every 172.16.x learn arrived under
  its logical ifindex (e.g. `GATEM-LEARN ifindex=13 ip=172.16.50.1`,
  the .50 VLAN logical), never the parent (6).

There is no parent-vs-logical asymmetry on the netlink learn path for
this kernel/driver (mlx5 native XDP on `ge-0-0-2`). The plan's premise
that the ZC→skb path delivers the reply to the physical parent (so the
kernel keys the entry under the parent) does NOT hold here — the kernel
demuxes to the logical sub-interface and keys the entry there.

## Cold-connect timing — no reproducible regression

10 trials, daemon settled, full `ip neigh flush all` on BOTH firewall
and client before each, 2s settle:

```
3.7, 1.6, 1.6, 0.8, 1.4, 0.6, 1.0, 1.5, 1.0, 1.7  (ms)
```

All single-digit ms — already the acceptance target. No `GATEM-RETRY`
(MissingNeighbor / pending_neigh) events fired during any settled-daemon
cold connect.

The ~1.7s figure DID reproduce, but only on the very first connect after
a long idle / immediately inside the daemon-restart startup
neighbor-dump window (a few hundred ms where `request_neighbor_dump`
races a concurrent flush). It is a startup transient, not a per-cold-
connect dataplane defect, and is not correlated with any ifindex
mismatch. Once the daemon is past its startup dump, cold connects are
0.6-3.7ms regardless of kernel/userspace neighbor-cache state.

## Why the fix would be wrong

1. Kernel keys the entry under logical ifindex 14; lookup keys on 14 →
   already hits. The `(6, target)` fallback queries an ifindex with no
   entry → no-op.
2. Steady-state on-link cold connect already meets the single-digit-ms
   gate with zero changes.
3. The 1.7s transient is in daemon startup, not the lookup path; a
   lookup-key fallback cannot affect it.

## Scope disposition

- #1651 native AF_PACKET resolver: KILLED (already established by the
  research plan — cites the deleted `send_raw_frame` tombstone at
  `neighbor.rs:29`, still a dangling doc comment on origin/master).
- The §6 ifindex fix: NOT shipped — Gate-M refutes its premise.
- #1648 (on-link warming): remains OPEN and orthogonal. The startup-
  window transient is exactly the class of thing a warm-on-bringup pass
  would smooth; #1648 is the right home for it, not a lookup-key change.

## Hygiene

Throwaway instrumentation (eprintln in `parse_neighbor_msg` +
`retry_pending_neigh`) was reverted; the cluster was restored to a
clean origin/master build (`strings | grep GATEM` → 0). No code change
proposed.
