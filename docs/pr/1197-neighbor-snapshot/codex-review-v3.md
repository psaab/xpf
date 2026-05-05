# Codex round-3 PLAN review — #1197 v3

Task ID: task-mosx1zj8-7ekx8r
Codex session ID: 019df93c-1f59-7531-8fdc-43f5aa0d3b80

---

**Verdict: PLAN-NEEDS-MAJOR**

Findings:

1. The proposed "15s probe tick" does not do what the plan says. `resolveNeighborsInner` (`daemon_neighbor.go:323`) skips entries in `NUD_REACHABLE|NUD_STALE|NUD_PERMANENT`, so idle stale entries are not re-probed. Also, the 15s resolve tick already exists at `daemon_neighbor.go:427`; the extra HA behavior is the `preinstallSnapshotNeighbors()` call at line 468. As written, a standby can keep an old `STALE` MAC forever, activation-time `resolveNeighbors()` will skip it, and userspace-dp may keep forwarding to the old snapshot MAC.

2. The monitor filter is too narrow. `buildNeighborSnapshots()` publishes all kernel neighbors on configured interfaces, not just static next-hops/NAT/address-book/fabric entries (`snapshot.go:1758`). userspace-dp checks static `state.neighbors` before helper dynamic neighbors (`forwarding/mod.rs:1464`). So any stale snapshot entry outside the proposed filter can shadow the helper's correct netlink-learned dynamic entry. The filter must align with the snapshot keyspace: configured forwarding/fabric interfaces, or current snapshot keys plus monitored probe targets. VRRP VIPs themselves are not useful neighbor targets.

3. `RTM_NEWNEIGH` handling cannot be MAC-only. The plan's `snapshotDisagreesOrMissing(... HardwareAddr)` gate ignores state-only changes and failed/incomplete transitions. `RTM_DELNEIGH` also must trigger an immediate snapshot regenerate/removal; probing and waiting for a future `NEWNEIGH` leaves stale userspace entries if the peer is actually gone. If raw NUD state remains in `neighborsEqual()`, add a forwarding-effective diff to avoid publishing on harmless `REACHABLE -> STALE` churn while still removing unusable entries.

4. Netlink subscription is a good authority signal, but not a durable database. It is not only MAC changes: the kernel's rtnetlink neighbor family sends `RTM_NEWNEIGH`/`RTM_DELNEIGH` notifications for neighbor creation/deletion and many updates. But not every NUD transition is a notification, and multicast can be lost. Use `NeighSubscribeWithOptions` with an initial dump or run an initial `RegenerateNeighborSnapshot()`, add error callback/resubscribe, a larger receive buffer, and debounce/coalesce regeneration.

Direct answers:

1. Deleting `preinstallSnapshotNeighbors()` is directionally right. Keeping either `NeighSet` loop preserves the bug class. It is only safe if the replacement actually probes stale entries and republishes/removes userspace snapshot entries.

2. `NeighSubscribe` is not MAC-only, but it is not a complete "all NUD transitions" stream. Treat events as triggers for full reconciliation, with periodic safety reconciliation/probing.

3. Proposed `isMonitoredNeighbor` scope is wrong. Broaden it to match every neighbor that can be present in `state.neighbors`, or stop letting static snapshot neighbors shadow dynamic neighbors.

4. `40 probes/min` is fine, but the plan underestimates cardinality because address-book and on-link hosts can be much larger. Add a tunable/cap and log target counts.

5. Phase 1 is not self-contained as written. It does not necessarily need TTL if PR1 includes actual stale probing plus immediate regen on delete/unusable state and a broad filter. Without those, TTL/dynamic-first lookup is required before this is plan-ready.

Sources checked: local repo files above, vishvananda `NeighSubscribe` implementation, and Linux kernel rtnetlink neighbor docs: https://kernel.org/doc/html/latest/netlink/specs/rt-neigh.html.

---

# Gemini Pro 3 — failed (ACP timeout, 9th today)
