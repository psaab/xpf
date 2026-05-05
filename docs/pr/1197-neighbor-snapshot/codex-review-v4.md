# Codex round-4 PLAN review — #1197 v4

Task ID: task-mosxc7qs-s8f330
Codex session ID: 019df943-679a-7eb3-8405-101fdcf9f639

---

**Verdict: PLAN-NEEDS-MAJOR**

The kernel-as-authority premise is right, but v4 is not implementation-ready yet.

Findings:

1. The STALE probing hole is only partially closed. `forceProbeNeighbors` exists in the plan, but `collectMonitoredNeighbors` is undefined, and section 7 still relies on `resolveNeighbors`, which currently skips `NUD_STALE` entries (`daemon_neighbor.go:323`). PR1 must define probe targets to match the snapshot keyspace: current snapshot keys plus kernel `NeighList` entries on the exact snapshotted interfaces, plus configured next-hop/NAT/address-book targets. Also call the force path on RG takeover, not only on the 15s tick.

2. The listener resubscribe sketch is broken. The `break` exits the `select`, not the inner loop, so a closed `updates` channel can spin and double-close `done`. Use a labeled break or wrap one subscription lifetime in a helper that returns. Also set `ReceiveBufferSize`; channel size 1024 is not the same as enlarging the netlink socket receive buffer.

3. The "forwarding-effective diff" is in the wrong layer. `shouldTriggerRegen` filters some event churn, but `RegenerateNeighborSnapshot()` still plans to use exact `neighborsEqual`, and the current comparator includes raw state (`snapshot.go:160`). The 60s safety tick and `BumpFIBGeneration` can still publish on harmless `REACHABLE -> STALE` churn. Add a manager-level forwarding-effective equality: key, MAC, and usable/unusable status.

4. The filter still needs to be exactly the `buildNeighborSnapshots` keyspace. The code iterates all configured interface base names and units (`snapshot.go:1758`), not an informal "forwarding/fabric" subset. Either reuse/export that interface enumeration or stop publishing neighbors outside the listener filter.

5. `shouldTriggerRegen` misses usable new states. Userspace treats every state except `failed` and `incomplete` as usable (`forwarding/mod.rs:45`), so new `DELAY`, `PROBE`, and possibly `NOARP` entries with a MAC should trigger too, unless you intentionally change the usable-state policy everywhere.

Answers to section 11:

1. 15s probing is safe only with target prioritization. Normal 50-100/min is fine. A 256 cap at 15s is about 17 targets/sec, doubled for IPv6 NS+ICMP, still manageable but noisy. Probe stale/probe/delay and priority next-hops first; don't blindly probe every reachable entry.

2. `NUD_NOARP` must be handled consistently. If userspace keeps treating `noarp` as usable, include `NOARP` with a valid MAC. If it should not forward, filter it out in both Go snapshot publishing and Rust update parsing.

3. 60s safety tick is acceptable after the event path is fixed and forwarding-effective diff exists. I would not use 10s as the default; it hides listener bugs and increases full-table churn.

4. Yes, dynamic fallback contains kernel-learned data. The helper has its own netlink dump/subscribe path (`neighbor.rs:423`), and lookup falls back to it (`forwarding/mod.rs:1476`). But static `state.neighbors` wins first, so stale manager-published entries still shadow dynamic ones.

5. One PR is fine only if delete + listener + force-probe + regen diff ship atomically. Do not ship deletion alone. Internal progressive commits are fine; externally this should land as one replacement of the broken mechanism.

Round-3 status: #3 is mostly addressed, #1/#2/#4 are still only partially addressed. Not a kill, but still major revision before implementation.
