# Codex round-1 PLAN review — #1197 v1

Task ID: task-moswpn47-2wyqtu
Codex session ID: 019df933-5954-79b2-b0ed-5c73a67ca52a

---

**Verdict: PLAN-NEEDS-MAJOR**

Findings:

1. The plan only fixes the second loop, but the first loop is also dangerous. `daemon_neighbor.go:49` reads every kernel neighbor and reinstalls it as `NUD_REACHABLE` (line 61), unless `FAILED/NOARP`. That means a `STALE` conflicting entry is promoted to `REACHABLE` before the proposed snapshot-conflict check runs. The STALE failover question is therefore not actually controlled by Option A as written.

2. Skip-on-conflict has no authority model. In steady state, kernel-learned `REACHABLE/STALE/DELAY/PROBE` should probably beat a cached snapshot. During takeover, a peer snapshot may beat the standby's old `STALE` cache. One unconditional rule cannot satisfy both. Do not globally force-overwrite `STALE`, because a freshly learned MAC will age to `STALE` and the bug comes back. But do not globally skip `STALE` during promotion either. The plan needs context: steady-state periodic refresh vs explicit takeover/prepare path.

3. A1 is mandatory, not optional. The userspace helper checks static snapshot neighbors before dynamic netlink-learned neighbors: `forwarding/mod.rs:1464`. So even if Go stops reverting kernel ARP, a stale `snapshot.neighbors` entry can still win inside userspace forwarding. `Manager.RegenerateNeighborSnapshot()` does not exist. The closest existing path is `BumpFIBGeneration()` (manager.go:421), which rebuilds via `buildNeighborSnapshots()` and publishes `update_neighbors`. A real fix needs that behavior as an explicit neighbor-refresh API.

4. `NeighListExecute` is not wrong, but it is gratuitous here. In netlink v1.3.1, `NeighList(linkIndex, family)` is just a wrapper over `NeighListExecute`. Use `NeighList` unless filtering flags/state. Also do not dump per snapshot entry; index one dump per `(ifindex,family)`. Use state bitmasks, not `==`, and decide how `PERMANENT` should behave.

5. IPv6 is in scope whether the plan wants it or not. Current code loops over v4 and v6 and snapshot preinstall sets both as `NUD_REACHABLE`. `SnapshotNeighbors()` drops state/router/link-local detail. A v4-only fix leaves the same stale-injection class for NDP.

Option D: pure event-driven-on-RG-transition is not ready as a replacement. This commit explicitly says HA transitions must not start neighbor repair in `UpdateRGActive()` (manager_ha.go:405), and the periodic path is the current readiness mechanism. But the periodic path should stop being a blind `NeighSet` writer. Keep background readiness, but make writes authority-aware and missing-only outside takeover context.

---

# Gemini Pro 3 — failed (ACP timeout, 8th today)
