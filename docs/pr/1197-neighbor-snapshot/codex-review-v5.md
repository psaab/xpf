# Codex round-5 PLAN review — #1197 v5

Task ID: task-mosxmmit-re0e9s
Codex session ID: 019df94a-d25b-7d92-b234-b5bb5990befc

---

**Verdict: PLAN-NEEDS-MINOR**

v5 is close, but not `PLAN-READY` as written.

Findings:

1. `shouldTriggerRegen` and manager publishing still do not share one exact forwarding predicate. The Rust helper accepts only valid MAC + usable state, and "usable" means "does not contain failed/incomplete" (`handlers.rs:165`, `forwarding_build.rs:326`, `forwarding/mod.rs:45`). The plan's `neighborsEqualForwarding` compares every `(key, MAC, usable)` tuple, which means empty-MAC `INCOMPLETE` rows from `buildNeighborSnapshots` still affect equality even though userspace-dp drops them. Fix: compare only publishable entries: `ifindex > 0`, parseable IP, parseable non-empty MAC, and helper-equivalent usable state. Old usable entry disappearing into `INCOMPLETE` must be detected because the old publishable key disappears.

2. `NUD_NONE` is a bridge mismatch. Go `usableNUD` omits `NUD_NONE`, but `neighborStateString(0)` emits `"none"` and Rust treats `"none"` as usable because it is not failed/incomplete (`snapshot.go:1842`). Either explicitly reject `none` in both Go snapshot publishing and Rust, or include it in the Go listener/comparator.

3. `MonitoredInterfaceLinkIndexes(cfg)` prevents source-code drift, but not runtime ifindex drift. If a link/VLAN disappears, recomputing by current `LinkByName` can exclude the old ifindex, so a `RTM_DELNEIGH` for the old ifindex may be ignored until the 60s safety regen. Add one of: cached previous monitored ifindexes, link subscription-triggered regen, or snapshot-key fallback for delete events.

4. `collectMonitoredNeighbors` mostly answers the stale-probe hole, but the tiering is not quite "stale before fresh" globally. Tier 1 is only stale snapshot keys, while tier 2 is state-blind configured next-hops/fabric peers. Build the full deduped target set first, annotate current NUD state, then sort risky states before fresh states, with criticality as the next sort key.

5. `runOneSubscription` fixes the round-4 spin/double-close bug: closed `updates` returns, and `done` has one owner. Minor caveat: close `done` on subscribe error too, because `NeighSubscribeWithOptions` can start its done goroutine before a `ListExisting` dump request fails. Also, the shown `regenDebouncer` has a data race on `pending` via `time.AfterFunc`; use a timer channel in the same goroutine.

6. The HA section still contradicts the v5 correction: it says takeover uses `resolveNeighbors`, while the corrected section says change VRRP MASTER to `forceProbeNeighbors`. Clean that before handing to implementors.

Not a kill, not another major redesign. Make the forwarding predicate single-source and fix the runtime/link/debounce nits, then implement phase 1.
