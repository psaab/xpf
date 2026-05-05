# Codex round-6 PLAN review — #1197 v6

Task ID: task-mosxv091-ejwxul
Codex session ID: 019df950-c82b-71b1-996d-6ae88205b2ec

---

**Verdict: PLAN-NEEDS-MINOR**

Findings:

1. The plan still does not fully close v5 nit #2. `neighborSnapshotPublishable` rejects `"none"`, but the sketched `RegenerateNeighborSnapshot` still publishes raw `newNeighbors`. Rust still treats anything except failed/incomplete as usable (`forwarding/mod.rs:45`), and `update_neighbors` accepts that via `handlers.rs:165`. Fix the plan to explicitly filter the publish payload to publishable neighbors, or change Rust accept rules to reject `"none"` everywhere.

2. The publishable predicate checks `n.IP == ""`, but the invariant above it requires parseable IP. Existing Rust parses IP/MAC before accepting neighbors. Make the pseudo-code match the invariant: `net.ParseIP(n.IP) != nil` and `net.ParseMAC(n.MAC)` rejection.

3. Section 6 still says the deleted 15s timer may be "repurposed to call `resolveNeighborsInner`". That contradicts the corrected force-probe design and the PR1 checklist. Remove that stale option.

Everything else from the six v5 nits is substantively addressed: publishable-only equality is specified, `NUD_NONE` is excluded from Go usable state, disappeared-link delete events get the snapshot-ifindex fallback, probe tiering is globally state-aware, the subscription/debounce race is fixed, and HA now says `forceProbeNeighbors`.

This is not a major redesign issue. Tighten those three plan lines and it is implementation-ready.
