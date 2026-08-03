# AGY hostile plan review — #6751 (round 19)

PLAN-READY-WITH-NITS

### Findings

1. **[NIT] Document `AbortFenceTimeout` parameter in Section 9 parameter summary**
   - **file:line**: [`docs/research/6751-nopat-admission/plan.md#L650-L655`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L650-L655)
   - **Details**: The named parameter for the fence timeout (`AbortFenceTimeout`, set to a small multiple of normal disconnect callback latency) is described in the abort transition contract in §5.6/§5.8, but should also be listed in the implementation parameter summary table in §9 alongside the peer reconnect backoff configuration.

2. **[NIT] Clarify socket re-close behavior on higher-generation aborts during an active fence**
   - **file:line**: [`docs/research/6751-nopat-admission/plan.md#L666-L675`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md#L666-L675)
   - **Details**: In §5.6, when a second abort carrying a newer generation arrives during an active fence, it re-arms the fence generation and timer. The text should explicitly note that if both sockets are already closed/detached, the new generation re-arms the fence without re-invoking `Close()` on already-closed socket descriptors.

---

### Adversarial Evaluation of v15.5 Atomic Generation-Fenced Teardown

1. **r18 Race Closure Verification (`installConn` placement)**
   - **Placement**: `installConn` in [`pkg/cluster/sync_conn.go:244-288`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L244-L288) performs its fence check under `s.mu` prior to slot occupancy evaluation (`d.wasDisconnected = s.conn0 == nil && s.conn1 == nil` at line 248) and slot assignment.
   - **Bypass check**: All incoming sync connections route exclusively through `installConn`. No code path allows a reconnect to assign `s.conn0` or `s.conn1` directly without passing through `installConn`.
   - **Result**: Any reconnect arriving between the two old disconnect callbacks ([`pkg/cluster/sync_conn.go:480-571`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L480-L571)) is refused by the fence check. The window identified in round 18 is structurally closed.

2. **Fence-Timeout Reset & Wedged-Handler Safety**
   - If a wedged handler fails to detach before `AbortFenceTimeout` expires, the state reset proceeds on timeout.
   - Frames arriving from the wedged handler following the reset are tagged with an outdated abort generation or evaluated against the active fence state in `receiveLoop` ([`pkg/cluster/sync_conn_read.go:14`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn_read.go#L14)). They are discarded immediately and cannot mutate or re-populate the reset bulk/quarantine state.

3. **Old Peer Convergence (Receiver-Local Fence)**
   - The fence mechanism is entirely receiver-local within `SessionSync.installConn` ([`pkg/cluster/sync_conn.go:244`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L244)).
   - Reconnect attempts from an older peer (unaware of fence semantics) during an active fence are refused by the receiver.
   - The old peer retries after its standard reconnect backoff, landing after the receiver clears the fence and both slots have detached (`conn0 == nil && conn1 == nil`).
   - This sets `d.wasDisconnected = true` ([`pkg/cluster/sync_conn.go:278`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L278)), re-arming `needColdPrime` and triggering a clean cold-prime bulk sync ([`pkg/cluster/sync_bulk.go:65`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_bulk.go#L65)) with zero protocol modifications required on the peer.

4. **Concurrent Abort Triggers & Reset-Once Guarantee**
   - Concurrent abort triggers (e.g., overflow + deadline + teardown) evaluate `abortGeneration` under `s.mu`.
   - Triggers with same or lower generations act as no-ops. Triggers with higher generations update the target generation under lock.
   - The state reset (clearing bulk, quarantine, and capability state) executes exactly once per transition when all slots detach or upon fence timeout.

5. **Final Adjudication**
   - All core #6751 design components (registry allocation, holder counts, tri-state returns, staged replacement, drain, quarantine buffer, probe, and 7 total metrics/counters) and the v15.5 atomic generation-fenced teardown transition are complete and verified. No open BLOCKERs or MAJORs remain.
