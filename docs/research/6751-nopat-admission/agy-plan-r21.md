# AGY hostile plan review — #6751 (round 21)

Verdict: **PLAN-READY-WITH-NITS**

---

### Round 21 Convergence Adjudication

All round-20 findings from Codex and SMR have been successfully folded into `docs/research/6751-nopat-admission/plan.md` v15.7+ (commit `bc5efeb37`). The specification of the generation-fenced abort lifecycle and identity allocation model is now complete, watertight, and implementable without open architectural or race hazards.

---

### Verification & Adjudication Summary

1. **Clause (5) Deterministic Detach on Abort/Timeout**
   - **Verification**: Verified against `pkg/cluster/sync_conn.go:480-496`. Today `handleDisconnect` only clears slots when the disconnecting connection instance matches, and full cleanup requires `s.conn0 == nil && s.conn1 == nil`. If a handler wedged at timeout, the registered slot remained non-nil, causing subsequent reconnects to see `wasDisconnected == false` (`sync_conn.go:248/278`) and miss `needColdPrime`.
   - **v15.7 Specification** (`plan.md:724-743`): Clause (5) generation-invalidates and logically detaches both slots (`s.conn0 = nil`, `s.conn1 = nil`) before the fence releases, including on `AbortFenceTimeout`. Late disconnect callbacks hit the `default:` stale-disconnect path in `handleDisconnect`, while late frame commits are rejected by clause (4)'s commit-time generation check. The next connection deterministically observes `wasDisconnected == true` and arms cold-prime.

2. **Clause (2b) Atomic Admission and Setup Tail**
   - **Verification**: Verified against `pkg/cluster/sync_conn.go:130-146`. Previously, `installConn` returned a decision and the setup tail (`receiveLoop` launch, `sendClockSync`, `OnPeerConnected`, `doBulkSync`) executed as separate un-fenced steps, creating a TOCTOU window where an abort could advance the generation mid-setup.
   - **v15.7 Specification** (`plan.md:716-723`): Clause (2b) commits the `ADMITTED` verdict and its entire setup tail as one serialized step under `s.mu` (or the serialized event loop).
   - **Implementability & Performance**: Spawning background goroutines (`go s.receiveLoop`, `go s.OnPeerConnected`, `go s.doBulkSync`) and executing local memory updates (`s.flushDeleteJournal`) under the lock takes sub-millisecond execution time, ensuring no starvation of the event loop.

3. **Capability Transport Single-Contract Cleanup**
   - **Verification**: Verified via codebase and plan search across `plan.md:561-573`, `1077-1083`, `1174-1176`, and `1423-1425`.
   - **v15.7 Specification**: All references to a piggyback alternative have been scrubbed. The contract is strictly the dedicated, periodic `syncMsgCapability` ticker.

---

### Ranked Findings

#### NIT 1: Periodic Ticker Cadence Alignment
- **Location**: `docs/research/6751-nopat-admission/plan.md:562-564`, `1423-1425`; [`pkg/cluster/sync_conn.go:137`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L137)
- **Detail**: Section 11 Question 2 asks whether `syncMsgCapability` should share an existing periodic timer cadence. In `pkg/cluster`, periodic tasks run alongside `syncSweep` or heartbeat timers. During implementation, `syncMsgCapability` can piggyback on the existing heartbeat/ping ticker interval (e.g. 5s–10s) rather than instantiating an uncoordinated standalone timer goroutine.

#### NIT 2: Setup Tail Non-Blocking Spawns Explicit Guarantee
- **Location**: `docs/research/6751-nopat-admission/plan.md:716-723`; [`pkg/cluster/sync_conn.go:133-145`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/cluster/sync_conn.go#L133-L145)
- **Detail**: To guarantee clause (2b) never introduces lock contention or event loop starvation, the implementation doc note should explicitly specify that network I/O or callback execution in the setup tail MUST be dispatched via background goroutines (`go s.OnPeerConnected()`, `go s.doBulkSync()`), with only handle setup and goroutine spawning occurring inside the atomic step.

---

### Final Plan Status

No **BLOCKER** or **MAJOR** issues remain in either the core #6751 NAT identity design or the fabric-alias discipline. The plan is **PLAN-READY-WITH-NITS** and ready to move to implementation.
