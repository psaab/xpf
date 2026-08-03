# AGY hostile plan review — #6751 (round 22)

cmd:git log -1 --oneline 6a93866b6...
Wait, let's check git worktrees or branches in `git/kimi-xpf` or worktree.
cmd:git show --stat 6a93866b6
Let's view the details of commit 6a93866b6 in `/home/ps/git/kimi-xpf`.
PLAN-READY-WITH-NITS

### Round 22 Adversarial Assessment & Convergence Adjudication

---

### 1. Analysis of Attack Vector 1: Atomic Unit Deadlock & Starvation (`sync_conn.go:588`)

**Analysis**:
In v15.8, clause (2b) restructures the `ADMITTED` verdict's atomic unit to **STAMP-AND-ENQUEUE** (`docs/research/6751-nopat-admission/plan.md:720-749`).

1. **No Lock Re-entrancy / No Self-Deadlock**:
   - The atomic admission unit is executed under `s.mu`. It performs only microsecond memory operations: (i) stamping the connection slot with `currentAbortGeneration`, and (ii) enqueuing generation-bound setup intents / spawning background goroutines (`go s.OnPeerConnected()`, `go s.doBulkSync()`).
   - The atomic unit finishes and **releases `s.mu` immediately**.
   - When `doBulkSync()` runs asynchronously on its background goroutine, `s.mu` has already been released. When `doBulkSync()` subsequently calls `getActiveConn()` (`sync_conn.go:588`), `s.mu` is not held by that goroutine. Lock re-entrancy and self-deadlock under `s.mu` are eliminated.

2. **Starvation Freedom**:
   - No network I/O, clock sync, journal replay, or socket writes occur inside the atomic unit.
   - Because the atomic unit only performs non-blocking memory writes and goroutine spawns, its execution duration is strictly bounded to microseconds regardless of journal size (e.g., 10k entries) or socket write backpressure.

---

### 2. Analysis of Attack Vector 2: Setup Intent Revalidation & Mid-Bulk Aborts

**Analysis**:
Intent revalidation extends the commit-time guard of clause (4) to all async setup paths:

1. **Revalidatability of Setup Effects**:
   - All four setup intents enqueued at admission—`receiveLoop`, `sendClockSync`, `OnPeerConnected`, and `doBulkSync`—have explicit effect-commit points (socket writes on the sender side, state mutations on the receiver side).
   - At each effect-commit point, the intent checks: `slot.IsAttached() && slot.Generation() == currentAbortGeneration && !fenceIsSet()`.

2. **Mid-Bulk Abort Behavior (10k-entry stream over seconds)**:
   - **Sender Side**: If an abort occurs mid-bulk (e.g., at entry 3,500 of 10,000), the abort advances `currentAbortGeneration` and invalidates/detaches the connection slot (clause 5). The background `doBulkSync()` task detects generation mismatch or a closed-socket error on its next frame write and immediately terminates.
   - **Receiver Side**: Frames arriving from the aborted slot carry the slot's pre-abort generation. Under clause (4), the receiver's serialized loop discards these frames at commit time because their generation is stale.
   - **Partial Bulk Disposition**: A bulk import is only reconciled and completed upon receiving a `BulkEnd` frame. Because `doBulkSync()` stopped mid-bulk, `BulkEnd` is never sent for that epoch.
   - **Epoch Death & Fail-Closed Cleanup**: Under clause (6) and quarantine rules (ii)/(iii), any incomplete bulk encountering socket teardown, receive deadline timeout, or a superseding `BulkStart` drops all pinned quarantine entries fail-closed without sending a bulk ACK.
   - **Conclusion**: Abort-mid-bulk is a cleanly defined, fail-closed state. Stale intents cannot complete a partial bulk or leak stale state across epochs.

---

### 3. Analysis of Attack Vector 3: Verification of §11 Stale Fabric-Gate Text

**Analysis**:
Verified. Section 11 (`docs/research/6751-nopat-admission/plan.md:1438-1441`) explicitly records:
> `...the full rewritten-tuple signature with the NAT64 exclusion and NO disposition gate (the cluster codec carries no disposition field, so non-fabric identity-NPTv6 rows also quarantine — Codex r14 blocker 1's priced consequence) false-positives on NOTHING except genuine self-NAT rows in the legacy window, and those are ADMITTED after the quarantine timeout (a delay, not a drop)...`

The text accurately reflects the removal of the fabric disposition gate folded in v15.0 and preserved through v15.8.

---

### 4. Final Adjudication Findings

No open **BLOCKER** or **MAJOR** issues remain in either the alias discipline or the core #6751 design (registry, minting, holder tracking, tri-state reserve scans, staged replacement, drain quarantine, probe helpers, or status counters).

#### NIT Findings

1. **NIT**: Implementation note in clause (2b) method naming mapping  
   - **Evidence**: `docs/research/6751-nopat-admission/plan.md:745`  
   - **Detail**: The prose references `go s.OnPeerConnected()`. In `pkg/cluster/sync_conn.go`, the connection setup callback is wired inside `handleNewConnection`. To make code-mapping completely transparent during implementation, note in §5.6 that `handleNewConnection` spawns the intent wrappers calling `doBulkSync` and `sendClockSync`.

2. **NIT**: Explicit exclusion of draining allocators from opportunistic reclamation  
   - **Evidence**: `docs/research/6751-nopat-admission/plan.md:223-225`  
   - **Detail**: Section 5.1 specifies `reclaim_absent(&self, live_egress: &FastSet<IpAddr>)` with a cap of 256 retained allocators. Ensure implementation notes explicitly confirm that allocators present in `self.draining` are excluded from `reclaim_absent` cleanup until their drain timers expire and all associated allocations reach zero.
