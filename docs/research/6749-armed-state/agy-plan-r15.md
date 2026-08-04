# AGY plan review — round 15 — #6749 armed-state plan v8.10 (12ced136fe30)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence constraint; prompt /tmp/agy-6749-r15-prompt.txt assembled at 123,397 bytes). Raw output: /tmp/agy-6749-r15.out.

**Verdict: DEMAND-REVISION** (4 BLOCKER + 3 MAJOR + 1 MINOR).

---

### Evidence Limitations & Missing Context
Before detailing the findings, the following areas lacked full source implementation in the inline snippets, where complete code files would have provided additional certainty:
1. **`PrepareLinkCycle()` implementation & cleanup mechanics:** Full source for `process_linkcycle.go:145-162` showing how worker thread state (`workers_stopped`) and `ctrl.Enabled` are restored when post-quiescence steps fail.
2. **Configstore promotion atomic write boundaries:** Full source for `store_commit.go:276-321`, `store.go:634-769`, and `store_persist.go:171-194` to verify single-transaction atomicity of `commit_revision` and config payload across all 5 promotion paths.
3. **Startup helper status handshake:** Full source for `daemon.go` / `manager.go` initialization loops to verify whether `apply_snapshot` or precheck is strictly gated on the first successful status poll.

---

### Findings

#### 1. BLOCKER: `StartCompile(false)` at `Compile` Entry Clobbers Precheck's `StartCompile(true)` Due to Missing `deferIntent` Parameter
- **Evidence:** `daemon_apply_dataplane.go:60-82`, `manager_compile.go:326-365`, `apply.go:37-40`, Plan §5-C (`StartCompile` specification).
- **Impact:** Dataplane corruption / packet drop due to workers armed on unprogrammed RETH MACs.
- **Analysis:**
  The plan specifies that `daemon_apply_dataplane.go:69-72` calls `StartCompile(true)` when `rethMACPending` is true. `StartCompile(true)` acquires `m.mu`, setting `m.deferWorkers = true` and `m.compileInFlight = true`.
  However, `ApplyConfig(ctx, cfg)` has no options or `deferIntent` argument (as explicitly confirmed in §5-C). When `Compile` is executed at `manager_compile.go`, its entry path executes `StartCompile(false)` for non-deferred compiles to reset stale flags.
  Because `Compile` receives no `deferIntent` parameter from the caller, `Compile` cannot distinguish whether `StartCompile(true)` was called by the daemon precheck for *this* compile or left stale by a *previous* compile. Calling `StartCompile(false)` at `Compile` entry unconditionally overwrites `m.deferWorkers` back to `false`. When `snap.DeferWorkers` is stamped at `manager_compile.go:330-332`, it reads `false`, publishing a non-deferred snapshot to the helper and arming workers before MAC programming completes.

#### 2. BLOCKER: Re-Sync Debt Firing Rule Ignores Non-Zero Helper-Behind States (`0 < helper_rev < accepted_rev`), Causing Permanent Un-Recoverable Lineage Divergence
- **Evidence:** Plan §5-C (UNKNOWN-outcome ownership & section iii), `process_status.go:10-40`.
- **Impact:** Infinite un-synchronized dataplane divergence on non-zero helper state rollbacks.
- **Analysis:**
  The re-sync debt's firing rule is explicitly defined as:
  `status.commit_revision > m.acceptedCommitRevision OR status.publication_rev ahead`
  Helper-behind handling in §5-C (iii) specifies:
  `helper-behind (a restarted helper echoes 0) routes to the startup re-apply`
  If a helper restarts with a restored, non-zero state file or suffers an incomplete persist where `0 < status.commit_revision < m.acceptedCommitRevision` (helper is behind Go with a non-zero revision):
  1. The adoption gate (iii) evaluates `status.commit_revision == m.acceptedCommitRevision` -> `false` (fabrics not adopted).
  2. The startup re-apply check evaluates `status.commit_revision == 0` -> `false` (startup re-apply does not fire).
  3. The re-sync debt evaluates `status.commit_revision > m.acceptedCommitRevision` -> `false` (re-sync debt does not fire).
  Neither re-sync nor startup re-apply fires. The system stays locked in an un-synchronized state indefinitely without re-applying the active config.

#### 3. BLOCKER: Post-Quiescence Failure in `PrepareLinkCycle()` Transaction Leaves Dataplane Workers Permanently Stopped
- **Evidence:** Plan §5-C (MAC debt lifecycle & §6 LinkController API), `process_linkcycle.go:145-162`.
- **Impact:** Dataplane outage / total traffic loss following a transient MAC programming error.
- **Analysis:**
  `PrepareLinkCycle()` stops worker threads and disables `ctrl`. If a subsequent phase (such as `programRethMAC` or `NotifyLinkCycle`) fails during a recovery transaction attempt, the debt state machine records the phase failure and schedules an autonomous backoff retry.
  However, the plan does not specify worker thread resumption or control re-enabling when a post-quiescence phase fails mid-transaction. Because `PrepareLinkCycle()` already executed `stop_workers` and `ctrl.Enabled=0`, leaving workers stopped until the next retry tick (up to 60s later) causes an un-budgeted dataplane outage. If the failure is persistent, workers remain stopped indefinitely.

#### 4. BLOCKER: Unseeded `publication_rev` at Startup Causes Immediate Helper Refusal for Early Post-Restart Publishes
- **Evidence:** Plan §5-C (R2 specification) & §6 item 3, `process_status.go:10-40`.
- **Impact:** Initial config apply failure upon manager restart.
- **Analysis:**
  `publication_rev` is manager-minted per send and seeded at manager startup from the helper's status echo (`m.lastPublicationRev`).
  If the Go manager executes a publish (e.g., initial boot apply or daemon startup apply) before the first status poll from the helper populates `m.lastPublicationRev`, `m.lastPublicationRev` defaults to `0`. The manager mints `publication_rev = 1`.
  If the helper previously persisted `publication_rev = 42` before the manager restarted, the helper enforces `publication_rev > stored_publication_rev` and rejects `1 <= 42`. The plan lacks an explicit startup poll barrier to block outbound publishes until `lastPublicationRev` is seeded from the helper's echo.

#### 5. MAJOR: The 150s `applySem` Fairness Bound Is Invalidated by Sequential Multi-RPC Apply Pipelines
- **Evidence:** Plan §5-C (Debt execution ownership & §9 item 10), `daemon_apply.go:49-56`, `process_control.go:33-56/:129-142`.
- **Impact:** Spurious timeout failures and backoff churn for MAC debt retries during heavy control-plane operations.
- **Analysis:**
  The plan asserts a 150s context timeout for blocking `applySem` acquires, claiming the worst single-owner hold is a 120s control RPC round trip.
  However, a full config commit held under `applySem` in `daemon_apply.go:49-56` executes multiple control RPCs sequentially (`apply_snapshot`, `update_neighbors`, `update_fabrics`, `set_forwarding_state`). If multiple RPCs encounter high latency or individual timeouts (e.g., 2 × 90s = 180s), the total hold time of `applySem` by a single valid apply pipeline legally exceeds 150s. Waiters attempting to acquire `applySem` with a 150s context timeout will fail and abort prematurely while the current owner is executing a valid apply pipeline.

#### 6. MAJOR: Work-Loop Pre-Mutation `claimToken` Re-Read Uses a Blocking `m.mu` Lock While Holding `applySem`
- **Evidence:** Plan §5-C (Debt execution ownership & serialization), `manager_status.go:132-179`, `daemon.go:485-496`.
- **Impact:** Severe lock contention and blocking of all apply pipeline threads.
- **Analysis:**
  The daemon work loop holds `applySem` while executing debt work. Before each netlink mutation, it performs a `claimToken` re-read under `m.mu`.
  While `ClaimMACDebtWork` and `ReportMACDebtAttempt` are specified as try-lock-or-skip on `m.mu`, the per-mutation `claimToken` re-read is specified as a blocking `m.mu` read. If the manager status loop or an apply path holds `m.mu` across a network control RPC (budgeted up to 120s), the daemon work loop blocks on `m.mu` while holding `applySem`. This blocks all incoming commits trying to acquire `applySem` for up to 120s, defeating the try-lock design of the work loop.

#### 7. MAJOR: `FabricSyncDebtOutstanding(projectionHash)` Lookup Fails to Detect Outstanding Debts During Telemetry Updates
- **Evidence:** Plan §4(i) (Fabric sync debt) & §6 (Public API preservation), `controllers.go:112-132`, `daemon_ha.go:774-783`.
- **Impact:** Premature HA takeover readiness assertion while fabric synchronization is actively failing.
- **Analysis:**
  Fabric sync debts are keyed on `(commit_revision, FULL_PAYLOAD_hash)`.
  If a telemetry update (such as a peer IP or link state change) occurs while a fabric sync is failing, the payload changes from $P_1$ to $P_2$, generating a debt keyed on `hash(P_2)`.
  When `FabricSyncDebtOutstanding` is queried by the HA controller using `projectionHash = hash(P_1)` (derived from the current map view), `hash(P_1)` does not match `hash(P_2)` in the debt table. `FabricSyncDebtOutstanding` returns `false` (no debt for $P_1$). Takeover readiness evaluates to `true` despite an active, failing fabric sync debt for $P_2$.

#### 8. MINOR: Note Debt Clearing Specification ("Cleared ONLY on Exact Echo") Contradicts Supersession by Newer Commit Revisions
- **Evidence:** Plan §5-C (iv) & §6 item 6.
- **Impact:** Stale note debt entries remain in backoff queue after newer commits land.
- **Analysis:**
  §6 item 6 specifies that a failed/unknown note debt is "cleared ONLY on an exact echo of the captured sent revision — never on an ACK, an unrelated poll, or the then-current pending revision."
  However, §5-C (iv) defines note debts as "supersedable". If a newer commit $C$ (revision $N+2$) lands and is accepted, the status poll echoes $N+2$. Because $N+2 \neq N+1$, the exact-echo rule prevents the status poll from clearing the note debt for $N+1$. The note debt remains queued in backoff until its next tick executes a CAS refusal.

---

DEMAND-REVISION
