# AGY plan review — round 16 — #6749 armed-state plan v8.11 (c381b621a44f)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence constraint; prompt /tmp/agy-6749-r16-prompt.txt assembled at 123,277 bytes). Raw output: /tmp/agy-6749-r16.out.

**Verdict: DEMAND-REVISION** (4 BLOCKER + 3 MAJOR + 1 MINOR + 1 NIT).

---

### Adversarial Plan Review Round 16: xpf issue #6749 (v8.11 Model)

---

### Audit of Attack Surfaces & Findings

#### Finding 1 [BLOCKER]: Option-B Unconfirmed Revision Fallback Causes Duplicate `commit_revision` Aliasing Between Distinct Configs
* **Location:** Plan doc §5-C (R1 epoch contract), §6 (`commit_revision`), `pkg/configstore/store.go:233-245`, `pkg/dataplane/userspace/manager_compile.go:326-365`.
* **Rationale:** Under Option-B durability (when a store write fails during `SyncApply`, `PromoteRollback`, or boot recovery promote), the plan specifies that the promotion proceeds in-memory, the revision is marked `UNCONFIRMED`, and `ActiveConfigRevision()` returns the **LAST CONFIRMED** revision.
* **Scenario:** Config A is confirmed on disk at `commit_revision = 5`. Config B is promoted in memory, but its store write fails. Under v8.11 rules, `ActiveConfigRevision()` returns `5` for Config B. `SetActiveRevision(5)` transports `5` to `Compile` alongside Config B. Config B is sent to the helper carrying `commit_revision = 5`.
* **Consequence:** Helper receives Config B carrying Config A's revision (`5`). Lineage gating (`status.commit_revision == m.acceptedCommitRevision`), fabric adoption gates (§4 (iii)), note CAS checks, and `expected_commit_revision` fences now treat Config B as identical in revision to Config A. When Config B is later modified or a note/fabric update is attempted, Go and helper disagree on whether B is a new revision or an old one. This induces state corruption, false content-dedup skips (`process_status.go:72-80`), and broken lineage gating across Option-B persistence failures.

---

#### Finding 2 [BLOCKER]: DUAL Refusal Induces Permanent Deadlock When Restarted Manager Active Config Lags Helper Stored Revision
* **Location:** Plan doc §5-C (R2 / Dual refusal), §5-C (UNKNOWN-outcome ownership / re-sync), `pkg/dataplane/userspace/process_status.go:10-40`.
* **Rationale:** The helper enforces DUAL refusal on `apply_snapshot`: it refuses if `publication_rev` is not strictly greater **OR** `commit_revision` is strictly older than the helper's stored `commit_revision`.
* **Scenario:** Helper accepts Config B with `commit_revision = 6`. The manager crashes before an Option-B store write for Config B lands on disk. Upon restart, the manager loads Config A (`commit_revision = 5`) from disk. The manager's startup status poll observes that the helper has stored `commit_revision = 6`.
* **Impact:** The manager detects helper-ahead divergence (`status.commit_revision (6) > m.acceptedCommitRevision (5)`). The re-sync debt fires and attempts to re-apply the manager's active config (Config A, rev 5) with a fresh `publication_rev = N+1`.
* **Consequence:** Helper receives Config A with `publication_rev = N+1` and `commit_revision = 5`. Helper evaluates DUAL refusal: stored `commit_revision` (6) is strictly newer than sent `commit_revision` (5). Helper **REFUSES** Config A! The re-sync debt retries on backoff, but **EVERY** attempt is rejected by DUAL refusal (`5 < 6`). Manager and helper are permanently wedged; the dataplane cannot recover without a manual helper process restart or a fresh external config promotion.

---

#### Finding 3 [BLOCKER]: Direct `Compile` Invocations (HA Sync, Background Recompiles, Tests) Trigger Canary Panic Under Single-Site `StartCompile` Model
* **Location:** Plan doc §5-C (Universal compile reservation), §6 (LinkController API), `pkg/dataplane/userspace/manager_compile.go:326-365`.
* **Rationale:** v8.11 restricts `StartCompile(rethMACPending)` to be called **EXACTLY ONCE** per apply by the daemon at the apply-flow entry (`daemon_apply_dataplane.go:60-82`), and dictates that `Compile` **NEVER** calls `StartCompile`, but instead reads the reservation and canary-asserts `m.compileInFlight == true`.
* **Scenario:** `Compile` is invoked outside the daemon's standard apply-flow entry—such as during HA peer config sync (`SyncApply` -> `Compile`), background route/scheduler recompiles, or unit tests.
* **Consequence:** Because `StartCompile` was not executed prior to entering `Compile` on these paths, `m.compileInFlight` is `false`. When `Compile` executes its canary assertion, it observes `m.compileInFlight == false` and panics/aborts, crashing the manager process.

---

#### Finding 4 [BLOCKER]: Mid-Quiesce Link Return Causes Wrong-MAC Rebind for Deferred Recovery Members
* **Location:** Plan doc §5-C (Debt execution / Recovery quiescence), §9 (Test item 2), `pkg/daemon/daemon_apply_dataplane.go:60-82`.
* **Rationale:** When a recovery batch executes for a set of due members, it invokes `PrepareLinkCycle` to quiesce the dataplane, programs MACs for due members, and then performs a global batch `rebind` across all configured interfaces before calling `NotifyLinkCycle`.
* **Scenario:** Member A has a MAC mismatch and is in the due set. Member B is down (link down) and also has a MAC mismatch (bucket i), so B's MAC program was not completed prior to quiescence. During Member A's link cycle quiescence (while workers are stopped), Member B's link carrier returns (link UP). The plan states: *"a member whose link returns DURING the batch's quiescence DEFERS to the next attempt (assert the batch's rebind physically binds its slots but its MAC obligation is the next batch's)"*.
* **Consequence:** The batch's global `rebind` executes and physically binds slots for **ALL** configured interfaces, including Member B. `NotifyLinkCycle` then starts workers and re-enables control. Member B's workers are started and armed with Member B's **OLD/WRONG MAC** on a live UP link, forwarding traffic on an un-programmed MAC until the next recovery attempt runs (up to 5s later). This violates the core safety invariant that no worker may be armed on an un-programmed MAC.

---

#### Finding 5 [MAJOR]: Pre-First-Poll `not-seeded-yet` Abort Drops Boot Apply Without Guaranteed Re-Trigger
* **Location:** Plan doc §5-C (R2 publication high-waters & seed), §6 (`m.lastPublicationRev`), `pkg/daemon/daemon_apply_dataplane.go:60-82`.
* **Rationale:** Any full-publish send attempted before the synchronous startup ping / first status poll completes returns a retryable `not-seeded-yet` error.
* **Scenario:** During node startup, the daemon initiates the boot `ApplyConfig` flow. If `ApplyConfig` attempts to publish a snapshot before `m.publicationRevSeeded` is `true`, it aborts with `not-seeded-yet`.
* **Consequence:** `FinishCompileReservation(token, PRE-PUBLISH FAILURE)` cleans up the reservation. When the status poll completes milliseconds later and sets `publicationRevSeeded = true`, no mechanism in the plan automatically re-triggers the aborted boot apply. The system remains in an un-applied state until an external config event or ticker fires.

---

#### Finding 6 [MAJOR]: Work-Loop `claimToken` Re-Read Contention Triggers Spurious Unwinds and Control Flapping
* **Location:** Plan doc §5-C (Debt execution ownership), §6 (`ClaimMACDebtWork`), `pkg/dataplane/userspace/manager_compile.go:326-365`.
* **Rationale:** The daemon work loop performs a try-lock `ValidateClaimToken(claimToken)` on `m.mu` before every netlink mutation. If `m.mu` is held (e.g. by status loop or control request), try-lock fails and returns `ok = false`.
* **Scenario:** `PrepareLinkCycle` has already quiesced the dataplane (ctrl disabled, workers stopped). The work loop moves to the first netlink mutation and calls `ValidateClaimToken`. `m.mu` is currently held by a 120s status loop control request.
* **Consequence:** `ValidateClaimToken` returns `ok = false` due to lock contention. The work loop treats `!ok` as an abandon signal, performs a balanced unwind (ctrl re-enabled, workers rebound/re-started), releases `applySem`, and waits for the next backoff tick (5s). This causes repeated dataplane control flapping and worker stop/start churn whenever status loop RPCs coincide with debt execution.

---

#### Finding 7 [MAJOR]: `FabricSyncStateOK()` Answers `true` Immediately After Startup Before Helper Alignment Is Verified
* **Location:** Plan doc §5-C (Fabric sync debt), §6 (`FabricSyncStateOK`), `pkg/dataplane/userspace/process_status.go:10-40`.
* **Rationale:** `FabricSyncStateOK() bool` is a no-argument manager query that returns `true` if there are no outstanding fabric sync debts in `m.fabricSyncDebts`.
* **Scenario:** The manager restarts. `m.fabricSyncDebts` is initialized to an empty map in memory.
* **Consequence:** Immediately after boot, before any status poll or fabric sync request has executed, `FabricSyncStateOK()` evaluates `m.fabricSyncDebts` (which is empty) and returns `true`. HA takeover readiness (`daemon_ha.go:774-783`) ANDs `fabricPopulated` with `FabricSyncStateOK()`. Because `FabricSyncStateOK()` returns `true` prematurely on an un-verified manager instance, HA takeover can proceed under the false assumption that fabric state is synchronized.

---

#### Finding 8 [MINOR]: `applySem` FIFO Queue Under High Control Churn Starves Urgent Dataplane MAC Recovery
* **Location:** Plan doc §5-C (Lock hierarchy + HONEST fairness), §9 (Test item 17).
* **Rationale:** `applySem` is a strict no-timeout FIFO queue. Sequential control requests (commits, HA syncs, route republishes) hold `applySem` for multi-RPC pipelines (each control request capped at 120s).
* **Scenario:** A RETH interface member flaps or suffers a MAC mismatch while several background control operations are queued in `applySem`.
* **Consequence:** The MAC debt autonomous recovery attempt is enqueued at the tail of the FIFO queue. If 4-5 control pipeline holds are queued ahead, wait time can exceed 10-15 minutes, leaving dataplane traffic on the affected RETH interface down/broken while waiting for low-priority background control tasks to yield `applySem`.

---

#### Finding 9 [NIT]: Requested Source Evidence
* In accordance with prompt instructions:
  1. Full source code for `pkg/configstore/store_commit.go`, `store_persist.go`, and `store.go` around `ActiveConfigRevision()` and Option-B error paths to verify how unconfirmed revisions are flagged and propagated in Go.
  2. Source code for `daemon_ha_fabric.go` and `daemon_ha_sync.go` to inspect exact `FabricSyncStateOK()` invocation sites and HA takeover logic.
  3. Source code for `daemon_apply.go` and `applyConfigLocked` to verify how queued DHCP/feed reapplies acquire `applySem` and interact with `StartCompile`.

---

DEMAND-REVISION
