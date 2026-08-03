# AGY plan review — round 12 — #6749 armed-state plan v8.7 (d63d98f75e3d)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence constraint; prompt /tmp/agy-6749-r12-prompt.txt assembled at 125,322 bytes). Raw output: /tmp/agy-6749-r12.out.

**Verdict: DEMAND-REVISION** (3 BLOCKER + 3 MAJOR).

---

### Answer to Specific Design Question

**Question:** Where does Go READ B's `ConfigGeneration` from when B's compile never committed bookkeeping (`manager_compile.go:350-365` commits only after a clean response; staging at `:272-313`)?

**Answer:** Go **cannot** read B's `ConfigGeneration` (nor B's `Config` snapshot) from anywhere. 
1. In `manager_compile.go:350-365`, `m.lastSnapshot = snap` and `m.markAppliedSnapshotLocked()` are executed **only after** `publishSnapshotFailClosedLocked` returns a clean `nil`. If the RPC times out or encounters EOF after the helper receives and applies B, `Compile` returns an error. The local variable `snap` (containing B) goes out of scope and is lost; `m.lastSnapshot` remains snapshot A.
2. In §6 (Public API Preservation), `StatusSnapshot` on the wire is **not** modified to carry `ConfigGeneration`.
3. Consequently, when the status poll detects `status.LastSnapshotGeneration > appliedSnapshot.Generation` (helper-ahead), Go possesses neither B's `ConfigGeneration` nor B's compiled `Config` snapshot in memory or from the wire status. Go cannot execute a #4036 exact-equal republish for B, nor can it instantiate a B-keyed debt with B's `ConfigGeneration`.

---

### Adversarial Plan Review Findings (Round 12)

#### 1. [BLOCKER] Timeout-but-Landed UNKNOWN Outcome Ownership Protocol Broken
* **Evidence:** `pkg/dataplane/userspace/manager_compile.go:350-365`, `userspace-dp/src/server/handlers/snapshot.rs:153`, `docs/research/6749-armed-state/plan.md` §5-C (iv), §6 item 3.
* **Impact:** As demonstrated above, when an `apply_snapshot` RPC for config B lands in the helper but times out on the wire, Go returns an error from `Compile()` without committing `m.lastSnapshot = snap` (`manager_compile.go:350-354`). Go retains A in `m.lastSnapshot`. When the subsequent status poll observes `status.LastSnapshotGeneration > appliedSnapshot.Generation`, Go has no copy of B or B's `ConfigGeneration`. The claimed status-poll re-sync workflow (#4036 exact-equal republish -> adopt B -> instantiate B-keyed debt carrying `B.ConfigGeneration`) cannot execute because Go discarded B upon RPC timeout and `StatusSnapshot` does not carry `ConfigGeneration`.

#### 2. [BLOCKER] Mismatch Between Go-Internal `ConfigGeneration` and Helper `guard.snapshot.generation` False-Refuses Tagged Completions and Fabric Updates
* **Evidence:** `docs/research/6749-armed-state/plan.md` §5-C (iv), §6 item 3; `userspace-dp/src/server/handlers/snapshot.rs:153, 470-473`; `pkg/dataplane/userspace/manager_generation.go:69-72`.
* **Impact:** The plan defines `ConfigGeneration` as a Go-internal snapshot field stamped at compile and never touched by overlay paths (§6). It is **not** transmitted inside `ConfigSnapshot` during `apply_snapshot`. In the helper, `guard.snapshot.generation` stores `snapshot.generation` (`snapshot.rs:153`), which corresponds to Go's `m.lastSnapshot.Generation`. 
When a FIB bump or overlay republish occurs (`BumpFIBGeneration`, `manager_generation.go:69-72`), Go increments `m.lastSnapshot.Generation` to $G+1$, while `m.lastSnapshot.ConfigGeneration` remains $G$. The helper updates its stored `guard.snapshot.generation` to $G+1$ (`snapshot.rs:470`).
When Go subsequently sends a tagged completion rebind or `update_fabrics` carrying `expected_snapshot_generation = m.lastSnapshot.ConfigGeneration` ($G$), the helper compares `expected_snapshot_generation` ($G$) against `guard.snapshot.generation` ($G+1$). Because they do not match, the helper **refuses** the request. All tagged completions and fabric updates become permanently false-refused after any FIB bump or overlay.

#### 3. [BLOCKER] Staged-Ahead Disjunction Falsely Triggers After FIB Bumps, Permanently Wedging Fabric Adoption
* **Evidence:** `docs/research/6749-armed-state/plan.md` §5-C (iii); `pkg/dataplane/userspace/manager_generation.go:69-72`.
* **Impact:** Section 5-C (iii) conditions fabric adoption (`applyHelperStatusLocked`) on `status.LastSnapshotGeneration == appliedSnapshot.Generation` AND `!(m.lastSnapshot.Generation > m.publishedSnapshot || m.lastSnapshot.Config != appliedSnapshot.Config)`.
However, `BumpFIBGeneration()` (`manager_generation.go:69-72`) advances `m.lastSnapshot.Generation = m.generation` without updating `m.publishedSnapshot`.
Therefore, after any FIB bump, `m.lastSnapshot.Generation > m.publishedSnapshot` evaluates to `true`. Go falsely concludes a config is staged-ahead-of-publish and permanently blocks fabric adoption in `applyHelperStatusLocked`, recreating the exact re-wedge defect v8.7 sought to eliminate.

#### 4. [MAJOR] Potential AB-BA Lock Inversion Between `m.mu` and `applySem` in `AttemptMACDebt` In-Flow Pass 1
* **Evidence:** `docs/research/6749-armed-state/plan.md` §5-C, §6 (`AttemptMACDebt`).
* **Impact:** `AttemptMACDebt` executes daemon-side under `applySem`. In-flow pass 1 invokes the internal attempt body directly while holding `applySem`. Updating debt settlement bookkeeping writes into manager state (`m.macEpochDebt`, `m.linkRecoveryDebt`), requiring `m.mu`. Conversely, autonomous background attempts (or status loop checks) acquire `m.mu` before invoking `AttemptMACDebt` (which attempts `applySem`). Without an explicit lock hierarchy, this introduces an un-sanitized `m.mu` $\leftrightarrow$ `applySem` lock ordering inversion that can deadlock the daemon apply thread with the background debt retry loop.

#### 5. [MAJOR] Link Flap Between Bucket-iii Precheck and Apply-Flow `programRethMAC` Leaves Member Unmonitored
* **Evidence:** `docs/research/6749-armed-state/plan.md` §5-C (Completion machinery).
* **Impact:** The three-bucket precheck classifies desired members into (i) MAC mismatch, (ii) MAC correct + link down, (iii) MAC correct + link up. If a member is classified as bucket (iii) at precheck, no debt entry is instantiated. If that member's link flaps down during `programRethMAC` (after precheck but before/during apply), `programRethMAC` finishes without adding it to `macEpochDebt` or `linkRecoveryDebt`. `hasActiveMACDebt` evaluates to `false` and tagged completion fires, but the member is now link-down with no entry in `linkRecoveryDebt` to drive its `setUp` recovery.

#### 6. [MAJOR] Deadlock Risk in Telemetry-Driven `guard_env_generation` Resend Suppression
* **Evidence:** `docs/research/6749-armed-state/plan.md` §5-C (i), §6 item 5.
* **Impact:** Go caches `(rejectedProjection, rejectedGuardEnvGen)` and suppresses `update_fabrics` resends while both match. If a helper guard rejection occurs during a transient sysfs read failure, Go suppresses resends. If sysfs recovers, but helper `guard_env_generation` increments only when telemetry evaluations run, Go remains suppressed on the stale generation. If telemetry evaluations depend on incoming RPCs or netlink events to trigger, helper never re-evaluates telemetry or bumps `guard_env_generation`, locking Go and helper in a permanent suppression deadlock.

---

DEMAND-REVISION
