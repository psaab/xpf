### Adversarial Plan Review Round 10: xpf Issue #6749 (v8.5 Model)

---

### 1. Assessment of Round 9 Folds & Attack Surfaces

1. **Fold Fidelity (Attack Surface 1):**
   - **Three-Bucket Precheck:** Correctly replaces the two-phase precheck. Bucket (i) opens an epoch for MAC mismatch; Bucket (ii) routes down/unplugged members to link-recovery debt without opening an epoch or disabling the dataplane; Bucket (iii) takes no defer action.
   - **In-Flow Settlement & Dispatch:** `programRethMAC` pass 1 runs synchronously under `applySem`. Successful first attempts dispatch `complete_deferred=true` in-flow; partial/failed attempts leave pending phases for autonomous settlement, which dispatches the tagged completion upon full settlement.
   - **Pre-disable & Prewarm State:** Guard-hits issue plain `ctrl.Enabled=0` without wiping `neighborsPrewarmed` or liveness state, enabling ~1 tick recovery upon sysfs restoration.
   - **Retry Clock & Latch Reset:** Explicit operator arms clear both the helper's stored latch and reset `pendingRetryAttempts` / `pendingRetryNextAt`. Event storms do not alter attempt exponents.

2. **Completeness (Open Q1):**
   - No unowned paths to `Registered && !Armed && state==none` remain. All states resolve into global fan-out disarm, explicit operator action, documented deletion boundary re-creation, explicit pending marks, or the documented mixed-version upgrade window.

3. **VERIFIED Pre-disable Failure Posture (Open Q2):**
   - Blocking projection RPC execution when `ctrl=0` readback fails is the correct fail-closed choice. Executing a projection update when `ctrl` status is unverified risks tearing down XSKs while kernel maps remain enabled. Running on the prior projection during control-plane degradation preserves existing traffic flows.

4. **Helper-Authoritative Fabric Cache Adoption (Open Q3):**
   - Unconditional adoption of `status.Fabrics` into `m.lastSnapshot.fabrics` during status polls is sound. Because `applyHelperStatusLocked` and `ApplyConfig` execute under `m.mu`, status polls cannot race in-flight applies. `m.lastSnapshot.fabrics` consistently reflects the helper's accepted state.

5. **Flap-During-Commit Safety (Open Q5):**
   - If a member link flaps down after the precheck classifies it into Bucket (iii), no defer epoch is open (`deferWorkers=false`). The helper binds available slots, and normal link-monitoring handles the flapped interface without triggering a completion dispatch. If an epoch was open due to another member, phase validation in the MAC debt suppresses completion until all desired members are validated link-UP.

6. **Hazard Budgets (Open Q7):**
   - The hazard budgets (~15s worst-case for fabric projection changes, ~3–4s for clean guard-hits, ~7s for isolated UNKNOWN responses, 60s floor for permanent bind errors) are acceptable for a severity-High availability defect. Dataplane transit on healthy interfaces remains unaffected during single-member link recovery.

---

### 2. Findings

1. **[MINOR] Stored-generation guard must compare `ConfigGeneration` rather than scalar `LastSnapshotGeneration`**
   - **File / Locus:** [`pkg/dataplane/userspace/manager_worker_arm_5134.go:38-70`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/dataplane/userspace/manager_worker_arm_5134.go#L38-L70), [`pkg/dataplane/userspace/manager_generation.go:69`](file:///home/ps/.gemini/antigravity-cli/scratch/pkg/dataplane/userspace/manager_generation.go#L69), and `manager_overlay.go:188` (referenced in §5-C & §11 Q4).
   - **Analysis:** §5-C and §11 Q4 state that the tagged completion retry suppresses while `status.LastSnapshotGeneration > debtEpochGeneration`. However, as documented in `manager_generation.go:69` and `manager_overlay.go:188`, `m.generation` (and `lastSnapshot.Generation`) is incremented on FIB-only route-overlay updates. If a route-overlay update is applied while a deferred epoch is active, `status.LastSnapshotGeneration` will increment even though the underlying config generation has not changed. This will falsely trigger the stored-generation guard and suppress tagged completion retries for the active epoch.
   - **Remediation:** Explicitly scope the stored-generation guard to check `status.ConfigGeneration > debt.ConfigGeneration` (or compare against `lastAcceptedConfigGeneration`), ensuring FIB-only overlay updates do not suppress active epoch completion retries.

2. **[NIT] Clarify `rebind.rs` handler parameter passing for `complete_deferred`**
   - **File / Locus:** [`userspace-dp/src/server/handlers/rebind.rs:10-70`](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/handlers/rebind.rs#L10-L70) and [`userspace-dp/src/server/helpers/status.rs:373-423`](file:///home/ps/.gemini/antigravity-cli/scratch/userspace-dp/src/server/helpers/status.rs#L373-L423).
   - **Analysis:** §5-C updates the signature of `reconcile_status_bindings` to `reconcile_status_bindings(state, defer_completion_authorized: bool)`. In `rebind.rs`, `handle` currently accepts `(guard: &mut ServerState, response: &mut ControlResponse, persist_state: &mut bool)`.
   - **Remediation:** Update `rebind::handle` signature to take `request: &ControlRequest` (or `complete_deferred: bool`) so `request.complete_deferred` is forwarded directly to `reconcile_status_bindings(guard, request.complete_deferred)`.

3. **[NIT] Desired additional inline evidence**
   - **File / Locus:** `pkg/dataplane/userspace/manager_compile.go` and `pkg/dataplane/userspace/manager_ha.go`.
   - **Analysis:** While the pasted evidence includes comprehensive Rust helper sources (`status.rs`, `planning.rs`, `rebind.rs`, `forwarding.rs`, `refresh_bindings.rs`, `bringup.rs`) and key Go snippets (`manager_worker_arm_5134.go`, `daemon_apply_dataplane.go`), full verbatim excerpts for `manager_compile.go:330-360` (epoch rollover logic) and `manager_ha.go:150-180` (pre-disable readback verification) were omitted.
   - **Remediation:** Including verbatim lines for these Go components in future review packages would allow line-anchored verification of mutex lock scopes and error exit paths.

---

PLAN-READY-WITH-NITS
