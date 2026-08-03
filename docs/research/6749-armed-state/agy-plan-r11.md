# AGY plan review — round 11 — #6749 armed-state plan v8.6 (dc0e618f8)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence constraint; prompt /tmp/agy-6749-r11-prompt.txt trimmed to 125,992 bytes under the ~127KB argv ceiling). Raw output: /tmp/agy-6749-r11.out.

**Verdict: PLAN-READY** (clean pass, zero findings; evidence wishes listed are informational, not nits).

---

### 1. Analysis of Attack Surfaces & Question Responses

#### 1. Audit of §1 Round-10 Disposition Table & r10 Folds
- **AGY r10 MINOR Fold (`m.configEpoch`):** Correctly specified in §5-C. `m.configEpoch` is a config-only epoch counter that advances **only** on accepted configuration commits (`manager_compile.go`). In contrast to the scalar `m.generation` (which is bumped inside `BumpFIBGeneration` at `manager_generation.go:69-72` without a config change), `m.configEpoch` is completely decoupled from FIB overlays and fabric telemetry.
- **AGY r10 NIT Fold 1 (Rebind Handler Plumbing):** Correctly folded in §5-C and §6. The rebind handler passes `request.complete_deferred` directly to `reconcile_status_bindings(state, request.complete_deferred)`, ensuring tagged completions drive convergence while untagged rebinds do not consume stored latches.
- **Disposition Table Audit:** All rows in §1 correctly reflect the v8.6 design. There are no claimed-but-unimplemented fold entries.

#### 2. Completeness (Q1: Unowned Producer Hunt)
- **Evaluation:** There is **no path** in the proposed model where a binding slot enters `Registered && !Armed` with `activation_state == none` outside of the five documented states:
  1. Global fan-out disarm (`set_forwarding_state(armed=false)`): C3 explicitly sets `activation_state = none` on registered slots, representing global default disarm ownership.
  2. Operator-initiated disarm/register: C2 assigns `activation_state = operator`.
  3. Identity deletion/re-creation boundary: Candidate dropouts or reshuffles clear claims and re-initialize as S5 (`armed=false, activation_state=pending`).
  4. Enabled-gate explicit pending mark (`update_fabrics` projection change): Explicitly sets `armed=false, activation_state=pending`.
  5. Mixed-version window: Old helper binaries lacking `activation_state` present `none` to a new Go manager, which triggers Option D's `slog.Warn` as expected until the helper binary is restarted.

#### 3. Bucket-i-Only Validation & Mixed-Bucket Mechanics (Q3)
- **Bucket-ii Independence:** Bucket-ii members (correct MAC, link down) create a link-recovery debt entry **only** and do not open a defer epoch or set `deferWorkers = true`. On a standard apply, XSK binding (`afxdp.reconcile`) succeeds for all interfaces regardless of carrier state; slots are marked `armed=true, state=none` and `enabled=true` is reported while link-recovery debt independently retries `setUp`.
- **Mixed Bucket-i + Bucket-ii Applies:** When a bucket-i member opens an epoch, S3 marks slots pending. At settle time, validation checks bucket-i members only. Once bucket-i settles, the tagged completion rebind (`complete_deferred=true`) runs `afxdp.reconcile`, which binds XSKs and arms all pending slots (including bucket-ii members).
- **Binding Posture:** A tagged completion rebind cannot fire "while bucket-i slots were never bound" because the execution of the tagged rebind itself is what performs the AF_XDP socket creation (`afxdp.reconcile`) and armed-state convergence in a single atomic critical section.

#### 4. `configEpoch` Scoping (Q4)
- **Scoping Integrity:** `m.configEpoch` advances strictly upon accepted configuration applies (boot config, DHCP/feed applies, accepted HA peer sync, configuration rollbacks, `commit confirmed` auto-reverts, and accepted full recompiles).
- **Invariance:** FIB generation bumps (`manager_generation.go:69-72`), resolved fabric persistence (`manager_ha.go:208`), pre-acceptance compile build failures (`manager_compile.go:214`), and applied-identical HA sync shortcuts (`daemon_ha_sync.go:563`) do **not** advance `m.configEpoch`. This guarantees MAC debt and #5134 debt retries remain stable across FIB/telemetry updates.

#### 5. `expected_snapshot_generation` Refusal (Q5)
- **Refusal Semantics:** The tagged completion rebind carries `expected_snapshot_generation = m.publishedSnapshot.Generation`. The helper's rebind handler verifies that `expected_snapshot_generation` matches its stored snapshot generation.
- **Absence of False Refusals:** Every successful publish path to the helper updates `m.publishedSnapshot.Generation` on the manager side in tandem with the helper's stored generation.
- **Stale Attempt Protection:** If a publish attempt for snapshot $B$ times out or loses an ACK, the helper lands $B$ while Go retains $A$ in `publishedSnapshot`. Go's subsequent tagged retry for epoch $A$ carries `expected = A.gen`, which the helper refuses because its stored generation is $B.gen$. This refusal is legitimate and essential to prevent a stale epoch $A$ completion from clearing epoch $B$'s latch.

#### 6. Three-Authority Latch Clear (Q6)
- **Authority Triad:** Every authorized defer exit path unconditionally clears all three latch authorities:
  1. Go manager flag: `m.deferWorkers = false`.
  2. Helper stored latch: `guard.snapshot.defer_workers = false`.
  3. Go cached snapshot: `m.lastSnapshot.DeferWorkers = false` (and `publishedSnapshot`).
- **Exit Coverage:** Tagged completion success, epoch rollover on no-MAC-work commits, explicit operator global arm, nil-config teardown, and HA peer supersession all clear all three authorities simultaneously, preventing ownerless re-latching during wholesale snapshot clones (`manager_overlay.go:188`).

#### 7. Pair-Gated Adoption (Q7)
- **Divergence Quadrants:** `applyHelperStatusLocked` adopts `status.Fabrics` into `m.lastSnapshot.fabrics` **only** when `(status.LastSnapshotGeneration, status.LastFIBGeneration) == (m.lastSnapshot.Generation, m.lastSnapshot.FIBGeneration)`.
  - *Go-ahead:* Un-published staged config in Go leaves Go's snapshot intact without splicing helper fabric data.
  - *Helper-ahead:* Landed-but-unacknowledged applies resolve via the #4036 exact-equal republish protocol rather than partial single-field adoption.
- **FIB Bump Races:** A status poll occurring during a `BumpFIBGeneration` window (`manager_generation.go:55-73`) will fail the pair check if the generation counters differ, safely retaining Go's committed fabric state until the FIB bump completes and resynchronizes the pair.
- **Zero/Absent FIB Fields:** Protocol fields `LastSnapshotGeneration` and `LastFIBGeneration` desynchronize only on actual generation drift; explicit `0` values match `0` during initialization.

#### 8. Edge-Triggered Verified Pre-Disable (Q8)
- **Flap Re-triggering:** A projection sequence $A \to B \to A$ correctly evaluates $B \neq \text{lastPreDisableProjection}$ ($A$), firing the pre-disable for $B$, and subsequently evaluates $A \neq \text{lastPreDisableProjection}$ ($B$), firing the pre-disable for $A$.
- **Readback Failures:** If the post-write readback cannot confirm `ctrl.Enabled == 0`, the pre-disable blocks the projection RPC send and returns an explicit error to `SyncFabricState`. The system does not wedge; standard periodic status retries (30s) or netlink events re-trigger `SyncFabricState` until a clean readback is obtained.

#### 9. Test Plan Re-specification (Q9)
- **Coverage & Delivery Proofs:** The re-specified test matrix in §9 enforces implementation invariants tightly:
  - Item 12 adds a test-only `CONVERGENCE_CALLS` atomic counter to prove slots transit `pending \to armed` strictly via the convergence locus (`reconcile_status_bindings`), preventing shortcuts that arm at replan time.
  - Items 13, 16, 17, and 19 explicitly exercise expected-generation refusals, multi-worker partial failure restoration, torn socket field resilience, pair-gated adoption quadrants, pre-disable readback fault injection, and wall-clock convergence budgets.

#### 10. Hazard Budget Sign-off (Q10)
- **Budget Realism:** The $\approx 19\text{s}$ wall-clock budget for accepted fabric projection changes (pre-disable + RPC + retry scheduling + worker readiness + status tick + jitter) is accurate.
- **Fail-Closed Posture:** Maintaining an open defer epoch (fail-closed) when a bucket-i member has a persistent MAC mismatch is the correct networking and security posture to prevent hardware frame corruption on live physical links.

#### 11. New Hazards vs Master
- **Evaluation:** No new hazards are introduced relative to `master`. The v8.6 revisions resolve the remaining edge cases around mixed-bucket outages, stored-generation guard contamination, and orphan re-latching.

---

### 2. Desired Additional Evidence

To review code-level implementation details beyond the inline plan text and excerpts, the following source locations would provide helpful context:
1. `pkg/daemon/daemon_reth.go` (around `programRethMAC` and `setUp` invocation sites) to inspect exact error-return tuple handling and integration with the new `LinkController` handoff interface.
2. `pkg/dataplane/userspace/manager_compile.go` (around post-acceptance snapshot publish logic) to verify the exact atomic sequencing of `m.configEpoch` incrementation relative to `publishedSnapshot` updates.
3. `userspace-dp/src/server/snapshot.rs` and `snapshot_refresh.rs` to review serde field attributes and default initializations for `expected_snapshot_generation` and `activation_state`.

---

### 3. Findings Summary

- **BLOCKER:** 0
- **MAJOR:** 0
- **MINOR:** 0
- **NIT:** 0

---

PLAN-READY
