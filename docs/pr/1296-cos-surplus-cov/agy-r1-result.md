I will first search for the implementation plan file `docs/pr/1296-cos-surplus-cov/plan.md` to read it and understand the proposed plan and why it is proposing a `PLAN-KILL`. I will use the `grep_search` and `view_file` tools to read the plan and examine the source files.
I will check my current permission grants to see which directories I can access directly.
I will check the current working directory to locate the source code repository.
I will list the contents of the `/home/ps/.gemini/antigravity-cli/scratch` directory to see if the codebase repository is placed here.
I will run `git rev-parse --show-toplevel` to locate the root of the git repository.
I will run a command to find git repositories in the home directory to locate the active codebase.
I will search for `docs/pr/1296-cos-surplus-cov/plan.md` within `/home/ps/git/` to identify which repository is the active workspace for this review.
I will check the git status inside the `/home/ps/git/bpfrx` directory to see if that is the main work area.
I will check where the plan files for issue 1296 are stored.
I will list the plan files specifically in the `1296-cos-surplus-cov` worktree to locate the plan under review.
I will check if there is a plan file under `docs/pr/1296-cos-surplus-cov/plan.md` in the current branch.
I will list files inside `.claude/worktrees/1296-cos-surplus-cov/docs/pr/` or find if there is a `1296` plan directory inside the worktree.
I will list files in `.claude/worktrees/1296-cos-surplus-cov/docs/pr/1296-cos-surplus-cov`.
I will read the implementation plan for issue #1296 to see its proposed direction, arguments, and details.
I will search for `EqualFlowEnforcement` in the codebase to understand how it is propagated from the Go compiler/parser to the Rust userspace dataplane.
I will search for `EqualFlowEnforcement` in the Go files in `pkg/` to see where it is configured and compiled.
I will search for `equal_flow` in the Rust `userspace-dp/src/` directory to see how the dataplane handles this configuration and logic.
I will view how `rate_mode` is configured in `/home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs` to verify that the Junos knob and Go compiler fields are successfully propagated to the Rust dataplane sidecar lease at runtime.
I will search for `equal_flow_enforcement` in `userspace-dp/src/` to trace how it is parsed/deserialized from the Go compiler wire format.
I will view `userspace-dp/src/afxdp/forwarding_build.rs` around line 784 to verify the end-to-end propagation of `equal_flow_enforcement` in the dataplane compilation.
I will grep for `equal_flow_enforcement` in `/home/ps/git/bpfrx/userspace-dp/src` to find the exact struct definition that deserializes the JSON configuration.
I will search for `equal_flow_enforcement` in `userspace-dp/src/afxdp/types/` to see where the incoming config types are defined.
I will check `userspace-dp/src/afxdp/types/cos.rs` around line 72 and 497 to verify how it is defined in the types.
I will check the other occurrence of `equal_flow_enforcement` in `userspace-dp/src/afxdp/types/cos.rs` around line 497.
I will read how the class-of-service compiler compiles the scheduler parameters in Go.
I will view how `EqualFlowEnforcement` is validated by the compiler in `pkg/config/compiler.go`.
I will search for `shared_cos_lease` in `/home/ps/git/bpfrx/` to locate the Rust module containing the lease state machine logic.
I will grep for `surplus_open` in `./userspace-dp/src/afxdp/types/shared_cos_lease.rs` to verify Ground 2.
I will view lines 1160 to 1210 of `userspace-dp/src/afxdp/types/shared_cos_lease.rs` to examine the context of `surplus_open` and how `equal_flow_enforced` interacts with surplus sharing.
I will view the preceding lines (1110 to 1160) in `shared_cos_lease.rs` to see how `equal_flow_enforced` and the rate limit/cap are calculated.
I will view lines 1050 to 1110 in `shared_cos_lease.rs` to see the initialization of `equal_flow_enforced` and `cap` in the `acquire_v8` function.
I will view lines 1420 to 1480 of `shared_cos_lease.rs` to see the definition of `equal_flow_cap_v8` and how it determines if the equal-flow cap is enforced.
I will grep for `rotate_epoch_v8` in the `shared_cos_lease.rs` file to see how equal-flow caps are calculated at the end of each epoch.
I will view lines 1497 to 1570 of `shared_cos_lease.rs` to analyze `maybe_rotate_epoch_v8`.
I will view lines 1570 to 1670 of `shared_cos_lease.rs` to see how the active flows are processed and the per-flow cap targets are evaluated.
I will search for `publish_equal_flow_epoch_v8` in `shared_cos_lease.rs` to inspect its implementation.
I will view `publish_equal_flow_epoch_v8` around line 1713 to understand how it calculates the equal flow cap targets for active flows across workers.
I will view lines 1800 to 1840 of `shared_cos_lease.rs` to see the remainder of `publish_equal_flow_epoch_v8`.
I will view lines 1840 to 1870 of `shared_cos_lease.rs` to see the final target and state publishing.
I will view `pkg/dataplane/userspace/snapshot.go` around line 2110 to see how the snapshot builder serializes the `EqualFlowEnforcement` compiler flag.
I will view `pkg/dataplane/userspace/protocol.go` from line 190 to 210 to check the struct definition of `CoSSchedulerSnapshot` and other control structs.
I will view lines 670 to 695 of `pkg/dataplane/userspace/protocol.go` to examine the other CoS control message structure and make sure it has the `equal_flow_enforcement` JSON field mapping correctly.
I will view the preceding lines (740 to 770) of `userspace-dp/src/afxdp/forwarding_build.rs` to trace where `scheduler` is retrieved and parsed in Rust.
I will search for the function signature of CoS build in `userspace-dp/src/afxdp/forwarding_build.rs` to see where the config comes from and how the JSON is decoded.
I will view `build_cos_state` in `userspace-dp/src/afxdp/forwarding_build.rs` to see the structure of `ConfigSnapshot` and how the schedulers are mapped.
I will search for `struct ConfigSnapshot` to check if `equal_flow_enforcement` is present in the `CoSScheduler` of the Rust configuration struct definition.
I will search for `CoSScheduler` in `userspace-dp/src/protocol/snapshot.rs` to find its definition and check if it contains the deserialization mapping for `equal_flow_enforcement`.
I will search for `equal_flow_enforcement` inside `userspace-dp/src/protocol/snapshot.rs` to verify that it is properly mapped.
I will search for `class_of_service` in `userspace-dp/src/protocol/snapshot.rs` to see what struct type it maps to.
I will search for the definition of `ClassOfServiceSnapshot` in `userspace-dp/src/protocol/snapshot.rs`.
I will search for the file where `ClassOfServiceSnapshot` is defined.
I will search for `equal_flow_enforcement` in `userspace-dp/src/protocol/cos.rs` to verify that the field is present and correctly deserialized from JSON.
I will read `docs/fairness-regimes.md` to see the documented fairness contracts and regimes, which are critical to the first ground.
I will read `docs/per-5-tuple/path2-archive/CLOSING-RATIONALE.md` from the `1296-cos-surplus-cov` worktree to verify the closing rationale of the prior fairness work and Ground 4 of the expected `PLAN-KILL`.
# AGY Adversarial Review: PLAN-NEEDS-MAJOR

## Verdict: PLAN-NEEDS-MAJOR

The proposed implementation plan to **PLAN-KILL** issue #1296 is **rejected**. While the plan's historical documentation is incredibly thorough, the review has exposed major, load-bearing cracks in the core assumptions of the PLAN-KILL grounds. Specifically, **Option 2 (a work-conserving, equal-flow-preserving surplus mode) is NOT already shipped**, and the zero-copy physics of AF_XDP do not block its implementation. 

Below is the end-to-end hostile verification and pressure-testing of the plan's grounds.

---

## 1. End-to-End Configuration Wire Validation (A)

We walked the configuration and control wire end-to-end and verified that the `equal-flow-enforcement` flag propagates successfully without any gaps:
1. **Junos CLI & Parser**: Parses `equal-flow-enforcement` and sets `sched.EqualFlowEnforcement = true` ([compiler_class_of_service.go:253](file:///home/ps/git/bpfrx/pkg/config/compiler_class_of_service.go#L253)).
2. **Compiler Validation**: Verifies the exact-rate constraint and rejects combining `equal-flow-enforcement` and `surplus-sharing` ([compiler.go:432](file:///home/ps/git/bpfrx/pkg/config/compiler.go#L432)).
3. **Snapshot & Wire Protocol**: Serializes via `CoSSchedulerSnapshot` ([snapshot.go:2110](file:///home/ps/git/bpfrx/pkg/dataplane/userspace/snapshot.go#L2110)) and transmits via JSON (`equal_flow_enforcement`) to Rust ([protocol/cos.rs:112](file:///home/ps/git/bpfrx/userspace-dp/src/protocol/cos.rs#L112)).
4. **Dataplane Compilation**: Maps config to `CoSQueueConfig.equal_flow_enforcement` ([forwarding_build.rs:784](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/forwarding_build.rs#L784)).
5. **Lease Initialization**: Resolves to `V8RateMode::EqualFlowSuppress` shared lease configuration ([coordinator/mod.rs:1063](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/coordinator/mod.rs#L1063)).
6. **Runtime Enforcement**: Evaluates the cap in `acquire_v8` ([shared_cos_lease.rs:1060](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease.rs#L1060)).

**Conclusion on A**: The control wire is fully intact. There is no wire gap.

---

## 2. Mode Conflation Check (B)

The plan does not conflate strict-exact (no surplus) and equal-flow enforcement. Because the Go compiler explicitly blocks combining `EqualFlowEnforcement` and `SurplusSharing`, and because the Rust dataplane shuts down the surplus path when equal-flow is active (`surplus_open = bypass && !equal_flow_enforced`), the current equal-flow mode behaves exactly like a strict-exact queue. The strict-exact CoV numbers are achievable precisely because surplus is completely suppressed.

---

## 3. The Option 2 Implementation Gap — Ground 2 Cracks (C)

The plan's claim that Option 2 is *"already implemented and shipped"* is **false**. 

* **The Gap**: The current implementation disables the surplus path entirely when equal-flow is enforced ([shared_cos_lease.rs:1186](file:///home/ps/git/bpfrx/userspace-dp/src/afxdp/types/shared_cos_lease.rs#L1186)). A true Option 2 would allow surplus sharing (`surplus_open = true`) but cap the worker's *total grant* (primary + surplus) at `equal_flow_cap`.
* **Mathematical Proof of Value**:
  * Consider a 2-worker cluster sharing a `5 * T` class cap. Worker 1 has 2 active flows; Worker 2 has 3 active flows. The equal-flow target per-flow rate is `T`. Fair share is `2.5 * T` per worker.
  * **Master's Current Behavior**:
    * Worker 1 is capped at its equal-flow cap `2 * T` (leaving `0.5 * T` of its fair share unused).
    * Worker 2 is capped at its primary fair share `2.5 * T`. Because `surplus_open` is closed, Worker 2 cannot borrow the unused `0.5 * T`.
    * **Result**: Worker 2's flows run at `0.83 * T`, while Worker 1's flows run at `1.0 * T`. The CoV is artificially inflated, and `0.5 * T` of aggregate throughput is wasted (stranded).
  * **Proposed Hybrid Option 2 Behavior**:
    * Worker 1 is capped at `2 * T`, leaving `0.5 * T` unused.
    * Worker 2 gets `2.5 * T` on its primary path.
    * Worker 2 is allowed to borrow surplus, but its total grant is capped at its `equal_flow_cap` (`3 * T`).
    * Worker 2 draws `0.5 * T` of surplus, reaching exactly `3 * T`.
    * **Result**: All flows across both workers run at exactly `1.0 * T` (CoV = `0.0`) while fully utilizing the `5 * T` class cap.

By completely shutting down surplus rather than capping the surplus draw by `equal_flow_cap`, the current implementation fails to deliver the work-conserving, equal-flow-preserving surplus donation mode requested. This is a severe, load-bearing crack in Ground 2.

---

## 4. Physics Check & Logical Coordination — Ground 3 Cracks (D)

Ground 3 argues that AF_XDP Zero-Copy physics (`xsk_rcv_check`) blocks any cross-worker coordination. This is a **false equivalence**:
* The zero-copy constraint restricts **ingress packet steering and queue rebinding** (meaning we cannot steer a packet received on worker A to worker B's memory).
* Egress shaping (CoS), however, is a **purely logical, rate-based scheduling mechanism**.
* Egress rates are already successfully coordinated across workers using lock-free shared leases without any packet copying or steering.
* Capping the surplus draw at the worker's globally coordinated `equal_flow_cap` requires no packet steering. It is entirely a logical adjustment inside `acquire_v8`. 

Thus, AF_XDP zero-copy physics do not block a hybrid work-conserving equal-flow surplus mode.

---

## 5. Review of Remaining Grounds (1 & 4)

* **Ground 1 (Structural PASS)**: While the master harness reports a PASS under the structural contract of #1217, that contract is designed to tolerate RSS skew (where a 0.67 CoV is deemed "passing"). However, the product and operators need raw flow equality (low raw CoV). Dodging the issue with a structural PASS ignores the core product gap.
* **Ground 4 (Revisit Criteria)**: The revisit criteria in `CLOSING-RATIONALE.md` were written for the complex and failed **AFD ECN/drop overlay (#1211)**. They should not be used to foreclose highly localized, low-risk, and mathematically sound improvements to the existing `acquire_v8` shared lease shaper.

---

## Technical Recommendation for the Plan Rewrite

To transition the plan to `PLAN-READY`, the plan must be rewritten to support the hybrid work-conserving equal-flow surplus mode (Option 2):
1. **Compiler**: Modify `pkg/config/compiler.go` validation to allow the combination of `equal-flow-enforcement` and `surplus-sharing`.
2. **Dataplane**: In `userspace-dp/src/afxdp/types/shared_cos_lease.rs`:
   * Keep `surplus_open` active even when equal-flow is enforced.
   * Modify the surplus grant loop in `acquire_v8` to cap the total granted bytes (primary + surplus) at `equal_flow_cap`.
3. **Verification**: Measure the raw CoV and aggregate throughput under the new hybrid mode on RSS-skewed fixtures to demonstrate the simultaneous optimization of CoV and throughput.

---

### Summary of Work
I conducted a read-only review of the implementation plan `docs/pr/1296-cos-surplus-cov/plan.md`. I traced the configuration wire end-to-end from the Go compiler to the Rust dataplane and evaluated the lease state machine logic in `userspace-dp/src/afxdp/types/shared_cos_lease.rs`. I verified that the plan's core assumptions for a `PLAN-KILL` are cracked because a valuable, work-conserving, equal-flow-preserving surplus mode is logically possible and is not blocked by zero-copy physics. I recommended a path forward to implement the hybrid Option 2 mode and set the verdict to `PLAN-NEEDS-MAJOR`.
