Reviewed the exact `ee2f548d8` blob via `git show`; later uncommitted review-document changes in the shared worktree were ignored. I made no file changes.

1. **BLOCKER — the §1 r6 disposition table is materially false.** The table is at `plan.md@ee2f548d8:108-126`.

   | r6 row | Round-7 audit |
   |---|---|
   | AGY f1 signature/latch atomicity | **CLOSED narrowly** inside Rust: explicit authorization and consume-on-Ok are adequate. |
   | AGY f2 transient MAC stranding | **OPEN:** recovery lacks config-epoch, all-member, and supersession semantics. |
   | AGY f3 retry thrash | **OPEN:** backoff helps, but the terminal attempt cap creates a permanent sink. |
   | AGY f4 clear→dispatch race | **PARTIAL:** current-epoch sleep/dispatch is gated; successor configs and global verbs are not. |
   | Codex f2 C2 + deletion | **PARTIAL:** result-based C2 works; claim lifetime contradicts R3 and the tests. |
   | Codex f3 partial-B/restored-A alias | **OPEN:** per-slot ownership is correct, but the proposed two-atomic socket tuple can tear and discards binding errors. |
   | Codex f4 `update_fabrics` wrong-physical | **OPEN/BLOCKER:** no Go fail-closed transaction; `pending` is not itself a forwarding gate; empty removal is unsendable. |
   | Codex f5 sysfs race | **OPEN/BLOCKER:** Rust’s guard and Go’s cached snapshot can disagree, allowing a later republish to bypass the guard. |
   | Codex f6 quiescence race | **PARTIAL:** same-epoch race closed; epoch abandonment/rollover is undefined. |
   | Codex f7 retry completeness | **OPEN:** hard stop and stale defer-state suppression both recreate indefinite disablement. |
   | Codex f8 latch/debt/MAC phases | **OPEN:** successful latch clearing is specified, but epoch authority, config generation, and MAC debt remain incomplete. |
   | Codex M9 tests | **OPEN:** several tests can green without exercising the production boundary. |
   | Codex NIT M10 | **CLOSED:** edge-triggered diagnostics and retry fingerprinting are adequately specified. |
   | SMR N1/N2/N3 | N3 is closed locally; N1’s cap is unsafe; N2’s replacement MAC debt remains epoch-incomplete. |

2. **BLOCKER — `update_fabrics` is not a fail-closed Go→Rust replan transaction.** V8 makes this RPC tear down and rebind workers (`plan.md@ee2f548d8:664-668`). Full Compile first disables bootstrap ctrl and clears bindings, but `SyncFabricState` merely sends the request, ignores the returned status, and writes back its input at [manager_ha.go:153](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_ha.go:153). It never invokes the map/ctrl publication path at [maps_sync.go:353](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/maps_sync.go:353).

   Rust reconciliation tears down the current workers at [reconcile/mod.rs:330](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/reconcile/mod.rs:330), potentially waiting ten seconds for readiness at [bringup.rs:30](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:30). During that interval Go can retain `ctrl.Enabled=1` and old READY rows while XSK slots disappear or are reused. This is a new v8 outage/wrong-slot window versus master.

   Also, “mark same-name/new-ifindex pending” is insufficient unless it explicitly sets `armed=false`: Rust `enabled` ignores `activation_state` and checks only `registered && armed` at [status.rs:267](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/status.rs:267). The plan currently says the carried record may remain armed (`plan.md@ee2f548d8:655-663`).

   The transaction needs manager-side projection detection, pre-disable/map clearing, immediate returned-status application, and fail-closed behavior on timeout/error. The small RPC has a three-second deadline at [process_control.go:33](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_control.go:33), shorter than readiness, so timeout-but-landed behavior also needs explicit idempotency.

3. **BLOCKER — the empty-replan guard has split Rust/Go authority and is bypassable.** Rust is supposed to retain the prior projection/vector while accepting telemetry (`plan.md@ee2f548d8:672-678`). After any successful RPC, however, Go unconditionally stores the entire incoming fabric slice in `m.lastSnapshot` at [manager_ha.go:175](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_ha.go:175). Route and scheduler publishers clone that snapshot wholesale, e.g. [manager_overlay.go:188](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_overlay.go:188). A later full apply can therefore resend the projection Rust rejected and recreate the empty-plan sink while sysfs is still unreadable.

   The current Rust handler also calls `refresh_fabric_links` with the full incoming projection before folding storage at [handlers/mod.rs:144](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/mod.rs:144); that immediately publishes fabric state to workers at [snapshot_refresh.rs:83](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:83). A rejected/debounced projection must be staged, not published through that path.

   Q4 does not require `rx_queues` provenance on every binding. A current eligible candidate with raw `rx_queues==0`, a prior identity, and a same-pass sysfs-read failure is enough: [planning.rs:605](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:605) returns zero only on `read_dir` failure and otherwise at least one. The planner should return an exact skip cause from the same pass. A legitimate full config removal goes through `apply_snapshot`, so it must not trigger this guard.

   If `update_fabrics` itself must support `fab0 → []`, production cannot currently express it: Go returns early for an empty slice at [manager_ha.go:166](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_ha.go:166), and `json:"fabrics,omitempty"` drops an explicitly empty slice at [protocol.go:83](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/protocol.go:83). Rust then receives `None`. Item 19(iv) can pass as a direct Rust test while production never sends the removal.

4. **BLOCKER — the defer “epoch” is still a leaking boolean.** V8 leaves the flag set after failed tagged completion and abandons that retry when its config generation becomes stale (`plan.md@ee2f548d8:695-700,736-742`). The daemon only installs/clears the flag when the current precheck finds a MAC mismatch at [daemon_apply_dataplane.go:50](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_dataplane.go:50), while Compile stamps every snapshot deferred whenever the manager boolean remains true at [manager_compile.go:330](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:330).

   Counterexample:

   - Deferred A’s tagged rebind fails, leaving the flag set.
   - Unrelated config B has no MAC mismatch, so its daemon path never clears or replaces the epoch.
   - Compile B publishes `DeferWorkers=true`.
   - A’s retry is abandoned because B changed config generation.
   - B has no MAC completion owner.

   B is workerless indefinitely. The same contradiction exists for the claimed global-disarm epoch expiry: every non-rebind caller passes `defer_completion_authorized=false` (`plan.md@ee2f548d8:596-615`), so neither Rust’s stored latch nor Go’s cached latch is consumed despite global verbs being called authorized exits at `plan.md@ee2f548d8:829-838`.

   Every config attempt needs explicit epoch rollover: retain current early-abort cleanup, cancel stale tagged/MAC debts, clear both latch authorities, then decide whether the accepted successor opens a new epoch.

5. **BLOCKER — the ~12-attempt pending retry cap deliberately recreates the issue’s permanent sink.** The plan stops retries until a pending/config/link change at `plan.md@ee2f548d8:765-805`, and the Go test pins that stop at `:1242-1253`. But `WorkerSpawn` includes transient `pthread_create` `EAGAIN`/`ENOMEM` failures at [bringup.rs:49](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:49). Resource or driver recovery need not change the pending identities, config, or link. Once the cap is reached, the entire vector remains pending and fail-closed forever.

   Keep the 60-second cap on frequency, not on autonomous recovery; warn at the threshold but continue low-rate probes. The tagged completion retry must also be explicitly exempt from any terminal cap.

6. **BLOCKER — MAC debt and “CONFIG generation” are not implementable contracts yet.** Only the #5134 debt is said to be config-scoped (`plan.md@ee2f548d8:743-753`); the distinct MAC debt at `:702-717` has no accepted-config identity, desired member/MAC set, supersession rule, or completion-mode history.

   Current code iterates every RETH member and aggregates link-cycle results at [daemon_apply_dataplane.go:261](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_dataplane.go:261). `programRethMAC` can fail before setting the MAC, after setting it but failing `setUp`, or succeed live/cycled at [daemon_reth.go:238](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_reth.go:238). The debt must be keyed to an accepted config epoch and the complete desired member→MAC set; all members must have the desired MAC and be administratively up before completion. A newer config must cancel it before stale MAC work can run.

   “CONFIG generation” itself is undefined. Manager has only the composite snapshot counter at [manager.go:93](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager.go:93); `config.Config` has no generation field at [types.go:270](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/config/types.go:270). The current counter is allocated before snapshot building at [manager_compile.go:214](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:214) and also advanced by FIB-only work at [manager_generation.go:69](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_generation.go:69). The plan must define when the new epoch advances: a failed newer compile must not cancel valid debt, while the mandatory same-config reapply must not invalidate its own debt.

7. **MAJOR — Q3’s data is per-slot, but the proposed socket-tuple predicate is not exact.** `plan_workers` creates a separate live record per binding and keys it by slot at [bringup.rs:273](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:273); one worker owning several slots does not share their socket fields. So there is no steady-state cross-slot bleed merely because of worker grouping.

   However, socket ifindex and queue are separate relaxed stores at [binding_state/mod.rs:873](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/binding_state/mod.rs:873) and separate relaxed loads at [binding_state/snapshot.rs:35](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/binding_state/snapshot.rs:35). Concrete trace: A `[a,b,c]` has slot 2 = `(c,q0,ifindex 30)`; B `[c]` with at least three queues has slot 2 = `(c,q2,30)`. During a surviving B worker’s publication, restored-A refresh can observe the new ifindex with the initial queue zero and accept B-q2 telemetry as A-q0.

   Worse, bind failure clears the socket tuple and then records `last_error` at [worker/mod.rs:921](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/worker/mod.rs:921). Treating tuple mismatch as `zero_unbound_slot` clears that exact error at [refresh_bindings.rs:433](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:433).

   Compare the immutable intended identity already stored in `workers.identities` before spawn at [bringup.rs:280](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:280), ideally using interface+ifindex+queue. Item 16 must exercise one worker with multiple slots and distinctive socket/error/counter values; its cited fixture currently assigns one slot per worker at [coordinator/tests.rs:4135](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/tests.rs:4135).

8. **MAJOR — literal Q1 passes, but the claim boundary is internally contradictory; Q2 itself is sound.** Existing control mutations are planner, binding/queue verbs, and global fan-out at [planning.rs:504](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:504), [binding.rs:27](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/binding.rs:27), [queue.rs:29](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/queue.rs:29), and [status.rs:418](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/status.rs:418). With S1–S5/C1–C3 implemented literally, I found no additional terminal producer of `Registered && !Armed && none`. Result-based C2 is valid: `register` and `disarm` intentionally serialize identically at [control.go:104](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/control.go:104).

   But the plan promises claims survive renames and die with the physical binding (`plan.md@ee2f548d8:543-552,986-989`), while R3 keys by interface name and item 8 explicitly says rename/same-ifindex reinitializes (`:824-827,1073-1075`). Actual candidates use Linux names at [planning.rs:398](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:398). Global-min queue contraction also deletes high-queue claimed identities on otherwise healthy interfaces at [planning.rs:495](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:495). The honest boundary is any deletion of the planned `(linux-interface,queue)` identity, not merely the two named candidate-drop cases or physical-XSK death.

   For Q2, a successful tagged rebind may converge all registered pendings. It genuinely replans every registered valid binding at [bringup.rs:273](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:273) and requires complete readiness before `Ok`. Per-cause authorization would incorrectly strand prior S4 pending state. Add an overlap test: prior S4 plus current S3; tagged success clears both, tagged failure clears neither.

9. **MAJOR — items 12–19 and the Go tests remain false-green-capable, and the proposed correctness pieces cannot be deferred.**

   - Item 13 needs production-scheduled tagged retry, successor non-defer/defer config rollover, global disarm/arm, and the Q2 overlap—not a manually issued second tagged request.
   - Item 15 must cover rename and queue-contraction claim deletion and force an actual replan while sysfs is unreadable.
   - Item 16 needs the single-worker/multi-slot and torn/error cases above.
   - Item 17 needs a real accepted-config epoch: failed newer compile, newer same-binding-plan config, same-config mandatory reapply, plus real FIB/fabric/overlay/scheduler publishers.
   - Item 19 needs Go pre-disable/immediate status application, present-empty wire encoding, guard-hit followed by cached-snapshot republish, explicit immediate `armed=false,pending`, and proof that trailing coalescing reconciles the final projection rather than dropping it.
   - Retry tests need recovery after attempt 12 with no reset event and a real first-Compile failure followed by a production status-loop tick.
   - MAC tests need two or more members, order permutations, stale-debt supersession, restart after MAC-set/link-up-failed, and live-success versus link-cycle completion.

   Do not split MAC debt or pending retry into follow-up PRs: success-gated MAC completion without its debt strands transient failures, and S4/restoration without an indefinite low-rate retry strands planner pendings. They may land as prerequisite stack entries, but must precede or be atomic with the behavior relying on them. Option D and its warning-only observability are the safe follow-up split.

DEMAND-REVISION
