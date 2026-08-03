Reviewed the exact `e7b835f73` blob via `git show`; all `plan.md` references below are to that committed blob, not the subsequently changed worktree copy. I made no file changes.

1. [BLOCKER] The round-8 disposition table is materially false.

| §1 row | Round-9 audit |
|---|---|
| f4 MAC contract | REOPENED/BLOCKER — configured-admin-down and missing-member semantics are wrong; first validation and cross-layer epoch handoff remain undefined. |
| f5 fabric transaction | REOPENED/BLOCKER — verified pre-disable failure and UNKNOWN-response cache adoption are absent. |
| f6 mixed-version producer | CLOSED narrowly — only as an operational constraint: mandatory helper restart plus D as a release gate. Same-config helper reuse is real at [process.go:18](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process.go:18), as is old-helper default-unarmed expansion at [planning.rs:504](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:504). |
| f7 retry clock | PARTIAL/MAJOR — the main deadline rule is fixed, but attempt-reset/cap language remains contradictory. |
| f8 identity | PARTIAL/MAJOR — planned identity is correct, but hidden invariant 3 and item 16 contradict it. |
| f9 rollover/operator latch | REOPENED/BLOCKER — timeout/EOF is unknown acceptance, not rollback-safe; operator arm omits Go’s cached latch; nil-config teardown is unhandled. |
| M8 tests | OPEN/MAJOR — several tests remain false-green-capable. |
| AGY row | Historical review result only; it closes no property contradicted by source. |
| SMR N1/N2/N3 | N2 whole-update guard and N3 claimed-slot physical rebind are closed; N1 is reopened by remaining compile-start text. |

That contradicts the claims at `plan.md@e7b835f73:212-222`.

2. [BLOCKER] `mac != desired || !linkUp` mistakes valid configured-down state for a defect.

The plan requires every desired member to be administratively up at `plan.md@e7b835f73:917-938`. But `Disable` is explicit configuration intent at [types_interfaces.go:22](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/config/types_interfaces.go:22), `RethToPhysical` selects members without filtering it at [types.go:71](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/config/types.go:71), and both the compiler and networkd deliberately keep such interfaces down at [compiler_iface.go:635](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/compiler_iface.go:635) and [networkd.go:601](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/networkd/networkd.go:601).

Therefore v8.3 either:

- calls `LinkSetUp`, violating the accepted configuration and oscillating against networkd; or

- respects `Disable`, leaving MAC debt permanently active and globally disabling the dataplane.

An out-of-band `ifconfig down` on a config-enabled interface is presently configuration drift—the compiler brings enabled interfaces back up at [compiler_iface.go:645](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/compiler_iface.go:645). But configured `disable` is authoritative. The debt must derive `desiredAdminUp` and validate actual admin state against it; MAC mutation must restore that desired state rather than unconditionally end UP.

Also define `linkUp` as administrative `IFF_UP`, not carrier/`OperState`. [monitor.go:1086](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/cluster/monitor.go:1086) explicitly distinguishes them; using carrier would turn a pulled cable into an unrepairable global defer.

Finally, the current precheck silently skips missing desired members at [daemon_apply_dataplane.go:61](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_dataplane.go:61). The plan never says missing must open debt. Missing must be an active, Warn-visible prerequisite failure, not “no work.”

3. [BLOCKER] There is no specified first validation trigger or safe epoch handoff.

The real outer flow is:

1. `applyConfigLocked` already holds `applySem` ([daemon_apply.go:127](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply.go:127)).

2. Manager `Compile` publishes the deferred snapshot ([daemon_apply_dataplane.go:137](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_dataplane.go:137)).

3. The daemon synchronously performs RETH MAC work ([daemon_apply_dataplane.go:247](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_dataplane.go:247)).

4. It then dispatches `NotifyLinkCycle` or mandatory re-apply ([daemon_apply_dataplane.go:385](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_dataplane.go:385)).

The plan opens phase-validation-pending debt but specifies only autonomous backoff at `plan.md@e7b835f73:927-951`. An autonomous attempt cannot acquire `applySem` until this enclosing apply returns. Meanwhile the immediate notification sees active debt, sends an untagged rebind, and cannot consume the latch.

The first validation must therefore be the inline MAC pass: after programming, reread every desired member’s MAC and administrative state, settle the current epoch, and dispatch before returning from the same outer daemon apply. It must not reacquire the non-reentrant semaphore it already holds.

The autonomous path also needs explicit lock ordering. The status loop holds `m.mu` at [process_status.go:162](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_status.go:162), while normal apply order is `applySem → m.mu`; acquiring `applySem` while holding `m.mu` creates an ABBA deadlock with `NotifyLinkCycle`, which takes `m.mu` at [process_linkcycle.go:191](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_linkcycle.go:191).

This can complete within one outer daemon apply, but not within the Manager’s `Compile` call alone. The design needs an explicit epoch token/handoff between daemon-owned netlink/applySem state and manager-owned generation/latch state. The current `LinkController` exposes no such operation at [apply.go:130](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/apply.go:130), contradicting `plan.md@e7b835f73:1189-1192`’s “manager API unchanged.”

4. [BLOCKER] Successor acceptance is three-state, but the plan models only success or rollback.

For a definite pre-send failure or explicit helper rejection, no helper mirror rollback is needed. But `plan.md@e7b835f73:892-896` and item 13’s “publish error” incorrectly include unknown post-send outcomes.

Go stamps `DeferWorkers` before publishing at [manager_compile.go:330](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:330), writes the request and then reads the response at [process_control.go:145](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_control.go:145). Rust may already have swapped B at [snapshot.rs:344](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/snapshot.rs:344), marked it for persistence at [snapshot.rs:421](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/snapshot.rs:421), and written state before replying at [handlers/mod.rs:314](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/mod.rs:314).

Blindly rolling manager state back to A can therefore leave helper B latched while A’s tagged completion remains considered valid. That completion can consume B’s latch before B’s MAC prerequisites.

Required outcomes are:

- definitely rejected/not sent: resume A;

- ACKed/adopted: promote B and supersede A;

- unknown after send: keep a provisional B token, fence A completion, remain fail-closed, and resolve through helper generation/status or an idempotent exact-B retry.

The accepted generation must advance at adoption, not generic “Compile success.” Go adopts `m.lastSnapshot` at [manager_compile.go:354](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:354) but can still fail afterward at [manager_compile.go:369](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:369). This directly contradicts `plan.md@e7b835f73:997-1003`.

Operator arm is also incomplete: the plan clears the manager Boolean and helper latch, but not `m.lastSnapshot.DeferWorkers`. Route and scheduler publications clone that cache at [manager_overlay.go:188](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_overlay.go:188) and [manager_compile.go:575](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:575), so they can re-latch the helper. Clean operator-arm success must clear every Go shadow/cache and helper state; unknown arm responses require idempotent retry or equivalent reconciliation.

Finally, the first-commit auto-revert-to-empty path performs bootstrap teardown without compiling a successor at [daemon_apply_commit.go:651](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_commit.go:651) and [bootstrap.go:470](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/bootstrap.go:470). It cannot “advance at Compile acceptance.” It must explicitly cancel flags/debts/caches during teardown.

5. [BLOCKER] The fabric transaction remains incomplete, although clean guard-hit release is viable.

First, “pre-disable before RPC” is insufficient without failure semantics. Ctrl lookup, update, and readback can fail at [process_linkcycle.go:42](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_linkcycle.go:42). The projection RPC must not be sent unless ctrl=0 is verified or another equally verified fail-closed gate exists. The current binding clear is best-effort, so it is not that proof.

Second, UNKNOWN recovery fails to update Go’s accepted-projection cache. The plan writes helper-accepted fabrics back only on a clean `update_fabrics` reply at `plan.md@e7b835f73:822-825`. A later status poll reports the helper’s accepted set—Rust exports it at [status.rs:204](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/status.rs:204)—but Go’s status recorder only assigns `m.lastStatus` at [manager_status.go:28](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_status.go:28).

Counterexample: helper accepts B, response is lost, Go cache remains A; status eventually enables B, then a route/scheduler clone of `m.lastSnapshot` republishes A. UNKNOWN resolution must atomically adopt `status.Fabrics` into the accepted cache before permitting partial publishers, or keep them fenced while retrying the exact transaction.

For the user’s guard-hit question: a clean guard hit returns prior accepted status, and the immediate normal readiness path can re-enable it at [maps_sync.go:397](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/maps_sync.go:397) and [maps_sync.go:809](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/maps_sync.go:809). Predisable does not reset the readiness state. No separate release latch is required for that clean case; the outage is the RPC/application interval, bounded by the small-request three-second deadline at [process_control.go:33](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_control.go:33).

For an isolated UNKNOWN where the helper did not commit, release is roughly failed RPC plus the next one-second poll and its round trip—up to about seven seconds. Persistent control failure remains indefinitely fail-closed. Both shapes need explicit tests.

6. [MAJOR] Planned-identity attribution is sound, but f8 is not actually closed.

The correct rule appears at `plan.md@e7b835f73:718-739`. Hidden invariant 3 still mandates comparison against `(socket_ifindex,socket_queue_id)` at `plan.md@e7b835f73:1229-1235`. Those fields are independently Relaxed-loaded and stored at [snapshot.rs:35](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/binding_state/snapshot.rs:35) and [binding_state/mod.rs:873](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/binding_state/mod.rs:873), so that invariant revives the torn-read bug.

Item 16 also says mismatch zeroing “preserves” the live error at `plan.md@e7b835f73:1501-1503`, then correctly says mismatch copies no error at `:1518-1522`.

For the dropped `(c,q2)` case: silently omitting its per-binding error is correct. `refresh_bindings` only visits identities in the restored vector at [refresh_bindings.rs:25](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:25); fabricating an A row for rejected B’s q2 error would be misattribution. The operation-level reconcile error/stage remains available at [snapshot.rs:379](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/snapshot.rs:379). Item 16 should explicitly pin “no dropped-identity row, no B→A attribution, operation-level diagnostic retained.” A new diagnostic registry is optional, not required for correctness.

7. [MAJOR] The retry clock can still be held at destructive five-second churn.

The principal rule—retry forever at a 60-second floor, immutable membership fingerprint, deadline pull-earlier only—is correct at `plan.md@e7b835f73:1058-1078`. But pseudocode says every config/link event resets attempts at `:1040`, while stale normative text still requires an “attempt cap” at `:1127` and `:1301`.

Pull-earlier prevents starvation but does not prevent an event storm from repeatedly resetting the attempt exponent to five seconds. That would continuously tear down/recreate the worker set instead of reaching the intended 60-second floor.

Define separately:

- deadline pull: an event may pull `nextAt` earlier;

- attempt exponent: preserved across unrelated events and reset only by a meaningful immutable pending-membership or physical-state transition;

- no terminal attempt cap.

Add a test starting beyond attempt 12, injecting continuous config/link events, and proving attempts remain at the 60-second floor.

8. [MAJOR] The test plan can still green with the architectural holes intact.

- Item 12 sees only final server state. The production handler replans and immediately reconciles at [snapshot.rs:344](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/snapshot.rs:344). Separate planner and convergence units do not prove the actual handler delivered `pending` to the convergence locus. Add a reconcile-entry hook/trace proving the new identity was pending and only that locus armed it.

- Item 13 misclassifies “publish error” as pre-acceptance, omits lost-ACK B with/without MAC work, and its “ALL latch authorities” assertion names only manager Boolean and helper latch. It also retains compile-start language at `plan.md@e7b835f73:1663-1668` and `:1830-1835`.

- Item 16 contains the contradictory error rule described above; the torn/poisoned/name/parent cases are otherwise adequate.

- Item 17’s advance matrix lacks UNKNOWN adoption, the nil-config bootstrap teardown, and the distinction between an applied-identical HA fast path and an actually accepted reverse/older peer configuration.

- Item 19 lacks pre-disable fault injection, clean guard-hit immediate re-enable, UNKNOWN-with-no-helper-commit release, and response-loss → status-cache-adoption → partial-clone preservation.

- Retry tests omit an event storm at the 60-second floor.

- MAC tests omit configured-disabled and missing members, inline first validation without semaphore reacquisition, and the stale-attempt race: hold `applySem`, supersede the epoch, release it, and prove no netlink mutation occurs. The positive-provenance unit can otherwise green by manually constructing “epoch open, no active debt” without exercising the daemon-to-manager validation handoff.

Items 14, 15, and 18 are adequate for their narrow scopes.

9. [MINOR] An older authoritative HA reverse sync should supersede newer-local debt; no generation floor is appropriate.

Authority is role-based: only RG0 primary pushes at [daemon_ha_sync.go:318](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_ha_sync.go:318), while a secondary accepts the peer configuration at [daemon_ha_sync.go:534](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_ha_sync.go:534). The generation hash is content/deduplication, not an ordinal, at [daemon_ha_sync.go:381](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_ha_sync.go:381).

Once historically older peer content successfully applies, it is the accepted authoritative configuration. Increment the node-local monotonic acceptance epoch and supersede newer-local debt; never import or compare a peer numeric generation floor. Conversely, the applied-identical shortcut at [daemon_ha_sync.go:563](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_ha_sync.go:563) performs no adoption and must not advance.

Add that exact reverse-sync test and its pre-adoption-failure counterpart.

10. [MAJOR] v8.3 introduces new failure modes relative to master.

The new hazards are:

- valid configured-down RETH state can now force permanent global defer or be forcibly undone;

- a lost B snapshot acknowledgment can leave A’s completion owner operating on B’s helper latch;

- a lost fabric response can enable B while Go retains A, allowing the next partial clone to revert B;

- event storms can pin full worker teardowns at five-second cadence;

- every clean transient fabric guard hit intentionally creates a bounded ctrl-disable pulse;

- nil-config bootstrap teardown can leave epoch/debt state with no accepted config owner unless explicitly cancelled.

These arise from the proposed ownership and transaction model; they are not documentation nits.

DEMAND-REVISION
