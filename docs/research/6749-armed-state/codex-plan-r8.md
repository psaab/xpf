Reviewed the exact committed `f84e0827a` blob; the worktree copy matched it. Source references below are from the same commit. No files were modified.

1. [BLOCKER] The round-7 disposition table is materially false.

The table claims every row closed at [plan.md:164](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:164), but the audit is:

| r7 row | Round-8 result |
|---|---|
| f2 `update_fabrics` transaction | REOPENED/BLOCKER — successful replies close the gate, but timeout/EOF after Rust mutation leaves Go’s ctrl/maps stale and enabled. |
| f3 guard authority | CLOSED narrowly — staged projection, exact read failure, helper-authoritative writeback, and production-removal scope are coherent. |
| f4 leaking epoch | REOPENED/BLOCKER — predecessor debt is canceled before successor acceptance; explicit arm clears only one of three latch authorities. |
| f5 terminal cap | PARTIAL/MAJOR — the core now retries forever, but normative text still specifies an attempt cap and reset semantics remain unsafe. |
| f6 debt contracts | REOPENED/BLOCKER — acceptance, production advance points, cross-layer epoch handoff, restart reconstruction, and stale-work fencing remain undefined. |
| f7 torn identity | PARTIAL/MAJOR — §5-C chooses immutable planned identity, but hidden invariant 3 still mandates the torn socket tuple. |
| f8 claim boundary | PARTIAL/MAJOR — §5-C, item 15, and §10 delete claims on rename; hidden invariant 8 says claims survive rename. |
| M9 tests | OPEN/MAJOR — several required tests can still green around the production boundary. |
| AGY aggregate | PARTIAL — arm-direction gating is sound; `deferWorkers && !hasActiveMACDebt` is not positive proof of current-epoch MAC completion. |
| SMR aggregate | CLOSED narrowly — exact guard cause, per-member cancellation, and plan-scoped overlap convergence are sound. |

The direct contradictions are visible in the no-cap rule at [plan.md:934](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:934) versus “attempt cap” at [plan.md:1150](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1150), planned identity at [plan.md:673](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:673) versus socket identity at [plan.md:1098](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1098), and rename deletion at [plan.md:594](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:594) versus rename survival at [plan.md:1123](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1123).

2. [BLOCKER] Compile-start rollover destroys the old epoch before the successor has earned supersession.

The plan cancels the prior tagged/MAC debts at compile start at [plan.md:796](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:796), while separately promising that only a newer accepted config supersedes debt and a failed compile cancels nothing at [plan.md:828](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:828) and [plan.md:870](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:870).

Concrete sink:

- Deferred A’s tagged completion fails. A’s helper latch remains set and A owns a tagged retry.
- No-MAC successor B begins and cancels A’s retry.
- B fails before helper acceptance—possible during shim compile/build or process/publish setup at [manager_compile.go:200](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:200) and [manager_compile.go:324](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:324).
- A’s helper latch remains, but the manager flag and tagged owner are gone. An untagged retry cannot consume it by [plan.md:856](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:856).

The successor must be provisional: preserve/suspend A, publish B, then atomically promote B and cancel A only at the defined acceptance point; resume A on pre-accept failure.

For Q4, “cancel then open” prevents self-cancellation only if it is one tokenized operation under the manager lock. The current setter merely changes a Boolean under its own lock at [manager.go:485](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager.go:485), while daemon and manager own different debts. The plan defines neither that atomic operation nor fencing for an already-running MAC retry.

Explicit operator arm has the same ownership defect: it clears only `m.deferWorkers` at [plan.md:808](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:808), while helper and cached-Go latches are cleared only by successful tagged completion at [plan.md:838](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:838). The arm may work once, but a later clone can re-latch, or a later pending state can be stranded behind the surviving helper latch. Operator completion must clear manager flag, helper snapshot latch, `lastSnapshot`, and `publishedSnapshot` atomically.

3. [BLOCKER] Q3 has no implementable accepted-generation boundary, and the production advance set is incomplete.

“Compile success” cannot be the boundary. There are two authoritative adoption shapes:

- Deferred-XSK startup adopts `m.lastSnapshot` and returns success at [manager_compile.go:272](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:272).
- Normal publish receives the helper ACK and adopts `m.lastSnapshot` at [manager_compile.go:350](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:350), but Compile can still return errors afterward at [manager_compile.go:369](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:369).

Therefore the epoch must advance once at full-config adoption, including post-ACK error returns, but not on pre-adoption failure. Calling it “successful Compile” permits both wrong implementations.

Every production full-config adoption that can move the local monotonic epoch is:

- Boot application of the active config at [daemon_run_bringup.go:516](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_run_bringup.go:516).
- Local commit, commit-confirmed application, config-poll, event-engine, in-process CLI, and manual rollback paths enumerated at [daemon_apply.go:38](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply.go:38).
- DHCP and dynamic-feed recompiles at [daemon_dhcp.go:73](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_dhcp.go:73) and [daemon_feeds.go:26](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_feeds.go:26).
- Non-duplicate HA peer sync at [daemon_ha_sync.go:571](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_ha_sync.go:571). The applied-identical fast path at line 563 does not move it, and the peer’s numeric epoch is never imported.
- A rollback to older content and non-nil commit-confirmed auto-revert at [daemon_apply_commit.go:685](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_commit.go:685).
- The mandatory same-config re-apply at [daemon_apply_dataplane.go:466](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_dataplane.go:466).

Rollback must increment a local monotonic epoch; it must never restore an older number. Successful rollback cancels newer-content debts; pre-adoption rollback failure retains them. The first-commit auto-revert to no config is teardown, so it must cancel debts during teardown rather than manufacture a config epoch. Confirmation alone performs no apply and moves nothing.

FIB, overlay, scheduler, neighbor, and fabric-telemetry publications do not move this epoch. Since `config.Config` has no origin or generation at [types.go:270](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/config/types.go:270), excluding boot/DHCP/feed while retaining the same manager API is impossible without an explicit apply-origin/adoption token.

4. [BLOCKER] The MAC-completion contract is not restart-safe or positively provenance-gated.

The current precheck examines only MAC inequality and silently skips missing links at [daemon_apply_dataplane.go:45](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_dataplane.go:45). `programRethMAC` then no-ops when the MAC already matches, without checking link-up, at [daemon_reth.go:238](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_reth.go:238). Thus “MAC installed, `setUp` failed, daemon restarts” reconstructs no debt: boot sees the correct MAC, opens no epoch, and leaves the member down.

The plan promises both-phase restart revalidation at [plan.md:814](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:814), but supplies no reconstruction rule. Boot/successor precheck must classify every desired member as missing, wrong-MAC, or down and recreate the epoch/debt from active config.

Likewise, `m.deferWorkers && !m.hasActiveMACDebt` at [plan.md:856](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:856) proves only absence of recorded failure—not successful completion for the current epoch. Use an explicit current-epoch `macPrerequisitesSatisfied` token, or treat incomplete phases as active debt from epoch opening.

Finally, autonomous retry must acquire the daemon’s apply serialization or revalidate its epoch immediately before each netlink mutation. `applySem` currently serializes all config entry points at [daemon.go:485](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon.go:485); the plan never says the new retry participates in it.

5. [BLOCKER] `update_fabrics` still lacks fail-closed handling for an unknown RPC outcome; Q2’s outage budget is understated.

The successful-response design is correct: mark every registered non-operator slot explicitly unarmed+pending, return status, and apply ctrl-disabled before binding rows. But the plan only describes applying the returned status at [plan.md:754](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:754).

A timeout/EOF can occur after Rust commits the projection and marks the vector. The current Go path simply returns on request failure at [manager_ha.go:170](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_ha.go:170), and the transport explicitly permits response-read failure after sending at [process_control.go:129](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_control.go:129). Go can therefore retain `ctrl.Enabled=1` and stale READY rows until a later successful poll—or indefinitely during persistent control failure. Pre-disable whenever the requested projection differs from the cached accepted projection, and remain fail-closed on an unknown outcome.

The busy watchdog is not a fallback: it requires at least one `Registered && Armed` binding at [maps_sync.go:1435](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/maps_sync.go:1435), while this design explicitly unarms all of them.

For Q2, I choose mark-and-retry, but only after that transaction fix:

- Window length: it is worse. The first rebind begins after roughly 5 seconds; readiness may take nearly 10 seconds at [bringup.rs:30](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:30), followed by the next status application. Worst successful convergence approaches 15–16 seconds, not “≤5s”.
- Complexity and lock/timeout surface: the in-handler wrapper is worse. It couples a 10-second Rust reconcile to a small-control-RPC deadline and holds both Go’s manager lock and Rust’s server-state lock across readiness. I found no proven current lock cycle, but it creates substantially more head-of-line and timeout-but-landed state.
- Mark-and-retry keeps mutation short and recovery in one existing mechanism, provided Go pre-disables and unknown outcomes stay fail-closed.

The f3 authority row itself is closed: helper status already carries its accepted fabrics at [status.rs:203](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/status.rs:203), and the explicitly-empty production limitation is honestly scoped.

6. [MAJOR] Q1 has a literal mixed-version producer; Q5 does not, but the identity and claim invariants remain contradictory.

For a v8.2 helper implementing S1–S5/C1–C3 literally, I found no additional terminal producer. The production writers are the planner, binding/queue verbs, and global fan-out at [planning.rs:500](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:500), [binding.rs:27](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/binding.rs:27), [queue.rs:29](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/queue.rs:29), and [status.rs:418](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/status.rs:418).

Literal Q1 nevertheless has the documented new-Go/old-helper case: the current planner constructs a new valid slot from `BindingStatus::default`, sets `registered=true`, and leaves `armed=false` at [planning.rs:500](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:500); both fields default false at [binding.rs:292](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/protocol/binding.rs:292). The missing additive state field is read as `none`, and desired equality can suppress a global arm at [manager_ha.go:601](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_ha.go:601). D warns, so it is not D-silent, but it satisfies the literal producer question and makes the helper-restart upgrade note load-bearing.

For Q5, no healthy parent re-key mismatch exists. Orphan VLANs are re-keyed into parent name/ifindex before the binding is created at [planning.rs:411](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:411); fabric parents use the same fields at [planning.rs:464](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:464); `plan_workers` copies those exact binding fields into `workers.identities` at [bringup.rs:273](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:273).

Item 16 can still green an unsafe implementation unless it poisons the relaxed socket tuple to appear equal to restored A while immutable planned identity remains B. It must also distinguish:

- Same planned identity with bind failure: copy that worker’s `last_error`, even though its socket tuple is zero.
- Planned-identity mismatch: never copy rejected B’s `last_error` onto restored A; preserve only A’s pre-restoration diagnostic.

7. [MAJOR] Retry reset semantics remain underspecified; the split conclusion is only conditionally correct.

The forever retry at [plan.md:933](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:933) fixes r7’s hard-cap blocker. But “reset on pending/config/link change” at [plan.md:945](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:945) needs an exact clock rule:

- Resetting `nextAt=now+5s` on every link/config event permits frequent events to postpone recovery forever.
- Including `last_change`, `last_error`, or other retry-mutated diagnostics in the pending fingerprint can reset every failed S4 pass and keep full teardown at the 5-second rate.

The actionable fingerprint should be immutable pending identity membership, and reset should only pull the deadline earlier, never postpone an already-due retry.

Q7: MAC debt and pending retry remain load-bearing and cannot be follow-ups. D is technically independent after the wire field lands—it reads status and emits an edge warning, without changing any state or reconcile path. It can be a separate stacked change, but the issue must not be declared complete or released without it: otherwise the detection leg is knowingly absent.

8. [MAJOR] The test plan can still green with the blockers intact.

- Item 12 at [plan.md:1257](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1257) is a useful happy path but can green if new slots are directly armed rather than exercising pending ownership.
- Item 13’s overlap test is good, but rollover tests only successful successors at [plan.md:1284](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1284). Add pre-accept successor failure, post-ACK error, a status tick at the rollover/open boundary, stale in-flight A completion, and explicit arm clearing all latch authorities.
- Item 14’s typed failure matrix is good if “retry” is production-scheduled rather than a direct test request.
- Item 15’s candidate-drop/rename/contraction coverage is good once invariant 8 stops contradicting it.
- Item 16 at [plan.md:1327](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1327) needs restored `guard.snapshot` equality, deliberately torn/poisoned socket fields, interface-name-only mismatch, positive parent-rekey equality, and correct A-error-versus-B-error attribution.
- Item 17 at [plan.md:1354](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1354) must distinguish pre-adoption failure from post-ACK Compile error and exercise boot, DHCP/feed, HA sync, older rollback, auto-revert, and deferred-XSK adoption—not merely one selected failed Compile.
- Item 18 is adequate for its narrow same-plan deficit.
- Item 19’s mark-all, authority-adoption, and final-coalesce cases are useful, but it lacks response-loss/pre-disable, integrated Go ctrl application, and separate projection changes for `name`, `parent_linux_name`, and `rx_queues`.

The Go retry tests include recovery after attempt 12 and first-Compile coverage, but lack reset-starvation/self-reset cases. The MAC tests name multi-member, supersession, and restart, yet can green by manually reconstructing debt; restart must instantiate a fresh daemon with active config, correct MAC, and administratively-down link. The provenance test currently pins the insufficient negative formula rather than positive current-epoch MAC success.

9. [MAJOR] v8.2 introduces several hazards not present in this form on master.

- Every accepted fabric projection change now intentionally disables the entire dataplane, potentially for about 15–16 seconds.
- A lost `update_fabrics` response creates a new Rust-unarmed/Go-enabled split-brain.
- Eager rollover creates a new failed-successor debt-loss sink.
- Explicit operator arm creates a new dual-cache/helper-latch afterlife.
- Ambiguous retry resets can add perpetual 5-second worker-set teardown or event-driven starvation.
- An origin-undefined accepted epoch can let background full recompiles, HA sync, or rollback cancel the wrong debt.

These are not documentation nits; they are consequences of the proposed ownership model and must be designed out before implementation.

DEMAND-REVISION
