# Codex plan review — round 12 — #6749 armed-state plan v8.7 (d63d98f75e3d)

**Reviewer:** Codex (hostile; companion task task-msdremqy-s0poqq, fresh thread; prompt /tmp/codex-6749-r12-prompt.txt). Raw output: /tmp/codex-6749-r12.out.

**Verdict: DEMAND-REVISION** (11 BLOCKER + 3 MAJOR; Q1 slot-writer hunt remains CLOSED).

---

Reviewed the exact `d63d98f75e3d` plan blob read-only; no files were modified.

1. **[BLOCKER] The §1 disposition table still materially overclaims closure.** The table is at `docs/research/6749-armed-state/plan.md:481-498`.

   | r11 row | Round-12 audit |
   |---|---|
   | f1 disposition audit | **OPEN** — nine “CLOSED” rows remain architecturally false. |
   | f2 pair authority | **OPEN/BLOCKER** — `appliedSnapshot` is delayed and can capture a generation the helper never stored; content dedup false-blocks. |
   | f3 request hybrids | **OPEN/BLOCKER** — `ConfigGeneration` is compared to a different helper scalar; old-helper suppression has an unobserved helper-ahead window. |
   | f4 completion token | **OPEN/BLOCKER** — full route/scheduler/#5134 republishes deterministically false-refuse legitimate completions. |
   | f5 ownership/exits | **OPEN/BLOCKER** — B is not retained, the status echo can erase staged intent, and forwarding verbs lack provenance/retry ownership. |
   | f6 `configEpoch` | **OPEN/BLOCKER** — ownerless B cannot be adopted; pending-XSK has no debt handoff; an asserted advance-point citation is actually an overlay. |
   | f7 debt cohort | **OPEN/BLOCKER** — down reclassification can discard an unsatisfied MAC obligation; bucket iii has no retry owner. |
   | f8 `LinkController` | **OPEN/BLOCKER** — control direction, locking, cycle history, recovery side effects, and eventual progress remain undefined. |
   | f9 environment/error chain | **OPEN/BLOCKER** — environment tokens lack causal/watch/incarnation semantics; propagated errors corrupt post-map bookkeeping. |
   | f10 tests | **OPEN/MAJOR** — the tests can green with the defects below. |
   | f11 budget | **NARROWLY CLOSED** only for relabeling 19 seconds as healthy baseline and disclosing approximately 70 seconds warm-clock. New unbounded suppression and semaphore-starvation hazards are omitted. |
   | AGY r11 clean | No fold was needed, but that verdict predates and does not validate the new v8.7 mechanics. |
   | SMR11-1 | **OPEN/BLOCKER** — `appliedSnapshot` is not the stable config-lineage refinement claimed at `plan.md:497`. |
   | SMR N2/N3 | **N2 OPEN/BLOCKER** — no production link-UP→rebind machinery exists. N3’s configured-disabled exclusion remains closed. |

   Q1’s same-version slot-writer hunt remains closed; I found no new `Registered && !Armed && none` producer. The failures below concern latch/lineage ownership rather than a seventh slot writer.

2. **[BLOCKER] `ConfigGeneration` is compared against the wrong helper authority.** The request and completion fences carry compile-stamped `ConfigGeneration`, which overlays deliberately preserve, but compare it to the helper’s ordinary stored snapshot `generation` (`plan.md:1217-1225`, `1526-1550`, `1846-1873`). Full overlays change that helper scalar:

   - Route overlay clones the snapshot, assigns a new `Generation`, sends full `apply_snapshot`, and marks it applied: `pkg/dataplane/userspace/manager_overlay.go:188-250`.
   - Scheduler republish does the same: `pkg/dataplane/userspace/manager_compile.go:575-621`.
   - #5134 clone-republish does the same while preserving the compiled lineage: `pkg/dataplane/userspace/manager_worker_arm_5134.go:57-92`.
   - Rust stores every full apply’s ordinary generation: `userspace-dp/src/server/handlers/snapshot.rs:150-155`.

   After any such publish, helper stored generation is `Goverlay` while the next fabric request or legitimate epoch completion carries the older `Gconfig`; refusal is permanent until another compile. This directly contradicts “no ordinary overlay can false-refuse” at `plan.md:1546-1550`. Test 13 covers only FIB and neighbor partial operations (`plan.md:2218-2223`) while claiming “arbitrary overlay churn”; it misses all three full-apply producers.

   The specified FIRST check is implementable before `refresh_fabric_links` and stored-fabric mutation at `handlers/mod.rs:144-174`, and likewise before rebind clearing. Ordering is not the defect; the compared domains are.

   I found no separate production compiler that obviously forgets the stamp—normal snapshot construction is at `manager_compile.go:214`. The token must instead be a distinct helper-stored config-lineage field. Making it Go-internal only cannot work.

   Mixed-version suppression is also insufficient: an old helper ignores the field, and after a timeout-landed B, Go remains at A until a successful poll even though the helper is already B (`process_control.go:145-161`, `manager_compile.go:350-365`). A fabric event in that unobserved interval sends A into B. Failed polls can extend the interval indefinitely; the required later helper restart bounds rollout duration, not this request-side safety gap.

3. **[BLOCKER] `appliedSnapshot.Generation` has asymmetric advance points and cannot serve as the proposed lineage gate.** The plan treats it as immediate helper-acknowledged authority (`plan.md:1182-1204`), but its actual contract intentionally delays capture while workers are deferred (`pkg/dataplane/userspace/applied_nat_view.go:64-98`).

   Both failure directions exist:

   - A clean deferred B advances helper `last_snapshot_generation`, while Go leaves `appliedSnapshot` at A. Thus every ordinary clean deferred B looks “helper-ahead” and is misclassified as an UNKNOWN timeout successor, inviting duplicate republish, epoch advance, and debt recreation.
   - During that defer window, FIB, neighbor, or resolved-fabric bookkeeping can advance mutable `m.lastSnapshot.Generation` without advancing the helper’s full-snapshot generation (`manager_generation.go:69-72`, `manager_neighbor.go:129-140`, `manager_ha.go:208-220`; Rust’s partial FIB path changes only FIB fields at `snapshot.rs:470-473`). Post-rebind capture then records the current mutated Go scalar at `process_linkcycle.go:219-233`, not the generation of the accepted full apply. Go can therefore record `G+1` while the helper remains at `G`, permanently wedging equality.

   `markAppliedSnapshotLocked` needs the exact accepted request lineage as an argument or separate stored state; reading mutable `m.lastSnapshot` later is not proof of helper authority.

4. **[BLOCKER] The staged-ahead disjunction false-blocks a fully converged content-dedup state.** Pending-XSK stores unpublished B at `manager_compile.go:272-313`. The content hash excludes generation, FIB, time, and the raw Config pointer (`pkg/dataplane/userspace/builder.go:156-178`). On equal forwarding content, `syncSnapshotLocked` merely advances `publishedSnapshot` and returns without a full apply or applied-snapshot capture (`process_status.go:72-80`).

   The resulting state is:

   - `lastSnapshot.Generation > publishedSnapshot` is false;
   - `lastSnapshot.Config != appliedSnapshot.Config` is true because B and A are distinct config objects;
   - helper and Go forwarding content are already equivalent.

   The plan’s gate at `plan.md:1187-1204` therefore blocks fabric adoption and all fabric sends forever. The next poll returns immediately at `process_status.go:15-16`, so there is no repair owner. This falsifies the “survives content-dedup” claim at `plan.md:497`.

   Pending-XSK before dedup is correctly detected as staged. A clean #5134 publish also makes both disjuncts false correctly, but then fails the separate `ConfigGeneration` fence in finding 2. I found no ordinary equality-matched false-adopt; the concrete defects are false-blocking and the contaminated applied generation in finding 3.

5. **[BLOCKER] Timeout-landed B cannot be recovered because Go retains neither B nor `B.ConfigGeneration`.** The claimed owner is status-poll exact-equal republish followed by B-keyed debt creation (`plan.md:1554-1573`, `2224-2232`). In production, Compile sends a local `snap`, but only installs it into manager bookkeeping after a clean response (`manager_compile.go:342-365`). On timeout/EOF, B is discarded.

   Moreover, `bumpGeneration` eagerly mutates the manager counter (`manager_generation.go:33-37`, called at `manager_compile.go:214`). A later compile therefore mints C rather than reproducing B. `syncSnapshotLocked` knows only retained A and normally exits because A is already published (`process_status.go:10-16`). The #4036 exact-equal rule requires the identical generation pair (`userspace-dp/src/server/handlers/snapshot.rs:56-68`), while `ConfigGeneration` is explicitly absent from wire/status state (`plan.md:1869-1873`).

   There is consequently nowhere for Go to read B’s compile token, exact snapshot content, or precheck member→MAC cohort. Reusing B’s ordinary generation with newly rebuilt content would also violate the flow-cache meaning of exact-equal. The plan needs durable in-flight snapshot retention or a different safe recompile/adoption protocol.

   The test is internally inconsistent: the B-with-MAC case assumes autonomous poll ownership, while the B-without-MAC case falls back to “the next apply” (`plan.md:2233-2235`)—the exact non-owner rejected in r11.

6. **[BLOCKER] The six-exit protocol can erase defer intent before B is even published, and its verbs lack provenance.** The worst new v8.7 race is the unconditional `stored_defer_workers` echo reconciliation at `plan.md:1727-1733`:

   - Daemon sets manager defer intent before Compile: `pkg/daemon/daemon_apply_dataplane.go:45-82`.
   - Compile constructs B outside `m.mu`, only acquiring it afterward: `manager_compile.go:200-229`.
   - It stamps `snap.DeferWorkers` from the then-current manager flag at `manager_compile.go:330-332`.

   A 1 Hz status poll can land between those operations. Helper A truthfully echoes `stored_defer_workers=false`; plan-directed reconciliation clears B’s staged manager intent; Compile then publishes B non-deferred and starts workers before MAC programming. A==A lineage cannot detect this because B has not yet entered `m.lastSnapshot`. This recreates the issue’s pre-MAC activation race.

   The additive field also defaults missing to false without a protocol bump (`plan.md:1834-1836`, `1858-1862`), making an old helper’s omission and a fresh helper’s empty state indistinguishable from an authoritative clear.

   Exits (c)/(d) are likewise not distinguishable. The plan authorizes latch consumption for explicit operator arm/disarm but keeps forwarding verb signatures unchanged (`plan.md:1740-1748`, `1874-1877`). The same Boolean verb comes from the public operator API, automatic unsupported-config disarm, and HA desired-state reconciliation (`manager_status.go:78-129`, `manager_ha.go:568-598`, `601-654`). Rust receives only `armed` (`userspace-dp/src/server/handlers/forwarding.rs:12-33`). Clearing on every false lets an automatic disarm cancel an unfinished epoch; not clearing makes explicit exit (d) impossible.

   The promised UNKNOWN disarm retry also has no durable owner: `SetForwardingArmed` sends once and returns the error, while desired-state sync retries its independently derived HA/config intent. The test matrix at `plan.md:2241-2248` omits lost global disarm entirely. Ordinary helper restart is another unmodelled authority transition: `stopLocked` is used for unhealthy and configuration-driven restarts (`process.go:18-33`) and resets published/applied state (`process.go:246-264`), not merely nil-config teardown.

7. **[BLOCKER] Every-attempt reclassification can discard an unsatisfied MAC obligation.** Bucket i means MAC mismatch; bucket ii/linkRecovery means MAC already correct and link down (`plan.md:1337-1361`, `1369-1388`). Yet a down bucket-i member is moved to non-gating linkRecovery before mutation (`plan.md:1400-1418`).

   A mismatched member already down at the first attempt therefore moves to a collection that only retries link-up without ever receiving the desired MAC. The same loss occurs after a precheck-to-attempt flap. Completion can then arm the dataplane with the wrong member MAC. Transfer must require proof that the desired MAC is installed; otherwise its MAC phase remains in `macEpochDebt`.

   Bucket iii has the converse hole: it creates no entry. If a correct/up member goes down after precheck, there is no “next validation attempt” on which to reclassify it. `programRethMAC` equality is a no-op without a link check (`pkg/daemon/daemon_reth.go:238-246`).

   The test plan positively requires the defective downgrade at `plan.md:2582-2589`. Lifecycle text also remains collection-ambiguous: successor cancellation says “the debt/debts” (`plan.md:1463`, `1568`), and member removal cancels “its own entry” without specifying one or both collections (`plan.md:2590-2593`).

8. **[BLOCKER] `AttemptMACDebt` is directionally and transactionally unimplementable as specified.** The plan declares manager→daemon synchronous dispatch (`plan.md:1883-1924`). The actual `LinkController` is obtained by the daemon and implemented by a wrapper containing only `*Manager` (`pkg/dataplane/apply.go:130-134`, `pkg/dataplane/userspace/controllers.go:11-39`, `manager.go:379-381`). Adding a method there creates daemon→manager dispatch. The plan’s own test then asks for a “REAL daemon-to-manager validation handoff” (`plan.md:2605-2609`). Both directions are needed, but only one method is designed.

   Manager owns `configEpoch` and debt under `m.mu`; daemon owns `applySem` and netlink. Holding `m.mu` across a manager→daemon attempt makes settlement/completion callbacks reentrant; releasing it gives the daemon no authoritative epoch check before each mutation. The plan’s `d.configEpoch` at `plan.md:1906-1910` invents a second authority without a synchronization contract.

   The result type also omits `linkCycled` (`plan.md:1893-1898`) even though `programRethMAC` can install the MAC, cycle the NIC, and then return `(true,error)` on final link-up failure (`daemon_reth.go:257-270`). A later equality no-op loses that history and can choose full reapply rather than the required XSK rebind.

   Finally, bare `programRethMAC` plus reread omits mandatory post-cycle repairs: DAD/link-local, RX-VLAN, VLAN child MACs, VIP/VRRP, announcements, RA, and XSK rebind (`pkg/daemon/daemon_apply_dataplane.go:285-401`). The claimed existing link-UP→rebind owner is false: the sole production `NotifyLinkCycle` call is this apply flow at line 393; the general link monitor only emits SNMP traps (`daemon_flow.go:725-743`, `857-887`).

9. **[BLOCKER] TRY-acquire has an indefinite starvation execution.** Each contention discards the attempt until the next 5→10→30→60-second debt tick (`plan.md:1449-1458`). Production contains recurring `applySem` owners, including an always-on fixed 30-second proxy-ARP reconcile (`pkg/daemon/daemon_proxyarp.go:16-24`, `220-280`).

   Once debt reaches 30/60 seconds, a legal schedule can phase-lock every TRY with that periodic owner indefinitely, despite no commit, MAC failure, or persistent control fault. Commit priority is correct; unbounded recovery starvation is not. Use a short jittered contention retry, wake-on-release, or an explicit maximum-delay/fairness invariant. The test at `plan.md:2626-2635` proves only one collision followed by a manually free semaphore.

10. **[BLOCKER] `guard_env_generation` has neither causal sampling nor a rejected-candidate/lifecycle owner.** The plan hashes candidate inputs at later “telemetry evaluations” (`plan.md:1115-1125`). Current queue discovery is a fresh sysfs read (`userspace-dp/src/server/helpers/planning.rs:605-621`), and status refresh currently runs after handler work (`handlers/mod.rs:144-174`, `264-266`). Unless the guard verdict and returned generation derive from one captured sample, sysfs can recover between rejection and token generation, causing Go to cache `(B,g-good)` and suppress B forever.

   A rejected new-parent B is not stored (`plan.md:1223-1225`). Current helper state retains only its accepted snapshot (`userspace-dp/src/server/state.rs:35-40`), full status reports fabrics from that snapshot (`helpers/status.rs:203-208`), and planning derives candidates from it (`helpers/planning.rs:455-479`). Recovery of a B-only parent is therefore invisible unless the design explicitly retains and reevaluates rejected candidates.

   Cache generation is also not helper-incarnation scoped. A single Manager survives helper replacement, while each Rust process initializes fresh generation/status state (`process.go:18-34`, `userspace-dp/src/server/lifecycle.rs:182-203`). An H1 `(B,0)` rejection can suppress the first valid H2 request when H2 also starts at zero. There are not two simultaneous helpers behind this Manager; sequential process incarnations are the real alias.

   Finally, observing a generation bump does not dispatch a send: the manager status loop performs no fabric synchronization (`process_status.go:152-201`). Production fabric refresh runs on events or a 30-second ticker (`daemon_ha_fabric.go:243-256`, `833-849`), adding an unbudgeted 30 seconds even after a correct environmental observation.

11. **[BLOCKER] Propagating `SyncFabricState` errors through the current wrapper corrupts transaction semantics.** `SetFabricForwarding` commits the BPF map first and then invokes helper synchronization (`pkg/dataplane/userspace/controllers.go:112-132`). If the new error is returned, callers interpret an already-committed map mutation as map failure.

   Fab0 has another explicit sync, but fab1 and both clear legs rely solely on the wrapper (`pkg/daemon/daemon_ha_fabric.go:738-756`, `944-957`, `771-778`, `969-976`). On a clear, the map can be zero while `fabricPopulated` remains true; takeover readiness trusts that Boolean (`pkg/daemon/daemon_ha.go:774-783`). Swallowing the error instead leaves fab1/clear failures unscheduled.

   The contract needs separate map-commit and helper-sync outcomes/debt, or explicit ordered synchronization in every caller. Routing only the fab0 call at `daemon_ha_fabric.go:752-759` is insufficient.

12. **[MAJOR] The `configEpoch` advance contract remains internally inconsistent.** The plan says only observed-accepted compiled publishes advance and overlays never do, but cites `manager_compile.go:618` as a compile advance point (`plan.md:1588-1608`). Line 618 is the scheduler-overlay `publishedSnapshot` assignment inside the full republish at `manager_compile.go:575-621`, explicitly one of the paths that must not advance the epoch.

   The #5134 “never advance” correction is sound. The broader handoff is not: pending-XSK B is staged without advancing (`manager_compile.go:272-313`), daemon can already perform B’s MAC cycle, and later `syncSnapshotLocked` publishes B without rerunning the daemon precheck. No retained B cohort/results or atomic A→B debt transfer is specified. Clean deferred B is also misdetected as helper-ahead because of finding 3, permitting a second epoch advance after its normal clean compile already advanced.

13. **[MAJOR] The v8.7 test suite can green with the architecture broken.**

   - Fence/false-refusal tests cover FIB and neighbor partial updates, not route, scheduler, or #5134 full republishes (`plan.md:2218-2223`).
   - Authority tests omit partial scalar churn during delayed `appliedSnapshot` capture and distinct-Config content dedup (`plan.md:2366-2389`).
   - Ownerless-B tests assume retained B and exact-equal reconstruction rather than proving their production owner (`plan.md:2224-2235`).
   - UNKNOWN tests omit lost global disarm, old-helper missing echo, fresh-helper state, mid-defer restart, and the status-poll-before-Compile race (`plan.md:2241-2248`).
   - Debt tests positively bless losing the mismatched/down member’s MAC phase and omit bucket-iii flap (`plan.md:2582-2589`).
   - Attempt tests omit real cycle side effects, sticky `linkCycled`, bidirectional locking, and repeated contention (`plan.md:2590-2635`).
   - Environment tests use synthetic sequential generation changes; they omit same-sample TOCTOU, B-only rejected watches, helper-generation reuse, and status-to-send dispatch (`plan.md:2432-2440`, `2461-2466`).
   - Error tests cover one chain, not fab1, clears, or post-map-commit latch truth (`plan.md:2448-2456`).
   - Budget tests omit the 30-second environment dispatch delay and semaphore starvation (`plan.md:2473-2484`).
   - Protocol canaries name only `activation_state` and `complete_deferred`, omitting `expected_snapshot_generation`, `stored_defer_workers`, and `guard_env_generation` plus their missing-field semantics (`plan.md:2488-2490`).

14. **[MAJOR] The named approximately 70-second budget is defensible, but the actual v8.7 hazard budget is not.** The plan now honestly labels approximately 19 seconds as healthy baseline and approximately 70 seconds as warm-clock recovery (`plan.md:1230-1247`). That 70-second case is continued fail-closed recovery for identities already at the retry floor; it is operationally severe but not, alone, an unsafe architecture. Persistent verified-control failure remaining indefinitely fail-closed is also the correct safety posture if retries and diagnostics remain alive.

   Unacceptable for severity High are the unbounded cases introduced by v8.7: environment suppression with no rejected-candidate/incarnation owner, deterministic `ConfigGeneration` false-refusal, `appliedSnapshot` lineage wedging, TRY-acquire starvation, and ownerless B. Even the bounded environment-recovery path can become roughly 30 seconds plus the disclosed warm-clock budget.

   New hazards versus v8.6/master include premature non-deferred B publication from status echo, full-overlay completion refusal, content-dedup permanent divergence, unsourceable B adoption, loss of required MAC programming, autonomous cycles without network/XSK repairs, helper-incarnation suppression aliasing, and post-map error/readiness skew.

DEMAND-REVISION

Codex session ID: 019fc997-fbf4-7d33-b5be-23dcb706bc6e
Resume in Codex: codex resume 019fc997-fbf4-7d33-b5be-23dcb706bc6e
