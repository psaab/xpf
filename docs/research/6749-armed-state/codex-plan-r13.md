# Codex plan review — round 13 — #6749 armed-state plan v8.8 (c2147e57329e)

**Reviewer:** Codex (hostile; companion task task-msdu5oma-68z6tz, fresh thread; prompt /tmp/codex-6749-r13-prompt.txt). Raw output: /tmp/codex-6749-r13.out.

**Verdict: DEMAND-REVISION** (12 BLOCKER + 3 MAJOR).

---

Reviewed the exact committed blob `c2147e57329eea60fb1e479494744350950fd8f2` read-only. No files were modified.

1. **[BLOCKER] §1 still materially overclaims closure.** The disposition table is at `docs/research/6749-armed-state/plan.md:592-612`.

   | r12 row | Round-13 audit |
   |---|---|
   | f2 wire lineage | **OPEN/BLOCKER** — pending-XSK clones can publish B under A’s epoch; ambiguous failures can reuse an epoch. |
   | f3 `appliedSnapshot` | **NARROWLY CLOSED** — removing it from adoption fixes the original asymmetric-capture defect. |
   | f4 dedup | **OPEN/BLOCKER** — a local epoch collapse cannot change the helper’s stored epoch. |
   | f5 B ownership | **OPEN/BLOCKER** — active-config reapply has no production owner, and A recovery can overwrite B first. |
   | f6 echo/provenance/restart | **OPEN/BLOCKER** — defer intent lacks an API/entry reservation; operator provenance cannot reach Rust; restart reapply has the same missing owner. |
   | f7 obligations | **OPEN/BLOCKER** — recovery can cycle a live-XSK interface without prior quiescence. |
   | f8 debt contract | **OPEN/BLOCKER** — the daemon scheduler cannot obtain manager-owned work/epoch/backoff through the two proposed methods. |
   | f9 blocking acquire | **OPEN/BLOCKER** — 10 seconds does not establish progress and can add priority inversion. |
   | f10 environment token | **OPEN/BLOCKER** — one last-rejected value is not loss-safe, and flapping can pulse ctrl indefinitely. |
   | f11 typed outcome | **OPEN/BLOCKER** — no keyed debt state machine, clear rule, scheduler, or readiness propagation is specified. |
   | f12 advance/handoff | **OPEN/MAJOR** — two real pending-XSK acceptance legs are omitted from the “ONLY” list. |
   | f13 tests | **OPEN/MAJOR** — several tests positively encode incorrect behavior. |
   | f14 budget | **OPEN/MAJOR** — multiple residual unbounded High-severity executions remain. |

   Therefore f1 is also open, and the aggregate AGY/SMR “CLOSED” rows inherit these failures.

2. **[BLOCKER] The epoch allocator cannot represent an ambiguous post-write failure, and “once per config” is the wrong mint unit.** Normal commits (`pkg/daemon/daemon_apply_commit.go:194-246`), HA-peer applies (`daemon_apply_commit.go:326-354,489`), rollback/auto-revert (`daemon_apply_commit.go:629-698`), DHCP recompiles (`daemon_dhcp.go:73-90`), feed recompiles (`daemon_feeds.go:14-41`), and boot/background applies (`daemon_apply.go:38-70`; `daemon_run_bringup.go:516-520`) all funnel through `Manager.ApplyConfig → Compile` at `pkg/dataplane/userspace/manager.go:348-355`. A centralized mint can therefore cover those paths.

   But one stored config can be accepted by several Compile invocations: initial deferred compile, mandatory live-MAC reapply (`daemon_apply_dataplane.go:466-489`), and the proposed active-config reapply. That is two or three epochs for one config, contrary to `plan.md:1859-1866`; the contract must say “per accepted Compile invocation” and define same-config debt transfer.

   More fundamentally, the epoch must be placed on the wire before acceptance is observed. After a timeout/EOF, the request may have landed (`pkg/dataplane/userspace/process_control.go:145-161`), yet the plan rolls back with no epoch move and declares only two counters (`plan.md:1818-1829,1858-1866`). If pending rolls back, the next config can reuse the landed candidate epoch, allowing stale completions to pass the fence. If pending remains advanced to burn it, A debts fail the proposed `epoch == pendingConfigEpoch` validation (`plan.md:2241-2245`). A separate monotonic reservation/high-water is required. A pre-wire build failure may reuse or burn harmlessly; an ambiguous post-write failure must burn uniquely.

3. **[BLOCKER] The overlay carry rule publishes unpublished B under accepted epoch A.** Pending-XSK Compile exposes B through `m.lastSnapshot` without publishing it (`pkg/dataplane/userspace/manager_compile.go:245-313`). The same apply can then run the route-leak republish (`pkg/daemon/daemon_apply.go:322-335`), which clones `m.lastSnapshot` and publishes it (`manager_overlay.go:188-239`). Scheduler and #5134 likewise clone that pointer (`manager_compile.go:575-605`; `manager_worker_arm_5134.go:57-80`). v8.8 orders every such clone to carry `acceptedConfigEpoch` (`plan.md:1372-1375,2171-2179`), so B’s full content is installed under A’s lineage.

   The complete same-version full-publish census is normal Compile, pending-XSK deferred publish, route overlay, scheduler republish, and #5134. There is no missed sixth producer. However, the deferred producer’s clean publish and status-catch-up acceptance live at `pkg/dataplane/userspace/process_status.go:18-37,120-139`, contradicting the “`:361/:365 ONLY`” claim at `plan.md:1867-1875,2743-2747`.

   `update_neighbors` is correctly excluded: Go sends only neighbors plus their replace generation (`manager_neighbor.go:97-112`), and Rust mutates only the neighbor table (`userspace-dp/src/server/handlers/neighbors.rs:42-57`). `bump_fib` similarly changes only `fib_generation` (`handlers/snapshot.rs:470-473`).

4. **[BLOCKER] Content-dedup cannot transfer wire lineage.** The current hash zeros generation, FIB generation, time, and raw Config—but not the proposed epoch (`pkg/dataplane/userspace/builder.go:156-178`).

   - If `config_epoch` remains hashed, A and byte-identical B never dedup, so the specified case is unreachable.
   - If implementors exclude it, `syncSnapshotLocked` sends nothing (`process_status.go:72-80`), leaving the helper storing A’s epoch. Locally setting `accepted=pending=B` as required by `plan.md:1346-1349,1874-1878` makes the next status fail the adoption/latch gate and every B-tagged request refuse.

   The test’s assertion that adoption proceeds with “no repair owner needed” (`plan.md:2781-2786`) is therefore false. An explicit lineage-transfer publish or reapply is required.

5. **[BLOCKER] Active-config reapply has neither an owner nor a safe divergence interval.** On publish failure, Compile returns before retaining B in `m.lastSnapshot` or `m.cfg` (`pkg/dataplane/userspace/manager_compile.go:350-365`). The status loop is manager-local, holds `m.mu` for the tick, and contains no daemon/configstore hook (`process_status.go:152-257`). Yet the plan both requires that poll to reapply daemon-owned ActiveConfig and says the manager never calls the daemon (`plan.md:1683-1690,1831-1849`).

   Worse, A’s debts remain authorized. The poll processes status and then #5134 (`process_status.go:169-201`). An A #5134 retry clones A with a newer ordinary generation (`manager_worker_arm_5134.go:57-80`); Rust accepts that newer generation (`userspace-dp/src/server/handlers/snapshot.rs:83-106`) and overwrites timeout-landed B. The helper-ahead signal then disappears, so the advertised reapply never triggers. Suppressing only `SyncFabricState` is insufficient; every old-lineage full clone must be suppressed during divergence.

   The design needs a daemon-owned, single-flight reapply debt: enqueue after releasing `m.mu`, acquire `applySem`, reread ActiveConfig, use a uniquely reserved epoch, back off repeated UNKNOWNs, suppress all conflicting clone producers, and clear only on observed matching acceptance.

6. **[BLOCKER] Mixed-version suppression does not protect the stated upgrade window.** New Go with an old helper receives epoch 0 forever and the helper ignores `expected_config_epoch`. Suppression checks only `pending > accepted` or `status > accepted` (`plan.md:1388-1399`). After a timeout-landed B, Go can therefore believe A is current, see status epoch 0—not greater than A—and send A-derived fabrics into B; the old helper accepts them unfenced.

   The required restart and D warning at `plan.md:3131-3146` are operational instructions, not a request-side safety barrier. Either epoch support must be negotiated and required before new semantics run, or all lineage-sensitive sends must fail closed until a nonzero matching epoch is observed.

7. **[BLOCKER] The defer and provenance contracts cannot traverse the existing APIs.** The daemon computes defer intent before Compile (`pkg/daemon/daemon_apply_dataplane.go:45-82`) but calls `ApplyConfig(ctx,cfg)` (`:137-142`); `ConfigSink` has no options argument (`pkg/dataplane/apply.go:37-40`), and manager ApplyConfig calls `Compile(cfg)` (`manager.go:348-355`). Thus the promised Compile argument at `plan.md:1806-1817,2263-2268` has no production path.

   Snapshot content construction itself does not require the bit, but the arm gate does. Compile performs shim compilation, snapshot construction, and attachment before its main `m.mu` section (`manager_compile.go:177-228`). If defer/compile-in-flight becomes visible only near the existing stamp at `:330-332`, the status loop can run desired-arm reconciliation during that interval (`process_status.go:162-240`). The plan needs an entry-time reservation with rollback on every exit, not merely an atomic stamp immediately before publication.

   Operator-only disarm is also impossible as written. Go and Rust carry only `armed` (`pkg/dataplane/userspace/protocol_binding.go:7-9`; `userspace-dp/src/protocol/control.rs:947-951`), and the handler receives only that Boolean (`server/handlers/forwarding.rs:12-33`). No provenance field exists in the additive wire list (`plan.md:2159-2214`). Moreover, desired state is always armed on standalone systems (`manager_ha.go:363-388`), so it cannot own retry of a lost operator disarm. A wire provenance tag/separate verb and durable operator retry state are required.

8. **[BLOCKER] Non-gating recovery is not a safe XSK transaction.** The plan arms/binds a transferred member before recovery and later runs program-MAC, setUp, repairs, and rebind (`plan.md:1572-1596,1643-1649`). Current `PrepareLinkCycle` must disable ctrl and join all workers before any DOWN/UP (`pkg/dataplane/userspace/process_linkcycle.go:136-160`), while `programRethMAC` performs DOWN→MAC→UP internally (`pkg/daemon/daemon_reth.go:257-270`). The recovery cannot discover the fallback cycle early enough to quiesce safely without splitting that primitive.

   The slots do not need a separate arm verb: `stop_workers` preserves `registered/armed` while clearing socket state (`userspace-dp/src/server/handlers/stop_workers.rs:14-25`), and rebind recreates them. But using today’s Prepare/Notify path stops and rebinds the entire dataplane, flapping the global enabled gate; skipping Prepare risks active XSK/UMEM corruption. Either targeted per-member quiescence is needed or the plan must explicitly accept and budget the global outage.

   Additional holes:

   - A failed MAC write after successful DOWN returns `(false,error)`, losing cycle history (`daemon_reth.go:260-265`), so “sticky `linkCycled`” cannot rely on the current return value.
   - The cited repair sequence stops before proxy ARP/NDP; full apply runs it at `daemon_apply_dataplane.go:408-411`, and non-commit cycles otherwise wait up to 30 seconds (`daemon_proxyarp.go:220-226`).
   - `NotifyLinkCycle` is void (`pkg/dataplane/apply.go:130-134`), so recovery cannot retain debt until rebind is observed successful.

9. **[BLOCKER] The daemon scheduler cannot consume manager-owned debt through the proposed interface.** The plan puts collections, epoch, backoff, and settlement under `m.mu`, while scheduling lives daemon-side (`plan.md:1676-1683`). Its only additions are `ValidateMACDebtEpoch` and `ReportMACDebtAttempt` (`plan.md:2241-2257`). Neither supplies due members/phases, deadline, desired MACs, or a work-claim token; the daemon is not even given the epoch through `ApplyResult`, which currently contains only ordinary generation (`pkg/dataplane/apply.go:97-117`).

   Validation is also only `epoch == pending`, not “this member and phase are still outstanding.” A same-epoch operator cancellation can occur after Validate releases `m.mu` but before the following netlink syscall. The planned validation is therefore not a linearization fence.

   Naming all three collection cancellations at `plan.md:1713-1718` does close that subpart. It does not cover the separate #5134 Boolean (`manager_worker_arm_5134.go:22-26`). A superseded `pendingWorkerArm` can stop firing on epoch mismatch yet continue suppressing generic activation retry. It must be epoch-qualified and cleared on supersession.

10. **[BLOCKER] The blocking-acquire proof establishes neither deadlock freedom for the new paths nor eventual progress.** The specified debt path is ordered `applySem → m.mu`; I found no current synchronous inverse. But v8.8’s poll-triggered active reapply and environment dispatch require the missing manager→daemon handoff. Implementing either inline under `m.mu` creates the forbidden inverse; the plan must require enqueue-after-unlock. Its absolute “manager NEVER calls daemon” premise is already too broad—the asynchronous `OnXSKBound` callback is dispatched manager-side at `pkg/dataplane/userspace/maps_sync.go:451-456`.

   Ten seconds is not a fairness guarantee. `applySem` covers the full heavy apply (`pkg/daemon/daemon_apply.go:49-56,127-140`), and an IPsec retry may hold it for roughly 20 seconds (`daemon_ipsec_rebind.go:91-100,220-249`). Repeated legal owners can time out every attempt. After acquisition, Validate/Report can also block on `m.mu` while the status loop performs a full deferred/#5134 control request; control deadlines can reach 120 seconds (`process_status.go:185-200`; `process_control.go:52-56`). The attempt then monopolizes `applySem` while waiting for the manager. The test uses only one short owner (`plan.md:3072-3086`).

11. **[BLOCKER] The causal environment token remains loss- and flap-unsafe.** “Last rejected” must either retain the first rejection or replace it:

   - Keep-first fails to watch a later B′-only candidate.
   - Replace-on-reject drops B’s watch. If the B′ rejection response is lost, helper watch ownership and Go’s single cached `(B,g)` can diverge. Recovery depends on the unstated invariant that replacing the watched projection itself necessarily bumps the echoed generation; no identity is echoed and no test pins this.

   A loss-safe design needs an acknowledged rejected-projection identity, a bounded set of watched projections, or an explicit generation bump/ack rule.

   Repeated flapping is definitively unbounded. Every observed environment bump dispatches another pre-disable/send (`plan.md:1259-1270`), and polls run every second (`pkg/dataplane/userspace/process_status.go:152-162`). A 1 Hz input flap or B/B′ alternation can pulse the global ctrl gate at 1 Hz indefinitely; there is no debounce, minimum retry interval, or duty-cycle bound.

   The cited source model also needs correction: ordinary candidates may be skipped at zero, but fabric parents clamp queue count to at least one (`userspace-dp/src/server/helpers/planning.rs:452-476`), and readable sysfs already returns at least one (`:605-621`). The proposed B-only fabric-parent rejection either requires an unstated planner change or tests a state current source cannot produce.

12. **[BLOCKER] Fabric sync debt is not yet an executable state machine.** The plan does not specify its owner, key, scheduler/backoff, coalescing, or clear condition (`plan.md:1276-1293,2269-2277`). Current manager synchronization is void beneath the wrapper (`pkg/dataplane/userspace/controllers.go:112-143`), while takeover reads daemon-local `fabricPopulated` only (`pkg/daemon/daemon_ha.go:774-783`).

   Debt must be keyed at least by `(config_epoch, full fabric projection)` so an old fab0/fab1/clear retry cannot clear a newer failure. A clean matching sync—not an unrelated clean status—should clear it. With permanent helper-sync failure, `fabricPopulated=true` remains truthful map state, but takeover readiness must remain false while debt is outstanding. The plan states that intent but supplies no path by which manager retry completion updates daemon readiness.

13. **[MAJOR] The re-specified tests can green with the architecture broken.** In particular:

   - The dedup test asserts the impossible local collapse (`plan.md:2781-2786`).
   - Active-reapply tests assume the absent daemon owner (`plan.md:2561-2624`).
   - There is no UNKNOWN epoch-reservation/reuse test.
   - No test publishes route/scheduler/#5134 while pending-XSK B is staged.
   - Deferred acceptance tests omit both `process_status.go` advance legs.
   - No mixed-version timeout-landed-B test exercises epoch 0.
   - No test carries defer intent through the real `ConfigSink` abstraction or operator provenance through the Rust wire.
   - Recovery tests omit pre-cycle quiescence, MAC-write-after-DOWN failure, proxy-ARP repair, and rebind failure (`plan.md:3015-3038`).
   - The semaphore test omits >10-second/repeated owners and post-acquisition `m.mu` blocking.
   - Environment tests omit lost B′ replacement and sustained 1 Hz flapping (`plan.md:2837-2893`).
   - Fabric tests do not pin keyed supersession and exact debt-clear semantics.

14. **[MINOR] The all-member pass-1 cost is unbudgeted.** Current precheck stops after the first mismatch (`pkg/daemon/daemon_apply_dataplane.go:55-69`); v8.8 adds a fresh link read for every desired member under the apply critical path (`plan.md:1620-1624`). The tests cover one bucket-iii member (`plan.md:3031-3034`), not a 12-member RETH or a netlink-call/latency ceiling.

15. **[MAJOR] The stated 19/70-second labels are honest, but the cumulative High-severity hazard budget is not.** The disclosed healthy and warm-clock figures, and persistent genuine control failure remaining fail-closed, are defensible (`plan.md:3314-3340`). Residual unbounded cases are not:

   - epoch reuse lets stale work alias a new config;
   - A clones can overwrite timeout-landed B and erase the reapply signal;
   - active reapply, helper restart reapply, manager-owned MAC work, and fabric debt lack schedulable owners;
   - repeated 10-second semaphore failures and post-acquire manager blocking have no progress bound;
   - environment flapping can pulse ctrl indefinitely;
   - stale #5134 state can suppress successor activation;
   - autonomous recovery can globally stop/rebind live workers without an observed-success contract.

   New v8.8 hazards versus master/v8.7 include B-under-A wire lineage, ambiguous epoch reuse, false local dedup lineage transfer, an unspecified poll→daemon reverse path, operator provenance without wire representation, autonomous live-XSK cycling, blocking-acquire priority inversion, single-entry rejected-watch skew, and stale-clearing fabric debt.

DEMAND-REVISION

Codex session ID: 019fc9de-802b-7e01-846b-094a750c9d2a
Resume in Codex: codex resume 019fc9de-802b-7e01-846b-094a750c9d2a
