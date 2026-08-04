# Codex plan review — round 14 — #6749 armed-state plan v8.9 (6e2da70b98e1)

**Reviewer:** Codex (hostile; companion task task-msdwofas-rgffdh, fresh thread; prompt /tmp/codex-6749-r14-prompt.txt). Raw output: /tmp/codex-6749-r14.out.

**Verdict: DEMAND-REVISION** (12 BLOCKER + 3 MAJOR).

---

1. **[BLOCKER] The §1 disposition table still materially overclaims closure.** I reviewed the exact requested blob: both `6e2da70b98e1:docs/research/6749-armed-state/plan.md` and the working copy hash to `48db854703955cb7c54acf94112f225a82cf821b`. No files were modified. Every CLOSED row at `plan.md:694-710` is wrong as a whole:

   | r13 row | Round-14 audit |
   |---|---|
   | f2 | OPEN/BLOCKER — `archiveSeq` is not a commit sequence and is not transported with configs. |
   | f3 | OPEN/BLOCKER — the five-producer census is correct, but auxiliary first-publishers lack acceptance handoff. |
   | f4 | OPEN/BLOCKER — `note_config_epoch` lacks monotonicity and retry ownership. |
   | f5 | OPEN/BLOCKER — re-sync cannot fire under its own key rule and is not latest-wins. |
   | f6 | OPEN/BLOCKER — fail-closed-on-zero is reasonable only after zero is impossible for a current helper; v8.9 makes zero normal. |
   | f7 | OPEN/BLOCKER — provenance is specified, but `StartDeferredCompile` is one-sided and contradictory. |
   | f8 | OPEN/BLOCKER — the typed obligations survive, but the recovery transaction cannot prove quiescence. |
   | f9 | OPEN/BLOCKER — the token fences bookkeeping only, not external side effects. |
   | f10 | OPEN/BLOCKER — the lock direction is improved; the fairness proof is false. |
   | f11 | OPEN/BLOCKER — eviction/cache ownership and aggregate dispatch remain undefined. |
   | f12 | OPEN/BLOCKER — debt identity and readiness propagation remain non-executable. |
   | f13 | OPEN/MAJOR — tests can green all these defects. |
   | f14 | OPEN/MINOR — the latency claim is an unsupported estimate. |
   | f15 | OPEN/MAJOR — multiple severity-High executions remain unbounded. |

   Consequently f1 and the aggregate AGY/SMR rows at `plan.md:711-712` are also open.

2. **[BLOCKER] `archiveSeq` is not—and cannot be treated as—the globally monotonic config-commit sequence.** Source defines it as a per-process archive-filename/retention counter (`pkg/configstore/store.go:233-245`). Plain Commit increments it only when archival is enabled, unfenced, and successfully reseeded (`pkg/configstore/store_commit.go:276-321`, increment at `:304`). `CommitConfirmed` (`store_commit.go:395-527`), HA `SyncApply` (`pkg/configstore/store.go:634-769`), and `PromoteRollback` (`store_commit.go:856-912`) do not increment it. Conversely, manual `ArchiveConfig` increments it without a commit (`pkg/configstore/store_persist.go:714-798`, increment at `:786`).

   Even with archival enabled, a crash after `Add(1)` but before the asynchronous archive write at `store_commit.go:304-320` lets restart reseed from the previous on-disk maximum (`store_persist.go:516-579`) and reuse the value. A commit enabling archival is itself unsequenced because `SetArchiveConfig` runs only in the post-apply tail (`pkg/daemon/daemon_apply_tail.go:137-153`). These facts directly falsify `plan.md:2036-2051`.

   There is also no lineage transport: `config.Config` has no revision (`pkg/config/types.go:270-289`), `ActiveConfig` returns only `*config.Config` (`pkg/configstore/store_format.go:55-60`), and `ConfigSink.ApplyConfig` accepts only that pointer (`pkg/dataplane/apply.go:37-40`; `pkg/dataplane/userspace/manager.go:348-357`). `ApplyResult` carrying an epoch is an output and cannot tell Compile which committed revision it is compiling. Configs can therefore have no assigned sequence, while an observed `archiveSeq` value may have been assigned by a non-commit archive operation.

3. **[BLOCKER] The rollback refusal rejects legitimate flows, while equality leaves same-config divergence undetectable.** Manual `rollback N` merely replaces the candidate (`pkg/configstore/store_commit.go:963-1004`), so a later genuine Commit could receive a newer revision. Commit-confirmed auto-revert is different: `PromoteRollback` reinstalls the old compiled pointer (`store_commit.go:867-883`), and the daemon applies it directly (`pkg/daemon/daemon_apply_commit.go:645-697`). Boot recovery of an expired confirmed window likewise promotes the previous tree without a new sequence (`pkg/configstore/store_persist.go:171-194`). Both contradict `plan.md:2043-2044`; a helper already holding the unconfirmed config’s larger epoch would refuse the legitimate revert.

   A peer’s older-content config is a new local `SyncApply` promotion (`pkg/configstore/store.go:681-769`) and should receive a newer local revision, but v8.9 assigns none. Normal/HA/auto-revert promotion does precede dataplane apply (`pkg/daemon/daemon_apply_commit.go:194-222,354-357,489,645-697`); DHCP, feeds, and boot skip a store commit and reapply `ActiveConfig` (`pkg/daemon/daemon_dhcp.go:73-90`; `daemon_feeds.go:26-41`; `daemon_run_bringup.go:516-520`).

   More fundamentally, one commit revision does not order different full snapshots produced from the same config. Feed content demonstrably reshapes a full snapshot while using the identical `*config.Config` (`pkg/dataplane/userspace/feed_enforcement_test.go:216-252`). If feed snapshot P2 at epoch E lands but its response is lost, a later route producer can clone retained P1, assign a newer ordinary generation (`manager_overlay.go:188-239`), and publish it with the same E. The strict-less epoch guard accepts it, and `status.config_epoch > accepted` never detects divergence. v8.9 therefore needs a separate monotonic publication revision—or equivalent latest-snapshot ownership—not merely a commit revision.

   On factory reset, the default archive is erased (`pkg/configstore/factory_reset.go:93-102`), and successful zeroize stops xpfd (`pkg/grpcapi/server_diag_system_action.go:198-205`). The current helper starts fresh and never restores `state.json` (`userspace-dp/src/server/lifecycle.rs:182-204`; `server/handlers/mod.rs:161-167`), so a clean reset does not retain a pre-reset helper epoch. It still disproves “never reused”; any durable future helper restoration would require a jointly reset incarnation identifier.

4. **[BLOCKER] f3 replaces B-under-A with unauthorized staged-B first publishers.** Pending-XSK Compile exposes unpublished B through `m.lastSnapshot` (`pkg/dataplane/userspace/manager_compile.go:245-313`). Route overlay, scheduler, and #5134 then clone that pointer (`manager_overlay.go:188-239`; `manager_compile.go:575-605`; `manager_worker_arm_5134.go:57-80`). v8.9 expressly allows any producer carrying newest staged B (`plan.md:1458-1469`), but the accepted-epoch advance list omits those auxiliary producers (`plan.md:2053-2067`). Thus B can reach the helper while Go remains accepted=A, generating false helper-ahead/re-sync and skipping B’s debt handoff.

   The #5134 case is worse: an A-owned retry forcibly sets its clone’s `DeferWorkers=false` (`manager_worker_arm_5134.go:50-64`). If `m.lastSnapshot` is deferred B, that stale owner arms B before B’s MAC obligation settles. Either all auxiliary producers must remain suppressed while B is staged, or each must perform B’s full observed-acceptance transaction; payload epoch alone is insufficient.

5. **[BLOCKER] `note_config_epoch` is a monotonicity backdoor with no failed-transfer owner.** The plan says the verb simply sets the helper epoch (`plan.md:2088-2094,2426-2434`); the strict-older refusal applies only to `apply_snapshot` (`plan.md:2074-2081`). Any stale note retry after a newer full apply can therefore regress the stored epoch without changing snapshot content. The immediate current path may serialize under `m.mu`, but that does not make the wire invariant safe for UNKNOWN retries or future asynchronous dispatch.

   A genuine note failure wedges more directly: dedup already marks the snapshot published (`pkg/dataplane/userspace/process_status.go:72-80`), while a later poll merely echoes old A and performs no transfer. Nothing specified retries B, so suppression remains indefinitely. Moreover, `requestLocked` returns success even when the response contains no status (`pkg/dataplane/userspace/process_control.go:219-230`). The design needs a supersedable note debt, strict-older refusal before mutation, equality-idempotence, and clearing only on an exact echo of the captured sent epoch—not an ACK, an unrelated poll, or the then-current `pendingConfigEpoch`. Tests at `plan.md:3061-3071` cover none of these races.

6. **[BLOCKER] The re-sync debt is prohibited by its own firing rule and lacks latest-wins semantics.** v8.9 says debts fire only when their key equals `acceptedConfigEpoch`, then keys re-sync to pending B and settles it when accepted reaches B (`plan.md:2108-2117`). During the only useful interval, accepted=A, so the B debt cannot fire. The timeout description also says B staging is discarded and no epoch moves (`plan.md:1968-1974`), conflicting with using `m.pendingConfigEpoch` as B’s identity.

   With timeout-landed B followed by timeout-landed C, a queued B worker may acquire `applySem`, reread active C, and apply C while the debt/clear condition remains B (`plan.md:1980-2003`). No atomic rekey, latest-observed coalescing, or stale-drain revalidation exists. `ActiveConfig` supplies no revision and can be nil (`pkg/configstore/store_format.go:55-60`); channel saturation, 30-second semaphore timeout, nil active config, and reapply failure are not assigned explicit retry transitions. Also, the summary says re-sync drives the “normal commit path” (`plan.md:206-210`), while the detailed contract says explicitly no commit (`plan.md:1987-1991`).

7. **[BLOCKER] `StartDeferredCompile()` does not reserve non-deferred Compile operations.** The blob still contains the supposedly deleted Compile-argument contract (`plan.md:1954-1964`) alongside the new positive-only method (`plan.md:2006-2030,2496-2499`). A deferred A whose completion failed leaves `m.deferWorkers=true`. A no-MAC B calls no start method and publishes from that stale flag, contradicting the required non-deferred rollover at `plan.md:1558-1579,2795-2803`.

   The mandatory live-MAC reapply has the same race: it is intentionally non-deferred (`plan.md:1542-1546`; `pkg/daemon/daemon_apply_dataplane.go:466-489`). With `compileInFlight=false`, a status echo can re-latch true while Compile builds outside `m.mu` (`manager_compile.go:177-228`), after which the publish stamps true again (`manager_compile.go:330-332`).

   Cleanup is also not enumerated adequately. Reservation occurs before the daemon’s pre-Apply context exit (`daemon_apply_dataplane.go:126-135`); manager `ApplyConfig` can exit before Compile (`manager.go:348-355`); Compile has build, staging, publish, status, and tail returns throughout `manager_compile.go:200-414`. An internal Compile defer can cover ordinary returns and panic unwind only after Compile begins; it cannot restore the prior A state on a pre-Compile abort. Every Compile needs a begin token carrying `defer=true/false`, with rollback/finish ownership and an explicit pre-entry abort path. The provenance wire portion of f7 is otherwise substantially specified.

8. **[BLOCKER] `claimToken` fences bookkeeping, not cancellation of physical work.** The token is checked only by Report (`plan.md:1808-1823`). An operator can cancel a member after Claim while the daemon proceeds with link/MAC/netlink operations; operator binding verbs take `m.mu` but not `applySem` (`pkg/dataplane/userspace/manager_status.go:132-179`). Discarding the later report cannot undo those mutations.

   Wholesale discard is conservative for manager state, and valid sibling work is not permanently lost if it is re-claimed, but its successful side effects go unrecorded and are repeated—potentially including another global link cycle. The proposed test is impossible as written: after a superseding commit, Claim returns the current token, not a stale one (`plan.md:3392-3398`). If Claim precedes the commit, zero netlink calls requires another pre-side-effect validation that the plan does not provide. `Deadline` also has no named consumer; because Claim returns only already-due items, an empty result does not tell the daemon when to wake next.

9. **[BLOCKER] The “safe XSK transaction” cannot establish that workers were quiesced.** `LinkController.PrepareLinkCycle` remains void (`pkg/dataplane/apply.go:130-134`). Its implementation ignores ctrl-disable failure and merely logs and returns on `stop_workers` failure (`pkg/dataplane/userspace/process_linkcycle.go:145-162`). The daemon can therefore proceed to DOWN→MAC→UP with live UMEM users, violating `plan.md:1662-1674`.

   Multiple simultaneously due members have no batching/coalescing rule, so independent completions may cause back-to-back whole-dataplane quiesces. The test also says a rebind failure retries the “whole recovery” (`plan.md:3331-3336`), contradicting “retry only the missing phase” (`plan.md:1792-1794`) and permitting repeated global outages after physical repair already succeeded.

   The specific operator-disarmed concern is not itself a wedge: raw `BindingStatus.Ready` is `registered && bound && xsk_registered && heartbeat_fresh` and ignores `armed` (`userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:253-261`); a registered operator-disarmed slot is physically rebound (`plan.md:2611-2618`). An operator-*unregistered* slot cannot become ready, however, and the plan does not connect such cancellation to the interface-scoped recovery clear predicate.

10. **[BLOCKER] The f10 fairness proof is source-false.** A full apply holds `applySem` for the entire heavy pipeline (`pkg/daemon/daemon_apply.go:49-56`), including an `apply_snapshot` round trip legally budgeted up to 120 seconds (`pkg/dataplane/userspace/process_control.go:33-56,129-142`). A single valid owner can therefore exceed the proposed 30-second debt acquire, contrary to `plan.md:1840-1849`. The test itself queues approximately 30 seconds plus 20 seconds of legal owners while asserting a 30-second waiter succeeds (`plan.md:3383-3391`).

   FIFO wakeup does not help a waiter that times out, loses its position, and rejoins later. Similarly, fixed-cadence try-lock attempts can repeatedly collide with the status loop holding `m.mu` across a control request (`pkg/dataplane/userspace/process_status.go:152-173`). The precise no-synchronous-manager→daemon lock rule is sound; the claimed eventual-progress proof is not.

11. **[BLOCKER] The env ack-set still lacks eviction ownership and an aggregate-rate invariant.** Status exposes the retained identities (`plan.md:2451-2462`), but the plan never states that Go must discard suppression state for identities absent from that set. Retaining an evicted identity can suppress it forever after the helper drops its watch; discarding it is probably the intended rule but must be explicit and tested. The fifth-entry test at `plan.md:3129-3145` checks replacement, not eviction→cache-drop→resend.

   Ten candidates in one projection do **not** automatically produce ten dispatches: identity is the whole projection hash. However, up to four distinct retained projections can dispatch independently, and a stream of novel projection hashes can churn through eviction without any aggregate pulse/duty bound. The stated ≤0.2/s guarantee is only per identity, not global.

12. **[BLOCKER] Fabric debt does not prove matching helper/map state or reach takeover readiness.** The plan’s projection hash covers only planner fields (`plan.md:1257-1260`), but the sent `FabricSnapshot` also includes overlay ifindex, peer address, both MACs, and `Up` (`pkg/dataplane/userspace/protocol.go:315-333`; `fabric.go:40-60`). Same-epoch telemetry updates therefore alias. A stale clean retry can satisfy the same `(epoch, projection-hash)` key and clear a newer unsynced payload.

   A projection change with a genuinely different hash should supersede the old entry; that part is sound. Also, after successful `SetFabricForwarding`, the map is already newer—not older—because the wrapper commits it before helper sync (`pkg/dataplane/userspace/controllers.go:112-132`). The dangerous gap is map-new/helper-old. A clean guard rejection explicitly retains the old helper projection and leaves readiness untouched (`plan.md:1407-1418,3178-3187`), while recording no failure debt.

   Finally, the claimed existing readiness conduit does not exist. `dataplane.HAController` has four mutating methods and no debt query (`pkg/dataplane/apply.go:138-143`), while takeover reads only daemon-local `fabricPopulated` (`pkg/daemon/daemon_ha.go:774-783`). A new consistency-defined query/pushed state is required; `plan.md:2515-2526` cannot simultaneously rely on it and claim no other interface change.

13. **[MAJOR] The v8.9 tests can green while all major holes remain.** The matrix still says DHCP/feed, HA, rollback, auto-revert, and background compiles “mint” epochs (`plan.md:3014-3027`), contradicting the commit-lineage model. It omits archive-disabled/first-enable commits, `CommitConfirmed`, `SyncApply`, live and boot-time auto-revert, manual archive increments, crash/reseed reuse, and production revision plumbing.

   Other missing or invalid cases include auxiliary B first-publish and A-#5134 arming B; stale/failed/two-note transfers; B→C re-sync coalescing and drain failures; a status echo during non-deferred Compile; Prepare failure and recovery batching; a realizable post-Claim cancellation; one >30-second semaphore owner; fifth-identity cache invalidation; full-payload fabric aliasing; clean guard-reject readiness; and compilation through an actual HA debt-read API. The stale-token test at `plan.md:3392-3398` positively specifies impossible ordering.

14. **[MINOR] f14 remains an assertion, not a verified budget.** `plan.md:1524-1527` declares twelve netlink reads approximately ≤1 ms but adds no benchmark, fake-call ceiling, or loaded-namespace bound. Current precheck can stop at the first mismatch (`pkg/daemon/daemon_apply_dataplane.go:55-69`), so it supplies no evidence for the new worst-case all-member pass.

15. **[MAJOR] The severity-High hazard budget remains unbounded, and v8.9 adds new hazards.** Residual indefinite cases include normal epoch zero causing every lineage-sensitive operation to fail closed; equal-epoch stale dynamic snapshots; a failed note leaving permanent suppression; a re-sync debt forbidden from firing; stale defer being stamped into a non-deferred successor; repeated 30-second semaphore/manager-lock misses; and recovery repeatedly quiescing the whole dataplane.

   New v8.9 hazards versus master/v8.8 include using a non-commit archive counter as a safety authority, rejecting legitimate auto-revert, collapsing distinct same-config publications onto one epoch, epoch regression through the note verb, A-owned #5134 arming staged B, stale physical side effects after Claim cancellation, and takeover readiness while helper projection remains old. The plan is salvageable only by replacing `archiveSeq` with a real durable promotion revision, adding a separate latest-publication identity, and redesigning the affected ownership protocols.

DEMAND-REVISION

Codex session ID: 019fca1f-1a26-7be3-a4c0-69f5f348d89b
Resume in Codex: codex resume 019fca1f-1a26-7be3-a4c0-69f5f348d89b
