# Codex plan review — round 15 — #6749 armed-state plan v8.10 (12ced136fe30)

**Reviewer:** Codex (hostile; companion task task-msdyv5wo-1gs8c2, fresh thread; prompt /tmp/codex-6749-r15-prompt.txt). Raw output: /tmp/codex-6749-r15.out.

**Verdict: DEMAND-REVISION** (12 BLOCKER + 2 MAJOR + 1 MINOR; f11 (environment token) is the one clean closure).

---

Reviewed the exact `12ced136fe30` blobs via `git show`; later worktree changes were excluded. No files were modified. `plan.md` below means `docs/research/6749-armed-state/plan.md` at that commit.

1. [BLOCKER] The §1 round-14 disposition table is materially false.

   | r14 row | Re-derived status |
   |---|---|
   | f1 disposition accuracy | OPEN/BLOCKER |
   | f2 durable config identity | OPEN/BLOCKER |
   | f3 rollback/same-commit ordering | OPEN/BLOCKER |
   | f4 auxiliary first-publishers | PARTIAL/BLOCKER |
   | f5 note transfer | OPEN/BLOCKER |
   | f6 re-sync ownership | OPEN/BLOCKER |
   | f7 compile reservation | OPEN/BLOCKER |
   | f8 claim-token fence | OPEN/BLOCKER |
   | f9 recovery quiescence | OPEN/BLOCKER |
   | f10 semaphore fairness | OPEN/BLOCKER |
   | f11 environment token | CLOSED |
   | f12 fabric debt/readiness | OPEN/BLOCKER |
   | f13 tests green with holes | OPEN/MAJOR |
   | f14 pass-1 bound | OPEN/MINOR |
   | f15 hazard budget | OPEN/BLOCKER |

   The claimed closures are at `plan.md:813-827`. f11 is the only clean closure: bounded reject-set eviction, incarnation scoping, and both rate caps are specified at `plan.md:1460-1496` and tested at `plan.md:3447-3463`.

   The aggregate AGY/SMR rows at `plan.md:828-832` are consequently also wrong: AGY f1 fails on migration/rebase, AGY f2 depends on the broken f7 gate, AGY f3 depends on f9, and AGY f5-f7/SMR14-1/-3/-4/-6 inherit the open CAS, re-sync, recovery, token, and readiness defects.

2. [BLOCKER] R1 is not “durable on every accepted promotion”; successful writes can carry the pair atomically, but several accepted paths deliberately proceed without a durable write.

   Exact boundaries:

   - Plain Commit: one `writeActive(candidate)` at `pkg/configstore/store_commit.go:160-211`, before promotion at `:213-225`.
   - CommitConfirmed: one `writeActive(candidate)` at `pkg/configstore/store_commit.go:427-468`, before promotion at `:470-493`. The later `confirm.json` write at `:513-524` does not split the active config/revision pair.
   - SyncApply: promotes in memory at `pkg/configstore/store.go:681-695`, then writes at `:722-760`; failure is explicitly degrade-not-fail and still returns the accepted config at `:738-769`.
   - PromoteRollback: promotes at `pkg/configstore/store_commit.go:867-884`, then performs one marker/active write at `:901-912`; failure still returns `ok=true` at `:917-946`.
   - Expired-window boot recovery: promotes at `pkg/configstore/store_persist.go:171-175`, then performs one write at `:176-195`; failure is tolerated at `:196-228`.

   `writeTreeMarked` provides one durable temp/fsync/rename write capable of containing config and revision together (`pkg/configstore/db.go:431-461`). Thus none of these paths inherently requires split writes, and every enumerated path attempts a write. The failure is semantic: SyncApply, rollback, and boot recovery can be accepted while disk still contains the old pair. A crash before the retry—explicitly described as loading stale config at `pkg/configstore/store_persist.go:367-401`—loses the accepted revision and permits reuse. Plain/CommitConfirmed also accept post-rename durability uncertainty.

   The design must either change Option-B acceptance, introduce a genuinely durable non-reusable high-water/incarnation, or formally reset the helper under a proven new incarnation. Same-file atomicity alone does not solve revision reuse.

   The plan also falsely says every listed promotion precedes `ApplyConfig` (`plan.md:2273-2285`): first-commit PromoteRollback returns `prevCfg=nil` and enters bootstrap instead of calling the dataplane (`pkg/daemon/daemon_apply_commit.go:645-697`).

3. [BLOCKER] R1 has neither a rollout migration nor an atomic transport into `Compile`.

   Existing `active.json` contains no revision. `Load` reads and installs it without rewriting (`pkg/configstore/store_persist.go:21-114`), while boot merely calls `ActiveConfig` and reapplies it (`pkg/daemon/daemon_run_bringup.go:516-520`). Because v8.10 says boot reapply never promotes (`plan.md:2286-2290`) and the gates require nonzero (`plan.md:1572-1575,2313-2326`), an upgraded node remains at revision zero until an operator makes another promotion. Restarting the helper cannot repair the store’s zero.

   Downgrade is also undesigned: envelope readers ignore unknown fields (`pkg/configstore/envelope.go:258-312`) and old writers reconstruct only known fields (`:170-189`). An old daemon can therefore erase an additive revision during a rewrite. A format/min-reader or incarnation policy is required.

   Separately, `ConfigSink.ApplyConfig` still receives only `*config.Config` (`pkg/dataplane/apply.go:37-40`); Manager calls argument-less `Compile(cfg)` (`pkg/dataplane/userspace/manager.go:348-357`) and has no configstore. `ActiveConfigRevision()` is a separate scalar, while putting the revision in `ApplyResult` is too late—the snapshot has already been sent (`plan.md:2700-2706,2762-2767`).

   Concrete corruption trace: the feed callback captures A before acquiring `applySem` (`pkg/daemon/daemon_feeds.go:26-41`); commit B can interpose; the queued feed apply then combines stale A with current revision B. DHCP has the same capture-before-lock path (`pkg/daemon/daemon_dhcp.go:85-90`; semaphore acquisition occurs only at `pkg/daemon/daemon_apply.go:49-56,83-86`). The helper can accept A labelled B, after which every revision comparison falsely agrees.

   R1 needs an atomic `(config, revision)` value carried as an input through daemon → `ConfigSink` → `Compile`, plus stale-pair revalidation for queued reapplies.

4. [BLOCKER] `publication_rev` conflates two distinct high-waters and does not define a safe startup/restart path.

   The plan defines only `m.lastPublicationRev` as the manager’s minted/burned counter (`plan.md:2700-2707`), but divergence compares helper status against the “last observed” publication value (`plan.md:2185-2192,2295-2312`). Those cannot be the same field. For a same-commit send N that lands but times out, the mint counter is already N. If it doubles as observed state, the next `status.publication_rev == N` is not ahead; commit revision is unchanged; no re-sync fires.

   The design needs separate `mintedPublicationRev` and `observedPublicationRev`, with the latter moving only on a response/poll that proves helper acceptance.

   For startup, the only safe seed points are the synchronous pings in both helper-reuse and spawn paths (`pkg/dataplane/userspace/process.go:18-29,116-125`). Merely starting the status loop after `ensureProcessLocked`, as the standing plan requires at `plan.md:2434-2437`, still leaves a first-send-before-first-tick window. The plan must prohibit mint/send until the ping echo seeds both counters and must classify a first-send refusal through a typed retry owner.

   A fresh Manager also has no existing-helper adoption path: reuse requires a non-nil `m.proc`; otherwise it unlinks the socket and spawns a new helper (`pkg/dataplane/userspace/process.go:18-45,79-125`). If v8.10 adds such adoption, another independent blocker remains: Manager generation restarts at zero (`pkg/dataplane/userspace/manager.go:85-105,336-345`; `manager_generation.go:33-38`), while the surviving helper rejects rollback of `(generation,fib_generation)` before side effects (`userspace-dp/src/server/handlers/snapshot.rs:33-105`). Seeding only `publication_rev` cannot pass that guard.

   A whole-daemon restart can reconstruct lost completion by boot-reapplying active config with N+1, provided R1 transport and both guards are fixed. A Manager-only replacement over a running helper currently has neither the adoption mechanism nor an explicit startup reapply owner.

   Every actual wire retry must re-mint; reuse necessarily fails strict `>`. The prose implies this correctly at `plan.md:2295-2303`, but no common five-producer send primitive or retry test pins exactly-one-mint-per-wire-attempt.

5. [BLOCKER] R2 does not provide the claimed second-layer stale-config fence, and its mixed-version/rebase rules are unsafe.

   The plan claims strict publication ordering will reject any stale full send that escapes Go suppression (`plan.md:1612-1620`), and the test expects a forced stale-A publish to be refused (`plan.md:3103-3107`). That is false: a stale-A request minted when it is actually sent receives a revision greater than landed B and therefore passes the only specified helper fence. Publication order orders sends; it does not prove config freshness. The helper also needs a nondecreasing `commit_revision` check, with fresh revisions for legitimate rollback, or Go suppression must be proven gap-free across UNKNOWN bookkeeping.

   The UNKNOWN transition is itself ambiguous: the staged snapshot is discarded and “no revision moves” at `plan.md:2173-2179`, without saying precisely when `pendingCommitRevision` remains set or clears relative to the poll. Clearing it early admits the stale auxiliary send; retaining it after a no-commit timeout needs a specified poll transition that releases suppression.

   Mixed-version text is contradictory. Strict `publication_rev > stored` at `plan.md:2307-2310,2631-2634` rejects old Go’s omitted zero against a fresh new helper’s stored zero, while `plan.md:1641-1643,2323-2326` says `0 == 0` is accepted. A legacy-zero mode and its exit condition are required.

   `allow_epoch_rebase` is also only justified by Go-local `acceptedCommitRevision == 0` (`plan.md:2327-2336`), which the helper cannot verify. A stale or concurrent manager can therefore request a downward rebase of both revisions, defeating R2 monotonicity and reopening old-send overwrite. Rebase needs an incarnation/handshake proof; R2 should never be lowered merely because a client asserted a Boolean.

6. [BLOCKER] `note_commit_revision` is neither a coherent CAS nor wired to return its claimed refusal state.

   The specified rule says mutation occurs only when `stored == expected_rev`, but also calls an equality repeat idempotent (`plan.md:1622-1628,2655-2667`). After A→B succeeds, a repeat observes `stored == new_rev`, not `expected_rev`. The required order is:

   - `stored == new_rev`: idempotent success;
   - else `stored == expected_rev`: mutate;
   - else: typed refusal carrying current state.

   Rust can linearize the handler and status under the same server-state lock (`userspace-dp/src/server/handlers/mod.rs:122-267`), but Go currently discards the entire response whenever `OK=false` (`pkg/dataplane/userspace/process_control.go:148-169`). Although `ControlResponse` already has `Status` (`pkg/dataplane/userspace/protocol.go:86-90`), v8.10 never specifies the necessary error-return plumbing.

   Unconditional refusal abandonment is wrong: `current > expected` may prove supersession, but `current < expected` is helper-behind/reset and needs reapply ownership. The plan only owns zero-behind, not nonzero-behind (`plan.md:1581-1583,2185-2192`). Rebase also invalidates the monotonicity needed to make later-state abandonment safe.

   The exact echo is necessarily `StatusSnapshot.commit_revision` (`plan.md:2635-2641`); no distinct note-ack field is required because a matching full apply is equally valid proof. But v8.10 must say that exact note echo advances accepted state and clears the note debt before generic divergence classification. Otherwise the same B echo simultaneously clears the note debt (`plan.md:1632-1637`) and fires re-sync because B > accepted A (`plan.md:2185-2192`).

   Finally, the semantic hash must exclude both lineage fields. Current `snapshotContentHash` zeros only Generation, FIBGeneration, and GeneratedAt (`pkg/dataplane/userspace/builder.go:156-178`). If `commit_revision` participates, forwarding-identical A/B never dedup and the note path never runs.

7. [BLOCKER] The re-sync owner is incomplete and its proposed execution bypasses the machinery it claims to reconstruct.

   The helper-ahead/latest-wins queue and explicit retry transitions are useful (`plan.md:2185-2228`). However:

   - Nonzero helper-behind is unowned; only `commit > accepted`, publication-ahead, and the special zero case are defined (`plan.md:1577-1583,2185-2192`). Option-B persistence failure makes nonzero-behind reachable.
   - Same-commit lost completion is invisible without separate minted/observed R2 high-waters.
   - The config/revision pair cannot reach the send, as finding 3 shows.
   - The drain says it already holds `applySem` and invokes dataplane `ApplyConfig` (`plan.md:2198-2208,3096-3113`). A literal `d.dp.ApplyConfig` bypasses the daemon’s three-bucket RETH precheck and MAC-debt creation at `pkg/daemon/daemon_apply_dataplane.go:45-72`. Calling `d.applyConfig` instead would reacquire the already-held semaphore. The design must explicitly call an appropriate no-promotion, semaphore-already-held daemon path such as a revised `applyConfigLocked`, carrying the atomic config/revision pair.

   Without that, a timeout-landed deferred B can be “recovered” by publishing B without recreating B’s MAC obligation, potentially arming workers before its RETH MAC is safe.

8. [BLOCKER] Universal `StartCompile` is self-clobbering and cannot implement failed-successor rollback.

   The table says obsolete Compile-argument text was deleted (`plan.md:819`), yet it remains at `plan.md:2159-2164`.

   More importantly, the deferred flow calls `StartCompile(true)` before `ApplyConfig`, which enters argument-less `Compile` (`plan.md:2222-2226`; `pkg/daemon/daemon_apply_dataplane.go:45-72,137-142`; `pkg/dataplane/userspace/manager.go:348-357`). The plan then calls `StartCompile(false)` at Compile entry for a non-deferred Compile. Compile has no argument or owner token identifying whether the current `compileInFlight` belongs to this deferred invocation. The literal sequence clobbers true; treating any existing flag as “mine” confuses concurrent Compiles, which current source explicitly recognizes as reachable (`pkg/dataplane/userspace/maps_sync.go:1266-1270`).

   `ClearCompileReservation()` is also un-tokened and receives no outcome. It cannot distinguish:

   - successful acceptance, where the new intent becomes authoritative;
   - pre-publish failure, which must restore the prior latch;
   - timeout/UNKNOWN;
   - post-acceptance tail failure;
   - a newer overlapping reservation.

   That contradicts the failed-successor rule at `plan.md:1760-1764`. Compile can publish successfully and then return an error during status/HA/forwarding work (`pkg/dataplane/userspace/manager_compile.go:350-409`).

   The pre-Compile aborts are the daemon context boundary at `pkg/daemon/daemon_apply_dataplane.go:126-135` and Manager’s context return at `pkg/dataplane/userspace/manager.go:348-355`. The plan routes both, Compile’s defer, and the daemon defer through the same ownerless Clear (`plan.md:2236-2246,2738-2748`), allowing double-clear of a newer reservation. This needs a reservation token with prior value and an explicit finish outcome, or strict Compile serialization.

9. [BLOCKER] The work-pull claim fence is not implementable and can hold `applySem` while blocking on `m.mu`.

   The plan requires an `m.mu` token read before every netlink mutation (`plan.md:1996-2007`) but exposes only Claim and Report (`plan.md:1984-1995,2749-2761`). There is no `ValidateClaimToken`, and the signatures contain no `ok` result distinguishing try-lock contention from “no work.”

   Only Claim/Report are declared try-lock-or-skip (`plan.md:2055-2060`). A normal per-mutation read can block behind the status loop, which holds `m.mu` across its entire request/reconcile cascade and may issue another full publish (`pkg/dataplane/userspace/process_status.go:162-257`). Because the worker already owns `applySem`, this recreates the semaphore monopoly the try-lock rule was meant to eliminate.

   The validator must itself be try-lock. Contention or mismatch must abandon the claimed batch, perform any required balanced unwind, release `applySem`, and schedule a fresh Claim.

   Deadline delivery is also impossible: Claim returns only “currently due” items whose deadlines are inside `due`, yet an empty Claim is supposed to tell the daemon its next wake (`plan.md:1986-2015`). An empty slice carries no deadline. Return `nextWake` separately.

10. [BLOCKER] Recovery batching can leave the global quiesce half-open or rebind a newly-live wrong-MAC member.

   Making `PrepareLinkCycle` return an error correctly fixes today’s ignored disable/stop failures (`pkg/dataplane/userspace/process_linkcycle.go:145-162`; `plan.md:2016-2029`). The remaining transaction is unsafe:

   - After successful Prepare, `stop_workers` has stopped every worker and cleared socket state (`userspace-dp/src/server/handlers/stop_workers.rs:7-26`). If claimToken then changes, the plan says to abandon remaining work (`plan.md:1996-2006`) but mandates no `NotifyLinkCycle`/rebind finalizer. Operator cancellation can therefore leave all workers stopped.
   - The batch is frozen to currently-due members (`plan.md:1986-1991,2024-2027`). `NotifyLinkCycle` sleeps one second and then globally rebinds (`pkg/dataplane/userspace/process_linkcycle.go:184-224`; `userspace-dp/src/server/handlers/rebind.rs:41-71`). A `macAndLinkRecovery` member that returns during that sleep can be rebound and enabled before its MAC obligation is repaired. It must be absorbed/revalidated before global rebind or explicitly kept non-forwarding.
   - “Operator-unregister cancels via member-removal” is unsupported. The actual member-removal rule is config removal (`plan.md:2067-2070`); operator verbs merely mutate binding state under `m.mu` (`pkg/dataplane/userspace/manager_status.go:132-179`).
   - The test still says a rebind failure retries the whole recovery (`plan.md:3650-3655`), contradicting phase-only retries at `plan.md:2027-2029`.

   Registered-but-disarmed readiness itself is correct: raw Ready intentionally ignores armed (`userspace-dp/src/afxdp/coordinator/refresh_bindings.rs:253-261`).

11. [BLOCKER] The 150-second fairness claim is not a bound on either one owner or queue acquisition.

   `applySem` covers the whole pipeline (`pkg/daemon/daemon_apply.go:49-56,83-86`), which can include:

   - initial full `ApplyConfig` (`pkg/daemon/daemon_apply_dataplane.go:137-163`);
   - mandatory live-MAC second `ApplyConfig` (`:397-401,466-489`);
   - route-overlay `apply_snapshot` after routing-rule reconciliation (`pkg/daemon/daemon_apply.go:320-335`; `daemon_apply_routing.go:363-408`; `pkg/dataplane/userspace/manager_overlay.go:232-254`);
   - further HA, forwarding, neighbor, and FIB requests (`pkg/dataplane/userspace/manager_compile.go:383-410`; `manager_generation.go:81-132`).

   Each request has its own deadline. The cited 120 seconds is only a cap; under the actual 64 MiB limit, the maximum sized request gets roughly 67 seconds (`pkg/dataplane/userspace/process_control.go:31-56,85-103`). Multiple sequential 67-second sends already exceed 150 seconds, and there is no whole-pipeline deadline.

   The proposed test is internally impossible if its owners are queued ahead: 30s + 20s + 120s already exceeds 150s (`plan.md:3703-3713`). If they queue behind the recovery waiter, FIFO makes the sequence irrelevant.

   An arbitrary number of existing callers can be queued. FIFO bounds ordering, not total wait; a 150-second timeout merely removes the recovery waiter and makes it lose its place again on retry. The real guarantee is therefore no finite guarantee under sustained legal arrivals. A persistent queued reservation/priority mechanism or a proven whole-owner bound is required. The old 10/30-second prose at `plan.md:1695-1703` also directly contradicts the new claim at `:2039-2054`.

12. [BLOCKER] Fabric debt hashes the sent payload, but readiness has no way to name that payload.

   `SetFabricForwarding` writes `FabricFwdInfo` to the BPF map and then invokes parameterless `SyncFabricState` (`pkg/dataplane/userspace/controllers.go:112-132`). The manager independently rebuilds its `FabricSnapshot` using fresh config/netlink/neighbor samples (`pkg/dataplane/userspace/manager_ha.go:153-175`; `fabric.go:38-60`).

   These are not the same projection:

   - `FabricFwdInfo` contains only two ifindexes and two MACs (`pkg/dataplane/types.go:797-804`).
   - `FabricSnapshot` also contains names, parent/overlay identity, queue count, peer address, and Up (`pkg/dataplane/userspace/protocol.go:315-333`).
   - Peer-MAC resolution is explicitly independent (`pkg/daemon/daemon_ha_fabric.go:484-490`).

   A link or neighbor change between map write and snapshot construction can produce map P1 and sent P2. The daemon cannot reconstruct the exact full sent hash required by `plan.md:1513-1545`; recomputing later is another TOCTOU sample. `FabricSyncDebtOutstanding(P2)` can therefore return false while a P1/P3 debt remains, allowing `fabricPopulated=true` to admit takeover (`pkg/daemon/daemon_ha.go:774-783`).

   Use a no-argument manager-owned consistency query, or return an opaque token from the exact map-update/helper-send transaction and store that token in readiness state.

13. [MAJOR] The v8.10 tests can green while all major holes remain.

   Active §9 still tests deleted v8.9 identifiers: `expected_config_epoch` at `plan.md:3066-3081`, pending/accepted config epochs at `:3287-3309`, `status.config_epoch` at `:3353-3355`, `note_config_epoch` at `:3371-3378`, `expected_config_epoch` at `:3380-3387`, and fabric debt keyed by `config_epoch` at `:3482-3488`.

   Missing production-chain tests include:

   - legacy active.json migration, downgrade, and migration-write failure;
   - Option-B crash-before-retry revision reuse;
   - atomic config/revision handoff and the feed/DHCP A-config/B-revision race;
   - separate minted/observed publication high-waters and same-commit timeout;
   - synchronous pre-send seed, legacy generation guard, old-Go/new-helper zero, and per-wire retry remint;
   - stale/concurrent manager epoch rebase;
   - CAS helper-behind, typed refusal response, note-vs-divergence poll ordering, and revision-excluded semantic hashing;
   - re-sync through the daemon precheck;
   - actual precheck(true) → argument-less Compile ordering, overlapping Compiles, double Clear, and post-acceptance error;
   - contention at the per-mutation token check, empty-Claim wake delivery, and balanced unwind after Prepare;
   - a recovery member becoming due during the one-second sleep;
   - multiple full RPCs inside one semaphore owner and arbitrary queued owners;
   - exact map-write → sent-payload → readiness-token provenance.

14. [MINOR] f14’s pass-1 “ceiling” is still unspecified.

   `plan.md:1703-1710` gives neither a numeric fake-netlink call limit nor a wall-clock threshold. An implementation can choose any ceiling and make the test green. A fake-netlink CI time also does not bound loaded production netlink latency. The row is not closed until exact assertions are stated.

15. [BLOCKER] The severity-High hazard budget remains unbounded, and v8.10 introduces new outage classes.

   Persistent external control failure may reasonably remain indefinitely fail-closed (`plan.md:3997-4008`). The unacceptable residuals are design-created and ownerless:

   - legacy store revision zero disables lineage gates indefinitely;
   - Option-B crash loses and can reuse revision identity;
   - stale config can be labelled with the current revision;
   - same-commit lost completion can disappear through the single R2 high-water;
   - a surviving helper rejects a restarted Manager through the legacy generation fence;
   - unverified rebase permits a stale manager to lower both revisions;
   - compile reservations can clobber or clear each other;
   - token validation can monopolize `applySem`;
   - token cancellation can leave all workers stopped;
   - a mid-quiesce wrong-MAC member can be rebound;
   - fabric readiness can false-clear against a payload it never identified;
   - repeated 150-second timeouts can continually lose FIFO position.

   These are all new versus master, and most are new versus v8.9’s model. Several reproduce the issue’s exact terminal condition: an accepted configuration with the entire dataplane fail-closed indefinitely and no reliable autonomous owner.

DEMAND-REVISION

Codex session ID: 019fca57-270e-74c3-abfd-0dbb3bdcbd07
Resume in Codex: codex resume 019fca57-270e-74c3-abfd-0dbb3bdcbd07
