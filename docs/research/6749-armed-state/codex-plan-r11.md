# Codex plan review — round 11 — #6749 armed-state plan v8.6 (f42b500ce2; plan content = dc0e618f8)

**Reviewer:** Codex (hostile; companion task task-msdpdhr4-xmh4du, fresh thread; prompt /tmp/codex-6749-r11-prompt.txt). A second dispatch (orphan task-msdotvm6-vc98k3 from the interrupted prior session) stalled 70+ minutes with no output and was cancelled; this completed task is the round-11 Codex verdict of record. Raw output: /tmp/codex-6749-r11.out.

**Verdict: DEMAND-REVISION** (9 BLOCKER + 3 MAJOR; Q1 unowned-producer hunt remains CLOSED).

---

Reviewed the exact `f42b500ce2` committed plan blob; no files were modified.

1. [BLOCKER] The §1 disposition table materially overclaims closure.

   The table at [plan.md:374](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:374) audits as follows:

   | r10 row | Round-11 result |
   |---|---|
   | Codex f2 | REOPENED/BLOCKER — mixed-bucket predicate and cohort semantics remain contradictory; handoff remains undefined. |
   | Codex f3 | REOPENED/BLOCKER — the pair uses the wrong generation authority and does not fence request-side hybrids. |
   | Codex f4 | REOPENED/BLOCKER — legitimate completions false-refuse; unknown successors and latch exits can become ownerless. |
   | Codex f5/f6 | REOPENED/MAJOR — several tests and invariants still contradict the proposed mechanics. |
   | Codex f7 | REOPENED/BLOCKER for the edge trigger; REOPENED/MAJOR for the claimed 19-second bound. |
   | AGY f1 | Narrowly closed: the intended `configEpoch` is FIB-clean. Its advance/consumer contract is still inconsistent. |
   | AGY f2/f3 | Narrowly closed: forwarding `complete_deferred` is sufficiently stated. |
   | SMR N1–N3 | N1 narrowly closed; N2 and N3 reopened by the bucket-flap contradiction and unsafe pre-disable edge. |

   Q1 itself remains closed: the production writers are the planner ([planning.rs:482](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:482)), binding and queue verbs ([binding.rs:21](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/binding.rs:21), [queue.rs:23](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/queue.rs:23)), and global fan-out ([status.rs:418](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/status.rs:418)). I found no additional same-version `Registered && !Armed && none` producer.

2. [BLOCKER] Pair-gated adoption compares values that are not a helper snapshot-lineage pair.

   The plan compares helper `(last_snapshot_generation,last_fib_generation)` with `m.lastSnapshot.(Generation,FIBGeneration)` ([plan.md:1025](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1025)). A clean FIB bump disproves that equivalence:

   - Go moves from `(G,F)` to `(G+1,F+1)` before sending ([manager_generation.go:69–72](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_generation.go:69)).
   - Rust updates only its FIB generation and remains at snapshot generation `G` ([snapshot.rs:470–473](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/snapshot.rs:470)).
   - Content dedup then advances `publishedSnapshot` without a full publish ([process_status.go:72–80](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_status.go:72)).
   - The successful FIB retry owner clears, so nothing necessarily repairs the split.

   Neighbor regeneration and resolved-fabric persistence produce the same split ([manager_neighbor.go:129–140](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_neighbor.go:129), [manager_ha.go:201–220](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_ha.go:201)); neither partial Rust handler advances `last_snapshot_generation` ([neighbors.rs:42–57](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/neighbors.rs:42), [handlers/mod.rs:168–174](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/mod.rs:168)).

   Adoption can therefore remain blocked after ordinary successful operations. A later wholesale clone can republish stale Go fabrics and undo the helper’s accepted fabric update—the exact #5306 failure documented in [manager_ha.go:179–193](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_ha.go:179).

   Partial status is not the problem: current Rust statuses serialize both counters and unsuppressed responses attach a refreshed full status ([control.rs:173–176](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/protocol/control.rs:173), [handlers/mod.rs:264–266](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/mod.rs:264)). The authority is wrong. The source already identifies `appliedSnapshot.Generation` as the actual helper-accepted full-snapshot authority ([applied_nat_view.go:5–21](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/applied_nat_view.go:5)).

3. [BLOCKER] Pair-gated response adoption does not prevent request-side fabric hybrids.

   `SyncFabricState` builds from `m.lastSnapshot.Config` and sends `update_fabrics` with no lineage token ([manager_ha.go:153–175](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_ha.go:153), [protocol.go:55–84](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/protocol.go:55)). Rust mutates whichever snapshot it currently stores before responding ([handlers/mod.rs:144–174](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/mod.rs:144)).

   Both quadrants therefore remain:

   - Go-ahead: pending-XSK Compile stores unpublished B ([manager_compile.go:245–313](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:245)); Sync sends B fabrics into helper A.
   - Helper-ahead: a landed-but-unacknowledged B leaves Go at A; Sync sends A fabrics into helper B.

   The v8.6 handler can replan and unarm the helper vector before the post-response adoption gate runs. Keeping Go’s cache whole afterward cannot undo that helper-side hybrid. The request itself needs lineage fencing or must be suppressed during divergence. The quadrant tests at [plan.md:1937](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1937) test only response adoption.

4. [BLOCKER] `expected_snapshot_generation` permanently false-refuses legitimate same-epoch completions.

   After any partial operation in finding 2, Go can publish `G+1` while the helper’s stored full-snapshot generation remains `G`. `configEpoch` correctly remains unchanged, so the MAC completion is still legitimate; nevertheless the proposed tag sends `G+1` and the helper refuses forever ([plan.md:1293–1314](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1293)). This is precisely the false-refusal the plan claims to have eliminated.

   The text also treats `m.publishedSnapshot` as an object with `.Generation` and a cached defer copy, while it is a `uint64` ([manager.go:194](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager.go:194)). The design needs a distinct, explicitly helper-acknowledged full-snapshot token.

   I found no intended happy-path stale-completion bypass if every tagged request carries a nonzero expectation. However, refusal ordering is not specified. Current rebind clears live binding fields before reconciliation ([rebind.rs:42–50](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/handlers/rebind.rs:42)); the generation mismatch check must precede every mutation, teardown, reconcile-entry increment, latch change, and persistence.

5. [BLOCKER] Timeout-but-landed successors and defer exits still lack a complete ownership protocol.

   The plan simultaneously says an unacknowledged successor rolls the flag back and leaves A’s debts alive ([plan.md:1099](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1099)), and that a landed-but-unacknowledged deferred B “always has an active MAC debt” ([plan.md:1300](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1300)). Go cannot establish both facts: the write can land before response decoding fails ([process_control.go:145–161](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process_control.go:145)), while Compile commits its snapshot bookkeeping only after a clean response ([manager_compile.go:350–365](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:350)).

   Result: helper B can be deferred, A’s completion is deliberately refused, and Go owns neither an accepted B epoch nor a specified autonomous B republish. “The next apply” is not a retry owner.

   The requested exit enumeration is also incomplete:

   - Tagged completion: clean three-authority clearing is stated, but a lost response can clear only the helper.
   - No-MAC rollover/acceptance cancellation: clean full apply is described; timeout-but-landed falls into the ownerless case above.
   - Operator arm: only the clean global-arm case tests all three authorities ([plan.md:1823–1827](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1823)); no unknown-result recovery exists.
   - Nil-config teardown: prose/tests cancel epoch/debt only ([plan.md:1126–1132](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1126)). Current `stopLocked` resets process/published state but retains `m.deferWorkers` and `m.lastSnapshot` ([process.go:197–267](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/process.go:197)).
   - HA supersede: `configEpoch` supersession is asserted, but unknown-response latch/cache reconciliation is not.
   - Global disarm is called an epoch-expiry path at [plan.md:1285](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1285) but is absent from the all-three list.

   The “exactly two exits” ownership statement ([plan.md:1429–1438](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1429)) is therefore false.

6. [MAJOR] `configEpoch` has the right purpose but an inconsistent advance contract.

   The correct split is: MAC/link-recovery debt and #5134 debt use `configEpoch`; full-snapshot/refusal lineage remains separate; FIB/cache sequencing stays on existing counters; every actually accepted config path—including HA peer, rollback, auto-revert, and background full recompile—advances; applied-identical HA does not.

   Two v8.6 mechanics violate that split:

   - The direct #5134 retry is required to advance `configEpoch` ([plan.md:1332–1334](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1332), [plan.md:1919–1922](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1919)), but it merely clones `m.lastSnapshot`, clears defer, and directly republishes without a three-bucket precheck ([manager_worker_arm_5134.go:57–87](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_worker_arm_5134.go:57)). Advancing cancels same-config bucket-ii recovery entries through their epoch guard, with nothing recreating them.
   - Pending-XSK Compile stores B and returns success without helper publication ([manager_compile.go:272–313](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/manager_compile.go:272)). The plan alternates between advancing “at compile acceptance” and “after accepted publish completes” ([plan.md:1317–1325](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1317). Either choice has different debt-cancellation requirements, but neither is specified.

7. [BLOCKER] Bucket-i-only completion remains semantically contradictory.

   Bucket ii is called an entry “in the MAC debt” ([plan.md:1157–1163](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1157)), while completion is authorized by `!m.hasActiveMACDebt` ([plan.md:1201–1219](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1201)). No definition excludes link-recovery entries. A literal implementation therefore lets an unplugged bucket-ii sibling gate a bucket-i epoch—the r10 mixed-case outage unchanged.

   The cohort policy also says mutually exclusive things:

   - Every programmed bucket-i member must validate MAC and link-up ([plan.md:1173–1177](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1173)).
   - Settle-time reread downgrades a now-down member to non-gating bucket ii ([plan.md:1194–1200](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1194)).
   - Q7 says that same permanently-down bucket-i member keeps the epoch open ([plan.md:2341–2351](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:2341)).
   - Tests still require every member to be up ([plan.md:2105–2111](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:2105)).

   `programRethMAC` makes this distinction observable: MAC equality returns without inspecting link state, while final link-up failure returns `(true,error)` ([daemon_reth.go:238–270](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_reth.go:238)).

   The bind/arm leg itself has no converse hole: planning includes every registered valid-ifindex slot, reconciliation succeeds only when bound equals planned, and pending slots arm only afterward ([bringup.rs:188–204](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:188), [plan.md:858–881](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:858)). Helper `enabled=true` requires every registered slot armed ([status.rs:274–281](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/status.rs:274)). Thus bucket ii cannot silently remain unarmed while enabled, and a truthful completion cannot skip binding bucket-i slots. The blocker is the undefined completion cohort.

8. [BLOCKER] The LinkController handoff is still not an architecture contract.

   The plan supplies no method name, signature, bucket/result types, epoch token, return/error semantics, locking rules, rollback behavior, or lifecycle ([plan.md:1523–1536](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1523)). The existing interface is three void methods ([apply.go:130–134](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/apply.go:130)).

   Today the daemon owns the precheck and per-member netlink results ([daemon_apply_dataplane.go:45–82](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_dataplane.go:45), [daemon_apply_dataplane.go:261–299](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_apply_dataplane.go:261)), and owns the capacity-one `applySem` ([daemon.go:485–496](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon.go:485)). The proposed manager-owned autonomous debt cannot acquire that semaphore or perform reverse netlink work through an unspecified daemon→manager method. The debt owner and bidirectional serialization protocol must be designed, not deferred to implementation.

9. [BLOCKER] Edge-triggering pre-disable solely by projection value is unsafe.

   The guard is environmental: unreadable sysfs yields zero queues and can later recover without projection B changing ([planning.rs:605–621](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/userspace-dp/src/server/helpers/planning.rs:605)). The plan nevertheless tracks only `requestedProjection != lastPreDisableProjection` ([plan.md:993–1019](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:993)).

   Counterexample:

   - B is verified-disabled, sent, guard-rejected, and ctrl re-enabled.
   - Sysfs recovers.
   - Identical B is retried. The edge suppresses disable, but B is now accepted and marks/replans the vector.
   - If the response is lost, ctrl remains enabled throughout an unknown helper mutation.

   Tracking last attempted B causes this bypass. Tracking only accepted B causes every identical rejection to pulse again. A→B(rejected)→A also produces an unnecessary pulse because A differs from the last attempted value. One scalar cannot meet both claimed properties; this needs a preflight/acceptance token or another two-phase fence.

   Readback failure is safely fail-closed only if the tracker advances after successful proof and the error reaches the scheduling layer. Neither is pinned. The manager and internal wrappers are void, while the daemon ignores the public controller error ([controllers.go:42–48](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/controllers.go:42), [controllers.go:128–143](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/dataplane/userspace/controllers.go:128), [daemon_ha_fabric.go:752–759](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/pkg/daemon/daemon_ha_fabric.go:752)).

10. [MAJOR] The v8.6 test plan can green with the blockers intact.

   - Reconcile-entry counting exists, but the common test list still treats `update_fabrics` as an in-handler reconcile caller despite the design explicitly removing that reconcile ([plan.md:971–984](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:971), [plan.md:1746–1750](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1746)).
   - Lost-ACK tests prove stale A refusal but omit legitimate same-epoch false refusal and the ownerless B case.
   - Three-authority tests cover clean global arm, not unknown tagged/rollover/operator/HA results or nil teardown.
   - Pair-quadrant tests cover adoption, not request-side mutation or FIB/neighbor/fabric-persist counter splits.
   - Nil-config and HA tests assert debt/epoch behavior, not all three latch authorities.
   - Fault injection omits tracker retention and a second recovered identical attempt.
   - Budget tests assume a fresh retry clock.
   - Event-storm tests correctly preserve the exponent, thereby exposing—not resolving—the possible 60-second accepted-change delay.
   - Bucket tests omit the explicit mixed `{bucket-i mismatch, bucket-ii correct/down}` completion predicate and retain the contradictory “every member up” rule.
   - The capacity-one race at [plan.md:2139–2145](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:2139) is not implementable as written: once the autonomous attempt is queued behind the synthetic semaphore owner, a later separate flow cannot acquire ahead of it.
   - The revised restart test correctly classifies correct-MAC/down as bucket ii, but does not choose the bucket-i flap policy.

   Additional contradictions remain: a nonexistent fabric rate-cap/trailing-coalesce test ([plan.md:1678](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1678), [plan.md:1990](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1990)); “TWO additive fields” followed by three ([plan.md:1499–1518](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1499)); and “No coordinator changes” despite the specified identity-copy coordinator change ([plan.md:1457–1465](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1457), [plan.md:1603–1606](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1603)).

11. [MAJOR] The ≈19-second figure is a clean-baseline estimate, not a worst-case bound.

   Retry exponent is preserved, and only a changed pending `(interface,queue_id)` membership pulls the deadline earlier ([plan.md:1362–1366](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1362), [plan.md:1397–1404](/home/ps/git/kimi-xpf/.claude/worktrees/6749-research-armed-state/docs/research/6749-armed-state/plan.md:1397)). A same-name/new-parent-ifindex projection can mark the same identities pending while their retry is already at the 60-second floor. Convergence is then roughly 60 seconds plus readiness, polling, RPC, and jitter—not 19 seconds. Defer/debt suppressions can extend it further.

   A roughly 19-second healthy unsuppressed baseline is acceptable for this High-severity fail-closed repair. Persistent verified-control failure remaining fail-closed and permanent bind failures probing every 60 seconds are also defensible if their errors and edge warnings reach operators. The unsafe guard edge is not acceptable. Nor is the contradictory claim that one permanently-down bucket-i member may disable the entire dataplane indefinitely; under the stated settle reread it must either downgrade to bucket ii or the plan must justify retaining the exact outage class being fixed.

   New hazards introduced by v8.6 versus master are therefore concrete: reject→accept pre-disable bypass, helper-side wrong-lineage fabric mutation, permanently wedged pair adoption and stale-fabric reversion, legitimate completion false-refusal, ownerless timeout-landed successors, and configEpoch cancellation of link-recovery debt.

DEMAND-REVISION

Codex session ID: 019fc963-ea62-7232-9a3d-c267bec1650e
Resume in Codex: codex resume 019fc963-ea62-7232-9a3d-c267bec1650e
