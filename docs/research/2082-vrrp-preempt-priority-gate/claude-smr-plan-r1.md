# Claude SMR — hostile PLAN review r1, #2082

Reviewer stance: hostile. Goal = falsify the plan or find the flaw that makes
it ship wrong. Verified against worktree source @ research/2082 (base
origin/master `4565a9ee1`).

## Verdict summary

Reachability claim **holds** — independently re-traced. Path A is the right
direction. But the plan as written has **three gaps** that must close before
PLAN-READY, and **one claim it understates** that actually strengthens it.

## Re-verified claims (PASS)

- **Per-RG shared preempt.** `compiler_system.go:1056` sets `rg.Preempt=true`
  per redundancy-group; `vrrp.go:96` `preemptMap[rg.ID]=rg.Preempt`; copied into
  both nodes' RETH instances (`vrrp.go:153,:172`). No per-node preempt. ✓
- **Secondary RETH priority = 100 < 200.** `group_state.go:205-219`
  `LocalPriorities()` returns 200 (Primary) / 100 (Secondary) from cluster
  STATE. ✓
- **Unconditional trigger.** `manager.go:159-161` loops ALL instances:
  `restorePreempt()` then `triggerPreemptNow()`, no priority/state filter.
  Invoked from `daemon_ha_sync.go:88` `onSessionSyncBulkReceived` (the node that
  received the bulk snapshot = the rejoining Secondary). ✓
- **Consumer has no priority check.** `instance.go:369` `if vi.getPreempt() ||
  force { becomeMaster() }`. ✓
- **No last-seen-peer-priority field.** Grep confirms zero. The data must be
  added. ✓
- **Failback uses force=true.** `daemon_ha.go:241-244` Secondary→Primary →
  `ForceRGMaster` (force=true). `SecondaryHold→Primary` (boot) skips
  ForceRGMaster. So legitimate promotion bypasses any gate. ✓ → Path A cannot
  regress failback.

**Reachability: CONFIRMED. PLAN-KILL is wrong. Path A safe wrt failback.**

## GAP 1 — Lock reentrancy is a SHIP-BLOCKING implementation hazard the plan
underspecifies (must pin the discipline in the plan)

`getPriority()` (`track.go:34`) and `getPreempt()` (`instance.go:252`) BOTH take
`vi.mu.RLock()`. Go `sync.RWMutex` is **non-reentrant**. If
`shouldPreemptObservedMaster()` takes `vi.mu` (to read `lastMasterPriority`/
`lastMasterSeen`) and then calls `getPriority()` or `getPreempt()` (which RLock
again), it **self-deadlocks** (an RLock while holding the lock can also deadlock
against a concurrent pending Lock — Go's RWMutex does not support recursive
read-locking when a writer is queued). The plan's §8 risk #4 *mentions* this but
§5 step 3 does not mandate the fix. The plan MUST specify: the helper computes
the effective priority and preempt **inline under a single `vi.mu.RLock()`**
(replicating the small `getPriority` clamp), OR reads `lastMaster*` into locals
under one lock then calls `getPriority()`/`getPreempt()` with the lock released.
Pick one explicitly. Leaving this to implementation invites the exact deadlock.

## GAP 2 — The TOCTOU/race fear is OVERSTATED in §8 but the plan should turn
that into a stated correctness GUARANTEE (single-goroutine serialization)

Verified: `handleBackupRx` (`:355`), `handleMasterRx` (`:387`), and the
`preemptNowCh` case (`:360`) are ALL cases of the SAME `select` in the SAME run
goroutine (`:350` for-loop). The receiver goroutine only does `rxCh <- pkt`
(`:489` etc). Therefore `lastMasterPriority` is written (in the handlers) and
read (in the gate) by **one goroutine, serialized** — there is NO cross-goroutine
TOCTOU on the gate decision. The lock is needed only for *external* readers
(`Status()`, `getPriority`). The plan's §8 risk #2/#4 frame this as a hot-path/
concurrency worry; it should instead STATE the serialization invariant (gate
reads what the most-recently-processed advert wrote, atomically wrt state
transitions) — this is a positive correctness argument, and it neutralizes the
"async stale read" objection a reviewer will raise. Add it to §6.

## GAP 3 — Priority-0 staleness creates a real "no-master / blocked-takeover"
hazard the plan dismisses too lightly (the harder of the two failure
directions)

The plan says "don't record priority-0 adverts as a master." Correct in spirit
(priority-0 = resignation, not a master to respect). But trace the consequence:
the master resigns with priority-0 (planned shutdown burst, `instance.go:380`
StateMaster stop → 3× `sendAdvert(0)`). The Secondary's `handleBackupRx`
(`:721`) on priority-0 → `masterDownTimer.Reset(1ms)` → masterDown fires →
becomeMaster (correct, fast takeover). BUT if `ReleaseSyncHold` fires the
`preemptNowCh` gate in the tiny window AFTER the last real advert (pri 200
recorded, fresh `lastMasterSeen`) and BEFORE the masterDown timer promotes us,
the gate sees `lastMasterPriority=200`, fresh → DENIES preemption. That is
*fine* (the masterDown timer still promotes us 1ms later — the gate denying the
sync-hold kick does not block the RFC election). The plan MUST state this
explicitly: **the gate only governs the sync-hold preempt SHORTCUT; it never
disables the masterDown-timer election path.** A denied gate leaves the
masterDown timer running (the plan says this in §4 step 3 but does not connect
it to the priority-0 resign case). Without that connection a reviewer will
(correctly) ask "doesn't blocking the gate after a silent master death cause a
no-master outage?" — answer: NO, because masterDown expiry is independent and
untouched. Make this a first-class invariant in §6, and add a test:
`TestPreemptNow_DeniedGateLeavesMasterDownTimerArmed` (or assert via the staleness
fallback). Also verify the gate denial path does NOT `masterDownTimer.Stop()`
(today's code stops it only inside the `if` — confirm the patch keeps Stop()
inside the taken branch only). Re-read `instance.go:369-372`: `masterDownTimer.
Stop()` is INSIDE the `if`, so a denied gate already leaves it running. Good —
the plan should cite this.

## Understated strength (in plan's favor)

§4 risk-1 resolution already shows the non-force `preemptNowCh` kick serves NO
legitimate promotion (force=true does failback; boot uses the masterDown timer).
So Path A's gate, in the common case, simply **deletes the only behavior the
non-force kick produces today that is wrong**, while keeping the one case that
could matter (a legitimate priority-200 node releasing sync-hold while a stale/
lower master lingers → gate true on 200>100, instant). This is a *stronger*
argument for Path A over B than the plan makes: Path B would lose that one
legitimate-fast case; Path A keeps it. The plan states this but buries it —
elevate to §4 recommendation.

## Path B / Path C

- Path B (drop the non-force kick) is genuinely viable and simpler (no new
  state, no lock question). The ONLY thing it costs is the legitimate
  high-priority-node-releasing-sync-hold-with-a-stale-lower-master fast case.
  Whether that case occurs in practice is the open judgment. Path A is the safe
  superset. Acceptable to ship A; B is a legitimate reviewer counter-proposal,
  not a kill.
- Path C (accept) is too weak — becomeMaster() (`:777`) does addVIPs +
  sendAdvert + emitEvent + async GARP. The emitEvent drives downstream cluster
  reconcile (rg_active/blackhole). A transient VIP-on-secondary + GARP on a
  firewall is a real (if brief) data-path hazard. Reject C. ✓ (plan agrees)

## Required changes for PLAN-READY

1. §5 + §6: mandate the exact lock discipline for `shouldPreemptObservedMaster`
   (single RLock, no nested getPriority/getPreempt calls) — close GAP 1.
2. §6: state the single-run-goroutine serialization invariant (GAP 2) and the
   "gate governs only the shortcut, never the masterDown election" invariant
   (GAP 3), citing that `masterDownTimer.Stop()` is inside the taken branch.
3. §7: add the denied-gate-leaves-timer-armed test and a priority-0-resign
   interaction test.
4. §4: elevate the "Path A keeps the one legitimate fast case Path B loses"
   point to the recommendation rationale.

These are tightening/specification changes, not redesigns. No new risk surface.

OVERALL: PLAN-NEEDS-WORK (close GAPs 1-3 by specifying lock discipline + two
invariants + two tests; reachability and Path-A direction are sound and the
fix does not regress failover).
