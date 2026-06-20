# Plan of action — #2082: `ReleaseSyncHold` preempt path lacks peer-priority gate (transient dual-master)

- **Issue:** #2082 (severity LOW, audit-verified; go-cluster-ha lens)
- **Revision:** r3 (r2 closed all r1 findings; r2 review: SMR + reviewer B +
  AGY → PLAN-READY, reviewer A2 found ONE real new blocker — `run()` nil-`conn`
  receiver panic makes the "run `run()` briefly" test path crash. r3 binds the
  wiring tests to an extracted `stepBackup()` seam + folds A2's minor/cosmetic
  notes.)
- **Branch:** `research/2082-vrrp-preempt-priority-gate`
- **Mode:** `/research` — STOPS at PLAN-READY/PLAN-KILL. No code, no PR, no production-source edits.
- **Reviewers required to converge:** hostile Claude general-purpose reviewer A
  + hostile Claude general-purpose reviewer B + AGY adversarial + Claude SMR.
  (Codex companion is infra-degraded this campaign; substituted by two
  independent hostile Claude plan-reviewers per the research-skill
  infra-blocked exception. 3-way convergence = A + B + AGY + SMR all READY.)

### r1 → r2 changelog (what every reviewer required, and how r2 closes it)

1. **Drop the IP tie-break; use strict `>` only (AGY, RFC 5798 §6.4.2).** A
   BACKUP preempts only on *strictly higher* priority; equal priority does NOT
   preempt (the IP tie-break in `handleMasterRx` resolves a MASTER-MASTER
   *collision*, which is a different state than preemption). Removing it also
   deletes the need to record the peer's IP and eliminates the
   nil-`localIP` edge case (reviewer A's open point — now moot). §4/§5/§6
   updated.
2. **Fix the concurrency model (reviewer B, reviewer A).** r1 wrongly described
   `lastMaster*` as written by the *receiver* goroutine and read by the run
   loop (a cross-goroutine TOCTOU). FACT: `handleBackupRx`/`handleMasterRx`
   run in the **run-loop goroutine** (`instance.go:354-355,386-387`, both
   `case pkt := <-vi.rxCh:`); the receiver goroutines only `rxCh <- pkt`. So
   the record and the gate are **co-goroutine and serialized** — no TOCTOU.
   The only lock rule is the genuine RWMutex non-reentrancy one (item 3). §6
   rewritten; §8 corrected.
3. **Pin the lock discipline as a binding design rule (all 4 reviewers).**
   `getPriority()` (`track.go:33`) and `getPreempt()` (`instance.go:253`) both
   `vi.mu.RLock()`; Go RWMutex is non-reentrant (and RLock-while-writer-queued
   deadlocks). `shouldPreemptObservedMaster()` MUST snapshot
   `lastMasterPriority`/`lastMasterSeen` under a single `vi.mu.RLock()`,
   release, *then* call `getPriority()`/`getPreempt()` — OR use unlocked
   `*Locked` private helpers (`getPriorityLocked()`, `masterDownIntervalLocked()`)
   entirely within one held lock. NEVER nest. §5/§6 specify this.
4. **Integration test is BLIND on the smoke cluster (reviewer B, AGY).**
   `docs/ha-cluster-userspace.conf` sets NO `preempt` on any RG, and the smoke
   scripts (`test/incus/test-chained-crash.sh:362`, `test-double-failover.sh:239`)
   explicitly assert *no auto-preempt*. With `preempt=false`, `restorePreempt()`
   restores false → the `preemptNowCh` case never calls `becomeMaster()` → the
   bug path is NOT exercised. `make test-failover` 14/0 therefore proves
   no-regression ONLY, never the fix. §7 elevates a preempt-enabled
   run-loop/unit repro to the HARD validation; adding `preempt` to the shared
   smoke cluster is rejected (would break the no-preempt assertions).
5. **New invariants the gate relies on (SMR, reviewer B):** (a) the gate
   governs ONLY the sync-hold preempt *shortcut* — it never disables the
   `masterDownTimer.C` election; a denied gate leaves the timer armed
   (`masterDownTimer.Stop()` is inside the taken branch only, `instance.go:372`);
   (b) priority-0 resignation takeover flows through the *ungated*
   `masterDownTimer.C` path (`handleBackupRx` Reset(1ms) → `instance.go:357`),
   so not recording priority-0 cannot block a post-resign takeover; (c)
   staleness (`lastMasterSeen > masterDownInterval`) rescues BOTH cold-start
   AND silent-master-death (deny window bounded to `masterDownInterval`). §6.
6. **Note the pre-existing force/non-force coalescing (reviewer B).** The
   cap-1 `preemptNowCh` coalesces sends; `ForceRGMaster` sets `forcePreemptOnce`
   before `triggerPreemptNow` and guards `getState()!=StateMaster`. Path A
   changes ONLY the `force==false` branch, so legitimate force=true promotion
   is provably untouched. §8.

---

## 1. Problem statement

`pkg/vrrp/instance.go` run loop, `StateBackup` → `case <-vi.preemptNowCh:`
(currently lines ~360-372):

```go
case <-vi.preemptNowCh:
    vi.mu.Lock()
    force := vi.forcePreemptOnce
    vi.forcePreemptOnce = false
    vi.mu.Unlock()
    if vi.getPreempt() || force {
        vi.becomeMaster()
        advertTimer.Reset(vi.advertInterval())
        masterDownTimer.Stop()
    }
```

`becomeMaster()` is called whenever `getPreempt() || force` is true. It does
**not** compare the node's effective priority against the priority of the
master it is about to displace. Standard VRRP (RFC 5798 §6.1, §6.4.2) says a
preempting BACKUP should take over only when its priority is **higher** than
the current master's. The audit (issue title) cites
`pkg/vrrp/manager.go:159-164` — that is the *trigger* site
(`releaseSyncHoldWithReason` → `restorePreempt()` + `triggerPreemptNow()`); the
*unconditional `becomeMaster`* is the `preemptNowCh` consumer in `instance.go`.

The `preemptNowCh` is signalled from two places:
1. `Manager.releaseSyncHoldWithReason()` (the `ReleaseSyncHold` path) — fires
   `triggerPreemptNow()` on **every** instance after bulk session sync
   completes. `restorePreempt()` runs immediately before, restoring
   `cfg.Preempt` to the configured value.
2. `Manager.ForceRGMaster(rgID)` — sets `forcePreemptOnce=true` then
   `triggerPreemptNow()`. This is an **intentional, cluster-authoritative**
   override (Secondary→Primary failover-reset), and is out of scope of the
   bug — `force=true` deliberately bypasses priority.

### The dual-master scenario (sync-hold path, `force=false`)

Healthy 2-node chassis cluster, RG1 with operator-set `preempt`:

| | Node A | Node B |
|---|---|---|
| cluster state | Primary | Secondary |
| RETH VRRP priority (`LocalPriorities()`) | **200** | **100** |
| `cfg.Preempt` (`preemptMap[rgID]`, shared per-RG) | true | true |
| VRRP state | MASTER | BACKUP |

Node B reboots (or its session-sync link reconnects). On startup the daemon
calls `SetSyncHold(30s)` → B's RETH instances get `cfg.Preempt=false`,
`desiredPreempt=true`. B starts as BACKUP. When B finishes receiving the bulk
session snapshot from A, `onSessionSyncBulkReceived()` →
`vrrpMgr.ReleaseSyncHold()` → for every instance: `restorePreempt()`
(cfg.Preempt → true) then `triggerPreemptNow()`.

B's run loop is in `StateBackup`, hits `case <-vi.preemptNowCh:`,
`getPreempt()==true` → **`becomeMaster()` unconditionally**. B (priority 100)
adds the VIPs, sends an advert, and emits a MASTER event while A (priority 200)
is still the legitimate MASTER. → **transient dual-master**: both nodes own the
RETH VIP, both reply to ARP, GARP may move the L2 path to B.

### Self-heal

After `becomeMaster()`, B is in `StateMaster` with `masterDownTimer` stopped
and `advertTimer` armed at the advert interval. On the next advert B receives
from A, `handleMasterRx()` sees `pktPri(200) > pri(100)` → `becomeBackup()`. So
B self-corrects within roughly one advert interval (~30 ms RETH default, up to
~1 s for standalone VRRP at the 1 s default). The window is bounded but
**non-zero**, and B has *already*: (a) added kernel VIP addresses, (b) sent a
priority-100 advert, (c) emitted a MASTER VRRPEvent (which drives downstream
rg_active / blackhole-route / GARP side effects), and (d) possibly fired async
GARP that moves the switch's MAC table to B for up to one round trip.

---

## 2. Reachability analysis (the central research question)

**Is the unconditional `becomeMaster` on `preemptNowCh` reachable for a
LOWER-priority node with `preempt=true`? — YES, confirmed by source trace.**

Evidence chain (all on `origin/master`, SHA `4565a9ee1`):

1. **Preempt is per-RG, shared by both nodes.** `RedundancyGroup.Preempt` is a
   single bool set from `chassis cluster redundancy-group <id> preempt`
   (`pkg/config/compiler_system.go:1056`). RETH VRRP instances copy it via
   `preemptMap[rgID]` into **both** nodes' instances
   (`pkg/vrrp/vrrp.go:96`, `:153`/`:172`). There is no per-node preempt — if the
   operator enables preempt, the Secondary node also gets `Preempt=true`.

2. **RETH VRRP priority is binary and state-derived: 200 for Primary, 100 for
   Secondary** (`cluster.Manager.LocalPriorities()`,
   `pkg/cluster/group_state.go:205-219`). So the Secondary node's RETH instance
   advertises priority 100 while the Primary advertises 200 — a genuine
   lower-priority node.

3. **`ReleaseSyncHold` fires `triggerPreemptNow()` on all instances**
   unconditionally (`manager.go:159-161`), with no cluster-state or
   priority filter. It is invoked from `onSessionSyncBulkReceived()`
   (`pkg/daemon/daemon_ha_sync.go:88`) — i.e. on the node that just *received*
   a bulk snapshot, which is precisely the rejoining Secondary in the common
   case.

4. **The `preemptNowCh` consumer only checks `getPreempt() || force`**
   (`instance.go:369`) — no priority comparison. With `force=false` (sync-hold
   path) and `getPreempt()==true`, `becomeMaster()` runs regardless of the
   node being priority 100 vs a priority-200 peer.

5. **No last-seen-peer-priority state exists.** Grep of `pkg/vrrp/` for
   `lastPeer|peerPri|masterPri|lastSeen|observedPri` → **zero matches**.
   `handleBackupRx` only resets the masterDown timer; it does *not* record the
   master's advertised priority. **This is the binding constraint for any
   priority-gate option** (see §4): the data needed to gate does not currently
   exist and must be added.

**Counter-argument considered (why it is NOT unreachable):**

- *"Sync-hold is only meant for the higher-priority node preempting."* The
  design intent (README §Behavior, `feedback`/#485) is that sync-hold prevents
  a rejoining node from preempting *before* sessions are synced. But the
  release mechanism applies `triggerPreemptNow` to *every* instance with
  preempt restored, regardless of whether that node is the high- or
  low-priority one. There is no code path that restricts the release-time
  preempt kick to the higher-priority node.

- *"In a healthy cluster the rejoining node is always the Secondary, which
  should not preempt at all."* Exactly — that's the bug. A non-preempting
  Secondary should never become MASTER on sync-hold release. With `preempt`
  configured (a legal, common operator choice for RG1), it does.

- *"`force` makes it intentional."* Only the `ForceRGMaster` path sets
  `force=true`, and that is the cluster-authoritative Secondary→Primary
  promotion — correct by design and explicitly out of scope. The sync-hold
  path uses `force=false`, so this defense does not cover it.

**Conclusion: REACHABLE. PLAN-KILL is not the outcome.** The transient is real
but LOW severity because it self-heals within one advert interval and only the
`preempt`-configured RG is affected.

### Severity calibration / blast radius

- **Affected configs:** only clusters that set `preempt` on a redundancy group
  AND run RETH VRRP (i.e. *not* `no-reth-vrrp` / `PrivateRGElection`, which skip
  RETH VRRP entirely — `vrrp.go:78`). The loss userspace smoke cluster's RG
  config must be checked (§7).
- **Window:** one advert interval (≈30 ms RETH default; ≤1 s standalone). The
  side effects fired in that window (VIP add, MASTER event → rg_active /
  blackhole reconcile, async GARP) are the real cost, not the steady state.
- **Standalone (`CollectInstances`) VRRP:** also reachable in principle (a
  preempt=true, lower-priority standalone instance on sync-hold release), but
  sync-hold is a cluster mechanism (`SetSyncHold` only called from the HA path,
  `daemon_run.go:485`), and standalone instances are not under cluster sync —
  so the realistic trigger is the RETH/cluster path. The fix must still be
  correct for standalone instances since they share the run loop.

---

## 3. Goal / non-goals

**Goal:** On the `ReleaseSyncHold` (`force=false`) preempt path, a node must
become MASTER only when its effective priority would legitimately win the VRRP
election against the currently-observed master — i.e. respect RFC 5798
preemption semantics. Eliminate the transient dual-master on sync-hold release
for a lower-priority preempting node.

**Why the fix is at the VRRP layer (not `rg_state.go`):** the confirmed harm is
a spurious MASTER `VRRPEvent` from the Secondary that flips `rg_active=true` via
`allMasterLocked()` (non-strict mode) + removes blackholes + GARP. The ROOT
cause is the illegitimate VRRP transition; the `rg_active` rule is *correct*
given a legitimate MASTER. Fixing `rg_state` instead would paper over the wrong
VRRP state without stopping the spurious VIP add / advert / GARP burst. The
VRRP-layer gate stops the wrong transition at its source — the right, minimal
layer.

**Non-goals:**
- Do **not** change the `ForceRGMaster` (`force=true`) path — cluster-
  authoritative promotion must stay unconditional and immediate.
- Do **not** change the `rg_state.go` `allMasterLocked()` rg_active rule — it is
  correct given a legitimate MASTER (see above).
- Do **not** regress the project's ~60 ms failover or immediate priority-0
  takeover.
- Do **not** alter the steady-state RFC election (`handleBackupRx`,
  `handleMasterRx`, masterDownInterval) — those are already correct.
- Do **not** restructure the cluster election or sync-hold trigger ordering
  beyond what is needed (path B is offered but weighed against scope).

---

## 4. Path options

### Path A — add a peer-priority gate on the `preemptNowCh` (sync-hold) case (RECOMMENDED)

Record the last-seen master's effective priority on the instance, and on the
sync-hold preempt kick, only `becomeMaster()` if we would win. Concretely:

1. Add `lastMasterPriority int` + `lastMasterSeen time.Time` to `vrrpInstance`
   (guarded by `vi.mu` for external readers; written/read by the run-loop
   goroutine — see §6). Set them in `handleBackupRx` (and `handleMasterRx`)
   for every **non-zero**-priority advert received from a peer:
   `lastMasterPriority = int(pkt.Priority); lastMasterSeen = now`.
   Priority-0 adverts are resignation — do **not** record as a "master"
   (safe: post-resign takeover is ungated, §6 invariant b). **No peer-IP
   field** — the gate uses strict priority only (RFC 5798 §6.4.2; r2 item 1).
2. In the `preemptNowCh` case, when `force==false`, gate on:
   ```
   if force || vi.shouldPreemptObservedMaster() {
       vi.becomeMaster() ...
   }
   ```
   where `shouldPreemptObservedMaster()` returns true iff:
   - `getPreempt()` is true (else false — a non-preempting node never preempts
     on the shortcut), AND
   - **either** we have **not** recently observed a live master (`lastMasterSeen`
     is zero or older than `masterDownInterval()`) — no live master to respect,
     so becoming MASTER is correct (cold-start / peer-down / silent-master-death
     rescue), **or** we **have** observed a recent master AND
     `getPriority() > lastMasterPriority` (**strict `>`**, RFC 5798 §6.4.2).
   - Equal priority → **false** (RFC 5798 §6.4.2: an equal-priority BACKUP does
     not preempt). No IP tie-break here (that is `handleMasterRx`'s
     MASTER-MASTER collision resolver, not a preemption rule).
   - `force==true` always wins via the short-circuit (ForceRGMaster unchanged).
3. If the gate denies preemption, do **not** `becomeMaster()`. Leave the node
   in BACKUP with its `masterDownTimer` running (the gate never stops it —
   `masterDownTimer.Stop()` stays inside the taken `becomeMaster` branch only,
   `instance.go:372`). The normal RFC election then governs: peer master gone →
   masterDown expiry promotes us; cluster promotes us → `UpdateRGPriority(200)`
   + `ForceRGMaster` (force=true) still works.

**Why strict `>` and no tie-break (r2):** RFC 5798 §6.4.2 — a BACKUP transitions
to MASTER on a *higher*-priority condition only. Equal priority is NOT a
preemption trigger; the address tie-break exists only to break a MASTER-MASTER
collision (two nodes already MASTER), which `handleMasterRx` handles. Using the
tie-break in the *preempt* gate would (a) be RFC-non-compliant and (b) force the
instance to record + track the peer master's IP. Strict `>` is correct,
simpler, and stateless beyond the priority+timestamp. For RETH (200/100) equal
never occurs anyway; for standalone instances equal-priority-no-preempt is the
correct RFC behavior.

**Failover-timing impact:** none for legitimate cases. The higher-priority node
(priority 200, the one that *should* preempt) passes the gate immediately —
`getPriority(200) > lastMasterPriority(100)`. The priority-0 takeover path
(`handleBackupRx` peer-resigned → masterDownTimer 1 ms) is untouched. The only
behavior change is the lower-priority node *not* transiently grabbing MASTER —
which is the fix, not a regression.

**Staleness handling:** if `lastMasterSeen` is older than `masterDownInterval`,
treat as "no live master" and allow becomeMaster (the master is presumed gone;
this is the cold-start / peer-down case where the rejoining node legitimately
takes over). This avoids a deadlock where a node that never heard a master
refuses to ever take over on sync-hold release.

**Cost:** ~25 lines in `instance.go` + 2 struct fields + the helper. Self-
contained in `pkg/vrrp`. No cluster/daemon changes.

### Path B — route sync-hold release through normal election instead of forcing a preempt kick

Drop `triggerPreemptNow()` from `releaseSyncHoldWithReason()` for the sync-hold
(non-force) path entirely; only `restorePreempt()`. The node then preempts (or
not) purely via the normal RFC state machine: a preempt-enabled
higher-priority node already ignores the lower peer advert and lets masterDown
expire (`handleBackupRx` tail), promoting in ~masterDownInterval. A
lower-priority node simply never preempts. This is the "let RFC do it" option.

**Pro:** smallest code change, removes the special-case entirely; no new state.
**Con:** loses the *fast* preempt-on-sync-complete for the legitimate
higher-priority node — it now waits up to masterDownInterval (~97 ms RETH)
instead of preempting immediately on sync completion. For the
sync-hold-release-of-the-returning-PRIMARY case (failback), this adds up to
~one masterDownInterval of delay before the high-priority node reclaims. The
existing fast-path (`preemptNowCh` immediate becomeMaster) was added precisely
to make sync-complete preemption instant. Path B regresses that for the
legitimate case to fix the illegitimate one — a worse trade than Path A, which
keeps the fast path for the node that should win and only blocks the node that
should not. **Also**: the legitimate failback path is actually driven by
`ForceRGMaster` (force=true) on Secondary→Primary cluster transition, so the
sync-hold `preemptNowCh` fast-path may be less load-bearing than it appears —
this needs confirmation (see Risks). If confirmed redundant, Path B becomes
attractive for its simplicity.

### Path C — document-and-accept (transient self-heals within one advert interval)

Argue the window is ≤1 advert interval (~30 ms RETH), self-healing, LOW
severity, and the cost of new state + a gate is not worth it. Document the
transient in `pkg/vrrp/README.md` and close.

**Con:** the transient still fires real side effects (VIP add on the wrong
node, a MASTER VRRPEvent that drives rg_active/blackhole/GARP reconciliation, a
GARP burst that can move the L2 path to the wrong node for a round trip). For a
firewall these are not free: a transient VIP-on-secondary + GARP can briefly
blackhole or asymmetrically route traffic, and the spurious MASTER event churns
downstream cluster reconciliation. "Self-heals in 30 ms" understates the blast
radius. **Not recommended**, but listed for completeness and as the floor if
reviewers judge the fix riskier than the bug.

### Recommendation

**Path A.** It directly encodes RFC 5798 preemption on the one path that
violates it, keeps the fast preempt for the node that legitimately should win,
adds no cluster/daemon coupling, and is unit-testable in isolation. Path B is
the fallback if review establishes the sync-hold fast-path is redundant with
`ForceRGMaster` (then simplicity wins). Path C is the floor.

---

## 5. Detailed change set (Path A)

All in `pkg/vrrp/`:

1. **`instance.go` struct:** add
   ```go
   lastMasterPriority int       // last non-zero peer advert priority (mu)
   lastMasterSeen     time.Time // when lastMasterPriority was recorded (mu)
   ```
2. **`handleBackupRx` + `handleMasterRx`:** on any received advert with
   `pkt.Priority != 0`, record `lastMasterPriority`/`lastMasterSeen` under
   `vi.mu` (a short `vi.mu.Lock(); …; vi.mu.Unlock()` — these handlers run in
   the run-loop goroutine; the lock guards only external readers like
   `Status()`). Record before the existing branch logic so it always runs.
3. **New helper `shouldPreemptObservedMaster() bool`** implementing §4 Path A
   step 2: preempt configured AND (no live master OR strictly-higher effective
   priority). **Lock discipline (BINDING, all reviewers):** Go's `sync.RWMutex`
   is non-reentrant. The helper MUST NOT hold `vi.mu` while calling
   `getPriority()` / `getPreempt()` (both RLock `vi.mu` → deadlock). Implement
   as one of:
   - **(preferred) snapshot-then-release:** `vi.mu.RLock()` → read
     `lastMasterPriority`, `lastMasterSeen`, `cfg.Preempt`, `cfg.Priority`,
     `trackDown`, `cfg.TrackInterface`, `cfg.TrackPriorityCost`, **and
     `cfg.AdvertiseInterval`** (needed for the masterDownInterval staleness
     horizon) into locals → `vi.mu.RUnlock()` → compute the effective priority
     inline (replicating the `getPriority` owner-255 / track-clamp logic) and
     the masterDownInterval staleness horizon from locals. Single lock
     acquisition, no nesting. (`advertInterval()`/`masterDownInterval()` today
     are effectively immutable post-construction —`updateConfig` never mutates
     `AdvertiseInterval`— but snapshot it anyway for a clean single-lock read.
     Note `masterDownInterval()` itself calls `getPriority()` → RLock, so it too
     needs a `masterDownIntervalLocked()` variant or inline computation.)
   - **or** add unlocked private helpers `getPriorityLocked()` /
     `masterDownIntervalLocked()` and call them strictly within one held
     `vi.mu.RLock()`. (Factor the existing `getPriority`/`masterDownInterval`
     bodies into `*Locked` and have the public methods wrap with the lock.)
   Pick one explicitly in the implementation; do not reintroduce a
   `getPriority()` call inside a held lock "for DRY."
   **Use `RLock`, not `Lock` (AGY r2):** the helper only reads — use
   `vi.mu.RLock()`/`RUnlock()` so it does not block concurrent external readers
   (`Status()`). **Optimize the relock (AGY r2, optional):** the `preemptNowCh`
   case already does a `vi.mu.Lock()` to read+clear `forcePreemptOnce`; an
   implementer may fold the gate read into a single held-lock helper
   (`shouldPreemptObservedMasterLocked()` reading `forcePreemptOnce` + the
   snapshot in one scope), releasing before `becomeMaster()`. Behavior-neutral;
   not required for correctness.
4. **`run()` `preemptNowCh` case:** replace `if vi.getPreempt() || force` with
   `if force || vi.shouldPreemptObservedMaster()`. (force short-circuits;
   ForceRGMaster path unchanged. The helper already requires `getPreempt()`.)
   Note: at this site `vi.mu` is NOT held (the case releases it after reading
   `forcePreemptOnce`, `instance.go:365-368`), so the helper is entered
   lock-free — the only deadlock risk is internal to the helper (item 3).
5. **`pkg/vrrp/README.md`:** document the sync-hold preempt gate under the
   Behavior / Sync-hold section — a lower-priority preempt-enabled node no
   longer transiently becomes MASTER on sync-hold release; it defers to the
   observed higher-priority master (strict `>`, RFC 5798 §6.4.2) and follows
   the normal RFC election. Also update the `CLAUDE.md` Chassis-Cluster
   sync-hold bullet (one line: "sync-hold release preempt is now peer-priority
   gated").

No changes to `manager.go` trigger logic (it still calls `restorePreempt` +
`triggerPreemptNow` for all instances; the gate lives in the consumer so both
the sync-hold and any future trigger benefit). No new field for peer IP.

---

## 6. Correctness arguments / invariants

- **Single-goroutine serialization (no TOCTOU) — corrected in r2.**
  `handleBackupRx`/`handleMasterRx` (the `lastMaster*` writers) and the
  `preemptNowCh` case (the gate reader) are ALL cases of the *same* `select`
  in the *same* run-loop goroutine (`instance.go:350` for-loop;
  `:354-355,:386-387,:360`). The receiver goroutines only `rxCh <- pkt`. So the
  gate reads exactly what the most-recently-processed advert wrote, atomically
  with respect to state transitions — there is **no cross-goroutine race on the
  gate decision**. `vi.mu` is needed only for *external* readers (`Status()`,
  `getPriority`); it is NOT a correctness barrier between record and gate.
- **Legitimate higher-priority preempt still instant.** Node with effective
  priority 200 observing a master at 100 (or no live master): `200 > 100` →
  gate passes → immediate becomeMaster. No timing regression.
- **Illegitimate lower-priority preempt blocked.** Node at 100 observing a live
  master at 200: `100 > 200` false, fresh `lastMasterSeen` → gate denies →
  stays BACKUP. Bug fixed.
- **Invariant (a): gate governs only the shortcut, never the election.** A
  denied gate does NOT touch `masterDownTimer` (Stop() is inside the taken
  `becomeMaster` branch only, `instance.go:372`). So the RFC `masterDownTimer.C`
  election (`instance.go:357-358`) remains armed and independent. The gate can
  never cause a *no-master* outage — at worst it defers the shortcut; the timer
  still promotes on real master death.
- **Invariant (b): priority-0 resignation takeover is ungated.** When the
  master resigns (priority-0 burst), `handleBackupRx` sets
  `masterDownTimer.Reset(1ms)` (`instance.go:727`) → `masterDownTimer.C` →
  becomeMaster — this NEVER flows through the gated `preemptNowCh` case. Hence
  not recording priority-0 (leaving a stale-high `lastMasterPriority`) cannot
  block a legitimate post-resign takeover.
- **Invariant (c): staleness rescues cold-start AND silent-master-death.**
  `lastMasterSeen` zero (never heard a master) OR older than
  `masterDownInterval` (master gone silently, no priority-0) → gate treats as
  "no live master" → becomeMaster allowed. Deny window for a silent death is
  bounded by `masterDownInterval` (~97ms RETH), and the ungated timer (invariant
  a) promotes independently inside that window anyway. No "never take over"
  deadlock; no outage.
- **ForceRGMaster unaffected.** `force==true` short-circuits the gate
  (`if force || …`). Legitimate Secondary→Primary promotion
  (`daemon_ha.go:243`) is untouched.
- **Owner-255 / track demotion.** The gate compares the *effective* priority
  (the `getPriority` value: owner-255 exempt, track-clamped [1,254]) — not raw
  `cfg.Priority`. Owner-255 always wins (`255 > any ≤254`); a track-demoted
  node correctly fails the gate and stays BACKUP. Reuses existing semantics; no
  new clamp logic (computed inline-from-snapshot or via `getPriorityLocked`,
  §5 item 3).
- **Staleness threshold = masterDownInterval.** Same horizon the RFC uses to
  declare the master dead; consistent with `handleBackupRx` timer semantics.
- **Equal priority does not preempt (RFC 5798 §6.4.2).** Strict `>`; no IP
  tie-break in the gate. RETH (200/100) never hits equal; standalone
  equal-priority-no-preempt is correct RFC behavior.

---

## 7. Test plan

**PRIMARY regression guard — MUST exercise the actual `preemptNowCh` decision
wiring, NOT just the helper in isolation (reviewer A, SMR).** A helper-only test
(`shouldPreemptObservedMaster()` alone) is INSUFFICIENT: if the implementer adds
the helper but leaves `run()` as `if vi.getPreempt() || force`, a helper test
passes while the bug ships. The decision wiring must be tested.

**CRITICAL test-construction hazard (reviewer A2, r3) — do NOT call `run()`
directly in a unit test.** `run()`'s preamble unconditionally spawns
`go vi.receiver()` when `afPacketFD < 0` (`instance.go:305`), and `receiver()`'s
first action is `vi.conn.SetReadDeadline(...)` on the (nil) `conn`
(`instance.go:445`) → **nil-pointer panic in a background goroutine that crashes
the test process.** A `newInstance(...)` test instance has `conn==nil` and
`afPacketFD==-1`, so "run `run()` briefly under a stop channel" is BROKEN.

**Required seam:** extract the `StateBackup` `select` body into a single-iteration
method, e.g. `stepBackup(masterDownTimer, advertTimer *time.Timer) (returned
bool)`, that the `run()` loop calls, AND that the test calls directly. The test
then: `newInstance(...)` → `setState(StateBackup)` → seed `lastMaster*` →
`triggerPreemptNow()` → call `stepBackup(...)` once → assert `getState()`. The
fail-soft chain inside `becomeMaster()` is verified: `addVIPs()` Warn+returns on
`netlink.LinkByName` failure (`instance.go:1006-1011`), `sendPacket` returns nil
on `rawConn==nil` (`instance.go:886`), `sendGARP` is fail-soft (and the test
sets `suppressGARP`). So `stepBackup` taking the becomeMaster branch does not
panic — only the receiver-spawn in `run()` does, which the seam avoids. (If the
implementer prefers not to extract a seam, the alternative is to give the test a
non-nil `conn`/`afPacketFD` stub so the receiver does not nil-panic — but the
`stepBackup` seam is cleaner and is the recommended path.)

**Unit (`pkg/vrrp/vrrp_test.go`), new tests:**

1. `TestPreemptNow_LowerPriorityStaysBackup` (**wiring guard, via `stepBackup`
   seam**): priority 100, preempt=true, `lastMasterPriority=200`/
   `lastMasterSeen=now`, `suppressGARP=true`, trigger preempt, call
   `stepBackup(...)` once → assert state stays `StateBackup`. **MUST FAIL on
   today's `if vi.getPreempt() || force`** (which would becomeMaster) — true
   regression guard.
2. `TestPreemptNow_HigherPriorityBecomesMaster`: priority 200, observed master
   100 → call `stepBackup(...)` → state → `StateMaster`. NOTE: `becomeMaster()`
   spawns `go vi.sendGARP()` unless `suppressGARP` is set — the test should
   `vi.suppressGARP.Store(true)` (or tolerate the fail-soft GARP goroutine,
   which no-ops on a fake interface) to avoid a stray goroutine.
3. `TestShouldPreempt_NoObservedMaster`: `lastMasterSeen` zero → true (helper,
   cold-start).
4. `TestShouldPreempt_StaleMaster`: `lastMasterSeen` older than
   masterDownInterval → true (helper, silent-death/peer-down rescue).
5. `TestPreemptNow_ForceBypassesGate`: priority 100, observed master 200,
   `force=true` → `StateMaster` (ForceRGMaster path unchanged).
6. `TestShouldPreempt_EqualPriorityNoPreempt`: equal priority, fresh master →
   **false** (RFC 5798 §6.4.2 — no IP tie-break; helper).
7. `TestHandleBackupRx_RecordsMasterPriority`: feed a non-zero advert → assert
   `lastMaster*` updated; feed a priority-0 advert → assert `lastMaster*`
   **unchanged** (resignation not recorded).
8. `TestPreemptNow_DeniedGateLeavesMasterDownTimerArmed` (invariant a): denied
   gate (via `stepBackup`) → assert the masterDown timer was NOT stopped (e.g.
   pass a short masterDown timer and verify a subsequent `stepBackup` on its
   expiry promotes to MASTER). Uses the seam, not `run()`.
9. (-race) run the suite with `-race` to confirm the snapshot lock discipline
   has no data race between the run loop and external `Status()` readers.

**Integration / failover — HONEST coverage statement (reviewer B, AGY):**
The smoke cluster config (`docs/ha-cluster-userspace.conf`) sets **NO `preempt`**
on any RG, and the smoke scripts (`test/incus/test-chained-crash.sh:362`,
`test-double-failover.sh:239`) explicitly assert *no auto-preempt*. With
`preempt=false`, `restorePreempt()` restores false → the `preemptNowCh` case
never calls `becomeMaster()` → **the bug path is NOT exercised**. Therefore:
- `make test-failover` (loss userspace cluster) is REQUIRED but is a
  **no-regression gate ONLY** — a green 14/0 does NOT validate this fix. It is
  mandated by CLAUDE.md for any VRRP/failover change and must stay green.
- Do **NOT** add `preempt` to the shared smoke cluster — it would break the
  existing no-auto-preempt assertions in the smoke scripts and is a shared
  resource.
- The ACTUAL validation of the fix is the run-loop wiring unit test (#1 above)
  with `preempt=true` + recorded `lastMasterPriority`. If a live integration
  repro is wanted, it belongs in an ISOLATED throwaway 2-node config with
  `preempt` set on an RG (not the shared loss cluster) — optional, the unit
  guard is sufficient and authoritative.
- `go test ./pkg/vrrp/ -race` and `go build ./...` are mandatory.

---

## 8. Risks / open questions

1. **Is the sync-hold `preemptNowCh` fast-path redundant with `ForceRGMaster`
   for legitimate failback? — PARTIALLY RESOLVED by source trace
   (`pkg/daemon/daemon_ha.go:209-245`).** Legitimate Secondary→Primary cluster
   promotion is driven by `UpdateRGPriority(rg,200)` + `ForceRGMaster(rg)`
   (force=true), which bypasses any preempt gate. The `SecondaryHold→Primary`
   (initial boot) edge *intentionally skips* `ForceRGMaster` ("VRRP should
   follow its own election timer") — so even on boot the non-force sync-hold
   preempt kick is **not** the mechanism that promotes a node; VRRP's own
   masterDown timer is. This means: (a) Path A's gate cannot break legitimate
   failback (that path uses force=true), and (b) the only thing the non-force
   `preemptNowCh` kick does today is exactly the buggy behavior — let a
   preempt-configured node jump to MASTER on sync-complete *outside* the RFC
   election. This makes **Path B more credible** (the non-force kick may serve
   no correct purpose), AND confirms **Path A is safe** (it only blocks the
   illegitimate non-force preempt; force=true is untouched). One residual: a
   node that *is* the legitimate high-priority Primary and releases sync-hold
   while a stale/lower peer briefly holds master — Path A still lets it preempt
   instantly (gate true on `200 > 100`), Path B would make it wait
   masterDownInterval. Net: **Path A dominates Path B** — same safety, no
   regression to the one fast-path case that could matter. Reviewers to
   confirm the trace.
2. **Recording `lastMasterPriority` on every advert** is in the RX handling
   path (`handleBackupRx`), a single int+time write per received advert (30 ms
   cadence) — negligible. It runs in the run-loop goroutine (NOT the receiver),
   so it is serialized with the gate read (§6). The `vi.mu` it takes is only to
   protect external readers.
3. **Standalone (non-cluster) VRRP** shares the run loop. Path A is correct for
   it (records peer priority and gates), but standalone instances are not under
   sync-hold, so the gate's only effect there is on a future `triggerPreemptNow`
   caller — currently none besides ForceRGMaster (cluster). No behavior change
   for standalone today; future-proof. Equal-priority-no-preempt is RFC-correct.
4. **Concurrency / lock reentrancy (RESOLVED in r2, was the top r1 hazard).**
   The record and gate are co-goroutine (no TOCTOU). The ONLY hazard is RWMutex
   non-reentrancy: `shouldPreemptObservedMaster()` must snapshot under one
   `vi.mu.RLock()` then release before calling `getPriority()`/`getPreempt()`,
   OR use `*Locked` helpers within one held lock — never nest (§5 item 3).
   `-race` in the test suite guards the snapshot vs `Status()` readers.
5. **`make test-failover` CANNOT exercise the bug** — the smoke cluster is
   `preempt=false` and the scripts assert no-auto-preempt (§7). Resolved by
   making test-failover a no-regression gate only and the run-loop unit test the
   authoritative validation. NOT an open risk anymore — a stated constraint.
6. **Pre-existing force/non-force `preemptNowCh` coalescing (reviewer B) — NOT
   worsened by Path A.** The cap-1 channel coalesces sends; `ForceRGMaster`
   sets `forcePreemptOnce` before `triggerPreemptNow` and guards
   `getState()!=StateMaster` (`manager.go`). Path A changes ONLY the
   `force==false` branch (adds the gate). The `force==true` consume reads
   `forcePreemptOnce` at consume time and short-circuits the gate, so legitimate
   force promotion is provably untouched. The coalescing semantics are
   unchanged from today.

---

## 9. Documentation impact

- `pkg/vrrp/README.md` — Behavior / Sync-hold section: state that sync-hold
  release no longer unconditionally preempts; a preempt-enabled node defers to
  an observed higher-priority master (RFC 5798 §6.1).
- `CLAUDE.md` "Chassis Cluster (HA)" sync-hold bullet — note the preempt gate
  if the summary is load-bearing (likely a one-line addition).

---

## 10. Rollback

Pure-Go, self-contained in `pkg/vrrp`. Revert is a single `git revert` of the
implementation commit; no migration, no on-disk state, no wire-format change.

---

## 11. Verdict ledger

**r1:**
- Claude SMR r1: PLAN-NEEDS-WORK (lock discipline underspecified; add
  serialization + gate-only-shortcut + staleness invariants; tests must drive
  run loop).
- Hostile reviewer A r1: PLAN-NEEDS-WORK (test must drive run() not helper;
  lock discipline binding not "verify"; integration blind without preempt RG;
  pin nil-localIP — now moot, tie-break dropped).
- Hostile reviewer B r1: PLAN-NEEDS-WORK (r1's cross-goroutine TOCTOU model is
  factually wrong — record+gate co-goroutine; staleness must cover
  silent-master-death; test-failover is `preempt=false` so proves nothing;
  note coalescing). Confirmed REAL harm: spurious Secondary MASTER →
  `allMasterLocked()` → rg_active=true + blackholes removed on Secondary.
- AGY r1: PLAN-NEEDS-WORK (deadlock via nested RLock → use `*Locked` helpers;
  drop IP tie-break, RFC 5798 §6.4.2 strict `>`; enable preempt in test config
  or downgrade integration claim).

All four r1 → **PLAN-NEEDS-WORK, reachability CONFIRMED (PLAN-KILL refuted by
all four).** r2 closes every required change (see r1→r2 changelog at top).

**r2:**
- Claude SMR r2: PLAN-READY (all four r1 changes correctly closed; load-bearing
  claims re-verified; two non-blocking nits folded into r2).
- Hostile reviewer B r2: PLAN-READY (all four r1 points closed + verified;
  harm real even multi-VLAN, self-healing with no durable rg_active damage; vrrp
  is the correct fix layer; strict `>` correct for all cases).
- AGY r2: PLAN-NEEDS-WORK — independently found the SAME nil-`conn`
  receiver-panic test blocker as A2 (strong corroboration); RFC compliance +
  lock discipline + invariants verified; two refinements (use RLock in the gate
  helper; optionally fold the relock) folded into r3 §5.
- Hostile reviewer A r2 (A2): PLAN-NEEDS-WORK — three of four r1 points fully
  closed, but found ONE real NEW blocker: §7's "run `run()` briefly" test path
  panics (nil `conn` in the unconditionally-spawned receiver). Plus minor
  (snapshot `AdvertiseInterval`) + cosmetic (line cites). → r3.

**r3 (closes A2's blocker):** wiring tests bound to an extracted `stepBackup()`
seam (no `run()` in unit tests → no receiver nil-panic); `AdvertiseInterval`
added to the §5 snapshot; line cites corrected (372, 727). r3 re-review pending
to confirm convergence.

- Claude SMR r3: _pending_
- Hostile reviewer A r3: _pending_
- Hostile reviewer B r3: _pending (B2 already PLAN-READY at r2; r3 changes are a
  strict superset addressing A2's blocker, no regression to B2's findings)_
- AGY r3: _pending_

**Current status: PLAN-READY candidate (r3), pending r3 re-review convergence.**
**Reachability: CONFIRMED REACHABLE (not PLAN-KILL).**
