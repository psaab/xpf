# Plan of action — #2082: `ReleaseSyncHold` preempt path lacks peer-priority gate (transient dual-master)

- **Issue:** #2082 (severity LOW, audit-verified; go-cluster-ha lens)
- **Revision:** r1 (initial draft, pre-review)
- **Branch:** `research/2082-vrrp-preempt-priority-gate`
- **Mode:** `/research` — STOPS at PLAN-READY/PLAN-KILL. No code, no PR, no production-source edits.
- **Reviewers required to converge:** Codex (hostile) + AGY (adversarial) + Claude SMR (hostile). 3-way.

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

**Non-goals:**
- Do **not** change the `ForceRGMaster` (`force=true`) path — cluster-
  authoritative promotion must stay unconditional and immediate.
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
   (guarded by `vi.mu`). Set them in `handleBackupRx` (and `handleMasterRx`)
   for every non-zero-priority advert received from a peer:
   `lastMasterPriority = int(pkt.Priority); lastMasterSeen = now`.
   (Priority-0 adverts are resignation — do not record as a "master".)
2. In the `preemptNowCh` case, when `force==false`, gate on:
   ```
   if vi.shouldPreemptObservedMaster() {
       vi.becomeMaster() ...
   }
   ```
   where `shouldPreemptObservedMaster()` returns true iff:
   - `getPreempt()` is true, AND
   - we have **not** recently observed a peer master (`lastMasterSeen` is zero
     or older than `masterDownInterval()`) — meaning there is no live master to
     respect, so becoming MASTER is correct (this preserves the
     no-peer / cold-start case where becoming master IS the right move), OR
   - we **have** observed a recent master AND `getPriority() > lastMasterPriority`
     (strict `>`, RFC 5798 preemption), OR equal priority with the
     IP-address tie-break favoring us (reuse the `handleMasterRx` tie-break so
     behavior is symmetric).
   - `force==true` always wins (ForceRGMaster path unchanged).
3. If the gate denies preemption, do **not** `becomeMaster()`. Leave the node
   in BACKUP with its masterDown timer running. The normal RFC election then
   governs: if the peer master later disappears, masterDown expiry promotes us
   correctly; if a legitimately-higher local priority later applies (cluster
   promotes us to Primary → `UpdateRGPriority(rg,200)` + `ForceRGMaster` with
   `force=true`), that path still works.

**Why strict `>` (not `>=`):** RFC 5798 §6.1 preemption is "higher priority".
Equal-priority is resolved by the address tie-break, which we reuse so the
sync-hold path matches steady-state `handleMasterRx`. Using `>=` would let a
priority-100 Secondary preempt a priority-100… (not possible here since RETH is
200/100) but would also let an equal-priority node with a *lower* IP wrongly
preempt — incorrect.

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
   lastMasterPriority int       // last non-zero peer advert priority (guarded by mu)
   lastMasterSeen     time.Time // when lastMasterPriority was recorded (guarded by mu)
   ```
2. **`handleBackupRx` + `handleMasterRx`:** on any received advert with
   `pkt.Priority != 0`, record `lastMasterPriority`/`lastMasterSeen` under
   `vi.mu`. (Place the record before the existing branch logic so it always
   runs.)
3. **New helper `shouldPreemptObservedMaster() bool`** implementing the gate in
   §4 Path A step 2 (preempt configured + (no live master OR strictly-higher
   effective priority OR equal-with-IP-tiebreak)). Reuse the IP tie-break
   already in `handleMasterRx` (extract a small `peerIPWins(srcIP) bool` helper
   to avoid duplicating the v4/v6 compare).
4. **`run()` `preemptNowCh` case:** replace `if vi.getPreempt() || force` with
   `if force || vi.shouldPreemptObservedMaster()`. (force short-circuits;
   ForceRGMaster path unchanged. `shouldPreemptObservedMaster` already requires
   `getPreempt()`.)
5. **`pkg/vrrp/README.md`:** document the sync-hold preempt gate under the
   Behavior / Sync-hold section — a lower-priority preempt-enabled node no
   longer transiently becomes MASTER on sync-hold release; it defers to the
   observed higher-priority master and follows the normal RFC election.

No changes to `manager.go` trigger logic (it still calls `restorePreempt` +
`triggerPreemptNow` for all instances; the gate lives in the consumer so both
the sync-hold and any future trigger benefit).

---

## 6. Correctness arguments / invariants

- **Legitimate higher-priority preempt still instant.** Node with priority 200
  observing a master at 100 (or no master): `getPriority(200) >
  lastMasterPriority(100)` → gate passes → immediate becomeMaster. No timing
  regression.
- **Illegitimate lower-priority preempt blocked.** Node at 100 observing a live
  master at 200: `100 > 200` false, not stale → gate denies → stays BACKUP.
  Bug fixed.
- **Cold start / no peer.** `lastMasterSeen` zero or stale (> masterDownInterval)
  → gate treats as "no live master" → becomeMaster allowed. A genuinely-alone
  node on sync-hold release still takes over (no deadlock).
- **ForceRGMaster unaffected.** `force==true` short-circuits the gate.
- **Equal priority.** Resolved by the same IP tie-break as `handleMasterRx` →
  symmetric, RFC 5798 §6.4.3 consistent. (RETH is 200/100 so equal does not
  occur there; matters for standalone instances sharing the run loop.)
- **Owner-255 / track demotion.** The gate compares `getPriority()` (effective,
  track-clamped, owner-exempt) — not raw `cfg.Priority` — so a track-demoted
  node correctly fails the gate, and an owner-255 node correctly wins. Reuses
  existing `getPriority()` semantics; no new clamp logic.
- **Staleness threshold = masterDownInterval.** Same horizon the RFC uses to
  declare the master dead; consistent with `handleBackupRx` timer semantics.

---

## 7. Test plan

**Unit (`pkg/vrrp/vrrp_test.go`), new tests:**

1. `TestPreemptNow_LowerPriorityDefersToObservedMaster`: instance priority 100,
   preempt=true, record `lastMasterPriority=200`/`lastMasterSeen=now`, fire the
   preempt gate path → assert state stays BACKUP (no becomeMaster). Drive via a
   testable seam — either call `shouldPreemptObservedMaster()` directly
   (preferred, no socket) or exercise the run loop with a stubbed socket.
2. `TestPreemptNow_HigherPriorityPreemptsObservedMaster`: priority 200,
   observed master 100 → gate true.
3. `TestPreemptNow_NoObservedMasterAllowsTakeover`: `lastMasterSeen` zero →
   gate true (cold-start).
4. `TestPreemptNow_StaleMasterAllowsTakeover`: `lastMasterSeen` older than
   masterDownInterval → gate true.
5. `TestPreemptNow_ForceBypassesGate`: priority 100, observed master 200,
   `force=true` → becomeMaster (ForceRGMaster path).
6. `TestPreemptNow_EqualPriorityIPTiebreak`: equal priority, our IP higher →
   gate true; peer IP higher → gate false.
7. `TestHandleBackupRx_RecordsMasterPriority`: feed an advert, assert
   `lastMasterPriority`/`lastMasterSeen` updated; priority-0 advert does NOT
   update them.

**The test must FAIL on the unpatched code** (per the project's "durability/
side-effect tests must fail if the effect is removed" discipline): test #1
against today's `if vi.getPreempt() || force` would (incorrectly) becomeMaster
— so it is a true regression guard.

**Integration / failover (required at `/engineer` time — this is failover-class
HA code):**
- `make test-failover` on the loss userspace cluster
  (`loss:xpf-userspace-fw0/fw1`) — must pass (zero-drop, e.g. 14/0). Touches
  VRRP preempt/become-master → mandatory per CLAUDE.md ("Any change touching
  cluster, VRRP, session sync, or failover code MUST pass `make test-failover`
  before commit").
- **Precondition check:** confirm whether the loss cluster RG config sets
  `preempt` (if not, the bug path isn't exercised by default — add a transient
  preempt-enabled config variant for the targeted repro, or assert via logs
  that the Secondary no longer logs `transitioning to MASTER` on sync-hold
  release). The smoke must demonstrate the Secondary does NOT flap to MASTER on
  rejoin/sync-complete while the Primary holds the VIP.
- `go test ./pkg/vrrp/ -race` and `go build ./...`.

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
2. **Recording `lastMasterPriority` on every advert** is in the RX hot path
   (`handleBackupRx`), but it is a single guarded int+time write per received
   advert (30 ms cadence) — negligible. Confirm no lock-ordering issue
   (`vi.mu` already taken/released in these handlers via `getPriority`).
3. **Standalone (non-cluster) VRRP** shares the run loop. Path A is correct for
   it (it just records peer priority and gates), but standalone instances are
   not under sync-hold, so the gate's only effect there is on a future
   `triggerPreemptNow` caller — currently none besides ForceRGMaster (cluster).
   No behavior change for standalone today; future-proof.
4. **Concurrency:** `shouldPreemptObservedMaster()` reads `lastMaster*` under
   `vi.mu`; the run-loop goroutine is the only writer of state transitions, the
   receiver goroutine writes `lastMaster*` — both under `vi.mu`. Verify no
   deadlock with the existing `getPreempt()`/`getPriority()` RLock usage (the
   helper must take the lock once, not call `getPriority()` while already
   holding it).
5. **`make test-failover` may not exercise the bug** without a preempt-enabled
   RG — see §7. The smoke could be green while the fix is untested at the
   integration level. Must add a targeted repro or log-assertion.

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

## 11. Verdict ledger (filled during review)

- Codex r?: _pending_
- AGY r?: _pending_
- Claude SMR r?: _pending_

**Current status: PLAN-READY candidate, pending 3-way convergence.**
**Reachability: CONFIRMED REACHABLE (not PLAN-KILL).**
