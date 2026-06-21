# Plan of Action — #2120: standby silently expires long-lived synced sessions

- **Issue:** #2120 (HIGH, `audit`/`bug`, 3/3 adversarial-skeptic verified)
- **Class:** FAILOVER-class regression (reintroduces #131)
- **Revision:** r3 (single coherent design; folds both r2 + r3 hostile reviewers)
- **Research branch:** `research/2120-standby-wheel-expiry`
- **Base:** origin/master @ 325d10683
- **Status:** **PLAN-READY** — 3-way converged (Claude SMR PLAN-READY + 2 hostile
  Claude plan-reviewers). R3-B's lone BLOCKER (first_held_ns clear-list
  contradiction) was ALREADY fixed in the committed plan (it reviewed a
  pre-tightening read); all r3 NITs (ABS-cap magnitude, MAX_RG_EPOCHS visibility,
  ha_runtime deref, epoch-bump de-dup, ==0 residual counter) folded.

## Changelog
- **r3:** ONE coherent Option-B design replacing all r2/r2.1 menus (deletes the
  stale option-(iii)/fixed-ceiling text both r2 reviewers flagged as an internal
  contradiction). (a) HOLD keys on `!forwards_here` (forwarding, not origin) so
  the demotion-window ForwardFlow entry is held by one branch — no missing
  "ownership branch" (B2#1/A2#2). (b) Node-level epoch at `rg_epochs[0]` lets the
  self-heal fire for `owner_rg_id==0` fabric/reverse entries (B2#2). (c) Epoch
  bump moved BEFORE `rg_runtime.store` (MANDATORY) → airtight self-heal edge
  (A2#3). (d) Ceiling = `min(MULT×timeout, ABS_CAP)` from `first_held_ns` →
  flapping-safe (B2#4) + bounded 30-day worst case (B2#5). (e) `==0` active/active
  residual documented + accepted (A2#4). Adds `seen_rg_epoch:u32` +
  `first_held_ns:u64` to `SessionEntry`.
- **r2.1:** self-heal EDGE-triggered via `rg_epochs`; ceiling RELATIVE.
- **r2:** (a) Gate keys on **RG ownership** (`owner_rg_id` not locally
  forwarding-active), NOT on `is_peer_synced()` origin — this exactly mirrors
  the eBPF GC `if isPrimary { age }` contract and also covers a *demoted*
  node's formerly-local sessions (SMR M2). (b) Add a **promotion-transition
  self-heal**: on the expire pass, a held entry whose RG just became active is
  re-stamped (Case-4) rather than expired, closing the store→RefreshOwnerRGS
  race (SMR M1). (c) Explicitly **exclude `fabric_ingress`** sessions from the
  hold (age normally — matches the existing fabric-skip convention at
  ha.rs:501). (d) Make the held/expired observability counter MANDATORY.

---

## 1. Problem statement

In HA chassis-cluster mode with the userspace AF_XDP dataplane, the **STANDBY**
node silently expires long-lived peer-synced sessions whose idle timeout
(default 300 s TCP, 60 s UDP/ICMP) elapses with no local refresh. On failover
the newly-promoted primary has no conntrack/session match for that flow, so its
return traffic is re-evaluated as a brand-new connection and dropped. This is
exactly the #131 symptom ("iperf3 streams die on first failover"),
reintroduced by the eBPF→userspace migration.

The common cases that `make test-failover` exercises — short flows, or flows
with continuous bidirectional traffic that fail over within the idle window —
are unaffected, which is why the regression went unnoticed.

---

## 2. Root-cause chain (verified against origin/master @ 325d10683)

The regression is the interaction of three independently-correct facts:

1. **The Go GC is `SkipSweep`'d in userspace mode.**
   `pkg/daemon/daemon_run.go:741-743`:
   ```go
   if _, ok := d.dp.(userspaceSessionDeltaDrainer); ok {
       gc.SkipSweep = func() bool { return true }
   }
   ```
   The Go conntrack GC's expiry loop never runs in userspace mode (it would
   burn ~19% CPU scanning maps not used for forwarding). Its
   `gc.IsLocalPrimary = d.cluster.IsLocalPrimaryAny` gate
   (`daemon_run.go:748`) — the mechanism that, in the eBPF era, prevented the
   standby from aging synced sessions — is therefore **dead code** for
   userspace expiry.

2. **Expiry is now owned by the Rust per-worker timer wheel, which has NO
   standby/RG-active gate.** `userspace-dp/src/afxdp/worker/loop_body/mod.rs:573`
   calls `sessions.expire_stale_entries(loop_now_ns)` on EVERY worker poll
   cycle, unconditionally. In `userspace-dp/src/session/expire.rs:134-135`,
   once a session crosses its idle timeout it is `remove_entry`'d
   **unconditionally**. The `is_peer_synced()` check at expire.rs:155-157 only
   suppresses the outbound **Close delta** — it does NOT exempt the synced
   session from removal. Synced TCP sessions are imported with `tcp_flags: 0`
   (`userspace-dp/src/server/helpers.rs:349`), so
   `session_timeout_ns(PROTO_TCP, 0, …)` resolves to the 300 s established-TCP
   default. The standby passes no transit traffic for an inactive RG, so
   nothing ever refreshes `last_seen_ns` and the wheel reaps the entry at
   ~300 s. The same loop also deletes the BPF session-map redirect + conntrack
   entries (`delete_session_map_entry_for_removed_session_with_origin`,
   loop_body/mod.rs:583).

3. **The primary stopped re-syncing established flows.** Commit `391ea5a14`
   (#270) removed the `|| val.LastSeen >= threshold` activity term from the
   incremental sweep, leaving only `val.Created >= threshold`. **History note
   (corrected r2):** at `391ea5a14` the change was in `pkg/cluster/sync.go`
   (lines ~755/770 of that revision); `sync_conn.go` did not yet exist — the
   sweep was relocated to `sync_conn.go:403/421` later by refactor `0dc166c7b`
   ("split cluster sync helpers"), which carried the already-narrowed predicate.
   The current-code citation (`sync_conn.go:403` and `:421`) is correct;
   `391ea5a14` is the commit that narrowed it. `Created` is the immutable
   session-creation timestamp, so a flow created before the threshold is swept
   exactly once and never re-synced. #270's stated rationale — "Established
   flows whose LastSeen moved do not need re-syncing — the peer already has
   them from the original create" — was correct **only** while fact #1's
   `IsLocalPrimary` gate kept the standby from aging synced sessions. The
   userspace migration invalidated that invariant; #270 was never revisited.

The original #131 fix (`b35bb4562`, "sync established session state on periodic
sweep") added the exact `|| val.LastSeen >= threshold` clause that #270 later
removed, and also removed an older single-`GLOBAL_CTR_SESSIONS_NEW` fast-path
skip "since it only tracked new session creation, not ongoing activity."
**History note (corrected r2):** the *current* two-counter (`NEW`+`CLOSED`)
`lastSweepEmpty` fast-path (`sync_conn.go:382-389/446-453`) was NOT reinstated
by #270 — `git show 391ea5a14` does not touch `lastSweepEmpty`. It was added
later by `62e3a9026` ("perf: adaptive sync sweep interval to reduce idle CPU")
and relocated by `0dc166c7b`. Option A's reasoning that this fast-path defeats a
LastSeen re-sync remains valid against *current* code; only the historical
attribution is corrected.

### Verified supporting facts

- **The primary's delete path is alive and independent of the Go GC.** When
  the primary's wheel expires a *locally-owned* session it emits a Close delta
  (expire.rs:159) → event stream / `DrainSessionDeltas` →
  `queueUserspaceSessionDeltas` (daemon_ha_userspace.go:765-793) →
  `QueueDeleteV4/V6` to the peer. So a session that genuinely ends on the
  primary IS reaped on the standby via a primary-driven DeleteSynced. The
  standby does not depend on its own idle timer to clean up synced sessions.
- **On promotion, owned synced sessions get a fresh `last_seen_ns`.** RG
  activation enqueues `WorkerCommand::RefreshOwnerRGS` (ha.rs:114) →
  `handle_refresh_owner_rgs` (refresh_owner_rgs.rs) →
  `refresh_for_ha_transition` which sets `record.entry.last_seen_ns = now_ns`
  (session/mod.rs:601) and re-arms the wheel (`push_to_wheel`, mod.rs:605).
  So a synced session held on the standby is re-stamped with a full timeout at
  the instant of promotion and ages normally thereafter.
- **The standby's import refreshes `last_seen` on a re-synced Open.** Sync
  messages install via `WorkerCommand::UpsertSynced` →
  `upsert_synced_with_origin` (session/install.rs), which does
  `remove_entry(&key)` + reinsert with `last_seen_ns = now_ns`. A re-imported
  synced entry therefore gets a fresh timeout. (NB: `update_session` REJECTS
  peer-synced re-imports — install.rs:215 path — but the sync path is
  `upsert_synced_with_origin`, not `update_session`, so Option A's re-sync
  does land.)
- **The worker already has the RG-active state in scope at the expire call
  site.** `loop_body/mod.rs:491` loads
  `ha_runtime: BTreeMap<i32, HAGroupRuntime>` from the `ha_state` ArcSwap
  (lock-free, L1-hot, the same snapshot used by `poll_binding`). The expire
  call at line 573 is in the same scope. `HAGroupRuntime::is_forwarding_active(now_secs)`
  (types/runtime.rs:233 — `self.active && self.lease.active(now_secs)`) is the
  canonical RG-forwarding predicate already used by the fabric-redirect path
  (shared_ops.rs:692). `SessionMetadata.owner_rg_id` (entry.rs:27) is carried
  on every entry.

---

## 3. Blast radius

| Area | Option A | Option B (recommended, r2) |
|------|----------|----------|
| `pkg/cluster/sync_conn.go` (sweep) | 2 predicates + fast-path correction | unchanged |
| `userspace-dp/src/session/expire.rs` | unchanged | hybrid gate + self-heal + ceiling reaper (~30-40 lines) |
| `userspace-dp/src/afxdp/worker/loop_body/mod.rs` | unchanged | pass `ha_runtime` + `now_secs` into expire |
| `userspace-dp/src/session/mod.rs` (`WheelPopStats`) | unchanged | `held_standby` + `reaped_stale_synced` counters |
| `userspace-dp/src/afxdp/ha.rs` (coordinator ordering) | unchanged | OPTIONAL belt (enqueue cmd before store) |
| Wire format | unchanged | unchanged |
| Go tests | sync_test.go | sync_test.go regression-guard (sweep untouched) |
| Rust tests | none | session/tests.rs + ha_tests.rs (incl. race + ceiling) |

Both options are small in LOC. The risk is in correctness of the HA contract,
not LOC. B's r2 scope grew from r1 (self-heal + ceiling) to close the
promotion/demotion race and bound the lost-delete leak — still ~1 file of
real logic plus tests.

---

## 4. Multiple Path Options

### Option A — restore established-flow re-sync (control-plane / "republish")

Re-add the activity term in `syncSweep`:

```go
if (val.Created >= threshold || val.LastSeen >= threshold) && s.ShouldSyncZone(val.IngressZone) {
```

at sync_conn.go:403 and :421, and **delete (or correct) the `lastSweepEmpty`
NEW/CLOSED-counter fast-path** at sync_conn.go:382-389 (and the counter
re-cache at :446-453), because those counters track only create/close events,
not ongoing activity — a re-sync sweep gated on them still skips active
established flows (this is exactly what #131's `b35bb45` removed and #270
re-added).

**How it fixes the bug:** every established flow with primary-side activity is
re-published every sweep. The standby's `upsert_synced_with_origin` removes and
reinserts the entry with `last_seen_ns = now_ns`, so the wheel's idle clock is
continuously reset and the entry never reaches 300 s idle. On failover the
standby still has the (recently-refreshed) session.

**Correctness:**
- Covers the regression's scenario (a flow "alive on the primary" — i.e. the
  primary forwards it, advancing `LastSeen`).
- A flow that is genuinely idle on *both* nodes (>300 s with zero packets)
  expires on the primary too — correct behavior; no false retention.
- This is the literal pre-#270 (== #131) behavior; the receiver already
  overwrites, so no wire change.

**Cost / downside:**
- **Sweep never backs off.** `runSweep` doubles the interval up to 10 s only
  while sweeps come back empty (sync_conn.go:316-320). With the LastSeen term,
  any cluster carrying established flows sweeps **all** of them every 1 s,
  forever, and the empty-sweep fast-path is dead. This is precisely the
  send-queue pressure / WaitForIdle-convergence cost #270 set out to remove.
  Under a large established-flow table this re-introduces per-second bulk
  serialization + control-socket traffic (CLAUDE.md flags >1/s control-socket
  callers as a session-install starvation risk).
- Re-sync granularity is the 1 s sweep, well under 300 s, so it is safe with
  generous margin — but it pays the full table cost every second to defend a
  300 s deadline.
- Does **not** fix the root invariant: the standby's wheel still has no notion
  of "I am not the owner; I must not age this." A future change that throttles
  or coalesces the sweep would silently re-break failover.

### Option B — hold sessions this node does not forward (root-invariant) [RECOMMENDED]

**One design (r3 — supersedes all r2/r2.1 menus).** In `expire.rs`, before the
`remove_entry` in the Case-3 arm, decide HOLD / SELF-HEAL / AGE:

```rust
// loop_body/mod.rs (ha_runtime :491, loop_now_secs :297, rg_epochs :63 — all in scope)
let expired_entries = sessions.expire_stale_entries(
    loop_now_ns, loop_now_secs, ha_runtime.as_ref(), &rg_epochs);
```
```rust
// expire.rs, Case-3 arm, `entry` = just-read immutable borrow.
// rg_active(rg): rg>0 && (rg as usize)<MAX_RG_EPOCHS
//                && ha_state.get(&rg).map(|r| r.is_forwarding_active(now_secs)).unwrap_or(false)
// epoch_of(rg):  if rg>0 && (rg as usize)<MAX_RG_EPOCHS { rg_epochs[rg].load(Relaxed) }
//                else { rg_epochs[0].load(Relaxed) }   // RG 0 = node-level epoch (see below)
let rg            = entry.metadata.owner_rg_id;
let peer_synced   = entry.origin.is_peer_synced();
let node_active   = rg_active_any(ha_state, now_secs);          // hoisted once per call
let forwards_here = if rg > 0 { rg_active(ha_state, rg, now_secs) } else { node_active };

// (1) SELF-HEAL EDGE — fires once when this node STARTS forwarding the session
//     but the entry's epoch predates the activation (RefreshOwnerRGS may not
//     have landed). Re-stamp ONCE; subsequent expires see matching epochs -> AGE.
if peer_synced && forwards_here && epoch_of(rg) != entry.seen_rg_epoch {
    re_stamp(last_seen = now_ns);
    entry.seen_rg_epoch = epoch_of(rg);
    re_bucket_as_case4();
    self.last_pop_stats.healed_on_promote += 1;
    continue;
}
// (2) HOLD — this node does not forward the session (standby / demotion window).
//     Keyed on FORWARDING, not origin, so a still-ForwardFlow demotion-window
//     entry is also held until the epoch flip self-heals or the peer takes over.
if !forwards_here && (peer_synced || node_active) {   // node_active guard = "in a cluster"
    let held_ns = now_ns.saturating_sub(entry.first_held_ns_or(last_seen_ns));
    if held_ns > stale_ceiling_ns(entry.expires_after_ns) {   // bounded leak reaper
        self.last_pop_stats.reaped_stale_synced += 1;
        // fall through to remove_entry
    } else {
        if entry.first_held_ns == 0 { entry.first_held_ns = now_ns; } // flapping-safe clock
        entry.seen_rg_epoch = epoch_of(rg);   // arm the self-heal edge for next promote
        re_bucket_as_case4();
        self.last_pop_stats.held_standby += 1;
        continue;
    }
}
// (3) AGE — normal remove_entry path (active-node owned, or standalone).
```

**Key r3 decisions (each closes a specific r2 reviewer finding):**

1. **HOLD keys on FORWARDING, not origin (closes A2#2 / B2#1 demotion race).**
   The hold fires whenever `!forwards_here` — so a demotion-window entry that is
   still `ForwardFlow` (the `demote_owner_rg` flip install.rs:304-306 not yet
   applied) IS held because its RG is already inactive. No separate "ownership
   branch" is missing now; there is one branch and it is ownership-keyed. The
   `(peer_synced || node_active)` guard prevents a STANDALONE node (empty
   `ha_state` → `node_active` false, sessions `owner_rg_id==0` + non-peer-synced)
   from ever holding — only a real cluster node (has active RGs, i.e. `node_active`,
   or holds peer-synced copies) retains. **Counter-decision to A2's "just age the
   demoting node's copy":** we HOLD it instead (multi-RG standby), because holding
   is strictly safer for the failback leg and the ceiling bounds it; aging relies
   on the peer already having the copy, which couples failback to sync
   completeness. **Single-RG sub-case (intentional AGE):** in a single-RG cluster,
   demoting RG1 makes `node_active` false, so a still-`ForwardFlow` entry in the
   ~1-poll pre-`DemoteOwnerRGS`-flip window has `(peer_synced||node_active)==false`
   → AGED. NOT a failover hole: the demoting node is becoming standby, the PEER
   (new primary) already holds the synced copy, and once the flip lands the entry
   is held via `peer_synced`. Aging this node's redundant pre-flip copy loses
   nothing the cluster needs.

2. **`owner_rg_id==0` uses a NODE-LEVEL epoch at `rg_epochs[0]` (closes B2#2).**
   `rg_epochs[0]` is currently unused (all bumps + the flow-cache consumer guard
   `idx>0`, ha.rs:74/101, flow_cache.rs:98). r3 bumps `rg_epochs[0]` on ANY RG
   activation (a node-level "started forwarding something" edge) so the self-heal
   can fire for `owner_rg_id==0` fabric/reverse entries too. For the `==0` HOLD,
   `forwards_here == node_active`, so a `==0` entry is held iff the node forwards
   NOTHING. **Active/active caveat (A2#4):** on a node with RG1 active + RG2
   standby, a `==0` peer-synced entry belonging to the RG2 path is AGED
   (`node_active` true). This is the one residual under-retention; r3's position
   is that `owner_rg_id==0` entries are rare (fabric/reverse with unresolved
   owner) and the failover path normally re-derives them on promotion via
   `prewarm_reverse_synced_sessions_for_owner_rgs` (ha.rs:125). If reviewers want
   zero `==0` loss in active/active, the fix is to resolve the entry's real RG at
   import so `owner_rg_id>0` (out of scope here) — tracked as a follow-up, NOT a
   blocker for the dominant `owner_rg_id>0` regression this issue is about.

3. **SELF-HEAL is EDGE-triggered via `rg_epochs`, bumped BEFORE the store
   (closes A2#1 over-retention + A2#3 residual race).** The level-triggered
   "option (iii)" and the lease-derived "(i)" are BOTH deleted — (i) is broken
   (lease slides every `update_ha_state`, ha.rs:9-24); (iii) re-stamps an idle
   promoted entry forever. Only the epoch edge is correct. **r3 also moves the
   `rg_epochs` bump for activated RGs to BEFORE `rg_runtime.store`** in
   `update_ha_state` (today: store ha.rs:39, bump ha.rs:101 — reordered so any
   worker observing the active `rg_runtime` also observes the bumped epoch via
   the ArcSwap publish/acquire). This makes the edge airtight: a worker either
   sees old-rg+old-epoch (HOLD branch) or new-rg+new-epoch (SELF-HEAL branch) —
   never new-rg+old-epoch (the AGE-the-held-entry hole). Bump uses Release; the
   worker loads `rg_runtime` (ArcSwap acquire) then `rg_epochs` (Relaxed) — the
   ArcSwap publish orders the prior epoch Release before the worker's rg_runtime
   acquire.

4. **Ceiling: RELATIVE + ABSOLUTE-CAPPED + measured from `first_held_ns`
   (closes B2#4 flapping + B2#5 90-day).** `stale_ceiling_ns(t) =
   min(STALE_SYNCED_CEILING_MULT * t, STALE_SYNCED_CEILING_ABS_NS)` with the
   hold duration measured from **`first_held_ns`** (when the entry FIRST entered
   the held state), NOT `last_seen`.
   - **`first_held_ns` lifecycle (CRITICAL — the crux of B2#4):** set on the
     first HOLD observation (when it is 0); cleared (→0) ONLY when the entry
     genuinely leaves the held world — i.e. on a real-traffic refresh
     (`update_session`, mod.rs:449), a promotion refresh
     (`refresh_for_ha_transition`, mod.rs:601), or a re-import
     (`upsert_synced`, install.rs). The **self-heal re-stamp does NOT clear
     `first_held_ns`** — otherwise a flapping RG (self-heal on every activate
     edge) would reset the ceiling clock and the leak bound would be defeated
     (the exact B2#4 failure). So a dead, leaked, flapping entry keeps its
     original `first_held_ns` and is reaped at the ceiling.
   - **ABS cap floor (NIT — pin in r3-final):** the cap must be ≥ the largest
     idle window a legitimate failover could need on the standby. A configured
     30-day `inactivity-timeout` keeps a flow alive 30 days on the primary; if
     that flow idles on the wire beyond the cap and fails over, the standby must
     still have it. So set `STALE_SYNCED_CEILING_ABS_NS` generously (e.g. 7 days,
     not 24 h) — large enough to cover realistic long-idle deployments, small
     enough to bound the pathological `MaxDurationSeconds` config. The cap is
     SAFE at any value ≥ the real failover window because a held entry is by
     definition NOT forwarding here — the cap reaps only standby state, never a
     live LOCAL flow (unlike the rejected fixed-ceiling-for-all-sessions). Final
     magnitude is an Open Question.

5. **Per-RG refinement, not faithful restoration (A#3 honest framing).** The old
   Go-GC `IsLocalPrimaryAny` gate (gc.go:249/277) was node-global; this is a
   per-RG refinement (better for active/active). Stated as such.

This is a **per-RG-ownership** gate with an edge-triggered self-heal and a
flapping-safe, absolutely-bounded ceiling. It threads `ha_state`, `now_secs`,
and `&rg_epochs` into `expire_stale_entries`, and adds `seen_rg_epoch: u32` +
`first_held_ns: u64` to `SessionEntry` (write sites enumerated in §6).

**Correctness:**
- Uses `is_forwarding_active(now_secs)` (active bool AND live watchdog lease),
  the same predicate fabric-redirect already trusts. The lease is set fresh and
  atomically with `active` at promotion (runtime.rs:222-234; ha.rs:12-24,39), so
  there is NO "becoming-primary-but-lease-not-set" drop window — staleness fails
  CLOSED (a node that lost cluster state reads inactive → holds, never wrongly
  ages; and never wrongly retains forwarding because forwarding itself is gated
  on the same predicate elsewhere). The only promotion/demotion window is the
  command-apply gap, addressed above.
- Re-bucketing keeps the entry observable each interval. **Correction (reviewer
  A#1/B#2): re-bucketing does NOT re-stamp `last_seen`.** Retention-through-
  promotion depends on the self-heal re-stamp (above) OR on RefreshOwnerRGS
  landing before the next expire. Do not claim re-bucket alone is sufficient.
- This is NOT a byte-faithful restoration of the node-global Go-GC
  `IsLocalPrimaryAny` gate (reviewer A#3) — it is a **per-RG refinement** of it
  (better for active/active, where one RG can be active and another standby on
  the same node). State this honestly; the divergence is intentional and an
  improvement, not an accident.
- No new control-socket or sync traffic; the 1 s sweep keeps its empty-sweep
  back-off (#270's perf win preserved).

**Cost / downside:**
- **Standby memory.** Held sessions occupy the standby's table until a primary
  delete, promotion, or the stale-synced ceiling (below). Bounded by the
  primary's live session count (already fully replicated). The wheel is
  O(due bucket), so re-bucketing held entries is cheap.
- **Leak risk if a primary delete is lost — REQUIRES A HARD CEILING (r2,
  reviewer B#1).** The earlier "bulk re-sync on reconnect reconciles" mitigation
  is **FALSE**: `handleNewConnection` only bulk-syncs on `coldStart`
  (`!bulkEverCompleted`, sync_conn.go:197-209); a WARM reconnect skips bulk sync
  and `reconcileStaleSessions` is guarded by `bulkInProgress`. The only
  reconnect backstop is the `deleteJournal`, which is **bounded and lossy**
  (evicts oldest + increments `DeletesDropped`, sync_conn.go:541-543). Also a
  primary Close can be filtered if `shouldSyncUserspaceDelta` finds the node
  not-primary-for-RG at close time (daemon_ha_userspace.go:357-393, reviewer
  A#8). Therefore: under B, a held synced session whose Close delta is lost AND
  whose journal entry is evicted is held **indefinitely** (until promotion or
  cold-start). **The stale-synced ceiling is NON-optional** and (r3) is
  `min(MULT × entry.expires_after_ns, ABS_CAP)` measured from `first_held_ns`
  (flapping-safe), applied to held entries — so a leaked entry is reaped without
  a primary delete, bounded even for 30-day-timeout configs (B2#5), and not
  resettable by self-heal re-stamps on a flapping RG (B2#4). Safe because a held
  entry is by definition not forwarding here (the cap never reaps a live local
  flow).
  - Note (reviewer B): Option A does NOT have this leak — A ages all synced
    sessions, so a lost delete self-heals at the normal timeout. This is a
    genuine robustness edge for A; the r3 ceiling restores the same self-heal
    property for B at a longer, failover-safe deadline.
- Threads `now_secs`, `ha_state`, `&rg_epochs` through `expire_stale_entries`
  and its callers/tests; adds `seen_rg_epoch` + `first_held_ns` to SessionEntry.

### Option A+B note
A and B are not mutually exclusive, but combining them is redundant: B alone
fully fixes the regression at lower steady-state cost, and A's re-sync becomes
unnecessary for *retention* (it would still re-sync state drift, but the
standby already gets state via the create + the wheel never reaps it). Shipping
both pays A's per-second cost for no retention benefit.

---

## 5. Recommendation — **Option B + mandatory stale-synced ceiling**

B (per-RG wheel ownership gate) **plus a non-optional stale-synced ceiling** is
recommended, for four reasons — stated honestly against A's one genuine edge:

1. **It fixes the root invariant in the layer that owns expiry.** The bug is
   "a node ages sessions it does not forward." #270's rationale was *predicated*
   on the standby never aging synced sessions. B re-establishes a (per-RG
   refinement of) that contract in the Rust wheel, so #270's intent becomes
   true again. A only patches the symptom (re-feed the standby fast enough to
   outrun an expiry that should not apply).
2. **It preserves #270's performance win and avoids control-socket
   starvation.** A keeps `synced>0` every sweep → `interval` pinned at 1 s
   forever, the empty-sweep fast-path dead, and the ENTIRE active-flow table
   re-installed on the peer's **control socket** every second
   (`PutClusterSyncedV4` → `SetClusterSyncedSessionV4`) — exactly the >1/s
   control-socket contention CLAUDE.md warns starves session installs. B adds
   zero steady-state sync/control-socket traffic.
3. **It fails closed under watchdog staleness.** B's `is_forwarding_active`
   reads inactive when the lease is stale → holds, never wrongly ages. The lease
   is atomic with `active` at promotion (no lease-gap window).
4. **It is robust to future sweep changes.** Retention no longer depends on
   sweep cadence, so a later sweep throttle cannot silently re-break failover.

**A's one genuine edge (acknowledged, not papered over):** A ages all synced
sessions, so a *lost* primary Close delta self-heals at the normal timeout. B
holds a leaked entry until promotion/cold-start UNLESS bounded. This is why the
**stale-synced ceiling is NON-optional in the recommendation** — it restores
the lost-delete self-heal property (at a much longer, failover-safe deadline)
without paying A's per-second cost. With the ceiling, B dominates A on every
axis.

**Why not A as the ship:** A is simpler (Go-only, no Rust HA threading) and
self-heals lost deletes, but it permanently defeats the empty-sweep back-off and
hammers the control socket at the active-flow rate. If reviewers reject B's Rust
threading, the documented fallback is **A with the `lastSweepEmpty` two-counter
fast-path corrected** (the counters track create/close, not activity, so they
must not short-circuit a LastSeen-based sweep). The plan's position is B+ceiling.

**Not reverting #270.** #270 also did #269 (journal kernel SESSION_OPEN during
demotion). That is orthogonal and stays. We re-establish the invariant #270
assumed, we do not revert it.

---

## 6. Detailed implementation plan (Option B)

1. **expire.rs**: change `expire_stale_entries(&mut self, now_ns)` to
   `expire_stale_entries(&mut self, now_ns, now_secs, ha_state: &BTreeMap<i32,HAGroupRuntime>, rg_epochs: &[AtomicU32; MAX_RG_EPOCHS])`.
   Implement the §4 three-way SELF-HEAL / HOLD / AGE decision before
   `remove_entry`. Hoist `node_active = rg_active_any(...)` once per call. Use the
   `<MAX_RG_EPOCHS` (16) guard + `else rg_epochs[0]` exactly as the flow-cache
   consumer (flow_cache.rs:98) for every `rg_epochs` index. Bump `held_standby` /
   `reaped_stale_synced` / `healed_on_promote`.
   - Keep `expire_stale`/test wrappers signature-compatible (empty map + zeroed
     epochs = standalone default).
   - **Standalone safety:** a standalone session is non-peer-synced + on a node
     with no active RG → `(peer_synced || node_active)` is false → never held.
     Explicit non-clustered test.
2. **loop_body/mod.rs:573**: pass `loop_now_secs`, `ha_runtime.as_ref()`,
   `&rg_epochs` (all in scope: :297, :491, :63).
3. **MANDATORY coordinator ordering (r3 — closes A2#3 residual race):** in
   `update_ha_state`, bump `rg_epochs` for activated RGs (and the node-level
   `rg_epochs[0]`) **BEFORE** `self.ha.rg_runtime.store(...)` (move the activated
   epoch fetch_add ahead of ha.rs:39, with the demote bumps too). This is NOT
   optional — it makes the self-heal edge airtight (a worker observing the active
   `rg_runtime` always observes the bumped epoch via the ArcSwap publish). Verify
   `handle_activated_rgs`/`handle_demote` still read a consistent `ha_state`.
4. **session/mod.rs**: add to `SessionEntry`: `seen_rg_epoch: u32` and
   `first_held_ns: u64`. Write-site contract:
   - install (install.rs:143, :229): `seen_rg_epoch = epoch_of(owner_rg)`,
     `first_held_ns = 0`.
   - `refresh_for_ha_transition` (mod.rs:601, promotion): re-snapshot
     `seen_rg_epoch`, clear `first_held_ns = 0`.
   - `update_session` (mod.rs:449, real-traffic / re-import refresh):
     re-snapshot `seen_rg_epoch`, clear `first_held_ns = 0`.
   - HOLD branch in expire: set `first_held_ns = now_ns` IFF currently 0; record
     `seen_rg_epoch = epoch_of(rg)`.
   - SELF-HEAL branch in expire: re-stamp `last_seen`, record `seen_rg_epoch`,
     **leave `first_held_ns` UNTOUCHED** (clearing it here re-opens B2#4).
   Add **mandatory** `held_standby`, `reaped_stale_synced`, `healed_on_promote`
   to `WheelPopStats`, surfaced as worker/Prometheus counters. **Also add
   `aged_owner_rg_zero_active_node`** (R3-B#5) so the known active/active `==0`
   under-retention residual is OBSERVABLE in the field, not a silent drop. State
   the
   `SessionEntry` size delta (verify with `size_of`, do not assume free padding).
5. **Ceiling** = `min(STALE_SYNCED_CEILING_MULT × entry.expires_after_ns,
   STALE_SYNCED_CEILING_ABS_NS)` (MULT≈3, ABS≈**7 days** per §4.4 — NOT 24 h: the
   cap must be ≥ the largest legitimate standby idle window so a long-idle
   `inactivity-timeout` flow is not reaped before failover), measured from
   `first_held_ns` (flapping-safe). RELATIVE because configured timeouts reach
   `MaxDurationSeconds` (schema_validators.go:132) so a fixed ceiling would reap
   live long-timeout sessions; ABS-capped to bound the pathological worst case;
   `first_held_ns`-based so self-heal re-stamps on a flapping RG cannot reset it.
   - **Impl note (R3 NITs):** derive the `rg_epochs` bound from the passed
     array's const-generic length (`rg_epochs.len()`), not a cross-module
     `flow_cache::MAX_RG_EPOCHS` (visibility); pass the HA map as the existing
     working form `ha_runtime.as_ref()` (match loop_body:508), not the pseudocode
     shorthand; REMOVE the now-duplicate epoch-bump loop from
     `handle_activated_rgs`/`handle_demote` when hoisting the bump before the
     store (avoid a double-increment).
6. **Docs**: update `userspace-dp/src/session/README.md` (expire.rs section),
   `docs/fabric-cross-chassis-fwd.md` / the HA session-sync doc with the per-RG
   standby-retention invariant + ceiling, and note in `pkg/cluster` docs that
   #270's sweep narrowing is intentional and retention is owned by the wheel.
7. **Do NOT** change `helpers.rs` `tcp_flags: 0` (the timeout is correct for an
   active owner; B simply stops a non-owner node from applying it).

---

## 7. Test plan

### Rust unit (session/tests.rs, ha_tests.rs)
- `expire_holds_peer_synced_when_rg_inactive`: SyncImport TCP, `owner_rg_id=1`,
  RG1 inactive; advance `>302 s`; assert retained, `held_standby` incremented
  (read from the SAME call that did work — `expire` resets `last_pop_stats` at
  the top each call, expire.rs:95), `expired==0`.
- `expire_ages_peer_synced_when_rg_active`: same but RG1 `is_forwarding_active`;
  assert removed at >302 s.
- `expire_ages_active_node_owned_session`: a `ForwardFlow` session `owner_rg_id=1`
  with RG1 **active** — must expire (this node forwards it). Guards over-retention.
- **Origin coverage:** repeat the hold test for ALL three `is_peer_synced`
  origins — `SyncImport`, `SharedMaterialize`, `WorkerLocalImport`
  (entry.rs:78-82) — identical behavior. (SharedPromote is set only on the active
  node, promote.rs:99-103 → ages; assert it is NOT held — resolves SMR M3.)
- **owner_rg_id==0:** `expire_holds_peer_synced_owner_rg_zero_whole_node_standby`
  (held: fabric/reverse SyncImport, `owner_rg_id=0`, zero active RGs) +
  `expire_ages_owner_rg_zero_on_active_node` (active/active RG1-active node ages
  it — documents the known active/active residual, A2#4).
- `expire_standalone_ages_normally`: empty `ha_state` + zeroed epochs,
  ForwardFlow, `owner_rg_id=0` → `(peer_synced||node_active)` false → ages.
- **Promotion race (closes A2#1/A2#3 — reproduce the store-before-epoch sub-window):**
  `expire_in_promotion_window_survives` — hold past deadline (RG inactive), then
  set `ha_state` RG-active AND bump `rg_epochs[rg]` (the r3 ordering: epoch
  bumped with/before the active state), WITHOUT applying RefreshOwnerRGS; call
  expire; assert SELF-HEAL re-stamped + survived. ALSO a negative:
  `expire_no_selfheal_when_epoch_unchanged` — RG active but epoch == seen_rg_epoch
  (already healed): the entry AGES (no perpetual re-stamp / over-retention).
- **owner_rg_id==0 promotion race (closes B2#2):**
  `expire_owner_rg_zero_survives_promotion` — held `==0` entry, then a node-level
  activation (bump `rg_epochs[0]`); assert self-heal fires via the node epoch.
- **Demotion window:** `expire_in_demotion_window_holds` — a `ForwardFlow`
  session whose RG just flipped inactive, DemoteOwnerRGS NOT yet applied; assert
  held via the FORWARDING gate (`!forwards_here`), not aged (this is now a single
  ownership branch, consistent with the code).
- **Ceiling — relative + abs-cap + flapping:**
  `expire_reaps_held_past_relative_ceiling`,
  `expire_reaps_held_at_abs_cap_for_long_timeout` (30-day timeout reaped at
  ABS_CAP not 90 days), and `expire_flapping_rg_still_reaps` (repeated
  promote/demote epoch bumps + self-heal re-stamps do NOT reset `first_held_ns`
  → entry still reaped at the ceiling). Closes B2#4/B2#5.
- `promotion_restamps_held_session`: hold past deadline, then
  `handle_refresh_owner_rgs` (the command-landed complement to the race test);
  assert `last_seen` advanced + re-armed.

### Go unit (sync_test.go)
- If Option B is taken, sync_conn.go is unchanged → existing
  `TestSyncSweep*` must still pass unmodified (regression guard that we did
  NOT touch the sweep).
- (If the fallback Option A is taken instead: add
  `TestSyncSweepResyncsEstablishedByLastSeen` and a fast-path-correctness test
  that an active established flow is swept even when NEW/CLOSED counters are
  unchanged.)

### Failover integration — **MANDATORY new gate (this is the gap)**
The existing `test/incus/test-failover.sh` and `test-stress-failover.sh` run a
**continuous** iperf3 and fail over within seconds — they NEVER idle a flow
past the 300 s TCP timeout, so they cannot catch this regression.

Add an **idle-window failover variant** (e.g.
`test/incus/test-failover-idle.sh`, or an `IDLE_BEFORE_FAILOVER` mode in the
existing script / `failover-test` skill):
1. Establish a long-lived TCP flow trust→untrust through the cluster (e.g.
   `iperf3` with a `--bidir`/holding socket, or a netcat/ssh session) so a
   session is created and synced to the standby.
2. To bound the test, set a **short** TCP established timeout via config
   (e.g. `set ... timeout 30`) so the idle window is 30 s instead of 300 s,
   AND/OR keep one-direction trickle on the primary to mirror the real
   scenario.
3. **Idle the flow on the wire past the configured established timeout** while
   confirming on the standby (`show security flow session` / session counters)
   that with the fix the synced session is **retained** (pre-fix: purged).
4. Trigger RG failover.
5. Assert the previously-established TCP flow **survives** (resumes / no
   RST/timeout) on the new primary.
- **Both legs (B2#6):** also run a demote-then-failback variant (idle a flow
  whose RG fails AWAY from this node, idle past timeout, fail BACK) and, if
  feasible, a fabric (`owner_rg_id==0`) flow, so the live gate exercises the
  demotion + `==0` paths the unit tests cover.
- Run the standard `make test-failover` (continuous traffic) too, to prove no
  ~60 ms failover-timing regression.

### Build/test gates
- `make build-userspace-dp` + `cargo test -p userspace-dp` (the Rust change).
- `make test` (Go).
- `make cluster-deploy` to the loss userspace cluster, then the new
  idle-window failover test + standard `make test-failover` (CLAUDE.md: any
  cluster/VRRP/session-sync/failover change MUST pass `test-failover`).

---

## 8. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Over-retention (holding a session a node should age) | HOLD keys on `!forwards_here` + `(peer_synced || node_active)` (§4); active-node owned sessions (RG active) and standalone (non-peer-synced, no active RG) age. Self-heal is EDGE-triggered (epoch), so a healed entry ages normally next pass — no perpetual re-stamp. Tests assert every negative incl. all 3 peer-synced origins + SharedPromote-ages. |
| Lost primary-delete → indefinite hold | **NON-optional ceiling** `min(MULT × expires_after_ns, ABS_CAP)` from `first_held_ns`. Verified: warm reconnect does NOT bulk-sync (coldStart-only, sync_conn.go:197-209), journal bounded+lossy (:541-543), Close can be filtered (daemon_ha_userspace.go:381-387). Relative→never reaps live long-timeout; ABS-cap→bounds 30-day worst case; first_held_ns→flapping-safe. |
| Promotion/demotion command-apply race (A2#1, A2#3, B2#1, B2#2) | EDGE self-heal via `rg_epochs` (incl. node-level `rg_epochs[0]` for `owner_rg_id==0`), with the epoch bumped **BEFORE** `rg_runtime.store` (§6.3, MANDATORY) so a worker that sees the active RG always sees the bumped epoch → airtight. Demotion window held by the FORWARDING gate (no origin dependence). Tests drive expire in the store-before-epoch sub-window. |
| Stale HA snapshot in the worker | `ha_runtime` ArcSwap snapshot already trusted for every forwarding decision; `is_forwarding_active` includes the watchdog lease (atomic with `active` at promotion) → fails closed (reads inactive → holds; never wrongly ages). |
| `owner_rg_id==0` under-retention in active/active (A2#4) | KNOWN residual: a `==0` entry for a standby RG on an otherwise-active node ages. `==0` entries are rare (unresolved-owner fabric/reverse) and re-derived on promotion (prewarm, ha.rs:125). Follow-up: resolve real RG at import so `owner_rg_id>0`. NOT a blocker for the dominant `owner_rg_id>0` regression. |
| Primary Close filtered by `shouldSyncUserspaceDelta` (A#8) | Ceiling bounds it; r3 follow-up: confirm the primary is primary-for-RG when emitting the Close for a session it owns, else document the residual. |
| `SessionEntry` +12 bytes (`seen_rg_epoch` u32 + `first_held_ns` u64) | Measure `size_of` (do not assume padding); per-entry cost across the table is small vs. the correctness it buys. |

---

## 9. Why this matches #270's intent

#270 said established flows "do not need re-syncing — the peer already has
them." That is TRUE iff the peer (standby) does not throw them away. B makes it
true by stopping the standby from aging the sessions it does not forward —
restoring the precondition #270 assumed — instead of re-feeding the standby fast
enough to beat an expiry that should never fire. We keep #270's sweep narrowing
and its empty-sweep back-off; we fix the layer that broke the assumption.

---

## 10. Rollout / revert

- Rust change (+ doc). Revert is a clean `git revert`. No wire-format or config
  change, so a mixed-version cluster is safe: the patched node retains more; the
  unpatched node behaves as today. The ceiling makes even a patched-node leak
  bounded.

## 11. Open questions for reviewers (settled in r3 unless noted)

1. **Demotion-window: HOLD vs AGE the demoting node's formerly-local copy** —
   A2 recommended AGE (peer owns it); r3 chose HOLD (forwarding-gate + ceiling,
   no coupling to sync completeness). Reviewable; either is correct, HOLD is the
   safer default.
2. **`owner_rg_id==0` active/active residual** — r3 accepts the known
   under-retention (rare unresolved-owner entries, re-derived on promotion) and
   files the real fix (resolve RG at import) as a follow-up. Confirm acceptable.
3. **Constants** — `STALE_SYNCED_CEILING_MULT` (≈3) and
   `STALE_SYNCED_CEILING_ABS_NS`. The ABS cap must be ≥ the largest legitimate
   standby idle window (a 30-day-timeout flow that idles + fails over); plan
   leans ≈7 days (not 24 h) to avoid reaping a valid long-idle synced session
   before failover. Confirm.
4. Idle-window failover test — new `test-failover-idle.sh` vs. a mode flag on
   the `failover-test` skill. Plan default: new script + skill note.

---

## Reviewer convergence ledger
- **r1 (plan r1):** Claude SMR = PLAN-REJECT; reviewer A = PLAN-REJECT;
  reviewer B = PLAN-READY-WITH-NITS. Findings (promotion race, leak-mitigation
  false, gate-too-narrow, history ×2, etc.) all source-verified → folded into r2.
- **r2 (plan r2.1):** Claude SMR = PLAN-READY-WITH-NITS; reviewer A2 =
  PLAN-REJECT (BLOCKER internal-contradiction option-iii; MAJOR demotion
  code/test contradiction; MAJOR residual epoch-after-store race; MAJOR `==0`
  active/active); reviewer B2 = PLAN-REJECT (BLOCKER no-ownership-branch / `==0`
  promotion; MAJOR half-migrated doc; MAJOR flapping-RG ceiling defeat; MAJOR
  90-day hold). Both confirmed the APPROACH correct + all r1 findings resolved.
  All r2 findings source-verified → folded into r3 (single coherent design:
  forwarding-gate HOLD, node-level epoch-edge self-heal bumped before store,
  relative+abs-capped+first_held_ns ceiling, full test matrix).
- **r3 (this revision):** Claude SMR r3 = PLAN-READY (3 NITs folded); reviewer
  R3-A = PLAN-READY-WITH-NITS (all 4 r2 BLOCKERs + 8 MAJORs source-verified
  resolved; single-RG-demotion + epoch-reorder verify CLEAN; NITs: ABS-cap
  magnitude, MAX_RG_EPOCHS visibility, ha_runtime deref); reviewer R3-B =
  PLAN-REJECT on ONE BLOCKER (first_held_ns clear-list said "or self-heal") —
  but that text was ALREADY corrected in commit 272d4fc74 before R3-B finished
  (it cited a stale pre-tightening read; the committed plan says "self-heal does
  NOT clear first_held_ns"), so the BLOCKER is moot; R3-B's remaining MAJOR/MINORs
  (promotion clears first_held_ns — already in §6.4; epoch-bump de-dup; ABS-cap
  floor; ==0 residual counter) folded. **CONVERGED PLAN-READY:** all three
  reviewers agree the design is correct + complete; the only delta was a
  doc-consistency line already fixed. Final NIT folds applied this revision.
