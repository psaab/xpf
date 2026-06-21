# Plan of Action — #2120: standby silently expires long-lived synced sessions

- **Issue:** #2120 (HIGH, `audit`/`bug`, 3/3 adversarial-skeptic verified)
- **Class:** FAILOVER-class regression (reintroduces #131)
- **Revision:** r2 (folds Claude-SMR r1 findings M1/M2 + fabric caveat)
- **Research branch:** `research/2120-standby-wheel-expiry`
- **Base:** origin/master @ 325d10683
- **Status:** DRAFT — awaiting 3-way convergence (Claude SMR + 2 hostile Claude plan-reviewers)

## Changelog
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

### Option B — exempt non-locally-owned sessions from wheel expiry on the standby (root-invariant) [RECOMMENDED]

In `expire.rs`, gate the `remove_entry` on a **HYBRID** of origin and RG
ownership (r2 — refined from reviewer A). The gate holds an entry iff it is the
standby's copy (`is_peer_synced()`) AND this node does not forward its RG. This
is a **per-RG refinement** of the dead Go-GC contract — NOT a byte-faithful
restoration (the old `IsLocalPrimaryAny` gate at gc.go:249/277 was node-global,
aging nothing once the node was secondary for any RG; gc.go:290-291 "On
secondary, all sessions are active (no local expiry)"). The per-RG form is
better for active/active. **Verified facts driving the hybrid:**
- A *demoted* node's formerly-local sessions DO become `is_peer_synced`:
  `demote_owner_rg` flips `ForwardFlow` → `SyncImport` (install.rs:304-306). So
  the origin term correctly classifies them as "standby's copy" after demotion —
  no failback hole.
- During the demotion *transition* (RG flipped inactive, DemoteOwnerRGS not yet
  applied), a session is still `ForwardFlow`; the ownership term (RG inactive)
  is what holds it in that window (the self-heal arm), so neither term alone is
  sufficient — hence the hybrid.

This requires threading the HA snapshot + `now_secs` into
`expire_stale_entries`:

```rust
// loop_body/mod.rs (ha_runtime loaded at :491, loop_now_secs already in scope)
let expired_entries =
    sessions.expire_stale_entries(loop_now_ns, loop_now_secs, ha_runtime.as_ref());
```
```rust
// expire.rs, inside the "Case 3 vs 4" arm, BEFORE remove_entry.
// `entry` is the just-read immutable borrow.
let rg = entry.metadata.owner_rg_id;
let peer_synced = entry.origin.is_peer_synced();   // standby's copy (post-demote too)
let rg_locally_active = rg > 0
    && ha_state.get(&rg).map(|r| r.is_forwarding_active(now_secs)).unwrap_or(false);
let node_has_active_rg = ha_state.values().any(|r| r.is_forwarding_active(now_secs));
let standby_hold = peer_synced && match rg {
    // Owned by a known RG: hold iff this node does not forward that RG.
    r if r > 0 => !rg_locally_active,
    // owner_rg_id==0 (fabric_ingress / reverse with no resolved owner):
    // hold only on a whole-node standby (mirror node-global IsLocalPrimaryAny).
    _ => !node_has_active_rg,
};
if standby_hold {
    // A node that does not forward this session must not age it. But bound the
    // hold so a lost primary-delete cannot leak forever (warm reconnect does
    // NOT bulk-reconcile; the delete journal is lossy).
    if now_ns.saturating_sub(entry.last_seen_ns) > STALE_SYNCED_CEILING_NS {
        // fall through to remove_entry (bounded leak reaper)
        self.last_pop_stats.reaped_stale_synced += 1;
    } else {
        <re-bucket exactly as Case 4>;
        self.last_pop_stats.held_standby += 1;   // MANDATORY observability counter
        continue;
    }
} else if peer_synced && rg_locally_active
          && entry.last_seen_ns < /* RG activation instant */ {
    // PROMOTION SELF-HEAL: this peer-owned entry's RG just became active but its
    // last_seen predates activation (RefreshOwnerRGS may not have landed). Treat
    // it as Case-4 ALIVE and re-stamp so promotion timing cannot expire it.
    <re-stamp last_seen = now_ns; re-bucket as Case 4>;
    continue;
}
// else: not held, not in the self-heal window -> normal remove_entry path
```

**r2 — promotion/demotion transition self-heal (closes M1 / reviewer A#1 /
B#2).** `update_ha_state` does `rg_runtime.store(...)` (ha.rs:39) THEN enqueues
`RefreshOwnerRGS`/`DemoteOwnerRGS` (ha.rs:87→114 / :51). A worker can, across
iterations, load `ha_runtime` showing the new RG state (loop_body:491) yet have
checked its command queue (:497) *before* the command enqueue landed — so
`expire` (:573) acts on the new RG state with `last_seen` not yet refreshed and
the origin not yet flipped. **Verified facts:** (a) `expire` NEVER re-stamps
`last_seen` (only `refresh_for_ha_transition` mod.rs:601 / `upsert_synced`
install.rs do) — so re-bucket ALONE does NOT save a promoted session; the false
"re-bucket re-stamps" claim is removed. (b) The window is bounded by one
`SESSION_GC_INTERVAL_NS` (1 s, expire.rs:96) — rare but silent.
**Fix = the self-heal arm above:** on promotion, re-stamp; on demotion, the
ownership branch holds the entry even before the origin flip (it keys on RG, not
only origin). The implementation needs the "RG activation instant" — options:
(i) a per-RG `activated_at_ns` derived from the lease/`active_lease_until`
(runtime.rs:222) minus `HA_WATCHDOG_STALE_AFTER_SECS`; (ii) a small per-RG
activation epoch; OR (iii) the simplest sufficient form — re-stamp ANY
peer-owned entry the first time expire would remove it under a newly-active RG
(idempotent; at most one extra timeout cycle). Plan default: (iii), validated by
`expire_in_promotion_window_survives`. The coordinator-ordering belt
(enqueue command BEFORE `rg_runtime.store`) is item 3 of §6 — optional.

**Gate scope (r2 — closes reviewer A#2/A#3).** The `owner_rg_id > 0` gate
ALONE is too narrow: a peer-synced session can have `owner_rg_id == 0` and yet
must be held on the standby — e.g. a `fabric_ingress` synced entry, or a reverse
companion whose resolution yielded no owner RG (`owner_rg_id` is only set when
`> 0`, shared_ops.rs). `handle_refresh_owner_rgs` itself scopes on
`owner_rg_id > 0 || fabric_ingress` (refresh_owner_rgs.rs:34). The standby-hold
predicate must therefore be at least as wide as the retention need:

```
standby_hold = is_peer_synced(origin)                     // standby's copy
    && rg_inactive_for_this_node(metadata, ha_state, now_secs)
```
where `rg_inactive_for_this_node` is:
  - if `owner_rg_id > 0`: NOT `is_forwarding_active(owner_rg_id)`;
  - if `owner_rg_id == 0`: treat as standby-held iff the node is not primary for
    ANY RG carrying this fabric path — concretely, hold `owner_rg_id==0`
    peer-synced entries whenever the node has NO active RG at all (a true
    standby), and age them otherwise (so an active node does not over-retain
    its own owner_rg_id==0 sessions). The exact predicate for the `==0` case is
    an **r2 open item to settle in r3** with reviewer input — the conservative
    default is: `owner_rg_id==0` peer-synced entries are held only when
    `ha_state` shows zero forwarding-active RGs (whole-node standby), matching
    the node-global eBPF `IsLocalPrimaryAny` semantics for those entries.

This is a deliberate HYBRID: keying on **origin** (`is_peer_synced`, post-demote
also set — see below) for "is this the standby's copy", and on **RG ownership**
for "does this node forward it". `fabric_ingress` is NOT blanket-excluded in r2
(reviewer A#2 showed exclusion drops fabric synced entries the standby needs) —
it is held under the same rule; an active node's own fabric_ingress sessions are
aged because their RG is locally active.

**Demote-side origin flip (r2 — verified, reviewer A).** On demotion,
`demote_owner_rg` (install.rs:304-306) flips a local `ForwardFlow` entry to
`SyncImport` for the demoted RG. So a demoted node's formerly-local sessions
BECOME peer-synced and are then held by the origin gate — the failback hole my
earlier "origin under-retains demoted-local" worry described is closed by this
flip. BUT there is a **symmetric demotion race** (mirror of M1): between
`rg_runtime.store(inactive)` (ha.rs:39) and the `DemoteOwnerRGS` command being
applied, a still-`ForwardFlow` session with a now-inactive `owner_rg_id` exists;
the origin gate would NOT hold it (still ForwardFlow) and it could be aged in
that ~1-poll window. This is the same class as M1 and is closed by the same
self-heal/ordering fix (treat a peer-OWNED-RG-inactive entry as held regardless
of whether the origin flip has landed — i.e. gate the demotion case on
ownership too, not only origin, for that transition window).

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
  cold-start). **r2 makes the stale-synced ceiling NON-optional**: a much longer
  cap (e.g. 2× the largest configured timeout, or a fixed conservative bound
  like 1 h) applied ONLY to peer-synced standby-held entries, so a leaked entry
  is eventually reaped without a primary delete. This bounds the leak while
  preserving the failover guarantee (the cap >> any real idle window).
  - Note (reviewer B): Option A does NOT have this leak — A ages all synced
    sessions, so a lost delete self-heals at the normal timeout. This is a
    genuine robustness edge for A, weighed in §5.
- Threads two extra args (`now_secs`, `ha_state`) through
  `expire_stale_entries` and its callers/tests; adds the ceiling check.

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

1. **expire.rs**: change `expire_stale_entries(&mut self, now_ns: u64)` to
   `expire_stale_entries(&mut self, now_ns: u64, now_secs: u64, ha_state: &BTreeMap<i32, HAGroupRuntime>)`.
   In the Case-3 (expired) arm, before `remove_entry`, evaluate the §4
   `standby_hold` predicate (origin `is_peer_synced` + RG-inactive-for-node,
   covering `owner_rg_id==0` fabric/reverse per §4). When held: take the Case-4
   re-bucket branch + `continue` (do NOT remove/delta/count-expired; bump
   `held_standby`) — UNLESS the entry has exceeded the **stale-synced ceiling**
   (`now - last_seen > STALE_SYNCED_CEILING_NS`), in which case remove it
   (bounded leak reaper; bump a `reaped_stale_synced` counter). Implement the §4
   transition self-heal: an entry observed `locally_active` whose `last_seen`
   predates the RG activation is **re-stamped** (`last_seen = now`) and treated
   Case-4, not removed — so neither promotion nor demotion command-apply timing
   can expire failover state.
   - Keep the `expire_stale`/test wrapper signature-compatible (empty map =
     standalone default).
   - **Standalone safety:** a standalone session has `owner_rg_id == 0` AND a
     non-peer-synced origin → `is_peer_synced` false → never held. Add the
     explicit non-clustered unit test. (The `owner_rg_id==0` HOLD branch fires
     only for `is_peer_synced` entries on a whole-node standby — settle the
     exact `==0` predicate in r3.)
2. **loop_body/mod.rs:573**: pass `loop_now_secs` + `ha_runtime.as_ref()`.
   In-iteration, command-drain (incl. RefreshOwnerRGS, :497-518) precedes expire
   (:573); the self-heal covers the cross-iteration store-before-command gap on
   BOTH promotion and demotion.
3. **Coordinator ordering hardening (optional, defense-in-depth):** consider
   enqueuing `RefreshOwnerRGS`/`DemoteOwnerRGS` BEFORE `rg_runtime.store` in
   `update_ha_state` (ha.rs:39 vs :87/:51) so a worker that observes the new RG
   state also observes the pending command. The self-heal (item 1) already makes
   this unnecessary for correctness; this is a belt. Verify it does not break
   the RefreshOwnerRGS handler, which itself reads `ha_state` for resolution.
4. **session/mod.rs `WheelPopStats`**: add **mandatory** `held_standby` and
   `reaped_stale_synced` counters (parity with `expired`/`re_bucketed`),
   surfaced as worker/Prometheus counters — a silent-failure bug needs a visible
   signal (held vs reaped vs expired).
5. **Define `STALE_SYNCED_CEILING_NS`** conservatively (e.g. `max(2 ×
   largest configured timeout, 1 h)`) — must be >> any real idle window so it
   never fires for a live failover flow, only for a genuinely-leaked entry.
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
- `expire_ages_local_session_regardless_of_rg`: a `ForwardFlow` session
  `owner_rg_id=1` inactive — must STILL expire (origin not peer-synced). Note in
  the test comment: in real operation `demote_owner_rg` flips ForwardFlow→
  SyncImport, so this exercises the *pre-flip* state.
- **Origin coverage:** repeat the hold test for ALL three `is_peer_synced`
  origins — `SyncImport`, `SharedMaterialize`, `WorkerLocalImport`
  (entry.rs:78-82) — they must behave identically.
- **owner_rg_id==0 fabric/reverse:** `expire_holds_peer_synced_fabric_owner_rg_zero`
  — a `fabric_ingress` SyncImport entry with `owner_rg_id=0` on a whole-node
  standby (no active RG): assert held per the §4 `==0` rule. And the active-node
  counterpart: an `owner_rg_id==0` peer-synced entry on a node with an active RG
  ages (no over-retention).
- `expire_standalone_no_ha_state_ages_normally`: empty `ha_state`, ForwardFlow,
  `owner_rg_id=0` — ages at the configured timeout (no standalone regression).
- **Promotion race (closes M1/A#1/B#2 — MUST reproduce the ordering):**
  `expire_in_promotion_window_survives` — hold a session past deadline (RG
  inactive), then flip `ha_state` to RG-active WITHOUT applying RefreshOwnerRGS,
  then call `expire_stale_entries`; assert the self-heal re-stamped `last_seen`
  and the session SURVIVED (NOT removed). A plain `handle_refresh_owner_rgs`
  in-process test does NOT exercise the race — drive expire directly with the
  active map and no refresh.
- **Demotion race:** `expire_in_demotion_window_holds` — a ForwardFlow session
  whose RG just flipped inactive but DemoteOwnerRGS not yet applied; assert held
  via the ownership branch (not aged in the window).
- **Ceiling:** `expire_reaps_stale_synced_past_ceiling` — a held peer-synced
  entry advanced past `STALE_SYNCED_CEILING_NS` is removed (`reaped_stale_synced`
  bumped), proving the lost-delete leak is bounded.
- `promotion_restamps_held_session`: hold past deadline, then
  `handle_refresh_owner_rgs` for RG1; assert `last_seen` advanced + re-armed.

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
| Over-retention (holding a session a node should age) | Gate on `is_peer_synced()` + RG-inactive-for-node (§4); active-node sessions (their RG `is_forwarding_active`) and standalone (`owner_rg_id==0` + non-peer-synced) age normally; unit tests assert each negative case incl. all 3 peer-synced origins. |
| Lost primary-delete → indefinite hold | **NON-optional stale-synced ceiling** (`STALE_SYNCED_CEILING_NS`) reaps a leaked entry at a long, failover-safe deadline. Verified: warm reconnect does NOT bulk-sync (coldStart-only, sync_conn.go:197-209) and the delete journal is bounded+lossy (sync_conn.go:541-543) — so a ceiling is required, not optional. |
| Promotion/demotion command-apply race (M1, A#1, B#2) | Self-heal in expire re-stamps a peer-owned entry on first active-observation (and holds via ownership during the demotion window) — retention no longer depends on RefreshOwnerRGS/DemoteOwnerRGS landing before the next expire. Test drives expire in the window with no command applied. |
| Stale HA snapshot in the worker | `ha_runtime` is the ArcSwap snapshot the worker already trusts for every forwarding decision; `is_forwarding_active` includes the watchdog lease (set atomically with `active` at promotion) so staleness fails *closed* (reads inactive → holds; never wrongly ages). |
| Primary Close filtered by `shouldSyncUserspaceDelta` (A#8) | The ceiling also bounds this path; verify (r3) the primary is always primary-for-RG when it emits the Close for a session it owns, else document the residual. |
| Threading churn through `expire_stale_entries` callers/tests | Mechanical; empty-map test default. |

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

## 11. Open questions for reviewers (r3)

1. **`owner_rg_id==0` peer-synced HOLD predicate** — plan default: hold only on
   a whole-node standby (zero forwarding-active RGs). Confirm or refine; this is
   the one part of the gate not yet fully pinned.
2. **Self-heal vs. coordinator-ordering** for the promotion/demotion race —
   plan default: wheel self-heal (no cross-thread dep) + optional ordering belt.
   Confirm.
3. **`STALE_SYNCED_CEILING_NS` value** — plan default `max(2× largest timeout,
   1 h)`. Confirm the magnitude (must be >> any real idle window).
4. Idle-window failover test — new `test-failover-idle.sh` vs. a mode flag on
   the `failover-test` skill. Plan default: new script + skill note.

---

## Reviewer convergence ledger
- **r1:** Claude SMR = PLAN-REJECT (M1 transition race; M2 demotion-contract).
  Reviewer A (hostile) = PLAN-REJECT (BLOCKER promotion-race + false mitigation;
  MAJOR gate-too-narrow; MAJOR not-faithful-restoration; MAJOR demotion race;
  MINOR history ×2; MINOR origin coverage; MINOR delete-filter leak). Reviewer B
  (hostile) = PLAN-READY-WITH-NITS (MAJOR leak-mitigation-false / ceiling must be
  mandatory; MAJOR re-bucket-doesn't-restamp; MINOR history; MINOR lease-race is
  a non-issue; NIT cost-honest/test-valid). **All findings verified against
  source and folded into r2.** Not yet converged → re-review r2.
