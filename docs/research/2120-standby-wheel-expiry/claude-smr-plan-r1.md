# Claude SMR — hostile plan review r1 — #2120

Reviewer: Claude SMR (in-conversation, hostile). Bias: refute by default.
Base verified against origin/master @ 325d10683 in the research worktree.

## Summary

Root-cause is **correct and source-verified**. The recommendation of Option B
over Option A is **sound**. But I independently found one **MAJOR** correctness
gap in Option B that the plan does NOT address — a promotion-transition race
window — plus several MINOR specification gaps. I am NOT passing r1 clean.

VERDICT: PLAN-REJECT (one MAJOR must be resolved in r2; recommendation stands).

## Verified-correct claims (with evidence)

- `gc.SkipSweep = func() bool { return true }` is unconditional in userspace
  mode — daemon_run.go:741-743. The `gc.IsLocalPrimary` assignment at :748 is
  therefore dead for expiry. Root-cause fact #1 holds.
- The Rust wheel removes peer-synced entries unconditionally; expire.rs:135
  `remove_entry`, and the `is_peer_synced()` check at :155-157 only guards the
  Close-delta push, not removal. Fact #2 holds.
- Synced TCP import uses `tcp_flags: 0` — helpers.rs:349 — so
  `session_timeout_ns(PROTO_TCP, 0, …)` = 300 s default. Fact #3 holds.
- Worker has the HA snapshot in scope at the expire site: `ha_runtime` loaded
  at loop_body:491, expire at :573. `is_forwarding_active` (active && lease)
  at runtime.rs:233 is the correct predicate. Option B is feasible.
- Promotion re-stamps last_seen: handle_activated_rgs enqueues RefreshOwnerRGS
  (ha.rs:114) → handle_refresh_owner_rgs → refresh_for_ha_transition →
  `record.entry.last_seen_ns = now_ns` (mod.rs:601) + push_to_wheel (:605).
- Primary delete path is alive & GC-independent: Close delta (expire.rs:159) →
  queueUserspaceSessionDeltas "close" arm → QueueDeleteV4/V6
  (daemon_ha_userspace.go:765-793). Held sessions WILL be reaped on real close.
- Option A re-sync DOES land on the standby: the sync install path is
  `upsert_synced_with_origin` (install.rs) which remove+reinserts with fresh
  last_seen — NOT `update_session` (which rejects peer re-import at mod.rs:413).
  Plan's claim is correct.
- Existing failover tests never idle past timeout (continuous iperf3):
  test-failover.sh / test-stress-failover.sh. The new idle-window gate is
  genuinely necessary.

## Findings

### [MAJOR] M1 — promotion-transition race can expire the very sessions failover needs
`update_ha_state` does `rg_runtime.store(active)` (ha.rs:39) and THEN enqueues
`RefreshOwnerRGS` to each worker (ha.rs:87→114). These are two separate steps
on the coordinator thread. A worker loads `ha_runtime` once per poll
(loop_body:491), drains its command queue at ~497-518, and expires at :573 —
all using that one snapshot. Within a poll, commands run before expire, so the
refresh re-stamps before expire. **But across iterations** there is a window: a
poll can load `ha_runtime` (now showing the RG active) at :491 AFTER the store,
yet check/drain its command queue at :497 BEFORE the `RefreshOwnerRGS` enqueue
lands. In that poll, Option B's gate (`is_forwarding_active` → true) NO LONGER
holds the session, last_seen has NOT been refreshed, and a session already past
its idle deadline (which Option B had been legitimately holding) is EXPIRED at
:573 — destroying exactly the flow failover must preserve.

Mitigating factor (must be stated, not relied on blindly): `expire_stale_entries`
is gated to run at most once per `SESSION_GC_INTERVAL_NS` = 1 s (expire.rs:96),
whereas the command queue is drained EVERY poll (sub-ms). So the refresh is
applied within microseconds of activation, and the 1 s expire tick almost never
lands in the sub-ms store→enqueue→drain gap. The probability is small — but for
a HIGH failover-correctness regression, "small" is not "zero," and the failure
is silent + exactly the symptom we are fixing.

REQUIRED in r2: a deterministic guard, e.g. ONE of:
  (a) Make activation atomic w.r.t. workers: enqueue RefreshOwnerRGS BEFORE (or
      together with) the rg_runtime.store, so any worker that observes the
      active RG also observes the pending refresh in the same or an earlier
      queue state. (Verify this does not break demotion ordering or the
      RefreshOwnerRGS handler, which itself reads ha_state for resolution.)
  (b) Have the wheel HOLD peer-synced entries for one extra GC interval after a
      local RG→active transition (a per-RG "just activated at tick T; grace
      until T+1" marker the worker consults), so the refresh is guaranteed
      applied before any expire treats the RG as active.
  (c) Re-stamp last_seen for held peer-synced entries inline when the gate
      flips active in the expire pass itself (i.e., on the transition poll,
      treat a peer-synced entry whose RG just became active as Case-4 alive +
      re-stamp), making the wheel self-healing and independent of RefreshOwnerRGS
      timing.
Option (c) is the most robust (no cross-thread ordering dependency) and should
be the plan's default; (a) is a cleaner invariant if it composes. The plan must
pick one and add a Rust unit test that drives expire in the transition window
(RG flipped active, RefreshOwnerRGS NOT yet applied, entry past deadline) and
asserts the session survives.

### [MINOR] M2 — demotion path interaction unspecified
On demotion (active→inactive), `demote_shared_owner_rgs` (ha.rs:60) and
DemoteOwnerRGS run, and the local entries become standby-held. The plan does
not state what happens to sessions that were LOCAL (ForwardFlow, not
peer-synced) on the node that just demoted. Those are `!is_peer_synced()` so
Option B's gate does NOT hold them → they age normally on the demoted node.
That is arguably correct (they are no longer owned), but the plan should state
it explicitly: demotion does NOT convert local sessions to peer-synced, so a
just-demoted node will age its formerly-local sessions at the normal timeout.
Confirm this is intended (it matches eBPF-era GC behavior: the demoted node's
IsLocalPrimary went false and the GC stopped aging — wait, that is the
OPPOSITE; eBPF GC STOPPED aging on the demoted node). RE-CHECK: does the
eBPF-era contract age or hold formerly-local sessions on a demoted node? If the
old GC held them (IsLocalPrimary false ⇒ skip), Option B under-retains here,
because B keys on origin, not on current ownership. This needs an explicit
answer in r2 and possibly broadens B's gate to `owner_rg_id` ownership
regardless of origin.

### [MINOR] M3 — `SharedPromote` / `SharedMaterialize` origin coverage
`is_peer_synced()` returns true for `SyncImport | SharedMaterialize |
WorkerLocalImport` (entry.rs:78-83) but NOT `SharedPromote`. The plan says "gate
keys on is_peer_synced()". Confirm SharedPromote / shared-materialize lifecycles
on the standby are correctly classified — a shared-active session that should be
held must satisfy the gate. Enumerate which origins represent "standby must
hold" and assert the gate matches exactly (a too-narrow gate re-leaks; too-wide
over-retains local sessions).

### [MINOR] M4 — counter / observability commitment is soft
The plan lists `held_peer_synced` as "optional." For a silent-failure HIGH bug,
the held-vs-expired signal should be MANDATORY (a Prometheus counter or at least
a WheelPopStats field surfaced), so an operator can SEE the standby is holding
rather than purging. Make it required.

### [NIT] M5 — standalone gate
`owner_rg_id > 0` gate for standalone safety is correct (standalone sessions
have owner_rg_id 0). Add the explicit unit test the plan already lists; keep it.

## On A vs B
B remains the right recommendation: it restores the lost invariant, preserves
#270's empty-sweep back-off, and fails closed under watchdog staleness. A's
per-second full-table re-sync cost is real (sweep never empties → never backs
off past 1 s → empty-sweep fast-path dead). But B is NOT correct as written
because of M1 — resolve M1 (preferably via mitigation (c)) and B is shippable.
