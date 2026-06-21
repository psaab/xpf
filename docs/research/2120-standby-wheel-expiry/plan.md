# Plan of Action — #2120: standby silently expires long-lived synced sessions

- **Issue:** #2120 (HIGH, `audit`/`bug`, 3/3 adversarial-skeptic verified)
- **Class:** FAILOVER-class regression (reintroduces #131)
- **Revision:** r1 (initial draft for hostile plan-review)
- **Research branch:** `research/2120-standby-wheel-expiry`
- **Base:** origin/master @ 325d10683
- **Status:** DRAFT — awaiting 3-way convergence (Claude SMR + Codex + AGY)

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
   incremental sweep, leaving only `val.Created >= threshold`
   (`pkg/cluster/sync_conn.go:403` and `:421`). `Created` is the immutable
   session-creation timestamp, so a flow created before the threshold is swept
   exactly once and never re-synced. #270's stated rationale — "Established
   flows whose LastSeen moved do not need re-syncing — the peer already has
   them from the original create" — was correct **only** while fact #1's
   `IsLocalPrimary` gate kept the standby from aging synced sessions. The
   userspace migration invalidated that invariant; #270 was never revisited.

The original #131 fix (`b35bb4562`, "sync established session state on periodic
sweep") added the exact `|| val.LastSeen >= threshold` clause that #270 later
removed, and also removed the `GLOBAL_CTR_SESSIONS_NEW` fast-path skip "since
it only tracked new session creation, not ongoing activity." #270 reinstated
that fast-path (`sync_conn.go:382-389/447`).

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

| Area | Option A | Option B |
|------|----------|----------|
| `pkg/cluster/sync_conn.go` (sweep) | 2 predicates + fast-path revisit | unchanged |
| `userspace-dp/src/session/expire.rs` | unchanged | the removal arm (~10 lines) |
| `userspace-dp/src/afxdp/worker/loop_body/mod.rs` | unchanged | pass `ha_runtime` + `now_secs` into expire |
| Wire format | unchanged | unchanged |
| Go tests | sync_test.go | none |
| Rust tests | none | session/tests.rs + ha_tests.rs |

Both options are small. The risk is in correctness of the HA contract, not LOC.

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

### Option B — exempt peer-synced sessions from wheel expiry on the standby (root-invariant)

In `expire.rs`, gate the `remove_entry` for an entry where
`removed.origin.is_peer_synced()` on whether the local node is the active owner
of `metadata.owner_rg_id`. Concretely, before removing, peek the entry's
metadata; if it is peer-synced AND the local node is NOT forwarding-active for
its `owner_rg_id`, **skip removal and re-bucket the wheel entry** (Case-4
"still alive" handling) so it is re-checked next interval. This requires
threading the HA snapshot + `now_secs` into `expire_stale_entries`:

```rust
// loop_body/mod.rs (the ha_runtime + loop_now_secs are already in scope)
let expired_entries =
    sessions.expire_stale_entries(loop_now_ns, loop_now_secs, ha_runtime.as_ref());
```
```rust
// expire.rs, inside the "Case 3 vs 4" arm, before remove_entry:
if entry.origin.is_peer_synced()
    && entry.metadata.owner_rg_id > 0
    && !ha_state
        .get(&entry.metadata.owner_rg_id)
        .map(|r| r.is_forwarding_active(now_secs))
        .unwrap_or(false)
{
    // Standby owns no forwarding for this RG: hold the synced session
    // (mirror the dead Go-GC IsLocalPrimary contract). Re-bucket so the
    // wheel re-checks it; promotion (RefreshOwnerRGS) re-stamps last_seen.
    <re-bucket as Case 4>; continue;
}
```

**How it fixes the bug:** the standby never ages a synced session it does not
forward. The session is reaped only by (a) a primary-driven DeleteSynced when
the real flow ends, or (b) normal aging *after* this node is promoted (at which
point `RefreshOwnerRGS` has re-stamped `last_seen_ns`). This is the userspace
re-implementation of the exact contract the Go GC's `IsLocalPrimary` used to
enforce.

**Correctness:**
- Uses `is_forwarding_active(now_secs)` (active bool AND live watchdog lease),
  the same predicate fabric-redirect already trusts — a standby with a stale
  watchdog correctly counts as inactive, so we never wrongly *retain* on a
  node that has silently lost cluster state. Conversely a node that is genuinely
  the owner ages normally.
- Forward AND reverse peer-synced companions are both held (the gate keys on
  `is_peer_synced()` + `owner_rg_id`, which both carry).
- Re-bucketing (vs. dropping the wheel hint) keeps the entry observable so it
  is re-evaluated each interval; even if a promotion path were ever to skip
  `RefreshOwnerRGS`, the next expire pass would re-stamp/age it correctly once
  the RG is active.
- No new control-socket or sync traffic; the existing 1 s sweep keeps its
  empty-sweep back-off (#270's perf win preserved).

**Cost / downside:**
- **Standby memory.** Held synced sessions occupy the standby's session table
  until a primary delete or promotion. This is bounded by the primary's live
  session count (already fully replicated by design) — it does NOT grow
  unboundedly; it is exactly the set the standby must hold to survive failover.
  The wheel re-buckets these entries each interval, a small constant per-entry
  cost (the wheel is O(due bucket), not O(N), so re-bucketing N held entries
  each ~256 s long-timeout cycle is cheap).
- **Leak risk if a primary delete is ever lost.** If the primary's Close delta
  never reaches the standby (e.g. fabric/sync outage at the moment the flow
  closes) the standby would hold the synced session until promotion refresh
  ages it. Mitigation: this is the *same* exposure the eBPF-era design
  accepted (the standby never aged synced sessions then either); bulk re-sync
  on reconnect reconciles the table; and a belt-and-suspenders **stale-synced
  reaper bound** (a much longer cap, e.g. 2× the largest configured timeout,
  applied only to peer-synced entries on the standby) can be added if reviewers
  want a hard ceiling. Default plan: no extra reaper (matches eBPF-era
  semantics); add only if a reviewer requires a bound.
- Threads two extra args (`now_secs`, `ha_state`) through
  `expire_stale_entries` and its callers/tests.

### Option A+B note
A and B are not mutually exclusive, but combining them is redundant: B alone
fully fixes the regression at lower steady-state cost, and A's re-sync becomes
unnecessary for *retention* (it would still re-sync state drift, but the
standby already gets state via the create + the wheel never reaps it). Shipping
both pays A's per-second cost for no retention benefit.

---

## 5. Recommendation — **Option B (root-invariant)**

B is recommended as the primary fix, for four reasons:

1. **It restores the actual lost invariant.** The bug is "the standby ages
   sessions it does not own." #270's rationale was *predicated* on the standby
   never aging synced sessions. B re-establishes that exact contract in the
   layer that now owns expiry (the Rust wheel), so #270's intent — "established
   flows do not need re-syncing because the peer already has them" — becomes
   true again. A patches a symptom (keeps re-feeding the standby fast enough to
   outrun an expiry that should never have applied).
2. **It preserves #270's performance win.** A re-introduces the per-second
   full-table re-sync and kills the empty-sweep back-off — the precise cost
   #270 removed. B adds zero sync/control-socket traffic.
3. **It is failure-mode-correct under watchdog staleness.** B uses
   `is_forwarding_active(now_secs)`, so a standby that has lost cluster state
   does not wrongly retain; A has no such coupling (it just keeps importing).
4. **It is robust to future sweep changes.** Any later throttling/coalescing
   of the sweep cannot silently re-break failover, because retention no longer
   depends on sweep cadence.

**Secondary / hedge:** #270's commit ALSO touched `pkg/cluster/sync.go` for
#269 (journal kernel SESSION_OPEN during demotion). That part is orthogonal and
stays. We do **not** revert #270; we re-establish the invariant it assumed.

If reviewers judge the Rust HA-state threading too invasive or want a
defense-in-depth belt, the fallback is Option A with the
empty-sweep fast-path corrected — but the plan's position is B.

---

## 6. Detailed implementation plan (Option B)

1. **expire.rs**: change `expire_stale_entries(&mut self, now_ns: u64)` to
   `expire_stale_entries(&mut self, now_ns: u64, now_secs: u64, ha_state: &BTreeMap<i32, HAGroupRuntime>)`.
   In the Case-3 (expired) arm, before `remove_entry`, read the entry's
   `origin` + `metadata.owner_rg_id` (already borrowed as `entry`); if
   peer-synced AND not forwarding-active for its RG, take the Case-4
   re-bucket branch and `continue` (do NOT remove, do NOT push delta, do NOT
   count as expired).
   - Keep the `expire_stale`/test convenience wrapper signature-compatible
     (add the two params or provide a test default of "all RGs active /
     empty map = standalone").
   - **Standalone-node safety:** an empty `ha_state` map (no cluster) must
     NOT retain anything. Gate the whole skip on `owner_rg_id > 0`; a
     standalone session has `owner_rg_id == 0` and is unaffected. Verify a
     non-clustered run sees an empty/None HA map and ages normally.
2. **loop_body/mod.rs:573**: pass `loop_now_secs` and `ha_runtime.as_ref()`
   into the call. (`loop_now_secs` is already computed in the loop;
   `ha_runtime` is loaded at line 491.)
3. **session/mod.rs `WheelPopStats`**: add a `held_peer_synced` counter
   (parity with `expired`/`re_bucketed`) so the behavior is observable and
   testable; surface it as a Prometheus/worker counter if cheap (optional —
   the existing `session_expires` counter already drops for held entries,
   which itself is a signal).
4. **Docs**: update `userspace-dp/src/session/README.md` (expire.rs section)
   and `docs/fabric-cross-chassis-fwd.md` / the HA session-sync doc to state
   the standby-retention invariant and that the Go-GC `IsLocalPrimary` gate is
   now mirrored in the Rust wheel. Note in `pkg/cluster` docs that #270's
   sweep narrowing is intentional and retention is owned by the wheel gate.
5. **Do NOT** change `helpers.rs` `tcp_flags: 0` (the 300 s timeout is correct
   for an active owner; B simply stops the standby from applying it).

---

## 7. Test plan

### Rust unit (session/tests.rs, ha_tests.rs)
- `expire_holds_peer_synced_when_rg_inactive`: install a SyncImport TCP
  session with `owner_rg_id = 1`, an `ha_state` where RG1 is inactive; advance
  `>302 s`; assert the session is **retained** and `held_peer_synced`
  incremented, `expired == 0`.
- `expire_ages_peer_synced_when_rg_active`: same, but RG1
  `is_forwarding_active`; assert the session **is** removed at >302 s.
- `expire_ages_local_session_regardless_of_rg`: a non-peer-synced
  (`ForwardFlow`) session with `owner_rg_id = 1` inactive — must STILL expire
  (only peer-synced get the gate). Guards against over-retention.
- `expire_standalone_no_ha_state_ages_normally`: empty `ha_state`,
  `owner_rg_id = 0` — ages at 300 s (no regression for standalone).
- `promotion_restamps_held_session`: hold a session past 302 s (RG inactive),
  then `handle_refresh_owner_rgs` for RG1; assert `last_seen_ns` advanced and
  the session no longer immediately expires.
- Reverse-companion variant of the hold test.

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
| Over-retention (holding a session the standby should age) | Gate strictly on `is_peer_synced() && owner_rg_id > 0 && !is_forwarding_active`; local sessions and standalone (`owner_rg_id==0`) untouched; unit tests assert each negative case. |
| Lost primary-delete → indefinite hold | Same exposure as eBPF era; bulk re-sync reconciles on reconnect; optional long stale-synced cap if a reviewer requires a hard ceiling. |
| Stale HA snapshot in the worker | `ha_runtime` is the ArcSwap snapshot the worker already trusts for every forwarding decision; `is_forwarding_active` includes the watchdog lease so staleness fails *closed* (treated inactive → not retained-wrongly is impossible; retained-correctly requires a LIVE active lease). |
| Threading churn through `expire_stale_entries` callers/tests | Mechanical; provide a test-default overload or pass an empty map for standalone tests. |
| Wheel re-bucket churn for many held entries | Wheel is O(due bucket); long-timeout entries re-bucket at most every 256 s; cost is bounded and amortized. |

---

## 9. Why this matches #270's intent

#270 said established flows "do not need re-syncing — the peer already has
them." That is TRUE iff the peer (standby) does not throw them away. Option B
makes it true by stopping the standby from aging them — restoring the precise
precondition #270 assumed — instead of re-feeding the standby fast enough to
beat an expiry that should never fire. We keep #270's sweep narrowing and its
empty-sweep back-off; we fix the layer that broke the assumption.

---

## 10. Rollout / revert

- Single Rust change (+ doc); revert is a clean `git revert` of the
  implementation PR. No wire-format or config change, so a mixed-version
  cluster (one node patched, one not) is safe: the patched standby simply
  retains more; the unpatched standby behaves as today.

## 11. Open questions for reviewers

1. Should B add a hard stale-synced ceiling (defense-in-depth) or match the
   eBPF-era "never age on standby" semantics exactly? (Plan default: match
   eBPF era; no extra cap.)
2. Re-bucket vs. drop-the-wheel-hint for held entries — plan recommends
   re-bucket (keeps the entry observable). Confirm.
3. Idle-window failover test: new script vs. mode flag on the existing
   `failover-test` skill? (Plan default: new `test-failover-idle.sh` + skill
   note.)
