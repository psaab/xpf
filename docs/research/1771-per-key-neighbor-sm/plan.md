# #1771 — Per-Key Neighbor Resolver State Machine (§10a) — research plan v1

## 1. Status

**PLAN-KILL-recommended (design preserved for reopen).**

This is NOT a fresh design-heavy redesign. #1771 §10a is **~90% already
shipped** via the incremental, measurement-gated "Path B" plan that the
prior research round (`docs/research/1771-per-key-resolver/plan.md` on
branch `research/1771-per-key-resolver`) converged on. Phases 1–3 merged
(PR #1779, PR #1833). The ONE remaining piece — the per-key **epoch** (§2.1
co-located per-key epoch) plus the resolver **exponential GET backoff**
(§2.3) — was explicitly **gated on a measured `epoch_rejects`/`get_attempts`
rate**, and the gate came back **negative on the live loss cluster**
(`epoch_rejects` = 0 and `get_attempts` = 0 on both nodes, across cold
restart + immediate v4/v6 connects + line-rate P12 history + failover
cycles — PR #1833). The plan that shipped these phases explicitly declared
"**PLAN-KILL of §2.1 alone is an acceptable outcome**."

My firsthand read (this round): the recommended terminal is to **close
#1771 as substantially-complete** with §2.1/§2.3 **PLAN-KILLED on
measurement** — the global-epoch conservatism is provably causing **zero**
measurable harm, and a per-key FSM is a real behavioral change on a live
failover/forwarding-path resolver (blackhole risk HIGH) with **no measured
payoff**. This doc brings §10a current, fully specifies the remaining
design so it is ready to build IF a future workload flips the gate, and
lists the reopen trigger. It is a **deferred terminal**, not a call to
engineer now.

Reviewer disposition target: PLAN-KILL (or PLAN-DEFERRED-with-reopen-gate).
The parent owns the hostile plan-review; this half stops at the doc.

---

## 2. Issue framing

#1771 is the §10a follow-up to the #1769 investigation (merged as PR #1770,
the immediate stuck-state fix). Lineage:

- **#1769 / PR #1770 (shipped):** the live wedge — a directly-connected
  next-hop that lost its `dynamic_neighbors` entry (transient
  FAILED/DELNEIGH, or a dropped good RTM_NEWNEIGH) armed a 3 s negative
  cache and was never re-probed/re-buffered, producing repeated 3 s connect
  blackouts. Fixed with a **shared, per-key, rate-limited on-demand
  resolver**: single-key `RTM_GETNEIGH` + REACHABLE/PERMANENT-only cache +
  probe-on-STALE/DELAY + immediate-revocation-on-FAILED, guarded by a
  **global neighbor epoch** with bump-first ordering and an in-lock epoch
  re-check. That closed the wedge but left two coarse mechanisms: a
  **global** epoch (bumped on every RTMGRP_NEIGH batch) and a per-binding
  enqueue throttle.

- **#1771 §10a (this issue):** the full per-key resolver state machine —
  per-key epoch (not global), per-key pending bound, backoff that coalesces
  to one in-flight GET/probe per key, ENOBUFS-triggered throttled re-dump,
  and the full Prometheus counter set.

The issue is **OPEN** (a "closed" event fired when PR #1833 merged with a
`Closes #1771` line; it was subsequently reopened as the live tracking
issue for the gated Phase-4 tail). Labels: `refactor`, `perf`.

---

## 3. Honest scope and value

**The theoretical value.** The global epoch is bumped once per RTMGRP_NEIGH
recv batch (`neighbor.rs:1225`, `fetch_add(1, Release)`). A confirmed
single-key GET reply is cached only if the global epoch has not advanced
since enqueue. So an **unrelated** neighbor churning during our GET (any
NEWNEIGH/DELNEIGH for any key on the box) advances the global epoch and
causes our confirmed insert to be **conservatively rejected** even though
our key was untouched. A per-key epoch removes exactly those false
rejects. **This is a GET-retry-rate optimization, not a correctness fix**
— the #1769 in-lock re-read already closes the actual out-of-order stale-MAC
race; the global epoch is *correct*, merely conservative.

**The measured value.** The prior plan added the `epoch_rejects` counter
precisely so the decision could be data-driven, and gated §2.1 on a
materially-nonzero rate. Live measurement (PR #1833, loss userspace
cluster, both nodes):

- `epoch_rejects` = **0** — the conservatism has never rejected a real
  confirmed insert under any lab workload.
- `get_attempts` = **0** — even across a cold xpfd restart with immediate
  v4/v6 connects, line-rate P12 history, and failover cycles, the resolver's
  GET path **never fired**: neighbor resolution completes via ordinary RX
  learning (ARP reply / NDP NA → `dynamic_neighbors.insert_if_changed`)
  before the negative fast-fail ever enqueues a resolve.

So the mechanism §2.1 would optimize (a) never mis-rejects and (b) barely
executes at all. There is no measurable harm to remove.

**Honest disposition.** Per the prior plan's own gate and the standing
project rule ("PLAN-KILL acceptable if the global-epoch conservatism is not
causing measurable harm and per-key adds risk without payoff"), the value
is **below the risk floor**. Building a per-key co-located-epoch map (or a
per-key FSM) touches the hottest shared structure (`ShardedNeighborMap`) on
the live failover/forwarding path; a per-key state-machine bug is a stuck
neighbor = a blackhole. Spending that risk to shave a reject rate that is
**measured at zero** is not justified. **Recommend PLAN-KILL**, with the
design below preserved and a concrete numeric reopen gate.

---

## 4. What already shipped (bringing §10a current)

The team-lead brief assumed §10a is unstarted with an existing design-of-
record awaiting `/engineer`. That is **stale**. Ground truth vs origin/master:

| §10a item | Shipped? | Where | Notes |
|---|---|---|---|
| Shared per-key rate-limited on-demand resolver | ✅ #1770 | `neighbor_resolver.rs` | single-key GET, REACHABLE/PERMANENT-only cache, probe-on-STALE, immediate-FAILED-revoke, epoch guard |
| **§2.2 Per-key pending bound** | ✅ #1779 | `worker/mod.rs:137,570`; `mod.rs:436` | `pending_neigh` is now `FastMap<(i32,IpAddr),PendingNeighPacket>` (was `VecDeque`); `MAX_PENDING_NEIGH` (4096) now bounds **distinct next-hops**; one representative packet per key; #1772 dwell/depth/timeout accounting preserved |
| **§2.5 ENOBUFS detection + throttled upsert-only re-dump** | ✅ #1779 | `neighbor.rs:979+`; counters in `neighbor_resolver.rs:146–161` | `netlink_enobufs` / `netlink_redumps` / `netlink_redump_upserts`; re-dump is upsert-only (no eviction); re-dump upserts attributed by `nlmsg_seq`; **stale-entry eviction (lost-DELNEIGH) explicitly deferred** — needs per-slot source-tagging, its own scope |
| **§2.6 Full Prometheus counter set** | ✅ #1833 | `server/helpers/status.rs:170–181`; `lifecycle.rs:241–257` | queue_depth (gauge), enqueue_drops, disconnected, get_attempts, get_resolved, probe_on_stale, get_failures, epoch_rejects, get_backoff_attempts, netlink_{enobufs,redumps,redump_upserts}; `pending_keys` + `neg_neigh_keys` gauges |
| **§2.4 Negative policy = "don't buffer dup SYNs, not stop resolution"** | ✅ #1833 | invariant N1 test + docs; `rate_limit_decide` (`neighbor_resolver.rs:614`) | held on master unchanged → shipped as test (`invariant_n1_...`) + compile-time assert `NEG_NEIGH_TTL_NS > RESOLVER_PER_KEY_RATE_LIMIT_NS` (`neighbor_resolver.rs:86`) + docs; no runtime change |
| **§2.6 backoff-retry telemetry** (`get_backoff_attempts`) | ✅ #1833 | `rate_limit_decide` → `AdmitRetry` | counts re-admitted keys, but the window is still **flat 1 s** (see §2.3 below) |
| **§2.1 Per-key co-located epoch** | ❌ **declined on measurement** | — | `epoch_rejects` = 0, `get_attempts` = 0 on the live cluster; gate unmet (PR #1833) |
| **§2.3 Resolver exponential GET backoff** (1→2→4→8 s widening) | ❌ **not shipped** | resolver still uses flat `RESOLVER_PER_KEY_RATE_LIMIT_NS` = 1 s (`neighbor_resolver.rs:78`); `last_resolved: FastMap<(i32,IpAddr),u64>` (key→ts, no `KeyBackoff`) | tied to Phase 4; the plan said "land §2.3 standalone if §2.1 killed" — but `get_attempts`=0 means it, too, has ~zero measured payoff |

**Also note:** the abandoned full-FSM attempt (PR #1774, CLOSED unmerged)
implemented per-key epochs, a single representative packet per key, backoff
coalescing (10 ms→5 s), per-key TTL states, and 5 FSM unit tests — but was
**never wired into the packet path** and was superseded by the incremental
Path B. Its `ShardedEpochMap` "separate map" design was PLAN-KILLED in
round-1 review for **reopening the #1769 absent-key-DELNEIGH stale-MAC
race**; the co-located-slot design in §5 below is the race-safe successor.

**Net remaining #1771 scope = §2.1 (per-key co-located epoch) + §2.3
(resolver exponential GET backoff) only.** Everything else is on master.

---

## 5. Concrete design (the remaining per-key FSM, reconciled with current code)

This section specifies the remaining work so it is buildable IF the reopen
gate (§10) ever fires. It supersedes the abandoned separate-map design of
PR #1774 with the co-located-slot design the prior review converged on.

### 5.1 §2.1 — co-located per-key epoch

Do **not** add a standalone epoch map (that reopens the #1769 race). Store
the epoch in the neighbor map's shard slot. Change `ShardedNeighborMap`'s
value from `NeighborEntry` to:

```rust
struct NeighborSlot {
    entry: Option<NeighborEntry>, // None == tombstone (deleted, epoch retained)
    epoch: u64,                   // per-key generation from a process-global monotonic AtomicU64
    last_change_ns: u64,          // for tombstone GC
}
```

- **Monitor** (`neighbor.rs::neigh_monitor_thread`, per event, under the
  key's shard lock): NEWNEIGH(K) → `slot.epoch = GLOBAL_NEIGH_EPOCH.fetch_add(1, Release); slot.entry = Some(neigh); slot.last_change_ns = now`.
  DELNEIGH(K) → same bump, `slot.entry = None`. The `or_insert` is
  load-bearing: a **DELNEIGH for an absent key still creates a tombstone
  slot and bumps** (the #1769 absent-key case, preserved per-key). Epochs
  come from a **process-global monotonic counter** (never reused post-GC),
  so a stale snapshot of value N can never collide with a future recreated
  slot.
- **Resolver** (`neighbor_resolver.rs`): `enqueue()` snapshots
  `epoch_before = shard.get(K).map(|s| s.epoch).unwrap_or(0)`. The confirmed
  insert becomes `insert_confirmed_if_unchanged(K, val, epoch_before)` that
  reads `slot.epoch` **under the same shard lock** it inserts within — one
  critical section, structurally identical to today's global guard but
  reading a per-slot field. Absent-slot confirm is allowed **only when
  `epoch_before == 0`** (genuine first-resolution); absent + `epoch_before != 0`
  ⇒ reject (slot existed and was removed/GC'd since the snapshot). This is
  safe because `ResolveItem` carries `enqueued_ns` and the resolver
  **discards any item older than `AGE_DISCARD_LIMIT_NS = TOMBSTONE_TTL_NS − 2 s`**
  before the confirm, making create→tombstone→GC within one in-flight
  request's lifetime mathematically impossible (GC TTL 60 s ≫ 200 ms GET).
- **Tombstone GC:** incremental, **one shard at a time on a timer** (reuse
  the resolver's 5-min GC cadence) — **never `with_all_shards`** (that
  stop-the-world all-shard lock is a dataplane latency spike). Reap
  `entry.is_none() && now − last_change_ns > TOMBSTONE_TTL_NS` (60 s). With
  the global-monotonic epoch + age-discard, the TTL is a **cardinality**
  device only, not a correctness device.

### 5.2 §2.3 — resolver exponential GET backoff

Replace the flat 1 s `RESOLVER_PER_KEY_RATE_LIMIT_NS` window with a per-key
saturating exponential (1→2→4→8 s, capped) so a permanently-dead key
coalesces to one in-flight `RTM_GETNEIGH` on a widening interval:

```rust
struct KeyBackoff { last_get_ns: u64, get_attempts: u8 } // saturating_add — no u8 overflow / probe storm
```

Two distinct clocks stay separate (this is NOT a duplicate of the dispatch
clock): (1) the dispatch-side per-*packet* kernel-ARP `PROBE_SCHEDULE_NS`
(`neighbor_dispatch.rs`, unchanged), and (2) the resolver-side per-*key*
userspace-GET clock (the only thing §2.3 changes). Because the resolver
also fires `trigger_kernel_arp_probe()` on stale/failed/no-reply, widening
the resolver clock reduces a dead key's aggregate kernel-probe cadence — the
desired direction. **Due-key wake** must run on **every resolver loop
iteration** gated by `now − last_check ≥ 500 ms` (NOT only in the
`recv_timeout` Timeout arm — under continuous traffic that arm never fires
and negative-key re-probing would starve); due-key state must retain
`iface_name` so the re-issued GET is addressable.

---

## 6. Public API preservation

- **Wire/status API is already stable and must not change on a KILL.** The
  §2.6 counter set (`neighbor_resolver_*`, `netlink_*`, `pending_keys`,
  `neg_neigh_keys`) is shipped Rust→Go→Prometheus; a KILL leaves it intact.
- **If §2.1 is ever built:** changing the shard value to `NeighborSlot`
  means every `ShardedNeighborMap` accessor must treat `entry: None` as
  absent — `get`, `contains_key`, `len`, `is_empty`, `with_all_shards` /
  `BulkShardGuard::total_len`, `dynamic_neighbor_status()`, manager
  `replace`, and all existing tests. A tombstone must be **invisible to
  forwarding and to status**. This is a large internal API surface (the
  round-1 review's "value-type surgery under-specified" finding) and is the
  single biggest reason the change is not low-risk.
- `insert_confirmed_if_unchanged` (`sharded_neighbor.rs:308`) keeps its
  signature shape; only the epoch it reads changes from the global atomic to
  the per-slot field.

---

## 7. Hidden invariants (must be preserved per-key if ever built)

The #1769 correctness guarantees are load-bearing and MUST survive any
per-key rework:

1. **Bump-first ordering** — the monitor bumps the epoch (`Release`)
   **before** it mutates the map (`neighbor.rs:1225`), so any concurrent
   invalidation is observable to the resolver's post-GET re-read.
2. **In-lock epoch re-check** — the authoritative guard is the epoch
   re-read **inside** the shard lock in `insert_confirmed_if_unchanged`
   (`sharded_neighbor.rs:317`), not the cheap pre-lock fast-path reject.
   Per-key must keep the read and the insert in one critical section.
3. **REACHABLE/PERMANENT-only cache** — `classify_nud` caches a MAC only for
   REACHABLE/PERMANENT (`neighbor_resolver.rs:410`); STALE/DELAY/PROBE →
   probe-only, never cache the unconfirmed MAC.
4. **Immediate revocation on authoritative FAILED/INCOMPLETE** (firewall
   posture, AGY F3) — no removal grace; `NoReply` (timeout/error) must NOT
   revoke (a transient GET loss must not evict a still-good entry).
5. **Absent-key DELNEIGH still bumps** — the tombstone `or_insert` is what
   closes the #1769 absent-key race per-key; the abandoned separate-map
   PR #1774 got this wrong and was KILLed for it.

**Composition with recently-landed neighbor code:**

- **#6349 outlined ARP/NDP learn/program handlers**
  (`outline_arp_reply_learn_and_program` / `outline_ndp_na_learn_and_program`,
  `poll_stages.rs:191,263`). These are the **RX-learning fast path** that
  populates `dynamic_neighbors` from received ARP replies / NDP NAs — and
  they are *why* `get_attempts` measures 0: RX learning resolves the
  neighbor before the resolver's GET path is ever reached. A per-key epoch
  must bump/insert through these handlers with the same bump-first, in-lock
  discipline as the monitor. They also strengthen the KILL case: the
  resolver GET is a rarely-exercised backstop, not the primary resolution
  path.
- **#5288 `KernelNeighborProgramLimiter`** (`neighbor_program_limiter.rs`) —
  a per-worker, set-associative (64 buckets × ways), 50 ms-interval rate cap
  on `add_kernel_neighbor` netlink writes, keyed by `(i32, IpAddr)`. The
  resolver's confirmed-cache path writes the **in-memory** map
  (`insert_confirmed_if_unchanged`), not `add_kernel_neighbor`, so it
  **bypasses** the limiter by design (§2.1 would not change that). A per-key
  epoch must not add a new kernel-program path that escapes this cap. The
  limiter and the resolver share the same `(ifindex, next_hop)` key space —
  any per-key structure should reuse that key type for consistency.

---

## 8. Risk table

| Risk | Severity | Likelihood if built | Mitigation |
|---|---|---|---|
| Per-key FSM/epoch bug → stuck neighbor → **blackhole** on the live failover/forwarding path | **HIGH** | Medium | Named property test reproducing the absent-key-DELNEIGH race; differential test (global vs per-key identical except fewer rejects); live churn-injection gate. **But the payoff is measured 0 — risk unbought.** |
| `NeighborSlot` value-type surgery misses an accessor → tombstone leaks into forwarding/status | High | Medium | API-audit checklist (§6); every accessor filters `entry.is_some()`; status/manager/test coverage |
| Tombstone GC resurrection (GET delayed in queue snapshots epoch 0, slot GC'd, stale insert) | High | Low | Global-monotonic epoch (never reused) + `epoch_before==0`-only absent-confirm + `AGE_DISCARD_LIMIT_NS` age-discard — belt-and-suspenders |
| Tombstone cardinality growth (memory bound) | Low | Low | 60 s incremental one-shard-at-a-time GC; bounded by distinct churned next-hops; NOT `with_all_shards` |
| §2.3 backoff double-clock / u8 overflow / negative-key starvation | Medium | Low | Two clocks documented distinct owners; only resolver clock changes; `saturating_add`; due-key wake every loop iter gated 500 ms |
| ENOBUFS re-dump RTNL contention (already shipped) | — | — | 5 s throttle; upsert-only; single-key GET ≠ dump path — already live and validated |
| **Opportunity cost / complexity on a hot shared structure with zero measured benefit** | **HIGH** | Certain if built | **PLAN-KILL** — do not spend the risk |

The dominant row is the last: a real behavioral change to the hottest
shared neighbor structure, buying a reject rate measured at exactly zero.

---

## 9. Test plan (only relevant IF the gate ever flips)

The shipped phases are already covered: 23 unit tests in
`neighbor_resolver_tests.rs`, the `invariant_n1_...` live-thread test, the
ENOBUFS-injection re-dump test, and the §2.6 metric wire pins. A KILL adds
**no** tests. IF §2.1/§2.3 were ever built:

- **Property test** — absent-key-DELNEIGH race: GET snapshots key K's
  epoch; a NEWNEIGH then DELNEIGH(K) land; the confirmed insert is
  **REJECTED** (no stale-MAC resurrection) — the exact #1769/#1774 defect.
- **Differential test** — global-epoch path vs per-key path produce
  identical cache state under concurrent confirms + *unrelated-key* churn,
  except the per-key path has strictly fewer `epoch_rejects`.
- **§2.3 backoff** — a permanently-dead key's GET interval widens
  1→2→4→8 s (saturating); negative-key re-probe does not starve under
  continuous traffic.
- **cargo test + make test** green; no regression on
  `userspace-perf-compare.sh`.
- **Live gate (loss userspace cluster):** `make test-failover` **with
  neighbor-churn injection** (`ip neigh flush` / add-delete loops on a
  non-target next-hop during failover) — connectivity must not blackhole;
  the `-P 12 -p 5208` #1769 hang-repro must connect promptly. v4 + v6.
  Neighbor resolution is on the failover path, so `make test-failover` is
  mandatory before any such change per project rule.

---

## 10. Out of scope + staging recommendation

**Out of scope for #1771 (independent follow-ups if ever motivated):**

- **Stale-entry eviction on lost-DELNEIGH** — §2.5 shipped upsert-only
  re-dump (re-adds *missing* good entries); evicting *stale* entries needs
  per-slot source-tagging and is a separate scope, deliberately deferred.
- Changing the single-key GET mechanism (optimal per #1769).
- Changing the netlink multicast subscription model or the shared
  off-hot-path resolver-thread architecture.
- L7 application identification.

**Staging recommendation.** The remaining work is at most **two small,
independent PRs** (§2.1 epoch; §2.3 backoff) — NOT one big refactor and NOT
the abandoned single-PR full-FSM (PR #1774). But the recommendation is
**neither now**: PLAN-KILL both on the negative measurement.

**Recommended terminal:** close #1771 as substantially-shipped (Phases 1–3
merged), with §2.1 + §2.3 **PLAN-KILLED-on-measurement**. Preserve this doc
+ §5 design so a reopen is a build, not a re-derivation.

**Reopen gate (numeric, falsifiable).** Reopen §2.1 **only if** a realistic
production or lab workload shows `epoch_rejects` climbing at a materially
nonzero rate **AND** `get_attempts > 0` (the resolver GET path actually
executing — today it does not, because #6349 RX-learning resolves first).
Reopen §2.3 only if `get_backoff_attempts` shows a sustained population of
permanently-dead keys cycling the flat 1 s window frequently enough to
matter. Both are already exported to Prometheus, so the trigger is a
dashboard alert, not a code change.

---

## 11. Open questions (each PLAN-KILL-invitable)

1. **Is `epoch_rejects` = 0 a lab artifact or a structural property?** If
   the global epoch only advances on RTMGRP_NEIGH batches and real
   deployments have low neighbor-table churn relative to the ~sub-ms GET
   window, the reject rate may be structurally ~0 everywhere — making §2.1
   permanently unjustified. → If structural, **PLAN-KILL permanently**, not
   just "gated."
2. **Does `get_attempts` = 0 mean the resolver is effectively dead code on
   this platform?** #6349 RX-learning resolves every neighbor before the
   negative fast-fail enqueues. If the on-demand GET path never executes in
   practice, both §2.1 *and* §2.3 optimize a path that does not run. →
   Invites PLAN-KILL of the entire remaining resolver-optimization scope;
   possibly even a question about whether the GET path earns its complexity.
3. **Is the `NeighborSlot` value-type surgery worth it for a zero-measured
   win?** Every `ShardedNeighborMap` accessor must become tombstone-aware —
   a wide, error-prone internal API change on the hottest neighbor
   structure. → If the win stays at zero, this surgery is pure risk →
   PLAN-KILL.
4. **Should #1771 simply be closed rather than left open as a gated
   tracker?** An open issue with all shippable scope merged and the tail
   killed-on-measurement is arguably noise. → Invites closing #1771 outright
   (the KILL terminal), reopen-gated by the Prometheus alert in §10.
5. **Does §2.3's exponential backoff have ANY independent value given
   `get_attempts` = 0?** The prior plan said "land §2.3 standalone if §2.1
   killed" — but that predates the measurement showing the GET path never
   fires. → Invites PLAN-KILL of §2.3 as well (not just deferral).
6. **Would tombstones + incremental GC add measurable latency/memory to the
   forwarding path they can never be worth here?** Even a correct
   implementation adds a slot field and a GC timer to the hot map. → If the
   only benefit is a zero-rate reject reduction, the added steady-state cost
   argues for PLAN-KILL.
7. **Is there any non-lab workload (huge L2 domain, aggressive neighbor
   GC, many transient next-hops) that would flip the gate — and can we
   name it precisely enough to be a real reopen trigger rather than a
   hypothetical?** If no concrete workload can be named, the reopen gate is
   vacuous and the honest disposition is a hard KILL, not a deferral.

---

## Appendix — code map (verified this round, origin/master @ f6fd76043)

- `userspace-dp/src/afxdp/neighbor_resolver.rs` — shared on-demand resolver
  (shipped #1770); flat 1 s per-key rate limit (`last_resolved`,
  `rate_limit_decide`); `classify_nud` / `decide_action`; all §2.6 counters.
- `userspace-dp/src/afxdp/neighbor.rs:1225` — global `neighbor_generation`
  bump-first per recv batch (the global epoch §2.1 would make per-key);
  ENOBUFS re-dump telemetry (#1779).
- `userspace-dp/src/afxdp/sharded_neighbor.rs:308` —
  `insert_confirmed_if_unchanged` (in-lock global-epoch re-check).
- `userspace-dp/src/afxdp/worker/mod.rs:137` — `pending_neigh` is now a
  per-key `FastMap` (§2.2 shipped #1779); `mod.rs:436` `MAX_PENDING_NEIGH`.
- `userspace-dp/src/afxdp/neg_neigh.rs` — negative-cache gate (post-#2.2
  semantics).
- `userspace-dp/src/afxdp/poll_stages.rs:191,263` — #6349 outlined
  ARP/NDP RX-learning handlers (the reason `get_attempts` = 0).
- `userspace-dp/src/afxdp/neighbor_program_limiter.rs` — #5288 per-worker
  kernel-neighbor-program rate cap (resolver in-memory cache bypasses it).
- Prior design-of-record: `docs/research/1771-per-key-resolver/plan.md`
  (branch `research/1771-per-key-resolver`); §10a source:
  `docs/research/1769-neighbor-redesign/plan.md` §10a.
- Shipped: PR #1779 (Phases 1–2), PR #1833 (Phase 3 + §2.1 declined).
  Abandoned: PR #1774 (full-FSM, CLOSED unmerged), PR #1775 (research,
  CLOSED).
