# Plan of action — #2134 (wire screen session-limit lifecycle) + #2128 (evict-on-zero leak)

- **Revision:** r2 (post hostile review round 1 — 2 independent Claude
  plan reviewers, both NEEDS-REVISION; this revision folds all findings)
- **Issues:** #2134 (HIGH — security feature non-functional), #2128 (HIGH — memory-DoS leak)
- **Branch:** `research/2128-2134-screen-session-limit`
- **Mode:** `/research` — STOPS at PLAN-READY. No code, no PR, no production-source edits.
- **Base:** origin/master @ `8260727af`. **All line citations below are
  against this base (the `session/` module is split into
  `mod.rs`/`install.rs`/`lookup.rs`/`expire.rs`/`entry.rs`/`key.rs` per
  #2005). The r1 draft mis-cited a stale single-`mod.rs` checkout; both
  reviewers correctly flagged this — r2 re-cites against the worktree.**

## r1 → r2 changelog (what the hostile review changed)

The two reviewers independently converged on the same load-bearing
defects. The architecture (Path B) survived; the *mechanism* did not, in
three places:

1. **[BLOCKER, reviewer A] The screen session-limit check runs
   PER-PACKET with no new-flow gate** — so once a flow's own session is
   counted, every subsequent data packet of that flow re-evaluates
   `count >= limit` and gets dropped. Wiring the counter would tear down
   established flows at the limit boundary. **r2 relocates the limit
   check from the per-packet screen stage to the session-MISS / new-flow
   decision** (§3.2 rewritten).
2. **[MAJOR, both] The "single choke point" thesis is false** — HA
   promote (`update_session` in-place branch, `mod.rs:472`) creates a
   counted session WITHOUT `install_with_protocol_with_origin`, and HA
   demote (`demote_owner_rg`, `install.rs:305`) un-counts a session
   in-place WITHOUT `remove_entry`. r2 specifies explicit increment at
   promote + decrement at demote (§3.4 rewritten, §6.3 now a closed
   spec, not an open question).
3. **[MAJOR, reviewer B] Unconditional hot-path cost when the feature is
   OFF** — r1 gated counter maintenance only on the
   counted-class predicate, adding 2 map ops to every install/remove for
   the ~99% of deployments with no `limit-session`. r2 adds an
   any-zone-configured OFF-gate so install/remove pay nothing when
   unconfigured (§3.3, §3.5).

Plus: closed the in-place-mutation audit (§6.3, Finding 4 — `is_reverse`
is invariant across refresh; only `origin` flips, only at promote/demote)
and tightened the test plan to cover the established-flow regression and
the promote/demote cycles (§5).

> The two issues are coupled and MUST ship together. #2134 wires the
> per-IP session-limit lifecycle so the limit actually enforces. The
> moment that lifecycle is live, the #2128 read-path leak (phantom
> zero entries) becomes reachable in production. Fixing one without
> the other is either a no-op (wire without evict → leak) or a
> still-broken feature (evict without wire → still 0, still no
> enforcement). One PR, wire-AND-evict.

---

## 1. Problem statement (confirmed against source)

`set security screen ids-option <name> limit-session source-ip-based <n>`
(and `destination-ip-based <n>`) is intended to cap the number of
concurrent sessions a single source/destination IP may hold. In the
userspace AF_XDP dataplane it is **a complete no-op today**, and the
counter map it consults **leaks unbounded zero-count entries**.

### 1.1 The no-op (#2134) — CONFIRMED

Screen ingress runs `check_src` / `check_dst`
(`userspace-dp/src/screen/session_limit.rs:19,29`) on the hot path via:

```
poll_descriptor/mod.rs:159  stage_screen_check
  -> poll_stages.rs:289     screen.check_packet_with_zone_id
  -> screen/mod.rs (check_packet_with_zone_id)
       profile.session_limit_src > 0 -> session_limits.check_src(...)
       profile.session_limit_dst > 0 -> session_limits.check_dst(...)
```

`check_src` returns `count >= limit`. The count comes from
`self.src_counts` — a `FxHashMap<IpAddr,u32>` that is **only ever
incremented by `SessionLimitTracker::session_created`**. And
`session_created` (and `session_expired`) are wired NOWHERE in
production:

- `ScreenState::session_created` / `session_expired`
  (`screen/mod.rs:459,466`) carry `#[cfg_attr(not(test),
  allow(dead_code))]`.
- `git grep session_created`/`session_expired` over `userspace-dp/src`
  shows callers ONLY in `screen/mod.rs` (the self-delegating wrappers),
  `screen/session_limit.rs` (the mutators), and `screen/tests.rs`
  (`#[cfg(test)]`). **No production session-create or session-expire
  path notifies `screen`.**

Result: production `src_counts[ip]` is always 0, so `0 >= limit` is
always false. The (limit+1)-th session is never rejected. **The
operator gets zero protection.** Verified: `check_src`/`check_dst` ARE
called on the production ingress hot path (so the check fires), but
always against 0.

### 1.2 The leak (#2128) — CONFIRMED, currently masked by the no-op

`check_src`/`check_dst` READ the count via
`self.src_counts.entry(ip).or_insert(0)`. `entry().or_insert(0)`
**inserts a zero entry as a side effect** for every distinct IP that
ever reaches the session-limit check, even when no session is created
(packet later dropped by policy, spoofed-source flood, stateless
UDP/ICMP). `session_expired` only removes an entry it decremented to 0,
so an IP whose count was *created at 0 and never incremented* is never
reclaimed. The 30s periodic cleanup (`screen/mod.rs`) sweeps only
`port_scan` + `ip_sweep`, never `session_limits`; `update_profiles`
never clears it either. Per-worker `ScreenState` => per-worker unbounded
growth. Turning on the protection makes the box MORE vulnerable to a
source-IP-spray memory DoS.

**Reachability note:** today, this read path leaks only because
`check_src`/`check_dst` are gated by `profile.session_limit_src/dst >
0`. So #2128 is *already reachable* the instant an operator configures
the (currently useless) limit — the phantom-zero leak is live even
though enforcement is not. #2134's wiring does not "create" the leak;
it makes the *whole feature* live, at which point the read path must be
made non-mutating (#2128's fix) or counts will be both wrong and
leaky.

### 1.3 Semantics target (Junos parity)

Junos `limit-session source-ip-based <n>` caps **concurrent sessions
per source IP arriving on the screened zone**. The count is over
*sessions admitted through that zone's screen*, not all sessions
globally. The current code keys the tracker globally (one
`SessionLimitTracker` shared across zones) and compares the global
per-IP count against the *ingress zone's* configured limit. See §6.4
for the zone-scoping decision (kept global per-IP, matching the
existing structure and Junos's per-IP — not per-zone-per-IP — counting;
flagged as an explicit reviewer question).

---

## 2. The session lifecycle, mapped (the wiring surface)

The per-IP count must increment exactly once per *locally-admitted*
session create and decrement exactly once per removal of that same
session. The dataplane has MANY create and delete sites; getting this
right requires hooking at a **choke point**, not at each call site.

### 2.1 Create sites — ONE choke point for *fresh* installs, PLUS one in-place promote

**Fresh installs** all go through
`SessionTable::install_with_protocol_with_origin`
(`session/install.rs:113`). Production callers (across poll_descriptor,
forwarding, shared_ops, and the `install_with_protocol` wrapper at
`install.rs:91`). HA-synced imports do NOT go through it — they use
`upsert_synced_with_origin` (`install.rs:199`), a separate sink that
never counts.

`install_with_protocol_with_origin` already computes the exact
"is-this-a-locally-counted-session" predicate, to gate its HA Open delta
(`install.rs:160`):

```rust
if !metadata.is_reverse
    && !origin.is_peer_synced()
    && !origin.is_transient_local_seed()
{
    self.push_delta(SessionDelta { kind: Open, ... });
}
```

`is_peer_synced()` = `SyncImport | SharedMaterialize | WorkerLocalImport`
(`session/entry.rs:78`; note: `SharedPromote` is NOT in this set, so a
promoted session IS counted — correct, it's locally owned).
`is_transient_local_seed()` = `MissingNeighborSeed`. This predicate is
precisely the set of sessions that should count: locally-admitted,
forward-direction, real (not seed), not imported from the peer.

**Second create site — in-place HA promote (NOT a fresh install).**
`update_session` (`mod.rs:354`) promotes a peer-synced entry to local
in place; its promote branch (`mod.rs:472`) emits the Open delta on
`was_peer_synced && !origin.is_peer_synced() && !metadata.is_reverse`
but does NOT call `install_with_protocol_with_origin`. So a counted
session can be *created* (in the counting sense) here without hitting the
install choke point. **r2 requires an explicit increment here** (§3.4).
Driven in production by `maybe_promote_synced_session`
(`session_glue/promote.rs`) on the data path post-failover.

### 2.2 Delete sites — ONE slab-delete sink for removals, PLUS one in-place demote

**Removals** all funnel through `SessionTable::remove_entry`
(`mod.rs:645`; the sole `self.entries.remove(handle)` is at `mod.rs:695`
— verified the only other `entries.remove` at `mod.rs:894` is the
owner-RG *index* helper `remove_owner_rg_index_entry`, not a session
removal). Callers:

| File:line | Trigger |
|---|---|
| `expire.rs:135` (`expire_stale_entries`) | timer-wheel stale expiry (primary) |
| `install.rs:139` (`install_*`) | defensive pre-clear before insert (same key) |
| `install.rs:225` (`upsert_synced_*`) | defensive pre-clear before upsert |
| `install.rs:292` (`delete`) | explicit delete (clear, RST teardown, fabric-cancel, promote-purge) |
| `lookup.rs:190` (`take_synced_local`) | materialize synced→local |

`remove_entry` reads the full `record` (key with src/dst IP, metadata
with `is_reverse`, `origin`) before freeing the slab slot — and returns
the removed `SessionEntry` — so it has everything needed to decide
whether this removal should decrement, and which (src,dst). Its two
early `None` returns (stale-handle / primary-key guard, `mod.rs:663`/
`:673`) RESTORE the mapping and do NOT remove — the decrement MUST be on
the `Some(record)` success path only (§6.2).

**Second un-count site — in-place HA demote (NOT a removal).**
`demote_owner_rg` (`install.rs:295`) flips `entry.origin =
SyncImport` IN PLACE (`install.rs:305`) inside an `if
!entry.origin.is_peer_synced()` guard, WITHOUT calling `remove_entry`.
A counted local session becomes uncounted peer-synced with no
decrement → **counter leaks UP** → eventually wrongly blocks legitimate
traffic from that IP. Driven by `handle_demote_owner_rgs`
(`session_glue/commands/demote_owner_rgs.rs`) on every RG demotion (a
routine failover/failback event). **r2 requires an explicit decrement
here** (§3.4).

### 2.3 Why NOT the SessionDelta stream (rejected sub-approach)

The HA `SessionDelta { Open | Close }` stream looks like a tidy single
SSOT, but it is **NOT a faithful 1:1 record of local removals**.
`delete()` (`session/mod.rs:1200`) is a bare `remove_entry` and does
NOT emit a Close delta; only some callers manually pair `delete()` with
`emit_close_delta_with_origin` (`session_glue/mod.rs:449`), while others
do not (e.g. the forward+reverse fabric/RST cancel at
`session_glue/mod.rs:720-721`, `promote.rs:164`). Driving the counter
off the delta stream would therefore **miss** those removals and leak
the counter upward — exactly the opposite-direction leak #2134 warns
about. Rejected.

### 2.4 The defensive pre-clear (potential double-count) — handled

`install_*` and `upsert_*` call `remove_entry(&key)` as a pre-clear
before inserting the new record (same key). If `remove_entry`
decrements and `install_*` increments, an *idempotent re-install of the
same key* nets to a transient (-1,+1) on the SAME (src,dst) — correct
net, but it momentarily evicts and re-creates the map entry. This is
benign for correctness. The plan's increment lives in `install_*`
(after the successful insert) and decrement in `remove_entry`; the
pre-clear path's decrement-then-increment is self-cancelling for the
same IP. See §6.2 for the precise placement that avoids a spurious
decrement when `remove_entry` is a no-op (key absent).

---

## 3. Design — chosen approach (Path B: SessionTable owns the count, check at new-flow)

Put the per-IP local-session counters **inside `SessionTable`**, driven
by the create/remove paths under an OFF-gate, and perform the
**limit check at the new-flow (session-miss) decision**, not per packet.

### 3.1 Where the counter lives

Add to `SessionTable` (`session/mod.rs`) two small maps plus the OFF-gate
flag:

```
session_limit_active: bool                     // any zone configures limit-session
session_limit_src_counts: FxHashMap<IpAddr,u32>
session_limit_dst_counts: FxHashMap<IpAddr,u32>
```

(The existing `SessionLimitTracker` type in `screen/session_limit.rs`
can be relocated here verbatim — its `saturating_sub`-then-`remove`-at-0
logic at `session_limit.rs:47` is exactly the evict-on-zero we want, and
its mutators are already correct; only the READ path needs to become
non-mutating, see §3.2/#2128.)

`session_limit_active` is set whenever the worker's
forwarding/screen-profile snapshot is applied (the same place
`screen_state.update_profiles` runs, `worker_loop` ~line 318), computed
as "any screen profile has `session_limit_src > 0 || session_limit_dst >
0`" — mirroring `ScreenState::has_advanced_features`
(`screen/mod.rs:472`). When false, ALL counter maintenance below is
skipped (zero cost for the ~99% of deployments with no `limit-session`).

Maintenance (all gated by `if self.session_limit_active`):

- **Increment** at TWO sites, both under the counted-class predicate
  (`!is_reverse && !origin.is_peer_synced() &&
  !origin.is_transient_local_seed()`):
  1. `install_with_protocol_with_origin` (`install.rs`), on the success
     path AFTER the slab insert (the function already returns `false`
     early on `len() >= max_sessions` before any state change, so the
     increment is naturally only on real installs). Place it right next
     to the existing Open-delta push (`install.rs:160`) — same gate.
  2. `update_session` promote branch (`mod.rs:472`), inside the existing
     `if was_peer_synced && !origin.is_peer_synced() && !metadata.is_reverse`
     block (same place the Open delta is pushed). Keyed on
     `key.src_ip`/`key.dst_ip`.
- **Decrement** at TWO sites:
  1. `remove_entry` (`mod.rs:645`), on the `Some(record)` success path
     only (NOT the guard `None` returns at `mod.rs:663`/`:673`), under
     the SAME predicate read from `record.entry`. This covers expire,
     explicit delete (clear / RST / fabric-cancel / promote-purge), and
     `take_synced_local`.
  2. `demote_owner_rg` (`install.rs:295`), inside the existing
     `if !entry.origin.is_peer_synced()` guard, evaluating the FULL
     counted-class predicate on the entry's CURRENT (pre-mutation)
     origin/metadata, and decrementing BEFORE the `entry.origin =
     SyncImport` assignment (`install.rs:305`). Keyed on `key.src_ip`/
     `key.dst_ip`.

Every decrement uses `saturating_sub` and **evicts the map entry the
moment its count reaches 0** (#2128).

### 3.2 Where the limit is CHECKED — at new-flow, NOT per packet

> **r2 fix for the BLOCKER.** In r1 the check stayed in
> `check_packet_with_zone_id` (`screen/mod.rs:343-358`), which runs on
> EVERY packet of EVERY flow (it sits OUTSIDE the `is_syn` gate that
> guards `port_scan` at `mod.rs:319`), and `stage_screen_check` runs
> BEFORE the session lookup (`poll_descriptor/mod.rs:199` vs the lookup
> at `:269`). So with the counter live, an established flow whose own
> session is counted would re-check `count >= limit` on every data
> packet and self-drop at the boundary. **The check must fire only when
> a NEW session is about to be created.**

Move the session-limit check OUT of the per-packet screen stage and into
the **session-MISS / new-flow install decision** in `poll_descriptor`
(the slow path after `resolve_flow_session_decision` returns `None`,
where `from_zone_id`, the ingress screen profile, the flow's pre-NAT
`flow.src_ip`/`flow.dst_ip`, and both `sessions` and `screen`/forwarding
are in scope, around `poll_descriptor/mod.rs:746+`). There:

- look up the ingress zone's screen profile;
- if `session_limit_src > 0` and `sessions.session_limit_src_count(
  flow.src_ip) >= limit` → reject the new flow (recycle, emit the
  `session-limit-src` screen-drop event), do NOT install;
- mirror for dst;
- otherwise proceed to install (which increments — §3.1).

This fires exactly once per new flow, before its session exists, so it
never counts the flow's own session against itself. Established-flow data
packets hit the flow-cache / session-hit path and never reach this check.
The stateless + rate + scan checks stay in `stage_screen_check`
(unchanged); only the session-limit sub-check relocates.

The COUNT read is a non-mutating query on `SessionTable`
(`session_limit_src_counts.get(&ip).copied().unwrap_or(0)`), which
**fixes #2128 by construction**: no `entry().or_insert`, so an IP that
never creates a session never gets a map entry. The map is only ever
populated by a real increment and shrunk to empty by decrement-to-zero
eviction; bounded by distinct IPs with ≥1 live local session (≤
`max_sessions`).

(Because the check now lives in `poll_descriptor` where `sessions` is
directly in scope, there is NO need to thread `&SessionTable` into
`stage_screen_check` — the r1 borrow concern is moot. The per-zone screen
profile is directly readable via `worker_ctx.forwarding.screen_profiles`
(`types/forwarding.rs:70`), so no new plumbing into `ScreenState` is
needed. Reuse the existing `emit_screen_drop_event` / screen-drop counter
helpers for the event.)

**Placement note (SMR-1):** there are TWO counted forward installs on
the miss path — `SessionOrigin::ForwardFlow` (`:1375`) AND
`SessionOrigin::LocalMiss` (`:907`, host-inbound). The check must gate
the path leading to BOTH (place it upstream, after zone resolution at
`:746+`, so it dominates both install sites). The ReverseFlow installs
(`:1577`, `:536` cluster-peer-return) and the seed (`:2813`) are NOT
counted (`is_reverse`/`is_transient_local_seed`) and correctly need
neither check nor count.

**All-protocol coverage (SMR-2):** the miss-path install region is NOT
TCP-gated (it keys on `flow.forward_key.protocol` generically), so the
limit correctly applies to TCP, UDP, and ICMP sessions — matching Junos
(`limit-session` is protocol-agnostic). This is why the check is
relocated to the miss path rather than gated on `is_syn` like
`port_scan`: an `is_syn` gate would silently exempt UDP/ICMP floods.

### 3.3 Hot-path cost — zero when unconfigured

- **Feature OFF (no zone has `limit-session`):** `session_limit_active`
  is false → increment/decrement skipped entirely; the new-flow check is
  guarded by `session_limit_src/dst > 0` per profile (already false). NO
  added cost on any path. Directly honors the #1357 codegen-sensitivity
  note kept at `install.rs:106-112`.
- **Feature ON, per new session (create):** one `FxHashMap` upsert for
  src + one for dst, under the predicate — same cost class as the
  existing Open-delta push already on this path. No new lock
  (`SessionTable` is single-worker-owned; no `Mutex`).
- **Feature ON, per removal:** one `get_mut` + possible `remove` for src
  + dst inside `remove_entry` (which already does several index
  cleanups). No new lock.
- **Per new flow (check):** two `get` lookups (per new flow, NOT per
  packet). Cheaper than today's mutating `entry().or_insert`.
- **No allocation on the steady-state hot path.**

### 3.4 HA promote/demote — counted correctly (the hard part, now closed)

- **Standby importing peer sessions:** `upsert_synced_with_origin`
  (`install.rs:199`) with `SyncImport`/`SharedMaterialize` — never
  counts (separate sink, no increment). Correct: those were screened by
  the active owner, not locally.
- **Promote synced→local (failover):** `update_session` promote branch
  (`mod.rs:472`) — explicit increment added (§3.1 site 2). Promotion is
  data-path packet-driven (`maybe_promote_synced_session`), one session
  at a time, and is NOT limit-checked (promotions don't go through the
  new-flow check) — so a mass post-failover promotion does NOT
  spike-trip the limit and drop legitimate traffic. Once a heavy IP's
  promoted count exceeds the limit, the next NEW SYN from that IP is
  correctly dropped at the new-flow check until sessions drain —
  designed Junos-equivalent behavior (documented, §6.5).
- **Demote local→synced (failover/failback):** `demote_owner_rg`
  (`install.rs:305`) — explicit decrement added (§3.1 decrement site 2),
  BEFORE the in-place origin flip.
- **The pre-clear self-balance:** `install_*`/`upsert_*` call
  `remove_entry(&key)` before (re)insert. local→synced via `upsert_*`
  with `allow_replace_local=true`: the pre-clear `remove_entry`
  decrements the old local entry (correct), and `upsert_*` re-inserts
  with a synced origin that does NOT increment (correct). synced→local
  via `install_*` re-install of the same key: pre-clear removes a synced
  entry (no decrement — synced wasn't counted), install increments
  (correct). Net correct in both directions.

### 3.5 Closed audit — every counted-class transition is covered

The count for an entry must change **iff its counted-class predicate
value changes**. The COMPLETE set of slab-insert / origin / is_reverse
mutation sites (verified against the base):

| Site | File:line | Effect on counted-class | Count action |
|---|---|---|---|
| fresh install | `install.rs:154` | creates (if predicate true) | increment (§3.1.1) |
| upsert_synced | `install.rs:240` | synced (never counted); pre-clear removes prior local | pre-clear decrement only |
| delete / expire / take_synced_local | via `remove_entry` `mod.rs:645` | removes | decrement (§3.1.dec.1) |
| promote synced→local | `mod.rs:472` | uncounted→counted | increment (§3.1.2) |
| demote local→synced | `install.rs:305` | counted→uncounted | decrement (§3.1.dec.2) |
| `update_session` refresh (non-promote) | `mod.rs:354` | metadata replaced wholesale, but **origin & is_reverse preserved for a key** — counted-class unchanged | none |
| failback refresh (`refresh_owner_rgs`) | `session_glue/commands/refresh_owner_rgs.rs` | preserves origin | none |
| `restore_entry` | `mod.rs:709` | dead in production (`allow(dead_code)`) | none |

**`is_reverse` invariant:** a session's direction is fixed at install;
no production path flips `is_reverse` for an existing key. `update_session`
replaces `metadata` wholesale, but callers pass same-direction metadata
(a forward session stays forward across refresh). The invariant test
(§5.8) guards this: sum of per-IP counts == live counted entries after
any op sequence — it FAILS if any transition is missed.

### 3.6 Per-worker scoping (unchanged, documented)

Each worker owns its own `SessionTable` and screened sessions are
steered to a worker by RX-queue hash. The per-IP count is therefore
per-worker — a single source IP's sessions may spread across N worker
queues, so the *effective* limit is up to N×limit in the worst spread.
This matches today's per-worker `ScreenState` design and the eBPF-era
per-CPU-map behavior; it is a pre-existing property, not introduced by
this change. Documented in the screen design doc; flagged for reviewers
(§6.6) but NOT a blocker (Junos on multi-core SPC behaves similarly;
exact-flow steering keeps a given 5-tuple on one queue, so a single
attacker IP opening many flows DOES spread across queues — the
worst-case N×limit dilution is inherent to per-worker state and was the
same under the eBPF per-CPU map).

---

## 4. Multiple Path Options (design fork — for reviewer judgment)

### Path A — hook at each create/expire SITE (the issue's literal text)

Call `screen.session_created(src,dst)` / `session_expired(src,dst)` at
each of the ~7 create sites and the expire loop + every delete site.

- **Pro:** counter stays in `ScreenState`; no new SessionTable
  surface; no cross-object borrow.
- **Con:** FRAGILE. 7 create sites + ~5 delete sites, each needing the
  correct predicate; trivially easy to miss one (e.g. a future create
  site) → silent leak or under-count. The delete sites are worse:
  `delete()` is bare, several callers don't have the tuple handy, and
  the promote/demote transitions are easy to miss. High regression
  surface for a security feature. **Rejected.**

### Path B — counter in `SessionTable`, check at new-flow (RECOMMENDED)

Increment in `install_with_protocol_with_origin` (the fresh-install
choke point) PLUS the `update_session` promote branch; decrement in
`remove_entry` (the removal sink) PLUS `demote_owner_rg`; check the
limit at the new-flow decision via a non-mutating query.

- **Pro:** removals are structurally exhaustive — every delete (clear /
  RST / fabric-cancel / expire / take) funnels through `remove_entry`,
  so the decrement cannot be forgotten by a future delete site. Fresh
  installs all funnel through `install_with_protocol_with_origin`.
  Read-only query fixes #2128 by construction. Check-at-new-flow avoids
  the per-packet self-drop (BLOCKER).
- **Con:** the "single choke point" claim is only true for *removals*
  and *fresh installs* — the in-place HA promote (`update_session`) and
  demote (`demote_owner_rg`) bypass the choke points and need TWO
  explicit, enumerated increment/decrement sites (§3.1, §3.4, §3.5).
  These are the only two such in-place transitions (audit §3.5), and the
  invariant test (§5.8) catches a missed one.

### Path C — SessionDelta stream as SSOT — REJECTED (§2.3)

Not a faithful local-removal record (`delete()` emits no Close delta);
would leak. Documented and rejected.

**Recommendation: Path B.** For deletes (the leak-up risk that would
silently block legitimate traffic), it is the only option where coverage
is structural (one removal sink) rather than site-enumeration that rots.
The two in-place HA transitions are explicitly enumerated and
test-guarded. It also fixes #2128 by making the read non-mutating.

---

## 5. Test plan

Unit/integration (Rust, in `userspace-dp`), MUST exercise the REAL
install/expire paths (existing tests manually call `session_created`,
which is exactly the gap #2134 names):

1. **Enforcement end-to-end (the security purpose):** drive `n`
   brand-new flows from one source IP through the real
   `install_with_protocol_with_origin` path (forward-flow origin) on a
   zone with `session_limit_src = n`; assert the first `n` install and
   the (n+1)-th NEW-FLOW check rejects with `session-limit-src` BEFORE
   any install attempt. Same for dst. (Drives the real install path, not
   the manual `session_created` the existing tests use — that is exactly
   the #2134 gap.)
2. **Established-flow does NOT self-drop (the r2 BLOCKER regression):**
   with `session_limit_src = n` and exactly `n` live flows from IP X
   (count == n), drive MANY subsequent DATA packets of those same `n`
   flows through the session-HIT / flow-cache path; assert NONE is
   dropped (the limit check must NOT run on established-flow packets).
   This test FAILS if the check is left in the per-packet screen stage.
3. **Decrement + evict-to-0 across the timer wheel (#2128):** create
   `n`, advance time, run `expire_stale_entries`; assert the count
   decrements and the map ENTRY is removed at 0 (assert no key for the
   IP after all expire). Then assert a new flow from that IP is admitted
   again.
4. **Decrement across explicit delete paths:** `clear`-style `delete()`,
   forward+reverse cancel, RST teardown — assert count → 0 and evict.
5. **#2128 phantom-zero regression:** run the new-flow check for an IP
   that NEVER creates a session (over-limit reject, or policy-deny) —
   assert NO map entry is created (counts map stays empty for that IP).
   FAILS on any read path using `entry().or_insert`.
6. **HA exclusion + promote + demote:** import a peer session via
   `upsert_synced_with_origin` (SyncImport) — assert NO local increment.
   PROMOTE it via the `update_session` promote branch — assert +1
   exactly. DEMOTE via `demote_owner_rg` — assert -1 and evict-at-0.
   This directly exercises the two in-place transition sites (§3.1/§3.4)
   that bypass the choke points; it FAILS if either explicit
   increment/decrement is omitted.
7. **Reverse + seed exclusion:** reverse-flow and MissingNeighborSeed
   installs do NOT increment (mirror the counted-class predicate).
8. **Idempotent re-install:** install same key twice (pre-clear path) —
   assert count is 1, not 2.
9. **Differential / invariant test (strongest guard):** after an
   arbitrary sequence of
   install/expire/delete/promote/demote/take_synced_local/refresh, the
   sum of per-IP src counts (and dst counts) EQUALS the number of live
   counted entries (`!is_reverse && !is_peer_synced() && !is_seed`) in
   the table. The sequence MUST include promote→demote cycles and a
   `update_session` refresh that preserves origin (to prove §3.5's
   is_reverse/origin invariant). Catches any missed transition.

Loss-cluster smoke (at /engineer time — HOT-PATH + SECURITY gate):

10. Configure `limit-session source-ip-based <n>` on the WAN/untrust
    screen profile of the loss userspace cluster. Flood from many
    distinct source IPs (and a single IP exceeding `n`). Assert:
    (a) the (n+1)-th NEW session from the over-limit IP is rejected —
    pin the assertion to the PER-REASON signal (`session-limit-src` via
    the screen event stream / `show security screen`), NOT the aggregate
    `screen_drops` counter which can't distinguish reasons;
    (b) established flows from an at-limit IP keep flowing (the §5.2
    regression at line rate);
    (c) RSS of the helper does NOT grow with distinct-IP churn (#2128);
    (d) `make cluster-deploy` then `apply-cos-config.sh` (deploy wipes
    CoS);
    (e) `make test-failover` passes — NOTE this proves zero-drop
    forwarding across failover but does NOT itself prove count integrity;
    the §5.9 invariant test is the count-integrity guard. MANDATORY
    since this touches session lifecycle + HA.

---

## 6. Resolved decisions + residual risks for reviewers

### 6.1 Check location — RESOLVED (was the BLOCKER)
The limit check moves to the new-flow / session-miss decision in
`poll_descriptor` (§3.2), so it fires once per new flow before the
session exists — never per-packet, never against a flow's own session.
The r1 borrow concern (threading `&SessionTable` into the screen stage)
is moot: the check now lives where `sessions` is already in scope.

### 6.2 Decrement placement vs the defensive pre-clear — RESOLVED
`remove_entry` returns `None` on the stale-handle / primary-key guards
(`mod.rs:663`/`:673`) — it RESTORES the mapping, does not remove. The
decrement is on the `Some(record)` success path ONLY (§3.1). A guard hit
never decrements.

### 6.3 HA promote/demote — RESOLVED (was a MAJOR open question)
Both in-place transitions are now explicit, enumerated sites (§3.1,
§3.5): increment in the `update_session` promote branch (`mod.rs:472`);
decrement in `demote_owner_rg` before the in-place flip (`install.rs:305`).
Demotion is NOT routed through remove+reinsert (that would tear down the
slab handle + four secondary indices on a per-failover loop — needless
regression). The audit (§3.5) confirms these are the ONLY two in-place
counted-class transitions; `update_session` refresh and failback refresh
preserve origin/is_reverse. The §5.9 invariant test guards against a
missed site. Reviewers: re-confirm the §3.5 audit is exhaustive.

### 6.4 Zone scoping — global per-IP vs per-zone-per-IP (residual)
The counter is global per-IP, compared against the *ingress zone's*
configured limit. Junos counts per-IP (not per-zone-per-IP), so global
matches Junos and the existing structure. If two zones configure
different limits, a src IP's global count is checked against whichever
zone the new flow arrived on. Recommend keeping global per-IP (simpler,
Junos-parity). Reviewers: confirm acceptable, or specify per-(zone,ip)
scoping (more state, less Junos-faithful).

### 6.5 NAT keying — RESOLVED (verified)
The count and the check both key on the ORIGINAL pre-NAT tuple: the
install key is `flow.forward_key` whose `src_ip`/`dst_ip` are the
client's pre-NAT addresses (`session/key.rs:13-14`), and the new-flow
check reads `flow.src_ip`/`flow.dst_ip` (same pre-NAT values the screen
stage uses, `poll_stages.rs:283-284`). Matches Junos per-source-IP
semantics. Reverse installs carry `is_reverse: true` and are excluded.

### 6.6 Per-worker scoping (§3.6) — residual, pre-existing
Per-worker count → worst-case N×limit dilution when one IP spreads
flows across N RX queues. Pre-existing (same under eBPF per-CPU map),
documented, not changed by this work. Reviewers: acceptable?

### 6.7 Counter overflow / underflow — RESOLVED
`u32` per-IP count, `saturating_add`/`saturating_sub`, bounded by
`max_sessions` (`DEFAULT_MAX_SESSIONS`, `mod.rs:22`). Saturation is the
right failure mode (never wrap). Map size ≤ 2 × max_sessions, evicted to
empty as sessions drain.

### 6.8 Reverse-direction read semantics — RESOLVED (note)
The new-flow check reads the forward direction's original src/dst against
the ingress zone's limit; reverse/reply flows are uncounted and the count
is over forward-direction original-source sessions only. A reply opening
toward the responder is itself a forward flow on its own ingress zone and
counts there if that zone configures a limit. Normal traffic is
unaffected.

---

## 7. Files touched (implementation preview — for scope sizing only)

- `userspace-dp/src/session/mod.rs` — `session_limit_active` flag +
  two count maps on `SessionTable`; decrement in `remove_entry`
  (`mod.rs:645`, success path) + increment in the `update_session`
  promote branch (`mod.rs:472`); non-mutating query methods
  (`session_limit_src_count`/`_dst_count`); a setter for the OFF-gate;
  evict-on-zero.
- `userspace-dp/src/session/install.rs` — increment in
  `install_with_protocol_with_origin` (`:160`, next to the Open-delta
  push); decrement in `demote_owner_rg` (`:305`, before the in-place
  origin flip).
- `userspace-dp/src/screen/session_limit.rs` — relocate the tracker
  logic into `SessionTable` (or keep the type but make its READ path
  non-mutating, `get().copied()` — #2128); retire the
  `session_created`/`session_expired`/`check_src`/`check_dst` mutators
  here once the count moves to SessionTable.
- `userspace-dp/src/screen/mod.rs` — remove the per-packet session-limit
  sub-check from `check_packet_with_zone_id` (`:343-358`); retire the
  dead `session_created`/`session_expired` wrappers; add an
  `any_session_limit_configured()`-style helper for the OFF-gate (or
  reuse `has_advanced_features`).
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs` — add the new-flow
  session-limit check on the session-MISS path (~`:746+`), reading the
  SessionTable query + emitting the screen-drop event/counter.
- `userspace-dp/src/afxdp/worker/loop_body/mod.rs` — set
  `session_limit_active` when the forwarding/profile snapshot is applied
  (~`:318`).
- `userspace-dp/src/screen/tests.rs` + `session/tests.rs` + new
  integration tests — exercise real install/expire/promote/demote paths
  (§5), including the established-flow regression and the invariant test.
- Docs: screen / session-limit design doc + `session/README.md` (the
  counted-class invariant) + `_Log.md`.

NO Go-side change (the compiler already plumbs
`LimitSession.SourceIPBased/DestinationIPBased` →
`session_limit_src/dst`, `pkg/config/compiler_security.go:393-406`).
NO eBPF change (retired path).

---

## 8. Verdict sought

PLAN-READY for Path B as revised in r2: counter in `SessionTable`
maintained at the install/remove sinks PLUS the two enumerated in-place
HA transitions, OFF-gated for zero cost when unconfigured, with the
limit CHECK relocated to the new-flow decision (fixing the per-packet
self-drop) and the read made non-mutating (fixing #2128). One PR fixes
#2134 and #2128 together.
