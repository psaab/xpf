# Plan of action — #2134 (wire screen session-limit lifecycle) + #2128 (evict-on-zero leak)

- **Revision:** r1 (draft, pre-review)
- **Issues:** #2134 (HIGH — security feature non-functional), #2128 (HIGH — memory-DoS leak)
- **Branch:** `research/2128-2134-screen-session-limit`
- **Mode:** `/research` — STOPS at PLAN-READY. No code, no PR, no production-source edits.
- **Base:** origin/master @ `8260727af`

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

### 2.1 Create sites — there is ONE choke point

Every new local session is installed through
`SessionTable::install_with_protocol_with_origin`
(`session/mod.rs:749`). Production callers (7, across 5 files):

| File:line | Origin | Notes |
|---|---|---|
| `poll_descriptor/mod.rs:487` | LocalMiss | local-delivery |
| `poll_descriptor/mod.rs:1318` | ForwardFlow | **brand-new forward flow** (primary) |
| `poll_descriptor/mod.rs:1520` | ReverseFlow | reverse half of new flow |
| `poll_descriptor/mod.rs:2641` | MissingNeighborSeed | transient ARP-seed |
| `forwarding/mod.rs:1112` | (re-install) | materialize synced→local |
| `shared_ops.rs:743` | ReverseFlow | reverse-from-forward-match |
| `session/mod.rs:730` | (wrapper) | `install_with_protocol` thin wrapper |

HA-synced imports do **not** go through this function — they use
`upsert_synced_with_origin` (`session/mod.rs:834`), a separate sink.

`install_with_protocol_with_origin` already computes the exact
"is-this-a-locally-counted-session" predicate, to gate its HA Open
delta (`session/mod.rs:795`):

```rust
if !metadata.is_reverse
    && !origin.is_peer_synced()
    && !origin.is_transient_local_seed()
{
    self.push_delta(SessionDelta { kind: Open, ... });
}
```

`is_peer_synced()` = `SyncImport | SharedMaterialize | WorkerLocalImport`
(`session/entry.rs`). `is_transient_local_seed()` = `MissingNeighborSeed`.
This predicate is precisely the set of sessions that should count toward
the local screen limit: locally-admitted, forward-direction, real (not
seed), not imported from the peer.

### 2.2 Delete sites — there is ONE choke point

Every removal funnels through `SessionTable::remove_entry`
(`session/mod.rs:1331`). Callers:

| File:line | Trigger |
|---|---|
| `session/mod.rs:503` (`expire_stale_entries`) | timer-wheel stale expiry (primary) |
| `session/mod.rs:774` (`install_*`) | defensive pre-clear before insert (same key) |
| `session/mod.rs:860` (`upsert_synced_*`) | defensive pre-clear before upsert |
| `session/mod.rs:1200` (`delete`) | explicit delete (clear, RST teardown, fabric-cancel, promote-purge) |
| `session/mod.rs:1236` (`take_synced_local`) | materialize synced→local |

`remove_entry` reads the full `record` (key with src/dst IP, metadata
with `is_reverse`, `origin`) before freeing the slab slot — so it has
everything needed to decide whether this removal should decrement, and
which (src,dst).

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

## 3. Design — chosen approach (Path B: SessionTable owns the count)

Put the per-IP local-session counters **inside `SessionTable`**, driven
by the two choke points, and let the screen check **read** them.

### 3.1 Where the counter lives

Add to `SessionTable` (`session/mod.rs`) a small counter type (reuse
the existing `SessionLimitTracker` shape, relocated, OR a private
`session_limit_counts: { src: FxHashMap<IpAddr,u32>, dst:
FxHashMap<IpAddr,u32> }`). It is maintained by:

- **Increment** in `install_with_protocol_with_origin`, gated by the
  EXACT existing Open-delta predicate
  (`!is_reverse && !origin.is_peer_synced() &&
  !origin.is_transient_local_seed()`), AND only when the insert
  actually happened (the function already returns `false` early on
  `len() >= max_sessions`, before any state change — so the increment
  goes on the success path after the slab insert).
- **Decrement** in `remove_entry`, on the SAME predicate read from the
  removed `record` (`!record.entry.metadata.is_reverse &&
  !record.entry.origin.is_peer_synced() &&
  !record.entry.origin.is_transient_local_seed()`), only when an entry
  was actually removed (the early `None` returns — stale-handle /
  primary-key guard — must NOT decrement). **Evict the map entry the
  moment its count reaches 0** (#2128's correctness requirement
  applied to the live counter), via the existing
  `saturating_sub`-then-`remove`-at-0 logic from
  `session_limit.rs:47`.

### 3.2 Where the screen check reads the count

`check_src`/`check_dst` move from `ScreenState` to a **read-only query
on `SessionTable`** (or `ScreenState` borrows a read-only view). The
screen check (`stage_screen_check`, `poll_stages.rs:240`) gains an
immutable `&SessionTable` parameter. At its call site
(`poll_descriptor/mod.rs:159`) `sessions` is in scope and NOT yet
borrowed mutably (first mut use is `resolve_flow_session_decision` at
line ~258), so a shared borrow that ends before the mut borrow is
NLL-clean.

The read becomes non-mutating (fixes #2128): `src_counts.get(&ip)
.copied().unwrap_or(0) >= limit`. No phantom zero entries — the map is
only ever populated by a real increment, only ever shrunk to empty by
decrement-to-zero eviction. The map size is bounded by the number of
distinct IPs with at least one live local session (itself bounded by
`max_sessions`).

### 3.3 Hot-path cost

- **Per new session (create):** one `FxHashMap` upsert for src + one
  for dst, under the predicate. Same cost as the existing Open-delta
  push (already on this path). No new lock (SessionTable is
  single-worker-owned; no `Mutex`). Negligible.
- **Per removal (expire/delete):** one `get_mut` + possible `remove`
  for src + dst. Already inside `remove_entry` which does several
  index cleanups; this is one more cheap map op. No new lock.
- **Per packet (screen check):** `check_src`/`check_dst` were already
  called per packet on the screen path for IPs in screened zones; the
  change makes them READ-only (`get` instead of `entry().or_insert`),
  which is *cheaper* than today (no insert). No regression.
- **No allocation on the steady-state hot path** (FxHashMap reuses
  buckets; entries created on first session for an IP, freed at 0).

### 3.4 HA-synced sessions — NOT counted (correct)

Synced imports use `upsert_synced_with_origin` (separate sink, never
calls `install_with_protocol_with_origin`), and even when promoted the
Open-delta predicate (and our increment predicate) only fires on
`was_peer_synced && !origin.is_peer_synced()` (promotion to local
ownership). So:

- A standby node importing peer sessions does NOT inflate its local
  per-IP count — correct: those sessions were screened by the *active*
  owner, not locally.
- On failover, when the standby promotes a synced session to local
  (`upsert_synced_with_origin` / `materialize_transient_synced_local`),
  it transitions to a locally-owned session. The increment must fire on
  that promotion (the same `was_peer_synced && !is_peer_synced()`
  branch that emits the Open delta — `session/mod.rs:1014`) so the
  newly-owned sessions count post-failover. Symmetric: when a local
  session is demoted to synced (`demote_owner_rg`,
  `session/mod.rs` sets origin = SyncImport), the count must DECREMENT.
  **§6.3 covers the promote/demote count transitions** — this is the
  subtle HA correctness surface and the main thing reviewers must
  scrutinize.

### 3.5 Per-worker scoping (unchanged, documented)

Each worker owns its own `SessionTable` and screened sessions are
steered to a worker by RX-queue hash. The per-IP count is therefore
per-worker — a single source IP's sessions may spread across N worker
queues, so the *effective* limit is up to N×limit in the worst spread.
This matches today's per-worker `ScreenState` design and the eBPF-era
per-CPU-map behavior; it is a pre-existing property, not introduced by
this change. Documented in the screen design doc; flagged for reviewers
(§6.4) but NOT a blocker (Junos on multi-core SPC behaves similarly;
exact-flow steering keeps a given 5-tuple on one queue).

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

### Path B — counter in `SessionTable`, screen reads it (RECOMMENDED)

Increment in `install_with_protocol_with_origin`, decrement in
`remove_entry`, both at the single choke point with the existing
predicate; screen check reads a non-mutating query.

- **Pro:** ONE create choke point + ONE delete choke point, both
  already computing the exact predicate. Future create/delete sites
  are automatically covered (they all funnel through the choke points).
  Decrement-on-removal is automatic and exhaustive (every removal,
  including clear/RST/fabric-cancel, goes through `remove_entry`).
  Read-only screen query fixes #2128 by construction.
- **Con:** moves `check_src`/`check_dst` out of `ScreenState` (small
  refactor); threads `&SessionTable` into `stage_screen_check` (one new
  param). Promote/demote count transitions need explicit handling
  (§6.3). Per-worker scoping unchanged.

### Path C — SessionDelta stream as SSOT — REJECTED (§2.3)

Not a faithful local-removal record (`delete()` emits no Close delta);
would leak. Documented and rejected.

**Recommendation: Path B.** It is the only option where "did we cover
every create/delete site" is answered structurally (choke points)
rather than by enumeration that rots. It also fixes #2128 as a
side-effect of making the read non-mutating.

---

## 5. Test plan

Unit/integration (Rust, in `userspace-dp`), MUST exercise the REAL
install/expire paths (existing tests manually call `session_created`,
which is exactly the gap #2134 names):

1. **Enforcement end-to-end (the security purpose):** drive `n`
   brand-new flows from one source IP through the real
   `install_with_protocol_with_origin` path (forward-flow origin) on a
   zone with `session_limit_src = n`; assert the first `n` install and
   the (n+1)-th screen check returns `Drop("session-limit-src")`
   BEFORE any install attempt. Same for dst.
2. **Decrement + evict-to-0 across the timer wheel:** create `n`, then
   advance time and run `expire_stale_entries`; assert the count
   decrements and the map ENTRY is removed at 0 (#2128 — assert
   `src_counts.is_empty()` / no key for the IP after all expire). Then
   assert a new flow from that IP is admitted again.
3. **Decrement across explicit delete paths:** `clear`-style
   `delete()`, forward+reverse cancel, RST teardown — assert count
   returns to 0 and entry evicts.
4. **#2128 phantom-zero regression:** run the screen check for an IP
   that NEVER creates a session (e.g. policy-deny / stateless packet) —
   assert NO map entry is created (`src_counts` stays empty). This test
   FAILS on current master and on any read path that uses
   `entry().or_insert`.
5. **HA exclusion:** import a peer session via
   `upsert_synced_with_origin` (SyncImport) — assert it does NOT
   increment the local count. Then PROMOTE it to local — assert the
   count increments exactly once. Then DEMOTE — assert it decrements.
6. **Reverse + seed exclusion:** reverse-flow and MissingNeighborSeed
   installs do NOT increment (mirror the Open-delta predicate).
7. **Idempotent re-install:** install same key twice (pre-clear path) —
   assert count is 1, not 2.
8. **Differential / invariant test:** after an arbitrary sequence of
   install/expire/delete/promote/demote, the sum of per-IP counts
   equals the number of live locally-counted sessions
   (`!is_reverse && !is_peer_synced() && !is_seed`) in the table.
   This is the strongest guard against a missed choke-point path.

Loss-cluster smoke (at /engineer time — HOT-PATH + SECURITY gate):

9. Configure `limit-session source-ip-based <n>` on the WAN/untrust
   screen profile of the loss userspace cluster. Flood from many
   distinct source IPs (and a single IP exceeding `n`). Assert:
   (a) the (n+1)-th session from the over-limit IP is rejected
   (`show security screen` / screen-drop counter), (b) RSS of the
   helper does NOT grow with distinct-IP churn (the #2128 bound),
   (c) `make cluster-deploy` then `apply-cos-config.sh` (deploy wipes
   CoS), (d) `make test-failover` passes (promote/demote count
   transitions don't corrupt forwarding) — MANDATORY since this touches
   session lifecycle + HA.

---

## 6. Open questions / risks for reviewers

### 6.1 Borrow feasibility of `&SessionTable` into the screen check
Confirmed `sessions` is unborrowed at `poll_descriptor/mod.rs:159`
(first mut use ~258). NLL should allow a shared borrow that ends before
the mut borrow. Reviewers: confirm no hidden re-borrow forces a
conflict (e.g. if `screen` and `sessions` are fields of one struct).
They are separate `&mut` params today, so this should be clean.

### 6.2 Decrement placement vs the defensive pre-clear
`remove_entry` returns `None` on the stale-handle / primary-key guards
(it RESTORES the mapping and does not actually remove). Decrement MUST
be on the `Some(record)` success path only, AFTER the primary-key guard
passes — never on the guard's early `None`. Otherwise a guard hit would
wrongly decrement.

### 6.3 HA promote/demote count transitions (the hard part)
- Promote synced→local (`upsert_synced_with_origin` /
  `materialize_transient_synced_local`): increment on the
  `was_peer_synced && !is_peer_synced()` branch.
- Demote local→synced (`demote_owner_rg` sets origin = SyncImport
  WITHOUT going through remove_entry): this mutates origin in place,
  so the choke-point decrement does NOT fire. Must add an explicit
  decrement there, or route demotion through remove+reinsert.
  **Reviewers: is in-place origin mutation the only path that changes
  the counted-class without hitting a choke point? Audit
  `demote_owner_rg` and any other in-place origin/is_reverse mutation.**

### 6.4 Zone scoping — global per-IP vs per-zone-per-IP
Current `SessionLimitTracker` is global per-IP, compared against the
*ingress zone's* configured limit. Junos counts per-IP (not
per-zone-per-IP). Keeping it global matches Junos and the existing
structure. BUT: if two zones configure different limits, the global
count is checked against whichever zone the packet arrived on. Is that
acceptable, or should the count be scoped per (zone, ip)? Recommend
keeping global per-IP (simpler, matches today + Junos); reviewers to
confirm.

### 6.5 Counter overflow / underflow
`u32` per-IP count, `saturating_add`/`saturating_sub`. max_sessions
bounds it. Saturation is the right failure mode (never wrap).

### 6.6 Per-worker scoping (§3.5)
Pre-existing; documented, not changed. Reviewers: acceptable?

---

## 7. Files touched (implementation preview — for scope sizing only)

- `userspace-dp/src/session/mod.rs` — counter state on SessionTable;
  increment in `install_with_protocol_with_origin` + promote branch;
  decrement in `remove_entry` + demote path; read-only query method;
  evict-on-zero.
- `userspace-dp/src/screen/session_limit.rs` — make read non-mutating
  (`get().copied()`), or relocate the count into SessionTable and
  retire this tracker's maps (keep the type as a thin query if useful).
- `userspace-dp/src/screen/mod.rs` — `check_src`/`check_dst` read from
  the SessionTable view; retire the dead `session_created`/`expired`
  wrappers (or keep as test shims clearly marked).
- `userspace-dp/src/afxdp/poll_stages.rs` — thread `&SessionTable`
  into `stage_screen_check`.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs` — pass `sessions`
  to the screen-check call.
- `userspace-dp/src/screen/tests.rs` + new integration tests —
  exercise real install/expire paths (§5).
- Docs: screen / session-limit design doc + `_Log.md`.

NO Go-side change (the compiler already plumbs
`LimitSession.SourceIPBased/DestinationIPBased` →
`session_limit_src/dst`). NO eBPF change (retired path).

---

## 8. Verdict sought

PLAN-READY for Path B (wire the lifecycle at the install/remove choke
points + non-mutating read = fixes #2134 and #2128 together), or a
reviewer-driven revision of the HA promote/demote handling (§6.3) and
zone-scoping (§6.4).
