# #965: bucketed timer-wheel session GC (replace O(N) scan)

Plan v11 — 2026-04-29. Addresses Codex round-10 wording fixes
(task-mok33z3b-yg8x1d):

α. CoS gate ambiguity resolved. The per-class table listed P=12
   minimum throughput for every row, but the trailing prose said
   "Hard gate on iperf-c only", which left CI behavior unclear.
   Now: every P=12 row is a blocking gate (shaped-rate thresholds
   at ≈ 90 % of each class's shape). P=1 stays as counter-only
   smoke for non-iperf-c classes (single-stream variance makes a
   hard P=1 throughput gate brittle for low-shape classes);
   iperf-c keeps its historical P=1 ≥ 6 Gb/s hard gate.

β. Stale top-of-doc version banner caught up with the round-9
   work. The previous commit said "Plan v9 / round-8 fixes" while
   the file already had v9-and-v10 changes; bumped to v11 with a
   proper changelog stack.

v10 — Addresses Codex round-9 wording fixes
(task-mok2wa0n-cvx3es):

i. CoS smoke gate enumerated per-class against the actual
   `test/incus/cos-iperf-config.set` fixture. Each iperf-{a,b,c,
   d,e,f} class plus best-effort gets its own P=12 throughput
   gate scaled to ≈ 90 % of its shape (iperf-c at 88 %, the
   historical 25 g → 22 Gb/s smoke).

ii. v8 changelog header rewritten to reference the corrected
   sub-tick lag bounds (today ≤ 1 s; wheel ≤ 2 s; additional
   deviation < 1 wheel-tick) instead of the wrong "preserves
   the existing 1-s lag bound" prose.

iii. "Not popped during this call" wording tightened to "not
   popped during this BUCKET drain" both in the inline drain
   comment and the v8 changelog summary, with explicit note
   that re-pushes into LATER buckets the outer multi-tick
   catch-up loop visits ARE popped within the same call.

v9 — Addresses Codex round-8 wording fixes
(task-mok24765-mmf95n; no blocking findings, all substantive
claims verified correct):

a. Sub-tick lag wording now gives explicit absolute bounds
   (today's gated scan ≤ 1 s; wheel ≤ 2 s) and frames the
   wheel's contribution as "additional deviation < 1 wheel-tick"
   instead of "same worst-case lag".

b. Stale "Drain in place into a local Vec" comment replaced with
   "Drain the bucket allocation-free" to match the v8 no-Vec
   redesign.

c. "Not popped during this call" tightened to "not popped during
   this bucket drain" with an explicit note that re-pushes into
   later buckets WILL be popped within the same multi-tick
   catch-up call (intentional and correct).

v8 — Addresses Codex round-7 (task-mok1ojg3-0esulj):

1. Acceptance gate 4a workload was self-contradictory: "10 %
   touched per second" produces K ≈ 5K (every active session pushes
   to every bucket once per 256 s), not K ≈ 977. Redefined 4a as a
   Poisson touch process tuned to T_active = 5 (~1000 touches/s
   spread across 50K sessions), which actually matches the
   N × T_active / 256 = 977 model and the K ≤ 1500 bound.

2. Per-second-touch test classification was wrong: under sustained
   per-second touch on every session, popped entries are ALL stale
   duplicates. So `entries_re_bucketed = 0`, not = N;
   `entries_dropped_stale ≈ K`, not `≈ N × 255`. Test rewritten
   with the correct classification.

3. Drain pseudocode allocated `Vec::with_capacity(due_count)` per
   pop, contradicting the "no per-second Vec allocation" claim.
   Redesigned: snapshot bucket length, iterate via `pop_front`
   exactly that many times, no scratch buffer needed. Re-pushed
   entries land at the back of the VecDeque and are not popped
   during this BUCKET drain (the next wheel rotation handles
   same-bucket re-pushes; re-pushes into later buckets are
   processed within the same multi-tick catch-up call).

4. "No production caller can observe the difference" softened to
   "additional deviation < 1 wheel-tick" with explicit absolute
   bounds — see point (a) above for the corrected wording.

Earlier rounds remain in effect: round-3 (bucket-helper / pop
race + alias `WheelEntry`), round-4 (memory math + alias borrow
shape), round-5 (per-tick cost model uses K not N/256), round-6
(sub-tick lag documentation, mostly-idle table arithmetic, single
acceptance-gate spec, K-bound assertions in unit test).


## Investigation findings (Claude, on commit 08ff1838)

`SessionTable.expire_stale_entries` at `userspace-dp/src/session.rs:279-340`
runs once per `SESSION_GC_INTERVAL_NS = 1s`. Inside that gate it does:

```rust
let stale = self.sessions.iter()
    .filter_map(|(key, entry)| {
        if now_ns.saturating_sub(entry.last_seen_ns) > entry.expires_after_ns {
            Some(key.clone())
        } else { None }
    })
    .collect::<Vec<_>>();
// then iterate stale and remove each
```

This is O(N) over the entire `FxHashMap<SessionKey, SessionEntry>`
every tick. At 1M concurrent sessions (a realistic 100G workload):

- Hash-map iter + entry-tuple copy ≈ 100 ns/entry → ~100 ms per tick.
- Two `Vec` allocations per tick (`stale`, `expired_entries`).
- The hot worker thread BLOCKS for those 100 ms — every queue
  starves, mouse-latency p99 jumps to >100 ms, and the XSK RX rings
  back-pressure into the kernel.

This is the "stop the world" GC pause #965 calls out.

### Where last_seen / expires_after are written

- `install_with_protocol` (L484) — initial insert.
- `upsert_synced` (L554) — HA peer sync insert.
- `update_session` (L612) — protocol-specific update.
- `lookup_with_origin` (L390) — every read also touches last_seen
  (this is the most frequent path; ~per session-miss-cached-hit).
- `touch` (L274) — flow-cache amortized keepalive.
- `refresh_local` / `refresh_for_ha_activation` /
  `refresh_for_ha_transition` — HA state-machine paths.

Any change to expiration management has to thread these write sites.

## Approach

Add a **bucketed timer wheel** that mirrors the `sessions` HashMap.
On insert / touch / refresh, push the key into the bucket whose
index = `(last_seen_ns + expires_after_ns) / TICK_NS` modulo the
wheel size. On GC tick, pop one bucket and walk only those keys.

The wheel is purely an *index*; the authoritative state still lives
in `sessions: FxHashMap<SessionKey, SessionEntry>`. We do NOT
require #964's slab + integer handle refactor for #965 to land.

### Wheel shape

```rust
const WHEEL_TICK_NS: u64 = 1_000_000_000;        // 1 s
const WHEEL_BUCKETS: usize = 256;                // 256 s window
const WHEEL_MASK: u64 = (WHEEL_BUCKETS as u64) - 1; // 0xFF

/// What a wheel bucket holds. The `scheduled_tick` is the
/// expiration tick at the moment of bucketing — used by `pop`
/// to distinguish stale duplicates (`scheduled_tick !=
/// entry.wheel_tick`) from genuinely-due entries
/// (`scheduled_tick == entry.wheel_tick`).
pub(crate) struct WheelEntry {
    pub key: SessionKey,
    pub scheduled_tick: u64,
}

pub(crate) struct SessionWheel {
    /// 256 buckets indexed by `expiration_tick & WHEEL_MASK`.
    /// Each bucket holds entries whose `scheduled_tick` modulo
    /// 256 equals the bucket index.
    buckets: Box<[VecDeque<WheelEntry>; WHEEL_BUCKETS]>,
    /// Tick that bucket index 0 represents on the *current*
    /// wheel revolution. Advanced lazily as `cursor_tick`
    /// crosses bucket boundaries.
    base_tick: u64,
    /// Most-recent processed tick. Strictly < the live `now_tick`
    /// once initialized. Initialized lazily on the first
    /// insert/touch/expire that observes a `now_ns`.
    cursor_tick: u64,
    /// `false` until the first observation of `now_ns`. Until then
    /// every wheel mutation resets cursor/base from `now_ns`. This
    /// avoids the catastrophe of `cursor_tick = 0` being many
    /// years behind `now_tick = uptime_secs` on the first GC call.
    initialized: bool,
}
```

### Cursor / base initialization (Codex finding #1)

`SessionTable::new()` does not have a `now_ns`. The wheel must be
created in an "uninitialized" state and lazily initialize on the
first observation of `now_ns` from any of the touch/insert/expire
paths:

```rust
fn wheel_observe(&mut self, now_ns: u64) {
    if !self.wheel.initialized {
        let now_tick = now_ns / WHEEL_TICK_NS;
        self.wheel.base_tick = now_tick;
        self.wheel.cursor_tick = now_tick;
        self.wheel.initialized = true;
    }
}
```

Every public method that takes `now_ns` calls `wheel_observe(now_ns)`
before any wheel push or pop. Test:
`first_gc_with_large_monotonic_now_doesnt_walk_billions_of_buckets`.

### Bucket-index calculation (Codex round-3 finding #1 — absolute, not relative)

There is exactly ONE bucket helper. It takes an absolute target
tick (the tick the entry should be checked at) and returns
`(target_tick & WHEEL_MASK) as usize`. Both `push` and `pop` use
the same formula.

```rust
const FAR_FUTURE_OFFSET: u64 = WHEEL_BUCKETS as u64 - 1;

#[inline]
fn bucket_for_tick(tick: u64) -> usize {
    (tick & WHEEL_MASK) as usize
}

/// Compute the absolute target tick at which an entry with the
/// given expiration_ns should be checked, given the current
/// `now_ns`. Returns `now_tick + delta.min(FAR_FUTURE_OFFSET)`.
/// An entry with delta >= WHEEL_BUCKETS lands FAR_FUTURE_OFFSET
/// ticks ahead and gets re-checked there (still-alive case
/// triggers re-bucketing in pop).
fn target_tick_for(now_ns: u64, expiration_ns: u64) -> u64 {
    let now_tick = now_ns / WHEEL_TICK_NS;
    let expiration_tick = expiration_ns / WHEEL_TICK_NS;
    let delta = expiration_tick.saturating_sub(now_tick);
    now_tick + delta.min(FAR_FUTURE_OFFSET)
}
```

Use absolute target ticks throughout. The `target_tick` is what's
written into `entry.wheel_tick` and `WheelEntry.scheduled_tick`.
At pop time, `self.wheel.cursor_tick` advances absolutely; the
bucket index is just `(cursor_tick & WHEEL_MASK)`. The
"exactly 256s" case lands at `now_tick + 255`, which the wheel
will revisit only after a full rotation — distinct from the
current bucket. Test: `wheel_handles_exact_256s_timeout`.

#### Sub-tick expiration semantics (Codex round-6 #1)

The pop loop is `while cursor_tick < now_tick { pop bucket; cursor++ }`,
and `target_tick = floor((last_seen + expires_after) / WHEEL_TICK_NS)`.
A session expiring at `last_seen + expires_after + 1ns` has
`target_tick = (last_seen + expires_after) / TICK_NS` and
`now_tick = (last_seen + expires_after + 1) / TICK_NS` —
when the +1 ns does not cross a tick boundary, both are equal,
so the bucket containing this entry is NOT popped on this call;
it will be popped on the next tick (cursor_tick advances when
now_tick advances by ≥ 1).

So the wheel introduces **up to one wheel-tick (1 s) of lag**
between the exact instant `last_seen + expires_after + 1 ns` and
the wheel's detection of the expiration.

Why this is a non-regression in production: the existing
`expire_stale_entries` is gated by

```rust
if now_ns.saturating_sub(self.last_gc_ns) < SESSION_GC_INTERVAL_NS {
    return Vec::new();
}
```

with `SESSION_GC_INTERVAL_NS = 1 s`, so today's scan already has
up to ~1 s of lag in production. The wheel can add **up to one
more tick** on top of that depending on the relative phase of
the entry's `target_tick` vs. the wheel cursor at expiration
time. So the honest bound is:

  - Today's scan: absolute expiry-detection lag ≤ 1 s
    (`SESSION_GC_INTERVAL_NS`).
  - Wheel: absolute expiry-detection lag ≤ 2 s (existing 1 s
    gate lag + up to one wheel-tick of phase deviation).
  - Additional deviation introduced by the wheel vs. today:
    **strictly less than one wheel-tick = 1 s.**

That additional ≤1 s deviation is the only behavioral change
the wheel introduces. No documented user-visible behavior is
specified at sub-second precision (timeout knobs are second-
granular in Junos config), so the deviation is below the
resolution at which any operator can observe it; but the
correct phrasing is "additional deviation < 1 tick" / "absolute
expiry can approach 2 s in the worst phase", not "same worst-
case lag".

The existing `expiry_boundary_strict_greater_than` test asserts
the exact-boundary case (`now == last_seen + expires_after`,
which is NOT expired under either today's `>` semantics or the
wheel). It continues to pass. A sibling test
`wheel_lags_today_subtick_by_at_most_one_tick` asserts the
documented bound: at `now == last_seen + expires_after + 1 ns`
the wheel reports not-yet-expired, but at `now == last_seen +
expires_after + WHEEL_TICK_NS + 1` (one tick past the expiration
ceiling) the wheel does report expired. This guards the
documented semantics from drifting silently.

### Coverage of long-lived sessions

The default established-TCP timeout in `userspace-dp/src/session.rs`
is 300 s (`DEFAULT_TCP_SESSION_TIMEOUT_NS = 300_000_000_000`), which
is already larger than the 256-s wheel window. Operators can set
arbitrarily long per-protocol timeouts (Junos allows up to days).
Any timeout that exceeds the 256-s window lands in the far-future
bucket. When that bucket is popped (256 s after insertion),
`wheel_pop_one_bucket` re-checks the entry's actual
`last_seen + expires_after` against `now_ns`, finds it still in the
future, and re-buckets via the same logic. Cost: one HashMap
lookup + one push per long session per 256 s.

### Push-to-wheel: when, and the duplicate bound (Codex round-2 #2)

When `install` / `upsert_synced` / `lookup_with_origin` / `update_session`
/ `refresh_*` updates `last_seen_ns` or `expires_after_ns`, we may
need to add a wheel entry. To bound duplicates we throttle:

```rust
let new_expiration_tick = target_tick_for(
    now_ns,
    entry.last_seen_ns + entry.expires_after_ns,
);
if new_expiration_tick != entry.wheel_tick {
    entry.wheel_tick = new_expiration_tick;
    let bucket = bucket_for_tick(new_expiration_tick);
    self.wheel.buckets[bucket].push_back(WheelEntry {
        key: actual_key.clone(),
        scheduled_tick: new_expiration_tick,
    });
}
// Same-tick touches: no push.
```

The wheel push happens only when the expiration TICK changes. A
session touched 1000 times within the same second produces ZERO
extra wheel entries.

Note: this snippet is the throttle *condition* in isolation. In a
real call site (e.g. `update_session`, `lookup_with_origin`), the
`&mut SessionEntry` borrow on `self.sessions` MUST be scoped to
end before the `self.wheel.buckets[...]` push, or the borrow
checker will reject the compound `&mut self` aliasing. See the
alias correctness section below for the full borrow-scoped shape.

#### Memory math (corrected per Codex rounds 2 + 4)

Measured (`rustc 1.x`, 64-bit):
- `size_of::<SessionKey>()` = **40 B** (u8 + u8 + 2×IpAddr(17 B) + u16 + u16, align 2)
- `size_of::<WheelEntry>()` = **48 B** (40 B SessionKey + u64 + alignment padding to 8 B, align 8)

Live wheel storage is bounded by the wheel itself: the wheel only
holds entries whose `scheduled_tick ∈ [cursor_tick, cursor_tick +
FAR_FUTURE_OFFSET]`, i.e. at most 256 distinct future-tick slots.
For each session, throttling caps push frequency at one push per
TICK in which `(last_seen + expires_after)` produces a new
`scheduled_tick`. Stale entries (where the canonical `wheel_tick`
has moved on) are not deleted eagerly — they sit in the wheel until
their bucket is popped, at which point the lazy-delete discriminator
drops them in O(1).

Therefore:

  live_wheel_entries ≤ Σ over live sessions of
                       min(distinct_active_touch_ticks_in_last_256s, 256)
                       + recently-superseded duplicates not yet drained

The drain time of a stale duplicate is bounded by one wheel
rotation: ≤ 256 s after it was superseded. So the steady-state
upper bound is ≈ N_sessions × 256 entries (the absolute ceiling),
and the realistic value is much smaller because most sessions are
idle and touch in <<256 distinct ticks.

| Workload | Active touch ticks / sess | Live entries at 100K sessions | Memory |
|---|---|---|---|
| Idle TCP keepalive (rare touch) | ~1 | ~100K | ~4.8 MB |
| Mostly-idle session table | ~3–5 | ~300K–500K | ~14–24 MB |
| Active TCP throughput (touch ≤1/s) | up to 256 | ≤25.6M | ≤1.2 GB |
| Pathological (every session, every tick) | 256 | 25.6M | 1.2 GB |

At 1M sessions × 256 × 48 B the absolute ceiling is **~12.3 GB**.
That ceiling is reached only when every session is touched in 256
distinct seconds inside a 256-s window, which already implies a 1M-
session steady state with continuous activity. The realistic value
is well under 100 MB.

This is honest: the wheel storage cost is bounded by `N × WHEEL_BUCKETS`,
not by session lifetime. The earlier draft's "linear with
lifetime_secs" claim was wrong — once GC keeps up with the wheel
rotation, stale duplicates are drained within 256 s and don't
accumulate over the full session lifetime.

#964 (slot-handle compaction) replaces the 40-B `SessionKey` with a
~4-B slot index, taking `WheelEntry` from 48 B to ~16 B — roughly
**3× smaller** (not 30×; the 30× figure assumed the 248-B miscount).
That follow-up is meaningful at scale: at 1M sessions × per-second
touch, 12.3 GB drops to ~4 GB. Active deletion (per Out of scope)
takes that further by bounding live entries to N (one per
session) — at 1M × 16 B = ~16 MB. Either follow-up is the right
venue for solving the ceiling at the per-second-touch worst case;
#965 alone delivers the realistic-deployment win and the
per-tick-bound shape, with a documented memory ceiling that grows
proportionally to N × WHEEL_BUCKETS under adversarial touch
patterns.

**Decision**: ship #965 with the corrected algorithm + this
honest memory math. Document the "every-session-touched-every-tick
at 1M scale" worst case as the boundary. The bigger #964 slab
refactor is the right venue for solving the duplicate-storage
size; #965 alone delivers the "no Stop-the-World" win for the
realistic case.

### Per-tick GC work — the algorithm in full

Per Codex findings #2/#3/#5/#8: cap-vs-uncapped, deferred-tail
semantics, alias-key correctness, and the off-by-1-ns expiry
boundary all need explicit pseudocode.

Decision per Codex finding #2: **no per-tick cap**. The cap was a
flawed knob — at 5K/tick when due-rate is ≥5K/s the backlog grows
unbounded. We pay the bucket cost. Multi-level wheels and active
deletion are deferred to follow-ups (see Out of scope).

> **Superseded in part by #18780 (2026-11-08).** One
> `expire_stale_entries_ha` CALL is now budgeted (`EXPIRY_PASS_MAX_POPS`
> 4096 pops, `EXPIRY_PASS_MAX_REAPS` 256 reaps plus pair completions; see
> `userspace-dp/src/session/README.md`, "Per-call budget"). The objection
> above is to a cap per TICK: a tick is 1 s, so a 5K/tick cap drains at most
> 5K rows/s and falls behind any faster due rate. #18780's cap is per CALL,
> and a cut call sets `expiry_backlog` so the NEXT worker-loop iteration
> resumes at the same cursor without waiting for the 1 s gate. The sustained
> drain ceiling is therefore 256 reaps per loop iteration (the loop runs
> thousands of iterations per second), not per tick. What happens above that
> ceiling, which this plan's objection still describes correctly: the cursor
> lags, every call is a continuation, and `last_gc_ns` and the PPTP
> association sweep do not advance until it catches up.
> `WheelPopStats::budget_cuts` counts cut calls (in `cumulative_pop_stats`; not
> yet exported to the Go status). The reason for the change is an RG
> activation that re-stamps a whole table into one tick: one unbudgeted call
> then did the whole table's reap and teardown in one iteration (0.27-0.37 s
> per worker measured at 34k-48k rows, `docs/log/18780.md`).

#### Per-tick cost model (corrected per Codex round-5 #1)

Per-tick work = `O(K)` where `K` is the number of `WheelEntry`s
sitting in the popped bucket at that moment. Each entry costs:

  - 1 FxHashMap lookup on `self.sessions[key]` (~80–150 ns)
  - 1 tick-comparison branch (entry-gone / stale / expired / re-bucket)
  - In the stale and gone cases: O(1) drop and continue
  - In the expired case: 1 HashMap remove + delta push
  - In the re-bucket case: 1 HashMap mut + 1 wheel push

Per-entry cost is dominated by the HashMap lookup. Realistic
estimate: ~100 ns per stale/gone entry, ~300 ns per expired/re-
bucketed entry.

`K` is bounded by the number of pushes that landed in this bucket
since it was last popped (one wheel rotation = 256 s ago) minus
those popped at the start of this rotation. Push frequency per
session is throttled to "1 per second-aligned `scheduled_tick`
that the canonical `wheel_tick` advances onto". So under the
**worst plausible hot-path workload — every session touched at
least once per second**, each session contributes one push per
second, and over a full 256-s rotation produces 256 entries (255
of which are stale duplicates by the time their bucket is popped).

Concretely:

  total_wheel_entries ≤ Σ over sessions of
                        (distinct `scheduled_tick`s pushed in last 256 s)
                      ≤ N_sessions × min(touches_per_256s, 256)

For a population with **uniform per-second touch on every session**
(each session touches at a different sub-tick offset within each
1-second tick, so scheduled ticks spread roughly uniformly across
the wheel after warm-up):

  total_wheel_entries ≈ N_sessions × 256        (1 push/sess/tick × 256 ticks)
  K (per popped bucket) ≈ N_sessions            (entries spread evenly)
  per-tick cost       ≈ N_sessions × 100 ns

For **mostly-idle** workloads where each session is touched in
≈ T_active distinct ticks across the 256-tick window (T_active ≪ 256):

  total_wheel_entries ≈ N_sessions × T_active
  K (per popped bucket) ≈ N_sessions × T_active / 256
  per-tick cost       ≈ (N_sessions × T_active / 256) × 100 ns

Per-tick cost table (assuming 100 ns per stale/canonical entry):

| N (sessions) | per-second touch (T_active=256, K=N) | mostly idle (T_active=5, K = N × 5/256) |
|---|---|---|
| 10K | 1 ms (10K × 100 ns) | ~20 µs (~195 entries) |
| 100K | **10 ms** (100K × 100 ns) | ~200 µs (~1.95K entries) |
| 1M | **100 ms** (1M × 100 ns) | ~2 ms (~19.5K entries) |

#### What this means for "Stop the World goes away"

Today's StW scans `self.sessions` (N entries) once per
`SESSION_GC_INTERVAL_NS = 1 s`, producing one ~100 ms blocking
call per second at 1M sessions. The wheel pops **one bucket per
tick** (one per second, at the same cadence), so under the
worst-plausible hot-path workload — sustained per-second touch
on every session — each tick still pays K ≈ N work because
every bucket is full of N entries (one per session, mostly
stale duplicates) after warm-up.

So the wheel does **NOT** reduce per-tick wall time under that
workload; it preserves it (~100 ms per tick at 1M, ~10 ms per
tick at 100K). What it changes is the *shape*: today's StW is a
single blocking call inside `expire_stale_entries`; the wheel's
work is paid as a steady drain on the same call, with no
allocation of a Vec<SessionKey> for the candidate set. (The
allocation savings are real but secondary.)

The win, restated honestly:

1. **Realistic mixed-traffic deployments** (most sessions idle,
   T_active ≈ 5): per-tick cost drops from O(N) to O(N × 5 / 256),
   which at 100K sessions is ~200 µs vs. today's ~10 ms — a
   **~50× improvement** in the typical case.

2. **All-active per-second-touch at 100K**: per-tick cost is
   ~10 ms, same as today's ~10 ms StW. The wall-time at this
   load is the same; the win is that work doesn't pile up into
   an even larger periodic spike when GC is delayed.

3. **All-active per-second-touch at 1M**: per-tick cost is
   ~100 ms — **the same wall time as today's StW.** The wheel
   does not solve this case; it tracks under "active deletion"
   and "multi-level wheel" follow-ups (see Out of scope). At
   this scale we recommend operators tune `SESSION_GC_INTERVAL_NS`
   higher or land #964 first.

4. **Same-bucket install bursts** (synthetic: all N sessions
   installed in one tick, then idle): bucket sees O(N) work *once*
   per 256 s, then idles for 255 ticks. The other 255 ticks have
   no GC work at all — strictly better than today's "100ms blast
   every 1s".

The single-line summary: **for realistic deployments the wheel
delivers a ~50× per-tick latency win; for synthetic worst-case
sustained-per-second-touch the wheel matches today's wall time
but with bounded per-tick shape; for any workload this PR removes
the per-second `Vec<SessionKey>` allocation that today's
expire_stale_entries does inside its hot path.**

The acceptance-gate workloads, latency targets, and unit-test
specifications live in §Acceptance gates below — that section is
the single source of truth for what we will measure.

```rust
pub fn expire_stale_entries(&mut self, now_ns: u64) -> Vec<ExpiredSession> {
    if self.last_gc_ns != 0 && now_ns.saturating_sub(self.last_gc_ns) < SESSION_GC_INTERVAL_NS {
        return Vec::new();
    }
    self.last_gc_ns = now_ns;
    self.wheel_observe(now_ns);  // lazy init if first call

    let now_tick = now_ns / WHEEL_TICK_NS;
    let mut expired = Vec::new();
    // Cursor starts at the lazy-init now_tick, so the first call
    // after init is a no-op (loop body runs zero times).
    while self.wheel.cursor_tick < now_tick {
        let bucket_idx = bucket_for_tick(self.wheel.cursor_tick);
        // Drain the bucket allocation-free. We cannot hold a
        // `&mut VecDeque` from the wheel and simultaneously call
        // `self.wheel.buckets[new_bucket].push_back(...)` for a
        // re-bucket whose target may equal `bucket_idx`. Round-3
        // caught the v3 same-bucket-reinsert race that arose from
        // `mem::take` followed by `buckets[idx] = due` overwriting
        // re-bucketed entries. Round-7 (#3) caught that the v4
        // drain-into-Vec design re-introduced a per-pop allocation
        // — `Vec::with_capacity(due_count)` once per popped bucket
        // = once per tick, more than today's StW which allocates
        // once per gc-interval.
        //
        // Allocation-free design: snapshot the bucket length BEFORE
        // iterating, then `pop_front` exactly that many times. Any
        // `push_back` re-bucket targeting this same bucket lands at
        // the back of the VecDeque and is NOT popped during THIS
        // BUCKET DRAIN (the inner `for _ in 0..due_count` loop
        // stops after `due_count` iterations). The next wheel
        // rotation that visits this bucket processes the re-pushed
        // entries normally. NOTE: a single `expire_stale_entries`
        // call may catch up multiple ticks (the outer `while
        // cursor_tick < now_tick` advances the cursor across
        // several buckets). A re-push from bucket A whose target
        // lands in a later bucket B that the OUTER loop will visit
        // in this same call IS popped before the call returns —
        // that's intentional and correct (it represents an entry
        // that was re-bucketed forward into a tick that has already
        // arrived). Only same-bucket re-pushes are deferred to the
        // next wheel rotation, by design.
        let due_count = self.wheel.buckets[bucket_idx].len();
        for _ in 0..due_count {
            let entry_snap = self.wheel.buckets[bucket_idx]
                .pop_front()
                .expect("len snapshot bounds the iteration");
            let WheelEntry { key, scheduled_tick } = entry_snap;
            let Some(entry) = self.sessions.get(&key) else {
                // Already removed elsewhere — drop hint.
                continue;
            };
            if entry.wheel_tick != scheduled_tick {
                // Stale duplicate: the entry has been re-scheduled
                // to a different tick. The new tick has its own
                // wheel entry already.
                continue;
            }
            // scheduled_tick matches entry.wheel_tick — this is the
            // canonical scheduled-check entry. Match today's strict
            // `>` semantics for "actually expired".
            if now_ns.saturating_sub(entry.last_seen_ns) > entry.expires_after_ns {
                if let Some(removed) = self.remove_entry(&key) {
                    // ... emit SessionDelta + ExpiredSession ...
                    expired.push(...);
                }
            } else {
                // Still alive — long-timeout (>= 256s) case, or a
                // session re-scheduled to exactly this tick. Re-
                // bucket at the new absolute target tick. The new
                // bucket may be `bucket_idx` again (e.g. exactly
                // 256s timeout repeats); that's fine because the
                // inner `for _ in 0..due_count` loop iterates
                // exactly `due_count` times — re-pushed entries
                // into THIS bucket land at the back of the
                // VecDeque and are not popped during this BUCKET
                // drain. They get processed at the next wheel
                // rotation that visits this bucket. (Re-pushes
                // into a LATER bucket — e.g. target_tick > current
                // cursor + 1 — that the OUTER `while cursor_tick
                // < now_tick` loop will visit in this same call
                // ARE popped before the call returns; that case
                // represents an entry re-bucketed forward into a
                // tick that has already arrived.)
                let new_target_tick = target_tick_for(
                    now_ns,
                    entry.last_seen_ns + entry.expires_after_ns,
                );
                let new_bucket = bucket_for_tick(new_target_tick);
                let entry_mut = self.sessions.get_mut(&key)
                    .expect("entry was just read");
                entry_mut.wheel_tick = new_target_tick;
                self.wheel.buckets[new_bucket].push_back(WheelEntry {
                    key,
                    scheduled_tick: new_target_tick,
                });
            }
        }
        self.wheel.cursor_tick = self.wheel.cursor_tick.saturating_add(1);
    }
    self.wheel.base_tick = now_tick;
    expired
}
```

This algorithm correctly handles four cases on pop:
1. **Entry gone** (already removed by another path) — drop hint.
2. **Stale duplicate** (`wheel_tick != scheduled_tick`) — drop, the
   new scheduled tick has its own entry.
3. **Actually expired** — remove, emit ExpiredSession + delta.
4. **Still alive at the canonical scheduled tick** — long-timeout
   case (e.g. 300s TCP-ESTABLISHED). Re-bucket at the new
   expiration tick. This is the case that v2's pseudocode dropped
   incorrectly (Codex round-2 finding #1).

### Alias correctness in lookup_with_origin (Codex finding #5)

`lookup_with_origin` resolves NAT aliases via
`reverse_translated_index`. The wheel push must use `actual_key`
(the canonical key the entry is stored under), NOT the caller's
alias key. Otherwise the wheel push goes to the wrong shard and
the canonical entry never gets its expiration refreshed.

```rust
let actual_key = if self.sessions.contains_key(key) {
    key.clone()
} else if let Some(alias) = self.reverse_translated_index.get(key) {
    alias.clone()
} else {
    return None;
};

// Scope the &mut self.sessions borrow so it ends BEFORE we touch
// self.wheel. Without this scoping the closure form
// `self.sessions.get_mut(...).map(|entry| { ... self.wheel ... })`
// holds a mutable borrow on `self` (via `self.sessions`) and a
// second mutable borrow on `self.wheel` simultaneously, which the
// borrow checker rejects.
let push_tick: Option<u64> = {
    let entry = self.sessions.get_mut(&actual_key)?;
    // ... last_seen_ns / expires_after_ns updates ...
    let new_expiration_tick = target_tick_for(
        now_ns,
        entry.last_seen_ns + entry.expires_after_ns,
    );
    if new_expiration_tick != entry.wheel_tick {
        entry.wheel_tick = new_expiration_tick;
        Some(new_expiration_tick)
    } else {
        None
    }
}; // <-- &mut self.sessions borrow ends here

if let Some(tick) = push_tick {
    // PUSH actual_key, not the alias `key`. Payload must be a
    // WheelEntry carrying the canonical scheduled_tick so pop's
    // lazy-delete discriminator can detect staleness.
    let bucket = bucket_for_tick(tick);
    self.wheel.buckets[bucket].push_back(WheelEntry {
        key: actual_key.clone(),
        scheduled_tick: tick,
    });
}

// Build the SessionLookup return value via a fresh & immutable
// borrow on self.sessions (the &mut borrow above has dropped).
self.sessions.get(&actual_key).map(|entry| {
    // ... return SessionLookup ...
})
```

Test: `wheel_alias_lookup_refreshes_canonical_key`.

### Hot-path allocation: lazy-grow with documented warm-up (Codex round-2 #3)

Round-1's `max_sessions / WHEEL_BUCKETS` reserve was wrong: short-
timeout workloads concentrate sessions in a small number of "live"
buckets (those between `cursor_tick` and `cursor_tick +
typical_timeout_ticks`). For a 30s timeout × 100K sessions, only
30 of 256 buckets see traffic at steady state, and each holds
~3300 entries — far above the proposed 100K/256 = 390 reserve.
Pre-reserving 390 per bucket means every active bucket reallocates
2-3× as it grows.

**Decision**: don't pre-reserve at all. Construct each VecDeque
empty (24 B header). On the hot path, the FIRST `push_back` to
each bucket allocates a small backing buffer; subsequent pushes
amortize Vec-style geometric growth. Steady-state allocation
amortizes across the bucket lifetime (up to 256 ticks).

Drop the "no allocations on the hot path" claim entirely. The
honest phrasing is: "amortized O(1) push, occasional reallocation
during bucket warmup". `VecDeque` doubles its backing buffer
geometrically, so for a steady-state size of ~B entries it
reallocates `~log2(B)` times during warm-up; each realloc copies
*all* current elements (so the realloc just before reaching
capacity B copies up to B−1 elements). For B=3K and B_avg ≈ B/2
across the warm-up, the per-bucket warm-up moves ≈ B − 1 ≈ 3K
elements total. Across 256 buckets that's 256 × 3K = ~768K
element-moves during warm-up at 48 B each ≈ ~36 MB total. Spread
over 256 ticks (256 s wall time), that's ~150 KB/s of allocator
traffic. Negligible vs the per-packet hot path.

After warm-up (after first wheel rotation), each bucket's VecDeque
has settled at ~max-bucket-size capacity. New pushes don't grow.

```rust
fn new_wheel() -> SessionWheel {
    let mut buckets: Vec<VecDeque<WheelEntry>> = Vec::with_capacity(WHEEL_BUCKETS);
    for _ in 0..WHEEL_BUCKETS {
        // Lazy: first push allocates the backing buffer.
        buckets.push(VecDeque::new());
    }
    let buckets: Box<[VecDeque<WheelEntry>; WHEEL_BUCKETS]> =
        buckets.into_boxed_slice().try_into().expect("right size");
    SessionWheel { buckets, base_tick: 0, cursor_tick: 0, initialized: false }
}
```

Construction memory cost: 256 × 24 B = 6 KB. Steady state: bucket
buffers grow to fit avg load × geometric headroom. For typical
100K × 30s workloads, ~30 active buckets × ~3K entries × 48 B =
~4.3 MB.

### Files touched

- `userspace-dp/src/session.rs`: add `SessionWheel` (~150 LOC),
  add wheel push at insert/touch/refresh sites, replace
  `expire_stale_entries` body with wheel pop. ~250 LOC change.
  Public API unchanged.

### Tests

- `wheel_pops_expired_entry_from_bucket`: insert one session, advance
  time past its timeout, verify expire_stale_entries returns it.
- `wheel_skips_touched_entry`: insert, touch (advances last_seen),
  advance time past original bucket but before new bucket; verify
  expire_stale_entries does NOT return it.
- `wheel_handles_long_timeout_via_far_future_bucket`: insert with
  timeout > 256s; verify entry doesn't expire prematurely; advance
  past 256s; verify entry re-buckets and expires correctly later.
- `wheel_handles_exact_256s_timeout` (Codex finding #4): insert
  with `expires_after_ns == WHEEL_BUCKETS * WHEEL_TICK_NS`. Verify
  the entry lands in the FAR_FUTURE bucket (not the current one)
  and gets re-checked after the wheel rotation.
- `wheel_alias_lookup_refreshes_canonical_key` (Codex finding #5):
  install entry under canonical key K; lookup via NAT alias key A
  (where reverse_translated_index[A] = K); verify the wheel push
  goes to K's bucket, not A's.
- `first_gc_with_large_monotonic_now_doesnt_walk_billions_of_buckets`
  (Codex finding #1): construct fresh SessionTable; call
  expire_stale_entries with `now_ns = 10^18` (wall-time-ish big);
  verify it returns immediately (no infinite loop, no panic).
- `expiry_boundary_strict_greater_than` (Codex finding #8): insert
  entry with `expires_after_ns = 1_000_000_000`; advance to
  exactly `last_seen + 1_000_000_000` (boundary); verify entry is
  NOT expired (matches today's `>` semantics, not `>=`).
- `wheel_lags_today_subtick_by_at_most_one_tick` (Codex round-6
  #1): bypass the gc-interval gate by setting `last_gc_ns`
  directly. Insert entry with `expires_after_ns = 1_000_000_000`.
  Call `expire_stale_entries(last_seen + 1_000_000_000 + 1)`
  (one ns past expiration). Assert wheel returns it as NOT
  expired (acceptable 1-tick lag vs today's hypothetical sub-
  tick `>` scan). Then call `expire_stale_entries(last_seen +
  1_000_000_000 + WHEEL_TICK_NS + 1)` (one tick past
  expiration). Assert wheel returns it as EXPIRED. This guards
  the documented bound from drifting.
- `wheel_duplicate_count_per_session_bounded` (Codex finding #7):
  insert one session; touch it 100 times within the same tick;
  count wheel entries for that key; assert ≤ 2 (the initial push
  + at most one re-push if expiration tick changed).
- `wheel_sustained_overload_drains_all_buckets`: insert 50K
  sessions all with same expiration; advance time past expiration;
  verify expire_stale_entries returns all 50K in a single call
  (no per-tick cap; one tick = one bucket = O(B) work, not capped).
  **Changed by #18780:** the cell now asserts all N drain in exactly
  `ceil(N / EXPIRY_PASS_MAX_REAPS)` consecutive calls (per-call budget
  with continuation; see the supersession note under "Per-tick GC work").
- `wheel_per_second_touch_bounds_K_per_bucket` (Codex round-5 #2,
  hardened per round-6 #5, classifications corrected per round-7
  #2): install N=10K sessions, then touch every session once per
  second for ≥ 300 s of simulated time before measuring. After
  warm-up, instrument the next pop to count entries scanned (`K`)
  and entries dropped/expired/re-bucketed. **Under sustained
  per-second touch on every session, every entry in the popped
  bucket is a stale duplicate** — the canonical `wheel_tick` for
  every session has advanced beyond the bucket's `scheduled_tick`
  because each session pushed a fresher entry every second since
  the bucket was last popped. So:
    * `K ≤ 12,000` (model says 10,000; 20 % headroom catches a
      2× duplicate-push regression — a 5× wall-time bound would
      not).
    * `entries_dropped_stale ≈ K` (every entry is dropped via
      the `wheel_tick != scheduled_tick` discriminator).
    * `entries_re_bucketed = 0` (no canonical entry expires in
      this regime; sessions are kept alive by the per-second
      touch).
    * `entries_expired = 0` (same reason).
    * Across a full 256-tick rotation: total entries scanned
      ≈ 256 × K ≈ 256 × N. Assert
      `total_scanned ∈ [0.9, 1.1] × 256 × N` to catch leakage
      of stale entries the lazy-delete discriminator should
      drop on visit but didn't.
  The point of the test is to bound *work shape*, not wall time;
  wall-time perf is the §Acceptance gate 4b informational gate.
- `wheel_alias_lookup_does_not_double_borrow_self`: compile-time
  test that the alias path's `lookup_with_origin` body type-checks
  (i.e. the &mut self.sessions borrow is scoped before
  self.wheel.buckets is touched). This is enforced by the borrow
  checker; the test exists to guard against future refactors that
  reintroduce a `.map(|entry| { ... self.wheel ... })` shape.
- `wheel_handles_concurrent_insert_and_pop`: not relevant
  (SessionTable is not Send + Sync — owned by a single worker;
  Codex confirmed worker.rs:490 has `let mut sessions = ...`).

Plus 4 existing GC tests (lines 2138, 2142, 2162, +1 more) must
continue to pass.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` ≥ baseline (851 post-#921) + 11 new = 862.
3. Cluster smoke (HARD): no regression on the unloaded-session path.
   Run on `loss:xpf-userspace-fw0/fw1` (the userspace-dp HA cluster
   that is the default deploy target — NOT the legacy eBPF
   `bpfrx-fw0/fw1` cluster) AND with CoS configured on every
   iperf3 forwarding-class via `test/incus/cos-iperf-config.set`.
   CoS state is wiped by `cluster-deploy`, so the smoke runner
   must re-apply that fixture before measurement.

   Per-class enumeration (matches the fixture's shaped rates,
   ~10 % headroom for L2 overhead and TCP RTT variance):

   | Class       | Port  | Shaped rate | P=12 gate     | P=1 gate     |
   |-------------|-------|-------------|---------------|--------------|
   | iperf-c     | 5203  | 25 g exact  | ≥ 22 Gb/s     | ≥ 6 Gb/s     |
   | iperf-f     | 5206  | 19 g exact  | ≥ 17.1 Gb/s   | counter-only |
   | iperf-e     | 5205  | 16 g exact  | ≥ 14.4 Gb/s   | counter-only |
   | iperf-d     | 5204  | 13 g exact  | ≥ 11.7 Gb/s   | counter-only |
   | iperf-b     | 5202  | 10 g exact  | ≥ 9.0 Gb/s    | counter-only |
   | iperf-a     | 5201  | 1 g exact   | ≥ 0.9 Gb/s    | counter-only |
   | best-effort | 5207  | 100 m exact | ≥ 90 Mb/s     | counter-only |

   - "P=12 gate" runs `iperf3 -P 12 -p <port>` and asserts the
     achieved Gb/s is ≥ the listed minimum. **Every P=12 row is
     a blocking gate.** iperf-c is the historical 22 Gb/s smoke
     (≈ 88 % of its 25 g shape); the others use ≈ 90 % of their
     respective shapes (matches typical TCP/L2 overhead).
   - "P=1 counter-only" rows run `iperf3 -P 1 -p <port>` against
     the class and assert that the egress class counter
     (`show class-of-service interface reth0 unit 80`) increments
     by at least the iperf3 byte count. This validates the
     classifier / queue path lit up without imposing a hard
     throughput gate at single-stream P=1 (where small-packet
     overhead can drag below the shape under noise). iperf-c is
     the only class with a P=1 throughput gate (≥ 6 Gb/s) and
     stays as the historical hard gate.
   - A class whose iperf3 run lights up best-effort (queue 0)
     instead of the targeted class is a config-misapplied smoke
     that does NOT validate the refactor; treat it as a failure
     of step 3 regardless of the iperf3 number.
4. **Mouse-latency gate** — TWO synthetic workloads (per Codex
   round-5 #2 + round-6 #4 / #5). The numbers below are the
   single source of truth; any other section that mentions "the
   acceptance gate" defers to this list.

   4a. **Realistic mostly-idle workload**:
       - N = 50K sessions installed.
       - Touch rate calibrated so that each session contributes
         ≈ T_active = 5 distinct expiration ticks over the 256-s
         wheel window. Concretely: a Poisson touch process at
         rate ~5/256 ≈ 0.02 per session per second, i.e. roughly
         1000 touches/s spread across the 50K-session population.
       - Run for ≥ 300 s of simulated time before measuring (so
         the wheel reaches steady state and any warm-up
         allocations have settled).
       - Assert: per-pop K (entries scanned per popped bucket)
         ≤ 1500 (the model gives N × T_active / 256 = 50K × 5 /
         256 = 977; 1500 is ~50 % headroom and catches a
         regression where touch pushes more than one entry per
         tick-change).
       - Assert: p99 GC-tick wall time ≤ 1 ms over a 60-s
         measurement window (model: 977 × 100 ns = 98 µs; 10×
         margin allows for HashMap probe variance and alloc
         churn during warm-up).
       - **NOT** a "10 % touched per second" workload — that
         shape produces ≈ 5K active sessions each pushing once
         per second, so K ≈ 5K, not 977. The two-rate framing
         of T_active vs. per-second touch fraction was the
         source of the round-6 → round-7 contradiction; the
         spec above pins the rate to a Poisson process tuned to
         T_active = 5.

   4b. **Sustained per-second touch** (worst-plausible hot path):
       - N = 10K sessions installed.
       - EVERY session touched once per second.
       - Run for ≥ 300 s before measuring.
       - Assert: per-pop K ≤ 12,000 (model gives 10K; 20%
         headroom catches a 2× duplicate-push regression). This
         is the **primary** correctness assertion — wall time is
         a derivative of K and is hardware-dependent.
       - Wall-time perf gate (informational, not blocking):
         p99 GC-tick wall time ≤ 5 ms on the cluster test host
         (model gives 10K × 100 ns = 1 ms; 5× margin allows for
         alloc churn and HashMap probe variance). Failure here
         flags a perf regression but does not block CI by itself
         since wall time depends on the runner.

   Both correctness gates (4a and 4b K-bounds) must hold. The
   wall-time gate at 4a must hold; the wall-time perf gate at
   4b is informational. Adversarial same-bucket install bursts
   are out of scope for #965 and tracked under the active-
   deletion / multi-level-wheel follow-ups (see Out of scope).
5. Codex hostile review: AGREE-TO-MERGE.
6. Gemini adversarial review: AGREE-TO-MERGE.

## Risk

**Medium.**

- Wheel is purely an index; `sessions` HashMap is authoritative
  state.
- Stale-duplicate vs. canonical pop is decided by
  `entry.wheel_tick == scheduled_tick`. Long-timeout entries get
  re-bucketed correctly per the algorithm in §"Per-tick GC work".
- Memory growth scales with sessions × distinct expiration ticks
  visited per session. For typical workloads that's ≤MB; for
  pathological dense-throughput workloads it grows toward GB
  scale. #964's slab is the right place to fix this; #965 ships
  with this caveat documented.
- `wheel_tick: u64` adds 8 B to `SessionEntry`. At 100K sessions
  ≈ 800 KB. Acceptable.

Risk areas:
- `touch` / `lookup_with_origin` add a wheel push when the
  expiration tick changes. Same-tick touches are no-ops. The push
  is amortized O(1) `VecDeque::push_back` with occasional
  reallocation during bucket warm-up.

## Out of scope

- #964 (slab + integer handles): `sessions` stays as
  `FxHashMap<SessionKey, SessionEntry>`. The wheel uses
  `WheelEntry { SessionKey, scheduled_tick }` as the bucket
  payload. After #964, the payload becomes
  `WheelEntry { SlotHandle, scheduled_tick }` — same structure,
  ~3× smaller (16 B vs 48 B). The path between #965 and #964 is
  mechanical.
- Active wheel-entry deletion (intrusive doubly-linked list per
  bucket with back-reference in SessionEntry). Would bound live
  wheel entries at exactly N (one per session) instead of up to
  N × 256 under sustained per-tick touch. Significantly more code;
  defer to a follow-up if the per-tick cost under adversarial
  workloads becomes a problem.
- Multi-level wheels (hashed timing wheels): the single wheel +
  re-bucket-on-still-alive is enough for the typical 100K-session
  / ≤300 s timeout case. Multi-level is a follow-up if profiling
  shows the per-bucket spike under sustained per-tick touch
  (analyzed below) is an issue.
- Per-protocol expire policy refactor: timeouts are still computed
  from `key.protocol` and `tcp_flags` at insert/update time.
