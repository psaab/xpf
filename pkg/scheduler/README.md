# pkg/scheduler

Time-window scheduler for Junos `schedulers` blocks. Evaluates active
state every 60 s and notifies a callback when any scheduler's
active/inactive state changes. Used to gate firewall filters,
forwarding-class rewrites, and other config that should engage only
during specific windows.

## Entry points

- `Scheduler` — `scheduler.go`.
- `New(schedulers map[string]*config.SchedulerConfig, updateFn func(map[string]bool) error) *Scheduler` —
  `scheduler.go`. The `updateFn` callback fires on state change **and**
  while a prior republish is still pending (self-heal, see below), not
  every tick.
- `NewPrimed(..., now)` — constructor for daemon apply paths that need the
  initial active-state map without firing the callback while an external
  apply semaphore is already held.
- `NewPrimedInLocation(..., loc)` — `scheduler.go`. Apply paths with a
  committed system time zone use this constructor so the scheduler does not
  depend on Go's process-cached `time.Local`.
- `Run(ctx context.Context)` — `scheduler.go`.
- `IsActive(name string) bool` — `scheduler.go`.
- `ActiveState() map[string]bool` — `scheduler.go`. Snapshot of every
  scheduler's active flag.
- `Update(schedulers map[string]*config.SchedulerConfig)` —
  `scheduler.go`.
- `RepublishPending() bool` / `RepublishFailureStatus() (pending bool,
  failures uint64, since time.Time)` — `scheduler.go`. Expose the #3780
  self-heal state for tests and metrics.
- `RepublishFailClosed() bool` — `scheduler.go`. True when the bounded-age
  republish-failure latch is set and scheduled policies are forced inactive
  in the scheduler's authoritative state. It does not expire a schedule
  already held by a wedged dataplane. Feeds
  `xpf_scheduler_republish_fail_open_stale`; the old
  `xpf_scheduler_republish_fail_closed` metric remains a deprecated alias.

## Time-window model (#3849, #11305)

A `config.SchedulerConfig` resolves to at most one window per instant:

- **Daily window** — `StartTime`/`StopTime` (the body of a Junos
  `daily { start-time X; stop-time Y; }` block, or the legacy simplified
  shape where `start-time`/`stop-time` are direct children of the
  scheduler). Both `HH:MM` and `HH:MM:SS` are accepted; omitted seconds
  mean `:00`. `AllDay` marks the daily window active for the whole day
  (`daily all-day`).
- **Per-day overrides** — `Days["monday".."sunday"]`. A weekday present in
  `Days` overrides the daily window for that weekday; its `Exclude` flag
  forces the day inactive, `AllDay` forces it active. Days without an
  override fall back to the daily window.
- **Date range** — `StartDate`/`StopDate` gate the whole scheduler. Date-only
  `YYYY-MM-DD` bounds keep their existing semantics: start at local midnight,
  and stop inclusive through the entire stop date. Junos date-time bounds
  use `YYYY-MM-DD.HH:MM`, interpreted as local wall-clock instants. The start
  is inclusive and the date-time stop is exclusive; a date-only bound can
  still be paired with a date-time bound.
- A scheduler with only a date range (no time-of-day window) is active for
  the entire range.

`compileSchedulers` (`pkg/config/compiler_system.go`) reads all of these
for both the hierarchical and flat-set AST shapes; the flat-set grammar is
grouped by the `schedulers` entry in `setSchema`
(`pkg/config/schema_schedulers.go`). The scheduler's typed time slots are
validated at commit: times accept `HH:MM` or `HH:MM:SS`, and date bounds
accept `YYYY-MM-DD` or `YYYY-MM-DD.HH:MM`.

**Time zone — committed system local (#3988, #10949).** Scheduler dates and
times are Junos local wall-clock. The daemon resolves a configured
`system time-zone` with `time.LoadLocation` and includes that value in the
scheduler generation hash, so a committed zone change rebuilds and publishes
the scheduler state in the new zone during apply. Each subsequent tick
converts its instant into the generation's cached location before evaluating
date and time windows; peers with the same committed zone therefore agree
regardless of restart history. If no zone is configured, the caller's time
location is retained. If a configured zone cannot be loaded, scheduled
policies fail closed.

`withinDateRange` parses date-only bounds with
`time.ParseInLocation("2006-01-02", …, now.Location())` and date-time bounds
with `time.ParseInLocation("2006-01-02.15:04", …, now.Location())`. Parsing
in the scheduler's local location keeps both absolute instants and
date-only-midnight boundaries consistent with the same clock the
time-of-day comparison uses. Daily `start-time`/`stop-time` windows compare
only wall-clock H/M/S components (`parseTimeOfDay` vs `timeOfDay`), so
`08:30` and `08:30:00` denote the same clock time.

**Fail-closed invariant (#3849 — security).** `isWithinWindow` treats an
ABSENT window as **inactive**, never always-on. A scheduler that resolves
to no window for a given instant — no daily window, no applicable per-day
override, and no date range — returns `false`. Before #3849 the
`daily {}` block was never descended (so `StartTime`/`StopTime` stayed
empty) and an empty window returned `true`, so a policy `scheduler-name`
scoped to business hours actually permitted traffic 24/7 (fail-open). A
window that fails to compile now DENIES, matching the firewall's
fail-closed posture. To express "always active", omit `scheduler-name`
from the policy or use `daily all-day`.

**No-window commit warning (#3860).** The fail-closed flip (#3849/#3858)
is safe but silent: a *degenerate* scheduler that defines no window at all
— an empty `scheduler x {}`, or a bare `daily;` with no start/stop time,
no `all-day`, no per-day arm, and no start/stop date — now resolves to
INACTIVE where the old always-on bug forwarded 24/7. An operator migrating
a config that leaned on that bug would lose enforcement with no signal.
`ValidateConfig` (`pkg/config/compiler_validate_warn.go`,
`schedulerHasEffectiveWindow`) therefore emits a commit-time WARNING naming
each such scheduler: *"scheduler X defines no time window; policies bound
to it will be INACTIVE (use `daily all-day` for always-on)."* A scheduler
carrying any window — a daily/weekday time-of-day arm, `all-day`, or a
start/stop calendar range — does NOT warn. The predicate mirrors the
runtime `schedulerHasTimeWindow || schedulerHasDateRange` split, so the
warning fires exactly when `isWithinWindow` would fail closed for every
instant. It is a warning, not a hard reject, because a degenerate scheduler
is legal Junos and an upgrade must not refuse an existing candidate.

**Overnight windows with per-day overrides.** An overnight window
(e.g. `22:00:00`-`06:00:00`) wraps past midnight, but `effectiveDayWindow`
resolves the applicable window by the *current* weekday. The post-midnight
tail (00:00-06:00 the next calendar day) is therefore evaluated against
that next day's window — a per-day override on the next day (or its absence)
governs the tail, not the prior day's overnight window. This matches (and
does not regress) the single-daily behavior: a uniform `daily 22:00-06:00`
carries across every night because every day resolves to the same window.
Mixing an overnight daily window with divergent per-day arms is the case to
reason about carefully.

## Republish self-heal (#3780)

`updateFn` returns an `error`. A window transition republishes
enforcement (the daemon rebuilds and publishes the userspace policy
snapshot with the new `inactive` bits); if that republish **fails**, the
transition has NOT converged — a scheduled permit whose window just
closed would keep forwarding (fail-open), or a scheduled block would never
engage. A non-nil `updateFn` result latches an internal `republishPending`
flag, and the NEXT evaluation tick re-fires `updateFn` with the current
active state **even when the state did not change**, retrying on the
scheduler's own throttle-paced 60 s sweep until it converges. A successful
republish clears the flag. This replaces the previous fire-and-forget
behavior where a swallowed republish failure left stale enforcement live
until the next unrelated state change (which can be hours away).

The daemon side surfaces the failure as the
`xpf_scheduler_republish_failed` gauge (1 while a republish is pending)
plus `xpf_scheduler_republish_stale_seconds` (age of the current failure
streak), and logs an `ERROR` on the transition into failure. See
`pkg/daemon/daemon_scheduler.go` (`publishPolicyScheduleState`,
`recordSchedulerRepublishResult`).

## Dataplane heartbeat lease (#11285)

Successful snapshots containing scheduled policies seed a versioned
`scheduler_heartbeat`; unchanged, converged 60 s ticks renew that lease
without rebuilding a snapshot or advancing its generation. The scheduler
does not heartbeat while a snapshot republish is pending, so a wedged
publisher cannot keep stale scheduled permits alive.

The Rust helper records heartbeat receipt with its monotonic clock. At exactly
300 s the schedule disposition remains authoritative; only when the lease is
older does the helper choose the deny-first interpretation: scheduled permits
become ineligible, while scheduled denies/rejects remain eligible. On the
first expired-lease lookup, workers with scheduled DENY/REJECT rules clear
old-phase flow-cache entries once so a cached unscheduled PERMIT below a newly
eligible deny returns through policy revalidation; later cache hits use the
ordinary fast path. Expiry does not change snapshot generation.
Version zero (no heartbeat received) never expires, preserving compatibility
with older Go publishers. An older helper rejects the new verb; Go ignores
that best-effort refusal, so dataplane-side expiry requires a helper that
implements #11285.

## Bounded-age FAIL-OPEN-STALE escalation (#5669, #10906)

The #3780 self-heal retries a failed republish every tick. Until it converges,
the last snapshot remains stale. A helper implementing #11285 expires stale
scheduled permits after five minutes without a heartbeat while preserving
scheduled denies/rejects; helpers that predate #11285 cannot independently
expire that stale state. The daemon still surfaces the retry failure through
the stale-seconds gauge.

Once the failure streak exceeds `RepublishFailClosedAge` (5 min ≈ five
60 s ticks — long enough to absorb transient control-socket contention
without a false alarm, short enough to surface a genuinely stuck republish
promptly), the scheduler latches `republishFailClosed` and:

- emits a **one-time** `slog.Warn` alarm that the last-known scheduled
  decision may remain enforced until its dataplane lease expires (or
  indefinitely on a helper predating #11285), and
- sets every scheduler inactive in the authoritative active-state map and tries to republish that state;
- full and partial snapshot builders preserve latch-inactive scheduled `DENY`/`REJECT` eligibility while keeping scheduled permits inactive.

**What this actually buys — and what it does NOT.** The latch-specific
snapshot still uses the same `updateFn` channel whose failures define the
streak, so it may not reach a persistently-wedged helper. On a #11285 helper,
lease expiry uses an action-aware fallback: scheduled permits become
ineligible, while scheduled denies/rejects remain eligible. A legacy helper
that rejects the heartbeat verb cannot expire a stale permit if the latch
snapshot also fails to reach it.

Together, the republish latch and dataplane lease bound stale scheduled
permits while choosing the denying interpretation when freshness is unknown.
Concretely they deliver:

- **(a) a one-time loud alarm** (`slog.Warn`, "FAIL-OPEN-STALE") — the
  operator is told that scheduled permits may remain live until the lease
  expires, or longer on a legacy helper;
- **(b) the `xpf_scheduler_republish_fail_open_stale` 0/1 gauge** for
  monitoring/alerting. `xpf_scheduler_republish_fail_closed` remains as a
  deprecated alias with the same value for existing alert expressions;
- **(c) authoritative-state consistency** — `ActiveState()` / `IsActive()`
  report schedulers inactive, while the current userspace builder preserves
  latch-inactive scheduled denies/rejects and leaves permits inactive;
- **(d) ordered recovery** — after a latch snapshot succeeds, the scheduler
  clears the latch and forces exactly one normal-disposition republish before
  returning to heartbeats. That removes the latch's deny override when a
  window is closed; a legitimately open window can then republish active
  without reopening a stale permit first.

The latch clears on the next **successful** republish. Because it engages
only while a republish is failing, it never marks a converged, genuinely
active window inactive (`republishPending == false`). `RepublishFailClosed()`
exposes the latch; the daemon's `SchedulerRepublishFailClosed` reads that
same latch (not a second daemon-side timer) and feeds it to the
`xpf_scheduler_republish_fail_open_stale` gauge (with the old gauge emitted
as a deprecated alias), so the gauge reflects the scheduler's
force-inactive/alarm decision exactly rather than approximately
(#5669 review fold, #10906).

**By-design: a scheduler config change resets the streak.** A commit that
changes the scheduler policy set (its `policySchedulerConfigHash`) tears
down and re-primes the scheduler with a fresh `republishFailClosed=false`
and a reset failure streak/clock, so repeated scheduler edits while the
dataplane stays wedged could keep restarting the 5 min bound and indefinitely
delay the FAIL-OPEN-STALE alarm. This is intentional — a new config is a new
streak — but operators editing schedulers during a control-socket outage
should watch `xpf_scheduler_republish_failed`/`_stale_seconds`, which are not
reset by the escalation logic itself.

**Limitation (block-engage scope).** Lease expiry cannot engage a scheduled
deny/reject rule whose rule snapshot never reached the helper. For a
scheduler-bound deny/reject already present in the snapshot, the helper keeps
it eligible after expiry even if the last active-state bit was inactive;
scheduled permits instead become ineligible. A fresh heartbeat or successful
republish is required to restore the current time-window disposition.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## Gotchas

- Evaluation interval is fixed at 60 s. Don't try to drive sub-minute
  precision through this package. This 60 s tick is also the retry cadence
  for a failed republish (#3780).
- `updateFn` receives the **full** active-state map, not just the
  changed entries. Callers compute their own diff if they care. It MUST
  return a non-nil error only when a live republish did not converge (so
  the retry latches); return nil for shutdown / nothing-to-publish so the
  self-heal does not spin.
- Daemon callers must publish scheduler changes while holding the daemon
  apply semaphore. Runtime scheduler callbacks take that semaphore before
  touching dataplane state so commits and time-window flips cannot publish
  hybrid policy snapshots.
- The daemon reconciler keeps an existing scheduler instance when the
  committed scheduler config is byte-identical. This preserves the
  monotonic/wall-clock recovery state and avoids resetting timers on
  no-op commits. Runtime publishes use the daemon context when acquiring
  the apply semaphore, so shutdown cancels a blocked scheduler publish
  instead of leaving a goroutine parked behind a long apply.
- The scheduler uses wall-clock time only in the control plane to evaluate
  Junos time windows. Packet workers must not recompute wall-clock schedules;
  they consume published active bits and check only the monotonic dataplane
  heartbeat lease.
- Wall-clock discontinuities are fail-closed. Each evaluation compares
  wall elapsed time with Go's monotonic elapsed time from the previous
  evaluation; backward wall steps or drift beyond the tolerance publish
  all schedulers inactive for that evaluation instead of extending an
  allow window with a stale wall-clock assumption.
