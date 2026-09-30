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

## Bounded-age FAIL-OPEN-STALE escalation (#5669, #10906)

The #3780 self-heal retries a failed republish every tick, but a
**persistently** failing republish — a wedged control socket (the shared
helper control socket carries status poll, HA sync, session installs, and
snapshot sync, per `CLAUDE.md`), an incompatible helper — leaves the stale
window **fail-open** (a scheduled permit still forwarding past its close)
for as long as the retry keeps failing, silently, with no operator signal
beyond the climbing stale-seconds gauge.

Once the failure streak exceeds `RepublishFailClosedAge` (5 min ≈ five
60 s ticks — long enough to absorb transient control-socket contention
without a false alarm, short enough to surface a genuinely stuck republish
promptly), the scheduler latches `republishFailClosed` and:

- emits a **one-time** `slog.Warn` alarm that the last-known schedule may
  still permit traffic in a wedged dataplane, and
- forces **every scheduled policy to the `inactive` (deny) disposition** in
  the authoritative active-state map on the next evaluation, and tries to
  republish that all-inactive snapshot.

**What this actually buys — and what it does NOT.** Be precise about the
packet-path effect, because the honest scope is narrower than "force
inactive ⇒ the permit stops forwarding":

The forced-inactive snapshot is published through **the same `updateFn`
channel** (`Manager.UpdatePolicyScheduleState` → `apply_snapshot`) whose
failures *define* the streak. In a **persistently-wedged** dataplane — the
exact case that latches fail-closed — that publish also fails, so the
all-inactive snapshot **does not reach the helper**: the stale scheduled
**permit keeps forwarding** past its window close until the control socket
recovers. The latch does **not** itself stop packets in a wedged dataplane.

So the escalation does not close the packet-path fail-open window; it
**bounds the *silent* fail-open window** and converts it into a loud,
observable, authoritative-deny posture. Concretely it delivers:

- **(a) a one-time loud alarm** (`slog.Warn`, "FAIL-OPEN-STALE") — the
  operator is told that the last-known schedule in a wedged dataplane may
  still permit traffic instead of only seeing a climbing stale-seconds
  gauge;
- **(b) the `xpf_scheduler_republish_fail_open_stale` 0/1 gauge** for
  monitoring/alerting. `xpf_scheduler_republish_fail_closed` remains as a
  deprecated alias with the same value for existing alert expressions;
- **(c) authoritative + surface deny consistency** — `ActiveState()` /
  `IsActive()` (and any `show`/policy-match surface reading them) report the
  scheduled policies **inactive (deny)**. This control-plane view does not
  guarantee the wedged dataplane has stopped enforcing a last-known permit;
- **(d) deny-lands-first on recovery** — when the republish recovers the
  scheduler first publishes the all-inactive snapshot and clears the latch,
  and only the **next** tick republishes the true (possibly reopened)
  window. So the moment the socket unwedges, the helper receives *deny*
  before it receives any reopened permit — the recovery cannot briefly
  re-open a stale permit ahead of the correct state.

The latch clears on the next **successful** republish, after which the true
window state is republished and any legitimately-open permit reopens (no
permanent false-deny). Because the latch engages **only** while a republish
is failing — enforcement is already broken — it never force-denies a
converged, genuinely-active window (those have `republishPending == false`).
`RepublishFailClosed()` exposes the latch; the daemon's
`SchedulerRepublishFailClosed` reads **that same latch** (not a second
daemon-side timer) and feeds it to the
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

**Limitation (block-engage scope).** The fail-closed disposition is
`inactive` (drop the scheduled rule → default-deny), which is the correct
fail-closed for the dominant **scheduled-permit** case. A scheduled
**block** whose engage-activation was never published is already un-engaged
in the wedged dataplane; forcing it `inactive` matches that state but cannot
*engage* a block, which requires a successful publish. Actively engaging a
stuck block would need per-policy action awareness in the dataplane, out of
this package's scope.

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
  Junos time windows. Packet workers must consume published active/inactive
  booleans from the userspace snapshot and must not evaluate scheduler time in
  the hot path.
- Wall-clock discontinuities are fail-closed. Each evaluation compares
  wall elapsed time with Go's monotonic elapsed time from the previous
  evaluation; backward wall steps or drift beyond the tolerance publish
  all schedulers inactive for that evaluation instead of extending an
  allow window with a stale wall-clock assumption.
