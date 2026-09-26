# pkg/rpm

Real-time Performance Monitoring probes (ICMP echo, TCP connect, HTTP
GET). Tracks RTT and jitter, emits events for the event-options engine,
fires per-test pass/fail transitions for the ip-monitoring engine, and
pins probes to devices/next-hops via `SO_BINDTODEVICE` / `SO_MARK`.

**Interval overflow bound (#5723).** `test-interval` / `probe-interval`
are operator-settable in seconds and are bounded to `[1,
config.MaxDurationSeconds]` at commit (`schema_system.go`), so a
pathological value cannot overflow `time.Duration(sec)*time.Second` into
a non-positive Duration and panic `time.NewTicker` in `runProbeLoop`
(a commit-reachable xpfd crash, sibling of the #5705 keepalive
overflow). `clampRPMIntervalSeconds` (`rpm.go`) re-applies the same
`[1, MaxDurationSeconds]` clamp at runtime as defense-in-depth for the
lenient HA-sync / on-disk Load ingress, which only downgrades an
out-of-range value to a warning.

## Entry points

- `Manager` — `rpm.go`.
- `ProbeResult` — `rpm.go`. Per-test metrics (RTT, jitter,
  success/fail counters).
- `Event` — `rpm.go`. `test_failed`, `probe_failed`, `test_completed`.
- `Transition` — `rpm.go`. Per-test pass/fail status transition with a
  current-state results snapshot (#1827 — sensor input for
  `pkg/ipmon`).
- `New()` — `rpm.go`.
- `Apply(ctx context.Context, cfg *config.RPMConfig)` — `rpm.go`.
- `StopAll()` — `rpm.go`.
- `Results()` — `rpm.go`.
- `SetEventCallback(fn)` — `rpm.go`. Registers the event-options callback.
  Events emitted BEFORE a callback is registered (a first probe cycle that ran
  before wiring) are buffered and REPLAYED to `fn` on registration, in FIFO
  order, so a boot-time failover edge is not dropped (#3755). The buffer is
  bounded (`maxBufferedEvents`) and stays empty on the normal daemon boot
  because the callback is wired before any probe starts.
- `HasEventCallback()` — `rpm.go` (#3755). Reports whether an event callback is
  registered (boot-ordering test seam).
- `SetTransitionCallback(fn)` — `rpm.go` (#1827).
- `SetRethMap(map[string]string)` — `rpm.go` (#1827). RETH → physical
  member translation for `destination-interface` resolution.
- `SetPinInstallResults(map[string]error)` — `rpm.go` (#1895). Per-test
  probe-pin install failures from `routing.Manager.ApplyProbePins`
  (map replaced wholesale, so a successful retry resumes probing
  without a probe restart).
- `HoldPinsForReprogram([]string, error)` — `rpm.go` (#1895). Pre-holds
  the union of currently-marked live tests and the new pin set while
  the kernel band is cleared-and-reprogrammed; the daemon publishes
  the real results via `SetPinInstallResults` after the reprogram
  (after `Apply` on a config change — the first probe cycle may hold,
  bounded by one test-interval).
- `PinInstallFailureCount()` — `rpm.go` (#1895). Backs the
  `xpf_rpm_probe_pin_install_failures` gauge.

## Callers

`pkg/daemon`, `pkg/eventengine`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`, `pkg/routing` (probe pin mark assignment),
`golang.org/x/net/icmp`.

## Gotchas

- **`Apply` restarts every probe, but no longer wipes every verdict
  (#6561).** It reallocates the results table (`StopAll`) and reseeds
  each key `LastStatus: "unknown"`. ip-monitoring reads `"unknown"` as
  PASS (`seedResultsLocked` buckets it with pass), so at the default
  `hold-down` of 0 that used to withdraw an ACTIVE failover route on the
  spot — and the trigger was not an RPM edit: `reconcileRPM`'s hash
  covers `cfg.RethToPhysical()`, so any RETH-member change reopened the
  gate. `Apply` now snapshots the prior results first and carries a
  test's runtime state forward when `probeMeasurementIdentity` — probe
  type, target, source, routing-instance, next-hop, and the destination
  interface AFTER RETH translation — is unchanged. A new test, a
  retargeted one, or one whose path moved correctly keeps `"unknown"`;
  a key the config dropped stays ABSENT, which ip-monitoring needs to
  keep distinct so it can clear a stale FAIL (#4423 M8).
- The identity is a resolved PATH, deliberately not the fwmark:
  `routing.BuildProbePins` assigns `ProbeFwmarkBase + idx` over sorted
  probe/test names, so the mark is a POSITION in the pin band — it does
  not move on a RETH remap and does move when an unrelated test sorts
  earlier.


- **The first probe cycle runs immediately** (`runProbeLoop` before the ticker
  loop), so a `ping_probe_failed` / `ping_test_failed` / `ping_test_completed`
  can be emitted the instant `Apply` starts a probe. The daemon wires the
  event-options callback BEFORE `reconcileRPM` starts probes; as a belt,
  `fireEvent` buffers any event fired while `onEvent` is nil and
  `SetEventCallback` replays it, so a boot-time failover edge is never dropped
  (#3755). Regression-locked by `TestFireEventBufferedUntilCallbackRegistered`.
- **icmp-ping sends a real ICMP echo since #1827** (raw socket, id/seq
  matching, 3 s timeout). The pre-#1827 prober never put a packet on
  the wire (raw-IP dial + UDP connect fallback — a route-existence
  check), so icmp-ping tests that "always passed" can now fail and can
  now trigger event-options policies. Release-noted behavior change.
- **Probe replies are not authenticated (#10872; accepted risk).** ICMP's
  fresh random token rejects static blind replies but an on-path attacker
  can observe and echo it; tcp-ping only confirms a TCP handshake; and
  schemeless http-get targets default to plaintext HTTP. See [the multi-WAN
  deployment guide](../../docs/multi-wan.md) for the explicit threat boundary
  and deployment guidance.
- **Setup errors hold state** (AGY PR #1843 F2 + Codex HIGH-2): a
  raw-socket open failure (capability/permission) AND socket-control
  failures on the tcp-ping/http-get dial path (SO_BINDTODEVICE /
  SO_MARK) are `ErrProbeSetup` — the probe loop holds the test's
  current state (no counters, no status change, no events, no
  Transition), logs a rate-limited Warn, and ip-monitoring never
  actuates routes off an environment error. Genuine dial outcomes
  (refused/timeout/unreachable) and send/receive errors stay path
  failures; ambiguous dial errnos default to PATH.
- **Scoped-hostname resolver setup failures also hold state** (#5061):
  a VRF/path-scoped hostname target resolves through a DNS socket pinned
  to the SAME `SO_BINDTODEVICE`/`SO_MARK` as the probe (#2614). A bind
  failure on that *resolver* socket is `ErrProbeSetup` too — one shared
  `vrfBindControl` classifies both the data socket and the resolver
  socket. The sentinel survives `net.OpError` on the data-socket dial
  path but is flattened to a string by `*net.DNSError` on the resolver
  path, so the setup error is captured in an out-of-band `setupErrSink`
  and `resolveProbeTarget` / `probeTCP` / `probeHTTP` re-tag the
  lookup/dial failure from it. Before #5061 the resolver Control
  returned the raw error, so an EPERM/ENODEV resolver bind was counted
  as probe loss for icmp-ping/tcp-ping/http-get.
- **Lifecycle cancellation holds state too** (#5852): a `StopAll` /
  config replacement / daemon shutdown cancels the SHARED probe context
  (`Apply` builds it as `context.WithCancel`; `m.cancel()` cancels it).
  A probe interrupted mid-flight by that cancel is NEUTRAL to path
  health — `runSingleTest` returns before touching counters, the
  successive-loss threshold, events, or `fireTransition`, so
  ip-monitoring never remediates routes DURING teardown/reconfigure. The
  discriminator is the SHARED `ctx.Err()`, NOT the returned error's type:
  a genuine probe TIMEOUT is a per-probe SOCKET deadline (icmp
  `SetReadDeadline` / TCP dial timeout) that leaves `ctx.Err() == nil`
  and MUST still count as real path loss (an actually-unreachable target
  must still fail over). Only `m.cancel()` cancels the shared context, so
  `ctx.Err() != nil` is exactly a lifecycle stop; a probe's own timeout
  never cancels it. Regression-locked by
  `TestRunSingleTestLifecycleCancelIsNeutral5852` (neutral) +
  `TestRunSingleTestGenuineFailureStillCounts5852` /
  `TestRunSingleTestProbeDeadlineWithLiveCtxCounts5852` (no
  over-neutralization). Sibling of the setup-error hold above.
- The raw-socket seam is injectable (`icmpListenFunc` in `icmp.go`) so
  prober logic is unit-testable without privileges.
- **The http-get probe's transport is one-shot** (#4912): `probeHTTP`
  builds a per-probe `http.Transport`, sets `DisableKeepAlives: true`, and
  defers `CloseIdleConnections()`, then drains+closes the response body on
  every path. A bodyless response (HTTP 204 / `Content-Length: 0`) is
  fully consumed by `Body.Close()`, so the keep-alive default would return
  the socket to the idle pool of that now-unowned transport (whose
  `IdleConnTimeout == 0` never expires) — leaking one fd + read-loop
  goroutine per probe to an empty health endpoint. Disabling keep-alives
  closes the connection after the single request instead.
- **An http-get probe has bounded redirect and body work (#10726):** `probeHTTP`
  follows at most three redirect hops and refuses a longer chain. The response
  body drain remains capped at 1 MiB and the 10-second client timeout bounds
  stalled reads; a large but readable body still counts as a successful reply.
- `destination-interface` takes precedence over the routing-instance
  VRF device for `SO_BINDTODEVICE`; otherwise VRF binding uses
  `vrf-<ri-name>` — not the destination interface itself.
- Next-hop-pinned tests (`next-hop` leaf) set `SO_MARK` with the fwmark
  derived from `routing.BuildProbePins` — the SAME deterministic
  assignment pkg/routing programs as fwmark rules, so socket mark and
  kernel rule cannot drift.
- **A next-hop test whose pin failed to install never probes** (#1895):
  an unbacked `SO_MARK` falls through to the main table and measures
  the default path — a dead pinned uplink would false-PASS and
  suppress ip-monitoring failover. `executeProbe` returns
  `ErrProbeSetup` (hold state, no socket opened) while the pin is in
  the `SetPinInstallResults` failed map — or when a next-hop test has
  no pin slot at all (band exhaustion belt-and-braces). The daemon
  retries failed installs on hash-gated reconciles AND on a slow
  periodic loop (30 s, only while pins are failed), and clears the
  map on success — boot-time failures recover without a commit.
- Events expose both the test owner (probe name) and the test name so
  event-options policies can match on either via `attributes-match`.
- A consecutive-failure counter discriminates transient blips from
  sustained failures; `test_failed` only fires when the threshold is
  crossed, not on every individual missed probe.
