# pkg/logging

Multi-backend structured logging. Wraps `slog.Handler` with syslog
routing, a ring-buffer event subscription stream (consumed by the SSE
endpoint and the CLI's `monitor` commands), local file streaming with
facility/severity filtering, and a per-IP session aggregator for top-N
reports.

## Entry points

- `SyslogSlogHandler` — `slog_handler.go`. Slog handler that
  fans events out to configured syslog clients.
- `EventBuffer` — `eventbuf.go`. `NewEventBuffer(size int)` — the
  caller picks the size; `pkg/daemon/daemon_run.go` constructs it
  with 1000. A non-positive size is clamped to `defaultEventBufferSize`
  (1000) so the ring is never zero-capacity (a zero ring panics on the
  first `Add` via `head % size`, #3342). Bounded ring; full → drops the
  oldest entry. `Latest(n)` and `LatestFiltered(n, …)` both treat
  `n <= 0` as "return nothing" — a count argument never reaches
  `make([]EventRecord, n)` with a negative len (which panics).
- `Subscription` — `eventbuf.go`. A consumer of the event ring.
  `Subscribe(bufSize)` never fails and is the entry point ONLY for the
  TRUSTED, genuinely bounded in-process consumers (the CLI monitor). Every
  REQUEST-CREATED stream must use `TrySubscribe(bufSize)`, which returns
  `nil` once the live subscriber count reaches `defaultMaxSubscribers` (64):
  the UNTRUSTED REST SSE surface (`/api/v1/events/stream`,
  `/api/v1/logs/stream`) — the REST handler then responds `503` (#4484 L-2) —
  AND the gRPC `MonitorPacketDrop` stream, which is created per-RPC on the
  loopback-but-UNAUTHENTICATED gRPC listener and so is NOT inherently
  bounded (it returns `codes.ResourceExhausted` at the cap, #5850). A
  request-created stream that used the uncapped `Subscribe` would let any
  local process open an unbounded number of streams. Every `Add` fans out
  O(N) over the subscriber set and each subscription holds a buffered
  channel, so an unbounded set is a memory + per-event-CPU DoS vector on the
  untrusted surface; the cap mirrors `metricsMaxInFlight` (#4162). The cap
  counts ALL subscribers uniformly (trusted `Subscribe` callers included),
  so the trusted set (few, operator-driven) shrinks the untrusted headroom
  but is never itself rejected. The fan-out is intentionally lossy but
  OBSERVABLE (#5064): every record `Add` publishes is stamped with the
  buffer's monotonic `BufSeq` (from 1, strictly increasing per buffer — the
  SAME value stored in the ring, so a live stream and a `Latest()` snapshot
  agree), and a subscriber whose channel is full is skipped rather than
  blocking `Add`. When that happens the drop is counted per-subscriber
  (`Subscription.Dropped()`) and in aggregate (`EventBuffer.DroppedTotal()`,
  exported as `xpf_event_stream_subscriber_dropped_total`), and the NEXT
  record delivered to that subscriber carries `Overrun=true`. A consumer
  therefore detects loss three ways: a `BufSeq` discontinuity pinpointing
  which records were shed, the in-band `Overrun` flag, and the monotonic drop
  counters — so a gapped forensic stream can never be mistaken for a complete
  one. `BufSeq` is 0 and `Overrun` is false on records that never went
  through `Add` (a bare `EventRecord` literal or `DecodeRawEventRecord`),
  distinct from `EventSeq` (the reader-scoped per-event ordinal, #4915).
  `Close()` unsubscribes AND closes `C`
  (#3384): a consumer ranging over `C` until it closes terminates rather
  than blocking forever. The unsubscribe runs first under the fan-out write
  lock (so a concurrent `Add` can never send on the closed channel) and
  `sync.Once` makes a double `Close` safe. `ParseSeverityStrict` / `ParseCategoryStrict`
  (`syslog.go`) are the fail-closed parse variants — they return an error
  on an unknown token instead of `0` ("no filter"); the SSE log/event
  stream uses them so a typo'd query rejects rather than streaming
  everything (#3383).
- `LocalLogWriter` — `locallog.go`. File-based writer with
  facility/severity filters. The active file and every rotation reopen go
  through the shared hardened open (`openHardenedAuditLog`, `trace.go`):
  `O_NOFOLLOW`, regular-file verified, mode `0600` (not world-readable
  `0644`), dir `0750` — the event-mode security log carries the same
  policy/session/NAT forensics the flow-trace writer was hardened for
  (#3477). The `0600` is *enforced*, not create-only: an existing
  pre-hardening `0644` file is `fchmod`-tightened on open (on the held
  O_NOFOLLOW regular-file fd) so an upgrade does not leave it
  world-readable. Write and rotation failures are observable:
  `DroppedWrites()` counts lost lines (write error AND nil-file/closed
  paths), `FailedRotations()` counts incomplete rotations (a generation
  shift, the active-file rename, or the reopen), and a ≤1/s WARN — with
  separate clocks per failure class so a write-drop storm cannot suppress
  the rotation warning — carries both counts (#3478).
- `SessionAggregator` — `aggregator.go`. Top-N per-IP rollups,
  cardinality-capped (see "Aggregator cardinality cap" below).

## Callers

`pkg/daemon`, `pkg/api`, `pkg/grpcapi`, `pkg/flowexport`, `pkg/cli`.

## Dependencies

`pkg/config`, `pkg/dataplane`.

## Logging rules (CLAUDE.md authoritative)

- Use `slog.Debug` for high-frequency or per-packet diagnostics. Use
  `slog.Info` only for state transitions and one-time events.
- The HA watchdog sync was previously logging at `slog.Info` 15 times per
  second, drowning out real diagnostics. Don't reintroduce that pattern.
- Never put `slog.Info` inside per-session, per-packet, or per-poll-tick
  loops.

## Syslog stream-transport resilience (#2283)

`SyslogClient.Send` / `SendBinary` are reached on the SHARED dataplane
event hot-path (EventStream reader → `EventReader.ProcessRawEvent` →
`logEvent` → `SyslogClient.Send`). The event reader runs that path
inline, so a syslog client must never block or thrash on a bad target.
Two bounds enforce that for the stream transports (TCP/TLS); UDP is
connectionless and exempt:

- **Per-write deadline.** Every TCP/TLS `conn.Write` is preceded by
  `SetWriteDeadline(now + writeTimeout)` (default
  `defaultWriteTimeout`, 4s). A slow/hung/congested server surfaces as
  `os.ErrDeadlineExceeded`; the message is dropped (counted, not
  retried-in-place) and the reader continues. Without this a hung
  server stalls the entire event reader indefinitely.
- **Timeout drops without retry (#2287).** A write that fails with a
  *timeout* (the deadline expired — `net.Error.Timeout()==true`) is
  dropped and returned immediately. It is NOT reconnect+retried: the
  deadline already bounded the attempt, and reconnecting would re-arm
  another full `writeTimeout`, doubling the worst-case stall on the
  event reader (~2× plus a dial). Only a *genuine connection error*
  (broken pipe / ECONNRESET, non-timeout) triggers the reconnect+retry
  path below.
- **Partial-frame teardown (#3874).** A stream `conn.Write` can return
  `0 < n < len(b)` — some but not all of the framed record reached the
  wire — when the deadline expires (or the peer resets) mid-write. Both
  stream framings are corrupted by a truncated write: the RFC 6587
  octet-count prefix (`<len> <msg>`) and the self-framing binary record
  (length at offset `[3:5]`) both tell the collector to expect `len`
  bytes, so a truncated frame leaves the collector's length parser
  mid-record. If the connection stayed up, the NEXT frame's bytes would
  concatenate onto the truncated one and the parser would mis-frame every
  subsequent message — a **permanent desync of the audit/forensics
  channel**, exactly under incident load (slow writes / a backpressured
  collector, when the logs matter most). A half-written octet-counted
  frame is unrecoverable in-stream, so `streamWrite` tears the connection
  down (`conn=nil`) whenever `0 < n < len(b)`; the next `Send` sees
  `conn==nil`, treats it as a non-timeout write failure, and the
  cooldown-gated reconnect path dials a fresh, correctly-counted stream
  (the resync). A **clean 0-byte timeout** (`n==0`) wrote nothing, cannot
  desync the collector, and stays drop-without-close per #2287 — only a
  partial write closes. Closing the raw conn here does NOT reintroduce
  the #2285 re-entrant deadlock: `net.Conn.Close` (and `*tls.Conn.Close`)
  is a pure syscall that never routes back through the
  slog→`SyslogSlogHandler.Handle`→`SyslogClient.Send` path, so it cannot
  re-lock `s.mu` on the sending goroutine. It is also NOT the #2287 stall
  hazard: the close is cheap (no dial, no second `writeTimeout`) — the
  reconnect happens on the next `Send` via the `conn==nil` path, so the
  worst-case in-`Send` stall stays one `writeTimeout`.
- **Reconnect cooldown.** A non-timeout write failure on a stream
  transport attempts one reconnect, gated by `reconnectCooldown`
  (default `defaultReconnectCooldown`, 1s). If the previous reconnect
  cycle failed inside the window, the reconnect is skipped and the send
  fails fast (drop) — so a down server cannot drive a fresh 5s-timeout
  dial on every event (thundering herd). The cooldown clock
  (`lastReconnectFailure`) is armed by BOTH failure modes (#2302): a
  failed **dial**, AND a dial that succeeds but whose subsequent
  retry-**write** fails (accept-then-reset collector, half-open server,
  TLS app-layer drop). Gating only on a failed dial left an
  accept-then-reset target permanently un-throttled — the dial succeeded
  every time, so every log message drove a fresh TCP connect + teardown
  (a dial storm: ephemeral port exhaustion + SYN pressure on the
  collector). The clock is cleared only on a FULLY successful reconnect
  (dial AND the retry-write both land), so the legitimate
  single-broken-pipe recovery path is unaffected.
- **Severity filtering — complete threshold mapping (#5314).**
  `SyslogClient.MinSeverity` encodes the Junos `host <facility> <severity>`
  threshold: "forward this severity AND every more-severe one" (lower RFC
  number = more severe). `ShouldSend(sev)` forwards a record iff it is at
  least as severe as `MinSeverity`. The representation:
  - `0` = no filter — forward everything. This is the ZERO VALUE (an
    unconfigured client forwards all) and what Junos `any`, an unset
    severity, and (tolerantly) an unknown token map to.
  - `SeverityNone` (-2) = Junos `none` — forward nothing.
  - `SeverityEmergency` (-1) = Junos `emergency` — forward ONLY emergency.
    Emergency is RFC severity 0, which is already the send-all sentinel, so
    the most severe level gets its own code rather than collapsing into
    send-all.
  - raw RFC level `alert(1)..debug(7)` — forward `severity <= MinSeverity`.

  `ParseSeverity` maps all ten schema severities
  (`junosSyslogSeverities`, pkg/config) to these codes, case-insensitively.
  Before #5314 it mapped only error/warning/info and returned 0 for
  everything else, so `host H <facility> critical` collapsed to the
  send-all sentinel and a security appliance forwarded substantially more
  syslog data than authorized — critical/notice/alert/emergency/debug/none
  all leaked as "no filter". A syslog host that lists several
  `<facility> <severity>` pairs is folded to one client filter via
  `MoreRestrictiveMinSeverity` (the most restrictive pair wins).
- **Unmapped facility names are reported, not silent (#5797).**
  `ParseFacility` returns `FacilityLocal0` for any name it does not know,
  which makes an authored `local0` indistinguishable from a name the
  mapper simply lacks — and the mapper lacks the **Junos** facility
  vocabulary outright. Junos writes `authorization`, `kernel`,
  `interactive-commands`, `conflict-log`, `pfe`; `ParseFacility` knows only
  the BSD/rsyslog spellings (`auth`, `kern`, ...). So an ordinary Junos
  `host H authorization critical` forwards under **local0** today and the
  collector's facility-based routing misfiles it, with no signal.
  `ParseFacilityChecked` returns the "was this recognized" bit so the
  daemon can warn; the substituted code is unchanged, because which
  facility a record actually goes out under is an operator-visible contract
  question still owned by #5797. Prefer the checked form at any call site
  that can surface the difference.
- **rsyslog selector tokens are shape-checked (#5797).** The `file` and
  `user` destinations do not use `SyslogClient` at all — the daemon builds
  an rsyslog selector `<facility>.<severity>` and writes a managed drop-in.
  #4902 belted the file NAME and user TOKEN on that line but not the two
  selector tokens, so a newline or an rsyslog metacharacter in either one
  escaped the selector and injected configuration on the leniently-loaded /
  peer-synced path. `syslogSelectorTokenSafe` (pkg/daemon) rejects anything
  outside `[A-Za-z0-9-]`, which admits the entire legitimate Junos
  vocabulary — including the names the mapper cannot yet resolve — so the
  belt does not pre-empt the mapping decision above.
- **Lazy connect — receiver down at apply does not disable the stream
  (#3351).** A TCP/TLS receiver that is unreachable at config-apply or
  boot must NOT permanently silence the stream. `NewSyslogClientTransport`
  therefore returns a *usable but unconnected* client (`conn==nil`,
  cooldown pre-armed) PLUS the dial error for the caller to log, rather
  than `(nil, err)`. The first `Send` sees `conn==nil`, treats it as a
  non-timeout write failure, and the cooldown-gated reconnect path above
  dials when the receiver returns — so audit logging resumes on its own.
  The cooldown is armed at construction (so the first reconnect waits one
  window instead of dialing under `s.mu` on the very next event, exactly
  as `reconnect()` arms on a failed dial). UDP is unaffected: a UDP
  "dial" needs no live peer, so a UDP failure is a genuine construction
  error (unresolvable host / bad source bind) and still returns
  `(nil, err)` — lazy connect is TCP/TLS-only. The daemon
  (`applySyslogConfig`) installs the non-nil client even when the
  constructor returns an error, logging `syslog stream receiver
  unreachable at apply; installed in reconnecting state`. Because a
  reconnecting client now outlives a transient outage, the daemon's
  zero-streams path tears the clients down when a day-2 commit removes
  ALL streams — otherwise a down-at-apply client would resume forwarding
  audit logs to a deleted receiver once it recovered.
  `EventReader.SyslogClientCount()` exposes the installed count for that
  teardown assertion.
- **Unknown transport fails CLOSED — no silent plaintext-UDP downgrade
  (#5581).** `NewSyslogClientTransport` accepts only the empty default
  (→ `udp`), `udp`, `tcp`, and `tls`; any other token (a typo like
  `tls-typo`, a newer/unsupported value, wrong case) returns
  `(nil, ErrUnsupportedTransport)`. Previously the constructor accepted
  any token and `dial()`'s `default` arm mapped every unrecognized value
  to `dialUDP()`, so a security-log stream configured with a bad
  transport shipped audit records as **plaintext UDP** while config and
  status still named a non-UDP transport. The strict commit schema
  (`security log stream <s> transport protocol`, enum `udp|tcp|tls`,
  #2008) already refutes bad tokens at a normal commit, but the tolerant
  persisted / HA-synced load path does not — so this runtime guard is the
  fail-closed backstop for a token that never passed a current strict
  commit. `dial()` also fails closed on an unrecognized `s.protocol`
  (defense-in-depth for the reconnect path) instead of downgrading to
  UDP. The daemon (`applySyslogConfig`) hits the existing `client==nil`
  branch, logs `failed to create syslog client` with the bad token, and
  installs NO client — the operator sees a visible apply error rather
  than a stream that silently forwards nowhere-secure. This differs from
  the #3351 lazy-connect case: a down-at-apply TCP/TLS receiver returns a
  *non-nil* reconnecting client (transient reachability), whereas an
  unknown transport is a *configuration* error that yields a nil client.
- **In-process CLI commit PRESERVES the configured transport (#5712).**
  The CLI-side `reloadSyslog` (`pkg/cli/apply.go`) runs on EVERY
  local-console commit/rollback (#3704) and calls `ReplaceSyslogClients`
  on the event reader SHARED with the daemon — AFTER the daemon's
  `applySyslogConfig` already installed the correct clients. It used to
  rebuild every stream as plaintext UDP via `NewSyslogClient`, a duplicate
  runtime owner that CLOBBERED a configured TCP/TLS stream back down to
  UDP, silently downgrading the secure-syslog transport after an
  in-process commit. `buildSyslogClients` now builds through
  `NewSyslogClientTransport` with `stream.Transport.Protocol` (carrying the
  per-stream source-address and facility, and the #3351 reconnecting
  install), so the rebuild is idempotent with the daemon's build and the
  configured transport survives regardless of which owner writes last.
- **Daemon syslog-apply CLOSES superseded clients (#3579).**
  `applySyslogConfig` (pkg/daemon) rebuilds every `SyslogClient` from
  config on each apply, so the prior set is always fully superseded
  by-object. It therefore swaps via the closing `ReplaceSyslogClients`
  (which installs the new set then `Close()`s the old set after releasing
  `syslogMu`), NOT the non-closing `SetSyslogClients` — matching the CLI
  apply path (`pkg/cli/apply.go`). Previously `applySyslogConfig` used
  `SetSyslogClients`, which dropped the old clients from the set without
  closing them, leaking one TCP/TLS socket (fd) per re-apply that changed
  or removed a CONNECTED stream. All three apply branches (event-mode,
  zero-streams teardown, and stream install) close. `SyslogClient.Close`
  takes only the client's own mutex and emits no slog, so closing from
  the apply path cannot re-enter the slog->syslog handler under a held
  lock (#2285).
- **Drop warning emitted AFTER the lock is released (#2287).**
  `SyslogClient.Send`/`SendBinary` hold `s.mu` for the whole write +
  reconnect sequence. The rate-limited drop warning (`slog.Warn`) must
  NOT be emitted while `s.mu` is held: `slog.Default()` is the
  `SyslogSlogHandler`, whose `Handle` synchronously calls back into
  this same client's `Send`, which re-locks `s.mu` (`sync.Mutex` is
  non-reentrant) → self-deadlock on the dataplane event-reader
  goroutine. `noteDrop` therefore only *captures* the warning snapshot
  under the lock; the caller emits it via a `defer` ordered to run
  after the `Unlock`. The ≤1/s gate is preserved.
- **Handler re-entrancy guard (#2287).** As defense-in-depth,
  `SyslogSlogHandler.Handle` tracks the set of goroutine IDs currently
  inside its syslog-forwarding section. If a client `Send` emits any
  slog record (drop warning or otherwise) that routes back through the
  handler on the SAME goroutine, the nested record is NOT re-forwarded
  to syslog — so no present or future under-lock/transitive slog call
  from the send path can wedge the daemon by recursing into a client's
  `Send`. The guard is per-goroutine (not a per-handler flag), so
  concurrent `Handle` calls on different goroutines are never falsely
  skipped. Forwarding to the base handler (stderr) stays unconditional,
  even on a re-entrant call, so records are never lost from local logs.
  `Handle` snapshots the client set FIRST and returns before the guard
  when there are no clients (the default until syslog config applies), so
  the guard's `goID()` (`runtime.Stack` + `ParseUint`) never runs on the
  common no-client path (#2295) — only when a record is actually being
  forwarded to at least one client.

Drops are observable via `DroppedWrites()` (write timeout or write
error), `DroppedDials()` (post-write-failure reconnect dial failed),
and `DroppedCooldown()` (reconnect suppressed by cooldown); the drop
warning is rate-limited to ≤1/s so a flapping target cannot spam the
log from the hot-path (CLAUDE.md logging rules). The warning's `reason`
attribute is one of `write` / `dial` / `cooldown`.

Tests (`syslog_resilience_test.go`, `syslog_reentrancy_test.go`) use
deterministic fakes — a deadline-honouring conn, an always-fail conn, a
timeout conn, a recording conn, a controllable clock, and a dial seam
(`dialFn`/`nowFn`) — plus a `goIDFn` seam — with no sleeps. The hang
test fails if the write deadline is removed; the cooldown test fails if
the cooldown gate is removed; the accept-then-reset test (#2302) fails
(sees a 50-dial storm) if the cooldown is not armed on a
dial-success-then-write-failure; the re-entrancy test deadlocks (and
times out) if the drop warning is moved back under `s.mu` or the handler
guard is removed; the timeout-drop test fails (sees a dial) if a write
timeout reconnects; the no-client test (#2295) fails (sees `goID` calls)
if `Handle` runs the re-entrancy guard before the client check. The
lazy-connect tests (`syslog_lazy_connect_3351_test.go`) fail if the
constructor reverts to dropping a TCP/TLS client when the receiver is
down at apply (`got nil` — stream permanently disabled) or if a lazy
client never reconnects once the receiver returns.

## Gotchas

- The binary RT_FLOW format used by Junos session logging is custom; it
  is not human-readable without a parser. Use the local-log facility for
  human-readable session events.
- Userspace event-stream telemetry enters through
  `EventReader.ProcessRawEvent`, not by direct `EventBuffer.Add`, so it
  gets the same name resolution, callback fanout, local writers, and
  syslog delivery as the legacy eBPF ring-buffer events do.
  `DecodeRawEventRecord` is decode-only and must not be used as a
  replacement for the full reader path when audit delivery matters.
- **Protocol names come from the `appid.ProtocolName` SSOT (#3040).** The
  event-log `protoName` helper (`ringbuf.go`) renders an IP protocol number
  through the shared `appid.ProtocolName` table that REST (`pkg/api`,
  #2949) and gRPC (`pkg/grpcapi`, #3037) already use, so GRE(47)/ESP(50)/
  IPIP(4)/IPv6(41) sessions display named (GRE/ESP/IPIP/IPV6) instead of
  numeric — matching the other operator surfaces. Before #3040 this helper
  carried its own tcp/udp/icmp/icmpv6 map and rendered every other protocol
  as a bare number. Casing is an event-log-local concern (this surface
  upper-cases, keeping ICMPv6 mixed-case for the trace-filter contract);
  unknown protocols still fall back to the numeric form. Pin:
  `protoname_test.go`.
- **Zone names are resolved AS-OF the event, not recomputed live (#3335).**
  `EventReader.ProcessRawEvent` (`ringbuf.go`) stamps `EventRecord.InZoneName`
  / `OutZoneName` from the dataplane's zone-ID→name table at the instant the
  event fires. All three consumers that render zone names — the interactive
  `show security log` (`pkg/cli/cli_show_security_log.go`), the gRPC
  `GetEvents` (`pkg/grpcapi/server_show_events.go`), and the showText
  "security-log" topic (`Server.showSecurityLog` in
  `pkg/grpcapi/server_show_security_text.go`, which the remote `cli` binary
  routes `show security log` through) — MUST prefer those stored names and
  fall back to the current-config reverse map only for legacy records whose
  resolved name is empty. Recomputing from the live config corrupts forensic
  timelines: zone IDs are assigned from current state and can be renumbered
  (#3075), so an old event that carried `InZoneName="trust"` would otherwise
  re-render under whatever name now owns that ID. Pins:
  `server_show_events_historical_zone_3335_test.go` (covers `GetEvents` AND the
  showText `showSecurityLog` topic),
  `cli_show_security_log_historical_zone_3335_test.go`.
- **Flow-trace files are basename-only under `/var/log` (#3420).**
  `NewTraceWriter` (`trace.go`) treats the persistent
  `security flow traceoptions file <name>` value as a bare basename: an
  absolute path, a path separator, or a `.`/`..` component is rejected
  (`sanitizeTraceFileName`), the file is opened under `traceLogDir`
  (`/var/log` in production; a package var only so tests can redirect it)
  with `O_NOFOLLOW` and verified to be a regular file, and its mode is
  enforced to `0600` rather than world-readable — created `0600`, and an
  existing looser file `fchmod`-tightened on open (#3477) — flow
  tuples/zones/policy IDs are audit-grade telemetry. Rotation reopens
  through the same `openTraceFile` guard, which now delegates to the shared
  `openHardenedAuditLog` helper that `LocalLogWriter` also uses (#3477) —
  both audit-log writers get identical O_NOFOLLOW / regular-file /
  enforced-0600 semantics. Before #3420 the value was kept
  verbatim (absolute) or joined under
  `/var/log` without a `..` check, so a committed config could append
  root-written telemetry anywhere the daemon could write. The committed
  config is also rejected at commit-time (`validateFlowTraceFileAST`,
  `pkg/config`); this runtime guard is the defense-in-depth backstop that
  fails safe (tracing disabled) on a leniently-loaded / peer-synced value.
  This is the persistent-config sibling of the interactive
  `monitor security flow file` hardening (#3378). Pins:
  `TestNewTraceWriterRejectsPathTraversal`,
  `TestNewTraceWriterNoFollowSymlink`.
- **Flow-trace flags and packet-filter prefixes are validated, and fail
  safe at runtime (#3422).** A `security flow traceoptions packet-filter
  <n> { source-prefix / destination-prefix <prefix> }` whose value does not
  parse, or a `flag <name>` the writer does not implement (only
  `basic-datapath` and `session` are honoured — `matchFlags`), is rejected
  at commit-time (`validateFlowTraceFlagsAndFiltersAST`, `pkg/config`). The
  lenient load / peer-sync path downgrades both to warnings and
  `NewTraceWriter` fails safe: an unparseable filter is kept but marked
  `invalid` (never-match) instead of being dropped — dropping every typo'd
  filter would leave `tw.filters` empty and `HandleEvent` would then trace
  EVERYTHING (a filter meant to narrow tracing broadened it, M01); an
  unimplemented flag is dropped rather than installed into a non-empty flag
  map that suppresses the `basic-datapath`/`session` defaults and makes
  `matchFlags` never match (an empty trace file while the daemon reports
  tracing enabled, M02). Pins: `TestFlowTraceFilterFailsCommit` /
  `TestFlowTraceFilterLenientDowngrade` (`pkg/config`),
  `TestTraceWriterInvalidFilterMatchesNone` /
  `TestTraceWriterUnknownFlagAppliesDefaults` (`pkg/logging`).
- **Audit-log write/rotation failures are observable, not silent (#3478).**
  Both audit-log writers (`TraceWriter`, `LocalLogWriter`) and the session
  aggregator (`ForwardLogMsg`) previously swallowed write and rotation
  failures — a bare `return`, a `_ =`, or a production-off `slog.Debug` — so
  an operator who had enabled `traceoptions` / `security log mode event`
  could not tell ENOSPC/EIO/closed-fd/failed-rename was dropping audit lines.
  Each writer now exposes `DroppedWrites()` and `FailedRotations()` as atomic
  counters, with a ≤1/s WARN carrying both (CLAUDE.md hot-path logging
  rules — never per-event). The two failure classes use SEPARATE warn clocks
  so a write-drop storm cannot suppress the rotation warning, and vice versa.
  `DroppedWrites()` covers EVERY drop path — a failed write AND a
  nil/closed-file write (a writer wedged by a prior failed reopen would
  otherwise drop every subsequent event after a single `FailedRotations`
  bump). `FailedRotations()` covers a failed generation shift (a lost
  retained generation), a failed active-file rename, and a failed reopen.
  `rotate()` returns an error on any of those and resets the byte accounting
  to 0 ONLY when the active file was actually rolled aside; on a failed
  primary rename it re-syncs `written` to the real file size so the next
  write retries rotation instead of growing unbounded under a bogus 0. The
  aggregator surfaces the per-call error at Debug (the writer counter is the
  aggregate metric). Pins: `TestTraceWriter_WriteFailureObservable`,
  `TestTraceWriter_RotationFailureObservable`,
  `TestTraceWriter_GenerationShiftFailureObservable`,
  `TestTraceWriter_NilFileDropObservable`,
  `TestTraceWriter_TightensExistingMode`,
  `TestLocalLogWriter_WriteFailureObservable`,
  `TestLocalLogWriter_RotationFailureObservable`,
  `TestLocalLogWriter_GenerationShiftFailureObservable`,
  `TestLocalLogWriter_NilFileDropObservable`,
  `TestLocalLogWriter_TightensExistingMode`,
  `TestLocalLogWriter_HardenedOpen`.
- **Flow-trace uses ONE stable EventReader callback, writer swapped in place
  (#3932).** The daemon registers a single indirection callback
  (`Daemon.flowTraceCallback`, `pkg/daemon/daemon_flow.go`) on the
  `EventReader` exactly once — guarded by `traceCBOnce` — and every config
  commit that changes `security flow traceoptions` only SWAPS the underlying
  `TraceWriter` behind an `atomic.Pointer`, closing the writer it replaced
  (`reconcileFlowTrace`). Before #3932, `applyFlowTrace`/`updateFlowTrace`
  called `EventReader.AddCallback` on every such commit without removing the
  previous one, so a long-lived daemon accumulated N callbacks: each event was
  dispatched to all N, and the stale (already-closed) writers still received
  every event, bumping their `DroppedWrites` — a growing per-event cost plus a
  leaked-writer drop storm. The callback reads the live writer lock-free;
  `traceReconMu` serializes the build+swap on the commit path so exactly one
  writer is closed per swap. Disabling traceoptions clears the pointer to nil
  (the stable callback stays but becomes a no-op); a build failure keeps the
  current writer running (the flowexport #3742 keep-old-on-failure posture).
  `EventReader.CallbackCount()` is the leak witness. Pin:
  `TestFlowTraceSingleCallbackAcrossReconciles` (`pkg/daemon`).
- **Session aggregator: equality gate keeps the live window, teardown flushes
  it (#5313).** `applyAggregator` (`pkg/daemon/daemon_system.go`) derives a
  comparable `aggregatorSig` (report enabled + flush interval + top-N) from the
  active config and retires+rebuilds the running `SessionAggregator` ONLY when
  the signature genuinely changes. An unchanged report-enabled re-apply — any
  unrelated commit that re-runs `applySyslogConfig` (a syslog-stream edit, a
  hostname change) — now keeps the SAME live aggregator, so its pending flush
  window survives. Before #5313 `applyAggregator` cancelled+replaced on EVERY
  call, and `SessionAggregator.Run` returned on `ctx.Done()` WITHOUT flushing
  (`flushAndLog` fired only on `ticker.C`), so up to a full ~5 min window of
  accumulated `SESSION_CLOSE` counters was silently discarded on any such
  commit. The composed fix: (1) the equality gate above, and (2) `Run` now
  performs a FINAL `flushAndLog` on `ctx.Done()` before returning, so a genuine
  replace/disable/shutdown emits the retiring window as its own (partial)
  report and the new generation starts from an empty window. `flushAndLog`
  suppresses an all-empty report and `topAndReset` drains the window, so a
  ticker flush immediately followed by teardown neither double-counts nor emits
  an empty line. Pins (fail-on-revert): `TestApplyAggregatorEqualityGateKeeps-
  LiveAggregator` + `TestApplyAggregatorConfigChangeFlushesPendingWindow`
  (`pkg/daemon`), `TestAggregatorRunFinalFlushOnCancel` +
  `TestAggregatorRunNoEmptyFlushOnCancel` + `TestAggregatorFlushAndLogNoDouble-
  Emit` (`pkg/logging`).
- **Event time is DECISION time, not receive time (#2465/#2470/#2511).**
  The on-wire RT_FLOW frame carries an absolute Unix-nanosecond timestamp
  in its first 8 bytes (LE u64), stamped by the userspace-dp producer at
  the instant the forwarding decision was made. Both the live reader path
  (`ProcessRawEvent` → `logEvent`) and the decode-only
  `DecodeRawEventRecord` set `EventRecord.Time` from that wire value via
  the shared `eventTimeFromWire` guard: a nonzero timestamp that fits an
  `int64` wins; a zero/absent stamp (old-format frame or synthesized
  event) or one that would overflow `int64` falls back to `time.Now()`
  (daemon receive time). Before #2511 `logEvent` always used `time.Now()`,
  so the production logging path recorded receive time even though
  `DecodeRawEventRecord` already honored the wire stamp — under helper
  backlog or reconnect that drifted from the decision instant. Keep the two
  paths on the single `eventTimeFromWire` SSOT.
- **SESSION_CLOSE log lines carry no `action` (#2513).** A session close
  is a termination event, not a forwarding decision, so it has no
  permit/deny/reject action — the userspace-dp producer writes the wire
  action byte as 0 for a close
  (`encode_session_close_rt_flow`). Byte 0 maps to "deny" via
  `actionName`, so the standard (plain) formatter used to render
  `RT_FLOW SESSION_CLOSE ... action=deny ...`, which misread as a drop.
  Both close renderers now omit action: the standard line
  (`formatSyslogMsg`, keyed on `Type == "SESSION_CLOSE"`) drops the
  `action=` field and keeps `proto/policy/zone/pkts/bytes`; the structured
  line (`formatStructuredMsg` `RT_FLOW_SESSION_CLOSE`) never carried one and
  reports a close `reason="..."` (e.g. "TCP FIN", "idle Timeout") matching
  Junos. The omission is scoped to the close event type only — POLICY_DENY,
  SCREEN_DROP, and FILTER_LOG (the genuine deny/reject paths) still render
  `action`. Golden coverage: `session_close_format_test.go`.
- **SESSION_OPEN log lines carry no `action` (#2593).** Sibling of #2513
  on the adjacent event: a session open (`RT_FLOW_SESSION_CREATE`) is a
  permit-and-create event, not a forwarding decision, so it has no
  permit/deny/reject action — the userspace-dp producer writes the wire
  action byte as 0 for a create
  (`encode_session_create_rt_flow`), identical to the close path. Byte 0
  maps to "deny" via `actionName`, so the standard (plain) formatter used
  to render `RT_FLOW SESSION_OPEN ... action=deny ...`, which misread a
  successful permit-and-open as a drop. Both create renderers now omit
  action: the standard line (`formatSyslogMsg`, keyed on
  `Type == "SESSION_OPEN"` — `eventTypeName(eventTypeSessionOpen)`) drops
  the `action=` field and keeps `proto/policy/zone`; the structured line
  (`formatStructuredMsg` `RT_FLOW_SESSION_CREATE`) never carried one. The
  omission is scoped to the open event type only — POLICY_DENY,
  SCREEN_DROP, and FILTER_LOG (the genuine deny/reject paths) still render
  `action`. Golden coverage: `session_create_format_test.go`.
- **Implicit default-policy renders as `policy-name="default-policy"`
  (#3057).** A flow that matches no configured zone-pair or `junos-global`
  policy is decided by the implicit `security policies default-policy`
  (deny-all / permit-all). The userspace-dp producer stamps a RESERVED
  sentinel policy ID on that deny/reject event —
  `DEFAULT_POLICY_SENTINEL_ID = u32::MAX` (`0xFFFFFFFF`,
  `userspace-dp/src/policy.rs`), mirrored on the Go side as
  `dataplane.DefaultPolicySentinelID`. A real configured policy ID is
  `policySetID*MaxRulesPerPolicy + ruleIndex`, so `0xFFFFFFFF` can never be a
  real ID (it would need ~16.7M policy sets); the two stay byte-identical on
  the shared `policy_id` u32 wire field (no layout change) and are pinned by
  `TestDefaultPolicySentinelLockstepWithRust`. Before #3057 the default
  emitted `0`, which ALIASED the FIRST configured policy (also ID 0): a
  default deny then logged with the first rule's name — actively misleading
  when that rule is a permit. `resolvePolicyName` now resolves the sentinel
  to `dataplane.DefaultPolicyName` (`"default-policy"`) authoritatively (even
  before any policyNames map is published); `compilePolicies` also seeds the
  sentinel into the `PolicyNames` map so `show security flow session` and the
  gRPC session entries render it consistently. The sentinel is display-only —
  the implicit default touches NO per-rule hit counter (those are name-keyed
  per #3143/#3154 and only the matched-rule path in `try_match_rule`
  increments one). Coverage: `default_policy_sentinel_3057_test.go`
  (Go) + `default_policy_no_match_emits_sentinel_policy_id` /
  `policy_deny_event_emit_carries_default_policy_sentinel` (Rust).
- `pkg/dataplane/userspace/eventstream_test.go` owns the deterministic
  local syslog harness for userspace RT_FLOW policy-deny, screen-drop, and
  filter-log frames. It sends raw event-stream frames through
  `EventReader.ProcessRawEvent` and a UDP syslog listener, so changes to
  userspace decode or fanout should extend that harness rather than bypass it.
- The event buffer is bounded. If a subscriber stops draining, new events
  drop silently — by design. Don't wire a slow consumer to it.
- The session aggregator flushes on a 5-minute timer. The flushed
  snapshot is the basis for `show security session aggregate`.

### Aggregator cardinality cap (#2936)

`SessionAggregator` keyed its source/destination maps by every distinct
IP seen in `SESSION_CLOSE` events with no bound. Under high-cardinality
traffic (spoofed-source or scan traffic — exactly what a security
appliance sees during an incident) the two maps grew for the full flush
window, and `topEntries` then allocated and `sort.Slice`-sorted O(N) over
the entire cardinality twice per flush. The observability feature became
a control-plane resource-exhaustion amplifier — it degraded under the
very traffic it is meant to report on.

The interim fix bounds memory **by configuration, not by traffic
cardinality**: each map admits at most `defaultMaxAggKeys` (10000)
distinct keys per flush window. Once a map is at the cap, a NEW key is
dropped and counted in `droppedSrc`/`droppedDst`; keys already admitted
keep aggregating, so the top-N over the admitted set stays accurate. The
per-flush allocate+sort cost is therefore bounded by the cap.

When the cap is hit, `flushAndLog` emits a warning-severity
`RT_FLOW_SESSION_AGGREGATE dropped-keys source=N destination=M cap=K`
line in addition to the top-N report. A non-zero `dropped-keys` count is
itself an incident indicator (cardinality exceeded the cap this window).
Below-cap traffic produces identical top-N output with no dropped line —
the common case is behavior-preserving. Coverage:
`TestSessionAggregator_CardinalityCap` (fail-on-revert) and
`TestSessionAggregator_BelowCapUnchanged`.

This is a deliberate interim. Capped maps keep the top-N exact only for
the keys admitted *before* the cap was reached; a heavy hitter whose
first packet of the window arrives after the cap fills is missed.
Bounded heavy-hitter accounting (Space-Saving / Misra-Gries top-K with an
overflow bucket) would make the top-K accurate independent of arrival
order under adversarial cardinality. That accuracy refinement is tracked
as a follow-up and is not required to close the DoS.
