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

## Control bytes never reach the syslog wire (#6585)

`SyslogClient.Send` runs `termsafe.SanitizeForDisplay` on the message
before it becomes a frame. That is the LAST boundary before the wire and
every caller passes through it, which is the point: the producers are
open-ended — any `slog` attribute anywhere in the daemon — so a
per-producer fix rots on the next one.

**Why the local copy was already safe and this one was not.** Go's
standard `slog` text handler quotes non-printing attribute values, so the
stderr/journald copy is protected. `SyslogSlogHandler` deliberately
bypasses that path to build the syslog framing itself (`formatRecord`
rebuilds attributes with a raw `slog.Value.String()`), and reintroduced
the raw value.

**A proven live producer.** DDNS provider error text reaches
`slog.Warn(..., "err", err)` in `pkg/ddns/surface_a.go`, and that error
embeds the PROVIDER's decoded response body — Route 53's `e.Error.Code` /
`e.Error.Message` and Cloudflare's `cfErrors(env)`. A hostile,
compromised or MITM'd DDNS endpoint therefore gets its bytes onto the
operator's remote syslog.

**Two consequences, both worse than the terminal case** because syslog is
aggregated and long-retained:

1. **Log injection.** RFC 3164 has no length prefix, so a bare LF is a
   record delimiter — a collector writing records to a file, or a relay
   forwarding with RFC 6587 non-transparent framing, reads the payload as
   an additional record with an arbitrary priority, timestamp and host.
2. **Deferred terminal injection.** ESC/CSI stored verbatim in the
   collector fires whenever an operator later `cat`s or `tail`s the
   archive.

**Variant choice matters here.** `SanitizeForDisplay` (single-line), NOT
`SanitizeBlockForDisplay` — the block variant deliberately PRESERVES LF,
which is correct for a multi-line table and exactly wrong for a single
syslog frame.

**Placement matters too.** The call sits before the format branch, so
both RFC 3164 and RFC 5424 (`sd-syslog`) are covered; which format is
live is an operator config choice, not a property of the code. The
sanitizer's allocation-free fast path means an already-clean record — every
ordinary one — pays a scan and no allocation, which is what keeps this
acceptable on the shared dataplane event path described below.

The hostname is sanitized at that same frame boundary, independently of
where the client was constructed. Only hostname-token bytes are allowed;
spaces, control characters, line breaks, and other framing delimiters are
replaced with `_` for both network RFC 3164/RFC 5424 and local RFC 5424
records. The clean-hostname fast path allocates nothing.

## RFC 5424 SD-PARAM values are escaped at the interpolation (#9321)

`formatStructuredMsg` builds the Junos `[junos@2636.1.1.1.2.129 …]`
STRUCTURED-DATA element and interpolates operator- and config-derived
names into `param="%s"`: policy, source/destination zone, application,
`service-name`, `packet-incoming-interface`, plus the close/deny reason.
RFC 5424 §6.3.3 requires `"` (%d34), `\` (%d92) and `]` (%d93) to be
escaped with a backslash inside a PARAM-VALUE. Until #9321 none of the
three was.

`escapeSDParamValue` now escapes all three, applied ONCE per value in
`formatStructuredMsg` — after the empty-value fallbacks (a fallback is
itself a param value) and before the type switch (several values are
interpolated twice in one record; `appName` is both `service-name` and
`application`).

**The value is legal; the interpolation was not.** Junos permits these
characters in a quoted name, and this tree's #1798 commit gate correctly
accepts them — measured on both the braced and the flat-set channel, with
a newline as the positive control that the gate's *control-byte*
validator does fire. Rejecting them at commit would be a behaviour change
on a supported spelling, so the fix is at the render side, which is where
`pkg/config/freetext.go`'s own three-layer doctrine puts it. That
doctrine's layer-3 enumeration named `pkg/networkd`, `pkg/frr` and
`pkg/ipsec`; `pkg/logging` was a fourth interpolation sink outside it.

**Two consequences, and the second is the one operators feel:**

1. **Audit integrity.** A login class whose `allow-configuration` covers
   `security policies` could forge a second SD-PARAM in records shipped
   off-box — attributing a deny to a different zone in the collector. The
   record leaves the box precisely because the on-box actor is not trusted
   to curate it, so "privileged actor" is not a mitigation.
2. **Audit availability.** A `]` closed the element early, so a strict
   RFC 5424 collector read the remainder as MSG. Every deny record for
   that policy was then silently lost at the SIEM.

**This is NOT a widening of the #6585 sanitizer, deliberately.**
`termsafe.SanitizeForDisplay` is scoped to control bytes because #6585's
own third acceptance criterion is an over-reach guard — "ordinary
multi-word and UTF-8 attribute values are unchanged on the wire" — and
because it protects the RFC 3164 FRAME, which these three printable bytes
cannot damage. Widening it would mangle every other consumer of that
sanitizer (gRPC show output, IPsec error text) for a property only the SD
element has. #6585 closed frame integrity; #9321 closes SD-element
integrity. Two boundaries, both needed.

**Cost.** Allocation-free fast path for the already-clean case — every
ordinary record — because this runs on the shared dataplane event path
(#2283), once per firewall event per structured client. An ordinary
record is byte-identical to its pre-#9321 output, pinned against golden
strings captured by running the unmodified formatter at `77240ec4e`.

**Coverage is by reflection, not by a hand-kept field list.**
`TestEveryStringFieldIsSDParamSafe9321` walks every exported string field
of `EventRecord`, poisons each in turn with `a"b\c]d`, and asserts the
emitted element keeps its exact param-name list and closes at the very
end — so a string field added later is poisoned automatically. A
hand-written list would be an inventory built by reading today's format
strings, blind by construction to tomorrow's field.

## `then log` does not reach the syslog clients (#6859)

Junos routes the two firewall-filter logging actions to different sinks: `then
log` writes the filter-log buffer, `then syslog` sends to the system log. xpf
categorised every filter-log event as `CategoryFirewall` and gated the fan-out
only per-CLIENT, never per-term — so both spellings went to every subscribed
syslog client, and a term an operator wrote as `then log` specifically to keep
hits ON the box was shipped to whatever remote collector was configured.

`EventReader` now holds a `(filter_id, term_id) -> then syslog` map and skips
the syslog fan-out for a FILTER_LOG event whose term did not carry `then
syslog`. Three things about it are load-bearing:

**The decision cannot be made in the dataplane.** The `syslog` bit reaches the
Rust `FirewallTermSnapshot` (#6853) but `parse_term` never consumes it, so the
event carries no indication of which spelling produced it. What it does carry is
`RuleID`/`TermID`, and the Rust side assigns both as positional indices into the
snapshot the Go control plane itself rendered — so the control plane can answer
authoritatively from the same snapshot it sent. `userspace.FilterTermSyslogMap`
is a projection of that snapshot rather than a second walk of the config,
because a divergence between the two orderings would silently route one term's
hits under another term's spelling with nothing failing.

**Placement is what makes the subtractive change safe.** The gate sits AFTER the
event-buffer callbacks and the daemon log line, and BEFORE the local-writer
loop, so suppression costs no local visibility. xpf has no `show firewall log`;
`show security log` reads the event buffer and still shows the hit. One step
earlier and the gate would blind the local surface too — which is why the
regression cells assert the RENDERED local record, not that a call was made.

**Nil is not the same as empty.** A nil map means "no apply has wired this yet"
and preserves the pre-#6859 fan-out, so a path that never wires it cannot
silently suppress `then syslog` as well. An empty NON-nil map is the opposite
instruction — "wired; this config has no `then syslog` terms" — and is what a
config with all filters removed installs, so the reader cannot resume forwarding
under deleted terms' ids. `FilterTermSyslog()` returns the map rather than a
count for exactly this reason: both states have length zero.

Only FILTER_LOG is gated. Session/policy/screen events have no per-term spelling
to honour, and suppressing them would be a logging outage dressed as a parity
fix.

The behaviour change is announced at commit by a `pkg/config` advisory naming
each affected term, fired only when the config actually installs syslog clients.
See `docs/feature-gaps.md`.

## Syslog stream-transport resilience (#2283)

`SyslogClient.Send` / `SendBinary` are reached on the SHARED dataplane
event hot-path (EventStream reader → `EventReader.ProcessRawEvent` →
`logEvent` → `SyslogClient.Send`). The event reader runs that path
inline, so a syslog client must never block or thrash on a bad target.
Two bounds enforce that. **They now apply to UDP as well (#9025)** — this
sentence used to read "UDP is connectionless and exempt", and that
exemption was false. A connected-UDP `Write` can block indefinitely on a
full socket send buffer (ENOBUFS / a congested or down egress path parks
the goroutine in the netpoller until the buffer drains), which is what
`pkg/flowexport/transport.go` already recorded (#4423 H07) while this
module denied it. UDP is also the DEFAULT protocol, so the unbounded
path was the common one, and the goroutine it parks carries HA session
sync, the ISSU drain signal and full-resync as well as logging:

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
  down (`conn=nil`) whenever `0 < n < len(b)`; an immediate subsequent
  `Send` is dropped by the timeout's cooldown before another write or dial,
  and after the window expires the cooldown-gated path dials a fresh,
  correctly-counted stream.
- A **clean 0-byte TCP timeout** (`n==0`) wrote nothing, cannot desync the
  collector, and stays drop-without-close per #2287. A timeout nevertheless
  arms the reconnect cooldown, and subsequent sends in that window fail fast
  before attempting another write. A TLS timeout also detaches and closes the
  connection because Go's TLS state is corrupt after a timed-out `Write`; the
  next post-cooldown send reconnects instead of reusing it.
- Closing the raw conn here does NOT reintroduce the #2285 re-entrant deadlock:
  it never routes back through the slog→`SyslogSlogHandler.Handle`→
  `SyslogClient.Send` path, so it cannot re-lock `s.mu` on the sending
  goroutine. `closeSyslogConn` closes a TLS connection's raw socket first, so
  `close_notify` cannot block on a blackholed collector; its expected error is
  ignored. `Close` marks the client closed and detaches the socket without
  waiting on `s.mu`; its deferred join is bounded so a commit cannot wait on a
  hung write.
- **Reconnect cooldown.** A non-timeout write failure on a stream
  transport attempts one cooldown-gated reconnect, gated by
  `reconnectCooldown` (default `defaultReconnectCooldown`, 1s). If the
  previous reconnect cycle failed inside the window, the reconnect is skipped
  and the send fails fast (drop) — so a down server cannot drive a fresh
  5s-timeout dial on every event (thundering herd). A timeout arms the same
  clock and the next send fails fast before `Write`, so a hung server costs at
  most one `writeTimeout` per cooldown window. The cooldown clock
  (`lastReconnectFailure`) is armed by all three failure modes (#2302/#9911):
  a failed **dial**, a **write timeout**, AND a dial that succeeds but whose
  subsequent retry-**write** fails (accept-then-reset collector, half-open
  server, TLS app-layer drop). Gating only on a failed dial left an
  accept-then-reset target permanently un-throttled — the dial succeeded
  every time, so every log message drove a fresh TCP connect + teardown (a
  dial storm: ephemeral port exhaustion + SYN pressure on the collector). The
  clock is cleared only on a FULLY successful reconnect (dial AND the
  retry-write both land), so the legitimate single-broken-pipe recovery path is
  unaffected.
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
  `<facility> <severity>` pairs resolves to one client filter, but only
  the selectors that can MATCH a record this client emits take part
  (#5797). A client stamps exactly one facility, so a selector naming a
  different facility code matches nothing it will ever send and does not
  constrain it. `daemon info; authorization critical` therefore filters
  daemon records at **info**, not critical, and `daemon info;
  authorization none` does not silence the destination — before #5797 a
  blind `MoreRestrictiveMinSeverity` fold across every pair did both.
  What still folds via `MoreRestrictiveMinSeverity` is two selectors
  naming the SAME facility, which is a genuine conflict on one facility.
  The Junos `any` wildcard matches every record and applies unless an
  exact selector for the stamped facility is present (more-specific
  wins). Residual, tracked separately: one client carries one facility,
  so a host naming two mappable facilities can still honor only the one
  it stamps, and which one that is depends on selector order — honoring
  both needs a source facility on the event envelope (#7187).
- **The `file` and `user` sinks keep every authored selector (#7187).**
  The discussion above is about the `host` sink, which has always
  appended into `SyslogHostConfig.Facilities`. The other two sinks held a
  SCALAR facility/severity pair and the compiler ASSIGNED into it inside
  the per-child loop, so `file messages { daemon info; authorization
  warning; }` compiled to exactly one selector — the LAST one parsed —
  and every earlier pair was gone before any renderer, validator or
  `show` command could observe it. Nothing could diagnose it because the
  config was reduced at compile time. Both now carry
  `Selectors []SyslogFacility`, and the rsyslog render joins them with
  `;` into the one drop-in the destination owns
  (`daemon.info;authorization.warning<TAB>/var/log/messages`) — rsyslog's
  selector field already expresses that OR, which is Junos' meaning for
  several statements under one stanza. Two knock-ons worth knowing:
  an empty selector list still renders `*.*`, as an unset scalar pair
  did; and an unsafe selector (the #5797 belt) now drops ITSELF rather
  than the whole destination, because deleting an operator's safe
  selectors because a sibling was poisoned is a worse outcome than the
  injection it defends against. For a one-selector destination that is
  bit-identical to the old behaviour — nothing safe survives, and the
  destination is skipped.
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
  question still owned by #5797. Note there is no commit gate to lean on
  instead: `system syslog <dest> <facility> <severity>` models the facility
  as the schema's wildcard KEY and validates only the severity VALUE, so
  every spelling commits clean.

  **The mapping is documented, not a judgement call (#6830).** Junos
  publishes the facility→wire table for messages directed to a remote
  destination, in two rules that together cover the whole `[edit system
  syslog]` vocabulary: *Table 3, Default Facilities for Messages Directed to
  a Remote Destination* lists the six Junos-SPECIFIC names with a `localX`
  stand-in, and *"for facilities that are not listed, the default alternative
  name is the same as the local facility name"* covers the rest.

  | Junos name | Junos wire facility | this box emits today | |
  |---|---|---|---|
  | `change-log` | `local6` | `local6` | ✅ |
  | `daemon` | `daemon` | `daemon` | ✅ |
  | `user` | `user` | `user` | ✅ |
  | `authorization` | `auth` | `local0` | ❌ |
  | `conflict-log` | `local5` | `local0` | ❌ |
  | `dfc` | `local1` | `local0` | ❌ |
  | `firewall` | `local3` | `local0` | ❌ |
  | `ftp` | `ftp` | `local0` | ❌ |
  | `interactive-commands` | `local7` | `local0` | ❌ |
  | `kernel` | `kern` | `local0` | ❌ |
  | `ntp` | `ntp` | `local0` | ❌ |
  | `pfe` | `local4` | `local0` | ❌ |

  The repository already implemented **one row** of that table — `change-log`
  → `local6` in `ParseFacility` is exactly Table 3's value. The table was
  consulted once and never finished. So #6830's first question ("the mapping
  itself, per unmapped Junos name") is a **lookup**: every name in the
  vocabulary has a documented answer, including the three the issue flags as
  possibly having none (`interactive-commands`, `conflict-log`, `pfe` — all
  three are Table 3 rows).

  `JunosRemoteFacility` and `FacilityMisfiled` carry that table and report the
  gap. **They are NOT wired into the emit path**: for a name that is silently
  `local0` today, emitting the documented facility MOVES records for any
  collector already bucketing them there, which is an upgrade-visible contract
  change and the one part of #6830 that is a genuine decision. What they do
  change is the diagnostic — it can now name the target facility, so an
  operator is told *what Junos would send* rather than only that something was
  substituted, and a real Junos name is distinguished from a typo (those need
  opposite operator actions).

  As of #6829 ALL THREE `ParseFacility` call sites that install a client use
  the checked form and warn: `applySystemSyslog` (host streams), the
  security/audit stream wiring in `daemon_system.go`, and the CLI commit
  mirror in `pkg/cli/apply.go`. The last two were previously left on the
  unchecked form on the argument that the schema enum gates them — true on the
  STRICT path only. `configstore.Store` downgrades that gate to a warning on
  `Load` (boot) and `SyncApply` (HA peer sync), which is the same reachability
  class the severity belt exists for, so the two were treated inconsistently.
  Untold, an unmappable name sends every record on those streams out under
  local0 while `show system syslog` still reports the authored name.

  The `any` wildcard does NOT warn. `set system syslog host <ip> any <sev>` is
  the canonical Junos form and names no facility deliberately, so the
  substitution warning's own text — "records will carry a facility the
  configuration does not name" — is false for it. `logging.FacilityIsWildcard`
  is the single definition all three call sites share; it suppresses the
  warning only, and does not change what `ParseFacility` returns.
- **rsyslog selector tokens are grammar-checked, per POSITION (#5797).** The
  `file` and `user` destinations do not use `SyslogClient` at all — the
  daemon builds an rsyslog selector `<facility>.<severity>` and writes a
  managed drop-in. #4902 belted the file NAME and user TOKEN on that line
  but not the two selector tokens, so an rsyslog metacharacter in either
  one escaped the selector and injected configuration. The two tokens do
  not share a threat model: the severity is enum-gated at commit and so
  only arrives unsafe on the tolerant load / peer-sync path, while the
  unvalidated facility reaches the render site verbatim from an ORDINARY
  commit (`set system syslog file audit "daemon;*.* /tmp/pwn" info` passes
  commit-check). The belt is the only thing standing between that string
  and a written rsyslog directive, so it is bound at the render site by
  `pkg/daemon/syslog_selector_render_5797_test.go`, not only by the
  predicates' own unit tests.

  The belt is **position-aware**, because rsyslog's two selector positions
  have different grammars (rsyslog.conf(5), sysklogd format) and a single
  allowlist applied to both is necessarily their intersection:

  | position | accepted | rendered example |
  |---|---|---|
  | facility | empty (folds to `*`), `any` (folds to `*`), exact `*`, or a comma-separated list of `[A-Za-z0-9-]` names | `auth,authpriv.info`, `*.info` |
  | severity | empty (folds to `*`), a `[A-Za-z0-9-]` name, exact `*`, or one of the `=` / `!` / `!=` priority modifiers in front of a name or `*` | `daemon.*`, `daemon.=info`, `daemon.!=debug` |

  The comma is admitted **per member**: `auth,authpriv` renders, while
  `auth,`, `,auth`, `auth,,authpriv` and `auth,authpriv;*.* /tmp/pwn` do
  not. The comma operator is deliberately NOT accepted in the severity
  position — rsyslog defines it for multiple facilities "with the same
  priority pattern", and multiple priorities are written as `;`-joined
  selectors, so `daemon.info,err` was never a valid selector and admitting
  it would widen the accept set without recovering any working config.

  Everything rejected for structural reasons is still rejected in **both**
  positions: whitespace, `.`, `;`, `:`, `/`, control bytes, and arbitrary
  punctuation. `daemon;*.* /tmp/pwn` is dropped; that is the injection
  #5797 exists for. The space is the load-bearing byte rather than the
  newline — a literal newline cannot reach these tokens (the lexer folds it
  to a space), while a space pushes attacker-chosen text into the rsyslog
  ACTION position.

  Accepting `*` and the comma list costs nothing, which is why they are in
  rather than out. The render is `fmt.Sprintf("%s.%s", facility, severity)`,
  so a whole-token `*` can only ever produce `*.<severity>` — one byte, no
  room for a payload — and each list member is checked individually. Both
  spellings pass commit-check and both rendered a working drop-in before
  any belt existed, so rejecting them would not have hardened the render
  path: it would have warned-and-reconciled-AWAY an operator's working
  destination on upgrade (the drop-in is not merely left unwritten,
  `reconcileSyslogDropins` removes it). What the belt still refuses to do
  is decide which facility NAMES are honoured — that is the deferred
  mapping question above, and the `change-log` → `local6` remap and
  `any` → `*` fold remain whole-token comparisons, so a list member spelled
  `change-log` or `any` is passed through verbatim.
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
- **The reconnect `slog.Debug` is emitted after the lock too (#8597).**
  #2287 moved the drop WARNING out from under `s.mu` and left two
  `slog.Debug("... reconnecting")` emits on the same failure path under
  it — one in `Send`, one in `SendBinary`. Under `xpfd --debug` those
  records are enabled, so they take the identical route back into the
  locked client and wedge the caller. `pendingDebug` mirrors
  `pendingDropWarn`: capture under the lock, emit from the same
  after-`Unlock` defer.
  The reason this survived the #2287 fix is worth keeping: the #2287
  regression cells install a base handler at the DEFAULT level (Info),
  where `slog.Debug` short-circuits in `slog.Default().Enabled()` and
  never reaches `Handle`. The defect lived on an axis those fixtures
  hold constant, not in a branch they miss.
  `syslog_debug_under_lock_8597_test.go` re-runs the #2287 wiring with a
  Debug-level base handler, and carries a control cell asserting Debug
  really is enabled there — without it the deadlock cells would pass
  whether or not the emit sits under the lock.
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

**#9165 — every transport counts a write failure, and the counters have
a reader.** Two halves, both of which had to be true for the defect to be
invisible.

The write-failure arm only reached `noteDrop` for stream protocols
(`if s.protocol != "udp"`), and #9025 had added a UDP arm for the
DEADLINE EXPIRY it introduced — which is what made this look covered. A
deadline expiry is not the failure an operator hits; a dead collector is,
and on a CONNECTED datagram socket (`dialUDP`) Linux reports that as
ECONNREFUSED, not as a timeout. So on the DEFAULT transport,
`droppedWrites` stayed 0, the rate-limited warning never fired, and a
`show` still rendered the collector as configured — three instruments
reading healthy while every message went nowhere. Every UDP write
failure is now counted. There is still no reconnect arm on the datagram
path: a datagram socket has no connection to re-establish, so the
message is still dropped and the error still returned. Only the
ACCOUNTING changed, which is why `DroppedDials`/`DroppedCooldown` must
stay at zero for a UDP client — an assertion the acceptance table makes.

The second half is that all three accessors had **zero production
readers**. A counted drop reached an operator through exactly one
channel, the ≤1/s warning above, so a warning that had already been
rate-limited away left nothing behind at all. `EventReader.SyslogDropStats()`
snapshots every installed client, the daemon wires it as
`api.Config.SyslogDropsFn`, and the collector emits
`xpf_syslog_messages_dropped_total{addr,protocol,reason}` BEFORE the
dataplane gate — syslog clients run whether or not the dataplane loaded,
and a box that failed to load its dataplane is exactly the box whose logs
an operator needs. All three reasons are emitted even at zero: a series
that appears only once it becomes non-zero has no prior sample for
`increase()`, and its absence is indistinguishable from a scrape that
never reached the code.

The log LEVEL was deliberately not changed. `ringbuf.go`'s
`slog.Debug("syslog send failed", ...)` sits in the per-event fan-out
loop, where CLAUDE.md mandates `slog.Debug`; raising it would reintroduce
the log flood that rule exists to prevent. The defect was the missing
counter, not the level.

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

## The commit path does not dial a stream client (#9326)

`applySyslogConfig` used to construct every client with `NewSyslogClientTransport`,
which **dials**. Measured by driving the real apply:

```
one apply, 3 unreachable TCP streams          -> 15.01 s   (3 x the 5 s dialer timeout)
four applies of an IDENTICAL 5-stream stanza  -> 20 dials  (no idempotence gate)
```

A commit is the operator's control loop. Blocking it on whether a third-party
collector happens to be up couples config change to someone else's uptime, and
on a cluster it widens the window in which the two nodes disagree about the
committed config.

Three changes, and the asymmetry between them is the part to keep:

- **TCP/TLS construct WITHOUT dialing** (`NewSyslogClientDeferred`). Safe only
  because a stream client reconnects lazily: `Send` → `writeMsg` fails on a nil
  conn → the stream branch performs one cooldown-gated reconnect and retries, so
  the connection is established on the first record.
- **UDP keeps dialing at construction**, and `NewSyslogClientDeferred`
  **refuses** `udp` so that cannot be lost by a later caller. UDP has no lazy
  reconnect — `writeMsg` returns the error and the caller deliberately does not
  reconnect — so a deferred UDP client would forward nothing, silently, for the
  life of the config. A UDP dial is cheap anyway: it binds rather than
  handshakes.
- **`dialUDP` gained the 5 s dialer its siblings already had.** Its only
  blocking term is the NAME LOOKUP, and `net.Dial` on a hostname resolves with
  no deadline and no context. The connectionless nature of UDP bounds the send,
  not the lookup that precedes it; conflating the two is how this stayed
  asymmetric.

The #3351 operator signal ("receiver unreachable at apply") is preserved rather
than dropped: `warmSyslogClients` runs the connect asynchronously and logs the
warning there, off the commit path.

An **idempotence gate** (`syslogClientFingerprint`) skips the rebuild when
nothing the client set depends on has changed — mirroring the SNMP reconcile's
hash gate. It is scoped to the client rebuild ALONE and sits below the
zone-name / policy-name / filter-term / interface-name wiring, which is derived
from the apply result and netlink rather than the stanza and must be re-run on
every apply; gating the whole function would silently stop refreshing all of it.
The fingerprint covers the RESOLVED source addresses, because a
source-interface's address can change with no syslog edit at all. It is
forgotten on both teardown paths, or re-adding an unchanged stanza would
hash-match a client set that has been closed.

`security log stream <s> host` is also a typed leaf now (`ValidateSyslogHost`:
an IP address or a DNS name, the `ValidateNTPServer` shape). It was `args: 1`
with no valueType and no validator, so any string reached the dialer's resolver.

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
- **A wedged writer now RECOVERS, not just reports (#9118).** #3478 above made
  the wedge observable and deliberately stopped there. The gap that left: a
  failed reopen inside `rotate()` leaves `file == nil`, and `rotate()` is
  reached only from `written >= maxSize` — which needs a *successful* write. So
  once wedged, the only reopen in the file could never run again, and one
  transient `openat` failure (EMFILE / ENFILE / ENOSPC / EROFS / EACCES) at a
  rotation boundary silenced `security log mode event` and `traceoptions` until
  the next config commit or a daemon restart. On an unattended appliance in
  steady state that is unbounded, and it is the exact channel an operator uses
  to reconstruct an incident.

  Both writers now attempt a reopen on the write path itself, rate-limited to
  one attempt per `reopenBackoff9118` (1 s) so a durable failure such as ENOSPC
  cannot turn every dropped line into an `openat`. Recoveries are counted and
  exported by `RecoveredWrites()`, because "never broke" and "broke and healed"
  are indistinguishable if only the drop counter moves.

  `Close()` on both writers now records that the nil handle is **deliberate**.
  It has to: `Close()` also nils the handle, so without that flag the recovery
  path could not tell a wedge from a retirement and would recreate an audit file
  after shutdown — or resurrect a writer the daemon has just replaced on the
  `ReplaceLocalWriters` path. The byte count is re-synced from `Stat()` on
  reopen, since a wedge that began mid-rotation leaves `written` describing a
  file that was already renamed aside.

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
- **Lifecycle action applicability is ONE predicate, not a per-surface
  exception (#7531).** The producer writes the wire action byte as 0 for BOTH
  lifecycle events and says so at each write site — *"a session close has no
  permit/deny/reject action semantics, so this byte is intentionally 0 … Do NOT
  rely on the 0 rendering as a value"*, and the same for the open path. The Go
  side then taught that exception to the formatters one at a time: #2513 for the
  close text lines, #2593 for the open text lines, #4914 for the binary close
  record. **Every surface added afterwards inherited the raw `actionName(0)` ==
  `"deny"` until someone noticed it too** — a four-issue tail for one fact.

  The surfaces that never got their own issue were `EventRecord.Action` itself,
  which the trace, REST and SSE surfaces all read, and the binary SESSION_OPEN
  record (#4914 covered only the close). A `deny` on a session CREATE is the
  more misleading of the two: it reads as a blocked connection attempt rather
  than an established one.

  `eventCarriesForwardingAction(eventType)` now states the fact once and the
  surfaces read it. `recordActionName` returns the empty string for a lifecycle
  event, `formatBinaryRecord` stamps `actionNotApplicable` (0xFF) for both, and
  the trace OMITS `action=` rather than printing an empty one — an empty field
  reads as a producer that failed to populate it, a different and more alarming
  claim than "this event type has no action".

  **Empty rather than a placeholder, deliberately.** `EventRecord.Action` feeds
  the event-buffer filter (`EventFilter.matches`), so before this an operator
  filtering `action deny` matched every normal session open and close — the
  concrete harm, since it makes a deny filter useless on a busy box. A
  placeholder string would just be a new value to match by accident.

  Applicability is a property of the EVENT TYPE, not of the byte, so a future
  producer writing a stray non-zero cannot resurrect the claim. Pins:
  `lifecycle_action_7531_test.go` (both lifecycle types, the non-lifecycle
  control that must KEEP its decision, the binary sentinel with a POLICY_DENY
  control, trace omission with a POLICY_DENY control, and the deny-filter
  behaviour in both directions).
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


## Audit-log disk writes are off the event reader (#9025)

`TraceWriter.HandleEvent` and the local-log fan-out did a synchronous
`WriteString` on a raw `*os.File` — no `bufio` — and called `rotate()`
inline when the size cap tripped, all from inside ringbuf's synchronous
callback loop. One `write(2)` per logged event on a SHARED goroutine.

That goroutine is not a logging goroutine. The same EventStream switch
loop also carries `EventTypeSessionOpen/Update/Close` (**HA session
sync**), `EventTypeDrainComplete` (the **ISSU drain signal**) and
`EventTypeFullResync`. Under disk distress — writeback stall,
dirty-page throttling, a full or hung device — the reader parked and
those parked with it. The contract was already stated in-tree and named
this collateral: `pkg/flowexport/routemask.go` (#3743) moved FIB lookups
off this exact path because they *"stall the event reader and every
other callback behind it (including the trace writer)"* — and the trace
writer it named as a victim was itself still blocking.

Both writers now hand the line to a **bounded queue** (`auditQueueDepth`)
drained by **one dedicated goroutine**, dropping and counting on
overflow — the shape #3478 established for volume, reused rather than
reinvented. Dropping is correct and blocking is not: a blocking send on
a full queue reinstates the stall one buffer later.

Notes that are easy to get wrong:

- **`LocalLogWriter.Send` is unchanged.** Its error REPORTS THE WRITE
  RESULT and #3478 M04 made that deliberate; that contract and "the
  write does not happen on your goroutine" cannot both hold. So only the
  one caller that cannot afford to wait — the event reader — was moved,
  via `SendFromEventReader`. Every other caller keeps the synchronous
  guarantee.
- **A retired writer REFUSES.** After `Close`, an enqueue fails and the
  loss is counted. Accepting into a channel with no reader would be a
  silent loss — strictly worse than the pre-#9025 nil-file drop it
  replaced.
- **`Close` drains the queued tail** before closing the handle. Those are
  exactly the audit records around whatever caused the shutdown. It
  drains *before* taking `mu`, because the writer goroutine takes `mu`
  itself.
- **SNMP traps** are bounded on the write too, not just the dial (#9025).
  The trap worker is single and serial, so one backpressured target
  head-of-line-blocks traps to every healthy target, and `Stop()` waits
  on `trapWG`.
