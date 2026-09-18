# pkg/cli

Interactive Junos-style CLI: readline-driven REPL with tab completion, `?`
help, prefix matching, `| match` filtering, and command history. Used by
both the daemon-local CLI (xpfd in TTY mode) and the remote CLI
(`cmd/cli`) once it has a gRPC connection.

## Entry points

- `CLI` — `cli.go`. The REPL engine.
- `New(...)` — `cli.go`. Takes ~10 injected managers (configstore,
  dataplane, cluster, frr, dhcp, …). The package has no globals.
- The readline command tree is compiled from `pkg/cmdtree` at REPL
  start; add a new command in `pkg/cmdtree/tree.go` and it shows up
  here, in the remote CLI, and in gRPC tab completion automatically.
- Per-injection setters: `SetForwardingSampler`, `SetRPMResultsFn`,
  `SetFeedsFn`, `SetLLDPNeighborsFn`, `SetVRRPManager`,
  `SetApplyConfigFn`, `SetCommitFns`, …. All on `*CLI`.

## Request / diagnostic command files (#4653)

The operational request and diagnostic handlers were historically one
1300-line `cli_request.go` grab-bag. They are split by command family into
sibling files (same package, so unexported helpers stay reachable):

- `cli_request.go` — the `handleRequest` dispatch shell plus the small
  `request dhcp` / `request protocols` handlers.
- `cli_request_ping.go` — `ping` / `traceroute` and their `diagcmd` argv
  builders (`buildPingArgv`, `buildTracerouteArgv`). `buildPingArgv`
  clamps the `-s` payload to `diagcmd.MaxPingSize` (#6382), so the local
  console shares the single ping-size ceiling the REST and gRPC surfaces
  already enforce (#5250 A8-b1 F4) — including a digit token that
  overflows `int64` (that arm is why a naive `strconv.Atoi` guard would
  leak the huge value). Because the console's input is a RAW operator
  token (unlike the structured int the REST/gRPC surfaces receive, where
  `0` means "unset"), it enforces ONLY the upper ceiling and
  intentionally preserves an explicit `-s 0` / `-s -1` / non-numeric
  token for the `ping` child to reject rather than dropping input the
  operator typed.
- `cli_request_testcmd.go` — `test policy` / `test routing` /
  `test security-zone` (the `policymatch` adapters).
- `monitor_traffic.go` — `monitor` dispatch + `monitor traffic` tcpdump
  wrapper (joins the sibling `monitor.go` / `monitor_interface.go`).
- `cli_request_chassis.go` — `request chassis cluster failover` /
  `data-plane`.
- `cli_request_system.go` — `request system reboot|halt|power-off|zeroize`
  and `software` / `configuration` / `dynamic-dns`.
  - **`zeroize` runs the FULL shared wipe, not a partial config-only one
    (#5890).** `performConsoleZeroize` resolves+validates the configured
    config root (`zeroizeConfigRoot`, #5554/#5684 — fail-CLOSED on an
    undeterminable store/path so it never wipes the wrong directory) and then
    DELEGATES to the exported `grpcapi.PerformZeroizeWipe(configDir,
    configBase)` — the SAME primitive the gRPC `runZeroize` runs — before
    stopping xpfd. Both paths therefore erase an IDENTICAL owned-artifact set
    (config state + `tls/` + rendered service configs [frr/swanctl/kea] +
    provisioned login accounts [shadow/authorized_keys/`sudoers.d/xpf-*`] +
    config archive + BPF pins + networkd) and cannot diverge. Before #5890 the
    console called only `zeroizeConfigState` (config DB + archive), which LEFT
    `tls/`, the rendered secrets, and the login accounts on disk — secret
    residue a re-tenanted device could recover. It is fail-CLOSED: a wipe that
    does not complete surfaces the error and does NOT stop the daemon (never
    reboot into a half-wiped, secret-retaining state). The `#5554`/`#5280`
    configured-root resolution (a non-default `-config` erases its own root,
    not a hardcoded `/etc/xpf`) is preserved inside `zeroizeConfigRoot`.
  - **`zeroize` runs THROUGH the daemon's coordinated factory-reset
    transaction (#5871), not out-of-band.** `performConsoleZeroize` routes the
    wipe through `factoryResetFn` — wired by the daemon to `d.factoryReset`
    via `SetFactoryResetFn`, the SAME gate the gRPC path uses as
    `grpcapi.Config.ZeroizeFn`. The transaction acquires the daemon apply
    semaphore (draining any in-flight apply, blocking a concurrent one) and
    enters the terminal reset generation BEFORE erasing, so no concurrent /
    subsequent commit / HA-sync / reconcile re-persists the erased `.configdb`
    SSOT or re-renders the wiped secrets. The pre-#5871 console called the
    wipe DIRECTLY (ungated), so a concurrent writer could re-create just-erased
    state while the console reported a clean reset. `factoryResetFn` is nil
    only when the CLI is spawned OUTSIDE the daemon (offline recovery / unit
    test): there is no reconcile loop to race, so the ungated direct wipe is
    the explicit, reduced-guarantee fallback (mirroring
    `grpcapi.runZeroize`'s `zeroizeFn==nil` path) — still fail-CLOSED and
    still stops the daemon only on a fully-successful reset.
- `cli_request_security.go` — `request security ipsec|policies|wireguard`.

The security-sensitive `--` end-of-options separators in the diagcmd/tcpdump
argv builders (#2084 / #4524 / #4527) moved verbatim.

Fail-open hardening (#4883): `parseMonitorTrafficArgs` (`monitor_traffic.go`)
rejects an empty/unrecognized `matching` predicate instead of launching an
UNFILTERED capture, and the `monitor security flow` writer goroutine
(`monitor.go`) clears `active/cancel/sub` and records `lastErr` when the trace
writer fails — so a disk-full/rotation error no longer wedges the monitor
Active (surfaced by `show monitor security flow`).

## `show interfaces` render files (#4654)

The `show interfaces` presenters were historically one 1396-line
`cli_show_interfaces.go`, where the RETH/member display logic repeated
across the summary/terse/detail/extensive modes and drifted (the #4328
family of fixes). They are split per render mode plus a shared
RETH/kernel-query helper file (same package, so the unexported helpers
stay reachable). Pure code motion — the netlink/sysfs query order and the
visible output are byte-identical:

- `cli_show_interfaces.go` — the `showInterfaces` dispatch + summary
  renderer, `showInterfacesRethMemberSummary`, and `showTunnelInterfaces`.
- `cli_show_interfaces_terse.go` — `showInterfacesTerse` (the tabular
  `show interfaces terse` view, cluster-peer aware).
- `cli_show_interfaces_detail.go` — `showInterfacesDetail` plus
  `showInterfacesRethDetail`, the synthesized bondless-reth aggregate /
  absent-member block reused by the extensive view.
- `cli_show_interfaces_extensive.go` — `showInterfacesExtensive` /
  `showInterfacesExtensiveFiltered`.
- `cli_show_interfaces_stats.go` — `showInterfacesStatistics` and
  `showVlans` (the two small tabular summaries).
- `cli_show_interfaces_shared.go` — the shared RETH/kernel-query helpers
  `dhcpLease`, `rethMemberLinkState`, `rethMemberAttrs`, and `baseIfName`,
  so the four render modes resolve reth link state / member attrs / lease
  data through one place and can no longer drift.

## `show services` / `show class-of-service` presenters (#4655)

The service-status presenters were historically one 868-line
`cli_show_services.go` that mixed unrelated service families —
CoS, DDNS, DHCP (client/relay/server), SNMP, LLDP, and port
mirroring — so different owners edited one bucket. They are split
per service family into sibling files (same package, so the
unexported `showConfigRedacted`/`userspaceDataplaneStatus` helpers
and injected `*Fn` hooks stay reachable). Pure code motion — every
presenter's rendered output is byte-identical:

- `cli_show_services.go` — the `handleShowServices` dispatch shell
  plus the presenters with no dedicated family file:
  `showRPMProbeResults`, `showIPMonitoringStatus`,
  `showApplicationIdentificationStatus`, `showSchedulers`.
- `show_services_cos.go` — the `show class-of-service` dispatch
  (`handleShowClassOfService`, `parseCoSClassifierArgs`),
  `showClassOfServiceInterface`, and `showInterfacesQueue` (the
  live CoS runtime queue view).
- `show_services_ddns.go` — the two dynamic-DNS presenters:
  `showServicesDynamicDNS` (Surface A router/interface-address)
  and `showDHCPDynamicDNS` (DHCP-server DDNS).
- `show_services_dhcp.go` — the DHCP client/relay/server family:
  `showDHCPLeases`, `showDHCPClientIdentifier`, `showDHCPRelay`,
  and `showDHCPServer`.
- `show_services_snmp.go` — `showSNMP` and `showSNMPv3`.
- `show_services_lldp.go` — `showLLDP` and `showLLDPNeighbors`.
- `show_services_mirror.go` — `showPortMirroring` (SPAN).

## Callers

`cmd/cli` (remote client), `cmd/xpfd` (when stdin is a TTY).

## Dependencies

`appid`, `cliterm`, `cluster`, `cmdtree`, `config`, `configstore`, `dataplane`,
`dhcp`, `dhcprelay`, `feeds`, `frr`, `ipsec`, `lldp`, `logging`, `routing`,
`rpm`, `vrrp`.

## Gotchas

- **`show security nat source pool` reports the allocator's recycled-scan cost,
  and it is gated on the DENOMINATOR (#9392).** #9327 measured that the Rust
  port allocator's recycled phase does not amortize: retained tokens are pushed
  to the BACK of the per-address FIFO, so K out-of-band-occupied tokens ahead of
  F free ones cost `(K+F)/F` pops per claim, degrading to `K+1` as `F -> 1` —
  worst exactly as the pool approaches exhaustion. It could not say whether a
  production pool reaches that shape, because `recycle_scan_pops` was Rust-side
  `#[cfg(test)]`. #9392 promoted it, added the WALK counter it needs as a
  denominator, and this view renders `Recycled-scan pops: <pops> over <scans>
  (<ratio> per scan)` beside the utilisation the cliff is a function of.

  The render is gated on `RecycleScanWalksTotal > 0`, never on the pop count. An
  older helper omits both keys and they decode 0, and a pool whose recycled phase
  has not run reports 0 honestly — printing a ratio from a zero denominator would
  state a measurement nobody made, which is the fabricated healthy zero this
  exact view already had refused out of it twice (#7473 for a disarmed pool,
  #8606 for a pool the helper has no entry for). ~1 per scan is the healthy
  reading and it is still printed: the baseline is what makes a large ratio
  legible as a cliff rather than as a busy pool.

- **A session-derived view runs IN xpfd, so its memory is the control
  plane's (#8597).** `showTopTalkers` used to append one formatted row per
  SESSION, sort the whole slice, and print twenty. `MaxSessions` is dynamic
  and large by design (`worker_count × per-worker`, #5323), so on a busy box
  `show security flow session sort-by bytes` allocated millions of entries —
  six strings each — inside the daemon, with no recover on the console path.
  A legitimate, unprivileged diagnostic OOM-killed the process being
  diagnosed.

  The bound is on the COLLECTION, not the print: a `topTalkerLimit`-sized
  min-heap of RAW session key/value copies, formatted only for the survivors.
  Two properties are load-bearing and both have cells:

  1. **The scan allocates nothing per session.** Not "less" — nothing.
     Deferring the formatting behind a closure per candidate looks bounded and
     is not; the closure heap-allocates on every session, and the address and
     zone work still ran before it. That draft measured 125x growth over a
     200x table and was rejected by the allocation-ratio cell, which is why
     that cell measures a ratio between two real runs rather than asserting
     the design.
  2. **The output is unchanged**, including the `(of N total)` figure, which
     still counts every session the filter admitted rather than the rows kept.
     A bound that redefined that number would change what the operator reads.

  The print cap stays explicit and independent of the collection cap. Deriving
  it from `len(entries)` makes the two one bound — and a mutation removing the
  collection bound then HANGS a test on a full stdout pipe instead of failing
  it.

  The REST side has treated a full conntrack walk as an admission decision
  since #5318 (`sessionCountCap`); this is the console sibling that was never
  brought along. The other CLI session views stream (`count++` and print), so
  this was the only local accumulator.

- **`load {override,merge,set} terminal` COMMITS only on Ctrl-D (#6548).**
  Ctrl-C — and any other read error — is an ABORT: the partial input is
  discarded and `handleLoad` returns an error, so the candidate is untouched.
  The loop originally took the same `break` for EOF, `readline.ErrInterrupt`
  and every read error, joined whatever lines had arrived, applied them, and
  printed `load <mode> complete`. An operator who aborted a paste was told it
  succeeded and could commit a TRUNCATED configuration — and a truncated
  `security policies` stanza is a WIDENED one, because the deny terms that
  would have followed never arrive.

  This is the #4883-D bug. It was fixed on the remote CLI and never applied
  here, so the console kept the broken loop. **The read loop therefore lives in
  `pkg/cliterm` and both surfaces call it** — a divergence between the console
  and the remote CLI on this is always a bug, so it is single-sourced rather
  than duplicated and held in step by a test. `pkg/cliterm` is deliberately
  dependency-light so `cmd/cli` can import it without pulling in the whole
  interactive console.

  `CLI.readLineFn` is a test seam (nil in production) that makes the loop
  drivable. It exists because the loop had NO other observable — the difference
  between a committed paste and an aborted one is invisible from outside the
  process — and it was unguarded for exactly as long as it was undrivable.
  Covered by `load_terminal_abort_6548_test.go`; the abort fixtures paste a
  syntactically COMPLETE prefix on purpose, so a green cannot come from the
  truncated input merely failing to parse.
- TTY detection uses `unix.IoctlGetTermios(fd, TCGETS)`, **not**
  `os.ModeCharDevice` — `/dev/null` matches `ModeCharDevice` and would
  trick the latter into starting an interactive session in a systemd unit.
- Commits prefer the daemon's atomicity primitive: `commitFn` and
  `commitConfirmedFn` hold the apply semaphore across `store.Commit()` and
  the dataplane apply. This serializes CLI commits with HTTP/gRPC
  commits (#846). Falls back to `store.Commit()` + `applyConfigFn` only
  when the daemon hookups are absent (test/standalone).
- `fwdSampler` (forwarding CPU stats) can be `nil` — every show handler
  null-checks it.
- Device- or remote-originated strings printed to the operator's terminal MUST
  pass through `pkg/termsafe` (#6468). Printed raw they can smuggle terminal
  escape sequences (OSC 52 clipboard write, CSI erase/redraw) that the terminal
  acts on — clipboard hijack and output spoofing. Both helpers backslash-escape
  C0/DEL/C1 control bytes and invalid UTF-8 while passing legitimate multibyte
  UTF-8 through unchanged.

  **Pick the variant by the SHAPE of the value, not by its source.**
  `SanitizeForDisplay` is for a single-line FIELD the caller formats into a row:
  it escapes LF and TAB along with everything else, because an embedded newline
  in a field is itself a forgery vector — it fakes a table row.
  `SanitizeBlockForDisplay` is for a MULTI-LINE blob whose own line structure is
  the output: it PRESERVES LF and TAB so a BGP table is not collapsed into one
  `\x0a`-laden line, and escapes CR because a bare carriage return overwrites a
  line rather than carrying structure. Using the single-line variant on a block
  mangles the output; using the block variant on a field re-opens the
  row-forgery hole. The tests assert both directions.

  **Both** variants escape U+2028/U+2029. Neither is Unicode category Cc, so
  `unicode.IsControl` does not reach them, but a terminal or pager that honors
  either as a break can forge a row with it — in a block whose line structure is
  the output, and equally in a single-line field the caller pads into a row.
  Escaping LF but passing U+2028 in the field variant would be incoherent: that
  variant is the stricter of the two about line breaks.

  **Command output and swanctl SAs (#6584).** `show log` / `show log <name>`
  / `show system boot-messages` and their `ShowText` / `GetSystemInfo`
  mirrors block-sanitize their `journalctl` / `tail` stdout — the syslog
  stream carries the very DHCP lease hostnames #6468 was filed about, so
  reading the LOG bypassed the sanitized lease table. The IPsec SA views
  are the PARSED-ROW class, not the raw-block class the issue assumed
  (`stdout` never reaches a terminal; the parsed fields do), so they are
  guarded once at INGEST in `pkg/ipsec` — thirteen fields across four
  renderers is exactly the width of sweep that ships half-applied.

  `TestEveryCommandOutputDisplaySiteIsSanitizedOrDeclared6584`
  (`pkg/cli`) is the mechanism that was missing: every function that
  forks an external command must apply at least as many `termsafe` calls
  as it makes forks, or appear in `declaredUnsanitizedForks` with a
  reason. The count is RELATIVE on purpose — deleting a fork lowers the
  requirement, so it cannot go vacuous the way an absolute count does,
  while deleting a sanitize still reds. It fails in BOTH directions, so a
  stale exemption is caught too. Streaming sites (`tcpdump`, `ping`,
  `traceroute`) are exempted with the reason they need a shape change to
  a line-wise writer before they can be guarded at all.

  **The guard goes on BOTH terminal-facing renderers.** Every one of these
  commands runs on the local CLI *and* the remote `cli`, which prints
  `resp.Output` verbatim (`cmd/cli`: `fmt.Print(resp.Output)`); a fix on one
  renderer alone leaves the other at pre-fix behavior, and the remote `cli` is
  the more common operator posture. Guarded surfaces:

  | Value | Variant | `pkg/cli` | `pkg/grpcapi` |
  |---|---|---|---|
  | DHCP lease `Hostname` / `HWAddress` | field | `show_services_dhcp.go` | `server_show_dhcp_lldp_snmp.go` |
  | DHCP-DDNS owned-record `FQDN` | field | `show_services_ddns.go` | `server_show_dhcp_lldp_snmp.go` |
  | Surface A DDNS `LastError` (provider response body — Cloudflare / Route 53 embed it with `%s`; dyndns2 / duckdns wrap it in `%q`, generic omits it, rfc2136 uses fixed rcode strings) | field | `show_services_ddns.go` | `server_show_dhcp_lldp_snmp.go` |
  | Raw `vtysh` stdout (BGP hostname capability, IS-IS dynamic hostname TLVs, OSPF router IDs) | block | `cli_show_routing.go` (OSPF ×4, BGP ×3, IS-IS ×3, BFD, route-map), `cli_request.go` (OSPF/BGP clear) | `server_routing.go` (OSPF/BGP/IS-IS response boundary), `server_show_routes_text.go` (BFD peers, route-map) |
  | **Parsed** FRR table rows — every cell, via `termsafe.SanitizeRowForDisplay` (OSPF neighbors, BGP summary, BGP routes, RIP routes, IS-IS adjacency) | field (per cell) | `cli_show_routing.go` ×5 | `server_routing.go` ×5 |

  On the gRPC routing handlers the block guard sits on the RESPONSE rather than
  on each vtysh branch, so a `case` added to one of those switches later is
  covered by construction — the fail-open direction is exactly what left this
  class half fixed after the first pass. The structured branches pay nothing:
  clean text takes the sanitizer's allocation-free fast path.

  **A parsed field is not covered by a raw-output sweep.** The last row of that
  table is a distinct class, and it is the one a "sanitize the raw output"
  framing structurally cannot see. `frr.GetISISAdjacency` scrapes
  `show isis neighbor` with `strings.Fields` and reprints the cells into a
  caller-formatted row; FRR puts the hostname the peer advertised in its Dynamic
  Hostname TLV (RFC 5301) in the first column, so `SystemID` is peer-controlled
  text — and `strings.Fields` splits on whitespace ONLY, so ESC/DEL/BEL/C1 ride
  inside the token untouched. **Tokenizing is not sanitizing.**

  Guard the WHOLE row, never the one column you believe is device-controlled:

  - Column identity is not stable. A value carrying a space in an early column
    shifts every later column, so peer bytes land in cells a per-column analysis
    marked safe.
  - "This column is numeric" is a property of the current FRR, not of the
    protocol. `bgp default show-hostname` already makes FRR emit a peer-supplied
    hostname in the BGP summary; today the only thing keeping it out is that
    `frr.bgpPeerJSON` does not declare the field, which is a load-bearing
    invariant documented at its definition and pinned by
    `pkg/frr/bgp_summary_hostname_6468_test.go`.

  Guard the cells **before** the caller's width format, not the finished row.
  `%-20s` pads whatever it is handed, so escaping afterwards pads the RAW cell
  and then expands each escape, pushing every later column right by the
  expansion. `assertCellGuardRanBeforeWidthFormat6579` binds that ordering.

  **What the guard does NOT do — do not overstate this in a review.** It makes
  a row safe to **print**. It does not make the row **correct**, and a call to
  `SanitizeRowForDisplay` is not evidence that a displayed value is genuine:

  - The column shift above is the *reason* to guard every cell. It is not
    something guarding every cell *repairs*. A peer hostname containing a space
    still shifts `strings.Fields`, so `State` can end up displaying a token the
    peer chose, and `SanitizeForDisplay` preserves plausible printable text —
    it cannot tell a real `Up` from an attacker-supplied one. **A row can be
    terminal-safe and materially false.**
  - Fixing *that* needs the parse to change (FRR's JSON output, or
    right-anchored column parsing that reports malformed rows instead of
    rendering them silently). That is tracked as **#6590** and is deliberately
    out of scope for the display guard.
  - Bidi overrides and other Cf runes are also out of scope: they reorder
    characters within a line but cannot forge or erase a row.

  The block and field variants are observationally identical for a
  `strings.Fields`-derived cell (the split already consumed every whitespace
  rune), but NOT for a JSON-decoded one — a BGP-summary cell can carry a real
  LF, which the block variant preserves by design and would render as a forged
  table row.

  That matters for testing, because on the gRPC handlers the response-boundary
  block guard **masks** a dropped per-cell guard: the ESC is neutralized either
  way, so a raw-control-byte assertion cannot tell the two apart. Two shapes see
  through the mask, and every row binder uses one:

  - a real LF in a JSON-decoded cell (BGP summary), which the block variant
    preserves by design;
  - **column alignment**, which works even where the LF shape is unreachable —
    for a `strings.Fields`-derived cell such as IS-IS `SystemID`, the split
    already consumed every whitespace rune, so alignment is the only
    discriminator left.

  `pkg/grpcapi/GetRIPStatus` has no response-boundary guard (it has no
  raw-`vtysh` branch for one to protect), so its per-cell guard is isolated by
  construction; the local CLI row paths print directly and are likewise
  unmasked.

  The sanitizer lives in the leaf package `pkg/termsafe` (stdlib-only) because
  `pkg/cli` imports `pkg/grpcapi`, so a helper in `pkg/cli` could not be shared
  upward. Fail-on-revert guards for every call site live in
  `cli_residual_escape_6468_test.go` / `cli_row_escape_6579_test.go` /
  `cli_show_dhcp_escape_6468_test.go` and their `pkg/grpcapi` mirrors; all ten
  parsed-row sites (five per renderer) are individually bound.

  Not guarded, deliberately: LLDP neighbor fields are already sanitized at the
  ingest boundary (`lldp.sanitizeTLVString`); the DHCPv6 DUID view and the
  Surface A DDNS *name* are firewall-self/operator-authored, not
  device-controlled. (The Surface A `LastError` in the table above is a
  different field on the same view — its bytes come from the provider, not from
  us.) `frr.FormatRouteDetail` is JSON-typed with no free-text cell (prefix,
  protocol enum, local interface name, integer distance/metric), and
  `routing.RouteEntry` comes from netlink rather than from a peer. The
  `pkg/api` REST handlers render the same FRR tables into a JSON
  `TextResponse`, which is a machine surface with no shipped terminal consumer.
  Sanitizing happens at the display boundary only, so machine consumers — the
  status views, the REST `TextResponse`, the gRPC structs — still get the raw
  value.
- Session filters (`session_filter.go`) serve BOTH show and clear. The
  clear path must call `validate()` (unknown zone/pool names are
  command errors — an inert filter degrades into clear-nothing or, via
  `hasFilter()`, clear-ALL) and `populateIfaceMaps()` (interface
  matching needs the zone/egress maps; only show built them before
  #1827 PR-3). Peer-forwarded clears go through
  `buildPeerClearRequest` — every filter dimension must be carried,
  because an empty `ClearSessionsRequest` means clear-all to the peer.
  Key ports are network byte order (`ntohs` before comparing) and
  dataplane IPv4 NAT fields decode with NativeEndian (`uint32ToIP`).
  The FILTERED clear (`clearFilteredSessions`) is BOUNDED (#4886): it
  collects at most `cliClearFilteredBatch` forward keys (plus each
  session's reverse/DNAT companion), deletes that chunk, and resumes —
  cursor primary (`IterateSessionsFrom`, one O(N) forward pass, deferred
  anchor delete) with a fresh-rescan fallback for a cursor-less dataplane
  — so peak memory is O(batch), not O(matches). The pre-#4886 path
  snapshotted every matching key first (hundreds of MB before deleting on
  a multi-million-entry table). This mirrors the already-bounded gRPC
  `ClearSessions` (#5454); using the cursor (not a bare rescan) keeps a
  broad clear O(N), avoiding the O(N²) CPU-stall that would starve the HA
  watchdog (#4719). The cursor path terminates unconditionally (the cursor
  advances every round regardless of delete success). The fresh-rescan
  fallback re-collects from the top each round, so it depends on deletes
  actually removing keys to converge; a #5948 no-progress guard breaks the
  loop if a non-empty chunk removed NOTHING (every forward delete genuinely
  failed → the same set would be re-collected forever). A not-found key
  counts as removed (it will not reappear), so a concurrently-drained chunk
  is still progress, not a stall. This is defense-in-depth: production always
  takes the cursor path (both `dataplane.Manager` and the userspace
  `LegacyDataPlaneAdapter` implement the cursor iterators), so the rescan is
  test/edge only.
- `show` PAGER auto-disable (`dispatchWithPager`, #4886): the pager only
  engages when `os.Stdout` is a real terminal (`stdoutIsTerminal`, probed
  via TCGETS — `/dev/null` is a CharDevice so `os.ModeCharDevice` is
  wrong). A `show … | match X` redirects `os.Stdout` to the filter pipe;
  the inner bare `show` used to route back to the pager, which then wrote
  `--More--` into the hidden outer pipe while blocking on stdin — the
  command hung with no visible prompt. Auto-disabling on a non-TTY stdout
  (pipe / file / scripted) fixes the nesting and streams straight through.
- GLOBAL-ONLY clears (`cli_clear.go`) — commands whose backend action can
  ONLY clear everything and have no scoped variant (`clear arp`, `clear ipv6
  neighbors`, `clear interfaces statistics`, `clear system config-lock`,
  `clear security nat statistics`, `clear security nat source
  persistent-nat-table`, `clear security counters`, `clear security policies
  hit-count`, `clear firewall all`) enforce EXACT ARITY via
  `requireClearNoScope`: a trailing scope-looking operand (e.g. `clear arp
  192.0.2.10`) is REJECTED before any mutation instead of being silently
  discarded and clearing everything (#5811, extends the #5570 policy-hit-count
  fix to the whole global-only set). The remote CLI (`cmd/cli/clear.go`) carries
  a byte-identical `requireClearNoScope` so both parsers reject the same input
  the same way. Scoped clears (`clear security flow session <filter>`, `clear
  dhcp client-identifier interface <name>`) are unaffected — they legitimately
  take a scope.
- `show security match-policies` (`showMatchPolicies`) and `test policy`
  (`testPolicy`) are THIN adapters over the single shared policy simulator
  `pkg/policymatch` (#3042) — the same matcher the REST and gRPC surfaces
  use. The pre-#3042 hand-written CLI matchers (the removed
  `matchPolicyAddr`/`matchPolicyApp`/`matchSingleApp` in `cli_helpers.go`)
  scanned only zone-pair policies, hard-coded a `default deny` message, and
  missed predefined apps, multi-level application-sets, literal CIDRs,
  `any-ipv4`/`any-ipv6`, and source/destination exclusion — so the
  diagnostic could report the OPPOSITE of what the dataplane enforces.
  `policymatch.Match` now honors the configured `default-policy` and reports
  whether a global policy matched. #3104: `show security match-policies` and
  `test policy` thread live per-scheduler active-state
  (`c.policyInactiveFn()` → `policymatch.Query.PolicyInactiveFn`) so a
  scheduler-inactive policy is skipped like the runtime. #3414: `policyInactiveFn()`
  is now ALWAYS non-nil — with no live state (no provider / early boot) it binds
  a nil state map, which fails closed so scheduled policies are simulated as
  INACTIVE (matching the dataplane's nil-state => dropped) rather than certified
  as-if-active. #3628: the usage/help text these commands print when
  from-zone/to-zone are missing is the shared SSOT constant
  `policymatch.MatchPoliciesUsage` / `TestPolicyUsage`, so the four surfaces
  (local + remote CLI, show + test) advertise the SAME selectors the parsers
  accept — `source-port`, `destination-port`, `icmp-type`, `icmp-code`, and
  `protocol` by name OR 0-255 number — instead of the stale, drifted
  `protocol <tcp|udp>`-only subset that hid the ICMP / source-port / non-TCP-UDP
  selectors from operators.
- #3674: the local `test policy` (`testPolicy`) output now renders the SAME
  identity fields `show security match-policies` (`showMatchPolicies`) already
  prints over the shared `policymatch.Result` — the stable runtime **Policy ID**
  (the RT_FLOW / session-table / audit ID from the #3667 `RuntimePolicyIDs`
  SSOT), the **Rule ID** (#3668 stable inventory join key), the **Scope**
  (`zone-pair (from-zone …, to-zone …)` or `global (match from-zone …, to-zone
  …)`, rendered through the shared `matchScopeZone` helper so an unset global
  scope reads `any`), and the policy **Description**. Both are thin adapters over
  the one simulator, so a `test policy` verdict now correlates with the runtime
  policy and identifies which scoped/global rule fired — previously the request
  path printed only name + action (and, for a global match, name + action with no
  scope), making it the poorest of the four match-policies surfaces. The
  rendering is shared via `printPolicyMatchIdentity`; it is a display-only change,
  no schema/wire impact.
- #4497 (avo-001 F3): the local `test policy` (`testPolicy`) query echo now
  surfaces the queried **ICMP/ICMPv6 type and code** in the trailing tuple
  annotation. A `test policy … protocol icmp icmp-type 8 icmp-code 0` verdict
  ends with `… [icmp type 8 code 0]` (previously the bare `[icmp]`), so the
  operator reads the exact ICMP packet the simulator matched — the type/code the
  parser already threads into `policymatch.Query.ICMPType/ICMPCode` (#3284) and
  matches against an icmp-type-constrained application (junos-ping = type 8).
  The annotation is rendered by the shared `formatQueryProtoTail` helper; a
  non-ICMP query prints the bare `[proto]` exactly as before. Display-only; no
  schema/wire impact.
