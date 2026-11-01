# cmd/cli

Standalone Junos-style CLI client. Connects to xpfd's gRPC API and runs
the same readline / tab-completion / `?`-help experience as the
daemon-local CLI.

## Entry

`main.go` parses flags, dials the gRPC API (see `dialOpts`), and runs
its own remote dispatch — it does NOT import `pkg/cli` (the
daemon-local console). The two CLIs are independent implementations
(twins): they share only `pkg/cmdtree`, `pkg/cliterm`,
`pkg/config` helpers and, for some commands, the gRPC renderers in
`pkg/grpcapi` whose `resp.Output` this client prints verbatim. A fix
in `pkg/cli` therefore does NOT reach this binary; mirror it here
(see the twins note in `pkg/cli/README.md`).

The dial raises the client `MaxCallRecvMsgSize` to
`configstore.MaxConfigSize` + 1 MiB of framing headroom
(`maxConfigRecvBytes`), so a `show configuration` for a config up to the
store's 16 MiB ceiling can be displayed. grpc-Go's 4 MiB default receive
cap would otherwise truncate a large config with `ResourceExhausted`
(#5321). Tracking the store const keeps the two bounds from drifting.

## Flags

- `-addr` — gRPC server address. Default `127.0.0.1:50051`.
- `-c "<command>"` — single-command, non-interactive mode. Exits with
  the command's status. Useful for scripted operations.

## Unknown subcommands under keyword-only nodes refuse (#16798)

`dispatchOperational` consults `cmdtree.ValidateOperationalLine` (the
operational SSOT) before routing. A line whose first unrecognised
token sits under a keyword-only node — a node with keyword children
and no value slot — is refused as `unknown <path> command: <token>`
(ambiguous abbreviations as `ambiguous <path> command: <token>`),
so `-c` exits 1 instead of printing help and exiting 0 for work that
never happened (`clear security ike security-associations`,
`request system software add`, a misspelt `failover`). Bare keyword
nodes keep their help listing; failures involving a value slot or a
leaf fall through to the existing strict handlers (usage /
unknown-filter / exact-arity errors).

**The output pipe is not tree grammar (#18664, the #9628 rule).** The
gate (`validateOperationalLine`, `operational_gate.go`) validates only
the words before the first bare `|` token. It finds that token with
`showPipeIndex`, the same rule `splitShowPipe` uses in the handlers, so
the gate and the handler agree on where the command ends. Before this,
the bare `|` was judged as an unknown keyword under the keyword-only
`show configuration` node, and operational `show configuration |
display set` failed with `unknown show configuration command: |`. The
rules:

- An unknown word BEFORE the pipe refuses exactly as without the pipe
  (`show configuration bogus | display set` ->
  `unknown show configuration command: bogus`).
- A pipe directly under a keyword-only node is admitted only for a
  command in `operationalPipeConsumers`, whose handler parses the pipe
  itself. Today that is only `show configuration`. Every other
  keyword-only node still refuses, exactly as before #18664 (exit 1),
  but the message now names the modifier:
  `syntax error: "<path>" does not accept the output modifier "| ..."`
  instead of `unknown <path> command: |`. Admitting the pipe would hand
  it to a handler that prints help or runs the bare command and drops
  the modifier, exiting 0 (the #16798 class). A pipe after a value slot,
  leaf or `AcceptsArgs` tail (`show configuration security | display
  set`, `show system rollback 1 | display json`) is still the handler's
  business, as before.
- Output filters (`| match`, `| count`, ...) never reach the gate. They
  are peeled first by `cliterm.SplitPipe` in `dispatch`, so a chained
  `show configuration | display set | match x` reaches the gate as
  `show configuration | display set`.
- An invalid modifier after `show configuration` is refused by the
  handler and named: `syntax error: unknown pipe command "frobnicate"`,
  `unknown display format "yaml"`, `syntax error: missing pipe
  modifier`. `| compare [rollback <N>]` is not supported in operational
  mode (Junos supports it); the handler says so and points at
  configuration mode, where `show | compare [rollback <N>]` works.
- A `|` glued to a word (`|display`, `configuration|display`) is not
  the pipe operator on any operational surface. `showPipeIndex`,
  `cliterm.SplitPipe` and `pkg/cli` `splitAtPipe` all need a bare `|`
  word. The glued token is refused as an unknown word, with a hint
  showing the spaced form.

## Local-only verbs run without a live daemon (#4909)

`main.go` normally probes the daemon with `GetStatus` at startup and
exits if xpfd is unreachable. But some `-c` verbs execute entirely in
the client with no gRPC round-trip and must work exactly when the daemon
is DOWN (recovery/bootstrap). `isLocalOnlyCommand` classifies these and
dispatches them BEFORE the reachability probe. Today the only member is
the offline WireGuard key generator (`request security wireguard
generate-private-key`, #1434) — a pure-Go X25519 keygen. The pre-fix
startup probe made it unreachable precisely when it was needed.

## Tab completion

Driven by the gRPC `Complete` RPC, which lowers the same `pkg/cmdtree`
tree the daemon uses. Adding a command in `pkg/cmdtree/tree.go` shows up
here and in the daemon-local CLI without changes here.

## `show` command layout

The remote-CLI `show` umbrella was historically one ~2100-line
`show.go` grab-bag. It is split by feature family into sibling files in
this package (#4660) so local-vs-remote parity review is tractable
per feature. `show.go` keeps only the top-level `handleShow` dispatcher,
the config-mode `handleConfigShow`, and the shared text-proxy helpers
(`showText` / `showTextFiltered` / `showSystemInfo`). The per-feature
handlers live in:

- `show_security.go` — `show security` zones / policies / screen /
  match-policies / statistics / log / vrrp / ike / ipsec renderers.
- `show_flow.go` — `show security flow session` parse + render + summary,
  plus flow statistics.
- `show_nat.go` — `show security nat` source / destination renderers.
- `show_interfaces.go` — `show interfaces`.
- `show_protocols.go` — `show protocols` ospf / bgp / bfd / rip / isis.
- `show_system.go` — `show system` commit / rollback / uptime / ...
- `show_services.go` — `show services` rpm / ip-monitoring / app-id / ddns.
- `show_dhcp.go` — `show dhcp` leases / client-identifier.

The split is pure code motion. All handlers moved verbatim; the gRPC
call sequences and the text-proxy fallthrough are preserved so the
remote CLI output stays bit-identical to before.

## Selectors are not positional (#9065)

An operational command may carry both a **selector** (an operator-supplied
value — an interface name, a zone, a pool) and one or more **modifiers**
(declared keywords such as `detail`, `terse`, `extensive`). This package used
to decide which was which by POSITION: `if args[1] == "detail"`. That is wrong
by construction, because `show interfaces ge-0/0/1 extensive` and
`show interfaces extensive` differ by which words are keywords, not by index —
so at whichever token a ladder failed to enumerate, the modifier overwrote the
selector or both were dropped. `show interfaces ge-0/0/1 extensive` sent
`Filter="extensive"`, matched nothing, and printed EMPTY output for an
interface that exists.

Fixing that per command re-opens the class at the next word — which is
empirically what happened when `global` was fixed on the filtered policy path
and `brief` was left broken one line above it. So:

**Use `cmdtree.SplitModifiersAt` / `cmdtree.SplitModifiers`.** The command
tree is the authority on which words are keywords at a node, so a modifier
child added to the tree later is handled here for free instead of becoming the
next member. The split is position-independent, resolves abbreviations by the
same prefix rule as the rest of the tree, and reports a second value (`Extra`)
and an ambiguous keyword (`Ambiguous`) rather than silently binding either.

**Never silently discard a selector.** Either bind it into the request, scope
the response client-side, or REFUSE the command with an error naming it. The
third outcome — issuing a request for a different question and printing the
answer — is the defect: the operator is shown output that looks valid and is
told nothing. Where the selector is scoped client-side (`show security zones`,
`show security nat source pool`, `show security policies from-zone/to-zone`),
an unmatched value must FAIL rather than print an empty body, because "no such
zone" and "this zone is empty" otherwise read identically.

`selector_survives_modifier_9065_test.go` is the completeness gate: it walks
every operational-tree node declaring a value slot beside keyword children and
drives each (selector, modifier) pair through `handleShow`. Its header records
what it can and cannot see — notably that a selector honoured client-side is
indistinguishable from one dropped, which is why the obvious per-node
strengthening was written, measured, and withdrawn.

## Interactive loop & signals

The interactive session runs two goroutines against one `ctl`:

- the **main loop** (`main.go`) reads a line, dispatches it, and owns all
  configuration-mode transitions — `configure` enters, `exit`/`quit` and
  EOF (Ctrl-D) leave;
- the **SIGINT goroutine** (`runSignalLoop`) handles Ctrl-C: it cancels a
  running command, and on a second Ctrl-C within 2 s tears the session
  down, issuing `ExitConfigure` first if still in configuration mode so
  the daemon-side config lock is released.

Both goroutines touch `ctl.configMode`, so it is an `atomic.Bool`
accessed only via `Load`/`Store` (#5053). A plain `bool` let the SIGINT
read race the main loop's write; a Ctrl-C landing during a mode
transition could observe stale state and skip the `ExitConfigure`
cleanup.

There are two DISTINCT `ExitConfigure` release contracts:

- **Explicit `exit`/`quit`** (`dispatchConfig`) is TRANSACTIONAL (#5812):
  it checks the RPC error and only clears local config-mode state
  (`configMode`/`editPath`/prompt) on SUCCESS. On an error (a transport
  timeout/disconnect before the release reaches the daemon), the
  server-side lock + candidate may still be owned by this session, so it
  surfaces the error and STAYS in configuration mode with the edit path
  intact — the operator retries `exit` (the RPC is idempotent
  server-side, so a retry after a response-lost success still succeeds).
- **Teardown** paths that run without a cancellable command context
  (SIGINT double-Ctrl-C, EOF/Ctrl-D, and the post-loop exit) call
  `ExitConfigure` through `exitConfigureBounded` — best-effort, error
  discarded, time-bounded (`exitConfigureTimeout`) so a wedged daemon
  cannot hang Ctrl-C cleanup or block process exit. The client is exiting
  anyway and has no interactive recovery, so a lost release is left to
  the daemon's disconnect cleanup / lease reclamation.

## Operational notes

- Output streams over gRPC. There's no separate SSH / Telnet layer —
  authentication is by gRPC peer credentials.
- `| match <pattern>` filtering is client-side; the server sends full
  output. (Junos pipes are simulated this way.)
- Some lab VMs have a stale `/usr/local/sbin/cli` that shadows the
  current `/usr/local/bin/cli` via `PATH`. If a deploy looks correct
  but the CLI behavior is stale, delete the `sbin` copy.
