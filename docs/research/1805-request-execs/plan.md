# #1805 — Bound gRPC/HTTP request-path exec sites

Status: DRAFT v2 — round-1 findings folded (Codex PLAN-NEEDS-MAJOR; AGY Option-A confirmed), pending round-2 confirm

## Issue framing

PR #1802 (U3/#1794) bounded all apply-path exec sites with 15s
CommandContext + WaitDelay=5s. Request-reachable raw `exec.Command` sites
remain in pkg/grpcapi and pkg/api: they don't hold applySem but pin gRPC/
HTTP handler goroutines indefinitely on a wedged binary (journalctl on a
broken journal, ss/ps on a stuck kernel, chronyc with a dead chronyd
socket).

## Audit boundary (pre-scoped per U3 lesson)

`grep -n "exec.Command" pkg/grpcapi/*.go pkg/api/*.go` (non-test), master
f96290a98. Full inventory:

| Site | Cmd | Disposition |
|---|---|---|
| grpcapi/server_show_status.go:169 | ps aux | BOUND (15s) |
| grpcapi/server_show_status.go:177 | df -h | BOUND |
| grpcapi/server_show_status.go:223 | journalctl --boot | BOUND |
| grpcapi/server_show_status.go:231 | ss -tnp | BOUND |
| grpcapi/server_show_system.go:260,262,265,267 | chronyc ×2, ntpq, timedatectl | BOUND |
| grpcapi/server_diag.go:616,628 | ip -4/-6 neigh flush | BOUND |
| grpcapi/server_show.go:390 | journalctl -u xpfd | BOUND |
| grpcapi/server_show.go:445 | tail -n N logfile | BOUND |
| api/system.go:250-area (261,268) | systemctl reboot/halt | BOUND with care (below) |
| grpcapi/server_diag.go:566,574,582 | systemctl reboot/halt/poweroff | BOUND with care |
| grpcapi/server_diag.go:132 | (already CommandContext) | verify ctx provenance, leave |
| api/system.go:133,171 | (already CommandContext) | verify ctx provenance, leave |

Reboot/halt/poweroff sites: `systemctl reboot` normally returns promptly;
bounding it cannot break shutdown (by the time the timeout could fire,
either systemd acted or it's wedged and the error path is correct). These
run in goroutines after a delay — bound them identically but keep the
fire-and-forget semantics (log-only on error, as today).

## Honest scope/value framing

Mechanical hardening, small blast radius. Value: a wedged external binary
can no longer pin handler goroutines (each pinned handler holds a gRPC
stream/HTTP conn; enough of them exhausts the server). If reviewers find
the pattern wrong (e.g. request ctx should be plumbed instead of a fresh
15s ctx), iterate; PLAN-KILL is acceptable if they conclude the risk of
changing show-command semantics outweighs the hang fix.

## Concrete design (v2 — round-1 folds)

Import direction: pkg/daemon imports grpcapi/api (daemon_run.go:21,:33),
so the U3 helpers CANNOT be imported here (cycle). **Option A decided**
(AGY confirmed + structural-mirroring precedent runtime_probes.go:7-10):
unexported per-package helpers in pkg/grpcapi/exec_timeout.go and
pkg/api/exec_timeout.go — but NOT a byte-mirror of the daemon helper
(round-1 Codex finding 1): the request-path sites use THREE distinct
output modes that must be preserved exactly:

- `outputTimeout(ctx, name, args...) ([]byte, error)` — wraps
  `cmd.Output()` (stdout-only) for the 4 server_show_status.go sites,
  which today feed stdout directly into user-visible responses; a
  CombinedOutput mirror would leak stderr into them.
- `combinedOutputTimeout(ctx, name, args...) ([]byte, error)` — for the
  sites that use CombinedOutput today (chronyc/ntpq/timedatectl, ip neigh
  flush, journalctl, tail).
- `runTimeout(ctx, name, args...) error` — wraps `.Run()` for the
  deferred power actions (errors remain IGNORED exactly as today —
  round-1 fold: v1 wrongly said "log-only as today"; today they are
  ignored, and this plan does not change that).

All three: `context.WithTimeout(parent, 15s)` + `cmd.WaitDelay = 5s`.
Parent ctx: the request ctx where in scope (derive — client cancellation
kills the child); `showNTP` has no ctx today → plumb the handler ctx down
(round-1 fold); `GetSystemInfo` discards ctx with `_` → use it;
`context.Background()` for the deferred reboot/halt/poweroff goroutines
(client disconnect must not cancel a confirmed power action).

Additional round-1 folds:
- **U3-parity completion**: the three existing CommandContext sites
  (server_diag.go:132, api/system.go:133,:171) get `WaitDelay = 5s` added
  (they are request-ctx-bounded but can still hang on inherited pipes
  with zero WaitDelay).
- **tail -n N cap** (server_show.go:435,:445): N is request-controlled
  with only Atoi validation; a time cap does not bound a huge fast read.
  Clamp N to [1, 10000] before exec and note the byte-bound rationale at
  the site.
- Site count corrected: **17 raw exec.Command call expressions** (4
  status, 4 NTP, 5 diag incl 3 power, 2 show, 2 api incl 1 power pair) —
  the implementer re-greps and reconciles the table before starting.

Semantics preserved per site AS-IS (v1 overgeneralized — round-1 fold):
some sites return gRPC errors on failure (server_show_status.go:171,
server_show.go:391), some substitute fallback text, power goroutines
ignore errors. Only the unbounded wait changes; every site keeps its
exact current error disposition.

## Public API preservation

No exported signature changes. Wire formats untouched.

## Hidden invariants

- show-command outputs feed CLI rendering — partial output on timeout must
  not panic formatters (they all handle err today by substituting a
  message; verify per site).
- The power-action goroutines deliberately outlive the RPC — keep
  context.Background there, NOT the request ctx (client disconnect must
  not cancel a confirmed reboot).

## Risk assessment

| Class | Level |
|---|---|
| Behavioral regression | LOW (error paths already exist at every site) |
| Lifetime/borrow | N/A |
| Performance regression | NONE (slow path only) |
| Architectural mismatch | LOW |

## Test plan

- Unit: helper timeout test per package (sleep-bin pattern like U3's
  daemon tests — reuse the same test shape).
- go build ./... + go test ./pkg/grpcapi/ ./pkg/api/ ./pkg/daemon/.
- Manual gate: `cli show system status`, `show log`, `show system uptime`
  (chrony path) on the deployed cluster still render.
- Standard smoke Pass A; no failover gate (no cluster/dataplane code).

## Out of scope

- Plumbing request ctx into the already-CommandContext sites beyond
  verification (they may already use it).
- pkg/cli local-mode exec sites (different process, CLI binary — not
  handler-pinning; note for a future issue if any exist).
- Migrating pkg/daemon to a shared package (Option B) unless reviewers
  prefer it.

## Open questions for adversarial review

1. RESOLVED round 1: Option A, with three output-mode-preserving helper
   variants (not a byte-mirror).
2. RESOLVED round 1: derive from request ctx where in scope (plumb ctx
   into showNTP; stop discarding in GetSystemInfo); Background for
   deferred power actions.
3. RESOLVED round 1: 15s fine for ps/df/ss/journalctl -n/neigh flush;
   NTP fallback chain worst-case stacking documented at the site; tail
   gets an N clamp in addition to the time bound.
4. Open: reboot/halt/poweroff bounding — confirm no shutdown-ordering
   hazard (the bound only fires if systemctl wedges).
5. Open: audit completeness — round-2 reviewers re-grep
   pkg/grpcapi+pkg/api and flag any miss vs the 17-site table.
