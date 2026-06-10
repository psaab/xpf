# #1805 — Bound gRPC/HTTP request-path exec sites

Status: DRAFT v1 — pending adversarial plan review

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

## Concrete design

Import direction: pkg/daemon imports grpcapi/api, so the U3 helpers in
pkg/daemon/exec_timeout.go CANNOT be imported here (cycle). Options:

- **Option A (recommended): unexported per-package helper copies.** ~30
  lines each in pkg/grpcapi/exec_timeout.go and pkg/api/exec_timeout.go,
  byte-mirroring the daemon helper (15s ctx + WaitDelay 5s + doc comment
  pointing at the daemon original). Precedent: the project favored local
  helpers over new micro-packages in U3 review.
- Option B: new shared package pkg/execto with RunTimeout()/
  RunStdinTimeout(); migrate daemon callers too. More churn, one SSOT.

Where a request ctx is naturally available (gRPC handler methods), derive:
`ctx, cancel := context.WithTimeout(reqCtx, 15*time.Second)` so client
cancellation also kills the child. The helper takes a parent ctx parameter
to support this: `runCommandTimeoutCtx(ctx, name, args...)`; nil/Background
for the goroutine-deferred power actions.

Semantics preserved: every call site keeps its exact current error
handling (most log-and-continue or return partial output); only the
unbounded wait changes.

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

1. Option A (local copies) vs Option B (shared pkg) — which fits project
   convention? Is a third duplicate (after daemon's) acceptable?
2. Should gRPC sites derive from the request ctx (cancellation propagation)
   or use a detached 15s ctx (uniform with daemon)? Recommended: derive
   where a ctx is in scope, detached otherwise — confirm.
3. Any site where a 15s bound is WRONG (journalctl --boot on a huge journal
   legitimately >15s? tail -n on a giant log?) — should any get a larger
   bound or a size cap instead?
4. The reboot/halt/poweroff bounding — any shutdown-ordering hazard?
5. Did the audit miss request-reachable exec in other packages (pkg/cli
   server-side? pkg/routing called from handlers?) — reviewers should
   re-grep with their own boundary.
