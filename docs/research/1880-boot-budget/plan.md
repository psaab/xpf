# #1880 — first xpfd boot after deploy intermittently exceeds the failover harness's 60s comeback budget

Revision: r1 (2026-06-12)
Branch: `research/1880-boot-budget`
Status: DRAFT — awaiting 3-way hostile plan review (Claude SMR + Codex + AGY)

## 1. Problem

Two consecutive PR smokes (#1871, #1877, 2026-06-11) failed their FIRST
`make test-failover` run with `FAIL fw0 xpfd did not come back within 60s`
(12/13), the daemon verified active moments later, and the immediate rerun
passed 13/0 both times. The issue prescribed a measurement-led research pass:
measure cold start-to-active on the loss cluster, attribute the time, then
fix a real regression or raise the harness budget with justification.

## 2. Measurements (2026-06-12, loss userspace cluster, 2 deploy cycles + contrasts)

All cluster work ran under `test/incus/with-cluster.sh` lock cells. The
instrumented re-implementation of the harness Phase-4 poll lives at
`docs/research/1880-boot-budget/measure-boot.sh` (per-iteration exec latency
+ wall clock + in-VM journal forensics).

| Scenario | Comeback (harness iterations) | Wall clock |
|---|---|---|
| Reboot only, no recent deploy/commit (cycle1-reboot-only) | 17 | 22.2s |
| First reboot after deploy, ~92s after fw0 cleanup (cycle1-post-deploy) | 40 | 51.3s |
| Reboot ~45s into the post-deploy window (cycle2-in-window) | **60 (boundary)** | **73.6s** |
| Predicted worst case (reboot at window start) | ~120 | ~147s |

Attribution of the in-VM time (journal monotonic + unix timestamps):

- In-VM boot is FAST and stable: kernel+userspace ≈ 10s, xpfd unit spawn at
  9.4–10.8s monotonic; `systemd-networkd-wait-online` 1.4–2.4s; frr start
  0.4–0.6s. `xpfd.service` is `Type=simple`, so `systemctl is-active` flips
  the instant ExecStart spawns — daemon-internal init (#1869 pre-flight,
  snapshot volume, bulk-sync hold) is NOT in the measured path at all.
  (#1869's verify-dataplane runs at deploy time in `deploy_vm()`, not boot.)
- VM firmware/agent gap (last journal line of old boot → first kernel line
  of new boot) ≈ 16s. Poll detection adds ≤1.3s granularity.
- The variable term is SHUTDOWN: a reboot issued while `frr.service` sits in
  `stop-sigterm` blocks the whole shutdown until frr's 2-minute
  `TimeoutStopSec` expires (`frr.service: State 'stop-sigterm' timed out.
  Killing.` then SIGKILL of watchfrr/mgmtd/zebra/staticd). Cycle 1 measured
  a 28s residual wait (reboot landed 92s into the window); cycle 2 measured
  ~45s residual (60 iterations, the exact harness boundary).

Harness accounting bug (secondary): `test-failover.sh` line 207 counts
iterations, not seconds. Each iteration costs ~1.23s wall (1s sleep +
~240ms `incus exec`), so "60s budget" is really ~74s wall, and the PASS
message `fw0 xpfd active after ${i}s` under-reports by ~23%.

## 3. Root cause

Deterministic, reproduced standalone on fw1: a single plain
`systemctl reload frr` prints `Job for frr.service canceled.`, parks the
unit at `ActiveState=deactivating SubState=stop-sigterm` for exactly 120s,
then SIGKILLs every FRR daemon (`pidof zebra watchfrr` → empty) before
`Restart=always` resurrects it ~5s later.

Mechanism: FRR 10.6.0's `/usr/lib/frr/frrinit.sh reload` **unconditionally
restarts watchfrr** ("restart watchfrr to pick up added daemons":
`daemon_stop watchfrr && daemon_start watchfrr`). watchfrr is the unit's
MainPID (`Type=forking`, `PIDFile=/run/frr/watchfrr.pid`). systemd sees the
main PID die mid-ExecReload, cancels the reload job, and drives the unit
through stop-sigterm cleanup of the (still running, SIGTERM-surviving)
cgroup — the 2-minute timer whose expiry murders FRR.

Triggers in our stack — both call `pkg/frr.Manager.reload()` →
`systemctl reload frr`:

1. **Deploy**: `deploy_vm()` runs `xpfd cleanup` right after
   `systemctl stop xpfd`; `cmd/xpfd/main.go` cleanup calls
   `frr.New().Clear()` → reload. Every deploy poisons frr.service for
   ~120s on both nodes.
2. **Every config commit**: `daemon_apply.go` step 3 → `frr.ApplyFull()` →
   unconditional `reload()`. The smoke's `apply-cos-config.sh` commit
   re-arms the window minutes before `test-failover` reboots fw0.

The failover harness reboot lands 45–120s after the last trigger depending
on deploy push speed and test preflight duration → intermittent first-run
failure; the rerun has no fresh trigger → always passes (22s comeback).

Journal history: **990** `stop-sigterm timed out` events on fw0 since
2026-04-20 (journal horizon; FRR 10.6.0-2 installed 2026-04-07). This has
been happening on every commit/deploy for two months. The 2026-06-11 smoke
failures are a timing drift into the window, not a new regression — and
none of the issue's candidate causes (#1869 pre-flight, snapshot volume,
FRR reload *duration*, bulk-sync hold) is the consumer.

## 4. Collateral defects found (same root)

- (a) **FRR is SIGKILLed ~2min after every commit/deploy** and auto-restarts.
  Masked because zebra's SIGKILL leaves kernel routes installed and the
  restart re-reads frr.conf (which xpfd keeps current).
- (b) **Stale-config removal on commit is broken**: `systemctl reload frr`
  always fails ("Job canceled" / "Unit ... is inactive"), so
  `reload()` falls back to `VtyshLoad` (`vtysh -f`), which is **additive**
  — removed routes/protocol stanzas survive until the delayed FRR murder +
  restart accidentally applies the full config. Route deletions can take up
  to ~2 minutes to converge, via a routing flap.
- (c) Harness counts iterations as seconds (Section 2).

## 5. Paths

### Path A — fix the reload mechanism in pkg/frr (root fix, recommended)

Stop using `systemctl reload frr` from the daemon entirely. Primary reload
becomes a direct bounded invocation of
`/usr/lib/frr/frr-reload.py --reload /etc/frr/frr.conf` (the same diff
engine frrinit.sh uses, minus the watchfrr bounce and minus systemd job
machinery). Keep `vtysh -f` as the existing last-resort fallback with its
additive caveat documented. Concretely:

- `pkg/frr/vtysh.go`: add `FrrReloadPy(ctx)` to the `frrExecutor`
  interface (mockable like `SystemctlReload`); drop `SystemctlReload`.
- `pkg/frr/manager.go reload()`: try `frr-reload.py --reload` (15s ctx,
  same `reloadTimeout` shutdown-correctness invariant), fall back to
  `VtyshLoad`. Binary-missing (frr-pythontools absent) → fallback, warn.
- Validated on the VM: `frr-reload.py --test --stdout /etc/frr/frr.conf`
  exits 0 in <1s, computes the diff via the vtysh socket, does not touch
  unit state, and works even while frr.service shows `deactivating`.

Fixes the harness flake (no more poison window), the FRR murders (a), and
the stale-config-removal correctness bug (b) in one mechanism change.
`xpfd cleanup` → `Clear()` inherits the fix.

### Path B — make the harness reboot genuinely unclean + wall-clock budget

`test-failover.sh` documents its reboot as "unclean — no priority-0
burst", but `incus exec fw0 -- reboot` is a graceful systemd reboot: xpfd
is stopped cleanly (and therefore DOES emit the planned-shutdown
priority-0 burst, taking the ~1ms takeover path instead of the ~60ms
worst-case detection the test claims to exercise) and the shutdown queues
behind any wedged stop job. Change Phase 3 to a forced reboot
(`systemctl reboot --force --force` inside the VM — no unit stops, no
unmount, immediate reset), which (i) restores the test's stated intent and
(ii) makes the comeback immune to ANY shutdown-job hang, present or
future. Forced-reboot comeback ≈ firmware 16s + boot 10s + agent ≈ 20s.

Also fix accounting: time the Phase-4 wait on wall-clock seconds
(`SECONDS`/epoch) instead of iteration count, keep `REBOOT_WAIT=60` (3×
headroom over the ~22s clean comeback), and log the true elapsed time.

Side benefit: the current graceful reboot has a Phase-4 false-positive
race — the poll starts 3s after `reboot`, and `systemctl is-active xpfd`
returns active for the OLD boot if the shutdown hasn't reached xpfd's stop
job yet (measured: xpfd stop begins <3s in, so it has not bitten, but
nothing guarantees that under load). A forced reboot kills the guest
instantly, eliminating the race.

### Path C — raise the budget only (fallback, NOT recommended)

`REBOOT_WAIT=60 → 150` wall-clock seconds, justified by the measured 147s
worst case. Leaves the FRR murder/stale-route bugs in place and makes
every genuinely-slow regression 2.5× slower to detect. Only appropriate if
reviewers reject A and B.

### PLAN-KILL invitation

Kill criteria reviewers should probe: (i) is `frr-reload.py --reload` safe
under concurrent vtysh writers (config sync on the secondary, operator
vtysh)? (ii) does Path B's forced reboot invalidate any assertion later in
test-failover (fw0 rejoin-as-secondary, sync-hold release)? (iii) is there
a reason the graceful-reboot path itself must stay under test (e.g., a
release gate that exercises clean shutdown)? If (iii) holds, B can add a
separate clean-shutdown assertion rather than revert.

## 6. Recommendation

Ship **A + B together** (independent, both small):
- A: `pkg/frr` mechanism change + unit tests (executor mock: success,
  script-missing fallback, timeout) + docs (`pkg/frr` README / module docs).
- B: harness Phase-3 forced reboot + Phase-4 wall-clock accounting; keep
  the 60s budget. `bash -n` + 2 consecutive first-run-after-deploy
  failover passes as the gate (the exact failure mode).

## 7. Validation plan (Phase 2 gates)

1. Unit: `go test ./pkg/frr/...` (new executor mock paths) + full suite.
2. Live: deploy to loss userspace cluster; assert `frr.service` stays
   `active/running` on both nodes through deploy + apply-cos commit
   (`systemctl show frr -p ActiveState,SubState` polled for 150s — today
   this deterministically shows `stop-sigterm`).
3. Live: stale-route removal — commit a static route, commit its deletion,
   assert it leaves zebra (`show ip route`) within the reload, not after a
   2-minute FRR restart.
4. Harness: `make test-failover` twice, each as the FIRST run after a fresh
   deploy — 13/13 both times (reproduces the smoke failure precondition).
5. Existing failover invariants: fw0 rejoins as secondary, no auto-preempt,
   iperf3 survives — already asserted by the harness.

## 8. Risks

- `frr-reload.py` runtime on large diffs: bounded by the 15s ctx; on
  timeout we fall back to `vtysh -f` (additive but never worse than the
  status quo, which ALWAYS took that fallback).
- frr-pythontools not installed on some target: explicit binary-existence
  check → fallback + warn once (status quo behavior).
- Forced reboot leaves dirty filesystems: ext4 journal recovery on these
  VMs is sub-second and this is precisely the power-fail scenario the test
  claims to cover; the standalone/legacy regression environments inherit
  the same script — verify `CLUSTER_ENV=` legacy path still passes once.
- Path A changes the reload path for ALL commits, not just deploys —
  mitigated by gate 2/3 above and the fact that the current "primary" path
  has been 100%-failing since April (every reload already runs the
  fallback today).

## 9. Out of scope

- Fixing FRR upstream (frrinit.sh reload watchfrr bounce) or re-typing
  frr.service (`Type=notify`) — environment-level changes we don't own;
  noted for an operator doc footnote.
- systemd-notify readiness gating for xpfd (`Type=notify`) — orthogonal
  hardening; the measurement shows unit-spawn vs daemon-ready is not the
  failing term. Candidate follow-up issue only.
- The other 60s budgets (`test-chained-crash.sh`, `test-double-failover.sh`
  TAKEOVER_WAIT) — different semantics (takeover-ready, not reboot).

## 10. Deliverable

One PR off `engineer/1880-boot-budget`: pkg/frr reload mechanism + harness
unclean-reboot/wall-clock fix + module docs + validation evidence in the PR
body. `Closes #1880`.

## 11. Decision asked of reviewers

PLAN-READY on A+B as scoped, or argue for C / a different mechanism (e.g.,
keep systemctl reload but add a frr.service drop-in with
`TimeoutStopSec=15`), or PLAN-KILL with a counter-example against the
Section 3 mechanism.
