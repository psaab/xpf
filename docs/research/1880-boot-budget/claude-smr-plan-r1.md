# #1880 plan review — Claude SMR, round 1 (HOSTILE)

Verdict: **PLAN-NEEDS-REVISION** (mechanism verified; Path A failure
semantics and Path B primitive under-specified — independently matching
two of Codex's High findings before reading them).

## Verified (re-derived, not trusted)

- Root mechanism reproduced live by me during research: standalone
  `systemctl reload frr` on fw1 → `Job for frr.service canceled.` →
  `deactivating/stop-sigterm` for 120s → SIGKILL, `pidof zebra watchfrr`
  empty → auto-restart. Deterministic, not raced.
- Both triggers verified at source: `cmd/xpfd/main.go:41`
  (`frr.New().Clear()` in cleanup, invoked by
  `test/incus/cluster-setup.sh` deploy_vm immediately after
  `systemctl stop xpfd`) and `pkg/frr/manager.go:311-315` (ApplyFull →
  unconditional `reload()`); `reload()` tries `SystemctlReload` first
  (manager.go:528).
- Harness math verified: `test-failover.sh:207` loops 60 iterations of
  `wait_for_instance "$FW0" 1` (one is-active + 1s sleep each); measured
  ~240ms exec overhead → ~74s wall for "60s".
- xpfd's own shutdown does NOT touch FRR — the deploy-window reload at
  388.17 came from `xpfd cleanup`, 1.3s after the unit stop completed.
  The boot-side chain (networkd-wait-online 1.4-2.4s, frr start 0.5s) is
  not the consumer; issue candidates (#1869 pre-flight, snapshots,
  bulk-sync hold) are all off the measured path.

## Findings

1. **High — fallback-after-timeout is unsafe as written.** r1 plan says
   "on timeout we fall back to vtysh -f". `reload()` shares ONE 15s ctx
   (manager.go:523); a timed-out primary hands a dead ctx to the
   fallback, and `daemon_apply.go:80` documents the apply path as not
   safe to interrupt mid-stream. r2 must specify: independent bounded
   contexts, fallback only on non-timeout failure or with explicit
   reasoning for the partial-diff case (vtysh -f after a partial diff is
   additive-convergent: desired lines re-applied, stale removals
   possibly missed — exactly status-quo parity, never worse).
2. **High — stale-removal guarantee contradicts "pythontools may be
   absent".** If `/usr/lib/frr/frr-reload.py` is missing the plan's
   correctness claim (b) silently evaporates. r2 must add
   `frr-pythontools` to cluster provisioning (`cluster-setup.sh:459`
   apt list), and the daemon must warn-once + count when degraded.
3. **Medium — reboot primitive should reuse the in-tree proven one.**
   `test-double-failover.sh:187` already crashes fw0 with
   `echo b > /proc/sysrq-trigger` ("sysrq reboot — unclean shutdown,
   tests worst-case failover") and `test-ha-crash.sh` uses
   `incus stop --force`. Path B should use sysrq-b, not introduce a
   third primitive (`systemctl reboot -ff`) with unproven incus-VM
   behavior.
4. **Medium — error masking.** `Clear()` discards the reload error
   (manager.go:325 `_ = m.reload()`); `xpfd cleanup` discards Clear's
   error implications beyond exit message. r2: propagate from Clear,
   decide and DOCUMENT the cleanup-path policy (log loudly, still exit
   0 so deploys are not aborted by a transiently-down FRR — deploy
   already wraps cleanup in `|| true`).
5. **Low — "3× headroom" is 2.7×, and the post-change budget must be
   re-justified with a measured sysrq-reboot comeback, not the graceful
   number.**
6. **Low — stale comments**: manager.go:38 reloadTimeout rationale and
   pkg/frr/README.md:84 reference `TimeoutStopSec=20` (xpfd's), not
   FRR's measured 120s stop window; update with Path A.

## Where I am deliberately NOT asking for more

- Concurrency: all daemon FRR writers serialize under `applySem`
  (daemon.go:160, daemon_apply.go:111, daemon_ipmon.go:179);
  `frr-reload.py` is the same engine `systemctl reload` ran via
  frrinit.sh, so Path A does not widen the concurrency surface. Operator
  vtysh races are pre-existing and out of scope.
- Graceful-shutdown coverage loss from Path B: the graceful path is
  exercised by every deploy restart and by `test-restart-connectivity`;
  test-failover's own header has claimed unclean semantics since
  ca89ab974.
