# Codex plan review r1 — task-mqabhgun-jrtm9b (2026-06-12)

Verdict: PLAN-NEEDS-REVISION ("root thesis and repo call graph mostly
check out... not PLAN-KILL").

- High — Path A timeout fallback internally inconsistent: reload() shares
  one 15s ctx (manager.go:523,528,534); a timed-out primary hands a dead
  ctx to VtyshLoad; daemon_apply.go:80 documents apply as not safe to
  interrupt mid-stream. Plan must define timeout semantics / prove
  interruption safety.
- High — missing frr-reload.py silently removes the root fix: cluster
  provisioning installs frr only (cluster-setup.sh:458); fallback is the
  known-additive vtysh -f (vtysh.go:86) so stale removal would not be
  fixed.
- High — FRR apply/cleanup failures masked above pkg/frr: applyFRRConfig
  warn-and-continue (daemon_ipmon.go:161); Clear() discards reload error
  (manager.go:325); xpfd cleanup discards Clear result (main.go:40).
  Needs explicit success signal/gate.
- Medium — concurrency asked but not answered; applySem serializes
  internal writers (daemon.go:160, daemon_apply.go:111,
  daemon_ipmon.go:179); operator vtysh outside the model.
- Medium — Path B primitive under-proven; repo already has proven unclean
  mechanisms: sysrq reboot (test-double-failover.sh:187) and incus stop
  --force (test-ha-crash.sh:294). Prefer one of those.
- Low — keep REBOOT_WAIT=60 only after A+B; "3x" is really 2.7x; gate
  with measured forced-reboot wall clock.
- Low — stale docs: manager.go:38 / pkg/frr/README.md:84 reference
  xpfd's TimeoutStopSec=20, not FRR's 120s stop window.
- Cheaper fix considered (frr.service TimeoutStopSec drop-in): "not
  equally good... Path A remains the right root fix".
