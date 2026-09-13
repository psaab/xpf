# Plan — #9486 validate XPF_DEPLOY_DEB=1 live, then flip default

Base `7ef226474`, branch `fix/9486-upgrade-deb-default`. STEP-0: NOT done —
`XPF_DEPLOY_DEB` appears only in `test/incus/cluster-setup.sh:606/623/656/693`
(opt-in) and docs; zero Makefile references; default is raw push+restart.

1. Baseline (no lock): `loss:xpf-userspace-fw0/fw1` state, `xpfd --version`
   both nodes, `versions/current` + rollback slots, RG0 roles, iperf3 sanity.
2. Build `make deb` OUTSIDE the lock (multi-minute, local-only).
3. Under `with-cluster.sh` lock: `XPF_DEPLOY_DEB=1 ... deploy all` with iperf3
   running across both cuts. Expect: both nodes on new version via
   `versions/current`, rollback slot populated (N=3), one ~60 ms gap per
   node, no TCP reset. Record all numbers.
4. Postinst stage-only assert: after `apt install`, before cut, running
   `xpfd` pid+version unchanged and dataplane still forwarding.
5. Rollback on fw1 per documented operator sequence (`docs/in-place-upgrade.md`
   "Rollback": stop → restore config-DB PREFLIGHT snapshot → re-flip
   current to previous → start); verify boot+forward; re-cut forward.
   NOTE: no `xpfd upgrade --rollback` verb exists (already filed as #9486
   comment); this exercises the documented HA operator path, not `rollback()`.
6. On success: flip default (`XPF_DEPLOY_DEB` default-on, `XPF_DEPLOY_FAST=1`
   keeps raw push), update `cluster-setup.sh:606-612` + `in-place-upgrade.md:725`,
   run `make harness-census` (criterion 6: `cluster-deploy` recipe reaches deb
   path). Commits: validation evidence, default flip, docs. Open PR
   (`Closes #9486` + test table), add Copilot reviewer, STOP.
7. Any step fails → comment specifics on #9486, BLOCKED with logs, no flip.
