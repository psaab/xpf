# #9486 validation results — XPF_DEPLOY_DEB=1 live on loss userspace cluster

Date 2026-09-13. Base `7ef226474`, branch `fix/9486-upgrade-deb-default`.
Deb `xpf_0.0.17469+g7ef2264747e6_amd64.deb` (built outside the lock).
Deployed version token: `working-15061-g7ef226474-dirty`
(`-dirty` = the deb build's own transient `debian/changelog` rewrite, visible
to `git describe` at compile time; pre-existing quirk, not this lane).
Nodes `loss:xpf-userspace-fw0/fw1`, LAN host `loss:cluster-userspace-host`,
target `172.16.80.200`. All under the #1875 `with-cluster.sh` lock
(3 cells: forward-cut, rollback-attempt, recover+variant).
Raw logs: `evidence/` (`run.log`, `apt-fw*.log`, `cut-fw*.log`,
`recut-fw1.log`, `rollback-*.log`, `textboot-*.log`, `ping.log`, `iperf.log`,
`pre/post/final-status.log`).

## Pre-state (both nodes)

- dpkg `0.0.3885+gf5b5d5e864f4` installed (June dogfood); sbin held REAL
  raw-pushed binaries (Sep 12, sha `104cf236…`, both nodes identical);
  running `…-16129-ga94eaf6c5` (HA proto 1, sync v2, matched peers).
- `/var/lib/xpf/versions/`: fw0 3 dirs (2553/2554/2555), fw1 1 dir (2555),
  all pre-#1981 (no `.srcgen`), plus lingering June `.<ver>.dbsnap` dirs.
- `versions/current` ABSENT on both (nothing in upgrade code removes it;
  raw reconcile only drops dangling sbin links — removal agent unknown).
- No `staged-gen/`, no journal. node0 primary, RG0-2 failover count 0.

## One-time repair (torn layout)

Recreated `current -> <newest-OLD>` (2555 on both) before deploying.
Without a restorable previous the cut refuse-before-STOPs; the cut still
validated OLD restorability (lockstep+ELF) before any STOP. Rationale
recorded in `../plan.md` step 5 note.

## Criterion 1 — deb deploy, versions/current + rollback slot: PASS

- `apt install` (upgrade, $2 set): postinst published a staged generation
  (`fw0: 01789328980285697031-…`, `fw1: 01789329072483114348-…`) and
  reported `clustered node (node-id present) — staged only` on both.
- Rolling cuts (secondary fw1 first, then primary fw0) ran the full
  journal machine: `STAGED -> PREFLIGHT -> COPIED -> VERIFIED -> STOPPED
  -> FLIPPED -> STARTED -> COMMITTED` (`cut-fw*.log`), drain + rejoin
  confirmed per node.
- Post: `current -> working-15061-g7ef226474-dirty` both nodes;
  `versions/<NEW>/.srcgen` stamped with the published genid; sbin links
  resolve through `current`; drop-in `ExecStart` pinned to concrete NEW.
- Retention: fw0 GC removed 2553 + its orphan `.dbsnap` at commit
  (now {2554, 2555, NEW}); fw1 {2555, NEW}. Rollback slot populated.
- Cluster ends node0-primary all RGs, failover count 0, session sync clean.
- Side observation: the NEW preinst realigned sbin through the repaired
  `current` (mechanism-B-adjacent), harmless — cuts run via absolute
  staged path.

## Criterion 2 — traffic continuity: PASS with deviation (see below)

- iperf3 `-P4 -t1500 -i1`, ONE client session spanning 272 s across BOTH
  cuts + rollback + text-boot + re-flip: 271 SUM intervals, median
  95.4 Mbit/s, p5 50.3, max 111.0, total retransmits 1713 on a path whose
  baseline already retransmits heavily (pre-run spot check: 137/10 s).
- Zero-transfer seconds: exactly 3 (t=39-41 s), aligned with the PRIMARY
  cut's STOP->STARTED window (fw0 journal, +125 s clock skew corrected).
  The SECONDARY cut produced no measurable dip.
- TCP: NO reset, NO stream death, NO error — session survived all events.
- ping `-i0.2 -D` (1321 replies): NO gap > 1.0 s for the whole run; at the
  primary cut a ~0.4-0.6 s disturbance (seq 191-192 missing, 11.9 ms RTT
  on seq 193).
- DEVIATION: the acceptance's "~60 ms VRRP-class gap" was not observed as
  60 ms — the primary cut shows a ~3 s TCP throughput stall (STOP->STARTED
  3 s on both cuts) with sub-second ICMP disturbance. [INFERENCE] On this
  lossy path, TCP RTO backoff plausibly amplifies a sub-second forwarding
  disturbance into a seconds-scale hole; ping (stateless) sailed through.
  Continuity (no reset/death, single bounded stall, secondary cut
  invisible) is proven; the 60 ms figure is not. Recommend parent decide
  whether 60 ms needs finer instruments or a follow-up issue.

## Criterion 3 — postinst stage-only on clustered node: PASS (both nodes)

- pid unchanged across `apt install` (fw1 341020, fw0 739);
  `current` still -> OLD; `staged only; cut over with: xpfd upgrade
  --rolling` in apt output; forwarding alive (ping 3/3) pre-cut.

## Criterion 4 — rollback incl. DB restore: PARTIAL (see analysis)

- By-the-book operator sequence (stop -> restore PREFLIGHT snapshot
  `.<NEW>.dbsnap/active.json` -> re-flip current/sbin/unit -> start)
  executed on fw1; snapshot present, restore byte-correct (live DB
  preserved at `.configdb.old`).
- The rolled-back June binary FAIL-CLOSED on boot, by design
  (`evidence/rollback-journal.log`, fw1 `journalctl -u xpfd` 19:53:36–52):
  `config envelope format v=2 is newer than this build supports (v=1);
  refusing to load` — clean NEW shutdown, then the OLD binary crash-looping
  every ~4 s (restart counter 8 by 19:54:09), systemd `activating`, DB never
  overwritten. The design doc's brick ("an N daemon that fatal-rejects
  the N+1 envelope DB") was avoided exactly as specified: refuse, no
  overwrite. But boot+forward on the restored DB was impossible with THIS
  slot: the June rollback target predates the envelope v1->v2 bump, and
  the snapshot itself is v2 (written by the Sep-12 raw binary).
- Compensating proof (text-bootstrap variant, same cell): DB removed, June
  binary booted from `/etc/xpf/xpf.conf` text -> ACTIVE, ping 5/5,
  iperf3 15 s 48.1 Mbit/s. Old binary boots + forwards; the binary half
  of rollback is proven. (This bypasses the mandatory DB-restore order —
  labeled as variant, not the documented sequence.)
- Steady-state note: post-flip slots hold adjacent deb versions
  (envelope-consistent); the ancient June dirs age out via the proven GC
  (2553 already reaped). The skew that blocked the by-the-book boot
  cannot recur between consecutive deb upgrades.
- Ask parent: (a) accept item 4 as validated-with-exception, (b) require
  a `xpfd upgrade --rollback` operator verb first (pre-existing #9486
  comment: HA rollback has no single-command surface), or (c) require an
  envelope-major rollback policy. Recommendation: (a) + file (b) as
  follow-up (parent files).

## Criteria 5+6 — implemented after validation (this PR)

- Default flip in `cmd_deploy`: deb path unless `XPF_DEPLOY_FAST=1`;
  comment at `cluster-setup.sh:606-612` rewritten (no unmet
  precondition); `docs/in-place-upgrade.md:725` updated.
- Census: `make cluster-deploy` recipe -> `cluster-setup.sh deploy` ->
  deb path; `make harness-census` green (see PR body).
