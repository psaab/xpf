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
- No `staged-gen/`, no journal. node0 primary RG0 (failover count 0);
  RG1/RG2 split (node1 primary RG1, node0 primary RG2) with failover
  count 3 each from earlier events (`pre-status.log` / `run.log:29-34`).
  Post-run all RGs read count 0 with node0 primary — the counters reset
  when both daemons restarted during the cuts.

## One-time repair (torn layout)

Recreated `current -> <newest-OLD>` (2555 on both) before deploying.
Without a restorable previous the cut refuse-before-STOPs; the cut still
validated OLD restorability (lockstep+ELF) before any STOP. Rationale
recorded in `plan.md` step 5 note.

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

## Criterion 2 — traffic continuity: PARTIAL (no reset/death proven; gaps exceed the bar)

- iperf3 `-P4 -t1500 -i1` (streams [5]/[7]/[9]/[11]), ONE client session
  spanning 272 s across BOTH cuts + rollback + text-boot + re-flip
  (`evidence/iperf.log`): NO reset, NO stream death, NO error — all four
  streams survived every event in one session. That half of the bar is met.
- The gap half is NOT met — per-stream analysis (the earlier SUM-level
  "median 95.4, one 3 s zero window" hid this; corrected here):
  - Streams [7]/[9]/[11] went ZERO for ~30 s (t=12→42): collapse begins
    t=11-12 (25→8.4 Mbit/s, cwnd 100K→1.41K floor), then 0.00 bits/sec
    with cwnd pinned at 1.41K and ~1 RTO probe/sec failing, starting ~3 s
    after fw1's STOP (19:51:22) — i.e. spanning the SECONDARY cut.
  - Stream [5] carried the full load alone t=12-38 (~95-102 Mbit/s, cwnd
    445-460K), collapsed t=38-39 (cwnd→1.41K), stayed zero t=39-54 (15 s)
    across fw0's STOP→STARTED (fw0 journal +125 s skew, see
    `evidence/clock-skew.log`), and recovered t=54-55 with a
    445-retransmit storm.
  - Streams [7]/[9]/[11] recovered t=42-43 with 79-84 retransmits each
    (backlog flush), exactly as fw0's cut completed.
- ping `-i0.2 -D` (1321 replies): NO gap > 1.0 s for the whole run; at the
  primary cut a ~0.4-0.6 s disturbance (seq 191-192 missing, 11.9 ms RTT
  on seq 193). Stateless ICMP sailed through what stalled TCP for seconds.
- [INFERENCE, offered not asserted] The pattern — 3 flows blackholed from
  the secondary cut until the primary's own restart, while a 4th flowed —
  fits synced-session state stranded by fw1's restart and cleared only by
  fw0's STOP (fresh sessions post-START recovered instantly). An
  alternative this data cannot exclude is loss-burst + RTO collapse on an
  already heavily-retransmitting path (baseline 137 retransmits/10 s).
  Either way the acceptance's "~60 ms VRRP-class gap per node" is not what
  was measured: throughput stalled seconds-scale on BOTH cuts (30 s across
  three streams on the secondary cut; 15 s on the survivor across the
  primary cut). Recommend parent file a follow-up on the secondary-cut
  starvation regardless of this issue's disposition.

## Criterion 3 — postinst stage-only on clustered node: PASS (both nodes)

- pid unchanged across `apt install` (fw1 341020, fw0 739);
  `current` still -> OLD; `staged only; cut over with: xpfd upgrade
  --rolling` in apt output; forwarding alive pre-cut (fw0 ping 3/3 per
  `run.log:107`; fw1 ping 2/3 with 33% loss per `run.log:61` — lossy-path
  baseline, not a stage-only signal).

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
- Compensating attempt (text-bootstrap variant): DB removed, June binary
  booted from `/etc/xpf/xpf.conf` text -> ACTIVE 3× (part 3, cells C, D),
  cluster membership works cross-version (both sides report peer
  versions, HA proto 1/1). CORRECTION of an earlier overstatement: the
  48-Mbps iperf numbers in those windows traversed fw0 (NEW primary) —
  fw1/June was secondary throughout, so June's own datapath forwarding
  is UNPROVEN. What the windows do prove: the old binary boots cleanly
  and does not interfere with the cluster forwarding around it.
- Steady-state note: post-flip slots hold adjacent deb versions, which
  makes another 3-month envelope skew unlikely — but packaging adjacency
  is not a format-compat proof. A rollback across a future envelope-major
  bump would fail closed the same way; that policy gap is part of the
  item-4 ask above. The ancient June dirs age out via the proven GC
  (2553, then 2554, already reaped across the two forward cuts).
- Instrumentation note: part-3 scripts logged `CLI-UNREACHABLE` 3×
  (`recover-status.log`, `textboot-status.log`, `final-status-fw1.log`) —
  each a `cli` query racing the just-started daemon's gRPC socket, each
  followed by successful reads in the same step. Timing artifact, not a
  daemon state.
- Item-6 follow-up runs (cells C, D — June-primary attempt, see
  `evidence/cellc*.log`, `evidence/celld*.log`):
  - June slot binary self-reports `...-3308-g0eb3b133a` (built 2026-06-21);
    the `...-2555-gf5b5d5e86-dirty` directory name reflects the seeding
    deb's version, not the embedded token. Recorded as observed.
  - Cell C: failover-to-fw1 BEFORE the June boot did not pin the path —
    the DB removal cleared the manual-primary pin, so June booted
    secondary; the 30 s / 48 Mbps iperf in that window traversed fw0.
    Session sync June<->NEW observed DISCONNECTED both directions
    (`Transfer ready: no`), membership OK.
  - Cell D: failover-to-node-1 AFTER June was running was REFUSED by the
    cluster safety gate on all 3 RGs, verbatim: `FailedPrecondition:
    local redundancy group N not transfer-ready for explicit failover
    reasons=[session sync disconnected]`. June therefore cannot take
    primary across this version skew — the gate that protects traffic
    from unsynced takeovers holds, by design.
  - Net: June boots (3×), joins membership, never forwards production
    traffic in any observed window; every layer that could strand traffic
    (envelope fail-closed, transfer-readiness gate) refused instead.
    Forwarding-through-June would need a both-June cluster or peer
    isolation — NOT attempted; proposed for parent approval if wanted.
- Ask parent: (a) accept item 4 as validated-with-exception, (b) require
  a `xpfd upgrade --rollback` operator verb first (pre-existing #9486
  comment: HA rollback has no single-command surface), or (c) require an
  envelope-major rollback policy. Recommendation: (a) + file (b) as
  follow-up (parent files).

## Criteria 5+6 — implemented after validation (this PR)

- Default flip in `cmd_deploy`: deb path unless `XPF_DEPLOY_FAST=1`;
  comment rewritten (no unmet precondition); `docs/in-place-upgrade.md`
  Dogfood section updated + one config-preserved sentence.
- Makefile waste fixed: `cluster-deploy`/`loss-cluster-deploy` prereqs
  are `deb` by default, `build build-ctl` under `XPF_DEPLOY_FAST=1`
  (verified `make -n` both modes).
- Config delta: deb path preserves node config (no CLUSTER_CONF push, no
  DB clear, no Phase-0 push) with a prominent NOTICE on every deb deploy
  (`evidence/deploy-deb0.log` shows it firing); usage texts + 4 doc
  claims corrected to raw-path scope.
- `XPF_DEPLOY_DEB` (now read nowhere) warns when set, so `=0` cannot
  silently select the default (`evidence/deploy-deb0.log` shows the warn).
- Census: `make cluster-deploy` recipe -> `cluster-setup.sh deploy` ->
  deb path; `make harness-census` green (52 harnesses).
- REAL default entry proven live (item 4b, `evidence/deploy-default*.log`):
  literal `make cluster-deploy` rc=0 cut both nodes forward to
  `working-15065-g0b634b4e0-dirty` (prev `working-15061-…`,
  envelope-consistent), GC reaped 2554+orphan snap, 205 SUM iperf
  intervals with 0 zero-transfer seconds on ANY stream and no resets.
- Same-tree redeploy wart (observed, pre-existing, not fixed): the DEB=0
  run died at `incus file push` (`/tmp/<same-name>.deb`: permission
  denied overwriting run#1's file), before apt — the generation guard
  was not reached. Same-name re-push collides; distinct versions (the
  norm) do not.
